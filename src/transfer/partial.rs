//! Resumable partial downloads.
//!
//! A download is written into a hidden, pre-sized `.<name>.rsftp-part` file
//! next to its destination. The byte ranges already written and verified are
//! recorded in `.<name>.rsftp-part.json`, together with the remote path, size
//! and modification time. Both engines (rsftp-turbo and SFTP) fill in only
//! the missing ranges, so
//!
//! * a turbo download that fails part-way is finished over SFTP without
//!   fetching the completed ranges again, and
//! * a download interrupted by an error or by closing the app resumes where it
//!   left off next time (if the remote file is unchanged).
//!
//! A download the user stops is discarded instead.

use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::{download::publish_temporary_file, DownloadError, DownloadProgress, SegmentProgress};

const META_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Meta {
    version: u32,
    remote: String,
    size: u64,
    mtime: Option<u64>,
    /// Sorted, non-overlapping `[start, end)` ranges already written.
    done: Vec<(u64, u64)>,
}

pub struct Partial {
    pub size: u64,
    file: Arc<File>,
    data_path: PathBuf,
    meta_path: PathBuf,
    meta: Mutex<Meta>,
    next_index: AtomicU32,
}

impl Partial {
    /// Opens (resuming if it matches) or creates the partial file for `destination`.
    pub fn open(destination: &Path, remote: &str, size: u64, mtime: Option<u64>) -> io::Result<Arc<Self>> {
        let name = destination.file_name().unwrap_or_default().to_string_lossy();
        let data_path = destination.with_file_name(format!(".{name}.rsftp-part"));
        let meta_path = destination.with_file_name(format!(".{name}.rsftp-part.json"));
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }

        let previous = fs::read(&meta_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Meta>(&bytes).ok())
            .filter(|meta| {
                meta.version == META_VERSION
                    && meta.remote == remote
                    && meta.size == size
                    && meta.mtime == mtime
                    && mtime.is_some()
                    && fs::metadata(&data_path).is_ok_and(|data| data.len() == size)
            });
        let done = match previous {
            Some(meta) => normalize(meta.done, size),
            None => {
                let _ = fs::remove_file(&data_path);
                Vec::new()
            }
        };

        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&data_path)?;
        file.set_len(size)?;
        let partial = Self {
            size,
            file: Arc::new(file),
            data_path,
            meta_path,
            meta: Mutex::new(Meta { version: META_VERSION, remote: remote.to_owned(), size, mtime, done }),
            next_index: AtomicU32::new(0),
        };
        partial.persist();
        Ok(Arc::new(partial))
    }

    pub fn file(&self) -> Arc<File> {
        Arc::clone(&self.file)
    }

    /// A fresh progress-bar piece index (unique for this download).
    pub fn next_index(&self) -> u32 {
        self.next_index.fetch_add(1, Ordering::Relaxed)
    }

    pub fn pieces_used(&self) -> u32 {
        self.next_index.load(Ordering::Relaxed)
    }

    pub fn completed(&self) -> Vec<(u64, u64)> {
        self.meta.lock().map(|meta| meta.done.clone()).unwrap_or_default()
    }

    pub fn done_bytes(&self) -> u64 {
        self.completed().iter().map(|(start, end)| end - start).sum()
    }

    pub fn is_complete(&self) -> bool {
        self.done_bytes() == self.size
    }

    /// Ranges still to download, in file order.
    pub fn missing(&self) -> Vec<(u64, u64)> {
        let mut missing = Vec::new();
        let mut position = 0;
        for (start, end) in self.completed() {
            if start > position {
                missing.push((position, start));
            }
            position = end;
        }
        if position < self.size {
            missing.push((position, self.size));
        }
        missing
    }

    /// Records `[start, end)` as written. Call only after the data is on disk
    /// (and, for turbo, verified).
    pub fn mark_done(&self, start: u64, end: u64) {
        if let Ok(mut meta) = self.meta.lock() {
            let mut done = std::mem::take(&mut meta.done);
            done.push((start, end));
            meta.done = normalize(done, self.size);
        }
        self.persist();
    }

    fn persist(&self) {
        let Ok(meta) = self.meta.lock().map(|meta| meta.clone()) else { return };
        let Ok(json) = serde_json::to_vec(&meta) else { return };
        // Best effort: losing the record only means less can be resumed.
        let temp = self.meta_path.with_extension("json.tmp");
        if fs::write(&temp, json).is_ok() {
            let _ = fs::rename(&temp, &self.meta_path);
        }
    }

    /// Shows already completed ranges (from a previous attempt) in the UI.
    pub fn announce(&self, progress: &Option<mpsc::UnboundedSender<DownloadProgress>>) {
        let Some(tx) = progress else { return };
        let done = self.done_bytes();
        for (start, end) in self.completed() {
            let _ = tx.send(DownloadProgress {
                total_bytes: self.size,
                transferred_bytes: done,
                completed_segments: 0,
                total_segments: 0,
                segment: Some(SegmentProgress {
                    index: self.next_index(),
                    start,
                    end_exclusive: end,
                    transferred_bytes: end - start,
                    complete: true,
                    failed: false,
                }),
                file_path: None,
                file_complete: false,
                accelerated: false,
            });
        }
    }

    /// Verifies every byte was written and moves the file into place.
    pub async fn finish(&self, destination: &Path) -> Result<(), DownloadError> {
        let done = self.done_bytes();
        let actual = self.file.metadata()?.len();
        if done != self.size || actual != self.size {
            return Err(DownloadError::SizeMismatch { expected: self.size, actual: done.min(actual) });
        }
        self.file.sync_all()?;
        publish_temporary_file(&self.data_path, destination).await?;
        let _ = fs::remove_file(&self.meta_path);
        Ok(())
    }

    /// Deletes the partial download (when the user stops it).
    pub fn discard(&self) {
        let _ = fs::remove_file(&self.data_path);
        let _ = fs::remove_file(&self.meta_path);
    }
}

/// Sorts, clamps to the file size and merges touching or overlapping ranges.
fn normalize(mut ranges: Vec<(u64, u64)>, size: u64) -> Vec<(u64, u64)> {
    ranges.retain(|(start, end)| start < end && *start < size);
    for range in &mut ranges {
        range.1 = range.1.min(size);
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Splits `ranges` into pieces of at most `piece` bytes.
pub fn split(ranges: &[(u64, u64)], piece: u64) -> Vec<(u64, u64)> {
    let piece = piece.max(1);
    let mut pieces = Vec::new();
    for &(start, end) in ranges {
        let mut position = start;
        while position < end {
            let next = position.saturating_add(piece).min(end);
            pieces.push((position, next));
            position = next;
        }
    }
    pieces
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_merge_and_missing_is_the_complement() {
        assert_eq!(normalize(vec![(10, 20), (0, 5), (5, 10), (30, 99)], 50), vec![(0, 20), (30, 50)]);
        assert_eq!(split(&[(0, 10), (20, 25)], 4), vec![(0, 4), (4, 8), (8, 10), (20, 24), (24, 25)]);
    }

    #[test]
    fn resumes_only_when_the_remote_file_is_unchanged() {
        let directory = std::env::temp_dir().join(format!("rsftp-partial-{}", std::process::id()));
        let destination = directory.join("file.bin");
        let partial = Partial::open(&destination, "/remote/file.bin", 100, Some(7)).unwrap();
        partial.mark_done(0, 40);
        partial.mark_done(60, 100);
        assert_eq!(partial.missing(), vec![(40, 60)]);
        drop(partial);

        let resumed = Partial::open(&destination, "/remote/file.bin", 100, Some(7)).unwrap();
        assert_eq!(resumed.done_bytes(), 80);
        drop(resumed);

        let changed = Partial::open(&destination, "/remote/file.bin", 100, Some(8)).unwrap();
        assert_eq!(changed.done_bytes(), 0);
        changed.mark_done(0, 100);
        assert!(changed.is_complete());
        changed.discard();
        let _ = fs::remove_dir_all(&directory);
    }
}
