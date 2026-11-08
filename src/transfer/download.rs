//! Bounded, retrying SFTP range-download engine.
//!
//! Each segment is fetched through its own SFTP file handle and written
//! directly into its assigned byte range in one pre-sized temporary file.
//! Positional writes avoid a shared seek cursor and are safe for concurrent
//! workers on both Unix and Windows.

use std::{
    fs::OpenOptions as StdOpenOptions,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use russh_sftp::client::SftpSession;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt},
    sync::{mpsc, Semaphore},
    task::JoinSet,
};

use super::{plan_download_segments, SegmentRange, TransferSettings};

const RETRIES: usize = 3;
const BUFFER_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct SegmentProgress {
    pub index: u32,
    pub start: u64,
    pub end_exclusive: u64,
    pub transferred_bytes: u64,
    pub complete: bool,
    pub failed: bool,
}

#[derive(Debug, Clone)]
pub struct DownloadProgress {
    pub total_bytes: u64,
    pub transferred_bytes: u64,
    pub completed_segments: u32,
    pub total_segments: u32,
    pub segment: Option<SegmentProgress>,
    /// Relative path of the file within a recursive transfer.
    pub file_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DownloadResult {
    pub bytes: u64,
    pub segments: u32,
    pub segmented: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("remote file size is unavailable")]
    UnknownSize,
    #[error("download range planner: {0}")]
    Plan(#[from] super::SegmentPlanError),
    #[error("SFTP error: {0}")]
    Sftp(String),
    #[error("local filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("segment {index} failed after {attempts} attempts: {message}")]
    Segment { index: u32, attempts: usize, message: String },
    #[error("segment worker failed: {0}")]
    Worker(String),
    #[error("download size mismatch: expected {expected} bytes, wrote {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
}

/// Download a remote regular file using concurrent positional writes.
///
/// The temporary output is created and sized once. Each worker writes only
/// within its non-overlapping range using platform-native positional I/O:
/// FileExt::write_at on Unix and FileExt::seek_write on Windows. No worker
/// changes a shared file cursor, and the output handle remains open until all
/// workers have stopped. The file is flushed and validated before publication.
pub async fn download_file(
    sftp: Arc<SftpSession>,
    remote_path: &str,
    destination: &Path,
    settings: TransferSettings,
    progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
) -> Result<DownloadResult, DownloadError> {
    let metadata = sftp.metadata(remote_path.to_owned()).await
        .map_err(|e| DownloadError::Sftp(e.to_string()))?;
    let size = metadata.size.ok_or(DownloadError::UnknownSize)?;
    let plan = plan_download_segments(size, settings)?;
    let total_segments = plan.segments.len() as u32;

    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).await?;
    let temp_destination = temporary_destination(destination);

    // create_new prevents accidentally reusing a stale temporary file. On
    // Windows the handle is deliberately kept open until every worker exits.
    let output = StdOpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .open(&temp_destination)?;
    output.set_len(size)?;
    let output = Arc::new(output);

    if size == 0 {
        output.sync_all()?;
        drop(output);
        publish_temporary_file(&temp_destination, destination).await?;
        if let Some(tx) = &progress {
            let _ = tx.send(DownloadProgress {
                total_bytes: 0, transferred_bytes: 0,
                completed_segments: 0, total_segments: 0, segment: None,
            
                file_path: None,});
        }
        return Ok(DownloadResult { bytes: 0, segments: 0, segmented: false });
    }

    if let Some(tx) = &progress {
        for range in &plan.segments {
            let _ = tx.send(DownloadProgress {
                total_bytes: size,
                transferred_bytes: 0,
                completed_segments: 0,
                total_segments,
                segment: Some(SegmentProgress {
                    index: range.index, start: range.start,
                    end_exclusive: range.end_exclusive,
                    transferred_bytes: 0, complete: false, failed: false,
                }),
            
                file_path: None,});
        }
    }

    let transferred = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let completed = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let permits = Arc::new(Semaphore::new(settings.max_segments_per_file.max(1) as usize));
    let mut workers = JoinSet::new();

    for range in plan.segments.iter().copied() {
        let session = Arc::clone(&sftp);
        let remote = remote_path.to_owned();
        let output_file = Arc::clone(&output);
        let permit_pool = Arc::clone(&permits);
        let progress_tx = progress.clone();
        let transferred_bytes = Arc::clone(&transferred);
        let completed_segments = Arc::clone(&completed);

        workers.spawn(async move {
            let _permit = permit_pool.acquire_owned().await
                .map_err(|e| DownloadError::Worker(e.to_string()))?;
            fetch_segment(
                session, &remote, output_file, range, size,
                progress_tx, transferred_bytes, completed_segments, total_segments,
            ).await
        });
    }

    let mut failure = None;
    while let Some(joined) = workers.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if failure.is_none() {
                    failure = Some(error);
                }
            }
            Err(error) => {
                if failure.is_none() {
                    failure = Some(DownloadError::Worker(error.to_string()));
                }
            }
        }
    }

    // Let every worker exit before closing the output handle. In particular,
    // this ensures no spawn_blocking positional write is still active on
    // Windows when the temporary file is cleaned up or renamed.

    if let Some(error) = failure {
        drop(output);
        let _ = fs::remove_file(&temp_destination).await;
        return Err(error);
    }

    output.sync_all()?;
    drop(output);

    // The file is pre-sized, so metadata length alone cannot prove every byte
    // was received. Verify the successful segment byte count as well.
    let written = transferred.load(std::sync::atomic::Ordering::Relaxed);
    let actual = fs::metadata(&temp_destination).await?.len();
    if written != size || actual != size {
        let _ = fs::remove_file(&temp_destination).await;
        return Err(DownloadError::SizeMismatch {
            expected: size,
            actual: written.min(actual),
        });
    }

    publish_temporary_file(&temp_destination, destination).await?;
    Ok(DownloadResult { bytes: size, segments: total_segments, segmented: plan.is_segmented() })
}

async fn publish_temporary_file(temp: &Path, destination: &Path) -> Result<(), DownloadError> {
    // std::fs::rename does not replace an existing destination on Windows.
    // Close our handles first, then remove the old file and rename. If another
    // process has it open without delete sharing, Windows returns an I/O error.
    if fs::try_exists(destination).await? {
        fs::remove_file(destination).await?;
    }
    fs::rename(temp, destination).await?;
    Ok(())
}

async fn fetch_segment(
    sftp: Arc<SftpSession>,
    remote_path: &str,
    output: Arc<std::fs::File>,
    range: SegmentRange,
    total_size: u64,
    progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
    transferred: Arc<std::sync::atomic::AtomicU64>,
    completed: Arc<std::sync::atomic::AtomicU32>,
    total_segments: u32,
) -> Result<(), DownloadError> {
    let mut last_error = String::new();

    for attempt in 1..=RETRIES {
        let mut attempt_transferred = 0_u64;
        let result = async {
            let mut remote = sftp.open(remote_path.to_owned()).await
                .map_err(|e| e.to_string())?;
            remote.seek(std::io::SeekFrom::Start(range.start)).await
                .map_err(|e| e.to_string())?;

            let mut remaining = range.len();
            let mut offset = range.start;
            let mut buffer = vec![0_u8; BUFFER_SIZE];

            while remaining > 0 {
                let wanted = remaining.min(buffer.len() as u64) as usize;
                let read = remote.read(&mut buffer[..wanted]).await.map_err(|e| e.to_string())?;
                if read == 0 {
                    return Err(format!("unexpected EOF at byte {offset}"));
                }

                let chunk = buffer[..read].to_vec();
                let file = Arc::clone(&output);
                let write_offset = offset;
                tokio::task::spawn_blocking(move || write_all_at(&file, &chunk, write_offset))
                    .await
                    .map_err(|e| format!("local write worker failed: {e}"))?
                    .map_err(|e| e.to_string())?;

                offset += read as u64;
                remaining -= read as u64;
                attempt_transferred += read as u64;
                let now = transferred.fetch_add(read as u64, std::sync::atomic::Ordering::Relaxed) + read as u64;
                if let Some(tx) = &progress {
                    let _ = tx.send(DownloadProgress {
                        total_bytes: total_size,
                        transferred_bytes: now,
                        completed_segments: completed.load(std::sync::atomic::Ordering::Relaxed),
                        total_segments,
                        segment: Some(SegmentProgress {
                            index: range.index, start: range.start, end_exclusive: range.end_exclusive,
                            transferred_bytes: attempt_transferred, complete: false, failed: false,
                        }),
                    
                file_path: None,});
                }
            }
            Ok::<(), String>(())
        }.await;

        match result {
            Ok(()) => {
                let done = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if let Some(tx) = &progress {
                    let _ = tx.send(DownloadProgress {
                        total_bytes: total_size,
                        transferred_bytes: transferred.load(std::sync::atomic::Ordering::Relaxed),
                        completed_segments: done, total_segments,
                        segment: Some(SegmentProgress {
                            index: range.index, start: range.start, end_exclusive: range.end_exclusive,
                            transferred_bytes: range.len(), complete: true, failed: false,
                        }),
                    
                file_path: None,});
                }
                return Ok(());
            }
            Err(error) => {
                last_error = error;
                if attempt_transferred > 0 {
                    transferred.fetch_sub(attempt_transferred, std::sync::atomic::Ordering::Relaxed);
                    if let Some(tx) = &progress {
                        let _ = tx.send(DownloadProgress {
                            total_bytes: total_size,
                            transferred_bytes: transferred.load(std::sync::atomic::Ordering::Relaxed),
                            completed_segments: completed.load(std::sync::atomic::Ordering::Relaxed),
                            total_segments,
                            segment: Some(SegmentProgress {
                                index: range.index, start: range.start, end_exclusive: range.end_exclusive,
                                transferred_bytes: 0, complete: false, failed: false,
                            }),
                        
                file_path: None,});
                    }
                }
                if attempt < RETRIES {
                    tokio::time::sleep(Duration::from_millis(250 * attempt as u64)).await;
                }
            }
        }
    }

    if let Some(tx) = &progress {
        let _ = tx.send(DownloadProgress {
            total_bytes: total_size,
            transferred_bytes: transferred.load(std::sync::atomic::Ordering::Relaxed),
            completed_segments: completed.load(std::sync::atomic::Ordering::Relaxed),
            total_segments,
            segment: Some(SegmentProgress {
                index: range.index, start: range.start, end_exclusive: range.end_exclusive,
                transferred_bytes: 0, complete: false, failed: true,
            }),
        
                file_path: None,});
    }

    Err(DownloadError::Segment { index: range.index, attempts: RETRIES, message: last_error })
}

#[cfg(unix)]
fn write_all_at(file: &std::fs::File, mut buffer: &[u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    while !buffer.is_empty() {
        let written = file.write_at(buffer, offset)?;
        if written == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "failed to write download chunk"));
        }
        offset += written as u64;
        buffer = &buffer[written..];
    }
    Ok(())
}

#[cfg(windows)]
fn write_all_at(file: &std::fs::File, mut buffer: &[u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buffer.is_empty() {
        let written = file.seek_write(buffer, offset)?;
        if written == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "failed to write download chunk"));
        }
        offset += written as u64;
        buffer = &buffer[written..];
    }
    Ok(())
}

fn temporary_destination(destination: &Path) -> PathBuf {
    let name = destination.file_name().unwrap_or_default().to_string_lossy();
    destination.with_file_name(format!(".{name}.sftp-download-{}.tmp", std::process::id()))
}
