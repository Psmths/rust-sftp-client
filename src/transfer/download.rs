//! Bounded, retrying SFTP range-download engine.
//!
//! Each segment is fetched through its own SFTP file handle. Segment data is
//! streamed to disk (never buffered as a whole file), then concatenated in
//! range order and atomically renamed into place.

use std::{path::{Path, PathBuf}, sync::Arc, time::Duration};

use russh_sftp::client::SftpSession;
use tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
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

/// Download a remote regular file using the configured byte-range plan.
///
/// The remote SFTP session is shared across independently opened file handles.
/// Each range is streamed to a temporary part file, retried up to three times,
/// and assembled only after every range has completed successfully. The final
/// destination is replaced only after the assembled file has been flushed.
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

    if size == 0 {
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).await?;
        let temp = temporary_destination(destination);
        File::create(&temp).await?.sync_all().await?;
        fs::rename(&temp, destination).await?;
        if let Some(tx) = &progress {
            let _ = tx.send(DownloadProgress {
                total_bytes: 0, transferred_bytes: 0,
                completed_segments: 0, total_segments: 0, segment: None,
            });
        }
        return Ok(DownloadResult { bytes: 0, segments: 0, segmented: false });
    }

    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).await?;
    let work_dir = temporary_directory(destination);
    fs::create_dir_all(&work_dir).await?;

    if let Some(tx) = &progress {
        for range in &plan.segments {
            let _ = tx.send(DownloadProgress {
                total_bytes: size,
                transferred_bytes: 0,
                completed_segments: 0,
                total_segments,
                segment: Some(SegmentProgress {
                    index: range.index,
                    start: range.start,
                    end_exclusive: range.end_exclusive,
                    transferred_bytes: 0,
                    complete: false,
                    failed: false,
                }),
            });
        }
    }

    let transferred = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let completed = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let permits = Arc::new(Semaphore::new(settings.max_segments_per_file.max(1) as usize));
    let mut workers = JoinSet::new();

    for range in plan.segments.iter().copied() {
        let session = Arc::clone(&sftp);
        let remote = remote_path.to_owned();
        let part_path = part_path(&work_dir, range.index);
        let permit_pool = Arc::clone(&permits);
        let progress_tx = progress.clone();
        let transferred_bytes = Arc::clone(&transferred);
        let completed_segments = Arc::clone(&completed);

        workers.spawn(async move {
            let _permit = permit_pool.acquire_owned().await
                .map_err(|e| DownloadError::Worker(e.to_string()))?;
            fetch_segment(
                session, &remote, &part_path, range, size,
                progress_tx, transferred_bytes, completed_segments, total_segments,
            ).await
        });
    }

    let mut failure = None;
    while let Some(joined) = workers.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) => { failure = Some(error); workers.abort_all(); break; }
            Err(error) => { failure = Some(DownloadError::Worker(error.to_string())); workers.abort_all(); break; }
        }
    }

    if let Some(error) = failure {
        let _ = fs::remove_dir_all(&work_dir).await;
        return Err(error);
    }

    let temp_destination = temporary_destination(destination);
    let mut assembled = OpenOptions::new().create(true).truncate(true).write(true).open(&temp_destination).await?;
    for range in &plan.segments {
        let mut part = File::open(part_path(&work_dir, range.index)).await?;
        tokio::io::copy(&mut part, &mut assembled).await?;
    }
    assembled.flush().await?;
    assembled.sync_all().await?;
    drop(assembled);

    let actual = fs::metadata(&temp_destination).await?.len();
    if actual != size {
        let _ = fs::remove_file(&temp_destination).await;
        let _ = fs::remove_dir_all(&work_dir).await;
        return Err(DownloadError::SizeMismatch { expected: size, actual });
    }

    // Rename is atomic when source and destination are on the same filesystem.
    if destination.exists() {
        fs::remove_file(destination).await?;
    }
    fs::rename(&temp_destination, destination).await?;
    fs::remove_dir_all(&work_dir).await?;

    Ok(DownloadResult { bytes: size, segments: total_segments, segmented: plan.is_segmented() })
}

async fn fetch_segment(
    sftp: Arc<SftpSession>,
    remote_path: &str,
    part_path: &Path,
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

            let mut local = File::create(part_path).await.map_err(|e| e.to_string())?;
            let mut remaining = range.len();
            let mut buffer = vec![0_u8; BUFFER_SIZE];

            while remaining > 0 {
                let wanted = remaining.min(buffer.len() as u64) as usize;
                let read = remote.read(&mut buffer[..wanted]).await.map_err(|e| e.to_string())?;
                if read == 0 {
                    return Err(format!("unexpected EOF at byte {}", range.end_exclusive - remaining));
                }
                local.write_all(&buffer[..read]).await.map_err(|e| e.to_string())?;
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
                    });
                }
            }

            local.flush().await.map_err(|e| e.to_string())?;
            local.sync_all().await.map_err(|e| e.to_string())?;
            Ok::<(), String>(())
        }.await;

        match result {
            Ok(()) => {
                let done = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if let Some(tx) = &progress {
                    let _ = tx.send(DownloadProgress {
                        total_bytes: total_size,
                        transferred_bytes: transferred.load(std::sync::atomic::Ordering::Relaxed),
                        completed_segments: done,
                        total_segments,
                        segment: Some(SegmentProgress {
                            index: range.index, start: range.start, end_exclusive: range.end_exclusive,
                            transferred_bytes: range.len(), complete: true, failed: false,
                        }),
                    });
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
                        });
                    }
                }
                let _ = fs::remove_file(part_path).await;
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
        });
    }

    Err(DownloadError::Segment {
        index: range.index, attempts: RETRIES, message: last_error,
    })
}

fn part_path(directory: &Path, index: u32) -> PathBuf {
    directory.join(format!("segment-{index:04}.part"))
}

fn temporary_directory(destination: &Path) -> PathBuf {
    let name = destination.file_name().unwrap_or_default().to_string_lossy();
    destination.with_file_name(format!(".{name}.sftp-parts-{}", std::process::id()))
}

fn temporary_destination(destination: &Path) -> PathBuf {
    let name = destination.file_name().unwrap_or_default().to_string_lossy();
    destination.with_file_name(format!(".{name}.sftp-download-{}.tmp", std::process::id()))
}
