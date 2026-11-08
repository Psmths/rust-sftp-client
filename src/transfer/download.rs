//! Bounded, retrying SFTP range-download engine.
//!
//! Each piece is fetched through its own SFTP file handle (pieces are spread
//! round-robin over the connection's SFTP channels) and written directly into
//! its byte range of the pre-sized partial file (see `partial.rs`).
//! Positional writes avoid a shared seek cursor and are safe for concurrent
//! workers on both Unix and Windows.

use std::{path::Path, sync::Arc, time::Duration};

use russh_sftp::client::SftpSession;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt},
    sync::{mpsc, Semaphore},
    task::JoinSet,
};

use super::{partial::Partial, CancelToken, SegmentRange, TransferSettings};

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
    /// True only for the terminal update of an individual recursive file.
    pub file_complete: bool,
    /// The bytes are arriving over rsftp-turbo (UDP) rather than SSH/SFTP.
    pub accelerated: bool,
}

#[derive(Debug, Clone)]
pub struct DownloadResult {
    pub bytes: u64,
    pub segments: u32,
    pub segmented: bool,
    /// Downloaded over rsftp-turbo (UDP) rather than SFTP.
    pub accelerated: bool,
    /// Diagnostic summary (rsftp-turbo statistics), for logs and tooltips.
    pub details: Option<String>,
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
    #[error("cancelled")]
    Cancelled,
    #[error("rsftp-turbo: {0}")]
    Turbo(String),
}

/// Downloads the missing ranges of `partial` over SFTP.
///
/// Missing ranges are split into a few large pieces (one per worker, each at
/// least the configured segment size) that workers fetch through their own
/// SFTP handles and write with positional writes. Completed pieces are
/// recorded in `partial`; the caller publishes the file when it is complete.
pub async fn download_file(
    sessions: Vec<Arc<SftpSession>>,
    remote_path: &str,
    partial: &Arc<Partial>,
    settings: TransferSettings,
    progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
    cancel: CancelToken,
) -> Result<DownloadResult, DownloadError> {
    if cancel.is_cancelled() {
        return Err(DownloadError::Cancelled);
    }
    if sessions.is_empty() {
        return Err(DownloadError::Worker("no SFTP channel available".into()));
    }
    let size = partial.size;
    let missing = partial.missing();
    let missing_bytes: u64 = missing.iter().map(|(start, end)| end - start).sum();
    if missing_bytes == 0 {
        return Ok(DownloadResult { bytes: size, segments: 0, segmented: false, accelerated: false, details: None });
    }
    if settings.target_segment_size_bytes == 0 || settings.max_segments_per_file == 0 {
        return Err(DownloadError::Plan(super::SegmentPlanError::ZeroSegmentSize));
    }
    // Few, large pieces: each SFTP handle reads ahead past its piece's end,
    // so many small pieces would waste bandwidth.
    let piece_len = if missing_bytes < settings.segmentation_threshold_bytes {
        u64::MAX
    } else {
        settings
            .target_segment_size_bytes
            .max(missing_bytes.div_ceil(u64::from(settings.max_segments_per_file)))
    };
    let pieces: Vec<SegmentRange> = super::partial::split(&missing, piece_len)
        .into_iter()
        .map(|(start, end_exclusive)| SegmentRange { index: partial.next_index(), start, end_exclusive })
        .collect();
    let total_segments = pieces.len() as u32;

    if let Some(tx) = &progress {
        let done = partial.done_bytes();
        for range in &pieces {
            let _ = tx.send(DownloadProgress {
                total_bytes: size,
                transferred_bytes: done,
                completed_segments: 0,
                total_segments,
                segment: Some(SegmentProgress {
                    index: range.index, start: range.start,
                    end_exclusive: range.end_exclusive,
                    transferred_bytes: 0, complete: false, failed: false,
                }),
                file_path: None,
                file_complete: false, accelerated: false,
            });
        }
    }

    let output = partial.file();
    let transferred = Arc::new(std::sync::atomic::AtomicU64::new(partial.done_bytes()));
    let completed = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let permits = Arc::new(Semaphore::new(settings.max_segments_per_file.max(1) as usize));
    let mut workers = JoinSet::new();

    for range in pieces.iter().copied() {
        let session = Arc::clone(&sessions[range.index as usize % sessions.len()]);
        let remote = remote_path.to_owned();
        let output_file = Arc::clone(&output);
        let permit_pool = Arc::clone(&permits);
        let progress_tx = progress.clone();
        let transferred_bytes = Arc::clone(&transferred);
        let completed_segments = Arc::clone(&completed);
        let cancel = cancel.clone();
        let partial = Arc::clone(partial);

        workers.spawn(async move {
            let _permit = tokio::select! {
                permit = permit_pool.acquire_owned() => permit.map_err(|e| DownloadError::Worker(e.to_string()))?,
                _ = cancel.cancelled() => return Err(DownloadError::Cancelled),
            };
            fetch_segment(
                session, &remote, output_file, range, size,
                progress_tx, transferred_bytes, completed_segments, total_segments, cancel,
            ).await?;
            partial.mark_done(range.start, range.end_exclusive);
            Ok(())
        });
    }

    // Every worker is joined before returning, so no positional write is
    // still running when the caller publishes or discards the file.
    let mut failure = None;
    while let Some(joined) = workers.join_next().await {
        let result = joined.unwrap_or_else(|error| Err(DownloadError::Worker(error.to_string())));
        if let Err(error) = result {
            failure.get_or_insert(error);
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(DownloadResult { bytes: size, segments: total_segments, segmented: total_segments > 1, accelerated: false, details: None })
}

pub(crate) async fn publish_temporary_file(temp: &Path, destination: &Path) -> Result<(), DownloadError> {
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
    cancel: CancelToken,
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
                let read = tokio::select! {
                    read = remote.read(&mut buffer[..wanted]) => read.map_err(|e| e.to_string())?,
                    _ = cancel.cancelled() => return Err("cancelled".to_owned()),
                };
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
                    
                file_path: None,
                file_complete: false, accelerated: false,});
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
                    
                file_path: None,
                file_complete: false, accelerated: false,});
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
                        
                file_path: None,
                file_complete: false, accelerated: false,});
                    }
                }
                // A cancelled segment is not retried or reported as failed.
                if cancel.is_cancelled() {
                    return Err(DownloadError::Cancelled);
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
        
                file_path: None,
                file_complete: false, accelerated: false,});
    }

    Err(DownloadError::Segment { index: range.index, attempts: RETRIES, message: last_error })
}

#[cfg(unix)]
pub(crate) fn write_all_at(file: &std::fs::File, mut buffer: &[u8], mut offset: u64) -> std::io::Result<()> {
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
pub(crate) fn write_all_at(file: &std::fs::File, mut buffer: &[u8], mut offset: u64) -> std::io::Result<()> {
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

