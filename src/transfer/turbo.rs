//! Downloads over rsftp-turbo (UDP).
//!
//! Fills the missing ranges of a [`Partial`] download: a probe first checks
//! that the service answers and picks the packet size, then a bounded number
//! of workers fetch fixed-size pieces, each verified against the server's
//! XXH3-128 digest, write them with positional writes and record them in the
//! partial file. Failed or corrupted pieces are fetched again up to
//! [`RETRIES`] times. Whatever is left when turbo gives up is finished by the
//! SFTP engine.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use rsftp_turbo_proto::{
    client::{Connection, FetchError, FetchStats, SegmentFetcher},
    Ticket, MAX_SEGMENT_LEN,
};
use tokio::{sync::mpsc, task::JoinSet};

use super::{
    download::write_all_at,
    partial::{split, Partial},
    CancelToken, DownloadError, DownloadProgress, DownloadResult, SegmentProgress, SegmentRange, TransferSettings,
};

/// Largest piece: each one is held in memory until its digest is verified.
const MAX_TURBO_SEGMENT: u64 = 8 * 1024 * 1024;
const MIN_TURBO_SEGMENT: u64 = 256 * 1024;
const RETRIES: usize = 3;
/// Progress is reported every this many bytes per piece.
const PROGRESS_STEP: u64 = 256 * 1024;

#[allow(dead_code)] // the messages are kept for debugging
pub enum TurboError {
    /// The service did not answer at all; use SFTP instead.
    Unavailable(String),
    Failed(DownloadError),
}

impl From<DownloadError> for TurboError {
    fn from(error: DownloadError) -> Self {
        TurboError::Failed(error)
    }
}

impl From<std::io::Error> for TurboError {
    fn from(error: std::io::Error) -> Self {
        TurboError::Failed(DownloadError::Io(error))
    }
}

/// Splits missing ranges into pieces of the configured segment size (at most 8 MiB).
pub fn plan(missing: &[(u64, u64)], settings: TransferSettings) -> Vec<(u64, u64)> {
    let piece = settings
        .target_segment_size_bytes
        .clamp(MIN_TURBO_SEGMENT, MAX_TURBO_SEGMENT.min(u64::from(MAX_SEGMENT_LEN)));
    split(missing, piece)
}

struct Shared {
    size: u64,
    total_segments: u32,
    transferred: AtomicU64,
    completed: AtomicU32,
    progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
    stats: Mutex<FetchStats>,
    retried_segments: AtomicU32,
    workers: usize,
}

impl Shared {
    fn report(&self, range: SegmentRange, segment_bytes: u64, complete: bool, failed: bool) {
        if let Some(tx) = &self.progress {
            let _ = tx.send(DownloadProgress {
                total_bytes: self.size,
                transferred_bytes: self.transferred.load(Ordering::Relaxed),
                completed_segments: self.completed.load(Ordering::Relaxed),
                total_segments: self.total_segments,
                segment: Some(SegmentProgress {
                    index: range.index,
                    start: range.start,
                    end_exclusive: range.end_exclusive,
                    transferred_bytes: segment_bytes,
                    complete,
                    failed,
                }),
                file_path: None,
                file_complete: false,
                accelerated: true,
            });
        }
    }
}

pub async fn download(
    server: SocketAddr,
    ticket: &Ticket,
    partial: &Arc<Partial>,
    settings: TransferSettings,
    progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
    cancel: CancelToken,
) -> Result<DownloadResult, TurboError> {
    if cancel.is_cancelled() {
        return Err(TurboError::Failed(DownloadError::Cancelled));
    }
    let connection = Connection::new(server, ticket).map_err(|error| TurboError::Unavailable(error.to_string()))?;
    match connection.negotiate(&|| cancel.is_cancelled()).await {
        Ok(_) => {}
        Err(FetchError::Cancelled) => return Err(TurboError::Failed(DownloadError::Cancelled)),
        Err(error) => return Err(TurboError::Unavailable(error.to_string())),
    }

    let pieces: Vec<SegmentRange> = plan(&partial.missing(), settings)
        .into_iter()
        .map(|(start, end_exclusive)| SegmentRange { index: partial.next_index(), start, end_exclusive })
        .collect();
    let workers = (settings.max_segments_per_file.max(1) as usize).min(pieces.len());
    let shared = Arc::new(Shared {
        size: partial.size,
        total_segments: pieces.len() as u32,
        transferred: AtomicU64::new(partial.done_bytes()),
        completed: AtomicU32::new(0),
        progress,
        stats: Mutex::new(FetchStats::default()),
        retried_segments: AtomicU32::new(0),
        workers,
    });
    for range in &pieces {
        shared.report(*range, 0, false, false);
    }
    let queue = Arc::new(Mutex::new(pieces.into_iter().collect::<VecDeque<_>>()));
    // Stops the remaining workers when one fails for good.
    let abort = CancelToken::new();
    let mut tasks = JoinSet::new();
    for _ in 0..workers {
        let connection = Arc::clone(&connection);
        let queue = Arc::clone(&queue);
        let shared = Arc::clone(&shared);
        let partial = Arc::clone(partial);
        let (cancel, abort) = (cancel.clone(), abort.clone());
        tasks.spawn(async move {
            let result = worker(connection, queue, shared, partial, &cancel, &abort).await;
            if result.is_err() {
                abort.cancel();
            }
            result
        });
    }

    let mut failure: Option<TurboError> = None;
    while let Some(joined) = tasks.join_next().await {
        let result = joined.unwrap_or_else(|error| Err(TurboError::Failed(DownloadError::Worker(error.to_string()))));
        if let Err(error) = result {
            // Workers stopped because another one failed report "cancelled";
            // keep the error that actually caused the failure.
            let is_fallout = |error: &TurboError| matches!(error, TurboError::Failed(DownloadError::Cancelled));
            if failure.as_ref().is_none_or(|kept| is_fallout(kept) && !is_fallout(&error)) {
                failure = Some(error);
            }
        }
    }
    if cancel.is_cancelled() {
        failure = Some(TurboError::Failed(DownloadError::Cancelled));
    }
    // Best effort: let the server forget the transfer right away.
    connection.close().await;
    if let Some(error) = failure {
        // Completed pieces stay recorded in `partial` for SFTP or a resume.
        return Err(error);
    }
    Ok(DownloadResult {
        bytes: partial.size,
        segments: shared.total_segments,
        segmented: shared.total_segments > 1,
        accelerated: true,
        details: Some(summary(&shared)),
    })
}

async fn worker(
    connection: Arc<Connection>,
    queue: Arc<Mutex<VecDeque<SegmentRange>>>,
    shared: Arc<Shared>,
    partial: Arc<Partial>,
    cancel: &CancelToken,
    abort: &CancelToken,
) -> Result<(), TurboError> {
    let mut fetcher = SegmentFetcher::new(connection).await.map_err(|error| TurboError::Unavailable(error.to_string()))?;
    let result = fetch_pieces(&mut fetcher, &queue, &shared, &partial, cancel, abort).await;
    if let Ok(mut stats) = shared.stats.lock() {
        stats.merge(&fetcher.stats());
    }
    result
}

async fn fetch_pieces(
    fetcher: &mut SegmentFetcher,
    queue: &Mutex<VecDeque<SegmentRange>>,
    shared: &Shared,
    partial: &Arc<Partial>,
    cancel: &CancelToken,
    abort: &CancelToken,
) -> Result<(), TurboError> {
    let stopped = || cancel.is_cancelled() || abort.is_cancelled();
    loop {
        let next = queue.lock().ok().and_then(|mut queue| queue.pop_front());
        let Some(range) = next else { return Ok(()) };
        let len = range.len() as u32;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut counted = 0_u64;
            let mut last_report = 0_u64;
            let result = fetcher
                .fetch(
                    range.start,
                    len,
                    &mut |bytes| {
                        shared.transferred.fetch_add(bytes - counted, Ordering::Relaxed);
                        counted = bytes;
                        if bytes - last_report >= PROGRESS_STEP {
                            last_report = bytes;
                            shared.report(range, bytes, false, false);
                        }
                    },
                    &stopped,
                )
                .await;
            match result {
                Ok(data) => {
                    let file = partial.file();
                    let offset = range.start;
                    tokio::task::spawn_blocking(move || write_all_at(&file, &data, offset))
                        .await
                        .map_err(|error| DownloadError::Worker(error.to_string()))??;
                    partial.mark_done(range.start, range.end_exclusive);
                    shared.completed.fetch_add(1, Ordering::Relaxed);
                    shared.report(range, range.len(), true, false);
                    break;
                }
                Err(error) => {
                    // Discard this attempt's bytes from the total.
                    shared.transferred.fetch_sub(counted, Ordering::Relaxed);
                    if matches!(error, FetchError::Cancelled) || stopped() {
                        return Err(TurboError::Failed(DownloadError::Cancelled));
                    }
                    if error.is_retryable() && attempt < RETRIES {
                        shared.retried_segments.fetch_add(1, Ordering::Relaxed);
                        shared.report(range, 0, false, false);
                        tokio::time::sleep(Duration::from_millis(250 * attempt as u64)).await;
                        continue;
                    }
                    shared.report(range, 0, false, true);
                    return Err(TurboError::Failed(DownloadError::Turbo(format!(
                        "piece at byte {} failed after {attempt} attempt(s): {error}",
                        range.start
                    ))));
                }
            }
        }
    }
}

/// One-line statistics for the log and the transfer tooltip.
fn summary(shared: &Shared) -> String {
    let stats = shared.stats.lock().map(|stats| *stats).unwrap_or_default();
    let rtt = stats.smoothed_rtt.map(|rtt| format!("{} ms", rtt.as_millis())).unwrap_or_else(|| "?".into());
    format!(
        "turbo: {} workers, {} pieces ({} retried), {}-byte chunks, loss {:.1}% ({} of {} chunks re-requested, \\
         {} duplicates), {} congestion events, {} stalls, peak window {} chunks, RTT {rtt}, \\
         waited {:.1} s for digests",
        shared.workers,
        shared.total_segments,
        shared.retried_segments.load(Ordering::Relaxed),
        stats.chunk_size,
        stats.loss_ratio() * 100.0,
        stats.chunks_requested.saturating_sub(stats.chunks_received),
        stats.chunks_requested,
        stats.duplicate_chunks,
        stats.loss_events,
        stats.stalls,
        stats.peak_window,
        stats.digest_wait.as_secs_f64(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_uses_bounded_contiguous_pieces() {
        let settings = TransferSettings::default(); // 8 MiB target
        let size = 20 * 1024 * 1024 + 5;
        let pieces = plan(&[(0, size)], settings);
        assert_eq!(pieces.len(), 3);
        assert!(pieces.windows(2).all(|pair| pair[0].1 == pair[1].0));
        assert_eq!(pieces.last().unwrap().1, size);
        assert!(pieces.iter().all(|(start, end)| end - start <= MAX_TURBO_SEGMENT));
        assert!(plan(&[], settings).is_empty());
        let huge_target = TransferSettings { target_segment_size_bytes: 1 << 40, ..settings };
        assert!(plan(&[(0, size)], huge_target).iter().all(|(start, end)| end - start <= MAX_TURBO_SEGMENT));
        // Only the gaps of a partial download are planned.
        assert_eq!(plan(&[(100, 200), (300, 400)], settings), vec![(100, 200), (300, 400)]);
    }
}
