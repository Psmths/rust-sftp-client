//! Downloads over rsftp-turbo (UDP), protocol version 1.
//!
//! Fills the missing ranges of a [`Partial`] download: segments are fetched by
//! a bounded number of workers, each verified against the server's SHA-256
//! digest, written with positional writes and recorded in the partial file.
//! Failed or corrupted segments are fetched again up to [`RETRIES`] times.
//! Whatever is left when turbo gives up is finished by the SFTP engine.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use rsftp_turbo_proto::{
    client::{Connection, FetchError, FetchStats, SegmentFetcher},
    Ticket, MAX_SEGMENT_LEN,
};
use tokio::{
    sync::{mpsc, Semaphore},
    task::JoinSet,
};

use super::{
    download::write_all_at,
    partial::{split, Partial},
    CancelToken, DownloadError, DownloadProgress, DownloadResult, SegmentProgress, SegmentRange, TransferSettings,
};

/// Largest segment: each one is held in memory until its digest is verified.
const MAX_TURBO_SEGMENT: u64 = 8 * 1024 * 1024;
const MIN_TURBO_SEGMENT: u64 = 256 * 1024;
/// Attempts per segment before it is left to SFTP.
const RETRIES: usize = 5;
/// Turbo gives up on a file (SFTP finishes it) once this many segments in a
/// row have failed for good: the service is then likely unusable.
const GIVE_UP_AFTER: u32 = 3;
/// Segments fetched at the same time over one connection, across all of its
/// downloads, unless "Workers per file" is higher. Every fetcher has its own
/// congestion window; with several files at once (4 files x 8 workers) they
/// overrun the link and the server, and segments fail.
pub const CONNECTION_FETCH_SLOTS: usize = 16;
/// Progress is reported every this many bytes per segment.
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

/// Splits missing ranges into segments of the configured segment size (at most 8 MiB).
pub fn plan(missing: &[(u64, u64)], settings: TransferSettings) -> Vec<(u64, u64)> {
    let segment = settings
        .target_segment_size_bytes
        .clamp(MIN_TURBO_SEGMENT, MAX_TURBO_SEGMENT.min(u64::from(MAX_SEGMENT_LEN)));
    split(missing, segment)
}

struct Shared {
    size: u64,
    total_segments: u32,
    transferred: AtomicU64,
    completed: AtomicU32,
    /// Set once the server has answered; before that, silence means
    /// "unavailable" rather than "failed".
    reachable: AtomicBool,
    progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
    stats: Mutex<FetchStats>,
    retried_segments: AtomicU32,
    /// Segments that failed for good and were left to SFTP.
    skipped_segments: AtomicU32,
    /// Segments in a row that failed for good (reset by any success).
    failures_in_row: AtomicU32,
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
                file_complete: false, accelerated: true,
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
    slots: Arc<Semaphore>,
) -> Result<DownloadResult, TurboError> {
    if cancel.is_cancelled() {
        return Err(TurboError::Failed(DownloadError::Cancelled));
    }
    let size = partial.size;
    let segments: Vec<SegmentRange> = plan(&partial.missing(), settings)
        .into_iter()
        .map(|(start, end_exclusive)| SegmentRange { index: partial.next_index(), start, end_exclusive })
        .collect();
    if segments.is_empty() {
        return Ok(DownloadResult { bytes: size, segments: 0, segmented: false, accelerated: true, details: None });
    }
    let connection = Connection::new(server, ticket).map_err(|error| TurboError::Unavailable(error.to_string()))?;

    let workers = (settings.max_segments_per_file.max(1) as usize).min(segments.len());
    let shared = Arc::new(Shared {
        size,
        total_segments: segments.len() as u32,
        transferred: AtomicU64::new(partial.done_bytes()),
        completed: AtomicU32::new(0),
        reachable: AtomicBool::new(false),
        progress,
        stats: Mutex::new(FetchStats::default()),
        retried_segments: AtomicU32::new(0),
        skipped_segments: AtomicU32::new(0),
        failures_in_row: AtomicU32::new(0),
        workers,
    });
    for range in &segments {
        shared.report(*range, 0, false, false);
    }
    let queue = Arc::new(Mutex::new(segments.into_iter().collect::<VecDeque<_>>()));
    // Stops the remaining workers when one fails for good.
    let abort = CancelToken::new();
    let mut tasks = JoinSet::new();
    for _ in 0..workers {
        let connection = Arc::clone(&connection);
        let queue = Arc::clone(&queue);
        let shared = Arc::clone(&shared);
        let partial = Arc::clone(partial);
        let slots = Arc::clone(&slots);
        let (cancel, abort) = (cancel.clone(), abort.clone());
        tasks.spawn(async move {
            let result = worker(connection, queue, shared, partial, slots, &cancel, &abort).await;
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
    // A user cancellation always reports as such.
    if cancel.is_cancelled() {
        failure = Some(TurboError::Failed(DownloadError::Cancelled));
    }

    // Best effort: let the server forget the transfer right away.
    connection.close().await;
    if let Some(error) = failure {
        // Completed segments stay recorded in `partial` for SFTP or a resume.
        return Err(error);
    }
    // The caller checks that every byte is recorded and publishes the file.
    Ok(DownloadResult {
        bytes: size,
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
    slots: Arc<Semaphore>,
    cancel: &CancelToken,
    abort: &CancelToken,
) -> Result<(), TurboError> {
    let mut fetcher = SegmentFetcher::new(connection).await.map_err(|error| TurboError::Unavailable(error.to_string()))?;
    let result = fetch_segments(&mut fetcher, &queue, &shared, &partial, &slots, cancel, abort).await;
    if let Ok(mut stats) = shared.stats.lock() {
        stats.merge(&fetcher.stats());
    }
    result
}

async fn fetch_segments(
    fetcher: &mut SegmentFetcher,
    queue: &Mutex<VecDeque<SegmentRange>>,
    shared: &Shared,
    partial: &Arc<Partial>,
    slots: &Semaphore,
    cancel: &CancelToken,
    abort: &CancelToken,
) -> Result<(), TurboError> {
    let stopped = || cancel.is_cancelled() || abort.is_cancelled();
    let take = || queue.lock().ok().and_then(|mut queue| queue.pop_front());
    // Each worker holds the segment it fetches next, so it can ask for that
    // segment's digest while the current one finishes.
    let mut upcoming = take();
    while let Some(range) = upcoming.take() {
        upcoming = take();
        let next = upcoming.map(|next| (next.start, next.len() as u32));
        let len = range.len() as u32;
        let mut attempt = 0;
        loop {
            attempt += 1;
            // Wait for a free fetch slot of this connection.
            let _slot = tokio::select! {
                slot = slots.acquire() => slot.map_err(|error| DownloadError::Worker(error.to_string()))?,
                _ = cancel.cancelled() => return Err(TurboError::Failed(DownloadError::Cancelled)),
                _ = abort.cancelled() => return Err(TurboError::Failed(DownloadError::Cancelled)),
            };
            let mut counted = 0_u64;
            let mut last_report = 0_u64;
            let result = fetcher
                .fetch_ahead(
                    range.start,
                    len,
                    next,
                    &mut |bytes| {
                        shared.reachable.store(true, Ordering::Relaxed);
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
            drop(_slot);
            match result {
                Ok(data) => {
                    shared.reachable.store(true, Ordering::Relaxed);
                    let file = partial.file();
                    let offset = range.start;
                    tokio::task::spawn_blocking(move || write_all_at(&file, &data, offset))
                        .await
                        .map_err(|error| DownloadError::Worker(error.to_string()))??;
                    partial.mark_done(range.start, range.end_exclusive);
                    shared.completed.fetch_add(1, Ordering::Relaxed);
                    shared.failures_in_row.store(0, Ordering::Relaxed);
                    shared.report(range, range.len(), true, false);
                    break;
                }
                Err(error) => {
                    // Discard this attempt's bytes from the total.
                    shared.transferred.fetch_sub(counted, Ordering::Relaxed);
                    if matches!(error, FetchError::Cancelled) || stopped() {
                        return Err(TurboError::Failed(DownloadError::Cancelled));
                    }
                    let reachable = shared.reachable.load(Ordering::Relaxed);
                    if matches!(error, FetchError::Unreachable) && !reachable {
                        return Err(TurboError::Unavailable(error.to_string()));
                    }
                    // The whole file changed: SFTP has to start over too.
                    if matches!(error, FetchError::FileChanged) {
                        shared.report(range, 0, false, true);
                        return Err(TurboError::Failed(DownloadError::Turbo(error.to_string())));
                    }
                    // A service that answered before and then stopped is
                    // usually just overloaded: try again.
                    let retryable = error.is_retryable() || matches!(error, FetchError::Unreachable);
                    if retryable && attempt < RETRIES {
                        shared.retried_segments.fetch_add(1, Ordering::Relaxed);
                        shared.report(range, 0, false, false);
                        tokio::time::sleep(Duration::from_millis(250 * attempt as u64)).await;
                        continue;
                    }
                    // Leave this segment to SFTP and carry on with the others,
                    // unless segments keep failing.
                    shared.report(range, 0, false, true);
                    shared.skipped_segments.fetch_add(1, Ordering::Relaxed);
                    let in_row = shared.failures_in_row.fetch_add(1, Ordering::Relaxed) + 1;
                    if in_row >= GIVE_UP_AFTER {
                        return Err(TurboError::Failed(DownloadError::Turbo(format!(
                            "{in_row} segments in a row failed after {attempt} attempt(s) each; last error: {error}"
                        ))));
                    }
                    break;
                }
            }
        }
    }
    Ok(())
}

/// One-line statistics for the log and the transfer tooltip.
fn summary(shared: &Shared) -> String {
    let stats = shared.stats.lock().map(|stats| *stats).unwrap_or_default();
    let rtt = stats.smoothed_rtt.map(|rtt| format!("{} ms", rtt.as_millis())).unwrap_or_else(|| "?".into());
    format!(
        "turbo: {} workers, {} segments ({} retried, {} left to SFTP), loss {:.1}% ({} of {} packets re-requested, \
         {} duplicates), {} congestion events, {} stalls, peak window {} packets, RTT {rtt}, waited {:.1} s for segment hashes \
         ({} of them requested ahead)",
        shared.workers,
        shared.total_segments,
        shared.retried_segments.load(Ordering::Relaxed),
        shared.skipped_segments.load(Ordering::Relaxed),
        stats.loss_ratio() * 100.0,
        stats.chunks_requested.saturating_sub(stats.chunks_received),
        stats.chunks_requested,
        stats.duplicate_chunks,
        stats.loss_events,
        stats.stalls,
        stats.peak_window,
        stats.open_wait.as_secs_f64(),
        stats.digests_ahead,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_uses_bounded_contiguous_segments() {
        let settings = TransferSettings::default(); // 8 MiB target
        let size = 20 * 1024 * 1024 + 5;
        let segments = plan(&[(0, size)], settings);
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].0, 0);
        assert!(segments.windows(2).all(|pair| pair[0].1 == pair[1].0));
        assert_eq!(segments.last().unwrap().1, size);
        assert!(segments.iter().all(|(start, end)| end - start <= MAX_TURBO_SEGMENT));
        assert!(plan(&[], settings).is_empty());
        let huge_target = TransferSettings { target_segment_size_bytes: 1 << 40, ..settings };
        assert!(plan(&[(0, size)], huge_target).iter().all(|(start, end)| end - start <= MAX_TURBO_SEGMENT));
        // Only the gaps of a partial download are planned.
        assert_eq!(plan(&[(100, 200), (300, 400)], settings), vec![(100, 200), (300, 400)]);
    }
}
