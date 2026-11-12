//! Client side: fetches verified segments of a file over UDP.
//!
//! One [`Connection`] per transfer is shared by several [`SegmentFetcher`]s,
//! each with its own UDP socket so their replies never mix. A fetcher keeps a
//! congestion window of requested-but-unreceived chunks, re-requests chunks
//! whose request timed out, and verifies the segment's SHA-256 digest before
//! returning it.

use std::{
    collections::VecDeque,
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use tokio::{net::UdpSocket, time::timeout};

use crate::{
    ticket::Ticket,
    wire::{Direction, Message, PacketCipher, SegmentStatus, CHUNK_SIZE, MAX_PACKET, MAX_READ_LEN},
};

/// Chunks requested by one READ (≈ 77 KB).
const BATCH_CHUNKS: usize = 64;
const INITIAL_WINDOW: usize = 64;
const MIN_WINDOW: usize = 32;
/// Largest congestion window in chunks (≈ 2.4 MB in flight per fetcher; a
/// file uses several fetchers). Larger windows mostly overflow buffers.
const MAX_WINDOW: usize = 2048;
/// Requested UDP receive buffer, so bursts of DATA are not dropped by the
/// client's own kernel. The OS may cap it (Linux: `net.core.rmem_max`).
const RECEIVE_BUFFER: usize = 8 * 1024 * 1024;
const INITIAL_RTO: Duration = Duration::from_millis(500);
/// Floor for request timeouts: data queued behind earlier bursts arrives
/// late, and re-requesting it too early only adds duplicate traffic.
const MIN_RTO: Duration = Duration::from_millis(200);
const MAX_RTO: Duration = Duration::from_secs(3);
/// How often waiting loops re-check for cancellation.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const OPEN_ATTEMPTS: u32 = 6;
/// Shortest wait for a segment's digest before asking again. The server reads
/// and hashes the whole segment first, which takes a while when it is busy,
/// and every repeated request makes it read and hash the segment again.
const OPEN_TIMEOUT: Duration = Duration::from_secs(1);
/// A segment attempt fails after this long without receiving any data.
const STALL_LIMIT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum FetchError {
    /// Nothing answered: the daemon is not running or UDP is blocked.
    Unreachable,
    /// The server stopped answering in the middle of a segment.
    Timeout,
    /// The data received did not match the server's SHA-256 digest.
    HashMismatch,
    /// The file changed on the server since the ticket was issued.
    FileChanged,
    Server(String),
    Cancelled,
    Io(io::Error),
}

impl FetchError {
    /// Whether fetching the same segment again may succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(self, FetchError::Timeout | FetchError::HashMismatch | FetchError::Io(_))
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Unreachable => f.write_str("the rsftp-turbo service did not answer over UDP"),
            FetchError::Timeout => f.write_str("the rsftp-turbo service stopped answering"),
            FetchError::HashMismatch => f.write_str("segment failed SHA-256 verification"),
            FetchError::FileChanged => f.write_str("the file changed on the server during the download"),
            FetchError::Server(message) => write!(f, "server error: {message}"),
            FetchError::Cancelled => f.write_str("cancelled"),
            FetchError::Io(error) => write!(f, "UDP error: {error}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// State shared by all fetchers of one transfer.
pub struct Connection {
    pub server: SocketAddr,
    pub transfer: u64,
    cipher: PacketCipher,
    counter: AtomicU64,
    next_request: AtomicU32,
}

impl Connection {
    pub fn new(server: SocketAddr, ticket: &Ticket) -> Result<Arc<Self>, FetchError> {
        let key = ticket.key_bytes().ok_or_else(|| FetchError::Server("invalid transfer key in ticket".into()))?;
        Ok(Arc::new(Self {
            server,
            transfer: ticket.transfer,
            cipher: PacketCipher::new(&key),
            counter: AtomicU64::new(0),
            next_request: AtomicU32::new(1),
        }))
    }

    fn seal(&self, message: &Message) -> Vec<u8> {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        self.cipher.seal(Direction::ToServer, self.transfer, counter, message)
    }

    fn request_id(&self) -> u32 {
        self.next_request.fetch_add(1, Ordering::Relaxed)
    }

    /// Tells the server the transfer is over (best effort; it also expires).
    pub async fn close(&self) {
        if let Ok(socket) = bind_for(self.server).await {
            let _ = socket.send(&self.seal(&Message::Close)).await;
        }
    }
}

async fn bind_for(server: SocketAddr) -> io::Result<UdpSocket> {
    let local: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = socket2::Socket::new(socket2::Domain::for_address(local), socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    // Best effort: a larger buffer absorbs bursts while this task is busy.
    let _ = socket.set_recv_buffer_size(RECEIVE_BUFFER);
    socket.set_nonblocking(true)?;
    socket.bind(&local.into())?;
    let socket = UdpSocket::from_std(std::net::UdpSocket::from(socket))?;
    socket.connect(server).await?;
    Ok(socket)
}

/// An ICMP "port unreachable" surfaces as a refused/reset error on a
/// connected UDP socket: nothing listens on the turbo port.
fn is_unreachable(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Chunk {
    Missing,
    InFlight,
    Received,
}

struct Batch {
    start: usize,
    end: usize,
    sent_at: Instant,
    deadline: Instant,
    /// Contains chunks requested before: no RTT sample (Karn's rule).
    retransmission: bool,
}

/// Counters for diagnosing throughput, summed over a fetcher's lifetime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FetchStats {
    /// Chunks asked for, including re-requests.
    pub chunks_requested: u64,
    /// Distinct chunks that arrived.
    pub chunks_received: u64,
    /// Chunks that arrived although already received (late or duplicated).
    pub duplicate_chunks: u64,
    /// Window reductions after request timeouts (≈ congestion events).
    pub loss_events: u64,
    /// Timeout periods in which nothing at all arrived.
    pub stalls: u64,
    pub peak_window: usize,
    /// Time spent waiting for the server to hash segments before data flows.
    pub open_wait: Duration,
    /// Segments whose digest had been asked for ahead (see `fetch_ahead`).
    pub digests_ahead: u64,
    pub smoothed_rtt: Option<Duration>,
}

impl FetchStats {
    pub fn merge(&mut self, other: &FetchStats) {
        self.chunks_requested += other.chunks_requested;
        self.chunks_received += other.chunks_received;
        self.duplicate_chunks += other.duplicate_chunks;
        self.loss_events += other.loss_events;
        self.stalls += other.stalls;
        self.peak_window = self.peak_window.max(other.peak_window);
        self.open_wait += other.open_wait;
        self.digests_ahead += other.digests_ahead;
        self.smoothed_rtt = match (self.smoothed_rtt, other.smoothed_rtt) {
            (Some(a), Some(b)) => Some((a + b) / 2),
            (a, b) => a.or(b),
        };
    }

    /// Share of requested chunks that never arrived for their request.
    pub fn loss_ratio(&self) -> f64 {
        if self.chunks_requested == 0 {
            0.0
        } else {
            1.0 - (self.chunks_received as f64 / self.chunks_requested as f64).min(1.0)
        }
    }
}

pub struct SegmentFetcher {
    stats: FetchStats,
    conn: Arc<Connection>,
    socket: UdpSocket,
    buffer: Vec<u8>,
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    window: usize,
    ssthresh: usize,
    /// OPEN_SEGMENT sent ahead for the next segment: (request, offset, len, sent at).
    prefetch_pending: Option<(u32, u64, u32, Instant)>,
    /// Its answer: (offset, len, status, digest).
    prefetched: Option<(u64, u32, SegmentStatus, [u8; 32])>,
}

/// The digest an OPEN_SEGMENT answer carries, or the error it reports.
fn digest_result(status: SegmentStatus, sha256: [u8; 32]) -> Result<[u8; 32], FetchError> {
    match status {
        SegmentStatus::Ok => Ok(sha256),
        SegmentStatus::FileChanged => Err(FetchError::FileChanged),
        SegmentStatus::OutOfRange => Err(FetchError::Server("segment outside the file".into())),
        SegmentStatus::IoError => Err(FetchError::Server("read error on the server".into())),
    }
}

impl SegmentFetcher {
    pub async fn new(conn: Arc<Connection>) -> Result<Self, FetchError> {
        let socket = bind_for(conn.server).await.map_err(FetchError::Io)?;
        Ok(Self {
            conn,
            socket,
            buffer: vec![0_u8; MAX_PACKET],
            srtt: None,
            rttvar: Duration::ZERO,
            rto: INITIAL_RTO,
            window: INITIAL_WINDOW,
            ssthresh: MAX_WINDOW,
            stats: FetchStats::default(),
            prefetch_pending: None,
            prefetched: None,
        })
    }

    /// Keeps the answer to a digest request sent ahead; true if `message` was one.
    fn keep_prefetched(&mut self, message: &Message) -> bool {
        if let (Message::SegmentInfo { request, status, sha256, .. }, Some((pending, offset, len, _))) =
            (message, self.prefetch_pending)
        {
            if *request == pending {
                self.prefetch_pending = None;
                self.prefetched = Some((offset, len, *status, *sha256));
                return true;
            }
        }
        false
    }

    fn sample_rtt(&mut self, sample: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(sample);
                self.rttvar = sample / 2;
            }
            Some(srtt) => {
                let deviation = if srtt > sample { srtt - sample } else { sample - srtt };
                self.rttvar = (self.rttvar * 3 + deviation) / 4;
                self.srtt = Some((srtt * 7 + sample) / 8);
            }
        }
        let srtt = self.srtt.unwrap_or(sample);
        // At least twice the smoothed RTT: the variance estimate alone reacts
        // too slowly to queueing delay that builds up during a burst.
        self.rto = (srtt + self.rttvar * 4).max(srtt * 2).clamp(MIN_RTO, MAX_RTO);
    }

    async fn send(&self, message: &Message) -> Result<(), FetchError> {
        match self.socket.send(&self.conn.seal(message)).await {
            Ok(_) => Ok(()),
            Err(error) if is_unreachable(&error) => Err(FetchError::Unreachable),
            Err(error) => Err(FetchError::Io(error)),
        }
    }

    /// Waits up to `wait` for one authenticated packet of this transfer.
    async fn receive(&mut self, wait: Duration) -> Result<Option<Message>, FetchError> {
        match timeout(wait, self.socket.recv(&mut self.buffer)).await {
            Err(_) => Ok(None),
            Ok(Err(error)) if is_unreachable(&error) => Err(FetchError::Unreachable),
            Ok(Err(error)) => Err(FetchError::Io(error)),
            Ok(Ok(len)) => match self.conn.cipher.open(Direction::ToClient, &self.buffer[..len]) {
                Ok((header, message)) if header.transfer == self.conn.transfer => Ok(Some(message)),
                // Stray or forged packets are ignored.
                _ => Ok(None),
            },
        }
    }

    /// Asks the server for the segment's digest.
    /// Counters since this fetcher was created.
    pub fn stats(&self) -> FetchStats {
        FetchStats { smoothed_rtt: self.srtt, ..self.stats }
    }

    async fn open_segment(&mut self, offset: u64, len: u32, cancelled: &(dyn Fn() -> bool + Sync)) -> Result<[u8; 32], FetchError> {
        let mut rto = self.rto.max(OPEN_TIMEOUT);
        // Asked for ahead (see `fetch_ahead`): use that answer, or wait for it.
        if let Some((pending_offset, pending_len, status, sha256)) = self.prefetched {
            if (pending_offset, pending_len) == (offset, len) {
                self.prefetched = None;
                self.stats.digests_ahead += 1;
                return digest_result(status, sha256);
            }
        }
        if let Some((request, pending_offset, pending_len, sent_at)) = self.prefetch_pending {
            if (pending_offset, pending_len) == (offset, len) {
                let deadline = sent_at + rto;
                loop {
                    if cancelled() {
                        return Err(FetchError::Cancelled);
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    match self.receive((deadline - now).min(POLL_INTERVAL)).await? {
                        Some(Message::SegmentInfo { request: answered, status, sha256, .. }) if answered == request => {
                            self.prefetch_pending = None;
                            self.stats.digests_ahead += 1;
                            return digest_result(status, sha256);
                        }
                        Some(Message::Error { message }) => return Err(FetchError::Server(message)),
                        _ => {}
                    }
                }
                // No answer in time: ask again below, with a longer wait.
                self.prefetch_pending = None;
                rto = (rto * 2).min(MAX_RTO * 2);
            }
        }
        for _ in 0..OPEN_ATTEMPTS {
            // A fresh request id and packet counter per attempt; the server
            // rejects replayed counters.
            let request = self.conn.request_id();
            let sent_at = Instant::now();
            self.send(&Message::OpenSegment { request, offset, len }).await?;
            let deadline = sent_at + rto;
            loop {
                if cancelled() {
                    return Err(FetchError::Cancelled);
                }
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let mut message = self.receive((deadline - now).min(POLL_INTERVAL)).await?;
                if message.as_ref().is_some_and(|message| self.keep_prefetched(message)) {
                    message = None;
                }
                match message {
                    Some(Message::SegmentInfo { request: answered, status, sha256, .. }) if answered == request => {
                        self.sample_rtt(sent_at.elapsed());
                        return digest_result(status, sha256);
                    }
                    Some(Message::Error { message }) => return Err(FetchError::Server(message)),
                    _ => {}
                }
            }
            rto = (rto * 2).min(MAX_RTO * 2);
        }
        Err(FetchError::Unreachable)
    }

    /// Downloads and verifies `[offset, offset + len)`.
    ///
    /// `progress` is called with the number of segment bytes received so far.
    pub async fn fetch(
        &mut self,
        offset: u64,
        len: u32,
        progress: &mut (dyn FnMut(u64) + Send),
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Vec<u8>, FetchError> {
        self.fetch_ahead(offset, len, None, progress, cancelled).await
    }

    /// Like [`fetch`](Self::fetch), and once every chunk of this segment has
    /// been requested, also asks for the digest of `next` (the segment this
    /// fetcher fetches after this one). The server reads and hashes it while
    /// this segment's last data arrives, so the next fetch usually starts
    /// without waiting for its digest. Uses only protocol version 1 messages.
    pub async fn fetch_ahead(
        &mut self,
        offset: u64,
        len: u32,
        next: Option<(u64, u32)>,
        progress: &mut (dyn FnMut(u64) + Send),
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Vec<u8>, FetchError> {
        let opened_at = Instant::now();
        let opened = self.open_segment(offset, len, cancelled).await;
        self.stats.open_wait += opened_at.elapsed();
        let expected = opened?;
        self.stats.peak_window = self.stats.peak_window.max(self.window);
        let len_usize = len as usize;
        let chunk_count = len_usize.div_ceil(CHUNK_SIZE);
        let mut data = vec![0_u8; len_usize];
        let mut state = vec![Chunk::Missing; chunk_count];
        let mut requested_before = vec![false; chunk_count];
        let mut received_chunks = 0_usize;
        let mut received_bytes = 0_u64;
        let mut in_flight = 0_usize;
        let mut cursor = 0_usize;
        let mut batches: VecDeque<Batch> = VecDeque::new();
        let mut growth_credit = 0_usize;
        let mut last_loss: Option<Instant> = None;
        let mut last_progress = Instant::now();
        let max_batch = BATCH_CHUNKS.min(MAX_READ_LEN as usize / CHUNK_SIZE);

        while received_chunks < chunk_count {
            if cancelled() {
                return Err(FetchError::Cancelled);
            }

            // Fill the congestion window with requests for missing chunks.
            while in_flight < self.window {
                // Ask in batches, not one chunk per arriving packet: wait until
                // a batch fits (or only a few chunks remain to be asked for).
                let unrequested = chunk_count - received_chunks - in_flight;
                let wanted = max_batch.min(self.window / 2).max(1).min(unrequested.max(1));
                if in_flight > 0 && self.window - in_flight < wanted {
                    break;
                }
                while cursor < chunk_count && state[cursor] != Chunk::Missing {
                    cursor += 1;
                }
                if cursor >= chunk_count {
                    break;
                }
                let start = cursor;
                let mut end = start;
                while end < chunk_count
                    && end - start < max_batch
                    && state[end] == Chunk::Missing
                    && in_flight + (end - start) < self.window
                {
                    end += 1;
                }
                if end == start {
                    break;
                }
                let mut retransmission = false;
                for index in start..end {
                    state[index] = Chunk::InFlight;
                    retransmission |= requested_before[index];
                    requested_before[index] = true;
                }
                in_flight += end - start;
                self.stats.chunks_requested += (end - start) as u64;
                cursor = end;
                let byte_start = start * CHUNK_SIZE;
                let byte_end = (end * CHUNK_SIZE).min(len_usize);
                let request = self.conn.request_id();
                self.send(&Message::Read {
                    request,
                    offset: offset + byte_start as u64,
                    len: (byte_end - byte_start) as u32,
                })
                .await?;
                let now = Instant::now();
                batches.push_back(Batch { start, end, sent_at: now, deadline: now + self.rto, retransmission });
            }

            // Every chunk has been asked for once: ask for the next digest now.
            if cursor >= chunk_count {
                if let Some((next_offset, next_len)) = next {
                    let already = self.prefetch_pending.is_some_and(|(_, o, l, _)| (o, l) == (next_offset, next_len))
                        || self.prefetched.is_some_and(|(o, l, _, _)| (o, l) == (next_offset, next_len));
                    if !already {
                        let request = self.conn.request_id();
                        self.send(&Message::OpenSegment { request, offset: next_offset, len: next_len }).await?;
                        self.prefetch_pending = Some((request, next_offset, next_len, Instant::now()));
                    }
                }
            }

            // Wait for data until the earliest request deadline.
            let now = Instant::now();
            let deadline = batches.iter().map(|batch| batch.deadline).min().unwrap_or(now + self.rto);
            let wait = deadline.saturating_duration_since(now).min(POLL_INTERVAL);
            let mut message = self.receive(wait).await?;
            if message.as_ref().is_some_and(|message| self.keep_prefetched(message)) {
                message = None;
            }
            match message {
                Some(Message::Data { offset: chunk_offset, data: chunk }) => {
                    if let Some(index) = chunk_index(offset, len_usize, chunk_offset, chunk.len()) {
                        if state[index] == Chunk::Received {
                            self.stats.duplicate_chunks += 1;
                        } else {
                            self.stats.chunks_received += 1;
                            if state[index] == Chunk::InFlight {
                                in_flight -= 1;
                            }
                            state[index] = Chunk::Received;
                            let start = index * CHUNK_SIZE;
                            data[start..start + chunk.len()].copy_from_slice(&chunk);
                            received_chunks += 1;
                            received_bytes += chunk.len() as u64;
                            progress(received_bytes);
                            last_progress = Instant::now();
                            // Slow start doubles the window per round trip;
                            // afterwards it grows by one batch per window.
                            if self.window < self.ssthresh {
                                self.window += 1;
                            } else {
                                growth_credit += 1;
                                if growth_credit >= self.window {
                                    growth_credit = 0;
                                    self.window += max_batch;
                                }
                            }
                            self.window = self.window.min(MAX_WINDOW);
                            self.stats.peak_window = self.stats.peak_window.max(self.window);
                        }
                    }
                }
                Some(Message::SegmentInfo { status: SegmentStatus::FileChanged, .. }) => return Err(FetchError::FileChanged),
                Some(Message::Error { message }) => return Err(FetchError::Server(message)),
                _ => {}
            }

            // Retire finished batches and re-queue chunks of timed-out ones.
            let now = Instant::now();
            let mut lost = false;
            let mut samples = Vec::new();
            batches.retain(|batch| {
                if (batch.start..batch.end).all(|index| state[index] == Chunk::Received) {
                    if !batch.retransmission {
                        samples.push(now.saturating_duration_since(batch.sent_at));
                    }
                    return false;
                }
                if now >= batch.deadline {
                    for index in batch.start..batch.end {
                        if state[index] == Chunk::InFlight {
                            state[index] = Chunk::Missing;
                            in_flight -= 1;
                            cursor = cursor.min(index);
                        }
                    }
                    lost = true;
                    return false;
                }
                true
            });
            for sample in samples {
                self.sample_rtt(sample);
            }
            if lost {
                // At most one window reduction per round trip.
                let srtt = self.srtt.unwrap_or(self.rto);
                if last_loss.is_none_or(|at| now.saturating_duration_since(at) > srtt) {
                    self.ssthresh = (self.window / 2).max(MIN_WINDOW);
                    self.window = self.ssthresh;
                    growth_credit = 0;
                    last_loss = Some(now);
                    self.stats.loss_events += 1;
                }
                // Many requests can expire at once after a burst of loss; only
                // a whole timeout period without any data counts as silence.
                let silent_for = now.saturating_duration_since(last_progress);
                if silent_for >= self.rto {
                    self.rto = (self.rto * 2).min(MAX_RTO);
                    self.stats.stalls += 1;
                }
                if silent_for >= STALL_LIMIT {
                    return Err(FetchError::Timeout);
                }
            }
        }

        let digest = Sha256::digest(&data);
        if digest.as_slice() != expected.as_slice() {
            return Err(FetchError::HashMismatch);
        }
        Ok(data)
    }
}

/// Index of the chunk at `chunk_offset`, if it belongs to this segment and has
/// the exact length that chunk must have.
fn chunk_index(segment_offset: u64, segment_len: usize, chunk_offset: u64, chunk_len: usize) -> Option<usize> {
    let relative = usize::try_from(chunk_offset.checked_sub(segment_offset)?).ok()?;
    if relative >= segment_len || relative % CHUNK_SIZE != 0 {
        return None;
    }
    let expected_len = CHUNK_SIZE.min(segment_len - relative);
    (chunk_len == expected_len).then_some(relative / CHUNK_SIZE)
}

#[cfg(test)]
mod tests {
    use super::chunk_index;
    use crate::CHUNK_SIZE;

    #[test]
    fn chunk_index_accepts_only_exact_chunks_of_the_segment() {
        let len = CHUNK_SIZE * 3 + 10;
        assert_eq!(chunk_index(1000, len, 1000, CHUNK_SIZE), Some(0));
        assert_eq!(chunk_index(1000, len, 1000 + CHUNK_SIZE as u64 * 3, 10), Some(3));
        assert_eq!(chunk_index(1000, len, 1000 + CHUNK_SIZE as u64 * 3, CHUNK_SIZE), None);
        assert_eq!(chunk_index(1000, len, 999, CHUNK_SIZE), None);
        assert_eq!(chunk_index(1000, len, 1001, CHUNK_SIZE), None);
        assert_eq!(chunk_index(1000, len, 1000 + len as u64, 1), None);
    }
}
