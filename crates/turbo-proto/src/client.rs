//! Client side: fetches verified segments of a file over UDP.
//!
//! One [`Connection`] per download is shared by several [`SegmentFetcher`]s,
//! each with its own UDP socket so their replies never mix. All fetchers of a
//! download share one [`Congestion`] controller: a window of requested but
//! unreceived chunks plus a pacing rate for requests. It tolerates a little
//! random loss and backs off gently when loss exceeds that.
//!
//! A fetcher asks for a segment's data right away and for its XXH3-128 digest
//! as soon as every chunk has been requested once, so verification usually
//! costs no extra round trip. Lost chunks are re-requested after a timeout.

use std::{
    collections::VecDeque,
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use tokio::{net::UdpSocket, time::timeout};

use crate::{
    ticket::Ticket,
    wire::{
        data_packet_len, digest, Direction, Message, PacketCipher, SegmentStatus, CHUNK_SIZE, LARGE_CHUNK,
        MAX_PACKET, MAX_READ_LEN,
    },
};

/// Chunks asked for by one READ.
const BATCH_CHUNKS: usize = 64;
/// Smallest READ when the shared window is nearly full.
const MIN_BATCH_CHUNKS: usize = 16;
/// Shared window of a download, in chunks.
const INITIAL_WINDOW: usize = 256;
const MIN_WINDOW: usize = 64;
/// ≈ 45 MB in flight per download.
const MAX_WINDOW: usize = 32_768;
/// Loss per round trip that is treated as noise rather than congestion.
const LOSS_TOLERANCE: f64 = 0.02;
/// Window factor when loss exceeds the tolerance.
const DECREASE: f64 = 0.7;
/// Requests are paced at this multiple of window / RTT.
const PACING_GAIN: f64 = 1.25;
const INITIAL_RTO: Duration = Duration::from_millis(500);
/// Floor for request timeouts: data queued behind earlier bursts arrives
/// late, and re-requesting it too early only adds duplicate traffic.
const MIN_RTO: Duration = Duration::from_millis(200);
const MAX_RTO: Duration = Duration::from_secs(3);
/// How often waiting loops re-check for cancellation.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const PROBE_ATTEMPTS: u32 = 4;
const DIGEST_ATTEMPTS: u32 = 6;
/// A segment attempt fails after this long without receiving any data.
const STALL_LIMIT: Duration = Duration::from_secs(10);
/// Requested UDP receive buffer, so bursts are not dropped by the client's
/// own kernel. The OS may cap it (Linux: `net.core.rmem_max`).
const RECEIVE_BUFFER: usize = 8 * 1024 * 1024;
/// Fits one GRO-coalesced receive (up to 64 KiB).
const RECEIVE_CHUNK: usize = 65_536 + MAX_PACKET;

#[derive(Debug)]
pub enum FetchError {
    /// Nothing answered: the daemon is not running or UDP is blocked.
    Unreachable,
    /// The server stopped answering in the middle of a segment.
    Timeout,
    /// The data received did not match the server's digest.
    HashMismatch,
    /// The file changed on the server during the download.
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
            FetchError::HashMismatch => f.write_str("segment failed XXH3-128 verification"),
            FetchError::FileChanged => f.write_str("the file changed on the server during the download"),
            FetchError::Server(message) => write!(f, "server error: {message}"),
            FetchError::Cancelled => f.write_str("cancelled"),
            FetchError::Io(error) => write!(f, "UDP error: {error}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// Counters for diagnosing throughput.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FetchStats {
    /// Chunks asked for, including re-requests.
    pub chunks_requested: u64,
    /// Distinct chunks that arrived.
    pub chunks_received: u64,
    /// Chunks that arrived although already received (late or duplicated).
    pub duplicate_chunks: u64,
    /// Rounds in which loss exceeded the tolerance (window reductions).
    pub loss_events: u64,
    /// Request timeouts after which nothing at all had arrived for a while.
    pub stalls: u64,
    pub peak_window: usize,
    /// Time spent waiting for digests after a segment's data had all arrived.
    pub digest_wait: Duration,
    pub smoothed_rtt: Option<Duration>,
    /// Chunk size used for this download.
    pub chunk_size: usize,
}

impl FetchStats {
    pub fn merge(&mut self, other: &FetchStats) {
        self.chunks_requested += other.chunks_requested;
        self.chunks_received += other.chunks_received;
        self.duplicate_chunks += other.duplicate_chunks;
        // Window figures come from the shared controller: not additive.
        self.loss_events = self.loss_events.max(other.loss_events);
        self.peak_window = self.peak_window.max(other.peak_window);
        self.stalls += other.stalls;
        self.digest_wait += other.digest_wait;
        self.smoothed_rtt = self.smoothed_rtt.or(other.smoothed_rtt);
        self.chunk_size = self.chunk_size.max(other.chunk_size);
    }

    /// Share of requested chunks that did not arrive for their request.
    pub fn loss_ratio(&self) -> f64 {
        if self.chunks_requested == 0 {
            0.0
        } else {
            1.0 - (self.chunks_received as f64 / self.chunks_requested as f64).min(1.0)
        }
    }
}

struct CongestionState {
    slow_start: bool,
    round_start: Instant,
    delivered: u64,
    lost: u64,
    max_in_flight: usize,
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    next_send: Instant,
    peak_window: usize,
    loss_events: u64,
}

/// Window and pacing shared by all fetchers of one download.
pub struct Congestion {
    window: AtomicUsize,
    in_flight: AtomicUsize,
    state: Mutex<CongestionState>,
}

impl Default for Congestion {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            window: AtomicUsize::new(INITIAL_WINDOW),
            in_flight: AtomicUsize::new(0),
            state: Mutex::new(CongestionState {
                slow_start: true,
                round_start: now,
                delivered: 0,
                lost: 0,
                max_in_flight: 0,
                srtt: None,
                rttvar: Duration::ZERO,
                rto: INITIAL_RTO,
                next_send: now,
                peak_window: INITIAL_WINDOW,
                loss_events: 0,
            }),
        }
    }
}

impl Congestion {
    /// Claims room for `chunks` more chunks in flight, if the window allows.
    pub fn try_reserve(&self, chunks: usize) -> bool {
        let window = self.window.load(Ordering::Relaxed);
        self.in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |in_flight| {
                (in_flight + chunks <= window).then_some(in_flight + chunks)
            })
            .is_ok()
    }

    /// Claims room for between `min` and `max` chunks; returns how many (0 if
    /// fewer than `min` fit).
    pub fn try_reserve_up_to(&self, max: usize, min: usize) -> usize {
        let window = self.window.load(Ordering::Relaxed);
        let mut granted = 0;
        let _ = self.in_flight.fetch_update(Ordering::AcqRel, Ordering::Acquire, |in_flight| {
            granted = window.saturating_sub(in_flight).min(max);
            (granted >= min).then_some(in_flight + granted)
        });
        if granted >= min { granted } else { 0 }
    }

    pub fn release(&self, chunks: usize) {
        if chunks > 0 {
            let _ = self.in_flight.fetch_update(Ordering::AcqRel, Ordering::Acquire, |in_flight| {
                Some(in_flight.saturating_sub(chunks))
            });
        }
    }

    pub fn rto(&self) -> Duration {
        self.state.lock().map(|state| state.rto).unwrap_or(INITIAL_RTO)
    }

    pub fn srtt(&self) -> Option<Duration> {
        self.state.lock().ok().and_then(|state| state.srtt)
    }

    pub fn sample_rtt(&self, sample: Duration) {
        let Ok(mut state) = self.state.lock() else { return };
        match state.srtt {
            None => {
                state.srtt = Some(sample);
                state.rttvar = sample / 2;
            }
            Some(srtt) => {
                let deviation = if srtt > sample { srtt - sample } else { sample - srtt };
                state.rttvar = (state.rttvar * 3 + deviation) / 4;
                state.srtt = Some((srtt * 7 + sample) / 8);
            }
        }
        let srtt = state.srtt.unwrap_or(sample);
        // At least twice the smoothed RTT: the variance estimate alone reacts
        // too slowly to queueing delay that builds up during a burst.
        state.rto = (srtt + state.rttvar * 4).max(srtt * 2).clamp(MIN_RTO, MAX_RTO);
    }

    /// Time at which a request for `bytes` may be sent (pacing at
    /// `PACING_GAIN` × window / RTT).
    pub fn pace(&self, bytes: usize, chunk: usize) -> Instant {
        let now = Instant::now();
        let Ok(mut state) = self.state.lock() else { return now };
        let srtt = state.srtt.unwrap_or(INITIAL_RTO).as_secs_f64().max(0.001);
        let window_bytes = (self.window.load(Ordering::Relaxed) * chunk) as f64;
        let rate = (window_bytes / srtt * PACING_GAIN).max(1.0);
        let interval = Duration::from_secs_f64(bytes as f64 / rate);
        let slot = state.next_send.max(now);
        state.next_send = slot + interval;
        slot
    }

    /// Feeds delivery and loss counts; about once per RTT the window is
    /// adjusted: doubled in slow start, grown by 1/8 afterwards, reduced to
    /// 70% when loss exceeds the tolerance, unchanged if it was not used.
    pub fn report(&self, delivered: u64, lost: u64) {
        let Ok(mut state) = self.state.lock() else { return };
        state.delivered += delivered;
        state.lost += lost;
        let in_flight = self.in_flight.load(Ordering::Relaxed);
        state.max_in_flight = state.max_in_flight.max(in_flight);
        let now = Instant::now();
        let round = state.srtt.unwrap_or(INITIAL_RTO);
        let total = state.delivered + state.lost;
        if now.saturating_duration_since(state.round_start) < round || total == 0 {
            return;
        }
        let window = self.window.load(Ordering::Relaxed);
        let loss = state.lost as f64 / total as f64;
        let used = state.max_in_flight * 2 >= window;
        let next = if loss > LOSS_TOLERANCE {
            state.slow_start = false;
            state.loss_events += 1;
            (window as f64 * DECREASE) as usize
        } else if !used {
            window
        } else if state.slow_start {
            window * 2
        } else {
            window + BATCH_CHUNKS.max(window / 8)
        };
        let next = next.clamp(MIN_WINDOW, MAX_WINDOW);
        self.window.store(next, Ordering::Relaxed);
        state.peak_window = state.peak_window.max(next);
        state.round_start = now;
        state.delivered = 0;
        state.lost = 0;
        state.max_in_flight = in_flight;
    }

    fn snapshot(&self) -> (usize, u64) {
        self.state.lock().map(|state| (state.peak_window, state.loss_events)).unwrap_or_default()
    }
}

/// State shared by all fetchers of one download.
pub struct Connection {
    pub server: SocketAddr,
    pub transfer: u64,
    cipher: PacketCipher,
    counter: AtomicU64,
    next_request: AtomicU32,
    chunk: AtomicUsize,
    pub congestion: Congestion,
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
            chunk: AtomicUsize::new(CHUNK_SIZE),
            congestion: Congestion::default(),
        }))
    }

    fn seal(&self, message: &Message) -> Vec<u8> {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        self.cipher.seal(Direction::ToServer, self.transfer, counter, message)
    }

    fn request_id(&self) -> u32 {
        self.next_request.fetch_add(1, Ordering::Relaxed)
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk.load(Ordering::Relaxed)
    }

    /// Checks that the server answers over UDP and picks the chunk size:
    /// [`LARGE_CHUNK`] if a full-size probe reply gets through, otherwise
    /// [`CHUNK_SIZE`]. Fails with `Unreachable` if nothing answers.
    pub async fn negotiate(&self, cancelled: &(dyn Fn() -> bool + Sync)) -> Result<usize, FetchError> {
        let socket = bind_for(self.server).await.map_err(FetchError::Io)?;
        let mut buffer = vec![0_u8; MAX_PACKET];
        let large = data_packet_len(LARGE_CHUNK);
        let small = data_packet_len(CHUNK_SIZE);
        let mut small_works = false;
        for attempt in 1..=PROBE_ATTEMPTS {
            let (large_id, small_id) = (self.request_id(), self.request_id());
            let sent_at = Instant::now();
            for (request, size) in [(large_id, large), (small_id, small)] {
                if let Err(error) = socket.send(&self.seal(&Message::Probe { request, size: size as u16 })).await {
                    return Err(if is_unreachable(&error) { FetchError::Unreachable } else { FetchError::Io(error) });
                }
            }
            let deadline = sent_at + Duration::from_millis(400) * attempt;
            loop {
                if cancelled() {
                    return Err(FetchError::Cancelled);
                }
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                match timeout((deadline - now).min(POLL_INTERVAL), socket.recv(&mut buffer)).await {
                    Err(_) => {}
                    Ok(Err(error)) if is_unreachable(&error) => return Err(FetchError::Unreachable),
                    Ok(Err(error)) => return Err(FetchError::Io(error)),
                    Ok(Ok(len)) => match self.cipher.open(Direction::ToClient, &buffer[..len]) {
                        Ok((header, Message::ProbeReply { request, .. })) if header.transfer == self.transfer => {
                            self.congestion.sample_rtt(sent_at.elapsed());
                            if request == large_id && len == large {
                                self.chunk.store(LARGE_CHUNK, Ordering::Relaxed);
                                return Ok(LARGE_CHUNK);
                            }
                            if request == small_id {
                                small_works = true;
                            }
                        }
                        Ok((header, Message::Error { message })) if header.transfer == self.transfer => {
                            return Err(FetchError::Server(message));
                        }
                        _ => {}
                    },
                }
            }
            if small_works {
                self.chunk.store(CHUNK_SIZE, Ordering::Relaxed);
                return Ok(CHUNK_SIZE);
            }
        }
        Err(FetchError::Unreachable)
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

pub struct SegmentFetcher {
    conn: Arc<Connection>,
    socket: UdpSocket,
    buffer: Vec<u8>,
    inbox: Vec<Message>,
    /// Linux UDP GRO: the kernel hands over many datagrams per receive.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    gro: bool,
    stats: FetchStats,
}

impl SegmentFetcher {
    pub async fn new(conn: Arc<Connection>) -> Result<Self, FetchError> {
        let socket = bind_for(conn.server).await.map_err(FetchError::Io)?;
        #[cfg(target_os = "linux")]
        let gro = nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::UdpGroSegment, &true).is_ok();
        #[cfg(not(target_os = "linux"))]
        let gro = false;
        Ok(Self {
            conn,
            socket,
            buffer: vec![0_u8; RECEIVE_CHUNK],
            inbox: Vec::with_capacity(1024),
            gro,
            stats: FetchStats::default(),
        })
    }

    /// Counters since this fetcher was created (window figures are shared).
    pub fn stats(&self) -> FetchStats {
        let (peak_window, loss_events) = self.conn.congestion.snapshot();
        FetchStats {
            peak_window,
            loss_events,
            smoothed_rtt: self.conn.congestion.srtt(),
            chunk_size: self.conn.chunk_size(),
            ..self.stats
        }
    }

    async fn send(&self, message: &Message) -> Result<(), FetchError> {
        match self.socket.send(&self.conn.seal(message)).await {
            Ok(_) => Ok(()),
            Err(error) if is_unreachable(&error) => Err(FetchError::Unreachable),
            Err(error) => Err(FetchError::Io(error)),
        }
    }

    /// Waits up to `wait` for data, then moves every queued packet of this
    /// transfer into `self.inbox`.
    async fn receive_batch(&mut self, wait: Duration) -> Result<(), FetchError> {
        match timeout(wait, self.socket.readable()).await {
            Err(_) => return Ok(()),
            Ok(Err(error)) => return Err(FetchError::Io(error)),
            Ok(Ok(())) => {}
        }
        loop {
            match self.receive_one() {
                Ok((len, segment)) => {
                    let segment = if segment == 0 { len } else { segment };
                    let mut start = 0;
                    while start < len {
                        let end = (start + segment).min(len);
                        if let Ok((header, message)) = self.conn.cipher.open(Direction::ToClient, &self.buffer[start..end]) {
                            if header.transfer == self.conn.transfer {
                                self.inbox.push(message);
                            }
                        }
                        start = end;
                    }
                    if self.inbox.len() >= 4096 {
                        return Ok(());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if is_unreachable(&error) => return Err(FetchError::Unreachable),
                Err(error) => return Err(FetchError::Io(error)),
            }
        }
    }

    /// One non-blocking receive: (bytes, GRO segment size or 0).
    fn receive_one(&mut self) -> io::Result<(usize, usize)> {
        #[cfg(target_os = "linux")]
        if self.gro {
            use std::os::fd::AsRawFd;
            let fd = self.socket.as_raw_fd();
            let buffer = &mut self.buffer;
            return self.socket.try_io(tokio::io::Interest::READABLE, || receive_gro(fd, buffer));
        }
        let len = self.socket.try_recv(&mut self.buffer)?;
        Ok((len, 0))
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
        // Chunks this fetcher holds in the shared window; always given back.
        let mut reserved = 0_usize;
        let result = self.fetch_inner(offset, len, progress, cancelled, &mut reserved).await;
        self.conn.congestion.release(reserved);
        result
    }

    async fn fetch_inner(
        &mut self,
        offset: u64,
        len: u32,
        progress: &mut (dyn FnMut(u64) + Send),
        cancelled: &(dyn Fn() -> bool + Sync),
        reserved: &mut usize,
    ) -> Result<Vec<u8>, FetchError> {
        let conn = Arc::clone(&self.conn);
        let chunk = conn.chunk_size();
        let len_usize = len as usize;
        let chunk_count = len_usize.div_ceil(chunk);
        let max_batch = BATCH_CHUNKS.min(MAX_READ_LEN as usize / chunk);
        let mut data = vec![0_u8; len_usize];
        let mut state = vec![Chunk::Missing; chunk_count];
        let mut requested_before = vec![false; chunk_count];
        let mut received_chunks = 0_usize;
        let mut received_bytes = 0_u64;
        let mut cursor = 0_usize;
        let mut batches: VecDeque<Batch> = VecDeque::new();
        let mut last_progress = Instant::now();
        let mut expected: Option<u128> = None;
        // (request id, deadline) of the outstanding DIGEST request.
        let mut digest_request: Option<(u32, Instant)> = None;
        let mut digest_attempts = 0_u32;
        let mut waiting_since: Option<Instant> = None;

        loop {
            if cancelled() {
                return Err(FetchError::Cancelled);
            }
            if received_chunks == chunk_count {
                if let Some(expected) = expected {
                    if let Some(since) = waiting_since {
                        self.stats.digest_wait += since.elapsed();
                    }
                    if digest(&data) != expected {
                        return Err(FetchError::HashMismatch);
                    }
                    return Ok(data);
                }
                waiting_since.get_or_insert_with(Instant::now);
            }

            // Ask for missing chunks while the shared window has room.
            loop {
                if chunk_count - received_chunks - *reserved == 0 {
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
                while end < chunk_count && end - start < max_batch && state[end] == Chunk::Missing {
                    end += 1;
                }
                let count = conn.congestion.try_reserve_up_to(end - start, MIN_BATCH_CHUNKS.min(end - start));
                if count == 0 {
                    break;
                }
                let end = start + count;
                *reserved += count;
                let byte_start = start * chunk;
                let byte_end = (end * chunk).min(len_usize);
                let slot = conn.congestion.pace(byte_end - byte_start, chunk);
                if slot > Instant::now() + Duration::from_millis(1) {
                    tokio::time::sleep_until(slot.into()).await;
                }
                let mut retransmission = false;
                for index in start..end {
                    state[index] = Chunk::InFlight;
                    retransmission |= requested_before[index];
                    requested_before[index] = true;
                }
                cursor = end;
                self.stats.chunks_requested += count as u64;
                let request = conn.request_id();
                self.send(&Message::Read {
                    request,
                    offset: offset + byte_start as u64,
                    len: (byte_end - byte_start) as u32,
                    chunk: chunk as u16,
                })
                .await?;
                let now = Instant::now();
                batches.push_back(Batch { start, end, sent_at: now, deadline: now + conn.congestion.rto(), retransmission });
            }

            // Once everything has been requested, ask for the digest; it
            // arrives together with the last data.
            let all_requested = received_chunks + *reserved == chunk_count;
            if expected.is_none() && digest_request.is_none() && all_requested {
                let request = conn.request_id();
                self.send(&Message::Digest { request, offset, len }).await?;
                let deadline = Instant::now() + conn.congestion.rto().max(INITIAL_RTO);
                digest_request = Some((request, deadline));
            }

            // Wait for packets until the earliest deadline.
            let now = Instant::now();
            let deadline = batches
                .iter()
                .map(|batch| batch.deadline)
                .chain(digest_request.map(|(_, deadline)| deadline))
                .min()
                .unwrap_or(now + POLL_INTERVAL);
            self.receive_batch(deadline.saturating_duration_since(now).min(POLL_INTERVAL)).await?;

            let mut delivered = 0_u64;
            let mut inbox = std::mem::take(&mut self.inbox);
            for message in inbox.drain(..) {
                match message {
                    Message::Data { offset: chunk_offset, data: bytes } => {
                        let Some(index) = chunk_index(offset, len_usize, chunk_offset, bytes.len(), chunk) else { continue };
                        if state[index] == Chunk::Received {
                            self.stats.duplicate_chunks += 1;
                            continue;
                        }
                        if state[index] == Chunk::InFlight {
                            *reserved -= 1;
                            conn.congestion.release(1);
                        }
                        state[index] = Chunk::Received;
                        let start = index * chunk;
                        data[start..start + bytes.len()].copy_from_slice(&bytes);
                        received_chunks += 1;
                        received_bytes += bytes.len() as u64;
                        delivered += 1;
                        self.stats.chunks_received += 1;
                        last_progress = Instant::now();
                    }
                    Message::DigestInfo { request, status, xxh3, .. } => {
                        if digest_request.is_some_and(|(asked, _)| asked == request) {
                            match status {
                                SegmentStatus::Ok => expected = Some(xxh3),
                                SegmentStatus::FileChanged => return Err(FetchError::FileChanged),
                                SegmentStatus::OutOfRange => return Err(FetchError::Server("segment outside the file".into())),
                                SegmentStatus::IoError => return Err(FetchError::Server("read error on the server".into())),
                            }
                        }
                    }
                    Message::Error { message } => return Err(FetchError::Server(message)),
                    _ => {}
                }
            }
            self.inbox = inbox;
            if delivered > 0 {
                progress(received_bytes);
            }

            // Retire finished batches; re-queue the chunks of timed-out ones.
            let now = Instant::now();
            let mut lost = 0_u64;
            let mut released = 0_usize;
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
                            released += 1;
                            lost += 1;
                            cursor = cursor.min(index);
                        }
                    }
                    return false;
                }
                true
            });
            *reserved -= released;
            conn.congestion.release(released);
            for sample in samples {
                conn.congestion.sample_rtt(sample);
            }
            conn.congestion.report(delivered, lost);

            if let Some((_, deadline)) = digest_request {
                if expected.is_none() && now >= deadline {
                    digest_request = None; // asked again on the next pass
                    digest_attempts += 1;
                    if digest_attempts >= DIGEST_ATTEMPTS {
                        return Err(FetchError::Timeout);
                    }
                }
            }
            if lost > 0 && now.saturating_duration_since(last_progress) >= conn.congestion.rto() {
                self.stats.stalls += 1;
            }
            // Only time a stall while something is actually requested; a
            // fetcher waiting for room in the shared window is not stalled.
            if *reserved == 0 {
                last_progress = now;
            }
            if received_chunks < chunk_count && now.saturating_duration_since(last_progress) >= STALL_LIMIT {
                return Err(FetchError::Timeout);
            }
        }
    }
}

/// Receives one (possibly GRO-coalesced) datagram and its segment size.
#[cfg(target_os = "linux")]
fn receive_gro(fd: std::os::fd::RawFd, buffer: &mut [u8]) -> io::Result<(usize, usize)> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};

    let mut cmsg = nix::cmsg_space!(i32);
    let mut iov = [io::IoSliceMut::new(buffer)];
    let message = recvmsg::<()>(fd, &mut iov, Some(cmsg.as_mut_slice()), MsgFlags::empty()).map_err(io::Error::from)?;
    let mut segment = 0;
    for control in message.cmsgs().map_err(io::Error::from)? {
        if let ControlMessageOwned::UdpGroSegments(size) = control {
            segment = usize::try_from(size).unwrap_or(0);
        }
    }
    Ok((message.bytes, segment))
}

/// Index of the chunk at `chunk_offset`, if it belongs to this segment and has
/// the exact length that chunk must have.
fn chunk_index(segment_offset: u64, segment_len: usize, chunk_offset: u64, chunk_len: usize, chunk: usize) -> Option<usize> {
    let relative = usize::try_from(chunk_offset.checked_sub(segment_offset)?).ok()?;
    if relative >= segment_len || relative % chunk != 0 {
        return None;
    }
    let expected_len = chunk.min(segment_len - relative);
    (chunk_len == expected_len).then_some(relative / chunk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_index_accepts_only_exact_chunks_of_the_segment() {
        let chunk = CHUNK_SIZE;
        let len = chunk * 3 + 10;
        assert_eq!(chunk_index(1000, len, 1000, chunk, chunk), Some(0));
        assert_eq!(chunk_index(1000, len, 1000 + chunk as u64 * 3, 10, chunk), Some(3));
        assert_eq!(chunk_index(1000, len, 1000 + chunk as u64 * 3, chunk, chunk), None);
        assert_eq!(chunk_index(1000, len, 999, chunk, chunk), None);
        assert_eq!(chunk_index(1000, len, 1001, chunk, chunk), None);
        assert_eq!(chunk_index(1000, len, 1000 + len as u64, 1, chunk), None);
        assert_eq!(chunk_index(0, 5000, LARGE_CHUNK as u64, LARGE_CHUNK, LARGE_CHUNK), Some(1));
    }

    #[test]
    fn congestion_window_is_shared_and_reacts_to_loss() {
        let congestion = Congestion::default();
        assert!(congestion.try_reserve(INITIAL_WINDOW));
        assert!(!congestion.try_reserve(1));
        congestion.release(INITIAL_WINDOW);
        assert!(congestion.try_reserve(1));
        congestion.release(1);

        congestion.sample_rtt(Duration::from_millis(1));
        assert!(congestion.try_reserve(INITIAL_WINDOW));
        std::thread::sleep(Duration::from_millis(3));
        congestion.report(1000, 0); // clean round with a full window: slow start doubles
        assert_eq!(congestion.window.load(Ordering::Relaxed), INITIAL_WINDOW * 2);
        std::thread::sleep(Duration::from_millis(3));
        congestion.report(900, 100); // 10% loss: back off
        let reduced = (INITIAL_WINDOW as f64 * 2.0 * DECREASE) as usize;
        assert_eq!(congestion.window.load(Ordering::Relaxed), reduced);
        std::thread::sleep(Duration::from_millis(3));
        congestion.report(990, 10); // 1% loss is tolerated
        assert!(congestion.window.load(Ordering::Relaxed) >= reduced);
    }
}
