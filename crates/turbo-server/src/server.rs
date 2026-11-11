//! UDP side of the daemon.

use std::{
    collections::HashMap,
    fs::File,
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    os::unix::fs::FileExt,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime},
};

use rsftp_turbo_proto::{
    wire::{parse_header, DATA_PACKET_LEN, KEY_LEN, MAX_PACKET},
    Direction, Message, PacketCipher, ReplayWindow, SegmentStatus, CHUNK_SIZE, MAX_READ_LEN, MAX_SEGMENT_LEN,
};
use sha2::{Digest, Sha256};

/// A transfer nobody has used for this long is forgotten (and its file closed).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Upper bound on registered transfers, so local users cannot exhaust descriptors.
pub const MAX_TRANSFERS: usize = 1024;
const SEND_BUFFER: usize = 8 * 1024 * 1024;
/// DATA packets per batched send (UDP GSO allows at most 64 and 64 KiB).
#[cfg(target_os = "linux")]
const GSO_BATCH: usize = 48;
const RECEIVE_BUFFER: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Testing aid: silently drop every n-th DATA packet (0 = never).
    pub drop_data_every: u32,
}

struct Transfer {
    cipher: PacketCipher,
    file: File,
    size: u64,
    modified: Option<SystemTime>,
    /// Only requests from this address are answered.
    client_ip: Option<IpAddr>,
    counter: AtomicU64,
    replay: Mutex<ReplayWindow>,
    last_used: Mutex<Instant>,
}

impl Transfer {
    fn seal(&self, transfer: u64, message: &Message) -> Vec<u8> {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        self.cipher.seal(Direction::ToClient, transfer, counter, message)
    }

    fn unchanged(&self) -> bool {
        match self.file.metadata() {
            Ok(meta) => meta.len() == self.size && meta.modified().ok() == self.modified,
            Err(_) => false,
        }
    }

    fn in_range(&self, offset: u64, len: u32, max: u32) -> bool {
        len > 0 && len <= max && offset.checked_add(u64::from(len)).is_some_and(|end| end <= self.size)
    }

    fn read(&self, offset: u64, len: u32) -> io::Result<Vec<u8>> {
        let mut data = vec![0_u8; len as usize];
        self.file.read_exact_at(&mut data, offset)?;
        Ok(data)
    }

    fn digest(&self, offset: u64, len: u32) -> (SegmentStatus, [u8; 32]) {
        if !self.in_range(offset, len, MAX_SEGMENT_LEN) {
            return (SegmentStatus::OutOfRange, [0; 32]);
        }
        if !self.unchanged() {
            return (SegmentStatus::FileChanged, [0; 32]);
        }
        match self.read(offset, len) {
            Ok(data) => {
                let mut sha256 = [0_u8; 32];
                sha256.copy_from_slice(&Sha256::digest(&data));
                (SegmentStatus::Ok, sha256)
            }
            Err(_) => (SegmentStatus::IoError, [0; 32]),
        }
    }
}

/// What `rsftp-turbo ticket` needs to build a ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub transfer: u64,
    pub key: [u8; KEY_LEN],
    pub port: u16,
}

pub struct Server {
    socket: UdpSocket,
    transfers: RwLock<HashMap<u64, Arc<Transfer>>>,
    options: Options,
    data_sent: AtomicU32,
    /// Set when the kernel rejects batched (GSO) sends; then packets are sent one by one.
    gso_disabled: AtomicBool,
    counters: Counters,
}

/// Traffic counters, reset each time they are reported.
#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    data_packets: AtomicU64,
    data_bytes: AtomicU64,
    send_calls: AtomicU64,
    send_errors: AtomicU64,
}

/// What the server did since the previous report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrafficReport {
    pub requests: u64,
    pub data_packets: u64,
    pub data_bytes: u64,
    pub send_calls: u64,
    pub send_errors: u64,
    pub gso: bool,
    pub transfers: usize,
}

impl Server {
    pub fn bind(addr: SocketAddr, options: Options) -> io::Result<Arc<Self>> {
        let socket = open_socket(addr)?;
        Ok(Arc::new(Self {
            socket,
            transfers: RwLock::new(HashMap::new()),
            options,
            data_sent: AtomicU32::new(0),
            gso_disabled: AtomicBool::new(false),
            counters: Counters::default(),
        }))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Registers an open, readable regular file for one client.
    pub fn register(&self, file: File, client_ip: Option<IpAddr>) -> io::Result<Registration> {
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
        }
        self.expire_idle();
        let mut key = [0_u8; KEY_LEN];
        getrandom::fill(&mut key).map_err(|error| io::Error::other(error.to_string()))?;
        let port = self.local_addr()?.port();
        let mut transfers = self.transfers.write().map_err(|_| io::Error::other("transfer table poisoned"))?;
        if transfers.len() >= MAX_TRANSFERS {
            return Err(io::Error::other("too many active transfers"));
        }
        let transfer = loop {
            let id = getrandom::u64().map_err(|error| io::Error::other(error.to_string()))?;
            if id != 0 && !transfers.contains_key(&id) {
                break id;
            }
        };
        transfers.insert(
            transfer,
            Arc::new(Transfer {
                cipher: PacketCipher::new(&key),
                size: meta.len(),
                modified: meta.modified().ok(),
                file,
                client_ip: client_ip.map(|ip| ip.to_canonical()),
                counter: AtomicU64::new(0),
                replay: Mutex::new(ReplayWindow::new()),
                last_used: Mutex::new(Instant::now()),
            }),
        );
        Ok(Registration { transfer, key, port })
    }

    /// Forgets transfers that have been idle for [`IDLE_TIMEOUT`].
    pub fn expire_idle(&self) {
        if let Ok(mut transfers) = self.transfers.write() {
            transfers.retain(|_, transfer| {
                transfer.last_used.lock().map(|at| at.elapsed() < IDLE_TIMEOUT).unwrap_or(false)
            });
        }
    }

    /// Counters since the previous call.
    pub fn take_report(&self) -> TrafficReport {
        let take = |counter: &AtomicU64| counter.swap(0, Ordering::Relaxed);
        TrafficReport {
            requests: take(&self.counters.requests),
            data_packets: take(&self.counters.data_packets),
            data_bytes: take(&self.counters.data_bytes),
            send_calls: take(&self.counters.send_calls),
            send_errors: take(&self.counters.send_errors),
            gso: cfg!(target_os = "linux") && !self.gso_disabled.load(Ordering::Relaxed),
            transfers: self.active_transfers(),
        }
    }

    fn count_send(&self, result: &io::Result<usize>, packets: u64, bytes: usize) {
        self.counters.send_calls.fetch_add(1, Ordering::Relaxed);
        match result {
            Ok(_) => {
                self.counters.data_packets.fetch_add(packets, Ordering::Relaxed);
                self.counters.data_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
            }
            Err(_) => {
                self.counters.send_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn active_transfers(&self) -> usize {
        self.transfers.read().map(|transfers| transfers.len()).unwrap_or(0)
    }

    /// Starts `threads` receive loops on clones of the socket.
    pub fn spawn_workers(self: &Arc<Self>, threads: usize) -> io::Result<Vec<JoinHandle<()>>> {
        (0..threads.max(1))
            .map(|index| {
                // Each worker gets its own socket on the same port
                // (SO_REUSEPORT): the kernel then delivers all packets of one
                // client socket to the same worker, so its requests are
                // answered in order and workers don't contend for one queue.
                let socket = if index == 0 {
                    self.socket.try_clone()?
                } else {
                    match self.local_addr().and_then(open_socket) {
                        Ok(socket) => socket,
                        Err(_) => self.socket.try_clone()?,
                    }
                };
                let server = Arc::clone(self);
                thread::Builder::new()
                    .name(format!("udp-{index}"))
                    .spawn(move || server.receive_loop(&socket))
            })
            .collect()
    }

    fn receive_loop(&self, socket: &UdpSocket) {
        let mut buffer = vec![0_u8; MAX_PACKET];
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((len, from)) => self.handle(socket, &buffer[..len], from),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // ICMP errors from earlier sends (e.g. a client that went away).
                Err(_) => thread::sleep(Duration::from_millis(1)),
            }
        }
    }

    /// Handles one datagram. Anything that is not an authenticated, fresh
    /// request for a known transfer from its client's address is dropped
    /// without a reply.
    fn handle(&self, socket: &UdpSocket, packet: &[u8], from: SocketAddr) {
        let Ok(header) = parse_header(packet) else { return };
        let transfer = match self.transfers.read() {
            Ok(transfers) => match transfers.get(&header.transfer) {
                Some(transfer) => Arc::clone(transfer),
                None => return,
            },
            Err(_) => return,
        };
        if transfer.client_ip.is_some_and(|ip| ip != from.ip().to_canonical()) {
            return;
        }
        let Ok((header, message)) = transfer.cipher.open(Direction::ToServer, packet) else { return };
        let fresh = transfer.replay.lock().map(|mut window| window.accept(header.counter)).unwrap_or(false);
        if !fresh {
            return;
        }
        if let Ok(mut last_used) = transfer.last_used.lock() {
            *last_used = Instant::now();
        }
        let id = header.transfer;
        self.counters.requests.fetch_add(1, Ordering::Relaxed);
        match message {
            Message::OpenSegment { request, offset, len } => {
                let (status, sha256) = transfer.digest(offset, len);
                let reply = Message::SegmentInfo { request, offset, len, status, sha256 };
                let _ = socket.send_to(&transfer.seal(id, &reply), from);
            }
            Message::Read { offset, len, .. } => {
                if !transfer.in_range(offset, len, MAX_READ_LEN) {
                    let reply = Message::Error { message: "read outside the file".into() };
                    let _ = socket.send_to(&transfer.seal(id, &reply), from);
                    return;
                }
                let data = match transfer.read(offset, len) {
                    Ok(data) => data,
                    Err(error) => {
                        let reply = Message::Error { message: format!("read failed: {error}") };
                        let _ = socket.send_to(&transfer.seal(id, &reply), from);
                        return;
                    }
                };
                self.send_data(socket, &transfer, id, from, offset, &data);
            }
            Message::Close => {
                if let Ok(mut transfers) = self.transfers.write() {
                    transfers.remove(&id);
                }
                let _ = socket.send_to(&transfer.seal(id, &Message::Closed), from);
            }
            // Server-to-client messages are never valid requests.
            Message::SegmentInfo { .. } | Message::Data { .. } | Message::Closed | Message::Error { .. } => {}
        }
    }

    /// Sends `data` (starting at file `offset`) as DATA packets. Send errors
    /// are ignored: a full queue means the burst was too large, and the
    /// client re-requests whatever is missing.
    fn send_data(&self, socket: &UdpSocket, transfer: &Transfer, id: u64, to: SocketAddr, offset: u64, data: &[u8]) {
        #[cfg(target_os = "linux")]
        if self.options.drop_data_every == 0 && !self.gso_disabled.load(Ordering::Relaxed) {
            self.send_data_batched(socket, transfer, id, to, offset, data);
            return;
        }
        let mut packet = Vec::with_capacity(DATA_PACKET_LEN);
        for (index, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
            if self.should_drop() {
                continue;
            }
            packet.clear();
            let counter = transfer.counter.fetch_add(1, Ordering::Relaxed);
            let chunk_offset = offset + (index * CHUNK_SIZE) as u64;
            transfer.cipher.seal_data_into(Direction::ToClient, id, counter, chunk_offset, chunk, &mut packet);
            let sent = socket.send_to(&packet, to);
            self.count_send(&sent, 1, chunk.len());
        }
    }

    /// Linux: up to [`GSO_BATCH`] packets per system call using UDP
    /// segmentation offload. Falls back to single sends if unsupported.
    #[cfg(target_os = "linux")]
    fn send_data_batched(&self, socket: &UdpSocket, transfer: &Transfer, id: u64, to: SocketAddr, offset: u64, data: &[u8]) {
        let mut batch = Vec::with_capacity(GSO_BATCH * DATA_PACKET_LEN);
        for (group_index, group) in data.chunks(CHUNK_SIZE * GSO_BATCH).enumerate() {
            batch.clear();
            let group_offset = offset + (group_index * CHUNK_SIZE * GSO_BATCH) as u64;
            for (index, chunk) in group.chunks(CHUNK_SIZE).enumerate() {
                let counter = transfer.counter.fetch_add(1, Ordering::Relaxed);
                let chunk_offset = group_offset + (index * CHUNK_SIZE) as u64;
                transfer.cipher.seal_data_into(Direction::ToClient, id, counter, chunk_offset, chunk, &mut batch);
            }
            let packets = group.len().div_ceil(CHUNK_SIZE) as u64;
            if group.len() <= CHUNK_SIZE {
                let sent = socket.send_to(&batch, to);
                self.count_send(&sent, packets, group.len());
                continue;
            }
            match send_gso(socket, &batch, to) {
                Ok(sent) => self.count_send(&Ok(sent), packets, group.len()),
                Err(error) => {
                    use nix::errno::Errno;
                    if matches!(error, Errno::EINVAL | Errno::EIO | Errno::ENOPROTOOPT | Errno::EOPNOTSUPP) {
                        // No GSO on this kernel/interface: from now on send singly.
                        if !self.gso_disabled.swap(true, Ordering::Relaxed) {
                            eprintln!("rsftp-turbo: batched UDP sends (GSO) not supported here ({error}); sending packets one by one");
                        }
                        for (packet, chunk) in batch.chunks(DATA_PACKET_LEN).zip(group.chunks(CHUNK_SIZE)) {
                            let sent = socket.send_to(packet, to);
                            self.count_send(&sent, 1, chunk.len());
                        }
                    } else {
                        self.count_send(&Err(io::Error::from(error)), packets, group.len());
                    }
                }
            }
        }
    }

    fn should_drop(&self) -> bool {
        let every = self.options.drop_data_every;
        every > 0 && self.data_sent.fetch_add(1, Ordering::Relaxed) % every == every - 1
    }
}

/// One `sendmsg` carrying several equally sized datagrams (the last may be
/// shorter); the kernel or NIC splits them (UDP_SEGMENT, Linux 4.18+).
#[cfg(target_os = "linux")]
fn send_gso(socket: &UdpSocket, batch: &[u8], to: SocketAddr) -> nix::Result<usize> {
    use std::{io::IoSlice, os::fd::AsRawFd};

    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, SockaddrStorage};

    let segment = DATA_PACKET_LEN as u16;
    let address = SockaddrStorage::from(to);
    sendmsg(
        socket.as_raw_fd(),
        &[IoSlice::new(batch)],
        &[ControlMessage::UdpGsoSegments(&segment)],
        MsgFlags::empty(),
        Some(&address),
    )
}

/// A UDP socket on `addr` with large buffers and SO_REUSEPORT, so that every
/// worker can bind its own socket to the same address.
fn open_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() {
        // `[::]` also accepts IPv4 clients.
        let _ = socket.set_only_v6(false);
    }
    let _ = socket.set_reuse_port(true);
    // Best effort (capped by net.core.wmem_max / rmem_max): bursts of DATA
    // for many clients are queued instead of dropped by this host.
    let _ = socket.set_send_buffer_size(SEND_BUFFER);
    let _ = socket.set_recv_buffer_size(RECEIVE_BUFFER);
    socket.bind(&addr.into())?;
    Ok(UdpSocket::from(socket))
}
