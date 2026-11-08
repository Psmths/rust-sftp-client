//! Packet format (protocol version 2).
//!
//! ```text
//! +-------+------+-------------+-------------+--------------------------------+
//! | magic | kind | transfer id | counter     | AES-256-GCM(body) + 16-byte tag |
//! | 4     | 1    | 8 (BE)      | 8 (BE)      |                                |
//! +-------+------+-------------+-------------+--------------------------------+
//! ```
//!
//! The 21-byte header is authenticated as associated data. The 96-bit nonce
//! is `direction ‖ 0 0 0 ‖ counter`; each side increments its own counter
//! for every packet it sends, so a nonce is never reused under one key.
//!
//! Data flows as soon as the client asks for it (`Read`); the client asks for
//! a segment's XXH3-128 digest (`Digest`) once it has requested all of the
//! segment, so verification costs no extra round trip. The chunk size is
//! chosen per transfer with `Probe` (largest that gets through unfragmented).

use std::fmt;

use aes_gcm::{
    aead::{Aead, AeadInOut, KeyInit, Nonce, Payload},
    Aes256Gcm,
};

pub const DEFAULT_PORT: u16 = 6767;
pub const MAGIC: [u8; 4] = *b"RTB2";
pub const HEADER_LEN: usize = 4 + 1 + 8 + 8;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
/// Bytes a DATA packet adds around its chunk (header, offset, tag).
pub const DATA_OVERHEAD: usize = HEADER_LEN + 8 + TAG_LEN;
/// Chunk size that always fits: 1245-byte packets stay below the 1280-byte
/// IPv6 minimum MTU, so they are never fragmented.
pub const CHUNK_SIZE: usize = 1200;
/// Larger chunk used when a probe shows the path carries it: 1425-byte
/// packets fit a 1500-byte MTU and PPPoE (1492) over IPv4 and IPv6.
pub const LARGE_CHUNK: usize = 1380;
pub const MIN_CHUNK: usize = 512;
pub const MAX_CHUNK: usize = 1400;
/// Size of a DATA packet carrying a full default chunk.
pub const DATA_PACKET_LEN: usize = CHUNK_SIZE + DATA_OVERHEAD;
/// Largest byte range a single READ may ask for.
pub const MAX_READ_LEN: u32 = 4 * 1024 * 1024;
/// Largest range one DIGEST may cover.
pub const MAX_SEGMENT_LEN: u32 = 64 * 1024 * 1024;
/// Largest probe reply the server will produce.
pub const MAX_PROBE_LEN: usize = 1500;
/// Receive buffer size that fits every packet of the protocol.
pub const MAX_PACKET: usize = 2048;

const KIND_DIGEST: u8 = 1;
const KIND_DIGEST_INFO: u8 = 2;
const KIND_READ: u8 = 3;
const KIND_DATA: u8 = 4;
const KIND_CLOSE: u8 = 5;
const KIND_CLOSED: u8 = 6;
const KIND_ERROR: u8 = 7;
const KIND_PROBE: u8 = 8;
const KIND_PROBE_REPLY: u8 = 9;
const MAX_ERROR_LEN: usize = 512;
/// Body bytes of a PROBE_REPLY besides its padding.
const PROBE_REPLY_FIXED: usize = 4 + 2;

/// Size of a DATA packet for `chunk` bytes of data.
pub const fn data_packet_len(chunk: usize) -> usize {
    chunk + DATA_OVERHEAD
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    ToServer = 0,
    ToClient = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SegmentStatus {
    Ok = 0,
    /// The file's size or modification time changed since the ticket was issued.
    FileChanged = 1,
    /// The requested range is empty, too large or outside the file.
    OutOfRange = 2,
    IoError = 3,
}

impl SegmentStatus {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Ok,
            1 => Self::FileChanged,
            2 => Self::OutOfRange,
            3 => Self::IoError,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Client → server: report the XXH3-128 digest of `[offset, offset + len)`.
    Digest { request: u32, offset: u64, len: u32 },
    /// Server → client: digest of a range (zero unless `status` is Ok).
    DigestInfo { request: u32, offset: u64, len: u32, status: SegmentStatus, xxh3: u128 },
    /// Client → server: send `[offset, offset + len)` as DATA packets of
    /// `chunk` bytes each (the last one may be shorter).
    Read { request: u32, offset: u64, len: u32, chunk: u16 },
    /// Server → client: up to `MAX_CHUNK` bytes of file data.
    Data { offset: u64, data: Vec<u8> },
    /// Client → server: the transfer is finished; forget it.
    Close,
    /// Server → client: acknowledgement of `Close`.
    Closed,
    /// Server → client: a request failed.
    Error { message: String },
    /// Client → server: answer with a PROBE_REPLY packet of exactly `size` bytes.
    Probe { request: u32, size: u16 },
    /// Server → client: answer to `Probe`, padded to the requested size.
    ProbeReply { request: u32, size: u16, padding: usize },
}

impl Message {
    fn kind(&self) -> u8 {
        match self {
            Message::Digest { .. } => KIND_DIGEST,
            Message::DigestInfo { .. } => KIND_DIGEST_INFO,
            Message::Read { .. } => KIND_READ,
            Message::Data { .. } => KIND_DATA,
            Message::Close => KIND_CLOSE,
            Message::Closed => KIND_CLOSED,
            Message::Error { .. } => KIND_ERROR,
            Message::Probe { .. } => KIND_PROBE,
            Message::ProbeReply { .. } => KIND_PROBE_REPLY,
        }
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut body = Vec::new();
        match self {
            Message::Digest { request, offset, len } => {
                body.extend_from_slice(&request.to_be_bytes());
                body.extend_from_slice(&offset.to_be_bytes());
                body.extend_from_slice(&len.to_be_bytes());
            }
            Message::Read { request, offset, len, chunk } => {
                body.extend_from_slice(&request.to_be_bytes());
                body.extend_from_slice(&offset.to_be_bytes());
                body.extend_from_slice(&len.to_be_bytes());
                body.extend_from_slice(&chunk.to_be_bytes());
            }
            Message::DigestInfo { request, offset, len, status, xxh3 } => {
                body.extend_from_slice(&request.to_be_bytes());
                body.extend_from_slice(&offset.to_be_bytes());
                body.extend_from_slice(&len.to_be_bytes());
                body.push(*status as u8);
                body.extend_from_slice(&xxh3.to_be_bytes());
            }
            Message::Data { offset, data } => {
                body.reserve(8 + data.len());
                body.extend_from_slice(&offset.to_be_bytes());
                body.extend_from_slice(data);
            }
            Message::Close | Message::Closed => {}
            Message::Error { message } => {
                let mut end = message.len().min(MAX_ERROR_LEN);
                while !message.is_char_boundary(end) {
                    end -= 1;
                }
                body.extend_from_slice(&message.as_bytes()[..end]);
            }
            Message::Probe { request, size } => {
                body.extend_from_slice(&request.to_be_bytes());
                body.extend_from_slice(&size.to_be_bytes());
            }
            Message::ProbeReply { request, size, padding } => {
                body.extend_from_slice(&request.to_be_bytes());
                body.extend_from_slice(&size.to_be_bytes());
                body.resize(body.len() + padding, 0);
            }
        }
        body
    }

    fn decode_body(kind: u8, body: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader { buf: body, pos: 0 };
        let message = match kind {
            KIND_DIGEST => {
                let request = reader.u32()?;
                let offset = reader.u64()?;
                let len = reader.u32()?;
                Message::Digest { request, offset, len }
            }
            KIND_READ => {
                let request = reader.u32()?;
                let offset = reader.u64()?;
                let len = reader.u32()?;
                let chunk = reader.u16()?;
                Message::Read { request, offset, len, chunk }
            }
            KIND_DIGEST_INFO => {
                let request = reader.u32()?;
                let offset = reader.u64()?;
                let len = reader.u32()?;
                let status = SegmentStatus::from_u8(reader.u8()?).ok_or(WireError::Malformed("segment status"))?;
                let mut xxh3 = [0_u8; 16];
                xxh3.copy_from_slice(reader.bytes(16)?);
                Message::DigestInfo { request, offset, len, status, xxh3: u128::from_be_bytes(xxh3) }
            }
            KIND_DATA => {
                let offset = reader.u64()?;
                let data = reader.rest().to_vec();
                if data.len() > MAX_CHUNK {
                    return Err(WireError::Malformed("data chunk too long"));
                }
                Message::Data { offset, data }
            }
            KIND_CLOSE => Message::Close,
            KIND_CLOSED => Message::Closed,
            KIND_ERROR => Message::Error { message: String::from_utf8_lossy(reader.rest()).into_owned() },
            KIND_PROBE => {
                let request = reader.u32()?;
                let size = reader.u16()?;
                Message::Probe { request, size }
            }
            KIND_PROBE_REPLY => {
                let request = reader.u32()?;
                let size = reader.u16()?;
                let padding = reader.rest().len();
                Message::ProbeReply { request, size, padding }
            }
            other => return Err(WireError::UnknownKind(other)),
        };
        let open_ended = matches!(message, Message::Data { .. } | Message::Error { .. } | Message::ProbeReply { .. });
        if !open_ended && reader.pos != body.len() {
            return Err(WireError::Malformed("trailing bytes"));
        }
        Ok(message)
    }

    /// A PROBE_REPLY whose sealed packet is exactly `size` bytes (or as close
    /// as possible if `size` is too small).
    pub fn probe_reply(request: u32, size: u16) -> Message {
        let fixed = HEADER_LEN + PROBE_REPLY_FIXED + TAG_LEN;
        let padding = usize::from(size).min(MAX_PROBE_LEN).saturating_sub(fixed);
        Message::ProbeReply { request, size, padding }
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(len).ok_or(WireError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let mut out = [0_u8; 2];
        out.copy_from_slice(self.bytes(2)?);
        Ok(u16::from_be_bytes(out))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        let mut out = [0_u8; 4];
        out.copy_from_slice(self.bytes(4)?);
        Ok(u32::from_be_bytes(out))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        let mut out = [0_u8; 8];
        out.copy_from_slice(self.bytes(8)?);
        Ok(u64::from_be_bytes(out))
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = &self.buf[self.pos..];
        self.pos = self.buf.len();
        rest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    BadMagic,
    UnknownKind(u8),
    /// The packet was not sealed with this transfer's key, or was modified.
    Authentication,
    Malformed(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => f.write_str("truncated packet"),
            WireError::BadMagic => f.write_str("not an rsftp-turbo packet (or a different protocol version)"),
            WireError::UnknownKind(kind) => write!(f, "unknown packet kind {kind}"),
            WireError::Authentication => f.write_str("packet failed authentication"),
            WireError::Malformed(what) => write!(f, "malformed packet: {what}"),
        }
    }
}

impl std::error::Error for WireError {}

/// The unauthenticated packet header; only used to find the transfer (and so
/// the key) before the packet is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub transfer: u64,
    pub counter: u64,
}

pub fn parse_header(packet: &[u8]) -> Result<Header, WireError> {
    if packet.len() < HEADER_LEN + TAG_LEN {
        return Err(WireError::Truncated);
    }
    if packet[..4] != MAGIC {
        return Err(WireError::BadMagic);
    }
    let mut transfer = [0_u8; 8];
    transfer.copy_from_slice(&packet[5..13]);
    let mut counter = [0_u8; 8];
    counter.copy_from_slice(&packet[13..21]);
    Ok(Header { kind: packet[4], transfer: u64::from_be_bytes(transfer), counter: u64::from_be_bytes(counter) })
}

/// Seals and opens packets of one transfer.
pub struct PacketCipher {
    aead: Aes256Gcm,
}

impl PacketCipher {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self { aead: Aes256Gcm::new_from_slice(key).expect("AES-256 keys are 32 bytes") }
    }

    /// Builds a packet. `counter` must never repeat for one key and direction.
    pub fn seal(&self, direction: Direction, transfer: u64, counter: u64, message: &Message) -> Vec<u8> {
        let mut packet = Vec::with_capacity(HEADER_LEN + TAG_LEN + MAX_CHUNK + 8);
        packet.extend_from_slice(&MAGIC);
        packet.push(message.kind());
        packet.extend_from_slice(&transfer.to_be_bytes());
        packet.extend_from_slice(&counter.to_be_bytes());
        let body = message.encode_body();
        let sealed = self
            .aead
            .encrypt(&nonce(direction, counter), Payload { msg: &body, aad: &packet[..HEADER_LEN] })
            .expect("AES-GCM sealing of a short message cannot fail");
        packet.extend_from_slice(&sealed);
        packet
    }

    /// Appends a sealed DATA packet to `out` without intermediate buffers.
    /// Produces exactly the bytes [`seal`](Self::seal) would for
    /// `Message::Data`; used on the server's hot path.
    pub fn seal_data_into(
        &self,
        direction: Direction,
        transfer: u64,
        counter: u64,
        offset: u64,
        data: &[u8],
        out: &mut Vec<u8>,
    ) {
        debug_assert!(data.len() <= MAX_CHUNK);
        let start = out.len();
        out.extend_from_slice(&MAGIC);
        out.push(KIND_DATA);
        out.extend_from_slice(&transfer.to_be_bytes());
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(data);
        let (header, body) = out[start..].split_at_mut(HEADER_LEN);
        let tag = self
            .aead
            .encrypt_inout_detached(&nonce(direction, counter), header, body.into())
            .expect("AES-GCM sealing of a short message cannot fail");
        out.extend_from_slice(&tag);
    }

    /// Authenticates and decodes a packet sent in `direction`.
    pub fn open(&self, direction: Direction, packet: &[u8]) -> Result<(Header, Message), WireError> {
        let header = parse_header(packet)?;
        let body = self
            .aead
            .decrypt(&nonce(direction, header.counter), Payload { msg: &packet[HEADER_LEN..], aad: &packet[..HEADER_LEN] })
            .map_err(|_| WireError::Authentication)?;
        let message = Message::decode_body(header.kind, &body)?;
        Ok((header, message))
    }
}

fn nonce(direction: Direction, counter: u64) -> Nonce<Aes256Gcm> {
    let mut bytes = [0_u8; 12];
    bytes[0] = direction as u8;
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::<Aes256Gcm>::from(bytes)
}

/// XXH3-128 of `data`, as used for segment verification.
pub fn digest(data: &[u8]) -> u128 {
    xxhash_rust::xxh3::xxh3_128(data)
}

/// Sliding-window replay filter for packet counters (last 128 counters).
#[derive(Clone, Debug, Default)]
pub struct ReplayWindow {
    started: bool,
    highest: u64,
    seen: u128,
}

impl ReplayWindow {
    const WIDTH: u64 = 128;

    pub fn new() -> Self {
        Self::default()
    }

    /// Records `counter`; false if it was seen before or is too old to tell.
    pub fn accept(&mut self, counter: u64) -> bool {
        if !self.started {
            self.started = true;
            self.highest = counter;
            self.seen = 1;
            return true;
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            self.seen = if shift >= Self::WIDTH { 0 } else { self.seen << shift };
            self.seen |= 1;
            self.highest = counter;
            return true;
        }
        let age = self.highest - counter;
        if age >= Self::WIDTH {
            return false;
        }
        let bit = 1_u128 << age;
        if self.seen & bit != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> PacketCipher {
        PacketCipher::new(&[7_u8; KEY_LEN])
    }

    #[test]
    fn every_message_round_trips() {
        let messages = [
            Message::Digest { request: 1, offset: 2, len: 3 },
            Message::DigestInfo { request: 4, offset: 5, len: 6, status: SegmentStatus::FileChanged, xxh3: u128::MAX - 7 },
            Message::Read { request: 7, offset: 8, len: 9, chunk: 1380 },
            Message::Data { offset: 1_000_000, data: vec![42; LARGE_CHUNK] },
            Message::Close,
            Message::Closed,
            Message::Error { message: "nope".into() },
            Message::Probe { request: 3, size: 1425 },
            Message::probe_reply(3, 1425),
        ];
        for (counter, message) in messages.iter().enumerate() {
            let packet = cipher().seal(Direction::ToClient, 99, counter as u64, message);
            assert!(packet.len() <= MAX_PROBE_LEN, "{} bytes", packet.len());
            let (header, decoded) = cipher().open(Direction::ToClient, &packet).unwrap();
            assert_eq!(header.transfer, 99);
            assert_eq!(header.counter, counter as u64);
            assert_eq!(&decoded, message);
        }
    }

    #[test]
    fn probe_replies_have_the_requested_size() {
        for size in [1245_u16, 1425, 1500] {
            let packet = cipher().seal(Direction::ToClient, 1, 1, &Message::probe_reply(1, size));
            assert_eq!(packet.len(), usize::from(size));
        }
        assert_eq!(data_packet_len(LARGE_CHUNK), 1425);
        assert_eq!(DATA_PACKET_LEN, 1245);
    }

    #[test]
    fn in_place_data_sealing_matches_seal() {
        for chunk in [CHUNK_SIZE, LARGE_CHUNK, 10] {
            let data = vec![5_u8; chunk];
            let expected = cipher().seal(Direction::ToClient, 3, 77, &Message::Data { offset: 4096, data: data.clone() });
            let mut out = vec![1, 2, 3];
            cipher().seal_data_into(Direction::ToClient, 3, 77, 4096, &data, &mut out);
            assert_eq!(&out[..3], &[1, 2, 3]);
            assert_eq!(&out[3..], &expected[..]);
            assert_eq!(expected.len(), data_packet_len(chunk));
        }
    }

    #[test]
    fn tampering_wrong_key_and_wrong_direction_are_rejected() {
        let packet = cipher().seal(Direction::ToServer, 1, 0, &Message::Read { request: 1, offset: 0, len: 10, chunk: 1200 });
        let mut tampered = packet.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(cipher().open(Direction::ToServer, &tampered).unwrap_err(), WireError::Authentication);
        let mut header_changed = packet.clone();
        header_changed[12] ^= 1; // transfer id is authenticated too
        assert_eq!(cipher().open(Direction::ToServer, &header_changed).unwrap_err(), WireError::Authentication);
        assert_eq!(cipher().open(Direction::ToClient, &packet).unwrap_err(), WireError::Authentication);
        let other = PacketCipher::new(&[8_u8; KEY_LEN]);
        assert_eq!(other.open(Direction::ToServer, &packet).unwrap_err(), WireError::Authentication);
        assert_eq!(parse_header(&packet[..10]).unwrap_err(), WireError::Truncated);
        let mut old_version = packet.clone();
        old_version[3] = b'1';
        assert_eq!(parse_header(&old_version).unwrap_err(), WireError::BadMagic);
    }

    #[test]
    fn digest_is_xxh3_128() {
        assert_eq!(digest(b""), xxhash_rust::xxh3::xxh3_128(b""));
        assert_ne!(digest(b"a"), digest(b"b"));
    }

    #[test]
    fn replay_window_rejects_duplicates_and_old_counters() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(5));
        assert!(!window.accept(5));
        assert!(window.accept(3));
        assert!(!window.accept(3));
        assert!(window.accept(200));
        assert!(!window.accept(5));
        assert!(window.accept(199));
        assert!(!window.accept(199));
    }
}
