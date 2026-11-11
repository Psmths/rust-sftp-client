//! Packet format.
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

use std::fmt;

use aes_gcm::{
    aead::{Aead, AeadInOut, KeyInit, Nonce, Payload},
    Aes256Gcm,
};

pub const DEFAULT_PORT: u16 = 6767;
pub const MAGIC: [u8; 4] = *b"RTB1";
pub const HEADER_LEN: usize = 4 + 1 + 8 + 8;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
/// File bytes per DATA packet. Header, offset and tag bring a packet to
/// 1245 bytes, below the 1280-byte IPv6 minimum MTU, so it is never fragmented.
pub const CHUNK_SIZE: usize = 1200;
/// Largest byte range a single READ may ask for.
pub const MAX_READ_LEN: u32 = 4 * 1024 * 1024;
/// Largest segment the server hashes for one OPEN_SEGMENT.
pub const MAX_SEGMENT_LEN: u32 = 64 * 1024 * 1024;
/// Receive buffer size that fits every packet of the protocol.
pub const MAX_PACKET: usize = 2048;
/// Size of a DATA packet carrying a full chunk.
pub const DATA_PACKET_LEN: usize = HEADER_LEN + 8 + CHUNK_SIZE + TAG_LEN;

const KIND_OPEN_SEGMENT: u8 = 1;
const KIND_SEGMENT_INFO: u8 = 2;
const KIND_READ: u8 = 3;
const KIND_DATA: u8 = 4;
const KIND_CLOSE: u8 = 5;
const KIND_CLOSED: u8 = 6;
const KIND_ERROR: u8 = 7;
const MAX_ERROR_LEN: usize = 512;

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
    /// Client → server: hash `[offset, offset + len)` and report its digest.
    OpenSegment { request: u32, offset: u64, len: u32 },
    /// Server → client: digest of a segment (all zero unless `status` is Ok).
    SegmentInfo { request: u32, offset: u64, len: u32, status: SegmentStatus, sha256: [u8; 32] },
    /// Client → server: send `[offset, offset + len)` as DATA packets.
    Read { request: u32, offset: u64, len: u32 },
    /// Server → client: up to `CHUNK_SIZE` bytes of file data.
    Data { offset: u64, data: Vec<u8> },
    /// Client → server: the transfer is finished; forget it.
    Close,
    /// Server → client: acknowledgement of `Close`.
    Closed,
    /// Server → client: a request failed.
    Error { message: String },
}

impl Message {
    fn kind(&self) -> u8 {
        match self {
            Message::OpenSegment { .. } => KIND_OPEN_SEGMENT,
            Message::SegmentInfo { .. } => KIND_SEGMENT_INFO,
            Message::Read { .. } => KIND_READ,
            Message::Data { .. } => KIND_DATA,
            Message::Close => KIND_CLOSE,
            Message::Closed => KIND_CLOSED,
            Message::Error { .. } => KIND_ERROR,
        }
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut body = Vec::new();
        match self {
            Message::OpenSegment { request, offset, len } | Message::Read { request, offset, len } => {
                body.extend_from_slice(&request.to_be_bytes());
                body.extend_from_slice(&offset.to_be_bytes());
                body.extend_from_slice(&len.to_be_bytes());
            }
            Message::SegmentInfo { request, offset, len, status, sha256 } => {
                body.extend_from_slice(&request.to_be_bytes());
                body.extend_from_slice(&offset.to_be_bytes());
                body.extend_from_slice(&len.to_be_bytes());
                body.push(*status as u8);
                body.extend_from_slice(sha256);
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
        }
        body
    }

    fn decode_body(kind: u8, body: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader { buf: body, pos: 0 };
        let message = match kind {
            KIND_OPEN_SEGMENT | KIND_READ => {
                let request = reader.u32()?;
                let offset = reader.u64()?;
                let len = reader.u32()?;
                if kind == KIND_READ {
                    Message::Read { request, offset, len }
                } else {
                    Message::OpenSegment { request, offset, len }
                }
            }
            KIND_SEGMENT_INFO => {
                let request = reader.u32()?;
                let offset = reader.u64()?;
                let len = reader.u32()?;
                let status = SegmentStatus::from_u8(reader.u8()?).ok_or(WireError::Malformed("segment status"))?;
                let mut sha256 = [0_u8; 32];
                sha256.copy_from_slice(reader.bytes(32)?);
                Message::SegmentInfo { request, offset, len, status, sha256 }
            }
            KIND_DATA => {
                let offset = reader.u64()?;
                let data = reader.rest().to_vec();
                if data.len() > CHUNK_SIZE {
                    return Err(WireError::Malformed("data chunk too long"));
                }
                Message::Data { offset, data }
            }
            KIND_CLOSE => Message::Close,
            KIND_CLOSED => Message::Closed,
            KIND_ERROR => Message::Error { message: String::from_utf8_lossy(reader.rest()).into_owned() },
            other => return Err(WireError::UnknownKind(other)),
        };
        if !matches!(message, Message::Data { .. } | Message::Error { .. }) && reader.pos != body.len() {
            return Err(WireError::Malformed("trailing bytes"));
        }
        Ok(message)
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
            WireError::BadMagic => f.write_str("not an rsftp-turbo packet"),
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
        let mut packet = Vec::with_capacity(HEADER_LEN + TAG_LEN + CHUNK_SIZE + 8);
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
        debug_assert!(data.len() <= CHUNK_SIZE);
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
            Message::OpenSegment { request: 1, offset: 2, len: 3 },
            Message::SegmentInfo { request: 4, offset: 5, len: 6, status: SegmentStatus::FileChanged, sha256: [9; 32] },
            Message::Read { request: 7, offset: 8, len: 9 },
            Message::Data { offset: 1_000_000, data: vec![42; CHUNK_SIZE] },
            Message::Close,
            Message::Closed,
            Message::Error { message: "nope".into() },
        ];
        for (counter, message) in messages.iter().enumerate() {
            let packet = cipher().seal(Direction::ToClient, 99, counter as u64, message);
            assert!(packet.len() <= 1280, "{} bytes", packet.len());
            let (header, decoded) = cipher().open(Direction::ToClient, &packet).unwrap();
            assert_eq!(header.transfer, 99);
            assert_eq!(header.counter, counter as u64);
            assert_eq!(&decoded, message);
        }
    }

    #[test]
    fn in_place_data_sealing_matches_seal() {
        let data = vec![5_u8; CHUNK_SIZE];
        let expected = cipher().seal(Direction::ToClient, 3, 77, &Message::Data { offset: 4096, data: data.clone() });
        let mut out = vec![1, 2, 3];
        cipher().seal_data_into(Direction::ToClient, 3, 77, 4096, &data, &mut out);
        assert_eq!(&out[..3], &[1, 2, 3]);
        assert_eq!(&out[3..], &expected[..]);
        assert_eq!(expected.len(), DATA_PACKET_LEN);
        let short = cipher().seal(Direction::ToClient, 3, 78, &Message::Data { offset: 0, data: vec![9; 10] });
        let mut out = Vec::new();
        cipher().seal_data_into(Direction::ToClient, 3, 78, 0, &[9; 10], &mut out);
        assert_eq!(out, short);
    }

    #[test]
    fn tampering_wrong_key_and_wrong_direction_are_rejected() {
        let packet = cipher().seal(Direction::ToServer, 1, 0, &Message::Read { request: 1, offset: 0, len: 10 });
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
    }

    #[test]
    fn replay_window_rejects_duplicates_and_old_counters() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(5));
        assert!(!window.accept(5));
        assert!(window.accept(3));
        assert!(!window.accept(3));
        assert!(window.accept(200));
        assert!(!window.accept(5)); // older than the window
        assert!(window.accept(199));
        assert!(!window.accept(199));
    }
}
