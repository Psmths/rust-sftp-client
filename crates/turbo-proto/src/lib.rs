//! rsftp-turbo: a UDP download accelerator for Rust SFTP Client.
//!
//! Directory browsing and authentication stay on SSH/SFTP. To download a file
//! the client runs `rsftp-turbo ticket` on the server over its SSH connection.
//! That command (running as the logged-in user, so normal file permissions
//! apply) opens the file and hands the open descriptor to the `rsftp-turbo
//! serve` daemon, which returns a one-time transfer id and a random 256-bit
//! key. The ticket travels back over the encrypted SSH channel; the file data
//! then flows over UDP:
//!
//! * every packet is sealed with AES-256-GCM under the transfer key, so data
//!   cannot be read, forged or modified in transit, and the daemon ignores
//!   anything it cannot authenticate (no amplification for spoofed requests);
//! * the daemon only answers the IP address the SSH session came from and
//!   rejects replayed requests;
//! * files are fetched in segments; for each segment the server reports a
//!   SHA-256 digest, the client re-requests lost chunks until the segment is
//!   complete, verifies the digest and retries the segment on mismatch;
//! * the client paces requests with a congestion window (slow start, then
//!   additive increase, multiplicative decrease on loss).

pub mod client;
pub mod ticket;
pub mod wire;

pub use ticket::{
    ListEntry, Listing, StreamReply, StreamRequest, Ticket, PROTOCOL_VERSION, TICKET_COMMAND, TICKET_STREAM_COMMAND,
};
pub use wire::{
    Direction, Message, PacketCipher, ReplayWindow, SegmentStatus, WireError, CHUNK_SIZE, DEFAULT_PORT,
    MAX_READ_LEN, MAX_SEGMENT_LEN,
};
