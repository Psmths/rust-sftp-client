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
//! * files are fetched in segments; data flows immediately, lost chunks are
//!   re-requested, and each segment is checked against an XXH3-128 digest the
//!   server computes (requested alongside the last data, so it costs no extra
//!   round trip); a segment that does not match is fetched again;
//! * one congestion controller per download paces requests from all its
//!   workers, tolerates a little random loss and backs off gently beyond it;
//! * a probe picks the largest packet size the path carries unfragmented.

pub mod client;
pub mod ticket;
pub mod wire;

pub use ticket::{StreamReply, Ticket, PROTOCOL_VERSION, TICKET_COMMAND, TICKET_STREAM_COMMAND};
pub use wire::{
    data_packet_len, digest, Direction, Message, PacketCipher, ReplayWindow, SegmentStatus, WireError, CHUNK_SIZE,
    DEFAULT_PORT, IPV4_FULL_CHUNK, IPV6_FULL_CHUNK, LARGE_CHUNK, LEGACY_MAX_CHUNK, MAX_CHUNK, MAX_READ_LEN,
    MAX_SEGMENT_LEN, MIN_CHUNK,
};
