//! `rsftp-turbo`: the server half of the UDP download accelerator.
//!
//! * [`server`] serves registered transfers over UDP.
//! * [`registration`] accepts open file descriptors from `rsftp-turbo ticket`
//!   over a Unix socket. The daemon itself never opens files, so it can run
//!   as an unprivileged user without access to anyone's home directory.
//! * [`ticket`] is the command the client runs over SSH.
//!
//! Only Unix servers are supported (descriptor passing needs Unix sockets).

#[cfg(unix)]
pub mod registration;
#[cfg(unix)]
pub mod server;
#[cfg(unix)]
pub mod ticket;

/// Default path of the registration socket.
pub const DEFAULT_SOCKET: &str = "/run/rsftp-turbo/turbo.sock";
