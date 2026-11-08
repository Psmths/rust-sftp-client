//! `rsftp-turbo ticket`: run by the client over SSH as the logged-in user.
//!
//! Opens files with the user's own permissions, registers them with the
//! daemon and prints JSON tickets. Two modes:
//!
//! * `ticket`: one path on stdin, one [`Ticket`] on stdout;
//! * `ticket --stream`: one path per stdin line, one [`StreamReply`] line per
//!   path, until stdin closes. The client keeps this running for the whole SSH
//!   connection so it needs only one SSH channel.

use std::{
    fs::File,
    io::{self, BufRead, Read, Write},
    path::Path,
};

use rsftp_turbo_proto::{ticket::to_hex, StreamReply, Ticket, PROTOCOL_VERSION};

use crate::registration::{register, RegisterRequest};

const MAX_PATH: u64 = 64 * 1024;

/// Why a ticket was not issued.
#[derive(Debug)]
pub struct TicketFailure {
    pub message: String,
    /// The daemon cannot be reached, as opposed to a problem with this file.
    pub service_unavailable: bool,
}

impl TicketFailure {
    fn file(message: String) -> Self {
        Self { message, service_unavailable: false }
    }
}

/// Single-shot mode: reads one path from stdin.
pub fn run(socket: &Path) -> Result<Ticket, String> {
    let mut input = String::new();
    io::stdin()
        .take(MAX_PATH)
        .read_to_string(&mut input)
        .map_err(|error| format!("cannot read the path from stdin: {error}"))?;
    issue(trim_line(&input), socket).map_err(|failure| failure.message)
}

/// Streaming mode: answers every stdin line until stdin closes.
pub fn run_stream(socket: &Path) -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut line = String::new();
    loop {
        line.clear();
        if stdin.lock().take(MAX_PATH).read_line(&mut line)? == 0 {
            return Ok(());
        }
        let reply = match issue(trim_line(&line), socket) {
            Ok(ticket) => StreamReply { ticket: Some(ticket), error: None, service_unavailable: false },
            Err(failure) => StreamReply {
                ticket: None,
                error: Some(failure.message),
                service_unavailable: failure.service_unavailable,
            },
        };
        serde_json::to_writer(&mut stdout, &reply)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
}

fn trim_line(line: &str) -> &str {
    let line = line.strip_suffix('\n').unwrap_or(line);
    line.strip_suffix('\r').unwrap_or(line)
}

/// Opens `path` as the current user and registers it with the daemon.
pub fn issue(path: &str, socket: &Path) -> Result<Ticket, TicketFailure> {
    if path.is_empty() {
        return Err(TicketFailure::file("no file path given".into()));
    }
    let file = File::open(path).map_err(|error| TicketFailure::file(format!("cannot open {path}: {error}")))?;
    let meta = file.metadata().map_err(|error| TicketFailure::file(format!("cannot stat {path}: {error}")))?;
    if !meta.is_file() {
        return Err(TicketFailure::file(format!("{path} is not a regular file")));
    }

    // "client_ip client_port server_ip server_port", set by sshd.
    let ssh_connection = std::env::var("SSH_CONNECTION").unwrap_or_default();
    let fields: Vec<&str> = ssh_connection.split_whitespace().collect();
    let client_ip = fields.first().map(|ip| (*ip).to_owned());
    let server_ip = fields.get(2).map(|ip| (*ip).to_owned());

    let request = RegisterRequest { version: PROTOCOL_VERSION, client_ip };
    let registration = register(socket, &file, &request).map_err(|error| TicketFailure {
        message: format!("the rsftp-turbo service is not available ({}): {error}", socket.display()),
        service_unavailable: true,
    })?;

    Ok(Ticket {
        version: PROTOCOL_VERSION,
        transfer: registration.transfer,
        key: to_hex(&registration.key),
        port: registration.port,
        address: server_ip,
        size: meta.len(),
    })
}
