//! `rsftp-turbo ticket`: run by the client over SSH as the logged-in user.
//!
//! Opens files with the user's own permissions, registers them with the
//! daemon and prints JSON tickets. Two modes:
//!
//! * `ticket`: one path on stdin, one [`Ticket`] on stdout;
//! * `ticket --stream`: one request per stdin line, one [`StreamReply`] line
//!   per request, until stdin closes. The client keeps this running for the
//!   whole SSH connection so it needs only one SSH channel. A request is a
//!   file path (a ticket) or a JSON [`StreamRequest`] (a directory listing,
//!   which needs no daemon: it is read here, as the logged-in user).

use std::{
    fs::{self, File},
    io::{self, BufRead, Read, Write},
    path::Path,
    time::UNIX_EPOCH,
};

use rsftp_turbo_proto::{
    ticket::to_hex, ListEntry, Listing, StreamReply, StreamRequest, Ticket, PROTOCOL_VERSION,
};

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
        let request = trim_line(&line);
        let reply = if request.starts_with('{') {
            answer_request(request)
        } else {
            match issue(request, socket) {
                Ok(ticket) => StreamReply { ticket: Some(ticket), ..StreamReply::default() },
                Err(failure) => StreamReply {
                    error: Some(failure.message),
                    service_unavailable: failure.service_unavailable,
                    ..StreamReply::default()
                },
            }
        };
        serde_json::to_writer(&mut stdout, &reply)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
}

/// Answers a JSON request line.
fn answer_request(request: &str) -> StreamReply {
    match serde_json::from_str::<StreamRequest>(request) {
        Ok(StreamRequest { list: Some(path) }) => match list_directory(&path) {
            Ok(listing) => StreamReply { listing: Some(listing), list_reply: true, ..StreamReply::default() },
            Err(message) => StreamReply { error: Some(message), list_reply: true, ..StreamReply::default() },
        },
        Ok(_) => StreamReply { error: Some("unknown request".into()), ..StreamReply::default() },
        Err(error) => StreamReply { error: Some(format!("invalid request: {error}")), ..StreamReply::default() },
    }
}

/// Lists `path` (relative paths start at the working directory, which over
/// SSH is the login's home folder) with the current user's permissions.
pub fn list_directory(path: &str) -> Result<Listing, String> {
    let requested = if path.is_empty() { "." } else { path };
    let resolved = fs::canonicalize(requested).map_err(|error| format!("cannot open {requested}: {error}"))?;
    let reader = fs::read_dir(&resolved).map_err(|error| format!("cannot list {}: {error}", resolved.display()))?;
    let mut entries = Vec::new();
    for entry in reader {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        // DirEntry::metadata does not follow symbolic links, like SFTP READDIR.
        let entry = match entry.metadata() {
            Ok(meta) => ListEntry {
                name,
                dir: meta.is_dir(),
                size: meta.len(),
                mtime: meta.modified().ok().and_then(|time| time.duration_since(UNIX_EPOCH).ok()).map(|age| age.as_secs()),
            },
            Err(_) => ListEntry { name, dir: false, size: 0, mtime: None },
        };
        entries.push(entry);
    }
    Ok(Listing { path: resolved.to_string_lossy().into_owned(), entries })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_a_directory_without_following_links() {
        let root = std::env::temp_dir().join(format!("rsftp-list-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("file.bin"), b"12345").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("sub"), root.join("link")).unwrap();

        let listing = list_directory(&format!("{}/sub/..", root.display())).unwrap();
        assert_eq!(Path::new(&listing.path), fs::canonicalize(&root).unwrap());
        let find = |name: &str| listing.entries.iter().find(|entry| entry.name == name).cloned();
        assert!(find("sub").unwrap().dir);
        let file = find("file.bin").unwrap();
        assert_eq!((file.dir, file.size), (false, 5));
        assert!(file.mtime.is_some());
        #[cfg(unix)]
        assert!(!find("link").unwrap().dir);
        assert!(find(".").is_none() && find("..").is_none());

        assert!(list_directory(&format!("{}/missing", root.display())).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn json_lines_are_requests_and_errors_are_marked_as_list_replies() {
        let failed = answer_request(r#"{"list":"/nonexistent-rsftp-dir"}"#);
        assert!(failed.list_reply && failed.listing.is_none() && failed.error.is_some());
        let unknown = answer_request(r#"{"other":1}"#);
        assert!(!unknown.list_reply && unknown.error.is_some());
    }
}
