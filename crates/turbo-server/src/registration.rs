//! Registration over a Unix socket.
//!
//! `rsftp-turbo ticket` runs as the SSH user, opens the requested file (so the
//! operating system enforces that user's permissions) and passes the open
//! descriptor to the daemon with `SCM_RIGHTS`, together with a small JSON
//! request. The daemon replies with the transfer id, key and UDP port.

use std::{
    fs::{self, File, Permissions},
    io::{self, IoSlice, IoSliceMut, Read, Write},
    net::{IpAddr, Shutdown},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    sync::Arc,
    thread,
    time::Duration,
};

use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use rsftp_turbo_proto::ticket::{from_hex, to_hex};
use serde::{Deserialize, Serialize};

use crate::server::{Registration, Server};

const MAX_MESSAGE: u64 = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub version: u32,
    /// Address of the SSH client; the daemon only answers it.
    pub client_ip: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterResponse {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub transfer: u64,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub port: u16,
}

/// Accepts registrations forever. The socket is world-writable on purpose:
/// a caller can only register files it was already able to open.
pub fn serve(server: Arc<Server>, path: &Path) -> io::Result<()> {
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, Permissions::from_mode(0o666))?;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let server = Arc::clone(&server);
        let _ = thread::Builder::new().name("register".into()).spawn(move || {
            if let Err(error) = handle(&server, stream) {
                eprintln!("rsftp-turbo: registration failed: {error}");
            }
        });
    }
    Ok(())
}

fn handle(server: &Server, mut stream: UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut body = vec![0_u8; 4096];
    let mut cmsg = nix::cmsg_space!([RawFd; 4]);
    let (received, mut descriptors) = {
        let mut iov = [IoSliceMut::new(&mut body)];
        let message = recvmsg::<()>(stream.as_raw_fd(), &mut iov, Some(cmsg.as_mut_slice()), MsgFlags::empty())
            .map_err(io::Error::from)?;
        let mut descriptors = Vec::new();
        for control in message.cmsgs().map_err(io::Error::from)? {
            if let ControlMessageOwned::ScmRights(fds) = control {
                // SAFETY: the kernel just installed these descriptors in our
                // process; nothing else owns them.
                descriptors.extend(fds.into_iter().map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }));
            }
        }
        (message.bytes, descriptors)
    };
    body.truncate(received);
    (&mut stream).take(MAX_MESSAGE).read_to_end(&mut body)?;

    let response = match (descriptors.len(), serde_json::from_slice::<RegisterRequest>(&body)) {
        (1, Ok(request)) => {
            let file = File::from(descriptors.remove(0));
            let client_ip = request.client_ip.as_deref().and_then(|ip| ip.parse::<IpAddr>().ok());
            match server.register(file, client_ip) {
                Ok(Registration { transfer, key, port }) => {
                    RegisterResponse { error: None, transfer, key: to_hex(&key), port }
                }
                Err(error) => failure(error.to_string()),
            }
        }
        (count, Ok(_)) => failure(format!("expected one file descriptor, got {count}")),
        (_, Err(error)) => failure(format!("invalid request: {error}")),
    };
    // Extra descriptors (if any) are closed when `descriptors` is dropped.
    serde_json::to_writer(&mut stream, &response)?;
    stream.flush()
}

fn failure(error: String) -> RegisterResponse {
    RegisterResponse { error: Some(error), transfer: 0, key: String::new(), port: 0 }
}

/// Client side of the registration: passes `file` to the daemon.
pub fn register(socket: &Path, file: &File, request: &RegisterRequest) -> io::Result<Registration> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let body = serde_json::to_vec(request)?;
    let fds = [file.as_raw_fd()];
    let sent = sendmsg::<()>(
        stream.as_raw_fd(),
        &[IoSlice::new(&body)],
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::empty(),
        None,
    )
    .map_err(io::Error::from)?;
    (&stream).write_all(&body[sent..])?;
    stream.shutdown(Shutdown::Write)?;

    let mut reply = Vec::new();
    (&stream).take(MAX_MESSAGE).read_to_end(&mut reply)?;
    let response: RegisterResponse = serde_json::from_slice(&reply)?;
    if let Some(error) = response.error {
        return Err(io::Error::other(error));
    }
    let key = from_hex(&response.key)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "daemon returned an invalid key"))?;
    Ok(Registration { transfer: response.transfer, key, port: response.port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_passing_registers_the_file() {
        let directory = std::env::temp_dir().join(format!("rsftp-turbo-reg-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let socket = directory.join("turbo.sock");
        let data_path = directory.join("data.bin");
        fs::write(&data_path, b"hello turbo").unwrap();

        let server = Server::bind("127.0.0.1:0".parse().unwrap(), Default::default()).unwrap();
        let listener_server = Arc::clone(&server);
        let listener_socket = socket.clone();
        thread::spawn(move || serve(listener_server, &listener_socket));
        for _ in 0..100 {
            if socket.exists() { break; }
            thread::sleep(Duration::from_millis(10));
        }

        let file = File::open(&data_path).unwrap();
        let request = RegisterRequest { version: 1, client_ip: Some("127.0.0.1".into()) };
        let registration = register(&socket, &file, &request).unwrap();
        assert_ne!(registration.transfer, 0);
        assert_eq!(registration.port, server.local_addr().unwrap().port());
        assert_eq!(server.active_transfers(), 1);

        // Directories are refused.
        let dir = File::open(&directory).unwrap();
        assert!(register(&socket, &dir, &request).is_err());
        let _ = fs::remove_dir_all(&directory);
    }
}
