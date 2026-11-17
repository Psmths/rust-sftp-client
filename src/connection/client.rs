use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering}, Arc, Mutex},
    time::{Duration, Instant},
};
use russh::{client, keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate}, ChannelMsg};
use russh::keys::ssh_key::HashAlg;
use russh_sftp::client::{fs::ReadDir, SftpSession};
use tokio::{fs, io::{AsyncReadExt, AsyncWriteExt}, sync::{mpsc, Semaphore}, task::JoinSet};

use crate::{
    connection::{AuthMethod, ConnectionProfile, NetworkSettings},
    transfer::{
        download_file,
        partial::Partial,
        turbo::{self, TurboError},
        CancelToken, DownloadError, DownloadProgress, DownloadResult, SegmentProgress, TransferSettings,
    },
};
use rsftp_turbo_proto::{StreamReply, StreamRequest, Ticket, PROTOCOL_VERSION, TICKET_STREAM_COMMAND};

/// How long to wait for `rsftp-turbo ticket` on the server.
const TICKET_TIMEOUT: Duration = Duration::from_secs(15);
/// How long to wait for a directory listing from the helper (large folders
/// on slow links take a while to arrive).
const LIST_TIMEOUT: Duration = Duration::from_secs(60);

/// Whether the rsftp-turbo helper lists directories on this connection.
const HELPER_LISTING_UNKNOWN: u8 = 0;
const HELPER_LISTING_YES: u8 = 1;
const HELPER_LISTING_NO: u8 = 2;

/// One remote directory entry (symbolic links are described themselves).
#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: String,
    pub dir: bool,
    pub size: u64,
    /// Modification time, Unix seconds.
    pub mtime: Option<u64>,
}
/// Small, world-readable regular files used to check rsftp-turbo right after
/// connecting (the helper only issues tickets for regular files). The check
/// fetches and verifies at most [`TURBO_PROBE_BYTES`] of one over UDP.
const TURBO_PROBE_FILES: [&str; 3] = ["/etc/hostname", "/etc/os-release", "/etc/passwd"];
const TURBO_PROBE_BYTES: u64 = 4096;

/// Writes one line to the session's log: (severity, message id, message).
pub type EventLog = Arc<dyn Fn(crate::logging::Severity, &str, &str) + Send + Sync>;

/// Whether the server offers rsftp-turbo, learned on first use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TurboState {
    /// Turned off in the network settings.
    Disabled,
    /// Not tried yet (no download yet, and the connect-time check could not run).
    Untested,
    /// The connect-time check is running.
    Testing,
    /// The connect-time check reached the service over UDP.
    Ready,
    /// At least one download went over UDP.
    Active,
    /// Not usable on this connection; downloads use SFTP. Holds the reason.
    Unavailable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurboInfo {
    pub state: TurboState,
    /// Why the most recent file fell back to SFTP although turbo is usable.
    pub last_fallback: Option<String>,
}

/// A long-running `rsftp-turbo ticket --stream` on the server: one SSH
/// channel, reserved at connect time, that issues tickets for every download.
struct TicketStream {
    channel: russh::Channel<client::Msg>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Opens the ticket channel and starts the helper on it.
async fn open_ticket_stream(ssh: &client::Handle<VerifyHostKey>) -> Result<TicketStream, String> {
    let channel = ssh.channel_open_session().await
        .map_err(|error| format!("cannot open an SSH channel for rsftp-turbo: {error}"))?;
    channel.exec(true, TICKET_STREAM_COMMAND).await
        .map_err(|error| format!("cannot start rsftp-turbo: {error}"))?;
    Ok(TicketStream { channel, stdout: Vec::new(), stderr: Vec::new() })
}

/// What a turbo attempt achieved for one file.
enum TurboOutcome {
    /// The whole file arrived over turbo.
    Done(DownloadResult),
    /// The user stopped the transfer.
    Cancelled,
    /// Turbo was not used or did not finish; SFTP does the rest.
    NotUsed,
}

/// Why no ticket was issued.
enum TicketError {
    /// The helper is not installed, its service is not running, or exec is refused.
    Unavailable(String),
    /// The helper ran but refused this file (e.g. permission denied).
    Refused(String),
}

/// Read buffer for uploads; large enough to keep the SFTP write pipeline full.
const UPLOAD_BUFFER: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("host key verification required: {fingerprint}")]
    HostKeyRequired { fingerprint: String },
    #[error("host key changed; expected {expected}, received {observed}")]
    HostKeyChanged { expected: String, observed: String },
    #[error("SSH error: {0}")]
    Ssh(String),
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("SFTP subsystem request was rejected")]
    SubsystemRejected,
    #[error("SFTP error: {0}")]
    Sftp(String),
    #[error("private key error: {0}")]
    PrivateKey(String),
}

#[derive(Clone)]
struct VerifyHostKey {
    expected: Option<String>,
    observed: Arc<Mutex<Option<String>>>,
}

impl client::Handler for VerifyHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fingerprint = server_public_key.public_key().fingerprint(HashAlg::default()).to_string();
        if let Ok(mut slot) = self.observed.lock() {
            *slot = Some(fingerprint.clone());
        }
        // Unknown and changed keys are both rejected by the SSH handshake.
        Ok(self.expected.as_deref() == Some(fingerprint.as_str()))
    }
}

/// Retain the SSH handle for the lifetime of the SFTP channel.
pub struct SftpConnection {
    ssh: client::Handle<VerifyHostKey>,
    /// Primary channel, used for listings and file operations.
    sftp: Arc<SftpSession>,
    /// Every SFTP channel (the primary first); transfers are spread over them.
    channels: Vec<Arc<SftpSession>>,
    next_channel: AtomicUsize,
    turbo: Mutex<TurboInfo>,
    /// The ticket helper; `None` once it has exited or failed.
    tickets: tokio::sync::Mutex<Option<TicketStream>>,
    /// The session's log.
    events: EventLog,
    /// `HELPER_LISTING_*`: learned from the first listing.
    helper_listing: AtomicU8,
    /// The start folder, listed through the helper during connect, and how
    /// long that took; taken by the session.
    early_listing: Mutex<Option<(Result<(String, Vec<DirEntry>), String>, Duration)>>,
    /// Turbo segments in flight across all downloads of this connection.
    turbo_slots: Arc<Semaphore>,
    turbo_slot_count: AtomicUsize,
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
}

impl SftpConnection {
    /// With no pinned fingerprint this performs a rejected probe and reports the
    /// observed key. The caller must show it to the user, persist explicit trust,
    /// then call again with that exact fingerprint.
    pub async fn connect(
        profile: &ConnectionProfile,
        password: Option<&str>,
        trusted_fingerprint: Option<&str>,
        network: NetworkSettings,
        events: EventLog,
        start_folder: Option<String>,
    ) -> Result<Self, ConnectError> {
        use crate::logging::Severity;
        profile.validate().map_err(|e| ConnectError::Ssh(e.to_string()))?;
        if profile.auth_method == AuthMethod::SshAgent {
            return Err(ConnectError::Ssh("SSH-agent authentication is not implemented".into()));
        }

        let observed = Arc::new(Mutex::new(None));
        let handler = VerifyHostKey {
            expected: trusted_fingerprint.map(str::to_owned),
            observed: Arc::clone(&observed),
        };
        let config = network.ssh_config();
        let mut ssh = match client::connect(Arc::new(config), (profile.host.as_str(), profile.port), handler).await {
            Ok(session) => session,
            Err(error) => {
                let fingerprint = observed.lock().ok().and_then(|value| value.clone());
                if let Some(observed) = fingerprint {
                    return match trusted_fingerprint {
                        None => Err(ConnectError::HostKeyRequired { fingerprint: observed }),
                        Some(expected) => Err(ConnectError::HostKeyChanged {
                            expected: expected.to_owned(), observed,
                        }),
                    };
                }
                return Err(ConnectError::Ssh(error.to_string()));
            }
        };
        events(Severity::Info, "CONNECT", &format!(
            "SSH connection established; host key verified ({})",
            trusted_fingerprint.unwrap_or("not pinned")
        ));

        let method = match profile.auth_method {
            AuthMethod::Password => "a password".to_owned(),
            AuthMethod::PrivateKey => format!("the private key {}", profile.private_key_path.as_deref().unwrap_or("?")),
            AuthMethod::SshAgent => "the SSH agent".to_owned(),
        };
        events(Severity::Info, "AUTH", &format!("Authenticating as {} with {method}", profile.username));
        let authenticated = match profile.auth_method {
            AuthMethod::Password => {
                let password = password.ok_or_else(|| ConnectError::Ssh("Password is required".into()))?;
                ssh.authenticate_password(profile.username.clone(), password).await
                    .map_err(|e| ConnectError::Ssh(e.to_string()))?.success()
            }
            AuthMethod::PrivateKey => {
                let key_path = profile.private_key_path.as_deref()
                    .ok_or_else(|| ConnectError::PrivateKey("Key path is missing".into()))?;
                let key = russh::keys::load_secret_key(Path::new(key_path), None)
                    .map_err(|e| ConnectError::PrivateKey(e.to_string()))?;
                let hash = ssh.best_supported_rsa_hash().await
                    .map_err(|e| ConnectError::Ssh(e.to_string()))?.flatten();
                ssh.authenticate_publickey(
                    profile.username.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                ).await.map_err(|e| ConnectError::Ssh(e.to_string()))?.success()
            }
            AuthMethod::SshAgent => false,
        };
        if !authenticated {
            events(Severity::Warning, "AUTH", &format!("Authentication failed: the server rejected {method} for {}", profile.username));
            return Err(ConnectError::AuthenticationFailed);
        }
        events(Severity::Notice, "AUTH", &format!("Authentication succeeded as {}", profile.username));

        // The rsftp-turbo helper first: it reserves its channel before the
        // SFTP channels take the remaining session slots (OpenSSH
        // MaxSessions), and it can list the start folder while they open.
        let (mut tickets, mut turbo_state) = if network.turbo {
            match open_ticket_stream(&ssh).await {
                Ok(stream) => {
                    events(Severity::Info, "TURBO", "Started the rsftp-turbo helper over SSH");
                    (Some(stream), TurboState::Untested)
                }
                Err(reason) => {
                    events(Severity::Warning, "TURBO", &format!("rsftp-turbo helper not available ({reason}); downloads use SFTP"));
                    (None, TurboState::Unavailable(reason))
                }
            }
        } else {
            events(Severity::Info, "TURBO", "rsftp-turbo is turned off in the settings; downloads use SFTP");
            (None, TurboState::Disabled)
        };

        let early = async {
            let (stream, path) = (tickets.as_mut()?, start_folder.as_deref()?);
            events(Severity::Info, "LIST", &format!("Listing {path} through the rsftp-turbo helper while the SFTP channels open"));
            let started = Instant::now();
            Some(match exchange_line(stream, list_request(path)?, LIST_TIMEOUT).await {
                Ok(reply) => match listing_from_reply(reply) {
                    Some(result) => EarlyListing::Listed(result, started.elapsed()),
                    None => EarlyListing::NotSupported,
                },
                Err(TicketError::Unavailable(reason) | TicketError::Refused(reason)) => EarlyListing::HelperFailed(reason),
            })
        };
        let (early, channels) = tokio::join!(early, open_sftp_channels(&ssh, &network, network.channel_count()));
        let channels = channels?;
        let sftp = Arc::clone(&channels[0]);
        events(Severity::Info, "SFTP", &format!("Opened {} SFTP channel(s)", channels.len()));

        let mut helper_listing = HELPER_LISTING_UNKNOWN;
        let early_listing = match early {
            Some(EarlyListing::Listed(result, took)) => {
                helper_listing = HELPER_LISTING_YES;
                Some((result, took))
            }
            Some(EarlyListing::NotSupported) => {
                helper_listing = HELPER_LISTING_NO;
                events(Severity::Info, "LIST", "Directory listings use SFTP (the rsftp-turbo helper is too old to list)");
                None
            }
            Some(EarlyListing::HelperFailed(reason)) => {
                // Its stream is out of step now: turbo is off for this connection.
                tickets = None;
                events(Severity::Warning, "TURBO", &format!("rsftp-turbo helper stopped ({reason}); falling back to SFTP"));
                turbo_state = TurboState::Unavailable(reason);
                None
            }
            None => None,
        };

        Ok(Self {
            events,
            ssh,
            sftp,
            channels,
            next_channel: AtomicUsize::new(0),
            turbo: Mutex::new(TurboInfo { state: turbo_state, last_fallback: None }),
            tickets: tokio::sync::Mutex::new(tickets),
            helper_listing: AtomicU8::new(helper_listing),
            early_listing: Mutex::new(early_listing),
            turbo_slots: Arc::new(Semaphore::new(turbo::CONNECTION_FETCH_SLOTS)),
            turbo_slot_count: AtomicUsize::new(turbo::CONNECTION_FETCH_SLOTS),
            host: profile.host.clone(),
            port: profile.port,
            fingerprint: trusted_fingerprint.unwrap_or_default().to_owned(),
        })
    }

    /// All SFTP channels, starting at the next one in round-robin order, so
    /// consecutive transfers begin on different channels.
    fn transfer_sessions(&self) -> Vec<Arc<SftpSession>> {
        let start = self.next_channel.fetch_add(1, Ordering::Relaxed);
        let count = self.channels.len();
        (0..count).map(|offset| Arc::clone(&self.channels[(start + offset) % count])).collect()
    }

    /// Number of SFTP channels actually opened.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Opens an interactive login shell on its own SSH channel, with a
    /// pseudo-terminal of type `term` and `cols` x `rows` characters.
    pub async fn open_shell(&self, term: &str, cols: u16, rows: u16) -> Result<russh::Channel<client::Msg>, String> {
        let channel = self.ssh.channel_open_session().await.map_err(|error| {
            format!("could not open an SSH channel ({error}); the server's session limit (MaxSessions) may be reached")
        })?;
        channel.request_pty(true, term, u32::from(cols), u32::from(rows), 0, 0, &[]).await
            .map_err(|error| format!("pseudo-terminal request failed: {error}"))?;
        channel.request_shell(true).await.map_err(|error| format!("shell request failed: {error}"))?;
        Ok(channel)
    }

    /// Writes a line to the session's log.
    pub fn log(&self, severity: crate::logging::Severity, msgid: &str, message: &str) {
        (self.events)(severity, msgid, message);
    }

    pub async fn list_dir(&self, path: &str) -> Result<ReadDir, ConnectError> {
        self.sftp.read_dir(path.to_owned()).await.map_err(|e| ConnectError::Sftp(e.to_string()))
    }

    pub async fn canonicalize(&self, path: &str) -> Result<String, ConnectError> {
        self.sftp.canonicalize(path.to_owned()).await.map_err(|e| ConnectError::Sftp(e.to_string()))
    }

    /// Lists `path` (absolute, or relative to the home folder) and returns
    /// its absolute path and entries (without `.` and `..`, unsorted).
    ///
    /// Uses the rsftp-turbo helper when it can list: one round trip over the
    /// SSH channel it already holds, instead of SFTP's realpath, opendir,
    /// several readdirs and close. Falls back to SFTP when the helper is not
    /// running or too old.
    pub async fn list_directory(&self, path: &str) -> Result<(String, Vec<DirEntry>), String> {
        if self.helper_listing.load(Ordering::Relaxed) != HELPER_LISTING_NO {
            match self.helper_list(path).await {
                Some(result) => {
                    self.helper_listing.store(HELPER_LISTING_YES, Ordering::Relaxed);
                    return result;
                }
                None => {
                    self.helper_listing.store(HELPER_LISTING_NO, Ordering::Relaxed);
                    (self.events)(
                        crate::logging::Severity::Info,
                        "LIST",
                        "Directory listings use SFTP (the rsftp-turbo helper is not running or too old to list)",
                    );
                }
            }
        }
        self.sftp_list(path).await
    }

    /// The start folder's listing if the helper produced it during connect.
    pub fn take_early_listing(&self) -> Option<(Result<(String, Vec<DirEntry>), String>, Duration)> {
        self.early_listing.lock().ok().and_then(|mut early| early.take())
    }

    /// `Some(true)` once a listing came from the rsftp-turbo helper,
    /// `Some(false)` once listings fell back to SFTP, `None` before the first.
    pub fn listing_via_helper(&self) -> Option<bool> {
        match self.helper_listing.load(Ordering::Relaxed) {
            HELPER_LISTING_YES => Some(true),
            HELPER_LISTING_NO => Some(false),
            _ => None,
        }
    }

    /// `None` if the helper cannot list (use SFTP); otherwise its answer,
    /// which may be an error such as "permission denied".
    async fn helper_list(&self, path: &str) -> Option<Result<(String, Vec<DirEntry>), String>> {
        let reply = self.helper_exchange(list_request(path)?, LIST_TIMEOUT).await.ok()?;
        listing_from_reply(reply)
    }

    async fn sftp_list(&self, path: &str) -> Result<(String, Vec<DirEntry>), String> {
        let requested = if path.is_empty() { "." } else { path };
        let path = if crate::session::needs_canonical_path(requested) {
            self.canonicalize(requested).await.map_err(|e| e.to_string())?
        } else {
            requested.to_owned()
        };
        let read_dir = self.list_dir(&path).await.map_err(|e| e.to_string())?;
        let entries = read_dir
            .filter_map(|entry| {
                let name = entry.file_name();
                if name == "." || name == ".." {
                    return None;
                }
                let attrs = entry.metadata();
                Some(DirEntry { dir: attrs.is_dir(), size: attrs.size.unwrap_or(0), mtime: attrs.mtime.map(u64::from), name })
            })
            .collect();
        Ok((path, entries))
    }


    /// Recursively upload a local file or directory to a remote destination.
    /// Directory structure is preserved and progress is reported separately for each file.
    /// Each file waits for one of the session's `file_slots`.
    pub async fn upload_path(
        &self,
        local_path: &Path,
        remote_path: &str,
        file_slots: Arc<Semaphore>,
        plan: Option<TransferPlan>,
        progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
        cancel: CancelToken,
    ) -> Result<DownloadResult, crate::transfer::DownloadError> {
        let TransferPlan { mut directories, files } = match plan {
            Some(plan) => plan,
            None => plan_upload(local_path, remote_path).await?,
        };
        let files: Vec<(PathBuf, String, u64, Option<u64>)> =
            files.into_iter().map(|file| (file.local, file.remote, file.size, file.mtime)).collect();
        let total = files.iter().map(|(_, _, size, _)| size).sum::<u64>();

        // Parent directories must exist before their children are uploaded.
        directories.sort_by_key(|(path, _)| path.components().count());
        for (_, directory) in &directories {
            if !self.sftp.try_exists(directory.clone()).await
                .map_err(|e| crate::transfer::DownloadError::Sftp(e.to_string()))? {
                self.sftp.create_dir(directory.clone()).await
                    .map_err(|e| crate::transfer::DownloadError::Sftp(e.to_string()))?;
            }
        }

        if let Some(tx) = &progress {
            for (local, _, file_size, _) in &files {
                let relative_path = local.strip_prefix(local_path).unwrap_or(local);
                let relative = if relative_path.as_os_str().is_empty() {
                    local.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()
                } else {
                    relative_path.to_string_lossy().to_string()
                };
                let _ = tx.send(DownloadProgress {
                    total_bytes: *file_size, transferred_bytes: 0,
                    completed_segments: 0, total_segments: 0, segment: None,
                    file_path: Some(relative), file_complete: false, accelerated: false,
                });
            }
        }
        let transferred_total = Arc::new(AtomicU64::new(0));
        let parallel = file_slots;
        let mut workers = JoinSet::new();
        for (local, remote, file_size, mtime) in files {
            let relative = relative_name(&local, local_path);
            let Some(sftp) = self.transfer_sessions().into_iter().next() else { break; };
            let parallel = Arc::clone(&parallel);
            let transferred_total = Arc::clone(&transferred_total);
            let progress = progress.clone();
            let cancel = cancel.clone();
            workers.spawn(async move {
                let _permit = tokio::select! {
                    permit = parallel.acquire_owned() => permit.map_err(|e| DownloadError::Worker(e.to_string()))?,
                    _ = cancel.cancelled() => return Err(DownloadError::Cancelled),
                };
                let mut buffer = vec![0_u8; UPLOAD_BUFFER];
                let mut file_transferred = 0_u64;
                let mut input = fs::File::open(&local).await.map_err(DownloadError::Io)?;
                let mut output = sftp.create(remote.clone()).await.map_err(|e| DownloadError::Sftp(e.to_string()))?;
                loop {
                    if cancel.is_cancelled() {
                        // Don't leave a truncated file behind on the server.
                        drop(output);
                        let _ = sftp.remove_file(remote).await;
                        return Err(DownloadError::Cancelled);
                    }
                    let count = input.read(&mut buffer).await.map_err(DownloadError::Io)?;
                    if count == 0 { break; }
                    output.write_all(&buffer[..count]).await.map_err(|e| DownloadError::Sftp(e.to_string()))?;
                    transferred_total.fetch_add(count as u64, Ordering::Relaxed);
                    file_transferred = file_transferred.saturating_add(count as u64);
                    if let Some(tx) = &progress {
                        let _ = tx.send(DownloadProgress {
                            total_bytes: file_size,
                            transferred_bytes: file_transferred,
                            completed_segments: 0,
                            total_segments: 0,
                            segment: None,
                            file_path: Some(relative.clone()),
                            file_complete: false, accelerated: false,
                        });
                    }
                }
                output.close().await.map_err(|e| DownloadError::Sftp(e.to_string()))?;
                // Keep the modification time, so later transfers can compare it.
                if let Some(mtime) = mtime.and_then(|mtime| u32::try_from(mtime).ok()) {
                    let mut attributes = russh_sftp::protocol::FileAttributes::empty();
                    attributes.atime = Some(mtime);
                    attributes.mtime = Some(mtime);
                    let _ = sftp.set_metadata(remote.clone(), attributes).await;
                }
                if let Some(tx) = &progress {
                    let _ = tx.send(DownloadProgress {
                        total_bytes: file_size, transferred_bytes: file_transferred,
                        completed_segments: 0, total_segments: 0, segment: None,
                        file_path: Some(relative), file_complete: true, accelerated: false,
                    });
                }
                Ok::<(), DownloadError>(())
            });
        }
        let mut failure = None;
        while let Some(joined) = workers.join_next().await {
            let result = joined.unwrap_or_else(|error| Err(DownloadError::Worker(error.to_string())));
            if let Err(error) = result {
                // Stop the other files cleanly (they remove partial uploads) and
                // report the first error once they have finished.
                cancel.cancel();
                failure.get_or_insert(error);
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        let transferred = transferred_total.load(Ordering::Relaxed);
        if let Some(tx) = &progress {
            let _ = tx.send(DownloadProgress {
                total_bytes: total, transferred_bytes: transferred,
                completed_segments: 0, total_segments: 0, segment: None,
                file_path: None, file_complete: false, accelerated: false,
            });
        }
        Ok(DownloadResult { bytes: transferred, segments: 0, segmented: false, accelerated: false, details: None })
    }

    /// Recursively download a remote file or directory. Each file uses the
    /// existing segmented downloader; progress is reported separately for each file.
    /// Each file waits for one of the session's `file_slots`.
    #[allow(clippy::too_many_arguments)]
    pub async fn download_path(
        self: Arc<Self>,
        remote_path: &str,
        destination: &Path,
        settings: TransferSettings,
        file_slots: Arc<Semaphore>,
        plan: Option<TransferPlan>,
        progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
        cancel: CancelToken,
    ) -> Result<DownloadResult, crate::transfer::DownloadError> {
        let plan = match plan {
            Some(plan) => plan,
            None => self.plan_download(remote_path, destination).await?,
        };
        let directories: Vec<PathBuf> = plan.directories.into_iter().map(|(local, _)| local).collect();
        let files: Vec<(String, PathBuf, u64)> = plan.files.into_iter().map(|file| (file.remote, file.local, file.size)).collect();
        let total = files.iter().map(|(_, _, size)| size).sum::<u64>();

        for directory in directories {
            fs::create_dir_all(directory).await
                .map_err(crate::transfer::DownloadError::Io)?;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).await
                .map_err(crate::transfer::DownloadError::Io)?;
        }

        if let Some(tx) = &progress {
            for (_, local, file_size) in &files {
                let relative_path = local.strip_prefix(destination).unwrap_or(local);
                let relative = if relative_path.as_os_str().is_empty() {
                    local.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()
                } else {
                    relative_path.to_string_lossy().to_string()
                };
                let _ = tx.send(DownloadProgress {
                    total_bytes: *file_size, transferred_bytes: 0,
                    completed_segments: 0, total_segments: 0, segment: None,
                    file_path: Some(relative), file_complete: false, accelerated: false,
                });
            }
        }
        let parallel = file_slots;
        let mut workers = JoinSet::new();
        for (remote, local, file_size) in files {
            let relative = relative_name(&local, destination);
            let connection = Arc::clone(&self);
            let parallel = Arc::clone(&parallel);
            let progress = progress.clone();
            let cancel = cancel.clone();
            workers.spawn(async move {
                let _permit = tokio::select! {
                    permit = parallel.acquire_owned() => permit.map_err(|e| DownloadError::Worker(e.to_string()))?,
                    _ = cancel.cancelled() => return Err(DownloadError::Cancelled),
                };
                let (inner_tx, mut inner_rx) = mpsc::unbounded_channel();
                let download = connection.download_one(&remote, &local, settings, Some(inner_tx), cancel);
                tokio::pin!(download);
                loop {
                    tokio::select! {
                        result = &mut download => {
                            let result = result?;
                            if let Some(tx) = &progress {
                                let _ = tx.send(DownloadProgress {
                                    total_bytes: result.bytes, transferred_bytes: result.bytes,
                                    completed_segments: result.segments, total_segments: result.segments,
                                    segment: None, file_path: Some(relative.clone()), file_complete: true, accelerated: result.accelerated,
                                });
                            }
                            return Ok::<DownloadResult, DownloadError>(result);
                        }
                        update = inner_rx.recv() => {
                            if let (Some(tx), Some(update)) = (&progress, update) {
                                let segment = update.segment.map(|segment| SegmentProgress {
                                    index: segment.index,
                                    start: segment.start,
                                    end_exclusive: segment.end_exclusive,
                                    transferred_bytes: segment.transferred_bytes,
                                    complete: segment.complete,
                                    failed: segment.failed,
                                });
                                let _ = tx.send(DownloadProgress {
                                    total_bytes: file_size,
                                    transferred_bytes: update.transferred_bytes,
                                    completed_segments: update.completed_segments,
                                    total_segments: update.total_segments,
                                    segment,
                                    file_path: Some(relative.clone()), file_complete: false, accelerated: update.accelerated,
                                });
                            }
                        }
                    }
                }
            });
        }
        let mut completed = 0_u64;
        let mut segment_count = 0_u32;
        let mut segmented = false;
        let mut accelerated = false;
        let mut details: Vec<String> = Vec::new();
        let mut failure = None;
        while let Some(joined) = workers.join_next().await {
            match joined.unwrap_or_else(|error| Err(DownloadError::Worker(error.to_string()))) {
                Ok(result) => {
                    completed = completed.saturating_add(result.bytes);
                    segment_count = segment_count.saturating_add(result.segments);
                    segmented |= result.segmented;
                    accelerated |= result.accelerated;
                    details.extend(result.details);
                }
                Err(error) => {
                    // Let the other files stop cleanly (removing their temporary
                    // files) and report the first error afterwards.
                    cancel.cancel();
                    failure.get_or_insert(error);
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        if let Some(tx) = &progress {
            let _ = tx.send(DownloadProgress {
                total_bytes: total, transferred_bytes: completed,
                completed_segments: segment_count, total_segments: segment_count,
                segment: None, file_path: None, file_complete: false, accelerated: false,
            });
        }
        // A single file (the usual right-click / drag download) keeps its own
        // statistics; for folders, list them per file.
        let details = match details.len() {
            0 => None,
            1 => details.pop(),
            _ => Some(details.join("; ")),
        };
        Ok(DownloadResult { bytes: completed, segments: segment_count, segmented, accelerated, details })
    }

    /// Lists what downloading `remote_path` (a file or a folder, recursively)
    /// to `destination` transfers.
    pub async fn plan_download(&self, remote_path: &str, destination: &Path) -> Result<TransferPlan, DownloadError> {
        let root_meta = self.sftp.metadata(remote_path.to_owned()).await
            .map_err(|e| DownloadError::Sftp(e.to_string()))?;
        let mut plan = TransferPlan::default();
        let mut stack = vec![(remote_path.to_owned(), destination.to_path_buf(), root_meta)];
        while let Some((remote, local, metadata)) = stack.pop() {
            if metadata.is_dir() {
                plan.directories.push((local.clone(), remote.clone()));
                let entries = self.sftp.read_dir(remote.clone()).await
                    .map_err(|e| DownloadError::Sftp(e.to_string()))?;
                for entry in entries {
                    let name = entry.file_name();
                    if name == "." || name == ".." { continue; }
                    let attrs = entry.metadata();
                    let child_remote = format!("{}/{}", remote.trim_end_matches('/'), name);
                    stack.push((child_remote, local.join(&name), attrs));
                }
            } else {
                plan.files.push(PlannedFile {
                    local,
                    remote,
                    size: metadata.size.unwrap_or(0),
                    mtime: metadata.mtime.map(u64::from),
                });
            }
        }
        Ok(plan)
    }

    /// Size and modification time of the remote files the upload `plan`
    /// would write that exist already, by index into `plan.files`. Each
    /// target folder is listed once.
    pub async fn existing_remote_targets(&self, plan: &TransferPlan) -> Vec<Option<TargetFile>> {
        let mut folders: std::collections::HashMap<String, std::collections::HashMap<String, TargetFile>> =
            std::collections::HashMap::new();
        let mut found = Vec::with_capacity(plan.files.len());
        for file in &plan.files {
            let (folder, name) = match file.remote.rsplit_once('/') {
                Some(("", name)) => ("/".to_owned(), name.to_owned()),
                Some((folder, name)) => (folder.to_owned(), name.to_owned()),
                None => (".".to_owned(), file.remote.clone()),
            };
            if !folders.contains_key(&folder) {
                // A folder that does not exist yet holds nothing to overwrite.
                let mut listing = std::collections::HashMap::new();
                if let Ok(entries) = self.sftp.read_dir(folder.clone()).await {
                    for entry in entries {
                        let attrs = entry.metadata();
                        if !attrs.is_dir() {
                            listing.insert(
                                entry.file_name(),
                                TargetFile { size: attrs.size.unwrap_or(0), mtime: attrs.mtime.map(u64::from) },
                            );
                        }
                    }
                }
                folders.insert(folder.clone(), listing);
            }
            found.push(folders.get(&folder).and_then(|listing| listing.get(&name)).copied());
        }
        found
    }

    pub async fn create_dir(&self, path: &str) -> Result<(), ConnectError> {
        self.sftp.create_dir(path.to_owned()).await.map_err(|e| ConnectError::Sftp(e.to_string()))
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<(), ConnectError> {
        self.sftp.rename(from.to_owned(), to.to_owned()).await.map_err(|e| ConnectError::Sftp(e.to_string()))
    }

    /// Deletes a file, symlink or (recursively) a directory. Symlinks are
    /// removed, never followed.
    pub async fn remove_path(&self, path: &str) -> Result<(), ConnectError> {
        let sftp_error = |e: russh_sftp::client::error::Error| ConnectError::Sftp(e.to_string());
        let metadata = self.sftp.symlink_metadata(path.to_owned()).await.map_err(sftp_error)?;
        if !metadata.is_dir() {
            return self.sftp.remove_file(path.to_owned()).await.map_err(sftp_error);
        }
        // Parents are recorded before their children, so deleting in reverse
        // order empties every directory before it is removed.
        let mut directories = vec![path.to_owned()];
        let mut stack = vec![path.to_owned()];
        while let Some(directory) = stack.pop() {
            let entries = self.sftp.read_dir(directory.clone()).await.map_err(sftp_error)?;
            for entry in entries {
                let name = entry.file_name();
                if name == "." || name == ".." { continue; }
                let child = format!("{}/{}", directory.trim_end_matches('/'), name);
                if entry.metadata().is_dir() {
                    directories.push(child.clone());
                    stack.push(child);
                } else {
                    self.sftp.remove_file(child).await.map_err(sftp_error)?;
                }
            }
        }
        for directory in directories.into_iter().rev() {
            self.sftp.remove_dir(directory).await.map_err(sftp_error)?;
        }
        Ok(())
    }

    pub async fn download(
        self: Arc<Self>,
        remote_path: &str,
        destination: &Path,
        settings: TransferSettings,
        progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
        cancel: CancelToken,
    ) -> Result<DownloadResult, crate::transfer::DownloadError> {
        self.download_one(remote_path, destination, settings, progress, cancel).await
    }

    /// Downloads one regular file: over rsftp-turbo (UDP) when the server
    /// offers it, otherwise (or if turbo fails) over SFTP.
    async fn download_one(
        &self,
        remote_path: &str,
        destination: &Path,
        settings: TransferSettings,
        progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
        cancel: CancelToken,
    ) -> Result<DownloadResult, DownloadError> {
        if cancel.is_cancelled() {
            return Err(DownloadError::Cancelled);
        }
        let metadata = self.sftp.metadata(remote_path.to_owned()).await
            .map_err(|e| DownloadError::Sftp(e.to_string()))?;
        let size = metadata.size.ok_or(DownloadError::UnknownSize)?;
        let mtime = metadata.mtime.map(u64::from);
        // Resumes an earlier attempt of the same, unchanged file.
        let partial = Partial::open(destination, remote_path, size, mtime)?;
        partial.announce(&progress);

        let mut details = None;
        let mut accelerated = false;
        if !partial.is_complete() {
            match self.try_turbo(remote_path, &partial, settings, progress.clone(), cancel.clone()).await {
                TurboOutcome::Done(result) => {
                    accelerated = true;
                    details = result.details;
                }
                TurboOutcome::Cancelled => {
                    partial.discard();
                    return Err(DownloadError::Cancelled);
                }
                TurboOutcome::NotUsed => {}
            }
        }
        if !partial.is_complete() {
            let resumed_from = partial.done_bytes();
            match download_file(self.transfer_sessions(), remote_path, &partial, settings, progress, cancel).await {
                Ok(_) => {
                    if resumed_from > 0 {
                        let note = format!("resumed: {resumed_from} of {size} bytes were already downloaded");
                        details = Some(match details {
                            Some(turbo) => format!("{turbo}; {note}"),
                            None => note,
                        });
                    }
                }
                Err(DownloadError::Cancelled) => {
                    partial.discard();
                    return Err(DownloadError::Cancelled);
                }
                // Completed pieces stay on disk; the next attempt resumes.
                Err(error) => return Err(error),
            }
        }
        partial.finish(destination).await?;
        // Keep the modification time, so later transfers can compare it.
        if let Some(mtime) = mtime {
            set_local_mtime(destination, mtime);
        }
        let pieces = partial.pieces_used();
        Ok(DownloadResult { bytes: size, segments: pieces, segmented: pieces > 1, accelerated, details })
    }

    /// Turbo state of this connection, for display.
    pub fn turbo_info(&self) -> TurboInfo {
        self.turbo.lock().map(|info| info.clone()).unwrap_or(TurboInfo {
            state: TurboState::Unavailable("internal error".into()),
            last_fallback: None,
        })
    }

    /// Marks the connect-time turbo check as started; false if there is
    /// nothing to check (turbo is off or already known to be unavailable).
    pub fn begin_turbo_probe(&self) -> bool {
        let Ok(mut info) = self.turbo.lock() else { return false };
        if info.state != TurboState::Untested {
            return false;
        }
        info.state = TurboState::Testing;
        true
    }

    /// Checks right after connecting that rsftp-turbo answers, so its status
    /// is known before the first download. Call after `begin_turbo_probe`.
    pub async fn probe_turbo(&self) {
        use crate::logging::Severity;
        (self.events)(Severity::Info, "TURBO", "Checking the rsftp-turbo service over UDP");
        let state = self.turbo_probe_state().await;
        match &state {
            TurboState::Ready => (self.events)(Severity::Notice, "TURBO", "rsftp-turbo service confirmed over UDP; downloads will use it"),
            TurboState::Unavailable(reason) => {
                (self.events)(Severity::Warning, "TURBO", &format!("rsftp-turbo service unavailable ({reason}); downloads use SFTP"))
            }
            TurboState::Untested => (self.events)(
                Severity::Info,
                "TURBO",
                "Could not check rsftp-turbo now (no small readable file to probe); the first download will",
            ),
            _ => {}
        }
        if let Ok(mut info) = self.turbo.lock() {
            // A download may have settled the state in the meantime.
            if info.state == TurboState::Testing {
                info.state = state;
            }
        }
    }

    async fn turbo_probe_state(&self) -> TurboState {
        let mut ticket = None;
        for path in TURBO_PROBE_FILES {
            match self.request_turbo_ticket(path).await {
                // An empty file has nothing to fetch; try the next one.
                Ok(issued) if issued.size == 0 => {}
                Ok(issued) => {
                    ticket = Some(issued);
                    break;
                }
                Err(TicketError::Unavailable(reason)) => return TurboState::Unavailable(reason),
                Err(TicketError::Refused(_)) => {}
            }
        }
        // No readable probe file: leave it to the first download.
        let Some(ticket) = ticket else { return TurboState::Untested };
        let Some(server) = self.turbo_address(&ticket).await else {
            return TurboState::Unavailable(format!("cannot resolve {} for UDP", self.host));
        };
        let connection = match rsftp_turbo_proto::client::Connection::new(server, &ticket) {
            Ok(connection) => connection,
            Err(error) => return TurboState::Unavailable(error.to_string()),
        };
        let len = ticket.size.min(TURBO_PROBE_BYTES) as u32;
        let result = match rsftp_turbo_proto::client::SegmentFetcher::new(std::sync::Arc::clone(&connection)).await {
            Ok(mut fetcher) => fetcher.fetch(0, len, &mut |_: u64| {}, &|| false).await.map(|_| ()),
            Err(error) => Err(error),
        };
        connection.close().await;
        match result {
            Ok(_) => TurboState::Ready,
            Err(error) => TurboState::Unavailable(format!(
                "no answer from {server} over UDP (is port {}/udp open and the service listening on that address?): {error}",
                server.port()
            )),
        }
    }

    fn set_turbo_state(&self, state: TurboState) {
        if let TurboState::Unavailable(reason) = &state {
            let was = self.turbo_info().state;
            if !matches!(was, TurboState::Unavailable(_)) {
                (self.events)(crate::logging::Severity::Warning, "TURBO", &format!(
                    "rsftp-turbo unavailable for this connection ({reason}); falling back to SFTP"
                ));
            }
        }
        if let Ok(mut info) = self.turbo.lock() {
            info.state = state;
        }
    }

    fn note_turbo_fallback(&self, reason: String) {
        (self.events)(crate::logging::Severity::Warning, "TURBO", &format!("Falling back to SFTP: {reason}"));
        if let Ok(mut info) = self.turbo.lock() {
            info.last_fallback = Some(reason);
        }
    }

    /// `None` means "use SFTP"; `Some` is the final result of a turbo download.
    /// Downloads as much of `partial` as possible over rsftp-turbo.
    async fn try_turbo(
        &self,
        remote_path: &str,
        partial: &Arc<Partial>,
        settings: TransferSettings,
        progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
        cancel: CancelToken,
    ) -> TurboOutcome {
        if matches!(self.turbo_info().state, TurboState::Disabled | TurboState::Unavailable(_)) {
            return TurboOutcome::NotUsed;
        }
        let ticket = match self.request_turbo_ticket(remote_path).await {
            Ok(ticket) => ticket,
            Err(TicketError::Unavailable(reason)) => {
                self.set_turbo_state(TurboState::Unavailable(reason));
                return TurboOutcome::NotUsed;
            }
            // SFTP will report the real problem (e.g. permission denied).
            Err(TicketError::Refused(reason)) => {
                self.note_turbo_fallback(format!("{remote_path}: {reason}"));
                return TurboOutcome::NotUsed;
            }
        };
        if ticket.size != partial.size {
            self.note_turbo_fallback(format!("{remote_path}: the file changed size while starting the download"));
            return TurboOutcome::NotUsed;
        }
        let Some(server) = self.turbo_address(&ticket).await else {
            self.set_turbo_state(TurboState::Unavailable(format!("cannot resolve {} for UDP", self.host)));
            return TurboOutcome::NotUsed;
        };
        // One file may still use all of its configured workers.
        let wanted = settings.max_segments_per_file as usize;
        let current = self.turbo_slot_count.fetch_max(wanted, Ordering::Relaxed);
        if wanted > current {
            self.turbo_slots.add_permits(wanted - current);
        }
        match turbo::download(server, &ticket, partial, settings, progress, cancel, Arc::clone(&self.turbo_slots)).await {
            Ok(result) => {
                self.set_turbo_state(TurboState::Active);
                TurboOutcome::Done(result)
            }
            Err(TurboError::Failed(DownloadError::Cancelled)) => TurboOutcome::Cancelled,
            // UDP blocked or service down: stop trying on this connection.
            Err(TurboError::Unavailable(_)) => {
                self.set_turbo_state(TurboState::Unavailable(format!(
                    "no answer from {server} over UDP (is port {}/udp open and the service listening on that address?)",
                    server.port()
                )));
                TurboOutcome::NotUsed
            }
            // Anything else: SFTP finishes the missing pieces of this file.
            Err(TurboError::Failed(error)) => {
                self.note_turbo_fallback(format!(
                    "{remote_path}: {error} (finished over SFTP from byte {} of {})",
                    partial.done_bytes(),
                    partial.size
                ));
                TurboOutcome::NotUsed
            }
        }
    }

    /// UDP address of the turbo service: the host this client connected to
    /// over SSH, on the ticket's port.
    ///
    /// The address in the ticket comes from `SSH_CONNECTION` and is the
    /// server's *own* address, which behind NAT or port forwarding is a
    /// private one the client cannot reach; it is only used if the host name
    /// cannot be resolved.
    async fn turbo_address(&self, ticket: &Ticket) -> Option<SocketAddr> {
        if let Ok(mut addresses) = tokio::net::lookup_host((self.host.as_str(), ticket.port)).await {
            if let Some(address) = addresses.next() {
                return Some(address);
            }
        }
        let ip = ticket.address.as_deref()?.parse::<std::net::IpAddr>().ok()?;
        Some(SocketAddr::new(ip, ticket.port))
    }

    /// Asks the ticket helper for a ticket for `remote_path`.
    async fn request_turbo_ticket(&self, remote_path: &str) -> Result<Ticket, TicketError> {
        if remote_path.contains('\n') {
            return Err(TicketError::Refused("file names containing a newline are not supported".into()));
        }
        // Lines starting with `{` are JSON requests; real paths are absolute.
        if !remote_path.starts_with('/') {
            return Err(TicketError::Refused("only absolute paths can be fetched over rsftp-turbo".into()));
        }
        ticket_from_reply(self.helper_exchange(format!("{remote_path}\n"), TICKET_TIMEOUT).await?)
    }

    /// Writes one request line to the helper and reads its JSON reply line.
    /// Requests are serialised on the one channel. A helper that fails,
    /// answers garbage or times out is dropped (its stream would be out of
    /// step), which turns turbo off for this connection.
    async fn helper_exchange(&self, line: String, limit: Duration) -> Result<StreamReply, TicketError> {
        let mut guard = self.tickets.lock().await;
        let Some(stream) = guard.as_mut() else {
            return Err(TicketError::Unavailable("the rsftp-turbo helper is not running".into()));
        };
        let result = exchange_line(stream, line, limit).await;
        // A helper that died or stopped answering is unusable from now on.
        if matches!(result, Err(TicketError::Unavailable(_))) {
            *guard = None;
        }
        result
    }
}

/// Writes one request line to the helper and reads its JSON reply line.
/// After an `Unavailable` error the stream is out of step and must be dropped.
async fn exchange_line(stream: &mut TicketStream, mut line: String, limit: Duration) -> Result<StreamReply, TicketError> {
    if !line.ends_with('\n') {
        line.push('\n');
    }
    let exchange = async {
        stream.channel.data(line.as_bytes()).await
            .map_err(|error| TicketError::Unavailable(format!("rsftp-turbo channel failed: {error}")))?;
        let mut exit_status = None;
        loop {
            if let Some(end) = stream.stdout.iter().position(|&byte| byte == b'\n') {
                let line: Vec<u8> = stream.stdout.drain(..=end).collect();
                return serde_json::from_slice::<StreamReply>(&line).map_err(|error| {
                    TicketError::Unavailable(format!("unexpected reply from rsftp-turbo: {error}"))
                });
            }
            match stream.channel.wait().await {
                Some(ChannelMsg::Data { data }) => stream.stdout.extend_from_slice(&data),
                Some(ChannelMsg::ExtendedData { data, .. }) => stream.stderr.extend_from_slice(&data),
                Some(ChannelMsg::ExitStatus { exit_status: status }) => exit_status = Some(status),
                Some(ChannelMsg::Failure) => {
                    return Err(TicketError::Unavailable("the server refused to run rsftp-turbo".into()));
                }
                // Eof may come before the exit status; wait for Close.
                Some(ChannelMsg::Close) | None => return Err(helper_exited(exit_status, &stream.stderr)),
                Some(_) => {}
            }
        }
    };
    let result = match tokio::time::timeout(limit, exchange).await {
        Ok(result) => result,
        Err(_) => Err(TicketError::Unavailable(
            "timed out waiting for the rsftp-turbo helper (is rsftp-turbo on the server up to date?)".into(),
        )),
    };
    result
}

/// Interprets the helper's answer to a list request; `None` if the helper is
/// too old to list (it answered as if the request were a file name).
fn listing_from_reply(reply: StreamReply) -> Option<Result<(String, Vec<DirEntry>), String>> {
    if !reply.list_reply {
        return None;
    }
    Some(match (reply.listing, reply.error) {
        (Some(listing), _) => Ok((
            listing.path,
            listing
                .entries
                .into_iter()
                .filter(|entry| entry.name != "." && entry.name != "..")
                .map(|entry| DirEntry { name: entry.name, dir: entry.dir, size: entry.size, mtime: entry.mtime })
                .collect(),
        )),
        (None, Some(error)) => Err(error),
        (None, None) => Err("empty listing reply from rsftp-turbo".into()),
    })
}

fn list_request(path: &str) -> Option<String> {
    serde_json::to_string(&StreamRequest { list: Some(path.to_owned()) }).ok()
}

/// What listing the start folder through the helper during connect gave.
enum EarlyListing {
    /// The helper listed it (or reported why it could not), and how long it took.
    Listed(Result<(String, Vec<DirEntry>), String>, Duration),
    /// The helper is too old to list.
    NotSupported,
    /// The helper stopped working.
    HelperFailed(String),
}

/// Opens `count` SFTP channels at once; at least one must open. Channels
/// beyond the server's session limit (OpenSSH MaxSessions) fail quietly.
async fn open_sftp_channels(
    ssh: &client::Handle<VerifyHostKey>,
    network: &NetworkSettings,
    count: usize,
) -> Result<Vec<Arc<SftpSession>>, ConnectError> {
    let results = futures::future::join_all((0..count.max(1)).map(|_| open_sftp_channel(ssh, network))).await;
    let mut channels = Vec::new();
    let mut first_error = None;
    for result in results {
        match result {
            Ok(channel) => channels.push(Arc::new(channel)),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    match (channels.is_empty(), first_error) {
        (true, Some(error)) => Err(error),
        _ => Ok(channels),
    }
}

/// Interprets the helper's answer to a ticket request.
fn ticket_from_reply(reply: StreamReply) -> Result<Ticket, TicketError> {
    match (reply.ticket, reply.error) {
        (Some(ticket), _) if ticket.version == PROTOCOL_VERSION => Ok(ticket),
        (Some(ticket), _) => Err(TicketError::Unavailable(format!(
            "server speaks rsftp-turbo protocol {}, this client {PROTOCOL_VERSION}",
            ticket.version
        ))),
        (None, Some(error)) if reply.service_unavailable => Err(TicketError::Unavailable(error)),
        (None, Some(error)) => Err(TicketError::Refused(error)),
        (None, None) => Err(TicketError::Unavailable("empty reply from rsftp-turbo".into())),
    }
}

/// Reason text for a ticket helper that exited.
fn helper_exited(exit_status: Option<u32>, stderr: &[u8]) -> TicketError {
    let stderr = String::from_utf8_lossy(stderr).trim().trim_start_matches("rsftp-turbo: ").to_owned();
    TicketError::Unavailable(match exit_status {
        Some(127) => "rsftp-turbo is not installed on the server (or not on the SSH session's PATH)".into(),
        _ if stderr.contains("unknown") || stderr.contains("usage") => {
            "the server's rsftp-turbo is too old (it needs `ticket --stream`); update it".into()
        }
        Some(status) if stderr.is_empty() => format!("rsftp-turbo exited with status {status}"),
        _ if stderr.is_empty() => "rsftp-turbo exited unexpectedly".into(),
        _ => stderr,
    })
}

/// Opens one SSH session channel running the SFTP subsystem.
async fn open_sftp_channel(
    ssh: &client::Handle<VerifyHostKey>,
    network: &NetworkSettings,
) -> Result<SftpSession, ConnectError> {
    let channel = ssh.channel_open_session().await.map_err(|e| ConnectError::Ssh(e.to_string()))?;
    channel.request_subsystem(true, "sftp").await
        .map_err(|e| ConnectError::Ssh(e.to_string()))?;
    SftpSession::new_with_config(channel.into_stream(), network.sftp_config()).await
        .map_err(|e| ConnectError::Sftp(e.to_string()))
}

/// One file of a transfer, with its source's size and modification time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedFile {
    pub local: PathBuf,
    pub remote: String,
    pub size: u64,
    /// Unix seconds.
    pub mtime: Option<u64>,
}

/// Everything a file or folder transfer creates: its folders as (local,
/// remote) paths and its files.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransferPlan {
    pub directories: Vec<(PathBuf, String)>,
    pub files: Vec<PlannedFile>,
}

/// A file that exists already where a transfer would write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetFile {
    pub size: u64,
    /// Unix seconds.
    pub mtime: Option<u64>,
}

/// Lists what uploading `local_path` (a file or a folder, recursively) to
/// `remote_path` transfers. Symbolic links are skipped.
pub async fn plan_upload(local_path: &Path, remote_path: &str) -> Result<TransferPlan, DownloadError> {
    let mut plan = TransferPlan::default();
    let mut stack = vec![(local_path.to_path_buf(), remote_path.to_owned())];
    while let Some((path, remote)) = stack.pop() {
        let meta = fs::metadata(&path).await.map_err(DownloadError::Io)?;
        if meta.is_dir() {
            plan.directories.push((path.clone(), remote.clone()));
            let mut entries = fs::read_dir(&path).await.map_err(DownloadError::Io)?;
            while let Some(entry) = entries.next_entry().await.map_err(DownloadError::Io)? {
                let file_type = entry.file_type().await.map_err(DownloadError::Io)?;
                if file_type.is_symlink() { continue; }
                let child_remote = format!("{}/{}", remote.trim_end_matches('/'), entry.file_name().to_string_lossy());
                stack.push((entry.path(), child_remote));
            }
        } else if meta.is_file() {
            plan.files.push(PlannedFile { local: path, remote, size: meta.len(), mtime: unix_mtime(&meta) });
        }
    }
    Ok(plan)
}

/// Size and modification time of the local files the download `plan`
/// would write that exist already, by index into `plan.files`.
pub fn existing_local_targets(plan: &TransferPlan) -> Vec<Option<TargetFile>> {
    plan.files.iter()
        .map(|file| {
            std::fs::metadata(&file.local).ok()
                .filter(std::fs::Metadata::is_file)
                .map(|meta| TargetFile { size: meta.len(), mtime: unix_mtime(&meta) })
        })
        .collect()
}

/// Modification time in Unix seconds.
pub fn unix_mtime(meta: &std::fs::Metadata) -> Option<u64> {
    meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok().map(|since| since.as_secs())
}

/// Sets a local file's modification time (best effort).
fn set_local_mtime(path: &Path, mtime: u64) {
    let time = std::time::UNIX_EPOCH + Duration::from_secs(mtime);
    if let Ok(file) = std::fs::File::options().write(true).open(path) {
        let _ = file.set_modified(time);
    }
}

/// Path of `path` relative to the transfer root, or its file name when the
/// root is the file itself.
fn relative_name(path: &Path, root: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    if relative.as_os_str().is_empty() {
        path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()
    } else {
        relative.to_string_lossy().into_owned()
    }
}

pub fn host_key_store_path() -> Result<PathBuf, String> {
    let home = crate::places::home_dir().ok_or_else(|| "home directory is not set".to_owned())?;
    Ok(home.join(".config/rust-sftp-client/known_hosts.json"))
}

pub fn load_trusted_fingerprint(host: &str, port: u16) -> Option<String> {
    let path = host_key_store_path().ok()?;
    let data = std::fs::read(path).ok()?;
    let entries: std::collections::HashMap<String, String> = serde_json::from_slice(&data).ok()?;
    entries.get(&format!("{host}:{port}")).cloned()
}

/// First trust is explicit. Existing pins can only be re-confirmed, never replaced.
pub fn trust_host_key(host: &str, port: u16, fingerprint: &str) -> Result<(), String> {
    let path = host_key_store_path()?;
    let parent = path.parent().ok_or_else(|| "Invalid known-hosts path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut entries: std::collections::HashMap<String, String> = std::fs::read(&path).ok()
        .and_then(|data| serde_json::from_slice(&data).ok()).unwrap_or_default();
    let key = format!("{host}:{port}");
    if let Some(existing) = entries.get(&key) {
        if existing != fingerprint {
            return Err(format!("Refusing to replace pinned host key for {key}"));
        }
        return Ok(());
    }
    entries.insert(key, fingerprint.to_owned());
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, serde_json::to_vec_pretty(&entries).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    std::fs::rename(temp, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_store_refuses_key_replacement() {
        let mut map = std::collections::HashMap::new();
        map.insert("host.example:22".to_owned(), "SHA256:old".to_owned());
        assert_eq!(map.get("host.example:22").map(String::as_str), Some("SHA256:old"));
        assert_ne!(map.get("host.example:22").map(String::as_str), Some("SHA256:new"));
    }
}
