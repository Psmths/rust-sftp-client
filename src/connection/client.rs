use std::{path::{Path, PathBuf}, sync::{atomic::{AtomicU64, AtomicUsize, Ordering}, Arc, Mutex}};
use russh::{client, keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate}};
use russh::keys::ssh_key::HashAlg;
use russh_sftp::client::{fs::ReadDir, SftpSession};
use tokio::{fs, io::{AsyncReadExt, AsyncWriteExt}, sync::{mpsc, Semaphore}, task::JoinSet};

use crate::{
    connection::{AuthMethod, ConnectionProfile, NetworkSettings},
    transfer::{download_file, DownloadError, DownloadProgress, DownloadResult, SegmentProgress, TransferSettings},
};

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
    _ssh: client::Handle<VerifyHostKey>,
    /// Primary channel, used for listings and file operations.
    sftp: Arc<SftpSession>,
    /// Every SFTP channel (the primary first); transfers are spread over them.
    channels: Vec<Arc<SftpSession>>,
    next_channel: AtomicUsize,
    network: NetworkSettings,
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
    ) -> Result<Self, ConnectError> {
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
            return Err(ConnectError::AuthenticationFailed);
        }

        let sftp = Arc::new(open_sftp_channel(&ssh, &network).await?);
        let mut channels = vec![Arc::clone(&sftp)];
        // Extra channels are an optimisation: stop quietly at the server's
        // session limit (OpenSSH MaxSessions defaults to 10).
        while channels.len() < network.channel_count() {
            match open_sftp_channel(&ssh, &network).await {
                Ok(extra) => channels.push(Arc::new(extra)),
                Err(_) => break,
            }
        }

        Ok(Self {
            _ssh: ssh,
            sftp,
            channels,
            next_channel: AtomicUsize::new(0),
            network,
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

    pub async fn list_dir(&self, path: &str) -> Result<ReadDir, ConnectError> {
        self.sftp.read_dir(path.to_owned()).await.map_err(|e| ConnectError::Sftp(e.to_string()))
    }

    pub async fn canonicalize(&self, path: &str) -> Result<String, ConnectError> {
        self.sftp.canonicalize(path.to_owned()).await.map_err(|e| ConnectError::Sftp(e.to_string()))
    }


    /// Recursively upload a local file or directory to a remote destination.
    /// Directory structure is preserved and progress is reported separately for each file.
    pub async fn upload_path(
        &self,
        local_path: &Path,
        remote_path: &str,
        progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
    ) -> Result<DownloadResult, crate::transfer::DownloadError> {
        let mut directories: Vec<(PathBuf, String)> = Vec::new();
        let mut files: Vec<(PathBuf, String, u64)> = Vec::new();
        let mut stack = vec![(local_path.to_path_buf(), remote_path.to_owned())];
        let mut total = 0_u64;

        while let Some((path, remote)) = stack.pop() {
            let meta = fs::metadata(&path).await
                .map_err(crate::transfer::DownloadError::Io)?;
            if meta.is_dir() {
                directories.push((path.clone(), remote.clone()));
                let mut entries = fs::read_dir(&path).await
                    .map_err(crate::transfer::DownloadError::Io)?;
                while let Some(entry) = entries.next_entry().await
                    .map_err(crate::transfer::DownloadError::Io)? {
                    let file_type = entry.file_type().await
                        .map_err(crate::transfer::DownloadError::Io)?;
                    if file_type.is_symlink() { continue; }
                    let child_remote = format!("{}/{}", remote.trim_end_matches('/'), entry.file_name().to_string_lossy());
                    stack.push((entry.path(), child_remote));
                }
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
                files.push((path, remote, meta.len()));
            }
        }

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
            for (local, _, file_size) in &files {
                let relative_path = local.strip_prefix(local_path).unwrap_or(local);
                let relative = if relative_path.as_os_str().is_empty() {
                    local.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()
                } else {
                    relative_path.to_string_lossy().to_string()
                };
                let _ = tx.send(DownloadProgress {
                    total_bytes: *file_size, transferred_bytes: 0,
                    completed_segments: 0, total_segments: 0, segment: None,
                    file_path: Some(relative), file_complete: false,
                });
            }
        }
        let transferred_total = Arc::new(AtomicU64::new(0));
        let parallel = Arc::new(Semaphore::new(self.network.file_parallelism()));
        let mut workers = JoinSet::new();
        for (local, remote, file_size) in files {
            let relative = relative_name(&local, local_path);
            let Some(sftp) = self.transfer_sessions().into_iter().next() else { break; };
            let parallel = Arc::clone(&parallel);
            let transferred_total = Arc::clone(&transferred_total);
            let progress = progress.clone();
            workers.spawn(async move {
                let _permit = parallel.acquire_owned().await.map_err(|e| DownloadError::Worker(e.to_string()))?;
                let mut buffer = vec![0_u8; UPLOAD_BUFFER];
                let mut file_transferred = 0_u64;
                let mut input = fs::File::open(&local).await.map_err(DownloadError::Io)?;
                let mut output = sftp.create(remote).await.map_err(|e| DownloadError::Sftp(e.to_string()))?;
                loop {
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
                            file_complete: false,
                        });
                    }
                }
                output.close().await.map_err(|e| DownloadError::Sftp(e.to_string()))?;
                if let Some(tx) = &progress {
                    let _ = tx.send(DownloadProgress {
                        total_bytes: file_size, transferred_bytes: file_transferred,
                        completed_segments: 0, total_segments: 0, segment: None,
                        file_path: Some(relative), file_complete: true,
                    });
                }
                Ok::<(), DownloadError>(())
            });
        }
        while let Some(joined) = workers.join_next().await {
            let result = joined.unwrap_or_else(|error| Err(DownloadError::Worker(error.to_string())));
            if let Err(error) = result {
                workers.abort_all();
                return Err(error);
            }
        }
        let transferred = transferred_total.load(Ordering::Relaxed);
        if let Some(tx) = &progress {
            let _ = tx.send(DownloadProgress {
                total_bytes: total, transferred_bytes: transferred,
                completed_segments: 0, total_segments: 0, segment: None,
                file_path: None, file_complete: false,
            });
        }
        Ok(DownloadResult { bytes: transferred, segments: 0, segmented: false })
    }

    /// Recursively download a remote file or directory. Each file uses the
    /// existing segmented downloader; progress is reported separately for each file.
    pub async fn download_path(
        &self,
        remote_path: &str,
        destination: &Path,
        settings: TransferSettings,
        progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
    ) -> Result<DownloadResult, crate::transfer::DownloadError> {
        let root_meta = self.sftp.metadata(remote_path.to_owned()).await
            .map_err(|e| crate::transfer::DownloadError::Sftp(e.to_string()))?;
        let mut directories: Vec<PathBuf> = Vec::new();
        let mut files: Vec<(String, PathBuf, u64)> = Vec::new();
        let mut stack = vec![(remote_path.to_owned(), destination.to_path_buf(), root_meta)];
        let mut total = 0_u64;

        while let Some((remote, local, metadata)) = stack.pop() {
            if metadata.is_dir() {
                directories.push(local.clone());
                let entries = self.sftp.read_dir(remote.clone()).await
                    .map_err(|e| crate::transfer::DownloadError::Sftp(e.to_string()))?;
                for entry in entries {
                    let name = entry.file_name();
                    if name == "." || name == ".." { continue; }
                    let attrs = entry.metadata();
                    let child_remote = format!("{}/{}", remote.trim_end_matches('/'), name);
                    stack.push((child_remote, local.join(&name), attrs));
                }
            } else {
                let file_size = metadata.size.unwrap_or(0);
                total = total.saturating_add(file_size);
                files.push((remote, local, file_size));
            }
        }

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
                    file_path: Some(relative), file_complete: false,
                });
            }
        }
        let parallel = Arc::new(Semaphore::new(self.network.file_parallelism()));
        let mut workers = JoinSet::new();
        for (remote, local, file_size) in files {
            let relative = relative_name(&local, destination);
            let sessions = self.transfer_sessions();
            let parallel = Arc::clone(&parallel);
            let progress = progress.clone();
            workers.spawn(async move {
                let _permit = parallel.acquire_owned().await.map_err(|e| DownloadError::Worker(e.to_string()))?;
                let (inner_tx, mut inner_rx) = mpsc::unbounded_channel();
                let download = download_file(sessions, &remote, &local, settings, Some(inner_tx));
                tokio::pin!(download);
                loop {
                    tokio::select! {
                        result = &mut download => {
                            let result = result?;
                            if let Some(tx) = &progress {
                                let _ = tx.send(DownloadProgress {
                                    total_bytes: result.bytes, transferred_bytes: result.bytes,
                                    completed_segments: result.segments, total_segments: result.segments,
                                    segment: None, file_path: Some(relative.clone()), file_complete: true,
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
                                    file_path: Some(relative.clone()), file_complete: false,
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
        while let Some(joined) = workers.join_next().await {
            match joined.unwrap_or_else(|error| Err(DownloadError::Worker(error.to_string()))) {
                Ok(result) => {
                    completed = completed.saturating_add(result.bytes);
                    segment_count = segment_count.saturating_add(result.segments);
                    segmented |= result.segmented;
                }
                Err(error) => {
                    workers.abort_all();
                    return Err(error);
                }
            }
        }
        if let Some(tx) = &progress {
            let _ = tx.send(DownloadProgress {
                total_bytes: total, transferred_bytes: completed,
                completed_segments: segment_count, total_segments: segment_count,
                segment: None, file_path: None, file_complete: false,
            });
        }
        Ok(DownloadResult { bytes: completed, segments: segment_count, segmented })
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
        &self,
        remote_path: &str,
        destination: &Path,
        settings: TransferSettings,
        progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
    ) -> Result<DownloadResult, crate::transfer::DownloadError> {
        download_file(self.transfer_sessions(), remote_path, destination, settings, progress).await
    }
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
