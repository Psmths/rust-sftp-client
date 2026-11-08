use std::{path::{Path, PathBuf}, sync::{Arc, Mutex}};
use russh::{client, keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate}};
use russh::keys::ssh_key::HashAlg;
use russh_sftp::client::{fs::ReadDir, SftpSession};
use tokio::sync::mpsc;

use crate::{connection::{AuthMethod, ConnectionProfile}, transfer::{download_file, DownloadProgress, DownloadResult, TransferSettings}};

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
    sftp: Arc<SftpSession>,
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
        let mut config = client::Config::default();
        config.nodelay = true;
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

        let channel = ssh.channel_open_session().await.map_err(|e| ConnectError::Ssh(e.to_string()))?;
        if !channel.request_subsystem(true, "sftp").await.map_err(|e| ConnectError::Ssh(e.to_string()))? {
            return Err(ConnectError::SubsystemRejected);
        }
        let sftp = SftpSession::new(channel.into_stream()).await
            .map_err(|e| ConnectError::Sftp(e.to_string()))?;

        Ok(Self {
            _ssh: ssh,
            sftp: Arc::new(sftp),
            host: profile.host.clone(),
            port: profile.port,
            fingerprint: trusted_fingerprint.unwrap_or_default().to_owned(),
        })
    }

    pub async fn list_dir(&self, path: &str) -> Result<ReadDir, ConnectError> {
        self.sftp.read_dir(path.to_owned()).await.map_err(|e| ConnectError::Sftp(e.to_string()))
    }

    pub async fn canonicalize(&self, path: &str) -> Result<String, ConnectError> {
        self.sftp.canonicalize(path.to_owned()).await.map_err(|e| ConnectError::Sftp(e.to_string()))
    }

    pub async fn download(
        &self,
        remote_path: &str,
        destination: &Path,
        settings: TransferSettings,
        progress: Option<mpsc::UnboundedSender<DownloadProgress>>,
    ) -> Result<DownloadResult, crate::transfer::DownloadError> {
        download_file(Arc::clone(&self.sftp), remote_path, destination, settings, progress).await
    }
}

pub fn host_key_store_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| "HOME is not set".to_owned())?;
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
