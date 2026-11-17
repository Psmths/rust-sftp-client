use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read as _,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc as std_mpsc, Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use eframe::egui;

use crate::conflict::ConflictAction;
use crate::connection::{
    load_trusted_fingerprint, trust_host_key, AlgorithmKind, AuthMethod, ConnectionProfile, NetworkSettings, SshAlgorithms, TurboState,
};
use crate::logging::{default_log_dir, Logger};
use crate::session::{select_click, sort_rows, ConnectOutcome, LocalEntry, QueueTab, RemoteEntry, Session, SortColumn, SortOrder, SpeedSample};
use crate::settings::AppSettings;
use crate::transfer::TransferSettings;
use crate::places::{self, Drive};
use crate::terminal::{Terminal, TerminalColors, TerminalSettings, TERMINAL_TYPES};
use crate::win32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    const ALL: [HashAlgorithm; 3] = [HashAlgorithm::Md5, HashAlgorithm::Sha1, HashAlgorithm::Sha256];

    fn label(self) -> &'static str {
        match self {
            HashAlgorithm::Md5 => "MD5",
            HashAlgorithm::Sha1 => "SHA1",
            HashAlgorithm::Sha256 => "SHA256",
        }
    }
}

enum Hasher {
    Md5(md5::Context),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
}

impl Hasher {
    fn new(algorithm: HashAlgorithm) -> Self {
        use sha2::Digest as _;
        match algorithm {
            HashAlgorithm::Md5 => Hasher::Md5(md5::Context::new()),
            HashAlgorithm::Sha1 => Hasher::Sha1(sha1::Sha1::new()),
            HashAlgorithm::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        match self {
            Hasher::Md5(context) => context.consume(data),
            Hasher::Sha1(hasher) => hasher.update(data),
            Hasher::Sha256(hasher) => hasher.update(data),
        }
    }

    fn finish(self) -> String {
        use sha2::Digest as _;
        let bytes: Vec<u8> = match self {
            Hasher::Md5(context) => context.finalize().0.to_vec(),
            Hasher::Sha1(hasher) => hasher.finalize().to_vec(),
            Hasher::Sha256(hasher) => hasher.finalize().to_vec(),
        };
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

const HASH_BUFFER: usize = 1024 * 1024;

/// A running or finished checksum calculation, shown in its own window.
struct HashJob {
    id: u64,
    algorithm: HashAlgorithm,
    name: String,
    location: String,
    total: u64,
    done: Arc<AtomicU64>,
    cancel: Arc<AtomicBool>,
    rx: std_mpsc::Receiver<Result<String, String>>,
    result: Option<Result<String, String>>,
}

/// Items a delete / rename dialog acts on.
#[derive(Clone)]
enum FileTarget {
    Local(Vec<LocalEntry>),
    Remote(Vec<RemoteEntry>),
}

impl FileTarget {
    /// (name, is_dir) of every item.
    fn items(&self) -> Vec<(&str, bool)> {
        match self {
            FileTarget::Local(entries) => entries.iter().map(|e| (e.name.as_str(), e.dir)).collect(),
            FileTarget::Remote(entries) => entries.iter().map(|e| (e.name.as_str(), e.dir)).collect(),
        }
    }

    fn is_remote(&self) -> bool {
        matches!(self, FileTarget::Remote(_))
    }
}

/// Result of a background delete / rename.
struct OpResult {
    session: u64,
    msgid: &'static str,
    remote: bool,
    result: Result<String, String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RowAction {
    Open,
    Transfer,
    Hash(HashAlgorithm),
    Rename,
    Delete,
    NewFolder,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsPage {
    Appearance,
    Transfers,
    Segmentation,
    Network,
    Algorithms,
    Terminal,
    Logging,
}

impl SettingsPage {
    const ALL: [SettingsPage; 7] = [
        SettingsPage::Appearance,
        SettingsPage::Transfers,
        SettingsPage::Segmentation,
        SettingsPage::Network,
        SettingsPage::Algorithms,
        SettingsPage::Terminal,
        SettingsPage::Logging,
    ];

    fn title(self) -> &'static str {
        match self {
            SettingsPage::Appearance => "Appearance",
            SettingsPage::Transfers => "Transfers",
            SettingsPage::Segmentation => "Segmented downloads",
            SettingsPage::Network => "Network Settings",
            SettingsPage::Algorithms => "SSH Algorithms",
            SettingsPage::Terminal => "SSH Terminal",
            SettingsPage::Logging => "Logging",
        }
    }
}

/// Contents of the settings window, validated on OK/Apply.
#[derive(Default)]
struct SettingsDraft {
    threshold_mib: String,
    segment_mib: String,
    workers: String,
    sftp_channels: String,
    pipelined_requests: String,
    sftp_packet_kib: String,
    ssh_window_mib: String,
    algorithms: SshAlgorithms,
    /// List shown on the SSH Algorithms page and its selected row.
    algorithm_kind: AlgorithmKind,
    algorithm_row: Option<usize>,
    compression: bool,
    keepalive_secs: String,
    request_timeout_secs: String,
    parallel_files: String,
    turbo: bool,
    logging_enabled: bool,
    log_connections: bool,
    log_transfers: bool,
    log_directory: String,
    split_sessions: bool,
    theme: win32::Theme,
    units: crate::units::SizeUnits,
    terminal_font_size: String,
    terminal_colors: TerminalColors,
    terminal_type: String,
    terminal_scrollback: String,
    terminal_wheel_lines: String,
    terminal_copy_on_select: bool,
    terminal_ctrl_c_copies: bool,
}

impl SettingsDraft {
    fn from_settings(settings: &AppSettings) -> Self {
        let transfer = &settings.transfer;
        let network = &settings.network;
        let logging = &settings.logging;
        Self {
            threshold_mib: (transfer.segmentation_threshold_bytes / MIB).to_string(),
            segment_mib: (transfer.target_segment_size_bytes / MIB).to_string(),
            workers: transfer.max_segments_per_file.to_string(),
            sftp_channels: network.sftp_channels.to_string(),
            pipelined_requests: network.pipelined_requests.to_string(),
            sftp_packet_kib: network.sftp_packet_kib.to_string(),
            ssh_window_mib: network.ssh_window_mib.to_string(),
            algorithms: network.algorithms(),
            algorithm_kind: AlgorithmKind::default(),
            algorithm_row: None,
            compression: network.compression,
            keepalive_secs: network.keepalive_secs.to_string(),
            request_timeout_secs: network.request_timeout_secs.to_string(),
            parallel_files: network.parallel_files.to_string(),
            turbo: network.turbo,
            logging_enabled: logging.enabled,
            log_connections: logging.log_connections,
            log_transfers: logging.log_transfers,
            log_directory: logging.directory.display().to_string(),
            split_sessions: logging.split_sessions,
            theme: settings.theme,
            units: settings.units,
            terminal_font_size: format!("{}", settings.terminal.font_size),
            terminal_colors: settings.terminal.colors,
            terminal_type: settings.terminal.terminal_type.clone(),
            terminal_scrollback: settings.terminal.scrollback_lines.to_string(),
            terminal_wheel_lines: settings.terminal.wheel_lines.to_string(),
            terminal_copy_on_select: settings.terminal.copy_on_select,
            terminal_ctrl_c_copies: settings.terminal.ctrl_c_copies,
        }
    }

    fn parse(&self) -> Result<AppSettings, String> {
        let transfer = TransferSettings {
            segmentation_threshold_bytes: parse_setting(&self.threshold_mib, "Segmentation threshold", 1, 1024 * 1024)? * MIB,
            target_segment_size_bytes: parse_setting(&self.segment_mib, "Segment size", 1, 4096)? * MIB,
            max_segments_per_file: parse_setting(&self.workers, "Workers per file", 1, 32)? as u32,
        };
        let network = NetworkSettings {
            sftp_channels: parse_setting(&self.sftp_channels, "SFTP channels", 1, 16)? as u32,
            pipelined_requests: parse_setting(&self.pipelined_requests, "Requests in flight", 1, 256)? as u32,
            sftp_packet_kib: parse_setting(&self.sftp_packet_kib, "SFTP packet size", 32, 256)? as u32,
            ssh_window_mib: parse_setting(&self.ssh_window_mib, "SSH window size", 1, 1024)? as u32,
            algorithms: Some(self.algorithms.clone()),
            compression: self.compression,
            keepalive_secs: parse_setting(&self.keepalive_secs, "Keepalive interval", 0, 3600)? as u32,
            request_timeout_secs: parse_setting(&self.request_timeout_secs, "Request timeout", 5, 3600)? as u32,
            parallel_files: parse_setting(&self.parallel_files, "Files transferred at once", 1, 32)? as u32,
            turbo: self.turbo,
            // The legacy cipher choice is superseded by `algorithms`.
            ..NetworkSettings::default()
        };
        if let Some(kind) = self.algorithms.empty_kind() {
            return Err(format!("Turn on at least one algorithm under SSH Algorithms → {}.", kind.label()));
        }
        let directory = self.log_directory.trim();
        if self.logging_enabled && directory.is_empty() {
            return Err("Choose a log directory.".into());
        }
        let logging = crate::logging::LoggingSettings {
            enabled: self.logging_enabled,
            log_connections: self.log_connections,
            log_transfers: self.log_transfers,
            directory: if directory.is_empty() { default_log_dir() } else { PathBuf::from(directory) },
            split_sessions: self.split_sessions,
        };
        let font_size = self.terminal_font_size.trim().parse::<f32>().ok()
            .filter(|size| (6.0..=32.0).contains(size))
            .ok_or_else(|| "Terminal font size must be a number from 6 to 32.".to_owned())?;
        let terminal_type = self.terminal_type.trim();
        if terminal_type.is_empty() || !terminal_type.chars().all(|c| c.is_ascii_graphic()) {
            return Err("Terminal type must be a name such as xterm-256color.".into());
        }
        let terminal = TerminalSettings {
            font_size,
            colors: self.terminal_colors,
            terminal_type: terminal_type.to_owned(),
            scrollback_lines: parse_setting(&self.terminal_scrollback, "Scrollback", 0, 100_000)? as u32,
            wheel_lines: parse_setting(&self.terminal_wheel_lines, "Mouse wheel lines", 1, 20)? as u32,
            copy_on_select: self.terminal_copy_on_select,
            ctrl_c_copies: self.terminal_ctrl_c_copies,
        };
        // Settings not edited in this window are carried over when applying.
        Ok(AppSettings {
            transfer,
            network,
            logging,
            terminal,
            theme: self.theme,
            units: self.units,
            hide_hidden_items: false,
            last_local_dir: None,
        })
    }
}

const MIB: u64 = 1024 * 1024;

const SAVE_PASSWORD_TIP: &str = "Stores the password in your system's credential store (Windows Credential \
Manager, or the Secret Service keyring such as GNOME Keyring or KWallet on Linux), never in the profiles \
file.\n\nThe password is saved after it has logged in successfully, or when you save the profile with a \
password entered. It is shared by all profiles for the same user, host and port. Unticking the box and \
saving the profile removes it.";

const NETWORK_TIP_CHANNELS: &str = "Number of SFTP channels opened inside each SSH connection. Download \
segments and the files of folder transfers are spread across them, and every channel has its own flow-control \
window, so more channels keep more data moving at once.\n\nServers limit how many channels a connection may open \
(OpenSSH: MaxSessions, 10 by default); channels beyond the limit are skipped without an error.\n\nDefault: 4.";

const TRANSFER_TIP_PARALLEL_FILES: &str = "How many files are transferred at the same time on one \
connection: the files of folder uploads and downloads and individually queued files share this limit. \
Further files wait in the queue.\n\nRaising this speeds up many small files, where opening and closing \
each file (several network round trips) costs more than moving the data. Large single files are not \
affected; they are sped up by segmented downloads instead.\n\nDefault: 4.";

const NETWORK_TIP_PIPELINE: &str = "Number of SFTP read or write requests sent ahead for each open file \
without waiting for the server's replies.\n\nEvery request waits a full network round trip, so on high-latency \
links more requests in flight means higher throughput, at the cost of some memory per transfer.\n\nDefault: 64.";

const NETWORK_TIP_PACKET: &str = "Largest amount of file data carried by a single SFTP read or write request. \
Bigger packets mean fewer requests and less protocol overhead.\n\nServers that announce their own limit (OpenSSH \
does) are respected automatically. Lower this to 32 KiB if uploads fail on a server that does not.\n\nDefault: 256 KiB.";

const NETWORK_TIP_WINDOW: &str = "How much data the server may send on a channel before it has to wait for \
this client to acknowledge it.\n\nA channel can never be faster than window size ÷ round-trip time: 16 MiB at \
100 ms latency allows about 160 MiB/s, 2 MiB only about 20 MiB/s. Raise it for fast, long-distance links.\n\nDefault: 16 MiB.";

const NETWORK_TIP_KEEPALIVE: &str = "Sends an SSH keepalive message after this many seconds without traffic. \
This stops routers, NAT gateways and firewalls from dropping idle connections, and detects connections that \
have silently died.\n\n0 turns keepalives off. Default: 30 s.";

const NETWORK_TIP_TIMEOUT: &str = "How long to wait for the server to answer a single SFTP request before \
treating it as failed. A failed download segment is retried; other operations report an error.\n\nRaise this \
for slow or heavily loaded servers. Default: 30 s.";

const ALGORITHMS_HELP_KEX: &str = "How the client and server agree on session keys. mlkem768x25519 adds \
post-quantum protection; curve25519 is the common choice. SHA-1 methods are only for very old servers.";

const ALGORITHMS_HELP_CIPHERS: &str = "Encrypts the connection. AES-GCM is fastest on CPUs with AES \
instructions (practically all x86-64 and ARM CPUs); ChaCha20-Poly1305 on CPUs without them. CBC modes are \
only for very old servers.";

const ALGORITHMS_HELP_MACS: &str = "Protects the data against tampering when a CTR or CBC cipher is used. \
AES-GCM and ChaCha20-Poly1305 have this built in and ignore this list.";

const ALGORITHMS_HELP_HOST_KEYS: &str = "Key types accepted to identify the server. If a change makes the \
server show a different key than the one you trusted, connecting reports a changed host key.";

const NETWORK_TIP_TURBO: &str = "Downloads files over rsftp-turbo, a UDP transfer protocol, when the server \
has its helper installed (rsftp-turbo service on UDP port 6767). Browsing, uploads and logins keep using \
SSH/SFTP.\n\nThe transfer is authorised over your SSH session, so you can only download files your account \
can read. Every UDP packet is encrypted and authenticated with AES-256-GCM, lost packets are re-requested, \
and every segment is checked against a SHA-256 digest computed on the server; a bad segment is downloaded \
again.\n\nIf the server has no helper, or UDP is blocked, downloads use SFTP automatically.\n\nDefault: on.";

const NETWORK_TIP_COMPRESSION: &str = "Compresses all SSH traffic with zlib.\n\nThis only helps on slow links \
(a few MB/s or less) when moving compressible data such as text, logs or source code. On fast links, or with \
files that are already compressed (archives, video, images), it costs CPU time and makes transfers \
slower.\n\nDefault: off.";

fn parse_setting(value: &str, label: &str, min: u64, max: u64) -> Result<u64, String> {
    match value.trim().parse::<u64>() {
        Ok(number) if (min..=max).contains(&number) => Ok(number),
        _ => Err(format!("{label} must be a whole number from {min} to {max}.")),
    }
}

#[derive(Clone)]
enum Dialog {
    Profiles,
    Password,
    TrustHostKey,
    Error,
    ConfirmDelete,
    Rename,
    NewFolder,
}

#[derive(Clone, Debug)]
enum DragPayload {
    /// Every item being dragged: the whole selection if the dragged item is in it.
    Local(Vec<PathBuf>),
    Remote(Vec<String>),
}

pub struct SftpApp {
    runtime: tokio::runtime::Runtime,
    logger: Arc<Logger>,
    settings: AppSettings,
    /// One tab per connection; there is always at least one.
    sessions: Vec<Session>,
    active: usize,
    next_session_id: u64,
    drives: Vec<Drive>,
    saved_profiles: Vec<ConnectionProfile>,
    selected_profile: Option<usize>,
    host: String,
    port: String,
    username: String,
    profile_name: String,
    key_path: String,
    /// Profile setting: remote folder opened after connecting.
    remote_folder: String,
    auth: AuthMethod,
    password: String,
    /// "Save password" checkbox of the profile editor / password prompt.
    save_password: bool,
    /// Background lookup of a saved password before connecting.
    password_lookup: Option<std_mpsc::Receiver<Result<Option<String>, String>>>,
    /// Results of background credential-store writes (status text or error).
    credential_tx: std_mpsc::Sender<Result<String, String>>,
    credential_rx: std_mpsc::Receiver<Result<String, String>>,
    dialog: Option<Dialog>,
    /// Session the host-key dialog belongs to.
    dialog_session: Option<u64>,
    error_message: String,
    settings_open: bool,
    settings_page: SettingsPage,
    settings_draft: SettingsDraft,
    settings_error: String,
    hash_jobs: Vec<HashJob>,
    next_hash_id: u64,
    file_target: Option<FileTarget>,
    /// Session that `file_target` belongs to.
    file_target_session: u64,
    /// Text of the Rename / New folder dialogs.
    rename_value: String,
    rename_error: String,
    rename_focus: bool,
    /// The New folder dialog creates on the server (else locally).
    new_folder_remote: bool,
    op_tx: std_mpsc::Sender<OpResult>,
    op_rx: std_mpsc::Receiver<OpResult>,
    ops_pending: usize,
    /// Minutes shown by the statistics graph.
    stats_span_minutes: u32,
}

impl SftpApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let settings = crate::settings::load();
        win32::apply(&cc.egui_ctx, settings.theme);
        crate::units::set(settings.units);
        // Open where the user left off; the home folder the first time (or if it is gone).
        let path = settings
            .last_local_dir
            .clone()
            .filter(|path| path.is_dir())
            .or_else(crate::places::home_dir)
            .unwrap_or_else(|| PathBuf::from(if cfg!(windows) { "C:\\" } else { "/" }));
        let logger = Arc::new(Logger::new(settings.logging.clone()));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime initialization failed");
        let first_session = Session::new(1, runtime.handle().clone(), logger.clone(), path, settings.network.file_parallelism());
        let (op_tx, op_rx) = std_mpsc::channel();
        let (credential_tx, credential_rx) = std_mpsc::channel();
        Self {
            runtime,
            logger,
            settings,
            sessions: vec![first_session],
            active: 0,
            next_session_id: 1,
            drives: places::list(),
            saved_profiles: load_profiles(),
            selected_profile: None,
            host: String::new(),
            port: "22".into(),
            username: String::new(),
            profile_name: "New site".into(),
            key_path: String::new(),
            remote_folder: String::new(),
            auth: AuthMethod::Password,
            password: String::new(),
            save_password: false,
            password_lookup: None,
            credential_tx,
            credential_rx,
            dialog: None,
            dialog_session: None,
            error_message: String::new(),
            settings_open: false,
            settings_page: SettingsPage::Transfers,
            settings_draft: SettingsDraft::default(),
            settings_error: String::new(),
            hash_jobs: Vec::new(),
            next_hash_id: 0,
            file_target: None,
            file_target_session: 0,
            rename_value: String::new(),
            rename_error: String::new(),
            rename_focus: false,
            new_folder_remote: false,
            op_tx,
            op_rx,
            ops_pending: 0,
            stats_span_minutes: 5,
        }
    }

    fn session(&self) -> &Session {
        &self.sessions[self.active]
    }

    fn session_mut(&mut self) -> &mut Session {
        &mut self.sessions[self.active]
    }

    fn session_index(&self, id: u64) -> Option<usize> {
        self.sessions.iter().position(|session| session.id == id)
    }

    fn add_session(&mut self, path: PathBuf) -> usize {
        self.next_session_id += 1;
        let session = Session::new(
            self.next_session_id,
            self.runtime.handle().clone(),
            self.logger.clone(),
            path,
            self.settings.network.file_parallelism(),
        );
        self.sessions.push(session);
        self.sessions.len() - 1
    }

    /// Disconnects and closes the session at `index` (cancelling its
    /// transfers) and switches to the next connected tab.
    fn close_session(&mut self, index: usize) {
        if index >= self.sessions.len() { return; }
        let mut session = self.sessions.remove(index);
        session.disconnect();
        self.logger.forget(session.id);
        if self.dialog_session == Some(session.id) {
            self.dialog = None;
            self.dialog_session = None;
        }
        if self.sessions.is_empty() {
            self.active = self.add_session(session.path.clone());
            self.session_mut().status = session.status;
            return;
        }
        let count = self.sessions.len();
        // `index` now points at the tab that was to the right of the closed one.
        self.active = (0..count)
            .map(|offset| (index + offset) % count)
            .find(|&candidate| self.sessions[candidate].is_connected())
            .unwrap_or_else(|| index.min(count - 1));
    }

    fn disconnect_active(&mut self) {
        self.close_session(self.active);
    }

    /// Discards a tab that was opened for a connection that never succeeded.
    fn discard_unconnected(&mut self, id: u64) {
        let Some(index) = self.session_index(id) else { return; };
        let session = &self.sessions[index];
        if session.created_for_connect && !session.is_connected() && !session.is_connecting() && self.sessions.len() > 1 {
            self.close_session(index);
        }
    }

    fn can_close_active(&self) -> bool {
        let session = self.session();
        session.is_connected() || session.is_connecting() || self.sessions.len() > 1
    }

    fn profile_value(&self) -> Result<ConnectionProfile, String> {
        let port = self.port.parse::<u16>().map_err(|_| "Port must be between 1 and 65535".to_owned())?;
        let profile = ConnectionProfile {
            name: self.profile_name.trim().into(),
            host: self.host.trim().into(),
            port,
            username: self.username.trim().into(),
            auth_method: self.auth,
            private_key_path: (self.auth == AuthMethod::PrivateKey).then(|| self.key_path.trim().into()),
            save_password: self.auth == AuthMethod::Password && self.save_password,
            default_remote_path: Some(self.remote_folder.trim().to_owned()).filter(|path| !path.is_empty()),
        };
        profile.validate().map_err(|e| e.to_string())?;
        if profile.auth_method == AuthMethod::SshAgent {
            return Err("SSH-agent authentication is not supported yet. Choose password or private key.".into());
        }
        Ok(profile)
    }

    fn save_profile(&mut self) {
        let profile = match self.profile_value() {
            Ok(profile) => profile,
            Err(error) => return self.show_error(error),
        };
        let duplicate = self.saved_profiles.iter().enumerate()
            .any(|(index, existing)| existing.name == profile.name && Some(index) != self.selected_profile);
        if duplicate {
            return self.show_error(format!("A profile named \"{}\" already exists.", profile.name));
        }
        let previous = match self.selected_profile.filter(|&index| index < self.saved_profiles.len()) {
            Some(index) => Some(std::mem::replace(&mut self.saved_profiles[index], profile.clone())),
            None => {
                self.saved_profiles.push(profile.clone());
                self.selected_profile = Some(self.saved_profiles.len() - 1);
                None
            }
        };
        if let Err(error) = persist_profiles(&self.saved_profiles) {
            return self.show_error(format!("Could not save profile: {error}"));
        }
        self.session_mut().status = format!("Saved connection profile: {}", profile.name);
        // Forget a password saved under the old login if it is no longer wanted there.
        if let Some(previous) = previous.filter(|previous| previous.save_password) {
            if !profile.save_password || crate::credentials::key(&previous) != crate::credentials::key(&profile) {
                self.forget_password(&previous);
            }
        }
        if profile.save_password && !self.password.is_empty() {
            self.remember_password(&profile, self.password.clone());
        }
    }

    /// Saves `password` for the profile's login in the background.
    fn remember_password(&self, profile: &ConnectionProfile, password: String) {
        let key = crate::credentials::key(profile);
        let tx = self.credential_tx.clone();
        std::thread::spawn(move || {
            let result = crate::credentials::store(&key, &password)
                .map(|()| format!("Password for {key} saved in the system credential store"))
                .map_err(|error| format!("Could not save the password for {key}: {error}"));
            let _ = tx.send(result);
        });
    }

    /// Removes the profile's saved password unless another saved profile for
    /// the same login still wants it.
    fn forget_password(&self, profile: &ConnectionProfile) {
        let key = crate::credentials::key(profile);
        let still_used = self.saved_profiles.iter()
            .any(|other| other.save_password && crate::credentials::key(other) == key);
        if still_used { return; }
        let tx = self.credential_tx.clone();
        std::thread::spawn(move || {
            let result = crate::credentials::delete(&key)
                .map(|()| format!("Saved password for {key} removed"))
                .map_err(|error| format!("Could not remove the saved password for {key}: {error}"));
            let _ = tx.send(result);
        });
    }

    /// Looks up the saved password before connecting; `poll_password_lookup`
    /// connects or asks for the password when it arrives.
    fn start_password_lookup(&mut self, profile: &ConnectionProfile) {
        let key = crate::credentials::key(profile);
        let (tx, rx) = std_mpsc::channel();
        self.password_lookup = Some(rx);
        self.session_mut().status = format!("Reading saved password for {key} …");
        std::thread::spawn(move || {
            let _ = tx.send(crate::credentials::load(&key));
        });
    }

    fn poll_password_lookup(&mut self) {
        let Some(result) = self.password_lookup.as_ref().and_then(|rx| rx.try_recv().ok()) else { return; };
        self.password_lookup = None;
        match result {
            Ok(Some(password)) => self.begin_connect(Some(password)),
            Ok(None) => {
                self.session_mut().status = "No saved password found".into();
                self.dialog = Some(Dialog::Password);
            }
            Err(error) => {
                self.session_mut().status = format!("Could not read the saved password: {error}");
                self.dialog = Some(Dialog::Password);
            }
        }
    }

    fn poll_credentials(&mut self) {
        while let Ok(result) = self.credential_rx.try_recv() {
            match result {
                Ok(message) => self.session_mut().status = message,
                Err(error) => self.show_error(error),
            }
        }
    }

    /// After a successful password login: save the password if requested and
    /// remember the choice in the matching saved profile.
    fn on_password_login(&mut self, profile: &ConnectionProfile, password: String) {
        if !profile.save_password { return; }
        self.remember_password(profile, password);
        let mut changed = false;
        for saved in self.saved_profiles.iter_mut() {
            if saved.name == profile.name && !saved.save_password && crate::credentials::key(saved) == crate::credentials::key(profile) {
                saved.save_password = true;
                changed = true;
            }
        }
        if changed {
            if let Err(error) = persist_profiles(&self.saved_profiles) {
                self.show_error(format!("Could not save profile: {error}"));
            }
        }
    }

    /// Clears the profile editor for a new, unsaved profile.
    fn new_profile(&mut self) {
        self.selected_profile = None;
        self.profile_name = "New profile".into();
        self.host.clear();
        self.port = "22".into();
        self.username.clear();
        self.auth = AuthMethod::Password;
        self.key_path.clear();
        self.remote_folder.clear();
        self.password.clear();
        self.save_password = false;
    }

    fn delete_profile(&mut self) {
        let Some(index) = self.selected_profile.filter(|&index| index < self.saved_profiles.len()) else { return; };
        let removed = self.saved_profiles.remove(index);
        if let Err(error) = persist_profiles(&self.saved_profiles) {
            self.show_error(format!("Could not save profiles: {error}"));
            return;
        }
        if removed.save_password {
            self.forget_password(&removed);
        }
        self.session_mut().status = format!("Deleted connection profile: {}", removed.name);
        if self.saved_profiles.is_empty() {
            self.new_profile();
        } else {
            self.apply_profile(index.min(self.saved_profiles.len() - 1));
        }
    }

    fn upload_selected(&mut self) {
        for path in self.session().uploadable_selection() {
            self.session_mut().queue_upload(path);
        }
    }

    fn download_selected(&mut self) {
        let settings = self.settings.transfer;
        self.session_mut().download_selected(settings);
    }

    fn push_hash_job(
        &mut self,
        name: String,
        location: String,
        total: u64,
        algorithm: HashAlgorithm,
    ) -> (Arc<AtomicU64>, Arc<AtomicBool>, std_mpsc::Sender<Result<String, String>>) {
        let (tx, rx) = std_mpsc::channel();
        let done = Arc::new(AtomicU64::new(0));
        let cancel = Arc::new(AtomicBool::new(false));
        self.next_hash_id += 1;
        self.hash_jobs.push(HashJob {
            id: self.next_hash_id,
            algorithm,
            name,
            location,
            total,
            done: done.clone(),
            cancel: cancel.clone(),
            rx,
            result: None,
        });
        (done, cancel, tx)
    }

    fn start_local_hash(&mut self, entry: &LocalEntry, algorithm: HashAlgorithm) {
        let (done, cancel, tx) = self.push_hash_job(entry.name.clone(), entry.path.display().to_string(), entry.size, algorithm);
        let path = entry.path.clone();
        std::thread::spawn(move || {
            let result = (|| -> Result<String, String> {
                let mut file = fs::File::open(&path).map_err(|e| e.to_string())?;
                let mut hasher = Hasher::new(algorithm);
                let mut buffer = vec![0_u8; HASH_BUFFER];
                loop {
                    if cancel.load(Ordering::Relaxed) { return Err("Cancelled".into()); }
                    let read = file.read(&mut buffer).map_err(|e| e.to_string())?;
                    if read == 0 { break; }
                    hasher.update(&buffer[..read]);
                    done.fetch_add(read as u64, Ordering::Relaxed);
                }
                Ok(hasher.finish())
            })();
            let _ = tx.send(result);
        });
    }

    fn begin_delete(&mut self, target: FileTarget) {
        if target.items().is_empty() { return; }
        self.file_target = Some(target);
        self.file_target_session = self.session().id;
        self.dialog = Some(Dialog::ConfirmDelete);
    }

    /// Opens the New folder dialog for the local (or remote) pane.
    fn begin_new_folder(&mut self, remote: bool) {
        if remote && !self.session().is_connected() { return; }
        self.rename_value = "New folder".into();
        self.rename_error.clear();
        self.rename_focus = true;
        self.new_folder_remote = remote;
        self.file_target_session = self.session().id;
        self.dialog = Some(Dialog::NewFolder);
    }

    /// Creates the folder named in the dialog in the pane's current folder;
    /// false keeps the dialog open (with an error).
    fn perform_new_folder(&mut self) -> bool {
        let Some(index) = self.session_index(self.file_target_session) else { return true; };
        let name = self.rename_value.trim().to_owned();
        if !valid_file_name(&name, !self.new_folder_remote) {
            self.rename_error = "That is not a valid folder name.".into();
            return false;
        }
        if self.new_folder_remote {
            let session = &self.sessions[index];
            if session.remote_entries.iter().any(|entry| entry.name == name) {
                self.rename_error = format!("\"{name}\" already exists.");
                return false;
            }
            let Some(connection) = session.connection.clone() else { return true; };
            let path = join_remote(&session.remote_path, &name);
            let (tx, session_id) = (self.op_tx.clone(), session.id);
            self.ops_pending += 1;
            self.runtime.spawn(async move {
                let result = connection.create_dir(&path).await
                    .map(|()| format!("Created remote folder {path}"))
                    .map_err(|error| format!("Could not create remote folder {path}: {error}"));
                let _ = tx.send(OpResult { session: session_id, msgid: "MKDIR", remote: true, result });
            });
        } else {
            let session = &mut self.sessions[index];
            let path = session.path.join(&name);
            if path.symlink_metadata().is_ok() {
                self.rename_error = format!("\"{name}\" already exists.");
                return false;
            }
            if let Err(error) = fs::create_dir(&path) {
                session.log_file_operation("MKDIR", &Err(format!("Could not create folder {}: {error}", path.display())));
                self.rename_error = format!("Could not create the folder: {error}");
                return false;
            }
            session.log_file_operation("MKDIR", &Ok(format!("Created folder {}", path.display())));
            session.status = format!("Created folder {name}");
            session.local_selected = vec![path.clone()];
            session.local_anchor = Some(path);
            session.refresh_local();
        }
        true
    }

    fn begin_rename(&mut self, target: FileTarget) {
        let Some((name, _)) = target.items().first().copied() else { return; };
        self.rename_value = name.to_owned();
        self.rename_error.clear();
        self.rename_focus = true;
        self.file_target = Some(target);
        self.file_target_session = self.session().id;
        self.dialog = Some(Dialog::Rename);
    }

    fn perform_delete(&mut self) {
        let Some(target) = self.file_target.take() else { return; };
        let Some(index) = self.session_index(self.file_target_session) else { return; };
        let session_id = self.file_target_session;
        let tx = self.op_tx.clone();
        let names: Vec<String> = match &target {
            FileTarget::Local(entries) => entries.iter().map(|entry| entry.path.display().to_string()).collect(),
            FileTarget::Remote(entries) => entries.iter().map(|entry| format!("remote {}", entry.path)).collect(),
        };
        self.sessions[index].log_file_operation("DELETE", &Ok(format!("Deleting {}", names.join(", "))));
        match target {
            FileTarget::Local(entries) => {
                self.sessions[index].local_selected.clear();
                std::thread::spawn(move || {
                    let result = entries.iter().try_for_each(|entry| {
                        // DirEntry metadata does not follow symlinks, so a link
                        // to a directory is removed as a file, not recursed into.
                        let removed = if entry.dir { fs::remove_dir_all(&entry.path) } else { fs::remove_file(&entry.path) };
                        removed.map_err(|error| format!("Could not delete {}: {error}", entry.path.display()))
                    });
                    let names: Vec<String> = entries.iter().map(|entry| entry.path.display().to_string()).collect();
                    let result = result.map(|()| format!("Deleted {}", names.join(", ")));
                    let _ = tx.send(OpResult { session: session_id, msgid: "DELETE", remote: false, result });
                });
            }
            FileTarget::Remote(entries) => {
                let Some(connection) = self.sessions[index].connection.clone() else { return; };
                self.sessions[index].remote_selected.clear();
                self.runtime.spawn(async move {
                    let names: Vec<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
                    let mut result = Ok(format!("Deleted remote {}", names.join(", ")));
                    for entry in &entries {
                        if let Err(error) = connection.remove_path(&entry.path).await {
                            result = Err(format!("Could not delete remote {}: {error}", entry.path));
                            break;
                        }
                    }
                    let _ = tx.send(OpResult { session: session_id, msgid: "DELETE", remote: true, result });
                });
            }
        }
        self.ops_pending += 1;
        self.sessions[index].status = "Deleting…".into();
    }

    /// Validates the rename dialog and starts the rename. Returns true when
    /// the dialog can close.
    fn perform_rename(&mut self) -> bool {
        let Some(target) = self.file_target.clone() else { return true; };
        let Some(index) = self.session_index(self.file_target_session) else { return true; };
        let new_name = self.rename_value.trim().to_owned();
        if !valid_file_name(&new_name, !target.is_remote()) {
            self.rename_error = "That is not a valid file name.".into();
            return false;
        }
        match target {
            FileTarget::Local(entries) => {
                let Some(entry) = entries.first() else { return true; };
                if entry.name == new_name { return true; }
                let destination = entry.path.with_file_name(&new_name);
                if destination.symlink_metadata().is_ok() {
                    self.rename_error = format!("\"{new_name}\" already exists.");
                    return false;
                }
                if let Err(error) = fs::rename(&entry.path, &destination) {
                    self.sessions[index].log_file_operation("RENAME", &Err(format!(
                        "Could not rename {} to {}: {error}", entry.path.display(), destination.display()
                    )));
                    self.rename_error = format!("Could not rename: {error}");
                    return false;
                }
                let session = &mut self.sessions[index];
                let message = format!("Renamed {} to {}", entry.path.display(), destination.display());
                session.log_file_operation("RENAME", &Ok(message));
                session.status = format!("Renamed {} to {new_name}", entry.name);
                session.local_selected = vec![destination];
                session.refresh_local();
            }
            FileTarget::Remote(entries) => {
                let Some(entry) = entries.first().cloned() else { return true; };
                if entry.name == new_name { return true; }
                let session = &self.sessions[index];
                // Search results may sit in a subfolder: rename within their own folder.
                // (The server refuses to rename onto an existing name there.)
                if entry.folder.is_empty() && session.remote_entries.iter().any(|existing| existing.name == new_name) {
                    self.rename_error = format!("\"{new_name}\" already exists.");
                    return false;
                }
                let Some(connection) = session.connection.clone() else { return true; };
                let destination = join_remote(&remote_parent(&entry.path), &new_name);
                let tx = self.op_tx.clone();
                let session_id = session.id;
                self.ops_pending += 1;
                self.runtime.spawn(async move {
                    let result = connection.rename(&entry.path, &destination).await
                        .map(|()| format!("Renamed remote {} to {destination}", entry.path))
                        .map_err(|error| format!("Could not rename remote {}: {error}", entry.path));
                    let _ = tx.send(OpResult { session: session_id, msgid: "RENAME", remote: true, result });
                });
            }
        }
        self.file_target = None;
        true
    }

    fn poll_ops(&mut self) {
        while let Ok(op) = self.op_rx.try_recv() {
            self.ops_pending = self.ops_pending.saturating_sub(1);
            let Some(index) = self.session_index(op.session) else { continue; };
            let session = &mut self.sessions[index];
            session.log_file_operation(op.msgid, &op.result);
            if op.remote { session.reload_remote(); } else { session.refresh_local(); }
            match op.result {
                Ok(message) => session.status = message,
                Err(error) => self.show_error(error),
            }
        }
    }

    fn poll_sessions(&mut self) {
        let mut failed = Vec::new();
        for index in 0..self.sessions.len() {
            let id = self.sessions[index].id;
            match self.sessions[index].poll_connection() {
                Some(ConnectOutcome::Connected { password }) => {
                    self.password.clear();
                    if let (Some(password), Some(profile)) = (password, self.sessions[index].profile.clone()) {
                        self.on_password_login(&profile, password);
                    }
                }
                Some(ConnectOutcome::HostKeyRequired) => {
                    self.active = index;
                    self.dialog_session = Some(id);
                    self.dialog = Some(Dialog::TrustHostKey);
                }
                Some(ConnectOutcome::Failed(error)) => {
                    self.show_error(error);
                    failed.push(id);
                }
                None => {}
            }
            if let Some(error) = self.sessions[index].poll_remote_listing() {
                self.show_error(error);
            }
            self.sessions[index].poll_queue();
        }
        for id in failed {
            self.discard_unconnected(id);
        }
        if let Some(error) = self.logger.take_error() {
            self.session_mut().status = error;
        }
    }

    /// "Target files already exist" dialog for the first session that has
    /// transfers waiting for that decision: a side-by-side listing of the
    /// files, coloured by what the selected action does with each.
    fn conflict_window(&mut self, ctx: &egui::Context) {
        let Some(index) = self.sessions.iter().position(|session| session.conflict_prompt.is_some()) else { return; };
        let title = self.sessions[index].title();
        let other_session = index != self.active;
        let id = egui::ViewportId::from_hash_of("rust-sftp-client-conflicts");
        let builder = egui::ViewportBuilder::default()
            .with_title("Target files already exist")
            .with_inner_size([860.0, 540.0])
            .with_min_inner_size([620.0, 380.0]);
        let mut decision: Option<bool> = None;
        let Some(prompt) = self.sessions[index].conflict_prompt.as_mut() else { return; };
        let conflicts = prompt.conflicts();
        ctx.show_viewport_immediate(id, builder, |window_ctx, _| {
            egui::CentralPanel::default().show(window_ctx, |ui| {
                let total: usize = prompt.jobs.iter().map(|job| job.targets.len()).sum();
                let heading = format!("{} of {total} file(s) already exist at the destination.", conflicts.len());
                ui.strong(heading);
                if other_session {
                    ui.weak(format!("Session: {title}"));
                }
                ui.add_space(4.0);
                ui.horizontal_top(|ui| {
                    ui.vertical(|ui| {
                        ui.label("What should happen to them?");
                        for action in ConflictAction::ALL {
                            ui.radio_value(&mut prompt.action, action, action.label());
                        }
                    });
                });
                let action = prompt.action;
                let overwritten = conflicts.iter()
                    .filter(|&&(job, file)| {
                        let prepared = &prompt.jobs[job];
                        let plan = prepared.plan.as_ref().expect("conflicts come from a plan");
                        prepared.targets[file].is_some_and(|target| action.overwrites(&plan.files[file], &target))
                    })
                    .count();
                let colors = ConflictColors::new(ui.visuals().dark_mode);
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.colored_label(colors.replaced_text, format!("■ {overwritten} overwritten"));
                    ui.label("·");
                    ui.colored_label(win32::gray_text(), format!("■ {} kept", conflicts.len() - overwritten));
                    ui.label("·");
                    ui.colored_label(colors.new_text, format!("■ {} new file(s) transferred", prompt.new_files()));
                    ui.label("·");
                    ui.colored_label(win32::warn_amber(), "values that differ");
                });
                ui.add_space(4.0);

                let footer = 64.0;
                let list_height = (ui.available_height() - footer).max(120.0);
                win32::list_view(ui, list_height, |ui| {
                    let header_height = 19.0;
                    let row_height = 18.0;
                    let direction_width = 22.0;
                    let size_width = 90.0;
                    let time_width = 140.0;
                    let result_width = 100.0;
                    let fixed = direction_width + 2.0 * (size_width + time_width) + result_width;
                    let name_width = (ui.available_width() - fixed - ui.spacing().scroll.bar_width).max(160.0);
                    ui.horizontal(|ui| {
                        win32::header_cell(ui, direction_width, header_height, "");
                        win32::header_cell(ui, name_width, header_height, "Name");
                        win32::header_cell(ui, size_width, header_height, "Local size");
                        win32::header_cell(ui, time_width, header_height, "Local modified");
                        win32::header_cell(ui, size_width, header_height, "Remote size");
                        win32::header_cell(ui, time_width, header_height, "Remote modified");
                        win32::header_cell(ui, result_width, header_height, "Result");
                        let rest = ui.available_width();
                        if rest > 0.0 { win32::header_cell(ui, rest, header_height, ""); }
                    });
                    let area = egui::ScrollArea::vertical().id_salt("conflict_list").auto_shrink([false, false]);
                    win32::scroll_rows(ui, area, row_height, conflicts.len(), |ui, range| {
                        for &(job, file) in &conflicts[range] {
                            let prepared = &prompt.jobs[job];
                            let plan = prepared.plan.as_ref().expect("conflicts come from a plan");
                            let source = &plan.files[file];
                            let Some(target) = prepared.targets[file] else { continue; };
                            let overwrite = action.overwrites(source, &target);
                            let download = prepared.download();
                            // Local and remote side: (size, mtime) of each.
                            let source_side = (source.size, source.mtime);
                            let target_side = (target.size, target.mtime);
                            let (local, remote) = if download { (target_side, source_side) } else { (source_side, target_side) };
                            let size_differs = crate::conflict::sizes_differ(source, &target);
                            let time_differs = crate::conflict::times_differ(source.mtime, target.mtime);
                            let (row_rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), row_height), egui::Sense::hover());
                            let row = egui::UiBuilder::new().max_rect(row_rect).layout(egui::Layout::left_to_right(egui::Align::Center));
                            ui.scope_builder(row, |ui| {
                                ui.spacing_mut().item_spacing.x = 0.0;
                                // Like a diff: the side being replaced in red, the side replacing it in green.
                                let (local_fill, remote_fill) = match (overwrite, download) {
                                    (false, _) => (None, None),
                                    (true, true) => (Some(colors.replaced), Some(colors.new)),
                                    (true, false) => (Some(colors.new), Some(colors.replaced)),
                                };
                                let text = if overwrite { win32::text_color() } else { win32::gray_text() };
                                let differs = |differ: bool| if differ { win32::warn_amber() } else { text };
                                conflict_cell(ui, direction_width, row_height, if download { "↓" } else { "↑" }, None, text, false);
                                conflict_cell(ui, name_width, row_height, &conflict_name(prepared, &source.local), None, text, false);
                                let sides = [(local, local_fill), (remote, remote_fill)];
                                for ((size, mtime), fill) in sides {
                                    conflict_cell(ui, size_width, row_height, &size_text(size), fill, differs(size_differs), true);
                                    conflict_cell(ui, time_width, row_height, &mtime_text(mtime), fill, differs(time_differs), false);
                                }
                                let (result, color) = if overwrite {
                                    (if download { "Overwrite local" } else { "Overwrite remote" }, colors.replaced_text)
                                } else {
                                    ("Keep", win32::gray_text())
                                };
                                conflict_cell(ui, result_width, row_height, result, None, color, false);
                            });
                        }
                    });
                });
                ui.add_space(6.0);
                ui.checkbox(&mut prompt.remember, "Apply this decision to all further conflicts in this session");
                dialog_buttons(ui, |ui| {
                    if win32::button_sized(ui, true, "Cancel", 75.0).clicked() { decision = Some(false); }
                    if win32::button_sized(ui, true, "OK", 75.0).clicked() { decision = Some(true); }
                });
            });
            if window_ctx.input(|input| input.viewport().close_requested()) {
                decision = Some(false);
            }
        });
        let session = &mut self.sessions[index];
        match decision {
            Some(true) => {
                let (action, remember) = session.conflict_prompt.as_ref().map(|prompt| (prompt.action, prompt.remember)).unwrap_or_default();
                session.resolve_conflicts(action, remember);
            }
            Some(false) => session.cancel_conflicts(),
            None => {}
        }
    }

    fn hash_windows(&mut self, ctx: &egui::Context) {
        let mut closed = Vec::new();
        for job in &mut self.hash_jobs {
            if job.result.is_none() {
                if let Ok(result) = job.rx.try_recv() { job.result = Some(result); }
            }
            let id = egui::ViewportId::from_hash_of(("rust-sftp-client-hash", job.id));
            let builder = egui::ViewportBuilder::default()
                .with_title(format!("{} - {}", job.algorithm.label(), job.name))
                .with_inner_size([500.0, 190.0])
                .with_resizable(false);
            let mut close = false;
            ctx.show_viewport_immediate(id, builder, |window_ctx, _| {
                egui::CentralPanel::default().show(window_ctx, |ui| {
                    egui::Grid::new("hash_fields").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                        ui.label("File:");
                        win32::field(ui, &job.location);
                        ui.end_row();
                        ui.label("Algorithm:");
                        ui.label(job.algorithm.label());
                        ui.end_row();
                        ui.label(if job.result.is_some() { "Result:" } else { "Progress:" });
                        match &job.result {
                            None => {
                                let done = job.done.load(Ordering::Relaxed);
                                let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 18.0), egui::Sense::hover());
                                let painter = ui.painter();
                                painter.rect_filled(rect, 0.0, win32::window());
                                win32::thin_sunken(painter, rect);
                                let total = job.total.max(1);
                                let piece = Piece { start: 0, end: total, done: done.min(total), failed: false };
                                paint_piece_bar(painter, rect.shrink(1.0), total, &[piece], PIECE_FILL);
                            }
                            Some(Ok(hash)) => {
                                let mut text = hash.as_str();
                                win32::text_edit(ui, egui::TextEdit::singleline(&mut text)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY));
                            }
                            Some(Err(error)) => { ui.colored_label(win32::error_red(), error); }
                        }
                        ui.end_row();
                    });
                    if job.result.is_none() {
                        let done = job.done.load(Ordering::Relaxed);
                        ui.weak(format!("{} of {}", size_text(done), size_text(job.total)));
                    }
                    dialog_buttons(ui, |ui| {
                        match &job.result {
                            None => {
                                if win32::button_sized(ui, true, "Cancel", 75.0).clicked() { close = true; }
                            }
                            Some(result) => {
                                if win32::button_sized(ui, true, "Close", 75.0).clicked() { close = true; }
                                if let Ok(hash) = result {
                                    if win32::button_sized(ui, true, "Copy", 75.0).clicked() { ui.ctx().copy_text(hash.clone()); }
                                }
                            }
                        }
                    });
                });
                if window_ctx.input(|input| input.viewport().close_requested()) { close = true; }
            });
            if close {
                job.cancel.store(true, Ordering::Relaxed);
                closed.push(job.id);
            }
        }
        self.hash_jobs.retain(|job| !closed.contains(&job.id));
    }

    fn open_settings(&mut self) {
        self.settings_draft = SettingsDraft::from_settings(&self.settings);
        self.settings_error.clear();
        self.settings_open = true;
    }

    /// Connects with the profile in the editor fields, asking for (or looking
    /// up) the password as needed. Used by the Connect button and the quick
    /// connect menu.
    fn connect_with_form(&mut self) {
        match self.profile_value() {
            Ok(profile) => {
                if profile.auth_method == AuthMethod::Password {
                    if !self.password.is_empty() {
                        // Typed in the profile editor: use it (and save it once it works).
                        self.dialog = None;
                        self.begin_connect(Some(self.password.clone()));
                    } else if profile.save_password {
                        self.dialog = None;
                        self.start_password_lookup(&profile);
                    } else {
                        self.dialog = Some(Dialog::Password);
                    }
                } else {
                    self.dialog = None;
                    self.begin_connect(None);
                }
            }
            Err(error) => self.show_error(error),
        }
    }

    /// Connects to a saved profile straight away (the toolbar's quick connect menu).
    fn quick_connect(&mut self, index: usize) {
        self.apply_profile(index);
        self.connect_with_form();
    }

    fn apply_profile(&mut self, index: usize) {
        if let Some(profile) = self.saved_profiles.get(index) {
            self.profile_name = profile.name.clone();
            self.host = profile.host.clone();
            self.port = profile.port.to_string();
            self.username = profile.username.clone();
            self.auth = profile.auth_method;
            self.key_path = profile.private_key_path.clone().unwrap_or_default();
            self.save_password = profile.save_password;
            self.remote_folder = profile.default_remote_path.clone().unwrap_or_default();
            self.password.clear();
            self.selected_profile = Some(index);
        }
    }

    fn show_error(&mut self, message: String) {
        self.error_message = message;
        self.dialog = Some(Dialog::Error);
    }

    /// Connects using the profile editor's values: in the current tab if it is
    /// idle, otherwise in a new tab.
    fn begin_connect(&mut self, password: Option<String>) {
        let profile = match self.profile_value() {
            Ok(profile) => profile,
            Err(error) => return self.show_error(error),
        };
        let current = self.session();
        let index = if !current.is_connected() && !current.is_connecting() {
            self.active
        } else {
            let path = current.path.clone();
            let index = self.add_session(path);
            self.sessions[index].created_for_connect = true;
            index
        };
        self.active = index;
        let trusted = load_trusted_fingerprint(&profile.host, profile.port);
        let network = self.settings.network.clone();
        self.sessions[index].start_connect(profile, password, trusted, network);
    }

    fn accept_host_key(&mut self) {
        let Some(index) = self.dialog_session.and_then(|id| self.session_index(id)) else {
            return self.show_error("Missing host-key trust context".into());
        };
        self.dialog_session = None;
        let session = &mut self.sessions[index];
        let (Some(profile), Some(fingerprint)) = (session.profile.clone(), session.pending_fingerprint.take()) else {
            return self.show_error("Missing host-key trust context".into());
        };
        if let Err(error) = trust_host_key(&profile.host, profile.port, &fingerprint) {
            return self.show_error(format!("Could not save host-key trust: {error}"));
        }
        session.log_host_key_decision(&fingerprint, true);
        let password = session.pending_password.clone();
        session.start_connect(profile, password, Some(fingerprint), self.settings.network.clone());
    }

    fn reject_host_key(&mut self) {
        let Some(id) = self.dialog_session.take() else { return; };
        let Some(index) = self.session_index(id) else { return; };
        let session = &mut self.sessions[index];
        if let Some(fingerprint) = session.pending_fingerprint.take() {
            session.log_host_key_decision(&fingerprint, false);
        }
        session.pending_password = None;
        session.status = "Host key rejected".into();
        self.discard_unconnected(id);
    }

    fn local_pane(&mut self, ui: &mut egui::Ui) {
        let a = self.active;
        let (_, dropped) = ui.dnd_drop_zone::<DragPayload, _>(egui::Frame::default(), |ui| {
            self.local_pane_contents(ui);
        });
        if let Some(payload) = dropped {
            if let DragPayload::Remote(paths) = payload.as_ref() {
                for path in paths {
                    self.sessions[a].queue_download(path.clone(), self.settings.transfer);
                }
            }
        }
    }

    fn local_pane_contents(&mut self, ui: &mut egui::Ui) {
        let a = self.active;
        let connected = self.sessions[a].connection.is_some();
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            if win32::icon_button(ui, self.sessions[a].path.parent().is_some(), win32::Icon::Up, "Up one level").clicked() {
                if let Some(parent) = self.sessions[a].path.parent().map(PathBuf::from) { self.sessions[a].open_local_dir(parent); }
            }
            if win32::icon_button(ui, true, win32::Icon::Refresh, "Refresh").clicked() {
                self.drives = places::list();
                self.sessions[a].refresh_local();
            }
            if win32::icon_button(ui, true, win32::Icon::NewFolder, "New folder").clicked() {
                self.begin_new_folder(false);
            }
            ui.add_space(6.0);
            ui.label("Filter:");
            win32::text_edit(ui, egui::TextEdit::singleline(&mut self.sessions[a].local_filter).desired_width(ui.available_width() - RECURSIVE_WIDTH));
            ui.checkbox(&mut self.sessions[a].local_recursive, "Recursive").on_hover_text(RECURSIVE_TIP);
        });
        ui.horizontal(|ui| {
            ui.label("Address:");
            let current = places::containing(&self.drives, &self.sessions[a].path);
            let current_text = current.map(|index| self.drives[index].path.display().to_string()).unwrap_or_default();
            let mut chosen = None;
            egui::ComboBox::from_id_salt("local_drive")
                .width(if cfg!(windows) { 60.0 } else { 130.0 })
                .selected_text(current_text)
                .show_ui(ui, |ui| {
                    for (index, drive) in self.drives.iter().enumerate() {
                        if ui.add(egui::Button::selectable(current == Some(index), drive.label.as_str()).wrap_mode(egui::TextWrapMode::Extend)).clicked() {
                            chosen = Some(drive.path.clone());
                        }
                    }
                })
                .response
                .on_hover_text("Drive");
            if let Some(path) = chosen { self.sessions[a].open_local_dir(path); }
            win32::field(ui, &self.sessions[a].path.display().to_string());
        });
        ui.add_space(2.0);

        let filter = self.sessions[a].local_filter.trim().to_lowercase();
        let searching = self.sessions[a].searching_local();
        let show_hidden = self.sessions[a].show_hidden;
        let mut rows: Vec<LocalEntry> = if searching {
            self.sessions[a].local_search.as_ref().map(|search| search.results.clone()).unwrap_or_default()
        } else {
            self.sessions[a].local_entries.iter()
                .filter(|entry| (show_hidden || !entry.hidden) && entry.name.to_lowercase().contains(&filter))
                .cloned().collect()
        };
        sort_rows(&mut rows, self.sessions[a].local_sort);
        let footer = list_footer(rows.len(), self.sessions[a].uploadable_selection().len(), searching,
            self.sessions[a].local_search.as_ref().map(|search| (search.done, search.truncated)));
        // Rows the context menu can act on (".." excluded).
        let listed = rows.clone();
        if let (Some(parent), false) = (self.sessions[a].path.parent(), searching) {
            rows.insert(0, LocalEntry {
                name: "..".into(), path: parent.to_path_buf(), dir: true,
                size: 0, modified: "—".into(), hidden: false, folder: String::new(),
            });
        }
        let mut open_dir = None;
        // Row order for Shift-click ranges (".." is never part of a range).
        let order: Vec<PathBuf> = rows.iter().filter(|entry| entry.name != "..").map(|entry| entry.path.clone()).collect();
        let list_height = (ui.available_height() - FOOTER_HEIGHT).max(60.0);
        let mut sort_click = None;
        let mut background_new_folder = false;
        win32::list_view(ui, list_height, |ui| {
            let (name_width, header) = reserve_list_header(ui);
            win32::scroll(ui, file_list_scroll(("local_list", self.sessions[a].id)), |ui| {
                for entry in rows {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        let selected = self.sessions[a].local_selected.contains(&entry.path);
                        let response = file_row(ui, name_width, &entry.label(), entry.dir, entry.size, &entry.modified, selected);
                        // Dragging a selected item drags the whole selection; dragging
                        // any other item selects just it first, as Explorer does.
                        if response.dragged() && entry.name != ".." {
                            let session = &mut self.sessions[a];
                            if response.drag_started() && !selected {
                                session.local_selected = vec![entry.path.clone()];
                                session.local_anchor = Some(entry.path.clone());
                            }
                            let paths = if session.local_selected.contains(&entry.path) {
                                order.iter().filter(|path| session.local_selected.contains(path)).cloned().collect()
                            } else {
                                vec![entry.path.clone()]
                            };
                            response.dnd_set_drag_payload(DragPayload::Local(paths));
                        }
                        if response.clicked() {
                            let (ctrl, shift) = click_modifiers(&response);
                            let session = &mut self.sessions[a];
                            if entry.name == ".." {
                                session.local_selected = vec![entry.path.clone()];
                                session.local_anchor = None;
                            } else {
                                select_click(&mut session.local_selected, &mut session.local_anchor, &order, &entry.path, ctrl, shift);
                            }
                        }
                        if response.secondary_clicked() && !selected {
                            self.sessions[a].local_selected = vec![entry.path.clone()];
                            self.sessions[a].local_anchor = Some(entry.path.clone());
                        }
                        let in_selection = self.sessions[a].local_selected.contains(&entry.path);
                        let count = if in_selection { self.sessions[a].uploadable_selection().len().max(1) } else { 1 };
                        let mut action = None;
                        if entry.name != ".." {
                            response.context_menu(|ui| {
                                let label = match (connected, count > 1) {
                                    (true, true) => format!("Upload {count} items to remote"),
                                    (true, false) => "Upload to remote".to_owned(),
                                    (false, _) => "Upload to remote (not connected)".to_owned(),
                                };
                                action = row_context_menu(ui, entry.dir, &label, connected, count == 1, count == 1);
                            });
                        }
                        let targets = || -> Vec<LocalEntry> {
                            if in_selection {
                                let selected = &self.sessions[a].local_selected;
                                listed.iter().filter(|e| selected.contains(&e.path)).cloned().collect()
                            } else {
                                vec![entry.clone()]
                            }
                        };
                        match action {
                            Some(RowAction::Open) => open_dir = Some(entry.path.clone()),
                            Some(RowAction::Transfer) => {
                                for target in targets() { self.sessions[a].queue_upload(target.path); }
                            }
                            Some(RowAction::Hash(algorithm)) => self.start_local_hash(&entry, algorithm),
                            Some(RowAction::NewFolder) => self.begin_new_folder(false),
                            Some(RowAction::Rename) => self.begin_rename(FileTarget::Local(vec![entry.clone()])),
                            Some(RowAction::Delete) => {
                                let targets = targets();
                                self.begin_delete(FileTarget::Local(targets));
                            }
                            None => {}
                        }
                        if response.double_clicked() && entry.dir { open_dir = Some(entry.path.clone()); }
                    });
                }
                let session = &mut self.sessions[a];
                background_new_folder = list_background(ui, &mut || {
                    session.local_selected.clear();
                    session.local_anchor = None;
                });
            });
            sort_click = paint_list_header(ui, header, name_width, self.sessions[a].local_sort);
        });
        if background_new_folder { self.begin_new_folder(false); }
        if let Some(column) = sort_click { self.sessions[a].local_sort.toggle(column); }
        if let Some(path) = open_dir {
            // Opening a folder found by a search shows that folder, not more results.
            if searching { self.sessions[a].local_filter.clear(); }
            self.sessions[a].open_local_dir(path);
        }
        ui.label(footer);
    }

    fn remote_pane(&mut self, ui: &mut egui::Ui) {
        let a = self.active;
        let (_, dropped) = ui.dnd_drop_zone::<DragPayload, _>(egui::Frame::default(), |ui| {
            self.remote_pane_contents(ui);
        });
        if let Some(payload) = dropped {
            if let DragPayload::Local(paths) = payload.as_ref() {
                for path in paths {
                    self.sessions[a].queue_upload(path.clone());
                }
            }
        }
    }

    fn remote_pane_contents(&mut self, ui: &mut egui::Ui) {
        let a = self.active;
        let connected = self.sessions[a].connection.is_some();
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            if win32::icon_button(ui, connected, win32::Icon::Up, "Up one level").clicked() {
                let parent = remote_parent(&self.sessions[a].remote_path);
                self.sessions[a].navigate_remote(parent);
            }
            if win32::icon_button(ui, connected, win32::Icon::Refresh, "Refresh").clicked() {
                let path = self.sessions[a].remote_path.clone();
                self.sessions[a].load_remote(&path);
            }
            if win32::icon_button(ui, connected, win32::Icon::NewFolder, "New folder").clicked() {
                self.begin_new_folder(true);
            }
            ui.add_space(6.0);
            ui.label("Filter:");
            win32::text_edit(ui, egui::TextEdit::singleline(&mut self.sessions[a].remote_filter).desired_width(ui.available_width() - RECURSIVE_WIDTH));
            ui.add_enabled(connected, egui::Checkbox::new(&mut self.sessions[a].remote_recursive, "Recursive")).on_hover_text(RECURSIVE_TIP);
        });
        ui.horizontal(|ui| {
            ui.label("Address:");
            win32::field(ui, if connected { self.sessions[a].remote_path.as_str() } else { "" });
        });
        ui.add_space(2.0);

        let filter = self.sessions[a].remote_filter.trim().to_lowercase();
        let searching = self.sessions[a].searching_remote();
        let show_hidden = self.sessions[a].show_hidden;
        let mut rows: Vec<RemoteEntry> = if searching {
            self.sessions[a].remote_search.as_ref().map(|search| search.results.clone()).unwrap_or_default()
        } else {
            self.sessions[a].remote_entries.iter()
                .filter(|entry| (show_hidden || !entry.hidden()) && entry.name.to_lowercase().contains(&filter))
                .cloned().collect()
        };
        sort_rows(&mut rows, self.sessions[a].remote_sort);
        let footer = list_footer(rows.len(), self.sessions[a].remote_selected.len(), searching,
            self.sessions[a].remote_search.as_ref().map(|search| (search.done, search.truncated)));
        let listed = rows.clone();
        let remote_path_trimmed = self.sessions[a].remote_path.trim_end_matches('/');
        if !searching && !remote_path_trimmed.is_empty() && remote_path_trimmed != "/" {
            rows.insert(0, RemoteEntry {
                name: "..".into(), path: remote_parent(&self.sessions[a].remote_path), dir: true,
                size: 0, modified: "—".into(), folder: String::new(),
            });
        }
        let mut open_dir = None;
        let order: Vec<String> = rows.iter().filter(|entry| entry.name != "..").map(|entry| entry.path.clone()).collect();
        let mut open_profiles = false;
        let mut sort_click = None;
        let mut background_new_folder = false;
        let list_height = (ui.available_height() - FOOTER_HEIGHT).max(60.0);
        win32::list_view(ui, list_height, |ui| {
            let (name_width, header) = reserve_list_header(ui);
            if !connected {
                ui.vertical_centered(|ui| {
                    ui.add_space(60.0);
                    ui.label("Not connected to a server.");
                    ui.weak("Connect to an SSH server to browse remote files.");
                    ui.add_space(8.0);
                    if win32::button_sized(ui, true, "Connect…", 75.0).clicked() { open_profiles = true; }
                });
                paint_list_header(ui, header, name_width, self.sessions[a].remote_sort);
                return;
            }
            win32::scroll(ui, file_list_scroll(("remote_list", self.sessions[a].id)), |ui| {
                for entry in rows {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        let selected = self.sessions[a].remote_selected.contains(&entry.path);
                        let response = file_row(ui, name_width, &entry.label(), entry.dir, entry.size, &entry.modified, selected);
                        if response.dragged() && entry.name != ".." {
                            let session = &mut self.sessions[a];
                            if response.drag_started() && !selected {
                                session.remote_selected = vec![entry.path.clone()];
                                session.remote_anchor = Some(entry.path.clone());
                            }
                            let paths = if session.remote_selected.contains(&entry.path) {
                                order.iter().filter(|path| session.remote_selected.contains(path)).cloned().collect()
                            } else {
                                vec![entry.path.clone()]
                            };
                            response.dnd_set_drag_payload(DragPayload::Remote(paths));
                        }
                        if response.clicked() {
                            let (ctrl, shift) = click_modifiers(&response);
                            let session = &mut self.sessions[a];
                            if entry.name == ".." {
                                session.remote_selected = vec![entry.path.clone()];
                                session.remote_anchor = None;
                            } else {
                                select_click(&mut session.remote_selected, &mut session.remote_anchor, &order, &entry.path, ctrl, shift);
                            }
                        }
                        if response.secondary_clicked() && !selected {
                            self.sessions[a].remote_selected = vec![entry.path.clone()];
                            self.sessions[a].remote_anchor = Some(entry.path.clone());
                        }
                        let in_selection = self.sessions[a].remote_selected.contains(&entry.path);
                        let count = if in_selection { self.sessions[a].remote_selected.len() } else { 1 };
                        let mut action = None;
                        if entry.name != ".." {
                            response.context_menu(|ui| {
                                let label = if count > 1 { format!("Download {count} items") } else { "Download".to_owned() };
                                // Hashing is local-only: a remote hash would have to download the file.
                                action = row_context_menu(ui, entry.dir, &label, true, count == 1, false);
                            });
                        }
                        let targets = || -> Vec<RemoteEntry> {
                            if in_selection {
                                listed.iter().filter(|e| self.sessions[a].remote_selected.contains(&e.path)).cloned().collect()
                            } else {
                                vec![entry.clone()]
                            }
                        };
                        match action {
                            Some(RowAction::Open) => open_dir = Some(entry.path.clone()),
                            Some(RowAction::Transfer) => {
                                for target in targets() { self.sessions[a].queue_download(target.path, self.settings.transfer); }
                            }
                            Some(RowAction::Rename) => self.begin_rename(FileTarget::Remote(vec![entry.clone()])),
                            Some(RowAction::Delete) => {
                                let targets = targets();
                                self.begin_delete(FileTarget::Remote(targets));
                            }
                            Some(RowAction::NewFolder) => self.begin_new_folder(true),
                            Some(RowAction::Hash(_)) | None => {}
                        }
                        if response.double_clicked() && entry.dir { open_dir = Some(entry.path.clone()); }
                    });
                }
                let session = &mut self.sessions[a];
                background_new_folder = list_background(ui, &mut || {
                    session.remote_selected.clear();
                    session.remote_anchor = None;
                });
            });
            sort_click = paint_list_header(ui, header, name_width, self.sessions[a].remote_sort);
        });
        if background_new_folder { self.begin_new_folder(true); }
        if let Some(column) = sort_click { self.sessions[a].remote_sort.toggle(column); }
        if let Some(path) = open_dir {
            if searching { self.sessions[a].remote_filter.clear(); }
            self.sessions[a].navigate_remote(path);
        }
        if open_profiles { self.dialog = Some(Dialog::Profiles); }
        ui.label(footer);
    }

    /// Transfer rows of one queue tab (pending, complete or failed).
    fn transfer_list_tab(&mut self, ui: &mut egui::Ui, tab: QueueTab) {
        let a = self.active;
        let list_height = ui.available_height().max(40.0);
        win32::list_view(ui, list_height, |ui| {
            let file_width = 220.0;
            let protocol_width = 70.0;
            let percent_width = 80.0;
            let speed_width = 95.0;
            let elapsed_width = 90.0;
            let remaining_width = 105.0;
            let header_height = 19.0;
            let row_height = 18.0;
            let fixed = file_width + protocol_width + percent_width + speed_width + elapsed_width + remaining_width;
            let progress_width = (ui.available_width() - fixed - ui.spacing().scroll.bar_width).max(160.0);
            ui.horizontal(|ui| {
                win32::header_cell(ui, file_width, header_height, "File");
                win32::header_cell(ui, protocol_width, header_height, "Protocol");
                win32::header_cell(ui, progress_width, header_height, "Progress");
                win32::header_cell(ui, percent_width, header_height, "Complete");
                win32::header_cell(ui, speed_width, header_height, "Speed");
                win32::header_cell(ui, elapsed_width, header_height, "Elapsed");
                win32::header_cell(ui, remaining_width, header_height, "Remaining");
                let rest = ui.available_width();
                if rest > 0.0 { win32::header_cell(ui, rest, header_height, ""); }
            });
            // Rows of this tab in display order, with their depth: transfers,
            // each expanded folder followed by its files. Only the rows in
            // view are drawn.
            let visible = queue_rows(&self.sessions[a].transfers, tab);
            let area = egui::ScrollArea::vertical().id_salt(("queue_list", self.sessions[a].id)).auto_shrink([false, false]);
            let mut toggle = None;
            let mut clear = false;
            let mut select = None;
            let mut stop = None;
            // Some(Some(id)): retry that row; Some(None): retry every failed row.
            let mut retry = None;
            win32::scroll_rows(ui, area, row_height, visible.len().max(1), |ui, range| {
                let session = &self.sessions[a];
                let any_active = session.has_active_operations();
                let failed_count = session.transfers.iter()
                    .filter(|item| item.operation_id.is_none() && item.is_failed() && item.job.is_some())
                    .count();
                let tab_count = session.transfers.iter()
                    .filter(|item| item.operation_id.is_none() && item.tab() == tab)
                    .count();
                // Menu items for the whole tab (also on the empty space below
                // the rows). Returns the chosen one.
                let tab_menu = |ui: &mut egui::Ui| -> Option<TabAction> {
                    let mut chosen = None;
                    if tab == QueueTab::Pending {
                        if ui.add_enabled(any_active, egui::Button::new("Stop all transfers")).clicked() {
                            chosen = Some(TabAction::StopAll);
                        }
                    } else {
                        if tab == QueueTab::Failed {
                            let label = format!("Retry all failed ({failed_count})");
                            if ui.add_enabled(session.is_connected() && failed_count > 0, egui::Button::new(label)).clicked() {
                                chosen = Some(TabAction::RetryAll);
                            }
                        }
                        let label = if tab == QueueTab::Failed { "Clear failed" } else { "Clear completed" };
                        if ui.add_enabled(tab_count > 0, egui::Button::new(format!("{label} ({tab_count})"))).clicked() {
                            chosen = Some(TabAction::Clear);
                        }
                    }
                    if chosen.is_some() {
                        ui.close();
                    }
                    chosen
                };
                let mut tab_action = None;
                if visible.is_empty() {
                    let empty = match tab {
                        QueueTab::Pending => "There are no pending transfers.",
                        QueueTab::Failed => "No transfers have failed or been stopped.",
                        _ => "There are no completed transfers.",
                    };
                    ui.add_space(6.0);
                    ui.horizontal(|ui| { ui.add_space(6.0); ui.weak(empty); });
                }
                for &(index, depth) in &visible[range.start.min(visible.len())..range.end.min(visible.len())] {
                    let item = &session.transfers[index];
                    // The whole row is one click target; the cells are drawn on top of it.
                    let (row_rect, row_response) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), row_height), egui::Sense::click()
                    );
                    if session.selected_transfer == Some(item.id) {
                        ui.painter().rect_filled(row_rect, 0.0, win32::queue_selection());
                    }
                    if row_response.clicked() || row_response.secondary_clicked() {
                        select = Some(item.id);
                    }
                    if item.folder && row_response.double_clicked() {
                        toggle = Some(item.id);
                    }
                    // Rows of a folder transfer stop the whole folder transfer.
                    let operation = item.operation_id.unwrap_or(item.id);
                    row_response.context_menu(|ui| {
                        win32::menu_item_style(ui.style_mut());
                        if item.folder {
                            if ui.button(if item.expanded { "Collapse" } else { "Expand" }).clicked() {
                                toggle = Some(item.id);
                                ui.close();
                            }
                            ui.separator();
                        }
                        if item.is_failed() {
                            let label = if item.folder { "Retry failed files" } else { "Retry" };
                            if ui.add_enabled(session.can_retry(item.id), egui::Button::new(label)).clicked() {
                                retry = Some(Some(item.id));
                                ui.close();
                            }
                        } else if tab == QueueTab::Pending {
                            let label = if item.operation_id.is_some() || item.folder { "Stop folder transfer" } else { "Stop transfer" };
                            if ui.add_enabled(session.is_operation_active(operation), egui::Button::new(label)).clicked() {
                                stop = Some(Some(operation));
                                ui.close();
                            }
                        }
                        if let Some(action) = tab_menu(ui) {
                            tab_action = Some(action);
                        }
                    });
                    let row_layout = egui::UiBuilder::new()
                        .max_rect(row_rect)
                        .layout(egui::Layout::left_to_right(egui::Align::Center));
                    ui.scope_builder(row_layout, |ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        // Expander column; the files of a folder are indented below it.
                        let indent = EXPANDER_WIDTH * f32::from(depth);
                        ui.add_space(indent);
                        let (expander, expander_response) =
                            ui.allocate_exact_size(egui::vec2(EXPANDER_WIDTH, row_height), egui::Sense::click());
                        if item.folder {
                            paint_expander(ui.painter(), expander, item.expanded);
                            if expander_response.clicked() {
                                toggle = Some(item.id);
                            }
                        }
                        file_text_cell(ui, (file_width - EXPANDER_WIDTH - indent).max(40.0), row_height, &item.name, false);
                        file_text_cell(ui, protocol_width, row_height, item.protocol.unwrap_or("—"), false);
                        let (cell_rect, response) = ui.allocate_exact_size(
                            egui::vec2(progress_width, row_height), egui::Sense::hover()
                        );
                        let bar_rect = cell_rect.shrink2(egui::vec2(4.0, 2.0));
                        let painter = ui.painter();
                        painter.rect_filled(bar_rect, 0.0, win32::window());
                        win32::thin_sunken(painter, bar_rect);
                        let bar_rect = bar_rect.shrink(1.0);
                        let failed = item.state.starts_with("Failed");
                        let complete = item.state == "Complete";
                        let pieces: Vec<Piece> = if !item.segments.is_empty() && item.total > 0 {
                            item.segments.iter().map(|segment| {
                                let length = segment.end_exclusive.saturating_sub(segment.start);
                                Piece {
                                    start: segment.start,
                                    end: segment.end_exclusive,
                                    done: if segment.complete { length } else { segment.transferred_bytes.min(length) },
                                    failed: segment.failed,
                                }
                            }).collect()
                        } else {
                            let total = item.total.max(1);
                            let done = if complete { total } else { item.transferred.min(total) };
                            vec![Piece { start: 0, end: total, done, failed }]
                        };
                        let total = if item.segments.is_empty() || item.total == 0 { item.total.max(1) } else { item.total };
                        let fill = if complete {
                            win32::ok_green()
                        } else if item.state == "Cancelled" {
                            win32::shadow()
                        } else {
                            PIECE_FILL
                        };
                        paint_piece_bar(painter, bar_rect, total, &pieces, fill);
                        if response.hovered() {
                            let details = item.details.as_deref().map(|details| format!("\n\n{details}")).unwrap_or_default();
                            response.on_hover_text(format!(
                                "{} / {} · {} segments\n{}{details}",
                                size_text(item.transferred), size_text(item.total), item.segments.len(), item.state
                            ));
                        }
                        let percent = if item.total == 0 {
                            if item.state == "Complete" { 100.0 } else { 0.0 }
                        } else { item.transferred as f64 * 100.0 / item.total as f64 };
                        file_text_cell(ui, percent_width, row_height, &format!("{percent:.1}%"), false);
                        let speed = if item.state == "Queued" { "—".into() } else { speed_text(item.speed_mib_s) };
                        file_text_cell(ui, speed_width, row_height, &speed, false);
                        let elapsed = item.started_at.map(|start| {
                            item.finished_at.unwrap_or_else(Instant::now).saturating_duration_since(start)
                        });
                        file_text_cell(ui, elapsed_width, row_height, &elapsed.map(duration_text).unwrap_or_else(|| "—".into()), false);
                        let remaining = if item.state == "Complete" {
                            Some(Duration::ZERO)
                        } else if (item.state == "Downloading" || item.state == "Uploading") && item.transferred > 0 && item.total > item.transferred {
                            elapsed.map(|duration| {
                                let rate = item.transferred as f64 / duration.as_secs_f64().max(0.001);
                                Duration::from_secs_f64(((item.total - item.transferred) as f64 / rate).max(0.0))
                            })
                        } else { None };
                        let remaining = remaining.map(duration_text).unwrap_or_else(|| {
                            if failed { "Failed".into() }
                            else if item.state == "Cancelled" { "Cancelled".into() }
                            else if item.state == "Queued" { "Queued".into() }
                            else { "Calculating…".into() }
                        });
                        file_text_cell(ui, remaining_width, row_height, &remaining, false);
                    });
                }
                // Right-click on the empty space below the rows.
                let clip = ui.clip_rect();
                let top = ui.cursor().min.y;
                if top < clip.bottom() - 1.0 {
                    let filler = egui::Rect::from_min_max(egui::pos2(clip.left(), top), egui::pos2(clip.right(), clip.bottom() - 1.0));
                    ui.allocate_rect(filler, egui::Sense::click()).context_menu(|ui| {
                        win32::menu_item_style(ui.style_mut());
                        if let Some(action) = tab_menu(ui) {
                            tab_action = Some(action);
                        }
                    });
                }
                match tab_action {
                    Some(TabAction::StopAll) => stop = Some(None),
                    Some(TabAction::RetryAll) => retry = Some(None),
                    Some(TabAction::Clear) => clear = true,
                    None => {}
                }
            });
            let session = &mut self.sessions[a];
            if let Some(id) = toggle {
                session.toggle_expanded(id);
            }
            if let Some(id) = select {
                session.selected_transfer = Some(id);
            }
            match stop {
                Some(Some(operation)) => session.cancel_operation(operation),
                Some(None) => session.cancel_all(),
                None => {}
            }
            let settings = self.settings.transfer;
            match retry {
                Some(Some(id)) => { session.retry(id, settings); }
                Some(None) => { session.retry_all_failed(settings); }
                None => {}
            }
            if clear {
                let count = session.clear_tab(tab);
                session.status = format!("Cleared {count} transfer(s) from the queue");
            }
        });
    }

    /// The selected session's log lines (kept in memory whether or not file logging is on).
    fn log_tab(&mut self, ui: &mut egui::Ui) {
        let a = self.active;
        let entries = self.sessions[a].recent_log();
        let list_height = ui.available_height().max(40.0);
        win32::list_view(ui, list_height, |ui| {
            if entries.is_empty() {
                ui.add_space(6.0);
                ui.horizontal(|ui| { ui.add_space(6.0); ui.weak("Nothing has been logged for this session yet."); });
                return;
            }
            let area = egui::ScrollArea::both()
                .id_salt(("session_log", self.sessions[a].id))
                .auto_shrink([false, false])
                .stick_to_bottom(true);
            win32::scroll(ui, area, |ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.add_space(2.0);
                for entry in &entries {
                    let color = match entry.severity {
                        crate::logging::Severity::Error => win32::error_red(),
                        crate::logging::Severity::Warning => win32::warn_amber(),
                        _ => win32::text_color(),
                    };
                    let time = crate::logging::iso8601_utc(entry.time);
                    let line = format!(
                        " {}  {:<6}  {:<8}  {}",
                        time.replace('T', " ").trim_end_matches('Z'),
                        entry.severity.label(),
                        entry.msgid,
                        entry.message
                    );
                    ui.add(egui::Label::new(egui::RichText::new(line).monospace().color(color)).wrap_mode(egui::TextWrapMode::Extend));
                }
            });
        });
    }

    /// Speed graph and counters of the selected session.
    fn statistics_tab(&mut self, ui: &mut egui::Ui) {
        let a = self.active;
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            ui.label("Timespan:");
            egui::ComboBox::from_id_salt("stats_span")
                .width(80.0)
                .selected_text(format!("{} min", self.stats_span_minutes))
                .show_ui(ui, |ui| {
                    for minutes in [1_u32, 2, 5, 10, 15, 30] {
                        ui.selectable_value(&mut self.stats_span_minutes, minutes, format!("{minutes} min"));
                    }
                });
        });
        ui.add_space(2.0);
        let session = &self.sessions[a];
        let span = Duration::from_secs(u64::from(self.stats_span_minutes) * 60);
        let now = Instant::now();
        let window: Vec<SpeedSample> = session
            .speed_history
            .iter()
            .copied()
            .filter(|sample| now.saturating_duration_since(sample.at) <= span)
            .collect();
        let peak = |pick: fn(&SpeedSample) -> f64| window.iter().map(pick).fold(0.0_f64, f64::max);
        // Averages cover only the seconds in which that direction was transferring,
        // so idle time does not pull them towards zero.
        // None when that direction never ran in the timespan.
        let average = |pick: fn(&SpeedSample) -> Option<f64>| {
            let active: Vec<f64> = window.iter().filter_map(pick).collect();
            (!active.is_empty()).then(|| active.iter().sum::<f64>() / active.len() as f64)
        };
        let average_down = average(|sample| sample.downloading.then_some(sample.down));
        let average_up = average(|sample| sample.uploading.then_some(sample.up));
        let (bytes_down, bytes_up) = session.bytes_transferred();
        let count = |tab: QueueTab| session.transfers.iter().filter(|item| item.operation_id.is_none() && item.tab() == tab).count();
        let connected_for = session.connected_at.map(|since| duration_text(now.saturating_duration_since(since)));
        let rows: Vec<(&str, String)> = vec![
            ("Downloading now:", speed_text(session.speed("Downloading"))),
            ("Uploading now:", speed_text(session.speed("Uploading"))),
            ("Peak download:", speed_text(peak(|sample| sample.down))),
            ("Peak upload:", speed_text(peak(|sample| sample.up))),
            ("Average download:", speed_text(average_down.unwrap_or(0.0))),
            ("Average upload:", speed_text(average_up.unwrap_or(0.0))),
            ("Downloaded:", size_text(bytes_down)),
            ("Uploaded:", size_text(bytes_up)),
            ("Transfers:", format!("{} active, {} complete, {} failed", count(QueueTab::Pending), count(QueueTab::Complete), count(QueueTab::Failed))),
            ("Connected for:", connected_for.unwrap_or_else(|| "—".into())),
        ];
        debug_assert_eq!(rows.len(), STATS_ROWS);
        let height = ui.available_height().max(60.0);
        ui.horizontal_top(|ui| {
            let stats_width = 300.0;
            let graph_width = (ui.available_width() - stats_width - 8.0).max(120.0);
            let (rect, _) = ui.allocate_exact_size(egui::vec2(graph_width, height), egui::Sense::hover());
            paint_speed_graph(ui, rect, &window, span, now, (average_down, average_up));
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.set_width(stats_width);
                // Scrolls when the panel is made smaller than the table,
                // instead of forcing the panel taller.
                egui::ScrollArea::vertical().id_salt("stats_scroll").max_height(height).auto_shrink([false, true]).show(ui, |ui| {
                    egui::Grid::new("stats_grid").num_columns(2).spacing([12.0, STATS_ROW_GAP]).show(ui, |ui| {
                        for (label, value) in &rows {
                            ui.label(*label);
                            ui.label(value);
                            ui.end_row();
                        }
                    });
                });
            });
        });
    }

    /// Interactive shell on the selected session's SSH connection.
    fn terminal_tab(&mut self, ui: &mut egui::Ui) {
        let session = &mut self.sessions[self.active];
        if !session.is_connected() {
            session.terminal = None;
            ui.add_space(4.0);
            ui.weak("Connect to a server to open an SSH terminal.");
            return;
        }
        let settings = &self.settings.terminal;
        let (rows, cols) = Terminal::grid_size(ui, settings, ui.available_size());
        let ctx = ui.ctx().clone();
        let restart = session.terminal(&ctx, settings, rows, cols).is_some_and(|terminal| terminal.show(ui, settings));
        if restart {
            // Opened again on the next frame.
            session.terminal = None;
            ctx.request_repaint();
        }
    }

    fn dialog_window(&mut self, ctx: &egui::Context) {
        let Some(dialog) = self.dialog.clone() else { return; };
        let id = egui::ViewportId::from_hash_of("rust-sftp-client-dialog");
        let title = match &dialog {
            Dialog::Profiles => "Connection profiles",
            Dialog::Password => "SSH password",
            Dialog::TrustHostKey => "Verify SSH host key",
            Dialog::Error => "Operation failed",
            Dialog::ConfirmDelete => "Confirm Delete",
            Dialog::Rename => "Rename",
            Dialog::NewFolder => "New Folder",
        };
        let size = match &dialog {
            // Fits the tallest form (password logon: eight rows) with 240 px fields.
            Dialog::Profiles => [520.0, 310.0],
            Dialog::TrustHostKey => [470.0, 260.0],
            Dialog::ConfirmDelete => [440.0, 180.0],
            Dialog::Rename | Dialog::NewFolder => [420.0, 180.0],
            _ => [470.0, 210.0],
        };
        // The minimum must not exceed the size: on Wayland a fixed-size window
        // gets max size = its size, and min > max is a protocol error that makes
        // the compositor disconnect (crash) the app.
        let builder = egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size(size)
            .with_min_inner_size(size)
            .with_resizable(false);
        let mut close = false;
        let mut connect = false;
        let mut save = false;
        let mut accept_trust = false;
        let mut password_value = None;
        let mut confirm_delete = false;
        let mut confirm_rename = false;
        let mut confirm_new_folder = false;
        let mut repaint = false;
        ctx.show_viewport_immediate(id, builder, |window_ctx, _class| {
            egui::CentralPanel::default().show(window_ctx, |ui| {
                match &dialog {
                    Dialog::Profiles => {
                        let mut apply = None;
                        let mut new_profile = false;
                        let mut delete = false;
                        let footer_height = 40.0;
                        let body_height = (ui.available_height() - footer_height).max(120.0);
                        ui.horizontal_top(|ui| {
                            ui.vertical(|ui| {
                                ui.set_width(170.0);
                                ui.label("Saved profiles:");
                                let list_height = body_height - 50.0;
                                win32::list_view(ui, list_height, |ui| {
                                    win32::scroll(ui, egui::ScrollArea::vertical().id_salt("profile_list").auto_shrink([false, false]), |ui| {
                                        for (index, profile) in self.saved_profiles.iter().enumerate() {
                                            if win32::list_item(ui, &profile.name, self.selected_profile == Some(index)).clicked() {
                                                apply = Some(index);
                                            }
                                        }
                                        if self.selected_profile.is_none() {
                                            win32::list_item(ui, "(new, unsaved profile)", true);
                                        }
                                    });
                                });
                                ui.add_space(4.0);
                                ui.horizontal(|ui| {
                                    if win32::button_sized(ui, true, "New Profile", 82.0).clicked() { new_profile = true; }
                                    let saved = self.selected_profile.is_some_and(|index| index < self.saved_profiles.len());
                                    if win32::button_sized(ui, saved, "Delete", 82.0).clicked() { delete = true; }
                                });
                            });
                            ui.add_space(8.0);
                            ui.vertical(|ui| {
                                let heading = if self.selected_profile.is_some() { "Profile settings" } else { "New profile (unsaved)" };
                                ui.strong(heading);
                                win32::etched_hline(ui);
                                egui::Grid::new("profile_fields").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                                    let field_width = (ui.available_width() - 90.0).max(160.0);
                                    ui.label("Profile name:");
                                    win32::text_edit(ui, egui::TextEdit::singleline(&mut self.profile_name).desired_width(field_width));
                                    ui.end_row();
                                    ui.label("Host name:");
                                    win32::text_edit(ui, egui::TextEdit::singleline(&mut self.host).desired_width(field_width));
                                    ui.end_row();
                                    ui.label("Port:");
                                    win32::text_edit(ui, egui::TextEdit::singleline(&mut self.port).desired_width(55.0));
                                    ui.end_row();
                                    ui.label("User name:");
                                    win32::text_edit(ui, egui::TextEdit::singleline(&mut self.username).desired_width(field_width));
                                    ui.end_row();
                                    ui.label("Logon type:");
                                    egui::ComboBox::from_id_salt("auth_method")
                                        .width(field_width)
                                        .selected_text(match self.auth { AuthMethod::Password => "Password", AuthMethod::PrivateKey => "Private key", AuthMethod::SshAgent => "SSH agent (unsupported)" })
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(&mut self.auth, AuthMethod::Password, "Password");
                                            ui.selectable_value(&mut self.auth, AuthMethod::PrivateKey, "Private key");
                                            ui.add_enabled(false, egui::Button::selectable(false, "SSH agent (not implemented)"));
                                        });
                                    ui.end_row();
                                    if self.auth == AuthMethod::PrivateKey {
                                        ui.label("Key file:");
                                        win32::text_edit(ui, egui::TextEdit::singleline(&mut self.key_path).desired_width(field_width));
                                        ui.end_row();
                                    }
                                    if self.auth == AuthMethod::Password {
                                        ui.label("Password:");
                                        let hint = if self.save_password { "Leave empty to use the saved password" } else { "Asked for when connecting" };
                                        win32::text_edit(ui, egui::TextEdit::singleline(&mut self.password)
                                            .password(true)
                                            .hint_text(hint)
                                            .desired_width(field_width));
                                        ui.end_row();
                                        ui.label("");
                                        ui.horizontal(|ui| {
                                            ui.checkbox(&mut self.save_password, "Save password");
                                            win32::info_tip(ui, SAVE_PASSWORD_TIP);
                                        });
                                        ui.end_row();
                                    }
                                    ui.label("Remote folder:");
                                    win32::text_edit(ui, egui::TextEdit::singleline(&mut self.remote_folder)
                                        .hint_text("Home folder")
                                        .desired_width(field_width));
                                    ui.end_row();
                                });
                            });
                        });
                        // Only a saved profile can be deleted.
                        let can_delete = self.selected_profile.is_some_and(|index| index < self.saved_profiles.len());
                        if let Some(index) = apply { self.apply_profile(index); }
                        if new_profile { self.new_profile(); }
                        if delete && can_delete { self.delete_profile(); }
                        repaint |= apply.is_some() || new_profile || delete;
                        dialog_buttons(ui, |ui| {
                            if win32::button_sized(ui, true, "Cancel", 75.0).clicked() { close = true; }
                            if win32::button_sized(ui, true, "Connect", 75.0).clicked() { connect = true; }
                            if win32::button_sized(ui, true, "Save", 75.0).clicked() { save = true; }
                        });
                    }
                    Dialog::Password => {
                        ui.label(format!("Enter the password for {}@{}:{}", self.username, self.host, self.port));
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Password:");
                            let response = win32::text_edit(ui, egui::TextEdit::singleline(&mut self.password).password(true).desired_width(f32::INFINITY));
                            if response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                                password_value = Some(self.password.clone());
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut self.save_password, "Save password");
                            win32::info_tip(ui, SAVE_PASSWORD_TIP);
                        });
                        dialog_buttons(ui, |ui| {
                            if win32::button_sized(ui, true, "Cancel", 75.0).clicked() { close = true; }
                            if win32::button_sized(ui, true, "OK", 75.0).clicked() { password_value = Some(self.password.clone()); }
                        });
                    }
                    Dialog::TrustHostKey => {
                        let session = self.dialog_session.and_then(|id| self.session_index(id)).map(|index| &self.sessions[index]);
                        let server = session.and_then(|session| session.profile.as_ref())
                            .map(|profile| format!("{}:{}", profile.host, profile.port))
                            .unwrap_or_else(|| "The server".into());
                        let fingerprint = session.and_then(|session| session.pending_fingerprint.clone())
                            .unwrap_or_else(|| "Fingerprint unavailable".into());
                        ui.strong("Unknown SSH host key");
                        ui.add_space(4.0);
                        ui.label(format!("The server {server} is not trusted yet."));
                        ui.label("Verify this fingerprint using a trusted channel before accepting it.");
                        ui.add_space(6.0);
                        win32::field(ui, &fingerprint);
                        dialog_buttons(ui, |ui| {
                            if win32::button_sized(ui, true, "Reject", 75.0).clicked() { close = true; }
                            if win32::button_sized(ui, true, "Trust and continue", 75.0).clicked() { accept_trust = true; }
                        });
                    }
                    Dialog::Error => {
                        ui.label(&self.error_message);
                        dialog_buttons(ui, |ui| {
                            if win32::button_sized(ui, true, "OK", 75.0).clicked() { close = true; }
                        });
                    }
                    Dialog::ConfirmDelete => {
                        let message = self.file_target.as_ref().map(delete_message).unwrap_or_default();
                        ui.add_space(4.0);
                        ui.horizontal_top(|ui| {
                            win32::message_icon(ui, win32::Icon::Warning);
                            ui.add_space(10.0);
                            ui.add(egui::Label::new(message).wrap());
                        });
                        dialog_buttons(ui, |ui| {
                            if win32::button_sized(ui, true, "No", 75.0).clicked() { close = true; }
                            if win32::button_sized(ui, true, "Yes", 75.0).clicked() { confirm_delete = true; }
                        });
                    }
                    Dialog::NewFolder => {
                        let location = self.session_index(self.file_target_session)
                            .map(|index| {
                                let session = &self.sessions[index];
                                if self.new_folder_remote { session.remote_path.clone() } else { session.path.display().to_string() }
                            })
                            .unwrap_or_default();
                        ui.label(format!("Name of the new folder in {location}:"));
                        let response = win32::text_edit(ui, egui::TextEdit::singleline(&mut self.rename_value).desired_width(f32::INFINITY));
                        if self.rename_focus {
                            response.request_focus();
                            // Select the suggested name, so typing replaces it.
                            if let Some(mut state) = egui::TextEdit::load_state(ui.ctx(), response.id) {
                                let all = egui::text::CCursorRange::two(egui::text::CCursor::new(0), egui::text::CCursor::new(self.rename_value.chars().count()));
                                state.cursor.set_char_range(Some(all));
                                state.store(ui.ctx(), response.id);
                            }
                            self.rename_focus = false;
                        }
                        if response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) { confirm_new_folder = true; }
                        if !self.rename_error.is_empty() {
                            ui.colored_label(win32::error_red(), &self.rename_error);
                        }
                        dialog_buttons(ui, |ui| {
                            if win32::button_sized(ui, true, "Cancel", 75.0).clicked() { close = true; }
                            if win32::button_sized(ui, true, "OK", 75.0).clicked() { confirm_new_folder = true; }
                        });
                    }
                    Dialog::Rename => {
                        let old_name = self.file_target.as_ref()
                            .and_then(|target| target.items().first().map(|(name, _)| name.to_string()))
                            .unwrap_or_default();
                        ui.label(format!("Rename \"{old_name}\" to:"));
                        let response = win32::text_edit(ui, egui::TextEdit::singleline(&mut self.rename_value).desired_width(f32::INFINITY));
                        if self.rename_focus {
                            response.request_focus();
                            self.rename_focus = false;
                        }
                        if response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) { confirm_rename = true; }
                        if !self.rename_error.is_empty() {
                            ui.colored_label(win32::error_red(), &self.rename_error);
                        }
                        dialog_buttons(ui, |ui| {
                            if win32::button_sized(ui, true, "Cancel", 75.0).clicked() { close = true; }
                            if win32::button_sized(ui, true, "OK", 75.0).clicked() { confirm_rename = true; }
                        });
                    }
                }
            });
            if window_ctx.input(|input| input.viewport().close_requested()) { close = true; }
            if repaint { window_ctx.request_repaint(); }
        });
        if confirm_delete {
            self.dialog = None;
            self.perform_delete();
        }
        if confirm_rename && self.perform_rename() {
            self.dialog = None;
        }
        if confirm_new_folder && self.perform_new_folder() {
            self.dialog = None;
        }
        if save { self.save_profile(); }
        if connect {
            self.connect_with_form();
        }
        if let Some(password) = password_value {
            self.password = password.clone();
            self.dialog = None;
            self.begin_connect(Some(password));
        }
        if accept_trust {
            self.dialog = None;
            self.accept_host_key();
        }
        if close {
            if matches!(&dialog, Dialog::TrustHostKey) { self.reject_host_key(); }
            if matches!(&dialog, Dialog::ConfirmDelete | Dialog::Rename) { self.file_target = None; }
            self.dialog = None;
        }
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        if !self.settings_open { return; }
        let id = egui::ViewportId::from_hash_of("rust-sftp-client-settings");
        let builder = egui::ViewportBuilder::default()
            .with_title("Settings")
            .with_inner_size([680.0, 470.0])
            .with_min_inner_size([520.0, 300.0]);
        let mut close = false;
        let mut apply = false;
        ctx.show_viewport_immediate(id, builder, |window_ctx, _| {
            egui::CentralPanel::default().show(window_ctx, |ui| {
                let body_height = (ui.available_height() - 40.0).max(120.0);
                ui.horizontal_top(|ui| {
                    ui.vertical(|ui| {
                        ui.set_width(160.0);
                        win32::list_view(ui, body_height, |ui| {
                            for page in SettingsPage::ALL {
                                if win32::list_item(ui, page.title(), self.settings_page == page).clicked() {
                                    self.settings_page = page;
                                }
                            }
                        });
                    });
                    ui.add_space(10.0);
                    ui.vertical(|ui| {
                        ui.strong(self.settings_page.title());
                        win32::etched_hline(ui);
                        let draft = &mut self.settings_draft;
                        let row = |ui: &mut egui::Ui, label: &str, value: &mut String, unit: &str| {
                            ui.label(label);
                            win32::text_edit(ui, egui::TextEdit::singleline(value).desired_width(70.0));
                            ui.weak(unit);
                            ui.end_row();
                        };
                        match self.settings_page {
                            SettingsPage::Transfers => {
                                egui::Grid::new("settings_transfers").num_columns(4).spacing([8.0, 8.0]).show(ui, |ui| {
                                    ui.label("Files transferred at once:");
                                    win32::text_edit(ui, egui::TextEdit::singleline(&mut draft.parallel_files).desired_width(70.0));
                                    ui.weak("per connection (1–32)");
                                    win32::info_tip(ui, TRANSFER_TIP_PARALLEL_FILES);
                                    ui.end_row();
                                });
                                ui.add_space(6.0);
                                ui.weak("Applies to single files and to the files of folder transfers alike; the rest wait in the queue.");
                            }
                            SettingsPage::Segmentation => {
                                egui::Grid::new("settings_segmentation").num_columns(3).spacing([8.0, 8.0]).show(ui, |ui| {
                                    row(ui, "Segment files larger than:", &mut draft.threshold_mib, "MiB");
                                    row(ui, "Segment size:", &mut draft.segment_mib, "MiB");
                                    row(ui, "Workers per file:", &mut draft.workers, "1–32");
                                });
                                ui.add_space(6.0);
                                ui.weak("Large downloads are split into segments that are fetched in parallel by several workers.");
                            }
                            SettingsPage::Network => {
                                let info_row = |ui: &mut egui::Ui, label: &str, value: &mut String, unit: &str, tip: &str| {
                                    ui.label(label);
                                    win32::text_edit(ui, egui::TextEdit::singleline(value).desired_width(70.0));
                                    ui.weak(unit);
                                    win32::info_tip(ui, tip);
                                    ui.end_row();
                                };
                                egui::Grid::new("settings_network").num_columns(4).spacing([8.0, 6.0]).show(ui, |ui| {
                                    info_row(ui, "SFTP channels per connection:", &mut draft.sftp_channels, "1–16", NETWORK_TIP_CHANNELS);
                                    info_row(ui, "Requests in flight per file:", &mut draft.pipelined_requests, "1–256", NETWORK_TIP_PIPELINE);
                                    info_row(ui, "SFTP packet size:", &mut draft.sftp_packet_kib, "KiB (32–256)", NETWORK_TIP_PACKET);
                                    info_row(ui, "SSH window size:", &mut draft.ssh_window_mib, "MiB (1–1024)", NETWORK_TIP_WINDOW);
                                    info_row(ui, "Keepalive interval:", &mut draft.keepalive_secs, "s (0 = off)", NETWORK_TIP_KEEPALIVE);
                                    info_row(ui, "Request timeout:", &mut draft.request_timeout_secs, "s (5–3600)", NETWORK_TIP_TIMEOUT);

                                    ui.label("SSH compression:");
                                    ui.checkbox(&mut draft.compression, "Enable (zlib)");
                                    ui.label("");
                                    win32::info_tip(ui, NETWORK_TIP_COMPRESSION);
                                    ui.end_row();

                                    ui.label("UDP downloads:");
                                    ui.checkbox(&mut draft.turbo, "Use rsftp-turbo when available");
                                    ui.label("");
                                    win32::info_tip(ui, NETWORK_TIP_TURBO);
                                    ui.end_row();
                                });
                                ui.add_space(6.0);
                                ui.weak("Hover an information icon for details about a setting.");
                                ui.add_space(4.0);
                                ui.colored_label(win32::warn_amber(), "Network settings apply to new connections.");
                            }
                            SettingsPage::Appearance => {
                                ui.horizontal(|ui| {
                                    ui.label("Theme:");
                                    egui::ComboBox::from_id_salt("theme")
                                        .width(180.0)
                                        .selected_text(draft.theme.label())
                                        .show_ui(ui, |ui| {
                                            for theme in [win32::Theme::Light, win32::Theme::Dark] {
                                                ui.selectable_value(&mut draft.theme, theme, theme.label());
                                            }
                                        });
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Units:");
                                    egui::ComboBox::from_id_salt("units")
                                        .width(260.0)
                                        .selected_text(draft.units.label())
                                        .show_ui(ui, |ui| {
                                            for units in crate::units::SizeUnits::ALL {
                                                ui.selectable_value(&mut draft.units, units, units.label());
                                            }
                                        });
                                });
                                ui.add_space(6.0);
                                ui.weak("Units apply to file sizes, transfer speeds, the transfer queue and the statistics.");
                                ui.weak("Both apply to every window as soon as you click OK or Apply.");
                            }
                            SettingsPage::Algorithms => {
                                let tabs = AlgorithmKind::ALL.map(|kind| (kind, kind.label().to_owned()));
                                if win32::tab_strip(ui, &mut draft.algorithm_kind, &tabs) {
                                    draft.algorithm_row = None;
                                }
                                ui.add_space(6.0);
                                let kind = draft.algorithm_kind;
                                let list_height = (body_height - 170.0).max(110.0);
                                let mut clicked = None;
                                let mut action = None;
                                ui.horizontal_top(|ui| {
                                    ui.vertical(|ui| {
                                        ui.set_width((ui.available_width() - 96.0).max(220.0));
                                        win32::list_view(ui, list_height, |ui| {
                                            let area = egui::ScrollArea::vertical().id_salt(("algorithms", kind.label())).auto_shrink([false, false]);
                                            win32::scroll(ui, area, |ui| {
                                                for (index, choice) in draft.algorithms.list_mut(kind).iter_mut().enumerate() {
                                                    ui.horizontal(|ui| {
                                                        ui.add_space(3.0);
                                                        ui.checkbox(&mut choice.enabled, "");
                                                        let label = if kind.is_weak(&choice.name) {
                                                            format!("{}  (weak)", choice.name)
                                                        } else {
                                                            choice.name.clone()
                                                        };
                                                        if win32::list_item(ui, &label, draft.algorithm_row == Some(index)).clicked() {
                                                            clicked = Some(index);
                                                        }
                                                    });
                                                }
                                            });
                                        });
                                    });
                                    ui.add_space(6.0);
                                    ui.vertical(|ui| {
                                        ui.spacing_mut().item_spacing.y = 6.0;
                                        let count = draft.algorithms.list(kind).len();
                                        let row = draft.algorithm_row;
                                        if win32::button_sized(ui, row.is_some_and(|row| row > 0), "Move Up", 86.0).clicked() {
                                            action = Some(-1);
                                        }
                                        if win32::button_sized(ui, row.is_some_and(|row| row + 1 < count), "Move Down", 86.0).clicked() {
                                            action = Some(1);
                                        }
                                        if win32::button_sized(ui, true, "Defaults", 86.0).clicked() {
                                            action = Some(0);
                                        }
                                    });
                                });
                                if clicked.is_some() {
                                    draft.algorithm_row = clicked;
                                }
                                match (action, draft.algorithm_row) {
                                    (Some(0), _) => {
                                        *draft.algorithms.list_mut(kind) = kind.defaults();
                                        draft.algorithm_row = None;
                                    }
                                    (Some(step), Some(row)) => {
                                        let target = row as isize + step;
                                        let list = draft.algorithms.list_mut(kind);
                                        if target >= 0 && (target as usize) < list.len() {
                                            list.swap(row, target as usize);
                                            draft.algorithm_row = Some(target as usize);
                                        }
                                    }
                                    _ => {}
                                }
                                ui.add_space(6.0);
                                ui.weak(match kind {
                                    AlgorithmKind::KeyExchange => ALGORITHMS_HELP_KEX,
                                    AlgorithmKind::Cipher => ALGORITHMS_HELP_CIPHERS,
                                    AlgorithmKind::Mac => ALGORITHMS_HELP_MACS,
                                    AlgorithmKind::HostKey => ALGORITHMS_HELP_HOST_KEYS,
                                });
                                ui.add_space(4.0);
                                ui.colored_label(win32::warn_amber(), "The server uses the first ticked algorithm it supports. Applies to new connections.");
                            }
                            SettingsPage::Terminal => {
                                egui::Grid::new("settings_terminal").num_columns(3).spacing([8.0, 8.0]).show(ui, |ui| {
                                    row(ui, "Font size:", &mut draft.terminal_font_size, "pt (6–32)");

                                    ui.label("Colours:");
                                    egui::ComboBox::from_id_salt("terminal_colors")
                                        .width(150.0)
                                        .selected_text(draft.terminal_colors.label())
                                        .show_ui(ui, |ui| {
                                            for colors in TerminalColors::ALL {
                                                ui.selectable_value(&mut draft.terminal_colors, colors, colors.label());
                                            }
                                        });
                                    ui.label("");
                                    ui.end_row();

                                    ui.label("Terminal type:");
                                    egui::ComboBox::from_id_salt("terminal_type")
                                        .width(150.0)
                                        .selected_text(draft.terminal_type.as_str())
                                        .show_ui(ui, |ui| {
                                            for term in TERMINAL_TYPES {
                                                ui.selectable_value(&mut draft.terminal_type, term.to_owned(), term);
                                            }
                                        });
                                    ui.weak("TERM");
                                    ui.end_row();

                                    row(ui, "Scrollback:", &mut draft.terminal_scrollback, "lines (0–100000)");
                                    row(ui, "Mouse wheel scrolls:", &mut draft.terminal_wheel_lines, "lines per notch (1–20)");
                                });
                                ui.add_space(6.0);
                                ui.checkbox(&mut draft.terminal_copy_on_select, "Copy text to the clipboard when it is selected");
                                ui.checkbox(&mut draft.terminal_ctrl_c_copies, "Ctrl+C copies the selection (and interrupts without one)");
                                ui.indent("terminal_ctrl_c_help", |ui| {
                                    ui.weak("When off, Ctrl+C always interrupts. Ctrl+Shift+C copies in either case.");
                                });
                                ui.add_space(6.0);
                                ui.colored_label(win32::warn_amber(), "Terminal type and scrollback apply to new shells.");
                            }
                            SettingsPage::Logging => {
                                ui.checkbox(&mut draft.logging_enabled, "Enable logging");
                                ui.add_enabled_ui(draft.logging_enabled, |ui| {
                                    ui.indent("log_categories", |ui| {
                                        ui.checkbox(&mut draft.log_connections, "Log connections");
                                        ui.checkbox(&mut draft.log_transfers, "Log transfers");
                                    });
                                    ui.add_space(6.0);
                                    ui.label("Log directory:");
                                    ui.horizontal(|ui| {
                                        let width = (ui.available_width() - 80.0).max(120.0);
                                        win32::text_edit(ui, egui::TextEdit::singleline(&mut draft.log_directory).desired_width(width));
                                        if win32::button_sized(ui, true, "Default", 70.0).clicked() {
                                            draft.log_directory = default_log_dir().display().to_string();
                                        }
                                    });
                                    ui.add_space(6.0);
                                    ui.checkbox(&mut draft.split_sessions, "Split individual session logs");
                                    ui.indent("split_help", |ui| {
                                        ui.weak("Writes one file per session, named after the remote, e.g. alice@example.org_22_20261108T140312Z_2.log");
                                    });
                                });
                                ui.add_space(6.0);
                                ui.weak("Connection and transfer events are written to the same file in RFC 5424 syslog format with UTC timestamps.");
                            }
                        }
                        if !self.settings_error.is_empty() {
                            ui.add_space(6.0);
                            ui.colored_label(win32::error_red(), &self.settings_error);
                        }
                    });
                });
                dialog_buttons(ui, |ui| {
                    if win32::button_sized(ui, true, "Apply", 75.0).clicked() { apply = true; }
                    if win32::button_sized(ui, true, "Cancel", 75.0).clicked() { close = true; }
                    if win32::button_sized(ui, true, "OK", 75.0).clicked() { apply = true; close = true; }
                });
            });
            if window_ctx.input(|input| input.viewport().close_requested()) { close = true; }
        });
        if apply {
            let last_local_dir = self.settings.last_local_dir.clone();
            let hide_hidden_items = self.settings.hide_hidden_items;
            let result = self.settings_draft.parse().map(|settings| AppSettings { last_local_dir, hide_hidden_items, ..settings }).and_then(|settings| {
                if settings.logging.enabled {
                    fs::create_dir_all(&settings.logging.directory)
                        .map_err(|error| format!("Cannot create log directory {}: {error}", settings.logging.directory.display()))?;
                }
                crate::settings::save(&settings).map_err(|error| format!("Could not save settings: {error}"))?;
                Ok(settings)
            });
            match result {
                Ok(settings) => {
                    if settings.theme != self.settings.theme {
                        win32::apply(ctx, settings.theme);
                    }
                    crate::units::set(settings.units);
                    if settings.network.parallel_files != self.settings.network.parallel_files {
                        for session in &mut self.sessions {
                            session.set_concurrency(settings.network.file_parallelism());
                        }
                    }
                    self.logger.set_settings(settings.logging.clone());
                    self.settings = settings;
                    self.settings_error.clear();
                    self.session_mut().status = "Settings applied".into();
                }
                Err(error) => {
                    self.settings_error = error;
                    close = false;
                }
            }
        }
        if close { self.settings_open = false; }
    }
}

impl eframe::App for SftpApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_sessions();
        self.poll_ops();
        self.poll_password_lookup();
        self.poll_credentials();
        let show_hidden = !self.settings.hide_hidden_items;
        for session in &mut self.sessions {
            session.show_hidden = show_hidden;
            session.sample_speeds();
            session.poll_transfer_checks();
            session.update_searches();
        }
        // Remember the folder being browsed, so the next run opens there.
        let browsing = self.session().path.clone();
        if self.settings.last_local_dir.as_ref() != Some(&browsing) {
            self.settings.last_local_dir = Some(browsing);
            let _ = crate::settings::save(&self.settings);
        }

        let connected = self.session().is_connected();
        let can_close = self.can_close_active();
        let can_download = connected && !self.session().remote_selected.is_empty();
        let can_upload = self.session().can_upload();
        egui::TopBottomPanel::top("toolbar")
            .frame(win32::panel_frame(3))
            .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 1.0;
                // Connect button with an attached menu of saved profiles.
                let mut quick = None;
                ui.scope(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    if win32::icon_button(ui, true, win32::Icon::Connect, "Connect… (opens a new session tab)").clicked() {
                        self.dialog = Some(Dialog::Profiles);
                    }
                    let menu_id = ui.id().with("quick_connect");
                    let open = egui::Popup::is_id_open(ui.ctx(), menu_id);
                    let arrow = win32::dropdown_arrow(ui, true, open, "Connect to a saved profile");
                    egui::Popup::menu(&arrow).id(menu_id).show(|ui| {
                        win32::menu_item_style(ui.style_mut());
                        ui.set_min_width(180.0);
                        if self.saved_profiles.is_empty() {
                            ui.add_enabled(false, egui::Button::new("No saved profiles"));
                        }
                        for (index, profile) in self.saved_profiles.iter().enumerate() {
                            let label = format!("{}  ({}@{})", profile.name, profile.username, profile.host);
                            if ui.button(label).clicked() {
                                quick = Some(index);
                            }
                        }
                        ui.separator();
                        if ui.button("Manage profiles…").clicked() {
                            self.dialog = Some(Dialog::Profiles);
                        }
                    });
                });
                if let Some(index) = quick { self.quick_connect(index); }
                if win32::icon_button(ui, can_close, win32::Icon::Disconnect, "Disconnect and close this session").clicked() { self.disconnect_active(); }
                win32::toolbar_separator(ui);
                if win32::icon_button(ui, can_upload, win32::Icon::Upload, "Upload selected local items").clicked() { self.upload_selected(); }
                if win32::icon_button(ui, can_download, win32::Icon::Download, "Download selected remote files").clicked() { self.download_selected(); }
                win32::toolbar_separator(ui);
                let showing = !self.settings.hide_hidden_items;
                let tip = if showing {
                    "Hidden items are shown (dot files; on Windows also files marked hidden). Click to hide them."
                } else {
                    "Hidden items are hidden (dot files; on Windows also files marked hidden). Click to show them."
                };
                if win32::icon_toggle(ui, showing, win32::Icon::HiddenItems, tip).clicked() {
                    self.settings.hide_hidden_items = showing;
                    if let Err(error) = crate::settings::save(&self.settings) {
                        self.session_mut().status = format!("Could not save settings: {error}");
                    }
                }
                win32::toolbar_separator(ui);
                if win32::icon_button(ui, true, win32::Icon::Settings, "Settings").clicked() { self.open_settings(); }
            });
        });
        egui::TopBottomPanel::top("sessions")
            .frame(win32::panel_frame(0).inner_margin(egui::Margin { left: 4, right: 4, top: 3, bottom: 0 }))
            .show(ctx, |ui| {
            let tabs: Vec<(u64, String)> = self.sessions.iter().map(|session| (session.id, session.title())).collect();
            let mut active_id = self.session().id;
            if win32::tab_strip(ui, &mut active_id, &tabs) {
                if let Some(index) = self.session_index(active_id) { self.active = index; }
            }
        });
        egui::TopBottomPanel::bottom("status")
            .exact_height(22.0)
            .frame(win32::panel_frame(0).inner_margin(egui::Margin::symmetric(2, 2)))
            .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                let active = self.sessions.iter()
                    .map(|session| session.transfers.iter().filter(|item| item.is_pending() && !item.folder).count())
                    .sum::<usize>();
                let connection = match &self.session().connection {
                    Some(connection) => format!("Connected to {}:{}", connection.host, connection.port),
                    None => "Not connected".into(),
                };
                // Totals over every session, not just the visible one.
                let speed = |state: &str| -> f64 { self.sessions.iter().map(|session| session.speed(state)).sum() };
                let speeds = format!("↓ {}   ↑ {}", speed_text(speed("Downloading")), speed_text(speed("Uploading")));
                let turbo = turbo_badge(self.session());
                let turbo_width = if turbo.is_some() { TURBO_PANE_WIDTH + ui.spacing().item_spacing.x } else { 0.0 };
                let fixed = 200.0 + turbo_width + 180.0 + 130.0 + VERSION_PANE_WIDTH + 4.0 * ui.spacing().item_spacing.x;
                let message_width = (ui.available_width() - fixed).max(120.0);
                win32::status_pane(ui, message_width, self.session().status.as_str());
                win32::status_pane(ui, 200.0, connection);
                match turbo {
                    Some(true) => {
                        win32::status_badge(ui, TURBO_PANE_WIDTH, "Turbo Active", TURBO_ACTIVE)
                            .on_hover_text("Downloads from this server use rsftp-turbo over UDP.");
                    }
                    Some(false) => {
                        win32::status_badge(ui, TURBO_PANE_WIDTH, "Turbo Unavailable", TURBO_UNAVAILABLE)
                            .on_hover_text("Downloads from this server use SFTP. The Log tab says why rsftp-turbo is unavailable.");
                    }
                    None => {}
                }
                win32::status_pane(ui, 180.0, speeds);
                win32::status_pane(ui, 130.0, format!("{active} active transfer{}", if active == 1 { "" } else { "s" }))
                    .on_hover_text("Across all sessions");
                win32::status_pane(ui, VERSION_PANE_WIDTH, version_text())
                    .on_hover_text(format!("Rust SFTP Client {}", version_text()));
            });
        });
        egui::TopBottomPanel::bottom("queue")
            .resizable(true)
            .default_height(queue_panel_height(&ctx.style()))
            .min_height(100.0)
            .max_height(600.0)
            .frame(win32::panel_frame(QUEUE_PANEL_MARGIN))
            .show(ctx, |ui| {
            let a = self.active;
            let count = |tab: QueueTab| self.sessions[a].transfers.iter().filter(|item| item.operation_id.is_none() && item.tab() == tab).count();
            let tabs = [
                (QueueTab::Pending, format!("Pending ({})", count(QueueTab::Pending))),
                (QueueTab::Complete, format!("Complete ({})", count(QueueTab::Complete))),
                (QueueTab::Failed, format!("Failed ({})", count(QueueTab::Failed))),
                (QueueTab::Log, "Log".to_owned()),
                (QueueTab::Statistics, "Statistics".to_owned()),
                (QueueTab::Terminal, "SSH Terminal".to_owned()),
            ];
            win32::tab_strip(ui, &mut self.sessions[a].queue_tab, &tabs);
            // Each tab gets exactly the space left in the panel, so switching
            // tabs never resizes the panel (it would otherwise grow or shrink
            // to whatever the tab's contents need).
            let page = ui.available_rect_before_wrap();
            let mut page_ui = ui.new_child(egui::UiBuilder::new().max_rect(page).layout(egui::Layout::top_down(egui::Align::Min)));
            page_ui.set_clip_rect(page.intersect(ui.clip_rect()));
            match self.sessions[a].queue_tab {
                QueueTab::Log => self.log_tab(&mut page_ui),
                QueueTab::Statistics => self.statistics_tab(&mut page_ui),
                QueueTab::Terminal => self.terminal_tab(&mut page_ui),
                tab => self.transfer_list_tab(&mut page_ui, tab),
            }
            ui.advance_cursor_after_rect(page);
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.columns(2, |columns| {
                columns[0].set_min_width(300.0);
                self.local_pane(&mut columns[0]);
                self.remote_pane(&mut columns[1]);
            });
        });
        self.dialog_window(ctx);
        self.settings_window(ctx);
        self.hash_windows(ctx);
        self.conflict_window(ctx);
        if self.ops_pending > 0 || self.hash_jobs.iter().any(|job| job.result.is_none()) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        if self.sessions.iter().any(Session::is_busy) || self.password_lookup.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        if self.session().queue_tab == QueueTab::Statistics {
            // Keep the graph scrolling smoothly (about 30 frames per second) while it is visible.
            ctx.request_repaint_after(std::time::Duration::from_millis(33));
        }
    }
}

/// Status-bar rsftp-turbo badge: width and background colours.
const TURBO_PANE_WIDTH: f32 = 120.0;
const TURBO_ACTIVE: egui::Color32 = egui::Color32::from_rgb(0, 128, 0);
const TURBO_UNAVAILABLE: egui::Color32 = egui::Color32::from_rgb(170, 0, 0);

/// Rows in the statistics table and the gap between them.
const STATS_ROWS: usize = 10;
const STATS_ROW_GAP: f32 = 3.0;
/// Inner margin of the transfer queue panel.
const QUEUE_PANEL_MARGIN: i8 = 6;

/// Height of the transfer queue panel that shows the whole statistics tab
/// without growing: tab strip, timespan row (each followed by a 2 px space)
/// and the table, whose rows are `interact_size.y` tall (the grid default).
fn queue_panel_height(style: &egui::Style) -> f32 {
    let row = style.spacing.interact_size.y;
    let gap = style.spacing.item_spacing.y;
    let rows = STATS_ROWS as f32;
    let table = rows * row + (rows - 1.0) * STATS_ROW_GAP;
    2.0 * f32::from(QUEUE_PANEL_MARGIN) + (row + gap + 2.0) * 2.0 + table
}

/// Win32 dialog button row: right-aligned, pinned to the bottom of the dialog.
/// Add buttons right-to-left (the default/cancel button first).
fn dialog_buttons(ui: &mut egui::Ui, add_buttons: impl FnOnce(&mut egui::Ui)) {
    ui.with_layout(egui::Layout::bottom_up(egui::Align::Max), |ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            add_buttons(ui);
        });
    });
}

fn row_context_menu(
    ui: &mut egui::Ui,
    dir: bool,
    transfer_label: &str,
    transfer_enabled: bool,
    single: bool,
    hashable: bool,
) -> Option<RowAction> {
    win32::menu_item_style(ui.style_mut());
    let mut action = None;
    let mut item = |ui: &mut egui::Ui, enabled: bool, label: &str, value: RowAction| {
        if ui.add_enabled(enabled, egui::Button::new(label)).clicked() {
            action = Some(value);
            ui.close();
        }
    };
    if dir { item(ui, true, "Open", RowAction::Open); }
    item(ui, transfer_enabled, transfer_label, RowAction::Transfer);
    if hashable {
        ui.separator();
        for algorithm in HashAlgorithm::ALL {
            item(ui, !dir && single, &format!("Calculate {}", algorithm.label()), RowAction::Hash(algorithm));
        }
    }
    ui.separator();
    item(ui, single, "Rename", RowAction::Rename);
    item(ui, true, "Delete", RowAction::Delete);
    ui.separator();
    item(ui, true, "New folder", RowAction::NewFolder);
    action
}

/// Right-click menu and click target for the empty space below a file list.
/// Returns true if "New folder" was chosen; a click clears `clear_selection`.
fn list_background(ui: &mut egui::Ui, clear_selection: &mut dyn FnMut()) -> bool {
    let height = ui.available_height().max(ROW_HEIGHT);
    let (_, response) = ui.allocate_exact_size(egui::vec2(ui.available_width(), height), egui::Sense::click());
    if response.clicked() { clear_selection(); }
    let mut new_folder = false;
    response.context_menu(|ui| {
        win32::menu_item_style(ui.style_mut());
        if ui.button("New folder").clicked() {
            new_folder = true;
            ui.close();
        }
    });
    new_folder
}

/// Whether `name` can name a file or folder (local names follow Windows' rules on Windows).
fn valid_file_name(name: &str, local: bool) -> bool {
    let invalid: &[char] = if local && cfg!(windows) { &['/', '\\', ':', '*', '?', '"', '<', '>', '|'] } else { &['/'] };
    !name.is_empty() && name != "." && name != ".." && !name.contains(invalid)
}

fn delete_message(target: &FileTarget) -> String {
    let items = target.items();
    let location = if target.is_remote() { " from the server" } else { "" };
    match items.as_slice() {
        [(name, true)] => format!("Are you sure you want to permanently delete the folder \"{name}\" and all of its contents{location}?"),
        [(name, false)] => format!("Are you sure you want to permanently delete \"{name}\"{location}?"),
        _ => format!("Are you sure you want to permanently delete these {} items{location}?", items.len()),
    }
}

const VERSION_PANE_WIDTH: f32 = 110.0;

/// "v0.2.0", plus the CI build number when built by the release workflow
/// (matching release tags such as v0.2.0-build.42).
fn version_text() -> String {
    let version = env!("CARGO_PKG_VERSION");
    match option_env!("RSFTP_BUILD_NUMBER").filter(|build| !build.is_empty()) {
        Some(build) => format!("v{version} (build {build})"),
        None => format!("v{version}"),
    }
}

/// rsftp-turbo badge for the status bar: Some(true) "Turbo Active",
/// Some(false) "Turbo Unavailable" (the reason is in the session log), None
/// to hide it (turned off, not connected, or not known yet).
fn turbo_badge(session: &Session) -> Option<bool> {
    match session.connection.as_ref()?.turbo_info().state {
        TurboState::Ready | TurboState::Active => Some(true),
        TurboState::Unavailable(_) => Some(false),
        TurboState::Disabled | TurboState::Untested | TurboState::Testing => None,
    }
}

/// A speed in MiB/s, written in the chosen units.
fn speed_text(mib_per_second: f64) -> String {
    crate::units::speed_mib(mib_per_second)
}

const ROW_HEIGHT: f32 = 18.0;
const FOOTER_HEIGHT: f32 = 20.0;
const SIZE_WIDTH: f32 = 80.0;
const MODIFIED_WIDTH: f32 = 150.0;
const TYPE_WIDTH: f32 = 80.0;

/// Draws the file list column headers and returns the width of the Name column.
const HEADER_HEIGHT: f32 = 19.0;

/// Scroll area of a file list: vertical only, always shown. The Name column
/// takes whatever width the fixed columns leave, so nothing scrolls sideways.
fn file_list_scroll(id: impl std::hash::Hash) -> egui::ScrollArea {
    egui::ScrollArea::vertical()
        .id_salt(id)
        .auto_shrink([false, false])
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
}

/// Reserves the column header row of a file list and returns the Name column
/// width with it. The header is painted afterwards by [`paint_list_header`],
/// over the rows, so it stays put while they scroll.
fn reserve_list_header(ui: &mut egui::Ui) -> (f32, egui::Rect) {
    let name_width = (ui.available_width() - SIZE_WIDTH - MODIFIED_WIDTH - TYPE_WIDTH - ui.spacing().scroll.bar_width).max(100.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), HEADER_HEIGHT), egui::Sense::hover());
    (name_width, rect)
}

/// Paints the sortable column headers into `rect`; returns the column clicked.
fn paint_list_header(ui: &mut egui::Ui, rect: egui::Rect, name_width: f32, order: SortOrder) -> Option<SortColumn> {
    let mut header = ui.new_child(egui::UiBuilder::new().max_rect(rect).layout(egui::Layout::left_to_right(egui::Align::Min)));
    header.set_clip_rect(rect.intersect(ui.clip_rect()));
    header.spacing_mut().item_spacing.x = 0.0;
    let mut clicked = None;
    for (column, width, label) in [
        (SortColumn::Name, name_width, "Name"),
        (SortColumn::Size, SIZE_WIDTH, "Size"),
        (SortColumn::Modified, MODIFIED_WIDTH, "Modified (UTC)"),
        (SortColumn::Type, TYPE_WIDTH, "Type"),
    ] {
        let sorted = (order.column == column).then_some(order.ascending);
        if win32::header_button(&mut header, width, HEADER_HEIGHT, label, sorted).clicked() {
            clicked = Some(column);
        }
    }
    let rest = header.available_width();
    if rest > 0.0 { win32::header_cell(&mut header, rest, HEADER_HEIGHT, ""); }
    clicked
}

/// Room left next to a filter box for its "Recursive" check box.
const RECURSIVE_WIDTH: f32 = 82.0;

const RECURSIVE_TIP: &str = "Search every folder below this one for names containing the filter text, \
instead of filtering only this folder. Results show their folder relative to this one; double-click a folder to \
open it. Symbolic links are not followed, and hidden folders are searched only while hidden items are shown. \
At most 5000 results are listed.";

/// Footer of a file pane: selection and item counts, or search progress.
fn list_footer(shown: usize, selected: usize, searching: bool, search: Option<(bool, bool)>) -> String {
    if !searching {
        return format!("{selected} selected, {shown} object(s)");
    }
    let state = match search {
        None => " · waiting for typing to pause…",
        Some((false, _)) => " · searching…",
        Some((true, true)) => " · stopped at the 5000-result limit",
        Some((true, false)) => "",
    };
    format!("{selected} selected, {shown} found in subfolders{state}")
}

/// Ctrl (Command on macOS) and Shift state of the click that produced `response`.
fn click_modifiers(response: &egui::Response) -> (bool, bool) {
    response.ctx.input(|input| (input.modifiers.ctrl || input.modifiers.command, input.modifiers.shift))
}

const GRAPH_DOWN: egui::Color32 = egui::Color32::from_rgb(40, 100, 210);
const GRAPH_UP: egui::Color32 = egui::Color32::from_rgb(0, 140, 60);

/// Line graph of download and upload speed over the last `span`, newest at the
/// right, with dotted lines at the (active-time) average download and upload speed.
fn paint_speed_graph(
    ui: &egui::Ui,
    rect: egui::Rect,
    samples: &[SpeedSample],
    span: Duration,
    now: Instant,
    (average_down, average_up): (Option<f64>, Option<f64>),
) {
    let painter = ui.painter().with_clip_rect(rect);
    painter.rect_filled(rect, 0.0, win32::window());
    win32::sunken(&painter, rect);
    let font = egui::TextStyle::Small.resolve(ui.style());
    let plot = egui::Rect::from_min_max(rect.min + egui::vec2(62.0, 8.0), rect.max - egui::vec2(10.0, 18.0));
    if plot.width() < 20.0 || plot.height() < 20.0 {
        return;
    }
    let peak = samples.iter().map(|sample| sample.down.max(sample.up)).fold(0.0_f64, f64::max);
    // The axis ends on a round number in the units shown.
    let y_max = crate::units::nice_speed_ceiling_mib(peak.max(0.5));
    let x_of = |at: Instant| plot.right() - now.saturating_duration_since(at).as_secs_f32() / span.as_secs_f32() * plot.width();
    let y_of = |value: f64| plot.bottom() - (value / y_max).clamp(0.0, 1.0) as f32 * plot.height();

    // Grid and axis labels.
    for step in 0..=4 {
        let fraction = step as f32 / 4.0;
        let y = plot.bottom() - fraction * plot.height();
        painter.line_segment([egui::pos2(plot.left(), y), egui::pos2(plot.right(), y)], egui::Stroke::new(1.0, win32::grid()));
        painter.text(egui::pos2(plot.left() - 4.0, y), egui::Align2::RIGHT_CENTER, speed_text(y_max * f64::from(fraction)), font.clone(), win32::gray_text());
        let x = plot.left() + fraction * plot.width();
        painter.line_segment([egui::pos2(x, plot.top()), egui::pos2(x, plot.bottom())], egui::Stroke::new(1.0, win32::grid()));
        let ago = span.mul_f32(1.0 - fraction);
        let label = if step == 4 { "now".to_owned() } else { format!("-{}", short_duration(ago)) };
        let anchor = if step == 0 { egui::Align2::LEFT_TOP } else if step == 4 { egui::Align2::RIGHT_TOP } else { egui::Align2::CENTER_TOP };
        painter.text(egui::pos2(x, plot.bottom() + 3.0), anchor, label, font.clone(), win32::gray_text());
    }
    painter.rect_stroke(plot, 0.0, egui::Stroke::new(1.0, win32::shadow()), egui::StrokeKind::Outside);

    // Series. Samples stop while the app is idle; a gap wider than a few
    // sample intervals is drawn as zero so the line does not bridge it.
    let series = |pick: fn(&SpeedSample) -> f64| -> Vec<egui::Pos2> {
        let mut points = Vec::with_capacity(samples.len() + 4);
        let mut previous: Option<&SpeedSample> = None;
        for (index, sample) in samples.iter().enumerate() {
            // Moving average over about one second, so the 250 ms samples do not jitter.
            let neighbours = &samples[index.saturating_sub(2)..(index + 3).min(samples.len())];
            let smoothed = neighbours.iter().map(pick).sum::<f64>() / neighbours.len() as f64;
            if let Some(last) = previous {
                if sample.at.saturating_duration_since(last.at) > Duration::from_millis(2500) {
                    points.push(egui::pos2(x_of(last.at + Duration::from_secs(1)), y_of(0.0)));
                    let before = sample.at.checked_sub(Duration::from_secs(1)).unwrap_or(sample.at);
                    points.push(egui::pos2(x_of(before), y_of(0.0)));
                }
            }
            points.push(egui::pos2(x_of(sample.at), y_of(smoothed)));
            previous = Some(sample);
        }
        if let Some(last) = previous {
            if now.saturating_duration_since(last.at) > Duration::from_millis(2500) {
                points.push(egui::pos2(x_of(last.at + Duration::from_secs(1)), y_of(0.0)));
                points.push(egui::pos2(plot.right(), y_of(0.0)));
            }
        }
        points
    };
    let picks: [(fn(&SpeedSample) -> f64, egui::Color32); 2] = [(|sample| sample.up, GRAPH_UP), (|sample| sample.down, GRAPH_DOWN)];
    for (pick, color) in picks {
        let points = series(pick);
        if points.len() >= 2 {
            painter.add(egui::Shape::line(points, egui::Stroke::new(1.5, color)));
        } else if let Some(point) = points.first() {
            painter.circle_filled(*point, 2.0, color);
        }
    }

    // Averages: dotted lines across the plot, labelled at the left.
    let (average_down_color, average_up_color) = if ui.visuals().dark_mode {
        (egui::Color32::from_rgb(255, 95, 95), egui::Color32::from_rgb(240, 100, 240))
    } else {
        (egui::Color32::from_rgb(220, 0, 0), egui::Color32::from_rgb(200, 0, 200))
    };
    let mut label_slots: Vec<f32> = Vec::new();
    for (average, color, label) in [(average_down, average_down_color, "avg download"), (average_up, average_up_color, "avg upload")] {
        let Some(average) = average else { continue };
        let y = y_of(average).round() + 0.5;
        painter.extend(egui::Shape::dotted_line(&[egui::pos2(plot.left(), y), egui::pos2(plot.right(), y)], color, 4.0, 0.9));
        // Label above the line; below it if the other label is already there.
        let mut label_y = y - 2.0;
        if label_slots.iter().any(|other| (other - label_y).abs() < 12.0) {
            label_y = y + 13.0;
        }
        label_slots.push(label_y);
        painter.text(egui::pos2(plot.left() + 4.0, label_y), egui::Align2::LEFT_BOTTOM, format!("{label} {}", speed_text(average)), font.clone(), color);
    }

    // Legend.
    let mut x = plot.right() - 6.0;
    let entries = [
        ("Avg upload", average_up_color, true),
        ("Avg download", average_down_color, true),
        ("Upload", GRAPH_UP, false),
        ("Download", GRAPH_DOWN, false),
    ];
    for (label, color, dotted) in entries {
        let galley = painter.layout_no_wrap(label.to_owned(), font.clone(), win32::text_color());
        x -= galley.size().x;
        painter.galley(egui::pos2(x, plot.top() + 4.0), galley, win32::text_color());
        x -= 14.0;
        let swatch = egui::Rect::from_min_size(egui::pos2(x, plot.top() + 7.0), egui::vec2(10.0, 8.0));
        if dotted {
            let y = swatch.center().y;
            painter.extend(egui::Shape::dotted_line(&[egui::pos2(swatch.left(), y), egui::pos2(swatch.right(), y)], color, 3.0, 0.9));
        } else {
            painter.rect_filled(swatch, 0.0, color);
        }
        x -= 14.0;
    }
}


/// "45 s" or "5 min".
fn short_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds % 60 == 0 { format!("{} min", seconds / 60) } else { format!("{seconds} s") }
}

/// One file-list row: icon and name, size, modification time and type.
/// The whole row is the click and drag target, and a selected row is
/// highlighted across every column, as in Explorer's details view.
fn file_row(ui: &mut egui::Ui, name_width: f32, name: &str, dir: bool, size: u64, modified: &str, selected: bool) -> egui::Response {
    let width = name_width + SIZE_WIDTH + MODIFIED_WIDTH + TYPE_WIDTH;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, ROW_HEIGHT), egui::Sense::click_and_drag());
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let painter = ui.painter().with_clip_rect(rect.intersect(ui.clip_rect()));
    if selected {
        painter.rect_filled(rect, 0.0, win32::selection());
    }
    let color = if selected { win32::selection_text() } else { win32::text_color() };
    let font = egui::TextStyle::Body.resolve(ui.style());

    let icon = egui::Rect::from_min_size(rect.left_center() + egui::vec2(4.0, -6.0), egui::vec2(14.0, 12.0));
    paint_file_icon(&painter, icon, dir);
    let name_rect = egui::Rect::from_min_max(egui::pos2(icon.right() + 6.0, rect.top()), egui::pos2(rect.left() + name_width - 4.0, rect.bottom()));
    painter.with_clip_rect(name_rect.intersect(painter.clip_rect()))
        .text(name_rect.left_center(), egui::Align2::LEFT_CENTER, name, font.clone(), color);

    let mut left = rect.left() + name_width;
    let modified = modified.replace('T', " ").trim_end_matches('Z').to_owned();
    let size = if dir { String::new() } else { size_text(size) };
    for (text, width, right_align) in [
        (size.as_str(), SIZE_WIDTH, true),
        (modified.as_str(), MODIFIED_WIDTH, false),
        (if dir { "File folder" } else { "File" }, TYPE_WIDTH, false),
    ] {
        let cell = egui::Rect::from_min_size(egui::pos2(left, rect.top()), egui::vec2(width, ROW_HEIGHT));
        let clipped = painter.with_clip_rect(cell.shrink2(egui::vec2(4.0, 0.0)).intersect(painter.clip_rect()));
        if right_align {
            clipped.text(cell.right_center() - egui::vec2(6.0, 0.0), egui::Align2::RIGHT_CENTER, text, font.clone(), color);
        } else {
            clipped.text(cell.left_center() + egui::vec2(5.0, 0.0), egui::Align2::LEFT_CENTER, text, font.clone(), color);
        }
        left += width;
    }
    response
}

/// Small Explorer-style icon: a manila folder or a dog-eared page.
/// Icons keep their own colours in both themes, like Explorer's.
fn paint_file_icon(painter: &egui::Painter, rect: egui::Rect, dir: bool) {
    let outline = egui::Stroke::new(1.0, if dir { egui::Color32::from_rgb(128, 96, 0) } else { egui::Color32::from_rgb(128, 128, 128) });
    if dir {
        let tab = egui::Rect::from_min_size(rect.min, egui::vec2(6.0, 3.0));
        let body = egui::Rect::from_min_max(rect.min + egui::vec2(0.0, 2.0), rect.max);
        painter.rect(tab, 0.0, egui::Color32::from_rgb(240, 200, 80), outline, egui::StrokeKind::Inside);
        painter.rect(body, 0.0, egui::Color32::from_rgb(255, 222, 110), outline, egui::StrokeKind::Inside);
    } else {
        let page = egui::Rect::from_center_size(rect.center(), egui::vec2(10.0, 12.0));
        painter.rect(page, 0.0, egui::Color32::WHITE, outline, egui::StrokeKind::Inside);
        let corner = egui::Rect::from_min_max(egui::pos2(page.right() - 4.0, page.top()), egui::pos2(page.right(), page.top() + 4.0));
        painter.rect(corner, 0.0, egui::Color32::from_rgb(223, 223, 223), outline, egui::StrokeKind::Inside);
    }
}

/// Background and text colours of the conflict listing.
struct ConflictColors {
    /// Cells of the file that will be overwritten.
    replaced: egui::Color32,
    replaced_text: egui::Color32,
    /// Cells of the file that replaces it.
    new: egui::Color32,
    new_text: egui::Color32,
}

impl ConflictColors {
    fn new(dark: bool) -> Self {
        if dark {
            Self {
                replaced: egui::Color32::from_rgb(90, 36, 36),
                replaced_text: egui::Color32::from_rgb(240, 120, 120),
                new: egui::Color32::from_rgb(30, 74, 40),
                new_text: egui::Color32::from_rgb(120, 210, 130),
            }
        } else {
            Self {
                replaced: egui::Color32::from_rgb(255, 220, 220),
                replaced_text: egui::Color32::from_rgb(180, 0, 0),
                new: egui::Color32::from_rgb(214, 245, 214),
                new_text: egui::Color32::from_rgb(0, 120, 0),
            }
        }
    }
}

/// One cell of the conflict listing, optionally filled.
fn conflict_cell(ui: &mut egui::Ui, width: f32, height: f32, text: &str, fill: Option<egui::Color32>, color: egui::Color32, right_align: bool) {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    if !ui.is_rect_visible(rect) { return; }
    if let Some(fill) = fill {
        ui.painter().rect_filled(rect.shrink2(egui::vec2(0.0, 1.0)), 0.0, fill);
    }
    let painter = ui.painter().with_clip_rect(rect.shrink2(egui::vec2(4.0, 0.0)).intersect(ui.clip_rect()));
    let (anchor, pos) = if right_align {
        (egui::Align2::RIGHT_CENTER, rect.right_center() - egui::vec2(6.0, 0.0))
    } else {
        (egui::Align2::LEFT_CENTER, rect.left_center() + egui::vec2(5.0, 0.0))
    };
    let galley = painter.layout_no_wrap(text.to_owned(), egui::TextStyle::Body.resolve(ui.style()), color);
    if galley.size().x > rect.width() - 10.0 {
        response.on_hover_text(text);
    }
    painter.text(pos, anchor, text, egui::TextStyle::Body.resolve(ui.style()), color);
}

/// Name of a conflicting file: its path below the folder the transfer was
/// started from (so it includes the transferred folder's name).
fn conflict_name(prepared: &crate::session::PreparedJob, local: &std::path::Path) -> String {
    let root = match &prepared.job {
        crate::session::Job::DownloadFile { local, .. }
        | crate::session::Job::DownloadPath { local, .. }
        | crate::session::Job::UploadPath { local, .. } => local,
    };
    let base = root.parent().unwrap_or(root);
    local.strip_prefix(base).unwrap_or(local).display().to_string()
}

/// A Unix modification time as the file panes show it.
fn mtime_text(mtime: Option<u64>) -> String {
    match mtime {
        Some(seconds) => format_unix_utc(seconds as i64).replace('T', " ").trim_end_matches('Z').to_owned(),
        None => "—".into(),
    }
}

/// A queue context-menu action that applies to the whole tab.
enum TabAction {
    StopAll,
    RetryAll,
    Clear,
}

/// Width of the expand/collapse column of the transfer queue, and the
/// indentation of a folder's files.
const EXPANDER_WIDTH: f32 = 16.0;

/// Rows the queue tab `tab` shows, as (index into `transfers`, depth):
/// each transfer, and below an expanded folder transfer its files. A
/// folder's files are listed with it, whatever their own state.
fn queue_rows(transfers: &[crate::session::TransferItem], tab: QueueTab) -> Vec<(usize, u8)> {
    let expanded: HashSet<usize> = transfers.iter()
        .filter(|item| item.folder && item.expanded && item.operation_id.is_none() && item.tab() == tab)
        .map(|item| item.id)
        .collect();
    let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
    if !expanded.is_empty() {
        for (index, item) in transfers.iter().enumerate() {
            if let Some(operation) = item.operation_id.filter(|operation| expanded.contains(operation)) {
                children.entry(operation).or_default().push(index);
            }
        }
    }
    let mut rows = Vec::new();
    for (index, item) in transfers.iter().enumerate() {
        if item.operation_id.is_some() || item.tab() != tab {
            continue;
        }
        rows.push((index, 0));
        if let Some(files) = children.get(&item.id) {
            rows.extend(files.iter().map(|&file| (file, 1)));
        }
    }
    rows
}

/// Win32 tree-view style expander: a triangle pointing right (collapsed) or down.
fn paint_expander(painter: &egui::Painter, rect: egui::Rect, expanded: bool) {
    let c = rect.center();
    let points = if expanded {
        vec![c + egui::vec2(-4.0, -2.0), c + egui::vec2(4.0, -2.0), c + egui::vec2(0.0, 3.0)]
    } else {
        vec![c + egui::vec2(-2.0, -4.0), c + egui::vec2(3.0, 0.0), c + egui::vec2(-2.0, 4.0)]
    };
    painter.add(egui::Shape::convex_polygon(points, win32::text_color(), egui::Stroke::NONE));
}

fn file_text_cell(ui: &mut egui::Ui, width: f32, height: f32, text: &str, right_align: bool) {
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(width, height),
        egui::Sense::hover(),
    );
    if !ui.is_rect_visible(rect) { return; }
    let painter = ui.painter().with_clip_rect(rect.shrink2(egui::vec2(4.0, 0.0)).intersect(ui.clip_rect()));
    let (anchor, pos) = if right_align {
        (egui::Align2::RIGHT_CENTER, rect.right_center() - egui::vec2(6.0, 0.0))
    } else {
        (egui::Align2::LEFT_CENTER, rect.left_center() + egui::vec2(5.0, 0.0))
    };
    painter.text(pos, anchor, text, egui::TextStyle::Body.resolve(ui.style()), win32::text_color());
}

const PIECE_FILL: egui::Color32 = egui::Color32::from_rgb(40, 100, 210);

/// A byte range of a transfer and how much of it (from its start) is done.
struct Piece {
    start: u64,
    end: u64,
    done: u64,
    failed: bool,
}

/// qBittorrent-style piece bar: one continuous bar where every pixel column is
/// shaded by how much of the bytes it covers have been transferred.
fn paint_piece_bar(painter: &egui::Painter, rect: egui::Rect, total: u64, pieces: &[Piece], fill: egui::Color32) {
    if total == 0 || rect.width() < 1.0 { return; }
    let columns = (rect.width() * painter.pixels_per_point()).floor().max(1.0) as usize;
    let column_width = rect.width() / columns as f32;
    let bytes_per_column = total as f64 / columns as f64;
    let paint_run = |from: usize, to: usize, color: egui::Color32| {
        if color == win32::window() { return; }
        let x0 = rect.left() + from as f32 * column_width;
        let x1 = rect.left() + to as f32 * column_width;
        painter.rect_filled(egui::Rect::from_min_max(egui::pos2(x0, rect.top()), egui::pos2(x1, rect.bottom())), 0.0, color);
    };
    let mut run: Option<(usize, egui::Color32)> = None;
    for column in 0..columns {
        let c0 = column as f64 * bytes_per_column;
        let c1 = c0 + bytes_per_column;
        let (mut done, mut failed) = (0.0, 0.0);
        for piece in pieces {
            let (start, end) = (piece.start as f64, piece.end as f64);
            if end <= c0 || start >= c1 { continue; }
            let lo = start.max(c0);
            if piece.failed {
                failed += end.min(c1) - lo;
            } else {
                let hi = ((piece.start + piece.done) as f64).min(end).min(c1);
                if hi > lo { done += hi - lo; }
            }
        }
        let done = (done / bytes_per_column).clamp(0.0, 1.0) as f32;
        let failed = (failed / bytes_per_column).clamp(0.0, 1.0) as f32;
        let color = mix(mix(win32::window(), fill, done), win32::error_red(), failed);
        match run {
            Some((_, run_color)) if run_color == color => {}
            Some((run_start, run_color)) => {
                paint_run(run_start, column, run_color);
                run = Some((column, color));
            }
            None => run = Some((column, color)),
        }
    }
    if let Some((run_start, run_color)) = run { paint_run(run_start, columns, run_color); }
}

fn mix(a: egui::Color32, b: egui::Color32, t: f32) -> egui::Color32 {
    let channel = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    egui::Color32::from_rgb(channel(a.r(), b.r()), channel(a.g(), b.g()), channel(a.b(), b.b()))
}

fn profiles_path() -> Result<PathBuf, String> {
    let home = crate::places::home_dir().ok_or_else(|| "home directory is not set".to_owned())?;
    Ok(home.join(".config/rust-sftp-client/profiles.json"))
}

fn load_profiles() -> Vec<ConnectionProfile> {
    profiles_path().ok().and_then(|path| fs::read(path).ok())
        .and_then(|data| serde_json::from_slice(&data).ok()).unwrap_or_default()
}

fn persist_profiles(profiles: &[ConnectionProfile]) -> Result<(), String> {
    let path = profiles_path()?;
    let parent = path.parent().ok_or_else(|| "Invalid profile storage path".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let data = serde_json::to_vec_pretty(profiles).map_err(|error| error.to_string())?;
    let temp = path.with_extension("json.tmp");
    fs::write(&temp, data).map_err(|error| error.to_string())?;
    fs::rename(&temp, &path).map_err(|error| error.to_string())
}

pub(crate) fn join_remote(parent: &str, name: &str) -> String {
    if parent == "/" { format!("/{name}") }
    else if parent == "." || parent.is_empty() { name.to_owned() }
    else { format!("{}/{name}", parent.trim_end_matches('/')) }
}

fn remote_parent(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" { return "/".into(); }
    if trimmed == "." { return "..".into(); }
    if trimmed == ".." { return "../..".into(); }
    match trimmed.rsplit_once('/') {
        Some(("", _)) => "/".into(),
        Some((parent, _)) if !parent.is_empty() => parent.to_owned(),
        _ => ".".into(),
    }
}

pub(crate) fn format_iso8601(value: SystemTime) -> String {
    let seconds = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(error) => -(error.duration().as_secs() as i64),
    };
    format_unix_utc(seconds)
}

pub(crate) fn format_unix_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        day_seconds / 3600, (day_seconds % 3600) / 60, day_seconds % 60)
}

fn duration_text(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

/// A size, written in the chosen units.
fn size_text(bytes: u64) -> String {
    crate::units::size(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(algorithm: HashAlgorithm, chunks: &[&[u8]]) -> String {
        let mut hasher = Hasher::new(algorithm);
        for chunk in chunks { hasher.update(chunk); }
        hasher.finish()
    }

    #[test]
    fn hashes_match_known_vectors() {
        assert_eq!(digest(HashAlgorithm::Md5, &[b"abc"]), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(digest(HashAlgorithm::Sha1, &[b"abc"]), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            digest(HashAlgorithm::Sha256, &[b"abc"]),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn chunked_input_hashes_like_contiguous_input() {
        for algorithm in HashAlgorithm::ALL {
            assert_eq!(digest(algorithm, &[b"a", b"bc"]), digest(algorithm, &[b"abc"]));
        }
    }

    #[test]
    fn folder_names_are_validated() {
        assert!(valid_file_name("New folder", true));
        assert!(valid_file_name(".config", false));
        for bad in ["", ".", "..", "a/b"] {
            assert!(!valid_file_name(bad, false), "{bad:?}");
            assert!(!valid_file_name(bad, true), "{bad:?}");
        }
        // Characters Windows forbids are only refused for local names there.
        assert!(valid_file_name("a:b", false));
        assert_eq!(valid_file_name("a:b", true), !cfg!(windows));
    }

    #[test]
    fn delete_message_describes_targets() {
        let entry = |name: &str, dir: bool| RemoteEntry {
            name: name.into(), path: format!("/{name}"), dir, size: 0, modified: String::new(), folder: String::new(),
        };
        let one = FileTarget::Remote(vec![entry("a.txt", false)]);
        assert!(delete_message(&one).contains("\"a.txt\" from the server"));
        let folder = FileTarget::Remote(vec![entry("dir", true)]);
        assert!(delete_message(&folder).contains("folder \"dir\" and all of its contents"));
        let many = FileTarget::Remote(vec![entry("a", false), entry("b", true)]);
        assert!(delete_message(&many).contains("these 2 items"));
    }
}
