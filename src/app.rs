use std::{
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
use tokio::io::AsyncReadExt as _;

use crate::connection::{load_trusted_fingerprint, trust_host_key, AuthMethod, ConnectionProfile};
use crate::logging::{default_log_dir, Logger};
use crate::session::{ConnectOutcome, LocalEntry, QueueTab, RemoteEntry, Session};
use crate::settings::AppSettings;
use crate::transfer::TransferSettings;
use crate::places::{self, Drive};
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
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsPage {
    Transfers,
    Segmentation,
    Logging,
}

impl SettingsPage {
    const ALL: [SettingsPage; 3] = [SettingsPage::Transfers, SettingsPage::Segmentation, SettingsPage::Logging];

    fn title(self) -> &'static str {
        match self {
            SettingsPage::Transfers => "Transfers",
            SettingsPage::Segmentation => "Segmented downloads",
            SettingsPage::Logging => "Logging",
        }
    }
}

/// Contents of the settings window, validated on OK/Apply.
#[derive(Default)]
struct SettingsDraft {
    concurrent: String,
    threshold_mib: String,
    segment_mib: String,
    workers: String,
    logging_enabled: bool,
    log_connections: bool,
    log_transfers: bool,
    log_directory: String,
    split_sessions: bool,
}

impl SettingsDraft {
    fn from_settings(settings: &AppSettings) -> Self {
        let transfer = &settings.transfer;
        let logging = &settings.logging;
        Self {
            concurrent: transfer.max_concurrent_transfers.to_string(),
            threshold_mib: (transfer.segmentation_threshold_bytes / MIB).to_string(),
            segment_mib: (transfer.target_segment_size_bytes / MIB).to_string(),
            workers: transfer.max_segments_per_file.to_string(),
            logging_enabled: logging.enabled,
            log_connections: logging.log_connections,
            log_transfers: logging.log_transfers,
            log_directory: logging.directory.display().to_string(),
            split_sessions: logging.split_sessions,
        }
    }

    fn parse(&self) -> Result<AppSettings, String> {
        let transfer = TransferSettings {
            max_concurrent_transfers: parse_setting(&self.concurrent, "Concurrent transfers", 1, 16)? as u32,
            segmentation_threshold_bytes: parse_setting(&self.threshold_mib, "Segmentation threshold", 1, 1024 * 1024)? * MIB,
            target_segment_size_bytes: parse_setting(&self.segment_mib, "Segment size", 1, 4096)? * MIB,
            max_segments_per_file: parse_setting(&self.workers, "Workers per file", 1, 32)? as u32,
        };
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
        Ok(AppSettings { transfer, logging })
    }
}

const MIB: u64 = 1024 * 1024;

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
}

#[derive(Clone, Debug)]
enum DragPayload {
    Local(PathBuf),
    Remote(String),
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
    auth: AuthMethod,
    password: String,
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
    rename_value: String,
    rename_error: String,
    rename_focus: bool,
    op_tx: std_mpsc::Sender<OpResult>,
    op_rx: std_mpsc::Receiver<OpResult>,
    ops_pending: usize,
}

impl SftpApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        win32::apply(&cc.egui_ctx);
        let path = crate::places::home_dir().unwrap_or_else(|| PathBuf::from(if cfg!(windows) { "C:\\" } else { "/" }));
        let settings = crate::settings::load();
        let logger = Arc::new(Logger::new(settings.logging.clone()));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime initialization failed");
        let first_session = Session::new(1, runtime.handle().clone(), logger.clone(), path, &settings.transfer);
        let (op_tx, op_rx) = std_mpsc::channel();
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
            auth: AuthMethod::Password,
            password: String::new(),
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
            op_tx,
            op_rx,
            ops_pending: 0,
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
            &self.settings.transfer,
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
        match self.selected_profile.filter(|&index| index < self.saved_profiles.len()) {
            Some(index) => self.saved_profiles[index] = profile,
            None => {
                self.saved_profiles.push(profile);
                self.selected_profile = Some(self.saved_profiles.len() - 1);
            }
        }
        match persist_profiles(&self.saved_profiles) {
            Ok(()) => self.session_mut().status = format!("Saved connection profile: {}", self.profile_name.trim()),
            Err(error) => self.show_error(format!("Could not save profile: {error}")),
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
        self.password.clear();
    }

    fn delete_profile(&mut self) {
        let Some(index) = self.selected_profile.filter(|&index| index < self.saved_profiles.len()) else { return; };
        let removed = self.saved_profiles.remove(index);
        if let Err(error) = persist_profiles(&self.saved_profiles) {
            self.show_error(format!("Could not save profiles: {error}"));
            return;
        }
        self.session_mut().status = format!("Deleted connection profile: {}", removed.name);
        if self.saved_profiles.is_empty() {
            self.new_profile();
        } else {
            self.apply_profile(index.min(self.saved_profiles.len() - 1));
        }
    }

    fn upload_selected(&mut self) {
        if let Some(path) = self.session().local_selected.clone() {
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

    fn start_remote_hash(&mut self, entry: &RemoteEntry, algorithm: HashAlgorithm) {
        let Some(connection) = self.session().connection.clone() else { return; };
        let (done, cancel, tx) = self.push_hash_job(entry.name.clone(), entry.path.clone(), entry.size, algorithm);
        let path = entry.path.clone();
        self.runtime.spawn(async move {
            let result: Result<String, String> = async {
                let mut file = connection.open_read(&path).await.map_err(|e| e.to_string())?;
                let mut hasher = Hasher::new(algorithm);
                let mut buffer = vec![0_u8; HASH_BUFFER];
                loop {
                    if cancel.load(Ordering::Relaxed) { return Err("Cancelled".into()); }
                    let read = file.read(&mut buffer).await.map_err(|e| e.to_string())?;
                    if read == 0 { break; }
                    hasher.update(&buffer[..read]);
                    done.fetch_add(read as u64, Ordering::Relaxed);
                }
                Ok(hasher.finish())
            }.await;
            let _ = tx.send(result);
        });
    }

    fn begin_delete(&mut self, target: FileTarget) {
        if target.items().is_empty() { return; }
        self.file_target = Some(target);
        self.file_target_session = self.session().id;
        self.dialog = Some(Dialog::ConfirmDelete);
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
        match target {
            FileTarget::Local(entries) => {
                self.sessions[index].local_selected = None;
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
        let invalid_chars: &[char] = if !target.is_remote() && cfg!(windows) {
            &['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        } else {
            &['/']
        };
        if new_name.is_empty() || new_name == "." || new_name == ".." || new_name.contains(invalid_chars) {
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
                    self.rename_error = format!("Could not rename: {error}");
                    return false;
                }
                let session = &mut self.sessions[index];
                let message = format!("Renamed {} to {}", entry.path.display(), destination.display());
                session.log_file_operation("RENAME", &Ok(message));
                session.status = format!("Renamed {} to {new_name}", entry.name);
                session.local_selected = Some(destination);
                session.refresh_local();
            }
            FileTarget::Remote(entries) => {
                let Some(entry) = entries.first().cloned() else { return true; };
                if entry.name == new_name { return true; }
                let session = &self.sessions[index];
                if session.remote_entries.iter().any(|existing| existing.name == new_name) {
                    self.rename_error = format!("\"{new_name}\" already exists.");
                    return false;
                }
                let Some(connection) = session.connection.clone() else { return true; };
                let destination = join_remote(&session.remote_path, &new_name);
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
                Some(ConnectOutcome::Connected) => self.password.clear(),
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
                                painter.rect_filled(rect, 0.0, win32::WINDOW);
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
                            Some(Err(error)) => { ui.colored_label(win32::ERROR_RED, error); }
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

    fn apply_profile(&mut self, index: usize) {
        if let Some(profile) = self.saved_profiles.get(index) {
            self.profile_name = profile.name.clone();
            self.host = profile.host.clone();
            self.port = profile.port.to_string();
            self.username = profile.username.clone();
            self.auth = profile.auth_method;
            self.key_path = profile.private_key_path.clone().unwrap_or_default();
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
        self.sessions[index].start_connect(profile, password, trusted);
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
        session.start_connect(profile, password, Some(fingerprint));
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
            if let DragPayload::Remote(path) = payload.as_ref() {
                self.sessions[a].queue_download(path.clone(), self.settings.transfer);
            }
        }
    }

    fn local_pane_contents(&mut self, ui: &mut egui::Ui) {
        let a = self.active;
        let connected = self.sessions[a].connection.is_some();
        ui.horizontal(|ui| {
            ui.strong("Local site");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.weak(format!("{} items", self.sessions[a].local_entries.len()));
            });
        });
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            if win32::icon_button(ui, self.sessions[a].path.parent().is_some(), win32::Icon::Up, "Up one level").clicked() {
                if let Some(parent) = self.sessions[a].path.parent().map(PathBuf::from) { self.sessions[a].open_local_dir(parent); }
            }
            if win32::icon_button(ui, true, win32::Icon::Refresh, "Refresh").clicked() {
                self.drives = places::list();
                self.sessions[a].refresh_local();
            }
            ui.add_space(6.0);
            ui.label("Filter:");
            win32::text_edit(ui, egui::TextEdit::singleline(&mut self.sessions[a].local_filter).desired_width(f32::INFINITY));
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

        let filter = self.sessions[a].local_filter.to_lowercase();
        let mut rows: Vec<LocalEntry> = self.sessions[a].local_entries.iter()
            .filter(|entry| entry.name.to_lowercase().contains(&filter)).cloned().collect();
        if let Some(parent) = self.sessions[a].path.parent() {
            rows.insert(0, LocalEntry {
                name: "..".into(), path: parent.to_path_buf(), dir: true,
                size: 0, modified: "—".into(),
            });
        }
        let list_height = (ui.available_height() - FOOTER_HEIGHT).max(60.0);
        win32::list_view(ui, list_height, |ui| {
            let name_width = list_header(ui);
            egui::ScrollArea::vertical().id_salt(("local_list", self.sessions[a].id)).auto_shrink([false, false]).show(ui, |ui| {
                for entry in rows {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        let response = file_name_cell(
                            ui,
                            name_width,
                            ROW_HEIGHT,
                            &entry.name,
                            entry.dir,
                            self.sessions[a].local_selected.as_ref() == Some(&entry.path),
                        );
                        if response.dragged() { response.dnd_set_drag_payload(DragPayload::Local(entry.path.clone())); }
                        if response.clicked() || response.secondary_clicked() { self.sessions[a].local_selected = Some(entry.path.clone()); }
                        let mut action = None;
                        if entry.name != ".." {
                            response.context_menu(|ui| {
                                let label = if connected { "Upload to remote" } else { "Upload to remote (not connected)" };
                                action = row_context_menu(ui, entry.dir, label, connected, true);
                            });
                        }
                        match action {
                            Some(RowAction::Open) => self.sessions[a].open_local_dir(entry.path.clone()),
                            Some(RowAction::Transfer) => self.sessions[a].queue_upload(entry.path.clone()),
                            Some(RowAction::Hash(algorithm)) => self.start_local_hash(&entry, algorithm),
                            Some(RowAction::Rename) => self.begin_rename(FileTarget::Local(vec![entry.clone()])),
                            Some(RowAction::Delete) => self.begin_delete(FileTarget::Local(vec![entry.clone()])),
                            None => {}
                        }
                        if response.double_clicked() && entry.dir { self.sessions[a].open_local_dir(entry.path.clone()); }
                        file_row_details(ui, entry.dir, entry.size, &entry.modified);
                    });
                }
            });
        });
        let visible = self.sessions[a].local_entries.iter().filter(|entry| entry.name.to_lowercase().contains(&filter)).count();
        ui.label(format!("{visible} object(s)"));
    }

    fn remote_pane(&mut self, ui: &mut egui::Ui) {
        let a = self.active;
        let (_, dropped) = ui.dnd_drop_zone::<DragPayload, _>(egui::Frame::default(), |ui| {
            self.remote_pane_contents(ui);
        });
        if let Some(payload) = dropped {
            if let DragPayload::Local(path) = payload.as_ref() {
                self.sessions[a].queue_upload(path.clone());
            }
        }
    }

    fn remote_pane_contents(&mut self, ui: &mut egui::Ui) {
        let a = self.active;
        let connected = self.sessions[a].connection.is_some();
        ui.horizontal(|ui| {
            ui.strong("Remote site");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(connection) = &self.sessions[a].connection {
                    ui.colored_label(win32::OK_GREEN, format!("{}:{}", connection.host, connection.port));
                } else {
                    ui.colored_label(win32::WARN_AMBER, "Not connected");
                }
            });
        });
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
            ui.add_space(6.0);
            ui.label("Filter:");
            win32::text_edit(ui, egui::TextEdit::singleline(&mut self.sessions[a].remote_filter).desired_width(f32::INFINITY));
        });
        ui.horizontal(|ui| {
            ui.label("Address:");
            win32::field(ui, if connected { self.sessions[a].remote_path.as_str() } else { "" });
        });
        ui.add_space(2.0);

        let filter = self.sessions[a].remote_filter.to_lowercase();
        let mut rows: Vec<RemoteEntry> = self.sessions[a].remote_entries.iter()
            .filter(|entry| entry.name.to_lowercase().contains(&filter)).cloned().collect();
        let remote_path_trimmed = self.sessions[a].remote_path.trim_end_matches('/');
        if !remote_path_trimmed.is_empty() && remote_path_trimmed != "/" {
            rows.insert(0, RemoteEntry {
                name: "..".into(), path: remote_parent(&self.sessions[a].remote_path), dir: true,
                size: 0, modified: "—".into(),
            });
        }
        let mut open_profiles = false;
        let list_height = (ui.available_height() - FOOTER_HEIGHT).max(60.0);
        win32::list_view(ui, list_height, |ui| {
            let name_width = list_header(ui);
            if !connected {
                ui.vertical_centered(|ui| {
                    ui.add_space(60.0);
                    ui.label("Not connected to a server.");
                    ui.weak("Connect to an SSH server to browse remote files.");
                    ui.add_space(8.0);
                    if win32::button_sized(ui, true, "Connect…", 75.0).clicked() { open_profiles = true; }
                });
                return;
            }
            egui::ScrollArea::vertical().id_salt(("remote_list", self.sessions[a].id)).auto_shrink([false, false]).show(ui, |ui| {
                for entry in rows {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        let selected = self.sessions[a].remote_selected.contains(&entry.path);
                        let response = file_name_cell(ui, name_width, ROW_HEIGHT, &entry.name, entry.dir, selected);
                        if response.dragged() { response.dnd_set_drag_payload(DragPayload::Remote(entry.path.clone())); }
                        if response.clicked() {
                            let multi = response.ctx.input(|input| input.modifiers.ctrl || input.modifiers.command);
                            if multi {
                                if selected { self.sessions[a].remote_selected.retain(|path| path != &entry.path); }
                                else { self.sessions[a].remote_selected.push(entry.path.clone()); }
                            } else {
                                self.sessions[a].remote_selected.clear();
                                self.sessions[a].remote_selected.push(entry.path.clone());
                            }
                        }
                        if response.secondary_clicked() && !selected {
                            self.sessions[a].remote_selected.clear();
                            self.sessions[a].remote_selected.push(entry.path.clone());
                        }
                        let in_selection = self.sessions[a].remote_selected.contains(&entry.path);
                        let count = if in_selection { self.sessions[a].remote_selected.len() } else { 1 };
                        let mut action = None;
                        if entry.name != ".." {
                            response.context_menu(|ui| {
                                let label = if count > 1 { format!("Download {count} items") } else { "Download".to_owned() };
                                action = row_context_menu(ui, entry.dir, &label, true, count == 1);
                            });
                        }
                        let targets = || -> Vec<RemoteEntry> {
                            if in_selection {
                                self.sessions[a].remote_entries.iter().filter(|e| self.sessions[a].remote_selected.contains(&e.path)).cloned().collect()
                            } else {
                                vec![entry.clone()]
                            }
                        };
                        match action {
                            Some(RowAction::Open) => self.sessions[a].navigate_remote(entry.path.clone()),
                            Some(RowAction::Transfer) => {
                                for target in targets() { self.sessions[a].queue_download(target.path, self.settings.transfer); }
                            }
                            Some(RowAction::Hash(algorithm)) => self.start_remote_hash(&entry, algorithm),
                            Some(RowAction::Rename) => self.begin_rename(FileTarget::Remote(vec![entry.clone()])),
                            Some(RowAction::Delete) => {
                                let targets = targets();
                                self.begin_delete(FileTarget::Remote(targets));
                            }
                            None => {}
                        }
                        if response.double_clicked() && entry.dir { self.sessions[a].navigate_remote(entry.path.clone()); }
                        file_row_details(ui, entry.dir, entry.size, &entry.modified);
                    });
                }
            });
        });
        if open_profiles { self.dialog = Some(Dialog::Profiles); }
        let visible = self.sessions[a].remote_entries.iter().filter(|entry| entry.name.to_lowercase().contains(&filter)).count();
        ui.label(format!("{} selected, {visible} object(s)", self.sessions[a].remote_selected.len()));
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
        };
        let builder = egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size(match &dialog {
                Dialog::Profiles => [640.0, 380.0],
                Dialog::TrustHostKey => [470.0, 260.0],
                Dialog::ConfirmDelete => [440.0, 170.0],
                Dialog::Rename => [420.0, 160.0],
                _ => [470.0, 210.0],
            })
            .with_min_inner_size([420.0, 180.0])
            .with_resizable(false);
        let mut close = false;
        let mut connect = false;
        let mut save = false;
        let mut accept_trust = false;
        let mut password_value = None;
        let mut confirm_delete = false;
        let mut confirm_rename = false;
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
                                    egui::ScrollArea::vertical().id_salt("profile_list").auto_shrink([false, false]).show(ui, |ui| {
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
                            win32::text_edit(ui, egui::TextEdit::singleline(&mut self.password).password(true).desired_width(f32::INFINITY));
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
                            ui.colored_label(win32::ERROR_RED, &self.rename_error);
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
        if save { self.save_profile(); }
        if connect {
            match self.profile_value() {
                Ok(profile) => {
                    if profile.auth_method == AuthMethod::Password {
                        self.dialog = Some(Dialog::Password);
                    } else {
                        self.dialog = None;
                        self.begin_connect(None);
                    }
                }
                Err(error) => self.show_error(error),
            }
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
            .with_inner_size([640.0, 380.0])
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
                                egui::Grid::new("settings_transfers").num_columns(3).spacing([8.0, 8.0]).show(ui, |ui| {
                                    row(ui, "Concurrent transfers:", &mut draft.concurrent, "1–16");
                                });
                                ui.add_space(6.0);
                                ui.weak("Maximum number of files transferred at the same time, per session.");
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
                            ui.colored_label(win32::ERROR_RED, &self.settings_error);
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
            let result = self.settings_draft.parse().and_then(|settings| {
                if settings.logging.enabled {
                    fs::create_dir_all(&settings.logging.directory)
                        .map_err(|error| format!("Cannot create log directory {}: {error}", settings.logging.directory.display()))?;
                }
                crate::settings::save(&settings).map_err(|error| format!("Could not save settings: {error}"))?;
                Ok(settings)
            });
            match result {
                Ok(settings) => {
                    if settings.transfer.max_concurrent_transfers != self.settings.transfer.max_concurrent_transfers {
                        for session in &mut self.sessions {
                            session.set_concurrency(settings.transfer.max_concurrent_transfers);
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

        let connected = self.session().is_connected();
        let can_close = self.can_close_active();
        let can_download = connected && !self.session().remote_selected.is_empty();
        let can_upload = self.session().can_upload();
        egui::TopBottomPanel::top("menubar")
            .frame(win32::panel_frame(0).inner_margin(egui::Margin::symmetric(2, 1)))
            .show(ctx, |ui| {
            win32::menu_bar().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("New connection…").clicked() { self.dialog = Some(Dialog::Profiles); ui.close(); }
                    if ui.add_enabled(can_close, egui::Button::new("Disconnect")).clicked() { self.disconnect_active(); ui.close(); }
                    ui.separator();
                    if ui.button("Exit").clicked() { ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close); }
                });
                ui.menu_button("View", |ui| {
                    if ui.button("Refresh local").clicked() { self.session_mut().refresh_local(); ui.close(); }
                    if ui.add_enabled(connected, egui::Button::new("Refresh remote")).clicked() {
                        self.session_mut().reload_remote();
                        ui.close();
                    }
                });
                ui.menu_button("Transfer", |ui| {
                    if ui.add_enabled(can_upload, egui::Button::new("Upload selected")).clicked() { self.upload_selected(); ui.close(); }
                    if ui.add_enabled(can_download, egui::Button::new("Download selected")).clicked() { self.download_selected(); ui.close(); }
                    ui.separator();
                    if ui.button("Settings…").clicked() { self.open_settings(); ui.close(); }
                });
            });
        });
        egui::TopBottomPanel::top("toolbar")
            .frame(win32::panel_frame(3))
            .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 1.0;
                if win32::icon_button(ui, true, win32::Icon::Connect, "Connect… (opens a new session tab)").clicked() { self.dialog = Some(Dialog::Profiles); }
                if win32::icon_button(ui, can_close, win32::Icon::Disconnect, "Disconnect and close this session").clicked() { self.disconnect_active(); }
                win32::toolbar_separator(ui);
                if win32::icon_button(ui, can_upload, win32::Icon::Upload, "Upload selected local item").clicked() { self.upload_selected(); }
                if win32::icon_button(ui, can_download, win32::Icon::Download, "Download selected remote files").clicked() { self.download_selected(); }
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
                    .map(|session| session.transfers.iter().filter(|item| item.is_pending()).count())
                    .sum::<usize>();
                let connection = match &self.session().connection {
                    Some(connection) => format!("Connected to {}:{}", connection.host, connection.port),
                    None => "Not connected".into(),
                };
                // Totals over every session, not just the visible one.
                let speed = |state: &str| -> f64 { self.sessions.iter().map(|session| session.speed(state)).sum() };
                let speeds = format!("↓ {}   ↑ {}", speed_text(speed("Downloading")), speed_text(speed("Uploading")));
                let fixed = 200.0 + 180.0 + 130.0 + 3.0 * ui.spacing().item_spacing.x;
                let message_width = (ui.available_width() - fixed).max(120.0);
                win32::status_pane(ui, message_width, self.session().status.as_str());
                win32::status_pane(ui, 200.0, connection);
                win32::status_pane(ui, 180.0, speeds);
                win32::status_pane(ui, 130.0, format!("{active} active transfer{}", if active == 1 { "" } else { "s" }))
                    .on_hover_text("Across all sessions");
            });
        });
        egui::TopBottomPanel::bottom("queue")
            .resizable(true)
            .default_height(180.0)
            .min_height(100.0)
            .max_height(600.0)
            .frame(win32::panel_frame(6))
            .show(ctx, |ui| {
            let a = self.active;
            let queued = self.sessions[a].transfers.iter().filter(|item| item.state == "Queued").count();
            let active = self.sessions[a].transfers.iter().filter(|item| item.state == "Downloading" || item.state == "Uploading").count();
            let failed = self.sessions[a].transfers.iter().filter(|item| item.state.starts_with("Failed")).count();
            let pending_count = self.sessions[a].transfers.iter().filter(|item| item.is_pending()).count();
            let finished_count = self.sessions[a].transfers.len() - pending_count;
            ui.horizontal(|ui| {
                ui.strong("Transfer queue");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak(format!("{queued} queued, {active} active, {failed} failed"));
                });
            });
            win32::tab_strip(ui, &mut self.sessions[a].queue_tab, &[
                (QueueTab::Pending, format!("Pending ({pending_count})")),
                (QueueTab::Complete, format!("Complete ({finished_count})")),
            ]);
            let show_pending = self.sessions[a].queue_tab == QueueTab::Pending;
            let list_height = ui.available_height().max(40.0);
            win32::list_view(ui, list_height, |ui| {
                let file_width = 220.0;
                let percent_width = 80.0;
                let speed_width = 95.0;
                let elapsed_width = 90.0;
                let remaining_width = 105.0;
                let header_height = 19.0;
                let row_height = 18.0;
                let fixed = file_width + percent_width + speed_width + elapsed_width + remaining_width;
                let progress_width = (ui.available_width() - fixed - ui.spacing().scroll.bar_width).max(160.0);
                ui.horizontal(|ui| {
                    win32::header_cell(ui, file_width, header_height, "File");
                    win32::header_cell(ui, progress_width, header_height, "Progress");
                    win32::header_cell(ui, percent_width, header_height, "Complete");
                    win32::header_cell(ui, speed_width, header_height, "Speed (MiB/s)");
                    win32::header_cell(ui, elapsed_width, header_height, "Elapsed");
                    win32::header_cell(ui, remaining_width, header_height, "Remaining");
                    let rest = ui.available_width();
                    if rest > 0.0 { win32::header_cell(ui, rest, header_height, ""); }
                });
                egui::ScrollArea::vertical().id_salt(("queue_list", self.sessions[a].id)).auto_shrink([false, false]).show(ui, |ui| {
                    if !self.sessions[a].transfers.iter().any(|item| item.is_pending() == show_pending) {
                        let empty = if show_pending { "There are no pending transfers." } else { "There are no completed transfers." };
                        ui.add_space(6.0);
                        ui.horizontal(|ui| { ui.add_space(6.0); ui.weak(empty); });
                        return;
                    }
                    for item in self.sessions[a].transfers.iter().filter(|item| item.is_pending() == show_pending) {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            file_text_cell(ui, file_width, row_height, &item.name, false);
                            let (cell_rect, response) = ui.allocate_exact_size(
                                egui::vec2(progress_width, row_height), egui::Sense::hover()
                            );
                            let bar_rect = cell_rect.shrink2(egui::vec2(4.0, 2.0));
                            let painter = ui.painter();
                            painter.rect_filled(bar_rect, 0.0, win32::WINDOW);
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
                            let fill = if complete { win32::OK_GREEN } else { PIECE_FILL };
                            paint_piece_bar(painter, bar_rect, total, &pieces, fill);
                            if response.hovered() {
                                response.on_hover_text(format!(
                                    "{} / {} · {} segments\n{}",
                                    size_text(item.transferred), size_text(item.total), item.segments.len(), item.state
                                ));
                            }
                            let percent = if item.total == 0 {
                                if item.state == "Complete" { 100.0 } else { 0.0 }
                            } else { item.transferred as f64 * 100.0 / item.total as f64 };
                            file_text_cell(ui, percent_width, row_height, &format!("{percent:.1}%"), false);
                            let speed = if item.state == "Queued" { "—".into() } else { format!("{:.2}", item.speed_mib_s) };
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
                                if failed { "Failed".into() } else if item.state == "Queued" { "Queued".into() } else { "Calculating…".into() }
                            });
                            file_text_cell(ui, remaining_width, row_height, &remaining, false);
                        });
                    }
                });
            });
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
        if self.ops_pending > 0 || self.hash_jobs.iter().any(|job| job.result.is_none()) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        if self.sessions.iter().any(Session::is_busy) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
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

fn row_context_menu(ui: &mut egui::Ui, dir: bool, transfer_label: &str, transfer_enabled: bool, single: bool) -> Option<RowAction> {
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
    ui.separator();
    for algorithm in HashAlgorithm::ALL {
        item(ui, !dir && single, &format!("Calculate {}", algorithm.label()), RowAction::Hash(algorithm));
    }
    ui.separator();
    item(ui, single, "Rename", RowAction::Rename);
    item(ui, true, "Delete", RowAction::Delete);
    action
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

fn speed_text(mib_per_second: f64) -> String {
    if mib_per_second >= 1.0 {
        format!("{mib_per_second:.1} MiB/s")
    } else {
        format!("{:.0} KiB/s", mib_per_second * 1024.0)
    }
}

const ROW_HEIGHT: f32 = 18.0;
const FOOTER_HEIGHT: f32 = 20.0;
const SIZE_WIDTH: f32 = 80.0;
const MODIFIED_WIDTH: f32 = 150.0;
const TYPE_WIDTH: f32 = 80.0;

/// Draws the file list column headers and returns the width of the Name column.
fn list_header(ui: &mut egui::Ui) -> f32 {
    let name_width = (ui.available_width() - SIZE_WIDTH - MODIFIED_WIDTH - TYPE_WIDTH - ui.spacing().scroll.bar_width).max(100.0);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        win32::header_cell(ui, name_width, 19.0, "Name");
        win32::header_cell(ui, SIZE_WIDTH, 19.0, "Size");
        win32::header_cell(ui, MODIFIED_WIDTH, 19.0, "Modified (UTC)");
        win32::header_cell(ui, TYPE_WIDTH, 19.0, "Type");
        let rest = ui.available_width();
        if rest > 0.0 { win32::header_cell(ui, rest, 19.0, ""); }
    });
    name_width
}

fn file_row_details(ui: &mut egui::Ui, dir: bool, size: u64, modified: &str) {
    file_text_cell(ui, SIZE_WIDTH, ROW_HEIGHT, &if dir { String::new() } else { size_text(size) }, true);
    file_text_cell(ui, MODIFIED_WIDTH, ROW_HEIGHT, &modified.replace('T', " ").trim_end_matches('Z').to_owned(), false);
    file_text_cell(ui, TYPE_WIDTH, ROW_HEIGHT, if dir { "File folder" } else { "File" }, false);
}

fn file_name_cell(
    ui: &mut egui::Ui,
    width: f32,
    height: f32,
    text: &str,
    dir: bool,
    selected: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(width, height),
        egui::Sense::click_and_drag(),
    );
    if ui.is_rect_visible(rect) {
        let painter = ui.painter().with_clip_rect(rect.intersect(ui.clip_rect()));
        let icon = egui::Rect::from_min_size(rect.left_center() + egui::vec2(4.0, -6.0), egui::vec2(14.0, 12.0));
        paint_file_icon(&painter, icon, dir);
        let color = if selected { win32::SELECTION_TEXT } else { win32::TEXT };
        let galley = painter.layout_no_wrap(text.to_owned(), egui::TextStyle::Body.resolve(ui.style()), color);
        let text_rect = egui::Rect::from_min_size(
            egui::pos2(icon.right() + 4.0, rect.center().y - galley.size().y / 2.0),
            galley.size(),
        ).expand2(egui::vec2(2.0, 1.0));
        if selected {
            painter.rect_filled(text_rect, 0.0, win32::SELECTION);
        }
        painter.galley(text_rect.min + egui::vec2(2.0, 1.0), galley, color);
    }
    response
}

/// Small Explorer-style icon: a manila folder or a dog-eared page.
fn paint_file_icon(painter: &egui::Painter, rect: egui::Rect, dir: bool) {
    let outline = egui::Stroke::new(1.0, if dir { egui::Color32::from_rgb(128, 96, 0) } else { win32::SHADOW });
    if dir {
        let tab = egui::Rect::from_min_size(rect.min, egui::vec2(6.0, 3.0));
        let body = egui::Rect::from_min_max(rect.min + egui::vec2(0.0, 2.0), rect.max);
        painter.rect(tab, 0.0, egui::Color32::from_rgb(240, 200, 80), outline, egui::StrokeKind::Inside);
        painter.rect(body, 0.0, egui::Color32::from_rgb(255, 222, 110), outline, egui::StrokeKind::Inside);
    } else {
        let page = egui::Rect::from_center_size(rect.center(), egui::vec2(10.0, 12.0));
        painter.rect(page, 0.0, win32::WINDOW, outline, egui::StrokeKind::Inside);
        let corner = egui::Rect::from_min_max(egui::pos2(page.right() - 4.0, page.top()), egui::pos2(page.right(), page.top() + 4.0));
        painter.rect(corner, 0.0, win32::LIGHT, outline, egui::StrokeKind::Inside);
    }
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
    painter.text(pos, anchor, text, egui::TextStyle::Body.resolve(ui.style()), win32::TEXT);
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
        if color == win32::WINDOW { return; }
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
        let color = mix(mix(win32::WINDOW, fill, done), win32::ERROR_RED, failed);
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

fn size_text(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut index = 0;
    while value >= 1024.0 && index < UNITS.len() - 1 { value /= 1024.0; index += 1; }
    if index == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[index]) }
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
    fn delete_message_describes_targets() {
        let entry = |name: &str, dir: bool| RemoteEntry {
            name: name.into(), path: format!("/{name}"), dir, size: 0, modified: String::new(),
        };
        let one = FileTarget::Remote(vec![entry("a.txt", false)]);
        assert!(delete_message(&one).contains("\"a.txt\" from the server"));
        let folder = FileTarget::Remote(vec![entry("dir", true)]);
        assert!(delete_message(&folder).contains("folder \"dir\" and all of its contents"));
        let many = FileTarget::Remote(vec![entry("a", false), entry("b", true)]);
        assert!(delete_message(&many).contains("these 2 items"));
    }
}
