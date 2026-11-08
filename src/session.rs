//! One connection tab: its local folder, remote listing, SFTP connection and
//! transfer queue. Each session has its own concurrency limit and log context.

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{mpsc as std_mpsc, Arc},
    time::{Duration, Instant, SystemTime},
};

use tokio::{
    runtime::Handle,
    sync::{mpsc, Semaphore},
    task::AbortHandle,
};

use crate::{
    connection::{ConnectError, ConnectionProfile, SftpConnection},
    logging::{Category, Logger, SessionLog, Severity},
    transfer::{DownloadProgress, DownloadResult, SegmentProgress, TransferSettings},
};

#[derive(Clone)]
pub struct LocalEntry {
    pub name: String,
    pub path: PathBuf,
    pub dir: bool,
    pub size: u64,
    pub modified: String,
}

#[derive(Clone)]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub dir: bool,
    pub size: u64,
    pub modified: String,
}

pub struct TransferItem {
    pub id: usize,
    pub operation_id: Option<usize>,
    pub name: String,
    pub destination: PathBuf,
    pub transferred: u64,
    pub total: u64,
    pub segments: Vec<SegmentProgress>,
    pub started_at: Option<Instant>,
    pub finished_at: Option<Instant>,
    pub last_speed_sample_at: Option<Instant>,
    pub last_speed_sample_bytes: u64,
    pub speed_mib_s: f64,
    pub state: String,
}

impl TransferItem {
    fn queued(id: usize, name: String, destination: PathBuf, total: u64) -> Self {
        Self {
            id,
            operation_id: None,
            name,
            destination,
            transferred: 0,
            total,
            segments: Vec::new(),
            started_at: None,
            finished_at: None,
            last_speed_sample_at: None,
            last_speed_sample_bytes: 0,
            speed_mib_s: 0.0,
            state: "Queued".into(),
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self.state.as_str(), "Queued" | "Downloading" | "Uploading")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum QueueTab {
    Pending,
    Complete,
}

pub enum QueueEvent {
    Started { id: usize, state: String },
    Progress { id: usize, progress: DownloadProgress },
    Finished { id: usize, result: Result<DownloadResult, String> },
}

/// What a queued operation does, kept for its start/finish log lines.
struct TransferRecord {
    direction: &'static str,
    source: String,
    target: String,
    started: Option<Instant>,
}

/// Outcome of a finished connection attempt, for the app to act on.
pub enum ConnectOutcome {
    Connected,
    HostKeyRequired,
    Failed(String),
}

pub struct Session {
    pub id: u64,
    runtime: Handle,
    logger: Arc<Logger>,
    pub log: SessionLog,

    pub path: PathBuf,
    pub local_entries: Vec<LocalEntry>,
    pub local_filter: String,
    pub local_selected: Option<PathBuf>,

    pub remote_path: String,
    pub remote_entries: Vec<RemoteEntry>,
    pub remote_filter: String,
    pub remote_selected: Vec<String>,

    pub connection: Option<Arc<SftpConnection>>,
    pub profile: Option<ConnectionProfile>,
    /// Created by "Connect" rather than being the app's initial tab; such a
    /// tab is discarded again if its connection attempt fails.
    pub created_for_connect: bool,
    pub pending_password: Option<String>,
    pub pending_fingerprint: Option<String>,
    connect_rx: Option<std_mpsc::Receiver<Result<SftpConnection, ConnectError>>>,
    list_rx: Option<std_mpsc::Receiver<Result<Vec<RemoteEntry>, String>>>,

    pub transfers: Vec<TransferItem>,
    pub queue_tab: QueueTab,
    next_transfer_id: usize,
    queue_tx: std_mpsc::Sender<QueueEvent>,
    queue_rx: std_mpsc::Receiver<QueueEvent>,
    transfer_slots: Arc<Semaphore>,
    transfer_records: HashMap<usize, TransferRecord>,
    tasks: Vec<AbortHandle>,

    pub status: String,
}

impl Session {
    pub fn new(id: u64, runtime: Handle, logger: Arc<Logger>, path: PathBuf, settings: &TransferSettings) -> Self {
        let (queue_tx, queue_rx) = std_mpsc::channel();
        let mut session = Self {
            id,
            runtime,
            logger,
            log: SessionLog { id, remote: "-".into(), started: SystemTime::now() },
            path,
            local_entries: Vec::new(),
            local_filter: String::new(),
            local_selected: None,
            remote_path: String::new(),
            remote_entries: Vec::new(),
            remote_filter: String::new(),
            remote_selected: Vec::new(),
            connection: None,
            profile: None,
            created_for_connect: false,
            pending_password: None,
            pending_fingerprint: None,
            connect_rx: None,
            list_rx: None,
            transfers: Vec::new(),
            queue_tab: QueueTab::Pending,
            next_transfer_id: 1,
            queue_tx,
            queue_rx,
            transfer_slots: Arc::new(Semaphore::new(settings.max_concurrent_transfers.max(1) as usize)),
            transfer_records: HashMap::new(),
            tasks: Vec::new(),
            status: "Ready · No active SFTP session".into(),
        };
        session.refresh_local();
        session
    }

    /// Text for the session tab.
    pub fn title(&self) -> String {
        match (&self.profile, &self.connection) {
            (Some(profile), Some(_)) => profile.name.clone(),
            (Some(profile), None) if self.is_connecting() => format!("{} (connecting…)", profile.name),
            _ => "Not connected".into(),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    pub fn is_connecting(&self) -> bool {
        self.connect_rx.is_some() || self.pending_fingerprint.is_some()
    }

    pub fn is_busy(&self) -> bool {
        self.connect_rx.is_some() || self.list_rx.is_some() || self.transfers.iter().any(TransferItem::is_pending)
    }

    fn log_event(&self, category: Category, severity: Severity, msgid: &str, message: &str) {
        self.logger.log(&self.log, category, severity, msgid, message);
    }

    // ----- local side -----

    pub fn refresh_local(&mut self) {
        self.local_entries.clear();
        if let Ok(read_dir) = fs::read_dir(&self.path) {
            for item in read_dir.flatten() {
                let path = item.path();
                if let Ok(meta) = item.metadata() {
                    self.local_entries.push(LocalEntry {
                        name: item.file_name().to_string_lossy().into_owned(),
                        path,
                        dir: meta.is_dir(),
                        size: meta.len(),
                        modified: meta.modified().ok().map(crate::app::format_iso8601).unwrap_or_else(|| "—".into()),
                    });
                }
            }
        } else {
            self.status = format!("Cannot read {}", self.path.display());
        }
        self.local_entries.sort_by(|a, b| b.dir.cmp(&a.dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    }

    pub fn open_local_dir(&mut self, path: PathBuf) {
        self.path = path;
        self.local_selected = None;
        self.refresh_local();
    }

    // ----- connection -----

    pub fn start_connect(&mut self, profile: ConnectionProfile, password: Option<String>, trusted: Option<String>) {
        self.log = SessionLog {
            id: self.id,
            remote: format!("{}@{}:{}", profile.username, profile.host, profile.port),
            started: SystemTime::now(),
        };
        self.log_event(
            Category::Connection,
            Severity::Info,
            "CONNECT",
            &format!("Connecting to {} using {:?} authentication", self.log.remote, profile.auth_method),
        );
        self.profile = Some(profile.clone());
        self.pending_password = password.clone();
        let (tx, rx) = std_mpsc::channel();
        self.connect_rx = Some(rx);
        self.status = format!("Connecting to {}:{} …", profile.host, profile.port);
        self.runtime.spawn(async move {
            let result = SftpConnection::connect(&profile, password.as_deref(), trusted.as_deref()).await;
            let _ = tx.send(result);
        });
    }

    pub fn poll_connection(&mut self) -> Option<ConnectOutcome> {
        let result = self.connect_rx.as_ref().and_then(|rx| rx.try_recv().ok())?;
        self.connect_rx = None;
        Some(match result {
            Ok(connection) => {
                self.log_event(
                    Category::Connection,
                    Severity::Notice,
                    "CONNECT",
                    &format!("Connected to {} (host key {})", self.log.remote, connection.fingerprint),
                );
                let host = connection.host.clone();
                self.connection = Some(Arc::new(connection));
                self.pending_password = None;
                self.remote_path = ".".into();
                self.remote_selected.clear();
                self.status = format!("Connected to {host}");
                self.load_remote(".");
                ConnectOutcome::Connected
            }
            Err(ConnectError::HostKeyRequired { fingerprint }) => {
                self.log_event(
                    Category::Connection,
                    Severity::Warning,
                    "HOSTKEY",
                    &format!("Host key is not trusted yet: {fingerprint}"),
                );
                self.pending_fingerprint = Some(fingerprint);
                self.status = "First-time SSH host-key trust is required".into();
                ConnectOutcome::HostKeyRequired
            }
            Err(error) => {
                self.log_event(Category::Connection, Severity::Error, "CONNECT", &format!("Connection failed: {error}"));
                self.pending_password = None;
                self.status = "Connection failed".into();
                ConnectOutcome::Failed(error.to_string())
            }
        })
    }

    pub fn log_host_key_decision(&self, fingerprint: &str, trusted: bool) {
        let (severity, verdict) = if trusted { (Severity::Notice, "trusted") } else { (Severity::Warning, "rejected") };
        self.log_event(Category::Connection, severity, "HOSTKEY", &format!("Host key {verdict} by user: {fingerprint}"));
    }

    /// Drops the connection and cancels this session's queued and running transfers.
    pub fn disconnect(&mut self) {
        let cancelled = self.transfers.iter().filter(|item| item.is_pending()).count();
        for task in self.tasks.drain(..) {
            task.abort();
        }
        if self.connection.take().is_some() {
            let detail = if cancelled > 0 { format!(" ({cancelled} transfer(s) cancelled)") } else { String::new() };
            self.log_event(Category::Connection, Severity::Notice, "DISCONNECT", &format!("Disconnected from {}{detail}", self.log.remote));
        }
        self.connect_rx = None;
        self.list_rx = None;
        self.remote_entries.clear();
        self.remote_selected.clear();
        self.status = "Disconnected".into();
    }

    // ----- remote side -----

    pub fn load_remote(&mut self, path: &str) {
        let Some(connection) = self.connection.clone() else { return; };
        let path = path.to_owned();
        let (tx, rx) = std_mpsc::channel();
        self.list_rx = Some(rx);
        self.status = format!("Reading remote directory {path} …");
        self.runtime.spawn(async move {
            let result = async {
                let read_dir = connection.list_dir(&path).await.map_err(|e| e.to_string())?;
                let mut entries = Vec::new();
                for entry in read_dir {
                    let name = entry.file_name();
                    if name == "." || name == ".." { continue; }
                    let attrs = entry.metadata();
                    let full_path = crate::app::join_remote(&path, &name);
                    entries.push(RemoteEntry {
                        name,
                        path: full_path,
                        dir: attrs.is_dir(),
                        size: attrs.size.unwrap_or(0),
                        modified: attrs.mtime.map(|t| crate::app::format_unix_utc(t as i64)).unwrap_or_else(|| "—".into()),
                    });
                }
                entries.sort_by(|a, b| b.dir.cmp(&a.dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
                Ok(entries)
            }.await;
            let _ = tx.send(result);
        });
    }

    pub fn reload_remote(&mut self) {
        let path = self.remote_path.clone();
        self.load_remote(&path);
    }

    /// Returns an error message if the listing failed.
    pub fn poll_remote_listing(&mut self) -> Option<String> {
        let result = self.list_rx.as_ref().and_then(|rx| rx.try_recv().ok())?;
        self.list_rx = None;
        match result {
            Ok(entries) => {
                self.remote_entries = entries;
                self.remote_selected.clear();
                self.status = format!("Remote directory loaded · {} entries", self.remote_entries.len());
                None
            }
            Err(error) => Some(format!("Could not list remote directory: {error}")),
        }
    }

    pub fn navigate_remote(&mut self, path: String) {
        self.remote_path = path.clone();
        self.remote_selected.clear();
        self.load_remote(&path);
    }

    // ----- transfers -----

    pub fn set_concurrency(&mut self, limit: u32) {
        // Transfers already queued keep the old limit; new ones use the new one.
        self.transfer_slots = Arc::new(Semaphore::new(limit.max(1) as usize));
    }

    fn next_id(&mut self) -> usize {
        let id = self.next_transfer_id;
        self.next_transfer_id += 1;
        id
    }

    fn record(&mut self, id: usize, direction: &'static str, source: String, target: String) {
        self.log_event(Category::Transfer, Severity::Info, "TRANSFER", &format!("Queued {direction} {source} -> {target}"));
        self.transfer_records.insert(id, TransferRecord { direction, source, target, started: None });
    }

    /// Runs `work` once a transfer slot is free, forwarding progress to the queue.
    fn spawn_transfer<F>(&mut self, id: usize, state: &'static str, work: impl FnOnce(mpsc::UnboundedSender<DownloadProgress>) -> F + Send + 'static)
    where
        F: std::future::Future<Output = Result<DownloadResult, String>> + Send + 'static,
    {
        let slots = self.transfer_slots.clone();
        let tx = self.queue_tx.clone();
        let handle = self.runtime.spawn(async move {
            let _permit = match slots.acquire_owned().await {
                Ok(permit) => permit,
                Err(error) => {
                    let _ = tx.send(QueueEvent::Finished { id, result: Err(error.to_string()) });
                    return;
                }
            };
            let _ = tx.send(QueueEvent::Started { id, state: state.into() });
            let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
            let transfer = work(progress_tx);
            tokio::pin!(transfer);
            loop {
                tokio::select! {
                    result = &mut transfer => {
                        while let Ok(progress) = progress_rx.try_recv() {
                            let _ = tx.send(QueueEvent::Progress { id, progress });
                        }
                        let _ = tx.send(QueueEvent::Finished { id, result });
                        break;
                    }
                    progress = progress_rx.recv() => {
                        if let Some(progress) = progress {
                            let _ = tx.send(QueueEvent::Progress { id, progress });
                        }
                    }
                }
            }
        });
        self.tasks.retain(|task| !task.is_finished());
        self.tasks.push(handle.abort_handle());
    }

    /// Downloads the selected remote files (not folders) into the local folder.
    pub fn download_selected(&mut self, settings: TransferSettings) {
        let Some(connection) = self.connection.clone() else { return; };
        if self.remote_selected.is_empty() { return; }
        let files: Vec<RemoteEntry> = self.remote_entries.iter()
            .filter(|entry| self.remote_selected.contains(&entry.path) && !entry.dir)
            .cloned().collect();
        if files.is_empty() {
            self.status = "Select one or more remote files to download".into();
            return;
        }
        let count = files.len();
        for entry in files {
            let id = self.next_id();
            let destination = self.path.join(&entry.name);
            self.transfers.push(TransferItem::queued(id, entry.name.clone(), destination.clone(), entry.size));
            self.record(id, "download", entry.path.clone(), destination.display().to_string());
            let connection = connection.clone();
            self.spawn_transfer(id, "Downloading", move |progress| async move {
                connection.download(&entry.path, &destination, settings, Some(progress)).await.map_err(|e| e.to_string())
            });
        }
        self.status = format!("Queued {count} download(s) to {}", self.path.display());
    }

    /// Uploads a local file or folder (recursively) into the current remote folder.
    pub fn queue_upload(&mut self, local_path: PathBuf) {
        let Some(connection) = self.connection.clone() else {
            self.status = "Connect to a remote server before uploading".into();
            return;
        };
        let Some(name) = local_path.file_name().map(|name| name.to_string_lossy().into_owned()) else {
            self.status = "Cannot upload this filesystem path".into();
            return;
        };
        let remote_destination = crate::app::join_remote(&self.remote_path, &name);
        let total = fs::metadata(&local_path).map(|meta| if meta.is_file() { meta.len() } else { 0 }).unwrap_or(0);
        let id = self.next_id();
        self.transfers.push(TransferItem::queued(id, name.clone(), local_path.clone(), total));
        self.record(id, "upload", local_path.display().to_string(), remote_destination.clone());
        let destination = remote_destination.clone();
        self.spawn_transfer(id, "Uploading", move |progress| async move {
            connection.upload_path(&local_path, &destination, Some(progress)).await.map_err(|e| e.to_string())
        });
        self.status = format!("Queued recursive upload: {name} → {remote_destination}");
    }

    /// Downloads a remote file or folder (recursively) into the local folder.
    pub fn queue_download(&mut self, remote_path: String, settings: TransferSettings) {
        let Some(connection) = self.connection.clone() else { return; };
        let name = remote_path.rsplit('/').find(|part| !part.is_empty()).unwrap_or(&remote_path).to_owned();
        let destination = self.path.join(&name);
        let id = self.next_id();
        self.transfers.push(TransferItem::queued(id, name, destination.clone(), 0));
        self.record(id, "download", remote_path.clone(), destination.display().to_string());
        let (source, target) = (remote_path.clone(), destination.clone());
        self.spawn_transfer(id, "Downloading", move |progress| async move {
            connection.download_path(&source, &target, settings, Some(progress)).await.map_err(|e| e.to_string())
        });
        self.status = format!("Queued recursive download: {remote_path} → {}", destination.display());
    }

    pub fn speed(&self, state: &str) -> f64 {
        self.transfers.iter().filter(|item| item.state == state).map(|item| item.speed_mib_s).sum()
    }

    pub fn poll_queue(&mut self) {
        while let Ok(event) = self.queue_rx.try_recv() {
            match event {
                QueueEvent::Started { id, state } => {
                    if let Some(item) = self.transfers.iter_mut().find(|item| item.id == id) {
                        let now = Instant::now();
                        item.started_at = Some(now);
                        item.last_speed_sample_at = Some(now);
                        item.last_speed_sample_bytes = 0;
                        item.speed_mib_s = 0.0;
                        item.state = state;
                    }
                    if let Some(record) = self.transfer_records.get_mut(&id) {
                        record.started = Some(Instant::now());
                        let message = format!("Started {} {} -> {}", record.direction, record.source, record.target);
                        self.log_event(Category::Transfer, Severity::Info, "TRANSFER", &message);
                    }
                }
                QueueEvent::Progress { id, progress } => self.apply_progress(id, progress),
                QueueEvent::Finished { id, result } => self.finish_transfer(id, result),
            }
        }
    }

    fn apply_progress(&mut self, id: usize, progress: DownloadProgress) {
        let target_id = if let Some(relative) = progress.file_path.as_ref() {
            if let Some(existing) = self.transfers.iter().find(|item| item.operation_id == Some(id) && item.name == *relative) {
                existing.id
            } else {
                let child_state = self.transfers.iter().find(|item| item.id == id)
                    .map(|item| item.state.clone()).unwrap_or_else(|| "Downloading".into());
                self.transfers.retain(|item| item.id != id);
                let child_id = self.next_id();
                let now = Instant::now();
                let mut child = TransferItem::queued(child_id, relative.clone(), PathBuf::from(relative), progress.total_bytes);
                child.operation_id = Some(id);
                child.started_at = Some(now);
                child.last_speed_sample_at = Some(now);
                child.state = child_state;
                self.transfers.push(child);
                child_id
            }
        } else {
            id
        };
        let mut completed_file = None;
        if let Some(item) = self.transfers.iter_mut().find(|item| item.id == target_id) {
            let now = Instant::now();
            if progress.transferred_bytes < item.last_speed_sample_bytes {
                // A segment retry rolled the aggregate counter back.
                item.last_speed_sample_bytes = progress.transferred_bytes;
                item.last_speed_sample_at = Some(now);
                item.speed_mib_s = 0.0;
            } else if let Some(sampled_at) = item.last_speed_sample_at {
                let elapsed = now.saturating_duration_since(sampled_at);
                if elapsed >= Duration::from_millis(250) {
                    let delta = progress.transferred_bytes - item.last_speed_sample_bytes;
                    item.speed_mib_s = delta as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
                    item.last_speed_sample_bytes = progress.transferred_bytes;
                    item.last_speed_sample_at = Some(now);
                }
            } else {
                item.last_speed_sample_at = Some(now);
                item.last_speed_sample_bytes = progress.transferred_bytes;
            }
            item.transferred = progress.transferred_bytes;
            item.total = progress.total_bytes;
            if progress.file_complete && item.state != "Complete" {
                item.finished_at = Some(now);
                item.state = "Complete".into();
                if item.operation_id.is_some() {
                    completed_file = Some((item.name.clone(), item.total));
                }
            }
            if let Some(segment) = progress.segment {
                if let Some(existing) = item.segments.iter_mut().find(|s| s.index == segment.index) {
                    *existing = segment;
                } else {
                    item.segments.push(segment);
                    item.segments.sort_by_key(|s| s.index);
                }
            }
            if item.state != "Uploading" && item.state != "Complete" {
                item.state = "Downloading".into();
            }
        }
        if let (Some((name, bytes)), Some(record)) = (completed_file, self.transfer_records.get(&id)) {
            let message = format!("File complete in {} {}: {name} ({bytes} bytes)", record.direction, record.source);
            self.log_event(Category::Transfer, Severity::Info, "TRANSFER", &message);
        }
    }

    fn finish_transfer(&mut self, id: usize, result: Result<DownloadResult, String>) {
        let now = Instant::now();
        let child_exists = self.transfers.iter().any(|item| item.operation_id == Some(id));
        if let Some(record) = self.transfer_records.remove(&id) {
            let elapsed = record.started.map(|start| now.saturating_duration_since(start)).unwrap_or_default();
            let (severity, message) = match &result {
                Ok(done) => {
                    let rate = done.bytes as f64 / elapsed.as_secs_f64().max(0.001) / (1024.0 * 1024.0);
                    (Severity::Notice, format!(
                        "Completed {} {} -> {}: {} bytes in {:.1} s ({rate:.2} MiB/s)",
                        record.direction, record.source, record.target, done.bytes, elapsed.as_secs_f64()
                    ))
                }
                Err(error) => (Severity::Error, format!(
                    "Failed {} {} -> {}: {error}", record.direction, record.source, record.target
                )),
            };
            self.log_event(Category::Transfer, severity, "TRANSFER", &message);
        }
        match result {
            Ok(result) => {
                if child_exists {
                    for item in self.transfers.iter_mut().filter(|item| item.operation_id == Some(id)) {
                        if item.state != "Complete" {
                            item.finished_at = Some(now);
                            item.transferred = item.total;
                            item.state = "Complete".into();
                        }
                    }
                } else if let Some(item) = self.transfers.iter_mut().find(|item| item.id == id) {
                    item.finished_at = Some(now);
                    item.transferred = result.bytes;
                    item.total = result.bytes;
                    item.state = "Complete".into();
                }
            }
            Err(error) => {
                let mut marked = false;
                for item in self.transfers.iter_mut().filter(|item| item.operation_id == Some(id)) {
                    if item.state != "Complete" {
                        item.finished_at = Some(now);
                        for segment in &mut item.segments {
                            if !segment.complete { segment.failed = true; }
                        }
                        item.state = format!("Failed: {error}");
                    }
                    marked = true;
                }
                if !marked {
                    if let Some(item) = self.transfers.iter_mut().find(|item| item.id == id) {
                        item.finished_at = Some(now);
                        item.state = format!("Failed: {error}");
                    }
                }
            }
        }
    }

    /// Logs a delete / rename carried out in this session.
    pub fn log_file_operation(&self, msgid: &str, result: &Result<String, String>) {
        match result {
            Ok(message) => self.log_event(Category::Transfer, Severity::Notice, msgid, message),
            Err(error) => self.log_event(Category::Transfer, Severity::Error, msgid, error),
        }
    }

    pub fn can_upload(&self) -> bool {
        self.is_connected()
            && self.local_selected.as_deref().is_some_and(|path| Some(path) != self.path.parent())
    }
}

