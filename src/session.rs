//! One connection tab: its local folder, remote listing, SFTP connection and
//! transfer queue. Each session has its own concurrency limit and log context.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    path::PathBuf,
    sync::{mpsc as std_mpsc, Arc},
    time::{Duration, Instant, SystemTime},
};

use tokio::{
    runtime::Handle,
    sync::{mpsc, Semaphore},
};

use crate::{
    connection::{ConnectError, ConnectionProfile, NetworkSettings, SftpConnection},
    logging::{Category, LogEntry, Logger, SessionLog, Severity},
    transfer::{CancelToken, DownloadProgress, DownloadResult, SegmentProgress, TransferSettings},
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

/// Column a file list is sorted by.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortColumn {
    Name,
    Size,
    Modified,
    Type,
}

/// Sort order of a file list. Folders always come before files.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SortOrder {
    pub column: SortColumn,
    pub ascending: bool,
}

impl Default for SortOrder {
    fn default() -> Self {
        Self { column: SortColumn::Name, ascending: true }
    }
}

impl SortOrder {
    /// Clicking a header sorts by that column; clicking it again flips the order.
    pub fn toggle(&mut self, column: SortColumn) {
        if self.column == column {
            self.ascending = !self.ascending;
        } else {
            *self = Self { column, ascending: true };
        }
    }
}

/// What the file lists sort on.
pub trait Sortable {
    fn sort_name(&self) -> &str;
    fn sort_dir(&self) -> bool;
    fn sort_size(&self) -> u64;
    /// ISO 8601 UTC, so its text order is its time order.
    fn sort_modified(&self) -> &str;
}

impl Sortable for LocalEntry {
    fn sort_name(&self) -> &str { &self.name }
    fn sort_dir(&self) -> bool { self.dir }
    fn sort_size(&self) -> u64 { self.size }
    fn sort_modified(&self) -> &str { &self.modified }
}

impl Sortable for RemoteEntry {
    fn sort_name(&self) -> &str { &self.name }
    fn sort_dir(&self) -> bool { self.dir }
    fn sort_size(&self) -> u64 { self.size }
    fn sort_modified(&self) -> &str { &self.modified }
}

/// Sorts `rows` by `order`: folders first, then the column, then the name.
pub fn sort_rows<T: Sortable>(rows: &mut [T], order: SortOrder) {
    use std::cmp::Ordering;
    rows.sort_by(|a, b| {
        let by_name = || a.sort_name().to_lowercase().cmp(&b.sort_name().to_lowercase());
        let by_column = match order.column {
            SortColumn::Name => by_name(),
            SortColumn::Size => a.sort_size().cmp(&b.sort_size()),
            SortColumn::Modified => a.sort_modified().cmp(b.sort_modified()),
            // Folders and files are already apart; files share one type.
            SortColumn::Type => Ordering::Equal,
        };
        let by_column = if order.ascending { by_column } else { by_column.reverse() };
        b.sort_dir().cmp(&a.sort_dir()).then(by_column).then_with(by_name)
    });
}

/// Applies a click with modifiers to a selection, Explorer-style: plain click
/// selects only the item, Ctrl toggles it, Shift selects the range from the
/// anchor (the last item clicked without Shift) in `order`, Ctrl+Shift adds
/// that range.
pub fn select_click<T: Clone + PartialEq>(
    selected: &mut Vec<T>,
    anchor: &mut Option<T>,
    order: &[T],
    clicked: &T,
    ctrl: bool,
    shift: bool,
) {
    let position = |item: &T| order.iter().position(|other| other == item);
    match (shift, anchor.as_ref().and_then(position), position(clicked)) {
        (true, Some(from), Some(to)) => {
            let (low, high) = if from <= to { (from, to) } else { (to, from) };
            if !ctrl {
                selected.clear();
            }
            for item in &order[low..=high] {
                if !selected.contains(item) {
                    selected.push(item.clone());
                }
            }
        }
        _ => {
            if ctrl {
                if let Some(index) = selected.iter().position(|item| item == clicked) {
                    selected.remove(index);
                } else {
                    selected.push(clicked.clone());
                }
            } else {
                selected.clear();
                selected.push(clicked.clone());
            }
            *anchor = Some(clicked.clone());
        }
    }
}

/// What a transfer row moves, so it can be retried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Job {
    /// One remote file through the segmented download engine.
    DownloadFile { remote: String, local: PathBuf, size: u64 },
    /// A remote file or folder, recursively.
    DownloadPath { remote: String, local: PathBuf, dir: bool },
    /// A local file or folder, recursively.
    UploadPath { local: PathBuf, remote: String, dir: bool },
}

impl Job {
    /// The job of one file of a folder transfer, from the relative name its
    /// progress reports (local path syntax, relative to the folder).
    pub fn child(&self, relative: &str) -> Job {
        let remote_relative = relative.replace('\\', "/");
        match self {
            Job::DownloadPath { remote, local, dir: true } => Job::DownloadPath {
                remote: crate::app::join_remote(remote, &remote_relative),
                local: local.join(relative),
                dir: false,
            },
            Job::UploadPath { local, remote, dir: true } => Job::UploadPath {
                local: local.join(relative),
                remote: crate::app::join_remote(remote, &remote_relative),
                dir: false,
            },
            // The transfer was a single file: its one row is that file.
            other => other.clone(),
        }
    }
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
    /// Download (into the local folder) or upload.
    pub download: bool,
    /// "UDP" (rsftp-turbo) or "SFTP", known once data flows.
    pub protocol: Option<&'static str>,
    /// Diagnostic summary of a finished turbo download.
    pub details: Option<String>,
    /// What to run again for "Retry".
    pub job: Option<Job>,
}

impl TransferItem {
    fn queued(id: usize, name: String, destination: PathBuf, total: u64, download: bool) -> Self {
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
            download,
            protocol: None,
            details: None,
            job: None,
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self.state.as_str(), "Queued" | "Downloading" | "Uploading")
    }

    pub fn is_failed(&self) -> bool {
        self.state.starts_with("Failed") || self.state == "Cancelled"
    }

    /// Which queue tab lists this transfer.
    pub fn tab(&self) -> QueueTab {
        if self.is_pending() {
            QueueTab::Pending
        } else if self.is_failed() {
            QueueTab::Failed
        } else {
            QueueTab::Complete
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum QueueTab {
    Pending,
    Complete,
    Failed,
    Log,
    Statistics,
}

/// Download and upload speed of a session at one moment, in MiB/s.
#[derive(Clone, Copy, Debug)]
pub struct SpeedSample {
    pub at: Instant,
    pub down: f64,
    pub up: f64,
    /// A download / upload was running when the sample was taken.
    pub downloading: bool,
    pub uploading: bool,
}

/// How far back the statistics graph can look.
pub const SPEED_HISTORY: Duration = Duration::from_secs(30 * 60);
const SPEED_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

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
    /// Carries the password that worked, so the app can save it if asked to.
    Connected { password: Option<String> },
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
    pub local_selected: Vec<PathBuf>,
    /// Start of a Shift-click range: the item last clicked without Shift.
    pub local_anchor: Option<PathBuf>,
    pub local_sort: SortOrder,

    pub remote_path: String,
    pub remote_entries: Vec<RemoteEntry>,
    pub remote_filter: String,
    pub remote_selected: Vec<String>,
    pub remote_anchor: Option<String>,
    pub remote_sort: SortOrder,

    pub connection: Option<Arc<SftpConnection>>,
    pub profile: Option<ConnectionProfile>,
    /// Created by "Connect" rather than being the app's initial tab; such a
    /// tab is discarded again if its connection attempt fails.
    pub created_for_connect: bool,
    pub pending_password: Option<String>,
    pub pending_fingerprint: Option<String>,
    connect_rx: Option<std_mpsc::Receiver<Result<SftpConnection, ConnectError>>>,
    /// A listing in progress: resolves to (absolute path, entries).
    list_rx: Option<std_mpsc::Receiver<Result<(String, Vec<RemoteEntry>), String>>>,
    /// The pending listing is the profile's default folder: on failure, show
    /// the home folder instead.
    home_fallback: bool,

    pub transfers: Vec<TransferItem>,
    pub queue_tab: QueueTab,
    next_transfer_id: usize,
    queue_tx: std_mpsc::Sender<QueueEvent>,
    queue_rx: std_mpsc::Receiver<QueueEvent>,
    transfer_slots: Arc<Semaphore>,
    transfer_records: HashMap<usize, TransferRecord>,
    /// Job of each running operation, for the rows of its files.
    operation_jobs: HashMap<usize, Job>,
    /// Cancel tokens of operations that have not finished, by operation id.
    operations: HashMap<usize, CancelToken>,
    /// Operations the user stopped; their failure is shown as "Cancelled".
    cancelled_operations: HashSet<usize>,
    /// Row selected in the transfer queue.
    pub selected_transfer: Option<usize>,
    /// One sample per second, oldest first, for the statistics graph.
    pub speed_history: VecDeque<SpeedSample>,
    pub connected_at: Option<Instant>,

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
            local_selected: Vec::new(),
            local_anchor: None,
            local_sort: SortOrder::default(),
            remote_path: String::new(),
            remote_entries: Vec::new(),
            remote_filter: String::new(),
            remote_selected: Vec::new(),
            remote_anchor: None,
            remote_sort: SortOrder::default(),
            connection: None,
            profile: None,
            created_for_connect: false,
            pending_password: None,
            pending_fingerprint: None,
            connect_rx: None,
            list_rx: None,
            home_fallback: false,
            transfers: Vec::new(),
            queue_tab: QueueTab::Pending,
            next_transfer_id: 1,
            queue_tx,
            queue_rx,
            transfer_slots: Arc::new(Semaphore::new(settings.max_concurrent_transfers.max(1) as usize)),
            transfer_records: HashMap::new(),
            operation_jobs: HashMap::new(),
            operations: HashMap::new(),
            cancelled_operations: HashSet::new(),
            selected_transfer: None,
            speed_history: VecDeque::new(),
            connected_at: None,
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
        self.connect_rx.is_some()
            || self.list_rx.is_some()
            || self.transfers.iter().any(TransferItem::is_pending)
            || self.connection.as_ref().is_some_and(|connection| {
                connection.turbo_info().state == crate::connection::TurboState::Testing
            })
    }

    fn log_event(&self, category: Category, severity: Severity, msgid: &str, message: &str) {
        self.logger.log(&self.log, category, severity, msgid, message);
    }

    /// Log lines of this session, oldest first.
    pub fn recent_log(&self) -> Vec<LogEntry> {
        self.logger.recent(self.id)
    }

    /// Records the current speeds about once a second (call every frame).
    pub fn sample_speeds(&mut self) {
        let now = Instant::now();
        if self.speed_history.back().is_some_and(|last| now.saturating_duration_since(last.at) < SPEED_SAMPLE_INTERVAL) {
            return;
        }
        let running = |state: &str| self.transfers.iter().any(|item| item.state == state);
        let sample = SpeedSample {
            at: now,
            down: self.speed("Downloading"),
            up: self.speed("Uploading"),
            downloading: running("Downloading"),
            uploading: running("Uploading"),
        };
        self.speed_history.push_back(sample);
        while self.speed_history.front().is_some_and(|first| now.saturating_duration_since(first.at) > SPEED_HISTORY) {
            self.speed_history.pop_front();
        }
    }

    /// Bytes moved so far in this session: (downloaded, uploaded).
    pub fn bytes_transferred(&self) -> (u64, u64) {
        self.transfers.iter().fold((0, 0), |(down, up), item| {
            if item.download { (down + item.transferred, up) } else { (down, up + item.transferred) }
        })
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
        self.local_selected.clear();
        self.local_anchor = None;
        self.refresh_local();
    }

    // ----- connection -----

    pub fn start_connect(
        &mut self,
        profile: ConnectionProfile,
        password: Option<String>,
        trusted: Option<String>,
        network: NetworkSettings,
    ) {
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
            let result = SftpConnection::connect(&profile, password.as_deref(), trusted.as_deref(), network).await;
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
                    &format!(
                        "Connected to {} (host key {}, {} SFTP channel(s))",
                        self.log.remote, connection.fingerprint, connection.channel_count()
                    ),
                );
                let host = connection.host.clone();
                self.connected_at = Some(Instant::now());
                let connection = Arc::new(connection);
                if connection.begin_turbo_probe() {
                    let probe = Arc::clone(&connection);
                    self.runtime.spawn(async move { probe.probe_turbo().await });
                }
                self.connection = Some(connection);
                let password = self.pending_password.take();
                // Filled in with the absolute home directory once listed.
                self.remote_path = String::new();
                self.remote_selected.clear();
                self.status = format!("Connected to {host}");
                let default_path = self
                    .profile
                    .as_ref()
                    .and_then(|profile| profile.default_remote_path.clone())
                    .filter(|path| !path.trim().is_empty());
                match default_path {
                    Some(path) => {
                        // SFTP servers do not expand `~`; relative paths start at home.
                        let path = path.trim();
                        let path = match path.strip_prefix('~') {
                            Some("") => ".",
                            Some(rest) if rest.starts_with('/') => rest.trim_start_matches('/'),
                            _ => path,
                        };
                        self.load_remote(if path.is_empty() { "." } else { path });
                        self.home_fallback = true;
                    }
                    None => self.load_remote("."),
                }
                ConnectOutcome::Connected { password }
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
        // Transfers stop cooperatively and clean up their partial files.
        self.cancel_all();
        if self.connection.take().is_some() {
            let detail = if cancelled > 0 { format!(" ({cancelled} transfer(s) cancelled)") } else { String::new() };
            self.log_event(Category::Connection, Severity::Notice, "DISCONNECT", &format!("Disconnected from {}{detail}", self.log.remote));
        }
        self.connect_rx = None;
        self.list_rx = None;
        self.home_fallback = false;
        self.connected_at = None;
        self.remote_entries.clear();
        self.remote_selected.clear();
        self.status = "Disconnected".into();
    }

    // ----- remote side -----

    /// Lists `path` in the background. Relative paths and `.`/`..` are
    /// resolved on the server first, so `remote_path` is always absolute.
    pub fn load_remote(&mut self, path: &str) {
        let Some(connection) = self.connection.clone() else { return; };
        self.home_fallback = false;
        let requested = if path.is_empty() { ".".to_owned() } else { path.to_owned() };
        let (tx, rx) = std_mpsc::channel();
        self.list_rx = Some(rx);
        self.status = format!("Reading remote directory {requested} …");
        self.runtime.spawn(async move {
            let result = async {
                // Through the rsftp-turbo helper when it can list, else SFTP.
                let (path, listed) = connection.list_directory(&requested).await?;
                let mut entries: Vec<RemoteEntry> = listed
                    .into_iter()
                    .map(|entry| RemoteEntry {
                        path: crate::app::join_remote(&path, &entry.name),
                        name: entry.name,
                        dir: entry.dir,
                        size: entry.size,
                        modified: entry.mtime.map(|t| crate::app::format_unix_utc(t as i64)).unwrap_or_else(|| "—".into()),
                    })
                    .collect();
                entries.sort_by(|a, b| b.dir.cmp(&a.dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
                Ok((path, entries))
            }.await;
            let _ = tx.send(result);
        });
    }

    pub fn reload_remote(&mut self) {
        let path = self.remote_path.clone();
        self.load_remote(&path);
    }

    /// Returns an error message if the listing failed. The current path only
    /// changes when a listing succeeds.
    pub fn poll_remote_listing(&mut self) -> Option<String> {
        let result = self.list_rx.as_ref().and_then(|rx| rx.try_recv().ok())?;
        self.list_rx = None;
        let fall_back = std::mem::take(&mut self.home_fallback);
        match result {
            Ok((path, entries)) => {
                self.remote_path = path;
                self.remote_entries = entries;
                self.remote_selected.clear();
                self.status = format!("Remote directory loaded · {} entries", self.remote_entries.len());
                None
            }
            Err(error) if fall_back => {
                self.log_event(
                    Category::Connection,
                    Severity::Warning,
                    "LIST",
                    &format!("Default remote folder unavailable, opening the home folder: {error}"),
                );
                self.load_remote(".");
                Some(format!("Could not open the default remote folder: {error}\n\nShowing the home folder instead."))
            }
            Err(error) => Some(format!("Could not list remote directory: {error}")),
        }
    }

    pub fn navigate_remote(&mut self, path: String) {
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
    fn spawn_transfer<F>(
        &mut self,
        id: usize,
        state: &'static str,
        work: impl FnOnce(mpsc::UnboundedSender<DownloadProgress>, CancelToken) -> F + Send + 'static,
    )
    where
        F: std::future::Future<Output = Result<DownloadResult, String>> + Send + 'static,
    {
        let slots = self.transfer_slots.clone();
        let tx = self.queue_tx.clone();
        let cancel = CancelToken::new();
        self.operations.insert(id, cancel.clone());
        self.runtime.spawn(async move {
            // A queued transfer can be stopped while it waits for a slot.
            let permit = tokio::select! {
                permit = slots.acquire_owned() => permit.map_err(|error| error.to_string()),
                _ = cancel.cancelled() => Err("cancelled".to_owned()),
            };
            let _permit = match permit {
                Ok(permit) => permit,
                Err(error) => {
                    let _ = tx.send(QueueEvent::Finished { id, result: Err(error) });
                    return;
                }
            };
            let _ = tx.send(QueueEvent::Started { id, state: state.into() });
            let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
            let transfer = work(progress_tx, cancel);
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
    }

    /// Stops an operation (a single transfer or a whole folder transfer).
    pub fn cancel_operation(&mut self, operation: usize) {
        if let Some(token) = self.operations.get(&operation) {
            token.cancel();
            self.cancelled_operations.insert(operation);
            self.status = "Stopping transfer…".into();
        }
    }

    /// Stops every queued and running transfer of this session.
    pub fn cancel_all(&mut self) {
        for (operation, token) in &self.operations {
            token.cancel();
            self.cancelled_operations.insert(*operation);
        }
        if !self.operations.is_empty() {
            self.status = "Stopping all transfers…".into();
        }
    }

    /// Whether an operation can still be stopped.
    pub fn is_operation_active(&self, operation: usize) -> bool {
        self.operations.contains_key(&operation)
    }

    pub fn has_active_operations(&self) -> bool {
        !self.operations.is_empty()
    }

    /// Downloads the selected remote files (not folders) into the local folder.
    pub fn download_selected(&mut self, settings: TransferSettings) {
        if !self.is_connected() || self.remote_selected.is_empty() { return; }
        let files: Vec<RemoteEntry> = self.remote_entries.iter()
            .filter(|entry| self.remote_selected.contains(&entry.path) && !entry.dir)
            .cloned().collect();
        if files.is_empty() {
            self.status = "Select one or more remote files to download".into();
            return;
        }
        let count = files.len();
        for entry in files {
            let local = self.path.join(&entry.name);
            self.start_job(Job::DownloadFile { remote: entry.path, local, size: entry.size }, settings);
        }
        self.status = format!("Queued {count} download(s) to {}", self.path.display());
    }

    /// Queues `job` as a new transfer. `settings` only matter for downloads.
    fn start_job(&mut self, job: Job, settings: TransferSettings) -> bool {
        let Some(connection) = self.connection.clone() else {
            self.status = "Connect to the server first".into();
            return false;
        };
        let id = self.next_id();
        let name_of = |path: &str| path.rsplit(['/', '\\']).find(|part| !part.is_empty()).unwrap_or(path).to_owned();
        match job.clone() {
            Job::DownloadFile { remote, local, size } => {
                self.transfers.push(TransferItem::queued(id, name_of(&remote), local.clone(), size, true));
                self.record(id, "download", remote.clone(), local.display().to_string());
                self.spawn_transfer(id, "Downloading", move |progress, cancel| async move {
                    connection.download(&remote, &local, settings, Some(progress), cancel).await.map_err(|e| e.to_string())
                });
            }
            Job::DownloadPath { remote, local, .. } => {
                self.transfers.push(TransferItem::queued(id, name_of(&remote), local.clone(), 0, true));
                self.record(id, "download", remote.clone(), local.display().to_string());
                self.spawn_transfer(id, "Downloading", move |progress, cancel| async move {
                    connection.download_path(&remote, &local, settings, Some(progress), cancel).await.map_err(|e| e.to_string())
                });
            }
            Job::UploadPath { local, remote, .. } => {
                let total = fs::metadata(&local).map(|meta| if meta.is_file() { meta.len() } else { 0 }).unwrap_or(0);
                self.transfers.push(TransferItem::queued(id, name_of(&local.to_string_lossy()), local.clone(), total, false));
                self.record(id, "upload", local.display().to_string(), remote.clone());
                self.spawn_transfer(id, "Uploading", move |progress, cancel| async move {
                    connection.upload_path(&local, &remote, Some(progress), cancel).await.map_err(|e| e.to_string())
                });
            }
        }
        if let Some(item) = self.transfers.iter_mut().find(|item| item.id == id) {
            item.job = Some(job.clone());
        }
        self.operation_jobs.insert(id, job);
        true
    }

    /// Whether the transfer row `id` can be retried.
    pub fn can_retry(&self, id: usize) -> bool {
        self.is_connected() && self.transfers.iter().any(|item| item.id == id && item.is_failed() && item.job.is_some())
    }

    /// Runs a failed or stopped transfer row again as a new transfer; the
    /// failed row is removed. A row of a folder transfer retries just its file.
    pub fn retry(&mut self, id: usize, settings: TransferSettings) {
        let Some((name, job)) = self.transfers.iter()
            .find(|item| item.id == id && item.is_failed())
            .and_then(|item| Some((item.name.clone(), item.job.clone()?)))
        else {
            return;
        };
        if self.start_job(job, settings) {
            self.status = format!("Retrying {name}");
            self.transfers.retain(|item| item.id != id);
            if self.selected_transfer == Some(id) {
                self.selected_transfer = None;
            }
        }
    }

    /// Retries every failed or stopped row; returns how many were queued.
    pub fn retry_all_failed(&mut self, settings: TransferSettings) -> usize {
        let ids: Vec<usize> = self.transfers.iter().filter(|item| item.is_failed() && item.job.is_some()).map(|item| item.id).collect();
        for &id in &ids {
            self.retry(id, settings);
        }
        if !ids.is_empty() {
            self.status = format!("Retrying {} transfer(s)", ids.len());
        }
        ids.len()
    }

    /// Uploads a local file or folder (recursively) into the current remote folder.
    pub fn queue_upload(&mut self, local_path: PathBuf) {
        if !self.is_connected() {
            self.status = "Connect to a remote server before uploading".into();
            return;
        }
        let Some(name) = local_path.file_name().map(|name| name.to_string_lossy().into_owned()) else {
            self.status = "Cannot upload this filesystem path".into();
            return;
        };
        let remote_destination = crate::app::join_remote(&self.remote_path, &name);
        let dir = local_path.is_dir();
        let job = Job::UploadPath { local: local_path, remote: remote_destination.clone(), dir };
        // Upload jobs do not use transfer settings.
        if self.start_job(job, TransferSettings::default()) {
            self.status = format!("Queued recursive upload: {name} → {remote_destination}");
        }
    }

    /// Downloads a remote file or folder (recursively) into the local folder.
    pub fn queue_download(&mut self, remote_path: String, settings: TransferSettings) {
        if !self.is_connected() { return; }
        let name = remote_path.rsplit('/').find(|part| !part.is_empty()).unwrap_or(&remote_path).to_owned();
        let destination = self.path.join(&name);
        // From the listing; an unknown path is treated as a folder.
        let dir = self.remote_entries.iter().find(|entry| entry.path == remote_path).is_none_or(|entry| entry.dir);
        let job = Job::DownloadPath { remote: remote_path.clone(), local: destination.clone(), dir };
        if self.start_job(job, settings) {
            self.status = format!("Queued recursive download: {remote_path} → {}", destination.display());
        }
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
                let parent = self.transfers.iter().find(|item| item.id == id);
                let child_state = parent.map(|item| item.state.clone()).unwrap_or_else(|| "Downloading".into());
                let download = parent.is_none_or(|item| item.download);
                self.transfers.retain(|item| item.id != id);
                let child_id = self.next_id();
                let now = Instant::now();
                let mut child = TransferItem::queued(child_id, relative.clone(), PathBuf::from(relative), progress.total_bytes, download);
                child.operation_id = Some(id);
                child.job = self.operation_jobs.get(&id).map(|job| job.child(relative));
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
            // Initial "queued" updates carry no bytes and say nothing about the
            // protocol; a turbo download that falls back switches to SFTP here.
            let moving = progress.transferred_bytes > 0
                || progress.file_complete
                || progress.segment.as_ref().is_some_and(|segment| segment.transferred_bytes > 0 || segment.complete);
            if progress.accelerated {
                item.protocol = Some("UDP");
            } else if moving {
                item.protocol = Some("SFTP");
            }
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
        self.operations.remove(&id);
        let cancelled = self.cancelled_operations.remove(&id) && result.is_err();
        let child_exists = self.transfers.iter().any(|item| item.operation_id == Some(id));
        self.operation_jobs.remove(&id);
        if let Some(record) = self.transfer_records.remove(&id) {
            let elapsed = record.started.map(|start| now.saturating_duration_since(start)).unwrap_or_default();
            let (severity, message) = match &result {
                Ok(done) => {
                    let rate = done.bytes as f64 / elapsed.as_secs_f64().max(0.001) / (1024.0 * 1024.0);
                    let via = if done.accelerated { "rsftp-turbo (UDP)" } else { "SFTP" };
                    let details = done.details.as_deref().map(|details| format!(" [{details}]")).unwrap_or_default();
                    (Severity::Notice, format!(
                        "Completed {} {} -> {} via {via}: {} bytes in {:.1} s ({rate:.2} MiB/s){details}",
                        record.direction, record.source, record.target, done.bytes, elapsed.as_secs_f64()
                    ))
                }
                Err(_) if cancelled => (Severity::Notice, format!(
                    "Cancelled {} {} -> {} by user", record.direction, record.source, record.target
                )),
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
                    item.protocol = Some(if result.accelerated { "UDP" } else { "SFTP" });
                    item.details = result.details.clone();
                }
            }
            Err(error) => {
                let state = if cancelled { "Cancelled".to_owned() } else { format!("Failed: {error}") };
                let mut marked = false;
                for item in self.transfers.iter_mut().filter(|item| item.operation_id == Some(id)) {
                    if item.state != "Complete" {
                        item.finished_at = Some(now);
                        if !cancelled {
                            for segment in &mut item.segments {
                                if !segment.complete { segment.failed = true; }
                            }
                        }
                        item.speed_mib_s = 0.0;
                        item.state = state.clone();
                    }
                    marked = true;
                }
                if !marked {
                    if let Some(item) = self.transfers.iter_mut().find(|item| item.id == id) {
                        item.finished_at = Some(now);
                        item.speed_mib_s = 0.0;
                        item.state = state;
                    }
                }
                if cancelled {
                    self.status = "Transfer stopped".into();
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

    /// Selected local items that can be uploaded (the ".." row cannot).
    pub fn uploadable_selection(&self) -> Vec<PathBuf> {
        let parent = self.path.parent();
        self.local_selected.iter().filter(|path| Some(path.as_path()) != parent).cloned().collect()
    }

    pub fn can_upload(&self) -> bool {
        self.is_connected() && !self.uploadable_selection().is_empty()
    }
}


/// True unless `path` is already absolute and free of `.`/`..` segments.
pub(crate) fn needs_canonical_path(path: &str) -> bool {
    !path.starts_with('/') || path.split('/').any(|part| part == "." || part == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(name: &str, dir: bool, size: u64, modified: &str) -> LocalEntry {
        LocalEntry { name: name.into(), path: PathBuf::from(name), dir, size, modified: modified.into() }
    }

    #[test]
    fn sorting_keeps_folders_first_and_flips_on_toggle() {
        let mut rows = vec![
            local("b.txt", false, 5, "2026-01-02T00:00:00Z"),
            local("zdir", true, 0, "2026-01-01T00:00:00Z"),
            local("a.txt", false, 9, "2026-01-03T00:00:00Z"),
            local("adir", true, 0, "2026-01-04T00:00:00Z"),
        ];
        let names = |rows: &[LocalEntry]| rows.iter().map(|row| row.name.clone()).collect::<Vec<_>>();
        let mut order = SortOrder::default();
        sort_rows(&mut rows, order);
        assert_eq!(names(&rows), ["adir", "zdir", "a.txt", "b.txt"]);
        order.toggle(SortColumn::Size);
        sort_rows(&mut rows, order);
        assert_eq!(names(&rows), ["adir", "zdir", "b.txt", "a.txt"]);
        order.toggle(SortColumn::Size);
        assert!(!order.ascending);
        sort_rows(&mut rows, order);
        assert_eq!(names(&rows), ["zdir", "adir", "a.txt", "b.txt"]);
        order.toggle(SortColumn::Modified);
        sort_rows(&mut rows, order);
        assert_eq!(names(&rows), ["zdir", "adir", "b.txt", "a.txt"]);
    }

    #[test]
    fn folder_rows_retry_their_own_file() {
        let download = Job::DownloadPath { remote: "/srv/media".into(), local: PathBuf::from("/home/u/media"), dir: true };
        assert_eq!(
            download.child("show/ep1.mkv"),
            Job::DownloadPath { remote: "/srv/media/show/ep1.mkv".into(), local: PathBuf::from("/home/u/media/show/ep1.mkv"), dir: false }
        );
        let upload = Job::UploadPath { local: PathBuf::from("/home/u/docs"), remote: "/srv/docs".into(), dir: true };
        assert_eq!(
            upload.child("a/b.txt"),
            Job::UploadPath { local: PathBuf::from("/home/u/docs/a/b.txt"), remote: "/srv/docs/a/b.txt".into(), dir: false }
        );
        // A single file's row is the file itself, even if a folder shares its name.
        let file = Job::DownloadPath { remote: "/srv/a".into(), local: PathBuf::from("/home/u/a"), dir: false };
        assert_eq!(file.child("a"), file);
    }

    #[test]
    fn clicks_select_toggle_and_range() {
        let order: Vec<u32> = (1..=6).collect();
        let (mut selected, mut anchor) = (Vec::new(), None);
        select_click(&mut selected, &mut anchor, &order, &2, false, false);
        assert_eq!(selected, [2]);
        select_click(&mut selected, &mut anchor, &order, &4, true, false);
        assert_eq!(selected, [2, 4]);
        select_click(&mut selected, &mut anchor, &order, &4, true, false);
        assert_eq!((selected.clone(), anchor), (vec![2], Some(4)));
        select_click(&mut selected, &mut anchor, &order, &6, false, true);
        assert_eq!(selected, [4, 5, 6]);
        select_click(&mut selected, &mut anchor, &order, &1, true, true);
        assert_eq!(selected, [4, 5, 6, 1, 2, 3]);
        select_click(&mut selected, &mut anchor, &order, &3, false, false);
        assert_eq!((selected.clone(), anchor), (vec![3], Some(3)));
    }

    #[test]
    fn only_clean_absolute_paths_skip_canonicalisation() {
        assert!(needs_canonical_path("."));
        assert!(needs_canonical_path(".."));
        assert!(needs_canonical_path("docs"));
        assert!(needs_canonical_path("/home/alice/.."));
        assert!(needs_canonical_path("/home/./alice"));
        assert!(!needs_canonical_path("/"));
        assert!(!needs_canonical_path("/home/alice/.config"));
        assert!(!needs_canonical_path("/C:/Users/alice"));
    }
}
