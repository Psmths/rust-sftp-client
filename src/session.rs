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
    conflict::ConflictAction,
    connection::{
        existing_local_targets, plan_upload, ConnectError, ConnectionProfile, NetworkSettings, SftpConnection, TargetFile,
        TransferPlan,
    },
    logging::{Category, LogEntry, Logger, SessionLog, Severity},
    search::{self, Search, SearchKey},
    terminal::{Terminal, TerminalSettings},
    transfer::{CancelToken, DownloadProgress, DownloadResult, SegmentProgress, TransferSettings},
};

#[derive(Clone)]
pub struct LocalEntry {
    pub name: String,
    pub path: PathBuf,
    pub dir: bool,
    pub size: u64,
    pub modified: String,
    /// Dot name, or (Windows) marked hidden.
    pub hidden: bool,
    /// For recursive search results: the folder relative to the searched one.
    pub folder: String,
}

impl LocalEntry {
    /// Name as listed: with its relative folder for search results.
    pub fn label(&self) -> String {
        if self.folder.is_empty() { self.name.clone() } else { format!("{}{}{}", self.folder, std::path::MAIN_SEPARATOR, self.name) }
    }
}

#[derive(Clone)]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub dir: bool,
    pub size: u64,
    pub modified: String,
    /// For recursive search results: the folder relative to the searched one.
    pub folder: String,
}

impl RemoteEntry {
    pub fn label(&self) -> String {
        if self.folder.is_empty() { self.name.clone() } else { format!("{}/{}", self.folder, self.name) }
    }

    pub fn hidden(&self) -> bool {
        self.name.starts_with('.')
    }
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

/// A transfer the user asked for, with what it would write and which of
/// those files exist already (checked before it is queued).
pub struct PreparedJob {
    pub job: Job,
    pub settings: TransferSettings,
    /// `None` when listing failed; the transfer then runs and reports the error.
    pub plan: Option<TransferPlan>,
    /// For each file of `plan`: the file it would overwrite.
    pub targets: Vec<Option<TargetFile>>,
}

impl PreparedJob {
    pub fn download(&self) -> bool {
        !matches!(self.job, Job::UploadPath { .. })
    }

    /// Files that exist already, as indices into the plan's files.
    pub fn conflicts(&self) -> impl Iterator<Item = usize> + '_ {
        self.targets.iter().enumerate().filter(|(_, target)| target.is_some()).map(|(index, _)| index)
    }
}

/// Transfers waiting for the user to decide about files that exist already.
pub struct ConflictPrompt {
    pub jobs: Vec<PreparedJob>,
    /// The action selected in the dialog.
    pub action: ConflictAction,
    /// "Apply to all further conflicts in this session".
    pub remember: bool,
}

impl ConflictPrompt {
    /// Every existing file as (job index, file index).
    pub fn conflicts(&self) -> Vec<(usize, usize)> {
        self.jobs.iter().enumerate().flat_map(|(job, prepared)| prepared.conflicts().map(move |file| (job, file))).collect()
    }

    /// Files that do not exist yet.
    pub fn new_files(&self) -> usize {
        self.jobs.iter().map(|prepared| prepared.targets.iter().filter(|target| target.is_none()).count()).sum()
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
    /// A folder transfer: its row sums up the rows of its files, which have
    /// this row's id as `operation_id`.
    pub folder: bool,
    /// The folder's file rows are shown below it.
    pub expanded: bool,
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
            folder: false,
            expanded: false,
        }
    }

    /// Updates the speed from the byte count at `now` (sampled at most every 250 ms).
    fn sample_speed(&mut self, transferred: u64, now: Instant) {
        if transferred < self.last_speed_sample_bytes {
            // A segment retry rolled the counter back.
            self.last_speed_sample_bytes = transferred;
            self.last_speed_sample_at = Some(now);
            self.speed_mib_s = 0.0;
        } else if let Some(sampled_at) = self.last_speed_sample_at {
            let elapsed = now.saturating_duration_since(sampled_at);
            if elapsed >= Duration::from_millis(250) {
                let delta = transferred - self.last_speed_sample_bytes;
                self.speed_mib_s = delta as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
                self.last_speed_sample_bytes = transferred;
                self.last_speed_sample_at = Some(now);
            }
        } else {
            self.last_speed_sample_at = Some(now);
            self.last_speed_sample_bytes = transferred;
        }
    }

    /// State while data moves: "Downloading" or "Uploading".
    fn active_state(&self) -> &'static str {
        if self.download { "Downloading" } else { "Uploading" }
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
    Terminal,
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
/// Transfer speeds are measured every 250 ms; the graph samples them as often.
const SPEED_SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

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
    /// "Recursive" box next to the filter: search the whole tree below.
    pub local_recursive: bool,
    pub local_search: Option<Search<LocalEntry>>,
    /// Filter text and when it last changed, to start searches after typing pauses.
    local_filter_seen: (String, Instant),

    pub remote_path: String,
    pub remote_entries: Vec<RemoteEntry>,
    pub remote_filter: String,
    pub remote_selected: Vec<String>,
    pub remote_anchor: Option<String>,
    pub remote_sort: SortOrder,
    pub remote_recursive: bool,
    pub remote_search: Option<Search<RemoteEntry>>,
    remote_filter_seen: (String, Instant),
    /// Show hidden items (set by the app from its settings every frame).
    pub show_hidden: bool,

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
    /// When the pending listing was requested, and for which path.
    list_started: Option<(Instant, String)>,

    pub transfers: Vec<TransferItem>,
    pub queue_tab: QueueTab,
    next_transfer_id: usize,
    queue_tx: std_mpsc::Sender<QueueEvent>,
    queue_rx: std_mpsc::Receiver<QueueEvent>,
    /// One permit per file being transferred: individual files and the files
    /// of folder transfers share them.
    transfer_slots: Arc<Semaphore>,
    transfer_records: HashMap<usize, TransferRecord>,
    /// Job of each running operation, for the rows of its files.
    operation_jobs: HashMap<usize, Job>,
    /// Cancel tokens of operations that have not finished, by operation id.
    operations: HashMap<usize, CancelToken>,
    /// Operations the user stopped; their failure is shown as "Cancelled".
    cancelled_operations: HashSet<usize>,
    /// Transfers asked for this frame, checked for existing files together.
    incoming: Vec<(Job, TransferSettings)>,
    /// The check for existing files in progress.
    scan_rx: Option<std_mpsc::Receiver<Vec<PreparedJob>>>,
    /// Files exist already: the app asks what to do.
    pub conflict_prompt: Option<ConflictPrompt>,
    /// Decision applied to all further conflicts in this session.
    pub remembered_action: Option<ConflictAction>,
    /// Rows of folder transfers: (operation id, relative path) -> row id.
    folder_rows: HashMap<(usize, String), usize>,
    /// Bytes (downloaded, uploaded) of rows removed with "Clear", so the
    /// statistics keep counting them.
    cleared_bytes: (u64, u64),
    /// Row selected in the transfer queue.
    pub selected_transfer: Option<usize>,
    /// One sample per second, oldest first, for the statistics graph.
    pub speed_history: VecDeque<SpeedSample>,
    pub connected_at: Option<Instant>,
    /// Interactive shell of the "SSH Terminal" tab, opened when first shown.
    pub terminal: Option<Terminal>,

    pub status: String,
}

impl Session {
    /// `file_slots`: files transferred at the same time (see [`Session::set_concurrency`]).
    pub fn new(id: u64, runtime: Handle, logger: Arc<Logger>, path: PathBuf, file_slots: usize) -> Self {
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
            local_recursive: false,
            local_search: None,
            local_filter_seen: (String::new(), Instant::now()),
            remote_path: String::new(),
            remote_entries: Vec::new(),
            remote_filter: String::new(),
            remote_selected: Vec::new(),
            remote_anchor: None,
            remote_sort: SortOrder::default(),
            remote_recursive: false,
            remote_search: None,
            remote_filter_seen: (String::new(), Instant::now()),
            show_hidden: true,
            connection: None,
            profile: None,
            created_for_connect: false,
            pending_password: None,
            pending_fingerprint: None,
            connect_rx: None,
            list_rx: None,
            home_fallback: false,
            list_started: None,
            transfers: Vec::new(),
            queue_tab: QueueTab::Pending,
            next_transfer_id: 1,
            queue_tx,
            queue_rx,
            transfer_slots: Arc::new(Semaphore::new(file_slots.max(1))),
            transfer_records: HashMap::new(),
            operation_jobs: HashMap::new(),
            operations: HashMap::new(),
            cancelled_operations: HashSet::new(),
            incoming: Vec::new(),
            scan_rx: None,
            conflict_prompt: None,
            remembered_action: None,
            folder_rows: HashMap::new(),
            cleared_bytes: (0, 0),
            selected_transfer: None,
            speed_history: VecDeque::new(),
            connected_at: None,
            terminal: None,
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
        self.searching_local() && self.local_search.as_ref().is_none_or(|search| !search.done)
            || self.searching_remote() && self.remote_search.as_ref().is_none_or(|search| !search.done)
            || self.connect_rx.is_some()
            || self.list_rx.is_some()
            || self.transfers.iter().any(TransferItem::is_pending)
            || self.connection.as_ref().is_some_and(|connection| {
                connection.turbo_info().state == crate::connection::TurboState::Testing
            })
    }

    fn log_event(&self, category: Category, severity: Severity, msgid: &str, message: &str) {
        self.logger.log(&self.log, category, severity, msgid, message);
    }

    /// A callback that writes connection events to this session's log.
    fn event_log(&self) -> crate::connection::EventLog {
        let (logger, log) = (Arc::clone(&self.logger), self.log.clone());
        Arc::new(move |severity, msgid, message| logger.log(&log, Category::Connection, severity, msgid, message))
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
        self.transfers.iter().filter(|item| item.operation_id.is_none()).fold(self.cleared_bytes, |(down, up), item| {
            if item.download { (down + item.transferred, up) } else { (down, up + item.transferred) }
        })
    }

    // ----- recursive search -----

    /// Remote entries the pane shows: search results while searching, else the folder.
    pub fn remote_shown(&self) -> Box<dyn Iterator<Item = &RemoteEntry> + '_> {
        match (&self.remote_search, self.searching_remote()) {
            (Some(search), true) => Box::new(search.results.iter()),
            _ => Box::new(self.remote_entries.iter()),
        }
    }

    /// The local pane shows recursive search results instead of the folder.
    pub fn searching_local(&self) -> bool {
        self.local_recursive && !self.local_filter.trim().is_empty()
    }

    pub fn searching_remote(&self) -> bool {
        self.remote_recursive && !self.remote_filter.trim().is_empty() && self.is_connected()
    }

    /// Starts, restarts or stops the recursive searches to match the filters
    /// (once typing pauses) and takes in their results. Call every frame.
    pub fn update_searches(&mut self) {
        const TYPING_PAUSE: Duration = Duration::from_millis(300);
        let now = Instant::now();
        if self.local_filter != self.local_filter_seen.0 {
            self.local_filter_seen = (self.local_filter.clone(), now);
        }
        if self.remote_filter != self.remote_filter_seen.0 {
            self.remote_filter_seen = (self.remote_filter.clone(), now);
        }

        if self.searching_local() {
            let key = SearchKey {
                query: self.local_filter.trim().to_lowercase(),
                root: self.path.display().to_string(),
                show_hidden: self.show_hidden,
            };
            let stale = self.local_search.as_ref().is_none_or(|search| search.key != key);
            if stale && now.saturating_duration_since(self.local_filter_seen.1) >= TYPING_PAUSE {
                self.local_search = Some(search::local(self.path.clone(), key));
            }
        } else {
            self.local_search = None;
        }
        if let Some(search) = &mut self.local_search {
            search.poll();
        }

        match self.connection.clone().filter(|_| self.searching_remote()) {
            Some(connection) => {
                let key = SearchKey {
                    query: self.remote_filter.trim().to_lowercase(),
                    root: self.remote_path.clone(),
                    show_hidden: self.show_hidden,
                };
                let stale = self.remote_search.as_ref().is_none_or(|search| search.key != key);
                if stale && now.saturating_duration_since(self.remote_filter_seen.1) >= TYPING_PAUSE {
                    self.remote_search = Some(search::remote(&self.runtime, connection, self.remote_path.clone(), key));
                }
            }
            None => self.remote_search = None,
        }
        if let Some(search) = &mut self.remote_search {
            search.poll();
        }
    }

    // ----- local side -----

    pub fn refresh_local(&mut self) {
        // A search below this folder is run again with the fresh contents.
        self.local_search = None;
        self.local_entries.clear();
        if let Ok(read_dir) = fs::read_dir(&self.path) {
            for item in read_dir.flatten() {
                let path = item.path();
                if let Ok(meta) = item.metadata() {
                    let name = item.file_name().to_string_lossy().into_owned();
                    self.local_entries.push(LocalEntry {
                        hidden: crate::search::is_hidden_local(&name, Some(&meta)),
                        name,
                        path,
                        dir: meta.is_dir(),
                        size: meta.len(),
                        modified: meta.modified().ok().map(crate::app::format_iso8601).unwrap_or_else(|| "—".into()),
                        folder: String::new(),
                    });
                }
            }
            self.log_event(Category::Connection, Severity::Info, "LIST", &format!(
                "Listed local {}: {} entries", self.path.display(), self.local_entries.len()
            ));
        } else {
            self.status = format!("Cannot read {}", self.path.display());
            self.log_event(Category::Connection, Severity::Error, "LIST", &format!("Could not list local {}", self.path.display()));
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
        let events = self.event_log();
        // Listed through the rsftp-turbo helper while the SFTP channels open.
        let start_folder = Some(start_folder(&profile).0);
        self.runtime.spawn(async move {
            let result = SftpConnection::connect(&profile, password.as_deref(), trusted.as_deref(), network, events, start_folder).await;
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
                let (folder, is_default) = self.profile.as_ref().map(start_folder).unwrap_or_else(|| (".".into(), false));
                let early = self.connection.as_ref().and_then(|connection| connection.take_early_listing());
                match early {
                    // Already listed during connect: hand it to the usual listing handling.
                    Some((result, took)) => {
                        let (tx, rx) = std_mpsc::channel();
                        let _ = tx.send(result.map(|(path, listed)| {
                            let entries = remote_entries(&path, listed);
                            (path, entries)
                        }));
                        self.list_rx = Some(rx);
                        self.list_started = Some((Instant::now().checked_sub(took).unwrap_or_else(Instant::now), folder));
                    }
                    None => self.load_remote(&folder),
                }
                self.home_fallback = is_default;
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

    /// The shell of the "SSH Terminal" tab, opened on the current connection
    /// with `rows` x `cols` characters if it has none yet. None while not connected.
    pub fn terminal(
        &mut self,
        ctx: &eframe::egui::Context,
        settings: &TerminalSettings,
        rows: u16,
        cols: u16,
    ) -> Option<&mut Terminal> {
        let connection = self.connection.as_ref()?;
        if !self.terminal.as_ref().is_some_and(|terminal| terminal.belongs_to(connection)) {
            self.terminal = Some(Terminal::open(&self.runtime, connection, ctx.clone(), settings, rows, cols));
        }
        self.terminal.as_mut()
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
        self.terminal = None;
        self.incoming.clear();
        self.scan_rx = None;
        self.conflict_prompt = None;
        self.remembered_action = None;
        self.remote_entries.clear();
        self.remote_selected.clear();
        self.status = "Disconnected".into();
    }

    // ----- remote side -----

    /// Lists `path` in the background. Relative paths and `.`/`..` are
    /// resolved on the server first, so `remote_path` is always absolute.
    pub fn load_remote(&mut self, path: &str) {
        let Some(connection) = self.connection.clone() else { return; };
        // A search below this folder is run again with the fresh contents.
        self.remote_search = None;
        self.home_fallback = false;
        let requested = if path.is_empty() { ".".to_owned() } else { path.to_owned() };
        let (tx, rx) = std_mpsc::channel();
        self.list_rx = Some(rx);
        self.list_started = Some((Instant::now(), requested.clone()));
        self.status = format!("Reading remote directory {requested} …");
        self.runtime.spawn(async move {
            let result = async {
                // Through the rsftp-turbo helper when it can list, else SFTP.
                let (path, listed) = connection.list_directory(&requested).await?;
                let entries = remote_entries(&path, listed);
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
        let (started, requested) = self.list_started.take().unwrap_or_else(|| (Instant::now(), String::new()));
        let elapsed = started.elapsed().as_millis();
        let via = match self.connection.as_ref().and_then(|connection| connection.listing_via_helper()) {
            Some(true) => "the rsftp-turbo helper",
            _ => "SFTP",
        };
        match &result {
            Ok((path, entries)) => self.log_event(Category::Connection, Severity::Info, "LIST", &format!(
                "Listed remote {path}: {} entries via {via} in {elapsed} ms", entries.len()
            )),
            Err(error) => self.log_event(Category::Connection, Severity::Error, "LIST", &format!(
                "Could not list remote {requested}: {error}"
            )),
        }
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

    /// Sets how many files are transferred at the same time.
    pub fn set_concurrency(&mut self, limit: usize) {
        // Transfers already queued keep the old limit; new ones use the new one.
        self.transfer_slots = Arc::new(Semaphore::new(limit.max(1)));
    }

    /// The transfer row `id`. Rows are kept in id order (ids only grow and
    /// rows are appended), so this is a binary search.
    fn transfer_mut(&mut self, id: usize) -> Option<&mut TransferItem> {
        let index = self.transfers.binary_search_by_key(&id, |item| item.id).ok()?;
        Some(&mut self.transfers[index])
    }

    fn transfer(&self, id: usize) -> Option<&TransferItem> {
        let index = self.transfers.binary_search_by_key(&id, |item| item.id).ok()?;
        Some(&self.transfers[index])
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

    /// Runs `work`, forwarding progress to the queue. With `needs_slot` it
    /// first waits for a free file slot; folder transfers take one per file
    /// themselves.
    fn spawn_transfer<F>(
        &mut self,
        id: usize,
        state: &'static str,
        needs_slot: bool,
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
            let permit = if needs_slot {
                tokio::select! {
                    permit = slots.acquire_owned() => permit.map(Some).map_err(|error| error.to_string()),
                    _ = cancel.cancelled() => Err("cancelled".to_owned()),
                }
            } else {
                Ok(None)
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
        let files: Vec<RemoteEntry> = self.remote_shown()
            .filter(|entry| self.remote_selected.contains(&entry.path) && !entry.dir)
            .cloned().collect();
        if files.is_empty() {
            self.status = "Select one or more remote files to download".into();
            return;
        }
        let count = files.len();
        for entry in files {
            let local = self.path.join(&entry.name);
            self.request_job(Job::DownloadFile { remote: entry.path, local, size: entry.size }, settings);
        }
        self.status = format!("Checking {count} download(s) to {} for existing files…", self.path.display());
    }

    /// Asks for `job`: the transfers asked for in one frame are checked for
    /// files that exist already (see [`Session::poll_transfer_checks`]) and
    /// then queued.
    fn request_job(&mut self, job: Job, settings: TransferSettings) {
        if !self.is_connected() {
            self.status = "Connect to the server first".into();
            return;
        }
        self.incoming.push((job, settings));
    }

    /// Starts checking the transfers asked for, and queues them (or asks the
    /// user about existing files) once the check is done. Call every frame.
    pub fn poll_transfer_checks(&mut self) {
        if let Some(rx) = &self.scan_rx {
            match rx.try_recv() {
                Ok(jobs) => {
                    self.scan_rx = None;
                    let prompt = ConflictPrompt { jobs, action: ConflictAction::default(), remember: false };
                    if prompt.conflicts().is_empty() {
                        self.queue_prepared(prompt.jobs, ConflictAction::Ignore);
                    } else if let Some(action) = self.remembered_action {
                        self.queue_prepared(prompt.jobs, action);
                    } else {
                        let count = prompt.conflicts().len();
                        self.status = format!("{count} file(s) exist already: choose what to do");
                        self.conflict_prompt = Some(prompt);
                    }
                }
                Err(std_mpsc::TryRecvError::Empty) => {}
                Err(std_mpsc::TryRecvError::Disconnected) => self.scan_rx = None,
            }
        }
        // One batch at a time: the next waits until this one is decided.
        if self.scan_rx.is_some() || self.conflict_prompt.is_some() || self.incoming.is_empty() {
            return;
        }
        let Some(connection) = self.connection.clone() else {
            self.incoming.clear();
            return;
        };
        let batch = std::mem::take(&mut self.incoming);
        let (tx, rx) = std_mpsc::channel();
        self.scan_rx = Some(rx);
        self.runtime.spawn(async move {
            let mut prepared = Vec::with_capacity(batch.len());
            for (job, settings) in batch {
                let (plan, targets) = match &job {
                    Job::DownloadFile { remote, local, .. } | Job::DownloadPath { remote, local, .. } => {
                        match connection.plan_download(remote, local).await {
                            Ok(plan) => {
                                let checked = plan.clone();
                                let targets = tokio::task::spawn_blocking(move || existing_local_targets(&checked)).await.unwrap_or_default();
                                (Some(plan), targets)
                            }
                            Err(_) => (None, Vec::new()),
                        }
                    }
                    Job::UploadPath { local, remote, .. } => match plan_upload(local, remote).await {
                        Ok(plan) => {
                            let targets = connection.existing_remote_targets(&plan).await;
                            (Some(plan), targets)
                        }
                        Err(_) => (None, Vec::new()),
                    },
                };
                prepared.push(PreparedJob { job, settings, plan, targets });
            }
            let _ = tx.send(prepared);
        });
    }

    /// Queues the transfers of the conflict prompt with `action` for the
    /// files that exist; `remember` applies it to later conflicts too.
    pub fn resolve_conflicts(&mut self, action: ConflictAction, remember: bool) {
        let Some(prompt) = self.conflict_prompt.take() else { return; };
        if remember {
            self.remembered_action = Some(action);
        }
        self.queue_prepared(prompt.jobs, action);
    }

    /// Drops the transfers of the conflict prompt.
    pub fn cancel_conflicts(&mut self) {
        if self.conflict_prompt.take().is_some() {
            self.status = "Transfer cancelled".into();
        }
    }

    /// Queues checked transfers, leaving out existing files that `action` keeps.
    fn queue_prepared(&mut self, jobs: Vec<PreparedJob>, action: ConflictAction) {
        let (mut queued, mut skipped) = (0, 0);
        for prepared in jobs {
            let PreparedJob { job, settings, plan, targets } = prepared;
            let Some(mut plan) = plan else {
                // Listing failed: the transfer reports why.
                queued += usize::from(self.start_job_planned(job, settings, None));
                continue;
            };
            let had_files = !plan.files.is_empty();
            skipped += leave_out_kept_files(&mut plan, &targets, action);
            // Everything exists and is kept: nothing to do.
            if had_files && plan.files.is_empty() {
                continue;
            }
            queued += usize::from(self.start_job_planned(job, settings, Some(plan)));
        }
        if skipped > 0 {
            let message = format!("Skipped {skipped} existing file(s) ({})", action.label());
            self.log_event(Category::Transfer, Severity::Info, "TRANSFER", &message);
        }
        self.status = match (queued, skipped) {
            (0, 0) => "Nothing to transfer".into(),
            (queued, 0) => format!("Queued {queued} transfer(s)"),
            (queued, skipped) => format!("Queued {queued} transfer(s); skipped {skipped} existing file(s)"),
        };
    }

    /// Queues `job` as a new transfer. `settings` only matter for downloads.
    fn start_job(&mut self, job: Job, settings: TransferSettings) -> bool {
        self.start_job_planned(job, settings, None)
    }

    /// Queues `job`, transferring the files of `plan` (or, without one,
    /// everything the job covers).
    fn start_job_planned(&mut self, job: Job, settings: TransferSettings, plan: Option<TransferPlan>) -> bool {
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
                self.spawn_transfer(id, "Downloading", true, move |progress, cancel| async move {
                    connection.download(&remote, &local, settings, Some(progress), cancel).await.map_err(|e| e.to_string())
                });
            }
            Job::DownloadPath { remote, local, dir } => {
                let mut item = TransferItem::queued(id, name_of(&remote), local.clone(), 0, true);
                item.folder = dir;
                self.transfers.push(item);
                self.record(id, "download", remote.clone(), local.display().to_string());
                let slots = Arc::clone(&self.transfer_slots);
                self.spawn_transfer(id, "Downloading", false, move |progress, cancel| async move {
                    connection.download_path(&remote, &local, settings, slots, plan, Some(progress), cancel).await.map_err(|e| e.to_string())
                });
            }
            Job::UploadPath { local, remote, dir } => {
                let total = fs::metadata(&local).map(|meta| if meta.is_file() { meta.len() } else { 0 }).unwrap_or(0);
                let mut item = TransferItem::queued(id, name_of(&local.to_string_lossy()), local.clone(), total, false);
                item.folder = dir;
                self.transfers.push(item);
                self.record(id, "upload", local.display().to_string(), remote.clone());
                let slots = Arc::clone(&self.transfer_slots);
                self.spawn_transfer(id, "Uploading", false, move |progress, cancel| async move {
                    connection.upload_path(&local, &remote, slots, plan, Some(progress), cancel).await.map_err(|e| e.to_string())
                });
            }
        }
        if let Some(item) = self.transfer_mut(id) {
            item.job = Some(job.clone());
        }
        self.operation_jobs.insert(id, job);
        true
    }

    /// Whether the transfer row `id` can be retried.
    pub fn can_retry(&self, id: usize) -> bool {
        self.is_connected() && self.transfer(id).is_some_and(|item| item.is_failed() && item.job.is_some())
    }

    /// Failed or stopped file rows of the folder transfer `id` that can be retried.
    fn failed_children(&self, id: usize) -> Vec<usize> {
        self.transfers.iter()
            .filter(|item| item.operation_id == Some(id) && item.is_failed() && item.job.is_some())
            .map(|item| item.id)
            .collect()
    }

    /// Runs a failed or stopped transfer row again as a new transfer; the
    /// failed row is removed. A file row of a folder transfer retries just
    /// its file; a folder row retries its failed files (or the whole folder
    /// if it failed before listing any). Returns how many transfers were queued.
    pub fn retry(&mut self, id: usize, settings: TransferSettings) -> usize {
        let Some(item) = self.transfer(id).filter(|item| item.is_failed()) else { return 0; };
        if item.folder {
            let children = self.failed_children(id);
            if !children.is_empty() {
                let count = children.into_iter().map(|child| self.retry(child, settings)).sum();
                self.status = format!("Retrying {count} file(s) of {}", self.transfer(id).map(|item| item.name.as_str()).unwrap_or("the folder"));
                return count;
            }
        }
        let Some((name, job, parent)) = self.transfer(id).and_then(|item| Some((item.name.clone(), item.job.clone()?, item.operation_id))) else {
            return 0;
        };
        if !self.start_job(job, settings) {
            return 0;
        }
        self.status = format!("Retrying {name}");
        self.remove_rows(&HashSet::from([id]));
        if let Some(parent) = parent {
            self.refresh_folder_after_retry(parent);
        }
        1
    }

    /// A folder row after one of its files was retried as its own transfer:
    /// its totals drop that file, and with no failed file left it counts as
    /// complete (or disappears when it has no files left).
    fn refresh_folder_after_retry(&mut self, parent: usize) {
        let (mut transferred, mut total, mut children, mut failed) = (0, 0, 0, 0);
        for item in self.transfers.iter().filter(|item| item.operation_id == Some(parent)) {
            transferred += item.transferred;
            total += item.total;
            children += 1;
            failed += usize::from(item.is_failed());
        }
        if children == 0 {
            self.remove_rows(&HashSet::from([parent]));
            return;
        }
        if let Some(folder) = self.transfer_mut(parent) {
            folder.transferred = transferred;
            folder.total = total;
            if failed == 0 {
                folder.state = "Complete".into();
            }
        }
    }

    /// Retries every failed or stopped transfer; returns how many were queued.
    pub fn retry_all_failed(&mut self, settings: TransferSettings) -> usize {
        let ids: Vec<usize> = self.transfers.iter()
            .filter(|item| item.operation_id.is_none() && item.is_failed() && item.job.is_some())
            .map(|item| item.id)
            .collect();
        let count = ids.into_iter().map(|id| self.retry(id, settings)).sum();
        if count > 0 {
            self.status = format!("Retrying {count} transfer(s)");
        }
        count
    }

    /// Removes the finished transfers listed in `tab` (Complete or Failed),
    /// with the file rows of folder transfers. Returns how many were removed.
    pub fn clear_tab(&mut self, tab: QueueTab) -> usize {
        let cleared: HashSet<usize> = self.transfers.iter()
            .filter(|item| item.operation_id.is_none() && item.tab() == tab && !item.is_pending() && !self.operations.contains_key(&item.id))
            .map(|item| item.id)
            .collect();
        let (down, up) = self.transfers.iter()
            .filter(|item| cleared.contains(&item.id))
            .fold((0, 0), |(down, up), item| if item.download { (down + item.transferred, up) } else { (down, up + item.transferred) });
        self.cleared_bytes.0 += down;
        self.cleared_bytes.1 += up;
        self.remove_rows(&cleared);
        cleared.len()
    }

    /// Shows or hides the file rows of the folder transfer `id`.
    pub fn toggle_expanded(&mut self, id: usize) {
        if let Some(item) = self.transfer_mut(id).filter(|item| item.folder) {
            item.expanded = !item.expanded;
        }
    }

    /// Removes the rows `ids` and the file rows of those that are folders.
    fn remove_rows(&mut self, ids: &HashSet<usize>) {
        self.transfers.retain(|item| !ids.contains(&item.id) && !item.operation_id.is_some_and(|operation| ids.contains(&operation)));
        self.folder_rows.retain(|(operation, _), row| !ids.contains(operation) && !ids.contains(row));
        if self.selected_transfer.is_some_and(|selected| self.transfer(selected).is_none()) {
            self.selected_transfer = None;
        }
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
        self.request_job(job, TransferSettings::default());
        self.status = format!("Checking {name} → {remote_destination} for existing files…");
    }

    /// Downloads a remote file or folder (recursively) into the local folder.
    pub fn queue_download(&mut self, remote_path: String, settings: TransferSettings) {
        if !self.is_connected() { return; }
        let name = remote_path.rsplit('/').find(|part| !part.is_empty()).unwrap_or(&remote_path).to_owned();
        let destination = self.path.join(&name);
        // From the listing; an unknown path is treated as a folder.
        let dir = self.remote_entries.iter()
            .chain(self.remote_search.iter().flat_map(|search| search.results.iter()))
            .find(|entry| entry.path == remote_path)
            .is_none_or(|entry| entry.dir);
        let job = Job::DownloadPath { remote: remote_path.clone(), local: destination.clone(), dir };
        self.request_job(job, settings);
        self.status = format!("Checking {remote_path} → {} for existing files…", destination.display());
    }

    pub fn speed(&self, state: &str) -> f64 {
        // Folder rows carry the speed of their files.
        self.transfers.iter()
            .filter(|item| item.operation_id.is_none() && item.state == state)
            .map(|item| item.speed_mib_s)
            .sum()
    }

    pub fn poll_queue(&mut self) {
        while let Ok(event) = self.queue_rx.try_recv() {
            match event {
                QueueEvent::Started { id, state } => {
                    if let Some(item) = self.transfer_mut(id) {
                        let now = Instant::now();
                        item.started_at = Some(now);
                        item.last_speed_sample_at = Some(now);
                        item.last_speed_sample_bytes = 0;
                        item.speed_mib_s = 0.0;
                        // Folder transfers start at once; a file waits for a slot.
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
        let now = Instant::now();
        let folder = self.transfer(id).is_some_and(|item| item.folder);
        // Progress of a file in a folder transfer goes to that file's row,
        // which is created on its first report.
        let target_id = match progress.file_path.as_ref() {
            Some(relative) if folder => match self.folder_rows.get(&(id, relative.clone())) {
                Some(&row) => row,
                None => {
                    let download = self.transfer(id).is_none_or(|item| item.download);
                    let child_id = self.next_id();
                    let mut child = TransferItem::queued(child_id, relative.clone(), PathBuf::from(relative), 0, download);
                    child.operation_id = Some(id);
                    child.job = self.operation_jobs.get(&id).map(|job| job.child(relative));
                    self.transfers.push(child);
                    self.folder_rows.insert((id, relative.clone()), child_id);
                    child_id
                }
            },
            _ => id,
        };
        let mut completed_file = None;
        let mut change = None;
        if let Some(item) = self.transfer_mut(target_id) {
            let before = (item.transferred, item.total);
            item.sample_speed(progress.transferred_bytes, now);
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
                item.speed_mib_s = 0.0;
                if item.operation_id.is_some() {
                    completed_file = Some((item.name.clone(), item.total));
                }
            } else if moving && item.state == "Queued" {
                item.started_at.get_or_insert(now);
                item.state = item.active_state().into();
            }
            if let Some(segment) = progress.segment {
                if let Some(existing) = item.segments.iter_mut().find(|s| s.index == segment.index) {
                    *existing = segment;
                } else {
                    item.segments.push(segment);
                    item.segments.sort_by_key(|s| s.index);
                }
            }
            change = Some((before, (item.transferred, item.total), item.protocol));
        }
        // The folder row adds up its files.
        if let (true, Some(((old_done, old_total), (done, total), protocol))) = (target_id != id, change) {
            if let Some(parent) = self.transfer_mut(id) {
                let transferred = (parent.transferred + done).saturating_sub(old_done);
                parent.total = (parent.total + total).saturating_sub(old_total);
                parent.sample_speed(transferred, now);
                parent.transferred = transferred;
                parent.protocol = match (parent.protocol, protocol) {
                    (current, None) => current,
                    (None, new) => new,
                    (Some(current), Some(new)) if current == new => Some(current),
                    _ => Some("Mixed"),
                };
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
        let child_exists = self.folder_rows.keys().any(|(operation, _)| *operation == id);
        self.folder_rows.retain(|(operation, _), _| *operation != id);
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
                            item.speed_mib_s = 0.0;
                            item.state = "Complete".into();
                        }
                    }
                }
                if let Some(item) = self.transfer_mut(id) {
                    item.finished_at = Some(now);
                    item.speed_mib_s = 0.0;
                    item.state = "Complete".into();
                    item.details = result.details.clone();
                    if item.folder {
                        item.transferred = item.total.max(result.bytes);
                        item.total = item.transferred;
                        item.protocol.get_or_insert(if result.accelerated { "UDP" } else { "SFTP" });
                    } else {
                        item.transferred = result.bytes;
                        item.total = result.bytes;
                        item.protocol = Some(if result.accelerated { "UDP" } else { "SFTP" });
                    }
                }
            }
            Err(error) => {
                let state = if cancelled { "Cancelled".to_owned() } else { format!("Failed: {error}") };
                if child_exists {
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
                    }
                }
                if let Some(item) = self.transfer_mut(id) {
                    item.finished_at = Some(now);
                    item.speed_mib_s = 0.0;
                    item.state = state;
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


/// Removes from `plan` the existing files (`targets`, by file index) that
/// `action` keeps; returns how many were removed.
fn leave_out_kept_files(plan: &mut TransferPlan, targets: &[Option<TargetFile>], action: ConflictAction) -> usize {
    let before = plan.files.len();
    let mut index = 0;
    plan.files.retain(|file| {
        let target = targets.get(index).copied().flatten();
        index += 1;
        target.is_none_or(|target| action.overwrites(file, &target))
    });
    before - plan.files.len()
}

/// Listing entries of the remote folder `path`, folders first.
fn remote_entries(path: &str, listed: Vec<crate::connection::DirEntry>) -> Vec<RemoteEntry> {
    let mut entries: Vec<RemoteEntry> = listed
        .into_iter()
        .map(|entry| RemoteEntry {
            path: crate::app::join_remote(path, &entry.name),
            name: entry.name,
            dir: entry.dir,
            size: entry.size,
            modified: entry.mtime.map(|t| crate::app::format_unix_utc(t as i64)).unwrap_or_else(|| "—".into()),
            folder: String::new(),
        })
        .collect();
    entries.sort_by(|a, b| b.dir.cmp(&a.dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    entries
}

/// The remote folder to open after connecting, and whether it is the
/// profile's default folder (which falls back to home if it cannot be listed).
/// SFTP servers do not expand `~`; relative paths start at the home folder.
fn start_folder(profile: &ConnectionProfile) -> (String, bool) {
    let Some(path) = profile.default_remote_path.as_deref().map(str::trim).filter(|path| !path.is_empty()) else {
        return (".".into(), false);
    };
    let path = match path.strip_prefix('~') {
        Some("") => ".",
        Some(rest) if rest.starts_with('/') => rest.trim_start_matches('/'),
        _ => path,
    };
    (if path.is_empty() { ".".into() } else { path.to_owned() }, true)
}

/// True unless `path` is already absolute and free of `.`/`..` segments.
pub(crate) fn needs_canonical_path(path: &str) -> bool {
    !path.starts_with('/') || path.split('/').any(|part| part == "." || part == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(runtime: &tokio::runtime::Runtime) -> Session {
        let logger = Arc::new(Logger::new(crate::logging::LoggingSettings::default()));
        Session::new(1, runtime.handle().clone(), logger, std::env::temp_dir(), 4)
    }

    /// Adds a running folder transfer row, as `start_job` does.
    fn folder_transfer(session: &mut Session) -> usize {
        let id = session.next_id();
        let mut item = TransferItem::queued(id, "photos".into(), PathBuf::from("photos"), 0, true);
        item.folder = true;
        item.state = "Downloading".into();
        item.job = Some(Job::DownloadPath { remote: "/photos".into(), local: PathBuf::from("photos"), dir: true });
        session.operation_jobs.insert(id, item.job.clone().unwrap());
        session.transfers.push(item);
        id
    }

    fn file_progress(name: &str, done: u64, total: u64, complete: bool) -> DownloadProgress {
        DownloadProgress {
            total_bytes: total,
            transferred_bytes: done,
            completed_segments: 0,
            total_segments: 0,
            segment: None,
            file_path: Some(name.into()),
            file_complete: complete,
            accelerated: false,
        }
    }

    #[test]
    fn folder_row_sums_up_its_files() {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let mut session = test_session(&runtime);
        let folder = folder_transfer(&mut session);
        session.apply_progress(folder, file_progress("a.jpg", 0, 100, false));
        session.apply_progress(folder, file_progress("b.jpg", 0, 50, false));
        session.apply_progress(folder, file_progress("a.jpg", 40, 100, false));
        session.apply_progress(folder, file_progress("b.jpg", 50, 50, true));

        let parent = session.transfer(folder).unwrap();
        assert_eq!((parent.transferred, parent.total), (90, 150));
        assert_eq!(parent.state, "Downloading");
        let files: Vec<&TransferItem> = session.transfers.iter().filter(|item| item.operation_id == Some(folder)).collect();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].state, "Downloading");
        assert_eq!(files[1].state, "Complete");
        // Only the folder row is listed (and counted) in the tab.
        assert_eq!(session.transfers.iter().filter(|item| item.operation_id.is_none()).count(), 1);
        assert_eq!(session.bytes_transferred(), (90, 0));

        let result = DownloadResult { bytes: 150, segments: 0, segmented: false, accelerated: false, details: None };
        session.finish_transfer(folder, Ok(result));
        let parent = session.transfer(folder).unwrap();
        assert_eq!((parent.transferred, parent.state.as_str()), (150, "Complete"));
        assert!(session.transfers.iter().all(|item| item.state == "Complete"));

        // Clearing removes the folder with its files but keeps the byte count.
        assert_eq!(session.clear_tab(QueueTab::Complete), 1);
        assert!(session.transfers.is_empty());
        assert_eq!(session.bytes_transferred(), (150, 0));
    }

    #[test]
    fn clearing_failed_keeps_completed() {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let mut session = test_session(&runtime);
        let done = folder_transfer(&mut session);
        session.finish_transfer(done, Ok(DownloadResult { bytes: 0, segments: 0, segmented: false, accelerated: false, details: None }));
        let failed = folder_transfer(&mut session);
        session.apply_progress(failed, file_progress("c.jpg", 10, 20, false));
        session.finish_transfer(failed, Err("connection lost".into()));
        assert!(session.transfers.iter().filter(|item| item.operation_id == Some(failed)).all(TransferItem::is_failed));

        assert_eq!(session.clear_tab(QueueTab::Failed), 1);
        assert_eq!(session.transfers.len(), 1);
        assert_eq!(session.transfers[0].id, done);
    }

    #[test]
    fn retrying_the_last_failed_file_completes_the_folder() {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let mut session = test_session(&runtime);
        let folder = folder_transfer(&mut session);
        session.apply_progress(folder, file_progress("a.jpg", 30, 30, true));
        session.apply_progress(folder, file_progress("b.jpg", 5, 20, false));
        session.finish_transfer(folder, Err("timeout".into()));
        let failed_file = session.failed_children(folder);
        assert_eq!(failed_file.len(), 1);

        // Not connected: retry cannot start a transfer, so nothing changes.
        assert_eq!(session.retry(folder, TransferSettings::default()), 0);
        // What happens once the file's own transfer has been queued:
        session.remove_rows(&HashSet::from([failed_file[0]]));
        session.refresh_folder_after_retry(folder);
        let parent = session.transfer(folder).unwrap();
        assert_eq!((parent.transferred, parent.total, parent.state.as_str()), (30, 30, "Complete"));
    }

    #[test]
    fn kept_files_are_left_out_of_the_plan() {
        use crate::connection::PlannedFile;
        let file = |name: &str, size: u64| PlannedFile { local: PathBuf::from(name), remote: format!("/{name}"), size, mtime: Some(100) };
        let plan = TransferPlan { directories: Vec::new(), files: vec![file("new", 1), file("same", 5), file("bigger", 9)] };
        let targets = [None, Some(TargetFile { size: 5, mtime: Some(100) }), Some(TargetFile { size: 5, mtime: Some(100) })];

        let mut ignore = plan.clone();
        assert_eq!(leave_out_kept_files(&mut ignore, &targets, ConflictAction::Ignore), 2);
        assert_eq!(ignore.files.len(), 1);
        assert_eq!(ignore.files[0].remote, "/new");

        let mut by_size = plan.clone();
        assert_eq!(leave_out_kept_files(&mut by_size, &targets, ConflictAction::OverwriteIfSizeDiffers), 1);
        assert_eq!(by_size.files.iter().map(|file| file.remote.as_str()).collect::<Vec<_>>(), ["/new", "/bigger"]);

        let mut all = plan.clone();
        assert_eq!(leave_out_kept_files(&mut all, &targets, ConflictAction::Overwrite), 0);
    }

    fn local(name: &str, dir: bool, size: u64, modified: &str) -> LocalEntry {
        LocalEntry { name: name.into(), path: PathBuf::from(name), dir, size, modified: modified.into(), hidden: false, folder: String::new() }
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
        // Both folders are 0 bytes: ties keep the A-Z name order.
        assert_eq!(names(&rows), ["adir", "zdir", "a.txt", "b.txt"]);
        order.toggle(SortColumn::Modified);
        sort_rows(&mut rows, order);
        assert_eq!(names(&rows), ["zdir", "adir", "b.txt", "a.txt"]);
        order.toggle(SortColumn::Name);
        order.toggle(SortColumn::Name);
        assert!(!order.ascending);
        sort_rows(&mut rows, order);
        assert_eq!(names(&rows), ["zdir", "adir", "b.txt", "a.txt"]);
    }

    #[test]
    fn start_folder_follows_the_profile() {
        let profile = |folder: Option<&str>| ConnectionProfile {
            name: "p".into(), host: "h".into(), port: 22, username: "u".into(),
            auth_method: crate::connection::AuthMethod::Password, private_key_path: None,
            save_password: false, default_remote_path: folder.map(str::to_owned),
        };
        assert_eq!(start_folder(&profile(None)), (".".to_owned(), false));
        assert_eq!(start_folder(&profile(Some("  "))), (".".to_owned(), false));
        assert_eq!(start_folder(&profile(Some("/srv/media"))), ("/srv/media".to_owned(), true));
        assert_eq!(start_folder(&profile(Some("~"))), (".".to_owned(), true));
        assert_eq!(start_folder(&profile(Some("~/projects"))), ("projects".to_owned(), true));
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
