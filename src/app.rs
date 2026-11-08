use std::{
    fs,
    path::PathBuf,
    sync::{mpsc as std_mpsc, Arc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use eframe::egui;
use tokio::sync::{mpsc, Semaphore};

use crate::connection::{
    load_trusted_fingerprint, trust_host_key, AuthMethod, ConnectError, ConnectionProfile,
    SftpConnection,
};
use crate::transfer::{DownloadProgress, DownloadResult, SegmentProgress, TransferSettings};

#[derive(Clone)]
struct LocalEntry {
    name: String,
    path: PathBuf,
    dir: bool,
    size: u64,
    modified: String,
}

#[derive(Clone)]
struct RemoteEntry {
    name: String,
    path: String,
    dir: bool,
    size: u64,
    modified: String,
}

#[derive(Clone)]
struct TransferItem {
    id: usize,
    operation_id: Option<usize>,
    name: String,
    destination: PathBuf,
    transferred: u64,
    total: u64,
    segments: Vec<SegmentProgress>,
    started_at: Option<Instant>,
    finished_at: Option<Instant>,
    last_speed_sample_at: Option<Instant>,
    last_speed_sample_bytes: u64,
    speed_mib_s: f64,
    state: String,
}

#[derive(Clone)]
enum Dialog {
    Profiles,
    Password,
    TrustHostKey,
    Error,
}

#[derive(Clone, Debug)]
enum DragPayload {
    Local(PathBuf),
    Remote(String),
}

enum QueueEvent {
    Started { id: usize, state: String },
    Progress { id: usize, progress: DownloadProgress },
    Finished { id: usize, result: Result<DownloadResult, String> },
}

pub struct SftpApp {
    runtime: tokio::runtime::Runtime,
    path: PathBuf,
    local_entries: Vec<LocalEntry>,
    local_filter: String,
    local_selected: Option<PathBuf>,
    remote_path: String,
    remote_entries: Vec<RemoteEntry>,
    remote_filter: String,
    remote_selected: Vec<String>,
    connection: Option<Arc<SftpConnection>>,
    connection_profile: Option<ConnectionProfile>,
    saved_profiles: Vec<ConnectionProfile>,
    selected_profile: Option<usize>,
    host: String,
    port: String,
    username: String,
    profile_name: String,
    key_path: String,
    auth: AuthMethod,
    password: String,
    pending_password: Option<String>,
    pending_fingerprint: Option<String>,
    dialog: Option<Dialog>,
    error_message: String,
    settings_open: bool,
    status: String,
    transfer: TransferSettings,
    transfers: Vec<TransferItem>,
    next_transfer_id: usize,
    queue_tx: std_mpsc::Sender<QueueEvent>,
    queue_rx: std_mpsc::Receiver<QueueEvent>,
    connect_rx: Option<std_mpsc::Receiver<Result<SftpConnection, ConnectError>>>,
    list_rx: Option<std_mpsc::Receiver<Result<Vec<RemoteEntry>, String>>>,
    transfer_slots: Arc<Semaphore>,
}

impl SftpApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let path = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));
        let saved_profiles = load_profiles();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime initialization failed");
        let (queue_tx, queue_rx) = std_mpsc::channel();
        let mut app = Self {
            runtime,
            path,
            local_entries: Vec::new(),
            local_filter: String::new(),
            local_selected: None,
            remote_path: String::new(),
            remote_entries: Vec::new(),
            remote_filter: String::new(),
            remote_selected: Vec::new(),
            connection: None,
            connection_profile: None,
            saved_profiles,
            selected_profile: None,
            host: String::new(),
            port: "22".into(),
            username: String::new(),
            profile_name: "New site".into(),
            key_path: String::new(),
            auth: AuthMethod::Password,
            password: String::new(),
            pending_password: None,
            pending_fingerprint: None,
            dialog: None,
            error_message: String::new(),
            settings_open: false,
            status: "Ready · No active SFTP session".into(),
            transfer: TransferSettings::default(),
            transfers: Vec::new(),
            next_transfer_id: 1,
            queue_tx,
            queue_rx,
            connect_rx: None,
            list_rx: None,
            transfer_slots: Arc::new(Semaphore::new(4)),
        };
        app.refresh_local();
        app
    }

    fn refresh_local(&mut self) {
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
                        modified: meta.modified().ok().map(format_iso8601).unwrap_or_else(|| "—".into()),
                    });
                }
            }
        } else {
            self.status = format!("Cannot read {}", self.path.display());
        }
        self.local_entries.sort_by(|a, b| b.dir.cmp(&a.dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
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
        match self.profile_value() {
            Ok(profile) => {
                if let Some(index) = self.saved_profiles.iter().position(|p| p.name == profile.name) {
                    self.saved_profiles[index] = profile;
                    self.selected_profile = Some(index);
                } else {
                    self.saved_profiles.push(profile);
                    self.selected_profile = Some(self.saved_profiles.len() - 1);
                }
                match persist_profiles(&self.saved_profiles) {
                    Ok(()) => self.status = format!("Saved connection profile: {}", self.profile_name),
                    Err(error) => self.show_error(format!("Could not save profile: {error}")),
                }
            }
            Err(error) => self.show_error(error),
        }
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

    fn begin_connect(&mut self, password: Option<String>) {
        let profile = match self.profile_value() {
            Ok(profile) => profile,
            Err(error) => {
                self.show_error(error);
                return;
            }
        };
        self.connection_profile = Some(profile.clone());
        self.pending_password = password.clone();
        let trusted = load_trusted_fingerprint(&profile.host, profile.port);
        let (tx, rx) = std_mpsc::channel();
        self.connect_rx = Some(rx);
        self.status = format!("Connecting to {}:{} …", profile.host, profile.port);
        self.runtime.spawn(async move {
            let result = SftpConnection::connect(&profile, password.as_deref(), trusted.as_deref()).await;
            let _ = tx.send(result);
        });
    }

    fn poll_connection(&mut self) {
        let result = self.connect_rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some(result) = result {
            self.connect_rx = None;
            match result {
                Ok(connection) => {
                    let host = connection.host.clone();
                    self.connection = Some(Arc::new(connection));
                    self.pending_password = None;
                    self.password.clear();
                    self.remote_path = ".".into();
                    self.remote_selected.clear();
                    self.status = format!("Connected to {host}");
                    self.dialog = None;
                    self.load_remote(".");
                }
                Err(ConnectError::HostKeyRequired { fingerprint }) => {
                    self.pending_fingerprint = Some(fingerprint);
                    self.dialog = Some(Dialog::TrustHostKey);
                    self.status = "First-time SSH host-key trust is required".into();
                }
                Err(error) => {
                    self.pending_password = None;
                    self.show_error(error.to_string());
                    self.status = "Connection failed".into();
                }
            }
        }
    }

    fn accept_host_key(&mut self) {
        let (Some(profile), Some(fingerprint)) = (self.connection_profile.clone(), self.pending_fingerprint.clone()) else {
            self.show_error("Missing host-key trust context".into());
            return;
        };
        if let Err(error) = trust_host_key(&profile.host, profile.port, &fingerprint) {
            self.show_error(format!("Could not save host-key trust: {error}"));
            return;
        }
        self.pending_fingerprint = None;
        self.begin_connect(self.pending_password.clone());
    }

    fn load_remote(&mut self, path: &str) {
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
                    let full_path = join_remote(&path, &name);
                    entries.push(RemoteEntry {
                        name,
                        path: full_path,
                        dir: attrs.is_dir(),
                        size: attrs.size.unwrap_or(0),
                        modified: attrs.mtime.map(|t| format_unix_utc(t as i64)).unwrap_or_else(|| "—".into()),
                    });
                }
                entries.sort_by(|a, b| b.dir.cmp(&a.dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
                Ok(entries)
            }.await;
            let _ = tx.send(result);
        });
    }

    fn poll_remote_listing(&mut self) {
        let result = self.list_rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some(result) = result {
            self.list_rx = None;
            match result {
                Ok(entries) => {
                    self.remote_entries = entries;
                    self.remote_selected.clear();
                    self.status = format!("Remote directory loaded · {} entries", self.remote_entries.len());
                }
                Err(error) => self.show_error(format!("Could not list remote directory: {error}")),
            }
        }
    }

    fn navigate_remote(&mut self, path: String) {
        self.remote_path = path.clone();
        self.remote_selected.clear();
        self.load_remote(&path);
    }

    fn download_selected(&mut self) {
        let Some(connection) = self.connection.clone() else { return; };
        if self.remote_selected.is_empty() { return; }
        let files: Vec<RemoteEntry> = self.remote_entries.iter()
            .filter(|entry| self.remote_selected.contains(&entry.path) && !entry.dir)
            .cloned().collect();
        if files.is_empty() {
            self.status = "Select one or more remote files to download".into();
            return;
        }
        self.transfer_slots = Arc::new(Semaphore::new(self.transfer.max_concurrent_transfers.max(1) as usize));
        for entry in files {
            let id = self.next_transfer_id;
            self.next_transfer_id += 1;
            let destination = self.path.join(&entry.name);
            self.transfers.push(TransferItem {
                id,
                operation_id: None,
                name: entry.name.clone(),
                destination: destination.clone(),
                transferred: 0,
                total: entry.size,
                segments: Vec::new(),
                started_at: None,
                finished_at: None,
                last_speed_sample_at: None,
                last_speed_sample_bytes: 0,
                speed_mib_s: 0.0,
                state: "Queued".into(),
            });
            let connection = connection.clone();
            let settings = self.transfer;
            let slots = self.transfer_slots.clone();
            let tx = self.queue_tx.clone();
            self.runtime.spawn(async move {
                let _permit = match slots.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(error) => {
                        let _ = tx.send(QueueEvent::Finished { id, result: Err(error.to_string()) });
                        return;
                    }
                };
                let _ = tx.send(QueueEvent::Started { id, state: "Downloading".into() });
                let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
                let download = connection.download(&entry.path, &destination, settings, Some(progress_tx));
                tokio::pin!(download);
                loop {
                    tokio::select! {
                        result = &mut download => {
                            let result = result.map_err(|e| e.to_string());
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
        self.status = format!("Queued {} download(s) to {}", self.remote_selected.len(), self.path.display());
    }


    fn queue_dropped_local(&mut self, local_path: PathBuf) {
        self.transfer_slots = Arc::new(Semaphore::new(self.transfer.max_concurrent_transfers.max(1) as usize));
        let Some(connection) = self.connection.clone() else {
            self.status = "Connect to a remote server before uploading".into();
            return;
        };
        let Some(name) = local_path.file_name().map(|name| name.to_string_lossy().into_owned()) else {
            self.status = "Cannot upload this filesystem path".into();
            return;
        };
        let remote_destination = join_remote(&self.remote_path, &name);
        let total = fs::metadata(&local_path)
            .map(|meta| if meta.is_file() { meta.len() } else { 0 }).unwrap_or(0);
        let id = self.next_transfer_id;
        self.next_transfer_id += 1;
        self.transfers.push(TransferItem {
            id, operation_id: None, name: name.clone(), destination: local_path.clone(), transferred: 0, total,
            segments: Vec::new(), started_at: None, finished_at: None,
            last_speed_sample_at: None, last_speed_sample_bytes: 0, speed_mib_s: 0.0,
            state: "Queued".into(),
        });
        let slots = self.transfer_slots.clone();
        let tx = self.queue_tx.clone();
        let remote_destination_for_task = remote_destination.clone();
        self.runtime.spawn(async move {
            let _permit = match slots.acquire_owned().await {
                Ok(permit) => permit,
                Err(error) => {
                    let _ = tx.send(QueueEvent::Finished { id, result: Err(error.to_string()) });
                    return;
                }
            };
            let _ = tx.send(QueueEvent::Started { id, state: "Uploading".into() });
            let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
            let upload = connection.upload_path(&local_path, &remote_destination_for_task, Some(progress_tx));
            tokio::pin!(upload);
            loop {
                tokio::select! {
                    result = &mut upload => {
                        let _ = tx.send(QueueEvent::Finished { id, result: result.map_err(|e| e.to_string()) });
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
        self.status = format!("Queued recursive upload: {name} → {remote_destination}");
    }

    fn queue_dropped_remote(&mut self, remote_path: String) {
        self.transfer_slots = Arc::new(Semaphore::new(self.transfer.max_concurrent_transfers.max(1) as usize));
        let Some(connection) = self.connection.clone() else { return; };
        let name = remote_path.rsplit('/').find(|part| !part.is_empty()).unwrap_or(&remote_path).to_owned();
        let destination = self.path.join(&name);
        let id = self.next_transfer_id;
        self.next_transfer_id += 1;
        self.transfers.push(TransferItem {
            id, operation_id: None, name: name.clone(), destination: destination.clone(), transferred: 0, total: 0,
            segments: Vec::new(), started_at: None, finished_at: None,
            last_speed_sample_at: None, last_speed_sample_bytes: 0, speed_mib_s: 0.0,
            state: "Queued".into(),
        });
        let settings = self.transfer;
        let slots = self.transfer_slots.clone();
        let tx = self.queue_tx.clone();
        let remote_path_for_task = remote_path.clone();
        let destination_for_task = destination.clone();
        self.runtime.spawn(async move {
            let _permit = match slots.acquire_owned().await {
                Ok(permit) => permit,
                Err(error) => {
                    let _ = tx.send(QueueEvent::Finished { id, result: Err(error.to_string()) });
                    return;
                }
            };
            let _ = tx.send(QueueEvent::Started { id, state: "Downloading".into() });
            let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
            let download = connection.download_path(&remote_path_for_task, &destination_for_task, settings, Some(progress_tx));
            tokio::pin!(download);
            loop {
                tokio::select! {
                    result = &mut download => {
                        let _ = tx.send(QueueEvent::Finished { id, result: result.map_err(|e| e.to_string()) });
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
        self.status = format!("Queued recursive download: {remote_path} → {}", destination.display());
    }

    fn poll_queue(&mut self) {
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
                }
                QueueEvent::Progress { id, progress } => {
                    let target_id = if let Some(relative) = progress.file_path.as_ref() {
                        if let Some(existing) = self.transfers.iter().find(|item| item.operation_id == Some(id) && item.name == *relative) {
                            existing.id
                        } else {
                            let child_state = self.transfers.iter().find(|item| item.id == id)
                                .map(|item| item.state.clone()).unwrap_or_else(|| "Downloading".into());
                            self.transfers.retain(|item| item.id != id);
                            let child_id = self.next_transfer_id;
                            self.next_transfer_id += 1;
                            self.transfers.push(TransferItem {
                                id: child_id, operation_id: Some(id), name: relative.clone(),
                                destination: PathBuf::from(relative), transferred: 0, total: progress.total_bytes,
                                segments: Vec::new(), started_at: Some(Instant::now()), finished_at: None,
                                last_speed_sample_at: Some(Instant::now()), last_speed_sample_bytes: 0,
                                speed_mib_s: 0.0, state: child_state,
                            });
                            child_id
                        }
                    } else { id };
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
                        if progress.file_path.is_some() && progress.transferred_bytes >= progress.total_bytes {
                            item.finished_at = Some(now);
                            item.state = "Complete".into();
                        }
                        if let Some(segment) = progress.segment {
                            if let Some(existing) = item.segments.iter_mut().find(|s| s.index == segment.index) {
                                *existing = segment;
                            } else {
                                item.segments.push(segment);
                                item.segments.sort_by_key(|s| s.index);
                            }
                        }
                        if item.state != "Uploading" {
                            item.state = "Downloading".into();
                        }
                    }
                }
                QueueEvent::Finished { id, result } => {
                    let child_exists = self.transfers.iter().any(|item| item.operation_id == Some(id));
                    match result {
                        Ok(result) => {
                            if child_exists {
                                for item in self.transfers.iter_mut().filter(|item| item.operation_id == Some(id)) {
                                    if item.state != "Complete" {
                                        item.finished_at = Some(Instant::now());
                                        item.transferred = item.total;
                                        item.state = "Complete".into();
                                    }
                                }
                            } else if let Some(item) = self.transfers.iter_mut().find(|item| item.id == id) {
                                item.finished_at = Some(Instant::now());
                                item.transferred = result.bytes;
                                item.total = result.bytes;
                                item.state = "Complete".into();
                            }
                        }
                        Err(error) => {
                            let mut marked = false;
                            for item in self.transfers.iter_mut().filter(|item| item.operation_id == Some(id)) {
                                item.finished_at = Some(Instant::now());
                                for segment in &mut item.segments {
                                    if !segment.complete { segment.failed = true; }
                                }
                                item.state = format!("Failed: {error}");
                                marked = true;
                            }
                            if !marked {
                                if let Some(item) = self.transfers.iter_mut().find(|item| item.id == id) {
                                    item.finished_at = Some(Instant::now());
                                    item.state = format!("Failed: {error}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn local_pane(&mut self, ui: &mut egui::Ui) {
        let (_, dropped) = ui.dnd_drop_zone::<DragPayload, _>(egui::Frame::default(), |ui| {
            self.local_pane_contents(ui);
        });
        if let Some(payload) = dropped {
            if let DragPayload::Remote(path) = payload.as_ref() {
                self.queue_dropped_remote(path.clone());
            }
        }
    }

    fn local_pane_contents(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong("LOCAL FILESYSTEM");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(egui::RichText::new(format!("{} items", self.local_entries.len())).small().weak());
                if ui.small_button("Refresh").clicked() { self.refresh_local(); }
            });
        });
        ui.horizontal(|ui| {
            if ui.small_button("Parent").clicked() {
                if let Some(parent) = self.path.parent() { self.path = parent.to_path_buf(); self.local_selected = None; self.refresh_local(); }
            }
            ui.add(egui::TextEdit::singleline(&mut self.local_filter).hint_text("Filter files").desired_width(f32::INFINITY));
        });
        ui.label(egui::RichText::new(self.path.display().to_string()).small().monospace().color(egui::Color32::from_rgb(115,165,205)));
        ui.separator();

        const SIZE_WIDTH: f32 = 76.0;
        const MODIFIED_WIDTH: f32 = 178.0;
        const TYPE_WIDTH: f32 = 42.0;
        let name_width = (ui.available_width() - SIZE_WIDTH - MODIFIED_WIDTH - TYPE_WIDTH - 24.0).max(100.0);
        ui.horizontal(|ui| {
            file_text_cell(ui, name_width, 18.0, "NAME", true);
            file_text_cell(ui, SIZE_WIDTH, 18.0, "SIZE", true);
            file_text_cell(ui, MODIFIED_WIDTH, 18.0, "MODIFIED (UTC)", true);
            file_text_cell(ui, TYPE_WIDTH, 18.0, "TYPE", true);
        });
        ui.separator();

        let filter = self.local_filter.to_lowercase();
        let mut rows: Vec<LocalEntry> = self.local_entries.iter()
            .filter(|entry| entry.name.to_lowercase().contains(&filter)).cloned().collect();
        if let Some(parent) = self.path.parent() {
            rows.insert(0, LocalEntry {
                name: "..".into(), path: parent.to_path_buf(), dir: true,
                size: 0, modified: "—".into(),
            });
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for entry in rows {
                let name_width = (ui.available_width() - SIZE_WIDTH - MODIFIED_WIDTH - TYPE_WIDTH - 24.0).max(100.0);
                ui.horizontal(|ui| {
                    let response = file_name_cell(
                        ui,
                        name_width,
                        22.0,
                        &entry.name,
                        self.local_selected.as_ref() == Some(&entry.path),
                    );
                    if response.dragged() { response.dnd_set_drag_payload(DragPayload::Local(entry.path.clone())); }
                    if response.clicked() { self.local_selected = Some(entry.path.clone()); }
                    if response.double_clicked() && entry.dir {
                        self.path = entry.path.clone();
                        self.local_selected = None;
                        self.refresh_local();
                    }
                    file_text_cell(ui, SIZE_WIDTH, 22.0, &if entry.dir { "—".into() } else { size_text(entry.size) }, false);
                    file_text_cell(ui, MODIFIED_WIDTH, 22.0, &entry.modified, false);
                    file_text_cell(ui, TYPE_WIDTH, 22.0, if entry.dir { "DIR" } else { "FILE" }, false);
                });
            }
        });
        ui.separator();
        let visible = self.local_entries.iter().filter(|entry| entry.name.to_lowercase().contains(&filter)).count();
        ui.label(egui::RichText::new(format!("{visible} visible entries")).small().weak());
    }

    fn remote_pane(&mut self, ui: &mut egui::Ui) {
        let (_, dropped) = ui.dnd_drop_zone::<DragPayload, _>(egui::Frame::default(), |ui| {
            self.remote_pane_contents(ui);
        });
        if let Some(payload) = dropped {
            if let DragPayload::Local(path) = payload.as_ref() {
                self.queue_dropped_local(path.clone());
            }
        }
    }

    fn remote_pane_contents(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong("REMOTE SERVER");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(connection) = &self.connection {
                    ui.label(egui::RichText::new(format!("{}:{}", connection.host, connection.port)).small().color(egui::Color32::from_rgb(120, 190, 140)));
                } else {
                    ui.label(egui::RichText::new("NOT CONNECTED").small().color(egui::Color32::from_rgb(210, 160, 85)));
                }
            });
        });
        ui.horizontal(|ui| {
            if ui.add_enabled(self.connection.is_some(), egui::Button::new("Parent")).clicked() {
                let parent = remote_parent(&self.remote_path);
                self.navigate_remote(parent);
            }
            if ui.add_enabled(self.connection.is_some(), egui::Button::new("Refresh")).clicked() {
                let path = self.remote_path.clone();
                self.load_remote(&path);
            }
            ui.add(egui::TextEdit::singleline(&mut self.remote_filter).hint_text("Filter remote files").desired_width(f32::INFINITY));
        });
        ui.label(egui::RichText::new(&self.remote_path).small().monospace().color(egui::Color32::from_rgb(115, 165, 205)));
        ui.separator();

        const SIZE_WIDTH: f32 = 76.0;
        const MODIFIED_WIDTH: f32 = 178.0;
        const TYPE_WIDTH: f32 = 42.0;
        let name_width = (ui.available_width() - SIZE_WIDTH - MODIFIED_WIDTH - TYPE_WIDTH - 24.0).max(100.0);
        ui.horizontal(|ui| {
            file_text_cell(ui, name_width, 18.0, "NAME", true);
            file_text_cell(ui, SIZE_WIDTH, 18.0, "SIZE", true);
            file_text_cell(ui, MODIFIED_WIDTH, 18.0, "MODIFIED (UTC)", true);
            file_text_cell(ui, TYPE_WIDTH, 18.0, "TYPE", true);
        });
        ui.separator();
        if self.connection.is_none() {
            ui.vertical_centered(|ui| {
                ui.add_space(90.0);
                ui.heading("Remote filesystem unavailable");
                ui.label(egui::RichText::new("Connect to an SSH server to browse remote files.").weak());
                if ui.button("Connect to server").clicked() { self.dialog = Some(Dialog::Profiles); }
            });
            return;
        }

        let filter = self.remote_filter.to_lowercase();
        let mut rows: Vec<RemoteEntry> = self.remote_entries.iter()
            .filter(|entry| entry.name.to_lowercase().contains(&filter)).cloned().collect();
        let remote_path_trimmed = self.remote_path.trim_end_matches('/');
        if !remote_path_trimmed.is_empty() && remote_path_trimmed != "/" {
            rows.insert(0, RemoteEntry {
                name: "..".into(), path: remote_parent(&self.remote_path), dir: true,
                size: 0, modified: "—".into(),
            });
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for entry in rows {
                let name_width = (ui.available_width() - SIZE_WIDTH - MODIFIED_WIDTH - TYPE_WIDTH - 24.0).max(100.0);
                ui.horizontal(|ui| {
                    let selected = self.remote_selected.contains(&entry.path);
                    let response = file_name_cell(ui, name_width, 22.0, &entry.name, selected);
                    if response.dragged() { response.dnd_set_drag_payload(DragPayload::Remote(entry.path.clone())); }
                    if response.clicked() {
                        let multi = response.ctx.input(|input| input.modifiers.ctrl || input.modifiers.command);
                        if multi {
                            if selected { self.remote_selected.retain(|path| path != &entry.path); }
                            else { self.remote_selected.push(entry.path.clone()); }
                        } else {
                            self.remote_selected.clear();
                            self.remote_selected.push(entry.path.clone());
                        }
                    }
                    if response.double_clicked() && entry.dir { self.navigate_remote(entry.path.clone()); }
                    file_text_cell(ui, SIZE_WIDTH, 22.0, &if entry.dir { "—".into() } else { size_text(entry.size) }, false);
                    file_text_cell(ui, MODIFIED_WIDTH, 22.0, &entry.modified, false);
                    file_text_cell(ui, TYPE_WIDTH, 22.0, if entry.dir { "DIR" } else { "FILE" }, false);
                });
            }
        });
        ui.separator();
        let visible = self.remote_entries.iter().filter(|entry| entry.name.to_lowercase().contains(&filter)).count();
        ui.label(egui::RichText::new(format!("{} selected · {visible} visible entries", self.remote_selected.len())).small().weak());
    }

    fn dialog_window(&mut self, ctx: &egui::Context) {
        let Some(dialog) = self.dialog.clone() else { return; };
        let id = egui::ViewportId::from_hash_of("rust-sftp-client-dialog");
        let title = match &dialog {
            Dialog::Profiles => "Connection profile",
            Dialog::Password => "SSH password",
            Dialog::TrustHostKey => "Verify SSH host key",
            Dialog::Error => "Operation failed",
        };
        let builder = egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size([470.0, match &dialog { Dialog::Profiles => 390.0, Dialog::TrustHostKey => 260.0, _ => 210.0 }])
            .with_min_inner_size([420.0, 180.0])
            .with_resizable(false);
        let mut close = false;
        let mut connect = false;
        let mut save = false;
        let mut accept_trust = false;
        let mut password_value = None;
        ctx.show_viewport_immediate(id, builder, |window_ctx, _class| {
            egui::CentralPanel::default().show(window_ctx, |ui| {
                match &dialog {
                    Dialog::Profiles => {
                        if !self.saved_profiles.is_empty() {
                            let selected = self.selected_profile.map(|index| self.saved_profiles[index].name.clone()).unwrap_or_else(|| "Select saved profile".into());
                            let mut apply = None;
                            egui::ComboBox::from_id_salt("saved_profiles").selected_text(selected).show_ui(ui, |ui| {
                                for (index, profile) in self.saved_profiles.iter().enumerate() {
                                    if ui.selectable_label(self.selected_profile == Some(index), &profile.name).clicked() { apply = Some(index); }
                                }
                            });
                            if let Some(index) = apply { self.apply_profile(index); }
                            ui.separator();
                        }
                        ui.label("PROFILE NAME");
                        ui.text_edit_singleline(&mut self.profile_name);
                        ui.horizontal(|ui| { ui.label("Host"); ui.text_edit_singleline(&mut self.host); });
                        ui.horizontal(|ui| {
                            ui.label("Port");
                            ui.add(egui::TextEdit::singleline(&mut self.port).desired_width(55.0));
                            ui.label("Username");
                            ui.text_edit_singleline(&mut self.username);
                        });
                        egui::ComboBox::from_id_salt("auth_method")
                            .selected_text(match self.auth { AuthMethod::Password => "Password", AuthMethod::PrivateKey => "Private key", AuthMethod::SshAgent => "SSH agent (unsupported)" })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.auth, AuthMethod::Password, "Password");
                                ui.selectable_value(&mut self.auth, AuthMethod::PrivateKey, "Private key");
                                ui.add_enabled(false, egui::Button::selectable(false, "SSH agent (not implemented)"));
                            });
                        if self.auth == AuthMethod::PrivateKey {
                            ui.label("Private key path");
                            ui.text_edit_singleline(&mut self.key_path);
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Save profile").clicked() { save = true; }
                            if ui.button("Connect").clicked() { connect = true; }
                            if ui.button("Close").clicked() { close = true; }
                        });
                    }
                    Dialog::Password => {
                        ui.heading("Enter SSH password");
                        ui.label(format!("{}@{}:{}", self.username, self.host, self.port));
                        ui.add(egui::TextEdit::singleline(&mut self.password).password(true).desired_width(f32::INFINITY));
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Connect").clicked() { password_value = Some(self.password.clone()); }
                            if ui.button("Cancel").clicked() { close = true; }
                        });
                    }
                    Dialog::TrustHostKey => {
                        ui.heading("Unknown SSH host key");
                        ui.label(format!("{}:{} is not trusted yet.", self.host, self.port));
                        ui.label("Verify this fingerprint using a trusted channel before accepting it.");
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new(self.pending_fingerprint.as_deref().unwrap_or("Fingerprint unavailable")).monospace().strong());
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Trust and continue").clicked() { accept_trust = true; }
                            if ui.button("Reject").clicked() { close = true; }
                        });
                    }
                    Dialog::Error => {
                        ui.label(&self.error_message);
                        ui.add_space(10.0);
                        if ui.button("Close").clicked() { close = true; }
                    }
                }
            });
            if window_ctx.input(|input| input.viewport().close_requested()) { close = true; }
        });
        if save { self.save_profile(); }
        if connect {
            match self.profile_value() {
                Ok(profile) => {
                    self.connection_profile = Some(profile.clone());
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
        if accept_trust { self.accept_host_key(); }
        if close {
            if matches!(&dialog, Dialog::TrustHostKey) { self.pending_password = None; self.pending_fingerprint = None; }
            self.dialog = None;
        }
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        if !self.settings_open { return; }
        let id = egui::ViewportId::from_hash_of("rust-sftp-client-settings");
        let builder = egui::ViewportBuilder::default().with_title("Transfer settings").with_inner_size([420.0, 250.0]);
        let mut close = false;
        ctx.show_viewport_immediate(id, builder, |window_ctx, _| {
            egui::CentralPanel::default().show(window_ctx, |ui| {
                let mut threshold = (self.transfer.segmentation_threshold_bytes / (1024 * 1024)) as u32;
                ui.add(egui::Slider::new(&mut threshold, 1..=1024).text("Threshold (MiB)"));
                self.transfer.segmentation_threshold_bytes = u64::from(threshold) * 1024 * 1024;
                let mut segment = (self.transfer.target_segment_size_bytes / (1024 * 1024)) as u32;
                ui.add(egui::Slider::new(&mut segment, 1..=256).text("Segment size (MiB)"));
                self.transfer.target_segment_size_bytes = u64::from(segment) * 1024 * 1024;
                ui.add(egui::Slider::new(&mut self.transfer.max_segments_per_file, 1..=32).text("Workers per file"));
                ui.add(egui::Slider::new(&mut self.transfer.max_concurrent_transfers, 1..=16).text("Concurrent transfers"));
                if ui.button("Close").clicked() { close = true; }
            });
            if window_ctx.input(|input| input.viewport().close_requested()) { close = true; }
        });
        if close { self.settings_open = false; }
    }
}

impl eframe::App for SftpApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::dark());
        ctx.style_mut(|style| {
            style.spacing.item_spacing = egui::vec2(5.0, 4.0);
            style.spacing.button_padding = egui::vec2(7.0, 3.0);
            style.spacing.interact_size.y = 22.0;
        });
        self.poll_connection();
        self.poll_remote_listing();
        self.poll_queue();

        egui::TopBottomPanel::top("header").exact_height(34.0).show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                ui.strong("RUST SFTP CLIENT");
                ui.separator();
                let connected = self.connection.is_some();
                ui.label(egui::RichText::new(if connected { "CONNECTED" } else { "DISCONNECTED" }).small()
                    .color(if connected { egui::Color32::from_rgb(120, 190, 140) } else { egui::Color32::from_rgb(220, 170, 90) }));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Settings").clicked() { self.settings_open = true; }
                    if ui.small_button("New connection").clicked() { self.dialog = Some(Dialog::Profiles); }
                    if ui.small_button("Disconnect").clicked() {
                        self.connection = None;
                        self.remote_entries.clear();
                        self.remote_selected.clear();
                        self.status = "Disconnected".into();
                    }
                });
            });
        });
        egui::TopBottomPanel::top("toolbar").exact_height(32.0).show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                ui.add_enabled(false, egui::Button::new("Upload"));
                if ui.add_enabled(self.connection.is_some() && !self.remote_selected.is_empty(), egui::Button::new("Download")).clicked() {
                    self.download_selected();
                }
                if ui.add_enabled(self.connection.is_some(), egui::Button::new("Refresh remote")).clicked() {
                    let path = self.remote_path.clone();
                    self.load_remote(&path);
                }
                ui.separator();
                ui.add_enabled(false, egui::Button::new("Delete"));
                ui.add_enabled(false, egui::Button::new("Rename"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new("SSH · SFTP v3").small().weak());
                });
            });
        });
        egui::SidePanel::left("sidebar").resizable(false).exact_width(174.0).show(ctx, |ui| {
            ui.add_space(8.0);
            ui.label(egui::RichText::new("SESSIONS").small().strong().weak());
            if ui.selectable_label(true, "Sites").clicked() && self.connection.is_none() { self.dialog = Some(Dialog::Profiles); }
            ui.selectable_label(false, "Recent");
            ui.add_space(12.0);
            ui.label(egui::RichText::new("LOCAL").small().strong().weak());
            if ui.selectable_label(false, "Home").clicked() {
                if let Some(home) = std::env::var_os("HOME") { self.path = PathBuf::from(home); self.refresh_local(); }
            }
            if ui.selectable_label(false, "Downloads").clicked() {
                if let Some(home) = std::env::var_os("HOME") {
                    let path = PathBuf::from(home).join("Downloads");
                    if path.is_dir() { self.path = path; self.refresh_local(); }
                }
            }
            ui.add_space(14.0);
            ui.label(egui::RichText::new("TRANSFER QUEUE").small().strong().weak());
            let active = self.transfers.iter().filter(|item| item.state == "Queued" || item.state == "Downloading" || item.state == "Uploading").count();
            ui.label(egui::RichText::new(format!("{active} active")).small().weak());
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.label(egui::RichText::new("v0.1.0 · NATIVE RUST").small().weak());
            });
        });
        egui::TopBottomPanel::bottom("queue")
            .resizable(true)
            .default_height(170.0)
            .min_height(90.0)
            .max_height(600.0)
            .show(ctx, |ui| {
            let queued = self.transfers.iter().filter(|item| item.state == "Queued").count();
            let active = self.transfers.iter().filter(|item| item.state == "Downloading" || item.state == "Uploading").count();
            let failed = self.transfers.iter().filter(|item| item.state.starts_with("Failed")).count();
            ui.horizontal(|ui| {
                ui.strong("TRANSFER ACTIVITY");
                ui.label(egui::RichText::new(format!("{queued} queued · {active} active · {failed} failed")).small().weak());
            });
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                if self.transfers.is_empty() {
                    ui.label(egui::RichText::new("Transfer queue is empty").small().weak());
                } else {
                    let file_width = 190.0;
                    let percent_width = 105.0;
                    let speed_width = 95.0;
                    let elapsed_width = 95.0;
                    let remaining_width = 110.0;
                    let row_height = 22.0;
                    ui.horizontal(|ui| {
                        ui.add_sized([file_width, row_height], egui::Label::new(egui::RichText::new("FILE").small().strong()));
                        let progress_width = (ui.available_width() - percent_width - speed_width - elapsed_width - remaining_width - 30.0).max(160.0);
                        ui.add_sized([progress_width, row_height], egui::Label::new(egui::RichText::new("PROGRESS").small().strong()));
                        ui.add_sized([percent_width, row_height], egui::Label::new(egui::RichText::new("PERCENT COMPLETE").small().strong()).halign(egui::Align::LEFT));
                        ui.add_sized([speed_width, row_height], egui::Label::new(egui::RichText::new("SPEED (MiB/s)").small().strong()).halign(egui::Align::LEFT));
                        ui.add_sized([elapsed_width, row_height], egui::Label::new(egui::RichText::new("TIME ELAPSED").small().strong()).halign(egui::Align::LEFT));
                        ui.add_sized([remaining_width, row_height], egui::Label::new(egui::RichText::new("TIME REMAINING").small().strong()));
                    });
                    ui.separator();
                    for item in &self.transfers {
                        ui.horizontal(|ui| {
                            ui.add_sized([file_width, row_height], egui::Label::new(
                                egui::RichText::new(&item.name).monospace().small()
                            ).truncate());
                            let progress_width = (ui.available_width() - percent_width - speed_width - elapsed_width - remaining_width - 30.0).max(160.0);
                            let bar_height = 15.0;
                            let (bar_rect, response) = ui.allocate_exact_size(
                                egui::vec2(progress_width, bar_height), egui::Sense::hover()
                            );
                            let painter = ui.painter();
                            painter.rect_filled(bar_rect, 1.0, egui::Color32::from_rgb(48, 53, 62));
                            if item.segments.len() > 1 && item.total > 0 {
                                for segment in &item.segments {
                                    let start_fraction = segment.start as f32 / item.total as f32;
                                    let end_fraction = segment.end_exclusive as f32 / item.total as f32;
                                    let x0 = bar_rect.left() + bar_rect.width() * start_fraction;
                                    let x1 = bar_rect.left() + bar_rect.width() * end_fraction;
                                    let segment_rect = egui::Rect::from_min_max(
                                        egui::pos2(x0, bar_rect.top()),
                                        egui::pos2(x1, bar_rect.bottom())
                                    );
                                    let fraction = if segment.complete { 1.0 } else {
                                        segment.transferred_bytes as f32
                                            / (segment.end_exclusive - segment.start).max(1) as f32
                                    }.clamp(0.0, 1.0);
                                    let color = if segment.failed {
                                        egui::Color32::from_rgb(190, 65, 65)
                                    } else if segment.complete {
                                        egui::Color32::from_rgb(65, 170, 105)
                                    } else {
                                        egui::Color32::from_rgb(65, 135, 205)
                                    };
                                    if fraction > 0.0 {
                                        let fill_rect = egui::Rect::from_min_max(
                                            segment_rect.min,
                                            egui::pos2(segment_rect.left() + segment_rect.width() * fraction, segment_rect.bottom())
                                        );
                                        painter.rect_filled(fill_rect, 0.0, color);
                                    }
                                    if segment.failed {
                                        painter.rect_filled(segment_rect, 0.0, color);
                                    }
                                    if segment.index > 0 {
                                        let x = segment_rect.left();
                                        painter.line_segment(
                                            [egui::pos2(x, bar_rect.top()), egui::pos2(x, bar_rect.bottom())],
                                            egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(25, 29, 35))
                                        );
                                    }
                                }
                            } else {
                                let fraction = if item.total == 0 {
                                    if item.state == "Complete" { 1.0 } else { 0.0 }
                                } else { item.transferred as f32 / item.total as f32 }.clamp(0.0, 1.0);
                                if fraction > 0.0 {
                                    let fill_rect = egui::Rect::from_min_max(
                                        bar_rect.min,
                                        egui::pos2(bar_rect.left() + bar_rect.width() * fraction, bar_rect.bottom())
                                    );
                                    painter.rect_filled(fill_rect, 1.0, if item.state == "Complete" {
                                        egui::Color32::from_rgb(65, 170, 105)
                                    } else { egui::Color32::from_rgb(65, 135, 205) });
                                }
                            }
                            if response.hovered() {
                                response.on_hover_text(format!(
                                    "{} / {} · {} segments",
                                    size_text(item.transferred), size_text(item.total), item.segments.len()
                                ));
                            }
                            let percent = if item.total == 0 {
                                if item.state == "Complete" { 100.0 } else { 0.0 }
                            } else { item.transferred as f64 * 100.0 / item.total as f64 };
                            ui.add_sized([percent_width, row_height], egui::Label::new(
                                egui::RichText::new(format!("{percent:.1}%")).small().monospace()
                            ).halign(egui::Align::LEFT));
                            ui.add_sized([speed_width, row_height], egui::Label::new(
                                egui::RichText::new(if item.state == "Queued" { "—".into() } else { format!("{:.2}", item.speed_mib_s) }).small().monospace()
                            ).halign(egui::Align::LEFT));
                            let elapsed = item.started_at.map(|start| {
                                item.finished_at.unwrap_or_else(Instant::now).saturating_duration_since(start)
                            });
                            ui.add_sized([elapsed_width, row_height], egui::Label::new(
                                egui::RichText::new(elapsed.map(duration_text).unwrap_or_else(|| "—".into())).small().monospace()
                            ));
                            let remaining = if item.state == "Complete" {
                                Some(Duration::ZERO)
                            } else if (item.state == "Downloading" || item.state == "Uploading") && item.transferred > 0 && item.total > item.transferred {
                                elapsed.map(|duration| {
                                    let rate = item.transferred as f64 / duration.as_secs_f64().max(0.001);
                                    Duration::from_secs_f64(((item.total - item.transferred) as f64 / rate).max(0.0))
                                })
                            } else { None };
                            ui.add_sized([remaining_width, row_height], egui::Label::new(
                                egui::RichText::new(remaining.map(duration_text).unwrap_or_else(|| {
                                    if item.state == "Queued" { "Queued".into() } else { "Calculating…".into() }
                                })).small().monospace()
                            ));
                        });
                    }
                }
            });
        });
        egui::TopBottomPanel::bottom("status").exact_height(22.0).show(ctx, |ui| {
            ui.horizontal_centered(|ui| { ui.label(egui::RichText::new(&self.status).small().weak()); });
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
        if self.connect_rx.is_some() || self.list_rx.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        }
        if self.transfers.iter().any(|item| item.state == "Queued" || item.state == "Downloading" || item.state == "Uploading") {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

fn file_name_cell(
    ui: &mut egui::Ui,
    width: f32,
    height: f32,
    text: &str,
    selected: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(width, height),
        egui::Sense::click_and_drag(),
    );
    let visuals = ui.style().interact_selectable(&response, selected);
    if visuals.bg_fill != egui::Color32::TRANSPARENT {
        ui.painter().rect_filled(rect, 3.0, visuals.bg_fill);
    }
    ui.painter().text(
        rect.left_center() + egui::vec2(6.0, 0.0),
        egui::Align2::LEFT_CENTER,
        text,
        egui::FontId::monospace(14.0),
        visuals.fg_stroke.color,
    );
    response
}

fn file_text_cell(ui: &mut egui::Ui, width: f32, height: f32, text: &str, header: bool) {
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(width, height),
        egui::Sense::hover(),
    );
    ui.painter().text(
        rect.left_center() + egui::vec2(6.0, 0.0),
        egui::Align2::LEFT_CENTER,
        text,
        egui::FontId::monospace(if header { 12.0 } else { 12.0 }),
        ui.visuals().text_color(),
    );
}

fn profiles_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| "HOME is not set".to_owned())?;
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

fn join_remote(parent: &str, name: &str) -> String {
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

fn format_iso8601(value: SystemTime) -> String {
    let seconds = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(error) => -(error.duration().as_secs() as i64),
    };
    format_unix_utc(seconds)
}

fn format_unix_utc(seconds: i64) -> String {
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
