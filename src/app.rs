use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use eframe::egui;
use crate::connection::{AuthMethod, ConnectionProfile};
use crate::transfer::TransferSettings;

#[derive(Clone)]
struct Entry { name: String, path: PathBuf, dir: bool, size: u64, modified: String }

pub struct SftpApp {
    path: PathBuf, entries: Vec<Entry>, filter: String, selected: Option<PathBuf>,
    host: String, port: String, username: String, profile: String, key_path: String,
    auth: AuthMethod, connect_open: bool, settings_open: bool, status: String,
    transfer: TransferSettings, saved_profiles: Vec<ConnectionProfile>, selected_profile: Option<usize>,
}

impl SftpApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let path = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));
        let saved_profiles = load_profiles();
        let mut app = Self {
            path, entries: Vec::new(), filter: String::new(), selected: None,
            host: String::new(), port: "22".into(), username: String::new(),
            profile: "New site".into(), key_path: String::new(), auth: AuthMethod::Password,
            connect_open: false, settings_open: false,
            status: "Ready · No active SFTP session".into(), transfer: TransferSettings::default(),
            saved_profiles, selected_profile: None,
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        self.entries.clear();
        if let Ok(read_dir) = fs::read_dir(&self.path) {
            for item in read_dir.flatten() {
                let path = item.path();
                if let Ok(meta) = item.metadata() {
                    self.entries.push(Entry {
                        name: item.file_name().to_string_lossy().into_owned(),
                        path, dir: meta.is_dir(), size: meta.len(),
                        modified: meta.modified().ok().map(format_iso8601).unwrap_or_else(|| "—".into()),
                    });
                }
            }
        } else { self.status = format!("Cannot read {}", self.path.display()); }
        self.entries.sort_by(|a,b| b.dir.cmp(&a.dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    }

    fn profile_value(&self) -> Result<ConnectionProfile, String> {
        let port = self.port.parse::<u16>().map_err(|_| "Port must be between 1 and 65535".to_owned())?;
        let profile = ConnectionProfile {
            name: self.profile.trim().into(), host: self.host.trim().into(), port,
            username: self.username.trim().into(), auth_method: self.auth,
            private_key_path: (self.auth == AuthMethod::PrivateKey).then(|| self.key_path.trim().into()),
        };
        profile.validate().map_err(|e| e.to_string())?;
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
                    Ok(()) => self.status = format!("Saved connection profile: {}", self.profile),
                    Err(error) => self.status = format!("Could not save profile: {error}"),
                }
            }
            Err(error) => self.status = error,
        }
    }

    fn apply_profile(&mut self, index: usize) {
        if let Some(profile) = self.saved_profiles.get(index) {
            self.profile = profile.name.clone();
            self.host = profile.host.clone();
            self.port = profile.port.to_string();
            self.username = profile.username.clone();
            self.auth = profile.auth_method;
            self.key_path = profile.private_key_path.clone().unwrap_or_default();
            self.selected_profile = Some(index);
        }
    }

    fn local_pane(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong("LOCAL FILESYSTEM");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(egui::RichText::new(format!("{} items", self.entries.len())).small().weak());
                if ui.small_button("Refresh").clicked() { self.refresh(); }
            });
        });
        ui.horizontal(|ui| {
            if ui.small_button("Parent").clicked() {
                if let Some(parent) = self.path.parent() { self.path = parent.to_path_buf(); self.refresh(); }
            }
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter files").desired_width(f32::INFINITY));
        });
        ui.label(egui::RichText::new(self.path.display().to_string()).small().monospace().color(egui::Color32::from_rgb(115,165,205)));
        ui.separator();
        egui::Grid::new("local_header").num_columns(4).striped(false).show(ui, |ui| {
            for (h,w) in [("NAME", 0.0), ("SIZE", 76.0), ("MODIFIED (UTC)", 178.0), ("TYPE", 42.0)] {
                let text = egui::RichText::new(h).small().strong().monospace();
                if w == 0.0 { ui.label(text); } else { ui.add_sized([w,18.0],egui::Label::new(text).halign(egui::Align::LEFT)); }
            }
            ui.end_row();
        });
        ui.separator();
        let filter = self.filter.to_lowercase();
        let rows: Vec<Entry> = self.entries.iter().filter(|e| e.name.to_lowercase().contains(&filter)).cloned().collect();
        egui::ScrollArea::vertical().auto_shrink([false,false]).show(ui, |ui| {
            egui::Grid::new("local_rows").num_columns(4).striped(true).min_col_width(0.0).show(ui, |ui| {
                for e in rows {
                    let label = egui::RichText::new(&e.name).monospace();
                    let response = ui.add_sized([ui.available_width().max(180.0),22.0], egui::SelectableLabel::new(self.selected.as_ref()==Some(&e.path), label));
                    if response.clicked() { self.selected = Some(e.path.clone()); }
                    if response.double_clicked() && e.dir { self.path=e.path.clone(); self.selected=None; self.refresh(); }
                    ui.add_sized([76.0,22.0],egui::Label::new(egui::RichText::new(if e.dir {"—".into()} else {size_text(e.size)}).small().monospace()).halign(egui::Align::LEFT));
                    ui.add_sized([178.0,22.0],egui::Label::new(egui::RichText::new(e.modified).small().monospace()).halign(egui::Align::LEFT));
                    ui.add_sized([42.0,22.0],egui::Label::new(egui::RichText::new(if e.dir {"DIR"} else {"FILE"}).small().monospace()).halign(egui::Align::LEFT));
                    ui.end_row();
                }
            });
        });
        ui.separator();
        ui.label(egui::RichText::new(format!("{} visible entries", self.entries.iter().filter(|e| e.name.to_lowercase().contains(&filter)).count())).small().weak());
    }

    fn windows(&mut self, ctx: &egui::Context) {
        if self.connect_open {
            egui::Window::new("Connection profiles").collapsible(false).resizable(false).show(ctx, |ui| {
                if !self.saved_profiles.is_empty() {
                    let selected = self.selected_profile.map(|i| self.saved_profiles[i].name.clone()).unwrap_or_else(|| "Select saved profile".into());
                    let mut profile_to_apply = None;
                    egui::ComboBox::from_id_salt("saved_profiles").selected_text(selected).show_ui(ui, |ui| {
                        for (i, p) in self.saved_profiles.iter().enumerate() {
                            if ui.selectable_label(self.selected_profile == Some(i), &p.name).clicked() {
                                profile_to_apply = Some(i);
                            }
                        }
                    });
                    if let Some(index) = profile_to_apply {
                        self.apply_profile(index);
                    }
                    ui.separator();
                }
                ui.label("PROFILE NAME");
                ui.text_edit_singleline(&mut self.profile);
                ui.horizontal(|ui| { ui.label("Host"); ui.text_edit_singleline(&mut self.host); });
                ui.horizontal(|ui| { ui.label("Port"); ui.add(egui::TextEdit::singleline(&mut self.port).desired_width(55.0)); ui.label("Username"); ui.text_edit_singleline(&mut self.username); });
                egui::ComboBox::from_id_salt("auth").selected_text(match self.auth { AuthMethod::Password=>"Password", AuthMethod::PrivateKey=>"Private key", AuthMethod::SshAgent=>"SSH agent" }).show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.auth,AuthMethod::Password,"Password");
                    ui.selectable_value(&mut self.auth,AuthMethod::PrivateKey,"Private key");
                    ui.selectable_value(&mut self.auth,AuthMethod::SshAgent,"SSH agent");
                });
                if self.auth==AuthMethod::PrivateKey { ui.label("Private key path"); ui.text_edit_singleline(&mut self.key_path); }
                ui.horizontal(|ui| {
                    if ui.button("Save profile").clicked() { self.save_profile(); }
                    if ui.button("Connect").clicked() {
                        match self.profile_value() {
                            Ok(_) => self.status = "SSH authentication and remote browsing are not yet connected to the interface.".into(),
                            Err(e) => self.status = e,
                        }
                    }
                    if ui.button("Close").clicked() { self.connect_open=false; }
                });
            });
        }
        if self.settings_open {
            egui::Window::new("Transfer settings").collapsible(false).resizable(false).show(ctx, |ui| {
                let mut threshold=(self.transfer.segmentation_threshold_bytes/(1024*1024)) as u32;
                ui.add(egui::Slider::new(&mut threshold,1..=1024).text("Threshold (MiB)"));
                self.transfer.segmentation_threshold_bytes=u64::from(threshold)*1024*1024;
                let mut segment=(self.transfer.target_segment_size_bytes/(1024*1024)) as u32;
                ui.add(egui::Slider::new(&mut segment,1..=256).text("Segment size (MiB)"));
                self.transfer.target_segment_size_bytes=u64::from(segment)*1024*1024;
                ui.add(egui::Slider::new(&mut self.transfer.max_segments_per_file,1..=32).text("Workers per file"));
                ui.add(egui::Slider::new(&mut self.transfer.max_concurrent_transfers,1..=16).text("Concurrent transfers"));
                if ui.button("Close").clicked() { self.settings_open=false; }
            });
        }
    }
}

impl eframe::App for SftpApp {
    fn update(&mut self, ctx:&egui::Context, _frame:&mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::dark());
        ctx.style_mut(|s| { s.spacing.item_spacing=egui::vec2(5.0,4.0); s.spacing.button_padding=egui::vec2(7.0,3.0); s.spacing.interact_size.y=22.0; });
        egui::TopBottomPanel::top("header").exact_height(34.0).show(ctx,|ui| {
            ui.horizontal_centered(|ui| {
                ui.strong("RUST SFTP CLIENT"); ui.separator();
                ui.label(egui::RichText::new("DISCONNECTED").small().color(egui::Color32::from_rgb(220,170,90)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {
                    if ui.small_button("Settings").clicked(){self.settings_open=true;}
                    if ui.small_button("New connection").clicked(){self.connect_open=true;}
                });
            });
        });
        egui::TopBottomPanel::top("toolbar").exact_height(32.0).show(ctx,|ui| {
            ui.horizontal_centered(|ui| {
                ui.add_enabled(false,egui::Button::new("Upload"));
                ui.add_enabled(false,egui::Button::new("Download"));
                ui.add_enabled(false,egui::Button::new("Refresh remote"));
                ui.separator(); ui.add_enabled(false,egui::Button::new("Delete"));
                ui.add_enabled(false,egui::Button::new("Rename"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {ui.label(egui::RichText::new("SSH · SFTP v3").small().weak());});
            });
        });
        egui::SidePanel::left("sidebar").resizable(false).exact_width(174.0).show(ctx,|ui| {
            ui.add_space(8.0); ui.label(egui::RichText::new("SESSIONS").small().strong().weak());
            ui.selectable_label(true,"Sites"); ui.selectable_label(false,"Recent");
            ui.add_space(12.0); ui.label(egui::RichText::new("LOCAL").small().strong().weak());
            if ui.selectable_label(false,"Home").clicked(){if let Some(h)=std::env::var_os("HOME"){self.path=PathBuf::from(h);self.refresh();}}
            if ui.selectable_label(false,"Downloads").clicked(){if let Some(h)=std::env::var_os("HOME"){let p=PathBuf::from(h).join("Downloads");if p.is_dir(){self.path=p;self.refresh();}}}
            ui.add_space(14.0); ui.label(egui::RichText::new("TRANSFER QUEUE").small().strong().weak());
            ui.label(egui::RichText::new("No active transfers").small().weak());
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min),|ui|{ui.label(egui::RichText::new("v0.1.0 · NATIVE RUST").small().weak());});
        });
        egui::TopBottomPanel::bottom("queue").resizable(true).default_height(108.0).min_height(72.0).show(ctx,|ui| {
            ui.horizontal(|ui|{ui.strong("TRANSFER ACTIVITY");ui.label(egui::RichText::new("0 queued · 0 active · 0 failed").small().weak());});
            ui.separator();
            ui.horizontal(|ui|{for h in ["NAME","DIRECTION","PROGRESS","SPEED","STATUS"]{ui.label(egui::RichText::new(h).small().strong().monospace());ui.separator();}});
            ui.label(egui::RichText::new("Transfer queue is empty").small().weak());
        });
        egui::TopBottomPanel::bottom("status").exact_height(22.0).show(ctx,|ui| {
            ui.horizontal_centered(|ui|{ui.label(egui::RichText::new(&self.status).small().weak());});
        });
        egui::CentralPanel::default().show(ctx,|ui| {
            ui.columns(2,|cols|{
                cols[0].set_min_width(300.0); self.local_pane(&mut cols[0]);
                cols[1].vertical_centered(|ui|{
                    ui.horizontal(|ui|{ui.strong("REMOTE SERVER");ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui|{ui.label(egui::RichText::new("NOT CONNECTED").small().color(egui::Color32::from_rgb(210,160,85)));});});
                    ui.separator();ui.add_space(90.0);ui.heading("Remote filesystem unavailable");
                    ui.label(egui::RichText::new("Connect to an SSH server to browse remote files.").weak());
                    if ui.button("Connect to server").clicked(){self.connect_open=true;}
                });
            });
        });
        self.windows(ctx);
    }
}

fn profiles_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| "HOME is not set".to_owned())?;
    Ok(home.join(".config").join("rust-sftp-client").join("profiles.json"))
}

fn load_profiles() -> Vec<ConnectionProfile> {
    profiles_path().ok().and_then(|p| fs::read(p).ok())
        .and_then(|data| serde_json::from_slice(&data).ok()).unwrap_or_default()
}

fn persist_profiles(profiles: &[ConnectionProfile]) -> Result<(), String> {
    let path = profiles_path()?;
    let parent = path.parent().ok_or_else(|| "Invalid profile storage path".to_owned())?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let data = serde_json::to_vec_pretty(profiles).map_err(|e| e.to_string())?;
    let temp = path.with_extension("json.tmp");
    fs::write(&temp, data).map_err(|e| e.to_string())?;
    fs::rename(&temp, &path).map_err(|e| e.to_string())
}

// Convert filesystem timestamps to a stable UTC ISO-8601 representation.
fn format_iso8601(value: SystemTime) -> String {
    let seconds = match value.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    };
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365*yoe + yoe/4 - yoe/100);
    let mp = (5*doy + 2) / 153;
    let day = doy - (153*mp+2)/5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    let hour = day_seconds / 3600;
    let minute = (day_seconds % 3600) / 60;
    let second = day_seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn size_text(bytes:u64)->String {
    const U:[&str;5]=["B","KiB","MiB","GiB","TiB"];
    let mut n=bytes as f64;let mut i=0;while n>=1024.0&&i<U.len()-1{n/=1024.0;i+=1;}
    if i==0{format!("{bytes} B")}else{format!("{n:.1} {}",U[i])}
}
