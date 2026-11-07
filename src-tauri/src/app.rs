use std::path::{Path, PathBuf};
use eframe::egui;
use crate::connection::{AuthMethod, ConnectionProfile};
use crate::transfer::TransferSettings;

#[derive(Clone)]
struct Entry { name: String, path: PathBuf, dir: bool, size: u64, modified: String }

pub struct SftpApp {
    path: PathBuf, entries: Vec<Entry>, filter: String, selected: Option<PathBuf>,
    host: String, port: String, username: String, profile: String, key_path: String,
    auth: AuthMethod, connect_open: bool, settings_open: bool, status: String,
    transfer: TransferSettings,
}

impl SftpApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let path = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));
        let mut app = Self {
            path, entries: Vec::new(), filter: String::new(), selected: None,
            host: String::new(), port: "22".into(), username: String::new(),
            profile: "New site".into(), key_path: String::new(), auth: AuthMethod::Password,
            connect_open: false, settings_open: false,
            status: "Ready · No active SFTP session".into(), transfer: TransferSettings::default(),
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        self.entries.clear();
        if let Ok(read_dir) = std::fs::read_dir(&self.path) {
            for item in read_dir.flatten() {
                let path = item.path();
                if let Ok(meta) = item.metadata() {
                    self.entries.push(Entry {
                        name: item.file_name().to_string_lossy().into_owned(),
                        path, dir: meta.is_dir(), size: meta.len(),
                        modified: meta.modified().ok().map(|v| format!("{v:?}")).unwrap_or_else(|| "—".into()),
                    });
                }
            }
        } else { self.status = format!("Cannot read {}", self.path.display()); }
        self.entries.sort_by(|a,b| b.dir.cmp(&a.dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    }

    fn local_pane(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong("LOCAL FILESYSTEM");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(egui::RichText::new(format!("{} items", self.entries.len())).small().weak());
                if ui.small_button("↻").clicked() { self.refresh(); }
            });
        });
        ui.horizontal(|ui| {
            if ui.small_button("↑").on_hover_text("Parent directory").clicked() {
                if let Some(parent) = self.path.parent() { self.path = parent.to_path_buf(); self.refresh(); }
            }
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter files…").desired_width(f32::INFINITY));
        });
        ui.label(egui::RichText::new(self.path.display().to_string()).small().monospace().color(egui::Color32::from_rgb(115,165,205)));
        ui.separator();
        egui::Grid::new("local_header").num_columns(4).show(ui, |ui| {
            for h in ["NAME", "SIZE", "MODIFIED", "TYPE"] { ui.label(egui::RichText::new(h).small().strong()); }
            ui.end_row();
        });
        ui.separator();
        let filter = self.filter.to_lowercase();
        let rows: Vec<Entry> = self.entries.iter().filter(|e| e.name.to_lowercase().contains(&filter)).cloned().collect();
        egui::ScrollArea::vertical().auto_shrink([false,false]).show(ui, |ui| {
            for e in rows {
                ui.horizontal(|ui| {
                    let label = format!("{} {}", if e.dir { "▸" } else { " " }, e.name);
                    let response = ui.add_sized([ui.available_width() * 0.50, 22.0], egui::SelectableLabel::new(self.selected.as_ref()==Some(&e.path), label));
                    if response.clicked() { self.selected = Some(e.path.clone()); }
                    if response.double_clicked() && e.dir { self.path=e.path.clone(); self.selected=None; self.refresh(); }
                    ui.add_sized([66.0,22.0], egui::Label::new(egui::RichText::new(if e.dir {"—".into()} else {size_text(e.size)}).small().monospace()));
                    ui.add_sized([100.0,22.0], egui::Label::new(egui::RichText::new(e.modified).small().weak()));
                    ui.add_sized([38.0,22.0], egui::Label::new(egui::RichText::new(if e.dir {"DIR"} else {"FILE"}).small().weak()));
                });
            }
        });
        ui.separator();
        ui.label(egui::RichText::new(format!("{} visible entries", self.entries.iter().filter(|e| e.name.to_lowercase().contains(&filter)).count())).small().weak());
    }

    fn windows(&mut self, ctx: &egui::Context) {
        if self.connect_open {
            egui::Window::new("New connection").collapsible(false).resizable(false).show(ctx, |ui| {
                ui.label("SITE PROFILE");
                ui.text_edit_singleline(&mut self.profile);
                ui.horizontal(|ui| { ui.label("Host"); ui.text_edit_singleline(&mut self.host); });
                ui.horizontal(|ui| { ui.label("Port"); ui.add(egui::TextEdit::singleline(&mut self.port).desired_width(55.0)); ui.label("Username"); ui.text_edit_singleline(&mut self.username); });
                egui::ComboBox::from_id_salt("auth").selected_text(match self.auth { AuthMethod::Password=>"Password", AuthMethod::PrivateKey=>"Private key", AuthMethod::SshAgent=>"SSH agent" }).show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.auth,AuthMethod::Password,"Password");
                    ui.selectable_value(&mut self.auth,AuthMethod::PrivateKey,"Private key");
                    ui.selectable_value(&mut self.auth,AuthMethod::SshAgent,"SSH agent");
                });
                if self.auth==AuthMethod::PrivateKey { ui.text_edit_singleline(&mut self.key_path); }
                ui.label(egui::RichText::new("Host key verification is required before authentication.").small().weak());
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() { self.connect_open=false; }
                    if ui.button("Validate profile").clicked() {
                        let p=ConnectionProfile { name:self.profile.trim().into(),host:self.host.trim().into(),port:self.port.parse().unwrap_or(0),username:self.username.trim().into(),auth_method:self.auth,private_key_path:(self.auth==AuthMethod::PrivateKey).then(||self.key_path.trim().into()) };
                        match p.validate() { Ok(())=>self.status="Profile valid · SSH connection implementation pending".into(),Err(e)=>self.status=e.to_string() }
                    }
                });
                ui.label(egui::RichText::new("Connection and credential handling are not yet implemented.").small().weak());
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
                ui.label(egui::RichText::new("◆").color(egui::Color32::from_rgb(75,160,220)));
                ui.strong("RUST SFTP CLIENT"); ui.separator();
                ui.label(egui::RichText::new("● DISCONNECTED").small().color(egui::Color32::from_rgb(220,170,90)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {
                    if ui.small_button("⚙ Settings").clicked(){self.settings_open=true;}
                    if ui.small_button("+ New connection").clicked(){self.connect_open=true;}
                });
            });
        });
        egui::TopBottomPanel::top("toolbar").exact_height(32.0).show(ctx,|ui| {
            ui.horizontal_centered(|ui| {
                ui.add_enabled(false,egui::Button::new("↑ Upload"));
                ui.add_enabled(false,egui::Button::new("↓ Download"));
                ui.add_enabled(false,egui::Button::new("↻ Refresh remote"));
                ui.separator(); ui.add_enabled(false,egui::Button::new("Delete"));
                ui.add_enabled(false,egui::Button::new("Rename"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {ui.label(egui::RichText::new("SSH · SFTP v3").small().weak());});
            });
        });
        egui::SidePanel::left("sidebar").resizable(false).exact_width(174.0).show(ctx,|ui| {
            ui.add_space(8.0); ui.label(egui::RichText::new("SESSIONS").small().strong().weak());
            ui.selectable_label(true,"  ◉  Sites"); ui.selectable_label(false,"  ◷  Recent");
            ui.add_space(12.0); ui.label(egui::RichText::new("LOCAL").small().strong().weak());
            if ui.selectable_label(false,"  ⌂  Home").clicked(){if let Some(h)=std::env::var_os("HOME"){self.path=PathBuf::from(h);self.refresh();}}
            if ui.selectable_label(false,"  ↓  Downloads").clicked(){if let Some(h)=std::env::var_os("HOME"){let p=PathBuf::from(h).join("Downloads");if p.is_dir(){self.path=p;self.refresh();}}}
            ui.add_space(14.0); ui.label(egui::RichText::new("TRANSFER QUEUE").small().strong().weak());
            ui.label(egui::RichText::new("No active transfers").small().weak());
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min),|ui|{ui.label(egui::RichText::new("v0.1.0 · NATIVE RUST").small().weak());});
        });
        egui::TopBottomPanel::bottom("queue").resizable(true).default_height(108.0).min_height(72.0).show(ctx,|ui| {
            ui.horizontal(|ui|{ui.strong("TRANSFER ACTIVITY");ui.label(egui::RichText::new("0 queued · 0 active · 0 failed").small().weak());});
            ui.separator();
            ui.horizontal(|ui|{for h in ["NAME","DIRECTION","PROGRESS","SPEED","STATUS"]{ui.label(egui::RichText::new(h).small().strong());ui.separator();}});
            ui.label(egui::RichText::new("Transfer queue is empty").small().weak());
        });
        egui::TopBottomPanel::bottom("status").exact_height(22.0).show(ctx,|ui| {
            ui.horizontal_centered(|ui|{ui.label(egui::RichText::new("●").color(egui::Color32::from_rgb(190,155,85)));ui.label(egui::RichText::new(&self.status).small().weak());});
        });
        egui::CentralPanel::default().show(ctx,|ui| {
            ui.columns(2,|cols|{
                cols[0].set_min_width(300.0); self.local_pane(&mut cols[0]);
                cols[1].vertical_centered(|ui|{
                    ui.horizontal(|ui|{ui.strong("REMOTE SERVER");ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui|{ui.label(egui::RichText::new("NOT CONNECTED").small().color(egui::Color32::from_rgb(210,160,85)));});});
                    ui.separator();ui.add_space(90.0);ui.heading("Remote filesystem unavailable");
                    ui.label(egui::RichText::new("Connect to an SSH server to browse remote files.").weak());
                    if ui.button("+ Connect to server").clicked(){self.connect_open=true;}
                });
            });
        });
        self.windows(ctx);
    }
}

fn size_text(bytes:u64)->String {
    const U:[&str;5]=["B","KiB","MiB","GiB","TiB"];
    let mut n=bytes as f64;let mut i=0;while n>=1024.0&&i<U.len()-1{n/=1024.0;i+=1;}
    if i==0{format!("{bytes} B")}else{format!("{n:.1} {}",U[i])}
}
