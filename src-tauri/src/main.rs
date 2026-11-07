mod app;
mod connection;
mod transfer;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Rust SFTP Client")
            .with_inner_size([1440.0, 920.0])
            .with_min_inner_size([1050.0, 680.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Rust SFTP Client",
        options,
        Box::new(|cc| Ok(Box::new(app::SftpApp::new(cc)))),
    )
}
