// Release builds on Windows are GUI apps: don't open a console window.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod conflict;
mod connection;
mod credentials;
mod logging;
mod transfer;
mod units;
mod places;
mod search;
mod session;
mod settings;
mod terminal;
mod win32;

use std::{
    panic::{self, AssertUnwindSafe},
    process::Command,
    sync::Mutex,
};

use eframe::Renderer;

/// Forces a renderer (`wgpu` or `glow`); also marks a fallback relaunch.
const RENDERER_ENV: &str = "RUST_SFTP_CLIENT_RENDERER";
/// Carries the first renderer's error into the fallback process.
const FIRST_ERROR_ENV: &str = "RUST_SFTP_CLIENT_FIRST_ERROR";
const ERROR_LOG: &str = "startup-error.log";

/// Message of the most recent panic, captured by the panic hook.
static LAST_PANIC: Mutex<Option<String>> = Mutex::new(None);

fn main() {
    install_panic_hook();

    // wgpu uses Direct3D 12 on Windows, which also works in virtual machines
    // without GPU drivers (via the WARP software rasteriser), where OpenGL is
    // often limited to version 1.1. Elsewhere OpenGL is the dependable default.
    let (preferred, fallback) = if cfg!(windows) {
        (Renderer::Wgpu, Renderer::Glow)
    } else {
        (Renderer::Glow, Renderer::Wgpu)
    };
    let forced = std::env::var(RENDERER_ENV).ok().and_then(|name| parse_renderer(&name));
    let renderer = forced.unwrap_or(preferred);

    let error = match run(renderer) {
        Ok(()) => return,
        Err(error) => error,
    };

    // A failed renderer may leave the windowing system unusable for this
    // process, so the other renderer is tried in a fresh one.
    if forced.is_none() {
        if relaunch_with(fallback, &format!("{} renderer: {error}", renderer_name(renderer))).is_ok() {
            return;
        }
    }

    let mut message = format!("Rust SFTP Client could not start.\n\n{} renderer: {error}", renderer_name(renderer));
    if let Ok(first) = std::env::var(FIRST_ERROR_ENV) {
        message.push_str(&format!("\n\nBefore that, the {first}"));
    }
    message.push_str(
        "\n\nThis usually means no usable graphics driver is installed. In a virtual machine, \
         enable 3D acceleration or install the guest additions / graphics drivers.",
    );
    report_fatal_error(&message);
    std::process::exit(1);
}

fn run(renderer: Renderer) -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Rust SFTP Client")
            .with_inner_size([1440.0, 920.0])
            .with_min_inner_size([1050.0, 680.0]),
        renderer,
        ..Default::default()
    };
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        eframe::run_native(
            "Rust SFTP Client",
            options,
            Box::new(|cc| Ok(Box::new(app::SftpApp::new(cc)))),
        )
    }));
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(LAST_PANIC
            .lock()
            .ok()
            .and_then(|mut last| last.take())
            .unwrap_or_else(|| "the application panicked".into())),
    }
}

fn relaunch_with(renderer: Renderer, first_error: &str) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env(RENDERER_ENV, renderer_name(renderer))
        .env(FIRST_ERROR_ENV, first_error)
        .spawn()
        .map(|_| ())
}

fn parse_renderer(name: &str) -> Option<Renderer> {
    match name.trim().to_ascii_lowercase().as_str() {
        "wgpu" => Some(Renderer::Wgpu),
        "glow" | "opengl" | "gl" => Some(Renderer::Glow),
        _ => None,
    }
}

fn renderer_name(renderer: Renderer) -> &'static str {
    match renderer {
        Renderer::Wgpu => "wgpu",
        Renderer::Glow => "glow",
    }
}

/// Records panics so they can be shown to the user and written to the error
/// log; without a console, they would otherwise vanish.
fn install_panic_hook() {
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let message = format!("panic in thread '{}': {info}", thread.name().unwrap_or("unnamed"));
        append_error_log(&message);
        if thread.name() == Some("main") {
            if let Ok(mut last) = LAST_PANIC.lock() {
                *last = Some(message);
            }
        }
        default_hook(info);
    }));
}

/// Writes `message` to the error log, shows it to the user, and returns.
fn report_fatal_error(message: &str) {
    let log_path = append_error_log(message);
    let message = match log_path {
        Some(path) => format!("{message}\n\nDetails were written to:\n{}", path.display()),
        None => message.to_owned(),
    };
    eprintln!("{message}");
    show_error_dialog(&message);
}

/// Appends a timestamped entry to `startup-error.log` in the config folder.
fn append_error_log(message: &str) -> Option<std::path::PathBuf> {
    use std::io::Write as _;
    let directory = settings::config_dir().ok()?;
    std::fs::create_dir_all(&directory).ok()?;
    let path = directory.join(ERROR_LOG);
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&path).ok()?;
    let timestamp = logging::iso8601_utc(std::time::SystemTime::now());
    writeln!(file, "{timestamp} {message}").ok()?;
    Some(path)
}

#[cfg(windows)]
fn show_error_dialog(message: &str) {
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(window: *mut core::ffi::c_void, text: *const u16, caption: *const u16, kind: u32) -> i32;
    }
    const MB_OK: u32 = 0x0000_0000;
    const MB_ICONERROR: u32 = 0x0000_0010;
    let wide = |text: &str| text.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (text, caption) = (wide(message), wide("Rust SFTP Client"));
    // SAFETY: both buffers are NUL-terminated UTF-16 and outlive the call.
    unsafe {
        MessageBoxW(std::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), MB_OK | MB_ICONERROR);
    }
}

#[cfg(not(windows))]
fn show_error_dialog(_message: &str) {
    // The message has already been printed to stderr.
}
