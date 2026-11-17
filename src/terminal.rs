//! Interactive SSH shell for the "SSH Terminal" tab: a pseudo-terminal channel
//! on the session's SSH connection, a VT100/xterm screen model and its egui view.

use std::{
    num::NonZeroU16,
    sync::{Arc, Mutex, Weak},
};

use eframe::egui::{self, Color32, Event, FontId, Key, Pos2, Rect, Sense};
use russh::ChannelMsg;
use serde::{Deserialize, Serialize};
use tokio::{runtime::Handle, sync::mpsc};

use crate::{connection::SftpConnection, logging::Severity};

/// `TERM` values offered in the settings; the first is the default.
pub const TERMINAL_TYPES: [&str; 4] = ["xterm-256color", "xterm", "vt100", "linux"];

/// Settings of the "SSH Terminal" tab.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct TerminalSettings {
    /// Font size in points.
    pub font_size: f32,
    pub colors: TerminalColors,
    /// `TERM` sent to the server (new shells).
    pub terminal_type: String,
    /// Lines kept above the screen for the mouse wheel (new shells).
    pub scrollback_lines: u32,
    /// Lines moved per mouse-wheel notch.
    pub wheel_lines: u32,
    /// Copy text to the clipboard as soon as it is selected.
    pub copy_on_select: bool,
    /// Ctrl+C copies the selection when there is one (and interrupts
    /// otherwise). When off, Ctrl+C always interrupts and Ctrl+Shift+C copies.
    pub ctrl_c_copies: bool,
}

impl Default for TerminalSettings {
    fn default() -> Self {
        Self {
            font_size: 12.0,
            colors: TerminalColors::Dark,
            terminal_type: TERMINAL_TYPES[0].into(),
            scrollback_lines: 5000,
            wheel_lines: 3,
            copy_on_select: false,
            ctrl_c_copies: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TerminalColors {
    /// Light grey on black, like a console window.
    #[default]
    Dark,
    /// Black on white.
    Light,
}

impl TerminalColors {
    pub const ALL: [TerminalColors; 2] = [TerminalColors::Dark, TerminalColors::Light];

    pub fn label(self) -> &'static str {
        match self {
            TerminalColors::Dark => "Light text on black",
            TerminalColors::Light => "Black text on white",
        }
    }

    /// Default (foreground, background) colours.
    fn defaults(self) -> (Color32, Color32) {
        match self {
            TerminalColors::Dark => (Color32::from_rgb(204, 204, 204), Color32::from_rgb(12, 12, 12)),
            TerminalColors::Light => (Color32::from_rgb(12, 12, 12), Color32::from_rgb(255, 255, 255)),
        }
    }
}

const SELECTION: Color32 = Color32::from_rgb(38, 79, 120);
/// The 16 ANSI colours (Windows console palette).
const ANSI: [Color32; 16] = [
    Color32::from_rgb(12, 12, 12),
    Color32::from_rgb(197, 15, 31),
    Color32::from_rgb(19, 161, 14),
    Color32::from_rgb(193, 156, 0),
    Color32::from_rgb(0, 55, 218),
    Color32::from_rgb(136, 23, 152),
    Color32::from_rgb(58, 150, 221),
    Color32::from_rgb(204, 204, 204),
    Color32::from_rgb(118, 118, 118),
    Color32::from_rgb(231, 72, 86),
    Color32::from_rgb(22, 198, 12),
    Color32::from_rgb(249, 241, 165),
    Color32::from_rgb(59, 120, 255),
    Color32::from_rgb(180, 0, 158),
    Color32::from_rgb(97, 214, 214),
    Color32::from_rgb(242, 242, 242),
];

enum Input {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
}

#[derive(Clone, PartialEq, Eq)]
enum State {
    Opening,
    Open,
    Closed(String),
}

/// A cell position on the visible screen: (row, column).
type CellPos = (u16, u16);

pub struct Terminal {
    parser: Arc<Mutex<vt100::Parser>>,
    state: Arc<Mutex<State>>,
    /// Dropping the sender closes the shell channel.
    input: mpsc::UnboundedSender<Input>,
    /// The connection the shell runs on.
    connection: Weak<SftpConnection>,
    /// (rows, cols) last sent to the server.
    size: (u16, u16),
    /// Mouse selection: where the drag started and where it is now.
    selection: Option<(CellPos, CellPos)>,
    /// Mouse-wheel movement not yet turned into whole lines.
    wheel: f32,
    /// Give the view keyboard focus on its next frame.
    focus: bool,
}

impl Terminal {
    /// Starts a login shell of `rows` x `cols` on `connection`. `ctx` is
    /// repainted whenever the shell writes something.
    pub fn open(
        runtime: &Handle,
        connection: &Arc<SftpConnection>,
        ctx: egui::Context,
        settings: &TerminalSettings,
        rows: u16,
        cols: u16,
    ) -> Self {
        let (rows, cols) = (rows.max(2), cols.max(10));
        let scrollback = settings.scrollback_lines as usize;
        let parser = Arc::new(Mutex::new(vt100::Parser::new(nonzero(rows), nonzero(cols), scrollback)));
        let state = Arc::new(Mutex::new(State::Opening));
        let (input, input_rx) = mpsc::unbounded_channel();
        let term = settings.terminal_type.clone();
        runtime.spawn(run_shell(Arc::clone(connection), Arc::clone(&parser), Arc::clone(&state), input_rx, ctx, term, (rows, cols)));
        Self {
            parser,
            state,
            input,
            connection: Arc::downgrade(connection),
            size: (rows, cols),
            selection: None,
            wheel: 0.0,
            focus: true,
        }
    }

    /// The shell runs on `connection` (not on an earlier one).
    pub fn belongs_to(&self, connection: &Arc<SftpConnection>) -> bool {
        self.connection.upgrade().is_some_and(|own| Arc::ptr_eq(&own, connection))
    }

    /// Characters (rows, cols) that fit in a view of `size` points.
    pub fn grid_size(ui: &egui::Ui, settings: &TerminalSettings, size: egui::Vec2) -> (u16, u16) {
        let (cell_w, cell_h) = cell_size(ui, settings);
        let fit = |length: f32, cell: f32| ((length - 4.0) / cell).floor().clamp(1.0, f32::from(u16::MAX)) as u16;
        (fit(size.y, cell_h), fit(size.x, cell_w))
    }

    /// The terminal view, filling the space left in `ui`. Returns true when
    /// the user asked for a new shell after this one ended.
    pub fn show(&mut self, ui: &mut egui::Ui, settings: &TerminalSettings) -> bool {
        let state = self.state.lock().unwrap().clone();
        let mut restart = false;
        if let State::Closed(reason) = &state {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("Shell closed: {reason}")).color(ui.visuals().warn_fg_color));
                restart = ui.button("Open new shell").clicked();
            });
            ui.add_space(2.0);
        }
        let (rect, response) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
        if self.focus || response.clicked() || response.drag_started() {
            response.request_focus();
            self.focus = false;
        }
        let focused = response.has_focus();
        if focused {
            // Keep Tab, arrows and Escape for the shell instead of moving the focus.
            ui.memory_mut(|memory| {
                memory.set_focus_lock_filter(
                    response.id,
                    egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true },
                )
            });
        }

        let (cell_w, cell_h) = cell_size(ui, settings);
        let origin = rect.min + egui::vec2(2.0, 2.0);
        let (rows, cols) = Self::grid_size(ui, settings, rect.size());
        if (rows, cols) != self.size && !matches!(state, State::Closed(_)) {
            self.size = (rows, cols);
            self.parser.lock().unwrap().set_size(nonzero(rows), nonzero(cols));
            self.selection = None;
            let _ = self.input.send(Input::Resize { cols, rows });
        }
        let cell_at = |pos: Pos2| -> CellPos {
            let col = ((pos.x - origin.x) / cell_w).floor().clamp(0.0, f32::from(cols.saturating_sub(1)));
            let row = ((pos.y - origin.y) / cell_h).floor().clamp(0.0, f32::from(rows.saturating_sub(1)));
            (row as u16, col as u16)
        };

        // Mouse: drag selects, a click clears the selection, the wheel scrolls.
        if response.drag_started() {
            if let Some(pos) = response.interact_pointer_pos() {
                let cell = cell_at(pos);
                self.selection = Some((cell, cell));
            }
        } else if response.dragged() {
            if let (Some(pos), Some((_, end))) = (response.interact_pointer_pos(), self.selection.as_mut()) {
                *end = cell_at(pos);
            }
        } else if response.clicked() {
            self.selection = None;
        }
        if response.drag_stopped() && settings.copy_on_select {
            if let Some(text) = self.selected_text().filter(|text| !text.is_empty()) {
                ui.ctx().copy_text(text);
            }
        }
        if response.hovered() {
            let delta = ui.input(|input| input.smooth_scroll_delta.y);
            if delta != 0.0 {
                self.wheel += delta / cell_h;
                let lines = self.wheel.trunc();
                self.wheel -= lines;
                if lines != 0.0 {
                    self.scroll(lines as i32, settings.wheel_lines.max(1) as usize);
                }
            }
        }

        if focused {
            self.handle_keys(ui, settings);
        }

        let parser = self.parser.lock().unwrap();
        let screen = parser.screen();
        let font = FontId::monospace(settings.font_size);
        let (foreground, background) = settings.colors.defaults();
        let look = Look { cell: (cell_w, cell_h), font: font.clone(), colors: (foreground, background) };
        paint_screen(ui, rect, origin, &look, screen, self.selection.map(ordered), focused);
        if state == State::Opening {
            ui.painter().text(origin, egui::Align2::LEFT_TOP, "Opening shell…", font, foreground);
        }
        restart
    }

    /// Mouse wheel: `lines` up (positive) or down. Moves through the
    /// scrollback, or sends arrow keys to full-screen programs.
    fn scroll(&mut self, lines: i32, wheel_lines: usize) {
        let mut parser = self.parser.lock().unwrap();
        let screen = parser.screen_mut();
        if screen.alternate_screen() {
            let key: &[u8] = match (lines > 0, screen.application_cursor()) {
                (true, true) => b"\x1bOA",
                (true, false) => b"\x1b[A",
                (false, true) => b"\x1bOB",
                (false, false) => b"\x1b[B",
            };
            drop(parser);
            let _ = self.input.send(Input::Data(key.repeat(wheel_lines * lines.unsigned_abs() as usize)));
        } else {
            let offset = (screen.scrollback() as i64 + i64::from(lines) * wheel_lines as i64).max(0) as usize;
            screen.set_scrollback(offset);
        }
    }

    /// Sends typed keys, pastes and clipboard shortcuts to the shell.
    /// Text of the mouse selection.
    fn selected_text(&self) -> Option<String> {
        let ((start_row, start_col), (end_row, end_col)) = ordered(self.selection?);
        Some(self.parser.lock().unwrap().screen().contents_between(start_row, start_col, end_row, end_col + 1))
    }

    fn handle_keys(&mut self, ui: &egui::Ui, settings: &TerminalSettings) {
        let (events, shift) = ui.input(|input| (input.events.clone(), input.modifiers.shift));
        let (application_cursor, bracketed_paste) = {
            let parser = self.parser.lock().unwrap();
            (parser.screen().application_cursor(), parser.screen().bracketed_paste())
        };
        let mut out = Vec::new();
        for event in events {
            match event {
                Event::Text(text) => out.extend_from_slice(text.as_bytes()),
                Event::Paste(text) => {
                    let text = text.replace("\r\n", "\r").replace('\n', "\r");
                    if bracketed_paste { out.extend_from_slice(b"\x1b[200~"); }
                    out.extend_from_slice(text.as_bytes());
                    if bracketed_paste { out.extend_from_slice(b"\x1b[201~"); }
                }
                // Ctrl+Shift+C always copies. Ctrl+C copies a selection if set
                // up so, and otherwise interrupts, as in a console.
                Event::Copy => {
                    let copy = shift || settings.ctrl_c_copies;
                    match self.selected_text().filter(|_| copy) {
                        Some(text) => {
                            ui.ctx().copy_text(text);
                            self.selection = None;
                        }
                        None if shift => {}
                        None => out.push(0x03),
                    }
                }
                Event::Cut => out.push(0x18),
                Event::Key { key, pressed: true, modifiers, .. } => {
                    if let Some(bytes) = key_bytes(key, modifiers, application_cursor) {
                        out.extend_from_slice(&bytes);
                    }
                }
                _ => {}
            }
        }
        if !out.is_empty() {
            // Typing returns to the live screen.
            self.parser.lock().unwrap().screen_mut().set_scrollback(0);
            self.selection = None;
            let _ = self.input.send(Input::Data(out));
        }
    }
}

/// Runs the shell channel until it closes or the [`Terminal`] is dropped.
async fn run_shell(
    connection: Arc<SftpConnection>,
    parser: Arc<Mutex<vt100::Parser>>,
    state: Arc<Mutex<State>>,
    mut input: mpsc::UnboundedReceiver<Input>,
    ctx: egui::Context,
    term: String,
    (rows, cols): (u16, u16),
) {
    let close = |reason: String| {
        *state.lock().unwrap() = State::Closed(reason);
        ctx.request_repaint();
    };
    let mut channel = match connection.open_shell(&term, cols, rows).await {
        Ok(channel) => channel,
        Err(error) => {
            connection.log(Severity::Error, "SHELL", &format!("Could not open an SSH terminal: {error}"));
            close(error);
            return;
        }
    };
    connection.log(Severity::Notice, "SHELL", "Opened an SSH terminal");
    *state.lock().unwrap() = State::Open;
    ctx.request_repaint();
    let mut exit_status = None;
    let reason = loop {
        tokio::select! {
            message = channel.wait() => match message {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    parser.lock().unwrap().process(&data);
                    ctx.request_repaint();
                }
                Some(ChannelMsg::ExitStatus { exit_status: status }) => exit_status = Some(status),
                Some(ChannelMsg::ExitSignal { signal_name, .. }) => break format!("shell killed by signal {signal_name:?}"),
                Some(ChannelMsg::Close) | None => break match exit_status {
                    Some(0) | None => "the shell exited".to_owned(),
                    Some(status) => format!("the shell exited with status {status}"),
                },
                Some(_) => {}
            },
            request = input.recv() => match request {
                Some(Input::Data(bytes)) => {
                    if let Err(error) = channel.data(&bytes[..]).await {
                        break format!("sending to the shell failed: {error}");
                    }
                }
                Some(Input::Resize { cols, rows }) => {
                    let _ = channel.window_change(u32::from(cols), u32::from(rows), 0, 0).await;
                }
                // The tab's terminal was dropped (disconnect or new shell).
                None => {
                    let _ = channel.close().await;
                    connection.log(Severity::Info, "SHELL", "Closed the SSH terminal");
                    return;
                }
            },
        }
    };
    connection.log(Severity::Info, "SHELL", &format!("SSH terminal closed: {reason}"));
    close(reason);
}

fn nonzero(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap_or(NonZeroU16::MIN)
}

/// Selection with its start before its end.
fn ordered((a, b): (CellPos, CellPos)) -> (CellPos, CellPos) {
    if a <= b { (a, b) } else { (b, a) }
}

/// Width and height of one character cell, in points.
fn cell_size(ui: &egui::Ui, settings: &TerminalSettings) -> (f32, f32) {
    let font = FontId::monospace(settings.font_size);
    ui.fonts_mut(|fonts| (fonts.glyph_width(&font, 'M'), fonts.row_height(&font)))
}

fn color(color: vt100::Color, default: Color32) -> Color32 {
    match color {
        vt100::Color::Default => default,
        vt100::Color::Idx(index) => indexed_color(index),
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
    }
}

/// xterm 256-colour palette.
fn indexed_color(index: u8) -> Color32 {
    match index {
        0..=15 => ANSI[usize::from(index)],
        16..=231 => {
            let level = |value: u8| if value == 0 { 0 } else { 55 + value * 40 };
            let index = index - 16;
            Color32::from_rgb(level(index / 36), level(index / 6 % 6), level(index % 6))
        }
        _ => {
            let gray = 8 + (index - 232) * 10;
            Color32::from_rgb(gray, gray, gray)
        }
    }
}

/// Foreground and background colour of a cell, after bold, dim and inverse.
fn cell_colors(cell: &vt100::Cell, (foreground, background): (Color32, Color32), selected: bool) -> (Color32, Color32) {
    let mut fg = match cell.fgcolor() {
        // Bold brightens the eight basic colours, as in xterm.
        vt100::Color::Idx(index) if cell.bold() && index < 8 => ANSI[usize::from(index) + 8],
        other => color(other, foreground),
    };
    let mut bg = color(cell.bgcolor(), background);
    if cell.dim() {
        fg = fg.gamma_multiply(0.6);
    }
    if cell.inverse() {
        std::mem::swap(&mut fg, &mut bg);
    }
    if selected {
        bg = SELECTION;
        fg = Color32::WHITE;
    }
    (fg, bg)
}

/// How the screen is drawn: cell size, font and default (fg, bg) colours.
struct Look {
    cell: (f32, f32),
    font: FontId,
    colors: (Color32, Color32),
}

fn paint_screen(
    ui: &egui::Ui,
    rect: Rect,
    origin: Pos2,
    look: &Look,
    screen: &vt100::Screen,
    selection: Option<(CellPos, CellPos)>,
    focused: bool,
) {
    let ((cell_w, cell_h), font, (foreground, background)) = (look.cell, &look.font, look.colors);
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, background);
    let (rows, cols) = screen.size();
    let (rows, cols) = (rows.get(), cols.get());
    let selected = |pos: CellPos| selection.is_some_and(|(start, end)| start <= pos && pos <= end);
    let cell_rect = |row: u16, col: u16, width: u16| {
        Rect::from_min_size(
            origin + egui::vec2(f32::from(col) * cell_w, f32::from(row) * cell_h),
            egui::vec2(f32::from(width) * cell_w, cell_h),
        )
    };
    for row in 0..rows {
        // Runs of ASCII text in one style are drawn as one string; other
        // characters are drawn one by one so a font fallback cannot shift
        // the rest of the line.
        let mut run = String::new();
        let mut run_start = 0;
        let mut run_style = (foreground, false);
        let flush = |run: &mut String, start: u16, (fg, underline): (Color32, bool)| {
            if run.trim_end().is_empty() {
                run.clear();
                return;
            }
            let at = cell_rect(row, start, 1).min;
            painter.text(at, egui::Align2::LEFT_TOP, run.as_str(), font.clone(), fg);
            if underline {
                let y = at.y + cell_h - 1.5;
                let width = run.chars().count() as f32 * cell_w;
                painter.hline(at.x..=at.x + width, y, egui::Stroke::new(1.0_f32, fg));
            }
            run.clear();
        };
        let mut col = 0;
        while col < cols {
            let Some(cell) = screen.cell(row, col) else { break; };
            let width = if cell.is_wide() { 2 } else { 1 };
            let (fg, bg) = cell_colors(cell, (foreground, background), selected((row, col)));
            if bg != background {
                painter.rect_filled(cell_rect(row, col, width), 0.0, bg);
            }
            let text = if cell.has_contents() { cell.contents() } else { " " };
            let style = (fg, cell.underline());
            if text.is_ascii() && width == 1 {
                if style != run_style && !run.is_empty() {
                    flush(&mut run, run_start, run_style);
                }
                if run.is_empty() {
                    run_start = col;
                    run_style = style;
                }
                run.push_str(text);
            } else {
                flush(&mut run, run_start, run_style);
                let cell_box = cell_rect(row, col, width);
                painter.text(cell_box.center(), egui::Align2::CENTER_CENTER, text, font.clone(), fg);
            }
            col += width;
        }
        flush(&mut run, run_start, run_style);
    }
    // Cursor: a block when the view has focus, an outline otherwise.
    if screen.scrollback() == 0 && !screen.hide_cursor() {
        let (row, col) = screen.cursor_position();
        if row < rows && col < cols {
            let cursor = cell_rect(row, col, 1);
            if focused {
                painter.rect_filled(cursor, 0.0, foreground.gamma_multiply(0.7));
                if let Some(cell) = screen.cell(row, col).filter(|cell| cell.has_contents()) {
                    painter.text(cursor.center(), egui::Align2::CENTER_CENTER, cell.contents(), font.clone(), background);
                }
            } else {
                painter.rect_stroke(cursor, 0.0, egui::Stroke::new(1.0_f32, foreground), egui::StrokeKind::Inside);
            }
        }
    }
}

/// Bytes an xterm sends for a key press that does not produce text.
fn key_bytes(key: Key, modifiers: egui::Modifiers, application_cursor: bool) -> Option<Vec<u8>> {
    // Ctrl+letter and the other C0 control combinations.
    if modifiers.ctrl && !modifiers.alt {
        let name = key.name();
        if name.len() == 1 {
            let c = name.as_bytes()[0].to_ascii_uppercase();
            if c.is_ascii_uppercase() {
                return Some(vec![c - b'@']);
            }
        }
        let control = match key {
            Key::Space | Key::Num2 => Some(0x00),
            Key::OpenBracket | Key::Num3 => Some(0x1b),
            Key::Backslash | Key::Num4 => Some(0x1c),
            Key::CloseBracket | Key::Num5 => Some(0x1d),
            Key::Num6 => Some(0x1e),
            Key::Minus | Key::Slash | Key::Num7 => Some(0x1f),
            _ => None,
        };
        if let Some(control) = control {
            return Some(vec![control]);
        }
    }
    // xterm modifier parameter: 1 + shift + 2*alt + 4*ctrl.
    let modifier = 1 + u8::from(modifiers.shift) + 2 * u8::from(modifiers.alt) + 4 * u8::from(modifiers.ctrl);
    let cursor = |letter: char| -> Vec<u8> {
        if modifier > 1 {
            format!("\x1b[1;{modifier}{letter}").into_bytes()
        } else if application_cursor {
            format!("\x1bO{letter}").into_bytes()
        } else {
            format!("\x1b[{letter}").into_bytes()
        }
    };
    let tilde = |code: u8| -> Vec<u8> {
        if modifier > 1 { format!("\x1b[{code};{modifier}~").into_bytes() } else { format!("\x1b[{code}~").into_bytes() }
    };
    let function = |letter: char| -> Vec<u8> {
        if modifier > 1 { format!("\x1b[1;{modifier}{letter}").into_bytes() } else { format!("\x1bO{letter}").into_bytes() }
    };
    Some(match key {
        Key::Enter => b"\r".to_vec(),
        Key::Backspace if modifiers.ctrl => vec![0x08],
        Key::Backspace => vec![0x7f],
        Key::Tab if modifiers.shift => b"\x1b[Z".to_vec(),
        Key::Tab => b"\t".to_vec(),
        Key::Escape => vec![0x1b],
        Key::ArrowUp => cursor('A'),
        Key::ArrowDown => cursor('B'),
        Key::ArrowRight => cursor('C'),
        Key::ArrowLeft => cursor('D'),
        Key::Home => cursor('H'),
        Key::End => cursor('F'),
        Key::Insert => tilde(2),
        Key::Delete => tilde(3),
        Key::PageUp => tilde(5),
        Key::PageDown => tilde(6),
        Key::F1 => function('P'),
        Key::F2 => function('Q'),
        Key::F3 => function('R'),
        Key::F4 => function('S'),
        Key::F5 => tilde(15),
        Key::F6 => tilde(17),
        Key::F7 => tilde(18),
        Key::F8 => tilde(19),
        Key::F9 => tilde(20),
        Key::F10 => tilde(21),
        Key::F11 => tilde(23),
        Key::F12 => tilde(24),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_keys() {
        let ctrl = egui::Modifiers::CTRL;
        assert_eq!(key_bytes(Key::A, ctrl, false), Some(vec![0x01]));
        assert_eq!(key_bytes(Key::D, ctrl, false), Some(vec![0x04]));
        assert_eq!(key_bytes(Key::Z, ctrl, false), Some(vec![0x1a]));
        assert_eq!(key_bytes(Key::OpenBracket, ctrl, false), Some(vec![0x1b]));
    }

    #[test]
    fn cursor_keys_follow_the_mode() {
        let none = egui::Modifiers::NONE;
        assert_eq!(key_bytes(Key::ArrowUp, none, false), Some(b"\x1b[A".to_vec()));
        assert_eq!(key_bytes(Key::ArrowUp, none, true), Some(b"\x1bOA".to_vec()));
        assert_eq!(key_bytes(Key::ArrowLeft, egui::Modifiers::CTRL, true), Some(b"\x1b[1;5D".to_vec()));
        assert_eq!(key_bytes(Key::Delete, none, false), Some(b"\x1b[3~".to_vec()));
        assert_eq!(key_bytes(Key::F1, none, false), Some(b"\x1bOP".to_vec()));
    }

    #[test]
    fn plain_letters_are_left_to_text_events() {
        assert_eq!(key_bytes(Key::A, egui::Modifiers::NONE, false), None);
        assert_eq!(key_bytes(Key::A, egui::Modifiers::SHIFT, false), None);
    }

    #[test]
    fn palette() {
        assert_eq!(indexed_color(16), Color32::from_rgb(0, 0, 0));
        assert_eq!(indexed_color(231), Color32::from_rgb(255, 255, 255));
        assert_eq!(indexed_color(232), Color32::from_rgb(8, 8, 8));
        assert_eq!(indexed_color(255), Color32::from_rgb(238, 238, 238));
    }
}
