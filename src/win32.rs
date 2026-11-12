//! Classic Win32 ("Windows Classic" theme) look for egui: system colours,
//! square corners, 3D bevelled controls, sunken list views and status panels.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use serde::{Deserialize, Serialize};

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Pos2, Rect,
    Response, Sense, Shadow, Stroke, TextStyle, TextWrapMode, Ui, WidgetText,
};

/// Light (Windows Classic) or dark colours.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Theme {
    #[default]
    Light,
    Dark,
}

impl Theme {
    pub fn label(self) -> &'static str {
        match self {
            Theme::Light => "Light (Windows Classic)",
            Theme::Dark => "Dark",
        }
    }
}

/// The colours of one theme, named after the Win32 system colours.
struct Palette {
    /// COLOR_3DFACE / COLOR_BTNFACE
    face: Color32,
    /// COLOR_3DHIGHLIGHT
    highlight: Color32,
    /// COLOR_3DLIGHT
    light: Color32,
    /// COLOR_3DSHADOW
    shadow: Color32,
    /// COLOR_3DDKSHADOW
    dark_shadow: Color32,
    /// COLOR_WINDOW (list views, edit controls)
    window: Color32,
    /// COLOR_WINDOWTEXT / COLOR_BTNTEXT
    text: Color32,
    /// COLOR_GRAYTEXT
    gray_text: Color32,
    /// COLOR_HIGHLIGHT (selection background)
    selection: Color32,
    /// COLOR_HIGHLIGHTTEXT
    selection_text: Color32,
    ok_green: Color32,
    error_red: Color32,
    warn_amber: Color32,
    /// COLOR_SCROLLBAR: the scroll bar track (classic Windows dithers the
    /// highlight and button face; this is the blend). Also checked toolbar buttons.
    scroll_track: Color32,
    scroll_thumb: Color32,
    scroll_thumb_hovered: Color32,
    scroll_thumb_dragged: Color32,
    /// Face of a pressed button.
    pressed_face: Color32,
    /// Background of selected text in edit boxes.
    text_selection: Color32,
    hyperlink: Color32,
    faint_bg: Color32,
    /// Selected row of the transfer queue: light enough for normal text.
    queue_selection: Color32,
    /// Grid lines of graphs.
    grid: Color32,
}

const LIGHT_PALETTE: Palette = Palette {
    face: Color32::from_rgb(212, 208, 200),
    highlight: Color32::WHITE,
    light: Color32::from_rgb(223, 223, 223),
    shadow: Color32::from_rgb(128, 128, 128),
    dark_shadow: Color32::from_rgb(64, 64, 64),
    window: Color32::WHITE,
    text: Color32::BLACK,
    gray_text: Color32::from_rgb(128, 128, 128),
    selection: Color32::from_rgb(10, 36, 106),
    selection_text: Color32::WHITE,
    ok_green: Color32::from_rgb(0, 128, 0),
    error_red: Color32::from_rgb(170, 0, 0),
    warn_amber: Color32::from_rgb(150, 80, 0),
    scroll_track: Color32::from_rgb(234, 232, 228),
    scroll_thumb: Color32::from_rgb(176, 172, 166),
    scroll_thumb_hovered: Color32::from_rgb(150, 147, 141),
    scroll_thumb_dragged: Color32::from_rgb(128, 128, 128),
    pressed_face: Color32::from_rgb(196, 192, 184),
    text_selection: Color32::from_rgb(166, 202, 240),
    hyperlink: Color32::from_rgb(0, 0, 255),
    faint_bg: Color32::from_rgb(236, 234, 230),
    queue_selection: Color32::from_rgb(204, 220, 245),
    grid: Color32::from_rgb(225, 225, 225),
};

const DARK_PALETTE: Palette = Palette {
    face: Color32::from_rgb(48, 48, 52),
    highlight: Color32::from_rgb(96, 96, 102),
    light: Color32::from_rgb(70, 70, 75),
    shadow: Color32::from_rgb(24, 24, 26),
    dark_shadow: Color32::from_rgb(8, 8, 9),
    window: Color32::from_rgb(30, 30, 33),
    text: Color32::from_rgb(222, 222, 222),
    gray_text: Color32::from_rgb(140, 140, 145),
    selection: Color32::from_rgb(38, 79, 150),
    selection_text: Color32::WHITE,
    ok_green: Color32::from_rgb(110, 200, 110),
    error_red: Color32::from_rgb(240, 110, 110),
    warn_amber: Color32::from_rgb(235, 175, 70),
    scroll_track: Color32::from_rgb(40, 40, 44),
    scroll_thumb: Color32::from_rgb(88, 88, 94),
    scroll_thumb_hovered: Color32::from_rgb(110, 110, 116),
    scroll_thumb_dragged: Color32::from_rgb(132, 132, 138),
    pressed_face: Color32::from_rgb(38, 38, 42),
    text_selection: Color32::from_rgb(50, 90, 150),
    hyperlink: Color32::from_rgb(120, 170, 255),
    faint_bg: Color32::from_rgb(40, 40, 44),
    queue_selection: Color32::from_rgb(45, 66, 102),
    grid: Color32::from_rgb(58, 58, 62),
};

static DARK: AtomicBool = AtomicBool::new(false);

fn palette() -> &'static Palette {
    if DARK.load(Ordering::Relaxed) { &DARK_PALETTE } else { &LIGHT_PALETTE }
}

pub fn face() -> Color32 { palette().face }
pub fn highlight() -> Color32 { palette().highlight }
pub fn light() -> Color32 { palette().light }
pub fn shadow() -> Color32 { palette().shadow }
pub fn dark_shadow() -> Color32 { palette().dark_shadow }
pub fn window() -> Color32 { palette().window }
pub fn text_color() -> Color32 { palette().text }
pub fn gray_text() -> Color32 { palette().gray_text }
pub fn selection() -> Color32 { palette().selection }
pub fn selection_text() -> Color32 { palette().selection_text }
pub fn ok_green() -> Color32 { palette().ok_green }
pub fn error_red() -> Color32 { palette().error_red }
pub fn warn_amber() -> Color32 { palette().warn_amber }
pub fn scroll_track() -> Color32 { palette().scroll_track }
pub fn queue_selection() -> Color32 { palette().queue_selection }
pub fn grid() -> Color32 { palette().grid }

/// Install the Win32 theme in light or dark colours and, if available, a
/// Windows-like UI font. Call again to switch themes.
pub fn apply(ctx: &egui::Context, theme: Theme) {
    install_font(ctx);
    DARK.store(theme == Theme::Dark, Ordering::Relaxed);
    let colors = palette();
    ctx.set_theme(if theme == Theme::Dark { egui::ThemePreference::Dark } else { egui::ThemePreference::Light });
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Small, FontId::proportional(11.0)),
            (TextStyle::Body, FontId::proportional(12.5)),
            (TextStyle::Button, FontId::proportional(12.5)),
            (TextStyle::Monospace, FontId::monospace(12.0)),
            (TextStyle::Heading, FontId::proportional(15.0)),
        ]
        .into();

        let spacing = &mut style.spacing;
        spacing.item_spacing = egui::vec2(4.0, 3.0);
        spacing.button_padding = egui::vec2(6.0, 2.0);
        spacing.interact_size.y = 21.0;
        spacing.window_margin = egui::Margin::same(8);
        spacing.menu_margin = egui::Margin::same(2);
        spacing.scroll = egui::style::ScrollStyle::solid();
        spacing.scroll.bar_width = 14.0;
        spacing.scroll.bar_inner_margin = 0.0;
        spacing.scroll.handle_min_length = 16.0;
        spacing.scroll.dormant_background_opacity = 1.0;
        spacing.scroll.active_background_opacity = 1.0;
        spacing.scroll.interact_background_opacity = 1.0;
        spacing.scroll.dormant_handle_opacity = 1.0;
        spacing.scroll.active_handle_opacity = 1.0;
        spacing.scroll.interact_handle_opacity = 1.0;

        let visuals = &mut style.visuals;
        *visuals = if theme == Theme::Dark { egui::Visuals::dark() } else { egui::Visuals::light() };
        visuals.override_text_color = None;
        visuals.weak_text_color = Some(gray_text());
        visuals.hyperlink_color = colors.hyperlink;
        visuals.faint_bg_color = colors.faint_bg;
        visuals.extreme_bg_color = window();
        visuals.text_edit_bg_color = Some(window());
        visuals.code_bg_color = window();
        visuals.warn_fg_color = warn_amber();
        visuals.error_fg_color = error_red();
        visuals.panel_fill = face();
        visuals.window_fill = face();
        visuals.window_stroke = Stroke::new(1.0, dark_shadow());
        visuals.window_corner_radius = CornerRadius::ZERO;
        visuals.menu_corner_radius = CornerRadius::ZERO;
        visuals.window_shadow = Shadow::NONE;
        visuals.popup_shadow = Shadow { offset: [2, 2], blur: 0, spread: 0, color: Color32::from_black_alpha(90) };
        // egui does not recolour selected text in edit boxes, so use a light
        // highlight for generic selection; navy is reserved for list views/menus.
        visuals.selection.bg_fill = colors.text_selection;
        visuals.selection.stroke = Stroke::new(1.0, text_color());
        visuals.text_cursor.stroke = Stroke::new(1.0, text_color());
        visuals.text_cursor.blink = true;
        visuals.slider_trailing_fill = false;
        visuals.handle_shape = egui::style::HandleShape::Rect { aspect_ratio: 0.5 };
        visuals.striped = false;

        let widgets = &mut visuals.widgets;
        for w in [
            &mut widgets.noninteractive,
            &mut widgets.inactive,
            &mut widgets.hovered,
            &mut widgets.active,
            &mut widgets.open,
        ] {
            w.corner_radius = CornerRadius::ZERO;
            w.expansion = 0.0;
            w.fg_stroke = Stroke::new(1.0, text_color());
        }
        widgets.noninteractive.bg_fill = face();
        widgets.noninteractive.weak_bg_fill = face();
        widgets.noninteractive.bg_stroke = Stroke::new(1.0, shadow());

        widgets.inactive.bg_fill = window(); // checkbox / edit backgrounds
        widgets.inactive.weak_bg_fill = face(); // button / combo backgrounds
        widgets.inactive.bg_stroke = Stroke::new(1.0, shadow());

        widgets.hovered.bg_fill = window();
        widgets.hovered.weak_bg_fill = face();
        widgets.hovered.bg_stroke = Stroke::new(1.0, dark_shadow());

        widgets.active.bg_fill = window();
        widgets.active.weak_bg_fill = colors.pressed_face;
        widgets.active.bg_stroke = Stroke::new(1.0, dark_shadow());

        widgets.open.bg_fill = window();
        widgets.open.weak_bg_fill = face();
        widgets.open.bg_stroke = Stroke::new(1.0, dark_shadow());
    });
}

fn install_font(ctx: &egui::Context) {
    const CANDIDATES: &[&str] = &[
        "C:\\Windows\\Fonts\\tahoma.ttf",
        "/usr/share/fonts/TTF/tahoma.ttf",
        "/usr/share/fonts/truetype/msttcorefonts/tahoma.ttf",
        "/usr/share/wine/fonts/tahoma.ttf",
        "/usr/share/fonts/wine-tahoma-fonts/tahoma.ttf",
        "/usr/share/fonts/liberation-fonts/LiberationSans-Regular.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/TTF/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ];
    /// Fuller fonts for characters the UI font lacks (Wine's Tahoma has no
    /// arrows, for example); egui's own fonts do not cover them either.
    const FALLBACKS: &[&str] = &[
        "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/liberation-fonts/LiberationSans-Regular.ttf",
        "/usr/share/fonts/TTF/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ];
    let Some((primary, bytes)) = CANDIDATES.iter().find_map(|path| std::fs::read(path).ok().map(|bytes| (*path, bytes))) else { return; };
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert("win32-ui".into(), Arc::new(FontData::from_owned(bytes)));
    let family = fonts.families.entry(FontFamily::Proportional).or_default();
    family.insert(0, "win32-ui".into());
    let fallback = FALLBACKS.iter().filter(|path| **path != primary).find_map(|path| std::fs::read(path).ok());
    if let Some(bytes) = fallback {
        fonts.font_data.insert("win32-ui-fallback".into(), Arc::new(FontData::from_owned(bytes)));
        fonts.families.entry(FontFamily::Proportional).or_default().insert(1, "win32-ui-fallback".into());
    }
    ctx.set_fonts(fonts);
}

/// Paint a one-pixel edge: `tl` on the top/left, `br` on the bottom/right.
fn edge(painter: &egui::Painter, rect: Rect, tl: Color32, br: Color32) {
    let px = pixel(painter);
    let r = rect;
    painter.rect_filled(Rect::from_min_max(r.min, Pos2::new(r.max.x - px, r.min.y + px)), 0.0, tl);
    painter.rect_filled(Rect::from_min_max(r.min, Pos2::new(r.min.x + px, r.max.y - px)), 0.0, tl);
    painter.rect_filled(Rect::from_min_max(Pos2::new(r.min.x, r.max.y - px), r.max), 0.0, br);
    painter.rect_filled(Rect::from_min_max(Pos2::new(r.max.x - px, r.min.y), r.max), 0.0, br);
}

/// One logical pixel, snapped to whole physical pixels.
fn pixel(painter: &egui::Painter) -> f32 {
    let ppp = painter.pixels_per_point();
    ppp.round().max(1.0) / ppp
}

/// EDGE_RAISED, as used by push buttons.
pub fn raised(painter: &egui::Painter, rect: Rect) {
    let rect = painter.round_rect_to_pixels(rect);
    let px = pixel(painter);
    edge(painter, rect, light(), dark_shadow());
    edge(painter, rect.shrink(px), highlight(), shadow());
}

/// EDGE_SUNKEN, as used by list views and edit controls.
pub fn sunken(painter: &egui::Painter, rect: Rect) {
    let rect = painter.round_rect_to_pixels(rect);
    let px = pixel(painter);
    edge(painter, rect, shadow(), highlight());
    edge(painter, rect.shrink(px), dark_shadow(), light());
}

/// BDR_SUNKENOUTER, the shallow edge used by status-bar panes and progress bars.
pub fn thin_sunken(painter: &egui::Painter, rect: Rect) {
    edge(painter, painter.round_rect_to_pixels(rect), shadow(), highlight());
}

/// BDR_RAISEDINNER, used by list-view column headers.
pub fn thin_raised(painter: &egui::Painter, rect: Rect) {
    let rect = painter.round_rect_to_pixels(rect);
    edge(painter, rect, highlight(), dark_shadow());
    edge(painter, rect.shrink(pixel(painter)), face(), shadow());
}

fn text_galley(ui: &Ui, text: impl Into<WidgetText>) -> Arc<egui::Galley> {
    let text: WidgetText = text.into();
    text.into_galley(ui, Some(TextWrapMode::Extend), f32::INFINITY, TextStyle::Button)
}

/// Paint text the way Win32 draws disabled labels: white emboss under gray.
fn paint_text(painter: &egui::Painter, pos: Pos2, galley: Arc<egui::Galley>, enabled: bool) {
    if enabled {
        painter.galley(pos, galley, text_color());
    } else {
        painter.galley(pos + egui::vec2(1.0, 1.0), galley.clone(), highlight());
        painter.galley(pos, galley, gray_text());
    }
}

/// Push button with a minimum width (dialog buttons are traditionally 75 px).
pub fn button_sized(ui: &mut Ui, enabled: bool, text: &str, min_width: f32) -> Response {
    let galley = text_galley(ui, text);
    let size = egui::vec2(
        (galley.size().x + 18.0).max(min_width),
        (galley.size().y + 8.0).max(ui.spacing().interact_size.y + 2.0),
    );
    let (rect, response) = ui.allocate_exact_size(size, if enabled { Sense::click() } else { Sense::hover() });
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect_filled(rect, 0.0, face());
        let pressed = enabled && response.is_pointer_button_down_on() && response.contains_pointer();
        let mut text_pos = rect.center() - galley.size() / 2.0;
        if pressed {
            let rect = painter.round_rect_to_pixels(rect);
            edge(painter, rect, dark_shadow(), dark_shadow());
            edge(painter, rect.shrink(pixel(painter)), shadow(), shadow());
            text_pos += egui::vec2(1.0, 1.0);
        } else {
            raised(painter, rect);
        }
        if response.has_focus() {
            painter.rect_stroke(
                rect.shrink(4.0),
                0.0,
                Stroke::new(1.0, dark_shadow()),
                egui::StrokeKind::Inside,
            );
        }
        paint_text(painter, text_pos.round(), galley, enabled);
    }
    response
}

/// List-view column header cell.
pub fn header_cell(ui: &mut Ui, width: f32, height: f32, text: &str) {
    let _ = header_button(ui, width, height, text, None);
}

/// Clickable list-view column header; `sorted` shows the sort direction
/// (`Some(true)` ascending) on the column the list is sorted by.
pub fn header_button(ui: &mut Ui, width: f32, height: f32, text: &str, sorted: Option<bool>) -> Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), Sense::click());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let pressed = response.is_pointer_button_down_on() && response.contains_pointer();
        painter.rect_filled(rect, 0.0, face());
        if pressed {
            edge(painter, painter.round_rect_to_pixels(rect), shadow(), highlight());
        } else {
            thin_raised(painter, rect);
        }
        let nudge = if pressed { 1.0 } else { 0.0 };
        let arrow_room = if sorted.is_some() { 14.0 } else { 0.0 };
        let galley = WidgetText::from(text).into_galley(ui, Some(TextWrapMode::Truncate), (width - 10.0 - arrow_room).max(0.0), TextStyle::Body);
        painter.galley(Pos2::new(rect.left() + 5.0 + nudge, rect.center().y - galley.size().y / 2.0 + nudge), galley, text_color());
        if let Some(ascending) = sorted {
            // Explorer-style sort arrow at the right edge of the header.
            let center = Pos2::new(rect.right() - 9.0 + nudge, rect.center().y + nudge);
            let (tip, base) = if ascending { (-3.0, 2.0) } else { (3.0, -2.0) };
            painter.add(egui::Shape::convex_polygon(
                vec![
                    Pos2::new(center.x, center.y + tip),
                    Pos2::new(center.x + 4.0, center.y + base),
                    Pos2::new(center.x - 4.0, center.y + base),
                ],
                shadow(),
                Stroke::NONE,
            ));
        }
    }
    response
}

/// Shows `area` with visible scroll bars.
///
/// egui paints the track with `extreme_bg_color` and the thumb with the
/// widgets' `bg_fill`, both white in this theme (they are also the list and
/// checkbox backgrounds), so the bars would be invisible. The scroll bar
/// colours apply to the area's own `ui`; the contents get the normal visuals.
pub fn scroll<R>(
    ui: &mut Ui,
    area: egui::ScrollArea,
    add_contents: impl FnOnce(&mut Ui) -> R,
) -> egui::scroll_area::ScrollAreaOutput<R> {
    let normal = ui.visuals().clone();
    ui.scope(|ui| {
        let visuals = ui.visuals_mut();
        let colors = palette();
        visuals.extreme_bg_color = colors.scroll_track;
        visuals.widgets.inactive.bg_fill = colors.scroll_thumb;
        visuals.widgets.hovered.bg_fill = colors.scroll_thumb_hovered;
        visuals.widgets.active.bg_fill = colors.scroll_thumb_dragged;
        area.show(ui, |ui| {
            *ui.visuals_mut() = normal;
            add_contents(ui)
        })
    })
    .inner
}

/// White, sunken "client edge" area — the frame around list views.
/// `height` is the total outer height, including the 2 px edge.
pub fn list_view<R>(ui: &mut Ui, height: f32, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
    let inner = egui::Frame::new()
        .fill(window())
        .inner_margin(egui::Margin::same(2))
        .show(ui, |ui| {
            ui.set_height((height - 4.0).max(0.0));
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
            add_contents(ui)
        });
    sunken(ui.painter(), inner.response.rect);
    inner.inner
}

/// Win32 tab control strip. Returns true if the selection changed.
pub fn tab_strip<T: PartialEq + Copy>(ui: &mut Ui, current: &mut T, tabs: &[(T, String)]) -> bool {
    let mut changed = false;
    let height = 21.0;
    let start = ui.cursor().min;
    let mut selected_span = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for (value, label) in tabs {
            let selected = *current == *value;
            let galley = text_galley(ui, label.as_str());
            let size = egui::vec2(galley.size().x + 20.0, height);
            let (rect, response) = ui.allocate_exact_size(size, Sense::click());
            if response.clicked() && !selected {
                *current = *value;
                changed = true;
            }
            let painter = ui.painter();
            let px = pixel(painter);
            // Selected tabs are taller and overlap their neighbours slightly.
            let tab = if selected { rect.expand2(egui::vec2(2.0, 0.0)) } else { Rect::from_min_max(rect.min + egui::vec2(0.0, 2.0), rect.max) };
            let tab = painter.round_rect_to_pixels(tab);
            painter.rect_filled(tab, 0.0, face());
            painter.rect_filled(Rect::from_min_max(tab.min, Pos2::new(tab.min.x + px, tab.max.y)), 0.0, highlight());
            painter.rect_filled(Rect::from_min_max(tab.min, Pos2::new(tab.max.x, tab.min.y + px)), 0.0, highlight());
            painter.rect_filled(Rect::from_min_max(Pos2::new(tab.max.x - px, tab.min.y), tab.max), 0.0, dark_shadow());
            painter.rect_filled(Rect::from_min_max(Pos2::new(tab.max.x - 2.0 * px, tab.min.y + px), Pos2::new(tab.max.x - px, tab.max.y)), 0.0, shadow());
            let text_pos = (tab.center() - galley.size() / 2.0 + egui::vec2(0.0, if selected { -1.0 } else { 0.0 })).round();
            painter.galley(text_pos, galley, text_color());
            if selected { selected_span = Some(tab.x_range()); }
        }
    });
    // Top edge of the tab page, interrupted under the selected tab.
    let painter = ui.painter();
    let px = pixel(painter);
    let y = (start.y + height).round();
    let right = ui.max_rect().right();
    let line = |from: f32, to: f32| {
        if to > from {
            painter.rect_filled(Rect::from_min_max(Pos2::new(from, y - px), Pos2::new(to, y)), 0.0, highlight());
        }
    };
    match selected_span {
        Some(span) => { line(start.x, span.min); line(span.max, right); }
        None => line(start.x, right),
    }
    changed
}

/// Status-bar pane: shallow sunken box holding a line of text.
pub fn status_pane(ui: &mut Ui, width: f32, text: impl Into<WidgetText>) -> Response {
    let height = ui.available_height().max(18.0);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), Sense::hover());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        thin_sunken(painter, rect);
        let text: WidgetText = text.into();
        let galley = text.into_galley(ui, Some(TextWrapMode::Truncate), width - 8.0, TextStyle::Body);
        painter.galley(Pos2::new(rect.left() + 4.0, rect.center().y - galley.size().y / 2.0).round(), galley, text_color());
    }
    response
}

/// Etched vertical separator used between toolbar button groups.
pub fn toolbar_separator(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, ui.spacing().interact_size.y), Sense::hover());
    let painter = ui.painter();
    let px = pixel(painter);
    let x = rect.center().x.round();
    painter.rect_filled(Rect::from_min_max(Pos2::new(x - px, rect.top()), Pos2::new(x, rect.bottom())), 0.0, shadow());
    painter.rect_filled(Rect::from_min_max(Pos2::new(x, rect.top()), Pos2::new(x + px, rect.bottom())), 0.0, highlight());
}

/// Etched horizontal line (SS_ETCHEDHORZ).
pub fn etched_hline(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 4.0), Sense::hover());
    let painter = ui.painter();
    let px = pixel(painter);
    let y = rect.center().y.round();
    painter.rect_filled(Rect::from_min_max(Pos2::new(rect.left(), y - px), Pos2::new(rect.right(), y)), 0.0, shadow());
    painter.rect_filled(Rect::from_min_max(Pos2::new(rect.left(), y), Pos2::new(rect.right(), y + px)), 0.0, highlight());
}

/// Panel frame with no inner stroke and the 3D face colour.
pub fn panel_frame(margin: i8) -> egui::Frame {
    egui::Frame::new().fill(face()).inner_margin(egui::Margin::same(margin))
}

/// Menu items: flat, highlighted in navy with white text on hover.
pub fn menu_item_style(style: &mut egui::Style) {
    egui::containers::menu::menu_style(style);
    style.spacing.button_padding = egui::vec2(8.0, 2.0);
    for w in [&mut style.visuals.widgets.hovered, &mut style.visuals.widgets.active, &mut style.visuals.widgets.open] {
        w.weak_bg_fill = selection();
        w.bg_fill = selection();
        w.bg_stroke = Stroke::NONE;
        w.fg_stroke = Stroke::new(1.0, selection_text());
    }
}

/// Read-only sunken white field (e.g. an address box).
pub fn field(ui: &mut Ui, text: &str) {
    let height = ui.spacing().interact_size.y;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::hover());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect_filled(rect, 0.0, window());
        sunken(painter, rect);
        let galley = WidgetText::from(text).into_galley(ui, Some(TextWrapMode::Truncate), rect.width() - 10.0, TextStyle::Body);
        painter.galley(Pos2::new(rect.left() + 5.0, rect.center().y - galley.size().y / 2.0).round(), galley, text_color());
    }
}

/// Edit control with a sunken client edge.
pub fn text_edit(ui: &mut Ui, edit: egui::TextEdit<'_>) -> Response {
    let inner = egui::Frame::new()
        .fill(window())
        .inner_margin(egui::Margin::symmetric(3, 3))
        .show(ui, |ui| ui.add(edit.frame(false).margin(egui::Margin::ZERO)));
    sunken(ui.painter(), inner.response.rect);
    inner.inner
}

/// Full-width list-box row, navy when selected.
pub fn list_item(ui: &mut Ui, text: &str, selected: bool) -> Response {
    let height = 18.0;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::click());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let color = if selected { selection_text() } else { text_color() };
        if selected {
            painter.rect_filled(rect, 0.0, selection());
        }
        let galley = WidgetText::from(text).into_galley(ui, Some(TextWrapMode::Truncate), rect.width() - 10.0, TextStyle::Body);
        painter.galley(Pos2::new(rect.left() + 5.0, rect.center().y - galley.size().y / 2.0).round(), galley, color);
    }
    response
}

/// Toolbar / message-box icons, painted as vectors on a 16×16 grid.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Icon {
    Up,
    Refresh,
    Connect,
    Disconnect,
    Settings,
    Upload,
    Download,
    Warning,
    Information,
    /// An eye: show / hide hidden items.
    HiddenItems,
    /// A folder with a green plus.
    NewFolder,
}

/// Paint `icon` into `rect` (any square size; drawn on a 16-unit grid).
/// Disabled icons are drawn in washed-out grayscale.
pub fn paint_icon(painter: &egui::Painter, rect: Rect, icon: Icon, enabled: bool) {
    let scale = rect.width().min(rect.height()) / 16.0;
    let origin = rect.center() - egui::vec2(8.0, 8.0) * scale;
    let p = |x: f32, y: f32| origin + egui::vec2(x, y) * scale;
    let c = |color: Color32| {
        if enabled { return color; }
        let l = 0.3 * color.r() as f32 + 0.59 * color.g() as f32 + 0.11 * color.b() as f32;
        let v = (150.0 + l * 0.3).round() as u8;
        Color32::from_rgb(v, v, v)
    };
    let fill_rect = |x0: f32, y0: f32, x1: f32, y1: f32, color: Color32| {
        painter.rect_filled(Rect::from_min_max(p(x0, y0), p(x1, y1)), 0.0, c(color));
    };
    let outlined_rect = |x0: f32, y0: f32, x1: f32, y1: f32, fill: Color32, outline: Color32| {
        painter.rect(
            Rect::from_min_max(p(x0, y0), p(x1, y1)),
            0.0,
            c(fill),
            Stroke::new(scale.max(1.0), c(outline)),
            egui::StrokeKind::Inside,
        );
    };
    let triangle = |a: (f32, f32), b: (f32, f32), d: (f32, f32), color: Color32| {
        painter.add(egui::Shape::convex_polygon(vec![p(a.0, a.1), p(b.0, b.1), p(d.0, d.1)], c(color), Stroke::NONE));
    };
    let green = Color32::from_rgb(0, 128, 0);
    let blue = Color32::from_rgb(30, 100, 200);
    let folder = Color32::from_rgb(255, 222, 110);
    let folder_edge = Color32::from_rgb(128, 96, 0);
    let metal = Color32::from_rgb(90, 90, 90);
    let tray = |painter: &egui::Painter| {
        let stroke = Stroke::new(1.5 * scale, c(dark_shadow()));
        painter.add(egui::Shape::line(vec![p(1.5, 10.0), p(1.5, 14.5), p(14.5, 14.5), p(14.5, 10.0)], stroke));
    };

    match icon {
        Icon::Up => {
            outlined_rect(1.0, 5.0, 6.0, 7.5, Color32::from_rgb(240, 200, 80), folder_edge);
            outlined_rect(1.0, 6.5, 12.0, 14.5, folder, folder_edge);
            triangle((11.0, 0.5), (15.5, 5.5), (6.5, 5.5), green);
            fill_rect(9.8, 5.5, 12.2, 11.0, green);
        }
        Icon::Refresh => {
            let center = p(8.0, 8.0);
            let radius = 5.2 * scale;
            let (start, end) = (20.0_f32.to_radians(), 300.0_f32.to_radians());
            let points: Vec<Pos2> = (0..=24)
                .map(|i| start + (end - start) * i as f32 / 24.0)
                .map(|a| center + egui::vec2(a.cos(), a.sin()) * radius)
                .collect();
            painter.add(egui::Shape::line(points, Stroke::new(2.2 * scale, c(green))));
            let normal = egui::vec2(end.cos(), end.sin());
            let tangent = egui::vec2(-end.sin(), end.cos());
            let tip = center + normal * radius + tangent * 3.8 * scale;
            let base = center + normal * radius - tangent * 0.6 * scale;
            painter.add(egui::Shape::convex_polygon(
                vec![tip, base + normal * 3.2 * scale, base - normal * 3.2 * scale],
                c(green),
                Stroke::NONE,
            ));
        }
        Icon::Connect | Icon::Disconnect => {
            let connected = icon == Icon::Connect;
            let gap = if connected { 0.0 } else { 2.0 };
            let body = if connected { Color32::from_rgb(40, 140, 60) } else { metal };
            // Cables.
            fill_rect(0.0, 7.3, 3.0 - gap, 8.7, dark_shadow());
            fill_rect(13.0 + gap, 7.3, 16.0, 8.7, dark_shadow());
            // Plug with two prongs.
            outlined_rect(3.0 - gap, 4.5, 8.0 - gap, 11.5, body, dark_shadow());
            fill_rect(8.0 - gap, 5.8, 10.5 - gap, 7.0, dark_shadow());
            fill_rect(8.0 - gap, 9.0, 10.5 - gap, 10.2, dark_shadow());
            // Socket.
            outlined_rect(10.5 + gap, 3.5, 13.0 + gap, 12.5, body, dark_shadow());
            if !connected {
                painter.line_segment([p(2.0, 14.0), p(14.0, 2.0)], Stroke::new(2.0 * scale, c(error_red())));
            }
        }
        Icon::Settings => {
            let center = p(8.0, 8.0);
            let gear = Color32::from_rgb(96, 96, 96);
            for k in 0..8 {
                let a = (k as f32) * std::f32::consts::FRAC_PI_4;
                let (dir, side) = (egui::vec2(a.cos(), a.sin()), egui::vec2(-a.sin(), a.cos()));
                let (inner, outer, half) = (3.5 * scale, 7.3 * scale, 1.5 * scale);
                painter.add(egui::Shape::convex_polygon(
                    vec![
                        center + dir * inner - side * half,
                        center + dir * outer - side * half,
                        center + dir * outer + side * half,
                        center + dir * inner + side * half,
                    ],
                    c(gear),
                    Stroke::NONE,
                ));
            }
            painter.circle_filled(center, 5.2 * scale, c(gear));
            painter.circle_filled(center, 2.1 * scale, face());
        }
        Icon::Upload => {
            tray(painter);
            triangle((8.0, 0.5), (13.0, 6.0), (3.0, 6.0), blue);
            fill_rect(6.8, 6.0, 9.2, 12.0, blue);
        }
        Icon::Download => {
            tray(painter);
            fill_rect(6.8, 0.5, 9.2, 6.5, green);
            triangle((3.0, 6.5), (13.0, 6.5), (8.0, 12.0), green);
        }
        Icon::Warning => {
            painter.add(egui::Shape::convex_polygon(
                vec![p(8.0, 0.5), p(15.5, 15.0), p(0.5, 15.0)],
                c(Color32::from_rgb(255, 204, 0)),
                Stroke::new(scale.max(1.0), c(Color32::BLACK)),
            ));
            fill_rect(7.2, 5.0, 8.8, 10.5, Color32::BLACK);
            fill_rect(7.2, 11.8, 8.8, 13.4, Color32::BLACK);
        }
        Icon::NewFolder => {
            outlined_rect(0.5, 5.0, 5.5, 7.5, Color32::from_rgb(240, 200, 80), folder_edge);
            outlined_rect(0.5, 6.5, 12.0, 14.5, folder, folder_edge);
            // The plus, with a white outline so it stands out from the folder.
            fill_rect(10.0, 0.0, 14.0, 9.0, Color32::WHITE);
            fill_rect(7.5, 2.5, 16.0, 6.5, Color32::WHITE);
            fill_rect(11.0, 1.0, 13.0, 8.0, green);
            fill_rect(8.5, 3.5, 15.5, 5.5, green);
        }
        Icon::HiddenItems => {
            // Almond-shaped eye with an iris and pupil.
            let outline: Vec<Pos2> = (0..=16)
                .map(|k| {
                    let t = k as f32 / 16.0 * std::f32::consts::PI;
                    p(8.0 - 7.0 * t.cos(), 8.0 - 4.6 * t.sin())
                })
                .chain((1..16).map(|k| {
                    let t = k as f32 / 16.0 * std::f32::consts::PI;
                    p(8.0 + 7.0 * t.cos(), 8.0 + 4.6 * t.sin())
                }))
                .collect();
            painter.add(egui::Shape::convex_polygon(outline, c(Color32::WHITE), Stroke::new(scale.max(1.0), c(dark_shadow()))));
            painter.circle_filled(p(8.0, 8.0), 3.0 * scale, c(blue));
            painter.circle_filled(p(8.0, 8.0), 1.3 * scale, c(Color32::BLACK));
            painter.circle_filled(p(7.0, 7.0), 0.7 * scale, c(Color32::WHITE));
        }
        Icon::Information => {
            let center = p(8.0, 8.0);
            painter.circle(center, 7.2 * scale, c(Color32::from_rgb(30, 90, 200)), Stroke::new(scale.max(1.0), c(Color32::from_rgb(10, 50, 130))));
            painter.circle_filled(p(8.0, 4.3), 1.2 * scale, Color32::WHITE);
            fill_rect(7.0, 6.6, 9.0, 12.2, Color32::WHITE);
        }
    }
}

/// Flat toolbar button showing an icon; raises on hover, sinks when pressed.
pub fn icon_button(ui: &mut Ui, enabled: bool, icon: Icon, tooltip: &str) -> Response {
    let size = egui::vec2(25.0, 23.0);
    let (rect, response) = ui.allocate_exact_size(size, if enabled { Sense::click() } else { Sense::hover() });
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let pressed = enabled && response.is_pointer_button_down_on() && response.contains_pointer();
        let mut icon_rect = Rect::from_center_size(rect.center(), egui::vec2(16.0, 16.0));
        if pressed {
            thin_sunken(painter, rect);
            icon_rect = icon_rect.translate(egui::vec2(1.0, 1.0));
        } else if enabled && response.hovered() {
            edge(painter, painter.round_rect_to_pixels(rect), highlight(), shadow());
        }
        paint_icon(painter, icon_rect, icon, enabled);
    }
    response.on_hover_text(tooltip)
}

/// Toolbar button that stays pressed in while `on`, like a checked Win32
/// toolbar button.
pub fn icon_toggle(ui: &mut Ui, on: bool, icon: Icon, tooltip: &str) -> Response {
    let size = egui::vec2(25.0, 23.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let pressed = response.is_pointer_button_down_on() && response.contains_pointer();
        let mut icon_rect = Rect::from_center_size(rect.center(), egui::vec2(16.0, 16.0));
        if on || pressed {
            if on {
                // Checked buttons show the dithered light face.
                painter.rect_filled(rect, 0.0, scroll_track());
            }
            thin_sunken(painter, rect);
            // Only a button being pressed nudges its icon; a checked one stays centred.
            if pressed {
                icon_rect = icon_rect.translate(egui::vec2(1.0, 1.0));
            }
        } else if response.hovered() {
            edge(painter, painter.round_rect_to_pixels(rect), highlight(), shadow());
        }
        paint_icon(painter, icon_rect, icon, true);
    }
    response.on_hover_text(tooltip)
}

/// Large message-box style icon.
pub fn message_icon(ui: &mut Ui, icon: Icon) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(32.0, 32.0), Sense::hover());
    paint_icon(ui.painter(), rect, icon, true);
}

/// Small "Information" icon that explains a setting in its tooltip.
pub fn info_tip(ui: &mut Ui, text: &str) -> Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), Sense::hover());
    if ui.is_rect_visible(rect) {
        paint_icon(ui.painter(), rect, Icon::Information, true);
    }
    response.on_hover_text(text)
}
