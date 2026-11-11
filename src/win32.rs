//! Classic Win32 ("Windows Classic" theme) look for egui: system colours,
//! square corners, 3D bevelled controls, sunken list views and status panels.

use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Pos2, Rect,
    Response, Sense, Shadow, Stroke, TextStyle, TextWrapMode, Ui, WidgetText,
};

/// COLOR_3DFACE / COLOR_BTNFACE
pub const FACE: Color32 = Color32::from_rgb(212, 208, 200);
/// COLOR_3DHIGHLIGHT
pub const HIGHLIGHT: Color32 = Color32::WHITE;
/// COLOR_3DLIGHT
pub const LIGHT: Color32 = Color32::from_rgb(223, 223, 223);
/// COLOR_3DSHADOW
pub const SHADOW: Color32 = Color32::from_rgb(128, 128, 128);
/// COLOR_3DDKSHADOW
pub const DARK_SHADOW: Color32 = Color32::from_rgb(64, 64, 64);
/// COLOR_WINDOW (list views, edit controls)
pub const WINDOW: Color32 = Color32::WHITE;
/// COLOR_WINDOWTEXT / COLOR_BTNTEXT
pub const TEXT: Color32 = Color32::BLACK;
/// COLOR_GRAYTEXT
pub const GRAY_TEXT: Color32 = Color32::from_rgb(128, 128, 128);
/// COLOR_HIGHLIGHT (selection background)
pub const SELECTION: Color32 = Color32::from_rgb(10, 36, 106);
/// COLOR_HIGHLIGHTTEXT
pub const SELECTION_TEXT: Color32 = Color32::WHITE;
pub const OK_GREEN: Color32 = Color32::from_rgb(0, 128, 0);
pub const ERROR_RED: Color32 = Color32::from_rgb(170, 0, 0);
pub const WARN_AMBER: Color32 = Color32::from_rgb(150, 80, 0);

/// Install the Win32 theme and, if available, a Windows-like UI font.
pub fn apply(ctx: &egui::Context) {
    install_font(ctx);
    ctx.set_theme(egui::ThemePreference::Light);
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
        *visuals = egui::Visuals::light();
        visuals.override_text_color = None;
        visuals.weak_text_color = Some(GRAY_TEXT);
        visuals.hyperlink_color = Color32::from_rgb(0, 0, 255);
        visuals.faint_bg_color = Color32::from_rgb(236, 234, 230);
        visuals.extreme_bg_color = WINDOW;
        visuals.text_edit_bg_color = Some(WINDOW);
        visuals.code_bg_color = WINDOW;
        visuals.warn_fg_color = WARN_AMBER;
        visuals.error_fg_color = ERROR_RED;
        visuals.panel_fill = FACE;
        visuals.window_fill = FACE;
        visuals.window_stroke = Stroke::new(1.0, DARK_SHADOW);
        visuals.window_corner_radius = CornerRadius::ZERO;
        visuals.menu_corner_radius = CornerRadius::ZERO;
        visuals.window_shadow = Shadow::NONE;
        visuals.popup_shadow = Shadow { offset: [2, 2], blur: 0, spread: 0, color: Color32::from_black_alpha(90) };
        // egui does not recolour selected text in edit boxes, so use a light
        // highlight for generic selection; navy is reserved for list views/menus.
        visuals.selection.bg_fill = Color32::from_rgb(166, 202, 240);
        visuals.selection.stroke = Stroke::new(1.0, TEXT);
        visuals.text_cursor.stroke = Stroke::new(1.0, TEXT);
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
            w.fg_stroke = Stroke::new(1.0, TEXT);
        }
        widgets.noninteractive.bg_fill = FACE;
        widgets.noninteractive.weak_bg_fill = FACE;
        widgets.noninteractive.bg_stroke = Stroke::new(1.0, SHADOW);

        widgets.inactive.bg_fill = WINDOW; // checkbox / edit backgrounds
        widgets.inactive.weak_bg_fill = FACE; // button / combo backgrounds
        widgets.inactive.bg_stroke = Stroke::new(1.0, SHADOW);

        widgets.hovered.bg_fill = WINDOW;
        widgets.hovered.weak_bg_fill = FACE;
        widgets.hovered.bg_stroke = Stroke::new(1.0, DARK_SHADOW);

        widgets.active.bg_fill = WINDOW;
        widgets.active.weak_bg_fill = Color32::from_rgb(196, 192, 184);
        widgets.active.bg_stroke = Stroke::new(1.0, DARK_SHADOW);

        widgets.open.bg_fill = WINDOW;
        widgets.open.weak_bg_fill = FACE;
        widgets.open.bg_stroke = Stroke::new(1.0, DARK_SHADOW);
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
    let Some(bytes) = CANDIDATES.iter().find_map(|path| std::fs::read(path).ok()) else { return; };
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert("win32-ui".into(), Arc::new(FontData::from_owned(bytes)));
    fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "win32-ui".into());
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
    edge(painter, rect, LIGHT, DARK_SHADOW);
    edge(painter, rect.shrink(px), HIGHLIGHT, SHADOW);
}

/// EDGE_SUNKEN, as used by list views and edit controls.
pub fn sunken(painter: &egui::Painter, rect: Rect) {
    let rect = painter.round_rect_to_pixels(rect);
    let px = pixel(painter);
    edge(painter, rect, SHADOW, HIGHLIGHT);
    edge(painter, rect.shrink(px), DARK_SHADOW, LIGHT);
}

/// BDR_SUNKENOUTER, the shallow edge used by status-bar panes and progress bars.
pub fn thin_sunken(painter: &egui::Painter, rect: Rect) {
    edge(painter, painter.round_rect_to_pixels(rect), SHADOW, HIGHLIGHT);
}

/// BDR_RAISEDINNER, used by list-view column headers.
pub fn thin_raised(painter: &egui::Painter, rect: Rect) {
    let rect = painter.round_rect_to_pixels(rect);
    edge(painter, rect, HIGHLIGHT, DARK_SHADOW);
    edge(painter, rect.shrink(pixel(painter)), FACE, SHADOW);
}

fn text_galley(ui: &Ui, text: impl Into<WidgetText>) -> Arc<egui::Galley> {
    let text: WidgetText = text.into();
    text.into_galley(ui, Some(TextWrapMode::Extend), f32::INFINITY, TextStyle::Button)
}

/// Paint text the way Win32 draws disabled labels: white emboss under gray.
fn paint_text(painter: &egui::Painter, pos: Pos2, galley: Arc<egui::Galley>, enabled: bool) {
    if enabled {
        painter.galley(pos, galley, TEXT);
    } else {
        painter.galley(pos + egui::vec2(1.0, 1.0), galley.clone(), HIGHLIGHT);
        painter.galley(pos, galley, GRAY_TEXT);
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
        painter.rect_filled(rect, 0.0, FACE);
        let pressed = enabled && response.is_pointer_button_down_on() && response.contains_pointer();
        let mut text_pos = rect.center() - galley.size() / 2.0;
        if pressed {
            let rect = painter.round_rect_to_pixels(rect);
            edge(painter, rect, DARK_SHADOW, DARK_SHADOW);
            edge(painter, rect.shrink(pixel(painter)), SHADOW, SHADOW);
            text_pos += egui::vec2(1.0, 1.0);
        } else {
            raised(painter, rect);
        }
        if response.has_focus() {
            painter.rect_stroke(
                rect.shrink(4.0),
                0.0,
                Stroke::new(1.0, DARK_SHADOW),
                egui::StrokeKind::Inside,
            );
        }
        paint_text(painter, text_pos.round(), galley, enabled);
    }
    response
}

/// List-view column header cell.
pub fn header_cell(ui: &mut Ui, width: f32, height: f32, text: &str) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), Sense::hover());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect_filled(rect, 0.0, FACE);
        thin_raised(painter, rect);
        let galley = WidgetText::from(text).into_galley(ui, Some(TextWrapMode::Truncate), width - 10.0, TextStyle::Body);
        painter.galley(Pos2::new(rect.left() + 5.0, rect.center().y - galley.size().y / 2.0), galley, TEXT);
    }
}

/// COLOR_SCROLLBAR: the scroll bar track (classic Windows dithers white and
/// button face; this is the blend).
pub const SCROLL_TRACK: Color32 = Color32::from_rgb(234, 232, 228);
const SCROLL_THUMB: Color32 = Color32::from_rgb(176, 172, 166);
const SCROLL_THUMB_HOVERED: Color32 = Color32::from_rgb(150, 147, 141);
const SCROLL_THUMB_DRAGGED: Color32 = SHADOW;

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
        visuals.extreme_bg_color = SCROLL_TRACK;
        visuals.widgets.inactive.bg_fill = SCROLL_THUMB;
        visuals.widgets.hovered.bg_fill = SCROLL_THUMB_HOVERED;
        visuals.widgets.active.bg_fill = SCROLL_THUMB_DRAGGED;
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
        .fill(WINDOW)
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
            painter.rect_filled(tab, 0.0, FACE);
            painter.rect_filled(Rect::from_min_max(tab.min, Pos2::new(tab.min.x + px, tab.max.y)), 0.0, HIGHLIGHT);
            painter.rect_filled(Rect::from_min_max(tab.min, Pos2::new(tab.max.x, tab.min.y + px)), 0.0, HIGHLIGHT);
            painter.rect_filled(Rect::from_min_max(Pos2::new(tab.max.x - px, tab.min.y), tab.max), 0.0, DARK_SHADOW);
            painter.rect_filled(Rect::from_min_max(Pos2::new(tab.max.x - 2.0 * px, tab.min.y + px), Pos2::new(tab.max.x - px, tab.max.y)), 0.0, SHADOW);
            let text_pos = (tab.center() - galley.size() / 2.0 + egui::vec2(0.0, if selected { -1.0 } else { 0.0 })).round();
            painter.galley(text_pos, galley, TEXT);
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
            painter.rect_filled(Rect::from_min_max(Pos2::new(from, y - px), Pos2::new(to, y)), 0.0, HIGHLIGHT);
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
        painter.galley(Pos2::new(rect.left() + 4.0, rect.center().y - galley.size().y / 2.0).round(), galley, TEXT);
    }
    response
}

/// Etched vertical separator used between toolbar button groups.
pub fn toolbar_separator(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, ui.spacing().interact_size.y), Sense::hover());
    let painter = ui.painter();
    let px = pixel(painter);
    let x = rect.center().x.round();
    painter.rect_filled(Rect::from_min_max(Pos2::new(x - px, rect.top()), Pos2::new(x, rect.bottom())), 0.0, SHADOW);
    painter.rect_filled(Rect::from_min_max(Pos2::new(x, rect.top()), Pos2::new(x + px, rect.bottom())), 0.0, HIGHLIGHT);
}

/// Etched horizontal line (SS_ETCHEDHORZ).
pub fn etched_hline(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 4.0), Sense::hover());
    let painter = ui.painter();
    let px = pixel(painter);
    let y = rect.center().y.round();
    painter.rect_filled(Rect::from_min_max(Pos2::new(rect.left(), y - px), Pos2::new(rect.right(), y)), 0.0, SHADOW);
    painter.rect_filled(Rect::from_min_max(Pos2::new(rect.left(), y), Pos2::new(rect.right(), y + px)), 0.0, HIGHLIGHT);
}

/// Panel frame with no inner stroke and the 3D face colour.
pub fn panel_frame(margin: i8) -> egui::Frame {
    egui::Frame::new().fill(FACE).inner_margin(egui::Margin::same(margin))
}

/// Menu items: flat, highlighted in navy with white text on hover.
pub fn menu_item_style(style: &mut egui::Style) {
    egui::containers::menu::menu_style(style);
    style.spacing.button_padding = egui::vec2(8.0, 2.0);
    for w in [&mut style.visuals.widgets.hovered, &mut style.visuals.widgets.active, &mut style.visuals.widgets.open] {
        w.weak_bg_fill = SELECTION;
        w.bg_fill = SELECTION;
        w.bg_stroke = Stroke::NONE;
        w.fg_stroke = Stroke::new(1.0, SELECTION_TEXT);
    }
}

/// Menu bar using Win32 menu colours for the bar and its drop-downs.
pub fn menu_bar() -> egui::MenuBar {
    egui::MenuBar::new()
        .style(menu_item_style)
        .config(egui::containers::menu::MenuConfig::new().style(menu_item_style))
}

/// Read-only sunken white field (e.g. an address box).
pub fn field(ui: &mut Ui, text: &str) {
    let height = ui.spacing().interact_size.y;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::hover());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect_filled(rect, 0.0, WINDOW);
        sunken(painter, rect);
        let galley = WidgetText::from(text).into_galley(ui, Some(TextWrapMode::Truncate), rect.width() - 10.0, TextStyle::Body);
        painter.galley(Pos2::new(rect.left() + 5.0, rect.center().y - galley.size().y / 2.0).round(), galley, TEXT);
    }
}

/// Edit control with a sunken client edge.
pub fn text_edit(ui: &mut Ui, edit: egui::TextEdit<'_>) -> Response {
    let inner = egui::Frame::new()
        .fill(WINDOW)
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
        let color = if selected { SELECTION_TEXT } else { TEXT };
        if selected {
            painter.rect_filled(rect, 0.0, SELECTION);
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
        let stroke = Stroke::new(1.5 * scale, c(DARK_SHADOW));
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
            fill_rect(0.0, 7.3, 3.0 - gap, 8.7, DARK_SHADOW);
            fill_rect(13.0 + gap, 7.3, 16.0, 8.7, DARK_SHADOW);
            // Plug with two prongs.
            outlined_rect(3.0 - gap, 4.5, 8.0 - gap, 11.5, body, DARK_SHADOW);
            fill_rect(8.0 - gap, 5.8, 10.5 - gap, 7.0, DARK_SHADOW);
            fill_rect(8.0 - gap, 9.0, 10.5 - gap, 10.2, DARK_SHADOW);
            // Socket.
            outlined_rect(10.5 + gap, 3.5, 13.0 + gap, 12.5, body, DARK_SHADOW);
            if !connected {
                painter.line_segment([p(2.0, 14.0), p(14.0, 2.0)], Stroke::new(2.0 * scale, c(ERROR_RED)));
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
            painter.circle_filled(center, 2.1 * scale, FACE);
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
            edge(painter, painter.round_rect_to_pixels(rect), HIGHLIGHT, SHADOW);
        }
        paint_icon(painter, icon_rect, icon, enabled);
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
