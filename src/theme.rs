//! The app's look: flat surfaces, 1 px hairlines instead of borders, 4 px
//! corners, monochrome line icons, and the Inter and JetBrains Mono fonts,
//! in one of the three Rosé Pine palettes (rosepinetheme.com).

use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};

use serde::{Deserialize, Serialize};

use eframe::egui::{
    emath::GuiRounding,
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Pos2, Rect,
    Response, Sense, Shadow, Stroke, TextStyle, TextWrapMode, Ui, WidgetText,
};

/// Corner radius of surfaces and controls.
pub const RADIUS: f32 = 4.0;

/// The three Rosé Pine palettes (rosepinetheme.com): Main and Moon (dark)
/// and Dawn (light).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Theme {
    RosePineMoon,
    /// Older settings files said "light" for the classic light theme.
    #[serde(alias = "light")]
    RosePineDawn,
    /// Rosé Pine. Also what older settings files get for their other themes
    /// (serde needs this catch-all to be the last variant).
    #[default]
    #[serde(other)]
    RosePine,
}

impl Theme {
    pub const ALL: [Theme; 3] = [Theme::RosePine, Theme::RosePineMoon, Theme::RosePineDawn];

    pub fn label(self) -> &'static str {
        match self {
            Theme::RosePine => "Rosé Pine (dark)",
            Theme::RosePineMoon => "Rosé Pine Moon (dark, softer)",
            Theme::RosePineDawn => "Rosé Pine Dawn (light)",
        }
    }

    fn is_dark(self) -> bool {
        self != Theme::RosePineDawn
    }

    fn palette(self) -> &'static Palette {
        match self {
            Theme::RosePine => &ROSE_PINE,
            Theme::RosePineMoon => &ROSE_PINE_MOON,
            Theme::RosePineDawn => &ROSE_PINE_DAWN,
        }
    }
}

/// A Rosé Pine palette, named by role.
struct Palette {
    /// base: lists, edit boxes.
    ground: Color32,
    /// surface: panels (toolbar, sidebar, status bar, dialogs).
    surface: Color32,
    /// highlight low: hovered rows and buttons.
    hover: Color32,
    /// highlight med: selected rows; hairlines between regions.
    selected: Color32,
    /// highlight high: borders of controls; pressed buttons.
    rule_strong: Color32,
    /// muted: borders of hovered controls; disabled text.
    muted: Color32,
    /// subtle: secondary text (headers, hints, the status bar) and icons.
    subtle: Color32,
    text: Color32,
    /// iris: focus outlines, the selection bar, the active tab's underline.
    accent: Color32,
    /// foam: success (a transfer done, a newer file).
    ok: Color32,
    /// love: errors.
    error: Color32,
    /// gold: warnings.
    warn: Color32,
    /// pine: graphs and progress.
    pine: Color32,
    /// rose: the second graph line.
    rose: Color32,
}

const fn rgb(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

const ROSE_PINE: Palette = Palette {
    ground: rgb(0x191724),
    surface: rgb(0x1f1d2e),
    hover: rgb(0x21202e),
    selected: rgb(0x403d52),
    rule_strong: rgb(0x524f67),
    muted: rgb(0x6e6a86),
    subtle: rgb(0x908caa),
    text: rgb(0xe0def4),
    accent: rgb(0xc4a7e7),
    ok: rgb(0x9ccfd8),
    error: rgb(0xeb6f92),
    warn: rgb(0xf6c177),
    pine: rgb(0x31748f),
    rose: rgb(0xebbcba),
};

const ROSE_PINE_MOON: Palette = Palette {
    ground: rgb(0x232136),
    surface: rgb(0x2a273f),
    hover: rgb(0x2a283e),
    selected: rgb(0x44415a),
    rule_strong: rgb(0x56526e),
    muted: rgb(0x6e6a86),
    subtle: rgb(0x908caa),
    text: rgb(0xe0def4),
    accent: rgb(0xc4a7e7),
    ok: rgb(0x9ccfd8),
    error: rgb(0xeb6f92),
    warn: rgb(0xf6c177),
    pine: rgb(0x3e8fb0),
    rose: rgb(0xea9a97),
};

const ROSE_PINE_DAWN: Palette = Palette {
    ground: rgb(0xfaf4ed),
    surface: rgb(0xfffaf3),
    hover: rgb(0xf4ede8),
    selected: rgb(0xdfdad9),
    rule_strong: rgb(0xcecacd),
    muted: rgb(0x9893a5),
    subtle: rgb(0x797593),
    text: rgb(0x575279),
    accent: rgb(0x907aa9),
    ok: rgb(0x56949f),
    error: rgb(0xb4637a),
    warn: rgb(0xea9d34),
    pine: rgb(0x286983),
    rose: rgb(0xd7827e),
};

static THEME: AtomicU8 = AtomicU8::new(Theme::RosePine as u8);

fn theme() -> Theme {
    Theme::ALL.into_iter().find(|theme| *theme as u8 == THEME.load(Ordering::Relaxed)).unwrap_or_default()
}

fn pal() -> &'static Palette {
    theme().palette()
}

pub fn ground() -> Color32 { pal().ground }
pub fn hover_fill() -> Color32 { pal().hover }
pub fn text_color() -> Color32 { pal().text }
pub fn muted() -> Color32 { pal().subtle }
pub fn selection() -> Color32 { pal().selected }
pub fn selection_text() -> Color32 { pal().text }
pub fn queue_selection() -> Color32 { pal().selected }
pub fn ok_green() -> Color32 { pal().ok }
pub fn error_red() -> Color32 { pal().error }
pub fn warn_amber() -> Color32 { pal().warn }
pub fn notice_blue() -> Color32 { pal().accent }
pub fn grid() -> Color32 { pal().selected }
pub fn rule_strong() -> Color32 { pal().rule_strong }
/// Graph and progress colours.
pub fn pine() -> Color32 { pal().pine }
pub fn rose() -> Color32 { pal().rose }

/// `a` blended towards `b` by `amount` (0–1).
pub fn mix(a: Color32, b: Color32, amount: f32) -> Color32 {
    let channel = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * amount.clamp(0.0, 1.0)).round() as u8;
    Color32::from_rgb(channel(a.r(), b.r()), channel(a.g(), b.g()), channel(a.b(), b.b()))
}

/// Inter (UI) and JetBrains Mono (file names, paths, the terminal), both
/// under the SIL Open Font License (see assets/fonts).
static INTER: &[u8] = include_bytes!("../assets/fonts/Inter-Regular.ttf");
static JETBRAINS_MONO: &[u8] = include_bytes!("../assets/fonts/JetBrainsMono-Regular.ttf");
/// Berkeley Mono, for file listings, when it was present at build time (it is
/// a commercial font and not in the repository; see build.rs).
#[cfg(berkeley_mono)]
static BERKELEY_MONO: Option<&[u8]> = Some(include_bytes!("../assets/fonts/BerkeleyMonoVariable-Regular.ttf"));
#[cfg(not(berkeley_mono))]
static BERKELEY_MONO: Option<&[u8]> = None;

/// Font family of file listings.
const LISTING_FAMILY: &str = "listing";

/// The file-listing font (Berkeley Mono, else JetBrains Mono) at `size`.
pub fn listing_font(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(LISTING_FAMILY.into()))
}

/// Installs the fonts, text sizes, spacing and the theme's colours. Call
/// again to switch themes.
pub fn apply(ctx: &egui::Context, theme: Theme) {
    THEME.store(theme as u8, Ordering::Relaxed);
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert("inter".into(), Arc::new(FontData::from_static(INTER)));
    fonts.font_data.insert("jetbrains-mono".into(), Arc::new(FontData::from_static(JETBRAINS_MONO)));
    fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "inter".into());
    fonts.families.entry(FontFamily::Monospace).or_default().insert(0, "jetbrains-mono".into());
    // File listings: Berkeley Mono if built in, then the monospace fonts for
    // anything it lacks.
    let mut listing = fonts.families[&FontFamily::Monospace].clone();
    if let Some(berkeley) = BERKELEY_MONO {
        fonts.font_data.insert("berkeley-mono".into(), Arc::new(FontData::from_static(berkeley)));
        listing.insert(0, "berkeley-mono".into());
    }
    fonts.families.insert(FontFamily::Name(LISTING_FAMILY.into()), listing);
    ctx.set_fonts(fonts);

    let radius = CornerRadius::same(RADIUS as u8);
    ctx.set_theme(if theme.is_dark() { egui::ThemePreference::Dark } else { egui::ThemePreference::Light });
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Small, FontId::proportional(11.0)),
            (TextStyle::Body, FontId::proportional(13.0)),
            (TextStyle::Button, FontId::proportional(13.0)),
            (TextStyle::Monospace, FontId::monospace(12.5)),
            (TextStyle::Heading, FontId::proportional(15.0)),
        ]
        .into();

        let spacing = &mut style.spacing;
        spacing.item_spacing = egui::vec2(4.0, 3.0);
        spacing.button_padding = egui::vec2(6.0, 2.0);
        spacing.interact_size.y = 21.0;
        spacing.window_margin = egui::Margin::same(8);
        spacing.menu_margin = egui::Margin::same(4);
        // Slim, always-visible bars with a rounded thumb set into the track.
        spacing.scroll = egui::style::ScrollStyle::solid();
        spacing.scroll.bar_width = 10.0;
        spacing.scroll.bar_inner_margin = 2.0;
        spacing.scroll.handle_min_length = 16.0;
        spacing.scroll.dormant_background_opacity = 1.0;
        spacing.scroll.active_background_opacity = 1.0;
        spacing.scroll.interact_background_opacity = 1.0;
        spacing.scroll.dormant_handle_opacity = 1.0;
        spacing.scroll.active_handle_opacity = 1.0;
        spacing.scroll.interact_handle_opacity = 1.0;

        let visuals = &mut style.visuals;
        *visuals = if theme.is_dark() { egui::Visuals::dark() } else { egui::Visuals::light() };
        visuals.override_text_color = None;
        visuals.weak_text_color = Some(pal().subtle);
        visuals.hyperlink_color = pal().subtle;
        visuals.faint_bg_color = pal().surface;
        visuals.extreme_bg_color = pal().ground;
        visuals.text_edit_bg_color = Some(pal().ground);
        visuals.code_bg_color = pal().ground;
        visuals.warn_fg_color = pal().warn;
        visuals.error_fg_color = pal().error;
        visuals.panel_fill = pal().surface;
        visuals.window_fill = pal().surface;
        visuals.window_stroke = Stroke::new(1.0_f32, pal().rule_strong);
        visuals.window_corner_radius = radius;
        visuals.menu_corner_radius = radius;
        visuals.window_shadow = Shadow::NONE;
        visuals.popup_shadow = Shadow::NONE;
        visuals.selection.bg_fill = pal().rule_strong;
        visuals.selection.stroke = Stroke::new(1.0_f32, pal().text);
        visuals.text_cursor.stroke = Stroke::new(1.0_f32, pal().text);
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
            w.corner_radius = radius;
            w.expansion = 0.0;
            w.fg_stroke = Stroke::new(1.0_f32, pal().text);
        }
        // Drop-downs and check boxes: dark fill, hairline border that
        // lightens on hover, white while pressed or open.
        widgets.noninteractive.bg_fill = pal().surface;
        widgets.noninteractive.weak_bg_fill = pal().surface;
        widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, pal().selected);
        widgets.inactive.bg_fill = pal().ground;
        widgets.inactive.weak_bg_fill = pal().ground;
        widgets.inactive.bg_stroke = Stroke::new(1.0_f32, pal().rule_strong);
        widgets.hovered.bg_fill = pal().ground;
        widgets.hovered.weak_bg_fill = pal().hover;
        widgets.hovered.bg_stroke = Stroke::new(1.0_f32, pal().muted);
        widgets.active.bg_fill = pal().ground;
        widgets.active.weak_bg_fill = pal().selected;
        widgets.active.bg_stroke = Stroke::new(1.0_f32, pal().accent);
        widgets.open.bg_fill = pal().ground;
        widgets.open.weak_bg_fill = pal().hover;
        widgets.open.bg_stroke = Stroke::new(1.0_f32, pal().accent);
    });
}

/// One logical pixel, snapped to whole physical pixels.
fn pixel(painter: &egui::Painter) -> f32 {
    let ppp = painter.pixels_per_point();
    ppp.round().max(1.0) / ppp
}

/// A 1 px outline inside `rect`, with rounded corners.
fn hairline(painter: &egui::Painter, rect: Rect, color: Color32) {
    let rect = rect.round_to_pixels(painter.pixels_per_point());
    painter.rect_stroke(rect, RADIUS, Stroke::new(pixel(painter), color), egui::StrokeKind::Inside);
}

/// A 1 px horizontal line along `y`.
fn hline(painter: &egui::Painter, left: f32, right: f32, y: f32, color: Color32) {
    let px = pixel(painter);
    painter.rect_filled(Rect::from_min_max(Pos2::new(left, y - px), Pos2::new(right, y)), 0.0, color);
}

/// Outline of a region (progress bars, the transfer map).
pub fn outline(painter: &egui::Painter, rect: Rect) {
    hairline(painter, rect, pal().selected);
}

/// Outline of a control or a framed area (edit boxes, the speed graph).
pub fn outline_strong(painter: &egui::Painter, rect: Rect) {
    hairline(painter, rect, pal().rule_strong);
}

fn text_galley(ui: &Ui, text: impl Into<WidgetText>) -> Arc<egui::Galley> {
    let text: WidgetText = text.into();
    text.into_galley(ui, Some(TextWrapMode::Extend), f32::INFINITY, TextStyle::Button)
}

/// Push button with a minimum width (dialog buttons are 75 px): a dark fill
/// and a hairline that lightens on hover; white when focused.
pub fn button_sized(ui: &mut Ui, enabled: bool, text: &str, min_width: f32) -> Response {
    let galley = text_galley(ui, text);
    let size = egui::vec2(
        (galley.size().x + 18.0).max(min_width),
        (galley.size().y + 8.0).max(ui.spacing().interact_size.y + 2.0),
    );
    let (rect, response) = ui.allocate_exact_size(size, if enabled { Sense::click() } else { Sense::hover() });
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let pressed = enabled && response.is_pointer_button_down_on() && response.contains_pointer();
        let hovered = enabled && response.hovered();
        let fill = if pressed { pal().selected } else if hovered { pal().hover } else { pal().surface };
        painter.rect_filled(rect.round_to_pixels(painter.pixels_per_point()), RADIUS, fill);
        let border = if response.has_focus() { pal().accent } else if hovered { pal().muted } else { pal().rule_strong };
        hairline(painter, rect, border);
        let color = if enabled { pal().text } else { pal().muted };
        painter.galley((rect.center() - galley.size() / 2.0).round(), galley, color);
    }
    response
}

/// List column header cell.
pub fn header_cell(ui: &mut Ui, width: f32, height: f32, text: &str) {
    let _ = header_button(ui, width, height, text, None);
}

/// Clickable list column header: muted text, white on hover, a rule
/// underneath. `sorted` shows the sort direction (`Some(true)` ascending)
/// on the column the list is sorted by.
pub fn header_button(ui: &mut Ui, width: f32, height: f32, text: &str, sorted: Option<bool>) -> Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), Sense::click());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let pressed = response.is_pointer_button_down_on() && response.contains_pointer();
        painter.rect_filled(rect, 0.0, if pressed { pal().hover } else { pal().ground });
        hline(painter, rect.left(), rect.right(), rect.bottom().round(), pal().selected);
        let color = if response.hovered() { pal().text } else { pal().subtle };
        let arrow_room = if sorted.is_some() { 14.0 } else { 0.0 };
        let galley = WidgetText::from(text).into_galley(ui, Some(TextWrapMode::Truncate), (width - 10.0 - arrow_room).max(0.0), TextStyle::Body);
        painter.galley(Pos2::new(rect.left() + 5.0, rect.center().y - galley.size().y / 2.0), galley, color);
        if rect.left() > ui.clip_rect().left() + 1.0 {
            // A faint divider between columns.
            let px = pixel(painter);
            let x = rect.left().round();
            painter.rect_filled(Rect::from_min_max(Pos2::new(x, rect.top() + 5.0), Pos2::new(x + px, rect.bottom() - 5.0)), 0.0, pal().selected);
        }
        if let Some(ascending) = sorted {
            let center = Pos2::new(rect.right() - 9.0, rect.center().y);
            let (tip, base) = if ascending { (-3.0, 2.0) } else { (3.0, -2.0) };
            painter.add(egui::Shape::convex_polygon(
                vec![
                    Pos2::new(center.x, center.y + tip),
                    Pos2::new(center.x + 4.0, center.y + base),
                    Pos2::new(center.x - 4.0, center.y + base),
                ],
                pal().subtle,
                Stroke::NONE,
            ));
        }
    }
    response
}

/// The scroll bar colours apply to the area's own `ui`; the contents get the
/// normal visuals (whose widget fills differ).
fn scroll_bar_visuals(visuals: &mut egui::Visuals) {
    visuals.extreme_bg_color = pal().ground;
    visuals.widgets.inactive.bg_fill = pal().rule_strong;
    visuals.widgets.hovered.bg_fill = pal().muted;
    visuals.widgets.active.bg_fill = pal().subtle;
}

/// Shows `area` with visible scroll bars.
pub fn scroll<R>(
    ui: &mut Ui,
    area: egui::ScrollArea,
    add_contents: impl FnOnce(&mut Ui) -> R,
) -> egui::scroll_area::ScrollAreaOutput<R> {
    let normal = ui.visuals().clone();
    ui.scope(|ui| {
        scroll_bar_visuals(ui.visuals_mut());
        area.show(ui, |ui| {
            *ui.visuals_mut() = normal;
            add_contents(ui)
        })
    })
    .inner
}

/// [`scroll`] for a list of `count` rows of equal height: only the rows in
/// view are laid out, so long lists stay fast. `add_rows` gets the range of
/// row indices to draw.
pub fn scroll_rows<R>(
    ui: &mut Ui,
    area: egui::ScrollArea,
    row_height: f32,
    count: usize,
    add_rows: impl FnOnce(&mut Ui, std::ops::Range<usize>) -> R,
) -> egui::scroll_area::ScrollAreaOutput<R> {
    let normal = ui.visuals().clone();
    ui.scope(|ui| {
        scroll_bar_visuals(ui.visuals_mut());
        area.show_rows(ui, row_height, count, |ui, rows| {
            *ui.visuals_mut() = normal;
            add_rows(ui, rows)
        })
    })
    .inner
}

/// The framed area around lists. `height` is the total outer height.
pub fn list_view<R>(ui: &mut Ui, height: f32, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
    let inner = egui::Frame::new()
        .fill(pal().ground)
        .corner_radius(RADIUS)
        .inner_margin(egui::Margin::same(2))
        .show(ui, |ui| {
            ui.set_height((height - 4.0).max(0.0));
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
            add_contents(ui)
        });
    hairline(ui.painter(), inner.response.rect, pal().selected);
    inner.inner
}

/// Text tabs with a white underline on the selected one, over a rule.
/// Returns true if the selection changed.
pub fn tab_strip<T: PartialEq + Copy>(ui: &mut Ui, current: &mut T, tabs: &[(T, String)]) -> bool {
    let mut changed = false;
    let height = 21.0;
    let start = ui.cursor().min;
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
            let color = if selected || response.hovered() { pal().text } else { pal().subtle };
            painter.galley((rect.center() - galley.size() / 2.0).round(), galley, color);
            if selected {
                let line = Rect::from_min_max(Pos2::new(rect.left() + 6.0, rect.bottom() - 2.0), Pos2::new(rect.right() - 6.0, rect.bottom()));
                painter.rect_filled(line, 0.0, pal().accent);
            }
        }
    });
    let painter = ui.painter();
    let y = (start.y + height).round() + pixel(painter);
    hline(painter, start.x, ui.max_rect().right(), y, pal().selected);
    changed
}

/// Status-bar pane: a line of muted text.
pub fn status_pane(ui: &mut Ui, width: f32, text: impl Into<WidgetText>) -> Response {
    let height = ui.available_height().max(18.0);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), Sense::hover());
    if ui.is_rect_visible(rect) {
        let text: WidgetText = text.into();
        let galley = text.into_galley(ui, Some(TextWrapMode::Truncate), width - 8.0, TextStyle::Body);
        ui.painter().galley(Pos2::new(rect.left() + 4.0, rect.center().y - galley.size().y / 2.0).round(), galley, pal().subtle);
    }
    response
}

/// Status-bar badge: a rounded `fill` holding centred text in the ground colour.
pub fn status_badge(ui: &mut Ui, width: f32, text: &str, fill: Color32) -> Response {
    let height = ui.available_height().max(18.0);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), Sense::hover());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect_filled(rect.shrink2(egui::vec2(2.0, 2.0)), RADIUS, fill);
        let galley = WidgetText::from(text).into_galley(ui, Some(TextWrapMode::Truncate), width - 8.0, TextStyle::Body);
        painter.galley((rect.center() - galley.size() / 2.0).round(), galley, pal().ground);
    }
    response
}

/// Vertical rule between groups of toolbar buttons.
pub fn toolbar_separator(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, ui.spacing().interact_size.y), Sense::hover());
    let painter = ui.painter();
    let px = pixel(painter);
    let x = rect.center().x.round();
    painter.rect_filled(Rect::from_min_max(Pos2::new(x, rect.top() + 3.0), Pos2::new(x + px, rect.bottom() - 3.0)), 0.0, pal().rule_strong);
}

/// Full-width horizontal rule.
pub fn separator(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 4.0), Sense::hover());
    let painter = ui.painter();
    hline(painter, rect.left(), rect.right(), rect.center().y.round() + pixel(painter), pal().selected);
}

/// Inner margin of a toolbar band and of a group frame, so controls in both
/// line up when the two are stacked.
pub const GROUP_MARGIN: i8 = 4;

/// Starts a toolbar band: a hairline-framed strip around a row of toolbar
/// controls. Add to `content_ui`, then `end_band`.
pub fn begin_band(ui: &mut Ui) -> egui::frame::Prepared {
    egui::Frame::new()
        .inner_margin(egui::Margin { left: GROUP_MARGIN, right: GROUP_MARGIN, top: 2, bottom: 2 })
        .begin(ui)
}

pub fn end_band(ui: &mut Ui, band: egui::frame::Prepared) -> Response {
    let response = band.end(ui);
    hairline(ui.painter(), response.rect, pal().selected);
    response
}

/// Starts a group frame: a hairline around related controls. Add to
/// `content_ui`, then `end_group`.
pub fn begin_group(ui: &mut Ui) -> egui::frame::Prepared {
    egui::Frame::new().inner_margin(egui::Margin::same(GROUP_MARGIN)).begin(ui)
}

pub fn end_group(ui: &mut Ui, group: egui::frame::Prepared) -> Response {
    let response = group.end(ui);
    hairline(ui.painter(), response.rect, pal().selected);
    response
}

/// Panel frame in the surface colour.
pub fn panel_frame(margin: i8) -> egui::Frame {
    egui::Frame::new().fill(pal().surface).inner_margin(egui::Margin::same(margin))
}

/// Menu items: flat, a lighter fill on hover.
pub fn menu_item_style(style: &mut egui::Style) {
    egui::containers::menu::menu_style(style);
    style.spacing.button_padding = egui::vec2(8.0, 3.0);
    for w in [&mut style.visuals.widgets.hovered, &mut style.visuals.widgets.active, &mut style.visuals.widgets.open] {
        w.weak_bg_fill = pal().selected;
        w.bg_fill = pal().selected;
        w.bg_stroke = Stroke::NONE;
        w.fg_stroke = Stroke::new(1.0_f32, pal().text);
    }
}

/// Read-only field (e.g. a path box), in the monospace font.
pub fn field(ui: &mut Ui, text: &str) {
    field_sized(ui, text, ui.available_width());
}

/// `field` with a given width.
pub fn field_sized(ui: &mut Ui, text: &str, width: f32) {
    let height = ui.spacing().interact_size.y;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width.max(0.0), height), Sense::hover());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect_filled(rect.round_to_pixels(painter.pixels_per_point()), RADIUS, pal().ground);
        hairline(painter, rect, pal().rule_strong);
        let galley = WidgetText::from(text).into_galley(ui, Some(TextWrapMode::Truncate), rect.width() - 10.0, TextStyle::Monospace);
        painter.galley(Pos2::new(rect.left() + 5.0, rect.center().y - galley.size().y / 2.0).round(), galley, pal().text);
    }
}

/// Edit box: a hairline that turns white while it has the keyboard.
pub fn text_edit(ui: &mut Ui, edit: egui::TextEdit<'_>) -> Response {
    let inner = egui::Frame::new()
        .fill(pal().ground)
        .corner_radius(RADIUS)
        .inner_margin(egui::Margin::symmetric(3, 3))
        .show(ui, |ui| ui.add(edit.frame(false).margin(egui::Margin::ZERO)));
    let border = if inner.inner.has_focus() { pal().accent } else { pal().rule_strong };
    hairline(ui.painter(), inner.response.rect, border);
    inner.inner
}

/// Full-width list row (settings pages): hover fill, selection with a bar.
pub fn list_item(ui: &mut Ui, text: &str, selected: bool) -> Response {
    let height = 22.0;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::click());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        if selected {
            painter.rect_filled(rect, RADIUS, pal().selected);
            selection_bar(painter, rect);
        } else if response.hovered() {
            painter.rect_filled(rect, RADIUS, pal().hover);
        }
        let color = if selected { pal().text } else { pal().text };
        let galley = WidgetText::from(text).into_galley(ui, Some(TextWrapMode::Truncate), rect.width() - 14.0, TextStyle::Body);
        painter.galley(Pos2::new(rect.left() + 10.0, rect.center().y - galley.size().y / 2.0).round(), galley, color);
    }
    response
}

/// The 2 px accent bar at the left of a selected row.
pub fn selection_bar(painter: &egui::Painter, rect: Rect) {
    painter.rect_filled(Rect::from_min_max(rect.min, Pos2::new(rect.left() + 2.0, rect.bottom())), 0.0, pal().accent);
}

/// Toolbar and message icons, painted as lines on a 16×16 grid.
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
    NewFolder,
    /// An outline star: bookmark the current folder.
    Bookmark,
    /// A filled star: the folder is bookmarked (click to remove).
    RemoveBookmark,
    /// A plus: add (a connection).
    Add,
}

/// Paints `icon` into `rect` (any square size): monochrome lines (light grey,
/// darker when disabled), with colour only where it carries meaning (warning
/// amber, a broken connection).
pub fn paint_icon(painter: &egui::Painter, rect: Rect, icon: Icon, enabled: bool) {
    let scale = rect.width().min(rect.height()) / 16.0;
    let origin = rect.center() - egui::vec2(8.0, 8.0) * scale;
    let p = |x: f32, y: f32| origin + egui::vec2(x, y) * scale;
    let ink = if enabled { pal().subtle } else { pal().muted };
    let stroke = Stroke::new(1.3 * scale, ink);
    let line = |points: &[(f32, f32)], stroke: Stroke| {
        painter.add(egui::Shape::line(points.iter().map(|&(x, y)| p(x, y)).collect(), stroke));
    };
    let closed = |points: &[(f32, f32)], stroke: Stroke| {
        painter.add(egui::Shape::closed_line(points.iter().map(|&(x, y)| p(x, y)).collect(), stroke));
    };
    let folder = [(1.5, 3.5), (6.0, 3.5), (7.5, 5.0), (14.5, 5.0), (14.5, 13.5), (1.5, 13.5)];
    let tray = [(2.0, 10.0), (2.0, 14.0), (14.0, 14.0), (14.0, 10.0)];
    let star = |filled: bool| {
        let points: Vec<Pos2> = (0..10)
            .map(|k| {
                let radius = if k % 2 == 0 { 7.0 } else { 2.9 };
                let angle = (-90.0 + 36.0 * k as f32).to_radians();
                p(8.0 + radius * angle.cos(), 8.6 + radius * angle.sin())
            })
            .collect();
        if filled {
            for k in 0..10 {
                painter.add(egui::Shape::convex_polygon(vec![p(8.0, 8.6), points[k], points[(k + 1) % 10]], ink, Stroke::NONE));
            }
        }
        painter.add(egui::Shape::closed_line(points, stroke));
    };

    match icon {
        Icon::Up => {
            // An elbow arrow: up and out of this folder.
            line(&[(13.5, 13.0), (5.5, 13.0), (5.5, 3.0)], stroke);
            line(&[(2.0, 6.5), (5.5, 3.0), (9.0, 6.5)], stroke);
        }
        Icon::Refresh => {
            let center = p(8.0, 8.0);
            let radius = 5.5 * scale;
            let (start, end) = (20.0_f32.to_radians(), 300.0_f32.to_radians());
            let points: Vec<Pos2> = (0..=24)
                .map(|i| start + (end - start) * i as f32 / 24.0)
                .map(|a| center + egui::vec2(a.cos(), a.sin()) * radius)
                .collect();
            painter.add(egui::Shape::line(points, stroke));
            let tip = center + egui::vec2(end.cos(), end.sin()) * radius;
            painter.add(egui::Shape::line(vec![tip + egui::vec2(-3.2, -0.6) * scale, tip, tip + egui::vec2(0.2, 3.2) * scale], stroke));
        }
        Icon::Connect | Icon::Disconnect => {
            let gap = if icon == Icon::Connect { 0.0 } else { 1.5 };
            line(&[(0.5, 8.0), (3.5 - gap, 8.0)], stroke);
            closed(&[(3.5 - gap, 5.0), (7.5 - gap, 5.0), (7.5 - gap, 11.0), (3.5 - gap, 11.0)], stroke);
            line(&[(7.5 - gap, 6.6), (10.0 - gap, 6.6)], stroke);
            line(&[(7.5 - gap, 9.4), (10.0 - gap, 9.4)], stroke);
            closed(&[(10.0 + gap, 4.0), (12.5 + gap, 4.0), (12.5 + gap, 12.0), (10.0 + gap, 12.0)], stroke);
            line(&[(12.5 + gap, 8.0), (15.5, 8.0)], stroke);
            if icon == Icon::Disconnect && enabled {
                line(&[(3.0, 14.5), (13.0, 1.5)], Stroke::new(1.3 * scale, pal().error));
            }
        }
        Icon::Settings => {
            // A gear: eight teeth around a ring.
            let teeth: Vec<Pos2> = (0..32)
                .map(|k| {
                    let tooth = k / 4;
                    let corner = k % 4;
                    let middle = tooth as f32 * 45.0;
                    let (offset, radius) = [(-14.0, 5.0), (-9.0, 7.0), (9.0, 7.0), (14.0, 5.0)][corner];
                    let angle = (middle + offset).to_radians();
                    p(8.0 + radius * angle.cos(), 8.0 + radius * angle.sin())
                })
                .collect();
            painter.add(egui::Shape::closed_line(teeth, stroke));
            painter.circle_stroke(p(8.0, 8.0), 2.2 * scale, stroke);
        }
        Icon::Upload => {
            line(&tray, stroke);
            line(&[(8.0, 11.0), (8.0, 1.5)], stroke);
            line(&[(4.5, 5.0), (8.0, 1.5), (11.5, 5.0)], stroke);
        }
        Icon::Download => {
            line(&tray, stroke);
            line(&[(8.0, 1.5), (8.0, 11.0)], stroke);
            line(&[(4.5, 7.5), (8.0, 11.0), (11.5, 7.5)], stroke);
        }
        Icon::Warning => {
            let amber = Stroke::new(1.3 * scale, if enabled { pal().warn } else { pal().muted });
            closed(&[(8.0, 1.5), (15.0, 14.5), (1.0, 14.5)], amber);
            line(&[(8.0, 6.0), (8.0, 10.0)], amber);
            painter.circle_filled(p(8.0, 12.3), 0.8 * scale, amber.color);
        }
        Icon::Information => {
            painter.circle_stroke(p(8.0, 8.0), 6.8 * scale, stroke);
            painter.circle_filled(p(8.0, 4.8), 0.9 * scale, ink);
            line(&[(8.0, 7.0), (8.0, 11.8)], stroke);
        }
        Icon::HiddenItems => {
            let outline: Vec<(f32, f32)> = (0..=16)
                .map(|k| {
                    let t = k as f32 / 16.0 * std::f32::consts::PI;
                    (8.0 - 7.0 * t.cos(), 8.0 - 4.4 * t.sin())
                })
                .chain((1..16).map(|k| {
                    let t = k as f32 / 16.0 * std::f32::consts::PI;
                    (8.0 + 7.0 * t.cos(), 8.0 + 4.4 * t.sin())
                }))
                .collect();
            closed(&outline, stroke);
            painter.circle_stroke(p(8.0, 8.0), 2.2 * scale, stroke);
        }
        Icon::NewFolder => {
            closed(&folder, stroke);
            line(&[(5.5, 9.3), (10.5, 9.3)], stroke);
            line(&[(8.0, 6.8), (8.0, 11.8)], stroke);
        }
        // Outline: not bookmarked yet. Filled: bookmarked (click to remove).
        Icon::Bookmark => star(false),
        Icon::RemoveBookmark => star(true),
        Icon::Add => {
            line(&[(3.0, 8.0), (13.0, 8.0)], stroke);
            line(&[(8.0, 3.0), (8.0, 13.0)], stroke);
        }
    }
}


/// Material Design's "cancel" icon, on its 24-unit grid: a filled circle in
/// `color` with a cross cut out of it (`background` shows through).
pub fn paint_material_cancel(painter: &egui::Painter, rect: Rect, color: Color32, background: Color32) {
    let scale = rect.width().min(rect.height()) / 24.0;
    let p = |x: f32, y: f32| rect.center() + egui::vec2(x - 12.0, y - 12.0) * scale;
    painter.circle_filled(p(12.0, 12.0), 10.0 * scale, color);
    let cut = Stroke::new(2.0 * scale, background);
    painter.line_segment([p(7.7, 7.7), p(16.3, 16.3)], cut);
    painter.line_segment([p(16.3, 7.7), p(7.7, 16.3)], cut);
}

/// Coloured Material Design icons (filled style) for menu items.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MenuIcon {
    /// `folder`
    Open,
    /// `file_upload`
    Upload,
    /// `file_download`
    Download,
    /// `tag` (#), for checksums.
    Hash,
    /// `edit`
    Rename,
    /// `delete`
    Delete,
    /// `create_new_folder`
    NewFolder,
}

impl MenuIcon {
    /// Each action's colour from the palette (muted when disabled).
    fn color(self) -> Color32 {
        let p = pal();
        match self {
            MenuIcon::Open | MenuIcon::NewFolder => p.warn,
            MenuIcon::Upload | MenuIcon::Download => p.ok,
            MenuIcon::Hash => p.accent,
            MenuIcon::Rename => p.rose,
            MenuIcon::Delete => p.error,
        }
    }
}

/// Paints a Material icon from its 24-unit grid into `rect`, filled with
/// `color`; `background` shows through its cut-outs (the plus of New folder).
pub fn paint_menu_icon(painter: &egui::Painter, rect: Rect, icon: MenuIcon, color: Color32, background: Color32) {
    let scale = rect.width().min(rect.height()) / 24.0;
    let p = |x: f32, y: f32| rect.center() + egui::vec2(x - 12.0, y - 12.0) * scale;
    let block = |x0: f32, y0: f32, x1: f32, y1: f32, radius: f32, fill: Color32| {
        painter.rect_filled(Rect::from_min_max(p(x0, y0), p(x1, y1)), radius * scale, fill);
    };
    let polygon = |points: &[(f32, f32)]| {
        painter.add(egui::Shape::convex_polygon(points.iter().map(|&(x, y)| p(x, y)).collect(), color, Stroke::NONE));
    };
    // `folder`: a tab and a rounded body.
    let folder = || {
        polygon(&[(2.0, 7.0), (2.6, 4.6), (4.0, 4.0), (10.0, 4.0), (12.0, 6.0), (12.0, 7.0)]);
        block(2.0, 6.0, 22.0, 20.0, 2.0, color);
    };
    match icon {
        MenuIcon::Open => folder(),
        MenuIcon::NewFolder => {
            folder();
            block(11.0, 12.0, 19.0, 14.0, 0.0, background);
            block(14.0, 9.0, 16.0, 17.0, 0.0, background);
        }
        MenuIcon::Upload => {
            polygon(&[(5.0, 10.0), (12.0, 3.0), (19.0, 10.0)]);
            block(9.0, 9.9, 15.0, 16.0, 0.0, color);
            block(5.0, 18.0, 19.0, 20.0, 0.0, color);
        }
        MenuIcon::Download => {
            block(9.0, 3.0, 15.0, 9.1, 0.0, color);
            polygon(&[(5.0, 9.0), (19.0, 9.0), (12.0, 16.0)]);
            block(5.0, 18.0, 19.0, 20.0, 0.0, color);
        }
        MenuIcon::Hash => {
            block(8.0, 4.0, 10.0, 20.0, 0.0, color);
            block(14.0, 4.0, 16.0, 20.0, 0.0, color);
            block(4.0, 8.0, 20.0, 10.0, 0.0, color);
            block(4.0, 14.0, 20.0, 16.0, 0.0, color);
        }
        MenuIcon::Rename => {
            // The pencil's body and its rubber-capped end.
            polygon(&[(3.0, 17.25), (14.06, 6.19), (17.81, 9.94), (6.75, 21.0), (3.0, 21.0)]);
            polygon(&[(15.13, 5.12), (17.3, 2.95), (21.05, 6.7), (18.88, 8.87)]);
        }
        MenuIcon::Delete => {
            block(6.0, 7.0, 18.0, 21.0, 2.0, color);
            block(5.0, 4.0, 19.0, 6.0, 0.0, color);
            polygon(&[(8.5, 4.0), (9.5, 3.0), (14.5, 3.0), (15.5, 4.0)]);
        }
    }
}

/// A menu item with a coloured Material icon before its label. Disabled
/// items show both in the disabled colour and cannot be clicked.
pub fn menu_item(ui: &mut Ui, enabled: bool, icon: MenuIcon, text: &str) -> Response {
    let galley = WidgetText::from(text).into_galley(ui, Some(TextWrapMode::Extend), f32::INFINITY, TextStyle::Button);
    let width = (galley.size().x + 44.0).max(ui.available_width());
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 24.0), if enabled { Sense::click() } else { Sense::hover() });
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let hovered = enabled && response.hovered();
        let background = if hovered { pal().selected } else { pal().surface };
        if hovered {
            painter.rect_filled(rect, RADIUS, background);
        }
        let color = if enabled { icon.color() } else { pal().muted };
        let icon_rect = Rect::from_center_size(Pos2::new(rect.left() + 16.0, rect.center().y), egui::vec2(16.0, 16.0));
        paint_menu_icon(painter, icon_rect, icon, color, background);
        let text_color = if enabled { pal().text } else { pal().muted };
        painter.galley(Pos2::new(rect.left() + 32.0, rect.center().y - galley.size().y / 2.0).round(), galley, text_color);
    }
    response
}

/// Icon-only toolbar button: a lighter fill on hover, darker while pressed.
pub fn icon_button(ui: &mut Ui, enabled: bool, icon: Icon, tooltip: &str) -> Response {
    icon_button_sized(ui, enabled, icon, tooltip, egui::vec2(25.0, 23.0), 16.0)
}

/// [`icon_button`] of a given size, with an icon `icon_size` points square.
pub fn icon_button_sized(ui: &mut Ui, enabled: bool, icon: Icon, tooltip: &str, size: egui::Vec2, icon_size: f32) -> Response {
    let (rect, response) = ui.allocate_exact_size(size, if enabled { Sense::click() } else { Sense::hover() });
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let pressed = enabled && response.is_pointer_button_down_on() && response.contains_pointer();
        if pressed || (enabled && response.hovered()) {
            painter.rect_filled(rect, RADIUS, if pressed { pal().selected } else { pal().hover });
        }
        paint_icon(painter, Rect::from_center_size(rect.center(), egui::vec2(icon_size, icon_size)), icon, enabled);
    }
    response.on_hover_text(tooltip)
}

/// Toolbar button that stays checked while `on`: a lighter fill and a hairline.
pub fn icon_toggle(ui: &mut Ui, on: bool, icon: Icon, tooltip: &str) -> Response {
    let size = egui::vec2(25.0, 23.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let pressed = response.is_pointer_button_down_on() && response.contains_pointer();
        if on || pressed || response.hovered() {
            painter.rect_filled(rect, RADIUS, if pressed { pal().selected } else { pal().hover });
        }
        if on {
            hairline(painter, rect, pal().rule_strong);
        }
        paint_icon(painter, Rect::from_center_size(rect.center(), egui::vec2(16.0, 16.0)), icon, true);
    }
    response.on_hover_text(tooltip)
}

/// Large message icon (dialogs).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_theme_names_old_and_new() {
        let read = |json: &str| serde_json::from_str::<Theme>(json).unwrap();
        assert_eq!(read(r#""rosePine""#), Theme::RosePine);
        assert_eq!(read(r#""rosePineMoon""#), Theme::RosePineMoon);
        assert_eq!(read(r#""rosePineDawn""#), Theme::RosePineDawn);
        // Earlier versions' themes: the classic light one maps to Dawn, the rest to Rosé Pine.
        assert_eq!(read(r#""light""#), Theme::RosePineDawn);
        assert_eq!(read(r#""dark""#), Theme::RosePine);
        assert_eq!(read(r#""modern""#), Theme::RosePine);
        assert_eq!(serde_json::to_string(&Theme::RosePineMoon).unwrap(), r#""rosePineMoon""#);
    }

    #[test]
    fn an_old_theme_name_keeps_the_other_settings() {
        let settings: crate::settings::AppSettings =
            serde_json::from_str(r#"{"theme":"modern","hideHiddenItems":true}"#).unwrap();
        assert_eq!(settings.theme, Theme::RosePine);
        assert!(settings.hide_hidden_items);
    }

    #[test]
    fn every_theme_has_a_distinct_palette() {
        let grounds: Vec<Color32> = Theme::ALL.iter().map(|theme| theme.palette().ground).collect();
        assert_eq!(grounds, vec![rgb(0x191724), rgb(0x232136), rgb(0xfaf4ed)]);
        assert!(Theme::RosePine.is_dark() && Theme::RosePineMoon.is_dark() && !Theme::RosePineDawn.is_dark());
    }
}
