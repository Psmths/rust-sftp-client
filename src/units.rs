//! How sizes and speeds are written everywhere in the UI (file lists,
//! transfer queue, status bar, statistics): binary or decimal prefixes, and
//! speeds in bytes or bits per second. One global choice, like the theme.

use std::sync::atomic::{AtomicU8, Ordering};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SizeUnits {
    /// KiB, MiB, GiB (1024); speeds in MiB/s.
    #[default]
    Binary,
    /// kB, MB, GB (1000); speeds in MB/s.
    Decimal,
    /// kB, MB, GB (1000); speeds in Mbit/s, as network links are rated.
    DecimalBits,
}

impl SizeUnits {
    pub const ALL: [SizeUnits; 3] = [SizeUnits::Binary, SizeUnits::Decimal, SizeUnits::DecimalBits];

    pub fn label(self) -> &'static str {
        match self {
            SizeUnits::Binary => "Binary (KiB, MiB, GiB · MiB/s)",
            SizeUnits::Decimal => "Decimal (kB, MB, GB · MB/s)",
            SizeUnits::DecimalBits => "Decimal, speeds in bits (MB · Mbit/s)",
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn set(units: SizeUnits) {
    CURRENT.store(units as u8, Ordering::Relaxed);
}

pub fn current() -> SizeUnits {
    match CURRENT.load(Ordering::Relaxed) {
        1 => SizeUnits::Decimal,
        2 => SizeUnits::DecimalBits,
        _ => SizeUnits::Binary,
    }
}

const MIB: f64 = 1024.0 * 1024.0;

/// (step between prefixes, unit names) for sizes.
fn size_scale(units: SizeUnits) -> (f64, [&'static str; 5]) {
    match units {
        SizeUnits::Binary => (1024.0, ["B", "KiB", "MiB", "GiB", "TiB"]),
        SizeUnits::Decimal | SizeUnits::DecimalBits => (1000.0, ["B", "kB", "MB", "GB", "TB"]),
    }
}

/// (multiplier from bytes/s, step between prefixes, unit names) for speeds.
fn speed_scale(units: SizeUnits) -> (f64, f64, [&'static str; 4]) {
    match units {
        SizeUnits::Binary => (1.0, 1024.0, ["B/s", "KiB/s", "MiB/s", "GiB/s"]),
        SizeUnits::Decimal => (1.0, 1000.0, ["B/s", "kB/s", "MB/s", "GB/s"]),
        SizeUnits::DecimalBits => (8.0, 1000.0, ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"]),
    }
}

/// `value` scaled down by `step` until it is below `step` (or the units run out).
fn scaled(mut value: f64, step: f64, count: usize) -> (f64, usize) {
    let mut index = 0;
    while value >= step && index + 1 < count {
        value /= step;
        index += 1;
    }
    (value, index)
}

/// A file or transfer size, e.g. "512 B" or "1.5 MiB".
pub fn size(bytes: u64) -> String {
    let (step, names) = size_scale(current());
    let (value, index) = scaled(bytes as f64, step, names.len());
    if index == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", names[index]) }
}

/// A speed given in MiB/s (how transfers measure it), e.g. "84.3 MiB/s" or "707 Mbit/s".
pub fn speed_mib(mib_per_second: f64) -> String {
    let (multiplier, step, names) = speed_scale(current());
    let (value, index) = scaled(mib_per_second.max(0.0) * MIB * multiplier, step, names.len());
    let decimals = if index == 0 || value >= 100.0 { 0 } else { 1 };
    format!("{value:.decimals$} {}", names[index])
}

/// The smallest round speed (1, 2 or 5 × a power of ten in the unit
/// [`speed_mib`] would use) at or above `mib_per_second`, in MiB/s: graph
/// axes then end on round numbers in whichever units are shown.
pub fn nice_speed_ceiling_mib(mib_per_second: f64) -> f64 {
    let (multiplier, step, names) = speed_scale(current());
    let display = mib_per_second.max(f64::MIN_POSITIVE) * MIB * multiplier;
    let (value, index) = scaled(display, step, names.len());
    let magnitude = 10_f64.powf(value.log10().floor());
    let nice = [1.0, 2.0, 5.0, 10.0]
        .iter()
        .map(|factor| factor * magnitude)
        .find(|candidate| *candidate >= value)
        .unwrap_or(10.0 * magnitude);
    nice * step.powi(index as i32) / multiplier / MIB
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test, because the setting is global.
    #[test]
    fn formats_follow_the_chosen_units() {
        set(SizeUnits::Binary);
        assert_eq!(size(512), "512 B");
        assert_eq!(size(1536), "1.5 KiB");
        assert_eq!(speed_mib(84.31), "84.3 MiB/s");
        assert_eq!(speed_mib(0.5), "512 KiB/s");
        assert!((nice_speed_ceiling_mib(84.0) - 100.0).abs() < 1e-9);

        set(SizeUnits::Decimal);
        assert_eq!(size(1_500_000), "1.5 MB");
        assert_eq!(speed_mib(1.0), "1.0 MB/s");

        set(SizeUnits::DecimalBits);
        assert_eq!(size(1_500_000), "1.5 MB");
        // 94.2 MiB/s is about 790 Mbit/s.
        assert_eq!(speed_mib(94.2), "790 Mbit/s");
        let ceiling = nice_speed_ceiling_mib(94.2) * MIB * 8.0;
        assert!((ceiling - 1e9).abs() < 1.0, "{ceiling}");

        set(SizeUnits::Binary);
    }
}
