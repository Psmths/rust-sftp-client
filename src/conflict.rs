//! What to do when a transfer would write over a file that exists already.

use crate::connection::{PlannedFile, TargetFile};

/// Modification times this close (in seconds) count as equal: FAT and some
/// servers keep times with 2-second precision.
const TIME_TOLERANCE_SECS: u64 = 1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConflictAction {
    /// Keep the existing file; do not transfer.
    #[default]
    Ignore,
    Overwrite,
    OverwriteIfTimeDiffers,
    OverwriteIfSizeDiffers,
    OverwriteIfSizeOrTimeDiffers,
}

impl ConflictAction {
    pub const ALL: [ConflictAction; 5] = [
        ConflictAction::Ignore,
        ConflictAction::Overwrite,
        ConflictAction::OverwriteIfTimeDiffers,
        ConflictAction::OverwriteIfSizeDiffers,
        ConflictAction::OverwriteIfSizeOrTimeDiffers,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ConflictAction::Ignore => "Ignore (keep the existing files)",
            ConflictAction::Overwrite => "Overwrite",
            ConflictAction::OverwriteIfTimeDiffers => "Overwrite if the modification time differs",
            ConflictAction::OverwriteIfSizeDiffers => "Overwrite if the size differs",
            ConflictAction::OverwriteIfSizeOrTimeDiffers => "Overwrite if the size or the modification time differs",
        }
    }

    /// Whether `source` replaces the existing `target`.
    pub fn overwrites(self, source: &PlannedFile, target: &TargetFile) -> bool {
        let size = sizes_differ(source, target);
        let time = times_differ(source.mtime, target.mtime);
        match self {
            ConflictAction::Ignore => false,
            ConflictAction::Overwrite => true,
            ConflictAction::OverwriteIfTimeDiffers => time,
            ConflictAction::OverwriteIfSizeDiffers => size,
            ConflictAction::OverwriteIfSizeOrTimeDiffers => size || time,
        }
    }
}

pub fn sizes_differ(source: &PlannedFile, target: &TargetFile) -> bool {
    source.size != target.size
}

/// Unknown times count as different.
pub fn times_differ(source: Option<u64>, target: Option<u64>) -> bool {
    match (source, target) {
        (Some(source), Some(target)) => source.abs_diff(target) > TIME_TOLERANCE_SECS,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn source(size: u64, mtime: u64) -> PlannedFile {
        PlannedFile { local: PathBuf::from("a"), remote: "/a".into(), size, mtime: Some(mtime) }
    }

    #[test]
    fn actions_compare_size_and_time() {
        let target = TargetFile { size: 10, mtime: Some(1000) };
        let same = source(10, 1001);
        let newer = source(10, 2000);
        let bigger = source(11, 1000);
        assert!(!ConflictAction::Ignore.overwrites(&bigger, &target));
        assert!(ConflictAction::Overwrite.overwrites(&same, &target));
        assert!(!ConflictAction::OverwriteIfTimeDiffers.overwrites(&same, &target));
        assert!(ConflictAction::OverwriteIfTimeDiffers.overwrites(&newer, &target));
        assert!(!ConflictAction::OverwriteIfSizeDiffers.overwrites(&newer, &target));
        assert!(ConflictAction::OverwriteIfSizeDiffers.overwrites(&bigger, &target));
        assert!(ConflictAction::OverwriteIfSizeOrTimeDiffers.overwrites(&newer, &target));
        assert!(ConflictAction::OverwriteIfSizeOrTimeDiffers.overwrites(&bigger, &target));
        assert!(!ConflictAction::OverwriteIfSizeOrTimeDiffers.overwrites(&same, &target));
    }

    #[test]
    fn unknown_times_differ() {
        assert!(times_differ(None, Some(5)));
        assert!(times_differ(Some(5), None));
        assert!(!times_differ(Some(5), Some(6)));
    }
}
