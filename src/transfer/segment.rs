use serde::{Deserialize, Serialize};
use thiserror::Error;

/// User-adjustable transfer defaults. Sizes are bytes internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct TransferSettings {
    pub segmentation_threshold_bytes: u64,
    pub target_segment_size_bytes: u64,
    pub max_segments_per_file: u32,
    pub max_concurrent_transfers: u32,
}

impl Default for TransferSettings {
    fn default() -> Self {
        Self {
            segmentation_threshold_bytes: 64 * 1024 * 1024,
            target_segment_size_bytes: 8 * 1024 * 1024,
            max_segments_per_file: 8,
            max_concurrent_transfers: 4,
        }
    }
}

/// Half-open byte range [start, end_exclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SegmentRange {
    pub index: u32,
    pub start: u64,
    pub end_exclusive: u64,
}

impl SegmentRange {
    pub fn len(self) -> u64 { self.end_exclusive - self.start }
    pub fn is_empty(self) -> bool { self.start == self.end_exclusive }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentPlan {
    pub file_size: u64,
    pub segments: Vec<SegmentRange>,
}

impl SegmentPlan {
    pub fn is_segmented(&self) -> bool { self.segments.len() > 1 }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SegmentPlanError {
    #[error("target segment size must be greater than zero")]
    ZeroSegmentSize,
    #[error("maximum segments per file must be greater than zero")]
    ZeroConcurrency,
}

/// Plan contiguous, non-overlapping ranges for a remote regular file.
/// Files below the threshold receive one full-file range. The caller must
/// verify file type and server support before scheduling parallel reads.
#[cfg_attr(not(test), allow(dead_code))] // superseded by partial-file planning; kept with its tests
pub fn plan_download_segments(
    file_size: u64,
    settings: TransferSettings,
) -> Result<SegmentPlan, SegmentPlanError> {
    if settings.target_segment_size_bytes == 0 {
        return Err(SegmentPlanError::ZeroSegmentSize);
    }
    if settings.max_segments_per_file == 0 {
        return Err(SegmentPlanError::ZeroConcurrency);
    }
    if file_size == 0 {
        return Ok(SegmentPlan { file_size, segments: Vec::new() });
    }

    let desired = file_size / settings.target_segment_size_bytes
        + u64::from(file_size % settings.target_segment_size_bytes != 0);
    let count = if file_size < settings.segmentation_threshold_bytes {
        1
    } else {
        desired.min(u64::from(settings.max_segments_per_file)).max(1)
    };
    let count = count as u32;
    let base_len = file_size / u64::from(count);
    let remainder = file_size % u64::from(count);

    let mut segments = Vec::with_capacity(count as usize);
    let mut start = 0_u64;
    for index in 0..count {
        let len = base_len + u64::from(u64::from(index) < remainder);
        let end_exclusive = start + len;
        segments.push(SegmentRange { index, start, end_exclusive });
        start = end_exclusive;
    }

    Ok(SegmentPlan { file_size, segments })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> TransferSettings {
        TransferSettings {
            segmentation_threshold_bytes: 64,
            target_segment_size_bytes: 16,
            max_segments_per_file: 4,
            max_concurrent_transfers: 4,
        }
    }

    #[test]
    fn small_files_use_one_range() {
        let plan = plan_download_segments(63, settings()).expect("valid plan");
        assert_eq!(plan.segments, vec![SegmentRange { index: 0, start: 0, end_exclusive: 63 }]);
        assert!(!plan.is_segmented());
    }

    #[test]
    fn large_file_is_split_into_contiguous_ranges() {
        let plan = plan_download_segments(100, settings()).expect("valid plan");
        assert_eq!(plan.segments, vec![
            SegmentRange { index: 0, start: 0, end_exclusive: 25 },
            SegmentRange { index: 1, start: 25, end_exclusive: 50 },
            SegmentRange { index: 2, start: 50, end_exclusive: 75 },
            SegmentRange { index: 3, start: 75, end_exclusive: 100 },
        ]);
        assert!(plan.is_segmented());
    }

    #[test]
    fn uneven_file_has_no_gaps_or_overlaps() {
        let plan = plan_download_segments(101, settings()).expect("valid plan");
        assert_eq!(plan.segments.first().map(|s| s.start), Some(0));
        assert_eq!(plan.segments.last().map(|s| s.end_exclusive), Some(101));
        for pair in plan.segments.windows(2) { assert_eq!(pair[0].end_exclusive, pair[1].start); }
        assert_eq!(plan.segments.iter().map(|s| s.len()).sum::<u64>(), 101);
    }

    #[test]
    fn empty_file_has_no_ranges() {
        assert!(plan_download_segments(0, settings()).expect("valid plan").segments.is_empty());
    }

    #[test]
    fn rejects_zero_segment_size() {
        let mut value = settings();
        value.target_segment_size_bytes = 0;
        assert_eq!(plan_download_segments(100, value), Err(SegmentPlanError::ZeroSegmentSize));
    }

    #[test]
    fn rejects_zero_segment_limit() {
        let mut value = settings();
        value.max_segments_per_file = 0;
        assert_eq!(plan_download_segments(100, value), Err(SegmentPlanError::ZeroConcurrency));
    }
}
