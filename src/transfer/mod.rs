mod download;
mod segment;

pub use download::{download_file, DownloadError, DownloadProgress, DownloadResult, SegmentProgress};
pub use segment::{plan_download_segments, SegmentPlan, SegmentPlanError, SegmentRange, TransferSettings};
