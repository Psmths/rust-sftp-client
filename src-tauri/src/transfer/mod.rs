mod download;
mod segment;

pub use download::{download_file, DownloadError, DownloadProgress, DownloadResult};
pub use segment::{plan_download_segments, SegmentPlan, SegmentPlanError, SegmentRange, TransferSettings};
