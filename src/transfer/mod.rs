mod cancel;
mod download;
pub mod partial;
mod segment;
pub mod turbo;

pub use cancel::CancelToken;
pub use download::{download_file, DownloadError, DownloadProgress, DownloadResult, SegmentProgress};
pub use segment::{SegmentPlanError, SegmentRange, TransferSettings};
