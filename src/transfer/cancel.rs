//! Cooperative cancellation for transfers.
//!
//! Transfers check the token between chunks (and race it against slow reads),
//! then return [`DownloadError::Cancelled`](super::DownloadError::Cancelled)
//! through their normal error paths, so temporary and partial files are
//! cleaned up exactly as for any other failure.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio::sync::Notify;

#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// Resolves once [`cancel`](Self::cancel) has been called.
    pub async fn cancelled(&self) {
        loop {
            // Created before the check, so a cancel in between still wakes it.
            let notified = self.0.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn waiters_wake_on_cancel() {
        let token = CancelToken::new();
        let waiter = tokio::spawn({
            let token = token.clone();
            async move { token.cancelled().await }
        });
        tokio::task::yield_now().await;
        token.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter).await.unwrap().unwrap();
        // Already-cancelled tokens resolve immediately.
        token.cancelled().await;
        assert!(token.is_cancelled());
    }
}
