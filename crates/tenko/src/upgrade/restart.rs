//! Restarts through the service manager: `tenko serve` stops gracefully and exits with
//! status 12 ([`crate::exit::RESTART`]); systemd (`RestartForceExitStatus=12`) and the
//! failure actions of the Windows service start it again. The installed update, a changed
//! module set and a switch back to the previous version all restart this way.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::watch;

/// Set when the process runs as a Windows service.
static WINDOWS_SERVICE: AtomicBool = AtomicBool::new(false);

/// Records that the process runs under the Windows Service Control Manager.
pub fn set_windows_service() {
    WINDOWS_SERVICE.store(true, Ordering::SeqCst);
}

/// Whether a service manager starts this process again after it exits with status 12: a
/// systemd unit (`INVOCATION_ID` or `NOTIFY_SOCKET` is set), the Windows service, or another
/// supervisor that declares it with `TENKO_SUPERVISED=1` (s6, runit, a container restart
/// policy, a test harness).
pub fn supervised() -> bool {
    WINDOWS_SERVICE.load(Ordering::SeqCst)
        || std::env::var_os("INVOCATION_ID").is_some()
        || std::env::var_os("NOTIFY_SOCKET").is_some()
        || std::env::var_os("TENKO_SUPERVISED").is_some_and(|value| value == "1")
}

/// A shared request to restart: set once, read by `tenko serve` to stop and exit with
/// status 12.
#[derive(Clone, Debug)]
pub struct Restart {
    tx: Arc<watch::Sender<Option<String>>>,
}

impl Default for Restart {
    fn default() -> Self {
        Self::new()
    }
}

impl Restart {
    /// A handle without a request.
    pub fn new() -> Self {
        let (tx, _) = watch::channel(None);
        Self { tx: Arc::new(tx) }
    }

    /// Requests the restart; the first reason wins.
    pub fn request(&self, reason: impl Into<String>) {
        let reason = reason.into();
        self.tx.send_if_modified(|current| {
            if current.is_some() {
                return false;
            }
            tracing::info!(reason = %reason, "restart requested");
            *current = Some(reason);
            true
        });
    }

    /// The reason, once a restart was requested.
    pub fn reason(&self) -> Option<String> {
        self.tx.borrow().clone()
    }

    /// Resolves with the reason when a restart is requested.
    pub async fn requested(&self) -> String {
        let mut rx = self.tx.subscribe();
        loop {
            if let Some(reason) = rx.borrow_and_update().clone() {
                return reason;
            }
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_first_reason_wins_and_waiters_wake() {
        let restart = Restart::new();
        assert_eq!(restart.reason(), None);
        let waiter = tokio::spawn({
            let restart = restart.clone();
            async move { restart.requested().await }
        });
        restart.request("update to 0.2.0");
        restart.request("module change");
        assert_eq!(waiter.await.expect("join"), "update to 0.2.0");
        assert_eq!(restart.reason().as_deref(), Some("update to 0.2.0"));
        // A late waiter sees the request at once.
        assert_eq!(restart.requested().await, "update to 0.2.0");
    }
}
