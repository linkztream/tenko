//! `sd_notify` for systemd units with `Type=notify` (OPS-13): `READY=1` once the API
//! listens, `STOPPING=1` when the shutdown begins. Outside a unit (`NOTIFY_SOCKET` unset)
//! nothing is sent.

use crate::serve::{Hooks, Ready};

/// The hooks that notify systemd.
pub(super) fn hooks() -> Hooks {
    if std::env::var_os("NOTIFY_SOCKET").is_none() {
        return Hooks::default();
    }
    Hooks {
        ready: Some(Box::new(|ready: &Ready| {
            let status = format!(
                "listening on {}",
                ready
                    .addrs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            notify(&[
                sd_notify::NotifyState::Ready,
                sd_notify::NotifyState::Status(&status),
            ]);
        })),
        stopping: Some(Box::new(|| {
            notify(&[
                sd_notify::NotifyState::Stopping,
                sd_notify::NotifyState::Status("shutting down"),
            ]);
        })),
    }
}

fn notify(states: &[sd_notify::NotifyState<'_>]) {
    if let Err(error) = sd_notify::notify(states) {
        tracing::warn!(%error, "sd_notify failed");
    }
}
