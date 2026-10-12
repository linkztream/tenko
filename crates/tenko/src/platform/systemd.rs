//! `sd_notify` for systemd units with `Type=notify` (OPS-13): `READY=1` once the API
//! listens, `STOPPING=1` when the shutdown begins, and `EXTEND_TIMEOUT_USEC` while a slow
//! start step (a data-format migration) runs. Outside a unit (`NOTIFY_SOCKET` unset)
//! nothing is sent.

use std::{sync::mpsc, thread, time::Duration};

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

/// How much more time each `EXTEND_TIMEOUT_USEC` message asks for.
const EXTENSION: Duration = Duration::from_secs(90);

/// How often the extension is renewed while the slow step runs.
const RENEW_EVERY: Duration = Duration::from_secs(30);

/// Renews the start timeout of the unit until it is dropped.
pub(super) struct Extension {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Drop for Extension {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Sends `EXTEND_TIMEOUT_USEC` now and every [`RENEW_EVERY`] until the returned guard is
/// dropped, so that a long step (a data-format migration) does not hit `TimeoutStartSec=`.
/// Outside a unit (`NOTIFY_SOCKET` unset) nothing is sent and `None` is returned.
pub(super) fn extend(reason: &str) -> Option<Extension> {
    std::env::var_os("NOTIFY_SOCKET")?;
    let (stop, stopped) = mpsc::channel();
    let status = reason.to_owned();
    let thread = thread::Builder::new()
        .name("sd-notify-extend".to_owned())
        .spawn(move || {
            renew(&stopped, RENEW_EVERY, |usec| {
                notify(&[
                    sd_notify::NotifyState::ExtendTimeoutUsec(usec),
                    sd_notify::NotifyState::Status(&status),
                ]);
            });
        })
        .ok()?;
    Some(Extension {
        stop: Some(stop),
        thread: Some(thread),
    })
}

/// Calls `send` with the extension in microseconds at once and every `every` until `stop`
/// receives a value or its sender is dropped.
fn renew(stop: &mpsc::Receiver<()>, every: Duration, mut send: impl FnMut(u32)) {
    let usec = u32::try_from(EXTENSION.as_micros()).unwrap_or(u32::MAX);
    loop {
        send(usec);
        match stop.recv_timeout(every) {
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_extension_is_renewed_until_the_guard_goes() {
        let (stop, stopped) = mpsc::channel::<()>();
        let worker = thread::spawn(move || {
            let mut sent = Vec::new();
            renew(&stopped, Duration::from_millis(10), |usec| sent.push(usec));
            sent
        });
        thread::sleep(Duration::from_millis(55));
        drop(stop);
        let sent = worker.join().expect("join");
        assert!(sent.len() >= 3, "{sent:?}");
        assert!(sent.iter().all(|usec| *usec == 90_000_000));
    }

    #[test]
    fn the_extension_outlasts_the_renewal() {
        assert!(EXTENSION > RENEW_EVERY * 2);
    }
}
