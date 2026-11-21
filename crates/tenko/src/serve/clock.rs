//! The clock guard of this node (`tenko_core::clock`), for the controller's process and for the
//! process of a node without the controller role alike: `<data dir>/clock.json` carries its
//! state across a restart, a sampler looks every second, and on a controller a hold raises its
//! finding.
//!
//! The file holds the wall time of the last trusted look and the hold, if any. It is written
//! with the store's private-file helper at every change of the hold, every minute, and at a
//! clean stop. At start a missing file is a new installation, which starts trusted; an
//! unreadable one is treated the same, with a warning.
//!
//! The findings of a controller: `sys.clock.jumped` (a warning) while destruction waits after a
//! jump and resumes by itself; `sys.clock.held` (to act on) while a person must confirm the
//! clock, after a jump or a start gap of more than a day. A start gap within a day is the
//! downtime of a restart: one line in the log, no finding.
//!
//! How a hold ends without the confirm in the web UI: a hold of at most a day ends by itself
//! after the wait. A longer one, on a controller whose UI cannot be reached and on every node
//! without the controller role (which has no API), ends only by root on that host: stop the
//! service, delete `<data dir>/clock.json`, start the service. The node then starts trusted.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use tenko_api::{dto::system::StatusWarning, state::AppState};
use tenko_core::{
    Timestamp,
    clock::{self, Held, Reason, Release, Saved, SavedHold},
};
use tokio::sync::watch;

/// The file in the data directory.
pub(super) const FILE: &str = "clock.json";

/// How often the file is written while nothing changes.
const WRITE_EVERY: Duration = Duration::from_secs(60);

/// Restores the guard from the file of `data_dir`; called before any round can run.
pub(crate) fn restore(data_dir: &Path) {
    let path = data_dir.join(FILE);
    clock::restore(read(&path));
    log_change(None, clock::trusted_now().err().as_ref(), &path);
}

/// The state the file holds; `None` for a missing file, and for an unreadable one with a
/// warning.
fn read(path: &Path) -> Option<Saved> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "the clock guard's file cannot be read; starting without it");
            return None;
        }
    };
    serde_json::from_slice(&bytes)
        .inspect_err(|error| {
            tracing::warn!(path = %path.display(), %error, "the clock guard's file is not valid; starting without it");
        })
        .ok()
}

fn write(path: &Path, saved: &Saved) {
    let Ok(bytes) = serde_json::to_vec(saved) else {
        return;
    };
    if let Err(error) = tenko_store::fs::write_private(path, &bytes) {
        tracing::warn!(%error, "the clock guard's file cannot be written");
    }
}

/// Whether the file is due: never written, the hold changed, or a minute passed.
fn due(written: Option<(Option<&SavedHold>, Duration)>, held: Option<&SavedHold>) -> bool {
    let key = |held: Option<&SavedHold>| held.map(|held| (held.reason, held.since));
    written.is_none_or(|(was, age)| key(was) != key(held) || age >= WRITE_EVERY)
}

/// Looks every second until `stop`, keeps the file and the findings of `state` (a controller's
/// API, `None` on a node without one) current, and writes the file once more at the end.
pub(crate) async fn run(
    data_dir: PathBuf,
    state: Option<AppState>,
    node: String,
    mut stop: watch::Receiver<bool>,
) {
    let path = data_dir.join(FILE);
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut held = clock::trusted_now().err();
    let mut written: Option<(Option<SavedHold>, Instant)> = None;
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = ticker.tick() => {}
        }
        if *stop.borrow() {
            break;
        }
        let now = clock::trusted_now().err();
        log_change(held.as_ref(), now.as_ref(), &path);
        if let Some(state) = &state {
            let warning = notice(&node, now.as_ref());
            for code in [clock::JUMPED, clock::HELD] {
                match &warning {
                    Some(warning) if warning.code == code => state.set_notice(warning.clone()),
                    _ => state.clear_notice(code),
                }
            }
        }
        held = now;
        let saved = clock::saved();
        if due(
            written
                .as_ref()
                .map(|(was, at)| (was.as_ref(), at.elapsed())),
            saved.held.as_ref(),
        ) {
            write(&path, &saved);
            written = Some((saved.held, Instant::now()));
        }
    }
    write(&path, &clock::saved());
}

/// One line when a hold of destruction begins (warn; info for a start gap that ends by itself)
/// and one when it ends; `path` is the file that root deletes to end a hold.
fn log_change(before: Option<&Held>, now: Option<&Held>, path: &Path) {
    match (before, now) {
        (None, Some(held)) if held.reason == Reason::StartGap && held.release == Release::Wait => {
            tracing::info!(
                gap_secs = held.jump_ms / 1_000,
                until = ?held.until,
                "the clock is away from the last time it trusted; expired data is kept until then"
            );
        }
        (None, Some(held)) => tracing::warn!(
            reason = held.reason.as_str(),
            jump_ms = held.jump_ms,
            until = ?held.until,
            "the clock is held: expired data is kept; {}",
            match held.release {
                Release::Wait => "it resumes by itself".to_owned(),
                _ => format!(
                    "an administrator confirms the clock in the web UI of a controller, or root \
                     stops the service, deletes {} and starts it",
                    path.display()
                ),
            }
        ),
        (Some(_), None) => tracing::info!("the clock is trusted again"),
        _ => {}
    }
}

/// The finding of a hold of destruction: [`clock::JUMPED`] while it ends by itself,
/// [`clock::HELD`] while a person ends it, none for a start gap that ends by itself.
fn notice(node: &str, held: Option<&Held>) -> Option<StatusWarning> {
    let held = held?;
    let code = match (held.release, held.reason) {
        (Release::Person, _) => clock::HELD,
        (_, Reason::StartGap) => return None,
        _ => clock::JUMPED,
    };
    let secs = held.jump_ms.unsigned_abs().div_ceil(1_000);
    let direction = if held.jump_ms < 0 { "back" } else { "forward" };
    let what = match (held.reason, held.jump_ms < 0) {
        (Reason::StartGap, false) => format!("{node} was off for {secs} s"),
        (Reason::StartGap, true) => {
            format!("the clock of {node} is {secs} s behind the last time it trusted")
        }
        _ => format!("the clock of {node} jumped {direction} by {secs} s"),
    };
    // Whole seconds, so that the finding keeps its identity from one look to the next.
    let until = held.until.and_then(|until| {
        let nanos = until.unix_nanos();
        Timestamp::from_unix_nanos(nanos - nanos.rem_euclid(1_000_000_000)).ok()
    });
    let mut params = std::collections::BTreeMap::from([
        ("node".to_owned(), node.to_owned()),
        ("reason".to_owned(), held.reason.as_str().to_owned()),
        ("direction".to_owned(), direction.to_owned()),
        ("jump_secs".to_owned(), secs.to_string()),
    ]);
    let next = match until {
        Some(until) => {
            params.insert("until".to_owned(), until.to_rfc3339());
            format!("resumes by itself at {until}")
        }
        None => "waits until a person confirms the clock".to_owned(),
    };
    Some(StatusWarning {
        code: code.to_owned(),
        detail: format!("{what}; Tenko keeps expired data there and {next}"),
        params,
    })
}

#[cfg(test)]
mod tests {
    use tenko_api::{dto::system::FindingSeverity, routes::system::diagnostics::severity_of};
    use tenko_core::{clock::Guard, testing::TempDir};

    use super::*;

    fn held(reason: Reason, jump_ms: i64, release: Release) -> Held {
        Held {
            reason,
            jump_ms,
            since: Timestamp::UNIX_EPOCH,
            release,
            until: (release == Release::Wait)
                .then(|| Timestamp::from_unix_nanos(1_800_000_000_400_000_000).expect("a time")),
        }
    }

    #[test]
    fn an_unreadable_file_starts_trusted_with_a_warning() {
        let dir = TempDir::new("clock-file");
        let path = dir.join(FILE);
        assert_eq!(read(&path), None, "no file");
        std::fs::write(&path, b"{\"last_trusted_at\": 12").expect("write");
        let saved = read(&path);
        assert_eq!(saved, None);
        let guard = Guard::start(saved, Instant::now(), Timestamp::UNIX_EPOCH);
        assert_eq!(guard.trusted(), Ok(()));
    }

    #[tokio::test]
    async fn the_file_is_written_on_change_every_minute_and_at_stop() {
        let hold = SavedHold {
            reason: Reason::Jump,
            jump_ms: 60_000,
            since: Timestamp::UNIX_EPOCH,
        };
        assert!(due(None, None), "the first look");
        assert!(!due(Some((None, Duration::from_secs(59))), None));
        assert!(due(Some((None, WRITE_EVERY)), None), "a minute");
        assert!(due(Some((None, Duration::ZERO)), Some(&hold)), "a change");
        let moved = SavedHold {
            jump_ms: 61_000,
            ..hold.clone()
        };
        assert!(
            !due(Some((Some(&hold), Duration::ZERO)), Some(&moved)),
            "the same hold"
        );

        let dir = TempDir::new("clock-stop");
        let (stop, stopped) = watch::channel(false);
        stop.send(true).expect("a receiver");
        run(
            dir.path().to_owned(),
            Some(AppState::default()),
            "n1".to_owned(),
            stopped,
        )
        .await;
        let saved = read(&dir.join(FILE)).expect("written at the stop");
        let round: Saved =
            serde_json::from_slice(&serde_json::to_vec(&saved).expect("json")).expect("json");
        assert_eq!(round, saved);
    }

    #[test]
    fn a_start_gap_within_a_day_raises_no_finding() {
        assert_eq!(notice("n1", None), None);
        assert_eq!(
            notice("n1", Some(&held(Reason::StartGap, 90_000, Release::Wait))),
            None
        );
        let long = notice(
            "n1",
            Some(&held(Reason::StartGap, 90_000_000, Release::Person)),
        )
        .expect("a person confirms");
        assert_eq!(long.code, clock::HELD);
        assert_eq!(long.params["reason"], "start_gap");
        assert_eq!(long.params["jump_secs"], "90000");
        assert!(!long.params.contains_key("until"));
    }

    #[test]
    fn a_wait_is_a_warning_and_a_person_is_act_now() {
        let wait =
            notice("n1", Some(&held(Reason::Jump, -3_600_500, Release::Wait))).expect("a wait");
        assert_eq!(wait.code, clock::JUMPED);
        assert_eq!(severity_of(&wait.code), FindingSeverity::Warning);
        assert_eq!(
            (
                wait.params["direction"].as_str(),
                wait.params["jump_secs"].as_str(),
                wait.params["until"].as_str()
            ),
            ("back", "3601", "2027-01-15T08:00:00Z")
        );
        let person =
            notice("n1", Some(&held(Reason::Jump, 90_000_000, Release::Person))).expect("a person");
        assert_eq!(person.code, clock::HELD);
        assert_eq!(severity_of(&person.code), FindingSeverity::Error);
        assert_eq!(person.params["direction"], "forward");
    }
}
