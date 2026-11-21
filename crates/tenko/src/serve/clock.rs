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
//! The findings of a controller: `sys.clock.jumped` (a warning) while a hold of destruction ends
//! by itself; `sys.clock.held` (to act on) while a person must confirm the clock: after a jump
//! or a start gap of more than a day, and after a wait that ended while issuing is still held.
//! A start gap within a day that holds destruction alone is the downtime of a restart: one line
//! in the log, no finding.
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

/// Restores the guard from the file of `data_dir`; called before any round can run. `api`
/// says whether this process serves the confirm (a controller).
pub(crate) fn restore(data_dir: &Path, api: bool) {
    let path = data_dir.join(FILE);
    clock::restore(read(&path));
    log_change(None, current().as_ref(), &way_out(&path, api));
}

/// A hold as the sampler sees it: the hold, and whether it holds destruction and issuing.
type Now = (Held, bool, bool);

/// The hold now; the hold of destruction when there is one, else that of issuing alone.
fn current() -> Option<Now> {
    let issuing = clock::plausible_now().err();
    match clock::trusted_now() {
        Err(held) => Some((held, true, issuing.is_some())),
        Ok(_) => issuing.map(|held| (held, false, true)),
    }
}

/// Whether a hold ends by itself with nothing for a person to see: a start gap whose wait
/// holds destruction alone.
fn silent((held, destroy, issue): &Now) -> bool {
    *destroy && !issue && held.reason == Reason::StartGap && held.release == Release::Wait
}

/// What ends a hold that needs a person on this node.
fn way_out(path: &Path, api: bool) -> String {
    let root = format!(
        "root stops the service, deletes {} and starts it",
        path.display()
    );
    if api {
        format!("an administrator confirms the clock in the web UI, or {root}")
    } else {
        root
    }
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

/// Whether the file is due: never written, the hold or what it holds changed, or a minute
/// passed.
fn due(written: Option<(Option<&SavedHold>, Duration)>, held: Option<&SavedHold>) -> bool {
    let key = |held: Option<&SavedHold>| {
        held.map(|held| (held.reason, held.since, held.destroy, held.issue))
    };
    written.is_none_or(|(was, age)| key(was) != key(held) || age >= WRITE_EVERY)
}

/// Looks every second until `stop`, keeps the file and the findings of `state` (a controller's
/// API, `None` on a node without one) current, and writes the file once more at the end.
/// `node` is the name a person reads, `id` the node id the confirm names.
pub(crate) async fn run(
    data_dir: PathBuf,
    state: Option<AppState>,
    (node, id): (String, String),
    mut stop: watch::Receiver<bool>,
) {
    let path = data_dir.join(FILE);
    let out = way_out(&path, state.is_some());
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut held = current();
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
        let now = current();
        log_change(held.as_ref(), now.as_ref(), &out);
        if let Some(state) = &state {
            let warning = notice(&node, &id, now.as_ref());
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

/// One line at each change of what is held: info for a start gap that ends by itself with
/// nothing to see, warn for any other hold, with `out`, the way out that needs a person on this
/// node.
fn log_change(before: Option<&Now>, now: Option<&Now>, out: &str) {
    let answers = |now: &Now| (now.1, now.2);
    match (before.map(answers), now) {
        (Some(was), Some(now)) if was == answers(now) => {}
        (_, Some(now)) if silent(now) => {
            tracing::info!(
                gap_secs = now.0.jump_ms / 1_000,
                until = ?now.0.until,
                "the clock is away from the last time it trusted; it is trusted again by itself then"
            );
        }
        (_, Some((held, true, _))) => tracing::warn!(
            reason = held.reason.as_str(),
            jump_ms = held.jump_ms,
            until = ?held.until,
            "the clock is held; {}",
            match held.release {
                Release::Wait => {
                    "it is trusted again to judge what has expired by itself then".to_owned()
                }
                _ => format!("it is trusted again when {out}"),
            }
        ),
        (_, Some((held, false, _))) => tracing::warn!(
            reason = held.reason.as_str(),
            jump_ms = held.jump_ms,
            "the clock is trusted again to judge what has expired, not to issue what other \
             machines check; it is trusted for that when {out}"
        ),
        (Some(_), None) => tracing::info!("the clock is trusted again"),
        (None, None) => {}
    }
}

/// The finding of a hold: [`clock::JUMPED`] while destruction waits, [`clock::HELD`] while a
/// person ends it (issuing alone after a wait included), none for a start gap that ends by
/// itself with nothing to see.
fn notice(node: &str, id: &str, now: Option<&Now>) -> Option<StatusWarning> {
    let now = now?;
    let (held, destroy, issue) = now;
    let code = match (*destroy, held.release) {
        _ if silent(now) => return None,
        (false, _) | (_, Release::Person) => clock::HELD,
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
    let stage = match (destroy, issue) {
        (true, true) => "all",
        (true, false) => "expiry",
        _ => "issuing",
    };
    let mut params = std::collections::BTreeMap::from([
        ("node".to_owned(), node.to_owned()),
        ("node_id".to_owned(), id.to_owned()),
        ("reason".to_owned(), held.reason.as_str().to_owned()),
        ("direction".to_owned(), direction.to_owned()),
        ("jump_secs".to_owned(), secs.to_string()),
        ("stage".to_owned(), stage.to_owned()),
    ]);
    let next = match (until, stage) {
        (Some(until), _) => {
            params.insert("until".to_owned(), until.to_rfc3339());
            format!(
                "Tenko trusts it again to judge what has expired by itself at {until}, or at \
                 once when an administrator confirms the clock"
            )
        }
        (None, "issuing") => "Tenko trusts it again to judge what has expired, but not to \
                              issue what other machines check until an administrator \
                              confirms the clock"
            .to_owned(),
        (None, "expiry") => "Tenko trusts it again to judge what has expired only when an \
                             administrator confirms the clock"
            .to_owned(),
        (None, _) => {
            "Tenko trusts it again only when an administrator confirms the clock".to_owned()
        }
    };
    Some(StatusWarning {
        code: code.to_owned(),
        detail: format!("{what}; {next}"),
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
            destroy: true,
            issue: true,
            forward_ms: 60_000,
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
        let waited = SavedHold {
            destroy: false,
            ..hold.clone()
        };
        assert!(
            due(Some((Some(&hold), Duration::ZERO)), Some(&waited)),
            "the wait ended"
        );

        let dir = TempDir::new("clock-stop");
        let (stop, stopped) = watch::channel(false);
        stop.send(true).expect("a receiver");
        run(
            dir.path().to_owned(),
            Some(AppState::default()),
            ("n1".to_owned(), "7".to_owned()),
            stopped,
        )
        .await;
        let saved = read(&dir.join(FILE)).expect("written at the stop");
        let round: Saved =
            serde_json::from_slice(&serde_json::to_vec(&saved).expect("json")).expect("json");
        assert_eq!(round, saved);
    }

    fn show(now: &Now) -> Option<StatusWarning> {
        notice("n1", "7", Some(now))
    }

    #[test]
    fn a_start_gap_within_a_day_raises_no_finding() {
        assert_eq!(notice("n1", "7", None), None);
        let short = (held(Reason::StartGap, 90_000, Release::Wait), true, false);
        assert_eq!(show(&short), None);
        let long = (
            held(Reason::StartGap, 90_000_000, Release::Person),
            true,
            false,
        );
        let long = show(&long).expect("a person confirms");
        assert_eq!(long.code, clock::HELD);
        assert_eq!(
            (
                long.params["reason"].as_str(),
                long.params["jump_secs"].as_str(),
                long.params["stage"].as_str(),
                long.params["node_id"].as_str()
            ),
            ("start_gap", "90000", "expiry", "7")
        );
        assert!(!long.params.contains_key("until"));
    }

    #[test]
    fn a_start_gap_that_holds_issuing_is_shown_during_its_wait() {
        // A backward start gap, a restart during a hold of a jump, a start gap that grew.
        for jump_ms in [-90_000, 91_000, 150_000] {
            let gap = (held(Reason::StartGap, jump_ms, Release::Wait), true, true);
            let warning = show(&gap).expect("issuing is held");
            assert_eq!(warning.code, clock::JUMPED, "{jump_ms}");
            assert_eq!(warning.params["stage"], "all");
        }
    }

    #[test]
    fn a_wait_is_a_warning_and_a_person_is_act_now() {
        let wait = (held(Reason::Jump, -3_600_500, Release::Wait), true, true);
        let wait = show(&wait).expect("a wait");
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
        let person = (held(Reason::Jump, 90_000_000, Release::Person), true, true);
        let person = show(&person).expect("a person");
        assert_eq!(person.code, clock::HELD);
        assert_eq!(severity_of(&person.code), FindingSeverity::Error);
        assert_eq!(
            (
                person.params["direction"].as_str(),
                person.params["stage"].as_str()
            ),
            ("forward", "all")
        );
    }

    #[test]
    fn issuing_held_after_the_wait_is_act_now_with_its_own_stage() {
        let issuing = (held(Reason::Jump, 60_000, Release::Person), false, true);
        let issuing = show(&issuing).expect("a person");
        assert_eq!(issuing.code, clock::HELD);
        assert_eq!(issuing.params["stage"], "issuing");
        assert!(
            issuing.detail.contains("not to issue"),
            "{}",
            issuing.detail
        );
    }

    #[test]
    fn the_way_out_on_a_node_without_the_api_is_root_alone() {
        let path = Path::new("/srv/tenko/clock.json");
        assert!(way_out(path, true).starts_with("an administrator confirms the clock"));
        let root = way_out(path, false);
        assert!(root.starts_with("root stops the service"), "{root}");
        assert!(!root.contains("web UI"), "{root}");
    }
}
