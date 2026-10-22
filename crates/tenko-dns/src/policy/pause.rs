//! The pause of the block lists (the blocking view, `docs/dns.md`): while it lasts no block
//! list blocks a name, in the query and in the answer; allow lists, exemptions and RPZ zones
//! go on as before. A pause has an end (5, 15 or 60 minutes in the UI) or lasts until it is
//! resumed; it ends by itself at its end, with no timer.
//!
//! The state is one atomic of the process, as the role runs once per process: the query
//! path reads it with one relaxed load while no pause is set, and reads the clock only
//! during a pause. A restart ends a pause: the lists block again.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tenko_core::Timestamp;

/// No pause.
const NONE: u64 = 0;

/// A pause until it is resumed.
const OPEN: u64 = u64::MAX;

/// The end of the pause in milliseconds since 1970, [`NONE`] or [`OPEN`].
static UNTIL: AtomicU64 = AtomicU64::new(NONE);

/// When the pause started, in milliseconds since 1970.
static SINCE: AtomicU64 = AtomicU64::new(0);

/// The longest pause with an end.
pub const MAX_PAUSE: Duration = Duration::from_secs(24 * 3_600);

/// A pause in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Paused {
    /// When it started.
    pub since: Timestamp,
    /// When it ends; `None` until it is resumed.
    pub until: Option<Timestamp>,
}

fn now_millis() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX - 1)
}

fn timestamp(millis: u64) -> Timestamp {
    Timestamp::from_unix_nanos(i128::from(millis) * 1_000_000).unwrap_or_else(|_| Timestamp::now())
}

/// Pauses the block lists for `length` (cut to [`MAX_PAUSE`]), or until [`resume`] when it
/// is `None`; a pause in force is replaced.
pub fn pause(length: Option<Duration>) -> Paused {
    let now = now_millis();
    let until = length.map_or(OPEN, |length| {
        let millis = u64::try_from(length.min(MAX_PAUSE).as_millis()).unwrap_or(0);
        now.saturating_add(millis.max(1)).min(OPEN - 1)
    });
    SINCE.store(now, Ordering::Relaxed);
    UNTIL.store(until, Ordering::Relaxed);
    Paused {
        since: timestamp(now),
        until: (until != OPEN).then(|| timestamp(until)),
    }
}

/// Ends the pause; whether one was in force.
pub fn resume() -> bool {
    let was = state().is_some();
    UNTIL.store(NONE, Ordering::Relaxed);
    was
}

/// Whether the block lists are paused now (the query path: no allocation).
pub fn active() -> bool {
    let until = UNTIL.load(Ordering::Relaxed);
    if until == NONE {
        return false;
    }
    if until == OPEN || now_millis() < until {
        return true;
    }
    // The pause ended: the next reader need not read the clock.
    let _ = UNTIL.compare_exchange(until, NONE, Ordering::Relaxed, Ordering::Relaxed);
    false
}

/// The pause in force, if any.
pub fn state() -> Option<Paused> {
    if !active() {
        return None;
    }
    let until = UNTIL.load(Ordering::Relaxed);
    Some(Paused {
        since: timestamp(SINCE.load(Ordering::Relaxed)),
        until: match until {
            NONE => return None,
            OPEN => None,
            millis => Some(timestamp(millis)),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test holds the process-wide state from start to end (nextest runs each test in
    // its own process).
    #[test]
    fn a_pause_starts_ends_by_itself_and_resumes() {
        assert!(!active());
        assert_eq!(state(), None);
        let open = pause(None);
        assert!(open.until.is_none());
        assert!(active());
        assert_eq!(state().map(|paused| paused.until), Some(None));
        assert!(resume());
        assert!(!active());
        assert!(!resume());
        let timed = pause(Some(Duration::from_secs(300)));
        let until = timed.until.expect("an end");
        let length = until.unix_nanos() - timed.since.unix_nanos();
        assert_eq!(length, 300_000_000_000);
        assert!(active());
        let short = pause(Some(Duration::from_millis(1)));
        assert!(short.until.is_some());
        std::thread::sleep(Duration::from_millis(5));
        assert!(!active(), "the pause ended by itself");
        assert_eq!(state(), None);
        let long = pause(Some(Duration::from_secs(10 * 24 * 3_600)));
        let length = long.until.expect("an end").unix_nanos() - long.since.unix_nanos();
        assert_eq!(length, 24 * 3_600 * 1_000_000_000, "cut to a day");
        resume();
    }
}
