//! The in-memory paces of approvals, per controller and on its monotonic clock: requests per
//! source, audit records per source and per browser session, wrong codes and the lock they
//! cause. A restart forgets them, which only lets an attacker start one window anew.

use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

/// Keys a pace holds at most: at capacity the windows that are over go first, then an
/// arbitrary one. With keys of at most 39 octets (an IPv6 address as text) this is below 1 MiB
/// per pace.
const CAPACITY: usize = 4_096;

/// Events per key in windows: a window starts at a key's first event and lasts its duration.
#[derive(Debug, Default)]
pub(crate) struct Pace(Mutex<HashMap<Vec<u8>, (Instant, u32)>>);

impl Pace {
    /// Counts an event of `key` at `now` and answers the number of its events in the current
    /// window, this one included.
    pub(crate) fn hit(&self, key: &[u8], now: Instant, window: Duration) -> u32 {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if map.len() >= CAPACITY && !map.contains_key(key) {
            map.retain(|_, (start, _)| now.saturating_duration_since(*start) < window);
            if map.len() >= CAPACITY
                && let Some(victim) = map.keys().next().cloned()
            {
                map.remove(&victim);
            }
        }
        let entry = map.entry(key.to_vec()).or_insert((now, 0));
        if now.saturating_duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1
    }

    /// Whether `key` has a window that is not over at `now`.
    pub(crate) fn active(&self, key: &[u8], now: Instant, window: Duration) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .is_some_and(|(start, _)| now.saturating_duration_since(*start) < window)
    }
}

/// The paces of the approval service.
#[derive(Debug, Default)]
pub(crate) struct Paces {
    /// Requests per source.
    pub(crate) requests: Pace,
    /// Audited requests per source.
    pub(crate) request_audits: Pace,
    /// Wrong codes per browser session.
    pub(crate) wrong_codes: Pace,
    /// Locked lookups per browser session.
    pub(crate) locks: Pace,
    /// Audited refusals per browser session or source.
    pub(crate) refusals: Pace,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_counts_its_events_and_ends() {
        let pace = Pace::default();
        let start = Instant::now();
        let window = Duration::from_secs(10);
        assert_eq!(pace.hit(b"a", start, window), 1);
        assert_eq!(pace.hit(b"a", start + Duration::from_secs(9), window), 2);
        assert_eq!(pace.hit(b"b", start + Duration::from_secs(9), window), 1);
        assert!(pace.active(b"a", start + Duration::from_secs(9), window));
        assert!(!pace.active(b"a", start + window, window));
        assert_eq!(pace.hit(b"a", start + window, window), 1);
    }

    #[test]
    fn the_map_stays_within_its_capacity() {
        let pace = Pace::default();
        let now = Instant::now();
        for index in 0..=CAPACITY {
            pace.hit(&index.to_be_bytes(), now, Duration::from_secs(60));
        }
        assert!(pace.0.lock().expect("a lock").len() <= CAPACITY);
    }
}
