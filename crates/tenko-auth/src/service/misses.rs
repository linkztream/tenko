//! Secrets refused a moment ago: a bounded negative cache for session cookies and bearer
//! tokens that neither this controller's copy nor the leader holds, and a bound on the reads
//! at the leader's commit index that unknown secrets may cause at once.
//!
//! A session or a token exists only after its batch committed, and its secret has 256 (or
//! more) random bits, so a secret the leader did not hold cannot become valid later: caching
//! the refusal never refuses a real session.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tenko_core::Timestamp;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Refused secrets kept at most.
pub(super) const CAPACITY: usize = 4_096;
/// How long a refusal is kept.
pub(super) const TTL: Duration = Duration::from_secs(60);
/// Reads at the leader's commit index for unknown secrets that may run at once; further
/// unknown secrets are refused without one.
pub(super) const CONFIRMING: usize = 4;

/// The negative cache and the bound on confirming reads.
#[derive(Debug)]
pub(super) struct Misses {
    refused: Mutex<HashMap<Vec<u8>, Timestamp>>,
    confirming: Arc<Semaphore>,
}

impl Default for Misses {
    fn default() -> Self {
        Self {
            refused: Mutex::new(HashMap::new()),
            confirming: Arc::new(Semaphore::new(CONFIRMING)),
        }
    }
}

impl Misses {
    /// Whether the secret with this hash was refused less than [`TTL`] ago.
    pub(super) fn recent(&self, hash: &[u8], now: Timestamp) -> bool {
        let mut refused = self.refused.lock().unwrap_or_else(PoisonError::into_inner);
        match refused.get(hash) {
            Some(until) if now < *until => true,
            Some(_) => {
                refused.remove(hash);
                false
            }
            None => false,
        }
    }

    /// Notes a secret the leader does not hold. At capacity the ended entries go first,
    /// then an arbitrary one.
    pub(super) fn remember(&self, hash: &[u8], now: Timestamp) {
        let until = now.checked_add(TTL).unwrap_or(now);
        let mut refused = self.refused.lock().unwrap_or_else(PoisonError::into_inner);
        if refused.len() >= CAPACITY && !refused.contains_key(hash) {
            refused.retain(|_, until| now < *until);
            if refused.len() >= CAPACITY
                && let Some(victim) = refused.keys().next().cloned()
            {
                refused.remove(&victim);
            }
        }
        refused.insert(hash.to_vec(), until);
    }

    /// A slot for one confirming read, or `None` when [`CONFIRMING`] are under way.
    pub(super) fn confirming(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.confirming).try_acquire_owned().ok()
    }

    /// The number of refusals kept.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i128) -> Timestamp {
        Timestamp::from_unix_nanos(secs * 1_000_000_000).expect("in range")
    }

    #[test]
    fn a_refusal_is_kept_for_its_lifetime_only() {
        let misses = Misses::default();
        misses.remember(b"one", at(1_000));
        assert!(misses.recent(b"one", at(1_000)));
        assert!(misses.recent(b"one", at(1_059)));
        assert!(!misses.recent(b"one", at(1_060)));
        assert!(!misses.recent(b"two", at(1_000)));
        assert_eq!(misses.len(), 0);
    }

    #[test]
    fn the_cache_stays_within_its_capacity() {
        let misses = Misses::default();
        for n in 0..(CAPACITY + 100) {
            misses.remember(&n.to_be_bytes(), at(1_000));
        }
        assert_eq!(misses.len(), CAPACITY);
        // Ended entries make room first.
        misses.remember(b"late", at(2_000));
        assert_eq!(misses.len(), 1);
    }

    #[test]
    fn confirming_reads_are_bounded() {
        let misses = Misses::default();
        let held: Vec<_> = (0..CONFIRMING)
            .map(|_| misses.confirming().expect("a slot"))
            .collect();
        assert!(misses.confirming().is_none());
        drop(held);
        assert!(misses.confirming().is_some());
    }
}
