//! The failure cache of RFC 9520 ([`FailureCache`], recursion plan section 2.2): a
//! resolution that ends in SERVFAIL for a cause of the server's is answered SERVFAIL with
//! the same extended error for 5 seconds, doubling on each repeat up to
//! `[dns.recursion] failure_cache_max_secs` (5 minutes); a cause of the client's is not
//! cached. The lookup runs on the worker and allocates nothing. [`MemFailures`] is the
//! reference, bounded like the other oracles; the node's is `crate::cache::Failures`
//! (WP10.3).

use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use tenko_core::dns::ExtendedError;

use super::BudgetBound;
use crate::{cache::CacheKey, name};

/// The first hold of a failure (RFC 9520 section 3.2).
pub const FAILURE_MIN: Duration = Duration::from_secs(5);

/// The default longest hold.
pub const FAILURE_MAX: Duration = Duration::from_secs(300);

/// The failures [`MemFailures`] keeps at most by default.
pub const FAILURE_BOUND: usize = 100_000;

/// Why a resolution failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureCause {
    /// No server of a delegation answered, a delegation loop, priming failed.
    NoReachableAuthority,
    /// A bound of the work budget was hit.
    Budget(BudgetBound),
    /// Every server failed with a network error.
    Network,
    /// The answer is bogus.
    Bogus(ExtendedError),
}

impl FailureCause {
    /// The extended error the failure is answered with.
    pub const fn ede(self) -> ExtendedError {
        match self {
            FailureCause::NoReachableAuthority | FailureCause::Budget(_) => {
                ExtendedError::NO_REACHABLE_AUTHORITY
            }
            FailureCause::Network => ExtendedError::NETWORK_ERROR,
            FailureCause::Bogus(ede) => ede,
        }
    }
}

/// The failure cache; see the module documentation.
pub trait FailureCache: Send + Sync {
    /// Records a failure of `key` at `now` and returns how long it holds.
    fn record(&self, key: &CacheKey, cause: FailureCause, now: Instant) -> Duration;

    /// The failure of `key` that still holds at `now` (the worker: allocates nothing).
    fn lookup(&self, key: &CacheKey, now: Instant) -> Option<FailureCause>;

    /// Removes every failure, or those whose name is at or below `suffix` (lowercase wire
    /// form). Returns how many.
    fn flush(&self, suffix: Option<&[u8]>) -> usize;

    /// Failures held.
    fn len(&self) -> usize;

    /// Whether none is held.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The failures by key and the use counter of the bound.
type Held = (HashMap<Box<[u8]>, Failed>, u64);

#[derive(Debug, Clone, Copy)]
struct Failed {
    cause: FailureCause,
    until: Instant,
    hold: Duration,
    used: u64,
}

/// The reference [`FailureCache`]; see the module documentation.
#[derive(Debug)]
pub struct MemFailures {
    max: Duration,
    bound: usize,
    failures: Mutex<Held>,
}

impl MemFailures {
    /// An empty cache whose holds double up to `max` (at least [`FAILURE_MIN`]), keeping
    /// at most [`FAILURE_BOUND`] failures.
    pub fn new(max: Duration) -> Self {
        Self::bounded(max, FAILURE_BOUND)
    }

    /// An empty cache keeping at most `bound` failures: past it the least recently used
    /// sixteenth goes.
    pub fn bounded(max: Duration, bound: usize) -> Self {
        Self {
            max: max.max(FAILURE_MIN),
            bound: bound.max(1),
            failures: Mutex::new((HashMap::new(), 0)),
        }
    }
}

impl Default for MemFailures {
    fn default() -> Self {
        Self::new(FAILURE_MAX)
    }
}

impl FailureCache for MemFailures {
    fn record(&self, key: &CacheKey, cause: FailureCause, now: Instant) -> Duration {
        let mut guard = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let (failures, tick) = &mut *guard;
        *tick += 1;
        let used = *tick;
        let hold = match failures.get(key.as_bytes()) {
            // A repeat while the last hold or as long again runs doubles it.
            Some(last) if now < last.until + last.hold => (last.hold * 2).min(self.max),
            _ => FAILURE_MIN,
        };
        failures.insert(
            key.as_bytes().into(),
            Failed {
                cause,
                until: now + hold,
                hold,
                used,
            },
        );
        crate::infra::trim(failures, self.bound, |failed| failed.used);
        hold
    }

    fn lookup(&self, key: &CacheKey, now: Instant) -> Option<FailureCause> {
        let mut guard = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let (failures, tick) = &mut *guard;
        *tick += 1;
        let failed = failures
            .get_mut(key.as_bytes())
            .filter(|failed| failed.until > now)?;
        failed.used = *tick;
        Some(failed.cause)
    }

    fn flush(&self, suffix: Option<&[u8]>) -> usize {
        let mut guard = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let failures = &mut guard.0;
        let before = failures.len();
        match suffix {
            None => failures.clear(),
            Some(suffix) => {
                failures.retain(|key, _| !name::is_within(CacheKey::qname_of(key), suffix));
            }
        }
        before - failures.len()
    }

    fn len(&self) -> usize {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .0
            .len()
    }
}
