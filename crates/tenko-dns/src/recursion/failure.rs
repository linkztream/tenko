//! The failure cache of RFC 9520 ([`FailureCache`], recursion plan section 2.2): a
//! resolution that ends in SERVFAIL for a cause of the server's is answered SERVFAIL with
//! the same extended error for 5 seconds, doubling on each repeat up to
//! `[dns.recursion] failure_cache_max_secs` (5 minutes); a cause of the client's is not
//! cached. The lookup runs on the worker and allocates nothing. [`MemFailures`] is the
//! reference WP10.3 builds the real one after.

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

#[derive(Debug, Clone, Copy)]
struct Failed {
    cause: FailureCause,
    until: Instant,
    hold: Duration,
}

/// The reference [`FailureCache`]; see the module documentation.
#[derive(Debug)]
pub struct MemFailures {
    max: Duration,
    failures: Mutex<HashMap<Box<[u8]>, Failed>>,
}

impl MemFailures {
    /// An empty cache whose holds double up to `max` (at least [`FAILURE_MIN`]).
    pub fn new(max: Duration) -> Self {
        Self {
            max: max.max(FAILURE_MIN),
            failures: Mutex::new(HashMap::new()),
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
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
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
            },
        );
        hold
    }

    fn lookup(&self, key: &CacheKey, now: Instant) -> Option<FailureCause> {
        let failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        failures
            .get(key.as_bytes())
            .filter(|failed| failed.until > now)
            .map(|failed| failed.cause)
    }

    fn flush(&self, suffix: Option<&[u8]>) -> usize {
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
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
            .len()
    }
}
