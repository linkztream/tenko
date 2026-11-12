//! The failure cache of RFC 9520 ([`FailureCache`], recursion plan section 2.2): a
//! resolution that ends in SERVFAIL for a cause of the server's is answered SERVFAIL with
//! the same extended error for 5 seconds, doubling on each repeat up to
//! `[dns.recursion] failure_cache_max_secs` (5 minutes); a cause of the client's is not
//! cached. The lookup runs on the worker and allocates nothing. The node's implementation
//! is [`crate::cache::Failures`].

use std::time::{Duration, Instant};

use tenko_core::dns::ExtendedError;

use super::BudgetBound;
use crate::cache::CacheKey;

/// The first hold of a failure (RFC 9520 section 3.2).
pub const FAILURE_MIN: Duration = Duration::from_secs(5);

/// The default longest hold.
pub const FAILURE_MAX: Duration = Duration::from_secs(300);

/// The failures the cache keeps at most when no answer cache sets the bound.
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
