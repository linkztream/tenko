//! The metric series of the lease path (WP7.2): the families of [`crate::metrics`] that the
//! committer, the refusal gate, expiry and the history retention count, and the three
//! families this package adds for expiry and history (P3-Q13).
//!
//! [`DROPPED`] is the one instance of `tenko_dhcp_dropped_total{reason}`: the engine counts
//! its drops on it as the refusal gate does, so the family is registered once.

use std::sync::atomic::AtomicU64;

use tenko_core::metrics::{Counter, CounterVec, Desc, Gauge, Histogram, Registry};

use crate::metrics as families;

/// The reasons of `tenko_dhcp_dropped_total`, in series order.
pub const DROP_REASONS: [&str; 7] = [
    "malformed",
    "filtered",
    "no_scope",
    "pool_full",
    "queue",
    "store_refused",
    "rate_limited",
];

/// The series of a drop reason in [`DROPPED`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DropReason {
    /// The request did not parse.
    Malformed = 0,
    /// A MAC filter refused the client.
    Filtered = 1,
    /// No scope serves the request's link.
    NoScope = 2,
    /// The scope has no free address.
    PoolFull = 3,
    /// The commit queue was full.
    Queue = 4,
    /// The store refused the lease write (P3-Q14).
    StoreRefused = 5,
    /// A rate limit dropped it.
    RateLimited = 6,
}

impl DropReason {
    /// Counts one drop.
    pub fn count(self) {
        DROPPED.inc(self as u16);
    }
}

/// `tenko_dhcp_dropped_total{reason}`.
pub static DROPPED: CounterVec = CounterVec::fixed(
    families::DROPPED,
    &[
        &["malformed"],
        &["filtered"],
        &["no_scope"],
        &["pool_full"],
        &["queue"],
        &["store_refused"],
        &["rate_limited"],
    ],
);

/// `tenko_dhcp_store_refused_total`: lease writes the store refused.
pub static STORE_REFUSED: Counter = Counter::new(families::STORE_REFUSED);

/// `tenko_dhcp_commit_duration_seconds`: from the hand-off to the commit, in microseconds.
pub static COMMIT_DURATION: Histogram = Histogram::new(families::COMMIT_DURATION);

/// Leases the expiry service moved to `expired`.
pub const EXPIRED_DESC: Desc = Desc::counter(
    "tenko_dhcp_expired",
    "DHCP leases the expiry service marked expired",
);

/// Rows of `dhcp.history`, as the retention service last counted them.
pub const HISTORY_ROWS_DESC: Desc =
    Desc::gauge("tenko_dhcp_history_rows", "Rows in the DHCP lease history");

/// Rows of `dhcp.history` the retention service purged.
pub const HISTORY_PURGED_DESC: Desc = Desc::counter(
    "tenko_dhcp_history_purged",
    "DHCP lease history rows purged by retention",
);

/// `tenko_dhcp_expired_total`.
pub static EXPIRED: Counter = Counter::new(EXPIRED_DESC);

/// `tenko_dhcp_history_rows`.
pub static HISTORY_ROWS: Gauge = Gauge::new(HISTORY_ROWS_DESC);

/// `tenko_dhcp_history_purged_total`.
pub static HISTORY_PURGED: Counter = Counter::new(HISTORY_PURGED_DESC);

/// History rows written by this process (the committer's and expiry's batches) since it
/// started; the retention service adds them to its count of `dhcp.history` between runs.
pub static HISTORY_WRITTEN: AtomicU64 = AtomicU64::new(0);

/// Registers the lease path's series.
pub fn register(registry: &Registry) {
    registry.register(&DROPPED);
    registry.register(&STORE_REFUSED);
    registry.register(&COMMIT_DURATION);
    registry.register(&EXPIRED);
    registry.register(&HISTORY_ROWS);
    registry.register(&HISTORY_PURGED);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_follow_the_series() {
        assert_eq!(
            DROP_REASONS[DropReason::StoreRefused as usize],
            "store_refused"
        );
        assert_eq!(DROP_REASONS[DropReason::Queue as usize], "queue");
        assert_eq!(DROP_REASONS.len(), DropReason::RateLimited as usize + 1);
        for desc in [EXPIRED_DESC, HISTORY_ROWS_DESC, HISTORY_PURGED_DESC] {
            assert!(desc.name.starts_with("tenko_dhcp_"));
            assert!(families::ALL.iter().all(|known| known.name != desc.name));
        }
    }

    #[test]
    fn the_series_register_once() {
        let registry = Registry::new();
        register(&registry);
        STORE_REFUSED.inc();
        DropReason::StoreRefused.count();
        let names = registry.names();
        assert!(names.contains(&"tenko_dhcp_dropped"));
        assert!(names.contains(&"tenko_dhcp_history_purged"));
        assert!(STORE_REFUSED.get() >= 1);
        assert!(DROPPED.get(DropReason::StoreRefused as u16) >= 1);
    }
}
