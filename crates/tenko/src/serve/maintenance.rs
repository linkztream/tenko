//! Store maintenance: the re-seed rule of ADR 0002 at start and periodically, and a disk
//! usage line in the log.
//!
//! redb never repacks its file in place, so the state file keeps free pages after churn. The
//! rule: re-seed when the state file at start is larger than `store.reseed_ratio_percent`
//! of the live data (default 200 percent), or, while running, larger than twice that (redb
//! keeps growth slack of up to the pages in use). Files below `store.reseed_min_mib` are left
//! alone: for a small store the ratio says nothing.

use std::time::Duration;

use tenko_store::raft::{DiskUsage, RaftStore};
use tokio::sync::watch;

use crate::config::StoreSection;

/// When to re-seed.
#[derive(Debug, Clone, Copy)]
pub(super) struct Policy {
    /// The threshold at start, as a ratio of the state file to the live data.
    ratio_at_open: f64,
    /// The threshold while running.
    ratio_running: f64,
    /// Smallest state file considered, in bytes.
    min_bytes: u64,
    /// Time between checks.
    interval: Duration,
}

impl Policy {
    /// The policy of the `[store]` section.
    pub(super) fn new(section: &StoreSection) -> Self {
        let ratio = f64::from(section.reseed_ratio_percent) / 100.0;
        Self {
            ratio_at_open: ratio,
            ratio_running: ratio * 2.0,
            min_bytes: section.reseed_min_mib.saturating_mul(1024 * 1024),
            interval: Duration::from_secs(section.maintenance_interval_hours.saturating_mul(3_600)),
        }
    }
}

/// Applies the rule to the size at start and returns a summary for the start log.
pub(super) async fn at_start(store: &RaftStore, policy: Policy) -> String {
    let usage = store.disk_usage();
    let due = usage.state_bytes_at_open >= policy.min_bytes
        && usage
            .state_ratio_at_open
            .is_some_and(|ratio| ratio > policy.ratio_at_open);
    if due {
        reseed(store, &usage, "at start").await;
        return describe(&store.disk_usage());
    }
    describe(&usage)
}

/// Checks every interval until `stop` is set.
pub(super) async fn run(store: RaftStore, policy: Policy, mut stop: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(policy.interval.max(Duration::from_secs(60)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = ticker.tick() => {}
        }
        if *stop.borrow() {
            return;
        }
        let usage = store.disk_usage();
        tracing::info!("store maintenance: {}", describe(&usage));
        let due = usage.state_bytes >= policy.min_bytes
            && usage
                .state_ratio
                .is_some_and(|ratio| ratio > policy.ratio_running);
        if due {
            reseed(&store, &usage, "while running").await;
        }
    }
}

async fn reseed(store: &RaftStore, usage: &DiskUsage, when: &str) {
    tracing::info!(
        state_bytes = usage.state_bytes,
        data_bytes = usage.data_bytes,
        "re-seeding the store {when}: the state file is large for its live data (ADR 0002)"
    );
    match store.reseed_in_place().await {
        Ok(done) => tracing::info!(
            bytes_before = done.bytes_before,
            bytes_after = done.bytes_after,
            elapsed_ms = u64::try_from(done.duration.as_millis()).unwrap_or(u64::MAX),
            "store re-seeded: {} MiB -> {} MiB",
            mib(done.bytes_before),
            mib(done.bytes_after)
        ),
        Err(error) => tracing::warn!(%error, "store re-seed failed; the old file stays in use"),
    }
}

fn describe(usage: &DiskUsage) -> String {
    let ratio = usage
        .state_ratio
        .map_or_else(|| "-".to_owned(), |ratio| format!("{ratio:.2}"));
    format!(
        "log {} MiB, state {} MiB (ratio {ratio}), snapshots {} MiB, live data {} MiB",
        mib(usage.log_bytes),
        mib(usage.state_bytes),
        mib(usage.snapshot_bytes),
        mib(usage.data_bytes)
    )
}

#[allow(clippy::cast_precision_loss, reason = "a display value in MiB")]
fn mib(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / (1024.0 * 1024.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_follows_the_section() {
        let policy = Policy::new(&StoreSection::default());
        assert!((policy.ratio_at_open - 2.0).abs() < f64::EPSILON);
        assert!((policy.ratio_running - 4.0).abs() < f64::EPSILON);
        assert_eq!(policy.min_bytes, 64 * 1024 * 1024);
        assert_eq!(policy.interval, Duration::from_secs(24 * 3_600));
    }

    #[test]
    fn sizes_print_in_mib() {
        assert_eq!(mib(3 * 1024 * 1024 / 2), "1.5");
    }
}
