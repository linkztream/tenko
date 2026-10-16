//! Acceptance of requirement OPS-26 (a controller without a quorum) on the cluster lab.
//!
//! OPS-26 asks that a controller cut off from its cluster says so, serves reads from its copy
//! and refuses writes, keeps IPAM changes in a queue, and settles the queue after the heal. The
//! lab splits two controllers from one with real processes and relays on every link. The test
//! proves the data the web UI shows (the isolated banner and the stale status item read
//! `store.quorum` of `GET /system/status`, the `cluster.quorum` events of the `cluster` topic and
//! the `Tenko-Staleness` header, see `ui/src/cluster/PartitionStatus.tsx`), the staleness header
//! on reads of the minority and its absence on the majority, and the drain of the queue after the
//! heal: one change applied, one a conflict that waits for the person's decision.
//!
//! The acceptance files are not in the weekly lab job, which runs `cluster_*.rs` only; they run in
//! the exit run with `--run-ignored`. The scenario is the one of `cluster_partition.rs`
//! (`cluster_support/scenarios.rs`) with the banner checks switched on.

mod cluster_support;
mod serve_support;

use cluster_support::scenarios::{SplitOptions, split_two_against_one};

/// OPS-26: the isolated minority gives the banner and the stale item their data, reads carry the
/// staleness header, writes are refused and queued, and the queue drains after the heal.
#[test]
#[ignore = "slow acceptance scenario, the exit run"]
fn ops_26_an_isolated_controller_shows_its_banner_data_and_drains_its_queue_after_the_heal() {
    let split = split_two_against_one(SplitOptions { banner_data: true });
    println!(
        "OPS-26: isolated {:?} after the cut, healthy {:?} after the heal, quorum events {:?}, \
         took {:?}",
        split.isolated_after, split.healthy_after, split.quorum_states, split.took
    );
    assert!(
        split.quorum_states.iter().any(|state| state == "isolated"),
        "the minority announced that it was isolated: {:?}",
        split.quorum_states
    );
    assert_eq!(
        split.quorum_states.last().map(String::as_str),
        Some("healthy"),
        "the minority announced that it was healthy again: {:?}",
        split.quorum_states
    );
}
