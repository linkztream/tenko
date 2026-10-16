//! A split of two controllers against one with real processes (WP3.1c with WP3.9, OPS-26):
//! the relays cut every link between the minority and the majority. The minority refuses
//! writes with 503 `cluster.no_quorum` once `isolation_after_ms` has passed, serves reads
//! with the staleness header and queues IPAM changes; the majority commits. After the heal
//! the queue drains (one change applied, one a conflict), the digests agree, and the
//! `cluster.quorum` events arrive on the `cluster` topic. `partition.rs` checks the same
//! in one process. The scenario is in `cluster_support/scenarios.rs`; the exit run calls it
//! with more checks from `acceptance_partition.rs`.

mod cluster_support;
mod serve_support;

use cluster_support::scenarios::{SplitOptions, split_two_against_one};

#[test]
#[ignore = "slow lab scenario, nightly"]
fn a_split_two_against_one_queues_on_the_minority_and_settles_after_the_heal() {
    let split = split_two_against_one(SplitOptions::default());
    println!(
        "isolated {:?} after the cut, healthy {:?} after the heal, quorum events {:?}",
        split.isolated_after, split.healthy_after, split.quorum_states
    );
}
