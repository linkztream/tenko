//! Acceptance of exit criterion E9 (OPS-03, OPS-04) on the cluster lab.
//!
//! E9 asks that a 3-node cluster loses a controller and goes on: under 100 writes per second the
//! leader is killed, writes resume within the M3 threshold (15 s), the digests of the survivors
//! agree at the last committed revision of the load (no committed write lost), the event-stream
//! client receives every event after it reconnects from its `Last-Event-ID` or is told to reload,
//! and a probe reconnects to a survivor and drains its buffer.
//!
//! The lab covers all of it on one machine: three real `tenko serve` processes with the internal
//! CA, an SSE client and an enrolled probe on the leader, and the digest comparison through the
//! API of every survivor. It does not cover `HAProxy` in front of the controllers or three separate
//! virtual machines: those are the owner's part (WP3.8b).
//!
//! The weekly lab job (`cluster-lab` in `ci.yml`) runs this file with the `cluster_*.rs` scenarios,
//! ignored tests included; the exit run runs it with `--run-ignored all`. The scenario itself is the one of `cluster_failover.rs`
//! (`cluster_support/scenarios.rs`), called, not copied.

mod cluster_support;
mod serve_support;

use cluster_support::scenarios::{RESUME_LIMIT, leader_killed_under_load};

/// E9, OPS-03, OPS-04: the leader of three controllers is killed under 100 writes per second.
/// Writes resume within 15 s, the survivors agree at the last committed revision and lose no
/// committed write, the event stream and the probe move to a survivor, and the old leader
/// rejoins as a follower.
#[test]
#[ignore = "slow acceptance scenario, the exit run"]
fn e9_a_cluster_loses_its_leader_under_load_and_goes_on_without_losing_a_write() {
    let summary = leader_killed_under_load();
    println!(
        "E9: controller {} killed; controller {} leads after {:?}; writes resumed {:?} after the \
         kill; survivors {:?} agree at revision {} (load committed up to {}); took {:?}",
        summary.old_leader,
        summary.new_leader,
        summary.elected,
        summary.resumed,
        summary.agreed_members,
        summary.agreed_revision,
        summary.committed_revision,
        summary.took
    );
    assert!(
        summary.resumed < RESUME_LIMIT,
        "writes resumed {:?} after the kill, more than {RESUME_LIMIT:?}",
        summary.resumed
    );
    assert_ne!(
        summary.new_leader, summary.old_leader,
        "a survivor leads after the kill"
    );
    assert!(
        summary.agreed_revision >= summary.committed_revision,
        "the members agree at or after the last committed revision of the load"
    );
    assert!(
        summary.stream_connections.len() >= 2,
        "the event stream reconnected: {:?}",
        summary.stream_connections
    );
}
