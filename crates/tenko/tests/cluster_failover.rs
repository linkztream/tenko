//! Failover scenarios of the cluster lab (WP3.1c, E9 on one machine): the leader killed
//! under 100 writes per second, a follower killed under load, and every controller
//! restarted. Slow; they run in the weekly lab job and with `--run-ignored`. The first scenario
//! is in `cluster_support/scenarios.rs`; `acceptance_cluster.rs` calls it for the exit run.

mod cluster_support;
mod serve_support;

use std::{
    thread,
    time::{Duration, Instant},
};

use cluster_support::{
    ClusterLab,
    scenarios::{SCENARIO_LIMIT, leader_killed_under_load, print_report},
};

#[test]
#[ignore = "slow lab scenario, nightly"]
fn the_leader_is_killed_under_load() {
    let summary = leader_killed_under_load();
    println!(
        "the leader {} was killed; {} leads after {:?}; writes resumed {:?}; survivors {:?} agree at revision {}",
        summary.old_leader,
        summary.new_leader,
        summary.elected,
        summary.resumed,
        summary.agreed_members,
        summary.agreed_revision
    );
}

#[test]
#[ignore = "slow lab scenario, nightly"]
fn a_follower_is_killed_under_load() {
    let mut lab = ClusterLab::start(3);
    let leader = lab.leader();
    let follower = lab.followers()[0];
    let load = lab.start_load(leader, 100);
    thread::sleep(Duration::from_secs(5));
    lab.kill(follower);
    thread::sleep(Duration::from_secs(10));
    lab.restart(follower);
    let restarted = Instant::now();
    // The lag of the restarted follower, as the leader sees it, recovers under load.
    let lag = lab.wait_until(
        "the restarted follower to catch up under load",
        Duration::from_secs(90),
        || {
            let view = lab.members(leader)?;
            let member = view["members"]
                .as_array()?
                .iter()
                .find(|member| member["node"].as_u64() == Some(follower))?
                .clone();
            member["lag_entries"].as_u64().filter(|lag| *lag <= 100)
        },
    );
    let caught_up = restarted.elapsed();
    thread::sleep(Duration::from_secs(5));
    let report = load.stop();
    print_report("kill a follower at 100 writes/s", &report);
    println!("the follower caught up {caught_up:?} after its restart (lag {lag} entries)");
    assert_eq!(
        report.failed_writes(),
        0,
        "writes through the leader failed while a follower was down: {}",
        report.summary()
    );
    let last = report.committed_revision();
    let agreement = lab.digests_agree(last);
    assert_eq!(agreement.members.len(), 3);
    let missing = lab.missing_creates(&report, follower);
    assert!(
        missing.is_empty(),
        "the restarted follower lacks {} creates",
        missing.len()
    );
    assert!(lab.elapsed() < SCENARIO_LIMIT, "took {:?}", lab.elapsed());
}

#[test]
#[ignore = "slow lab scenario, nightly"]
fn every_controller_restarts_with_its_data() {
    let mut lab = ClusterLab::start(3);
    let leader = lab.leader();
    let report = lab.write_load(leader, 50, Duration::from_secs(5));
    print_report("writes before the restart", &report);
    let last = report.committed_revision();
    let before = lab.digests_agree(last);

    let ids = lab.ids();
    for id in &ids {
        let stopped = lab.stop(*id);
        assert_eq!(stopped.code, Some(0), "controller {id} stopped gracefully");
    }
    let restarted = Instant::now();
    lab.restart_all(&ids);
    let leader = lab.leader();
    let elected = restarted.elapsed();
    lab.wait_for_members(3);
    println!("after a restart of all three, controller {leader} leads after {elected:?}");

    let after = lab.digests_agree(last);
    assert!(after.revision >= before.revision);
    for id in lab.ids() {
        let missing = lab.missing_creates(&report, id);
        assert!(missing.is_empty(), "controller {id} lost {missing:?}");
    }
    // The cluster takes writes again.
    let again = lab.write_load(leader, 20, Duration::from_secs(3));
    assert!(again.committed_count() > 0, "{}", again.summary());
    assert!(lab.elapsed() < SCENARIO_LIMIT, "took {:?}", lab.elapsed());
}
