//! Failover scenarios of the cluster lab (WP3.1c, E9 on one machine): the leader killed
//! under 100 writes per second, a follower killed under load, and every controller
//! restarted. Slow; they run in the weekly lab job and with `--run-ignored`.

mod cluster_support;
mod serve_support;

use std::{
    thread,
    time::{Duration, Instant},
};

use cluster_support::{ClusterLab, LoadReport};

/// The M3 threshold: writes resume within this time after the leader is killed.
const RESUME_LIMIT: Duration = Duration::from_secs(15);

/// How long one scenario may take, the lab's start included.
const SCENARIO_LIMIT: Duration = Duration::from_secs(600);

/// Prints the report of a load.
fn print_report(what: &str, report: &LoadReport) {
    println!("{what}: {}", report.summary());
}

#[test]
#[ignore = "slow lab scenario, nightly"]
#[allow(clippy::too_many_lines, reason = "one scenario, step by step")]
fn the_leader_is_killed_under_load() {
    let mut lab = ClusterLab::start(3);
    let leader = lab.leader();
    let followers = lab.followers();
    let target = followers[0];

    // An event stream and a probe on the leader, so both must move elsewhere.
    let events = lab.sse_client(leader, "ipam");
    let probe = lab.probe(leader);
    lab.wait_for("the probe connected", Duration::from_secs(60), || {
        lab.node_view(leader, probe.id)
            .is_some_and(|view| view["connected"] == true)
    });

    let load = lab.start_load(target, 100);
    thread::sleep(Duration::from_secs(5));
    let killed = Instant::now();
    lab.kill(leader);
    probe.inject(None);
    let new_leader = lab.leader();
    assert_ne!(new_leader, leader);
    let elected = killed.elapsed();
    thread::sleep(Duration::from_secs(20));
    let report = load.stop();
    print_report("kill the leader at 100 writes/s", &report);

    let resumed = report
        .resumed_after(killed)
        .unwrap_or_else(|| panic!("no write committed after the kill\n{}", lab.diagnostics()));
    println!(
        "new leader {new_leader} after {elected:?}; writes resumed {resumed:?} after the kill"
    );
    assert!(
        resumed < RESUME_LIMIT,
        "writes resumed {resumed:?} after the kill, more than {RESUME_LIMIT:?}"
    );

    // No committed write lost: the survivors agree at the last committed revision and
    // show every address the load created.
    let last = report.committed_revision();
    let agreement = lab.digests_agree(last);
    println!(
        "survivors {:?} agree at revision {} (load committed up to {last})",
        agreement.members, agreement.revision
    );
    for survivor in lab.ids() {
        let missing = lab.missing_creates(&report, survivor);
        assert!(
            missing.is_empty(),
            "controller {survivor} lost {} committed creates: {missing:?}",
            missing.len()
        );
    }

    // The event stream reconnected elsewhere and has every committed write's event, or
    // was told to reload.
    let committed: Vec<u64> = report
        .committed()
        .filter_map(cluster_support::WriteRecord::revision)
        .collect();
    events.wait_for(
        &lab,
        "every committed write on the event stream, or a reset",
        Duration::from_secs(60),
        |seen| {
            let ids: std::collections::BTreeSet<u64> = seen
                .iter()
                .filter_map(|event| event.id.as_deref()?.parse().ok())
                .collect();
            seen.iter().any(|event| event.event == "reset")
                || committed.iter().all(|revision| ids.contains(revision))
        },
    );
    let connections = events.connections();
    println!(
        "event stream: {} events, {} resets, connections {connections:?}",
        events.events().len(),
        events.resets()
    );
    assert!(
        connections.len() >= 2 && connections.last() != Some(&lab.url(leader)),
        "the event stream did not move to a survivor: {connections:?}"
    );

    // The probe reconnects to a survivor and its buffer drains.
    lab.wait_for(
        "the probe's batch at a survivor and an empty buffer",
        Duration::from_secs(90),
        || lab.probe_facts(new_leader, probe.id) == Some(2) && probe.buffered() == 0,
    );
    lab.wait_for("the probe connected again", Duration::from_secs(60), || {
        lab.node_view(new_leader, probe.id)
            .is_some_and(|view| view["connected"] == true)
    });

    // The old leader comes back as a follower and catches up.
    lab.restart(leader);
    lab.wait_for_members(3);
    lab.digests_agree(last);
    assert!(lab.elapsed() < SCENARIO_LIMIT, "took {:?}", lab.elapsed());
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
