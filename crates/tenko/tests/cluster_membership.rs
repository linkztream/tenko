//! Membership scenarios of the cluster lab (WP3.1c): a member rejoins with an empty data
//! directory (M6), a dead voter is replaced, a controller is revoked, and the leader steps
//! down under load.

mod cluster_support;
mod serve_support;

use std::{
    thread,
    time::{Duration, Instant},
};

use cluster_support::{ClusterLab, LabOptions, State, learners, voters, write_result};
use serde_json::json;

/// How long one scenario may take, the lab's start included.
const SCENARIO_LIMIT: Duration = Duration::from_secs(600);

/// M6: the state file of a member that rejoined empty stays below twice the raw size.
const M6_LIMIT: f64 = 2.0;

fn mib(bytes: u64) -> f64 {
    #[allow(clippy::cast_precision_loss, reason = "file sizes")]
    let bytes = bytes as f64;
    (bytes / 1_048_576.0 * 1000.0).round() / 1000.0
}

#[test]
#[ignore = "slow lab scenario, nightly"]
fn a_member_rejoins_with_an_empty_data_directory() {
    let mut lab = ClusterLab::start(3);
    let leader = lab.leader();
    let member = lab.followers()[0];

    // Churn: creates and updates for a while.
    let churn = lab.write_load(leader, 100, Duration::from_secs(20));
    println!("churn: {}", churn.summary());
    lab.digests_agree(churn.committed_revision());
    let before = lab.store_size(member);
    let raw = lab.store_size(leader);

    let rejoined = Instant::now();
    let new = lab.wipe_and_restart(member);
    let join = lab.last_join_time().expect("a join");
    let agreement = lab.digests_agree(churn.committed_revision());
    let complete = rejoined.elapsed();
    assert!(agreement.members.contains(&new));
    let missing = lab.missing_creates(&churn, new);
    assert!(missing.is_empty(), "the rejoined member lacks {missing:?}");

    // At rest: the rejoined member stopped gracefully, the leader quiet.
    thread::sleep(Duration::from_secs(3));
    lab.stop(new).assert_code(0);
    let after = lab.store_size(new);
    let raw_now = lab.store_size(leader).state.max(raw.state);
    #[allow(clippy::cast_precision_loss, reason = "file sizes")]
    let ratio = after.state as f64 / raw_now as f64;
    let result = json!({
        "measurement": "M6",
        "threshold": format!("state file below {M6_LIMIT}x raw at rest"),
        "raw": "the leader's state file (store/sm.redb) after the churn",
        "churn": churn.summary(),
        "raw_state_bytes": raw_now,
        "member_before": { "state": before.state, "log": before.log, "snapshots": before.snapshots },
        "rejoined_after": { "state": after.state, "log": after.log, "snapshots": after.snapshots },
        "ratio": ratio,
        "join_seconds": join.as_secs_f64(),
        "rejoin_complete_seconds": complete.as_secs_f64(),
        "pass": ratio < M6_LIMIT,
    });
    println!("M6: {result}");
    println!(
        "M6: raw {} MiB, member before {} MiB, rejoined {} MiB (ratio {ratio:.3}); join {join:?}, complete {complete:?}",
        mib(raw_now),
        mib(before.state),
        mib(after.state)
    );
    write_result("m6-rejoin", &result);
    assert!(
        ratio < M6_LIMIT,
        "the rejoined state file is {ratio:.2}x the raw size"
    );
    lab.restart(new);
    lab.wait_for_members(3);
    assert!(lab.elapsed() < SCENARIO_LIMIT, "took {:?}", lab.elapsed());
}

#[test]
#[ignore = "slow lab scenario, nightly"]
fn a_dead_voter_is_replaced() {
    let mut lab = ClusterLab::start_with(
        3,
        LabOptions {
            spare: Some(1),
            ..LabOptions::default()
        },
    );
    let leader = lab.leader();
    let dead = lab.followers()[0];
    lab.kill(dead);

    // A fourth controller joins and stays a learner: four voters would be even.
    let new = lab.add_controller();
    let view = lab.wait_until(
        "the new controller as a learner",
        Duration::from_secs(60),
        || {
            let view = lab.members(leader)?;
            learners(&view).contains(&new).then_some(view)
        },
    );
    assert_eq!(voters(&view).len(), 3, "{view}");

    let replaced = lab.cli(
        leader,
        &[
            "cluster",
            "promote",
            &new.to_string(),
            "--replace",
            &dead.to_string(),
        ],
    );
    replaced.assert_code(0);
    lab.mark_removed(dead);
    let view = lab.wait_for_members(3);
    let mut all = voters(&view);
    all.sort_unstable();
    assert!(all.contains(&new) && !all.contains(&dead), "{view}");

    let load = lab.write_load(leader, 20, Duration::from_secs(3));
    assert!(
        load.failed_writes() == 0 && load.committed_count() > 0,
        "writes after the replacement: {}",
        load.summary()
    );
    lab.digests_agree(load.committed_revision());
    assert!(lab.elapsed() < SCENARIO_LIMIT, "took {:?}", lab.elapsed());
}

#[test]
#[ignore = "slow lab scenario, nightly"]
fn a_revoked_controller_leaves_and_cannot_come_back() {
    let mut lab = ClusterLab::start(3);
    let leader = lab.leader();
    let revoked = lab.followers()[0];
    let remaining = lab.followers()[1];

    let removed = lab.cli(
        leader,
        &["cluster", "remove", &revoked.to_string(), "--yes"],
    );
    removed.assert_code(0);
    // Its links close: it loses its quorum while the other two keep theirs.
    lab.wait_for(
        "the revoked controller cut off and two voters left",
        Duration::from_secs(60),
        || {
            let cut_off = lab.quorum(revoked).is_some_and(|state| state != "healthy");
            let view = lab.members(leader);
            let two = view.is_some_and(|view| {
                let mut all = voters(&view);
                all.sort_unstable();
                let mut expected = vec![leader, remaining];
                expected.sort_unstable();
                all == expected && view["members"].as_array().map(Vec::len) == Some(2)
            });
            cut_off && two
        },
    );
    let load = lab.write_load(leader, 20, Duration::from_secs(3));
    assert!(
        load.failed_writes() == 0 && load.committed_count() > 0,
        "the remaining two keep quorum: {}",
        load.summary()
    );

    // With its old identity it does not come back: after a restart it is still cut off,
    // its writes are refused, and the others do not list it.
    lab.stop(revoked);
    lab.restart(revoked);
    thread::sleep(Duration::from_secs(5));
    assert_ne!(lab.quorum(revoked).as_deref(), Some("healthy"));
    let refused = lab.api(revoked).post(
        "/prefixes",
        &json!({ "cidr": "203.0.113.0/24", "description": "from a revoked controller" }),
    );
    assert_eq!(refused.status, 503, "{}", refused.text);
    let view = lab.members(leader).expect("the leader's view");
    assert_eq!(
        view["members"].as_array().map(Vec::len),
        Some(2),
        "the revoked controller came back: {view}"
    );
    lab.stop(revoked);
    lab.mark_removed(revoked);
    assert_eq!(lab.state(revoked), State::Removed);
    lab.digests_agree(load.committed_revision());
    assert!(lab.elapsed() < SCENARIO_LIMIT, "took {:?}", lab.elapsed());
}

#[test]
#[ignore = "slow lab scenario, nightly"]
fn the_leader_steps_down_under_load() {
    let lab = ClusterLab::start(3);
    let leader = lab.leader();
    let target = lab.followers()[0];
    let load = lab.start_load(target, 50);
    thread::sleep(Duration::from_secs(3));
    let asked = Instant::now();
    let stepped = lab.cli(leader, &["cluster", "step-down", "--json"]);
    stepped.assert_code(0);
    let answer = stepped.json();
    let new = answer["leader"].as_u64().expect("the new leader");
    assert_ne!(new, leader, "{answer}");
    let leads = lab.wait_until("the new leader leads", Duration::from_secs(5), || {
        lab.current_leader()
            .filter(|(id, _)| *id == new)
            .map(|_| asked.elapsed())
    });
    thread::sleep(Duration::from_secs(5));
    let report = load.stop();
    println!(
        "step-down: {leader} -> {new}, leading {leads:?} after the request; load {}",
        report.summary()
    );
    let resumed = report
        .resumed_after(asked)
        .expect("writes committed after the step-down");
    assert!(
        resumed < Duration::from_secs(5),
        "writes resumed {resumed:?} after the step-down"
    );
    let (_, unanswered, skipped) = report.failures();
    assert_eq!((unanswered, skipped), (0, 0), "{}", report.summary());
    lab.digests_agree(report.committed_revision());
    assert!(lab.elapsed() < SCENARIO_LIMIT, "took {:?}", lab.elapsed());
}
