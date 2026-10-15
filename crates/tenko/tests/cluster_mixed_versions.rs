//! A rolling upgrade across two versions (WP3.1c with WP3.6): three controllers start on an
//! older `tenko` binary, then each moves to the binary under test in the order of
//! `docs/upgrades.md` (followers first, then the leader after a step-down) while the cluster
//! keeps taking writes. It needs a second binary of another version: set `TENKO_OLD_BIN` to
//! its path (a release that has `tenko cluster join`); without it the scenario says so and
//! passes. The links run directly, without the lab's relays, because an older binary may
//! not know `[cluster] peer_address_map`.

mod cluster_support;
mod serve_support;

use std::{path::PathBuf, process::Command, time::Duration};

use cluster_support::{ClusterLab, LabOptions};

/// The variable that names the older binary.
const OLD_BIN: &str = "TENKO_OLD_BIN";

/// The versions the members report, by node id.
fn versions(lab: &ClusterLab, on: u64) -> Vec<(u64, String)> {
    lab.members(on)
        .and_then(|view| {
            view["members"].as_array().map(|members| {
                members
                    .iter()
                    .filter_map(|member| {
                        Some((
                            member["node"].as_u64()?,
                            member["version"].as_str().unwrap_or("?").to_owned(),
                        ))
                    })
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// A short write load through `target`; every write must commit.
#[track_caller]
fn writes_commit(lab: &ClusterLab, target: u64, what: &str) -> u64 {
    let load = lab.write_load(target, 20, Duration::from_secs(3));
    assert!(
        load.failed_writes() == 0 && load.committed_count() > 0,
        "{what}: {}",
        load.summary()
    );
    load.committed_revision()
}

#[test]
#[ignore = "slow lab scenario, nightly"]
fn mixed_versions_needs_a_second_binary() {
    let Some(old) = std::env::var_os(OLD_BIN).map(PathBuf::from) else {
        println!(
            "skipped: {OLD_BIN} is not set; the mixed-version scenario needs the path of an \
             older tenko binary (see deploy/compose/lab-cluster/README.md)"
        );
        return;
    };
    assert!(old.is_file(), "{OLD_BIN}={} is not a file", old.display());
    let reported = Command::new(&old)
        .arg("--version")
        .output()
        .expect("run the older binary");
    let old_version = String::from_utf8_lossy(&reported.stdout).trim().to_owned();
    println!(
        "older binary: {old_version}; binary under test: {}",
        serve_support::VERSION
    );

    let mut lab = ClusterLab::start_with(
        3,
        LabOptions {
            binary: Some(old),
            direct_links: true,
            ..LabOptions::default()
        },
    );
    let leader = lab.leader();
    println!("before: {:?}", versions(&lab, leader));
    writes_commit(&lab, leader, "on the older version");
    let check = lab.cli(leader, &["cluster", "upgrade-check"]);
    println!("upgrade-check: {}", check.stdout);
    check.assert_code(0);

    // The followers first, one at a time.
    for follower in lab.followers() {
        lab.stop(follower);
        lab.set_binary(follower, None);
        lab.restart(follower);
        lab.wait_for_members(3);
        writes_commit(&lab, follower, "with mixed versions");
        println!("mixed: {:?}", versions(&lab, leader));
    }

    // Then the leader, after it hands over.
    lab.cli(leader, &["cluster", "step-down"]).assert_code(0);
    lab.wait_for("another leader", Duration::from_secs(30), || {
        lab.current_leader().is_some_and(|(id, _)| id != leader)
    });
    lab.stop(leader);
    lab.set_binary(leader, None);
    lab.restart(leader);
    lab.wait_for_members(3);
    let now = lab.leader();
    let last = writes_commit(&lab, now, "after the upgrade");
    lab.digests_agree(last);
    let after = versions(&lab, now);
    println!("after: {after:?}");
    assert!(
        after
            .iter()
            .all(|(_, version)| version == serve_support::VERSION),
        "{after:?}"
    );
}
