//! The cluster recovery in the cluster lab (OPS-03, OPS-26; `docs/plans/cluster-recovery-plan.md`
//! sections 3.2 to 3.7, exit checks E134 (a), E135, E136, E138 and E142): `tenko cluster
//! recover` on a stopped survivor, the first start's probe for a live majority, the fence of
//! a superseded controller, two competing forced histories.
//!
//! Every wait is a condition with the lab's limit; nothing here bounds a measured time.

mod cluster_support;
mod serve_support;

use std::time::Duration;

use cluster_support::{ClusterLab, LabOptions};
use serde_json::{Value, json};
use serve_support::Outcome;

/// The first start's probe of the scenarios: long enough for a loopback answer.
const PROBE_SECS: u64 = 2;

/// How long a fence may take to arrive: the authority's push interval and a margin.
const FENCE_LIMIT: Duration = Duration::from_secs(90);

fn lab(n: usize) -> ClusterLab {
    let lab = ClusterLab::start_with(
        n,
        LabOptions {
            recover_probe_secs: Some(PROBE_SECS),
            ..LabOptions::default()
        },
    );
    lab.api(lab.leader())
        .post("/prefixes", &json!({ "cidr": "203.0.113.0/24" }))
        .expect(201);
    lab
}

/// Creates the address `203.0.113.<n>` through controller `id`; the answer.
fn write(lab: &ClusterLab, id: u64, n: u64) -> serve_support::api::Reply {
    lab.api(id)
        .post("/addresses", &json!({ "ip": format!("203.0.113.{n}") }))
}

/// The fingerprint line of `tenko cluster recover --inspect` on controller `id`.
#[track_caller]
fn fingerprint(lab: &ClusterLab, id: u64) -> String {
    let inspected = lab.recover(id, &["--inspect"]);
    inspected.assert_code(0);
    inspected
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("fingerprint"))
        .map_or_else(
            || panic!("no fingerprint\n{}", inspected.diagnostics()),
            |rest| rest.trim().to_owned(),
        )
}

/// The quorum state and its reason as controller `id` reports them.
fn quorum(lab: &ClusterLab, id: u64) -> Option<(String, Option<String>)> {
    let view = lab.members(id)?;
    Some((
        view["quorum"]["state"].as_str()?.to_owned(),
        view["quorum"]["reason"].as_str().map(str::to_owned),
    ))
}

#[track_caller]
fn wait_fenced(lab: &ClusterLab, id: u64, reason: &str) -> Value {
    lab.wait_until(
        &format!("controller {id} fenced ({reason})"),
        FENCE_LIMIT,
        || {
            let view = lab.members(id)?;
            (view["quorum"]["state"] == "fenced" && view["quorum"]["reason"] == reason)
                .then_some(view)
        },
    )
}

#[track_caller]
fn refused_with(outcome: &Outcome, code: &str) {
    assert_ne!(outcome.code, Some(0), "{}", outcome.diagnostics());
    assert!(
        outcome.stderr.contains(code) || outcome.stdout.contains(code),
        "expected {code}\n{}",
        outcome.diagnostics()
    );
}

/// E136, E138 and E142: a stale survivor is forced only with `--accept-older`; it takes
/// office when nobody answers its probe; two old controllers that return together fence at
/// the authority's first contact, and stay fenced across a restart; `--undo` after the
/// first start is refused; the fresher old controller forced in turn meets the first
/// forced history as a sibling, which stops writing.
#[test]
#[ignore = "slow lab scenario; runner: ci.yml#cluster-lab"]
fn a_stale_survivor_is_forced_and_the_old_controllers_fence() {
    let mut lab = lab(3);
    let leader = lab.leader();
    let stale = lab.followers()[0];
    let others: Vec<u64> = lab.ids().into_iter().filter(|id| *id != stale).collect();
    write(&lab, leader, 1).expect(201);

    // The stale one is cut off while the others write on.
    lab.partition(&[stale], &others);
    let majority_leader = lab.wait_until("a leader of the majority", FENCE_LIMIT, || {
        others
            .iter()
            .copied()
            .find(|id| lab.members(*id).is_some_and(|view| view["leader"] == *id))
    });
    write(&lab, majority_leader, 2).expect(201);
    for id in lab.ids() {
        lab.stop(id).assert_code(0);
    }
    lab.heal();

    let fresher = fingerprint(&lab, others[0]);
    let mut force = vec!["--force", "--compare", fresher.as_str()];
    let confirm = format!("{stale}:1");
    force.extend(["--confirm", confirm.as_str()]);
    refused_with(&lab.recover(stale, &force), "cluster.recover.not_freshest");
    force.push("--accept-older");
    lab.recover(stale, &force).assert_code(0);

    // Nobody answers the probe: the forced controller takes office.
    lab.restart(stale);
    assert_eq!(
        quorum(&lab, stale).map(|(state, _)| state).as_deref(),
        Some("single")
    );
    write(&lab, stale, 3).expect(201);
    let view = lab.members(stale).expect("the members view");
    assert_eq!(view["generation"]["number"], 1, "{view}");
    // E138: the step cannot be undone once the controller took office.
    refused_with(
        &lab.recover(stale, &["--undo"]),
        "cluster.recover.undo_refused",
    );

    // E142: the two old controllers return together and form their old quorum, until the
    // authority's first contact fences them; the writes they took meanwhile are counted.
    lab.restart_all(&others);
    let mut taken = 0_u64;
    let mut n = 10;
    lab.wait_for("both old controllers fenced", FENCE_LIMIT, || {
        n += 1;
        if write(&lab, others[0], n).status == 201 {
            taken += 1;
        }
        others.iter().all(|id| {
            quorum(&lab, *id).is_some_and(|(state, reason)| {
                state == "fenced" && reason.as_deref() == Some("superseded")
            })
        })
    });
    println!("E142: the returning old controllers took {taken} write(s) before the fence");
    let refused = write(&lab, others[0], 200);
    let problem = refused.expect(503);
    assert_eq!(problem["code"], "cluster.superseded", "{problem}");
    assert!(
        refused.header("retry-after").is_none(),
        "no retry hint: an operator acts"
    );
    let ready = lab.get(others[0], "/health/ready").expect("an answer");
    assert_eq!(ready.status, 503, "{}", ready.text);
    // E138: a superseded controller restarted stays fenced.
    lab.stop(others[0]).assert_code(0);
    lab.restart(others[0]);
    wait_fenced(&lab, others[0], "superseded");

    // E136: the fresher old controller is forced in turn (generation 2, parent generation
    // 0); the first forced history meets it as a sibling and stops writing.
    lab.stop(others[0]).assert_code(0);
    let confirm = format!("{}:2", others[0]);
    lab.recover(others[0], &["--force", "--confirm", &confirm])
        .assert_code(0);
    lab.restart(others[0]);
    write(&lab, others[0], 4).expect(201);
    let first = wait_fenced(&lab, stale, "conflict");
    assert_eq!(first["generation"]["stopped_by"]["number"], 2, "{first}");
    assert_eq!(
        first["generation"]["stopped_by"]["suggested"], true,
        "{first}"
    );
    let second = lab.members(others[0]).expect("the members view");
    assert_eq!(second["generation"]["number"], 2, "{second}");
    assert_eq!(second["quorum"]["state"], "single", "{second}");
}

/// E134 (a): the partition heals before the forced controller's first start; the probe
/// finds the old majority alive, the forced controller refuses office, and `--undo` brings
/// it back into the live cluster, which lost nothing.
#[test]
#[ignore = "slow lab scenario; runner: ci.yml#cluster-lab"]
fn a_live_majority_keeps_the_forced_controller_out_of_office() {
    let mut lab = lab(3);
    let cut = lab.followers()[0];
    let others: Vec<u64> = lab.ids().into_iter().filter(|id| *id != cut).collect();
    lab.partition(&[cut], &others);
    lab.stop(cut).assert_code(0);
    let confirm = format!("{cut}:1");
    lab.recover(cut, &["--force", "--confirm", &confirm])
        .assert_code(0);
    lab.heal();
    let leader = lab.wait_until("a leader of the majority", FENCE_LIMIT, || {
        others
            .iter()
            .copied()
            .find(|id| lab.members(*id).is_some_and(|view| view["leader"] == *id))
    });
    write(&lab, leader, 5).expect(201);

    lab.restart(cut);
    wait_fenced(&lab, cut, "majority_alive");
    let problem = write(&lab, cut, 6).expect(503);
    assert_eq!(
        problem["code"], "cluster.recover.majority_alive",
        "{problem}"
    );
    // The live majority was not fenced by a step the operator may still undo.
    for id in &others {
        assert_eq!(
            quorum(&lab, *id).map(|(state, _)| state).as_deref(),
            Some("healthy")
        );
    }

    lab.stop(cut).assert_code(0);
    lab.recover(cut, &["--undo"]).assert_code(0);
    lab.restart(cut);
    lab.wait_for_members(3);
    let address = lab.wait_until(
        "the majority's write on the returned controller",
        FENCE_LIMIT,
        || {
            let reply = lab.get(cut, "/addresses")?;
            (reply.status == 200 && reply.text.contains("203.0.113.5")).then_some(reply)
        },
    );
    assert_eq!(address.status, 200);
}

/// E135: two controllers forced at once on the two sides of a partition both take office;
/// after the heal each meets the other's record as a sibling, both stop writing, and both
/// name the same suggested winner.
#[test]
#[ignore = "slow lab scenario; runner: ci.yml#cluster-lab"]
fn two_controllers_forced_at_once_both_stop_and_agree_on_the_winner() {
    let mut lab = lab(3);
    let ids = lab.ids();
    let (gone, a, b) = (ids[0], ids[1], ids[2]);
    lab.kill(gone);
    lab.stop(a).assert_code(0);
    lab.stop(b).assert_code(0);
    for id in [a, b] {
        let confirm = format!("{id}:1");
        lab.recover(id, &["--force", "--confirm", &confirm])
            .assert_code(0);
    }
    lab.partition(&[a], &[b]);
    lab.restart(a);
    lab.restart(b);
    write(&lab, a, 7).expect(201);
    write(&lab, b, 8).expect(201);

    lab.heal();
    let seen_a = wait_fenced(&lab, a, "conflict");
    let seen_b = wait_fenced(&lab, b, "conflict");
    let winner = |view: &Value| {
        let stopped = &view["generation"]["stopped_by"];
        if stopped["suggested"] == true {
            stopped["forced"].clone()
        } else {
            view["generation"]["forced"].clone()
        }
    };
    assert_eq!(winner(&seen_a), winner(&seen_b), "{seen_a}\n{seen_b}");
    assert_ne!(
        seen_a["generation"]["stopped_by"]["suggested"],
        seen_b["generation"]["stopped_by"]["suggested"],
        "exactly one side is the suggested winner"
    );
    for id in [a, b] {
        let problem = write(&lab, id, 9).expect(503);
        assert_eq!(problem["code"], "cluster.recover.conflict", "{problem}");
    }
}
