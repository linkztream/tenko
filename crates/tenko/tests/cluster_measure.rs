//! The measurements of the cluster lab on one machine (WP3.1c; the final runs are on three
//! VMs in WP3.8): M3 failover, M12 forwarded write latency, M4 steady writes and the
//! catch-up of an empty controller (the one-host stand-in for the catch-up of 6 M record sets), M1
//! reads on a follower during the snapshot install of a joining learner. M6 is measured by
//! `cluster_membership.rs`. Each test writes its raw result as JSON into the directory of
//! `TENKO_LAB_RESULTS` and is skipped without it, so the weekly lab job does not spend half
//! an hour on numbers nobody keeps; `bench/phase1-cluster/run.ps1` and `run.sh` set it and
//! summarize the files. `TENKO_LAB_SECONDS` shortens the timed phases for a quick check.

mod cluster_support;
mod serve_support;

use std::{
    fmt::Write as _,
    thread,
    time::{Duration, Instant},
};

use cluster_support::{
    ClusterLab, LabOptions, LoadReport, RESULTS_ENV,
    load::{ReadReport, ms, quantile},
    write_result,
};
use serde_json::{Value, json};

/// The M3 threshold.
const M3_LIMIT: Duration = Duration::from_secs(15);

/// The M12 margin: the follower's p99 may exceed the leader's by this much.
const M12_MARGIN: Duration = Duration::from_millis(20);

/// The M4 latency threshold at 1,000 writes per second.
const M4_P99: Duration = Duration::from_millis(250);

/// The reads per second of M1: well below what one follower serves, so the reads measure
/// the store and not a queue in front of it.
const READ_RATE: u32 = 50;

/// The options of every measured lab: four API workers per controller.
fn measured() -> LabOptions {
    LabOptions {
        workers: Some(4),
        ..LabOptions::default()
    }
}

/// Whether results are wanted; prints why not otherwise.
fn measuring(name: &str) -> bool {
    let wanted = std::env::var_os(RESULTS_ENV).is_some();
    if !wanted {
        println!(
            "skipped {name}: set {RESULTS_ENV} to a directory to run the measurement \
             (bench/phase1-cluster/run.ps1 or run.sh do)"
        );
    }
    wanted
}

/// A timed phase: `default` seconds, or `TENKO_LAB_SECONDS` when set (a quick check).
fn phase(default: u64) -> Duration {
    let seconds = std::env::var("TENKO_LAB_SECONDS")
        .ok()
        .and_then(|text| text.parse().ok())
        .map_or(default, |quick: u64| quick.min(default));
    Duration::from_secs(seconds)
}

/// The machine and build a result was measured on.
fn environment() -> Value {
    json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "cpus": thread::available_parallelism().map_or(0, std::num::NonZero::get),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "version": serve_support::VERSION,
    })
}

#[test]
#[ignore = "slow lab measurement, run by bench/phase1-cluster"]
fn m3_failover_under_load() {
    if !measuring("M3") {
        return;
    }
    let runs: usize = std::env::var("TENKO_LAB_M3_RUNS")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(20);
    let mut lab = ClusterLab::start_with(3, measured());
    let mut results = Vec::new();
    let mut resumed_all = Vec::new();
    for run in 1..=runs {
        let leader = lab.leader();
        let target = lab.followers()[0];
        let load = lab.start_load(target, 100);
        thread::sleep(Duration::from_secs(3));
        let killed = Instant::now();
        lab.kill(leader);
        let new_leader = lab.leader();
        let elected = killed.elapsed();
        let resumed = lab.wait_until("writes to resume", Duration::from_secs(60), || {
            load.resumed_after(killed)
        });
        thread::sleep(Duration::from_secs(2));
        let report = load.stop();
        let agreement = lab.digests_agree(report.committed_revision());
        let lost: usize = lab
            .ids()
            .into_iter()
            .map(|id| lab.missing_creates(&report, id).len())
            .sum();
        assert_eq!(lost, 0, "run {run}: committed creates lost");
        lab.restart(leader);
        lab.wait_for_members(3);
        println!(
            "M3 run {run}: killed {leader}, {new_leader} leads after {elected:?}, writes resumed after {resumed:?}"
        );
        resumed_all.push(resumed);
        results.push(json!({
            "run": run,
            "killed": leader,
            "new_leader": new_leader,
            "elected_ms": ms(elected),
            "resumed_ms": ms(resumed),
            "load": report.summary(),
            "digest_revision": agreement.revision,
            "lost_creates": lost,
        }));
    }
    resumed_all.sort_unstable();
    let worst = resumed_all.last().copied().unwrap_or_default();
    let result = json!({
        "measurement": "M3",
        "threshold": "writes resume within 15 s after the leader is killed at 100 writes/s; no committed write lost",
        "environment": environment(),
        "runs": results,
        "resumed_ms": {
            "min": ms(resumed_all.first().copied().unwrap_or_default()),
            "median": ms(quantile(&resumed_all, 0.5)),
            "max": ms(worst),
        },
        "pass": worst < M3_LIMIT,
    });
    write_result("m3-failover", &result);
    assert!(worst < M3_LIMIT, "the slowest failover took {worst:?}");
}

#[test]
#[ignore = "slow lab measurement, run by bench/phase1-cluster"]
fn m12_forwarded_write_latency() {
    if !measuring("M12") {
        return;
    }
    let lab = ClusterLab::start_with(3, measured());
    let leader = lab.leader();
    let follower = lab.followers()[0];
    let warm = lab.write_load(leader, 100, Duration::from_secs(5));
    let on_leader = lab.write_load(leader, 100, phase(60));
    let on_follower = lab.write_load(follower, 100, phase(60));
    let limit = on_leader.p99() + M12_MARGIN;
    let pass = on_follower.p99() <= limit;
    let result = json!({
        "measurement": "M12",
        "threshold": "follower p99 at most the leader's p99 plus 20 ms at 100 writes/s",
        "environment": environment(),
        "warm_up": warm.summary(),
        "leader": on_leader.summary(),
        "follower": on_follower.summary(),
        "difference_p99_ms": ms(on_follower.p99()) - ms(on_leader.p99()),
        "pass": pass,
    });
    println!("M12: {result}");
    // The threshold is a proposal (slice 3 plan, section 5): the verdict is recorded, the
    // run does not fail on it.
    write_result("m12-forwarded-writes", &result);
}

/// Waits until the leader reports `member` with no lag; the time it took.
fn caught_up(lab: &ClusterLab, leader: u64, member: u64, since: Instant) -> Duration {
    lab.wait_until(
        "the new controller to catch up",
        Duration::from_secs(600),
        || {
            let view = lab.members(leader)?;
            let entry = view["members"]
                .as_array()?
                .iter()
                .find(|entry| entry["node"].as_u64() == Some(member))?
                .clone();
            (entry["lag_entries"].as_u64() == Some(0)).then(|| since.elapsed())
        },
    )
}

#[test]
#[ignore = "slow lab measurement, run by bench/phase1-cluster"]
fn m4_steady_writes_and_the_catch_up_of_an_empty_controller() {
    if !measuring("M4") {
        return;
    }
    // Snapshots by log size, as Spike A's catch-up: the empty controller receives a
    // snapshot and the few entries after it, not the whole log of the steady phase.
    let mut lab = ClusterLab::start_with(
        3,
        LabOptions {
            config: "[store]\nsnapshot_every_entries = 1000\nsnapshot_every_log_mib = 2\n\
                     snapshot_keep_entries = 100\n"
                .to_owned(),
            spare: Some(1),
            ..measured()
        },
    );
    let leader = lab.leader();
    // A rate this machine keeps up with first, then the threshold's rate.
    let moderate: LoadReport = lab.write_load(leader, 300, phase(60));
    println!("M4 at 300/s: {}", moderate.summary());
    lab.digests_agree(moderate.committed_revision());
    let steady: LoadReport = lab.write_load(leader, 1000, phase(60));
    println!("M4 at 1,000/s: {}", steady.summary());

    // An overloaded cluster may lose its leader; how long until it is whole again.
    let stopped = Instant::now();
    let recovered = wait_whole(&lab, Duration::from_secs(300)).then(|| stopped.elapsed());
    let sustained = steady.committed_rate();
    let mut result = json!({
        "measurement": "M4 (one host)",
        "threshold": "1,000 updates/s with p99 below 250 ms; 6 M RRset catch-up below 5 min on 1 Gbit (three VMs, WP3.8)",
        "stand_in": "one host, loopback; IPAM address writes through the API instead of the Spike A RRset workload; the catch-up of an empty fourth controller (a snapshot and the entries after it) after the steady phase instead of 6 M RRsets",
        "environment": environment(),
        "moderate": moderate.summary(),
        "steady": steady.summary(),
        "sustained_per_second": sustained,
        "recovered_seconds": recovered.map(|after| after.as_secs_f64()),
        "catch_up": Value::Null,
        "pass_latency": steady.p99() < M4_P99,
        "pass_rate": sustained >= 990.0,
    });
    // Written now as well: a catch-up that fails leaves the steady figures behind.
    write_result("m4-one-host", &result);
    if recovered.is_some() {
        let leader = lab.leader();
        lab.digests_agree(steady.committed_revision());
        let size = lab.store_size(leader);
        let begun = Instant::now();
        let new = lab.add_controller();
        let join = lab.last_join_time().expect("a join");
        let complete = caught_up(&lab, leader, new, begun);
        result["catch_up"] = json!({
            "join_seconds": join.as_secs_f64(),
            "caught_up_seconds": complete.as_secs_f64(),
            "member": new,
            "leader_store": { "state": size.state, "log": size.log, "snapshots": size.snapshots },
            "learner_snapshot_bytes": lab.store_size(new).snapshots,
        });
    }
    println!("M4: {result}");
    write_result("m4-one-host", &result);
}

/// Waits up to `limit` until every running controller is healthy under one leader; false
/// when the cluster did not get there.
fn wait_whole(lab: &ClusterLab, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some((leader, _)) = lab.current_leader() {
            let whole = lab.ids().into_iter().all(|id| {
                lab.members(id).is_some_and(|view| {
                    view["leader"].as_u64() == Some(leader) && view["quorum"]["state"] == "healthy"
                })
            });
            if whole {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
    false
}

#[test]
#[ignore = "slow lab measurement, run by bench/phase1-cluster"]
fn m1_reads_on_a_follower_during_a_snapshot_install() {
    if !measuring("M1") {
        return;
    }
    // Small snapshot intervals, so the joining learner needs a snapshot, not the log.
    let mut lab = ClusterLab::start_with(
        3,
        LabOptions {
            config: "[store]\nsnapshot_every_entries = 500\nsnapshot_keep_entries = 100\n"
                .to_owned(),
            spare: Some(1),
            ..measured()
        },
    );
    let leader = lab.leader();
    let follower = lab.followers()[0];
    let preload = lab.write_load(leader, 200, phase(30));
    lab.digests_agree(preload.committed_revision());

    let reads = lab.start_reads(follower, READ_RATE, "/addresses?limit=20");
    thread::sleep(phase(20));
    let join_start = Instant::now();
    let new = lab.add_controller();
    let join = lab.last_join_time().expect("a join");
    let installed = Instant::now();
    let complete = caught_up(&lab, leader, new, join_start);
    thread::sleep(Duration::from_secs(5));
    let report: ReadReport = reads.stop();
    let baseline = report.window(report.started, join_start);
    let during = report.window(join_start, installed);
    let snapshot = lab.store_size(new);
    #[allow(clippy::cast_precision_loss, reason = "durations in milliseconds")]
    let ratio = ms(during.p99()) / ms(baseline.p99()).max(0.001);
    let pass = ratio < 2.0 && during.bad() == 0 && baseline.bad() == 0;
    let result = json!({
        "measurement": "M1 (one host)",
        "threshold": "no empty reads; read p99 below 2x the baseline during the snapshot install",
        "stand_in": "one host; IPAM list reads on a follower while a learner installs a snapshot through the real transport, instead of the 6 M RRset test index",
        "environment": environment(),
        "preload": preload.summary(),
        "baseline": baseline.summary(),
        "during_install": during.summary(),
        "ratio_p99": ratio,
        "join_seconds": join.as_secs_f64(),
        "caught_up_seconds": complete.as_secs_f64(),
        "learner_snapshot_bytes": snapshot.snapshots,
        "learner_state_bytes": snapshot.state,
        "pass": pass,
    });
    println!("M1: {result}");
    write_result("m1-snapshot-install", &result);
}

/// A number of a result as text with up to `decimals` decimals (`-` when absent).
fn num(value: &Value, decimals: usize) -> String {
    value
        .as_f64()
        .map_or_else(|| "-".to_owned(), |number| format!("{number:.decimals$}"))
}

/// The table row of a load summary.
fn load_row(label: &str, load: &Value) -> String {
    format!(
        "| {label} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
        num(&load["writes"], 0),
        num(&load["committed"], 0),
        num(&load["committed_per_second"], 1),
        num(&load["p50_ms"], 1),
        num(&load["p99_ms"], 1),
        num(&load["max_ms"], 1),
        num(&load["longest_stall_ms"], 0),
        num(&load["refused"], 0),
    )
}

const LOAD_HEADER: &str = "| Load | Writes | Committed | Committed/s | p50 (ms) | p99 (ms) | Max (ms) | Longest stall (ms) | Refused |\n|---|---|---|---|---|---|---|---|---|\n";

/// The Markdown tables of every result in the directory of `TENKO_LAB_RESULTS`.
#[allow(clippy::too_many_lines, reason = "one table per measurement")]
fn summary(dir: &std::path::Path) -> String {
    let read = |name: &str| -> Option<Value> {
        let text = std::fs::read(dir.join(format!("{name}.json"))).ok()?;
        serde_json::from_slice(&text).ok()
    };
    let mut text = String::new();
    if let Some(m3) = read("m3-failover") {
        let runs = m3["runs"].as_array().cloned().unwrap_or_default();
        let _ = write!(
            text,
            "### M3 failover: {} runs of kill -9 of the leader at 100 writes/s\n\n",
            runs.len()
        );
        text.push_str("| Run | Killed | New leader | Elected (ms) | Writes resumed (ms) | Writes | Refused | Unanswered | p99 (ms) | Digests agree at |\n|---|---|---|---|---|---|---|---|---|---|\n");
        for run in &runs {
            let _ = writeln!(
                text,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                run["run"],
                run["killed"],
                run["new_leader"],
                num(&run["elected_ms"], 0),
                num(&run["resumed_ms"], 0),
                num(&run["load"]["writes"], 0),
                num(&run["load"]["refused"], 0),
                num(&run["load"]["unanswered"], 0),
                num(&run["load"]["p99_ms"], 0),
                run["digest_revision"],
            );
        }
        let _ = write!(
            text,
            "\nWrites resumed after min {} ms, median {} ms, max {} ms (threshold 15,000 ms): {}.\n\n",
            num(&m3["resumed_ms"]["min"], 0),
            num(&m3["resumed_ms"]["median"], 0),
            num(&m3["resumed_ms"]["max"], 0),
            if m3["pass"] == true { "PASS" } else { "FAIL" }
        );
    }
    if let Some(m12) = read("m12-forwarded-writes") {
        text.push_str("### M12 forwarded write latency at 100 writes/s\n\n");
        text.push_str(LOAD_HEADER);
        text.push_str(&load_row("leader", &m12["leader"]));
        text.push_str(&load_row("follower", &m12["follower"]));
        let _ = write!(
            text,
            "\nFollower p99 minus leader p99: {} ms (threshold +20 ms): {}.\n\n",
            num(&m12["difference_p99_ms"], 1),
            if m12["pass"] == true { "PASS" } else { "FAIL" }
        );
    }
    if let Some(m4) = read("m4-one-host") {
        text.push_str(
            "### M4 on one host: 1,000 writes/s on the leader, then an empty fourth controller\n\n",
        );
        text.push_str(LOAD_HEADER);
        text.push_str(&load_row("leader, 300/s", &m4["moderate"]));
        text.push_str(&load_row("leader, 1,000/s", &m4["steady"]));
        let _ = write!(
            text,
            "\nAt 1,000 writes/s: {} committed writes/s; p99 below 250 ms: {}. ",
            num(&m4["sustained_per_second"], 1),
            if m4["pass_latency"] == true {
                "yes"
            } else {
                "no"
            },
        );
        match m4["recovered_seconds"].as_f64() {
            Some(after) => {
                let _ = write!(
                    text,
                    "The cluster was whole again {after:.1} s after the load. Leader store: state {} bytes, log {} bytes. The empty fourth controller joined in {} s (`tenko cluster join`, the copy of the data) and had no lag {} s after the join began.\n\n",
                    m4["catch_up"]["leader_store"]["state"],
                    m4["catch_up"]["leader_store"]["log"],
                    num(&m4["catch_up"]["join_seconds"], 1),
                    num(&m4["catch_up"]["caught_up_seconds"], 1),
                );
            }
            None => text.push_str(
                "The cluster was not whole again within 300 s after the load, so the catch-up was not measured.\n\n",
            ),
        }
    }
    if let Some(m1) = read("m1-snapshot-install") {
        text.push_str("### M1 on one host: reads on a follower during the snapshot install of a joining learner\n\n");
        text.push_str("| Phase | Reads | Bad or empty | p50 (ms) | p99 (ms) | Max (ms) |\n|---|---|---|---|---|---|\n");
        for (label, key) in [
            ("baseline", "baseline"),
            ("during the install", "during_install"),
        ] {
            let phase = &m1[key];
            let _ = writeln!(
                text,
                "| {label} | {} | {} | {} | {} | {} |",
                num(&phase["reads"], 0),
                num(&phase["bad"], 0),
                num(&phase["p50_ms"], 1),
                num(&phase["p99_ms"], 1),
                num(&phase["max_ms"], 1),
            );
        }
        let _ = write!(
            text,
            "\np99 during the install / baseline: {} (threshold below 2): {}. The learner's join took {} s; its snapshot directory holds {} bytes.\n\n",
            num(&m1["ratio_p99"], 2),
            if m1["pass"] == true { "PASS" } else { "FAIL" },
            num(&m1["join_seconds"], 1),
            m1["learner_snapshot_bytes"],
        );
    }
    if let Some(m6) = read("m6-rejoin") {
        text.push_str("### M6 disk growth after a rejoin with an empty data directory\n\n");
        text.push_str("| File | Bytes |\n|---|---|\n");
        let _ = write!(
            text,
            "| raw: the leader's state file after the churn | {} |\n| the member's state file before | {} |\n| the rejoined member's state file at rest | {} |\n",
            m6["raw_state_bytes"], m6["member_before"]["state"], m6["rejoined_after"]["state"],
        );
        let _ = write!(
            text,
            "\nRatio {} (threshold below 2): {}.\n\n",
            num(&m6["ratio"], 3),
            if m6["pass"] == true { "PASS" } else { "FAIL" }
        );
    }
    text
}

#[test]
#[ignore = "run by bench/phase1-cluster after the measurements"]
fn summary_of_the_results() {
    let Some(dir) = std::env::var_os(RESULTS_ENV) else {
        println!("skipped: set {RESULTS_ENV} to the directory of the results");
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let text = summary(&dir);
    std::fs::write(dir.join("summary.md"), &text).expect("write summary.md");
    println!("{text}");
}
