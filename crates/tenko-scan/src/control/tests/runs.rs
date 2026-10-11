//! Scans from dispatch to diff, with the probes played by the tests.

use std::collections::BTreeSet;

use tenko_cluster::node_sync::{
    commands::{CommandState, SCAN_CANCEL, SCAN_RUN},
    payload::{CancelArgs, ScanRunArgs, decode_args},
};
use tenko_core::{NodeId, observe::ProbeMethod};
use tenko_jobs::JobState;
use tenko_store::ReadViewExt;
use uuid::Uuid;

use super::support::{Rig, hours_ago, request};
use crate::control::model::{FactChange, ScanKind, ScanState, tables::BASELINES};

fn run_args(record: &tenko_cluster::node_sync::commands::CommandRecord) -> ScanRunArgs {
    decode_args(&record.encoding, &record.payload.0).expect("scan.run arguments")
}

#[tokio::test]
async fn the_dispatch_issues_one_command_per_probe_and_network_part() {
    let mut rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/25", "192.0.2.128/25"], &[])
        .await;
    rig.probe(1002, &["192.0.2.0/24"], &["192.0.2.0/26"]).await;
    rig.probe(1003, &["198.51.100.0/24"], &[]).await;
    rig.run_jobs();

    let submitted = rig
        .scan_network("192.0.2.0/24", &[ScanKind::PortScan])
        .await;
    let view = rig.dispatched(submitted.id).await;
    assert_eq!(view.state, ScanState::Running);

    let mut parts: Vec<(u64, String)> = view
        .probes
        .iter()
        .map(|probe| (probe.node.0, probe.target.clone()))
        .collect();
    parts.sort();
    assert_eq!(
        parts,
        vec![
            (1001, "192.0.2.0/25".to_owned()),
            (1001, "192.0.2.128/25".to_owned()),
            (1002, "192.0.2.0/24".to_owned()),
        ]
    );
    assert_eq!(rig.commands(1003).await.len(), 0, "no scope, no command");

    let issued = rig.commands(1001).await;
    assert_eq!(issued.len(), 2);
    for record in issued.iter().chain(&rig.commands(1002).await) {
        assert_eq!(record.kind, SCAN_RUN);
        assert_eq!(record.state, CommandState::Pending);
        assert_eq!(record.run, Some(view.id));
        assert_eq!(record.expires_at, Some(view.deadline));
        assert!(record.issued_by.is_some());
        let args = run_args(record);
        assert_eq!(args.methods, vec!["tcp_connect".to_owned()]);
        assert!(!args.ignore_blackout);
        assert!(args.deadline_secs.is_some_and(|secs| secs > 0));
        let part = view
            .probes
            .iter()
            .find(|probe| probe.command == record.id)
            .expect("the part of the command");
        assert_eq!(args.target.as_deref(), Some(part.target.as_str()));
    }
}

#[tokio::test]
async fn a_single_address_goes_to_the_probe_without_its_prefix_length() {
    let mut rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    rig.run_jobs();
    let view = rig
        .scan_network("192.0.2.10/32", &[ScanKind::PassiveRefresh])
        .await;
    let view = rig.dispatched(view.id).await;
    let record = &rig.commands(1001).await[0];
    assert_eq!(run_args(record).target.as_deref(), Some("192.0.2.10"));
    assert_eq!(view.probes[0].target, "192.0.2.10");
    assert_eq!(
        run_args(record).methods,
        ["arp", "nd", "mdns", "llmnr", "reverse_dns"]
    );
}

#[tokio::test]
async fn the_baseline_holds_the_facts_of_the_probes_and_methods_of_the_run() {
    let mut rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    rig.probe(1002, &["198.51.100.0/24"], &[]).await;
    rig.seed_services(1001, ProbeMethod::TcpConnect, "192.0.2.10", vec![22], false)
        .await;
    rig.seed_services(1001, ProbeMethod::TcpConnect, "192.0.2.11", vec![80], true)
        .await;
    // Another method, another probe and another network are not part of the baseline.
    rig.seed_services(1001, ProbeMethod::Arp, "192.0.2.12", vec![22], false)
        .await;
    rig.seed_services(1002, ProbeMethod::TcpConnect, "192.0.2.13", vec![22], false)
        .await;
    rig.seed_services(
        1001,
        ProbeMethod::TcpConnect,
        "203.0.113.5",
        vec![22],
        false,
    )
    .await;
    rig.run_jobs();

    let view = rig
        .scan_network("192.0.2.0/24", &[ScanKind::PortScan])
        .await;
    rig.dispatched(view.id).await;
    let (baseline, _) = rig
        .view()
        .await
        .get_typed(&BASELINES, &view.id)
        .expect("read")
        .expect("baseline");
    let facts: BTreeSet<(String, bool)> = baseline
        .facts
        .iter()
        .map(|fact| (fact.subject.clone(), fact.current))
        .collect();
    assert_eq!(
        facts,
        BTreeSet::from([
            ("services:192.0.2.10".to_owned(), true),
            ("services:192.0.2.11".to_owned(), false),
        ])
    );
    assert!(
        baseline
            .facts
            .iter()
            .all(|fact| fact.source == "probe:1001:tcp_connect")
    );
    assert!(!baseline.truncated);
}

#[tokio::test]
async fn progress_follows_the_reports_of_the_probes() {
    let mut rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/25"], &[]).await;
    rig.probe(1002, &["192.0.2.128/25"], &[]).await;
    rig.run_jobs();
    let view = rig
        .scan_network("192.0.2.0/24", &[ScanKind::PortScan])
        .await;
    let view = rig.dispatched(view.id).await;
    assert_eq!(view.progress, 0);
    let first = rig.commands(1001).await[0].id;
    let second = rig.commands(1002).await[0].id;

    rig.report(1001, first, CommandState::Accepted, 0, None)
        .await;
    rig.report(1001, first, CommandState::Running, 40, None)
        .await;
    let view = rig.control.scan(view.id).await.expect("run");
    assert_eq!(view.progress, 20, "the mean of 40 and 0");
    let part = view
        .probes
        .iter()
        .find(|probe| probe.node == NodeId(1001))
        .expect("part");
    assert_eq!((part.state.as_str(), part.progress), ("running", 40));
    let other = view
        .probes
        .iter()
        .find(|probe| probe.node == NodeId(1002))
        .expect("part");
    assert_eq!((other.state.as_str(), other.progress), ("pending", 0));
    assert_eq!(view.state, ScanState::Running);

    rig.report(1002, second, CommandState::Running, 100, None)
        .await;
    let view = rig.control.scan(view.id).await.expect("run");
    assert_eq!(view.progress, 70);
    assert!(view.diff.is_none());
}

#[tokio::test]
async fn the_run_waits_for_every_result_a_probe_announced() {
    let mut rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    rig.run_jobs();
    let view = rig
        .scan_network("192.0.2.0/24", &[ScanKind::PortScan])
        .await;
    let view = rig.dispatched(view.id).await;
    let command = rig.commands(1001).await[0].id;

    rig.ingest(1001, command, 1, &rig.services(&[("192.0.2.10", &[22])]))
        .await;
    rig.report(1001, command, CommandState::Done, 100, Some(2))
        .await;
    let waiting = rig.control.scan(view.id).await.expect("run");
    assert_eq!(waiting.probes[0].state, "done");
    assert_eq!(
        (waiting.probes[0].batches, waiting.probes[0].ingested),
        (Some(2), 1)
    );
    assert_eq!(
        waiting.state,
        ScanState::Running,
        "one batch is still on its way"
    );
    assert!(waiting.finished_at.is_none());

    rig.ingest(1001, command, 2, &rig.services(&[("192.0.2.11", &[80])]))
        .await;
    let done = rig
        .wait_run(view.id, |view| view.finished_at.is_some())
        .await;
    assert_eq!(done.state, ScanState::Done);
    assert_eq!(done.progress, 100);
    assert_eq!(done.diff.expect("diff").counts["services"].new, 2);
}

#[tokio::test]
async fn the_diff_tells_new_changed_unchanged_and_gone_facts_apart() {
    let mut rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    rig.probe(1002, &["198.51.100.0/24"], &[]).await;
    rig.seed_services(1001, ProbeMethod::TcpConnect, "192.0.2.11", vec![80], false)
        .await;
    rig.seed_services(1001, ProbeMethod::TcpConnect, "192.0.2.12", vec![22], false)
        .await;
    rig.seed_services(
        1001,
        ProbeMethod::TcpConnect,
        "192.0.2.13",
        vec![445],
        false,
    )
    .await;
    rig.seed_services(1001, ProbeMethod::TcpConnect, "192.0.2.14", vec![445], true)
        .await;
    rig.seed_services(1001, ProbeMethod::Arp, "192.0.2.15", vec![22], false)
        .await;
    rig.run_jobs();

    let view = rig
        .scan_network("192.0.2.0/24", &[ScanKind::PortScan])
        .await;
    let view = rig.dispatched(view.id).await;
    let command = rig.commands(1001).await[0].id;
    rig.report(1001, command, CommandState::Running, 50, None)
        .await;
    let batch = rig.services(&[
        ("192.0.2.10", &[22, 443]),
        ("192.0.2.11", &[80]),
        ("192.0.2.12", &[22, 3389]),
    ]);
    rig.ingest(1001, command, 1, &batch).await;
    rig.report(1001, command, CommandState::Done, 100, Some(1))
        .await;

    let done = rig
        .wait_run(view.id, |view| view.finished_at.is_some())
        .await;
    assert_eq!(done.state, ScanState::Done);
    let diff = done.diff.expect("diff");
    let counts = diff.counts["services"];
    assert_eq!(
        (counts.new, counts.changed, counts.unchanged, counts.gone),
        (1, 1, 1, 1)
    );
    assert_eq!(diff.counts.len(), 1);
    assert!(!diff.truncated);
    let change = |what: FactChange| -> Vec<&str> {
        diff.items
            .iter()
            .filter(|item| item.change == what)
            .map(|item| item.subject.as_str())
            .collect()
    };
    assert_eq!(change(FactChange::New), ["services:192.0.2.10"]);
    assert_eq!(change(FactChange::Changed), ["services:192.0.2.12"]);
    assert_eq!(
        change(FactChange::Gone),
        ["services:192.0.2.13"],
        "an expired fact and one of another method are not reported gone"
    );
    let changed = diff
        .items
        .iter()
        .find(|item| item.change == FactChange::Changed)
        .expect("changed");
    assert!(changed.before.is_some() && changed.after.is_some());

    // The listing carries the counts only.
    let (listed, more) = rig.control.scans(10, None).await.expect("scans");
    assert!(!more);
    assert_eq!(
        listed[0].diff.as_ref().expect("diff").counts["services"].new,
        1
    );
    assert_eq!(listed[0].diff.as_ref().expect("diff").items.len(), 0);
}

#[tokio::test]
async fn a_probe_that_did_not_finish_says_nothing_about_absence() {
    let mut rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    rig.seed_services(
        1001,
        ProbeMethod::TcpConnect,
        "192.0.2.13",
        vec![445],
        false,
    )
    .await;
    rig.run_jobs();
    let view = rig
        .scan_network("192.0.2.0/24", &[ScanKind::PortScan])
        .await;
    let view = rig.dispatched(view.id).await;
    let command = rig.commands(1001).await[0].id;
    rig.report(1001, command, CommandState::Failed, 30, None)
        .await;

    let done = rig
        .wait_run(view.id, |view| view.finished_at.is_some())
        .await;
    assert_eq!(done.state, ScanState::Partial);
    assert_eq!(done.probes[0].state, "failed");
    assert_eq!(done.diff.expect("diff").counts.len(), 0, "{:?}", done.error);
}

#[tokio::test]
async fn the_deadline_ends_the_run_with_the_silent_probe_timed_out() {
    let mut rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/25"], &[]).await;
    rig.probe(1002, &["192.0.2.128/25"], &[]).await;
    rig.seed_services(
        1001,
        ProbeMethod::TcpConnect,
        "192.0.2.13",
        vec![445],
        false,
    )
    .await;
    rig.seed_services(
        1002,
        ProbeMethod::TcpConnect,
        "192.0.2.130",
        vec![445],
        false,
    )
    .await;
    rig.run_jobs();

    // The steps read the wall clock, not the engine's: a request an hour old has a
    // deadline that has passed by the time the dispatch is done.
    let mut asked = request("192.0.2.0/24", &[ScanKind::PortScan]);
    asked.deadline_secs = Some(30);
    let cx = rig.t.ctx().at(hours_ago(1));
    let view = rig.control.submit(&cx, asked).await.expect("submitted");
    let done = rig
        .wait_run(view.id, |view| view.finished_at.is_some())
        .await;

    assert_eq!(done.state, ScanState::Partial);
    assert_eq!(done.progress, 100);
    for probe in &done.probes {
        assert_eq!(probe.state, "expired", "{probe:?}");
    }
    let diff = done.diff.expect("diff");
    assert_eq!(
        diff.counts.len(),
        0,
        "nothing is gone when no probe finished"
    );
    let job = rig
        .t
        .wait_for_state(done.job_id.expect("job"), JobState::Succeeded)
        .await;
    assert_eq!(job.state, JobState::Succeeded);
}

/// Three probes with a scan dispatched to them: one running, one pending, one done.
struct Cancelled {
    rig: Rig,
    run: Uuid,
    job: tenko_core::JobId,
    running: Uuid,
    pending: Uuid,
    finished: Uuid,
}

async fn scan_with_three_probes() -> Cancelled {
    let mut rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/26"], &[]).await;
    rig.probe(1002, &["192.0.2.64/26"], &[]).await;
    rig.probe(1003, &["192.0.2.128/26"], &[]).await;
    rig.run_jobs();
    let view = rig
        .scan_network("192.0.2.0/24", &[ScanKind::PortScan])
        .await;
    let view = rig.dispatched(view.id).await;
    let running = rig.commands(1001).await[0].id;
    let pending = rig.commands(1002).await[0].id;
    let finished = rig.commands(1003).await[0].id;
    rig.report(1001, running, CommandState::Running, 10, None)
        .await;
    rig.report(1003, finished, CommandState::Done, 100, Some(0))
        .await;
    Cancelled {
        job: view.job_id.expect("job"),
        run: view.id,
        rig,
        running,
        pending,
        finished,
    }
}

async fn assert_cancelled(scan: &Cancelled) {
    let rig = &scan.rig;
    let ended = rig
        .wait_run(scan.run, |view| view.finished_at.is_some())
        .await;
    assert_eq!(ended.state, ScanState::Cancelled);
    assert!(ended.diff.is_none());
    let state_of = |command: Uuid| {
        ended
            .probes
            .iter()
            .find(|probe| probe.command == command)
            .map(|probe| probe.state.clone())
            .expect("part")
    };
    assert_eq!(state_of(scan.running), "cancelled");
    assert_eq!(state_of(scan.pending), "cancelled");
    assert_eq!(
        state_of(scan.finished),
        "done",
        "a final command stays as it ended"
    );

    let cancels = rig.commands_of(1001, SCAN_CANCEL).await;
    assert_eq!(
        cancels.len(),
        1,
        "the probe that works on it is asked to stop"
    );
    let args: CancelArgs =
        decode_args(&cancels[0].encoding, &cancels[0].payload.0).expect("arguments");
    assert_eq!(args.command, scan.running);
    assert_eq!(cancels[0].run, Some(scan.run));
    assert_eq!(
        rig.commands_of(1002, SCAN_CANCEL).await.len(),
        0,
        "never sent"
    );
    assert_eq!(
        rig.commands_of(1003, SCAN_CANCEL).await.len(),
        0,
        "already over"
    );
}

#[tokio::test]
async fn cancelling_the_job_while_it_waits_for_the_probes_takes_effect_at_once() {
    let scan = scan_with_three_probes().await;
    let rig = &scan.rig;
    rig.t
        .engine
        .cancel(scan.job, &rig.cx())
        .await
        .expect("cancelled");
    assert_cancelled(&scan).await;
    rig.t.wait_for_state(scan.job, JobState::Cancelled).await;
}
