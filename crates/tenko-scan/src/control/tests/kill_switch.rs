//! The kill switch: stop and resume commands, their audit records and the view of them.

use tenko_cluster::node_sync::{
    commands::{CommandState, SCAN_RESUME, SCAN_RUN, SCAN_STOP},
    payload::{StopArgs, decode_args},
};
use tenko_core::{NodeId, Role};

use super::support::{LOCAL, Rig, refused};
use crate::control::{
    MAX_REASON_CHARS, actions, codes,
    model::{KillSwitchView, ProbeSummary, ScanKind, ScanState},
};

async fn summary(rig: &Rig, node: u64) -> ProbeSummary {
    rig.control
        .probes()
        .await
        .expect("probes")
        .into_iter()
        .find(|probe| probe.node == NodeId(node))
        .expect("the probe")
}

fn reason_of(record: &tenko_cluster::node_sync::commands::CommandRecord) -> String {
    decode_args::<StopArgs>(&record.encoding, &record.payload.0)
        .expect("stop arguments")
        .reason
}

#[tokio::test]
async fn stopping_one_probe_issues_a_command_and_an_audit_record() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    rig.probe(1002, &["198.51.100.0/24"], &[]).await;
    let cx = rig.cx();

    let result = rig
        .control
        .stop(&cx, Some(NodeId(1001)), Some("  maintenance window  "))
        .await
        .expect("stopped");
    assert_eq!(result.commands.len(), 1);
    assert_eq!(result.commands[0].node, NodeId(1001));

    let issued = rig.commands_of(1001, SCAN_STOP).await;
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0].id, result.commands[0].command);
    assert_eq!(reason_of(&issued[0]), "maintenance window");
    assert_eq!(issued[0].issued_at, cx.now);
    assert_eq!(issued[0].issued_by, cx.principal.user());
    assert_eq!(issued[0].state, CommandState::Pending);
    assert_eq!(rig.commands(1002).await.len(), 0);

    let audit = rig.audit_of(actions::STOP.as_str()).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(
        audit[0].draft.details.context["reason"],
        "maintenance window"
    );
    assert_eq!(audit[0].draft.details.context["scope"], "node");
    assert_eq!(audit[0].draft.objects.len(), 1);
    assert_eq!(audit[0].principal, cx.principal);
}

#[tokio::test]
async fn stopping_every_probe_issues_one_command_each() {
    let rig = Rig::with_local(Some(LOCAL));
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    rig.probe(1002, &["198.51.100.0/24"], &[]).await;
    rig.enrol(1003, &[Role::Dns]).await;

    let result = rig
        .control
        .stop(&rig.cx(), None, None)
        .await
        .expect("stopped");
    let mut nodes: Vec<u64> = result
        .commands
        .iter()
        .map(|command| command.node.0)
        .collect();
    nodes.sort_unstable();
    assert_eq!(nodes, vec![LOCAL, 1001, 1002], "the in-process probe too");
    for node in nodes {
        let issued = rig.commands_of(node, SCAN_STOP).await;
        assert_eq!(issued.len(), 1, "node {node}");
        assert_eq!(reason_of(&issued[0]), "stopped from the controllers");
    }
    assert_eq!(rig.commands(1003).await.len(), 0);
    let audit = rig.audit_of(actions::STOP.as_str()).await;
    assert_eq!(audit.len(), 1, "one record for the whole switch");
    assert_eq!(audit[0].draft.details.context["scope"], "installation");
    assert_eq!(audit[0].draft.objects.len(), 3);
}

#[tokio::test]
async fn stopping_without_probes_issues_nothing() {
    let rig = Rig::new();
    let result = rig
        .control
        .stop(&rig.cx(), None, None)
        .await
        .expect("stopped");
    assert_eq!(result.commands.len(), 0);
    assert_eq!(rig.audit_of(actions::STOP.as_str()).await.len(), 0);
}

#[tokio::test]
async fn a_long_reason_is_cut_and_a_blank_one_gets_the_default() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let long = "x".repeat(MAX_REASON_CHARS + 50);
    rig.control
        .stop(&rig.cx(), Some(NodeId(1001)), Some(&long))
        .await
        .expect("long");
    rig.control
        .stop(&rig.cx(), Some(NodeId(1001)), Some("   "))
        .await
        .expect("blank");
    let issued = rig.commands_of(1001, SCAN_STOP).await;
    assert_eq!(reason_of(&issued[0]).chars().count(), MAX_REASON_CHARS);
    assert_eq!(reason_of(&issued[1]), "stopped from the controllers");
}

#[tokio::test]
async fn only_probes_can_be_stopped_or_resumed() {
    let rig = Rig::new();
    rig.enrol(1002, &[Role::Dns]).await;
    for node in [1002, 77] {
        let (code, status) = if node == 77 {
            (codes::NODE_NOT_FOUND, 404)
        } else {
            (codes::NOT_A_PROBE, 409)
        };
        let error = rig
            .control
            .stop(&rig.cx(), Some(NodeId(node)), None)
            .await
            .expect_err("stop");
        assert_eq!(refused(&error), (code, status));
        let error = rig
            .control
            .resume(&rig.cx(), Some(NodeId(node)))
            .await
            .expect_err("resume");
        assert_eq!(refused(&error), (code, status));
    }
}

#[tokio::test]
async fn the_view_shows_the_switch_until_the_probe_confirms_it() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    rig.probe(1002, &["198.51.100.0/24"], &[]).await;
    let before = summary(&rig, 1001).await.kill_switch;
    assert_eq!(
        before,
        KillSwitchView {
            stopped: false,
            reason: None,
            at: None,
            by: None,
            confirmed: true,
        }
    );

    let cx = rig.cx();
    let result = rig
        .control
        .stop(&cx, Some(NodeId(1001)), Some("incident 4711"))
        .await
        .expect("stopped");
    let waiting = summary(&rig, 1001).await.kill_switch;
    assert_eq!(
        waiting,
        KillSwitchView {
            stopped: true,
            reason: Some("incident 4711".to_owned()),
            at: Some(cx.now),
            by: cx.principal.user(),
            confirmed: false,
        }
    );
    assert!(!summary(&rig, 1002).await.kill_switch.stopped);
    let config = rig.control.config(NodeId(1001)).await.expect("config");
    assert_eq!(config.kill_switch, waiting);

    let command = result.commands[0].command;
    rig.report(1001, command, CommandState::Accepted, 0, None)
        .await;
    assert!(!summary(&rig, 1001).await.kill_switch.confirmed);
    rig.report(1001, command, CommandState::Done, 100, None)
        .await;
    let confirmed = summary(&rig, 1001).await.kill_switch;
    assert!(confirmed.stopped && confirmed.confirmed);
    assert_eq!(confirmed.reason.as_deref(), Some("incident 4711"));
    let config = rig.control.config(NodeId(1001)).await.expect("config");
    assert_eq!(config.kill_switch, confirmed);
}

#[tokio::test]
async fn resuming_clears_the_switch() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let stop = rig
        .control
        .stop(&rig.cx(), Some(NodeId(1001)), Some("incident 4711"))
        .await
        .expect("stopped");
    rig.report(
        1001,
        stop.commands[0].command,
        CommandState::Done,
        100,
        None,
    )
    .await;

    let cx = rig.cx();
    let resume = rig
        .control
        .resume(&cx, Some(NodeId(1001)))
        .await
        .expect("resumed");
    let view = summary(&rig, 1001).await.kill_switch;
    assert_eq!(
        view,
        KillSwitchView {
            stopped: false,
            reason: None,
            at: Some(cx.now),
            by: cx.principal.user(),
            confirmed: false,
        }
    );
    let issued = rig.commands_of(1001, SCAN_RESUME).await;
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0].id, resume.commands[0].command);
    assert_eq!(issued[0].payload.0.len(), 0);
    rig.report(1001, issued[0].id, CommandState::Done, 100, None)
        .await;
    assert!(summary(&rig, 1001).await.kill_switch.confirmed);
    let audit = rig.audit_of(actions::RESUME.as_str()).await;
    assert_eq!(audit.len(), 1);
    assert!(!audit[0].draft.details.context.contains_key("reason"));

    let all = rig.control.resume(&rig.cx(), None).await.expect("all");
    assert_eq!(all.commands.len(), 1);
}

#[tokio::test]
async fn a_probe_that_reports_a_stop_of_its_own_shows_as_stopped() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    rig.report_scope(1001, &["192.0.2.0/24"], &[], true).await;
    let view = summary(&rig, 1001).await.kill_switch;
    assert!(view.stopped && view.confirmed);
    assert_eq!(view.reason.as_deref(), Some("reported by the probe"));
    assert_eq!((view.at, view.by), (None, None));
}

#[tokio::test]
async fn a_scan_submitted_while_a_probe_is_stopped_is_still_dispatched_to_it() {
    let mut rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    rig.run_jobs();
    rig.control
        .stop(&rig.cx(), Some(NodeId(1001)), Some("incident 4711"))
        .await
        .expect("stopped");
    assert!(summary(&rig, 1001).await.kill_switch.stopped);

    // The control does not look at the switch: the probe refuses the command itself.
    let view = rig
        .scan_network("192.0.2.0/24", &[ScanKind::PortScan])
        .await;
    let view = rig.dispatched(view.id).await;
    let run = rig.commands_of(1001, SCAN_RUN).await;
    assert_eq!(run.len(), 1);
    rig.report(1001, run[0].id, CommandState::Rejected, 0, None)
        .await;
    let ended = rig
        .wait_run(view.id, |view| view.finished_at.is_some())
        .await;
    assert_eq!(ended.state, ScanState::Partial);
    assert_eq!(ended.probes[0].state, "rejected");
}
