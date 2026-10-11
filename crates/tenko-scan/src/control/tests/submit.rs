//! Submitting scans: which probes cover a target, and what is refused.

use tenko_core::{HostId, PrefixId, Role};

use super::support::{Rig, refused, request};
use crate::{
    config::ScanConfig,
    control::{
        actions, codes,
        model::{ScanKind, ScanState, ScanTarget},
    },
};

#[tokio::test]
async fn a_submitted_scan_names_the_networks_and_is_audited() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let view = rig
        .scan_network("192.0.2.0/24", &[ScanKind::PortScan, ScanKind::PortScan])
        .await;
    assert_eq!(view.state, ScanState::Queued);
    assert_eq!(view.networks, vec!["192.0.2.0/24".parse().expect("net")]);
    assert_eq!(
        view.kinds,
        vec![ScanKind::PortScan],
        "kinds are deduplicated"
    );
    assert!(view.job_id.is_some());
    assert_eq!(
        view.probes.len(),
        0,
        "nothing is dispatched before the job runs"
    );
    assert!(view.deadline > view.created_at);

    let audit = rig.audit_of(actions::RUN.as_str()).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].draft.details.context["run"], view.id.to_string());
    assert_eq!(audit[0].draft.details.context["kinds"], "port_scan");
}

#[tokio::test]
async fn a_scan_without_kinds_refreshes_the_passive_methods() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let view = rig.scan_network("192.0.2.0/25", &[]).await;
    assert_eq!(view.kinds, vec![ScanKind::PassiveRefresh]);
}

#[tokio::test]
async fn a_target_no_probe_covers_is_refused() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &["192.0.2.64/26"]).await;
    rig.enrol(1002, &[Role::Dns]).await;
    for network in ["203.0.113.0/24", "192.0.2.64/26", "192.0.2.77/32"] {
        let error = rig
            .control
            .submit(&rig.cx(), request(network, &[]))
            .await
            .expect_err(network);
        assert_eq!(error.code, codes::JOB_NO_PROBE, "{network}");
        assert_eq!(error.status, 422);
    }
    let scans = rig.control.scans(10, None).await.expect("scans");
    assert_eq!(scans.0.len(), 0, "a refused scan leaves no run behind");
    assert_eq!(rig.audit_of(actions::RUN.as_str()).await.len(), 0);
}

#[tokio::test]
async fn a_node_without_the_probe_role_does_not_cover_anything() {
    let rig = Rig::new();
    rig.enrol(1002, &[Role::Dns]).await;
    rig.report_scope(1002, &["192.0.2.0/24"], &[], false).await;
    let error = rig
        .control
        .submit(&rig.cx(), request("192.0.2.0/24", &[]))
        .await
        .expect_err("no probe");
    assert_eq!(error.code, codes::JOB_NO_PROBE);
}

#[tokio::test]
async fn the_stored_configuration_decides_which_scope_a_probe_covers() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let config = ScanConfig {
        prefixes: vec!["198.51.100.0/24".to_owned()],
        ..ScanConfig::default()
    };
    rig.control
        .put_config(&rig.cx(), tenko_core::NodeId(1001), config.clone(), None)
        .await
        .expect("stored");
    let error = rig
        .control
        .submit(&rig.cx(), request("192.0.2.0/24", &[]))
        .await
        .expect_err("the stored scope wins over the reported one");
    assert_eq!(error.code, codes::JOB_NO_PROBE);
    rig.scan_network("198.51.100.0/25", &[]).await;

    let off = ScanConfig {
        enabled: false,
        ..config
    };
    rig.control
        .put_config(&rig.cx(), tenko_core::NodeId(1001), off, None)
        .await
        .expect("stored");
    let error = rig
        .control
        .submit(&rig.cx(), request("198.51.100.0/25", &[]))
        .await
        .expect_err("a switched-off scanner covers nothing");
    assert_eq!(error.code, codes::JOB_NO_PROBE);
}

#[tokio::test]
async fn a_deadline_out_of_range_is_refused() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    for secs in [0, 29, 3601] {
        let mut asked = request("192.0.2.0/24", &[]);
        asked.deadline_secs = Some(secs);
        let error = rig
            .control
            .submit(&rig.cx(), asked)
            .await
            .expect_err("range");
        assert_eq!(error.code, codes::JOB_INVALID, "{secs}");
    }
    for secs in [30, 3600] {
        let mut asked = request("192.0.2.0/24", &[]);
        asked.deadline_secs = Some(secs);
        rig.control
            .submit(&rig.cx(), asked)
            .await
            .expect("in range");
    }
}

#[tokio::test]
async fn targets_that_do_not_exist_or_do_not_parse_are_refused() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let mut asked = request("192.0.2.0/24", &[]);
    for target in [
        ScanTarget::prefix(PrefixId::generate()),
        ScanTarget::host(HostId::generate()),
    ] {
        asked.target = target;
        let error = rig
            .control
            .submit(&rig.cx(), asked.clone())
            .await
            .expect_err("unknown");
        assert_eq!(refused(&error), (codes::JOB_TARGET, 404));
    }
    asked.target = request("not a network", &[]).target;
    let error = rig
        .control
        .submit(&rig.cx(), asked)
        .await
        .expect_err("text");
    assert_eq!(refused(&error), (codes::JOB_TARGET, 422));
}

#[tokio::test]
async fn an_unknown_run_is_not_found() {
    let rig = Rig::new();
    let error = rig
        .control
        .scan(uuid::Uuid::now_v7())
        .await
        .expect_err("unknown");
    assert_eq!(refused(&error), (codes::JOB_NOT_FOUND, 404));
}
