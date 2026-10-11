//! Edits of a probe's configuration through the control.

use serde_json::json;
use tenko_cluster::node_sync::secrets::SecretUse;
use tenko_core::{NodeId, Revision, Role};
use tenko_store::ReadViewExt;

use super::support::{LOCAL, Rig, refused};
use crate::{
    config::{SNMP_SECRET_PURPOSE, ScanConfig},
    control::{
        actions, codes,
        model::{ProbeConfigOrigin, tables::PROBE_CONFIG},
    },
};

fn config(value: serde_json::Value) -> ScanConfig {
    serde_json::from_value(value).expect("a scan configuration")
}

fn with_inline_password() -> ScanConfig {
    config(json!({ "snmp": { "enabled": true, "devices": [{
        "address": "192.0.2.2", "user": "monitor", "auth": "sha256",
        "auth_password": "correct horse battery"
    }] } }))
}

#[tokio::test]
async fn inline_passwords_are_refused_without_being_repeated() {
    let rig = Rig::with_local(Some(LOCAL));
    let error = rig
        .control
        .put_config(&rig.cx(), NodeId(LOCAL), with_inline_password(), None)
        .await
        .expect_err("inline password");
    assert_eq!(refused(&error), (codes::CONFIG_INVALID, 422));
    assert!(!format!("{error:?}").contains("correct horse"), "{error:?}");
    let stored = rig.control.config(NodeId(LOCAL)).await.expect("config");
    assert!(!stored.stored);
    assert_eq!(rig.audit_of(actions::CONFIG_UPDATE.as_str()).await.len(), 0);
}

#[tokio::test]
async fn secrets_by_purpose_snmp_are_accepted_and_recorded() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let secret = rig.operator_secret().await;
    let named = config(
        json!({ "prefixes": ["192.0.2.0/24"], "snmp": { "enabled": true,
        "devices": [
            { "address": "192.0.2.2", "user": "monitor", "auth": "sha256",
              "auth_secret": secret.secret.to_string() },
            { "address": "192.0.2.3", "user": "monitor", "auth": "sha256" }
        ] } }),
    );

    let view = rig
        .control
        .put_config(&rig.cx(), NodeId(1001), named, None)
        .await
        .expect("stored");
    assert!(view.stored);
    assert_eq!(view.origin, Some(ProbeConfigOrigin::Api));
    assert_eq!(view.lacking_secrets, vec!["192.0.2.3".to_owned()]);
    assert!(!view.in_sync, "the probe has not applied it yet");

    let (record, _) = rig
        .view()
        .await
        .get_typed(&PROBE_CONFIG, &1001)
        .expect("read")
        .expect("record");
    assert_eq!(
        record.secrets,
        vec![SecretUse {
            purpose: SNMP_SECRET_PURPOSE.to_owned(),
            secret: secret.secret,
        }]
    );
    assert_eq!(record.updated_by, rig.cx().principal.user());
}

#[tokio::test]
async fn secrets_that_do_not_exist_are_refused() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let unknown = config(json!({ "snmp": { "enabled": true, "devices": [{
        "address": "192.0.2.2", "user": "monitor", "auth": "sha256",
        "auth_secret": uuid::Uuid::now_v7().to_string()
    }] } }));
    let error = rig
        .control
        .put_config(&rig.cx(), NodeId(1001), unknown, None)
        .await
        .expect_err("unknown secret");
    assert_eq!(refused(&error), (codes::CONFIG_SECRET, 422));
}

#[tokio::test]
async fn secrets_need_a_vault() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let secret = rig.operator_secret().await;
    let engine = tenko_jobs::testing::TestEngine::new();
    let control = crate::control::ScanControl::new(
        std::sync::Arc::clone(&rig.store),
        &engine.engine,
        None,
        None,
    );
    let named = config(json!({ "snmp": { "enabled": true, "devices": [{
        "address": "192.0.2.2", "user": "monitor", "auth": "sha256",
        "auth_secret": secret.secret.to_string()
    }] } }));
    let error = control
        .put_config(&rig.cx(), NodeId(1001), named, None)
        .await
        .expect_err("no vault");
    assert_eq!(refused(&error), (codes::VAULT_UNAVAILABLE, 503));
}

#[tokio::test]
async fn an_invalid_configuration_names_the_key() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let bad = ScanConfig {
        prefixes: vec!["192.0.2.0/33".to_owned()],
        ..ScanConfig::default()
    };
    let error = rig
        .control
        .put_config(&rig.cx(), NodeId(1001), bad, None)
        .await
        .expect_err("prefix");
    assert_eq!(refused(&error), (codes::CONFIG_INVALID, 422));
    assert!(error.detail.contains("prefixes"), "{}", error.detail);
}

#[tokio::test]
async fn every_edit_writes_an_audit_record_and_a_stale_one_does_not() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let first = rig
        .control
        .put_config(
            &rig.cx(),
            NodeId(1001),
            ScanConfig {
                prefixes: vec!["192.0.2.0/24".to_owned(), "198.51.100.0/24".to_owned()],
                ..ScanConfig::default()
            },
            None,
        )
        .await
        .expect("first");
    let revision = first.revision.expect("revision");
    let second = rig
        .control
        .put_config(
            &rig.cx(),
            NodeId(1001),
            ScanConfig {
                prefixes: vec!["203.0.113.0/24".to_owned()],
                ..ScanConfig::default()
            },
            Some(Revision(revision)),
        )
        .await
        .expect("second");
    assert!(second.revision.expect("revision") > revision);

    let stale = rig
        .control
        .put_config(
            &rig.cx(),
            NodeId(1001),
            ScanConfig::default(),
            Some(Revision(revision)),
        )
        .await
        .expect_err("stale");
    assert_eq!(refused(&stale), (codes::CONFIG_STALE, 412));
    // A creation that expects a revision of an existing row is stale, too.
    rig.probe(1002, &["198.51.100.0/24"], &[]).await;
    let missing = rig
        .control
        .put_config(
            &rig.cx(),
            NodeId(1002),
            ScanConfig::default(),
            Some(Revision(revision)),
        )
        .await
        .expect_err("nothing to match");
    assert_eq!(missing.code, codes::CONFIG_STALE);

    let audit = rig.audit_of(actions::CONFIG_UPDATE.as_str()).await;
    assert_eq!(audit.len(), 2);
    assert_eq!(
        audit[0].draft.details.context["prefixes"],
        "192.0.2.0/24,198.51.100.0/24"
    );
    assert_eq!(audit[1].draft.details.context["prefixes"], "203.0.113.0/24");
    assert_eq!(audit[1].draft.details.context["secrets"], "0");
    assert_eq!(audit[1].draft.objects.len(), 1);
    assert_eq!(audit[1].principal, rig.cx().principal);
}

#[tokio::test]
async fn unknown_nodes_and_nodes_without_the_probe_role_have_no_configuration() {
    let rig = Rig::new();
    rig.enrol(1002, &[Role::Dns]).await;
    let error = rig.control.config(NodeId(77)).await.expect_err("unknown");
    assert_eq!(refused(&error), (codes::NODE_NOT_FOUND, 404));
    let error = rig.control.config(NodeId(1002)).await.expect_err("dns");
    assert_eq!(refused(&error), (codes::NOT_A_PROBE, 409));
    let error = rig
        .control
        .put_config(&rig.cx(), NodeId(1002), ScanConfig::default(), None)
        .await
        .expect_err("dns");
    assert_eq!(error.code, codes::NOT_A_PROBE);
}
