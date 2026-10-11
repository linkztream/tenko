//! A probe's offer of its own configuration, over the node sync and in process.

use std::sync::Arc;

use serde_json::json;
use tenko_cluster::node_sync::{NodeSync, OfferHandler, codes as sync_codes, payload};
use tenko_core::{NodeId, Principal, Role, SystemComponent, codec::to_cbor};
use tenko_store::ReadViewExt;

use super::support::{LOCAL, Rig, refused};
use crate::{
    config::ScanConfig,
    control::{
        actions, codes, decode_offer,
        model::{ProbeConfigOrigin, ProbeConfigRecord, tables::PROBE_CONFIG},
    },
};

fn config(value: serde_json::Value) -> ScanConfig {
    serde_json::from_value(value).expect("a scan configuration")
}

fn encoded(config: &ScanConfig) -> Vec<u8> {
    to_cbor(config).expect("cbor").to_vec()
}

fn offered() -> ScanConfig {
    config(json!({ "prefixes": ["192.0.2.0/24"], "exclude": ["192.0.2.1/32"], "active": false }))
}

/// The handler of the control, as the node sync finds it.
fn handler(rig: &Rig) -> Arc<dyn OfferHandler> {
    let sync = NodeSync::new(Arc::clone(&rig.store));
    assert!(sync.offer_handler("scan.probe_config").is_none());
    rig.control.take_offers(&sync);
    sync.offer_handler("scan.probe_config").expect("registered")
}

async fn stored(rig: &Rig, node: u64) -> Option<ProbeConfigRecord> {
    rig.view()
        .await
        .get_typed(&PROBE_CONFIG, &node)
        .expect("read")
        .map(|(record, _)| record)
}

#[tokio::test]
async fn a_valid_offer_becomes_the_initial_configuration() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let handler = handler(&rig);
    let node = rig.node(1001).await;

    let kept = handler
        .offer(&node, payload::CBOR, &encoded(&offered()))
        .await
        .expect("offer");
    assert!(kept);

    let record = stored(&rig, 1001).await.expect("stored");
    assert_eq!(record.origin, ProbeConfigOrigin::Offer);
    assert_eq!(record.config, offered());
    assert_eq!(record.updated_by, None);
    let view = rig.control.config(NodeId(1001)).await.expect("config");
    assert_eq!(view.origin, Some(ProbeConfigOrigin::Offer));

    let audit = rig.audit_of(actions::CONFIG_OFFER.as_str()).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].principal, Principal::Node { id: NodeId(1001) });
    assert_eq!(audit[0].draft.details.context["node"], node.name);
    assert_eq!(audit[0].draft.details.context["prefixes"], "192.0.2.0/24");
}

#[tokio::test]
async fn a_second_offer_changes_nothing() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let handler = handler(&rig);
    let node = rig.node(1001).await;
    assert!(
        handler
            .offer(&node, payload::CBOR, &encoded(&offered()))
            .await
            .expect("first")
    );
    let before = stored(&rig, 1001).await.expect("stored");

    let other = config(json!({ "prefixes": ["198.51.100.0/24"] }));
    let again = handler
        .offer(&node, payload::CBOR, &encoded(&other))
        .await
        .expect("second");
    assert!(!again);
    assert_eq!(stored(&rig, 1001).await.expect("stored"), before);
    assert_eq!(rig.audit_of(actions::CONFIG_OFFER.as_str()).await.len(), 1);
}

#[tokio::test]
async fn an_offer_does_not_replace_a_configuration_set_through_the_api() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let handler = handler(&rig);
    rig.control
        .put_config(
            &rig.cx(),
            NodeId(1001),
            config(json!({ "prefixes": ["203.0.113.0/24"] })),
            None,
        )
        .await
        .expect("stored");
    let node = rig.node(1001).await;
    assert!(
        !handler
            .offer(&node, payload::CBOR, &encoded(&offered()))
            .await
            .expect("offer")
    );
    let record = stored(&rig, 1001).await.expect("stored");
    assert_eq!(record.origin, ProbeConfigOrigin::Api);
    assert_eq!(record.config.prefixes, vec!["203.0.113.0/24".to_owned()]);
}

#[tokio::test]
async fn an_offer_with_an_inline_password_is_refused() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let handler = handler(&rig);
    let node = rig.node(1001).await;
    let inline = config(json!({ "snmp": { "enabled": true, "devices": [{
        "address": "192.0.2.2", "user": "monitor", "auth": "sha256",
        "auth_password": "correct horse battery"
    }] } }));

    let error = handler
        .offer(&node, payload::CBOR, &encoded(&inline))
        .await
        .expect_err("refused");
    assert_eq!(
        (error.code(), error.status()),
        (sync_codes::CONFIG_INVALID, 422)
    );
    assert!(!format!("{error:?}").contains("correct horse"));
    assert!(stored(&rig, 1001).await.is_none());
    assert_eq!(rig.audit_of(actions::CONFIG_OFFER.as_str()).await.len(), 0);
}

#[tokio::test]
async fn an_offer_that_does_not_decode_is_refused_with_its_code() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let handler = handler(&rig);
    let node = rig.node(1001).await;
    let bytes = encoded(&offered());

    let error = handler
        .offer(&node, "json/1", &bytes)
        .await
        .expect_err("encoding");
    assert_eq!(
        (error.code(), error.status()),
        (sync_codes::CONFIG_ENCODING, 400)
    );
    let error = handler
        .offer(&node, payload::CBOR, &[0xff, 0x00])
        .await
        .expect_err("bytes");
    assert_eq!(
        (error.code(), error.status()),
        (sync_codes::CONFIG_PAYLOAD, 400)
    );
    let huge = vec![0_u8; payload::MAX_ARGS_BYTES * 16 + 1];
    let error = handler
        .offer(&node, payload::CBOR, &huge)
        .await
        .expect_err("size");
    assert_eq!(error.code(), sync_codes::CONFIG_PAYLOAD);
    let bad = ScanConfig {
        concurrency: 0,
        ..ScanConfig::default()
    };
    let error = decode_offer(payload::CBOR, &encoded(&bad)).expect_err("range");
    assert_eq!(
        (error.code(), error.status()),
        (sync_codes::CONFIG_INVALID, 422)
    );
    assert!(stored(&rig, 1001).await.is_none());
}

#[tokio::test]
async fn an_offer_keeps_no_vault_secret_the_node_could_not_have_been_given() {
    let rig = Rig::new();
    rig.probe(1001, &["192.0.2.0/24"], &[]).await;
    let handler = handler(&rig);
    let node = rig.node(1001).await;
    let named = config(json!({ "snmp": { "enabled": true, "devices": [{
        "address": "192.0.2.2", "user": "monitor", "auth": "sha256",
        "auth_secret": uuid::Uuid::now_v7().to_string()
    }] } }));
    assert!(
        handler
            .offer(&node, payload::CBOR, &encoded(&named))
            .await
            .expect("offer")
    );
    let record = stored(&rig, 1001).await.expect("stored");
    assert_eq!(record.secrets.len(), 0);
    assert!(record.config.snmp.devices[0].auth_secret.is_none());
    let view = rig.control.config(NodeId(1001)).await.expect("config");
    assert_eq!(view.lacking_secrets, vec!["192.0.2.2".to_owned()]);
}

#[tokio::test]
async fn the_local_probe_offers_its_section_once_without_passwords() {
    let rig = Rig::with_local(Some(LOCAL));
    let section = config(
        json!({ "prefixes": ["192.0.2.0/24"], "snmp": { "enabled": true,
        "devices": [{ "address": "192.0.2.2", "user": "monitor", "auth": "sha256",
                      "auth_password": "correct horse battery" }] } }),
    );

    assert!(rig.control.offer_local(&section).await.expect("offered"));
    let record = stored(&rig, LOCAL).await.expect("stored");
    assert_eq!(record.origin, ProbeConfigOrigin::Offer);
    assert!(record.config.snmp.devices[0].auth_password.is_none());
    assert_eq!(record.config.prefixes, vec!["192.0.2.0/24".to_owned()]);
    let view = rig.control.config(NodeId(LOCAL)).await.expect("config");
    assert_eq!(view.lacking_secrets, vec!["192.0.2.2".to_owned()]);

    let audit = rig.audit_of(actions::CONFIG_OFFER.as_str()).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(
        audit[0].principal,
        Principal::System {
            component: SystemComponent::Scan,
            on_behalf_of: None
        }
    );
    assert_eq!(
        audit[0].draft.details.context["node"],
        format!("controller-{LOCAL}")
    );

    let again = config(json!({ "prefixes": ["198.51.100.0/24"] }));
    assert!(!rig.control.offer_local(&again).await.expect("second"));
    assert_eq!(
        stored(&rig, LOCAL).await.expect("stored").config.prefixes,
        vec!["192.0.2.0/24".to_owned()]
    );
}

#[tokio::test]
async fn the_local_offer_is_refused_for_an_invalid_section_and_skipped_without_a_role() {
    let rig = Rig::with_local(Some(LOCAL));
    let bad = ScanConfig {
        prefixes: vec!["192.0.2.0/33".to_owned()],
        ..ScanConfig::default()
    };
    let error = rig.control.offer_local(&bad).await.expect_err("invalid");
    assert_eq!(refused(&error), (codes::CONFIG_INVALID, 422));
    assert!(stored(&rig, LOCAL).await.is_none());

    let rig = Rig::new();
    rig.enrol(1001, &[Role::Probe]).await;
    assert!(!rig.control.offer_local(&offered()).await.expect("no role"));
    assert!(stored(&rig, LOCAL).await.is_none());
}
