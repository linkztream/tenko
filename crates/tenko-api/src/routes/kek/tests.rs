//! Route tests of the key-encryption key area over a real `KekAdmin` on a `MemStore`, with
//! the authentication service of the secrets tests: the status, the authorization by role,
//! the step-up of a rotation, the conflict of a second request and the stub answers.

use std::{path::PathBuf, sync::Arc, time::Duration};

use axum::{Extension, body::Body, http::Request};
use serde_json::{Value, json};
use tenko_auth::settings::Profile;
use tenko_core::{NodeId, Timestamp};
use tenko_store::{MemStore, Store};
use tenko_vault::{
    KekConfig, KekOptions, KekProtection, KekRing, MemKek, StoreVault, VaultStart,
    distribution::{KekAdmin, NoPeers},
    kek::DpapiScope,
    kek_state::{RotationPhase, RotationRecord},
};
use tower::ServiceExt as _;

use super::{
    KekProtectionView, KekRotationPhase, KekRotationView, KekStatusView, KekSummaryView, summary_of,
};
use crate::routes::{
    auth::testkit::Credential,
    secrets::tests::{Harness, USER_PIN},
};

/// The KEK service of controller 1 over its own `MemStore`: one in-memory generation
/// `mem-1`, a `file` provider whose key file is never read, and no peers.
async fn kek_admin() -> Arc<KekAdmin> {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let ring = KekRing::new(Arc::new(MemKek::generate("mem-1")));
    let start = VaultStart {
        node: NodeId(1),
        provider: "file".to_owned(),
    };
    let vault = StoreVault::start(store, ring, &start)
        .await
        .expect("the vault starts");
    KekAdmin::new(
        Arc::new(vault),
        KekConfig::File {
            path: PathBuf::from("unused.example.test.key"),
            retired: Vec::new(),
        },
        KekOptions::default(),
        NodeId(1),
        Arc::new(NoPeers),
    )
}

/// The API over the authentication service, with an administrator signed in with a passkey,
/// and the KEK service.
async fn harness() -> Harness {
    let mut harness = Harness::new(Profile::Home).await;
    harness.router = harness.router.clone().layer(Extension(kek_admin().await));
    harness
}

/// A viewer's session.
async fn viewer(h: &Harness) -> String {
    h.create_user("vera", &["viewer"]).await;
    h.login("vera", USER_PIN).await
}

fn warning_codes(body: &Value) -> Vec<&str> {
    body["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .map(|warning| warning["code"].as_str().expect("a code"))
        .collect()
}

#[tokio::test]
async fn an_administrator_reads_the_status() {
    let h = harness().await;
    let reply = h
        .call("GET", "/system/kek", Credential::Cookie(&h.admin), None)
        .await;
    reply.assert_status(200);
    let body = &reply.body;
    assert_eq!(body["node"], 1);
    assert_eq!(body["provider"], "file");
    assert_eq!(body["active"], "mem-1");
    assert_eq!(body["protection"]["code"], "memory");
    assert_eq!(body["protection"]["weak"], true);
    assert_ne!(body["protection"]["text"].as_str().expect("a text"), "");
    assert_eq!(warning_codes(body), ["vault.kek.weak"]);
    assert_eq!(body["warnings"][0]["params"]["protection"], "memory");
    assert_eq!(body["missing"], json!([]));
    assert_eq!(body["refused"], json!([]));
    assert!(body.get("rotation").is_none(), "{body}");
    let generation = &body["generations"][0];
    assert_eq!(generation["id"], "mem-1");
    assert_eq!(generation["active"], true);
    assert_eq!(generation["loaded"], true);
    assert_eq!(generation["protection"]["code"], "memory");
    let controller = &body["controllers"][0];
    assert_eq!(controller["node"], 1);
    assert_eq!(controller["provider"], "file");
    assert_eq!(controller["protection"]["code"], "memory");
    assert_eq!(body["strongest"]["code"], "memory");
    let status: KekStatusView = reply.parse();
    assert_eq!(status.generations.len(), 1);
    assert_eq!(status.controllers.len(), 1);
    assert!(status.rotation.is_none());
}

#[tokio::test]
async fn a_viewer_reads_the_status_but_cannot_rotate() {
    let h = harness().await;
    let viewer = viewer(&h).await;
    h.call("GET", "/system/kek", Credential::Cookie(&viewer), None)
        .await
        .assert_status(200);
    h.call(
        "POST",
        "/system/kek/rotate",
        Credential::Cookie(&viewer),
        None,
    )
    .await
    .assert_problem(403, "auth.forbidden");
    let status = h
        .call("GET", "/system/kek", Credential::Cookie(&h.admin), None)
        .await;
    assert!(status.body.get("rotation").is_none(), "{}", status.body);
}

#[tokio::test]
async fn anonymous_requests_are_refused() {
    let h = harness().await;
    h.call("GET", "/system/kek", Credential::Anonymous, None)
        .await
        .assert_problem(401, "auth.unauthenticated");
    h.call("POST", "/system/kek/rotate", Credential::Anonymous, None)
        .await
        .assert_problem(401, "auth.unauthenticated");
}

#[tokio::test]
async fn without_the_service_both_endpoints_answer_not_implemented() {
    let h = Harness::new(Profile::Home).await;
    let admin = Credential::Cookie(&h.admin);
    for (method, path) in [("GET", "/system/kek"), ("POST", "/system/kek/rotate")] {
        let reply = h.call(method, path, admin, None).await;
        reply.assert_problem(501, "sys.not_implemented");
        assert_eq!(
            reply.body["params"]["path"],
            format!("/api/v1{path}"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn without_the_authentication_service_a_rotation_is_not_implemented() {
    let router = crate::router().layer(Extension(kek_admin().await));
    let get = Request::get("/api/v1/system/kek")
        .body(Body::empty())
        .expect("request");
    let response = router.clone().oneshot(get).await.expect("response");
    assert_eq!(response.status(), 200);
    let post = Request::post("/api/v1/system/kek/rotate")
        .body(Body::empty())
        .expect("request");
    let response = router.oneshot(post).await.expect("response");
    assert_eq!(response.status(), 501);
}

#[tokio::test]
async fn a_fresh_administrator_requests_a_rotation_and_a_second_request_conflicts() {
    let h = harness().await;
    let admin = Credential::Cookie(&h.admin);
    let started = h.call("POST", "/system/kek/rotate", admin, None).await;
    started.assert_status(202);
    let rotation = &started.body["rotation"];
    assert_eq!(rotation["phase"], "requested");
    assert!(
        rotation["requested_by"]
            .as_str()
            .expect("a subject")
            .starts_with("user:"),
        "{rotation}"
    );
    assert_eq!(rotation["waiting_for"], json!([]));
    assert_eq!(rotation["unreachable"], json!([]));
    assert_eq!(rotation["rewrapped"], 0);
    assert!(rotation.get("generation").is_none(), "{rotation}");
    assert!(rotation.get("error").is_none(), "{rotation}");
    assert!(rotation.get("distributing_since").is_none(), "{rotation}");
    let status: KekStatusView = started.parse();
    assert_eq!(
        status.rotation.map(|rotation| rotation.phase),
        Some(KekRotationPhase::Requested)
    );

    let again = h.call("POST", "/system/kek/rotate", admin, None).await;
    again.assert_problem(409, "vault.kek.rotation_in_progress");

    let read = h.call("GET", "/system/kek", admin, None).await;
    read.assert_status(200);
    assert_eq!(read.body["rotation"]["phase"], "requested");
    assert_eq!(read.body["active"], "mem-1");
}

#[tokio::test]
async fn a_session_older_than_five_minutes_needs_a_step_up() {
    let h = harness().await;
    let stale = h.aged_admin_session(Duration::from_secs(600)).await;
    let refused = h
        .call(
            "POST",
            "/system/kek/rotate",
            Credential::Cookie(&stale),
            None,
        )
        .await;
    refused.assert_problem(403, "auth.step_up_required");
    assert_eq!(refused.body["params"]["required"], "fresh");
    let status = h
        .call("GET", "/system/kek", Credential::Cookie(&stale), None)
        .await;
    status.assert_status(200);
    assert!(status.body.get("rotation").is_none(), "{}", status.body);
    h.call(
        "POST",
        "/system/kek/rotate",
        Credential::Cookie(&h.admin),
        None,
    )
    .await
    .assert_status(202);
}

#[tokio::test]
async fn the_summary_is_empty_before_a_status_and_follows_it_after() {
    let admin = kek_admin().await;
    let (summary, warnings) = summary_of(&admin);
    assert_eq!(summary, None);
    assert_eq!(warnings.len(), 0);

    let status = admin.status().await.expect("a status");
    assert_eq!(status.warnings.len(), 1);
    let (summary, warnings) = summary_of(&admin);
    let summary = summary.expect("a summary after a status");
    assert_eq!(summary.provider, "file");
    assert_eq!(summary.protection.code, "memory");
    assert!(summary.protection.weak);
    assert_eq!(summary.active, "mem-1");
    assert_eq!(summary.generations, 1);
    assert_eq!(summary.epoch, status.epoch);
    assert_eq!(summary.rotation, None);
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].code, "vault.kek.weak");
    assert_eq!(warnings[0].detail, status.warnings[0].detail);
    assert_eq!(warnings[0].params["protection"], "memory");
    let json = serde_json::to_value(&summary).expect("json");
    assert!(json.get("rotation").is_none(), "{json}");
}

#[tokio::test]
async fn the_summary_names_the_phase_of_a_rotation() {
    let admin = kek_admin().await;
    admin.status().await.expect("a status");
    let ctx = tenko_core::RequestCtx::system(tenko_core::SystemComponent::Api);
    admin.request_rotation(&ctx).await.expect("a request");
    let (summary, _) = summary_of(&admin);
    assert_eq!(
        summary.expect("a summary").rotation,
        Some(KekRotationPhase::Requested)
    );
}

#[test]
fn protections_carry_stable_codes_and_the_weak_flag() {
    for (protection, code, weak) in [
        (
            KekProtection::Dpapi {
                scope: DpapiScope::User,
            },
            "dpapi_user",
            false,
        ),
        (
            KekProtection::Dpapi {
                scope: DpapiScope::Machine,
            },
            "dpapi_machine",
            false,
        ),
        (
            KekProtection::SystemdCreds { tpm2: false },
            "systemd_creds_host",
            false,
        ),
        (
            KekProtection::SystemdCreds { tpm2: true },
            "systemd_creds_tpm2",
            false,
        ),
        (KekProtection::PlainFile, "plain_file", true),
        (KekProtection::Memory, "memory", true),
    ] {
        let view = KekProtectionView::from(protection);
        assert_eq!(view.code, code);
        assert_eq!(view.text, protection.describe());
        assert_eq!(view.weak, weak, "{code}");
    }
}

#[test]
fn a_rotation_record_maps_to_its_view_without_the_distribution_start() {
    let at = |text: &str| -> Timestamp { text.parse().expect("a time") };
    let mut record = RotationRecord::requested(at("2026-10-10T10:00:00Z"), "user:1".to_owned());
    record.phase = RotationPhase::Failed;
    record.updated_at = at("2026-10-10T10:03:00Z");
    record.generation = Some("mem-2".to_owned());
    record.distributing_since = Some(at("2026-10-10T10:01:00Z"));
    record.waiting_for = vec![NodeId(2), NodeId(3)];
    record.unreachable = vec![NodeId(4)];
    record.rewrapped = 17;
    record.error = Some("the controllers 2,3 did not take the new key generation".to_owned());
    record.finished_at = Some(at("2026-10-10T10:03:00Z"));

    let view = KekRotationView::from(&record);
    assert_eq!(view.phase, KekRotationPhase::Failed);
    assert_eq!(view.requested_at, record.requested_at);
    assert_eq!(view.requested_by, "user:1");
    assert_eq!(view.updated_at, record.updated_at);
    assert_eq!(view.generation.as_deref(), Some("mem-2"));
    assert_eq!(view.waiting_for, [2, 3]);
    assert_eq!(view.unreachable, [4]);
    assert_eq!(view.rewrapped, 17);
    assert_eq!(view.error, record.error);
    assert_eq!(view.finished_at, record.finished_at);
    let json = serde_json::to_value(&view).expect("json");
    assert_eq!(json["phase"], "failed");
    assert!(json.get("distributing_since").is_none(), "{json}");
    let back: KekRotationView = serde_json::from_value(json).expect("a view");
    assert_eq!(back, view);
}

#[test]
fn every_phase_has_its_snake_case_name() {
    for (phase, name) in [
        (RotationPhase::Requested, "requested"),
        (RotationPhase::Distributing, "distributing"),
        (RotationPhase::Rewrapping, "rewrapping"),
        (RotationPhase::Done, "done"),
        (RotationPhase::Failed, "failed"),
    ] {
        assert_eq!(phase.as_str(), name);
        let view = KekRotationPhase::from(phase);
        assert_eq!(serde_json::to_value(view).expect("json"), name);
    }
}

#[test]
fn the_summary_view_round_trips() {
    let view = KekSummaryView {
        provider: "dpapi".to_owned(),
        protection: KekProtectionView::from(KekProtection::Dpapi {
            scope: DpapiScope::Machine,
        }),
        active: "dpapi-2-b".to_owned(),
        generations: 2,
        epoch: 3,
        rotation: Some(KekRotationPhase::Done),
    };
    let json = serde_json::to_value(&view).expect("json");
    assert_eq!(json["rotation"], "done");
    let back: KekSummaryView = serde_json::from_value(json).expect("a view");
    assert_eq!(back, view);
}

#[test]
fn both_operations_are_documented() {
    let document = crate::openapi();
    let status = document
        .paths
        .paths
        .get("/api/v1/system/kek")
        .and_then(|item| item.get.as_ref())
        .expect("GET /system/kek");
    assert_eq!(status.operation_id.as_deref(), Some("get_kek_status"));
    let rotate = document
        .paths
        .paths
        .get("/api/v1/system/kek/rotate")
        .and_then(|item| item.post.as_ref())
        .expect("POST /system/kek/rotate");
    assert_eq!(rotate.operation_id.as_deref(), Some("rotate_kek"));
    for code in ["202", "401", "403", "409", "501", "503"] {
        assert!(rotate.responses.responses.contains_key(code), "{code}");
    }
    let schemas = &document.components.as_ref().expect("components").schemas;
    for name in [
        "KekStatusView",
        "KekRotationView",
        "KekRotationPhase",
        "KekProtectionView",
        "KekGenerationView",
        "RefusedGenerationView",
        "ControllerKekView",
    ] {
        assert!(schemas.contains_key(name), "{name}");
    }
}
