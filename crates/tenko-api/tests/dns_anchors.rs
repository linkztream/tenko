//! The trust anchor and negative trust anchor routes (WP10.2) through the router over the
//! zone service on an in-memory store: the rows, their audit records, the root's
//! protection outside the Lab profile, the expiry the Hardened profile requires, and the
//! presentation forms of the keys.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tenko_api::state::AppState;
use tenko_auth::settings::Profile;
use tenko_core::{RequestCtx, SystemComponent};
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{MemStore, Store, WriteBatch};
use tower::ServiceExt;

const API: &str = "/api/v1";
const ROOT_DS: &str = "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
const DNSKEY: &str = "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=";

struct Reply {
    status: StatusCode,
    body: Value,
}

async fn app(profile: Profile) -> (Router, Arc<MemStore>) {
    let store = Arc::new(MemStore::default());
    let ctx = RequestCtx::system(SystemComponent::Setup);
    let mut batch = WriteBatch::for_request(&ctx);
    batch
        .put_typed(&tenko_auth::model::SETTINGS, &(), &profile.defaults())
        .expect("settings");
    store.propose(batch).await.expect("the profile");
    let vault = Arc::new(tenko_vault::MemVault::with_store(Arc::clone(&store)));
    let service = ZoneService::with_direct_jobs(
        Arc::clone(&store) as Arc<dyn Store>,
        Some(vault as Arc<dyn tenko_vault::Vault>),
        ZoneConfig::default(),
    );
    let (router, _) = tenko_api::api(AppState::default());
    (router.layer(axum::Extension(service)), store)
}

async fn send(router: &Router, method: &str, path: &str, body: Option<Value>) -> Reply {
    let builder = Request::builder()
        .method(method)
        .uri(format!("{API}{path}"));
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("request");
    let response = router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("JSON")
    };
    Reply { status, body }
}

async fn items(router: &Router, path: &str) -> Vec<Value> {
    let list = send(router, "GET", path, None).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    list.body["items"].as_array().expect("items").clone()
}

#[tokio::test]
async fn an_operator_anchor_is_added_read_listed_refreshed_and_removed() {
    let (router, _) = app(Profile::Standard).await;
    assert_eq!(
        items(&router, "/dns/trust-anchors").await,
        Vec::<Value>::new()
    );
    let created = send(
        &router,
        "POST",
        "/dns/trust-anchors",
        Some(json!({"zone": "corp.example.test", "dnskey": DNSKEY})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["zone"], "corp.example.test");
    let keys = created.body["keys"].as_array().expect("keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["key_tag"], 3613);
    assert_eq!(keys[0]["algorithm"], 15);
    assert_eq!(keys[0]["state"], "valid");
    assert_eq!(keys[0]["source"]["kind"], "operator");
    assert_eq!(keys[0]["data"]["kind"], "dnskey");
    assert!(created.body["next_query"].is_string(), "{}", created.body);
    // A second key as a DS joins the row; the same key twice is refused.
    let again = send(
        &router,
        "POST",
        "/dns/trust-anchors",
        Some(json!({"zone": "corp.example.test", "ds": "3613 15 2 3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b"})),
    )
    .await;
    assert_eq!(again.status, StatusCode::CREATED, "{}", again.body);
    assert_eq!(again.body["keys"].as_array().expect("keys").len(), 2);
    let twice = send(
        &router,
        "POST",
        "/dns/trust-anchors",
        Some(json!({"zone": "corp.example.test", "dnskey": DNSKEY})),
    )
    .await;
    assert_eq!(twice.status, StatusCode::BAD_REQUEST, "{}", twice.body);
    assert_eq!(twice.body["code"], "dns.trust_anchor.invalid");
    // Read and list.
    let got = send(&router, "GET", "/dns/trust-anchors/corp.example.test", None).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.body);
    assert_eq!(got.body["keys"].as_array().expect("keys").len(), 2);
    assert_eq!(items(&router, "/dns/trust-anchors").await.len(), 1);
    let missing = send(&router, "GET", "/dns/trust-anchors/other.test", None).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.body["code"], "dns.trust_anchor.not_found");
    // Refresh is accepted and recorded.
    let refresh = send(
        &router,
        "POST",
        "/dns/trust-anchors/corp.example.test/refresh",
        None,
    )
    .await;
    assert_eq!(refresh.status, StatusCode::ACCEPTED, "{}", refresh.body);
    assert!(refresh.body["command_id"].is_string());
    // Removed.
    let removed = send(
        &router,
        "DELETE",
        "/dns/trust-anchors/corp.example.test",
        None,
    )
    .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{}", removed.body);
    assert_eq!(
        items(&router, "/dns/trust-anchors").await,
        Vec::<Value>::new()
    );
    let gone = send(
        &router,
        "DELETE",
        "/dns/trust-anchors/corp.example.test",
        None,
    )
    .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_root_is_protected_outside_the_lab_profile() {
    let (router, _) = app(Profile::Standard).await;
    for body in [
        json!({"zone": ".", "ds": ROOT_DS}),
        json!({"zone": ".", "ds": ROOT_DS, "replace_root": true}),
    ] {
        let reply = send(&router, "POST", "/dns/trust-anchors", Some(body)).await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
        assert_eq!(reply.body["code"], "dns.trust_anchor.root_protected");
    }
    let removed = send(&router, "DELETE", "/dns/trust-anchors/root", None).await;
    assert_eq!(removed.status, StatusCode::CONFLICT, "{}", removed.body);
    // replace_root applies to the root only, and a key needs exactly one form.
    let elsewhere = send(
        &router,
        "POST",
        "/dns/trust-anchors",
        Some(json!({"zone": "example.test", "ds": ROOT_DS, "replace_root": true})),
    )
    .await;
    assert_eq!(
        elsewhere.status,
        StatusCode::BAD_REQUEST,
        "{}",
        elsewhere.body
    );
    let both = send(
        &router,
        "POST",
        "/dns/trust-anchors",
        Some(json!({"zone": "example.test", "ds": ROOT_DS, "dnskey": DNSKEY})),
    )
    .await;
    assert_eq!(both.status, StatusCode::BAD_REQUEST, "{}", both.body);
    let bad = send(
        &router,
        "POST",
        "/dns/trust-anchors",
        Some(json!({"zone": "example.test", "ds": "20326 8 2 zz"})),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.body);
    assert_eq!(bad.body["code"], "dns.trust_anchor.invalid");
}

#[tokio::test]
async fn the_lab_profile_replaces_the_root_anchor() {
    let (router, _) = app(Profile::Lab).await;
    let replaced = send(
        &router,
        "POST",
        "/dns/trust-anchors",
        Some(json!({"zone": ".", "ds": ROOT_DS, "replace_root": true})),
    )
    .await;
    assert_eq!(replaced.status, StatusCode::CREATED, "{}", replaced.body);
    assert_eq!(replaced.body["zone"], ".");
    let keys = replaced.body["keys"].as_array().expect("keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["key_tag"], 20326);
    assert_eq!(keys[0]["digest_type"], 2);
    // The root reads under the path spelling `root`.
    let got = send(&router, "GET", "/dns/trust-anchors/root", None).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.body);
    assert_eq!(got.body["zone"], ".");
    // Replaced again: one key, not two.
    let again = send(
        &router,
        "POST",
        "/dns/trust-anchors",
        Some(json!({"zone": ".", "dnskey": DNSKEY, "replace_root": true})),
    )
    .await;
    assert_eq!(again.status, StatusCode::CREATED, "{}", again.body);
    assert_eq!(again.body["keys"].as_array().expect("keys").len(), 1);
    let removed = send(&router, "DELETE", "/dns/trust-anchors/root", None).await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{}", removed.body);
}

#[tokio::test]
async fn negative_trust_anchors_live_at_most_seven_days() {
    let (router, _) = app(Profile::Standard).await;
    let created = send(
        &router,
        "POST",
        "/dns/ntas",
        Some(json!({"zone": "broken.example.test", "reason": "the signer expired its keys"})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["zone"], "broken.example.test");
    assert!(created.body["expires_at"].is_string());
    let id = created.body["id"].as_str().expect("id").to_owned();
    let listed = items(&router, "/dns/ntas").await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"], id);
    for (body, field) in [
        (json!({"zone": ".", "reason": "x"}), "zone"),
        (json!({"zone": "a.test", "reason": ""}), "reason"),
        (
            json!({"zone": "a.test", "reason": "x", "expires_at": "2099-01-01T00:00:00Z"}),
            "expires_at",
        ),
        (
            json!({"zone": "a.test", "reason": "x", "expires_at": "2000-01-01T00:00:00Z"}),
            "expires_at",
        ),
    ] {
        let reply = send(&router, "POST", "/dns/ntas", Some(body)).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{field}: {}",
            reply.body
        );
        assert_eq!(reply.body["code"], "dns.nta.invalid", "{}", reply.body);
    }
    let deleted = send(&router, "DELETE", &format!("/dns/ntas/{id}"), None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.body);
    assert_eq!(items(&router, "/dns/ntas").await, Vec::<Value>::new());
    let gone = send(&router, "DELETE", &format!("/dns/ntas/{id}"), None).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    assert_eq!(gone.body["code"], "dns.nta.not_found");
}

#[tokio::test]
async fn the_hardened_profile_requires_an_expiry() {
    let (router, _) = app(Profile::Hardened).await;
    let without = send(
        &router,
        "POST",
        "/dns/ntas",
        Some(json!({"zone": "broken.example.test", "reason": "x"})),
    )
    .await;
    assert_eq!(without.status, StatusCode::BAD_REQUEST, "{}", without.body);
    assert_eq!(without.body["code"], "dns.nta.invalid");
    assert_eq!(without.body["params"]["field"], "expires_at");
    let soon = tenko_core::Timestamp::now()
        .checked_add(std::time::Duration::from_secs(3600))
        .expect("time")
        .to_rfc3339();
    let with = send(
        &router,
        "POST",
        "/dns/ntas",
        Some(json!({"zone": "broken.example.test", "reason": "x", "expires_at": soon})),
    )
    .await;
    assert_eq!(with.status, StatusCode::CREATED, "{}", with.body);
}
