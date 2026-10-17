//! The TSIG key operations through the router, over the zone service on an in-memory store
//! and vault.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tenko_api::state::AppState;
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{MemStore, Store};
use tower::ServiceExt;

const API: &str = "/api/v1";
const PROBLEM_JSON: &str = "application/problem+json";

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Reply {
    #[track_caller]
    fn assert_problem(&self, status: u16, code: &str) {
        assert_eq!(self.status.as_u16(), status, "{}", self.body);
        assert_eq!(
            self.headers
                .get(header::CONTENT_TYPE)
                .map(axum::http::HeaderValue::as_bytes),
            Some(PROBLEM_JSON.as_bytes())
        );
        assert_eq!(self.body["code"], code, "{}", self.body);
    }
}

fn app() -> Router {
    let store = Arc::new(MemStore::default());
    let vault = Arc::new(tenko_vault::MemVault::with_store(Arc::clone(&store)));
    let service = ZoneService::with_direct_jobs(
        Arc::clone(&store) as Arc<dyn Store>,
        Some(vault as Arc<dyn tenko_vault::Vault>),
        ZoneConfig::default(),
    );
    let (router, _) = tenko_api::api(AppState::default());
    router.layer(axum::Extension(service))
}

async fn send(router: &Router, method: &str, path: &str, body: Option<Value>) -> Reply {
    send_with(router, method, path, body, &[]).await
}

async fn send_with(
    router: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    extra: &[(&str, &str)],
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{API}{path}"));
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("request");
    let response = router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("JSON")
    };
    Reply {
        status,
        headers,
        body,
    }
}

#[tokio::test]
async fn a_key_is_generated_with_a_secret_of_the_hash_length() {
    let router = app();
    let created = send(
        &router,
        "POST",
        "/dns/keys",
        Some(json!({"name": "transfer-key"})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["key"]["name"], "transfer-key");
    assert_eq!(created.body["key"]["algorithm"], "hmac-sha256");
    // 32 octets in base64 with padding: 44 characters.
    let secret = created.body["secret"].as_str().expect("secret");
    assert_eq!(secret.len(), 44, "{secret}");
    assert!(secret.ends_with('='));

    let other = send(
        &router,
        "POST",
        "/dns/keys",
        Some(json!({"name": "other-key"})),
    )
    .await;
    assert_ne!(other.body["secret"], created.body["secret"]);
}

#[tokio::test]
async fn an_imported_key_echoes_its_secret() {
    let router = app();
    let secret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ=";
    let created = send(
        &router,
        "POST",
        "/dns/keys",
        Some(json!({"name": "imported", "secret": secret, "description": "from a peer"})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["secret"], secret);
    assert_eq!(created.body["key"]["description"], "from a peer");
}

#[tokio::test]
async fn a_duplicate_or_malformed_key_is_refused() {
    let router = app();
    send(
        &router,
        "POST",
        "/dns/keys",
        Some(json!({"name": "transfer-key"})),
    )
    .await;
    let again = send(
        &router,
        "POST",
        "/dns/keys",
        Some(json!({"name": "transfer-key"})),
    )
    .await;
    again.assert_problem(409, "dns.key.exists");

    let short = send(
        &router,
        "POST",
        "/dns/keys",
        Some(json!({"name": "short", "secret": "AAAA"})),
    )
    .await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST, "{}", short.body);
    let not_base64 = send(
        &router,
        "POST",
        "/dns/keys",
        Some(json!({"name": "garbled", "secret": "!!! not base64 !!!"})),
    )
    .await;
    assert_eq!(
        not_base64.status,
        StatusCode::BAD_REQUEST,
        "{}",
        not_base64.body
    );
    let body = send(&router, "POST", "/dns/keys", Some(json!({"name": 3}))).await;
    assert_eq!(body.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_key_is_read_without_its_secret_and_listed_by_name() {
    let router = app();
    for name in ["b-key", "a-key", "c-key"] {
        send(&router, "POST", "/dns/keys", Some(json!({"name": name}))).await;
    }
    let got = send(&router, "GET", "/dns/keys/a-key", None).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.body);
    assert_eq!(got.body["name"], "a-key");
    assert!(got.body.get("secret").is_none(), "{}", got.body);

    let list = send(&router, "GET", "/dns/keys", None).await;
    assert_eq!(list.status, StatusCode::OK);
    let items = list.body["items"].as_array().expect("items");
    let names: Vec<&str> = items
        .iter()
        .map(|item| item["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["a-key", "b-key", "c-key"]);
    assert!(items.iter().all(|item| item.get("secret").is_none()));

    let first = send(&router, "GET", "/dns/keys?limit=2", None).await;
    assert_eq!(first.body["items"].as_array().expect("items").len(), 2);
    let cursor = first.body["next_cursor"].as_str().expect("cursor");
    let rest = send(
        &router,
        "GET",
        &format!("/dns/keys?limit=2&cursor={cursor}"),
        None,
    )
    .await;
    assert_eq!(rest.body["items"][0]["name"], "c-key");
    assert!(rest.body["next_cursor"].is_null());
}

#[tokio::test]
async fn a_deleted_key_is_gone() {
    let router = app();
    send(
        &router,
        "POST",
        "/dns/keys",
        Some(json!({"name": "transfer-key"})),
    )
    .await;
    let deleted = send(&router, "DELETE", "/dns/keys/transfer-key", None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    send(&router, "GET", "/dns/keys/transfer-key", None)
        .await
        .assert_problem(404, "dns.key.not_found");
    send(&router, "DELETE", "/dns/keys/transfer-key", None)
        .await
        .assert_problem(404, "dns.key.not_found");
    let list = send(&router, "GET", "/dns/keys", None).await;
    assert_eq!(list.body["items"], json!([]));
}

#[tokio::test]
async fn a_malformed_key_name_or_a_missing_service_is_refused() {
    let router = app();
    send(&router, "GET", "/dns/keys/not%20a%20name", None)
        .await
        .assert_problem(400, "sys.invalid_request");
    let (bare, _) = tenko_api::api(AppState::default());
    send(&bare, "GET", "/dns/keys", None)
        .await
        .assert_problem(409, "dns.module.disabled");
    send(&bare, "POST", "/dns/keys", Some(json!({"name": "k"})))
        .await
        .assert_problem(409, "dns.module.disabled");
}
