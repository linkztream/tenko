//! The fields the recursive resolver adds to forwarding rules and views (WP10.0), through the
//! router over the zone service on an in-memory store: the defaults show in the answers, and
//! until WP10.1, WP10.2 and WP10.4 build them the other values answer 501 and write nothing.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
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
    content_type: Option<String>,
    body: Value,
}

impl Reply {
    #[track_caller]
    fn assert_not_implemented(&self, method: &str, path: &str) {
        assert_eq!(self.status, StatusCode::NOT_IMPLEMENTED, "{}", self.body);
        assert_eq!(self.content_type.as_deref(), Some(PROBLEM_JSON));
        assert_eq!(self.body["code"], "sys.not_implemented", "{}", self.body);
        assert_eq!(self.body["params"]["method"], method, "{}", self.body);
        assert_eq!(
            self.body["params"]["path"],
            format!("{API}{path}"),
            "{}",
            self.body
        );
    }
}

fn app() -> Router {
    let store = Arc::new(MemStore::default());
    let vault = Arc::new(tenko_vault::MemVault::with_store(Arc::clone(&store)));
    let service = ZoneService::with_direct_jobs(
        store as Arc<dyn Store>,
        Some(vault as Arc<dyn tenko_vault::Vault>),
        ZoneConfig::default(),
    );
    let (router, _) = tenko_api::api(AppState::default());
    router.layer(axum::Extension(service))
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
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().expect("text").to_owned());
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
        content_type,
        body,
    }
}

async fn items(router: &Router, path: &str) -> Vec<Value> {
    let list = send(router, "GET", path, None).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    list.body["items"].as_array().expect("items").clone()
}

#[tokio::test]
async fn a_rule_created_as_before_shows_the_defaults() {
    let router = app();
    let created = send(
        &router,
        "POST",
        "/dns/forwarders",
        Some(json!({"suffix": "example.net", "upstreams": [{"address": "192.0.2.53"}]})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["mode"], "forward");
    assert_eq!(created.body["validate"], true);

    // The defaults named in the request are the same rule.
    let named = send(
        &router,
        "POST",
        "/dns/forwarders",
        Some(json!({
            "suffix": "example.org",
            "mode": "forward",
            "validate": true,
            "upstreams": [{"address": "192.0.2.53"}]
        })),
    )
    .await;
    assert_eq!(named.status, StatusCode::CREATED, "{}", named.body);
    assert_eq!(named.body["mode"], "forward");
    assert_eq!(named.body["validate"], true);
}

#[tokio::test]
async fn a_recurse_rule_and_validate_false_answer_501_and_write_nothing() {
    let router = app();
    // A recurse rule names no upstream: the field may be absent.
    send(
        &router,
        "POST",
        "/dns/forwarders",
        Some(json!({"suffix": "example.net", "mode": "recurse"})),
    )
    .await
    .assert_not_implemented("POST", "/dns/forwarders");
    send(
        &router,
        "POST",
        "/dns/forwarders",
        Some(json!({
            "suffix": "example.net",
            "validate": false,
            "upstreams": [{"address": "192.0.2.53"}]
        })),
    )
    .await
    .assert_not_implemented("POST", "/dns/forwarders");
    assert_eq!(items(&router, "/dns/forwarders").await, Vec::<Value>::new());

    let created = send(
        &router,
        "POST",
        "/dns/forwarders",
        Some(json!({"suffix": "example.net", "upstreams": [{"address": "192.0.2.53"}]})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let path = format!(
        "/dns/forwarders/{}",
        created.body["id"].as_str().expect("id")
    );
    for patch in [json!({"mode": "recurse"}), json!({"validate": false})] {
        send(&router, "PATCH", &path, Some(patch))
            .await
            .assert_not_implemented("PATCH", "/dns/forwarders/{id}");
    }
    let got = send(&router, "GET", &path, None).await;
    assert_eq!(got.body, created.body);

    // The defaults are accepted in a patch.
    let patched = send(
        &router,
        "PATCH",
        &path,
        Some(json!({"mode": "forward", "validate": true, "description": "kept"})),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    assert_eq!(patched.body["mode"], "forward");
    assert_eq!(patched.body["validate"], true);
}

#[tokio::test]
async fn a_view_resolution_answers_501_and_writes_nothing() {
    let router = app();
    send(
        &router,
        "POST",
        "/dns/views",
        Some(json!({"name": "lan", "order": 1, "resolution": "recurse"})),
    )
    .await
    .assert_not_implemented("POST", "/dns/views");
    assert_eq!(items(&router, "/dns/views").await, Vec::<Value>::new());

    let created = send(
        &router,
        "POST",
        "/dns/views",
        Some(json!({"name": "lan", "order": 1})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert!(created.body.get("resolution").is_none(), "{}", created.body);
    let path = format!("/dns/views/{}", created.body["id"].as_str().expect("id"));
    for patch in [
        json!({"resolution": "refuse"}),
        json!({"default_resolution": true}),
    ] {
        send(&router, "PATCH", &path, Some(patch))
            .await
            .assert_not_implemented("PATCH", "/dns/views/{id}");
    }
    let got = send(&router, "GET", &path, None).await;
    assert_eq!(got.body, created.body);

    // `default_resolution: false` is the absent field.
    let patched = send(
        &router,
        "PATCH",
        &path,
        Some(json!({"default_resolution": false, "description": "kept"})),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    assert_eq!(patched.body["description"], "kept");
}
