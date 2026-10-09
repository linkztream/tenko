//! Route tests of the connectors area: instances over a connector host whose sample plugin
//! cannot start, so the API is exercised while the plugin keeps failing.

use std::{ffi::OsString, sync::Arc, time::Duration};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tenko_connect::{
    host::{
        ConnectorHost, HostConfig,
        launch::LaunchSpec,
        normalize::{DiscardSink, ObservationSink},
        registry::{Bundled, PluginRegistry},
        supervisor::SupervisorConfig,
    },
    sample,
};
use tenko_core::{
    Action, Authorizer, Denied, DenyReason, ObjectKind, ObjectRef, Principal, ScopeFilter, SecretId,
};
use tenko_jobs::{EngineConfig, JobEngine};
use tenko_store::{MemStore, Store};
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;

use super::routes;
use crate::{API_BASE, problem::PROBLEM_JSON, state::AppState};

/// Allows everything but revealing secrets.
struct NoReveal;

impl Authorizer for NoReveal {
    fn check(&self, _: &Principal, action: Action, object: &ObjectRef) -> Result<(), Denied> {
        if action == Action::Reveal {
            return Err(Denied {
                action,
                object: *object,
                reason: DenyReason::MissingPermission,
            });
        }
        Ok(())
    }

    fn scope(&self, _: &Principal, _: Action, _: ObjectKind) -> ScopeFilter {
        ScopeFilter::All
    }
}

/// Reads nothing.
struct Blind;

impl Authorizer for Blind {
    fn check(&self, _: &Principal, _: Action, _: &ObjectRef) -> Result<(), Denied> {
        Ok(())
    }

    fn scope(&self, _: &Principal, _: Action, _: ObjectKind) -> ScopeFilter {
        ScopeFilter::Nothing
    }
}

struct Fixture {
    router: Router,
    host: Arc<ConnectorHost>,
}

fn fixture(authorizer: Option<Arc<dyn Authorizer>>) -> Fixture {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let manifest = sample::manifest();
    let registry = PluginRegistry::new(
        vec![Bundled {
            manifest: manifest.clone(),
            launch: LaunchSpec {
                expected: Some(manifest),
                program: std::env::temp_dir().join("tenko-no-such-plugin-program"),
                args: vec![OsString::from("--mode"), OsString::from("normal")],
                cwd: None,
                env: Vec::new(),
            },
        }],
        None,
    );
    let host = ConnectorHost::new(
        Arc::clone(&store),
        None,
        registry,
        HostConfig {
            supervisor: SupervisorConfig::default(),
            start_wait: Duration::from_millis(100),
            schedule: false,
            ..HostConfig::default()
        },
        Arc::new(DiscardSink) as Arc<dyn ObservationSink>,
    );
    let engine = JobEngine::new(Arc::clone(&store), EngineConfig::default());
    host.register_steps(&engine);
    let (router, _) = OpenApiRouter::<AppState>::new()
        .nest(API_BASE, routes())
        .split_for_parts();
    let mut state = AppState::new(store);
    state.authorizer = authorizer;
    let router = router.with_state(state).layer(Extension(Arc::clone(&host)));
    Fixture { router, host }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Reply {
    fn assert_problem(&self, status: u16, code: &str) {
        let label = format!("{} {}", self.status, self.body);
        assert_eq!(self.status.as_u16(), status, "{label}");
        assert_eq!(
            self.headers
                .get(header::CONTENT_TYPE)
                .map(|value| value.to_str().unwrap_or_default()),
            Some(PROBLEM_JSON),
            "{label}"
        );
        assert_eq!(self.body["code"], code, "{label}");
    }
}

async fn send(
    router: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    if_match: Option<&str>,
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{API_BASE}{path}"));
    if let Some(etag) = if_match {
        builder = builder.header(header::IF_MATCH, etag);
    }
    let body = match body {
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = router
        .clone()
        .oneshot(builder.body(body).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("JSON body")
    };
    Reply {
        status,
        headers,
        body,
    }
}

fn new_sample(name: &str) -> Value {
    json!({ "plugin": "sample", "name": name, "settings": { "hosts": 4 } })
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario from creation to deletion"
)]
async fn instances_are_created_read_changed_and_deleted() {
    let fx = fixture(None);
    let plugins = send(&fx.router, "GET", "/connectors/plugins", None, None).await;
    assert_eq!(plugins.status, StatusCode::OK, "{}", plugins.body);
    assert_eq!(plugins.body["items"][0]["name"], "sample");
    assert_eq!(plugins.body["items"][0]["usable"], true);
    assert_eq!(
        plugins.body["items"][0]["manifest"]["settings"]["properties"]["hosts"]["type"],
        "integer"
    );

    let created = send(
        &fx.router,
        "POST",
        "/connectors",
        Some(new_sample("Lab")),
        None,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let id = created.body["id"].as_str().expect("id").to_owned();
    assert_eq!(created.body["plugin"], "sample");
    assert_eq!(created.body["settings"]["hosts"], 4);
    assert_eq!(created.body["settings"]["site"], "lab");
    assert_eq!(created.body["capabilities"][0], "inventory");
    assert!(created.body["health"]["process"]["state"].is_string());
    let etag = created.headers[header::ETAG]
        .to_str()
        .expect("etag")
        .to_owned();
    assert_eq!(
        created.headers[header::LOCATION]
            .to_str()
            .expect("location"),
        format!("{API_BASE}/connectors/{id}")
    );

    let read = send(&fx.router, "GET", &format!("/connectors/{id}"), None, None).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.headers[header::ETAG].to_str().expect("etag"), etag);

    // A stale If-Match is a conflict; the current one applies.
    let stale = send(
        &fx.router,
        "PATCH",
        &format!("/connectors/{id}"),
        Some(json!({ "name": "Lab A" })),
        Some("\"999999\""),
    )
    .await;
    stale.assert_problem(409, "connect.instance.conflict");
    let renamed = send(
        &fx.router,
        "PATCH",
        &format!("/connectors/{id}"),
        Some(json!({ "name": "Lab A", "poll_interval_secs": 600 })),
        Some(&etag),
    )
    .await;
    assert_eq!(renamed.status, StatusCode::OK, "{}", renamed.body);
    assert_eq!(renamed.body["name"], "Lab A");
    assert_eq!(renamed.body["poll_interval_secs"], 600);

    let second = send(
        &fx.router,
        "POST",
        "/connectors",
        Some(new_sample("Garage")),
        None,
    )
    .await;
    assert_eq!(second.status, StatusCode::CREATED);
    let page = send(&fx.router, "GET", "/connectors?limit=1", None, None).await;
    assert_eq!(page.body["items"][0]["name"], "Garage", "{}", page.body);
    let cursor = page.body["next_cursor"]
        .as_str()
        .expect("cursor")
        .to_owned();
    let next = send(
        &fx.router,
        "GET",
        &format!("/connectors?limit=1&cursor={cursor}"),
        None,
        None,
    )
    .await;
    assert_eq!(next.body["items"][0]["name"], "Lab A", "{}", next.body);
    assert!(next.body["next_cursor"].is_null());

    let disabled = send(
        &fx.router,
        "POST",
        &format!("/connectors/{id}/disable"),
        None,
        None,
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK);
    assert_eq!(disabled.body["enabled"], false);
    assert_eq!(disabled.body["health"]["process"]["state"], "stopped");
    let run = send(
        &fx.router,
        "POST",
        &format!("/connectors/{id}/run"),
        None,
        None,
    )
    .await;
    run.assert_problem(409, "connect.instance.disabled");
    let enabled = send(
        &fx.router,
        "POST",
        &format!("/connectors/{id}/enable"),
        None,
        None,
    )
    .await;
    assert_eq!(enabled.body["enabled"], true);

    let run = send(
        &fx.router,
        "POST",
        &format!("/connectors/{id}/run"),
        None,
        None,
    )
    .await;
    assert_eq!(run.status, StatusCode::ACCEPTED, "{}", run.body);
    assert!(run.body["job"].is_string());

    let deleted = send(
        &fx.router,
        "DELETE",
        &format!("/connectors/{id}"),
        None,
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = send(&fx.router, "GET", &format!("/connectors/{id}"), None, None).await;
    gone.assert_problem(404, "connect.instance.not_found");
    fx.host.shutdown().await;
}

#[tokio::test]
async fn invalid_requests_are_precise_problems() {
    let fx = fixture(None);
    let bad = send(
        &fx.router,
        "POST",
        "/connectors",
        Some(json!({ "plugin": "sample", "name": "x", "settings": { "hosts": 900 } })),
        None,
    )
    .await;
    bad.assert_problem(422, "connect.settings.invalid");
    assert_eq!(
        bad.body["errors"][0]["field"], "settings.hosts",
        "{}",
        bad.body
    );
    assert_eq!(bad.body["errors"][0]["code"], "connect.settings.range");

    let unknown = send(
        &fx.router,
        "POST",
        "/connectors",
        Some(json!({ "plugin": "nope", "name": "x" })),
        None,
    )
    .await;
    unknown.assert_problem(422, "connect.plugin.unknown");

    let not_object = send(&fx.router, "POST", "/connectors", Some(json!([1])), None).await;
    not_object.assert_problem(400, "sys.invalid_request");
    let extra = send(
        &fx.router,
        "POST",
        "/connectors",
        Some(json!({ "plugin": "sample", "name": "x", "colour": "red" })),
        None,
    )
    .await;
    extra.assert_problem(400, "sys.invalid_request");

    let malformed = send(&fx.router, "GET", "/connectors/not-a-uuid", None, None).await;
    malformed.assert_problem(400, "sys.invalid_request");

    let first = send(
        &fx.router,
        "POST",
        "/connectors",
        Some(new_sample("Twice")),
        None,
    )
    .await;
    assert_eq!(first.status, StatusCode::CREATED);
    let twice = send(
        &fx.router,
        "POST",
        "/connectors",
        Some(new_sample("twice")),
        None,
    )
    .await;
    twice.assert_problem(409, "connect.instance.name_taken");
    fx.host.shutdown().await;
}

#[tokio::test]
async fn secret_references_need_permission_to_reveal_them() {
    let fx = fixture(Some(Arc::new(NoReveal)));
    let secret = SecretId::generate();
    let body = json!({
        "plugin": "sample",
        "name": "With key",
        "secrets": { "api_key": { "secret": secret.to_string() } }
    });
    let refused = send(&fx.router, "POST", "/connectors", Some(body), None).await;
    refused.assert_problem(403, "auth.forbidden");

    // Without references the instance can be created and its settings changed.
    let created = send(
        &fx.router,
        "POST",
        "/connectors",
        Some(new_sample("Plain")),
        None,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let id = created.body["id"].as_str().expect("id").to_owned();
    let changed = send(
        &fx.router,
        "PATCH",
        &format!("/connectors/{id}"),
        Some(json!({ "settings": { "hosts": 2 } })),
        None,
    )
    .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    let with_key = send(
        &fx.router,
        "PATCH",
        &format!("/connectors/{id}"),
        Some(json!({ "secrets": { "api_key": { "secret": secret.to_string() } } })),
        None,
    )
    .await;
    with_key.assert_problem(403, "auth.forbidden");
    fx.host.shutdown().await;
}

#[tokio::test]
async fn a_failing_plugin_never_affects_the_api() {
    let fx = fixture(None);
    let created = send(
        &fx.router,
        "POST",
        "/connectors",
        Some(new_sample("Broken")),
        None,
    )
    .await;
    let id = created.body["id"].as_str().expect("id").to_owned();
    let mut last_error = Value::Null;
    for _ in 0..50 {
        let started = std::time::Instant::now();
        let read = send(&fx.router, "GET", &format!("/connectors/{id}"), None, None).await;
        assert_eq!(read.status, StatusCode::OK);
        assert!(started.elapsed() < Duration::from_secs(1));
        last_error = read.body["health"]["process"]["last_error"]["code"].clone();
        if !last_error.is_null() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(last_error, "connect.plugin.spawn_failed");
    let check = send(
        &fx.router,
        "POST",
        &format!("/connectors/{id}/check"),
        None,
        None,
    )
    .await;
    check.assert_problem(503, "connect.plugin.unavailable");
    fx.host.shutdown().await;
}

#[tokio::test]
async fn readers_without_permission_see_empty_lists() {
    let fx = fixture(Some(Arc::new(Blind)));
    let plugins = send(&fx.router, "GET", "/connectors/plugins", None, None).await;
    assert_eq!(plugins.body["items"], json!([]));
    let list = send(&fx.router, "GET", "/connectors", None, None).await;
    assert_eq!(list.body["items"], json!([]));
}
