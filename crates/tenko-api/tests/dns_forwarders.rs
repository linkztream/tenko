//! The forwarding rule operations through the router, over the zone service on an in-memory
//! store.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tenko_api::state::AppState;
use tenko_auth::settings::Profile;
use tenko_core::{
    Action, Authorizer, Denied, DenyReason, ObjectKind, ObjectRef, Principal, RequestCtx,
    ScopeFilter, SystemComponent,
};
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store, WriteBatch};
use tower::ServiceExt;

const API: &str = "/api/v1";
const PROBLEM_JSON: &str = "application/problem+json";
const MISSING: &str = "0190d1c2-0000-7000-8000-0000000000ff";

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Reply {
    fn etag(&self) -> String {
        self.headers
            .get(header::ETAG)
            .expect("etag")
            .to_str()
            .expect("text")
            .to_owned()
    }

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

    /// A `dns.forwarder.invalid` problem naming `field`.
    #[track_caller]
    fn assert_invalid(&self, field: &str) {
        self.assert_problem(400, "dns.forwarder.invalid");
        assert_eq!(self.body["params"]["field"], field, "{}", self.body);
    }
}

/// An authorizer of an operator with every DNS right but `dns.keys`: every action on a
/// `DnsKey` is refused, everything else allowed.
struct WithoutKeys;

impl Authorizer for WithoutKeys {
    fn check(&self, _: &Principal, action: Action, object: &ObjectRef) -> Result<(), Denied> {
        if object.kind == ObjectKind::DnsKey {
            Err(Denied {
                action,
                object: *object,
                reason: DenyReason::MissingPermission,
            })
        } else {
            Ok(())
        }
    }

    fn scope(&self, _: &Principal, _: Action, kind: ObjectKind) -> ScopeFilter {
        if kind == ObjectKind::DnsKey {
            ScopeFilter::Nothing
        } else {
            ScopeFilter::All
        }
    }
}

/// The router over a zone service on an in-memory store, with `authorizer` (none: every
/// action allowed) and the settings row of `profile` when one is given.
async fn app_with(
    authorizer: Option<Arc<dyn Authorizer>>,
    profile: Option<Profile>,
) -> (Router, Arc<MemStore>) {
    let store = Arc::new(MemStore::default());
    if let Some(profile) = profile {
        let ctx = RequestCtx::system(SystemComponent::Setup);
        let mut batch = WriteBatch::for_request(&ctx);
        batch
            .put_typed(&tenko_auth::model::SETTINGS, &(), &profile.defaults())
            .expect("settings");
        store.propose(batch).await.expect("the profile");
    }
    let vault = Arc::new(tenko_vault::MemVault::with_store(Arc::clone(&store)));
    let service = ZoneService::with_direct_jobs(
        Arc::clone(&store) as Arc<dyn Store>,
        Some(vault as Arc<dyn tenko_vault::Vault>),
        ZoneConfig::default(),
    );
    let mut state = AppState::default();
    state.authorizer = authorizer;
    let (router, _) = tenko_api::api(state);
    (router.layer(axum::Extension(service)), store)
}

fn app() -> (Router, Arc<MemStore>) {
    let store = Arc::new(MemStore::default());
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

async fn create(router: &Router, body: Value) -> Reply {
    send(router, "POST", "/dns/forwarders", Some(body)).await
}

async fn create_plain(router: &Router, suffix: &str) -> Reply {
    let created = create(
        router,
        json!({"suffix": suffix, "upstreams": [{"address": "192.0.2.53"}]}),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    created
}

fn rule_path(reply: &Reply) -> String {
    format!("/dns/forwarders/{}", reply.body["id"].as_str().expect("id"))
}

/// The audit actions in the store, in order.
async fn audit_actions(store: &MemStore) -> Vec<String> {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(
        &tenko_store::tables::AUDIT,
        KeyRange::all(),
        usize::MAX,
        false,
    )
    .expect("audit")
    .into_iter()
    .map(|(_, record, _)| record.draft.action.as_str().to_owned())
    .collect()
}

#[tokio::test]
async fn a_rule_is_created_read_and_listed_by_suffix() {
    let (router, _) = app();
    let created = create(
        &router,
        json!({
            "suffix": "example.net",
            "upstreams": [{"address": "192.0.2.53"}],
            "description": "  corporate names  "
        }),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["suffix"], "example.net");
    assert_eq!(created.body["transport"], "plain");
    assert_eq!(created.body["description"], "corporate names");
    assert_eq!(created.body["upstreams"][0]["address"], "192.0.2.53");
    assert!(created.body["revision"].is_number(), "{}", created.body);
    let etag = created.etag();

    let got = send(&router, "GET", &rule_path(&created), None).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.body);
    assert_eq!(got.etag(), etag);
    assert_eq!(got.body, created.body);

    create_plain(&router, "example.org").await;
    create_plain(&router, ".").await;

    let list = send(&router, "GET", "/dns/forwarders", None).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    let suffixes: Vec<&str> = list.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["suffix"].as_str().expect("suffix"))
        .collect();
    assert_eq!(suffixes, [".", "example.net", "example.org"]);
    assert!(list.body["next_cursor"].is_null());

    let mut seen = Vec::new();
    let mut path = "/dns/forwarders?limit=1".to_owned();
    for _ in 0..3 {
        let page = send(&router, "GET", &path, None).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let items = page.body["items"].as_array().expect("items");
        assert_eq!(items.len(), 1);
        seen.push(items[0]["suffix"].as_str().expect("suffix").to_owned());
        match page.body["next_cursor"].as_str() {
            Some(cursor) => path = format!("/dns/forwarders?limit=1&cursor={cursor}"),
            None => break,
        }
    }
    assert_eq!(seen, [".", "example.net", "example.org"]);
}

#[tokio::test]
async fn a_dot_rule_keeps_its_ports_and_tls_name() {
    let (router, _) = app();
    let created = create(
        &router,
        json!({
            "suffix": "example.net",
            "transport": "dot",
            "tls_name": "dns.example.test",
            "upstreams": [
                {"address": "2001:db8::53"},
                {"address": "192.0.2.54", "port": 8853}
            ]
        }),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["transport"], "dot");
    assert_eq!(created.body["tls_name"], "dns.example.test");
    assert_eq!(created.body["upstreams"][0]["address"], "2001:db8::53");
    assert_eq!(created.body["upstreams"][1]["port"], 8853);
}

#[tokio::test]
async fn an_invalid_rule_is_refused_with_the_field() {
    let (router, _) = app();
    let upstream = json!({"address": "192.0.2.53"});

    create(
        &router,
        json!({"suffix": "example.net", "transport": "dot", "upstreams": [upstream]}),
    )
    .await
    .assert_invalid("tls_name");

    create(
        &router,
        json!({
            "suffix": "example.net",
            "upstreams": [{"address": "192.0.2.53", "path": "/dns-query"}]
        }),
    )
    .await
    .assert_invalid("upstreams");

    create(
        &router,
        json!({
            "suffix": "example.net",
            "transport": "doh",
            "tls_name": "dns.example.test",
            "upstreams": [{"address": "192.0.2.53", "path": "dns-query"}]
        }),
    )
    .await
    .assert_invalid("upstreams");

    let many: Vec<Value> = (1..=17)
        .map(|n| json!({"address": format!("192.0.2.{n}")}))
        .collect();
    create(&router, json!({"suffix": "example.net", "upstreams": many}))
        .await
        .assert_invalid("upstreams");
    create(&router, json!({"suffix": "example.net", "upstreams": []}))
        .await
        .assert_invalid("upstreams");

    create(
        &router,
        json!({"suffix": "example.net", "upstreams": [upstream], "view": MISSING}),
    )
    .await
    .assert_invalid("view");

    create_plain(&router, "example.net").await;
    create(
        &router,
        json!({"suffix": "example.net", "upstreams": [upstream]}),
    )
    .await
    .assert_invalid("suffix");

    let list = send(&router, "GET", "/dns/forwarders", None).await;
    assert_eq!(list.body["items"].as_array().expect("items").len(), 1);
}

#[tokio::test]
async fn a_rule_is_changed_with_its_etag() {
    let (router, _) = app();
    let created = create(
        &router,
        json!({
            "suffix": "example.net",
            "upstreams": [{"address": "192.0.2.53"}],
            "description": "first"
        }),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let path = rule_path(&created);
    let got = send(&router, "GET", &path, None).await;
    let etag = got.etag();

    let change = json!({
        "transport": "doh",
        "tls_name": "dns.example.test",
        "upstreams": [
            {"address": "192.0.2.54", "path": "/dns-query"},
            {"address": "2001:db8::54"}
        ]
    });
    let patched = send_with(
        &router,
        "PATCH",
        &path,
        Some(change.clone()),
        &[("if-match", &etag)],
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    assert_eq!(patched.body["transport"], "doh");
    assert_eq!(patched.body["tls_name"], "dns.example.test");
    assert_eq!(patched.body["upstreams"][0]["path"], "/dns-query");
    assert_eq!(patched.body["description"], "first");
    assert_ne!(patched.etag(), etag);

    send_with(
        &router,
        "PATCH",
        &path,
        Some(change),
        &[("if-match", &etag)],
    )
    .await
    .assert_problem(412, "sys.store.precondition_failed");

    let cleared = send(&router, "PATCH", &path, Some(json!({"description": ""}))).await;
    assert_eq!(cleared.status, StatusCode::OK, "{}", cleared.body);
    assert!(
        cleared.body.get("description").is_none(),
        "{}",
        cleared.body
    );
    assert_eq!(cleared.body["transport"], "doh");

    send(
        &router,
        "PATCH",
        &format!("/dns/forwarders/{MISSING}"),
        Some(json!({"description": "x"})),
    )
    .await
    .assert_problem(404, "dns.forwarder.not_found");
    send(
        &router,
        "PATCH",
        "/dns/forwarders/not-an-id",
        Some(json!({"description": "x"})),
    )
    .await
    .assert_problem(400, "sys.invalid_request");
}

#[tokio::test]
async fn a_deleted_rule_is_gone() {
    let (router, _) = app();
    let created = create_plain(&router, "example.net").await;
    let path = rule_path(&created);

    let deleted = send(&router, "DELETE", &path, None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    send(&router, "GET", &path, None)
        .await
        .assert_problem(404, "dns.forwarder.not_found");
    send(&router, "DELETE", &path, None)
        .await
        .assert_problem(404, "dns.forwarder.not_found");
    let list = send(&router, "GET", "/dns/forwarders", None).await;
    assert_eq!(list.body["items"], json!([]));
}

#[tokio::test]
async fn every_change_is_audited_in_order() {
    let (router, store) = app();
    let created = create_plain(&router, "example.net").await;
    let path = rule_path(&created);
    let patched = send(
        &router,
        "PATCH",
        &path,
        Some(json!({"description": "named"})),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    let deleted = send(&router, "DELETE", &path, None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    let actions = audit_actions(&store).await;
    let forwarder: Vec<&str> = actions
        .iter()
        .map(String::as_str)
        .filter(|action| action.starts_with("dns.forwarder."))
        .collect();
    assert_eq!(
        forwarder,
        [
            "dns.forwarder.create",
            "dns.forwarder.update",
            "dns.forwarder.delete"
        ],
        "{actions:?}"
    );
}

#[tokio::test]
async fn without_the_zone_service_the_module_is_disabled() {
    let (bare, _) = tenko_api::api(AppState::default());
    send(&bare, "GET", "/dns/forwarders", None)
        .await
        .assert_problem(409, "dns.module.disabled");
}

/// `validate: false` is gated as a negative trust anchor is: it needs the Create right on
/// keys, the root rule never has it, and the Hardened profile refuses it.
#[tokio::test]
async fn validation_off_needs_the_key_right_and_is_refused_on_the_root_and_under_hardened() {
    let unvalidated = |suffix: &str| json!({"suffix": suffix, "upstreams": [{"address": "192.0.2.53"}], "validate": false});
    // An operator with `dns.write` but not `dns.keys` creates rules, but none that
    // switches validation off, and cannot switch it off on an existing rule.
    let (router, _) = app_with(Some(Arc::new(WithoutKeys)), None).await;
    let plain = create_plain(&router, "example.net").await;
    let id = plain.body["id"].as_str().expect("id").to_owned();
    create(&router, unvalidated("stripped.example.net"))
        .await
        .assert_problem(403, "auth.forbidden");
    send(
        &router,
        "PATCH",
        &format!("/dns/forwarders/{id}"),
        Some(json!({"validate": false})),
    )
    .await
    .assert_problem(403, "auth.forbidden");
    // Turning it on, or leaving it as it is, needs no key right.
    let on = send(
        &router,
        "PATCH",
        &format!("/dns/forwarders/{id}"),
        Some(json!({"validate": true, "description": "kept"})),
    )
    .await;
    assert_eq!(on.status, StatusCode::OK, "{}", on.body);
    assert!(
        send(&router, "GET", "/dns/forwarders", None).await.body["items"]
            .as_array()
            .is_some_and(|items| items.len() == 1)
    );

    // With the right: the root rule never relays answers unvalidated, another suffix
    // may under the Standard profile.
    let (router, _) = app_with(None, Some(Profile::Standard)).await;
    create(&router, unvalidated("."))
        .await
        .assert_invalid("validate");
    let created = create(&router, unvalidated("stripped.example.net")).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["validate"], false);
    let id = created.body["id"].as_str().expect("id").to_owned();
    send(
        &router,
        "PATCH",
        &format!("/dns/forwarders/{id}"),
        Some(json!({"suffix": "."})),
    )
    .await
    .assert_invalid("validate");

    // The Hardened profile refuses it on every suffix, on a create and on a change.
    let (router, _) = app_with(None, Some(Profile::Hardened)).await;
    create(&router, unvalidated("stripped.example.net"))
        .await
        .assert_invalid("validate");
    let plain = create_plain(&router, "example.net").await;
    let id = plain.body["id"].as_str().expect("id").to_owned();
    send(
        &router,
        "PATCH",
        &format!("/dns/forwarders/{id}"),
        Some(json!({"validate": false})),
    )
    .await
    .assert_invalid("validate");
    let still = send(&router, "GET", &format!("/dns/forwarders/{id}"), None).await;
    assert_eq!(still.body["validate"], true);
}
