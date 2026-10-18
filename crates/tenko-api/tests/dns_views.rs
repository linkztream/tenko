//! The view operations through the router, over the zone service on an in-memory store:
//! create, read, list in order with a cursor, move, the recursion access list, the in-use
//! rules on zones, scopes and access lists, `If-Match` and the audit records.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tenko_api::state::AppState;
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store};
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

    /// A `dns.view.invalid` problem naming `field`.
    #[track_caller]
    fn assert_invalid(&self, field: &str) {
        self.assert_problem(400, "dns.view.invalid");
        assert_eq!(self.body["params"]["field"], field, "{}", self.body);
    }
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

fn zone_body(name: &str, scopes: &[&str]) -> Value {
    json!({
        "name": name,
        "kind": "primary",
        "serial": "counter",
        "soa": {"mname": format!("ns1.{name}"), "rname": format!("hostmaster.{name}")},
        "name_servers": [format!("ns1.{name}")],
        "scopes": scopes.iter().map(|scope| json!({"name": scope})).collect::<Vec<_>>(),
    })
}

async fn create_zone(router: &Router, name: &str, scopes: &[&str]) -> Value {
    let reply = send(router, "POST", "/dns/zones", Some(zone_body(name, scopes))).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    reply.body
}

async fn create_view(router: &Router, body: Value) -> Reply {
    send(router, "POST", "/dns/views", Some(body)).await
}

async fn create_named(router: &Router, name: &str, order: u32) -> Value {
    let created = create_view(
        router,
        json!({
            "name": name,
            "order": order,
            "rules": [{"test": "client_subnet", "prefixes": ["192.0.2.0/24"]}],
        }),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    created.body
}

fn view_path(view: &Value) -> String {
    format!("/dns/views/{}", view["id"].as_str().expect("id"))
}

async fn names(router: &Router) -> Vec<(String, u64)> {
    let list = send(router, "GET", "/dns/views", None).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    list.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| {
            (
                item["name"].as_str().expect("name").to_owned(),
                item["order"].as_u64().expect("order"),
            )
        })
        .collect()
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
async fn a_view_is_created_read_listed_in_order_and_moved() {
    let (router, _) = app();
    let zone = create_zone(&router, "example.test", &["internal", "external"]).await;
    let created = create_view(
        &router,
        json!({
            "name": "inside",
            "order": 1,
            "rules": [
                {"test": "client_subnet", "prefixes": ["192.0.2.0/24", "2001:db8::/32"]},
                {"test": "transport", "transports": ["udp", "dot"]},
                {"test": "interface", "addresses": ["192.0.2.53"]},
                {"test": "qtype", "types": ["A", "AAAA"]},
                {"test": "time_of_day", "from_minute": 1320, "to_minute": 360},
                {"test": "qname", "suffixes": ["example.test"]}
            ],
            "scope_map": [
                {"zone": zone["id"], "scope": "internal", "weight": 700},
                {"zone": zone["id"], "scope": "external", "weight": 300}
            ],
            "description": "  the office  "
        }),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["order"], 1);
    assert_eq!(created.body["description"], "the office");
    assert_eq!(created.body["rules"].as_array().map(Vec::len), Some(6));
    assert_eq!(created.body["scope_map"][1]["weight"], 300);
    assert!(created.body.get("recursion").is_none(), "{}", created.body);
    let etag = created.etag();
    let got = send(&router, "GET", &view_path(&created.body), None).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.body);
    assert_eq!(got.etag(), etag);
    assert_eq!(got.body, created.body);

    create_named(&router, "outside", 99).await;
    let top = create_named(&router, "top", 1).await;
    assert_eq!(
        names(&router).await,
        [
            ("top".to_owned(), 1),
            ("inside".to_owned(), 2),
            ("outside".to_owned(), 3)
        ]
    );
    let mut seen = Vec::new();
    let mut path = "/dns/views?limit=1".to_owned();
    for _ in 0..4 {
        let page = send(&router, "GET", &path, None).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        seen.push(
            page.body["items"][0]["name"]
                .as_str()
                .expect("name")
                .to_owned(),
        );
        match page.body["next_cursor"].as_str() {
            Some(cursor) => path = format!("/dns/views?limit=1&cursor={cursor}"),
            None => break,
        }
    }
    assert_eq!(seen, ["top", "inside", "outside"]);

    // A move to the end; the others close up.
    let moved = send(
        &router,
        "PATCH",
        &view_path(&top),
        Some(json!({"order": 3})),
    )
    .await;
    assert_eq!(moved.status, StatusCode::OK, "{}", moved.body);
    assert_eq!(moved.body["order"], 3);
    assert_eq!(
        names(&router).await,
        [
            ("inside".to_owned(), 1),
            ("outside".to_owned(), 2),
            ("top".to_owned(), 3)
        ]
    );
    // The first view's ETag is stale now: its position moved.
    let stale = send_with(
        &router,
        "PATCH",
        &view_path(&created.body),
        Some(json!({"name": "renamed"})),
        &[("if-match", &etag)],
    )
    .await;
    stale.assert_problem(412, "sys.store.precondition_failed");
}

#[tokio::test]
async fn invalid_views_name_their_field() {
    let (router, _) = app();
    let zone = create_zone(&router, "example.test", &["internal"]).await;
    for (body, field) in [
        (json!({"name": "", "order": 1}), "name"),
        (
            json!({"name": "v", "order": 1, "rules": [{"test": "transport", "transports": []}]}),
            "rules",
        ),
        (
            json!({"name": "v", "order": 1, "rules": [{"test": "time_of_day", "from_minute": 0, "to_minute": 1440}]}),
            "rules",
        ),
        (
            json!({"name": "v", "order": 1, "scope_map": [{"zone": zone["id"], "scope": "internal", "weight": 0}]}),
            "scope_map",
        ),
        (
            json!({"name": "v", "order": 1, "scope_map": [{"zone": zone["id"], "scope": "missing", "weight": 1}]}),
            "scope_map",
        ),
        (
            json!({"name": "v", "order": 1, "scope_map": [{"zone": MISSING, "scope": "default", "weight": 1}]}),
            "scope_map",
        ),
        (
            json!({"name": "v", "order": 1, "recursion": MISSING}),
            "recursion",
        ),
    ] {
        create_view(&router, body).await.assert_invalid(field);
    }
    // A malformed rule is a request error.
    let reply = create_view(
        &router,
        json!({"name": "v", "order": 1, "rules": [{"test": "client_subnet", "prefixes": ["not a prefix"]}]}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    send(&router, "GET", &format!("/dns/views/{MISSING}"), None)
        .await
        .assert_problem(404, "dns.view.not_found");
    send(&router, "GET", "/dns/views/not-a-uuid", None)
        .await
        .assert_problem(400, "sys.invalid_request");
}

#[tokio::test]
async fn the_in_use_rules_hold_for_scopes_zones_lists_and_rules() {
    let (router, _) = app();
    let zone = create_zone(&router, "example.test", &["internal"]).await;
    let zone_path = format!("/dns/zones/{}", zone["id"].as_str().expect("id"));
    let acl = send(
        &router,
        "POST",
        "/dns/acls",
        Some(json!({"name": "office", "entries": [{"kind": "prefix", "prefix": "192.0.2.0/24"}]})),
    )
    .await;
    assert_eq!(acl.status, StatusCode::CREATED, "{}", acl.body);
    let acl_path = format!("/dns/acls/{}", acl.body["id"].as_str().expect("id"));
    let view = create_view(
        &router,
        json!({
            "name": "inside",
            "order": 1,
            "scope_map": [{"zone": zone["id"], "scope": "internal", "weight": 1}],
            "recursion": acl.body["id"],
        }),
    )
    .await;
    assert_eq!(view.status, StatusCode::CREATED, "{}", view.body);
    assert_eq!(view.body["recursion"], acl.body["id"]);

    let removed = send(
        &router,
        "PATCH",
        &zone_path,
        Some(json!({"scopes": [{"name": "default"}]})),
    )
    .await;
    removed.assert_problem(409, "dns.view.in_use");
    assert_eq!(removed.body["params"]["by"], "view:inside");
    send(&router, "DELETE", &zone_path, None)
        .await
        .assert_problem(409, "dns.view.in_use");
    let list = send(&router, "GET", &acl_path, None).await;
    assert_eq!(
        list.body["used_by"],
        json!(["view:inside"]),
        "{}",
        list.body
    );
    send(&router, "DELETE", &acl_path, None)
        .await
        .assert_problem(409, "dns.acl.in_use");

    let rule = send(
        &router,
        "POST",
        "/dns/forwarders",
        Some(json!({"suffix": "example.net", "upstreams": [{"address": "192.0.2.53"}], "view": view.body["id"]})),
    )
    .await;
    assert_eq!(rule.status, StatusCode::CREATED, "{}", rule.body);
    let refused = send(&router, "DELETE", &view_path(&view.body), None).await;
    refused.assert_problem(409, "dns.view.in_use");
    assert_eq!(refused.body["params"]["by"], "forwarder:example.net");

    // The view lets go of the scope and the list; the zone and the list can go.
    let freed = send(
        &router,
        "PATCH",
        &view_path(&view.body),
        Some(json!({"scope_map": [], "default_recursion": true})),
    )
    .await;
    assert_eq!(freed.status, StatusCode::OK, "{}", freed.body);
    assert!(freed.body.get("recursion").is_none(), "{}", freed.body);
    let list_gone = send(&router, "DELETE", &acl_path, None).await;
    assert_eq!(
        list_gone.status,
        StatusCode::NO_CONTENT,
        "{}",
        list_gone.body
    );
    let gone = send(&router, "DELETE", &zone_path, None).await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT, "{}", gone.body);
}

#[tokio::test]
async fn every_change_is_audited_in_order() {
    let (router, store) = app();
    let created = create_named(&router, "inside", 1).await;
    let path = view_path(&created);
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
    let view: Vec<&str> = actions
        .iter()
        .map(String::as_str)
        .filter(|action| action.starts_with("dns.view."))
        .collect();
    assert_eq!(
        view,
        ["dns.view.create", "dns.view.update", "dns.view.delete"],
        "{actions:?}"
    );
}

#[tokio::test]
async fn without_the_zone_service_the_module_is_disabled() {
    let (bare, _) = tenko_api::api(AppState::default());
    send(&bare, "GET", "/dns/views", None)
        .await
        .assert_problem(409, "dns.module.disabled");
}
