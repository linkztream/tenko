//! Route tests of the DNS operations that stay 501 until their package: each checks the
//! scope of its action on the right object before it answers, and refuses a malformed path
//! first. The built operations (zones, records, access lists, keys, forwarding rules) have
//! their tests in `tests/dns_zones.rs`, `tests/dns_records.rs`, `tests/dns_keys.rs` and
//! `tests/dns_forwarders.rs`; here they only
//! show that a path, then the scope, is checked before the zone service is needed.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, header},
};
use serde_json::Value;
use tenko_core::{Action, Authorizer, ObjectKind};
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;

use super::routes;
use crate::{
    API_BASE,
    routes::tenancy::testkit::{Policy, Reply},
    state::AppState,
};

const ZONE: &str = "0190d1c2-0000-7000-8000-000000000001";

fn router(state: AppState) -> Router {
    let (router, _) = OpenApiRouter::<AppState>::new()
        .nest(API_BASE, routes())
        .split_for_parts();
    router.with_state(state)
}

async fn send(router: &Router, method: &str, path: &str) -> Reply {
    let request = Request::builder()
        .method(method)
        .uri(format!("{API_BASE}{path}"))
        .body(Body::empty())
        .expect("request");
    let response = router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().expect("text").to_owned())
        .unwrap_or_default();
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
        etag: None,
        body,
    }
}

fn with_policy(read: bool, write: bool) -> (Router, Arc<Policy>) {
    let policy = Policy::new(read, write);
    let state = AppState {
        authorizer: Some(Arc::clone(&policy) as Arc<dyn Authorizer>),
        ..AppState::default()
    };
    (router(state), policy)
}

#[tokio::test]
async fn an_allowed_call_reaches_the_stub() {
    let (router, policy) = with_policy(true, true);
    let reply = send(&router, "GET", &format!("/dns/zones/{ZONE}/dnssec")).await;
    reply.assert_problem(501, "sys.not_implemented");
    assert_eq!(
        reply.body["params"]["path"],
        "/api/v1/dns/zones/{id}/dnssec"
    );
    let asked = policy.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].0, Action::Read);
    assert_eq!(asked[0].1.kind, ObjectKind::Zone);
    assert_eq!(asked[0].1.id.to_string(), ZONE);
}

#[tokio::test]
async fn a_reader_reads_and_is_refused_writes() {
    let (router, policy) = with_policy(true, false);
    send(&router, "GET", "/dns/views")
        .await
        .assert_problem(501, "sys.not_implemented");
    send(&router, "DELETE", &format!("/dns/forwarders/{ZONE}"))
        .await
        .assert_problem(403, "auth.forbidden");
    // A built route checks the scope before it needs the zone service.
    send(&router, "DELETE", &format!("/dns/zones/{ZONE}"))
        .await
        .assert_problem(403, "auth.forbidden");
    send(&router, "GET", "/dns/zones")
        .await
        .assert_problem(409, "dns.module.disabled");
    send(&router, "DELETE", &format!("/dns/views/{ZONE}"))
        .await
        .assert_problem(403, "auth.forbidden");
    send(&router, "POST", "/dns/lists")
        .await
        .assert_problem(403, "auth.forbidden");
    let kinds: Vec<(Action, ObjectKind)> =
        policy.asked().iter().map(|(a, o)| (*a, o.kind)).collect();
    assert_eq!(
        kinds,
        [
            (Action::Read, ObjectKind::DnsView),
            (Action::Delete, ObjectKind::DnsForwarder),
            (Action::Delete, ObjectKind::Zone),
            (Action::Read, ObjectKind::Zone),
            (Action::Delete, ObjectKind::DnsView),
            (Action::Create, ObjectKind::DnsList),
        ]
    );
}

#[tokio::test]
async fn keys_rollovers_and_nodes_are_checked_on_their_objects() {
    let (router, policy) = with_policy(true, true);
    send(
        &router,
        "POST",
        &format!("/dns/zones/{ZONE}/dnssec/rollover"),
    )
    .await
    .assert_problem(501, "sys.not_implemented");
    // A node this server neither is nor knows: the dns role is not here.
    for (method, path) in [
        ("GET", "/nodes/1001/dns"),
        ("POST", "/nodes/1001/dns/cache/flush"),
        ("GET", "/nodes/1001/dns/log"),
    ] {
        send(&router, method, path)
            .await
            .assert_problem(404, "cluster.node.not_found");
    }
    let kinds: Vec<(Action, ObjectKind)> =
        policy.asked().iter().map(|(a, o)| (*a, o.kind)).collect();
    assert_eq!(
        kinds,
        [
            (Action::Execute, ObjectKind::DnsKey),
            (Action::Read, ObjectKind::Node),
            (Action::Read, ObjectKind::Zone),
            (Action::Update, ObjectKind::Node),
            (Action::Execute, ObjectKind::Zone),
            (Action::Read, ObjectKind::Node),
            (Action::Read, ObjectKind::Zone),
        ]
    );
}

#[tokio::test]
async fn a_malformed_path_is_refused_before_anything_else() {
    let (router, policy) = with_policy(true, true);
    send(&router, "GET", "/dns/zones/not-a-uuid")
        .await
        .assert_problem(400, "sys.invalid_request");
    send(&router, "POST", "/dns/zones/not-a-uuid/dnssec/rollover")
        .await
        .assert_problem(400, "sys.invalid_request");
    send(&router, "GET", "/dns/keys/bad%20name")
        .await
        .assert_problem(400, "sys.invalid_request");
    send(&router, "GET", "/nodes/0/dns")
        .await
        .assert_problem(400, "sys.invalid_request");
    assert_eq!(policy.asked(), []);
}
