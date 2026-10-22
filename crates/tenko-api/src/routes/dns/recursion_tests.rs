//! Route tests of the recursive resolver's stubs (WP10.0): each operation checks the scope of
//! its action on the right kind and answers 501 until its package builds it, a viewer is
//! refused, and a malformed path answers 400 before anything else.

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

const NTA: &str = "0190d1c2-0000-7000-8000-000000000001";
const STUB: &str = "sys.not_implemented";

fn router(state: AppState) -> Router {
    let (router, _) = OpenApiRouter::<AppState>::new()
        .nest(API_BASE, routes())
        .split_for_parts();
    router.with_state(state)
}

fn with_policy(read: bool, write: bool) -> (Router, Arc<Policy>) {
    let policy = Policy::new(read, write);
    let state = AppState {
        authorizer: Some(Arc::clone(&policy) as Arc<dyn Authorizer>),
        ..AppState::default()
    };
    (router(state), policy)
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

/// Every operation of the area with the action and the kind it is checked on.
fn operations() -> Vec<(&'static str, String, Action, ObjectKind)> {
    vec![
        (
            "GET",
            "/dns/trust-anchors".to_owned(),
            Action::Read,
            ObjectKind::Zone,
        ),
        (
            "POST",
            "/dns/trust-anchors".to_owned(),
            Action::Create,
            ObjectKind::DnsKey,
        ),
        (
            "GET",
            "/dns/trust-anchors/example.test".to_owned(),
            Action::Read,
            ObjectKind::Zone,
        ),
        (
            "GET",
            "/dns/trust-anchors/root".to_owned(),
            Action::Read,
            ObjectKind::Zone,
        ),
        (
            "DELETE",
            "/dns/trust-anchors/example.test".to_owned(),
            Action::Delete,
            ObjectKind::DnsKey,
        ),
        (
            "POST",
            "/dns/trust-anchors/example.test/refresh".to_owned(),
            Action::Execute,
            ObjectKind::DnsKey,
        ),
        (
            "GET",
            "/dns/ntas".to_owned(),
            Action::Read,
            ObjectKind::Zone,
        ),
        (
            "POST",
            "/dns/ntas".to_owned(),
            Action::Create,
            ObjectKind::DnsKey,
        ),
        (
            "DELETE",
            format!("/dns/ntas/{NTA}"),
            Action::Delete,
            ObjectKind::DnsKey,
        ),
    ]
}

/// Every node operation with the two checks it makes: the action on the node, then the
/// action on the zone kind.
fn node_operations() -> Vec<(&'static str, &'static str, Action, Action)> {
    vec![
        (
            "GET",
            "/nodes/1001/dns/recursion",
            Action::Read,
            Action::Read,
        ),
        (
            "POST",
            "/nodes/1001/dns/recursion/prime",
            Action::Update,
            Action::Execute,
        ),
        ("GET", "/nodes/1001/dns/infra", Action::Read, Action::Read),
        (
            "POST",
            "/nodes/1001/dns/infra/flush",
            Action::Update,
            Action::Execute,
        ),
    ]
}

#[tokio::test]
async fn a_caller_with_the_scope_reaches_the_stub_on_the_right_kind() {
    let (router, policy) = with_policy(true, true);
    for (method, path, _, _) in operations() {
        send(&router, method, &path).await.assert_problem(501, STUB);
    }
    let expected: Vec<(Action, ObjectKind)> = operations()
        .into_iter()
        .map(|(_, _, action, kind)| (action, kind))
        .collect();
    let asked: Vec<(Action, ObjectKind)> =
        policy.asked().iter().map(|(a, o)| (*a, o.kind)).collect();
    assert_eq!(asked, expected);
}

#[tokio::test]
async fn a_viewer_is_refused_the_changes_and_may_read() {
    let (router, policy) = with_policy(true, false);
    for (method, path, action, _) in operations() {
        let reply = send(&router, method, &path).await;
        if action == Action::Read {
            reply.assert_problem(501, STUB);
        } else {
            reply.assert_problem(403, "auth.forbidden");
        }
    }
    // Without the scope even a read is refused.
    let (nothing, _) = with_policy(false, false);
    send(&nothing, "GET", "/dns/trust-anchors")
        .await
        .assert_problem(403, "auth.forbidden");
    send(&nothing, "GET", "/dns/ntas")
        .await
        .assert_problem(403, "auth.forbidden");
    assert_eq!(policy.asked().len(), operations().len());
}

#[tokio::test]
async fn the_node_routes_check_the_node_then_the_zone_kind() {
    let (router, policy) = with_policy(true, true);
    for (method, path, _, _) in node_operations() {
        send(&router, method, path).await.assert_problem(501, STUB);
    }
    let asked = policy.asked();
    assert_eq!(asked.len(), 2 * node_operations().len());
    for (n, (_, _, on_node, on_zone)) in node_operations().into_iter().enumerate() {
        assert_eq!(
            (asked[2 * n].0, asked[2 * n].1.kind),
            (on_node, ObjectKind::Node)
        );
        assert_eq!(
            (asked[2 * n + 1].0, asked[2 * n + 1].1.kind),
            (on_zone, ObjectKind::Zone)
        );
    }
}

#[tokio::test]
async fn a_viewer_is_refused_the_node_commands() {
    let (router, _) = with_policy(true, false);
    for (method, path, on_node, _) in node_operations() {
        let reply = send(&router, method, path).await;
        if on_node == Action::Read {
            reply.assert_problem(501, STUB);
        } else {
            reply.assert_problem(403, "auth.forbidden");
        }
    }
}

#[tokio::test]
async fn a_malformed_path_is_refused_before_anything_else() {
    let (router, policy) = with_policy(true, true);
    for (method, path) in [
        ("GET", "/nodes/0/dns/recursion"),
        ("POST", "/nodes/abc/dns/recursion/prime"),
        ("GET", "/nodes/-1/dns/infra"),
        ("POST", "/nodes/0/dns/infra/flush"),
        ("DELETE", "/dns/ntas/not-a-uuid"),
        ("GET", "/dns/trust-anchors/bad%20zone"),
        ("DELETE", "/dns/trust-anchors/a..b"),
        ("POST", "/dns/trust-anchors/a..b/refresh"),
    ] {
        send(&router, method, path)
            .await
            .assert_problem(400, "sys.invalid_request");
    }
    assert_eq!(policy.asked(), []);
}
