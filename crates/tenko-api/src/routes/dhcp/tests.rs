//! Route tests of the DHCP contracts: every operation checks the scope of its action on the
//! right object before anything else answers, and refuses a malformed path first. Without
//! the configuration service the configuration routes answer 409 `dhcp.module.disabled`
//! after the check; the routes of later packages answer 501. The operations themselves are
//! tested over the service in `tests/dhcp_*.rs`.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, header},
};
use serde_json::{Value, json};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, Authorizer, NodeId, ObjectKind, ObjectRef, PrefixId,
    dhcp::{ClassId, PolicyId, scope_object, server_object},
};
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;
use uuid::Uuid;

use super::{reconcile_routes, routes};
use crate::{
    API_BASE,
    routes::tenancy::testkit::{Policy, Reply},
    state::AppState,
};

const PREFIX: &str = "0190d1c2-0000-7000-8000-000000000001";
const OTHER: &str = "0190d1c2-0000-7000-8000-000000000002";
const DISABLED: &str = "dhcp.module.disabled";
const STUB: &str = "sys.not_implemented";
// WP7.5: the lease routes of a server without the dhcp role.
const NOT_DHCP: &str = "dhcp.node.not_dhcp";

fn id(text: &str) -> Uuid {
    text.parse().expect("UUID")
}

fn router(state: AppState) -> Router {
    let (router, _) = OpenApiRouter::<AppState>::new()
        .nest(API_BASE, routes().merge(reconcile_routes()))
        .split_for_parts();
    router.with_state(state)
}

/// A JSON body that the route accepts, for the requests that need one.
fn body_for(method: &str, path: &str) -> Option<Value> {
    if !matches!(method, "POST" | "PUT" | "PATCH") || path.contains("/release") {
        return None;
    }
    Some(match (method, path) {
        ("POST", "/dhcp/scopes") => json!({ "prefix": PREFIX }),
        ("POST", p) if p.ends_with("/exclusions") => {
            json!({ "first": "192.0.2.10", "last": "192.0.2.19" })
        }
        ("POST", "/dhcp/shared-networks") => json!({ "name": "lan" }),
        ("POST", "/dhcp/option-defs") => json!({ "code": 224, "name": "site", "kind": "u8" }),
        ("POST", "/dhcp/classes") => json!({ "name": "pxe", "matches": [] }),
        ("POST", "/dhcp/policies") => {
            json!({ "name": "uefi", "condition": { "join": "and", "terms": [] } })
        }
        ("POST", "/dhcp/filters") => json!({ "mac": "00:00:5e:00:53:01", "kind": "deny" }),
        _ => json!({}),
    })
}

async fn send(router: &Router, method: &str, path: &str) -> Reply {
    let builder = Request::builder()
        .method(method)
        .uri(format!("{API_BASE}{path}"));
    let request = match body_for(method, path) {
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

/// The (action, kind) pairs the policy was asked.
fn kinds(policy: &Policy) -> Vec<(Action, ObjectKind)> {
    policy.asked().iter().map(|(a, o)| (*a, o.kind)).collect()
}

/// Sends every request and expects, after the check, 409 `dhcp.module.disabled` (a
/// configuration route without its service), 409 `dhcp.node.not_dhcp` (a lease or history
/// route of a server without the dhcp role, WP7.5), 404 `cluster.node.not_found` (a node
/// route for a node this server does not know) or 501 (a route of a later package).
async fn expect_after_check(router: &Router, requests: &[(&str, String)]) {
    for (method, path) in requests {
        // WP9.3: the export is built; without the configuration service it is disabled.
        let later = path.contains("/reservations");
        let reply = send(router, method, path).await;
        if later {
            reply.assert_problem(501, STUB);
        } else if path.starts_with("/ipam/") {
            // WP8.2: the view is built; this router has no IPAM service.
            reply.assert_problem(503, "ipam.unavailable");
        } else if path.starts_with("/nodes/") {
            reply.assert_problem(404, "cluster.node.not_found");
        } else if path.contains("/leases") || path.contains("/history") {
            reply.assert_problem(409, NOT_DHCP);
        } else if path == "/dhcp/option-catalog" {
            reply.assert_json(200);
        } else {
            reply.assert_problem(409, DISABLED);
        }
    }
}

#[tokio::test]
async fn an_allowed_call_reaches_the_service_or_the_stub() {
    let (router, policy) = with_policy(true, true);
    send(
        &router,
        "POST",
        &format!("/dhcp/scopes/{PREFIX}/exclusions"),
    )
    .await
    .assert_problem(409, DISABLED);
    let reply = send(&router, "POST", "/dhcp/leases/192.0.2.50/release").await;
    reply.assert_problem(409, NOT_DHCP);
    assert_eq!(
        policy.asked(),
        [
            (Action::Update, scope_object(PrefixId(id(PREFIX)))),
            (Action::Execute, anywhere(ObjectKind::DhcpScope)),
        ]
    );
}

#[tokio::test]
async fn a_reader_reads_and_is_refused_writes() {
    let (router, policy) = with_policy(true, false);
    send(&router, "GET", "/dhcp/scopes")
        .await
        .assert_problem(409, DISABLED);
    send(&router, "POST", "/dhcp/scopes")
        .await
        .assert_problem(403, "auth.forbidden");
    send(&router, "PUT", "/dhcp/settings")
        .await
        .assert_problem(403, "auth.forbidden");
    send(&router, "DELETE", &format!("/dhcp/classes/{PREFIX}"))
        .await
        .assert_problem(403, "auth.forbidden");
    send(&router, "POST", "/dhcp/leases/192.0.2.50/release")
        .await
        .assert_problem(403, "auth.forbidden");
    send(&router, "GET", "/dhcp/leases")
        .await
        .assert_problem(409, NOT_DHCP);
    send(&router, "PUT", &format!("/dhcp/pools/{PREFIX}"))
        .await
        .assert_problem(403, "auth.forbidden");
    // WP8.2: the view is built; this router has no IPAM service.
    send(&router, "GET", "/ipam/reconcile")
        .await
        .assert_problem(503, "ipam.unavailable");
    assert_eq!(
        kinds(&policy),
        [
            (Action::Read, ObjectKind::DhcpScope),
            (Action::Create, ObjectKind::DhcpScope),
            (Action::Update, ObjectKind::DhcpScope),
            (Action::Delete, ObjectKind::DhcpClass),
            (Action::Execute, ObjectKind::DhcpScope),
            (Action::Read, ObjectKind::DhcpScope),
            (Action::Update, ObjectKind::DhcpScope),
            (Action::Read, ObjectKind::Observation),
        ]
    );
}

#[tokio::test]
async fn scopes_are_checked_on_the_prefix() {
    let (router, policy) = with_policy(true, true);
    expect_after_check(
        &router,
        &[
            ("GET", format!("/dhcp/scopes/{PREFIX}")),
            ("PATCH", format!("/dhcp/scopes/{PREFIX}")),
            ("DELETE", format!("/dhcp/scopes/{PREFIX}")),
            ("GET", format!("/dhcp/scopes/{PREFIX}/utilization")),
            ("GET", format!("/dhcp/scopes/{PREFIX}/effective-options")),
            ("GET", format!("/dhcp/scopes/{PREFIX}/exclusions")),
            ("POST", format!("/dhcp/scopes/{PREFIX}/exclusions")),
            (
                "DELETE",
                format!("/dhcp/scopes/{PREFIX}/exclusions/{OTHER}"),
            ),
        ],
    )
    .await;
    let scope = scope_object(PrefixId(id(PREFIX)));
    assert_eq!(scope.kind, ObjectKind::DhcpScope);
    assert_eq!(
        policy.asked(),
        [
            (Action::Read, scope),
            (Action::Update, scope),
            (Action::Delete, scope),
            (Action::Read, scope),
            (Action::Read, scope),
            (Action::Read, scope),
            (Action::Update, scope),
            (Action::Update, scope),
        ]
    );
}

#[tokio::test]
async fn a_scope_is_created_with_the_kind_and_its_prefix() {
    let (router, policy) = with_policy(true, true);
    send(&router, "POST", "/dhcp/scopes")
        .await
        .assert_problem(409, DISABLED);
    assert_eq!(
        policy.asked(),
        [
            (Action::Create, anywhere(ObjectKind::DhcpScope)),
            (Action::Create, scope_object(PrefixId(id(PREFIX)))),
        ]
    );
}

#[tokio::test]
async fn server_wide_configuration_is_checked_on_the_singleton() {
    let (router, policy) = with_policy(true, true);
    expect_after_check(
        &router,
        &[
            ("GET", "/dhcp/settings".to_owned()),
            ("PUT", "/dhcp/settings".to_owned()),
            ("GET", "/dhcp/shared-networks".to_owned()),
            ("POST", "/dhcp/shared-networks".to_owned()),
            ("PATCH", format!("/dhcp/shared-networks/{PREFIX}")),
            ("DELETE", format!("/dhcp/shared-networks/{PREFIX}")),
            ("GET", "/dhcp/export".to_owned()),
        ],
    )
    .await;
    let server = server_object();
    assert_eq!(server.id, Uuid::nil());
    assert_eq!(
        policy.asked(),
        [
            (Action::Read, server),
            (Action::Update, server),
            (Action::Read, server),
            (Action::Create, server),
            (Action::Update, server),
            (Action::Delete, server),
            (Action::Read, server),
        ]
    );
}

#[tokio::test]
async fn objects_are_checked_on_their_own_kind() {
    let (router, policy) = with_policy(true, true);
    expect_after_check(
        &router,
        &[
            ("GET", "/dhcp/option-catalog".to_owned()),
            ("POST", "/dhcp/option-defs".to_owned()),
            ("PATCH", format!("/dhcp/option-defs/{PREFIX}")),
            ("GET", format!("/dhcp/classes/{PREFIX}")),
            ("PATCH", format!("/dhcp/classes/{OTHER}")),
            ("DELETE", format!("/dhcp/policies/{PREFIX}")),
            ("GET", "/dhcp/policies".to_owned()),
            ("POST", "/dhcp/filters".to_owned()),
            ("DELETE", format!("/dhcp/filters/{PREFIX}")),
            ("GET", "/dhcp/pools".to_owned()),
            ("DELETE", format!("/dhcp/pools/{PREFIX}")),
            ("GET", format!("/dhcp/reservations/{PREFIX}")),
            ("GET", "/dhcp/history".to_owned()),
            ("GET", "/dhcp/leases/192.0.2.50".to_owned()),
            ("POST", "/dhcp/leases/192.0.2.50/release".to_owned()),
        ],
    )
    .await;
    assert_eq!(
        kinds(&policy),
        [
            (Action::Read, ObjectKind::DhcpOptionDef),
            (Action::Create, ObjectKind::DhcpOptionDef),
            (Action::Update, ObjectKind::DhcpOptionDef),
            (Action::Read, ObjectKind::DhcpClass),
            (Action::Update, ObjectKind::DhcpClass),
            (Action::Delete, ObjectKind::DhcpPolicy),
            (Action::Read, ObjectKind::DhcpPolicy),
            (Action::Create, ObjectKind::DhcpFilter),
            (Action::Delete, ObjectKind::DhcpFilter),
            (Action::Read, ObjectKind::DhcpScope),
            (Action::Update, ObjectKind::DhcpScope),
            (Action::Read, ObjectKind::DhcpScope),
            (Action::Read, ObjectKind::DhcpScope),
            (Action::Read, ObjectKind::DhcpScope),
            (Action::Execute, ObjectKind::DhcpScope),
        ]
    );
    let asked = policy.asked();
    assert_eq!(asked[3].1, ObjectRef::from(ClassId(id(PREFIX))));
    assert_eq!(asked[4].1, ObjectRef::from(ClassId(id(OTHER))));
    assert_eq!(asked[5].1, ObjectRef::from(PolicyId(id(PREFIX))));
}

#[tokio::test]
async fn option_set_owners_map_to_their_objects() {
    let (router, policy) = with_policy(true, true);
    expect_after_check(
        &router,
        &[
            ("GET", "/dhcp/option-sets".to_owned()),
            ("GET", "/dhcp/option-sets/server".to_owned()),
            ("PUT", format!("/dhcp/option-sets/shared_network:{OTHER}")),
            ("GET", format!("/dhcp/option-sets/scope:{PREFIX}")),
            ("PUT", format!("/dhcp/option-sets/pool:{PREFIX}")),
            ("DELETE", format!("/dhcp/option-sets/policy:{OTHER}")),
            ("PUT", format!("/dhcp/option-sets/host:{OTHER}")),
        ],
    )
    .await;
    let server = server_object();
    assert_eq!(
        policy.asked(),
        [
            (Action::Read, anywhere(ObjectKind::DhcpScope)),
            (Action::Read, server),
            (Action::Update, server),
            (Action::Read, scope_object(PrefixId(id(PREFIX)))),
            (Action::Update, anywhere(ObjectKind::DhcpScope)),
            (Action::Update, ObjectRef::from(PolicyId(id(OTHER)))),
            (
                Action::Update,
                ObjectRef::new(ObjectKind::Interface, id(OTHER))
            ),
        ]
    );
}

#[tokio::test]
async fn node_routes_check_the_node_first() {
    let (router, policy) = with_policy(true, true);
    expect_after_check(
        &router,
        &[
            ("GET", "/nodes/1001/dhcp".to_owned()),
            ("GET", "/nodes/1001/dhcp/leases".to_owned()),
            (
                "POST",
                "/nodes/1001/dhcp/leases/192.0.2.50/release".to_owned(),
            ),
            ("GET", "/nodes/1001/dhcp/history".to_owned()),
        ],
    )
    .await;
    let node = ObjectRef::node(NodeId(1001));
    let any = anywhere(ObjectKind::DhcpScope);
    assert_eq!(
        policy.asked(),
        [
            (Action::Read, node),
            (Action::Read, any),
            (Action::Read, node),
            (Action::Read, any),
            (Action::Update, node),
            (Action::Execute, any),
            (Action::Read, node),
            (Action::Read, any),
        ]
    );
}

#[tokio::test]
async fn a_malformed_path_is_refused_before_anything_else() {
    let (router, policy) = with_policy(true, true);
    for (method, path) in [
        ("GET", "/dhcp/scopes/not-a-uuid"),
        ("DELETE", "/dhcp/scopes/not-a-uuid/exclusions/not-a-uuid"),
        ("DELETE", &format!("/dhcp/scopes/{PREFIX}/exclusions/x")),
        ("GET", "/dhcp/classes/not-a-uuid"),
        ("GET", "/dhcp/pools/not-a-uuid"),
        ("GET", "/dhcp/reservations/not-a-uuid"),
        ("GET", "/dhcp/option-sets/zone:x"),
        ("PUT", "/dhcp/option-sets/scope:not-a-uuid"),
        ("GET", "/dhcp/leases/not-an-address"),
        ("POST", "/dhcp/leases/not-an-address/release"),
        ("GET", "/nodes/0/dhcp"),
        ("GET", "/nodes/x/dhcp/history"),
        // WP9.4: an IPv6 address is a lease address; a malformed one is not.
        ("POST", "/nodes/1001/dhcp/leases/2001:db8::zz/release"),
    ] {
        send(&router, method, path)
            .await
            .assert_problem(400, "sys.invalid_request");
    }
    assert_eq!(policy.asked(), []);
}
