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

// WP9.4: the router advertisement check and the server DUID in the node report.
#[test]
fn the_node_report_carries_the_ra_check_and_the_server_duid() {
    use std::collections::BTreeMap;

    use tenko_core::{Revision, Timestamp, dhcp::BindingState};
    use tenko_dhcp::{
        ra::{FLAGS_OFF, RaCheck, RaFinding, RaLinkReport, RaReport},
        role::DhcpStatus,
    };

    let none = [
        (BindingState::Free, 0),
        (BindingState::Active, 0),
        (BindingState::Expired, 0),
        (BindingState::Released, 0),
        (BindingState::Abandoned, 0),
        (BindingState::Reset, 0),
        (BindingState::Backup, 0),
    ];
    let status = |ra: RaReport, server_duid: Option<Vec<u8>>| DhcpStatus {
        node: NodeId(7),
        serving: true,
        accepting: true,
        refusal: None,
        probe: true,
        probe_expected: false,
        listeners: Vec::new(),
        scopes: 0,
        leases: none,
        last_commit: None,
        revision: Revision::ZERO,
        lag: 0,
        started: Timestamp::UNIX_EPOCH,
        installs: 0,
        proxies: Vec::new(),
        listeners6: Vec::new(),
        scopes6: 1,
        leases6: none,
        ra,
        server_duid,
    };
    let seen: Timestamp = "2026-10-25T12:00:00Z".parse().expect("time");
    let watching = RaReport {
        check: RaCheck::Watching,
        links: vec![RaLinkReport {
            interface: "eth1".to_owned(),
            routers: vec!["fe80::2".parse().expect("router")],
            managed: false,
            other: false,
            prefixes: vec!["2001:db8:30::/64".parse().expect("prefix")],
            scopes: vec!["2001:db8:30::/64".parse().expect("scope")],
            seen,
        }],
        findings: vec![RaFinding {
            code: FLAGS_OFF,
            interface: "eth1".to_owned(),
            detail: "neither M nor O".to_owned(),
            params: BTreeMap::from([
                ("interface".to_owned(), "eth1".to_owned()),
                ("routers".to_owned(), "fe80::2".to_owned()),
                ("scopes".to_owned(), "2001:db8:30::/64".to_owned()),
            ]),
        }],
    };
    let duid = vec![0, 1, 0, 1, 0x2e, 0x8b, 0x58, 0, 0, 0, 0x5e, 0, 0x53, 0x10];
    let dto = super::leases::status_dto(status(watching, Some(duid)));
    let json = serde_json::to_value(&dto).expect("json");
    assert_eq!(json["server_duid"], "000100012e8b580000005e005310");
    assert_eq!(json["ra"]["check"], "watching");
    assert!(json["ra"].get("reason").is_none());
    assert_eq!(
        json["ra"]["links"],
        json!([{
            "interface": "eth1",
            "routers": ["fe80::2"],
            "managed": false,
            "other": false,
            "prefixes": ["2001:db8:30::/64"],
            "scopes": ["2001:db8:30::/64"],
            "seen": "2026-10-25T12:00:00Z",
        }])
    );
    assert_eq!(json["ra"]["findings"][0]["code"], "dhcp.ra.flags_off");
    assert_eq!(json["ra"]["findings"][0]["params"]["routers"], "fe80::2");

    let unavailable = RaReport {
        check: RaCheck::Unavailable("no CAP_NET_RAW".to_owned()),
        ..RaReport::default()
    };
    let json =
        serde_json::to_value(super::leases::status_dto(status(unavailable, None))).expect("json");
    assert_eq!(json["ra"]["check"], "unavailable");
    assert_eq!(json["ra"]["reason"], "no CAP_NET_RAW");
    assert!(json.get("server_duid").is_none());
    let json = serde_json::to_value(super::leases::status_dto(status(RaReport::default(), None)))
        .expect("json");
    assert_eq!(json["ra"]["check"], "off");
}
