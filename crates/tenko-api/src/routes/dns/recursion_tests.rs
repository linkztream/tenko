//! Route tests of the recursive resolver's routes: each trust anchor operation (a stub of
//! WP10.0 until WP10.2) checks the scope of its action on the right kind and answers 501, a
//! viewer is refused, and a malformed path answers 400 before anything else. The node routes
//! (WP10.1) check the node and then the zone kind before they look for the role; the
//! mapping of the resolver's report is tested here, the routes over a role in
//! `tests/dns_recursion.rs`.

use std::{net::IpAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, header},
};
use serde_json::Value;
use tenko_core::{
    Action, Authorizer, ObjectKind, Timestamp,
    dns::{DnsName, QueryTransport, Rtype},
};
use tenko_dns::{
    infra::ServerFigures,
    log::Resolution,
    querylog::LogLine,
    recurse::{CounterValues, InfraAddressView, PrimingReport, RecursionReport, RootServer},
    recursion::{AddressOrigin, InfraSizes, WorkBudget, infra::EdnsSupport},
};
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;

use super::{
    nodes::line_dto,
    recursion::{address_dto, recursion_dto},
    routes,
};
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
    // No role runs in this router: the node is not known.
    for (method, path, _, _) in node_operations() {
        send(&router, method, path)
            .await
            .assert_problem(404, "cluster.node.not_found");
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
            reply.assert_problem(404, "cluster.node.not_found");
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

// WP10.1: the mapping of the resolver's report.
fn root_server(last: u8, srtt: Option<Duration>) -> RootServer {
    RootServer {
        name: DnsName::new("a.root-servers.test").expect("name"),
        address: IpAddr::from([192, 0, 2, last]),
        srtt,
    }
}

fn report() -> RecursionReport {
    RecursionReport {
        hints_source: "shipped".to_owned(),
        hints_date: "2026-01-31".to_owned(),
        priming: Some(PrimingReport {
            at: Timestamp::UNIX_EPOCH,
            ok: false,
            duration: Duration::from_micros(1_500),
        }),
        root_expires_in: None,
        root: vec![
            root_server(1, Some(Duration::from_micros(2_250))),
            root_server(2, None),
        ],
        infra: InfraSizes {
            cuts: 2,
            servers: 3,
            names: 4,
        },
        infra_bounds: (20, 30),
        counters: CounterValues {
            failure_hits: 5,
            bound_time: 6,
            ..CounterValues::default()
        },
        budget: WorkBudget {
            wall: Duration::from_millis(2_500),
            ..WorkBudget::DEFAULT
        },
        problems: vec!["priming_failed".to_owned()],
    }
}

#[test]
fn a_resolver_that_is_off_reads_as_empty() {
    let status = recursion_dto(None);
    assert!(!status.enabled);
    assert!(status.root_servers.is_empty() && status.problems.is_empty());
    assert!(status.last_priming.is_none() && status.root_expires_secs.is_none());
    assert_eq!(status.infra.max_zones, 0);
    assert_eq!(status.budget.wall_ms, 0);
    assert_eq!(status.counters.answered, 0);
}

#[test]
fn the_report_maps_field_by_field() {
    let status = recursion_dto(Some(report()));
    assert!(status.enabled);
    let priming = status.last_priming.expect("priming");
    assert_eq!(priming.outcome, "failed");
    assert!((priming.duration_ms - 1.5).abs() < 1e-9);
    assert_eq!(status.root_expires_secs, None);
    assert_eq!(status.root_servers[0].srtt_ms, Some(2.25));
    assert_eq!(status.root_servers[1].srtt_ms, None);
    assert_eq!(
        (
            status.infra.zones,
            status.infra.max_zones,
            status.infra.servers,
            status.infra.max_servers,
            status.infra.names
        ),
        (2, 20, 3, 30, 4)
    );
    assert_eq!(status.budget.queries, 32);
    assert_eq!(status.budget.wall_ms, 2_500);
    assert_eq!(status.counters.failure_cache_hits, 5);
    assert_eq!(status.counters.budget_time, 6);
    assert_eq!(status.problems, ["priming_failed"]);
    assert!(status.trust_anchors.is_empty());
}

#[test]
fn an_address_maps_its_figures_and_its_edns_support() {
    let view = |edns| InfraAddressView {
        address: IpAddr::from([192, 0, 2, 9]),
        origin: AddressOrigin::SiblingGlue,
        ttl: 60,
        figures: ServerFigures::default(),
        edns,
        tcp_only: false,
        lame: true,
    };
    let unknown = address_dto(&view(EdnsSupport::Unknown));
    assert_eq!(unknown.origin, "sibling_glue");
    assert_eq!(unknown.edns, None);
    assert!(unknown.srtt_ms.is_none() && unknown.p50_ms.is_none() && unknown.lame);
    assert_eq!(address_dto(&view(EdnsSupport::Yes)).edns, Some(true));
    assert_eq!(address_dto(&view(EdnsSupport::No)).edns, Some(false));
}

#[test]
fn a_log_line_carries_the_resolution_and_the_sub_queries() {
    let line = |resolution, subqueries| LogLine {
        at: Timestamp::UNIX_EPOCH,
        client: None,
        transport: QueryTransport::Udp,
        qname: "www.example.test".to_owned(),
        rtype: Rtype::A,
        rcode: 0,
        view: None,
        blocked: None,
        cached: false,
        duration_micros: 30,
        resolution,
        subqueries,
    };
    let recursed =
        serde_json::to_value(line_dto(line(Some(Resolution::Recurse), 5), false)).expect("JSON");
    assert_eq!(recursed["resolution"], "recurse");
    assert_eq!(recursed["subqueries"], 5);
    // An old line and a line without sub-queries leave the fields out.
    let old = serde_json::to_value(line_dto(line(None, 0), false)).expect("JSON");
    assert!(old.get("resolution").is_none() && old.get("subqueries").is_none());
}
// WP10.1: end.
