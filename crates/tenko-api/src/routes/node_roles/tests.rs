//! Route tests of `/nodes/{id}/roles` over the role service on an in-memory store: the
//! stored set with its revision, the refusals, the audit record and the findings of the own
//! node. Test data stays in the documentation ranges.

use std::sync::{Arc, Mutex};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, header},
};
use futures::future::BoxFuture;
use serde_json::{Value, json};
use tenko_cluster::model::{
    CertificateRef, MemberRecord, NodeRecord, ProtocolState,
    tables::{MEMBERS, NODES},
};
use tenko_core::{NodeId, RequestCtx, Role, RoleSet, SystemComponent, Timestamp};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt as _, Store, WriteBatch};
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;
use uuid::Uuid;

use super::{NodeRoleService, OwnNode, RoleHost, dns_resolver_finding, routes};
use crate::{
    API_BASE,
    dto::system::StatusWarning,
    routes::tenancy::testkit::{Policy, Reply},
    state::AppState,
};

/// This controller's node id.
const OWN: u64 = 1;
/// An enrolled probe.
const PROBE: u64 = 1001;

/// A host that reports what it was asked and answers a fixed finding when the dns role
/// leaves.
#[derive(Default)]
struct Host {
    supervised: bool,
    asked: Mutex<Vec<(RoleSet, RoleSet)>>,
}

impl RoleHost for Host {
    fn supervised(&self) -> bool {
        self.supervised
    }

    fn findings(&self, configured: RoleSet, running: RoleSet) -> BoxFuture<'_, Vec<StatusWarning>> {
        Box::pin(async move {
            self.asked.lock().expect("lock").push((configured, running));
            if running.contains(Role::Dns) && !configured.contains(Role::Dns) {
                vec![dns_resolver_finding("/etc/tenko/installer.state")]
            } else {
                Vec::new()
            }
        })
    }
}

struct Api {
    router: Router,
    store: Arc<MemStore>,
    service: Arc<NodeRoleService>,
}

fn roles(text: &str) -> RoleSet {
    text.parse().expect("roles")
}

impl Api {
    fn new(running: &str, pinned: bool, supervised: bool) -> Self {
        let store = Arc::new(MemStore::default());
        let host = Arc::new(Host {
            supervised,
            ..Host::default()
        });
        let service = Arc::new(NodeRoleService::new(
            Arc::clone(&store) as Arc<dyn Store>,
            OwnNode {
                id: NodeId(OWN),
                running: roles(running),
                pinned,
            },
            host,
        ));
        let router = Self::router(AppState::default(), &service);
        Self {
            router,
            store,
            service,
        }
    }

    fn router(state: AppState, service: &Arc<NodeRoleService>) -> Router {
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        router
            .with_state(state)
            .layer(Extension(Arc::clone(service)))
    }

    async fn send_to(
        router: &Router,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let body = match body {
            Some(body) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = router
            .clone()
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let text = |name| {
            response
                .headers()
                .get(name)
                .map(|v: &header::HeaderValue| v.to_str().expect("text").to_owned())
        };
        let content_type = text(header::CONTENT_TYPE).unwrap_or_default();
        let etag = text(header::ETAG);
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
            etag,
            body,
        }
    }

    async fn get(&self, node: u64) -> Reply {
        Self::send_to(
            &self.router,
            "GET",
            &format!("/nodes/{node}/roles"),
            &[],
            None,
        )
        .await
    }

    async fn put(&self, node: u64, if_match: Option<&str>, roles: &[&str]) -> Reply {
        let headers: Vec<(&str, &str)> =
            if_match.map(|tag| ("if-match", tag)).into_iter().collect();
        Self::send_to(
            &self.router,
            "PUT",
            &format!("/nodes/{node}/roles"),
            &headers,
            Some(json!({ "roles": roles })),
        )
        .await
    }

    async fn write(&self, batch: WriteBatch) {
        self.store.propose(batch).await.expect("written");
    }

    /// Enrols a node with `roles` directly in the registry table.
    async fn enrol(&self, id: u64, roles: &[Role]) {
        let now = Timestamp::now();
        let certificate = CertificateRef {
            serial: format!("{id:x}"),
            sha256: "00".repeat(32),
            not_before: now,
            not_after: now,
        };
        let record = NodeRecord {
            id: NodeId(id),
            name: format!("probe-{id}.example.test"),
            roles: roles.to_vec(),
            address: Some("192.0.2.10".to_owned()),
            vrf: None,
            certificate: certificate.clone(),
            serials: vec![certificate],
            enrolled_at: now,
            enrolment: Uuid::now_v7(),
            enrolled_by: None,
            renewed_at: None,
            last_seen: None,
            version: None,
            protocol: ProtocolState::default(),
        };
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Cluster));
        batch.put_typed(&NODES, &id, &record).expect("record");
        self.write(batch).await;
    }

    /// Records `id` as a member of the controller cluster.
    async fn member(&self, id: u64) {
        let record = MemberRecord {
            node: NodeId(id),
            address: "192.0.2.20:8444".to_owned(),
            version: "0.0.1".to_owned(),
            data_format: 1,
            joined_at: Timestamp::now(),
            protocol_majors: Vec::new(),
            raft_wire: None,
            formats: Vec::new(),
        };
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Cluster));
        batch.put_typed(&MEMBERS, &id, &record).expect("member");
        self.write(batch).await;
    }

    async fn audit_count(&self) -> usize {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.scan(
            tenko_store::tables::AUDIT.name(),
            KeyRange::all(),
            100,
            false,
        )
        .expect("audit")
        .len()
    }
}

#[tokio::test]
async fn the_own_set_round_trips_with_its_revision_and_audit() {
    let api = Api::new("controller,dns", false, false);
    let before = api.get(OWN).await;
    before.assert_json(200);
    assert_eq!(before.body["stored"], false, "{}", before.body);
    assert_eq!(before.body["configured"], json!(["controller", "dns"]));
    assert_eq!(before.body["running"], json!(["controller", "dns"]));
    assert_eq!(before.body["controller"], true);
    assert_eq!(before.body["restart"], "none");
    assert!(before.etag.is_none(), "no revision while none is stored");

    let changed = api.put(OWN, None, &["controller", "dns", "dhcp"]).await;
    changed.assert_json(200);
    assert_eq!(
        changed.body["configured"],
        json!(["controller", "dns", "dhcp"])
    );
    assert_eq!(changed.body["running"], json!(["controller", "dns"]));
    assert_eq!(changed.body["origin"], "api");
    assert_eq!(changed.body["restart"], "required", "no service manager");
    let etag = changed.etag.clone().expect("etag");
    assert_eq!(api.audit_count().await, 1);
    let view = api.store.read(ReadConsistency::Local).await.expect("view");
    let audit = view
        .scan_typed(&tenko_store::tables::AUDIT, KeyRange::all(), 10, false)
        .expect("audit");
    let record = &audit[0].1.draft;
    assert_eq!(record.action.as_str(), "nodes.roles");
    assert_eq!(
        record.details.changes[0].old.as_deref(),
        Some("controller,dns")
    );
    assert_eq!(
        record.details.changes[0].new.as_deref(),
        Some("controller,dns,dhcp")
    );
    drop(view);

    // A stale revision is refused; the current one passes.
    api.put(OWN, Some("\"999\""), &["controller"])
        .await
        .assert_problem(412, "node.roles.revision_mismatch");
    let back = api.put(OWN, Some(&etag), &["controller", "dns"]).await;
    back.assert_json(200);
    assert_eq!(back.body["restart"], "none", "back to the running set");
    // The same set again writes nothing.
    api.put(OWN, None, &["controller", "dns"])
        .await
        .assert_json(200);
    assert_eq!(api.audit_count().await, 2);
}

#[tokio::test]
async fn a_supervised_node_schedules_its_restart_and_reports_findings() {
    let api = Api::new("controller,dns", false, true);
    let changed = api.put(OWN, None, &["controller", "dhcp"]).await;
    changed.assert_json(200);
    assert_eq!(changed.body["restart"], "scheduled");
    let findings = changed.body["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), 1, "{}", changed.body);
    assert_eq!(findings[0]["code"], "node.roles.dns_resolver");
    assert_eq!(findings[0]["params"]["file"], "/etc/tenko/installer.state");
}

#[tokio::test]
async fn the_refusals() {
    let api = Api::new("controller,dns", false, false);
    // The last controller keeps its role.
    api.put(OWN, None, &["dns"])
        .await
        .assert_problem(409, "node.roles.last_controller");
    // With a second controller the role still follows the membership.
    api.member(2).await;
    api.put(OWN, None, &["dns"])
        .await
        .assert_problem(409, "node.roles.controller");
    api.get(2).await.assert_json(200);
    // An enrolled node runs the probe role only, and never the controller role.
    api.enrol(PROBE, &[Role::Probe]).await;
    let probe = api.get(PROBE).await;
    probe.assert_json(200);
    assert_eq!(probe.body["configured"], json!(["probe"]));
    assert_eq!(probe.body["controller"], false);
    assert_eq!(probe.body["restart"], "on_node");
    api.put(PROBE, None, &["probe", "dns"])
        .await
        .assert_problem(422, "node.roles.unsupported");
    api.put(PROBE, None, &["controller", "probe"])
        .await
        .assert_problem(409, "node.roles.controller");
    api.put(PROBE, None, &[])
        .await
        .assert_problem(422, "node.roles.empty");
    api.put(PROBE, None, &["probe"]).await.assert_json(200);
    // Unknown nodes and malformed input.
    api.get(77)
        .await
        .assert_problem(404, "cluster.node.not_found");
    api.put(77, None, &["probe"])
        .await
        .assert_problem(404, "cluster.node.not_found");
    api.get(0).await.assert_problem(400, "sys.invalid_request");
    let unknown = api.put(OWN, None, &["controller", "ntp"]).await;
    assert_eq!(unknown.status.as_u16(), 400, "{}", unknown.body);
    // Nothing was written but the probe's set.
    assert_eq!(api.audit_count().await, 1);
}

#[tokio::test]
async fn a_pinned_node_refuses_a_change() {
    let api = Api::new("controller,dns,dhcp", true, true);
    let read = api.get(OWN).await;
    read.assert_json(200);
    assert_eq!(read.body["pinned"], true);
    api.put(OWN, None, &["controller"])
        .await
        .assert_problem(409, "node.roles.pinned");
    assert_eq!(api.audit_count().await, 0);
}

#[tokio::test]
async fn reads_pass_and_changes_need_the_right_permission() {
    let api = Api::new("controller", false, false);
    let policy = Policy::new(true, false);
    let router = Api::router(
        AppState {
            authorizer: Some(policy.clone()),
            ..AppState::default()
        },
        &api.service,
    );
    Api::send_to(&router, "GET", "/nodes/1/roles", &[], None)
        .await
        .assert_json(200);
    let put = Api::send_to(
        &router,
        "PUT",
        "/nodes/1/roles",
        &[],
        Some(json!({ "roles": ["controller", "dns"] })),
    )
    .await;
    assert_eq!(put.status.as_u16(), 403, "{}", put.body);
    assert_eq!(api.audit_count().await, 0);
}

#[tokio::test]
async fn without_the_service_the_routes_are_stubs() {
    let (router, _) = OpenApiRouter::<AppState>::new()
        .nest(API_BASE, routes())
        .split_for_parts();
    let router = router.with_state(AppState::default());
    Api::send_to(&router, "GET", "/nodes/1/roles", &[], None)
        .await
        .assert_problem(501, "sys.not_implemented");
}
