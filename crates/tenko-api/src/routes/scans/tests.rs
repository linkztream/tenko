//! Route tests of the scan area over the scan control on an in-memory store, a job engine
//! and an in-memory vault. Test data stays in the documentation ranges.

use std::sync::Arc;

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, header},
};
use serde_json::{Value, json};
use tenko_cluster::model::{CertificateRef, NodeRecord, ProtocolState, tables::NODES};
use tenko_core::{NodeId, RequestCtx, Role, SystemComponent, Timestamp, secret::SecretRef};
use tenko_jobs::{EngineConfig, JobEngine};
use tenko_scan::control::ScanControl;
use tenko_store::{MemStore, Store, WriteBatch};
use tenko_vault::{
    MemVault, SecretBytes, SecretPurpose, SecretSpec, Vault, operator::OPERATOR_PURPOSE,
};
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;
use uuid::Uuid;

use super::routes;
use crate::{
    API_BASE,
    routes::tenancy::testkit::{Policy, Reply},
    state::AppState,
};

/// This controller's node id; it runs the probe role in process.
const LOCAL: u64 = 1;

struct Api {
    router: Router,
    store: Arc<MemStore>,
    vault: Arc<MemVault>,
    control: Arc<ScanControl>,
}

impl Api {
    fn new() -> Self {
        Self::with_state(AppState::default())
    }

    fn with_state(state: AppState) -> Self {
        let store = Arc::new(MemStore::default());
        let vault = Arc::new(MemVault::with_store(Arc::clone(&store)));
        let dyn_store: Arc<dyn Store> = Arc::clone(&store) as Arc<dyn Store>;
        let engine = JobEngine::new(Arc::clone(&dyn_store), EngineConfig::default());
        let control = ScanControl::new(
            dyn_store,
            &engine,
            Some(Arc::clone(&vault) as Arc<dyn Vault>),
            Some(NodeId(LOCAL)),
        );
        let router = Self::router(state, &control);
        Self {
            router,
            store,
            vault,
            control,
        }
    }

    fn router(state: AppState, control: &Arc<ScanControl>) -> Router {
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        router
            .with_state(state)
            .layer(Extension(Arc::clone(control)))
    }

    /// The same control behind other checks.
    fn sibling(&self, state: AppState) -> Router {
        Self::router(state, &self.control)
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
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().expect("text").to_owned())
            .unwrap_or_default();
        let etag = response
            .headers()
            .get(header::ETAG)
            .map(|v| v.to_str().expect("text").to_owned());
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

    async fn send(&self, method: &str, path: &str, body: Option<Value>) -> Reply {
        Self::send_to(&self.router, method, path, &[], body).await
    }

    async fn put_config(&self, node: u64, if_match: Option<&str>, body: Value) -> Reply {
        let headers: Vec<(&str, &str)> =
            if_match.map(|tag| ("if-match", tag)).into_iter().collect();
        Self::send_to(
            &self.router,
            "PUT",
            &format!("/nodes/{node}/scan-config"),
            &headers,
            Some(body),
        )
        .await
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
        self.store.propose(batch).await.expect("enrolled");
    }

    async fn operator_secret(&self) -> SecretRef {
        self.vault
            .put_operator(
                &RequestCtx::system(SystemComponent::Api),
                SecretSpec::new(SecretPurpose::from_static(OPERATOR_PURPOSE))
                    .labelled("switch.example.test"),
                SecretBytes::from("correct horse battery".to_owned()),
            )
            .await
            .expect("secret")
    }
}

fn scan(kind: &str, value: &str) -> Value {
    json!({ "target": { "kind": kind, "value": value }, "kinds": ["passive_refresh"] })
}

#[tokio::test]
async fn a_probe_configuration_round_trips_with_its_revision() {
    let api = Api::new();
    let empty = api.send("GET", "/nodes/1/scan-config", None).await;
    empty.assert_json(200);
    assert_eq!(empty.body["stored"], false, "{}", empty.body);
    assert_eq!(empty.body["in_sync"], true);
    assert_eq!(empty.body["kill_switch"]["stopped"], false);
    assert_eq!(empty.etag, None);

    let stored = api
        .put_config(
            LOCAL,
            None,
            json!({ "prefixes": ["192.0.2.0/24"], "active": false }),
        )
        .await;
    stored.assert_json(200);
    assert_eq!(stored.body["stored"], true, "{}", stored.body);
    assert_eq!(stored.body["origin"], "api");
    assert_eq!(stored.body["config"]["prefixes"][0], "192.0.2.0/24");
    assert_eq!(stored.body["config"]["active"], false);
    assert_eq!(
        stored.body["in_sync"], false,
        "the probe has not reported yet"
    );
    let revision = stored.body["revision"].as_u64().expect("revision");
    let tag = format!("\"{revision}\"");
    assert_eq!(stored.etag.as_deref(), Some(tag.as_str()));

    let read = api.send("GET", "/nodes/1/scan-config", None).await;
    read.assert_json(200);
    assert_eq!(read.etag.as_deref(), Some(tag.as_str()));

    let fresh = api
        .put_config(
            LOCAL,
            Some(&tag),
            json!({ "prefixes": ["198.51.100.0/24"] }),
        )
        .await;
    fresh.assert_json(200);
    assert!(fresh.body["revision"].as_u64().expect("revision") > revision);
    let stale = api
        .put_config(LOCAL, Some(&tag), json!({ "prefixes": ["203.0.113.0/24"] }))
        .await;
    stale.assert_problem(412, "node.config.revision_mismatch");
    let bad_tag = api
        .put_config(LOCAL, Some("seven"), json!({ "prefixes": [] }))
        .await;
    assert_eq!(bad_tag.status.as_u16(), 400, "{}", bad_tag.body);
}

#[tokio::test]
async fn passwords_are_refused_and_secrets_must_be_operator_secrets() {
    let api = Api::new();
    let inline = api
        .put_config(
            LOCAL,
            None,
            json!({ "snmp": { "enabled": true, "devices": [{
                "address": "192.0.2.2", "user": "monitor", "auth": "sha256",
                "auth_password": "correct horse battery"
            }] } }),
        )
        .await;
    inline.assert_problem(422, "node.config.invalid");
    assert!(
        !inline.body.to_string().contains("correct horse"),
        "a refusal never repeats the password: {}",
        inline.body
    );

    let unknown = api
        .put_config(
            LOCAL,
            None,
            json!({ "snmp": { "enabled": true, "devices": [{
                "address": "192.0.2.2", "user": "monitor", "auth": "sha256",
                "auth_secret": Uuid::now_v7().to_string()
            }] } }),
        )
        .await;
    unknown.assert_problem(422, "node.config.secret");

    let secret = api.operator_secret().await;
    let named = api
        .put_config(
            LOCAL,
            None,
            json!({ "prefixes": ["192.0.2.0/24"], "snmp": { "enabled": true, "devices": [
                { "address": "192.0.2.2", "user": "monitor", "auth": "sha256",
                  "auth_secret": secret.secret.to_string() },
                { "address": "192.0.2.3", "user": "monitor", "auth": "sha256" }
            ] } }),
        )
        .await;
    named.assert_json(200);
    assert_eq!(
        named.body["config"]["snmp"]["devices"][0]["auth_secret"],
        secret.secret.to_string()
    );
    assert_eq!(named.body["lacking_secrets"], json!(["192.0.2.3"]));
    assert!(!named.body.to_string().contains("correct horse"));
}

#[tokio::test]
async fn unknown_nodes_and_nodes_without_the_probe_role_are_refused() {
    let api = Api::new();
    api.enrol(1002, &[Role::Dns]).await;
    api.send("GET", "/nodes/77/scan-config", None)
        .await
        .assert_problem(404, "cluster.node.not_found");
    api.send("GET", "/nodes/1002/scan-config", None)
        .await
        .assert_problem(409, "node.config.not_a_probe");
    api.send("POST", "/nodes/1002/scan/stop", None)
        .await
        .assert_problem(409, "node.config.not_a_probe");
    api.send("GET", "/nodes/zero/scan-config", None)
        .await
        .assert_problem(400, "sys.invalid_request");
    api.send("GET", "/scans/seven", None)
        .await
        .assert_problem(400, "sys.invalid_request");
}

#[tokio::test]
async fn the_kill_switch_issues_one_command_per_probe() {
    let api = Api::new();
    api.enrol(1001, &[Role::Probe]).await;
    api.enrol(1002, &[Role::Dns]).await;
    let probes = api.send("GET", "/scans/probes", None).await;
    probes.assert_json(200);
    let nodes: Vec<u64> = probes.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["node"].as_u64().expect("node"))
        .collect();
    assert_eq!(nodes, vec![LOCAL, 1001]);
    assert_eq!(probes.body["items"][0]["in_process"], true);

    let stopped = api
        .send(
            "POST",
            "/scans/stop",
            Some(json!({ "reason": "maintenance window" })),
        )
        .await;
    stopped.assert_json(202);
    assert_eq!(stopped.body["commands"].as_array().map(Vec::len), Some(2));
    let view = api.send("GET", "/nodes/1001/scan-config", None).await;
    view.assert_json(200);
    assert_eq!(view.body["kill_switch"]["stopped"], true, "{}", view.body);
    assert_eq!(view.body["kill_switch"]["reason"], "maintenance window");
    assert_eq!(view.body["kill_switch"]["confirmed"], false);

    let resumed = api.send("POST", "/nodes/1001/scan/resume", None).await;
    resumed.assert_json(202);
    assert_eq!(resumed.body["commands"][0]["node"], 1001);
    let view = api.send("GET", "/nodes/1001/scan-config", None).await;
    assert_eq!(view.body["kill_switch"]["stopped"], false, "{}", view.body);
    // The local probe keeps its stop until it is resumed itself.
    let local = api.send("GET", "/nodes/1/scan-config", None).await;
    assert_eq!(local.body["kill_switch"]["stopped"], true, "{}", local.body);

    let one = api.send("POST", "/nodes/1/scan/stop", None).await;
    one.assert_json(202);
    assert_eq!(one.body["commands"].as_array().map(Vec::len), Some(1));
    api.send("POST", "/scans/resume", None)
        .await
        .assert_json(202);
    let bad = api
        .send("POST", "/scans/stop", Some(json!({ "why": "unknown key" })))
        .await;
    assert_eq!(bad.status.as_u16(), 400, "{}", bad.body);
}

#[tokio::test]
async fn a_scan_goes_to_the_probes_that_cover_the_target() {
    let api = Api::new();
    api.put_config(LOCAL, None, json!({ "prefixes": ["192.0.2.0/24"] }))
        .await
        .assert_json(200);
    let queued = api
        .send("POST", "/scans", Some(scan("network", "192.0.2.0/28")))
        .await;
    queued.assert_json(202);
    assert_eq!(queued.body["state"], "queued", "{}", queued.body);
    assert_eq!(queued.body["networks"], json!(["192.0.2.0/28"]));
    assert!(queued.body["job_id"].is_string(), "{}", queued.body);
    let id = queued.body["id"].as_str().expect("id").to_owned();

    let shown = api.send("GET", &format!("/scans/{id}"), None).await;
    shown.assert_json(200);
    assert_eq!(shown.body["id"], id);

    api.send("POST", "/scans", Some(scan("network", "198.51.100.0/24")))
        .await
        .assert_problem(422, "scan.job.no_probe");
    api.send(
        "POST",
        "/scans",
        Some(scan("prefix", &Uuid::now_v7().to_string())),
    )
    .await
    .assert_problem(404, "scan.job.target");
    api.send("POST", "/scans", Some(scan("address", "not an address")))
        .await
        .assert_problem(422, "scan.job.target");
    let mut short = scan("address", "192.0.2.9");
    short["deadline_secs"] = json!(5);
    api.send("POST", "/scans", Some(short))
        .await
        .assert_problem(422, "scan.job.invalid");
    api.send("GET", &format!("/scans/{}", Uuid::now_v7()), None)
        .await
        .assert_problem(404, "scan.job.not_found");
}

#[tokio::test]
async fn scans_list_newest_first_in_pages() {
    let api = Api::new();
    api.put_config(LOCAL, None, json!({ "prefixes": ["192.0.2.0/24"] }))
        .await
        .assert_json(200);
    let mut ids = Vec::new();
    for host in 1..=3 {
        let reply = api
            .send(
                "POST",
                "/scans",
                Some(scan("address", &format!("192.0.2.{host}"))),
            )
            .await;
        reply.assert_json(202);
        ids.push(reply.body["id"].as_str().expect("id").to_owned());
    }
    ids.reverse();
    let first = api.send("GET", "/scans?limit=2", None).await;
    first.assert_json(200);
    let listed: Vec<String> = first
        .items()
        .iter()
        .map(|item| item["id"].as_str().expect("id").to_owned())
        .collect();
    assert_eq!(listed, ids[..2]);
    let cursor = first.body["next_cursor"]
        .as_str()
        .expect("cursor")
        .to_owned();
    let second = api
        .send("GET", &format!("/scans?limit=2&cursor={cursor}"), None)
        .await;
    second.assert_json(200);
    assert_eq!(second.items().len(), 1);
    assert_eq!(second.items()[0]["id"], ids[2]);
    assert_eq!(second.body["next_cursor"], Value::Null);
    api.send("GET", "/scans?state=done", None)
        .await
        .assert_problem(400, "sys.invalid_query");
}

#[tokio::test]
async fn reads_pass_and_changes_need_the_right_permission() {
    let api = Api::new();
    let policy = Policy::new(true, false);
    let router = api.sibling(AppState {
        authorizer: Some(policy.clone()),
        ..AppState::default()
    });
    let get = Api::send_to(&router, "GET", "/nodes/1/scan-config", &[], None).await;
    get.assert_json(200);
    let put = Api::send_to(
        &router,
        "PUT",
        "/nodes/1/scan-config",
        &[],
        Some(json!({ "prefixes": ["192.0.2.0/24"] })),
    )
    .await;
    assert_eq!(put.status.as_u16(), 403, "{}", put.body);
    let stop = Api::send_to(&router, "POST", "/scans/stop", &[], None).await;
    assert_eq!(stop.status.as_u16(), 403, "{}", stop.body);
    let run = Api::send_to(
        &router,
        "POST",
        "/scans",
        &[],
        Some(scan("address", "192.0.2.9")),
    )
    .await;
    assert_eq!(run.status.as_u16(), 403, "{}", run.body);
    let asked: Vec<String> = policy
        .asked()
        .iter()
        .map(|(action, object)| format!("{action:?} {:?}", object.kind))
        .collect();
    assert!(asked.contains(&"Update Node".to_owned()), "{asked:?}");
    assert!(asked.contains(&"Execute Address".to_owned()), "{asked:?}");
}

#[tokio::test]
async fn without_the_scan_control_every_endpoint_is_a_stub() {
    let (router, _) = OpenApiRouter::<AppState>::new()
        .nest(API_BASE, routes())
        .split_for_parts();
    let router = router.with_state(AppState::default());
    for (method, path) in [
        ("GET", "/nodes/1/scan-config"),
        ("POST", "/scans/stop"),
        ("GET", "/scans/probes"),
    ] {
        Api::send_to(&router, method, path, &[], None)
            .await
            .assert_problem(501, "sys.not_implemented");
    }
}
