//! Route tests of VLAN provisioning over one IPAM service, the job engine and an in-memory
//! network controller. Test data stays in the documentation ranges.

use std::sync::Arc;

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, header},
};
use serde_json::{Value, json};
use tenko_core::{Authorizer, JobId};
use tenko_ipam::{
    IpamConfig, IpamService,
    vlan::{
        Controllers,
        memory::{MemoryController, MemoryControllers},
    },
};
use tenko_jobs::{EngineConfig, JobEngine, JobState};
use tenko_store::{MemStore, Store};
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;

use super::routes;
use crate::{
    API_BASE,
    routes::tenancy::testkit::{Policy, Reply},
    state::AppState,
};

struct Api {
    router: Router,
    engine: JobEngine,
    memory: MemoryControllers,
}

impl Api {
    fn new(state: AppState, controllers: bool) -> Self {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let mut engine = JobEngine::new(Arc::clone(&store), EngineConfig::default());
        tenko_ipam::jobs::register_steps(&mut engine);
        let memory = MemoryControllers::new(vec![MemoryController::new("unifi.example.test")]);
        let slot = Controllers::with(memory.clone());
        tenko_ipam::vlan::register_steps(&mut engine, &slot);
        let service = IpamService::new(store, Arc::new(engine.clone()), IpamConfig::default())
            .expect("service");
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let mut router = router
            .with_state(state)
            .layer(Extension(service))
            .layer(Extension(engine.clone()));
        if controllers {
            router = router.layer(Extension(slot));
        }
        Self {
            router,
            engine,
            memory,
        }
    }

    async fn send(&self, method: &str, path: &str, body: Option<Value>) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
        let body = match body {
            Some(body) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .router
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

    async fn drive(&self, job: &str) -> tenko_jobs::Job {
        let id: JobId = job.parse().expect("job id");
        self.engine.drive_once(id).await.expect("drive")
    }
}

fn request(vid: u16) -> Value {
    json!({
        "create": { "vid": vid, "name": "IoT" },
        "prefix": { "cidr": "198.51.100.0/24" },
        "dhcp_relay": ["192.0.2.53"]
    })
}

#[tokio::test]
async fn a_dry_run_shows_the_controller_diff_and_a_submit_runs_the_job() {
    let api = Api::new(AppState::default(), true);
    let preview = api
        .send("POST", "/vlans/provision?dry_run=true", Some(request(30)))
        .await;
    preview.assert_json(200);
    let body = &preview.body;
    assert_eq!(body["controller"]["mode"], "automatic", "{body}");
    assert_eq!(body["controller"]["diff"].as_array().map(Vec::len), Some(2));
    assert_eq!(body["controller"]["network"]["dhcp_relay"][0], "192.0.2.53");
    assert_eq!(body["steps"][1]["step_kind"], "ipam.vlan.controller");
    assert!(body["plan"]["summary"]["lines"].is_array(), "{body}");
    assert_eq!(api.memory.snapshot()[0].networks.len(), 1);

    let submitted = api
        .send("POST", "/vlans/provision", Some(request(30)))
        .await;
    submitted.assert_json(202);
    let job = submitted.body["job_id"].as_str().expect("job").to_owned();
    let vlan = submitted.body["vlan"].as_str().expect("vlan").to_owned();
    assert_eq!(api.drive(&job).await.state, JobState::Succeeded);
    assert!(
        api.memory.snapshot()[0]
            .networks
            .iter()
            .any(|n| n.vlan == Some(30))
    );
    let prefixes = api
        .send("GET", &format!("/vlans/{vlan}/prefixes"), None)
        .await;
    prefixes.assert_json(200);
    assert_eq!(prefixes.texts("cidr"), ["198.51.100.0/24"]);
    assert_eq!(prefixes.texts("status"), ["active"]);
}

#[tokio::test]
async fn refusals_and_bad_requests_are_problems() {
    let api = Api::new(AppState::default(), true);
    api.send(
        "POST",
        "/vlans/provision?dry_run=true",
        Some(json!({ "create": { "vid": 10, "name": "Management" } })),
    )
    .await
    .assert_problem(409, "connect.guardrail.protected_vlan");
    api.send(
        "POST",
        "/vlans/provision",
        Some(json!({ "create": { "vid": 30, "name": "IoT" }, "vlan": "0190d1c2-0000-7000-8000-000000000001" })),
    )
    .await
    .assert_problem(400, "ipam.vlan.invalid_request");
    api.send(
        "POST",
        "/vlans/provision",
        Some(json!({ "create": { "vid": 30, "name": "IoT" }, "colour": "blue" })),
    )
    .await
    .assert_problem(400, "sys.invalid_request");
    api.send(
        "POST",
        "/vlans/provision?dry_run=true",
        Some(json!({ "create": { "vid": 5000, "name": "IoT" } })),
    )
    .await
    .assert_problem(400, "ipam.validation");
    api.send(
        "GET",
        "/vlans/0190d1c2-0000-7000-8000-000000000001/prefixes",
        None,
    )
    .await
    .assert_problem(404, "ipam.not_found");
    api.send(
        "GET",
        "/vlans/0190d1c2-0000-7000-8000-000000000001/prefixes?deleted=only",
        None,
    )
    .await
    .assert_problem(400, "sys.invalid_query");

    let id = api.memory.snapshot()[0].info.id;
    api.memory.update(id, |c| c.info.writes_enabled = false);
    let refused = api
        .send("POST", "/vlans/provision", Some(request(40)))
        .await;
    refused.assert_problem(409, "ipam.plan.unacknowledged");
    assert_eq!(
        refused.body["params"]["codes"],
        "ipam.vlan.controller_read_only"
    );
}

#[tokio::test]
async fn without_the_controller_slot_the_route_is_unavailable() {
    let api = Api::new(AppState::default(), false);
    api.send("POST", "/vlans/provision?dry_run=true", Some(request(30)))
        .await
        .assert_problem(503, "ipam.vlan.controllers_unavailable");
}

#[tokio::test]
async fn a_submit_needs_the_right_to_run_jobs() {
    let state = AppState {
        authorizer: Some(Policy::new(true, false) as Arc<dyn Authorizer>),
        ..AppState::default()
    };
    let api = Api::new(state, true);
    api.send("POST", "/vlans/provision?dry_run=true", Some(request(30)))
        .await
        .assert_problem(403, "auth.forbidden");
}
