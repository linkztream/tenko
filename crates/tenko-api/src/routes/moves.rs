//! Moving hosts and addresses to another network (IPAM-19).
//!
//! Area: moves. Owners: WP1.4b, WP2.8 (the L2 step). Requirements: IPAM-19, CONN-06,
//! CONN-08, CONN-09, CONN-18, TGL-20, API-04, API-09.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `POST /moves?dry_run=true` | 200 [`MovePreview`] | 400, 403, 404, 409, 422, 423 |
//! | `POST /moves` | 202 [`MoveSubmitted`]: one job per moved address in one job group | 400, 403, 404, 409 `ipam.plan.unacknowledged` or `ipam.move.plan_changed`, 422, 423, 503 |
//!
//! The preview lists per address the old and new address, whether the host part stays and
//! why not, the DNS change, the L2 step (`l2`: a port profile on a switch port or a
//! per-client VLAN on an access point through the network controller, a manual step and
//! why, or a guardrail refusal with its code), the steps of its job (automatic or manual)
//! and warnings. The network controllers are read once per preview, never written. A
//! submit computes the preview again (it does not take the client's copy), refuses with
//! 409 `ipam.move.plan_changed` when `expect_fingerprint` names another plan than the one
//! it computed, refuses while a warning that needs an acknowledgement is not listed in
//! `acknowledge`, and starts the jobs; the answer repeats the items so the UI can compare
//! them with its preview. The jobs then appear in `GET /jobs`, and their manual steps are
//! completed through `POST /jobs/{id}/steps/{index}/complete`.
//!
//! The server adds the network controllers (`Arc<tenko_ipam::vlan::Controllers>`) as a
//! request extension; without it every L2 step is a manual step
//! (`ipam.move.l2.no_controller`).
//!
//! `Idempotency-Key` makes a submit safe to repeat: the same request under the same key
//! answers the first result with `replayed: true`. The rules (what moves, the new address,
//! the steps, the timeout, rollback) are documented in `tenko_ipam::moves`.
//!
//! # Authorization
//!
//! With an [`Authorizer`](tenko_core::Authorizer) in the state, a move needs
//! [`Action::Update`] on every named object and on the target prefix, [`Action::Execute`]
//! on jobs (the operator role) and [`Action::Execute`] on every connector an automatic L2
//! step writes through; a preview needs [`Action::Read`] on every named object and on the
//! target. A scoped principal therefore moves only objects from and into its scope.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tenko_core::{Action, ObjectKind, ObjectRef, Revision};
use tenko_ipam::{
    MovePreview, MoveRequest, MoveSubmitted,
    moves::{preview_move, submit_move},
    vlan::Controllers,
};
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::common::{IdempotencyKeyHeader, Ipam, IpamJson, authorize, new_of};
use crate::{
    extract::Ctx,
    list::Filters,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The routes of the area.
pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(create_move))
}

/// The query of `POST /moves` (documentation).
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
struct MoveParams {
    /// Compute the preview without starting anything (API-09).
    dry_run: Option<bool>,
    /// For a dry run: read at least at this store revision.
    at_least: Option<u64>,
}

/// Previews (`dry_run=true`) or starts a move of hosts or addresses into a network.
#[utoipa::path(
    post,
    path = "/moves",
    tag = "moves",
    operation_id = "create_move",
    summary = "Preview or start a move to another network",
    params(MoveParams, IdempotencyKeyHeader),
    request_body = MoveRequest,
    responses(
        (status = 200, description = "The preview of a dry run", body = MovePreview),
        (status = 202, description = "The jobs of the move, one per moved address, in one job group", body = MoveSubmitted),
        (status = 400, description = "Invalid request (`ipam.move.invalid_request`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "An object or the target does not exist (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A warning needs an acknowledgement (`ipam.plan.unacknowledged`), the plan differs from the confirmed preview (`ipam.move.plan_changed`), the target is full (`ipam.address.full`) or an object is deleted (`ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "An object cannot move (`ipam.move.unmanaged`, `ipam.move.nothing_to_move`, `ipam.move.already_in_target`, `ipam.move.family_mismatch`, `ipam.move.unsupported_object`, `ipam.move.target_not_network`), or the idempotency key was used for another move (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "A host is locked (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM or the job engine is not configured (`ipam.unavailable`, `ipam.move.no_engine`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_move(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    controllers: Option<Extension<Arc<Controllers>>>,
    filters: Filters,
    IpamJson(request): IpamJson<MoveRequest>,
) -> Result<Response, ApiError> {
    filters.only(&["dry_run"])?;
    let dry_run = filters.boolean("dry_run")?.unwrap_or(false);
    let at_least = filters.page()?.at_least.map(Revision);
    let controllers = controllers.map_or_else(Arc::default, |Extension(slot)| slot);
    if dry_run {
        for object in &request.objects {
            authorize(&app, &cx, Action::Read, *object)?;
        }
        authorize(&app, &cx, Action::Read, ObjectRef::from(request.target))?;
        let preview = preview_move(&ipam, &controllers, &request, &cx, at_least).await?;
        return Ok((StatusCode::OK, Json(preview)).into_response());
    }
    for object in &request.objects {
        authorize(&app, &cx, Action::Update, *object)?;
    }
    // The move writes addresses into the target, so a scoped principal needs the target
    // inside its scope as well as every moved object (IAM-01).
    authorize(&app, &cx, Action::Update, ObjectRef::from(request.target))?;
    authorize(&app, &cx, Action::Execute, new_of(ObjectKind::Job))?;
    // The move service takes the refusal as the `CodedError` of the controllers' port.
    #[allow(clippy::result_large_err)]
    let connector = |info: &tenko_ipam::vlan::ControllerInfo| {
        authorize(&app, &cx, Action::Execute, ObjectRef::from(info.id))
            .map_err(|error| error.coded_error().clone())
    };
    let submitted = submit_move(&ipam, &controllers, &request, &cx, &connector).await?;
    Ok((StatusCode::ACCEPTED, Json(submitted)).into_response())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{Arc, Mutex},
    };

    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use serde_json::{Value, json};
    use tenko_core::{
        AuthStrength, Authorizer, ConnectorId, Denied, DenyReason, HostId, InterfaceId, JobId,
        MacAddr, ObjectRef, PrefixId, Principal, RequestCtx, ScopeFilter, SessionId, UserId,
        VlanId,
        ipam::{AssignmentMode, RangeRole},
    };
    use tenko_ipam::{
        IpamCommand, IpamConfig, IpamService, PlanOptions,
        command::{AddressInput, HostInput, InterfaceInput, PrefixInput, RangeInput, VlanInput},
        jobs::register_steps,
        vlan::{
            controllers::{
                ControllerClient, ControllerDevice, ControllerDeviceKind, ControllerNetwork,
                ControllerPortState, ControllerProfile,
            },
            memory::{Call, MemoryController, MemoryControllers},
        },
    };
    use tenko_jobs::{EngineConfig, JobEngine, JobKind, JobQuery, JobState};
    use tenko_store::{MemStore, Store};
    use tower::ServiceExt;
    use utoipa_axum::router::OpenApiRouter;

    use super::*;
    use crate::{
        API_BASE,
        routes::{
            jobs,
            tenancy::testkit::{Policy, Reply},
        },
    };

    /// The moves and jobs routes over one IPAM service and one job engine, with the
    /// source network 192.0.2.0/24 and the target 198.51.100.0/24 on VLAN 30 whose DHCP
    /// pool .100 to .199 leases for two hours. An `Api` with controllers adds the
    /// in-memory network controller [`unifi`] as the controller slot of the router and of
    /// the engine's controller step.
    struct Api {
        router: Router,
        service: Arc<IpamService>,
        engine: JobEngine,
        target: PrefixId,
        /// The network controllers behind the slot, when there is one.
        memory: Option<MemoryControllers>,
    }

    impl Api {
        async fn new() -> Self {
            Self::with_state(AppState::default()).await
        }

        async fn with_state(state: AppState) -> Self {
            Self::build(state, None).await
        }

        /// An `Api` whose controller slot holds the in-memory controller [`unifi`].
        async fn with_controllers(state: AppState) -> Self {
            Self::build(state, Some(MemoryControllers::new(vec![unifi()]))).await
        }

        async fn build(state: AppState, memory: Option<MemoryControllers>) -> Self {
            let store: Arc<dyn Store> = Arc::new(MemStore::default());
            let mut engine = JobEngine::new(Arc::clone(&store), EngineConfig::default());
            register_steps(&mut engine);
            let slot = memory.clone().map(Controllers::with);
            if let Some(slot) = &slot {
                tenko_ipam::moves::register_steps(&mut engine, slot);
            }
            let service = IpamService::new(store, Arc::new(engine.clone()), IpamConfig::default())
                .expect("service");
            let mut router = router(state)
                .layer(Extension(Arc::clone(&service)))
                .layer(Extension(engine.clone()));
            if let Some(slot) = &slot {
                router = router.layer(Extension(Arc::clone(slot)));
            }
            let target = PrefixId::generate();
            let api = Self {
                router,
                service,
                engine,
                target,
                memory,
            };
            let vlan = VlanInput {
                id: Some(VlanId::generate()),
                vid: 30,
                vni: None,
                name: "IoT".to_owned(),
                site: None,
                status: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            };
            let target_input = PrefixInput {
                vlan: vlan.id,
                ..prefix(Some(target), "198.51.100.0/24")
            };
            api.make(vec![
                IpamCommand::CreateVlan(vlan),
                IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
                IpamCommand::CreatePrefix(target_input),
                IpamCommand::CreateRange(RangeInput {
                    id: None,
                    prefix: target,
                    first: "198.51.100.100".parse().expect("ip"),
                    last: "198.51.100.199".parse().expect("ip"),
                    role: RangeRole::DhcpPool,
                    status: None,
                    lease_secs: Some(7_200),
                    delegated_len: None,
                    tags: BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }),
            ])
            .await;
            api
        }

        /// The in-memory network controllers of an `Api` with controllers.
        fn memory(&self) -> &MemoryControllers {
            self.memory.as_ref().expect("an Api with controllers")
        }

        /// The connector instance of the one in-memory controller.
        fn connector(&self) -> ConnectorId {
            self.memory().snapshot()[0].info.id
        }

        /// Changes the one in-memory controller.
        fn update_controller(&self, change: impl FnOnce(&mut MemoryController)) {
            self.memory().update(self.connector(), change);
        }

        /// Runs commands as a person.
        async fn make(&self, commands: Vec<IpamCommand>) {
            self.make_acknowledging(&[], commands).await;
        }

        /// Runs commands as a person, acknowledging warnings.
        async fn make_acknowledging(&self, codes: &[&str], commands: Vec<IpamCommand>) {
            let cx = RequestCtx::new(Principal::User {
                id: UserId::generate(),
                session: SessionId::generate(),
                strength: AuthStrength::Passkey,
            });
            self.service
                .execute(
                    &commands,
                    &cx,
                    &PlanOptions::acknowledging(codes.iter().copied()),
                )
                .await
                .expect("execute");
        }

        /// The move jobs started so far.
        async fn move_jobs(&self) -> usize {
            let query = JobQuery {
                kinds: vec![JobKind::from_static("ipam.move")],
                ..JobQuery::default()
            };
            self.engine.list(&query).await.expect("jobs").items.len()
        }

        /// A host with one interface and one address.
        async fn host(&self, name: &str, mode: AssignmentMode, ip: &str) -> HostId {
            let id = HostId::generate();
            let interface = InterfaceId::generate();
            self.make(vec![
                IpamCommand::CreateHost(HostInput {
                    id: Some(id),
                    tenant: None,
                    name: name.parse().expect("name"),
                    mode: Some(mode),
                    lock: None,
                    site: None,
                    interfaces: vec![InterfaceInput {
                        id: Some(interface),
                        host: None,
                        name: "eth0".to_owned(),
                        mac: Some("00-00-5E-00-53-10".parse().expect("mac")),
                        duid: None,
                        client_id: None,
                        tags: BTreeSet::new(),
                        custom: BTreeMap::new(),
                        description: None,
                    }],
                    tags: BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }),
                IpamCommand::CreateAddress(AddressInput {
                    interface: Some(interface),
                    ..address(ip)
                }),
            ])
            .await;
            id
        }

        /// A move of `objects` into the target network.
        fn body(&self, objects: &[ObjectRef]) -> Value {
            json!({ "objects": objects, "target": self.target })
        }

        async fn post(&self, path: &str, key: Option<&str>, body: &Value) -> Reply {
            self.send("POST", path, key, Some(body)).await
        }

        async fn get(&self, path: &str) -> Reply {
            self.send("GET", path, None, None).await
        }

        async fn send(
            &self,
            method: &str,
            path: &str,
            key: Option<&str>,
            body: Option<&Value>,
        ) -> Reply {
            let mut builder = Request::builder()
                .method(method)
                .uri(format!("{API_BASE}{path}"));
            if body.is_some() {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
            }
            if let Some(key) = key {
                builder = builder.header("idempotency-key", key);
            }
            let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
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
                .map(|value| value.to_str().expect("text").to_owned())
                .unwrap_or_default();
            let bytes = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            Reply {
                status,
                content_type,
                etag: None,
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            }
        }
    }

    /// The moves and jobs routes under the API base, over `state`.
    fn router(state: AppState) -> Router {
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes().merge(jobs::routes()))
            .split_for_parts();
        router.with_state(state)
    }

    fn prefix(id: Option<PrefixId>, cidr: &str) -> PrefixInput {
        PrefixInput {
            id,
            vrf: None,
            cidr: cidr.parse().expect("cidr"),
            role: None,
            status: None,
            vlan: None,
            site: None,
            alarm: None,
            alloc: None,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }
    }

    fn address(ip: &str) -> AddressInput {
        AddressInput {
            id: None,
            vrf: None,
            ip: ip.parse().expect("ip"),
            status: None,
            interface: None,
            dns_name: None,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }
    }

    fn step_kinds(item: &Value) -> Vec<&str> {
        item["steps"]
            .as_array()
            .expect("steps")
            .iter()
            .map(|step| step["kind"].as_str().expect("kind"))
            .collect()
    }

    /// The engine's step kinds of a previewed item.
    fn engine_kinds(item: &Value) -> Vec<&str> {
        item["steps"]
            .as_array()
            .expect("steps")
            .iter()
            .map(|step| step["step_kind"].as_str().expect("step kind"))
            .collect()
    }

    /// The MAC address of the host the tests move.
    fn host_mac() -> MacAddr {
        "00:00:5e:00:53:10".parse().expect("mac")
    }

    /// An in-memory UniFi controller: the networks `net-iot` (VLAN 30) and `net-home`
    /// (VLAN 20), the port profiles `prof-iot` (untagged `net-iot`) and `prof-home`, the
    /// switch `sw-1` with port 5 (profile `prof-home`) and the uplink port 1, and the
    /// client of the moved host (MAC 00:00:5e:00:53:10) on port 5 in `net-home`.
    fn unifi() -> MemoryController {
        let mut controller = MemoryController::new("unifi.example.test");
        controller.networks.extend([
            ControllerNetwork {
                id: "net-iot".to_owned(),
                name: "IoT".to_owned(),
                vlan: Some(30),
                subnet: "198.51.100.0/24".parse().ok(),
                management: false,
                dhcp: None,
            },
            ControllerNetwork {
                id: "net-home".to_owned(),
                name: "Home".to_owned(),
                vlan: Some(20),
                subnet: "203.0.113.0/24".parse().ok(),
                management: false,
                dhcp: None,
            },
        ]);
        controller.profiles.extend([
            ControllerProfile {
                id: "prof-iot".to_owned(),
                name: "Profile IoT".to_owned(),
                native_network: Some("net-iot".to_owned()),
                tagged: Vec::new(),
            },
            ControllerProfile {
                id: "prof-home".to_owned(),
                name: "Profile Home".to_owned(),
                native_network: Some("net-home".to_owned()),
                tagged: Vec::new(),
            },
        ]);
        controller.devices.push(ControllerDevice {
            id: "sw-1".to_owned(),
            name: "switch1.example.test".to_owned(),
            model: None,
            mac: None,
            ip: None,
            kind: ControllerDeviceKind::Switch,
            ports: Vec::new(),
        });
        controller.ports.extend([
            ControllerPortState {
                device: "sw-1".to_owned(),
                index: 1,
                name: Some("Uplink".to_owned()),
                profile: None,
                native_vlan: None,
                uplink: true,
                management: false,
                up: true,
            },
            ControllerPortState {
                device: "sw-1".to_owned(),
                index: 5,
                name: Some("Desk".to_owned()),
                profile: Some("prof-home".to_owned()),
                native_vlan: Some(20),
                uplink: false,
                management: false,
                up: true,
            },
        ]);
        controller.clients.push(ControllerClient {
            mac: host_mac(),
            ip: Some("192.0.2.10".parse().expect("ip")),
            device: "sw-1".to_owned(),
            port: Some(5),
            ssid: None,
            network: Some("net-home".to_owned()),
            vlan: Some(20),
            name: Some("nas01".to_owned()),
            management: false,
        });
        controller
    }

    /// Whether the controllers were written through (a change applied or reverted).
    fn written(calls: &[Call]) -> bool {
        calls.iter().any(|call| {
            matches!(
                call,
                Call::ApplyAttachment { .. }
                    | Call::RevertAttachment { .. }
                    | Call::Apply { .. }
                    | Call::Revert { .. }
            )
        })
    }

    /// An authorizer that allows everything except writing through connectors, and
    /// records every question.
    struct NoConnectorWrites {
        asked: Mutex<Vec<(Action, ObjectRef)>>,
    }

    impl NoConnectorWrites {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                asked: Mutex::new(Vec::new()),
            })
        }

        fn asked(&self) -> Vec<(Action, ObjectRef)> {
            self.asked.lock().expect("lock").clone()
        }
    }

    impl Authorizer for NoConnectorWrites {
        fn check(
            &self,
            _principal: &Principal,
            action: Action,
            object: &ObjectRef,
        ) -> Result<(), Denied> {
            self.asked.lock().expect("lock").push((action, *object));
            if action == Action::Execute && object.kind == ObjectKind::Connector {
                return Err(Denied {
                    action,
                    object: *object,
                    reason: DenyReason::MissingPermission,
                });
            }
            Ok(())
        }

        fn scope(&self, _principal: &Principal, _action: Action, _kind: ObjectKind) -> ScopeFilter {
            ScopeFilter::All
        }
    }

    #[tokio::test]
    async fn a_dry_run_answers_the_preview_and_starts_nothing() {
        let api = Api::new().await;
        let host = api
            .host("nas01", AssignmentMode::Static, "192.0.2.10")
            .await;
        let reply = api
            .post("/moves?dry_run=true", None, &api.body(&[host.into()]))
            .await;
        reply.assert_json(200);
        let body = &reply.body;
        assert_eq!(body["timeout_secs"], 3_600, "half the lease of two hours");
        assert_eq!(body["timeout_source"], "lease");
        assert_eq!(body["target"]["lease_secs"], 7_200);
        assert_eq!(body["parallelism"], 4);
        let item = &body["items"][0];
        assert_eq!(item["old_ip"], "192.0.2.10");
        assert_eq!(item["new_ip"], "198.51.100.10");
        assert_eq!(item["same_host_part"], true);
        assert_eq!(item["mode"], "static");
        assert_eq!(
            step_kinds(item),
            [
                "ipam.intent",
                "device.manual",
                "l2.move",
                "observe",
                "cleanup"
            ]
        );
        assert_eq!(api.move_jobs().await, 0, "a dry run starts no job");
    }

    #[tokio::test]
    async fn a_submit_starts_jobs_whose_manual_steps_complete_through_the_jobs_api() {
        let api = Api::new().await;
        let printer = api
            .host("printer", AssignmentMode::Reserved, "192.0.2.150")
            .await;
        let body = api.body(&[printer.into()]);
        let reply = api.post("/moves", Some("move-a"), &body).await;
        reply.assert_json(202);
        let group = reply.body["group"].as_str().expect("group");
        assert!(group.starts_with("ipam.move."), "{group}");
        assert_eq!(reply.body["replayed"], false);
        let item = &reply.body["items"][0];
        assert_eq!(item["reason"], "ipam.move.host_part_reserved");
        assert_eq!(
            step_kinds(item),
            [
                "ipam.intent",
                "dhcp.manual",
                "l2.move",
                "observe",
                "cleanup"
            ]
        );
        let job: JobId =
            serde_json::from_value(reply.body["jobs"][0]["job_id"].clone()).expect("job id");

        // The same request under the same key answers the first jobs.
        let again = api.post("/moves", Some("move-a"), &body).await;
        again.assert_json(202);
        assert_eq!(again.body["replayed"], true);
        assert_eq!(again.body["jobs"], reply.body["jobs"]);
        assert_eq!(again.body["group"], reply.body["group"]);
        // Another request under the key is refused.
        let other = api
            .host("other", AssignmentMode::Static, "192.0.2.40")
            .await;
        api.post("/moves", Some("move-a"), &api.body(&[other.into()]))
            .await
            .assert_problem(422, "ipam.idempotency_mismatch");

        // The intent runs, then DHCP, L2 and the observation wait for a person.
        let state = api.engine.drive_once(job).await.expect("drive").state;
        assert_eq!(state, JobState::Waiting);
        for step in 1..=3 {
            let reply = api
                .post(
                    &format!("/jobs/{job}/steps/{step}/complete"),
                    None,
                    &json!({ "note": format!("step {step} done") }),
                )
                .await;
            reply.assert_json(200);
            api.engine.drive_once(job).await.expect("drive");
        }
        let job = api.engine.job(job).await.expect("job");
        assert_eq!(job.state, JobState::Succeeded);
    }

    #[tokio::test]
    async fn unmanaged_and_locked_hosts_are_refused() {
        let api = Api::new().await;
        let wild = api
            .host("wild", AssignmentMode::Unmanaged, "192.0.2.30")
            .await;
        for path in ["/moves?dry_run=true", "/moves"] {
            api.post(path, None, &api.body(&[wild.into()]))
                .await
                .assert_problem(422, "ipam.move.unmanaged");
        }
        let safe = api.host("safe", AssignmentMode::Static, "192.0.2.31").await;
        api.make(vec![IpamCommand::SetLock {
            host: safe,
            lock: true,
            expected: None,
        }])
        .await;
        api.post("/moves", None, &api.body(&[safe.into()]))
            .await
            .assert_problem(423, "ipam.host.locked");
        assert_eq!(api.move_jobs().await, 0, "a refused move starts no job");
    }

    #[tokio::test]
    async fn warnings_that_need_an_acknowledgement_block_the_submit() {
        let api = Api::new().await;
        // A target of /62 is off the nibble boundary of reverse DNS.
        let v6 = PrefixId::generate();
        api.make_acknowledging(
            &["ipam.prefix.nibble_boundary"],
            vec![
                IpamCommand::CreatePrefix(prefix(None, "2001:db8:1::/64")),
                IpamCommand::CreatePrefix(prefix(Some(v6), "2001:db8:4::/62")),
            ],
        )
        .await;
        let host = api
            .host("v6host", AssignmentMode::Static, "2001:db8:1::10")
            .await;
        let body = json!({ "objects": [ObjectRef::from(host)], "target": v6 });
        let preview = api.post("/moves?dry_run=true", None, &body).await;
        preview.assert_json(200);
        let unacknowledged = preview.body["unacknowledged"].clone();
        assert!(
            unacknowledged
                .as_array()
                .is_some_and(|codes| !codes.is_empty()),
            "{}",
            preview.body
        );
        api.post("/moves", None, &body)
            .await
            .assert_problem(409, "ipam.plan.unacknowledged");
        let acknowledged = json!({
            "objects": [ObjectRef::from(host)],
            "target": v6,
            "acknowledge": unacknowledged,
        });
        api.post("/moves", None, &acknowledged)
            .await
            .assert_json(202);
        assert_eq!(api.move_jobs().await, 1);
    }

    #[tokio::test]
    async fn bad_requests_answer_problem_details() {
        let api = Api::new().await;
        api.post("/moves", None, &api.body(&[]))
            .await
            .assert_problem(400, "ipam.move.invalid_request");
        api.post("/moves", None, &json!({ "objects": [], "bogus": 1 }))
            .await
            .assert_problem(400, "sys.invalid_request");
        let host = api
            .host("nas01", AssignmentMode::Static, "192.0.2.10")
            .await;
        api.post("/moves?x=1", None, &api.body(&[host.into()]))
            .await
            .assert_problem(400, "sys.invalid_query");
        api.post("/moves", None, &api.body(&[HostId::generate().into()]))
            .await
            .assert_problem(404, "ipam.not_found");
        let elsewhere =
            json!({ "objects": [ObjectRef::from(host)], "target": PrefixId::generate() });
        api.post("/moves", None, &elsewhere)
            .await
            .assert_problem(404, "ipam.not_found");
    }

    #[tokio::test]
    async fn without_the_service_moves_are_unavailable() {
        let api = Api::new().await;
        let bare = Api {
            router: router(AppState::default()),
            ..api
        };
        let body = bare.body(&[HostId::generate().into()]);
        bare.post("/moves", None, &body)
            .await
            .assert_problem(503, "ipam.unavailable");
    }

    #[tokio::test]
    async fn a_reader_may_preview_but_only_an_operator_may_move() {
        let reader = Policy::new(true, false);
        let api = Api::with_state(AppState {
            authorizer: Some(Arc::clone(&reader) as Arc<dyn Authorizer>),
            ..AppState::default()
        })
        .await;
        let host = api
            .host("nas01", AssignmentMode::Static, "192.0.2.10")
            .await;
        let body = api.body(&[host.into()]);
        api.post("/moves?dry_run=true", None, &body)
            .await
            .assert_json(200);
        api.post("/moves", None, &body)
            .await
            .assert_problem(403, "auth.forbidden");
        let asked = reader.asked();
        assert!(asked.contains(&(Action::Read, host.into())), "{asked:?}");
        assert!(asked.contains(&(Action::Update, host.into())), "{asked:?}");

        let operator = Policy::new(true, true);
        let api = Api {
            router: router(AppState {
                authorizer: Some(Arc::clone(&operator) as Arc<dyn Authorizer>),
                ..AppState::default()
            })
            .layer(Extension(Arc::clone(&api.service)))
            .layer(Extension(api.engine.clone())),
            ..api
        };
        api.post("/moves", None, &body).await.assert_json(202);
        let asked = operator.asked();
        assert!(
            asked.contains(&(Action::Execute, new_of(ObjectKind::Job))),
            "{asked:?}"
        );
    }

    #[tokio::test]
    async fn a_dry_run_plans_the_port_profile_through_the_controller_and_writes_nothing() {
        let api = Api::with_controllers(AppState::default()).await;
        let host = api
            .host("nas01", AssignmentMode::Static, "192.0.2.10")
            .await;
        let reply = api
            .post("/moves?dry_run=true", None, &api.body(&[host.into()]))
            .await;
        reply.assert_json(200);
        let body = &reply.body;
        assert_eq!(body["target"]["vid"], 30);
        let item = &body["items"][0];
        let l2 = &item["l2"];
        assert_eq!(l2["action"], "port_profile", "{l2}");
        assert_eq!(l2["attachment"]["medium"], "wired");
        assert_eq!(l2["attachment"]["device_name"], "switch1.example.test");
        assert_eq!(l2["attachment"]["port"], 5);
        assert_eq!(l2["attachment"]["profile_name"], "Profile Home");
        assert_eq!(l2["profile_name"], "Profile IoT");
        assert_eq!(l2["network_name"], "IoT");
        let diff = l2["diff"].as_array().expect("diff");
        assert!(!diff.is_empty(), "{l2}");
        assert_eq!(diff[0]["before"], "Profile Home");
        assert_eq!(diff[0]["after"], "Profile IoT");
        assert_eq!(l2["connector"]["id"], json!(api.connector()));
        assert_eq!(l2["connector"]["name"], "unifi.example.test");
        let controllers = body["controllers"].as_array().expect("controllers");
        assert_eq!(controllers.len(), 1, "{body}");
        assert_eq!(controllers[0]["id"], json!(api.connector()));
        assert_eq!(controllers[0]["name"], "unifi.example.test");
        assert!(
            body["fingerprint"]
                .as_str()
                .is_some_and(|fingerprint| !fingerprint.is_empty()),
            "{body}"
        );
        assert_eq!(
            body["unacknowledged"],
            Value::Null,
            "nothing to acknowledge"
        );
        assert_eq!(
            step_kinds(item),
            [
                "ipam.intent",
                "device.manual",
                "l2.controller",
                "observe",
                "cleanup"
            ]
        );
        assert_eq!(
            engine_kinds(item),
            [
                "ipam.move.intent",
                "ipam.move.device",
                "ipam.move.controller",
                "ipam.move.observe",
                "ipam.move.cleanup"
            ]
        );
        assert_eq!(item["steps"][2]["automatic"], true);

        let calls = api.memory().calls();
        assert!(!written(&calls), "{calls:?}");
        let reads = calls
            .iter()
            .filter(|call| matches!(call, Call::Attachments { .. }))
            .count();
        assert_eq!(reads, 1, "the controller is read once: {calls:?}");
        assert_eq!(api.move_jobs().await, 0, "a dry run starts no job");
    }

    #[tokio::test]
    async fn a_dry_run_of_a_dynamic_host_has_no_manual_device_step() {
        let api = Api::with_controllers(AppState::default()).await;
        let host = api
            .host("camera", AssignmentMode::Dynamic, "192.0.2.20")
            .await;
        let reply = api
            .post("/moves?dry_run=true", None, &api.body(&[host.into()]))
            .await;
        reply.assert_json(200);
        let item = &reply.body["items"][0];
        assert_eq!(item["l2"]["action"], "port_profile", "{item}");
        assert_eq!(
            step_kinds(item),
            ["ipam.intent", "l2.controller", "observe", "cleanup"]
        );
    }

    #[tokio::test]
    async fn a_submit_starts_a_job_that_writes_through_the_connector() {
        let api = Api::with_controllers(AppState::default()).await;
        let host = api
            .host("nas01", AssignmentMode::Static, "192.0.2.10")
            .await;
        let body = api.body(&[host.into()]);
        let reply = api.post("/moves", None, &body).await;
        reply.assert_json(202);
        assert_eq!(reply.body["items"][0]["l2"]["action"], "port_profile");
        let job = reply.body["jobs"][0]["job_id"].as_str().expect("job");
        let detail = api.get(&format!("/jobs/{job}")).await;
        detail.assert_json(200);
        let spec = &detail.body["job"]["spec"];
        assert_eq!(spec["kind"], "ipam.move");

        // The connector is a target of the job, in the wire form of an object reference.
        let connector = json!(ObjectRef::from(api.connector()));
        assert_eq!(connector["kind"], "connector");
        assert!(connector["id"].is_string(), "{connector}");
        let targets = spec["targets"].as_array().expect("targets");
        assert!(targets.contains(&connector), "{targets:?}");
        assert!(
            targets.contains(&json!(ObjectRef::from(host))),
            "{targets:?}"
        );
        assert!(
            targets.contains(&json!(ObjectRef::from(api.target))),
            "{targets:?}"
        );

        let kinds: Vec<&str> = spec["steps"]
            .as_array()
            .expect("steps")
            .iter()
            .map(|step| step["kind"].as_str().expect("kind"))
            .collect();
        assert_eq!(
            kinds,
            [
                "ipam.move.intent",
                "ipam.move.device",
                "ipam.move.controller",
                "ipam.move.observe",
                "ipam.move.cleanup"
            ]
        );
        assert_eq!(api.move_jobs().await, 1);
        let calls = api.memory().calls();
        assert!(
            !written(&calls),
            "a submit writes nothing itself: {calls:?}"
        );
    }

    #[tokio::test]
    async fn a_submit_needs_execute_on_the_connector_it_writes_through() {
        let operator = Policy::new(true, true);
        let api = Api::with_controllers(AppState {
            authorizer: Some(Arc::clone(&operator) as Arc<dyn Authorizer>),
            ..AppState::default()
        })
        .await;
        let host = api
            .host("nas01", AssignmentMode::Static, "192.0.2.10")
            .await;
        let body = api.body(&[host.into()]);
        let connector = ObjectRef::from(api.connector());
        api.post("/moves?dry_run=true", None, &body)
            .await
            .assert_json(200);
        let asked = operator.asked();
        assert!(
            !asked.contains(&(Action::Execute, connector)),
            "a preview writes nothing: {asked:?}"
        );
        api.post("/moves", None, &body).await.assert_json(202);
        let asked = operator.asked();
        assert!(asked.contains(&(Action::Execute, connector)), "{asked:?}");
        assert_eq!(api.move_jobs().await, 1);

        // A principal that may update the host and run jobs, but not use the connector.
        let guarded = NoConnectorWrites::new();
        let api = Api::with_controllers(AppState {
            authorizer: Some(Arc::clone(&guarded) as Arc<dyn Authorizer>),
            ..AppState::default()
        })
        .await;
        let host = api
            .host("nas01", AssignmentMode::Static, "192.0.2.10")
            .await;
        let body = api.body(&[host.into()]);
        let connector = ObjectRef::from(api.connector());
        api.post("/moves?dry_run=true", None, &body)
            .await
            .assert_json(200);
        api.post("/moves", None, &body)
            .await
            .assert_problem(403, "auth.forbidden");
        let asked = guarded.asked();
        assert!(asked.contains(&(Action::Update, host.into())), "{asked:?}");
        assert!(
            asked.contains(&(Action::Execute, new_of(ObjectKind::Job))),
            "{asked:?}"
        );
        assert!(asked.contains(&(Action::Execute, connector)), "{asked:?}");
        assert_eq!(api.move_jobs().await, 0, "a refused submit starts no job");
        let calls = api.memory().calls();
        assert!(!written(&calls), "{calls:?}");

        // A reader is refused before the connector is asked at all.
        let reader = Policy::new(true, false);
        let api = Api::with_controllers(AppState {
            authorizer: Some(Arc::clone(&reader) as Arc<dyn Authorizer>),
            ..AppState::default()
        })
        .await;
        let host = api
            .host("nas01", AssignmentMode::Static, "192.0.2.10")
            .await;
        api.post("/moves", None, &api.body(&[host.into()]))
            .await
            .assert_problem(403, "auth.forbidden");
        let connector = ObjectRef::from(api.connector());
        let asked = reader.asked();
        assert!(!asked.contains(&(Action::Execute, connector)), "{asked:?}");
        assert_eq!(api.move_jobs().await, 0);
    }

    #[tokio::test]
    async fn a_submit_runs_the_confirmed_plan_or_nothing() {
        let api = Api::with_controllers(AppState::default()).await;
        let host = api
            .host("nas01", AssignmentMode::Static, "192.0.2.10")
            .await;
        let request = |expect: Option<&str>| {
            let mut body = api.body(&[host.into()]);
            if let Some(expect) = expect {
                body["expect_fingerprint"] = json!(expect);
            }
            body
        };
        let first = api.post("/moves?dry_run=true", None, &request(None)).await;
        first.assert_json(200);
        let confirmed = first.body["fingerprint"].as_str().expect("fingerprint");
        let again = api.post("/moves?dry_run=true", None, &request(None)).await;
        assert_eq!(
            again.body["fingerprint"], first.body["fingerprint"],
            "the same plan has the same fingerprint"
        );

        // Somebody gives the port another profile before the submit.
        api.update_controller(|controller| {
            controller.profiles.push(ControllerProfile {
                id: "prof-guest".to_owned(),
                name: "Profile Guest".to_owned(),
                native_network: None,
                tagged: Vec::new(),
            });
            let port = controller
                .ports
                .iter_mut()
                .find(|port| port.index == 5)
                .expect("port");
            port.profile = Some("prof-guest".to_owned());
        });
        let stale = api.post("/moves", None, &request(Some(confirmed))).await;
        stale.assert_problem(409, "ipam.move.plan_changed");
        assert_eq!(api.move_jobs().await, 0, "a changed plan starts no job");

        // The preview of the changed controller is the plan to confirm.
        let second = api.post("/moves?dry_run=true", None, &request(None)).await;
        second.assert_json(200);
        let now = second.body["fingerprint"].as_str().expect("fingerprint");
        assert_ne!(now, confirmed);
        assert_eq!(
            second.body["items"][0]["l2"]["diff"][0]["before"],
            "Profile Guest"
        );
        assert_eq!(stale.body["params"]["fingerprint"], now);
        api.post("/moves", None, &request(Some(now)))
            .await
            .assert_json(202);
        assert_eq!(api.move_jobs().await, 1);
    }

    #[tokio::test]
    async fn a_client_on_an_uplink_port_is_left_to_a_person_and_needs_an_acknowledgement() {
        let api = Api::with_controllers(AppState::default()).await;
        api.update_controller(|controller| {
            controller.clients[0].port = Some(1);
        });
        let host = api
            .host("nas01", AssignmentMode::Static, "192.0.2.10")
            .await;
        let body = api.body(&[host.into()]);
        let preview = api.post("/moves?dry_run=true", None, &body).await;
        preview.assert_json(200);
        let item = &preview.body["items"][0];
        let l2 = &item["l2"];
        assert_eq!(l2["action"], "manual", "{l2}");
        assert_eq!(l2["reason"], "ipam.move.l2.refused");
        assert_eq!(l2["problem"]["code"], "connect.guardrail.uplink");
        assert_eq!(l2["connector"]["id"], json!(api.connector()));
        assert_eq!(
            preview.body["unacknowledged"],
            json!(["ipam.move.l2_refused"])
        );
        assert_eq!(
            step_kinds(item),
            [
                "ipam.intent",
                "device.manual",
                "l2.move",
                "observe",
                "cleanup"
            ]
        );
        assert_eq!(item["steps"][2]["step_kind"], "ipam.move.l2");
        assert_eq!(item["steps"][2]["automatic"], false);

        api.post("/moves", None, &body)
            .await
            .assert_problem(409, "ipam.plan.unacknowledged");
        assert_eq!(api.move_jobs().await, 0);

        // Acknowledged, a person moves the device: the connector is not a target.
        let acknowledged = json!({
            "objects": [ObjectRef::from(host)],
            "target": api.target,
            "acknowledge": ["ipam.move.l2_refused"],
        });
        let reply = api.post("/moves", None, &acknowledged).await;
        reply.assert_json(202);
        let job = reply.body["jobs"][0]["job_id"].as_str().expect("job");
        let detail = api.get(&format!("/jobs/{job}")).await;
        detail.assert_json(200);
        let targets = detail.body["job"]["spec"]["targets"]
            .as_array()
            .expect("targets");
        assert!(
            targets.iter().all(|target| target["kind"] != "connector"),
            "{targets:?}"
        );
        let calls = api.memory().calls();
        assert!(!written(&calls), "{calls:?}");
    }

    #[tokio::test]
    async fn without_a_controller_slot_the_l2_step_is_a_manual_step() {
        let api = Api::new().await;
        let host = api
            .host("nas01", AssignmentMode::Static, "192.0.2.10")
            .await;

        // The target has a VLAN, but the server did not add the network controllers.
        let reply = api
            .post("/moves?dry_run=true", None, &api.body(&[host.into()]))
            .await;
        reply.assert_json(200);
        let item = &reply.body["items"][0];
        assert_eq!(reply.body["target"]["vid"], 30);
        assert_eq!(item["l2"]["action"], "manual", "{item}");
        assert_eq!(item["l2"]["reason"], "ipam.move.l2.no_controller");
        assert_eq!(
            step_kinds(item),
            [
                "ipam.intent",
                "device.manual",
                "l2.move",
                "observe",
                "cleanup"
            ]
        );
        assert_eq!(item["steps"][2]["step_kind"], "ipam.move.l2");
        assert_eq!(item["steps"][2]["automatic"], false);
        assert_eq!(reply.body["unacknowledged"], Value::Null);
        assert_eq!(reply.body["controllers"], Value::Null);

        // A target without a VLAN has nothing to put the device into.
        let flat = PrefixId::generate();
        api.make(vec![IpamCommand::CreatePrefix(prefix(
            Some(flat),
            "203.0.113.0/24",
        ))])
        .await;
        let body = json!({ "objects": [ObjectRef::from(host)], "target": flat });
        let reply = api.post("/moves?dry_run=true", None, &body).await;
        reply.assert_json(200);
        let item = &reply.body["items"][0];
        assert_eq!(reply.body["target"]["vid"], Value::Null);
        assert_eq!(item["l2"]["action"], "manual", "{item}");
        assert_eq!(item["l2"]["reason"], "ipam.move.l2.no_vlan");
        assert_eq!(
            step_kinds(item),
            [
                "ipam.intent",
                "device.manual",
                "l2.move",
                "observe",
                "cleanup"
            ]
        );

        // A submit then starts the job with the manual step.
        api.post("/moves", None, &body).await.assert_json(202);
        assert_eq!(api.move_jobs().await, 1);
    }

    #[tokio::test]
    async fn a_target_without_a_vlan_leaves_the_controllers_unread() {
        let api = Api::with_controllers(AppState::default()).await;
        let host = api
            .host("nas01", AssignmentMode::Static, "192.0.2.10")
            .await;
        let flat = PrefixId::generate();
        api.make(vec![IpamCommand::CreatePrefix(prefix(
            Some(flat),
            "203.0.113.0/24",
        ))])
        .await;
        let body = json!({ "objects": [ObjectRef::from(host)], "target": flat });
        let reply = api.post("/moves?dry_run=true", None, &body).await;
        reply.assert_json(200);
        assert_eq!(
            reply.body["items"][0]["l2"]["reason"],
            "ipam.move.l2.no_vlan"
        );
        assert_eq!(api.memory().calls(), []);
    }

    #[test]
    fn the_operation_is_documented() {
        let (_, document) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let operation = document.paths.paths["/api/v1/moves"]
            .post
            .as_ref()
            .expect("post");
        assert_eq!(operation.operation_id.as_deref(), Some("create_move"));
        assert_eq!(operation.tags.as_deref(), Some(&["moves".to_owned()][..]));
        for status in [
            "200", "202", "400", "403", "404", "409", "422", "423", "503",
        ] {
            assert!(
                operation.responses.responses.contains_key(status),
                "{status}"
            );
        }
    }
}
