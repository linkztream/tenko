//! Moving hosts and addresses to another network (IPAM-19).
//!
//! Area: moves. Owner: WP1.4b. Requirements: IPAM-19, CONN-09, API-04, API-09.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `POST /moves?dry_run=true` | 200 [`MovePreview`] | 400, 403, 404, 409, 422, 423 |
//! | `POST /moves` | 202 [`MoveSubmitted`]: one job per moved address in one job group | 400, 403, 404, 409 `ipam.plan.unacknowledged`, 422, 423, 503 |
//!
//! The preview lists per address the old and new address, whether the host part stays and
//! why not, the DNS change, the steps of its job (automatic or manual) and warnings. A
//! submit computes the preview again (it does not take the client's copy), refuses while a
//! warning that needs an acknowledgement is not listed in `acknowledge`, and starts the
//! jobs; the answer repeats the items so the UI can compare them with its preview. The
//! jobs then appear in `GET /jobs`, and their manual steps are completed through
//! `POST /jobs/{id}/steps/{index}/complete`.
//!
//! `Idempotency-Key` makes a submit safe to repeat: the same request under the same key
//! answers the first result with `replayed: true`. The rules (what moves, the new address,
//! the steps, the timeout, rollback) are documented in `tenko_ipam::moves`.
//!
//! # Authorization
//!
//! With an [`Authorizer`](tenko_core::Authorizer) in the state, a move needs
//! [`Action::Update`] on every named object and [`Action::Execute`] on jobs (the operator
//! role); a preview needs [`Action::Read`] on every named object.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tenko_core::{Action, ObjectKind, Revision};
use tenko_ipam::{MovePreview, MoveRequest, MoveSubmitted};
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
        (status = 409, description = "A warning needs an acknowledgement (`ipam.plan.unacknowledged`), the target is full (`ipam.address.full`) or an object is deleted (`ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "An object cannot move (`ipam.move.unmanaged`, `ipam.move.nothing_to_move`, `ipam.move.already_in_target`, `ipam.move.family_mismatch`, `ipam.move.unsupported_object`, `ipam.move.target_not_network`), or the idempotency key was used for another move (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "A host is locked (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM or the job engine is not configured (`ipam.unavailable`, `ipam.move.no_engine`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_move(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
    IpamJson(request): IpamJson<MoveRequest>,
) -> Result<Response, ApiError> {
    filters.only(&["dry_run"])?;
    let dry_run = filters.boolean("dry_run")?.unwrap_or(false);
    let at_least = filters.page()?.at_least.map(Revision);
    if dry_run {
        for object in &request.objects {
            authorize(&app, &cx, Action::Read, *object)?;
        }
        let preview = ipam.move_preview(&request, &cx, at_least).await?;
        return Ok((StatusCode::OK, Json(preview)).into_response());
    }
    for object in &request.objects {
        authorize(&app, &cx, Action::Update, *object)?;
    }
    authorize(&app, &cx, Action::Execute, new_of(ObjectKind::Job))?;
    let submitted = ipam.move_submit(&request, &cx).await?;
    Ok((StatusCode::ACCEPTED, Json(submitted)).into_response())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    };

    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use serde_json::{Value, json};
    use tenko_core::{
        AuthStrength, Authorizer, HostId, InterfaceId, JobId, ObjectRef, PrefixId, Principal,
        RequestCtx, SessionId, UserId,
        ipam::{AssignmentMode, RangeRole},
    };
    use tenko_ipam::{
        IpamCommand, IpamConfig, IpamService, PlanOptions,
        command::{AddressInput, HostInput, InterfaceInput, PrefixInput, RangeInput},
        jobs::register_steps,
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
    /// source network 192.0.2.0/24 and the target 198.51.100.0/24 whose DHCP pool
    /// .100 to .199 leases for two hours.
    struct Api {
        router: Router,
        service: Arc<IpamService>,
        engine: JobEngine,
        target: PrefixId,
    }

    impl Api {
        async fn new() -> Self {
            Self::with_state(AppState::default()).await
        }

        async fn with_state(state: AppState) -> Self {
            let store: Arc<dyn Store> = Arc::new(MemStore::default());
            let mut engine = JobEngine::new(Arc::clone(&store), EngineConfig::default());
            register_steps(&mut engine);
            let service = IpamService::new(store, Arc::new(engine.clone()), IpamConfig::default())
                .expect("service");
            let router = router(state)
                .layer(Extension(Arc::clone(&service)))
                .layer(Extension(engine.clone()));
            let target = PrefixId::generate();
            let api = Self {
                router,
                service,
                engine,
                target,
            };
            api.make(vec![
                IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
                IpamCommand::CreatePrefix(prefix(Some(target), "198.51.100.0/24")),
                IpamCommand::CreateRange(RangeInput {
                    id: None,
                    prefix: target,
                    first: "198.51.100.100".parse().expect("ip"),
                    last: "198.51.100.199".parse().expect("ip"),
                    role: RangeRole::DhcpPool,
                    status: None,
                    lease_secs: Some(7_200),
                    tags: BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }),
            ])
            .await;
            api
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
            let mut builder = Request::builder()
                .method("POST")
                .uri(format!("{API_BASE}{path}"))
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(key) = key {
                builder = builder.header("idempotency-key", key);
            }
            let response = self
                .router
                .clone()
                .oneshot(builder.body(Body::from(body.to_string())).expect("request"))
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
        assert_eq!(body["parallelism"], 2);
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
