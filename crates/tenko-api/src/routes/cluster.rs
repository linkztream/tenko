//! The controller cluster: the members with their replication state, promotion, removal,
//! step-down and the state digests (OPS-03).
//!
//! Area: cluster. Owner: WP3.1a.
//! Requirements: OPS-03, OPS-04, OPS-08.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /cluster/members` | 200 [`ClusterView`]: the leader, the term, the quorum state and the members with their replication figures | 401, 403, 503 `cluster.member.not_leader`, `.starting` |
//! | `POST /cluster/members/{id}/promote` | 200 [`ClusterView`] after the change; body [`PromoteRequest`] (optional) | 400, 401, 403, 404 `cluster.member.not_found`; 409 `cluster.member.even_voters`, `.not_caught_up`, `.changing`, `cluster.single`; 503 `cluster.member.not_leader`, `.starting` |
//! | `DELETE /cluster/members/{id}` | 200 [`ClusterView`] after the change | 400, 401, 403, 404 `cluster.member.not_found`; 409 `cluster.member.last_voter`, `.changing`, `cluster.single`; 503 `cluster.member.not_leader`, `.starting` |
//! | `POST /cluster/step-down` | 200 [`StepDown`]: who led, who leads now, the new term | 401, 403, 409 `cluster.member.no_successor`, `.changing`, `cluster.single`; 503 `cluster.member.not_leader`, `.starting` |
//! | `GET /cluster/digests` | 200 [`DigestReport`]: the state digest of every member at one revision (`?revision=` names it) | 400 `sys.invalid_query`, 401, 403, 503 `cluster.member.starting` |
//!
//! # The service
//!
//! The server adds the cluster administration ([`ClusterAdmin`]) as a request extension.
//! Without it (a controller that has no peer layer), every endpoint answers `501`
//! `sys.not_implemented`. Membership changes run on the leader: a controller that does not
//! lead hands them over, so any controller serves these endpoints. Each change is an inline
//! job `cluster.edit` and is audited as `cluster.member.promote` or `cluster.member.remove`.
//!
//! # Authorization
//!
//! Reading the members and the digests needs [`Action::Read`] on nodes (viewers and
//! operators have it). Promotion needs [`Action::Update`] on the node, removal
//! [`Action::Delete`] on the node (as its revocation does), and step-down
//! [`Action::Update`] on nodes: administrator rights, which a personal token of an
//! administrator carries too, so `tenko cluster` works with the token of `tenko login`.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use tenko_cluster::{
    admin::{self, ClusterAdmin, DigestReport, MemberView, PromoteRequest, StepDown},
    error::ClusterError,
};
use tenko_core::{
    Action, CodedError, JobId, NodeId, ObjectKind, ObjectRef, Revision, error::codes,
};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{auth::OptionalJson, not_implemented};
use crate::{
    dto::system::QuorumView,
    extract::Ctx,
    list::Filters,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_cluster_members))
        .routes(routes!(remove_cluster_member))
        .routes(routes!(promote_cluster_member))
        .routes(routes!(step_down_cluster_leader))
        .routes(routes!(get_cluster_digests))
}

type Admin = Option<Extension<Arc<dyn ClusterAdmin>>>;

fn admin_or_stub(
    admin: Admin,
    method: &str,
    path: &str,
) -> Result<Arc<dyn ClusterAdmin>, ApiError> {
    admin
        .map(|Extension(admin)| admin)
        .ok_or_else(|| not_implemented(method, path))
}

fn failed(error: ClusterError) -> ApiError {
    ApiError::from_coded_error(error.into_coded())
}

fn invalid_request(detail: impl Into<String>) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(codes::INVALID_REQUEST, 400, detail).with_title("Invalid request"),
    )
}

fn parse_node(raw: &str) -> Result<NodeId, ApiError> {
    raw.parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .map(NodeId)
        .ok_or_else(|| {
            invalid_request("the node identifier is not a positive number")
                .with_param("field", "id")
        })
}

/// What reading the members needs: the nodes.
const fn nodes() -> ObjectRef {
    ObjectRef::singleton(ObjectKind::Node)
}

/// What changing the membership needs: the system.
/// The cluster as one controller sees it: the answer of `GET /cluster/members` and of a
/// membership change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ClusterView {
    /// The controller that answered.
    #[schema(value_type = u64)]
    pub node: NodeId,
    /// The leader it knows, if any.
    #[schema(value_type = Option<u64>)]
    pub leader: Option<NodeId>,
    /// The Raft term it knows.
    pub term: u64,
    /// Whether it is in contact with a quorum.
    pub quorum: QuorumView,
    /// Whether a membership change is in progress (joint consensus).
    pub changing: bool,
    /// The members by node id. Replication figures (`matched`, `lag_entries`,
    /// `last_contact_ms`) come from the leader; a follower asks it.
    pub members: Vec<MemberView>,
    /// The inline job `cluster.edit` of a promotion or removal; absent on `GET`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub job_id: Option<JobId>,
}

impl From<admin::ClusterView> for ClusterView {
    fn from(view: admin::ClusterView) -> Self {
        Self {
            node: view.node,
            leader: view.leader,
            term: view.term,
            quorum: view.quorum.into(),
            changing: view.changing,
            members: view.members,
            job_id: view.job_id,
        }
    }
}

/// Shows the controller cluster as this controller sees it: the leader it knows, the Raft
/// term, whether it is in contact with a quorum (`single`, `healthy`, `electing` or
/// `isolated`, with the time it began and, while isolated, the age of its copy), whether a
/// membership change is in progress and every member with its role, address, version and,
/// from the leader, its replication state (matched index, lag in entries and milliseconds
/// since the last contact).
#[utoipa::path(
    get,
    path = "/cluster/members",
    tag = "cluster",
    operation_id = "list_cluster_members",
    summary = "List the controller cluster members",
    responses(
        (status = 200, description = "The cluster as this controller sees it", body = ClusterView),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to read nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No leader is known to answer the replication figures (`cluster.member.not_leader`) or the controller is still starting (`cluster.member.starting`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_cluster_members(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    admin: Admin,
) -> Result<Json<ClusterView>, ApiError> {
    let admin = admin_or_stub(admin, "GET", "/cluster/members")?;
    app.authorize(&cx.principal, Action::Read, &nodes())?;
    admin
        .view()
        .await
        .map(|view| Json(view.into()))
        .map_err(failed)
}

/// Promotes a learner to a voter once it has caught up with the leader, in one joint
/// change of the membership (an inline job `cluster.edit`, audited as
/// `cluster.member.promote`). A promotion that would leave an even number of voters, or
/// that promotes a learner which is behind or out of contact, is refused unless `force` is
/// set. `replace` names a voter to remove in the same change: a dead voter is replaced
/// without passing through an even number of voters. The body may be left out.
#[utoipa::path(
    post,
    path = "/cluster/members/{id}/promote",
    tag = "cluster",
    operation_id = "promote_cluster_member",
    summary = "Promote a learner to a voter",
    params(("id" = u64, Path, description = "Node id of the learner")),
    request_body(content = PromoteRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "The cluster after the change", body = ClusterView),
        (status = 400, description = "The identifier or the body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to change the controller cluster (an administrator right)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The node, or the voter to replace, is not a member (`cluster.member.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The result would have an even number of voters (`cluster.member.even_voters`), the learner is too far behind or out of contact (`cluster.member.not_caught_up`), another change is in progress (`cluster.member.changing`) or the controller is not part of a cluster (`cluster.single`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No leader is known to take the change (`cluster.member.not_leader`) or the controller is still starting (`cluster.member.starting`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn promote_cluster_member(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    admin: Admin,
    Path(id): Path<String>,
    OptionalJson(request): OptionalJson<PromoteRequest>,
) -> Result<Json<ClusterView>, ApiError> {
    let admin = admin_or_stub(admin, "POST", "/cluster/members/{id}/promote")?;
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(node))?;
    admin
        .promote(&cx, node, request)
        .await
        .map(|view| Json(view.into()))
        .map_err(failed)
}

/// Removes a member from the cluster (an inline job `cluster.edit`, audited as
/// `cluster.member.remove`) and revokes the certificates it was issued, so that it cannot
/// rejoin without a new enrolment. The last voter cannot be removed.
#[utoipa::path(
    delete,
    path = "/cluster/members/{id}",
    tag = "cluster",
    operation_id = "remove_cluster_member",
    summary = "Remove a controller from the cluster",
    params(("id" = u64, Path, description = "Node id of the member")),
    responses(
        (status = 200, description = "The cluster after the change", body = ClusterView),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to change the controller cluster (an administrator right)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The node is not a member (`cluster.member.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The change would remove the last voter (`cluster.member.last_voter`), another change is in progress (`cluster.member.changing`) or the controller is not part of a cluster (`cluster.single`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No leader is known to take the change (`cluster.member.not_leader`) or the controller is still starting (`cluster.member.starting`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn remove_cluster_member(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    admin: Admin,
    Path(id): Path<String>,
) -> Result<Json<ClusterView>, ApiError> {
    let admin = admin_or_stub(admin, "DELETE", "/cluster/members/{id}")?;
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::node(node))?;
    admin
        .remove(&cx, node)
        .await
        .map(|view| Json(view.into()))
        .map_err(failed)
}

/// Hands leadership to the most caught-up voter and answers when it leads, so that the
/// controller that led can restart without an election it has to wait for. Refused when no
/// other voter is caught up.
#[utoipa::path(
    post,
    path = "/cluster/step-down",
    tag = "cluster",
    operation_id = "step_down_cluster_leader",
    summary = "Hand leadership to another controller",
    responses(
        (status = 200, description = "The controller that led, the one that leads now and the new term", body = StepDown),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to change the controller cluster (an administrator right)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "No other voter is caught up (`cluster.member.no_successor`), a membership change is in progress (`cluster.member.changing`) or the controller is not part of a cluster (`cluster.single`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No leader is known (`cluster.member.not_leader`) or the controller is still starting (`cluster.member.starting`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn step_down_cluster_leader(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    admin: Admin,
) -> Result<Json<StepDown>, ApiError> {
    let admin = admin_or_stub(admin, "POST", "/cluster/step-down")?;
    app.authorize(&cx.principal, Action::Update, &nodes())?;
    admin.step_down(&cx).await.map(Json).map_err(failed)
}

/// Asks every member for the SHA-256 digest over all of its tables at one revision, to
/// show that the replicas hold the same data. `agree` is true when every member answered
/// with the same digest at the same revision; a member that gave no digest carries the
/// error code instead. Without `revision`, the newest revision the answering controller
/// applied is used.
#[utoipa::path(
    get,
    path = "/cluster/digests",
    tag = "cluster",
    operation_id = "get_cluster_digests",
    summary = "Compare the state digests of the members",
    params(("revision" = Option<u64>, Query, description = "The revision to compare at; default the newest revision the answering controller applied")),
    responses(
        (status = 200, description = "The digest of every member at one revision", body = DigestReport),
        (status = 400, description = "The revision is not a number (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to read nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The controller is still starting (`cluster.member.starting`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_cluster_digests(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    admin: Admin,
    filters: Filters,
) -> Result<Json<DigestReport>, ApiError> {
    let admin = admin_or_stub(admin, "GET", "/cluster/digests")?;
    filters.only(&["revision"])?;
    let revision = filters.parse::<u64>("revision")?.map(Revision);
    app.authorize(&cx.principal, Action::Read, &nodes())?;
    admin.digests(revision).await.map(Json).map_err(failed)
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin, sync::Mutex};

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{HeaderMap, Request, StatusCode, header},
    };
    use serde_json::{Value, json};
    use tenko_cluster::admin::{
        ClusterView, MemberDigest, MemberRole, MemberView, QuorumKind, QuorumView, member_not_found,
    };
    use tenko_core::{
        Authorizer, Denied, DenyReason, Principal, RequestCtx, ScopeFilter, Timestamp,
    };
    use tenko_store::{MemStore, Store};
    use tower::ServiceExt;

    use super::*;
    use crate::{API_BASE, problem::PROBLEM_JSON};

    /// What the fake service was asked.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        View,
        Promote(NodeId, PromoteRequest),
        Remove(NodeId),
        StepDown,
        Digests(Option<Revision>),
    }

    /// Records its calls and answers with fixed documents, or fails with one error.
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<Call>>,
        failure: Option<ClusterError>,
    }

    impl Fake {
        fn failing(error: ClusterError) -> Self {
            Self {
                calls: Mutex::default(),
                failure: Some(error),
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().expect("calls").clone()
        }

        fn record<T>(&self, call: Call, answer: T) -> Result<T, ClusterError> {
            self.calls.lock().expect("calls").push(call);
            match &self.failure {
                Some(error) => Err(error.clone()),
                None => Ok(answer),
            }
        }
    }

    impl ClusterAdmin for Fake {
        fn view<'life0, 'async_trait>(
            &'life0 self,
        ) -> Pin<Box<dyn Future<Output = Result<ClusterView, ClusterError>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(std::future::ready(self.record(Call::View, cluster_view())))
        }

        fn promote<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _cx: &'life1 RequestCtx,
            node: NodeId,
            request: PromoteRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ClusterView, ClusterError>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(std::future::ready(
                self.record(Call::Promote(node, request), cluster_view()),
            ))
        }

        fn remove<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _cx: &'life1 RequestCtx,
            node: NodeId,
        ) -> Pin<Box<dyn Future<Output = Result<ClusterView, ClusterError>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(std::future::ready(
                self.record(Call::Remove(node), cluster_view()),
            ))
        }

        fn step_down<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _cx: &'life1 RequestCtx,
        ) -> Pin<Box<dyn Future<Output = Result<StepDown, ClusterError>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            let moved = StepDown {
                previous: NodeId(1),
                leader: NodeId(1001),
                term: 4,
            };
            Box::pin(std::future::ready(self.record(Call::StepDown, moved)))
        }

        fn digests<'life0, 'async_trait>(
            &'life0 self,
            revision: Option<Revision>,
        ) -> Pin<Box<dyn Future<Output = Result<DigestReport, ClusterError>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(std::future::ready(
                self.record(Call::Digests(revision), digest_report(revision)),
            ))
        }
    }

    fn at() -> Timestamp {
        "2026-10-10T08:00:00Z".parse().expect("time")
    }

    fn member(node: u64, name: &str, role: MemberRole, leader: bool) -> MemberView {
        MemberView {
            node: NodeId(node),
            name: Some(name.to_owned()),
            address: Some(format!("{name}.example.test:8444")),
            role,
            leader,
            matched: Some(120),
            lag_entries: Some(0),
            last_contact_ms: Some(40),
            version: Some("0.0.1".to_owned()),
            data_format: Some(3),
            joined_at: Some(at()),
            protocol_majors: Vec::new(),
            raft_wire: None,
            formats: Vec::new(),
        }
    }

    fn cluster_view() -> ClusterView {
        ClusterView {
            node: NodeId(1),
            leader: Some(NodeId(1)),
            term: 3,
            quorum: QuorumView {
                state: QuorumKind::Healthy,
                since: None,
                last_contact: None,
                applied: None,
            },
            changing: false,
            members: vec![
                member(1, "controller-1", MemberRole::Voter, true),
                member(1001, "controller-2", MemberRole::Voter, false),
                member(1002, "controller-3", MemberRole::Learner, false),
            ],
            job_id: None,
        }
    }

    fn digest_report(revision: Option<Revision>) -> DigestReport {
        let digest = |node: u64| MemberDigest {
            node: NodeId(node),
            revision: Some(Revision(42)),
            sha256: Some("ab".repeat(32)),
            tables: Some(31),
            entries: Some(900),
            error: None,
        };
        DigestReport {
            revision: revision.unwrap_or(Revision(42)),
            agree: true,
            members: vec![digest(1), digest(1001), digest(1002)],
        }
    }

    /// Denies one action, allows the rest.
    struct Deny(Action);

    impl Authorizer for Deny {
        fn check(&self, _: &Principal, action: Action, object: &ObjectRef) -> Result<(), Denied> {
            if action == self.0 {
                return Err(Denied {
                    action,
                    object: *object,
                    reason: DenyReason::MissingPermission,
                });
            }
            Ok(())
        }

        fn scope(&self, _: &Principal, action: Action, _: ObjectKind) -> ScopeFilter {
            if action == self.0 {
                ScopeFilter::Nothing
            } else {
                ScopeFilter::All
            }
        }
    }

    /// Allows everything and records what it was asked.
    #[derive(Default)]
    struct Record(Mutex<Vec<(Action, ObjectRef)>>);

    impl Authorizer for Record {
        fn check(&self, _: &Principal, action: Action, object: &ObjectRef) -> Result<(), Denied> {
            self.0.lock().expect("log").push((action, *object));
            Ok(())
        }

        fn scope(&self, _: &Principal, _: Action, _: ObjectKind) -> ScopeFilter {
            ScopeFilter::All
        }
    }

    fn router(authorizer: Option<Arc<dyn Authorizer>>, admin: Option<Arc<Fake>>) -> Router {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let mut state = AppState::new(store);
        state.authorizer = authorizer;
        let router = router.with_state(state);
        match admin {
            Some(admin) => router.layer(Extension(admin as Arc<dyn ClusterAdmin>)),
            None => router,
        }
    }

    /// A router with a fake that answers, and the fake.
    fn serving() -> (Router, Arc<Fake>) {
        let fake = Arc::new(Fake::default());
        (router(None, Some(Arc::clone(&fake))), fake)
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Value,
    }

    impl Reply {
        fn assert_problem(&self, status: u16, code: &str) {
            let label = format!("{} {}", self.status, self.body);
            assert_eq!(self.status.as_u16(), status, "{label}");
            assert_eq!(
                self.headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some(PROBLEM_JSON),
                "{label}"
            );
            assert_eq!(self.body["code"], code, "{label}");
        }
    }

    async fn send(router: &Router, method: &str, path: &str, body: Option<Value>) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
        let body = match body {
            Some(value) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let response = router
            .clone()
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("JSON body")
        };
        Reply {
            status,
            headers,
            body,
        }
    }

    #[tokio::test]
    async fn without_the_service_every_route_is_a_stub() {
        let stub = router(None, None);
        for (method, path, body) in [
            ("GET", "/cluster/members", None),
            (
                "POST",
                "/cluster/members/1002/promote",
                Some(json!({ "force": true })),
            ),
            ("DELETE", "/cluster/members/1002", None),
            ("POST", "/cluster/step-down", None),
            ("GET", "/cluster/digests", None),
            ("GET", "/cluster/digests?revision=7", None),
        ] {
            send(&stub, method, path, body)
                .await
                .assert_problem(501, "sys.not_implemented");
        }
    }

    #[tokio::test]
    async fn the_members_are_listed() {
        let (router, fake) = serving();
        let reply = send(&router, "GET", "/cluster/members", None).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert_eq!(reply.body["node"], 1);
        assert_eq!(reply.body["leader"], 1);
        assert_eq!(reply.body["term"], 3);
        assert_eq!(reply.body["quorum"]["state"], "healthy");
        assert_eq!(reply.body["changing"], false);
        let members = reply.body["members"].as_array().expect("members");
        assert_eq!(members.len(), 3);
        assert_eq!(members[0]["node"], 1);
        assert_eq!(members[0]["leader"], true);
        assert_eq!(members[1]["node"], 1001);
        assert_eq!(members[2]["node"], 1002);
        assert_eq!(members[2]["role"], "learner");
        assert_eq!(members[2]["address"], "controller-3.example.test:8444");
        assert_eq!(members[2]["lag_entries"], 0);
        assert_eq!(fake.calls(), vec![Call::View]);
    }

    #[tokio::test]
    async fn promotion_passes_the_node_and_the_body_through() {
        let (router, fake) = serving();
        let reply = send(
            &router,
            "POST",
            "/cluster/members/1001/promote",
            Some(json!({ "force": true, "replace": 1002 })),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert_eq!(reply.body["members"].as_array().map(Vec::len), Some(3));
        let empty = send(
            &router,
            "POST",
            "/cluster/members/1002/promote",
            Some(json!({})),
        )
        .await;
        assert_eq!(empty.status, StatusCode::OK, "{}", empty.body);
        let none = send(&router, "POST", "/cluster/members/1002/promote", None).await;
        assert_eq!(none.status, StatusCode::OK, "{}", none.body);
        assert_eq!(
            fake.calls(),
            vec![
                Call::Promote(
                    NodeId(1001),
                    PromoteRequest {
                        force: true,
                        replace: Some(NodeId(1002)),
                    }
                ),
                Call::Promote(NodeId(1002), PromoteRequest::default()),
                Call::Promote(NodeId(1002), PromoteRequest::default()),
            ]
        );
        send(
            &router,
            "POST",
            "/cluster/members/1002/promote",
            Some(json!({ "forced": true })),
        )
        .await
        .assert_problem(400, "sys.invalid_request");
        assert_eq!(fake.calls().len(), 3, "a bad body reached the service");
    }

    #[tokio::test]
    async fn removal_passes_the_node_through() {
        let (router, fake) = serving();
        let reply = send(&router, "DELETE", "/cluster/members/1002", None).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert_eq!(reply.body["members"].as_array().map(Vec::len), Some(3));
        assert_eq!(fake.calls(), vec![Call::Remove(NodeId(1002))]);
    }

    #[tokio::test]
    async fn step_down_answers_who_leads_now() {
        let (router, fake) = serving();
        let reply = send(&router, "POST", "/cluster/step-down", None).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert_eq!(
            reply.body,
            json!({ "previous": 1, "leader": 1001, "term": 4 })
        );
        assert_eq!(fake.calls(), vec![Call::StepDown]);
    }

    #[tokio::test]
    async fn digests_take_an_optional_revision() {
        let (router, fake) = serving();
        let newest = send(&router, "GET", "/cluster/digests", None).await;
        assert_eq!(newest.status, StatusCode::OK, "{}", newest.body);
        assert_eq!(newest.body["revision"], 42);
        assert_eq!(newest.body["agree"], true);
        assert_eq!(newest.body["members"].as_array().map(Vec::len), Some(3));
        assert_eq!(newest.body["members"][1]["node"], 1001);
        assert_eq!(
            newest.body["members"][0]["sha256"].as_str().map(str::len),
            Some(64)
        );
        let named = send(&router, "GET", "/cluster/digests?revision=7", None).await;
        assert_eq!(named.status, StatusCode::OK, "{}", named.body);
        assert_eq!(named.body["revision"], 7);
        assert_eq!(
            fake.calls(),
            vec![Call::Digests(None), Call::Digests(Some(Revision(7)))]
        );

        let bad = send(&router, "GET", "/cluster/digests?revision=x", None).await;
        bad.assert_problem(400, "sys.invalid_query");
        assert_eq!(bad.body["errors"][0]["field"], "revision", "{}", bad.body);
        send(&router, "GET", "/cluster/digests?revision=-1", None)
            .await
            .assert_problem(400, "sys.invalid_query");
        send(
            &router,
            "GET",
            "/cluster/digests?revision=7&revision=8",
            None,
        )
        .await
        .assert_problem(400, "sys.invalid_query");
        send(&router, "GET", "/cluster/digests?bogus=1", None)
            .await
            .assert_problem(400, "sys.invalid_query");
        assert_eq!(fake.calls().len(), 2, "a bad query reached the service");
    }

    #[tokio::test]
    async fn a_bad_node_id_is_refused_before_the_service() {
        let (router, fake) = serving();
        for (method, path, body) in [
            ("POST", "/cluster/members/abc/promote", Some(json!({}))),
            ("POST", "/cluster/members/0/promote", Some(json!({}))),
            ("POST", "/cluster/members/-1/promote", Some(json!({}))),
            ("DELETE", "/cluster/members/abc", None),
            ("DELETE", "/cluster/members/0", None),
            ("DELETE", "/cluster/members/1.5", None),
        ] {
            let reply = send(&router, method, path, body).await;
            reply.assert_problem(400, "sys.invalid_request");
            assert_eq!(reply.body["params"]["field"], "id", "{path}");
        }
        assert_eq!(fake.calls().len(), 0, "a bad id reached the service");
    }

    #[tokio::test]
    async fn coded_errors_of_the_service_become_problems() {
        for (code, status) in [
            ("cluster.member.even_voters", 409),
            ("cluster.member.not_caught_up", 409),
            ("cluster.member.last_voter", 409),
            ("cluster.member.no_successor", 409),
            ("cluster.member.changing", 409),
            ("cluster.single", 409),
            ("cluster.member.not_leader", 503),
            ("cluster.member.starting", 503),
        ] {
            let error = ClusterError::new(code, status, "refused by the test");
            let fake = Arc::new(Fake::failing(error));
            let router = router(None, Some(Arc::clone(&fake)));
            for (method, path, body) in [
                ("GET", "/cluster/members", None),
                ("POST", "/cluster/members/1002/promote", Some(json!({}))),
                ("DELETE", "/cluster/members/1002", None),
                ("POST", "/cluster/step-down", None),
                ("GET", "/cluster/digests", None),
            ] {
                let reply = send(&router, method, path, body).await;
                reply.assert_problem(status, code);
                assert_eq!(reply.body["detail"], "refused by the test", "{path}");
            }
            assert_eq!(fake.calls().len(), 5, "{code}");
        }

        let fake = Arc::new(Fake::failing(member_not_found(NodeId(7))));
        let router = router(None, Some(fake));
        let reply = send(&router, "DELETE", "/cluster/members/7", None).await;
        reply.assert_problem(404, "cluster.member.not_found");
        assert_eq!(reply.body["params"]["node"], "7", "{}", reply.body);
    }

    #[tokio::test]
    async fn permissions_are_checked() {
        let fake = Arc::new(Fake::default());
        let no_admin = router(
            Some(Arc::new(Deny(Action::Update))),
            Some(Arc::clone(&fake)),
        );
        send(
            &no_admin,
            "POST",
            "/cluster/members/1002/promote",
            Some(json!({})),
        )
        .await
        .assert_problem(403, "auth.forbidden");
        send(&no_admin, "POST", "/cluster/step-down", None)
            .await
            .assert_problem(403, "auth.forbidden");
        let no_delete = router(
            Some(Arc::new(Deny(Action::Delete))),
            Some(Arc::clone(&fake)),
        );
        send(&no_delete, "DELETE", "/cluster/members/1002", None)
            .await
            .assert_problem(403, "auth.forbidden");
        assert_eq!(fake.calls().len(), 0, "a denied change reached the service");
        // Reading is a different right.
        assert_eq!(
            send(&no_admin, "GET", "/cluster/members", None)
                .await
                .status,
            StatusCode::OK
        );
        assert_eq!(
            send(&no_admin, "GET", "/cluster/digests", None)
                .await
                .status,
            StatusCode::OK
        );

        let fake = Arc::new(Fake::default());
        let blind = router(Some(Arc::new(Deny(Action::Read))), Some(Arc::clone(&fake)));
        send(&blind, "GET", "/cluster/members", None)
            .await
            .assert_problem(403, "auth.forbidden");
        send(&blind, "GET", "/cluster/digests", None)
            .await
            .assert_problem(403, "auth.forbidden");
        assert_eq!(fake.calls().len(), 0, "a denied read reached the service");
        assert_eq!(
            send(&blind, "POST", "/cluster/step-down", None)
                .await
                .status,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn each_route_asks_for_its_own_right() {
        let record = Arc::new(Record::default());
        let fake = Arc::new(Fake::default());
        let authorizer: Arc<dyn Authorizer> = record.clone();
        let router = router(Some(authorizer), Some(fake));
        for (method, path, body) in [
            ("GET", "/cluster/members", None),
            ("POST", "/cluster/members/1002/promote", Some(json!({}))),
            ("DELETE", "/cluster/members/1002", None),
            ("POST", "/cluster/step-down", None),
            ("GET", "/cluster/digests", None),
        ] {
            let reply = send(&router, method, path, body).await;
            assert_eq!(reply.status, StatusCode::OK, "{path} {}", reply.body);
        }
        let nodes = ObjectRef::singleton(ObjectKind::Node);
        let member = ObjectRef::node(NodeId(1002));
        assert_eq!(
            *record.0.lock().expect("log"),
            vec![
                (Action::Read, nodes),
                (Action::Update, member),
                (Action::Delete, member),
                (Action::Update, nodes),
                (Action::Read, nodes),
            ]
        );
    }

    #[test]
    fn the_document_lists_the_operations_under_the_cluster_tag() {
        let (_, api) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let document = serde_json::to_value(&api).expect("document");
        for (path, method, operation) in [
            ("/members", "get", "list_cluster_members"),
            ("/members/{id}/promote", "post", "promote_cluster_member"),
            ("/members/{id}", "delete", "remove_cluster_member"),
            ("/step-down", "post", "step_down_cluster_leader"),
            ("/digests", "get", "get_cluster_digests"),
        ] {
            let path = format!("{API_BASE}/cluster{path}");
            let found = &document["paths"][path.as_str()][method];
            assert_eq!(found["operationId"], operation, "{path}");
            assert_eq!(found["tags"], json!(["cluster"]), "{path}");
        }
    }
}
