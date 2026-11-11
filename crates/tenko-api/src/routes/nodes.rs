//! Cluster nodes: enrollment tokens, enrollment, the node registry and revocation (OPS-04,
//! OPS-08).
//!
//! Area: nodes. Owner: WP2.2.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /nodes` | 200 page of [`NodeView`] by id, each with its live connection | 400 `sys.invalid_query`, `sys.invalid_cursor` |
//! | `GET /nodes/{id}` | 200 [`NodeView`] with `ETag` | 400, 403, 404 `cluster.node.not_found` |
//! | `DELETE /nodes/{id}` | 204: the node is revoked, its connections close | 403, 404, 409 `cluster.node.conflict` |
//! | `POST /nodes/enrollments` | 201 [`CreatedEnrollment`] with the token, `Cache-Control: no-store` | 400, 403 (`auth.step_up_required` for a controller token), 501 `sys.not_implemented` (a controller token without the authentication service), 409 `cluster.node.name_taken`, 422 `cluster.enrollment.*`, `cluster.node.name` |
//! | `GET /nodes/enrollments` | 200 [`EnrollmentList`], newest first, never a secret | 403 |
//! | `DELETE /nodes/enrollments/{id}` | 204 | 403, 404 `cluster.enrollment.not_found` |
//! | `POST /nodes/enroll` | 201 [`EnrollResponse`] (public: the token authenticates) | 400, 401 `cluster.enrollment.invalid_token`, `.used`, `.expired`; 403 `cluster.enrollment.roles`, `cluster.enrollment.plain_http`, `cluster.enrollment.scheme_unknown`; 409 `cluster.protocol.unsupported`, `cluster.node.name_taken`; 422 `cluster.ca.invalid_csr`, `cluster.node.name`, `cluster.node.address` |
//!
//! # The service
//!
//! The server adds the node registry ([`NodeRegistry`]) as a request extension. Without it,
//! every endpoint answers `501` `sys.not_implemented`.
//!
//! # Authorization
//!
//! Reading nodes needs [`Action::Read`] on nodes (viewers and operators have it); creating,
//! listing and deleting enrollment tokens needs [`Action::Create`] on nodes, revoking
//! [`Action::Delete`] on the node: both are administrator rights. A token for the role
//! `controller` (a host that joins the controller cluster and receives the key encryption
//! keys, R22) also needs a sign-in within the last five minutes, like installs, and lives
//! at most an hour. `POST /nodes/enroll` takes no session: the single-use token is the
//! credential, and every refusal is audited. A token that arrives over plain HTTP is
//! accepted only under the Lab profile, and recorded with `transport: http`; under every
//! other profile it is refused with 403 `cluster.enrollment.plain_http` and withdrawn, since
//! it crossed the network in clear text. A token that arrives through a trusted reverse
//! proxy that did not state the scheme (no `X-Forwarded-Proto`, no PROXY protocol SSL
//! record) is accepted only under Lab as well, recorded with `transport: unknown`; under
//! every other profile it is refused with 403 `cluster.enrollment.scheme_unknown` and kept,
//! since nothing shows that it was exposed.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use tenko_auth::settings::Profile;
use tenko_cluster::{
    error::ClusterError,
    model::{
        CreatedEnrollment, EnrollRequest, EnrollResponse, EnrollmentView, NewEnrollment, NodeView,
    },
    registry::{EnrollTransport, NodeRegistry},
};
use tenko_core::{
    Action, CodedError, NodeId, ObjectKind, ObjectRef, Principal, ScopeFilter, error::codes,
};
use tenko_store::{ReadConsistency, ReadViewExt as _};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{
    auth::{ApiJson, PublicCtx},
    not_implemented,
};
use crate::{
    dto::Page,
    extract::{ClientInfo, Ctx},
    list::{Filters, encode_cursor},
    problem::{ApiError, ProblemDetails},
    server::forwarded::UnstatedScheme,
    state::AppState,
};

/// Names the list endpoint in cursors.
const CURSOR_ENDPOINT: &str = "cluster.nodes";

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_nodes))
        .routes(routes!(get_node, revoke_node))
        .routes(routes!(list_enrollments, create_enrollment))
        .routes(routes!(delete_enrollment))
        .routes(routes!(enroll_node))
        // The paths of 0.0.11 answer as before, outside the OpenAPI document.
        .route("/nodes/enrol", post(enroll_node)) // spelling: alias until 0.0.13
        .route(
            "/nodes/enrolments", // spelling: alias until 0.0.13
            get(list_enrollments).post(create_enrollment),
        )
        .route("/nodes/enrolments/{id}", delete(delete_enrollment)) // spelling: alias until 0.0.13
}

/// Body of `GET /nodes/enrollments`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EnrollmentList {
    /// Every token, newest first.
    pub items: Vec<EnrollmentView>,
}

type Registry = Option<Extension<Arc<NodeRegistry>>>;

fn registry_or_stub(
    registry: Registry,
    method: &str,
    path: &str,
) -> Result<Arc<NodeRegistry>, ApiError> {
    registry
        .map(|Extension(registry)| registry)
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

fn parse_enrollment(raw: &str) -> Result<Uuid, ApiError> {
    raw.parse().map_err(|_| {
        invalid_request("the enrollment identifier is not a UUID").with_param("field", "id")
    })
}

fn may_read_any(app: &AppState, principal: &Principal) -> bool {
    app.authorizer.as_ref().is_none_or(|authorizer| {
        !matches!(
            authorizer.scope(principal, Action::Read, ObjectKind::Node),
            ScopeFilter::Nothing
        )
    })
}

fn with_etag(view: NodeView) -> Response {
    let etag = HeaderValue::from_str(&format!("\"{}\"", view.revision.0)).ok();
    let mut response = Json(view).into_response();
    if let Some(etag) = etag {
        response.headers_mut().insert(header::ETAG, etag);
    }
    response
}

/// Lists the enrolled nodes by id, each with its roles, certificate, protocol state and,
/// while it is connected to this controller, its live connection.
#[utoipa::path(
    get,
    path = "/nodes",
    tag = "nodes",
    operation_id = "list_nodes",
    summary = "List cluster nodes",
    params(crate::list::PageParams),
    responses(
        (status = 200, description = "A page of nodes by id; empty without permission to read nodes", body = Page<NodeView>),
        (status = 400, description = "A parameter is unknown or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_nodes(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    registry: Registry,
    filters: Filters,
) -> Result<Json<Page<NodeView>>, ApiError> {
    let registry = registry_or_stub(registry, "GET", "/nodes")?;
    filters.only(&[])?;
    let page = filters.page()?;
    let limit = page.limit()?;
    let scope = filters.scope(CURSOR_ENDPOINT);
    let after: Option<u64> = page.cursor(scope)?;
    let revision = app.store.status().revision;
    if !may_read_any(&app, &cx.principal) {
        return Ok(Json(Page::new(Vec::new(), None, revision)));
    }
    let mut items: Vec<NodeView> = registry
        .list_nodes()
        .await
        .map_err(failed)?
        .into_iter()
        .filter(|view| after.is_none_or(|after| view.id.0 > after))
        .collect();
    let next = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|last| encode_cursor(scope, &last.id.0))
    } else {
        None
    };
    Ok(Json(Page::new(items, next, revision)))
}

/// Shows one node with its live connection.
#[utoipa::path(
    get,
    path = "/nodes/{id}",
    tag = "nodes",
    operation_id = "get_node",
    summary = "Get a cluster node",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 200, description = "The node, with `ETag`", body = NodeView),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to read nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_node(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    registry: Registry,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let registry = registry_or_stub(registry, "GET", "/nodes/{id}")?;
    let id = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(id))?;
    let view = registry.get_node(id).await.map_err(failed)?;
    Ok(with_etag(view))
}

/// Revokes a node: it is removed from the registry, every certificate it was issued is
/// refused from now on, its heartbeat stream is told and its connections close. The node
/// must be enrolled again with a new token to come back, under a new id.
#[utoipa::path(
    delete,
    path = "/nodes/{id}",
    tag = "nodes",
    operation_id = "revoke_node",
    summary = "Revoke a cluster node",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to revoke nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node changed at the same time (`cluster.node.conflict`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn revoke_node(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    registry: Registry,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let registry = registry_or_stub(registry, "DELETE", "/nodes/{id}")?;
    let id = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::node(id))?;
    registry.revoke(&cx, id).await.map_err(failed)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Lists the enrollment tokens, newest first, with their state (`pending`, `used`,
/// `expired`) and the node a used one enrolled. The token text is never shown again.
#[utoipa::path(
    get,
    path = "/nodes/enrollments",
    tag = "nodes",
    operation_id = "list_enrollments",
    summary = "List enrollment tokens",
    responses(
        (status = 200, description = "Every token, newest first", body = EnrollmentList),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to enroll nodes", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_enrollments(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    registry: Registry,
) -> Result<Json<EnrollmentList>, ApiError> {
    let registry = registry_or_stub(registry, "GET", "/nodes/enrollments")?;
    app.authorize(
        &cx.principal,
        Action::Create,
        &ObjectRef::singleton(ObjectKind::Node),
    )?;
    let items = registry.list_enrollments(cx.now).await.map_err(failed)?;
    Ok(Json(EnrollmentList { items }))
}

/// Creates a single-use enrollment token for a probe, DNS or DHCP node. The token is in
/// this answer only; the controller keeps a digest. The answer also carries the CA root
/// fingerprint and the command to run on the node, and opens the cluster port when it
/// starts on demand.
#[utoipa::path(
    post,
    path = "/nodes/enrollments",
    tag = "nodes",
    operation_id = "create_enrollment",
    summary = "Create an enrollment token",
    request_body(content = NewEnrollment, content_type = "application/json"),
    responses(
        (status = 201, description = "The token, shown once (`Cache-Control: no-store`)", body = CreatedEnrollment),
        (status = 400, description = "The body is not valid JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to enroll nodes, or a controller token without a sign-in in the last five minutes (`auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A node has the name (`cluster.node.name_taken`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The role controller beside another role (`cluster.enrollment.roles`), a lifetime outside 60 s to 7 days or a controller token for more than an hour (`cluster.enrollment.lifetime`), or a bad name (`cluster.node.name`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn create_enrollment(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    registry: Registry,
    auth: Option<Extension<Arc<tenko_auth::AuthService>>>,
    client: ClientInfo,
    ApiJson(request): ApiJson<NewEnrollment>,
) -> Result<Response, ApiError> {
    let registry = registry_or_stub(registry, "POST", "/nodes/enrollments")?;
    app.authorize(
        &cx.principal,
        Action::Create,
        &ObjectRef::singleton(ObjectKind::Node),
    )?;
    let controller = request.roles.contains(&tenko_core::Role::Controller);
    if controller {
        // A controller receives the installation's key encryption keys (R22): only an
        // interactive sign-in within the last five minutes creates its token. Without the
        // authentication service nothing can check that, so nothing creates one.
        let Some(Extension(auth)) = &auth else {
            return Err(not_implemented("POST", "/nodes/enrollments"));
        };
        if !matches!(cx.principal, Principal::User { .. }) {
            return Err(ApiError::from_coded_error(
                CodedError::new(
                    "auth.step_up_required",
                    403,
                    "a controller token needs an interactive sign-in within the last five minutes; a personal API token cannot create one",
                )
                .with_param("required", "fresh"),
            ));
        }
        auth.require_fresh_session(&cx)
            .await
            .map_err(|error| ApiError::from_coded_error(CodedError::from_coded(&error)))?;
    }
    let (enrollment, token) = registry
        .create_enrollment(&cx, request)
        .await
        .map_err(failed)?;
    let ca_fingerprint = registry.ca().root_info().sha256.clone();
    let origin = client
        .origin()
        .unwrap_or_else(|| "https://<controller>:8443".to_owned());
    let token = token.to_text().to_string();
    let command = if controller {
        format!(
            "tenko cluster join --controller {origin} --token {token} --ca-fingerprint {ca_fingerprint} --address HOST:PORT --data-dir D"
        )
    } else {
        format!(
            "tenko node enroll --controller {origin} --token {token} --ca-fingerprint {ca_fingerprint}"
        )
    };
    let body = CreatedEnrollment {
        enrollment,
        token,
        ca_fingerprint,
        command,
    };
    let mut response = (StatusCode::CREATED, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// Deletes an enrollment token (pending, used or expired); a pending one can no longer be
/// used.
#[utoipa::path(
    delete,
    path = "/nodes/enrollments/{id}",
    tag = "nodes",
    operation_id = "delete_enrollment",
    summary = "Delete an enrollment token",
    params(("id" = String, Path, description = "Token id (UUID)")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to enroll nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such token (`cluster.enrollment.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_enrollment(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    registry: Registry,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let registry = registry_or_stub(registry, "DELETE", "/nodes/enrollments/{id}")?;
    let id = parse_enrollment(&id)?;
    app.authorize(
        &cx.principal,
        Action::Create,
        &ObjectRef::singleton(ObjectKind::Node),
    )?;
    registry.delete_enrollment(&cx, id).await.map_err(failed)?;
    Ok(StatusCode::NO_CONTENT)
}

/// How the request reached this server: over plain HTTP when it came through a listener
/// (a peer address is known) and neither the connection nor a trusted reverse proxy said
/// HTTPS; unstated when a trusted reverse proxy said nothing about the scheme
/// ([`UnstatedScheme`]). A router used without a listener (tests) counts as HTTPS.
fn transport(client: Option<&ClientInfo>, unstated: bool) -> EnrollTransport {
    match client {
        Some(client) if client.peer.is_some() && !client.https => EnrollTransport::PlainHttp,
        Some(client) if client.peer.is_some() && unstated => EnrollTransport::Unstated,
        _ => EnrollTransport::Https,
    }
}

/// The stored security profile; Standard when none is stored, so that a missing record
/// never allows plain HTTP.
async fn plain_http_profile(app: &AppState) -> Result<Profile, ApiError> {
    let view = app.store.read(ReadConsistency::Local).await?;
    Ok(view
        .get_typed(&tenko_auth::model::SETTINGS, &())?
        .map_or(Profile::Standard, |(settings, _)| settings.profile))
}

/// Enrolls a node: it presents its token and a certificate request over its own key, and
/// gets its node id, its certificate (with the id and roles) and the CA root it trusts on
/// the cluster port. The token is used up. `tenko node enroll` calls this.
#[utoipa::path(
    post,
    path = "/nodes/enroll",
    tag = "nodes",
    operation_id = "enroll_node",
    summary = "Enroll a node with a token",
    request_body(content = EnrollRequest, content_type = "application/json"),
    responses(
        (status = 201, description = "The node, its certificate and the CA root (`Cache-Control: no-store`)", body = EnrollResponse),
        (status = 400, description = "The body is not valid JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "The token is not valid (`cluster.enrollment.invalid_token`), was created by another controller (`cluster.enrollment.wrong_controller`), was used (`cluster.enrollment.used`) or expired (`cluster.enrollment.expired`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The token does not allow a requested role (`cluster.enrollment.roles`), or it arrived over plain HTTP and the profile is not Lab (`cluster.enrollment.plain_http`; the token is withdrawn), or through a trusted reverse proxy that did not state the scheme and the profile is not Lab (`cluster.enrollment.scheme_unknown`; the token is kept)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "No common protocol major (`cluster.protocol.unsupported`) or the name is taken (`cluster.node.name_taken`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The certificate request (`cluster.ca.invalid_csr`), the name (`cluster.node.name`) or the address (`cluster.node.address`) is not usable", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security()
)]
async fn enroll_node(
    State(app): State<AppState>,
    PublicCtx { ctx, .. }: PublicCtx,
    client: Option<Extension<ClientInfo>>,
    unstated: Option<Extension<UnstatedScheme>>,
    registry: Registry,
    ApiJson(request): ApiJson<EnrollRequest>,
) -> Result<Response, ApiError> {
    let registry = registry_or_stub(registry, "POST", "/nodes/enroll")?;
    let mut cx = ctx;
    cx.principal = Principal::system(tenko_core::SystemComponent::Cluster);
    let transport = transport(
        client.as_ref().map(|Extension(client)| client),
        unstated.is_some(),
    );
    if transport != EnrollTransport::Https && plain_http_profile(&app).await? != Profile::Lab {
        let refusal = match transport {
            EnrollTransport::PlainHttp => registry.refuse_plain_http(&cx, &request).await,
            _ => registry.refuse_unstated_scheme(&cx).await,
        };
        return Err(failed(refusal));
    }
    let enrolled = registry
        .enroll_over(&cx, request, transport)
        .await
        .map_err(failed)?;
    let body = EnrollResponse {
        node: enrolled.node,
        certificate: enrolled.certificate_pem,
        ca_root: enrolled.ca_root_pem,
        endpoints: registry.endpoints(),
        cluster_port: Some(registry.cluster_port()),
        heartbeat_secs: registry.config().heartbeat_secs,
        majors: registry.config().majors.clone(),
    };
    let mut response = (StatusCode::CREATED, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{HeaderMap, Request},
    };
    use serde_json::{Value, json};
    use tenko_cluster::{
        ca::{CaPolicy, InternalCa, generate_csr, pem_block},
        registry::RegistryConfig,
        token::{CaFingerprint, EnrollmentToken},
    };
    use tenko_core::{Authorizer, Denied, DenyReason, RequestCtx, SystemComponent};
    use tenko_jobs::{EngineConfig, JobEngine};
    use tenko_store::{MemStore, Store};
    use tenko_vault::MemVault;
    use tower::ServiceExt;

    use super::*;
    use crate::{API_BASE, problem::PROBLEM_JSON};

    /// Denies one action on nodes, allows the rest.
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

    async fn router(authorizer: Option<Arc<dyn Authorizer>>, with_registry: bool) -> Router {
        router_on(Arc::new(MemStore::default()), authorizer, with_registry).await
    }

    async fn router_on(
        store: Arc<MemStore>,
        authorizer: Option<Arc<dyn Authorizer>>,
        with_registry: bool,
    ) -> Router {
        let vault = MemVault::with_store(store.clone());
        let ctx = RequestCtx::system(SystemComponent::Cluster);
        let ca = InternalCa::load_or_init(&*store, &vault, &ctx, CaPolicy::default())
            .await
            .expect("CA");
        let store: Arc<dyn Store> = store;
        let engine = JobEngine::new(Arc::clone(&store), EngineConfig::default());
        let registry = NodeRegistry::new(
            Arc::clone(&store),
            Arc::new(ca),
            RegistryConfig::new(NodeId(1)),
        );
        registry.register_steps(&engine);
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let mut state = AppState::new(store);
        state.authorizer = authorizer;
        let router = router.with_state(state);
        if with_registry {
            router.layer(Extension(registry))
        } else {
            router
        }
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

    fn csr() -> String {
        let (_, csr) = generate_csr().expect("csr");
        pem_block("CERTIFICATE REQUEST", &csr)
    }

    async fn token(router: &Router) -> String {
        let created = send(
            router,
            "POST",
            "/nodes/enrollments",
            Some(json!({ "roles": ["probe"] })),
        )
        .await;
        assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
        created.body["token"].as_str().expect("token").to_owned()
    }

    #[tokio::test]
    async fn tokens_are_created_once_listed_without_secret_and_deleted() {
        let router = router(None, true).await;
        let created = send(
            &router,
            "POST",
            "/nodes/enrollments",
            Some(json!({ "name": "probe-dmz", "expires_in_secs": 600 })),
        )
        .await;
        assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
        assert_eq!(created.headers[header::CACHE_CONTROL], "no-store");
        let text = created.body["token"].as_str().expect("token");
        assert!(text.starts_with("tnk2.") && text.len() == 125, "{text}");
        let fingerprint = created.body["ca_fingerprint"]
            .as_str()
            .expect("fingerprint");
        assert_eq!(fingerprint.len(), 64);
        // The token carries the fingerprint the answer shows.
        assert_eq!(
            EnrollmentToken::parse(text)
                .expect("a token")
                .ca_fingerprint()
                .map(|carried| carried.to_hex()),
            Some(fingerprint.to_owned())
        );
        let command = created.body["command"].as_str().expect("command");
        assert!(
            command.contains(text) && command.contains(fingerprint),
            "{command}"
        );
        assert_eq!(created.body["enrollment"]["roles"], json!(["probe"]));
        assert_eq!(created.body["enrollment"]["state"], "pending");
        let id = created.body["enrollment"]["id"]
            .as_str()
            .expect("id")
            .to_owned();

        let list = send(&router, "GET", "/nodes/enrollments", None).await;
        assert_eq!(list.status, StatusCode::OK);
        assert_eq!(list.body["items"].as_array().map(Vec::len), Some(1));
        assert!(
            !list.body.to_string().contains(text),
            "the list shows the token"
        );
        assert!(!list.body.to_string().contains("digest"));

        let deleted = send(&router, "DELETE", &format!("/nodes/enrollments/{id}"), None).await;
        assert_eq!(deleted.status, StatusCode::NO_CONTENT);
        send(&router, "DELETE", &format!("/nodes/enrollments/{id}"), None)
            .await
            .assert_problem(404, "cluster.enrollment.not_found");
        send(&router, "DELETE", "/nodes/enrollments/not-a-uuid", None)
            .await
            .assert_problem(400, "sys.invalid_request");
        // A controller token needs a fresh interactive sign-in, which only the
        // authentication service can check; this router has none, so nothing creates one
        // (the server always has it: `tenko`'s cluster tests create controller tokens).
        for body in [
            json!({ "roles": ["controller", "probe"] }),
            json!({ "roles": ["controller"], "expires_in_secs": 7200 }),
            json!({ "roles": ["controller"] }),
        ] {
            send(&router, "POST", "/nodes/enrollments", Some(body))
                .await
                .assert_problem(501, "sys.not_implemented");
        }
        send(
            &router,
            "POST",
            "/nodes/enrollments",
            Some(json!({ "expires_in_secs": 5 })),
        )
        .await
        .assert_problem(422, "cluster.enrollment.lifetime");
    }

    #[tokio::test]
    async fn the_paths_of_0_0_11_answer_like_the_documented_ones() {
        const OLD_TOKENS: &str = "/nodes/enrolments"; // spelling: alias until 0.0.13
        const OLD_ENROLL: &str = "/nodes/enrol"; // spelling: alias until 0.0.13
        let router = router(None, true).await;
        let created = send(
            &router,
            "POST",
            OLD_TOKENS,
            Some(json!({ "roles": ["probe"] })),
        )
        .await;
        assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
        assert_eq!(created.headers[header::CACHE_CONTROL], "no-store");
        let unused = send(&router, "POST", OLD_TOKENS, Some(json!({}))).await;
        assert_eq!(unused.status, StatusCode::CREATED, "{}", unused.body);
        let id = unused.body["enrollment"]["id"]
            .as_str()
            .expect("id")
            .to_owned();
        let old = send(&router, "GET", OLD_TOKENS, None).await;
        let new = send(&router, "GET", "/nodes/enrollments", None).await;
        assert_eq!(old.status, StatusCode::OK);
        assert_eq!(old.body, new.body);

        let request = json!({
            "token": created.body["token"],
            "csr": csr(),
            "name": "probe-dmz",
            "address": "192.0.2.20",
            "version": "0.0.1",
            "majors": [1],
        });
        let enrolled = send(&router, "POST", OLD_ENROLL, Some(request.clone())).await;
        assert_eq!(enrolled.status, StatusCode::CREATED, "{}", enrolled.body);
        assert_eq!(enrolled.body["node"]["id"], 1001);
        send(&router, "POST", OLD_ENROLL, Some(request))
            .await
            .assert_problem(401, "cluster.enrollment.used");

        let deleted = send(&router, "DELETE", &format!("{OLD_TOKENS}/{id}"), None).await;
        assert_eq!(deleted.status, StatusCode::NO_CONTENT);
        send(&router, "DELETE", &format!("{OLD_TOKENS}/{id}"), None)
            .await
            .assert_problem(404, "cluster.enrollment.not_found");
    }

    #[tokio::test]
    async fn a_node_enrolls_once_is_listed_and_revoked() {
        let router = router(None, true).await;
        let token_text = token(&router).await;
        let request = json!({
            "token": token_text,
            "csr": csr(),
            "name": "probe-dmz",
            "address": "192.0.2.20",
            "version": "0.0.1",
            "majors": [1],
        });
        let enrolled = send(&router, "POST", "/nodes/enroll", Some(request.clone())).await;
        assert_eq!(enrolled.status, StatusCode::CREATED, "{}", enrolled.body);
        assert_eq!(enrolled.headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(enrolled.body["node"]["id"], 1001);
        assert_eq!(enrolled.body["node"]["connected"], false);
        assert!(
            enrolled.body["certificate"]
                .as_str()
                .is_some_and(|pem| pem.starts_with("-----BEGIN CERTIFICATE-----"))
        );
        assert!(
            enrolled.body["ca_root"]
                .as_str()
                .is_some_and(|pem| pem.contains("BEGIN CERTIFICATE"))
        );
        assert_eq!(enrolled.body["majors"], json!([1]));
        assert_eq!(enrolled.body["cluster_port"], 8444);

        let mut again = request.clone();
        again["csr"] = json!(csr());
        send(&router, "POST", "/nodes/enroll", Some(again))
            .await
            .assert_problem(401, "cluster.enrollment.used");
        let mut forged = request.clone();
        forged["token"] = json!(
            "tnk1.0190d1c2000070008000000000000001.QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"
        );
        send(&router, "POST", "/nodes/enroll", Some(forged))
            .await
            .assert_problem(401, "cluster.enrollment.invalid_token");
        send(
            &router,
            "POST",
            "/nodes/enroll",
            Some(json!({ "token": "x" })),
        )
        .await
        .assert_problem(400, "sys.invalid_request");
        let mut bad_csr = request.clone();
        bad_csr["token"] = json!(token(&router).await);
        bad_csr["csr"] = json!("not a request");
        send(&router, "POST", "/nodes/enroll", Some(bad_csr))
            .await
            .assert_problem(422, "cluster.ca.invalid_csr");

        let list = send(&router, "GET", "/nodes", None).await;
        assert_eq!(list.status, StatusCode::OK);
        assert_eq!(list.body["items"][0]["name"], "probe-dmz");
        let one = send(&router, "GET", "/nodes/1001", None).await;
        assert_eq!(one.status, StatusCode::OK);
        assert!(one.headers.contains_key(header::ETAG));
        assert_eq!(one.body["address"], "192.0.2.20");
        send(&router, "GET", "/nodes/abc", None)
            .await
            .assert_problem(400, "sys.invalid_request");

        let revoked = send(&router, "DELETE", "/nodes/1001", None).await;
        assert_eq!(revoked.status, StatusCode::NO_CONTENT);
        send(&router, "GET", "/nodes/1001", None)
            .await
            .assert_problem(404, "cluster.node.not_found");
        send(&router, "DELETE", "/nodes/1001", None)
            .await
            .assert_problem(404, "cluster.node.not_found");
    }

    /// A store whose security settings name `profile`.
    async fn store_with_profile(profile: Profile) -> Arc<MemStore> {
        let store = Arc::new(MemStore::default());
        let mut batch =
            tenko_store::WriteBatch::for_request(&RequestCtx::system(SystemComponent::Api));
        batch
            .put_typed(&tenko_auth::model::SETTINGS, &(), &profile.defaults())
            .expect("settings");
        store.propose(batch).await.expect("stored");
        store
    }

    /// `POST /nodes/enroll` as a listener hands it on: from a peer, over plain HTTP.
    async fn enroll_over_plain_http(router: &Router, body: &Value) -> Reply {
        enroll_as(router, body, false, false).await
    }

    /// Enrolls through a trusted reverse proxy that did not state the scheme.
    async fn enroll_through_a_silent_proxy(router: &Router, body: &Value) -> Reply {
        enroll_as(router, body, true, true).await
    }

    async fn enroll_as(router: &Router, body: &Value, https: bool, unstated: bool) -> Reply {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{API_BASE}/nodes/enroll"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        request.extensions_mut().insert(ClientInfo {
            source_ip: Some("192.0.2.21".parse().expect("address")),
            peer: Some("192.0.2.21:40000".parse().expect("peer")),
            https,
            host: None,
            via_proxy: unstated,
        });
        if unstated {
            request.extensions_mut().insert(UnstatedScheme);
        }
        let response = router.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        Reply {
            status,
            headers,
            body: serde_json::from_slice(&bytes).expect("JSON body"),
        }
    }

    /// The context of the audit records of `action`, oldest first.
    async fn audit_contexts(
        store: &MemStore,
        action: &str,
    ) -> Vec<std::collections::BTreeMap<String, String>> {
        let view = store.read(ReadConsistency::Local).await.expect("view");
        view.scan_typed(
            &tenko_store::tables::AUDIT,
            tenko_store::KeyRange::all(),
            1000,
            false,
        )
        .expect("audit")
        .into_iter()
        .filter(|(_, record, _)| record.draft.action.as_str() == action)
        .map(|(_, record, _)| record.draft.details.context)
        .collect()
    }

    #[tokio::test]
    async fn plain_http_enrollment_is_refused_outside_lab_and_the_token_withdrawn() {
        for profile in [Profile::Home, Profile::Standard, Profile::Hardened] {
            let store = store_with_profile(profile).await;
            let router = router_on(Arc::clone(&store), None, true).await;
            let token_text = token(&router).await;
            enroll_over_plain_http(&router, &enroll_request(&token_text))
                .await
                .assert_problem(403, "cluster.enrollment.plain_http");
            // The token crossed the network in clear text: it is gone, also for HTTPS.
            send(
                &router,
                "POST",
                "/nodes/enroll",
                Some(enroll_request(&token_text)),
            )
            .await
            .assert_problem(401, "cluster.enrollment.invalid_token");
            let withdrawn = audit_contexts(&store, "cluster.enrollment.delete").await;
            assert!(
                withdrawn
                    .iter()
                    .any(|context| context.get("reason").map(String::as_str) == Some("plain_http")),
                "{profile:?}: {withdrawn:?}"
            );
        }
        // Without stored settings the answer is the same: no profile allows it by default.
        let router = router(None, true).await;
        let token_text = token(&router).await;
        enroll_over_plain_http(&router, &enroll_request(&token_text))
            .await
            .assert_problem(403, "cluster.enrollment.plain_http");
    }

    #[tokio::test]
    async fn plain_http_enrollment_under_lab_is_recorded_with_its_transport() {
        let store = store_with_profile(Profile::Lab).await;
        let router = router_on(Arc::clone(&store), None, true).await;
        let token_text = token(&router).await;
        let enrolled = enroll_over_plain_http(&router, &enroll_request(&token_text)).await;
        assert_eq!(enrolled.status, StatusCode::CREATED, "{}", enrolled.body);
        let records = audit_contexts(&store, "cluster.node.enroll").await;
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(
            records[0].get("transport").map(String::as_str),
            Some("http")
        );
        // Over HTTPS the record has no transport entry.
        let token_text = token(&router).await;
        let enrolled = send(
            &router,
            "POST",
            "/nodes/enroll",
            Some(enroll_request(&token_text)),
        )
        .await;
        assert_eq!(enrolled.status, StatusCode::CREATED, "{}", enrolled.body);
        let records = audit_contexts(&store, "cluster.node.enroll").await;
        assert_eq!(records.len(), 2, "{records:?}");
        assert!(!records[1].contains_key("transport"), "{records:?}");
    }

    #[tokio::test]
    async fn an_unstated_scheme_is_refused_outside_lab_and_the_token_kept() {
        for profile in [Profile::Home, Profile::Standard, Profile::Hardened] {
            let store = store_with_profile(profile).await;
            let router = router_on(Arc::clone(&store), None, true).await;
            let token_text = token(&router).await;
            let refused =
                enroll_through_a_silent_proxy(&router, &enroll_request(&token_text)).await;
            refused.assert_problem(403, "cluster.enrollment.scheme_unknown");
            let detail = refused.body["detail"].as_str().unwrap_or_default();
            assert!(
                detail.contains("X-Forwarded-Proto") && detail.contains("send-proxy-v2-ssl"),
                "the refusal says what to set: {detail}"
            );
            assert!(
                audit_contexts(&store, "cluster.enrollment.delete")
                    .await
                    .is_empty(),
                "{profile:?}: nothing withdrawn"
            );
            assert_eq!(
                audit_contexts(&store, "cluster.node.enroll").await.len(),
                1,
                "{profile:?}: the refusal is audited"
            );
            // The token is kept: the same token enrolls once the scheme is stated.
            let enrolled = send(
                &router,
                "POST",
                "/nodes/enroll",
                Some(enroll_request(&token_text)),
            )
            .await;
            assert_eq!(enrolled.status, StatusCode::CREATED, "{}", enrolled.body);
        }
    }

    #[tokio::test]
    async fn an_unstated_scheme_under_lab_is_recorded_as_unknown() {
        let store = store_with_profile(Profile::Lab).await;
        let router = router_on(Arc::clone(&store), None, true).await;
        let token_text = token(&router).await;
        let enrolled = enroll_through_a_silent_proxy(&router, &enroll_request(&token_text)).await;
        assert_eq!(enrolled.status, StatusCode::CREATED, "{}", enrolled.body);
        let records = audit_contexts(&store, "cluster.node.enroll").await;
        assert_eq!(
            records[0].get("transport").map(String::as_str),
            Some("unknown")
        );
    }

    /// The enrollment request for `token` with a fresh certificate request.
    fn enroll_request(token: &str) -> Value {
        json!({
            "token": token,
            "csr": csr(),
            "address": "192.0.2.21",
            "version": "0.0.1",
            "majors": [1],
        })
    }

    #[tokio::test]
    async fn a_token_of_another_controller_is_refused_and_a_tnk1_token_enrolls() {
        let router = router(None, true).await;

        // The same id and secret, but the fingerprint of another CA root.
        let text = token(&router).await;
        let ours = EnrollmentToken::parse(&text).expect("a token");
        let foreign = EnrollmentToken::parse(&text)
            .expect("a token")
            .with_ca_fingerprint(CaFingerprint::of_der(b"another controller's CA root"));
        assert_ne!(foreign.ca_fingerprint(), ours.ca_fingerprint());
        send(
            &router,
            "POST",
            "/nodes/enroll",
            Some(enroll_request(&foreign.to_text())),
        )
        .await
        .assert_problem(401, "cluster.enrollment.wrong_controller");

        // The refusal did not use the token: with the right fingerprint it enrolls.
        let enrolled = send(
            &router,
            "POST",
            "/nodes/enroll",
            Some(enroll_request(&text)),
        )
        .await;
        assert_eq!(enrolled.status, StatusCode::CREATED, "{}", enrolled.body);

        // A token in the format of 0.0.11 has no fingerprint and enrolls as before.
        let text = token(&router).await;
        let (tnk1, _) = text.rsplit_once('.').expect("four parts");
        let tnk1 = tnk1.replacen("tnk2.", "tnk1.", 1);
        assert_eq!(tnk1.len(), 81);
        let enrolled = send(
            &router,
            "POST",
            "/nodes/enroll",
            Some(enroll_request(&tnk1)),
        )
        .await;
        assert_eq!(enrolled.status, StatusCode::CREATED, "{}", enrolled.body);
        assert_eq!(enrolled.body["node"]["id"], 1002);
    }

    #[tokio::test]
    async fn permissions_are_checked() {
        let denied = router(Some(Arc::new(Deny(Action::Create))), true).await;
        send(&denied, "POST", "/nodes/enrollments", Some(json!({})))
            .await
            .assert_problem(403, "auth.forbidden");
        send(&denied, "GET", "/nodes/enrollments", None)
            .await
            .assert_problem(403, "auth.forbidden");
        let blind = router(Some(Arc::new(Deny(Action::Read))), true).await;
        let list = send(&blind, "GET", "/nodes", None).await;
        assert_eq!(list.status, StatusCode::OK);
        assert_eq!(list.body["items"], json!([]));
        send(&blind, "GET", "/nodes/1001", None)
            .await
            .assert_problem(403, "auth.forbidden");
        let no_revoke = router(Some(Arc::new(Deny(Action::Delete))), true).await;
        send(&no_revoke, "DELETE", "/nodes/1001", None)
            .await
            .assert_problem(403, "auth.forbidden");
    }

    #[tokio::test]
    async fn without_the_registry_every_route_is_a_stub() {
        let stub = router(None, false).await;
        for (method, path) in [
            ("GET", "/nodes"),
            ("GET", "/nodes/1001"),
            ("DELETE", "/nodes/1001"),
            ("GET", "/nodes/enrollments"),
            (
                "DELETE",
                "/nodes/enrollments/0190d1c2-0000-7000-8000-000000000001",
            ),
        ] {
            send(&stub, method, path, None)
                .await
                .assert_problem(501, "sys.not_implemented");
        }
        send(&stub, "POST", "/nodes/enrollments", Some(json!({})))
            .await
            .assert_problem(501, "sys.not_implemented");
        send(
            &stub,
            "POST",
            "/nodes/enroll",
            Some(json!({ "token": "x", "csr": "y" })),
        )
        .await
        .assert_problem(501, "sys.not_implemented");
    }
}
