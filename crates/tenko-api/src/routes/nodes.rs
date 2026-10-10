//! Cluster nodes: enrolment tokens, enrolment, the node registry and revocation (OPS-04,
//! OPS-08).
//!
//! Area: nodes. Owner: WP2.2.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /nodes` | 200 page of [`NodeView`] by id, each with its live connection | 400 `sys.invalid_query`, `sys.invalid_cursor` |
//! | `GET /nodes/{id}` | 200 [`NodeView`] with `ETag` | 400, 403, 404 `cluster.node.not_found` |
//! | `DELETE /nodes/{id}` | 204: the node is revoked, its connections close | 403, 404, 409 `cluster.node.conflict` |
//! | `POST /nodes/enrolments` | 201 [`CreatedEnrolment`] with the token, `Cache-Control: no-store` | 400, 403, 409 `cluster.node.name_taken`, 422 `cluster.enrolment.*`, `cluster.node.name` |
//! | `GET /nodes/enrolments` | 200 [`EnrolmentList`], newest first, never a secret | 403 |
//! | `DELETE /nodes/enrolments/{id}` | 204 | 403, 404 `cluster.enrolment.not_found` |
//! | `POST /nodes/enrol` | 201 [`EnrolResponse`] (public: the token authenticates) | 400, 401 `cluster.enrolment.invalid_token`, `.used`, `.expired`; 403 `cluster.enrolment.roles`; 409 `cluster.protocol.unsupported`, `cluster.node.name_taken`; 422 `cluster.ca.invalid_csr`, `cluster.node.name`, `cluster.node.address` |
//!
//! # The service
//!
//! The server adds the node registry ([`NodeRegistry`]) as a request extension. Without it,
//! every endpoint answers `501` `sys.not_implemented`.
//!
//! # Authorization
//!
//! Reading nodes needs [`Action::Read`] on nodes (viewers and operators have it); creating,
//! listing and deleting enrolment tokens needs [`Action::Create`] on nodes, revoking
//! [`Action::Delete`] on the node: both are administrator rights. `POST /nodes/enrol` takes
//! no session: the single-use token is the credential, and every refusal is audited.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tenko_cluster::{
    error::ClusterError,
    model::{CreatedEnrolment, EnrolRequest, EnrolResponse, EnrolmentView, NewEnrolment, NodeView},
    registry::NodeRegistry,
};
use tenko_core::{
    Action, CodedError, NodeId, ObjectKind, ObjectRef, Principal, ScopeFilter, error::codes,
};
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
    state::AppState,
};

/// Names the list endpoint in cursors.
const CURSOR_ENDPOINT: &str = "cluster.nodes";

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_nodes))
        .routes(routes!(get_node, revoke_node))
        .routes(routes!(list_enrolments, create_enrolment))
        .routes(routes!(delete_enrolment))
        .routes(routes!(enrol_node))
}

/// Body of `GET /nodes/enrolments`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EnrolmentList {
    /// Every token, newest first.
    pub items: Vec<EnrolmentView>,
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

fn parse_enrolment(raw: &str) -> Result<Uuid, ApiError> {
    raw.parse().map_err(|_| {
        invalid_request("the enrolment identifier is not a UUID").with_param("field", "id")
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

/// Lists the enrolment tokens, newest first, with their state (`pending`, `used`,
/// `expired`) and the node a used one enrolled. The token text is never shown again.
#[utoipa::path(
    get,
    path = "/nodes/enrolments",
    tag = "nodes",
    operation_id = "list_enrolments",
    summary = "List enrolment tokens",
    responses(
        (status = 200, description = "Every token, newest first", body = EnrolmentList),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to enrol nodes", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_enrolments(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    registry: Registry,
) -> Result<Json<EnrolmentList>, ApiError> {
    let registry = registry_or_stub(registry, "GET", "/nodes/enrolments")?;
    app.authorize(
        &cx.principal,
        Action::Create,
        &ObjectRef::singleton(ObjectKind::Node),
    )?;
    let items = registry.list_enrolments(cx.now).await.map_err(failed)?;
    Ok(Json(EnrolmentList { items }))
}

/// Creates a single-use enrolment token for a probe, DNS or DHCP node. The token is in
/// this answer only; the controller keeps a digest. The answer also carries the CA root
/// fingerprint and the command to run on the node, and opens the cluster port when it
/// starts on demand.
#[utoipa::path(
    post,
    path = "/nodes/enrolments",
    tag = "nodes",
    operation_id = "create_enrolment",
    summary = "Create an enrolment token",
    request_body(content = NewEnrolment, content_type = "application/json"),
    responses(
        (status = 201, description = "The token, shown once (`Cache-Control: no-store`)", body = CreatedEnrolment),
        (status = 400, description = "The body is not valid JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to enrol nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A node has the name (`cluster.node.name_taken`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "A controller role (`cluster.enrolment.roles`), a lifetime outside 60 s to 7 days (`cluster.enrolment.lifetime`) or a bad name (`cluster.node.name`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_enrolment(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    registry: Registry,
    client: ClientInfo,
    ApiJson(request): ApiJson<NewEnrolment>,
) -> Result<Response, ApiError> {
    let registry = registry_or_stub(registry, "POST", "/nodes/enrolments")?;
    app.authorize(
        &cx.principal,
        Action::Create,
        &ObjectRef::singleton(ObjectKind::Node),
    )?;
    let (enrolment, token) = registry
        .create_enrolment(&cx, request)
        .await
        .map_err(failed)?;
    let ca_fingerprint = registry.ca().root_info().sha256.clone();
    let controller = client
        .origin()
        .unwrap_or_else(|| "https://<controller>:8443".to_owned());
    let token = token.to_text().to_string();
    let command = format!(
        "tenko node enrol --controller {controller} --token {token} --ca-fingerprint {ca_fingerprint}"
    );
    let body = CreatedEnrolment {
        enrolment,
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

/// Deletes an enrolment token (pending, used or expired); a pending one can no longer be
/// used.
#[utoipa::path(
    delete,
    path = "/nodes/enrolments/{id}",
    tag = "nodes",
    operation_id = "delete_enrolment",
    summary = "Delete an enrolment token",
    params(("id" = String, Path, description = "Token id (UUID)")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to enrol nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such token (`cluster.enrolment.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_enrolment(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    registry: Registry,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let registry = registry_or_stub(registry, "DELETE", "/nodes/enrolments/{id}")?;
    let id = parse_enrolment(&id)?;
    app.authorize(
        &cx.principal,
        Action::Create,
        &ObjectRef::singleton(ObjectKind::Node),
    )?;
    registry.delete_enrolment(&cx, id).await.map_err(failed)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Enrols a node: it presents its token and a certificate request over its own key, and
/// gets its node id, its certificate (with the id and roles) and the CA root it trusts on
/// the cluster port. The token is used up. `tenko node enrol` calls this.
#[utoipa::path(
    post,
    path = "/nodes/enrol",
    tag = "nodes",
    operation_id = "enrol_node",
    summary = "Enrol a node with a token",
    request_body(content = EnrolRequest, content_type = "application/json"),
    responses(
        (status = 201, description = "The node, its certificate and the CA root (`Cache-Control: no-store`)", body = EnrolResponse),
        (status = 400, description = "The body is not valid JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "The token is not valid (`cluster.enrolment.invalid_token`), was used (`cluster.enrolment.used`) or expired (`cluster.enrolment.expired`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The token does not allow a requested role (`cluster.enrolment.roles`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "No common protocol major (`cluster.protocol.unsupported`) or the name is taken (`cluster.node.name_taken`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The certificate request (`cluster.ca.invalid_csr`), the name (`cluster.node.name`) or the address (`cluster.node.address`) is not usable", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn enrol_node(
    PublicCtx { ctx, .. }: PublicCtx,
    registry: Registry,
    ApiJson(request): ApiJson<EnrolRequest>,
) -> Result<Response, ApiError> {
    let registry = registry_or_stub(registry, "POST", "/nodes/enrol")?;
    let mut cx = ctx;
    cx.principal = Principal::system(tenko_core::SystemComponent::Cluster);
    let enrolled = registry.enrol(&cx, request).await.map_err(failed)?;
    let body = EnrolResponse {
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
        let store = Arc::new(MemStore::default());
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
            "/nodes/enrolments",
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
            "/nodes/enrolments",
            Some(json!({ "name": "probe-dmz", "expires_in_secs": 600 })),
        )
        .await;
        assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
        assert_eq!(created.headers[header::CACHE_CONTROL], "no-store");
        let text = created.body["token"].as_str().expect("token");
        assert!(text.starts_with("tnk1.") && text.len() == 81, "{text}");
        let fingerprint = created.body["ca_fingerprint"]
            .as_str()
            .expect("fingerprint");
        assert_eq!(fingerprint.len(), 64);
        let command = created.body["command"].as_str().expect("command");
        assert!(
            command.contains(text) && command.contains(fingerprint),
            "{command}"
        );
        assert_eq!(created.body["enrolment"]["roles"], json!(["probe"]));
        assert_eq!(created.body["enrolment"]["state"], "pending");
        let id = created.body["enrolment"]["id"]
            .as_str()
            .expect("id")
            .to_owned();

        let list = send(&router, "GET", "/nodes/enrolments", None).await;
        assert_eq!(list.status, StatusCode::OK);
        assert_eq!(list.body["items"].as_array().map(Vec::len), Some(1));
        assert!(
            !list.body.to_string().contains(text),
            "the list shows the token"
        );
        assert!(!list.body.to_string().contains("digest"));

        let deleted = send(&router, "DELETE", &format!("/nodes/enrolments/{id}"), None).await;
        assert_eq!(deleted.status, StatusCode::NO_CONTENT);
        send(&router, "DELETE", &format!("/nodes/enrolments/{id}"), None)
            .await
            .assert_problem(404, "cluster.enrolment.not_found");
        send(&router, "DELETE", "/nodes/enrolments/not-a-uuid", None)
            .await
            .assert_problem(400, "sys.invalid_request");
        send(
            &router,
            "POST",
            "/nodes/enrolments",
            Some(json!({ "roles": ["controller"] })),
        )
        .await
        .assert_problem(422, "cluster.enrolment.roles");
        send(
            &router,
            "POST",
            "/nodes/enrolments",
            Some(json!({ "expires_in_secs": 5 })),
        )
        .await
        .assert_problem(422, "cluster.enrolment.lifetime");
    }

    #[tokio::test]
    async fn a_node_enrols_once_is_listed_and_revoked() {
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
        let enrolled = send(&router, "POST", "/nodes/enrol", Some(request.clone())).await;
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
        send(&router, "POST", "/nodes/enrol", Some(again))
            .await
            .assert_problem(401, "cluster.enrolment.used");
        let mut forged = request.clone();
        forged["token"] = json!(
            "tnk1.0190d1c2000070008000000000000001.QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"
        );
        send(&router, "POST", "/nodes/enrol", Some(forged))
            .await
            .assert_problem(401, "cluster.enrolment.invalid_token");
        send(
            &router,
            "POST",
            "/nodes/enrol",
            Some(json!({ "token": "x" })),
        )
        .await
        .assert_problem(400, "sys.invalid_request");
        let mut bad_csr = request.clone();
        bad_csr["token"] = json!(token(&router).await);
        bad_csr["csr"] = json!("not a request");
        send(&router, "POST", "/nodes/enrol", Some(bad_csr))
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

    #[tokio::test]
    async fn permissions_are_checked() {
        let denied = router(Some(Arc::new(Deny(Action::Create))), true).await;
        send(&denied, "POST", "/nodes/enrolments", Some(json!({})))
            .await
            .assert_problem(403, "auth.forbidden");
        send(&denied, "GET", "/nodes/enrolments", None)
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
            ("GET", "/nodes/enrolments"),
            (
                "DELETE",
                "/nodes/enrolments/0190d1c2-0000-7000-8000-000000000001",
            ),
        ] {
            send(&stub, method, path, None)
                .await
                .assert_problem(501, "sys.not_implemented");
        }
        send(&stub, "POST", "/nodes/enrolments", Some(json!({})))
            .await
            .assert_problem(501, "sys.not_implemented");
        send(
            &stub,
            "POST",
            "/nodes/enrol",
            Some(json!({ "token": "x", "csr": "y" })),
        )
        .await
        .assert_problem(501, "sys.not_implemented");
    }
}
