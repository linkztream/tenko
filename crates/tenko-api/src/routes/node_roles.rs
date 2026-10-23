//! The roles of a node (OPS-01): which of `controller`, `dns`, `dhcp` and `probe` a node runs
//! from its next start.
//!
//! Area: nodes. Owner: node-roles.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /nodes/{id}/roles` | 200 [`NodeRoles`] with `ETag` (the revision of the stored set, absent while none is stored) | 400, 403, 404 `cluster.node.not_found` |
//! | `PUT /nodes/{id}/roles` | 200 [`NodeRoles`] with `ETag` | 400, 403, 404, 409 `node.roles.pinned`, `node.roles.last_controller`, `node.roles.controller`, 412 `node.roles.revision_mismatch`, 422 `node.roles.empty`, `node.roles.unsupported`, 503 `node.roles.store` |
//!
//! # The stored set
//!
//! Each node has one row of `nodes.roles` ([`NODE_ROLES`]), keyed by its node id. A
//! controller seeds its own row from the `roles` of its `tenko.toml` at its first start;
//! every node receives its row through the configuration stream (docs/node-sync.md). At
//! start the stored set decides over the file's, unless `--roles` on the command line pins
//! the set: then a change is refused with `node.roles.pinned`. A node applies a change by a
//! restart through its service manager, as a module change does; a node without one logs
//! what to do and `GET /system/status` carries `node.roles.restart_required`.
//!
//! What a change may do:
//!
//! - The `controller` role follows the cluster membership: it is never taken from the last
//!   controller (`node.roles.last_controller`), and otherwise neither taken nor given by
//!   this endpoint (`node.roles.controller`): a controller joins with a controller
//!   enrolment token and leaves with `DELETE /cluster/members/{id}`.
//! - A node without the controller role runs the `probe` role and only that role until
//!   Phase 5 (`node.roles.unsupported`), the same rule as `tenko serve` at start.
//!
//! The answer carries findings, which do not refuse the change: `node.roles.privileges`
//! when a role is switched on whose raw methods need a systemd drop-in the node does not
//! have, and `node.roles.dns_resolver` when the `dns` role leaves a node whose host resolver
//! the installer pointed at it (`--use-self`). Only the node itself can tell, so the
//! findings are those of the controller that answers, for its own node.
//!
//! # The service
//!
//! The server adds [`NodeRoleService`] as a request extension; without it every endpoint
//! answers `501` `sys.not_implemented`.
//!
//! # Authorization
//!
//! Reading needs [`Action::Read`] on the node (viewers and operators have it), changing
//! [`Action::Update`] on the node (administrators). A change is audited as `nodes.roles`
//! with the old and the new set.

#![allow(
    clippy::result_large_err,
    reason = "the errors are the CodedError of the API, handed on to problem details as they are"
)]

#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tenko_cluster::{
    model::tables::{MEMBERS, NODES},
    node_sync::roles::{NODE_ROLES, NodeRolesRecord, RolesOrigin},
};
use tenko_core::{
    Action, CodedError, NodeId, ObjectRef, RequestCtx, Revision, Role, RoleSet, Timestamp,
    audit::{AuditAction, AuditDetails, AuditDraft, FieldChange},
    error::codes,
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt as _, Store, StoreError, WriteBatch,
};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    auth::ApiJson,
    common::{if_match, with_etag},
    not_implemented,
};
use crate::{
    dto::system::StatusWarning,
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The audit action of a change.
pub const AUDIT_ACTION: &str = "nodes.roles";

/// The finding of a role whose raw methods need a drop-in the node does not have.
pub const PRIVILEGES: &str = "node.roles.privileges";

/// The finding of the `dns` role leaving a node that is its host's resolver.
pub const DNS_RESOLVER: &str = "node.roles.dns_resolver";

/// The status warning while a change of this node's roles waits for a restart.
pub const RESTART_NOTICE: &str = "node.roles.restart_required";

/// How a node applies its stored set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RoleRestart {
    /// The node runs the stored set (or `--roles` pins it): nothing to do.
    None,
    /// This node restarts itself through its service manager within seconds.
    Scheduled,
    /// This node has no service manager that starts it again: restart it by hand.
    Required,
    /// Another node: it applies the set at its next start and restarts itself when it
    /// receives a change, under a service manager.
    OnNode,
}

/// The roles of a node: the answer of `GET` and `PUT /nodes/{id}/roles`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NodeRoles {
    /// The node id.
    #[schema(value_type = u64)]
    pub node: NodeId,
    /// The roles the node runs from its next start: the stored set, else the roles it has
    /// now.
    #[schema(value_type = Vec<String>)]
    pub configured: Vec<Role>,
    /// The roles the node runs now; known for the node of the controller that answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<String>>)]
    pub running: Option<Vec<Role>>,
    /// Whether a set is stored for the node.
    pub stored: bool,
    /// Where the stored set came from: `seed` (the node's `tenko.toml` at its first start)
    /// or `api`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub origin: Option<RolesOrigin>,
    /// When the stored set was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<Timestamp>,
    /// The revision of the stored set, also the `ETag`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    /// Whether `--roles` on the command line pins the node's roles; the stored set is then
    /// not used and cannot be changed.
    pub pinned: bool,
    /// Whether the node is a controller (a member of the controller cluster).
    pub controller: bool,
    /// How the node applies the stored set.
    pub restart: RoleRestart,
    /// What the node should know about the set, which does not refuse it:
    /// `node.roles.privileges`, `node.roles.dns_resolver`.
    pub findings: Vec<StatusWarning>,
}

/// The body of `PUT /nodes/{id}/roles`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeRolesRequest {
    /// The roles: any of `controller`, `dns`, `dhcp` and `probe`.
    #[schema(value_type = Vec<String>)]
    pub roles: Vec<Role>,
}

/// What the role service needs from the server process it runs in.
pub trait RoleHost: Send + Sync + 'static {
    /// Whether a service manager starts this process again after exit status 12.
    fn supervised(&self) -> bool;

    /// The findings of this node running `configured` instead of `running`.
    fn findings(&self, configured: RoleSet, running: RoleSet) -> BoxFuture<'_, Vec<StatusWarning>>;
}

/// The facts of the node of the controller that serves the requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnNode {
    /// Its node id.
    pub id: NodeId,
    /// The roles it runs now.
    pub running: RoleSet,
    /// Whether `--roles` pins them.
    pub pinned: bool,
}

/// The service behind `/nodes/{id}/roles`: reads and writes `nodes.roles`.
pub struct NodeRoleService {
    store: Arc<dyn Store>,
    own: OwnNode,
    host: Arc<dyn RoleHost>,
}

impl std::fmt::Debug for NodeRoleService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeRoleService")
            .field("own", &self.own)
            .finish_non_exhaustive()
    }
}

/// What the store says a node is.
enum Kind {
    /// The node of this controller.
    Own,
    /// Another controller.
    Controller,
    /// An enrolled data-plane node with the roles of its enrolment.
    Enrolled(RoleSet),
}

impl Kind {
    const fn is_controller(&self) -> bool {
        matches!(self, Kind::Own | Kind::Controller)
    }
}

fn store_error(error: &StoreError) -> CodedError {
    CodedError::new(
        "node.roles.store",
        503,
        format!("the store is unavailable: {error}"),
    )
}

fn names(roles: RoleSet) -> String {
    let text = roles.to_string();
    if text.is_empty() {
        "(none)".to_owned()
    } else {
        text
    }
}

impl NodeRoleService {
    /// The service of a controller whose own node is `own`.
    pub fn new(store: Arc<dyn Store>, own: OwnNode, host: Arc<dyn RoleHost>) -> Self {
        Self { store, own, host }
    }

    async fn view(&self) -> Result<Arc<dyn ReadView>, CodedError> {
        self.store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| store_error(&error))
    }

    fn kind(&self, view: &dyn ReadView, node: NodeId) -> Result<Kind, CodedError> {
        if node == self.own.id {
            return Ok(Kind::Own);
        }
        if view
            .get_typed(&MEMBERS, &node.0)
            .map_err(|error| store_error(&error))?
            .is_some()
        {
            return Ok(Kind::Controller);
        }
        match view
            .get_typed(&NODES, &node.0)
            .map_err(|error| store_error(&error))?
        {
            Some((record, _)) => Ok(Kind::Enrolled(record.role_set())),
            None => Err(CodedError::new(
                "cluster.node.not_found",
                404,
                format!("there is no node {node}"),
            )
            .with_param("id", node.to_string())),
        }
    }

    /// The controllers of the cluster: the members of `cluster.members` and this one.
    fn controllers(&self, view: &dyn ReadView) -> Result<usize, CodedError> {
        let members = view
            .scan_typed(&MEMBERS, KeyRange::all(), usize::MAX, false)
            .map_err(|error| store_error(&error))?;
        let others = members
            .iter()
            .filter(|(_, member, _)| member.node != self.own.id)
            .count();
        Ok(others + 1)
    }

    async fn answer(
        &self,
        node: NodeId,
        kind: &Kind,
        stored: Option<(NodeRolesRecord, Revision)>,
    ) -> NodeRoles {
        let fallback = match kind {
            Kind::Own => self.own.running,
            Kind::Controller => RoleSet::from_iter([Role::Controller]),
            Kind::Enrolled(roles) => *roles,
        };
        let configured = stored
            .as_ref()
            .map_or(fallback, |(record, _)| record.role_set());
        let own = matches!(kind, Kind::Own);
        let (running, restart, findings, pinned) = if own {
            let running = self.own.running;
            let effective = if self.own.pinned { running } else { configured };
            let restart = if effective == running {
                RoleRestart::None
            } else if self.host.supervised() {
                RoleRestart::Scheduled
            } else {
                RoleRestart::Required
            };
            let findings = self.host.findings(configured, running).await;
            (Some(running), restart, findings, self.own.pinned)
        } else {
            (None, RoleRestart::OnNode, Vec::new(), false)
        };
        NodeRoles {
            node,
            configured: configured.roles().collect(),
            running: running.map(|roles| roles.roles().collect()),
            stored: stored.is_some(),
            origin: stored.as_ref().map(|(record, _)| record.origin),
            changed_at: stored.as_ref().map(|(record, _)| record.changed_at),
            revision: stored.as_ref().map(|(_, revision)| revision.0),
            pinned,
            controller: kind.is_controller(),
            restart,
            findings,
        }
    }

    /// The roles of `node`.
    ///
    /// # Errors
    ///
    /// `cluster.node.not_found` (404), `node.roles.store` (503).
    pub async fn get(&self, node: NodeId) -> Result<NodeRoles, CodedError> {
        let view = self.view().await?;
        let kind = self.kind(view.as_ref(), node)?;
        let stored = view
            .get_typed(&NODE_ROLES, &node.0)
            .map_err(|error| store_error(&error))?;
        drop(view);
        Ok(self.answer(node, &kind, stored).await)
    }

    /// Checks `roles` for `node` against the rules of the module documentation.
    fn check(&self, view: &dyn ReadView, kind: &Kind, roles: RoleSet) -> Result<(), CodedError> {
        if roles.is_empty() {
            return Err(CodedError::new(
                "node.roles.empty",
                422,
                "a node runs at least one role",
            ));
        }
        if matches!(kind, Kind::Own) && self.own.pinned {
            return Err(CodedError::new(
                "node.roles.pinned",
                409,
                format!(
                    "--roles {} on the command line of tenko serve decides the roles of this \
                     node; change it there",
                    names(self.own.running)
                ),
            )
            .with_param("pinned", names(self.own.running)));
        }
        let wants_controller = roles.contains(Role::Controller);
        if kind.is_controller() && !wants_controller {
            if self.controllers(view)? <= 1 {
                return Err(CodedError::new(
                    "node.roles.last_controller",
                    409,
                    "this node is the last controller of the cluster; it keeps the controller role",
                ));
            }
            return Err(CodedError::new(
                "node.roles.controller",
                409,
                "the controller role follows the cluster membership: remove the controller with \
                 DELETE /cluster/members/{id} instead",
            ));
        }
        if !kind.is_controller() && wants_controller {
            return Err(CodedError::new(
                "node.roles.controller",
                409,
                "the controller role follows the cluster membership: a controller joins with a \
                 controller enrolment token",
            ));
        }
        if !kind.is_controller() {
            let others: Vec<&str> = roles
                .roles()
                .filter(|role| *role != Role::Probe)
                .map(Role::as_str)
                .collect();
            if !others.is_empty() || !roles.contains(Role::Probe) {
                return Err(CodedError::new(
                    "node.roles.unsupported",
                    422,
                    "a node without the controller role runs the probe role and no other until \
                     Phase 5 (the dns and dhcp roles run in a controller's process)",
                )
                .with_param("roles", names(roles)));
            }
        }
        Ok(())
    }

    /// Stores `roles` for `node` (audited as `nodes.roles`); `expect` is the revision of
    /// `If-Match`.
    ///
    /// # Errors
    ///
    /// The refusals of the module documentation.
    pub async fn put(
        &self,
        ctx: &RequestCtx,
        node: NodeId,
        roles: RoleSet,
        expect: Option<Revision>,
    ) -> Result<NodeRoles, CodedError> {
        let view = self.view().await?;
        let kind = self.kind(view.as_ref(), node)?;
        self.check(view.as_ref(), &kind, roles)?;
        let current = view
            .get_typed(&NODE_ROLES, &node.0)
            .map_err(|error| store_error(&error))?;
        drop(view);
        let revision = current.as_ref().map(|(_, revision)| *revision);
        if let Some(expected) = expect
            && revision != Some(expected)
        {
            return Err(mismatch());
        }
        if current
            .as_ref()
            .is_some_and(|(record, _)| record.role_set() == roles)
        {
            return Ok(self.answer(node, &kind, current).await);
        }
        let before = match (&current, &kind) {
            (Some((record, _)), _) => record.role_set(),
            (None, Kind::Own) => self.own.running,
            (None, Kind::Enrolled(roles)) => *roles,
            (None, Kind::Controller) => RoleSet::from_iter([Role::Controller]),
        };
        let record = NodeRolesRecord::new(roles, RolesOrigin::Api, ctx.now);
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&NODE_ROLES, &node.0, revision);
        batch
            .put_typed(&NODE_ROLES, &node.0, &record)
            .map_err(|error| store_error(&error))?;
        let mut details = AuditDetails::default();
        details.changes.push(FieldChange {
            object: None,
            field: "roles".to_owned(),
            old: Some(names(before)),
            new: Some(names(roles)),
        });
        batch.audit(AuditDraft {
            details,
            source_ip: ctx.source_ip,
            ..AuditDraft::success(
                AuditAction::from_static(AUDIT_ACTION),
                vec![ObjectRef::node(node)],
            )
        });
        let written = self
            .store
            .propose(batch)
            .await
            .map_err(|error| match error {
                StoreError::PreconditionFailed(_) => mismatch(),
                other => store_error(&other),
            })?;
        Ok(self
            .answer(node, &kind, Some((record, written.revision)))
            .await)
    }
}

fn mismatch() -> CodedError {
    CodedError::new(
        "node.roles.revision_mismatch",
        412,
        "the roles of the node changed since they were read; read them again",
    )
}

/// The finding `node.roles.privileges`: `roles` need the systemd drop-ins `dropins`.
pub fn privileges_finding(roles: &[&str], dropins: &[&str]) -> StatusWarning {
    StatusWarning {
        code: PRIVILEGES.to_owned(),
        detail: format!(
            "the role(s) {} need raw sockets (CAP_NET_RAW, AF_PACKET) that this node does not \
             have; install the systemd drop-in(s) {} in /etc/systemd/system/tenko.service.d/ \
             (deploy/install.sh --reconfigure --roles does) and restart the service",
            roles.join(", "),
            dropins.join(", ")
        ),
        params: BTreeMap::from([
            ("roles".to_owned(), roles.join(", ")),
            ("dropins".to_owned(), dropins.join(", ")),
        ]),
    }
}

/// The finding `node.roles.dns_resolver`: the host's resolver, set by the installer in
/// `file`, points at a node that stops running the `dns` role.
pub fn dns_resolver_finding(file: &str) -> StatusWarning {
    StatusWarning {
        code: DNS_RESOLVER.to_owned(),
        detail: format!(
            "the installer pointed this host's resolver at the node (--use-self, recorded in \
             {file}); without the dns role the host resolves no names: run deploy/install.sh \
             --reconfigure without --use-self first, or keep the dns role"
        ),
        params: BTreeMap::from([("file".to_owned(), file.to_owned())]),
    }
}

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_node_roles, put_node_roles))
}

type Service = Option<Extension<Arc<NodeRoleService>>>;

fn service(service: Service, method: &str) -> Result<Arc<NodeRoleService>, ApiError> {
    service
        .map(|Extension(service)| service)
        .ok_or_else(|| not_implemented(method, "/nodes/{id}/roles"))
}

fn parse_node(raw: &str) -> Result<NodeId, ApiError> {
    raw.parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .map(NodeId)
        .ok_or_else(|| {
            ApiError::from_coded_error(
                CodedError::new(
                    codes::INVALID_REQUEST,
                    400,
                    "the node identifier is not a positive number",
                )
                .with_title("Invalid request")
                .with_param("field", "id"),
            )
        })
}

fn roles_answer(roles: NodeRoles) -> Response {
    let revision = roles.revision;
    let response = Json(roles).into_response();
    match revision {
        Some(revision) => with_etag(response, Revision(revision)),
        None => response,
    }
}

/// Shows the roles a node runs from its next start, with the roles it runs now (for the
/// node of the controller that answers), whether `--roles` pins them, how a change applies
/// and the findings of the set.
#[utoipa::path(
    get,
    path = "/nodes/{id}/roles",
    tag = "nodes",
    operation_id = "get_node_roles",
    summary = "Get a node's roles",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 200, description = "The roles, with `ETag` once a set is stored", body = NodeRoles),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to read nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable (`node.roles.store`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_node_roles(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    svc: Service,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let svc = service(svc, "GET")?;
    let id = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(id))?;
    let roles = svc.get(id).await.map_err(ApiError::from_coded_error)?;
    Ok(roles_answer(roles))
}

/// Sets the roles a node runs from its next start. The change is audited as `nodes.roles`;
/// the node applies it by a restart through its service manager (`restart: scheduled` for
/// the node of the controller that answers). Findings in the answer do not refuse the
/// change: a role whose raw methods need a drop-in the node lacks, or the `dns` role leaving
/// the host's own resolver.
#[utoipa::path(
    put,
    path = "/nodes/{id}/roles",
    tag = "nodes",
    operation_id = "put_node_roles",
    summary = "Set a node's roles",
    params(
        ("id" = u64, Path, description = "Node id"),
        ("If-Match" = Option<String>, Header, description = "The revision read, as `\"12\"`; the write fails with 412 `node.roles.revision_mismatch` when the roles changed since")
    ),
    request_body = NodeRolesRequest,
    responses(
        (status = 200, description = "The stored roles, with `ETag`", body = NodeRoles),
        (status = 400, description = "The body is not valid JSON, names an unknown role, or a header is malformed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to change nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "`--roles` pins the roles (`node.roles.pinned`), the last controller keeps its role (`node.roles.last_controller`), or the controller role follows the cluster membership (`node.roles.controller`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The roles changed since they were read (`node.roles.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "No role (`node.roles.empty`), or roles a node without the controller role does not run (`node.roles.unsupported`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable (`node.roles.store`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn put_node_roles(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    svc: Service,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<NodeRolesRequest>,
) -> Result<Response, ApiError> {
    let svc = service(svc, "PUT")?;
    let id = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(id))?;
    let expect = if_match(&headers)?;
    let roles = request.roles.into_iter().collect();
    let answer = svc
        .put(&cx, id, roles, expect)
        .await
        .map_err(ApiError::from_coded_error)?;
    Ok(roles_answer(answer))
}
