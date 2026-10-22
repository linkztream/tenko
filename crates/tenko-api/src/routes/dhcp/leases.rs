//! The leases, the history and the `dhcp` role of a node (WP7.5, `docs/dhcp.md` section
//! 10): `GET /dhcp/leases`, `GET /dhcp/leases/{addr}`, `POST /dhcp/leases/{addr}/release`,
//! `GET /dhcp/history`, `GET /nodes/{id}/dhcp`, `GET /nodes/{id}/dhcp/leases`,
//! `POST /nodes/{id}/dhcp/leases/{addr}/release` and `GET /nodes/{id}/dhcp/history`.
//!
//! In Phase 3 the role runs in the controller's own process (plan section 2.12), so every
//! route answers through that one node: the status is the role's report `dhcp.status`, and
//! the lease list, the release and the history read are node commands
//! (`dhcp.leases.list`, `dhcp.lease.release`, `dhcp.history.read`) that the role executes
//! in place. Each is recorded as a row of `cluster.node_commands` in the state it reached,
//! through an inline job, so that Phase 5 adds the remote path without changing the
//! routes; the `/dhcp/...` routes are the node routes of the one node. A server without
//! the role answers 409 `dhcp.node.not_dhcp`.
//!
//! Leases and their history are personal data (plan section 2.1): every page read is
//! audited as `dhcp.lease.read` with the filters and the count, and every release as
//! `dhcp.lease.release` with the reason, in the same write as the command row. A list
//! shows only the leases of the scopes the caller may read.

use std::{
    net::Ipv4Addr,
    sync::{Arc, OnceLock},
};

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tenko_auth::authz::anywhere;
use tenko_cluster::{
    node_sync::commands::{self, CommandRecord, CommandState},
    registry::NodeRegistry,
};
use tenko_core::{
    Action, CodedError, NodeId, ObjectKind, ObjectRef, Principal, RequestCtx, Timestamp,
    audit::AuditDraft,
    codec::to_cbor,
    dhcp::{audit, codes as dhcp_codes, scope_object},
};
use tenko_dhcp::role::{
    CommandResult, DhcpNode, DhcpStatus, Outcome, Output, commands as role, state_name,
};
use tenko_store::WriteBatch;

use super::{
    Configs, DhcpCommandAccepted, DhcpHistoryFilters, DhcpHistoryItem, DhcpLeaseCount,
    DhcpLeaseFilters, DhcpLeaseItem, DhcpLeaseParams, DhcpLeaseRelease, DhcpListenMode,
    DhcpListenerItem, DhcpNodeStatus, may_read_scope, parse_addr, parse_node,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, decode_cursor, encode_cursor},
    problem::{ApiError, ProblemDetails},
    routes::auth::OptionalJson,
    state::AppState,
};

/// The `dhcp` role of this process, filled in by `tenko serve` once the role has started
/// (the API starts first); empty on a node without the role.
#[derive(Clone, Default)]
pub struct DhcpNodeSlot(Arc<OnceLock<Arc<dyn DhcpNode>>>);

impl std::fmt::Debug for DhcpNodeSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DhcpNodeSlot")
            .field(&self.0.get().map(|node| node.node()))
            .finish()
    }
}

impl DhcpNodeSlot {
    /// Sets the role once; a second call changes nothing.
    pub fn set(&self, node: Arc<dyn DhcpNode>) {
        let _ = self.0.set(node);
    }

    /// The role, once it runs.
    pub fn get(&self) -> Option<&Arc<dyn DhcpNode>> {
        self.0.get()
    }

    /// The report of the role, once it runs.
    pub fn status(&self) -> Option<DhcpStatus> {
        self.get().map(|node| node.status())
    }
}

type Slot = Option<Extension<DhcpNodeSlot>>;
type Registry = Option<Extension<Arc<NodeRegistry>>>;

fn not_dhcp(node: NodeId) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(
            dhcp_codes::NODE_NOT_DHCP,
            409,
            format!("node {node} does not run the dhcp role"),
        )
        .with_title("Not a DHCP node")
        .with_param("node", node.to_string()),
    )
}

/// The role of `node` when this process runs it; else 409 `dhcp.node.not_dhcp` for a node
/// that exists and 404 `cluster.node.not_found` for one that does not.
async fn local_role(
    app: &AppState,
    slot: Slot,
    registry: Registry,
    node: NodeId,
) -> Result<Arc<dyn DhcpNode>, ApiError> {
    if let Some(Extension(slot)) = slot
        && let Some(role) = slot.get()
        && role.node() == node
    {
        return Ok(Arc::clone(role));
    }
    let known = app.platform.node.id == Some(node)
        || match registry {
            Some(Extension(registry)) => registry.get_node(node).await.is_ok(),
            None => false,
        };
    if known {
        return Err(not_dhcp(node));
    }
    Err(
        ApiError::new("cluster.node.not_found", 404, format!("no node {node}"))
            .with_param("node", node.to_string()),
    )
}

/// The role of this process for the `/dhcp/...` routes; 409 `dhcp.node.not_dhcp` without.
fn this_role(app: &AppState, slot: Slot) -> Result<Arc<dyn DhcpNode>, ApiError> {
    slot.and_then(|Extension(slot)| slot.get().cloned())
        .ok_or_else(|| not_dhcp(app.platform.node.id.unwrap_or(NodeId(1))))
}

/// Records a command executed in place as a row of `cluster.node_commands` in its final
/// state, with `audit` in the same write, through an inline job.
async fn record(
    configs: Configs,
    cx: &RequestCtx,
    node: NodeId,
    kind: &str,
    args: Vec<u8>,
    result: &CommandResult,
    audit: Option<AuditDraft>,
) -> Result<CommandRecord, ApiError> {
    let service = configs.get()?;
    let mut record = CommandRecord::new(node, kind, args, cx.now);
    record.issued_by = cx.principal.user();
    record.state = match result.outcome {
        Outcome::Done => CommandState::Done,
        Outcome::Failed => CommandState::Failed,
        Outcome::Rejected => CommandState::Rejected,
    };
    if record.state == CommandState::Done {
        record.progress = 100;
    }
    record.detail = Some(result.detail.chars().take(2_000).collect());
    record.reported_at = Some(cx.now);
    let mut batch = WriteBatch::for_request(cx);
    commands::stage_issue(&mut batch, &record)?;
    if let Some(audit) = audit {
        batch.audit(audit);
    }
    service
        .commit_record(
            cx,
            format!("{kind} on node {node}, executed in place"),
            vec![ObjectRef::node(node)],
            batch,
        )
        .await?;
    Ok(record)
}

/// The problem a command that did not end `done` answers with.
fn command_failed(kind: &str, result: &CommandResult) -> ApiError {
    let (code, status) = match result.code {
        Some(code @ dhcp_codes::LEASE_NOT_FOUND) => (code, 404),
        Some(code @ dhcp_codes::LEASE_STATE) => (code, 409),
        Some(code @ dhcp_codes::STORE_REFUSED) => (code, 503),
        Some(code) if result.outcome == Outcome::Rejected => (code, 400),
        _ => ("node.command.failed", 500),
    };
    ApiError::new(code, status, format!("{kind}: {}", result.detail))
}

/// A command that did not end `done`, as the outcome of its audit record.
struct Refusal<'a>(&'a CommandResult);

impl std::fmt::Display for Refusal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.detail)
    }
}

impl tenko_core::Coded for Refusal<'_> {
    fn code(&self) -> &'static str {
        self.0.code.unwrap_or("node.command.failed")
    }

    fn http_status(&self) -> u16 {
        command_failed("", self.0).status()
    }
}

fn invalid(field: &str, detail: impl Into<String>) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(tenko_core::error::codes::INVALID_VALUE, 400, detail.into())
            .with_param("field", field.to_owned()),
    )
}

fn limit_of(limit: Option<u32>) -> Result<u32, ApiError> {
    match limit {
        None => Ok(role::DEFAULT_PAGE),
        Some(limit) if (1..=role::MAX_PAGE).contains(&limit) => Ok(limit),
        Some(_) => Err(ApiError::invalid_query(
            "limit",
            "must be between 1 and 1000",
        )),
    }
}

fn time_of(field: &str, text: Option<&str>) -> Result<Option<Timestamp>, ApiError> {
    text.filter(|text| !text.trim().is_empty())
        .map(|text| {
            text.trim()
                .parse::<Timestamp>()
                .map_err(|_| invalid(field, format!("{field}: `{text}` is not an RFC 3339 time")))
        })
        .transpose()
}

fn lease_scope() -> CursorScope {
    CursorScope::new("dhcp.leases")
}

fn history_scope() -> CursorScope {
    CursorScope::new("dhcp.history")
}

/// The arguments of `dhcp.leases.list` from the filters.
fn list_args(filters: &DhcpLeaseFilters) -> Result<role::LeaseListArgs, ApiError> {
    Ok(role::LeaseListArgs {
        scope: filters.scope,
        addr: filters
            .addr
            .clone()
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty()),
        mac: filters.mac,
        name: filters
            .name
            .clone()
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty()),
        state: filters.state,
        after: filters
            .cursor
            .as_deref()
            .map(|cursor| decode_cursor(lease_scope(), cursor))
            .transpose()?,
        limit: limit_of(filters.limit)?,
        ..role::LeaseListArgs::default()
    })
}

/// The arguments of `dhcp.history.read` from the filters.
fn history_args(filters: &DhcpHistoryFilters) -> Result<role::HistoryArgs, ApiError> {
    let from = time_of("from", filters.from.as_deref())?;
    let to = time_of("to", filters.to.as_deref())?;
    if let (Some(from), Some(to)) = (from, to)
        && from > to
    {
        return Err(invalid("to", "to must not be before from"));
    }
    Ok(role::HistoryArgs {
        addr: filters
            .addr
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(parse_addr)
            .transpose()?,
        mac: filters.mac,
        scope: filters.scope,
        kind: filters.kind,
        from,
        to,
        before: filters
            .cursor
            .as_deref()
            .map(|cursor| decode_cursor(history_scope(), cursor))
            .transpose()?,
        limit: limit_of(filters.limit)?,
    })
}

/// The audit record of a page of leases or history read.
fn read_audit(
    node: NodeId,
    what: &str,
    count: usize,
    filters: &[(&str, Option<String>)],
) -> AuditDraft {
    let mut draft = AuditDraft::success(audit::LEASE_READ, vec![ObjectRef::node(node)])
        .with_context("read", what)
        .with_context("rows", count.to_string());
    for (key, value) in filters {
        if let Some(value) = value {
            draft = draft.with_context(format!("filter.{key}"), value.clone());
        }
    }
    draft
}

fn lease_filters(args: &role::LeaseListArgs) -> Vec<(&'static str, Option<String>)> {
    vec![
        ("scope", args.scope.map(|scope| scope.to_string())),
        ("addr", args.addr.clone()),
        ("exact", args.exact.map(|addr| addr.to_string())),
        ("mac", args.mac.map(|mac| mac.to_string())),
        ("name", args.name.clone()),
        (
            "state",
            args.state.map(|state| state_name(state).to_owned()),
        ),
    ]
}

fn item(row: role::LeaseRow) -> DhcpLeaseItem {
    DhcpLeaseItem {
        lease: row.lease,
        host: row.host,
        reserved: row.reserved,
        revision: row.revision,
    }
}

/// Lists the leases through the role, records and audits the read, and keeps the leases
/// of the scopes `principal` may read.
async fn list(
    app: &AppState,
    cx: &RequestCtx,
    configs: Configs,
    role: Arc<dyn DhcpNode>,
    args: role::LeaseListArgs,
) -> Result<Page<DhcpLeaseItem>, ApiError> {
    if let Some(scope) = args.scope {
        app.authorize(&cx.principal, Action::Read, &scope_object(scope))?;
    }
    let node = role.node();
    let encoded = to_cbor(&args)?.to_vec();
    let result = role.execute(role::LEASES_LIST, &encoded).await;
    let audit = match &result.output {
        Output::Leases(page) => Some(read_audit(
            node,
            "leases",
            page.items.len(),
            &lease_filters(&args),
        )),
        _ => None,
    };
    record(
        configs,
        cx,
        node,
        role::LEASES_LIST,
        encoded,
        &result,
        audit,
    )
    .await?;
    let Output::Leases(page) = result.output else {
        return Err(command_failed(role::LEASES_LIST, &result));
    };
    let items = visible(app, &cx.principal, page.items);
    Ok(Page::new(
        items,
        page.next.map(|next| encode_cursor(lease_scope(), &next)),
        app.store.status().revision,
    ))
}

fn visible(app: &AppState, principal: &Principal, rows: Vec<role::LeaseRow>) -> Vec<DhcpLeaseItem> {
    rows.into_iter()
        .filter(|row| may_read_scope(app, principal, row.lease.scope))
        .map(item)
        .collect()
}

/// Reads the history through the role, records and audits the read.
async fn history(
    app: &AppState,
    cx: &RequestCtx,
    configs: Configs,
    role: Arc<dyn DhcpNode>,
    args: role::HistoryArgs,
) -> Result<Page<DhcpHistoryItem>, ApiError> {
    if let Some(scope) = args.scope {
        app.authorize(&cx.principal, Action::Read, &scope_object(scope))?;
    }
    let node = role.node();
    let encoded = to_cbor(&args)?.to_vec();
    let result = role.execute(role::HISTORY_READ, &encoded).await;
    let audit = match &result.output {
        Output::History(page) => Some(read_audit(
            node,
            "history",
            page.items.len(),
            &[
                ("addr", args.addr.map(|addr| addr.to_string())),
                ("mac", args.mac.map(|mac| mac.to_string())),
                ("scope", args.scope.map(|scope| scope.to_string())),
                ("from", args.from.map(Timestamp::to_rfc3339)),
                ("to", args.to.map(Timestamp::to_rfc3339)),
            ],
        )),
        _ => None,
    };
    record(
        configs,
        cx,
        node,
        role::HISTORY_READ,
        encoded,
        &result,
        audit,
    )
    .await?;
    let Output::History(page) = result.output else {
        return Err(command_failed(role::HISTORY_READ, &result));
    };
    let items = page
        .items
        .into_iter()
        .filter(|event| may_read_scope(app, &cx.principal, event.scope))
        .map(|event| DhcpHistoryItem { event })
        .collect();
    Ok(Page::new(
        items,
        page.next.map(|next| encode_cursor(history_scope(), &next)),
        app.store.status().revision,
    ))
}

/// Releases a lease through the role, records and audits it.
async fn release(
    cx: &RequestCtx,
    configs: Configs,
    role: Arc<dyn DhcpNode>,
    addr: Ipv4Addr,
    body: DhcpLeaseRelease,
) -> Result<(CommandRecord, role::LeaseRow), ApiError> {
    let node = role.node();
    let reason = body
        .reason
        .map(|reason| reason.trim().chars().take(500).collect::<String>())
        .filter(|reason| !reason.is_empty());
    let args = role::ReleaseArgs {
        vrf: body.vrf,
        addr,
        reason: reason.clone(),
    };
    let encoded = to_cbor(&args)?.to_vec();
    let result = role.execute(role::LEASE_RELEASE, &encoded).await;
    let mut draft = if result.outcome == Outcome::Done {
        AuditDraft::success(audit::LEASE_RELEASE, vec![ObjectRef::node(node)])
    } else {
        AuditDraft::failed(
            audit::LEASE_RELEASE,
            vec![ObjectRef::node(node)],
            &Refusal(&result),
        )
    }
    .with_context("addr", addr.to_string())
    .with_context("detail", result.detail.clone());
    if let Some(reason) = reason {
        draft = draft.with_context("reason", reason);
    }
    let record = record(
        configs,
        cx,
        node,
        role::LEASE_RELEASE,
        encoded,
        &result,
        Some(draft),
    )
    .await?;
    let Output::Lease(row) = result.output else {
        return Err(command_failed(role::LEASE_RELEASE, &result));
    };
    Ok((record, *row))
}

fn status_dto(status: DhcpStatus) -> DhcpNodeStatus {
    let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
    DhcpNodeStatus {
        node: status.node,
        serving: status.serving,
        accepting: status.accepting,
        probe: status.probe,
        listeners: status
            .listeners
            .into_iter()
            .map(|listener| DhcpListenerItem {
                address: std::net::IpAddr::V4(*listener.address.ip()),
                port: listener.address.port(),
                mode: match listener.mode {
                    tenko_dhcp::v4::engine::ListenMode::Relay => DhcpListenMode::Relay,
                    tenko_dhcp::v4::engine::ListenMode::Direct => DhcpListenMode::Direct,
                },
                interface: listener.interface,
                workers: u16::try_from(listener.workers).unwrap_or(u16::MAX),
            })
            .collect(),
        scopes: u32::try_from(status.scopes).unwrap_or(u32::MAX),
        leases: status
            .leases
            .into_iter()
            .map(|(state, leases)| DhcpLeaseCount {
                state,
                count: count(leases),
            })
            .collect(),
        last_commit_ms: status
            .last_commit
            .map(|duration| duration.as_secs_f64() * 1_000.0),
        revision: status.revision,
    }
}

#[utoipa::path(
    get,
    path = "/dhcp/leases",
    tag = "dhcp",
    operation_id = "list_dhcp_leases",
    summary = "List DHCP leases",
    description = "Scope: `dhcp.read`. The leases of the dhcp role's table in address order, \
                   filtered; the node command `dhcp.leases.list` of the one node. Reading \
                   leases is audited (`dhcp.lease.read`).",
    params(DhcpLeaseFilters),
    responses(
        (status = 200, description = "A page of leases by address", body = Page<DhcpLeaseItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "This server does not run the dhcp role (`dhcp.node.not_dhcp`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dhcp_leases(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    configs: Configs,
    Query(filters): Query<DhcpLeaseFilters>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let args = list_args(&filters)?;
    let role = this_role(&app, slot)?;
    Ok(Json(list(&app, &cx, configs, role, args).await?).into_response())
}

#[utoipa::path(
    get,
    path = "/dhcp/leases/{addr}",
    tag = "dhcp",
    operation_id = "get_dhcp_lease",
    summary = "Get the DHCP lease of an address",
    description = "Scope: `dhcp.read`. Audited (`dhcp.lease.read`). Without `vrf`, the lease \
                   of the address in the one VRF that has one.",
    params(("addr" = String, Path, description = "IPv4 address of the lease"), DhcpLeaseParams),
    responses(
        (status = 200, description = "The lease", body = DhcpLeaseItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No lease holds the address (`dhcp.lease.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "This server does not run the dhcp role (`dhcp.node.not_dhcp`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dhcp_lease(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    configs: Configs,
    Path(addr): Path<String>,
    Query(params): Query<DhcpLeaseParams>,
) -> Result<Response, ApiError> {
    let addr = parse_addr(&addr)?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let role = this_role(&app, slot)?;
    let args = role::LeaseListArgs {
        vrf: params.vrf,
        exact: Some(addr),
        limit: 2,
        ..role::LeaseListArgs::default()
    };
    let page = list(&app, &cx, configs, role, args).await?;
    let mut items = page.items.into_iter();
    match (items.next(), items.next()) {
        (Some(item), None) => Ok(Json(item).into_response()),
        (Some(_), Some(_)) => Err(invalid(
            "vrf",
            format!("{addr} has leases in several VRFs; name the VRF"),
        )),
        (None, _) => Err(ApiError::new(
            dhcp_codes::LEASE_NOT_FOUND,
            404,
            format!("no lease holds {addr}"),
        )
        .with_param("addr", addr.to_string())),
    }
}

#[utoipa::path(
    post,
    path = "/dhcp/leases/{addr}/release",
    tag = "dhcp",
    operation_id = "release_dhcp_lease",
    summary = "Release a DHCP lease (the address returns to the pool)",
    description = "Scope: `dhcp.write`. The node command `dhcp.lease.release` of the one \
                   node: the active lease becomes `released` now (history kind \
                   `reclaimed`); the client keeps using the address until it renews and is \
                   refused. Audited (`dhcp.lease.release`).",
    params(("addr" = String, Path, description = "IPv4 address of the lease")),
    request_body(content = DhcpLeaseRelease, content_type = "application/json"),
    responses(
        (status = 200, description = "The released lease", body = DhcpLeaseItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No lease holds the address (`dhcp.lease.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The lease is not active, or changed meanwhile (`dhcp.lease.state`), or this server does not run the dhcp role (`dhcp.node.not_dhcp`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store refused the lease write (`dhcp.store_refused`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn release_dhcp_lease(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    configs: Configs,
    Path(addr): Path<String>,
    OptionalJson(body): OptionalJson<DhcpLeaseRelease>,
) -> Result<Response, ApiError> {
    let addr = parse_addr(&addr)?;
    app.authorize(
        &cx.principal,
        Action::Execute,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let role = this_role(&app, slot)?;
    let (_, row) = release(&cx, configs, role, addr, body).await?;
    Ok(Json(item(row)).into_response())
}

#[utoipa::path(
    get,
    path = "/dhcp/history",
    tag = "dhcp",
    operation_id = "list_dhcp_history",
    summary = "Read the DHCP lease history",
    description = "Scope: `dhcp.read`. The rows of `dhcp.history`, newest first; the node \
                   command `dhcp.history.read` of the one node. Reading the history is \
                   audited (`dhcp.lease.read`).",
    params(DhcpHistoryFilters),
    responses(
        (status = 200, description = "A page of lease events, newest first", body = Page<DhcpHistoryItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "This server does not run the dhcp role (`dhcp.node.not_dhcp`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dhcp_history(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    configs: Configs,
    Query(filters): Query<DhcpHistoryFilters>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let args = history_args(&filters)?;
    let role = this_role(&app, slot)?;
    Ok(Json(history(&app, &cx, configs, role, args).await?).into_response())
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dhcp",
    tag = "dhcp",
    operation_id = "get_node_dhcp_status",
    summary = "Get the DHCP role of a node",
    description = "Scope: `dhcp.read`. The report `dhcp.status` of the node's DHCP role: \
                   whether it answers and the store takes its lease writes, its listeners \
                   and workers, the scopes it serves, its leases by state, the last commit's \
                   time and the revision of its configuration image.",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 200, description = "The report of the DHCP role", body = DhcpNodeStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dhcp role (`dhcp.node.not_dhcp`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_node_dhcp_status(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(node))?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let role = local_role(&app, slot, registry, node).await?;
    Ok(Json(status_dto(role.status())).into_response())
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dhcp/leases",
    tag = "dhcp",
    operation_id = "list_node_dhcp_leases",
    summary = "List the leases a node's DHCP role holds",
    description = "Scope: `dhcp.read`. The node command `dhcp.leases.list`, audited.",
    params(("id" = u64, Path, description = "Node id"), DhcpLeaseFilters),
    responses(
        (status = 200, description = "A page of leases by address", body = Page<DhcpLeaseItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dhcp role (`dhcp.node.not_dhcp`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_node_dhcp_leases(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    configs: Configs,
    Path(id): Path<String>,
    Query(filters): Query<DhcpLeaseFilters>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(node))?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let args = list_args(&filters)?;
    let role = local_role(&app, slot, registry, node).await?;
    Ok(Json(list(&app, &cx, configs, role, args).await?).into_response())
}

#[utoipa::path(
    post,
    path = "/nodes/{id}/dhcp/leases/{addr}/release",
    tag = "dhcp",
    operation_id = "release_node_dhcp_lease",
    summary = "Release a lease on a node's DHCP role",
    description = "Scope: `dhcp.write`. The node command `dhcp.lease.release`, recorded in the \
                   node's commands and audited.",
    params(("id" = u64, Path, description = "Node id"), ("addr" = String, Path, description = "IPv4 address of the lease")),
    request_body(content = DhcpLeaseRelease, content_type = "application/json"),
    responses(
        (status = 202, description = "The command is recorded", body = DhcpCommandAccepted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`), or no lease holds the address (`dhcp.lease.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dhcp role (`dhcp.node.not_dhcp`), or the lease is not active (`dhcp.lease.state`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store refused the lease write (`dhcp.store_refused`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn release_node_dhcp_lease(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    configs: Configs,
    Path((id, addr)): Path<(String, String)>,
    OptionalJson(body): OptionalJson<DhcpLeaseRelease>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    let addr = parse_addr(&addr)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(node))?;
    app.authorize(
        &cx.principal,
        Action::Execute,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let role = local_role(&app, slot, registry, node).await?;
    let (record, _) = release(&cx, configs, role, addr, body).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(DhcpCommandAccepted {
            command_id: record.id,
        }),
    )
        .into_response())
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dhcp/history",
    tag = "dhcp",
    operation_id = "read_node_dhcp_history",
    summary = "Read the lease history through a node's DHCP role",
    description = "Scope: `dhcp.read`. The node command `dhcp.history.read`, audited.",
    params(("id" = u64, Path, description = "Node id"), DhcpHistoryFilters),
    responses(
        (status = 200, description = "A page of lease events, newest first", body = Page<DhcpHistoryItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dhcp role (`dhcp.node.not_dhcp`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn read_node_dhcp_history(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    configs: Configs,
    Path(id): Path<String>,
    Query(filters): Query<DhcpHistoryFilters>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(node))?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let args = history_args(&filters)?;
    let role = local_role(&app, slot, registry, node).await?;
    Ok(Json(history(&app, &cx, configs, role, args).await?).into_response())
}
