//! `GET /nodes/{id}/dns`, `POST /nodes/{id}/dns/cache/flush`, `GET /nodes/{id}/dns/log`:
//! the `dns` role of a node (`docs/dns.md` section 8).
//!
//! In Phase 2 the role runs in the controller's own process (plan section 2.10), so the
//! routes answer for that one node: the status is the role's report `dns.status`, and the
//! cache flush and the log read are node commands (`dns.cache.flush`, `dns.log.read`) that
//! the role executes in place. Each command is recorded as a row of `cluster.node_commands`
//! in the state it reached, through an inline job, so that Phase 5 adds the remote path
//! (the command stream to a `dns` node) without changing the routes. Any other node, and
//! this node without the role, answers 409 `dns.node.not_dns`.

use std::sync::{Arc, OnceLock};

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
    Action, CodedError, NodeId, ObjectKind, ObjectRef, RequestCtx,
    audit::AuditDraft,
    codec::to_cbor,
    dns::{audit, codes as dns_codes},
};
use tenko_dns::{
    querylog::LogLine,
    status::{self, CommandResult, DnsNode, DnsStatus, LogReadArgs, Outcome, Output},
};
use tenko_store::WriteBatch;

use super::{
    DnsCommandAccepted, DnsNodeStatus, ListenerItem, QueryLogLine, QueryLogParams, UdpWorkerItem,
    Zones, parse_node,
};
use crate::{
    dto::Page,
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The `dns` role of this process, filled in by `tenko serve` once the role has started
/// (the API starts first); empty on a node without the role.
#[derive(Clone, Default)]
pub struct DnsNodeSlot(Arc<OnceLock<Arc<dyn DnsNode>>>);

impl std::fmt::Debug for DnsNodeSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DnsNodeSlot")
            .field(&self.0.get().map(|node| node.node()))
            .finish()
    }
}

impl DnsNodeSlot {
    /// Sets the role once; a second call changes nothing.
    pub fn set(&self, node: Arc<dyn DnsNode>) {
        let _ = self.0.set(node);
    }

    /// The role, once it runs.
    pub fn get(&self) -> Option<&Arc<dyn DnsNode>> {
        self.0.get()
    }

    /// The report of the role, once it runs.
    pub fn status(&self) -> Option<DnsStatus> {
        self.get().map(|node| node.status())
    }
}

type Slot = Option<Extension<DnsNodeSlot>>;
type Registry = Option<Extension<Arc<NodeRegistry>>>;

/// The role of `node` when this process runs it; else 409 `dns.node.not_dns` for a node
/// that exists and 404 `cluster.node.not_found` for one that does not.
async fn local_role(
    app: &AppState,
    slot: Slot,
    registry: Registry,
    node: NodeId,
) -> Result<Arc<dyn DnsNode>, ApiError> {
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
        return Err(ApiError::from_coded_error(
            CodedError::new(
                dns_codes::NODE_NOT_DNS,
                409,
                format!("node {node} does not run the dns role"),
            )
            .with_title("Not a DNS node")
            .with_param("node", node.to_string()),
        ));
    }
    Err(
        ApiError::new("cluster.node.not_found", 404, format!("no node {node}"))
            .with_param("node", node.to_string()),
    )
}

/// Executes a command on the role off the async threads.
async fn execute(role: Arc<dyn DnsNode>, kind: &'static str, args: Vec<u8>) -> CommandResult {
    tokio::task::spawn_blocking(move || role.execute(kind, &args))
        .await
        .unwrap_or_else(|join| CommandResult {
            outcome: Outcome::Failed,
            detail: format!("the command stopped: {join}"),
            output: Output::None,
        })
}

/// Records a command executed in place as a row of `cluster.node_commands` in its final
/// state, with `audit` in the same write, through an inline job.
async fn record(
    zones: Zones,
    cx: &RequestCtx,
    node: NodeId,
    kind: &str,
    args: Vec<u8>,
    result: &CommandResult,
    audit: Option<AuditDraft>,
) -> Result<CommandRecord, ApiError> {
    let service = zones.get()?;
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
    status::commit_command(
        service.jobs().as_ref(),
        cx,
        format!("{kind} on node {node}, executed in place"),
        vec![ObjectRef::node(node)],
        batch,
    )
    .await?;
    Ok(record)
}

fn command_failed(kind: &str, result: &CommandResult) -> ApiError {
    let (code, status) = match result.outcome {
        Outcome::Rejected => (dns_codes::NODE_NOT_DNS, 409),
        _ => ("node.command.failed", 500),
    };
    ApiError::new(code, status, format!("{kind}: {}", result.detail))
}

fn status_dto(status: DnsStatus) -> DnsNodeStatus {
    let count = |value: usize| u32::try_from(value).unwrap_or(u32::MAX);
    let layout = status.layout;
    DnsNodeStatus {
        socket_mode: layout
            .as_ref()
            .map(|layout| layout.mode.as_str().to_owned()),
        udp_workers: layout
            .as_ref()
            .map(|layout| {
                layout
                    .udp
                    .iter()
                    .map(|worker| UdpWorkerItem {
                        index: count(worker.index),
                        listen: worker.listen.to_string(),
                        socket: count(worker.socket),
                        received: worker.received,
                        sent: worker.sent,
                        dropped: worker.dropped,
                        forwarded: worker.forwarded,
                        recv_errors: worker.recv_errors,
                        send_errors: worker.send_errors,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        tcp_open: layout.as_ref().map_or(0, |layout| {
            u64::try_from(layout.tcp_open).unwrap_or(u64::MAX)
        }),
        tcp_refused: layout.as_ref().map_or(0, |layout| layout.tcp_refused),
        node: status.node,
        serving: status.serving,
        revision: status.revision,
        lag: status.lag,
        zones: status.zones,
        rrsets: status.rrsets,
        index_bytes: status.index_bytes,
        listeners: status
            .listeners
            .into_iter()
            .map(|listener| ListenerItem {
                address: listener.address.to_string(),
                transport: listener.transport,
                workers: listener.workers,
            })
            .collect(),
        cache_entries: status.cache_entries,
        started: Some(status.started),
    }
}

fn line_dto(line: LogLine) -> QueryLogLine {
    QueryLogLine {
        at: line.at,
        client: line.client,
        transport: line.transport,
        qname: line.qname,
        rtype: line.rtype,
        rcode: line.rcode,
        view: line.view,
        blocked: line.blocked,
        cached: line.cached,
        duration_micros: line.duration_micros,
    }
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dns",
    tag = "dns",
    operation_id = "get_node_dns_status",
    summary = "Get the DNS role of a node",
    description = "Scope: `dns.read`. The report `dns.status` of the node's DNS role: whether \
                   it answers, the store revision its index holds and how far it is behind, \
                   the zones and RRsets it serves, its listeners and the cache. In Phase 2 \
                   the role runs in the controller's process, so only that node answers.",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 200, description = "The state of the node's DNS role", body = DnsNodeStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role (`dns.node.not_dns`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_node_dns_status(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    let role = local_role(&app, slot, registry, node).await?;
    Ok(Json(status_dto(role.status())).into_response())
}

#[utoipa::path(
    post,
    path = "/nodes/{id}/dns/cache/flush",
    tag = "dns",
    operation_id = "flush_node_dns_cache",
    summary = "Flush a node's DNS cache",
    description = "Scope: `dns.write`. Issues the node command `dns.cache.flush`. The plain \
                   forwarder of Phase 2 keeps no cache, so the command is done at once with a \
                   detail that says so; it is recorded in the node's commands and audited.",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 202, description = "The command is recorded", body = DnsCommandAccepted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role (`dns.node.not_dns`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn flush_node_dns_cache(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    zones: Zones,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Execute, &anywhere(ObjectKind::Zone))?;
    let role = local_role(&app, slot, registry, node).await?;
    let result = execute(role, status::CACHE_FLUSH, Vec::new()).await;
    let draft = AuditDraft::success(audit::CACHE_FLUSH, vec![ObjectRef::node(node)])
        .with_context("detail", result.detail.clone());
    let record = record(
        zones,
        &cx,
        node,
        status::CACHE_FLUSH,
        Vec::new(),
        &result,
        Some(draft),
    )
    .await?;
    if result.outcome != Outcome::Done {
        return Err(command_failed(status::CACHE_FLUSH, &result));
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(DnsCommandAccepted {
            command_id: record.id,
        }),
    )
        .into_response())
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dns/log",
    tag = "dns",
    operation_id = "read_node_dns_log",
    summary = "Read a node's DNS query log",
    description = "Scope: `dns.read`. Issues the node command `dns.log.read`: a page of the \
                   node's query log, newest first, with the cursor of the next page. The read \
                   is recorded in the node's commands. 409 when the node's query log is off.",
    params(("id" = u64, Path, description = "Node id"), QueryLogParams),
    responses(
        (status = 200, description = "A page of log lines, newest first", body = Page<QueryLogLine>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role or its log is off (`dns.node.not_dns`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn read_node_dns_log(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    zones: Zones,
    Path(id): Path<String>,
    Query(params): Query<QueryLogParams>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    let limit = params.limit.unwrap_or(100);
    if !(1..=status::MAX_LOG_PAGE).contains(&limit) {
        return Err(ApiError::from_coded_error(
            CodedError::new(
                tenko_core::error::codes::INVALID_VALUE,
                400,
                "limit must be between 1 and 1000",
            )
            .with_param("field", "limit"),
        ));
    }
    let role = local_role(&app, slot, registry, node).await?;
    let args = to_cbor(&LogReadArgs {
        cursor: params.cursor,
        limit,
        qname: params.qname,
    })?
    .to_vec();
    let result = execute(role, status::LOG_READ, args.clone()).await;
    record(zones, &cx, node, status::LOG_READ, args, &result, None).await?;
    let Output::Log(page) = result.output else {
        return Err(command_failed(status::LOG_READ, &result));
    };
    let revision = app.store.status().revision;
    Ok(Json(Page::new(
        page.lines.into_iter().map(line_dto).collect(),
        page.next,
        revision,
    ))
    .into_response())
}
