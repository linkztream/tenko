//! `GET /nodes/{id}/dns`, `POST /nodes/{id}/dns/cache/flush`, `GET /nodes/{id}/dns/log`,
//! `POST /nodes/{id}/dns/log/stop` and `/start`: the `dns` role of a node (`docs/dns.md`
//! section 8, `docs/dns-querylog.md`).
//!
//! In Phase 2 the role runs in the controller's own process (plan section 2.10), so the
//! routes answer for that one node: the status is the role's report `dns.status`, and the
//! cache flush and the log read are node commands (`dns.cache.flush`, `dns.log.read`) that
//! the role executes in place. Each command is recorded as a row of `cluster.node_commands`
//! in the state it reached, through an inline job, so that Phase 5 adds the remote path
//! (the command stream to a `dns` node) without changing the routes. Any other node, and
//! this node without the role, answers 409 `dns.node.not_dns`.
//!
//! The query log holds personal data (P2-Q7, TGL-15). Every page read through the API is
//! audited as `dns.log.read` with the principal, the cursor range and the filters, in the
//! same write as the command row. A client address leaves the node only for a principal
//! that may update the node: for any other principal the lines that carry an address (a
//! log with `pseudonymise = false`) come without a client, and a filter by address is
//! refused with 403; pseudonyms are shown to every reader of the log.

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
    Action, CodedError, NodeId, ObjectKind, ObjectRef, RequestCtx, Timestamp,
    audit::{AuditAction, AuditDraft},
    codec::to_cbor,
    dns::{audit, codes as dns_codes},
};
use tenko_dns::{
    querylog::{LogFigures, LogLine, keys::is_pseudonym},
    status::{
        self, CacheFlushArgs, CommandResult, DnsNode, DnsStatus, LogReadArgs, Outcome, Output,
    },
};
use tenko_store::WriteBatch;

use super::{
    CacheFlushParams, DnsCommandAccepted, DnsNodeStatus, ListenerItem, QueryLogLine,
    QueryLogParams, QueryLogState, QueryLogStatus, UdpWorkerItem, Zones, parse_node,
};
use crate::{
    dto::Page,
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// A page of a node's query log was read (personal data, P2-Q7). Belongs in
/// `tenko_core::dns::audit` with the other actions of the module.
pub const LOG_READ_AUDIT: AuditAction = AuditAction::from_static("dns.log.read");
/// A node's query log was stopped (the kill switch).
pub const LOG_STOP_AUDIT: AuditAction = AuditAction::from_static("dns.log.stop");
/// A node's query log was started again.
pub const LOG_START_AUDIT: AuditAction = AuditAction::from_static("dns.log.start");

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

/// The share of lookups that hit, when there were any.
#[allow(clippy::cast_precision_loss, reason = "a ratio for people")]
fn hit_ratio(hits: u64, misses: u64) -> Option<f64> {
    let lookups = hits.saturating_add(misses);
    (lookups > 0).then(|| hits as f64 / lookups as f64)
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
        cache_bytes: status.cache_bytes,
        cache_hits: status.cache_hits,
        cache_misses: status.cache_misses,
        cache_hit_ratio: hit_ratio(status.cache_hits, status.cache_misses),
        cache_stale: status.cache_stale,
        problems: status.problems,
        started: Some(status.started),
        query_log: status.log.map(log_status_dto),
    }
}

fn log_status_dto(log: LogFigures) -> QueryLogStatus {
    QueryLogStatus {
        state: if log.stopped {
            QueryLogState::Stopped
        } else {
            QueryLogState::On
        },
        format: log.format.as_str().to_owned(),
        client: log.client.as_str().to_owned(),
        sample: log.sample,
        days: log.days,
        size_mb: log.size_mb,
        written: log.written,
        dropped: log.dropped,
        write_errors: log.write_errors,
    }
}

/// The DTO of a line; an address is kept only when `addresses` (the principal may update
/// the node).
fn line_dto(line: LogLine, addresses: bool) -> QueryLogLine {
    QueryLogLine {
        at: line.at,
        client: line
            .client
            .filter(|client| addresses || is_pseudonym(client)),
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
    description = "Scope: `dns.write`. Issues the node command `dns.cache.flush`: the node's \
                   cache is emptied, or only the names at or below `suffix`; the detail says \
                   how many entries went. The command is recorded in the node's commands and \
                   audited.",
    params(("id" = u64, Path, description = "Node id"), CacheFlushParams),
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
    Query(params): Query<CacheFlushParams>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Execute, &anywhere(ObjectKind::Zone))?;
    if let Some(suffix) = &params.suffix
        && tenko_core::dns::DnsName::new(suffix).is_err()
    {
        return Err(ApiError::new(
            "sys.invalid_value",
            400,
            format!("suffix: `{suffix}` is not a DNS name"),
        )
        .with_param("field", "suffix"));
    }
    let role = local_role(&app, slot, registry, node).await?;
    let args = if params.suffix.is_some() {
        to_cbor(&CacheFlushArgs {
            suffix: params.suffix,
        })?
        .to_vec()
    } else {
        Vec::new()
    };
    let result = execute(role, status::CACHE_FLUSH, args.clone()).await;
    let draft = AuditDraft::success(audit::CACHE_FLUSH, vec![ObjectRef::node(node)])
        .with_context("detail", result.detail.clone());
    let record = record(
        zones,
        &cx,
        node,
        status::CACHE_FLUSH,
        args,
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

fn invalid(field: &str, detail: impl Into<String>) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(tenko_core::error::codes::INVALID_VALUE, 400, detail.into())
            .with_param("field", field.to_owned()),
    )
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dns/log",
    tag = "dns",
    operation_id = "read_node_dns_log",
    summary = "Read a node's DNS query log",
    description = "Scope: `dns.read`. Issues the node command `dns.log.read`: a page of the \
                   node's query log, newest first, with the cursor of the next page, filtered \
                   by name (the name and the names under it), client (a pseudonym, or an \
                   address, which needs the right to update the node), RCODE and time. A read \
                   looks at 64 MiB of log files at most, so a narrow filter may answer a short \
                   page with a cursor to go on from. The read is recorded in the node's \
                   commands and audited as `dns.log.read` with the cursor range and the \
                   filters. Addresses are returned only to principals that may update the \
                   node. 409 when the node's query log is off.",
    params(("id" = u64, Path, description = "Node id"), QueryLogParams),
    responses(
        (status = 200, description = "A page of log lines, newest first", body = Page<QueryLogLine>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`, or filters by address without the right to update the node", body = ProblemDetails, content_type = "application/problem+json"),
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
        return Err(invalid("limit", "limit must be between 1 and 1000"));
    }
    if params.rcode.is_some_and(|rcode| rcode > 4_095) {
        return Err(invalid("rcode", "rcode must be between 0 and 4095"));
    }
    let args = LogReadArgs {
        cursor: params.cursor,
        limit,
        qname: params.qname.filter(|name| !name.trim().is_empty()),
        client: params.client.filter(|client| !client.trim().is_empty()),
        rcode: params.rcode,
        from: params.from,
        until: params.until,
    };
    let filter = args.filter();
    if let Err(error) = filter.validate() {
        let detail = error.to_string();
        let field = if detail.contains("client") {
            "client"
        } else {
            "until"
        };
        return Err(invalid(field, detail));
    }
    let addresses = app
        .authorize(&cx.principal, Action::Update, &ObjectRef::node(node))
        .is_ok();
    if filter.names_an_address() && !addresses {
        app.authorize(&cx.principal, Action::Update, &ObjectRef::node(node))?;
    }
    let role = local_role(&app, slot, registry, node).await?;
    let encoded = to_cbor(&args)?.to_vec();
    let result = execute(role, status::LOG_READ, encoded.clone()).await;
    let audit = match &result.output {
        Output::Log(page) => Some(log_read_audit(
            node,
            &args,
            page.lines.len(),
            page.next.as_deref(),
        )),
        _ => None,
    };
    record(zones, &cx, node, status::LOG_READ, encoded, &result, audit).await?;
    let Output::Log(page) = result.output else {
        return Err(command_failed(status::LOG_READ, &result));
    };
    let revision = app.store.status().revision;
    Ok(Json(Page::new(
        page.lines
            .into_iter()
            .map(|line| line_dto(line, addresses))
            .collect(),
        page.next,
        revision,
    ))
    .into_response())
}

/// The audit record of a page read: the cursor range, the lines and the filters.
fn log_read_audit(
    node: NodeId,
    args: &LogReadArgs,
    lines: usize,
    next: Option<&str>,
) -> AuditDraft {
    let mut draft = AuditDraft::success(LOG_READ_AUDIT, vec![ObjectRef::node(node)])
        .with_context("from_cursor", args.cursor.as_deref().unwrap_or("newest"))
        .with_context("to_cursor", next.unwrap_or("end"))
        .with_context("lines", lines.to_string());
    let filters = [
        ("qname", args.qname.clone()),
        ("client", args.client.clone()),
        ("rcode", args.rcode.map(|rcode| rcode.to_string())),
        ("from", args.from.map(Timestamp::to_rfc3339)),
        ("until", args.until.map(Timestamp::to_rfc3339)),
    ];
    for (key, value) in filters {
        if let Some(value) = value {
            draft = draft.with_context(format!("filter.{key}"), value);
        }
    }
    draft
}

/// Runs `dns.log.stop` or `dns.log.start` and records it with its audit record.
async fn switch_log(
    app: &AppState,
    cx: &RequestCtx,
    slot: Slot,
    registry: Registry,
    zones: Zones,
    id: &str,
    stop: bool,
) -> Result<Response, ApiError> {
    let node = parse_node(id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Execute, &anywhere(ObjectKind::Zone))?;
    let role = local_role(app, slot, registry, node).await?;
    let (kind, action) = if stop {
        (status::LOG_STOP, LOG_STOP_AUDIT)
    } else {
        (status::LOG_START, LOG_START_AUDIT)
    };
    let result = execute(role, kind, Vec::new()).await;
    let audit = (result.outcome == Outcome::Done).then(|| {
        AuditDraft::success(action, vec![ObjectRef::node(node)])
            .with_context("detail", result.detail.clone())
    });
    let record = record(zones, cx, node, kind, Vec::new(), &result, audit).await?;
    if result.outcome != Outcome::Done {
        return Err(command_failed(kind, &result));
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
    post,
    path = "/nodes/{id}/dns/log/stop",
    tag = "dns",
    operation_id = "stop_node_dns_log",
    summary = "Stop a node's DNS query log",
    description = "Scope: `dns.write`. Issues the node command `dns.log.stop`, the kill \
                   switch: the node logs no query until the log is started again, also after a \
                   restart. The files already written stay until their retention removes \
                   them. Recorded in the node's commands and audited as `dns.log.stop`. 409 \
                   when the node's query log is off in its settings.",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 202, description = "The command is recorded", body = DnsCommandAccepted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role or its log is off (`dns.node.not_dns`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn stop_node_dns_log(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    zones: Zones,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    switch_log(&app, &cx, slot, registry, zones, &id, true).await
}

#[utoipa::path(
    post,
    path = "/nodes/{id}/dns/log/start",
    tag = "dns",
    operation_id = "start_node_dns_log",
    summary = "Start a node's DNS query log again",
    description = "Scope: `dns.write`. Issues the node command `dns.log.start`: the node logs \
                   queries again after `dns.log.stop`. Recorded in the node's commands and \
                   audited as `dns.log.start`. 409 when the node's query log is off in its \
                   settings.",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 202, description = "The command is recorded", body = DnsCommandAccepted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role or its log is off (`dns.node.not_dns`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn start_node_dns_log(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    zones: Zones,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    switch_log(&app, &cx, slot, registry, zones, &id, false).await
}
