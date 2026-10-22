//! `GET /dns/blocking/stats`, `POST|DELETE /dns/blocking/pause`, `POST /dns/blocking/allow`:
//! the blocking view (`docs/dns.md`, "Blocking view"), for the home case and every profile.
//!
//! The routes act on the DNS role of the node that answers (in Phase 2 the controller's own
//! process), through the node commands the query log page uses: the figures are counted
//! from the node's query log by `dns.blocking.stats`, and the pause is
//! `dns.blocking.pause` and `dns.blocking.resume`. Each command is recorded as a row of
//! `cluster.node_commands` with its audit record in the same write. Allow from the log adds
//! a name to an uploaded allow list and starts the compile of its next version.
//!
//! The figures name the clients and the names they asked, personal data like the log
//! (P2-Q7): the read is audited as `dns.blocking.stats`, and a client address leaves the
//! node only for a principal that may update the node (pseudonyms are shown to every
//! reader). With an address shown, the DNS name IPAM records for it comes along for a
//! principal that may read addresses.

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use axum::{
    Extension, Json,
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, CodedError, NodeId, ObjectKind, ObjectRef, Timestamp,
    audit::AuditDraft,
    codec::to_cbor,
    dns::{BlockListId, audit, codes as dns_codes},
};
use tenko_dns::{
    lists::ListStaging,
    querylog::{
        keys::is_pseudonym,
        stats::{BlockingStats as Figures, MAX_TOP, StatsArgs},
    },
    status::{self, BlockingPauseArgs, DnsNode, Outcome, Output},
    zone::ZoneService,
};
use tenko_store::{KeyRange, ReadViewExt};

use super::{
    BlockingAllowRequest, BlockingAllowed, BlockingClientCount, BlockingHour, BlockingListCount,
    BlockingNameCount, BlockingPauseRequest, BlockingPauseState, BlockingStats,
    BlockingStatsParams, BlockingWindow, Zones,
    nodes::{Registry, Slot, command_failed, execute, line_dto, local_role, pause_dto, record},
};
use crate::{
    API_BASE,
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    routes::auth::ApiJson,
    state::AppState,
};

/// The IPAM addresses one read looks at for the names of the top clients, at most.
const MAX_ADDRESS_SCAN: usize = 200_000;

/// The DNS role of the node that answers: 409 `dns.node.not_dns` without one.
async fn this_role(
    app: &AppState,
    slot: Slot,
    registry: Registry,
) -> Result<Arc<dyn DnsNode>, ApiError> {
    let node = slot
        .as_ref()
        .and_then(|Extension(slot)| slot.get().map(|role| role.node()))
        .or(app.platform.node.id)
        .unwrap_or(NodeId(0));
    if node == NodeId(0) {
        return Err(ApiError::from_coded_error(
            CodedError::new(
                dns_codes::NODE_NOT_DNS,
                409,
                "this server does not run the dns role",
            )
            .with_title("Not a DNS node")
            .with_param("node", "0"),
        ));
    }
    local_role(app, slot, registry, node).await
}

fn invalid(field: &str, detail: impl Into<String>) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(tenko_core::error::codes::INVALID_VALUE, 400, detail.into())
            .with_param("field", field.to_owned()),
    )
}

fn log_off(node: NodeId) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(
            dns_codes::BLOCKING_LOG_OFF,
            409,
            format!(
                "the query log of node {node} is off: the blocking view counts from it \
                 (`[dns.log] enabled = true`)"
            ),
        )
        .with_title("Query log off")
        .with_param("node", node.to_string()),
    )
}

/// The DNS names IPAM records for `addresses`.
async fn ipam_names(
    service: &ZoneService,
    addresses: &[IpAddr],
) -> Result<HashMap<IpAddr, String>, ApiError> {
    if addresses.is_empty() {
        return Ok(HashMap::new());
    }
    let view = service.view(None).await?;
    let rows = view
        .scan_typed(
            &tenko_ipam::tables::ADDRESSES,
            KeyRange::all(),
            MAX_ADDRESS_SCAN,
            false,
        )
        .map_err(ApiError::from)?;
    Ok(rows
        .into_iter()
        .filter(|(_, address, _)| addresses.contains(&address.ip))
        .filter_map(|(_, address, _)| {
            address
                .dns_name
                .map(|name| (address.ip, name.as_str().trim_end_matches('.').to_owned()))
        })
        .collect())
}

#[utoipa::path(
    get,
    path = "/dns/blocking/stats",
    tag = "dns",
    operation_id = "get_dns_blocking_stats",
    summary = "Get the figures of the blocking view",
    description = "Scope: `dns.read`. Issues the node command `dns.blocking.stats` on the node \
                   that answers: the queries of the last 24 hours or 7 days counted from its \
                   query log, in total, blocked by a block list and from the cache, per hour, \
                   per block list, the names blocked and asked most often, the clients that \
                   asked most often and the newest blocked queries, with the pause of the \
                   block lists. A client is shown as the log keeps it; an address only to a \
                   principal that may update the node, with the DNS name IPAM records for it. \
                   Recorded in the node's commands and audited as `dns.blocking.stats`. 409 \
                   `dns.blocking.log_off` while the node's query log is off.",
    params(BlockingStatsParams),
    responses(
        (status = 200, description = "The figures of the window", body = BlockingStats),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The server does not run the dns role (`dns.node.not_dns`), or its query log is off (`dns.blocking.log_off`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dns_blocking_stats(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    zones: Zones,
    Query(params): Query<BlockingStatsParams>,
) -> Result<Response, ApiError> {
    let top = params.top.unwrap_or(10);
    if !(1..=MAX_TOP).contains(&top) {
        return Err(invalid("top", "top must be between 1 and 100"));
    }
    let role = this_role(&app, slot, registry).await?;
    let node = role.node();
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    let service = zones.get()?;
    let Some(log) = role.status().log else {
        return Err(log_off(node));
    };
    let window = params.window.unwrap_or_default();
    let hours: i64 = match window {
        BlockingWindow::Day => 24,
        BlockingWindow::Week => 24 * 7,
    };
    let until = cx.now;
    let from =
        Timestamp::from_unix_nanos(until.unix_nanos() - i128::from(hours) * 3_600_000_000_000)
            .unwrap_or(until);
    let args = StatsArgs {
        from,
        until,
        bucket_secs: 3_600,
        top,
    };
    let encoded = to_cbor(&args)?.to_vec();
    let result = execute(Arc::clone(&role), status::BLOCKING_STATS, encoded.clone()).await;
    let audit = match &result.output {
        Output::Blocking(stats) => Some(
            AuditDraft::success(audit::BLOCKING_STATS, vec![ObjectRef::node(node)])
                .with_context(
                    "window",
                    match window {
                        BlockingWindow::Day => "24h",
                        BlockingWindow::Week => "7d",
                    },
                )
                .with_context("queries", stats.queries.to_string()),
        ),
        _ => None,
    };
    record(
        Zones(Some(Arc::clone(&service))),
        &cx,
        node,
        status::BLOCKING_STATS,
        encoded,
        &result,
        audit,
    )
    .await?;
    let Output::Blocking(stats) = result.output else {
        if result.outcome == Outcome::Rejected && result.detail.contains("query log is off") {
            return Err(log_off(node));
        }
        return Err(command_failed(status::BLOCKING_STATS, &result));
    };
    let lookups = lookups(&app, &cx, &service, node, &stats).await?;
    #[allow(clippy::cast_precision_loss, reason = "a share for people")]
    let blocked_share = (stats.queries > 0).then(|| stats.blocked as f64 / stats.queries as f64);
    let mut body = BlockingStats {
        node,
        window,
        from,
        until,
        log_days: log.days,
        log_client: log.client.as_str().to_owned(),
        log_sample: log.sample,
        queries: stats.queries,
        blocked: stats.blocked,
        cached: stats.cached,
        blocked_share,
        clients: stats.clients,
        hours: Vec::new(),
        lists: Vec::new(),
        top_blocked: Vec::new(),
        top_names: Vec::new(),
        top_clients: Vec::new(),
        recent_blocked: Vec::new(),
        paused: tenko_dns::policy::pause::state().map(pause_dto),
        truncated: stats.truncated,
    };
    fill(&mut body, *stats, &lookups);
    Ok(Json(body).into_response())
}

/// What the figures are shown with: whether addresses are shown, the IPAM names of the
/// top clients' addresses, the names of the lists.
struct Lookups {
    addresses: bool,
    names: HashMap<IpAddr, String>,
    lists: HashMap<BlockListId, String>,
}

async fn lookups(
    app: &AppState,
    cx: &tenko_core::RequestCtx,
    service: &ZoneService,
    node: NodeId,
    stats: &Figures,
) -> Result<Lookups, ApiError> {
    let addresses = app
        .authorize(&cx.principal, Action::Update, &ObjectRef::node(node))
        .is_ok();
    let names = if addresses
        && app
            .authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Address))
            .is_ok()
    {
        let wanted: Vec<IpAddr> = stats
            .top_clients
            .iter()
            .filter_map(|count| count.key.parse().ok())
            .collect();
        ipam_names(service, &wanted).await?
    } else {
        HashMap::new()
    };
    let view = service.view(None).await?;
    let lists = ZoneService::block_lists(view.as_ref())?
        .into_iter()
        .map(|row| (row.list.id, row.list.name))
        .collect();
    Ok(Lookups {
        addresses,
        names,
        lists,
    })
}

/// Fills the lists of `body` from the figures.
fn fill(body: &mut BlockingStats, stats: Figures, lookups: &Lookups) {
    let shown = |client: &str| lookups.addresses || is_pseudonym(client);
    let name_count = |count: tenko_dns::querylog::stats::Count| BlockingNameCount {
        name: count.key,
        queries: count.queries,
        blocked: count.blocked,
    };
    body.hours = stats
        .buckets
        .into_iter()
        .map(|bucket| BlockingHour {
            start: bucket.start,
            queries: bucket.queries,
            blocked: bucket.blocked,
        })
        .collect();
    body.lists = stats
        .lists
        .into_iter()
        .map(|(list, blocked)| BlockingListCount {
            list,
            name: lookups.lists.get(&list).cloned(),
            blocked,
        })
        .collect();
    body.top_blocked = stats.top_blocked.into_iter().map(name_count).collect();
    body.top_names = stats.top_names.into_iter().map(name_count).collect();
    body.top_clients = stats
        .top_clients
        .into_iter()
        .map(|count| {
            let client = shown(&count.key).then_some(count.key);
            BlockingClientCount {
                name: client
                    .as_deref()
                    .and_then(|client| client.parse::<IpAddr>().ok())
                    .and_then(|address| lookups.names.get(&address).cloned()),
                client,
                queries: count.queries,
                blocked: count.blocked,
            }
        })
        .collect();
    body.recent_blocked = stats
        .recent_blocked
        .into_iter()
        .map(|line| line_dto(line, lookups.addresses))
        .collect();
}

/// A pause for some minutes or until resumed, or its end.
#[derive(Debug, Clone, Copy)]
enum Switch {
    Pause(Option<u32>),
    Resume,
}

/// Runs `dns.blocking.pause` or `dns.blocking.resume` and records it with its audit record.
async fn switch_pause(
    app: &AppState,
    cx: &tenko_core::RequestCtx,
    slot: Slot,
    registry: Registry,
    zones: Zones,
    switch: Switch,
) -> Result<Response, ApiError> {
    if let Switch::Pause(Some(minutes)) = switch
        && !(1..=1_440).contains(&minutes)
    {
        return Err(invalid("minutes", "a pause lasts 1 to 1440 minutes"));
    }
    let role = this_role(app, slot, registry).await?;
    let node = role.node();
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Execute, &anywhere(ObjectKind::Zone))?;
    let (kind, args) = match switch {
        Switch::Pause(minutes) => (
            status::BLOCKING_PAUSE,
            to_cbor(&BlockingPauseArgs { minutes })?.to_vec(),
        ),
        Switch::Resume => (status::BLOCKING_RESUME, Vec::new()),
    };
    let result = execute(role, kind, args.clone()).await;
    let audit = (result.outcome == Outcome::Done).then(|| {
        let mut draft = AuditDraft::success(
            match switch {
                Switch::Pause(_) => audit::BLOCKING_PAUSE,
                Switch::Resume => audit::BLOCKING_RESUME,
            },
            vec![ObjectRef::node(node)],
        )
        .with_context("detail", result.detail.clone());
        if let Switch::Pause(minutes) = switch {
            draft = draft.with_context(
                "minutes",
                minutes.map_or_else(|| "until resumed".to_owned(), |minutes| minutes.to_string()),
            );
        }
        draft
    });
    let command = record(zones, cx, node, kind, args, &result, audit).await?;
    let Output::Paused(paused) = result.output else {
        return Err(command_failed(kind, &result));
    };
    Ok(Json(BlockingPauseState {
        node,
        paused: paused.map(pause_dto),
        command_id: command.id,
    })
    .into_response())
}

#[utoipa::path(
    post,
    path = "/dns/blocking/pause",
    tag = "dns",
    operation_id = "pause_dns_blocking",
    summary = "Pause the block lists",
    description = "Scope: `dns.write`. Issues the node command `dns.blocking.pause` on the node \
                   that answers: no block list blocks a name for `minutes` (1 to 1440), or \
                   until the pause is resumed when `minutes` is absent; allow lists, \
                   exemptions and RPZ zones apply as before. A pause in force is replaced; a \
                   restart of the node ends it. Recorded in the node's commands and audited \
                   as `dns.blocking.pause`.",
    request_body(content = BlockingPauseRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "The pause in force", body = BlockingPauseState),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The server does not run the dns role (`dns.node.not_dns`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn pause_dns_blocking(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    zones: Zones,
    ApiJson(body): ApiJson<BlockingPauseRequest>,
) -> Result<Response, ApiError> {
    switch_pause(
        &app,
        &cx,
        slot,
        registry,
        zones,
        Switch::Pause(body.minutes),
    )
    .await
}

#[utoipa::path(
    delete,
    path = "/dns/blocking/pause",
    tag = "dns",
    operation_id = "resume_dns_blocking",
    summary = "End the pause of the block lists",
    description = "Scope: `dns.write`. Issues the node command `dns.blocking.resume` on the \
                   node that answers: the block lists block again. Recorded in the node's \
                   commands and audited as `dns.blocking.resume`.",
    responses(
        (status = 200, description = "No pause is in force", body = BlockingPauseState),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The server does not run the dns role (`dns.node.not_dns`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn resume_dns_blocking(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    zones: Zones,
) -> Result<Response, ApiError> {
    switch_pause(&app, &cx, slot, registry, zones, Switch::Resume).await
}

#[utoipa::path(
    post,
    path = "/dns/blocking/allow",
    tag = "dns",
    operation_id = "allow_dns_name",
    summary = "Allow a blocked name",
    description = "Scope: `dns.write`. Adds `name` (and the names under it) to the uploaded \
                   allow list `list`, or to the allow list `allowed`, created the first time, \
                   and starts the compile job `dns.list.compile` of its next version (202 \
                   with the job). A name the list covers already changes nothing (200, \
                   `already`). Audited as `dns.blocking.allow` with the name and the list.",
    request_body(content = BlockingAllowRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "The list covers the name already", body = BlockingAllowed),
        (status = 202, description = "The compile job; follow it at the `Location`", body = BlockingAllowed),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such list (`dns.list.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The list is not an uploaded allow list (`dns.list.invalid`), or the list jobs do not run on this server (`dns.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn allow_dns_name(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    staging: Option<Extension<Arc<ListStaging>>>,
    ApiJson(body): ApiJson<BlockingAllowRequest>,
) -> Result<Response, ApiError> {
    if body.name.is_root() {
        return Err(invalid("name", "the root cannot be allowed"));
    }
    if let Some(list) = body.list {
        app.authorize(&cx.principal, Action::Update, &ObjectRef::from(list))?;
    } else {
        app.authorize(
            &cx.principal,
            Action::Create,
            &anywhere(ObjectKind::DnsList),
        )?;
        app.authorize(
            &cx.principal,
            Action::Update,
            &anywhere(ObjectKind::DnsList),
        )?;
    }
    let Some(Extension(staging)) = staging else {
        return Err(ApiError::from_coded_error(
            CodedError::new(
                dns_codes::MODULE_DISABLED,
                409,
                "the block list jobs do not run on this server",
            )
            .with_title("DNS module disabled"),
        ));
    };
    let service = zones.get()?;
    let allowed = service
        .allow_name(&cx, &body.name, body.list, &staging)
        .await?;
    let body = BlockingAllowed {
        list: allowed.list,
        list_name: allowed.list_name,
        created: allowed.created,
        already: allowed.already,
        job: allowed.job,
    };
    let Some(job) = allowed.job else {
        return Ok((StatusCode::OK, Json(body)).into_response());
    };
    let mut response = (StatusCode::ACCEPTED, Json(body)).into_response();
    if let Ok(location) = HeaderValue::from_str(&format!("{API_BASE}/jobs/{job}")) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    Ok(response)
}
