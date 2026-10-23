//! The recursive resolver's routes (recursion plan section 3.4): trust anchors, negative
//! trust anchors and, per node, the resolver's status, its priming and its infrastructure
//! cache.
//!
//! Area: dns. Owner: WP10.0 (the contracts); WP10.1 built the node routes (the status, the
//! priming and the infrastructure cache); WP10.2 built the trust anchors and the negative
//! trust anchors (and the service behind them). Requirements: DNS-03, DNS-13, OPS-09.
//!
//! Every operation is declared with its request and answer types so that the OpenAPI
//! document, the typed client of the UI and the mock server have them. The node routes run
//! in the node's `dns` role like the cache routes do (`nodes.rs`): the status is the role's
//! report, the priming and the infrastructure cache are node commands (`dns.recursion.prime`,
//! `dns.infra.list`, `dns.infra.flush`) recorded in the node's commands. The trust anchor
//! operations check the caller's scope (and the interactive session where the table says
//! so, which the authorizer enforces by refusing a token) and then act on the store's rows
//! (`tenko_dns::anchors::rows`). A path segment that does not parse answers 400 before any
//! authorization.
//!
//! | Endpoint | Scope | Purpose |
//! |---|---|---|
//! | `GET /dns/trust-anchors` | `dns.read` | List the trust anchors |
//! | `POST /dns/trust-anchors` | `dns.keys`, interactive | Add a trust anchor for a zone |
//! | `GET /dns/trust-anchors/{zone}` | `dns.read` | Get the trust anchor of a zone |
//! | `DELETE /dns/trust-anchors/{zone}` | `dns.keys`, interactive | Remove the trust anchor of a zone |
//! | `POST /dns/trust-anchors/{zone}/refresh` | `dns.keys` | Run RFC 5011 for a zone now |
//! | `GET /dns/ntas` | `dns.read` | List the negative trust anchors |
//! | `POST /dns/ntas` | `dns.keys`, interactive | Create a negative trust anchor |
//! | `DELETE /dns/ntas/{id}` | `dns.keys`, interactive | Delete a negative trust anchor |
//! | `GET /nodes/{id}/dns/recursion` | `dns.read` | Get the recursive resolver of a node |
//! | `POST /nodes/{id}/dns/recursion/prime` | `dns.write` | Prime a node's resolver now |
//! | `GET /nodes/{id}/dns/infra` | `dns.read` | List what a node's infrastructure cache holds |
//! | `POST /nodes/{id}/dns/infra/flush` | `dns.write` | Flush a node's infrastructure cache |
//!
//! The status of a node whose resolver is off is not an error: it answers 200 with
//! `enabled: false`. The infrastructure cache holds the authority servers of zones and no
//! client data, so listing it is recorded as a node command and not audited; the priming and
//! the flush are audited (`dns.recursion.prime`, `dns.infra.flush`).
//!
//! # Error codes of the built operations
//!
//! | Code | Status | When |
//! |---|---|---|
//! | `dns.trust_anchor.not_found` | 404 | No trust anchor for the zone |
//! | `dns.trust_anchor.invalid` | 400 | A key that does not parse, twice, too many (`field`, `reason`) |
//! | `dns.trust_anchor.root_protected` | 409 | Removing or replacing the root's anchor outside Lab |
//! | `dns.nta.not_found` | 404 | No negative trust anchor of this id |
//! | `dns.nta.invalid` | 400 | The root, no expiry under Hardened, over seven days, no reason (`field`, `reason`) |
//! | `dns.recursion.disabled` | 409 | A node command (priming, listing or flushing the infrastructure cache) while the node's resolver is off |
//! | `sys.invalid_value` | 400 | A `suffix`, `cursor` or `limit` of the infrastructure cache that does not parse (`field`) |
//!
//! The root zone is written `root` in the path of a trust anchor (a URL turns the segment `.`
//! into a dot segment); a zone named `root` is written `root.`.

use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, CodedError, NodeId, ObjectKind, ObjectRef,
    audit::AuditDraft,
    codec::to_cbor,
    dns::{DnsName, NtaId, audit, codes as dns_codes},
    error::codes as error_codes,
};
use tenko_dns::{
    recurse::{InfraAddressView, InfraCutView, RecursionReport},
    recursion::infra::EdnsSupport,
    status::{
        self, CommandResult, DnsNode, InfraFlushArgs, InfraListArgs, InfraPage, Outcome, Output,
    },
};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    DnsCommandAccepted, InfraAddressItem, InfraCutItem, InfraFlushParams, InfraFlushed,
    InfraParams, InfraServerItem, InfraSizes, NtaCreate, NtaItem, PrimingItem, RecursionCounters,
    RecursionStatus, RootServerItem, TrustAnchorAdd, TrustAnchorItem, Zones, invalid,
    model::{AnchorKeyState, RecursionBudget},
    nodes::{Registry, Slot, command_failed, execute, local_role, record},
    parse_id, parse_node, with_etag,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams, encode_cursor},
    problem::{ApiError, ProblemDetails},
    routes::auth::ApiJson,
    state::AppState,
};
// WP10.2: the rows behind the trust anchor and negative trust anchor routes.
use tenko_auth::settings::Profile;
use tenko_dns::{
    anchors::text,
    validate::ValidatorReport,
    zone::{ZoneError, ZoneService},
};
use tenko_store::ReadViewExt as _;

/// The security profile in force, from the settings row (Standard before setup).
async fn profile(service: &ZoneService) -> Result<Profile, ApiError> {
    let view = service.view(None).await?;
    Ok(view
        .as_ref()
        .get_typed(&tenko_auth::model::SETTINGS, &())?
        .map_or(Profile::Standard, |(settings, _)| settings.profile))
}

fn anchor_item(row: tenko_dns::anchors::rows::AnchorRow) -> TrustAnchorItem {
    TrustAnchorItem {
        anchor: row.anchor,
        revision: row.revision,
    }
}

fn nta_item(row: tenko_dns::anchors::rows::NtaRow) -> NtaItem {
    NtaItem {
        nta: row.nta,
        revision: row.revision,
    }
}
// WP10.2: end.

/// Zone cuts per page of the infrastructure cache when the request names no limit.
const DEFAULT_PAGE: u32 = 200;

/// A zone name from the path of a trust anchor.
fn parse_zone(raw: &str) -> Result<DnsName, ApiError> {
    // A URL turns the segment `.` into a dot segment that never reaches the server, so a
    // path spells the root `root`; a zone named `root` is written `root.`.
    if raw == "root" {
        return Ok(DnsName::root());
    }
    DnsName::new(raw).map_err(|_| invalid("zone", "the zone is not a DNS name"))
}

/// The routes of the recursive resolver.
#[inline(never)]
pub(super) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_dns_trust_anchors, add_dns_trust_anchor))
        .routes(routes!(get_dns_trust_anchor, remove_dns_trust_anchor))
        .routes(routes!(refresh_dns_trust_anchor))
        .routes(routes!(list_dns_ntas, create_dns_nta))
        .routes(routes!(delete_dns_nta))
        .routes(routes!(get_node_dns_recursion))
        .routes(routes!(prime_node_dns_recursion))
        .routes(routes!(list_node_dns_infra))
        .routes(routes!(flush_node_dns_infra))
}

#[utoipa::path(
    get,
    path = "/dns/trust-anchors",
    tag = "dns",
    operation_id = "list_dns_trust_anchors",
    summary = "List the trust anchors",
    description = "Scope: `dns.read`. One row per zone: the root (the shipped anchors and what RFC 5011 made of them) and the anchors an operator added for private zones, each with its keys, their RFC 5011 state and source, and the times of the last and the next query.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of trust anchors by zone", body = Page<TrustAnchorItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_trust_anchors(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    let service = zones.get()?;
    let limit = page.limit()?;
    let scope = CursorScope::new("dns.trust_anchors");
    let after: Option<String> = page.cursor(scope)?;
    let view = page.read(service.store().as_ref()).await?;
    let mut items = Vec::new();
    let mut next = None;
    for row in ZoneService::trust_anchors(view.as_ref())? {
        let position = row.anchor.zone.to_string();
        if after.as_ref().is_some_and(|after| position <= *after) {
            continue;
        }
        if items.len() == limit {
            next = items
                .last()
                .map(|item: &TrustAnchorItem| encode_cursor(scope, &item.anchor.zone.to_string()));
            break;
        }
        items.push(anchor_item(row));
    }
    Ok(Json(Page::new(items, next, view.revision())).into_response())
}

#[utoipa::path(
    post,
    path = "/dns/trust-anchors",
    tag = "dns",
    operation_id = "add_dns_trust_anchor",
    summary = "Add a trust anchor for a zone",
    description = "Scope: `dns.keys`, in an interactive session. Adds a key, as a DS or a DNSKEY in presentation form, to the zone's trust anchor (creating it); the key is Valid at once and its source is the operator. The root is added to only with `replace_root` and only under the Lab profile. Audited as `dns.trust_anchor.add`.",
    request_body(content = TrustAnchorAdd, content_type = "application/json"),
    responses(
        (status = 201, description = "The trust anchor of the zone", body = TrustAnchorItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the key is invalid (`dns.trust_anchor.invalid`, parameters `field` and `reason`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to change trust anchors", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The root's anchor may not be replaced outside the Lab profile (`dns.trust_anchor.root_protected`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn add_dns_trust_anchor(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    ApiJson(body): ApiJson<TrustAnchorAdd>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::DnsKey))?;
    let service = zones.get()?;
    let key = match (body.ds, body.dnskey) {
        (Some(ds), None) => text::ds_key(text::parse_ds(&ds).map_err(ZoneError::from)?, cx.now),
        (None, Some(dnskey)) => text::dnskey_key(
            text::parse_dnskey(&dnskey).map_err(ZoneError::from)?,
            cx.now,
        ),
        _ => return Err(invalid("ds", "exactly one of ds and dnskey is given")),
    };
    let lab = profile(&service).await? == Profile::Lab;
    let (anchor, written) = service
        .add_trust_anchor(&cx, body.zone, key, body.replace_root, lab)
        .await?;
    let view = service.view(Some(written.revision)).await?;
    let row = ZoneService::trust_anchor(view.as_ref(), &anchor.zone)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::CREATED, &anchor_item(row), revision))
}

#[utoipa::path(
    get,
    path = "/dns/trust-anchors/{zone}",
    tag = "dns",
    operation_id = "get_dns_trust_anchor",
    summary = "Get the trust anchor of a zone",
    description = "Scope: `dns.read`. The root zone is written `.`.",
    params(("zone" = String, Path, description = "The zone name; `root` for the root (a URL cannot carry the segment `.`)")),
    responses(
        (status = 200, description = "The trust anchor with its `ETag`", body = TrustAnchorItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No trust anchor for the zone (`dns.trust_anchor.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dns_trust_anchor(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(zone): Path<String>,
) -> Result<Response, ApiError> {
    let zone = parse_zone(&zone)?;
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    let service = zones.get()?;
    let view = service.view(None).await?;
    let row = ZoneService::trust_anchor(view.as_ref(), &zone)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &anchor_item(row), revision))
}

#[utoipa::path(
    delete,
    path = "/dns/trust-anchors/{zone}",
    tag = "dns",
    operation_id = "remove_dns_trust_anchor",
    summary = "Remove the trust anchor of a zone",
    description = "Scope: `dns.keys`, in an interactive session. Names under the zone are validated against the next anchor above it, or are `indeterminate` when none applies. The root's anchor is removed only under the Lab profile. Audited as `dns.trust_anchor.remove`.",
    params(("zone" = String, Path, description = "The zone name; `root` for the root (a URL cannot carry the segment `.`)")),
    responses(
        (status = 204, description = "The trust anchor is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to change trust anchors", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No trust anchor for the zone (`dns.trust_anchor.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The root's anchor may not be removed outside the Lab profile (`dns.trust_anchor.root_protected`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn remove_dns_trust_anchor(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(zone): Path<String>,
) -> Result<Response, ApiError> {
    let zone = parse_zone(&zone)?;
    app.authorize(&cx.principal, Action::Delete, &anywhere(ObjectKind::DnsKey))?;
    let service = zones.get()?;
    let lab = profile(&service).await? == Profile::Lab;
    service.remove_trust_anchor(&cx, &zone, None, lab).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[utoipa::path(
    post,
    path = "/dns/trust-anchors/{zone}/refresh",
    tag = "dns",
    operation_id = "refresh_dns_trust_anchor",
    summary = "Run RFC 5011 for a zone now",
    description = "Scope: `dns.keys`. Asks the zone's DNSKEY set now instead of at the next refresh interval and applies RFC 5011 to the answer; audited as `dns.trust_anchor.refresh`. The answer is the recorded command; the key states follow through the `dns` events.",
    params(("zone" = String, Path, description = "The zone name; `root` for the root (a URL cannot carry the segment `.`)")),
    responses(
        (status = 202, description = "The refresh is queued on the leader's trust anchor service", body = DnsCommandAccepted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No trust anchor for the zone (`dns.trust_anchor.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The resolver is off (`dns.recursion.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn refresh_dns_trust_anchor(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(zone): Path<String>,
) -> Result<Response, ApiError> {
    let zone = parse_zone(&zone)?;
    app.authorize(
        &cx.principal,
        Action::Execute,
        &anywhere(ObjectKind::DnsKey),
    )?;
    let service = zones.get()?;
    let written = service.refresh_trust_anchor(&cx, &zone).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(DnsCommandAccepted {
            command_id: written.job.uuid(),
        }),
    )
        .into_response())
}

#[utoipa::path(
    get,
    path = "/dns/ntas",
    tag = "dns",
    operation_id = "list_dns_ntas",
    summary = "List the negative trust anchors",
    description = "Scope: `dns.read`. The negative trust anchors (RFC 7646) that have not expired, by zone: names at or below the zone are `insecure` instead of `bogus` while one lives.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of negative trust anchors by zone", body = Page<NtaItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_ntas(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    let service = zones.get()?;
    let limit = page.limit()?;
    let scope = CursorScope::new("dns.ntas");
    let after: Option<(String, NtaId)> = page.cursor(scope)?;
    let view = page.read(service.store().as_ref()).await?;
    let mut items = Vec::new();
    let mut next = None;
    for row in ZoneService::ntas(view.as_ref(), cx.now)? {
        let position = (row.nta.zone.to_string(), row.nta.id);
        if after.as_ref().is_some_and(|after| position <= *after) {
            continue;
        }
        if items.len() == limit {
            next = items.last().map(|item: &NtaItem| {
                encode_cursor(scope, &(item.nta.zone.to_string(), item.nta.id))
            });
            break;
        }
        items.push(nta_item(row));
    }
    Ok(Json(Page::new(items, next, view.revision())).into_response())
}

#[utoipa::path(
    post,
    path = "/dns/ntas",
    tag = "dns",
    operation_id = "create_dns_nta",
    summary = "Create a negative trust anchor",
    description = "Scope: `dns.keys`, in an interactive session. The expiry is at most seven days ahead and required under the Hardened profile; the reason is shown in the warnings of `GET /system/status` while the anchor lives. Audited as `dns.nta.create`.",
    request_body(content = NtaCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The negative trust anchor", body = NtaItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the anchor is invalid (`dns.nta.invalid`, parameters `field` and `reason`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to create one", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dns_nta(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    ApiJson(body): ApiJson<NtaCreate>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::DnsKey))?;
    let service = zones.get()?;
    let hardened = profile(&service).await? == Profile::Hardened;
    let (nta, written) = service
        .create_nta(&cx, body.zone, body.expires_at, body.reason, hardened)
        .await?;
    let revision = written.revision;
    Ok(with_etag(
        StatusCode::CREATED,
        &NtaItem { nta, revision },
        revision,
    ))
}

#[utoipa::path(
    delete,
    path = "/dns/ntas/{id}",
    tag = "dns",
    operation_id = "delete_dns_nta",
    summary = "Delete a negative trust anchor",
    description = "Scope: `dns.keys`, in an interactive session. Ends the anchor before its expiry; audited as `dns.nta.delete`.",
    params(("id" = String, Path, description = "Negative trust anchor identifier (UUID)")),
    responses(
        (status = 204, description = "The negative trust anchor is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to delete one", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such negative trust anchor (`dns.nta.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dns_nta(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<NtaId>(&id)?;
    app.authorize(&cx.principal, Action::Delete, &anywhere(ObjectKind::DnsKey))?;
    let service = zones.get()?;
    service.delete_nta(&cx, id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// WP10.1: the node routes.
/// A 400 `sys.invalid_value` for a query parameter.
fn invalid_value(field: &str, detail: impl Into<String>) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(error_codes::INVALID_VALUE, 400, detail.into())
            .with_param("field", field.to_owned()),
    )
}

/// The 409 for a node whose resolver is off.
fn disabled(node: NodeId) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(
            dns_codes::RECURSION_DISABLED,
            409,
            format!("the recursive resolver of node {node} is off"),
        )
        .with_title("Recursion disabled")
        .with_param("node", node.to_string()),
    )
}

/// The role of `node` when this process runs it and its resolver is on.
async fn recursing_role(
    app: &AppState,
    slot: Slot,
    registry: Registry,
    node: NodeId,
) -> Result<Arc<dyn DnsNode>, ApiError> {
    let role = local_role(app, slot, registry, node).await?;
    if role.status().recursion.is_none() {
        return Err(disabled(node));
    }
    Ok(role)
}

/// The error of a command that did not finish: a rejection is the resolver switched off
/// after the check, anything else is a failure of the node.
fn failed(node: NodeId, kind: &str, result: &CommandResult) -> ApiError {
    if result.outcome == Outcome::Rejected {
        disabled(node)
    } else {
        command_failed(kind, result)
    }
}

/// Milliseconds of a duration.
fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

/// A count as the API's unsigned 64 bits.
fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// The DTO of a node's resolver; a node without one reads as off with empty and zero
/// fields. `validation` is the validator's report when validation is on, `anchors` the
/// trust anchor rows the node reads (WP10.2).
pub(super) fn recursion_dto(
    report: Option<RecursionReport>,
    validation: Option<&ValidatorReport>,
    anchors: &[std::sync::Arc<tenko_core::dns::TrustAnchor>],
) -> RecursionStatus {
    // WP10.2: the keys of the anchors with their states.
    let trust_anchors: Vec<AnchorKeyState> = anchors
        .iter()
        .flat_map(|anchor| {
            anchor.keys.iter().map(|key| AnchorKeyState {
                zone: anchor.zone.clone(),
                key_tag: key.key_tag,
                state: key.state,
            })
        })
        .collect();
    let Some(report) = report else {
        return RecursionStatus {
            enabled: false,
            hints_source: String::new(),
            hints_date: String::new(),
            last_priming: None,
            root_expires_secs: None,
            root_servers: Vec::new(),
            infra: InfraSizes::default(),
            budget: RecursionBudget::default(),
            counters: RecursionCounters::default(),
            trust_anchors,
            problems: Vec::new(),
        };
    };
    let counters = report.counters;
    let (max_zones, max_servers) = report.infra_bounds;
    // WP10.2: the validator's figures.
    let validated = validation.map(|report| report.counters).unwrap_or_default();
    let (key_sets, key_sets_bound) =
        validation.map_or((0, 0), |report| (report.key_sets, report.key_sets_bound));
    RecursionStatus {
        enabled: true,
        hints_source: report.hints_source,
        hints_date: report.hints_date,
        last_priming: report.priming.map(|priming| PrimingItem {
            at: priming.at,
            outcome: if priming.ok { "ok" } else { "failed" }.to_owned(),
            duration_ms: millis(priming.duration),
        }),
        root_expires_secs: report.root_expires_in.map(|left| left.as_secs()),
        root_servers: report
            .root
            .into_iter()
            .map(|server| RootServerItem {
                name: server.name.to_string(),
                address: server.address.to_string(),
                srtt_ms: server.srtt.map(millis),
            })
            .collect(),
        infra: InfraSizes {
            zones: count(report.infra.cuts),
            max_zones: count(max_zones),
            servers: count(report.infra.servers),
            max_servers: count(max_servers),
            names: count(report.infra.names),
            // WP10.2: the validator's key sets.
            validated_zones: count(key_sets),
            max_validated_zones: count(key_sets_bound),
        },
        budget: RecursionBudget {
            queries: u32::from(report.budget.queries),
            restarts: u32::from(report.budget.restarts),
            depth: u32::from(report.budget.depth),
            attempts: u32::from(report.budget.attempts),
            wall_ms: u64::try_from(report.budget.wall.as_millis()).unwrap_or(u64::MAX),
        },
        counters: RecursionCounters {
            answered: counters.answered,
            servfail: counters.servfail,
            budget: counters.budget,
            timeout: counters.timeout,
            local: counters.local,
            failure_cache_hits: counters.failure_hits,
            joined: counters.joined,
            subqueries: counters.subqueries,
            budget_queries: counters.bound_queries,
            budget_restarts: counters.bound_restarts,
            budget_depth: counters.bound_depth,
            budget_time: counters.bound_time,
            primings_ok: counters.primings_ok,
            primings_failed: counters.primings_failed,
            unwanted: counters.unwanted,
            unwanted_flushes: counters.unwanted_flushes,
            // WP10.2: the validator's outcomes.
            secure: validated.secure,
            insecure: validated.insecure,
            bogus: validated.bogus,
            indeterminate: validated.indeterminate,
        },
        trust_anchors,
        problems: report.problems,
    }
}

/// The DTO of one address of a server in the listing.
pub(super) fn address_dto(view: &InfraAddressView) -> InfraAddressItem {
    let figures = view.figures;
    InfraAddressItem {
        address: view.address.to_string(),
        origin: view.origin.as_str().to_owned(),
        ttl: view.ttl,
        srtt_ms: figures.srtt.map(millis),
        p50_ms: figures.p50.map(millis),
        p99_ms: figures.p99.map(millis),
        failures: figures.failures,
        down: figures.down,
        edns: match view.edns {
            EdnsSupport::Unknown => None,
            EdnsSupport::Yes => Some(true),
            EdnsSupport::No => Some(false),
        },
        tcp_only: view.tcp_only,
        lame: view.lame,
        lower_case: figures.lower_case,
        unwanted: figures.unwanted,
    }
}

/// The DTO of one zone cut in the listing.
fn cut_dto(cut: InfraCutView) -> InfraCutItem {
    InfraCutItem {
        zone: cut.zone,
        servers: cut
            .servers
            .into_iter()
            .map(|server| InfraServerItem {
                name: server.name,
                addresses: server.addresses.iter().map(address_dto).collect(),
            })
            .collect(),
        ds: cut.ds.to_owned(),
        ttl: cut.ttl,
    }
}

/// A DNS name from a query parameter; blank counts as absent.
fn name_param(field: &str, raw: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(raw) = raw.filter(|raw| !raw.trim().is_empty()) else {
        return Ok(None);
    };
    DnsName::new(&raw)
        .map_err(|_| invalid_value(field, format!("{field}: `{raw}` is not a DNS name")))?;
    Ok(Some(raw))
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dns/recursion",
    tag = "dns",
    operation_id = "get_node_dns_recursion",
    summary = "Get the recursive resolver of a node",
    description = "Scope: `dns.read`. Whether the resolver runs (`enabled`; a node whose resolver is off answers with empty and zero fields), the source and date of the root hints, the last priming with its outcome and duration, the root servers with their smoothed round-trip times, the sizes of the infrastructure cache against their bounds, the work budget in force, the counters since the role started, and what is wrong (`priming_failed`). The counters include the validation outcomes (`secure`, `insecure`, `bogus`, `indeterminate`); `trust_anchors` lists the anchor keys with their RFC 5011 state; `problems` adds `clock` and `trust_anchor_stale`.",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 200, description = "The resolver's status", body = RecursionStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role (`dns.node.not_dns`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_node_dns_recursion(
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
    // WP10.2: with the validator's report and the anchors.
    let status = role.status();
    Ok(Json(recursion_dto(
        status.recursion,
        status.validation.as_ref(),
        &status.trust_anchors,
    ))
    .into_response())
}

#[utoipa::path(
    post,
    path = "/nodes/{id}/dns/recursion/prime",
    tag = "dns",
    operation_id = "prime_node_dns_recursion",
    summary = "Prime a node's resolver now",
    description = "Scope: `dns.write`. Issues the node command `dns.recursion.prime`, which asks the root servers for the root NS set again and refreshes the infrastructure cache from the answer; a priming that is running already is left to finish. The command is recorded in the node's commands and audited as `dns.recursion.prime`. The outcome shows in the status.",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 202, description = "The command was recorded", body = DnsCommandAccepted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role (`dns.node.not_dns`), or its resolver is off (`dns.recursion.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn prime_node_dns_recursion(
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
    let role = recursing_role(&app, slot, registry, node).await?;
    let result = execute(role, status::RECURSION_PRIME, Vec::new()).await;
    let draft = AuditDraft::success(audit::RECURSION_PRIME, vec![ObjectRef::node(node)])
        .with_context("detail", result.detail.clone());
    let record = record(
        zones,
        &cx,
        node,
        status::RECURSION_PRIME,
        Vec::new(),
        &result,
        Some(draft),
    )
    .await?;
    if result.outcome != Outcome::Done {
        return Err(failed(node, status::RECURSION_PRIME, &result));
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
    path = "/nodes/{id}/dns/infra",
    tag = "dns",
    operation_id = "list_node_dns_infra",
    summary = "List what a node's infrastructure cache holds",
    description = "Scope: `dns.read`. Issues the node command `dns.infra.list`: a page of the zone cuts the node's resolver knows, in the canonical order of their names, each with its authority servers, their addresses (origin, remaining time, smoothed round-trip time and its median and 99th percentile of the last minute, failures, back-off, EDNS capability, TCP-only, lame and lower-case flags, unwanted answers) and the DS state. `suffix` keeps the cuts at or below it; `cursor` is the `next_cursor` of the previous page. The infrastructure cache holds the authority servers of zones and no client data, so the read is recorded in the node's commands and not audited.",
    params(("id" = u64, Path, description = "Node id"), InfraParams),
    responses(
        (status = 200, description = "A page of zone cuts in canonical name order", body = Page<InfraCutItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role (`dns.node.not_dns`), or its resolver is off (`dns.recursion.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_node_dns_infra(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    zones: Zones,
    Path(id): Path<String>,
    Query(params): Query<InfraParams>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    let limit = params.limit.unwrap_or(DEFAULT_PAGE);
    if !(1..=status::MAX_INFRA_PAGE).contains(&limit) {
        return Err(invalid_value(
            "limit",
            format!("limit must be between 1 and {}", status::MAX_INFRA_PAGE),
        ));
    }
    let suffix = name_param("suffix", params.suffix)?;
    let after = name_param("cursor", params.cursor)?;
    let role = recursing_role(&app, slot, registry, node).await?;
    let args = to_cbor(&InfraListArgs {
        suffix,
        after,
        limit,
    })?
    .to_vec();
    let result = execute(role, status::INFRA_LIST, args.clone()).await;
    record(zones, &cx, node, status::INFRA_LIST, args, &result, None).await?;
    let Output::Infra(page) = result.output else {
        return Err(failed(node, status::INFRA_LIST, &result));
    };
    let InfraPage { cuts, next } = *page;
    let revision = app.store.status().revision;
    Ok(Json(Page::new(
        cuts.into_iter().map(cut_dto).collect(),
        next,
        revision,
    ))
    .into_response())
}

#[utoipa::path(
    post,
    path = "/nodes/{id}/dns/infra/flush",
    tag = "dns",
    operation_id = "flush_node_dns_infra",
    summary = "Flush a node's infrastructure cache",
    description = "Scope: `dns.write`. Issues the node command `dns.infra.flush`, which drops the zone cuts, server addresses and their figures, at or below `suffix` or all of them; the root hints stay and the next query primes again. The command is recorded in the node's commands and audited as `dns.infra.flush`.",
    params(("id" = u64, Path, description = "Node id"), InfraFlushParams),
    responses(
        (status = 200, description = "The number of entries dropped", body = InfraFlushed),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role (`dns.node.not_dns`), or its resolver is off (`dns.recursion.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn flush_node_dns_infra(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    slot: Slot,
    registry: Registry,
    zones: Zones,
    Path(id): Path<String>,
    Query(params): Query<InfraFlushParams>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Execute, &anywhere(ObjectKind::Zone))?;
    let suffix = name_param("suffix", params.suffix)?;
    let role = recursing_role(&app, slot, registry, node).await?;
    let args = if suffix.is_some() {
        to_cbor(&InfraFlushArgs {
            suffix: suffix.clone(),
        })?
        .to_vec()
    } else {
        Vec::new()
    };
    let result = execute(role, status::INFRA_FLUSH, args.clone()).await;
    let mut draft = AuditDraft::success(audit::INFRA_FLUSH, vec![ObjectRef::node(node)])
        .with_context("detail", result.detail.clone());
    if let Some(suffix) = suffix {
        draft = draft.with_context("suffix", suffix);
    }
    record(
        zones,
        &cx,
        node,
        status::INFRA_FLUSH,
        args,
        &result,
        Some(draft),
    )
    .await?;
    let Output::Flushed(entries) = result.output else {
        return Err(failed(node, status::INFRA_FLUSH, &result));
    };
    Ok(Json(InfraFlushed { entries }).into_response())
}
// WP10.1: end.
