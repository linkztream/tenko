//! `GET|POST /dns/forwarders`, `GET|PATCH|DELETE /dns/forwarders/{id}`: forwarding rules
//! (DNS-02). The role's catalog follows the rows through the feed; the forwarder routes a
//! query by the longest suffix of its view, then of all views.
//!
//! The list and a read carry each rule's upstreams with their round-trip times and state on
//! the node that answers, when it runs the DNS role (`upstream_status`).

use std::collections::HashMap;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tenko_auth::authz::anywhere;
use tenko_core::{Action, ObjectKind, ObjectRef, dns::ForwardRuleId};
use tenko_dns::{
    forwarders::{NewRule, RuleChange, RuleRow},
    zone::ZoneService,
};

use super::{ForwarderCreate, ForwarderItem, ForwarderPatch, Zones, parse_id, with_etag};
// dns-visibility: the upstreams' figures.
use super::{
    UpstreamFigures,
    nodes::{Slot, upstream_figures},
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams, encode_cursor},
    problem::{ApiError, ProblemDetails},
    routes::auth::{ApiJson, if_match},
    state::AppState,
};

fn item(row: RuleRow) -> ForwarderItem {
    ForwarderItem {
        rule: row.rule,
        revision: row.revision,
        upstream_status: None,
    }
}

// dns-visibility: the upstreams' figures.
/// The upstreams' figures per rule from the DNS role of this process, when it runs one.
fn figures(slot: Option<&Slot>) -> HashMap<ForwardRuleId, Vec<UpstreamFigures>> {
    let Some(Some(Extension(slot))) = slot else {
        return HashMap::new();
    };
    let Some(status) = slot.status() else {
        return HashMap::new();
    };
    status
        .upstreams
        .into_iter()
        .filter_map(|group| {
            group.rule.map(|rule| {
                (
                    rule,
                    group.upstreams.into_iter().map(upstream_figures).collect(),
                )
            })
        })
        .collect()
}
// dns-visibility: end.

/// The position of a rule in the list: its suffix, then its id.
fn position(item: &ForwarderItem) -> (String, ForwardRuleId) {
    (item.rule.suffix.to_string(), item.rule.id)
}

#[utoipa::path(
    get,
    path = "/dns/forwarders",
    tag = "dns",
    operation_id = "list_dns_forwarders",
    summary = "List forwarding rules",
    description = "Scope: `dns.read`. Forwarding rules by suffix (the root rule `.`, the \
                   default forwarder, first).",
    params(PageParams),
    responses(
        (status = 200, description = "A page of rules by suffix, each with its upstreams' round-trip times and state on the node that answers (`upstream_status`, when it runs the DNS role)", body = Page<ForwarderItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dns_forwarders(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    slot: Slot,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DnsForwarder),
    )?;
    let service = zones.get()?;
    let limit = page.limit()?;
    let scope = CursorScope::new("dns.forwarders");
    let after: Option<(String, ForwardRuleId)> = page.cursor(scope)?;
    let view = page.read(service.store().as_ref()).await?;
    let mut figures = figures(Some(&slot));
    let mut rows: Vec<ForwarderItem> = ZoneService::forward_rules(view.as_ref())?
        .into_iter()
        .map(|row| {
            let mut item = item(row);
            item.upstream_status = figures.remove(&item.rule.id);
            item
        })
        .collect();
    rows.sort_by_key(position);
    let mut items = Vec::new();
    let mut next = None;
    for row in rows {
        if after.as_ref().is_some_and(|after| &position(&row) <= after) {
            continue;
        }
        if items.len() == limit {
            next = items
                .last()
                .map(|item: &ForwarderItem| encode_cursor(scope, &position(item)));
            break;
        }
        items.push(row);
    }
    Ok(Json(Page::new(items, next, view.revision())).into_response())
}

#[utoipa::path(
    post,
    path = "/dns/forwarders",
    tag = "dns",
    operation_id = "create_dns_forwarder",
    summary = "Create a forwarding rule",
    description = "Scope: `dns.write`. One rule per suffix and view; DoT and DoH upstreams \
                   need `tls_name`, the name in their certificates.",
    request_body(content = ForwarderCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The rule", body = ForwarderItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the rule is invalid (`dns.forwarder.invalid`, parameters `field` and `reason`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dns_forwarder(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    ApiJson(body): ApiJson<ForwarderCreate>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DnsForwarder),
    )?;
    let service = zones.get()?;
    let (rule, written) = service
        .create_forward_rule(
            &cx,
            NewRule {
                suffix: body.suffix,
                upstreams: body.upstreams,
                transport: body.transport,
                tls_name: body.tls_name,
                view: body.view,
                description: body.description,
            },
        )
        .await?;
    let view = service.view(Some(written.revision)).await?;
    let row = ZoneService::forward_rule(view.as_ref(), rule.id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::CREATED, &item(row), revision))
}

#[utoipa::path(
    get,
    path = "/dns/forwarders/{id}",
    tag = "dns",
    operation_id = "get_dns_forwarder",
    summary = "Get a forwarding rule",
    description = "Scope: `dns.read`. The rule carries its upstreams' round-trip times and \
                   state on the node that answers (`upstream_status`), when it runs the DNS \
                   role.",
    params(("id" = String, Path, description = "Forwarding rule identifier (UUID)")),
    responses(
        (status = 200, description = "The rule with its `ETag`", body = ForwarderItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such rule (`dns.forwarder.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dns_forwarder(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    slot: Slot,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ForwardRuleId>(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let view = service.view(None).await?;
    let row = ZoneService::forward_rule(view.as_ref(), id)?;
    let revision = row.revision;
    let mut item = item(row);
    item.upstream_status = figures(Some(&slot)).remove(&id);
    Ok(with_etag(StatusCode::OK, &item, revision))
}

#[utoipa::path(
    patch,
    path = "/dns/forwarders/{id}",
    tag = "dns",
    operation_id = "update_dns_forwarder",
    summary = "Change a forwarding rule",
    description = "Scope: `dns.write`. An empty `tls_name` or `description` clears it; \
                   `all_views` makes the rule apply in every view.",
    params(
        ("id" = String, Path, description = "Forwarding rule identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    request_body(content = ForwarderPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed rule", body = ForwarderItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the rule is invalid (`dns.forwarder.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such rule (`dns.forwarder.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The rule changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_dns_forwarder(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ForwarderPatch>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ForwardRuleId>(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let expect = if_match(&headers)?;
    let (_, written) = service
        .update_forward_rule(
            &cx,
            id,
            RuleChange {
                suffix: body.suffix,
                upstreams: body.upstreams,
                transport: body.transport,
                tls_name: body.tls_name,
                view: body.view,
                all_views: body.all_views,
                description: body.description,
            },
            expect,
        )
        .await?;
    let view = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ZoneService::forward_rule(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    delete,
    path = "/dns/forwarders/{id}",
    tag = "dns",
    operation_id = "delete_dns_forwarder",
    summary = "Delete a forwarding rule",
    description = "Scope: `dns.write`.",
    params(
        ("id" = String, Path, description = "Forwarding rule identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The rule is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such rule (`dns.forwarder.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The rule changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dns_forwarder(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_id::<ForwardRuleId>(&id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let expect = if_match(&headers)?;
    service.delete_forward_rule(&cx, id, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
