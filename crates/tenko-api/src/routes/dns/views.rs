//! `GET|POST /dns/views`, `GET|PATCH|DELETE /dns/views/{id}`: views (DNS-20). The views
//! are tried in `order` and the first whose rules all match a query wins; its scope map
//! picks the zone scopes the query sees, and its recursion access list who may recurse. A
//! query no view matches is in the implicit default view, which is no row: the default
//! scope of every zone and the profile's recursion default. The role's catalog follows the
//! rows through the feed.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, ObjectKind, ObjectRef,
    dns::{ResolutionMode, ViewId},
};
use tenko_dns::zone::{
    ZoneService,
    views::{NewView, ViewChange, ViewRow},
};

use super::{ViewCreate, ViewItem, ViewPatch, Zones, parse_id, with_etag};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams, encode_cursor},
    problem::{ApiError, ProblemDetails},
    routes::auth::{ApiJson, if_match},
    state::AppState,
};

// WP10.4: the profile's resolution beside the view's own.
/// The resolution of a view without one of its own: recursion under every profile
/// (REC-Q2). A node whose resolver is off forwards to `[dns] forwarders` instead.
pub(super) const PROFILE_RESOLUTION: ResolutionMode = ResolutionMode::Recurse;
// WP10.4: end.

fn item(row: ViewRow) -> ViewItem {
    ViewItem {
        view: row.view,
        revision: row.revision,
        // WP10.4: the profile's resolution beside the view's own.
        profile_resolution: PROFILE_RESOLUTION,
    }
}

/// The position of a view in the list: its order, then its id.
fn position(item: &ViewItem) -> (u32, ViewId) {
    (item.view.order, item.view.id)
}

#[utoipa::path(
    get,
    path = "/dns/views",
    tag = "dns",
    operation_id = "list_dns_views",
    summary = "List DNS views",
    description = "Scope: `dns.read`. The views in the order they are tried (`order` from 1); \
                   a query no view matches is in the implicit default view, which is not \
                   listed.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of views in order", body = Page<ViewItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dns_views(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::DnsView))?;
    let service = zones.get()?;
    let limit = page.limit()?;
    let scope = CursorScope::new("dns.views");
    let after: Option<(u32, ViewId)> = page.cursor(scope)?;
    let view = page.read(service.store().as_ref()).await?;
    let rows: Vec<ViewItem> = ZoneService::dns_views(view.as_ref())?
        .into_iter()
        .map(item)
        .collect();
    let mut items = Vec::new();
    let mut next = None;
    for row in rows {
        if after.as_ref().is_some_and(|after| &position(&row) <= after) {
            continue;
        }
        if items.len() == limit {
            next = items
                .last()
                .map(|item: &ViewItem| encode_cursor(scope, &position(item)));
            break;
        }
        items.push(row);
    }
    Ok(Json(Page::new(items, next, view.revision())).into_response())
}

#[utoipa::path(
    post,
    path = "/dns/views",
    tag = "dns",
    operation_id = "create_dns_view",
    summary = "Create a DNS view",
    description = "Scope: `dns.write`. The view goes to `order` (from 1) and the views from \
                   there move one down; a position past the end is the end. Every zone \
                   scope of `scope_map` must exist, weights are 1 to 1000, and `recursion` \
                   names an access list. `resolution` (`recurse`, `forward` or `refuse`) \
                   says how the view's clients get names outside the zones and the \
                   forwarding rules; absent, the view follows the profile's default \
                   (`profile_resolution` in the answer).",
    request_body(content = ViewCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The view", body = ViewItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the view is invalid (`dns.view.invalid`, parameters `field` and `reason`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dns_view(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    ApiJson(body): ApiJson<ViewCreate>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DnsView),
    )?;
    let service = zones.get()?;
    let (view, written) = service
        .create_view(
            &cx,
            NewView {
                name: body.name,
                rules: body.rules,
                scope_map: body.scope_map,
                order: body.order,
                recursion: body.recursion,
                // WP10.4: the view's resolution.
                resolution: body.resolution,
                description: body.description,
            },
        )
        .await?;
    let read = service.view(Some(written.revision)).await?;
    let row = ZoneService::dns_view(read.as_ref(), view.id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::CREATED, &item(row), revision))
}

#[utoipa::path(
    get,
    path = "/dns/views/{id}",
    tag = "dns",
    operation_id = "get_dns_view",
    summary = "Get a DNS view",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "View identifier (UUID)")),
    responses(
        (status = 200, description = "The view with its `ETag`", body = ViewItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such view (`dns.view.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dns_view(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ViewId>(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let read = service.view(None).await?;
    let row = ZoneService::dns_view(read.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    patch,
    path = "/dns/views/{id}",
    tag = "dns",
    operation_id = "update_dns_view",
    summary = "Change a DNS view",
    description = "Scope: `dns.write`. `rules` and `scope_map` replace the view's; `order` \
                   moves the view and the others make room; `default_recursion` makes the \
                   view follow the profile's default; an empty `description` clears it. \
                   `resolution` sets how the view's clients get names outside the zones and \
                   the forwarding rules and `default_resolution` clears it, so that the \
                   view follows the profile's default again.",
    params(
        ("id" = String, Path, description = "View identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    request_body(content = ViewPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed view", body = ViewItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the view is invalid (`dns.view.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such view (`dns.view.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The view changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_dns_view(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ViewPatch>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ViewId>(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let expect = if_match(&headers)?;
    let (_, written) = service
        .update_view(
            &cx,
            id,
            ViewChange {
                name: body.name,
                rules: body.rules,
                scope_map: body.scope_map,
                order: body.order,
                recursion: body.recursion,
                default_recursion: body.default_recursion,
                // WP10.4: the view's resolution.
                resolution: body.resolution,
                default_resolution: body.default_resolution,
                description: body.description,
            },
            expect,
        )
        .await?;
    let read = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ZoneService::dns_view(read.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    delete,
    path = "/dns/views/{id}",
    tag = "dns",
    operation_id = "delete_dns_view",
    summary = "Delete a DNS view",
    description = "Scope: `dns.write`. The views after it move up one. A view a forwarding \
                   rule names is refused.",
    params(
        ("id" = String, Path, description = "View identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The view is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such view (`dns.view.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A forwarding rule names the view (`dns.view.in_use`, parameter `by`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The view changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dns_view(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_id::<ViewId>(&id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let expect = if_match(&headers)?;
    service.delete_view(&cx, id, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
