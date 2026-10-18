//! `GET|POST /dns/acls`, `GET|PATCH|DELETE /dns/acls/{id}`: access lists.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tenko_auth::authz::anywhere;
use tenko_core::{Action, ObjectKind, ObjectRef, dns::AclId};
use tenko_dns::zone::{
    ZoneService,
    acl::{AclChange, AclRow, NewAcl},
};

use super::{AclCreate, AclItem, AclPatch, Zones, parse_id, with_etag};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams, encode_cursor},
    problem::{ApiError, ProblemDetails},
    routes::auth::{ApiJson, if_match},
    state::AppState,
};

fn item(row: AclRow) -> AclItem {
    AclItem {
        acl: row.acl,
        used_by: row.used_by,
        revision: row.revision,
    }
}

#[utoipa::path(
    get,
    path = "/dns/acls",
    tag = "dns",
    operation_id = "list_dns_acls",
    summary = "List DNS access lists",
    description = "Scope: `dns.read`. Access lists by name, with the zones that name them.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of access lists by name", body = Page<AclItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dns_acls(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::DnsAcl))?;
    let service = zones.get()?;
    let limit = page.limit()?;
    let scope = CursorScope::new("dns.acls");
    let after: Option<(String, AclId)> = page.cursor(scope)?;
    let view = page.read(service.store().as_ref()).await?;
    let mut items = Vec::new();
    let mut next = None;
    for row in ZoneService::acls(view.as_ref())? {
        let position = (row.acl.name.to_lowercase(), row.acl.id);
        if after.as_ref().is_some_and(|after| &position <= after) {
            continue;
        }
        if items.len() == limit {
            next = items.last().map(|item: &AclItem| {
                encode_cursor(scope, &(item.acl.name.to_lowercase(), item.acl.id))
            });
            break;
        }
        items.push(item(row));
    }
    Ok(Json(Page::new(items, next, view.revision())).into_response())
}

#[utoipa::path(
    post,
    path = "/dns/acls",
    tag = "dns",
    operation_id = "create_dns_acl",
    summary = "Create a DNS access list",
    description = "Scope: `dns.write`. The first entry that matches decides; no match refuses.",
    request_body(content = AclCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The access list", body = AclItem),
        (status = 400, description = "The request is malformed or the name is invalid or taken (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dns_acl(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    ApiJson(body): ApiJson<AclCreate>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::DnsAcl))?;
    let service = zones.get()?;
    let (acl, written) = service
        .create_acl(
            &cx,
            NewAcl {
                name: body.name,
                entries: body.entries,
                description: body.description,
            },
        )
        .await?;
    let view = service.view(Some(written.revision)).await?;
    let row = ZoneService::acl(view.as_ref(), acl.id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::CREATED, &item(row), revision))
}

#[utoipa::path(
    get,
    path = "/dns/acls/{id}",
    tag = "dns",
    operation_id = "get_dns_acl",
    summary = "Get a DNS access list",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "Access list identifier (UUID)")),
    responses(
        (status = 200, description = "The access list with its `ETag`", body = AclItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such access list (`dns.acl.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dns_acl(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<AclId>(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let view = service.view(None).await?;
    let row = ZoneService::acl(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    patch,
    path = "/dns/acls/{id}",
    tag = "dns",
    operation_id = "update_dns_acl",
    summary = "Change a DNS access list",
    description = "Scope: `dns.write`.",
    params(
        ("id" = String, Path, description = "Access list identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    request_body(content = AclPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed access list", body = AclItem),
        (status = 400, description = "The request is malformed or the name is invalid or taken (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such access list (`dns.acl.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The access list changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_dns_acl(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<AclPatch>,
) -> Result<Response, ApiError> {
    let id = parse_id::<AclId>(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let expect = if_match(&headers)?;
    let (_, written) = service
        .update_acl(
            &cx,
            id,
            AclChange {
                name: body.name,
                entries: body.entries,
                description: body.description,
            },
            expect,
        )
        .await?;
    let view = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ZoneService::acl(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    delete,
    path = "/dns/acls/{id}",
    tag = "dns",
    operation_id = "delete_dns_acl",
    summary = "Delete a DNS access list",
    description = "Scope: `dns.write`. A list a zone names stays (`dns.acl.in_use`).",
    params(
        ("id" = String, Path, description = "Access list identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The access list is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such access list (`dns.acl.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A zone or a view names the access list (`dns.acl.in_use`, parameter `by`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The access list changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dns_acl(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_id::<AclId>(&id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let expect = if_match(&headers)?;
    service.delete_acl(&cx, id, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
