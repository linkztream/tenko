//! `GET|POST /dns/lists`, `GET|PATCH|DELETE /dns/lists/{id}`, `POST /dns/lists/{id}/fetch`
//! and `PUT /dns/lists/{id}/file`: block lists and allow lists (DNS-21, P2-Q6).
//!
//! A URL list is fetched by the leader service `dns.lists` on its interval and at once by
//! the fetch route; an uploaded list is compiled from the file the upload route hands in.
//! Both run the compile job `dns.list.compile` (202 with the job); the role's catalog
//! follows the versions through the feed. A list read carries its newest version and the
//! outcome of its last fetch or compile on this controller.

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{FromRequestParts, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, CodedError, ObjectKind, ObjectRef,
    dns::{BlockListId, ListKind, codes},
};
use tenko_dns::{
    lists::{ListChange, ListRow, ListStaging, NewList, fetch_status, job::Trigger},
    zone::ZoneService,
};

use super::{
    DnsJobStarted, ListCreate, ListItem, ListPatch, ListVersionItem, Zones, parse_id, with_etag,
};
use crate::{
    API_BASE,
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams, encode_cursor},
    problem::{ApiError, ProblemDetails},
    routes::auth::{ApiJson, if_match},
    state::AppState,
};

/// The body limit of `PUT /dns/lists/{id}/file`, in octets (`[dns.lists] max_upload`), as
/// the server adds it to the request extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListUploadLimit(pub usize);

/// The default upload limit: 64 MiB.
const DEFAULT_UPLOAD: usize = 64 * 1024 * 1024;

/// The staging of uploaded files and the upload limit, from the request extensions.
pub(crate) struct Uploads {
    staging: Option<Arc<ListStaging>>,
    limit: usize,
}

impl<S: Send + Sync> FromRequestParts<S> for Uploads {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Uploads {
            staging: parts.extensions.get::<Arc<ListStaging>>().cloned(),
            limit: parts
                .extensions
                .get::<ListUploadLimit>()
                .map_or(DEFAULT_UPLOAD, |limit| limit.0),
        }))
    }
}

impl Uploads {
    fn staging(&self) -> Result<Arc<ListStaging>, ApiError> {
        self.staging.clone().ok_or_else(|| {
            ApiError::from_coded_error(
                CodedError::new(
                    codes::MODULE_DISABLED,
                    409,
                    "the block list jobs do not run on this server",
                )
                .with_title("DNS module disabled"),
            )
        })
    }
}

fn item(row: ListRow) -> ListItem {
    let status = fetch_status(row.list.id);
    ListItem {
        version: row.version.map(|version| ListVersionItem {
            revision: version.revision,
            entries: version.entries,
            fetched: version.fetched,
            etag: version.etag,
            bytes: version.bytes,
        }),
        last_error: status.as_ref().and_then(|status| status.error.clone()),
        last_error_detail: status.as_ref().and_then(|status| status.detail.clone()),
        last_checked: status.map(|status| status.checked),
        list: row.list,
        revision: row.revision,
    }
}

/// The position of a list in the page: its name without case, then its id.
fn position(item: &ListItem) -> (String, BlockListId) {
    (item.list.name.to_lowercase(), item.list.id)
}

fn invalid_exempt(text: &str) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(
            codes::LIST_INVALID,
            400,
            format!("exempt: `{text}` is not a prefix such as 192.0.2.0/24"),
        )
        .with_title("Invalid block list")
        .with_param("field", "exempt")
        .with_param("reason", "a prefix such as 192.0.2.0/24"),
    )
}

/// The exempt prefixes of a request (an address is its host prefix).
fn prefixes(texts: &[String]) -> Result<Vec<IpNet>, ApiError> {
    texts
        .iter()
        .map(|text| {
            text.parse::<IpNet>()
                .or_else(|_| text.parse::<std::net::IpAddr>().map(IpNet::from))
                .map(|prefix| prefix.trunc())
                .map_err(|_| invalid_exempt(text))
        })
        .collect()
}

fn job_started(job_id: tenko_core::JobId) -> Response {
    let mut response = (StatusCode::ACCEPTED, Json(DnsJobStarted { job_id })).into_response();
    if let Ok(location) = HeaderValue::from_str(&format!("{API_BASE}/jobs/{job_id}")) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

#[utoipa::path(
    get,
    path = "/dns/lists",
    tag = "dns",
    operation_id = "list_dns_lists",
    summary = "List block lists",
    description = "Scope: `dns.read`. Block and allow lists by name, each with its newest \
                   version and the outcome of its last fetch or compile on this controller.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of block lists by name", body = Page<ListItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dns_lists(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::DnsList))?;
    let service = zones.get()?;
    let limit = page.limit()?;
    let scope = CursorScope::new("dns.lists");
    let after: Option<(String, BlockListId)> = page.cursor(scope)?;
    let view = page.read(service.store().as_ref()).await?;
    let mut rows: Vec<ListItem> = ZoneService::block_lists(view.as_ref())?
        .into_iter()
        .map(item)
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
                .map(|item: &ListItem| encode_cursor(scope, &position(item)));
            break;
        }
        items.push(row);
    }
    Ok(Json(Page::new(items, next, view.revision())).into_response())
}

#[utoipa::path(
    post,
    path = "/dns/lists",
    tag = "dns",
    operation_id = "create_dns_list",
    summary = "Create a block list",
    description = "Scope: `dns.write`. A `block` list (the default) answers the names it holds \
                   and the names under them with its action and the extended error `Blocked`; \
                   an `allow` list keeps them from being blocked, and exempts its `exempt` \
                   clients from every list and RPZ zone. A URL list is fetched within a minute; \
                   an uploaded list waits for its file (`PUT /dns/lists/{id}/file`).",
    request_body(content = ListCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The block list", body = ListItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the list is invalid (`dns.list.invalid`, parameters `field` and `reason`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dns_list(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    ApiJson(body): ApiJson<ListCreate>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DnsList),
    )?;
    let service = zones.get()?;
    let exempt = prefixes(&body.exempt)?;
    let (list, written) = service
        .create_block_list(
            &cx,
            NewList {
                name: body.name,
                kind: body.kind.unwrap_or(ListKind::Block),
                source: body.source,
                format: body.format,
                interval_hours: body.interval_hours,
                action: body.action,
                enabled: body.enabled,
                exempt,
                description: body.description,
            },
        )
        .await?;
    let view = service.view(Some(written.revision)).await?;
    let row = ZoneService::block_list(view.as_ref(), list.id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::CREATED, &item(row), revision))
}

#[utoipa::path(
    get,
    path = "/dns/lists/{id}",
    tag = "dns",
    operation_id = "get_dns_list",
    summary = "Get a block list",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "Block list identifier (UUID)")),
    responses(
        (status = 200, description = "The block list with its newest version and its `ETag`", body = ListItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such list (`dns.list.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dns_list(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<BlockListId>(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let view = service.view(None).await?;
    let row = ZoneService::block_list(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    patch,
    path = "/dns/lists/{id}",
    tag = "dns",
    operation_id = "update_dns_list",
    summary = "Change a block list",
    description = "Scope: `dns.write`. A new `source` or `format` drops the list's versions: a \
                   URL list is fetched again within a minute, an uploaded list waits for its \
                   next file. `exempt` replaces the prefixes; an empty `description` clears it.",
    params(
        ("id" = String, Path, description = "Block list identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    request_body(content = ListPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed block list", body = ListItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the list is invalid (`dns.list.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such list (`dns.list.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The list changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_dns_list(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ListPatch>,
) -> Result<Response, ApiError> {
    let id = parse_id::<BlockListId>(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let expect = if_match(&headers)?;
    let exempt = body.exempt.as_deref().map(prefixes).transpose()?;
    let (_, written) = service
        .update_block_list(
            &cx,
            id,
            ListChange {
                name: body.name,
                kind: body.kind,
                source: body.source,
                format: body.format,
                interval_hours: body.interval_hours,
                action: body.action,
                enabled: body.enabled,
                exempt,
                description: body.description,
            },
            expect,
        )
        .await?;
    let view = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ZoneService::block_list(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    delete,
    path = "/dns/lists/{id}",
    tag = "dns",
    operation_id = "delete_dns_list",
    summary = "Delete a block list",
    description = "Scope: `dns.write`.",
    params(
        ("id" = String, Path, description = "Block list identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The list and its versions are gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such list (`dns.list.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The list changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dns_list(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_id::<BlockListId>(&id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let expect = if_match(&headers)?;
    service.delete_block_list(&cx, id, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[utoipa::path(
    post,
    path = "/dns/lists/{id}/fetch",
    tag = "dns",
    operation_id = "fetch_dns_list",
    summary = "Fetch and compile a block list now",
    description = "Scope: `dns.write`. Starts the compile job `dns.list.compile`: the URL is \
                   read with `If-None-Match` and the entity tag of the newest version; a source \
                   that did not change writes nothing, a failed fetch keeps the version and \
                   shows in `last_error`. Audited as `dns.list.fetch`.",
    params(("id" = String, Path, description = "Block list identifier (UUID)")),
    responses(
        (status = 202, description = "The fetch job; follow it at the `Location`", body = DnsJobStarted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such list (`dns.list.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The list is uploaded, not fetched (`dns.list.invalid`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn fetch_dns_list(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    uploads: Uploads,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<BlockListId>(&id)?;
    app.authorize(&cx.principal, Action::Execute, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let staging = uploads.staging()?;
    let job = service
        .start_list_compile(&cx, id, &staging, None, Trigger::Fetch)
        .await?;
    Ok(job_started(job))
}

fn too_large(limit: usize) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(
            crate::problem::codes::BODY_TOO_LARGE,
            413,
            format!(
                "the file may have at most {} MiB (dns.lists.max_upload)",
                limit / (1024 * 1024)
            ),
        )
        .with_title("Request body too large"),
    )
}

#[utoipa::path(
    put,
    path = "/dns/lists/{id}/file",
    tag = "dns",
    operation_id = "upload_dns_list",
    summary = "Upload the file of a block list",
    description = "Scope: `dns.write`. The body is the list's text in its `format` (a hosts \
                   file or one domain per line), at most `[dns.lists] max_upload` MiB (64 by \
                   default). Starts the compile job `dns.list.compile`, which writes the next \
                   version. Audited as `dns.list.upload`.",
    params(("id" = String, Path, description = "Block list identifier (UUID)")),
    request_body(content = String, content_type = "text/plain"),
    responses(
        (status = 202, description = "The compile job; follow it at the `Location`", body = DnsJobStarted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such list (`dns.list.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The list is fetched from a URL, not uploaded (`dns.list.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "The file is larger than `[dns.lists] max_upload` (`sys.body_too_large`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn upload_dns_list(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    uploads: Uploads,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let id = parse_id::<BlockListId>(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let staging = uploads.staging()?;
    let limit = uploads.limit;
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|length| length > limit) {
        return Err(too_large(limit));
    }
    let file = axum::body::to_bytes(body, limit)
        .await
        .map_err(|_| too_large(limit))?;
    let job = service
        .start_list_compile(&cx, id, &staging, Some(file.to_vec()), Trigger::Upload)
        .await?;
    Ok(job_started(job))
}
