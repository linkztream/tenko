//! `GET /dhcp/pools`, `GET|PUT|DELETE /dhcp/pools/{range}`: the IPAM ranges of role
//! `dhcp_pool` and `dhcp_pd_pool` (WP9.2, the delegation pools) of the scopes with their DHCP
//! settings; a delegation pool counts prefixes. A pool is checked on the kind first
//! and then on the scope of its range's prefix.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tenko_auth::authz::anywhere;
use tenko_core::{Action, ObjectKind, RangeId, dhcp::scope_object};
use tenko_dhcp::config::{
    ConfigService,
    pools::{PoolChange, PoolRow},
};

use super::{
    Configs, DhcpPoolItem, DhcpPoolSet, DhcpScopeFilter, may_read_scope, page_of, parse_id,
    with_etag,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams},
    problem::{ApiError, ProblemDetails},
    routes::auth::{ApiJson, if_match},
    state::AppState,
};

fn item(row: PoolRow) -> DhcpPoolItem {
    DhcpPoolItem {
        range: row.range.id,
        role: row.range.role,
        delegated_len: row.range.delegated_len,
        prefix: row.range.prefix,
        first: row.range.first,
        last: row.range.last,
        lease_secs: row.range.lease_secs,
        settings: row.settings,
        size: row.size,
        leased: row.leased,
        revision: row.revision,
    }
}

#[utoipa::path(
    get,
    path = "/dhcp/pools",
    tag = "dhcp",
    operation_id = "list_dhcp_pools",
    summary = "List DHCP pools",
    description = "Scope: `dhcp.read`. The pools of the scopes the caller may read, by scope and start address: the address pools (`role` `dhcp_pool`) and the delegation pools of DHCPv6 scopes (`dhcp_pd_pool`, with `delegated_len`; `size` and `leased` count prefixes).",
    params(PageParams, DhcpScopeFilter),
    responses(
        (status = 200, description = "A page of pools by start address", body = Page<DhcpPoolItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix of `scope` (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dhcp_pools(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Query(page): Query<PageParams>,
    Query(filter): Query<DhcpScopeFilter>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    if let Some(prefix) = filter.scope {
        app.authorize(&cx.principal, Action::Read, &scope_object(prefix))?;
    }
    let service = configs.get()?;
    let view = page.read(service.store().as_ref()).await?;
    let items: Vec<DhcpPoolItem> = ConfigService::pools(view.as_ref(), filter.scope)?
        .into_iter()
        .filter(|row| may_read_scope(&app, &cx.principal, row.range.prefix))
        .map(item)
        .collect();
    let mut scope = CursorScope::new("dhcp.pools");
    if let Some(prefix) = filter.scope {
        scope = scope.with(&prefix.to_string());
    }
    let page = page_of(
        items,
        |item| (item.prefix, item.first, item.range),
        &page,
        scope,
        view.revision(),
    )?;
    Ok(Json(page).into_response())
}

#[utoipa::path(
    get,
    path = "/dhcp/pools/{range}",
    tag = "dhcp",
    operation_id = "get_dhcp_pool",
    summary = "Get a DHCP pool",
    description = "Scope: `dhcp.read` on the pool's scope.",
    params(("range" = String, Path, description = "Range identifier (UUID) of the pool")),
    responses(
        (status = 200, description = "The pool, with the `ETag` of its settings", body = DhcpPoolItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The range does not exist or is no pool (`dhcp.pool.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dhcp_pool(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(range): Path<String>,
) -> Result<Response, ApiError> {
    let range = parse_id::<RangeId>("range", &range)?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let service = configs.get()?;
    let view = service.view(None).await?;
    let prefix = ConfigService::pool_prefix(view.as_ref(), range)?;
    app.authorize(&cx.principal, Action::Read, &scope_object(prefix))?;
    let row = ConfigService::pool(view.as_ref(), range)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    put,
    path = "/dhcp/pools/{range}",
    tag = "dhcp",
    operation_id = "set_dhcp_pool",
    summary = "Set the DHCP settings of a pool",
    description = "Scope: `dhcp.write` on the pool's scope. The range itself is changed through the IPAM range routes.",
    params(
        ("range" = String, Path, description = "Range identifier (UUID) of the pool"),
        ("If-Match" = Option<String>, Header, description = "The revision of the settings the client read (0 for none); a stale revision is refused with 412")
    ),
    request_body(content = DhcpPoolSet, content_type = "application/json"),
    responses(
        (status = 200, description = "The pool with its settings", body = DhcpPoolItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), the range lies outside its scope (`dhcp.pool.outside`) or the lease times are invalid (`dhcp.lease_times.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The range does not exist (`dhcp.pool.not_found`), its prefix has no scope (`dhcp.scope.not_found`) or a class does not exist (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The range's role is not `dhcp_pool` (`dhcp.pool.not_pool`), or the DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The settings changed since they were read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn set_dhcp_pool(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(range): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<DhcpPoolSet>,
) -> Result<Response, ApiError> {
    let range = parse_id::<RangeId>("range", &range)?;
    app.authorize(
        &cx.principal,
        Action::Update,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    let prefix = ConfigService::pool_prefix(service.view(None).await?.as_ref(), range)?;
    app.authorize(&cx.principal, Action::Update, &scope_object(prefix))?;
    let (_, written) = service
        .set_pool(
            &cx,
            range,
            PoolChange {
                classes: body.classes,
                lease: body.lease,
            },
            expect,
        )
        .await?;
    let view = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ConfigService::pool(view.as_ref(), range)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    delete,
    path = "/dhcp/pools/{range}",
    tag = "dhcp",
    operation_id = "delete_dhcp_pool",
    summary = "Remove the DHCP settings of a pool (the range stays)",
    description = "Scope: `dhcp.write` on the pool's scope. The pool's options go with them.",
    params(
        ("range" = String, Path, description = "Range identifier (UUID) of the pool"),
        ("If-Match" = Option<String>, Header, description = "The revision of the settings the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The settings are gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The pool has no settings (`dhcp.pool.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The settings changed since they were read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dhcp_pool(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(range): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let range = parse_id::<RangeId>("range", &range)?;
    app.authorize(
        &cx.principal,
        Action::Update,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    let view = service.view(None).await?;
    if let Ok(prefix) = ConfigService::pool_prefix(view.as_ref(), range) {
        app.authorize(&cx.principal, Action::Update, &scope_object(prefix))?;
    }
    service.delete_pool(&cx, range, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
