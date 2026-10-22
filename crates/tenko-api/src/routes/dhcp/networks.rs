//! `GET|POST /dhcp/shared-networks`, `GET|PATCH|DELETE /dhcp/shared-networks/{id}`:
//! shared networks, server-wide configuration on the `dhcp_scope` singleton.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tenko_core::{
    Action,
    dhcp::{SharedNetworkId, server_object},
};
use tenko_dhcp::config::{
    ConfigService,
    networks::{SharedNetworkChange, SharedNetworkRow},
};

use super::{
    Configs, SharedNetworkCreate, SharedNetworkItem, SharedNetworkPatch, page_of, parse_id,
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

fn item(row: SharedNetworkRow) -> SharedNetworkItem {
    SharedNetworkItem {
        shared_network: row.shared_network,
        scopes: row.scopes,
        revision: row.revision,
    }
}

#[utoipa::path(
    get,
    path = "/dhcp/shared-networks",
    tag = "dhcp",
    operation_id = "list_dhcp_shared_networks",
    summary = "List DHCP shared networks",
    description = "Scope: `dhcp.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of shared networks by name", body = Page<SharedNetworkItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dhcp_shared_networks(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &server_object())?;
    let service = configs.get()?;
    let view = page.read(service.store().as_ref()).await?;
    let items: Vec<SharedNetworkItem> = ConfigService::shared_networks(view.as_ref())?
        .into_iter()
        .map(item)
        .collect();
    let page = page_of(
        items,
        |item| (item.shared_network.name.clone(), item.shared_network.id),
        &page,
        CursorScope::new("dhcp.shared_networks"),
        view.revision(),
    )?;
    Ok(Json(page).into_response())
}

#[utoipa::path(
    post,
    path = "/dhcp/shared-networks",
    tag = "dhcp",
    operation_id = "create_dhcp_shared_network",
    summary = "Create a DHCP shared network",
    description = "Scope: `dhcp.write`. Scopes join it with their `shared_network`.",
    request_body(content = SharedNetworkCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The shared network", body = SharedNetworkItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the name or interface is invalid or the name is taken (`dhcp.shared_network.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dhcp_shared_network(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    ApiJson(body): ApiJson<SharedNetworkCreate>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &server_object())?;
    let service = configs.get()?;
    let (network, written) = service
        .create_shared_network(&cx, body.name, body.interface, body.description)
        .await?;
    let view = service.view(Some(written.revision)).await?;
    let row = ConfigService::shared_network(view.as_ref(), network.id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::CREATED, &item(row), revision))
}

#[utoipa::path(
    get,
    path = "/dhcp/shared-networks/{id}",
    tag = "dhcp",
    operation_id = "get_dhcp_shared_network",
    summary = "Get a DHCP shared network",
    description = "Scope: `dhcp.read`.",
    params(("id" = String, Path, description = "Shared network identifier (UUID)")),
    responses(
        (status = 200, description = "The shared network, with its `ETag`", body = SharedNetworkItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such shared network (`dhcp.shared_network.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dhcp_shared_network(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<SharedNetworkId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &server_object())?;
    let service = configs.get()?;
    let view = service.view(None).await?;
    let row = ConfigService::shared_network(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    patch,
    path = "/dhcp/shared-networks/{id}",
    tag = "dhcp",
    operation_id = "update_dhcp_shared_network",
    summary = "Change a DHCP shared network",
    description = "Scope: `dhcp.write`.",
    params(
        ("id" = String, Path, description = "Shared network identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    request_body(content = SharedNetworkPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed shared network", body = SharedNetworkItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the name or interface is invalid or the name is taken (`dhcp.shared_network.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such shared network (`dhcp.shared_network.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The shared network changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_dhcp_shared_network(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<SharedNetworkPatch>,
) -> Result<Response, ApiError> {
    let id = parse_id::<SharedNetworkId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &server_object())?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    let (_, written) = service
        .update_shared_network(
            &cx,
            id,
            SharedNetworkChange {
                name: body.name,
                interface: body.interface,
                description: body.description,
            },
            expect,
        )
        .await?;
    let view = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ConfigService::shared_network(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    delete,
    path = "/dhcp/shared-networks/{id}",
    tag = "dhcp",
    operation_id = "delete_dhcp_shared_network",
    summary = "Delete a DHCP shared network",
    description = "Scope: `dhcp.write`. A shared network that scopes still name stays (`dhcp.shared_network.in_use`).",
    params(
        ("id" = String, Path, description = "Shared network identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The shared network is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such shared network (`dhcp.shared_network.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Scopes still belong to it (`dhcp.shared_network.in_use`), or the DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The shared network changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dhcp_shared_network(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_id::<SharedNetworkId>("id", &id)?;
    app.authorize(&cx.principal, Action::Delete, &server_object())?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    service.delete_shared_network(&cx, id, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
