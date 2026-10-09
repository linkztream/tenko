//! Hosts and their interfaces.
//!
//! Area: hosts. Owner: WP1.4. Requirements: IPAM-05, IPAM-07.
//!
//! A host owns interfaces, and an interface carries MAC addresses and links to addresses.
//! History, restore and bulk changes are in [`super::common`].

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_hosts, create_host))
        .routes(routes!(get_host, update_host, delete_host))
        .routes(routes!(create_interface))
        .routes(routes!(update_interface, delete_interface))
}

#[utoipa::path(
    get,
    path = "/hosts",
    tag = "hosts",
    operation_id = "list_hosts",
    summary = "List hosts",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_hosts(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/hosts")
}

#[utoipa::path(
    post,
    path = "/hosts",
    tag = "hosts",
    operation_id = "create_host",
    summary = "Create a host",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_host(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/hosts")
}

#[utoipa::path(
    get,
    path = "/hosts/{id}",
    tag = "hosts",
    operation_id = "get_host",
    summary = "Get one host",
    params(("id" = String, Path, description = "Host identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_host(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/hosts/{id}")
}

#[utoipa::path(
    patch,
    path = "/hosts/{id}",
    tag = "hosts",
    operation_id = "update_host",
    summary = "Update a host",
    params(("id" = String, Path, description = "Host identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_host(_ctx: Ctx) -> ApiError {
    not_implemented("PATCH", "/hosts/{id}")
}

#[utoipa::path(
    delete,
    path = "/hosts/{id}",
    tag = "hosts",
    operation_id = "delete_host",
    summary = "Delete a host",
    params(("id" = String, Path, description = "Host identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_host(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/hosts/{id}")
}

#[utoipa::path(
    post,
    path = "/hosts/{id}/interfaces",
    tag = "hosts",
    operation_id = "create_interface",
    summary = "Add an interface to a host",
    params(("id" = String, Path, description = "Host identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_interface(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/hosts/{id}/interfaces")
}

#[utoipa::path(
    patch,
    path = "/interfaces/{id}",
    tag = "hosts",
    operation_id = "update_interface",
    summary = "Update an interface",
    params(("id" = String, Path, description = "Interface identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_interface(_ctx: Ctx) -> ApiError {
    not_implemented("PATCH", "/interfaces/{id}")
}

#[utoipa::path(
    delete,
    path = "/interfaces/{id}",
    tag = "hosts",
    operation_id = "delete_interface",
    summary = "Delete an interface",
    params(("id" = String, Path, description = "Interface identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_interface(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/interfaces/{id}")
}
