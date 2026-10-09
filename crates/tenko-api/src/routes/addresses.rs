//! Addresses.
//!
//! Area: addresses. Owner: WP1.4. Requirements: IPAM-05, IPAM-07.
//!
//! Create, read, update and soft-delete for addresses, with mode, lock, MAC and DUID. History,
//! restore and bulk changes are in [`super::common`].

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_addresses, create_address))
        .routes(routes!(get_address, update_address, delete_address))
}

#[utoipa::path(
    get,
    path = "/addresses",
    tag = "addresses",
    operation_id = "list_addresses",
    summary = "List addresses",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_addresses(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/addresses")
}

#[utoipa::path(
    post,
    path = "/addresses",
    tag = "addresses",
    operation_id = "create_address",
    summary = "Create an address",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_address(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/addresses")
}

#[utoipa::path(
    get,
    path = "/addresses/{id}",
    tag = "addresses",
    operation_id = "get_address",
    summary = "Get one address",
    params(("id" = String, Path, description = "Address identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_address(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/addresses/{id}")
}

#[utoipa::path(
    patch,
    path = "/addresses/{id}",
    tag = "addresses",
    operation_id = "update_address",
    summary = "Update an address",
    params(("id" = String, Path, description = "Address identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_address(_ctx: Ctx) -> ApiError {
    not_implemented("PATCH", "/addresses/{id}")
}

#[utoipa::path(
    delete,
    path = "/addresses/{id}",
    tag = "addresses",
    operation_id = "delete_address",
    summary = "Delete an address",
    params(("id" = String, Path, description = "Address identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_address(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/addresses/{id}")
}
