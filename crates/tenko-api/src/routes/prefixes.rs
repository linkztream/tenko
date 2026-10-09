//! Prefixes, the prefix tree, next-free allocation and ranges.
//!
//! Area: prefixes. Owner: WP1.4. Requirements: IPAM-05, IPAM-06, IPAM-07, IPAM-10.
//!
//! The tree carries utilization and alarms. `GET /prefixes/tree` is registered next to
//! `/prefixes/{id}`; axum matches the static segment first.

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_prefixes, create_prefix))
        .routes(routes!(get_prefix_tree))
        .routes(routes!(get_prefix, update_prefix, delete_prefix))
        .routes(routes!(next_free_address))
        .routes(routes!(next_free_prefix))
        .routes(routes!(list_prefix_addresses))
        .routes(routes!(list_prefix_ranges, create_range))
        .routes(routes!(get_range, update_range, delete_range))
}

#[utoipa::path(
    get,
    path = "/prefixes",
    tag = "prefixes",
    operation_id = "list_prefixes",
    summary = "List prefixes",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_prefixes(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/prefixes")
}

#[utoipa::path(
    post,
    path = "/prefixes",
    tag = "prefixes",
    operation_id = "create_prefix",
    summary = "Create a prefix",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_prefix(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/prefixes")
}

#[utoipa::path(
    get,
    path = "/prefixes/tree",
    tag = "prefixes",
    operation_id = "get_prefix_tree",
    summary = "Get the prefix tree with utilization and alarms",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_prefix_tree(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/prefixes/tree")
}

#[utoipa::path(
    get,
    path = "/prefixes/{id}",
    tag = "prefixes",
    operation_id = "get_prefix",
    summary = "Get one prefix",
    params(("id" = String, Path, description = "Prefix identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_prefix(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/prefixes/{id}")
}

#[utoipa::path(
    patch,
    path = "/prefixes/{id}",
    tag = "prefixes",
    operation_id = "update_prefix",
    summary = "Update a prefix",
    params(("id" = String, Path, description = "Prefix identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_prefix(_ctx: Ctx) -> ApiError {
    not_implemented("PATCH", "/prefixes/{id}")
}

#[utoipa::path(
    delete,
    path = "/prefixes/{id}",
    tag = "prefixes",
    operation_id = "delete_prefix",
    summary = "Delete a prefix",
    params(("id" = String, Path, description = "Prefix identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_prefix(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/prefixes/{id}")
}

#[utoipa::path(
    post,
    path = "/prefixes/{id}/next-free-address",
    tag = "prefixes",
    operation_id = "next_free_address",
    summary = "Allocate the next free address in a prefix",
    params(("id" = String, Path, description = "Prefix identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn next_free_address(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/prefixes/{id}/next-free-address")
}

#[utoipa::path(
    post,
    path = "/prefixes/{id}/next-free-prefix",
    tag = "prefixes",
    operation_id = "next_free_prefix",
    summary = "Allocate the next free child prefix of a prefix",
    params(("id" = String, Path, description = "Prefix identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn next_free_prefix(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/prefixes/{id}/next-free-prefix")
}

#[utoipa::path(
    get,
    path = "/prefixes/{id}/addresses",
    tag = "prefixes",
    operation_id = "list_prefix_addresses",
    summary = "List the addresses of a prefix, optionally with the free ones",
    params(
        ("id" = String, Path, description = "Prefix identifier"),
        ("include_free" = Option<bool>, Query, description = "Also return the free addresses")
    ),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_prefix_addresses(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/prefixes/{id}/addresses")
}

#[utoipa::path(
    get,
    path = "/prefixes/{id}/ranges",
    tag = "prefixes",
    operation_id = "list_prefix_ranges",
    summary = "List the ranges of a prefix",
    params(("id" = String, Path, description = "Prefix identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_prefix_ranges(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/prefixes/{id}/ranges")
}

#[utoipa::path(
    post,
    path = "/prefixes/{id}/ranges",
    tag = "prefixes",
    operation_id = "create_range",
    summary = "Create a range in a prefix",
    params(("id" = String, Path, description = "Prefix identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_range(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/prefixes/{id}/ranges")
}

#[utoipa::path(
    get,
    path = "/ranges/{id}",
    tag = "prefixes",
    operation_id = "get_range",
    summary = "Get one range",
    params(("id" = String, Path, description = "Range identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_range(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/ranges/{id}")
}

#[utoipa::path(
    patch,
    path = "/ranges/{id}",
    tag = "prefixes",
    operation_id = "update_range",
    summary = "Update a range",
    params(("id" = String, Path, description = "Range identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_range(_ctx: Ctx) -> ApiError {
    not_implemented("PATCH", "/ranges/{id}")
}

#[utoipa::path(
    delete,
    path = "/ranges/{id}",
    tag = "prefixes",
    operation_id = "delete_range",
    summary = "Delete a range",
    params(("id" = String, Path, description = "Range identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_range(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/ranges/{id}")
}
