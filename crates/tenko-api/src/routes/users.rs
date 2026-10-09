//! Users, roles and break-glass access.
//!
//! Area: users. Owner: WP1.2. Requirements: IAM-05, IAM-09, IAM-19.
//!
//! Roles are global (`admin`, `operator`, `viewer`). Enabling break-glass access needs fresh
//! authentication (IAM-09).

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_users, create_user))
        .routes(routes!(get_user, update_user, delete_user))
        .routes(routes!(unlock_user))
        .routes(routes!(revoke_user_sessions))
        .routes(routes!(set_user_roles))
        .routes(routes!(list_roles))
        .routes(routes!(set_break_glass))
}

#[utoipa::path(
    get,
    path = "/users",
    tag = "users",
    operation_id = "list_users",
    summary = "List users",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_users(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/users")
}

#[utoipa::path(
    post,
    path = "/users",
    tag = "users",
    operation_id = "create_user",
    summary = "Create a user",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_user(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/users")
}

#[utoipa::path(
    get,
    path = "/users/{id}",
    tag = "users",
    operation_id = "get_user",
    summary = "Get one user",
    params(("id" = String, Path, description = "User identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_user(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/users/{id}")
}

#[utoipa::path(
    patch,
    path = "/users/{id}",
    tag = "users",
    operation_id = "update_user",
    summary = "Update a user",
    params(("id" = String, Path, description = "User identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_user(_ctx: Ctx) -> ApiError {
    not_implemented("PATCH", "/users/{id}")
}

#[utoipa::path(
    delete,
    path = "/users/{id}",
    tag = "users",
    operation_id = "delete_user",
    summary = "Delete a user",
    params(("id" = String, Path, description = "User identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_user(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/users/{id}")
}

#[utoipa::path(
    post,
    path = "/users/{id}/unlock",
    tag = "users",
    operation_id = "unlock_user",
    summary = "Lift the lockout of a user",
    params(("id" = String, Path, description = "User identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn unlock_user(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/users/{id}/unlock")
}

#[utoipa::path(
    delete,
    path = "/users/{id}/sessions",
    tag = "users",
    operation_id = "revoke_user_sessions",
    summary = "Revoke every session of a user",
    params(("id" = String, Path, description = "User identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn revoke_user_sessions(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/users/{id}/sessions")
}

#[utoipa::path(
    put,
    path = "/users/{id}/roles",
    tag = "users",
    operation_id = "set_user_roles",
    summary = "Replace the roles of a user",
    params(("id" = String, Path, description = "User identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn set_user_roles(_ctx: Ctx) -> ApiError {
    not_implemented("PUT", "/users/{id}/roles")
}

#[utoipa::path(
    get,
    path = "/roles",
    tag = "users",
    operation_id = "list_roles",
    summary = "List the available roles",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_roles(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/roles")
}

#[utoipa::path(
    put,
    path = "/system/break-glass",
    tag = "users",
    operation_id = "set_break_glass",
    summary = "Configure break-glass access; needs fresh authentication",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn set_break_glass(_ctx: Ctx) -> ApiError {
    not_implemented("PUT", "/system/break-glass")
}
