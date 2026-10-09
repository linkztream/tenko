//! Audit log and chain verification.
//!
//! Area: audit. Owner: WP1.7. Requirements: IAM-18.
//!
//! Records are identified by their sequence number in the hash chain. `GET /audit/verify`
//! is registered next to `/audit/{seq}`; axum matches the static segment first.

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_audit))
        .routes(routes!(verify_audit))
        .routes(routes!(get_audit_record))
}

#[utoipa::path(
    get,
    path = "/audit",
    tag = "audit",
    operation_id = "list_audit",
    summary = "List audit records",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_audit(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/audit")
}

#[utoipa::path(
    get,
    path = "/audit/verify",
    tag = "audit",
    operation_id = "verify_audit",
    summary = "Verify the hash chain of the audit log",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn verify_audit(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/audit/verify")
}

#[utoipa::path(
    get,
    path = "/audit/{seq}",
    tag = "audit",
    operation_id = "get_audit_record",
    summary = "Get one audit record",
    params(("seq" = u64, Path, description = "Sequence number of the audit record")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_audit_record(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/audit/{seq}")
}
