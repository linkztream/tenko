//! Jobs and manual steps.
//!
//! Area: jobs. Owner: WP1.6. Requirements: IPAM-17.
//!
//! Long operations return `202` with a job; these endpoints list and show jobs, cancel
//! them, and complete a manual step.

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_jobs))
        .routes(routes!(get_job))
        .routes(routes!(cancel_job))
        .routes(routes!(complete_job_step))
}

#[utoipa::path(
    get,
    path = "/jobs",
    tag = "jobs",
    operation_id = "list_jobs",
    summary = "List jobs",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_jobs(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/jobs")
}

#[utoipa::path(
    get,
    path = "/jobs/{id}",
    tag = "jobs",
    operation_id = "get_job",
    summary = "Get one job with its steps",
    params(("id" = String, Path, description = "Job identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_job(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/jobs/{id}")
}

#[utoipa::path(
    post,
    path = "/jobs/{id}/cancel",
    tag = "jobs",
    operation_id = "cancel_job",
    summary = "Cancel a job",
    params(("id" = String, Path, description = "Job identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn cancel_job(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/jobs/{id}/cancel")
}

#[utoipa::path(
    post,
    path = "/jobs/{id}/steps/{index}/complete",
    tag = "jobs",
    operation_id = "complete_job_step",
    summary = "Complete a manual step of a job",
    params(
        ("id" = String, Path, description = "Job identifier"),
        ("index" = u32, Path, description = "Zero-based index of the step")
    ),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn complete_job_step(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/jobs/{id}/steps/{index}/complete")
}
