//! Health, status, the OpenAPI document and metrics.
//!
//! Area: system. Owner: WP1.7. Requirements: API-01, OPS-05, OPS-19.
//!
//! Liveness and the OpenAPI document are open; the metrics endpoint needs a token with the
//! `metrics` scope. `GET /openapi.json` is already real: it serves the document that
//! [`crate::openapi`] builds from these annotations.

use axum::Json;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(health))
        .routes(routes!(ready))
        .routes(routes!(system_status))
        .routes(routes!(openapi_document))
        .routes(routes!(metrics))
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "system",
    operation_id = "health",
    summary = "Liveness probe",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn health(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/health")
}

#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "system",
    operation_id = "ready",
    summary = "Readiness probe",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn ready(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/health/ready")
}

#[utoipa::path(
    get,
    path = "/system/status",
    tag = "system",
    operation_id = "system_status",
    summary = "Get the status of the installation: version, store, certificates and warnings",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn system_status(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/system/status")
}

#[utoipa::path(
    get,
    path = "/openapi.json",
    tag = "system",
    operation_id = "openapi_document",
    summary = "Get the OpenAPI document of this API",
    responses(
        (status = 200, description = "The OpenAPI document", body = Object, content_type = "application/json")
    )
)]
async fn openapi_document() -> Json<utoipa::openapi::OpenApi> {
    Json(crate::openapi())
}

#[utoipa::path(
    get,
    path = "/metrics",
    tag = "system",
    operation_id = "metrics",
    summary = "Metrics in the OpenMetrics text format; needs a token with the metrics scope",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn metrics(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/metrics")
}
