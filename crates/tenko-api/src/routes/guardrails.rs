//! The guardrails of network-controller writes: protected paths and the move parallelism
//! (CONN-09).
//!
//! Area: connectors. Owner: WP3.12a.
//! Requirements: CONN-09.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /settings/guardrails` | 200 [`Guardrails`] with `ETag` of the stored revision (none while nothing is stored) | 401, 403, 503 |
//! | `PUT /settings/guardrails` | 200 [`Guardrails`] with the new `ETag` | 400, 401, 403, 409 `sys.store.precondition_failed`, 422 `connect.guardrails.invalid`, 503 |
//!
//! The guardrails live in the store and are the same on every controller. Both endpoints are
//! for administrators ([`Action::Administer`] on the system); a change needs no step-up. The
//! network-controller adapter reads the guardrails at every call, so a change applies to the
//! next plan, write or revert without a restart. A change is audited as
//! `connect.guardrails.update`.

use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use tenko_connect::{Guardrails, host::guardrails};
use tenko_core::Action;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    common::{if_match, with_etag},
    system::system_object,
};
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The routes of the area: `/settings/guardrails`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_guardrails, update_guardrails))
}

/// Shows the guardrails of network-controller writes in force: the stored ones, else the
/// defaults (no protected paths, `max_parallel` 10).
///
/// The protected paths (ports, networks, VLANs, clients) are paths network-controller writes
/// and moves never touch, on top of the uplinks and management networks the topology always
/// protects. `max_parallel` (1 to 64, default 10) bounds the concurrent layer-2 writes of
/// move jobs through one controller instance. Administrators only.
#[utoipa::path(
    get,
    path = "/settings/guardrails",
    tag = "guardrails",
    operation_id = "get_guardrails",
    summary = "Get the guardrails",
    responses(
        (status = 200, description = "The guardrails in force", body = Guardrails,
            headers(("ETag" = String, description = "The revision of the stored guardrails, for `If-Match` of `PUT /settings/guardrails`; absent while none are stored"))),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable (`sys.store.no_quorum`, `sys.store.timeout`, `sys.store.shutting_down`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_guardrails(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
) -> Result<Response, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    let (current, revision) = guardrails::read(state.store().as_ref())
        .await
        .map_err(|error| ApiError::from_coded_error(error.into_coded()))?;
    let response = Json(current).into_response();
    Ok(match revision {
        Some(revision) => with_etag(response, revision),
        None => response,
    })
}

/// Replaces the guardrails of network-controller writes; the whole body is sent.
///
/// The protected paths (ports, networks, VLANs, clients) are paths network-controller writes
/// and moves never touch, on top of the uplinks and management networks the topology always
/// protects. `max_parallel` (1 to 64, default 10) bounds the concurrent layer-2 writes of
/// move jobs through one controller instance. Limits: at most 256 paths, VLAN ids 1 to 4094,
/// references 1 to 128 characters, no duplicates; a violation is refused with 422
/// `connect.guardrails.invalid`, parameter `field`. A change applies to the next plan, write
/// or revert without a restart and is audited as `connect.guardrails.update`. Administrators
/// only.
#[utoipa::path(
    put,
    path = "/settings/guardrails",
    tag = "guardrails",
    operation_id = "update_guardrails",
    summary = "Change the guardrails",
    params(("If-Match" = Option<String>, Header, description = "The revision the client read, as in the `ETag` of `GET /settings/guardrails`; a stale revision is refused with 409")),
    request_body = Guardrails,
    responses(
        (status = 200, description = "The guardrails now in force", body = Guardrails,
            headers(("ETag" = String, description = "The new revision of the guardrails"))),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or `If-Match` is malformed (`ipam.validation`, parameter `field`: `If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "`If-Match` is stale or a concurrent change won (`sys.store.precondition_failed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "A value is outside its limits (`connect.guardrails.invalid`, parameter `field`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable (`sys.store.no_quorum`, `sys.store.timeout`, `sys.store.shutting_down`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn update_guardrails(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    Json(body): Json<Guardrails>,
) -> Result<Response, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    let expect = if_match(&headers)?;
    let (stored, revision) = guardrails::update(state.store().as_ref(), &ctx, body, expect)
        .await
        .map_err(|error| ApiError::from_coded_error(error.into_coded()))?;
    Ok(with_etag(Json(stored).into_response(), revision))
}

#[cfg(test)]
mod tests;
