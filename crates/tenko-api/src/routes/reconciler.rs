//! The settings of the reconciler: interval, debounce, orphan age, retention, refresh, purge
//! interval and adoption (IPAM-13).
//!
//! Area: ipam. Owner: WP3.12a.
//! Requirements: IPAM-13.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /settings/reconciler` | 200 [`ReconcilerSettings`] with `ETag` of the stored revision (none while nothing is stored) | 401, 403, 503 |
//! | `PUT /settings/reconciler` | 200 [`ReconcilerSettings`] with the new `ETag` | 400, 401, 403, 409 `sys.store.precondition_failed`, 422 `ipam.reconciler.settings.invalid`, 503 |
//!
//! The settings live in the store and are the same on every controller. Both endpoints are
//! for administrators ([`Action::Administer`] on the system); a change needs no step-up. The
//! reconciler reads the settings at every run, so a change applies at its next run without a
//! restart. A change is audited as `ipam.reconciler.settings.update`.

use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use tenko_core::Action;
use tenko_ipam::reconcile::settings::{self, ReconcilerSettings};
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

/// The routes of the area: `/settings/reconciler`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_reconciler_settings, update_reconciler_settings))
}

/// Shows the settings of the reconciler in force: the stored ones, else the defaults.
///
/// Limits and defaults: interval between periodic runs 30 to 86,400 seconds (default 300);
/// debounce after an ingest or an intent change 0 to 300 seconds (default 2); orphan age
/// 3,600 to 31,536,000 seconds (default 604,800); retention of facts 86,400 to 31,536,000
/// seconds (default 2,592,000); refresh of an unchanged fact 60 to 86,400 seconds and
/// shorter than the retention (default 900); interval between retention purges 300 to
/// 86,400 seconds (default 3,600); adoption policies applied (default true). Administrators
/// only.
#[utoipa::path(
    get,
    path = "/settings/reconciler",
    tag = "reconciler",
    operation_id = "get_reconciler_settings",
    summary = "Get the reconciler settings",
    responses(
        (status = 200, description = "The settings in force", body = ReconcilerSettings,
            headers(("ETag" = String, description = "The revision of the stored settings, for `If-Match` of `PUT /settings/reconciler`; absent while none are stored"))),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable (`sys.store.no_quorum`, `sys.store.timeout`, `sys.store.shutting_down`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn get_reconciler_settings(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
) -> Result<Response, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    let (current, revision) = settings::read(state.store().as_ref())
        .await
        .map_err(|error| ApiError::from_coded_error(error.into_coded()))?;
    let response = Json(current).into_response();
    Ok(match revision {
        Some(revision) => with_etag(response, revision),
        None => response,
    })
}

/// Replaces the settings of the reconciler; every field is sent. A change applies at the
/// reconciler's next run, on every controller, without a restart, and is audited as
/// `ipam.reconciler.settings.update` with one change per field.
///
/// Limits (seconds unless noted) and defaults: `interval_secs` 30 to 86,400 (default 300);
/// `debounce_secs` 0 to 300 (default 2); `orphan_after_secs` 3,600 to 31,536,000 (default
/// 604,800); `retention_secs` 86,400 to 31,536,000 (default 2,592,000); `refresh_secs` 60 to
/// 86,400 and shorter than `retention_secs` (default 900); `purge_interval_secs` 300 to
/// 86,400 (default 3,600); `adopt` (default true). A value outside its limits is refused with
/// 422 `ipam.reconciler.settings.invalid`, parameter `field`. Administrators only.
#[utoipa::path(
    put,
    path = "/settings/reconciler",
    tag = "reconciler",
    operation_id = "update_reconciler_settings",
    summary = "Change the reconciler settings",
    params(("If-Match" = Option<String>, Header, description = "The revision the client read, as in the `ETag` of `GET /settings/reconciler`; a stale revision is refused with 409")),
    request_body = ReconcilerSettings,
    responses(
        (status = 200, description = "The settings now in force", body = ReconcilerSettings,
            headers(("ETag" = String, description = "The new revision of the settings"))),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or `If-Match` is malformed (`ipam.validation`, parameter `field`: `If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "`If-Match` is stale or a concurrent change won (`sys.store.precondition_failed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "A value is outside its limits (`ipam.reconciler.settings.invalid`, parameter `field`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable (`sys.store.no_quorum`, `sys.store.timeout`, `sys.store.shutting_down`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn update_reconciler_settings(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    Json(body): Json<ReconcilerSettings>,
) -> Result<Response, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    let expect = if_match(&headers)?;
    let (stored, revision) = settings::update(state.store().as_ref(), &ctx, body, expect)
        .await
        .map_err(|error| ApiError::from_coded_error(error.into_coded()))?;
    Ok(with_etag(Json(stored).into_response(), revision))
}

#[cfg(test)]
mod tests;
