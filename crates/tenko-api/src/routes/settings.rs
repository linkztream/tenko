//! Security settings.
//!
//! Area: settings. Owner: WP1.2. Requirements: TGL-01, TGL-02, TGL-04, TGL-05.
//!
//! The security profile, its toggles and deviations. Every change is audited.

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_security_settings, update_security_settings))
}

#[utoipa::path(
    get,
    path = "/settings/security",
    tag = "settings",
    operation_id = "get_security_settings",
    summary = "Get the security profile, toggles and deviations",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_security_settings(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/settings/security")
}

#[utoipa::path(
    patch,
    path = "/settings/security",
    tag = "settings",
    operation_id = "update_security_settings",
    summary = "Change the security profile, toggles or deviations",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_security_settings(_ctx: Ctx) -> ApiError {
    not_implemented("PATCH", "/settings/security")
}
