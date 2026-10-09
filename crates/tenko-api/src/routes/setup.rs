//! First-run setup (API-10).
//!
//! Area: setup. Owner: WP1.2. Open only before setup has completed: `GET /setup` reports
//! the state, `POST /setup` takes the one-time setup token, the profile, the first
//! administrator, the host name and the language, and returns a session.

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_setup, complete_setup))
}

#[utoipa::path(
    get,
    path = "/setup",
    tag = "setup",
    operation_id = "get_setup",
    summary = "Report whether first-run setup is still open",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_setup(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/setup")
}

#[utoipa::path(
    post,
    path = "/setup",
    tag = "setup",
    operation_id = "complete_setup",
    summary = "Complete first-run setup and start a session",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn complete_setup(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/setup")
}
