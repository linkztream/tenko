//! Server-sent events.
//!
//! Area: events. Owner: WP1.7. Requirements: API-05.
//!
//! One stream, filtered by topic. Events carry references, not bodies, and their ids are
//! revisions, so a client resumes from the revision of its last list. The stream itself is
//! WP1.7; until then the endpoint is a stub.

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(events))
}

#[utoipa::path(
    get,
    path = "/events",
    tag = "events",
    operation_id = "events",
    summary = "Subscribe to server-sent events",
    params(
        ("topics" = Option<String>, Query, description = "Comma-separated topics: ipam, jobs, audit, import, system")
    ),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn events(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/events")
}
