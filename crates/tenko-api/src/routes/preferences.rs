//! The personal preferences of the signed-in person: the saved layout of each table of the
//! web UI (UI-Q4 of the UI plan, API-08).
//!
//! Area: auth (the person's own routes, beside `/auth/session`). Owner: U6.
//!
//! | Endpoint | Success | Notes |
//! |---|---|---|
//! | `GET /auth/preferences` | 200 page of `Preference` | every key of the person, ordered by key; not paginated (at most 64) |
//! | `PUT /auth/preferences/{key}` | 200 `Preference` | the body is a `TableLayout`; creates or replaces the key |
//! | `DELETE /auth/preferences/{key}` | 204 | the table returns to its default layout |
//!
//! Own data only: the routes take no user id and act on the user of the session, so an
//! administrator cannot read or write another person's preferences through them. They need
//! an interactive session; a personal or scoped token is refused (`401
//! auth.unauthenticated`), like the other routes that act on the person's own account. The
//! document is checked against its schema (unknown fields refused, at most 16 KiB, at most
//! 64 keys per person); the column ids inside it are the UI's to check. Nothing is audited
//! and no event reaches the live stream. `tenko_auth::preferences` has the bounds.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use tenko_auth::preferences::{Preference, TableLayout};

use super::auth::{ApiJson, RouteError, Svc, Unauthenticated, Unavailable, page};
use crate::{dto::Page, extract::Ctx, problem::ProblemDetails, state::AppState};
use utoipa_axum::{router::OpenApiRouter, routes};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_preferences))
        .routes(routes!(put_preference, delete_preference))
}

/// Lists every preference of the signed-in person, ordered by key.
#[utoipa::path(
    get,
    path = "/auth/preferences",
    tag = "auth",
    operation_id = "list_preferences",
    summary = "List the preferences of the signed-in person (saved table layouts)",
    responses(
        (status = 200, description = "Every key of the person; not paginated: `next_cursor` is always `null`", body = Page<Preference>),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn list_preferences(
    State(app): State<AppState>,
    Svc(service): Svc,
    Ctx(ctx): Ctx,
) -> Result<Json<Page<Preference>>, RouteError> {
    Ok(page(&app, service.list_preferences(&ctx).await?))
}

/// Writes one preference of the signed-in person.
#[utoipa::path(
    put,
    path = "/auth/preferences/{key}",
    tag = "auth",
    operation_id = "put_preference",
    summary = "Save one preference of the signed-in person, such as the layout of a table",
    params(("key" = String, Path, description = "`table:<id>`: `table:` and 1 to 64 of a-z, 0-9, `.`, `_` and `-`")),
    request_body = TableLayout,
    responses(
        (status = 200, description = "The preference as stored", body = Preference),
        (status = 400, description = "The body does not match the schema or names an unknown field (`sys.invalid_request`), or the key, a column id, a width or the version is invalid (`auth.invalid_request` with `field`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The person has 64 keys already (`auth.preference.limit`), or another write of the person's keys came first (`auth.conflict`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "The document exceeds 16 KiB (`auth.preference.too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn put_preference(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(key): Path<String>,
    ApiJson(layout): ApiJson<TableLayout>,
) -> Result<Json<Preference>, RouteError> {
    Ok(Json(service.put_preference(&ctx, &key, &layout).await?))
}

/// Removes one preference of the signed-in person.
#[utoipa::path(
    delete,
    path = "/auth/preferences/{key}",
    tag = "auth",
    operation_id = "delete_preference",
    summary = "Remove one preference of the signed-in person; the table returns to its default",
    params(("key" = String, Path, description = "`table:<id>`")),
    responses(
        (status = 204, description = "The preference was removed"),
        (status = 400, description = "The key is invalid (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The person has no such key (`auth.preference.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn delete_preference(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(key): Path<String>,
) -> Result<StatusCode, RouteError> {
    service.delete_preference(&ctx, &key).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
#[path = "preferences_tests.rs"]
mod tests;
