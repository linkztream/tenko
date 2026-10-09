//! Server-sent events.
//!
//! Area: events. Owner: WP1.7. Requirements: API-05.
//!
//! One stream, filtered by topic. Events carry references, not bodies, and their ids are
//! store revisions, so a client resumes after the revision of its last list (`from`) or
//! the last event it saw (`Last-Event-ID`). See [`crate::sse`] for replay, `reset` and
//! `shutdown`.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, header},
    response::Response,
};
use serde::Deserialize;
use tenko_core::Revision;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::events::{EventData, TopicSet},
    extract::Ctx,
    list::Filters,
    problem::{ApiError, ProblemDetails, codes},
    sse::event_stream,
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(events))
}

const LAST_EVENT_ID: HeaderName = HeaderName::from_static("last-event-id");
const X_ACCEL_BUFFERING: HeaderName = HeaderName::from_static("x-accel-buffering");

/// Query of `GET /events`, for the OpenAPI document; the handler reads it through
/// [`Filters`] so that errors are problem details.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
struct EventsQuery {
    /// Comma-separated topics: `ipam`, `jobs`, `audit`, `import`, `system`, `admin`; all
    /// when absent.
    topics: Option<String>,
    /// Resume after this store revision (the `revision` of a list); `Last-Event-ID` wins
    /// on reconnects.
    from: Option<u64>,
}

#[utoipa::path(
    get,
    path = "/events",
    tag = "events",
    operation_id = "events",
    summary = "Subscribe to server-sent events",
    description = "A `text/event-stream`. Data events have the topic as event name, the store \
        revision as id and an `EventData` document as data. `reset` (data `ResetData`) tells \
        the client to reload at the given revision; `shutdown` ends the stream. A `: keep-alive` \
        comment arrives every 15 seconds.",
    params(
        EventsQuery,
        ("Last-Event-ID" = Option<String>, Header, description = "Revision of the last event the client received")
    ),
    responses(
        (status = 200, description = "The event stream; each `data` field is an `EventData` (or a `ResetData` for `reset`)", content_type = "text/event-stream", body = EventData),
        (status = 400, description = "Unknown topic or malformed parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The server is shutting down", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn events(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    filters: Filters,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    filters.only(&["topics", "from"])?;
    let topics = TopicSet::parse(filters.get("topics")?.unwrap_or_default()).map_err(|error| {
        ApiError::new(codes::UNKNOWN_TOPIC, 400, error.to_string())
            .with_param("topic", error.value.clone())
    })?;
    let from = filters.parse::<u64>("from")?.map(Revision);
    // A malformed id cannot be served; the far future makes the hub answer `reset`.
    let last = headers
        .get(LAST_EVENT_ID)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok())
                .map_or(Revision(u64::MAX), Revision)
        })
        .or(from);

    let hub = state.events();
    if hub.is_shutting_down() {
        return Err(ApiError::new(
            codes::SHUTTING_DOWN,
            503,
            "the server is shutting down; reconnect shortly",
        ));
    }
    let stream = event_stream(hub, state.store.as_ref(), last, topics, ctx.principal).await;
    let mut response = Response::new(Body::from_stream(stream));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    headers.insert(X_ACCEL_BUFFERING, HeaderValue::from_static("no"));
    Ok(response)
}
