//! Metrics in the `OpenMetrics` text format (OPS-05, OPS-21), split from the system area.
//!
//! Area: metrics. Owner: WP3.5 (the request counters and the handler moved here from
//! `routes/system.rs` in WP3.0 without a change of behaviour).
//! Requirements: OPS-05, OPS-21.
//!
//! `GET /metrics` needs a token with the `metrics` scope (owner decision S3-Q7); until
//! scoped tokens exist (WP3.2) any authenticated principal that may read the system passes.
//! WP3.5 replaces the counters with the metrics core of `tenko-core::metrics`, keeping the
//! names of the existing series.

use axum::{
    extract::State,
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use tenko_core::{Action, Principal, Timestamp};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::system::system_object;
use crate::{
    extract::Ctx,
    middleware::metrics::Sample,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// Media type of `GET /metrics`.
pub const OPENMETRICS: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// The routes of the area.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(metrics))
}

#[utoipa::path(
    get,
    path = "/metrics",
    tag = "metrics",
    operation_id = "metrics",
    summary = "Metrics in the OpenMetrics text format; needs a token with the metrics scope",
    responses(
        (status = 200, description = "Counters and gauges in the OpenMetrics text format", body = String, content_type = "application/openmetrics-text"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The token lacks the metrics scope", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn metrics(State(state): State<AppState>, Ctx(ctx): Ctx) -> Result<Response, ApiError> {
    require_metrics_scope(&state, &ctx.principal)?;
    let text = render_metrics(&state, ctx.now);
    let mut response = text.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(OPENMETRICS));
    Ok(response)
}

/// The scope check of `GET /metrics`. Token scopes arrive with WP3.2; until then every
/// authenticated principal that may read the system passes.
fn require_metrics_scope(state: &AppState, principal: &Principal) -> Result<(), ApiError> {
    state.authorize(principal, Action::Read, &system_object())
}

/// The metrics text: request counters, event hub, store and TLS gauges.
pub(crate) fn render_metrics(state: &AppState, now: Timestamp) -> String {
    let platform = &state.platform;
    let store = state.store.status();
    let hub = state.events();
    #[allow(clippy::cast_precision_loss)]
    let mut samples = vec![
        Sample::gauge(
            "tenko_build_info",
            "Version of the server, as a label-free 1.",
            1.0,
        ),
        Sample::gauge(
            "tenko_uptime_seconds",
            "Seconds since the API started.",
            platform.started.elapsed().as_secs_f64(),
        ),
        Sample::gauge(
            "tenko_sse_subscribers",
            "Open server-sent event streams.",
            hub.subscribers() as f64,
        ),
        Sample::counter(
            "tenko_sse_events",
            "Events published to subscribers.",
            hub.published() as f64,
        ),
        Sample::gauge(
            "tenko_store_revision",
            "Last applied store revision.",
            store.revision.get() as f64,
        ),
        Sample::gauge(
            "tenko_audit_head",
            "Sequence number of the newest audit record.",
            store.audit_head.get() as f64,
        ),
        Sample::gauge(
            "tenko_store_journal_entries",
            "Change sets in the store journal.",
            store.journal_len as f64,
        ),
        Sample::gauge(
            "tenko_store_data_bytes",
            "Bytes of live data in the store.",
            store.data_bytes as f64,
        ),
    ];
    if let Some(listener) = platform.listener.load_full()
        && let Some(certificate) = listener.status(now).0.certificate
        && let Some(not_after) = certificate.not_after
    {
        #[allow(clippy::cast_precision_loss)]
        let seconds = (not_after.0 - now.0).whole_seconds() as f64;
        samples.push(Sample::gauge(
            "tenko_tls_certificate_expiry_seconds",
            "Seconds until the served certificate expires.",
            seconds,
        ));
    }
    platform.metrics.render(&samples)
}
