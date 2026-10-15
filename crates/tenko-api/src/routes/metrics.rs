//! Metrics in the `OpenMetrics` text format (OPS-05, OPS-21), split from the system area.
//!
//! Area: metrics. Owner: WP3.5.
//! Requirements: OPS-05, OPS-21.
//!
//! `GET /metrics` encodes the snapshot of the state's metrics registry: the request
//! counters and latency histograms of the middleware, the process counters, the gauges
//! that a timer of the server binary sets every `[metrics] gauge_interval_secs`
//! ([`refresh_gauges`] for the gauges of this crate), and two values computed at scrape
//! time, `tenko_uptime_seconds` and `tenko_build_info`.
//!
//! Reading it is the read of [`METRICS_OBJECT`] (owner decision S3-Q7): a token with the
//! `metrics` scope passes, so does any principal that reads the system (an administrator's
//! session); a token without that scope gets 403.

use axum::{
    extract::State,
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use tenko_auth::authz::METRICS_OBJECT;
use tenko_core::{
    Action, Principal, Timestamp,
    metrics::{Desc, Gauge, Registry, Snapshot, Value, encode},
};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// Media type of `GET /metrics`.
pub const OPENMETRICS: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

static SSE_SUBSCRIBERS: Gauge = Gauge::new(Desc::gauge(
    "tenko_sse_subscribers",
    "Open server-sent event streams.",
));
static SSE_EVENTS: Gauge = Gauge::new(Desc::counter(
    "tenko_sse_events",
    "Events published to subscribers.",
));
static STORE_REVISION: Gauge = Gauge::new(Desc::gauge(
    "tenko_store_revision",
    "Last applied store revision.",
));
static AUDIT_HEAD: Gauge = Gauge::new(Desc::gauge(
    "tenko_audit_head",
    "Sequence number of the newest audit record.",
));
static STORE_JOURNAL: Gauge = Gauge::new(Desc::gauge(
    "tenko_store_journal_entries",
    "Change sets in the store journal.",
));
static STORE_DATA_BYTES: Gauge = Gauge::new(
    Desc::gauge("tenko_store_data_bytes", "Bytes of live data in the store.").unit("bytes"),
);
static TLS_EXPIRY: Gauge = Gauge::new(
    Desc::gauge(
        "tenko_tls_certificate_expiry_seconds",
        "Seconds until the served certificate expires.",
    )
    .unit("seconds"),
);

/// Computed at scrape time.
static BUILD_INFO: Desc = Desc::gauge(
    "tenko_build_info",
    "Version of the server, as a label-free 1.",
);
/// Computed at scrape time.
static UPTIME: Desc =
    Desc::gauge("tenko_uptime_seconds", "Seconds since the API started.").unit("seconds");

/// Registers the gauges of this crate (called once per state).
pub(crate) fn register(registry: &Registry) {
    registry.register(&SSE_SUBSCRIBERS);
    registry.register(&SSE_EVENTS);
    registry.register(&STORE_REVISION);
    registry.register(&AUDIT_HEAD);
    registry.register(&STORE_JOURNAL);
    registry.register(&STORE_DATA_BYTES);
    registry.register(&TLS_EXPIRY);
}

/// Sets the gauges of this crate from the state: the event hub, the store status and the
/// certificate of the listener. The server binary calls it on its gauge timer; a scrape
/// does not compute them again.
#[allow(clippy::cast_precision_loss)]
pub fn refresh_gauges(state: &AppState, now: Timestamp) {
    refresh_live_gauges(state);
    let expiry = state
        .platform
        .listener
        .load_full()
        .and_then(|listener| listener.status(now).0.certificate)
        .and_then(|certificate| certificate.not_after);
    match expiry {
        Some(not_after) => TLS_EXPIRY.set((not_after.0 - now.0).whole_seconds() as f64),
        None => TLS_EXPIRY.unset(),
    }
}

/// Sets the gauges of this crate that read memory only (the event hub and the store
/// status), without the certificate: what the samples of the `metrics` topic read, once per
/// second while a client listens.
pub fn refresh_live_gauges(state: &AppState) {
    let store = state.store.status();
    let hub = state.events();
    SSE_SUBSCRIBERS.set(as_gauge(
        u64::try_from(hub.subscribers()).unwrap_or(u64::MAX),
    ));
    SSE_EVENTS.set_total(hub.published());
    STORE_REVISION.set(as_gauge(store.revision.get()));
    AUDIT_HEAD.set(as_gauge(store.audit_head.get()));
    STORE_JOURNAL.set(as_gauge(store.journal_len));
    STORE_DATA_BYTES.set(as_gauge(store.data_bytes));
}

#[allow(clippy::cast_precision_loss)]
fn as_gauge(value: u64) -> f64 {
    value as f64
}

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
    Ok(openmetrics_response(render_metrics(&state)))
}

/// A `200` answer with the `OpenMetrics` media type.
pub fn openmetrics_response(text: String) -> Response {
    let mut response = text.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(OPENMETRICS));
    response
}

/// The check of `GET /metrics` (S3-Q7): the read of [`METRICS_OBJECT`].
fn require_metrics_scope(state: &AppState, principal: &Principal) -> Result<(), ApiError> {
    state.authorize(principal, Action::Read, &METRICS_OBJECT)
}

/// The registry's snapshot with the values computed at scrape time (the uptime and the
/// build information): what `GET /metrics` encodes.
pub fn snapshot(state: &AppState) -> Snapshot {
    let mut snapshot = state.platform.metrics.registry().snapshot();
    snapshot.push(&BUILD_INFO, Value::Gauge(1.0));
    snapshot.push(
        &UPTIME,
        Value::Gauge(state.platform.started.elapsed().as_secs_f64()),
    );
    snapshot
}

/// Serves `GET /metrics` in plain HTTP without authentication on `listener` until
/// `shutdown` completes: the loopback listener of `[metrics] listen`. The caller binds a
/// loopback address only; the text is the same as that of `GET /api/v1/metrics`.
///
/// # Errors
///
/// The I/O error that ended the accept loop.
pub async fn serve_plain(
    listener: tokio::net::TcpListener,
    state: AppState,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let router = axum::Router::new()
        .route("/metrics", axum::routing::get(plain_metrics))
        .with_state(state);
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}

async fn plain_metrics(State(state): State<AppState>) -> Response {
    openmetrics_response(render_metrics(&state))
}

/// The metrics text of `GET /metrics` and of the loopback listener of `[metrics] listen`.
pub fn render_metrics(state: &AppState) -> String {
    let mut text = String::with_capacity(16 * 1024);
    encode(&snapshot(state), &mut text);
    text
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::routes::auth::testkit::{
        Credential::{Anonymous, Bearer, Cookie},
        Harness,
    };

    async fn token(h: &Harness, admin: &str, scopes: &[&str]) -> String {
        let created = h
            .call(
                "POST",
                "/auth/tokens",
                Cookie(admin),
                Some(&json!({ "name": "scraper", "scopes": scopes })),
            )
            .await;
        created.assert_status(201);
        created.body["token"].as_str().expect("a token").to_owned()
    }

    #[tokio::test]
    async fn a_token_with_the_metrics_scope_reads_the_text() {
        let (h, admin) = Harness::installed().await;
        let token = token(&h, &admin, &["metrics"]).await;
        let reply = h.call("GET", "/metrics", Bearer(&token), None).await;
        reply.assert_status(200);
        assert_eq!(reply.header("content-type"), Some(OPENMETRICS));
        tenko_core::metrics::check(&reply.text)
            .unwrap_or_else(|error| panic!("{error}\n{}", reply.text));
        assert!(reply.text.contains("# TYPE tenko_build_info gauge\n"));
        assert!(reply.text.contains("\ntenko_build_info 1\n"));
        assert!(reply.text.contains("# UNIT tenko_uptime_seconds seconds\n"));
        assert!(reply.text.ends_with("# EOF\n"));
    }

    #[tokio::test]
    async fn a_token_without_the_metrics_scope_is_refused() {
        let (h, admin) = Harness::installed().await;
        let token = token(&h, &admin, &["audit:read"]).await;
        h.call("GET", "/metrics", Bearer(&token), None)
            .await
            .assert_problem(403, "auth.forbidden");
        h.call("GET", "/metrics", Anonymous, None)
            .await
            .assert_status(401);
    }

    #[tokio::test]
    async fn an_administrators_session_reads_the_text() {
        let (h, admin) = Harness::installed().await;
        let reply = h.call("GET", "/metrics", Cookie(&admin), None).await;
        reply.assert_status(200);
        assert_eq!(reply.header("content-type"), Some(OPENMETRICS));
    }

    #[test]
    fn the_timer_gauges_are_set_by_refresh_and_not_at_scrape() {
        let state = AppState::default();
        let before = render_metrics(&state);
        assert!(!before.contains("\ntenko_store_revision "), "{before}");
        assert!(before.contains("# TYPE tenko_store_revision gauge\n"));
        refresh_gauges(&state, Timestamp::now());
        let after = render_metrics(&state);
        assert!(after.contains("\ntenko_store_revision 0\n"), "{after}");
        assert!(after.contains("\ntenko_sse_subscribers 0\n"));
        assert!(after.contains("\ntenko_sse_events_total 0\n"));
        assert!(after.contains("\ntenko_store_data_bytes 0\n"));
        assert!(after.contains("# UNIT tenko_store_data_bytes bytes\n"));
        // No listener runs, so no certificate expiry.
        assert!(!after.contains("\ntenko_tls_certificate_expiry_seconds "));
    }
}
