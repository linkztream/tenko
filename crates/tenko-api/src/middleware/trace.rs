//! The span of an API request (OPS-05): `http.server.request`, the outermost layer of the
//! router, so that it covers the CSRF guard, the rate limits, authentication, the quorum
//! gate and the idempotency replay as well as the handler.
//!
//! - Only API paths are traced; the health routes, `GET /api/v1/metrics` and the web UI
//!   are not.
//! - Every request starts a trace of its own: an incoming `traceparent` is ignored (the
//!   context of a proxy is not trusted in Phase 1) and no trace id goes back to the client.
//! - The attributes follow the OpenTelemetry HTTP conventions: `http.request.method`,
//!   `http.route` (the path template of the request metrics, `other` when no documented
//!   operation matched; never the raw path), `http.response.status_code`, `url.scheme`,
//!   `network.protocol.version`, and `tenko.route_class` (the class label of
//!   `tenko_http_request_duration_seconds`). Nothing from the request or the response (body,
//!   headers, cookies, query) is recorded.
//! - The span ends when the response head leaves the layer; an event stream keeps running
//!   after it.
//!
//! Without a trace layer in the subscriber the span is disabled and the layer only passes
//! the request on.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{Method, Version},
    middleware::Next,
    response::Response,
};
use tracing::{Instrument as _, field::Empty};

use super::{Layers, RouteLabel, is_api_path};
use crate::server::forwarded::{ConnInfo, client_info};

/// Paths that are never traced: the probes and the scrape.
fn traced(method: &Method, path: &str) -> bool {
    if !is_api_path(path) {
        return false;
    }
    let health = path == "/api/v1/health" || path.starts_with("/api/v1/health/");
    let scrape = method == Method::GET && path == "/api/v1/metrics";
    !health && !scrape
}

/// The method as the conventions name it: the standard methods, else `_OTHER`.
fn method_name(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        Method::CONNECT => "CONNECT",
        Method::TRACE => "TRACE",
        _ => "_OTHER",
    }
}

fn protocol_version(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_2 => "2",
        Version::HTTP_3 => "3",
        _ => "1.1",
    }
}

/// The request span around the rest of the stack.
pub(crate) async fn request(
    State(layers): State<Arc<Layers>>,
    request: Request,
    next: Next,
) -> Response {
    if !traced(request.method(), request.uri().path()) {
        return next.run(request).await;
    }
    let method = request.method().clone();
    let span = tracing::info_span!(
        parent: None,
        "http.server.request",
        otel.kind = "server",
        otel.status_code = Empty,
        http.request.method = method_name(&method),
        http.route = Empty,
        http.response.status_code = Empty,
        url.scheme = Empty,
        network.protocol.version = protocol_version(request.version()),
        tenko.route_class = Empty,
    );
    if span.is_disabled() {
        return next.run(request).await;
    }
    let client = client_info(
        request.extensions().get::<ConnInfo>(),
        request.headers(),
        request.uri(),
    );
    span.record("url.scheme", client.scheme());

    let response = next.run(request).instrument(span.clone()).await;

    let row = response
        .extensions()
        .get::<RouteLabel>()
        .map_or_else(|| layers.routes.other_row(&method), |label| label.0);
    let status = response.status().as_u16();
    span.record("http.route", layers.routes.route_of(row));
    span.record("tenko.route_class", layers.routes.class_of_row(row));
    span.record("http.response.status_code", status);
    if status >= 500 {
        span.record("otel.status_code", "error");
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_scrapes_and_the_ui_are_not_traced() {
        assert!(!traced(&Method::GET, "/api/v1/health"));
        assert!(!traced(&Method::GET, "/api/v1/health/ready"));
        assert!(!traced(&Method::GET, "/api/v1/metrics"));
        assert!(!traced(&Method::GET, "/"));
        assert!(!traced(&Method::GET, "/assets/index.js"));
        assert!(traced(&Method::GET, "/api/v1/prefixes"));
        assert!(traced(&Method::POST, "/api/v1/prefixes"));
        assert!(traced(&Method::GET, "/api/v1/events"));
        assert!(traced(&Method::GET, "/api/v1/healthy"));
    }

    #[test]
    fn methods_and_versions_follow_the_conventions() {
        assert_eq!(method_name(&Method::POST), "POST");
        assert_eq!(
            method_name(&Method::from_bytes(b"PURGE").expect("method")),
            "_OTHER"
        );
        assert_eq!(protocol_version(Version::HTTP_11), "1.1");
        assert_eq!(protocol_version(Version::HTTP_2), "2");
    }
}
