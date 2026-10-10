//! The HTTP middleware of the server.
//!
//! Two layers wrap the router:
//!
//! - **Every request** (`outer`): a [`RequestId`] (also sent back as `X-Request-Id`), the
//!   [`ClientInfo`] under the trusted proxy rules, the request counters, and the security
//!   headers of ADR 0008 (`Strict-Transport-Security` on HTTPS responses).
//! - **API routes** (`api`, a route layer, so it sees the matched route template), in
//!   this order: the `Origin` CSRF guard (`csrf`), the per-address rate limit (before
//!   authentication, so it shields the login path), authentication through the
//!   [`Authenticator`](tenko_core::Authenticator) of the state (once per request; the
//!   outcome goes to [`AuthOutcome`] for `Ctx`), the per-principal rate limit, the quorum
//!   gate of an isolated controller (`quorum`, WP3.9; pass-through until then), the
//!   `Idempotency-Key` replay ([`idempotency`]), and `Cache-Control: no-store` on API
//!   responses that set no caching themselves.
//!
//! Refusals are problem details: 403 `sys.csrf_rejected`, 429 `sys.rate_limited` with
//! `Retry-After`, 422 `sys.idempotency_mismatch`, 409 `sys.idempotency_in_flight`, 409
//! `sys.idempotency_not_replayable` (a secret-bearing response is never stored, see
//! [`idempotency`]).

pub(crate) mod csrf;
pub mod headers;
pub mod idempotency;
pub(crate) mod metrics;
pub(crate) mod quorum;
pub mod rate_limit;

use std::{sync::Arc, time::Instant};

use axum::{
    extract::{MatchedPath, Request, State},
    http::{HeaderName, HeaderValue, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tenko_core::{AuthFailure, RequestId, Timestamp};

pub use idempotency::IdempotencyConfig;
pub use rate_limit::{LimitScope, Quota, RateLimitConfig, RateLimiter, RetryAfter};

use crate::{
    extract::{AuthOutcome, ClientInfo, credentials, placeholder_principal},
    problem::{ApiError, codes},
    server::forwarded::{ConnInfo, client_info},
    state::AppState,
};
use metrics::{Event, UI_ROUTE, UNMATCHED_ROUTE};

/// Header that carries the request id back to the client.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Settings of the HTTP middleware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConfig {
    /// Origins accepted by the CSRF guard besides the request's own origin, for example the
    /// public origin behind a proxy or `http://localhost:5173` for `vite dev`.
    pub allowed_origins: Vec<String>,
    /// Rate limits per client address and per principal.
    pub rate_limit: RateLimitConfig,
    /// `Idempotency-Key` replay.
    pub idempotency: IdempotencyConfig,
    /// Send `Strict-Transport-Security` on HTTPS responses (TGL-08: on in every profile
    /// that uses TLS).
    pub hsts: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig::default(),
            idempotency: IdempotencyConfig::default(),
            hsts: true,
        }
    }
}

/// Shared state of the middleware.
pub(crate) struct Layers {
    pub(crate) state: AppState,
    pub(crate) limiter: RateLimiter,
    allowed_origins: Vec<String>,
    idempotency: IdempotencyConfig,
    hsts: bool,
}

impl Layers {
    pub(crate) fn new(state: AppState, config: &HttpConfig) -> Self {
        Self {
            state,
            limiter: RateLimiter::new(config.rate_limit.clone()),
            allowed_origins: config
                .allowed_origins
                .iter()
                .filter_map(|origin| csrf::normalize(origin))
                .collect(),
            idempotency: config.idempotency,
            hsts: config.hsts,
        }
    }
}

/// The route label of an API response, for the request counters.
#[derive(Debug, Clone)]
struct RouteLabel(String);

/// Middleware of every request: request id, client info, counters, security headers.
pub(crate) async fn outer(
    State(layers): State<Arc<Layers>>,
    mut request: Request,
    next: Next,
) -> Response {
    let id = RequestId::generate();
    let client = client_info(
        request.extensions().get::<ConnInfo>(),
        request.headers(),
        request.uri(),
    );
    let method = request.method().clone();
    let api_path = is_api_path(request.uri().path());
    let https = client.https;
    request.extensions_mut().insert(id);
    request.extensions_mut().insert(client);

    let mut response = next.run(request).await;

    let route = match response.extensions().get::<RouteLabel>() {
        Some(RouteLabel(route)) => route.as_str(),
        None if api_path => UNMATCHED_ROUTE,
        None => UI_ROUTE,
    };
    layers
        .state
        .platform
        .metrics
        .request(route, &method, response.status().as_u16());
    headers::apply(response.headers_mut(), https && layers.hsts);
    if let Ok(value) = HeaderValue::from_str(&id.to_string()) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

/// Whether a path belongs to the API (and never falls back to the UI).
pub(crate) fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

/// Middleware of the API routes: CSRF guard, rate limits, authentication, idempotency.
pub(crate) async fn api(
    State(layers): State<Arc<Layers>>,
    mut request: Request,
    next: Next,
) -> Response {
    let route = request.extensions().get::<MatchedPath>().map_or_else(
        || UNMATCHED_ROUTE.to_owned(),
        |path| path.as_str().to_owned(),
    );
    let refusal = match guard(&layers, &mut request).await {
        Some(refusal) => Some(refusal),
        None => quorum::check(&layers.state, &request),
    };
    let mut response = if let Some(refusal) = refusal {
        refusal
    } else {
        let principal = match &layers.state.auth {
            None => Some(placeholder_principal()),
            Some(_) => request
                .extensions()
                .get::<AuthOutcome>()
                .and_then(AuthOutcome::principal)
                .cloned(),
        };
        let state = &layers.state;
        idempotency::handle(
            state.store.as_ref(),
            &state.platform.in_flight,
            layers.idempotency,
            principal.as_ref(),
            request,
            |request| next.run(request),
        )
        .await
    };
    response.extensions_mut().insert(RouteLabel(route));
    response
        .headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

/// The checks before the handler: CSRF guard, address limit, authentication, principal
/// limit. Returns the refusal, if any; stores the authentication outcome in the request.
async fn guard(layers: &Layers, request: &mut Request) -> Option<Response> {
    let client = request
        .extensions()
        .get::<ClientInfo>()
        .cloned()
        .unwrap_or_default();
    let metrics = &layers.state.platform.metrics;

    if let Err(refusal) = csrf::check(
        request.method(),
        request.headers(),
        &client,
        &layers.allowed_origins,
    ) {
        metrics.count(Event::CsrfRejected);
        let detail = match refusal {
            csrf::Refusal::ForeignOrigin => {
                "the Origin of this state-changing request is not this server's origin"
            }
            csrf::Refusal::MissingOrigin => {
                "a state-changing browser request must carry an Origin header"
            }
        };
        return Some(ApiError::new(codes::CSRF_REJECTED, 403, detail).into_response());
    }

    if let Some(ip) = client.source_ip
        && let Err(retry) = layers.limiter.check_ip(ip, Instant::now())
    {
        metrics.count(Event::RateLimitedIp);
        return Some(too_many_requests(retry, LimitScope::Ip));
    }

    let Some(authenticator) = &layers.state.auth else {
        return None;
    };
    let credentials = credentials(request.headers());
    let outcome = if credentials.is_present() {
        authenticator
            .authenticate(&credentials, client.source_ip, Timestamp::now())
            .await
    } else {
        Err(AuthFailure::Missing)
    };
    let principal = outcome
        .as_ref()
        .ok()
        .map(|authenticated| authenticated.principal.subject());
    request.extensions_mut().insert(AuthOutcome(outcome));

    if let Some(subject) = principal
        && let Err(retry) = layers.limiter.check_principal(&subject, Instant::now())
    {
        metrics.count(Event::RateLimitedPrincipal);
        return Some(too_many_requests(retry, LimitScope::Principal));
    }
    None
}

/// 429 `sys.rate_limited` with `Retry-After`.
pub(crate) fn too_many_requests(retry: RetryAfter, scope: LimitScope) -> Response {
    let seconds = retry.seconds();
    let mut response = ApiError::new(
        codes::RATE_LIMITED,
        429,
        format!("too many requests; retry in {seconds} s"),
    )
    .with_param("scope", scope.as_str())
    .with_param("retry_after", seconds.to_string())
    .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
    response
}
