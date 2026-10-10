//! Health, status, the internal CA root, the OpenAPI document and metrics; in-app updates
//! and the module switch in the submodules [`updates`] and [`modules`].
//!
//! Area: system. Owner: WP1.7 (`GET /system/ca-root`: WP1.8b; [`updates`] and [`modules`]:
//! WP2.10).
//! Requirements: API-01, API-10, OPS-05, OPS-19, OPS-22, OPS-24, OPS-25.
//!
//! Liveness, readiness, the CA root and the OpenAPI document are open. `GET /system/status`
//! needs an authenticated principal with read access to the system. `GET /metrics` needs a
//! token with the `metrics` scope; until scopes exist (WP1.2, Slice 3) any authenticated
//! principal may read it.
//!
//! `GET /system/ca-root` answers the root certificate of the internal CA while the listener
//! is in TLS mode a, so that admin clients and the first-run wizard can install it (Q5). The
//! server binary provides it as the request extension `Arc<CaRootSource>`; without it, or
//! in another TLS mode, the answer is 404 `tls.no_internal_ca`.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use tenko_cluster::ca::{TlsMode, TlsService};
use tenko_core::{Action, ObjectKind, ObjectRef, Principal, Timestamp};
use tenko_store::{ReadConsistency, StoreRole};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    dto::system::{Health, NodeStatus, Readiness, StoreSummary, SystemStatus, UiStatus},
    extract::Ctx,
    middleware::metrics::Sample,
    problem::{ApiError, ProblemDetails, codes},
    state::AppState,
};

pub mod modules;
pub mod updates;

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .merge(modules::routes())
        .merge(updates::routes())
        .routes(routes!(health))
        .routes(routes!(ready))
        .routes(routes!(system_status))
        .routes(routes!(get_ca_root))
        .routes(routes!(openapi_document))
        .routes(routes!(metrics))
}

/// Media type of `GET /metrics`.
pub const OPENMETRICS: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Media type of `GET /system/ca-root`.
pub const PEM_FILE: &str = "application/x-pem-file";

/// Stable code of `GET /system/ca-root` when the internal CA does not serve the listener.
pub const NO_INTERNAL_CA: &str = "tls.no_internal_ca";

/// `Cache-Control` of `GET /system/ca-root`: the root changes only when the CA is created
/// again, so clients and proxies may keep it for an hour.
const CA_ROOT_CACHE: &str = "public, max-age=3600";

/// `Content-Disposition` of `GET /system/ca-root`.
const CA_ROOT_FILE: &str = "attachment; filename=\"tenko-ca-root.pem\"";

/// The internal CA root behind `GET /system/ca-root`: the PEM of the root certificate and
/// the TLS service whose mode decides whether it is the root clients need. The server binary
/// adds it as the request extension `Arc<CaRootSource>` when it runs the internal CA. Holds
/// no key material.
#[derive(Debug, Clone)]
pub struct CaRootSource {
    tls: TlsService,
    root_pem: Arc<str>,
    /// SHA-256 of the root certificate, hex, as the server prints it at readiness.
    fingerprint: Arc<str>,
}

impl CaRootSource {
    /// A source for the root `root_pem` (one PEM certificate) of the CA that issues the
    /// certificate of `tls`, with the root's SHA-256 `fingerprint` in hex.
    pub fn new(
        tls: TlsService,
        root_pem: impl Into<Arc<str>>,
        fingerprint: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            tls,
            root_pem: root_pem.into(),
            fingerprint: fingerprint.into(),
        }
    }

    /// The root while the listener is in TLS mode a (internal CA), `None` in the other
    /// modes.
    pub fn current(&self) -> Option<Arc<str>> {
        matches!(self.tls.status().mode, TlsMode::InternalCa).then(|| Arc::clone(&self.root_pem))
    }

    /// The SHA-256 fingerprint of the root (hex) while the listener is in TLS mode a,
    /// `None` in the other modes.
    pub fn fingerprint(&self) -> Option<Arc<str>> {
        matches!(self.tls.status().mode, TlsMode::InternalCa).then(|| Arc::clone(&self.fingerprint))
    }
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "system",
    operation_id = "health",
    summary = "Liveness probe",
    responses(
        (status = 200, description = "The process answers", body = Health)
    )
)]
async fn health() -> Json<Health> {
    Json(Health {
        status: "ok".to_owned(),
        version: crate::version().to_owned(),
    })
}

#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "system",
    operation_id = "ready",
    summary = "Readiness probe",
    responses(
        (status = 200, description = "The node serves requests", body = Readiness),
        (status = 503, description = "Not ready: starting, catching up or shutting down", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn ready(State(state): State<AppState>) -> Result<Json<Readiness>, ApiError> {
    let not_ready = |reason: &str| {
        ApiError::new(
            codes::NOT_READY,
            503,
            format!("the node is not ready: {reason}"),
        )
        .with_param("reason", reason)
    };
    if state.events().is_shutting_down() {
        return Err(not_ready("shutting_down"));
    }
    if !state.is_ready() {
        return Err(not_ready("starting"));
    }
    if state.store.status().role == StoreRole::Shutdown {
        return Err(not_ready("store_stopped"));
    }
    let view = state
        .store
        .read(ReadConsistency::Local)
        .await
        .map_err(|_| not_ready("store_unavailable"))?;
    Ok(Json(Readiness {
        status: "ready".to_owned(),
        revision: view.revision(),
    }))
}

#[utoipa::path(
    get,
    path = "/system/status",
    tag = "system",
    operation_id = "system_status",
    summary = "Get the status of the installation: version, store, certificates and warnings",
    responses(
        (status = 200, description = "Status of this node", body = SystemStatus),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn system_status(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
) -> Result<Json<SystemStatus>, ApiError> {
    state.authorize(&ctx.principal, Action::Read, &system_object())?;
    Ok(Json(status_of(&state, ctx.now)))
}

/// Downloads the root certificate of the internal CA (TLS mode a), for installation on
/// admin clients. Open: the certificate is public.
#[utoipa::path(
    get,
    path = "/system/ca-root",
    tag = "system",
    operation_id = "get_ca_root",
    summary = "Download the root certificate of the internal CA as PEM",
    responses(
        (status = 200, description = "The root certificate of the internal CA", body = String, content_type = "application/x-pem-file",
            headers(
                ("Cache-Control" = String, description = "`public, max-age=3600`"),
                ("Content-Disposition" = String, description = "`attachment; filename=\"tenko-ca-root.pem\"`")
            )),
        (status = 404, description = "The listener does not use the internal CA (`tls.no_internal_ca`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_ca_root(source: Option<Extension<Arc<CaRootSource>>>) -> Result<Response, ApiError> {
    let root = source
        .and_then(|Extension(source)| source.current())
        .ok_or_else(|| {
            ApiError::new(
                NO_INTERNAL_CA,
                404,
                "the server certificate does not come from the internal CA: it is imported or \
                 TLS ends in a reverse proxy, so there is no internal CA root to install",
            )
        })?;
    let mut response = root.to_string().into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(PEM_FILE));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CA_ROOT_CACHE),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static(CA_ROOT_FILE),
    );
    Ok(response)
}

/// The status document of the node.
pub(crate) fn status_of(state: &AppState, now: Timestamp) -> SystemStatus {
    let platform = &state.platform;
    let store = state.store.status();
    let listener = platform.listener.load_full();
    let (tls, mut warnings) = match &listener {
        Some(listener) => {
            let (tls, warnings) = listener.status(now);
            (Some(tls), warnings)
        }
        None => (None, Vec::new()),
    };
    let ui = listener.as_ref().map_or(
        UiStatus {
            stub: crate::ui::UI_STUB,
            from_directory: false,
        },
        |listener| listener.ui(),
    );
    warnings.extend(state.notices_list());
    if ui.stub {
        warnings.push(crate::dto::system::StatusWarning {
            code: "sys.ui.stub".to_owned(),
            detail: "this development build serves a placeholder page instead of the web UI"
                .to_owned(),
            params: std::collections::BTreeMap::new(),
        });
    }
    SystemStatus {
        version: crate::version().to_owned(),
        started_at: platform.started_at,
        uptime_seconds: platform.started.elapsed().as_secs(),
        node: NodeStatus {
            id: platform.node.id,
            roles: platform.node.roles.clone(),
        },
        store: StoreSummary {
            role: serde_json::to_value(store.role)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_default(),
            leader: store.leader,
            revision: store.revision,
            lag: store.lag,
            audit_head: store.audit_head,
            journal_oldest: store.journal_oldest,
            journal_len: store.journal_len,
            data_bytes: store.data_bytes,
            disk_bytes: store.disk_bytes,
        },
        tls,
        ui,
        modules: state.modules(),
        warnings,
        cluster: state.cluster_status(),
    }
}

/// The object of system-wide reads (status, metrics, audit).
pub(crate) fn system_object() -> ObjectRef {
    ObjectRef::new(ObjectKind::System, Uuid::nil())
}

#[utoipa::path(
    get,
    path = "/openapi.json",
    tag = "system",
    operation_id = "openapi_document",
    summary = "Get the OpenAPI document of this API",
    responses(
        (status = 200, description = "The OpenAPI document", body = Object, content_type = "application/json")
    )
)]
async fn openapi_document() -> Json<utoipa::openapi::OpenApi> {
    Json(crate::openapi())
}

#[utoipa::path(
    get,
    path = "/metrics",
    tag = "system",
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

/// The scope check of `GET /metrics`. Token scopes arrive with WP1.2 and Slice 3; until
/// then every authenticated principal that may read the system passes.
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

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{HeaderMap, Request, StatusCode},
    };
    use tenko_cluster::ca::{TlsPolicy, TrustedProxies};
    use tower::ServiceExt as _;

    use super::*;

    const ROOT: &str = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n";

    fn tls(mode: TlsMode) -> TlsService {
        TlsService::new(mode, TlsPolicy::default()).expect("tls service")
    }

    const FINGERPRINT: &str = "4f0c2b7e9a1d6c3b8e5f7a2d9c1b4e6f8a3d5c7e9b1f2a4c6e8d0b3f5a7c9e1";

    #[test]
    fn the_fingerprint_follows_the_tls_mode() {
        let internal = CaRootSource::new(tls(TlsMode::InternalCa), ROOT, FINGERPRINT);
        assert_eq!(internal.fingerprint().as_deref(), Some(FINGERPRINT));
        let proxied = CaRootSource::new(tls(reverse_proxy()), ROOT, FINGERPRINT);
        assert!(proxied.fingerprint().is_none());
    }

    fn reverse_proxy() -> TlsMode {
        TlsMode::ReverseProxy {
            trusted_proxies: TrustedProxies::default(),
            proxy_protocol: false,
            public_host: "ddi.example.org".to_owned(),
        }
    }

    async fn get(source: Option<CaRootSource>) -> (StatusCode, HeaderMap, String) {
        let mut router = crate::router();
        if let Some(source) = source {
            router = router.layer(Extension(Arc::new(source)));
        }
        let request = Request::get("/api/v1/system/ca-root")
            .body(Body::empty())
            .expect("request");
        let response = router.oneshot(request).await.expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (
            status,
            headers,
            String::from_utf8(body.to_vec()).expect("UTF-8"),
        )
    }

    #[tokio::test]
    async fn the_root_is_served_in_internal_ca_mode() {
        let source = CaRootSource::new(tls(TlsMode::InternalCa), ROOT, FINGERPRINT);
        let (status, headers, body) = get(Some(source)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, ROOT);
        assert_eq!(headers[header::CONTENT_TYPE], PEM_FILE);
        assert_eq!(headers[header::CACHE_CONTROL], CA_ROOT_CACHE);
        assert_eq!(headers[header::CONTENT_DISPOSITION], CA_ROOT_FILE);
    }

    #[tokio::test]
    async fn other_modes_answer_no_internal_ca() {
        let source = CaRootSource::new(tls(reverse_proxy()), ROOT, FINGERPRINT);
        let (status, headers, body) = get(Some(source)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
        let problem: serde_json::Value = serde_json::from_str(&body).expect("problem JSON");
        assert_eq!(problem["code"], NO_INTERNAL_CA);
        assert!(!body.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn without_a_source_the_answer_is_no_internal_ca() {
        let (status, _, body) = get(None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let problem: serde_json::Value = serde_json::from_str(&body).expect("problem JSON");
        assert_eq!(problem["code"], NO_INTERNAL_CA);
    }

    #[test]
    fn the_source_follows_a_mode_switch() {
        let service = tls(TlsMode::InternalCa);
        let source = CaRootSource::new(service.clone(), ROOT, FINGERPRINT);
        assert_eq!(source.current().as_deref(), Some(ROOT));
        service.set_mode(reverse_proxy()).expect("switch");
        assert_eq!(source.current(), None);
    }
}
