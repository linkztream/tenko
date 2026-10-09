//! Health, status, the OpenAPI document and metrics.
//!
//! Area: system. Owner: WP1.7. Requirements: API-01, OPS-05, OPS-19, OPS-22.
//!
//! Liveness, readiness and the OpenAPI document are open. `GET /system/status` needs an
//! authenticated principal with read access to the system. `GET /metrics` needs a token
//! with the `metrics` scope; until scopes exist (WP1.2, Slice 3) any authenticated
//! principal may read it.

use axum::{
    Json,
    extract::State,
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
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

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(health))
        .routes(routes!(ready))
        .routes(routes!(system_status))
        .routes(routes!(openapi_document))
        .routes(routes!(metrics))
}

/// Media type of `GET /metrics`.
pub const OPENMETRICS: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

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
        warnings,
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
