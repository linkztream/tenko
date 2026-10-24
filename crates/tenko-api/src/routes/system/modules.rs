//! The module switch (OPS-25): which product modules the installation runs.
//!
//! Area: system. Owner: WP2.10. The server binary provides the request extension
//! `Arc<dyn ModuleService>`; without it the endpoints answer 503 `modules.unavailable`.
//!
//! | Endpoint | Who | Success | Notable errors |
//! |---|---|---|---|
//! | `GET /system/modules` | any signed-in principal (the UI needs it for every user) | 200 [`ModuleSettings`] | |
//! | `PUT /system/modules` | administer the system | 200 [`ModuleSettings`] | 409 `modules.pinned` |
//!
//! The set applies at start: a disabled module registers no routes and starts nothing. A
//! change is stored, audited and applied by a restart, which the server runs itself through
//! its service manager when it has one (`restart: scheduled`).

use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use futures::future::BoxFuture;
use tenko_core::{Action, CodedError, RequestCtx};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    modules::{ModuleSet, ModuleSettings, ModulesRequest},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The stable code while the server provides no module service.
pub const UNAVAILABLE: &str = "modules.unavailable";

/// What the module endpoints need from the server binary; the routes authorize the action.
pub trait ModuleService: Send + Sync + 'static {
    /// The running and the configured module sets.
    fn settings<'a>(
        &'a self,
        ctx: &'a RequestCtx,
    ) -> BoxFuture<'a, Result<ModuleSettings, CodedError>>;

    /// Stores the installation's choice (audited) and schedules the restart that applies it.
    fn set<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        modules: ModuleSet,
    ) -> BoxFuture<'a, Result<ModuleSettings, CodedError>>;
}

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_modules, put_modules))
}

type Service = Option<Extension<Arc<dyn ModuleService>>>;

fn service(service: Service) -> Result<Arc<dyn ModuleService>, ApiError> {
    service.map(|Extension(service)| service).ok_or_else(|| {
        ApiError::new(
            UNAVAILABLE,
            503,
            "this server does not provide the module switch",
        )
    })
}

/// Reports the modules the server runs and the ones its next start runs. Every signed-in
/// principal may read it: the UI shows only the areas of running modules.
#[utoipa::path(
    get,
    path = "/system/modules",
    tag = "system",
    operation_id = "get_modules",
    summary = "Get the product modules this installation runs",
    responses(
        (status = 200, description = "The running and the configured modules", body = ModuleSettings),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No module service (`modules.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_modules(
    crate::extract::Ctx(ctx): crate::extract::Ctx,
    svc: Service,
) -> Result<Json<ModuleSettings>, ApiError> {
    let svc = service(svc)?;
    Ok(Json(
        svc.settings(&ctx)
            .await
            .map_err(ApiError::from_coded_error)?,
    ))
}

/// Sets what the installation is for: the product modules it runs. The change is audited
/// and applies at the next start; a server under a service manager restarts itself.
#[utoipa::path(
    put,
    path = "/system/modules",
    tag = "system",
    operation_id = "put_modules",
    summary = "Set the product modules this installation runs",
    request_body = ModulesRequest,
    responses(
        (status = 200, description = "Stored; the running and the configured modules", body = ModuleSettings),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "`modules` in tenko.toml decides (`modules.pinned`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No module service (`modules.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn put_modules(
    State(state): State<AppState>,
    crate::extract::Ctx(ctx): crate::extract::Ctx,
    svc: Service,
    Json(request): Json<ModulesRequest>,
) -> Result<Json<ModuleSettings>, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &super::system_object())?;
    let svc = service(svc)?;
    Ok(Json(
        svc.set(&ctx, request.modules)
            .await
            .map_err(ApiError::from_coded_error)?,
    ))
}
