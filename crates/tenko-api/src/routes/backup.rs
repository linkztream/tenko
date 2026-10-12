//! Backups: create a backup into the target directory, the backup status and the schedule (OPS-07).
//!
//! Area: backup. Owner: WP3.4b.
//! Requirements: OPS-07. Decision: ADR 0016.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /system/backups` | 200 [`BackupStatusView`]: the settings, the last good and failed backups, the recent backups, the restore notice and the warnings | 401, 403, 501, 503 |
//! | `POST /system/backups` | 201 [`BackupRunView`] of the backup written | 401, 403 (`auth.forbidden`, `auth.step_up_required`), 409 `backup.running`, 422 `backup.key.missing`, `backup.passphrase.weak`, `backup.key.invalid`, 500 `backup.io`, 501, 503 |
//! | `PUT /system/backups/settings` | 200 [`BackupSettingsView`] | 400, 401, 403 (`auth.forbidden`, `auth.step_up_required`), 409 `sys.store.precondition_failed`, 422 `backup.settings.invalid`, `backup.key.invalid`, 501, 503 |
//!
//! # The service
//!
//! The server adds its [`BackupService`] as a request extension. Without it every endpoint
//! answers `501` `sys.not_implemented`, so the bare router of the route table test keeps
//! working.
//!
//! # Authorization and step-up
//!
//! Reading the status needs [`Action::Read`] on the system. Writing a backup and changing
//! the settings need [`Action::Administer`] on the system and a session whose sign-in is at
//! most five minutes old (403 `auth.step_up_required`, parameter `required`: `fresh`): a
//! backup is a copy of every secret (R36), and the settings decide whom backups are
//! encrypted to. A personal API token never administers the system.
//!
//! # Writing a backup
//!
//! `POST /system/backups` writes a backup into the target directory of the controller that
//! answers and returns when the file is complete. It is encrypted to the configured
//! recipient and, when the body carries one, to a passphrase as well; without either it is
//! refused with 422 `backup.key.missing`. It is recorded as the inline job `backup.create`
//! and audited as `sys.backup.create`. Phase 1 offers no download (owner decision S3-Q11):
//! the file stays on the controller.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures::future::BoxFuture;
use tenko_auth::{AuthError, AuthService};
use tenko_core::{Action, CodedError, Principal, RequestCtx, Revision};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    common::{if_match, with_etag},
    not_implemented,
    system::system_object,
};
pub use crate::dto::backup::{
    BackupCreateRequest, BackupFailure, BackupOutcome, BackupReason, BackupRunView,
    BackupSettingsUpdate, BackupSettingsView, BackupStatusView, BackupSummaryView,
    RestoreNoticeView,
};
use crate::{
    dto::system::StatusWarning,
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// What the backup endpoints need from the server binary; the routes authorize the action
/// and check the step-up.
pub trait BackupService: Send + Sync + 'static {
    /// The status as the controller that answers sees it.
    fn status<'a>(
        &'a self,
        ctx: &'a RequestCtx,
    ) -> BoxFuture<'a, Result<BackupStatusView, CodedError>>;

    /// Writes a backup now, wrapped to the configured recipient and to `passphrase` when
    /// given; records and audits it.
    fn create<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        passphrase: Option<String>,
    ) -> BoxFuture<'a, Result<BackupRunView, CodedError>>;

    /// Replaces the settings (audited), if they are still at `expect`.
    fn update_settings<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        update: BackupSettingsUpdate,
        expect: Option<Revision>,
    ) -> BoxFuture<'a, Result<BackupSettingsView, CodedError>>;

    /// The fragment of `GET /system/status` and its warnings.
    fn summary(&self) -> BoxFuture<'_, (Option<BackupSummaryView>, Vec<StatusWarning>)>;
}

/// The routes of the area: `/system/backups` and `/system/backups/settings`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_backups, create_backup))
        .routes(routes!(update_backup_settings))
}

type Service = Option<Extension<Arc<dyn BackupService>>>;
type Auth = Option<Extension<Arc<AuthService>>>;

fn service(service: Service, method: &str, path: &str) -> Result<Arc<dyn BackupService>, ApiError> {
    service
        .map(|Extension(service)| service)
        .ok_or_else(|| not_implemented(method, path))
}

/// Checks that the request arrived on a session whose sign-in is at most five minutes old.
async fn require_fresh(
    auth: Auth,
    ctx: &RequestCtx,
    method: &str,
    path: &str,
) -> Result<(), ApiError> {
    let auth = auth
        .map(|Extension(auth)| auth)
        .ok_or_else(|| not_implemented(method, path))?;
    if !matches!(ctx.principal, Principal::User { .. }) {
        return Err(AuthError::StepUpRequired { required: "fresh" }.into());
    }
    auth.require_fresh_session(ctx).await?;
    Ok(())
}

/// The backup fragment of `GET /system/status`, when the server has a backup service.
pub async fn summary_of(
    service: Option<&Arc<dyn BackupService>>,
) -> (Option<BackupSummaryView>, Vec<StatusWarning>) {
    match service {
        Some(service) => service.summary().await,
        None => (None, Vec::new()),
    }
}

/// Shows the backup settings, the last good and the last failed backup with the age of the
/// good one, the recent backups of every controller, the restore this installation started
/// from and the conditions to look at.
#[utoipa::path(
    get,
    path = "/system/backups",
    tag = "backup",
    operation_id = "get_backups",
    summary = "Get the backup status and settings",
    responses(
        (status = 200, description = "The backup status", body = BackupStatusView,
            headers(("ETag" = String, description = "The revision of the settings, for `If-Match` of `PUT /system/backups/settings`"))),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "This server has no backup service (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable (`sys.store.no_quorum`, `sys.store.timeout`, `sys.store.shutting_down`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_backups(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    svc: Service,
) -> Result<Response, ApiError> {
    state.authorize(&ctx.principal, Action::Read, &system_object())?;
    let svc = service(svc, "GET", "/system/backups")?;
    let status = svc.status(&ctx).await.map_err(ApiError::from_coded_error)?;
    let revision = status.settings.revision;
    let response = Json(status).into_response();
    Ok(match revision {
        Some(revision) => with_etag(response, revision),
        None => response,
    })
}

/// Writes a backup of the installation into the target directory of the controller that
/// answers, encrypted to the configured recipient and, when the body carries one, to a
/// passphrase. Returns when the file is complete; recorded as the inline job
/// `backup.create` and audited as `sys.backup.create`. Administrators only, with a session
/// whose sign-in is at most five minutes old. The file is not downloadable through the API.
#[utoipa::path(
    post,
    path = "/system/backups",
    tag = "backup",
    operation_id = "create_backup",
    summary = "Write a backup now",
    request_body = BackupCreateRequest,
    responses(
        (status = 201, description = "The backup is written", body = BackupRunView),
        (status = 400, description = "The body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`), or the session was not signed in within the last five minutes (`auth.step_up_required`, parameter `required`: `fresh`); personal tokens are refused with `auth.forbidden`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A backup is running on this controller (`backup.running`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "No recipient is configured and no passphrase given (`backup.key.missing`), the passphrase is shorter than 12 characters (`backup.passphrase.weak`, parameter `min`), or the configured recipient is invalid (`backup.key.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 500, description = "The backup could not be written (`backup.io`, `backup.internal`); the failure is recorded", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "This server has no backup service (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable (`sys.store.no_quorum`, `sys.store.timeout`, `sys.store.shutting_down`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn create_backup(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    svc: Service,
    auth: Auth,
    Json(request): Json<BackupCreateRequest>,
) -> Result<(StatusCode, Json<BackupRunView>), ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    let svc = service(svc, "POST", "/system/backups")?;
    require_fresh(auth, &ctx, "POST", "/system/backups").await?;
    let run = svc
        .create(&ctx, request.passphrase)
        .await
        .map_err(ApiError::from_coded_error)?;
    Ok((StatusCode::CREATED, Json(run)))
}

/// Replaces the backup settings of the installation: the schedule, how many files it keeps,
/// the target directory, the recipient key and whether backups include the configuration.
/// Audited as `sys.backup.settings`. Administrators only, with a session whose sign-in is at
/// most five minutes old.
#[utoipa::path(
    put,
    path = "/system/backups/settings",
    tag = "backup",
    operation_id = "update_backup_settings",
    summary = "Change the backup schedule, target and recipient",
    params(("If-Match" = Option<String>, Header, description = "The revision the client read, as in the `ETag` of `GET /system/backups`; a stale revision is refused with 409")),
    request_body = BackupSettingsUpdate,
    responses(
        (status = 200, description = "The settings now in force", body = BackupSettingsView,
            headers(("ETag" = String, description = "The new revision of the settings"))),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or `If-Match` is malformed (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`), or the session was not signed in within the last five minutes (`auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "`If-Match` is stale or a concurrent change won (`sys.store.precondition_failed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "A value is out of range or the target directory is not absolute (`backup.settings.invalid`), the schedule is turned on without a recipient (`backup.key.missing`), or the recipient does not parse (`backup.key.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "This server has no backup service (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable (`sys.store.no_quorum`, `sys.store.timeout`, `sys.store.shutting_down`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn update_backup_settings(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    svc: Service,
    auth: Auth,
    headers: HeaderMap,
    Json(update): Json<BackupSettingsUpdate>,
) -> Result<Response, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    let svc = service(svc, "PUT", "/system/backups/settings")?;
    require_fresh(auth, &ctx, "PUT", "/system/backups/settings").await?;
    let expect = if_match(&headers)?;
    let settings = svc
        .update_settings(&ctx, update, expect)
        .await
        .map_err(ApiError::from_coded_error)?;
    let revision = settings.revision;
    let response = Json(settings).into_response();
    Ok(match revision {
        Some(revision) => with_etag(response, revision),
        None => response,
    })
}

#[cfg(test)]
mod tests;
