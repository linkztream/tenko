//! In-app updates (OPS-24, TGL-23, R17): the update notice with release notes, the
//! what's-new notes after an upgrade, and installation from the UI.
//!
//! Area: system. Owner: WP2.10. The server binary provides the request extension
//! `Arc<dyn UpdateService>`; without it every endpoint answers 503 `update.unavailable`.
//!
//! | Endpoint | Who | Success | Notable errors |
//! |---|---|---|---|
//! | `GET /system/updates` | read on the system | 200 [`UpdateStatus`] | |
//! | `POST /system/updates/check` | administer the system | 200 [`UpdateStatus`] after asking the source | 409 `update.check_off`, 502 `update.fetch_failed` |
//! | `PUT /system/updates/manifest` | administer the system | 200 [`UpdateStatus`] | 400 `update.manifest.*` |
//! | `POST /system/updates/install` | administer, step-up per TGL-23 | 202 [`InstallStarted`] | 403 `auth.step_up_required`, 409 `update.install_blocked`, `update.backup_required`, 422 `backup.key.missing` |
//! | `POST /system/updates/upload?version=&backup=` | administer, step-up per TGL-23 | 202 [`InstallStarted`] | 400 `update.checksum_mismatch`, 409 `update.install_blocked`, `update.backup_required`, 422 `backup.key.missing` |
//! | `GET /system/updates/whats-new` | any signed-in user | 200 [`WhatsNew`] | |
//! | `POST /system/updates/whats-new/seen` | any signed-in user | 204 | |
//!
//! Before an install the request answers whether to take a backup first (ADR 0023):
//! `backup: "run"` makes the job's first step a backup, `"skip"` installs without one and
//! is audited, and without the field the install starts only while a good backup is younger
//! than an hour (`install.backup` of the status says how old the newest one is); otherwise
//! it is refused with 409 `update.backup_required`. The Hardened profile refuses `"skip"`
//! (TGL-37).
//!
//! An install is a background job: download (or the uploaded file), SHA-256 verification
//! against the manifest, a dry run of `tenko upgrade check` by the new binary against a copy
//! of the store, and the switch of the `current` link. When the job succeeds the server
//! restarts into the new version; a version that does not become ready in time is switched
//! back. Uploads stream to disk and are sent without `Idempotency-Key`.

use std::sync::Arc;

use axum::{
    Extension, Json,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Query, State},
    http::StatusCode,
};
use futures::{StreamExt as _, TryStreamExt as _, future::BoxFuture, stream::BoxStream};
use tenko_core::{Action, CodedError, RequestCtx};
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt as _},
    routes,
};

use crate::{
    dto::{
        release::ReleaseManifest,
        updates::{InstallRequest, InstallStarted, UpdateStatus, UploadQuery, WhatsNew},
    },
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The stable code of every update endpoint while the server provides no update service.
pub const UNAVAILABLE: &str = "update.unavailable";

/// The body of an uploaded release file, streamed.
pub type UploadBody = BoxStream<'static, Result<Bytes, std::io::Error>>;

/// What the update endpoints need from the server binary. Authorization of the action on
/// the system is done by the routes; the service enforces TGL-23 (policy and step-up) and
/// everything about the installation.
pub trait UpdateService: Send + Sync + 'static {
    /// The update status.
    fn status<'a>(&'a self, ctx: &'a RequestCtx)
    -> BoxFuture<'a, Result<UpdateStatus, CodedError>>;

    /// Asks the release source now and returns the status afterwards.
    fn check_now<'a>(
        &'a self,
        ctx: &'a RequestCtx,
    ) -> BoxFuture<'a, Result<UpdateStatus, CodedError>>;

    /// Stores an uploaded release manifest (air-gapped installations).
    fn put_manifest<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        manifest: ReleaseManifest,
    ) -> BoxFuture<'a, Result<UpdateStatus, CodedError>>;

    /// Starts the install job of a version from the release source, after the rule of the
    /// backup before an update (`request.backup`).
    fn install<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        request: InstallRequest,
    ) -> BoxFuture<'a, Result<InstallStarted, CodedError>>;

    /// Stores an uploaded release file of `query.version` and starts its install job, after
    /// the rule of the backup before an update (`query.backup`), which is checked before the
    /// body is read.
    fn upload<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        query: UploadQuery,
        body: UploadBody,
    ) -> BoxFuture<'a, Result<InstallStarted, CodedError>>;

    /// The notes to show the user of `ctx` after an upgrade.
    fn whats_new<'a>(&'a self, ctx: &'a RequestCtx) -> BoxFuture<'a, Result<WhatsNew, CodedError>>;

    /// Records that the user of `ctx` has seen the notes of the running version.
    fn mark_seen<'a>(&'a self, ctx: &'a RequestCtx) -> BoxFuture<'a, Result<(), CodedError>>;
}

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_updates))
        .routes(routes!(check_updates))
        .routes(routes!(put_update_manifest))
        .routes(routes!(install_update))
        .routes(routes!(upload_update).layer(DefaultBodyLimit::disable()))
        .routes(routes!(get_whats_new))
        .routes(routes!(mark_whats_new_seen))
}

type Service = Option<Extension<Arc<dyn UpdateService>>>;

fn service(service: Service) -> Result<Arc<dyn UpdateService>, ApiError> {
    service.map(|Extension(service)| service).ok_or_else(|| {
        ApiError::new(
            UNAVAILABLE,
            503,
            "this server does not provide in-app updates",
        )
    })
}

fn coded(error: CodedError) -> ApiError {
    ApiError::from_coded_error(error)
}

/// Reports the running version, the newest known release and the notes of every release in
/// between, and whether this installation can install it from the UI or why not.
#[utoipa::path(
    get,
    path = "/system/updates",
    tag = "system",
    operation_id = "get_updates",
    summary = "Get the update status: newer releases with their notes and how to install them",
    responses(
        (status = 200, description = "The update status", body = UpdateStatus),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No update service (`update.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_updates(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    svc: Service,
) -> Result<Json<UpdateStatus>, ApiError> {
    state.authorize(&ctx.principal, Action::Read, &super::system_object())?;
    let svc = service(svc)?;
    Ok(Json(svc.status(&ctx).await.map_err(coded)?))
}

/// Asks the release source now instead of waiting for the schedule. Only the running version
/// is sent.
#[utoipa::path(
    post,
    path = "/system/updates/check",
    tag = "system",
    operation_id = "check_updates",
    summary = "Ask the release source for new versions now",
    responses(
        (status = 200, description = "The update status after the check", body = UpdateStatus),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The check is off: air-gapped or switched off in the settings (`update.check_off`, parameter `reason`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 502, description = "The release source did not answer with a valid manifest (`update.fetch_failed`, `update.manifest.*`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No update service (`update.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn check_updates(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    svc: Service,
) -> Result<Json<UpdateStatus>, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &super::system_object())?;
    let svc = service(svc)?;
    Ok(Json(svc.check_now(&ctx).await.map_err(coded)?))
}

/// Stores a release manifest (`releases.json`) uploaded by an administrator, for
/// installations that never contact the release source. It replaces the stored manifest.
#[utoipa::path(
    put,
    path = "/system/updates/manifest",
    tag = "system",
    operation_id = "put_update_manifest",
    summary = "Upload a release manifest (air-gapped installations)",
    request_body(content = ReleaseManifest, description = "The release manifest, at most 1 MiB", content_type = "application/json"),
    responses(
        (status = 200, description = "The manifest is stored; the update status", body = UpdateStatus),
        (status = 400, description = "The manifest is invalid (`update.manifest.json`, `update.manifest.invalid`, `update.manifest.schema`, `update.manifest.project`, `update.manifest.too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No update service (`update.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn put_update_manifest(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    svc: Service,
    body: Bytes,
) -> Result<Json<UpdateStatus>, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &super::system_object())?;
    let svc = service(svc)?;
    let manifest = ReleaseManifest::parse(&body)
        .map_err(|error| ApiError::new(error.code(), 400, error.to_string()))?;
    Ok(Json(svc.put_manifest(&ctx, manifest).await.map_err(coded)?))
}

/// Starts installing a version from the release source: a background job downloads the file
/// for this platform, verifies its SHA-256 against the manifest, lets the new binary dry-run
/// its migrations against a copy of the store and switches the `current` link; the server
/// then restarts into the new version and switches back if it does not become ready.
#[utoipa::path(
    post,
    path = "/system/updates/install",
    tag = "system",
    operation_id = "install_update",
    summary = "Install a newer version from the release source",
    request_body = InstallRequest,
    responses(
        (status = 202, description = "The install job started; follow it on the `jobs` topic", body = InstallStarted),
        (status = 400, description = "The version is not in the manifest or not newer (`update.version_unknown`, `update.not_newer`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed, or a fresh authentication is needed (`auth.forbidden`, `auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "This installation cannot install from the UI now (`update.install_blocked`, parameter `reason`: an `InstallBlock`), or a backup must be taken first (`update.backup_required`, parameters `max_age_seconds`, `age_seconds` of the newest good backup when there is one, and `skip_allowed`: `false` when the profile refused `backup: \"skip\"`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "`backup: \"run\"` without a configured backup recipient (`backup.key.missing`): take the backup with a passphrase through `POST /system/backups` first", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No update service (`update.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn install_update(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    svc: Service,
    Json(request): Json<InstallRequest>,
) -> Result<(StatusCode, Json<InstallStarted>), ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &super::system_object())?;
    let svc = service(svc)?;
    let started = svc.install(&ctx, request).await.map_err(coded)?;
    Ok((StatusCode::ACCEPTED, Json(started)))
}

/// Installs an uploaded release file (the executable for this platform, as published with
/// the release). The manifest must list the version with a file for this platform; the
/// upload must match its size and SHA-256. Then the same job runs as for an install from the
/// source. Send it without `Idempotency-Key`.
#[utoipa::path(
    post,
    path = "/system/updates/upload",
    tag = "system",
    operation_id = "upload_update",
    summary = "Install an uploaded release file",
    params(UploadQuery),
    request_body(content = Vec<u8>, description = "The release file for this platform", content_type = "application/octet-stream"),
    responses(
        (status = 202, description = "The file is stored and verified; the install job started", body = InstallStarted),
        (status = 400, description = "The file does not match the manifest (`update.checksum_mismatch`, `update.size_mismatch`), or the version is unknown (`update.version_unknown`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed, or a fresh authentication is needed (`auth.forbidden`, `auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "This installation cannot install now (`update.install_blocked`, parameter `reason`), or a backup must be taken first (`update.backup_required`, as for `POST /system/updates/install`); both are answered before the body is read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "`backup=run` without a configured backup recipient (`backup.key.missing`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "The file is larger than the manifest says (`update.size_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No update service (`update.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn upload_update(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    svc: Service,
    Query(query): Query<UploadQuery>,
    body: Body,
) -> Result<(StatusCode, Json<InstallStarted>), ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &super::system_object())?;
    let svc = service(svc)?;
    let stream = body
        .into_data_stream()
        .map_err(std::io::Error::other)
        .boxed();
    let started = svc.upload(&ctx, query, stream).await.map_err(coded)?;
    Ok((StatusCode::ACCEPTED, Json(started)))
}

/// The release notes to show the signed-in user once after an upgrade: the releases after the
/// version whose notes the user saw last, up to the running one.
#[utoipa::path(
    get,
    path = "/system/updates/whats-new",
    tag = "system",
    operation_id = "get_whats_new",
    summary = "Get the notes to show this user after an upgrade",
    responses(
        (status = 200, description = "The notes and whether to show them", body = WhatsNew),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No update service (`update.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_whats_new(Ctx(ctx): Ctx, svc: Service) -> Result<Json<WhatsNew>, ApiError> {
    let svc = service(svc)?;
    Ok(Json(svc.whats_new(&ctx).await.map_err(coded)?))
}

/// Records that the signed-in user has seen the notes of the running version.
#[utoipa::path(
    post,
    path = "/system/updates/whats-new/seen",
    tag = "system",
    operation_id = "mark_whats_new_seen",
    summary = "Mark the notes of the running version as seen by this user",
    responses(
        (status = 204, description = "Recorded"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No update service (`update.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn mark_whats_new_seen(Ctx(ctx): Ctx, svc: Service) -> Result<StatusCode, ApiError> {
    let svc = service(svc)?;
    svc.mark_seen(&ctx).await.map_err(coded)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::to_bytes,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt as _;

    use super::*;

    #[tokio::test]
    async fn without_a_service_the_endpoints_answer_unavailable() {
        for (method, path) in [
            ("GET", "/api/v1/system/updates"),
            ("GET", "/api/v1/system/updates/whats-new"),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .expect("request");
            let response = crate::router().oneshot(request).await.expect("response");
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
            let body = to_bytes(response.into_body(), 64 * 1024)
                .await
                .expect("body");
            let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem");
            assert_eq!(problem["code"], UNAVAILABLE, "{path}");
        }
    }

    #[test]
    fn every_update_path_is_documented() {
        let document = crate::openapi();
        for path in [
            "/api/v1/system/updates",
            "/api/v1/system/updates/check",
            "/api/v1/system/updates/manifest",
            "/api/v1/system/updates/install",
            "/api/v1/system/updates/upload",
            "/api/v1/system/updates/whats-new",
            "/api/v1/system/updates/whats-new/seen",
        ] {
            assert!(document.paths.paths.contains_key(path), "{path}");
        }
    }
}
