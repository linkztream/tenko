//! Key-encryption keys: provider, protection, generations and online rotation (IAM-15).
//!
//! Area: kek. Owner: WP3.4a.
//! Requirements: IAM-15, IAM-16.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /system/kek` | 200 [`KekStatusView`]: this controller's provider, protection, generations and warnings, the protection of every controller and the online rotation in progress or the last one | 401, 403 `auth.forbidden`, 501 |
//! | `POST /system/kek/rotate` | 202 [`KekStatusView`] with the rotation in phase `requested` | 401, 403 (`auth.forbidden`, also for personal tokens; `auth.step_up_required`), 409 `vault.kek.rotation_in_progress`, `sys.store.precondition_failed`, 501, 503 `sys.store.*` |
//!
//! # The service
//!
//! The server adds [`KekAdmin`] of this controller (and the authentication service) as
//! request extensions. Without them both endpoints answer `501` `sys.not_implemented`, so
//! the bare router of the route table test keeps working. Every controller of a cluster
//! serves both endpoints: the status describes the controller that answers (its provider,
//! its protection, the generations it holds) together with what the replicated state says
//! about the installation, and the request of a rotation is a record in the replicated state
//! that the leader picks up.
//!
//! # Authorization
//!
//! Reading the status needs [`Action::Read`] on the system (viewers and operators have it).
//! Requesting a rotation needs [`Action::Administer`] on the system: administrators only.
//!
//! # Step-up
//!
//! A rotation is a destructive operation on the root of the vault, so `POST /system/kek/rotate`
//! needs a fresh session: a sign-in within the last five minutes. An older session is
//! refused with 403 `auth.step_up_required` and the parameter `required` set to `fresh`; the
//! client asks the person to sign in again and repeats the request. A personal API token never
//! administers the system: the authorization refuses it with 403 `auth.forbidden` before the
//! step-up. The step-up check itself also refuses anything but a session (a token, a system
//! component) with 403 `auth.step_up_required`, never with `500` or `401`.
//!
//! # `202 Accepted`
//!
//! The answer to `POST /system/kek/rotate` only says that the request is recorded
//! (`vault.kek.rotate_request` in the audit log). The leader carries the rotation out in the
//! background, in two phases: it creates the new generation and has every reachable
//! controller take it (`distributing`), then activates it and re-wraps every envelope
//! (`rewrapping`) until the rotation is `done` or `failed`. Follow it with `GET /system/kek`
//! (`rotation.phase`) or on the `system` event topic. While a rotation runs, another request
//! is refused with 409 `vault.kek.rotation_in_progress`; a concurrent request that loses the
//! race gets 409 `sys.store.precondition_failed` and may be repeated.
//!
//! # The status in `/system/status`
//!
//! [`summary_of`] gives the server the KEK fragment of `GET /system/status`
//! ([`KekSummaryView`]) and its warnings, from the summary that [`KekAdmin`] caches whenever
//! it sees a change; it does no I/O.

#[cfg(test)]
mod tests;

use std::sync::Arc;

use axum::{Extension, Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use tenko_auth::{AuthError, AuthService};
use tenko_core::{Action, NodeId, Principal, RequestCtx, Timestamp};
use tenko_vault::{
    KekProtection,
    distribution::{
        ControllerProtection, GenerationStatus, KekAdmin, KekStatus, KekSummary, KekWarning,
        RefusedStatus,
    },
    kek_state::{RotationPhase, RotationRecord},
};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{not_implemented, system::system_object};
use crate::{
    dto::system::StatusWarning,
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub use crate::dto::kek::{KekProtectionView, KekRotationPhase, KekSummaryView};

impl From<KekProtection> for KekProtectionView {
    fn from(protection: KekProtection) -> Self {
        Self {
            code: protection.code().to_owned(),
            text: protection.describe().to_owned(),
            weak: protection.is_weak(),
        }
    }
}

/// One key generation of the installation, as this controller sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KekGenerationView {
    /// The identifier that envelopes name.
    pub id: String,
    /// Whether the generation wraps new data keys.
    pub active: bool,
    /// Whether this controller holds the generation.
    pub loaded: bool,
    /// How this controller protects the generation; absent when it does not hold it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<KekProtectionView>,
    /// When the installation first listed the generation; absent for a generation that only
    /// this controller holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<Timestamp>,
}

impl From<&GenerationStatus> for KekGenerationView {
    fn from(generation: &GenerationStatus) -> Self {
        Self {
            id: generation.id.clone(),
            active: generation.active,
            loaded: generation.loaded,
            protection: generation.protection.map(KekProtectionView::from),
            created_at: generation.created_at,
        }
    }
}

/// A plain generation file that this controller refused to load because a sealed generation
/// is older (the protection would silently drop).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RefusedGenerationView {
    /// The generation number in the file name.
    pub generation: u32,
    /// The file name, without its directory.
    pub file: String,
    /// The protection of the file (plain).
    pub protection: KekProtectionView,
}

impl From<&RefusedStatus> for RefusedGenerationView {
    fn from(refused: &RefusedStatus) -> Self {
        Self {
            generation: refused.generation,
            file: refused.file.clone(),
            protection: refused.protection.into(),
        }
    }
}

/// How one controller of the installation protects its key-encryption key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ControllerKekView {
    /// The controller.
    pub node: u64,
    /// Its provider: `dpapi`, `systemd_creds`, `systemd_credential` or `file`.
    pub provider: String,
    /// The protection at its last start.
    pub protection: KekProtectionView,
    /// The strongest protection this controller ever had; a `protection` weaker than this is
    /// a downgrade.
    pub strongest: KekProtectionView,
    /// When the controller last started and recorded this.
    pub updated_at: Timestamp,
}

impl From<&ControllerProtection> for ControllerKekView {
    fn from(controller: &ControllerProtection) -> Self {
        Self {
            node: controller.node.0,
            provider: controller.provider.clone(),
            protection: controller.protection.into(),
            strongest: controller.strongest.into(),
            updated_at: controller.updated_at,
        }
    }
}

impl From<RotationPhase> for KekRotationPhase {
    fn from(phase: RotationPhase) -> Self {
        match phase {
            RotationPhase::Requested => Self::Requested,
            RotationPhase::Distributing => Self::Distributing,
            RotationPhase::Rewrapping => Self::Rewrapping,
            RotationPhase::Done => Self::Done,
            RotationPhase::Failed => Self::Failed,
        }
    }
}

/// An online rotation of the key-encryption key: in progress, or the last one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KekRotationView {
    /// Where the rotation stands.
    pub phase: KekRotationPhase,
    /// When an administrator asked for it.
    pub requested_at: Timestamp,
    /// Who asked, as a principal subject such as `user:<id>`.
    pub requested_by: String,
    /// When the phase last changed.
    pub updated_at: Timestamp,
    /// The new generation, once the leader created it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    /// Reachable controllers that have not taken the new generation yet.
    pub waiting_for: Vec<u64>,
    /// Controllers that could not be reached while the generation was distributed; each
    /// fetches it when it starts.
    pub unreachable: Vec<u64>,
    /// How many envelopes are re-wrapped under the new generation so far.
    pub rewrapped: u64,
    /// Why the rotation failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// When the rotation ended (`done` or `failed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<Timestamp>,
}

impl From<&RotationRecord> for KekRotationView {
    fn from(rotation: &RotationRecord) -> Self {
        let nodes = |nodes: &[NodeId]| nodes.iter().map(|node| node.0).collect();
        Self {
            phase: rotation.phase.into(),
            requested_at: rotation.requested_at,
            requested_by: rotation.requested_by.clone(),
            updated_at: rotation.updated_at,
            generation: rotation.generation.clone(),
            waiting_for: nodes(&rotation.waiting_for),
            unreachable: nodes(&rotation.unreachable),
            rewrapped: rotation.rewrapped,
            error: rotation.error.clone(),
            finished_at: rotation.finished_at,
        }
    }
}

/// The key-encryption keys of this controller and of the installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KekStatusView {
    /// The controller that answers.
    pub node: u64,
    /// Its provider: `dpapi`, `systemd_creds`, `systemd_credential` or `file`.
    pub provider: String,
    /// The protection of its active key-encryption key.
    pub protection: KekProtectionView,
    /// The active generation, which wraps new data keys.
    pub active: String,
    /// The KEK epoch of the active generation; it grows with every activation.
    pub epoch: u64,
    /// Every generation of the installation and every generation loaded here, oldest first.
    pub generations: Vec<KekGenerationView>,
    /// Generations of the installation that this controller does not hold; it fetches them
    /// from a member.
    pub missing: Vec<String>,
    /// Plain generation files that this controller refused to load.
    pub refused: Vec<RefusedGenerationView>,
    /// The strongest protection this controller ever had; absent before its first start was
    /// recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strongest: Option<KekProtectionView>,
    /// How every controller of the installation protects its key, by node.
    pub controllers: Vec<ControllerKekView>,
    /// The online rotation in progress, or the last one; absent when there never was one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<KekRotationView>,
    /// Conditions to look at: `vault.kek.weak`, `vault.kek.downgrade`, `vault.kek.missing`
    /// and `vault.kek.rotation_failed`.
    pub warnings: Vec<StatusWarning>,
}

impl From<&KekStatus> for KekStatusView {
    fn from(status: &KekStatus) -> Self {
        Self {
            node: status.node.0,
            provider: status.provider.clone(),
            protection: status.protection.into(),
            active: status.active.clone(),
            epoch: status.epoch,
            generations: status.generations.iter().map(Into::into).collect(),
            missing: status.missing.clone(),
            refused: status.refused.iter().map(Into::into).collect(),
            strongest: status.strongest.map(Into::into),
            controllers: status.controllers.iter().map(Into::into).collect(),
            rotation: status.rotation.as_ref().map(Into::into),
            warnings: status.warnings.iter().map(warning_of).collect(),
        }
    }
}

impl From<&KekSummary> for KekSummaryView {
    fn from(summary: &KekSummary) -> Self {
        Self {
            provider: summary.provider.clone(),
            protection: summary.protection.into(),
            active: summary.active.clone(),
            generations: u64::try_from(summary.generations).unwrap_or(u64::MAX),
            epoch: summary.epoch,
            rotation: summary.rotation.map(Into::into),
        }
    }
}

/// The status warning of a key-encryption key condition.
fn warning_of(warning: &KekWarning) -> StatusWarning {
    StatusWarning {
        code: warning.code.clone(),
        detail: warning.detail.clone(),
        params: warning.params.clone(),
    }
}

/// The key-encryption key part of `GET /system/status`: the summary of `admin` and its
/// warnings as status warnings. The summary is `None` before the service saw the first
/// state (it refreshes at start and on every change), and the warnings are empty then.
///
/// It reads the summary that the service caches, so it is synchronous and does no I/O:
/// the status endpoint stays cheap whatever the store does.
pub fn summary_of(admin: &KekAdmin) -> (Option<KekSummaryView>, Vec<StatusWarning>) {
    admin.summary().map_or_else(
        || (None, Vec::new()),
        |summary| {
            let warnings = summary.warnings.iter().map(warning_of).collect();
            (Some(KekSummaryView::from(&summary)), warnings)
        },
    )
}

/// The routes of the area: `/system/kek` and `/system/kek/rotate`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_kek_status))
        .routes(routes!(rotate_kek))
}

type Kek = Option<Extension<Arc<KekAdmin>>>;
type Auth = Option<Extension<Arc<AuthService>>>;

/// The service, or the `501` stub answer when the server did not add one.
fn kek_or_stub(kek: Kek, method: &str, path: &str) -> Result<Arc<KekAdmin>, ApiError> {
    kek.map(|Extension(kek)| kek)
        .ok_or_else(|| not_implemented(method, path))
}

fn auth_or_stub(auth: Auth, method: &str, path: &str) -> Result<Arc<AuthService>, ApiError> {
    auth.map(|Extension(auth)| auth)
        .ok_or_else(|| not_implemented(method, path))
}

/// Checks that the request arrived on a session whose sign-in is at most five minutes old.
/// Anything but a session (a personal token, a system component) cannot satisfy a step-up:
/// it is refused with the same `403` as an old session, not with `401`.
async fn require_fresh(auth: &AuthService, ctx: &RequestCtx) -> Result<(), ApiError> {
    if !matches!(ctx.principal, Principal::User { .. }) {
        return Err(AuthError::StepUpRequired { required: "fresh" }.into());
    }
    auth.require_fresh_session(ctx).await?;
    Ok(())
}

/// Shows the key-encryption keys of this controller and of the installation: the provider
/// and how the active key is protected, every generation with the one that is active, the
/// generations this controller lacks or refused, the protection of every controller, the
/// online rotation in progress or the last one, and the conditions to look at. The key
/// material itself is never part of the answer.
#[utoipa::path(
    get,
    path = "/system/kek",
    tag = "kek",
    operation_id = "get_kek_status",
    summary = "Get the key-encryption key status of this controller and the installation",
    responses(
        (status = 200, description = "The key-encryption key status", body = KekStatusView),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "This server has no key-encryption key service (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable (`sys.store.no_quorum`, `sys.store.timeout`, `sys.store.shutting_down`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_kek_status(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    kek: Kek,
) -> Result<Json<KekStatusView>, ApiError> {
    state.authorize(&ctx.principal, Action::Read, &system_object())?;
    let kek = kek_or_stub(kek, "GET", "/system/kek")?;
    let status = kek.status().await?;
    Ok(Json(KekStatusView::from(&status)))
}

/// Starts an online rotation of the key-encryption key. The request is recorded in the
/// replicated state (audited as `vault.kek.rotate_request`) and answers at once; the leader
/// then creates a new generation, has every reachable controller take it, activates it and
/// re-wraps every envelope under it. Follow the rotation with `GET /system/kek`
/// (`rotation.phase`) or on the `system` event topic. Administrators only, and only with a
/// session whose sign-in is at most five minutes old.
#[utoipa::path(
    post,
    path = "/system/kek/rotate",
    tag = "kek",
    operation_id = "rotate_kek",
    summary = "Start an online rotation of the key-encryption key",
    responses(
        (status = 202, description = "The rotation is requested; the status shows it in phase `requested`", body = KekStatusView),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`), or the session was not signed in within the last five minutes (`auth.step_up_required`, parameter `required`: `fresh`); personal tokens are refused with `auth.forbidden`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A rotation is already running (`vault.kek.rotation_in_progress`), or a concurrent request won (`sys.store.precondition_failed`; repeat the request)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "This server has no key-encryption key service (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable (`sys.store.no_quorum`, `sys.store.timeout`, `sys.store.shutting_down`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn rotate_kek(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    kek: Kek,
    auth: Auth,
) -> Result<(StatusCode, Json<KekStatusView>), ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    let kek = kek_or_stub(kek, "POST", "/system/kek/rotate")?;
    let auth = auth_or_stub(auth, "POST", "/system/kek/rotate")?;
    require_fresh(&auth, &ctx).await?;
    let status = kek.request_rotation(&ctx).await?;
    Ok((StatusCode::ACCEPTED, Json(KekStatusView::from(&status))))
}
