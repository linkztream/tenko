//! Mirrored sources and takeovers (`docs/plans/windows-takeover-plan.md` section 3.2, ADR
//! 0033 and ADR 0034; MIG-01, MIG-04, MIG-08).
//!
//! Area: migrate. Owner: WP14.0 (the contracts); the operations are built by WP14.1 (the
//! mirrors, the push, the losses, the diff) and WP14.2 (the prepare, the takeover and the
//! revert). Every operation is declared with its request and answer types so that the
//! OpenAPI document, the typed client of the UI and the CLI have them; until its package
//! builds it, each operation checks the caller's right and answers `501` with
//! `sys.not_implemented`. The routes belong to the DHCP module (OPS-25): a server without
//! it registers none of them.
//!
//! | Endpoint | Right | Purpose |
//! |---|---|---|
//! | `PUT /migrate/mirrors/{id}/snapshot` | the mirror's own token (`mirror:<id>`) | Push a snapshot |
//! | `GET /migrate/mirrors` | `migrate.read` | List mirrors |
//! | `POST /migrate/mirrors` | `migrate.write`, a session | Create a mirror, its service account and its token |
//! | `GET /migrate/mirrors/{id}` | `migrate.read` | Get a mirror |
//! | `PATCH /migrate/mirrors/{id}` | `migrate.write`, a session | Change a mirror |
//! | `DELETE /migrate/mirrors/{id}` | `migrate.write`, a session | Delete a mirror with its account and token |
//! | `POST /migrate/mirrors/{id}/token` | an administrator's session | Replace the token; shown once |
//! | `GET /migrate/mirrors/{id}/snapshot` | `migrate.read` | The latest snapshot as stored |
//! | `GET /migrate/mirrors/{id}/losses` | `migrate.read` | The loss report with the acknowledgments |
//! | `POST /migrate/mirrors/{id}/losses/ack` | `migrate.write`, a session | Acknowledge loss entries |
//! | `GET /migrate/mirrors/{id}/scopes/{cidr}/diff` | `migrate.read` | The diff of a mirrored scope against Tenko's |
//! | `POST /migrate/mirrors/{id}/scopes/{cidr}/prepare` | `migrate.write`, a session | Start the prepare job |
//! | `POST /migrate/mirrors/{id}/scopes/{cidr}/takeover` | `migrate.write`, a session | Start the takeover job |
//! | `POST /migrate/mirrors/{id}/scopes/{cidr}/revert` | `migrate.write`, a session | Start the revert job |
//! | `GET /migrate/takeovers` | `migrate.read` | List takeover records |
//! | `GET /migrate/takeovers/{id}` | `migrate.read` | Get a takeover record |
//!
//! `{cidr}` is the scope's network with its length in one path segment, the slash
//! percent-encoded (`192.0.2.0%2F24`).
//!
//! # Authorization
//!
//! The scopes are `migrate.read` (administrators and operators) and `migrate.write`
//! (administrators) of `tenko_core::migrate::MigrateScope`. Creating, changing and deleting
//! a mirror, replacing its token, acknowledging losses and starting the three scope jobs
//! are interactive: a personal token is refused (`tenko_auth::roles::interactive_only`
//! covers the kinds `mirror` and `takeover`), so those operations declare
//! `security(("session" = []))`. The push authorizes `Action::Execute` on the mirror, the
//! one action the mirror's own token reaches; it is the only operation of the API such a
//! token reaches (plan section 2.1, rule 2; `ad.mirror_token` of WP14.4 proves it).

use std::net::IpAddr;

use axum::{
    extract::{DefaultBodyLimit, Path, State},
    response::Response,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, CodedError, JobId, MirrorId, ObjectKind, Revision, TakeoverId, Timestamp, UserId,
    error::codes,
    ir::{LossEntry, MirrorSnapshot, SourceKindLabel},
    migrate::{
        LossAck, Mirror, SkippedItem, TakeoverCounts, TakeoverState, mirror_object, takeover_object,
    },
    serde_util::HexBytes,
};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt},
    routes,
};

use super::not_implemented;
use crate::{
    dto::Page,
    extract::Ctx,
    list::PageParams,
    problem::{ApiError, ProblemDetails},
    routes::auth::ApiJson,
    state::AppState,
};

// ---------------------------------------------------------------------------------------
// Types

/// A mirrored source with its freshness (plan section 2.4): the row and what the card shows.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MirrorItem {
    /// The row.
    #[serde(flatten)]
    pub mirror: Mirror,
    /// Seconds since the last accepted push; none before the first push.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<u64>,
    /// Whether the mirror is stale: no push for three intervals.
    pub stale: bool,
    /// When the mirror's token expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires_at: Option<Timestamp>,
    /// The counts of the latest snapshot: scopes, reservations, leases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<SnapshotCounts>,
    /// The server the latest snapshot names and the adapter's version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<tenko_core::ir::MirrorOrigin>,
    /// How many loss entries of the latest snapshot are not acknowledged.
    pub losses_open: u32,
}

/// What the latest snapshot of a mirror holds, in numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SnapshotCounts {
    /// Scopes.
    pub scopes: u32,
    /// Reservations over every scope.
    pub reservations: u32,
    /// Leases.
    pub leases: u32,
    /// Loss entries.
    pub losses: u32,
}

/// `POST /migrate/mirrors`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MirrorCreate {
    /// The name, unique among mirrors; the service account is `mirror-<name>`.
    pub name: String,
    /// The kind of source (`windows-dhcp`).
    pub kind: SourceKindLabel,
    /// The expected interval between pushes, in seconds; 60 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_secs: Option<u32>,
    /// The token's lifetime in days; the TGL-05 maximum when absent (WT-Q11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires_in_days: Option<u32>,
}

/// `PATCH /migrate/mirrors/{id}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct MirrorPatch {
    /// A new name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether pushes are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// The expected interval between pushes, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_secs: Option<u32>,
}

/// `POST /migrate/mirrors/{id}/token`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct MirrorTokenRequest {
    /// The token's lifetime in days; the TGL-05 maximum when absent (WT-Q11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<u32>,
}

/// A mirror with the token the exporter needs, shown once (`POST /migrate/mirrors`,
/// `POST /migrate/mirrors/{id}/token`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MirrorCreated {
    /// The mirror.
    pub mirror: MirrorItem,
    /// The token, for the exporter's `Install-TenkoDhcpMirror.ps1`; never shown again.
    pub token: String,
    /// When the token expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires_at: Option<Timestamp>,
    /// The SHA-256 fingerprint of this installation's certificate authority root, for the
    /// exporter's pin (plan section 2.1, rule 5).
    pub ca_fingerprint: String,
}

/// The answer of a push: `200 {"sequence", "changed"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SnapshotAccepted {
    /// The accepted sequence.
    pub sequence: u64,
    /// Whether the snapshot differs from the stored one (a changed push writes a row and an
    /// audit record; an unchanged one writes nothing).
    pub changed: bool,
}

/// The stored snapshot of a mirror (`GET /migrate/mirrors/{id}/snapshot`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SnapshotItem {
    /// The mirror.
    pub mirror: MirrorId,
    /// The sequence.
    pub sequence: u64,
    /// The SHA-256 of the envelope in canonical CBOR.
    pub hash: HexBytes,
    /// When the push was accepted.
    pub received: Timestamp,
    /// The envelope as pushed.
    pub envelope: MirrorSnapshot,
}

/// One entry of the loss report with its acknowledgment (`GET /migrate/mirrors/{id}/losses`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MirrorLossItem {
    /// The entry's key, for the acknowledgment.
    pub key: String,
    /// The entry.
    pub entry: LossEntry,
    /// The scope the entry belongs to, when its location names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub scope: Option<IpNet>,
    /// The acknowledgment that holds for the entry, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<LossAck>,
}

/// The loss report of the latest snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MirrorLosses {
    /// The mirror.
    pub mirror: MirrorId,
    /// The snapshot's sequence.
    pub sequence: u64,
    /// The entries.
    pub entries: Vec<MirrorLossItem>,
}

/// `POST /migrate/mirrors/{id}/losses/ack`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LossAckRequest {
    /// The keys of the entries to acknowledge, as `GET .../losses` lists them.
    pub keys: Vec<String>,
}

/// The answer of an acknowledgment.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LossAckResult {
    /// The acknowledgments written.
    pub acks: Vec<LossAck>,
    /// The revision that committed them.
    pub revision: Revision,
}

/// What a row of the diff is about (plan section 2.5).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    /// The network as an IPAM prefix.
    Prefix,
    /// A pool range.
    Pool,
    /// An exclusion range.
    Exclusion,
    /// The lease time.
    LeaseTime,
    /// An option at the server, scope or reservation level.
    Option,
    /// A reservation.
    Reservation,
    /// The DDNS settings.
    Ddns,
}

/// What the prepare would do about a row.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DiffAction {
    /// Create it in Tenko.
    Create,
    /// Change Tenko's to the mirror's.
    Update,
    /// Remove it from Tenko's scope.
    Remove,
    /// Attach to the IPAM host that already holds the reservation's MAC address, client
    /// identifier or address.
    Attach,
    /// Nothing: the two agree.
    Keep,
    /// The operator decides: a server option Tenko's server set already holds, or two IPAM
    /// hosts that disagree about a reservation; the prepare does not run while such a row
    /// stands.
    Decide,
}

/// One row of the diff of a mirrored scope against Tenko's scope of the same network.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DiffRow {
    /// What the row is about.
    pub kind: DiffKind,
    /// The item: a range (`192.0.2.100-192.0.2.199`), an option (`scope:6`), a reservation
    /// (`192.0.2.10`), a setting.
    pub item: String,
    /// The mirror's value, as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror: Option<String>,
    /// Tenko's value, as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenko: Option<String>,
    /// What the prepare would do.
    pub action: DiffAction,
    /// Why the operator must decide, for `decide`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The diff of a mirrored scope (`GET /migrate/mirrors/{id}/scopes/{cidr}/diff`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScopeDiff {
    /// The mirror.
    pub mirror: MirrorId,
    /// The scope.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub scope: IpNet,
    /// The snapshot's sequence.
    pub sequence: u64,
    /// Whether the source's scope is active in the snapshot.
    pub source_active: bool,
    /// Tenko's scope of the network, when it exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenko_scope: Option<tenko_core::PrefixId>,
    /// Whether Tenko's scope is enabled.
    pub tenko_enabled: bool,
    /// The rows; empty when the two agree.
    pub rows: Vec<DiffRow>,
    /// How many loss entries of the scope are not acknowledged.
    pub losses_open: u32,
}

/// The answer of the prepare, the takeover and the revert: the job that runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ScopeJobStarted {
    /// The job.
    pub job: JobId,
    /// The mirror.
    pub mirror: MirrorId,
    /// The scope.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub scope: IpNet,
}

/// A takeover record (`GET /migrate/takeovers`, `GET /migrate/takeovers/{id}`), without the
/// before-images; `GET .../{id}` adds them.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TakeoverItem {
    /// Identifier.
    pub id: TakeoverId,
    /// The mirror.
    pub mirror: MirrorId,
    /// The scope.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub scope: IpNet,
    /// The snapshot's sequence.
    pub sequence: u64,
    /// Where it ended.
    pub state: TakeoverState,
    /// The counts.
    pub counts: TakeoverCounts,
    /// The adopted addresses.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub adopted_leases: Vec<IpAddr>,
    /// The adopted names.
    #[serde(default)]
    pub adopted_names: Vec<tenko_core::dns::DnsName>,
    /// The names left frozen.
    #[serde(default)]
    pub frozen_names: Vec<tenko_core::dns::DnsName>,
    /// What was skipped, with the reasons.
    #[serde(default)]
    pub skipped: Vec<SkippedItem>,
    /// The before-images of every RRset the takeover changed (only on `GET .../{id}`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub before: Vec<tenko_core::migrate::RrSetImage>,
    /// The job that ran it.
    pub job: JobId,
    /// When the state was reached.
    pub at: Timestamp,
    /// Who started the job.
    pub by: UserId,
}

/// The filters of `GET /migrate/takeovers`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TakeoverFilters {
    /// Only the takeovers of this mirror.
    #[serde(default)]
    pub mirror: Option<MirrorId>,
    /// Only the takeovers of this scope.
    #[serde(default)]
    #[param(value_type = Option<String>)]
    pub scope: Option<IpNet>,
}

// ---------------------------------------------------------------------------------------
// Helpers

/// A 400 `sys.invalid_request` for a malformed path segment.
fn invalid(field: &str, detail: &str) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(codes::INVALID_REQUEST, 400, detail)
            .with_title("Invalid request")
            .with_param("field", field),
    )
}

/// An identifier from the path; `field` names the path parameter.
fn parse_id<T: std::str::FromStr>(field: &str, raw: &str) -> Result<T, ApiError> {
    raw.parse()
        .map_err(|_| invalid(field, "the identifier is not a UUID"))
}

/// A scope's network from the path: the network with its length, the slash
/// percent-encoded; axum hands it over decoded.
fn parse_cidr(raw: &str) -> Result<IpNet, ApiError> {
    raw.parse::<IpNet>()
        .ok()
        .filter(|cidr| cidr.trunc() == *cidr)
        .ok_or_else(|| invalid("cidr", "the scope is not a network with its length"))
}

/// A path of a scope under a mirror: the mirror's id and the scope.
fn mirror_and_scope(
    app: &AppState,
    cx: &tenko_core::RequestCtx,
    id: &str,
    cidr: &str,
    action: Action,
    kind: ObjectKind,
) -> Result<(MirrorId, IpNet), ApiError> {
    let id = parse_id::<MirrorId>("id", id)?;
    // The right is checked before the scope is parsed, so a session-only operation refuses
    // a token whatever the path says.
    match kind {
        ObjectKind::Mirror => app.authorize(&cx.principal, action, &mirror_object(id))?,
        _ => app.authorize(&cx.principal, action, &anywhere(kind))?,
    }
    let cidr = parse_cidr(cidr)?;
    Ok((id, cidr))
}

// ---------------------------------------------------------------------------------------
// The push

#[utoipa::path(
    put,
    path = "/migrate/mirrors/{id}/snapshot",
    tag = "migrate",
    operation_id = "push_mirror_snapshot",
    summary = "Push a snapshot of a mirrored source",
    description = "The one operation the mirror's own token (`mirror:<id>`) reaches, and the only right it has: `Action::Execute` on the mirror. The body is the envelope `MirrorSnapshot` (`format` 1), at most 8 MiB on the wire (`Content-Encoding: gzip` allowed, 32 MiB inflated), at most 1,000 scopes, 10,000 reservations and 100,000 leases, with a `sequence` above the last accepted one and at most one push per 10 s per mirror. A push whose envelope hashes like the stored one writes nothing and answers `changed: false`; a changed one writes the snapshot row and the audit record `migrate.mirror.push`. A refused push is audited as `migrate.mirror.refuse` at most once a minute per mirror and nothing of it is stored.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    request_body(content = MirrorSnapshot, content_type = "application/json"),
    responses(
        (status = 200, description = "The accepted sequence and whether the snapshot changed", body = SnapshotAccepted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The token is not this mirror's, or the mirror is disabled (`auth.forbidden`, `migrate.mirror.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror (`migrate.mirror.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The sequence is not above the last accepted one: a replay (`migrate.mirror.sequence`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "The body is above the bound (`migrate.mirror.too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The envelope does not validate; `path` names the first error (`migrate.mirror.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "A push came faster than the floor (`migrate.mirror.rate`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn push_mirror_snapshot(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<MirrorId>("id", &id)?;
    app.authorize(&cx.principal, Action::Execute, &mirror_object(id))?;
    Err(not_implemented("PUT", "/migrate/mirrors/{id}/snapshot"))
}

// ---------------------------------------------------------------------------------------
// Mirrors

#[utoipa::path(
    get,
    path = "/migrate/mirrors",
    tag = "migrate",
    operation_id = "list_mirrors",
    summary = "List mirrored sources",
    description = "Scope: `migrate.read`. Mirrors by name, each with its freshness, the counts of its latest snapshot and its open losses (the card of the connectors page).",
    params(PageParams),
    responses(
        (status = 200, description = "A page of mirrors by name", body = Page<MirrorItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_mirrors(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Mirror))?;
    Err(not_implemented("GET", "/migrate/mirrors"))
}

#[utoipa::path(
    post,
    path = "/migrate/mirrors",
    tag = "migrate",
    operation_id = "create_mirror",
    summary = "Create a mirrored source",
    description = "Scope: `migrate.write`, an interactive session. Creates the mirror, the service account `mirror-<name>` with no grants, and one scoped token whose only scope is `mirror:<id>`, shown once with the fingerprint of the certificate authority root the exporter pins. The token expires within TGL-05 (WT-Q11). Audited as `migrate.mirror.create`.",
    request_body(content = MirrorCreate, content_type = "application/json"),
    security(("session" = [])),
    responses(
        (status = 201, description = "The mirror and its token", body = MirrorCreated),
        (status = 400, description = "The request is malformed, or the settings are invalid (`migrate.mirror.invalid_settings`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.write`, or a token was used", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A mirror of this name exists (`migrate.mirror.exists`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_mirror(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    ApiJson(_body): ApiJson<MirrorCreate>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::Mirror))?;
    Err(not_implemented("POST", "/migrate/mirrors"))
}

#[utoipa::path(
    get,
    path = "/migrate/mirrors/{id}",
    tag = "migrate",
    operation_id = "get_mirror",
    summary = "Get a mirrored source",
    description = "Scope: `migrate.read`. The mirror with its freshness; a `mirror:` token does not reach it (a stolen token gives neither data nor reach).",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    responses(
        (status = 200, description = "The mirror", body = MirrorItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror (`migrate.mirror.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_mirror(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<MirrorId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &mirror_object(id))?;
    Err(not_implemented("GET", "/migrate/mirrors/{id}"))
}

#[utoipa::path(
    patch,
    path = "/migrate/mirrors/{id}",
    tag = "migrate",
    operation_id = "update_mirror",
    summary = "Change a mirrored source",
    description = "Scope: `migrate.write`, an interactive session. The name, whether pushes are accepted, the expected interval. Audited as `migrate.mirror.update`.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    request_body(content = MirrorPatch, content_type = "application/json"),
    security(("session" = [])),
    responses(
        (status = 200, description = "The mirror after the change", body = MirrorItem),
        (status = 400, description = "The request is malformed, or the settings are invalid (`migrate.mirror.invalid_settings`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.write`, or a token was used", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror (`migrate.mirror.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A mirror of the new name exists (`migrate.mirror.exists`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_mirror(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
    ApiJson(_body): ApiJson<MirrorPatch>,
) -> Result<Response, ApiError> {
    let id = parse_id::<MirrorId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &mirror_object(id))?;
    Err(not_implemented("PATCH", "/migrate/mirrors/{id}"))
}

#[utoipa::path(
    delete,
    path = "/migrate/mirrors/{id}",
    tag = "migrate",
    operation_id = "delete_mirror",
    summary = "Delete a mirrored source",
    description = "Scope: `migrate.write`, an interactive session. Deletes the mirror, its snapshot and its loss acknowledgments, and with them its service account and token; the takeover records stay. Audited as `migrate.mirror.delete`.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    security(("session" = [])),
    responses(
        (status = 204, description = "Deleted"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.write`, or a token was used", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror (`migrate.mirror.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_mirror(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<MirrorId>("id", &id)?;
    app.authorize(&cx.principal, Action::Delete, &mirror_object(id))?;
    Err(not_implemented("DELETE", "/migrate/mirrors/{id}"))
}

#[utoipa::path(
    post,
    path = "/migrate/mirrors/{id}/token",
    tag = "migrate",
    operation_id = "replace_mirror_token",
    summary = "Replace the token of a mirrored source",
    description = "An administrator's interactive session (`Action::Administer` on the mirror). Mints a new scoped token with the scope `mirror:<id>` for the mirror's service account and revokes the old one at once; the new token is shown once. Audited as `migrate.mirror.token`.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    request_body(content = MirrorTokenRequest, content_type = "application/json"),
    security(("session" = [])),
    responses(
        (status = 201, description = "The mirror and its new token", body = MirrorCreated),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal is not an administrator, or a token was used", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror (`migrate.mirror.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn replace_mirror_token(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
    ApiJson(_body): ApiJson<MirrorTokenRequest>,
) -> Result<Response, ApiError> {
    let id = parse_id::<MirrorId>("id", &id)?;
    app.authorize(&cx.principal, Action::Administer, &mirror_object(id))?;
    Err(not_implemented("POST", "/migrate/mirrors/{id}/token"))
}

#[utoipa::path(
    get,
    path = "/migrate/mirrors/{id}/snapshot",
    tag = "migrate",
    operation_id = "get_mirror_snapshot",
    summary = "Get the latest snapshot of a mirrored source",
    description = "Scope: `migrate.read`. The envelope as stored, with its sequence, hash and the time it was accepted.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    responses(
        (status = 200, description = "The snapshot", body = SnapshotItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror, or no push yet (`migrate.mirror.not_found`, `migrate.mirror.no_snapshot`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_mirror_snapshot(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<MirrorId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &mirror_object(id))?;
    Err(not_implemented("GET", "/migrate/mirrors/{id}/snapshot"))
}

#[utoipa::path(
    get,
    path = "/migrate/mirrors/{id}/losses",
    tag = "migrate",
    operation_id = "list_mirror_losses",
    summary = "The loss report of a mirrored source",
    description = "Scope: `migrate.read`. The entries of the latest snapshot's loss report, each with its key and the acknowledgment that holds for it; an acknowledgment lapses when the entry changes.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    responses(
        (status = 200, description = "The loss report", body = MirrorLosses),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror, or no push yet (`migrate.mirror.not_found`, `migrate.mirror.no_snapshot`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_mirror_losses(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<MirrorId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &mirror_object(id))?;
    Err(not_implemented("GET", "/migrate/mirrors/{id}/losses"))
}

#[utoipa::path(
    post,
    path = "/migrate/mirrors/{id}/losses/ack",
    tag = "migrate",
    operation_id = "ack_mirror_losses",
    summary = "Acknowledge loss entries of a mirrored source",
    description = "Scope: `migrate.write`, an interactive session. An acknowledgment holds while the entry recurs unchanged; the prepare and the takeover refuse a scope with an unacknowledged entry. Audited as `migrate.mirror.losses_ack`.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    request_body(content = LossAckRequest, content_type = "application/json"),
    security(("session" = [])),
    responses(
        (status = 200, description = "The acknowledgments written", body = LossAckResult),
        (status = 400, description = "The request is malformed, or a key names no entry of the latest snapshot (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.write`, or a token was used", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror, or no push yet (`migrate.mirror.not_found`, `migrate.mirror.no_snapshot`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn ack_mirror_losses(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
    ApiJson(_body): ApiJson<LossAckRequest>,
) -> Result<Response, ApiError> {
    let id = parse_id::<MirrorId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &mirror_object(id))?;
    Err(not_implemented("POST", "/migrate/mirrors/{id}/losses/ack"))
}

// ---------------------------------------------------------------------------------------
// Scopes

#[utoipa::path(
    get,
    path = "/migrate/mirrors/{id}/scopes/{cidr}/diff",
    tag = "migrate",
    operation_id = "get_mirror_scope_diff",
    summary = "The diff of a mirrored scope against Tenko's scope",
    description = "Scope: `migrate.read`. The pool ranges, the exclusions, the lease time, the options at each level, the reservations (by MAC address or client identifier and address), the DDNS settings and the IPAM prefix of the network, each row saying what the prepare would do (plan section 2.5).",
    params(
        ("id" = String, Path, description = "Mirror identifier (UUID)"),
        ("cidr" = String, Path, description = "The scope's network with its length, the slash percent-encoded (`192.0.2.0%2F24`)")
    ),
    responses(
        (status = 200, description = "The diff", body = ScopeDiff),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror, no push yet, or the snapshot holds no such scope (`migrate.mirror.not_found`, `migrate.mirror.no_snapshot`, `migrate.mirror.scope_not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_mirror_scope_diff(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path((id, cidr)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    mirror_and_scope(&app, &cx, &id, &cidr, Action::Read, ObjectKind::Mirror)?;
    Err(not_implemented(
        "GET",
        "/migrate/mirrors/{id}/scopes/{cidr}/diff",
    ))
}

#[utoipa::path(
    post,
    path = "/migrate/mirrors/{id}/scopes/{cidr}/prepare",
    tag = "migrate",
    operation_id = "prepare_mirror_scope",
    summary = "Prepare Tenko's scope from a mirrored scope",
    description = "Scope: `migrate.write`, an interactive session. Starts the prepare job of plan section 2.5: the IPAM prefix, the disabled scope, the pool, the exclusions, the option sets, the DDNS settings and the reservations as IPAM hosts named by section 2.9. Refused while a loss entry of the scope is unacknowledged or a diff row needs a decision. Audited as `dhcp.scope.prepare` when the job completes.",
    params(
        ("id" = String, Path, description = "Mirror identifier (UUID)"),
        ("cidr" = String, Path, description = "The scope's network with its length, the slash percent-encoded (`192.0.2.0%2F24`)")
    ),
    security(("session" = [])),
    responses(
        (status = 202, description = "The job", body = ScopeJobStarted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.write`, or a token was used", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror, no push yet, or no such scope (`migrate.mirror.not_found`, `migrate.mirror.no_snapshot`, `migrate.mirror.scope_not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The scope is not ready (`migrate.takeover.losses`, `migrate.takeover.diff`, `migrate.takeover.scope_enabled`, `migrate.takeover.running`, `migrate.mirror.stale`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn prepare_mirror_scope(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path((id, cidr)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    mirror_and_scope(&app, &cx, &id, &cidr, Action::Create, ObjectKind::Takeover)?;
    Err(not_implemented(
        "POST",
        "/migrate/mirrors/{id}/scopes/{cidr}/prepare",
    ))
}

#[utoipa::path(
    post,
    path = "/migrate/mirrors/{id}/scopes/{cidr}/takeover",
    tag = "migrate",
    operation_id = "take_over_mirror_scope",
    summary = "Take over a mirrored scope",
    description = "Scope: `migrate.write`, an interactive session. Starts the takeover job of plan section 2.7: the checks, the task that waits for a push showing the source's scope inactive, the adoption of the records and the leases (section 2.8), the scope enabled, the record in `migrate.takeovers`. A failure rolls the job back from the before-images. Audited as `dhcp.scope.takeover` with its counts.",
    params(
        ("id" = String, Path, description = "Mirror identifier (UUID)"),
        ("cidr" = String, Path, description = "The scope's network with its length, the slash percent-encoded (`192.0.2.0%2F24`)")
    ),
    security(("session" = [])),
    responses(
        (status = 202, description = "The job", body = ScopeJobStarted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.write`, or a token was used", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror, no push yet, or no such scope (`migrate.mirror.not_found`, `migrate.mirror.no_snapshot`, `migrate.mirror.scope_not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A check of step 1 failed (`migrate.takeover.not_fresh`, `migrate.takeover.losses`, `migrate.takeover.diff`, `migrate.takeover.zone`, `migrate.takeover.scope_enabled`, `migrate.takeover.running`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn take_over_mirror_scope(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path((id, cidr)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    mirror_and_scope(&app, &cx, &id, &cidr, Action::Create, ObjectKind::Takeover)?;
    Err(not_implemented(
        "POST",
        "/migrate/mirrors/{id}/scopes/{cidr}/takeover",
    ))
}

#[utoipa::path(
    post,
    path = "/migrate/mirrors/{id}/scopes/{cidr}/revert",
    tag = "migrate",
    operation_id = "revert_mirror_scope",
    summary = "Revert the takeover of a mirrored scope",
    description = "Scope: `migrate.write`, an interactive session. Starts the reverse action of plan section 2.10: Tenko's scope disabled, its leases and records kept; the operator activates the source's scope again. Audited as `dhcp.scope.revert`.",
    params(
        ("id" = String, Path, description = "Mirror identifier (UUID)"),
        ("cidr" = String, Path, description = "The scope's network with its length, the slash percent-encoded (`192.0.2.0%2F24`)")
    ),
    security(("session" = [])),
    responses(
        (status = 202, description = "The job", body = ScopeJobStarted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.write`, or a token was used", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror or no completed takeover of the scope (`migrate.mirror.not_found`, `migrate.takeover.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A job of the scope runs already (`migrate.takeover.running`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn revert_mirror_scope(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path((id, cidr)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    mirror_and_scope(&app, &cx, &id, &cidr, Action::Update, ObjectKind::Takeover)?;
    Err(not_implemented(
        "POST",
        "/migrate/mirrors/{id}/scopes/{cidr}/revert",
    ))
}

// ---------------------------------------------------------------------------------------
// Takeovers

#[utoipa::path(
    get,
    path = "/migrate/takeovers",
    tag = "migrate",
    operation_id = "list_takeovers",
    summary = "List takeover records",
    description = "Scope: `migrate.read`. The records of plan section 2.7, step 6, newest first, without their before-images.",
    params(PageParams, TakeoverFilters),
    responses(
        (status = 200, description = "A page of takeovers", body = Page<TakeoverItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_takeovers(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Takeover))?;
    Err(not_implemented("GET", "/migrate/takeovers"))
}

#[utoipa::path(
    get,
    path = "/migrate/takeovers/{id}",
    tag = "migrate",
    operation_id = "get_takeover",
    summary = "Get a takeover record",
    description = "Scope: `migrate.read`. The record with the before-images of every RRset the takeover changed.",
    params(("id" = String, Path, description = "Takeover identifier (UUID)")),
    responses(
        (status = 200, description = "The takeover", body = TakeoverItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such takeover (`migrate.takeover.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_takeover(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<TakeoverId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &takeover_object(id))?;
    Err(not_implemented("GET", "/migrate/takeovers/{id}"))
}

// ---------------------------------------------------------------------------------------
// Registration

/// The routes of the area; the push carries its own body limit.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    mirror_routes().merge(scope_and_takeover_routes())
}

// The registration is split into small functions that are never inlined: the server builds
// the router while its start-up future runs on a thread with a small stack, and one long
// chain of `routes!` keeps every temporary in one stack frame.

#[inline(never)]
fn mirror_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(
            routes!(push_mirror_snapshot, get_mirror_snapshot)
                .layer(DefaultBodyLimit::max(tenko_core::migrate::MAX_BODY_BYTES)),
        )
        .routes(routes!(list_mirrors, create_mirror))
        .routes(routes!(get_mirror, update_mirror, delete_mirror))
        .routes(routes!(replace_mirror_token))
        .routes(routes!(list_mirror_losses))
        .routes(routes!(ack_mirror_losses))
}

#[inline(never)]
fn scope_and_takeover_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_mirror_scope_diff))
        .routes(routes!(prepare_mirror_scope))
        .routes(routes!(take_over_mirror_scope))
        .routes(routes!(revert_mirror_scope))
        .routes(routes!(list_takeovers))
        .routes(routes!(get_takeover))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use serde_json::Value;
    use tenko_core::{Action, Authorizer, ObjectKind};
    use tower::ServiceExt;
    use utoipa_axum::router::OpenApiRouter;

    use super::routes;
    use crate::{
        API_BASE,
        routes::tenancy::testkit::{Policy, Reply},
        state::AppState,
    };

    const MIRROR: &str = "0190d1c2-0000-7000-8000-000000000001";

    fn router(state: AppState) -> Router {
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        router.with_state(state)
    }

    async fn send(router: &Router, method: &str, path: &str, body: Option<&str>) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
        if body.is_some() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        let request = request
            .body(body.map_or_else(Body::empty, |text| Body::from(text.to_owned())))
            .expect("request");
        let response = router.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|value| value.to_str().expect("text").to_owned())
            .unwrap_or_default();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("JSON")
        };
        Reply {
            status,
            content_type,
            etag: None,
            body,
        }
    }

    fn with_policy(read: bool, write: bool) -> (Router, Arc<Policy>) {
        let policy = Policy::new(read, write);
        let state = AppState {
            authorizer: Some(Arc::clone(&policy) as Arc<dyn Authorizer>),
            ..AppState::default()
        };
        (router(state), policy)
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one row per operation, read top to bottom"
    )]
    async fn every_operation_checks_its_right_on_its_object_then_answers_501() {
        let (router, policy) = with_policy(true, true);
        let scope = format!("/migrate/mirrors/{MIRROR}/scopes/192.0.2.0%2F24");
        let cases: [(&str, String, Option<&str>, Action, ObjectKind); 16] = [
            (
                "GET",
                "/migrate/mirrors".to_owned(),
                None,
                Action::Read,
                ObjectKind::Mirror,
            ),
            (
                "POST",
                "/migrate/mirrors".to_owned(),
                Some(r#"{"name":"lab","kind":"windows-dhcp"}"#),
                Action::Create,
                ObjectKind::Mirror,
            ),
            (
                "GET",
                format!("/migrate/mirrors/{MIRROR}"),
                None,
                Action::Read,
                ObjectKind::Mirror,
            ),
            (
                "PATCH",
                format!("/migrate/mirrors/{MIRROR}"),
                Some("{}"),
                Action::Update,
                ObjectKind::Mirror,
            ),
            (
                "DELETE",
                format!("/migrate/mirrors/{MIRROR}"),
                None,
                Action::Delete,
                ObjectKind::Mirror,
            ),
            (
                "POST",
                format!("/migrate/mirrors/{MIRROR}/token"),
                Some("{}"),
                Action::Administer,
                ObjectKind::Mirror,
            ),
            (
                "PUT",
                format!("/migrate/mirrors/{MIRROR}/snapshot"),
                None,
                Action::Execute,
                ObjectKind::Mirror,
            ),
            (
                "GET",
                format!("/migrate/mirrors/{MIRROR}/snapshot"),
                None,
                Action::Read,
                ObjectKind::Mirror,
            ),
            (
                "GET",
                format!("/migrate/mirrors/{MIRROR}/losses"),
                None,
                Action::Read,
                ObjectKind::Mirror,
            ),
            (
                "POST",
                format!("/migrate/mirrors/{MIRROR}/losses/ack"),
                Some(r#"{"keys":[]}"#),
                Action::Update,
                ObjectKind::Mirror,
            ),
            (
                "GET",
                format!("{scope}/diff"),
                None,
                Action::Read,
                ObjectKind::Mirror,
            ),
            (
                "POST",
                format!("{scope}/prepare"),
                None,
                Action::Create,
                ObjectKind::Takeover,
            ),
            (
                "POST",
                format!("{scope}/takeover"),
                None,
                Action::Create,
                ObjectKind::Takeover,
            ),
            (
                "POST",
                format!("{scope}/revert"),
                None,
                Action::Update,
                ObjectKind::Takeover,
            ),
            (
                "GET",
                "/migrate/takeovers".to_owned(),
                None,
                Action::Read,
                ObjectKind::Takeover,
            ),
            (
                "GET",
                format!("/migrate/takeovers/{MIRROR}"),
                None,
                Action::Read,
                ObjectKind::Takeover,
            ),
        ];
        for (method, path, body, action, kind) in cases {
            let reply = send(&router, method, &path, body).await;
            reply.assert_problem(501, "sys.not_implemented");
            let asked = policy.asked();
            let (last_action, object) = asked.last().expect("a question");
            assert_eq!(*last_action, action, "{method} {path}");
            assert_eq!(object.kind, kind, "{method} {path}");
            if path.contains(MIRROR) && kind == ObjectKind::Mirror {
                assert_eq!(object.id.to_string(), MIRROR, "{method} {path}");
            }
        }
    }

    #[tokio::test]
    async fn a_reader_reads_and_is_refused_the_writes_before_the_scope_is_parsed() {
        let (router, policy) = with_policy(true, false);
        send(&router, "GET", "/migrate/mirrors", None)
            .await
            .assert_problem(501, "sys.not_implemented");
        send(
            &router,
            "DELETE",
            &format!("/migrate/mirrors/{MIRROR}"),
            None,
        )
        .await
        .assert_problem(403, "auth.forbidden");
        // A write with a malformed scope is refused for the right first, so a session-only
        // operation never tells a token anything about the path.
        send(
            &router,
            "POST",
            &format!("/migrate/mirrors/{MIRROR}/scopes/not-a-network/takeover"),
            None,
        )
        .await
        .assert_problem(403, "auth.forbidden");
        assert_eq!(policy.asked().len(), 3);
    }

    #[tokio::test]
    async fn a_malformed_path_is_refused_after_the_right_or_before_the_stub() {
        let (router, _) = with_policy(true, true);
        send(&router, "GET", "/migrate/mirrors/not-a-uuid", None)
            .await
            .assert_problem(400, "sys.invalid_request");
        send(
            &router,
            "GET",
            &format!("/migrate/mirrors/{MIRROR}/scopes/192.0.2.1%2F24/diff"),
            None,
        )
        .await
        .assert_problem(400, "sys.invalid_request");
        send(&router, "GET", "/migrate/takeovers/7", None)
            .await
            .assert_problem(400, "sys.invalid_request");
    }
}
