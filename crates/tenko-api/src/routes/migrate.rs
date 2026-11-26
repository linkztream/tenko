//! Mirrored sources and takeovers (`docs/plans/windows-takeover-plan.md` section 3.2, ADR
//! 0033 and ADR 0034; MIG-01, MIG-04, MIG-08).
//!
//! Area: migrate. Owner: WP14.0 (the contracts); the operations are built by WP14.1 (the
//! mirrors, the push, the losses, the diff) and WP14.2 (the prepare, the takeover and the
//! revert). The mirrors, the push, the losses and the diff run on
//! `tenko_migrate::mirror::MirrorService`, which the server adds as a request extension;
//! without it, and for the operations of WP14.2 until that package builds them, an
//! operation checks the caller's right and answers `501` with `sys.not_implemented`. The
//! routes belong to the DHCP module (OPS-25): a server without it registers none of them.
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

use std::{net::IpAddr, sync::Arc};

use axum::{
    Extension, Json,
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_auth::{
    AuthService,
    authz::anywhere,
    service::{MirrorTokenTerms, types::SecretString},
};
use tenko_core::{
    Action, CodedError, Denied, DenyReason, JobId, MirrorId, ObjectKind, RequestCtx, TakeoverId,
    Timestamp, UserId,
    error::codes,
    ir::{MirrorSnapshot, SourceKindLabel},
    migrate::{
        LossAck, Mirror, SkippedItem, Snapshot, TakeoverCounts, TakeoverState, findings,
        mirror_object, takeover_object,
    },
};
pub use tenko_migrate::mirror::{
    DiffAction, DiffKind, DiffRow, MirrorItem, MirrorLossItem, MirrorLosses, MirrorPatch,
    MirroredScope, ScopeDiff, SnapshotAccepted, SnapshotCounts,
};
use tenko_migrate::mirror::{
    MirrorError, MirrorService,
    body::{self, MAX_BODY_BYTES},
    service::{Decoded, NewMirror, blocking},
};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{not_implemented, system::CaRootSource};
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

/// `POST /migrate/mirrors`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MirrorCreate {
    /// The name shown, 1 to 64 characters, spaces allowed but not at either end; it is not
    /// unique (the service account is `mirror-<id>`).
    pub name: String,
    /// The kind of source (`windows-dhcp`).
    pub kind: SourceKindLabel,
    /// The expected interval between pushes, in seconds; 60 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_secs: Option<u32>,
    /// The token's lifetime in days; the TGL-05 maximum when absent (WT-Q11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires_in_days: Option<u32>,
    /// The client addresses or networks the exporter pushes from (at most 64); empty for
    /// anywhere, which the Hardened profile refuses. A push from elsewhere is refused like an
    /// unknown token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_prefixes: Vec<String>,
}

/// `POST /migrate/mirrors/{id}/token`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct MirrorTokenRequest {
    /// The token's lifetime in days; the TGL-05 maximum when absent (WT-Q11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<u32>,
    /// The client addresses or networks the new token is accepted from, as on creation; the
    /// old token's list does not carry over.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_prefixes: Vec<String>,
}

/// A mirror with the token the exporter needs, shown once (`POST /migrate/mirrors`,
/// `POST /migrate/mirrors/{id}/token`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MirrorCreated {
    /// The mirror.
    pub mirror: MirrorItem,
    /// The token, for the exporter's `Install-TenkoDhcpMirror.ps1`; never shown again.
    pub token: SecretString,
    /// When the token expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires_at: Option<Timestamp>,
    /// The SHA-256 fingerprint of this installation's certificate authority root, for the
    /// exporter's pin (plan section 2.1, rule 5); absent when the API does not serve a
    /// certificate of the internal authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint: Option<String>,
}

/// `POST /migrate/mirrors/{id}/losses/ack`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LossAckRequest {
    /// The sequence of the loss report the keys were read from (`GET .../losses`); a newer
    /// snapshot refuses the acknowledgment, so that it holds only for what was read.
    pub sequence: u64,
    /// The keys of the entries to acknowledge.
    pub keys: Vec<String>,
}

/// The answer of an acknowledgment.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LossAckResult {
    /// The acknowledgments written.
    pub acks: Vec<LossAck>,
    /// The revision that committed them.
    pub revision: tenko_core::Revision,
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

/// The mirror service, which the server adds as a request extension.
type Mirrors = Option<Extension<Arc<MirrorService>>>;

/// The certificate authority root, which the server adds in its internal-CA mode.
type CaRoot = Option<Extension<Arc<CaRootSource>>>;

/// The service, or the `501` stub answer when the server did not add one.
fn service(mirrors: Mirrors, method: &str, path: &str) -> Result<Arc<MirrorService>, ApiError> {
    mirrors
        .map(|Extension(service)| service)
        .ok_or_else(|| not_implemented(method, path))
}

/// The mirror a path names, after the caller's right on it, and the service.
fn mirror_op(
    app: &AppState,
    mirrors: Mirrors,
    cx: &RequestCtx,
    raw: &str,
    action: Action,
    (method, path): (&str, &str),
) -> Result<(MirrorId, Arc<MirrorService>), ApiError> {
    let id = parse_id::<MirrorId>("id", raw)?;
    app.authorize(&cx.principal, action, &mirror_object(id))?;
    Ok((id, service(mirrors, method, path)?))
}

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
    cx: &RequestCtx,
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

/// The mirror with the fingerprint of the internal authority's root, which the exporter pins.
fn pinned(mut mirror: MirrorItem, ca_root: &CaRoot) -> MirrorItem {
    mirror.ca_fingerprint = ca_root
        .as_ref()
        .and_then(|Extension(source)| source.fingerprint())
        .map(|fingerprint| fingerprint.to_string());
    mirror
}

/// A mirror with its new token, answered `201` with `Cache-Control: no-store` like every
/// answer that carries a token.
fn created(
    (mirror, token): (MirrorItem, tenko_auth::service::types::CreatedToken),
    ca_root: &CaRoot,
) -> Response {
    let mirror = pinned(mirror, ca_root);
    let body = MirrorCreated {
        ca_fingerprint: mirror.ca_fingerprint.clone(),
        mirror,
        token: token.token,
        token_expires_at: token.info.expires_at,
    };
    (
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(body),
    )
        .into_response()
}

// ---------------------------------------------------------------------------------------
// The push

/// Reads the body whole: the read stops at [`MAX_BODY_BYTES`], with or without a declared
/// length, and the server's deadline for request bodies (`middleware::body_deadline`, 408
/// `sys.body_timeout`) ends a body that arrives too slowly; `Content-Encoding` is absent,
/// `identity` or `gzip` (`true`).
async fn read_body(headers: &HeaderMap, raw: Body) -> Result<(Bytes, bool), MirrorError> {
    let gzip = match headers
        .get(header::CONTENT_ENCODING)
        .map(HeaderValue::as_bytes)
    {
        None | Some(b"identity") => false,
        Some(b"gzip") => true,
        Some(_) => {
            return Err(MirrorError::Request(
                "the body is plain or gzip, nothing else".to_owned(),
            ));
        }
    };
    let bytes = axum::body::to_bytes(raw, MAX_BODY_BYTES)
        .await
        .map_err(|error| {
            if timed_out(&error) {
                MirrorError::BodyTimeout
            } else {
                MirrorError::TooLarge {
                    limit: MAX_BODY_BYTES,
                }
            }
        })?;
    Ok((bytes, gzip))
}

/// Whether a body's read ended on the server's deadline for bodies, which ends it with a
/// `TimedOut` error somewhere in the error's chain.
fn timed_out(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut next = Some(error);
    while let Some(error) = next {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
        {
            return true;
        }
        next = error.source();
    }
    false
}

#[utoipa::path(
    put,
    path = "/migrate/mirrors/{id}/snapshot",
    tag = "migrate",
    operation_id = "push_mirror_snapshot",
    summary = "Push a snapshot of a mirrored source",
    description = "The one operation the mirror's own token (`mirror:<id>`) reaches, and the only one it reaches; no other token and no session pushes. The body is the envelope `MirrorSnapshot` (`format` 1), at most 8 MiB on the wire (`Content-Encoding: gzip` allowed, 32 MiB inflated), at most 102,000 list items, 1,000 scopes, 10,000 reservations and 20,000 leases (a refusal names the count), every text one line without a control character or a format character that hides or reorders text, with a `sequence` above the last one accepted from this token and at most one push per 10 s per mirror (`Retry-After` says when the next one is admitted). A token bound to source prefixes is refused like an unknown token from any other address, and under Hardened so is a mirror token without prefixes. The body is read whole first, within the server's deadline for request bodies (408 `sys.body_timeout`), so that a body that arrives slowly holds no other push; a node then decodes one push at a time; a push that waits 2 s for that is answered 429 as well, and so is a push of a mirror while another push of it is in flight on the node. A push whose token is replaced while its body arrives is refused 401. A push whose configuration (everything but the leases, their loss entries, the sequence and the time) changed answers `changed: true` and writes the snapshot, the mirror and the audit record `migrate.mirror.push` at once while the mirror's reserve lasts: 30 in a row, and one more for every ten minutes since (`changes_left`); past it, or while the node's clock guard holds its clock, the push is held, and the first push after the refill whose configuration still differs is written (`held_change_due` on the controller that holds it); changed leases alone are written at most every ten minutes without an audit record (the mirror's `stored_sequence` and `stored_at` say which push the stored leases are from); otherwise the mirror's freshness is written at most every half of its stale threshold. The first push a token makes binds the mirror to the server its `source.server` names, and a push naming another is refused until the token is replaced. A refused push is audited as `migrate.mirror.refuse` at most once a minute per mirror and nothing of it is stored; a refused sequence names the last accepted one in `params.last`.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    request_body(content = MirrorSnapshot, content_type = "application/json"),
    security(("token" = [])),
    responses(
        (status = 200, description = "The accepted sequence and whether the snapshot changed", body = SnapshotAccepted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid token: unknown, replaced, used from outside its source prefixes, or a token without prefixes under Hardened", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The token is not this mirror's own, a session was used, or the mirror is disabled (`auth.forbidden`, `migrate.mirror.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror (`migrate.mirror.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 408, description = "The body did not arrive within the server's deadline for request bodies (`sys.body_timeout`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The sequence is not above the last accepted one: a replay (`migrate.mirror.sequence`, `params.last`), the push names another server than the one the mirror is bound to (`migrate.mirror.source`, `params.bound`, `params.server`), or the row changed under every attempt (`migrate.mirror.conflict`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "The body is above the bound (`migrate.mirror.too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The envelope does not validate; `path` names the first error (`migrate.mirror.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "A push came faster than the floor or while another push of the mirror is in flight, or another push held the node's decode for 2 s (`migrate.mirror.rate`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn push_mirror_snapshot(
    State(app): State<AppState>,
    mirrors: Mirrors,
    auth: Option<Extension<Arc<AuthService>>>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
    headers: HeaderMap,
    raw: Body,
) -> Result<Response, ApiError> {
    let (id, service) = mirror_op(
        &app,
        mirrors,
        &cx,
        &id,
        Action::Execute,
        ("PUT", "/migrate/mirrors/{id}/snapshot"),
    )?;
    // Plan section 2.1, rule 2: the push is the mirror's own token's, never another token's
    // or a session's that could execute on the mirror.
    if auth.and_then(|Extension(auth)| auth.token_mirror(&cx.principal)) != Some(id) {
        return Err(Denied {
            action: Action::Execute,
            object: mirror_object(id),
            reason: DenyReason::MissingPermission,
        }
        .into());
    }
    // One push of the mirror in flight on this controller until this one ends, however it
    // ends. The body is read first, under its deadline, so that a slow body holds no other
    // mirror's push; one decode at a time on this node, from the inflate to the write. The
    // decode with its hashes, and the row's encode, run on a blocking thread that owns both
    // until it ends, however the request ends.
    let outcome = async {
        let in_flight = service.admit(id).await?;
        let (bytes, gzip) = read_body(&headers, raw).await?;
        let guards = (in_flight, service.decoding().await?);
        let (decoded, guards) = blocking(guards, move || {
            body::decode(&bytes, gzip).and_then(Decoded::of)
        })
        .await
        .map_err(|error| MirrorError::Request(format!("the body was not decoded: {error}")))?;
        service.push(&cx, id, decoded?, guards).await
    }
    .await;
    let error = match outcome {
        Ok(accepted) => return Ok(Json(accepted).into_response()),
        Err(error) => error,
    };
    if !matches!(error, MirrorError::NotFound(_) | MirrorError::Store(_)) {
        service.refused(&cx, id, &error).await;
    }
    Ok(refusal(error))
}

/// The problem of a refused mirror operation, with `Retry-After` when the refusal says when
/// to come back (429 `migrate.mirror.rate` and `migrate.mirror.busy`).
fn refusal(error: MirrorError) -> Response {
    let retry = match &error {
        MirrorError::Rate { retry_after } | MirrorError::Busy { retry_after } => Some(*retry_after),
        _ => None,
    };
    let mut response = ApiError::from(error).into_response();
    if let Some(seconds) = retry {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
    }
    response
}

/// The answer of a read of a stored snapshot: its body, or the refusal.
fn answered<T: Serialize>(result: Result<T, MirrorError>) -> Response {
    match result {
        Ok(body) => Json(body).into_response(),
        Err(error) => refusal(error),
    }
}

// ---------------------------------------------------------------------------------------
// Mirrors

#[utoipa::path(
    get,
    path = "/migrate/mirrors",
    tag = "migrate",
    operation_id = "list_mirrors",
    summary = "List mirrored sources",
    description = "Scope: `migrate.read`. Mirrors by name, each with its freshness, the counts of its latest snapshot and its open losses (the card of the connectors page); one page holds every mirror.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of mirrors by name", body = Page<MirrorItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.read`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_mirrors(
    State(app): State<AppState>,
    mirrors: Mirrors,
    ca_root: CaRoot,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Mirror))?;
    let service = service(mirrors, "GET", "/migrate/mirrors")?;
    let items = service
        .list()
        .await?
        .into_iter()
        .map(|item| pinned(item, &ca_root))
        .collect();
    Ok(Json(Page::new(items, None, app.store.status().revision)).into_response())
}

#[utoipa::path(
    post,
    path = "/migrate/mirrors",
    tag = "migrate",
    operation_id = "create_mirror",
    summary = "Create a mirrored source",
    description = "Scope: `migrate.write`, an interactive session that signed in within five minutes. A takeover script's delegated session (ADR 0038) creates one within five minutes of its approval instead, only for a DHCP server of its plan (the mirror named for the server, kind `windows-dhcp`) with the mirror host's address as its one source prefix. Creates the mirror, the service account `mirror-<id>` with no grants, and one scoped token whose only scope is `mirror:<id>`, bound to `source_prefixes` when given, shown once with the fingerprint of the certificate authority root the exporter pins. The token expires within TGL-05 (WT-Q11). A source prefix is at least a /16 (IPv4) or a /48 (IPv6); under Hardened at least one is required. An installation holds at most 32 mirrors. Audited as `migrate.mirror.create`.",
    request_body(content = MirrorCreate, content_type = "application/json"),
    security(("session" = [])),
    responses(
        (status = 201, description = "The mirror and its token", body = MirrorCreated),
        (status = 400, description = "The request is malformed, or the settings are invalid (`migrate.mirror.invalid_settings`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.write`, a token was used, or the sign-in is older than five minutes (`auth.step_up_required`); a takeover script's delegated session past five minutes after its approval, or with a mirror outside its plan (`auth.delegation.refused`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The installation holds 32 mirrors (`migrate.mirror.limit`), or an account of the service account's name exists; `params.name` names it (`migrate.mirror.exists`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_mirror(
    State(app): State<AppState>,
    mirrors: Mirrors,
    ca_root: CaRoot,
    auth: Option<Extension<Arc<tenko_auth::AuthService>>>,
    Ctx(cx): Ctx,
    ApiJson(body): ApiJson<MirrorCreate>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::Mirror))?;
    // ADR 0038: a takeover script's delegated session creates only the mirrors of its plan.
    if cx.principal.delegation().is_some() {
        let refused = || ApiError::from(tenko_auth::AuthError::DelegationRefused);
        let plan = auth.ok_or_else(refused)?.delegation_plan(&cx).await?;
        if !tenko_auth::delegation::mirror_in_plan(
            &plan,
            &body.name,
            body.kind.as_str(),
            &body.source_prefixes,
        ) {
            return Err(refused());
        }
    }
    let service = service(mirrors, "POST", "/migrate/mirrors")?;
    let new = NewMirror {
        name: body.name,
        kind: body.kind,
        interval_secs: body.interval_secs,
        token: MirrorTokenTerms {
            expires_in_days: body.token_expires_in_days,
            source_prefixes: body.source_prefixes,
        },
    };
    Ok(created(service.create(&cx, new).await?, &ca_root))
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
        (status = 404, description = "No such mirror (`migrate.mirror.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_mirror(
    State(app): State<AppState>,
    mirrors: Mirrors,
    ca_root: CaRoot,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let (id, service) = mirror_op(
        &app,
        mirrors,
        &cx,
        &id,
        Action::Read,
        ("GET", "/migrate/mirrors/{id}"),
    )?;
    Ok(Json(pinned(service.get(id).await?, &ca_root)).into_response())
}

#[utoipa::path(
    patch,
    path = "/migrate/mirrors/{id}",
    tag = "migrate",
    operation_id = "update_mirror",
    summary = "Change a mirrored source",
    description = "Scope: `migrate.write`, an interactive session. The name (the service account keeps its own), whether pushes are accepted, the expected interval, and the partner: the other mirror of a pair of DHCP servers, set on both mirrors at once (`null` takes the pair apart on both). Audited as `migrate.mirror.update`, naming both mirrors when the pair changes.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    request_body(content = MirrorPatch, content_type = "application/json"),
    security(("session" = [])),
    responses(
        (status = 200, description = "The mirror after the change", body = MirrorItem),
        (status = 400, description = "The request is malformed, or the settings are invalid (`migrate.mirror.invalid_settings`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.write`, or a token was used", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror (`migrate.mirror.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A mirror of the new name exists (`migrate.mirror.exists`), the pairing is refused: the mirror itself, a mirror that does not exist, or a mirror already paired with another (`migrate.mirror.partner`, `params.reason`), or the row changed under every attempt (`migrate.mirror.conflict`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_mirror(
    State(app): State<AppState>,
    mirrors: Mirrors,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<MirrorPatch>,
) -> Result<Response, ApiError> {
    let (id, service) = mirror_op(
        &app,
        mirrors,
        &cx,
        &id,
        Action::Update,
        ("PATCH", "/migrate/mirrors/{id}"),
    )?;
    Ok(Json(service.update(&cx, id, body).await?).into_response())
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
        (status = 409, description = "The row changed under every attempt (`migrate.mirror.conflict`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_mirror(
    State(app): State<AppState>,
    mirrors: Mirrors,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let (id, service) = mirror_op(
        &app,
        mirrors,
        &cx,
        &id,
        Action::Delete,
        ("DELETE", "/migrate/mirrors/{id}"),
    )?;
    service.delete(&cx, id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[utoipa::path(
    post,
    path = "/migrate/mirrors/{id}/token",
    tag = "migrate",
    operation_id = "replace_mirror_token",
    summary = "Replace the token of a mirrored source",
    description = "An administrator's interactive session that signed in within five minutes (`Action::Administer` on the mirror). Mints a new scoped token with the scope `mirror:<id>` for the mirror's service account and revokes the old one at once; the new token starts a new series of sequences. The new token is shown once. Audited as `migrate.mirror.token`.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    request_body(content = MirrorTokenRequest, content_type = "application/json"),
    security(("session" = [])),
    responses(
        (status = 201, description = "The mirror and its new token", body = MirrorCreated),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal is not an administrator, a token was used, or the sign-in is older than five minutes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror (`migrate.mirror.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The row changed under every attempt (`migrate.mirror.conflict`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn replace_mirror_token(
    State(app): State<AppState>,
    mirrors: Mirrors,
    ca_root: CaRoot,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<MirrorTokenRequest>,
) -> Result<Response, ApiError> {
    let (id, service) = mirror_op(
        &app,
        mirrors,
        &cx,
        &id,
        Action::Administer,
        ("POST", "/migrate/mirrors/{id}/token"),
    )?;
    Ok(created(
        service
            .replace_token(
                &cx,
                id,
                &MirrorTokenTerms {
                    expires_in_days: body.expires_in_days,
                    source_prefixes: body.source_prefixes,
                },
            )
            .await?,
        &ca_root,
    ))
}

#[utoipa::path(
    get,
    path = "/migrate/mirrors/{id}/snapshot",
    tag = "migrate",
    operation_id = "get_mirror_snapshot",
    summary = "Get the latest snapshot of a mirrored source",
    description = "Scope: `migrate.read`. The envelope as stored at its last change, with its sequence, the hash of its content and the time it was accepted; its `taken_at` is that of the last change.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    responses(
        (status = 200, description = "The snapshot", body = Snapshot),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror, or no push yet (`migrate.mirror.not_found`, `migrate.mirror.no_snapshot`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "Another read of a stored snapshot held the node's one for 2 s (`migrate.mirror.busy`, `Retry-After`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_mirror_snapshot(
    State(app): State<AppState>,
    mirrors: Mirrors,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let (id, service) = mirror_op(
        &app,
        mirrors,
        &cx,
        &id,
        Action::Read,
        ("GET", "/migrate/mirrors/{id}/snapshot"),
    )?;
    // Serialized while the read is held, so that the next read decodes after it.
    Ok(match service.snapshot(id).await {
        Ok(held) => Json(&*held).into_response(),
        Err(error) => refusal(error),
    })
}

#[utoipa::path(
    get,
    path = "/migrate/mirrors/{id}/losses",
    tag = "migrate",
    operation_id = "list_mirror_losses",
    summary = "The loss report of a mirrored source",
    description = "Scope: `migrate.read`. The entries of the latest snapshot's loss report with its sequence, each with its key, its scope (the scope holding the address its location names; none: every scope) and the acknowledgment that holds for it; an acknowledgment lapses when the entry changes.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    responses(
        (status = 200, description = "The loss report", body = MirrorLosses),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror, or no push yet (`migrate.mirror.not_found`, `migrate.mirror.no_snapshot`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "Another read of a stored snapshot held the node's one for 2 s (`migrate.mirror.busy`, `Retry-After`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_mirror_losses(
    State(app): State<AppState>,
    mirrors: Mirrors,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let (id, service) = mirror_op(
        &app,
        mirrors,
        &cx,
        &id,
        Action::Read,
        ("GET", "/migrate/mirrors/{id}/losses"),
    )?;
    Ok(answered(service.losses(id).await))
}

#[utoipa::path(
    post,
    path = "/migrate/mirrors/{id}/losses/ack",
    tag = "migrate",
    operation_id = "ack_mirror_losses",
    summary = "Acknowledge loss entries of a mirrored source",
    description = "Scope: `migrate.write`, an interactive session. Acknowledges entries of the loss report at `sequence`, the one that was read; a newer snapshot refuses it with 409 `migrate.mirror.snapshot_moved`. An acknowledgment holds while the entry recurs unchanged; the prepare and the takeover refuse a scope with an unacknowledged entry. Audited as `migrate.mirror.losses_ack`.",
    params(("id" = String, Path, description = "Mirror identifier (UUID)")),
    request_body(content = LossAckRequest, content_type = "application/json"),
    security(("session" = [])),
    responses(
        (status = 200, description = "The acknowledgments written", body = LossAckResult),
        (status = 400, description = "The request is malformed, names no key, or a key names no entry of the snapshot (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `migrate.write`, or a token was used", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such mirror, or no push yet (`migrate.mirror.not_found`, `migrate.mirror.no_snapshot`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A newer snapshot came in after the one that was read (`migrate.mirror.snapshot_moved`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "Another read of a stored snapshot held the node's one for 2 s (`migrate.mirror.busy`, `Retry-After`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn ack_mirror_losses(
    State(app): State<AppState>,
    mirrors: Mirrors,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<LossAckRequest>,
) -> Result<Response, ApiError> {
    let (id, service) = mirror_op(
        &app,
        mirrors,
        &cx,
        &id,
        Action::Update,
        ("POST", "/migrate/mirrors/{id}/losses/ack"),
    )?;
    Ok(answered(
        service
            .ack(&cx, id, body.sequence, &body.keys)
            .await
            .map(|(acks, revision)| LossAckResult { acks, revision }),
    ))
}

// ---------------------------------------------------------------------------------------
// Scopes

#[utoipa::path(
    get,
    path = "/migrate/mirrors/{id}/scopes/{cidr}/diff",
    tag = "migrate",
    operation_id = "get_mirror_scope_diff",
    summary = "The diff of a mirrored scope against Tenko's scope",
    description = "Scope: `migrate.read`. The pool ranges, the exclusions, the lease time, the options at each level, the reservations (by MAC address or client identifier and address), the DDNS settings, the MAC filters (the scope's restriction to the allow list and the source's entries) and the IPAM prefix of the network in the default VRF, each row saying what the prepare would do (plan section 2.5); only differences are rows, and what the prepare cannot write is the operator's decision. For a paired mirror, rows of kind `partner` name every configuration difference of the scope between the mirror's latest snapshot and its partner's (`partner_sequence`), each for the operator to decide.",
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
        (status = 429, description = "Another read of a stored snapshot held the node's one for 2 s (`migrate.mirror.busy`, `Retry-After`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_mirror_scope_diff(
    State(app): State<AppState>,
    mirrors: Mirrors,
    Ctx(cx): Ctx,
    Path((id, cidr)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (id, scope) = mirror_and_scope(&app, &cx, &id, &cidr, Action::Read, ObjectKind::Mirror)?;
    let service = service(mirrors, "GET", "/migrate/mirrors/{id}/scopes/{cidr}/diff")?;
    Ok(answered(service.diff(id, scope).await))
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
// Findings

/// The health findings of the mirrored sources for `GET /system/status` (plan section 2.12):
/// one warning per code, naming its mirrors by name and short id (`mirrors`, since names
/// are not unique) and by id (`ids`).
pub(crate) async fn warnings(
    mirrors: Option<Arc<MirrorService>>,
) -> Vec<crate::dto::system::StatusWarning> {
    let Some(mirrors) = mirrors else {
        return Vec::new();
    };
    let found = match mirrors.findings().await {
        Ok(found) => found,
        Err(error) => {
            tracing::warn!(%error, "the findings of the mirrored sources could not be read");
            return Vec::new();
        }
    };
    found
        .into_iter()
        .map(|finding| {
            let names = finding
                .mirrors
                .iter()
                .map(|(id, name)| format!("{name} ({})", Mirror::short_id(*id)))
                .collect::<Vec<_>>()
                .join(", ");
            let ids = finding
                .mirrors
                .iter()
                .map(|(id, _)| id.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let detail = match finding.code {
                findings::MIRROR_STALE => "no push for three intervals from the mirrored sources",
                findings::MIRROR_SCOPE_ACTIVE => {
                    "a mirrored source pushed after a takeover silenced it: a server answers beside Tenko"
                }
                findings::MIRROR_UNBOUND => {
                    "the Hardened profile refuses the pushes of mirrors whose token has no source prefix; replace their tokens with prefixes"
                }
                _ => "the token of a mirrored source expires within fourteen days",
            };
            crate::dto::system::StatusWarning {
                code: finding.code.to_owned(),
                detail: format!("{detail}: {names}"),
                params: std::collections::BTreeMap::from([
                    ("mirrors".to_owned(), names),
                    ("ids".to_owned(), ids),
                    ("count".to_owned(), finding.mirrors.len().to_string()),
                ]),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------------------
// Registration

/// The routes of the area; the push reads its body within its own bound.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    mirror_routes().merge(scope_and_takeover_routes())
}

// The registration is split into small functions that are never inlined: the server builds
// the router while its start-up future runs on a thread with a small stack, and one long
// chain of `routes!` keeps every temporary in one stack frame.

#[inline(never)]
fn mirror_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(push_mirror_snapshot, get_mirror_snapshot))
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
                Some(r#"{"sequence":1,"keys":[]}"#),
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

#[cfg(test)]
#[path = "migrate_tests.rs"]
mod service_tests;
