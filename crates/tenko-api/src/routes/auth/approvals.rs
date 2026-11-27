//! Approvals of a takeover script (ADR 0038, `docs/plans/windows-takeover-plan.md` section
//! 2.16.5). The rules live in `tenko_auth::approval` and the service; these handlers read the
//! bodies, the node's TLS root and the caller.
//!
//! | Endpoint | Caller | Purpose |
//! |---|---|---|
//! | `POST /auth/approvals` | none: the script | Ask for an approval with the plan and the key: an id and a nonce |
//! | `POST /auth/approvals/lookup` | an administrator's session, fresh | The pending approval of a typed code |
//! | `POST /auth/approvals/{id}/approve` | an administrator's session, fresh | Approve it, with the code again |
//! | `POST /auth/approvals/{id}/deny` | an administrator's session | Deny it, or withdraw it before the collect |
//! | `POST /auth/approvals/clear` | an administrator's session, fresh | Deny every waiting or uncollected approval, or those of one source |
//! | `POST /auth/approvals/{id}/collect` | none: the script, with the key's signature | The delegated session, once |
//!
//! The code covers the SHA-256 of the root of the internal authority, which the API listener
//! serves in TLS mode a; in any other mode there is no root the script can bind, and the
//! request, the lookup and the approval answer 404 `tls.no_internal_ca`.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{DefaultBodyLimit, Path, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tenko_auth::approval::{
    ApprovalRequest, ApprovalTicket, ApprovalView, ClearApprovals, ClearedApprovals, CodeEntry,
    CollectRequest, DelegatedSession, MAX_REQUEST_BYTES,
};
use tenko_core::ApprovalId;
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt as _},
    routes,
};

use super::{
    ApiJson, OptionalJson, PublicCtx, RouteError, Svc, Unavailable, read_body, secret_json,
    unsupported_media_type,
};
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    routes::system::{CaRootSource, NO_INTERNAL_CA},
    state::AppState,
};

/// The largest collect body, in octets: one signature of 64 octets in base64url.
const MAX_COLLECT_BYTES: usize = 1_024;

/// The routes of the approvals.
pub(super) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(request_approval).layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES)))
        .routes(routes!(look_up_approval))
        .routes(routes!(approve_approval))
        .routes(routes!(deny_approval))
        .routes(routes!(clear_approvals))
        .routes(routes!(collect_approval).layer(DefaultBodyLimit::max(MAX_COLLECT_BYTES)))
}

type CaRoot = Option<Extension<Arc<CaRootSource>>>;

/// The SHA-256 of the internal authority's root while the listener serves it.
fn root_sha256(root: &CaRoot) -> Result<[u8; 32], ApiError> {
    root.as_ref()
        .and_then(|Extension(source)| source.fingerprint())
        .and_then(|hex| tenko_auth::encoding::hex_decode(&hex).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            ApiError::new(
                NO_INTERNAL_CA,
                404,
                "the API listener does not serve a certificate of the internal authority, so a \
                 takeover script cannot bind its code to the node's root",
            )
        })
}

/// The body of a public request, as sent: JSON only.
async fn json_body(request: Request) -> Result<axum::body::Bytes, ApiError> {
    let (is_json, body) = read_body(request, &()).await?;
    if is_json {
        Ok(body)
    } else {
        Err(unsupported_media_type())
    }
}

/// Asks for an approval: the takeover script sends its plan and its public key, without a
/// credential.
#[utoipa::path(
    post,
    path = "/auth/approvals",
    tag = "auth",
    operation_id = "request_approval",
    summary = "Ask a person to approve a takeover script",
    description = "No credential. The takeover script's request (ADR 0038): the plan of its run, its P-256 public key and what it reports about itself, at most 64 KiB of strict JSON (unknown and duplicate fields refused). Tenko checks the plan against its own limits and answers the approval's id and a nonce, nothing else. Both sides then compute the approval code over the domain, the SHA-256 of the internal authority's root, the SHA-256 of this body as sent, the key and the id; the person types it on the approval page. At most two pending approvals per source address (an IPv6 /64), 64 in all, each for ten minutes; one request per source every 10 s. Audited as `auth.approval.request`, at most once a minute per source. A delegated session never reaches it.",
    request_body(content = ApprovalRequest, content_type = "application/json"),
    responses(
        (status = 201, description = "The approval waits for a person", body = ApprovalTicket),
        (status = 404, description = "The listener does not serve the internal authority's root (`tls.no_internal_ca`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "The body is larger than 64 KiB (`sys.body_too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The body does not parse, or the plan is outside Tenko's limits; `params.reason` says which (`auth.approval.plan`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "A bound was reached; `params.limit` is `spacing`, `source` or `pending` (`auth.approval.limit`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security()
)]
async fn request_approval(
    Svc(service): Svc,
    PublicCtx { ctx, .. }: PublicCtx,
    root: CaRoot,
    request: Request,
) -> Result<Response, RouteError> {
    root_sha256(&root)?;
    let body = json_body(request).await?;
    let ticket = service.request_approval(&ctx, &body).await?;
    Ok((StatusCode::CREATED, Json(ticket)).into_response())
}

/// Finds the pending approval of the code the person typed.
#[utoipa::path(
    post,
    path = "/auth/approvals/lookup",
    tag = "auth",
    operation_id = "look_up_approval",
    summary = "Find the approval of a typed code",
    description = "An administrator's own session that signed in within the last five minutes (a passkey under Hardened). The code is compared in constant time with the code of every pending approval over this node's root; the answer is the request in full: the plan, the machine, user and version as the script reported them, and the source address. Five wrong codes from one browser session within ten minutes lock its lookups for ten minutes. A wrong code is audited as `auth.approval.refuse`, at most once a minute per session.",
    request_body(content = CodeEntry, content_type = "application/json"),
    responses(
        (status = 200, description = "The approval the code belongs to", body = ApprovalView),
        (status = 401, description = "No valid session; a token is refused (`auth.unauthenticated`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not an administrator (`auth.forbidden`), the sign-in is older than five minutes (`auth.step_up_required`), a delegated session (`auth.delegation.refused`), or the code matches no pending approval (`auth.approval.code`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The listener does not serve the internal authority's root (`tls.no_internal_ca`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The code matches more than one pending approval (`auth.approval.ambiguous`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "The session's lookups are locked after five wrong codes (`auth.approval.limit`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security(("session" = []))
)]
async fn look_up_approval(
    Svc(service): Svc,
    root: CaRoot,
    Ctx(ctx): Ctx,
    ApiJson(body): ApiJson<CodeEntry>,
) -> Result<Json<ApprovalView>, RouteError> {
    let root = root_sha256(&root)?;
    Ok(Json(
        service.look_up_approval(&ctx, &body.code, &root).await?,
    ))
}

/// Approves a pending request.
#[utoipa::path(
    post,
    path = "/auth/approvals/{id}/approve",
    tag = "auth",
    operation_id = "approve_approval",
    summary = "Approve a takeover script's request",
    description = "An administrator's own session that signed in within the last five minutes (a passkey under Hardened), with the code typed again, compared in constant time. The script may then collect a delegated session of this administrator, narrowed to the plan. At most one approval per domain is approved or has a delegated session alive at a time. When the domain has an open run (`run` in the answer and in the lookup's), the approval joins it at the collect, and its plan must equal the run's. Audited as `auth.approval.approve` with the run.",
    params(("id" = String, Path, description = "Approval identifier (UUID)")),
    request_body(content = CodeEntry, content_type = "application/json"),
    responses(
        (status = 200, description = "The approval, approved", body = ApprovalView),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session; a token is refused (`auth.unauthenticated`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not an administrator (`auth.forbidden`), the sign-in is older than five minutes (`auth.step_up_required`), a delegated session (`auth.delegation.refused`), a wrong code (`auth.approval.code`), or the request was denied (`auth.approval.denied`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such approval (`auth.approval.not_found`), or no internal authority's root (`tls.no_internal_ca`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The approval was decided before (`auth.approval.consumed`), the domain has an open run with another plan; `params.run` names it (`migrate.run.plan`); or, for a new run, the Hardened profile refuses a plan that flips the zones, since the domain controllers cannot sign their transfers; `detail` says what to do (`migrate.run.profile`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "The approval waited longer than ten minutes (`auth.approval.expired`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "Another approval of the domain is open, or the session's lookups are locked (`auth.approval.limit`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security(("session" = []))
)]
async fn approve_approval(
    Svc(service): Svc,
    root: CaRoot,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<CodeEntry>,
) -> Result<Json<ApprovalView>, RouteError> {
    let root = root_sha256(&root)?;
    let id = id.parse::<ApprovalId>()?;
    Ok(Json(service.approve(&ctx, id, &body.code, &root).await?))
}

/// Denies a pending request.
#[utoipa::path(
    post,
    path = "/auth/approvals/{id}/deny",
    tag = "auth",
    operation_id = "deny_approval",
    summary = "Deny a takeover script's request",
    description = "An administrator's own session. Denies a waiting request, or withdraws an approval the script has not collected yet. Audited as `auth.approval.deny`.",
    params(("id" = String, Path, description = "Approval identifier (UUID)")),
    responses(
        (status = 204, description = "The request was denied"),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session; a token is refused (`auth.unauthenticated`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not an administrator (`auth.forbidden`), a delegated session (`auth.delegation.refused`), or denied before (`auth.approval.denied`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such approval (`auth.approval.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The approval was collected before (`auth.approval.consumed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "The approval waited longer than ten minutes (`auth.approval.expired`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security(("session" = []))
)]
async fn deny_approval(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
) -> Result<StatusCode, RouteError> {
    let id = id.parse::<ApprovalId>()?;
    service.deny_approval(&ctx, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Denies every waiting request and every approval not collected yet, or those of one source.
#[utoipa::path(
    post,
    path = "/auth/approvals/clear",
    tag = "auth",
    operation_id = "clear_approvals",
    summary = "Deny the waiting approvals, of every source or one",
    description = "An administrator's own session that signed in within the last five minutes (a passkey under Hardened). Denies every waiting request and every approval the script has not collected, or, with `source`, those whose source is that address's (the address, an IPv4-mapped IPv6 address as its IPv4 address, or its IPv6 /64): the way out when requests the person does not recognize fill the bounds. Answers how many waiting requests and how many uncollected approvals were denied. Audited as `auth.approval.deny`, one record per approval.",
    request_body(content = ClearApprovals, content_type = "application/json"),
    responses(
        (status = 200, description = "How many approvals of each kind were denied", body = ClearedApprovals),
        (status = 400, description = "The body is not one object of the schema, or `source` is not an address (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session; a token is refused (`auth.unauthenticated`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not an administrator (`auth.forbidden`), the sign-in is older than five minutes (`auth.step_up_required`), or a delegated session (`auth.delegation.refused`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security(("session" = []))
)]
async fn clear_approvals(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    OptionalJson(body): OptionalJson<ClearApprovals>,
) -> Result<Json<ClearedApprovals>, RouteError> {
    Ok(Json(service.clear_approvals(&ctx, body.source).await?))
}

/// Collects the delegated session of an approved request.
#[utoipa::path(
    post,
    path = "/auth/approvals/{id}/collect",
    tag = "auth",
    operation_id = "collect_approval",
    summary = "Collect the delegated session of an approved request",
    description = "No credential: the script signs the collect message (`tenko-takeover-collect-v1`, a zero octet, the id's 16 octets and the nonce) with its key, from the request's source address. Answers once with the delegated session: a `tnka_` bearer secret, accepted only from that address, that reaches the routes of `tenko_auth::delegation::TAKEOVER` and nothing else, for its run only (`delegation`, the run's id: the domain's open run, which the sitting joins with an equal plan, or the run the collect creates, audited as `migrate.run.join` or `migrate.run.create`), is never fresh, and ends at its deadline (the shorter of eight hours after the approval and the profile's absolute lifetime) or after 15 minutes without a request. Audited as `auth.approval.collect`; a collect from another address or with a wrong signature as `auth.approval.refuse`, at most once a minute per source.",
    params(("id" = String, Path, description = "Approval identifier (UUID)")),
    request_body(content = CollectRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "The delegated session, shown once", body = DelegatedSession),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "The approver may no longer administer (`auth.unauthenticated`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The signature does not verify (`auth.approval.signature`), or the request was denied (`auth.approval.denied`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such approval from this address (`auth.approval.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The person has not decided yet (`auth.approval.pending`), or it was collected before or its run changed meanwhile (`auth.approval.consumed`), or the domain has an open run with another plan; `params.run` names it (`migrate.run.plan`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "The approval's time is over (`auth.approval.expired`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "The body is larger than 1 KiB (`sys.body_too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security()
)]
async fn collect_approval(
    Svc(service): Svc,
    PublicCtx { ctx, .. }: PublicCtx,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, RouteError> {
    let id = id.parse::<ApprovalId>()?;
    let body = json_body(request).await?;
    let session: DelegatedSession = service.collect_approval(&ctx, id, &body).await?;
    secret_json(StatusCode::OK, None, &session)
}
