//! "Keep both" on an address conflict.
//!
//! Area: proposals. Requirements: IPAM-15, IPAM-23.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `POST /proposals/{id}/keep` | 200 decision with the closed proposal | 400 `ipam.validation`, 403, 404 `ipam.proposal.not_found`, 409 `ipam.proposal.not_open`, `ipam.proposal.not_keepable`, 412 `ipam.proposal.revision_mismatch` |
//!
//! Keeping closes an open address conflict (`conflict_shared_address` or
//! `conflict_address_taken`) as a rejection that records a per-address exception: the
//! conflict is not raised again while the same devices share the address, whichever
//! sources report them. It needs `approve` on proposals, like a rejection, and is audited
//! as `ipam.proposal.keep` with the MAC addresses kept.

use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use tenko_core::{Action, ObjectRef, ProposalId};
use tenko_ipam::proposals::{self, Decision};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    common::{IfMatch, Ipam, IpamJson, IpamPath, authorize, if_match, with_etag},
    proposals::RejectRequest,
};
use crate::{
    extract::Ctx,
    list::Filters,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(keep_proposal))
}

/// Keeps an address conflict as intended ("keep both"): the proposal is closed and the
/// conflict stays quiet while the same devices share the address.
#[utoipa::path(
    post,
    path = "/proposals/{id}/keep",
    tag = "proposals",
    operation_id = "keep_proposal",
    summary = "Keep an address conflict as intended",
    params(("id" = String, Path, description = "Proposal identifier"), IfMatch),
    request_body = RejectRequest,
    responses(
        (status = 200, description = "The decision: the closed proposal (state `rejected`) and the revision, with `ETag` of the proposal", body = Decision),
        (status = 400, description = "The reason is over 1,024 bytes or has control characters (`ipam.validation`), the body is malformed (`sys.invalid_request`), or a parameter is unknown (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not decide proposals", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such proposal (`ipam.proposal.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The proposal is decided already, or it is not an address conflict (`ipam.proposal.not_open`, `ipam.proposal.not_keepable`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "If-Match is stale (`ipam.proposal.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn keep_proposal(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<ProposalId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(request): IpamJson<RejectRequest>,
) -> Result<Response, ApiError> {
    filters.only(&[])?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Approve, ObjectRef::from(id))?;
    let decision: Decision = proposals::keep(&ipam, id, request.reason, &cx, expected).await?;
    let revision = decision.proposal.revision;
    Ok(with_etag(Json(decision).into_response(), revision))
}

#[cfg(test)]
#[path = "proposal_keep_tests.rs"]
mod tests;
