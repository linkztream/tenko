//! `POST /dns/zones/{id}/flip` and `POST /dns/zones/{id}/release` (Windows takeover plan
//! section 2.6, ADR 0034; MIG-04): the flip of a zone between secondary and primary in
//! place, and the release of the frozen (`transfer`) names a takeover did not adopt. WP14.0
//! declares them with their request and answer types (`tenko_core::dns::ZoneFlip`,
//! `ZoneRelease`, `ZoneFlipReport`, `ZoneReleaseReport`); WP14.2 builds them on the zone
//! service. Until then each checks the caller's right and answers `501`.
//!
//! The flip is interactive: it changes which server is the authority of a zone, so a
//! personal token is refused with `auth.forbidden` after the scope check, as the document
//! says (`security(("session" = []))`). The release is an ordinary write of the zone.

use axum::{
    extract::{Path, State},
    response::Response,
};
use tenko_core::{
    Action, CodedError, ObjectRef, Principal,
    dns::{ZoneFlip, ZoneId, ZoneRelease},
};

use super::parse_id;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    routes::{auth::ApiJson, not_implemented},
    state::AppState,
};

/// A personal or scoped token on an operation that needs a person (403 `auth.forbidden`).
fn needs_a_session(principal: &Principal) -> Result<(), ApiError> {
    if matches!(principal, Principal::User { .. }) {
        return Ok(());
    }
    Err(ApiError::from_coded_error(
        CodedError::new(
            "auth.forbidden",
            403,
            "flipping a zone needs an interactive session; a token is refused",
        )
        .with_title("Forbidden"),
    ))
}

#[utoipa::path(
    post,
    path = "/dns/zones/{id}/flip",
    tag = "dns",
    operation_id = "flip_dns_zone",
    summary = "Flip a zone between secondary and primary in place",
    description = "Scope: `dns.write`, an interactive session. `{\"to\": \"primary\", \"soa\": {...}, \"ns\": [...]}` turns a secondary zone into a primary zone: the transfer service stops refreshing it, the SOA `mname` and `rname` and the apex NS set become the given values, the serial continues from the copy's, and the records stay with their provenance (the A, AAAA and DHCID RRsets at a name with a DHCID RRset, and the PTR records pointing at such names, stay `transfer`, frozen for the takeover; every other RRset becomes `ad`, WT-Q9). `{\"to\": \"secondary\", \"primaries\": [...]}` turns a primary zone back into a secondary of the named primaries; the next transfer replaces every record. One change set per zone; audited as `dns.zone.flip` with the counts by origin. A catalog zone is refused.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    request_body(content = ZoneFlip, content_type = "application/json"),
    security(("session" = [])),
    responses(
        (status = 200, description = "The zone's kind, serial and RRsets by origin after the flip", body = tenko_core::dns::ZoneFlipReport),
        (status = 400, description = "The request is malformed, or the values are invalid (`sys.invalid_request`, `dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`, or a token was used (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The zone is not of the kind the flip starts from, or is a catalog zone (`dns.zone.flip.not_secondary`, `dns.zone.flip.not_primary`, `dns.zone.flip.catalog`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn flip_dns_zone(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ZoneFlip>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Execute, &ObjectRef::from(id))?;
    needs_a_session(&cx.principal)?;
    body.validate()?;
    Err(not_implemented("POST", "/dns/zones/{id}/flip"))
}

#[utoipa::path(
    post,
    path = "/dns/zones/{id}/release",
    tag = "dns",
    operation_id = "release_dns_zone",
    summary = "Release the frozen names of a primary zone",
    description = "Scope: `dns.write`. Turns every remaining `transfer` RRset of a primary zone into `manual`, or deletes them with `delete`, after listing them with `dry_run`: the names a takeover did not adopt because no mirrored lease or reservation stands behind them. Audited as `dns.zone.release` with the counts. A catalog zone is refused.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    request_body(content = ZoneRelease, content_type = "application/json"),
    responses(
        (status = 200, description = "The names and RRsets released, deleted or (in a dry run) listed", body = tenko_core::dns::ZoneReleaseReport),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The zone is not a primary zone, or is a catalog zone (`dns.zone.flip.not_primary`, `dns.zone.flip.catalog`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn release_dns_zone(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
    ApiJson(_body): ApiJson<ZoneRelease>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Execute, &ObjectRef::from(id))?;
    Err(not_implemented("POST", "/dns/zones/{id}/release"))
}
