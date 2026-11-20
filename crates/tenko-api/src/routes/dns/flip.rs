//! `POST /dns/zones/{id}/flip` and `POST /dns/zones/{id}/release` (Windows takeover plan
//! section 2.6, ADR 0034; MIG-04): the flip of a zone between secondary and primary in
//! place, and the release of the frozen (`transfer`) names a takeover did not adopt, on the
//! zone service (`tenko_dns::zone::flip`).
//!
//! The flip changes which server is the authority of a zone, and the release deletes
//! records or changes who may write the names a takeover is to adopt, so both need an
//! interactive session that signed in within five minutes, as creating a mirror does: after
//! the scope check a token is refused with `auth.forbidden` and an older sign-in with
//! `auth.step_up_required`; the flip declares `security(("session" = []))`, and the
//! release keeps the default, since a token may run its dry run. A release's dry run changes
//! nothing and lists only names a `dns.read` caller reads in the records, so it needs the
//! scope alone. A flip to secondary names the servers the node will connect to, so their
//! addresses pass the egress policy of server-side fetches and their TSIG keys need
//! `dns.keys`, by the same checks as a zone's `source`.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tenko_auth::AuthService;
use tenko_core::{
    Action, CodedError, ObjectRef, Principal, RequestCtx,
    dns::{SecondarySource, ZoneFlip, ZoneId, ZoneRelease},
};

use super::{
    Zones,
    lists::Egress,
    parse_id,
    zones::{check_key_references, check_primaries},
};
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    routes::{auth::ApiJson, not_implemented},
    state::AppState,
};

type Auth = Option<Extension<Arc<AuthService>>>;

/// An interactive session that signed in within five minutes: a token is refused with 403
/// `auth.forbidden`, an older sign-in with 403 `auth.step_up_required`.
async fn needs_a_fresh_session(auth: Auth, cx: &RequestCtx, path: &str) -> Result<(), ApiError> {
    if !matches!(cx.principal, Principal::User { .. }) {
        return Err(ApiError::from_coded_error(
            CodedError::new(
                "auth.forbidden",
                403,
                "this needs an interactive session; a token is refused",
            )
            .with_title("Forbidden"),
        ));
    }
    let Some(Extension(auth)) = auth else {
        return Err(not_implemented("POST", path));
    };
    auth.require_fresh_session(cx).await?;
    Ok(())
}

#[utoipa::path(
    post,
    path = "/dns/zones/{id}/flip",
    tag = "dns",
    operation_id = "flip_dns_zone",
    summary = "Flip a zone between secondary and primary in place",
    description = "Scope: `dns.write`, an interactive session that signed in within five minutes. `{\"to\": \"primary\", \"soa\": {...}, \"ns\": [...]}` turns a secondary zone into a primary zone: the transfer service stops refreshing it, the SOA `mname` and `rname` and the apex NS set become the given values, the serial continues from the copy's, and the records stay with their provenance (the A, AAAA and DHCID RRsets of a name that holds a DHCID RRset and nothing but A, AAAA and DHCID, and the PTR records pointing at such names in a zone of the same tenant, stay `transfer`, frozen for the takeover; every other RRset of the copy becomes `ad`, WT-Q9). `{\"to\": \"secondary\", \"primaries\": [...]}` turns a primary zone back into a secondary of the named primaries: the next transfer replaces every record, whatever its serial, and the owners of its names are removed; a primary's address passes the egress policy of server-side fetches and a key needs `dns.keys`. One change set per zone of at most 20,000 RRsets, 50,000 records and 8 MiB, only a zone with the scope `default` alone, and one flip or release at a time on a node; audited as `dns.zone.flip` with the RRsets by origin. A catalog zone is refused.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    request_body(content = ZoneFlip, content_type = "application/json"),
    security(("session" = [])),
    responses(
        (status = 200, description = "The zone's kind, serial and RRsets by origin after the flip", body = tenko_core::dns::ZoneFlipReport),
        (status = 400, description = "The request is malformed, or the values are invalid (`sys.invalid_request`, `dns.zone.invalid`; `source.primaries` for an address the egress policy refuses, `scopes` for a zone with other scopes, `rrsets` for a zone past one change set, `dnssec` for a signed copy, `kind` for a copy that is missing or written in part, `update.kerberos` and `dnssec.mode` for a setting a secondary zone cannot keep)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write` (or `dns.keys` for a key it names), or a token was used (`auth.forbidden`), or the sign-in is older than five minutes (`auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone or key (`dns.zone.not_found`, `dns.key.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The zone is not of the kind the flip starts from, or is a catalog zone (`dns.zone.flip.not_secondary`, `dns.zone.flip.not_primary`, `dns.zone.flip.catalog`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "A flip or a release runs on this node (`dns.zone.flip.busy`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn flip_dns_zone(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    auth: Auth,
    Egress(policy): Egress,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ZoneFlip>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Execute, &ObjectRef::from(id))?;
    needs_a_fresh_session(auth, &cx, "/dns/zones/{id}/flip").await?;
    body.validate()?;
    let service = zones.get()?;
    if let ZoneFlip::Secondary { primaries } = &body {
        let keys: Vec<_> = primaries.iter().filter_map(|p| p.key.as_ref()).collect();
        check_key_references(&app, &cx, &service, keys).await?;
        let source = SecondarySource {
            primaries: primaries.clone(),
        };
        check_primaries(&policy, Some(&source))?;
    }
    let report = service.flip(&cx, id, &body).await?;
    Ok((StatusCode::OK, Json(report)).into_response())
}

#[utoipa::path(
    post,
    path = "/dns/zones/{id}/release",
    tag = "dns",
    operation_id = "release_dns_zone",
    summary = "Release the frozen names of a primary zone",
    description = "Scope: `dns.write`, and for anything but a dry run an interactive session that signed in within five minutes. Turns every remaining `transfer` RRset of a primary zone into `manual`, or deletes them with `delete` (with a serial step and a journal entry), after listing them with `dry_run`: the names a takeover did not adopt because no mirrored lease or reservation stands behind them. At most 20,000 frozen RRsets (50,000 records, 8 MiB) in one change set, and one flip or release at a time on a node. Audited as `dns.zone.release` with the counts. A catalog zone is refused.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    request_body(content = ZoneRelease, content_type = "application/json"),
    responses(
        (status = 200, description = "The names and RRsets released, deleted or (in a dry run) listed", body = tenko_core::dns::ZoneReleaseReport),
        (status = 400, description = "The request is malformed (`sys.invalid_request`), or the frozen RRsets pass one change set (`dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`, or a token was used for more than a dry run (`auth.forbidden`), or the sign-in is older than five minutes (`auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The zone is not a primary zone, or is a catalog zone (`dns.zone.flip.not_primary`, `dns.zone.flip.catalog`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "A flip or a release runs on this node (`dns.zone.flip.busy`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn release_dns_zone(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    auth: Auth,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ZoneRelease>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Execute, &ObjectRef::from(id))?;
    if !body.dry_run {
        needs_a_fresh_session(auth, &cx, "/dns/zones/{id}/release").await?;
    }
    let report = zones.get()?.release(&cx, id, body).await?;
    Ok((StatusCode::OK, Json(report)).into_response())
}

#[cfg(test)]
mod tests;
