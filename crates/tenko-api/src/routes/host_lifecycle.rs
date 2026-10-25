//! The lifecycle of a host: decommission and reinstate.
//!
//! Area: hosts. Requirements: IPAM-05, IPAM-12.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `POST /hosts/{id}/decommission` | 200 write response with the decommissioned host | 400 `ipam.validation` (a reason over 1,024 bytes or with control characters), 403, 404, 409 `ipam.host.decommissioned`, `ipam.object_deleted`, 412, 423 |
//! | `POST /hosts/{id}/reinstate` | 200 write response with the active host, warnings `ipam.host.reinstate_skipped` | 403, 404, 409 `ipam.host.not_decommissioned`, `ipam.object_deleted`, 412, 423 |
//!
//! A decommission releases the host's addresses (they are unassigned, which ends the DHCP
//! reservation they made, and their DNS names are removed unless `keep_dns` is set, so the
//! DNS actuator removes the records), its facts raise no proposals any more, and the
//! default hosts list leaves it out (`lifecycle=decommissioned` lists it). A reinstatement
//! binds back the released addresses that are still free. Both need the right to delete
//! the host, take `If-Match`, `dry_run` and `acknowledge` like every IPAM write, and are
//! audited as `ipam.host.decommission` and `ipam.host.reinstate` beside the address
//! updates they make.

use axum::{extract::State, http::HeaderMap, response::Response};
use serde::{Deserialize, Serialize};
use tenko_core::{Action, HostId, ObjectRef, ipam::Host};
use tenko_ipam::{IpamCommand, command::DecommissionHost};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::common::{
    IfMatch, Ipam, IpamJson, IpamPath, WriteParams, WriteResponse, authorize, if_match, write_args,
    write_one,
};
use crate::{
    extract::Ctx,
    list::Filters,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(decommission_host))
        .routes(routes!(reinstate_host))
}

/// What a decommission records and whether it keeps the DNS names.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecommissionBody {
    /// Why, for the list of decommissioned hosts (at most 1,024 bytes).
    #[serde(default)]
    reason: Option<String>,
    /// Keep the DNS names of the released addresses, so their records stay. By default the
    /// names and their records are removed.
    #[serde(default)]
    keep_dns: bool,
}

/// Decommissions a host: its addresses are released (unassigned; their DNS names removed
/// unless `keep_dns`), its facts raise no proposals and the default lists leave it out.
#[utoipa::path(
    post,
    path = "/hosts/{id}/decommission",
    tag = "hosts",
    operation_id = "decommission_host",
    summary = "Decommission a host",
    params(("id" = String, Path, description = "Host identifier"), WriteParams, IfMatch),
    request_body = DecommissionBody,
    responses(
        (status = 200, description = "The decommissioned host (`decommissioned` is set), with `ETag`, or the plan of a dry run", body = WriteResponse<Host>),
        (status = 400, description = "Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed: deleting the host is (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such host (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The host is decommissioned already, or deleted (`ipam.host.decommissioned`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "The host is locked against automation (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn decommission_host(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<HostId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(body): IpamJson<DecommissionBody>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    let object: ObjectRef = id.into();
    authorize(&app, &cx, Action::Delete, object)?;
    let command = IpamCommand::DecommissionHost(DecommissionHost {
        host: id,
        reason: body.reason,
        keep_dns: body.keep_dns,
        expected,
    });
    write_one::<Host>(&ipam, &cx, vec![command], &args, false).await
}

/// Reinstates a decommissioned host: the addresses it released that are still free are
/// bound again with the DNS names they lost; one that is not is a warning.
#[utoipa::path(
    post,
    path = "/hosts/{id}/reinstate",
    tag = "hosts",
    operation_id = "reinstate_host",
    summary = "Reinstate a decommissioned host",
    params(("id" = String, Path, description = "Host identifier"), WriteParams, IfMatch),
    responses(
        (status = 200, description = "The active host, with `ETag`, or the plan of a dry run; the warning `ipam.host.reinstate_skipped` names each address that did not come back", body = WriteResponse<Host>),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed: deleting the host is (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such host (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The host is not decommissioned, or deleted (`ipam.host.not_decommissioned`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "The host is locked against automation (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn reinstate_host(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<HostId>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    let object: ObjectRef = id.into();
    authorize(&app, &cx, Action::Delete, object)?;
    let command = IpamCommand::ReinstateHost { host: id, expected };
    write_one::<Host>(&ipam, &cx, vec![command], &args, false).await
}

#[cfg(test)]
#[path = "host_lifecycle_tests.rs"]
mod tests;
