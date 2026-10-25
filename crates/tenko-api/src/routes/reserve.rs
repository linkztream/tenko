//! Reserving an address in DHCP.
//!
//! Area: addresses. Requirements: DHCP-01, IPAM-14, IPAM-18, IPAM-23.
//!
//! A DHCP reservation is derived from IPAM's rows (docs/dhcp.md section 2), so reserving an
//! address writes IPAM rows: the host becomes (or is created) `reserved`, the interface gets
//! the MAC address and client identifier, and the address is bound to the interface with
//! status `active` or `planned`. The two routes do that in one plan, one store batch and one
//! audit record `ipam.address.reserve` ([`tenko_ipam::reserve`]):
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `POST /addresses/{id}/reserve` | 200 reserve response | 400 `ipam.validation`, 403, 404 `ipam.not_found`, `dhcp.scope.not_found`, 409 `dhcp.reservation.conflict`, `dhcp.reservation.no_identity`, `ipam.address.in_dhcp_pool`, `ipam.name_taken`, `ipam.reference_missing`, `ipam.object_deleted`, `ipam.status.transition`, 412 `ipam.revision_mismatch`, 423 `ipam.host.locked` |
//! | `POST /addresses/reserve` | 200 reserve response | as above; the address is named by `ip` (and `vrf`) and created when IPAM does not hold it |
//!
//! Each change is checked like the IPAM write it is: `update` on an existing host,
//! interface and address, `create` on a new host, interface or address; a request that
//! changes nothing is checked as an update of the address. No DHCP permission is asked for:
//! the rows are IPAM's. `?dry_run=true` answers the plan without writing, and
//! `?acknowledge=` acknowledges warnings as on every IPAM write. The routes take no
//! `Idempotency-Key`: a repeated request with an existing host finds the reservation in
//! place and changes nothing.

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tenko_core::{
    Action, AddressId, JobId, PrefixId, RequestCtx, Revision,
    audit::AuditAction,
    ipam::{Address, Host, Interface},
};
use tenko_ipam::{
    Entity, IpamPlan, PlanView, PlanWarning, query,
    reserve::{self, Reservation, ReserveInput, ReserveTarget},
};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::common::{
    Ipam, IpamHandle, IpamJson, IpamPath, WriteParams, authorize, command_access, write_args,
};
use crate::{
    extract::Ctx,
    list::Filters,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The audit action of a reservation.
pub(crate) const RESERVE_ACTION: AuditAction = AuditAction::from_static("ipam.address.reserve");

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(reserve_address))
        .routes(routes!(reserve_address_by_value))
}

/// The answer of a reservation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub(crate) struct ReserveResponse {
    /// The address after the change; on a dry run, as it would be.
    pub(crate) address: Option<Address>,
    /// The host after the change; on a dry run, as it would be.
    pub(crate) host: Option<Host>,
    /// The interface after the change; on a dry run, as it would be.
    pub(crate) interface: Option<Interface>,
    /// The prefix whose DHCP scope serves the reservation.
    #[schema(value_type = Option<String>)]
    pub(crate) scope: Option<PrefixId>,
    /// The revision that committed the change; `null` on a dry run.
    #[schema(value_type = Option<u64>)]
    pub(crate) revision: Option<Revision>,
    /// The inline job that carried the change; `null` on a dry run and when nothing
    /// changed.
    pub(crate) job_id: Option<JobId>,
    /// Whether this is a dry run.
    pub(crate) dry_run: bool,
    /// Whether the request changed nothing: the reservation was in place.
    pub(crate) unchanged: bool,
    /// Warnings of the plan.
    pub(crate) warnings: Vec<PlanWarning>,
    /// The plan (dry runs only).
    pub(crate) plan: Option<PlanView>,
}

/// Reserves an existing address in DHCP: the host becomes `reserved`, the interface gets
/// the MAC address and client identifier, the address is bound to it as `active` or
/// `planned`, in one batch with one audit record `ipam.address.reserve`.
#[utoipa::path(
    post,
    path = "/addresses/{id}/reserve",
    tag = "addresses",
    operation_id = "reserve_address",
    summary = "Reserve an address in DHCP",
    description = "Writes the IPAM rows a DHCP reservation is derived from (docs/dhcp.md section 2) in one batch: the host (`host`, or `new_host` for a new one, else the host of the address's interface) becomes `reserved`; the interface (`interface`, or `new_interface`, else the address's interface on that host, else the host's only interface, else a new `eth0`) gets `mac` and `client_id`; the address is bound to it with `status` `active` or `planned`. The address must lie in a prefix with a DHCP scope; the scope need not be enabled. Checked like the IPAM writes it makes; one audit record `ipam.address.reserve`.",
    params(("id" = String, Path, description = "Address identifier"), WriteParams),
    request_body = ReserveInput,
    responses(
        (status = 200, description = "The reservation's rows after the change, or the plan of a dry run", body = ReserveResponse),
        (status = 400, description = "Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`, `auth.out_of_scope`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such address (`ipam.not_found`), or its prefix has no DHCP scope (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Another reserved host holds the address or presents the client identity in the scope (`dhcp.reservation.conflict`, IPAM-23), the interface has no MAC address or client identifier (`dhcp.reservation.no_identity`, IPAM-18), the address lies in a DHCP pool (`ipam.address.in_dhcp_pool`), or another IPAM conflict (`ipam.name_taken`, `ipam.reference_missing`, `ipam.object_deleted`, `ipam.status.transition`, `ipam.plan.unacknowledged`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "An object changed between the read and the write (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "The host is locked against automation (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn reserve_address(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<AddressId>,
    filters: Filters,
    IpamJson(input): IpamJson<ReserveInput>,
) -> Result<Response, ApiError> {
    reserve(
        &app,
        cx,
        &ipam,
        ReserveTarget::Address(id),
        &input,
        &filters,
    )
    .await
}

/// Reserves an address named by value in DHCP; an address IPAM does not hold yet is
/// created on the interface. Otherwise as `POST /addresses/{id}/reserve`.
#[utoipa::path(
    post,
    path = "/addresses/reserve",
    tag = "addresses",
    operation_id = "reserve_address_by_value",
    summary = "Reserve an address in DHCP by value",
    description = "As `POST /addresses/{id}/reserve`, with the address named by `ip` and `vrf` (the default VRF when absent), for example from a DHCP lease. An address IPAM does not hold yet is created on the interface with `status` (`active` when absent).",
    params(WriteParams),
    request_body = ReserveInput,
    responses(
        (status = 200, description = "The reservation's rows after the change, or the plan of a dry run", body = ReserveResponse),
        (status = 400, description = "Invalid body or parameter, or no `ip` (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`, `auth.out_of_scope`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The address's prefix has no DHCP scope (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "As for `POST /addresses/{id}/reserve`, plus `ipam.address.no_prefix` and `ipam.address.network_or_broadcast` for a new address", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "An object changed between the read and the write (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "The host is locked against automation (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn reserve_address_by_value(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
    IpamJson(input): IpamJson<ReserveInput>,
) -> Result<Response, ApiError> {
    reserve(&app, cx, &ipam, ReserveTarget::ByValue, &input, &filters).await
}

async fn reserve(
    app: &AppState,
    mut cx: RequestCtx,
    ipam: &IpamHandle,
    target: ReserveTarget,
    input: &ReserveInput,
    filters: &Filters,
) -> Result<Response, ApiError> {
    let args = write_args(filters, false)?;
    // The commands carry identifiers chosen per request, so a receipt could never match.
    cx.idempotency = None;
    let view = ipam.view(None).await?;
    let reservation = reserve::commands(view.as_ref(), target, input)?;
    drop(view);
    if reservation.commands.is_empty() {
        authorize(app, &cx, Action::Update, reservation.address.into())?;
    }
    for command in &reservation.commands {
        let (action, object) = command_access(command);
        authorize(app, &cx, action, object)?;
    }
    let mut options = args.options.clone();
    options.reservation = Some(reservation.check);
    options.audit_as = Some(RESERVE_ACTION);
    if args.dry_run {
        let plan = ipam.preview(&cx, &reservation.commands, &options).await?;
        return Ok(Json(planned(&reservation, &plan)).into_response());
    }
    let applied = ipam.execute(&cx, &reservation.commands, &options).await?;
    let view = ipam.view(Some(applied.revision)).await?;
    let address = query::get::<Address>(view.as_ref(), reservation.address)?;
    let host = query::get::<Host>(view.as_ref(), reservation.host)?;
    let interface = query::get::<Interface>(view.as_ref(), reservation.interface)?;
    Ok(Json(ReserveResponse {
        scope: Some(address.prefix),
        address: Some(address),
        host: Some(host),
        interface: Some(interface),
        revision: Some(applied.revision),
        unchanged: applied.job_id.is_none(),
        job_id: applied.job_id,
        dry_run: false,
        warnings: applied.warnings,
        plan: None,
    })
    .into_response())
}

/// The answer of a dry run: the objects as the plan leaves them.
fn planned(reservation: &Reservation, plan: &IpamPlan) -> ReserveResponse {
    let address = after::<Address>(plan, reservation.address.into());
    ReserveResponse {
        scope: address.as_ref().map(|address| address.prefix),
        address,
        host: after::<Host>(plan, reservation.host.into()),
        interface: after::<Interface>(plan, reservation.interface.into()),
        revision: None,
        job_id: None,
        dry_run: true,
        unchanged: plan.is_empty(),
        warnings: plan.warnings.clone(),
        plan: Some(plan.view()),
    }
}

/// The last state the plan gives an object it changes; none when it does not change it.
fn after<T: Entity>(plan: &IpamPlan, object: tenko_core::ObjectRef) -> Option<T> {
    plan.changes
        .iter()
        .rev()
        .find(|change| change.object == object)
        .and_then(|change| change.after.clone())
        .and_then(T::from_object)
}

#[cfg(test)]
mod tests;
