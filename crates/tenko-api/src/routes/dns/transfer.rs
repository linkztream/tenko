//! `GET|POST /dns/zones/{id}/transfer`: the transfer state of a zone and a refresh now
//! (WP6.1, DNS-09).
//!
//! The state comes from the leader service `dns.transfer` (`tenko_dns::zone::secondary`),
//! which the server adds as the request extension `SecondaryService`: the serial held, each
//! primary's last success and last error, the next refresh and the expiry. A zone the
//! service has not seen (a primary zone, or a follower controller) shows the serial in the
//! store and its primaries without results. `POST` queues a refresh of a secondary zone at
//! once, audited as `dns.transfer.trigger`, and answers 202 with the state.

use axum::{
    Json,
    extract::{FromRequestParts, Path, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use tenko_core::{Action, CodedError, ObjectRef, dns::ZoneId};
use tenko_dns::zone::{
    ZoneService,
    secondary::{SecondaryService, TransferState},
};

use super::{PrimaryState, TransferStatus, Zones, parse_id};
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The secondary service of the request, from the extension the server adds while the DNS
/// module runs.
pub(crate) struct Secondaries(Option<SecondaryService>);

impl Secondaries {
    fn get(self) -> Result<SecondaryService, ApiError> {
        self.0.ok_or_else(|| {
            ApiError::from_coded_error(
                CodedError::new(
                    tenko_core::dns::codes::MODULE_DISABLED,
                    409,
                    "the transfer service does not run on this server",
                )
                .with_title("DNS module disabled"),
            )
        })
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Secondaries {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Secondaries(
            parts.extensions.get::<SecondaryService>().cloned(),
        )))
    }
}

fn status(zone: ZoneId, state: TransferState) -> TransferStatus {
    TransferStatus {
        zone,
        serial: state.serial,
        primaries: state
            .primaries
            .into_iter()
            .map(|primary| PrimaryState {
                address: primary.address.to_string(),
                last_success: primary.last_success,
                last_error: primary.last_error,
            })
            .collect(),
        next_refresh: state.next_refresh,
        expires: state.expires,
        running: state.running,
    }
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}/transfer",
    tag = "dns",
    operation_id = "get_dns_zone_transfer",
    summary = "Get the transfer state of a zone",
    description = "Scope: `dns.read`. The serial held, each primary's last success and the stable code of its last failure (`dns.transfer.failed`, `dns.transfer.tsig`, `dns.transfer.refused`), the next refresh and the expiry, as the leader's transfer service sees them; a zone it has not seen shows the serial in the store.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    responses(
        (status = 200, description = "The serial, the sources and the refresh timers", body = TransferStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dns_zone_transfer(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    secondaries: Secondaries,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let secondaries = secondaries.get()?;
    let view = service.view(None).await?;
    let zone = ZoneService::zone(view.as_ref(), id)?.zone;
    let state = secondaries.state(view.as_ref(), &zone)?;
    Ok((StatusCode::OK, Json(status(id, state))).into_response())
}

#[utoipa::path(
    post,
    path = "/dns/zones/{id}/transfer",
    tag = "dns",
    operation_id = "trigger_dns_zone_transfer",
    summary = "Transfer a secondary zone now",
    description = "Scope: `dns.write`. Queues a refresh of a secondary zone on the leader's transfer service at once (IXFR with the AXFR fallback), audited as `dns.transfer.trigger`; the answer is the state when the refresh was queued.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    responses(
        (status = 202, description = "The transfer is queued", body = TransferStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The zone is not a secondary zone (`dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn trigger_dns_zone_transfer(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    secondaries: Secondaries,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Execute, &ObjectRef::from(id))?;
    zones.get()?;
    let state = secondaries.get()?.trigger(&cx, id).await?;
    Ok((StatusCode::ACCEPTED, Json(status(id, state))).into_response())
}
