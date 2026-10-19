//! `GET /dns/zones/{id}/dnssec` and `POST /dns/zones/{id}/dnssec/rollover` (WP6.3, ADR
//! 0018): the signing state of a zone and the start of a key rollover.
//!
//! The state shows the keys without their private parts, each with its DNSKEY record, the
//! DS records the parent should hold (SHA-256, for the KSK or CSK that is published or
//! active), the serial last signed, the earliest signature expiry, the rollover that runs
//! and the health findings of the zone. Signing is switched on and off through the zone's
//! `dnssec` policy (`PATCH /dns/zones/{id}`); the signer acts on the change.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, ObjectKind, ObjectRef, Timestamp,
    dns::{DnssecKeyMeta, RecordData, ZoneId},
};
use tenko_dns::{
    dnssec::{crypto, health, keys, rollover},
    zone::ZoneService,
};

use super::{
    DnsJobStarted, DnssecFinding, DnssecKeyItem, DnssecStatus, RolloverRequest, Zones, parse_id,
};
use crate::{
    API_BASE,
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    routes::auth::ApiJson,
    state::AppState,
};

fn key_item(key: &DnssecKeyMeta) -> DnssecKeyItem {
    DnssecKeyItem {
        id: key.id,
        role: key.role,
        algorithm: key.algorithm,
        key_tag: key.key_tag,
        state: key.state,
        dnskey: crypto::dnskey(key.role, key.algorithm, &key.public_key.0),
        published: key.published,
        activated: key.activated,
        retired: key.retired,
    }
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}/dnssec",
    tag = "dns",
    operation_id = "get_dns_zone_dnssec",
    summary = "Get the signing state and keys of a zone",
    description = "Scope: `dns.read`. The keys without private parts, the DS records for the \
                   parent, the serial last signed, the earliest signature expiry, the \
                   rollover that runs and the health findings (OPS-09). A zone that was never \
                   signed answers its mode and no keys.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    responses(
        (status = 200, description = "The signing state, the keys without private parts and the DS records", body = DnssecStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dns_zone_dnssec(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let view = service.view(None).await?;
    let zone = ZoneService::zone(view.as_ref(), id)?.zone;
    let state = ZoneService::sign_state(view.as_ref(), id)?.map(|(state, _)| state);
    let status = match state {
        Some(state) => DnssecStatus {
            zone: id,
            mode: zone.dnssec.mode,
            keys: state.keys.iter().map(key_item).collect(),
            ds: keys::ds_records(&zone.name, &state),
            signed_serial: state.signed_serial,
            last_signed: state.last_signed,
            expires: state.expires,
            next_resign: state.next_resign,
            rollover_job: state.rollover_job,
            findings: health::findings(&zone, &state, Timestamp::now())
                .into_iter()
                .map(|finding| DnssecFinding {
                    code: finding.code.to_owned(),
                    detail: finding.detail,
                })
                .collect(),
        },
        None => DnssecStatus {
            zone: id,
            mode: zone.dnssec.mode,
            keys: Vec::new(),
            ds: Vec::<RecordData>::new(),
            signed_serial: None,
            last_signed: None,
            expires: None,
            next_resign: None,
            rollover_job: None,
            findings: Vec::new(),
        },
    };
    Ok((StatusCode::OK, Json(status)).into_response())
}

#[utoipa::path(
    post,
    path = "/dns/zones/{id}/dnssec/rollover",
    tag = "dns",
    operation_id = "start_dns_key_rollover",
    summary = "Start a DNSSEC key rollover",
    description = "Scope: `dns.keys`. Starts the job `dns.dnssec.rollover` for the role: a ZSK \
                   rolls by pre-publication (publish, wait the DNSKEY TTL, sign with the new \
                   key, wait the largest TTL, retire the old one), a KSK or CSK by double KSK \
                   with CDS and CDNSKEY (publish beside the old key, wait, a person confirms \
                   the new DS at the parent, the new key takes over, wait, retire). Audited as \
                   `dns.key.rollover`; every step as `dns.dnssec.rollover`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    request_body(content = RolloverRequest, content_type = "application/json"),
    responses(
        (status = 202, description = "The rollover job; follow it at the `Location`", body = DnsJobStarted),
        (status = 400, description = "The request is malformed, or the zone does not use the role (`dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The zone is not signed online (`dns.dnssec.not_online`) or a rollover runs (`dns.dnssec.rollover_running`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn start_dns_key_rollover(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<RolloverRequest>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(
        &cx.principal,
        Action::Execute,
        &anywhere(ObjectKind::DnsKey),
    )?;
    let service = zones.get()?;
    let role = body.role;
    let job = service
        .start_rollover(&cx, id, role, |zone, _| rollover::job_spec(zone, role))
        .await?;
    let mut response = (StatusCode::ACCEPTED, Json(DnsJobStarted { job_id: job })).into_response();
    if let Ok(location) = HeaderValue::from_str(&format!("{API_BASE}/jobs/{job}")) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    Ok(response)
}
