//! `GET|PUT /dhcp/settings`: the server settings, with what the security profile makes of
//! the values left to it (TGL-16, P3-Q13).

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use tenko_auth::settings::Profile;
use tenko_core::{Action, dhcp::server_object};
use tenko_dhcp::{
    config::{
        ConfigService,
        settings::{ProfileDefaults, SettingsChange, SettingsRow},
    },
    guard::DhcpProfile,
    limits::Limits,
};
use tenko_store::{ReadView, ReadViewExt};

use super::{Configs, DhcpSettingsItem, DhcpSettingsUpdate, with_etag};
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    routes::auth::{ApiJson, if_match},
    state::AppState,
};

/// The security profile of the installation; Home before setup.
pub(super) fn profile(view: &dyn ReadView) -> Result<Profile, ApiError> {
    Ok(view
        .get_typed(&tenko_auth::model::SETTINGS, &())?
        .map_or(Profile::Home, |(settings, _)| settings.profile))
}

/// What a profile makes of the unset settings (plan section 2.11).
pub(super) fn profile_defaults(profile: Profile) -> ProfileDefaults {
    match profile {
        Profile::Home => ProfileDefaults {
            conflict_detection: true,
            history_days: 30,
            trust_any_relay: false,
            limits: Limits::of_profile(DhcpProfile::Home),
        },
        Profile::Standard => ProfileDefaults {
            conflict_detection: true,
            history_days: 90,
            trust_any_relay: false,
            limits: Limits::of_profile(DhcpProfile::Standard),
        },
        Profile::Hardened => ProfileDefaults {
            conflict_detection: true,
            history_days: 90,
            trust_any_relay: false,
            limits: Limits::of_profile(DhcpProfile::Hardened),
        },
        Profile::Lab => ProfileDefaults {
            conflict_detection: false,
            history_days: 7,
            trust_any_relay: true,
            limits: Limits::of_profile(DhcpProfile::Lab),
        },
    }
}

/// The stored limits over the profile's.
fn effective_limits(stored: &tenko_core::dhcp::DhcpLimits, profile: Limits) -> Limits {
    Limits {
        leases_per_mac: stored.leases_per_mac.unwrap_or(profile.leases_per_mac),
        addresses_per_duid: stored
            .addresses_per_duid
            .unwrap_or(profile.addresses_per_duid),
        prefixes_per_duid: stored
            .prefixes_per_duid
            .unwrap_or(profile.prefixes_per_duid),
        offers_per_second: stored
            .offers_per_second
            .unwrap_or(profile.offers_per_second),
        renew_cache_percent: stored
            .renew_cache_percent
            .unwrap_or(profile.renew_cache_percent),
    }
}

fn item(row: SettingsRow, defaults: ProfileDefaults) -> DhcpSettingsItem {
    DhcpSettingsItem {
        effective_conflict_detection: row
            .settings
            .conflict_detection
            .unwrap_or(defaults.conflict_detection),
        effective_history_days: row.settings.history_days.unwrap_or(defaults.history_days),
        effective_trust_any_relay: row.settings.trusted_relays.is_none()
            && defaults.trust_any_relay,
        effective_limits: effective_limits(&row.settings.limits, defaults.limits).into(),
        settings: row.settings,
        revision: row.revision,
    }
}

#[utoipa::path(
    get,
    path = "/dhcp/settings",
    tag = "dhcp",
    operation_id = "get_dhcp_settings",
    summary = "Get the DHCP server settings",
    description = "Scope: `dhcp.read`. Before the first change the defaults, at revision 0.",
    responses(
        (status = 200, description = "The settings, with their `ETag`", body = DhcpSettingsItem),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dhcp_settings(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &server_object())?;
    let service = configs.get()?;
    let view = service.view(None).await?;
    let row = ConfigService::settings(view.as_ref())?;
    let defaults = profile_defaults(profile(view.as_ref())?);
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row, defaults), revision))
}

#[utoipa::path(
    put,
    path = "/dhcp/settings",
    tag = "dhcp",
    operation_id = "update_dhcp_settings",
    summary = "Change the DHCP server settings",
    description = "Scope: `dhcp.write`. A field left out keeps its value, except `conflict_detection` and `history_days`, which follow the security profile when left out. `trusted_relays` replaces the list of trusted relay agents, each with the links it may name; `clear_trusted_relays` unsets it, so that the profile decides again (every sender for every link under Lab, none otherwise). `limits` replaces the limits per client and per scope whole; a field left out of them follows the profile, zero turns a limit off.",
    params(
        ("If-Match" = Option<String>, Header, description = "The revision the client read (0 before the first change); a stale revision is refused with 412")
    ),
    request_body(content = DhcpSettingsUpdate, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed settings", body = DhcpSettingsItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the settings are invalid (`dhcp.settings.invalid`), or a new trusted relay names every link under the Hardened profile (`dhcp.settings.relay_any_link`), or the lease times are invalid (`dhcp.lease_times.invalid`) or the DDNS settings are invalid (`dhcp.ddns.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The settings changed since they were read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_dhcp_settings(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    headers: HeaderMap,
    ApiJson(body): ApiJson<DhcpSettingsUpdate>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Update, &server_object())?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    let (_, written) = service
        .update_settings(
            &cx,
            SettingsChange {
                lease: body.lease,
                authoritative: body.authoritative,
                ddns: body.ddns,
                conflict_detection: body.conflict_detection,
                history_days: body.history_days,
                trusted_relays: body.trusted_relays,
                clear_trusted_relays: body.clear_trusted_relays,
                limits: body.limits,
            },
            expect,
        )
        .await?;
    let view = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ConfigService::settings(view.as_ref())?;
    let defaults = profile_defaults(profile(view.as_ref())?);
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row, defaults), revision))
}
