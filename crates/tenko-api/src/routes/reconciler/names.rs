//! The name authority of the reconciler: which kinds of sources name a device when they
//! disagree, globally and per site, and the hosts that prefer a source.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /settings/reconciler/name-authority` | 200 [`NameAuthorityView`] | 401, 403, 503 |
//! | `PUT /settings/reconciler/name-authority` | 200 the global [`StoredAuthority`] | 400, 401, 403, 422 `ipam.name_authority.invalid`, 409, 503 |
//! | `DELETE /settings/reconciler/name-authority` | 204, the default order applies again | 401, 403, 409, 503 |
//! | `PUT /settings/reconciler/name-authority/sites/{site}` | 200 the site's [`StoredAuthority`] | 400, 401, 403, 404 `ipam.not_found`, 409, 422, 503 |
//! | `DELETE /settings/reconciler/name-authority/sites/{site}` | 204, the site follows the global rule again | 400, 401, 403, 409, 503 |
//! | `DELETE /settings/reconciler/name-authority/hosts/{host}` | 204, the host prefers no source any more | 400, 401, 403, 404 `ipam.not_found`, 409, 503 |
//!
//! A rule is an ordered list of kinds of sources (`proxmox`, `home_assistant`, `windows`,
//! `dns`, `mdns`, `llmnr`, `unifi`, `scan`, `dhcp`, `other`), the most trusted first, each
//! once; the kinds a rule leaves out rank after it. A site's rule decides for the devices
//! in the networks of the site, the global rule for the others, and without either the
//! default order (Proxmox, Home Assistant, Windows, DNS, mDNS, LLMNR, UniFi, scan). A host's
//! preference comes from an approval with `remember: host` and puts its source first for
//! that host. Every endpoint is for administrators ([`Action::Administer`] on the system);
//! the changes are audited as `ipam.name_authority.set`, `ipam.name_authority.clear` and
//! `ipam.name_preference.clear`, and the reconciler's next run applies them.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tenko_core::{Action, HostId, SiteId};
use tenko_ipam::reconcile::names::{self, NameAuthorityRule, NameAuthorityView, StoredAuthority};
use tenko_store::ReadConsistency;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::super::{
    common::{IpamJson, IpamPath},
    system::system_object,
};
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The routes: `/settings/reconciler/name-authority`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(
            get_name_authority,
            set_name_authority,
            clear_name_authority
        ))
        .routes(routes!(set_site_name_authority, clear_site_name_authority))
        .routes(routes!(clear_name_preference))
}

fn coded(error: tenko_ipam::IpamError) -> ApiError {
    ApiError::from_coded_error(error.into_coded())
}

/// Shows the name authority: the default order, the global rule and the rules of sites,
/// and the hosts that prefer a source. Administrators only.
#[utoipa::path(
    get,
    path = "/settings/reconciler/name-authority",
    tag = "reconciler",
    operation_id = "get_name_authority",
    summary = "Get the name authority",
    responses(
        (status = 200, description = "The default order, the stored rules and the hosts' preferred sources", body = NameAuthorityView),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn get_name_authority(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
) -> Result<Json<NameAuthorityView>, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    let view = state
        .store()
        .read(ReadConsistency::Local)
        .await
        .map_err(|error| coded(error.into()))?;
    Ok(Json(names::view_of(view.as_ref()).map_err(coded)?))
}

/// Sets the global rule: the kinds of sources, the most trusted first, each once.
#[utoipa::path(
    put,
    path = "/settings/reconciler/name-authority",
    tag = "reconciler",
    operation_id = "set_name_authority",
    summary = "Set the global name authority",
    request_body = NameAuthorityRule,
    responses(
        (status = 200, description = "The global rule", body = StoredAuthority),
        (status = 400, description = "The body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A concurrent change won (`sys.store.precondition_failed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The order is empty or names a kind twice (`ipam.name_authority.invalid`, parameter `field`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn set_name_authority(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    IpamJson(body): IpamJson<NameAuthorityRule>,
) -> Result<Json<StoredAuthority>, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    let rule = names::set_rule(state.store().as_ref(), &ctx, None, body.order)
        .await
        .map_err(coded)?;
    Ok(Json(rule))
}

/// Removes the global rule, so the default order applies again.
#[utoipa::path(
    delete,
    path = "/settings/reconciler/name-authority",
    tag = "reconciler",
    operation_id = "clear_name_authority",
    summary = "Remove the global name authority",
    responses(
        (status = 204, description = "The default order applies"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A concurrent change won (`sys.store.precondition_failed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn clear_name_authority(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
) -> Result<Response, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    names::clear_rule(state.store().as_ref(), &ctx, None)
        .await
        .map_err(coded)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Sets the rule of a site, which decides for the devices in the networks of the site.
#[utoipa::path(
    put,
    path = "/settings/reconciler/name-authority/sites/{site}",
    tag = "reconciler",
    operation_id = "set_site_name_authority",
    summary = "Set a site's name authority",
    params(("site" = String, Path, description = "Site identifier")),
    request_body = NameAuthorityRule,
    responses(
        (status = 200, description = "The site's rule", body = StoredAuthority),
        (status = 400, description = "The body or the site identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such site (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A concurrent change won (`sys.store.precondition_failed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The order is empty or names a kind twice (`ipam.name_authority.invalid`, parameter `field`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn set_site_name_authority(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    IpamPath(site): IpamPath<SiteId>,
    IpamJson(body): IpamJson<NameAuthorityRule>,
) -> Result<Json<StoredAuthority>, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    let rule = names::set_rule(state.store().as_ref(), &ctx, Some(site), body.order)
        .await
        .map_err(coded)?;
    Ok(Json(rule))
}

/// Removes the rule of a site, so the global rule decides there again.
#[utoipa::path(
    delete,
    path = "/settings/reconciler/name-authority/sites/{site}",
    tag = "reconciler",
    operation_id = "clear_site_name_authority",
    summary = "Remove a site's name authority",
    params(("site" = String, Path, description = "Site identifier")),
    responses(
        (status = 204, description = "The global rule decides for the site"),
        (status = 400, description = "The site identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A concurrent change won (`sys.store.precondition_failed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn clear_site_name_authority(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    IpamPath(site): IpamPath<SiteId>,
) -> Result<Response, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    names::clear_rule(state.store().as_ref(), &ctx, Some(site))
        .await
        .map_err(coded)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Forgets the source a host prefers; its name stays, and the names it was chosen from do
/// not open a proposal again.
#[utoipa::path(
    delete,
    path = "/settings/reconciler/name-authority/hosts/{host}",
    tag = "reconciler",
    operation_id = "clear_name_preference",
    summary = "Forget a host's preferred source",
    params(("host" = String, Path, description = "Host identifier")),
    responses(
        (status = 204, description = "The host prefers no source"),
        (status = 400, description = "The host identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The host prefers no source (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A concurrent change won (`sys.store.precondition_failed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store is unavailable", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn clear_name_preference(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    IpamPath(host): IpamPath<HostId>,
) -> Result<Response, ApiError> {
    state.authorize(&ctx.principal, Action::Administer, &system_object())?;
    names::clear_preference(state.store().as_ref(), &ctx, host)
        .await
        .map_err(coded)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
