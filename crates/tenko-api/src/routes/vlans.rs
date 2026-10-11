//! VLAN provisioning and the prefixes of a VLAN.
//!
//! Area: tenancy. Owner: WP2.7. Requirements: IPAM-03, CONN-06, CONN-08, CONN-09, TGL-20,
//! API-04, API-09.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `POST /vlans/provision?dry_run=true` | 200 [`VlanProvisionPreview`] | 400, 403, 404, 409, 502, 503 |
//! | `POST /vlans/provision` | 202 [`VlanProvisionSubmitted`]: one background job | 400, 403, 404, 409 `ipam.plan.unacknowledged`, 422, 502, 503 |
//! | `GET /vlans/{id}/prefixes` | 200 page of the prefixes linked to the VLAN | 400, 403, 404 |
//!
//! A provision creates a VLAN (or names an existing one), optionally a network prefix for
//! it, and gets the network onto the switches and access points: through the
//! network-controller connector (a plan with the controller's read-back diff, then in the
//! job a dry run, the write and a read-back that must show no difference), or as a manual
//! step when no controller is configured, writes are off for it (TGL-20) or the request
//! says `manual`. The preview shows the IPAM plan, the controller's diff and the steps; a
//! submit computes it again (it does not take the client's copy), refuses while a warning
//! that needs an acknowledgement is not listed in `acknowledge`, and starts the job, which
//! then appears in `GET /jobs`. The guardrails of the connector host refuse the management
//! VLAN with 409 `connect.guardrail.protected_vlan`. The rules are documented in
//! `tenko_ipam::vlan`.
//!
//! `Idempotency-Key` makes a submit safe to repeat: the same request under the same key
//! answers the first result with `replayed: true`.
//!
//! Linking a prefix to a VLAN is a change of the prefix (`PATCH /prefixes/{id}` with
//! `vlan`); `GET /vlans/{id}/prefixes` lists the prefixes linked to a VLAN, ordered by VRF
//! and network, with `deleted=include` the soft-deleted ones too.
//!
//! The server adds the network controllers (`Arc<tenko_ipam::vlan::Controllers>`) as a
//! request extension; without it a provision answers 503 `ipam.vlan.controllers_unavailable`.
//! [`host::HostControllers`] puts the connector host behind that slot.
//!
//! # Authorization
//!
//! With an [`Authorizer`](tenko_core::Authorizer) in the state, a provision needs
//! [`Action::Create`] on VLANs for a new VLAN or [`Action::Update`] on the named VLAN,
//! [`Action::Create`] on prefixes when it creates one and, for a submit,
//! [`Action::Execute`] on jobs and on the connector it names; a principal whose writes are
//! limited to a scope is refused (the network controller is global-only in Phase 1). The
//! prefix list needs [`Action::Read`] on the VLAN and lists the prefixes the principal
//! reads.

pub mod host;

use std::sync::Arc;

use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use tenko_core::{
    Action, CodedError, Denied, DenyReason, ObjectKind, ObjectRef, RequestCtx, Revision, VlanId,
    ipam::Prefix,
};
use tenko_ipam::scope::ScopeIndex;
use tenko_ipam::vlan::{
    Controllers, VlanProvisionPreview, VlanProvisionRequest, VlanProvisionSubmitted, codes,
    links::vlan_prefixes, provision,
};
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::common::{IdempotencyKeyHeader, Ipam, IpamJson, IpamPath, authorize, new_of};
use crate::{
    dto::Page,
    extract::Ctx,
    list::Filters,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The routes of the area.
pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(provision_vlan))
        .routes(routes!(list_vlan_prefixes))
}

/// The network controllers of the request, from the `Arc<Controllers>` extension; 503
/// `ipam.vlan.controllers_unavailable` when the server did not add one.
pub(crate) struct VlanControllers(pub(crate) Arc<Controllers>);

impl<S: Send + Sync> FromRequestParts<S> for VlanControllers {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<Arc<Controllers>>()
                .cloned()
                .map(VlanControllers)
                .ok_or_else(|| {
                    ApiError::from_coded_error(
                        CodedError::new(
                            codes::CONTROLLERS_UNAVAILABLE,
                            503,
                            "VLAN provisioning is not configured on this server",
                        )
                        .with_title("Service unavailable"),
                    )
                }),
        )
    }
}

/// The query of `POST /vlans/provision` (documentation).
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
struct ProvisionParams {
    /// Compute the preview without starting anything (API-09); the controller is read and
    /// diffed, nothing is written.
    dry_run: Option<bool>,
    /// For a dry run: read at least at this store revision.
    at_least: Option<u64>,
}

/// The query of `GET /vlans/{id}/prefixes` (documentation).
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
struct PrefixListParams {
    /// Soft-deleted prefixes: `exclude` (the default) or `include`.
    deleted: Option<String>,
    /// Read at least at this store revision.
    at_least: Option<u64>,
}

fn check(
    app: &AppState,
    cx: &RequestCtx,
    request: &VlanProvisionRequest,
    submit: bool,
) -> Result<(), ApiError> {
    // A provision writes through a network controller, which is global-only in Phase 1,
    // and its plan is applied by the job, so a scoped principal is refused (IAM-01).
    if let Some(authorizer) = &app.authorizer
        && !ScopeIndex::unrestricted(authorizer.as_ref(), &cx.principal)
    {
        return Err(Denied {
            action: Action::Create,
            object: new_of(ObjectKind::Vlan),
            reason: DenyReason::MissingPermission,
        }
        .into());
    }
    match request.vlan {
        Some(vlan) => authorize(app, cx, Action::Update, ObjectRef::from(vlan))?,
        None => authorize(app, cx, Action::Create, new_of(ObjectKind::Vlan))?,
    }
    if request.prefix.is_some() {
        authorize(app, cx, Action::Create, new_of(ObjectKind::Prefix))?;
    }
    if submit {
        authorize(app, cx, Action::Execute, new_of(ObjectKind::Job))?;
        if let Some(connector) = request.connector {
            authorize(app, cx, Action::Execute, ObjectRef::from(connector))?;
        }
    }
    Ok(())
}

/// Previews (`dry_run=true`) or starts the provision of a VLAN with its network.
#[utoipa::path(
    post,
    path = "/vlans/provision",
    tag = "tenancy",
    operation_id = "provision_vlan",
    summary = "Preview or start creating a VLAN with its network on the network controller",
    params(ProvisionParams, IdempotencyKeyHeader),
    request_body = VlanProvisionRequest,
    responses(
        (status = 200, description = "The preview of a dry run: the IPAM plan, the controller's read-back diff and the steps of the job", body = VlanProvisionPreview),
        (status = 202, description = "The job of the provision", body = VlanProvisionSubmitted),
        (status = 400, description = "Invalid request (`ipam.vlan.invalid_request`, `ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed, or writes through the connector are off (`connect.writes_disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The VLAN does not exist (`ipam.not_found`) or the connector is not a network controller (`ipam.vlan.controller_unknown`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A warning needs an acknowledgement (`ipam.plan.unacknowledged`), the VLAN id exists at the site (`ipam.vlan.duplicate`), the network overlaps (`ipam.prefix.overlap`), the connector is disabled (`ipam.vlan.controller_disabled`) or a guardrail refuses (`connect.guardrail.protected_vlan`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The idempotency key was used for another provision (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 502, description = "The network controller did not answer (`connect.unreachable` and other `connect.*` codes)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM, the job engine or the network controllers are not configured (`ipam.unavailable`, `ipam.move.no_engine`, `ipam.vlan.controllers_unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn provision_vlan(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    VlanControllers(controllers): VlanControllers,
    filters: Filters,
    IpamJson(request): IpamJson<VlanProvisionRequest>,
) -> Result<Response, ApiError> {
    filters.only(&["dry_run"])?;
    let dry_run = filters.boolean("dry_run")?.unwrap_or(false);
    let at_least = filters.page()?.at_least.map(Revision);
    check(&app, &cx, &request, !dry_run)?;
    if dry_run {
        let preview = provision::preview(&ipam, &controllers, &request, &cx, at_least).await?;
        return Ok((StatusCode::OK, Json(preview)).into_response());
    }
    let submitted = provision::submit(&ipam, &controllers, &request, &cx).await?;
    Ok((StatusCode::ACCEPTED, Json(submitted)).into_response())
}

/// Lists the prefixes linked to a VLAN.
#[utoipa::path(
    get,
    path = "/vlans/{id}/prefixes",
    tag = "tenancy",
    operation_id = "list_vlan_prefixes",
    summary = "List the prefixes of a VLAN",
    params(
        ("id" = String, Path, description = "The VLAN."),
        PrefixListParams
    ),
    responses(
        (status = 200, description = "The prefixes linked to the VLAN, by VRF and network", body = Page<Prefix>),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`, `sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The VLAN does not exist (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_vlan_prefixes(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<VlanId>,
    filters: Filters,
) -> Result<Json<Page<Prefix>>, ApiError> {
    filters.only(&["deleted"])?;
    let deleted = match filters.get("deleted")? {
        None | Some("exclude") => false,
        Some("include") => true,
        Some(other) => {
            return Err(ApiError::invalid_query(
                "deleted",
                format!("`{other}` is not `exclude` or `include`"),
            ));
        }
    };
    let at_least = filters.page()?.at_least.map(Revision);
    authorize(&app, &cx, Action::Read, ObjectRef::from(id))?;
    let view = ipam.view(at_least).await?;
    // A scoped reader sees the linked prefixes inside its scope.
    let scope = ipam.read_scope(&cx, ObjectKind::Prefix);
    let prefixes = vlan_prefixes(view.as_ref(), id, deleted)?
        .into_iter()
        .filter(|prefix| scope.admits(&ObjectRef::from(prefix.id)))
        .collect();
    Ok(Json(Page::new(prefixes, None, view.revision())))
}

#[cfg(test)]
mod tests;
