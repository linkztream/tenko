//! `GET /ipam/reconcile` (IPAM-21, WP8.2): the reconciliation view of the four truths,
//! [`tenko_ipam::reconcile::view`], filtered by prefix, host and kind and paged. A scoped
//! principal reads the rows whose address lies in its scope (IAM-01).

use axum::{Json, extract::State};
use tenko_auth::authz::anywhere;
use tenko_core::{Action, HostId, ObjectKind, ObjectRef, PrefixId, Revision, Timestamp};
use tenko_ipam::reconcile::view::{
    ReconcileKind, ReconcileQuery, ReconcileRow, reconcile, reconcile_where,
};
use uuid::Uuid;

use super::model::{ReconcileFilters, ReconcilePage};
use crate::{
    extract::Ctx,
    list::{Filters, encode_cursor},
    problem::{ApiError, ProblemDetails},
    routes::common::Ipam,
    state::AppState,
};

/// Gets the reconciliation view.
#[utoipa::path(
    get,
    path = "/ipam/reconcile",
    tag = "observations",
    operation_id = "get_ipam_reconcile",
    summary = "Get the reconciliation view of the four truths",
    description = "Scope: read access to observations (IAM-01). IPAM-21, IPAM-23. One row per difference between intent, the DHCP leases, the DNS records and the scans: ghosts, rogues, orphans, PTR mismatches and conflicts, each with the truth that wins by its rule. With `host`, the answer also carries the host's truths: the OS field by precedence (an inventory's OS, then an active scan's guess, then the DHCP fingerprint's), every OS guess and the vendors.",
    params(ReconcileFilters),
    responses(
        (status = 200, description = "A page of rows, ordered by address, then kind", body = ReconcilePage),
        (status = 400, description = "A parameter is unknown or malformed (`sys.invalid_query`, `sys.invalid_cursor`), or the limit is out of range (`ipam.invalid_filter`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read observations", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The prefix or the host does not exist (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_ipam_reconcile(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    ipam: Result<Ipam, ApiError>,
    filters: Filters,
) -> Result<Json<ReconcilePage>, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::Observation),
    )?;
    let Ipam(ipam) = ipam?;
    filters.only(&["prefix", "host", "kind"])?;
    let page = filters.page()?;
    let scope = filters.scope("ipam.reconcile");
    let query = ReconcileQuery {
        prefix: filters.parse::<PrefixId>("prefix")?,
        host: filters.parse::<HostId>("host")?,
        kind: filters.parse::<ReconcileKind>("kind")?,
        limit: Some(page.limit()?),
        cursor: page.cursor::<String>(scope)?,
    };
    let view = ipam.view(page.at_least.map(Revision)).await?;
    let readable = ipam.read_scope(&cx, ObjectKind::Observation);
    if readable.is_nothing() {
        return Ok(Json(ReconcilePage {
            items: Vec::new(),
            next_cursor: None,
            revision: view.revision(),
            host: None,
        }));
    }
    // ADR 0031: the lease view has followed this view first.
    ipam.leases().caught_up(view.revision()).await;
    let now = Timestamp::now();
    let found = if readable.is_all() {
        reconcile(view.as_ref(), Some(ipam.leases()), &query, now)?
    } else {
        // A row stands for its address: it is read where the address is in scope.
        let object = ObjectRef::new(ObjectKind::Observation, Uuid::nil());
        reconcile_where(
            view.as_ref(),
            Some(ipam.leases()),
            &query,
            now,
            &|row: &ReconcileRow| {
                readable.admits_by(|index| index.anchors_of_ip(object, row.vrf, row.address))
            },
        )?
    };
    Ok(Json(ReconcilePage {
        items: found.items,
        next_cursor: found
            .next_cursor
            .map(|cursor| encode_cursor(scope, &cursor)),
        revision: found.revision,
        host: found.host,
    }))
}
