//! The DHCP module (Phase 3): server settings, scopes, shared networks, pools and
//! exclusions, options, classes, policies, MAC filters, reservations, leases, history,
//! export and the DHCP role of a node.
//!
//! Area: dhcp. Owner: WP7.0 (the contracts); the operations are built by WP7.4 (the
//! configuration routes), WP7.2 and WP7.5 (leases, history, the node routes), WP8.1
//! (reservations), WP8.2 (`/ipam/reconcile`) and WP9.3 (export). Requirements: DHCP-01 to
//! DHCP-08, DHCP-13, DHCP-15, DHCP-16, IPAM-21, MIG-16, OPS-25.
//!
//! Every operation is declared with its request and answer types so that the OpenAPI
//! document, the typed client of the UI and the mock server have them. The configuration
//! routes are built (WP7.4, files `dhcp/settings.rs`, `dhcp/scopes.rs`, `dhcp/networks.rs`,
//! `dhcp/pools.rs`, `dhcp/options.rs`, `dhcp/classes.rs`) on the configuration service
//! (`tenko_dhcp::config`), which the server adds as the request extension
//! `Arc<ConfigService>`; every change is an inline job with its audit record, every read of
//! one object carries its revision as the `ETag`, and a change or deletion with `If-Match`
//! is refused with 412 when the object moved on. The leases, the history and the node
//! routes are built (WP7.5, file `dhcp/leases.rs`) on the `dhcp` role of the process, which
//! `tenko serve` puts in the request extension [`DhcpNodeSlot`]. The Kea export (WP9.3,
//! file `dhcp/export.rs`) reads through the configuration service. Until its package builds
//! it, any other operation (the reservations) checks the caller's scope and answers `501`
//! with `sys.not_implemented`. The routes belong
//! to the DHCP module (OPS-25): a server without it registers none of them, so they answer
//! 404 `sys.route_not_found`; a router without the configuration service answers the
//! configuration routes with 409 `dhcp.module.disabled`. `/ipam/reconcile` belongs to the
//! IPAM module and is registered by `reconcile_routes`.
//!
//! | Endpoint | Scope | Purpose |
//! |---|---|---|
//! | `GET /dhcp/settings` | `dhcp.read` | Get the DHCP server settings |
//! | `PUT /dhcp/settings` | `dhcp.write` | Change the DHCP server settings |
//! | `GET /dhcp/scopes` | `dhcp.read` | List DHCP scopes |
//! | `POST /dhcp/scopes` | `dhcp.write` | Create a DHCP scope for an IPAM network |
//! | `GET /dhcp/scopes/{prefix}` | `dhcp.read` | Get a DHCP scope |
//! | `PATCH /dhcp/scopes/{prefix}` | `dhcp.write` | Change a DHCP scope |
//! | `DELETE /dhcp/scopes/{prefix}` | `dhcp.write` | Delete a DHCP scope (the prefix stays) |
//! | `GET /dhcp/scopes/{prefix}/utilization` | `dhcp.read` | Get how full a DHCP scope is |
//! | `GET /dhcp/scopes/{prefix}/effective-options` | `dhcp.read` | Get the options a client gets in a DHCP scope |
//! | `GET /dhcp/scopes/{prefix}/exclusions` | `dhcp.read` | List the exclusion ranges of a DHCP scope |
//! | `POST /dhcp/scopes/{prefix}/exclusions` | `dhcp.write` | Exclude a range of a DHCP scope |
//! | `DELETE /dhcp/scopes/{prefix}/exclusions/{id}` | `dhcp.write` | Delete an exclusion range |
//! | `GET /dhcp/shared-networks` | `dhcp.read` | List DHCP shared networks |
//! | `POST /dhcp/shared-networks` | `dhcp.write` | Create a DHCP shared network |
//! | `GET /dhcp/shared-networks/{id}` | `dhcp.read` | Get a DHCP shared network |
//! | `PATCH /dhcp/shared-networks/{id}` | `dhcp.write` | Change a DHCP shared network |
//! | `DELETE /dhcp/shared-networks/{id}` | `dhcp.write` | Delete a DHCP shared network |
//! | `GET /dhcp/pools` | `dhcp.read` | List DHCP pools |
//! | `GET /dhcp/pools/{range}` | `dhcp.read` | Get a DHCP pool |
//! | `PUT /dhcp/pools/{range}` | `dhcp.write` | Set the DHCP settings of a pool |
//! | `DELETE /dhcp/pools/{range}` | `dhcp.write` | Remove the DHCP settings of a pool (the range stays) |
//! | `GET /dhcp/option-catalog` | `dhcp.read` | List the built-in DHCP options |
//! | `GET /dhcp/option-defs` | `dhcp.read` | List custom DHCP option definitions |
//! | `POST /dhcp/option-defs` | `dhcp.write` | Define a custom DHCP option |
//! | `GET /dhcp/option-defs/{id}` | `dhcp.read` | Get a custom DHCP option definition |
//! | `PATCH /dhcp/option-defs/{id}` | `dhcp.write` | Change a custom DHCP option definition |
//! | `DELETE /dhcp/option-defs/{id}` | `dhcp.write` | Delete a custom DHCP option definition |
//! | `GET /dhcp/option-sets` | `dhcp.read` | List DHCP option sets |
//! | `GET /dhcp/option-sets/{owner}` | `dhcp.read` | Get the DHCP options of a level |
//! | `PUT /dhcp/option-sets/{owner}` | `dhcp.write` | Replace the DHCP options of a level |
//! | `DELETE /dhcp/option-sets/{owner}` | `dhcp.write` | Clear the DHCP options of a level |
//! | `GET /dhcp/classes` | `dhcp.read` | List DHCP classes |
//! | `POST /dhcp/classes` | `dhcp.write` | Create a DHCP class |
//! | `GET /dhcp/classes/{id}` | `dhcp.read` | Get a DHCP class |
//! | `PATCH /dhcp/classes/{id}` | `dhcp.write` | Change a DHCP class |
//! | `DELETE /dhcp/classes/{id}` | `dhcp.write` | Delete a DHCP class |
//! | `GET /dhcp/policies` | `dhcp.read` | List DHCP policies |
//! | `POST /dhcp/policies` | `dhcp.write` | Create a DHCP policy |
//! | `GET /dhcp/policies/{id}` | `dhcp.read` | Get a DHCP policy |
//! | `PATCH /dhcp/policies/{id}` | `dhcp.write` | Change a DHCP policy |
//! | `DELETE /dhcp/policies/{id}` | `dhcp.write` | Delete a DHCP policy |
//! | `GET /dhcp/filters` | `dhcp.read` | List DHCP MAC filters |
//! | `POST /dhcp/filters` | `dhcp.write` | Add a DHCP MAC filter |
//! | `GET /dhcp/filters/{id}` | `dhcp.read` | Get a DHCP MAC filter |
//! | `PATCH /dhcp/filters/{id}` | `dhcp.write` | Change a DHCP MAC filter |
//! | `DELETE /dhcp/filters/{id}` | `dhcp.write` | Delete a DHCP MAC filter |
//! | `GET /dhcp/reservations` | `dhcp.read` | List DHCP reservations (IPAM hosts of mode reserved) |
//! | `GET /dhcp/reservations/{interface}` | `dhcp.read` | Get the DHCP reservation of an interface |
//! | `GET /dhcp/leases` | `dhcp.read` | List DHCP leases |
//! | `GET /dhcp/leases/{addr}` | `dhcp.read` | Get the DHCP lease of an address |
//! | `POST /dhcp/leases/{addr}/release` | `dhcp.write` | Release a DHCP lease (the address returns to the pool) |
//! | `GET /dhcp/history` | `dhcp.read` | Read the DHCP lease history |
//! | `GET /dhcp/export` | `dhcp.read` | Export the DHCP configuration and leases (Kea JSON) |
//! | `GET /nodes/{id}/dhcp` | `dhcp.read` | Get the DHCP role of a node |
//! | `GET /nodes/{id}/dhcp/leases` | `dhcp.read` | List the leases a node's DHCP role holds |
//! | `POST /nodes/{id}/dhcp/leases/{addr}/release` | `dhcp.write` | Release a lease on a node's DHCP role |
//! | `GET /nodes/{id}/dhcp/history` | `dhcp.read` | Read the lease history through a node's DHCP role |
//! | `GET /ipam/reconcile` | `read of observations` | Get the reconciliation view of the four truths |
//!
//! # Authorization
//!
//! The scopes are `dhcp.read`, which reads, and `dhcp.write`, which creates, changes and
//! deletes and runs (releases a lease). A route checks the action on the object it names:
//! the scope of a prefix (kind `dhcp_scope` with the prefix's identifier, so a grant on the
//! prefix reaches it), the class, policy, option definition or filter entry, or the
//! interface of a reservation. Server-wide configuration (the settings, shared networks,
//! the server level of the options, the export) is the `dhcp_scope` singleton, which no
//! scoped grant reaches, so only global roles use it. A route that names no object checks
//! the kind (lists and creates); a pool and the option set of a pool are checked on the
//! kind first and then on the scope of the pool's prefix. A list shows only the scopes,
//! pools, exclusions and option sets of the scopes the caller may read. The node routes
//! need the action on the node as well, and check it first.
//!
//! A path segment that does not parse answers 400 `sys.invalid_request` before any
//! authorization.

// WP7.4: the configuration routes.
mod classes;
mod model;
mod networks;
mod options;
mod pools;
mod scopes;
mod settings;
// WP7.5: the leases, the history and the node routes.
mod leases;
pub use leases::DhcpNodeSlot;
// WP8.2: `GET /ipam/reconcile`, the reconciliation view.
mod reconcile;
// WP9.3: `GET /dhcp/export`, the Kea export.
mod export;

#[cfg(test)]
mod tests;

use std::{net::IpAddr, sync::Arc};

use axum::{
    Json,
    extract::{FromRequestParts, Path, State},
    http::{HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, CodedError, InterfaceId, NodeId, ObjectKind, ObjectRef, Principal, Revision,
    dhcp::{OptionOwner, scope_object, server_object},
    error::codes,
};
use tenko_dhcp::config::ConfigService;
use utoipa_axum::{router::OpenApiRouter, routes};

pub use model::{
    DhcpClassCreate, DhcpClassItem, DhcpClassPatch, DhcpCommandAccepted, DhcpExportParams,
    DhcpFamily, DhcpFilterCreate, DhcpFilterItem, DhcpFilterPatch, DhcpHistoryFilters,
    DhcpHistoryItem, DhcpLeaseCount, DhcpLeaseFilters, DhcpLeaseItem, DhcpLeaseParams,
    DhcpLeasePeer, DhcpLeaseRelease, DhcpListenMode, DhcpListenerItem, DhcpNodeStatus,
    DhcpPdUtilization, DhcpPolicyCreate, DhcpPolicyFilter, DhcpPolicyItem, DhcpPolicyPatch,
    DhcpPoolItem, DhcpPoolSet, DhcpRaCheck, DhcpRaFinding, DhcpRaLink, DhcpRaReport,
    DhcpReservationItem, DhcpScopeCreate, DhcpScopeFilter, DhcpScopeItem, DhcpScopePatch,
    DhcpScopeUtilization, DhcpSettingsItem, DhcpSettingsUpdate, EffectiveOption, EffectiveOptions,
    EffectiveOptionsParams, ExclusionCreate, ExclusionItem, OptionCatalogItem, OptionCatalogParams,
    OptionDefCreate, OptionDefItem, OptionDefPatch, OptionSetFilter, OptionSetItem, OptionSetPut,
    OptionValueInput, OptionValueItem, ReconcileFilters, ReconcileKind, ReconcileRow,
    SharedNetworkCreate, SharedNetworkItem, SharedNetworkPatch, Truth,
};

use super::not_implemented;
use crate::{
    dto::Page,
    extract::Ctx,
    list::PageParams,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// A 400 `sys.invalid_request` for a malformed path segment.
fn invalid(field: &str, detail: &str) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(codes::INVALID_REQUEST, 400, detail)
            .with_title("Invalid request")
            .with_param("field", field),
    )
}

/// An identifier from the path; `field` names the path parameter.
fn parse_id<T: std::str::FromStr>(field: &str, raw: &str) -> Result<T, ApiError> {
    raw.parse()
        .map_err(|_| invalid(field, "the identifier is not a UUID"))
}

/// A node id from the path.
fn parse_node(raw: &str) -> Result<NodeId, ApiError> {
    raw.parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .map(NodeId)
        .ok_or_else(|| invalid("id", "the node identifier is not a positive number"))
}

// WP9.4: a lease address of either family.
/// An IPv4 or IPv6 address from the path.
fn parse_addr(raw: &str) -> Result<IpAddr, ApiError> {
    raw.parse()
        .map_err(|_| invalid("addr", "the address is not an IPv4 or IPv6 address"))
}

/// An option set owner from the path (`server`, `scope:<id>`, `shared_network:<id>`,
/// `pool:<id>`, `policy:<id>` or `host:<id>`).
fn parse_owner(raw: &str) -> Result<OptionOwner, ApiError> {
    OptionOwner::from_path(raw).map_err(|_| {
        invalid(
            "owner",
            "the owner is not server, scope:<id>, shared_network:<id>, pool:<id>, policy:<id> or host:<id>",
        )
    })
}

/// The object an option set is checked on first: the server-wide singleton for the server
/// and shared network levels, the scope of a prefix, the kind for a pool (the handler then
/// checks the pool's scope), the policy, and the interface of a reservation.
fn owner_object(owner: OptionOwner) -> ObjectRef {
    match owner {
        OptionOwner::Server | OptionOwner::SharedNetwork(_) => server_object(),
        OptionOwner::Scope(prefix) => scope_object(prefix),
        OptionOwner::Pool(_) => anywhere(ObjectKind::DhcpScope),
        OptionOwner::Policy(id) => ObjectRef::from(id),
        OptionOwner::Host(interface) => ObjectRef::new(ObjectKind::Interface, interface.0),
    }
}

/// The configuration service of the request, from the `Arc<ConfigService>` extension the
/// server adds while the DHCP module runs. Taken after the path and the scope are checked
/// ([`Configs::get`]), so a malformed path or a missing scope answers first.
pub(crate) struct Configs(Option<Arc<ConfigService>>);

impl Configs {
    /// The service; 409 `dhcp.module.disabled` when the server runs none.
    pub(crate) fn get(self) -> Result<Arc<ConfigService>, ApiError> {
        self.0.ok_or_else(|| {
            ApiError::from_coded_error(
                CodedError::new(
                    tenko_core::dhcp::codes::MODULE_DISABLED,
                    409,
                    "the DHCP configuration service does not run on this server",
                )
                .with_title("DHCP module disabled"),
            )
        })
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Configs {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Configs(
            parts.extensions.get::<Arc<ConfigService>>().cloned(),
        )))
    }
}

/// A JSON answer with the revision as its `ETag`.
fn with_etag(status: StatusCode, body: &impl Serialize, revision: Revision) -> Response {
    let mut response = (status, Json(body)).into_response();
    if let Ok(etag) = HeaderValue::from_str(&format!("\"{}\"", revision.0)) {
        response.headers_mut().insert(header::ETAG, etag);
    }
    response
}

/// Whether the caller may read the scope of `prefix`, for the filtering of lists.
fn may_read_scope(app: &AppState, principal: &Principal, prefix: tenko_core::PrefixId) -> bool {
    app.authorize(principal, Action::Read, &scope_object(prefix))
        .is_ok()
}

/// One page of `items`, already sorted by `position`, after the cursor of `page`.
fn page_of<T, P>(
    items: Vec<T>,
    position: impl Fn(&T) -> P,
    page: &PageParams,
    scope: crate::list::CursorScope,
    revision: Revision,
) -> Result<Page<T>, ApiError>
where
    P: Serialize + serde::de::DeserializeOwned + PartialOrd,
{
    let limit = page.limit()?;
    let after: Option<P> = page.cursor(scope)?;
    let mut out = Vec::new();
    let mut next = None;
    for item in items {
        if after
            .as_ref()
            .is_some_and(|after| position(&item) <= *after)
        {
            continue;
        }
        if out.len() == limit {
            next = out
                .last()
                .map(|last| crate::list::encode_cursor(scope, &position(last)));
            break;
        }
        out.push(item);
    }
    Ok(Page::new(out, next, revision))
}

/// The routes of the area: everything under `/dhcp` and `/nodes/{id}/dhcp`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    settings_and_scope_routes()
        .merge(network_and_pool_routes())
        .merge(option_routes())
        .merge(class_and_policy_routes())
        .merge(filter_and_lease_routes())
        .merge(node_routes())
}

/// The routes of the area that belong to the IPAM module: `/ipam/reconcile` (IPAM-21).
pub(crate) fn reconcile_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(reconcile::get_ipam_reconcile))
}

// The registration is split into small functions that are never inlined: the server builds
// the router while its start-up future runs on a thread with a small stack, and one long
// chain of `routes!` keeps every temporary in one stack frame.

#[inline(never)]
fn settings_and_scope_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(
            settings::get_dhcp_settings,
            settings::update_dhcp_settings
        ))
        .routes(routes!(scopes::list_dhcp_scopes, scopes::create_dhcp_scope))
        .routes(routes!(
            scopes::get_dhcp_scope,
            scopes::update_dhcp_scope,
            scopes::delete_dhcp_scope
        ))
        .routes(routes!(scopes::get_dhcp_scope_utilization))
        .routes(routes!(scopes::get_dhcp_effective_options))
        .routes(routes!(
            scopes::list_dhcp_exclusions,
            scopes::create_dhcp_exclusion
        ))
        .routes(routes!(scopes::delete_dhcp_exclusion))
}

#[inline(never)]
fn network_and_pool_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(
            networks::list_dhcp_shared_networks,
            networks::create_dhcp_shared_network
        ))
        .routes(routes!(
            networks::get_dhcp_shared_network,
            networks::update_dhcp_shared_network,
            networks::delete_dhcp_shared_network,
        ))
        .routes(routes!(pools::list_dhcp_pools))
        .routes(routes!(
            pools::get_dhcp_pool,
            pools::set_dhcp_pool,
            pools::delete_dhcp_pool
        ))
}

#[inline(never)]
fn option_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(options::list_dhcp_option_catalog))
        .routes(routes!(
            options::list_dhcp_option_defs,
            options::create_dhcp_option_def
        ))
        .routes(routes!(
            options::get_dhcp_option_def,
            options::update_dhcp_option_def,
            options::delete_dhcp_option_def
        ))
        .routes(routes!(options::list_dhcp_option_sets))
        .routes(routes!(
            options::get_dhcp_option_set,
            options::set_dhcp_option_set,
            options::delete_dhcp_option_set
        ))
}

#[inline(never)]
fn class_and_policy_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(
            classes::list_dhcp_classes,
            classes::create_dhcp_class
        ))
        .routes(routes!(
            classes::get_dhcp_class,
            classes::update_dhcp_class,
            classes::delete_dhcp_class
        ))
        .routes(routes!(
            classes::list_dhcp_policies,
            classes::create_dhcp_policy
        ))
        .routes(routes!(
            classes::get_dhcp_policy,
            classes::update_dhcp_policy,
            classes::delete_dhcp_policy
        ))
}

#[inline(never)]
fn filter_and_lease_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(
            classes::list_dhcp_filters,
            classes::create_dhcp_filter
        ))
        .routes(routes!(
            classes::get_dhcp_filter,
            classes::update_dhcp_filter,
            classes::delete_dhcp_filter
        ))
        .routes(routes!(list_dhcp_reservations))
        .routes(routes!(get_dhcp_reservation))
        .routes(routes!(leases::list_dhcp_leases))
        .routes(routes!(leases::get_dhcp_lease))
        .routes(routes!(leases::release_dhcp_lease))
        .routes(routes!(leases::list_dhcp_history))
        // WP9.3: the Kea export.
        .routes(routes!(export::export_dhcp))
}

#[inline(never)]
fn node_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(leases::get_node_dhcp_status))
        .routes(routes!(leases::list_node_dhcp_leases))
        .routes(routes!(leases::release_node_dhcp_lease))
        .routes(routes!(leases::read_node_dhcp_history))
}

#[utoipa::path(
    get,
    path = "/dhcp/reservations",
    tag = "dhcp",
    operation_id = "list_dhcp_reservations",
    summary = "List DHCP reservations (IPAM hosts of mode reserved)",
    description = "Scope: `dhcp.read`. Writes go to the IPAM host routes and `PUT /dhcp/option-sets/host:{interface}`.",
    params(PageParams, DhcpScopeFilter),
    responses(
        (status = 200, description = "A page of reservations by address", body = Page<DhcpReservationItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_reservations(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("GET", "/dhcp/reservations"))
}

#[utoipa::path(
    get,
    path = "/dhcp/reservations/{interface}",
    tag = "dhcp",
    operation_id = "get_dhcp_reservation",
    summary = "Get the DHCP reservation of an interface",
    description = "Scope: `dhcp.read`.",
    params(("interface" = String, Path, description = "Interface identifier (UUID) of the reservation")),
    responses(
        (status = 200, description = "The reservation", body = DhcpReservationItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such interface (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_reservation(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(interface): Path<String>,
) -> Result<Response, ApiError> {
    parse_id::<InterfaceId>("interface", &interface)?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("GET", "/dhcp/reservations/{interface}"))
}
