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
//! document, the typed client of the UI and the mock server have them; until its package
//! builds it, an operation checks the caller's scope and answers `501` with
//! `sys.not_implemented`. The routes belong to the DHCP module (OPS-25): a server without
//! it registers none of them, so they answer 404 `sys.route_not_found`. `/ipam/reconcile`
//! belongs to the IPAM module and is registered by `reconcile_routes`.
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
//! the kind (lists and creates); a pool is checked on the kind here and on its scope by the
//! implementation. The node routes need the action on the node as well, and check it first.
//!
//! A path segment that does not parse answers 400 `sys.invalid_request` before any
//! authorization.

mod model;

#[cfg(test)]
mod tests;

use std::net::Ipv4Addr;

use axum::{
    extract::{Path, State},
    response::Response,
};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, CodedError, InterfaceId, NodeId, ObjectKind, ObjectRef, PrefixId, RangeId,
    dhcp::{
        ClassId, ExclusionId, FilterId, OptionDefId, OptionOwner, PolicyId, SharedNetworkId,
        scope_object, server_object,
    },
    error::codes,
};
use utoipa_axum::{router::OpenApiRouter, routes};

pub use model::{
    DhcpClassCreate, DhcpClassItem, DhcpClassPatch, DhcpCommandAccepted, DhcpExport,
    DhcpExportParams, DhcpFilterCreate, DhcpFilterItem, DhcpFilterPatch, DhcpHistoryFilters,
    DhcpHistoryItem, DhcpLeaseCount, DhcpLeaseFilters, DhcpLeaseItem, DhcpLeaseParams,
    DhcpLeaseRelease, DhcpListenMode, DhcpListenerItem, DhcpNodeStatus, DhcpPolicyCreate,
    DhcpPolicyFilter, DhcpPolicyItem, DhcpPolicyPatch, DhcpPoolItem, DhcpPoolSet,
    DhcpReservationItem, DhcpScopeCreate, DhcpScopeFilter, DhcpScopeItem, DhcpScopePatch,
    DhcpScopeUtilization, DhcpSettingsItem, DhcpSettingsUpdate, EffectiveOption, EffectiveOptions,
    EffectiveOptionsParams, ExclusionCreate, ExclusionItem, OptionCatalogItem, OptionDefCreate,
    OptionDefItem, OptionDefPatch, OptionSetFilter, OptionSetItem, OptionSetPut, OptionValueInput,
    OptionValueItem, ReconcileFilters, ReconcileKind, ReconcileRow, SharedNetworkCreate,
    SharedNetworkItem, SharedNetworkPatch, Truth,
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

/// An IPv4 address from the path.
fn parse_addr(raw: &str) -> Result<Ipv4Addr, ApiError> {
    raw.parse()
        .map_err(|_| invalid("addr", "the address is not an IPv4 address"))
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

/// The object an option set is checked on: the server-wide singleton for the server and
/// shared network levels, the scope of a prefix, the kind for a pool (the implementation
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
    OpenApiRouter::new().routes(routes!(get_ipam_reconcile))
}

// The registration is split into small functions that are never inlined: the server builds
// the router while its start-up future runs on a thread with a small stack, and one long
// chain of `routes!` keeps every temporary in one stack frame.

#[inline(never)]
fn settings_and_scope_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_dhcp_settings, update_dhcp_settings))
        .routes(routes!(list_dhcp_scopes, create_dhcp_scope))
        .routes(routes!(
            get_dhcp_scope,
            update_dhcp_scope,
            delete_dhcp_scope
        ))
        .routes(routes!(get_dhcp_scope_utilization))
        .routes(routes!(get_dhcp_effective_options))
        .routes(routes!(list_dhcp_exclusions, create_dhcp_exclusion))
        .routes(routes!(delete_dhcp_exclusion))
}

#[inline(never)]
fn network_and_pool_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(
            list_dhcp_shared_networks,
            create_dhcp_shared_network
        ))
        .routes(routes!(
            get_dhcp_shared_network,
            update_dhcp_shared_network,
            delete_dhcp_shared_network,
        ))
        .routes(routes!(list_dhcp_pools))
        .routes(routes!(get_dhcp_pool, set_dhcp_pool, delete_dhcp_pool))
}

#[inline(never)]
fn option_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_dhcp_option_catalog))
        .routes(routes!(list_dhcp_option_defs, create_dhcp_option_def))
        .routes(routes!(
            get_dhcp_option_def,
            update_dhcp_option_def,
            delete_dhcp_option_def
        ))
        .routes(routes!(list_dhcp_option_sets))
        .routes(routes!(
            get_dhcp_option_set,
            set_dhcp_option_set,
            delete_dhcp_option_set
        ))
}

#[inline(never)]
fn class_and_policy_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_dhcp_classes, create_dhcp_class))
        .routes(routes!(
            get_dhcp_class,
            update_dhcp_class,
            delete_dhcp_class
        ))
        .routes(routes!(list_dhcp_policies, create_dhcp_policy))
        .routes(routes!(
            get_dhcp_policy,
            update_dhcp_policy,
            delete_dhcp_policy
        ))
}

#[inline(never)]
fn filter_and_lease_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_dhcp_filters, create_dhcp_filter))
        .routes(routes!(
            get_dhcp_filter,
            update_dhcp_filter,
            delete_dhcp_filter
        ))
        .routes(routes!(list_dhcp_reservations))
        .routes(routes!(get_dhcp_reservation))
        .routes(routes!(list_dhcp_leases))
        .routes(routes!(get_dhcp_lease))
        .routes(routes!(release_dhcp_lease))
        .routes(routes!(list_dhcp_history))
        .routes(routes!(export_dhcp))
}

#[inline(never)]
fn node_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_node_dhcp_status))
        .routes(routes!(list_node_dhcp_leases))
        .routes(routes!(release_node_dhcp_lease))
        .routes(routes!(read_node_dhcp_history))
}

#[utoipa::path(
    get,
    path = "/dhcp/settings",
    tag = "dhcp",
    operation_id = "get_dhcp_settings",
    summary = "Get the DHCP server settings",
    description = "Scope: `dhcp.read`.",
    responses(
        (status = 200, description = "The settings, with their `ETag`", body = DhcpSettingsItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_settings(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &server_object())?;
    Err(not_implemented("GET", "/dhcp/settings"))
}

#[utoipa::path(
    put,
    path = "/dhcp/settings",
    tag = "dhcp",
    operation_id = "update_dhcp_settings",
    summary = "Change the DHCP server settings",
    description = "Scope: `dhcp.write`.",
    request_body(content = DhcpSettingsUpdate, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed settings", body = DhcpSettingsItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the settings are invalid (`dhcp.settings.invalid`) or the lease times are invalid (`dhcp.lease_times.invalid`) or the DDNS settings are invalid (`dhcp.ddns.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_dhcp_settings(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Update, &server_object())?;
    Err(not_implemented("PUT", "/dhcp/settings"))
}

#[utoipa::path(
    get,
    path = "/dhcp/scopes",
    tag = "dhcp",
    operation_id = "list_dhcp_scopes",
    summary = "List DHCP scopes",
    description = "Scope: `dhcp.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of scopes by prefix", body = Page<DhcpScopeItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_scopes(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("GET", "/dhcp/scopes"))
}

#[utoipa::path(
    post,
    path = "/dhcp/scopes",
    tag = "dhcp",
    operation_id = "create_dhcp_scope",
    summary = "Create a DHCP scope for an IPAM network",
    description = "Scope: `dhcp.write`.",
    request_body(content = DhcpScopeCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The scope", body = DhcpScopeItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the scope settings are invalid (`dhcp.scope.invalid`) or the lease times are invalid (`dhcp.lease_times.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The prefix has a scope already (`dhcp.scope.exists`) or the prefix is a supernet, not a network a scope can serve (`dhcp.scope.not_network`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dhcp_scope(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("POST", "/dhcp/scopes"))
}

#[utoipa::path(
    get,
    path = "/dhcp/scopes/{prefix}",
    tag = "dhcp",
    operation_id = "get_dhcp_scope",
    summary = "Get a DHCP scope",
    description = "Scope: `dhcp.read`.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope")),
    responses(
        (status = 200, description = "The scope, with its `ETag`", body = DhcpScopeItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_scope(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(prefix): Path<String>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Read, &scope_object(prefix))?;
    Err(not_implemented("GET", "/dhcp/scopes/{prefix}"))
}

#[utoipa::path(
    patch,
    path = "/dhcp/scopes/{prefix}",
    tag = "dhcp",
    operation_id = "update_dhcp_scope",
    summary = "Change a DHCP scope",
    description = "Scope: `dhcp.write`.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope")),
    request_body(content = DhcpScopePatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed scope", body = DhcpScopeItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the scope settings are invalid (`dhcp.scope.invalid`) or the lease times are invalid (`dhcp.lease_times.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`) or no such shared network (`dhcp.shared_network.not_found`) or no such class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The scope changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_dhcp_scope(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(prefix): Path<String>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Update, &scope_object(prefix))?;
    Err(not_implemented("PATCH", "/dhcp/scopes/{prefix}"))
}

#[utoipa::path(
    delete,
    path = "/dhcp/scopes/{prefix}",
    tag = "dhcp",
    operation_id = "delete_dhcp_scope",
    summary = "Delete a DHCP scope (the prefix stays)",
    description = "Scope: `dhcp.write`.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope")),
    responses(
        (status = 204, description = "The scope is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dhcp_scope(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(prefix): Path<String>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Delete, &scope_object(prefix))?;
    Err(not_implemented("DELETE", "/dhcp/scopes/{prefix}"))
}

#[utoipa::path(
    get,
    path = "/dhcp/scopes/{prefix}/utilization",
    tag = "dhcp",
    operation_id = "get_dhcp_scope_utilization",
    summary = "Get how full a DHCP scope is",
    description = "Scope: `dhcp.read`.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope")),
    responses(
        (status = 200, description = "The figures of the scope", body = DhcpScopeUtilization),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_scope_utilization(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(prefix): Path<String>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Read, &scope_object(prefix))?;
    Err(not_implemented("GET", "/dhcp/scopes/{prefix}/utilization"))
}

#[utoipa::path(
    get,
    path = "/dhcp/scopes/{prefix}/effective-options",
    tag = "dhcp",
    operation_id = "get_dhcp_effective_options",
    summary = "Get the options a client gets in a DHCP scope",
    description = "Scope: `dhcp.read`.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope"), EffectiveOptionsParams),
    responses(
        (status = 200, description = "The options with the level each came from", body = EffectiveOptions),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_effective_options(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(prefix): Path<String>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Read, &scope_object(prefix))?;
    Err(not_implemented(
        "GET",
        "/dhcp/scopes/{prefix}/effective-options",
    ))
}

#[utoipa::path(
    get,
    path = "/dhcp/scopes/{prefix}/exclusions",
    tag = "dhcp",
    operation_id = "list_dhcp_exclusions",
    summary = "List the exclusion ranges of a DHCP scope",
    description = "Scope: `dhcp.read`.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope"), PageParams),
    responses(
        (status = 200, description = "A page of exclusion ranges by start address", body = Page<ExclusionItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_exclusions(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(prefix): Path<String>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Read, &scope_object(prefix))?;
    Err(not_implemented("GET", "/dhcp/scopes/{prefix}/exclusions"))
}

#[utoipa::path(
    post,
    path = "/dhcp/scopes/{prefix}/exclusions",
    tag = "dhcp",
    operation_id = "create_dhcp_exclusion",
    summary = "Exclude a range of a DHCP scope",
    description = "Scope: `dhcp.write`.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope")),
    request_body(content = ExclusionCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The exclusion range", body = ExclusionItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the exclusion range is unordered or outside the scope (`dhcp.exclusion.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dhcp_exclusion(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(prefix): Path<String>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Update, &scope_object(prefix))?;
    Err(not_implemented("POST", "/dhcp/scopes/{prefix}/exclusions"))
}

#[utoipa::path(
    delete,
    path = "/dhcp/scopes/{prefix}/exclusions/{id}",
    tag = "dhcp",
    operation_id = "delete_dhcp_exclusion",
    summary = "Delete an exclusion range",
    description = "Scope: `dhcp.write`.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope"), ("id" = String, Path, description = "Exclusion identifier (UUID)")),
    responses(
        (status = 204, description = "The exclusion range is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such exclusion range (`dhcp.exclusion.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dhcp_exclusion(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path((prefix, id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    parse_id::<ExclusionId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &scope_object(prefix))?;
    Err(not_implemented(
        "DELETE",
        "/dhcp/scopes/{prefix}/exclusions/{id}",
    ))
}

#[utoipa::path(
    get,
    path = "/dhcp/shared-networks",
    tag = "dhcp",
    operation_id = "list_dhcp_shared_networks",
    summary = "List DHCP shared networks",
    description = "Scope: `dhcp.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of shared networks by name", body = Page<SharedNetworkItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_shared_networks(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &server_object())?;
    Err(not_implemented("GET", "/dhcp/shared-networks"))
}

#[utoipa::path(
    post,
    path = "/dhcp/shared-networks",
    tag = "dhcp",
    operation_id = "create_dhcp_shared_network",
    summary = "Create a DHCP shared network",
    description = "Scope: `dhcp.write`.",
    request_body(content = SharedNetworkCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The shared network", body = SharedNetworkItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the shared network settings are invalid (`dhcp.shared_network.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dhcp_shared_network(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &server_object())?;
    Err(not_implemented("POST", "/dhcp/shared-networks"))
}

#[utoipa::path(
    get,
    path = "/dhcp/shared-networks/{id}",
    tag = "dhcp",
    operation_id = "get_dhcp_shared_network",
    summary = "Get a DHCP shared network",
    description = "Scope: `dhcp.read`.",
    params(("id" = String, Path, description = "Shared network identifier (UUID)")),
    responses(
        (status = 200, description = "The shared network, with its `ETag`", body = SharedNetworkItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such shared network (`dhcp.shared_network.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_shared_network(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    parse_id::<SharedNetworkId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &server_object())?;
    Err(not_implemented("GET", "/dhcp/shared-networks/{id}"))
}

#[utoipa::path(
    patch,
    path = "/dhcp/shared-networks/{id}",
    tag = "dhcp",
    operation_id = "update_dhcp_shared_network",
    summary = "Change a DHCP shared network",
    description = "Scope: `dhcp.write`.",
    params(("id" = String, Path, description = "Shared network identifier (UUID)")),
    request_body(content = SharedNetworkPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed shared network", body = SharedNetworkItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the shared network settings are invalid (`dhcp.shared_network.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such shared network (`dhcp.shared_network.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The shared network changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_dhcp_shared_network(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    parse_id::<SharedNetworkId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &server_object())?;
    Err(not_implemented("PATCH", "/dhcp/shared-networks/{id}"))
}

#[utoipa::path(
    delete,
    path = "/dhcp/shared-networks/{id}",
    tag = "dhcp",
    operation_id = "delete_dhcp_shared_network",
    summary = "Delete a DHCP shared network",
    description = "Scope: `dhcp.write`.",
    params(("id" = String, Path, description = "Shared network identifier (UUID)")),
    responses(
        (status = 204, description = "The shared network is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such shared network (`dhcp.shared_network.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The shared network still has scopes (`dhcp.shared_network.in_use`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dhcp_shared_network(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    parse_id::<SharedNetworkId>("id", &id)?;
    app.authorize(&cx.principal, Action::Delete, &server_object())?;
    Err(not_implemented("DELETE", "/dhcp/shared-networks/{id}"))
}

#[utoipa::path(
    get,
    path = "/dhcp/pools",
    tag = "dhcp",
    operation_id = "list_dhcp_pools",
    summary = "List DHCP pools",
    description = "Scope: `dhcp.read`.",
    params(PageParams, DhcpScopeFilter),
    responses(
        (status = 200, description = "A page of pools by start address", body = Page<DhcpPoolItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_pools(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("GET", "/dhcp/pools"))
}

#[utoipa::path(
    get,
    path = "/dhcp/pools/{range}",
    tag = "dhcp",
    operation_id = "get_dhcp_pool",
    summary = "Get a DHCP pool",
    description = "Scope: `dhcp.read`. The implementation checks the scope of the pool.",
    params(("range" = String, Path, description = "Range identifier (UUID) of the pool")),
    responses(
        (status = 200, description = "The pool", body = DhcpPoolItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such pool (`dhcp.pool.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_pool(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(range): Path<String>,
) -> Result<Response, ApiError> {
    parse_id::<RangeId>("range", &range)?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("GET", "/dhcp/pools/{range}"))
}

#[utoipa::path(
    put,
    path = "/dhcp/pools/{range}",
    tag = "dhcp",
    operation_id = "set_dhcp_pool",
    summary = "Set the DHCP settings of a pool",
    description = "Scope: `dhcp.write`. The implementation checks the scope of the pool.",
    params(("range" = String, Path, description = "Range identifier (UUID) of the pool")),
    request_body(content = DhcpPoolSet, content_type = "application/json"),
    responses(
        (status = 200, description = "The pool with its settings", body = DhcpPoolItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the lease times are invalid (`dhcp.lease_times.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such pool (`dhcp.pool.not_found`) or no such class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The range is not a DHCP pool (`dhcp.pool.not_pool`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn set_dhcp_pool(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(range): Path<String>,
) -> Result<Response, ApiError> {
    parse_id::<RangeId>("range", &range)?;
    app.authorize(
        &cx.principal,
        Action::Update,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("PUT", "/dhcp/pools/{range}"))
}

#[utoipa::path(
    delete,
    path = "/dhcp/pools/{range}",
    tag = "dhcp",
    operation_id = "delete_dhcp_pool",
    summary = "Remove the DHCP settings of a pool (the range stays)",
    description = "Scope: `dhcp.write`. The implementation checks the scope of the pool.",
    params(("range" = String, Path, description = "Range identifier (UUID) of the pool")),
    responses(
        (status = 204, description = "The settings are gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such pool (`dhcp.pool.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dhcp_pool(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(range): Path<String>,
) -> Result<Response, ApiError> {
    parse_id::<RangeId>("range", &range)?;
    app.authorize(
        &cx.principal,
        Action::Update,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("DELETE", "/dhcp/pools/{range}"))
}

#[utoipa::path(
    get,
    path = "/dhcp/option-catalog",
    tag = "dhcp",
    operation_id = "list_dhcp_option_catalog",
    summary = "List the built-in DHCP options",
    description = "Scope: `dhcp.read`.",
    responses(
        (status = 200, description = "The built-in options in code order", body = Vec<OptionCatalogItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_option_catalog(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpOptionDef),
    )?;
    Err(not_implemented("GET", "/dhcp/option-catalog"))
}

#[utoipa::path(
    get,
    path = "/dhcp/option-defs",
    tag = "dhcp",
    operation_id = "list_dhcp_option_defs",
    summary = "List custom DHCP option definitions",
    description = "Scope: `dhcp.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of definitions by space and code", body = Page<OptionDefItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_option_defs(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpOptionDef),
    )?;
    Err(not_implemented("GET", "/dhcp/option-defs"))
}

#[utoipa::path(
    post,
    path = "/dhcp/option-defs",
    tag = "dhcp",
    operation_id = "create_dhcp_option_def",
    summary = "Define a custom DHCP option",
    description = "Scope: `dhcp.write`.",
    request_body(content = OptionDefCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The definition", body = OptionDefItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or an option value or definition is invalid (`dhcp.option.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The option code is reserved by the catalog or the server (`dhcp.option.code_reserved`) or a definition for this space and code exists (`dhcp.option_def.exists`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dhcp_option_def(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DhcpOptionDef),
    )?;
    Err(not_implemented("POST", "/dhcp/option-defs"))
}

#[utoipa::path(
    get,
    path = "/dhcp/option-defs/{id}",
    tag = "dhcp",
    operation_id = "get_dhcp_option_def",
    summary = "Get a custom DHCP option definition",
    description = "Scope: `dhcp.read`.",
    params(("id" = String, Path, description = "Option definition identifier (UUID)")),
    responses(
        (status = 200, description = "The definition, with its `ETag`", body = OptionDefItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such option definition (`dhcp.option_def.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_option_def(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<OptionDefId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    Err(not_implemented("GET", "/dhcp/option-defs/{id}"))
}

#[utoipa::path(
    patch,
    path = "/dhcp/option-defs/{id}",
    tag = "dhcp",
    operation_id = "update_dhcp_option_def",
    summary = "Change a custom DHCP option definition",
    description = "Scope: `dhcp.write`.",
    params(("id" = String, Path, description = "Option definition identifier (UUID)")),
    request_body(content = OptionDefPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed definition", body = OptionDefItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or an option value or definition is invalid (`dhcp.option.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such option definition (`dhcp.option_def.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The definition is still used by an option set (`dhcp.option_def.in_use`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The option definition changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_dhcp_option_def(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<OptionDefId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    Err(not_implemented("PATCH", "/dhcp/option-defs/{id}"))
}

#[utoipa::path(
    delete,
    path = "/dhcp/option-defs/{id}",
    tag = "dhcp",
    operation_id = "delete_dhcp_option_def",
    summary = "Delete a custom DHCP option definition",
    description = "Scope: `dhcp.write`.",
    params(("id" = String, Path, description = "Option definition identifier (UUID)")),
    responses(
        (status = 204, description = "The definition is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such option definition (`dhcp.option_def.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The definition is still used by an option set (`dhcp.option_def.in_use`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dhcp_option_def(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<OptionDefId>("id", &id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    Err(not_implemented("DELETE", "/dhcp/option-defs/{id}"))
}

#[utoipa::path(
    get,
    path = "/dhcp/option-sets",
    tag = "dhcp",
    operation_id = "list_dhcp_option_sets",
    summary = "List DHCP option sets",
    description = "Scope: `dhcp.read`.",
    params(PageParams, OptionSetFilter),
    responses(
        (status = 200, description = "A page of option sets by level and owner", body = Page<OptionSetItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_option_sets(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("GET", "/dhcp/option-sets"))
}

#[utoipa::path(
    get,
    path = "/dhcp/option-sets/{owner}",
    tag = "dhcp",
    operation_id = "get_dhcp_option_set",
    summary = "Get the DHCP options of a level",
    description = "Scope: `dhcp.read`.",
    params(("owner" = String, Path, description = "Option set owner: `server`, `scope:<prefix>`, `shared_network:<id>`, `pool:<range>`, `policy:<id>` or `host:<interface>`")),
    responses(
        (status = 200, description = "The option set, with its `ETag`", body = OptionSetItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`) or no such pool (`dhcp.pool.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_option_set(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(owner): Path<String>,
) -> Result<Response, ApiError> {
    let owner = parse_owner(&owner)?;
    app.authorize(&cx.principal, Action::Read, &owner_object(owner))?;
    Err(not_implemented("GET", "/dhcp/option-sets/{owner}"))
}

#[utoipa::path(
    put,
    path = "/dhcp/option-sets/{owner}",
    tag = "dhcp",
    operation_id = "set_dhcp_option_set",
    summary = "Replace the DHCP options of a level",
    description = "Scope: `dhcp.write`.",
    params(("owner" = String, Path, description = "Option set owner: `server`, `scope:<prefix>`, `shared_network:<id>`, `pool:<range>`, `policy:<id>` or `host:<interface>`")),
    request_body(content = OptionSetPut, content_type = "application/json"),
    responses(
        (status = 200, description = "The option set", body = OptionSetItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or an option value or definition is invalid (`dhcp.option.invalid`) or an option code has no definition in its space (`dhcp.option.unknown`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The option code is reserved by the catalog or the server (`dhcp.option.code_reserved`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The option set changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn set_dhcp_option_set(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(owner): Path<String>,
) -> Result<Response, ApiError> {
    let owner = parse_owner(&owner)?;
    app.authorize(&cx.principal, Action::Update, &owner_object(owner))?;
    Err(not_implemented("PUT", "/dhcp/option-sets/{owner}"))
}

#[utoipa::path(
    delete,
    path = "/dhcp/option-sets/{owner}",
    tag = "dhcp",
    operation_id = "delete_dhcp_option_set",
    summary = "Clear the DHCP options of a level",
    description = "Scope: `dhcp.write`.",
    params(("owner" = String, Path, description = "Option set owner: `server`, `scope:<prefix>`, `shared_network:<id>`, `pool:<range>`, `policy:<id>` or `host:<interface>`")),
    responses(
        (status = 204, description = "The option set is empty"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dhcp_option_set(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(owner): Path<String>,
) -> Result<Response, ApiError> {
    let owner = parse_owner(&owner)?;
    app.authorize(&cx.principal, Action::Update, &owner_object(owner))?;
    Err(not_implemented("DELETE", "/dhcp/option-sets/{owner}"))
}

#[utoipa::path(
    get,
    path = "/dhcp/classes",
    tag = "dhcp",
    operation_id = "list_dhcp_classes",
    summary = "List DHCP classes",
    description = "Scope: `dhcp.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of classes by name", body = Page<DhcpClassItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_classes(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpClass),
    )?;
    Err(not_implemented("GET", "/dhcp/classes"))
}

#[utoipa::path(
    post,
    path = "/dhcp/classes",
    tag = "dhcp",
    operation_id = "create_dhcp_class",
    summary = "Create a DHCP class",
    description = "Scope: `dhcp.write`.",
    request_body(content = DhcpClassCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The class", body = DhcpClassItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the class is invalid (`dhcp.class.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dhcp_class(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DhcpClass),
    )?;
    Err(not_implemented("POST", "/dhcp/classes"))
}

#[utoipa::path(
    get,
    path = "/dhcp/classes/{id}",
    tag = "dhcp",
    operation_id = "get_dhcp_class",
    summary = "Get a DHCP class",
    description = "Scope: `dhcp.read`.",
    params(("id" = String, Path, description = "Class identifier (UUID)")),
    responses(
        (status = 200, description = "The class, with its `ETag`", body = DhcpClassItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_class(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ClassId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    Err(not_implemented("GET", "/dhcp/classes/{id}"))
}

#[utoipa::path(
    patch,
    path = "/dhcp/classes/{id}",
    tag = "dhcp",
    operation_id = "update_dhcp_class",
    summary = "Change a DHCP class",
    description = "Scope: `dhcp.write`.",
    params(("id" = String, Path, description = "Class identifier (UUID)")),
    request_body(content = DhcpClassPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed class", body = DhcpClassItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the class is invalid (`dhcp.class.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The class changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_dhcp_class(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ClassId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    Err(not_implemented("PATCH", "/dhcp/classes/{id}"))
}

#[utoipa::path(
    delete,
    path = "/dhcp/classes/{id}",
    tag = "dhcp",
    operation_id = "delete_dhcp_class",
    summary = "Delete a DHCP class",
    description = "Scope: `dhcp.write`.",
    params(("id" = String, Path, description = "Class identifier (UUID)")),
    responses(
        (status = 204, description = "The class is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The class is still named by a scope, a pool or a policy (`dhcp.class.in_use`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dhcp_class(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ClassId>("id", &id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    Err(not_implemented("DELETE", "/dhcp/classes/{id}"))
}

#[utoipa::path(
    get,
    path = "/dhcp/policies",
    tag = "dhcp",
    operation_id = "list_dhcp_policies",
    summary = "List DHCP policies",
    description = "Scope: `dhcp.read`.",
    params(PageParams, DhcpPolicyFilter),
    responses(
        (status = 200, description = "A page of policies in evaluation order", body = Page<DhcpPolicyItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_policies(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpPolicy),
    )?;
    Err(not_implemented("GET", "/dhcp/policies"))
}

#[utoipa::path(
    post,
    path = "/dhcp/policies",
    tag = "dhcp",
    operation_id = "create_dhcp_policy",
    summary = "Create a DHCP policy",
    description = "Scope: `dhcp.write`.",
    request_body(content = DhcpPolicyCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The policy", body = DhcpPolicyItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the policy is invalid (`dhcp.policy.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`) or no such class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dhcp_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DhcpPolicy),
    )?;
    Err(not_implemented("POST", "/dhcp/policies"))
}

#[utoipa::path(
    get,
    path = "/dhcp/policies/{id}",
    tag = "dhcp",
    operation_id = "get_dhcp_policy",
    summary = "Get a DHCP policy",
    description = "Scope: `dhcp.read`.",
    params(("id" = String, Path, description = "Policy identifier (UUID)")),
    responses(
        (status = 200, description = "The policy, with its `ETag`", body = DhcpPolicyItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such policy (`dhcp.policy.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<PolicyId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    Err(not_implemented("GET", "/dhcp/policies/{id}"))
}

#[utoipa::path(
    patch,
    path = "/dhcp/policies/{id}",
    tag = "dhcp",
    operation_id = "update_dhcp_policy",
    summary = "Change a DHCP policy",
    description = "Scope: `dhcp.write`.",
    params(("id" = String, Path, description = "Policy identifier (UUID)")),
    request_body(content = DhcpPolicyPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed policy", body = DhcpPolicyItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the policy is invalid (`dhcp.policy.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such policy (`dhcp.policy.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The policy changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_dhcp_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<PolicyId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    Err(not_implemented("PATCH", "/dhcp/policies/{id}"))
}

#[utoipa::path(
    delete,
    path = "/dhcp/policies/{id}",
    tag = "dhcp",
    operation_id = "delete_dhcp_policy",
    summary = "Delete a DHCP policy",
    description = "Scope: `dhcp.write`.",
    params(("id" = String, Path, description = "Policy identifier (UUID)")),
    responses(
        (status = 204, description = "The policy is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such policy (`dhcp.policy.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dhcp_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<PolicyId>("id", &id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    Err(not_implemented("DELETE", "/dhcp/policies/{id}"))
}

#[utoipa::path(
    get,
    path = "/dhcp/filters",
    tag = "dhcp",
    operation_id = "list_dhcp_filters",
    summary = "List DHCP MAC filters",
    description = "Scope: `dhcp.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of filter entries", body = Page<DhcpFilterItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_filters(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpFilter),
    )?;
    Err(not_implemented("GET", "/dhcp/filters"))
}

#[utoipa::path(
    post,
    path = "/dhcp/filters",
    tag = "dhcp",
    operation_id = "create_dhcp_filter",
    summary = "Add a DHCP MAC filter",
    description = "Scope: `dhcp.write`.",
    request_body(content = DhcpFilterCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The filter entry", body = DhcpFilterItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the filter entry is invalid (`dhcp.filter.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "An entry for this pattern exists (`dhcp.filter.exists`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dhcp_filter(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DhcpFilter),
    )?;
    Err(not_implemented("POST", "/dhcp/filters"))
}

#[utoipa::path(
    get,
    path = "/dhcp/filters/{id}",
    tag = "dhcp",
    operation_id = "get_dhcp_filter",
    summary = "Get a DHCP MAC filter",
    description = "Scope: `dhcp.read`.",
    params(("id" = String, Path, description = "Filter entry identifier (UUID)")),
    responses(
        (status = 200, description = "The filter entry, with its `ETag`", body = DhcpFilterItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such filter entry (`dhcp.filter.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_filter(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<FilterId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    Err(not_implemented("GET", "/dhcp/filters/{id}"))
}

#[utoipa::path(
    patch,
    path = "/dhcp/filters/{id}",
    tag = "dhcp",
    operation_id = "update_dhcp_filter",
    summary = "Change a DHCP MAC filter",
    description = "Scope: `dhcp.write`.",
    params(("id" = String, Path, description = "Filter entry identifier (UUID)")),
    request_body(content = DhcpFilterPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed filter entry", body = DhcpFilterItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the filter entry is invalid (`dhcp.filter.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such filter entry (`dhcp.filter.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "An entry for this pattern exists (`dhcp.filter.exists`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The filter entry changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_dhcp_filter(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<FilterId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    Err(not_implemented("PATCH", "/dhcp/filters/{id}"))
}

#[utoipa::path(
    delete,
    path = "/dhcp/filters/{id}",
    tag = "dhcp",
    operation_id = "delete_dhcp_filter",
    summary = "Delete a DHCP MAC filter",
    description = "Scope: `dhcp.write`.",
    params(("id" = String, Path, description = "Filter entry identifier (UUID)")),
    responses(
        (status = 204, description = "The filter entry is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such filter entry (`dhcp.filter.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dhcp_filter(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<FilterId>("id", &id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    Err(not_implemented("DELETE", "/dhcp/filters/{id}"))
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

#[utoipa::path(
    get,
    path = "/dhcp/leases",
    tag = "dhcp",
    operation_id = "list_dhcp_leases",
    summary = "List DHCP leases",
    description = "Scope: `dhcp.read`. Reading leases is audited (`dhcp.lease.read`).",
    params(DhcpLeaseFilters),
    responses(
        (status = 200, description = "A page of leases by address", body = Page<DhcpLeaseItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_leases(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("GET", "/dhcp/leases"))
}

#[utoipa::path(
    get,
    path = "/dhcp/leases/{addr}",
    tag = "dhcp",
    operation_id = "get_dhcp_lease",
    summary = "Get the DHCP lease of an address",
    description = "Scope: `dhcp.read`.",
    params(("addr" = String, Path, description = "IPv4 address of the lease"), DhcpLeaseParams),
    responses(
        (status = 200, description = "The lease", body = DhcpLeaseItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No lease holds the address (`dhcp.lease.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dhcp_lease(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(addr): Path<String>,
) -> Result<Response, ApiError> {
    parse_addr(&addr)?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("GET", "/dhcp/leases/{addr}"))
}

#[utoipa::path(
    post,
    path = "/dhcp/leases/{addr}/release",
    tag = "dhcp",
    operation_id = "release_dhcp_lease",
    summary = "Release a DHCP lease (the address returns to the pool)",
    description = "Scope: `dhcp.write`.",
    params(("addr" = String, Path, description = "IPv4 address of the lease")),
    request_body(content = DhcpLeaseRelease, content_type = "application/json"),
    responses(
        (status = 200, description = "The released lease", body = DhcpLeaseItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No lease holds the address (`dhcp.lease.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The lease is not in a state the operation accepts (`dhcp.lease.state`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The store refused the lease write (`dhcp.store_refused`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn release_dhcp_lease(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(addr): Path<String>,
) -> Result<Response, ApiError> {
    parse_addr(&addr)?;
    app.authorize(
        &cx.principal,
        Action::Execute,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("POST", "/dhcp/leases/{addr}/release"))
}

#[utoipa::path(
    get,
    path = "/dhcp/history",
    tag = "dhcp",
    operation_id = "list_dhcp_history",
    summary = "Read the DHCP lease history",
    description = "Scope: `dhcp.read`. Reading the history is audited (`dhcp.lease.read`).",
    params(DhcpHistoryFilters),
    responses(
        (status = 200, description = "A page of lease events, newest first", body = Page<DhcpHistoryItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dhcp_history(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("GET", "/dhcp/history"))
}

#[utoipa::path(
    get,
    path = "/dhcp/export",
    tag = "dhcp",
    operation_id = "export_dhcp",
    summary = "Export the DHCP configuration and leases (Kea JSON)",
    description = "Scope: `dhcp.read`. The export is audited (`dhcp.export`).",
    params(DhcpExportParams),
    responses(
        (status = 200, description = "The export", body = DhcpExport),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the export format is not known (`dhcp.export.format`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn export_dhcp(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &server_object())?;
    Err(not_implemented("GET", "/dhcp/export"))
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dhcp",
    tag = "dhcp",
    operation_id = "get_node_dhcp_status",
    summary = "Get the DHCP role of a node",
    description = "Scope: `dhcp.read`.",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 200, description = "The report of the DHCP role", body = DhcpNodeStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dhcp role (`dhcp.node.not_dhcp`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_node_dhcp_status(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(node))?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("GET", "/nodes/{id}/dhcp"))
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dhcp/leases",
    tag = "dhcp",
    operation_id = "list_node_dhcp_leases",
    summary = "List the leases a node's DHCP role holds",
    description = "Scope: `dhcp.read`. The node command `dhcp.leases.list`, audited.",
    params(("id" = u64, Path, description = "Node id"), DhcpLeaseFilters),
    responses(
        (status = 200, description = "A page of leases by address", body = Page<DhcpLeaseItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dhcp role (`dhcp.node.not_dhcp`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_node_dhcp_leases(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(node))?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("GET", "/nodes/{id}/dhcp/leases"))
}

#[utoipa::path(
    post,
    path = "/nodes/{id}/dhcp/leases/{addr}/release",
    tag = "dhcp",
    operation_id = "release_node_dhcp_lease",
    summary = "Release a lease on a node's DHCP role",
    description = "Scope: `dhcp.write`. The node command `dhcp.lease.release`.",
    params(("id" = u64, Path, description = "Node id"), ("addr" = String, Path, description = "IPv4 address of the lease")),
    request_body(content = DhcpLeaseRelease, content_type = "application/json"),
    responses(
        (status = 202, description = "The command is recorded", body = DhcpCommandAccepted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dhcp role (`dhcp.node.not_dhcp`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn release_node_dhcp_lease(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path((id, addr)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    parse_addr(&addr)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(node))?;
    app.authorize(
        &cx.principal,
        Action::Execute,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented(
        "POST",
        "/nodes/{id}/dhcp/leases/{addr}/release",
    ))
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dhcp/history",
    tag = "dhcp",
    operation_id = "read_node_dhcp_history",
    summary = "Read the lease history through a node's DHCP role",
    description = "Scope: `dhcp.read`. The node command `dhcp.history.read`, audited.",
    params(("id" = u64, Path, description = "Node id"), DhcpHistoryFilters),
    responses(
        (status = 200, description = "A page of lease events, newest first", body = Page<DhcpHistoryItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dhcp role (`dhcp.node.not_dhcp`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn read_node_dhcp_history(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(node))?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    Err(not_implemented("GET", "/nodes/{id}/dhcp/history"))
}

#[utoipa::path(
    get,
    path = "/ipam/reconcile",
    tag = "observations",
    operation_id = "get_ipam_reconcile",
    summary = "Get the reconciliation view of the four truths",
    description = "Scope: read access to observations (IAM-01). IPAM-21.",
    params(ReconcileFilters),
    responses(
        (status = 200, description = "A page of rows, one per difference between the truths", body = Page<ReconcileRow>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read observations", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_ipam_reconcile(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::Observation),
    )?;
    Err(not_implemented("GET", "/ipam/reconcile"))
}
