//! Hosts and their interfaces.
//!
//! Area: hosts. Owner: WP1.4. Requirements: IPAM-05, IPAM-07.
//!
//! A host owns interfaces, and an interface carries MAC addresses and links to addresses.
//! History, restore and bulk changes are in [`super::common`], which also documents the
//! conventions every endpoint here follows: the IPAM service as a request extension (503
//! `ipam.unavailable` without it), the list parameters, `ETag` and `If-Match`,
//! `Idempotency-Key`, `dry_run` and `acknowledge`, and the authorization checks.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /hosts` | 200 page of hosts | 400 `sys.invalid_query`, `sys.invalid_cursor` |
//! | `POST /hosts` | 201 write response, 200 for a dry run or a replay | 400, 403, 409 `ipam.name_taken`, `ipam.reference_missing`, 422 `ipam.idempotency_mismatch` |
//! | `GET /hosts/{id}` | 200 host with `ETag` | 404 `ipam.not_found` |
//! | `PATCH /hosts/{id}` | 200 write response | 404, 409 `ipam.name_taken`, 412 `ipam.revision_mismatch`, 423 `ipam.host.locked` |
//! | `DELETE /hosts/{id}` | 200 write response with the deleted host | 404, 409 `ipam.in_use`, 412, 423 |
//! | `GET /hosts/{id}/interfaces` | 200 page of the host's interfaces | 400, 404 |
//! | `POST /hosts/{id}/interfaces` | 201 write response | 400 (`host` in the body is another host), 409 `ipam.reference_missing`, `ipam.name_taken`, 423 |
//! | `GET /interfaces/{id}` | 200 interface with `ETag` | 404 |
//! | `PATCH /interfaces/{id}` | 200 write response | 404, 409 `ipam.name_taken`, 412, 423 |
//! | `DELETE /interfaces/{id}` | 200 write response with the deleted interface | 404, 409 `ipam.in_use`, 412, 423 |
//!
//! # Hosts
//!
//! A host belongs to a tenant (the default tenant when `tenant` is left out), has an
//! assignment mode (`static`, `reserved`, `dynamic` or `unmanaged`, IPAM-14), a lock against
//! automation (IPAM-16) and optionally a site. `POST /hosts` may carry the host's
//! `interfaces`, which are created with the host in one plan. A `reserved` host without a
//! MAC address (IPv4) or DUID (IPv6) is created with the warning
//! `ipam.host.reservation_identifier` (IPAM-18). Only people lock and unlock a host: automation
//! that tries gets 403 `ipam.host.lock_manual_only`, and automation that changes a locked host
//! gets 423 `ipam.host.locked`.
//!
//! The list takes the filters `tenant`, `site`, `mode`, `locked` (`true` or `false`),
//! `lifecycle` (`active` by default, `decommissioned` or `all`; see [`super::host_lifecycle`]),
//! `tag`, `q` (text over the name, the description and the tags), `sort` (`name` by default,
//! `mode`, `created`, `updated`) and `deleted`.
//!
//! # Deleting
//!
//! A host cannot be deleted while a live address is assigned to one of its interfaces (409
//! `ipam.in_use`). With `cascade=true` the plan deletes its interfaces and those addresses
//! along with it; `dry_run=true` shows what would go. The same holds for an interface and its
//! addresses.
//!
//! # Interfaces
//!
//! The interfaces of a host are created under it: `POST /hosts/{id}/interfaces` takes the
//! host from the path, and a `host` in the body that names another host is a 400
//! `ipam.validation`. A host that does not exist (or is deleted) is a 409
//! `ipam.reference_missing`, as for every reference in a body. The name of an interface is
//! unique per host, ignoring case. A MAC address that another live interface carries is
//! allowed with the warning `ipam.interface.duplicate_mac`.
//! `GET /hosts/{id}/interfaces` lists the interfaces of one host with the filters `tag`, `q`,
//! `sort` (`name`, `created`, `updated`) and `deleted`; the host must exist.

use axum::{Json, extract::State, http::HeaderMap, response::Response};
use tenko_core::{
    Action, HostId, InterfaceId, ObjectKind, ObjectRef, Revision,
    ipam::{Host, Interface},
};
use tenko_ipam::{
    IpamCommand, IpamError,
    command::{HostInput, HostPatch, InterfaceInput, InterfacePatch, UpdateHost, UpdateInterface},
    query,
};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::common::{
    DeleteParams, Filter, IdempotencyKeyHeader, IfMatch, Ipam, IpamJson, IpamPath, ReadParams,
    WriteParams, WriteResponse, authorize, get_one, if_match, list_args, list_collection,
    list_scoped, new_of, wire_page, write_args, write_one,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{Filters, PageParams},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_hosts, create_host))
        .routes(routes!(get_host, update_host, delete_host))
        .routes(routes!(list_host_interfaces, create_interface))
        .routes(routes!(get_interface, update_interface, delete_interface))
}

// ===== hosts =========================================================================

/// Lists hosts, by name unless `sort` says otherwise.
#[utoipa::path(
    get,
    path = "/hosts",
    tag = "hosts",
    operation_id = "list_hosts",
    summary = "List hosts",
    params(
        PageParams,
        ("tenant" = Option<String>, Query, description = "Only hosts of this tenant (identifier)."),
        ("site" = Option<String>, Query, description = "Only hosts at this site (identifier)."),
        ("mode" = Option<String>, Query, description = "Only hosts with this assignment mode: `static`, `reserved`, `dynamic` or `unmanaged`."),
        ("locked" = Option<bool>, Query, description = "Only hosts that are locked (`true`) or not locked (`false`) against automation."),
        ("lifecycle" = Option<String>, Query, description = "Hosts by lifecycle state: `active` (the default: hosts that are not decommissioned), `decommissioned` (the cleanup view) or `all`."),
        ("tag" = Option<String>, Query, description = "Only hosts that carry every one of these tags. Repeat the parameter or separate the tags with commas."),
        ("q" = Option<String>, Query, description = "Case-insensitive text search over the name, the description and the tags."),
        ("sort" = Option<String>, Query, description = "Sort order: comma-separated fields, `-` in front for descending, for example `-updated,name`. Fields: `name` (the default), `mode`, `created`, `updated`."),
        ("deleted" = Option<String>, Query, description = "Deleted hosts: `exclude` (the default), `include` or `only` (the restore view).")
    ),
    responses(
        (status = 200, description = "A page of hosts", body = Page<Host>),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_hosts(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<Page<Host>>, ApiError> {
    let args = list_args::<Host>(
        &filters,
        "ipam.hosts",
        &[
            Filter::Tenant,
            Filter::Site,
            Filter::Mode,
            Filter::Locked,
            Filter::Lifecycle,
            Filter::Tag,
            Filter::Q,
            Filter::Sort,
            Filter::Deleted,
        ],
    )?;
    list_collection::<Host>(&app, &cx, &ipam, args).await
}

/// Creates a host, with its interfaces when the body lists them. The name is unique within
/// the tenant.
#[utoipa::path(
    post,
    path = "/hosts",
    tag = "hosts",
    operation_id = "create_host",
    summary = "Create a host",
    params(WriteParams, IdempotencyKeyHeader),
    request_body = HostInput,
    responses(
        (status = 201, description = "The new host, with `ETag`; the plan warnings say, for example, that a reserved host has no MAC address (`ipam.host.reservation_identifier`)", body = WriteResponse<Host>),
        (status = 200, description = "The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true)", body = WriteResponse<Host>),
        (status = 400, description = "Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The name is taken in the tenant (or an interface name twice), the identifier is in use, or the tenant or site is missing (`ipam.name_taken`, `ipam.id_taken`, `ipam.reference_missing`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_host(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
    IpamJson(input): IpamJson<HostInput>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    authorize(&app, &cx, Action::Create, new_of(ObjectKind::Host))?;
    let command = IpamCommand::CreateHost(input);
    write_one::<Host>(&ipam, &cx, vec![command], &args, true).await
}

/// Shows one host with its `ETag`. A deleted host is shown too: it carries `meta.deleted`.
#[utoipa::path(
    get,
    path = "/hosts/{id}",
    tag = "hosts",
    operation_id = "get_host",
    summary = "Get one host",
    params(("id" = String, Path, description = "Host identifier"), ReadParams),
    responses(
        (status = 200, description = "The host, with `ETag`", body = Host),
        (status = 400, description = "Invalid parameter (`sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such host (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_host(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<HostId>,
    filters: Filters,
) -> Result<Response, ApiError> {
    get_one::<Host>(&app, &cx, &ipam, id, &filters).await
}

/// Changes a host: the name, the assignment mode, the lock (people only), the site (`null`
/// clears it), the tags, the custom fields and the description. The tenant cannot change.
#[utoipa::path(
    patch,
    path = "/hosts/{id}",
    tag = "hosts",
    operation_id = "update_host",
    summary = "Update a host",
    params(("id" = String, Path, description = "Host identifier"), WriteParams, IfMatch),
    request_body = HostPatch,
    responses(
        (status = 200, description = "The changed host, with `ETag`, or the plan of a dry run", body = WriteResponse<Host>),
        (status = 400, description = "Invalid body or parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed, or automation tried to lock or unlock (`auth.forbidden`, `ipam.host.lock_manual_only`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such host (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The name is taken in the tenant, the site is missing, or the host is deleted (`ipam.name_taken`, `ipam.reference_missing`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "The host is locked against automation (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_host(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<HostId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(patch): IpamJson<HostPatch>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Update, id.into())?;
    let command = IpamCommand::UpdateHost(UpdateHost {
        id,
        expected,
        patch,
    });
    write_one::<Host>(&ipam, &cx, vec![command], &args, false).await
}

/// Soft-deletes a host. Without `cascade` the host must have no live address on its
/// interfaces; with `cascade=true` its interfaces and their addresses are deleted with it.
/// The answer carries the deleted host.
#[utoipa::path(
    delete,
    path = "/hosts/{id}",
    tag = "hosts",
    operation_id = "delete_host",
    summary = "Delete a host",
    params(("id" = String, Path, description = "Host identifier"), DeleteParams, IfMatch),
    responses(
        (status = 200, description = "The deleted host (`meta.deleted` is set), or the plan of a dry run", body = WriteResponse<Host>),
        (status = 400, description = "Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such host (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Addresses are assigned to the host and `cascade` is not set, or the host is deleted already (`ipam.in_use`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "The host is locked against automation (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_host(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<HostId>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, true)?;
    let expected = if_match(&headers)?;
    let object: ObjectRef = id.into();
    authorize(&app, &cx, Action::Delete, object)?;
    let command = IpamCommand::Delete {
        object,
        expected,
        cascade: args.cascade,
    };
    write_one::<Host>(&ipam, &cx, vec![command], &args, false).await
}

// ===== interfaces ====================================================================

/// Lists the interfaces of one host, by name unless `sort` says otherwise.
#[utoipa::path(
    get,
    path = "/hosts/{id}/interfaces",
    tag = "hosts",
    operation_id = "list_host_interfaces",
    summary = "List the interfaces of a host",
    params(
        ("id" = String, Path, description = "Host identifier"),
        PageParams,
        ("tag" = Option<String>, Query, description = "Only interfaces that carry every one of these tags. Repeat the parameter or separate the tags with commas."),
        ("q" = Option<String>, Query, description = "Case-insensitive text search over the name, the MAC address, the description and the tags."),
        ("sort" = Option<String>, Query, description = "Sort order: comma-separated fields, `-` in front for descending, for example `-updated,name`. Fields: `name` (the default), `created`, `updated`."),
        ("deleted" = Option<String>, Query, description = "Deleted interfaces: `exclude` (the default), `include` or `only` (the restore view).")
    ),
    responses(
        (status = 200, description = "A page of the interfaces of the host", body = Page<Interface>),
        (status = 400, description = "Invalid parameter (`sys.invalid_request`, `sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to read the host (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such host (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_host_interfaces(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<HostId>,
    filters: Filters,
) -> Result<Json<Page<Interface>>, ApiError> {
    // The host is part of the scope, so that a cursor of one host's list is refused on
    // another's.
    let endpoint = format!("ipam.hosts.{id}.interfaces");
    let mut args = list_args::<Interface>(
        &filters,
        &endpoint,
        &[Filter::Tag, Filter::Q, Filter::Sort, Filter::Deleted],
    )?;
    args.query.host = Some(id);
    authorize(&app, &cx, Action::Read, id.into())?;
    let view = ipam.view(args.page.at_least.map(Revision)).await?;
    query::get::<Host>(view.as_ref(), id)?;
    let scope = ipam.read_scope(&cx, ObjectKind::Interface);
    let page = list_scoped::<Interface>(view.as_ref(), &args.query, &scope)?;
    Ok(Json(wire_page(page, args.scope)))
}

/// Adds an interface to a host. The host comes from the path; a `host` in the body must be
/// the same. The name is unique per host, ignoring case.
#[utoipa::path(
    post,
    path = "/hosts/{id}/interfaces",
    tag = "hosts",
    operation_id = "create_interface",
    summary = "Add an interface to a host",
    params(("id" = String, Path, description = "Host identifier"), WriteParams, IdempotencyKeyHeader),
    request_body = InterfaceInput,
    responses(
        (status = 201, description = "The new interface, with `ETag`; a MAC address that another interface carries is a warning (`ipam.interface.duplicate_mac`)", body = WriteResponse<Interface>),
        (status = 200, description = "The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true)", body = WriteResponse<Interface>),
        (status = 400, description = "Invalid body or parameter, or the `host` of the body is another host (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The host does not exist or is deleted, the name is taken on the host, or the identifier is in use (`ipam.reference_missing`, `ipam.name_taken`, `ipam.id_taken`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "The host is locked against automation (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_interface(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<HostId>,
    filters: Filters,
    IpamJson(mut input): IpamJson<InterfaceInput>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    authorize(&app, &cx, Action::Create, new_of(ObjectKind::Interface))?;
    if input.host.is_some_and(|host| host != id) {
        return Err(IpamError::invalid(
            "host",
            format!("the interface is added to host {id}, but the body names another host"),
        )
        .into());
    }
    input.host = Some(id);
    let command = IpamCommand::CreateInterface(input);
    write_one::<Interface>(&ipam, &cx, vec![command], &args, true).await
}

/// Shows one interface with its `ETag`. A deleted interface is shown too: it carries
/// `meta.deleted`.
#[utoipa::path(
    get,
    path = "/interfaces/{id}",
    tag = "hosts",
    operation_id = "get_interface",
    summary = "Get one interface",
    params(("id" = String, Path, description = "Interface identifier"), ReadParams),
    responses(
        (status = 200, description = "The interface, with `ETag`", body = Interface),
        (status = 400, description = "Invalid parameter (`sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such interface (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_interface(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<InterfaceId>,
    filters: Filters,
) -> Result<Response, ApiError> {
    get_one::<Interface>(&app, &cx, &ipam, id, &filters).await
}

/// Changes an interface: the name, the MAC address, the DUID and the client identifier
/// (`null` clears them), the tags, the custom fields and the description. The host cannot
/// change.
#[utoipa::path(
    patch,
    path = "/interfaces/{id}",
    tag = "hosts",
    operation_id = "update_interface",
    summary = "Update an interface",
    params(("id" = String, Path, description = "Interface identifier"), WriteParams, IfMatch),
    request_body = InterfacePatch,
    responses(
        (status = 200, description = "The changed interface, with `ETag`, or the plan of a dry run", body = WriteResponse<Interface>),
        (status = 400, description = "Invalid body or parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such interface (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The name is taken on the host, or the interface is deleted (`ipam.name_taken`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "The host is locked against automation (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_interface(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<InterfaceId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(patch): IpamJson<InterfacePatch>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Update, id.into())?;
    let command = IpamCommand::UpdateInterface(UpdateInterface {
        id,
        expected,
        patch,
    });
    write_one::<Interface>(&ipam, &cx, vec![command], &args, false).await
}

/// Soft-deletes an interface. Without `cascade` the interface must have no live address;
/// with `cascade=true` its addresses are deleted with it. The answer carries the deleted
/// interface.
#[utoipa::path(
    delete,
    path = "/interfaces/{id}",
    tag = "hosts",
    operation_id = "delete_interface",
    summary = "Delete an interface",
    params(("id" = String, Path, description = "Interface identifier"), DeleteParams, IfMatch),
    responses(
        (status = 200, description = "The deleted interface (`meta.deleted` is set), or the plan of a dry run", body = WriteResponse<Interface>),
        (status = 400, description = "Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such interface (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Addresses are assigned to the interface and `cascade` is not set, or the interface is deleted already (`ipam.in_use`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "The host is locked against automation (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_interface(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<InterfaceId>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, true)?;
    let expected = if_match(&headers)?;
    let object: ObjectRef = id.into();
    authorize(&app, &cx, Action::Delete, object)?;
    let command = IpamCommand::Delete {
        object,
        expected,
        cascade: args.cascade,
    };
    write_one::<Interface>(&ipam, &cx, vec![command], &args, false).await
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use tenko_core::{Action, HostId, InterfaceId, ObjectKind, ObjectRef};

    use super::super::tenancy::testkit::{Api, Policy, Reply, ip4, label, unknown_id};
    use crate::state::AppState;

    fn host_body(n: usize) -> Value {
        json!({ "name": label("host", n) })
    }

    fn mac(n: usize) -> String {
        format!("00-00-5E-00-53-{n:02X}")
    }

    /// A host with the interfaces `eth0` (MAC `00-00-5E-00-53-01`) and `eth1`.
    fn host_with_interfaces(n: usize) -> Value {
        json!({
            "name": label("host", n),
            "interfaces": [
                { "name": "eth0", "mac": mac(1) },
                { "name": "eth1" },
            ],
        })
    }

    /// Creates a host and returns its identifier.
    async fn make_host(api: &Api, n: usize) -> String {
        api.create("/hosts", &host_body(n)).await["id"]
            .as_str()
            .expect("id")
            .to_owned()
    }

    /// Adds an interface to a host and returns its identifier.
    async fn make_interface(api: &Api, host: &str, name: &str) -> String {
        let reply = api
            .post(
                &format!("/hosts/{host}/interfaces"),
                &json!({ "name": name }),
            )
            .await;
        reply.assert_write(201);
        reply.item_id()
    }

    /// Assigns an address of `192.0.2.0/24` to an interface (the prefix must exist).
    async fn assign(api: &Api, interface: &str, host_part: usize) -> String {
        let body = json!({ "ip": ip4(host_part), "interface": interface });
        let reply = api.post("/addresses", &body).await;
        reply.assert_write(201);
        reply.item_id()
    }

    /// The identifiers that a list answers.
    async fn ids_at(api: &Api, path: &str) -> Vec<String> {
        let reply = api.get(path).await;
        reply.assert_json(200);
        reply.ids()
    }

    fn id_of(value: &Value) -> String {
        value["id"].as_str().expect("id").to_owned()
    }

    // Hosts: create and read.

    #[tokio::test]
    async fn create_answers_201_with_defaults_and_an_etag() {
        let api = Api::new();
        let reply = api.post("/hosts", &host_body(1)).await;
        reply.assert_write(201);
        let item = reply.item();
        assert_eq!(item["name"], label("host", 1));
        assert_eq!(item["mode"], "static");
        assert_eq!(item["lock"], false);
        assert_eq!(item["site"], Value::Null);
        assert_eq!(item["meta"]["deleted"], Value::Null);
        // The host landed in the tenant `default`.
        let tenants = api.get("/tenants").await;
        assert_eq!(tenants.texts("name"), ["default"]);
        assert_eq!(tenants.ids(), [item["tenant"].as_str().expect("tenant")]);
    }

    #[tokio::test]
    async fn create_keeps_the_given_members() {
        let api = Api::new();
        let tenant = api
            .create("/tenants", &json!({ "name": label("tenant", 1) }))
            .await;
        let site = api
            .create("/sites", &json!({ "name": label("site", 1) }))
            .await;
        let body = json!({
            "name": "NAS01.Example.Test",
            "tenant": tenant["id"],
            "mode": "unmanaged",
            "lock": true,
            "site": site["id"],
            "tags": ["storage"],
            "description": "Network storage",
        });
        let reply = api.post("/hosts", &body).await;
        reply.assert_write(201);
        let item = reply.item();
        assert_eq!(item["name"], "nas01.example.test");
        assert_eq!(item["tenant"], tenant["id"]);
        assert_eq!(item["mode"], "unmanaged");
        assert_eq!(item["lock"], true);
        assert_eq!(item["site"], site["id"]);
        assert_eq!(item["meta"]["tags"], json!(["storage"]));
        assert_eq!(item["meta"]["description"], "Network storage");
    }

    #[tokio::test]
    async fn create_with_interfaces_creates_them_with_the_host() {
        let api = Api::new();
        let reply = api.post("/hosts", &host_with_interfaces(1)).await;
        reply.assert_write(201);
        let host = reply.item_id();
        let interfaces = api.get(&format!("/hosts/{host}/interfaces")).await;
        interfaces.assert_json(200);
        assert_eq!(interfaces.texts("name"), ["eth0", "eth1"]);
        assert_eq!(interfaces.texts("host"), [host.clone(), host]);
        assert_eq!(interfaces.items()[0]["mac"], "00:00:5e:00:53:01");
        assert_eq!(interfaces.items()[1]["mac"], Value::Null);
        // One write: the host and its interfaces share the revision.
        let revision = reply.revision();
        for interface in interfaces.items() {
            assert_eq!(interface["meta"]["revision"], revision);
        }
    }

    #[tokio::test]
    async fn get_returns_the_host_with_the_etag_of_the_write() {
        let api = Api::new();
        let created = api.post("/hosts", &host_body(1)).await;
        let reply = api.get(&format!("/hosts/{}", created.item_id())).await;
        reply.assert_json(200);
        assert_eq!(&reply.body, created.item());
        assert_eq!(reply.etag, created.etag);
    }

    #[tokio::test]
    async fn an_unknown_host_or_interface_is_a_404_problem() {
        let api = Api::new();
        let id = unknown_id();
        let body = json!({ "description": "x" });
        let replies = [
            (api.get(&format!("/hosts/{id}")).await, "host"),
            (
                api.patch(&format!("/hosts/{id}"), None, &body).await,
                "host",
            ),
            (api.delete(&format!("/hosts/{id}"), None).await, "host"),
            (api.get(&format!("/hosts/{id}/interfaces")).await, "host"),
            (api.get(&format!("/interfaces/{id}")).await, "interface"),
            (
                api.patch(&format!("/interfaces/{id}"), None, &body).await,
                "interface",
            ),
            (
                api.delete(&format!("/interfaces/{id}"), None).await,
                "interface",
            ),
        ];
        for (reply, kind) in replies {
            reply.assert_problem(404, "ipam.not_found");
            assert_eq!(reply.body["params"]["kind"], kind);
            assert_eq!(reply.body["params"]["id"], id);
        }
        for path in [
            "/hosts/not-a-uuid",
            "/interfaces/not-a-uuid",
            "/hosts/x/interfaces",
        ] {
            let reply = api.get(path).await;
            reply.assert_problem(400, "sys.invalid_request");
            assert_eq!(reply.body["params"]["part"], "path", "{path}");
        }
    }

    #[tokio::test]
    async fn a_body_or_identifier_that_does_not_fit_is_a_400_problem() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let interface = make_interface(&api, &host, "eth0").await;
        let host_path = format!("/hosts/{host}");
        let interface_path = format!("/interfaces/{interface}");
        let posts = [
            (
                "/hosts".to_owned(),
                json!({ "name": label("host", 2), "mode": "asleep" }),
            ),
            ("/hosts".to_owned(), json!({ "name": "not a host name" })),
            (
                "/hosts".to_owned(),
                json!({ "name": label("host", 2), "lock": "yes" }),
            ),
            (
                format!("{host_path}/interfaces"),
                json!({ "name": "eth1", "mac": "00-00-5E-00-53" }),
            ),
            (
                format!("{host_path}/interfaces"),
                json!({ "name": "eth1", "host": "x" }),
            ),
            (format!("{host_path}/interfaces"), json!({ "mac": mac(1) })),
        ];
        for (path, body) in posts {
            let reply = api.post(&path, &body).await;
            reply.assert_problem(400, "sys.invalid_request");
        }
        let patches = [
            (host_path.clone(), json!({ "mode": "asleep" })),
            (host_path.clone(), json!({ "name": 5 })),
            (interface_path.clone(), json!({ "mac": "nonsense" })),
            (interface_path.clone(), json!({ "duid": "0" })),
        ];
        for (path, body) in patches {
            let reply = api.patch(&path, None, &body).await;
            reply.assert_problem(400, "sys.invalid_request");
        }
        let plain = api
            .send_text("POST", "/hosts", "text/plain", "name=x")
            .await;
        plain.assert_problem(415, "sys.invalid_request");
        for path in [
            "/hosts/not-a-uuid".to_owned(),
            "/interfaces/not-a-uuid".to_owned(),
        ] {
            let reply = api.patch(&path, None, &json!({})).await;
            reply.assert_problem(400, "sys.invalid_request");
            api.delete(&path, None)
                .await
                .assert_problem(400, "sys.invalid_request");
        }
        api.post("/hosts/not-a-uuid/interfaces", &json!({ "name": "eth1" }))
            .await
            .assert_problem(400, "sys.invalid_request");
        assert_eq!(api.get("/hosts").await.items().len(), 1);
        let interfaces = api.get(&format!("{host_path}/interfaces")).await;
        assert_eq!(interfaces.ids(), [interface]);
    }

    #[tokio::test]
    async fn an_unknown_member_in_the_body_is_a_400_problem() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let interface = make_interface(&api, &host, "eth0").await;
        let other = make_host(&api, 2).await;
        let host_path = format!("/hosts/{host}");
        let interface_path = format!("/interfaces/{interface}");
        let posts = [
            (
                "/hosts".to_owned(),
                json!({ "name": label("host", 3), "colour": "red" }),
            ),
            (
                format!("{host_path}/interfaces"),
                json!({ "name": "eth1", "colour": "red" }),
            ),
            (
                "/hosts".to_owned(),
                json!({ "name": label("host", 3), "interfaces": [{ "name": "eth0", "colour": "red" }] }),
            ),
        ];
        for (path, body) in posts {
            let reply = api.post(&path, &body).await;
            reply.assert_problem(400, "sys.invalid_request");
            assert_eq!(reply.body["params"]["part"], "body");
        }
        // The tenant of a host and the host of an interface cannot change.
        let patches = [
            (host_path.clone(), json!({ "tenant": unknown_id() })),
            (interface_path.clone(), json!({ "host": other })),
        ];
        for (path, body) in patches {
            api.patch(&path, None, &body)
                .await
                .assert_problem(400, "sys.invalid_request");
        }
        assert_eq!(api.get("/hosts").await.items().len(), 2);
        let interfaces = api.get(&format!("{host_path}/interfaces")).await;
        assert_eq!(interfaces.ids(), [interface]);
    }

    // Hosts: lists.

    #[tokio::test]
    async fn hosts_page_with_limit_and_cursor() {
        let api = Api::new();
        let mut created = Vec::new();
        for n in 1..=5 {
            created.push(make_host(&api, n).await);
        }
        let pages = api.pages("/hosts", 2).await;
        let sizes: Vec<usize> = pages.iter().map(|page| page.items().len()).collect();
        assert_eq!(sizes, [2, 2, 1]);
        assert_eq!(pages[2].body["next_cursor"], Value::Null);
        let seen: Vec<String> = pages.iter().flat_map(Reply::ids).collect();
        assert_eq!(seen, created);
        let empty = Api::new().get("/hosts").await;
        assert_eq!(empty.body["items"], json!([]));
        assert_eq!(empty.body["next_cursor"], Value::Null);
    }

    #[tokio::test]
    async fn hosts_filter_by_tenant_site_mode_and_lock() {
        let api = Api::new();
        let tenant = api
            .create("/tenants", &json!({ "name": label("tenant", 1) }))
            .await;
        let site = api
            .create("/sites", &json!({ "name": label("site", 1) }))
            .await;
        let plain = make_host(&api, 1).await;
        let reserved = api
            .create(
                "/hosts",
                &json!({ "name": label("host", 2), "mode": "reserved", "tenant": tenant["id"] }),
            )
            .await;
        let locked = api
            .create(
                "/hosts",
                &json!({ "name": label("host", 3), "lock": true, "site": site["id"] }),
            )
            .await;
        let (reserved, locked) = (id_of(&reserved), id_of(&locked));
        let (tenant, site) = (id_of(&tenant), id_of(&site));
        let expected = [
            (format!("tenant={tenant}"), vec![reserved.clone()]),
            (format!("site={site}"), vec![locked.clone()]),
            ("mode=reserved".to_owned(), vec![reserved.clone()]),
            (
                "mode=static".to_owned(),
                vec![plain.clone(), locked.clone()],
            ),
            ("locked=true".to_owned(), vec![locked.clone()]),
            ("locked=false".to_owned(), vec![plain, reserved]),
            ("locked=true&mode=static".to_owned(), vec![locked]),
        ];
        for (query, ids) in expected {
            let found = ids_at(&api, &format!("/hosts?{query}")).await;
            assert_eq!(found, ids, "{query}");
        }
        for path in [
            "/hosts?mode=odd",
            "/hosts?locked=perhaps",
            "/hosts?tenant=x",
            "/hosts?status=active",
        ] {
            api.get(path).await.assert_problem(400, "sys.invalid_query");
        }
    }

    #[tokio::test]
    async fn hosts_filter_by_tag_and_text_and_sort() {
        let api = Api::new();
        let first = api
            .create(
                "/hosts",
                &json!({ "name": label("host", 1), "tags": ["red"] }),
            )
            .await;
        let second = api
            .create(
                "/hosts",
                &json!({
                    "name": label("host", 2),
                    "tags": ["blue", "red"],
                    "description": "Printer",
                }),
            )
            .await;
        let third = make_host(&api, 3).await;
        let (first, second) = (id_of(&first), id_of(&second));
        for (query, expected) in [
            ("tag=red", vec![first.clone(), second.clone()]),
            ("tag=red,blue", vec![second.clone()]),
            ("tag=red&tag=blue", vec![second.clone()]),
            ("q=PRINTER", vec![second.clone()]),
            ("q=-03.EXAMPLE", vec![third.clone()]),
            ("sort=-name", vec![third, second, first]),
        ] {
            assert_eq!(
                ids_at(&api, &format!("/hosts?{query}")).await,
                expected,
                "{query}"
            );
        }
        api.get("/hosts?sort=color")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn deleted_hosts_show_with_deleted_only_or_include() {
        let api = Api::new();
        let mut ids = Vec::new();
        for n in 1..=3 {
            ids.push(make_host(&api, n).await);
        }
        api.delete(&format!("/hosts/{}", ids[1]), None)
            .await
            .assert_write(200);
        assert_eq!(
            ids_at(&api, "/hosts").await,
            [ids[0].clone(), ids[2].clone()]
        );
        assert_eq!(ids_at(&api, "/hosts?deleted=only").await, [ids[1].clone()]);
        assert_eq!(ids_at(&api, "/hosts?deleted=include").await, ids);
        api.get("/hosts?deleted=maybe")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn parameters_that_an_endpoint_does_not_take_are_refused() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let interface = make_interface(&api, &host, "eth0").await;
        let body = json!({ "description": "x" });
        let name = json!({ "name": "x" });
        let replies = [
            (api.get("/hosts?bogus=1").await, "bogus"),
            (api.get(&format!("/hosts/{host}?bogus=1")).await, "bogus"),
            (
                api.get(&format!("/hosts/{host}?deleted=only")).await,
                "deleted",
            ),
            (
                api.post("/hosts?cascade=true", &host_body(2)).await,
                "cascade",
            ),
            (
                api.patch(&format!("/hosts/{host}?cascade=true"), None, &body)
                    .await,
                "cascade",
            ),
            (
                api.delete(&format!("/hosts/{host}?bogus=1"), None).await,
                "bogus",
            ),
            (
                api.get(&format!("/hosts/{host}/interfaces?mode=static"))
                    .await,
                "mode",
            ),
            (
                api.get(&format!("/hosts/{host}/interfaces?host={host}"))
                    .await,
                "host",
            ),
            (
                api.get(&format!("/interfaces/{interface}?bogus=1")).await,
                "bogus",
            ),
            (
                api.post(&format!("/hosts/{host}/interfaces?cascade=true"), &name)
                    .await,
                "cascade",
            ),
            (
                api.patch(
                    &format!("/interfaces/{interface}?cascade=true"),
                    None,
                    &body,
                )
                .await,
                "cascade",
            ),
            (
                api.delete(&format!("/interfaces/{interface}?bogus=1"), None)
                    .await,
                "bogus",
            ),
        ];
        for (reply, parameter) in replies {
            reply.assert_problem(400, "sys.invalid_query");
            assert_eq!(reply.body["params"]["parameter"], parameter);
        }
        // The cascade flag must be a boolean where it is taken.
        api.delete(&format!("/hosts/{host}?cascade=maybe"), None)
            .await
            .assert_problem(400, "sys.invalid_query");
        api.delete(&format!("/interfaces/{interface}?cascade=maybe"), None)
            .await
            .assert_problem(400, "sys.invalid_query");
        assert_eq!(api.get("/hosts").await.items().len(), 1);
    }

    // Hosts: updates.

    #[tokio::test]
    async fn patch_changes_the_host_and_moves_the_etag() {
        let api = Api::new();
        let site = api
            .create("/sites", &json!({ "name": label("site", 1) }))
            .await;
        let created = api.post("/hosts", &host_body(1)).await;
        let path = format!("/hosts/{}", created.item_id());
        let changes = json!({
            "name": "Renamed.Example.Test",
            "mode": "dynamic",
            "lock": true,
            "site": site["id"],
            "tags": ["moved"],
        });
        let reply = api.patch(&path, created.etag.as_deref(), &changes).await;
        reply.assert_write(200);
        let item = reply.item();
        assert_eq!(item["name"], "renamed.example.test");
        assert_eq!(item["mode"], "dynamic");
        assert_eq!(item["lock"], true);
        assert_eq!(item["site"], site["id"]);
        assert!(reply.revision() > created.revision());
        assert_eq!(api.get(&path).await.etag, reply.etag);
        let cleared = api
            .patch(&path, None, &json!({ "site": null, "lock": false }))
            .await;
        assert_eq!(cleared.item()["site"], Value::Null);
        assert_eq!(cleared.item()["lock"], false);
        assert_eq!(cleared.item()["mode"], "dynamic");
        assert_eq!(cleared.item()["name"], "renamed.example.test");
    }

    #[tokio::test]
    async fn patch_honors_if_match() {
        let api = Api::new();
        let created = api.post("/hosts", &host_body(1)).await;
        let path = format!("/hosts/{}", created.item_id());
        let first = api
            .patch(
                &path,
                created.etag.as_deref(),
                &json!({ "mode": "reserved" }),
            )
            .await;
        first.assert_write(200);
        let stale = api
            .patch(&path, created.etag.as_deref(), &json!({ "mode": "static" }))
            .await;
        stale.assert_problem(412, "ipam.revision_mismatch");
        assert_eq!(stale.body["params"]["kind"], "host");
        assert_eq!(
            stale.body["params"]["expected"],
            created.revision().to_string()
        );
        assert_eq!(stale.body["params"]["actual"], first.revision().to_string());
        api.delete(&path, created.etag.as_deref())
            .await
            .assert_problem(412, "ipam.revision_mismatch");
        for value in ["abc", "\"x\"", "-3", ""] {
            let reply = api.patch(&path, Some(value), &json!({})).await;
            reply.assert_problem(400, "ipam.validation");
            assert_eq!(reply.body["params"]["field"], "If-Match");
            api.delete(&path, Some(value))
                .await
                .assert_problem(400, "ipam.validation");
        }
        let got = api.get(&path).await;
        assert_eq!(got.etag, first.etag);
        assert_eq!(got.body["mode"], "reserved");
    }

    #[tokio::test]
    async fn host_dry_runs_write_nothing() {
        let api = Api::new();
        let create = api
            .post("/hosts?dry_run=true", &host_with_interfaces(1))
            .await;
        create.assert_dry_run();
        let lines = create.summary_lines();
        assert!(lines.contains(&"1 host created".to_owned()), "{lines:?}");
        assert!(
            lines.contains(&"2 interfaces created".to_owned()),
            "{lines:?}"
        );
        assert_eq!(create.item()["name"], label("host", 1));
        api.get(&format!("/hosts/{}", create.item_id()))
            .await
            .assert_problem(404, "ipam.not_found");
        api.get("/hosts").await.assert_no_items();

        let created = api.post("/hosts", &host_body(1)).await;
        let path = format!("/hosts/{}", created.item_id());
        let update = api
            .patch(
                &format!("{path}?dry_run=true"),
                created.etag.as_deref(),
                &json!({ "mode": "dynamic" }),
            )
            .await;
        update.assert_dry_run();
        assert_eq!(update.item()["mode"], "dynamic");
        let delete = api.delete(&format!("{path}?dry_run=true"), None).await;
        delete.assert_dry_run();
        assert!(delete.item()["meta"]["deleted"].is_object());
        let got = api.get(&path).await;
        assert_eq!(got.etag, created.etag);
        assert_eq!(got.body["mode"], "static");
        assert_eq!(got.body["meta"]["deleted"], Value::Null);
    }

    #[tokio::test]
    async fn a_reserved_host_without_a_mac_address_is_created_with_a_warning() {
        let api = Api::new();
        let body = json!({ "name": label("host", 1), "mode": "reserved" });
        let reply = api.post("/hosts", &body).await;
        reply.assert_write(201);
        let warnings = reply.body["warnings"].as_array().expect("warnings");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert_eq!(warnings[0]["code"], "ipam.host.reservation_identifier");
        assert_eq!(warnings[0]["requires_ack"], false);
        // With a MAC address the warning is gone.
        let with_mac = json!({
            "name": label("host", 2),
            "mode": "reserved",
            "interfaces": [{ "name": "eth0", "mac": mac(2) }],
        });
        let reply = api.post("/hosts", &with_mac).await;
        reply.assert_write(201);
        assert_eq!(reply.body["warnings"], json!([]));
    }

    #[tokio::test]
    async fn host_names_are_unique_within_a_tenant() {
        let api = Api::new();
        make_host(&api, 1).await;
        let duplicate = api
            .post(
                "/hosts",
                &json!({ "name": label("host", 1).to_uppercase() }),
            )
            .await;
        duplicate.assert_problem(409, "ipam.name_taken");
        assert_eq!(duplicate.body["params"]["kind"], "host");
        assert_eq!(duplicate.body["errors"][0]["field"], "name");
        let other = make_host(&api, 2).await;
        let rename = api
            .patch(
                &format!("/hosts/{other}"),
                None,
                &json!({ "name": label("host", 1) }),
            )
            .await;
        rename.assert_problem(409, "ipam.name_taken");
        // Another tenant has its own names.
        let tenant = api
            .create("/tenants", &json!({ "name": label("tenant", 1) }))
            .await;
        let body = json!({ "name": label("host", 1), "tenant": tenant["id"] });
        api.create("/hosts", &body).await;
        assert_eq!(api.get("/hosts").await.items().len(), 3);
    }

    #[tokio::test]
    async fn host_references_and_inline_interfaces_are_checked() {
        let api = Api::new();
        let missing = unknown_id();
        for (body, field) in [
            (
                json!({ "name": label("host", 1), "tenant": missing }),
                "tenant",
            ),
            (json!({ "name": label("host", 1), "site": missing }), "site"),
        ] {
            let reply = api.post("/hosts", &body).await;
            reply.assert_problem(409, "ipam.reference_missing");
            assert_eq!(reply.body["params"]["field"], field);
        }
        let host = make_host(&api, 1).await;
        api.patch(&format!("/hosts/{host}"), None, &json!({ "site": missing }))
            .await
            .assert_problem(409, "ipam.reference_missing");
        let clash = json!({
            "name": label("host", 2),
            "interfaces": [{ "name": "eth0" }, { "name": "ETH0" }],
        });
        api.post("/hosts", &clash)
            .await
            .assert_problem(409, "ipam.name_taken");
        let foreign = json!({
            "name": label("host", 3),
            "interfaces": [{ "name": "eth0", "host": host }],
        });
        api.post("/hosts", &foreign)
            .await
            .assert_problem(400, "ipam.validation");
        assert_eq!(api.get("/hosts").await.items().len(), 1);
    }

    #[tokio::test]
    async fn a_repeated_idempotency_key_returns_the_first_host_and_interface() {
        let api = Api::new();
        let headers = [("idempotency-key", "host-create-1")];
        let first = api
            .post_with("/hosts", &headers, &host_with_interfaces(1))
            .await;
        first.assert_write(201);
        let replay = api
            .post_with("/hosts", &headers, &host_with_interfaces(1))
            .await;
        replay.assert_json(200);
        assert_eq!(replay.body["replayed"], true);
        assert_eq!(replay.body["job_id"], Value::Null);
        assert_eq!(replay.item(), first.item());
        assert_eq!(replay.etag, first.etag);
        let other = api.post_with("/hosts", &headers, &host_body(2)).await;
        other.assert_problem(422, "ipam.idempotency_mismatch");
        assert_eq!(api.get("/hosts").await.items().len(), 1);

        let path = format!("/hosts/{}/interfaces", first.item_id());
        let interface_headers = [("idempotency-key", "interface-create-1")];
        let body = json!({ "name": "eth2" });
        let one = api.post_with(&path, &interface_headers, &body).await;
        one.assert_write(201);
        let again = api.post_with(&path, &interface_headers, &body).await;
        assert_eq!(again.body["replayed"], true);
        assert_eq!(again.item(), one.item());
        api.post_with(&path, &interface_headers, &json!({ "name": "eth3" }))
            .await
            .assert_problem(422, "ipam.idempotency_mismatch");
        assert_eq!(api.get(&path).await.items().len(), 3);
    }

    // Hosts: deletes.

    #[tokio::test]
    async fn delete_soft_deletes_the_host_and_its_interfaces() {
        let api = Api::new();
        let created = api.post("/hosts", &host_with_interfaces(1)).await;
        let host = created.item_id();
        let reply = api
            .delete(&format!("/hosts/{host}"), created.etag.as_deref())
            .await;
        reply.assert_write(200);
        assert!(reply.item()["meta"]["deleted"]["at"].is_string());
        let got = api.get(&format!("/hosts/{host}")).await;
        assert_eq!(got.etag, reply.etag);

        api.get(&format!("/hosts/{host}/interfaces"))
            .await
            .assert_no_items();
        let deleted = api
            .get(&format!("/hosts/{host}/interfaces?deleted=only"))
            .await;
        assert_eq!(deleted.items().len(), 2);
        api.delete(&format!("/hosts/{host}"), None)
            .await
            .assert_problem(409, "ipam.object_deleted");
        // The name is free again.
        api.create("/hosts", &host_body(1)).await;
    }

    #[tokio::test]
    async fn a_host_with_addresses_needs_cascade_to_be_deleted() {
        let api = Api::new();
        api.make_prefix(None, "192.0.2.0/24").await;
        let host = api.create("/hosts", &host_with_interfaces(1)).await;
        let host_id = id_of(&host);
        let interfaces = api.get(&format!("/hosts/{host_id}/interfaces")).await;
        let first = assign(&api, &interfaces.ids()[0], 10).await;
        let second = assign(&api, &interfaces.ids()[1], 11).await;
        let path = format!("/hosts/{host_id}");
        let blocked = api.delete(&path, None).await;
        blocked.assert_problem(409, "ipam.in_use");
        assert_eq!(blocked.body["params"]["by"], "addresses");
        assert_eq!(blocked.body["params"]["count"], "2");
        assert_eq!(blocked.body["params"]["kind"], "host");

        let preview = api
            .delete(&format!("{path}?cascade=true&dry_run=true"), None)
            .await;
        preview.assert_dry_run();
        let lines = preview.summary_lines();
        for line in [
            "2 addresses deleted",
            "2 interfaces deleted",
            "1 host deleted",
        ] {
            assert!(lines.contains(&line.to_owned()), "{line}: {lines:?}");
        }
        assert_eq!(api.get(&path).await.body["meta"]["deleted"], Value::Null);

        let reply = api.delete(&format!("{path}?cascade=true"), None).await;
        reply.assert_write(200);
        assert!(reply.item()["meta"]["deleted"].is_object());
        for address in [first, second] {
            let got = api.get(&format!("/addresses/{address}")).await;
            assert!(got.body["meta"]["deleted"].is_object(), "{}", got.body);
        }
        api.get("/addresses").await.assert_no_items();
        assert_eq!(api.get("/addresses?deleted=only").await.items().len(), 2);
    }

    // Interfaces.

    #[tokio::test]
    async fn an_interface_is_added_under_its_host() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let path = format!("/hosts/{host}/interfaces");
        let body = json!({
            "name": "eth0",
            "mac": mac(1),
            "duid": "00030001005e00530001",
            "client_id": "01005e00530001",
            "tags": ["uplink"],
            "description": "Uplink",
        });
        let reply = api.post(&path, &body).await;
        reply.assert_write(201);
        let item = reply.item();
        assert_eq!(item["host"], host);
        assert_eq!(item["name"], "eth0");
        assert_eq!(item["mac"], "00:00:5e:00:53:01");
        assert_eq!(item["duid"], "00030001005e00530001");
        assert_eq!(item["client_id"], "01005e00530001");
        assert_eq!(item["meta"]["tags"], json!(["uplink"]));
        let got = api.get(&format!("/interfaces/{}", reply.item_id())).await;
        got.assert_json(200);
        assert_eq!(&got.body, item);
        assert_eq!(got.etag, reply.etag);
        // The host in the body may repeat the host of the path.
        let same = json!({ "name": "eth1", "host": host });
        api.post(&path, &same).await.assert_write(201);
    }

    #[tokio::test]
    async fn a_body_that_names_another_host_is_refused() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let other = make_host(&api, 2).await;
        let body = json!({ "name": "eth0", "host": other });
        let reply = api.post(&format!("/hosts/{host}/interfaces"), &body).await;
        reply.assert_problem(400, "ipam.validation");
        assert_eq!(reply.body["params"]["field"], "host");
        assert_eq!(reply.body["errors"][0]["field"], "host");
        for id in [&host, &other] {
            let interfaces = api.get(&format!("/hosts/{id}/interfaces")).await;
            interfaces.assert_no_items();
        }
    }

    #[tokio::test]
    async fn an_interface_for_a_missing_or_deleted_host_is_a_409() {
        let api = Api::new();
        let missing = unknown_id();
        let body = json!({ "name": "eth0" });
        let reply = api
            .post(&format!("/hosts/{missing}/interfaces"), &body)
            .await;
        reply.assert_problem(409, "ipam.reference_missing");
        assert_eq!(reply.body["params"]["field"], "host");
        assert_eq!(reply.body["params"]["kind"], "host");
        assert_eq!(reply.body["params"]["id"], missing);
        let host = make_host(&api, 1).await;
        api.delete(&format!("/hosts/{host}"), None)
            .await
            .assert_write(200);
        api.post(&format!("/hosts/{host}/interfaces"), &body)
            .await
            .assert_problem(409, "ipam.reference_missing");
        assert_eq!(api.get("/hosts?deleted=include").await.items().len(), 1);
    }

    #[tokio::test]
    async fn interface_names_are_unique_per_host() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let other = make_host(&api, 2).await;
        make_interface(&api, &host, "eth0").await;
        let duplicate = api
            .post(
                &format!("/hosts/{host}/interfaces"),
                &json!({ "name": "ETH0" }),
            )
            .await;
        duplicate.assert_problem(409, "ipam.name_taken");
        assert_eq!(duplicate.body["params"]["kind"], "interface");
        make_interface(&api, &other, "eth0").await;
        let second = make_interface(&api, &host, "eth1").await;
        let rename = api
            .patch(
                &format!("/interfaces/{second}"),
                None,
                &json!({ "name": "eth0" }),
            )
            .await;
        rename.assert_problem(409, "ipam.name_taken");
    }

    #[tokio::test]
    async fn a_mac_address_on_two_interfaces_is_a_warning() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let path = format!("/hosts/{host}/interfaces");
        let first = api
            .post(&path, &json!({ "name": "eth0", "mac": mac(1) }))
            .await;
        assert_eq!(first.body["warnings"], json!([]));
        let second = api
            .post(&path, &json!({ "name": "eth1", "mac": mac(1) }))
            .await;
        second.assert_write(201);
        let warnings = second.body["warnings"].as_array().expect("warnings");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0]["code"], "ipam.interface.duplicate_mac");
        assert_eq!(warnings[0]["object"]["id"], second.item_id());
    }

    #[tokio::test]
    async fn an_interface_dry_run_writes_nothing() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let path = format!("/hosts/{host}/interfaces");
        let reply = api
            .post(&format!("{path}?dry_run=true"), &json!({ "name": "eth0" }))
            .await;
        reply.assert_dry_run();
        assert_eq!(reply.summary_lines(), ["1 interface created"]);
        assert_eq!(reply.item()["host"], host);
        api.get(&format!("/interfaces/{}", reply.item_id()))
            .await
            .assert_problem(404, "ipam.not_found");
        api.get(&path).await.assert_no_items();
    }

    #[tokio::test]
    async fn patch_changes_an_interface_and_honors_if_match() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let created = api
            .post(
                &format!("/hosts/{host}/interfaces"),
                &json!({ "name": "eth0", "mac": mac(1) }),
            )
            .await;
        let path = format!("/interfaces/{}", created.item_id());
        let changes = json!({
            "name": "uplink0",
            "mac": mac(2),
            "duid": "00030001005e00530002",
            "client_id": "01005e00530002",
            "description": "Moved",
        });
        let reply = api.patch(&path, created.etag.as_deref(), &changes).await;
        reply.assert_write(200);
        let item = reply.item();
        assert_eq!(item["name"], "uplink0");
        assert_eq!(item["mac"], "00:00:5e:00:53:02");
        assert_eq!(item["duid"], "00030001005e00530002");
        assert_eq!(item["client_id"], "01005e00530002");
        assert_eq!(item["host"], host);
        assert_eq!(api.get(&path).await.etag, reply.etag);
        let clear = json!({ "mac": null, "duid": null, "client_id": null });
        let cleared = api.patch(&path, None, &clear).await;
        assert_eq!(cleared.item()["mac"], Value::Null);
        assert_eq!(cleared.item()["duid"], Value::Null);
        assert_eq!(cleared.item()["client_id"], Value::Null);
        assert_eq!(cleared.item()["name"], "uplink0");
        // Stale and malformed If-Match.
        let stale = api
            .patch(&path, created.etag.as_deref(), &json!({ "name": "x" }))
            .await;
        stale.assert_problem(412, "ipam.revision_mismatch");
        assert_eq!(stale.body["params"]["kind"], "interface");
        api.patch(&path, Some("nope"), &json!({}))
            .await
            .assert_problem(400, "ipam.validation");
        api.delete(&path, Some("nope"))
            .await
            .assert_problem(400, "ipam.validation");
        // A dry run changes nothing.
        let dry = api
            .patch(
                &format!("{path}?dry_run=true"),
                None,
                &json!({ "name": "planned0" }),
            )
            .await;
        dry.assert_dry_run();
        assert_eq!(dry.item()["name"], "planned0");
        assert_eq!(api.get(&path).await.body["name"], "uplink0");
    }

    #[tokio::test]
    async fn an_interface_with_addresses_needs_cascade_to_be_deleted() {
        let api = Api::new();
        api.make_prefix(None, "192.0.2.0/24").await;
        let host = make_host(&api, 1).await;
        let interface = make_interface(&api, &host, "eth0").await;
        let address = assign(&api, &interface, 20).await;
        let path = format!("/interfaces/{interface}");
        let blocked = api.delete(&path, None).await;
        blocked.assert_problem(409, "ipam.in_use");
        assert_eq!(blocked.body["params"]["by"], "addresses");
        assert_eq!(blocked.body["params"]["kind"], "interface");
        let dry = api
            .delete(&format!("{path}?cascade=true&dry_run=true"), None)
            .await;
        dry.assert_dry_run();
        assert!(
            dry.summary_lines()
                .contains(&"1 address deleted".to_owned())
        );
        let reply = api.delete(&format!("{path}?cascade=true"), None).await;
        reply.assert_write(200);
        assert!(reply.item()["meta"]["deleted"].is_object());
        let address = api.get(&format!("/addresses/{address}")).await;
        assert!(address.body["meta"]["deleted"].is_object());
        // The host stays.
        let host = api.get(&format!("/hosts/{host}")).await;
        assert_eq!(host.body["meta"]["deleted"], Value::Null);
        api.delete(&path, None)
            .await
            .assert_problem(409, "ipam.object_deleted");
    }

    #[tokio::test]
    async fn an_interface_without_addresses_is_deleted_softly() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let interface = make_interface(&api, &host, "eth0").await;
        let path = format!("/interfaces/{interface}");
        let reply = api.delete(&path, None).await;
        reply.assert_write(200);
        assert!(reply.item()["meta"]["deleted"]["at"].is_string());
        assert_eq!(api.get(&path).await.etag, reply.etag);
        api.patch(&path, None, &json!({ "name": "x" }))
            .await
            .assert_problem(409, "ipam.object_deleted");
        // The name can be used again.
        make_interface(&api, &host, "eth0").await;
    }

    // The interfaces of a host.

    #[tokio::test]
    async fn the_interfaces_of_a_host_page_with_limit_and_cursor() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let other = make_host(&api, 2).await;
        let mut created = Vec::new();
        for n in 0..5 {
            created.push(make_interface(&api, &host, &format!("eth{n}")).await);
        }
        make_interface(&api, &other, "eth0").await;
        let path = format!("/hosts/{host}/interfaces");
        let pages = api.pages(&path, 2).await;
        let sizes: Vec<usize> = pages.iter().map(|page| page.items().len()).collect();
        assert_eq!(sizes, [2, 2, 1]);
        assert_eq!(pages[2].body["next_cursor"], Value::Null);
        let seen: Vec<String> = pages.iter().flat_map(Reply::ids).collect();
        assert_eq!(seen, created);
        for page in &pages {
            assert!(page.texts("host").iter().all(|item| *item == host));
        }
        // The cursor of one host's list is no cursor of another's.
        let cursor = pages[0].body["next_cursor"].as_str().expect("cursor");
        api.get(&format!(
            "/hosts/{other}/interfaces?limit=2&cursor={cursor}"
        ))
        .await
        .assert_problem(400, "sys.invalid_cursor");
        let others = api.get(&format!("/hosts/{other}/interfaces")).await;
        assert_eq!(others.items().len(), 1);
    }

    #[tokio::test]
    async fn the_interfaces_of_a_host_filter_and_sort() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let path = format!("/hosts/{host}/interfaces");
        let red = api
            .create(&path, &json!({ "name": "eth0", "tags": ["red"] }))
            .await;
        let both_body = json!({ "name": "eth1", "tags": ["blue", "red"], "mac": mac(7) });
        let both = api.create(&path, &both_body).await;
        let plain = make_interface(&api, &host, "eth2").await;
        let (red, both) = (id_of(&red), id_of(&both));
        for (query, expected) in [
            ("tag=red", vec![red.clone(), both.clone()]),
            ("tag=red,blue", vec![both.clone()]),
            ("q=00:00:5E:00:53:07", vec![both.clone()]),
            ("q=ETH2", vec![plain.clone()]),
            ("sort=-name", vec![plain.clone(), both.clone(), red.clone()]),
        ] {
            assert_eq!(
                ids_at(&api, &format!("{path}?{query}")).await,
                expected,
                "{query}"
            );
        }
        api.delete(&format!("/interfaces/{both}"), None)
            .await
            .assert_write(200);
        assert_eq!(ids_at(&api, &path).await, [red, plain]);
        assert_eq!(ids_at(&api, &format!("{path}?deleted=only")).await, [both]);
        assert_eq!(
            ids_at(&api, &format!("{path}?deleted=include")).await.len(),
            3
        );
        api.get(&format!("{path}?sort=color"))
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get(&format!("{path}?at_least=1"))
            .await
            .assert_json(200);
    }

    // Availability and authorization.

    #[tokio::test]
    async fn without_the_ipam_service_every_endpoint_is_a_503() {
        let api = Api::unavailable();
        let id = unknown_id();
        let body = json!({ "name": "eth0" });
        let replies = [
            api.get("/hosts").await,
            api.post("/hosts", &host_body(1)).await,
            api.get(&format!("/hosts/{id}")).await,
            api.patch(&format!("/hosts/{id}"), None, &json!({})).await,
            api.delete(&format!("/hosts/{id}"), None).await,
            api.get(&format!("/hosts/{id}/interfaces")).await,
            api.post(&format!("/hosts/{id}/interfaces"), &body).await,
            api.get(&format!("/interfaces/{id}")).await,
            api.patch(&format!("/interfaces/{id}"), None, &json!({}))
                .await,
            api.delete(&format!("/interfaces/{id}"), None).await,
        ];
        for reply in replies {
            reply.assert_problem(503, "ipam.unavailable");
        }
    }

    #[tokio::test]
    async fn a_principal_that_may_do_nothing_gets_403_on_writes_and_empty_lists() {
        let api = Api::new();
        let host = api.post("/hosts", &host_with_interfaces(1)).await;
        let host_id = host.item_id();
        let interfaces = api.get(&format!("/hosts/{host_id}/interfaces")).await;
        let interface = interfaces.ids()[0].clone();
        let denied = api.sibling(AppState {
            authorizer: Some(Policy::new(false, false)),
            ..AppState::default()
        });
        let list = denied.get("/hosts").await;
        list.assert_json(200);
        assert_eq!(list.body["items"], json!([]));
        assert_eq!(list.body["next_cursor"], Value::Null);
        let body = json!({ "name": "eth9" });
        let host_path = format!("/hosts/{host_id}");
        let interface_path = format!("/interfaces/{interface}");
        let replies = [
            (denied.get(&host_path).await, "read"),
            (denied.get(&format!("{host_path}/interfaces")).await, "read"),
            (denied.get(&interface_path).await, "read"),
            (denied.post("/hosts", &host_body(2)).await, "create"),
            (
                denied.post(&format!("{host_path}/interfaces"), &body).await,
                "create",
            ),
            (
                denied
                    .patch(&host_path, None, &json!({ "mode": "dynamic" }))
                    .await,
                "update",
            ),
            (
                denied
                    .patch(&interface_path, None, &json!({ "name": "x" }))
                    .await,
                "update",
            ),
            (
                denied
                    .delete(&format!("{host_path}?cascade=true"), None)
                    .await,
                "delete",
            ),
            (denied.delete(&interface_path, None).await, "delete"),
        ];
        for (reply, action) in replies {
            reply.assert_problem(403, "auth.forbidden");
            assert_eq!(reply.body["params"]["action"], action);
        }
        let got = api.get(&host_path).await;
        assert_eq!(got.etag, host.etag);
        let still = api.get(&format!("{host_path}/interfaces")).await;
        assert_eq!(still.items().len(), 2);
    }

    #[tokio::test]
    async fn a_read_only_principal_reads_hosts_and_interfaces_and_cannot_write() {
        let api = Api::new();
        let host = api.post("/hosts", &host_with_interfaces(1)).await;
        let reader = api.sibling(AppState {
            authorizer: Some(Policy::new(true, false)),
            ..AppState::default()
        });
        let path = format!("/hosts/{}/interfaces", host.item_id());
        assert_eq!(reader.get(&path).await.items().len(), 2);
        assert_eq!(reader.get("/hosts").await.items().len(), 1);
        reader
            .post(&path, &json!({ "name": "eth9" }))
            .await
            .assert_problem(403, "auth.forbidden");
    }

    #[tokio::test]
    async fn each_endpoint_asks_for_the_action_on_the_object() {
        let policy = Policy::new(true, true);
        let api = Api::with_authorizer(policy.clone());
        let host = api.post("/hosts", &host_body(1)).await;
        let host_id: HostId = host.item_id().parse().expect("host id");
        let host_ref = ObjectRef::from(host_id);
        api.get(&format!("/hosts/{host_id}/interfaces"))
            .await
            .assert_json(200);
        let interface = api
            .post(
                &format!("/hosts/{host_id}/interfaces"),
                &json!({ "name": "eth0" }),
            )
            .await;
        interface.assert_write(201);
        let interface_id: InterfaceId = interface.item_id().parse().expect("interface id");
        let interface_ref = ObjectRef::from(interface_id);
        let path = format!("/interfaces/{interface_id}");
        api.get(&path).await.assert_json(200);
        api.patch(&path, None, &json!({ "name": "eth1" }))
            .await
            .assert_write(200);
        api.delete(&path, None).await.assert_write(200);
        api.delete(&format!("/hosts/{host_id}"), None)
            .await
            .assert_write(200);
        assert_eq!(
            policy.asked(),
            [
                (
                    Action::Create,
                    crate::routes::common::new_of(ObjectKind::Host)
                ),
                (Action::Read, host_ref),
                (
                    Action::Create,
                    crate::routes::common::new_of(ObjectKind::Interface)
                ),
                (Action::Read, interface_ref),
                (Action::Update, interface_ref),
                (Action::Delete, interface_ref),
                (Action::Delete, host_ref),
            ]
        );
    }

    // Locks.

    #[tokio::test]
    async fn automation_cannot_change_a_locked_host_or_its_interfaces() {
        let api = Api::new();
        let body = json!({
            "name": label("host", 1),
            "lock": true,
            "interfaces": [{ "name": "eth0" }],
        });
        let host = api.post("/hosts", &body).await.item_id();
        let interfaces = api.get(&format!("/hosts/{host}/interfaces")).await;
        let interface = interfaces.ids()[0].clone();
        let robot = api.as_automation();
        let mode = json!({ "mode": "dynamic" });
        let replies = [
            robot.patch(&format!("/hosts/{host}"), None, &mode).await,
            robot.delete(&format!("/hosts/{host}"), None).await,
            robot
                .post(
                    &format!("/hosts/{host}/interfaces"),
                    &json!({ "name": "eth1" }),
                )
                .await,
            robot
                .patch(
                    &format!("/interfaces/{interface}"),
                    None,
                    &json!({ "name": "x" }),
                )
                .await,
            robot
                .delete(&format!("/interfaces/{interface}"), None)
                .await,
        ];
        for reply in replies {
            reply.assert_problem(423, "ipam.host.locked");
            assert_eq!(reply.body["params"]["host"], label("host", 1));
        }
        // Reads are fine, and people may change the host.
        robot.get(&format!("/hosts/{host}")).await.assert_json(200);
        api.patch(&format!("/hosts/{host}"), None, &mode)
            .await
            .assert_write(200);
        let after = api.get(&format!("/hosts/{host}")).await;
        assert_eq!(after.body["mode"], "dynamic");
        let still = api.get(&format!("/hosts/{host}/interfaces")).await;
        assert_eq!(still.items().len(), 1);
    }

    #[tokio::test]
    async fn only_people_lock_and_unlock_a_host() {
        let api = Api::new();
        let host = make_host(&api, 1).await;
        let path = format!("/hosts/{host}");
        let robot = api.as_automation();
        robot
            .patch(&path, None, &json!({ "lock": true }))
            .await
            .assert_problem(403, "ipam.host.lock_manual_only");
        assert_eq!(api.get(&path).await.body["lock"], false);
        let locked = api.patch(&path, None, &json!({ "lock": true })).await;
        assert_eq!(locked.item()["lock"], true);
        api.patch(&path, None, &json!({ "lock": false }))
            .await
            .assert_write(200);
    }
}
