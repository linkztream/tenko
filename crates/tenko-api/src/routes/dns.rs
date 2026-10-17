//! The DNS module (Phase 2): zones and records, views, forwarders, access lists, TSIG
//! keys, block lists and the DNS role of a node.
//!
//! Area: dns. Owner: WP4.0 (the contracts); the operations are built by WP4.2 (zones,
//! records, zone files, access lists, keys), WP4.3 (the node routes), WP5.1 and WP5.2
//! (forwarders, lists), WP5.4 (the query log), WP6.1 (transfers), WP6.3 (DNSSEC) and WP6.4
//! (views). Requirements: DNS-01, DNS-02, DNS-07, DNS-09, DNS-11, DNS-12, DNS-15, DNS-20,
//! DNS-21, DNS-26, MIG-15, OPS-25.
//!
//! Every operation is declared with its request and answer types so that the OpenAPI
//! document, the typed client of the UI and the mock server have them; until its package
//! builds it, an operation checks the caller's scope and answers `501` with
//! `sys.not_implemented`. The routes belong to the DNS module (OPS-25): a server without
//! it registers none of them, so they answer 404 `sys.route_not_found`.
//!
//! | Endpoint | Scope | Purpose |
//! |---|---|---|
//! | `GET /dns/zones` | `dns.read` | List DNS zones |
//! | `POST /dns/zones` | `dns.write` | Create a DNS zone |
//! | `GET /dns/zones/{id}` | `dns.read` | Get a DNS zone |
//! | `PATCH /dns/zones/{id}` | `dns.write` | Change a DNS zone |
//! | `DELETE /dns/zones/{id}` | `dns.write` | Delete a DNS zone and its records |
//! | `GET /dns/zones/{id}/records` | `dns.read` | List the RRsets of a zone |
//! | `POST /dns/zones/{id}/records/batch` | `dns.write` | Change RRsets of a zone in one batch |
//! | `POST /dns/zones/{id}/records/import` | `dns.write` | Import a zone file into a zone |
//! | `GET /dns/zones/{id}/records/export` | `dns.read` | Export a zone as a zone file |
//! | `GET /dns/zones/{id}/dnssec` | `dns.read` | Get the signing state and keys of a zone |
//! | `POST /dns/zones/{id}/dnssec/rollover` | `dns.keys` | Start a DNSSEC key rollover |
//! | `GET /dns/zones/{id}/transfer` | `dns.read` | Get the transfer state of a zone |
//! | `POST /dns/zones/{id}/transfer` | `dns.write` | Transfer a secondary zone now |
//! | `GET /dns/views` | `dns.read` | List DNS views |
//! | `POST /dns/views` | `dns.write` | Create a DNS view |
//! | `GET /dns/views/{id}` | `dns.read` | Get a DNS view |
//! | `PATCH /dns/views/{id}` | `dns.write` | Change a DNS view |
//! | `DELETE /dns/views/{id}` | `dns.write` | Delete a DNS view |
//! | `GET /dns/forwarders` | `dns.read` | List forwarding rules |
//! | `POST /dns/forwarders` | `dns.write` | Create a forwarding rule |
//! | `GET /dns/forwarders/{id}` | `dns.read` | Get a forwarding rule |
//! | `PATCH /dns/forwarders/{id}` | `dns.write` | Change a forwarding rule |
//! | `DELETE /dns/forwarders/{id}` | `dns.write` | Delete a forwarding rule |
//! | `GET /dns/acls` | `dns.read` | List DNS access lists |
//! | `POST /dns/acls` | `dns.write` | Create a DNS access list |
//! | `GET /dns/acls/{id}` | `dns.read` | Get a DNS access list |
//! | `PATCH /dns/acls/{id}` | `dns.write` | Change a DNS access list |
//! | `DELETE /dns/acls/{id}` | `dns.write` | Delete a DNS access list |
//! | `GET /dns/keys` | `dns.keys` | List TSIG keys |
//! | `POST /dns/keys` | `dns.keys` | Generate or import a TSIG key |
//! | `GET /dns/keys/{key}` | `dns.keys` | Get a TSIG key |
//! | `DELETE /dns/keys/{key}` | `dns.keys` | Delete a TSIG key |
//! | `GET /dns/lists` | `dns.read` | List block lists |
//! | `POST /dns/lists` | `dns.write` | Create a block list |
//! | `GET /dns/lists/{id}` | `dns.read` | Get a block list |
//! | `PATCH /dns/lists/{id}` | `dns.write` | Change a block list |
//! | `DELETE /dns/lists/{id}` | `dns.write` | Delete a block list |
//! | `POST /dns/lists/{id}/fetch` | `dns.write` | Fetch and compile a block list now |
//! | `GET /nodes/{id}/dns` | `dns.read` | Get the DNS role of a node |
//! | `POST /nodes/{id}/dns/cache/flush` | `dns.write` | Flush a node's DNS cache |
//! | `GET /nodes/{id}/dns/log` | `dns.read` | Read a node's DNS query log |
//!
//! # Authorization
//!
//! The scopes are those of ADR 0017 in the roles of ADR 0015 (`tenko_core::dns::DnsScope`):
//! `dns.read` reads, `dns.write` creates, changes, deletes and runs (imports, transfers,
//! fetches, cache flushes), `dns.keys` is every action on TSIG and DNSSEC keys. A route
//! checks the action on the object it names (the zone, view, rule, list), or on the kind
//! when it names none (lists and creates). The node routes need the action on the node as
//! well. The DNS kinds are global-only for grants in Phase 2.

mod model;

#[cfg(test)]
mod tests;

use axum::{
    extract::{Path, State},
    response::Response,
};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, CodedError, NodeId, ObjectKind, ObjectRef,
    dns::{AclId, BlockListId, DnsName, ForwardRuleId, ViewId, ZoneId},
    error::codes,
};
use utoipa_axum::{router::OpenApiRouter, routes};

pub use model::{
    AclCreate, AclItem, AclPatch, DnsCommandAccepted, DnsJobStarted, DnsNodeStatus, DnssecKeyItem,
    DnssecStatus, DryRunParams, ExportParams, ForwarderCreate, ForwarderItem, ForwarderPatch,
    ImportLoss, KeyCreate, KeyCreated, KeyItem, ListCreate, ListItem, ListPatch, ListVersionItem,
    ListenerItem, PrimaryState, QueryLogLine, QueryLogParams, RecordBatch, RecordBatchResult,
    RecordChange, RecordDiff, RecordFilters, RecordOp, RolloverRequest, RrSetItem, TransferStatus,
    ViewCreate, ViewItem, ViewPatch, ZoneCreate, ZoneFileImport, ZoneFileImportReport, ZoneItem,
    ZonePatch,
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

/// An identifier from the path.
fn parse_id<T: std::str::FromStr>(raw: &str) -> Result<T, ApiError> {
    raw.parse()
        .map_err(|_| invalid("id", "the identifier is not a UUID"))
}

/// A node id from the path.
fn parse_node(raw: &str) -> Result<NodeId, ApiError> {
    raw.parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .map(NodeId)
        .ok_or_else(|| invalid("id", "the node identifier is not a positive number"))
}

/// A TSIG key name from the path.
fn parse_key(raw: &str) -> Result<DnsName, ApiError> {
    DnsName::new(raw).map_err(|_| invalid("key", "the key name is not a DNS name"))
}

/// The routes of the area.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    zone_routes()
        .merge(record_routes())
        .merge(view_and_forwarder_routes())
        .merge(acl_key_and_list_routes())
        .merge(node_routes())
}

// The registration is split into small functions that are never inlined: the server builds
// the router while its start-up future runs on the main thread, and one long chain of
// `routes!` keeps every temporary in one stack frame, which overflows the 1 MiB main
// thread stack of a Windows debug build.

#[inline(never)]
fn zone_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_dns_zones, create_dns_zone))
        .routes(routes!(get_dns_zone, update_dns_zone, delete_dns_zone))
        .routes(routes!(get_dns_zone_dnssec))
        .routes(routes!(start_dns_key_rollover))
        .routes(routes!(get_dns_zone_transfer, trigger_dns_zone_transfer))
}

#[inline(never)]
fn record_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_dns_records))
        .routes(routes!(change_dns_records))
        .routes(routes!(import_dns_zone_file))
        .routes(routes!(export_dns_zone_file))
}

#[inline(never)]
fn view_and_forwarder_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_dns_views, create_dns_view))
        .routes(routes!(get_dns_view, update_dns_view, delete_dns_view))
        .routes(routes!(list_dns_forwarders, create_dns_forwarder))
        .routes(routes!(
            get_dns_forwarder,
            update_dns_forwarder,
            delete_dns_forwarder
        ))
}

#[inline(never)]
fn acl_key_and_list_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_dns_acls, create_dns_acl))
        .routes(routes!(get_dns_acl, update_dns_acl, delete_dns_acl))
        .routes(routes!(list_dns_keys, create_dns_key))
        .routes(routes!(get_dns_key, delete_dns_key))
        .routes(routes!(list_dns_lists, create_dns_list))
        .routes(routes!(get_dns_list, update_dns_list, delete_dns_list))
        .routes(routes!(fetch_dns_list))
}

#[inline(never)]
fn node_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_node_dns_status))
        .routes(routes!(flush_node_dns_cache))
        .routes(routes!(read_node_dns_log))
}

#[utoipa::path(
    get,
    path = "/dns/zones",
    tag = "dns",
    operation_id = "list_dns_zones",
    summary = "List DNS zones",
    description = "Scope: `dns.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of zones by name", body = Page<ZoneItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_zones(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    Err(not_implemented("GET", "/dns/zones"))
}

#[utoipa::path(
    post,
    path = "/dns/zones",
    tag = "dns",
    operation_id = "create_dns_zone",
    summary = "Create a DNS zone",
    description = "Scope: `dns.write`.",
    request_body(content = ZoneCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The zone, with its SOA and NS set", body = ZoneItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the settings are invalid (`dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A zone of this name exists (`dns.zone.exists`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dns_zone(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::Zone))?;
    Err(not_implemented("POST", "/dns/zones"))
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}",
    tag = "dns",
    operation_id = "get_dns_zone",
    summary = "Get a DNS zone",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    responses(
        (status = 200, description = "The zone with its `ETag`", body = ZoneItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dns_zone(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::from(parse_id::<ZoneId>(&id)?),
    )?;
    Err(not_implemented("GET", "/dns/zones/{id}"))
}

#[utoipa::path(
    patch,
    path = "/dns/zones/{id}",
    tag = "dns",
    operation_id = "update_dns_zone",
    summary = "Change a DNS zone",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    request_body(content = ZonePatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed zone", body = ZoneItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The zone changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_dns_zone(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Update,
        &ObjectRef::from(parse_id::<ZoneId>(&id)?),
    )?;
    Err(not_implemented("PATCH", "/dns/zones/{id}"))
}

#[utoipa::path(
    delete,
    path = "/dns/zones/{id}",
    tag = "dns",
    operation_id = "delete_dns_zone",
    summary = "Delete a DNS zone and its records",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    responses(
        (status = 204, description = "The zone is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dns_zone(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Delete,
        &ObjectRef::from(parse_id::<ZoneId>(&id)?),
    )?;
    Err(not_implemented("DELETE", "/dns/zones/{id}"))
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}/records",
    tag = "dns",
    operation_id = "list_dns_records",
    summary = "List the RRsets of a zone",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), RecordFilters),
    responses(
        (status = 200, description = "A page of RRsets in name and type order", body = Page<RrSetItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_records(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::from(parse_id::<ZoneId>(&id)?),
    )?;
    Err(not_implemented("GET", "/dns/zones/{id}/records"))
}

#[utoipa::path(
    post,
    path = "/dns/zones/{id}/records/batch",
    tag = "dns",
    operation_id = "change_dns_records",
    summary = "Change RRsets of a zone in one batch",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), DryRunParams),
    request_body(content = RecordBatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The diff, and after a write the serial and revision", body = RecordBatchResult),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or A record breaks a rule of its type (`dns.record.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "RRsets conflict (`dns.record.conflict`) or belong to another origin (`dns.record.origin`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn change_dns_records(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Update,
        &ObjectRef::from(parse_id::<ZoneId>(&id)?),
    )?;
    Err(not_implemented("POST", "/dns/zones/{id}/records/batch"))
}

#[utoipa::path(
    post,
    path = "/dns/zones/{id}/records/import",
    tag = "dns",
    operation_id = "import_dns_zone_file",
    summary = "Import a zone file into a zone",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), DryRunParams),
    request_body(content = ZoneFileImport, content_type = "application/json"),
    responses(
        (status = 200, description = "The counts and losses, and after a write the serial and revision", body = ZoneFileImportReport),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The zone file does not parse (`dns.zonefile.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn import_dns_zone_file(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Update,
        &ObjectRef::from(parse_id::<ZoneId>(&id)?),
    )?;
    Err(not_implemented("POST", "/dns/zones/{id}/records/import"))
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}/records/export",
    tag = "dns",
    operation_id = "export_dns_zone_file",
    summary = "Export a zone as a zone file",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), ExportParams),
    responses(
        (status = 200, description = "The zone file (RFC 1035) in byte-stable order (MIG-15)", body = String, content_type = "text/dns"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn export_dns_zone_file(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::from(parse_id::<ZoneId>(&id)?),
    )?;
    Err(not_implemented("GET", "/dns/zones/{id}/records/export"))
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}/dnssec",
    tag = "dns",
    operation_id = "get_dns_zone_dnssec",
    summary = "Get the signing state and keys of a zone",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    responses(
        (status = 200, description = "The signing state, the keys without private parts and the DS records", body = DnssecStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dns_zone_dnssec(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::from(parse_id::<ZoneId>(&id)?),
    )?;
    Err(not_implemented("GET", "/dns/zones/{id}/dnssec"))
}

#[utoipa::path(
    post,
    path = "/dns/zones/{id}/dnssec/rollover",
    tag = "dns",
    operation_id = "start_dns_key_rollover",
    summary = "Start a DNSSEC key rollover",
    description = "Scope: `dns.keys`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    request_body(content = RolloverRequest, content_type = "application/json"),
    responses(
        (status = 202, description = "The rollover job", body = DnsJobStarted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The zone is not signed online", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn start_dns_key_rollover(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    parse_id::<ZoneId>(&id)?;
    app.authorize(
        &cx.principal,
        Action::Execute,
        &anywhere(ObjectKind::DnsKey),
    )?;
    Err(not_implemented("POST", "/dns/zones/{id}/dnssec/rollover"))
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}/transfer",
    tag = "dns",
    operation_id = "get_dns_zone_transfer",
    summary = "Get the transfer state of a zone",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    responses(
        (status = 200, description = "The serial, the sources and the refresh timers", body = TransferStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dns_zone_transfer(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::from(parse_id::<ZoneId>(&id)?),
    )?;
    Err(not_implemented("GET", "/dns/zones/{id}/transfer"))
}

#[utoipa::path(
    post,
    path = "/dns/zones/{id}/transfer",
    tag = "dns",
    operation_id = "trigger_dns_zone_transfer",
    summary = "Transfer a secondary zone now",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    responses(
        (status = 202, description = "The transfer is queued", body = TransferStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The zone is not a secondary zone", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn trigger_dns_zone_transfer(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Execute,
        &ObjectRef::from(parse_id::<ZoneId>(&id)?),
    )?;
    Err(not_implemented("POST", "/dns/zones/{id}/transfer"))
}

#[utoipa::path(
    get,
    path = "/dns/views",
    tag = "dns",
    operation_id = "list_dns_views",
    summary = "List DNS views",
    description = "Scope: `dns.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of views in order", body = Page<ViewItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_views(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::DnsView))?;
    Err(not_implemented("GET", "/dns/views"))
}

#[utoipa::path(
    post,
    path = "/dns/views",
    tag = "dns",
    operation_id = "create_dns_view",
    summary = "Create a DNS view",
    description = "Scope: `dns.write`.",
    request_body(content = ViewCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The view", body = ViewItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the view is invalid (`dns.view.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dns_view(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DnsView),
    )?;
    Err(not_implemented("POST", "/dns/views"))
}

#[utoipa::path(
    get,
    path = "/dns/views/{id}",
    tag = "dns",
    operation_id = "get_dns_view",
    summary = "Get a DNS view",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "View identifier (UUID)")),
    responses(
        (status = 200, description = "The view with its `ETag`", body = ViewItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such view (`dns.view.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dns_view(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::from(parse_id::<ViewId>(&id)?),
    )?;
    Err(not_implemented("GET", "/dns/views/{id}"))
}

#[utoipa::path(
    patch,
    path = "/dns/views/{id}",
    tag = "dns",
    operation_id = "update_dns_view",
    summary = "Change a DNS view",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "View identifier (UUID)")),
    request_body(content = ViewPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed view", body = ViewItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such view (`dns.view.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The view changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_dns_view(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Update,
        &ObjectRef::from(parse_id::<ViewId>(&id)?),
    )?;
    Err(not_implemented("PATCH", "/dns/views/{id}"))
}

#[utoipa::path(
    delete,
    path = "/dns/views/{id}",
    tag = "dns",
    operation_id = "delete_dns_view",
    summary = "Delete a DNS view",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "View identifier (UUID)")),
    responses(
        (status = 204, description = "The view is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such view (`dns.view.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dns_view(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Delete,
        &ObjectRef::from(parse_id::<ViewId>(&id)?),
    )?;
    Err(not_implemented("DELETE", "/dns/views/{id}"))
}

#[utoipa::path(
    get,
    path = "/dns/forwarders",
    tag = "dns",
    operation_id = "list_dns_forwarders",
    summary = "List forwarding rules",
    description = "Scope: `dns.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of rules by suffix", body = Page<ForwarderItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_forwarders(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DnsForwarder),
    )?;
    Err(not_implemented("GET", "/dns/forwarders"))
}

#[utoipa::path(
    post,
    path = "/dns/forwarders",
    tag = "dns",
    operation_id = "create_dns_forwarder",
    summary = "Create a forwarding rule",
    description = "Scope: `dns.write`.",
    request_body(content = ForwarderCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The rule", body = ForwarderItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the rule is invalid (`dns.forwarder.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dns_forwarder(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DnsForwarder),
    )?;
    Err(not_implemented("POST", "/dns/forwarders"))
}

#[utoipa::path(
    get,
    path = "/dns/forwarders/{id}",
    tag = "dns",
    operation_id = "get_dns_forwarder",
    summary = "Get a forwarding rule",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "Forwarding rule identifier (UUID)")),
    responses(
        (status = 200, description = "The rule with its `ETag`", body = ForwarderItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such rule (`dns.forwarder.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dns_forwarder(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::from(parse_id::<ForwardRuleId>(&id)?),
    )?;
    Err(not_implemented("GET", "/dns/forwarders/{id}"))
}

#[utoipa::path(
    patch,
    path = "/dns/forwarders/{id}",
    tag = "dns",
    operation_id = "update_dns_forwarder",
    summary = "Change a forwarding rule",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "Forwarding rule identifier (UUID)")),
    request_body(content = ForwarderPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed rule", body = ForwarderItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such rule (`dns.forwarder.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The rule changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_dns_forwarder(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Update,
        &ObjectRef::from(parse_id::<ForwardRuleId>(&id)?),
    )?;
    Err(not_implemented("PATCH", "/dns/forwarders/{id}"))
}

#[utoipa::path(
    delete,
    path = "/dns/forwarders/{id}",
    tag = "dns",
    operation_id = "delete_dns_forwarder",
    summary = "Delete a forwarding rule",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "Forwarding rule identifier (UUID)")),
    responses(
        (status = 204, description = "The rule is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such rule (`dns.forwarder.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dns_forwarder(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Delete,
        &ObjectRef::from(parse_id::<ForwardRuleId>(&id)?),
    )?;
    Err(not_implemented("DELETE", "/dns/forwarders/{id}"))
}

#[utoipa::path(
    get,
    path = "/dns/acls",
    tag = "dns",
    operation_id = "list_dns_acls",
    summary = "List DNS access lists",
    description = "Scope: `dns.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of access lists by name", body = Page<AclItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_acls(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::DnsAcl))?;
    Err(not_implemented("GET", "/dns/acls"))
}

#[utoipa::path(
    post,
    path = "/dns/acls",
    tag = "dns",
    operation_id = "create_dns_acl",
    summary = "Create a DNS access list",
    description = "Scope: `dns.write`.",
    request_body(content = AclCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The access list", body = AclItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dns_acl(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::DnsAcl))?;
    Err(not_implemented("POST", "/dns/acls"))
}

#[utoipa::path(
    get,
    path = "/dns/acls/{id}",
    tag = "dns",
    operation_id = "get_dns_acl",
    summary = "Get a DNS access list",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "Access list identifier (UUID)")),
    responses(
        (status = 200, description = "The access list with its `ETag`", body = AclItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such access list (`dns.acl.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dns_acl(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::from(parse_id::<AclId>(&id)?),
    )?;
    Err(not_implemented("GET", "/dns/acls/{id}"))
}

#[utoipa::path(
    patch,
    path = "/dns/acls/{id}",
    tag = "dns",
    operation_id = "update_dns_acl",
    summary = "Change a DNS access list",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "Access list identifier (UUID)")),
    request_body(content = AclPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed access list", body = AclItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such access list (`dns.acl.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The access list changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_dns_acl(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Update,
        &ObjectRef::from(parse_id::<AclId>(&id)?),
    )?;
    Err(not_implemented("PATCH", "/dns/acls/{id}"))
}

#[utoipa::path(
    delete,
    path = "/dns/acls/{id}",
    tag = "dns",
    operation_id = "delete_dns_acl",
    summary = "Delete a DNS access list",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "Access list identifier (UUID)")),
    responses(
        (status = 204, description = "The access list is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such access list (`dns.acl.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A zone or view still names it (`dns.acl.in_use`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dns_acl(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Delete,
        &ObjectRef::from(parse_id::<AclId>(&id)?),
    )?;
    Err(not_implemented("DELETE", "/dns/acls/{id}"))
}

#[utoipa::path(
    get,
    path = "/dns/keys",
    tag = "dns",
    operation_id = "list_dns_keys",
    summary = "List TSIG keys",
    description = "Scope: `dns.keys`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of keys by name, without secrets", body = Page<KeyItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_keys(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("GET", "/dns/keys"))
}

#[utoipa::path(
    post,
    path = "/dns/keys",
    tag = "dns",
    operation_id = "create_dns_key",
    summary = "Generate or import a TSIG key",
    description = "Scope: `dns.keys`.",
    request_body(content = KeyCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The key and its secret, shown this once", body = KeyCreated),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A key of this name exists (`dns.key.exists`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dns_key(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("POST", "/dns/keys"))
}

#[utoipa::path(
    get,
    path = "/dns/keys/{key}",
    tag = "dns",
    operation_id = "get_dns_key",
    summary = "Get a TSIG key",
    description = "Scope: `dns.keys`.",
    params(("key" = String, Path, description = "TSIG key name")),
    responses(
        (status = 200, description = "The key without its secret", body = KeyItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such key (`dns.key.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dns_key(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    parse_key(&key)?;
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("GET", "/dns/keys/{key}"))
}

#[utoipa::path(
    delete,
    path = "/dns/keys/{key}",
    tag = "dns",
    operation_id = "delete_dns_key",
    summary = "Delete a TSIG key",
    description = "Scope: `dns.keys`.",
    params(("key" = String, Path, description = "TSIG key name")),
    responses(
        (status = 204, description = "The key and its secret are gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such key (`dns.key.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dns_key(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    parse_key(&key)?;
    app.authorize(&cx.principal, Action::Delete, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("DELETE", "/dns/keys/{key}"))
}

#[utoipa::path(
    get,
    path = "/dns/lists",
    tag = "dns",
    operation_id = "list_dns_lists",
    summary = "List block lists",
    description = "Scope: `dns.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of block lists by name", body = Page<ListItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_lists(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::DnsList))?;
    Err(not_implemented("GET", "/dns/lists"))
}

#[utoipa::path(
    post,
    path = "/dns/lists",
    tag = "dns",
    operation_id = "create_dns_list",
    summary = "Create a block list",
    description = "Scope: `dns.write`.",
    request_body(content = ListCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The block list", body = ListItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the list is invalid (`dns.list.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dns_list(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DnsList),
    )?;
    Err(not_implemented("POST", "/dns/lists"))
}

#[utoipa::path(
    get,
    path = "/dns/lists/{id}",
    tag = "dns",
    operation_id = "get_dns_list",
    summary = "Get a block list",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "Block list identifier (UUID)")),
    responses(
        (status = 200, description = "The block list with its newest version", body = ListItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such list (`dns.list.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dns_list(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::from(parse_id::<BlockListId>(&id)?),
    )?;
    Err(not_implemented("GET", "/dns/lists/{id}"))
}

#[utoipa::path(
    patch,
    path = "/dns/lists/{id}",
    tag = "dns",
    operation_id = "update_dns_list",
    summary = "Change a block list",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "Block list identifier (UUID)")),
    request_body(content = ListPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed block list", body = ListItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such list (`dns.list.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The list changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_dns_list(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Update,
        &ObjectRef::from(parse_id::<BlockListId>(&id)?),
    )?;
    Err(not_implemented("PATCH", "/dns/lists/{id}"))
}

#[utoipa::path(
    delete,
    path = "/dns/lists/{id}",
    tag = "dns",
    operation_id = "delete_dns_list",
    summary = "Delete a block list",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "Block list identifier (UUID)")),
    responses(
        (status = 204, description = "The list and its versions are gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such list (`dns.list.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dns_list(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Delete,
        &ObjectRef::from(parse_id::<BlockListId>(&id)?),
    )?;
    Err(not_implemented("DELETE", "/dns/lists/{id}"))
}

#[utoipa::path(
    post,
    path = "/dns/lists/{id}/fetch",
    tag = "dns",
    operation_id = "fetch_dns_list",
    summary = "Fetch and compile a block list now",
    description = "Scope: `dns.write`.",
    params(("id" = String, Path, description = "Block list identifier (UUID)")),
    responses(
        (status = 202, description = "The fetch job", body = DnsJobStarted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such list (`dns.list.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The list is uploaded, not fetched", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn fetch_dns_list(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Execute,
        &ObjectRef::from(parse_id::<BlockListId>(&id)?),
    )?;
    Err(not_implemented("POST", "/dns/lists/{id}/fetch"))
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dns",
    tag = "dns",
    operation_id = "get_node_dns_status",
    summary = "Get the DNS role of a node",
    description = "Scope: `dns.read`.",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 200, description = "The state of the node's DNS role", body = DnsNodeStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role (`dns.node.not_dns`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_node_dns_status(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::node(parse_node(&id)?),
    )?;
    Err(not_implemented("GET", "/nodes/{id}/dns"))
}

#[utoipa::path(
    post,
    path = "/nodes/{id}/dns/cache/flush",
    tag = "dns",
    operation_id = "flush_node_dns_cache",
    summary = "Flush a node's DNS cache",
    description = "Scope: `dns.write`.",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 202, description = "The command is recorded", body = DnsCommandAccepted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role (`dns.node.not_dns`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn flush_node_dns_cache(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Update,
        &ObjectRef::node(parse_node(&id)?),
    )?;
    app.authorize(&cx.principal, Action::Execute, &anywhere(ObjectKind::Zone))?;
    Err(not_implemented("POST", "/nodes/{id}/dns/cache/flush"))
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dns/log",
    tag = "dns",
    operation_id = "read_node_dns_log",
    summary = "Read a node's DNS query log",
    description = "Scope: `dns.read`.",
    params(("id" = u64, Path, description = "Node id"), QueryLogParams),
    responses(
        (status = 200, description = "A page of log lines, newest first", body = Page<QueryLogLine>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role or its log is off (`dns.node.not_dns`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn read_node_dns_log(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::node(parse_node(&id)?),
    )?;
    Err(not_implemented("GET", "/nodes/{id}/dns/log"))
}
