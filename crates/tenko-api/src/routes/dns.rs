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
//! document, the typed client of the UI and the mock server have them. The zones, records,
//! zone files, the zone journal, access lists and TSIG keys are built (WP4.2, files
//! `dns/zones.rs`, `dns/records.rs`, `dns/acls.rs`, `dns/keys.rs`), the forwarding
//! rules (WP5.1, `dns/forwarders.rs`), the block lists (WP5.2, `dns/lists.rs`) and the
//! transfer state with its refresh now (WP6.1, `dns/transfer.rs`, on the extension
//! `SecondaryService` of the leader's transfer service), on the zone service, and the views (WP6.4, `dns/views.rs`)
//! (`tenko_dns::zone`), which the server adds as the request extension
//! `Arc<ZoneService>`. Until its package builds it, any other operation checks the
//! caller's scope and answers `501` with `sys.not_implemented`. The routes belong to the
//! DNS module (OPS-25): a server without it registers none of them, so they answer 404
//! `sys.route_not_found`.
//!
//! | Endpoint | Scope | Purpose |
//! |---|---|---|
//! | `GET /dns/zones` | `dns.read` | List DNS zones |
//! | `POST /dns/zones` | `dns.write` | Create a DNS zone |
//! | `GET /dns/zones/{id}` | `dns.read` | Get a DNS zone |
//! | `PATCH /dns/zones/{id}` | `dns.write` | Change a DNS zone |
//! | `DELETE /dns/zones/{id}` | `dns.write` | Delete a DNS zone and its records |
//! | `GET /dns/zones/{id}/journal` | `dns.read` | List the serial steps of a zone scope |
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
//! | `PUT /dns/lists/{id}/file` | `dns.write` | Upload the file of a block list |
//! | `GET /nodes/{id}/dns` | `dns.read` | Get the DNS role of a node |
//! | `POST /nodes/{id}/dns/cache/flush` | `dns.write` | Flush a node's DNS cache |
//! | `GET /nodes/{id}/dns/cache` | `dns.read` | List what a node's DNS cache holds |
//! | `GET /nodes/{id}/dns/log` | `dns.read` | Read a node's DNS query log |
//! | `POST /nodes/{id}/dns/log/stop` | `dns.write` | Stop a node's DNS query log |
//! | `POST /nodes/{id}/dns/log/start` | `dns.write` | Start a node's DNS query log again |
//!
//! # Authorization
//!
//! The scopes are those of ADR 0017 in the roles of ADR 0015 (`tenko_core::dns::DnsScope`):
//! `dns.read` reads, `dns.write` creates, changes, deletes and runs (imports, transfers,
//! fetches, cache flushes), `dns.keys` is every action on TSIG and DNSSEC keys. A route
//! checks the action on the object it names (the zone, view, rule, list), or on the kind
//! when it names none (lists and creates). The node routes need the action on the node as
//! well. The DNS kinds are global-only for grants in Phase 2.

mod acls;
mod forwarders;
mod keys;
mod lists;
mod model;
mod nodes;
mod records;
// WP6.1: the two transfer routes.
mod transfer;
// WP6.4: the view routes.
mod views;
mod zones;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use axum::{
    Json,
    extract::{DefaultBodyLimit, FromRequestParts, Path, State},
    http::{HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tenko_auth::authz::anywhere;
use tenko_core::Revision;
use tenko_core::{
    Action, CodedError, NodeId, ObjectKind, ObjectRef,
    dns::{DnsName, ZoneId},
    error::codes,
};
use tenko_dns::zone::ZoneService;
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt},
    routes,
};

pub use lists::ListUploadLimit;
pub use nodes::DnsNodeSlot;
pub use zones::{JournalItem, JournalParams};
// cache-browse: the listing of a node's cache.
pub use model::{DnsCacheEntry, DnsCacheParams};

pub use model::{
    AclCreate, AclItem, AclPatch, BlockedCountItem, CacheFlushParams, DnsCommandAccepted,
    DnsJobStarted, DnsNodeStatus, DnssecKeyItem, DnssecStatus, DryRunParams, ExportParams,
    ForwarderCreate, ForwarderItem, ForwarderPatch, ImportLoss, ImportTypeCount, KeyCreate,
    KeyCreated, KeyItem, ListCreate, ListItem, ListPatch, ListVersionItem, ListenerItem,
    OriginCount, PrimaryState, QueryLogLine, QueryLogParams, QueryLogState, QueryLogStatus,
    RecordBatch, RecordBatchResult, RecordChange, RecordDiff, RecordFilters, RecordOp,
    RolloverRequest, RrSetItem, TransferStatus, UdpWorkerItem, ViewCreate, ViewItem, ViewPatch,
    ZoneCreate, ZoneFileImport, ZoneFileImportReport, ZoneItem, ZonePatch,
};

use super::not_implemented;
use crate::{
    extract::Ctx,
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

/// The largest import request: a zone file of 1 GiB in JSON.
const MAX_ZONE_FILE_REQUEST: usize = 1 << 30;

/// The zone service of the request, from the `Arc<ZoneService>` extension the server adds
/// while the DNS module runs. Taken after the path and the scope are checked
/// ([`Zones::get`]), so a malformed path or a missing scope answers first.
pub(crate) struct Zones(Option<Arc<ZoneService>>);

impl Zones {
    /// The service; 409 `dns.module.disabled` when the server runs none.
    pub(crate) fn get(self) -> Result<Arc<ZoneService>, ApiError> {
        self.0.ok_or_else(|| {
            ApiError::from_coded_error(
                CodedError::new(
                    tenko_core::dns::codes::MODULE_DISABLED,
                    409,
                    "the zone service does not run on this server",
                )
                .with_title("DNS module disabled"),
            )
        })
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Zones {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Zones(
            parts.extensions.get::<Arc<ZoneService>>().cloned(),
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
        .routes(routes!(zones::list_dns_zones, zones::create_dns_zone))
        .routes(routes!(
            zones::get_dns_zone,
            zones::update_dns_zone,
            zones::delete_dns_zone
        ))
        .routes(routes!(zones::list_dns_zone_journal))
        .routes(routes!(get_dns_zone_dnssec))
        .routes(routes!(start_dns_key_rollover))
        // WP6.1: the transfer state and a refresh now.
        .routes(routes!(
            transfer::get_dns_zone_transfer,
            transfer::trigger_dns_zone_transfer
        ))
}

#[inline(never)]
fn record_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(records::list_dns_records))
        .routes(routes!(records::change_dns_records))
        .routes(
            routes!(records::import_dns_zone_file)
                .layer(DefaultBodyLimit::max(MAX_ZONE_FILE_REQUEST)),
        )
        .routes(routes!(records::export_dns_zone_file))
}

#[inline(never)]
fn view_and_forwarder_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(views::list_dns_views, views::create_dns_view))
        .routes(routes!(
            views::get_dns_view,
            views::update_dns_view,
            views::delete_dns_view
        ))
        .routes(routes!(
            forwarders::list_dns_forwarders,
            forwarders::create_dns_forwarder
        ))
        .routes(routes!(
            forwarders::get_dns_forwarder,
            forwarders::update_dns_forwarder,
            forwarders::delete_dns_forwarder
        ))
}

#[inline(never)]
fn acl_key_and_list_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(acls::list_dns_acls, acls::create_dns_acl))
        .routes(routes!(
            acls::get_dns_acl,
            acls::update_dns_acl,
            acls::delete_dns_acl
        ))
        .routes(routes!(keys::list_dns_keys, keys::create_dns_key))
        .routes(routes!(keys::get_dns_key, keys::delete_dns_key))
        .routes(routes!(lists::list_dns_lists, lists::create_dns_list))
        .routes(routes!(
            lists::get_dns_list,
            lists::update_dns_list,
            lists::delete_dns_list
        ))
        .routes(routes!(lists::fetch_dns_list))
        .routes(routes!(lists::upload_dns_list).layer(DefaultBodyLimit::disable()))
}

#[inline(never)]
fn node_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(nodes::get_node_dns_status))
        .routes(routes!(nodes::flush_node_dns_cache))
        .routes(routes!(nodes::read_node_dns_log))
        // cache-browse: the listing of a node's cache.
        .routes(routes!(nodes::list_node_dns_cache))
        .routes(routes!(nodes::stop_node_dns_log))
        .routes(routes!(nodes::start_node_dns_log))
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

