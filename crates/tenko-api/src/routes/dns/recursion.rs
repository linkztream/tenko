//! The recursive resolver's routes (recursion plan section 3.4): trust anchors, negative
//! trust anchors and, per node, the resolver's status, its priming and its infrastructure
//! cache.
//!
//! Area: dns. Owner: WP10.0 (the contracts); the operations are built by WP10.2 (the trust
//! anchors and the negative trust anchors, the service behind them) and WP10.4 (the node
//! routes and the rest of the API). Requirements: DNS-03, DNS-13, OPS-09.
//!
//! Every operation is declared with its request and answer types so that the OpenAPI
//! document, the typed client of the UI and the mock server have them; until its package
//! builds it, an operation checks the caller's scope (and the interactive session where the
//! table says so, which the authorizer enforces by refusing a token) and answers `501` with
//! `sys.not_implemented`. A path segment that does not parse answers 400 before any
//! authorization.
//!
//! | Endpoint | Scope | Purpose |
//! |---|---|---|
//! | `GET /dns/trust-anchors` | `dns.read` | List the trust anchors |
//! | `POST /dns/trust-anchors` | `dns.keys`, interactive | Add a trust anchor for a zone |
//! | `GET /dns/trust-anchors/{zone}` | `dns.read` | Get the trust anchor of a zone |
//! | `DELETE /dns/trust-anchors/{zone}` | `dns.keys`, interactive | Remove the trust anchor of a zone |
//! | `POST /dns/trust-anchors/{zone}/refresh` | `dns.keys` | Run RFC 5011 for a zone now |
//! | `GET /dns/ntas` | `dns.read` | List the negative trust anchors |
//! | `POST /dns/ntas` | `dns.keys`, interactive | Create a negative trust anchor |
//! | `DELETE /dns/ntas/{id}` | `dns.keys`, interactive | Delete a negative trust anchor |
//! | `GET /nodes/{id}/dns/recursion` | `dns.read` | Get the recursive resolver of a node |
//! | `POST /nodes/{id}/dns/recursion/prime` | `dns.write` | Prime a node's resolver now |
//! | `GET /nodes/{id}/dns/infra` | `dns.read` | List what a node's infrastructure cache holds |
//! | `POST /nodes/{id}/dns/infra/flush` | `dns.write` | Flush a node's infrastructure cache |
//!
//! # Error codes of the built operations
//!
//! | Code | Status | When |
//! |---|---|---|
//! | `dns.trust_anchor.not_found` | 404 | No trust anchor for the zone |
//! | `dns.trust_anchor.invalid` | 400 | A key that does not parse, twice, too many (`field`, `reason`) |
//! | `dns.trust_anchor.root_protected` | 409 | Removing or replacing the root's anchor outside Lab |
//! | `dns.nta.not_found` | 404 | No negative trust anchor of this id |
//! | `dns.nta.invalid` | 400 | The root, no expiry under Hardened, over seven days, no reason (`field`, `reason`) |
//! | `dns.recursion.disabled` | 409 | A node command while the node's resolver is off |
//!
//! The root zone is written `root` in the path of a trust anchor (a URL turns the segment `.`
//! into a dot segment); a zone named `root` is written `root.`.

use axum::{
    extract::{Path, State},
    response::Response,
};
use tenko_auth::authz::anywhere;
use tenko_core::{Action, ObjectKind, ObjectRef, dns::DnsName, dns::NtaId};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    DnsCommandAccepted, InfraCutItem, InfraFlushParams, InfraFlushed, InfraParams, NtaCreate,
    NtaItem, RecursionStatus, TrustAnchorAdd, TrustAnchorItem, invalid, parse_id, parse_node,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::PageParams,
    problem::{ApiError, ProblemDetails},
    routes::not_implemented,
    state::AppState,
};

/// A zone name from the path of a trust anchor.
fn parse_zone(raw: &str) -> Result<DnsName, ApiError> {
    // A URL turns the segment `.` into a dot segment that never reaches the server, so a
    // path spells the root `root`; a zone named `root` is written `root.`.
    if raw == "root" {
        return Ok(DnsName::root());
    }
    DnsName::new(raw).map_err(|_| invalid("zone", "the zone is not a DNS name"))
}

/// The routes of the recursive resolver.
#[inline(never)]
pub(super) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_dns_trust_anchors, add_dns_trust_anchor))
        .routes(routes!(get_dns_trust_anchor, remove_dns_trust_anchor))
        .routes(routes!(refresh_dns_trust_anchor))
        .routes(routes!(list_dns_ntas, create_dns_nta))
        .routes(routes!(delete_dns_nta))
        .routes(routes!(get_node_dns_recursion))
        .routes(routes!(prime_node_dns_recursion))
        .routes(routes!(list_node_dns_infra))
        .routes(routes!(flush_node_dns_infra))
}

#[utoipa::path(
    get,
    path = "/dns/trust-anchors",
    tag = "dns",
    operation_id = "list_dns_trust_anchors",
    summary = "List the trust anchors",
    description = "Scope: `dns.read`. One row per zone: the root (the shipped anchors and what RFC 5011 made of them) and the anchors an operator added for private zones, each with its keys, their RFC 5011 state and source, and the times of the last and the next query.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of trust anchors by zone", body = Page<TrustAnchorItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_trust_anchors(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    Err(not_implemented("GET", "/dns/trust-anchors"))
}

#[utoipa::path(
    post,
    path = "/dns/trust-anchors",
    tag = "dns",
    operation_id = "add_dns_trust_anchor",
    summary = "Add a trust anchor for a zone",
    description = "Scope: `dns.keys`, in an interactive session. Adds a key, as a DS or a DNSKEY in presentation form, to the zone's trust anchor (creating it); the key is Valid at once and its source is the operator. The root is added to only with `replace_root` and only under the Lab profile. Audited as `dns.trust_anchor.add`.",
    request_body(content = TrustAnchorAdd, content_type = "application/json"),
    responses(
        (status = 201, description = "The trust anchor of the zone", body = TrustAnchorItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the key is invalid (`dns.trust_anchor.invalid`, parameters `field` and `reason`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to change trust anchors", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The root's anchor may not be replaced outside the Lab profile (`dns.trust_anchor.root_protected`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn add_dns_trust_anchor(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("POST", "/dns/trust-anchors"))
}

#[utoipa::path(
    get,
    path = "/dns/trust-anchors/{zone}",
    tag = "dns",
    operation_id = "get_dns_trust_anchor",
    summary = "Get the trust anchor of a zone",
    description = "Scope: `dns.read`. The root zone is written `.`.",
    params(("zone" = String, Path, description = "The zone name; `root` for the root (a URL cannot carry the segment `.`)")),
    responses(
        (status = 200, description = "The trust anchor with its `ETag`", body = TrustAnchorItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No trust anchor for the zone (`dns.trust_anchor.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dns_trust_anchor(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(zone): Path<String>,
) -> Result<Response, ApiError> {
    parse_zone(&zone)?;
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    Err(not_implemented("GET", "/dns/trust-anchors/{zone}"))
}

#[utoipa::path(
    delete,
    path = "/dns/trust-anchors/{zone}",
    tag = "dns",
    operation_id = "remove_dns_trust_anchor",
    summary = "Remove the trust anchor of a zone",
    description = "Scope: `dns.keys`, in an interactive session. Names under the zone are validated against the next anchor above it, or are `indeterminate` when none applies. The root's anchor is removed only under the Lab profile. Audited as `dns.trust_anchor.remove`.",
    params(("zone" = String, Path, description = "The zone name; `root` for the root (a URL cannot carry the segment `.`)")),
    responses(
        (status = 204, description = "The trust anchor is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to change trust anchors", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No trust anchor for the zone (`dns.trust_anchor.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The root's anchor may not be removed outside the Lab profile (`dns.trust_anchor.root_protected`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn remove_dns_trust_anchor(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(zone): Path<String>,
) -> Result<Response, ApiError> {
    parse_zone(&zone)?;
    app.authorize(&cx.principal, Action::Delete, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("DELETE", "/dns/trust-anchors/{zone}"))
}

#[utoipa::path(
    post,
    path = "/dns/trust-anchors/{zone}/refresh",
    tag = "dns",
    operation_id = "refresh_dns_trust_anchor",
    summary = "Run RFC 5011 for a zone now",
    description = "Scope: `dns.keys`. Asks the zone's DNSKEY set now instead of at the next refresh interval and applies RFC 5011 to the answer; audited as `dns.trust_anchor.refresh`. The answer is the recorded command; the key states follow through the `dns` events.",
    params(("zone" = String, Path, description = "The zone name; `root` for the root (a URL cannot carry the segment `.`)")),
    responses(
        (status = 202, description = "The refresh is queued on the leader's trust anchor service", body = DnsCommandAccepted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No trust anchor for the zone (`dns.trust_anchor.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The resolver is off (`dns.recursion.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn refresh_dns_trust_anchor(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(zone): Path<String>,
) -> Result<Response, ApiError> {
    parse_zone(&zone)?;
    app.authorize(
        &cx.principal,
        Action::Execute,
        &anywhere(ObjectKind::DnsKey),
    )?;
    Err(not_implemented("POST", "/dns/trust-anchors/{zone}/refresh"))
}

#[utoipa::path(
    get,
    path = "/dns/ntas",
    tag = "dns",
    operation_id = "list_dns_ntas",
    summary = "List the negative trust anchors",
    description = "Scope: `dns.read`. The negative trust anchors (RFC 7646) that have not expired, by zone: names at or below the zone are `insecure` instead of `bogus` while one lives.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of negative trust anchors by zone", body = Page<NtaItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_ntas(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    Err(not_implemented("GET", "/dns/ntas"))
}

#[utoipa::path(
    post,
    path = "/dns/ntas",
    tag = "dns",
    operation_id = "create_dns_nta",
    summary = "Create a negative trust anchor",
    description = "Scope: `dns.keys`, in an interactive session. The expiry is at most seven days ahead and required under the Hardened profile; the reason is shown in the warnings of `GET /system/status` while the anchor lives. Audited as `dns.nta.create`.",
    request_body(content = NtaCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The negative trust anchor", body = NtaItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the anchor is invalid (`dns.nta.invalid`, parameters `field` and `reason`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to create one", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_dns_nta(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("POST", "/dns/ntas"))
}

#[utoipa::path(
    delete,
    path = "/dns/ntas/{id}",
    tag = "dns",
    operation_id = "delete_dns_nta",
    summary = "Delete a negative trust anchor",
    description = "Scope: `dns.keys`, in an interactive session. Ends the anchor before its expiry; audited as `dns.nta.delete`.",
    params(("id" = String, Path, description = "Negative trust anchor identifier (UUID)")),
    responses(
        (status = 204, description = "The negative trust anchor is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to delete one", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such negative trust anchor (`dns.nta.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_dns_nta(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    parse_id::<NtaId>(&id)?;
    app.authorize(&cx.principal, Action::Delete, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("DELETE", "/dns/ntas/{id}"))
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dns/recursion",
    tag = "dns",
    operation_id = "get_node_dns_recursion",
    summary = "Get the recursive resolver of a node",
    description = "Scope: `dns.read`. Whether the resolver runs, the source and date of the root hints, the last priming and its outcome, the root servers with their smoothed round-trip times, the sizes of the infrastructure cache, the counters since the role started, the trust anchor keys with their state, and what is wrong (`priming_failed`, `clock`, `trust_anchor_stale`).",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 200, description = "The resolver's status", body = RecursionStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role (`dns.node.not_dns`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_node_dns_recursion(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    Err(not_implemented("GET", "/nodes/{id}/dns/recursion"))
}

#[utoipa::path(
    post,
    path = "/nodes/{id}/dns/recursion/prime",
    tag = "dns",
    operation_id = "prime_node_dns_recursion",
    summary = "Prime a node's resolver now",
    description = "Scope: `dns.write`. Issues a node command that asks the root servers for the root NS set again and refreshes the infrastructure cache from the answer; audited as `dns.recursion.prime`. The outcome shows in the status.",
    params(("id" = u64, Path, description = "Node id")),
    responses(
        (status = 202, description = "The command was recorded", body = DnsCommandAccepted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role (`dns.node.not_dns`), or its resolver is off (`dns.recursion.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn prime_node_dns_recursion(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Execute, &anywhere(ObjectKind::Zone))?;
    Err(not_implemented("POST", "/nodes/{id}/dns/recursion/prime"))
}

#[utoipa::path(
    get,
    path = "/nodes/{id}/dns/infra",
    tag = "dns",
    operation_id = "list_node_dns_infra",
    summary = "List what a node's infrastructure cache holds",
    description = "Scope: `dns.read`. A page of the zone cuts the node's resolver knows, in the canonical order of their names, each with its authority servers, their addresses (origin, remaining time, smoothed round-trip time, EDNS capability, TCP-only and lame flags) and the DS state. `suffix` keeps the cuts at or below it. The cuts reveal which zones the clients asked about, so the read is a node command and recorded in the node's commands.",
    params(("id" = u64, Path, description = "Node id"), InfraParams),
    responses(
        (status = 200, description = "A page of zone cuts in canonical name order", body = Page<InfraCutItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role (`dns.node.not_dns`), or its resolver is off (`dns.recursion.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_node_dns_infra(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    Err(not_implemented("GET", "/nodes/{id}/dns/infra"))
}

#[utoipa::path(
    post,
    path = "/nodes/{id}/dns/infra/flush",
    tag = "dns",
    operation_id = "flush_node_dns_infra",
    summary = "Flush a node's infrastructure cache",
    description = "Scope: `dns.write`. Issues a node command that drops the zone cuts, server addresses and their figures, at or below `suffix` or all of them; the root hints stay and the next query primes again. Audited as `dns.infra.flush`.",
    params(("id" = u64, Path, description = "Node id"), InfraFlushParams),
    responses(
        (status = 200, description = "The number of zone cuts dropped", body = InfraFlushed),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not run the dns role (`dns.node.not_dns`), or its resolver is off (`dns.recursion.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn flush_node_dns_infra(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let node = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(node))?;
    app.authorize(&cx.principal, Action::Execute, &anywhere(ObjectKind::Zone))?;
    Err(not_implemented("POST", "/nodes/{id}/dns/infra/flush"))
}
