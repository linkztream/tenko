//! Prefixes, the prefix tree, next-free allocation and ranges.
//!
//! Area: prefixes. Owner: WP1.4. Requirements: IPAM-05, IPAM-06, IPAM-07, IPAM-10.
//!
//! The handlers are thin: [`tenko_ipam`] plans and applies every change, and the shared
//! toolkit of [`super::common`] carries the conventions of plan section 4 (lists with
//! cursors, `ETag`, `If-Match`, `dry_run`, `acknowledge`, idempotent creates). The tree
//! carries utilization and alarms, so that the UI shows capacity, percent, alarm level and
//! children per prefix without further requests. `GET /prefixes/tree` is registered next to
//! `/prefixes/{id}`; axum matches the static segment first.
//!
//! | Endpoint | Success | Main errors |
//! |---|---|---|
//! | `GET /prefixes` | 200 page of prefixes | 400 `sys.invalid_query`, `sys.invalid_cursor` |
//! | `POST /prefixes` | 201 prefix, 200 on a dry run or a replay | 400 `ipam.validation`, `ipam.prefix.host_bits`; 409 `ipam.prefix.overlap`, `ipam.plan.unacknowledged` |
//! | `GET /prefixes/tree` | 200 [`TreeResponse`] | 400 `sys.invalid_query` |
//! | `GET /prefixes/{id}` | 200 prefix with `ETag` | 404 `ipam.not_found` |
//! | `PATCH /prefixes/{id}` | 200 prefix | 404; 409 `ipam.prefix.resize_orphans`, `ipam.status.transition`; 412 `ipam.revision_mismatch` |
//! | `DELETE /prefixes/{id}` | 200 deleted prefix | 409 `ipam.in_use` (unless `cascade=true`); 412 |
//! | `POST /prefixes/{id}/next-free-address` | 201 address | 404; 409 `ipam.address.full` |
//! | `POST /prefixes/{id}/next-free-prefix` | 201 prefix | 400 `ipam.validation`; 404; 409 `ipam.prefix.full`, `ipam.prefix.overlap` |
//! | `GET /prefixes/{id}/addresses` | 200 page of addresses, with free gaps and interface and host (`expand=host`) on request | 404 |
//! | `GET /prefixes/{id}/ranges` | 200 page of ranges | 404 |
//! | `POST /prefixes/{id}/ranges` | 201 range | 404; 409 `ipam.range.overlap`, `ipam.range.outside_prefix`, `ipam.range.not_in_network` |
//! | `GET /ranges/{id}` | 200 range with `ETag` | 404 |
//! | `PATCH /ranges/{id}` | 200 range | 404; 409; 412 |
//! | `DELETE /ranges/{id}` | 200 deleted range | 404; 412 |
//!
//! # The tree
//!
//! `GET /prefixes/tree` answers the prefixes of one VRF in pre-order with depth, parent,
//! number of child prefixes, utilization (counts as decimal strings, `percent`) and the
//! alarm level. Without `vrf` it shows the VRF named `default` of the tenant named
//! `default`; when that does not exist yet, or the VRF is unknown, `nodes` is empty. `within`
//! limits the tree to the prefixes inside a network, `depth` to the first levels (`depth=0`
//! is the top level only; `children` still counts the hidden ones). The tree is read from the
//! in-memory index of the IPAM service after a read view at `at_least`, so it is at least as
//! new as the `revision` it reports.
//!
//! # Authorization
//!
//! With an [`Authorizer`](tenko_core::Authorizer) in the state, reads need
//! [`Action::Read`], creates and next-free allocations [`Action::Create`] on the kind of the
//! new object, and changes [`Action::Update`] and [`Action::Delete`] on the object. The
//! lists and the tree are empty when the principal may read nothing of the kind.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use axum::{
    Json,
    body::Bytes,
    extract::{State, rejection::BytesRejection},
    http::HeaderMap,
    response::Response,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tenko_core::{
    Action, AddressId, CodedError, InterfaceId, ObjectKind, PrefixId, RangeId, Revision, SiteId,
    VlanId, VrfId,
    error::codes as core_codes,
    ipam::{
        Address, AllocPolicy, CustomValue, FieldKey, Prefix, PrefixRole, Range, RangeRole, Status,
        Tag, UtilizationAlarm,
    },
    net::Fqdn,
};
use tenko_ipam::{
    IpamCommand, IpamService, TreeNode,
    command::{
        AllocateAddress, AllocatePrefix, PrefixInput, PrefixPatch, RangeInput, RangePatch,
        UpdatePrefix, UpdateRange,
    },
    query::{self, Deleted, HostExpander, PrefixAddressItem},
    tables::{TENANT_NAMES, VRF_NAMES},
};
use tenko_store::{ReadView, ReadViewExt};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::common::{
    DeleteParams, Filter, IdempotencyKeyHeader, IfMatch, Ipam, IpamJson, IpamPath, ReadParams,
    WriteParams, WriteResponse, authorize, get_one, if_match, list_args, list_collection,
    may_expand_hosts, may_read_kind, new_of, take_expand, wire_page, write_args, write_one,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{Filters, PageParams},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// Name of the tenant and of its VRF that the tree shows when `vrf` is absent.
const DEFAULT_NAME: &str = "default";

/// Names the lists of the ranges of a prefix in cursors; the prefix identifier is mixed in.
const RANGES_ENDPOINT: &str = "ipam.prefix_ranges";

/// Names the address lists of a prefix in cursors; the prefix identifier is mixed in.
const ADDRESSES_ENDPOINT: &str = "ipam.prefix_addresses";

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_prefixes, create_prefix))
        .routes(routes!(get_prefix_tree))
        .routes(routes!(get_prefix, update_prefix, delete_prefix))
        .routes(routes!(next_free_address))
        .routes(routes!(next_free_prefix))
        .routes(routes!(list_prefix_addresses))
        .routes(routes!(list_prefix_ranges, create_range))
        .routes(routes!(get_range, update_range, delete_range))
}

/// The prefix tree of one VRF (`GET /prefixes/tree`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub(crate) struct TreeResponse {
    /// The VRF the nodes belong to; `null` when the request named none and the VRF `default`
    /// of the tenant `default` does not exist yet.
    pub(crate) vrf: Option<VrfId>,
    /// The store revision the tree is at least as new as; subscribe to events from here.
    #[schema(value_type = u64)]
    pub(crate) revision: Revision,
    /// The prefixes in pre-order, each with depth, parent, child count, utilization and
    /// alarm level.
    pub(crate) nodes: Vec<TreeNode>,
}

/// The optional body of `POST /prefixes/{id}/next-free-address`: how the new address is
/// chosen and what it carries. Every member is optional; an empty body means all defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct NextFreeAddress {
    /// Which end to allocate from; the policy of the prefix when absent.
    pub(crate) policy: Option<AllocPolicy>,
    /// Allocate inside this range of the prefix; outside every range when absent.
    pub(crate) range: Option<RangeId>,
    /// Client-chosen identifier of the new address; generated when absent.
    pub(crate) id: Option<AddressId>,
    /// Status of the new address; `active` when absent.
    pub(crate) status: Option<Status>,
    /// Interface the new address is assigned to.
    pub(crate) interface: Option<InterfaceId>,
    /// Intended DNS name of the new address.
    pub(crate) dns_name: Option<Fqdn>,
    /// Tags of the new address.
    pub(crate) tags: BTreeSet<Tag>,
    /// Custom field values of the new address.
    pub(crate) custom: BTreeMap<FieldKey, CustomValue>,
    /// Free text.
    pub(crate) description: Option<String>,
}

/// The body of `POST /prefixes/{id}/next-free-prefix`: the length of the new child prefix
/// and what it carries.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct NextFreePrefix {
    /// Prefix length of the new prefix, for example 26.
    pub(crate) length: u8,
    /// Which end to allocate from; the policy of the parent when absent.
    #[serde(default)]
    pub(crate) policy: Option<AllocPolicy>,
    /// Client-chosen identifier of the new prefix; generated when absent.
    #[serde(default)]
    pub(crate) id: Option<PrefixId>,
    /// Role of the new prefix; a network when absent.
    #[serde(default)]
    pub(crate) role: Option<PrefixRole>,
    /// Status of the new prefix; `active` when absent.
    #[serde(default)]
    pub(crate) status: Option<Status>,
    /// VLAN of the new prefix.
    #[serde(default)]
    pub(crate) vlan: Option<VlanId>,
    /// Site of the new prefix.
    #[serde(default)]
    pub(crate) site: Option<SiteId>,
    /// Utilization alarm thresholds of the new prefix.
    #[serde(default)]
    pub(crate) alarm: Option<UtilizationAlarm>,
    /// Tags of the new prefix.
    #[serde(default)]
    pub(crate) tags: BTreeSet<Tag>,
    /// Custom field values of the new prefix.
    #[serde(default)]
    pub(crate) custom: BTreeMap<FieldKey, CustomValue>,
    /// Free text.
    #[serde(default)]
    pub(crate) description: Option<String>,
}

/// The body of `POST /prefixes/{id}/ranges`; the prefix comes from the path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewRange {
    /// Client-chosen identifier; generated when absent.
    #[serde(default)]
    pub(crate) id: Option<RangeId>,
    /// First address, inclusive.
    #[schema(value_type = String, example = "192.0.2.100")]
    pub(crate) first: IpAddr,
    /// Last address, inclusive.
    #[schema(value_type = String, example = "192.0.2.199")]
    pub(crate) last: IpAddr,
    /// What the range is for.
    pub(crate) role: RangeRole,
    /// Status; `active` when absent.
    #[serde(default)]
    pub(crate) status: Option<Status>,
    /// DHCP lease time in seconds, 60 to 31,536,000 (`dhcp_pool` ranges only); half of it is
    /// the default timeout of moves into the prefix.
    #[serde(default)]
    pub(crate) lease_secs: Option<u32>,
    /// Tags.
    #[serde(default)]
    pub(crate) tags: BTreeSet<Tag>,
    /// Custom field values.
    #[serde(default)]
    pub(crate) custom: BTreeMap<FieldKey, CustomValue>,
    /// Free text.
    #[serde(default)]
    pub(crate) description: Option<String>,
}

/// Reads the optional JSON object body of an endpoint: empty means the defaults of `T`.
///
/// # Errors
///
/// 400 `sys.invalid_request` when the body is not a JSON object of the shape of `T`.
fn optional_body<T: DeserializeOwned + Default>(
    body: Result<Bytes, BytesRejection>,
) -> Result<T, ApiError> {
    let bad_request = |status: u16, detail: String| {
        ApiError::from_coded_error(
            CodedError::new(core_codes::INVALID_REQUEST, status, detail)
                .with_title("Invalid request body"),
        )
    };
    let bytes = body.map_err(|rejection| {
        bad_request(
            rejection.status().as_u16(),
            "the request body cannot be read".to_owned(),
        )
    })?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    // A struct would also accept a JSON array of its members; the body is an object.
    if bytes.trim_ascii_start().first() != Some(&b'{') {
        return Err(bad_request(
            400,
            "the request body must be a JSON object".to_owned(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| bad_request(400, format!("the request body is not valid: {error}")))
}

/// Answers 404 `ipam.not_found` when the prefix named by the path does not exist.
///
/// The planner reports a missing prefix as `ipam.reference_missing` (409), which fits a
/// reference inside a body but not the resource of the path.
async fn ensure_prefix(ipam: &IpamService, id: PrefixId) -> Result<(), ApiError> {
    let view = ipam.view(None).await?;
    query::get::<Prefix>(view.as_ref(), id)?;
    Ok(())
}

/// The VRF named `default` of the tenant named `default`, if both exist.
fn default_vrf(view: &dyn ReadView) -> Result<Option<VrfId>, ApiError> {
    let name = DEFAULT_NAME.to_owned();
    let Some((tenant, _)) = view.get_typed(&TENANT_NAMES, &name)? else {
        return Ok(None);
    };
    Ok(view
        .get_typed(&VRF_NAMES, &(tenant, name))?
        .map(|(vrf, _)| vrf))
}

/// Lists prefixes, in address order by default.
///
/// Filter by `status`, `vrf`, `within` (prefixes inside a network), `site`, `role`, `tag`
/// (all tags must match) and `q` (text over the network, tags and description); sort with
/// `sort=-updated,cidr`; `deleted=only` shows the restore view. The answer carries the
/// revision it was read at, and a cursor for the next page while there is one.
#[utoipa::path(
    get,
    path = "/prefixes",
    tag = "prefixes",
    operation_id = "list_prefixes",
    summary = "List prefixes",
    params(
        PageParams,
        ("status" = Option<Vec<Status>>, Query, description = "Only prefixes in one of these statuses; repeat the parameter or separate the values with commas"),
        ("vrf" = Option<String>, Query, description = "Only prefixes of this VRF (identifier)"),
        ("within" = Option<String>, Query, description = "Only prefixes inside this network, for example `192.0.2.0/24` (the network itself included)", example = "192.0.2.0/24"),
        ("site" = Option<String>, Query, description = "Only prefixes of this site (identifier)"),
        ("role" = Option<PrefixRole>, Query, description = "Only supernets or only networks"),
        ("tag" = Option<Vec<String>>, Query, description = "Only prefixes carrying every one of these tags"),
        ("q" = Option<String>, Query, description = "Case-insensitive text search over the network, the tags and the description"),
        ("sort" = Option<String>, Query, description = "Sort fields, `-` in front for descending: `cidr` (default), `status`, `created`, `updated`", example = "-updated,cidr"),
        ("deleted" = Option<Deleted>, Query, description = "`exclude` (default), `include` or `only` soft-deleted prefixes")
    ),
    responses(
        (status = 200, description = "A page of prefixes", body = Page<Prefix>),
        (status = 400, description = "A parameter is unknown, repeated or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_prefixes(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<Page<Prefix>>, ApiError> {
    let args = list_args::<Prefix>(
        &filters,
        "ipam.prefixes",
        &[
            Filter::Status,
            Filter::Vrf,
            Filter::Within,
            Filter::Site,
            Filter::PrefixRole,
            Filter::Tag,
            Filter::Q,
            Filter::Sort,
            Filter::Deleted,
        ],
    )?;
    list_collection::<Prefix>(&app, &cx, &ipam, args).await
}

/// Creates a prefix (IPAM-02).
///
/// Without `vrf` the prefix goes into the VRF `default`, which is created on first use.
/// Without `role` the prefix becomes a supernet when it contains existing prefixes, else a
/// network. Prefixes nest only inside supernets: a duplicate, a prefix inside a network and
/// a network around other prefixes are refused (`ipam.prefix.overlap`, IPAM-23). An IPv6
/// prefix off a nibble boundary (IPAM-06) is refused with `ipam.plan.unacknowledged` until
/// the request acknowledges the warning with `?acknowledge=ipam.prefix.nibble_boundary`;
/// `dry_run=true` shows the warning and the plan instead.
#[utoipa::path(
    post,
    path = "/prefixes",
    tag = "prefixes",
    operation_id = "create_prefix",
    summary = "Create a prefix",
    params(WriteParams, IdempotencyKeyHeader),
    request_body = PrefixInput,
    responses(
        (status = 201, description = "The new prefix, with `ETag`", body = WriteResponse<Prefix>),
        (status = 200, description = "The plan of a dry run, or the earlier result of a repeated `Idempotency-Key`", body = WriteResponse<Prefix>),
        (status = 400, description = "Invalid prefix (`ipam.validation`, `ipam.prefix.host_bits`) or parameter (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not create prefixes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A conflict (`ipam.prefix.overlap`, `ipam.id_taken`, `ipam.reference_missing`) or a warning that needs `acknowledge` (`ipam.plan.unacknowledged`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The `Idempotency-Key` was used for another request (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_prefix(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
    IpamJson(input): IpamJson<PrefixInput>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    authorize(&app, &cx, Action::Create, new_of(ObjectKind::Prefix))?;
    write_one::<Prefix>(
        &ipam,
        &cx,
        vec![IpamCommand::CreatePrefix(input)],
        &args,
        true,
    )
    .await
}

/// Shows the prefix tree of one VRF with utilization and alarms (IPAM-10).
///
/// Every node carries its parent, depth, number of child prefixes, the utilization
/// (`capacity`, `used`, `reserved`, `free`, `covered` as decimal strings, and `percent`)
/// and the alarm `level`. `children` counts all direct child prefixes, also those that
/// `depth` leaves out, so that the UI knows which nodes can be opened. Without `vrf` the tree
/// of the VRF `default` is shown.
#[utoipa::path(
    get,
    path = "/prefixes/tree",
    tag = "prefixes",
    operation_id = "get_prefix_tree",
    summary = "Get the prefix tree with utilization and alarms",
    params(
        ("vrf" = Option<String>, Query, description = "The VRF (identifier); the VRF `default` of the tenant `default` when absent"),
        ("within" = Option<String>, Query, description = "Only the prefixes inside this network, for example `192.0.2.0/24`", example = "192.0.2.0/24"),
        ("depth" = Option<u32>, Query, description = "Deepest level to return; 0 is the top level of the answer"),
        ReadParams
    ),
    responses(
        (status = 200, description = "The nodes in pre-order; empty when the VRF has no prefixes or does not exist", body = TreeResponse),
        (status = 400, description = "A parameter is unknown, repeated or malformed (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_prefix_tree(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<TreeResponse>, ApiError> {
    filters.only(&["vrf", "within", "depth"])?;
    // The tree has no pages: refuse the paging parameters that would be silently ignored.
    if let Some((name, _)) = filters
        .pairs()
        .iter()
        .find(|(name, _)| name == "limit" || name == "cursor")
    {
        return Err(ApiError::invalid_query(name, "unknown parameter"));
    }
    let at_least = filters.page()?.at_least.map(Revision);
    let vrf = filters.parse::<VrfId>("vrf")?;
    let within = filters.cidr("within")?;
    let depth = filters.parse::<u32>("depth")?;
    let view = ipam.view(at_least).await?;
    let revision = view.revision();
    if !may_read_kind(&app, &cx, ObjectKind::Prefix) {
        return Ok(Json(TreeResponse {
            vrf,
            revision,
            nodes: Vec::new(),
        }));
    }
    let vrf = match vrf {
        Some(vrf) => Some(vrf),
        None => default_vrf(view.as_ref())?,
    };
    // The index applies a revision before the store shows it, so the tree is at least as
    // new as the view that was opened first.
    let nodes = vrf
        .map(|vrf| ipam.tree().tree(vrf, within, depth))
        .unwrap_or_default();
    Ok(Json(TreeResponse {
        vrf,
        revision,
        nodes,
    }))
}

/// Shows one prefix with its `ETag`.
#[utoipa::path(
    get,
    path = "/prefixes/{id}",
    tag = "prefixes",
    operation_id = "get_prefix",
    summary = "Get one prefix",
    params(("id" = String, Path, description = "Prefix identifier"), ReadParams),
    responses(
        (status = 200, description = "The prefix, with `ETag: \"<revision>\"`", body = Prefix),
        (status = 400, description = "A parameter is unknown or malformed (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read the prefix", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_prefix(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<PrefixId>,
    filters: Filters,
) -> Result<Response, ApiError> {
    get_one::<Prefix>(&app, &cx, &ipam, id, &filters).await
}

/// Changes a prefix: network (resize or renumber), role, status, VLAN, site, alarm
/// thresholds, allocation policy, tags, custom fields and description.
///
/// The body is a merge patch: an absent member stays, `null` clears an optional member. The
/// VRF cannot change. Children, addresses and ranges must still fit a new network
/// (`ipam.prefix.resize_orphans`), and status changes follow IPAM-05
/// (`ipam.status.transition`). Send `If-Match` with the `ETag` that was read to refuse a
/// change over a newer one (412 `ipam.revision_mismatch`).
#[utoipa::path(
    patch,
    path = "/prefixes/{id}",
    tag = "prefixes",
    operation_id = "update_prefix",
    summary = "Update a prefix",
    params(("id" = String, Path, description = "Prefix identifier"), WriteParams, IfMatch),
    request_body = PrefixPatch,
    responses(
        (status = 200, description = "The changed prefix, or the plan of a dry run", body = WriteResponse<Prefix>),
        (status = 400, description = "Invalid change (`ipam.validation`, `ipam.prefix.host_bits`, `ipam.immutable`) or a malformed `If-Match` (`ipam.validation`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not change the prefix", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A conflict (`ipam.prefix.overlap`, `ipam.prefix.resize_orphans`, `ipam.prefix.has_children`, `ipam.prefix.has_ranges`, `ipam.status.transition`, `ipam.object_deleted`) or a warning that needs `acknowledge` (`ipam.plan.unacknowledged`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_prefix(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<PrefixId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(patch): IpamJson<PrefixPatch>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Update, id.into())?;
    let command = IpamCommand::UpdatePrefix(UpdatePrefix {
        id,
        expected,
        patch,
    });
    write_one::<Prefix>(&ipam, &cx, vec![command], &args, false).await
}

/// Deletes a prefix (soft delete, IPAM-09; restore with `POST /prefixes/{id}/restore`).
///
/// A prefix with ranges is refused (409 `ipam.in_use`) unless `cascade=true` deletes them
/// with it. Its addresses move to the parent prefix; without a parent they block the delete
/// the same way, and `cascade=true` deletes them instead. Child prefixes stay and belong to
/// the next prefix up. The answer shows the deleted prefix.
#[utoipa::path(
    delete,
    path = "/prefixes/{id}",
    tag = "prefixes",
    operation_id = "delete_prefix",
    summary = "Delete a prefix",
    params(("id" = String, Path, description = "Prefix identifier"), DeleteParams, IfMatch),
    responses(
        (status = 200, description = "The deleted prefix (`meta.deleted` is set), or the plan of a dry run", body = WriteResponse<Prefix>),
        (status = 400, description = "A parameter or `If-Match` is malformed (`sys.invalid_query`, `ipam.validation`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not delete the prefix", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Addresses or ranges still use the prefix (`ipam.in_use`) or it is deleted already (`ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_prefix(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<PrefixId>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, true)?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Delete, id.into())?;
    let command = IpamCommand::Delete {
        object: id.into(),
        expected,
        cascade: args.cascade,
    };
    write_one::<Prefix>(&ipam, &cx, vec![command], &args, false).await
}

/// Allocates the next free address of a network prefix and creates it (IPAM-07).
///
/// The address is the lowest (or, with `policy=highest`, the highest) free address outside
/// the ranges of the prefix, or inside the given `range`. Consecutive calls give consecutive
/// addresses. `dry_run=true` shows the candidate in `item` without creating it. The body is
/// optional.
#[utoipa::path(
    post,
    path = "/prefixes/{id}/next-free-address",
    tag = "prefixes",
    operation_id = "next_free_address",
    summary = "Allocate the next free address in a prefix",
    params(("id" = String, Path, description = "Prefix identifier"), WriteParams, IdempotencyKeyHeader),
    request_body(
        content = Option<NextFreeAddress>,
        description = "How to choose and what to store; an empty body means all defaults",
        content_type = "application/json"
    ),
    responses(
        (status = 201, description = "The new address, with `ETag`", body = WriteResponse<Address>),
        (status = 200, description = "The candidate of a dry run, or the earlier result of a repeated `Idempotency-Key`", body = WriteResponse<Address>),
        (status = 400, description = "Invalid body (`sys.invalid_request`) or values (`ipam.validation`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not create addresses", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "No free address (`ipam.address.full`) or a conflict (`ipam.id_taken`, `ipam.reference_missing`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The `Idempotency-Key` was used for another request (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn next_free_address(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<PrefixId>,
    filters: Filters,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let request: NextFreeAddress = optional_body(body)?;
    authorize(&app, &cx, Action::Create, new_of(ObjectKind::Address))?;
    ensure_prefix(&ipam, id).await?;
    let command = IpamCommand::AllocateAddress(AllocateAddress {
        prefix: id,
        policy: request.policy,
        range: request.range,
        id: request.id,
        status: request.status,
        interface: request.interface,
        dns_name: request.dns_name,
        tags: request.tags,
        custom: request.custom,
        description: request.description,
        hint: None,
    });
    write_one::<Address>(&ipam, &cx, vec![command], &args, true).await
}

/// Allocates the next free child prefix of a supernet and creates it (IPAM-07).
///
/// The new prefix has the given `length`. It is the lowest (or, with `policy=highest`, the
/// highest) block of that length inside the supernet that no other prefix touches. A network
/// prefix cannot be the parent (`ipam.prefix.overlap`), a length that is not longer than the
/// parent's or beyond the address size is invalid (`ipam.validation`), and a full parent
/// answers `ipam.prefix.full`.
#[utoipa::path(
    post,
    path = "/prefixes/{id}/next-free-prefix",
    tag = "prefixes",
    operation_id = "next_free_prefix",
    summary = "Allocate the next free child prefix of a prefix",
    params(("id" = String, Path, description = "Prefix identifier of the parent"), WriteParams, IdempotencyKeyHeader),
    request_body = NextFreePrefix,
    responses(
        (status = 201, description = "The new prefix, with `ETag`", body = WriteResponse<Prefix>),
        (status = 200, description = "The candidate of a dry run, or the earlier result of a repeated `Idempotency-Key`", body = WriteResponse<Prefix>),
        (status = 400, description = "Invalid length or values (`ipam.validation`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not create prefixes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "No free block (`ipam.prefix.full`), the parent is a network (`ipam.prefix.overlap`), or another conflict (`ipam.id_taken`, `ipam.reference_missing`, `ipam.plan.unacknowledged`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The `Idempotency-Key` was used for another request (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn next_free_prefix(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<PrefixId>,
    filters: Filters,
    IpamJson(request): IpamJson<NextFreePrefix>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    authorize(&app, &cx, Action::Create, new_of(ObjectKind::Prefix))?;
    ensure_prefix(&ipam, id).await?;
    let command = IpamCommand::AllocatePrefix(AllocatePrefix {
        parent: id,
        length: request.length,
        policy: request.policy,
        id: request.id,
        role: request.role,
        status: request.status,
        vlan: request.vlan,
        site: request.site,
        alarm: request.alarm,
        tags: request.tags,
        custom: request.custom,
        description: request.description,
        hint: None,
    });
    write_one::<Prefix>(&ipam, &cx, vec![command], &args, true).await
}

/// Lists the addresses inside a prefix in address order, optionally with the free gaps
/// between them (the address grid of the UI).
///
/// Each item is `{ "type": "address", "data": <address> }` or
/// `{ "type": "free", "data": { first, last, size } }`; `size` is a decimal string. With
/// `expand=host` the address data of a bound address also carries `interface_detail` and
/// `host` (see `GET /addresses`). The gaps
/// cover the assignable addresses of a network (IPv4 without network and broadcast address)
/// and are counted in the page size like addresses. The cursor stays valid across the
/// boundary between an address and a gap.
#[utoipa::path(
    get,
    path = "/prefixes/{id}/addresses",
    tag = "prefixes",
    operation_id = "list_prefix_addresses",
    summary = "List the addresses of a prefix, optionally with the free ones",
    params(
        ("id" = String, Path, description = "Prefix identifier"),
        PageParams,
        ("include_free" = Option<bool>, Query, description = "Also return the free gaps between the addresses (default false)"),
        ("expand" = Option<String>, Query, description = "`host`: each address bound to an interface also carries `interface_detail` (`id`, `name`, `mac`, `duid`) and `host` (`id`, `name`, `mode`, `lock`), read from the same view as the page. Both are absent for an unbound address, when the interface or host is deleted, and when the principal may not read interfaces and hosts. Does not change the cursor.")
    ),
    responses(
        (status = 200, description = "A page of addresses and free gaps in address order", body = Page<PrefixAddressItem>),
        (status = 400, description = "A parameter is unknown, repeated or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read the prefix", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_prefix_addresses(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<PrefixId>,
    filters: Filters,
) -> Result<Json<Page<PrefixAddressItem>>, ApiError> {
    let (filters, expand) = take_expand(&filters)?;
    filters.only(&["include_free"])?;
    let include_free = filters.boolean("include_free")?.unwrap_or(false);
    let page = filters.page()?;
    let scope = filters.scope(ADDRESSES_ENDPOINT).with(&id.to_string());
    let cursor = page.cursor::<String>(scope)?;
    let limit = page.limit()?;
    authorize(&app, &cx, Action::Read, id.into())?;
    let view = ipam.view(page.at_least.map(Revision)).await?;
    if !may_read_kind(&app, &cx, ObjectKind::Address) {
        query::get::<Prefix>(view.as_ref(), id)?;
        return Ok(Json(Page::new(Vec::new(), None, view.revision())));
    }
    let mut found = query::prefix_addresses(
        view.as_ref(),
        id,
        include_free,
        cursor.as_deref(),
        Some(limit),
    )?;
    if expand && may_expand_hosts(&app, &cx) {
        HostExpander::new(view.as_ref()).expand_items(&mut found.items)?;
    }
    Ok(Json(wire_page(found, scope)))
}

/// Lists the ranges of a prefix, by first address.
///
/// Filter by `role`, `status`, `tag` and `q`; sort with `sort=-first`; `deleted=only` shows
/// deleted ranges.
#[utoipa::path(
    get,
    path = "/prefixes/{id}/ranges",
    tag = "prefixes",
    operation_id = "list_prefix_ranges",
    summary = "List the ranges of a prefix",
    params(
        ("id" = String, Path, description = "Prefix identifier"),
        PageParams,
        ("role" = Option<RangeRole>, Query, description = "Only ranges of this role"),
        ("status" = Option<Vec<Status>>, Query, description = "Only ranges in one of these statuses; repeat the parameter or separate the values with commas"),
        ("tag" = Option<Vec<String>>, Query, description = "Only ranges carrying every one of these tags"),
        ("q" = Option<String>, Query, description = "Case-insensitive text search over the addresses, the tags and the description"),
        ("sort" = Option<String>, Query, description = "Sort fields, `-` in front for descending: `first` (default), `created`, `updated`", example = "-first"),
        ("deleted" = Option<Deleted>, Query, description = "`exclude` (default), `include` or `only` soft-deleted ranges")
    ),
    responses(
        (status = 200, description = "A page of ranges", body = Page<Range>),
        (status = 400, description = "A parameter is unknown, repeated or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read the prefix", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_prefix_ranges(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<PrefixId>,
    filters: Filters,
) -> Result<Json<Page<Range>>, ApiError> {
    let mut args = list_args::<Range>(
        &filters,
        &format!("{RANGES_ENDPOINT}.{id}"),
        &[
            Filter::RangeRole,
            Filter::Status,
            Filter::Tag,
            Filter::Q,
            Filter::Sort,
            Filter::Deleted,
        ],
    )?;
    args.query.prefix = Some(id);
    authorize(&app, &cx, Action::Read, id.into())?;
    let view = ipam.view(args.page.at_least.map(Revision)).await?;
    query::get::<Prefix>(view.as_ref(), id)?;
    drop(view);
    list_collection::<Range>(&app, &cx, &ipam, args).await
}

/// Creates a range inside a network prefix (IPAM-03): a DHCP pool, a reserved block or
/// infrastructure addresses.
///
/// The range lies inside the prefix (`ipam.range.outside_prefix`), does not overlap another
/// range of the prefix (`ipam.range.overlap`) and a DHCP pool must not cover the address of
/// a host with a DHCP reservation (`ipam.range.covers_reservation`). Ranges belong to
/// network prefixes only (`ipam.range.not_in_network`).
#[utoipa::path(
    post,
    path = "/prefixes/{id}/ranges",
    tag = "prefixes",
    operation_id = "create_range",
    summary = "Create a range in a prefix",
    params(("id" = String, Path, description = "Prefix identifier"), WriteParams, IdempotencyKeyHeader),
    request_body = NewRange,
    responses(
        (status = 201, description = "The new range, with `ETag`", body = WriteResponse<Range>),
        (status = 200, description = "The plan of a dry run, or the earlier result of a repeated `Idempotency-Key`", body = WriteResponse<Range>),
        (status = 400, description = "Invalid range (`ipam.validation`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not create ranges", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A conflict (`ipam.range.overlap`, `ipam.range.outside_prefix`, `ipam.range.not_in_network`, `ipam.range.covers_reservation`, `ipam.id_taken`) or a warning that needs `acknowledge` (`ipam.plan.unacknowledged`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The `Idempotency-Key` was used for another request (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_range(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<PrefixId>,
    filters: Filters,
    IpamJson(body): IpamJson<NewRange>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    authorize(&app, &cx, Action::Create, new_of(ObjectKind::Range))?;
    ensure_prefix(&ipam, id).await?;
    let command = IpamCommand::CreateRange(RangeInput {
        id: body.id,
        prefix: id,
        first: body.first,
        last: body.last,
        role: body.role,
        status: body.status,
        lease_secs: body.lease_secs,
        tags: body.tags,
        custom: body.custom,
        description: body.description,
    });
    write_one::<Range>(&ipam, &cx, vec![command], &args, true).await
}

/// Shows one range with its `ETag`.
#[utoipa::path(
    get,
    path = "/ranges/{id}",
    tag = "prefixes",
    operation_id = "get_range",
    summary = "Get one range",
    params(("id" = String, Path, description = "Range identifier"), ReadParams),
    responses(
        (status = 200, description = "The range, with `ETag: \"<revision>\"`", body = Range),
        (status = 400, description = "A parameter is unknown or malformed (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read the range", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such range (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_range(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<RangeId>,
    filters: Filters,
) -> Result<Response, ApiError> {
    get_one::<Range>(&app, &cx, &ipam, id, &filters).await
}

/// Changes a range: first and last address, role, status, tags, custom fields and
/// description.
///
/// The body is a merge patch. The prefix of a range cannot change. The same rules as for a
/// new range apply to the changed one. Send `If-Match` with the `ETag` that was read to
/// refuse a change over a newer one (412 `ipam.revision_mismatch`).
#[utoipa::path(
    patch,
    path = "/ranges/{id}",
    tag = "prefixes",
    operation_id = "update_range",
    summary = "Update a range",
    params(("id" = String, Path, description = "Range identifier"), WriteParams, IfMatch),
    request_body = RangePatch,
    responses(
        (status = 200, description = "The changed range, or the plan of a dry run", body = WriteResponse<Range>),
        (status = 400, description = "Invalid change (`ipam.validation`) or a malformed `If-Match`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not change the range", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such range (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A conflict (`ipam.range.overlap`, `ipam.range.outside_prefix`, `ipam.range.covers_reservation`, `ipam.status.transition`, `ipam.object_deleted`) or a warning that needs `acknowledge` (`ipam.plan.unacknowledged`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_range(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<RangeId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(patch): IpamJson<RangePatch>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Update, id.into())?;
    let command = IpamCommand::UpdateRange(UpdateRange {
        id,
        expected,
        patch,
    });
    write_one::<Range>(&ipam, &cx, vec![command], &args, false).await
}

/// Deletes a range (soft delete, IPAM-09; restore with `POST /ranges/{id}/restore`). The
/// answer shows the deleted range.
#[utoipa::path(
    delete,
    path = "/ranges/{id}",
    tag = "prefixes",
    operation_id = "delete_range",
    summary = "Delete a range",
    params(("id" = String, Path, description = "Range identifier"), WriteParams, IfMatch),
    responses(
        (status = 200, description = "The deleted range (`meta.deleted` is set), or the plan of a dry run", body = WriteResponse<Range>),
        (status = 400, description = "A parameter or `If-Match` is malformed (`sys.invalid_query`, `ipam.validation`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not delete the range", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such range (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The range is deleted already (`ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_range(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<RangeId>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Delete, id.into())?;
    let command = IpamCommand::Delete {
        object: id.into(),
        expected,
        cascade: false,
    };
    write_one::<Range>(&ipam, &cx, vec![command], &args, false).await
}
#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use serde_json::{Value, json};
    use tenko_core::{
        Authorizer, Denied, DenyReason, ObjectRef, Principal, RequestCtx, ScopeFilter,
        SystemComponent,
    };
    use tenko_ipam::{
        IpamService, PlanOptions,
        command::{AddressInput, SiteInput, VrfInput},
    };
    use tenko_store::{MemStore, Store};
    use tower::ServiceExt;

    use super::*;
    use crate::{API_BASE, problem::PROBLEM_JSON};

    // ----- harness ---------------------------------------------------------------------

    /// A decoded response.
    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Value,
    }

    impl Reply {
        fn content_type(&self) -> &str {
            self.headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
        }

        /// The `ETag` header, quotes included, ready to be sent back as `If-Match`.
        fn etag(&self) -> String {
            self.headers
                .get(header::ETAG)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        }

        fn assert_status(&self, status: StatusCode) {
            assert_eq!(self.status, status, "{}", self.body);
        }

        /// Asserts a problem document with this status and code.
        fn assert_problem(&self, status: u16, code: &str) {
            let label = format!("{} {}", self.status, self.body);
            assert_eq!(self.status.as_u16(), status, "{label}");
            assert_eq!(self.content_type(), PROBLEM_JSON, "{label}");
            assert_eq!(self.body["code"], code, "{label}");
            assert_eq!(self.body["status"], status, "{label}");
        }

        /// The object of a write answer.
        fn item(&self) -> &Value {
            &self.body["item"]
        }

        fn id(&self) -> String {
            self.item()["id"].as_str().expect("item id").to_owned()
        }

        fn items(&self) -> &[Value] {
            self.body["items"].as_array().expect("items array")
        }

        /// The text member `field` of every item of a list answer.
        fn texts(&self, field: &str) -> Vec<String> {
            self.items()
                .iter()
                .map(|item| item[field].as_str().expect("text member").to_owned())
                .collect()
        }

        fn revision(&self) -> u64 {
            self.body["revision"].as_u64().expect("revision")
        }

        fn assert_no_items(&self) {
            assert_eq!(self.body["items"], json!([]), "{}", self.body);
        }

        fn assert_no_nodes(&self) {
            assert_eq!(self.body["nodes"], json!([]), "{}", self.body);
        }

        fn nodes(&self) -> &[Value] {
            self.body["nodes"].as_array().expect("nodes array")
        }

        /// The `cidr` member of every node of a tree answer.
        fn node_cidrs(&self) -> Vec<String> {
            self.nodes()
                .iter()
                .map(|node| node["cidr"].as_str().expect("cidr").to_owned())
                .collect()
        }
    }

    /// The router under test with the service behind it.
    struct Api {
        router: Router,
        ipam: Arc<IpamService>,
    }

    fn service() -> Arc<IpamService> {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        IpamService::with_direct_jobs(store).expect("service")
    }

    fn bare_router(authorizer: Option<Arc<dyn Authorizer>>) -> Router {
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        router.with_state(AppState {
            authorizer,
            ..AppState::default()
        })
    }

    async fn call(
        router: &Router,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<String>,
    ) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let body = match body {
            Some(text) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(text)
            }
            None => Body::empty(),
        };
        let response = router
            .clone()
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Reply {
            status,
            headers,
            body,
        }
    }

    impl Api {
        fn new() -> Self {
            Self::with(service(), None)
        }

        fn with(ipam: Arc<IpamService>, authorizer: Option<Arc<dyn Authorizer>>) -> Self {
            let router = bare_router(authorizer).layer(Extension(Arc::clone(&ipam)));
            Self { router, ipam }
        }

        async fn get(&self, path: &str) -> Reply {
            call(&self.router, "GET", path, &[], None).await
        }

        async fn post(&self, path: &str, body: &Value) -> Reply {
            call(&self.router, "POST", path, &[], Some(body.to_string())).await
        }

        /// A request with a raw body text (empty, malformed or not an object).
        async fn post_raw(&self, path: &str, body: &str) -> Reply {
            call(&self.router, "POST", path, &[], Some(body.to_owned())).await
        }

        async fn patch(&self, path: &str, body: &Value, if_match: Option<&str>) -> Reply {
            let headers: Vec<(&str, &str)> = if_match
                .map(|value| ("if-match", value))
                .into_iter()
                .collect();
            call(
                &self.router,
                "PATCH",
                path,
                &headers,
                Some(body.to_string()),
            )
            .await
        }

        async fn delete(&self, path: &str, if_match: Option<&str>) -> Reply {
            let headers: Vec<(&str, &str)> = if_match
                .map(|value| ("if-match", value))
                .into_iter()
                .collect();
            call(&self.router, "DELETE", path, &headers, None).await
        }

        /// Creates a prefix through the API and returns it.
        async fn prefix(&self, body: &Value) -> Value {
            let reply = self.post("/prefixes", body).await;
            reply.assert_status(StatusCode::CREATED);
            reply.item().clone()
        }

        /// Creates a range through the API and returns it.
        async fn range(&self, prefix: &str, first: &str, last: &str, role: &str) -> Value {
            let body = json!({ "first": first, "last": last, "role": role });
            let reply = self
                .post(&format!("/prefixes/{prefix}/ranges"), &body)
                .await;
            reply.assert_status(StatusCode::CREATED);
            reply.item().clone()
        }

        /// Allocates the next free address and returns its text.
        async fn next_ip(&self, prefix: &str) -> String {
            let reply = self
                .post_raw(&format!("/prefixes/{prefix}/next-free-address"), "")
                .await;
            reply.assert_status(StatusCode::CREATED);
            reply.item()["ip"].as_str().expect("ip").to_owned()
        }

        /// Runs one command through the service, bypassing the HTTP layer.
        async fn execute(&self, command: IpamCommand) -> ObjectRef {
            let cx = RequestCtx::system(SystemComponent::Api);
            let applied = self
                .ipam
                .execute(&[command], &cx, &PlanOptions::default())
                .await
                .expect("the command applies");
            applied.results[0]
        }

        async fn vrf(&self, name: &str) -> String {
            let input = VrfInput {
                id: None,
                tenant: None,
                name: name.to_owned(),
                rd: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            };
            self.execute(IpamCommand::CreateVrf(input))
                .await
                .id
                .to_string()
        }

        async fn site(&self, name: &str) -> String {
            let input = SiteInput {
                id: None,
                name: name.to_owned(),
                parent: None,
                ad_site: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            };
            self.execute(IpamCommand::CreateSite(input))
                .await
                .id
                .to_string()
        }

        /// Creates an address object directly, bypassing next free.
        async fn address(&self, ip: &str) -> String {
            let input = AddressInput {
                id: None,
                vrf: None,
                ip: ip.parse().expect("ip"),
                status: None,
                interface: None,
                dns_name: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            };
            self.execute(IpamCommand::CreateAddress(input))
                .await
                .id
                .to_string()
        }
    }

    /// Five prefixes of the default VRF: two networks, two supernets, and a network inside a
    /// supernet. Returns the identifiers in creation order.
    async fn seed(api: &Api) -> Vec<String> {
        let mut ids = Vec::new();
        for body in [
            json!({ "cidr": "192.0.2.0/24", "tags": ["edge"], "description": "office network" }),
            json!({ "cidr": "198.51.100.0/24", "status": "planned", "tags": ["edge", "lab"] }),
            json!({ "cidr": "203.0.113.0/24", "role": "supernet" }),
            json!({ "cidr": "203.0.113.0/25", "tags": ["lab"] }),
            json!({ "cidr": "2001:db8::/32", "role": "supernet" }),
        ] {
            ids.push(
                api.prefix(&body).await["id"]
                    .as_str()
                    .expect("id")
                    .to_owned(),
            );
        }
        ids
    }

    fn unknown_id() -> String {
        PrefixId::generate().to_string()
    }

    // ----- prefixes: create, read, list --------------------------------------------------

    #[tokio::test]
    async fn create_answers_201_with_the_write_response_and_an_etag() {
        let api = Api::new();
        let body = json!({ "cidr": "192.0.2.0/24", "description": "office" });
        let reply = api.post("/prefixes", &body).await;
        reply.assert_status(StatusCode::CREATED);
        assert_eq!(reply.content_type(), "application/json");
        assert_eq!(reply.body["dry_run"], false);
        assert_eq!(reply.body["replayed"], false);
        assert_eq!(reply.body["warnings"], json!([]));
        assert_eq!(reply.body["plan"], Value::Null);
        assert!(reply.body["job_id"].is_string(), "{}", reply.body);
        let item = reply.item();
        assert_eq!(item["cidr"], "192.0.2.0/24");
        assert_eq!(item["role"], "network");
        assert_eq!(item["status"], "active");
        assert_eq!(item["meta"]["description"], "office");
        assert_eq!(item["meta"]["deleted"], Value::Null);
        assert_eq!(item["meta"]["revision"], reply.revision());
        assert_eq!(reply.etag(), format!("\"{}\"", reply.revision()));
    }

    #[tokio::test]
    async fn get_answers_the_prefix_with_its_etag() {
        let api = Api::new();
        let created = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = created["id"].as_str().expect("id");
        let reply = api.get(&format!("/prefixes/{id}")).await;
        reply.assert_status(StatusCode::OK);
        assert_eq!(reply.body, created);
        let revision = created["meta"]["revision"].as_u64().expect("revision");
        assert_eq!(reply.etag(), format!("\"{revision}\""));
    }

    #[tokio::test]
    async fn get_of_an_unknown_prefix_is_404() {
        let api = Api::new();
        let reply = api.get(&format!("/prefixes/{}", unknown_id())).await;
        reply.assert_problem(404, "ipam.not_found");
        assert_eq!(reply.body["params"]["kind"], "prefix");
    }

    #[tokio::test]
    async fn get_with_a_malformed_identifier_is_a_client_error() {
        let api = Api::new();
        let reply = api.get("/prefixes/not-an-identifier").await;
        assert!(reply.status.is_client_error(), "{}", reply.status);
    }

    #[tokio::test]
    async fn get_refuses_unknown_parameters_and_honours_at_least() {
        let api = Api::new();
        let created = api
            .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
            .await;
        let id = created.id();
        api.get(&format!("/prefixes/{id}?color=red"))
            .await
            .assert_problem(400, "sys.invalid_query");
        let revision = created.revision();
        let reply = api
            .get(&format!("/prefixes/{id}?at_least={revision}"))
            .await;
        reply.assert_status(StatusCode::OK);
    }

    #[tokio::test]
    async fn list_answers_a_page_in_address_order() {
        let api = Api::new();
        let empty = api.get("/prefixes").await;
        empty.assert_status(StatusCode::OK);
        assert_eq!(empty.body["items"], json!([]));
        assert_eq!(empty.body["next_cursor"], Value::Null);
        seed(&api).await;
        let reply = api.get("/prefixes").await;
        reply.assert_status(StatusCode::OK);
        assert_eq!(reply.items().len(), 5);
        assert_eq!(reply.body["next_cursor"], Value::Null);
        assert!(reply.revision() > 0);
        let cidrs = reply.texts("cidr");
        let v4: Vec<&str> = cidrs
            .iter()
            .map(String::as_str)
            .filter(|cidr| !cidr.contains(':'))
            .collect();
        assert_eq!(
            v4,
            [
                "192.0.2.0/24",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "203.0.113.0/25"
            ]
        );
        let first = &reply.items()[0];
        assert!(first["meta"]["revision"].is_u64());
        assert!(first["vrf"].is_string());
    }

    #[tokio::test]
    async fn list_pages_with_a_limit_and_a_cursor() {
        let api = Api::new();
        seed(&api).await;
        let all = api.get("/prefixes").await.texts("id");
        let mut seen = Vec::new();
        let mut path = "/prefixes?limit=2".to_owned();
        let mut sizes = Vec::new();
        loop {
            let page = api.get(&path).await;
            page.assert_status(StatusCode::OK);
            sizes.push(page.items().len());
            seen.extend(page.texts("id"));
            match page.body["next_cursor"].as_str() {
                Some(cursor) => path = format!("/prefixes?limit=2&cursor={cursor}"),
                None => break,
            }
        }
        assert_eq!(sizes, [2, 2, 1]);
        assert_eq!(seen, all);
    }

    #[tokio::test]
    async fn list_refuses_a_cursor_of_another_query_and_bad_limits() {
        let api = Api::new();
        seed(&api).await;
        let page = api.get("/prefixes?limit=2&status=active").await;
        let cursor = page.body["next_cursor"]
            .as_str()
            .expect("cursor")
            .to_owned();
        api.get(&format!("/prefixes?limit=2&status=planned&cursor={cursor}"))
            .await
            .assert_problem(400, "sys.invalid_cursor");
        api.get("/prefixes?cursor=garbage")
            .await
            .assert_problem(400, "sys.invalid_cursor");
        api.get("/prefixes?limit=0")
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get("/prefixes?limit=1001")
            .await
            .assert_problem(400, "sys.invalid_query");
        // The same cursor with its own filters works.
        let next = api
            .get(&format!("/prefixes?limit=2&status=active&cursor={cursor}"))
            .await;
        next.assert_status(StatusCode::OK);
    }

    #[tokio::test]
    async fn list_filters_by_status_role_and_tag() {
        let api = Api::new();
        seed(&api).await;
        let planned = api.get("/prefixes?status=planned").await;
        assert_eq!(planned.texts("cidr"), ["198.51.100.0/24"]);
        for query in ["status=planned,active", "status=planned&status=active"] {
            let reply = api.get(&format!("/prefixes?{query}")).await;
            assert_eq!(reply.items().len(), 5, "{query}");
        }
        api.get("/prefixes?status=deprecated")
            .await
            .assert_no_items();
        let supernets = api.get("/prefixes?role=supernet").await;
        assert_eq!(supernets.texts("cidr"), ["203.0.113.0/24", "2001:db8::/32"]);
        let lab = api.get("/prefixes?tag=lab").await;
        assert_eq!(lab.texts("cidr"), ["198.51.100.0/24", "203.0.113.0/25"]);
        let both = api.get("/prefixes?tag=edge,lab").await;
        assert_eq!(both.texts("cidr"), ["198.51.100.0/24"]);
        let repeated = api.get("/prefixes?tag=edge&tag=lab").await;
        assert_eq!(repeated.texts("cidr"), ["198.51.100.0/24"]);
        api.get("/prefixes?status=nonsense")
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get("/prefixes?role=router")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn list_filters_by_within_and_text() {
        let api = Api::new();
        seed(&api).await;
        let inside = api.get("/prefixes?within=203.0.113.0/24").await;
        assert_eq!(inside.texts("cidr"), ["203.0.113.0/24", "203.0.113.0/25"]);
        let half = api.get("/prefixes?within=203.0.113.0/25").await;
        assert_eq!(half.texts("cidr"), ["203.0.113.0/25"]);
        let v6 = api.get("/prefixes?within=2001:db8::/32").await;
        assert_eq!(v6.texts("cidr"), ["2001:db8::/32"]);
        let office = api.get("/prefixes?q=OFFICE").await;
        assert_eq!(office.texts("cidr"), ["192.0.2.0/24"]);
        let by_network = api.get("/prefixes?q=198.51.100").await;
        assert_eq!(by_network.texts("cidr"), ["198.51.100.0/24"]);
        api.get("/prefixes?within=192.0.2.5/24")
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get("/prefixes?within=nonsense")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn list_filters_by_vrf_and_site() {
        let api = Api::new();
        let ids = seed(&api).await;
        let red = api.vrf("red.example.test").await;
        let in_red = api
            .prefix(&json!({ "cidr": "192.0.2.0/24", "vrf": red }))
            .await;
        let reply = api.get(&format!("/prefixes?vrf={red}")).await;
        assert_eq!(reply.texts("id"), [in_red["id"].as_str().expect("id")]);
        let default_vrf = api.get(&format!("/prefixes/{}", ids[0])).await.body["vrf"]
            .as_str()
            .expect("vrf")
            .to_owned();
        let reply = api.get(&format!("/prefixes?vrf={default_vrf}")).await;
        assert_eq!(reply.items().len(), 5);
        assert_eq!(api.get("/prefixes").await.items().len(), 6);
        let site = api.site("hq.example.test").await;
        let at_site = api
            .prefix(&json!({ "cidr": "198.51.100.0/24", "vrf": red, "site": site }))
            .await;
        let reply = api.get(&format!("/prefixes?site={site}")).await;
        assert_eq!(reply.texts("id"), [at_site["id"].as_str().expect("id")]);
        api.get("/prefixes?vrf=not-an-id")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn list_sorts_and_shows_deleted_prefixes_on_request() {
        let api = Api::new();
        let ids = seed(&api).await;
        let ascending = api
            .get("/prefixes?role=network&sort=cidr")
            .await
            .texts("cidr");
        let descending = api
            .get("/prefixes?role=network&sort=-cidr")
            .await
            .texts("cidr");
        let mut reversed = ascending.clone();
        reversed.reverse();
        assert_eq!(descending, reversed);
        let newest = api.get("/prefixes?sort=-updated").await;
        assert_eq!(newest.texts("id")[0], ids[4]);
        let by_status = api.get("/prefixes?sort=status,cidr").await;
        assert_eq!(by_status.items().len(), 5);
        api.get("/prefixes?sort=colour")
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get("/prefixes?foo=1")
            .await
            .assert_problem(400, "sys.invalid_query");

        let gone = &ids[1];
        api.delete(&format!("/prefixes/{gone}"), None)
            .await
            .assert_status(StatusCode::OK);
        assert_eq!(api.get("/prefixes").await.items().len(), 4);
        let only = api.get("/prefixes?deleted=only").await;
        assert_eq!(only.texts("id"), [gone.as_str()]);
        assert!(only.items()[0]["meta"]["deleted"].is_object());
        assert_eq!(api.get("/prefixes?deleted=include").await.items().len(), 5);
        api.get("/prefixes?deleted=maybe")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn at_least_reads_your_own_write() {
        let api = Api::new();
        let created = api
            .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
            .await;
        let reply = api
            .get(&format!("/prefixes?at_least={}", created.revision()))
            .await;
        assert_eq!(reply.items().len(), 1);
        assert!(reply.revision() >= created.revision());
    }

    // ----- prefixes: conflicts and validation --------------------------------------------

    #[tokio::test]
    async fn overlap_answers_409_with_the_plan_problem_shape() {
        let api = Api::new();
        api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let reply = api
            .post("/prefixes", &json!({ "cidr": "192.0.2.0/25" }))
            .await;
        reply.assert_problem(409, "ipam.prefix.overlap");
        assert_eq!(reply.body["params"]["cidr"], "192.0.2.0/24");
        assert_eq!(reply.body["errors"][0]["field"], "cidr");
        assert_eq!(reply.body["errors"][0]["code"], "ipam.prefix.overlap");
        assert!(
            reply.body["detail"]
                .as_str()
                .expect("detail")
                .contains("192.0.2.0/25")
        );
        // An exact duplicate overlaps as well, and nothing was created.
        api.post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
            .await
            .assert_problem(409, "ipam.prefix.overlap");
        assert_eq!(api.get("/prefixes").await.items().len(), 1);
    }

    #[tokio::test]
    async fn supernets_nest_and_networks_do_not_contain_prefixes() {
        let api = Api::new();
        // Prefixes nest inside a supernet.
        let supernet = api
            .prefix(&json!({ "cidr": "192.0.2.0/24", "role": "supernet" }))
            .await;
        let inside = api.prefix(&json!({ "cidr": "192.0.2.0/25" })).await;
        assert_eq!(supernet["role"], "supernet");
        assert_eq!(inside["role"], "network");
        // Without a role the container of an existing prefix becomes a supernet.
        let leaf = api.prefix(&json!({ "cidr": "2001:db8:1::/64" })).await;
        let container = api.prefix(&json!({ "cidr": "2001:db8:1::/48" })).await;
        assert_eq!(leaf["role"], "network");
        assert_eq!(container["role"], "supernet");
        // A network may not contain another prefix, and nothing goes inside a network.
        api.prefix(&json!({ "cidr": "198.51.100.0/25" })).await;
        api.post("/prefixes", &json!({ "cidr": "198.51.100.0/26" }))
            .await
            .assert_problem(409, "ipam.prefix.overlap");
        api.post(
            "/prefixes",
            &json!({ "cidr": "198.51.100.0/24", "role": "network" }),
        )
        .await
        .assert_problem(409, "ipam.prefix.overlap");
    }

    #[tokio::test]
    async fn host_bits_answer_400() {
        let api = Api::new();
        let reply = api
            .post("/prefixes", &json!({ "cidr": "192.0.2.5/24" }))
            .await;
        reply.assert_problem(400, "ipam.prefix.host_bits");
        assert_eq!(reply.body["params"]["network"], "192.0.2.0/24");
        assert_eq!(reply.body["errors"][0]["field"], "cidr");
        api.get("/prefixes").await.assert_no_items();
    }

    #[tokio::test]
    async fn invalid_alarm_thresholds_and_missing_references_are_refused() {
        let api = Api::new();
        let alarm = json!({ "cidr": "192.0.2.0/24", "alarm": { "warn_pct": 90, "crit_pct": 80 } });
        api.post("/prefixes", &alarm)
            .await
            .assert_problem(400, "ipam.validation");
        let vrf = json!({ "cidr": "192.0.2.0/24", "vrf": VrfId::generate().to_string() });
        api.post("/prefixes", &vrf)
            .await
            .assert_problem(409, "ipam.reference_missing");
        let site = json!({ "cidr": "192.0.2.0/24", "site": SiteId::generate().to_string() });
        api.post("/prefixes", &site)
            .await
            .assert_problem(409, "ipam.reference_missing");
    }

    #[tokio::test]
    async fn a_client_chosen_identifier_is_used_once() {
        let api = Api::new();
        let id = unknown_id();
        let created = api
            .prefix(&json!({ "cidr": "192.0.2.0/24", "id": id }))
            .await;
        assert_eq!(created["id"], id);
        api.post("/prefixes", &json!({ "cidr": "198.51.100.0/24", "id": id }))
            .await
            .assert_problem(409, "ipam.id_taken");
    }

    #[tokio::test]
    async fn a_malformed_body_is_a_client_error() {
        let api = Api::new();
        for body in ["", "{", "[]", r#"{"cidr": 12}"#, r#"{"role": "network"}"#] {
            let reply = api.post_raw("/prefixes", body).await;
            assert!(reply.status.is_client_error(), "{body}: {}", reply.status);
        }
        api.get("/prefixes").await.assert_no_items();
    }

    #[tokio::test]
    async fn the_nibble_boundary_needs_an_acknowledgement() {
        let api = Api::new();
        let body = json!({ "cidr": "2001:db8::/33" });
        let refused = api.post("/prefixes", &body).await;
        refused.assert_problem(409, "ipam.plan.unacknowledged");
        assert_eq!(
            refused.body["params"]["codes"],
            "ipam.prefix.nibble_boundary"
        );
        api.get("/prefixes").await.assert_no_items();

        let preview = api.post("/prefixes?dry_run=true", &body).await;
        preview.assert_status(StatusCode::OK);
        let warning = &preview.body["warnings"][0];
        assert_eq!(warning["code"], "ipam.prefix.nibble_boundary");
        assert_eq!(warning["requires_ack"], true);
        assert_eq!(warning["acknowledged"], false);
        assert_eq!(
            preview.body["plan"]["summary"]["unacknowledged"],
            json!(["ipam.prefix.nibble_boundary"])
        );

        let accepted = api
            .post("/prefixes?acknowledge=ipam.prefix.nibble_boundary", &body)
            .await;
        accepted.assert_status(StatusCode::CREATED);
        assert_eq!(accepted.item()["cidr"], "2001:db8::/33");
        assert_eq!(accepted.body["warnings"][0]["acknowledged"], true);
        assert_eq!(api.get("/prefixes").await.items().len(), 1);
    }

    #[tokio::test]
    async fn a_nibble_aligned_ipv6_prefix_has_no_warning() {
        let api = Api::new();
        let reply = api
            .post("/prefixes", &json!({ "cidr": "2001:db8::/32" }))
            .await;
        reply.assert_status(StatusCode::CREATED);
        assert_eq!(reply.body["warnings"], json!([]));
    }

    #[tokio::test]
    async fn write_endpoints_refuse_unknown_parameters() {
        let api = Api::new();
        let body = json!({ "cidr": "192.0.2.0/24" });
        api.post("/prefixes?cascade=true", &body)
            .await
            .assert_problem(400, "sys.invalid_query");
        api.post("/prefixes?dry_run=maybe", &body)
            .await
            .assert_problem(400, "sys.invalid_query");
        let id = api.prefix(&body).await["id"]
            .as_str()
            .expect("id")
            .to_owned();
        api.patch(&format!("/prefixes/{id}?cascade=true"), &json!({}), None)
            .await
            .assert_problem(400, "sys.invalid_query");
        api.delete(&format!("/prefixes/{id}?force=true"), None)
            .await
            .assert_problem(400, "sys.invalid_query");
        api.delete(&format!("/prefixes/{id}?cascade=perhaps"), None)
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn a_repeated_idempotency_key_returns_the_first_result() {
        let api = Api::new();
        let body = json!({ "cidr": "192.0.2.0/24" });
        let key = [("idempotency-key", "prefix-create-0001")];
        let send = |body: Value| {
            let router = api.router.clone();
            async move { call(&router, "POST", "/prefixes", &key, Some(body.to_string())).await }
        };
        let first = send(body.clone()).await;
        first.assert_status(StatusCode::CREATED);
        let second = send(body).await;
        second.assert_status(StatusCode::OK);
        assert_eq!(second.body["replayed"], true);
        assert_eq!(second.id(), first.id());
        assert_eq!(api.get("/prefixes").await.items().len(), 1);
        let other = send(json!({ "cidr": "198.51.100.0/24" })).await;
        other.assert_problem(422, "ipam.idempotency_mismatch");
    }

    // ----- prefixes: update and delete ----------------------------------------------------

    #[tokio::test]
    async fn patch_changes_a_prefix_and_bumps_the_etag() {
        let api = Api::new();
        let created = api
            .post(
                "/prefixes",
                &json!({ "cidr": "192.0.2.0/24", "description": "office", "tags": ["edge"] }),
            )
            .await;
        let id = created.id();
        let patch = json!({
            "description": "office network",
            "status": "deprecated",
            "alarm": { "warn_pct": 70, "crit_pct": 90 },
            "tags": ["edge", "lab"]
        });
        let reply = api
            .patch(&format!("/prefixes/{id}"), &patch, Some(&created.etag()))
            .await;
        reply.assert_status(StatusCode::OK);
        assert_eq!(reply.body["dry_run"], false);
        assert!(reply.revision() > created.revision());
        let item = reply.item();
        assert_eq!(item["meta"]["description"], "office network");
        assert_eq!(item["status"], "deprecated");
        assert_eq!(item["alarm"], json!({ "warn_pct": 70, "crit_pct": 90 }));
        assert_eq!(item["meta"]["tags"], json!(["edge", "lab"]));
        assert_eq!(item["cidr"], "192.0.2.0/24");
        assert_eq!(reply.etag(), format!("\"{}\"", reply.revision()));
        let read = api.get(&format!("/prefixes/{id}")).await;
        assert_eq!(read.body, *item);
    }

    #[tokio::test]
    async fn patch_follows_merge_rules_for_null_and_absent_members() {
        let api = Api::new();
        let created = api
            .prefix(&json!({
                "cidr": "192.0.2.0/24",
                "description": "office",
                "alarm": { "warn_pct": 70, "crit_pct": 90 }
            }))
            .await;
        let id = created["id"].as_str().expect("id");
        let reply = api
            .patch(
                &format!("/prefixes/{id}"),
                &json!({ "description": null, "alarm": null }),
                None,
            )
            .await;
        reply.assert_status(StatusCode::OK);
        assert_eq!(reply.item()["meta"]["description"], Value::Null);
        assert_eq!(reply.item()["alarm"], Value::Null);
        assert_eq!(reply.item()["status"], "active");
    }

    #[tokio::test]
    async fn an_empty_patch_changes_nothing_and_writes_no_job() {
        let api = Api::new();
        let created = api
            .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
            .await;
        let path = format!("/prefixes/{}", created.id());
        let reply = api.patch(&path, &json!({}), Some(&created.etag())).await;
        reply.assert_status(StatusCode::OK);
        assert_eq!(reply.body["job_id"], Value::Null);
        assert_eq!(reply.item(), created.item());
        assert_eq!(reply.etag(), created.etag());
    }

    #[tokio::test]
    async fn patch_can_resize_a_prefix_and_refuses_orphans() {
        let api = Api::new();
        let wide = api.prefix(&json!({ "cidr": "192.0.2.0/25" })).await;
        let id = wide["id"].as_str().expect("id");
        let grown = api
            .patch(
                &format!("/prefixes/{id}"),
                &json!({ "cidr": "192.0.2.0/24" }),
                None,
            )
            .await;
        grown.assert_status(StatusCode::OK);
        assert_eq!(grown.item()["cidr"], "192.0.2.0/24");
        api.post_raw(&format!("/prefixes/{id}/next-free-address"), "")
            .await;
        api.address("192.0.2.200").await;
        let shrunk = api
            .patch(
                &format!("/prefixes/{id}"),
                &json!({ "cidr": "192.0.2.0/25" }),
                None,
            )
            .await;
        shrunk.assert_problem(409, "ipam.prefix.resize_orphans");
        api.patch(
            &format!("/prefixes/{id}"),
            &json!({ "cidr": "192.0.2.1/24" }),
            None,
        )
        .await
        .assert_problem(400, "ipam.prefix.host_bits");
    }

    #[tokio::test]
    async fn patch_of_an_unknown_prefix_is_404() {
        let api = Api::new();
        api.patch(&format!("/prefixes/{}", unknown_id()), &json!({}), None)
            .await
            .assert_problem(404, "ipam.not_found");
    }

    #[tokio::test]
    async fn if_match_must_be_current_and_well_formed() {
        let api = Api::new();
        let created = api
            .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
            .await;
        let id = created.id();
        let path = format!("/prefixes/{id}");
        let change = json!({ "description": "one" });
        let first = api.patch(&path, &change, Some(&created.etag())).await;
        first.assert_status(StatusCode::OK);
        // The old ETag is stale now.
        let stale = api
            .patch(
                &path,
                &json!({ "description": "two" }),
                Some(&created.etag()),
            )
            .await;
        stale.assert_problem(412, "ipam.revision_mismatch");
        assert_eq!(stale.body["params"]["kind"], "prefix");
        assert_eq!(stale.body["params"]["id"], id);
        assert_eq!(
            stale.body["params"]["expected"],
            created.revision().to_string()
        );
        assert_eq!(stale.body["params"]["actual"], first.revision().to_string());
        let stale_delete = api.delete(&path, Some(&created.etag())).await;
        stale_delete.assert_problem(412, "ipam.revision_mismatch");
        // Malformed headers are 400; weak validators and bare numbers are accepted.
        let malformed = api.patch(&path, &change, Some("\"abc\"")).await;
        malformed.assert_problem(400, "ipam.validation");
        assert_eq!(malformed.body["params"]["field"], "If-Match");
        let weak = format!("W/{}", first.etag());
        api.patch(&path, &json!({ "description": "three" }), Some(&weak))
            .await
            .assert_status(StatusCode::OK);
        let read = api.get(&path).await;
        assert_eq!(read.body["meta"]["description"], "three");
    }

    #[tokio::test]
    async fn dry_run_of_a_change_writes_nothing_and_shows_the_plan() {
        let api = Api::new();
        let created = api
            .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
            .await;
        let id = created.id();
        let path = format!("/prefixes/{id}");
        let patched = api
            .patch(
                &format!("{path}?dry_run=true"),
                &json!({ "description": "x" }),
                None,
            )
            .await;
        patched.assert_status(StatusCode::OK);
        assert_eq!(patched.body["dry_run"], true);
        assert_eq!(patched.body["revision"], Value::Null);
        assert_eq!(patched.body["job_id"], Value::Null);
        assert_eq!(patched.item()["meta"]["description"], "x");
        assert!(
            patched.body["plan"]["summary"]["lines"]
                .as_array()
                .expect("lines")
                .contains(&json!("1 prefix updated"))
        );
        assert_eq!(patched.body["plan"]["changes"][0]["action"], "update");
        assert_eq!(patched.etag(), "");
        let read = api.get(&path).await;
        assert_eq!(read.body, *created.item());
    }

    #[tokio::test]
    async fn dry_run_of_a_create_shows_the_new_prefix_without_writing() {
        let api = Api::new();
        let reply = api
            .post("/prefixes?dry_run=true", &json!({ "cidr": "192.0.2.0/24" }))
            .await;
        reply.assert_status(StatusCode::OK);
        assert_eq!(reply.body["dry_run"], true);
        assert_eq!(reply.body["revision"], Value::Null);
        assert_eq!(reply.item()["cidr"], "192.0.2.0/24");
        let lines = reply.body["plan"]["summary"]["lines"]
            .as_array()
            .expect("lines");
        assert!(lines.contains(&json!("1 prefix created")), "{lines:?}");
        assert!(reply.body["plan"]["base_revision"].is_u64());
        api.get("/prefixes").await.assert_no_items();
        api.get("/prefixes/tree").await.assert_no_nodes();
    }

    #[tokio::test]
    async fn delete_soft_deletes_and_restore_data_stays_readable() {
        let api = Api::new();
        let created = api
            .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
            .await;
        let id = created.id();
        let path = format!("/prefixes/{id}");
        let reply = api.delete(&path, Some(&created.etag())).await;
        reply.assert_status(StatusCode::OK);
        assert_eq!(reply.body["dry_run"], false);
        assert!(reply.item()["meta"]["deleted"].is_object());
        assert!(reply.revision() > created.revision());
        api.get("/prefixes").await.assert_no_items();
        let read = api.get(&path).await;
        read.assert_status(StatusCode::OK);
        assert!(read.body["meta"]["deleted"].is_object());
        // The address space is free again.
        api.post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
            .await
            .assert_status(StatusCode::CREATED);
        api.delete(&path, None)
            .await
            .assert_problem(409, "ipam.object_deleted");
        api.delete(&format!("/prefixes/{}", unknown_id()), None)
            .await
            .assert_problem(404, "ipam.not_found");
    }

    #[tokio::test]
    async fn dry_run_of_a_delete_keeps_the_prefix() {
        let api = Api::new();
        let id = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await["id"]
            .as_str()
            .expect("id")
            .to_owned();
        let reply = api
            .delete(&format!("/prefixes/{id}?dry_run=true"), None)
            .await;
        reply.assert_status(StatusCode::OK);
        assert_eq!(reply.body["dry_run"], true);
        let lines = reply.body["plan"]["summary"]["lines"]
            .as_array()
            .expect("lines");
        assert!(lines.contains(&json!("1 prefix deleted")), "{lines:?}");
        assert_eq!(api.get("/prefixes").await.items().len(), 1);
        assert_eq!(api.get("/prefixes?deleted=only").await.items().len(), 0);
    }

    #[tokio::test]
    async fn delete_of_a_prefix_with_ranges_needs_cascade() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id");
        let range = api
            .range(id, "192.0.2.100", "192.0.2.199", "dhcp_pool")
            .await;
        let range_id = range["id"].as_str().expect("range id");
        let refused = api.delete(&format!("/prefixes/{id}"), None).await;
        refused.assert_problem(409, "ipam.in_use");
        assert_eq!(refused.body["params"]["by"], "ranges");
        assert_eq!(refused.body["params"]["count"], "1");
        assert_eq!(api.get("/prefixes").await.items().len(), 1);

        let cascaded = api
            .delete(&format!("/prefixes/{id}?cascade=true"), None)
            .await;
        cascaded.assert_status(StatusCode::OK);
        assert!(cascaded.item()["meta"]["deleted"].is_object());
        let gone = api.get(&format!("/ranges/{range_id}")).await;
        assert!(gone.body["meta"]["deleted"].is_object());
        api.get("/prefixes").await.assert_no_items();
    }

    #[tokio::test]
    async fn delete_of_a_prefix_moves_its_addresses_to_the_parent_or_needs_cascade() {
        let api = Api::new();
        let supernet = api
            .prefix(&json!({ "cidr": "192.0.2.0/24", "role": "supernet" }))
            .await;
        let child = api.prefix(&json!({ "cidr": "192.0.2.0/25" })).await;
        let child_id = child["id"].as_str().expect("id");
        let ip = api.next_ip(child_id).await;
        assert_eq!(ip, "192.0.2.1");
        let moved = api.delete(&format!("/prefixes/{child_id}"), None).await;
        moved.assert_status(StatusCode::OK);
        let addresses = api
            .get(&format!(
                "/prefixes/{}/addresses",
                supernet["id"].as_str().expect("id")
            ))
            .await;
        assert_eq!(addresses.items().len(), 1);
        assert_eq!(addresses.items()[0]["data"]["ip"], "192.0.2.1");
        // Without a parent the addresses block the delete.
        let alone = api.prefix(&json!({ "cidr": "198.51.100.0/24" })).await;
        let alone_id = alone["id"].as_str().expect("id");
        api.next_ip(alone_id).await;
        let refused = api.delete(&format!("/prefixes/{alone_id}"), None).await;
        refused.assert_problem(409, "ipam.in_use");
        assert_eq!(refused.body["params"]["by"], "addresses");
        api.delete(&format!("/prefixes/{alone_id}?cascade=true"), None)
            .await
            .assert_status(StatusCode::OK);
    }

    // ----- ranges ---------------------------------------------------------------------

    #[tokio::test]
    async fn create_range_answers_201_and_get_range_reads_it() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let prefix_id = prefix["id"].as_str().expect("id");
        let body = json!({
            "first": "192.0.2.100",
            "last": "192.0.2.199",
            "role": "dhcp_pool",
            "tags": ["pool"],
            "description": "guests"
        });
        let reply = api
            .post(&format!("/prefixes/{prefix_id}/ranges"), &body)
            .await;
        reply.assert_status(StatusCode::CREATED);
        assert_eq!(reply.body["dry_run"], false);
        assert!(reply.body["job_id"].is_string());
        let item = reply.item();
        assert_eq!(item["prefix"], prefix_id);
        assert_eq!(item["first"], "192.0.2.100");
        assert_eq!(item["last"], "192.0.2.199");
        assert_eq!(item["role"], "dhcp_pool");
        assert_eq!(item["status"], "active");
        assert_eq!(item["meta"]["tags"], json!(["pool"]));
        assert_eq!(reply.etag(), format!("\"{}\"", reply.revision()));
        let read = api.get(&format!("/ranges/{}", reply.id())).await;
        read.assert_status(StatusCode::OK);
        assert_eq!(read.body, *item);
        assert_eq!(read.etag(), reply.etag());
    }

    #[tokio::test]
    async fn range_conflicts_are_409_with_stable_codes() {
        let api = Api::new();
        let network = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = network["id"].as_str().expect("id");
        api.range(id, "192.0.2.100", "192.0.2.199", "dhcp_pool")
            .await;
        let path = format!("/prefixes/{id}/ranges");
        let overlap = api
            .post(
                &path,
                &json!({ "first": "192.0.2.150", "last": "192.0.2.160", "role": "reserved" }),
            )
            .await;
        overlap.assert_problem(409, "ipam.range.overlap");
        let outside = api
            .post(
                &path,
                &json!({ "first": "198.51.100.1", "last": "198.51.100.9", "role": "reserved" }),
            )
            .await;
        outside.assert_problem(409, "ipam.range.outside_prefix");
        let supernet = api
            .prefix(&json!({ "cidr": "203.0.113.0/24", "role": "supernet" }))
            .await;
        let in_supernet = api
            .post(
                &format!("/prefixes/{}/ranges", supernet["id"].as_str().expect("id")),
                &json!({ "first": "203.0.113.1", "last": "203.0.113.9", "role": "reserved" }),
            )
            .await;
        in_supernet.assert_problem(409, "ipam.range.not_in_network");
        let backwards = api
            .post(
                &path,
                &json!({ "first": "192.0.2.20", "last": "192.0.2.10", "role": "reserved" }),
            )
            .await;
        assert!(backwards.status.is_client_error(), "{}", backwards.body);
        let unknown = api
            .post(
                &format!("/prefixes/{}/ranges", unknown_id()),
                &json!({ "first": "192.0.2.1", "last": "192.0.2.9", "role": "reserved" }),
            )
            .await;
        unknown.assert_problem(404, "ipam.not_found");
        // The body names no prefix; unknown members are refused.
        let extra = api
            .post(&path, &json!({ "first": "192.0.2.1", "last": "192.0.2.9", "role": "reserved", "prefix": id }))
            .await;
        assert!(extra.status.is_client_error(), "{}", extra.status);
    }

    #[tokio::test]
    async fn list_ranges_of_a_prefix_with_filters_and_pages() {
        let api = Api::new();
        let first = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let second = api.prefix(&json!({ "cidr": "198.51.100.0/24" })).await;
        let id = first["id"].as_str().expect("id");
        let other = second["id"].as_str().expect("id");
        api.range(id, "192.0.2.1", "192.0.2.9", "infrastructure")
            .await;
        let pool = api
            .range(id, "192.0.2.100", "192.0.2.199", "dhcp_pool")
            .await;
        api.range(id, "192.0.2.200", "192.0.2.210", "reserved")
            .await;
        api.range(other, "198.51.100.1", "198.51.100.9", "reserved")
            .await;

        let path = format!("/prefixes/{id}/ranges");
        let all = api.get(&path).await;
        all.assert_status(StatusCode::OK);
        assert_eq!(
            all.texts("first"),
            ["192.0.2.1", "192.0.2.100", "192.0.2.200"]
        );
        assert!(all.revision() > 0);
        assert_eq!(all.body["next_cursor"], Value::Null);
        let pools = api.get(&format!("{path}?role=dhcp_pool")).await;
        assert_eq!(pools.texts("id"), [pool["id"].as_str().expect("id")]);
        let descending = api.get(&format!("{path}?sort=-first")).await;
        assert_eq!(descending.texts("first")[0], "192.0.2.200");
        let text = api.get(&format!("{path}?q=192.0.2.2")).await;
        assert_eq!(text.texts("first"), ["192.0.2.200"]);
        api.get(&format!("{path}?status=planned"))
            .await
            .assert_status(StatusCode::OK);
        api.get(&format!("{path}?status=planned"))
            .await
            .assert_no_items();

        let page = api.get(&format!("{path}?limit=2")).await;
        assert_eq!(page.items().len(), 2);
        let cursor = page.body["next_cursor"].as_str().expect("cursor");
        let rest = api.get(&format!("{path}?limit=2&cursor={cursor}")).await;
        assert_eq!(rest.texts("first"), ["192.0.2.200"]);
        // A cursor of one prefix does not work on another.
        api.get(&format!("/prefixes/{other}/ranges?limit=2&cursor={cursor}"))
            .await
            .assert_problem(400, "sys.invalid_cursor");
        api.get(&format!("{path}?within=192.0.2.0/24"))
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get(&format!("{path}?role=gateway"))
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get(&format!("/prefixes/{}/ranges", unknown_id()))
            .await
            .assert_problem(404, "ipam.not_found");
    }

    #[tokio::test]
    async fn patch_and_delete_a_range() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let prefix_id = prefix["id"].as_str().expect("id");
        let created = api
            .post(
                &format!("/prefixes/{prefix_id}/ranges"),
                &json!({ "first": "192.0.2.100", "last": "192.0.2.199", "role": "dhcp_pool" }),
            )
            .await;
        let id = created.id();
        let path = format!("/ranges/{id}");
        let changed = api
            .patch(
                &path,
                &json!({ "last": "192.0.2.150", "role": "reserved", "description": "held" }),
                Some(&created.etag()),
            )
            .await;
        changed.assert_status(StatusCode::OK);
        assert_eq!(changed.item()["last"], "192.0.2.150");
        assert_eq!(changed.item()["role"], "reserved");
        assert_eq!(changed.item()["meta"]["description"], "held");
        assert!(changed.revision() > created.revision());
        api.patch(
            &path,
            &json!({ "last": "192.0.2.160" }),
            Some(&created.etag()),
        )
        .await
        .assert_problem(412, "ipam.revision_mismatch");
        api.patch(&path, &json!({ "last": "198.51.100.1" }), None)
            .await
            .assert_problem(409, "ipam.range.outside_prefix");
        let preview = api
            .patch(
                &format!("{path}?dry_run=true"),
                &json!({ "last": "192.0.2.170" }),
                None,
            )
            .await;
        assert_eq!(preview.body["dry_run"], true);
        assert_eq!(preview.item()["last"], "192.0.2.170");
        assert_eq!(api.get(&path).await.body["last"], "192.0.2.150");

        api.delete(&format!("{path}?cascade=true"), None)
            .await
            .assert_problem(400, "sys.invalid_query");
        let deleted = api.delete(&path, Some(&changed.etag())).await;
        deleted.assert_status(StatusCode::OK);
        assert!(deleted.item()["meta"]["deleted"].is_object());
        let ranges = api.get(&format!("/prefixes/{prefix_id}/ranges")).await;
        ranges.assert_no_items();
        let removed = api
            .get(&format!("/prefixes/{prefix_id}/ranges?deleted=only"))
            .await;
        assert_eq!(removed.texts("id"), [id.as_str()]);
        api.delete(&path, None)
            .await
            .assert_problem(409, "ipam.object_deleted");
    }

    #[tokio::test]
    async fn unknown_ranges_are_404() {
        let api = Api::new();
        let id = RangeId::generate();
        api.get(&format!("/ranges/{id}"))
            .await
            .assert_problem(404, "ipam.not_found");
        api.patch(&format!("/ranges/{id}"), &json!({}), None)
            .await
            .assert_problem(404, "ipam.not_found");
        api.delete(&format!("/ranges/{id}"), None)
            .await
            .assert_problem(404, "ipam.not_found");
    }

    #[tokio::test]
    async fn range_dry_run_writes_nothing() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id");
        let reply = api
            .post(
                &format!("/prefixes/{id}/ranges?dry_run=true"),
                &json!({ "first": "192.0.2.100", "last": "192.0.2.199", "role": "dhcp_pool" }),
            )
            .await;
        reply.assert_status(StatusCode::OK);
        assert_eq!(reply.body["dry_run"], true);
        assert_eq!(reply.item()["first"], "192.0.2.100");
        api.get(&format!("/prefixes/{id}/ranges"))
            .await
            .assert_no_items();
    }

    // ----- the tree ---------------------------------------------------------------------

    /// A supernet with two networks inside, and a separate network.
    async fn seed_tree(api: &Api) -> [String; 4] {
        let mut ids = Vec::new();
        for body in [
            json!({ "cidr": "192.0.2.0/24", "role": "supernet" }),
            json!({ "cidr": "192.0.2.0/25" }),
            json!({ "cidr": "192.0.2.128/25" }),
            json!({ "cidr": "203.0.113.0/24" }),
        ] {
            ids.push(
                api.prefix(&body).await["id"]
                    .as_str()
                    .expect("id")
                    .to_owned(),
            );
        }
        ids.try_into().expect("four identifiers")
    }

    #[tokio::test]
    async fn tree_without_a_default_vrf_is_empty() {
        let api = Api::new();
        let reply = api.get("/prefixes/tree").await;
        reply.assert_status(StatusCode::OK);
        assert_eq!(reply.body["vrf"], Value::Null);
        assert_eq!(reply.body["nodes"], json!([]));
        assert!(reply.body["revision"].is_u64());
    }

    #[tokio::test]
    async fn tree_shows_parents_depth_and_children_of_the_default_vrf() {
        let api = Api::new();
        let [supernet, low, high, network] = seed_tree(&api).await;
        let reply = api.get("/prefixes/tree").await;
        reply.assert_status(StatusCode::OK);
        assert!(reply.body["vrf"].is_string());
        assert_eq!(
            reply.node_cidrs(),
            [
                "192.0.2.0/24",
                "192.0.2.0/25",
                "192.0.2.128/25",
                "203.0.113.0/24"
            ]
        );
        let nodes = reply.nodes();
        assert_eq!(nodes[0]["id"], supernet);
        assert_eq!(nodes[0]["depth"], 0);
        assert_eq!(nodes[0]["children"], 2);
        assert_eq!(nodes[0]["role"], "supernet");
        assert_eq!(nodes[0].get("parent"), None);
        assert_eq!(nodes[1]["id"], low);
        assert_eq!(nodes[1]["parent"], supernet);
        assert_eq!(nodes[1]["depth"], 1);
        assert_eq!(nodes[1]["children"], 0);
        assert_eq!(nodes[2]["id"], high);
        assert_eq!(nodes[2]["parent"], supernet);
        assert_eq!(nodes[3]["id"], network);
        assert_eq!(nodes[3]["depth"], 0);
        assert_eq!(nodes[3]["status"], "active");
        assert_eq!(nodes[3]["level"], "normal");
    }

    #[tokio::test]
    async fn tree_utilization_uses_decimal_strings_and_a_percentage() {
        let api = Api::new();
        let [_, _, _, network] = seed_tree(&api).await;
        let utilization = |reply: &Reply, index: usize| reply.nodes()[index]["utilization"].clone();
        let empty = utilization(&api.get("/prefixes/tree").await, 3);
        assert_eq!(empty["capacity"], "254");
        assert_eq!(empty["used"], "0");
        assert_eq!(empty["reserved"], "0");
        assert_eq!(empty["free"], "254");
        assert_eq!(empty["percent"], 0.0);
        for _ in 0..3 {
            api.next_ip(&network).await;
        }
        api.range(&network, "203.0.113.100", "203.0.113.109", "reserved")
            .await;
        let busy = utilization(&api.get("/prefixes/tree").await, 3);
        assert_eq!(busy["used"], "3");
        assert_eq!(busy["reserved"], "10");
        assert_eq!(busy["free"], "241");
        assert_eq!(busy["by_role"][0]["role"], "reserved");
        assert_eq!(busy["by_role"][0]["size"], "10");
        let percent = busy["percent"].as_f64().expect("percent");
        assert!((percent - 5.1).abs() < f64::EPSILON, "{percent}");
        // The supernet covers its two children.
        let supernet = utilization(&api.get("/prefixes/tree").await, 0);
        assert_eq!(supernet["capacity"], "256");
        assert_eq!(supernet["covered"], "256");
        let child = utilization(&api.get("/prefixes/tree").await, 1);
        assert_eq!(child["capacity"], "126");
    }

    #[tokio::test]
    async fn tree_alarm_levels_follow_the_thresholds() {
        let api = Api::new();
        let network = api
            .prefix(&json!({
                "cidr": "198.51.100.0/29",
                "alarm": { "warn_pct": 50, "crit_pct": 80 }
            }))
            .await;
        let id = network["id"].as_str().expect("id");
        let level = |reply: &Reply| {
            reply.nodes()[0]["level"]
                .as_str()
                .expect("level")
                .to_owned()
        };
        let mut levels = Vec::new();
        for _ in 0..5 {
            api.next_ip(id).await;
            levels.push(level(&api.get("/prefixes/tree").await));
        }
        assert_eq!(
            levels,
            ["normal", "normal", "warning", "warning", "critical"]
        );
        let node = &api.get("/prefixes/tree").await.nodes()[0].clone();
        assert_eq!(node["alarm"], json!({ "warn_pct": 50, "crit_pct": 80 }));
        assert_eq!(node["utilization"]["capacity"], "6");
        assert_eq!(node["utilization"]["used"], "5");
        let percent = node["utilization"]["percent"].as_f64().expect("percent");
        assert!((percent - 83.3).abs() < f64::EPSILON, "{percent}");
    }

    #[tokio::test]
    async fn tree_filters_by_depth_within_and_vrf() {
        let api = Api::new();
        let [supernet, low, ..] = seed_tree(&api).await;
        let top = api.get("/prefixes/tree?depth=0").await;
        assert_eq!(top.node_cidrs(), ["192.0.2.0/24", "203.0.113.0/24"]);
        // The child count is the real one, whatever the depth limit hides.
        assert_eq!(top.nodes()[0]["children"], 2);
        let two = api.get("/prefixes/tree?depth=1").await;
        assert_eq!(two.nodes().len(), 4);
        let within = api.get("/prefixes/tree?within=192.0.2.0/24").await;
        assert_eq!(
            within.node_cidrs(),
            ["192.0.2.0/24", "192.0.2.0/25", "192.0.2.128/25"]
        );
        let part = api.get("/prefixes/tree?within=192.0.2.0/25").await;
        assert_eq!(part.node_cidrs(), ["192.0.2.0/25"]);
        assert_eq!(part.nodes()[0]["id"], low);
        assert_eq!(part.nodes()[0]["parent"], supernet);
        let v6 = api.get("/prefixes/tree?within=2001:db8::/32").await;
        v6.assert_no_nodes();

        let vrf = api.get("/prefixes/tree").await.body["vrf"]
            .as_str()
            .expect("vrf")
            .to_owned();
        let named = api.get(&format!("/prefixes/tree?vrf={vrf}")).await;
        assert_eq!(named.nodes().len(), 4);
        assert_eq!(named.body["vrf"], vrf);
        let red = api.vrf("red.example.test").await;
        api.prefix(&json!({ "cidr": "198.51.100.0/24", "vrf": red }))
            .await;
        let red_tree = api.get(&format!("/prefixes/tree?vrf={red}")).await;
        assert_eq!(red_tree.node_cidrs(), ["198.51.100.0/24"]);
        assert_eq!(red_tree.body["vrf"], red);
        let unknown = api
            .get(&format!("/prefixes/tree?vrf={}", VrfId::generate()))
            .await;
        unknown.assert_status(StatusCode::OK);
        unknown.assert_no_nodes();
        assert_eq!(api.get("/prefixes/tree").await.nodes().len(), 4);
    }

    #[tokio::test]
    async fn tree_refuses_bad_parameters() {
        let api = Api::new();
        for query in [
            "depth=deep",
            "depth=-1",
            "within=192.0.2.5/24",
            "within=nonsense",
            "vrf=nonsense",
            "limit=5",
            "cursor=abc",
            "status=active",
            "at_least=soon",
        ] {
            let reply = api.get(&format!("/prefixes/tree?{query}")).await;
            reply.assert_problem(400, "sys.invalid_query");
        }
    }

    #[tokio::test]
    async fn tree_with_at_least_includes_the_write() {
        let api = Api::new();
        let created = api
            .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
            .await;
        let reply = api
            .get(&format!("/prefixes/tree?at_least={}", created.revision()))
            .await;
        assert_eq!(reply.node_cidrs(), ["192.0.2.0/24"]);
        assert!(reply.revision() >= created.revision());
        let next = api
            .post("/prefixes", &json!({ "cidr": "198.51.100.0/24" }))
            .await;
        let reply = api
            .get(&format!("/prefixes/tree?at_least={}", next.revision()))
            .await;
        assert_eq!(reply.nodes().len(), 2);
    }

    #[tokio::test]
    async fn the_tree_leaves_deleted_prefixes_out() {
        let api = Api::new();
        let [supernet, low, ..] = seed_tree(&api).await;
        api.delete(&format!("/prefixes/{low}"), None)
            .await
            .assert_status(StatusCode::OK);
        let tree = api.get("/prefixes/tree").await;
        assert_eq!(tree.nodes().len(), 3);
        assert_eq!(tree.nodes()[0]["id"], supernet);
        assert_eq!(tree.nodes()[0]["children"], 1);
    }

    // ----- next free address -----------------------------------------------------------

    #[tokio::test]
    async fn next_free_address_hands_out_consecutive_addresses() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id");
        let path = format!("/prefixes/{id}/next-free-address");
        let first = api.post_raw(&path, "").await;
        first.assert_status(StatusCode::CREATED);
        assert_eq!(first.item()["ip"], "192.0.2.1");
        assert_eq!(first.item()["prefix"], id);
        assert_eq!(first.item()["status"], "active");
        assert!(first.body["job_id"].is_string());
        assert_eq!(first.etag(), format!("\"{}\"", first.revision()));
        assert_eq!(api.post_raw(&path, "  \n").await.item()["ip"], "192.0.2.2");
        assert_eq!(api.post(&path, &json!({})).await.item()["ip"], "192.0.2.3");
        let list = api.get(&format!("/prefixes/{id}/addresses")).await;
        assert_eq!(list.items().len(), 3);
    }

    #[tokio::test]
    async fn next_free_address_skips_ranges_unless_asked_for_one() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id");
        api.range(id, "192.0.2.1", "192.0.2.9", "reserved").await;
        let pool = api
            .range(id, "192.0.2.100", "192.0.2.102", "dhcp_pool")
            .await;
        assert_eq!(api.next_ip(id).await, "192.0.2.10");
        assert_eq!(api.next_ip(id).await, "192.0.2.11");
        let path = format!("/prefixes/{id}/next-free-address");
        let in_pool = json!({ "range": pool["id"] });
        let first = api.post(&path, &in_pool).await;
        first.assert_status(StatusCode::CREATED);
        assert_eq!(first.item()["ip"], "192.0.2.100");
        assert_eq!(
            first.body["warnings"][0]["code"],
            "ipam.address.in_dhcp_pool"
        );
        assert_eq!(first.body["warnings"][0]["requires_ack"], false);
        assert_eq!(api.post(&path, &in_pool).await.item()["ip"], "192.0.2.101");
        assert_eq!(api.post(&path, &in_pool).await.item()["ip"], "192.0.2.102");
        api.post(&path, &in_pool)
            .await
            .assert_problem(409, "ipam.address.full");
        // Another range of the same prefix works, a range of another prefix does not.
        let other = api.prefix(&json!({ "cidr": "198.51.100.0/24" })).await;
        let foreign = api
            .post(
                &format!(
                    "/prefixes/{}/next-free-address",
                    other["id"].as_str().expect("id")
                ),
                &in_pool,
            )
            .await;
        foreign.assert_problem(400, "ipam.validation");
    }

    #[tokio::test]
    async fn next_free_address_dry_run_shows_the_candidate_without_creating_it() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id");
        let path = format!("/prefixes/{id}/next-free-address");
        let preview = api.post_raw(&format!("{path}?dry_run=true"), "").await;
        preview.assert_status(StatusCode::OK);
        assert_eq!(preview.body["dry_run"], true);
        assert_eq!(preview.item()["ip"], "192.0.2.1");
        assert_eq!(preview.body["revision"], Value::Null);
        let lines = preview.body["plan"]["summary"]["lines"]
            .as_array()
            .expect("lines");
        assert!(lines.contains(&json!("1 address created")), "{lines:?}");
        api.get(&format!("/prefixes/{id}/addresses"))
            .await
            .assert_no_items();
        assert_eq!(api.next_ip(id).await, "192.0.2.1");
        let again = api.post_raw(&format!("{path}?dry_run=true"), "").await;
        assert_eq!(again.item()["ip"], "192.0.2.2");
    }

    #[tokio::test]
    async fn next_free_address_takes_its_options_from_the_body() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id");
        let path = format!("/prefixes/{id}/next-free-address");
        let highest = api.post(&path, &json!({ "policy": "highest" })).await;
        assert_eq!(highest.item()["ip"], "192.0.2.254");
        let chosen = unknown_id();
        let body = json!({
            "id": chosen,
            "status": "reserved",
            "dns_name": "nas.example.test",
            "tags": ["storage"],
            "description": "backup target"
        });
        let reply = api.post(&path, &body).await;
        reply.assert_status(StatusCode::CREATED);
        let item = reply.item();
        assert_eq!(item["id"], chosen);
        assert_eq!(item["ip"], "192.0.2.1");
        assert_eq!(item["status"], "reserved");
        assert_eq!(item["dns_name"], "nas.example.test");
        assert_eq!(item["meta"]["tags"], json!(["storage"]));
        assert_eq!(item["meta"]["description"], "backup target");
        let lowest = api.post(&path, &json!({ "policy": "lowest" })).await;
        assert_eq!(lowest.item()["ip"], "192.0.2.2");
    }

    #[tokio::test]
    async fn the_policy_of_the_prefix_is_the_default() {
        let api = Api::new();
        let prefix = api
            .prefix(&json!({ "cidr": "192.0.2.0/24", "alloc": "highest" }))
            .await;
        let id = prefix["id"].as_str().expect("id");
        assert_eq!(api.next_ip(id).await, "192.0.2.254");
        assert_eq!(api.next_ip(id).await, "192.0.2.253");
    }

    #[tokio::test]
    async fn a_full_prefix_answers_409_address_full() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/30" })).await;
        let id = prefix["id"].as_str().expect("id");
        assert_eq!(api.next_ip(id).await, "192.0.2.1");
        assert_eq!(api.next_ip(id).await, "192.0.2.2");
        let path = format!("/prefixes/{id}/next-free-address");
        let full = api.post_raw(&path, "").await;
        full.assert_problem(409, "ipam.address.full");
        assert_eq!(full.body["params"]["cidr"], "192.0.2.0/30");
        api.post_raw(&format!("{path}?dry_run=true"), "")
            .await
            .assert_problem(409, "ipam.address.full");
    }

    #[tokio::test]
    async fn next_free_address_validates_its_body_and_target() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id");
        let path = format!("/prefixes/{id}/next-free-address");
        for body in [
            "[]",
            "{",
            "42",
            r#"{"colour": "red"}"#,
            r#"{"policy": "middle"}"#,
        ] {
            api.post_raw(&path, body)
                .await
                .assert_problem(400, "sys.invalid_request");
        }
        api.post_raw(&format!("{path}?force=1"), "")
            .await
            .assert_problem(400, "sys.invalid_query");
        api.post_raw(&format!("/prefixes/{}/next-free-address", unknown_id()), "")
            .await
            .assert_problem(404, "ipam.not_found");
        api.get(&format!("/prefixes/{id}/addresses"))
            .await
            .assert_no_items();
    }

    // ----- next free prefix -----------------------------------------------------------

    #[tokio::test]
    async fn next_free_prefix_gives_distinct_blocks() {
        let api = Api::new();
        let parent = api
            .prefix(&json!({ "cidr": "192.0.2.0/24", "role": "supernet" }))
            .await;
        let id = parent["id"].as_str().expect("id");
        let path = format!("/prefixes/{id}/next-free-prefix");
        let first = api.post(&path, &json!({ "length": 26 })).await;
        first.assert_status(StatusCode::CREATED);
        assert_eq!(first.item()["cidr"], "192.0.2.0/26");
        assert_eq!(first.item()["role"], "network");
        assert_eq!(first.item()["status"], "active");
        assert_eq!(first.item()["vrf"], parent["vrf"]);
        assert_eq!(first.etag(), format!("\"{}\"", first.revision()));
        let second = api.post(&path, &json!({ "length": 26 })).await;
        assert_eq!(second.item()["cidr"], "192.0.2.64/26");
        assert_ne!(first.id(), second.id());
        let highest = api
            .post(&path, &json!({ "length": 26, "policy": "highest" }))
            .await;
        assert_eq!(highest.item()["cidr"], "192.0.2.192/26");
        let tree = api.get("/prefixes/tree").await;
        assert_eq!(tree.nodes()[0]["children"], 3);
        assert_eq!(tree.nodes()[1]["parent"], parent["id"]);
    }

    #[tokio::test]
    async fn next_free_prefix_carries_the_attributes_of_the_body() {
        let api = Api::new();
        let site = api.site("hq.example.test").await;
        let parent = api
            .prefix(&json!({ "cidr": "192.0.2.0/24", "role": "supernet" }))
            .await;
        let path = format!(
            "/prefixes/{}/next-free-prefix",
            parent["id"].as_str().expect("id")
        );
        let chosen = unknown_id();
        let body = json!({
            "length": 27,
            "id": chosen,
            "status": "planned",
            "site": site,
            "alarm": { "warn_pct": 80, "crit_pct": 95 },
            "tags": ["lab"],
            "description": "test network"
        });
        let reply = api.post(&path, &body).await;
        reply.assert_status(StatusCode::CREATED);
        let item = reply.item();
        assert_eq!(item["id"], chosen);
        assert_eq!(item["cidr"], "192.0.2.0/27");
        assert_eq!(item["status"], "planned");
        assert_eq!(item["site"], site);
        assert_eq!(item["alarm"], json!({ "warn_pct": 80, "crit_pct": 95 }));
        assert_eq!(item["meta"]["tags"], json!(["lab"]));
        assert_eq!(item["meta"]["description"], "test network");
        let as_supernet = api
            .post(&path, &json!({ "length": 27, "role": "supernet" }))
            .await;
        assert_eq!(as_supernet.item()["role"], "supernet");
        assert_eq!(as_supernet.item()["cidr"], "192.0.2.32/27");
    }

    #[tokio::test]
    async fn next_free_prefix_dry_run_shows_the_candidate() {
        let api = Api::new();
        let parent = api
            .prefix(&json!({ "cidr": "192.0.2.0/24", "role": "supernet" }))
            .await;
        let path = format!(
            "/prefixes/{}/next-free-prefix",
            parent["id"].as_str().expect("id")
        );
        let preview = api
            .post(&format!("{path}?dry_run=true"), &json!({ "length": 25 }))
            .await;
        preview.assert_status(StatusCode::OK);
        assert_eq!(preview.body["dry_run"], true);
        assert_eq!(preview.item()["cidr"], "192.0.2.0/25");
        assert_eq!(api.get("/prefixes").await.items().len(), 1);
        let real = api.post(&path, &json!({ "length": 25 })).await;
        assert_eq!(real.item()["cidr"], "192.0.2.0/25");
    }

    #[tokio::test]
    async fn a_full_supernet_answers_409_prefix_full() {
        let api = Api::new();
        let parent = api
            .prefix(&json!({ "cidr": "192.0.2.0/24", "role": "supernet" }))
            .await;
        let path = format!(
            "/prefixes/{}/next-free-prefix",
            parent["id"].as_str().expect("id")
        );
        assert_eq!(
            api.post(&path, &json!({ "length": 25 })).await.item()["cidr"],
            "192.0.2.0/25"
        );
        assert_eq!(
            api.post(&path, &json!({ "length": 25 })).await.item()["cidr"],
            "192.0.2.128/25"
        );
        let full = api.post(&path, &json!({ "length": 25 })).await;
        full.assert_problem(409, "ipam.prefix.full");
        assert_eq!(full.body["params"]["cidr"], "192.0.2.0/24");
        assert_eq!(full.body["params"]["length"], "25");
        // A smaller block does not fit either: both halves are taken.
        api.post(&path, &json!({ "length": 26 }))
            .await
            .assert_problem(409, "ipam.prefix.full");
    }

    #[tokio::test]
    async fn next_free_prefix_of_a_network_overlaps() {
        let api = Api::new();
        let network = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let path = format!(
            "/prefixes/{}/next-free-prefix",
            network["id"].as_str().expect("id")
        );
        let reply = api.post(&path, &json!({ "length": 26 })).await;
        reply.assert_problem(409, "ipam.prefix.overlap");
        assert_eq!(reply.body["params"]["cidr"], "192.0.2.0/24");
    }

    #[tokio::test]
    async fn next_free_prefix_validates_the_length_and_the_body() {
        let api = Api::new();
        let parent = api
            .prefix(&json!({ "cidr": "192.0.2.0/24", "role": "supernet" }))
            .await;
        let id = parent["id"].as_str().expect("id");
        let path = format!("/prefixes/{id}/next-free-prefix");
        for length in [24, 16, 33, 255] {
            let reply = api.post(&path, &json!({ "length": length })).await;
            reply.assert_problem(400, "ipam.validation");
            assert_eq!(reply.body["errors"][0]["field"], "length", "{length}");
        }
        for body in [
            r"{}",
            r#"{"length": "big"}"#,
            r#"{"length": 26, "colour": 1}"#,
            "",
        ] {
            let reply = api.post_raw(&path, body).await;
            assert!(reply.status.is_client_error(), "{body}: {}", reply.status);
        }
        api.post(
            &format!("/prefixes/{}/next-free-prefix", unknown_id()),
            &json!({ "length": 26 }),
        )
        .await
        .assert_problem(404, "ipam.not_found");
        assert_eq!(api.get("/prefixes").await.items().len(), 1);
    }

    #[tokio::test]
    async fn next_free_prefix_inside_an_ipv6_supernet() {
        let api = Api::new();
        let parent = api
            .prefix(&json!({ "cidr": "2001:db8::/32", "role": "supernet" }))
            .await;
        let path = format!(
            "/prefixes/{}/next-free-prefix",
            parent["id"].as_str().expect("id")
        );
        let first = api.post(&path, &json!({ "length": 48 })).await;
        first.assert_status(StatusCode::CREATED);
        assert_eq!(first.item()["cidr"], "2001:db8::/48");
        assert_eq!(first.body["warnings"], json!([]));
        let second = api.post(&path, &json!({ "length": 48 })).await;
        assert_eq!(second.item()["cidr"], "2001:db8:1::/48");
        let off_boundary = api.post(&path, &json!({ "length": 50 })).await;
        off_boundary.assert_problem(409, "ipam.plan.unacknowledged");
        let accepted = api
            .post(
                &format!("{path}?acknowledge=ipam.prefix.nibble_boundary"),
                &json!({ "length": 50 }),
            )
            .await;
        accepted.assert_status(StatusCode::CREATED);
        assert_eq!(accepted.item()["cidr"], "2001:db8:2::/50");
    }

    // ----- the addresses of a prefix ---------------------------------------------------

    #[tokio::test]
    async fn addresses_of_a_prefix_list_the_address_objects() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id");
        let empty = api.get(&format!("/prefixes/{id}/addresses")).await;
        empty.assert_status(StatusCode::OK);
        assert_eq!(empty.body["items"], json!([]));
        assert_eq!(empty.body["next_cursor"], Value::Null);
        for _ in 0..3 {
            api.next_ip(id).await;
        }
        let reply = api.get(&format!("/prefixes/{id}/addresses")).await;
        assert_eq!(reply.items().len(), 3);
        for (index, item) in reply.items().iter().enumerate() {
            assert_eq!(item["type"], "address");
            assert_eq!(item["data"]["ip"], format!("192.0.2.{}", index + 1));
            assert_eq!(item["data"]["prefix"], id);
        }
        assert!(reply.revision() > 0);
        let explicit = api
            .get(&format!("/prefixes/{id}/addresses?include_free=false"))
            .await;
        assert_eq!(explicit.items().len(), 3);
    }

    #[tokio::test]
    async fn addresses_with_free_gaps_show_sizes_as_strings() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/29" })).await;
        let id = prefix["id"].as_str().expect("id");
        let path = format!("/prefixes/{id}/addresses?include_free=true");
        let whole = api.get(&path).await;
        assert_eq!(whole.items().len(), 1);
        assert_eq!(
            whole.items()[0],
            json!({ "type": "free", "data": { "first": "192.0.2.1", "last": "192.0.2.6", "size": "6" } })
        );
        api.next_ip(id).await;
        api.next_ip(id).await;
        api.address("192.0.2.5").await;
        let reply = api.get(&path).await;
        reply.assert_status(StatusCode::OK);
        let summary: Vec<String> = reply
            .items()
            .iter()
            .map(|item| match item["type"].as_str().expect("type") {
                "address" => format!("address {}", item["data"]["ip"].as_str().expect("ip")),
                _ => format!(
                    "free {}-{} {}",
                    item["data"]["first"].as_str().expect("first"),
                    item["data"]["last"].as_str().expect("last"),
                    item["data"]["size"].as_str().expect("size is a string")
                ),
            })
            .collect();
        assert_eq!(
            summary,
            [
                "address 192.0.2.1",
                "address 192.0.2.2",
                "free 192.0.2.3-192.0.2.4 2",
                "address 192.0.2.5",
                "free 192.0.2.6-192.0.2.6 1"
            ]
        );
        let without = api.get(&format!("/prefixes/{id}/addresses")).await;
        assert_eq!(without.items().len(), 3);
    }

    #[tokio::test]
    async fn addresses_of_a_prefix_expand_interface_and_host() {
        use tenko_core::{HostId, InterfaceId, ipam::AssignmentMode};
        use tenko_ipam::command::{HostInput, InterfaceInput};

        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/29" })).await;
        let id = prefix["id"].as_str().expect("id");
        let (host, interface) = (HostId::generate(), InterfaceId::generate());
        api.execute(IpamCommand::CreateHost(HostInput {
            id: Some(host),
            tenant: None,
            name: "host-01.example.test".parse().expect("name"),
            mode: Some(AssignmentMode::Reserved),
            lock: None,
            site: None,
            interfaces: vec![InterfaceInput {
                id: Some(interface),
                host: None,
                name: "eth0".to_owned(),
                mac: Some("00-00-5E-00-53-02".parse().expect("mac")),
                duid: None,
                client_id: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            }],
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }))
        .await;
        api.execute(IpamCommand::CreateAddress(AddressInput {
            id: None,
            vrf: None,
            ip: "192.0.2.2".parse().expect("ip"),
            status: None,
            interface: Some(interface),
            dns_name: None,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }))
        .await;
        api.address("192.0.2.5").await;

        let path = format!("/prefixes/{id}/addresses?include_free=true");
        let plain = api.get(&path).await;
        plain.assert_status(StatusCode::OK);
        for item in plain.items() {
            assert!(item["data"].get("interface_detail").is_none(), "{item}");
            assert!(item["data"].get("host").is_none(), "{item}");
        }
        let expanded = api.get(&format!("{path}&expand=host")).await;
        expanded.assert_status(StatusCode::OK);
        let types = |reply: &Reply| reply.texts("type");
        assert_eq!(
            types(&expanded),
            ["free", "address", "free", "address", "free"]
        );
        assert_eq!(types(&expanded), types(&plain));
        let bound = &expanded.items()[1]["data"];
        assert_eq!(bound["ip"], "192.0.2.2");
        assert_eq!(bound["interface"], interface.to_string());
        assert_eq!(bound["interface_detail"]["id"], interface.to_string());
        assert_eq!(bound["interface_detail"]["name"], "eth0");
        assert!(bound["interface_detail"]["mac"].is_string(), "{bound}");
        assert!(bound["interface_detail"].get("duid").is_none(), "{bound}");
        assert_eq!(
            bound["host"],
            json!({
                "id": host.to_string(),
                "name": "host-01.example.test",
                "mode": "reserved",
                "lock": false,
            })
        );
        let unbound = &expanded.items()[3]["data"];
        assert_eq!(unbound["ip"], "192.0.2.5");
        assert!(unbound.get("interface_detail").is_none(), "{unbound}");
        assert!(unbound.get("host").is_none(), "{unbound}");
        for index in [0, 2, 4] {
            assert_eq!(expanded.items()[index], plain.items()[index], "free gaps");
        }

        // A cursor of a plain page continues an expanded one, and other values are refused.
        let first = api
            .get(&format!(
                "/prefixes/{id}/addresses?include_free=true&limit=1"
            ))
            .await;
        let cursor = first.body["next_cursor"].as_str().expect("cursor");
        let next = api
            .get(&format!(
                "/prefixes/{id}/addresses?include_free=true&limit=1&expand=host&cursor={cursor}"
            ))
            .await;
        next.assert_status(StatusCode::OK);
        assert_eq!(next.items()[0]["data"]["host"]["id"], host.to_string());
        api.get(&format!("/prefixes/{id}/addresses?expand=hosts"))
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn address_pages_continue_across_the_boundary_of_a_gap() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/29" })).await;
        let id = prefix["id"].as_str().expect("id");
        api.next_ip(id).await;
        api.next_ip(id).await;
        api.address("192.0.2.5").await;
        let base = format!("/prefixes/{id}/addresses?include_free=true&limit=2");
        let first = api.get(&base).await;
        assert_eq!(first.items().len(), 2);
        assert_eq!(first.items()[1]["data"]["ip"], "192.0.2.2");
        let cursor = first.body["next_cursor"]
            .as_str()
            .expect("cursor")
            .to_owned();
        assert_ne!(cursor, "");
        let second = api.get(&format!("{base}&cursor={cursor}")).await;
        second.assert_status(StatusCode::OK);
        assert_eq!(second.items()[0]["type"], "free");
        assert_eq!(second.items()[0]["data"]["first"], "192.0.2.3");
        assert_eq!(second.items()[0]["data"]["size"], "2");
        assert_eq!(second.items()[1]["data"]["ip"], "192.0.2.5");
        let cursor = second.body["next_cursor"]
            .as_str()
            .expect("cursor")
            .to_owned();
        let third = api.get(&format!("{base}&cursor={cursor}")).await;
        assert_eq!(third.items().len(), 1);
        assert_eq!(third.items()[0]["data"]["first"], "192.0.2.6");
        assert_eq!(third.body["next_cursor"], Value::Null);
    }

    #[tokio::test]
    async fn address_cursors_are_bound_to_the_prefix_and_the_query() {
        let api = Api::new();
        let first = api.prefix(&json!({ "cidr": "192.0.2.0/29" })).await;
        let second = api.prefix(&json!({ "cidr": "198.51.100.0/29" })).await;
        let id = first["id"].as_str().expect("id");
        let other = second["id"].as_str().expect("id");
        api.next_ip(id).await;
        api.next_ip(id).await;
        let page = api
            .get(&format!(
                "/prefixes/{id}/addresses?include_free=true&limit=1"
            ))
            .await;
        let cursor = page.body["next_cursor"]
            .as_str()
            .expect("cursor")
            .to_owned();
        api.get(&format!(
            "/prefixes/{id}/addresses?include_free=false&limit=1&cursor={cursor}"
        ))
        .await
        .assert_problem(400, "sys.invalid_cursor");
        api.get(&format!(
            "/prefixes/{other}/addresses?include_free=true&limit=1&cursor={cursor}"
        ))
        .await
        .assert_problem(400, "sys.invalid_cursor");
        api.get(&format!(
            "/prefixes/{id}/addresses?include_free=true&limit=1&cursor=0102"
        ))
        .await
        .assert_problem(400, "sys.invalid_cursor");
        api.get(&format!("/prefixes/{id}/addresses?limit=0"))
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn address_list_validates_parameters_and_the_prefix() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id");
        api.get(&format!("/prefixes/{id}/addresses?include_free=sometimes"))
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get(&format!("/prefixes/{id}/addresses?status=active"))
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get(&format!("/prefixes/{}/addresses", unknown_id()))
            .await
            .assert_problem(404, "ipam.not_found");
    }

    #[tokio::test]
    async fn ipv6_free_gaps_use_decimal_strings_beyond_the_json_integer_range() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "2001:db8::/64" })).await;
        let id = prefix["id"].as_str().expect("id");
        let reply = api
            .get(&format!("/prefixes/{id}/addresses?include_free=true"))
            .await;
        reply.assert_status(StatusCode::OK);
        assert_eq!(reply.items().len(), 1);
        let gap = &reply.items()[0]["data"];
        assert_eq!(gap["first"], "2001:db8::1");
        assert_eq!(gap["size"], "18446744073709551615");
        let tree = api.get("/prefixes/tree").await;
        assert_eq!(
            tree.nodes()[0]["utilization"]["capacity"],
            "18446744073709551615"
        );
    }

    // ----- availability and authorization ---------------------------------------------------

    #[tokio::test]
    async fn without_the_service_every_endpoint_answers_503() {
        let router = bare_router(None);
        let id = unknown_id();
        let body = json!({ "cidr": "192.0.2.0/24" }).to_string();
        let requests = [
            ("GET", "/prefixes".to_owned(), None),
            ("POST", "/prefixes".to_owned(), Some(body.clone())),
            ("GET", "/prefixes/tree".to_owned(), None),
            ("GET", format!("/prefixes/{id}"), None),
            ("PATCH", format!("/prefixes/{id}"), Some("{}".to_owned())),
            ("DELETE", format!("/prefixes/{id}"), None),
            ("POST", format!("/prefixes/{id}/next-free-address"), None),
            (
                "POST",
                format!("/prefixes/{id}/next-free-prefix"),
                Some(r#"{"length":26}"#.to_owned()),
            ),
            ("GET", format!("/prefixes/{id}/addresses"), None),
            ("GET", format!("/prefixes/{id}/ranges"), None),
            ("GET", format!("/ranges/{id}"), None),
            ("DELETE", format!("/ranges/{id}"), None),
        ];
        for (method, path, body) in requests {
            let reply = call(&router, method, &path, &[], body).await;
            reply.assert_problem(503, "ipam.unavailable");
        }
    }

    /// An authorizer that allows the listed actions and records every question.
    struct Policy {
        allowed: Vec<Action>,
        asked: Mutex<Vec<(Action, ObjectRef)>>,
    }

    impl Policy {
        fn new(allowed: &[Action]) -> Arc<Self> {
            Arc::new(Self {
                allowed: allowed.to_vec(),
                asked: Mutex::new(Vec::new()),
            })
        }

        fn asked(&self) -> Vec<(Action, ObjectRef)> {
            self.asked.lock().expect("lock").clone()
        }
    }

    impl Authorizer for Policy {
        fn check(
            &self,
            _principal: &Principal,
            action: Action,
            object: &ObjectRef,
        ) -> Result<(), Denied> {
            self.asked.lock().expect("lock").push((action, *object));
            if self.allowed.contains(&action) {
                Ok(())
            } else {
                Err(Denied {
                    action,
                    object: *object,
                    reason: DenyReason::MissingPermission,
                })
            }
        }

        fn scope(&self, _principal: &Principal, action: Action, _kind: ObjectKind) -> ScopeFilter {
            if self.allowed.contains(&action) {
                ScopeFilter::All
            } else {
                ScopeFilter::Nothing
            }
        }
    }

    #[tokio::test]
    async fn an_authorizer_that_denies_everything_gives_403_and_empty_lists() {
        let ipam = service();
        let admin = Api::with(Arc::clone(&ipam), None);
        let prefix = admin
            .prefix(&json!({ "cidr": "192.0.2.0/24", "role": "supernet" }))
            .await;
        let id = prefix["id"].as_str().expect("id").to_owned();
        let inner = admin
            .prefix(&json!({ "cidr": "192.0.2.0/25", "role": "network" }))
            .await;
        let range = admin
            .range(
                inner["id"].as_str().expect("id"),
                "192.0.2.10",
                "192.0.2.19",
                "reserved",
            )
            .await;
        let range_id = range["id"].as_str().expect("id").to_owned();

        let denied = Api::with(ipam, Some(Policy::new(&[])));
        let list = denied.get("/prefixes").await;
        list.assert_status(StatusCode::OK);
        assert_eq!(list.body["items"], json!([]));
        assert_eq!(list.body["next_cursor"], Value::Null);
        assert!(list.body["revision"].is_u64());
        let tree = denied.get("/prefixes/tree").await;
        tree.assert_status(StatusCode::OK);
        assert_eq!(tree.body["nodes"], json!([]));
        assert_eq!(tree.body["vrf"], Value::Null);
        let ranges = denied
            .get(&format!(
                "/prefixes/{}/ranges",
                inner["id"].as_str().expect("id")
            ))
            .await;
        assert_eq!(ranges.status.as_u16(), 403, "{}", ranges.body);

        let body = json!({ "cidr": "198.51.100.0/24" });
        let requests = [
            ("GET", format!("/prefixes/{id}"), None),
            ("POST", "/prefixes".to_owned(), Some(body.to_string())),
            ("PATCH", format!("/prefixes/{id}"), Some("{}".to_owned())),
            ("DELETE", format!("/prefixes/{id}"), None),
            ("POST", format!("/prefixes/{id}/next-free-address"), None),
            (
                "POST",
                format!("/prefixes/{id}/next-free-prefix"),
                Some(r#"{"length":26}"#.to_owned()),
            ),
            ("GET", format!("/prefixes/{id}/addresses"), None),
            ("GET", format!("/prefixes/{id}/ranges"), None),
            (
                "POST",
                format!("/prefixes/{id}/ranges"),
                Some(
                    json!({ "first": "192.0.2.1", "last": "192.0.2.2", "role": "reserved" })
                        .to_string(),
                ),
            ),
            ("GET", format!("/ranges/{range_id}"), None),
            (
                "PATCH",
                format!("/ranges/{range_id}"),
                Some("{}".to_owned()),
            ),
            ("DELETE", format!("/ranges/{range_id}"), None),
        ];
        for (method, path, body) in requests {
            let reply = call(&denied.router, method, &path, &[], body).await;
            assert_eq!(
                reply.status,
                StatusCode::FORBIDDEN,
                "{method} {path}: {}",
                reply.body
            );
            assert_eq!(reply.content_type(), PROBLEM_JSON, "{method} {path}");
        }
        // Nothing changed behind the denied requests.
        assert_eq!(admin.get("/prefixes").await.items().len(), 2);
        assert_eq!(
            admin.get(&format!("/ranges/{range_id}")).await.body["meta"]["deleted"],
            Value::Null
        );
    }

    #[tokio::test]
    async fn reads_without_write_permission_work_and_writes_are_refused() {
        let ipam = service();
        let admin = Api::with(Arc::clone(&ipam), None);
        let prefix = admin.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id").to_owned();
        let reader = Api::with(ipam, Some(Policy::new(&[Action::Read])));
        reader.get("/prefixes").await.assert_status(StatusCode::OK);
        assert_eq!(reader.get("/prefixes").await.items().len(), 1);
        reader
            .get(&format!("/prefixes/{id}"))
            .await
            .assert_status(StatusCode::OK);
        assert_eq!(reader.get("/prefixes/tree").await.nodes().len(), 1);
        reader
            .get(&format!("/prefixes/{id}/addresses?include_free=true"))
            .await
            .assert_status(StatusCode::OK);
        reader
            .post("/prefixes", &json!({ "cidr": "198.51.100.0/24" }))
            .await
            .assert_status(StatusCode::FORBIDDEN);
        reader
            .patch(
                &format!("/prefixes/{id}"),
                &json!({ "description": "x" }),
                None,
            )
            .await
            .assert_status(StatusCode::FORBIDDEN);
        reader
            .delete(&format!("/prefixes/{id}"), None)
            .await
            .assert_status(StatusCode::FORBIDDEN);
        assert_eq!(admin.get("/prefixes").await.items().len(), 1);
    }

    #[tokio::test]
    async fn addresses_stay_hidden_from_a_principal_that_may_not_read_them() {
        // A principal that may read prefixes but no addresses sees a page without items.
        struct NoAddresses;
        impl Authorizer for NoAddresses {
            fn check(&self, _: &Principal, _: Action, _: &ObjectRef) -> Result<(), Denied> {
                Ok(())
            }

            fn scope(&self, _: &Principal, _: Action, kind: ObjectKind) -> ScopeFilter {
                if kind == ObjectKind::Address {
                    ScopeFilter::Nothing
                } else {
                    ScopeFilter::All
                }
            }
        }
        let ipam = service();
        let admin = Api::with(Arc::clone(&ipam), None);
        let prefix = admin.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id").to_owned();
        admin.next_ip(&id).await;
        let limited = Api::with(ipam, Some(Arc::new(NoAddresses)));
        let reply = limited
            .get(&format!("/prefixes/{id}/addresses?include_free=true"))
            .await;
        reply.assert_status(StatusCode::OK);
        assert_eq!(reply.body["items"], json!([]));
        assert!(reply.body["revision"].is_u64());
        limited
            .get(&format!("/prefixes/{}/addresses", unknown_id()))
            .await
            .assert_problem(404, "ipam.not_found");
    }

    #[tokio::test]
    async fn each_endpoint_asks_for_the_action_on_the_right_object() {
        let ipam = service();
        let policy = Policy::new(&[Action::Read, Action::Create, Action::Update, Action::Delete]);
        let api = Api::with(ipam, Some(Arc::clone(&policy) as Arc<dyn Authorizer>));
        let created = api
            .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
            .await;
        created.assert_status(StatusCode::CREATED);
        let id = created.id();
        let prefix_ref = ObjectRef::new(ObjectKind::Prefix, id.parse().expect("uuid"));
        assert_eq!(
            policy.asked(),
            [(Action::Create, ObjectRef::singleton(ObjectKind::Prefix))]
        );
        let ask = |policy: &Policy, from: usize| policy.asked()[from..].to_vec();

        let mark = policy.asked().len();
        api.get(&format!("/prefixes/{id}")).await;
        assert_eq!(ask(&policy, mark), [(Action::Read, prefix_ref)]);

        let mark = policy.asked().len();
        api.patch(
            &format!("/prefixes/{id}"),
            &json!({ "description": "x" }),
            None,
        )
        .await;
        assert_eq!(ask(&policy, mark), [(Action::Update, prefix_ref)]);

        let mark = policy.asked().len();
        api.post_raw(&format!("/prefixes/{id}/next-free-address"), "")
            .await;
        assert_eq!(
            ask(&policy, mark),
            [(Action::Create, ObjectRef::singleton(ObjectKind::Address))]
        );

        let mark = policy.asked().len();
        let range = api
            .post(
                &format!("/prefixes/{id}/ranges"),
                &json!({ "first": "192.0.2.100", "last": "192.0.2.110", "role": "reserved" }),
            )
            .await;
        assert_eq!(
            ask(&policy, mark),
            [(Action::Create, ObjectRef::singleton(ObjectKind::Range))]
        );
        let range_ref = ObjectRef::new(ObjectKind::Range, range.id().parse().expect("uuid"));

        let mark = policy.asked().len();
        api.delete(&format!("/ranges/{}", range.id()), None).await;
        assert_eq!(ask(&policy, mark), [(Action::Delete, range_ref)]);

        let mark = policy.asked().len();
        api.delete(&format!("/prefixes/{id}?cascade=true"), None)
            .await;
        assert_eq!(ask(&policy, mark), [(Action::Delete, prefix_ref)]);
    }

    // ----- allocation under load and replays -----------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_next_free_calls_never_hand_out_the_same_address() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id").to_owned();
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let router = api.router.clone();
                let path = format!("/prefixes/{id}/next-free-address");
                tokio::spawn(async move { call(&router, "POST", &path, &[], None).await })
            })
            .collect();
        let mut ips = Vec::new();
        for task in tasks {
            let reply = task.await.expect("task");
            reply.assert_status(StatusCode::CREATED);
            ips.push(reply.item()["ip"].as_str().expect("ip").to_owned());
        }
        ips.sort_unstable_by_key(|ip| ip.rsplit('.').next().and_then(|n| n.parse::<u8>().ok()));
        let expected: Vec<String> = (1..=8).map(|n| format!("192.0.2.{n}")).collect();
        assert_eq!(ips, expected);
        assert_eq!(
            api.get(&format!("/prefixes/{id}/addresses"))
                .await
                .items()
                .len(),
            8
        );
    }

    #[tokio::test]
    async fn next_free_address_with_an_idempotency_key_allocates_once() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "192.0.2.0/24" })).await;
        let id = prefix["id"].as_str().expect("id").to_owned();
        let path = format!("/prefixes/{id}/next-free-address");
        let key = [("idempotency-key", "allocate-0001")];
        let first = call(&api.router, "POST", &path, &key, None).await;
        first.assert_status(StatusCode::CREATED);
        let second = call(&api.router, "POST", &path, &key, None).await;
        second.assert_status(StatusCode::OK);
        assert_eq!(second.body["replayed"], true);
        assert_eq!(second.id(), first.id());
        assert_eq!(second.item()["ip"], "192.0.2.1");
        assert_eq!(api.next_ip(&id).await, "192.0.2.2");
        assert_eq!(
            api.get(&format!("/prefixes/{id}/addresses"))
                .await
                .items()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn next_free_address_works_in_an_ipv6_network() {
        let api = Api::new();
        let prefix = api.prefix(&json!({ "cidr": "2001:db8::/64" })).await;
        let id = prefix["id"].as_str().expect("id");
        assert_eq!(api.next_ip(id).await, "2001:db8::1");
        assert_eq!(api.next_ip(id).await, "2001:db8::2");
        let highest = api
            .post(
                &format!("/prefixes/{id}/next-free-address"),
                &json!({ "policy": "highest" }),
            )
            .await;
        assert_eq!(highest.item()["ip"], "2001:db8::ffff:ffff:ffff:ffff");
    }

    #[tokio::test]
    async fn patch_refuses_a_status_change_that_the_lifecycle_does_not_allow() {
        let api = Api::new();
        let created = api
            .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
            .await;
        let path = format!("/prefixes/{}", created.id());
        let refused = api
            .patch(&path, &json!({ "status": "planned" }), None)
            .await;
        refused.assert_problem(409, "ipam.status.transition");
        assert_eq!(refused.body["params"]["from"], "active");
        assert_eq!(refused.body["params"]["to"], "planned");
        api.patch(&path, &json!({ "status": "deprecated" }), None)
            .await
            .assert_status(StatusCode::OK);
        assert_eq!(api.get(&path).await.body["status"], "deprecated");
    }

    // ----- the OpenAPI document --------------------------------------------------------------

    #[test]
    fn the_openapi_document_describes_every_operation_of_the_area() {
        let (_, document) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let json = serde_json::to_value(&document).expect("document");
        let operations = [
            ("get", "/api/v1/prefixes", "list_prefixes"),
            ("post", "/api/v1/prefixes", "create_prefix"),
            ("get", "/api/v1/prefixes/tree", "get_prefix_tree"),
            ("get", "/api/v1/prefixes/{id}", "get_prefix"),
            ("patch", "/api/v1/prefixes/{id}", "update_prefix"),
            ("delete", "/api/v1/prefixes/{id}", "delete_prefix"),
            (
                "post",
                "/api/v1/prefixes/{id}/next-free-address",
                "next_free_address",
            ),
            (
                "post",
                "/api/v1/prefixes/{id}/next-free-prefix",
                "next_free_prefix",
            ),
            (
                "get",
                "/api/v1/prefixes/{id}/addresses",
                "list_prefix_addresses",
            ),
            ("get", "/api/v1/prefixes/{id}/ranges", "list_prefix_ranges"),
            ("post", "/api/v1/prefixes/{id}/ranges", "create_range"),
            ("get", "/api/v1/ranges/{id}", "get_range"),
            ("patch", "/api/v1/ranges/{id}", "update_range"),
            ("delete", "/api/v1/ranges/{id}", "delete_range"),
        ];
        for (method, path, operation_id) in operations {
            let operation = &json["paths"][path][method];
            assert_eq!(operation["operationId"], operation_id, "{method} {path}");
            assert_eq!(operation["tags"], json!(["prefixes"]), "{method} {path}");
            assert!(operation["summary"].is_string(), "{method} {path}");
            assert!(operation["responses"]["503"].is_object(), "{method} {path}");
        }
        let schemas = &json["components"]["schemas"];
        for name in [
            "TreeResponse",
            "NextFreeAddress",
            "NextFreePrefix",
            "NewRange",
        ] {
            assert!(schemas[name].is_object(), "{name}");
        }
        let created = &json["paths"]["/api/v1/prefixes"]["post"]["responses"];
        assert!(created["201"].is_object() && created["409"].is_object());
        let parameters = &json["paths"]["/api/v1/prefixes"]["get"]["parameters"];
        let names: Vec<&str> = parameters
            .as_array()
            .expect("parameters")
            .iter()
            .filter_map(|parameter| parameter["name"].as_str())
            .collect();
        for expected in [
            "limit", "cursor", "at_least", "status", "vrf", "within", "site", "role", "tag", "q",
            "sort", "deleted",
        ] {
            assert!(names.contains(&expected), "{expected}: {names:?}");
        }
    }
}
