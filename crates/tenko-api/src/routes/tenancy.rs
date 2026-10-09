//! Tenants, VRFs, sites and VLANs.
//!
//! Area: tenancy. Owner: WP1.4. Requirements: IPAM-01, IPAM-03, IPAM-04.
//!
//! Create, read, update and soft-delete for the four containers of the IPAM model. History,
//! restore and bulk changes of these collections are in [`super::common`], which also
//! documents the conventions every endpoint here follows: the IPAM service as a request
//! extension (503 `ipam.unavailable` without it), the list parameters, `ETag` and `If-Match`,
//! `Idempotency-Key`, `dry_run` and `acknowledge`, and the authorization checks.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /tenants` | 200 page of tenants | 400 `sys.invalid_query`, `sys.invalid_cursor` |
//! | `POST /tenants` | 201 write response, 200 for a dry run or a replay | 400, 403, 409 `ipam.name_taken`, 422 `ipam.idempotency_mismatch` |
//! | `GET /tenants/{id}` | 200 tenant with `ETag` | 404 `ipam.not_found` |
//! | `PATCH /tenants/{id}` | 200 write response | 404, 409 `ipam.name_taken`, 412 `ipam.revision_mismatch` |
//! | `DELETE /tenants/{id}` | 200 write response with the deleted tenant | 404, 409 `ipam.in_use`, 412 |
//!
//! `/vrfs`, `/sites` and `/vlans` have the same five endpoints. Their lists take these
//! filters besides `tag`, `q`, `sort` and `deleted`:
//!
//! | Collection | Filters | Sort fields | Domain errors |
//! |---|---|---|---|
//! | `/vrfs` | `tenant` | `name` | `ipam.name_taken` (per tenant), `ipam.reference_missing` (tenant), `ipam.in_use` (prefixes) |
//! | `/sites` | `site` (the parent) | `name` | `ipam.name_taken`, `ipam.site.cycle`, `ipam.reference_missing` (parent), `ipam.in_use` (children, VLANs, prefixes, hosts) |
//! | `/vlans` | `status`, `site` | `vid`, `name` | `ipam.vlan.duplicate` (per site), `ipam.status.transition`, `ipam.reference_missing` (site), `ipam.in_use` (prefixes) |
//!
//! # Writes
//!
//! A write is one [`IpamCommand`] planned and applied by the IPAM service. The answer is a
//! `WriteResponse`: the object after the change, the committed `revision`, the inline
//! `job_id`, `dry_run`, `replayed`, the plan warnings and, on a dry run, the plan (`plan.summary`
//! says what would change). A DELETE is a soft delete (IPAM-09): the answer carries the object
//! with `meta.deleted` set, and `GET /{collection}/{id}` still shows it. The tenancy
//! containers take no `cascade`: what still uses them must be removed or moved first
//! (409 `ipam.in_use`).
//!
//! A VRF created without a tenant lives in the tenant `default`, which the first such write
//! creates.
//!
//! # Errors of the request itself
//!
//! The `{id}` segment is read with `IpamPath` and the body with `IpamJson` (both from
//! [`super::common`]), which answer problem details where axum's own extractors answer
//! plain text. A segment that is not an identifier (a UUID) is 400 `sys.invalid_request` with
//! the parameter `part` set to `path`. A body that is not valid JSON, lacks a member, has a
//! member of the wrong type or an invalid value (an unknown status, a malformed MAC address)
//! is 400 `sys.invalid_request` with `part` set to `body` and the reason in `detail`, and a
//! body with another media type is 415. What parses but breaks a rule of the domain (a VLAN
//! id outside 1 to 4094, a blank name) is 400 `ipam.validation` with the field in `errors`.

use axum::{Json, extract::State, http::HeaderMap, response::Response};
use tenko_core::{
    Action, ObjectKind, ObjectRef, SiteId, TenantId, VlanId, VrfId,
    ipam::{Site, Tenant, Vlan, Vrf},
};
use tenko_ipam::{
    IpamCommand,
    command::{
        SiteInput, SitePatch, TenantInput, TenantPatch, UpdateSite, UpdateTenant, UpdateVlan,
        UpdateVrf, VlanInput, VlanPatch, VrfInput, VrfPatch,
    },
};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::common::{
    Filter, IdempotencyKeyHeader, IfMatch, Ipam, IpamJson, IpamPath, ReadParams, WriteParams,
    WriteResponse, authorize, get_one, if_match, list_args, list_collection, new_of, write_args,
    write_one,
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
        .routes(routes!(list_tenants, create_tenant))
        .routes(routes!(get_tenant, update_tenant, delete_tenant))
        .routes(routes!(list_vrfs, create_vrf))
        .routes(routes!(get_vrf, update_vrf, delete_vrf))
        .routes(routes!(list_sites, create_site))
        .routes(routes!(get_site, update_site, delete_site))
        .routes(routes!(list_vlans, create_vlan))
        .routes(routes!(get_vlan, update_vlan, delete_vlan))
}

// ===== tenants ====================================================================

/// Lists tenants, by name unless `sort` says otherwise.
#[utoipa::path(
    get,
    path = "/tenants",
    tag = "tenancy",
    operation_id = "list_tenants",
    summary = "List tenants",
    params(
        PageParams,
        ("tag" = Option<String>, Query, description = "Only objects that carry every one of these tags. Repeat the parameter or separate the tags with commas."),
        ("q" = Option<String>, Query, description = "Case-insensitive text search over the name, the description and the tags."),
        ("sort" = Option<String>, Query, description = "Sort order: comma-separated fields, `-` in front for descending, for example `-updated,name`. Fields: `name` (the default), `created`, `updated`."),
        ("deleted" = Option<String>, Query, description = "Deleted tenants: `exclude` (the default), `include` or `only` (the restore view).")
    ),
    responses(
        (status = 200, description = "A page of tenants", body = Page<Tenant>),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_tenants(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<Page<Tenant>>, ApiError> {
    let args = list_args::<Tenant>(
        &filters,
        "ipam.tenants",
        &[Filter::Tag, Filter::Q, Filter::Sort, Filter::Deleted],
    )?;
    list_collection::<Tenant>(&app, &cx, &ipam, args).await
}

/// Creates a tenant. The name is unique, ignoring case.
#[utoipa::path(
    post,
    path = "/tenants",
    tag = "tenancy",
    operation_id = "create_tenant",
    summary = "Create a tenant",
    params(WriteParams, IdempotencyKeyHeader),
    request_body = TenantInput,
    responses(
        (status = 201, description = "The new tenant, with `ETag`", body = WriteResponse<Tenant>),
        (status = 200, description = "The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true)", body = WriteResponse<Tenant>),
        (status = 400, description = "Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The name is taken, or the identifier is in use (`ipam.name_taken`, `ipam.id_taken`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_tenant(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
    IpamJson(input): IpamJson<TenantInput>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    authorize(&app, &cx, Action::Create, new_of(ObjectKind::Tenant))?;
    let command = IpamCommand::CreateTenant(input);
    write_one::<Tenant>(&ipam, &cx, vec![command], &args, true).await
}

/// Shows one tenant with its `ETag`. A deleted tenant is shown too: it carries `meta.deleted`.
#[utoipa::path(
    get,
    path = "/tenants/{id}",
    tag = "tenancy",
    operation_id = "get_tenant",
    summary = "Get one tenant",
    params(("id" = String, Path, description = "Tenant identifier"), ReadParams),
    responses(
        (status = 200, description = "The tenant, with `ETag`", body = Tenant),
        (status = 400, description = "Invalid parameter (`sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such tenant (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_tenant(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<TenantId>,
    filters: Filters,
) -> Result<Response, ApiError> {
    get_one::<Tenant>(&app, &cx, &ipam, id, &filters).await
}

/// Changes a tenant: the name, the tags, the custom fields and the description (merge patch: a missing field stays, `null` clears an optional one).
#[utoipa::path(
    patch,
    path = "/tenants/{id}",
    tag = "tenancy",
    operation_id = "update_tenant",
    summary = "Update a tenant",
    params(("id" = String, Path, description = "Tenant identifier"), WriteParams, IfMatch),
    request_body = TenantPatch,
    responses(
        (status = 200, description = "The changed tenant, with `ETag`, or the plan of a dry run", body = WriteResponse<Tenant>),
        (status = 400, description = "Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`), or `If-Match` is malformed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such tenant (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The name is taken, or the tenant is deleted (`ipam.name_taken`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_tenant(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<TenantId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(patch): IpamJson<TenantPatch>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Update, id.into())?;
    let command = IpamCommand::UpdateTenant(UpdateTenant {
        id,
        expected,
        patch,
    });
    write_one::<Tenant>(&ipam, &cx, vec![command], &args, false).await
}

/// Soft-deletes a tenant that no live VRF or host belongs to. The answer carries the deleted tenant.
#[utoipa::path(
    delete,
    path = "/tenants/{id}",
    tag = "tenancy",
    operation_id = "delete_tenant",
    summary = "Delete a tenant",
    params(("id" = String, Path, description = "Tenant identifier"), WriteParams, IfMatch),
    responses(
        (status = 200, description = "The deleted tenant (`meta.deleted` is set), or the plan of a dry run", body = WriteResponse<Tenant>),
        (status = 400, description = "Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such tenant (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Live VRFs or hosts belong to the tenant, or it is deleted already (`ipam.in_use`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_tenant(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<TenantId>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    let object: ObjectRef = id.into();
    authorize(&app, &cx, Action::Delete, object)?;
    let command = IpamCommand::Delete {
        object,
        expected,
        cascade: false,
    };
    write_one::<Tenant>(&ipam, &cx, vec![command], &args, false).await
}

// ===== VRFs ====================================================================

/// Lists VRFs, by name unless `sort` says otherwise.
#[utoipa::path(
    get,
    path = "/vrfs",
    tag = "tenancy",
    operation_id = "list_vrfs",
    summary = "List VRFs",
    params(
        PageParams,
        ("tenant" = Option<String>, Query, description = "Only VRFs of this tenant (identifier)."),
        ("tag" = Option<String>, Query, description = "Only objects that carry every one of these tags. Repeat the parameter or separate the tags with commas."),
        ("q" = Option<String>, Query, description = "Case-insensitive text search over the name, the route distinguisher, the description and the tags."),
        ("sort" = Option<String>, Query, description = "Sort order: comma-separated fields, `-` in front for descending, for example `-updated,name`. Fields: `name` (the default), `created`, `updated`."),
        ("deleted" = Option<String>, Query, description = "Deleted VRFs: `exclude` (the default), `include` or `only` (the restore view).")
    ),
    responses(
        (status = 200, description = "A page of VRFs", body = Page<Vrf>),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_vrfs(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<Page<Vrf>>, ApiError> {
    let args = list_args::<Vrf>(
        &filters,
        "ipam.vrfs",
        &[
            Filter::Tenant,
            Filter::Tag,
            Filter::Q,
            Filter::Sort,
            Filter::Deleted,
        ],
    )?;
    list_collection::<Vrf>(&app, &cx, &ipam, args).await
}

/// Creates a VRF in a tenant (the default tenant when `tenant` is left out). The name is unique within the tenant, ignoring case.
#[utoipa::path(
    post,
    path = "/vrfs",
    tag = "tenancy",
    operation_id = "create_vrf",
    summary = "Create a VRF",
    params(WriteParams, IdempotencyKeyHeader),
    request_body = VrfInput,
    responses(
        (status = 201, description = "The new VRF, with `ETag`", body = WriteResponse<Vrf>),
        (status = 200, description = "The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true)", body = WriteResponse<Vrf>),
        (status = 400, description = "Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The name is taken in the tenant, the identifier is in use, or the tenant is missing (`ipam.name_taken`, `ipam.id_taken`, `ipam.reference_missing`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_vrf(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
    IpamJson(input): IpamJson<VrfInput>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    authorize(&app, &cx, Action::Create, new_of(ObjectKind::Vrf))?;
    let command = IpamCommand::CreateVrf(input);
    write_one::<Vrf>(&ipam, &cx, vec![command], &args, true).await
}

/// Shows one VRF with its `ETag`. A deleted VRF is shown too: it carries `meta.deleted`.
#[utoipa::path(
    get,
    path = "/vrfs/{id}",
    tag = "tenancy",
    operation_id = "get_vrf",
    summary = "Get one VRF",
    params(("id" = String, Path, description = "VRF identifier"), ReadParams),
    responses(
        (status = 200, description = "The VRF, with `ETag`", body = Vrf),
        (status = 400, description = "Invalid parameter (`sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such VRF (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_vrf(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<VrfId>,
    filters: Filters,
) -> Result<Response, ApiError> {
    get_one::<Vrf>(&app, &cx, &ipam, id, &filters).await
}

/// Changes a VRF: the name, the route distinguisher, the tags, the custom fields and the description. The tenant cannot change.
#[utoipa::path(
    patch,
    path = "/vrfs/{id}",
    tag = "tenancy",
    operation_id = "update_vrf",
    summary = "Update a VRF",
    params(("id" = String, Path, description = "VRF identifier"), WriteParams, IfMatch),
    request_body = VrfPatch,
    responses(
        (status = 200, description = "The changed VRF, with `ETag`, or the plan of a dry run", body = WriteResponse<Vrf>),
        (status = 400, description = "Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`), or `If-Match` is malformed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such VRF (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The name is taken in the tenant, or the VRF is deleted (`ipam.name_taken`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_vrf(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<VrfId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(patch): IpamJson<VrfPatch>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Update, id.into())?;
    let command = IpamCommand::UpdateVrf(UpdateVrf {
        id,
        expected,
        patch,
    });
    write_one::<Vrf>(&ipam, &cx, vec![command], &args, false).await
}

/// Soft-deletes a VRF that holds no live prefix. The answer carries the deleted VRF.
#[utoipa::path(
    delete,
    path = "/vrfs/{id}",
    tag = "tenancy",
    operation_id = "delete_vrf",
    summary = "Delete a VRF",
    params(("id" = String, Path, description = "VRF identifier"), WriteParams, IfMatch),
    responses(
        (status = 200, description = "The deleted VRF (`meta.deleted` is set), or the plan of a dry run", body = WriteResponse<Vrf>),
        (status = 400, description = "Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such VRF (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Live prefixes belong to the VRF, or it is deleted already (`ipam.in_use`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_vrf(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<VrfId>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    let object: ObjectRef = id.into();
    authorize(&app, &cx, Action::Delete, object)?;
    let command = IpamCommand::Delete {
        object,
        expected,
        cascade: false,
    };
    write_one::<Vrf>(&ipam, &cx, vec![command], &args, false).await
}

// ===== sites ====================================================================

/// Lists sites, by name unless `sort` says otherwise.
#[utoipa::path(
    get,
    path = "/sites",
    tag = "tenancy",
    operation_id = "list_sites",
    summary = "List sites",
    params(
        PageParams,
        ("site" = Option<String>, Query, description = "Only the children of this site (identifier of the parent)."),
        ("tag" = Option<String>, Query, description = "Only objects that carry every one of these tags. Repeat the parameter or separate the tags with commas."),
        ("q" = Option<String>, Query, description = "Case-insensitive text search over the name, the Active Directory site, the description and the tags."),
        ("sort" = Option<String>, Query, description = "Sort order: comma-separated fields, `-` in front for descending, for example `-updated,name`. Fields: `name` (the default), `created`, `updated`."),
        ("deleted" = Option<String>, Query, description = "Deleted sites: `exclude` (the default), `include` or `only` (the restore view).")
    ),
    responses(
        (status = 200, description = "A page of sites", body = Page<Site>),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_sites(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<Page<Site>>, ApiError> {
    let args = list_args::<Site>(
        &filters,
        "ipam.sites",
        &[
            Filter::Site,
            Filter::Tag,
            Filter::Q,
            Filter::Sort,
            Filter::Deleted,
        ],
    )?;
    list_collection::<Site>(&app, &cx, &ipam, args).await
}

/// Creates a site, optionally below a parent site. The name is unique, ignoring case.
#[utoipa::path(
    post,
    path = "/sites",
    tag = "tenancy",
    operation_id = "create_site",
    summary = "Create a site",
    params(WriteParams, IdempotencyKeyHeader),
    request_body = SiteInput,
    responses(
        (status = 201, description = "The new site, with `ETag`", body = WriteResponse<Site>),
        (status = 200, description = "The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true)", body = WriteResponse<Site>),
        (status = 400, description = "Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The name is taken, the identifier is in use, or the parent is missing (`ipam.name_taken`, `ipam.id_taken`, `ipam.reference_missing`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_site(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
    IpamJson(input): IpamJson<SiteInput>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    authorize(&app, &cx, Action::Create, new_of(ObjectKind::Site))?;
    let command = IpamCommand::CreateSite(input);
    write_one::<Site>(&ipam, &cx, vec![command], &args, true).await
}

/// Shows one site with its `ETag`. A deleted site is shown too: it carries `meta.deleted`.
#[utoipa::path(
    get,
    path = "/sites/{id}",
    tag = "tenancy",
    operation_id = "get_site",
    summary = "Get one site",
    params(("id" = String, Path, description = "Site identifier"), ReadParams),
    responses(
        (status = 200, description = "The site, with `ETag`", body = Site),
        (status = 400, description = "Invalid parameter (`sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such site (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_site(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<SiteId>,
    filters: Filters,
) -> Result<Response, ApiError> {
    get_one::<Site>(&app, &cx, &ipam, id, &filters).await
}

/// Changes a site: the name, the parent (`null` makes it a top-level site), the Active Directory site, the tags, the custom fields and the description.
#[utoipa::path(
    patch,
    path = "/sites/{id}",
    tag = "tenancy",
    operation_id = "update_site",
    summary = "Update a site",
    params(("id" = String, Path, description = "Site identifier"), WriteParams, IfMatch),
    request_body = SitePatch,
    responses(
        (status = 200, description = "The changed site, with `ETag`, or the plan of a dry run", body = WriteResponse<Site>),
        (status = 400, description = "Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`), or `If-Match` is malformed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such site (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The name is taken, the parent would make a cycle or is missing, or the site is deleted (`ipam.name_taken`, `ipam.site.cycle`, `ipam.reference_missing`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_site(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<SiteId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(patch): IpamJson<SitePatch>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Update, id.into())?;
    let command = IpamCommand::UpdateSite(UpdateSite {
        id,
        expected,
        patch,
    });
    write_one::<Site>(&ipam, &cx, vec![command], &args, false).await
}

/// Soft-deletes a site that has no live child site, VLAN, prefix or host. The answer carries the deleted site.
#[utoipa::path(
    delete,
    path = "/sites/{id}",
    tag = "tenancy",
    operation_id = "delete_site",
    summary = "Delete a site",
    params(("id" = String, Path, description = "Site identifier"), WriteParams, IfMatch),
    responses(
        (status = 200, description = "The deleted site (`meta.deleted` is set), or the plan of a dry run", body = WriteResponse<Site>),
        (status = 400, description = "Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such site (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Live child sites, VLANs, prefixes or hosts belong to the site, or it is deleted already (`ipam.in_use`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_site(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<SiteId>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    let object: ObjectRef = id.into();
    authorize(&app, &cx, Action::Delete, object)?;
    let command = IpamCommand::Delete {
        object,
        expected,
        cascade: false,
    };
    write_one::<Site>(&ipam, &cx, vec![command], &args, false).await
}

// ===== VLANs ====================================================================

/// Lists VLANs, by VLAN id unless `sort` says otherwise.
#[utoipa::path(
    get,
    path = "/vlans",
    tag = "tenancy",
    operation_id = "list_vlans",
    summary = "List VLANs",
    params(
        PageParams,
        ("status" = Option<String>, Query, description = "Only VLANs with one of these statuses: `planned`, `active`, `reserved` or `deprecated`. Repeat the parameter or separate the values with commas."),
        ("site" = Option<String>, Query, description = "Only VLANs of this site (identifier)."),
        ("tag" = Option<String>, Query, description = "Only objects that carry every one of these tags. Repeat the parameter or separate the tags with commas."),
        ("q" = Option<String>, Query, description = "Case-insensitive text search over the VLAN id, the name, the description and the tags."),
        ("sort" = Option<String>, Query, description = "Sort order: comma-separated fields, `-` in front for descending, for example `-vid,name`. Fields: `vid` (the default), `name`, `created`, `updated`."),
        ("deleted" = Option<String>, Query, description = "Deleted VLANs: `exclude` (the default), `include` or `only` (the restore view).")
    ),
    responses(
        (status = 200, description = "A page of VLANs", body = Page<Vlan>),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_vlans(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<Page<Vlan>>, ApiError> {
    let args = list_args::<Vlan>(
        &filters,
        "ipam.vlans",
        &[
            Filter::Status,
            Filter::Site,
            Filter::Tag,
            Filter::Q,
            Filter::Sort,
            Filter::Deleted,
        ],
    )?;
    list_collection::<Vlan>(&app, &cx, &ipam, args).await
}

/// Creates a VLAN, global or at a site. The VLAN id (1 to 4094) is unique per site.
#[utoipa::path(
    post,
    path = "/vlans",
    tag = "tenancy",
    operation_id = "create_vlan",
    summary = "Create a VLAN",
    params(WriteParams, IdempotencyKeyHeader),
    request_body = VlanInput,
    responses(
        (status = 201, description = "The new VLAN, with `ETag`", body = WriteResponse<Vlan>),
        (status = 200, description = "The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true)", body = WriteResponse<Vlan>),
        (status = 400, description = "Invalid body or parameter: the VLAN id is outside 1 to 4094, or the VNI is too large (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The VLAN id exists at the site, the identifier is in use, or the site is missing (`ipam.vlan.duplicate`, `ipam.id_taken`, `ipam.reference_missing`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_vlan(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
    IpamJson(input): IpamJson<VlanInput>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    authorize(&app, &cx, Action::Create, new_of(ObjectKind::Vlan))?;
    let command = IpamCommand::CreateVlan(input);
    write_one::<Vlan>(&ipam, &cx, vec![command], &args, true).await
}

/// Shows one VLAN with its `ETag`. A deleted VLAN is shown too: it carries `meta.deleted`.
#[utoipa::path(
    get,
    path = "/vlans/{id}",
    tag = "tenancy",
    operation_id = "get_vlan",
    summary = "Get one VLAN",
    params(("id" = String, Path, description = "VLAN identifier"), ReadParams),
    responses(
        (status = 200, description = "The VLAN, with `ETag`", body = Vlan),
        (status = 400, description = "Invalid parameter (`sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such VLAN (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_vlan(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<VlanId>,
    filters: Filters,
) -> Result<Response, ApiError> {
    get_one::<Vlan>(&app, &cx, &ipam, id, &filters).await
}

/// Changes a VLAN: the VLAN id, the VNI, the name, the site (`null` makes it global), the status (IPAM-05 transitions apply), the tags, the custom fields and the description.
#[utoipa::path(
    patch,
    path = "/vlans/{id}",
    tag = "tenancy",
    operation_id = "update_vlan",
    summary = "Update a VLAN",
    params(("id" = String, Path, description = "VLAN identifier"), WriteParams, IfMatch),
    request_body = VlanPatch,
    responses(
        (status = 200, description = "The changed VLAN, with `ETag`, or the plan of a dry run", body = WriteResponse<Vlan>),
        (status = 400, description = "Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`), or `If-Match` is malformed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such VLAN (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The VLAN id exists at the site, the status change is not allowed, the site is missing, or the VLAN is deleted (`ipam.vlan.duplicate`, `ipam.status.transition`, `ipam.reference_missing`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_vlan(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<VlanId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(patch): IpamJson<VlanPatch>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Update, id.into())?;
    let command = IpamCommand::UpdateVlan(UpdateVlan {
        id,
        expected,
        patch,
    });
    write_one::<Vlan>(&ipam, &cx, vec![command], &args, false).await
}

/// Soft-deletes a VLAN that no live prefix uses. The answer carries the deleted VLAN.
#[utoipa::path(
    delete,
    path = "/vlans/{id}",
    tag = "tenancy",
    operation_id = "delete_vlan",
    summary = "Delete a VLAN",
    params(("id" = String, Path, description = "VLAN identifier"), WriteParams, IfMatch),
    responses(
        (status = 200, description = "The deleted VLAN (`meta.deleted` is set), or the plan of a dry run", body = WriteResponse<Vlan>),
        (status = 400, description = "Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such VLAN (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Live prefixes use the VLAN, or it is deleted already (`ipam.in_use`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_vlan(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<VlanId>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    let object: ObjectRef = id.into();
    authorize(&app, &cx, Action::Delete, object)?;
    let command = IpamCommand::Delete {
        object,
        expected,
        cascade: false,
    };
    write_one::<Vlan>(&ipam, &cx, vec![command], &args, false).await
}

/// The harness of the route tests of the tenancy, hosts and addresses areas: one router over
/// the routes of all three, a fresh in-memory store with an IPAM service per [`Api`], and
/// helpers to send requests and to assert on answers. Test data lives in the documentation
/// ranges (`192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`, MACs `00-00-5E-00-53-xx`,
/// names under `example.test`).
#[cfg(test)]
pub(super) mod testkit {
    use std::{
        collections::{BTreeMap, BTreeSet},
        net::IpAddr,
        sync::{Arc, Mutex},
    };

    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use serde_json::Value;
    use tenko_core::{
        Action, AuthFlags, AuthStrength, Authenticated, Authenticator, Authorizer, Credentials,
        Denied, DenyReason, ObjectKind, ObjectRef, PrefixId, Principal, RequestCtx, ScopeFilter,
        SystemComponent, Timestamp, VrfId,
        auth::AuthFuture,
        ipam::{PrefixRole, RangeRole},
    };
    use tenko_ipam::{
        IpamCommand, IpamService, PlanOptions,
        command::{PrefixInput, RangeInput},
    };
    use tenko_store::{MemStore, Store};
    use tower::ServiceExt;
    use utoipa_axum::router::OpenApiRouter;

    use crate::{
        API_BASE,
        problem::PROBLEM_JSON,
        routes::{addresses, hosts, tenancy},
        state::AppState,
    };

    /// A decoded answer.
    #[derive(Debug)]
    pub struct Reply {
        pub status: StatusCode,
        pub content_type: String,
        pub etag: Option<String>,
        pub body: Value,
    }

    impl Reply {
        /// Asserts a JSON answer with this status.
        pub fn assert_json(&self, status: u16) -> &Self {
            assert_eq!(self.status.as_u16(), status, "{}", self.body);
            assert_eq!(self.content_type, "application/json", "{}", self.body);
            self
        }

        /// Asserts a problem document with this status and code, and its standard members.
        pub fn assert_problem(&self, status: u16, code: &str) -> &Self {
            let label = format!("{} {}", self.status, self.body);
            assert_eq!(self.status.as_u16(), status, "{label}");
            assert_eq!(self.content_type, PROBLEM_JSON, "{label}");
            assert_eq!(self.body["type"], "about:blank", "{label}");
            assert_eq!(self.body["status"], status, "{label}");
            assert_eq!(self.body["code"], code, "{label}");
            for member in ["title", "detail"] {
                let text = self.body[member].as_str().unwrap_or_default();
                assert!(!text.is_empty(), "{member} is empty: {label}");
            }
            self
        }

        /// Asserts the shape of an applied write: `item`, `revision`, `job_id`, `dry_run`,
        /// `replayed`, `warnings` and no plan, with an `ETag` that matches the item.
        pub fn assert_write(&self, status: u16) -> &Self {
            self.assert_json(status);
            let body = &self.body;
            let revision = body["revision"].as_u64().expect("revision");
            assert!(revision > 0, "{body}");
            assert!(body["job_id"].is_string(), "{body}");
            assert_eq!(body["dry_run"], false, "{body}");
            assert_eq!(body["replayed"], false, "{body}");
            assert!(body["warnings"].is_array(), "{body}");
            assert_eq!(body["plan"], Value::Null, "{body}");
            assert!(body["item"]["id"].is_string(), "{body}");
            assert_eq!(body["item"]["meta"]["revision"], revision, "{body}");
            assert_eq!(
                self.etag.as_deref(),
                Some(format!("\"{revision}\"").as_str())
            );
            self
        }

        /// Asserts the shape of a dry run: nothing committed, an `item` as it would be and
        /// a plan with a summary.
        pub fn assert_dry_run(&self) -> &Self {
            self.assert_json(200);
            let body = &self.body;
            assert_eq!(body["dry_run"], true, "{body}");
            assert_eq!(body["revision"], Value::Null, "{body}");
            assert_eq!(body["job_id"], Value::Null, "{body}");
            assert_eq!(body["replayed"], false, "{body}");
            assert!(body["warnings"].is_array(), "{body}");
            assert!(body["plan"]["summary"]["lines"].is_array(), "{body}");
            assert!(body["plan"]["changes"].is_array(), "{body}");
            assert!(body["plan"]["base_revision"].is_u64(), "{body}");
            assert_eq!(self.etag, None);
            self
        }

        /// The lines of `plan.summary` of a dry run.
        pub fn summary_lines(&self) -> Vec<String> {
            self.body["plan"]["summary"]["lines"]
                .as_array()
                .expect("summary lines")
                .iter()
                .map(|line| line.as_str().expect("line").to_owned())
                .collect()
        }

        /// The `item` of a write answer.
        pub fn item(&self) -> &Value {
            &self.body["item"]
        }

        /// The identifier of the `item` of a write answer.
        pub fn item_id(&self) -> String {
            self.item()["id"].as_str().expect("item id").to_owned()
        }

        /// The committed revision of a write answer.
        pub fn revision(&self) -> u64 {
            self.body["revision"].as_u64().expect("revision")
        }

        /// The items of a list answer.
        pub fn items(&self) -> &[Value] {
            self.body["items"].as_array().expect("items")
        }

        /// Asserts that a list answer has no items.
        pub fn assert_no_items(&self) -> &Self {
            assert_eq!(self.items(), &[] as &[Value], "{}", self.body);
            self
        }

        /// The identifiers of the items of a list answer.
        pub fn ids(&self) -> Vec<String> {
            self.texts("id")
        }

        /// One member of each item of a list answer, as text.
        pub fn texts(&self, member: &str) -> Vec<String> {
            self.items()
                .iter()
                .map(|item| match &item[member] {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                })
                .collect()
        }
    }

    /// Sends a request and decodes the answer.
    async fn send(
        router: &Router,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<(&str, String)>,
    ) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let body = match body {
            Some((content_type, text)) => {
                builder = builder.header(header::CONTENT_TYPE, content_type);
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
        let text_of = |name| {
            response
                .headers()
                .get(name)
                .map(|value| value.to_str().expect("header text").to_owned())
        };
        let content_type = text_of(header::CONTENT_TYPE).unwrap_or_default();
        let etag = text_of(header::ETAG);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        Reply {
            status,
            content_type,
            etag,
            body,
        }
    }

    /// The routes of the three areas under the API base, over `state`.
    fn router(state: AppState) -> Router {
        let area_routes = tenancy::routes()
            .merge(hosts::routes())
            .merge(addresses::routes());
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, area_routes)
            .split_for_parts();
        router.with_state(state)
    }

    /// A router over a fresh store and an IPAM service on it.
    pub struct Api {
        router: Router,
        service: Arc<IpamService>,
    }

    impl Api {
        /// An API without authorizer and authenticator: every check passes, and every
        /// request acts as the API itself.
        pub fn new() -> Self {
            Self::with_state(AppState::default())
        }

        /// An API whose checks go through `authorizer`.
        pub fn with_authorizer(authorizer: Arc<dyn Authorizer>) -> Self {
            Self::with_state(AppState {
                authorizer: Some(authorizer),
                ..AppState::default()
            })
        }

        /// An API over a fresh service and `state`.
        pub fn with_state(state: AppState) -> Self {
            let store = Arc::new(MemStore::default()) as Arc<dyn Store>;
            let service = IpamService::with_direct_jobs(store).expect("IPAM service");
            Self {
                router: router(state).layer(Extension(Arc::clone(&service))),
                service,
            }
        }

        /// An API that was started without the IPAM service: every endpoint answers 503.
        pub fn unavailable() -> Self {
            let store = Arc::new(MemStore::default()) as Arc<dyn Store>;
            Self {
                router: router(AppState::default()),
                service: IpamService::with_direct_jobs(store).expect("IPAM service"),
            }
        }

        /// Another router over the same service and store, with other checks.
        pub fn sibling(&self, state: AppState) -> Self {
            Self {
                router: router(state).layer(Extension(Arc::clone(&self.service))),
                service: Arc::clone(&self.service),
            }
        }

        /// The same service as seen by automation (the reconciler), which a locked host
        /// refuses and which may not lock hosts.
        pub fn as_automation(&self) -> Self {
            self.sibling(AppState {
                auth: Some(Arc::new(AsReconciler)),
                ..AppState::default()
            })
        }

        /// Sends a request with headers and an optional JSON body.
        pub async fn send(
            &self,
            method: &str,
            path: &str,
            headers: &[(&str, &str)],
            body: Option<&Value>,
        ) -> Reply {
            let body = body.map(|value| ("application/json", value.to_string()));
            send(&self.router, method, path, headers, body).await
        }

        /// Sends a body of any media type as it is.
        pub async fn send_text(
            &self,
            method: &str,
            path: &str,
            content_type: &str,
            text: &str,
        ) -> Reply {
            let body = Some((content_type, text.to_owned()));
            send(&self.router, method, path, &[], body).await
        }

        /// `GET`.
        pub async fn get(&self, path: &str) -> Reply {
            self.send("GET", path, &[], None).await
        }

        /// `POST` with a JSON body.
        pub async fn post(&self, path: &str, body: &Value) -> Reply {
            self.send("POST", path, &[], Some(body)).await
        }

        /// `POST` with headers and a JSON body.
        pub async fn post_with(&self, path: &str, headers: &[(&str, &str)], body: &Value) -> Reply {
            self.send("POST", path, headers, Some(body)).await
        }

        /// `PATCH` with a JSON body and, when given, an `If-Match` header.
        pub async fn patch(&self, path: &str, if_match: Option<&str>, body: &Value) -> Reply {
            let headers: Vec<(&str, &str)> = if_match
                .map(|value| ("if-match", value))
                .into_iter()
                .collect();
            self.send("PATCH", path, &headers, Some(body)).await
        }

        /// `DELETE` with, when given, an `If-Match` header.
        pub async fn delete(&self, path: &str, if_match: Option<&str>) -> Reply {
            let headers: Vec<(&str, &str)> = if_match
                .map(|value| ("if-match", value))
                .into_iter()
                .collect();
            self.send("DELETE", path, &headers, None).await
        }

        /// Creates an object through the API, expects 201 and returns the new object.
        pub async fn create(&self, collection: &str, body: &Value) -> Value {
            let reply = self.post(collection, body).await;
            reply.assert_write(201);
            reply.item().clone()
        }

        /// Walks a list page by page with `limit` and the cursors, and returns the pages.
        /// Every page but the last has a `next_cursor`; the last has `null`.
        pub async fn pages(&self, path: &str, limit: usize) -> Vec<Reply> {
            let separator = if path.contains('?') { '&' } else { '?' };
            let mut next = format!("{path}{separator}limit={limit}");
            let mut pages = Vec::new();
            loop {
                assert!(pages.len() < 50, "the cursor never ends");
                let reply = self.get(&next).await;
                reply.assert_json(200);
                assert!(reply.items().len() <= limit, "{}", reply.body);
                assert!(reply.body["revision"].as_u64().is_some(), "{}", reply.body);
                let cursor = reply.body["next_cursor"].as_str().map(str::to_owned);
                pages.push(reply);
                match cursor {
                    Some(cursor) => {
                        next = format!("{path}{separator}limit={limit}&cursor={cursor}");
                    }
                    None => return pages,
                }
            }
        }

        /// Runs commands directly on the service (for the prefixes, which have no route
        /// of these areas) and returns the primary object of each.
        pub async fn run(&self, commands: Vec<IpamCommand>) -> Vec<ObjectRef> {
            let cx = RequestCtx::system(SystemComponent::Api);
            self.service
                .execute(&commands, &cx, &PlanOptions::default())
                .await
                .expect("setup commands")
                .results
        }

        /// Creates a network prefix, in the default VRF when `vrf` is `None`.
        pub async fn make_prefix(&self, vrf: Option<&str>, cidr: &str) -> PrefixId {
            self.make_prefix_as(vrf, cidr, None).await
        }

        /// Creates a prefix with a role (a supernet, for instance).
        pub async fn make_prefix_as(
            &self,
            vrf: Option<&str>,
            cidr: &str,
            role: Option<PrefixRole>,
        ) -> PrefixId {
            let input = PrefixInput {
                id: None,
                vrf: vrf.map(|vrf| vrf.parse::<VrfId>().expect("VRF identifier")),
                cidr: cidr.parse().expect("network"),
                role,
                status: None,
                vlan: None,
                site: None,
                alarm: None,
                alloc: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            };
            let results = self.run(vec![IpamCommand::CreatePrefix(input)]).await;
            PrefixId::from(results[0].id)
        }

        /// Creates a range of a network prefix.
        pub async fn make_range(&self, prefix: PrefixId, first: &str, last: &str, role: RangeRole) {
            let input = RangeInput {
                id: None,
                prefix,
                first: first.parse().expect("address"),
                last: last.parse().expect("address"),
                role,
                status: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            };
            self.run(vec![IpamCommand::CreateRange(input)]).await;
        }
    }

    /// A name under `example.test`: `label("host", 3)` is `host-03.example.test`.
    pub fn label(prefix: &str, number: usize) -> String {
        format!("{prefix}-{number:02}.example.test")
    }

    /// An address in `192.0.2.0/24`: `ip4(10)` is `192.0.2.10`.
    pub fn ip4(host: usize) -> String {
        format!("192.0.2.{host}")
    }

    /// An identifier that no object has.
    pub fn unknown_id() -> String {
        PrefixId::generate().to_string()
    }

    /// What a [`Policy`] decides: the principal may read, and may or may not change things.
    /// It records every question.
    pub struct Policy {
        read: bool,
        write: bool,
        asked: Mutex<Vec<(Action, ObjectRef)>>,
    }

    impl Policy {
        /// A policy that allows reads when `read` and every other action when `write`.
        pub fn new(read: bool, write: bool) -> Arc<Self> {
            Arc::new(Self {
                read,
                write,
                asked: Mutex::new(Vec::new()),
            })
        }

        /// The questions asked so far.
        pub fn asked(&self) -> Vec<(Action, ObjectRef)> {
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
            let allowed = if action == Action::Read {
                self.read
            } else {
                self.write
            };
            if allowed {
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
            let allowed = if action == Action::Read {
                self.read
            } else {
                self.write
            };
            if allowed {
                ScopeFilter::All
            } else {
                ScopeFilter::Nothing
            }
        }
    }

    /// An authenticator that accepts every request as the reconciler.
    struct AsReconciler;

    impl Authenticator for AsReconciler {
        fn authenticate<'a>(
            &'a self,
            _credentials: &'a Credentials,
            _source_ip: Option<IpAddr>,
            _now: Timestamp,
        ) -> AuthFuture<'a> {
            Box::pin(async {
                Ok(Authenticated {
                    principal: Principal::system(SystemComponent::Reconciler),
                    user: None,
                    roles: BTreeSet::new(),
                    strength: AuthStrength::Passkey,
                    expires_at: None,
                    flags: AuthFlags::default(),
                })
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use tenko_core::{Action, ObjectKind, ObjectRef, TenantId};

    use super::testkit::{Api, Policy, Reply, label, unknown_id};
    use crate::state::AppState;

    /// One of the four collections of this area.
    #[derive(Clone, Copy)]
    struct Kind {
        /// The path of the collection.
        collection: &'static str,
        /// The kind name in problem parameters.
        noun: &'static str,
        /// The sort field that is the default and the one used for `sort=-field`.
        sort: &'static str,
        /// The body of the `n`th object; its names sort in the order of `n`.
        body: fn(usize) -> Value,
    }

    fn tenant_body(n: usize) -> Value {
        json!({ "name": label("tenant", n) })
    }

    fn vrf_body(n: usize) -> Value {
        json!({ "name": label("vrf", n) })
    }

    fn site_body(n: usize) -> Value {
        json!({ "name": label("site", n) })
    }

    fn vlan_body(n: usize) -> Value {
        json!({ "vid": 100 + n, "name": label("vlan", n) })
    }

    const KINDS: [Kind; 4] = [
        Kind {
            collection: "/tenants",
            noun: "tenant",
            sort: "name",
            body: tenant_body,
        },
        Kind {
            collection: "/vrfs",
            noun: "vrf",
            sort: "name",
            body: vrf_body,
        },
        Kind {
            collection: "/sites",
            noun: "site",
            sort: "name",
            body: site_body,
        },
        Kind {
            collection: "/vlans",
            noun: "vlan",
            sort: "vid",
            body: vlan_body,
        },
    ];

    impl Kind {
        /// The path of one object.
        fn at(self, id: &str) -> String {
            format!("{}/{id}", self.collection)
        }

        /// The body of the `n`th object with more members merged in.
        fn body_with(self, n: usize, extra: Value) -> Value {
            let mut body = (self.body)(n);
            let Value::Object(extra) = extra else {
                panic!("members must be an object");
            };
            body.as_object_mut().expect("object").extend(extra);
            body
        }

        /// Creates `count` objects (numbered from 1) and returns their identifiers.
        async fn create_many(self, api: &Api, count: usize) -> Vec<String> {
            let mut ids = Vec::new();
            for n in 1..=count {
                ids.push(
                    api.create(self.collection, &(self.body)(n)).await["id"]
                        .as_str()
                        .expect("id")
                        .to_owned(),
                );
            }
            ids
        }
    }

    // Create and read.

    #[tokio::test]
    async fn create_answers_201_with_the_object_the_revision_and_an_etag() {
        let api = Api::new();
        for kind in KINDS {
            let reply = api.post(kind.collection, &(kind.body)(1)).await;
            reply.assert_write(201);
            let item = reply.item();
            assert_eq!(item["name"], label(kind.noun, 1), "{}", kind.noun);
            assert_eq!(item["meta"]["deleted"], Value::Null);
            assert_eq!(item["meta"]["tags"], json!([]));
            assert!(item["meta"]["created"]["at"].is_string());
        }
    }

    #[tokio::test]
    async fn create_keeps_tags_description_and_a_client_chosen_identifier() {
        let api = Api::new();
        let id = unknown_id();
        let body = json!({
            "id": id,
            "name": label("tenant", 1),
            "tags": ["edge", "lab"],
            "description": "  Documentation tenant  ",
        });
        let reply = api.post("/tenants", &body).await;
        reply.assert_write(201);
        assert_eq!(reply.item_id(), id);
        assert_eq!(reply.item()["meta"]["tags"], json!(["edge", "lab"]));
        assert_eq!(reply.item()["meta"]["description"], "Documentation tenant");
        let again = api.post("/tenants", &body).await;
        again.assert_problem(409, "ipam.id_taken");
        assert_eq!(again.body["params"]["id"], id);
    }

    #[tokio::test]
    async fn get_returns_the_object_with_the_same_etag_as_the_write() {
        let api = Api::new();
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            created.assert_write(201);
            let reply = api.get(&kind.at(&created.item_id())).await;
            reply.assert_json(200);
            assert_eq!(&reply.body, created.item(), "{}", kind.noun);
            assert_eq!(reply.etag, created.etag, "{}", kind.noun);
        }
    }

    #[tokio::test]
    async fn an_unknown_object_is_a_404_problem_on_get_patch_and_delete() {
        let api = Api::new();
        for kind in KINDS {
            let id = unknown_id();
            let path = kind.at(&id);
            let replies = [
                api.get(&path).await,
                api.patch(&path, None, &json!({ "description": "x" })).await,
                api.delete(&path, None).await,
            ];
            for reply in replies {
                reply.assert_problem(404, "ipam.not_found");
                assert_eq!(reply.body["params"]["kind"], kind.noun);
                assert_eq!(reply.body["params"]["id"], id);
                assert_eq!(reply.body["title"], "Object not found");
            }
        }
    }

    #[tokio::test]
    async fn a_malformed_identifier_in_the_path_is_a_400_problem() {
        let api = Api::new();
        for kind in KINDS {
            let path = kind.at("not-a-uuid");
            let replies = [
                api.get(&path).await,
                api.patch(&path, None, &json!({})).await,
                api.delete(&path, None).await,
            ];
            for reply in replies {
                reply.assert_problem(400, "sys.invalid_request");
                assert_eq!(reply.body["params"]["part"], "path", "{}", kind.noun);
            }
        }
    }

    #[tokio::test]
    async fn a_body_that_cannot_be_read_is_a_400_problem() {
        let api = Api::new();
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            let path = kind.at(&created.item_id());
            let broken = ["not json", "{\"name\": 5}", "", "{\"name\": \"x\""];
            for text in broken.into_iter().chain(["{}", "[]"]) {
                let post = api
                    .send_text("POST", kind.collection, "application/json", text)
                    .await;
                post.assert_problem(400, "sys.invalid_request");
                assert_eq!(post.body["params"]["part"], "body", "{text}");
            }
            for text in broken {
                let changed = api
                    .send_text("PATCH", &path, "application/json", text)
                    .await;
                changed.assert_problem(400, "sys.invalid_request");
            }
            // Every member of a patch is optional.
            for text in ["{}", "[]"] {
                let changed = api
                    .send_text("PATCH", &path, "application/json", text)
                    .await;
                changed.assert_json(200);
            }
            let plain = api
                .send_text("POST", kind.collection, "text/plain", "{}")
                .await;
            plain.assert_problem(415, "sys.invalid_request");
            let none = api
                .send_text("PATCH", &path, "application/xml", "<a/>")
                .await;
            none.assert_problem(415, "sys.invalid_request");
            assert_eq!(api.get(&path).await.etag, created.etag, "{}", kind.noun);
            assert_eq!(api.get(kind.collection).await.items().len(), 1);
        }
    }

    #[tokio::test]
    async fn an_unknown_member_in_the_body_is_a_400_problem() {
        let api = Api::new();
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            let path = kind.at(&created.item_id());
            let unknown = kind.body_with(2, json!({ "colour": "red" }));
            let post = api.post(kind.collection, &unknown).await;
            post.assert_problem(400, "sys.invalid_request");
            assert_eq!(post.body["params"]["part"], "body", "{}", kind.noun);
            assert!(
                post.body["detail"]
                    .as_str()
                    .expect("detail")
                    .contains("colour")
            );
            let change = api.patch(&path, None, &json!({ "colour": "red" })).await;
            change.assert_problem(400, "sys.invalid_request");
            assert_eq!(api.get(&path).await.etag, created.etag, "{}", kind.noun);
            assert_eq!(api.get(kind.collection).await.items().len(), 1);
        }
        // What cannot change is refused rather than ignored.
        let tenant = api.create("/tenants", &tenant_body(7)).await;
        let vrf = api
            .create(
                "/vrfs",
                &json!({ "name": label("vrf", 9), "tenant": tenant["id"] }),
            )
            .await;
        let moved = api
            .patch(
                &format!("/vrfs/{}", vrf["id"].as_str().expect("id")),
                None,
                &json!({ "tenant": unknown_id() }),
            )
            .await;
        moved.assert_problem(400, "sys.invalid_request");
    }

    #[tokio::test]
    async fn a_value_that_does_not_fit_names_the_problem_in_the_detail() {
        let api = Api::new();
        let vid = api
            .post(
                "/vlans",
                &json!({ "vid": 70_000, "name": label("vlan", 1) }),
            )
            .await;
        vid.assert_problem(400, "sys.invalid_request");
        assert!(vid.body["detail"].as_str().expect("detail").contains("vid"));
        let id = api
            .post(
                "/tenants",
                &json!({ "id": "x", "name": label("tenant", 1) }),
            )
            .await;
        id.assert_problem(400, "sys.invalid_request");
        let tag = api
            .post(
                "/tenants",
                &json!({ "name": label("tenant", 1), "tags": [""] }),
            )
            .await;
        tag.assert_problem(400, "sys.invalid_request");
        api.get("/tenants").await.assert_no_items();
    }

    // Lists.

    #[tokio::test]
    async fn an_empty_list_is_a_page_without_items() {
        let api = Api::new();
        for kind in KINDS {
            let reply = api.get(kind.collection).await;
            reply.assert_json(200);
            assert_eq!(reply.body["items"], json!([]));
            assert_eq!(reply.body["next_cursor"], Value::Null);
            assert!(reply.body["revision"].is_u64());
        }
    }

    #[tokio::test]
    async fn lists_page_with_limit_and_cursor_and_show_every_object_once() {
        let api = Api::new();
        for kind in KINDS {
            let created = kind.create_many(&api, 5).await;
            let pages = api.pages(kind.collection, 2).await;
            let sizes: Vec<usize> = pages.iter().map(|page| page.items().len()).collect();
            assert_eq!(sizes, [2, 2, 1], "{}", kind.noun);
            assert!(pages[0].body["next_cursor"].is_string());
            assert!(pages[1].body["next_cursor"].is_string());
            assert_eq!(pages[2].body["next_cursor"], Value::Null);
            let seen: Vec<String> = pages.iter().flat_map(Reply::ids).collect();
            assert_eq!(seen, created, "{}", kind.noun);
        }
    }

    #[tokio::test]
    async fn a_page_that_ends_exactly_has_no_cursor() {
        let api = Api::new();
        for kind in KINDS {
            kind.create_many(&api, 4).await;
            let pages = api.pages(kind.collection, 2).await;
            let sizes: Vec<usize> = pages.iter().map(|page| page.items().len()).collect();
            assert_eq!(sizes, [2, 2], "{}", kind.noun);
            let one = api.get(&format!("{}?limit=4", kind.collection)).await;
            assert_eq!(one.body["next_cursor"], Value::Null);
        }
    }

    #[tokio::test]
    async fn sort_descending_reverses_the_order() {
        let api = Api::new();
        for kind in KINDS {
            let mut created = kind.create_many(&api, 3).await;
            created.reverse();
            let reply = api
                .get(&format!("{}?sort=-{}", kind.collection, kind.sort))
                .await;
            reply.assert_json(200);
            assert_eq!(reply.ids(), created, "{}", kind.noun);
            let by_creation = api.get(&format!("{}?sort=-created", kind.collection)).await;
            assert_eq!(by_creation.ids(), created, "{}", kind.noun);
        }
    }

    #[tokio::test]
    async fn sort_by_an_unknown_field_is_refused() {
        let api = Api::new();
        for kind in KINDS {
            let reply = api.get(&format!("{}?sort=color", kind.collection)).await;
            reply.assert_problem(400, "sys.invalid_query");
            assert_eq!(reply.body["params"]["parameter"], "sort");
        }
    }

    #[tokio::test]
    async fn tag_filters_need_every_tag() {
        let api = Api::new();
        for kind in KINDS {
            let red = api
                .create(
                    kind.collection,
                    &kind.body_with(1, json!({ "tags": ["red"] })),
                )
                .await;
            let both = api
                .create(
                    kind.collection,
                    &kind.body_with(2, json!({ "tags": ["blue", "red"] })),
                )
                .await;
            api.create(kind.collection, &(kind.body)(3)).await;
            let id_of = |value: &Value| value["id"].as_str().expect("id").to_owned();
            let (red, both) = (id_of(&red), id_of(&both));
            for (query, expected) in [
                ("tag=red", vec![red.clone(), both.clone()]),
                ("tag=blue", vec![both.clone()]),
                ("tag=red,blue", vec![both.clone()]),
                ("tag=red&tag=blue", vec![both.clone()]),
                ("tag=green", Vec::new()),
            ] {
                let reply = api.get(&format!("{}?{query}", kind.collection)).await;
                assert_eq!(reply.ids(), expected, "{} {query}", kind.noun);
            }
        }
    }

    #[tokio::test]
    async fn q_finds_text_without_regard_to_case() {
        let api = Api::new();
        for kind in KINDS {
            let created = kind.create_many(&api, 3).await;
            let reply = api.get(&format!("{}?q=-02.EXAMPLE", kind.collection)).await;
            reply.assert_json(200);
            assert_eq!(reply.ids(), [created[1].clone()], "{}", kind.noun);
            let none = api
                .get(&format!("{}?q=nothing-like-it", kind.collection))
                .await;
            none.assert_no_items();
        }
    }

    #[tokio::test]
    async fn deleted_objects_leave_the_list_and_show_with_deleted_only_or_include() {
        let api = Api::new();
        for kind in KINDS {
            let created = kind.create_many(&api, 3).await;
            api.delete(&kind.at(&created[1]), None)
                .await
                .assert_json(200);
            let live = api.get(kind.collection).await;
            assert_eq!(live.ids(), [created[0].clone(), created[2].clone()]);
            let only = api.get(&format!("{}?deleted=only", kind.collection)).await;
            assert_eq!(only.ids(), [created[1].clone()], "{}", kind.noun);
            assert!(only.items()[0]["meta"]["deleted"]["at"].is_string());
            let all = api
                .get(&format!("{}?deleted=include", kind.collection))
                .await;
            assert_eq!(all.ids(), created, "{}", kind.noun);
            let exclude = api
                .get(&format!("{}?deleted=exclude", kind.collection))
                .await;
            assert_eq!(exclude.ids().len(), 2);
            let bad = api.get(&format!("{}?deleted=maybe", kind.collection)).await;
            bad.assert_problem(400, "sys.invalid_query");
            assert_eq!(bad.body["params"]["parameter"], "deleted");
        }
    }

    #[tokio::test]
    async fn vrfs_filter_by_tenant() {
        let api = Api::new();
        let first = api.create("/tenants", &tenant_body(1)).await;
        let second = api.create("/tenants", &tenant_body(2)).await;
        let in_first = api
            .create(
                "/vrfs",
                &json!({ "name": label("vrf", 1), "tenant": first["id"] }),
            )
            .await;
        api.create(
            "/vrfs",
            &json!({ "name": label("vrf", 1), "tenant": second["id"] }),
        )
        .await;
        let reply = api
            .get(&format!(
                "/vrfs?tenant={}",
                first["id"].as_str().expect("id")
            ))
            .await;
        reply.assert_json(200);
        assert_eq!(reply.ids(), [in_first["id"].as_str().expect("id")]);
        assert_eq!(reply.items()[0]["tenant"], first["id"]);
        assert_eq!(api.get("/vrfs").await.items().len(), 2);
        api.get("/vrfs?tenant=nope")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn sites_filter_by_parent() {
        let api = Api::new();
        let root = api.create("/sites", &site_body(1)).await;
        let root_id = root["id"].as_str().expect("id");
        let child = api
            .create(
                "/sites",
                &json!({ "name": label("site", 2), "parent": root_id }),
            )
            .await;
        api.create("/sites", &site_body(3)).await;
        let reply = api.get(&format!("/sites?site={root_id}")).await;
        reply.assert_json(200);
        assert_eq!(reply.ids(), [child["id"].as_str().expect("id")]);
        assert_eq!(reply.items()[0]["parent"], root_id);
        assert_eq!(api.get("/sites").await.items().len(), 3);
    }

    #[tokio::test]
    async fn vlans_filter_by_status_and_site() {
        let api = Api::new();
        let site = api.create("/sites", &site_body(1)).await;
        let site_id = site["id"].as_str().expect("id");
        let planned = api
            .create(
                "/vlans",
                &json!({ "vid": 10, "name": label("vlan", 1), "site": site_id, "status": "planned" }),
            )
            .await;
        let active = api.create("/vlans", &vlan_body(2)).await;
        let reply = api.get("/vlans?status=planned").await;
        assert_eq!(reply.ids(), [planned["id"].as_str().expect("id")]);
        assert_eq!(
            api.get("/vlans?status=planned,active").await.items().len(),
            2
        );
        assert_eq!(
            api.get("/vlans?status=planned&status=active")
                .await
                .items()
                .len(),
            2
        );
        let at_site = api.get(&format!("/vlans?site={site_id}")).await;
        assert_eq!(at_site.ids(), [planned["id"].as_str().expect("id")]);
        let both = api
            .get(&format!("/vlans?site={site_id}&status=active"))
            .await;
        both.assert_no_items();
        assert_eq!(active["status"], "active");
        api.get("/vlans?status=sleeping")
            .await
            .assert_problem(400, "sys.invalid_query");
        let by_vid = api.get("/vlans?sort=-vid").await;
        assert_eq!(by_vid.texts("vid"), ["102", "10"]);
    }

    #[tokio::test]
    async fn unknown_and_foreign_parameters_are_refused_everywhere() {
        let api = Api::new();
        for kind in KINDS {
            let created = api.create(kind.collection, &(kind.body)(1)).await;
            let path = kind.at(created["id"].as_str().expect("id"));
            let replies = [
                (
                    api.get(&format!("{}?bogus=1", kind.collection)).await,
                    "bogus",
                ),
                (api.get(&format!("{path}?bogus=1")).await, "bogus"),
                (api.get(&format!("{path}?deleted=only")).await, "deleted"),
                (
                    api.post(&format!("{}?bogus=1", kind.collection), &(kind.body)(2))
                        .await,
                    "bogus",
                ),
                (
                    api.patch(&format!("{path}?cascade=true"), None, &json!({}))
                        .await,
                    "cascade",
                ),
                (
                    api.delete(&format!("{path}?cascade=true"), None).await,
                    "cascade",
                ),
                (
                    api.get(&format!("{}?limit=0", kind.collection)).await,
                    "limit",
                ),
                (
                    api.get(&format!("{}?limit=1001", kind.collection)).await,
                    "limit",
                ),
                (
                    api.get(&format!("{}?at_least=x", kind.collection)).await,
                    "at_least",
                ),
                (api.get(&format!("{}?q=a&q=b", kind.collection)).await, "q"),
            ];
            for (reply, parameter) in replies {
                reply.assert_problem(400, "sys.invalid_query");
                assert_eq!(
                    reply.body["params"]["parameter"], parameter,
                    "{}",
                    kind.noun
                );
            }
            // Nothing of that changed the object.
            let still = api.get(&path).await;
            assert_eq!(
                still.etag,
                Some(format!("\"{}\"", created["meta"]["revision"]))
            );
        }
        // Filters of other collections.
        for path in [
            "/tenants?status=active",
            "/tenants?tenant=x",
            "/vrfs?site=x",
            "/sites?tenant=x",
        ] {
            api.get(path).await.assert_problem(400, "sys.invalid_query");
        }
    }

    #[tokio::test]
    async fn a_cursor_of_another_query_is_refused() {
        let api = Api::new();
        for kind in KINDS {
            kind.create_many(&api, 3).await;
            let first = api.get(&format!("{}?limit=1", kind.collection)).await;
            let cursor = first.body["next_cursor"].as_str().expect("cursor");
            for path in [
                format!("{}?limit=1&cursor={cursor}&tag=red", kind.collection),
                format!("{}?limit=1&cursor={cursor}&sort=-created", kind.collection),
                format!("{}?cursor=garbage", kind.collection),
            ] {
                api.get(&path)
                    .await
                    .assert_problem(400, "sys.invalid_cursor");
            }
            api.get(&format!("{}?limit=1&cursor={cursor}", kind.collection))
                .await
                .assert_json(200);
        }
        // A cursor of one collection is no cursor of another.
        let sites = api.get("/sites?limit=1").await;
        let cursor = sites.body["next_cursor"].as_str().expect("cursor");
        api.get(&format!("/tenants?limit=1&cursor={cursor}"))
            .await
            .assert_problem(400, "sys.invalid_cursor");
    }

    #[tokio::test]
    async fn at_least_reads_at_or_after_a_revision() {
        let api = Api::new();
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            let revision = created.revision();
            let list = api
                .get(&format!("{}?at_least={revision}", kind.collection))
                .await;
            list.assert_json(200);
            assert!(list.body["revision"].as_u64().expect("revision") >= revision);
            assert_eq!(list.items().len(), 1);
            let one = api
                .get(&format!(
                    "{}?at_least={revision}",
                    kind.at(&created.item_id())
                ))
                .await;
            one.assert_json(200);
        }
    }

    // Updates.

    #[tokio::test]
    async fn patch_changes_the_object_and_moves_the_etag() {
        let api = Api::new();
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            let path = kind.at(&created.item_id());
            let changes = json!({ "description": "Changed", "tags": ["lab"] });
            let reply = api.patch(&path, created.etag.as_deref(), &changes).await;
            reply.assert_write(200);
            assert_eq!(reply.item()["meta"]["description"], "Changed");
            assert_eq!(reply.item()["meta"]["tags"], json!(["lab"]));
            assert_eq!(reply.item()["name"], label(kind.noun, 1));
            assert!(reply.revision() > created.revision(), "{}", kind.noun);
            assert_ne!(reply.etag, created.etag);
            let got = api.get(&path).await;
            assert_eq!(got.etag, reply.etag);
            assert_eq!(&got.body, reply.item());
            // A merge patch: null clears the description, absent members stay.
            let cleared = api
                .patch(&path, None, &json!({ "description": null }))
                .await;
            cleared.assert_write(200);
            assert_eq!(cleared.item()["meta"]["description"], Value::Null);
            assert_eq!(cleared.item()["meta"]["tags"], json!(["lab"]));
        }
    }

    #[tokio::test]
    async fn patch_without_a_change_keeps_the_revision() {
        let api = Api::new();
        let created = api.post("/tenants", &tenant_body(1)).await;
        let path = format!("/tenants/{}", created.item_id());
        let reply = api
            .patch(&path, None, &json!({ "name": label("tenant", 1) }))
            .await;
        reply.assert_json(200);
        assert_eq!(reply.body["job_id"], Value::Null);
        assert_eq!(reply.item()["meta"]["revision"], created.revision());
        assert_eq!(reply.etag, created.etag);
    }

    #[tokio::test]
    async fn patch_changes_the_fields_of_each_kind() {
        let api = Api::new();
        let tenant = api.create("/tenants", &tenant_body(1)).await;
        let renamed = api
            .patch(
                &format!("/tenants/{}", tenant["id"].as_str().expect("id")),
                None,
                &json!({ "name": label("tenant", 9) }),
            )
            .await;
        assert_eq!(renamed.item()["name"], label("tenant", 9));
        assert_eq!(
            api.get("/tenants").await.texts("name"),
            [label("tenant", 9)]
        );

        let vrf = api.create("/vrfs", &vrf_body(1)).await;
        let vrf_path = format!("/vrfs/{}", vrf["id"].as_str().expect("id"));
        let with_rd = api
            .patch(&vrf_path, None, &json!({ "rd": "64496:1" }))
            .await;
        assert_eq!(with_rd.item()["rd"], "64496:1");
        let no_rd = api.patch(&vrf_path, None, &json!({ "rd": null })).await;
        assert_eq!(no_rd.item()["rd"], Value::Null);

        let root = api.create("/sites", &site_body(1)).await;
        let child = api.create("/sites", &site_body(2)).await;
        let child_path = format!("/sites/{}", child["id"].as_str().expect("id"));
        let nested = api
            .patch(
                &child_path,
                None,
                &json!({ "parent": root["id"], "ad_site": "Default-First-Site-Name" }),
            )
            .await;
        assert_eq!(nested.item()["parent"], root["id"]);
        assert_eq!(nested.item()["ad_site"], "Default-First-Site-Name");
        let top = api
            .patch(&child_path, None, &json!({ "parent": null }))
            .await;
        assert_eq!(top.item()["parent"], Value::Null);
        assert_eq!(top.item()["ad_site"], "Default-First-Site-Name");

        let vlan = api.create("/vlans", &vlan_body(1)).await;
        let vlan_path = format!("/vlans/{}", vlan["id"].as_str().expect("id"));
        let changed = api
            .patch(
                &vlan_path,
                None,
                &json!({ "vid": 200, "vni": 5000, "status": "deprecated", "site": root["id"] }),
            )
            .await;
        let item = changed.item();
        assert_eq!(item["vid"], 200);
        assert_eq!(item["vni"], 5000);
        assert_eq!(item["status"], "deprecated");
        assert_eq!(item["site"], root["id"]);
        let global = api
            .patch(&vlan_path, None, &json!({ "vni": null, "site": null }))
            .await;
        assert_eq!(global.item()["vni"], Value::Null);
        assert_eq!(global.item()["site"], Value::Null);
    }

    #[tokio::test]
    async fn if_match_takes_a_quoted_bare_or_weak_revision() {
        let api = Api::new();
        let created = api.post("/tenants", &tenant_body(1)).await;
        let path = format!("/tenants/{}", created.item_id());
        let mut revision = created.revision();
        for form in ["\"{}\"", "{}", "W/\"{}\""] {
            let value = form.replace("{}", &revision.to_string());
            let reply = api
                .patch(&path, Some(&value), &json!({ "description": value }))
                .await;
            reply.assert_write(200);
            assert!(reply.revision() > revision, "{value}");
            revision = reply.revision();
        }
    }

    #[tokio::test]
    async fn a_stale_if_match_is_a_412_and_changes_nothing() {
        let api = Api::new();
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            let path = kind.at(&created.item_id());
            let first = api
                .patch(
                    &path,
                    created.etag.as_deref(),
                    &json!({ "description": "one" }),
                )
                .await;
            first.assert_write(200);
            let stale = created.etag.as_deref();
            let rejected = api
                .patch(&path, stale, &json!({ "description": "two" }))
                .await;
            rejected.assert_problem(412, "ipam.revision_mismatch");
            assert_eq!(rejected.body["params"]["kind"], kind.noun);
            assert_eq!(rejected.body["params"]["id"], created.item_id());
            assert_eq!(
                rejected.body["params"]["expected"],
                created.revision().to_string()
            );
            assert_eq!(
                rejected.body["params"]["actual"],
                first.revision().to_string()
            );
            api.delete(&path, stale)
                .await
                .assert_problem(412, "ipam.revision_mismatch");
            let got = api.get(&path).await;
            assert_eq!(got.etag, first.etag, "{}", kind.noun);
            assert_eq!(got.body["meta"]["description"], "one");
            assert_eq!(got.body["meta"]["deleted"], Value::Null);
        }
    }

    #[tokio::test]
    async fn a_malformed_if_match_is_a_400() {
        let api = Api::new();
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            let path = kind.at(&created.item_id());
            for value in ["abc", "\"abc\"", "12x", "-1", ""] {
                let reply = api.patch(&path, Some(value), &json!({})).await;
                reply.assert_problem(400, "ipam.validation");
                assert_eq!(reply.body["params"]["field"], "If-Match", "{value}");
                api.delete(&path, Some(value))
                    .await
                    .assert_problem(400, "ipam.validation");
            }
            assert_eq!(api.get(&path).await.etag, created.etag);
            // `*` matches any current revision.
            let reply = api.patch(&path, Some("*"), &json!({})).await;
            assert_eq!(reply.status.as_u16(), 200, "{}", reply.body);
        }
    }

    // Dry runs.

    #[tokio::test]
    async fn a_create_dry_run_answers_the_plan_and_writes_nothing() {
        let api = Api::new();
        for kind in KINDS {
            let path = format!("{}?dry_run=true", kind.collection);
            let reply = api.post(&path, &(kind.body)(1)).await;
            reply.assert_dry_run();
            let line = format!(
                "1 {} created",
                kind.noun.replace("vrf", "VRF").replace("vlan", "VLAN")
            );
            assert!(
                reply.summary_lines().contains(&line),
                "{:?}",
                reply.summary_lines()
            );
            assert_eq!(reply.item()["name"], label(kind.noun, 1));
            assert_eq!(reply.body["plan"]["changes"][0]["action"], "create");
            let id = reply.item_id();
            api.get(&kind.at(&id))
                .await
                .assert_problem(404, "ipam.not_found");
            api.get(kind.collection).await.assert_no_items();
        }
        api.get("/tenants").await.assert_no_items();
    }

    #[tokio::test]
    async fn an_update_dry_run_shows_the_change_and_leaves_the_object() {
        let api = Api::new();
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            let path = kind.at(&created.item_id());
            let reply = api
                .patch(
                    &format!("{path}?dry_run=true"),
                    created.etag.as_deref(),
                    &json!({ "description": "Planned change" }),
                )
                .await;
            reply.assert_dry_run();
            assert_eq!(reply.item()["meta"]["description"], "Planned change");
            assert_eq!(reply.body["plan"]["changes"][0]["action"], "update");
            assert!(
                reply
                    .summary_lines()
                    .iter()
                    .any(|line| line.ends_with(" updated")),
                "{:?}",
                reply.summary_lines()
            );
            let got = api.get(&path).await;
            assert_eq!(got.etag, created.etag);
            assert_eq!(got.body["meta"]["description"], Value::Null);
        }
    }

    #[tokio::test]
    async fn a_delete_dry_run_leaves_the_object_live() {
        let api = Api::new();
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            let path = kind.at(&created.item_id());
            let reply = api
                .delete(&format!("{path}?dry_run=true"), created.etag.as_deref())
                .await;
            reply.assert_dry_run();
            assert!(reply.item()["meta"]["deleted"].is_object());
            assert_eq!(reply.body["plan"]["changes"][0]["action"], "delete");
            let got = api.get(&path).await;
            assert_eq!(got.etag, created.etag);
            assert_eq!(got.body["meta"]["deleted"], Value::Null);
            assert_eq!(api.get(kind.collection).await.items().len(), 1);
        }
    }

    #[tokio::test]
    async fn dry_run_and_acknowledge_are_checked_as_parameters() {
        let api = Api::new();
        let bad = api.post("/tenants?dry_run=maybe", &tenant_body(1)).await;
        bad.assert_problem(400, "sys.invalid_query");
        assert_eq!(bad.body["params"]["parameter"], "dry_run");
        let acknowledged = api
            .post(
                "/tenants?acknowledge=ipam.parent_status,ipam.prefix.nibble_boundary",
                &tenant_body(1),
            )
            .await;
        acknowledged.assert_write(201);
        let yes = api.post("/tenants?dry_run=yes", &tenant_body(2)).await;
        yes.assert_dry_run();
    }

    // Deletes.

    #[tokio::test]
    async fn delete_soft_deletes_and_answers_the_deleted_object() {
        let api = Api::new();
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            let path = kind.at(&created.item_id());
            let reply = api.delete(&path, created.etag.as_deref()).await;
            reply.assert_write(200);
            assert!(
                reply.item()["meta"]["deleted"]["at"].is_string(),
                "{}",
                kind.noun
            );
            assert!(reply.revision() > created.revision());
            // Still readable, with the mark.
            let got = api.get(&path).await;
            got.assert_json(200);
            assert_eq!(got.etag, reply.etag);
            assert_eq!(&got.body, reply.item());
            // The name is free again.
            api.create(kind.collection, &(kind.body)(1)).await;
        }
    }

    #[tokio::test]
    async fn a_deleted_object_can_be_neither_deleted_nor_changed() {
        let api = Api::new();
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            let path = kind.at(&created.item_id());
            api.delete(&path, None).await.assert_write(200);
            let again = api.delete(&path, None).await;
            again.assert_problem(409, "ipam.object_deleted");
            assert_eq!(again.body["params"]["kind"], kind.noun);
            api.patch(&path, None, &json!({ "description": "x" }))
                .await
                .assert_problem(409, "ipam.object_deleted");
        }
    }

    #[tokio::test]
    async fn what_is_in_use_cannot_be_deleted() {
        let api = Api::new();
        let tenant = api.create("/tenants", &tenant_body(1)).await;
        let tenant_path = format!("/tenants/{}", tenant["id"].as_str().expect("id"));
        let vrf = api
            .create(
                "/vrfs",
                &json!({ "name": label("vrf", 1), "tenant": tenant["id"] }),
            )
            .await;
        let blocked = api.delete(&tenant_path, None).await;
        blocked.assert_problem(409, "ipam.in_use");
        assert_eq!(blocked.body["params"]["by"], "VRFs");
        assert_eq!(blocked.body["params"]["count"], "1");
        assert_eq!(blocked.body["params"]["kind"], "tenant");

        let vrf_id = vrf["id"].as_str().expect("id");
        api.make_prefix(Some(vrf_id), "192.0.2.0/24").await;
        let vrf_path = format!("/vrfs/{vrf_id}");
        let blocked = api.delete(&vrf_path, None).await;
        blocked.assert_problem(409, "ipam.in_use");
        assert_eq!(blocked.body["params"]["by"], "prefixes");

        let site = api.create("/sites", &site_body(1)).await;
        let site_id = site["id"].as_str().expect("id");
        let site_path = format!("/sites/{site_id}");
        let child = api
            .create(
                "/sites",
                &json!({ "name": label("site", 2), "parent": site_id }),
            )
            .await;
        let vlan = api
            .create(
                "/vlans",
                &json!({ "vid": 20, "name": label("vlan", 1), "site": site_id }),
            )
            .await;
        let blocked = api.delete(&site_path, None).await;
        blocked.assert_problem(409, "ipam.in_use");
        assert_eq!(blocked.body["params"]["by"], "sites");
        api.delete(
            &format!("/sites/{}", child["id"].as_str().expect("id")),
            None,
        )
        .await
        .assert_write(200);
        let blocked = api.delete(&site_path, None).await;
        assert_eq!(blocked.body["params"]["by"], "VLANs");
        api.delete(
            &format!("/vlans/{}", vlan["id"].as_str().expect("id")),
            None,
        )
        .await
        .assert_write(200);
        api.delete(&site_path, None).await.assert_write(200);
        // Nothing was deleted by the refusals.
        assert_eq!(
            api.get(&tenant_path).await.body["meta"]["deleted"],
            Value::Null
        );
        assert_eq!(
            api.get(&vrf_path).await.body["meta"]["deleted"],
            Value::Null
        );
    }

    // Conflicts and references.

    #[tokio::test]
    async fn names_are_unique_ignoring_case() {
        let api = Api::new();
        for kind in [KINDS[0], KINDS[2]] {
            let first = api.create(kind.collection, &(kind.body)(1)).await;
            let upper = label(kind.noun, 1).to_uppercase();
            let duplicate = api.post(kind.collection, &json!({ "name": upper })).await;
            duplicate.assert_problem(409, "ipam.name_taken");
            assert_eq!(duplicate.body["params"]["kind"], kind.noun);
            assert_eq!(duplicate.body["params"]["name"], upper);
            assert_eq!(duplicate.body["errors"][0]["field"], "name");
            // A rename onto an existing name is refused as well.
            let second = api.create(kind.collection, &(kind.body)(2)).await;
            let rename = api
                .patch(
                    &kind.at(second["id"].as_str().expect("id")),
                    None,
                    &json!({ "name": label(kind.noun, 1) }),
                )
                .await;
            rename.assert_problem(409, "ipam.name_taken");
            assert_eq!(api.get(kind.collection).await.items().len(), 2);
            assert_eq!(first["name"], label(kind.noun, 1));
        }
    }

    #[tokio::test]
    async fn vrf_names_are_unique_within_a_tenant() {
        let api = Api::new();
        let one = api.create("/tenants", &tenant_body(1)).await;
        let two = api.create("/tenants", &tenant_body(2)).await;
        let body = |tenant: &Value| json!({ "name": label("vrf", 1), "tenant": tenant["id"] });
        api.create("/vrfs", &body(&one)).await;
        api.post("/vrfs", &body(&one))
            .await
            .assert_problem(409, "ipam.name_taken");
        api.create("/vrfs", &body(&two)).await;
        // Without a tenant the VRF lands in the tenant `default`.
        let plain = api.create("/vrfs", &vrf_body(1)).await;
        let tenants = api.get("/tenants").await;
        assert_eq!(tenants.items().len(), 3);
        assert!(tenants.texts("name").contains(&"default".to_owned()));
        assert!(
            tenants
                .ids()
                .contains(&plain["tenant"].as_str().expect("tenant").to_owned())
        );
    }

    #[tokio::test]
    async fn vlan_ids_are_unique_per_site() {
        let api = Api::new();
        let site = api.create("/sites", &site_body(1)).await;
        let other = api.create("/sites", &site_body(2)).await;
        let at = |site: &Value, vid: u16| json!({ "vid": vid, "name": label("vlan", usize::from(vid)), "site": site["id"] });
        api.create("/vlans", &at(&site, 30)).await;
        let duplicate = api.post("/vlans", &at(&site, 30)).await;
        duplicate.assert_problem(409, "ipam.vlan.duplicate");
        assert_eq!(duplicate.body["params"]["vid"], "30");
        assert_eq!(duplicate.body["errors"][0]["field"], "vid");
        api.create("/vlans", &at(&other, 30)).await;
        let global = json!({ "vid": 30, "name": label("vlan", 99) });
        api.create("/vlans", &global).await;
        api.post("/vlans", &global)
            .await
            .assert_problem(409, "ipam.vlan.duplicate");
        // Moving a VLAN onto an id that the site has is refused too.
        let thirty_one = api.create("/vlans", &at(&site, 31)).await;
        let moved = api
            .patch(
                &format!("/vlans/{}", thirty_one["id"].as_str().expect("id")),
                None,
                &json!({ "vid": 30 }),
            )
            .await;
        moved.assert_problem(409, "ipam.vlan.duplicate");
    }

    #[tokio::test]
    async fn a_vlan_id_or_vni_out_of_range_is_a_400() {
        let api = Api::new();
        for vid in [0, 4095] {
            let reply = api
                .post("/vlans", &json!({ "vid": vid, "name": label("vlan", 1) }))
                .await;
            reply.assert_problem(400, "ipam.validation");
            assert_eq!(reply.body["params"]["field"], "vid");
            assert_eq!(reply.body["errors"][0]["field"], "vid");
        }
        let vni = json!({ "vid": 10, "name": label("vlan", 1), "vni": 16_777_216 });
        let reply = api.post("/vlans", &vni).await;
        reply.assert_problem(400, "ipam.validation");
        assert_eq!(reply.body["params"]["field"], "vni");
        let blank = api.post("/tenants", &json!({ "name": "   " })).await;
        blank.assert_problem(400, "ipam.validation");
        assert_eq!(blank.body["errors"][0]["field"], "name");
        api.get("/vlans").await.assert_no_items();
    }

    #[tokio::test]
    async fn references_must_exist_and_be_live() {
        let api = Api::new();
        let missing = unknown_id();
        let cases = [
            (
                "/vrfs",
                json!({ "name": label("vrf", 1), "tenant": missing }),
                "tenant",
            ),
            (
                "/sites",
                json!({ "name": label("site", 1), "parent": missing }),
                "parent",
            ),
            (
                "/vlans",
                json!({ "vid": 5, "name": label("vlan", 1), "site": missing }),
                "site",
            ),
        ];
        for (path, body, field) in cases {
            let reply = api.post(path, &body).await;
            reply.assert_problem(409, "ipam.reference_missing");
            assert_eq!(reply.body["params"]["field"], field);
            assert_eq!(reply.body["params"]["id"], missing);
        }
        // A deleted tenant is as good as none.
        let tenant = api.create("/tenants", &tenant_body(1)).await;
        let tenant_id = tenant["id"].as_str().expect("id");
        api.delete(&format!("/tenants/{tenant_id}"), None)
            .await
            .assert_write(200);
        api.post(
            "/vrfs",
            &json!({ "name": label("vrf", 1), "tenant": tenant_id }),
        )
        .await
        .assert_problem(409, "ipam.reference_missing");
        // A patch may not point a site at a missing parent either.
        let site = api.create("/sites", &site_body(1)).await;
        api.patch(
            &format!("/sites/{}", site["id"].as_str().expect("id")),
            None,
            &json!({ "parent": missing }),
        )
        .await
        .assert_problem(409, "ipam.reference_missing");
    }

    #[tokio::test]
    async fn a_site_cannot_become_its_own_ancestor() {
        let api = Api::new();
        let top = api.create("/sites", &site_body(1)).await;
        let top_id = top["id"].as_str().expect("id");
        let child = api
            .create(
                "/sites",
                &json!({ "name": label("site", 2), "parent": top_id }),
            )
            .await;
        let cycle = api
            .patch(
                &format!("/sites/{top_id}"),
                None,
                &json!({ "parent": child["id"] }),
            )
            .await;
        cycle.assert_problem(409, "ipam.site.cycle");
        assert_eq!(cycle.body["errors"][0]["field"], "parent");
        api.patch(
            &format!("/sites/{top_id}"),
            None,
            &json!({ "parent": top_id }),
        )
        .await
        .assert_problem(409, "ipam.site.cycle");
    }

    #[tokio::test]
    async fn a_vlan_status_follows_the_allowed_transitions() {
        let api = Api::new();
        let vlan = api.create("/vlans", &vlan_body(1)).await;
        let path = format!("/vlans/{}", vlan["id"].as_str().expect("id"));
        let back = api
            .patch(&path, None, &json!({ "status": "planned" }))
            .await;
        back.assert_problem(409, "ipam.status.transition");
        assert_eq!(back.body["params"]["from"], "active");
        assert_eq!(back.body["params"]["to"], "planned");
        api.patch(&path, None, &json!({ "status": "deprecated" }))
            .await
            .assert_write(200);
    }

    // Idempotency.

    #[tokio::test]
    async fn a_repeated_idempotency_key_returns_the_first_result() {
        let api = Api::new();
        for kind in KINDS {
            let key = format!("create-{}", kind.noun);
            let headers = [("idempotency-key", key.as_str())];
            let first = api
                .post_with(kind.collection, &headers, &(kind.body)(1))
                .await;
            first.assert_write(201);
            let replay = api
                .post_with(kind.collection, &headers, &(kind.body)(1))
                .await;
            replay.assert_json(200);
            assert_eq!(replay.body["replayed"], true, "{}", kind.noun);
            assert_eq!(replay.body["job_id"], Value::Null);
            assert_eq!(replay.body["dry_run"], false);
            assert_eq!(replay.item(), first.item());
            assert_eq!(replay.body["revision"], first.body["revision"]);
            assert_eq!(replay.etag, first.etag);
            assert_eq!(api.get(kind.collection).await.items().len(), 1);
            let other = api
                .post_with(kind.collection, &headers, &(kind.body)(2))
                .await;
            other.assert_problem(422, "ipam.idempotency_mismatch");
            assert_eq!(api.get(kind.collection).await.items().len(), 1);
        }
    }

    #[tokio::test]
    async fn an_invalid_idempotency_key_is_refused() {
        let api = Api::new();
        let reply = api
            .post_with(
                "/tenants",
                &[("idempotency-key", "has space")],
                &tenant_body(1),
            )
            .await;
        assert_eq!(reply.status, 400, "{}", reply.body);
        api.get("/tenants").await.assert_no_items();
    }

    // Availability and authorization.

    #[tokio::test]
    async fn without_the_ipam_service_every_endpoint_is_a_503() {
        let api = Api::unavailable();
        for kind in KINDS {
            let path = kind.at(&unknown_id());
            let replies = [
                api.get(kind.collection).await,
                api.post(kind.collection, &(kind.body)(1)).await,
                api.get(&path).await,
                api.patch(&path, None, &json!({})).await,
                api.delete(&path, None).await,
            ];
            for reply in replies {
                reply.assert_problem(503, "ipam.unavailable");
            }
        }
    }

    #[tokio::test]
    async fn a_principal_that_may_do_nothing_gets_403_on_writes_and_empty_lists() {
        let api = Api::new();
        let denied = api.sibling(AppState {
            authorizer: Some(Policy::new(false, false)),
            ..AppState::default()
        });
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            let path = kind.at(&created.item_id());
            let list = denied.get(kind.collection).await;
            list.assert_json(200);
            assert_eq!(list.body["items"], json!([]));
            assert_eq!(list.body["next_cursor"], Value::Null);
            assert!(list.body["revision"].is_u64());
            let replies = [
                (denied.get(&path).await, "read"),
                (
                    denied.post(kind.collection, &(kind.body)(2)).await,
                    "create",
                ),
                (
                    denied
                        .patch(&path, None, &json!({ "description": "x" }))
                        .await,
                    "update",
                ),
                (denied.delete(&path, None).await, "delete"),
            ];
            for (reply, action) in replies {
                reply.assert_problem(403, "auth.forbidden");
                assert_eq!(reply.body["params"]["action"], action, "{}", kind.noun);
            }
            // Dry runs are writes as far as permissions go.
            denied
                .post(
                    &format!("{}?dry_run=true", kind.collection),
                    &(kind.body)(2),
                )
                .await
                .assert_problem(403, "auth.forbidden");
            let got = api.get(&path).await;
            assert_eq!(got.etag, created.etag, "{}", kind.noun);
            assert_eq!(api.get(kind.collection).await.items().len(), 1);
        }
    }

    #[tokio::test]
    async fn a_read_only_principal_reads_and_cannot_write() {
        let api = Api::new();
        let reader = api.sibling(AppState {
            authorizer: Some(Policy::new(true, false)),
            ..AppState::default()
        });
        for kind in KINDS {
            let created = api.post(kind.collection, &(kind.body)(1)).await;
            let path = kind.at(&created.item_id());
            assert_eq!(reader.get(kind.collection).await.items().len(), 1);
            assert_eq!(reader.get(&path).await.etag, created.etag);
            reader
                .post(kind.collection, &(kind.body)(2))
                .await
                .assert_problem(403, "auth.forbidden");
            reader
                .delete(&path, None)
                .await
                .assert_problem(403, "auth.forbidden");
        }
    }

    #[tokio::test]
    async fn each_endpoint_asks_for_the_action_on_the_object() {
        let policy = Policy::new(true, true);
        let api = Api::with_authorizer(policy.clone());
        let created = api.post("/tenants", &tenant_body(1)).await;
        let id: TenantId = created.item_id().parse().expect("tenant id");
        let object = ObjectRef::from(id);
        let path = format!("/tenants/{id}");
        api.get(&path).await.assert_json(200);
        api.patch(&path, None, &json!({ "description": "x" }))
            .await
            .assert_write(200);
        api.delete(&path, None).await.assert_write(200);
        let singleton = ObjectRef::singleton(ObjectKind::Tenant);
        assert_eq!(
            policy.asked(),
            [
                (Action::Create, singleton),
                (Action::Read, object),
                (Action::Update, object),
                (Action::Delete, object),
            ]
        );
    }
}
