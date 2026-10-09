//! Tenants, VRFs, sites and VLANs.
//!
//! Area: tenancy. Owner: WP1.4. Requirements: IPAM-01, IPAM-03, IPAM-04.
//!
//! Create, read, update and soft-delete for the four containers of the IPAM model. History,
//! restore and bulk changes of these collections are in [`super::common`].

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
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

#[utoipa::path(
    get,
    path = "/tenants",
    tag = "tenancy",
    operation_id = "list_tenants",
    summary = "List tenants",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_tenants(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/tenants")
}

#[utoipa::path(
    post,
    path = "/tenants",
    tag = "tenancy",
    operation_id = "create_tenant",
    summary = "Create a tenant",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_tenant(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/tenants")
}

#[utoipa::path(
    get,
    path = "/tenants/{id}",
    tag = "tenancy",
    operation_id = "get_tenant",
    summary = "Get one tenant",
    params(("id" = String, Path, description = "Tenant identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_tenant(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/tenants/{id}")
}

#[utoipa::path(
    patch,
    path = "/tenants/{id}",
    tag = "tenancy",
    operation_id = "update_tenant",
    summary = "Update a tenant",
    params(("id" = String, Path, description = "Tenant identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_tenant(_ctx: Ctx) -> ApiError {
    not_implemented("PATCH", "/tenants/{id}")
}

#[utoipa::path(
    delete,
    path = "/tenants/{id}",
    tag = "tenancy",
    operation_id = "delete_tenant",
    summary = "Delete a tenant",
    params(("id" = String, Path, description = "Tenant identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_tenant(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/tenants/{id}")
}

#[utoipa::path(
    get,
    path = "/vrfs",
    tag = "tenancy",
    operation_id = "list_vrfs",
    summary = "List VRFs",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_vrfs(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/vrfs")
}

#[utoipa::path(
    post,
    path = "/vrfs",
    tag = "tenancy",
    operation_id = "create_vrf",
    summary = "Create a VRF",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_vrf(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/vrfs")
}

#[utoipa::path(
    get,
    path = "/vrfs/{id}",
    tag = "tenancy",
    operation_id = "get_vrf",
    summary = "Get one VRF",
    params(("id" = String, Path, description = "VRF identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_vrf(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/vrfs/{id}")
}

#[utoipa::path(
    patch,
    path = "/vrfs/{id}",
    tag = "tenancy",
    operation_id = "update_vrf",
    summary = "Update a VRF",
    params(("id" = String, Path, description = "VRF identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_vrf(_ctx: Ctx) -> ApiError {
    not_implemented("PATCH", "/vrfs/{id}")
}

#[utoipa::path(
    delete,
    path = "/vrfs/{id}",
    tag = "tenancy",
    operation_id = "delete_vrf",
    summary = "Delete a VRF",
    params(("id" = String, Path, description = "VRF identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_vrf(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/vrfs/{id}")
}

#[utoipa::path(
    get,
    path = "/sites",
    tag = "tenancy",
    operation_id = "list_sites",
    summary = "List sites",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_sites(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/sites")
}

#[utoipa::path(
    post,
    path = "/sites",
    tag = "tenancy",
    operation_id = "create_site",
    summary = "Create a site",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_site(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/sites")
}

#[utoipa::path(
    get,
    path = "/sites/{id}",
    tag = "tenancy",
    operation_id = "get_site",
    summary = "Get one site",
    params(("id" = String, Path, description = "Site identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_site(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/sites/{id}")
}

#[utoipa::path(
    patch,
    path = "/sites/{id}",
    tag = "tenancy",
    operation_id = "update_site",
    summary = "Update a site",
    params(("id" = String, Path, description = "Site identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_site(_ctx: Ctx) -> ApiError {
    not_implemented("PATCH", "/sites/{id}")
}

#[utoipa::path(
    delete,
    path = "/sites/{id}",
    tag = "tenancy",
    operation_id = "delete_site",
    summary = "Delete a site",
    params(("id" = String, Path, description = "Site identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_site(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/sites/{id}")
}

#[utoipa::path(
    get,
    path = "/vlans",
    tag = "tenancy",
    operation_id = "list_vlans",
    summary = "List VLANs",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_vlans(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/vlans")
}

#[utoipa::path(
    post,
    path = "/vlans",
    tag = "tenancy",
    operation_id = "create_vlan",
    summary = "Create a VLAN",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_vlan(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/vlans")
}

#[utoipa::path(
    get,
    path = "/vlans/{id}",
    tag = "tenancy",
    operation_id = "get_vlan",
    summary = "Get one VLAN",
    params(("id" = String, Path, description = "VLAN identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_vlan(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/vlans/{id}")
}

#[utoipa::path(
    patch,
    path = "/vlans/{id}",
    tag = "tenancy",
    operation_id = "update_vlan",
    summary = "Update a VLAN",
    params(("id" = String, Path, description = "VLAN identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_vlan(_ctx: Ctx) -> ApiError {
    not_implemented("PATCH", "/vlans/{id}")
}

#[utoipa::path(
    delete,
    path = "/vlans/{id}",
    tag = "tenancy",
    operation_id = "delete_vlan",
    summary = "Delete a VLAN",
    params(("id" = String, Path, description = "VLAN identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_vlan(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/vlans/{id}")
}
