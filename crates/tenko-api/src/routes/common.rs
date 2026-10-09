//! Change history, restore, bulk changes, tags, custom fields and search.
//!
//! Area: common. Owner: WP1.4. Requirements: IPAM-08, IPAM-09, API-04.
//!
//! `GET /{collection}/{id}/history`, `POST /{collection}/{id}/restore` and
//! `POST /{collection}/bulk` exist for tenants, VRFs, sites, VLANs, prefixes, ranges,
//! addresses, hosts and interfaces. The three stubs of one collection come from
//! `collection_stubs!`; WP1.4 replaces them with generic handlers.

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_tenant_history))
        .routes(routes!(restore_tenant))
        .routes(routes!(bulk_tenants))
        .routes(routes!(get_vrf_history))
        .routes(routes!(restore_vrf))
        .routes(routes!(bulk_vrfs))
        .routes(routes!(get_site_history))
        .routes(routes!(restore_site))
        .routes(routes!(bulk_sites))
        .routes(routes!(get_vlan_history))
        .routes(routes!(restore_vlan))
        .routes(routes!(bulk_vlans))
        .routes(routes!(get_prefix_history))
        .routes(routes!(restore_prefix))
        .routes(routes!(bulk_prefixes))
        .routes(routes!(get_range_history))
        .routes(routes!(restore_range))
        .routes(routes!(bulk_ranges))
        .routes(routes!(get_address_history))
        .routes(routes!(restore_address))
        .routes(routes!(bulk_addresses))
        .routes(routes!(get_host_history))
        .routes(routes!(restore_host))
        .routes(routes!(bulk_hosts))
        .routes(routes!(get_interface_history))
        .routes(routes!(restore_interface))
        .routes(routes!(bulk_interfaces))
        .routes(routes!(list_tags))
        .routes(routes!(list_custom_fields, create_custom_field))
        .routes(routes!(
            get_custom_field,
            update_custom_field,
            delete_custom_field
        ))
        .routes(routes!(search))
}

/// Declares the history, restore and bulk stubs of one collection. The path and the
/// operation id are built from the collection name with `concat!` and `stringify!`; the
/// OpenAPI document and the tests show the resulting literals.
macro_rules! collection_stubs {
    (
        $noun:literal, $collection:ident,
        history: $history:ident, restore: $restore:ident, bulk: $bulk:ident
    ) => {
        #[utoipa::path(
            get,
            path = concat!("/", stringify!($collection), "/{id}/history"),
            tag = "common",
            operation_id = stringify!($history),
            summary = concat!("Get the change history of one ", $noun),
            params(("id" = String, Path, description = concat!("Identifier of the ", $noun))),
            responses(
                (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
            )
        )]
        async fn $history(_ctx: Ctx) -> ApiError {
            not_implemented("GET", concat!("/", stringify!($collection), "/{id}/history"))
        }

        #[utoipa::path(
            post,
            path = concat!("/", stringify!($collection), "/{id}/restore"),
            tag = "common",
            operation_id = stringify!($restore),
            summary = concat!("Restore one deleted ", $noun),
            params(("id" = String, Path, description = concat!("Identifier of the ", $noun))),
            responses(
                (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
            )
        )]
        async fn $restore(_ctx: Ctx) -> ApiError {
            not_implemented("POST", concat!("/", stringify!($collection), "/{id}/restore"))
        }

        #[utoipa::path(
            post,
            path = concat!("/", stringify!($collection), "/bulk"),
            tag = "common",
            operation_id = stringify!($bulk),
            summary = concat!("Change several ", stringify!($collection), " in one request"),
            responses(
                (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
            )
        )]
        async fn $bulk(_ctx: Ctx) -> ApiError {
            not_implemented("POST", concat!("/", stringify!($collection), "/bulk"))
        }
    };
}

collection_stubs! {
    "tenant", tenants,
    history: get_tenant_history, restore: restore_tenant, bulk: bulk_tenants
}
collection_stubs! {
    "VRF", vrfs,
    history: get_vrf_history, restore: restore_vrf, bulk: bulk_vrfs
}
collection_stubs! {
    "site", sites,
    history: get_site_history, restore: restore_site, bulk: bulk_sites
}
collection_stubs! {
    "VLAN", vlans,
    history: get_vlan_history, restore: restore_vlan, bulk: bulk_vlans
}
collection_stubs! {
    "prefix", prefixes,
    history: get_prefix_history, restore: restore_prefix, bulk: bulk_prefixes
}
collection_stubs! {
    "range", ranges,
    history: get_range_history, restore: restore_range, bulk: bulk_ranges
}
collection_stubs! {
    "address", addresses,
    history: get_address_history, restore: restore_address, bulk: bulk_addresses
}
collection_stubs! {
    "host", hosts,
    history: get_host_history, restore: restore_host, bulk: bulk_hosts
}
collection_stubs! {
    "interface", interfaces,
    history: get_interface_history, restore: restore_interface, bulk: bulk_interfaces
}

#[utoipa::path(
    get,
    path = "/tags",
    tag = "common",
    operation_id = "list_tags",
    summary = "List the tags in use",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_tags(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/tags")
}

#[utoipa::path(
    get,
    path = "/custom-fields",
    tag = "common",
    operation_id = "list_custom_fields",
    summary = "List custom field definitions",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_custom_fields(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/custom-fields")
}

#[utoipa::path(
    post,
    path = "/custom-fields",
    tag = "common",
    operation_id = "create_custom_field",
    summary = "Create a custom field definition",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_custom_field(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/custom-fields")
}

#[utoipa::path(
    get,
    path = "/custom-fields/{key}",
    tag = "common",
    operation_id = "get_custom_field",
    summary = "Get one custom field definition",
    params(("key" = String, Path, description = "Key of the custom field")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_custom_field(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/custom-fields/{key}")
}

#[utoipa::path(
    patch,
    path = "/custom-fields/{key}",
    tag = "common",
    operation_id = "update_custom_field",
    summary = "Update a custom field definition",
    params(("key" = String, Path, description = "Key of the custom field")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_custom_field(_ctx: Ctx) -> ApiError {
    not_implemented("PATCH", "/custom-fields/{key}")
}

#[utoipa::path(
    delete,
    path = "/custom-fields/{key}",
    tag = "common",
    operation_id = "delete_custom_field",
    summary = "Delete a custom field definition",
    params(("key" = String, Path, description = "Key of the custom field")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_custom_field(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/custom-fields/{key}")
}

#[utoipa::path(
    get,
    path = "/search",
    tag = "common",
    operation_id = "search",
    summary = "Search prefixes, addresses and hosts",
    params(("q" = String, Query, description = "Search text")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn search(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/search")
}
