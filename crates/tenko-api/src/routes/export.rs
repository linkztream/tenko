//! CSV export in the import vocabulary.
//!
//! Area: export. Owner: WP1.5. Requirements: IPAM-11, MIG-14.
//!
//! The exported columns use the names the importer suggests, so an export can be imported
//! again without changes (the round trip of IPAM-11).

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(export_prefixes_csv))
        .routes(routes!(export_addresses_csv))
        .routes(routes!(export_hosts_csv))
}

#[utoipa::path(
    get,
    path = "/exports/prefixes.csv",
    tag = "export",
    operation_id = "export_prefixes_csv",
    summary = "Export prefixes as CSV",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn export_prefixes_csv(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/exports/prefixes.csv")
}

#[utoipa::path(
    get,
    path = "/exports/addresses.csv",
    tag = "export",
    operation_id = "export_addresses_csv",
    summary = "Export addresses as CSV",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn export_addresses_csv(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/exports/addresses.csv")
}

#[utoipa::path(
    get,
    path = "/exports/hosts.csv",
    tag = "export",
    operation_id = "export_hosts_csv",
    summary = "Export hosts as CSV",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn export_hosts_csv(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/exports/hosts.csv")
}
