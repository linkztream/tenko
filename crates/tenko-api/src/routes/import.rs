//! Import of spreadsheets and CSV files.
//!
//! Area: import. Owner: WP1.5. Requirements: IPAM-11, MIG-14.
//!
//! The flow is upload, mapping, preview, apply. The upload returns the sheets, the columns
//! with samples and a suggested mapping; the preview returns the summary, the rows and the
//! loss report; the apply returns `202` with a job.

use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The multipart form of `POST /imports`.
#[derive(ToSchema)]
pub struct ImportUpload {
    /// The spreadsheet or CSV file. Uploads are staged for 24 hours and limited to 20 MB.
    #[schema(value_type = String, format = Binary)]
    pub file: Vec<u8>,
}

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(create_import))
        .routes(routes!(get_import, delete_import))
        .routes(routes!(set_import_mapping))
        .routes(routes!(preview_import))
        .routes(routes!(apply_import))
}

#[utoipa::path(
    post,
    path = "/imports",
    tag = "import",
    operation_id = "create_import",
    summary = "Upload a file to import",
    request_body(content = ImportUpload, content_type = "multipart/form-data"),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_import(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/imports")
}

#[utoipa::path(
    get,
    path = "/imports/{id}",
    tag = "import",
    operation_id = "get_import",
    summary = "Get an upload with its sheets, columns and suggested mapping",
    params(("id" = String, Path, description = "Import identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_import(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/imports/{id}")
}

#[utoipa::path(
    delete,
    path = "/imports/{id}",
    tag = "import",
    operation_id = "delete_import",
    summary = "Discard an upload",
    params(("id" = String, Path, description = "Import identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_import(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/imports/{id}")
}

#[utoipa::path(
    put,
    path = "/imports/{id}/mapping",
    tag = "import",
    operation_id = "set_import_mapping",
    summary = "Set the column mapping, transforms and conflict policy",
    params(("id" = String, Path, description = "Import identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn set_import_mapping(_ctx: Ctx) -> ApiError {
    not_implemented("PUT", "/imports/{id}/mapping")
}

#[utoipa::path(
    get,
    path = "/imports/{id}/preview",
    tag = "import",
    operation_id = "preview_import",
    summary = "Preview the changes of an import: summary, rows and loss report",
    params(("id" = String, Path, description = "Import identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn preview_import(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/imports/{id}/preview")
}

#[utoipa::path(
    post,
    path = "/imports/{id}/apply",
    tag = "import",
    operation_id = "apply_import",
    summary = "Apply an import as a job",
    params(("id" = String, Path, description = "Import identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn apply_import(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/imports/{id}/apply")
}
