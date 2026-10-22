//! Import of spreadsheets and CSV files.
//!
//! Area: import. Owner: WP1.5. Requirements: IPAM-11, MIG-14.
//!
//! The flow is upload, mapping, preview, apply. The upload returns the sheets, the columns
//! with samples and a suggested mapping; the preview returns the summary, the rows and the
//! loss report; the apply returns `202` with a job. The rules of the import (what is read,
//! how it is mapped, what the loss report says, how credentials are treated) are in
//! [`tenko_ipam::import`]; this file is the HTTP face of [`ImportService`].
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `POST /imports` | 201 [`ImportView`] with `Location` | 400 `import.upload.empty`, `import.upload.malformed`, 413 `import.upload.too_large`, 415 `import.upload.unsupported`, 422 `import.upload.unreadable` |
//! | `GET /imports/{id}` | 200 [`ImportView`] | 404 `import.not_found`, 410 `import.expired`, `import.upload.lost` |
//! | `PUT /imports/{id}/mapping` | 200 [`ImportView`] with `mapped: true` | 404, 409 `import.state.conflict`, 410, 422 `import.mapping.invalid` |
//! | `GET /imports/{id}/preview?rows=N` | 200 [`ImportPreview`] | 400 `sys.invalid_query`, 404, 410 |
//! | `POST /imports/{id}/apply` | 202 [`ApplyAccepted`] with `Location: /api/v1/jobs/{job}` | 403 `import.credentials.vault_required`, 404, 409 `import.plan.blocked`, `import.state.conflict`, 410 |
//! | `DELETE /imports/{id}` | 204 | 404, 409 `import.state.conflict`, 410 |
//!
//! # Conventions
//!
//! - **Service.** The import service is a request extension `Arc<ImportService>` that the
//!   server adds (`.layer(Extension(service))`); without it every endpoint answers 503
//!   `import.unavailable`.
//! - **Authorization.** With an [`Authorizer`](tenko_core::Authorizer) in the state, an
//!   upload needs [`Action::Create`] on the kind [`ObjectKind::Import`], reading an import
//!   or its preview [`Action::Read`], the mapping [`Action::Update`], the apply
//!   [`Action::Execute`] and the delete [`Action::Delete`], all on the import itself. The
//!   service additionally shows an import only to the person (or token) that uploaded it.
//!   Credential columns need more than that (IAM-07): `preview` and `apply` pass the
//!   outcome of [`credential_gate`] to the service, which refuses to store operator secrets
//!   (403 `import.credentials.vault_required`) for an account that may not hold them. The
//!   gate also applies the cluster-wide rule of `POST /secrets`: while another enabled
//!   account that may reveal secrets signs in with a PIN alone, the credential columns are
//!   refused with the reason `pin_coupling` (IAM-07).
//! - **Idempotency.** `POST /imports/{id}/apply` takes `Idempotency-Key`; the job engine
//!   returns the first job again for a repeated key.
//!
//! # Credentials
//!
//! Credential columns (login, password) are never IPAM fields. Each host's login and
//! password become one operator secret of that host in the vault. Apply refuses them with
//! 403 `import.credentials.vault_required` unless the server has a vault and the principal
//! passes both [`Action::Create`] and [`Action::Reveal`] on [`ObjectKind::Secret`]; in
//! practice that is an administrator with a session of password strength or stronger (the
//! IAM-07 threshold). The problem carries the parameter `reason`, one of `vault_unavailable`
//! (the server has no vault), `step_up_required`, `forbidden`, `unauthenticated` or
//! `pin_coupling`, for a step-up the parameter `required`, the weakest session strength that
//! would do, and for `pin_coupling` the parameter `accounts`, the names of the accounts that
//! may reveal but sign in with a PIN alone. Setting
//! `options.credentials` to `skip` in the mapping leaves the credential columns out, and
//! the rest of the import goes ahead. The preview says in plain words what would happen to
//! the credentials (`credentials.statement`, `credentials.allowed` and `credentials.reason`)
//! and lists `import.credentials.vault_required` among the `blockers` of apply.
//!
//! # Upload
//!
//! The body is `multipart/form-data` with one or more file parts; every part that carries a
//! `filename` is a file (the field is conventionally `file` or `files`), and parts without
//! one are form fields that are ignored. The file name has its directory part removed (the
//! `\` of Windows clients included) and `filename*=UTF-8''...` (RFC 5987) wins over
//! `filename`. Several files form one import: the files of a CSV export, for example.
//!
//! The body is read here, not by an extractor, so the 2 MiB default body limit of axum does
//! not apply (the route disables it as well). The limit is `max_upload` of the import
//! configuration plus 1 MiB for the multipart framing: a declared `Content-Length` above it
//! is refused before any byte is read, and a body without a length is counted while it
//! streams in and refused at the limit, in both cases with 413 `import.upload.too_large`.
//! The service then applies `max_upload` to the file bytes themselves. The multipart parser
//! ([`parse_multipart`]) is small and strict: it needs the boundary of the content type,
//! CRLF line ends and a closing delimiter, and answers 400 `import.upload.malformed`
//! otherwise.
//!
//! A request with an `Idempotency-Key` is buffered by the idempotency middleware first,
//! which has its own, much smaller limit; send uploads without a key.
//!
//! # Apply
//!
//! The body of `POST /imports/{id}/apply` is optional: nothing (or only whitespace) means
//! `{}`. `acknowledge` lists plan warning codes the person accepts in addition to the ones
//! in the mapping options. The answer is the job to follow at `/jobs/{id}`; the import
//! shows it as `job_id`.

use std::sync::Arc;

use axum::{
    Extension, Json,
    body::Body,
    extract::{DefaultBodyLimit, FromRequest, FromRequestParts, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use serde::{Serialize, de::DeserializeOwned};
use tenko_auth::AuthService;
use tenko_core::{Action, CodedError, ImportId, ObjectKind, ObjectRef, Principal};
use tenko_ipam::import::{
    ApplyAccepted, ApplyRequest, CredentialGate, ImportPreview, ImportService, ImportView, Mapping,
    Upload, codes as import_codes, credential_gate, dto::PreviewRow,
};
use utoipa::ToSchema;
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt},
    routes,
};

use super::{
    auth::RouteError,
    common::{IdempotencyKeyHeader, IpamJson, IpamPath},
};
use crate::{
    API_BASE,
    extract::Ctx,
    list::{CursorScope, Filters, MAX_LIMIT, decode_cursor, encode_cursor},
    problem::{ApiError, ProblemDetails, codes as api_codes},
    state::AppState,
};

type Auth = Option<Extension<Arc<AuthService>>>;

/// Room for the multipart framing (boundaries, part headers, form fields) on top of the
/// file bytes that `max_upload` limits.
const MULTIPART_OVERHEAD: usize = 1024 * 1024;

/// The largest body of an apply request (a list of warning codes).
const APPLY_BODY_LIMIT: usize = 256 * 1024;

/// The most rows `GET /imports/{id}/preview?rows=N` lists.
const MAX_PREVIEW_ROWS: usize = 1_000;

/// The page size of `GET /imports/{id}/rows` when `limit` is absent.
const DEFAULT_ROWS_PAGE: usize = 200;

/// A page of the rows of the latest preview of an import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ImportRowsPage {
    /// The rows of the page, in source order.
    pub items: Vec<PreviewRow>,
    /// The cursor of the next page; `null` after the last row.
    pub next_cursor: Option<String>,
    /// Rows in the whole preview.
    pub total_rows: u64,
    /// The store revision the preview was computed from.
    pub base_revision: u64,
}

/// The position a rows cursor carries: the mapping revision of the preview and the next
/// row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
struct RowsCursor {
    /// The mapping revision.
    r: u64,
    /// The position of the next row.
    o: usize,
}

/// The multipart form of `POST /imports`.
#[derive(ToSchema)]
pub struct ImportUpload {
    /// The spreadsheet or CSV files of one import: repeat the part for several files (for
    /// example the files of a CSV export). A part is a file when it has a `filename`. All
    /// files together are limited to 20 MB, and an upload is staged for 24 hours.
    #[schema(value_type = Vec<String>, format = Binary)]
    pub files: Vec<Vec<u8>>,
}

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(create_import).layer(DefaultBodyLimit::disable()))
        .routes(routes!(get_import, delete_import))
        .routes(routes!(set_import_mapping))
        .routes(routes!(preview_import))
        .routes(routes!(list_import_rows))
        .routes(routes!(apply_import))
}

// ===== endpoints =====================================================================

/// Uploads one or more files as `multipart/form-data` and answers the sheets, the columns
/// with samples and shapes, and the suggested mapping.
#[utoipa::path(
    post,
    path = "/imports",
    tag = "import",
    operation_id = "create_import",
    summary = "Upload a file to import",
    request_body(content = ImportUpload, content_type = "multipart/form-data"),
    responses(
        (status = 201, description = "The upload with its sheets, columns and suggested mapping", body = ImportView,
            headers(("Location" = String, description = "The URL of the new import"))),
        (status = 400, description = "No file in the upload, or the multipart body is malformed (`import.upload.empty`, `import.upload.malformed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "The upload exceeds the size limit (`import.upload.too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "A file is not CSV or a workbook (`import.upload.unsupported`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "A file cannot be read (`import.upload.unreadable`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Import not configured (`import.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_import(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Imports(imports): Imports,
    request: Request,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &ObjectRef::singleton(ObjectKind::Import),
    )?;
    let max_upload = imports.config().max_upload;
    let boundary = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(boundary_from_content_type)
        .ok_or_else(|| {
            malformed("the upload must be multipart/form-data with a boundary".to_owned())
        })?;
    let declared = content_length(request.headers());
    let limit = max_upload.saturating_add(MULTIPART_OVERHEAD);
    let body = read_body(request.into_body(), declared, limit)
        .await
        .map_err(|error| match error {
            BodyError::TooLarge => upload_too_large(max_upload),
            BodyError::Read => malformed("the request body could not be read".to_owned()),
        })?;
    let uploads: Vec<Upload> = parse_multipart(&body, &boundary)
        .map_err(|error| malformed(error.to_string()))?
        .into_iter()
        .map(|file| Upload {
            name: file.name,
            bytes: file.bytes.to_vec(),
        })
        .collect();
    drop(body);
    let view = imports.upload(&cx, uploads).await?;
    Ok(located(
        StatusCode::CREATED,
        &format!("{API_BASE}/imports/{}", view.id),
        &view,
    ))
}

/// Shows an upload: its files, sheets, columns, the mapping in force (the person's, else the
/// suggestion), the targets a column can map to and the state of the import.
#[utoipa::path(
    get,
    path = "/imports/{id}",
    tag = "import",
    operation_id = "get_import",
    summary = "Get an upload with its sheets, columns and suggested mapping",
    params(("id" = String, Path, description = "Import identifier")),
    responses(
        (status = 200, description = "The upload with its analysis and mapping", body = ImportView),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such import (`import.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "The upload expired or was lost in a restart (`import.expired`, `import.upload.lost`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Import not configured (`import.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_import(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Imports(imports): Imports,
    IpamPath(id): IpamPath<ImportId>,
) -> Result<Json<ImportView>, ApiError> {
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    Ok(Json(imports.get(&cx, id).await?))
}

/// Discards an upload and its staged files. An import whose apply job runs cannot be
/// discarded.
#[utoipa::path(
    delete,
    path = "/imports/{id}",
    tag = "import",
    operation_id = "delete_import",
    summary = "Discard an upload",
    params(("id" = String, Path, description = "Import identifier")),
    responses(
        (status = 204, description = "The upload is discarded"),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such import (`import.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The import is being applied (`import.state.conflict`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "The upload expired or was lost in a restart (`import.expired`, `import.upload.lost`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Import not configured (`import.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_import(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Imports(imports): Imports,
    IpamPath(id): IpamPath<ImportId>,
) -> Result<StatusCode, ApiError> {
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    imports.delete(&cx, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Stores the person's mapping after checking that it fits the upload: every sheet mapped
/// once, columns inside the sheet, a network for network sheets. The options carry the
/// conflict policy, the credential policy (`import` or `skip`), the VRF and tenant of items
/// that name none, the decisions on proposed prefixes and the acknowledged plan warnings.
#[utoipa::path(
    put,
    path = "/imports/{id}/mapping",
    tag = "import",
    operation_id = "set_import_mapping",
    summary = "Set the column mapping, transforms and conflict policy",
    params(("id" = String, Path, description = "Import identifier")),
    request_body = Mapping,
    responses(
        (status = 200, description = "The upload with the mapping in force (`mapped` is true)", body = ImportView),
        (status = 400, description = "The identifier is not a UUID, or the body is not valid JSON for a mapping (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such import (`import.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The import is being applied (`import.state.conflict`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "The upload expired or was lost in a restart (`import.expired`, `import.upload.lost`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The mapping does not fit the upload (`import.mapping.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Import not configured (`import.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn set_import_mapping(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Imports(imports): Imports,
    IpamPath(id): IpamPath<ImportId>,
    IpamJson(mapping): IpamJson<Mapping>,
) -> Result<Json<ImportView>, ApiError> {
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    Ok(Json(imports.set_mapping(&cx, id, mapping).await?))
}

/// Shows what an apply would do, without writing anything: counts per entity and action,
/// the first rows of the source, the loss report by sheet, row and column, the proposed
/// prefixes, the plain statement about credentials and whether apply is possible now.
/// `rows` limits the rows listed (1 to 1,000; the server default when absent).
///
/// Credential columns (login, password) are never IPAM fields: each host's login and
/// password would become one operator secret of that host in the vault. `credentials`
/// says how many secrets would be created, replaced or left as they are, whether this
/// account may store them (`allowed`) and, when it may not, why (`reason`); then
/// `import.credentials.vault_required` is among the `blockers`. Storing them needs a vault
/// on the server and a principal that passes both create and reveal on secrets, in practice
/// an administrator with a password-or-stronger session (IAM-07), and no other account that
/// may reveal secrets signing in with a PIN alone (`reason` `pin_coupling`, as for
/// `POST /secrets`). Setting `options.credentials` to `skip` in the mapping leaves them out.
#[utoipa::path(
    get,
    path = "/imports/{id}/preview",
    tag = "import",
    operation_id = "preview_import",
    summary = "Preview the changes of an import: summary, rows and loss report",
    params(
        ("id" = String, Path, description = "Import identifier"),
        ("rows" = Option<u32>, Query, description = "How many source rows to list, 1 to 1,000. The summary and the loss report always cover the whole import.")
    ),
    responses(
        (status = 200, description = "The preview", body = ImportPreview),
        (status = 400, description = "The identifier is not a UUID, or a query parameter is unknown or out of range (`sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such import (`import.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "The upload expired or was lost in a restart (`import.expired`, `import.upload.lost`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Import not configured (`import.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn preview_import(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Imports(imports): Imports,
    IpamPath(id): IpamPath<ImportId>,
    filters: Filters,
    auth: Auth,
) -> Result<Json<ImportPreview>, RouteError> {
    reject_unknown_query(&filters, &["rows"])?;
    let rows = preview_rows(&filters)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let gate = gate(&app, &auth, &cx.principal).await?;
    Ok(Json(imports.preview(&cx, id, rows, &gate).await?))
}

/// Lists the rows of the latest preview page by page, beyond the 1,000 rows a preview
/// shows: the rows are kept with the upload when the preview is computed, so paging does not
/// compute it again. A preview must exist for the current mapping; after the mapping
/// changes, run the preview again (409 `import.preview.stale`, also for a cursor of the
/// earlier mapping). `limit` is 1 to 1,000 (200 when absent); `cursor` is the
/// `next_cursor` of the previous page.
#[utoipa::path(
    get,
    path = "/imports/{id}/rows",
    tag = "import",
    operation_id = "list_import_rows",
    summary = "List the rows of the latest preview of an import",
    params(
        ("id" = String, Path, description = "Import identifier"),
        ("limit" = Option<u32>, Query, description = "Page size, 1 to 1,000 (default 200)"),
        ("cursor" = Option<String>, Query, description = "Opaque cursor from the previous page's `next_cursor`")
    ),
    responses(
        (status = 200, description = "A page of preview rows", body = ImportRowsPage),
        (status = 400, description = "The identifier is not a UUID, a parameter is unknown or out of range, or the cursor is malformed (`sys.invalid_request`, `sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such import (`import.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "No preview for the current mapping, or the mapping changed since the cursor was made (`import.preview.stale`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "The upload expired or was lost in a restart (`import.expired`, `import.upload.lost`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Import not configured (`import.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_import_rows(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Imports(imports): Imports,
    IpamPath(id): IpamPath<ImportId>,
    filters: Filters,
) -> Result<Json<ImportRowsPage>, ApiError> {
    reject_unknown_query(&filters, &["limit", "cursor"])?;
    let limit = match filters.parse::<usize>("limit")? {
        None => DEFAULT_ROWS_PAGE,
        Some(0) => return Err(ApiError::invalid_query("limit", "must be at least 1")),
        Some(limit) if limit > MAX_LIMIT => {
            return Err(ApiError::invalid_query(
                "limit",
                format!("must be at most {MAX_LIMIT}"),
            ));
        }
        Some(limit) => limit,
    };
    let scope = CursorScope::new("import.rows").with(&id.to_string());
    let position: Option<RowsCursor> = filters
        .get("cursor")?
        .map(|cursor| decode_cursor(scope, cursor))
        .transpose()?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let page = imports
        .preview_rows(
            &cx,
            id,
            position.map(|p| p.r),
            position.map_or(0, |p| p.o),
            limit,
        )
        .await?;
    let next = page.offset + page.items.len();
    let next_cursor = (!page.items.is_empty() && next < page.total_rows).then(|| {
        encode_cursor(
            scope,
            &RowsCursor {
                r: page.mapping_revision,
                o: next,
            },
        )
    });
    Ok(Json(ImportRowsPage {
        items: page.items,
        next_cursor,
        total_rows: u64::try_from(page.total_rows).unwrap_or(u64::MAX),
        base_revision: page.base_revision,
    }))
}

/// Applies the import as a job of one step per chunk. The job rolls back what it wrote when
/// a chunk fails, and applying again plans nothing new.
///
/// Credential columns (login, password) are never IPAM fields: each host's login and
/// password become one operator secret of that host in the vault. Apply refuses them with
/// 403 `import.credentials.vault_required` unless the server has a vault and the principal
/// passes both `Action::Create` and `Action::Reveal` on `ObjectKind::Secret` (in practice
/// an administrator with a password-or-stronger session, the IAM-07 threshold). The problem
/// carries the parameter `reason`, one of `vault_unavailable`, `step_up_required`,
/// `forbidden`, `unauthenticated` or `pin_coupling`, for a step-up `required`, the weakest
/// session strength that would do, and for `pin_coupling` `accounts`, the accounts that may
/// reveal but sign in with a PIN alone (the rule of `POST /secrets`). Setting `options.credentials` to `skip` in the mapping leaves the
/// credential columns out and the rest of the import is applied.
#[utoipa::path(
    post,
    path = "/imports/{id}/apply",
    tag = "import",
    operation_id = "apply_import",
    summary = "Apply an import as a job",
    params(("id" = String, Path, description = "Import identifier"), IdempotencyKeyHeader),
    request_body(content = Option<ApplyRequest>, content_type = "application/json", description = "Optional; an empty body means no extra acknowledgements"),
    responses(
        (status = 202, description = "The apply job was accepted; follow it at `/jobs/{id}`", body = ApplyAccepted,
            headers(("Location" = String, description = "The URL of the job"))),
        (status = 400, description = "The identifier is not a UUID, or the body is not valid JSON for an apply request (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`), or the credential columns cannot be stored (`import.credentials.vault_required`, parameter `reason`: `vault_unavailable`, `step_up_required`, `forbidden`, `unauthenticated` or `pin_coupling`; parameter `required`: the weakest session strength for a step-up; parameter `accounts`: the accounts that sign in with a PIN alone, for `pin_coupling`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such import (`import.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The plan has warnings that need an acknowledgement or conflicts, or the import is busy (`import.plan.blocked`, `import.state.conflict`, or the plan's own error)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "The upload expired or was lost in a restart (`import.expired`, `import.upload.lost`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "The body is too large (`sys.body_too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Import not configured (`import.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn apply_import(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Imports(imports): Imports,
    IpamPath(id): IpamPath<ImportId>,
    auth: Auth,
    OptionalJson(request): OptionalJson<ApplyRequest>,
) -> Result<Response, RouteError> {
    app.authorize(&cx.principal, Action::Execute, &ObjectRef::from(id))?;
    let gate = gate(&app, &auth, &cx.principal).await?;
    let job_id = imports.apply(&cx, id, &request, &gate).await?;
    Ok(located(
        StatusCode::ACCEPTED,
        &format!("{API_BASE}/jobs/{job_id}"),
        &ApplyAccepted { job_id },
    ))
}

/// The credential gate of the request: the importing account's own check first (so a PIN
/// session still gets `step_up_required`), then, with the auth service present, the
/// cluster-wide rule of `POST /secrets` (`pin_coupling`).
async fn gate(
    app: &AppState,
    auth: &Auth,
    principal: &Principal,
) -> Result<CredentialGate, RouteError> {
    let gate = credential_gate(app.authorizer.as_deref(), principal);
    let (CredentialGate::Allowed, Some(Extension(auth))) = (&gate, auth) else {
        return Ok(gate);
    };
    let accounts = auth.pin_only_revealers().await?;
    if accounts.is_empty() {
        return Ok(gate);
    }
    Ok(CredentialGate::Denied {
        reason: "pin_coupling",
        required: None,
        // Backlog: the rule and the next step in the words of `POST /secrets`.
        detail: format!(
            "{}; or leave the credential columns out",
            tenko_auth::service::reveal::pin_coupling_detail(&accounts)
        ),
        accounts,
    })
}

// ===== request plumbing ==============================================================

/// The import service of the request, from the `Arc<ImportService>` extension; 503
/// `import.unavailable` when the server did not add one.
pub(crate) struct Imports(pub(crate) Arc<ImportService>);

impl<S: Send + Sync> FromRequestParts<S> for Imports {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<Arc<ImportService>>()
                .cloned()
                .map(Imports)
                .ok_or_else(|| {
                    ApiError::from_coded_error(
                        CodedError::new(
                            import_codes::UNAVAILABLE,
                            503,
                            "import is not configured on this server",
                        )
                        .with_title("Service unavailable"),
                    )
                }),
        )
    }
}

/// A JSON body that may be left out: no body, or only whitespace, is `T::default()`. A body
/// is read like [`IpamJson`] reads it (400 `sys.invalid_request`, 415 for another content
/// type), after a limit of [`APPLY_BODY_LIMIT`] bytes (413 `sys.body_too_large`).
struct OptionalJson<T>(T);

impl<T: DeserializeOwned + Default, S: Send + Sync> FromRequest<S> for OptionalJson<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = request.into_parts();
        let declared = content_length(&parts.headers);
        let bytes =
            read_body(body, declared, APPLY_BODY_LIMIT)
                .await
                .map_err(|error| match error {
                    BodyError::TooLarge => ApiError::new(
                        api_codes::BODY_TOO_LARGE,
                        413,
                        format!("the request body may carry at most {APPLY_BODY_LIMIT} bytes"),
                    ),
                    BodyError::Read => ApiError::from_coded_error(
                        CodedError::new(
                            tenko_core::error::codes::INVALID_REQUEST,
                            400,
                            "the request body could not be read",
                        )
                        .with_param("part", "body"),
                    ),
                })?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self(T::default()));
        }
        let request = Request::from_parts(parts, Body::from(bytes));
        IpamJson::<T>::from_request(request, state)
            .await
            .map(|IpamJson(value)| Self(value))
    }
}

/// Why a body could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyError {
    /// More bytes than the limit.
    TooLarge,
    /// The connection failed or the body was cut off.
    Read,
}

/// The `Content-Length` a request declares, if it is a number.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Reads a body of at most `limit` bytes. A declared length above the limit is refused
/// before any byte is read; otherwise the bytes are counted as they arrive, so a body without
/// a length is cut off at the limit as well.
async fn read_body(body: Body, declared: Option<u64>, limit: usize) -> Result<Vec<u8>, BodyError> {
    /// The most that is allocated before the bytes have actually arrived.
    const FIRST_ALLOCATION: usize = 1024 * 1024;
    let wide_limit = u64::try_from(limit).unwrap_or(u64::MAX);
    if declared.is_some_and(|declared| declared > wide_limit) {
        return Err(BodyError::TooLarge);
    }
    let expected = declared.map_or(0, |declared| usize::try_from(declared).unwrap_or(limit));
    let mut bytes = Vec::with_capacity(expected.min(FIRST_ALLOCATION));
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| BodyError::Read)?;
        if chunk.len() > limit - bytes.len() {
            return Err(BodyError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// A response with a JSON body and a `Location` header.
fn located(status: StatusCode, location: &str, body: &impl Serialize) -> Response {
    let mut response = (status, Json(body)).into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

/// 400 `import.upload.malformed`.
fn malformed(detail: String) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(import_codes::UPLOAD_MALFORMED, 400, detail).with_title("Malformed upload"),
    )
}

/// 413 `import.upload.too_large` for a body over the limit of `max_upload` bytes of files.
fn upload_too_large(max_upload: usize) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(
            import_codes::UPLOAD_TOO_LARGE,
            413,
            format!("the upload exceeds the limit of {max_upload} bytes"),
        )
        .with_title("Upload too large")
        .with_param("limit", max_upload.to_string()),
    )
}

/// Refuses every query parameter that is not in `known`, paging parameters included (the
/// endpoints here do not page), with 400 `sys.invalid_query`.
pub(super) fn reject_unknown_query(filters: &Filters, known: &[&str]) -> Result<(), ApiError> {
    match filters
        .pairs()
        .iter()
        .find(|(name, _)| !known.contains(&name.as_str()))
    {
        Some((name, _)) => Err(ApiError::invalid_query(name, "unknown parameter")),
        None => Ok(()),
    }
}

/// The `rows` of a preview: 1 to [`MAX_PREVIEW_ROWS`], or the service default when absent.
fn preview_rows(filters: &Filters) -> Result<Option<usize>, ApiError> {
    match filters.parse::<usize>("rows")? {
        Some(0) => Err(ApiError::invalid_query("rows", "must be at least 1")),
        Some(rows) if rows > MAX_PREVIEW_ROWS => Err(ApiError::invalid_query(
            "rows",
            format!("must be at most {MAX_PREVIEW_ROWS}"),
        )),
        rows => Ok(rows),
    }
}

// ===== multipart/form-data ===========================================================

/// The largest header block of one part; a part with more is refused.
const MAX_PART_HEADER_BYTES: usize = 16 * 1024;

/// The most parts one body may have.
const MAX_PARTS: usize = 512;

/// The longest boundary accepted (RFC 2046 allows 70).
const MAX_BOUNDARY: usize = 200;

/// The name an upload gets when the client sent content with an empty file name.
const UNNAMED_UPLOAD: &str = "upload";

/// Why a multipart body is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipartError(&'static str);

impl std::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for MultipartError {}

/// One file part of a multipart body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePart<'a> {
    /// The file name the client sent, without any directory part.
    pub name: String,
    /// The content of the part, as it lies in the body.
    pub bytes: &'a [u8],
}

/// The boundary of a `multipart/form-data` content type, quoted or not; `None` for another
/// media type, a missing, empty or overlong boundary.
///
/// ```ignore
/// assert_eq!(
///     boundary_from_content_type("multipart/form-data; boundary=\"xyz\""),
///     Some("xyz".to_owned())
/// );
/// ```
pub fn boundary_from_content_type(content_type: &str) -> Option<String> {
    let (media_type, parameters) = split_parameters(content_type);
    if !media_type.eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    let boundary = parameters
        .into_iter()
        .find_map(|(name, value)| (name == "boundary").then_some(value))?;
    let valid = !boundary.is_empty()
        && boundary.len() <= MAX_BOUNDARY
        && !boundary.chars().any(char::is_control);
    valid.then_some(boundary)
}

/// Splits the file parts out of a `multipart/form-data` body.
///
/// The parser follows RFC 2046 and RFC 7578 and is strict where a mistake could hide data:
///
/// - Anything before the first delimiter (the preamble) and after the closing delimiter
///   (the epilogue) is ignored. A delimiter is `--boundary` at the start of a line; a line
///   that only begins with the boundary text (`--boundaryX`) belongs to the content.
/// - Lines end with CRLF. A part is its header block, an empty line and the content up to
///   the CRLF in front of the next delimiter, which is not part of the content; the content
///   may be any bytes, including `--` and CRLF.
/// - A part is a file when its `Content-Disposition` has a `filename` or `filename*`
///   (RFC 5987, `UTF-8` and `ISO-8859-1`); that one wins over `filename`. The directory
///   part of the name, with `/` or `\`, is removed. A part with an empty file name and no
///   content is the "no file chosen" of a browser form and is left out. Parts without a
///   file name are form fields and are ignored.
///
/// # Errors
///
/// [`MultipartError`] when the body has no delimiter, a part is not terminated by the next
/// delimiter or has an unterminated or oversized header block, or there are more than 512
/// parts.
pub fn parse_multipart<'a>(
    body: &'a [u8],
    boundary: &str,
) -> Result<Vec<FilePart<'a>>, MultipartError> {
    let delimiter = Delimiters::new(boundary);
    let mut files = Vec::new();
    let mut found = delimiter
        .find(body, 0, true)
        .ok_or(MultipartError("the body has no multipart delimiter"))?;
    let mut parts = 0_usize;
    while let Found::Part { next, .. } = found {
        parts += 1;
        if parts > MAX_PARTS {
            return Err(MultipartError("the body has too many parts"));
        }
        let (headers, content_start) = split_headers(body, next)?;
        // A blank line directly in front of the delimiter is the end of the headers of an
        // empty part, so the search may start at the CRLF that ended the header block.
        found = delimiter
            .find(body, content_start.saturating_sub(2), false)
            .ok_or(MultipartError(
                "a part is not closed by the next multipart delimiter",
            ))?;
        let (Found::Part { start, .. } | Found::Close { start }) = found;
        let content = &body[content_start..start.max(content_start)];
        if let Some(name) = file_name(headers) {
            if name.is_empty() && content.is_empty() {
                continue;
            }
            files.push(FilePart {
                name: if name.is_empty() {
                    UNNAMED_UPLOAD.to_owned()
                } else {
                    name
                },
                bytes: content,
            });
        }
    }
    Ok(files)
}

/// The delimiters of one boundary, as byte patterns.
struct Delimiters {
    /// `--boundary`.
    dash: Vec<u8>,
    /// `CRLF--boundary`.
    line: Vec<u8>,
}

/// A delimiter found in a body.
#[derive(Debug, Clone, Copy)]
enum Found {
    /// A delimiter that is followed by another part; `start` is where the content of the
    /// part before it ends and `next` where the header block of the next part begins.
    Part { start: usize, next: usize },
    /// The closing delimiter.
    Close { start: usize },
}

impl Delimiters {
    fn new(boundary: &str) -> Self {
        let dash = [b"--".as_slice(), boundary.as_bytes()].concat();
        let line = [b"\r\n".as_slice(), &dash].concat();
        Self { dash, line }
    }

    /// The first delimiter at or after `from`. With `at_start`, `--boundary` at the very
    /// start of the body counts although no CRLF stands in front of it.
    fn find(&self, body: &[u8], from: usize, at_start: bool) -> Option<Found> {
        if at_start
            && body.starts_with(&self.dash)
            && let Some(found) = Self::classify(body, 0, self.dash.len())
        {
            return Some(found);
        }
        let mut at = from;
        while let Some(start) = find_bytes(body, &self.line, at) {
            if let Some(found) = Self::classify(body, start, start + self.line.len()) {
                return Some(found);
            }
            at = start + 1;
        }
        None
    }

    /// What follows the boundary text at `after`: `--` closes the body, optional spaces and
    /// a CRLF start the next part, anything else means this is no delimiter.
    fn classify(body: &[u8], start: usize, after: usize) -> Option<Found> {
        let rest = &body[after..];
        if rest.starts_with(b"--") {
            return Some(Found::Close { start });
        }
        let padding = rest
            .iter()
            .take_while(|&&byte| byte == b' ' || byte == b'\t')
            .count();
        rest[padding..].starts_with(b"\r\n").then_some(Found::Part {
            start,
            next: after + padding + 2,
        })
    }
}

/// The index of the first `needle` in `haystack` at or after `from`.
fn find_bytes(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let first = *needle.first()?;
    let mut at = from;
    while at + needle.len() <= haystack.len() {
        let window = &haystack[at..=haystack.len() - needle.len()];
        let candidate = at + window.iter().position(|&byte| byte == first)?;
        if haystack[candidate..].starts_with(needle) {
            return Some(candidate);
        }
        at = candidate + 1;
    }
    None
}

/// The header block of the part that starts at `at`, and where its content starts.
fn split_headers(body: &[u8], at: usize) -> Result<(&[u8], usize), MultipartError> {
    let rest = &body[at..];
    if rest.starts_with(b"\r\n") {
        return Ok((&[], at + 2));
    }
    let window = &rest[..rest.len().min(MAX_PART_HEADER_BYTES + 4)];
    let end = find_bytes(window, b"\r\n\r\n", 0).ok_or(MultipartError(
        "the headers of a part are unterminated or too large",
    ))?;
    Ok((&rest[..end], at + end + 4))
}

/// The file name of a part, from its `Content-Disposition`; `None` when the part has none
/// (a form field). The name is empty when the client sent an empty one.
fn file_name(headers: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(headers);
    let mut disposition: Option<String> = None;
    let mut continued = false;
    for line in text.split("\r\n") {
        if line.starts_with([' ', '\t']) {
            if continued && let Some(value) = disposition.as_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        continued = false;
        if disposition.is_none()
            && let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-disposition")
        {
            disposition = Some(value.trim().to_owned());
            continued = true;
        }
    }
    let disposition = disposition?;
    let (_, parameters) = split_parameters(&disposition);
    let lookup = |wanted: &str| {
        parameters
            .iter()
            .find_map(|(name, value)| (name == wanted).then_some(value.as_str()))
    };
    let raw = lookup("filename*")
        .and_then(decode_extended_value)
        .or_else(|| lookup("filename").map(str::to_owned))?;
    Some(base_name(&raw))
}

/// The file name without directory part and control characters.
fn base_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let cleaned: String = base.chars().filter(|c| !c.is_control()).collect();
    cleaned.trim().to_owned()
}

/// Decodes an RFC 5987 extended value (`UTF-8''%e2%82%ac.csv`); `None` for a charset other
/// than UTF-8 and ISO-8859-1 or for a malformed value.
fn decode_extended_value(value: &str) -> Option<String> {
    let mut pieces = value.splitn(3, '\'');
    let charset = pieces.next()?;
    let _language = pieces.next()?;
    let encoded = pieces.next()?;
    let bytes = percent_decode(encoded)?;
    if charset.eq_ignore_ascii_case("utf-8") {
        String::from_utf8(bytes).ok()
    } else if charset.eq_ignore_ascii_case("iso-8859-1") {
        Some(bytes.into_iter().map(char::from).collect())
    } else {
        None
    }
}

/// Percent-decodes `text`; `None` for an escape that is not two hexadecimal digits.
fn percent_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

/// Splits a header value such as `form-data; name="file"; filename="a.csv"` into its first
/// token and the lower-cased parameters. Quoted values keep everything but `\"`, which is
/// a quote: browsers do not escape the backslashes of Windows paths, which later become the
/// directory part of a name.
fn split_parameters(value: &str) -> (&str, Vec<(String, String)>) {
    let bytes = value.as_bytes();
    let head_end = value.find(';').unwrap_or(value.len());
    let head = value[..head_end].trim();
    let mut parameters = Vec::new();
    let mut i = head_end;
    while i < bytes.len() {
        // `bytes[i]` is the `;` that starts a parameter.
        i += 1;
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b';' {
            i += 1;
        }
        let key = value[key_start..i].trim().to_ascii_lowercase();
        if i >= bytes.len() || bytes[i] == b';' {
            continue;
        }
        i += 1;
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        let text = if bytes.get(i) == Some(&b'"') {
            i += 1;
            let mut quoted = Vec::new();
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => {
                        i += 1;
                        break;
                    }
                    b'\\' if bytes.get(i + 1) == Some(&b'"') => {
                        quoted.push(b'"');
                        i += 2;
                    }
                    byte => {
                        quoted.push(byte);
                        i += 1;
                    }
                }
            }
            while i < bytes.len() && bytes[i] != b';' {
                i += 1;
            }
            String::from_utf8_lossy(&quoted).into_owned()
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b';' {
                i += 1;
            }
            value[start..i].trim().to_owned()
        };
        if !key.is_empty() {
            parameters.push((key, text));
        }
    }
    (head, parameters)
}

/// The harness of the route tests of the import and export areas: one router over the routes
/// of both, services on a fresh in-memory store with the job runner started, and helpers to
/// send requests, upload files and read answers. Test data lives in the documentation ranges
/// of the fixtures (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, names under
/// `example.test`).
#[cfg(test)]
pub(super) mod testkit {
    use std::{path::PathBuf, sync::Arc, time::Duration};

    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{HeaderMap, Request, StatusCode, header},
        response::Response,
    };
    use serde_json::{Value, json};
    use tenko_core::{Authorizer, JobId};
    use tenko_ipam::{
        IpamConfig, IpamService,
        import::{ImportConfig, ImportService},
        jobs::register_steps,
    };
    use tenko_jobs::{EngineConfig, JobEngine, JobState, RunnerHandle};
    use tenko_store::{MemStore, Store};
    use tower::ServiceExt;
    use utoipa_axum::router::OpenApiRouter;
    use uuid::Uuid;

    use crate::{
        API_BASE,
        problem::PROBLEM_JSON,
        routes::{export, import},
        state::AppState,
    };

    /// The boundary of the multipart bodies the tests build.
    pub const BOUNDARY: &str = "tenko-test-boundary-7f3a";

    /// What a test wants different from the defaults.
    #[derive(Default)]
    pub struct Setup {
        /// `max_upload` of the import configuration.
        pub max_upload: Option<usize>,
        /// Checks of the state; none lets everything pass.
        pub authorizer: Option<Arc<dyn Authorizer>>,
        /// Leave the IPAM service out of the request extensions.
        pub without_ipam: bool,
        /// Leave the import service out of the request extensions.
        pub without_imports: bool,
    }

    /// Stops the runner and removes the staged files when the last handle goes.
    struct Keep {
        _runner: RunnerHandle,
        staging: PathBuf,
    }

    impl Drop for Keep {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.staging);
        }
    }

    /// A decoded answer.
    #[derive(Debug)]
    pub struct Reply {
        pub status: StatusCode,
        pub headers: HeaderMap,
        pub bytes: Vec<u8>,
    }

    impl Reply {
        /// A header as text, empty when absent.
        pub fn header(&self, name: &str) -> &str {
            self.headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
        }

        /// The body as text.
        pub fn text(&self) -> String {
            String::from_utf8_lossy(&self.bytes).into_owned()
        }

        /// The body as JSON; `null` for an empty body.
        pub fn json(&self) -> Value {
            if self.bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&self.bytes).unwrap_or_else(|_| Value::String(self.text()))
            }
        }

        /// Asserts a JSON answer with this status and returns the body.
        pub fn assert_json(&self, status: u16) -> Value {
            let body = self.json();
            assert_eq!(self.status.as_u16(), status, "{body}");
            assert_eq!(self.header("content-type"), "application/json", "{body}");
            body
        }

        /// Asserts a problem document with this status and code and returns it.
        pub fn assert_problem(&self, status: u16, code: &str) -> Value {
            let body = self.json();
            let label = format!("{} {body}", self.status);
            assert_eq!(self.status.as_u16(), status, "{label}");
            assert_eq!(self.header("content-type"), PROBLEM_JSON, "{label}");
            assert_eq!(body["status"], status, "{label}");
            assert_eq!(body["code"], code, "{label}");
            for member in ["title", "detail"] {
                let text = body[member].as_str().unwrap_or_default();
                assert!(!text.is_empty(), "{member} is empty: {label}");
            }
            body
        }
    }

    /// The router of both areas under the API base, over a state with `authorizer`.
    fn router(
        store: Arc<dyn Store>,
        authorizer: Option<Arc<dyn Authorizer>>,
        ipam: Option<Arc<IpamService>>,
        imports: Option<Arc<ImportService>>,
    ) -> Router {
        let mut state = AppState::new(store);
        state.authorizer = authorizer;
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, import::routes().merge(export::routes()))
            .split_for_parts();
        let mut router = router.with_state(state);
        if let Some(ipam) = ipam {
            router = router.layer(Extension(ipam));
        }
        if let Some(imports) = imports {
            router = router.layer(Extension(imports));
        }
        router
    }

    /// Both areas over a fresh store, IPAM service, job engine and import service.
    pub struct Api {
        router: Router,
        store: Arc<dyn Store>,
        pub engine: JobEngine,
        pub ipam: Arc<IpamService>,
        pub imports: Arc<ImportService>,
        #[allow(dead_code)]
        keep: Arc<Keep>,
    }

    impl Api {
        /// An API without authorizer and authenticator: every check passes, and every
        /// request acts as the API itself.
        pub fn new() -> Self {
            Self::with(Setup::default())
        }

        /// An API as `setup` says.
        pub fn with(setup: Setup) -> Self {
            let store: Arc<dyn Store> = Arc::new(MemStore::default());
            let mut engine = JobEngine::new(Arc::clone(&store), EngineConfig::default());
            register_steps(&mut engine);
            let ipam = IpamService::new(
                Arc::clone(&store),
                Arc::new(engine.clone()),
                IpamConfig::default(),
            )
            .expect("IPAM service");
            let staging = std::env::temp_dir().join(format!("tenko-api-import-{}", Uuid::now_v7()));
            let mut config = ImportConfig {
                staging_dir: staging.clone(),
                ..ImportConfig::default()
            };
            if let Some(max_upload) = setup.max_upload {
                config.max_upload = max_upload;
            }
            let imports = ImportService::new(Arc::clone(&ipam), engine.clone(), None, config)
                .expect("import service");
            let runner = engine.start().expect("job runner");
            let api = Self {
                router: Router::new(),
                store,
                engine,
                ipam,
                imports,
                keep: Arc::new(Keep {
                    _runner: runner,
                    staging,
                }),
            };
            api.sibling(setup)
        }

        /// Another router over the same services and store, with other checks or without
        /// some of the services.
        pub fn sibling(&self, setup: Setup) -> Self {
            let router = router(
                Arc::clone(&self.store),
                setup.authorizer,
                (!setup.without_ipam).then(|| Arc::clone(&self.ipam)),
                (!setup.without_imports).then(|| Arc::clone(&self.imports)),
            );
            Self {
                router,
                store: Arc::clone(&self.store),
                engine: self.engine.clone(),
                ipam: Arc::clone(&self.ipam),
                imports: Arc::clone(&self.imports),
                keep: Arc::clone(&self.keep),
            }
        }

        /// The raw response to a request.
        pub async fn call(&self, request: Request<Body>) -> Response {
            self.router
                .clone()
                .oneshot(request)
                .await
                .expect("response")
        }

        /// The raw response to a request with this method, path, content type and body.
        pub async fn respond(
            &self,
            method: &str,
            path: &str,
            content_type: Option<&str>,
            body: Body,
        ) -> Response {
            let mut builder = Request::builder()
                .method(method)
                .uri(format!("{API_BASE}{path}"));
            if let Some(content_type) = content_type {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }
            self.call(builder.body(body).expect("request")).await
        }

        /// Sends a request and decodes the answer.
        pub async fn send(
            &self,
            method: &str,
            path: &str,
            content_type: Option<&str>,
            body: Vec<u8>,
        ) -> Reply {
            let response = self
                .respond(method, path, content_type, Body::from(body))
                .await;
            Reply {
                status: response.status(),
                headers: response.headers().clone(),
                bytes: to_bytes(response.into_body(), usize::MAX)
                    .await
                    .expect("body")
                    .to_vec(),
            }
        }

        /// `GET`.
        pub async fn get(&self, path: &str) -> Reply {
            self.send("GET", path, None, Vec::new()).await
        }

        /// `DELETE`.
        pub async fn delete(&self, path: &str) -> Reply {
            self.send("DELETE", path, None, Vec::new()).await
        }

        /// A request with a JSON body.
        pub async fn json(&self, method: &str, path: &str, body: &Value) -> Reply {
            let body = body.to_string().into_bytes();
            self.send(method, path, Some("application/json"), body)
                .await
        }

        /// Uploads a multipart body made of `(field, filename, content)` parts.
        pub async fn upload_parts(&self, parts: &[(&str, Option<&str>, &[u8])]) -> Reply {
            let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
            let body = multipart_body(BOUNDARY, parts);
            self.send("POST", "/imports", Some(&content_type), body)
                .await
        }

        /// Uploads files as `file` parts.
        pub async fn upload(&self, files: &[(&str, &[u8])]) -> Reply {
            let parts: Vec<(&str, Option<&str>, &[u8])> = files
                .iter()
                .map(|(name, bytes)| ("file", Some(*name), *bytes))
                .collect();
            self.upload_parts(&parts).await
        }

        /// Uploads a file of the fixtures, expects 201 and returns the import.
        pub async fn upload_fixture(&self, name: &str) -> Value {
            let bytes = fixture(name);
            let file_name = name.rsplit('/').next().unwrap_or(name);
            self.upload(&[(file_name, &bytes)]).await.assert_json(201)
        }

        /// Sets the mapping of an import to its suggestion with the credentials left out.
        pub async fn skip_credentials(&self, import: &Value) -> Value {
            let id = import["id"].as_str().expect("import id");
            let mut mapping = import["mapping"].clone();
            mapping["options"]["credentials"] = json!("skip");
            self.json("PUT", &format!("/imports/{id}/mapping"), &mapping)
                .await
                .assert_json(200)
        }

        /// Waits for a job to end and returns its state.
        pub async fn wait_for_job(&self, id: &str) -> JobState {
            let id: JobId = id.parse().expect("job id");
            for _ in 0..1500 {
                let job = self.engine.job(id).await.expect("job");
                if job.state.is_terminal() {
                    return job.state;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("job {id} did not finish");
        }

        /// Uploads the workbook of the fixtures and applies it without its credentials;
        /// returns the import.
        pub async fn import_fixture(&self) -> Value {
            let uploaded = self.upload_fixture("ip-plan.xlsx").await;
            self.skip_credentials(&uploaded).await;
            let id = uploaded["id"].as_str().expect("import id");
            let accepted = self
                .send("POST", &format!("/imports/{id}/apply"), None, Vec::new())
                .await
                .assert_json(202);
            let job = accepted["job_id"].as_str().expect("job id");
            assert_eq!(self.wait_for_job(job).await, JobState::Succeeded);
            uploaded
        }
    }

    /// A multipart body made of `(field, filename, content)` parts; a part without a file
    /// name is a form field.
    pub fn multipart_body(boundary: &str, parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (field, filename, content) in parts {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            let disposition = match filename {
                Some(name) => format!(
                    "Content-Disposition: form-data; name=\"{field}\"; filename=\"{name}\"\r\n\
                     Content-Type: application/octet-stream\r\n"
                ),
                None => format!("Content-Disposition: form-data; name=\"{field}\"\r\n"),
            };
            body.extend_from_slice(disposition.as_bytes());
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(content);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        body
    }

    /// A file of the fixtures of `tenko-ipam`.
    pub fn fixture(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tenko-ipam/tests/fixtures")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|error| panic!("fixture {}: {error}", path.display()))
    }

    /// An identifier that no import has.
    pub fn unknown_id() -> String {
        Uuid::now_v7().to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use bytes::Bytes;
    use serde_json::{Value, json};
    use tenko_jobs::JobState;

    use super::testkit::{Api, BOUNDARY, Setup, fixture, multipart_body, unknown_id};
    use super::*;
    use crate::routes::tenancy::testkit::Policy;

    // ----- the multipart parser ---------------------------------------------------------

    /// The file parts of a body as name and content.
    fn parsed<'a>(body: &'a [u8], boundary: &str) -> Vec<(String, &'a [u8])> {
        parse_multipart(body, boundary)
            .expect("parses")
            .into_iter()
            .map(|file| (file.name, file.bytes))
            .collect()
    }

    /// A body of one part with this `Content-Disposition` and content, boundary `b`.
    fn one_part(disposition: &str, content: &str) -> Vec<u8> {
        format!("--b\r\nContent-Disposition: {disposition}\r\n\r\n{content}\r\n--b--\r\n")
            .into_bytes()
    }

    /// The name the parser gives the file of `one_part`, `None` when the part is no file.
    fn name_of(disposition: &str) -> Option<String> {
        let body = one_part(disposition, "x");
        parse_multipart(&body, "b")
            .expect("parses")
            .into_iter()
            .next()
            .map(|file| file.name)
    }

    #[test]
    fn the_boundary_is_a_quoted_or_unquoted_parameter() {
        let cases = [
            ("multipart/form-data; boundary=abc123", Some("abc123")),
            ("multipart/form-data; boundary=\"abc 123\"", Some("abc 123")),
            ("Multipart/Form-Data;Boundary=xyz", Some("xyz")),
            (
                "multipart/form-data; charset=utf-8; boundary=\"a;b\"; x=y",
                Some("a;b"),
            ),
            ("multipart/form-data; boundary=\"\"", None),
            ("multipart/form-data; boundary=", None),
            ("multipart/form-data", None),
            ("multipart/mixed; boundary=abc", None),
            ("application/json", None),
        ];
        for (header, expected) in cases {
            assert_eq!(
                boundary_from_content_type(header).as_deref(),
                expected,
                "{header}"
            );
        }
        let long = format!(
            "multipart/form-data; boundary={}",
            "x".repeat(MAX_BOUNDARY + 1)
        );
        assert_eq!(boundary_from_content_type(&long), None);
    }

    #[test]
    fn a_preamble_and_an_epilogue_are_ignored() {
        let body = b"A preamble\r\nof two lines.\r\n--b\r\n\
            Content-Disposition: form-data; name=\"file\"; filename=\"a.csv\"\r\n\r\n\
            ip,name\r\n192.0.2.1,gw\r\n\r\n--b--\r\nan epilogue --b\r\n";
        assert_eq!(
            parsed(body, "b"),
            vec![(
                "a.csv".to_owned(),
                b"ip,name\r\n192.0.2.1,gw\r\n".as_slice()
            )]
        );
        // No preamble: the first delimiter is the first byte of the body.
        let body = one_part("form-data; name=\"file\"; filename=\"a.csv\"", "x");
        assert_eq!(
            parsed(&body, "b"),
            vec![("a.csv".to_owned(), b"x".as_slice())]
        );
    }

    #[test]
    fn the_content_keeps_its_own_line_ends_and_dashes() {
        let content: &[u8] = b"\x00\x01--\r\n--\r\n--bnd-\r\n--bndx\r\n\xff\xfe\r\n--bn\r\n--";
        let mut body = b"--bnd\r\nContent-Disposition: form-data; name=\"file\"; filename=\"blob.bin\"\r\n\r\n"
            .to_vec();
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n--bnd--");
        assert_eq!(parsed(&body, "bnd"), vec![("blob.bin".to_owned(), content)]);
    }

    #[test]
    fn a_delimiter_may_be_followed_by_spaces_before_the_line_end() {
        let body = b"--b  \t\r\nContent-Disposition: form-data; name=\"f\"; filename=\"one\"\r\n\r\n1\r\n--b \r\n\
            Content-Disposition: form-data; name=\"f\"; filename=\"two\"\r\n\r\n2\r\n--b--";
        assert_eq!(
            parsed(body, "b"),
            vec![
                ("one".to_owned(), b"1".as_slice()),
                ("two".to_owned(), b"2".as_slice())
            ]
        );
    }

    #[test]
    fn several_files_and_form_fields_come_out_in_order() {
        let parts: [(&str, Option<&str>, &[u8]); 4] = [
            ("note", None, b"hello"),
            ("files", Some("Index.csv"), b"a\r\nb"),
            ("file", Some("192.0.2.0.csv"), b""),
            ("file", Some("last.csv"), b"--"),
        ];
        let body = multipart_body("bnd", &parts);
        assert_eq!(
            parsed(&body, "bnd"),
            vec![
                ("Index.csv".to_owned(), b"a\r\nb".as_slice()),
                ("192.0.2.0.csv".to_owned(), b"".as_slice()),
                ("last.csv".to_owned(), b"--".as_slice()),
            ]
        );
    }

    #[test]
    fn file_names_lose_their_directory_and_decode_rfc_5987() {
        let cases = [
            (
                "form-data; name=\"file\"; filename=\"a.csv\"",
                Some("a.csv"),
            ),
            (
                "form-data; name=file; filename=plain.csv",
                Some("plain.csv"),
            ),
            (
                "form-data; name=\"file\"; filename=\"C:\\Users\\someone\\plan.csv\"",
                Some("plan.csv"),
            ),
            (
                "form-data; name=\"file\"; filename=\"\\\\server\\share\\plan.csv\"",
                Some("plan.csv"),
            ),
            ("form-data; filename=\"../../etc/passwd\"", Some("passwd")),
            (
                "form-data; filename=\"we said \\\"hi\\\".csv\"",
                Some("we said \"hi\".csv"),
            ),
            (
                "form-data; filename=\"p\u{e5} lan.csv\"",
                Some("p\u{e5} lan.csv"),
            ),
            (
                "form-data; filename=\"fallback.csv\"; filename*=UTF-8''p%C3%A5%20lan.csv",
                Some("p\u{e5} lan.csv"),
            ),
            (
                "form-data; filename*=utf-8'sv'%e2%82%ac.csv",
                Some("\u{20ac}.csv"),
            ),
            (
                "form-data; filename*=ISO-8859-1''p%E5.csv",
                Some("p\u{e5}.csv"),
            ),
            (
                "form-data; filename=\"ok.csv\"; filename*=UTF-8''%ZZ.csv",
                Some("ok.csv"),
            ),
            (
                "form-data; filename=\"ok.csv\"; filename*=KOI8-R''x.csv",
                Some("ok.csv"),
            ),
            (
                "form-data;\r\n\tname=\"file\";\r\n filename=\"folded.csv\"",
                Some("folded.csv"),
            ),
            ("form-data; name=\"note\"", None),
            ("form-data", None),
        ];
        for (disposition, expected) in cases {
            assert_eq!(name_of(disposition).as_deref(), expected, "{disposition}");
        }
        // The header name is case-insensitive and the first one counts.
        let body = b"--b\r\ncontent-disposition: form-data; filename=\"low.csv\"\r\n\
            Content-Disposition: form-data; filename=\"second.csv\"\r\n\r\nx\r\n--b--";
        assert_eq!(
            parsed(body, "b"),
            vec![("low.csv".to_owned(), b"x".as_slice())]
        );
    }

    #[test]
    fn an_empty_file_name_is_no_file_chosen_unless_there_is_content() {
        let body = one_part("form-data; name=\"file\"; filename=\"\"", "");
        assert_eq!(parsed(&body, "b").len(), 0);
        let body = one_part("form-data; name=\"file\"; filename=\"\"", "data");
        assert_eq!(
            parsed(&body, "b"),
            vec![("upload".to_owned(), b"data".as_slice())]
        );
        // A part without headers has no disposition and is no file.
        assert_eq!(parsed(b"--b\r\n\r\ncontent\r\n--b--", "b").len(), 0);
        // The body of only the closing delimiter holds no parts.
        assert_eq!(parsed(b"--b--\r\n", "b").len(), 0);
    }

    #[test]
    fn an_empty_part_may_follow_its_headers_directly() {
        let body = b"--b\r\nContent-Disposition: form-data; filename=\"e.csv\"\r\n\r\n--b\r\n\
            Content-Disposition: form-data; filename=\"f.csv\"\r\n\r\n\r\n--b--";
        assert_eq!(
            parsed(body, "b"),
            vec![
                ("e.csv".to_owned(), b"".as_slice()),
                ("f.csv".to_owned(), b"".as_slice())
            ]
        );
    }

    #[test]
    fn malformed_bodies_are_refused() {
        let unterminated_headers = b"--b\r\nContent-Disposition: form-data".as_slice();
        let oversized_headers = format!(
            "--b\r\nX-Pad: {}\r\n\r\nx\r\n--b--",
            "p".repeat(MAX_PART_HEADER_BYTES)
        );
        let bad: [&[u8]; 7] = [
            b"",
            b"no boundary in here",
            b"--other\r\nContent-Disposition: form-data; filename=\"a\"\r\n\r\nx\r\n--other--",
            b"--b\r\nContent-Disposition: form-data; filename=\"a\"\r\n\r\nnever closed",
            unterminated_headers,
            // Line feeds only.
            b"--b\nContent-Disposition: form-data; filename=\"a\"\n\nx\n--b--\n",
            oversized_headers.as_bytes(),
        ];
        for body in bad {
            assert!(
                parse_multipart(body, "b").is_err(),
                "{}",
                String::from_utf8_lossy(&body[..body.len().min(60)])
            );
        }
    }

    #[test]
    fn the_number_of_parts_is_limited() {
        let field: [(&str, Option<&str>, &[u8]); 1] = [("f", None, b"v")];
        let many = |count: usize| -> Vec<u8> {
            let parts: Vec<_> = field.iter().copied().cycle().take(count).collect();
            multipart_body("b", &parts)
        };
        assert!(parse_multipart(&many(MAX_PARTS), "b").is_ok());
        assert_eq!(
            parse_multipart(&many(MAX_PARTS + 1), "b").map_err(|e| e.to_string()),
            Err("the body has too many parts".to_owned())
        );
    }

    // ----- upload -----------------------------------------------------------------------

    #[tokio::test]
    async fn uploading_the_workbook_answers_the_sheets_and_a_suggested_mapping() {
        let api = Api::new();
        let bytes = fixture("ip-plan.xlsx");
        let reply = api.upload(&[("ip-plan.xlsx", &bytes)]).await;
        let view = reply.assert_json(201);
        let id = view["id"].as_str().expect("id");
        assert_eq!(reply.header("location"), format!("/api/v1/imports/{id}"));
        assert_eq!(view["state"], "uploaded");
        assert_eq!(view["mapped"], false);
        assert_eq!(view["files"][0]["name"], "ip-plan.xlsx");
        assert_eq!(view["files"][0]["format"], "xlsx");
        assert_ne!(view["sheets"].as_array().expect("sheets").len(), 0);
        assert_ne!(
            view["mapping"]["sheets"].as_array().expect("mapping").len(),
            0
        );
        assert_ne!(view["targets"].as_array().expect("targets").len(), 0);
    }

    #[tokio::test]
    async fn the_directory_of_a_windows_file_name_is_dropped() {
        let api = Api::new();
        let bytes = fixture("ip-plan.xlsx");
        let view = api
            .upload(&[("C:\\Users\\example\\ip-plan.xlsx", &bytes)])
            .await
            .assert_json(201);
        assert_eq!(view["files"][0]["name"], "ip-plan.xlsx");
    }

    #[tokio::test]
    async fn several_csv_files_form_one_import() {
        let api = Api::new();
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tenko-ipam/tests/fixtures/ip-plan-csv");
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("fixture directory")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert!(names.len() > 3);
        let contents: Vec<Vec<u8>> = names
            .iter()
            .map(|name| fixture(&format!("ip-plan-csv/{name}")))
            .collect();
        let mut parts: Vec<(&str, Option<&str>, &[u8])> = vec![("note", None, b"ignored")];
        for (name, content) in names.iter().zip(&contents) {
            parts.push(("files", Some(name), content));
        }
        let view = api.upload_parts(&parts).await.assert_json(201);
        let files: Vec<&str> = view["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|file| file["name"].as_str().expect("name"))
            .collect();
        assert_eq!(files, names);
        assert!(view["sheets"].as_array().expect("sheets").len() >= names.len());
    }

    #[tokio::test]
    async fn an_upload_without_a_file_is_empty() {
        let api = Api::new();
        let field: [(&str, Option<&str>, &[u8]); 1] = [("note", None, b"hello")];
        api.upload_parts(&field)
            .await
            .assert_problem(400, "import.upload.empty");
        api.upload_parts(&[])
            .await
            .assert_problem(400, "import.upload.empty");
        // The "no file chosen" part of a browser form.
        let none_chosen: [(&str, Option<&str>, &[u8]); 1] = [("file", Some(""), b"")];
        api.upload_parts(&none_chosen)
            .await
            .assert_problem(400, "import.upload.empty");
        // A named file without content.
        let no_content: [(&str, Option<&str>, &[u8]); 1] = [("file", Some("a.csv"), b"")];
        api.upload_parts(&no_content)
            .await
            .assert_problem(400, "import.upload.empty");
    }

    #[tokio::test]
    async fn an_upload_that_is_not_multipart_is_malformed() {
        let api = Api::new();
        let multipart = format!("multipart/form-data; boundary={BOUNDARY}");
        let body = multipart_body(BOUNDARY, &[("file", Some("a.csv"), b"ip\r\n192.0.2.1\r\n")]);
        let truncated = body[..body.len() - 10].to_vec();
        let cases: [(Option<&str>, Vec<u8>); 6] = [
            (Some("application/json"), br#"{"file":"a.csv"}"#.to_vec()),
            (None, body.clone()),
            (Some("multipart/form-data"), body.clone()),
            (Some("text/csv"), b"ip\r\n192.0.2.1\r\n".to_vec()),
            (Some(&multipart), b"this is no multipart body".to_vec()),
            (Some(&multipart), truncated),
        ];
        for (content_type, body) in cases {
            api.send("POST", "/imports", content_type, body)
                .await
                .assert_problem(400, "import.upload.malformed");
        }
    }

    #[tokio::test]
    async fn the_file_bytes_are_limited_by_the_service() {
        let api = Api::with(Setup {
            max_upload: Some(1_000),
            ..Setup::default()
        });
        let big = vec![b'a'; 5_000];
        let problem = api
            .upload(&[("a.csv", &big)])
            .await
            .assert_problem(413, "import.upload.too_large");
        assert_eq!(problem["params"]["limit"], "1000");
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_refused_while_it_is_read() {
        let api = Api::with(Setup {
            max_upload: Some(1_000),
            ..Setup::default()
        });
        let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
        let request = |length: Option<&str>, body: Body| {
            let mut builder = Request::builder()
                .method("POST")
                .uri(format!("{API_BASE}/imports"))
                .header(header::CONTENT_TYPE, &content_type);
            if let Some(length) = length {
                builder = builder.header(header::CONTENT_LENGTH, length);
            }
            builder.body(body).expect("request")
        };
        let limit = 1_000 + MULTIPART_OVERHEAD;

        // A declared length over the limit is refused before the body is read.
        let declared = request(Some(&(limit + 1).to_string()), Body::empty());
        let reply = api.call(declared).await;
        assert_eq!(reply.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Without a declared length the bytes are counted as they arrive.
        let chunks = vec![
            Ok::<_, io::Error>(Bytes::from(vec![b'a'; limit / 2 + 1])),
            Ok(Bytes::from(vec![b'a'; limit / 2 + 1])),
        ];
        let streamed = request(None, Body::from_stream(futures::stream::iter(chunks)));
        let reply = api.call(streamed).await;
        assert_eq!(reply.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let bytes = axum::body::to_bytes(reply.into_body(), usize::MAX)
            .await
            .expect("body");
        let problem: Value = serde_json::from_slice(&bytes).expect("problem");
        assert_eq!(problem["code"], "import.upload.too_large");
        assert_eq!(problem["params"]["limit"], "1000");
    }

    #[tokio::test]
    async fn bytes_that_are_no_spreadsheet_are_unsupported() {
        let api = Api::new();
        let garbage: &[u8] = &[0x00, 0x9f, 0x92, 0x96, 0x00, 0x01, 0x02, 0x03];
        api.upload(&[("blob.bin", garbage)])
            .await
            .assert_problem(415, "import.upload.unsupported");
    }

    // ----- get and delete ---------------------------------------------------------------

    #[tokio::test]
    async fn an_import_can_be_read_and_discarded() {
        let api = Api::new();
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let id = uploaded["id"].as_str().expect("id");
        let path = format!("/imports/{id}");
        assert_eq!(api.get(&path).await.assert_json(200), uploaded);

        let reply = api.delete(&path).await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
        assert_eq!(reply.bytes.len(), 0);
        api.get(&path).await.assert_problem(404, "import.not_found");
        api.delete(&path)
            .await
            .assert_problem(404, "import.not_found");
    }

    #[tokio::test]
    async fn an_unknown_or_malformed_identifier_is_refused() {
        let api = Api::new();
        let unknown = unknown_id();
        for path in [
            format!("/imports/{unknown}"),
            format!("/imports/{unknown}/preview"),
        ] {
            api.get(&path).await.assert_problem(404, "import.not_found");
        }
        api.delete(&format!("/imports/{unknown}"))
            .await
            .assert_problem(404, "import.not_found");
        api.json(
            "PUT",
            &format!("/imports/{unknown}/mapping"),
            &json!({ "sheets": [] }),
        )
        .await
        .assert_problem(404, "import.not_found");
        api.send(
            "POST",
            &format!("/imports/{unknown}/apply"),
            None,
            Vec::new(),
        )
        .await
        .assert_problem(404, "import.not_found");

        for path in ["/imports/not-an-id", "/imports/not-an-id/preview"] {
            api.get(path)
                .await
                .assert_problem(400, "sys.invalid_request");
        }
        api.delete("/imports/12345")
            .await
            .assert_problem(400, "sys.invalid_request");
    }

    // ----- mapping ----------------------------------------------------------------------

    #[tokio::test]
    async fn the_suggested_mapping_can_be_stored_with_the_credentials_left_out() {
        let api = Api::new();
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let id = uploaded["id"].as_str().expect("id");
        let view = api.skip_credentials(&uploaded).await;
        assert_eq!(view["mapped"], true);
        assert_eq!(view["state"], "mapped");
        assert_eq!(view["mapping"]["options"]["credentials"], "skip");
        let again = api.get(&format!("/imports/{id}")).await.assert_json(200);
        assert_eq!(again["mapped"], true);
        assert_eq!(again["mapping"], view["mapping"]);
    }

    #[tokio::test]
    async fn a_mapping_that_does_not_fit_is_refused() {
        let api = Api::new();
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let path = format!("/imports/{}/mapping", uploaded["id"].as_str().expect("id"));
        let mut broken = uploaded["mapping"].clone();
        broken["sheets"][0]["sheet"] = json!("No such sheet");
        let problem = api
            .json("PUT", &path, &broken)
            .await
            .assert_problem(422, "import.mapping.invalid");
        assert!(
            problem["detail"]
                .as_str()
                .expect("detail")
                .contains("No such sheet")
        );

        let malformed = b"{\"sheets\": [".to_vec();
        api.send("PUT", &path, Some("application/json"), malformed)
            .await
            .assert_problem(400, "sys.invalid_request");
        api.json("PUT", &path, &json!({ "sheets": 5 }))
            .await
            .assert_problem(400, "sys.invalid_request");
        api.send(
            "PUT",
            &path,
            Some("text/plain"),
            b"{\"sheets\": []}".to_vec(),
        )
        .await
        .assert_problem(415, "sys.invalid_request");
        // Nothing was stored.
        let view = api
            .get(&format!(
                "/imports/{}",
                uploaded["id"].as_str().unwrap_or_default()
            ))
            .await;
        assert_eq!(view.assert_json(200)["mapped"], false);
    }

    // ----- preview ----------------------------------------------------------------------

    #[tokio::test]
    async fn the_preview_has_counts_a_loss_report_and_the_credential_statement() {
        let api = Api::new();
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let id = uploaded["id"].as_str().expect("id");
        let preview = api
            .get(&format!("/imports/{id}/preview"))
            .await
            .assert_json(200);
        assert_eq!(preview["id"], id);
        let counts = preview["summary"]["counts"].as_array().expect("counts");
        assert!(
            counts
                .iter()
                .any(|c| c["kind"] == "host" && c["action"] == "create" && c["count"] == 40),
            "{counts:?}"
        );
        assert_ne!(preview["loss"].as_array().expect("loss").len(), 0);
        assert!(preview["summary"]["loss"]["error"].as_u64().is_some());
        let statement = preview["credentials"]["statement"]
            .as_str()
            .expect("statement");
        assert!(statement.contains("operator secret"), "{statement}");
        assert_eq!(preview["credentials"]["allowed"], false);
        assert_eq!(preview["credentials"]["reason"], "vault_unavailable");
        assert!(
            preview["credentials"]["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("vault"))
        );
        assert_eq!(preview["can_apply"], false);
        assert!(
            preview["blockers"]
                .as_array()
                .expect("blockers")
                .contains(&json!("import.credentials.vault_required"))
        );
        assert!(preview["rows"].as_array().expect("rows").len() > 2);
    }

    // ----- GET /imports/{id}/rows -------------------------------------------------------

    /// The rows of all pages of `path`, following `next_cursor` to the end.
    async fn all_rows(api: &Api, path: &str, limit: usize) -> (Vec<Value>, usize) {
        let mut rows = Vec::new();
        let mut pages = 0;
        let mut url = format!("{path}?limit={limit}");
        loop {
            let page = api.get(&url).await.assert_json(200);
            pages += 1;
            let items = page["items"].as_array().expect("items");
            assert!(items.len() <= limit);
            rows.extend(items.iter().cloned());
            match page["next_cursor"].as_str() {
                Some(cursor) => url = format!("{path}?limit={limit}&cursor={cursor}"),
                None => break,
            }
            assert!(pages < 1_000, "paging does not end");
        }
        (rows, pages)
    }

    #[tokio::test]
    async fn rows_page_through_the_whole_preview_to_the_end() {
        let api = Api::new();
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let id = uploaded["id"].as_str().expect("id");
        let preview = api
            .get(&format!("/imports/{id}/preview?rows=1000"))
            .await
            .assert_json(200);
        let total = preview["total_rows"].as_u64().expect("total");
        let path = format!("/imports/{id}/rows");
        let (rows, pages) = all_rows(&api, &path, 100).await;
        assert_eq!(rows.len() as u64, total);
        assert_eq!(pages as u64, total.div_ceil(100));
        assert_eq!(&rows, preview["rows"].as_array().expect("rows"));
        let first = api.get(&path).await.assert_json(200);
        assert_eq!(first["items"].as_array().expect("items").len(), 200);
        assert_eq!(first["total_rows"], total);
        assert_eq!(first["base_revision"], preview["base_revision"]);
        let last = api
            .get(&format!("{path}?limit=1000"))
            .await
            .assert_json(200);
        assert_eq!(last["next_cursor"], Value::Null);
    }

    #[tokio::test]
    async fn rows_need_a_preview_of_the_current_mapping() {
        let api = Api::new();
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let id = uploaded["id"].as_str().expect("id");
        let path = format!("/imports/{id}/rows");
        api.get(&path)
            .await
            .assert_problem(409, "import.preview.stale");
        api.get(&format!("/imports/{id}/preview"))
            .await
            .assert_json(200);
        let page = api.get(&format!("{path}?limit=5")).await.assert_json(200);
        let cursor = page["next_cursor"].as_str().expect("cursor").to_owned();

        // A mapping change makes the stored preview and its cursors stale.
        api.skip_credentials(&uploaded).await;
        api.get(&format!("{path}?limit=5&cursor={cursor}"))
            .await
            .assert_problem(409, "import.preview.stale");
        api.get(&path)
            .await
            .assert_problem(409, "import.preview.stale");
        api.get(&format!("/imports/{id}/preview"))
            .await
            .assert_json(200);
        api.get(&format!("{path}?limit=5&cursor={cursor}"))
            .await
            .assert_problem(409, "import.preview.stale");
        let fresh = api.get(&format!("{path}?limit=5")).await.assert_json(200);
        assert_eq!(fresh["items"].as_array().expect("items").len(), 5);
    }

    #[tokio::test]
    async fn rows_check_their_parameters() {
        let api = Api::new();
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let id = uploaded["id"].as_str().expect("id");
        api.get(&format!("/imports/{id}/preview"))
            .await
            .assert_json(200);
        let path = format!("/imports/{id}/rows");
        api.get(&format!("{path}?limit=0"))
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get(&format!("{path}?limit=1001"))
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get(&format!("{path}?rows=5"))
            .await
            .assert_problem(400, "sys.invalid_query");
        api.get(&format!("{path}?cursor=not-a-cursor"))
            .await
            .assert_problem(400, "sys.invalid_cursor");
        let one = api.get(&format!("{path}?limit=1")).await.assert_json(200);
        assert_eq!(one["items"].as_array().expect("items").len(), 1);
        let most = api
            .get(&format!("{path}?limit=1000"))
            .await
            .assert_json(200);
        assert!(most["items"].as_array().expect("items").len() > 200);
        // A cursor of another import is refused.
        let other = api.upload_fixture("ip-plan.xlsx").await;
        let other_id = other["id"].as_str().expect("id");
        api.get(&format!("/imports/{other_id}/preview"))
            .await
            .assert_json(200);
        let cursor = one["next_cursor"].as_str().expect("cursor");
        api.get(&format!("/imports/{other_id}/rows?cursor={cursor}"))
            .await
            .assert_problem(400, "sys.invalid_cursor");
        api.get(&format!("/imports/{}/rows", uuid::Uuid::now_v7()))
            .await
            .assert_problem(404, "import.not_found");
    }

    #[tokio::test]
    async fn rows_limits_the_rows_of_the_preview() {
        let api = Api::new();
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let path = format!("/imports/{}/preview", uploaded["id"].as_str().expect("id"));
        let full = api.get(&path).await.assert_json(200);
        let two = api.get(&format!("{path}?rows=2")).await.assert_json(200);
        assert_eq!(two["rows"].as_array().expect("rows").len(), 2);
        assert_eq!(two["total_rows"], full["total_rows"]);
        assert_eq!(two["summary"], full["summary"]);
        let most = api.get(&format!("{path}?rows=1000")).await.assert_json(200);
        assert!(most["rows"].as_array().expect("rows").len() > 200);
    }

    #[tokio::test]
    async fn a_preview_refuses_bad_and_unknown_parameters() {
        let api = Api::new();
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let path = format!("/imports/{}/preview", uploaded["id"].as_str().expect("id"));
        for (query, parameter) in [
            ("rows=0", "rows"),
            ("rows=1001", "rows"),
            ("rows=-1", "rows"),
            ("rows=many", "rows"),
            ("rows=1&rows=2", "rows"),
            ("row=2", "row"),
            ("limit=5", "limit"),
            ("rows=2&at_least=1", "at_least"),
        ] {
            let problem = api
                .get(&format!("{path}?{query}"))
                .await
                .assert_problem(400, "sys.invalid_query");
            assert_eq!(problem["params"]["parameter"], parameter, "{query}");
        }
    }

    // ----- apply ------------------------------------------------------------------------

    #[tokio::test]
    async fn credential_columns_need_the_vault_unless_they_are_skipped() {
        let api = Api::new();
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let id = uploaded["id"].as_str().expect("id");
        let path = format!("/imports/{id}/apply");

        let problem = api
            .send("POST", &path, None, Vec::new())
            .await
            .assert_problem(403, "import.credentials.vault_required");
        assert_eq!(problem["params"]["reason"], "vault_unavailable");

        api.skip_credentials(&uploaded).await;
        let reply = api.send("POST", &path, None, Vec::new()).await;
        let accepted = reply.assert_json(202);
        let job = accepted["job_id"].as_str().expect("job id");
        assert_eq!(reply.header("location"), format!("/api/v1/jobs/{job}"));
        assert_eq!(api.wait_for_job(job).await, JobState::Succeeded);

        let view = api.get(&format!("/imports/{id}")).await.assert_json(200);
        assert_eq!(view["state"], "applied");
        assert_eq!(view["job_id"], job);
    }

    #[tokio::test]
    async fn the_apply_body_is_optional_json() {
        let api = Api::new();
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let path = format!("/imports/{}/apply", uploaded["id"].as_str().expect("id"));
        let json = Some("application/json");
        // Bodies that reach the service, which refuses the credentials.
        let reaches = [
            (None, b"".to_vec()),
            (None, b" \r\n".to_vec()),
            (json, b"".to_vec()),
            (json, b"{}".to_vec()),
            (
                json,
                br#"{"acknowledge": ["ipam.host.reservation_identifier"]}"#.to_vec(),
            ),
        ];
        for (content_type, body) in reaches {
            api.send("POST", &path, content_type, body)
                .await
                .assert_problem(403, "import.credentials.vault_required");
        }
        for body in [&b"{not json"[..], br#"{"acknowledge": 5}"#, b"\"text\""] {
            api.send("POST", &path, json, body.to_vec())
                .await
                .assert_problem(400, "sys.invalid_request");
        }
        api.send("POST", &path, None, b"{}".to_vec())
            .await
            .assert_problem(415, "sys.invalid_request");
        api.send("POST", &path, json, vec![b' '; APPLY_BODY_LIMIT + 1])
            .await
            .assert_problem(413, "sys.body_too_large");
    }

    // ----- authorization and availability -----------------------------------------------

    fn secret() -> ObjectRef {
        ObjectRef::singleton(ObjectKind::Secret)
    }

    #[tokio::test]
    async fn every_endpoint_asks_for_its_action_on_the_import() {
        let policy = Policy::new(true, true);
        let api = Api::with(Setup {
            authorizer: Some(policy.clone()),
            ..Setup::default()
        });
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let id = uploaded["id"].as_str().expect("id");
        let object = ObjectRef::from(id.parse::<ImportId>().expect("import id"));
        assert!(
            policy
                .asked()
                .contains(&(Action::Create, ObjectRef::singleton(ObjectKind::Import)))
        );

        let path = format!("/imports/{id}");
        let asked_by = |before: usize| policy.asked()[before..].to_vec();

        let before = policy.asked().len();
        api.get(&path).await.assert_json(200);
        assert_eq!(asked_by(before), vec![(Action::Read, object)]);

        let before = policy.asked().len();
        api.skip_credentials(&uploaded).await;
        assert_eq!(asked_by(before), vec![(Action::Update, object)]);

        // The credential gate (IAM-07) asks the same authorizer about secrets.
        let before = policy.asked().len();
        api.get(&format!("{path}/preview")).await.assert_json(200);
        let asked = asked_by(before);
        assert_eq!(asked[0], (Action::Read, object));
        assert!(asked.contains(&(Action::Create, secret())), "{asked:?}");
        assert!(asked.contains(&(Action::Reveal, secret())), "{asked:?}");

        let before = policy.asked().len();
        let accepted = api
            .send("POST", &format!("{path}/apply"), None, Vec::new())
            .await
            .assert_json(202);
        let asked = asked_by(before);
        assert_eq!(asked[0], (Action::Execute, object));
        assert!(asked.contains(&(Action::Reveal, secret())), "{asked:?}");
        api.wait_for_job(accepted["job_id"].as_str().expect("job id"))
            .await;

        let before = policy.asked().len();
        assert_eq!(api.delete(&path).await.status, StatusCode::NO_CONTENT);
        assert_eq!(asked_by(before), vec![(Action::Delete, object)]);
    }

    #[tokio::test]
    async fn a_principal_without_permission_is_refused() {
        let api = Api::new();
        let uploaded = api.upload_fixture("ip-plan.xlsx").await;
        let id = uploaded["id"].as_str().expect("id");
        let path = format!("/imports/{id}");
        let bytes = fixture("ip-plan.xlsx");
        let mapping = json!({ "sheets": [] });

        // Nothing allowed.
        let denied = api.sibling(Setup {
            authorizer: Some(Policy::new(false, false)),
            ..Setup::default()
        });
        let forbidden = (403, "auth.forbidden");
        denied
            .upload(&[("a.xlsx", &bytes)])
            .await
            .assert_problem(forbidden.0, forbidden.1);
        denied
            .get(&path)
            .await
            .assert_problem(forbidden.0, forbidden.1);
        denied
            .get(&format!("{path}/preview"))
            .await
            .assert_problem(forbidden.0, forbidden.1);
        denied
            .json("PUT", &format!("{path}/mapping"), &mapping)
            .await
            .assert_problem(forbidden.0, forbidden.1);
        denied
            .send("POST", &format!("{path}/apply"), None, Vec::new())
            .await
            .assert_problem(forbidden.0, forbidden.1);
        denied
            .delete(&path)
            .await
            .assert_problem(forbidden.0, forbidden.1);

        // Reading allowed, changing not.
        let reader = api.sibling(Setup {
            authorizer: Some(Policy::new(true, false)),
            ..Setup::default()
        });
        reader.get(&path).await.assert_json(200);
        reader
            .get(&format!("{path}/preview"))
            .await
            .assert_json(200);
        reader
            .upload(&[("a.xlsx", &bytes)])
            .await
            .assert_problem(forbidden.0, forbidden.1);
        reader
            .json("PUT", &format!("{path}/mapping"), &mapping)
            .await
            .assert_problem(forbidden.0, forbidden.1);
        reader
            .send("POST", &format!("{path}/apply"), None, Vec::new())
            .await
            .assert_problem(forbidden.0, forbidden.1);
        reader
            .delete(&path)
            .await
            .assert_problem(forbidden.0, forbidden.1);

        // The import is still there and unchanged.
        let again = api.get(&path).await.assert_json(200);
        assert_eq!(again, uploaded);
    }

    #[tokio::test]
    async fn without_the_import_service_every_endpoint_is_unavailable() {
        let api = Api::with(Setup {
            without_imports: true,
            ..Setup::default()
        });
        let path = format!("/imports/{}", unknown_id());
        let code = "import.unavailable";
        api.upload(&[("a.csv", b"ip\r\n192.0.2.1\r\n")])
            .await
            .assert_problem(503, code);
        api.get(&path).await.assert_problem(503, code);
        api.delete(&path).await.assert_problem(503, code);
        api.get(&format!("{path}/preview"))
            .await
            .assert_problem(503, code);
        api.json("PUT", &format!("{path}/mapping"), &json!({ "sheets": [] }))
            .await
            .assert_problem(503, code);
        api.send("POST", &format!("{path}/apply"), None, Vec::new())
            .await
            .assert_problem(503, code);
    }

    #[test]
    fn the_upload_schema_lists_binary_files() {
        let api = crate::routes::router().get_openapi().clone();
        let json = serde_json::to_value(&api).expect("document");
        let files = &json["components"]["schemas"]["ImportUpload"]["properties"]["files"];
        assert_eq!(files["type"], "array", "{files}");
        assert_eq!(files["items"]["format"], "binary", "{files}");
        let path = &json["paths"]["/imports/{id}/apply"]["post"];
        assert_ne!(path["requestBody"]["required"], true, "{path}");
        let schema = &path["requestBody"]["content"]["application/json"]["schema"];
        assert!(
            schema
                .to_string()
                .contains("#/components/schemas/ApplyRequest"),
            "{schema}"
        );
        assert!(
            path["responses"]["202"]["headers"]["Location"].is_object(),
            "{path}"
        );
        let upload = &json["paths"]["/imports"]["post"];
        assert!(
            upload["responses"]["201"]["headers"]["Location"].is_object(),
            "{upload}"
        );
    }
}
