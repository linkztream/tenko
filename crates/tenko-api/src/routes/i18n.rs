//! Language packs: the active languages, the compiled packs, upload, preview, activation and
//! the template (API-21).
//!
//! Area: i18n. Owner: WP3.7. Requirements: API-21. The store side is
//! [`crate::i18n::service`]; the validation [`crate::i18n::validate`].
//!
//! | Endpoint | Who | Success | Notable errors |
//! |---|---|---|---|
//! | `GET /i18n/languages` | everyone, before sign-in too | 200 [`LanguageList`] | |
//! | `GET /i18n/packs/{tag}` | everyone, before sign-in too | 200 [`PackMessages`], 304 | 404 `i18n.pack.not_found` |
//! | `GET /i18n/packs` | administer the system | 200 [`PackList`] | |
//! | `POST /i18n/packs` | administer the system | 201 [`PackUpload`] | 413 `i18n.pack.too_large`, 422 `i18n.pack.invalid` |
//! | `GET /i18n/packs/{tag}/report` | administer the system | 200 [`Report`] | 404 `i18n.pack.not_found` |
//! | `GET /i18n/packs/{tag}/candidate` | administer the system | 200 [`PackMessages`] | 404 `i18n.pack.no_candidate` |
//! | `POST /i18n/packs/{tag}/preview` | administer the system | 200 [`PackInfo`] | 404 `i18n.pack.no_candidate` |
//! | `POST /i18n/packs/{tag}/activate` | administer the system | 200 [`PackInfo`] | 409 `i18n.pack.not_previewed` |
//! | `DELETE /i18n/packs/{tag}/candidate` | administer the system | 200 [`PackInfo`] | 404 `i18n.pack.no_candidate` |
//! | `DELETE /i18n/packs/{tag}` | administer the system | 204 | 409 `i18n.pack.default_language` |
//! | `GET /i18n/template.xlf` | read the system | 200 XLIFF | 503 `i18n.unavailable` |
//!
//! The two public operations take no session: the sign-in page needs them. A pack is served
//! with its content hash as `ETag`; a request that names the hash in `?hash=` (as the UI does,
//! from `GET /i18n/languages`) may be cached for a year, any other must revalidate.
//!
//! The server binary may add an `Extension<Arc<Languages>>`; without one the routes use the
//! languages of the embedded UI ([`Languages::embedded`]).

use std::sync::Arc;

use axum::{
    Extension, Json,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tenko_auth::AuthService;
use tenko_core::{Action, i18n::is_language_tag};
use utoipa::IntoParams;
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt},
    routes,
};

use crate::{
    extract::Ctx,
    i18n::{
        MAX_PACK_BYTES,
        dto::{
            LanguageList, PackInfo, PackList, PackMessages, PackOrigin, PackUpload, PackUploadForm,
            Report,
        },
        service::Languages,
    },
    problem::{ApiError, ProblemDetails},
    routes::import::{boundary_from_content_type, parse_multipart},
    state::AppState,
};

/// Room for the multipart framing on top of the document.
const MULTIPART_OVERHEAD: usize = 64 * 1024;

/// How long a pack named by its hash may be cached.
const IMMUTABLE: HeaderValue = HeaderValue::from_static("public, max-age=31536000, immutable");
/// Answers that change with the store.
const REVALIDATE: HeaderValue = HeaderValue::from_static("no-cache");

/// The routes of the area.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_languages))
        .routes(
            routes!(list_packs, upload_pack)
                .layer(DefaultBodyLimit::max(MAX_PACK_BYTES + MULTIPART_OVERHEAD)),
        )
        .routes(routes!(get_pack, delete_pack))
        .routes(routes!(get_pack_report))
        .routes(routes!(get_pack_candidate, discard_pack_candidate))
        .routes(routes!(preview_pack))
        .routes(routes!(activate_pack))
        .routes(routes!(get_template))
}

type Langs = Option<Extension<Arc<Languages>>>;
type Auth = Option<Extension<Arc<AuthService>>>;

fn languages(langs: Langs) -> Arc<Languages> {
    langs.map_or_else(Languages::embedded, |Extension(languages)| languages)
}

/// A tag from the path; anything that is not shaped like a language tag is unknown.
fn path_tag(tag: &str) -> Result<&str, ApiError> {
    if is_language_tag(tag) {
        Ok(tag)
    } else {
        Err(ApiError::new(
            "i18n.pack.not_found",
            404,
            "there is no language pack with this tag",
        )
        .with_param("tag", tag))
    }
}

fn administer(state: &AppState, ctx: &tenko_core::RequestCtx) -> Result<(), ApiError> {
    state.authorize(
        &ctx.principal,
        Action::Administer,
        &super::system::system_object(),
    )
}

async fn default_language(auth: Auth) -> Option<String> {
    let Extension(auth) = auth?;
    match auth.installation().await {
        Ok(installation) => installation.map(|installation| installation.language),
        Err(error) => {
            tracing::warn!(%error, "the installation's default language cannot be read");
            None
        }
    }
}

fn with_cache(mut response: Response, cache: HeaderValue) -> Response {
    response.headers_mut().insert(header::CACHE_CONTROL, cache);
    response
}

/// Lists the languages users may choose: the built-in ones, with the hash of an active
/// uploaded override, then the active uploaded languages; and the installation's default
/// language. Public: the sign-in page and the setup wizard need it.
#[utoipa::path(
    get,
    path = "/i18n/languages",
    tag = "i18n",
    operation_id = "get_languages",
    summary = "List the languages of the installation",
    responses(
        (status = 200, description = "The languages users may choose", body = LanguageList)
    ),
    security()
)]
async fn get_languages(
    State(state): State<AppState>,
    langs: Langs,
    auth: Auth,
) -> Result<Response, ApiError> {
    let list = languages(langs)
        .languages(state.store.as_ref(), default_language(auth).await)
        .await?;
    Ok(with_cache(Json(list).into_response(), REVALIDATE))
}

/// The query of `GET /i18n/packs/{tag}`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PackQuery {
    /// The hash from `GET /i18n/languages`: the answer may then be cached for a year.
    pub hash: Option<String>,
}

/// Serves the messages of a language's active uploaded pack, for the UI's loader. Public:
/// the sign-in page renders in the pack. Built-in languages without an uploaded override
/// have none (the UI has them compiled in).
#[utoipa::path(
    get,
    path = "/i18n/packs/{tag}",
    tag = "i18n",
    operation_id = "get_pack",
    summary = "Get the messages of an active language pack",
    params(("tag" = String, Path, description = "BCP 47 language tag"), PackQuery),
    responses(
        (status = 200, description = "The messages, with the content hash as ETag", body = PackMessages,
            headers(("ETag" = String, description = "The content hash in quotes"))),
        (status = 304, description = "Not modified (If-None-Match)"),
        (status = 404, description = "No active uploaded pack for the tag (`i18n.pack.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security()
)]
async fn get_pack(
    State(state): State<AppState>,
    langs: Langs,
    Path(tag): Path<String>,
    Query(query): Query<PackQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let tag = path_tag(&tag)?;
    let pack = languages(langs)
        .active_messages(state.store.as_ref(), tag)
        .await?;
    let etag = format!("\"{}\"", pack.hash);
    let cache = if query.hash.as_deref() == Some(pack.hash.as_str()) {
        IMMUTABLE
    } else {
        REVALIDATE
    };
    let matches = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(|candidate| candidate.trim().trim_start_matches("W/"))
                .any(|candidate| candidate == etag || candidate == "*")
        });
    let etag = HeaderValue::from_str(&etag)
        .map_err(|_| ApiError::new("sys.internal", 500, "the pack hash is not a header value"))?;
    let mut response = if matches {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        Json(pack).into_response()
    };
    response.headers_mut().insert(header::ETAG, etag);
    Ok(with_cache(response, cache))
}

/// Lists every language with its active version and its candidate, for the languages page.
#[utoipa::path(
    get,
    path = "/i18n/packs",
    tag = "i18n",
    operation_id = "list_packs",
    summary = "List the language packs with their versions",
    responses(
        (status = 200, description = "Every language with its versions", body = PackList),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn list_packs(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    langs: Langs,
) -> Result<Json<PackList>, ApiError> {
    administer(&state, &ctx)?;
    Ok(Json(languages(langs).list(state.store.as_ref()).await?))
}

fn malformed(detail: impl Into<String>) -> ApiError {
    ApiError::new("i18n.upload.malformed", 400, detail)
}

/// Uploads a pack as `multipart/form-data` with one file part: an XLIFF 2.0 document of at
/// most 2 MiB whose `trgLang` names the language. The pack is validated against the running
/// UI and becomes the language's candidate, which an administrator previews and activates;
/// the answer is the report. A refused pack answers 422 with one entry in `errors` per
/// problem (`field` the unit key or `file`, `code`, and the params `detail` and `line`).
#[utoipa::path(
    post,
    path = "/i18n/packs",
    tag = "i18n",
    operation_id = "upload_pack",
    summary = "Upload a language pack",
    request_body(content = PackUploadForm, content_type = "multipart/form-data"),
    responses(
        (status = 201, description = "Validated and stored as the candidate of its language", body = PackUpload),
        (status = 400, description = "No file, several files or a malformed multipart body (`i18n.upload.empty`, `i18n.upload.malformed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "Over 2 MiB (`i18n.pack.too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Not a usable pack (`i18n.pack.invalid`, the problems in `errors`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No embedded UI to check against (`i18n.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn upload_pack(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    langs: Langs,
    request: Request,
) -> Result<Response, ApiError> {
    administer(&state, &ctx)?;
    let boundary = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(boundary_from_content_type)
        .ok_or_else(|| malformed("the upload must be multipart/form-data with a boundary"))?;
    let too_large = || {
        ApiError::new(
            "i18n.pack.too_large",
            413,
            format!("a language pack has at most {MAX_PACK_BYTES} bytes"),
        )
        .with_param("limit", MAX_PACK_BYTES.to_string())
    };
    let body = axum::body::to_bytes(request.into_body(), MAX_PACK_BYTES + MULTIPART_OVERHEAD)
        .await
        .map_err(|_| too_large())?;
    let files = parse_multipart(&body, &boundary).map_err(|error| malformed(error.to_string()))?;
    let file = match files.as_slice() {
        [file] => file,
        [] => {
            return Err(ApiError::new(
                "i18n.upload.empty",
                400,
                "the upload has no file",
            ));
        }
        _ => return Err(malformed("upload one language pack at a time")),
    };
    if file.bytes.len() > MAX_PACK_BYTES {
        return Err(too_large());
    }
    let upload = languages(langs)
        .upload(state.store.as_ref(), &ctx, file.bytes, PackOrigin::Upload)
        .await?;
    Ok((StatusCode::CREATED, Json(upload)).into_response())
}

/// Shows the validation report of a language's candidate, else of its active version.
#[utoipa::path(
    get,
    path = "/i18n/packs/{tag}/report",
    tag = "i18n",
    operation_id = "get_pack_report",
    summary = "Get the validation report of a language pack",
    params(("tag" = String, Path, description = "BCP 47 language tag")),
    responses(
        (status = 200, description = "The report", body = Report),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Nothing uploaded for the tag (`i18n.pack.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn get_pack_report(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    langs: Langs,
    Path(tag): Path<String>,
) -> Result<Json<Report>, ApiError> {
    administer(&state, &ctx)?;
    let tag = path_tag(&tag)?;
    Ok(Json(
        languages(langs).report(state.store.as_ref(), tag).await?,
    ))
}

/// Serves the messages of a language's candidate, for an administrator's preview.
#[utoipa::path(
    get,
    path = "/i18n/packs/{tag}/candidate",
    tag = "i18n",
    operation_id = "get_pack_candidate",
    summary = "Get the messages of an uploaded language pack for a preview",
    params(("tag" = String, Path, description = "BCP 47 language tag")),
    responses(
        (status = 200, description = "The messages of the candidate", body = PackMessages),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No candidate (`i18n.pack.no_candidate`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn get_pack_candidate(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    langs: Langs,
    Path(tag): Path<String>,
) -> Result<Response, ApiError> {
    administer(&state, &ctx)?;
    let tag = path_tag(&tag)?;
    let pack = languages(langs)
        .candidate_messages(state.store.as_ref(), tag)
        .await?;
    Ok(with_cache(
        Json(pack).into_response(),
        HeaderValue::from_static("no-store"),
    ))
}

/// Starts a preview: marks the candidate previewed (once previewed, it can be activated).
/// The UI then renders in its messages for the administrator's session only.
#[utoipa::path(
    post,
    path = "/i18n/packs/{tag}/preview",
    tag = "i18n",
    operation_id = "preview_pack",
    summary = "Preview an uploaded language pack",
    params(("tag" = String, Path, description = "BCP 47 language tag")),
    responses(
        (status = 200, description = "The language with its candidate marked previewed", body = PackInfo),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No candidate (`i18n.pack.no_candidate`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn preview_pack(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    langs: Langs,
    Path(tag): Path<String>,
) -> Result<Json<PackInfo>, ApiError> {
    administer(&state, &ctx)?;
    let tag = path_tag(&tag)?;
    Ok(Json(
        languages(langs)
            .preview(state.store.as_ref(), &ctx, tag)
            .await?,
    ))
}

/// Activates a previewed candidate: every user may choose the language, and every client
/// that shows it reloads its messages (the `system` event of the `i18n.*` tables).
#[utoipa::path(
    post,
    path = "/i18n/packs/{tag}/activate",
    tag = "i18n",
    operation_id = "activate_pack",
    summary = "Activate an uploaded language pack",
    params(("tag" = String, Path, description = "BCP 47 language tag")),
    responses(
        (status = 200, description = "The language with its new active version", body = PackInfo),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No candidate (`i18n.pack.no_candidate`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Not previewed yet (`i18n.pack.not_previewed`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn activate_pack(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    langs: Langs,
    Path(tag): Path<String>,
) -> Result<Json<PackInfo>, ApiError> {
    administer(&state, &ctx)?;
    let tag = path_tag(&tag)?;
    Ok(Json(
        languages(langs)
            .activate(state.store.as_ref(), &ctx, tag)
            .await?,
    ))
}

/// Discards a language's candidate; its active version stays.
#[utoipa::path(
    delete,
    path = "/i18n/packs/{tag}/candidate",
    tag = "i18n",
    operation_id = "discard_pack_candidate",
    summary = "Discard an uploaded language pack that is not active",
    params(("tag" = String, Path, description = "BCP 47 language tag")),
    responses(
        (status = 200, description = "The language without the candidate", body = PackInfo),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No candidate (`i18n.pack.no_candidate`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn discard_pack_candidate(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    langs: Langs,
    Path(tag): Path<String>,
) -> Result<Json<PackInfo>, ApiError> {
    administer(&state, &ctx)?;
    let tag = path_tag(&tag)?;
    Ok(Json(
        languages(langs)
            .discard(state.store.as_ref(), &ctx, tag)
            .await?,
    ))
}

/// Removes everything uploaded for a language: a built-in language reverts to its built-in
/// messages, any other language is retired (users who chose it fall back to their browser's
/// language or the installation default).
#[utoipa::path(
    delete,
    path = "/i18n/packs/{tag}",
    tag = "i18n",
    operation_id = "delete_pack",
    summary = "Remove a language pack, or revert a built-in language",
    params(("tag" = String, Path, description = "BCP 47 language tag")),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Nothing uploaded for the tag (`i18n.pack.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The installation's default language (`i18n.pack.default_language`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn delete_pack(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    langs: Langs,
    auth: Auth,
    Path(tag): Path<String>,
) -> Result<StatusCode, ApiError> {
    administer(&state, &ctx)?;
    let tag = path_tag(&tag)?;
    let default = default_language(auth).await;
    languages(langs)
        .remove(state.store.as_ref(), &ctx, tag, default.as_deref())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The query of `GET /i18n/template.xlf`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TemplateQuery {
    /// The language whose current messages fill the targets; the source language (`en`) by
    /// default, whose template has the English text as every target.
    pub language: Option<String>,
}

/// Exports the running key set as an XLIFF 2.0 pack for translators: every message with its
/// English source and note, and as target the language's current message where it has one.
#[utoipa::path(
    get,
    path = "/i18n/template.xlf",
    tag = "i18n",
    operation_id = "get_template",
    summary = "Export the template of a language pack",
    params(TemplateQuery),
    responses(
        (status = 200, description = "The XLIFF 2.0 document", body = String, content_type = "application/xliff+xml"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Not a language tag (`i18n.pack.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No embedded UI (`i18n.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_template(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    langs: Langs,
    Query(query): Query<TemplateQuery>,
) -> Result<Response, ApiError> {
    state.authorize(
        &ctx.principal,
        Action::Read,
        &super::system::system_object(),
    )?;
    let languages = languages(langs);
    let tag = match &query.language {
        Some(tag) => path_tag(tag)?.to_owned(),
        None => languages.keys().language.clone(),
    };
    let document = languages.template(state.store.as_ref(), &tag).await?;
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"tenko-{tag}.xlf\""))
        .map_err(|_| {
        ApiError::new("sys.internal", 500, "the file name is not a header value")
    })?;
    let mut response = Response::new(Body::from(document));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xliff+xml; charset=utf-8"),
    );
    headers.insert(header::CONTENT_DISPOSITION, disposition);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[cfg(test)]
mod tests;
