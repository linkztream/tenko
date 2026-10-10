//! Connector plugins and connector instances (ADR 0012, CONN-19).
//!
//! Area: connectors. Owner: WP2.0.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /connectors/plugins` | 200 the bundled and installed plugins with their manifests | |
//! | `GET /connectors` | 200 page of [`ConnectorView`], by name | 400 `sys.invalid_query`, `sys.invalid_cursor` |
//! | `POST /connectors` | 201 [`ConnectorView`] with `ETag` | 400, 403, 409 `connect.instance.name_taken`, 422 `connect.plugin.*`, `connect.settings.invalid`, `connect.secret.*`, `connect.instance.*` |
//! | `GET /connectors/{id}` | 200 [`ConnectorView`] with `ETag` | 400, 403, 404 `connect.instance.not_found` |
//! | `PATCH /connectors/{id}` | 200 [`ConnectorView`] with `ETag` | as create, plus 404 and 409 `connect.instance.conflict` (`If-Match`) |
//! | `DELETE /connectors/{id}` | 204 | 403, 404, 409 |
//! | `POST /connectors/{id}/enable` | 200 [`ConnectorView`] | 403, 404, 409 |
//! | `POST /connectors/{id}/disable` | 200 [`ConnectorView`] | 403, 404, 409 |
//! | `POST /connectors/{id}/run` | 202 [`RunAccepted`] (the job) | 403, 404, 409 `connect.instance.disabled`, `connect.instance.nothing_to_run` |
//! | `POST /connectors/{id}/check` | 200 [`HealthReport`] | 403, 404, 409 `connect.instance.disabled`, 503 `connect.plugin.unavailable`, 504 `connect.timeout` |
//!
//! # The service
//!
//! The server adds the connector host ([`ConnectorHost`]) as a request extension. Without
//! it, every endpoint answers `501` `sys.not_implemented`, so the bare router of the route
//! table test keeps working.
//!
//! # Authorization
//!
//! Reading needs [`Action::Read`] on connectors (the lists are empty without it); creating
//! [`Action::Create`]; changing, enabling and disabling [`Action::Update`]; deleting
//! [`Action::Delete`]; running and checking [`Action::Execute`] on the instance.
//!
//! A secret reference lets a plugin use the secret against a target the settings name, so
//! setting references requires [`Action::Reveal`] and [`Action::Update`] on every
//! referenced secret (operators may reveal secrets but not manage them), and so does
//! changing the settings of an instance that holds references. An operator can therefore
//! manage connectors without secrets; secret-bearing ones need an administrator.

use std::sync::Arc;

use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tenko_connect::{
    HealthReport,
    host::{
        ConnectorHost, HostError,
        registry::PluginInfo,
        service::{ConnectorPatch, ConnectorView, NewConnector},
    },
};
use tenko_core::{
    Action, CodedError, ConnectorId, JobId, ObjectKind, ObjectRef, Principal, RequestCtx, Revision,
    ScopeFilter, error::codes, secret::SecretRef,
};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    dto::Page,
    extract::Ctx,
    list::{Filters, PageParams, encode_cursor},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// Names the list endpoint in cursors.
const CURSOR_ENDPOINT: &str = "connect.instances";

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_connector_plugins))
        .routes(routes!(list_connectors, create_connector))
        .routes(routes!(get_connector, update_connector, delete_connector))
        .routes(routes!(enable_connector))
        .routes(routes!(disable_connector))
        .routes(routes!(run_connector))
        .routes(routes!(check_connector))
}

/// The plugins of this node.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PluginList {
    /// Bundled plugins first, then installed ones by name.
    pub items: Vec<PluginInfo>,
}

/// The answer to a run request: the job that runs the connector.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RunAccepted {
    /// The job (`GET /jobs/{id}` shows its progress).
    pub job: JobId,
}

type Host = Option<Extension<Arc<ConnectorHost>>>;

/// The host, or the `501` stub answer when the server did not add one.
fn host_or_stub(host: Host, method: &str, path: &str) -> Result<Arc<ConnectorHost>, ApiError> {
    host.map(|Extension(host)| host)
        .ok_or_else(|| not_implemented(method, path))
}

fn failed(error: HostError) -> ApiError {
    ApiError::from_coded_error(error.into_coded())
}

fn invalid_request(status: u16, detail: impl Into<String>) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(codes::INVALID_REQUEST, status, detail).with_title("Invalid request"),
    )
}

fn parse_id(raw: &str) -> Result<ConnectorId, ApiError> {
    raw.parse().map_err(|_| {
        invalid_request(400, "the connector identifier is not a UUID").with_param("field", "id")
    })
}

/// A JSON object body.
fn parse_body<T: DeserializeOwned>(body: Result<Bytes, BytesRejection>) -> Result<T, ApiError> {
    let bytes = body.map_err(|rejection| {
        invalid_request(
            rejection.status().as_u16(),
            "the request body cannot be read",
        )
    })?;
    if bytes.trim_ascii_start().first() != Some(&b'{') {
        return Err(invalid_request(
            400,
            "the request body must be a JSON object",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid_request(400, format!("the request body is not valid: {error}")))
}

/// `If-Match: "<revision>"`; `*` and absence mean any revision.
fn if_match(headers: &HeaderMap) -> Result<Option<Revision>, ApiError> {
    let Some(value) = headers.get(header::IF_MATCH) else {
        return Ok(None);
    };
    let text = value.to_str().unwrap_or_default().trim();
    if text == "*" {
        return Ok(None);
    }
    let bare = text.strip_prefix("W/").unwrap_or(text).trim_matches('"');
    bare.parse::<u64>().map(|r| Some(Revision(r))).map_err(|_| {
        invalid_request(400, "If-Match is not a revision such as \"12\"")
            .with_param("field", "If-Match")
    })
}

/// A view with its `ETag`.
fn with_etag(status: StatusCode, view: ConnectorView) -> Response {
    let etag = HeaderValue::from_str(&format!("\"{}\"", view.revision.0)).ok();
    let mut response = (status, Json(view)).into_response();
    if let Some(etag) = etag {
        response.headers_mut().insert(header::ETAG, etag);
    }
    response
}

fn authorize(
    app: &AppState,
    principal: &Principal,
    action: Action,
    object: &ObjectRef,
) -> Result<(), ApiError> {
    app.authorize(principal, action, object)
}

/// Every referenced secret needs [`Action::Reveal`]: a plugin can use it against the
/// target the settings name. It also needs [`Action::Update`] on the secret (WP2.1):
/// operators may reveal secrets under the reveal policy (TGL-24), but pointing a plugin at
/// a target with a secret bypasses that policy, so it stays with the people who manage
/// secrets.
fn authorize_secrets<'a>(
    app: &AppState,
    principal: &Principal,
    secrets: impl IntoIterator<Item = &'a SecretRef>,
) -> Result<(), ApiError> {
    for reference in secrets {
        let object = ObjectRef::from(reference.secret);
        authorize(app, principal, Action::Reveal, &object)?;
        authorize(app, principal, Action::Update, &object)?;
    }
    Ok(())
}

fn may_read_any(app: &AppState, principal: &Principal) -> bool {
    app.authorizer.as_ref().is_none_or(|authorizer| {
        !matches!(
            authorizer.scope(principal, Action::Read, ObjectKind::Connector),
            ScopeFilter::Nothing
        )
    })
}

/// Lists the plugins this node can run: bundled in the binary and installed in the
/// plugins directory, each with its manifest (the settings schema the configuration form
/// is built from, the secret purposes and the network targets) and what keeps it from
/// running.
#[utoipa::path(
    get,
    path = "/connectors/plugins",
    tag = "connectors",
    operation_id = "list_connector_plugins",
    summary = "List connector plugins",
    responses(
        (status = 200, description = "The plugins; empty without permission to read connectors", body = PluginList),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_connector_plugins(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    host: Host,
) -> Result<Json<PluginList>, ApiError> {
    let host = host_or_stub(host, "GET", "/connectors/plugins")?;
    if !may_read_any(&app, &cx.principal) {
        return Ok(Json(PluginList { items: Vec::new() }));
    }
    Ok(Json(PluginList {
        items: host.plugins(),
    }))
}

/// Lists connector instances by name, each with the health of its plugin process and
/// remote system and its last run.
#[utoipa::path(
    get,
    path = "/connectors",
    tag = "connectors",
    operation_id = "list_connectors",
    summary = "List connector instances",
    params(PageParams),
    responses(
        (status = 200, description = "A page of connector instances by name; empty without permission to read connectors", body = Page<ConnectorView>),
        (status = 400, description = "A parameter is unknown or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_connectors(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    host: Host,
    filters: Filters,
) -> Result<Json<Page<ConnectorView>>, ApiError> {
    let host = host_or_stub(host, "GET", "/connectors")?;
    filters.only(&[])?;
    let page = filters.page()?;
    let limit = page.limit()?;
    let scope = filters.scope(CURSOR_ENDPOINT);
    let after: Option<(String, ConnectorId)> = page.cursor(scope)?;
    if !may_read_any(&app, &cx.principal) {
        return Ok(Json(Page::new(Vec::new(), None, host.revision())));
    }
    let views = host
        .list(page.at_least.map(Revision))
        .await
        .map_err(failed)?;
    let revision = host.revision();
    let key = |view: &ConnectorView| (view.instance.name.to_lowercase(), view.instance.id);
    let mut items: Vec<ConnectorView> = views
        .into_iter()
        .filter(|view| after.as_ref().is_none_or(|after| key(view) > *after))
        .collect();
    let next = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|last| encode_cursor(scope, &key(last)))
    } else {
        None
    };
    Ok(Json(Page::new(items, next, revision)))
}

/// Creates a connector instance of a plugin. The settings are validated against the
/// plugin's settings schema and stored with its defaults filled in; secrets are given by
/// reference to operator secrets of the vault, one per declared purpose. An enabled
/// instance starts its plugin at once.
#[utoipa::path(
    post,
    path = "/connectors",
    tag = "connectors",
    operation_id = "create_connector",
    summary = "Create a connector instance",
    request_body(content = NewConnector, content_type = "application/json"),
    responses(
        (status = 201, description = "The new instance, with `ETag`", body = ConnectorView),
        (status = 400, description = "The body is not valid JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to create connectors, or to reveal a referenced secret (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Another instance has the name (`connect.instance.name_taken`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Unknown or unusable plugin (`connect.plugin.unknown`, `connect.plugin.unusable`), invalid settings (`connect.settings.invalid`, with field errors), secret references (`connect.secret.undeclared`, `connect.secret.missing`, `connect.secret.not_found`, `connect.secret.not_operator`) or values (`connect.instance.name`, `connect.instance.poll_interval`, `connect.instance.call_timeout`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_connector(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    host: Host,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let host = host_or_stub(host, "POST", "/connectors")?;
    authorize(
        &app,
        &cx.principal,
        Action::Create,
        &ObjectRef::singleton(ObjectKind::Connector),
    )?;
    let new: NewConnector = parse_body(body)?;
    authorize_secrets(&app, &cx.principal, new.secrets.values())?;
    let view = host.create(&cx, new).await.map_err(failed)?;
    let mut response = with_etag(StatusCode::CREATED, view.clone());
    if let Ok(location) = HeaderValue::from_str(&format!(
        "{}/connectors/{}",
        crate::API_BASE,
        view.instance.id
    )) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    Ok(response)
}

/// Shows one connector instance with the health of its plugin process and remote system
/// and its last run.
#[utoipa::path(
    get,
    path = "/connectors/{id}",
    tag = "connectors",
    operation_id = "get_connector",
    summary = "Get a connector instance",
    params(
        ("id" = String, Path, description = "Connector identifier (UUID)"),
        ("at_least" = Option<u64>, Query, description = "Read at least at this store revision (read-your-writes)")
    ),
    responses(
        (status = 200, description = "The instance, with `ETag`", body = ConnectorView),
        (status = 400, description = "The identifier or a parameter is malformed (`sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to read the instance", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such instance (`connect.instance.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_connector(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    host: Host,
    Path(id): Path<String>,
    filters: Filters,
) -> Result<Response, ApiError> {
    let host = host_or_stub(host, "GET", "/connectors/{id}")?;
    let id = parse_id(&id)?;
    filters.only(&[])?;
    let at_least = filters.page()?.at_least.map(Revision);
    authorize(&app, &cx.principal, Action::Read, &ObjectRef::from(id))?;
    let view = host.get(id, at_least).await.map_err(failed)?;
    Ok(with_etag(StatusCode::OK, view))
}

/// Changes a connector instance: its name, settings (the whole object, validated against
/// the schema), secret references (the whole map), poll interval, call timeout or whether
/// writes are allowed. Absent members stay as they are. Settings and secrets travel with
/// every call, so the plugin is not restarted.
#[utoipa::path(
    patch,
    path = "/connectors/{id}",
    tag = "connectors",
    operation_id = "update_connector",
    summary = "Change a connector instance",
    params(
        ("id" = String, Path, description = "Connector identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "Apply only to this revision (the `ETag` of a read)")
    ),
    request_body(content = ConnectorPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed instance, with `ETag`", body = ConnectorView),
        (status = 400, description = "The identifier, `If-Match` or the body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to change the instance, or to reveal a referenced secret (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such instance (`connect.instance.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The name is taken (`connect.instance.name_taken`) or the instance changed since `If-Match` (`connect.instance.conflict`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid settings, secret references or values, as for create", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_connector(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    host: Host,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let host = host_or_stub(host, "PATCH", "/connectors/{id}")?;
    let id = parse_id(&id)?;
    let expect = if_match(&headers)?;
    authorize(&app, &cx.principal, Action::Update, &ObjectRef::from(id))?;
    let patch: ConnectorPatch = parse_body(body)?;
    if let Some(secrets) = &patch.secrets {
        authorize_secrets(&app, &cx.principal, secrets.values())?;
    }
    if patch.settings.is_some() || patch.secrets.is_some() {
        // New settings redirect the secrets the instance already holds.
        let current = host.get(id, None).await.map_err(failed)?;
        authorize_secrets(&app, &cx.principal, current.instance.secrets.values())?;
    }
    let view = host.update(&cx, id, patch, expect).await.map_err(failed)?;
    Ok(with_etag(StatusCode::OK, view))
}

/// Deletes a connector instance and its last run; its plugin stops. The vault secrets it
/// referenced stay in the vault.
#[utoipa::path(
    delete,
    path = "/connectors/{id}",
    tag = "connectors",
    operation_id = "delete_connector",
    summary = "Delete a connector instance",
    params(("id" = String, Path, description = "Connector identifier (UUID)")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to delete the instance", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such instance (`connect.instance.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The instance changed at the same time (`connect.instance.conflict`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_connector(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    host: Host,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let host = host_or_stub(host, "DELETE", "/connectors/{id}")?;
    let id = parse_id(&id)?;
    authorize(&app, &cx.principal, Action::Delete, &ObjectRef::from(id))?;
    host.delete(&cx, id).await.map_err(failed)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_enabled(
    app: &AppState,
    cx: &RequestCtx,
    host: &ConnectorHost,
    id: &str,
    enabled: bool,
) -> Result<Response, ApiError> {
    let id = parse_id(id)?;
    authorize(app, &cx.principal, Action::Update, &ObjectRef::from(id))?;
    let view = host.set_enabled(cx, id, enabled).await.map_err(failed)?;
    Ok(with_etag(StatusCode::OK, view))
}

/// Enables a connector instance: its plugin starts and its schedule runs. Enabling an
/// enabled instance whose plugin failed starts the plugin again.
#[utoipa::path(
    post,
    path = "/connectors/{id}/enable",
    tag = "connectors",
    operation_id = "enable_connector",
    summary = "Enable a connector instance",
    params(("id" = String, Path, description = "Connector identifier (UUID)")),
    responses(
        (status = 200, description = "The instance, with `ETag`", body = ConnectorView),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to change the instance", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such instance (`connect.instance.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The instance changed at the same time (`connect.instance.conflict`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn enable_connector(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    host: Host,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host = host_or_stub(host, "POST", "/connectors/{id}/enable")?;
    set_enabled(&app, &cx, &host, &id, true).await
}

/// Disables a connector instance: its plugin stops and its schedule pauses.
#[utoipa::path(
    post,
    path = "/connectors/{id}/disable",
    tag = "connectors",
    operation_id = "disable_connector",
    summary = "Disable a connector instance",
    params(("id" = String, Path, description = "Connector identifier (UUID)")),
    responses(
        (status = 200, description = "The instance, with `ETag`", body = ConnectorView),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to change the instance", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such instance (`connect.instance.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The instance changed at the same time (`connect.instance.conflict`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn disable_connector(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    host: Host,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host = host_or_stub(host, "POST", "/connectors/{id}/disable")?;
    set_enabled(&app, &cx, &host, &id, false).await
}

/// Runs a connector instance now, as a job: the plugin's inventory and topology are read
/// and handed on as observations. Runs of one instance never overlap; the job waits for a
/// running one.
#[utoipa::path(
    post,
    path = "/connectors/{id}/run",
    tag = "connectors",
    operation_id = "run_connector",
    summary = "Run a connector instance now",
    params(("id" = String, Path, description = "Connector identifier (UUID)")),
    responses(
        (status = 202, description = "The run was submitted as a job", body = RunAccepted),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to run the instance", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such instance (`connect.instance.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The instance is disabled (`connect.instance.disabled`) or its plugin reads nothing (`connect.instance.nothing_to_run`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The job engine is not available (`connect.jobs_unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn run_connector(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    host: Host,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<RunAccepted>), ApiError> {
    let host = host_or_stub(host, "POST", "/connectors/{id}/run")?;
    let id = parse_id(&id)?;
    authorize(&app, &cx.principal, Action::Execute, &ObjectRef::from(id))?;
    let job = host.run_now(&cx, id).await.map_err(failed)?;
    Ok((StatusCode::ACCEPTED, Json(RunAccepted { job })))
}

/// Checks the remote system of a connector instance now (reachability and credentials,
/// without changing anything) and keeps the result as its health. A remote system that
/// answers with an error is a report with the health `unreachable` or `degraded`.
#[utoipa::path(
    post,
    path = "/connectors/{id}/check",
    tag = "connectors",
    operation_id = "check_connector",
    summary = "Check a connector instance now",
    params(("id" = String, Path, description = "Connector identifier (UUID)")),
    responses(
        (status = 200, description = "The health of the remote system", body = HealthReport),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to run the instance", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such instance (`connect.instance.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The instance is disabled (`connect.instance.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The plugin is not running (`connect.plugin.unavailable`, `connect.plugin.unusable`) or the vault or audit log is not available", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 504, description = "The plugin did not answer in time (`connect.timeout`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn check_connector(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    host: Host,
    Path(id): Path<String>,
) -> Result<Json<HealthReport>, ApiError> {
    let host = host_or_stub(host, "POST", "/connectors/{id}/check")?;
    let id = parse_id(&id)?;
    authorize(&app, &cx.principal, Action::Execute, &ObjectRef::from(id))?;
    // A check of a missing instance answers 404 rather than 409.
    host.get(id, None).await.map_err(failed)?;
    let report = host.check(id, cx.principal.user()).await.map_err(failed)?;
    Ok(Json(report))
}

#[cfg(test)]
mod tests;
