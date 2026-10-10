//! Operator secrets, their reveal and the credentials of hosts (IAM-15, IAM-16, IAM-07,
//! API-11, TGL-24).
//!
//! Area: secrets. Owner: WP2.1.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /secrets` | 200 page of [`OperatorSecretView`] by name; empty without permission | 400 `sys.invalid_query`, `sys.invalid_cursor` |
//! | `POST /secrets` | 201 [`OperatorSecretView`] with `ETag` | 400, 403 (`auth.forbidden`, `auth.step_up_required`), 409 `vault.pin_coupling`, 413 `vault.secret.too_large`, 422 `vault.secret.invalid` |
//! | `GET /secrets/{id}` | 200 [`OperatorSecretView`] with `ETag` | 403, 404 `vault.secret.not_found` |
//! | `PATCH /secrets/{id}` | 200 [`OperatorSecretView`] with `ETag` | 403, 404, 409 `vault.secret.conflict` (`If-Match`), 422 |
//! | `DELETE /secrets/{id}` | 204 | 403, 404, 409 `vault.secret.in_use`, `vault.secret.conflict` |
//! | `GET /secrets/{id}/references` | 200 [`SecretReferences`] | 403, 404 |
//! | `POST /secrets/{id}/reveal` | 200 [`RevealedSecret`], `Cache-Control: no-store` | 403 (`auth.forbidden`, `auth.step_up_required`, `vault.reveal.host_required`, `vault.reveal.not_bound`), 404, 429 `vault.reveal.rate_limited` |
//! | `GET /hosts/{id}/credentials` | 200 [`HostCredentialsView`] with `ETag` | 403, 404 `ipam.not_found` |
//! | `PUT /hosts/{id}/credentials` | 200 [`HostCredentialsView`] with `ETag` | 403, 404, 409 `vault.host_credentials.conflict`, 422 `vault.secret.invalid`, `vault.host_credentials.secret_missing` |
//!
//! # The service
//!
//! The server adds [`OperatorSecrets`] (and the authentication service) as request
//! extensions. Without them every endpoint answers `501` `sys.not_implemented`, so the bare
//! router of the route table test keeps working. Host credentials also need the IPAM
//! service (`503` `ipam.unavailable` without it).
//!
//! # Authorization
//!
//! Viewers see neither secrets nor credential bindings: the list is empty and everything
//! else is `403`. Operators read the metadata and the bindings ([`Action::Read`] on
//! secrets) and may reveal ([`Action::Reveal`]). Administrators create, change, delete
//! and bind ([`Action::Create`], [`Action::Update`], [`Action::Delete`]); creating also
//! needs [`Action::Reveal`], which is the IAM-07 threshold: a PIN-strength session never
//! stores or reveals a secret.
//!
//! # The PIN coupling rule (IAM-07, CON-07)
//!
//! `POST /secrets` is refused with 409 `vault.pin_coupling` while an enabled account that
//! may reveal secrets signs in with a PIN alone (no TOTP, no passkey): the parameter
//! `accounts` names them, comma-separated. Such an account would lose access the moment
//! the vault holds an operator secret.
//!
//! # Reveal (IAM-16, TGL-24)
//!
//! `POST /secrets/{id}/reveal` returns the value once. It needs [`Action::Reveal`], a
//! session of password strength or stronger, and what the reveal policy TGL-24 asks:
//! `session` (Home, Lab), `fresh` (a sign-in within five minutes, Standard) or `passkey`
//! (a passkey or hardware key sign-in within five minutes, Hardened, which also reveals
//! only secrets bound to the host the request names). A missing step-up is 403
//! `auth.step_up_required` with the parameter `required`: `password` (the PIN rule),
//! `fresh` or `passkey`. Every reveal and every refused reveal is audited
//! (`vault.secret.reveal` with the principal, the secret, the host and the reason, never the
//! value); the value is returned only after the audit record committed. One person may
//! reveal ten times a minute (429 with `Retry-After`). The answer carries
//! `Cache-Control: no-store`, so an `Idempotency-Key` retry gets 409
//! `sys.idempotency_not_replayable` instead of the value.
//!
//! # Writes
//!
//! Edits commit directly with their audit records, not as inline jobs: an inline job keeps
//! its batch in the job record, which would keep a copy of the encrypted value after the
//! secret is deleted. `PATCH` and `DELETE` take `If-Match` with the revision of the
//! metadata, `PUT /hosts/{id}/credentials` the `version` of the host's set.

mod dto;
#[cfg(test)]
pub(crate) mod tests;

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use tenko_auth::AuthService;
use tenko_connect::host::ConnectorHost;
use tenko_core::{
    Action, CodedError, HostId, ObjectKind, ObjectRef, Revision, SecretId, ipam::Host,
};
use tenko_ipam::query;
use tenko_vault::{
    SecretBytes,
    operator::{
        self, BindingRequest, CLIPBOARD_CLEAR_SECS, NewOperatorSecret as ModelNew, OperatorError,
        OperatorSecret, OperatorSecretPatch as ModelPatch, OperatorSecrets,
    },
};
use utoipa_axum::{router::OpenApiRouter, routes};

pub use dto::{
    CredentialRole, HostCredentialBinding, HostCredentialItem, HostCredentialsUpdate,
    HostCredentialsView, LastReveal, NewOperatorSecret, OperatorSecretPatch, OperatorSecretView,
    RevealRequest, RevealedSecret, SecretConnectorReference, SecretFilters, SecretHostRef,
    SecretHostReference, SecretKind, SecretOrigin, SecretReferences,
};

use super::{
    auth::{ApiJson, OptionalJson, RouteError, if_match, secret_json},
    common::{Ipam, IpamPath, may_read_kind},
    not_implemented,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{Filters, PageParams, encode_cursor},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// Names the list endpoint in cursors.
const CURSOR_ENDPOINT: &str = "vault.secrets";

/// The code of the PIN coupling refusal.
pub const PIN_COUPLING: &str = "vault.pin_coupling";

/// The platform routes of the area: `/secrets`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_secrets, create_secret))
        .routes(routes!(get_secret, update_secret, delete_secret))
        .routes(routes!(list_secret_references))
        .routes(routes!(reveal_secret))
}

/// The routes under a host (IPAM module): `/hosts/{id}/credentials`.
pub(crate) fn host_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_host_credentials, update_host_credentials))
}

type Secrets = Option<Extension<Arc<OperatorSecrets>>>;
type Auth = Option<Extension<Arc<AuthService>>>;
type Connectors = Option<Extension<Arc<ConnectorHost>>>;

/// The service, or the `501` stub answer when the server did not add one.
fn secrets_or_stub(
    secrets: Secrets,
    method: &str,
    path: &str,
) -> Result<Arc<OperatorSecrets>, ApiError> {
    secrets
        .map(|Extension(secrets)| secrets)
        .ok_or_else(|| not_implemented(method, path))
}

fn auth_or_stub(auth: Auth, method: &str, path: &str) -> Result<Arc<AuthService>, ApiError> {
    auth.map(|Extension(auth)| auth)
        .ok_or_else(|| not_implemented(method, path))
}

/// The object a create is checked against.
fn any_secret() -> ObjectRef {
    ObjectRef::singleton(ObjectKind::Secret)
}

fn view_response(status: StatusCode, secret: &OperatorSecret) -> Response {
    let view = OperatorSecretView::from(secret);
    let etag = view
        .revision
        .and_then(|revision| HeaderValue::from_str(&format!("\"{}\"", revision.0)).ok());
    let mut response = (status, Json(view)).into_response();
    if let Some(etag) = etag {
        response.headers_mut().insert(header::ETAG, etag);
    }
    response
}

fn credentials_response(credentials: &operator::HostCredentials) -> Response {
    let view = HostCredentialsView::from(credentials);
    let etag = HeaderValue::from_str(&format!("\"{}\"", view.version)).ok();
    let mut response = Json(view).into_response();
    if let Some(etag) = etag {
        response.headers_mut().insert(header::ETAG, etag);
    }
    response
}

/// The value of a request as bytes for the vault.
fn value_bytes(value: &tenko_auth::service::SecretString) -> SecretBytes {
    SecretBytes::from_slice(value.expose().as_bytes())
}

/// Lists the operator secrets by name: metadata only, never a value. Filters: `q` (text
/// over the name, the user name and the tags), `kind`, `tag` and `host` (bound to the
/// host). Empty without permission to read secrets.
#[utoipa::path(
    get,
    path = "/secrets",
    tag = "secrets",
    operation_id = "list_secrets",
    summary = "List operator secrets",
    params(PageParams, SecretFilters),
    responses(
        (status = 200, description = "A page of operator secrets by name; empty without permission to read secrets", body = Page<OperatorSecretView>),
        (status = 400, description = "A parameter is unknown or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_secrets(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    secrets: Secrets,
    filters: Filters,
) -> Result<Json<Page<OperatorSecretView>>, ApiError> {
    let secrets = secrets_or_stub(secrets, "GET", "/secrets")?;
    filters.only(&["q", "kind", "tag", "host"])?;
    let q = filters.get("q")?.map(str::to_lowercase);
    let kind: Option<SecretKind> = filters
        .get("kind")?
        .map(|kind| {
            serde_json::from_value(serde_json::Value::String(kind.to_owned())).map_err(|_| {
                ApiError::invalid_query("kind", "one of password, api_key, ssh_key, token, other")
            })
        })
        .transpose()?;
    let tag = filters.get("tag")?.map(str::to_lowercase);
    let host: Option<HostId> = filters.parse("host")?;
    let page = filters.page()?;
    let limit = page.limit()?;
    let scope = filters.scope(CURSOR_ENDPOINT);
    let after: Option<(String, SecretId)> = page.cursor(scope)?;
    if !may_read_kind(&app, &cx, ObjectKind::Secret) {
        return Ok(Json(Page::new(Vec::new(), None, secrets.revision())));
    }
    let revision = secrets.revision();
    let key = |secret: &OperatorSecret| (secret.record.name.to_lowercase(), secret.record.id);
    let mut items: Vec<OperatorSecret> = secrets
        .list()
        .await
        .map_err(ApiError::from)?
        .into_iter()
        .filter(|secret| {
            let record = &secret.record;
            kind.is_none_or(|kind| SecretKind::from(record.kind) == kind)
                && tag.as_ref().is_none_or(|tag| record.tags.contains(tag))
                && host.is_none_or(|host| secret.hosts.iter().any(|(bound, _)| *bound == host))
                && q.as_ref().is_none_or(|q| {
                    record.name.to_lowercase().contains(q)
                        || record
                            .username
                            .as_ref()
                            .is_some_and(|username| username.to_lowercase().contains(q))
                        || record.tags.iter().any(|tag| tag.contains(q))
                })
        })
        .filter(|secret| after.as_ref().is_none_or(|after| key(secret) > *after))
        .collect();
    let next = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|last| encode_cursor(scope, &key(last)))
    } else {
        None
    };
    Ok(Json(Page::new(
        items.iter().map(OperatorSecretView::from).collect(),
        next,
        revision,
    )))
}

/// Creates an operator secret: the value is encrypted under its own data key, the
/// metadata stored next to it, in one write audited as `vault.secret.create` (with the
/// name and the kind, never the value). Refused while an account that may reveal secrets
/// signs in with a PIN alone (IAM-07).
#[utoipa::path(
    post,
    path = "/secrets",
    tag = "secrets",
    operation_id = "create_secret",
    summary = "Create an operator secret",
    params(("Idempotency-Key" = Option<String>, Header, description = "Makes a retried request safe; a replay answers the first response")),
    request_body = NewOperatorSecret,
    responses(
        (status = 201, description = "The new secret (metadata only), with `ETag`", body = OperatorSecretView,
            headers(("ETag" = String, description = "The revision of the metadata"))),
        (status = 400, description = "The body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed, or the session is weaker than a password (`auth.forbidden`, `auth.step_up_required` with `required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "An account that may reveal secrets signs in with a PIN alone (`vault.pin_coupling`, parameter `accounts`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "The value exceeds 64 KiB (`vault.secret.too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "A value is invalid (`vault.secret.invalid`, parameter `field`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_secret(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    secrets: Secrets,
    auth: Auth,
    ApiJson(new): ApiJson<NewOperatorSecret>,
) -> Result<Response, RouteError> {
    let secrets = secrets_or_stub(secrets, "POST", "/secrets")?;
    app.authorize(&cx.principal, Action::Create, &any_secret())?;
    app.authorize(&cx.principal, Action::Reveal, &any_secret())?;
    if let Some(Extension(auth)) = auth {
        let accounts = auth.pin_only_revealers().await?;
        if !accounts.is_empty() {
            return Err(RouteError::from(ApiError::from_coded_error(
                CodedError::new(
                    PIN_COUPLING,
                    409,
                    format!(
                        "the vault takes operator secrets only when every account that may reveal them has more than a PIN (IAM-07): {} sign in with a PIN alone; add a passkey or TOTP to them, give them a password, or change their roles",
                        accounts.join(", ")
                    ),
                )
                .with_title("PIN coupling rule")
                .with_param("accounts", accounts.join(",")),
            )));
        }
    }
    let created = secrets
        .create(
            &cx,
            ModelNew {
                name: new.name,
                kind: new.kind.into(),
                tags: new.tags,
                username: new.username,
                notes: new.notes,
                value: value_bytes(&new.value),
            },
        )
        .await;
    Ok(view_response(StatusCode::CREATED, &created?))
}

/// Shows one operator secret: metadata, the hosts it is bound to and its last reveal.
#[utoipa::path(
    get,
    path = "/secrets/{id}",
    tag = "secrets",
    operation_id = "get_secret",
    summary = "Get an operator secret",
    params(("id" = String, Path, description = "Secret identifier")),
    responses(
        (status = 200, description = "The secret (metadata only), with `ETag`", body = OperatorSecretView,
            headers(("ETag" = String, description = "The revision of the metadata"))),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such operator secret (`vault.secret.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_secret(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    secrets: Secrets,
    IpamPath(id): IpamPath<SecretId>,
) -> Result<Response, RouteError> {
    let secrets = secrets_or_stub(secrets, "GET", "/secrets/{id}")?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    {
        let secret = secrets.get(id).await?;
        Ok(view_response(StatusCode::OK, &secret))
    }
}

/// Changes the metadata of an operator secret and, with `value`, replaces its value under a
/// fresh data key, in one write (`vault.secret.update` with the changed fields, the notes
/// only as changed; `vault.secret.replace` for the value).
#[utoipa::path(
    patch,
    path = "/secrets/{id}",
    tag = "secrets",
    operation_id = "update_secret",
    summary = "Update an operator secret",
    params(
        ("id" = String, Path, description = "Secret identifier"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read, as in the `ETag`; a stale revision is refused with 409")
    ),
    request_body = OperatorSecretPatch,
    responses(
        (status = 200, description = "The secret after the change, with `ETag`", body = OperatorSecretView,
            headers(("ETag" = String, description = "The new revision of the metadata"))),
        (status = 400, description = "The body or `If-Match` is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`, `auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such operator secret (`vault.secret.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "`If-Match` is stale or the secret changed meanwhile (`vault.secret.conflict`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "The value exceeds 64 KiB (`vault.secret.too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "A value is invalid (`vault.secret.invalid`, parameter `field`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_secret(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    secrets: Secrets,
    IpamPath(id): IpamPath<SecretId>,
    headers: HeaderMap,
    ApiJson(patch): ApiJson<OperatorSecretPatch>,
) -> Result<Response, RouteError> {
    let secrets = secrets_or_stub(secrets, "PATCH", "/secrets/{id}")?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let expect = if_match(&headers)?;
    let model = ModelPatch {
        name: patch.name,
        kind: patch.kind.map(Into::into),
        tags: patch.tags,
        username: patch.username,
        notes: patch.notes,
        value: patch.value.as_ref().map(value_bytes),
    };
    {
        let secret = secrets.update(&cx, id, model, expect).await?;
        Ok(view_response(StatusCode::OK, &secret))
    }
}

/// The connector instances that reference a secret, by name.
async fn connector_references(
    connectors: Option<&Arc<ConnectorHost>>,
    id: SecretId,
) -> Result<Vec<SecretConnectorReference>, ApiError> {
    let Some(connectors) = connectors else {
        return Ok(Vec::new());
    };
    let views = connectors
        .list(None)
        .await
        .map_err(|error| ApiError::from_coded_error(error.into_coded()))?;
    let mut out: Vec<SecretConnectorReference> = views
        .into_iter()
        .flat_map(|view| {
            let instance = view.instance;
            instance
                .secrets
                .iter()
                .filter(|(_, reference)| reference.secret == id)
                .map(|(purpose, _)| SecretConnectorReference {
                    connector: instance.id,
                    name: instance.name.clone(),
                    plugin: instance.plugin.clone(),
                    purpose: purpose.clone(),
                })
                .collect::<Vec<_>>()
        })
        .collect();
    out.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then(a.purpose.cmp(&b.purpose))
    });
    Ok(out)
}

/// Deletes an operator secret: its encrypted value, its metadata and its last-revealed
/// stamp, audited as `vault.secret.delete`. Refused while a host binds it or a connector
/// instance uses it (409 `vault.secret.in_use`; `GET /secrets/{id}/references` lists them).
#[utoipa::path(
    delete,
    path = "/secrets/{id}",
    tag = "secrets",
    operation_id = "delete_secret",
    summary = "Delete an operator secret",
    params(
        ("id" = String, Path, description = "Secret identifier"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read, as in the `ETag`; a stale revision is refused with 409")
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 400, description = "The identifier or `If-Match` is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`, `auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such operator secret (`vault.secret.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Still referenced (`vault.secret.in_use`, parameters `hosts` and `connectors` with the counts), or `If-Match` is stale (`vault.secret.conflict`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_secret(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    secrets: Secrets,
    connectors: Connectors,
    IpamPath(id): IpamPath<SecretId>,
    headers: HeaderMap,
) -> Result<Response, RouteError> {
    let secrets = secrets_or_stub(secrets, "DELETE", "/secrets/{id}")?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    let expect = if_match(&headers)?;
    let current = secrets.get(id).await?;
    let users = connector_references(connectors.as_ref().map(|Extension(c)| c), id).await?;
    if !users.is_empty() || !current.hosts.is_empty() {
        return Err(RouteError::from(OperatorError::InUse {
            hosts: current.hosts.iter().map(|(host, _)| *host).collect(),
            connectors: users.into_iter().map(|c| c.connector.to_string()).collect(),
        }));
    }
    secrets.delete(&cx, id, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Lists what references an operator secret: the hosts that bind it (with their names
/// when IPAM knows them) and the connector instances that use it, with the purpose.
#[utoipa::path(
    get,
    path = "/secrets/{id}/references",
    tag = "secrets",
    operation_id = "list_secret_references",
    summary = "List the references of an operator secret",
    params(("id" = String, Path, description = "Secret identifier")),
    responses(
        (status = 200, description = "The hosts and connector instances that reference the secret", body = SecretReferences),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such operator secret (`vault.secret.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_secret_references(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    secrets: Secrets,
    connectors: Connectors,
    ipam: Option<Extension<Arc<tenko_ipam::IpamService>>>,
    IpamPath(id): IpamPath<SecretId>,
) -> Result<Response, RouteError> {
    let secrets = secrets_or_stub(secrets, "GET", "/secrets/{id}/references")?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let secret = secrets.get(id).await?;
    let view = match &ipam {
        Some(Extension(ipam)) => Some(ipam.view(None).await.map_err(ApiError::from)?),
        None => None,
    };
    let mut hosts = Vec::new();
    for (host, role) in &secret.hosts {
        let found = match &view {
            Some(view) => query::get::<Host>(view.as_ref(), *host).ok(),
            None => None,
        };
        hosts.push(SecretHostReference {
            host: *host,
            name: found.as_ref().map(|host| host.name.to_string()),
            role: (*role).into(),
            deleted: found
                .as_ref()
                .is_some_and(|host| host.meta.deleted.is_some()),
        });
    }
    hosts.sort_by(|a, b| a.name.cmp(&b.name).then(a.host.cmp(&b.host)));
    let connectors = connector_references(connectors.as_ref().map(|Extension(c)| c), id).await?;
    Ok(Json(SecretReferences {
        id,
        hosts,
        connectors,
    })
    .into_response())
}

/// Reveals the value of an operator secret once, for the clipboard of the person who asks.
/// Needs permission to reveal, a session of password strength or stronger, and what the
/// reveal policy TGL-24 asks (a recent sign-in, a passkey, the host in view). The reveal is
/// audited before the value is returned; the answer is never stored.
#[utoipa::path(
    post,
    path = "/secrets/{id}/reveal",
    tag = "secrets",
    operation_id = "reveal_secret",
    summary = "Reveal an operator secret",
    params(("id" = String, Path, description = "Secret identifier")),
    request_body(content = RevealRequest, description = "The host in view and the reason; the body may be empty"),
    responses(
        (status = 200, description = "The value, sent once with `Cache-Control: no-store`", body = RevealedSecret),
        (status = 400, description = "The body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`, also for personal tokens), a step-up is needed (`auth.step_up_required`, parameter `required`: `password`, `fresh` or `passkey`), the policy reveals only secrets bound to the host in view (`vault.reveal.host_required`), or the secret is not bound to the host named (`vault.reveal.not_bound`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such operator secret (`vault.secret.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The reason is invalid (`vault.secret.invalid`) or the stored value is not text (`vault.secret.not_text`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "Too many reveals (`vault.reveal.rate_limited`), with `Retry-After`", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn reveal_secret(
    Ctx(cx): Ctx,
    secrets: Secrets,
    auth: Auth,
    IpamPath(id): IpamPath<SecretId>,
    OptionalJson(request): OptionalJson<RevealRequest>,
) -> Result<Response, RouteError> {
    let secrets = secrets_or_stub(secrets, "POST", "/secrets/{id}/reveal")?;
    let auth = auth_or_stub(auth, "POST", "/secrets/{id}/reveal")?;
    let grant = match auth.authorize_reveal(&cx, id).await {
        Ok(grant) => grant,
        Err(error) => {
            secrets
                .audit_refused_reveal(&cx, id, request.host, request.reason.as_deref(), &error)
                .await;
            return Err(error.into());
        }
    };
    let revealed = secrets
        .reveal(
            &cx,
            id,
            operator::RevealRequest {
                host: request.host,
                reason: request.reason,
                bound_host_only: grant.policy.bound_host_only,
                user: Some(grant.user),
                user_name: Some(grant.user_name),
            },
        )
        .await;
    let revealed = revealed?;
    let body = RevealedSecret {
        id,
        value: tenko_auth::service::SecretString::new(revealed.value.as_str()),
        username: revealed.username.clone(),
        kind: revealed.kind.into(),
        revealed_at: revealed.at,
        clear_after_secs: CLIPBOARD_CLEAR_SECS,
    };
    drop(revealed);
    secret_json(StatusCode::OK, None, &body)
}

/// The host, for the host routes: 404 `ipam.not_found` when IPAM does not know it.
async fn known_host(ipam: &tenko_ipam::IpamService, id: HostId) -> Result<Host, ApiError> {
    let view = ipam.view(None).await.map_err(ApiError::from)?;
    query::get::<Host>(view.as_ref(), id).map_err(ApiError::from)
}

/// Lists the credentials bound to a host, by role and name: metadata only. Operators and
/// administrators; viewers get 403.
#[utoipa::path(
    get,
    path = "/hosts/{id}/credentials",
    tag = "secrets",
    operation_id = "get_host_credentials",
    summary = "List the credentials of a host",
    params(("id" = String, Path, description = "Host identifier")),
    responses(
        (status = 200, description = "The credentials of the host, with `ETag` (the version of the set)", body = HostCredentialsView,
            headers(("ETag" = String, description = "The version of the set, for `If-Match`"))),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such host (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_host_credentials(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    secrets: Secrets,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<HostId>,
) -> Result<Response, RouteError> {
    let secrets = secrets_or_stub(secrets, "GET", "/hosts/{id}/credentials")?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    app.authorize(&cx.principal, Action::Read, &any_secret())?;
    known_host(&ipam, id).await?;
    {
        let credentials = secrets.host_credentials(id).await?;
        Ok(credentials_response(&credentials))
    }
}

/// Replaces the credentials bound to a host: every binding not listed is removed, one
/// role per secret. Audited as `vault.host.credentials` with what was bound and unbound.
/// Administrators only.
#[utoipa::path(
    put,
    path = "/hosts/{id}/credentials",
    tag = "secrets",
    operation_id = "update_host_credentials",
    summary = "Bind and unbind the credentials of a host",
    params(
        ("id" = String, Path, description = "Host identifier"),
        ("If-Match" = Option<String>, Header, description = "The version of the set the client read, as in the `ETag`; a stale version is refused with 409")
    ),
    request_body = HostCredentialsUpdate,
    responses(
        (status = 200, description = "The credentials of the host after the change, with `ETag`", body = HostCredentialsView,
            headers(("ETag" = String, description = "The new version of the set"))),
        (status = 400, description = "The body or `If-Match` is malformed (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`, `auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such host (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "`If-Match` is stale or the set changed meanwhile (`vault.host_credentials.conflict`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Too many bindings or a secret twice (`vault.secret.invalid`), or a secret that is not an operator secret (`vault.host_credentials.secret_missing`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_host_credentials(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    secrets: Secrets,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<HostId>,
    headers: HeaderMap,
    ApiJson(update): ApiJson<HostCredentialsUpdate>,
) -> Result<Response, RouteError> {
    let secrets = secrets_or_stub(secrets, "PUT", "/hosts/{id}/credentials")?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    app.authorize(&cx.principal, Action::Update, &any_secret())?;
    let expect = if_match(&headers)?.map(|Revision(version)| version);
    known_host(&ipam, id).await?;
    let wanted: Vec<BindingRequest> = update
        .credentials
        .iter()
        .map(|binding| BindingRequest {
            secret: binding.secret,
            role: binding.role.into(),
        })
        .collect();
    let credentials = secrets
        .set_host_credentials(&cx, id, &wanted, expect)
        .await?;
    Ok(credentials_response(&credentials))
}

/// The user name the remote hand-off of a host offers for `role` (API-11): the bound
/// credential of that role, else the `admin` one. `None` when the principal may not read
/// secrets or nothing is bound.
pub(crate) async fn handoff_username(
    app: &AppState,
    cx: &tenko_core::RequestCtx,
    secrets: Option<&Arc<OperatorSecrets>>,
    host: HostId,
    role: operator::CredentialRole,
) -> Result<Option<String>, ApiError> {
    let Some(secrets) = secrets else {
        return Ok(None);
    };
    if !may_read_kind(app, cx, ObjectKind::Secret) {
        return Ok(None);
    }
    let credentials = secrets
        .host_credentials(host)
        .await
        .map_err(ApiError::from)?;
    let pick = |wanted: operator::CredentialRole| {
        credentials
            .items
            .iter()
            .filter(|item| item.role == wanted)
            .find_map(|item| item.secret.record.username.clone())
    };
    Ok(pick(role).or_else(|| pick(operator::CredentialRole::Admin)))
}
