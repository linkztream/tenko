//! `GET|POST /dns/keys`, `GET|DELETE /dns/keys/{key}`: TSIG keys. The secret is in the
//! vault and appears once, in the answer of the create; every action needs `dns.keys`,
//! and a change needs an interactive session (the authorizer refuses a token).

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, ObjectKind,
    dns::{DnsName, KeyMeta},
};
use tenko_dns::zone::{ZoneService, keys::NewKey};

use super::{KeyCreate, KeyCreated, KeyItem, Zones, parse_key};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams, encode_cursor},
    problem::{ApiError, ProblemDetails},
    routes::auth::ApiJson,
    state::AppState,
};

fn item(key: KeyMeta) -> KeyItem {
    KeyItem {
        id: key.id,
        name: key.name,
        algorithm: key.algorithm,
        description: key.description,
        created: key.created,
    }
}

#[utoipa::path(
    get,
    path = "/dns/keys",
    tag = "dns",
    operation_id = "list_dns_keys",
    summary = "List TSIG keys",
    description = "Scope: `dns.keys`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of keys by name, without secrets", body = Page<KeyItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dns_keys(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::DnsKey))?;
    let service = zones.get()?;
    let limit = page.limit()?;
    let scope = CursorScope::new("dns.keys");
    let after: Option<String> = page.cursor(scope)?;
    let view = page.read(service.store().as_ref()).await?;
    let mut items = Vec::new();
    let mut next = None;
    for (key, _) in ZoneService::keys(view.as_ref())? {
        if after
            .as_deref()
            .is_some_and(|after| key.name.as_str() <= after)
        {
            continue;
        }
        if items.len() == limit {
            next = items
                .last()
                .map(|item: &KeyItem| encode_cursor(scope, &item.name.as_str().to_owned()));
            break;
        }
        items.push(item(key));
    }
    Ok(Json(Page::new(items, next, view.revision())).into_response())
}

#[utoipa::path(
    post,
    path = "/dns/keys",
    tag = "dns",
    operation_id = "create_dns_key",
    summary = "Generate or import a TSIG key",
    description = "Scope: `dns.keys`, in an interactive session. Without `secret` a secret of the algorithm's hash length is generated; with it, the base64 secret (16 to 1,024 octets) is imported. The secret is stored in the vault and shown in this answer only.",
    request_body(content = KeyCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The key and its secret, shown this once", body = KeyCreated),
        (status = 400, description = "The request is malformed, or the name or the secret is invalid (`sys.invalid_request`, `sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to change keys", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A key of this name exists (`dns.key.exists`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dns_key(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    ApiJson(body): ApiJson<KeyCreate>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::DnsKey))?;
    let service = zones.get()?;
    let created = service
        .create_key(
            &cx,
            NewKey {
                name: body.name,
                algorithm: body.algorithm.unwrap_or_default(),
                secret: body.secret,
                description: body.description,
            },
        )
        .await?;
    let answer = KeyCreated {
        key: item(created.key.clone()),
        secret: created.secret.as_str().to_owned(),
    };
    Ok((StatusCode::CREATED, Json(answer)).into_response())
}

#[utoipa::path(
    get,
    path = "/dns/keys/{key}",
    tag = "dns",
    operation_id = "get_dns_key",
    summary = "Get a TSIG key",
    description = "Scope: `dns.keys`.",
    params(("key" = String, Path, description = "TSIG key name")),
    responses(
        (status = 200, description = "The key without its secret", body = KeyItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such key (`dns.key.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dns_key(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    let name: DnsName = parse_key(&key)?;
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::DnsKey))?;
    let service = zones.get()?;
    let view = service.view(None).await?;
    let (key, _) = ZoneService::key(view.as_ref(), &name)?;
    Ok(Json(item(key)).into_response())
}

#[utoipa::path(
    delete,
    path = "/dns/keys/{key}",
    tag = "dns",
    operation_id = "delete_dns_key",
    summary = "Delete a TSIG key",
    description = "Scope: `dns.keys`, in an interactive session. The key and its secret in the vault go; an access list or zone that names the key matches nothing for it afterwards.",
    params(("key" = String, Path, description = "TSIG key name")),
    responses(
        (status = 204, description = "The key and its secret are gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to change keys", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such key (`dns.key.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dns_key(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    let name = parse_key(&key)?;
    app.authorize(&cx.principal, Action::Delete, &anywhere(ObjectKind::DnsKey))?;
    let service = zones.get()?;
    service.delete_key(&cx, &name).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
