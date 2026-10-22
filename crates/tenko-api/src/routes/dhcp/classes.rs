//! `GET|POST /dhcp/classes`, `GET|PATCH|DELETE /dhcp/classes/{id}`, the same for
//! `/dhcp/policies` and `/dhcp/filters`: classes, policies and MAC filters as rows. Their
//! matching against requests is WP8.4's.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, ObjectKind, ObjectRef,
    dhcp::{ClassId, FilterId, PolicyId, scope_object},
};
use tenko_dhcp::config::{
    ConfigService,
    classes::{
        ClassChange, ClassRow, FilterChange, FilterRow, NewPolicy, PolicyChange, PolicyFilter,
        PolicyRow,
    },
};

use super::{
    Configs, DhcpClassCreate, DhcpClassItem, DhcpClassPatch, DhcpFilterCreate, DhcpFilterItem,
    DhcpFilterPatch, DhcpPolicyCreate, DhcpPolicyFilter, DhcpPolicyItem, DhcpPolicyPatch, page_of,
    parse_id, with_etag,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams},
    problem::{ApiError, ProblemDetails},
    routes::auth::{ApiJson, if_match},
    state::AppState,
};

fn class_item(row: ClassRow) -> DhcpClassItem {
    DhcpClassItem {
        used_by: u32::try_from(row.used_by.len()).unwrap_or(u32::MAX),
        class: row.class,
        revision: row.revision,
    }
}

fn policy_item(row: PolicyRow) -> DhcpPolicyItem {
    DhcpPolicyItem {
        policy: row.policy,
        revision: row.revision,
    }
}

fn filter_item(row: FilterRow) -> DhcpFilterItem {
    DhcpFilterItem {
        filter: row.filter,
        revision: row.revision,
    }
}

// ----- classes --------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/dhcp/classes",
    tag = "dhcp",
    operation_id = "list_dhcp_classes",
    summary = "List DHCP classes",
    description = "Scope: `dhcp.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of classes by name", body = Page<DhcpClassItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dhcp_classes(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpClass),
    )?;
    let service = configs.get()?;
    let view = page.read(service.store().as_ref()).await?;
    let items: Vec<DhcpClassItem> = ConfigService::classes(view.as_ref())?
        .into_iter()
        .map(class_item)
        .collect();
    let page = page_of(
        items,
        |item| (item.class.name.clone(), item.class.id),
        &page,
        CursorScope::new("dhcp.classes"),
        view.revision(),
    )?;
    Ok(Json(page).into_response())
}

#[utoipa::path(
    post,
    path = "/dhcp/classes",
    tag = "dhcp",
    operation_id = "create_dhcp_class",
    summary = "Create a DHCP class",
    description = "Scope: `dhcp.write`. A class holds when any of its matches holds.",
    request_body(content = DhcpClassCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The class", body = DhcpClassItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the class is invalid or its name taken (`dhcp.class.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dhcp_class(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    ApiJson(body): ApiJson<DhcpClassCreate>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DhcpClass),
    )?;
    let service = configs.get()?;
    let (class, written) = service
        .create_class(&cx, body.name, body.matches, body.description)
        .await?;
    let view = service.view(Some(written.revision)).await?;
    let row = ConfigService::class(view.as_ref(), class.id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::CREATED, &class_item(row), revision))
}

#[utoipa::path(
    get,
    path = "/dhcp/classes/{id}",
    tag = "dhcp",
    operation_id = "get_dhcp_class",
    summary = "Get a DHCP class",
    description = "Scope: `dhcp.read`.",
    params(("id" = String, Path, description = "Class identifier (UUID)")),
    responses(
        (status = 200, description = "The class, with its `ETag`", body = DhcpClassItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dhcp_class(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ClassId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = configs.get()?;
    let view = service.view(None).await?;
    let row = ConfigService::class(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &class_item(row), revision))
}

#[utoipa::path(
    patch,
    path = "/dhcp/classes/{id}",
    tag = "dhcp",
    operation_id = "update_dhcp_class",
    summary = "Change a DHCP class",
    description = "Scope: `dhcp.write`.",
    params(
        ("id" = String, Path, description = "Class identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    request_body(content = DhcpClassPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed class", body = DhcpClassItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the class is invalid or its name taken (`dhcp.class.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The class changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_dhcp_class(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<DhcpClassPatch>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ClassId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    let (_, written) = service
        .update_class(
            &cx,
            id,
            ClassChange {
                name: body.name,
                matches: body.matches,
                description: body.description,
            },
            expect,
        )
        .await?;
    let view = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ConfigService::class(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &class_item(row), revision))
}

#[utoipa::path(
    delete,
    path = "/dhcp/classes/{id}",
    tag = "dhcp",
    operation_id = "delete_dhcp_class",
    summary = "Delete a DHCP class",
    description = "Scope: `dhcp.write`. A class a scope, pool or policy names stays (`dhcp.class.in_use`, parameter `by`).",
    params(
        ("id" = String, Path, description = "Class identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The class is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A scope, pool or policy names the class (`dhcp.class.in_use`), or the DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The class changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dhcp_class(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_id::<ClassId>("id", &id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    service.delete_class(&cx, id, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ----- policies -------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/dhcp/policies",
    tag = "dhcp",
    operation_id = "list_dhcp_policies",
    summary = "List DHCP policies",
    description = "Scope: `dhcp.read`. The policies of each scope in order, then the server's.",
    params(PageParams, DhcpPolicyFilter),
    responses(
        (status = 200, description = "A page of policies in evaluation order", body = Page<DhcpPolicyItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dhcp_policies(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Query(page): Query<PageParams>,
    Query(filter): Query<DhcpPolicyFilter>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpPolicy),
    )?;
    let service = configs.get()?;
    let view = page.read(service.store().as_ref()).await?;
    let items: Vec<DhcpPolicyItem> = ConfigService::policies(
        view.as_ref(),
        PolicyFilter {
            scope: filter.scope,
            server: filter.server.unwrap_or(false),
        },
    )?
    .into_iter()
    .map(policy_item)
    .collect();
    let mut scope = CursorScope::new("dhcp.policies");
    if let Some(prefix) = filter.scope {
        scope = scope.with(&prefix.to_string());
    }
    if filter.server == Some(true) {
        scope = scope.with("server");
    }
    let page = page_of(
        items,
        |item| {
            (
                item.policy.scope.is_none(),
                item.policy.scope,
                item.policy.order,
                item.policy.id,
            )
        },
        &page,
        scope,
        view.revision(),
    )?;
    Ok(Json(page).into_response())
}

#[utoipa::path(
    post,
    path = "/dhcp/policies",
    tag = "dhcp",
    operation_id = "create_dhcp_policy",
    summary = "Create a DHCP policy",
    description = "Scope: `dhcp.write`, and `dhcp.write` on the scope of a scope policy. Without an order the policy goes after the last of its scope.",
    request_body(content = DhcpPolicyCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The policy", body = DhcpPolicyItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), the policy is invalid or its name taken in the scope (`dhcp.policy.invalid`), its range lies outside the scope (`dhcp.pool.outside`), or its lease times or DDNS settings are invalid (`dhcp.lease_times.invalid`, `dhcp.ddns.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such scope (`dhcp.scope.not_found`) or class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dhcp_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    ApiJson(body): ApiJson<DhcpPolicyCreate>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DhcpPolicy),
    )?;
    if let Some(prefix) = body.scope {
        app.authorize(&cx.principal, Action::Update, &scope_object(prefix))?;
    }
    let service = configs.get()?;
    let (policy, written) = service
        .create_policy(
            &cx,
            NewPolicy {
                name: body.name,
                scope: body.scope,
                order: body.order,
                enabled: body.enabled,
                condition: body.condition,
                action: body.action,
                description: body.description,
            },
        )
        .await?;
    let view = service.view(Some(written.revision)).await?;
    let row = ConfigService::policy(view.as_ref(), policy.id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::CREATED, &policy_item(row), revision))
}

#[utoipa::path(
    get,
    path = "/dhcp/policies/{id}",
    tag = "dhcp",
    operation_id = "get_dhcp_policy",
    summary = "Get a DHCP policy",
    description = "Scope: `dhcp.read`.",
    params(("id" = String, Path, description = "Policy identifier (UUID)")),
    responses(
        (status = 200, description = "The policy, with its `ETag`", body = DhcpPolicyItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such policy (`dhcp.policy.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dhcp_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<PolicyId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = configs.get()?;
    let view = service.view(None).await?;
    let row = ConfigService::policy(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &policy_item(row), revision))
}

#[utoipa::path(
    patch,
    path = "/dhcp/policies/{id}",
    tag = "dhcp",
    operation_id = "update_dhcp_policy",
    summary = "Change a DHCP policy",
    description = "Scope: `dhcp.write`. The scope of a policy does not change.",
    params(
        ("id" = String, Path, description = "Policy identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    request_body(content = DhcpPolicyPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed policy", body = DhcpPolicyItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), the policy is invalid (`dhcp.policy.invalid`), or its range lies outside the scope (`dhcp.pool.outside`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such policy (`dhcp.policy.not_found`) or class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The policy changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_dhcp_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<DhcpPolicyPatch>,
) -> Result<Response, ApiError> {
    let id = parse_id::<PolicyId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    let (_, written) = service
        .update_policy(
            &cx,
            id,
            PolicyChange {
                name: body.name,
                order: body.order,
                enabled: body.enabled,
                condition: body.condition,
                action: body.action,
                description: body.description,
            },
            expect,
        )
        .await?;
    let view = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ConfigService::policy(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &policy_item(row), revision))
}

#[utoipa::path(
    delete,
    path = "/dhcp/policies/{id}",
    tag = "dhcp",
    operation_id = "delete_dhcp_policy",
    summary = "Delete a DHCP policy",
    description = "Scope: `dhcp.write`. The policy's options go with it.",
    params(
        ("id" = String, Path, description = "Policy identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The policy is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such policy (`dhcp.policy.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The policy changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dhcp_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_id::<PolicyId>("id", &id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    service.delete_policy(&cx, id, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ----- filters --------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/dhcp/filters",
    tag = "dhcp",
    operation_id = "list_dhcp_filters",
    summary = "List DHCP MAC filters",
    description = "Scope: `dhcp.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of filter entries by pattern", body = Page<DhcpFilterItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dhcp_filters(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpFilter),
    )?;
    let service = configs.get()?;
    let view = page.read(service.store().as_ref()).await?;
    let items: Vec<DhcpFilterItem> = ConfigService::filters(view.as_ref())?
        .into_iter()
        .map(filter_item)
        .collect();
    let page = page_of(
        items,
        |item| (item.filter.mac.to_string(), item.filter.id),
        &page,
        CursorScope::new("dhcp.filters"),
        view.revision(),
    )?;
    Ok(Json(page).into_response())
}

#[utoipa::path(
    post,
    path = "/dhcp/filters",
    tag = "dhcp",
    operation_id = "create_dhcp_filter",
    summary = "Add a DHCP MAC filter",
    description = "Scope: `dhcp.write`. A deny entry drops the client on every scope; on a restricted scope only clients an allow entry matches are served.",
    request_body(content = DhcpFilterCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The filter entry", body = DhcpFilterItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the entry is invalid (`dhcp.filter.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "An entry for the pattern exists (`dhcp.filter.exists`), or the DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dhcp_filter(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    ApiJson(body): ApiJson<DhcpFilterCreate>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DhcpFilter),
    )?;
    let service = configs.get()?;
    let (filter, written) = service
        .create_filter(&cx, body.mac, body.kind, body.note)
        .await?;
    let view = service.view(Some(written.revision)).await?;
    let row = ConfigService::filter(view.as_ref(), filter.id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::CREATED, &filter_item(row), revision))
}

#[utoipa::path(
    get,
    path = "/dhcp/filters/{id}",
    tag = "dhcp",
    operation_id = "get_dhcp_filter",
    summary = "Get a DHCP MAC filter",
    description = "Scope: `dhcp.read`.",
    params(("id" = String, Path, description = "Filter entry identifier (UUID)")),
    responses(
        (status = 200, description = "The filter entry, with its `ETag`", body = DhcpFilterItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such filter entry (`dhcp.filter.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dhcp_filter(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<FilterId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = configs.get()?;
    let view = service.view(None).await?;
    let row = ConfigService::filter(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &filter_item(row), revision))
}

#[utoipa::path(
    patch,
    path = "/dhcp/filters/{id}",
    tag = "dhcp",
    operation_id = "update_dhcp_filter",
    summary = "Change a DHCP MAC filter",
    description = "Scope: `dhcp.write`.",
    params(
        ("id" = String, Path, description = "Filter entry identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    request_body(content = DhcpFilterPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed filter entry", body = DhcpFilterItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the entry is invalid (`dhcp.filter.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such filter entry (`dhcp.filter.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "An entry for the pattern exists (`dhcp.filter.exists`), or the DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The entry changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_dhcp_filter(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<DhcpFilterPatch>,
) -> Result<Response, ApiError> {
    let id = parse_id::<FilterId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    let (_, written) = service
        .update_filter(
            &cx,
            id,
            FilterChange {
                mac: body.mac,
                kind: body.kind,
                note: body.note,
            },
            expect,
        )
        .await?;
    let view = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ConfigService::filter(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &filter_item(row), revision))
}

#[utoipa::path(
    delete,
    path = "/dhcp/filters/{id}",
    tag = "dhcp",
    operation_id = "delete_dhcp_filter",
    summary = "Delete a DHCP MAC filter",
    description = "Scope: `dhcp.write`.",
    params(
        ("id" = String, Path, description = "Filter entry identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The filter entry is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such filter entry (`dhcp.filter.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The entry changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dhcp_filter(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_id::<FilterId>("id", &id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    service.delete_filter(&cx, id, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
