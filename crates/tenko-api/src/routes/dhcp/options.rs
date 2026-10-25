//! `GET /dhcp/option-catalog`, `GET|POST /dhcp/option-defs`,
//! `GET|PATCH|DELETE /dhcp/option-defs/{id}`, `GET /dhcp/option-sets`,
//! `GET|PUT|DELETE /dhcp/option-sets/{owner}`: the catalog, custom definitions and the
//! option sets of the levels.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, ObjectKind, ObjectRef, Principal,
    dhcp::{
        CATALOG_V6, OptionDef, OptionDefId, OptionKind, OptionOwner, OptionSet, OptionSpace,
        SERVER_MANAGED_V6, catalog_v6,
    },
};
use tenko_dhcp::config::{
    ConfigService,
    options::{
        NewOptionDef, OptionDefChange, OptionDefRow, OptionInput, OptionSetRow, catalog, describe,
    },
};
use tenko_store::ReadView;

use super::{
    Configs, OptionCatalogItem, OptionCatalogParams, OptionDefCreate, OptionDefItem,
    OptionDefPatch, OptionSetFilter, OptionSetItem, OptionSetPut, OptionValueItem, owner_object,
    page_of, parse_id, parse_owner, with_etag,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams},
    problem::{ApiError, ProblemDetails},
    routes::auth::{ApiJson, if_match},
    state::AppState,
};

fn def_item(row: OptionDefRow) -> OptionDefItem {
    OptionDefItem {
        def: row.def,
        used_by: row.used_by,
        revision: row.revision,
    }
}

fn set_item(row: OptionSetRow, defs: &[OptionDef]) -> OptionSetItem {
    let OptionSet {
        owner,
        values,
        updated,
    } = row.set;
    OptionSetItem {
        owner,
        path: owner.to_path(),
        level: owner.level(),
        values: values
            .into_iter()
            .map(|value| {
                let (name, typed) = describe(&value, defs);
                // WP9.4: the DHCPv6 catalog names its codes.
                let name = name.or_else(|| name6(&value.space, value.code));
                OptionValueItem { value, name, typed }
            })
            .collect(),
        updated,
        revision: row.revision,
    }
}

// WP9.4: the DHCPv6 catalog and the codes a DHCPv6 server writes itself, with Kea's names.
/// The names and types of [`SERVER_MANAGED_V6`], as Kea names them.
const MANAGED_V6: [(u16, &str, OptionKind, bool); 21] = [
    (1, "clientid", OptionKind::Binary, false),
    (2, "serverid", OptionKind::Binary, false),
    (3, "ia-na", OptionKind::Binary, false),
    (4, "ia-ta", OptionKind::Binary, false),
    (5, "iaaddr", OptionKind::Binary, false),
    (6, "oro", OptionKind::U16, true),
    (7, "preference", OptionKind::U8, false),
    (8, "elapsed-time", OptionKind::U16, false),
    (9, "relay-msg", OptionKind::Binary, false),
    (11, "auth", OptionKind::Binary, false),
    (12, "unicast", OptionKind::Ipv6Address, false),
    (13, "status-code", OptionKind::Binary, false),
    (14, "rapid-commit", OptionKind::Empty, false),
    (18, "interface-id", OptionKind::Binary, false),
    (19, "reconf-msg", OptionKind::U8, false),
    (20, "reconf-accept", OptionKind::Empty, false),
    (25, "ia-pd", OptionKind::Binary, false),
    (26, "iaprefix", OptionKind::Binary, false),
    (37, "remote-id", OptionKind::Binary, false),
    (39, "client-fqdn", OptionKind::Binary, false),
    (79, "client-linklayer-addr", OptionKind::Binary, false),
];

/// The name of a `dhcp6` code of the built-in catalog or of the server-managed codes.
fn name6(space: &OptionSpace, code: u16) -> Option<String> {
    if !space.is_dhcp6() {
        return None;
    }
    catalog_v6(code)
        .map(|entry| entry.name)
        .or_else(|| {
            MANAGED_V6
                .iter()
                .find(|(managed, ..)| *managed == code)
                .map(|(_, name, ..)| *name)
        })
        .map(str::to_owned)
}

/// The DHCPv6 catalog with the server-managed codes, by code.
fn catalog6() -> Vec<OptionCatalogItem> {
    let mut items: Vec<OptionCatalogItem> = CATALOG_V6
        .iter()
        .map(|entry| OptionCatalogItem {
            space: OptionSpace::dhcp6(),
            code: entry.code,
            name: entry.name.to_owned(),
            kind: entry.kind,
            array: entry.array,
            server_managed: false,
        })
        .chain(
            MANAGED_V6
                .iter()
                .filter(|(code, ..)| SERVER_MANAGED_V6.contains(code))
                .map(|(code, name, kind, array)| OptionCatalogItem {
                    space: OptionSpace::dhcp6(),
                    code: *code,
                    name: (*name).to_owned(),
                    kind: *kind,
                    array: *array,
                    server_managed: true,
                }),
        )
        .collect();
    items.sort_by_key(|item| item.code);
    items
}

fn all_defs(view: &dyn ReadView) -> Result<Vec<OptionDef>, ApiError> {
    Ok(ConfigService::option_defs(view)?
        .into_iter()
        .map(|row| row.def)
        .collect())
}

/// Checks `action` on the owner's object, and for a pool also on the scope of the pool's
/// prefix (the owner's object of the service).
fn authorize_owner(
    app: &AppState,
    principal: &Principal,
    action: Action,
    view: &dyn ReadView,
    owner: OptionOwner,
) -> Result<(), ApiError> {
    if let OptionOwner::Pool(_) = owner {
        let object = ConfigService::option_owner_object(view, owner)?;
        app.authorize(principal, action, &object)?;
    }
    Ok(())
}

/// Whether the caller may read the set of `owner`, for the filtering of the list.
fn may_read(
    app: &AppState,
    principal: &Principal,
    view: &dyn ReadView,
    owner: OptionOwner,
) -> bool {
    let object: ObjectRef = match owner {
        OptionOwner::Pool(_) => match ConfigService::option_owner_object(view, owner) {
            Ok(object) => object,
            Err(_) => owner_object(owner),
        },
        other => owner_object(other),
    };
    app.authorize(principal, Action::Read, &object).is_ok()
}

#[utoipa::path(
    get,
    path = "/dhcp/option-catalog",
    tag = "dhcp",
    operation_id = "list_dhcp_option_catalog",
    summary = "List the built-in DHCP options",
    description = "Scope: `dhcp.read`. The DHCPv4 options of RFC 2132 and its successors (space `dhcp4`) and the DHCPv6 options of RFC 8415 and the option RFCs (space `dhcp6`) with their types, and the codes the server sets itself, which no option set holds; `space` keeps one of them.",
    params(OptionCatalogParams),
    responses(
        (status = 200, description = "The built-in options by space (`dhcp4` first) and code", body = Vec<OptionCatalogItem>),
        (status = 400, description = "The space is neither `dhcp4` nor `dhcp6` (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dhcp_option_catalog(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Query(params): Query<OptionCatalogParams>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpOptionDef),
    )?;
    let (v4, v6) = match params.space.as_deref().map(str::trim) {
        None | Some("") => (true, true),
        Some(OptionSpace::DHCP4) => (true, false),
        Some(OptionSpace::DHCP6) => (false, true),
        Some(_) => {
            return Err(ApiError::invalid_query("space", "must be dhcp4 or dhcp6"));
        }
    };
    let mut items: Vec<OptionCatalogItem> = Vec::new();
    if v4 {
        items.extend(catalog().into_iter().map(|entry| OptionCatalogItem {
            space: entry.space,
            code: entry.code,
            name: entry.name.to_owned(),
            kind: entry.kind,
            array: entry.array,
            server_managed: entry.server_managed,
        }));
    }
    // WP9.4: the DHCPv6 catalog.
    if v6 {
        items.extend(catalog6());
    }
    Ok(Json(items).into_response())
}

#[utoipa::path(
    get,
    path = "/dhcp/option-defs",
    tag = "dhcp",
    operation_id = "list_dhcp_option_defs",
    summary = "List custom DHCP option definitions",
    description = "Scope: `dhcp.read`.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of definitions by space and code", body = Page<OptionDefItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dhcp_option_defs(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpOptionDef),
    )?;
    let service = configs.get()?;
    let view = page.read(service.store().as_ref()).await?;
    let items: Vec<OptionDefItem> = ConfigService::option_defs(view.as_ref())?
        .into_iter()
        .map(def_item)
        .collect();
    let page = page_of(
        items,
        |item| {
            (
                item.def.space.as_str().to_owned(),
                item.def.code,
                item.def.id,
            )
        },
        &page,
        CursorScope::new("dhcp.option_defs"),
        view.revision(),
    )?;
    Ok(Json(page).into_response())
}

#[utoipa::path(
    post,
    path = "/dhcp/option-defs",
    tag = "dhcp",
    operation_id = "create_dhcp_option_def",
    summary = "Define a custom DHCP option",
    description = "Scope: `dhcp.write`. A code of the built-in catalog or one the server sets is refused; codes 224 to 254 of `dhcp4` are the site-specific range (RFC 3942), and a vendor space holds the option 43 sub-options of its vendor class.",
    request_body(content = OptionDefCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The definition", body = OptionDefItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the definition is invalid (`dhcp.option.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A catalog or server-managed code (`dhcp.option.code_reserved`), a definition of the space and code exists (`dhcp.option_def.exists`), or the DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dhcp_option_def(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    ApiJson(body): ApiJson<OptionDefCreate>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DhcpOptionDef),
    )?;
    let service = configs.get()?;
    let (def, written) = service
        .create_option_def(
            &cx,
            NewOptionDef {
                space: body.space.unwrap_or_else(OptionSpace::dhcp4),
                code: body.code,
                name: body.name,
                kind: body.kind,
                array: body.array,
                vendor_class: body.vendor_class,
                description: body.description,
            },
        )
        .await?;
    let view = service.view(Some(written.revision)).await?;
    let row = ConfigService::option_def(view.as_ref(), def.id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::CREATED, &def_item(row), revision))
}

#[utoipa::path(
    get,
    path = "/dhcp/option-defs/{id}",
    tag = "dhcp",
    operation_id = "get_dhcp_option_def",
    summary = "Get a custom DHCP option definition",
    description = "Scope: `dhcp.read`.",
    params(("id" = String, Path, description = "Option definition identifier (UUID)")),
    responses(
        (status = 200, description = "The definition, with its `ETag`", body = OptionDefItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such definition (`dhcp.option_def.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dhcp_option_def(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<OptionDefId>("id", &id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = configs.get()?;
    let view = service.view(None).await?;
    let row = ConfigService::option_def(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &def_item(row), revision))
}

#[utoipa::path(
    patch,
    path = "/dhcp/option-defs/{id}",
    tag = "dhcp",
    operation_id = "update_dhcp_option_def",
    summary = "Change a custom DHCP option definition",
    description = "Scope: `dhcp.write`. The type does not change while an option set uses the definition.",
    params(
        ("id" = String, Path, description = "Option definition identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    request_body(content = OptionDefPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed definition", body = OptionDefItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the definition is invalid (`dhcp.option.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such definition (`dhcp.option_def.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "An option set uses the definition and the type changes (`dhcp.option_def.in_use`), or the DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The definition changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_dhcp_option_def(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<OptionDefPatch>,
) -> Result<Response, ApiError> {
    let id = parse_id::<OptionDefId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    let (_, written) = service
        .update_option_def(
            &cx,
            id,
            OptionDefChange {
                name: body.name,
                kind: body.kind,
                array: body.array,
                vendor_class: body.vendor_class,
                description: body.description,
            },
            expect,
        )
        .await?;
    let view = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ConfigService::option_def(view.as_ref(), id)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &def_item(row), revision))
}

#[utoipa::path(
    delete,
    path = "/dhcp/option-defs/{id}",
    tag = "dhcp",
    operation_id = "delete_dhcp_option_def",
    summary = "Delete a custom DHCP option definition",
    description = "Scope: `dhcp.write`. A definition an option set uses stays (`dhcp.option_def.in_use`, parameter `by`).",
    params(
        ("id" = String, Path, description = "Option definition identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The definition is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such definition (`dhcp.option_def.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "An option set uses the definition (`dhcp.option_def.in_use`), or the DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The definition changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dhcp_option_def(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_id::<OptionDefId>("id", &id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    service.delete_option_def(&cx, id, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[utoipa::path(
    get,
    path = "/dhcp/option-sets",
    tag = "dhcp",
    operation_id = "list_dhcp_option_sets",
    summary = "List DHCP option sets",
    description = "Scope: `dhcp.read`. The sets the caller may read, by level and owner, each value with its name and typed view.",
    params(PageParams, OptionSetFilter),
    responses(
        (status = 200, description = "A page of option sets by level and owner", body = Page<OptionSetItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dhcp_option_sets(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Query(page): Query<PageParams>,
    Query(filter): Query<OptionSetFilter>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let service = configs.get()?;
    let view = page.read(service.store().as_ref()).await?;
    let defs = all_defs(view.as_ref())?;
    let items: Vec<OptionSetItem> = ConfigService::option_sets(view.as_ref(), filter.level)?
        .into_iter()
        .filter(|row| may_read(&app, &cx.principal, view.as_ref(), row.set.owner))
        .map(|row| set_item(row, &defs))
        .collect();
    let mut scope = CursorScope::new("dhcp.option_sets");
    if let Some(level) = filter.level {
        scope = scope.with(&format!("{level:?}"));
    }
    let page = page_of(
        items,
        |item| (item.level, item.owner.uuid()),
        &page,
        scope,
        view.revision(),
    )?;
    Ok(Json(page).into_response())
}

#[utoipa::path(
    get,
    path = "/dhcp/option-sets/{owner}",
    tag = "dhcp",
    operation_id = "get_dhcp_option_set",
    summary = "Get the DHCP options of a level",
    description = "Scope: `dhcp.read` on the owner. An owner without options reads as an empty set at revision 0.",
    params(("owner" = String, Path, description = "Option set owner: `server`, `scope:<prefix>`, `shared_network:<id>`, `pool:<range>`, `policy:<id>` or `host:<interface>`")),
    responses(
        (status = 200, description = "The option set, with its `ETag`", body = OptionSetItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The owner does not exist (`dhcp.scope.not_found`, `dhcp.shared_network.not_found`, `dhcp.pool.not_found`, `dhcp.policy.not_found`, `ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dhcp_option_set(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(owner): Path<String>,
) -> Result<Response, ApiError> {
    let owner = parse_owner(&owner)?;
    app.authorize(&cx.principal, Action::Read, &owner_object(owner))?;
    let service = configs.get()?;
    let view = service.view(None).await?;
    authorize_owner(&app, &cx.principal, Action::Read, view.as_ref(), owner)?;
    let row = ConfigService::option_set(view.as_ref(), owner)?;
    let defs = all_defs(view.as_ref())?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &set_item(row, &defs), revision))
}

#[utoipa::path(
    put,
    path = "/dhcp/option-sets/{owner}",
    tag = "dhcp",
    operation_id = "set_dhcp_option_set",
    summary = "Replace the DHCP options of a level",
    description = "Scope: `dhcp.write` on the owner. Each value is given in wire form (`data`, hexadecimal) or typed (`typed`) and checked against the type of its code; no values clear the set.",
    params(
        ("owner" = String, Path, description = "Option set owner: `server`, `scope:<prefix>`, `shared_network:<id>`, `pool:<range>`, `policy:<id>` or `host:<interface>`"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read (0 for no set); a stale revision is refused with 412")
    ),
    request_body(content = OptionSetPut, content_type = "application/json"),
    responses(
        (status = 200, description = "The option set", body = OptionSetItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), a value does not fit its type or appears twice (`dhcp.option.invalid`), or a code has no definition (`dhcp.option.unknown`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The owner does not exist (`dhcp.scope.not_found`, `dhcp.shared_network.not_found`, `dhcp.pool.not_found`, `dhcp.policy.not_found`, `ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A code the server sets itself (`dhcp.option.code_reserved`), or the DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The set changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn set_dhcp_option_set(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(owner): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<OptionSetPut>,
) -> Result<Response, ApiError> {
    let owner = parse_owner(&owner)?;
    app.authorize(&cx.principal, Action::Update, &owner_object(owner))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    authorize_owner(
        &app,
        &cx.principal,
        Action::Update,
        service.view(None).await?.as_ref(),
        owner,
    )?;
    let inputs = body
        .values
        .into_iter()
        .map(|value| OptionInput {
            space: value.space.unwrap_or_else(OptionSpace::dhcp4),
            code: value.code,
            data: value.data.map(|data| data.0),
            typed: value.typed,
        })
        .collect();
    let (_, written) = service.set_option_set(&cx, owner, inputs, expect).await?;
    let view = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ConfigService::option_set(view.as_ref(), owner)?;
    let defs = all_defs(view.as_ref())?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &set_item(row, &defs), revision))
}

#[utoipa::path(
    delete,
    path = "/dhcp/option-sets/{owner}",
    tag = "dhcp",
    operation_id = "delete_dhcp_option_set",
    summary = "Clear the DHCP options of a level",
    description = "Scope: `dhcp.write` on the owner. Clearing an empty set is no error.",
    params(
        ("owner" = String, Path, description = "Option set owner: `server`, `scope:<prefix>`, `shared_network:<id>`, `pool:<range>`, `policy:<id>` or `host:<interface>`"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The option set is empty"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The owner does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The set changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dhcp_option_set(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(owner): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let owner = parse_owner(&owner)?;
    app.authorize(&cx.principal, Action::Update, &owner_object(owner))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    let view = service.view(None).await?;
    if ConfigService::option_owner_object(view.as_ref(), owner).is_ok() {
        authorize_owner(&app, &cx.principal, Action::Update, view.as_ref(), owner)?;
    }
    drop(view);
    service.delete_option_set(&cx, owner, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
