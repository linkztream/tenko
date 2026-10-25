//! `GET|POST /dhcp/scopes`, `GET|PATCH|DELETE /dhcp/scopes/{prefix}`, the utilization and
//! the effective options of a scope, and its exclusion ranges.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tenko_auth::{authz::anywhere, settings::Profile};
use tenko_core::{
    Action, ObjectKind, PrefixId, Timestamp,
    dhcp::{ExclusionId, scope_object},
    serde_util::from_hex,
};
use tenko_dhcp::config::{
    ConfigService,
    // WP8.4: the compiled matcher of the image.
    effective::{ClientFacts, ImageMatcher},
    options::describe,
    scopes::{ExclusionRow, NewScope, ScopeChange, ScopeRow},
};

use super::{
    Configs, DhcpScopeCreate, DhcpScopeItem, DhcpScopePatch, DhcpScopeUtilization, EffectiveOption,
    EffectiveOptions, EffectiveOptionsParams, ExclusionCreate, ExclusionItem, may_read_scope,
    page_of, parse_id, settings::profile, with_etag,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams},
    problem::{ApiError, ProblemDetails},
    routes::auth::{ApiJson, if_match},
    state::AppState,
};

pub(super) fn item(row: ScopeRow) -> DhcpScopeItem {
    DhcpScopeItem {
        cidr: row.prefix.cidr,
        // WP9.1: the family of the prefix.
        family: match row.prefix.cidr {
            ipnet::IpNet::V4(_) => "v4".to_owned(),
            ipnet::IpNet::V6(_) => "v6".to_owned(),
        },
        vrf: row.prefix.vrf,
        pools: row.pools,
        leases: row.leases,
        revision: row.revision,
        scope: row.scope,
    }
}

fn exclusion_item(row: ExclusionRow) -> ExclusionItem {
    ExclusionItem {
        exclusion: row.exclusion,
        revision: row.revision,
    }
}

#[utoipa::path(
    get,
    path = "/dhcp/scopes",
    tag = "dhcp",
    operation_id = "list_dhcp_scopes",
    summary = "List DHCP scopes",
    description = "Scope: `dhcp.read`. The scopes the caller may read, by network, with their pools and active leases.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of scopes by network", body = Page<DhcpScopeItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dhcp_scopes(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Read,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    let service = configs.get()?;
    let view = page.read(service.store().as_ref()).await?;
    let rows: Vec<DhcpScopeItem> = ConfigService::scopes(view.as_ref())?
        .into_iter()
        .filter(|row| may_read_scope(&app, &cx.principal, row.scope.prefix))
        .map(item)
        .collect();
    let page = page_of(
        rows,
        |item| {
            (
                item.cidr.network(),
                item.cidr.prefix_len(),
                item.scope.prefix,
            )
        },
        &page,
        CursorScope::new("dhcp.scopes"),
        view.revision(),
    )?;
    Ok(Json(page).into_response())
}

#[utoipa::path(
    post,
    path = "/dhcp/scopes",
    tag = "dhcp",
    operation_id = "create_dhcp_scope",
    summary = "Create a DHCP scope for an IPAM network",
    description = "Scope: `dhcp.write` on the prefix. The DDNS settings default to the server's; under the Hardened profile a scope is restricted to allowed MAC addresses unless the request says otherwise (TGL-17).",
    request_body(content = DhcpScopeCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The scope", body = DhcpScopeItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the scope settings are invalid (`dhcp.scope.invalid`) or the lease times are invalid (`dhcp.lease_times.invalid`) or the DDNS settings are invalid (`dhcp.ddns.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`), shared network (`dhcp.shared_network.not_found`) or class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The prefix has a scope already (`dhcp.scope.exists`), the prefix is a supernet, not a network a scope can serve (`dhcp.scope.not_network`), or the DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dhcp_scope(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    ApiJson(body): ApiJson<DhcpScopeCreate>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Create,
        &anywhere(ObjectKind::DhcpScope),
    )?;
    app.authorize(&cx.principal, Action::Create, &scope_object(body.prefix))?;
    let service = configs.get()?;
    let restricted = if let Some(restricted) = body.restricted {
        restricted
    } else {
        let view = service.view(None).await?;
        profile(view.as_ref())? == Profile::Hardened
    };
    let (_, written) = service
        .create_scope(
            &cx,
            NewScope {
                prefix: body.prefix,
                enabled: body.enabled,
                lease: body.lease,
                authoritative: body.authoritative,
                server_id: body.server_id,
                ddns: body.ddns,
                shared_network: body.shared_network,
                restricted,
                classes: body.classes,
                description: body.description,
                // WP9.1: the DHCPv6 settings.
                v6: body.v6,
            },
        )
        .await?;
    let view = service.view(Some(written.revision)).await?;
    let row = ConfigService::scope(view.as_ref(), body.prefix)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::CREATED, &item(row), revision))
}

#[utoipa::path(
    get,
    path = "/dhcp/scopes/{prefix}",
    tag = "dhcp",
    operation_id = "get_dhcp_scope",
    summary = "Get a DHCP scope",
    description = "Scope: `dhcp.read`.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope")),
    responses(
        (status = 200, description = "The scope, with its `ETag`", body = DhcpScopeItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dhcp_scope(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(prefix): Path<String>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Read, &scope_object(prefix))?;
    let service = configs.get()?;
    let view = service.view(None).await?;
    let row = ConfigService::scope(view.as_ref(), prefix)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    patch,
    path = "/dhcp/scopes/{prefix}",
    tag = "dhcp",
    operation_id = "update_dhcp_scope",
    summary = "Change a DHCP scope",
    description = "Scope: `dhcp.write`. The nil UUID as `shared_network` takes the scope out of its shared network.",
    params(
        ("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    request_body(content = DhcpScopePatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed scope", body = DhcpScopeItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the scope settings are invalid (`dhcp.scope.invalid`) or the lease times are invalid (`dhcp.lease_times.invalid`) or the DDNS settings are invalid (`dhcp.ddns.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`) or no such shared network (`dhcp.shared_network.not_found`) or no such class (`dhcp.class.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The scope changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_dhcp_scope(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(prefix): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<DhcpScopePatch>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Update, &scope_object(prefix))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    let (_, written) = service
        .update_scope(
            &cx,
            prefix,
            ScopeChange {
                enabled: body.enabled,
                lease: body.lease,
                clear_lease: body.clear_lease,
                authoritative: body.authoritative,
                server_id: body.server_id,
                ddns: body.ddns,
                shared_network: body
                    .shared_network
                    .map(|network| (!network.0.is_nil()).then_some(network)),
                restricted: body.restricted,
                classes: body.classes,
                description: body.description,
                // WP9.1: the DHCPv6 settings, replaced or dropped.
                v6: if body.clear_v6 {
                    Some(None)
                } else {
                    body.v6.map(Some)
                },
            },
            expect,
        )
        .await?;
    let view = service
        .view(written.map(|written| written.revision))
        .await?;
    let row = ConfigService::scope(view.as_ref(), prefix)?;
    let revision = row.revision;
    Ok(with_etag(StatusCode::OK, &item(row), revision))
}

#[utoipa::path(
    delete,
    path = "/dhcp/scopes/{prefix}",
    tag = "dhcp",
    operation_id = "delete_dhcp_scope",
    summary = "Delete a DHCP scope (the prefix stays)",
    description = "Scope: `dhcp.write`. Its exclusions, the settings and options of its pools, its policies and its options go with it; the prefix and its ranges stay.",
    params(
        ("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The scope is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The scope changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dhcp_scope(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(prefix): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Delete, &scope_object(prefix))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    service.delete_scope(&cx, prefix, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The pool size as a power of two, rounded down, from 2^32 up.
fn pool_bits(size: u128) -> Option<u8> {
    (size >= 1 << 32).then(|| u8::try_from(size.ilog2()).unwrap_or(u8::MAX))
}

#[utoipa::path(
    get,
    path = "/dhcp/scopes/{prefix}/utilization",
    tag = "dhcp",
    operation_id = "get_dhcp_scope_utilization",
    summary = "Get how full a DHCP scope is",
    description = "Scope: `dhcp.read`. `pool_size` counts the pool addresses a client can hold: the dynamic ones (not excluded) and the reserved ones; `leased` and `abandoned` count dynamic addresses. A DHCPv6 scope (`family` `v6`) counts its DHCPv6 leases; its `pool_size` and `free` stop at 2^64 - 1 and `pool_bits` gives the size of a large pool.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope")),
    responses(
        (status = 200, description = "The figures of the scope", body = DhcpScopeUtilization),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dhcp_scope_utilization(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(prefix): Path<String>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Read, &scope_object(prefix))?;
    let service = configs.get()?;
    let view = service.view(None).await?;
    let at = Timestamp::now();
    // WP9.4: a DHCPv6 scope counts its DHCPv6 leases over 128-bit pools.
    if let Some(figures) = ConfigService::utilization6(view.as_ref(), prefix, at)? {
        let clamp = |value: u128| u64::try_from(value).unwrap_or(u64::MAX);
        return Ok(Json(DhcpScopeUtilization {
            prefix,
            pool_size: clamp(figures.pool_size),
            leased: figures.leased,
            reserved: figures.reserved,
            abandoned: figures.abandoned,
            free: clamp(figures.free),
            utilization: figures.utilization,
            at,
            family: "v6".to_owned(),
            pool_bits: pool_bits(figures.pool_size),
        })
        .into_response());
    }
    let figures = ConfigService::utilization(view.as_ref(), prefix, at)?;
    Ok(Json(DhcpScopeUtilization {
        prefix,
        pool_size: figures.pool_size,
        leased: figures.leased,
        reserved: figures.reserved,
        abandoned: figures.abandoned,
        free: figures.free,
        utilization: figures.utilization,
        at,
        family: "v4".to_owned(),
        pool_bits: pool_bits(u128::from(figures.pool_size)),
    })
    .into_response())
}

#[utoipa::path(
    get,
    path = "/dhcp/scopes/{prefix}/effective-options",
    tag = "dhcp",
    operation_id = "get_dhcp_effective_options",
    summary = "Get the options a client gets in a DHCP scope",
    description = "Scope: `dhcp.read`. The server's, the shared network's and the scope's options, those of the policies that match the client (none until classes are matched, WP8.4) and those of the client's reservation, the more specific level winning per code. Pool options depend on the address and are shown on the pool.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope"), EffectiveOptionsParams),
    responses(
        (status = 200, description = "The options with the level each came from", body = EffectiveOptions),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dhcp_effective_options(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(prefix): Path<String>,
    Query(params): Query<EffectiveOptionsParams>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Read, &scope_object(prefix))?;
    let client_id = params
        .client_id
        .as_deref()
        .map(|text| {
            from_hex(text)
                .filter(|bytes| !bytes.is_empty() && bytes.len() <= 255)
                .ok_or_else(|| {
                    ApiError::invalid_query("client_id", "1 to 255 octets in hexadecimal")
                })
        })
        .transpose()?;
    // WP8.6: an architecture type is two octets (RFC 4578).
    let architecture = params
        .architecture
        .map(|code| {
            u16::try_from(code)
                .map_err(|_| ApiError::invalid_query("architecture", "an integer from 0 to 65535"))
        })
        .transpose()?;
    let service = configs.get()?;
    let view = service.view(None).await?;
    let client = ClientFacts {
        mac: params.mac.map(tenko_core::net::MacAddr::octets),
        client_id,
        vendor_class: params.vendor_class,
        user_class: params.user_class,
        // WP8.6: the architecture and the host name of the "why this value" view.
        architecture,
        host_name: params.host_name,
        // WP8.4: the fields the query does not carry.
        ..ClientFacts::default()
    };
    let effective =
        ConfigService::effective_options(view.as_ref(), prefix, &client, &ImageMatcher)?;
    let defs: Vec<_> = ConfigService::option_defs(view.as_ref())?
        .into_iter()
        .map(|row| row.def)
        .collect();
    let options = effective
        .options
        .into_iter()
        .map(|entry| {
            let (name, typed) = describe(&entry.value, &defs);
            EffectiveOption {
                value: entry.value,
                name,
                typed,
                level: entry.owner.level(),
                owner: entry.owner,
            }
        })
        .collect();
    Ok(Json(EffectiveOptions {
        prefix,
        reservation: effective.reservation,
        policies: effective.policies,
        classes: effective.classes,
        options,
    })
    .into_response())
}

#[utoipa::path(
    get,
    path = "/dhcp/scopes/{prefix}/exclusions",
    tag = "dhcp",
    operation_id = "list_dhcp_exclusions",
    summary = "List the exclusion ranges of a DHCP scope",
    description = "Scope: `dhcp.read`. The explicit ranges; the prefix's reserved and infrastructure ranges and the addresses of hosts that are not dynamic are excluded as well.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope"), PageParams),
    responses(
        (status = 200, description = "A page of exclusion ranges by start address", body = Page<ExclusionItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dhcp_exclusions(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(prefix): Path<String>,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Read, &scope_object(prefix))?;
    let service = configs.get()?;
    let view = page.read(service.store().as_ref()).await?;
    let items: Vec<ExclusionItem> = ConfigService::exclusions(view.as_ref(), prefix)?
        .into_iter()
        .map(exclusion_item)
        .collect();
    let page = page_of(
        items,
        |item| (item.exclusion.first, item.exclusion.last, item.exclusion.id),
        &page,
        CursorScope::new("dhcp.exclusions").with(&prefix.to_string()),
        view.revision(),
    )?;
    Ok(Json(page).into_response())
}

#[utoipa::path(
    post,
    path = "/dhcp/scopes/{prefix}/exclusions",
    tag = "dhcp",
    operation_id = "create_dhcp_exclusion",
    summary = "Exclude a range of a DHCP scope",
    description = "Scope: `dhcp.write`.",
    params(("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope")),
    request_body(content = ExclusionCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The exclusion range", body = ExclusionItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the range is unordered or outside the scope (`dhcp.exclusion.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dhcp_exclusion(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path(prefix): Path<String>,
    ApiJson(body): ApiJson<ExclusionCreate>,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    app.authorize(&cx.principal, Action::Update, &scope_object(prefix))?;
    let service = configs.get()?;
    let (exclusion, written) = service
        .create_exclusion(&cx, prefix, body.first, body.last, body.description)
        .await?;
    Ok(with_etag(
        StatusCode::CREATED,
        &ExclusionItem {
            exclusion,
            revision: written.revision,
        },
        written.revision,
    ))
}

#[utoipa::path(
    delete,
    path = "/dhcp/scopes/{prefix}/exclusions/{id}",
    tag = "dhcp",
    operation_id = "delete_dhcp_exclusion",
    summary = "Delete an exclusion range",
    description = "Scope: `dhcp.write`.",
    params(
        ("prefix" = String, Path, description = "Prefix identifier (UUID) of the scope"),
        ("id" = String, Path, description = "Exclusion identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The exclusion range is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No scope serves the prefix (`dhcp.scope.not_found`) or no such exclusion range (`dhcp.exclusion.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The range changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dhcp_exclusion(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    Path((prefix, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let prefix = parse_id::<PrefixId>("prefix", &prefix)?;
    let id = parse_id::<ExclusionId>("id", &id)?;
    app.authorize(&cx.principal, Action::Update, &scope_object(prefix))?;
    let service = configs.get()?;
    let expect = if_match(&headers)?;
    service.delete_exclusion(&cx, prefix, id, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
