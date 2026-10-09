//! Change history, restore, bulk changes, tags, custom fields and search, and the helpers
//! every IPAM area file shares.
//!
//! Area: common. Owner: WP1.4. Requirements: IPAM-08, IPAM-09, API-04, API-09.
//!
//! `GET /{collection}/{id}/history`, `POST /{collection}/{id}/restore` and
//! `POST /{collection}/bulk` exist for tenants, VRFs, sites, VLANs, prefixes, ranges,
//! addresses, hosts and interfaces (`collection_routes!`).
//!
//! # Conventions of the IPAM endpoints (plan section 4)
//!
//! - **Service.** The IPAM service is a request extension `Arc<tenko_ipam::IpamService>`
//!   that the server adds (`.layer(Extension(service))`); without it every IPAM endpoint
//!   answers 503 `ipam.unavailable` ([`Ipam`]).
//! - **Lists** use [`crate::list`]: `limit` (1 to 1,000), an opaque `cursor` bound to the
//!   query and `at_least=<revision>` (read-your-writes), plus filters such as `status`,
//!   `vrf`, `tag`, `within`, `q`, `sort=-updated,name` and `deleted=include|only`; repeated
//!   keys and comma-separated values both work, unknown keys are refused
//!   (`sys.invalid_query`). The answer is a [`Page`]: `{ items, next_cursor, revision }`.
//! - **Reads** of one object answer the object with `ETag: "<revision>"`.
//! - **Writes** take `Idempotency-Key` on POST (API-04), `If-Match: "<revision>"` on PATCH,
//!   DELETE and restore (412 `ipam.revision_mismatch` when stale), `?dry_run=true` for the
//!   plan without writing (API-09) and `?acknowledge=<code>,...` for warnings that need an
//!   acknowledgement. The answer is a [`WriteResponse`]: the object after the change, the
//!   committed `revision`, the inline `job_id` (Q4), warnings, and on a dry run the plan.
//! - **Errors** are problem details with stable `ipam.*` codes.
//! - **Authorization.** With an [`Authorizer`](tenko_core::Authorizer) in the state, reads
//!   need [`Action::Read`], creates [`Action::Create`] on the kind, changes
//!   [`Action::Update`] and deletes [`Action::Delete`] on the object; a list is empty when
//!   the principal may read nothing of the kind.

use std::{collections::BTreeSet, sync::Arc};

use axum::{
    Json,
    extract::{FromRequest, FromRequestParts, Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tenko_core::{
    Action, CodedError, InterfaceId, JobId, ObjectKind, ObjectRef, PrefixId, RequestCtx, Revision,
    ScopeFilter, SiteId, TenantId, VrfId,
    ipam::{
        Address, AssignmentMode, CustomFieldDef, FieldKey, Host, Interface, Prefix, PrefixRole,
        Range, RangeRole, Site, Status, Tag, Tenant, Vlan, Vrf,
    },
};
use tenko_ipam::{
    Entity, HistoryEntry, IpamCommand, IpamService, PlanOptions, PlanView, PlanWarning, codes,
    command::{CustomFieldInput, CustomFieldPatch, UpdateCustomField},
    query::{self, AddressRow, Deleted, HostExpander, ListQuery, Listable, SearchHit, TagCount},
};
use tenko_store::ReadView;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, Filters, PageParams, SortKey, encode_cursor},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_tenant_history))
        .routes(routes!(restore_tenant))
        .routes(routes!(bulk_tenants))
        .routes(routes!(get_vrf_history))
        .routes(routes!(restore_vrf))
        .routes(routes!(bulk_vrfs))
        .routes(routes!(get_site_history))
        .routes(routes!(restore_site))
        .routes(routes!(bulk_sites))
        .routes(routes!(get_vlan_history))
        .routes(routes!(restore_vlan))
        .routes(routes!(bulk_vlans))
        .routes(routes!(get_prefix_history))
        .routes(routes!(restore_prefix))
        .routes(routes!(bulk_prefixes))
        .routes(routes!(get_range_history))
        .routes(routes!(restore_range))
        .routes(routes!(bulk_ranges))
        .routes(routes!(get_address_history))
        .routes(routes!(restore_address))
        .routes(routes!(bulk_addresses))
        .routes(routes!(get_host_history))
        .routes(routes!(restore_host))
        .routes(routes!(bulk_hosts))
        .routes(routes!(get_interface_history))
        .routes(routes!(restore_interface))
        .routes(routes!(bulk_interfaces))
        .routes(routes!(list_tags))
        .routes(routes!(list_custom_fields, create_custom_field))
        .routes(routes!(
            get_custom_field,
            update_custom_field,
            delete_custom_field
        ))
        .routes(routes!(search))
}

// ===== shared helpers ==================================================================

/// The IPAM service of the request, from the `Arc<IpamService>` extension; 503
/// `ipam.unavailable` when the server did not add one.
pub(crate) struct Ipam(pub(crate) Arc<IpamService>);

impl<S: Send + Sync> FromRequestParts<S> for Ipam {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<Arc<IpamService>>()
                .cloned()
                .map(Ipam)
                .ok_or_else(|| {
                    ApiError::from_coded_error(
                        CodedError::new(
                            codes::UNAVAILABLE,
                            503,
                            "IP address management is not configured on this server",
                        )
                        .with_title("Service unavailable"),
                    )
                }),
        )
    }
}

/// A JSON body refused with problem details instead of plain text: 400
/// `sys.invalid_request` for malformed JSON or a body that does not fit the schema (a
/// missing, mistyped or unknown member), 415 for another content type, 413 over the body
/// limit. The detail names the problem; IPAM bodies carry no secrets.
pub(crate) struct IpamJson<T>(pub(crate) T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for IpamJson<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => {
                let status = match rejection.status().as_u16() {
                    status @ (413 | 415) => status,
                    _ => 400,
                };
                Err(ApiError::from_coded_error(
                    CodedError::new(
                        tenko_core::error::codes::INVALID_REQUEST,
                        status,
                        rejection.body_text(),
                    )
                    .with_param("part", "body"),
                ))
            }
        }
    }
}

/// A path parameter refused with problem details: 400 `sys.invalid_request` when it does
/// not parse (an identifier that is not a UUID, a key with invalid characters).
pub(crate) struct IpamPath<T>(pub(crate) T);

impl<T: DeserializeOwned + Send, S: Send + Sync> FromRequestParts<S> for IpamPath<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(rejection) => Err(ApiError::from_coded_error(
                CodedError::new(
                    tenko_core::error::codes::INVALID_REQUEST,
                    400,
                    rejection.body_text(),
                )
                .with_param("part", "path"),
            )),
        }
    }
}

/// A `snake_case` enum value (`status=active`), or 400 `sys.invalid_query`.
fn parse_enum<T: DeserializeOwned>(name: &str, raw: &str, what: &str) -> Result<T, ApiError> {
    serde_json::from_value(serde_json::Value::String(raw.to_owned()))
        .map_err(|_| ApiError::invalid_query(name, format!("`{raw}` is not {what}")))
}

/// The single `snake_case` enum value of a parameter.
pub(crate) fn enum_param<T: DeserializeOwned>(
    filters: &Filters,
    name: &str,
    what: &str,
) -> Result<Option<T>, ApiError> {
    filters
        .get(name)?
        .map(|raw| parse_enum::<T>(name, raw, what))
        .transpose()
}

/// Every `snake_case` enum value of a parameter.
pub(crate) fn enum_params<T: DeserializeOwned>(
    filters: &Filters,
    name: &str,
    what: &str,
) -> Result<Vec<T>, ApiError> {
    filters
        .all(name)
        .into_iter()
        .map(|raw| parse_enum::<T>(name, raw, what))
        .collect()
}

/// The filters a list understands; the area file names the ones of its collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Filter {
    /// `status=active,planned`.
    Status,
    /// `vrf=<id>`.
    Vrf,
    /// `tenant=<id>`.
    Tenant,
    /// `site=<id>` (for sites: the parent).
    Site,
    /// `tag=a,b` (all must match).
    Tag,
    /// `within=192.0.2.0/24`.
    Within,
    /// `q=text`.
    Q,
    /// `sort=-updated,name`.
    Sort,
    /// `deleted=exclude|include|only`.
    Deleted,
    /// `prefix=<id>`.
    Prefix,
    /// `host=<id>`.
    Host,
    /// `interface=<id>`.
    Interface,
    /// `role=supernet|network` (prefixes).
    PrefixRole,
    /// `role=dhcp_pool|reserved|infrastructure` (ranges).
    RangeRole,
    /// `mode=static|reserved|dynamic|unmanaged` (hosts).
    Mode,
    /// `locked=true|false` (hosts).
    Locked,
}

impl Filter {
    /// The query parameter name.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Filter::Status => "status",
            Filter::Vrf => "vrf",
            Filter::Tenant => "tenant",
            Filter::Site => "site",
            Filter::Tag => "tag",
            Filter::Within => "within",
            Filter::Q => "q",
            Filter::Sort => "sort",
            Filter::Deleted => "deleted",
            Filter::Prefix => "prefix",
            Filter::Host => "host",
            Filter::Interface => "interface",
            Filter::PrefixRole | Filter::RangeRole => "role",
            Filter::Mode => "mode",
            Filter::Locked => "locked",
        }
    }
}

/// A parsed list request.
#[derive(Debug, Clone)]
pub(crate) struct ListArgs {
    /// The domain query (its cursor already unwrapped from the API cursor).
    pub(crate) query: ListQuery,
    /// Paging parameters.
    pub(crate) page: PageParams,
    /// The scope the cursors of this query are bound to.
    pub(crate) scope: CursorScope,
}

/// Reads the paging parameters and the allowed filters of a list of `T`; unknown
/// parameters, unknown sort fields and foreign cursors are refused.
pub(crate) fn list_args<T: Listable>(
    filters: &Filters,
    endpoint: &str,
    allowed: &[Filter],
) -> Result<ListArgs, ApiError> {
    let names: Vec<&str> = allowed.iter().map(|filter| filter.name()).collect();
    filters.only(&names)?;
    let page = filters.page()?;
    let scope = filters.scope(endpoint);
    let mut query = ListQuery {
        limit: Some(page.limit()?),
        cursor: page.cursor::<String>(scope)?,
        ..ListQuery::default()
    };
    for filter in allowed {
        let name = filter.name();
        match filter {
            Filter::Status => query.status = enum_params::<Status>(filters, name, "a status")?,
            Filter::Vrf => query.vrf = filters.parse::<VrfId>(name)?,
            Filter::Tenant => query.tenant = filters.parse::<TenantId>(name)?,
            Filter::Site => query.site = filters.parse::<SiteId>(name)?,
            Filter::Tag => query.tag = filters.parse_all::<Tag>(name)?,
            Filter::Within => query.within = filters.cidr(name)?,
            Filter::Q => query.q = filters.get(name)?.map(str::to_owned),
            Filter::Sort => {
                let mut fields: Vec<&'static str> = T::SORTS.to_vec();
                fields.extend(["created", "updated"]);
                query.sort = filters
                    .sort(&fields, &[SortKey::asc(T::SORTS[0])])?
                    .into_iter()
                    .map(|key| {
                        if key.descending {
                            format!("-{}", key.field)
                        } else {
                            key.field.to_owned()
                        }
                    })
                    .collect();
            }
            Filter::Deleted => {
                query.deleted = enum_param::<Deleted>(filters, name, "exclude, include or only")?
                    .unwrap_or_default();
            }
            Filter::Prefix => query.prefix = filters.parse::<PrefixId>(name)?,
            Filter::Host => query.host = filters.parse(name)?,
            Filter::Interface => query.interface = filters.parse::<InterfaceId>(name)?,
            Filter::PrefixRole => {
                query.prefix_role = enum_param::<PrefixRole>(filters, name, "supernet or network")?;
            }
            Filter::RangeRole => {
                query.range_role = enum_param::<RangeRole>(
                    filters,
                    name,
                    "dhcp_pool, reserved or infrastructure",
                )?;
            }
            Filter::Mode => {
                query.mode = enum_param::<AssignmentMode>(filters, name, "an assignment mode")?;
            }
            Filter::Locked => query.locked = filters.boolean(name)?,
        }
    }
    Ok(ListArgs { query, page, scope })
}

/// Lists one collection with the shared conventions: authorization scope, read view and
/// page.
pub(crate) async fn list_collection<T: Listable>(
    app: &AppState,
    cx: &RequestCtx,
    ipam: &IpamService,
    args: ListArgs,
) -> Result<Json<Page<T>>, ApiError> {
    let view = ipam.view(args.page.at_least.map(Revision)).await?;
    if !may_read_kind(app, cx, T::KIND) {
        return Ok(Json(Page::new(Vec::new(), None, view.revision())));
    }
    let page = query::list::<T>(view.as_ref(), &args.query)?;
    Ok(Json(wire_page(page, args.scope)))
}

/// A domain page with its cursor wrapped into an API cursor bound to `scope`.
pub(crate) fn wire_page<T>(page: query::Page<T>, scope: CursorScope) -> Page<T> {
    Page::new(
        page.items,
        page.next_cursor.map(|cursor| encode_cursor(scope, &cursor)),
        page.revision,
    )
}

/// Reads one object with the shared conventions: authorization, `at_least` and `ETag`.
pub(crate) async fn get_one<T: Entity + Serialize>(
    app: &AppState,
    cx: &RequestCtx,
    ipam: &IpamService,
    id: T::Id,
    filters: &Filters,
) -> Result<Response, ApiError> {
    filters.only(&[])?;
    let at_least = filters.page()?.at_least.map(Revision);
    authorize(app, cx, Action::Read, id.into())?;
    let view = ipam.view(at_least).await?;
    let object = query::get::<T>(view.as_ref(), id)?;
    let revision = object.meta().revision;
    Ok(with_etag(Json(object).into_response(), revision))
}

/// The parameters of a write: `dry_run`, `acknowledge` and, for deletes, `cascade`.
#[derive(Debug, Clone, Default)]
pub(crate) struct WriteArgs {
    /// Plan only.
    pub(crate) dry_run: bool,
    /// Acknowledged warnings.
    pub(crate) options: PlanOptions,
    /// Delete what blocks a delete.
    pub(crate) cascade: bool,
}

/// Reads the write parameters; unknown parameters are refused.
pub(crate) fn write_args(filters: &Filters, allow_cascade: bool) -> Result<WriteArgs, ApiError> {
    if allow_cascade {
        filters.only(&["dry_run", "acknowledge", "cascade"])?;
    } else {
        filters.only(&["dry_run", "acknowledge"])?;
    }
    Ok(WriteArgs {
        dry_run: filters.boolean("dry_run")?.unwrap_or(false),
        options: PlanOptions::acknowledging(filters.all("acknowledge")),
        cascade: allow_cascade && filters.boolean("cascade")?.unwrap_or(false),
    })
}

/// The revision of an `If-Match` header (`"12"`, `12` or `W/"12"`); `None` without one or
/// for `*` (any current revision).
pub(crate) fn if_match(headers: &HeaderMap) -> Result<Option<Revision>, ApiError> {
    let Some(value) = headers.get(header::IF_MATCH) else {
        return Ok(None);
    };
    let text = value.to_str().unwrap_or_default().trim();
    if text == "*" {
        return Ok(None);
    }
    let bare = text.strip_prefix("W/").unwrap_or(text).trim_matches('"');
    bare.parse::<u64>().map(|r| Some(Revision(r))).map_err(|_| {
        ApiError::from_coded_error(
            CodedError::new(
                codes::VALIDATION,
                400,
                format!(
                    "If-Match `{}` is not a revision such as \"12\"",
                    text.chars().take(64).collect::<String>()
                ),
            )
            .with_title("Invalid request")
            .with_param("field", "If-Match"),
        )
    })
}

/// Adds `ETag: "<revision>"`.
pub(crate) fn with_etag(mut response: Response, revision: Revision) -> Response {
    if let Ok(value) = HeaderValue::from_str(&format!("\"{}\"", revision.0)) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

/// Checks `action` on `object`; passes without an authorizer.
pub(crate) fn authorize(
    app: &AppState,
    cx: &RequestCtx,
    action: Action,
    object: ObjectRef,
) -> Result<(), ApiError> {
    if let Some(authorizer) = &app.authorizer {
        authorizer.check(&cx.principal, action, &object)?;
    }
    Ok(())
}

/// The object a create is checked against: the kind with a nil identifier.
pub(crate) fn new_of(kind: ObjectKind) -> ObjectRef {
    ObjectRef::singleton(kind)
}

/// Whether the principal may read objects of the kind at all (Slice 1 scopes are all or
/// nothing; anything narrower counts as all until scoped grants arrive).
pub(crate) fn may_read_kind(app: &AppState, cx: &RequestCtx, kind: ObjectKind) -> bool {
    app.authorizer.as_ref().is_none_or(|authorizer| {
        !matches!(
            authorizer.scope(&cx.principal, Action::Read, kind),
            ScopeFilter::Nothing
        )
    })
}

/// The `expand` parameter of the address lists, removed from the other parameters so that
/// a cursor stays valid with and without it. Only `host` exists; repeat the parameter or
/// separate values with commas.
///
/// # Errors
///
/// 400 `sys.invalid_query` for another value.
pub(crate) fn take_expand(filters: &Filters) -> Result<(Filters, bool), ApiError> {
    let mut host = false;
    for value in filters.all("expand") {
        for part in value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            if part == "host" {
                host = true;
            } else {
                return Err(ApiError::invalid_query(
                    "expand",
                    format!("unknown expansion `{part}`; allowed: host"),
                ));
            }
        }
    }
    let rest = filters
        .pairs()
        .iter()
        .filter(|(name, _)| name != "expand")
        .cloned();
    Ok((Filters::from_pairs(rest), host))
}

/// Address rows of a page, with interface and host when `expand` asks for them and the
/// principal may read interfaces and hosts (otherwise both stay absent).
pub(crate) fn address_rows(
    app: &AppState,
    cx: &RequestCtx,
    view: &dyn ReadView,
    addresses: Vec<Address>,
    expand: bool,
) -> Result<Vec<AddressRow>, ApiError> {
    let mut rows: Vec<AddressRow> = addresses.into_iter().map(AddressRow::from).collect();
    if expand && may_expand_hosts(app, cx) {
        let mut expander = HostExpander::new(view);
        for row in &mut rows {
            expander.expand(row)?;
        }
    }
    Ok(rows)
}

/// Whether `expand=host` may show interfaces and hosts to the principal.
pub(crate) fn may_expand_hosts(app: &AppState, cx: &RequestCtx) -> bool {
    may_read_kind(app, cx, ObjectKind::Interface) && may_read_kind(app, cx, ObjectKind::Host)
}

/// What a command needs: the action and the object it is checked against.
pub(crate) fn command_access(command: &IpamCommand) -> (Action, ObjectRef) {
    match command {
        IpamCommand::CreateTenant(_)
        | IpamCommand::CreateVrf(_)
        | IpamCommand::CreateSite(_)
        | IpamCommand::CreateVlan(_)
        | IpamCommand::CreatePrefix(_)
        | IpamCommand::CreateRange(_)
        | IpamCommand::CreateAddress(_)
        | IpamCommand::CreateHost(_)
        | IpamCommand::CreateInterface(_)
        | IpamCommand::AllocateAddress(_)
        | IpamCommand::AllocatePrefix(_) => (Action::Create, new_of(command.kind())),
        IpamCommand::UpdateTenant(u) => (Action::Update, u.id.into()),
        IpamCommand::UpdateVrf(u) => (Action::Update, u.id.into()),
        IpamCommand::UpdateSite(u) => (Action::Update, u.id.into()),
        IpamCommand::UpdateVlan(u) => (Action::Update, u.id.into()),
        IpamCommand::UpdatePrefix(u) => (Action::Update, u.id.into()),
        IpamCommand::UpdateRange(u) => (Action::Update, u.id.into()),
        IpamCommand::UpdateAddress(u) => (Action::Update, u.id.into()),
        IpamCommand::UpdateHost(u) => (Action::Update, u.id.into()),
        IpamCommand::UpdateInterface(u) => (Action::Update, u.id.into()),
        IpamCommand::SetLock { host, .. } | IpamCommand::SetMode { host, .. } => {
            (Action::Update, (*host).into())
        }
        IpamCommand::Delete { object, .. } => (Action::Delete, *object),
        IpamCommand::Restore { object, .. } => (Action::Update, *object),
        IpamCommand::CreateCustomField(_)
        | IpamCommand::UpdateCustomField(_)
        | IpamCommand::DeleteCustomField { .. } => {
            (Action::Administer, new_of(ObjectKind::CustomField))
        }
    }
}

/// A list without paging.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub(crate) struct ListBody<T> {
    /// Every item.
    pub(crate) items: Vec<T>,
    /// The store revision the list was read at.
    #[schema(value_type = u64)]
    pub(crate) revision: Revision,
}

/// The answer of a write.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub(crate) struct WriteResponse<T> {
    /// The object after the change; on a dry run, the object as it would be.
    pub(crate) item: Option<T>,
    /// The revision that committed the change; `null` on a dry run.
    #[schema(value_type = Option<u64>)]
    pub(crate) revision: Option<Revision>,
    /// The inline job that carried the change (Q4); `null` on a dry run, a replay and a
    /// change that changed nothing.
    pub(crate) job_id: Option<JobId>,
    /// Whether this is a dry run.
    pub(crate) dry_run: bool,
    /// Whether an earlier result was returned for a repeated `Idempotency-Key`.
    pub(crate) replayed: bool,
    /// Warnings of the plan.
    pub(crate) warnings: Vec<PlanWarning>,
    /// The plan (dry runs only).
    pub(crate) plan: Option<PlanView>,
}

/// Plans or applies `commands` and answers the primary object of the first command as
/// `T`: 201 for an applied create, 200 otherwise, with `ETag` once applied.
pub(crate) async fn write_one<T: Entity + Serialize>(
    ipam: &IpamService,
    cx: &RequestCtx,
    commands: Vec<IpamCommand>,
    args: &WriteArgs,
    created: bool,
) -> Result<Response, ApiError> {
    if args.dry_run {
        let plan = ipam.preview(&commands, cx, &args.options, None).await?;
        let primary = plan.results.first().copied();
        let item = primary.and_then(|primary| {
            plan.changes
                .iter()
                .rev()
                .find(|change| change.object == primary)
                .and_then(|change| change.after.clone())
                .and_then(T::from_object)
        });
        let body = WriteResponse {
            item,
            revision: None,
            job_id: None,
            dry_run: true,
            replayed: plan.replay.is_some(),
            warnings: plan.warnings.clone(),
            plan: Some(plan.view()),
        };
        return Ok((StatusCode::OK, Json(body)).into_response());
    }
    let applied = ipam.execute(&commands, cx, &args.options).await?;
    let view = ipam.view(Some(applied.revision)).await?;
    let item = match applied.results.first() {
        Some(primary) => Some(query::get::<T>(view.as_ref(), primary.id.into())?),
        None => None,
    };
    let etag = item.as_ref().map(|item| item.meta().revision);
    let status = if created && !applied.replayed {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let body = WriteResponse {
        item,
        revision: Some(applied.revision),
        job_id: applied.job_id,
        dry_run: false,
        replayed: applied.replayed,
        warnings: applied.warnings,
        plan: None,
    };
    let response = (status, Json(body)).into_response();
    Ok(match etag {
        Some(revision) => with_etag(response, revision),
        None => response,
    })
}

/// The answer of a bulk change.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub(crate) struct BulkResponse {
    /// The revision that committed the change; `null` on a dry run.
    #[schema(value_type = Option<u64>)]
    pub(crate) revision: Option<Revision>,
    /// The inline job (Q4).
    pub(crate) job_id: Option<JobId>,
    /// Whether this is a dry run.
    pub(crate) dry_run: bool,
    /// Whether an earlier result was returned for a repeated `Idempotency-Key`.
    pub(crate) replayed: bool,
    /// The primary object of each operation, in order.
    pub(crate) results: Vec<ObjectRef>,
    /// Warnings of the plan.
    pub(crate) warnings: Vec<PlanWarning>,
    /// The plan (dry runs only).
    pub(crate) plan: Option<PlanView>,
}

/// A bulk change: every operation applies, or none (API-04).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub(crate) struct BulkRequest {
    /// The operations, in order; all must target the collection of the endpoint.
    pub(crate) operations: Vec<IpamCommand>,
}

/// Parameters of writes (documentation of the query string).
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct WriteParams {
    /// Plan the change and return the plan without writing (API-09).
    dry_run: Option<bool>,
    /// Warning codes to acknowledge, comma-separated (for example
    /// `ipam.prefix.nibble_boundary`).
    acknowledge: Option<String>,
}

/// Parameters of deletes (documentation of the query string).
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct DeleteParams {
    /// Plan the delete and return the plan without writing (API-09).
    dry_run: Option<bool>,
    /// Warning codes to acknowledge, comma-separated.
    acknowledge: Option<String>,
    /// Also delete what would otherwise block the delete: the addresses and ranges of a
    /// prefix, the addresses of a host or an interface.
    cascade: Option<bool>,
}

/// Parameters of a read of one object (documentation of the query string).
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct ReadParams {
    /// Read at least at this store revision (read-your-writes).
    at_least: Option<u64>,
}

/// The `If-Match` header (documentation).
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Header)]
#[allow(dead_code)]
pub(crate) struct IfMatch {
    /// The revision the client read, as `"12"`; the write fails with 412
    /// `ipam.revision_mismatch` when the object changed since.
    #[param(rename = "If-Match")]
    if_match: Option<String>,
}

/// The `Idempotency-Key` header (documentation).
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Header)]
#[allow(dead_code)]
pub(crate) struct IdempotencyKeyHeader {
    /// Repeating a POST with the same key returns the first result (API-04).
    #[param(rename = "Idempotency-Key")]
    idempotency_key: Option<String>,
}

// ===== history, restore and bulk per collection =========================================

async fn history_of(
    app: &AppState,
    cx: &RequestCtx,
    ipam: &IpamService,
    object: ObjectRef,
    filters: &Filters,
) -> Result<Json<Page<HistoryEntry>>, ApiError> {
    filters.only(&[])?;
    let page = filters.page()?;
    let scope = filters.scope("ipam.history").with(&object.to_string());
    let cursor = page.cursor::<String>(scope)?;
    authorize(app, cx, Action::Read, object)?;
    let view = ipam.view(page.at_least.map(Revision)).await?;
    query::get_object(view.as_ref(), object)?;
    let history = query::history(
        view.as_ref(),
        object,
        cursor.as_deref(),
        Some(page.limit()?),
    )?;
    Ok(Json(wire_page(history, scope)))
}

async fn restore_of<T: Entity + Serialize>(
    app: &AppState,
    cx: &RequestCtx,
    ipam: &IpamService,
    object: ObjectRef,
    headers: &HeaderMap,
    filters: &Filters,
) -> Result<Response, ApiError> {
    let args = write_args(filters, false)?;
    let expected = if_match(headers)?;
    authorize(app, cx, Action::Update, object)?;
    write_one::<T>(
        ipam,
        cx,
        vec![IpamCommand::Restore { object, expected }],
        &args,
        false,
    )
    .await
}

async fn bulk_of(
    app: &AppState,
    cx: &RequestCtx,
    ipam: &IpamService,
    kind: ObjectKind,
    request: BulkRequest,
    filters: &Filters,
) -> Result<Response, ApiError> {
    let args = write_args(filters, false)?;
    for (index, operation) in request.operations.iter().enumerate() {
        if operation.kind() != kind {
            return Err(ApiError::from_coded_error(
                CodedError::new(
                    codes::BULK_WRONG_COLLECTION,
                    400,
                    format!(
                        "operation {index} changes a {}, not a {kind}",
                        operation.kind()
                    ),
                )
                .with_title("Operation for another collection")
                .with_param("index", index.to_string())
                .with_param("expected", kind.as_str()),
            ));
        }
        let (action, object) = command_access(operation);
        authorize(app, cx, action, object)?;
    }
    if args.dry_run {
        let plan = ipam
            .preview(&request.operations, cx, &args.options, None)
            .await?;
        let body = BulkResponse {
            revision: None,
            job_id: None,
            dry_run: true,
            replayed: plan.replay.is_some(),
            results: plan.results.clone(),
            warnings: plan.warnings.clone(),
            plan: Some(plan.view()),
        };
        return Ok(Json(body).into_response());
    }
    let applied = ipam.execute(&request.operations, cx, &args.options).await?;
    Ok(Json(BulkResponse {
        revision: Some(applied.revision),
        job_id: applied.job_id,
        dry_run: false,
        replayed: applied.replayed,
        results: applied.results,
        warnings: applied.warnings,
        plan: None,
    })
    .into_response())
}

/// Declares the history, restore and bulk handlers of one collection. The path and the
/// operation id are built from the collection name with `concat!` and `stringify!`.
macro_rules! collection_routes {
    (
        $noun:literal, $collection:ident, $entity:ty, $id:ty,
        history: $history:ident, restore: $restore:ident, bulk: $bulk:ident
    ) => {
        /// The change history of one object, newest first (IPAM-09).
        #[utoipa::path(
            get,
            path = concat!("/", stringify!($collection), "/{id}/history"),
            tag = "common",
            operation_id = stringify!($history),
            summary = concat!("Get the change history of one ", $noun),
            params(
                ("id" = String, Path, description = concat!("Identifier of the ", $noun)),
                PageParams
            ),
            responses(
                (status = 200, description = "History entries, newest first", body = Page<HistoryEntry>),
                (status = 400, description = "Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 404, description = "No such object (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
            )
        )]
        async fn $history(
            State(app): State<AppState>,
            Ctx(cx): Ctx,
            Ipam(ipam): Ipam,
            IpamPath(id): IpamPath<$id>,
            filters: Filters,
        ) -> Result<Json<Page<HistoryEntry>>, ApiError> {
            history_of(&app, &cx, &ipam, id.into(), &filters).await
        }

        /// Restores a soft-deleted object (IPAM-09), with the objects deleted together
        /// with it.
        #[utoipa::path(
            post,
            path = concat!("/", stringify!($collection), "/{id}/restore"),
            tag = "common",
            operation_id = stringify!($restore),
            summary = concat!("Restore one deleted ", $noun),
            params(
                ("id" = String, Path, description = concat!("Identifier of the ", $noun)),
                WriteParams,
                IfMatch
            ),
            responses(
                (status = 200, description = "The restored object, or the plan of a dry run", body = WriteResponse<$entity>),
                (status = 404, description = "No such object (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 409, description = "Not deleted, or a conflict (`ipam.not_deleted`, `ipam.name_taken`, `ipam.address.duplicate`, `ipam.prefix.overlap`)", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 412, description = "If-Match is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
            )
        )]
        async fn $restore(
            State(app): State<AppState>,
            Ctx(cx): Ctx,
            Ipam(ipam): Ipam,
            IpamPath(id): IpamPath<$id>,
            headers: HeaderMap,
            filters: Filters,
        ) -> Result<Response, ApiError> {
            restore_of::<$entity>(&app, &cx, &ipam, id.into(), &headers, &filters).await
        }

        /// Applies several operations of this collection in one plan: all or nothing
        /// (API-04).
        #[utoipa::path(
            post,
            path = concat!("/", stringify!($collection), "/bulk"),
            tag = "common",
            operation_id = stringify!($bulk),
            summary = concat!("Change several ", stringify!($collection), " in one request"),
            params(WriteParams, IdempotencyKeyHeader),
            request_body = BulkRequest,
            responses(
                (status = 200, description = "The committed change, or the plan of a dry run", body = BulkResponse),
                (status = 400, description = "Invalid operation (`ipam.validation`, `ipam.bulk.wrong_collection`)", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 409, description = "A conflict (`ipam.*`)", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 413, description = "Too many operations (`ipam.bulk.too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
            )
        )]
        async fn $bulk(
            State(app): State<AppState>,
            Ctx(cx): Ctx,
            Ipam(ipam): Ipam,
            filters: Filters,
            IpamJson(request): IpamJson<BulkRequest>,
        ) -> Result<Response, ApiError> {
            bulk_of(&app, &cx, &ipam, <$entity as Entity>::KIND, request, &filters).await
        }
    };
}

collection_routes! {
    "tenant", tenants, Tenant, TenantId,
    history: get_tenant_history, restore: restore_tenant, bulk: bulk_tenants
}
collection_routes! {
    "VRF", vrfs, Vrf, VrfId,
    history: get_vrf_history, restore: restore_vrf, bulk: bulk_vrfs
}
collection_routes! {
    "site", sites, Site, SiteId,
    history: get_site_history, restore: restore_site, bulk: bulk_sites
}
collection_routes! {
    "VLAN", vlans, Vlan, tenko_core::VlanId,
    history: get_vlan_history, restore: restore_vlan, bulk: bulk_vlans
}
collection_routes! {
    "prefix", prefixes, Prefix, PrefixId,
    history: get_prefix_history, restore: restore_prefix, bulk: bulk_prefixes
}
collection_routes! {
    "range", ranges, Range, tenko_core::RangeId,
    history: get_range_history, restore: restore_range, bulk: bulk_ranges
}
collection_routes! {
    "address", addresses, Address, tenko_core::AddressId,
    history: get_address_history, restore: restore_address, bulk: bulk_addresses
}
collection_routes! {
    "host", hosts, Host, tenko_core::HostId,
    history: get_host_history, restore: restore_host, bulk: bulk_hosts
}
collection_routes! {
    "interface", interfaces, Interface, InterfaceId,
    history: get_interface_history, restore: restore_interface, bulk: bulk_interfaces
}

// ===== tags, custom fields and search ===================================================

/// Lists the tags in use with how many live objects carry them (IPAM-08).
#[utoipa::path(
    get,
    path = "/tags",
    tag = "common",
    operation_id = "list_tags",
    summary = "List the tags in use",
    params(ReadParams),
    responses(
        (status = 200, description = "Tags with their use counts", body = ListBody<TagCount>),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_tags(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<ListBody<TagCount>>, ApiError> {
    filters.only(&[])?;
    let view = ipam.view(filters.page()?.at_least.map(Revision)).await?;
    // Count only the objects of kinds the principal may read.
    let items = query::tags(view.as_ref())?
        .into_iter()
        .filter_map(|mut tag| {
            tag.by_kind.retain(|kind, _| {
                kind.parse::<ObjectKind>()
                    .is_ok_and(|kind| may_read_kind(&app, &cx, kind))
            });
            tag.count = tag.by_kind.values().sum();
            (tag.count > 0).then_some(tag)
        })
        .collect();
    Ok(Json(ListBody {
        items,
        revision: view.revision(),
    }))
}

/// Lists the custom field definitions (IPAM-08), by key.
#[utoipa::path(
    get,
    path = "/custom-fields",
    tag = "common",
    operation_id = "list_custom_fields",
    summary = "List custom field definitions",
    params(ReadParams),
    responses(
        (status = 200, description = "The definitions, by key", body = ListBody<CustomFieldDef>),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_custom_fields(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<ListBody<CustomFieldDef>>, ApiError> {
    filters.only(&[])?;
    let view = ipam.view(filters.page()?.at_least.map(Revision)).await?;
    if !may_read_kind(&app, &cx, ObjectKind::CustomField) {
        return Ok(Json(ListBody {
            items: Vec::new(),
            revision: view.revision(),
        }));
    }
    Ok(Json(ListBody {
        items: query::custom_fields(view.as_ref())?,
        revision: view.revision(),
    }))
}

/// Plans or applies one custom field command and answers the definition by key.
async fn write_custom_field(
    ipam: &IpamService,
    cx: &RequestCtx,
    command: IpamCommand,
    key: &FieldKey,
    args: &WriteArgs,
    created: bool,
) -> Result<Response, ApiError> {
    if args.dry_run {
        let plan = ipam.preview(&[command], cx, &args.options, None).await?;
        let item = plan.changes.last().and_then(|change| match &change.after {
            Some(tenko_ipam::IpamObject::CustomField(def)) => Some(def.clone()),
            _ => None,
        });
        let body = WriteResponse {
            item,
            revision: None,
            job_id: None,
            dry_run: true,
            replayed: plan.replay.is_some(),
            warnings: plan.warnings.clone(),
            plan: Some(plan.view()),
        };
        return Ok(Json(body).into_response());
    }
    let applied = ipam.execute(&[command], cx, &args.options).await?;
    let view = ipam.view(Some(applied.revision)).await?;
    let found = query::custom_field(view.as_ref(), key).ok();
    let body = WriteResponse {
        item: found.as_ref().map(|(def, _)| def.clone()),
        revision: Some(applied.revision),
        job_id: applied.job_id,
        dry_run: false,
        replayed: applied.replayed,
        warnings: applied.warnings,
        plan: None,
    };
    let status = if created && !applied.replayed {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let response = (status, Json(body)).into_response();
    Ok(match found {
        Some((_, revision)) => with_etag(response, revision),
        None => response,
    })
}

/// Creates a custom field definition (IPAM-08).
#[utoipa::path(
    post,
    path = "/custom-fields",
    tag = "common",
    operation_id = "create_custom_field",
    summary = "Create a custom field definition",
    params(WriteParams, IdempotencyKeyHeader),
    request_body = CustomFieldInput,
    responses(
        (status = 201, description = "The new definition", body = WriteResponse<CustomFieldDef>),
        (status = 200, description = "The plan of a dry run, or a replayed request", body = WriteResponse<CustomFieldDef>),
        (status = 400, description = "Invalid definition (`ipam.custom_field.invalid_definition`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The key exists (`ipam.name_taken`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_custom_field(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
    IpamJson(input): IpamJson<CustomFieldInput>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    authorize(
        &app,
        &cx,
        Action::Administer,
        new_of(ObjectKind::CustomField),
    )?;
    let key = input.key.clone();
    write_custom_field(
        &ipam,
        &cx,
        IpamCommand::CreateCustomField(input),
        &key,
        &args,
        true,
    )
    .await
}

/// The key of a custom field in the path, or 400 `sys.invalid_request` like any other
/// malformed path parameter ([`IpamPath`]).
fn field_key(raw: &str) -> Result<FieldKey, ApiError> {
    FieldKey::new(raw).map_err(|error| {
        ApiError::from_coded_error(
            CodedError::new(
                tenko_core::error::codes::INVALID_REQUEST,
                400,
                error.to_string(),
            )
            .with_param("part", "path"),
        )
    })
}

/// Shows one custom field definition.
#[utoipa::path(
    get,
    path = "/custom-fields/{key}",
    tag = "common",
    operation_id = "get_custom_field",
    summary = "Get one custom field definition",
    params(("key" = String, Path, description = "Key of the custom field"), ReadParams),
    responses(
        (status = 200, description = "The definition, with `ETag`", body = CustomFieldDef),
        (status = 404, description = "No such field (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_custom_field(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(key): IpamPath<String>,
    filters: Filters,
) -> Result<Response, ApiError> {
    let key = field_key(&key)?;
    filters.only(&[])?;
    let view = ipam.view(filters.page()?.at_least.map(Revision)).await?;
    let (def, revision) = query::custom_field(view.as_ref(), &key)?;
    authorize(&app, &cx, Action::Read, def.id.into())?;
    Ok(with_etag(Json(def).into_response(), revision))
}

/// Changes a custom field definition: kind (a select may only gain options while values
/// exist), object kinds and the required flag.
#[utoipa::path(
    patch,
    path = "/custom-fields/{key}",
    tag = "common",
    operation_id = "update_custom_field",
    summary = "Update a custom field definition",
    params(("key" = String, Path, description = "Key of the custom field"), WriteParams, IfMatch),
    request_body = CustomFieldPatch,
    responses(
        (status = 200, description = "The changed definition, or the plan of a dry run", body = WriteResponse<CustomFieldDef>),
        (status = 400, description = "Invalid definition (`ipam.custom_field.invalid_definition`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such field (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Incompatible change (`ipam.custom_field.incompatible_change`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "If-Match is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_custom_field(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(key): IpamPath<String>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(patch): IpamJson<CustomFieldPatch>,
) -> Result<Response, ApiError> {
    let key = field_key(&key)?;
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize(
        &app,
        &cx,
        Action::Administer,
        new_of(ObjectKind::CustomField),
    )?;
    let command = IpamCommand::UpdateCustomField(UpdateCustomField {
        key: key.clone(),
        expected,
        patch,
    });
    write_custom_field(&ipam, &cx, command, &key, &args, false).await
}

/// Removes a custom field definition that no object uses.
#[utoipa::path(
    delete,
    path = "/custom-fields/{key}",
    tag = "common",
    operation_id = "delete_custom_field",
    summary = "Delete a custom field definition",
    params(("key" = String, Path, description = "Key of the custom field"), WriteParams, IfMatch),
    responses(
        (status = 200, description = "Removed (`item` is null), or the plan of a dry run", body = WriteResponse<CustomFieldDef>),
        (status = 404, description = "No such field (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Objects still use the field (`ipam.in_use`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "If-Match is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_custom_field(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(key): IpamPath<String>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let key = field_key(&key)?;
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize(
        &app,
        &cx,
        Action::Administer,
        new_of(ObjectKind::CustomField),
    )?;
    let command = IpamCommand::DeleteCustomField {
        key: key.clone(),
        expected,
    };
    write_custom_field(&ipam, &cx, command, &key, &args, false).await
}

/// The query of `GET /search` (documentation).
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
struct SearchParams {
    /// Search text: an address, a network, a name, a DNS name, a MAC address or words of
    /// a description.
    q: String,
    /// Most hits, 1 to 1,000. The default is 100.
    limit: Option<usize>,
    /// Read at least at this store revision.
    at_least: Option<u64>,
}

/// Searches prefixes, addresses and hosts (and interfaces, VLANs, sites, VRFs and tenants
/// by name). An address finds its address objects and the most specific prefix per VRF; a
/// network finds the prefixes inside it.
#[utoipa::path(
    get,
    path = "/search",
    tag = "common",
    operation_id = "search",
    summary = "Search prefixes, addresses and hosts",
    params(SearchParams),
    responses(
        (status = 200, description = "Hits, prefixes first", body = ListBody<SearchHit>),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn search(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<ListBody<SearchHit>>, ApiError> {
    filters.only(&["q"])?;
    let q = filters.get("q")?.unwrap_or_default().to_owned();
    let page = filters.page()?;
    let view = ipam.view(page.at_least.map(Revision)).await?;
    let readable: BTreeSet<ObjectKind> = tenko_ipam::object::IPAM_KINDS
        .into_iter()
        .filter(|kind| may_read_kind(&app, &cx, *kind))
        .collect();
    // The domain filters before it counts, so `limit` caps readable hits only.
    let items = query::search(view.as_ref(), &q, Some(page.limit()?), |kind| {
        readable.contains(&kind)
    })?;
    Ok(Json(ListBody {
        items,
        revision: view.revision(),
    }))
}

/// Route tests of the common area: change history, restore, bulk changes, tags, custom
/// fields and search, driven through the router over a fresh in-memory store. Test data
/// stays in the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, MAC
/// addresses 00-00-5E-00-53-xx and names under `example.test`).
#[cfg(test)]
mod tests {
    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::Request,
    };
    use serde_json::{Value, json};
    use tenko_core::{Authorizer, Denied, DenyReason, Principal, SystemComponent};
    use tenko_ipam::{DirectJobs, IpamConfig};
    use tenko_store::{MemStore, Store};
    use tower::ServiceExt;

    use super::super::tenancy::testkit::{Policy, Reply, ip4, label, unknown_id};
    use super::*;
    use crate::API_BASE;

    /// The nine collections with the kind name their objects and problems carry.
    const COLLECTIONS: [(&str, &str); 9] = [
        ("tenants", "tenant"),
        ("vrfs", "vrf"),
        ("sites", "site"),
        ("vlans", "vlan"),
        ("prefixes", "prefix"),
        ("ranges", "range"),
        ("addresses", "address"),
        ("hosts", "host"),
        ("interfaces", "interface"),
    ];

    /// A MAC address of the documentation range.
    const MAC: &str = "00-00-5E-00-53-01";

    const INCOMPATIBLE_CHANGE: &str = "ipam.custom_field.incompatible_change";
    const INVALID_DEFINITION: &str = "ipam.custom_field.invalid_definition";

    // ----- harness ---------------------------------------------------------------------

    /// The routes of the area under the API base, over `state`.
    fn router(state: AppState) -> Router {
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        router.with_state(state)
    }

    /// A service over a store of its own.
    fn service(config: IpamConfig) -> Arc<IpamService> {
        let store = Arc::new(MemStore::default()) as Arc<dyn Store>;
        let jobs = Arc::new(DirectJobs::new(Arc::clone(&store)));
        IpamService::new(store, jobs, config).expect("IPAM service")
    }

    /// The router under test with the IPAM service behind it.
    struct Api {
        router: Router,
        service: Arc<IpamService>,
    }

    impl Api {
        /// An API without authorizer: every check passes.
        fn new() -> Self {
            Self::over(service(IpamConfig::default()), AppState::default())
        }

        fn over(service: Arc<IpamService>, state: AppState) -> Self {
            Self {
                router: router(state).layer(Extension(Arc::clone(&service))),
                service,
            }
        }

        /// An API whose service allows at most `max_commands` commands per request.
        fn limited(max_commands: usize) -> Self {
            let config = IpamConfig {
                max_commands,
                ..IpamConfig::default()
            };
            Self::over(service(config), AppState::default())
        }

        /// An API that was started without the IPAM service.
        fn unavailable() -> Self {
            Self {
                router: router(AppState::default()),
                service: service(IpamConfig::default()),
            }
        }

        /// Another router over the same service whose checks go through `authorizer`.
        fn guarded<A: Authorizer + 'static>(&self, authorizer: &Arc<A>) -> Self {
            let authorizer: Arc<dyn Authorizer> = Arc::<A>::clone(authorizer);
            let state = AppState {
                authorizer: Some(authorizer),
                ..AppState::default()
            };
            Self::over(Arc::clone(&self.service), state)
        }

        async fn send(
            &self,
            method: &str,
            path: &str,
            headers: &[(&str, &str)],
            body: Option<(&str, String)>,
        ) -> Reply {
            let mut builder = Request::builder()
                .method(method)
                .uri(format!("{API_BASE}{path}"));
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            let body = match body {
                Some((content_type, text)) => {
                    builder = builder.header(header::CONTENT_TYPE, content_type);
                    Body::from(text)
                }
                None => Body::empty(),
            };
            let response = self
                .router
                .clone()
                .oneshot(builder.body(body).expect("request"))
                .await
                .expect("response");
            let status = response.status();
            let text_of = |name| {
                response
                    .headers()
                    .get(name)
                    .map(|value| value.to_str().expect("header text").to_owned())
            };
            let content_type = text_of(header::CONTENT_TYPE).unwrap_or_default();
            let etag = text_of(header::ETAG);
            let bytes = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            let body = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes)
                    .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
            };
            Reply {
                status,
                content_type,
                etag,
                body,
            }
        }

        async fn get(&self, path: &str) -> Reply {
            self.send("GET", path, &[], None).await
        }

        async fn post(&self, path: &str, body: &Value) -> Reply {
            self.post_with(path, &[], body).await
        }

        async fn post_with(&self, path: &str, headers: &[(&str, &str)], body: &Value) -> Reply {
            let body = ("application/json", body.to_string());
            self.send("POST", path, headers, Some(body)).await
        }

        async fn post_empty(&self, path: &str, headers: &[(&str, &str)]) -> Reply {
            self.send("POST", path, headers, None).await
        }

        /// `POST` of a body that is not necessarily JSON.
        async fn post_raw(&self, path: &str, content_type: &str, text: &str) -> Reply {
            let body = Some((content_type, text.to_owned()));
            self.send("POST", path, &[], body).await
        }

        async fn patch(&self, path: &str, body: &Value) -> Reply {
            let body = ("application/json", body.to_string());
            self.send("PATCH", path, &[], Some(body)).await
        }

        async fn delete(&self, path: &str) -> Reply {
            self.send("DELETE", path, &[], None).await
        }

        /// Walks a list page by page with `limit`; every page but the last has a cursor.
        async fn pages(&self, path: &str, limit: usize) -> Vec<Reply> {
            let mut next = format!("{path}?limit={limit}");
            let mut pages = Vec::new();
            loop {
                assert!(pages.len() < 20, "the cursor never ends");
                let reply = self.get(&next).await;
                reply.assert_json(200);
                let cursor = reply.body["next_cursor"].as_str().map(str::to_owned);
                pages.push(reply);
                match cursor {
                    Some(cursor) => next = format!("{path}?limit={limit}&cursor={cursor}"),
                    None => return pages,
                }
            }
        }

        /// Runs commands (`{ "op", "args" }` documents) on the service, bypassing the HTTP
        /// layer, and returns the primary object of each.
        async fn run(&self, commands: &[Value]) -> Vec<ObjectRef> {
            let commands: Vec<IpamCommand> = commands
                .iter()
                .map(|command| serde_json::from_value(command.clone()).expect("command"))
                .collect();
            let cx = RequestCtx::system(SystemComponent::Api);
            self.service
                .execute(&commands, &cx, &PlanOptions::default())
                .await
                .expect("setup commands")
                .results
        }

        /// Runs one command and returns its object.
        async fn make(&self, command: Value) -> ObjectRef {
            self.run(&[command]).await[0]
        }

        /// Soft-deletes an object on the service.
        async fn remove(&self, object: ObjectRef, cascade: bool) {
            let args = json!({ "object": object, "cascade": cascade });
            self.make(op("delete", args)).await;
        }

        /// The stored object, deleted or not.
        async fn stored<T: Entity>(&self, object: ObjectRef) -> T {
            let view = self.service.view(None).await.expect("view");
            query::get::<T>(view.as_ref(), object.id.into()).expect("stored object")
        }

        /// The revision of the store.
        fn revision(&self) -> u64 {
            self.service.store().status().revision.0
        }

        /// One live object of each collection, in the order of [`COLLECTIONS`]; none of
        /// them is referenced by another, so each can be deleted and restored on its own.
        async fn world(&self) -> Vec<ObjectRef> {
            let network = self.make(prefix_op("192.0.2.0/24")).await;
            let range = json!({ "prefix": network.id, "first": ip4(100), "last": ip4(199) });
            let range = op("create_range", with(range, json!({ "role": "dhcp_pool" })));
            let host = self.make(host_op(2)).await;
            let interface = json!({ "host": host.id, "name": "eth0", "mac": MAC });
            vec![
                self.make(tenant_op(1)).await,
                self.make(op("create_vrf", json!({ "name": label("vrf", 1) })))
                    .await,
                self.make(op("create_site", json!({ "name": label("site", 1) })))
                    .await,
                self.make(op(
                    "create_vlan",
                    json!({ "vid": 100, "name": label("vlan", 1) }),
                ))
                .await,
                self.make(prefix_op("198.51.100.0/24")).await,
                self.make(range).await,
                self.make(op("create_address", json!({ "ip": ip4(10) })))
                    .await,
                self.make(host_op(1)).await,
                self.make(op("create_interface", interface)).await,
            ]
        }
    }

    /// A command document.
    fn op(name: &str, args: Value) -> Value {
        let mut command = json!({ "op": name });
        command["args"] = args;
        command
    }

    /// `base` with the members of `extra` added.
    fn with(mut base: Value, extra: Value) -> Value {
        let (Some(members), Value::Object(extra)) = (base.as_object_mut(), extra) else {
            panic!("members must be objects");
        };
        members.extend(extra);
        base
    }

    fn tenant_op(n: usize) -> Value {
        op("create_tenant", json!({ "name": label("tenant", n) }))
    }

    fn host_op(n: usize) -> Value {
        op("create_host", json!({ "name": label("host", n) }))
    }

    fn prefix_op(cidr: &str) -> Value {
        op("create_prefix", json!({ "cidr": cidr }))
    }

    /// The body of a bulk request.
    fn bulk(operations: &[Value]) -> Value {
        json!({ "operations": operations })
    }

    /// The objects named in the `results` of a bulk answer.
    fn results(reply: &Reply) -> Vec<ObjectRef> {
        serde_json::from_value(reply.body["results"].clone()).expect("results")
    }

    /// The body of a text field that applies to prefixes and addresses.
    fn text_field(key: &str) -> Value {
        json!({ "key": key, "kind": { "type": "text" }, "applies_to": ["prefix", "address"] })
    }

    /// The body of a select field of addresses.
    fn tier_field(options: &[&str]) -> Value {
        json!({ "key": "tier", "kind": select(options), "applies_to": ["address"] })
    }

    fn select(options: &[&str]) -> Value {
        json!({ "type": "select", "options": options })
    }

    /// Asserts the answer of an applied custom field write and returns its definition.
    fn assert_field_write(reply: &Reply, status: u16) -> &Value {
        reply.assert_json(status);
        let body = &reply.body;
        let revision = body["revision"].as_u64().expect("revision");
        assert!(revision > 0 && body["job_id"].is_string(), "{body}");
        assert_eq!(body["dry_run"], false, "{body}");
        assert_eq!(body["replayed"], false, "{body}");
        assert_eq!(body["plan"], Value::Null, "{body}");
        assert!(body["warnings"].is_array(), "{body}");
        let etag = format!("\"{revision}\"");
        assert_eq!(reply.etag.as_deref(), Some(etag.as_str()), "{body}");
        &body["item"]
    }

    /// An authorizer that lets the principal read the listed kinds and nothing else.
    struct ReadsOnly(&'static [ObjectKind]);

    impl Authorizer for ReadsOnly {
        fn check(
            &self,
            _principal: &Principal,
            action: Action,
            object: &ObjectRef,
        ) -> Result<(), Denied> {
            if action == Action::Read && self.0.contains(&object.kind) {
                Ok(())
            } else {
                Err(Denied {
                    action,
                    object: *object,
                    reason: DenyReason::MissingPermission,
                })
            }
        }

        fn scope(&self, _principal: &Principal, action: Action, kind: ObjectKind) -> ScopeFilter {
            if action == Action::Read && self.0.contains(&kind) {
                ScopeFilter::All
            } else {
                ScopeFilter::Nothing
            }
        }
    }

    // ----- history ---------------------------------------------------------------------

    #[tokio::test]
    async fn history_lists_the_changes_of_an_object_newest_first() {
        let api = Api::new();
        let tenant = api.make(tenant_op(1)).await;
        let patch = json!({ "id": tenant.id, "patch": { "name": label("tenant", 2) } });
        api.make(op("update_tenant", patch)).await;
        api.remove(tenant, false).await;
        api.make(op("restore", json!({ "object": tenant }))).await;
        let reply = api.get(&format!("/tenants/{}/history", tenant.id)).await;
        reply.assert_json(200);
        assert_eq!(
            reply.texts("action"),
            ["restore", "delete", "update", "create"]
        );
        assert_eq!(reply.body["next_cursor"], Value::Null);
        assert_eq!(reply.body["revision"], api.revision());
        let revisions: Vec<u64> = reply
            .items()
            .iter()
            .map(|entry| entry["revision"].as_u64().expect("revision"))
            .collect();
        assert!(revisions[3] > 0, "{revisions:?}");
        assert!(
            revisions.windows(2).all(|pair| pair[0] > pair[1]),
            "{revisions:?}"
        );
        for entry in reply.items() {
            assert_eq!(entry["object"], json!(tenant));
            assert!(
                entry["at"].is_string() && entry["by"].is_object(),
                "{entry}"
            );
        }
        let change =
            json!({ "field": "name", "old": label("tenant", 1), "new": label("tenant", 2) });
        assert_eq!(reply.items()[2]["changes"], json!([change]));
        assert_eq!(reply.items()[3]["before"], Value::Null);
        assert_eq!(
            reply.items()[3]["after"]["data"]["name"],
            label("tenant", 1)
        );
    }

    #[tokio::test]
    async fn history_of_a_deleted_object_is_still_readable() {
        let api = Api::new();
        let prefix = api.make(prefix_op("192.0.2.0/24")).await;
        api.remove(prefix, false).await;
        let reply = api.get(&format!("/prefixes/{}/history", prefix.id)).await;
        reply.assert_json(200);
        assert_eq!(reply.texts("action"), ["delete", "create"]);
        assert!(reply.items()[0]["after"]["data"]["meta"]["deleted"].is_object());
    }

    #[tokio::test]
    async fn history_pages_by_limit_and_cursor() {
        let api = Api::new();
        let tenant = api.make(tenant_op(1)).await;
        for n in 2..=4 {
            let patch = json!({ "id": tenant.id, "patch": { "name": label("tenant", n) } });
            api.make(op("update_tenant", patch)).await;
        }
        let path = format!("/tenants/{}/history", tenant.id);
        let whole = api.get(&path).await;
        whole.assert_json(200);
        assert_eq!(whole.items().len(), 4);

        let single = api.pages(&path, 1).await;
        assert_eq!(single.len(), 4);
        let walked: Vec<Value> = single
            .iter()
            .flat_map(|page| page.items().to_vec())
            .collect();
        assert_eq!(walked, whole.items());
        assert_eq!(single[3].body["next_cursor"], Value::Null);

        let by_three = api.pages(&path, 3).await;
        let sizes: Vec<usize> = by_three.iter().map(|page| page.items().len()).collect();
        assert_eq!(sizes, [3, 1]);
    }

    #[tokio::test]
    async fn a_history_cursor_of_another_object_is_refused() {
        let api = Api::new();
        let mut paths = Vec::new();
        for n in 1..=2 {
            let tenant = api.make(tenant_op(n)).await;
            let patch = json!({ "id": tenant.id, "patch": { "description": "changed" } });
            api.make(op("update_tenant", patch)).await;
            paths.push(format!("/tenants/{}/history", tenant.id));
        }
        let page = api.get(&format!("{}?limit=1", paths[0])).await;
        let cursor = page.body["next_cursor"].as_str().expect("cursor");
        api.get(&format!("{}?cursor={cursor}", paths[0]))
            .await
            .assert_json(200);
        api.get(&format!("{}?cursor={cursor}", paths[1]))
            .await
            .assert_problem(400, "sys.invalid_cursor");
        api.get(&format!("{}?cursor=not-a-cursor", paths[0]))
            .await
            .assert_problem(400, "sys.invalid_cursor");
    }

    #[tokio::test]
    async fn history_refuses_bad_paging_and_unknown_parameters() {
        let api = Api::new();
        let tenant = api.make(tenant_op(1)).await;
        for query in [
            "limit=0",
            "limit=1001",
            "limit=many",
            "limit=1&limit=2",
            "sort=name",
            "x=1",
        ] {
            let reply = api
                .get(&format!("/tenants/{}/history?{query}", tenant.id))
                .await;
            reply.assert_problem(400, "sys.invalid_query");
        }
    }

    #[tokio::test]
    async fn history_and_restore_of_an_unknown_object_are_404() {
        let api = Api::new();
        let tenant = api.make(tenant_op(1)).await;
        for (collection, kind) in COLLECTIONS {
            let id = unknown_id();
            let history = api.get(&format!("/{collection}/{id}/history")).await;
            let restore = api
                .post_empty(&format!("/{collection}/{id}/restore"), &[])
                .await;
            for reply in [history, restore] {
                reply.assert_problem(404, "ipam.not_found");
                assert_eq!(reply.body["params"]["kind"], kind);
                assert_eq!(reply.body["params"]["id"], id);
            }
        }
        // The identifier of a tenant is no VRF.
        let wrong = api.get(&format!("/vrfs/{}/history", tenant.id)).await;
        wrong.assert_problem(404, "ipam.not_found");
    }

    #[tokio::test]
    async fn a_malformed_identifier_in_the_path_is_a_problem_document() {
        let api = Api::new();
        for (collection, _) in COLLECTIONS {
            let history = api.get(&format!("/{collection}/not-a-uuid/history")).await;
            let restore = api
                .post_empty(&format!("/{collection}/not-a-uuid/restore"), &[])
                .await;
            for reply in [history, restore] {
                reply.assert_problem(400, "sys.invalid_request");
                assert_eq!(reply.body["params"]["part"], "path");
            }
        }
    }

    // ----- restore ---------------------------------------------------------------------

    #[tokio::test]
    async fn restore_brings_back_a_deleted_object_of_every_collection() {
        let api = Api::new();
        for ((collection, _), object) in COLLECTIONS.into_iter().zip(api.world().await) {
            api.remove(object, false).await;
            let deleted_at = api.revision();
            let path = format!("/{collection}/{}/restore", object.id);
            let reply = api.post_empty(&path, &[]).await;
            reply.assert_write(200);
            assert_eq!(reply.item_id(), object.id.to_string(), "{collection}");
            assert_eq!(reply.item()["meta"]["deleted"], Value::Null, "{collection}");
            assert_eq!(reply.revision(), deleted_at + 1, "{collection}");
            let history = api
                .get(&format!("/{collection}/{}/history", object.id))
                .await;
            assert_eq!(
                history.texts("action"),
                ["restore", "delete", "create"],
                "{collection}"
            );
            assert_eq!(
                history.items()[0]["revision"],
                reply.revision(),
                "{collection}"
            );
        }
    }

    #[tokio::test]
    async fn restore_of_a_live_object_is_a_409() {
        let api = Api::new();
        for ((collection, kind), object) in COLLECTIONS.into_iter().zip(api.world().await) {
            let before = api.revision();
            let reply = api
                .post_empty(&format!("/{collection}/{}/restore", object.id), &[])
                .await;
            reply.assert_problem(409, "ipam.not_deleted");
            assert_eq!(reply.body["params"]["kind"], kind);
            assert_eq!(reply.body["params"]["id"], object.id.to_string());
            assert_eq!(api.revision(), before, "{collection}");
        }
    }

    #[tokio::test]
    async fn restore_checks_if_match() {
        let api = Api::new();
        let tenant = api.make(tenant_op(1)).await;
        let created = api.stored::<Tenant>(tenant).await.meta.revision.0;
        api.remove(tenant, false).await;
        let deleted = api.stored::<Tenant>(tenant).await.meta.revision.0;
        assert!(deleted > created);
        let path = format!("/tenants/{}/restore", tenant.id);

        let stale = format!("\"{created}\"");
        let reply = api.post_empty(&path, &[("if-match", stale.as_str())]).await;
        reply.assert_problem(412, "ipam.revision_mismatch");
        assert_eq!(reply.body["params"]["expected"], created.to_string());
        assert_eq!(reply.body["params"]["actual"], deleted.to_string());
        let reply = api
            .post_empty(&path, &[("if-match", "not a revision")])
            .await;
        reply.assert_problem(400, "ipam.validation");
        assert_eq!(api.revision(), deleted, "nothing was written");
        assert!(api.stored::<Tenant>(tenant).await.meta.deleted.is_some());

        let current = format!("W/\"{deleted}\"");
        let reply = api
            .post_empty(&path, &[("if-match", current.as_str())])
            .await;
        reply.assert_write(200);
        assert_eq!(reply.item()["meta"]["deleted"], Value::Null);
    }

    #[tokio::test]
    async fn restore_dry_run_returns_the_plan_and_changes_nothing() {
        let api = Api::new();
        let tenant = api.make(tenant_op(1)).await;
        api.remove(tenant, false).await;
        let before = api.revision();
        let path = format!("/tenants/{}/restore?dry_run=true", tenant.id);
        let reply = api.post_empty(&path, &[]).await;
        reply.assert_dry_run();
        assert_eq!(reply.item_id(), tenant.id.to_string());
        assert_eq!(reply.item()["meta"]["deleted"], Value::Null);
        assert_eq!(reply.summary_lines(), ["1 tenant restored"]);
        assert_eq!(
            reply.body["plan"]["summary"]["counts"],
            json!([{ "kind": "tenant", "action": "restore", "count": 1 }])
        );
        assert_eq!(reply.body["plan"]["base_revision"], before);
        assert_eq!(api.revision(), before);
        assert!(api.stored::<Tenant>(tenant).await.meta.deleted.is_some());
        let history = api.get(&format!("/tenants/{}/history", tenant.id)).await;
        assert_eq!(history.texts("action"), ["delete", "create"]);
    }

    #[tokio::test]
    async fn restore_refuses_unknown_parameters() {
        let api = Api::new();
        let tenant = api.make(tenant_op(1)).await;
        api.remove(tenant, false).await;
        for query in ["cascade=true", "dry_run=maybe", "x=1"] {
            let path = format!("/tenants/{}/restore?{query}", tenant.id);
            api.post_empty(&path, &[])
                .await
                .assert_problem(400, "sys.invalid_query");
        }
    }

    #[tokio::test]
    async fn restoring_a_prefix_brings_back_what_was_deleted_with_it() {
        let api = Api::new();
        let prefix = api.make(prefix_op("192.0.2.0/24")).await;
        let range = json!({ "prefix": prefix.id, "first": ip4(100), "last": ip4(199) });
        let range = api
            .make(op(
                "create_range",
                with(range, json!({ "role": "reserved" })),
            ))
            .await;
        let early = api
            .make(op("create_address", json!({ "ip": ip4(9) })))
            .await;
        let late = api
            .make(op("create_address", json!({ "ip": ip4(10) })))
            .await;
        // An address deleted before the prefix is not part of the cascade.
        api.remove(early, false).await;
        api.remove(prefix, true).await;
        assert!(api.stored::<Range>(range).await.meta.is_deleted());
        assert!(api.stored::<Address>(late).await.meta.is_deleted());

        let path = format!("/prefixes/{}/restore", prefix.id);
        let plan = api.post_empty(&format!("{path}?dry_run=true"), &[]).await;
        plan.assert_dry_run();
        assert_eq!(
            plan.summary_lines(),
            [
                "1 address restored",
                "1 prefix restored",
                "1 range restored"
            ]
        );
        let reply = api.post_empty(&path, &[]).await;
        reply.assert_write(200);
        assert_eq!(reply.item()["meta"]["deleted"], Value::Null);
        assert!(!api.stored::<Prefix>(prefix).await.meta.is_deleted());
        assert!(!api.stored::<Range>(range).await.meta.is_deleted());
        assert!(!api.stored::<Address>(late).await.meta.is_deleted());
        assert!(api.stored::<Address>(early).await.meta.is_deleted());
        let history = api.get(&format!("/ranges/{}/history", range.id)).await;
        assert_eq!(history.texts("action"), ["restore", "delete", "create"]);
        assert_eq!(history.items()[0]["revision"], reply.revision());
    }

    #[tokio::test]
    async fn restore_into_a_conflict_is_a_409_and_writes_nothing() {
        let api = Api::new();
        let tenant = api.make(tenant_op(1)).await;
        api.remove(tenant, false).await;
        api.make(tenant_op(1)).await;
        let prefix = api.make(prefix_op("192.0.2.0/24")).await;
        let address = api
            .make(op("create_address", json!({ "ip": ip4(10) })))
            .await;
        api.remove(address, false).await;
        api.make(op("create_address", json!({ "ip": ip4(10) })))
            .await;
        let spare = api.make(prefix_op("198.51.100.0/24")).await;
        api.remove(spare, false).await;
        api.make(prefix_op("198.51.100.0/24")).await;
        let before = api.revision();
        let cases = [
            ("tenants", tenant, "ipam.name_taken"),
            ("addresses", address, "ipam.address.duplicate"),
            ("prefixes", spare, "ipam.prefix.overlap"),
        ];
        for (collection, object, code) in cases {
            let path = format!("/{collection}/{}/restore", object.id);
            api.post_empty(&path, &[]).await.assert_problem(409, code);
        }
        assert_eq!(api.revision(), before);
        assert!(!api.stored::<Prefix>(prefix).await.meta.is_deleted());
    }

    // ----- bulk ------------------------------------------------------------------------

    #[tokio::test]
    async fn bulk_commits_its_operations_together() {
        let api = Api::new();
        let before = api.revision();
        let operations = [tenant_op(1), tenant_op(2), tenant_op(3)];
        let reply = api.post("/tenants/bulk", &bulk(&operations)).await;
        reply.assert_json(200);
        let body = &reply.body;
        assert_eq!(body["dry_run"], false, "{body}");
        assert_eq!(body["replayed"], false, "{body}");
        assert_eq!(body["warnings"], json!([]), "{body}");
        assert_eq!(body["plan"], Value::Null, "{body}");
        assert!(body["job_id"].is_string(), "{body}");
        assert_eq!(reply.revision(), before + 1, "one batch");
        let objects = results(&reply);
        assert_eq!(objects.len(), 3);
        for (n, object) in (1..).zip(objects) {
            assert_eq!(object.kind, ObjectKind::Tenant);
            let tenant = api.stored::<Tenant>(object).await;
            assert_eq!(tenant.name, label("tenant", n), "results are in order");
            assert_eq!(tenant.meta.revision.0, reply.revision());
        }
    }

    #[tokio::test]
    async fn bulk_mixes_creates_updates_deletes_and_restores_of_one_collection() {
        let api = Api::new();
        let kept = api.make(tenant_op(1)).await;
        let doomed = api.make(tenant_op(2)).await;
        let revived = api.make(tenant_op(4)).await;
        api.remove(revived, false).await;
        let before = api.revision();
        let operations = [
            op(
                "update_tenant",
                json!({ "id": kept.id, "patch": { "description": "renamed" } }),
            ),
            tenant_op(3),
            op("delete", json!({ "object": doomed })),
            op("restore", json!({ "object": revived })),
        ];
        let reply = api.post("/tenants/bulk", &bulk(&operations)).await;
        reply.assert_json(200);
        assert_eq!(reply.revision(), before + 1);
        let objects = results(&reply);
        assert_eq!(objects.len(), 4);
        assert_eq!(
            (objects[0], objects[2], objects[3]),
            (kept, doomed, revived)
        );
        let kept = api.stored::<Tenant>(kept).await;
        assert_eq!(kept.meta.description.as_deref(), Some("renamed"));
        assert!(api.stored::<Tenant>(doomed).await.meta.is_deleted());
        assert!(!api.stored::<Tenant>(revived).await.meta.is_deleted());
        assert_eq!(
            api.stored::<Tenant>(objects[1]).await.name,
            label("tenant", 3)
        );
    }

    #[tokio::test]
    async fn bulk_accepts_creates_for_every_collection() {
        let api = Api::new();
        let network = api.make(prefix_op("192.0.2.0/24")).await;
        let host = api.make(host_op(1)).await;
        let range = json!({ "prefix": network.id, "first": ip4(100), "last": ip4(199) });
        let operations = [
            tenant_op(1),
            op("create_vrf", json!({ "name": label("vrf", 1) })),
            op("create_site", json!({ "name": label("site", 1) })),
            op(
                "create_vlan",
                json!({ "vid": 100, "name": label("vlan", 1) }),
            ),
            prefix_op("198.51.100.0/24"),
            op("create_range", with(range, json!({ "role": "dhcp_pool" }))),
            op("create_address", json!({ "ip": ip4(10) })),
            host_op(2),
            op(
                "create_interface",
                json!({ "host": host.id, "name": "eth0", "mac": MAC }),
            ),
        ];
        for ((collection, kind), operation) in COLLECTIONS.into_iter().zip(operations) {
            let reply = api
                .post(&format!("/{collection}/bulk"), &bulk(&[operation]))
                .await;
            reply.assert_json(200);
            let objects = results(&reply);
            assert_eq!(objects.len(), 1, "{collection}");
            assert_eq!(objects[0].kind.as_str(), kind, "{collection}");
            let history = api
                .get(&format!("/{collection}/{}/history", objects[0].id))
                .await;
            assert_eq!(history.texts("action"), ["create"], "{collection}");
            assert_eq!(
                history.items()[0]["revision"],
                reply.revision(),
                "{collection}"
            );
        }
    }

    #[tokio::test]
    async fn bulk_allocates_the_next_free_objects() {
        let api = Api::new();
        let network = api.make(prefix_op("192.0.2.0/24")).await;
        let allocate = op("allocate_address", json!({ "prefix": network.id }));
        let reply = api
            .post("/addresses/bulk", &bulk(&[allocate.clone(), allocate]))
            .await;
        reply.assert_json(200);
        let mut ips = Vec::new();
        for object in results(&reply) {
            ips.push(api.stored::<Address>(object).await.ip.to_string());
        }
        assert_eq!(ips, [ip4(1), ip4(2)]);

        let supernet = json!({ "cidr": "198.51.100.0/24", "role": "supernet" });
        let supernet = api.make(op("create_prefix", supernet)).await;
        let child = op(
            "allocate_prefix",
            json!({ "parent": supernet.id, "length": 26 }),
        );
        let reply = api
            .post("/prefixes/bulk", &bulk(&[child.clone(), child]))
            .await;
        reply.assert_json(200);
        let mut cidrs = Vec::new();
        for object in results(&reply) {
            cidrs.push(api.stored::<Prefix>(object).await.cidr.to_string());
        }
        assert_eq!(cidrs, ["198.51.100.0/26", "198.51.100.64/26"]);
        // An address allocation belongs to the addresses, not to the prefixes.
        let allocate = op("allocate_address", json!({ "prefix": network.id }));
        api.post("/prefixes/bulk", &bulk(&[allocate]))
            .await
            .assert_problem(400, "ipam.bulk.wrong_collection");
    }

    #[tokio::test]
    async fn bulk_needs_the_acknowledgement_of_warnings() {
        let api = Api::new();
        let warning = "ipam.prefix.nibble_boundary";
        let request = bulk(&[prefix_op("2001:db8::/33")]);
        let refused = api.post("/prefixes/bulk", &request).await;
        refused.assert_problem(409, "ipam.plan.unacknowledged");
        assert_eq!(refused.body["params"]["codes"], warning);
        assert_eq!(api.revision(), 0);

        let plan = api.post("/prefixes/bulk?dry_run=true", &request).await;
        plan.assert_json(200);
        assert_eq!(plan.body["warnings"][0]["code"], warning);
        assert_eq!(plan.body["warnings"][0]["acknowledged"], false);
        assert_eq!(
            plan.body["plan"]["summary"]["unacknowledged"],
            json!([warning])
        );

        let path = format!("/prefixes/bulk?acknowledge={warning}");
        let done = api.post(&path, &request).await;
        done.assert_json(200);
        assert_eq!(done.body["warnings"][0]["code"], warning);
        assert_eq!(done.body["warnings"][0]["acknowledged"], true);
        assert!(done.body["job_id"].is_string(), "{}", done.body);
    }

    #[tokio::test]
    async fn bulk_with_a_failing_operation_writes_nothing() {
        let api = Api::new();
        api.make(prefix_op("192.0.2.0/24")).await;
        let before = api.revision();
        let operations = [
            prefix_op("198.51.100.0/24"),
            prefix_op("203.0.113.0/24"),
            prefix_op("192.0.2.0/24"),
        ];
        let reply = api.post("/prefixes/bulk", &bulk(&operations)).await;
        reply.assert_problem(409, "ipam.prefix.overlap");
        assert_eq!(api.revision(), before);
        let found = api.get("/search?q=198.51.100.0/24").await;
        found.assert_json(200).assert_no_items();
    }

    #[tokio::test]
    async fn bulk_refuses_an_operation_of_another_collection() {
        let api = Api::new();
        for (collection, kind) in COLLECTIONS {
            if collection == "tenants" {
                continue;
            }
            let reply = api
                .post(&format!("/{collection}/bulk"), &bulk(&[tenant_op(1)]))
                .await;
            reply.assert_problem(400, "ipam.bulk.wrong_collection");
            assert_eq!(reply.body["params"]["index"], "0", "{collection}");
            assert_eq!(reply.body["params"]["expected"], kind, "{collection}");
        }
        let operations = [tenant_op(1), tenant_op(2), prefix_op("192.0.2.0/24")];
        let reply = api.post("/tenants/bulk", &bulk(&operations)).await;
        reply.assert_problem(400, "ipam.bulk.wrong_collection");
        assert_eq!(reply.body["params"]["index"], "2");
        assert_eq!(reply.body["params"]["expected"], "tenant");
        assert_eq!(api.revision(), 0, "nothing was written");
    }

    #[tokio::test]
    async fn bulk_dry_run_returns_the_plan_and_changes_nothing() {
        let api = Api::new();
        // The first prefix also creates the default tenant and VRF; keep them out of the plan.
        api.make(prefix_op("203.0.113.0/24")).await;
        let before = api.revision();
        let operations = [prefix_op("192.0.2.0/24"), prefix_op("198.51.100.0/24")];
        let reply = api
            .post("/prefixes/bulk?dry_run=true", &bulk(&operations))
            .await;
        reply.assert_json(200);
        let body = &reply.body;
        assert_eq!(body["dry_run"], true, "{body}");
        assert_eq!(body["revision"], Value::Null, "{body}");
        assert_eq!(body["job_id"], Value::Null, "{body}");
        assert_eq!(body["replayed"], false, "{body}");
        assert_eq!(
            body["plan"]["summary"]["counts"],
            json!([{ "kind": "prefix", "action": "create", "count": 2 }])
        );
        assert_eq!(reply.summary_lines(), ["2 prefixes created"]);
        assert_eq!(body["plan"]["base_revision"], before);
        assert_eq!(body["plan"]["results"], body["results"]);
        assert_eq!(results(&reply).len(), 2);
        assert_eq!(api.revision(), before);
        let found = api.get("/search?q=192.0.2.0/24").await;
        found.assert_json(200).assert_no_items();

        let failing = [prefix_op("192.0.2.0/24"), prefix_op("192.0.2.0/24")];
        api.post("/prefixes/bulk?dry_run=true", &bulk(&failing))
            .await
            .assert_problem(409, "ipam.prefix.overlap");
    }

    #[tokio::test]
    async fn bulk_refuses_malformed_bodies_and_parameters() {
        let api = Api::new();
        let bodies = [
            "{",
            "[]",
            "{}",
            r#"{"operations": "all"}"#,
            r#"{"operations": [{"op": "create_nothing", "args": {}}]}"#,
            r#"{"operations": [{"op": "create_tenant", "args": {}}]}"#,
            r#"{"operations": [{"op": "create_tenant", "args": {"name": "a.example.test", "bogus": 1}}]}"#,
        ];
        for text in bodies {
            let reply = api
                .post_raw("/tenants/bulk", "application/json", text)
                .await;
            reply.assert_problem(400, "sys.invalid_request");
            assert_eq!(reply.body["params"]["part"], "body", "{text}");
        }
        api.post_raw("/tenants/bulk", "text/plain", r#"{"operations": []}"#)
            .await
            .assert_problem(415, "sys.invalid_request");
        for query in ["cascade=true", "dry_run=maybe", "x=1"] {
            api.post(&format!("/tenants/bulk?{query}"), &bulk(&[tenant_op(1)]))
                .await
                .assert_problem(400, "sys.invalid_query");
        }
        assert_eq!(api.revision(), 0, "nothing was written");
    }

    #[tokio::test]
    async fn bulk_refuses_more_operations_than_the_service_allows() {
        let api = Api::limited(2);
        let operations = [tenant_op(1), tenant_op(2), tenant_op(3)];
        let reply = api.post("/tenants/bulk", &bulk(&operations)).await;
        reply.assert_problem(413, "ipam.bulk.too_large");
        assert_eq!(reply.body["params"]["count"], "3");
        assert_eq!(reply.body["params"]["limit"], "2");
        api.post("/tenants/bulk", &bulk(&operations[..2]))
            .await
            .assert_json(200);
    }

    #[tokio::test]
    async fn an_empty_bulk_changes_nothing() {
        let api = Api::new();
        let reply = api.post("/tenants/bulk", &bulk(&[])).await;
        reply.assert_json(200);
        assert_eq!(reply.body["results"], json!([]));
        assert_eq!(reply.body["job_id"], Value::Null);
        assert_eq!(api.revision(), 0);
    }

    #[tokio::test]
    async fn bulk_replays_the_first_result_for_a_repeated_idempotency_key() {
        let api = Api::new();
        let key = [("idempotency-key", "bulk-key-1")];
        let operations = [tenant_op(1), tenant_op(2)];
        let first = api
            .post_with("/tenants/bulk", &key, &bulk(&operations))
            .await;
        first.assert_json(200);
        assert_eq!(first.body["replayed"], false);
        let committed = api.revision();

        let again = api
            .post_with("/tenants/bulk", &key, &bulk(&operations))
            .await;
        again.assert_json(200);
        assert_eq!(again.body["replayed"], true, "{}", again.body);
        assert_eq!(again.body["results"], first.body["results"]);
        assert_eq!(again.body["revision"], first.body["revision"]);
        assert_eq!(again.body["job_id"], Value::Null);
        assert_eq!(api.revision(), committed, "the replay writes nothing");

        let other = api
            .post_with("/tenants/bulk", &key, &bulk(&[tenant_op(3)]))
            .await;
        other.assert_problem(422, "ipam.idempotency_mismatch");
        assert_eq!(api.revision(), committed);
    }

    // ----- tags ------------------------------------------------------------------------

    #[tokio::test]
    async fn tags_count_live_objects_per_tag_and_kind() {
        let api = Api::new();
        let empty = api.get("/tags").await;
        empty.assert_json(200).assert_no_items();
        assert_eq!(empty.body["revision"], 0);

        let tenant = api
            .make(op(
                "create_tenant",
                json!({ "name": label("tenant", 1), "tags": ["edge", "lab"] }),
            ))
            .await;
        api.make(op(
            "create_prefix",
            json!({ "cidr": "192.0.2.0/24", "tags": ["edge"] }),
        ))
        .await;
        let address = api
            .make(op(
                "create_address",
                json!({ "ip": ip4(10), "tags": ["edge", "lab"] }),
            ))
            .await;
        let reply = api.get("/tags").await;
        reply.assert_json(200);
        assert_eq!(reply.body["revision"], api.revision());
        let edge = json!({ "tag": "edge", "count": 3, "by_kind": { "address": 1, "prefix": 1, "tenant": 1 } });
        let lab = json!({ "tag": "lab", "count": 2, "by_kind": { "address": 1, "tenant": 1 } });
        assert_eq!(reply.body["items"], json!([edge, lab]));

        // A soft-deleted object stops counting, a restored one counts again.
        api.remove(address, false).await;
        let reply = api.get("/tags").await;
        assert_eq!(reply.texts("count"), ["2", "1"]);
        assert_eq!(
            reply.items()[0]["by_kind"],
            json!({ "prefix": 1, "tenant": 1 })
        );
        api.remove(tenant, false).await;
        let reply = api.get("/tags").await;
        assert_eq!(reply.texts("tag"), ["edge"]);
        assert_eq!(reply.texts("count"), ["1"]);
        api.post_empty(&format!("/tenants/{}/restore", tenant.id), &[])
            .await
            .assert_write(200);
        let reply = api.get("/tags").await;
        assert_eq!(reply.texts("tag"), ["edge", "lab"]);
        assert_eq!(reply.texts("count"), ["2", "1"]);
    }

    #[tokio::test]
    async fn tags_refuse_unknown_parameters() {
        let api = Api::new();
        api.get("/tags?x=1")
            .await
            .assert_problem(400, "sys.invalid_query");
        let at_least = format!("/tags?at_least={}", api.revision());
        api.get(&at_least).await.assert_json(200);
    }

    // ----- custom fields ---------------------------------------------------------------

    #[tokio::test]
    async fn a_created_custom_field_can_be_read_back() {
        let api = Api::new();
        let reply = api.post("/custom-fields", &text_field("owner")).await;
        let item = assert_field_write(&reply, 201);
        assert!(item["id"].is_string(), "{item}");
        assert_eq!(item["key"], "owner");
        assert_eq!(item["kind"], json!({ "type": "text" }));
        assert_eq!(item["applies_to"], json!(["prefix", "address"]));
        assert_eq!(item["required"], false);

        let read = api.get("/custom-fields/owner").await;
        read.assert_json(200);
        assert_eq!(&read.body, item);
        assert_eq!(read.etag, reply.etag);
        api.get("/custom-fields/missing")
            .await
            .assert_problem(404, "ipam.not_found");
        api.get("/custom-fields/owner?x=1")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn custom_fields_are_listed_by_key() {
        let api = Api::new();
        api.get("/custom-fields")
            .await
            .assert_json(200)
            .assert_no_items();
        for key in ["zone", "alpha", "mid"] {
            api.post("/custom-fields", &text_field(key))
                .await
                .assert_json(201);
        }
        let reply = api.get("/custom-fields").await;
        reply.assert_json(200);
        assert_eq!(reply.texts("key"), ["alpha", "mid", "zone"]);
        assert_eq!(reply.body["revision"], api.revision());
    }

    #[tokio::test]
    async fn a_duplicate_custom_field_key_is_a_409() {
        let api = Api::new();
        api.post("/custom-fields", &text_field("owner"))
            .await
            .assert_json(201);
        let before = api.revision();
        api.post("/custom-fields", &text_field("owner"))
            .await
            .assert_problem(409, "ipam.name_taken");
        assert_eq!(api.revision(), before);
    }

    #[tokio::test]
    async fn an_invalid_custom_field_definition_is_a_400() {
        let api = Api::new();
        let base = text_field("owner");
        let invalid = [
            with(base.clone(), json!({ "applies_to": [] })),
            with(base.clone(), json!({ "applies_to": ["prefix", "prefix"] })),
            with(base.clone(), json!({ "applies_to": ["user"] })),
            with(base.clone(), json!({ "kind": select(&[]) })),
            with(base.clone(), json!({ "kind": select(&["a", "a"]) })),
            with(base.clone(), json!({ "kind": select(&[" padded"]) })),
        ];
        for body in invalid {
            api.post("/custom-fields", &body)
                .await
                .assert_problem(400, INVALID_DEFINITION);
        }
        let malformed = [
            with(base.clone(), json!({ "key": "Not A Key" })),
            with(base.clone(), json!({ "kind": { "type": "ip_address" } })),
            with(base.clone(), json!({ "bogus": true })),
            json!({ "key": "owner", "kind": { "type": "text" } }),
        ];
        for body in malformed {
            let reply = api.post("/custom-fields", &body).await;
            reply.assert_problem(400, "sys.invalid_request");
            assert_eq!(reply.body["params"]["part"], "body");
        }
        api.get("/custom-fields").await.assert_no_items();
        assert_eq!(api.revision(), 0);
    }

    #[tokio::test]
    async fn a_custom_field_dry_run_changes_nothing() {
        let api = Api::new();
        let reply = api
            .post("/custom-fields?dry_run=true", &text_field("owner"))
            .await;
        reply.assert_dry_run();
        assert_eq!(reply.item()["key"], "owner");
        assert_eq!(reply.summary_lines(), ["1 custom field created"]);
        assert_eq!(api.revision(), 0);
        api.get("/custom-fields/owner")
            .await
            .assert_problem(404, "ipam.not_found");
    }

    #[tokio::test]
    async fn a_repeated_idempotency_key_replays_a_custom_field_creation() {
        let api = Api::new();
        let key = [("idempotency-key", "field-key-1")];
        let first = api
            .post_with("/custom-fields", &key, &text_field("owner"))
            .await;
        assert_field_write(&first, 201);
        let again = api
            .post_with("/custom-fields", &key, &text_field("owner"))
            .await;
        again.assert_json(200);
        assert_eq!(again.body["replayed"], true, "{}", again.body);
        assert_eq!(again.body["item"], first.body["item"]);
        assert_eq!(api.get("/custom-fields").await.items().len(), 1);
    }

    #[tokio::test]
    async fn a_select_may_gain_options_but_not_lose_one() {
        let api = Api::new();
        api.post("/custom-fields", &tier_field(&["gold", "silver"]))
            .await
            .assert_json(201);
        api.make(prefix_op("192.0.2.0/24")).await;
        let value = json!({ "type": "select", "value": "gold" });
        api.make(op(
            "create_address",
            json!({ "ip": ip4(10), "custom": { "tier": value } }),
        ))
        .await;

        let more = json!({ "kind": select(&["gold", "silver", "bronze"]) });
        let reply = api.patch("/custom-fields/tier", &more).await;
        let item = assert_field_write(&reply, 200);
        assert_eq!(item["kind"], more["kind"]);
        let read = api.get("/custom-fields/tier").await;
        assert_eq!(read.etag, reply.etag);
        let before = api.revision();

        let fewer = json!({ "kind": select(&["silver", "bronze"]) });
        api.patch("/custom-fields/tier", &fewer)
            .await
            .assert_problem(409, INCOMPATIBLE_CHANGE);
        let other_type = json!({ "kind": { "type": "text" } });
        api.patch("/custom-fields/tier", &other_type)
            .await
            .assert_problem(409, INCOMPATIBLE_CHANGE);
        assert_eq!(api.revision(), before);
        assert_eq!(
            api.get("/custom-fields/tier").await.body["kind"],
            more["kind"]
        );
    }

    #[tokio::test]
    async fn a_custom_field_patch_changes_the_flags_and_validates() {
        let api = Api::new();
        api.post("/custom-fields", &text_field("owner"))
            .await
            .assert_json(201);
        let reply = api
            .patch(
                "/custom-fields/owner",
                &json!({ "applies_to": ["host"], "required": true }),
            )
            .await;
        let item = assert_field_write(&reply, 200);
        assert_eq!(item["applies_to"], json!(["host"]));
        assert_eq!(item["required"], true);
        assert_eq!(item["kind"], json!({ "type": "text" }));

        let dry = api
            .patch(
                "/custom-fields/owner?dry_run=true",
                &json!({ "required": false }),
            )
            .await;
        dry.assert_dry_run();
        assert_eq!(dry.item()["required"], false);
        assert_eq!(api.get("/custom-fields/owner").await.body["required"], true);

        api.patch("/custom-fields/owner", &json!({ "applies_to": [] }))
            .await
            .assert_problem(400, INVALID_DEFINITION);
        let unknown_member = api
            .patch("/custom-fields/owner", &json!({ "key": "other" }))
            .await;
        unknown_member.assert_problem(400, "sys.invalid_request");
        api.patch("/custom-fields/missing", &json!({ "required": true }))
            .await
            .assert_problem(404, "ipam.not_found");
    }

    #[tokio::test]
    async fn a_custom_field_in_use_cannot_be_deleted() {
        let api = Api::new();
        api.post("/custom-fields", &text_field("owner"))
            .await
            .assert_json(201);
        let value = json!({ "type": "text", "value": "lab" });
        let custom = json!({ "cidr": "192.0.2.0/24", "custom": { "owner": value } });
        let prefix = api.make(op("create_prefix", custom)).await;

        let refused = api.delete("/custom-fields/owner").await;
        refused.assert_problem(409, "ipam.in_use");
        assert_eq!(refused.body["params"]["by"], "objects");
        assert_eq!(refused.body["params"]["count"], "1");

        let clear = json!({ "id": prefix.id, "patch": { "custom": { "owner": null } } });
        api.make(op("update_prefix", clear)).await;
        let before = api.revision();
        let dry = api.delete("/custom-fields/owner?dry_run=true").await;
        dry.assert_json(200);
        assert_eq!(dry.body["dry_run"], true);
        assert_eq!(api.revision(), before);

        let removed = api.delete("/custom-fields/owner").await;
        removed.assert_json(200);
        assert_eq!(removed.body["item"], Value::Null);
        assert_eq!(removed.revision(), before + 1);
        assert!(removed.body["job_id"].is_string(), "{}", removed.body);
        assert_eq!(removed.etag, None);
        api.get("/custom-fields/owner")
            .await
            .assert_problem(404, "ipam.not_found");
        api.delete("/custom-fields/owner")
            .await
            .assert_problem(404, "ipam.not_found");
        api.get("/custom-fields").await.assert_no_items();
    }

    #[tokio::test]
    async fn an_invalid_custom_field_key_in_the_path_is_a_400() {
        let api = Api::new();
        let too_long = "a".repeat(65);
        for key in [
            "Upper",
            "1st",
            "with-dash",
            "with%20space",
            too_long.as_str(),
        ] {
            let path = format!("/custom-fields/{key}");
            api.get(&path)
                .await
                .assert_problem(400, "sys.invalid_request");
            api.patch(&path, &json!({ "required": true }))
                .await
                .assert_problem(400, "sys.invalid_request");
            api.delete(&path)
                .await
                .assert_problem(400, "sys.invalid_request");
        }
    }

    // ----- search ----------------------------------------------------------------------

    /// Prefixes in two VRFs, an address with a DNS name, a host with an interface and a
    /// MAC address. Returns the second VRF.
    async fn search_world(api: &Api) -> ObjectRef {
        let other = api
            .make(op("create_vrf", json!({ "name": label("vrf", 1) })))
            .await;
        let supernet = json!({ "cidr": "192.0.2.0/24", "role": "supernet" });
        let elsewhere = json!({ "cidr": "192.0.2.0/24", "vrf": other.id });
        api.run(&[
            op("create_prefix", supernet),
            prefix_op("192.0.2.0/25"),
            op("create_prefix", elsewhere),
            prefix_op("198.51.100.0/24"),
            op(
                "create_address",
                json!({ "ip": ip4(10), "dns_name": label("www", 1) }),
            ),
        ])
        .await;
        let host = api.make(host_op(1)).await;
        let interface = json!({ "host": host.id, "name": "eth0", "mac": MAC });
        api.make(op("create_interface", interface)).await;
        other
    }

    /// The `(kind, label)` of each hit of a search answer.
    fn hits(reply: &Reply) -> Vec<(String, String)> {
        reply
            .items()
            .iter()
            .map(|hit| {
                let kind = hit["object"]["kind"].as_str().expect("kind");
                assert_eq!(hit["item"]["kind"], kind, "{hit}");
                (
                    kind.to_owned(),
                    hit["label"].as_str().expect("label").to_owned(),
                )
            })
            .collect()
    }

    fn pair(kind: &str, text: &str) -> (String, String) {
        (kind.to_owned(), text.to_owned())
    }

    #[tokio::test]
    async fn search_by_address_finds_the_address_and_the_most_specific_prefix_per_vrf() {
        let api = Api::new();
        let other = search_world(&api).await;
        let reply = api.get(&format!("/search?q={}", ip4(10))).await;
        reply.assert_json(200);
        assert_eq!(reply.body["revision"], api.revision());
        let mut found = hits(&reply);
        assert_eq!(
            found.pop(),
            Some(pair("address", "192.0.2.10")),
            "prefixes come first"
        );
        found.sort();
        assert_eq!(
            found,
            [
                pair("prefix", "192.0.2.0/24"),
                pair("prefix", "192.0.2.0/25")
            ]
        );
        // The /24 hit is the one of the other VRF, not the supernet of the default VRF.
        let wide = reply
            .items()
            .iter()
            .find(|hit| hit["label"] == "192.0.2.0/24")
            .expect("hit");
        assert_eq!(wide["item"]["data"]["vrf"], other.id.to_string());
        // An address that no object has finds the prefixes only.
        let reply = api.get(&format!("/search?q={}", ip4(77))).await;
        assert_eq!(hits(&reply).len(), 2);
        assert!(hits(&reply).iter().all(|(kind, _)| kind == "prefix"));
    }

    #[tokio::test]
    async fn search_by_network_finds_the_prefixes_inside_it() {
        let api = Api::new();
        search_world(&api).await;
        let reply = api.get("/search?q=192.0.2.0/24").await;
        reply.assert_json(200);
        let mut found = hits(&reply);
        found.sort();
        assert_eq!(
            found,
            [
                pair("prefix", "192.0.2.0/24"),
                pair("prefix", "192.0.2.0/24"),
                pair("prefix", "192.0.2.0/25"),
            ]
        );
        let reply = api.get("/search?q=203.0.113.0/24").await;
        reply.assert_json(200).assert_no_items();
    }

    #[tokio::test]
    async fn search_understands_ipv6() {
        let api = Api::new();
        api.make(op(
            "create_prefix",
            json!({ "cidr": "2001:db8::/32", "role": "supernet" }),
        ))
        .await;
        api.make(prefix_op("2001:db8:1::/48")).await;
        api.make(op("create_address", json!({ "ip": "2001:db8:1::10" })))
            .await;
        let reply = api.get("/search?q=2001:db8:1::10").await;
        let mut found = hits(&reply);
        assert_eq!(found.pop(), Some(pair("address", "2001:db8:1::10")));
        assert_eq!(found, [pair("prefix", "2001:db8:1::/48")]);
        let reply = api.get("/search?q=2001:db8::/32").await;
        let mut found = hits(&reply);
        found.sort();
        assert_eq!(
            found,
            [
                pair("prefix", "2001:db8:1::/48"),
                pair("prefix", "2001:db8::/32")
            ]
        );
    }

    #[tokio::test]
    async fn search_by_name_finds_hosts_addresses_and_other_objects() {
        let api = Api::new();
        search_world(&api).await;
        let host = label("host", 1);
        for q in [host.as_str(), "HOST-01", "ost-01.example"] {
            let reply = api.get(&format!("/search?q={q}")).await;
            assert_eq!(hits(&reply), [pair("host", &host)], "{q}");
        }
        let reply = api.get(&format!("/search?q={}", label("www", 1))).await;
        assert_eq!(hits(&reply), [pair("address", "192.0.2.10")]);
        let reply = api.get(&format!("/search?q={}", label("vrf", 1))).await;
        assert_eq!(hits(&reply), [pair("vrf", &label("vrf", 1))]);
    }

    #[tokio::test]
    async fn search_by_mac_address_finds_the_interface() {
        let api = Api::new();
        search_world(&api).await;
        for q in [
            MAC,
            "00-00-5e-00-53-01",
            "00:00:5e:00:53:01",
            "000.05e0.0530.1",
        ] {
            let reply = api.get(&format!("/search?q={q}")).await;
            assert_eq!(hits(&reply), [pair("interface", "eth0")], "{q}");
        }
        let reply = api.get("/search?q=00-00-5E-00-53-02").await;
        reply.assert_json(200).assert_no_items();
    }

    #[tokio::test]
    async fn search_without_text_finds_nothing() {
        let api = Api::new();
        search_world(&api).await;
        for path in ["/search", "/search?q=", "/search?q=%20%20"] {
            let reply = api.get(path).await;
            reply.assert_json(200).assert_no_items();
            assert_eq!(reply.body["revision"], api.revision(), "{path}");
        }
    }

    #[tokio::test]
    async fn search_limit_caps_the_hits() {
        let api = Api::new();
        for n in 1..=5 {
            api.make(op("create_tenant", json!({ "name": label("lab", n) })))
                .await;
        }
        assert_eq!(api.get("/search?q=lab").await.items().len(), 5);
        assert_eq!(api.get("/search?q=lab&limit=5").await.items().len(), 5);
        let capped = api.get("/search?q=lab&limit=2").await;
        capped.assert_json(200);
        assert_eq!(capped.items().len(), 2);
        let one = api.get("/search?q=lab&limit=1").await;
        assert_eq!(one.items().len(), 1);
        for limit in ["0", "1001", "many", "-1"] {
            api.get(&format!("/search?q=lab&limit={limit}"))
                .await
                .assert_problem(400, "sys.invalid_query");
        }
    }

    #[tokio::test]
    async fn search_limit_counts_only_the_hits_the_principal_may_read() {
        let api = Api::new();
        let network = json!({ "cidr": "192.0.2.0/24", "description": "lab network" });
        api.make(op("create_prefix", network)).await;
        api.make(op("create_host", json!({ "name": label("lab", 1) })))
            .await;
        // Prefixes come first, so a limit of one cuts the host off.
        let all = api.get("/search?q=lab&limit=1").await;
        assert_eq!(hits(&all), [pair("prefix", "192.0.2.0/24")]);

        let hosts_only = api.guarded(&Arc::new(ReadsOnly(&[ObjectKind::Host])));
        let expected = [pair("host", &label("lab", 1))];
        let unlimited = hosts_only.get("/search?q=lab").await;
        assert_eq!(hits(&unlimited), expected);
        let limited = hosts_only.get("/search?q=lab&limit=1").await;
        assert_eq!(
            hits(&limited),
            expected,
            "the limit must apply to readable hits"
        );
    }

    #[tokio::test]
    async fn search_refuses_unknown_and_repeated_parameters() {
        let api = Api::new();
        for query in [
            "q=lab&x=1",
            "q=a&q=b",
            "q=lab&sort=name",
            "q=lab&cursor=x&at_least=x",
        ] {
            api.get(&format!("/search?{query}"))
                .await
                .assert_problem(400, "sys.invalid_query");
        }
        let at_least = format!("/search?q=lab&at_least={}", api.revision());
        api.get(&at_least).await.assert_json(200);
    }

    #[tokio::test]
    async fn search_skips_deleted_objects() {
        let api = Api::new();
        let host = api.make(host_op(1)).await;
        let prefix = api.make(prefix_op("192.0.2.0/24")).await;
        assert_eq!(api.get("/search?q=host-01").await.items().len(), 1);
        api.remove(host, false).await;
        api.remove(prefix, false).await;
        api.get("/search?q=host-01").await.assert_no_items();
        api.get("/search?q=192.0.2.0/24").await.assert_no_items();
        api.get("/search?q=192.0.2.5").await.assert_no_items();
        api.post_empty(&format!("/hosts/{}/restore", host.id), &[])
            .await
            .assert_write(200);
        assert_eq!(api.get("/search?q=host-01").await.items().len(), 1);
    }

    // ----- availability and authorization ----------------------------------------------

    #[tokio::test]
    async fn every_endpoint_answers_503_without_the_ipam_service() {
        let api = Api::unavailable();
        let id = unknown_id();
        let mut requests = Vec::new();
        for (collection, _) in COLLECTIONS {
            requests.push(("GET", format!("/{collection}/{id}/history"), None));
            requests.push(("POST", format!("/{collection}/{id}/restore"), None));
            requests.push(("POST", format!("/{collection}/bulk"), Some(bulk(&[]))));
        }
        requests.extend([
            ("GET", "/tags".to_owned(), None),
            ("GET", "/custom-fields".to_owned(), None),
            (
                "POST",
                "/custom-fields".to_owned(),
                Some(text_field("owner")),
            ),
            ("GET", "/custom-fields/owner".to_owned(), None),
            (
                "PATCH",
                "/custom-fields/owner".to_owned(),
                Some(json!({ "required": true })),
            ),
            ("DELETE", "/custom-fields/owner".to_owned(), None),
            ("GET", "/search?q=lab".to_owned(), None),
        ]);
        assert_eq!(requests.len(), 27 + 7);
        for (method, path, body) in requests {
            let body = body.map(|body| ("application/json", body.to_string()));
            let reply = api.send(method, &path, &[], body).await;
            reply.assert_problem(503, "ipam.unavailable");
            assert_eq!(
                reply.body["title"], "Service unavailable",
                "{method} {path}"
            );
        }
    }

    #[tokio::test]
    async fn a_principal_without_rights_may_not_change_anything_and_finds_nothing() {
        let api = Api::new();
        let tenant = api.make(tenant_op(1)).await;
        api.remove(tenant, false).await;
        api.make(op("create_tenant", json!({ "name": label("lab", 1) })))
            .await;
        api.post("/custom-fields", &text_field("owner"))
            .await
            .assert_json(201);
        let before = api.revision();

        let denied = api.guarded(&Policy::new(false, false));
        let history = denied.get(&format!("/tenants/{}/history", tenant.id)).await;
        history.assert_problem(403, "auth.forbidden");
        let restore = denied
            .post_empty(&format!("/tenants/{}/restore", tenant.id), &[])
            .await;
        restore.assert_problem(403, "auth.forbidden");
        denied
            .post("/tenants/bulk", &bulk(&[tenant_op(2)]))
            .await
            .assert_problem(403, "auth.forbidden");
        denied
            .post("/custom-fields", &text_field("zone"))
            .await
            .assert_problem(403, "auth.forbidden");
        denied
            .patch("/custom-fields/owner", &json!({ "required": true }))
            .await
            .assert_problem(403, "auth.forbidden");
        denied
            .delete("/custom-fields/owner")
            .await
            .assert_problem(403, "auth.forbidden");
        assert_eq!(api.revision(), before, "nothing was written");
        assert!(api.stored::<Tenant>(tenant).await.meta.is_deleted());

        assert_eq!(api.get("/search?q=lab").await.items().len(), 1);
        let search = denied.get("/search?q=lab").await;
        search.assert_json(200).assert_no_items();
        assert_eq!(search.body["revision"], before);
    }

    #[tokio::test]
    async fn a_reader_may_read_but_not_change_and_the_questions_name_the_object() {
        let api = Api::new();
        let tenant = api.make(tenant_op(1)).await;
        api.remove(tenant, false).await;
        let policy = Policy::new(true, false);
        let reader = api.guarded(&policy);

        api.make(op("create_tenant", json!({ "name": label("lab", 1) })))
            .await;
        let found = reader.get("/search?q=lab").await;
        assert_eq!(hits(&found), [pair("tenant", &label("lab", 1))]);
        reader
            .get(&format!("/tenants/{}/history", tenant.id))
            .await
            .assert_json(200);
        reader
            .post_empty(&format!("/tenants/{}/restore", tenant.id), &[])
            .await
            .assert_problem(403, "auth.forbidden");
        reader
            .post("/tenants/bulk", &bulk(&[tenant_op(2)]))
            .await
            .assert_problem(403, "auth.forbidden");
        let delete = op("delete", json!({ "object": tenant }));
        reader
            .post("/tenants/bulk", &bulk(&[delete]))
            .await
            .assert_problem(403, "auth.forbidden");
        reader
            .post("/custom-fields", &text_field("owner"))
            .await
            .assert_problem(403, "auth.forbidden");
        let tenants = ObjectRef::singleton(ObjectKind::Tenant);
        let fields = ObjectRef::singleton(ObjectKind::CustomField);
        let expected = [
            (Action::Read, tenant),
            (Action::Update, tenant),
            (Action::Create, tenants),
            (Action::Delete, tenant),
            (Action::Administer, fields),
        ];
        assert_eq!(policy.asked(), expected);
    }

    // ----- the OpenAPI document --------------------------------------------------------

    #[test]
    fn the_openapi_document_describes_every_operation_of_the_area() {
        let (_, document) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let json = serde_json::to_value(&document).expect("document");
        let mut operations = Vec::new();
        for (collection, kind) in COLLECTIONS {
            let base = format!("{API_BASE}/{collection}");
            operations.push((
                "get",
                format!("{base}/{{id}}/history"),
                format!("get_{kind}_history"),
            ));
            operations.push((
                "post",
                format!("{base}/{{id}}/restore"),
                format!("restore_{kind}"),
            ));
            operations.push(("post", format!("{base}/bulk"), format!("bulk_{collection}")));
        }
        for (method, path, id) in [
            ("get", "/tags", "list_tags"),
            ("get", "/custom-fields", "list_custom_fields"),
            ("post", "/custom-fields", "create_custom_field"),
            ("get", "/custom-fields/{key}", "get_custom_field"),
            ("patch", "/custom-fields/{key}", "update_custom_field"),
            ("delete", "/custom-fields/{key}", "delete_custom_field"),
            ("get", "/search", "search"),
        ] {
            operations.push((method, format!("{API_BASE}{path}"), id.to_owned()));
        }
        for (method, path, operation_id) in operations {
            let operation = &json["paths"][path.as_str()][method];
            assert_eq!(operation["operationId"], operation_id, "{method} {path}");
            assert_eq!(operation["tags"], json!(["common"]), "{method} {path}");
            assert!(operation["summary"].is_string(), "{method} {path}");
            assert!(operation["responses"]["503"].is_object(), "{method} {path}");
        }
        let names = |path: &str, method: &str| -> Vec<String> {
            json["paths"][path][method]["parameters"]
                .as_array()
                .expect("parameters")
                .iter()
                .map(|parameter| parameter["name"].as_str().expect("name").to_owned())
                .collect()
        };
        let restore = names(&format!("{API_BASE}/prefixes/{{id}}/restore"), "post");
        for expected in ["id", "dry_run", "acknowledge", "If-Match"] {
            assert!(
                restore.iter().any(|name| name == expected),
                "{expected}: {restore:?}"
            );
        }
        let changes = names(&format!("{API_BASE}/prefixes/bulk"), "post");
        for expected in ["dry_run", "acknowledge", "Idempotency-Key"] {
            assert!(
                changes.iter().any(|name| name == expected),
                "{expected}: {changes:?}"
            );
        }
        let search = names(&format!("{API_BASE}/search"), "get");
        for expected in ["q", "limit", "at_least"] {
            assert!(
                search.iter().any(|name| name == expected),
                "{expected}: {search:?}"
            );
        }
    }

    // ----- read rights and revisions of tags and custom fields ---------------------------

    #[tokio::test]
    async fn custom_field_writes_honour_if_match() {
        let api = Api::new();
        let field = json!({ "key": "rack", "kind": { "type": "text" }, "applies_to": ["host"] });
        api.post("/custom-fields", &field).await.assert_json(201);
        let read = api.get("/custom-fields/rack").await;
        let etag = read.etag.clone().expect("etag");
        let patch = json!({ "required": true });
        let body = Some(("application/json", patch.to_string()));
        api.send(
            "PATCH",
            "/custom-fields/rack",
            &[("if-match", "\"999\"")],
            body.clone(),
        )
        .await
        .assert_problem(412, "ipam.revision_mismatch");
        api.send("PATCH", "/custom-fields/rack", &[("if-match", &etag)], body)
            .await
            .assert_json(200);
        api.send(
            "DELETE",
            "/custom-fields/rack",
            &[("if-match", &etag)],
            None,
        )
        .await
        .assert_problem(412, "ipam.revision_mismatch");
        api.send("DELETE", "/custom-fields/rack", &[("if-match", "*")], None)
            .await
            .assert_json(200);
        api.get("/custom-fields/rack")
            .await
            .assert_problem(404, "ipam.not_found");
    }

    #[tokio::test]
    async fn tags_count_only_kinds_the_principal_may_read() {
        let api = Api::new();
        let network = json!({ "cidr": "192.0.2.0/24", "tags": ["lab"] });
        api.make(op("create_prefix", network)).await;
        let host = json!({ "name": label("lab", 1), "tags": ["lab", "printer"] });
        api.make(op("create_host", host)).await;
        let all = api.get("/tags").await;
        all.assert_json(200);
        assert_eq!(all.body["items"][0]["tag"], "lab");
        assert_eq!(all.body["items"][0]["count"], 2);

        let hosts_only = api.guarded(&Arc::new(ReadsOnly(&[ObjectKind::Host])));
        let reply = hosts_only.get("/tags").await;
        reply.assert_json(200);
        assert_eq!(reply.body["items"][0]["tag"], "lab");
        assert_eq!(reply.body["items"][0]["count"], 1);
        assert_eq!(reply.body["items"][0]["by_kind"], json!({ "host": 1 }));
        let prefixes_only = api.guarded(&Arc::new(ReadsOnly(&[ObjectKind::Prefix])));
        let reply = prefixes_only.get("/tags").await;
        let tags: Vec<&str> = reply.body["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["tag"].as_str().expect("tag"))
            .collect();
        assert_eq!(tags, ["lab"], "printer is only on a host");
    }

    #[tokio::test]
    async fn custom_field_reads_need_read_rights() {
        let api = Api::new();
        let field = json!({ "key": "owner", "kind": { "type": "text" }, "applies_to": ["host"] });
        api.post("/custom-fields", &field).await.assert_json(201);
        let hosts_only = api.guarded(&Arc::new(ReadsOnly(&[ObjectKind::Host])));
        let list = hosts_only.get("/custom-fields").await;
        list.assert_json(200);
        assert_eq!(list.body["items"], json!([]));
        hosts_only
            .get("/custom-fields/owner")
            .await
            .assert_problem(403, "auth.forbidden");
        let fields_too = api.guarded(&Arc::new(ReadsOnly(&[ObjectKind::CustomField])));
        fields_too
            .get("/custom-fields/owner")
            .await
            .assert_json(200);
        let list = fields_too.get("/custom-fields").await;
        assert_eq!(list.body["items"][0]["key"], "owner");
    }
}
