//! `GET|POST /dns/zones`, `GET|PATCH|DELETE /dns/zones/{id}` and the zone journal.
//!
//! A zone is read with its served SOA serial, its RRset counts per origin and its row
//! revision as the `ETag`; `PATCH` and `DELETE` take `If-Match`. Creating a primary or
//! RPZ zone writes its apex SOA and NS set in every scope.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, ObjectKind, ObjectRef, Revision, Timestamp,
    dns::{JournalEntry, ScopeName, Zone, ZoneId},
};
use tenko_dns::zone::{NewZone, ZoneChange, ZoneRow, ZoneService, journal};
use utoipa::{IntoParams, ToSchema};

use super::{OriginCount, ZoneCreate, ZoneItem, ZonePatch, Zones, parse_id, with_etag};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams, encode_cursor},
    problem::{ApiError, ProblemDetails},
    routes::auth::{ApiJson, if_match},
    state::AppState,
};

/// The item of a zone row.
pub(crate) fn zone_item(
    view: &dyn tenko_store::ReadView,
    row: ZoneRow,
) -> Result<ZoneItem, ApiError> {
    let summary = ZoneService::summary(view, &row.zone)?;
    Ok(ZoneItem {
        soa_serial: summary.soa_serial,
        rrsets: summary.rrsets,
        origins: summary
            .origins
            .into_iter()
            .map(|(origin, rrsets)| OriginCount {
                origin,
                rrsets: u32::try_from(rrsets).unwrap_or(u32::MAX),
            })
            .collect(),
        revision: row.revision,
        zone: row.zone,
    })
}

#[utoipa::path(
    get,
    path = "/dns/zones",
    tag = "dns",
    operation_id = "list_dns_zones",
    summary = "List DNS zones",
    description = "Scope: `dns.read`. Zones by name, with the served serial and the RRsets per origin.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of zones by name", body = Page<ZoneItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dns_zones(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Zone))?;
    let service = zones.get()?;
    let limit = page.limit()?;
    let scope = CursorScope::new("dns.zones");
    let after: Option<(String, ZoneId)> = page.cursor(scope)?;
    let view = page.read(service.store().as_ref()).await?;
    let rows = ZoneService::zones(view.as_ref())?;
    let mut items = Vec::new();
    let mut next = None;
    for row in rows {
        let position = (row.zone.name.as_str().to_owned(), row.zone.id);
        if after.as_ref().is_some_and(|after| &position <= after) {
            continue;
        }
        if items.len() == limit {
            next = items.last().map(|item: &ZoneItem| {
                encode_cursor(scope, &(item.zone.name.as_str().to_owned(), item.zone.id))
            });
            break;
        }
        items.push(zone_item(view.as_ref(), row)?);
    }
    Ok(Json(Page::new(items, next, view.revision())).into_response())
}

#[utoipa::path(
    post,
    path = "/dns/zones",
    tag = "dns",
    operation_id = "create_dns_zone",
    summary = "Create a DNS zone",
    description = "Scope: `dns.write`. A primary or RPZ zone gets the apex SOA (from `soa` and the first serial of the policy) and the NS set of `name_servers` in every scope; a secondary, stub or forward zone is a row only until transfers come (WP6.1).",
    request_body(content = ZoneCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The zone, with its SOA and NS set; the `ETag` is its revision", body = ZoneItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the settings are invalid (`dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A zone of this name exists (`dns.zone.exists`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_dns_zone(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    ApiJson(body): ApiJson<ZoneCreate>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::Zone))?;
    let service = zones.get()?;
    let written = service
        .create(
            &cx,
            NewZone {
                name: body.name,
                kind: body.kind,
                tenant: body.tenant,
                scopes: body.scopes,
                serial: body.serial.unwrap_or_default(),
                soa: body.soa,
                name_servers: body.name_servers,
                transfer: body.transfer.unwrap_or_default(),
                update: body.update.unwrap_or_default(),
                dnssec: body.dnssec.unwrap_or_default(),
                source: body.source,
                description: body.description,
                reverse_of: None,
            },
        )
        .await?;
    let view = service.view(Some(written.revision)).await?;
    let row = ZoneService::zone(view.as_ref(), written.zone.id)?;
    let revision = row.revision;
    let item = zone_item(view.as_ref(), row)?;
    Ok(with_etag(StatusCode::CREATED, &item, revision))
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}",
    tag = "dns",
    operation_id = "get_dns_zone",
    summary = "Get a DNS zone",
    description = "Scope: `dns.read`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)")),
    responses(
        (status = 200, description = "The zone with its `ETag`", body = ZoneItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_dns_zone(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let view = service.view(None).await?;
    let row = ZoneService::zone(view.as_ref(), id)?;
    let revision = row.revision;
    let item = zone_item(view.as_ref(), row)?;
    Ok(with_etag(StatusCode::OK, &item, revision))
}

#[utoipa::path(
    patch,
    path = "/dns/zones/{id}",
    tag = "dns",
    operation_id = "update_dns_zone",
    summary = "Change a DNS zone",
    description = "Scope: `dns.write`. A change of `soa` rewrites the SOA of every scope with the next serial; a new scope gets an SOA and a copy of the default scope's NS set; a removed scope loses its RRsets and journal.",
    params(
        ("id" = String, Path, description = "Zone identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read, as in the `ETag`; a stale revision is refused with 412")
    ),
    request_body(content = ZonePatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The changed zone", body = ZoneItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the settings are invalid (`dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The zone changed since it was read (`If-Match`, `sys.store.precondition_failed`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_dns_zone(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ZonePatch>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let expect = if_match(&headers)?;
    let written = service
        .update(
            &cx,
            id,
            ZoneChange {
                scopes: body.scopes,
                serial: body.serial,
                soa: body.soa,
                transfer: body.transfer,
                update: body.update,
                dnssec: body.dnssec,
                source: body.source,
                description: body.description,
                reverse_of: None,
            },
            expect,
        )
        .await?;
    let view = service.view(Some(written.revision)).await?;
    let row = ZoneService::zone(view.as_ref(), id)?;
    let revision = row.revision;
    let item = zone_item(view.as_ref(), row)?;
    Ok(with_etag(StatusCode::OK, &item, revision))
}

#[utoipa::path(
    delete,
    path = "/dns/zones/{id}",
    tag = "dns",
    operation_id = "delete_dns_zone",
    summary = "Delete a DNS zone and its records",
    description = "Scope: `dns.write`. The zone, its RRsets and its journal go; a zone larger than one batch loses its row first and the rest right after.",
    params(
        ("id" = String, Path, description = "Zone identifier (UUID)"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read; a stale revision is refused with 412")
    ),
    responses(
        (status = 204, description = "The zone is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The zone changed since it was read (`If-Match`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_dns_zone(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Delete, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let expect = if_match(&headers)?;
    service.delete(&cx, id, expect).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// One serial step of a zone scope.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JournalItem {
    /// The serial before.
    pub from_serial: u32,
    /// The serial after.
    pub to_serial: u32,
    /// When.
    pub at: Timestamp,
    /// The revision the step was planned against (the cursor of the next page).
    pub revision: Revision,
    /// Records added (the SOA not counted).
    pub added: u32,
    /// RRsets whose records changed: an owner and type with records both removed and
    /// added.
    pub replaced: u32,
    /// Records removed (the SOA not counted).
    pub removed: u32,
}

impl From<&JournalEntry> for JournalItem {
    fn from(entry: &JournalEntry) -> Self {
        use std::collections::BTreeSet;
        let data = |records: &[tenko_core::dns::JournalRecord]| -> Vec<(String, u16)> {
            records
                .iter()
                .filter(|record| record.rtype != tenko_core::dns::Rtype::SOA)
                .map(|record| (record.name.as_str().to_owned(), record.rtype.0))
                .collect()
        };
        let removed = data(&entry.removed);
        let added = data(&entry.added);
        let removed_sets: BTreeSet<&(String, u16)> = removed.iter().collect();
        let added_sets: BTreeSet<&(String, u16)> = added.iter().collect();
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        Self {
            from_serial: entry.from_serial,
            to_serial: entry.to_serial,
            at: entry.at,
            revision: entry.revision,
            added: count(added.len()),
            replaced: count(removed_sets.intersection(&added_sets).count()),
            removed: count(removed.len()),
        }
    }
}

/// The query of `GET /dns/zones/{id}/journal`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct JournalParams {
    /// The scope; `default` when absent.
    pub scope: Option<ScopeName>,
    /// The cursor of the next page (older entries).
    pub cursor: Option<String>,
    /// Items per page, 1 to 1000; 100 by default.
    pub limit: Option<u32>,
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}/journal",
    tag = "dns",
    operation_id = "list_dns_zone_journal",
    summary = "List the serial steps of a zone scope",
    description = "Scope: `dns.read`. The journal entries of a scope, newest first: the serials before and after, the time and the counts of records added, replaced and removed. The journal is bounded by entries and days; a large import resets it.",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), JournalParams),
    responses(
        (status = 200, description = "A page of journal entries, newest first", body = Page<JournalItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`), or the scope does not exist (`dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dns_zone_journal(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    Query(params): Query<JournalParams>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let page = PageParams {
        limit: params.limit,
        cursor: params.cursor.clone(),
        at_least: None,
    };
    let limit = page.limit()?;
    let scope_name = params.scope.unwrap_or_default();
    let cursor_scope = CursorScope::new("dns.journal").with(scope_name.as_str());
    let before: Option<u64> = page.cursor(cursor_scope)?;
    let view = service.view(None).await?;
    let zone: Zone = ZoneService::zone(view.as_ref(), id)?.zone;
    if !zone.has_scope(&scope_name) {
        return Err(tenko_dns::zone::ZoneError::zone_invalid(
            "scope",
            "the zone has no such scope",
        )
        .into());
    }
    let mut entries = journal::list(
        view.as_ref(),
        id,
        &scope_name,
        before.map(Revision),
        limit + 1,
    )?;
    let next = if entries.len() > limit {
        entries.truncate(limit);
        entries
            .last()
            .map(|entry| encode_cursor(cursor_scope, &entry.revision.0))
    } else {
        None
    };
    let items: Vec<JournalItem> = entries.iter().map(JournalItem::from).collect();
    Ok(Json(Page::new(items, next, view.revision())).into_response())
}
