//! `GET /dns/zones/{id}/records`, `POST .../records/batch`, `POST .../records/import` and
//! `GET .../records/export` (MIG-15).
//!
//! The batch applies its changes together or not at all; `dry_run=true` answers the diff
//! without writing. The import answers its preview with `dry_run=true` (200) and otherwise
//! starts the job `dns.import` (202 with `Location: /api/v1/jobs/{id}`), whose final step
//! carries the report. The export answers the zone file as `text/dns`.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use tenko_core::{
    Action, ObjectRef,
    dns::{Origin, RrSet, ZoneId},
};
use tenko_dns::zone::{
    RrSetFilter, ZoneService,
    import::{ImportReport, ImportRequest},
    records::{BatchOutcome, Change, Op},
};

use super::{
    DnsJobStarted, DryRunParams, ExportParams, ImportLoss, ImportTypeCount, RecordBatch,
    RecordBatchResult, RecordDiff, RecordFilters, RecordOp, RrSetItem, ZoneFileImport,
    ZoneFileImportReport, Zones, parse_id,
};
use crate::{
    API_BASE,
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams, encode_key_cursor},
    problem::{ApiError, ProblemDetails},
    routes::auth::ApiJson,
    state::AppState,
};

/// The item of a stored RRset.
pub(crate) fn rrset_item(rrset: &RrSet) -> Result<RrSetItem, ApiError> {
    Ok(RrSetItem {
        scope: rrset.scope.clone(),
        name: rrset.name.clone(),
        rtype: rrset.rtype,
        ttl: rrset.ttl,
        records: rrset.records()?,
        origin: rrset.origin,
        key: rrset.key.clone(),
        updated: rrset.updated.clone(),
    })
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}/records",
    tag = "dns",
    operation_id = "list_dns_records",
    summary = "List the RRsets of a zone",
    description = "Scope: `dns.read`. The RRsets of one scope in canonical name order (RFC 4034), types ascending; `name` keeps the owners whose name relative to the apex (or whole name) starts with the text, `@` the apex.",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), RecordFilters),
    responses(
        (status = 200, description = "A page of RRsets in name and type order", body = Page<RrSetItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`), or the scope does not exist (`dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_dns_records(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    Query(filters): Query<RecordFilters>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let page = PageParams {
        limit: filters.limit,
        cursor: filters.cursor.clone(),
        at_least: None,
    };
    let limit = page.limit()?;
    let filter = RrSetFilter {
        scope: filters.scope.clone().unwrap_or_default(),
        name: filters.name.clone(),
        rtype: filters.rtype,
        origin: filters.origin,
    };
    let cursor_scope = CursorScope::new("dns.records")
        .with(&id.to_string())
        .with(filter.scope.as_str())
        .with(filter.name.as_deref().unwrap_or_default())
        .with(
            &filter
                .rtype
                .map(|rtype| rtype.to_string())
                .unwrap_or_default(),
        )
        .with(
            &filter
                .origin
                .map(|origin| format!("{origin:?}"))
                .unwrap_or_default(),
        );
    let after = page.key_cursor(cursor_scope)?;
    let view = service.view(None).await?;
    let zone = ZoneService::zone(view.as_ref(), id)?.zone;
    if !zone.has_scope(&filter.scope) {
        return Err(tenko_dns::zone::ZoneError::zone_invalid(
            "scope",
            "the zone has no such scope",
        )
        .into());
    }
    let (rows, next) = ZoneService::rrsets(view.as_ref(), &zone, &filter, after.as_deref(), limit)?;
    let items = rows
        .iter()
        .map(|(rrset, _)| rrset_item(rrset))
        .collect::<Result<Vec<_>, _>>()?;
    let next = next.map(|key| encode_key_cursor(cursor_scope, &key));
    Ok(Json(Page::new(items, next, view.revision())).into_response())
}

fn batch_result(outcome: &BatchOutcome) -> Result<RecordBatchResult, ApiError> {
    let serial = outcome.serial();
    let changes = outcome
        .diff
        .iter()
        .map(|diff| {
            Ok(RecordDiff {
                scope: diff.key.scope.clone(),
                name: diff.key.name.clone(),
                rtype: diff.key.rtype,
                before: diff.before.as_ref().map(rrset_item).transpose()?,
                after: diff.after.as_ref().map(rrset_item).transpose()?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(RecordBatchResult {
        dry_run: outcome.dry_run,
        changes,
        serial,
        revision: outcome.written.as_ref().map(|written| written.revision),
    })
}

#[utoipa::path(
    post,
    path = "/dns/zones/{id}/records/batch",
    tag = "dns",
    operation_id = "change_dns_records",
    summary = "Change RRsets of a zone in one batch",
    description = "Scope: `dns.write`. The changes run in order and apply together or not at all: `set` replaces an RRset, `add` and `remove` change its records (an RRset left empty is deleted), `delete` removes it. The SOA follows the zone settings; the serial moves once per scope the batch touches. A change of an RRset of another origin needs `take_over`. `dry_run=true` answers the diff without writing.",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), DryRunParams),
    request_body(content = RecordBatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The diff, and after a write the serial and revision", body = RecordBatchResult),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), a record breaks a rule of its type (`dns.record.invalid`), or the zone holds no records or lacks the scope (`dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "RRsets conflict (`dns.record.conflict`) or belong to another origin without `take_over` (`dns.record.origin`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn change_dns_records(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    Query(query): Query<DryRunParams>,
    ApiJson(body): ApiJson<RecordBatch>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let changes: Vec<Change> = body
        .changes
        .into_iter()
        .map(|change| Change {
            op: match change.op {
                RecordOp::Set => Op::Set,
                RecordOp::Add => Op::Add,
                RecordOp::Remove => Op::Remove,
                RecordOp::Delete => Op::Delete,
            },
            scope: change.scope.unwrap_or_default(),
            name: change.name,
            rtype: change.rtype,
            ttl: change.ttl,
            records: change.records,
            take_over: change.take_over.unwrap_or(false),
            origin: Origin::Manual,
        })
        .collect();
    let outcome = service
        .change_records(&cx, id, &changes, query.dry_run.unwrap_or(false))
        .await?;
    Ok(Json(batch_result(&outcome)?).into_response())
}

/// The answer form of an import report.
pub(crate) fn import_report(report: ImportReport) -> ZoneFileImportReport {
    ZoneFileImportReport {
        dry_run: report.dry_run,
        added: report.added,
        replaced: report.replaced,
        removed: report.removed,
        types: report
            .types
            .into_iter()
            .map(|(rtype, records)| ImportTypeCount {
                rtype,
                records: u32::try_from(records).unwrap_or(u32::MAX),
            })
            .collect(),
        losses: report
            .losses
            .into_iter()
            .map(|loss| ImportLoss {
                line: loss.line,
                code: loss.code,
                detail: loss.detail,
            })
            .collect(),
        serial: report.serial,
        revision: report.revision,
    }
}

#[utoipa::path(
    post,
    path = "/dns/zones/{id}/records/import",
    tag = "dns",
    operation_id = "import_dns_zone_file",
    summary = "Import a zone file into a zone",
    description = "Scope: `dns.write`. `$ORIGIN` and `$TTL` are honoured, `$GENERATE` is expanded, `$INCLUDE` is refused. With `dry_run=true` the file is read against the zone and the answer is the preview: records per type, the RRsets that would be added, replaced and removed, and the losses. Without it the preview runs first and then the import job (`dns.import`) starts; its steps write the RRsets in chunks and its final step's output is the report (JSON).",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), DryRunParams),
    request_body(content = ZoneFileImport, content_type = "application/json"),
    responses(
        (status = 200, description = "The preview of a dry run", body = ZoneFileImportReport),
        (status = 202, description = "The import job; follow it at the `Location`", body = DnsJobStarted),
        (status = 400, description = "The request is malformed (`sys.invalid_request`), or the zone holds no records or lacks the scope (`dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The zone file does not parse or uses `$INCLUDE` (`dns.zonefile.invalid`, parameters `line` and `reason`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn import_dns_zone_file(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    Query(query): Query<DryRunParams>,
    ApiJson(body): ApiJson<ZoneFileImport>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let request = ImportRequest {
        zone: id,
        scope: body.scope.unwrap_or_default(),
        text: body.zone_file,
        replace: body.replace,
    };
    if query.dry_run.unwrap_or(false) {
        let report = service.preview_import(&cx, &request).await?;
        return Ok(Json(import_report(report)).into_response());
    }
    let (job_id, _) = service.start_import(&cx, request).await?;
    let mut response = (StatusCode::ACCEPTED, Json(DnsJobStarted { job_id })).into_response();
    if let Ok(location) = HeaderValue::from_str(&format!("{API_BASE}/jobs/{job_id}")) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    Ok(response)
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}/records/export",
    tag = "dns",
    operation_id = "export_dns_zone_file",
    summary = "Export a zone as a zone file",
    description = "Scope: `dns.read`. RFC 1035 text: `$ORIGIN` and `$TTL`, the apex SOA, then every RRset in canonical name order with the types ascending, one record per line, owners relative to the apex. The same data gives the same bytes, and a file the export wrote imports and exports to the same bytes (MIG-15). Every export writes the audit record `dns.zone.export`.",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), ExportParams),
    responses(
        (status = 200, description = "The zone file (RFC 1035) in byte-stable order (MIG-15)", body = String, content_type = "text/dns"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`), or the zone holds no records or lacks the scope (`dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such zone (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn export_dns_zone_file(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    Query(query): Query<ExportParams>,
) -> Result<Response, ApiError> {
    let id = parse_id::<ZoneId>(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let scope = query.scope.unwrap_or_default();
    let file = service.export(&cx, id, &scope).await?;
    let disposition = format!("attachment; filename=\"{}.zone\"", file.zone);
    let mut response = (StatusCode::OK, file.text).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/dns"));
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    Ok(response)
}
