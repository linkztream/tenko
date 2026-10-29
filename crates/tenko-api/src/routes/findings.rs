//! The findings (U1): one list, one count and one live topic over everything Tenko noticed
//! that a person may need to decide on.
//!
//! Area: findings. Requirements: IPAM-10, IPAM-15, IPAM-21, IPAM-23, IPAM-19.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /findings` | 200 page of findings, the most urgent first | 400 `sys.invalid_query`, `sys.invalid_cursor`, `ipam.invalid_filter`, 404 `ipam.not_found` (prefix or site filter), 503 `findings.unavailable` |
//! | `GET /findings/counts` | 200 counts per severity, area and source | 503 |
//! | `GET /findings/{id}` | 200 one finding | 404 `findings.not_found`, 503 |
//!
//! A finding is derived from its source and never stored ([`tenko_ipam::findings`]): an open
//! proposal, a prefix's utilization alarm, a row of the reconciliation view (or a scan
//! artifact on a network's edge address), a job waiting for a person, a health condition of
//! `GET /system/status`. The sources keep their own routes; the counts here are the ones the
//! rail badges, the status bar and the dashboard show, and `sources.proposal` equals the
//! number of open proposals of `GET /proposals?state=open`. The topic `findings` of
//! `GET /events` announces each change of the index.
//!
//! The list takes `severity` (`act`, `review`, `info`), `kind`, `subject` (`address`, `host`,
//! `prefix`, `record`, `job`, `node`, `device`), `area`, `source` (each repeatable or
//! comma-separated), `prefix` (a prefix identifier: findings about it, its addresses and its
//! networks), `site` (a site identifier: the findings of the site's prefixes) and `q` (text
//! of the summary, the subject or the code), and pages like every list (`limit`, `cursor`).
//!
//! # Authorization
//!
//! A principal sees a finding when it may read its source: a proposal's finding with read
//! access to the proposal (a scoped reader: where the proposal's subject lies in its scope),
//! an alarm's with read access to the prefix, a job's with read access to the job (its
//! targets), a row of the reconciliation view with read access to observations (a scoped
//! reader: where the address lies in its scope), a health condition with read access to the
//! system. The counts count what the principal sees.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
};
use tenko_auth::authz::anywhere;
use tenko_core::{
    Action, ObjectKind, ObjectRef, PrefixId, RequestCtx, SiteId, Timestamp, ipam::Prefix,
};
use tenko_ipam::{
    findings::{
        Finding, FindingArea, FindingCounts, FindingKind, FindingLevel, FindingQuery,
        FindingSource, SubjectKind,
    },
    scope::ScopeIndex,
    tables::PREFIXES,
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{
    common::{ReadScope, enum_params, read_scope},
    system::{StatusSources, system_object},
};
use crate::{
    dto::Page,
    extract::Ctx,
    findings::FindingsService,
    list::{Filters, encode_cursor},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The findings service is not running on this server (503).
pub const UNAVAILABLE: &str = "findings.unavailable";
/// No finding with this identifier, or none the principal may read (404). Params: `id`.
pub const NOT_FOUND: &str = "findings.not_found";

/// How long a request waits for the first load of the index after a start.
const LOAD_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The routes of the area.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_findings))
        .routes(routes!(count_findings))
        .routes(routes!(get_finding))
}

/// The service, its index loaded, with fresh health conditions.
async fn service(
    app: &AppState,
    service: Option<Extension<Arc<FindingsService>>>,
    sources: StatusSources,
    now: Timestamp,
) -> Result<Arc<FindingsService>, ApiError> {
    let Some(Extension(service)) = service else {
        return Err(ApiError::new(
            UNAVAILABLE,
            503,
            "the findings index does not run on this server",
        ));
    };
    if service.health_stale() {
        let warnings = sources.warnings(app, now).await;
        service.set_health(&warnings, now);
    }
    service.wait_loaded(LOAD_WAIT).await;
    Ok(service)
}

/// What a principal may read of each source.
struct Access {
    proposals: ReadScope,
    prefixes: ReadScope,
    jobs: ReadScope,
    /// `None` without read access to observations.
    observations: Option<ReadScope>,
    health: bool,
}

impl Access {
    fn of(app: &AppState, cx: &RequestCtx, index: Option<&Arc<ScopeIndex>>) -> Self {
        let scope = |kind| read_scope(app.authorizer.as_deref(), index.cloned(), cx, kind);
        let observations = app
            .authorize(
                &cx.principal,
                Action::Read,
                &anywhere(ObjectKind::Observation),
            )
            .is_ok()
            .then(|| scope(ObjectKind::Observation));
        Self {
            proposals: scope(ObjectKind::Proposal),
            prefixes: scope(ObjectKind::Prefix),
            jobs: scope(ObjectKind::Job),
            observations,
            health: app
                .authorize(&cx.principal, Action::Read, &system_object())
                .is_ok(),
        }
    }

    /// Whether every finding passes.
    fn everything(&self) -> bool {
        self.proposals.is_all()
            && self.prefixes.is_all()
            && self.jobs.is_all()
            && self.observations.as_ref().is_some_and(ReadScope::is_all)
            && self.health
    }

    fn admits(&self, finding: &Finding) -> bool {
        let object = record_of(finding);
        let by =
            |scope: &ReadScope| scope.admits_by(|index| index.anchors_of_finding(object, finding));
        match finding.source {
            FindingSource::Proposal => by(&self.proposals),
            FindingSource::Alarm => by(&self.prefixes),
            FindingSource::Job => by(&self.jobs),
            // The topology is a read of observations, as its map is.
            FindingSource::Reconcile | FindingSource::Topology => {
                self.observations.as_ref().is_some_and(by)
            }
            FindingSource::Health => self.health,
        }
    }
}

/// The record a finding stands for, as authorization knows it.
fn record_of(finding: &Finding) -> ObjectRef {
    let id = || Uuid::parse_str(&finding.evidence.id).unwrap_or(Uuid::nil());
    match finding.source {
        FindingSource::Proposal => ObjectRef::new(ObjectKind::Proposal, id()),
        FindingSource::Alarm => ObjectRef::new(ObjectKind::Prefix, id()),
        FindingSource::Job => ObjectRef::new(ObjectKind::Job, id()),
        FindingSource::Reconcile | FindingSource::Topology => {
            ObjectRef::new(ObjectKind::Observation, Uuid::nil())
        }
        FindingSource::Health => system_object(),
    }
}

/// Lists findings, the most urgent first, then the newest.
#[utoipa::path(
    get,
    path = "/findings",
    tag = "findings",
    operation_id = "list_findings",
    summary = "List findings",
    description = "U1. Everything Tenko noticed that a person may need to decide on, from every source (open proposals, utilization alarms, the reconciliation view and scan artifacts, jobs waiting for a person, health conditions), each with a severity (`act`, `review`, `info`), a subject, the evidence by reference and a default action. Ordered by severity, then the newest first. A principal sees the findings whose source it may read.",
    params(
        crate::list::PageParams,
        ("severity" = Option<String>, Query, description = "Only findings of these severities: `act`, `review`, `info`. Repeat the parameter or separate the values with commas."),
        ("kind" = Option<String>, Query, description = "Only findings of these kinds: `conflict`, `job_waiting`, `utilization`, `unknown_device`, `orphaned_record`, `orphaned_address`, `ptr_mismatch`, `intent_differs`, `outside_prefixes`, `vlan`, `host_name`, `dns`, `ghost`, `scan_artifact`, `health`, `topology_root`, `wlan_class`, `wlan_prefix`."),
        ("subject" = Option<String>, Query, description = "Only findings whose subject is of these kinds: `address`, `host`, `prefix`, `record`, `job`, `node`, `device`."),
        ("area" = Option<String>, Query, description = "Only findings of these areas: `ipam`, `dns`, `dhcp`, `discovery`, `topology`, `jobs`, `connectors`, `nodes`, `settings`."),
        ("source" = Option<String>, Query, description = "Only findings of these sources: `proposal`, `alarm`, `reconcile`, `job`, `health`, `topology`."),
        ("prefix" = Option<String>, Query, description = "Only findings about this prefix (identifier): its own subject, an address or a network inside it."),
        ("site" = Option<String>, Query, description = "Only findings about the prefixes of this site (identifier)."),
        ("q" = Option<String>, Query, description = "Only findings whose summary, subject or code contains this text (without case).")
    ),
    responses(
        (status = 200, description = "A page of findings", body = Page<Finding>),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`, `ipam.invalid_filter`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The prefix or site filter names no prefix or site (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The findings index does not run on this server (`findings.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_findings(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    findings: Option<Extension<Arc<FindingsService>>>,
    index: Option<Extension<Arc<ScopeIndex>>>,
    sources: StatusSources,
    filters: Filters,
) -> Result<Json<Page<Finding>>, ApiError> {
    filters.only(&[
        "severity", "kind", "subject", "area", "source", "prefix", "site", "q",
    ])?;
    let page = filters.page()?;
    let scope = filters.scope("findings");
    let mut query = FindingQuery {
        severities: enum_params::<FindingLevel>(&filters, "severity", "a severity")?,
        kinds: enum_params::<FindingKind>(&filters, "kind", "a finding kind")?,
        subjects: enum_params::<SubjectKind>(&filters, "subject", "a subject kind")?,
        areas: enum_params::<FindingArea>(&filters, "area", "an area")?,
        sources: enum_params::<FindingSource>(&filters, "source", "a source")?,
        within: None,
        text: filters
            .get("q")?
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned),
        limit: Some(page.limit()?),
        cursor: page.cursor::<String>(scope)?,
    };
    let prefix = filters.parse::<PrefixId>("prefix")?;
    let site = filters.parse::<SiteId>("site")?;
    if prefix.is_some() || site.is_some() {
        query.within = Some(within(&app, prefix, site).await?);
    }
    let service = service(&app, findings, sources, cx.now).await?;
    let access = Access::of(&app, &cx, index.as_ref().map(|Extension(index)| index));
    let found = if access.everything() {
        service.index().list(&query, &|_| true)?
    } else {
        service
            .index()
            .list(&query, &|finding: &Finding| access.admits(finding))?
    };
    Ok(Json(Page::new(
        found.items,
        found
            .next_cursor
            .map(|cursor| encode_cursor(scope, &cursor)),
        found.revision,
    )))
}

/// The prefixes of a prefix and a site filter: the prefix itself, the prefixes of the
/// site; both given, the prefix when it is the site's.
async fn within(
    app: &AppState,
    prefix: Option<PrefixId>,
    site: Option<SiteId>,
) -> Result<Vec<(PrefixId, tenko_core::VrfId, ipnet::IpNet)>, ApiError> {
    let view = app.store.read(ReadConsistency::Local).await?;
    let mut out = Vec::new();
    if let Some(id) = prefix {
        let found: Prefix = view
            .get_typed(&PREFIXES, &id)?
            .map(|(prefix, _)| prefix)
            .filter(|prefix| !prefix.meta.is_deleted())
            .ok_or_else(|| ApiError::from(tenko_ipam::IpamError::not_found(ObjectRef::from(id))))?;
        if site.is_none_or(|site| found.site == Some(site)) {
            out.push((found.id, found.vrf, found.cidr));
        }
        return Ok(out);
    }
    if let Some(site) = site {
        if view
            .get_typed(&tenko_ipam::tables::SITES, &site)?
            .is_none_or(|(found, _)| found.meta.is_deleted())
        {
            return Err(tenko_ipam::IpamError::not_found(ObjectRef::from(site)).into());
        }
        for (_, found, _) in view.scan_typed(&PREFIXES, KeyRange::all(), usize::MAX, false)? {
            let found: Prefix = found;
            if !found.meta.is_deleted() && found.site == Some(site) {
                out.push((found.id, found.vrf, found.cidr));
            }
        }
    }
    Ok(out)
}

/// Counts the findings per severity, area and source.
#[utoipa::path(
    get,
    path = "/findings/counts",
    tag = "findings",
    operation_id = "count_findings",
    summary = "Count findings per severity, area and source",
    description = "U1. The counts every surface reads: the rail badges, the status bar and the dashboard. `problems` is `act` plus `review`; information is never counted as a problem. `sources.proposal` equals the open proposals of `GET /proposals?state=open`. A principal counts the findings whose source it may read.",
    responses(
        (status = 200, description = "The counts", body = FindingCounts),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The findings index does not run on this server (`findings.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn count_findings(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    findings: Option<Extension<Arc<FindingsService>>>,
    index: Option<Extension<Arc<ScopeIndex>>>,
    sources: StatusSources,
    filters: Filters,
) -> Result<Json<FindingCounts>, ApiError> {
    filters.only(&[])?;
    let service = service(&app, findings, sources, cx.now).await?;
    let access = Access::of(&app, &cx, index.as_ref().map(|Extension(index)| index));
    Ok(Json(if access.everything() {
        service.index().counts()
    } else {
        service
            .index()
            .counts_where(&|finding: &Finding| access.admits(finding))
    }))
}

/// Shows one finding.
#[utoipa::path(
    get,
    path = "/findings/{id}",
    tag = "findings",
    operation_id = "get_finding",
    summary = "Get one finding",
    params(("id" = String, Path, description = "Finding identifier, such as `proposal:<id>` or `reconcile:<digest>`")),
    responses(
        (status = 200, description = "The finding", body = Finding),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such finding, or none the principal may read (`findings.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The findings index does not run on this server (`findings.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_finding(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    findings: Option<Extension<Arc<FindingsService>>>,
    index: Option<Extension<Arc<ScopeIndex>>>,
    sources: StatusSources,
    Path(id): Path<String>,
) -> Result<Json<Finding>, ApiError> {
    let service = service(&app, findings, sources, cx.now).await?;
    let access = Access::of(&app, &cx, index.as_ref().map(|Extension(index)| index));
    service
        .index()
        .get(&id)
        .filter(|finding| access.everything() || access.admits(finding))
        .map(Json)
        .ok_or_else(|| {
            ApiError::new(NOT_FOUND, 404, format!("no finding {id}")).with_param("id", id.clone())
        })
}

#[cfg(test)]
mod tests;
