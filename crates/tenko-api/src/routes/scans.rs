//! On-demand scan jobs, per-probe scan configuration and the remote kill switch (SCAN-05,
//! SCAN-09, OPS-28).
//!
//! Area: scans. Owner: WP3.10.
//! Requirements: SCAN-05, SCAN-09, OPS-28.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /nodes/{id}/scan-config` | 200 [`ProbeConfigView`] with `ETag` (the revision of the stored configuration, absent while none is stored) | 400, 403, 404 `cluster.node.not_found`, 409 `node.config.not_a_probe` |
//! | `PUT /nodes/{id}/scan-config` | 200 [`ProbeConfigView`] with `ETag` | 400, 403, 404, 409, 412 `node.config.revision_mismatch`, 422 `node.config.invalid`, `node.config.secret`, 503 `node.config.vault_unavailable` |
//! | `POST /nodes/{id}/scan/stop` | 202 [`KillSwitchResult`] | 400, 403, 404, 409 |
//! | `POST /nodes/{id}/scan/resume` | 202 [`KillSwitchResult`] | 400, 403, 404, 409 |
//! | `GET /scans/probes` | 200 [`ProbeList`]: every probe with its configuration state and kill switch | 403 |
//! | `POST /scans/stop` | 202 [`KillSwitchResult`], one command per probe | 400, 403 |
//! | `POST /scans/resume` | 202 [`KillSwitchResult`] | 403 |
//! | `POST /scans` | 202 [`ScanView`] of the queued run with its `job_id` | 400, 403, 404 and 422 `scan.job.target`, 422 `scan.job.no_probe`, `scan.job.invalid` |
//! | `GET /scans` | 200 page of [`ScanView`], newest first, diffs with their counts only | 400 `sys.invalid_query`, `sys.invalid_cursor`, 403 |
//! | `GET /scans/{id}` | 200 [`ScanView`] with the probes' progress and the whole diff | 400, 403, 404 `scan.job.not_found` |
//!
//! Part of the Discovery module: registered only while it runs.
//!
//! # The service
//!
//! The server adds the scan control of the controller ([`ScanControl`]) as a request
//! extension. Without it, every endpoint answers `501` `sys.not_implemented`, so the bare
//! router of the route table test keeps working.
//!
//! # Configuration
//!
//! A probe's configuration is the `[scan]` section as JSON, with SNMP passwords named as
//! operator secrets of the vault (`auth_secret`, `privacy_secret`), never as passwords or
//! password files. The controllers stream it to the probe, which applies it atomically;
//! `applied` and `in_sync` show what the probe reports it runs. A probe that never had a
//! stored configuration runs on its own file and offers it at its first connection; the
//! answer then has `origin: offer` and lists the devices that wait for a vault secret in
//! `lacking_secrets`.
//!
//! # Authorization
//!
//! Reading a configuration needs [`Action::Read`] on the node, changing it and the kill
//! switch [`Action::Update`] on the node (administrators); the installation-wide switch
//! needs [`Action::Update`] on nodes. Starting a scan needs [`Action::Execute`] on its
//! target: the prefix or the host, or prefixes and addresses in general for a network or
//! an address (operators may). Reading scans needs [`Action::Read`] on jobs, the probe list
//! [`Action::Read`] on nodes.
//!
//! # `202 Accepted`
//!
//! A scan runs as the job `scan.run` (dispatch, waiting, diff); follow it with
//! `GET /scans/{id}` or on the `discovery` and `jobs` event topics. A kill switch request
//! is recorded as one command per probe; a probe that is offline gets it when it connects
//! again, and `kill_switch.confirmed` turns true once it did.

#[cfg(test)]
mod tests;

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tenko_core::{Action, CodedError, NodeId, ObjectKind, ObjectRef, Revision, error::codes};
use tenko_scan::{
    config::ScanConfig,
    control::{
        ScanControl,
        model::{
            KillSwitchResult, ProbeConfigView, ProbeSummary, ScanRequest, ScanView, StopRequest,
            Target,
        },
    },
};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{
    auth::{ApiJson, OptionalJson},
    common::{if_match, with_etag},
    not_implemented,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{Filters, encode_cursor},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// Names the list endpoint in cursors.
const CURSOR_ENDPOINT: &str = "scan.runs";

/// The routes of the area.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_scan_config, update_scan_config))
        .routes(routes!(stop_node_scans))
        .routes(routes!(resume_node_scans))
        .routes(routes!(list_scans, create_scan))
        .routes(routes!(list_scan_probes))
        .routes(routes!(stop_scans))
        .routes(routes!(resume_scans))
        .routes(routes!(get_scan))
}

/// Body of `GET /scans/probes`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProbeList {
    /// Every probe: this controller's own probe role first, then the enrolled probes by id.
    pub items: Vec<ProbeSummary>,
}

type Control = Option<Extension<Arc<ScanControl>>>;

fn control_or_stub(
    control: Control,
    method: &str,
    path: &str,
) -> Result<Arc<ScanControl>, ApiError> {
    control
        .map(|Extension(control)| control)
        .ok_or_else(|| not_implemented(method, path))
}

fn failed(error: CodedError) -> ApiError {
    ApiError::from_coded_error(error)
}

fn invalid_request(detail: impl Into<String>) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(codes::INVALID_REQUEST, 400, detail).with_title("Invalid request"),
    )
}

fn parse_node(raw: &str) -> Result<NodeId, ApiError> {
    raw.parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .map(NodeId)
        .ok_or_else(|| {
            invalid_request("the node identifier is not a positive number")
                .with_param("field", "id")
        })
}

fn parse_run(raw: &str) -> Result<Uuid, ApiError> {
    raw.parse()
        .map_err(|_| invalid_request("the scan identifier is not a UUID").with_param("field", "id"))
}

/// The answer of a configuration with its revision as `ETag`.
fn config_answer(view: ProbeConfigView) -> Response {
    let revision = view.revision;
    let response = Json(view).into_response();
    match revision {
        Some(revision) => with_etag(response, Revision(revision)),
        None => response,
    }
}

/// What `POST /scans` is authorized against: the prefix or the host, or prefixes and
/// addresses in general.
fn scan_object(request: &ScanRequest) -> ObjectRef {
    match request.target.parse() {
        Some(Target::Prefix(id)) => ObjectRef::from(id),
        Some(Target::Host(id)) => ObjectRef::from(id),
        Some(Target::Address(_)) => ObjectRef::singleton(ObjectKind::Address),
        Some(Target::Network(_)) | None => ObjectRef::singleton(ObjectKind::Prefix),
    }
}

/// Shows the scan configuration the controllers hold for a probe, with what the probe
/// reports it applies and its kill switch. SNMP passwords appear only as vault secret ids.
#[utoipa::path(
    get,
    path = "/nodes/{id}/scan-config",
    tag = "scans",
    operation_id = "get_scan_config",
    summary = "Get a probe's scan configuration",
    params(("id" = u64, Path, description = "Node id of the probe")),
    responses(
        (status = 200, description = "The configuration, with `ETag` once one is stored", body = ProbeConfigView),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to read nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not have the role probe (`node.config.not_a_probe`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_scan_config(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    control: Control,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let control = control_or_stub(control, "GET", "/nodes/{id}/scan-config")?;
    let id = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::node(id))?;
    let view = control.config(id).await.map_err(failed)?;
    Ok(config_answer(view))
}

/// Replaces the scan configuration of a probe. The body is the `[scan]` section as JSON;
/// SNMP devices name operator secrets of the vault (`auth_secret`, `privacy_secret`) and
/// never passwords. The probe receives it within seconds and applies it atomically.
#[utoipa::path(
    put,
    path = "/nodes/{id}/scan-config",
    tag = "scans",
    operation_id = "update_scan_config",
    summary = "Replace a probe's scan configuration",
    params(
        ("id" = u64, Path, description = "Node id of the probe"),
        ("If-Match" = Option<String>, Header, description = "The revision read, as `\"12\"`; the write fails with 412 `node.config.revision_mismatch` when the configuration changed since")
    ),
    request_body(content = ScanConfig, content_type = "application/json"),
    responses(
        (status = 200, description = "The stored configuration, with `ETag`", body = ProbeConfigView),
        (status = 400, description = "The body is not valid JSON or a header is malformed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to change nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not have the role probe (`node.config.not_a_probe`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The configuration changed since it was read (`node.config.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "A key is out of range or a password is given inline (`node.config.invalid`), or a named secret does not exist or is not an operator secret (`node.config.secret`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No vault to check the secrets against (`node.config.vault_unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_scan_config(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    control: Control,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(config): ApiJson<ScanConfig>,
) -> Result<Response, ApiError> {
    let control = control_or_stub(control, "PUT", "/nodes/{id}/scan-config")?;
    let id = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(id))?;
    let expect = if_match(&headers)?;
    let view = control
        .put_config(&cx, id, config, expect)
        .await
        .map_err(failed)?;
    Ok(config_answer(view))
}

/// Switches the kill switch of one probe on: its running scans stop and none starts until
/// it is switched off. A probe that is offline gets the command when it connects again.
#[utoipa::path(
    post,
    path = "/nodes/{id}/scan/stop",
    tag = "scans",
    operation_id = "stop_node_scans",
    summary = "Stop a probe's scans",
    params(("id" = u64, Path, description = "Node id of the probe")),
    request_body(content = Option<StopRequest>, content_type = "application/json"),
    responses(
        (status = 202, description = "The command is recorded", body = KillSwitchResult),
        (status = 400, description = "The identifier or the body is malformed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to change nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not have the role probe (`node.config.not_a_probe`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn stop_node_scans(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    control: Control,
    Path(id): Path<String>,
    OptionalJson(body): OptionalJson<StopRequest>,
) -> Result<(StatusCode, Json<KillSwitchResult>), ApiError> {
    let control = control_or_stub(control, "POST", "/nodes/{id}/scan/stop")?;
    let id = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(id))?;
    let result = control
        .stop(&cx, Some(id), body.reason.as_deref())
        .await
        .map_err(failed)?;
    Ok((StatusCode::ACCEPTED, Json(result)))
}

/// Switches the kill switch of one probe off.
#[utoipa::path(
    post,
    path = "/nodes/{id}/scan/resume",
    tag = "scans",
    operation_id = "resume_node_scans",
    summary = "Resume a probe's scans",
    params(("id" = u64, Path, description = "Node id of the probe")),
    responses(
        (status = 202, description = "The command is recorded", body = KillSwitchResult),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to change nodes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such node (`cluster.node.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The node does not have the role probe (`node.config.not_a_probe`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn resume_node_scans(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    control: Control,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<KillSwitchResult>), ApiError> {
    let control = control_or_stub(control, "POST", "/nodes/{id}/scan/resume")?;
    let id = parse_node(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::node(id))?;
    let result = control.resume(&cx, Some(id)).await.map_err(failed)?;
    Ok((StatusCode::ACCEPTED, Json(result)))
}

/// Lists every probe: this controller's own probe role and the enrolled probes, each with
/// the state of its configuration and its kill switch.
#[utoipa::path(
    get,
    path = "/scans/probes",
    tag = "scans",
    operation_id = "list_scan_probes",
    summary = "List the probes",
    responses(
        (status = 200, description = "Every probe", body = ProbeList),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to read nodes", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_scan_probes(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    control: Control,
) -> Result<Json<ProbeList>, ApiError> {
    let control = control_or_stub(control, "GET", "/scans/probes")?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::singleton(ObjectKind::Node),
    )?;
    let items = control.probes().await.map_err(failed)?;
    Ok(Json(ProbeList { items }))
}

/// Switches the kill switch of every probe on (the installation-wide stop).
#[utoipa::path(
    post,
    path = "/scans/stop",
    tag = "scans",
    operation_id = "stop_scans",
    summary = "Stop every probe's scans",
    request_body(content = Option<StopRequest>, content_type = "application/json"),
    responses(
        (status = 202, description = "One command per probe is recorded", body = KillSwitchResult),
        (status = 400, description = "The body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to change nodes", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn stop_scans(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    control: Control,
    OptionalJson(body): OptionalJson<StopRequest>,
) -> Result<(StatusCode, Json<KillSwitchResult>), ApiError> {
    let control = control_or_stub(control, "POST", "/scans/stop")?;
    app.authorize(
        &cx.principal,
        Action::Update,
        &ObjectRef::singleton(ObjectKind::Node),
    )?;
    let result = control
        .stop(&cx, None, body.reason.as_deref())
        .await
        .map_err(failed)?;
    Ok((StatusCode::ACCEPTED, Json(result)))
}

/// Switches the kill switch of every probe off.
#[utoipa::path(
    post,
    path = "/scans/resume",
    tag = "scans",
    operation_id = "resume_scans",
    summary = "Resume every probe's scans",
    responses(
        (status = 202, description = "One command per probe is recorded", body = KillSwitchResult),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to change nodes", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn resume_scans(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    control: Control,
) -> Result<(StatusCode, Json<KillSwitchResult>), ApiError> {
    let control = control_or_stub(control, "POST", "/scans/resume")?;
    app.authorize(
        &cx.principal,
        Action::Update,
        &ObjectRef::singleton(ObjectKind::Node),
    )?;
    let result = control.resume(&cx, None).await.map_err(failed)?;
    Ok((StatusCode::ACCEPTED, Json(result)))
}

/// Starts a scan on demand of a prefix, a host, an address or a network: the probes whose
/// scope covers the target run the asked kinds (passive refresh when none is named) and
/// the job compares what they report with the facts from before.
#[utoipa::path(
    post,
    path = "/scans",
    tag = "scans",
    operation_id = "create_scan",
    summary = "Start a scan",
    request_body(content = ScanRequest, content_type = "application/json"),
    responses(
        (status = 202, description = "The run is queued; follow `GET /scans/{id}`", body = ScanView),
        (status = 400, description = "The body is not valid JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to scan the target", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The prefix or host does not exist (`scan.job.target`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The target cannot be scanned (`scan.job.target`), no probe covers it (`scan.job.no_probe`) or a value is out of range (`scan.job.invalid`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_scan(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    control: Control,
    ApiJson(request): ApiJson<ScanRequest>,
) -> Result<(StatusCode, Json<ScanView>), ApiError> {
    let control = control_or_stub(control, "POST", "/scans")?;
    app.authorize(&cx.principal, Action::Execute, &scan_object(&request))?;
    let view = control.submit(&cx, request).await.map_err(failed)?;
    Ok((StatusCode::ACCEPTED, Json(view)))
}

/// Lists the scans, newest first. Diffs carry their counts only; `GET /scans/{id}` has the
/// items.
#[utoipa::path(
    get,
    path = "/scans",
    tag = "scans",
    operation_id = "list_scans",
    summary = "List scans",
    params(crate::list::PageParams),
    responses(
        (status = 200, description = "A page of scans, newest first", body = Page<ScanView>),
        (status = 400, description = "A parameter is unknown or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to read jobs", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_scans(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    control: Control,
    filters: Filters,
) -> Result<Json<Page<ScanView>>, ApiError> {
    let control = control_or_stub(control, "GET", "/scans")?;
    filters.only(&[])?;
    let page = filters.page()?;
    let limit = page.limit()?;
    let scope = filters.scope(CURSOR_ENDPOINT);
    let before: Option<Uuid> = page.cursor(scope)?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::singleton(ObjectKind::Job),
    )?;
    let revision = app.store.status().revision;
    let (items, more) = control.scans(limit, before).await.map_err(failed)?;
    let next = if more {
        items.last().map(|last| encode_cursor(scope, &last.id))
    } else {
        None
    };
    Ok(Json(Page::new(items, next, revision)))
}

/// Shows one scan with every probe's progress and, once it ended, the whole diff.
#[utoipa::path(
    get,
    path = "/scans/{id}",
    tag = "scans",
    operation_id = "get_scan",
    summary = "Get a scan",
    params(("id" = String, Path, description = "Scan id (UUID)")),
    responses(
        (status = 200, description = "The scan", body = ScanView),
        (status = 400, description = "The identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed to read jobs", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such scan (`scan.job.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_scan(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    control: Control,
    Path(id): Path<String>,
) -> Result<Json<ScanView>, ApiError> {
    let control = control_or_stub(control, "GET", "/scans/{id}")?;
    let id = parse_run(&id)?;
    app.authorize(
        &cx.principal,
        Action::Read,
        &ObjectRef::singleton(ObjectKind::Job),
    )?;
    let view = control.scan(id).await.map_err(failed)?;
    Ok(Json(view))
}
