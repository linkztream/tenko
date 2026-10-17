//! Jobs and manual steps.
//!
//! Area: jobs. Owner: WP1.6. Requirements: IPAM-17.
//!
//! Long operations return `202` with a job; these endpoints list and show jobs, cancel
//! them, and complete a manual step. The handlers are thin: the job engine
//! ([`tenko_jobs::JobEngine`]) owns the rules, and its errors convert into problem details
//! with their own stable codes (`jobs.not_found`, `jobs.invalid_transition`,
//! `jobs.step.not_found`, `jobs.note.too_long`).
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /jobs` | 200 page of [`JobSummary`], newest first | 400 `jobs.query.invalid`, `sys.invalid_query`, `sys.invalid_cursor` |
//! | `GET /jobs/{id}` | 200 [`JobDetail`] | 400 `jobs.query.invalid`, `sys.invalid_query`, 403, 404 `jobs.not_found` |
//! | `POST /jobs/{id}/cancel` | 202 [`JobSummary`] | 400, 403, 404, 409 `jobs.invalid_transition` |
//! | `POST /jobs/{id}/steps/{index}/complete` | 200 [`JobSummary`] | 400, 403, 404 `jobs.not_found` or `jobs.step.not_found`, 409 |
//!
//! # The engine
//!
//! The server adds the engine to the router as a request extension
//! (`.layer(Extension(engine))`). Without it, every endpoint answers `501`
//! `sys.not_implemented`, exactly like the stub did, so the bare router of the route table
//! test keeps working.
//!
//! # Authorization
//!
//! With an [`Authorizer`](tenko_core::Authorizer) in the [`AppState`], reading one job
//! needs [`Action::Read`] on it, cancelling and completing need [`Action::Execute`], and
//! the list is empty when the principal may read no jobs. Without an authorizer every check
//! passes (development and tests). A job anchors to its targets (IAM-01): a scoped
//! principal lists and reads the jobs one of whose targets lies in its scope, and cancels
//! or completes those whose targets all do.
//!
//! # List conventions
//!
//! `GET /jobs` follows the list conventions of plan section 4 with the shared helpers of
//! [`crate::list`]: `limit` (1 to 1,000), an opaque `cursor` and `at_least=<revision>`,
//! answered as a [`crate::dto::Page`] (`{ items, next_cursor, revision }`). The cursor is
//! bound to the filters of the request, so a cursor replayed with other filters is refused.
//!
//! Two families of 400 problems come out of a list request:
//!
//! - The shared helpers answer `sys.invalid_query` for an unknown or repeated parameter, a
//!   bad `limit` or `at_least`, and `sys.invalid_cursor` for a bad or foreign cursor.
//! - This area answers `jobs.query.invalid` (parameters `param` and `value`) for values that
//!   only jobs understand: a bad `state`, `kind`, `target` or `group`, and a malformed job
//!   id or step index in the path.
//!
//! `group=<key>` lists the jobs of one parallelism group (the jobs of a bulk move), and
//! every [`JobSummary`] names the handler kind of its current step (`current_step_kind`).

use std::{collections::BTreeMap, fmt, sync::Arc};

use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::StatusCode,
};
use serde::{
    Deserialize,
    de::{IntoDeserializer, value::StrDeserializer},
};
use tenko_core::{
    Action, Coded, CodedError, JobId, ObjectKind, ObjectRef, RequestCtx, Revision, error::codes,
};
use tenko_ipam::scope::ScopeIndex;
use tenko_jobs::{
    JobDetail, JobEngine, JobKind, JobPage, JobQuery, JobState, JobSummary,
    model::GroupKey,
    query::{JobFilter, list_filtered},
};
use tenko_store::ReadConsistency;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{common::read_scope, not_implemented};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, Filters, PageParams, encode_cursor},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The query parameters of `GET /jobs` besides the paging parameters.
const LIST_PARAMS: [&str; 4] = ["state", "kind", "target", "group"];

/// Names the endpoint in cursors, so that a cursor from another list is refused.
const CURSOR_ENDPOINT: &str = "jobs.jobs";

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_jobs))
        .routes(routes!(get_job))
        .routes(routes!(cancel_job))
        .routes(routes!(complete_job_step))
}

/// The error code of a query or path parameter that the endpoints of this area cannot accept.
/// A malformed request body is `sys.invalid_request`.
const INVALID_QUERY: &str = "jobs.query.invalid";

/// Longest parameter value that an error repeats back, in characters.
const ECHO_LIMIT: usize = 128;

/// A request parameter that is malformed or unknown: `jobs.query.invalid` (400) with the
/// parameters `param` (its name) and `value` (what was sent, clipped).
#[derive(Debug, Clone, PartialEq, Eq)]
struct QueryError {
    /// The name of the parameter, for example `state` or `id`.
    param: String,
    /// The rejected value, clipped to [`ECHO_LIMIT`] characters.
    value: String,
    /// Why the value was rejected, in English.
    reason: &'static str,
}

impl QueryError {
    /// An error for the parameter `param` with the rejected `value`.
    fn new(param: &str, value: &str, reason: &'static str) -> Self {
        Self {
            param: param.to_owned(),
            value: value.chars().take(ECHO_LIMIT).collect(),
            reason,
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid parameter `{}` with value `{}`: {}",
            self.param, self.value, self.reason
        )
    }
}

impl Coded for QueryError {
    fn code(&self) -> &'static str {
        INVALID_QUERY
    }

    fn http_status(&self) -> u16 {
        400
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        BTreeMap::from([("param", self.param.clone()), ("value", self.value.clone())])
    }

    fn title(&self) -> &'static str {
        "Invalid request parameter"
    }
}

/// The filters of `GET /jobs`. Declares the query parameters in the OpenAPI document and
/// carries the parsed values; the paging parameters are [`PageParams`].
#[derive(Debug, Default, IntoParams)]
#[into_params(parameter_in = Query)]
struct JobFilters {
    /// Only jobs in one of these states. Repeat the parameter or separate the names with
    /// commas: `state=waiting&state=queued` and `state=waiting,queued` are the same.
    #[param(style = Form, explode = true, required = false, value_type = Vec<JobState>)]
    state: Vec<JobState>,
    /// Only jobs of one of these kinds, for example `ipam.move`. Repeat the parameter or
    /// separate the names with commas.
    #[param(style = Form, explode = true, required = false, value_type = Vec<JobKind>)]
    kind: Vec<JobKind>,
    /// Only jobs that change this object, written `kind/uuid`, for example
    /// `host/0190d1c2-0000-7000-8000-000000000001`.
    #[param(required = false, value_type = String)]
    target: Option<ObjectRef>,
    /// Only jobs of this parallelism group, for example the jobs of one bulk move.
    #[param(required = false, value_type = String)]
    group: Option<GroupKey>,
}

impl JobFilters {
    /// Reads the job filters from the query string.
    ///
    /// # Errors
    ///
    /// `jobs.query.invalid` for a state, kind or target that is not valid, and
    /// `sys.invalid_query` for a repeated `target`.
    fn from_filters(filters: &Filters) -> Result<Self, ApiError> {
        let state = filters
            .all("state")
            .into_iter()
            .map(parse_state)
            .collect::<Result<Vec<_>, QueryError>>()?;
        let kind = filters
            .all("kind")
            .into_iter()
            .map(parse_kind)
            .collect::<Result<Vec<_>, QueryError>>()?;
        let target = filters.get("target")?.map(parse_target).transpose()?;
        let group = filters
            .get("group")?
            .map(|raw| {
                GroupKey::new(raw.to_owned())
                    .map_err(|_| QueryError::new("group", raw, "not a group key"))
            })
            .transpose()?;
        Ok(Self {
            state,
            kind,
            target,
            group,
        })
    }

    /// The engine query for these filters, this page and the cursor scope of the request,
    /// with the group filter apart.
    fn into_query(
        self,
        page: &PageParams,
        scope: CursorScope,
    ) -> Result<(JobQuery, Option<GroupKey>), ApiError> {
        Ok((
            JobQuery {
                states: self.state,
                kinds: self.kind,
                target: self.target,
                limit: page.limit()?,
                cursor: page.cursor::<JobId>(scope)?,
                at_least: page.at_least.map(Revision),
            },
            self.group,
        ))
    }
}

/// Body of `POST /jobs/{id}/steps/{index}/complete`. The whole body is optional.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct CompleteStepRequest {
    /// What was done, kept in the job's transition log and in the audit record. At most
    /// 4,096 bytes.
    #[serde(default)]
    note: Option<String>,
}

/// Parses a job state name (`waiting`, `rolling_back`, ...).
fn parse_state(name: &str) -> Result<JobState, QueryError> {
    let name_deserializer: StrDeserializer<'_, serde::de::value::Error> = name.into_deserializer();
    JobState::deserialize(name_deserializer)
        .map_err(|_| QueryError::new("state", name, "not a job state"))
}

/// Parses a job kind such as `ipam.move`.
fn parse_kind(name: &str) -> Result<JobKind, QueryError> {
    JobKind::new(name.to_owned()).map_err(|_| QueryError::new("kind", name, "not a job kind"))
}

/// Parses `kind/uuid`, the written form of an [`ObjectRef`].
fn parse_target(raw: &str) -> Result<ObjectRef, QueryError> {
    let invalid = |reason| QueryError::new("target", raw, reason);
    let (kind, id) = raw
        .split_once('/')
        .ok_or_else(|| invalid("expected kind/uuid"))?;
    let kind: ObjectKind = kind.parse().map_err(|_| invalid("not an object kind"))?;
    // `tenko-api` has no direct `uuid` dependency; `JobId` parses a UUID like any other
    // identifier does.
    let id: JobId = id.parse().map_err(|_| invalid("not a UUID"))?;
    Ok(ObjectRef::new(kind, id.uuid()))
}

/// Parses the `{id}` path segment.
fn parse_id(raw: &str) -> Result<JobId, QueryError> {
    raw.parse()
        .map_err(|_| QueryError::new("id", raw, "not a job identifier (UUID)"))
}

/// Parses the `{index}` path segment.
fn parse_index(raw: &str) -> Result<u16, QueryError> {
    raw.parse().map_err(|_| {
        QueryError::new(
            "index",
            raw,
            "not a step index (a whole number from 0 to 65535)",
        )
    })
}

/// The engine, or the `501` stub answer when the server did not add one.
fn engine_or_stub(
    engine: Option<Extension<JobEngine>>,
    method: &str,
    path: &str,
) -> Result<JobEngine, ApiError> {
    engine
        .map(|Extension(engine)| engine)
        .ok_or_else(|| not_implemented(method, path))
}

/// Checks `action` on one job for the principal of the request. Passes when the state has
/// no authorizer.
fn authorize(app: &AppState, cx: &RequestCtx, action: Action, job: JobId) -> Result<(), ApiError> {
    app.authorize(&cx.principal, action, &ObjectRef::from(job))
}

/// The `at_least` revision of the request for one job. A single job has no pages, so the
/// paging parameters other than `at_least` are refused as unknown.
fn detail_at_least(filters: &Filters) -> Result<Option<Revision>, ApiError> {
    filters.only(&[])?;
    if let Some((name, _)) = filters
        .pairs()
        .iter()
        .find(|(name, _)| name == "limit" || name == "cursor")
    {
        return Err(ApiError::invalid_query(name, "unknown parameter"));
    }
    Ok(filters.page()?.at_least.map(Revision))
}

/// The page of a list that shows nothing, with the current revision of the store, so that
/// an empty answer still tells the client where to resume its event stream.
fn empty_page(engine: &JobEngine) -> Page<JobSummary> {
    Page::new(Vec::new(), None, engine.revision())
}

/// Turns the engine's page into the wire page: the cursor becomes an opaque string bound
/// to the `scope` of the request.
fn wire_page(page: JobPage, scope: CursorScope) -> Page<JobSummary> {
    Page::new(
        page.items,
        page.next_cursor.map(|id| encode_cursor(scope, &id)),
        page.revision,
    )
}

/// Lists jobs, newest first, with optional filters and paging.
///
/// Filter by state, kind or target object. The answer carries the revision it was read at,
/// so that a client can follow up with the event stream from there, and a cursor for the
/// next page while there is one. Without permission to read jobs the list is empty.
#[utoipa::path(
    get,
    path = "/jobs",
    tag = "jobs",
    operation_id = "list_jobs",
    summary = "List jobs",
    params(JobFilters, PageParams),
    responses(
        (status = 200, description = "A page of jobs, newest first", body = Page<JobSummary>),
        (status = 400, description = "A parameter is unknown, repeated or malformed (`sys.invalid_query`, `jobs.query.invalid`) or the cursor is bad (`sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_jobs(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    engine: Option<Extension<JobEngine>>,
    index: Option<Extension<Arc<ScopeIndex>>>,
    filters: Filters,
) -> Result<Json<Page<JobSummary>>, ApiError> {
    let engine = engine_or_stub(engine, "GET", "/jobs")?;
    filters.only(&LIST_PARAMS)?;
    let page = filters.page()?;
    let scope = filters.scope(CURSOR_ENDPOINT);
    let (query, group) = JobFilters::from_filters(&filters)?.into_query(&page, scope)?;
    let readable = read_scope(
        app.authorizer.as_deref(),
        index.map(|Extension(index)| index),
        &cx,
        ObjectKind::Job,
    );
    if readable.is_nothing() {
        return Ok(Json(empty_page(&engine)));
    }
    if readable.is_all() && group.is_none() {
        return Ok(Json(wire_page(engine.list(&query).await?, scope)));
    }
    // A group, or a scoped principal: filtered while scanning, so pages stay full.
    let view = app
        .store
        .read(match query.at_least {
            Some(revision) => ReadConsistency::AtLeast(revision),
            None => ReadConsistency::Local,
        })
        .await?;
    let keep = |job: &tenko_jobs::model::Job| {
        readable.admits_targets(ObjectRef::from(job.id), &job.spec.targets)
    };
    let filter = JobFilter {
        group,
        keep: if readable.is_all() { None } else { Some(&keep) },
    };
    Ok(Json(wire_page(
        list_filtered(view.as_ref(), &query, &filter)?,
        scope,
    )))
}

/// Shows one job: its steps, the transition log and the preview computed at submission.
///
/// `at_least=<revision>` waits until the store has reached the revision, so that a client
/// reads its own writes.
#[utoipa::path(
    get,
    path = "/jobs/{id}",
    tag = "jobs",
    operation_id = "get_job",
    summary = "Get one job with its steps",
    params(
        ("id" = String, Path, description = "Job identifier (UUID)"),
        ("at_least" = Option<u64>, Query, description = "Read at least at this store revision (read-your-writes)")
    ),
    responses(
        (status = 200, description = "The job with its steps, transitions and preview", body = JobDetail),
        (status = 400, description = "The identifier is malformed (`jobs.query.invalid`) or a parameter is unknown or malformed (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read the job", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such job (`jobs.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_job(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    engine: Option<Extension<JobEngine>>,
    Path(id): Path<String>,
    filters: Filters,
) -> Result<Json<JobDetail>, ApiError> {
    let engine = engine_or_stub(engine, "GET", "/jobs/{id}")?;
    let id = parse_id(&id)?;
    let at_least = detail_at_least(&filters)?;
    authorize(&app, &cx, Action::Read, id)?;
    Ok(Json(engine.detail(id, at_least).await?))
}

/// Cancels a job.
///
/// A queued job is cancelled at once. A running or waiting job is marked: the runner stops
/// it at the next step boundary, rolls back what ran and ends it as `cancelled`; the answer
/// shows `cancel_requested: true` until then. Cancelling twice is harmless. A job that is
/// rolling back or finished cannot be cancelled.
#[utoipa::path(
    post,
    path = "/jobs/{id}/cancel",
    tag = "jobs",
    operation_id = "cancel_job",
    summary = "Cancel a job",
    params(("id" = String, Path, description = "Job identifier (UUID)")),
    responses(
        (status = 202, description = "The cancellation was accepted; the job after the request", body = JobSummary),
        (status = 400, description = "The identifier is malformed (`jobs.query.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not cancel the job", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such job (`jobs.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The job is rolling back or finished (`jobs.invalid_transition`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn cancel_job(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    engine: Option<Extension<JobEngine>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<JobSummary>), ApiError> {
    let engine = engine_or_stub(engine, "POST", "/jobs/{id}/cancel")?;
    let id = parse_id(&id)?;
    authorize(&app, &cx, Action::Execute, id)?;
    engine.cancel(id, &cx).await?;
    let job = engine.job(id).await?;
    Ok((StatusCode::ACCEPTED, Json(JobSummary::from(&job))))
}

/// Marks a manual step as done.
///
/// The step must be waiting for a person. The optional note is kept in the transition log
/// and the audit record. The job continues with its next step. The body may be empty.
#[utoipa::path(
    post,
    path = "/jobs/{id}/steps/{index}/complete",
    tag = "jobs",
    operation_id = "complete_job_step",
    summary = "Complete a manual step of a job",
    params(
        ("id" = String, Path, description = "Job identifier (UUID)"),
        ("index" = u16, Path, description = "Zero-based index of the step")
    ),
    request_body(
        content = Option<CompleteStepRequest>,
        description = "An optional note about what was done",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "The step is done; the job after the request", body = JobSummary),
        (status = 400, description = "A parameter or the body is malformed (`jobs.query.invalid`, `sys.invalid_request`) or the note is longer than 4,096 bytes (`jobs.note.too_long`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not complete steps of the job", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such job or step (`jobs.not_found`, `jobs.step.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The step is not waiting for a person (`jobs.invalid_transition`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn complete_job_step(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    engine: Option<Extension<JobEngine>>,
    Path((id, index)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<JobSummary>, ApiError> {
    let engine = engine_or_stub(engine, "POST", "/jobs/{id}/steps/{index}/complete")?;
    let id = parse_id(&id)?;
    let index = parse_index(&index)?;
    authorize(&app, &cx, Action::Execute, id)?;
    let request = parse_complete_body(body)?;
    engine.complete_manual(id, index, request.note, &cx).await?;
    let job = engine.job(id).await?;
    Ok(Json(JobSummary::from(&job)))
}

/// Reads the optional body of the complete endpoint: empty, or `{ "note": ... }`.
fn parse_complete_body(
    body: Result<Bytes, BytesRejection>,
) -> Result<CompleteStepRequest, ApiError> {
    let bad_request = |status: u16, detail: String| {
        ApiError::from_coded_error(CodedError::new(codes::INVALID_REQUEST, status, detail))
    };
    let bytes = body.map_err(|rejection| {
        bad_request(
            rejection.status().as_u16(),
            "the request body cannot be read".to_owned(),
        )
    })?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(CompleteStepRequest::default());
    }
    // A struct would also accept a JSON array of its fields; the body is an object.
    if bytes.trim_ascii_start().first() != Some(&b'{') {
        return Err(bad_request(
            400,
            "the request body must be a JSON object".to_owned(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| bad_request(400, format!("the request body is not valid: {error}")))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use serde_json::{Value, json};
    use tenko_core::{
        Authorizer, Denied, DenyReason, HostId, MessageKey, Principal, SystemComponent,
    };
    use tenko_jobs::{
        EngineConfig, JobSpec, ManualStep, ManualTask, MockClock,
        query::MAX_LIMIT as ENGINE_MAX_LIMIT,
    };
    use tenko_store::MemStore;
    use tower::ServiceExt;

    use super::*;
    use crate::{API_BASE, problem::PROBLEM_JSON};

    /// A decoded response.
    struct Reply {
        status: StatusCode,
        content_type: String,
        body: Value,
    }

    impl Reply {
        /// Asserts a problem document with this status and code.
        fn assert_problem(&self, status: u16, code: &str) {
            let label = format!("{} {}", self.status, self.body);
            assert_eq!(self.status.as_u16(), status, "{label}");
            assert_eq!(self.content_type, PROBLEM_JSON, "{label}");
            assert_eq!(self.body["code"], code, "{label}");
            assert_eq!(self.body["status"], status, "{label}");
        }

        /// Asserts a `200 OK` JSON answer.
        fn assert_ok(&self) {
            assert_eq!(self.status, StatusCode::OK, "{}", self.body);
            assert_eq!(self.content_type, "application/json");
        }

        /// Asserts that a list answer has no items.
        fn assert_no_items(&self) {
            assert_eq!(self.item_ids(), Vec::<String>::new(), "{}", self.body);
        }

        /// The ids of the items of a list answer.
        fn item_ids(&self) -> Vec<String> {
            self.body["items"]
                .as_array()
                .expect("items array")
                .iter()
                .map(|item| item["id"].as_str().expect("id").to_owned())
                .collect()
        }
    }

    fn uri(path: &str) -> String {
        format!("{API_BASE}{path}")
    }

    /// A router of the jobs routes under the API base.
    fn app(engine: Option<&JobEngine>, authorizer: Option<Arc<dyn Authorizer>>) -> Router {
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let router = router.with_state(AppState {
            authorizer,
            ..AppState::default()
        });
        match engine {
            Some(engine) => router.layer(Extension(engine.clone())),
            None => router,
        }
    }

    async fn send(router: &Router, method: &str, path: &str, body: Option<&str>) -> Reply {
        let mut builder = Request::builder().method(method).uri(uri(path));
        let body = match body {
            Some(text) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(text.to_owned())
            }
            None => Body::empty(),
        };
        let response = router
            .clone()
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|value| value.to_str().expect("content type text").to_owned())
            .unwrap_or_default();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("JSON body")
        };
        Reply {
            status,
            content_type,
            body,
        }
    }

    async fn get(router: &Router, path: &str) -> Reply {
        send(router, "GET", path, None).await
    }

    async fn post(router: &Router, path: &str) -> Reply {
        send(router, "POST", path, None).await
    }

    fn engine() -> JobEngine {
        JobEngine::with_clock(
            Arc::new(MemStore::default()),
            EngineConfig::default(),
            Arc::new(MockClock::default()),
        )
    }

    fn host() -> ObjectRef {
        ObjectRef::from(HostId::generate())
    }

    /// A job of one manual step that changes `target`.
    fn spec(kind: &'static str, target: ObjectRef) -> JobSpec {
        let task = ManualTask {
            instruction: MessageKey::from_static("ipam.move.dhcp_step"),
            args: BTreeMap::from([("host".to_owned(), "printer-01".to_owned())]),
            undo: None,
        };
        JobSpec {
            kind: JobKind::from_static(kind),
            title: MessageKey::from_static("ipam.move.title"),
            targets: vec![target],
            steps: vec![ManualStep::spec(&task, None).expect("task encodes")],
            timeout: Duration::from_secs(3600),
            group: None,
            group_limit: None,
            idempotency: None,
            node: None,
        }
    }

    async fn queued(engine: &JobEngine, kind: &'static str, target: ObjectRef) -> JobId {
        engine
            .submit(
                spec(kind, target),
                &RequestCtx::system(SystemComponent::Api),
            )
            .await
            .expect("submit")
    }

    /// A job that waits for a person to do its manual step.
    async fn waiting(engine: &JobEngine, kind: &'static str, target: ObjectRef) -> JobId {
        let id = queued(engine, kind, target).await;
        let job = engine.drive_once(id).await.expect("drive");
        assert_eq!(job.state, JobState::Waiting);
        id
    }

    /// Three jobs: one waiting `ipam.move` on `target`, two queued `import.apply`.
    async fn three_jobs(engine: &JobEngine) -> (JobId, ObjectRef) {
        let target = host();
        let first = waiting(engine, "ipam.move", target).await;
        queued(engine, "import.apply", host()).await;
        queued(engine, "import.apply", host()).await;
        (first, target)
    }

    fn ids_newest_first(mut ids: Vec<String>) -> Vec<String> {
        ids.sort_unstable_by(|a, b| b.cmp(a));
        ids
    }

    // Listing.

    #[tokio::test]
    async fn list_without_a_filter_returns_every_job_newest_first() {
        let engine = engine();
        three_jobs(&engine).await;
        let router = app(Some(&engine), None);
        let reply = get(&router, "/jobs").await;
        reply.assert_ok();
        let ids = reply.item_ids();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids, ids_newest_first(ids.clone()));
        assert_eq!(reply.body["next_cursor"], Value::Null);
        assert!(reply.body["revision"].as_u64().expect("revision") > 0);
        let first = &reply.body["items"][0];
        assert!(first["kind"].is_string());
        assert!(first["step_count"].is_number());
        assert_eq!(first["cancel_requested"], false);
    }

    #[tokio::test]
    async fn list_of_an_empty_store_is_an_empty_page() {
        let engine = engine();
        let reply = get(&app(Some(&engine), None), "/jobs").await;
        reply.assert_ok();
        assert_eq!(reply.body["items"], json!([]));
        assert_eq!(reply.body["next_cursor"], Value::Null);
    }

    #[tokio::test]
    async fn list_filters_by_state() {
        let engine = engine();
        three_jobs(&engine).await;
        let router = app(Some(&engine), None);
        let waiting = get(&router, "/jobs?state=waiting").await;
        waiting.assert_ok();
        assert_eq!(waiting.item_ids().len(), 1);
        assert_eq!(waiting.body["items"][0]["state"], "waiting");
        assert_eq!(waiting.body["items"][0]["manual_steps"], json!([0]));
        let queued = get(&router, "/jobs?state=queued").await;
        assert_eq!(queued.item_ids().len(), 2);
        let none = get(&router, "/jobs?state=succeeded").await;
        none.assert_ok();
        none.assert_no_items();
    }

    #[tokio::test]
    async fn list_accepts_repeated_and_comma_separated_states() {
        let engine = engine();
        three_jobs(&engine).await;
        let router = app(Some(&engine), None);
        for query in [
            "state=waiting&state=queued",
            "state=waiting,queued",
            "state=queued,waiting&state=waiting",
        ] {
            let reply = get(&router, &format!("/jobs?{query}")).await;
            reply.assert_ok();
            assert_eq!(reply.item_ids().len(), 3, "{query}");
        }
        let both_missing = get(&router, "/jobs?state=succeeded,failed").await;
        both_missing.assert_no_items();
    }

    #[tokio::test]
    async fn list_ignores_blank_filter_values() {
        let engine = engine();
        three_jobs(&engine).await;
        let router = app(Some(&engine), None);
        for query in ["state=", "state=&kind=", "state=waiting,queued,", "target="] {
            let reply = get(&router, &format!("/jobs?{query}")).await;
            reply.assert_ok();
            assert_eq!(reply.item_ids().len(), 3, "{query}");
        }
        let one = get(&router, "/jobs?state=waiting,").await;
        assert_eq!(one.item_ids().len(), 1);
    }

    #[tokio::test]
    async fn list_filters_by_kind() {
        let engine = engine();
        three_jobs(&engine).await;
        let router = app(Some(&engine), None);
        let moves = get(&router, "/jobs?kind=ipam.move").await;
        moves.assert_ok();
        assert_eq!(moves.item_ids().len(), 1);
        assert_eq!(moves.body["items"][0]["kind"], "ipam.move");
        let imports = get(&router, "/jobs?kind=import.apply").await;
        assert_eq!(imports.item_ids().len(), 2);
        let both = get(&router, "/jobs?kind=import.apply&kind=ipam.move").await;
        assert_eq!(both.item_ids().len(), 3);
        let comma = get(&router, "/jobs?kind=import.apply,ipam.move").await;
        assert_eq!(comma.item_ids().len(), 3);
        let other = get(&router, "/jobs?kind=ipam.edit").await;
        other.assert_no_items();
        let combined = get(&router, "/jobs?kind=import.apply&state=waiting").await;
        combined.assert_no_items();
    }

    #[tokio::test]
    async fn list_filters_by_target() {
        let engine = engine();
        let (first, target) = three_jobs(&engine).await;
        let router = app(Some(&engine), None);
        for path in [
            format!("/jobs?target={target}"),
            format!("/jobs?target=host%2F{}", target.id),
        ] {
            let reply = get(&router, &path).await;
            reply.assert_ok();
            assert_eq!(reply.item_ids(), vec![first.to_string()], "{path}");
            assert_eq!(
                reply.body["items"][0]["targets"][0],
                json!({ "kind": "host", "id": target.id.to_string() })
            );
        }
        let unknown = get(&router, &format!("/jobs?target={}", host())).await;
        unknown.assert_ok();
        unknown.assert_no_items();
    }

    #[tokio::test]
    async fn list_pages_with_the_returned_cursor() {
        let engine = engine();
        three_jobs(&engine).await;
        let router = app(Some(&engine), None);
        let all = get(&router, "/jobs").await.item_ids();
        assert_eq!(all.len(), 3);

        let mut seen: Vec<String> = Vec::new();
        let mut path = "/jobs?limit=1".to_owned();
        let mut pages = 0;
        loop {
            let reply = get(&router, &path).await;
            reply.assert_ok();
            pages += 1;
            assert!(pages <= 3, "the cursor does not advance");
            let ids = reply.item_ids();
            assert_eq!(ids.len(), 1);
            seen.extend(ids);
            match reply.body["next_cursor"].as_str() {
                Some(cursor) => {
                    // Base64url: safe in a URL and not readable as a job id.
                    assert!(
                        cursor
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                        "{cursor}"
                    );
                    assert!(!seen.iter().any(|id| cursor.contains(id.as_str())));
                    path = format!("/jobs?limit=1&cursor={cursor}");
                }
                None => break,
            }
        }
        assert_eq!(pages, 3);
        assert_eq!(seen, all, "no duplicates, newest first");
        let mut unique = seen.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 3);
    }

    #[tokio::test]
    async fn list_pages_keep_their_filters() {
        let engine = engine();
        three_jobs(&engine).await;
        let router = app(Some(&engine), None);
        let first = get(&router, "/jobs?state=queued&limit=1").await;
        let cursor = first.body["next_cursor"].as_str().expect("cursor");
        let second = get(
            &router,
            &format!("/jobs?state=queued&limit=1&cursor={cursor}"),
        )
        .await;
        assert_eq!(second.item_ids().len(), 1);
        assert_eq!(second.body["next_cursor"], Value::Null);
        assert_ne!(first.item_ids(), second.item_ids());
    }

    #[tokio::test]
    async fn list_honours_at_least() {
        let engine = engine();
        three_jobs(&engine).await;
        let router = app(Some(&engine), None);
        let first = get(&router, "/jobs").await;
        let revision = first.body["revision"].as_u64().expect("revision");
        let again = get(&router, &format!("/jobs?at_least={revision}")).await;
        again.assert_ok();
        assert!(again.body["revision"].as_u64().expect("revision") >= revision);
    }

    #[tokio::test]
    async fn list_rejects_bad_parameters() {
        let engine = engine();
        three_jobs(&engine).await;
        let router = app(Some(&engine), None);
        let target = format!("host/{}", HostId::generate());
        let other = "lease/0190d1c2-0000-7000-8000-000000000001";

        // Values only jobs understand: `jobs.query.invalid` with `param` and `value`.
        let job_specific: Vec<(String, &str, String)> = vec![
            ("state=bogus".into(), "state", "bogus".into()),
            ("state=waiting,bogus".into(), "state", "bogus".into()),
            ("state=Waiting".into(), "state", "Waiting".into()),
            ("kind=Bad".into(), "kind", "Bad".into()),
            ("kind=nope.thing".into(), "kind", "nope.thing".into()),
            ("target=host".into(), "target", "host".into()),
            (format!("target={other}"), "target", other.into()),
            (
                "target=host/not-a-uuid".into(),
                "target",
                "host/not-a-uuid".into(),
            ),
        ];
        for (query, param, value) in job_specific {
            let reply = get(&router, &format!("/jobs?{query}")).await;
            reply.assert_problem(400, "jobs.query.invalid");
            assert_eq!(reply.body["params"]["param"], param, "{query}");
            assert_eq!(reply.body["params"]["value"], value, "{query}");
            assert_eq!(reply.body["title"], "Invalid request parameter", "{query}");
        }

        // Unknown, repeated or malformed parameters: the shared `sys.invalid_query`.
        let shared: Vec<(String, &str)> = vec![
            (format!("target={target}&target={target}"), "target"),
            ("limit=0".into(), "limit"),
            ("limit=1001".into(), "limit"),
            ("limit=-1".into(), "limit"),
            ("limit=abc".into(), "limit"),
            ("limit=1&limit=2".into(), "limit"),
            ("at_least=soon".into(), "at_least"),
            ("colour=red".into(), "colour"),
            ("state=waiting&sort=-updated".into(), "sort"),
        ];
        for (query, parameter) in shared {
            let reply = get(&router, &format!("/jobs?{query}")).await;
            reply.assert_problem(400, "sys.invalid_query");
            assert_eq!(reply.body["params"]["parameter"], parameter, "{query}");
        }

        // A bad cursor: the shared `sys.invalid_cursor`.
        for cursor in ["garbage", "v1.1234", "e30", "!!!!"] {
            let reply = get(&router, &format!("/jobs?cursor={cursor}")).await;
            reply.assert_problem(400, "sys.invalid_cursor");
        }
    }

    #[tokio::test]
    async fn a_cursor_of_another_filter_set_is_refused() {
        let engine = engine();
        three_jobs(&engine).await;
        let router = app(Some(&engine), None);
        let first = get(&router, "/jobs?state=queued&limit=1").await;
        let cursor = first.body["next_cursor"].as_str().expect("cursor");

        // The same filters, in another order and with another page size, still match.
        let same = get(
            &router,
            &format!("/jobs?limit=2&cursor={cursor}&state=queued"),
        )
        .await;
        same.assert_ok();
        assert_eq!(same.item_ids().len(), 1);

        // Other filters, or none at all, do not.
        for query in [
            format!("state=waiting&cursor={cursor}"),
            format!("state=queued&kind=ipam.move&cursor={cursor}"),
            format!("cursor={cursor}"),
        ] {
            let reply = get(&router, &format!("/jobs?{query}")).await;
            reply.assert_problem(400, "sys.invalid_cursor");
        }
    }

    #[tokio::test]
    async fn list_accepts_the_largest_page() {
        let engine = engine();
        three_jobs(&engine).await;
        let reply = get(&app(Some(&engine), None), "/jobs?limit=1000").await;
        reply.assert_ok();
        assert_eq!(reply.item_ids().len(), 3);
    }

    #[tokio::test]
    async fn a_long_bad_value_is_clipped_in_the_problem() {
        let engine = engine();
        let long = "x".repeat(500);
        let reply = get(&app(Some(&engine), None), &format!("/jobs?state={long}")).await;
        reply.assert_problem(400, "jobs.query.invalid");
        assert_eq!(
            reply.body["params"]["value"].as_str().expect("value").len(),
            ECHO_LIMIT
        );
    }

    // One job.

    #[tokio::test]
    async fn get_returns_the_job_with_steps_transitions_and_preview() {
        let engine = engine();
        let target = host();
        let id = waiting(&engine, "ipam.move", target).await;
        let reply = get(&app(Some(&engine), None), &format!("/jobs/{id}")).await;
        reply.assert_ok();
        let job = &reply.body["job"];
        assert_eq!(job["id"], id.to_string());
        assert_eq!(job["state"], "waiting");
        assert_eq!(job["spec"]["kind"], "ipam.move");
        assert_eq!(job["steps"].as_array().expect("steps").len(), 1);
        assert_eq!(job["steps"][0]["kind"], "jobs.manual");
        assert_eq!(job["steps"][0]["state"]["state"], "waiting_for_manual");
        assert_eq!(
            job["steps"][0]["state"]["data"]["task"]["instruction"],
            "ipam.move.dhcp_step"
        );
        let transitions = reply.body["transitions"].as_array().expect("transitions");
        assert!(transitions.len() >= 2, "{transitions:?}");
        assert_eq!(transitions[0]["event"], "submitted");
        assert_eq!(transitions[0]["state"], "queued");
        assert!(reply.body["preview"]["steps"][0]["summary"].is_string());
        assert!(reply.body["preview"]["steps"][0]["manual"].is_object());
        assert!(reply.body["revision"].as_u64().expect("revision") > 0);
    }

    #[tokio::test]
    async fn get_honours_at_least() {
        let engine = engine();
        let id = waiting(&engine, "ipam.move", host()).await;
        let router = app(Some(&engine), None);
        let first = get(&router, &format!("/jobs/{id}")).await;
        let revision = first.body["revision"].as_u64().expect("revision");
        let again = get(&router, &format!("/jobs/{id}?at_least={revision}")).await;
        again.assert_ok();
        let bad = get(&router, &format!("/jobs/{id}?at_least=later")).await;
        bad.assert_problem(400, "sys.invalid_query");
        assert_eq!(bad.body["params"]["parameter"], "at_least");
        // A single job has no pages, nor other filters.
        for (query, parameter) in [
            ("limit=5", "limit"),
            ("cursor=abc", "cursor"),
            ("state=waiting", "state"),
        ] {
            let reply = get(&router, &format!("/jobs/{id}?{query}")).await;
            reply.assert_problem(400, "sys.invalid_query");
            assert_eq!(reply.body["params"]["parameter"], parameter, "{query}");
        }
    }

    #[tokio::test]
    async fn get_of_an_unknown_job_is_not_found() {
        let engine = engine();
        let id = JobId::generate();
        let reply = get(&app(Some(&engine), None), &format!("/jobs/{id}")).await;
        reply.assert_problem(404, "jobs.not_found");
        assert_eq!(reply.body["params"]["job"], id.to_string());
    }

    #[tokio::test]
    async fn a_malformed_job_id_is_a_problem_not_plain_text() {
        let engine = engine();
        let router = app(Some(&engine), None);
        for path in [
            "/jobs/not-a-uuid",
            "/jobs/not-a-uuid/cancel",
            "/jobs/12345/steps/0/complete",
        ] {
            let reply = if path.ends_with("/jobs/not-a-uuid") {
                get(&router, path).await
            } else {
                post(&router, path).await
            };
            reply.assert_problem(400, "jobs.query.invalid");
            assert_eq!(reply.body["params"]["param"], "id", "{path}");
        }
    }

    // Cancel.

    #[tokio::test]
    async fn cancelling_a_waiting_job_requests_the_cancellation() {
        let engine = engine();
        let id = waiting(&engine, "ipam.move", host()).await;
        let router = app(Some(&engine), None);
        let reply = post(&router, &format!("/jobs/{id}/cancel")).await;
        assert_eq!(reply.status, StatusCode::ACCEPTED, "{}", reply.body);
        assert_eq!(reply.content_type, "application/json");
        assert_eq!(reply.body["id"], id.to_string());
        assert_eq!(reply.body["cancel_requested"], true);
        // Without a runner the job stays where it was; the runner rolls it back.
        assert_eq!(reply.body["state"], "waiting");
        // Cancelling again is harmless.
        let again = post(&router, &format!("/jobs/{id}/cancel")).await;
        assert_eq!(again.status, StatusCode::ACCEPTED);
        assert_eq!(again.body["cancel_requested"], true);
    }

    #[tokio::test]
    async fn cancelling_a_queued_job_cancels_it() {
        let engine = engine();
        let id = queued(&engine, "ipam.move", host()).await;
        let router = app(Some(&engine), None);
        let reply = post(&router, &format!("/jobs/{id}/cancel")).await;
        assert_eq!(reply.status, StatusCode::ACCEPTED, "{}", reply.body);
        assert_eq!(reply.body["state"], "cancelled");
        assert_eq!(reply.body["cancel_requested"], true);
        assert!(reply.body["finished"].is_string());

        let detail = get(&router, &format!("/jobs/{id}")).await;
        assert_eq!(detail.body["job"]["state"], "cancelled");
    }

    #[tokio::test]
    async fn cancelling_a_cancelled_job_conflicts() {
        let engine = engine();
        let id = queued(&engine, "ipam.move", host()).await;
        let router = app(Some(&engine), None);
        assert_eq!(
            post(&router, &format!("/jobs/{id}/cancel")).await.status,
            StatusCode::ACCEPTED
        );
        let reply = post(&router, &format!("/jobs/{id}/cancel")).await;
        reply.assert_problem(409, "jobs.invalid_transition");
        assert_eq!(reply.body["params"]["action"], "cancel");
    }

    #[tokio::test]
    async fn cancelling_an_unknown_job_is_not_found() {
        let engine = engine();
        let id = JobId::generate();
        let reply = post(&app(Some(&engine), None), &format!("/jobs/{id}/cancel")).await;
        reply.assert_problem(404, "jobs.not_found");
    }

    // Complete.

    #[tokio::test]
    async fn completing_a_manual_step_records_the_note() {
        let engine = engine();
        let id = waiting(&engine, "ipam.move", host()).await;
        let router = app(Some(&engine), None);
        let reply = send(
            &router,
            "POST",
            &format!("/jobs/{id}/steps/0/complete"),
            Some(r#"{"note":"reserved 192.0.2.10 in the DHCP server"}"#),
        )
        .await;
        reply.assert_ok();
        assert_eq!(reply.body["id"], id.to_string());
        assert_eq!(reply.body["steps_done"], 1);
        // The list of waiting steps is left out when it is empty.
        assert!(reply.body.get("manual_steps").is_none(), "{}", reply.body);

        let detail = get(&router, &format!("/jobs/{id}")).await;
        detail.assert_ok();
        let notes: Vec<&str> = detail.body["transitions"]
            .as_array()
            .expect("transitions")
            .iter()
            .filter_map(|row| row["note"].as_str())
            .collect();
        assert_eq!(notes, vec!["reserved 192.0.2.10 in the DHCP server"]);
        assert_eq!(detail.body["job"]["steps"][0]["state"]["state"], "done");
    }

    #[tokio::test]
    async fn completing_without_a_body_or_a_note_works() {
        let engine = engine();
        let router = app(Some(&engine), None);
        for body in [
            None,
            Some(""),
            Some("  \n"),
            Some("{}"),
            Some(r#"{"note":null}"#),
        ] {
            let id = waiting(&engine, "ipam.move", host()).await;
            let reply = send(
                &router,
                "POST",
                &format!("/jobs/{id}/steps/0/complete"),
                body,
            )
            .await;
            reply.assert_ok();
            assert_eq!(reply.body["steps_done"], 1, "{body:?}");
        }
    }

    #[tokio::test]
    async fn completing_twice_conflicts() {
        let engine = engine();
        let id = waiting(&engine, "ipam.move", host()).await;
        let router = app(Some(&engine), None);
        let path = format!("/jobs/{id}/steps/0/complete");
        post(&router, &path).await.assert_ok();
        let again = post(&router, &path).await;
        again.assert_problem(409, "jobs.invalid_transition");
    }

    #[tokio::test]
    async fn completing_a_step_that_does_not_exist_is_not_found() {
        let engine = engine();
        let id = waiting(&engine, "ipam.move", host()).await;
        let reply = post(
            &app(Some(&engine), None),
            &format!("/jobs/{id}/steps/9/complete"),
        )
        .await;
        reply.assert_problem(404, "jobs.step.not_found");
        assert_eq!(reply.body["params"]["step"], "9");
    }

    #[tokio::test]
    async fn completing_a_step_of_an_unknown_job_is_not_found() {
        let engine = engine();
        let id = JobId::generate();
        let reply = post(
            &app(Some(&engine), None),
            &format!("/jobs/{id}/steps/0/complete"),
        )
        .await;
        reply.assert_problem(404, "jobs.not_found");
    }

    #[tokio::test]
    async fn a_note_over_the_limit_is_refused() {
        let engine = engine();
        let id = waiting(&engine, "ipam.move", host()).await;
        let router = app(Some(&engine), None);
        let path = format!("/jobs/{id}/steps/0/complete");
        let too_long = json!({ "note": "n".repeat(tenko_jobs::MAX_NOTE_BYTES + 1) }).to_string();
        let reply = send(&router, "POST", &path, Some(&too_long)).await;
        reply.assert_problem(400, "jobs.note.too_long");
        let exact = json!({ "note": "n".repeat(tenko_jobs::MAX_NOTE_BYTES) }).to_string();
        send(&router, "POST", &path, Some(&exact)).await.assert_ok();
    }

    #[tokio::test]
    async fn a_bad_step_index_is_a_problem() {
        let engine = engine();
        let id = waiting(&engine, "ipam.move", host()).await;
        let router = app(Some(&engine), None);
        for index in ["x", "-1", "65536", "1.5"] {
            let reply = post(&router, &format!("/jobs/{id}/steps/{index}/complete")).await;
            reply.assert_problem(400, "jobs.query.invalid");
            assert_eq!(reply.body["params"]["param"], "index", "{index}");
            assert_eq!(reply.body["params"]["value"], index);
        }
    }

    #[tokio::test]
    async fn a_malformed_body_is_a_problem() {
        let engine = engine();
        let id = waiting(&engine, "ipam.move", host()).await;
        let router = app(Some(&engine), None);
        let path = format!("/jobs/{id}/steps/0/complete");
        for body in [
            "not json",
            r#"{"note":5}"#,
            r#"{"note":"x","extra":1}"#,
            "[]",
        ] {
            let reply = send(&router, "POST", &path, Some(body)).await;
            reply.assert_problem(400, "sys.invalid_request");
        }
        // Nothing of that changed the job.
        let detail = get(&router, &format!("/jobs/{id}")).await;
        assert_eq!(
            detail.body["job"]["steps"][0]["state"]["state"],
            "waiting_for_manual"
        );
    }

    // No engine.

    #[tokio::test]
    async fn without_the_engine_every_endpoint_answers_501() {
        let router = app(None, None);
        let id = JobId::generate();
        let endpoints = [
            ("GET", "/jobs".to_owned(), "/jobs"),
            ("GET", format!("/jobs/{id}"), "/jobs/{id}"),
            ("POST", format!("/jobs/{id}/cancel"), "/jobs/{id}/cancel"),
            (
                "POST",
                format!("/jobs/{id}/steps/0/complete"),
                "/jobs/{id}/steps/{index}/complete",
            ),
        ];
        for (method, path, template) in endpoints {
            let reply = send(&router, method, &path, None).await;
            reply.assert_problem(501, "sys.not_implemented");
            assert_eq!(reply.body["params"]["method"], method);
            assert_eq!(
                reply.body["params"]["path"],
                format!("{API_BASE}{template}")
            );
        }
    }

    // Authorization.

    /// An authorizer with one switch per action, that records what it was asked.
    struct Policy {
        read: bool,
        execute: bool,
        asked: Mutex<Vec<(Action, ObjectRef)>>,
    }

    impl Policy {
        fn new(read: bool, execute: bool) -> Arc<Self> {
            Arc::new(Self {
                read,
                execute,
                asked: Mutex::new(Vec::new()),
            })
        }

        fn asked(&self) -> Vec<(Action, ObjectRef)> {
            self.asked.lock().expect("lock").clone()
        }
    }

    impl Authorizer for Policy {
        fn check(
            &self,
            _principal: &Principal,
            action: Action,
            object: &ObjectRef,
        ) -> Result<(), Denied> {
            self.asked.lock().expect("lock").push((action, *object));
            let allowed = match action {
                Action::Read => self.read,
                Action::Execute => self.execute,
                _ => false,
            };
            if allowed {
                Ok(())
            } else {
                Err(Denied {
                    action,
                    object: *object,
                    reason: DenyReason::MissingPermission,
                })
            }
        }

        fn scope(
            &self,
            _principal: &Principal,
            action: Action,
            kind: ObjectKind,
        ) -> tenko_core::ScopeFilter {
            if action == Action::Read && kind == ObjectKind::Job && self.read {
                tenko_core::ScopeFilter::All
            } else {
                tenko_core::ScopeFilter::Nothing
            }
        }
    }

    #[tokio::test]
    async fn an_authorizer_that_denies_everything_hides_and_refuses() {
        let engine = engine();
        let (id, _) = three_jobs(&engine).await;
        let policy = Policy::new(false, false);
        let router = app(Some(&engine), Some(policy.clone()));

        let detail = get(&router, &format!("/jobs/{id}")).await;
        detail.assert_problem(403, "auth.forbidden");
        assert_eq!(detail.body["params"]["action"], "read");
        assert_eq!(detail.body["params"]["kind"], "job");

        let list = get(&router, "/jobs").await;
        list.assert_ok();
        assert_eq!(list.body["items"], json!([]));
        assert_eq!(list.body["next_cursor"], Value::Null);
        assert!(list.body["revision"].as_u64().expect("revision") > 0);
        // The filters are still validated.
        get(&router, "/jobs?state=bogus")
            .await
            .assert_problem(400, "jobs.query.invalid");

        post(&router, &format!("/jobs/{id}/cancel"))
            .await
            .assert_problem(403, "auth.forbidden");
        post(&router, &format!("/jobs/{id}/steps/0/complete"))
            .await
            .assert_problem(403, "auth.forbidden");

        // Refused requests changed nothing.
        let engine_view = engine.job(id).await.expect("job");
        assert!(engine_view.cancel_requested.is_none());
        assert_eq!(engine_view.state, JobState::Waiting);
    }

    #[tokio::test]
    async fn actions_map_to_read_and_execute_on_the_job() {
        let engine = engine();
        let id = waiting(&engine, "ipam.move", host()).await;
        let object = ObjectRef::from(id);

        // Read yes, execute no.
        let policy = Policy::new(true, false);
        let router = app(Some(&engine), Some(policy.clone()));
        get(&router, &format!("/jobs/{id}")).await.assert_ok();
        get(&router, "/jobs").await.assert_ok();
        post(&router, &format!("/jobs/{id}/cancel"))
            .await
            .assert_problem(403, "auth.forbidden");
        post(&router, &format!("/jobs/{id}/steps/0/complete"))
            .await
            .assert_problem(403, "auth.forbidden");
        assert_eq!(
            policy.asked(),
            vec![
                (Action::Read, object),
                (Action::Execute, object),
                (Action::Execute, object)
            ]
        );

        // Execute yes, read no.
        let policy = Policy::new(false, true);
        let router = app(Some(&engine), Some(policy.clone()));
        let completed = post(&router, &format!("/jobs/{id}/steps/0/complete")).await;
        completed.assert_ok();
        get(&router, &format!("/jobs/{id}"))
            .await
            .assert_problem(403, "auth.forbidden");
    }

    #[tokio::test]
    async fn an_authorizer_that_allows_everything_lists_every_job() {
        let engine = engine();
        three_jobs(&engine).await;
        let policy = Policy::new(true, true);
        let router = app(Some(&engine), Some(policy));
        let list = get(&router, "/jobs").await;
        list.assert_ok();
        assert_eq!(list.item_ids().len(), 3);
    }

    // Helpers and the document.

    #[test]
    fn cursors_carry_the_job_id_and_are_bound_to_the_scope() {
        let id = JobId::generate();
        let scope = Filters::from_pairs([("state", "queued")]).scope(CURSOR_ENDPOINT);
        let params = PageParams {
            cursor: Some(encode_cursor(scope, &id)),
            ..PageParams::default()
        };
        assert!(
            !params
                .cursor
                .as_deref()
                .unwrap_or_default()
                .contains(&id.to_string())
        );
        assert_eq!(params.cursor::<JobId>(scope).expect("cursor"), Some(id));
        let other = Filters::from_pairs([("state", "waiting")]).scope(CURSOR_ENDPOINT);
        let error = params.cursor::<JobId>(other).expect_err("foreign cursor");
        assert_eq!(error.coded_error().code, "sys.invalid_cursor");
        assert_eq!(
            PageParams::default().cursor::<JobId>(scope).expect("none"),
            None
        );
    }

    #[test]
    fn the_page_limits_are_the_ones_of_the_engine() {
        assert_eq!(crate::list::MAX_LIMIT, ENGINE_MAX_LIMIT);
        assert_eq!(crate::list::DEFAULT_LIMIT, tenko_jobs::query::DEFAULT_LIMIT);
    }

    #[test]
    fn the_document_describes_the_jobs_endpoints() {
        let document = crate::openapi();
        let json = serde_json::to_value(&document).expect("document");
        let list = &json["paths"]["/api/v1/jobs"]["get"];
        assert_eq!(list["operationId"], "list_jobs");
        let parameters: Vec<&str> = list["parameters"]
            .as_array()
            .expect("parameters")
            .iter()
            .map(|parameter| parameter["name"].as_str().expect("name"))
            .collect();
        assert_eq!(
            parameters,
            [
                "state", "kind", "target", "group", "limit", "cursor", "at_least"
            ]
        );
        let ok = &list["responses"]["200"]["content"]["application/json"]["schema"];
        assert!(
            ok["$ref"]
                .as_str()
                .expect("ref")
                .ends_with("Page_JobSummary")
        );
        assert!(json["components"]["schemas"]["JobSummary"].is_object());
        assert!(json["components"]["schemas"]["JobDetail"].is_object());

        let complete = &json["paths"]["/api/v1/jobs/{id}/steps/{index}/complete"]["post"];
        assert_eq!(complete["operationId"], "complete_job_step");
        assert_ne!(
            complete["requestBody"]["required"], true,
            "the body is optional"
        );
        for (path, method, status) in [
            ("/api/v1/jobs", "get", "400"),
            ("/api/v1/jobs/{id}", "get", "404"),
            ("/api/v1/jobs/{id}/cancel", "post", "409"),
            ("/api/v1/jobs/{id}/cancel", "post", "202"),
            ("/api/v1/jobs/{id}/steps/{index}/complete", "post", "404"),
        ] {
            let response = &json["paths"][path][method]["responses"][status];
            assert!(response.is_object(), "{method} {path} {status}");
        }
        let problem = &json["paths"]["/api/v1/jobs/{id}"]["get"]["responses"]["404"]["content"];
        assert!(problem["application/problem+json"].is_object());
    }
}
