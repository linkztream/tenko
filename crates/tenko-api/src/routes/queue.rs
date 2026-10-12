//! Changes queued on an isolated controller and their conflicts after the partition heals
//! (OPS-26, ADR 0013, `docs/partitions.md`).
//!
//! Area: queue. Owner: WP3.9.
//! Requirements: OPS-26.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `POST /queue` | 201 [`QueueItemView`]: the queued change with its plan against the local copy | 400 and 409 as the endpoint itself (the request is planned), 403, 409 `queue.not_isolated`, 413 `queue.too_large`, 422 `queue.not_queueable`, 503 `queue.unavailable`, 507 `queue.full` |
//! | `GET /queue` | 200 [`QueueList`]: the caller's queued changes on this controller, oldest first | 503 |
//! | `DELETE /queue/{id}` | 204: withdrawn | 404 `queue.not_found` |
//! | `GET /queue/conflicts` | 200 [`QueuedChangeList`]: what became of the caller's queued changes | 503 `ipam.unavailable` |
//! | `POST /queue/conflicts/{id}/reapply` | as the IPAM write it re-applies ([`WriteResponse`] or [`BulkResponse`]); `?dry_run=true` plans only | 404, 409 `queue.changed`, and the errors of the write |
//! | `DELETE /queue/conflicts/{id}` | 204: discarded | 404, 409 `queue.changed` |
//!
//! Part of the IPAM module: registered only while it runs.
//!
//! # The queue
//!
//! A controller in the isolated mode answers writes with 503 `cluster.no_quorum` and the
//! parameter `queueable` ([`crate::middleware::quorum`]). For a queueable write the client
//! sends the same request to `POST /queue` as data: `{ method, path, query, body, if_match }`.
//! The controller translates it into planner commands exactly as the endpoint would,
//! checks the caller's rights, plans it against its local copy and keeps it in its local
//! queue (`<data_dir>/queue/`, the `Arc<LocalQueue>` request extension) for 7 days. A
//! queued change does not see the other queued changes: each is planned against the
//! local copy alone. `POST /queue` and `DELETE /queue/{id}` write nothing to the store and
//! pass the quorum gate; everything else here is an ordinary read or write.
//!
//! # After the heal
//!
//! The controller drains its queue ([`tenko_ipam::queue::drain`]): an unchanged plan
//! applies on the author's behalf, everything else becomes a record with its conflict.
//! Every settled change, applied ones included, is a record in `ipam.queued_changes` that
//! its author lists with `GET /queue/conflicts` (from any controller), re-applies or
//! discards. A re-apply plans the stored commands now, as the caller, with the
//! acknowledgements of the original request plus those of `?acknowledge=`; the `If-Match`
//! of the original request is dropped (the caller confirms against the current state),
//! and an `If-Match` on the re-apply request takes its place for a single-object change.
//!
//! # Authorization
//!
//! Only people queue changes: a session or a token of a user. The rights are those of the
//! endpoint the request names, checked at queueing, again at the drain (the author's rights
//! at that time) and at a re-apply. The lists show the caller's own changes only.

mod translate;

#[cfg(test)]
mod tests;

pub(crate) use translate::{local, queueable};

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, NodeId, ObjectKind, Principal, RequestCtx, Revision, Timestamp, UserId,
    ipam::{Address, Host, Interface, Prefix, Range, Site, Tenant, Vlan, Vrf},
};
use tenko_ipam::{
    IpamCommand, IpamError, PlanView,
    queue::{
        self, ChangeState, ChangeSummary, Fingerprint, ItemState, LocalQueue, QUEUED_CHANGES,
        QueueItem, QueuedChange, QueuedRequest, SummaryAction, codes,
    },
};
use tenko_store::{ReadConsistency, WriteBatch};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    extract::Ctx,
    list::Filters,
    problem::{ApiError, ProblemDetails},
    routes::common::{
        BulkResponse, IfMatch, Ipam, IpamHandle, WriteArgs, WriteParams, authorize, command_access,
        if_match, write_args, write_one,
    },
    state::AppState,
};

/// The routes of the area.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_queue, queue_change))
        .routes(routes!(withdraw_queued_change))
        .routes(routes!(list_queued_changes))
        .routes(routes!(reapply_queued_change))
        .routes(routes!(discard_queued_change))
}

/// A queued change, as `GET /queue` lists it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct QueueItemView {
    /// Identifier.
    pub id: Uuid,
    /// When it was queued.
    pub queued_at: Timestamp,
    /// The controller whose queue holds it.
    #[schema(value_type = u64)]
    pub queued_on: NodeId,
    /// The method of the request.
    pub method: String,
    /// The path of the request, relative to `/api/v1`.
    pub path: String,
    /// What it does.
    pub summary: ChangeSummary,
    /// The plan against the local copy when it was queued.
    pub plan: PlanView,
    /// When it expires.
    pub expires_at: Timestamp,
    /// Its state.
    pub state: ItemState,
}

impl QueueItemView {
    fn of(item: &QueueItem, now: Timestamp) -> Self {
        Self {
            id: item.id,
            queued_at: item.queued_at,
            queued_on: item.queued_on,
            method: item.request.method.clone(),
            path: item.request.path.clone(),
            summary: item.summary.clone(),
            plan: item.plan.clone(),
            expires_at: item.expires_at,
            state: item.state(now),
        }
    }
}

/// Body of `GET /queue`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QueueList {
    /// The caller's queued changes on this controller, oldest first.
    pub items: Vec<QueueItemView>,
}

/// A settled queued change with the revision that wrote its record.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QueuedChangeView {
    /// The record.
    #[serde(flatten)]
    pub record: QueuedChange,
    /// The revision that wrote the record; for an `applied` change, the revision of the
    /// change itself.
    #[schema(value_type = u64)]
    pub revision: Revision,
}

/// Body of `GET /queue/conflicts`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QueuedChangeList {
    /// The caller's settled queued changes, oldest first.
    pub items: Vec<QueuedChangeView>,
    /// The revision the list was read at.
    #[schema(value_type = u64)]
    pub revision: Revision,
}

type Queue = Option<Extension<Arc<LocalQueue>>>;

fn queue_of(queue: Queue) -> Result<Arc<LocalQueue>, ApiError> {
    queue.map(|Extension(queue)| queue).ok_or_else(|| {
        IpamError::new(
            codes::UNAVAILABLE,
            503,
            "this server keeps no queue of changes",
        )
        .titled("Service unavailable")
        .into()
    })
}

/// The user behind a person's principal; 403 `queue.not_a_person` for anything else.
fn person(principal: &Principal) -> Result<UserId, ApiError> {
    match principal {
        Principal::User { id, .. } => Ok(*id),
        Principal::Token { owner, .. } => Ok(*owner),
        _ => Err(IpamError::new(
            codes::NOT_A_PERSON,
            403,
            "only people queue changes: sign in or use a token of a user",
        )
        .titled("Not allowed")
        .into()),
    }
}

fn not_found(id: Uuid) -> ApiError {
    IpamError::new(
        codes::NOT_FOUND,
        404,
        format!("you have no queued change {id} here"),
    )
    .titled("No such queued change")
    .into()
}

/// Queues an IPAM write on a controller cut off from its cluster. The body is the request
/// as it would have been sent; it is translated, checked and planned against the local
/// copy exactly as the endpoint would, and kept on this controller until the cluster is
/// back (at most 7 days). Not taken: dry runs, allocations of the next free address or
/// prefix, custom fields, moves, proposals and every non-IPAM write.
#[utoipa::path(
    post,
    path = "/queue",
    tag = "queue",
    operation_id = "queue_change",
    summary = "Queue a change on an isolated controller",
    request_body = QueuedRequest,
    responses(
        (status = 201, description = "The queued change with its plan against the local copy", body = QueueItemView),
        (status = 400, description = "The request, its query or `If-Match` is invalid as the endpoint would find it (`ipam.validation`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed: the endpoint's own check (`auth.forbidden`, `auth.out_of_scope`), or not a person (`queue.not_a_person`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The controller accepts writes: send the request itself (`queue.not_isolated`); or the plan fails against the local copy as the endpoint would answer (`ipam.*`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "Too large to queue (`queue.too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Not queueable (`queue.not_queueable`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No queue or no IPAM on this server (`queue.unavailable`, `ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 507, description = "The queue of this controller is full (`queue.full`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn queue_change(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    queue: Queue,
    Json(request): Json<QueuedRequest>,
) -> Result<Response, ApiError> {
    let queue = queue_of(queue)?;
    person(&cx.principal)?;
    let status = app.store.status();
    if status.quorum.accepts_writes() {
        return Err(IpamError::new(
            codes::NOT_ISOLATED,
            409,
            "this controller is in contact with its cluster: send the change itself",
        )
        .titled("Nothing to queue")
        .into());
    }
    let translated = translate::translate(&request)?;
    for command in &translated.commands {
        let (action, object) = command_access(command);
        authorize(&app, &cx, action, object)?;
    }
    // The queued plan is a preview: a key of the request means nothing to it.
    let planning = RequestCtx {
        idempotency: None,
        ..cx.clone()
    };
    let plan = ipam
        .preview(&planning, &translated.commands, &translated.options)
        .await?;
    let view = plan.view();
    let summary = queue::summarize(translated.action, &view).unwrap_or(ChangeSummary {
        action: translated.action,
        kind: translated.kind,
        key: None,
    });
    let expires_at = cx.now.checked_add(queue::EXPIRY).unwrap_or(cx.now);
    let item = QueueItem {
        id: Uuid::now_v7(),
        queued_at: cx.now,
        queued_on: queue.node(),
        expires_at,
        principal: cx.principal.clone(),
        request: QueuedRequest {
            method: request.method.trim().to_ascii_uppercase(),
            path: translated.path,
            query: request.query.filter(|query| !query.is_empty()),
            body: request.body,
            if_match: request.if_match,
        },
        commands: translated.commands,
        options: translated.options,
        base: plan.base,
        fingerprint: Fingerprint::of_plan(&plan),
        plan: view,
        summary,
        applying: false,
    };
    queue.add(&item)?;
    tracing::info!(
        item = %item.id,
        principal = %item.principal,
        method = %item.request.method,
        path = %item.request.path,
        "change queued while the controller is cut off from its cluster"
    );
    let body = QueueItemView::of(&item, cx.now);
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// Lists the caller's queued changes on this controller, oldest first.
#[utoipa::path(
    get,
    path = "/queue",
    tag = "queue",
    operation_id = "list_queue",
    summary = "List my queued changes on this controller",
    responses(
        (status = 200, description = "The caller's queued changes", body = QueueList),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No queue on this server (`queue.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_queue(Ctx(cx): Ctx, queue: Queue) -> Result<Json<QueueList>, ApiError> {
    let queue = queue_of(queue)?;
    let user = cx.principal.user();
    let items = queue
        .list()?
        .iter()
        .filter(|item| user.is_some() && item.author() == user)
        .map(|item| QueueItemView::of(item, cx.now))
        .collect();
    Ok(Json(QueueList { items }))
}

/// Withdraws one of the caller's queued changes before it is applied.
#[utoipa::path(
    delete,
    path = "/queue/{id}",
    tag = "queue",
    operation_id = "withdraw_queued_change",
    summary = "Withdraw a queued change",
    params(("id" = String, Path, description = "Queued change identifier")),
    responses(
        (status = 204, description = "Withdrawn"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The caller has no such queued change here (`queue.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The controller is applying it now (`queue.changed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No queue on this server (`queue.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn withdraw_queued_change(
    Ctx(cx): Ctx,
    queue: Queue,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let queue = queue_of(queue)?;
    let id = parse_id(&id)?;
    let user = cx.principal.user();
    let item = queue
        .get(id)?
        .filter(|item| user.is_some() && item.author() == user)
        .ok_or_else(|| not_found(id))?;
    if item.applying {
        return Err(changed("the controller is applying this change now"));
    }
    queue.remove(id)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Lists what became of the caller's queued changes after the partition healed: applied
/// on their behalf, in conflict, or expired. Readable on every controller.
#[utoipa::path(
    get,
    path = "/queue/conflicts",
    tag = "queue",
    operation_id = "list_queued_changes",
    summary = "List my settled queued changes",
    responses(
        (status = 200, description = "The caller's settled queued changes", body = QueuedChangeList),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_queued_changes(
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
) -> Result<Json<QueuedChangeList>, ApiError> {
    let view = ipam.view(None).await?;
    let items = match cx.principal.user() {
        Some(user) => queue::record::of_author(view.as_ref(), user)
            .map_err(IpamError::from)?
            .into_iter()
            .map(|(record, revision)| QueuedChangeView { record, revision })
            .collect(),
        None => Vec::new(),
    };
    Ok(Json(QueuedChangeList {
        items,
        revision: view.revision(),
    }))
}

/// Applies one of the caller's queued changes that was not applied (in conflict or
/// expired) now, as the caller. Answers like the write it re-applies; with
/// `?dry_run=true`, the plan only. The record goes once the change applied.
#[utoipa::path(
    post,
    path = "/queue/conflicts/{id}/reapply",
    tag = "queue",
    operation_id = "reapply_queued_change",
    summary = "Re-apply a queued change",
    params(("id" = String, Path, description = "Queued change identifier"), WriteParams, IfMatch),
    responses(
        (status = 200, description = "The change applied or planned, as the endpoint of the original request answers (`WriteResponse` of the object, or `BulkResponse` for a bulk change)", body = Object),
        (status = 201, description = "A create applied", body = Object),
        (status = 400, description = "Invalid parameter or `If-Match`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`, `auth.out_of_scope`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The caller has no such settled change (`queue.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The change was applied already (`queue.changed`), or the write fails as the endpoint would answer (`ipam.*`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The controller cannot write (`cluster.no_quorum`) or IPAM is not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn reapply_queued_change(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    Path(id): Path<String>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let id = parse_id(&id)?;
    let mut args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    let (record, revision) = own_record(&ipam, &cx, id).await?;
    if record.state == ChangeState::Applied {
        return Err(changed("this change was applied already"));
    }
    args.options
        .acknowledge
        .extend(record.options.acknowledge.iter().cloned());
    let mut commands = record.commands.clone();
    let single = commands.len() == 1;
    for command in &mut commands {
        set_expected(command, if single { expected } else { None });
        let (action, object) = command_access(command);
        authorize(&app, &cx, action, object)?;
    }
    let response = if record.summary.action == SummaryAction::Bulk {
        bulk(&ipam, &cx, &commands, &args).await?
    } else {
        let created = record.summary.action == SummaryAction::Create;
        one(&ipam, &cx, record.summary.kind, commands, &args, created).await?
    };
    if !args.dry_run && response.status().is_success() {
        let mut batch = WriteBatch::new(cx.principal.clone(), cx.now);
        batch
            .expect_typed(&QUEUED_CHANGES, &id, Some(revision))
            .delete_typed(&QUEUED_CHANGES, &id);
        if let Err(error) = app.store.propose(batch).await {
            tracing::warn!(
                record = %id,
                code = %tenko_core::Coded::code(&error),
                "a re-applied queued change keeps its record"
            );
        }
    }
    Ok(response)
}

/// Discards one of the caller's settled queued changes: a conflict or an expired change
/// the caller gives up, or an applied change the caller has seen.
#[utoipa::path(
    delete,
    path = "/queue/conflicts/{id}",
    tag = "queue",
    operation_id = "discard_queued_change",
    summary = "Discard a settled queued change",
    params(("id" = String, Path, description = "Queued change identifier")),
    responses(
        (status = 204, description = "Discarded"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The caller has no such settled change (`queue.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The record changed meanwhile (`queue.changed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The controller cannot write (`cluster.no_quorum`) or IPAM is not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn discard_queued_change(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&id)?;
    let (_, revision) = own_record(&ipam, &cx, id).await?;
    let mut batch = WriteBatch::new(cx.principal.clone(), cx.now);
    batch
        .expect_typed(&QUEUED_CHANGES, &id, Some(revision))
        .delete_typed(&QUEUED_CHANGES, &id);
    app.store.propose(batch).await.map_err(|error| {
        if matches!(error, tenko_store::StoreError::PreconditionFailed(_)) {
            changed("the record changed meanwhile; read it again")
        } else {
            IpamError::from(error).into()
        }
    })?;
    Ok(StatusCode::NO_CONTENT)
}

/// The caller's record `id` with its revision, read linearizably.
async fn own_record(
    ipam: &IpamHandle,
    cx: &RequestCtx,
    id: Uuid,
) -> Result<(QueuedChange, Revision), ApiError> {
    let view = ipam
        .store()
        .read(ReadConsistency::Linearizable)
        .await
        .map_err(IpamError::from)?;
    let user = cx.principal.user();
    queue::record::get(view.as_ref(), id)
        .map_err(IpamError::from)?
        .filter(|(record, _)| user == Some(record.author))
        .ok_or_else(|| not_found(id))
}

fn changed(detail: &str) -> ApiError {
    IpamError::new(codes::CHANGED, 409, detail)
        .titled("The queued change changed")
        .into()
}

fn parse_id(text: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(text).map_err(|_| {
        ApiError::from_coded_error(
            CodedError::new(
                tenko_ipam::codes::VALIDATION,
                400,
                format!("`{text}` is not a queued change identifier"),
            )
            .with_title("Invalid request")
            .with_param("field", "id"),
        )
    })
}

/// Replaces the `If-Match` revision of a single-object command.
fn set_expected(command: &mut IpamCommand, expected: Option<Revision>) {
    match command {
        IpamCommand::UpdateTenant(update) => update.expected = expected,
        IpamCommand::UpdateVrf(update) => update.expected = expected,
        IpamCommand::UpdateSite(update) => update.expected = expected,
        IpamCommand::UpdateVlan(update) => update.expected = expected,
        IpamCommand::UpdatePrefix(update) => update.expected = expected,
        IpamCommand::UpdateRange(update) => update.expected = expected,
        IpamCommand::UpdateAddress(update) => update.expected = expected,
        IpamCommand::UpdateHost(update) => update.expected = expected,
        IpamCommand::UpdateInterface(update) => update.expected = expected,
        IpamCommand::Delete { expected: slot, .. }
        | IpamCommand::Restore { expected: slot, .. } => {
            *slot = expected;
        }
        _ => {}
    }
}

/// A single-object write, answered as its endpoint answers.
async fn one(
    ipam: &IpamHandle,
    cx: &RequestCtx,
    kind: ObjectKind,
    commands: Vec<IpamCommand>,
    args: &WriteArgs,
    created: bool,
) -> Result<Response, ApiError> {
    match kind {
        ObjectKind::Tenant => write_one::<Tenant>(ipam, cx, commands, args, created).await,
        ObjectKind::Vrf => write_one::<Vrf>(ipam, cx, commands, args, created).await,
        ObjectKind::Site => write_one::<Site>(ipam, cx, commands, args, created).await,
        ObjectKind::Vlan => write_one::<Vlan>(ipam, cx, commands, args, created).await,
        ObjectKind::Prefix => write_one::<Prefix>(ipam, cx, commands, args, created).await,
        ObjectKind::Range => write_one::<Range>(ipam, cx, commands, args, created).await,
        ObjectKind::Address => write_one::<Address>(ipam, cx, commands, args, created).await,
        ObjectKind::Host => write_one::<Host>(ipam, cx, commands, args, created).await,
        ObjectKind::Interface => write_one::<Interface>(ipam, cx, commands, args, created).await,
        other => Err(IpamError::new(
            codes::NOT_QUEUEABLE,
            422,
            format!("a queued change of a {other} cannot be re-applied"),
        )
        .into()),
    }
}

/// A bulk write, answered as the bulk endpoint answers.
async fn bulk(
    ipam: &IpamHandle,
    cx: &RequestCtx,
    commands: &[IpamCommand],
    args: &WriteArgs,
) -> Result<Response, ApiError> {
    if args.dry_run {
        let plan = ipam.preview(cx, commands, &args.options).await?;
        let body = BulkResponse {
            revision: None,
            job_id: None,
            dry_run: true,
            replayed: plan.replay.is_some(),
            results: plan.results.clone(),
            warnings: plan.warnings.clone(),
            plan: Some(plan.view()),
        };
        return Ok((StatusCode::OK, Json(body)).into_response());
    }
    let applied = ipam.execute(cx, commands, &args.options).await?;
    let body = BulkResponse {
        revision: Some(applied.revision),
        job_id: applied.job_id,
        dry_run: false,
        replayed: applied.replayed,
        results: applied.results,
        warnings: applied.warnings,
        plan: None,
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}
