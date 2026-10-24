//! Proposals, the reconciler and adoption policies.
//!
//! Area: proposals. Owner: WP2.4. Requirements: IPAM-12, IPAM-13, IPAM-14, IPAM-15, IPAM-16,
//! IPAM-17.
//!
//! The reconciler compares intent with what the sources observe ([`super::observations`])
//! and keeps one open **proposal** per subject: a discovered host, intent that nobody has
//! seen for a long time, a host seen on another address, a conflict, an address outside every
//! known network. A proposal carries its evidence and the commands that would resolve it.
//! Observations never become intent by themselves: a person approves a proposal here, or an
//! adoption policy of the prefix applies it (ADR 0005). [`super::common`] documents the
//! conventions every IPAM endpoint follows: the IPAM service as a request extension (503
//! `ipam.unavailable` without it), the list parameters, `ETag` and `If-Match`, `dry_run` and
//! `acknowledge`, and the authorization checks.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /proposals` | 200 page of proposals | 400 `sys.invalid_query`, `sys.invalid_cursor`, 404 `ipam.not_found` (prefix filter), 503 |
//! | `GET /proposals/{id}` | 200 proposal with `ETag` | 403, 404 `ipam.proposal.not_found` |
//! | `POST /proposals/{id}/approve` | 200 decision with `ETag`, or the plan of a dry run | 403, 404, 409 `ipam.proposal.not_open`, `ipam.proposal.nothing_to_apply`, `ipam.plan.unacknowledged`, `ipam.name_taken`, 412 `ipam.proposal.revision_mismatch`, 423 `ipam.host.locked` |
//! | `POST /proposals/{id}/reject` | 200 decision with `ETag` | 400 `ipam.validation`, 403, 404, 409 `ipam.proposal.not_open`, 412 |
//! | `POST /proposals/approve` | 200 outcome of every proposal and the counts | 400, 403, 422 `ipam.proposal.batch_empty`, `ipam.proposal.batch_too_large`, 503 |
//! | `POST /proposals/reject` | 200 outcome of every proposal and the counts | 400 `ipam.validation`, 403, 422 `ipam.proposal.batch_empty`, `ipam.proposal.batch_too_large`, 503 |
//! | `POST /proposals/reconcile` | 200 report of the run | 403, 503 `ipam.reconciler.unavailable` |
//! | `GET /prefixes/{id}/adoption` | 200 policy view with `ETag` | 403, 404 `ipam.not_found`, 409 `ipam.object_deleted` |
//! | `PUT /prefixes/{id}/adoption` | 200 policy view with `ETag` | 400 `ipam.adoption.invalid`, `sys.invalid_request`, 403, 404, 409, 412 `ipam.revision_mismatch` |
//! | `DELETE /prefixes/{id}/adoption` | 200 policy view (the prefix inherits again) | 403, 404, 409, 412 |
//!
//! # Proposals
//!
//! A proposal has a `kind` (`discovered_host`, `orphaned_intent`, `address_mismatch`,
//! `conflict`, `outside_prefixes`), a `severity` (`info`, `warning`, `critical`) and a
//! `state`: `open`, `accepted` (approved by a person or adopted by a policy), `rejected`,
//! `expired` (the observation no longer holds) or `superseded` (a newer proposal about the
//! same subject replaced it). At most one proposal per subject is open at a time.
//!
//! The list takes the filters `kind`, `state` and `severity` (each repeatable or
//! comma-separated; all states unless `state` says otherwise), `prefix` (proposals about
//! this prefix, its addresses and its networks), `subject` (a MAC address, an IP address, an
//! object identifier or text of the subject name) and `sort` (`created`, `updated`,
//! `severity`, `kind`, `state`, `last_seen`; `-` in front for descending; `-created` by
//! default).
//!
//! # Deciding
//!
//! An **approval** plans the commands of the proposal as the approving person, applies them
//! and marks the proposal accepted in one batch inside an inline job, so the intent change,
//! the new state and their audit records commit together or not at all (IPAM-17). It takes
//! `dry_run=true` for the plan without writing and `acknowledge=<code>,...` for warnings
//! that need an acknowledgement, exactly like any other change. A proposal without commands
//! (a conflict, which a person resolves by hand) answers 409
//! `ipam.proposal.nothing_to_apply`; reject it once it is resolved.
//!
//! A **rejection** records the reason (at most 1,024 bytes) and remembers the fingerprint of
//! the proposal: the reconciler does not open the same subject again until its evidence
//! changes.
//!
//! Both decisions take `If-Match: "<revision>"` (the `ETag` of the proposal) and answer 412
//! `ipam.proposal.revision_mismatch` when the proposal changed since; a decided proposal
//! answers 409 `ipam.proposal.not_open`.
//!
//! # Deciding many at once
//!
//! `POST /proposals/approve` and `POST /proposals/reject` take `{"ids": [...]}` (one to 500
//! identifiers; the rejection also the `reason` of the single route, which applies to all)
//! and decide the proposals in order, each as the single route does and independently of
//! the others: one that is not open any more, lies outside the caller's scope, has nothing
//! to apply or is refused by any other check of the single route is `skipped` with the code
//! and message the single route answers with, and the rest are applied. The answer lists
//! every identifier with its outcome (`approved`, `rejected` or `skipped`) and the counts.
//! There is no `If-Match`, no dry run and no acknowledgement: a warning that needs one
//! skips the proposal (`ipam.plan.unacknowledged`). Authorization is the single route's,
//! evaluated for each proposal, after a first check that the principal may approve
//! proposals at all (403). Each decision writes the audit records of the single route and
//! nothing else, so there is no record of the batch itself. An empty list and a list over
//! 500 are 422 `ipam.proposal.batch_empty` and `ipam.proposal.batch_too_large`; a bad
//! reason is 400 `ipam.validation` for the whole request.
//!
//! `POST /proposals/reconcile` runs the reconciler once, now, and answers its report. It
//! needs the reconciler on this server (503 `ipam.reconciler.unavailable` otherwise). The
//! path coexists with `GET /proposals/{id}`: the static segment wins, so only `POST` is
//! served on it.
//!
//! # Adoption policies
//!
//! A prefix may carry an [`AdoptionPolicy`] that lets the reconciler apply some proposals
//! without a person (`manual`, `adopt_hosts`, `adopt_all`, with constraints on DHCP pools,
//! vendors and the number of sightings). The prefixes inside it inherit the policy of the
//! nearest prefix that has one. `GET` answers the prefix's own policy (`null` when it
//! inherits), the policy in force (`effective`) and the prefix it comes from (`source`).
//! `ETag` and `If-Match` carry the revision of the prefix's own policy; `"0"` means that it
//! has none. `PUT` sets the policy, `DELETE` removes it. Changes nudge the reconciler, which
//! then applies the new policy to the open proposals.
//!
//! # Authorization
//!
//! With an [`Authorizer`](tenko_core::Authorizer) in the state:
//!
//! - reading proposals needs [`Action::Read`] (a list is empty when the principal may read
//!   none);
//! - approving and rejecting need [`Action::Approve`] on the proposal, and an approval also
//!   needs, for every command of the proposal, what that command needs when sent on its own
//!   (for example [`Action::Create`] on hosts and addresses);
//! - running the reconciler needs [`Action::Approve`] on proposals;
//! - reading an adoption policy needs [`Action::Read`] and changing or removing one
//!   [`Action::Update`] on the prefix.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Extension, Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tenko_core::{
    Action, CodedError, ObjectKind, ObjectRef, PrefixId, ProposalId, RequestCtx, Revision,
    Timestamp,
};
use tenko_ipam::{
    PlanOptions,
    proposals::{
        self, AdoptionPolicy, Decision, IntentProposal, IntentProposalKind, IntentProposalState,
        PolicyView, ProposalQuery, ProposalSeverity,
        query::{self, SORTS},
    },
    reconcile::{ReconcileReport, Reconciler},
};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::common::{
    IfMatch, Ipam, IpamHandle, IpamJson, IpamPath, ReadParams, WriteParams, authorize,
    command_access, enum_params, if_match, new_of, with_etag, write_args,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{Filters, PageParams, SortKey, encode_cursor},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The routes of the area.
pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_proposals))
        .routes(routes!(reconcile_proposals))
        .routes(routes!(get_proposal))
        .routes(routes!(approve_proposal))
        .routes(routes!(reject_proposal))
        .routes(routes!(approve_proposals))
        .routes(routes!(reject_proposals))
        .routes(routes!(
            get_adoption_policy,
            set_adoption_policy,
            clear_adoption_policy
        ))
}

/// The body of a rejection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RejectRequest {
    /// Why the proposal is rejected; at most 1,024 bytes, no control characters other than
    /// line breaks and tabs. Blank counts as no reason.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The most proposals one batch decision takes.
pub const MAX_BATCH: usize = 500;

/// The body of a batch approval.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchApproveRequest {
    /// The proposals to approve, in the order they are applied: one to 500 identifiers.
    pub ids: Vec<ProposalId>,
}

/// The body of a batch rejection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchRejectRequest {
    /// The proposals to reject, in the order they are rejected: one to 500 identifiers.
    pub ids: Vec<ProposalId>,
    /// Why the proposals are rejected, for all of them; the rules of the single rejection
    /// apply (at most 1,024 bytes, no control characters other than line breaks and tabs,
    /// blank counts as no reason).
    #[serde(default)]
    pub reason: Option<String>,
}

/// What happened to one proposal of a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BatchOutcome {
    /// The proposal was approved.
    Approved,
    /// The proposal was rejected.
    Rejected,
    /// The proposal was left as it was; `code` and `message` say why.
    Skipped,
}

/// The outcome of one proposal of a batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BatchItem {
    /// The proposal.
    pub id: ProposalId,
    /// What happened to it.
    pub outcome: BatchOutcome,
    /// For a skipped proposal the error code of the refusal, the code the single route
    /// answers with, for example `ipam.proposal.not_open`.
    #[serde(default)]
    pub code: Option<String>,
    /// For a skipped proposal the HTTP status of that refusal.
    #[serde(default)]
    pub status: Option<u16>,
    /// For a skipped proposal the English explanation of the refusal.
    #[serde(default)]
    pub message: Option<String>,
    /// For a skipped proposal the parameters of that refusal, as in the problem document of
    /// the single route (for example `state`); empty otherwise.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
}

impl BatchItem {
    /// The item for `id`: `done` when the decision was applied, a skip with the error
    /// otherwise.
    fn new(id: ProposalId, done: BatchOutcome, outcome: Result<Decision, ApiError>) -> Self {
        match outcome {
            Ok(_) => Self {
                id,
                outcome: done,
                code: None,
                status: None,
                message: None,
                params: BTreeMap::new(),
            },
            Err(error) => {
                let error = error.coded_error();
                Self {
                    id,
                    outcome: BatchOutcome::Skipped,
                    code: Some(error.code.to_string()),
                    status: Some(error.status),
                    message: Some(error.detail.clone()),
                    params: error.params.clone(),
                }
            }
        }
    }
}

/// The answer of a batch decision: the outcome of every proposal and the counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BatchDecision {
    /// One entry per identifier of the request, in its order.
    pub results: Vec<BatchItem>,
    /// How many proposals were approved.
    pub approved: usize,
    /// How many proposals were rejected.
    pub rejected: usize,
    /// How many proposals were skipped.
    pub skipped: usize,
}

impl BatchDecision {
    /// The answer for `results`, with the counts.
    fn of(results: Vec<BatchItem>) -> Self {
        let count = |wanted| results.iter().filter(|item| item.outcome == wanted).count();
        Self {
            approved: count(BatchOutcome::Approved),
            rejected: count(BatchOutcome::Rejected),
            skipped: count(BatchOutcome::Skipped),
            results,
        }
    }
}

/// The 503 of the endpoints that need the reconciler on this server.
fn reconciler_unavailable() -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(
            proposals::codes::RECONCILER_UNAVAILABLE,
            503,
            "the reconciler does not run on this server",
        )
        .with_title("Service unavailable"),
    )
}

/// Asks the reconciler, when there is one, for a run soon.
fn nudge(reconciler: Option<&Extension<Arc<Reconciler>>>) {
    if let Some(Extension(reconciler)) = reconciler {
        reconciler.nudge();
    }
}

/// A decision as the answer: `ETag` of the proposal once the decision is committed.
fn decided(decision: Decision) -> Response {
    let etag = (!decision.dry_run).then_some(decision.proposal.revision);
    let response = Json(decision).into_response();
    match etag {
        Some(revision) => with_etag(response, revision),
        None => response,
    }
}

// ===== proposals =====================================================================

/// Lists proposals, newest first unless `sort` says otherwise.
#[utoipa::path(
    get,
    path = "/proposals",
    tag = "proposals",
    operation_id = "list_proposals",
    summary = "List proposals",
    params(
        PageParams,
        ("kind" = Option<String>, Query, description = "Only proposals of these kinds: `discovered_host`, `orphaned_intent`, `address_mismatch`, `conflict` or `outside_prefixes`. Repeat the parameter or separate the kinds with commas."),
        ("state" = Option<String>, Query, description = "Only proposals in these states: `open`, `accepted`, `rejected`, `expired` or `superseded`. Repeat the parameter or separate the states with commas. Every state when absent."),
        ("severity" = Option<String>, Query, description = "Only proposals of these severities: `info`, `warning` or `critical`."),
        ("prefix" = Option<String>, Query, description = "Only proposals about this prefix (identifier): its own subject, an address or a network inside it, or the prefix among the involved objects."),
        ("subject" = Option<String>, Query, description = "Only proposals about this subject: a MAC address, an IP address, an object identifier, or text contained in the subject name or key."),
        ("sort" = Option<String>, Query, description = "Sort order: comma-separated fields, `-` in front for descending. Fields: `created` (the default, newest first), `updated`, `severity`, `kind`, `state`, `last_seen`.")
    ),
    responses(
        (status = 200, description = "A page of proposals", body = Page<IntentProposal>),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The prefix filter names no prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_proposals(
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<Page<IntentProposal>>, ApiError> {
    filters.only(&["kind", "state", "severity", "prefix", "subject", "sort"])?;
    let page = filters.page()?;
    let scope = filters.scope("ipam.proposals");
    let query = ProposalQuery {
        kinds: enum_params::<IntentProposalKind>(&filters, "kind", "a proposal kind")?,
        states: enum_params::<IntentProposalState>(&filters, "state", "a proposal state")?,
        severities: enum_params::<ProposalSeverity>(&filters, "severity", "a severity")?,
        prefix: filters.parse::<PrefixId>("prefix")?,
        subject: filters.get("subject")?.map(str::to_owned),
        sort: filters
            .sort(SORTS, &[SortKey::desc("created")])?
            .into_iter()
            .map(|key| {
                if key.descending {
                    format!("-{}", key.field)
                } else {
                    key.field.to_owned()
                }
            })
            .collect(),
        limit: Some(page.limit()?),
        cursor: page.cursor::<String>(scope)?,
    };
    let view = ipam.view(page.at_least.map(Revision)).await?;
    let read = ipam.read_scope(&cx, ObjectKind::Proposal);
    if read.is_nothing() {
        return Ok(Json(Page::new(Vec::new(), None, view.revision())));
    }
    // A scoped reader sees the proposals whose subject lies in its scope, filtered before
    // paging so that pages stay full (IAM-01).
    let found = if read.is_all() {
        query::list(view.as_ref(), &query)?
    } else {
        query::list_where(view.as_ref(), &query, &|proposal: &IntentProposal| {
            read.admits_by(|index| index.anchors_of_proposal(proposal))
        })?
    };
    Ok(Json(Page::new(
        found.items,
        found
            .next_cursor
            .map(|cursor| encode_cursor(scope, &cursor)),
        found.revision,
    )))
}

/// Shows one proposal with its `ETag`.
#[utoipa::path(
    get,
    path = "/proposals/{id}",
    tag = "proposals",
    operation_id = "get_proposal",
    summary = "Get one proposal",
    params(("id" = String, Path, description = "Proposal identifier"), ReadParams),
    responses(
        (status = 200, description = "The proposal, with `ETag: \"<revision>\"`", body = IntentProposal),
        (status = 400, description = "A parameter is unknown or malformed (`sys.invalid_query`, `sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read the proposal", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such proposal (`ipam.proposal.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_proposal(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<ProposalId>,
    filters: Filters,
) -> Result<Response, ApiError> {
    filters.only(&[])?;
    let at_least = filters.page()?.at_least.map(Revision);
    authorize(&app, &cx, Action::Read, ObjectRef::from(id))?;
    let view = ipam.view(at_least).await?;
    let proposal = query::get(view.as_ref(), id)?;
    let revision = proposal.revision;
    Ok(with_etag(Json(proposal).into_response(), revision))
}

/// Approves a proposal: applies its commands and marks it accepted, in one batch.
#[utoipa::path(
    post,
    path = "/proposals/{id}/approve",
    tag = "proposals",
    operation_id = "approve_proposal",
    summary = "Approve a proposal",
    params(("id" = String, Path, description = "Proposal identifier"), WriteParams, IfMatch),
    responses(
        (status = 200, description = "The decision: the accepted proposal, the revision, the inline job and the objects changed, with `ETag` of the proposal; on a dry run the proposal as it is and the plan, with nothing written", body = Decision),
        (status = 400, description = "A parameter is unknown or malformed (`sys.invalid_query`, `sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not approve proposals, or not make one of the changes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such proposal (`ipam.proposal.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The proposal is decided already (`ipam.proposal.not_open`), suggests no change (`ipam.proposal.nothing_to_apply`), a warning needs an acknowledgement (`ipam.plan.unacknowledged`), or the change conflicts with intent (`ipam.name_taken`, `ipam.address.duplicate`, `ipam.reference_missing`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "If-Match is stale (`ipam.proposal.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "A host of the change is locked (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn approve_proposal(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    reconciler: Option<Extension<Arc<Reconciler>>>,
    IpamPath(id): IpamPath<ProposalId>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize_approval(&app, &cx, &ipam, id, &args.options).await?;
    let decision =
        proposals::approve(&ipam, id, &cx, &args.options, args.dry_run, expected).await?;
    if !decision.dry_run {
        nudge(reconciler.as_ref());
    }
    Ok(decided(decision))
}

/// What an approval of proposal `id` needs: [`Action::Approve`] on the proposal, what each
/// of its commands needs on its own, and, for a scoped principal, a plan that stays inside
/// its scope. Shared by the single and the batch approval.
async fn authorize_approval(
    app: &AppState,
    cx: &RequestCtx,
    ipam: &IpamHandle,
    id: ProposalId,
    options: &PlanOptions,
) -> Result<(), ApiError> {
    authorize(app, cx, Action::Approve, ObjectRef::from(id))?;
    // The principal needs what each command needs on its own. The commands of a proposal
    // never change once it is open (a changed set supersedes it with a new proposal), so
    // what is checked here is what the approval applies.
    let view = ipam.view(None).await?;
    let proposal = query::get(view.as_ref(), id)?;
    drop(view);
    for command in &proposal.commands {
        let (action, object) = command_access(command);
        authorize(app, cx, action, object)?;
    }
    // A scoped principal's approval is planned and checked first: every object the
    // proposal creates, changes or deletes must lie inside its scope (IAM-01).
    ipam.check(cx, &proposal.commands, options).await
}

/// Rejects a proposal and remembers its evidence, so the same subject does not open again
/// until the evidence changes.
#[utoipa::path(
    post,
    path = "/proposals/{id}/reject",
    tag = "proposals",
    operation_id = "reject_proposal",
    summary = "Reject a proposal",
    params(("id" = String, Path, description = "Proposal identifier"), IfMatch),
    request_body = RejectRequest,
    responses(
        (status = 200, description = "The decision: the rejected proposal and the revision, with `ETag` of the proposal", body = Decision),
        (status = 400, description = "The reason is over 1,024 bytes or has control characters (`ipam.validation`), the body is malformed (`sys.invalid_request`), or a parameter is unknown (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not decide proposals", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such proposal (`ipam.proposal.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The proposal is decided already (`ipam.proposal.not_open`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "If-Match is stale (`ipam.proposal.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn reject_proposal(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<ProposalId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(request): IpamJson<RejectRequest>,
) -> Result<Response, ApiError> {
    filters.only(&[])?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Approve, ObjectRef::from(id))?;
    let decision = proposals::reject(&ipam, id, request.reason, &cx, expected).await?;
    Ok(decided(decision))
}

/// Approves many proposals, each as the single approval does, one after the other.
#[utoipa::path(
    post,
    path = "/proposals/approve",
    tag = "proposals",
    operation_id = "approve_proposals",
    summary = "Approve many proposals",
    request_body = BatchApproveRequest,
    responses(
        (status = 200, description = "The outcome of every proposal, in the order of the request, and the counts. A proposal that is not open any more, that the principal may not approve, or that the single approval refuses is `skipped` with the code and message of that refusal; the others are applied", body = BatchDecision),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or a parameter is unknown (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not approve proposals at all", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "No identifier (`ipam.proposal.batch_empty`) or more than 500 (`ipam.proposal.batch_too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn approve_proposals(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    reconciler: Option<Extension<Arc<Reconciler>>>,
    filters: Filters,
    IpamJson(request): IpamJson<BatchApproveRequest>,
) -> Result<Json<BatchDecision>, ApiError> {
    filters.only(&[])?;
    check_batch_size(request.ids.len())?;
    authorize(&app, &cx, Action::Approve, new_of(ObjectKind::Proposal))?;
    let options = PlanOptions::default();
    let each = for_each_proposal(&cx);
    let mut results = Vec::with_capacity(request.ids.len());
    for id in request.ids {
        let outcome = async {
            authorize_approval(&app, &each, &ipam, id, &options).await?;
            let decision = proposals::approve(&ipam, id, &each, &options, false, None).await?;
            Ok::<_, ApiError>(decision)
        }
        .await;
        results.push(BatchItem::new(id, BatchOutcome::Approved, outcome));
    }
    let decision = BatchDecision::of(results);
    if decision.approved > 0 {
        nudge(reconciler.as_ref());
    }
    Ok(Json(decision))
}

/// Rejects many proposals, each as the single rejection does, one after the other.
#[utoipa::path(
    post,
    path = "/proposals/reject",
    tag = "proposals",
    operation_id = "reject_proposals",
    summary = "Reject many proposals",
    request_body = BatchRejectRequest,
    responses(
        (status = 200, description = "The outcome of every proposal, in the order of the request, and the counts. A proposal that is not open any more or that the principal may not decide is `skipped` with the code and message of that refusal; the others are rejected with the same reason", body = BatchDecision),
        (status = 400, description = "The reason is over 1,024 bytes or has control characters (`ipam.validation`), the body is malformed (`sys.invalid_request`), or a parameter is unknown (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not decide proposals at all", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "No identifier (`ipam.proposal.batch_empty`) or more than 500 (`ipam.proposal.batch_too_large`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn reject_proposals(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
    IpamJson(request): IpamJson<BatchRejectRequest>,
) -> Result<Json<BatchDecision>, ApiError> {
    filters.only(&[])?;
    check_batch_size(request.ids.len())?;
    // The reason is the same for every proposal: a bad one refuses the request, it does not
    // skip each proposal in turn.
    let reason = proposals::clean_reason(request.reason)?;
    authorize(&app, &cx, Action::Approve, new_of(ObjectKind::Proposal))?;
    let each = for_each_proposal(&cx);
    let mut results = Vec::with_capacity(request.ids.len());
    for id in request.ids {
        let outcome = async {
            authorize(&app, &each, Action::Approve, ObjectRef::from(id))?;
            let decision = proposals::reject(&ipam, id, reason.clone(), &each, None).await?;
            Ok::<_, ApiError>(decision)
        }
        .await;
        results.push(BatchItem::new(id, BatchOutcome::Rejected, outcome));
    }
    Ok(Json(BatchDecision::of(results)))
}

/// The context each proposal of a batch is decided in: the request's, without its idempotency
/// key. The key belongs to the batch as a whole (a repeat of the request is answered from its
/// first answer); handed to every approval it would match the receipt of the first one against
/// the commands of the next and refuse them with `ipam.idempotency_mismatch`.
fn for_each_proposal(cx: &RequestCtx) -> RequestCtx {
    RequestCtx {
        idempotency: None,
        ..cx.clone()
    }
}

/// The 422 of a batch with no proposal or too many.
fn check_batch_size(count: usize) -> Result<(), ApiError> {
    if count == 0 {
        return Err(ApiError::from_coded_error(
            CodedError::new(
                proposals::codes::BATCH_EMPTY,
                422,
                "name at least one proposal",
            )
            .with_title("Unprocessable content"),
        ));
    }
    if count > MAX_BATCH {
        return Err(ApiError::from_coded_error(
            CodedError::new(
                proposals::codes::BATCH_TOO_LARGE,
                422,
                format!("{count} proposals exceed the limit of {MAX_BATCH} in one request"),
            )
            .with_title("Unprocessable content")
            .with_param("count", count.to_string())
            .with_param("limit", MAX_BATCH.to_string()),
        ));
    }
    Ok(())
}

/// Runs the reconciler once, now, instead of waiting for its interval.
// The Slice 8 follow-ups (the proposal batches): the report says how many batches the write
// took and what a failed batch left for the next run.
#[utoipa::path(
    post,
    path = "/proposals/reconcile",
    tag = "proposals",
    operation_id = "reconcile_proposals",
    summary = "Run the reconciler now",
    responses(
        (status = 200, description = "What the run did: proposals opened, refreshed, superseded, expired and adopted, the revision of its write, how many batches the write took, and what a batch that failed twice left for the next run (`unwritten`, `failure`)", body = ReconcileReport),
        (status = 400, description = "A parameter is unknown (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not decide proposals", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The reconciler does not run on this server (`ipam.reconciler.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn reconcile_proposals(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    reconciler: Option<Extension<Arc<Reconciler>>>,
    filters: Filters,
) -> Result<Json<ReconcileReport>, ApiError> {
    filters.only(&[])?;
    authorize(&app, &cx, Action::Approve, new_of(ObjectKind::Proposal))?;
    let Some(Extension(reconciler)) = reconciler else {
        return Err(reconciler_unavailable());
    };
    Ok(Json(reconciler.reconcile(Timestamp::now()).await?))
}

// ===== adoption policies =============================================================

/// Shows the adoption policy of a prefix: its own, the one in force and where it comes from.
#[utoipa::path(
    get,
    path = "/prefixes/{id}/adoption",
    tag = "proposals",
    operation_id = "get_adoption_policy",
    summary = "Get the adoption policy of a prefix",
    params(("id" = String, Path, description = "Prefix identifier"), ReadParams),
    responses(
        (status = 200, description = "The policy view, with `ETag: \"<revision>\"` of the prefix's own policy (`\"0\"` without one)", body = PolicyView),
        (status = 400, description = "A parameter is unknown or malformed (`sys.invalid_query`, `sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read the prefix", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The prefix is deleted (`ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_adoption_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<PrefixId>,
    filters: Filters,
) -> Result<Response, ApiError> {
    filters.only(&[])?;
    let at_least = filters.page()?.at_least.map(Revision);
    authorize(&app, &cx, Action::Read, ObjectRef::from(id))?;
    let view = ipam.view(at_least).await?;
    let policy = proposals::policy_view(view.as_ref(), id)?;
    Ok(policy_response(policy))
}

/// A policy view as the answer, with `ETag` of the prefix's own policy.
fn policy_response(policy: PolicyView) -> Response {
    let revision = policy.revision;
    with_etag(Json(policy).into_response(), revision)
}

/// Sets the adoption policy of a prefix. The prefixes inside it that have no policy of their
/// own inherit it.
#[utoipa::path(
    put,
    path = "/prefixes/{id}/adoption",
    tag = "proposals",
    operation_id = "set_adoption_policy",
    summary = "Set the adoption policy of a prefix",
    params(("id" = String, Path, description = "Prefix identifier"), IfMatch),
    request_body = AdoptionPolicy,
    responses(
        (status = 200, description = "The policy view after the change, with `ETag`", body = PolicyView),
        (status = 400, description = "The policy is invalid (`ipam.adoption.invalid`), the body is malformed (`sys.invalid_request`), or a parameter is unknown (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not change the prefix", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The prefix is deleted (`ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "If-Match is stale (`ipam.revision_mismatch`); `\"0\"` means that the prefix has no policy of its own", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn set_adoption_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    reconciler: Option<Extension<Arc<Reconciler>>>,
    IpamPath(id): IpamPath<PrefixId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(policy): IpamJson<AdoptionPolicy>,
) -> Result<Response, ApiError> {
    filters.only(&[])?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Update, ObjectRef::from(id))?;
    let view = proposals::set_policy(&ipam, id, Some(policy), &cx, expected).await?;
    nudge(reconciler.as_ref());
    Ok(policy_response(view))
}

/// Removes the adoption policy of a prefix: it inherits again.
#[utoipa::path(
    delete,
    path = "/prefixes/{id}/adoption",
    tag = "proposals",
    operation_id = "clear_adoption_policy",
    summary = "Remove the adoption policy of a prefix",
    params(("id" = String, Path, description = "Prefix identifier"), IfMatch),
    responses(
        (status = 200, description = "The policy view after the change: no policy of its own, the inherited one in force", body = PolicyView),
        (status = 400, description = "A parameter is unknown or malformed (`sys.invalid_query`, `sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not change the prefix", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such prefix (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The prefix is deleted (`ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "If-Match is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn clear_adoption_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    reconciler: Option<Extension<Arc<Reconciler>>>,
    IpamPath(id): IpamPath<PrefixId>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    filters.only(&[])?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Update, ObjectRef::from(id))?;
    let view = proposals::set_policy(&ipam, id, None, &cx, expected).await?;
    nudge(reconciler.as_ref());
    Ok(policy_response(view))
}

/// Route tests of the proposals area, driven through the router over a fresh in-memory
/// store with a reconciler. Test data stays in the documentation ranges (192.0.2.0/24,
/// 198.51.100.0/24, MAC addresses 00-00-5E-00-53-xx).
#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        time::Duration,
    };

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use serde_json::{Value, json};
    use tenko_core::{
        AuthStrength, Authorizer, ConnectorId, Denied, DenyReason, ObservationId, Principal,
        RequestCtx, ScopeFilter, SessionId, UserId,
        ipam::{Host, PrefixRole},
        observe::{Observation, ObservationSource, Observed, ObservedHost},
    };
    use tenko_ipam::{
        IpamCommand, IpamService, PlanOptions,
        command::{HostInput, PrefixInput},
        observe::IngestBatch,
        query as ipam_query,
        reconcile::ReconcilerConfig,
    };
    use tenko_store::{MemStore, Store};
    use tower::ServiceExt;

    use super::super::tenancy::testkit::{Policy, Reply};
    use super::*;
    use crate::API_BASE;

    /// Devices of the documentation block, with the address each one reports.
    const WEB_MAC: &str = "00-00-5E-00-53-01";
    const DB_MAC: &str = "00-00-5E-00-53-02";
    const TWIN_A_MAC: &str = "00-00-5E-00-53-41";
    const TWIN_B_MAC: &str = "00-00-5E-00-53-42";

    // ----- harness ---------------------------------------------------------------------

    /// The routes of the area under the API base, over `state`.
    fn router(state: AppState) -> Router {
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        router.with_state(state)
    }

    /// An authorizer that allows everything except the listed actions.
    struct Deny(Vec<Action>);

    impl Authorizer for Deny {
        fn check(
            &self,
            _principal: &Principal,
            action: Action,
            object: &ObjectRef,
        ) -> Result<(), Denied> {
            if self.0.contains(&action) {
                Err(Denied {
                    action,
                    object: *object,
                    reason: DenyReason::MissingPermission,
                })
            } else {
                Ok(())
            }
        }

        fn scope(&self, _principal: &Principal, _action: Action, _kind: ObjectKind) -> ScopeFilter {
            ScopeFilter::All
        }
    }

    /// The proposals routes over one IPAM service and one reconciler, with the network
    /// 192.0.2.0/24 in the default VRF.
    struct Lab {
        router: Router,
        service: Arc<IpamService>,
        reconciler: Arc<Reconciler>,
        connector: ConnectorId,
        network: PrefixId,
    }

    impl Lab {
        async fn new() -> Self {
            let store: Arc<dyn Store> = Arc::new(MemStore::default());
            let service = IpamService::with_direct_jobs(store).expect("service");
            let reconciler = Reconciler::new(Arc::clone(&service), ReconcilerConfig::default())
                .expect("reconciler");
            let network = PrefixId::generate();
            let mut lab = Self {
                router: Router::new(),
                service,
                reconciler,
                connector: ConnectorId::generate(),
                network,
            };
            lab.router = lab.mounted(AppState::default());
            lab.make(vec![IpamCommand::CreatePrefix(prefix(
                Some(network),
                "192.0.2.0/24",
                None,
            ))])
            .await;
            lab
        }

        /// The routes with the IPAM service and the reconciler as extensions.
        fn mounted(&self, state: AppState) -> Router {
            router(state)
                .layer(Extension(Arc::clone(&self.service)))
                .layer(Extension(Arc::clone(&self.reconciler)))
        }

        /// The same service and store behind another router.
        fn behind(&self, router: Router) -> Self {
            Self {
                router,
                service: Arc::clone(&self.service),
                reconciler: Arc::clone(&self.reconciler),
                connector: self.connector,
                network: self.network,
            }
        }

        /// The same lab with `authorizer` checking every request.
        fn checked_by(&self, authorizer: Arc<dyn Authorizer>) -> Self {
            self.behind(self.mounted(AppState {
                authorizer: Some(authorizer),
                ..AppState::default()
            }))
        }

        /// The same lab on a server that runs no reconciler.
        fn without_reconciler(&self) -> Self {
            self.behind(router(AppState::default()).layer(Extension(Arc::clone(&self.service))))
        }

        /// The same lab on a server without IPAM.
        fn without_ipam(&self) -> Self {
            self.behind(router(AppState::default()))
        }

        /// Runs commands as a person.
        async fn make(&self, commands: Vec<IpamCommand>) {
            let cx = RequestCtx::new(Principal::User {
                id: UserId::generate(),
                session: SessionId::generate(),
                strength: AuthStrength::Passkey,
            });
            self.service
                .execute(&commands, &cx, &PlanOptions::default())
                .await
                .expect("execute");
        }

        /// One complete inventory poll of the connector, seen now.
        async fn poll(&self, hosts: Vec<ObservedHost>) {
            let when = Timestamp::now();
            let source = ObservationSource::Inventory {
                connector: self.connector,
            };
            let observations = hosts
                .into_iter()
                .map(|host| Observation {
                    id: ObservationId::generate(),
                    source: source.clone(),
                    subject: Observed::Host(host),
                    observed_at: when,
                    received_at: when,
                    expires_at: when.checked_add(Duration::from_secs(900)),
                })
                .collect();
            self.reconciler
                .ingest(IngestBatch {
                    source,
                    observations,
                    complete: true,
                    received_at: when,
                })
                .await
                .expect("ingest");
        }

        /// A run of the reconciler, now.
        async fn reconcile(&self) -> ReconcileReport {
            self.reconciler
                .reconcile(Timestamp::now())
                .await
                .expect("reconcile")
        }

        /// Two devices that intent does not know, and two on one address; one run.
        async fn discover(&self) {
            self.poll(vec![
                vm("qemu/101", "web01", WEB_MAC, "192.0.2.10"),
                vm("qemu/102", "db01", DB_MAC, "192.0.2.11"),
                vm("qemu/103", "twin-a", TWIN_A_MAC, "192.0.2.40"),
                vm("qemu/104", "twin-b", TWIN_B_MAC, "192.0.2.40"),
            ])
            .await;
            self.reconcile().await;
        }

        /// One unknown device and one run; the identifier of its proposal.
        async fn discover_web(&self) -> String {
            self.poll(vec![vm("qemu/101", "web01", WEB_MAC, "192.0.2.10")])
                .await;
            let report = self.reconcile().await;
            assert_eq!(report.opened, 1, "{report:?}");
            let list = self.get("/proposals?state=open&kind=discovered_host").await;
            list.assert_json(200);
            assert_eq!(list.items().len(), 1, "{}", list.body);
            list.ids().remove(0)
        }

        /// The names of the hosts of intent.
        async fn host_names(&self) -> Vec<String> {
            let view = self.service.view(None).await.expect("view");
            ipam_query::list::<Host>(view.as_ref(), &ipam_query::ListQuery::default())
                .expect("hosts")
                .items
                .into_iter()
                .map(|host| host.name.to_string())
                .collect()
        }

        /// Asserts that intent has no host.
        async fn assert_no_hosts(&self) {
            assert_eq!(self.host_names().await, Vec::<String>::new());
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
            Reply {
                status,
                content_type,
                etag,
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            }
        }

        async fn get(&self, path: &str) -> Reply {
            self.send("GET", path, &[], None).await
        }

        /// `POST` without a body.
        async fn post(&self, path: &str, headers: &[(&str, &str)]) -> Reply {
            self.send("POST", path, headers, None).await
        }

        /// A request with a JSON body.
        async fn with_json(
            &self,
            method: &str,
            path: &str,
            headers: &[(&str, &str)],
            body: &Value,
        ) -> Reply {
            let body = Some(("application/json", body.to_string()));
            self.send(method, path, headers, body).await
        }

        async fn delete(&self, path: &str, headers: &[(&str, &str)]) -> Reply {
            self.send("DELETE", path, headers, None).await
        }

        /// Walks a list page by page and returns the pages.
        async fn pages(&self, path: &str, limit: usize) -> Vec<Reply> {
            let separator = if path.contains('?') { '&' } else { '?' };
            let mut next = format!("{path}{separator}limit={limit}");
            let mut pages = Vec::new();
            loop {
                assert!(pages.len() < 50, "the cursor never ends");
                let reply = self.get(&next).await;
                reply.assert_json(200);
                assert!(reply.items().len() <= limit, "{}", reply.body);
                let cursor = reply.body["next_cursor"].as_str().map(str::to_owned);
                pages.push(reply);
                match cursor {
                    Some(cursor) => {
                        next = format!("{path}{separator}limit={limit}&cursor={cursor}");
                    }
                    None => return pages,
                }
            }
        }
    }

    /// An inventory host with one MAC address and one address.
    fn vm(id: &str, name: &str, mac: &str, ip: &str) -> ObservedHost {
        ObservedHost {
            external_id: id.to_owned(),
            name: Some(name.to_owned()),
            macs: vec![mac.parse().expect("mac")],
            ips: vec![ip.parse().expect("ip")],
            os: Some("Linux 6.x".to_owned()),
            platform: Some("qemu".to_owned()),
            parent: Some("pve1".to_owned()),
            tags: Vec::new(),
        }
    }

    fn prefix(id: Option<PrefixId>, cidr: &str, role: Option<PrefixRole>) -> PrefixInput {
        PrefixInput {
            id,
            vrf: None,
            cidr: cidr.parse().expect("cidr"),
            role,
            status: None,
            vlan: None,
            site: None,
            alarm: None,
            alloc: None,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }
    }

    fn host_named(name: &str) -> HostInput {
        HostInput {
            id: None,
            tenant: None,
            name: name.parse().expect("name"),
            mode: None,
            lock: None,
            site: None,
            interfaces: Vec::new(),
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }
    }

    // ----- lists and reads -------------------------------------------------------------

    #[tokio::test]
    async fn the_list_filters_by_kind_state_severity_prefix_and_subject() {
        let lab = Lab::new().await;
        lab.discover().await;
        let all = lab.get("/proposals").await;
        all.assert_json(200);
        assert!(all.items().len() >= 3, "{}", all.body);
        assert!(all.body["revision"].as_u64().is_some(), "{}", all.body);
        let open = lab.get("/proposals?state=open").await;
        assert_eq!(open.ids().len(), all.ids().len(), "everything is open");
        lab.get("/proposals?state=accepted")
            .await
            .assert_json(200)
            .assert_no_items();

        let conflicts = lab.get("/proposals?kind=conflict").await;
        conflicts.assert_json(200);
        assert_eq!(conflicts.items().len(), 1, "{}", conflicts.body);
        let conflict = &conflicts.items()[0];
        assert_eq!(conflict["rule"], "ipam.reconcile.conflict_shared_address");
        assert_eq!(conflict["severity"], "critical");
        assert_eq!(conflict["state"], "open");
        assert_eq!(conflict["commands"], json!([]));
        let discovered = lab.get("/proposals?kind=discovered_host").await;
        assert!(discovered.items().len() >= 2, "{}", discovered.body);

        // Repeated and comma-separated values both count.
        let both = discovered.items().len() + conflicts.items().len();
        for path in [
            "/proposals?kind=conflict&kind=discovered_host",
            "/proposals?kind=conflict,discovered_host",
        ] {
            let reply = lab.get(path).await;
            reply.assert_json(200);
            assert_eq!(reply.items().len(), both, "{path}: {}", reply.body);
        }
        let critical = lab.get("/proposals?severity=critical").await;
        assert_eq!(critical.ids(), conflicts.ids());
        let others = lab.get("/proposals?severity=info,warning").await;
        assert_eq!(
            others.items().len(),
            all.items().len() - 1,
            "{}",
            others.body
        );

        // A prefix: its addresses and its network.
        let by_prefix = lab.get(&format!("/proposals?prefix={}", lab.network)).await;
        by_prefix.assert_json(200);
        assert_eq!(
            by_prefix.items().len(),
            all.items().len(),
            "{}",
            by_prefix.body
        );

        // A subject: a MAC address in either spelling, an address.
        for mac in [WEB_MAC, "00:00:5e:00:53:01"] {
            let by_mac = lab.get(&format!("/proposals?subject={mac}")).await;
            by_mac.assert_json(200);
            assert_eq!(by_mac.items().len(), 1, "{mac}: {}", by_mac.body);
            assert_eq!(by_mac.items()[0]["kind"], "discovered_host");
            assert_eq!(by_mac.items()[0]["subject"]["ip"], "192.0.2.10");
        }
        let by_ip = lab.get("/proposals?subject=192.0.2.11").await;
        assert_eq!(by_ip.items().len(), 1, "{}", by_ip.body);
        assert_eq!(by_ip.items()[0]["subject"]["mac"], "00:00:5e:00:53:02");
        let shared = lab.get("/proposals?subject=192.0.2.40").await;
        assert!(
            shared.ids().contains(&conflicts.ids()[0]),
            "the conflict names the shared address: {}",
            shared.body
        );
    }

    #[tokio::test]
    async fn the_list_sorts_and_pages() {
        let lab = Lab::new().await;
        lab.discover().await;
        let up = lab.get("/proposals?sort=severity").await;
        assert_eq!(
            up.texts("severity").last().map(String::as_str),
            Some("critical")
        );
        let down = lab.get("/proposals?sort=-severity").await;
        assert_eq!(down.texts("severity")[0], "critical");
        let default = lab.get("/proposals").await;
        let explicit = lab.get("/proposals?sort=-created").await;
        assert_eq!(default.ids(), explicit.ids(), "newest first by default");

        // Pages of one cover the list once, in order.
        let pages = lab.pages("/proposals?sort=kind,-created", 1).await;
        assert!(pages.len() >= 3, "{}", pages.len());
        let walked: Vec<String> = pages.iter().flat_map(Reply::ids).collect();
        let whole = lab.get("/proposals?sort=kind,-created").await;
        assert_eq!(walked, whole.ids());
        assert_eq!(pages.last().expect("page").body["next_cursor"], Value::Null);

        // A cursor belongs to its query.
        let cursor = pages[0].body["next_cursor"].as_str().expect("cursor");
        lab.get(&format!("/proposals?sort=kind&cursor={cursor}"))
            .await
            .assert_problem(400, "sys.invalid_cursor");
        lab.get("/proposals?cursor=garbage")
            .await
            .assert_problem(400, "sys.invalid_cursor");
    }

    #[tokio::test]
    async fn bad_list_parameters_answer_problem_details() {
        let lab = Lab::new().await;
        lab.discover().await;
        for path in [
            "/proposals?sort=bogus",
            "/proposals?sort=-created,created",
            "/proposals?kind=nope",
            "/proposals?state=pending",
            "/proposals?severity=urgent",
            "/proposals?prefix=not-an-id",
            "/proposals?bogus=1",
            "/proposals?limit=0",
            "/proposals?limit=1001",
            "/proposals?subject=a&subject=b",
        ] {
            lab.get(path).await.assert_problem(400, "sys.invalid_query");
        }
        let unknown = PrefixId::generate();
        lab.get(&format!("/proposals?prefix={unknown}"))
            .await
            .assert_problem(404, "ipam.not_found");
    }

    #[tokio::test]
    async fn one_proposal_is_read_with_its_etag() {
        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        let reply = lab.get(&format!("/proposals/{id}")).await;
        reply.assert_json(200);
        let revision = reply.body["revision"].as_u64().expect("revision");
        assert!(revision > 0, "{}", reply.body);
        assert_eq!(
            reply.etag.as_deref(),
            Some(format!("\"{revision}\"").as_str())
        );
        let body = &reply.body;
        assert_eq!(body["id"], id.as_str());
        assert_eq!(body["kind"], "discovered_host");
        assert_eq!(body["state"], "open");
        assert_eq!(body["rule"], "ipam.reconcile.discovered_mac");
        assert_eq!(body["evidence"][0]["name"], "web01");
        assert_eq!(body["commands"][0]["op"], "create_host");

        lab.get(&format!("/proposals/{}", ProposalId::generate()))
            .await
            .assert_problem(404, "ipam.proposal.not_found");
        lab.get("/proposals/not-an-id")
            .await
            .assert_problem(400, "sys.invalid_request");
        lab.get(&format!("/proposals/{id}?bogus=1"))
            .await
            .assert_problem(400, "sys.invalid_query");
        lab.get(&format!("/proposals/{id}?at_least={revision}"))
            .await
            .assert_json(200);
    }

    // ----- decisions -------------------------------------------------------------------

    #[tokio::test]
    async fn a_dry_run_writes_nothing_and_an_approval_makes_the_device_intent() {
        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        let path = format!("/proposals/{id}/approve");

        let preview = lab.post(&format!("{path}?dry_run=true"), &[]).await;
        preview.assert_json(200);
        let body = &preview.body;
        assert_eq!(body["dry_run"], true, "{body}");
        assert_eq!(body["revision"], Value::Null, "{body}");
        assert_eq!(body["job_id"], Value::Null, "{body}");
        assert_eq!(body["proposal"]["state"], "open", "{body}");
        assert!(body["plan"]["summary"]["lines"].is_array(), "{body}");
        let changes = body["plan"]["changes"].as_array().expect("changes");
        assert!(!changes.is_empty(), "{body}");
        assert_eq!(preview.etag, None);
        lab.assert_no_hosts().await;
        let still = lab.get(&format!("/proposals/{id}")).await;
        assert_eq!(still.body["state"], "open");

        let applied = lab.post(&path, &[]).await;
        applied.assert_json(200);
        let body = &applied.body;
        assert_eq!(body["dry_run"], false, "{body}");
        assert_eq!(body["proposal"]["state"], "accepted", "{body}");
        assert_eq!(body["proposal"]["id"], id.as_str(), "{body}");
        assert!(body["job_id"].is_string(), "{body}");
        let revision = body["revision"].as_u64().expect("revision");
        assert!(
            body["results"].as_array().expect("results").len() >= 2,
            "{body}"
        );
        assert_eq!(body["proposal"]["results"], body["results"], "{body}");
        assert_eq!(body["plan"], Value::Null, "{body}");
        assert_eq!(body["proposal"]["revision"], revision, "{body}");
        assert_eq!(
            applied.etag.as_deref(),
            Some(format!("\"{revision}\"").as_str()),
            "the ETag is the revision of the proposal"
        );
        assert_eq!(lab.host_names().await, ["web01"]);
        let stored = lab.get(&format!("/proposals/{id}")).await;
        assert_eq!(stored.body["state"], "accepted");
        assert_eq!(stored.body["revision"], revision);

        // Decided is decided.
        lab.post(&path, &[])
            .await
            .assert_problem(409, "ipam.proposal.not_open");
        lab.post(&format!("{path}?dry_run=true"), &[])
            .await
            .assert_problem(409, "ipam.proposal.not_open");
        lab.with_json("POST", &format!("/proposals/{id}/reject"), &[], &json!({}))
            .await
            .assert_problem(409, "ipam.proposal.not_open");

        // The device is intent now: the next run opens nothing.
        let report = lab.reconcile().await;
        assert_eq!(report.opened, 0, "{report:?}");
        lab.get("/proposals?state=open")
            .await
            .assert_json(200)
            .assert_no_items();
        let accepted = lab.get("/proposals?state=accepted").await;
        assert_eq!(accepted.ids(), [id]);
    }

    #[tokio::test]
    async fn a_stale_if_match_is_refused_and_a_current_one_is_accepted() {
        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        let path = format!("/proposals/{id}");
        let revision = lab.get(&path).await.body["revision"]
            .as_u64()
            .expect("revision");
        let stale = format!("\"{}\"", revision + 1);
        let current = format!("\"{revision}\"");

        let refused = lab
            .post(&format!("{path}/approve"), &[("if-match", &stale)])
            .await;
        refused.assert_problem(412, "ipam.proposal.revision_mismatch");
        lab.with_json(
            "POST",
            &format!("{path}/reject"),
            &[("if-match", "\"1\"")],
            &json!({}),
        )
        .await
        .assert_problem(412, "ipam.proposal.revision_mismatch");
        lab.post(&format!("{path}/approve"), &[("if-match", "garbage")])
            .await
            .assert_problem(400, "ipam.validation");
        assert_eq!(
            lab.get(&path).await.body["state"],
            "open",
            "nothing changed"
        );
        lab.assert_no_hosts().await;

        lab.post(&format!("{path}/approve"), &[("if-match", &current)])
            .await
            .assert_json(200);
        assert_eq!(lab.host_names().await, ["web01"]);
    }

    #[tokio::test]
    async fn a_rejection_keeps_its_reason_and_the_same_evidence_stays_closed() {
        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        let path = format!("/proposals/{id}/reject");

        // The body is checked before anything is written.
        let long = json!({ "reason": "x".repeat(2_000) });
        lab.with_json("POST", &path, &[], &long)
            .await
            .assert_problem(400, "ipam.validation");
        lab.with_json("POST", &path, &[], &json!({ "reason": "bell\u{7}" }))
            .await
            .assert_problem(400, "ipam.validation");
        lab.with_json("POST", &path, &[], &json!({ "reason": "x", "bogus": 1 }))
            .await
            .assert_problem(400, "sys.invalid_request");
        lab.send(
            "POST",
            &path,
            &[],
            Some(("application/json", "{".to_owned())),
        )
        .await
        .assert_problem(400, "sys.invalid_request");
        lab.post(&path, &[])
            .await
            .assert_problem(415, "sys.invalid_request");
        lab.with_json("POST", &format!("{path}?bogus=1"), &[], &json!({}))
            .await
            .assert_problem(400, "sys.invalid_query");
        assert_eq!(
            lab.get(&format!("/proposals/{id}")).await.body["state"],
            "open"
        );

        let reason = json!({ "reason": "  a lab device, not for the register  " });
        let rejected = lab.with_json("POST", &path, &[], &reason).await;
        rejected.assert_json(200);
        let body = &rejected.body;
        assert_eq!(body["dry_run"], false, "{body}");
        assert_eq!(body["proposal"]["state"], "rejected", "{body}");
        assert_eq!(
            body["proposal"]["reason"], "a lab device, not for the register",
            "{body}"
        );
        assert!(body["job_id"].is_string(), "{body}");
        assert_eq!(body["results"], json!([]), "{body}");
        assert_eq!(
            rejected.etag.as_deref(),
            Some(format!("\"{}\"", body["proposal"]["revision"]).as_str())
        );
        lab.assert_no_hosts().await;

        lab.with_json("POST", &path, &[], &json!({}))
            .await
            .assert_problem(409, "ipam.proposal.not_open");
        lab.post(&format!("/proposals/{id}/approve"), &[])
            .await
            .assert_problem(409, "ipam.proposal.not_open");

        // Neither the next run nor the endpoint opens the subject again.
        let report = lab.reconcile().await;
        assert_eq!(report.opened, 0, "{report:?}");
        let run = lab.post("/proposals/reconcile", &[]).await;
        run.assert_json(200);
        assert_eq!(run.body["opened"], 0, "{}", run.body);
        lab.get("/proposals?state=open")
            .await
            .assert_json(200)
            .assert_no_items();
        let all = lab.get("/proposals").await;
        assert_eq!(all.ids(), [id]);
        assert_eq!(all.items()[0]["state"], "rejected");
    }

    #[tokio::test]
    async fn a_rejection_needs_no_reason_and_unknown_proposals_are_404() {
        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        let rejected = lab
            .with_json("POST", &format!("/proposals/{id}/reject"), &[], &json!({}))
            .await;
        rejected.assert_json(200);
        assert_eq!(rejected.body["proposal"]["state"], "rejected");
        assert_eq!(rejected.body["proposal"]["reason"], Value::Null);
        let unknown = ProposalId::generate();
        lab.post(&format!("/proposals/{unknown}/approve"), &[])
            .await
            .assert_problem(404, "ipam.proposal.not_found");
        lab.with_json(
            "POST",
            &format!("/proposals/{unknown}/reject"),
            &[],
            &json!({}),
        )
        .await
        .assert_problem(404, "ipam.proposal.not_found");
    }

    #[tokio::test]
    async fn a_conflict_has_nothing_to_apply_until_a_person_closes_it() {
        let lab = Lab::new().await;
        lab.discover().await;
        let conflicts = lab.get("/proposals?kind=conflict").await;
        let id = conflicts.ids().remove(0);
        for path in [
            format!("/proposals/{id}/approve"),
            format!("/proposals/{id}/approve?dry_run=true"),
        ] {
            lab.post(&path, &[])
                .await
                .assert_problem(409, "ipam.proposal.nothing_to_apply");
        }
        lab.with_json(
            "POST",
            &format!("/proposals/{id}/reject"),
            &[],
            &json!({ "reason": "fixed on the switch" }),
        )
        .await
        .assert_json(200);
    }

    #[tokio::test]
    async fn an_approval_that_clashes_with_intent_is_refused_and_leaves_the_proposal_open() {
        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        // Someone creates the name first: the planner refuses the approval.
        lab.make(vec![IpamCommand::CreateHost(host_named("web01"))])
            .await;
        lab.post(&format!("/proposals/{id}/approve"), &[])
            .await
            .assert_problem(409, "ipam.name_taken");
        assert_eq!(
            lab.get(&format!("/proposals/{id}")).await.body["state"],
            "open"
        );
    }

    // ----- batch decisions -------------------------------------------------------------

    /// The identifiers of the open proposals of one kind.
    async fn open_ids(lab: &Lab, kind: &str) -> Vec<String> {
        let list = lab
            .get(&format!("/proposals?state=open&kind={kind}&sort=created"))
            .await;
        list.assert_json(200);
        list.ids()
    }

    /// The results of a batch answer as `(id, outcome, code)`.
    fn outcomes(reply: &Reply) -> Vec<(String, String, Option<String>)> {
        reply.body["results"]
            .as_array()
            .expect("results")
            .iter()
            .map(|item| {
                (
                    item["id"].as_str().expect("id").to_owned(),
                    item["outcome"].as_str().expect("outcome").to_owned(),
                    item["code"].as_str().map(str::to_owned),
                )
            })
            .collect()
    }

    /// An authorizer that allows everything but deciding the listed proposals, as the scope
    /// of an operator that covers some of the proposals and not others.
    struct OutOfScopeFor(Vec<ObjectRef>);

    impl Authorizer for OutOfScopeFor {
        fn check(
            &self,
            _principal: &Principal,
            action: Action,
            object: &ObjectRef,
        ) -> Result<(), Denied> {
            if action == Action::Approve && self.0.contains(object) {
                Err(Denied {
                    action,
                    object: *object,
                    reason: DenyReason::OutOfScope,
                })
            } else {
                Ok(())
            }
        }

        fn scope(&self, _principal: &Principal, _action: Action, _kind: ObjectKind) -> ScopeFilter {
            ScopeFilter::All
        }
    }

    #[tokio::test]
    async fn a_batch_approval_makes_every_device_intent_and_answers_each() {
        let lab = Lab::new().await;
        lab.poll(vec![
            vm("qemu/101", "web01", WEB_MAC, "192.0.2.10"),
            vm("qemu/102", "db01", DB_MAC, "192.0.2.11"),
        ])
        .await;
        assert_eq!(lab.reconcile().await.opened, 2);
        let ids = open_ids(&lab, "discovered_host").await;
        assert_eq!(ids.len(), 2);

        let reply = lab
            .with_json("POST", "/proposals/approve", &[], &json!({ "ids": ids }))
            .await;
        reply.assert_json(200);
        let body = &reply.body;
        assert_eq!(
            (
                body["approved"].as_u64(),
                body["rejected"].as_u64(),
                body["skipped"].as_u64()
            ),
            (Some(2), Some(0), Some(0)),
            "{body}"
        );
        let expected: Vec<_> = ids
            .iter()
            .map(|id| (id.clone(), "approved".to_owned(), None))
            .collect();
        assert_eq!(outcomes(&reply), expected, "the order of the request");
        let mut names = lab.host_names().await;
        names.sort();
        assert_eq!(names, ["db01", "web01"]);
        assert_eq!(open_ids(&lab, "discovered_host").await.len(), 0);
        let accepted = lab.get("/proposals?state=accepted").await;
        assert_eq!(accepted.items().len(), 2, "{}", accepted.body);
        let report = lab.reconcile().await;
        assert_eq!(report.opened, 0, "{report:?}");
    }

    #[tokio::test]
    async fn a_batch_approval_skips_what_the_single_route_refuses_and_applies_the_rest() {
        let lab = Lab::new().await;
        lab.discover().await;
        let web = lab
            .get(&format!("/proposals?state=open&subject={WEB_MAC}"))
            .await
            .ids()
            .remove(0);
        let conflict = open_ids(&lab, "conflict").await.remove(0);
        let unknown = ProposalId::generate().to_string();
        let ids = [&conflict, &unknown, &web, &web];

        let reply = lab
            .with_json("POST", "/proposals/approve", &[], &json!({ "ids": ids }))
            .await;
        reply.assert_json(200);
        let body = &reply.body;
        assert_eq!(
            (
                body["approved"].as_u64(),
                body["rejected"].as_u64(),
                body["skipped"].as_u64()
            ),
            (Some(1), Some(0), Some(3)),
            "{body}"
        );
        assert_eq!(
            outcomes(&reply),
            [
                (
                    conflict.clone(),
                    "skipped".to_owned(),
                    Some("ipam.proposal.nothing_to_apply".to_owned())
                ),
                (
                    unknown.clone(),
                    "skipped".to_owned(),
                    Some("ipam.proposal.not_found".to_owned())
                ),
                (web.clone(), "approved".to_owned(), None),
                (
                    web.clone(),
                    "skipped".to_owned(),
                    Some("ipam.proposal.not_open".to_owned())
                ),
            ]
        );
        let results = body["results"].as_array().expect("results");
        assert_eq!(results[0]["status"], 409, "{body}");
        assert_eq!(results[1]["status"], 404, "{body}");
        assert!(
            results[0]["message"]
                .as_str()
                .is_some_and(|m| !m.is_empty()),
            "{body}"
        );
        assert_eq!(results[2]["code"], Value::Null, "{body}");
        assert!(lab.host_names().await.contains(&"web01".to_owned()));
        assert_eq!(
            lab.get(&format!("/proposals/{conflict}")).await.body["state"],
            "open",
            "a skipped proposal is left as it was"
        );
    }

    #[tokio::test]
    async fn a_batch_rejection_records_one_reason_and_skips_the_decided() {
        let lab = Lab::new().await;
        lab.poll(vec![
            vm("qemu/101", "web01", WEB_MAC, "192.0.2.10"),
            vm("qemu/102", "db01", DB_MAC, "192.0.2.11"),
        ])
        .await;
        lab.reconcile().await;
        let ids = open_ids(&lab, "discovered_host").await;

        // A bad reason refuses the request and decides nothing.
        let bad = json!({ "ids": ids, "reason": "bell\u{7}" });
        lab.with_json("POST", "/proposals/reject", &[], &bad)
            .await
            .assert_problem(400, "ipam.validation");
        let long = json!({ "ids": ids, "reason": "x".repeat(2_000) });
        lab.with_json("POST", "/proposals/reject", &[], &long)
            .await
            .assert_problem(400, "ipam.validation");
        assert_eq!(open_ids(&lab, "discovered_host").await.len(), 2);

        lab.with_json(
            "POST",
            &format!("/proposals/{}/reject", ids[0]),
            &[],
            &json!({}),
        )
        .await
        .assert_json(200);
        let reason = json!({ "ids": ids, "reason": "  lab devices, not for the register  " });
        let reply = lab
            .with_json("POST", "/proposals/reject", &[], &reason)
            .await;
        reply.assert_json(200);
        let body = &reply.body;
        assert_eq!(
            (
                body["approved"].as_u64(),
                body["rejected"].as_u64(),
                body["skipped"].as_u64()
            ),
            (Some(0), Some(1), Some(1)),
            "{body}"
        );
        assert_eq!(
            outcomes(&reply),
            [
                (
                    ids[0].clone(),
                    "skipped".to_owned(),
                    Some("ipam.proposal.not_open".to_owned())
                ),
                (ids[1].clone(), "rejected".to_owned(), None),
            ]
        );
        let stored = lab.get(&format!("/proposals/{}", ids[1])).await;
        assert_eq!(stored.body["state"], "rejected");
        assert_eq!(stored.body["reason"], "lab devices, not for the register");
        lab.assert_no_hosts().await;
        // Rejected is remembered: the next run opens nothing.
        assert_eq!(lab.reconcile().await.opened, 0);

        // No reason is fine.
        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        let reply = lab
            .with_json("POST", "/proposals/reject", &[], &json!({ "ids": [id] }))
            .await;
        reply.assert_json(200);
        assert_eq!(reply.body["rejected"], 1, "{}", reply.body);
    }

    #[tokio::test]
    async fn a_scoped_operator_decides_what_it_may_and_the_rest_is_skipped() {
        let lab = Lab::new().await;
        lab.poll(vec![
            vm("qemu/101", "web01", WEB_MAC, "192.0.2.10"),
            vm("qemu/102", "db01", DB_MAC, "192.0.2.11"),
            vm("qemu/103", "app01", "00-00-5E-00-53-03", "192.0.2.12"),
        ])
        .await;
        lab.reconcile().await;
        let ids = open_ids(&lab, "discovered_host").await;
        assert_eq!(ids.len(), 3);
        let outside = ObjectRef::from(ids[1].parse::<ProposalId>().expect("id"));
        let scoped = lab.checked_by(Arc::new(OutOfScopeFor(vec![outside])));

        let reply = scoped
            .with_json("POST", "/proposals/approve", &[], &json!({ "ids": ids }))
            .await;
        reply.assert_json(200);
        let body = &reply.body;
        assert_eq!(
            (body["approved"].as_u64(), body["skipped"].as_u64()),
            (Some(2), Some(1)),
            "{body}"
        );
        assert_eq!(
            outcomes(&reply),
            [
                (ids[0].clone(), "approved".to_owned(), None),
                (
                    ids[1].clone(),
                    "skipped".to_owned(),
                    Some("auth.out_of_scope".to_owned())
                ),
                (ids[2].clone(), "approved".to_owned(), None),
            ]
        );
        assert_eq!(body["results"][1]["status"], 403, "{body}");
        assert_eq!(open_ids(&lab, "discovered_host").await, [ids[1].clone()]);
        assert_eq!(lab.host_names().await.len(), 2);

        let reply = scoped
            .with_json("POST", "/proposals/reject", &[], &json!({ "ids": ids }))
            .await;
        reply.assert_json(200);
        assert_eq!(
            outcomes(&reply)
                .into_iter()
                .map(|(_, outcome, code)| (outcome, code))
                .collect::<Vec<_>>(),
            [
                (
                    "skipped".to_owned(),
                    Some("ipam.proposal.not_open".to_owned())
                ),
                ("skipped".to_owned(), Some("auth.out_of_scope".to_owned())),
                (
                    "skipped".to_owned(),
                    Some("ipam.proposal.not_open".to_owned())
                ),
            ]
        );
    }

    #[tokio::test]
    async fn a_batch_under_an_idempotency_key_decides_every_proposal() {
        let lab = Lab::new().await;
        lab.poll(vec![
            vm("qemu/101", "web01", WEB_MAC, "192.0.2.10"),
            vm("qemu/102", "db01", DB_MAC, "192.0.2.11"),
            vm("qemu/103", "app01", "00-00-5E-00-53-03", "192.0.2.12"),
        ])
        .await;
        lab.reconcile().await;
        let ids = open_ids(&lab, "discovered_host").await;
        let reply = lab
            .with_json(
                "POST",
                "/proposals/approve",
                &[("idempotency-key", "batch-one")],
                &json!({ "ids": ids }),
            )
            .await;
        reply.assert_json(200);
        assert_eq!(reply.body["approved"], 3, "{}", reply.body);
        assert_eq!(lab.host_names().await.len(), 3);
    }

    #[tokio::test]
    async fn a_reader_cannot_decide_a_batch() {
        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        let reader = Policy::new(true, false);
        let lab = lab.checked_by(Arc::clone(&reader) as Arc<dyn Authorizer>);
        for path in ["/proposals/approve", "/proposals/reject"] {
            lab.with_json("POST", path, &[], &json!({ "ids": [id] }))
                .await
                .assert_problem(403, "auth.forbidden");
        }
        lab.assert_no_hosts().await;
        assert_eq!(open_ids(&lab, "discovered_host").await, [id]);
    }

    #[tokio::test]
    async fn a_batch_takes_one_to_five_hundred_proposals() {
        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        for path in ["/proposals/approve", "/proposals/reject"] {
            lab.with_json("POST", path, &[], &json!({ "ids": [] }))
                .await
                .assert_problem(422, "ipam.proposal.batch_empty");
            let many: Vec<String> = (0..501)
                .map(|_| ProposalId::generate().to_string())
                .collect();
            let refused = lab
                .with_json("POST", path, &[], &json!({ "ids": many }))
                .await;
            refused.assert_problem(422, "ipam.proposal.batch_too_large");
            assert_eq!(refused.body["params"]["count"], "501");
            assert_eq!(refused.body["params"]["limit"], "500");

            // The limit itself is fine: every unknown identifier is skipped.
            let limit: Vec<String> = (0..500)
                .map(|_| ProposalId::generate().to_string())
                .collect();
            let reply = lab
                .with_json("POST", path, &[], &json!({ "ids": limit }))
                .await;
            reply.assert_json(200);
            assert_eq!(reply.body["skipped"], 500, "{}", reply.body);
            assert_eq!(
                reply.body["results"].as_array().expect("results").len(),
                500
            );
        }
        // Nothing was decided on the way.
        assert_eq!(
            open_ids(&lab, "discovered_host").await,
            std::slice::from_ref(&id)
        );
        // The body is checked like any other.
        for body in [json!({}), json!({ "ids": "x" }), json!({ "ids": ["nope"] })] {
            lab.with_json("POST", "/proposals/approve", &[], &body)
                .await
                .assert_problem(400, "sys.invalid_request");
        }
        lab.with_json(
            "POST",
            "/proposals/approve",
            &[],
            &json!({ "ids": [id], "reason": "x" }),
        )
        .await
        .assert_problem(400, "sys.invalid_request");
        lab.with_json(
            "POST",
            "/proposals/approve?bogus=1",
            &[],
            &json!({ "ids": [id] }),
        )
        .await
        .assert_problem(400, "sys.invalid_query");
        lab.without_ipam()
            .with_json("POST", "/proposals/approve", &[], &json!({ "ids": [id] }))
            .await
            .assert_problem(503, "ipam.unavailable");
    }

    // ----- the reconciler --------------------------------------------------------------

    #[tokio::test]
    async fn the_reconciler_runs_on_demand_and_reports() {
        let lab = Lab::new().await;
        lab.poll(vec![vm("qemu/101", "web01", WEB_MAC, "192.0.2.10")])
            .await;
        let run = lab.post("/proposals/reconcile", &[]).await;
        run.assert_json(200);
        let body = &run.body;
        assert!(body["at"].is_string(), "{body}");
        assert_eq!(body["opened"], 1, "{body}");
        assert_eq!(body["adopted"], 0, "{body}");
        assert!(body["revision"].as_u64().is_some(), "{body}");
        assert_eq!(lab.reconciler.last_report().expect("report").opened, 1);
        lab.get("/proposals?state=open").await.assert_json(200);

        let again = lab.post("/proposals/reconcile", &[]).await;
        again.assert_json(200);
        assert_eq!(again.body["opened"], 0, "{}", again.body);
        assert_eq!(again.body["unchanged"], 1, "{}", again.body);
        assert_eq!(again.body["revision"], Value::Null, "nothing changed");

        lab.post("/proposals/reconcile?bogus=1", &[])
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn without_a_reconciler_the_run_is_unavailable() {
        let lab = Lab::new().await.without_reconciler();
        let reply = lab.post("/proposals/reconcile", &[]).await;
        reply.assert_problem(503, "ipam.reconciler.unavailable");
        assert_eq!(reply.body["title"], "Service unavailable");
        // The reads and the decisions do not need it.
        lab.get("/proposals").await.assert_json(200);
    }

    #[tokio::test]
    async fn the_static_reconcile_path_answers_only_post() {
        let lab = Lab::new().await;
        assert_eq!(lab.get("/proposals/reconcile").await.status.as_u16(), 405);
        assert_eq!(
            lab.get(&format!("/proposals/{}", ProposalId::generate()))
                .await
                .status
                .as_u16(),
            404
        );
    }

    // ----- adoption policies -----------------------------------------------------------

    /// A supernet 198.51.100.0/24 with the network 198.51.100.0/25 inside it.
    async fn tree(lab: &Lab) -> (PrefixId, PrefixId) {
        let (supernet, child) = (PrefixId::generate(), PrefixId::generate());
        lab.make(vec![
            IpamCommand::CreatePrefix(prefix(
                Some(supernet),
                "198.51.100.0/24",
                Some(PrefixRole::Supernet),
            )),
            IpamCommand::CreatePrefix(prefix(Some(child), "198.51.100.0/25", None)),
        ])
        .await;
        (supernet, child)
    }

    #[tokio::test]
    async fn a_policy_is_inherited_down_the_tree_and_set_and_removed_per_prefix() {
        let lab = Lab::new().await;
        let (supernet, child) = tree(&lab).await;
        let (supernet_path, child_path) = (
            format!("/prefixes/{supernet}/adoption"),
            format!("/prefixes/{child}/adoption"),
        );

        // Nothing set: manual, from nowhere.
        let none = lab.get(&child_path).await;
        none.assert_json(200);
        assert_eq!(none.body["prefix"], child.to_string());
        assert_eq!(none.body["policy"], Value::Null, "{}", none.body);
        assert_eq!(none.body["effective"]["mode"], "manual");
        assert_eq!(none.body["effective"]["min_sightings"], 1);
        assert_eq!(none.body["effective"]["host_mode"], "dynamic");
        assert_eq!(none.body["source"], Value::Null);
        assert_eq!(none.body["revision"], 0);
        assert_eq!(none.etag.as_deref(), Some("\"0\""));

        // A policy on the supernet reaches the network inside it.
        let set = lab
            .with_json(
                "PUT",
                &supernet_path,
                &[("if-match", "\"0\"")],
                &json!({ "mode": "adopt_hosts" }),
            )
            .await;
        set.assert_json(200);
        let revision = set.body["revision"].as_u64().expect("revision");
        assert!(revision > 0, "{}", set.body);
        assert_eq!(
            set.etag.as_deref(),
            Some(format!("\"{revision}\"").as_str())
        );
        assert_eq!(set.body["policy"]["mode"], "adopt_hosts");
        assert_eq!(set.body["policy"]["min_sightings"], 1);
        assert_eq!(set.body["policy"]["only_dhcp_pools"], false);
        assert_eq!(set.body["policy"]["vendors"], json!([]));
        assert_eq!(set.body["source"], supernet.to_string());
        assert!(set.body["updated"].is_object(), "{}", set.body);
        let inherited = lab.get(&child_path).await;
        assert_eq!(inherited.body["policy"], Value::Null, "{}", inherited.body);
        assert_eq!(inherited.body["effective"]["mode"], "adopt_hosts");
        assert_eq!(inherited.body["source"], supernet.to_string());
        assert_eq!(inherited.body["revision"], 0);
        let own = lab.get(&supernet_path).await;
        assert_eq!(own.body, set.body);

        // The network's own policy wins, and removing it restores the inherited one.
        let child_policy = json!({
            "mode": "adopt_all",
            "only_dhcp_pools": true,
            "vendors": ["00-00-5E"],
            "min_sightings": 3,
            "host_mode": "static"
        });
        let own_set = lab.with_json("PUT", &child_path, &[], &child_policy).await;
        own_set.assert_json(200);
        assert_eq!(own_set.body["policy"]["min_sightings"], 3);
        assert_eq!(own_set.body["policy"]["host_mode"], "static");
        assert_eq!(own_set.body["effective"]["mode"], "adopt_all");
        assert_eq!(own_set.body["source"], child.to_string());
        let child_revision = own_set.body["revision"].as_u64().expect("revision");
        let cleared = lab
            .delete(
                &child_path,
                &[("if-match", &format!("\"{child_revision}\""))],
            )
            .await;
        cleared.assert_json(200);
        assert_eq!(cleared.body["policy"], Value::Null, "{}", cleared.body);
        assert_eq!(cleared.body["effective"]["mode"], "adopt_hosts");
        assert_eq!(cleared.body["source"], supernet.to_string());
        assert_eq!(cleared.etag.as_deref(), Some("\"0\""));
        // Removing what is not there changes nothing.
        let again = lab.delete(&child_path, &[]).await;
        again.assert_json(200);
        assert_eq!(again.body, cleared.body);
    }

    #[tokio::test]
    async fn a_policy_is_validated_and_guarded_by_its_revision() {
        let lab = Lab::new().await;
        let (supernet, _) = tree(&lab).await;
        let path = format!("/prefixes/{supernet}/adoption");

        for body in [
            json!({ "mode": "manual", "min_sightings": 0 }),
            json!({ "mode": "manual", "min_sightings": 1001 }),
            json!({ "mode": "adopt_hosts", "vendors": [""] }),
            json!({ "mode": "adopt_hosts", "vendors": ["v".repeat(65)] }),
        ] {
            lab.with_json("PUT", &path, &[], &body)
                .await
                .assert_problem(400, "ipam.adoption.invalid");
        }
        for body in [
            json!({}),
            json!({ "mode": "adopt_everything" }),
            json!({ "mode": "manual", "unknown": true }),
            json!({ "mode": "manual", "min_sightings": -1 }),
        ] {
            lab.with_json("PUT", &path, &[], &body)
                .await
                .assert_problem(400, "sys.invalid_request");
        }
        lab.with_json(
            "PUT",
            &format!("{path}?bogus=1"),
            &[],
            &json!({ "mode": "manual" }),
        )
        .await
        .assert_problem(400, "sys.invalid_query");
        lab.with_json(
            "PUT",
            &path,
            &[("if-match", "x")],
            &json!({ "mode": "manual" }),
        )
        .await
        .assert_problem(400, "ipam.validation");
        assert!(
            lab.get(&path).await.body["policy"].is_null(),
            "nothing was written"
        );

        // The first write expects no policy.
        let body = json!({ "mode": "adopt_hosts" });
        let first = lab
            .with_json("PUT", &path, &[("if-match", "\"0\"")], &body)
            .await;
        first.assert_json(200);
        let revision = first.body["revision"].as_u64().expect("revision");
        // "0" is stale now, as is any other revision.
        for stale in ["\"0\"", &format!("\"{}\"", revision + 1)] {
            lab.with_json("PUT", &path, &[("if-match", stale)], &body)
                .await
                .assert_problem(412, "ipam.revision_mismatch");
            lab.delete(&path, &[("if-match", stale)])
                .await
                .assert_problem(412, "ipam.revision_mismatch");
        }
        let current = format!("\"{revision}\"");
        let changed = lab
            .with_json(
                "PUT",
                &path,
                &[("if-match", &current)],
                &json!({ "mode": "adopt_all" }),
            )
            .await;
        changed.assert_json(200);
        assert!(
            changed.body["revision"].as_u64().expect("revision") > revision,
            "{}",
            changed.body
        );
        // The same policy again is a no-op that keeps the revision.
        let same = lab
            .with_json("PUT", &path, &[], &json!({ "mode": "adopt_all" }))
            .await;
        assert_eq!(same.body["revision"], changed.body["revision"]);
    }

    #[tokio::test]
    async fn a_policy_needs_a_live_prefix() {
        let lab = Lab::new().await;
        let unknown = format!("/prefixes/{}/adoption", PrefixId::generate());
        lab.get(&unknown)
            .await
            .assert_problem(404, "ipam.not_found");
        lab.with_json("PUT", &unknown, &[], &json!({ "mode": "manual" }))
            .await
            .assert_problem(404, "ipam.not_found");
        lab.delete(&unknown, &[])
            .await
            .assert_problem(404, "ipam.not_found");
        lab.get("/prefixes/not-an-id/adoption")
            .await
            .assert_problem(400, "sys.invalid_request");

        lab.make(vec![IpamCommand::Delete {
            object: lab.network.into(),
            expected: None,
            cascade: false,
        }])
        .await;
        let deleted = format!("/prefixes/{}/adoption", lab.network);
        lab.get(&deleted)
            .await
            .assert_problem(409, "ipam.object_deleted");
        lab.with_json("PUT", &deleted, &[], &json!({ "mode": "manual" }))
            .await
            .assert_problem(409, "ipam.object_deleted");
        lab.delete(&deleted, &[])
            .await
            .assert_problem(409, "ipam.object_deleted");
    }

    // ----- authorization and availability ----------------------------------------------

    #[tokio::test]
    async fn a_reader_reads_but_cannot_decide_run_or_set_policies() {
        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        let (supernet, _) = tree(&lab).await;
        let reader = Policy::new(true, false);
        let lab = lab.checked_by(Arc::clone(&reader) as Arc<dyn Authorizer>);

        lab.get("/proposals").await.assert_json(200);
        lab.get(&format!("/proposals/{id}")).await.assert_json(200);
        lab.get(&format!("/prefixes/{supernet}/adoption"))
            .await
            .assert_json(200);
        let before = lab.reconciler.last_report().expect("report");
        let adoption = format!("/prefixes/{supernet}/adoption");
        let refused = [
            lab.post(&format!("/proposals/{id}/approve"), &[]).await,
            lab.post(&format!("/proposals/{id}/approve?dry_run=true"), &[])
                .await,
            lab.with_json("POST", &format!("/proposals/{id}/reject"), &[], &json!({}))
                .await,
            lab.post("/proposals/reconcile", &[]).await,
            lab.with_json("PUT", &adoption, &[], &json!({ "mode": "adopt_all" }))
                .await,
            lab.delete(&adoption, &[]).await,
        ];
        for reply in &refused {
            reply.assert_problem(403, "auth.forbidden");
        }
        let asked = reader.asked();
        assert!(
            asked.contains(&(
                Action::Approve,
                ObjectRef::from(id.parse::<ProposalId>().expect("id"))
            )),
            "{asked:?}"
        );
        assert!(
            asked.contains(&(Action::Approve, new_of(ObjectKind::Proposal))),
            "{asked:?}"
        );
        assert!(
            asked.contains(&(Action::Update, ObjectRef::from(supernet))),
            "{asked:?}"
        );
        assert_eq!(lab.reconciler.last_report().expect("report"), before);
        lab.assert_no_hosts().await;
        let open = lab.get("/proposals?state=open").await;
        assert_eq!(open.ids(), [id], "nothing was decided");
    }

    #[tokio::test]
    async fn an_approval_needs_what_each_of_its_commands_needs() {
        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        let guarded = lab.checked_by(Arc::new(Deny(vec![Action::Create])));
        for path in [
            format!("/proposals/{id}/approve"),
            format!("/proposals/{id}/approve?dry_run=true"),
        ] {
            guarded
                .post(&path, &[])
                .await
                .assert_problem(403, "auth.forbidden");
        }
        lab.assert_no_hosts().await;
        // Rejecting changes no intent and needs no create right.
        guarded
            .with_json("POST", &format!("/proposals/{id}/reject"), &[], &json!({}))
            .await
            .assert_json(200);

        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        let recorder = Policy::new(true, true);
        let allowed = lab.checked_by(Arc::clone(&recorder) as Arc<dyn Authorizer>);
        allowed
            .post(&format!("/proposals/{id}/approve"), &[])
            .await
            .assert_json(200);
        let asked = recorder.asked();
        assert!(
            asked.contains(&(Action::Create, new_of(ObjectKind::Host))),
            "{asked:?}"
        );
        assert!(
            asked.contains(&(Action::Create, new_of(ObjectKind::Address))),
            "{asked:?}"
        );
    }

    #[tokio::test]
    async fn a_principal_that_reads_nothing_sees_an_empty_list_and_no_proposal() {
        let lab = Lab::new().await;
        let id = lab.discover_web().await;
        let blind = lab.checked_by(Policy::new(false, false));
        blind
            .get("/proposals")
            .await
            .assert_json(200)
            .assert_no_items();
        blind
            .get(&format!("/proposals/{id}"))
            .await
            .assert_problem(403, "auth.forbidden");
        blind
            .get(&format!("/prefixes/{}/adoption", lab.network))
            .await
            .assert_problem(403, "auth.forbidden");
    }

    #[tokio::test]
    async fn without_ipam_every_endpoint_but_the_run_is_unavailable() {
        let lab = Lab::new().await.without_ipam();
        let id = ProposalId::generate();
        let prefix = PrefixId::generate();
        let replies = [
            lab.get("/proposals").await,
            lab.get(&format!("/proposals/{id}")).await,
            lab.post(&format!("/proposals/{id}/approve"), &[]).await,
            lab.with_json("POST", &format!("/proposals/{id}/reject"), &[], &json!({}))
                .await,
            lab.get(&format!("/prefixes/{prefix}/adoption")).await,
            lab.with_json(
                "PUT",
                &format!("/prefixes/{prefix}/adoption"),
                &[],
                &json!({ "mode": "manual" }),
            )
            .await,
            lab.delete(&format!("/prefixes/{prefix}/adoption"), &[])
                .await,
        ];
        for reply in &replies {
            reply.assert_problem(503, "ipam.unavailable");
        }
    }

    // ----- the document ----------------------------------------------------------------

    #[test]
    fn the_operations_are_documented() {
        let (_, document) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let operations = [
            (
                "/api/v1/proposals",
                "get",
                "list_proposals",
                &["200", "400", "404", "503"][..],
            ),
            (
                "/api/v1/proposals/{id}",
                "get",
                "get_proposal",
                &["200", "400", "403", "404", "503"][..],
            ),
            (
                "/api/v1/proposals/{id}/approve",
                "post",
                "approve_proposal",
                &["200", "400", "403", "404", "409", "412", "423", "503"][..],
            ),
            (
                "/api/v1/proposals/{id}/reject",
                "post",
                "reject_proposal",
                &["200", "400", "403", "404", "409", "412", "503"][..],
            ),
            (
                "/api/v1/proposals/approve",
                "post",
                "approve_proposals",
                &["200", "400", "403", "422", "503"][..],
            ),
            (
                "/api/v1/proposals/reject",
                "post",
                "reject_proposals",
                &["200", "400", "403", "422", "503"][..],
            ),
            (
                "/api/v1/proposals/reconcile",
                "post",
                "reconcile_proposals",
                &["200", "403", "503"][..],
            ),
            (
                "/api/v1/prefixes/{id}/adoption",
                "get",
                "get_adoption_policy",
                &["200", "403", "404", "409", "503"][..],
            ),
            (
                "/api/v1/prefixes/{id}/adoption",
                "put",
                "set_adoption_policy",
                &["200", "400", "403", "404", "409", "412", "503"][..],
            ),
            (
                "/api/v1/prefixes/{id}/adoption",
                "delete",
                "clear_adoption_policy",
                &["200", "403", "404", "409", "412", "503"][..],
            ),
        ];
        for (path, method, id, statuses) in operations {
            let item = &document.paths.paths[path];
            let operation = match method {
                "get" => item.get.as_ref(),
                "post" => item.post.as_ref(),
                "put" => item.put.as_ref(),
                _ => item.delete.as_ref(),
            }
            .unwrap_or_else(|| panic!("{method} {path}"));
            assert_eq!(operation.operation_id.as_deref(), Some(id), "{path}");
            assert_eq!(
                operation.tags.as_deref(),
                Some(&["proposals".to_owned()][..]),
                "{path}"
            );
            for status in statuses {
                assert!(
                    operation.responses.responses.contains_key(*status),
                    "{method} {path} documents {status}"
                );
            }
        }
        let reject = document.paths.paths["/api/v1/proposals/{id}/reject"]
            .post
            .as_ref()
            .expect("post");
        assert!(reject.request_body.is_some());
        for path in ["/api/v1/proposals/approve", "/api/v1/proposals/reject"] {
            let batch = document.paths.paths[path].post.as_ref().expect("post");
            assert!(batch.request_body.is_some(), "{path}");
        }
    }

    #[test]
    fn the_routes_coexist_with_the_prefix_and_observation_routes() {
        // Merging panics when two areas register the same path and method, for example
        // `/proposals/reconcile` against `/proposals/{id}` or the adoption policy against the
        // prefix routes.
        let (_, document) = OpenApiRouter::<AppState>::new()
            .nest(
                API_BASE,
                routes()
                    .merge(super::super::prefixes::routes())
                    .merge(super::super::common::routes())
                    .merge(super::super::observations::routes()),
            )
            .split_for_parts();
        let mut ids = BTreeSet::new();
        for item in document.paths.paths.values() {
            for operation in [&item.get, &item.post, &item.put, &item.patch, &item.delete]
                .into_iter()
                .flatten()
            {
                let id = operation.operation_id.clone().expect("operation id");
                assert!(ids.insert(id.clone()), "operation id {id} is used twice");
            }
        }
        assert!(ids.contains("get_adoption_policy") && ids.contains("get_prefix"));
    }
}
