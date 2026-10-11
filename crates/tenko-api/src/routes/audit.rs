//! Audit log and chain verification.
//!
//! Area: audit. Owner: WP1.7. Requirements: IAM-18.
//!
//! Records are identified by their sequence number in the hash chain. `GET /audit/verify`
//! is registered next to `/audit/{seq}`; axum matches the static segment first.
//!
//! Reading the log needs the read permission on the audit log (`AUDIT_OBJECT`: a global
//! role that reads the system, the auditor role, or a token with the `audit:read` scope).
//! A principal whose grants are scoped (IAM-01) lists and reads only the records that name
//! objects inside its scope, and `GET /audit/verify` needs the global permission.
//!
//! `GET /audit` pages by sequence number, which is the table key: the cursor holds the last
//! sequence number examined, so a page costs one range scan however deep it is. A selective filter could make a request
//! read the whole table, so a request examines at most 20,000 records. When that runs out
//! first, the answer holds the matches found so far (possibly none) and a cursor that
//! continues the scan. `GET /audit/verify` walks the whole chain on a blocking thread.

use std::{str::FromStr, sync::Arc};

use axum::{
    Extension, Json,
    extract::{Path, State, rejection::PathRejection},
};
use bytes::Bytes;
use tenko_auth::authz::{AUDIT_OBJECT, is_context_kind, is_scoped_kind};
use tenko_core::{
    Action, AuditSeq, Coded, CodedError, Denied, DenyReason, ObjectKind, ObjectRef, RequestCtx,
    Timestamp,
    audit::{AuditAction, AuditOutcome, AuditRecord, ChainHead, ChainVerifier},
    codec::CodecError,
};
use tenko_ipam::scope::ScopeIndex;
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt, StoreError, Versioned, tables,
};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::common::{ReadScope, read_scope};
use crate::{
    dto::{
        Page, SortOrder,
        audit::{AuditBreak, AuditQuery, AuditVerifyReport},
    },
    extract::Ctx,
    list::{Filters, encode_cursor},
    problem::{ApiError, ProblemDetails, codes},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_audit))
        .routes(routes!(verify_audit))
        .routes(routes!(get_audit_record))
}

/// Query parameters of `GET /audit` besides the paging parameters.
const LIST_PARAMETERS: [&str; 7] = [
    "principal",
    "action",
    "object",
    "outcome",
    "from",
    "to",
    "order",
];

/// The endpoint name that cursors of `GET /audit` are bound to.
const CURSOR_ENDPOINT: &str = "sys.audit";

/// Rows read from the store per call while listing.
const LIST_CHUNK: usize = 512;

/// Rows one listing request examines at most, matching or not.
const EXAMINE_BUDGET: usize = 20_000;

/// Rows read from the store per call while verifying.
const VERIFY_CHUNK: usize = 1_000;

#[utoipa::path(
    get,
    path = "/audit",
    tag = "audit",
    operation_id = "list_audit",
    summary = "List audit records",
    description = "Newest first unless `order=asc`. Filters combine with AND. `principal` is a \
        subject such as `user:<uuid>`, `token:<uuid>` or `system:api`; `action` is exact or, \
        when it ends with a dot, a namespace prefix such as `ipam.prefix.`; `object` is a \
        kind such as `prefix`, or `kind:uuid`. Records are read in sequence order and a \
        request examines at most 20,000 of them: when that runs out first, the page holds \
        the matches found so far, possibly none, and `next_cursor` continues the scan. \
        `next_cursor` is null only when the scan reached the end of the log.",
    params(AuditQuery),
    responses(
        (status = 200, description = "A page of audit records", body = Page<AuditRecord>),
        (status = 400, description = "Malformed filter, limit or cursor", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_audit(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    index: Option<Extension<Arc<ScopeIndex>>>,
    filters: Filters,
) -> Result<Json<Page<AuditRecord>>, ApiError> {
    let visible = Visible::of(&state, &ctx, index)?;
    filters.only(&LIST_PARAMETERS)?;
    let page = filters.page()?;
    let listing = Listing::parse(&filters, page.limit()?)?;
    let scope = filters.scope(CURSOR_ENDPOINT);
    let after = page.cursor::<u64>(scope)?.map(AuditSeq);
    let view = page.read(state.store.as_ref()).await?;
    let revision = view.revision();
    let scanned = blocking(move || {
        scan_page_where(view.as_ref(), &listing, after, Bounds::DEFAULT, &|record| {
            visible.admits(record)
        })
    })
    .await?;
    let next_cursor = scanned.resume.map(|seq| encode_cursor(scope, &seq.get()));
    Ok(Json(Page::new(scanned.items, next_cursor, revision)))
}

#[utoipa::path(
    get,
    path = "/audit/verify",
    tag = "audit",
    operation_id = "verify_audit",
    summary = "Verify the hash chain of the audit log",
    description = "Walks the whole chain from record 1 and reports the first record that does \
        not verify: a gap in the sequence, a record that does not link to its predecessor, or \
        one whose hash no longer matches its content. `checked` counts the records that did \
        verify, `head` is the last of them and `store_head` the newest record of the log. \
        Reads the whole log; on a long log it takes a while.",
    responses(
        (status = 200, description = "The verification report; `intact` is false when the chain is broken", body = AuditVerifyReport),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn verify_audit(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
) -> Result<Json<AuditVerifyReport>, ApiError> {
    state.authorize(&ctx.principal, Action::Read, &AUDIT_OBJECT)?;
    let view = state.store.read(ReadConsistency::Local).await?;
    let report = blocking(move || verify_view(view.as_ref(), VERIFY_CHUNK)).await?;
    Ok(Json(report))
}

#[utoipa::path(
    get,
    path = "/audit/{seq}",
    tag = "audit",
    operation_id = "get_audit_record",
    summary = "Get one audit record",
    params(("seq" = u64, Path, description = "Sequence number of the audit record, from 1")),
    responses(
        (status = 200, description = "The audit record", body = AuditRecord),
        (status = 400, description = "The sequence number is not a positive integer", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No record has this sequence number", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_audit_record(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    index: Option<Extension<Arc<ScopeIndex>>>,
    seq: Result<Path<String>, PathRejection>,
) -> Result<Json<AuditRecord>, ApiError> {
    let visible = Visible::of(&state, &ctx, index)?;
    let Ok(Path(text)) = seq else {
        return Err(invalid_seq());
    };
    let seq = parse_seq(&text)?;
    let view = state.store.read(ReadConsistency::Local).await?;
    match view.get_typed(&tables::AUDIT, &seq)? {
        Some((record, _)) if visible.admits(&record) => Ok(Json(record)),
        Some(_) => Err(Denied {
            action: Action::Read,
            object: AUDIT_OBJECT,
            reason: DenyReason::OutOfScope,
        }
        .into()),
        None => Err(ApiError::new(
            codes::AUDIT_NOT_FOUND,
            404,
            format!("audit record {seq} does not exist"),
        )
        .with_param("seq", seq.to_string())),
    }
}

/// Which audit records a principal reads (IAM-01, IAM-18): every record with the read
/// permission on the audit log ([`AUDIT_OBJECT`]: a global role that reads the system, the
/// auditor role, or a token with the `audit:read` scope); otherwise, for a principal whose
/// grants reach IPAM objects, the records that name at least one object and only objects
/// of scoped kinds inside its scope. Anybody else is refused.
enum Visible {
    All,
    Scoped(Vec<(ObjectKind, ReadScope)>),
}

impl Visible {
    fn of(
        state: &AppState,
        ctx: &RequestCtx,
        index: Option<Extension<Arc<ScopeIndex>>>,
    ) -> Result<Self, ApiError> {
        let Some(authorizer) = state.authorizer.as_deref() else {
            return Ok(Self::All);
        };
        let denied = match authorizer.check(&ctx.principal, Action::Read, &AUDIT_OBJECT) {
            Ok(()) => return Ok(Self::All),
            Err(denied) => denied,
        };
        let index = index.map(|Extension(index)| index);
        let scopes: Vec<(ObjectKind, ReadScope)> = ObjectKind::ALL
            .iter()
            .copied()
            .filter(|kind| is_scoped_kind(*kind) && !is_context_kind(*kind))
            .map(|kind| (kind, read_scope(Some(authorizer), index.clone(), ctx, kind)))
            .filter(|(_, scope)| !scope.is_nothing())
            .collect();
        if scopes.is_empty() || denied.reason != DenyReason::MissingPermission {
            return Err(denied.into());
        }
        Ok(Self::Scoped(scopes))
    }

    fn admits(&self, record: &AuditRecord) -> bool {
        match self {
            Self::All => true,
            Self::Scoped(scopes) => {
                let objects = &record.draft.objects;
                !objects.is_empty()
                    && objects.iter().all(|object| {
                        scopes
                            .iter()
                            .find(|(kind, _)| *kind == object.kind)
                            .is_some_and(|(_, scope)| scope.admits(object))
                    })
            }
        }
    }
}

/// Runs store reads on a blocking thread: a listing decodes up to 20,000 records and a
/// verification reads the whole log.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| {
            ApiError::from_coded_error(CodedError::internal("the audit read was interrupted"))
        })?
        .map_err(ApiError::from)
}

fn invalid_seq() -> ApiError {
    ApiError::invalid_query("seq", "must be a positive integer")
}

/// The sequence number of a path: decimal digits, at least 1, at most `u64::MAX`.
fn parse_seq(text: &str) -> Result<AuditSeq, ApiError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_seq());
    }
    match text.parse::<u64>() {
        Ok(seq) if seq > 0 => Ok(AuditSeq(seq)),
        _ => Err(invalid_seq()),
    }
}

/// The filters of `GET /audit`; a record must match every one that is set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AuditFilter {
    /// The subject of the acting principal.
    principal: Option<String>,
    action: Option<ActionFilter>,
    object: Option<ObjectFilter>,
    outcome: Option<OutcomeFilter>,
    /// Records at or after this time.
    from: Option<Timestamp>,
    /// Records before this time.
    to: Option<Timestamp>,
}

/// `action=`: an exact action, or a namespace prefix when the value ends with a dot.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ActionFilter {
    Exact(String),
    Prefix(String),
}

/// `object=`: any object of a kind, or one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectFilter {
    Kind(ObjectKind),
    Exact(ObjectRef),
}

/// `outcome=`: the kind of outcome; the code of a failure is not part of the filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutcomeFilter {
    Success,
    Denied,
    Failed,
}

impl AuditFilter {
    /// Reads and validates the filters.
    ///
    /// # Errors
    ///
    /// 400 `sys.invalid_query` naming the first malformed parameter.
    fn parse(filters: &Filters) -> Result<Self, ApiError> {
        Ok(Self {
            principal: filters.get("principal")?.map(str::to_owned),
            action: filters
                .get("action")?
                .map(ActionFilter::parse)
                .transpose()?,
            object: filters
                .get("object")?
                .map(ObjectFilter::parse)
                .transpose()?,
            outcome: filters
                .get("outcome")?
                .map(OutcomeFilter::parse)
                .transpose()?,
            from: filters.timestamp("from")?,
            to: filters.timestamp("to")?,
        })
    }

    fn matches(&self, record: &AuditRecord) -> bool {
        let draft = &record.draft;
        self.from.is_none_or(|from| record.at >= from)
            && self.to.is_none_or(|to| record.at < to)
            && self
                .outcome
                .is_none_or(|outcome| outcome.matches(&draft.outcome))
            && self
                .action
                .as_ref()
                .is_none_or(|action| action.matches(draft.action.as_str()))
            && self
                .object
                .is_none_or(|object| object.matches(&draft.objects))
            && self
                .principal
                .as_deref()
                .is_none_or(|subject| record.principal.subject() == subject)
    }
}

impl ActionFilter {
    fn parse(value: &str) -> Result<Self, ApiError> {
        let invalid = |value: &str| {
            ApiError::invalid_query(
                "action",
                format!(
                    "`{value}` is not an action such as `ipam.prefix.create` or a prefix \
                     such as `ipam.`"
                ),
            )
        };
        if value.ends_with('.') {
            // Some action starts with the prefix exactly when the prefix plus one more
            // character is a valid action: this checks the namespace and the characters.
            AuditAction::new(format!("{value}x")).map_err(|_| invalid(value))?;
            Ok(Self::Prefix(value.to_owned()))
        } else {
            AuditAction::from_str(value).map_err(|_| invalid(value))?;
            Ok(Self::Exact(value.to_owned()))
        }
    }

    fn matches(&self, action: &str) -> bool {
        match self {
            Self::Exact(wanted) => action == wanted,
            Self::Prefix(prefix) => action.starts_with(prefix.as_str()),
        }
    }
}

impl ObjectFilter {
    fn parse(value: &str) -> Result<Self, ApiError> {
        let invalid = |reason: String| ApiError::invalid_query("object", reason);
        let kind = |text: &str| {
            text.parse::<ObjectKind>()
                .map_err(|_| invalid(format!("`{text}` is not an object kind")))
        };
        match value.split_once(':') {
            None => kind(value).map(Self::Kind),
            Some((text, id)) => {
                let kind = kind(text)?;
                let id = Uuid::parse_str(id)
                    .map_err(|_| invalid(format!("`{id}` is not a UUID; expected `kind:uuid`")))?;
                Ok(Self::Exact(ObjectRef::new(kind, id)))
            }
        }
    }

    fn matches(self, objects: &[ObjectRef]) -> bool {
        objects.iter().any(|object| match self {
            Self::Kind(kind) => object.kind == kind,
            Self::Exact(wanted) => *object == wanted,
        })
    }
}

impl OutcomeFilter {
    fn parse(value: &str) -> Result<Self, ApiError> {
        match value {
            "success" => Ok(Self::Success),
            "denied" => Ok(Self::Denied),
            "failed" => Ok(Self::Failed),
            _ => Err(ApiError::invalid_query(
                "outcome",
                "expected success, denied or failed",
            )),
        }
    }

    fn matches(self, outcome: &AuditOutcome) -> bool {
        matches!(
            (self, outcome),
            (Self::Success, AuditOutcome::Success)
                | (Self::Denied, AuditOutcome::Denied)
                | (Self::Failed, AuditOutcome::Failed { .. })
        )
    }
}

/// What a listing asks for: the filters, the direction and the page size.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listing {
    filter: AuditFilter,
    order: SortOrder,
    limit: usize,
}

impl Listing {
    /// Reads the filters and `order`; `limit` is already validated.
    fn parse(filters: &Filters, limit: usize) -> Result<Self, ApiError> {
        let order = match filters.get("order")? {
            None | Some("desc") => SortOrder::Desc,
            Some("asc") => SortOrder::Asc,
            Some(_) => return Err(ApiError::invalid_query("order", "expected asc or desc")),
        };
        Ok(Self {
            filter: AuditFilter::parse(filters)?,
            order,
            limit,
        })
    }
}

/// How much one listing reads: rows per store call and rows examined in total.
#[derive(Debug, Clone, Copy)]
struct Bounds {
    chunk: usize,
    budget: usize,
}

impl Bounds {
    const DEFAULT: Self = Self {
        chunk: LIST_CHUNK,
        budget: EXAMINE_BUDGET,
    };
}

/// One page of a listing.
#[derive(Debug)]
struct Scanned {
    items: Vec<AuditRecord>,
    /// The last sequence number examined when the scan can continue; `None` when it
    /// reached the end of the log.
    resume: Option<AuditSeq>,
}

/// Scans the audit table from after (ascending) or before (descending) `after`, in chunks,
/// until `limit` records match, the table ends or the budget is spent.
#[cfg(test)]
fn scan_page(
    view: &dyn ReadView,
    listing: &Listing,
    after: Option<AuditSeq>,
    bounds: Bounds,
) -> Result<Scanned, StoreError> {
    scan_page_where(view, listing, after, bounds, &|_| true)
}

/// [`scan_page`] counting only the records `keep` lets through (a scoped reader's).
fn scan_page_where(
    view: &dyn ReadView,
    listing: &Listing,
    after: Option<AuditSeq>,
    bounds: Bounds,
    keep: &dyn Fn(&AuditRecord) -> bool,
) -> Result<Scanned, StoreError> {
    let descending = listing.order == SortOrder::Desc;
    let mut items = Vec::new();
    let mut examined = 0_usize;
    let mut position = after;
    // The first read takes one row more than the page needs, so that a page that ends
    // exactly at the end of the log knows it.
    let mut chunk = (listing.limit + 1).min(bounds.chunk);
    while examined < bounds.budget {
        let want = chunk.min(bounds.budget - examined);
        let mut range = KeyRange::all();
        if let Some(seq) = position {
            let key = tables::AUDIT.key(&seq);
            range = if descending {
                range.before(key)
            } else {
                range.after(key)
            };
        }
        let rows = view.scan_typed(&tables::AUDIT, range, want, descending)?;
        let count = rows.len();
        for (index, (seq, record, _)) in rows.into_iter().enumerate() {
            examined += 1;
            position = Some(seq);
            if listing.filter.matches(&record) && keep(&record) {
                items.push(record);
                if items.len() == listing.limit {
                    let more = index + 1 < count || count == want;
                    return Ok(Scanned {
                        items,
                        resume: more.then_some(seq),
                    });
                }
            }
        }
        if count < want {
            return Ok(Scanned {
                items,
                resume: None,
            });
        }
        chunk = bounds.chunk;
    }
    Ok(Scanned {
        items,
        resume: position,
    })
}

/// A row of the audit table that the verification cannot turn into a record.
#[derive(Debug)]
enum Unreadable {
    /// The store failed, so nothing can be said about the chain.
    Store(StoreError),
    /// The stored value does not decode: the chain is broken at `seq`.
    Damaged { seq: AuditSeq, error: CodecError },
}

/// The audit table in sequence order, read in chunks.
struct ChainRows<'a> {
    view: &'a dyn ReadView,
    chunk: usize,
    /// The raw key of the last row read.
    after: Option<Bytes>,
    pending: std::vec::IntoIter<(Bytes, Versioned)>,
    exhausted: bool,
}

impl<'a> ChainRows<'a> {
    fn new(view: &'a dyn ReadView, chunk: usize) -> Self {
        Self {
            view,
            chunk,
            after: None,
            pending: Vec::new().into_iter(),
            exhausted: false,
        }
    }

    fn refill(&mut self) -> Result<(), StoreError> {
        let mut range = KeyRange::all();
        if let Some(after) = &self.after {
            range = range.after(after.clone());
        }
        let rows = self
            .view
            .scan(tables::AUDIT.name(), range, self.chunk, false)?;
        self.exhausted = rows.len() < self.chunk;
        self.pending = rows.into_iter();
        Ok(())
    }
}

impl Iterator for ChainRows<'_> {
    type Item = Result<AuditRecord, Unreadable>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((key, versioned)) = self.pending.next() {
                self.after = Some(key.clone());
                let seq = match tables::AUDIT.decode_key(&key) {
                    Ok(seq) => seq,
                    Err(error) => return Some(Err(Unreadable::Store(error.into()))),
                };
                return Some(
                    tables::AUDIT
                        .decode(&versioned.value)
                        .map_err(|error| Unreadable::Damaged { seq, error }),
                );
            }
            if self.exhausted {
                return None;
            }
            if let Err(error) = self.refill() {
                self.exhausted = true;
                return Some(Err(Unreadable::Store(error)));
            }
        }
    }
}

/// What a walk over the chain found.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Walk {
    /// Records that verified.
    checked: u64,
    /// The last record that verified.
    head: ChainHead,
    first_break: Option<AuditBreak>,
}

fn broken(seq: AuditSeq, error: &impl Coded) -> AuditBreak {
    AuditBreak {
        seq,
        code: error.code().to_owned(),
        detail: error.to_string(),
    }
}

/// Verifies records in sequence order from record 1 and stops at the first one that does
/// not verify. A break is a finding, not an error; only a failing store is an error.
fn verify_records(
    records: impl IntoIterator<Item = Result<AuditRecord, Unreadable>>,
) -> Result<Walk, StoreError> {
    let mut verifier = ChainVerifier::new();
    let mut checked = 0_u64;
    let mut first_break = None;
    for row in records {
        match row {
            Ok(record) => {
                if let Err(error) = verifier.push(&record) {
                    first_break = Some(broken(record.seq, &error));
                    break;
                }
                checked += 1;
            }
            Err(Unreadable::Damaged { seq, error }) => {
                first_break = Some(broken(seq, &error));
                break;
            }
            Err(Unreadable::Store(error)) => return Err(error),
        }
    }
    Ok(Walk {
        checked,
        head: verifier.head(),
        first_break,
    })
}

/// The newest sequence number of the audit table at the view.
fn highest_seq(view: &dyn ReadView) -> Result<AuditSeq, StoreError> {
    let rows = view.scan(tables::AUDIT.name(), KeyRange::all(), 1, true)?;
    match rows.first() {
        Some((key, _)) => Ok(tables::AUDIT.decode_key(key)?),
        None => Ok(AuditSeq::NONE),
    }
}

/// The verification report of the whole chain at the view.
fn verify_view(view: &dyn ReadView, chunk: usize) -> Result<AuditVerifyReport, StoreError> {
    let store_head = highest_seq(view)?;
    let walk = verify_records(ChainRows::new(view, chunk))?;
    Ok(AuditVerifyReport {
        intact: walk.first_break.is_none(),
        checked: walk.checked,
        head: walk.head,
        store_head,
        first_break: walk.first_break,
        revision: view.revision(),
    })
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tenko_core::{
        AuthStrength, HostId, PrefixId, Principal, Revision, SessionId, SystemComponent, UserId,
        audit::{AuditDraft, Digest},
    };
    use tenko_store::{MemStore, Store, WriteBatch};

    use super::*;

    const CREATE: AuditAction = AuditAction::from_static("ipam.prefix.create");
    const LOGIN: AuditAction = AuditAction::from_static("auth.login.password");
    const CANCEL: AuditAction = AuditAction::from_static("jobs.cancel");

    /// Minute `minute` after 2026-10-09T12:00:00Z.
    fn at(minute: u64) -> Timestamp {
        let base: Timestamp = "2026-10-09T12:00:00Z".parse().expect("time");
        base.checked_add(Duration::from_secs(60 * minute))
            .expect("in range")
    }

    fn user() -> Principal {
        Principal::User {
            id: UserId::generate(),
            session: SessionId::generate(),
            strength: AuthStrength::Passkey,
        }
    }

    fn sealed(seq: u64, prev: Digest, principal: Principal, draft: AuditDraft) -> AuditRecord {
        AuditRecord::seal(
            AuditSeq(seq),
            Revision(seq),
            at(seq),
            principal,
            None,
            draft,
            prev,
        )
        .expect("seal")
    }

    /// A chain of `len` records created by the IPAM component.
    fn chain(len: u64) -> Vec<AuditRecord> {
        let mut prev = Digest::ZERO;
        (1..=len)
            .map(|seq| {
                let draft = AuditDraft::success(CREATE, vec![PrefixId::generate().into()]);
                let record = sealed(seq, prev, Principal::system(SystemComponent::Ipam), draft);
                prev = record.hash;
                record
            })
            .collect()
    }

    fn rows(records: Vec<AuditRecord>) -> Vec<Result<AuditRecord, Unreadable>> {
        records.into_iter().map(Ok).collect()
    }

    fn filters(pairs: &[(&str, &str)]) -> Filters {
        Filters::from_pairs(pairs.iter().copied())
    }

    fn parsed(pairs: &[(&str, &str)]) -> AuditFilter {
        AuditFilter::parse(&filters(pairs)).expect("filter")
    }

    fn rejected(pairs: &[(&str, &str)]) -> ApiError {
        AuditFilter::parse(&filters(pairs)).expect_err("must be refused")
    }

    fn seqs(records: &[AuditRecord]) -> Vec<u64> {
        records.iter().map(|record| record.seq.get()).collect()
    }

    /// The seqs of `records` that match, in order.
    fn selected(filter: &AuditFilter, records: &[AuditRecord]) -> Vec<u64> {
        records
            .iter()
            .filter(|record| filter.matches(record))
            .map(|record| record.seq.get())
            .collect()
    }

    #[test]
    fn paths_are_positive_decimal_numbers() {
        assert_eq!(parse_seq("7").expect("seq"), AuditSeq(7));
        assert_eq!(
            parse_seq("18446744073709551615").expect("max"),
            AuditSeq(u64::MAX)
        );
        for bad in [
            "",
            "0",
            "00",
            "-1",
            "+1",
            "1.5",
            "abc",
            "1 ",
            "0x10",
            "18446744073709551616",
        ] {
            let error = parse_seq(bad).expect_err(bad);
            assert_eq!(error.coded_error().code, codes::INVALID_QUERY, "{bad}");
            assert_eq!(error.coded_error().status, 400, "{bad}");
            assert_eq!(error.coded_error().params["parameter"], "seq", "{bad}");
        }
    }

    #[test]
    fn filters_match_principal_action_object_outcome_and_time() {
        let alice = user();
        let prefix = PrefixId::generate();
        let host = HostId::generate();
        let mut prev = Digest::ZERO;
        let mut records = Vec::new();
        let cases = [
            (
                Principal::system(SystemComponent::Ipam),
                AuditDraft::success(CREATE, vec![prefix.into()]),
            ),
            (alice.clone(), AuditDraft::denied(CREATE, vec![host.into()])),
            (
                alice.clone(),
                AuditDraft::success(LOGIN, vec![prefix.into(), host.into()]),
            ),
            (
                Principal::system(SystemComponent::Jobs),
                AuditDraft {
                    outcome: AuditOutcome::Failed {
                        code: "jobs.cancelled".into(),
                    },
                    ..AuditDraft::success(CANCEL, vec![])
                },
            ),
        ];
        for (seq, (principal, draft)) in (1..).zip(cases) {
            let record = sealed(seq, prev, principal, draft);
            prev = record.hash;
            records.push(record);
        }

        assert_eq!(selected(&AuditFilter::default(), &records), [1, 2, 3, 4]);
        assert_eq!(
            selected(&parsed(&[("principal", "system:ipam")]), &records),
            [1]
        );
        let subject = alice.subject();
        assert_eq!(
            selected(&parsed(&[("principal", subject.as_str())]), &records),
            [2, 3]
        );
        assert_eq!(
            selected(&parsed(&[("action", "ipam.prefix.create")]), &records),
            [1, 2]
        );
        assert_eq!(selected(&parsed(&[("action", "ipam.")]), &records), [1, 2]);
        assert_eq!(
            selected(&parsed(&[("action", "ipam.prefix.")]), &records),
            [1, 2]
        );
        assert_eq!(
            selected(&parsed(&[("action", "ipam.prefix")]), &records),
            Vec::<u64>::new()
        );
        assert_eq!(selected(&parsed(&[("action", "jobs.")]), &records), [4]);
        assert_eq!(selected(&parsed(&[("object", "prefix")]), &records), [1, 3]);
        assert_eq!(selected(&parsed(&[("object", "host")]), &records), [2, 3]);
        let exact_host = format!("host:{}", host.0);
        let wrong_kind = format!("prefix:{}", host.0);
        assert_eq!(
            selected(&parsed(&[("object", exact_host.as_str())]), &records),
            [2, 3]
        );
        assert_eq!(
            selected(&parsed(&[("object", wrong_kind.as_str())]), &records),
            Vec::<u64>::new()
        );
        assert_eq!(
            selected(&parsed(&[("outcome", "success")]), &records),
            [1, 3]
        );
        assert_eq!(selected(&parsed(&[("outcome", "denied")]), &records), [2]);
        assert_eq!(selected(&parsed(&[("outcome", "failed")]), &records), [4]);
    }

    #[test]
    fn the_time_window_includes_from_and_excludes_to() {
        let records = chain(5);
        let from = at(2).to_rfc3339();
        let to = at(4).to_rfc3339();
        assert_eq!(
            selected(&parsed(&[("from", from.as_str())]), &records),
            [2, 3, 4, 5]
        );
        assert_eq!(
            selected(&parsed(&[("to", to.as_str())]), &records),
            [1, 2, 3]
        );
        assert_eq!(
            selected(
                &parsed(&[("from", from.as_str()), ("to", to.as_str())]),
                &records
            ),
            [2, 3]
        );
        assert_eq!(
            selected(
                &parsed(&[("from", to.as_str()), ("to", from.as_str())]),
                &records
            ),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn filters_combine_with_and() {
        let records = chain(4);
        let from = at(2).to_rfc3339();
        let filter = parsed(&[
            ("action", "ipam."),
            ("outcome", "success"),
            ("principal", "system:ipam"),
            ("from", from.as_str()),
        ]);
        assert_eq!(selected(&filter, &records), [2, 3, 4]);
        let none = parsed(&[("action", "ipam."), ("outcome", "denied")]);
        assert_eq!(selected(&none, &records), Vec::<u64>::new());
    }

    #[test]
    fn malformed_filters_name_the_parameter() {
        let host = HostId::generate().0;
        let cases: [(&str, String); 11] = [
            ("outcome", "ok".to_owned()),
            ("outcome", "Success".to_owned()),
            ("action", "nope.".to_owned()),
            ("action", ".".to_owned()),
            ("action", "ipam".to_owned()),
            ("action", "IPAM.prefix.create".to_owned()),
            ("object", "zone".to_owned()),
            ("object", "prefix:not-a-uuid".to_owned()),
            ("object", format!("zone:{host}")),
            ("from", "yesterday".to_owned()),
            ("to", "2026-10-09".to_owned()),
        ];
        for (name, value) in cases {
            let error = rejected(&[(name, value.as_str())]);
            assert_eq!(
                error.coded_error().code,
                codes::INVALID_QUERY,
                "{name}={value}"
            );
            assert_eq!(error.coded_error().status, 400, "{name}={value}");
            assert_eq!(
                error.coded_error().params["parameter"],
                name,
                "{name}={value}"
            );
        }
        let repeated = rejected(&[("outcome", "success"), ("outcome", "failed")]);
        assert_eq!(repeated.coded_error().params["parameter"], "outcome");
    }

    #[test]
    fn blank_filters_are_ignored_and_order_defaults_to_newest_first() {
        let blank = parsed(&[("principal", " "), ("outcome", "")]);
        assert_eq!(blank, AuditFilter::default());
        let listing = |pairs: &[(&str, &str)]| Listing::parse(&filters(pairs), 10);
        assert_eq!(listing(&[]).expect("default").order, SortOrder::Desc);
        assert_eq!(
            listing(&[("order", "desc")]).expect("desc").order,
            SortOrder::Desc
        );
        assert_eq!(
            listing(&[("order", "asc")]).expect("asc").order,
            SortOrder::Asc
        );
        for bad in ["ASC", "up", "-id"] {
            let error = listing(&[("order", bad)]).expect_err(bad);
            assert_eq!(error.coded_error().params["parameter"], "order", "{bad}");
        }
    }

    #[test]
    fn an_intact_chain_verifies() {
        let records = chain(5);
        let last = records[4].hash;
        let walk = verify_records(rows(records)).expect("walk");
        assert_eq!(walk.checked, 5);
        assert_eq!(walk.head.seq, AuditSeq(5));
        assert_eq!(walk.head.hash, last);
        assert_eq!(walk.first_break, None);
    }

    #[test]
    fn an_empty_chain_is_intact() {
        let walk = verify_records(Vec::new()).expect("walk");
        assert_eq!(walk.checked, 0);
        assert_eq!(walk.head, ChainHead::default());
        assert_eq!(walk.first_break, None);
    }

    #[test]
    fn a_changed_field_is_a_bad_hash() {
        let mut records = chain(4);
        let second = records[1].hash;
        records[2]
            .draft
            .details
            .context
            .insert("note".to_owned(), "edited".to_owned());
        let walk = verify_records(rows(records)).expect("walk");
        let found = walk.first_break.expect("a break");
        assert_eq!(found.seq, AuditSeq(3));
        assert_eq!(found.code, "sys.audit.bad_hash");
        assert!(found.detail.contains('3'), "{}", found.detail);
        assert_eq!(walk.checked, 2);
        assert_eq!(walk.head.seq, AuditSeq(2));
        assert_eq!(walk.head.hash, second);
    }

    #[test]
    fn a_removed_record_is_a_gap() {
        let mut records = chain(4);
        records.remove(1);
        let walk = verify_records(rows(records)).expect("walk");
        let found = walk.first_break.expect("a break");
        assert_eq!(found.seq, AuditSeq(3));
        assert_eq!(found.code, "sys.audit.gap");
        assert_eq!(walk.checked, 1);
        assert_eq!(walk.head.seq, AuditSeq(1));

        let mut records = chain(2);
        records.remove(0);
        let found = verify_records(rows(records))
            .expect("walk")
            .first_break
            .expect("a break");
        assert_eq!(found.seq, AuditSeq(2));
        assert_eq!(found.code, "sys.audit.gap");
    }

    #[test]
    fn a_broken_link_is_reported_at_the_record_that_does_not_link() {
        let mut records = chain(4);
        let third = &records[2];
        records[2] = sealed(
            3,
            Digest([7; 32]),
            third.principal.clone(),
            third.draft.clone(),
        );
        let walk = verify_records(rows(records)).expect("walk");
        let found = walk.first_break.expect("a break");
        assert_eq!(found.seq, AuditSeq(3));
        assert_eq!(found.code, "sys.audit.broken_link");
        assert_eq!(walk.checked, 2);
    }

    #[test]
    fn an_undecodable_row_is_a_break_and_a_failing_store_is_an_error() {
        let mut items = rows(chain(2));
        items.push(Err(Unreadable::Damaged {
            seq: AuditSeq(3),
            error: CodecError::Decode("truncated".to_owned()),
        }));
        items.extend(rows(chain(5)).into_iter().skip(3));
        let walk = verify_records(items).expect("walk");
        let found = walk.first_break.expect("a break");
        assert_eq!(found.seq, AuditSeq(3));
        assert_eq!(found.code, "sys.codec.decode");
        assert!(found.detail.contains("truncated"));
        assert_eq!(walk.checked, 2);

        let mut items = rows(chain(1));
        items.push(Err(Unreadable::Store(StoreError::Storage(
            "disk".to_owned(),
        ))));
        let error = verify_records(items).expect_err("store failure");
        assert_eq!(error, StoreError::Storage("disk".to_owned()));
    }

    /// A store with `count` records. Every fifth record is denied, the others succeed.
    async fn seeded(count: u64) -> Arc<MemStore> {
        let store = Arc::new(MemStore::default());
        for seq in 1..=count {
            let mut batch = WriteBatch::new(user(), at(seq));
            let objects = vec![PrefixId::generate().into()];
            batch.audit(if seq % 5 == 0 {
                AuditDraft::denied(CREATE, objects)
            } else {
                AuditDraft::success(CREATE, objects)
            });
            store.propose(batch).await.expect("propose");
        }
        store
    }

    async fn view(store: &Arc<MemStore>) -> Arc<dyn ReadView> {
        store.read(ReadConsistency::Local).await.expect("view")
    }

    fn listing(outcome: Option<&str>, order: SortOrder, limit: usize) -> Listing {
        let mut pairs = Vec::new();
        if let Some(outcome) = outcome {
            pairs.push(("outcome", outcome));
        }
        Listing {
            order,
            ..Listing::parse(&filters(&pairs), limit).expect("listing")
        }
    }

    /// Follows the resume points until the scan ends; returns the pages.
    fn walk_pages(view: &dyn ReadView, listing: &Listing, bounds: Bounds) -> Vec<Scanned> {
        let mut pages = Vec::new();
        let mut after = None;
        loop {
            let page = scan_page(view, listing, after, bounds).expect("scan");
            after = page.resume;
            let done = after.is_none();
            pages.push(page);
            assert!(pages.len() < 100, "the scan does not end");
            if done {
                return pages;
            }
        }
    }

    #[tokio::test]
    async fn pages_cover_the_log_once_in_both_directions() {
        let store = seeded(25).await;
        let view = view(&store).await;
        for (order, expected) in [
            (SortOrder::Asc, (1..=25).collect::<Vec<u64>>()),
            (SortOrder::Desc, (1..=25).rev().collect()),
        ] {
            for limit in [1, 4, 5, 24, 25, 26] {
                let pages = walk_pages(
                    view.as_ref(),
                    &listing(None, order, limit),
                    Bounds {
                        chunk: 7,
                        budget: 1_000,
                    },
                );
                let all: Vec<u64> = pages.iter().flat_map(|page| seqs(&page.items)).collect();
                assert_eq!(all, expected, "{order:?} limit {limit}");
                assert!(pages.iter().all(|page| page.items.len() <= limit));
                // Only the last page may be short or empty, and it says so.
                let (last, full) = pages.split_last().expect("a page");
                assert!(full.iter().all(|page| page.items.len() == limit));
                assert_eq!(last.resume, None);
                assert!(full.iter().all(|page| page.resume.is_some()));
            }
        }
    }

    #[tokio::test]
    async fn a_page_that_ends_at_the_end_of_the_log_has_no_cursor() {
        let store = seeded(10).await;
        let view = view(&store).await;
        let page = scan_page(
            view.as_ref(),
            &listing(None, SortOrder::Desc, 10),
            None,
            Bounds::DEFAULT,
        )
        .expect("scan");
        assert_eq!(seqs(&page.items), (1..=10).rev().collect::<Vec<u64>>());
        assert_eq!(page.resume, None);

        let page = scan_page(
            view.as_ref(),
            &listing(None, SortOrder::Desc, 9),
            None,
            Bounds::DEFAULT,
        )
        .expect("scan");
        assert_eq!(page.items.len(), 9);
        assert_eq!(page.resume, Some(AuditSeq(2)));
    }

    #[tokio::test]
    async fn a_selective_filter_stops_at_the_budget_and_resumes() {
        let store = seeded(25).await;
        let view = view(&store).await;
        let denied = listing(Some("denied"), SortOrder::Asc, 5);
        let bounds = Bounds {
            chunk: 4,
            budget: 10,
        };

        let first = scan_page(view.as_ref(), &denied, None, bounds).expect("scan");
        // Ten records examined (1 to 10): the matches among them, and a way to go on.
        assert_eq!(seqs(&first.items), [5, 10]);
        assert_eq!(first.resume, Some(AuditSeq(10)));

        let pages = walk_pages(view.as_ref(), &denied, bounds);
        let all: Vec<u64> = pages.iter().flat_map(|page| seqs(&page.items)).collect();
        assert_eq!(all, [5, 10, 15, 20, 25]);
        assert_eq!(pages.len(), 3);

        // A budget spent before any match gives an empty page that still continues.
        let tight = Bounds {
            chunk: 4,
            budget: 3,
        };
        let empty = scan_page(view.as_ref(), &denied, None, tight).expect("scan");
        assert_eq!(seqs(&empty.items), Vec::<u64>::new());
        assert_eq!(empty.resume, Some(AuditSeq(3)));
    }

    #[tokio::test]
    async fn a_filter_that_matches_nothing_ends_at_the_end_of_the_log() {
        let store = seeded(12).await;
        let view = view(&store).await;
        let failed = listing(Some("failed"), SortOrder::Desc, 3);
        let page = scan_page(
            view.as_ref(),
            &failed,
            None,
            Bounds {
                chunk: 5,
                budget: 100,
            },
        )
        .expect("scan");
        assert_eq!(seqs(&page.items), Vec::<u64>::new());
        assert_eq!(page.resume, None);

        let empty = Arc::new(MemStore::default());
        let view = self::view(&empty).await;
        let page = scan_page(view.as_ref(), &failed, None, Bounds::DEFAULT).expect("scan");
        assert_eq!(seqs(&page.items), Vec::<u64>::new());
        assert_eq!(page.resume, None);
    }

    #[tokio::test]
    async fn a_position_outside_the_log_ends_the_scan() {
        let store = seeded(5).await;
        let view = view(&store).await;
        for (order, after) in [
            (SortOrder::Asc, 5),
            (SortOrder::Asc, 99),
            (SortOrder::Desc, 1),
        ] {
            let page = scan_page(
                view.as_ref(),
                &listing(None, order, 3),
                Some(AuditSeq(after)),
                Bounds::DEFAULT,
            )
            .expect("scan");
            assert!(page.items.is_empty(), "{order:?} after {after}");
            assert_eq!(page.resume, None);
        }
    }

    #[tokio::test]
    async fn the_report_walks_the_log_in_chunks() {
        let store = seeded(23).await;
        let view = view(&store).await;
        for chunk in [1, 4, 23, 24, 1_000] {
            let report = verify_view(view.as_ref(), chunk).expect("report");
            assert!(report.intact, "chunk {chunk}");
            assert_eq!(report.checked, 23, "chunk {chunk}");
            assert_eq!(report.head.seq, AuditSeq(23), "chunk {chunk}");
            assert_eq!(report.store_head, AuditSeq(23), "chunk {chunk}");
            assert_eq!(report.first_break, None, "chunk {chunk}");
            assert_eq!(report.revision, view.revision(), "chunk {chunk}");
        }
        let newest = store
            .read(ReadConsistency::Local)
            .await
            .expect("view")
            .get_typed(&tables::AUDIT, &AuditSeq(23))
            .expect("record")
            .expect("present")
            .0;
        let report = verify_view(view.as_ref(), 5).expect("report");
        assert_eq!(report.head.hash, newest.hash);

        let empty = Arc::new(MemStore::default());
        let report = verify_view(self::view(&empty).await.as_ref(), 5).expect("report");
        assert!(report.intact);
        assert_eq!(report.checked, 0);
        assert_eq!(report.store_head, AuditSeq::NONE);
    }
}
