//! Settles the local queue once the controller accepts writes again (ADR 0013, S3-Q13).
//!
//! Items are settled oldest first, one at a time; a transient store error (no quorum, a
//! timeout, a shutdown) stops the drain and leaves the item and every later one queued
//! for the next drain. For each item:
//!
//! 1. An expired item becomes an `expired` record.
//! 2. The commands are planned against a linearizable view (the controller has caught
//!    up) as `System { component: Ipam, on_behalf_of: author }` under the idempotency key
//!    `queue-<id>`. A plan that replays an earlier receipt means a previous drain
//!    committed the item and stopped before removing its file: the file goes, nothing is
//!    written again.
//! 3. The plan is checked with the author's current rights ([`ScopeIndex::check_plan`]):
//!    a disabled account, a revoked token, a lost role or scope refuses it.
//! 4. A plan whose [`Fingerprint`] differs from the queued one is a conflict
//!    (`queue.plan_changed`); a planning error is a conflict with that error.
//! 5. An unchanged plan applies as one inline job; its audit drafts carry the context
//!    `queued_change`, `queued_at`, `queued_on` and `original_session`, and the `applied`
//!    record commits in the same batch. A stale plan (the store moved meanwhile) is
//!    planned again.
//!
//! The item's file is removed only after its record committed.

use std::sync::Arc;

use tenko_core::{
    Action, Authorizer, Coded, IdempotencyKey, Principal, RequestCtx, RequestId, SystemComponent,
    Timestamp, UserId,
};
use tenko_store::{ReadConsistency, WriteBatch};
use uuid::Uuid;

use super::{
    ChangeState, Conflict, Fingerprint, LocalQueue, QUEUED_CHANGES, QueueItem, QueuedChange, codes,
};
use crate::{
    ChangeAction, IpamError, IpamPlan, IpamService, codes as ipam_codes, scope::ScopeIndex,
};

/// Plans made for one item before the drain gives up on it for this round.
const MAX_ATTEMPTS: u32 = 8;

/// Store and job codes that say "not now" rather than "not this change".
const TRANSIENT: [&str; 5] = [
    "sys.store.no_quorum",
    "sys.store.timeout",
    "sys.store.shutting_down",
    "sys.store.unavailable",
    "ipam.contended",
];

/// What one drain did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Items applied on their authors' behalf.
    pub applied: Vec<Uuid>,
    /// Items recorded as conflicts.
    pub conflicts: Vec<Uuid>,
    /// Items recorded as expired.
    pub expired: Vec<Uuid>,
    /// Items whose authors cannot be named (a principal without a user): removed with a
    /// warning, never applied.
    pub dropped: Vec<Uuid>,
    /// Whether the drain stopped early on a transient error; the rest stays queued.
    pub interrupted: bool,
}

impl DrainReport {
    /// Whether the drain settled nothing.
    pub fn is_empty(&self) -> bool {
        self.applied.is_empty()
            && self.conflicts.is_empty()
            && self.expired.is_empty()
            && self.dropped.is_empty()
    }
}

/// How one item was settled.
enum Settled {
    Applied,
    Conflict,
    Expired,
    Dropped,
}

/// Drains the local queue of a controller.
pub struct Drainer {
    service: Arc<IpamService>,
    authorizer: Option<Arc<dyn Authorizer>>,
    scope: Option<Arc<ScopeIndex>>,
    queue: Arc<LocalQueue>,
    /// One drain at a time.
    running: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Drainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Drainer")
            .field("queue", &self.queue)
            .finish_non_exhaustive()
    }
}

impl Drainer {
    /// A drainer of `queue` that plans with `service` and checks rights with
    /// `authorizer` (every check passes without one: development and tests) and the
    /// anchors of `scope`.
    pub fn new(
        service: Arc<IpamService>,
        authorizer: Option<Arc<dyn Authorizer>>,
        scope: Option<Arc<ScopeIndex>>,
        queue: Arc<LocalQueue>,
    ) -> Self {
        Self {
            service,
            authorizer,
            scope,
            queue,
            running: tokio::sync::Mutex::new(()),
        }
    }

    /// The queue.
    pub fn queue(&self) -> &Arc<LocalQueue> {
        &self.queue
    }

    /// Settles every item once (see the module documentation). Returns at once while the
    /// store does not accept writes.
    ///
    /// # Errors
    ///
    /// `queue.io` when the queue directory cannot be read.
    pub async fn drain(&self) -> Result<DrainReport, IpamError> {
        let _running = self.running.lock().await;
        let mut report = DrainReport::default();
        if !self.service.store().status().quorum.accepts_writes() {
            report.interrupted = !self.queue.is_empty()?;
            return Ok(report);
        }
        for item in self.queue.list()? {
            let id = item.id;
            match self.settle(item).await {
                Ok(Settled::Applied) => report.applied.push(id),
                Ok(Settled::Conflict) => report.conflicts.push(id),
                Ok(Settled::Expired) => report.expired.push(id),
                Ok(Settled::Dropped) => report.dropped.push(id),
                Err(error) => {
                    tracing::info!(
                        item = %id,
                        code = %error.code(),
                        "the queue drain stops until the store accepts writes: {error}"
                    );
                    report.interrupted = true;
                    break;
                }
            }
        }
        Ok(report)
    }

    /// Settles one item; `Err` only for a transient error (the item stays queued).
    async fn settle(&self, mut item: QueueItem) -> Result<Settled, IpamError> {
        let now = Timestamp::now();
        let Some(author) = item.author() else {
            tracing::warn!(
                item = %item.id,
                principal = %item.principal,
                "a queued change without a user behind it was removed unapplied"
            );
            self.queue.remove(item.id)?;
            return Ok(Settled::Dropped);
        };
        if now >= item.expires_at {
            let record = QueuedChange::of(
                &item,
                author,
                now,
                ChangeState::Expired,
                None,
                Some(expired(&item)),
            );
            self.record(&record, author).await?;
            self.queue.remove(item.id)?;
            return Ok(Settled::Expired);
        }
        item.applying = true;
        self.queue.replace(&item)?;
        match self.apply(&item, author).await {
            Ok(settled) => {
                self.queue.remove(item.id)?;
                Ok(settled)
            }
            Err(error) => {
                item.applying = false;
                let _ = self.queue.replace(&item);
                Err(error)
            }
        }
    }

    /// Plans, checks and applies an item, or records its conflict.
    async fn apply(&self, item: &QueueItem, author: UserId) -> Result<Settled, IpamError> {
        let cx = system_cx(item, author)?;
        for _ in 0..MAX_ATTEMPTS {
            let view = self
                .service
                .store()
                .read(ReadConsistency::Linearizable)
                .await
                .map_err(IpamError::from)?;
            let planned = self
                .service
                .plan(view.as_ref(), &cx, &item.options, &item.commands);
            drop(view);
            let mut plan = match planned {
                Ok(plan) => plan,
                Err(error) if transient(&error) => return Err(error),
                Err(error) => {
                    return self
                        .conflict(item, author, None, Conflict::of(&error))
                        .await;
                }
            };
            if plan.replay.is_some() {
                // A previous drain committed the change and its record.
                return Ok(Settled::Applied);
            }
            if let Err(denied) = self.check_rights(&item.principal, &plan) {
                let view = plan.view();
                return self
                    .conflict(item, author, Some(view), Conflict::of(&denied))
                    .await;
            }
            if Fingerprint::of_plan(&plan) != item.fingerprint {
                let view = plan.view();
                let conflict = Conflict::of(
                    &IpamError::new(
                        codes::PLAN_CHANGED,
                        409,
                        "the state changed while the controller was cut off: the change would \
                         now do something else than what was queued",
                    )
                    .titled("The queued change no longer fits"),
                );
                return self.conflict(item, author, Some(view), conflict).await;
            }
            let record = QueuedChange::of(item, author, cx.now, ChangeState::Applied, None, None);
            annotate(&mut plan, item, &record)?;
            match self.service.apply(&plan, &cx).await {
                Ok(_) => return Ok(Settled::Applied),
                Err(error) if error.is(ipam_codes::PLAN_STALE) => {}
                Err(error) if transient(&error) => return Err(error),
                Err(error) => {
                    let view = plan.view();
                    return self
                        .conflict(item, author, Some(view), Conflict::of(&error))
                        .await;
                }
            }
        }
        Err(IpamError::contended(MAX_ATTEMPTS))
    }

    /// The author's current rights on every change of the plan.
    fn check_rights(
        &self,
        principal: &Principal,
        plan: &IpamPlan,
    ) -> Result<(), tenko_core::Denied> {
        let Some(authorizer) = &self.authorizer else {
            return Ok(());
        };
        if let Some(scope) = &self.scope {
            return scope.check_plan(authorizer.as_ref(), principal, plan);
        }
        for change in &plan.changes {
            let action = match change.action {
                ChangeAction::Create => Action::Create,
                ChangeAction::Delete | ChangeAction::Remove => Action::Delete,
                _ => Action::Update,
            };
            authorizer.check(principal, action, &change.object)?;
        }
        Ok(())
    }

    /// Records a conflict and settles the item.
    async fn conflict(
        &self,
        item: &QueueItem,
        author: UserId,
        current: Option<crate::PlanView>,
        conflict: Conflict,
    ) -> Result<Settled, IpamError> {
        let record = QueuedChange::of(
            item,
            author,
            Timestamp::now(),
            ChangeState::Conflict,
            current,
            Some(conflict),
        );
        self.record(&record, author).await?;
        Ok(Settled::Conflict)
    }

    /// Writes a record on its own.
    async fn record(&self, record: &QueuedChange, author: UserId) -> Result<(), IpamError> {
        let mut batch = WriteBatch::new(on_behalf_of(author), record.settled_at);
        batch.put_typed(&QUEUED_CHANGES, &record.id, record)?;
        self.service.store().propose(batch).await?;
        Ok(())
    }
}

/// The principal of the drain.
fn on_behalf_of(author: UserId) -> Principal {
    Principal::System {
        component: SystemComponent::Ipam,
        on_behalf_of: Some(author),
    }
}

/// The context the drain plans and applies an item in.
fn system_cx(item: &QueueItem, author: UserId) -> Result<RequestCtx, IpamError> {
    let key = IdempotencyKey::new(format!("queue-{}", item.id))
        .map_err(|error| IpamError::new(codes::IO, 500, error.to_string()))?;
    Ok(RequestCtx {
        principal: on_behalf_of(author),
        request: RequestId::generate(),
        now: Timestamp::now(),
        source_ip: None,
        idempotency: Some(key),
    })
}

/// Adds the queue context to every audit draft and the `applied` record to the batch.
fn annotate(plan: &mut IpamPlan, item: &QueueItem, record: &QueuedChange) -> Result<(), IpamError> {
    for draft in &mut plan.audit {
        let context = &mut draft.details.context;
        context.insert("queued_change".to_owned(), item.id.to_string());
        context.insert("queued_at".to_owned(), item.queued_at.to_rfc3339());
        context.insert("queued_on".to_owned(), item.queued_on.to_string());
        if let Some(session) = item.original_session() {
            context.insert("original_session".to_owned(), session.to_string());
        }
    }
    let mut extra = WriteBatch::new(plan.principal.clone(), plan.at);
    extra.put_typed(&QUEUED_CHANGES, &record.id, record)?;
    plan.mutations.extend(extra.mutations);
    Ok(())
}

/// The conflict of an expired item.
fn expired(item: &QueueItem) -> Conflict {
    Conflict::of(
        &IpamError::new(
            codes::EXPIRED,
            410,
            format!(
                "the change waited in the queue since {} and expired at {} before the \
                 controller was back in its cluster",
                item.queued_at.to_rfc3339(),
                item.expires_at.to_rfc3339()
            ),
        )
        .titled("The queued change expired"),
    )
}

fn transient(error: &IpamError) -> bool {
    TRANSIENT.contains(&error.code())
}
