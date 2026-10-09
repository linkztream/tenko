//! Store writes of a step, committed atomically with the step's own state.
//!
//! A step handler that changes store data does not propose its own batch. It computes a
//! [`StagedWrite`] (preconditions, mutations and audit drafts, typically from
//! `IpamService::plan`) and hands it to [`stage`] inside
//! [`StepHandler::execute`](crate::StepHandler::execute) or
//! [`compensate`](crate::StepHandler::compensate). The engine commits the staged writes in
//! the same [`WriteBatch`] as the step's transition:
//!
//! - in an inline job ([`JobEngine::run_inline`](crate::JobEngine::run_inline)) the change,
//!   the job record and every audit draft commit as one batch, so a single edit costs one
//!   write (plan decision Q4);
//! - in a background job the change commits together with "step done", so a crash can
//!   never leave a change without its step record or the reverse.
//!
//! If a staged precondition fails, nothing of the step is committed: an idempotent step is
//! executed again (up to `EngineConfig::stage_retries` times), any other step fails and
//! the job rolls back. An inline job returns the store error to the caller, which re-plans
//! and retries.
//!
//! Staging works on the task that runs the handler; a handler that spawns other tasks
//! stages from the handler's own task.

use std::cell::RefCell;

use tenko_core::{CodedError, JobId, audit::AuditDraft};
use tenko_store::{Mutation, Precondition, WriteBatch};

use crate::model::{StepContext, StepError};

/// Preconditions, mutations and audit drafts of a step, without principal or time: the
/// engine adds those when it commits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StagedWrite {
    /// Checked at apply together with the job's own preconditions.
    pub preconditions: Vec<Precondition>,
    /// Applied in order after the job's own mutations.
    pub mutations: Vec<Mutation>,
    /// Sealed into the audit chain with the job's own drafts.
    pub audit: Vec<AuditDraft>,
}

impl StagedWrite {
    /// Whether nothing is staged.
    pub fn is_empty(&self) -> bool {
        self.preconditions.is_empty() && self.mutations.is_empty() && self.audit.is_empty()
    }

    /// Appends another staged write.
    pub fn extend(&mut self, other: StagedWrite) {
        self.preconditions.extend(other.preconditions);
        self.mutations.extend(other.mutations);
        self.audit.extend(other.audit);
    }

    /// Adds the staged parts to a batch.
    pub(crate) fn add_to(self, batch: &mut WriteBatch) {
        batch.preconditions.extend(self.preconditions);
        batch.mutations.extend(self.mutations);
        batch.audit.extend(self.audit);
    }
}

impl From<WriteBatch> for StagedWrite {
    /// Keeps preconditions, mutations and audit drafts; principal, time, request and
    /// idempotency key come from the job when the engine commits.
    fn from(batch: WriteBatch) -> Self {
        Self {
            preconditions: batch.preconditions,
            mutations: batch.mutations,
            audit: batch.audit,
        }
    }
}

struct Staging {
    job: JobId,
    step: u16,
    writes: RefCell<StagedWrite>,
}

tokio::task_local! {
    static STAGING: Staging;
}

/// Stages store writes of the running step; see the [module documentation](self).
///
/// # Errors
///
/// Returns [`StepError::Coded`] with `jobs.stage.outside_step` (500) when called outside
/// a step the engine runs, or for another step than `cx` names, and `jobs.stage.reserved`
/// (500) when the write touches a `jobs.*` table, which only the engine writes.
pub fn stage(cx: &StepContext, write: impl Into<StagedWrite>) -> Result<(), StepError> {
    let write = write.into();
    if let Some(table) = write.mutations.iter().find_map(|mutation| match mutation {
        Mutation::Put { table, .. } | Mutation::Delete { table, .. }
            if table.namespace() == "jobs" =>
        {
            Some(table.clone())
        }
        _ => None,
    }) {
        return Err(StepError::Coded(Box::new(
            CodedError::new(
                "jobs.stage.reserved",
                500,
                format!("a step may not write the engine table {table}"),
            )
            .with_param("table", table.to_string()),
        )));
    }
    STAGING
        .try_with(|staging| {
            if staging.job == cx.job && staging.step == cx.step {
                staging.writes.borrow_mut().extend(write);
                true
            } else {
                false
            }
        })
        .ok()
        .filter(|staged| *staged)
        .map(|_| ())
        .ok_or_else(|| {
            StepError::Coded(Box::new(CodedError::new(
                "jobs.stage.outside_step",
                500,
                "writes can only be staged by the step the engine is running",
            )))
        })
}

/// Runs a handler future with staging enabled and returns its output with the staged
/// writes.
pub(crate) async fn run_staged<F: Future>(
    job: JobId,
    step: u16,
    future: F,
) -> (F::Output, StagedWrite) {
    STAGING
        .scope(
            Staging {
                job,
                step,
                writes: RefCell::new(StagedWrite::default()),
            },
            async move {
                let output = future.await;
                let writes = STAGING.with(|staging| staging.writes.take());
                (output, writes)
            },
        )
        .await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tenko_core::{RequestCtx, SystemComponent, TableName, audit::AuditAction};
    use tenko_store::MemStore;

    use super::*;

    fn cx(job: JobId, step: u16) -> StepContext {
        StepContext {
            job,
            step,
            attempt: 1,
            request: RequestCtx::system(SystemComponent::Jobs),
            store: Arc::new(MemStore::default()),
            deadline: None,
        }
    }

    fn write(table: &'static str) -> StagedWrite {
        let mut batch = WriteBatch::new(
            tenko_core::Principal::system(SystemComponent::Ipam),
            tenko_core::Timestamp::UNIX_EPOCH,
        );
        batch
            .put(TableName::from_static(table), vec![1], vec![2])
            .audit(AuditDraft::success(
                AuditAction::from_static("ipam.host.update"),
                vec![],
            ));
        batch.into()
    }

    #[tokio::test]
    async fn staged_writes_are_collected_per_step() {
        let job = JobId::generate();
        let (result, staged) = run_staged(job, 2, async {
            stage(&cx(job, 2), write("ipam.hosts"))?;
            stage(&cx(job, 2), write("ipam.addresses"))
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(staged.mutations.len(), 2);
        assert_eq!(staged.audit.len(), 2);
    }

    #[tokio::test]
    async fn staging_outside_the_step_is_refused() {
        let job = JobId::generate();
        let error = stage(&cx(job, 0), write("ipam.hosts")).expect_err("no step");
        assert!(matches!(&error, StepError::Coded(e) if e.code == "jobs.stage.outside_step"));
        let (result, staged) =
            run_staged(job, 0, async { stage(&cx(job, 1), write("ipam.hosts")) }).await;
        assert!(result.is_err());
        assert!(staged.is_empty());
    }

    #[tokio::test]
    async fn engine_tables_cannot_be_staged() {
        let job = JobId::generate();
        let (result, staged) =
            run_staged(job, 0, async { stage(&cx(job, 0), write("jobs.jobs")) }).await;
        assert!(matches!(&result, Err(StepError::Coded(e)) if e.code == "jobs.stage.reserved"));
        assert!(staged.is_empty());
    }
}
