//! Every write of the configuration service is an inline one-step job (decision Q4 of
//! Phase 1, as the IPAM and DNS writes are).
//!
//! A change is the job `dhcp.edit` whose step `dhcp.write` stages the batch, so the change,
//! the job record and the audit record commit in one write. The batch travels to the step
//! in memory ([`with_batch`]): an inline job runs its step on the requesting task, and a job
//! record that copied the batch would double every write. The jobs run through IPAM's
//! [`JobSink`]: the job engine implements it, and [`tenko_ipam::jobs::DirectJobs`] runs the
//! steps in place for tests and tools.
//!
//! The step is not idempotent: a runner that finds it interrupted after a restart has no
//! batch, fails it with `dhcp.job.batch_missing`, and the engine rolls the job back; the
//! caller had its error already and sends the change again.

use std::{cell::RefCell, collections::BTreeMap, future::Future, time::Duration};

use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, JobId, MessageKey, ObjectRef, RequestCtx, Revision,
    codec::{from_cbor, to_cbor},
    serde_util::HexBytes,
};
use tenko_ipam::jobs::JobSink;
use tenko_jobs::{
    Job, JobKind, JobSpec, JobState, StepContext, StepError, StepHandler, StepKind, StepOutcome,
    StepPreview, StepSpec,
};
use tenko_store::{Committed, ReadView, WriteBatch};
use uuid::Uuid;

use super::{ConfigError, ConfigResult};

/// Kind of the inline job of a change.
pub const EDIT_JOB: &str = "dhcp.edit";
/// Kind of its step.
pub const WRITE_STEP: &str = "dhcp.write";
/// Title of the inline job (a UI message key).
pub const EDIT_TITLE: &str = "dhcp.job.edit";
/// Summary key of the write step's preview.
pub const WRITE_PREVIEW: &str = "dhcp.job.write_preview";
/// The code of a step that runs without the batch its request handed over (after a
/// restart).
pub const BATCH_MISSING: &str = "dhcp.job.batch_missing";
/// The code `tenko_jobs::stage` answers outside a step the engine runs.
const OUTSIDE_STEP: &str = "jobs.stage.outside_step";

/// Parameters of `dhcp.write`: what the change does; the batch is handed over in memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteParams {
    /// Matches the step to the batch handed over with [`with_batch`].
    pub nonce: Uuid,
    /// One line on the change, for the job view.
    pub summary: String,
    /// The objects the batch changes.
    pub targets: Vec<ObjectRef>,
    /// Physical writes in the batch.
    pub mutations: u64,
}

tokio::task_local! {
    static PENDING: RefCell<Option<(Uuid, WriteBatch)>>;
}

/// Runs `future` with `batch` available to the `dhcp.write` step of `params`.
pub async fn with_batch<F: Future>(
    params: &WriteParams,
    batch: WriteBatch,
    future: F,
) -> F::Output {
    PENDING
        .scope(RefCell::new(Some((params.nonce, batch))), future)
        .await
}

fn take_batch(nonce: Uuid) -> Option<WriteBatch> {
    PENDING
        .try_with(|slot| {
            let mut slot = slot.borrow_mut();
            match slot.take() {
                Some((pending, batch)) if pending == nonce => Some(batch),
                other => {
                    *slot = other;
                    None
                }
            }
        })
        .ok()
        .flatten()
}

/// The handler of `dhcp.write`.
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteStep;

#[async_trait::async_trait]
impl StepHandler for WriteStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(WRITE_STEP)
    }

    /// Not idempotent: the batch expects the versions it read, so it fails once it
    /// committed, and it exists only while its request runs.
    fn idempotent(&self) -> bool {
        false
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params: WriteParams =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepPreview {
            summary: MessageKey::from_static(WRITE_PREVIEW),
            args: BTreeMap::from([("summary".to_owned(), params.summary)]),
            changes: params.targets,
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params: WriteParams =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        let Some(batch) = take_batch(params.nonce) else {
            return Err(StepError::Coded(Box::new(CodedError::new(
                BATCH_MISSING,
                409,
                "the change of this job is only available while its request runs; send it again",
            ))));
        };
        let output = match tenko_jobs::stage(cx, batch.clone()) {
            Ok(()) => None,
            Err(StepError::Coded(error)) if error.code == OUTSIDE_STEP => {
                let committed = cx.store.propose(batch).await?;
                Some(to_cbor(&committed).map_err(|error| StepError::coded(&error))?)
            }
            Err(error) => return Err(error),
        };
        Ok(StepOutcome::Done { output })
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        Err(StepError::NotCompensable)
    }
}

/// What a committed change reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    /// The revision of the write.
    pub revision: Revision,
    /// The inline job.
    pub job: JobId,
}

/// Commits `batch` as an inline job `dhcp.edit` through `jobs`.
///
/// # Errors
///
/// The step's or the store's error; a precondition failure keeps its store code so that
/// the caller plans again.
pub(crate) async fn commit(
    jobs: &dyn JobSink,
    cx: &RequestCtx,
    summary: String,
    targets: Vec<ObjectRef>,
    batch: WriteBatch,
) -> ConfigResult<Written> {
    let params = WriteParams {
        nonce: Uuid::now_v7(),
        summary,
        targets: targets.clone(),
        mutations: u64::try_from(batch.mutations.len()).unwrap_or(u64::MAX),
    };
    let spec = JobSpec {
        kind: JobKind::from_static(EDIT_JOB),
        title: MessageKey::from_static(EDIT_TITLE),
        targets,
        steps: vec![StepSpec {
            kind: StepKind::from_static(WRITE_STEP),
            params: HexBytes(to_cbor(&params)?.to_vec()),
            timeout: None,
        }],
        timeout: Duration::from_secs(60),
        group: None,
        group_limit: None,
        idempotency: None,
        node: None,
    };
    let job = with_batch(&params, batch, jobs.run_inline(spec, cx)).await?;
    if job.state != JobState::Succeeded {
        return Err(ConfigError::from_coded(job.error.unwrap_or_else(|| {
            CodedError::new("jobs.failed", 500, "the job failed")
        })));
    }
    let revision = committed_revision(&job)
        .ok_or_else(|| ConfigError::new("jobs.failed", 500, "the write step reported no result"))?;
    Ok(Written {
        revision,
        job: job.id,
    })
}

/// The revision of a succeeded job: the engine records it on the job; the in-place runner
/// leaves the [`Committed`] output of the write step.
fn committed_revision(job: &Job) -> Option<Revision> {
    if job.revision > Revision::ZERO {
        return Some(job.revision);
    }
    job.steps
        .iter()
        .rev()
        .filter_map(|step| step.output.as_ref())
        .find_map(|output| from_cbor::<Committed>(&output.0).ok())
        .map(|committed| committed.revision)
}
