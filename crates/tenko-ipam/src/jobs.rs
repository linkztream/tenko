//! Every IPAM change is an inline one-step job (IPAM-17, decision Q4).
//!
//! The service hands a plan to a [`JobSink`] as a [`JobSpec`] of kind `ipam.edit` with one
//! step of kind `ipam.write`. The step's parameters describe the change (summary lines,
//! targets, sizes and a nonce); the write batch itself travels to the step in memory
//! ([`with_batch`]), because an inline job runs its step on the requesting task, and a
//! job record that copied the batch would double the size of every import chunk.
//!
//! - With the job engine ([`tenko_jobs::JobEngine`] implements [`JobSink`]; call
//!   [`register_steps`] once), the step stages the batch through `tenko_jobs::stage`, so the
//!   change, the job record and every audit record commit in one write.
//! - [`DirectJobs`] runs the step in place, proposes the batch itself and reports a job
//!   without persisting it: for tests and tools without an engine.
//!
//! The step is not idempotent: a runner that finds it interrupted after a restart has no
//! batch to apply, fails the step with `ipam.job.batch_missing`, and the engine rolls the
//! job back; the caller had already received an error and plans again.

use std::{cell::RefCell, collections::BTreeMap, future::Future, sync::Arc, time::Duration};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tenko_core::{
    Coded, CodedError, JobId, MessageKey, ObjectRef, RequestCtx, Timestamp,
    codec::{from_cbor, to_cbor},
    ipam::Stamp,
    serde_util::HexBytes,
};
use tenko_jobs::{
    Job, JobError, JobKind, JobSpec, JobState, StepContext, StepError, StepHandler, StepKind,
    StepOutcome, StepPreview, StepRecord, StepSpec, StepState,
};
use tenko_store::{Committed, ReadView, Store, WriteBatch};
use uuid::Uuid;

/// Kind of the inline job of an IPAM change.
pub const EDIT_JOB: &str = "ipam.edit";
/// Kind of its single step.
pub const WRITE_STEP: &str = "ipam.write";
/// Title of the job (a UI message key).
pub const EDIT_TITLE: &str = "ipam.job.edit";
/// Summary key of the step preview.
pub const WRITE_PREVIEW: &str = "ipam.job.write_preview";

/// The job kind `ipam.edit`.
pub fn edit_job_kind() -> JobKind {
    JobKind::from_static(EDIT_JOB)
}

/// The code `tenko_jobs::stage` answers outside a step the engine runs.
const OUTSIDE_STEP: &str = "jobs.stage.outside_step";

/// The step kind `ipam.write`.
pub fn write_step_kind() -> StepKind {
    StepKind::from_static(WRITE_STEP)
}

/// The code of a step that runs without its batch (after a restart).
pub const BATCH_MISSING: &str = "ipam.job.batch_missing";

/// Parameters of the `ipam.write` step: what the change does. The batch itself is handed
/// over in memory ([`with_batch`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteStepParams {
    /// Matches the step to the batch handed over with [`with_batch`].
    pub nonce: Uuid,
    /// The plan's summary lines, for the step preview and the job view.
    #[serde(default)]
    pub summary: Vec<String>,
    /// The objects the batch changes.
    #[serde(default)]
    pub targets: Vec<ObjectRef>,
    /// Physical writes in the batch.
    #[serde(default)]
    pub mutations: u64,
    /// Audit records the batch adds.
    #[serde(default)]
    pub audit: u64,
}

impl WriteStepParams {
    /// Encodes the parameters for a [`StepSpec`].
    ///
    /// # Errors
    ///
    /// Returns a codec error if the parameters do not encode.
    pub fn encode(&self) -> Result<HexBytes, tenko_core::codec::CodecError> {
        Ok(HexBytes(to_cbor(self)?.to_vec()))
    }
}

tokio::task_local! {
    /// The batch of the inline job running on this task, keyed by its nonce.
    static PENDING: RefCell<Option<(Uuid, WriteBatch)>>;
}

/// Runs `future` (the inline job of `params`) with `batch` available to its `ipam.write`
/// step on this task.
pub async fn with_batch<F: Future>(
    params: &WriteStepParams,
    batch: WriteBatch,
    future: F,
) -> F::Output {
    PENDING
        .scope(RefCell::new(Some((params.nonce, batch))), future)
        .await
}

/// Takes the batch handed over for `nonce`, if this task carries it.
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

/// The one-step job of a plan.
///
/// # Errors
///
/// Returns a codec error if the parameters do not encode.
pub fn edit_job(params: &WriteStepParams) -> Result<JobSpec, tenko_core::codec::CodecError> {
    Ok(JobSpec {
        kind: edit_job_kind(),
        title: MessageKey::from_static(EDIT_TITLE),
        targets: params.targets.clone(),
        steps: vec![StepSpec {
            kind: write_step_kind(),
            params: params.encode()?,
            timeout: None,
        }],
        timeout: Duration::from_secs(60),
        group: None,
        // Replays of the request are answered from `ipam.receipts` before a job exists.
        idempotency: None,
    })
}

/// Runs inline one-step jobs (Q4). Implemented for the job engine
/// ([`tenko_jobs::JobEngine`], with [`IpamWriteStep`] registered) and by [`DirectJobs`],
/// the in-place stand-in.
#[async_trait::async_trait]
pub trait JobSink: Send + Sync + 'static {
    /// Records and runs the job now and returns it in its final state.
    ///
    /// # Errors
    ///
    /// Returns [`JobError`] when the job cannot run at all; a step failure may also come
    /// back as a job in a failed state with its error set.
    async fn run_inline(&self, spec: JobSpec, cx: &RequestCtx) -> Result<Job, JobError>;
}

/// The job engine runs the inline job and commits the staged batch together with the job
/// record in one write. Register [`IpamWriteStep`] with the engine first
/// ([`register_steps`]).
#[async_trait::async_trait]
impl JobSink for tenko_jobs::JobEngine {
    async fn run_inline(&self, spec: JobSpec, cx: &RequestCtx) -> Result<Job, JobError> {
        tenko_jobs::JobEngine::run_inline(self, spec, cx).await
    }
}

/// Registers the step handlers of the IPAM domain with the job engine.
pub fn register_steps(engine: &mut tenko_jobs::JobEngine) {
    engine.register(Arc::new(IpamWriteStep));
}

/// The handler of `ipam.write`: stages (under the engine) or proposes the batch handed over
/// with [`with_batch`]; when it proposes, the output is the CBOR of the
/// [`Committed`] result.
#[derive(Debug, Clone, Copy, Default)]
pub struct IpamWriteStep;

#[async_trait::async_trait]
impl StepHandler for IpamWriteStep {
    fn kind(&self) -> StepKind {
        write_step_kind()
    }

    /// Not idempotent: proposing the batch again after it committed fails its
    /// preconditions, so the engine rolls the job back instead of running it twice.
    fn idempotent(&self) -> bool {
        false
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params: WriteStepParams =
            from_cbor(params).map_err(|e| StepError::InvalidParams(e.to_string()))?;
        Ok(StepPreview {
            summary: MessageKey::from_static(WRITE_PREVIEW),
            args: BTreeMap::from([("summary".to_owned(), params.summary.join("; "))]),
            changes: params.targets,
            manual: None,
            warnings: Vec::new(),
        })
    }

    /// Under the job engine, stages the batch so it commits together with the job record
    /// in one write (Q4); elsewhere ([`DirectJobs`]) proposes it and reports the commit.
    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params: WriteStepParams =
            from_cbor(params).map_err(|e| StepError::InvalidParams(e.to_string()))?;
        let Some(batch) = take_batch(params.nonce) else {
            return Err(StepError::Coded(Box::new(CodedError::new(
                BATCH_MISSING,
                409,
                "the change of this job is only available while its request runs; plan it again",
            ))));
        };
        match tenko_jobs::stage(cx, batch.clone()) {
            Ok(()) => Ok(StepOutcome::Done { output: None }),
            Err(StepError::Coded(error)) if error.code == OUTSIDE_STEP => {
                let committed = cx.store.propose(batch).await?;
                let output = to_cbor(&committed).map_err(|e| StepError::coded(&e))?;
                Ok(StepOutcome::Done {
                    output: Some(output),
                })
            }
            Err(error) => Err(error),
        }
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        // Undo is a new change planned from history (restore), not a blind reversal.
        Err(StepError::NotCompensable)
    }
}

/// Runs inline jobs in place without persisting them: the stand-in for the job engine in
/// tests and tools without an engine.
pub struct DirectJobs {
    store: Arc<dyn Store>,
    handlers: BTreeMap<StepKind, Arc<dyn StepHandler>>,
}

impl std::fmt::Debug for DirectJobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectJobs")
            .field("handlers", &self.handlers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl DirectJobs {
    /// A runner with the `ipam.write` handler.
    pub fn new(store: Arc<dyn Store>) -> Self {
        let mut jobs = Self {
            store,
            handlers: BTreeMap::new(),
        };
        jobs.register(Arc::new(IpamWriteStep));
        jobs
    }

    /// Adds a step handler.
    pub fn register(&mut self, handler: Arc<dyn StepHandler>) {
        self.handlers.insert(handler.kind(), handler);
    }
}

#[async_trait::async_trait]
impl JobSink for DirectJobs {
    async fn run_inline(&self, spec: JobSpec, cx: &RequestCtx) -> Result<Job, JobError> {
        let id = JobId::generate();
        let mut job = Job {
            id,
            spec: spec.clone(),
            state: JobState::Running,
            steps: Vec::with_capacity(spec.steps.len()),
            created: Stamp::new(cx.now, cx.principal.clone()),
            started: Some(Timestamp::now()),
            runner: None,
            revision: tenko_core::Revision::ZERO,
            cancel_requested: None,
            error: None,
            finished: None,
        };
        for (index, step) in spec.steps.iter().enumerate() {
            let index = u16::try_from(index).unwrap_or(u16::MAX);
            let handler = self
                .handlers
                .get(&step.kind)
                .ok_or_else(|| JobError::UnknownStepKind(step.kind.clone()))?;
            let started = Timestamp::now();
            let context = StepContext {
                job: id,
                step: index,
                attempt: 1,
                request: cx.clone(),
                store: Arc::clone(&self.store),
                deadline: None,
            };
            let outcome = handler.execute(&step.params.0, &context).await;
            let finished = Some(Timestamp::now());
            match outcome {
                Ok(StepOutcome::Done { output }) => {
                    if let Some(committed) = output
                        .as_ref()
                        .and_then(|bytes| from_cbor::<Committed>(bytes).ok())
                    {
                        job.revision = committed.revision;
                    }
                    job.steps.push(StepRecord {
                        index,
                        kind: step.kind.clone(),
                        state: StepState::Done,
                        attempts: 1,
                        started: Some(started),
                        finished,
                        output: output.map(|bytes: Bytes| HexBytes(bytes.to_vec())),
                    });
                }
                Ok(_) => job.steps.push(StepRecord {
                    index,
                    kind: step.kind.clone(),
                    state: StepState::Skipped,
                    attempts: 1,
                    started: Some(started),
                    finished,
                    output: None,
                }),
                Err(error) => {
                    let coded = error.to_coded_error();
                    job.steps.push(StepRecord {
                        index,
                        kind: step.kind.clone(),
                        state: StepState::Failed {
                            error: coded.clone(),
                        },
                        attempts: 1,
                        started: Some(started),
                        finished,
                        output: None,
                    });
                    job.state = JobState::RolledBack;
                    job.error = Some(coded);
                    job.finished = finished;
                    return Ok(job);
                }
            }
        }
        job.state = JobState::Succeeded;
        job.finished = Some(Timestamp::now());
        Ok(job)
    }
}

/// The revision that committed a succeeded inline job: the engine records it on the job;
/// [`DirectJobs`] also leaves the step's [`Committed`] output.
pub(crate) fn committed_revision(job: &Job) -> Option<tenko_core::Revision> {
    if job.revision > tenko_core::Revision::ZERO {
        return Some(job.revision);
    }
    job.steps
        .iter()
        .find(|step| step.kind == write_step_kind())
        .and_then(|step| step.output.as_ref())
        .and_then(|output| from_cbor::<Committed>(&output.0).ok())
        .map(|committed| committed.revision)
}
