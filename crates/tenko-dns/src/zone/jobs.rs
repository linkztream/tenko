//! Every write of the zone service is a job (decision Q4 of Phase 1, ADR 0017).
//!
//! - A change of zones, records or access lists is an inline one-step job `dns.edit`
//!   whose step `dns.write` stages the batch, so the change, the job record and the audit
//!   record commit in one write. The batch travels to the step in memory ([`with_batch`]),
//!   as the IPAM writes do: an inline job runs its step on the requesting task, and a job
//!   record that copied the batch would double every write.
//! - A zone file import is a background job `dns.import` with one step per chunk and a
//!   final step (`super::import`); the job's steps show its progress.
//! - TSIG keys are not written through a job: their batch holds a vault envelope, and the
//!   operator secrets of the vault are proposed directly for the same reason (a job record
//!   would keep a copy of the envelope after the key is deleted).
//!
//! [`ZoneJobs`] is implemented by the job engine and by [`DirectJobs`], which runs the
//! steps in place for tests and tools without an engine.

use std::{cell::RefCell, collections::BTreeMap, future::Future, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, JobId, MessageKey, ObjectRef, RequestCtx, Revision, Timestamp,
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

use super::{ZoneError, ZoneResult};

/// Kind of the inline job of a change.
pub const EDIT_JOB: &str = "dns.edit";
/// Kind of its step.
pub const WRITE_STEP: &str = "dns.write";
/// Title of the inline job (a UI message key).
pub const EDIT_TITLE: &str = "dns.job.edit";
/// Summary key of the write step's preview.
pub const WRITE_PREVIEW: &str = "dns.job.write_preview";
/// The code of a step that runs without the data its request handed over (after a
/// restart).
pub const BATCH_MISSING: &str = "dns.job.batch_missing";
/// The code `tenko_jobs::stage` answers outside a step the engine runs.
const OUTSIDE_STEP: &str = "jobs.stage.outside_step";

/// Parameters of `dns.write`: what the change does; the batch is handed over in memory.
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

/// Runs `future` with `batch` available to the `dns.write` step of `params`.
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

/// Stages `batch` under the job engine, or proposes it outside one ([`DirectJobs`]) and
/// returns the commit.
///
/// # Errors
///
/// The staging or store error.
pub(crate) async fn stage_or_propose(
    cx: &StepContext,
    batch: WriteBatch,
) -> Result<Option<Committed>, StepError> {
    match tenko_jobs::stage(cx, batch.clone()) {
        Ok(()) => Ok(None),
        Err(StepError::Coded(error)) if error.code == OUTSIDE_STEP => {
            Ok(Some(cx.store.propose(batch).await?))
        }
        Err(error) => Err(error),
    }
}

/// Runs jobs of the zone service: inline jobs of changes, background jobs of imports.
#[async_trait::async_trait]
pub trait ZoneJobs: Send + Sync + 'static {
    /// Records and runs a one-step job now and returns it in its final state.
    ///
    /// # Errors
    ///
    /// [`JobError`] when the job cannot run; a failed step may also come back as a job in
    /// a failed state.
    async fn run_inline(&self, spec: JobSpec, cx: &RequestCtx) -> Result<Job, JobError>;

    /// Accepts a background job and returns its id.
    ///
    /// # Errors
    ///
    /// The engine's errors.
    async fn submit(&self, spec: JobSpec, cx: &RequestCtx) -> Result<JobId, JobError>;
}

#[async_trait::async_trait]
impl ZoneJobs for tenko_jobs::JobEngine {
    async fn run_inline(&self, spec: JobSpec, cx: &RequestCtx) -> Result<Job, JobError> {
        tenko_jobs::JobEngine::run_inline(self, spec, cx).await
    }

    async fn submit(&self, spec: JobSpec, cx: &RequestCtx) -> Result<JobId, JobError> {
        tenko_jobs::JobEngine::submit(self, spec, cx).await
    }
}

/// The handler of `dns.write`.
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
        let output = match stage_or_propose(cx, batch).await? {
            Some(committed) => Some(to_cbor(&committed).map_err(|error| StepError::coded(&error))?),
            None => None,
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

/// What a committed inline job reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    /// The revision of the write.
    pub revision: Revision,
    /// The inline job.
    pub job: JobId,
}

/// Commits `batch` as an inline job `dns.edit` through `jobs`.
///
/// # Errors
///
/// The step's or the store's error; a precondition failure keeps its store code so that
/// the caller plans again.
pub(crate) async fn commit(
    jobs: &dyn ZoneJobs,
    cx: &RequestCtx,
    summary: String,
    targets: Vec<ObjectRef>,
    batch: WriteBatch,
) -> ZoneResult<Written> {
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
        return Err(ZoneError::from_coded(job.error.unwrap_or_else(|| {
            CodedError::new("jobs.failed", 500, "the job failed")
        })));
    }
    let revision = committed_revision(&job)
        .ok_or_else(|| ZoneError::new("jobs.failed", 500, "the write step reported no result"))?;
    Ok(Written {
        revision,
        job: job.id,
    })
}

/// The revision of a succeeded job: the engine records it on the job; [`DirectJobs`]
/// leaves the [`Committed`] output of the write step.
pub(crate) fn committed_revision(job: &Job) -> Option<Revision> {
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

/// Runs jobs in place without persisting them: the stand-in for the job engine in tests
/// and tools. A background job runs to its end inside [`ZoneJobs::submit`]; its record is
/// kept in memory for [`DirectJobs::job`].
pub struct DirectJobs {
    store: Arc<dyn Store>,
    handlers: BTreeMap<StepKind, Arc<dyn StepHandler>>,
    finished: std::sync::Mutex<BTreeMap<JobId, Job>>,
}

impl std::fmt::Debug for DirectJobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectJobs")
            .field("handlers", &self.handlers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl DirectJobs {
    /// A runner with the handlers of the zone service registered later
    /// ([`DirectJobs::register`]).
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self {
            store,
            handlers: BTreeMap::new(),
            finished: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Adds a step handler.
    pub fn register(&mut self, handler: Arc<dyn StepHandler>) {
        self.handlers.insert(handler.kind(), handler);
    }

    /// A background job that ran, in its final state.
    pub fn job(&self, id: JobId) -> Option<Job> {
        self.finished
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
            .cloned()
    }

    async fn run(&self, spec: JobSpec, cx: &RequestCtx) -> Result<Job, JobError> {
        let id = JobId::generate();
        let mut job = Job {
            id,
            spec: spec.clone(),
            state: JobState::Running,
            steps: Vec::with_capacity(spec.steps.len()),
            created: Stamp::new(cx.now, cx.principal.clone()),
            started: Some(Timestamp::now()),
            runner: None,
            revision: Revision::ZERO,
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
                Ok(StepOutcome::Done { output }) => job.steps.push(StepRecord {
                    index,
                    kind: step.kind.clone(),
                    state: StepState::Done,
                    attempts: 1,
                    started: Some(started),
                    finished,
                    output: output.map(|bytes| HexBytes(bytes.to_vec())),
                }),
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
                    let coded = tenko_core::Coded::to_coded_error(&error);
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

#[async_trait::async_trait]
impl ZoneJobs for DirectJobs {
    async fn run_inline(&self, spec: JobSpec, cx: &RequestCtx) -> Result<Job, JobError> {
        self.run(spec, cx).await
    }

    async fn submit(&self, spec: JobSpec, cx: &RequestCtx) -> Result<JobId, JobError> {
        let job = self.run(spec, cx).await?;
        let id = job.id;
        self.finished
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, job);
        Ok(id)
    }
}
