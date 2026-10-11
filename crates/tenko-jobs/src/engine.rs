//! [`JobEngine`]: registration, preview, submission, inline jobs, cancel, manual tasks and
//! observation wake-up (plan section 2.6).
//!
//! The engine is a cheap handle (`Clone` shares it). Requests call it directly; the
//! background work (starting queued jobs, running steps, deadlines, rollback) is done by
//! the runner that [`JobEngine::start`] spawns, one per engine and node.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, PoisonError, RwLock},
    time::Duration,
};

use tenko_core::{
    Coded, CodedError, IdempotencyKey, JobId, NodeId, Principal, RequestCtx, RequestId, Revision,
    SystemComponent, Timestamp, codec::to_cbor, ipam::Stamp, observe::Observation,
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, Store, StoreError};

use crate::{
    clock::{Clock, SystemClock},
    drive::{self, run_compensate, run_execute},
    machine::{Boundary, HandlerInfo, Machine, ResultOp},
    manual::ManualStep,
    model::{
        GroupKey, Job, JobError, JobPreview, JobSpec, JobState, StepError, StepHandler, StepKind,
        StepRecord, StepState,
    },
    persist::{self, Author, Loaded, job_changed},
    query::{self, JobDetail, JobPage, JobQuery},
    runner::{self, Msg, RunnerHandle, Scope, Slots},
    stage::StagedWrite,
    tables::{IDEMPOTENCY, PREVIEWS, Transition, TransitionEvent},
    waiters::{PrefixResolver, Waiter, WaiterIndex},
};

/// Longest note accepted with a completed manual task, in bytes.
pub const MAX_NOTE_BYTES: usize = 4096;

/// Settings of an engine and its runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    /// This node: the runner identity in job records and leases.
    pub node: NodeId,
    /// Jobs the runner drives at once (handler calls in flight).
    pub workers: usize,
    /// Started jobs per [`GroupKey`] at once when the group has no own limit (CONN-09).
    pub default_group_limit: usize,
    /// Per-group limits.
    pub group_limits: BTreeMap<GroupKey, usize>,
    /// How long a runner lease lasts without renewal; other runners take the jobs of an
    /// expired lease over.
    pub lease_ttl: Duration,
    /// How often the runner looks for jobs it did not hear about (other nodes, expired
    /// leases).
    pub scan_interval: Duration,
    /// How much older than its step an observation may be and still count (clock skew
    /// between probes and controllers).
    pub observation_skew: Duration,
    /// How often an idempotent step runs again when its staged writes conflict.
    pub stage_retries: u32,
    /// How often a write is retried on transient store errors before the runner backs off.
    pub write_retries: u32,
    /// Wait before the runner looks at a job again after transient store errors.
    pub retry_backoff: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            node: NodeId(1),
            workers: 16,
            default_group_limit: 10,
            group_limits: BTreeMap::new(),
            lease_ttl: Duration::from_secs(30),
            scan_interval: Duration::from_secs(15),
            observation_skew: Duration::from_secs(5),
            stage_retries: 3,
            write_retries: 5,
            retry_backoff: Duration::from_secs(5),
        }
    }
}

impl EngineConfig {
    /// The parallelism limit of a group: the configured limit, else the limit the queued
    /// job carries (`JobSpec::group_limit`), else the default; never below 1.
    pub fn limit_for(&self, group: &GroupKey, job_limit: Option<usize>) -> usize {
        self.group_limits
            .get(group)
            .copied()
            .or(job_limit)
            .unwrap_or(self.default_group_limit)
            .max(1)
    }

    /// The configured parallelism limit of a group, ignoring limits carried by jobs.
    pub fn group_limit(&self, group: &GroupKey) -> usize {
        self.limit_for(group, None)
    }
}

/// Shared state of an engine and its runner.
pub(crate) struct Inner {
    pub store: Arc<dyn Store>,
    pub clock: Arc<dyn Clock>,
    pub config: EngineConfig,
    handlers: RwLock<HashMap<StepKind, Arc<dyn StepHandler>>>,
    pub waiters: Mutex<WaiterIndex>,
    prefixes: RwLock<Option<Arc<dyn PrefixResolver>>>,
    pub runners: Mutex<Slots>,
}

impl Inner {
    pub fn handler(&self, kind: &StepKind) -> Option<Arc<dyn StepHandler>> {
        self.handlers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(kind)
            .cloned()
    }

    pub fn handler_info(&self, kind: &StepKind) -> Option<HandlerInfo> {
        self.handler(kind).map(|handler| HandlerInfo {
            idempotent: handler.idempotent(),
        })
    }

    pub fn waiters(&self) -> std::sync::MutexGuard<'_, WaiterIndex> {
        self.waiters.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Tells the local runners that a job changed.
    pub fn wake(&self, job: JobId, revision: Option<Revision>) {
        for runner in self
            .runners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .senders()
        {
            let _ = runner.send(Msg::Wake { job, revision });
        }
    }

    /// Keeps the waiter index in step with a job: registers its waiting step, or removes it.
    pub fn track_waiter(&self, job: &Job) {
        let waiting = (job.state == JobState::Waiting)
            .then(|| {
                job.steps.iter().find_map(|record| match &record.state {
                    StepState::WaitingForObservation { condition, .. } => Some(Waiter {
                        step: record.index,
                        condition: condition.clone(),
                        since: record.started.unwrap_or(Timestamp::UNIX_EPOCH),
                    }),
                    _ => None,
                })
            })
            .flatten();
        let mut waiters = self.waiters();
        match waiting {
            Some(waiter) => waiters.insert(job.id, waiter),
            None => waiters.remove(job.id),
        }
    }

    /// The principal the runner acts as for a job: the job engine on behalf of the user
    /// who submitted it.
    pub fn runner_principal(job: &Job) -> Principal {
        Principal::System {
            component: SystemComponent::Jobs,
            on_behalf_of: job.created.by.user(),
        }
    }

    /// The request context steps of a background job run with.
    pub fn runner_ctx(&self, job: &Job) -> RequestCtx {
        RequestCtx {
            principal: Self::runner_principal(job),
            request: RequestId::generate(),
            now: self.clock.now(),
            source_ip: None,
            idempotency: None,
        }
    }

    pub async fn view(&self, at_least: Option<Revision>) -> Result<Arc<dyn ReadView>, StoreError> {
        let consistency = at_least.map_or(ReadConsistency::Local, ReadConsistency::AtLeast);
        self.store.read(consistency).await
    }
}

/// Runs jobs: one handler per [`StepKind`], persisted state in `jobs.*` tables, a runner
/// per node. See the [crate documentation](crate) for the full picture.
#[derive(Clone)]
pub struct JobEngine {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for JobEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobEngine")
            .field("node", &self.inner.config.node)
            .finish_non_exhaustive()
    }
}

/// Which error code a refused input gets.
fn invalid(code: &'static str, status: u16, detail: impl Into<String>) -> JobError {
    JobError::Step(StepError::Coded(Box::new(CodedError::new(
        code, status, detail,
    ))))
}

/// What an inline job returns: the job, or the error it failed or rolled back with. A
/// replayed request gets the same answer as the first one.
fn inline_outcome(job: Job) -> Result<Job, JobError> {
    match job.state {
        JobState::RolledBack | JobState::Failed | JobState::RollingBack | JobState::Cancelled => {
            let error = job
                .error
                .unwrap_or_else(|| CodedError::internal("the inline job failed"));
            Err(JobError::Step(StepError::Coded(Box::new(error))))
        }
        _ => Ok(job),
    }
}

/// The idempotency index key of a submission: the spec's key, else the request's.
fn idempotency_key(spec: &JobSpec, cx: &RequestCtx) -> Option<(String, String)> {
    spec.idempotency
        .as_ref()
        .or(cx.idempotency.as_ref())
        .map(|key: &IdempotencyKey| (cx.principal.subject(), key.as_str().to_owned()))
}

impl JobEngine {
    /// An engine on the system clock. The built-in [`ManualStep`] is registered.
    pub fn new(store: Arc<dyn Store>, config: EngineConfig) -> Self {
        Self::with_clock(store, config, Arc::new(SystemClock))
    }

    /// An engine on the given clock (tests use [`MockClock`](crate::MockClock)).
    pub fn with_clock(store: Arc<dyn Store>, config: EngineConfig, clock: Arc<dyn Clock>) -> Self {
        let mut engine = Self {
            inner: Arc::new(Inner {
                store,
                clock,
                config,
                handlers: RwLock::new(HashMap::new()),
                waiters: Mutex::new(WaiterIndex::default()),
                prefixes: RwLock::new(None),
                runners: Mutex::new(Slots::default()),
            }),
        };
        engine.register(Arc::new(ManualStep));
        engine
    }

    /// Registers the handler of its [`StepKind`], replacing an earlier one of the same kind.
    /// Handlers can be registered at any time; a job whose step kind has no handler fails
    /// that step.
    pub fn register(&mut self, handler: Arc<dyn StepHandler>) {
        self.inner
            .handlers
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(handler.kind(), handler);
    }

    /// Sets how prefixes resolve for [`ObservedPredicate::LeaseInPrefix`](crate::ObservedPredicate).
    pub fn set_prefix_resolver(&self, resolver: Arc<dyn PrefixResolver>) {
        *self
            .inner
            .prefixes
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(resolver);
    }

    /// The engine settings.
    pub fn config(&self) -> &EngineConfig {
        &self.inner.config
    }

    /// The store the engine writes to.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.inner.store
    }

    /// The revision this node's store has applied, for answers that carry no job (an
    /// empty list still tells a client where to resume its event stream).
    pub fn revision(&self) -> Revision {
        self.inner.store.status().revision
    }

    /// The clock the engine reads.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.inner.clock
    }

    /// Starts a runner of every job this node may run (unpinned ones and those pinned to
    /// this node) on the current tokio runtime: it resumes the jobs this node owns, takes
    /// over jobs of expired leases, starts queued jobs and drives waiting ones to their
    /// deadlines. For tests, tools and a node that runs no leader supervisor; a controller
    /// runs [`start_leader`](Self::start_leader) while it leads and
    /// [`start_pinned`](Self::start_pinned) always.
    ///
    /// # Errors
    ///
    /// Returns [`runner::AlreadyRunning`] if this engine already runs a runner.
    pub fn start(&self) -> Result<RunnerHandle, runner::AlreadyRunning> {
        runner::start(&self.inner, Scope::All)
    }

    /// Starts the runner of the leader for the term of office with the leader epoch
    /// `epoch` (plan section 2.3): every job without a pinned node, every write fenced
    /// with `epoch`, jobs of other runners taken over at once, leadership confirmed before
    /// each step that is not idempotent. The runner ends with
    /// [`RunnerExit::Deposed`](runner::RunnerExit::Deposed) when a fenced write fails.
    ///
    /// # Errors
    ///
    /// Returns [`runner::AlreadyRunning`] while another leader runner or a runner of every
    /// job ([`start`](Self::start)) runs on this engine.
    pub fn start_leader(&self, epoch: u64) -> Result<RunnerHandle, runner::AlreadyRunning> {
        runner::start(&self.inner, Scope::Leader { epoch })
    }

    /// Starts the runner of the jobs pinned to this node (`JobSpec::node`), such as the
    /// install of a release this controller downloaded. Every controller runs it, whether
    /// it leads or not; it also keeps the engine's index of waiting steps in step with the
    /// store, so an observation ingested here reaches every waiting job.
    ///
    /// # Errors
    ///
    /// Returns [`runner::AlreadyRunning`] while another pinned runner or a runner of every
    /// job ([`start`](Self::start)) runs on this engine.
    pub fn start_pinned(&self) -> Result<RunnerHandle, runner::AlreadyRunning> {
        runner::start(&self.inner, Scope::Pinned)
    }

    fn validate(&self, spec: &JobSpec) -> Result<(), JobError> {
        if spec.timeout.is_zero() {
            return Err(invalid(
                "jobs.spec.invalid",
                400,
                "the job timeout must be positive",
            ));
        }
        if spec.steps.len() > usize::from(u16::MAX) {
            return Err(invalid(
                "jobs.spec.invalid",
                400,
                "a job has at most 65,535 steps",
            ));
        }
        if spec
            .steps
            .iter()
            .any(|step| step.timeout.is_some_and(|t| t.is_zero()))
        {
            return Err(invalid(
                "jobs.spec.invalid",
                400,
                "a step timeout must be positive",
            ));
        }
        for step in &spec.steps {
            if self.inner.handler(&step.kind).is_none() {
                return Err(JobError::UnknownStepKind(step.kind.clone()));
            }
        }
        Ok(())
    }

    async fn preview_in(
        &self,
        spec: &JobSpec,
        view: &dyn ReadView,
    ) -> Result<JobPreview, JobError> {
        let mut steps = Vec::with_capacity(spec.steps.len());
        for step in &spec.steps {
            let handler = self
                .inner
                .handler(&step.kind)
                .ok_or_else(|| JobError::UnknownStepKind(step.kind.clone()))?;
            steps.push(
                handler
                    .preview(&step.params.0, view)
                    .await
                    .map_err(JobError::Step)?,
            );
        }
        let warnings = steps
            .iter()
            .flat_map(|step: &crate::StepPreview| step.warnings.iter().cloned())
            .collect();
        Ok(JobPreview { steps, warnings })
    }

    /// What the job would do, step by step, without side effects (API-09). Job-level
    /// warnings collect the step warnings so a list of previews (one job per target) can
    /// show them without opening each step.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::UnknownStepKind`], [`JobError::Step`] when a step's parameters
    /// are invalid, or a store error.
    pub async fn preview(&self, spec: &JobSpec, _cx: &RequestCtx) -> Result<JobPreview, JobError> {
        self.validate(spec)?;
        let view = self.inner.view(None).await?;
        self.preview_in(spec, view.as_ref()).await
    }

    fn new_job(&self, id: JobId, spec: JobSpec, cx: &RequestCtx) -> Job {
        let steps = spec
            .steps
            .iter()
            .enumerate()
            .map(|(index, step)| StepRecord {
                index: u16::try_from(index).unwrap_or(u16::MAX),
                kind: step.kind.clone(),
                state: StepState::Pending,
                attempts: 0,
                started: None,
                finished: None,
                output: None,
            })
            .collect();
        Job {
            id,
            spec,
            state: JobState::Queued,
            steps,
            created: Stamp::new(self.inner.clock.now(), cx.principal.clone()),
            started: None,
            runner: None,
            revision: Revision::ZERO,
            cancel_requested: None,
            error: None,
            finished: None,
        }
    }

    fn submitted_row(&self, cx: &RequestCtx) -> Transition {
        Transition {
            seq: 0,
            at: self.inner.clock.now(),
            by: cx.principal.clone(),
            request: Some(cx.request),
            event: TransitionEvent::Submitted,
            action: None,
            from: None,
            state: JobState::Queued,
            step: None,
            step_state: None,
            runner: None,
            note: None,
        }
    }

    fn author(&self, cx: &RequestCtx) -> Author {
        Author {
            principal: cx.principal.clone(),
            now: self.inner.clock.now(),
            request: Some(cx.request),
            source_ip: cx.source_ip,
        }
    }

    /// The job an earlier submission with the same idempotency key created.
    fn replayed(
        view: &dyn ReadView,
        key: Option<&(String, String)>,
    ) -> Result<Option<JobId>, StoreError> {
        match key {
            Some(key) => Ok(view.get_typed(&IDEMPOTENCY, key)?.map(|(id, _)| id)),
            None => Ok(None),
        }
    }

    /// Accepts a job for the runner. The preview is computed and stored with the job, so
    /// `GET /jobs/{id}` shows what the job meant to do. A repeated idempotency key (the
    /// spec's, else the request's, per principal) returns the first job (API-04).
    ///
    /// # Errors
    ///
    /// Returns the errors of [`preview`](Self::preview), or a store error.
    pub async fn submit(&self, spec: JobSpec, cx: &RequestCtx) -> Result<JobId, JobError> {
        self.validate(&spec)?;
        let key = idempotency_key(&spec, cx);
        let view = self.inner.view(None).await?;
        if let Some(id) = Self::replayed(view.as_ref(), key.as_ref())? {
            return Ok(id);
        }
        let preview = self.preview_in(&spec, view.as_ref()).await?;
        let job = self.new_job(JobId::generate(), spec, cx);
        let mut batch = persist::batch(
            None,
            &job,
            vec![self.submitted_row(cx)],
            StagedWrite::default(),
            &self.author(cx),
        )?;
        batch.put_typed(&PREVIEWS, &job.id, &preview)?;
        if let Some(key) = &key {
            batch.expect_typed(&IDEMPOTENCY, key, None);
            batch.put_typed(&IDEMPOTENCY, key, &job.id)?;
        }
        match self.inner.store.propose(batch).await {
            Ok(committed) => {
                self.inner.wake(job.id, Some(committed.revision));
                Ok(job.id)
            }
            Err(error @ StoreError::PreconditionFailed(_)) => {
                let view = self.inner.view(None).await?;
                Self::replayed(view.as_ref(), key.as_ref())?.ok_or(JobError::Store(error))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Runs a one-step job inside the caller's request (plan decision Q4: every single edit
    /// is an inline one-step job).
    ///
    /// The step's `execute` runs on the caller's task with the caller's context. When it
    /// finishes, the job record, its transitions, the job's audit draft and the step's
    /// [staged writes](mod@crate::stage) commit in **one** write batch, so the change and its
    /// job cost one revision. When the step asks for a person or an observation, the same
    /// batch commits the job as `waiting` and the runner takes over. When the step fails,
    /// the job is recorded as rolled back (audited, with the error) and the error returned;
    /// when the staged writes conflict, nothing is recorded and the store error is returned
    /// so that the caller re-plans and retries.
    ///
    /// # Errors
    ///
    /// Returns `jobs.spec.inline_one_step` (400) for a spec without exactly one step, the
    /// step's error as [`JobError::Step`], or [`JobError::Store`].
    pub async fn run_inline(&self, spec: JobSpec, cx: &RequestCtx) -> Result<Job, JobError> {
        self.validate(&spec)?;
        if spec.steps.len() != 1 {
            return Err(invalid(
                "jobs.spec.inline_one_step",
                400,
                "an inline job has exactly one step",
            ));
        }
        let key = idempotency_key(&spec, cx);
        let view = self.inner.view(None).await?;
        if let Some(id) = Self::replayed(view.as_ref(), key.as_ref())? {
            return inline_outcome(self.job(id).await?);
        }
        drop(view);

        let mut job = self.new_job(JobId::generate(), spec, cx);
        let mut rows = vec![self.submitted_row(cx)];
        let mut staged = StagedWrite::default();
        let mut results: Vec<ResultOp> = Vec::new();
        let handlers = |kind: &StepKind| self.inner.handler_info(kind);
        let no_tasks = BTreeMap::new();
        loop {
            let mut machine = Machine::new(
                job,
                self.inner.clock.now(),
                None,
                cx.principal.clone(),
                Some(cx.request),
                &handlers,
                &no_tasks,
            );
            for op in results.drain(..) {
                machine.apply(&op);
            }
            let boundary = machine.advance();
            let deadline = match boundary {
                Boundary::Execute { step } => machine.execute_deadline(step),
                _ => None,
            };
            rows.append(&mut machine.rows);
            job = machine.job;
            match boundary {
                Boundary::Execute { step } => {
                    let (op, writes) =
                        run_execute(&self.inner, &job, step, deadline, cx.clone()).await;
                    results.push(op);
                    staged.extend(writes);
                }
                Boundary::Compensate { step } => {
                    let (op, writes) = run_compensate(&self.inner, &job, step, cx.clone()).await;
                    results.push(op);
                    staged.extend(writes);
                }
                Boundary::Park { .. } | Boundary::Terminal => break,
            }
        }

        let mut batch = persist::batch(None, &job, rows, staged, &self.author(cx))?;
        if let Some(key) = &key {
            batch.expect_typed(&IDEMPOTENCY, key, None);
            batch.put_typed(&IDEMPOTENCY, key, &job.id)?;
        }
        match self.inner.store.propose(batch).await {
            Ok(committed) => {
                job.revision = committed.revision;
                if !job.state.is_terminal() {
                    self.inner.track_waiter(&job);
                    self.inner.wake(job.id, Some(committed.revision));
                }
                inline_outcome(job)
            }
            Err(error @ StoreError::PreconditionFailed(_)) => {
                let view = self.inner.view(None).await?;
                match Self::replayed(view.as_ref(), key.as_ref())? {
                    Some(id) => inline_outcome(self.job(id).await?),
                    None => Err(JobError::Store(error)),
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Applies a change made from outside the runner (a person or an observation) to the
    /// freshest job, retrying when the job changed underneath. `change` returns whether it
    /// changed anything.
    async fn change_job(
        &self,
        id: JobId,
        author: &Author,
        change: impl Fn(&mut Machine<'_>) -> Result<bool, JobError>,
    ) -> Result<Job, JobError> {
        let handlers = |kind: &StepKind| self.inner.handler_info(kind);
        let no_tasks = BTreeMap::new();
        for _ in 0..=self.inner.config.write_retries {
            let view = self.inner.view(None).await?;
            let loaded: Loaded = persist::load(view.as_ref(), id)?.ok_or(JobError::NotFound(id))?;
            drop(view);
            let mut machine = Machine::new(
                loaded.job.clone(),
                author.now,
                loaded.job.runner,
                author.principal.clone(),
                author.request,
                &handlers,
                &no_tasks,
            );
            if !change(&mut machine)? || machine.rows.is_empty() {
                return Ok(loaded.job);
            }
            let rows = std::mem::take(&mut machine.rows);
            let mut job = machine.job;
            let batch = persist::batch(Some(&loaded), &job, rows, StagedWrite::default(), author)?;
            match self.inner.store.propose(batch).await {
                Ok(committed) => {
                    job.revision = committed.revision;
                    self.inner.track_waiter(&job);
                    self.inner.wake(id, None);
                    return Ok(job);
                }
                Err(error) if job_changed(&error, id) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(JobError::Store(StoreError::Timeout))
    }

    /// Cancels a job. A queued job is cancelled at once. A running or waiting job is
    /// marked: the runner aborts the current step at its next boundary, rolls the job back
    /// and ends it in `cancelled`. Cancelling twice is harmless.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::NotFound`], [`JobError::InvalidTransition`] for a job that is
    /// rolling back or final, or a store error.
    pub async fn cancel(&self, id: JobId, cx: &RequestCtx) -> Result<(), JobError> {
        let stamp = Stamp::new(self.inner.clock.now(), cx.principal.clone());
        self.change_job(id, &self.author(cx), |machine| match machine.job.state {
            JobState::Queued => {
                machine.job.cancel_requested = Some(stamp.clone());
                machine.job.error = Some(crate::machine::cancelled());
                machine.job_action(crate::JobAction::Cancel)?;
                Ok(true)
            }
            JobState::Running | JobState::Waiting => {
                if machine.job.cancel_requested.is_some() {
                    return Ok(false);
                }
                machine.request_cancel(stamp.clone());
                Ok(true)
            }
            from => Err(JobError::InvalidTransition {
                from,
                action: crate::JobAction::Cancel.as_str(),
            }),
        })
        .await
        .map(|_| ())
    }

    /// Marks a manual task done: a step waiting for a person continues the job, and a
    /// manual undo task of a rolling-back job counts as compensated. The note is kept in
    /// the transition log and the audit record.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::NotFound`], `jobs.step.not_found` (404) for an index outside the
    /// job, `jobs.note.too_long` (400), [`JobError::InvalidTransition`] when the step is
    /// not waiting for a person, or a store error.
    pub async fn complete_manual(
        &self,
        id: JobId,
        step: u16,
        note: Option<String>,
        cx: &RequestCtx,
    ) -> Result<(), JobError> {
        if note
            .as_ref()
            .is_some_and(|note| note.len() > MAX_NOTE_BYTES)
        {
            return Err(invalid(
                "jobs.note.too_long",
                400,
                format!("a note has at most {MAX_NOTE_BYTES} bytes"),
            ));
        }
        self.change_job(id, &self.author(cx), |machine| {
            if usize::from(step) >= machine.job.steps.len() {
                return Err(JobError::Step(StepError::Coded(Box::new(
                    CodedError::new(
                        "jobs.step.not_found",
                        404,
                        format!("job {id} has no step {step}"),
                    )
                    .with_param("job", id.to_string())
                    .with_param("step", step.to_string()),
                ))));
            }
            if !machine.apply(&ResultOp::ManualDone { step }) {
                return Err(JobError::InvalidTransition {
                    from: machine.job.state,
                    action: "complete_manual",
                });
            }
            machine.note_step(step, note.clone());
            Ok(true)
        })
        .await
        .map(|_| ())
    }

    /// Wakes the steps an observation satisfies (`AddressSeen`, `LeaseInPrefix`): the step
    /// is done with the observation id as output and the job continues. Observations older
    /// than the waiting step (minus `observation_skew`) do not count. Failures are logged;
    /// the waiting step then runs into its deadline.
    pub async fn on_observation(&self, observation: &Observation) {
        let candidates = self.inner.waiters().candidates(observation);
        if candidates.is_empty() {
            return;
        }
        let resolver = self
            .inner
            .prefixes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let output = match to_cbor(&observation.id) {
            Ok(bytes) => bytes.to_vec(),
            Err(error) => {
                tracing::warn!(%error, "observation id does not encode");
                return;
            }
        };
        let author = Author {
            principal: Principal::system(SystemComponent::Jobs),
            now: self.inner.clock.now(),
            request: None,
            source_ip: None,
        };
        for (job, waiter) in candidates {
            let recent = observation
                .observed_at
                .checked_add(self.inner.config.observation_skew)
                .is_none_or(|seen| seen >= waiter.since);
            let matches = waiter.condition.matches(observation, |prefix| {
                resolver.as_ref().and_then(|resolver| resolver.cidr(prefix))
            });
            if !recent || !matches {
                continue;
            }
            let op = ResultOp::Observed {
                step: waiter.step,
                output: output.clone(),
            };
            let result = self
                .change_job(job, &author, |machine| {
                    let applied = machine.apply(&op);
                    if applied {
                        machine.note_step(
                            waiter.step,
                            Some(format!("observation {}", observation.id)),
                        );
                    }
                    Ok(applied)
                })
                .await;
            match result {
                // Re-index from the stored job: a stale entry (the job moved on) goes away.
                Ok(job) => self.inner.track_waiter(&job),
                Err(JobError::NotFound(_)) => self.inner.waiters().remove(job),
                Err(error) => {
                    tracing::warn!(%job, error = %error.to_coded_error().code, "observation could not resume the job");
                }
            }
        }
    }

    /// Reads a job.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::NotFound`] or a store error.
    pub async fn job(&self, id: JobId) -> Result<Job, JobError> {
        let view = self.inner.view(None).await?;
        Ok(persist::load(view.as_ref(), id)?
            .ok_or(JobError::NotFound(id))?
            .job)
    }

    /// Reads a job with its transition log and stored preview, at least at `at_least`.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::NotFound`] or a store error.
    pub async fn detail(
        &self,
        id: JobId,
        at_least: Option<Revision>,
    ) -> Result<JobDetail, JobError> {
        let view = self.inner.view(at_least).await?;
        query::detail(view.as_ref(), id)
    }

    /// Lists jobs, newest first, with filters and pagination.
    ///
    /// # Errors
    ///
    /// Returns a store error.
    pub async fn list(&self, query: &JobQuery) -> Result<JobPage, JobError> {
        let view = self.inner.view(query.at_least).await?;
        Ok(query::list(view.as_ref(), query)?)
    }

    /// Number of steps currently waiting for an observation in this engine's index.
    pub fn waiting_for_observations(&self) -> usize {
        self.inner.waiters().len()
    }

    /// Drives one job until it waits, ends or needs a handler that is not there, without
    /// a runner. Meant for tools and tests; the runner does the same for every job.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::NotFound`] if the job does not exist.
    pub async fn drive_once(&self, id: JobId) -> Result<Job, JobError> {
        let stop = std::sync::atomic::AtomicBool::new(false);
        let end = drive::drive(&self.inner, id, &stop, Scope::All).await;
        if matches!(end, drive::DriveEnd::Missing) {
            return Err(JobError::NotFound(id));
        }
        self.job(id).await
    }
}
