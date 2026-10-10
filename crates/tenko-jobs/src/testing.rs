//! Test support for this and other packages (feature `testing`).
//!
//! The harness gives a test an engine on a fresh [`MemStore`] with a [`MockClock`] standing
//! at 2026-10-09T12:00:00Z, and scripted step handlers:
//!
//! - [`TestEngine`] bundles the engine, the store and the clock. [`TestEngine::sibling`]
//!   builds a second engine (another node) on the same store and clock for takeover
//!   tests. Its readers ([`wait_for`](TestEngine::wait_for),
//!   [`transitions`](TestEngine::transitions), [`audit`](TestEngine::audit)) poll in real
//!   time and panic on a timeout, so a broken engine fails a test instead of hanging it.
//! - [`Scripted`] is a [`StepHandler`] whose outcomes, compensation results, staged writes
//!   and timing a test scripts, and whose calls it can count. Clones share their state:
//!   register one clone with the engine and keep another for assertions. A gated handler
//!   blocks in `execute` until the test releases it, which holds a job at an exact point
//!   (running, mid-cancel) without sleeping.
//! - [`step`], [`spec`], [`manual`], [`address_seen`], [`arp`] and [`lease`] build job
//!   specifications and observations from documentation-range test data.
//!
//! ```ignore
//! let mut t = TestEngine::new();
//! let mover = Scripted::new("jobs.test.move");
//! t.register(Arc::new(mover.clone()));
//! let _runner = t.engine.start()?;
//! let id = t.engine.submit(spec(vec![step(&mover.kind())]), &t.ctx()).await?;
//! let job = t.wait_for_state(id, JobState::Succeeded).await;
//! assert_eq!(mover.executions(), 1);
//! ```
//!
//! The helpers panic on failures that mean the test itself is broken (a store that cannot
//! be read, a harness constant that does not parse); each documents that under `# Panics`.

use std::{
    collections::BTreeMap,
    fmt::Debug,
    future::Future,
    net::IpAddr,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use bytes::Bytes;
use tenko_core::{
    AuthStrength, HostId, JobId, MacAddr, MessageKey, NodeId, ObjectRef, ObservationId, Principal,
    RequestCtx, Revision, SessionId, Timestamp, UserId, VrfId,
    audit::AuditRecord,
    observe::{Observation, ObservationSource, Observed, ProbeMethod},
    serde_util::HexBytes,
};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadView, ReadViewExt, Store, tables};
use tokio::sync::{Semaphore, watch};

pub use crate::clock::{Clock, MockClock};
use crate::{
    engine::{EngineConfig, JobEngine},
    manual::ManualStep,
    model::{
        Job, JobKind, JobSpec, JobState, ManualTask, ObservationCondition, ObservedPredicate,
        StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview, StepSpec,
    },
    stage::{StagedWrite, stage},
    tables::Transition,
};

/// How long the waiting helpers poll before they give up and panic.
const WAIT_LIMIT: Duration = Duration::from_secs(10);
/// Real time between two reads while polling.
const POLL: Duration = Duration::from_millis(1);
/// Rows read per page when scanning the audit table.
const AUDIT_PAGE: usize = 256;

const USER: &str = "018f0000-0000-7000-8000-000000000001";
const SESSION: &str = "018f0000-0000-7000-8000-000000000002";
const HOST: &str = "018f0000-0000-7000-8000-000000000003";

fn fixed<T>(text: &str) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    text.parse().expect("a fixed test identifier parses")
}

/// The host every [`spec`] names as its target.
pub fn host() -> HostId {
    fixed(HOST)
}

/// An engine on a fresh [`MemStore`] with a [`MockClock`] (2026-10-09T12:00:00Z).
#[derive(Debug)]
pub struct TestEngine {
    /// The engine under test, node 1 unless the configuration says otherwise.
    pub engine: JobEngine,
    /// The store the engine writes to; clones share it.
    pub store: MemStore,
    /// The clock the engine reads; clones share it.
    pub clock: MockClock,
}

impl TestEngine {
    /// An engine with the default [`EngineConfig`].
    pub fn new() -> Self {
        Self::with_config(EngineConfig::default())
    }

    /// An engine with the given configuration.
    pub fn with_config(config: EngineConfig) -> Self {
        Self::on(MemStore::default(), MockClock::default(), config)
    }

    fn on(store: MemStore, clock: MockClock, config: EngineConfig) -> Self {
        let engine =
            JobEngine::with_clock(Arc::new(store.clone()), config, Arc::new(clock.clone()));
        Self {
            engine,
            store,
            clock,
        }
    }

    /// A second engine on the same store and clock (another node), for takeover tests.
    /// Give it a configuration with a different [`EngineConfig::node`]; its handlers are
    /// its own, so register them again.
    #[must_use]
    pub fn sibling(&self, config: EngineConfig) -> Self {
        Self::on(self.store.clone(), self.clock.clone(), config)
    }

    /// Registers a step handler with the engine.
    pub fn register(&mut self, handler: Arc<dyn StepHandler>) {
        self.engine.register(handler);
    }

    /// A request context of a user principal (fixed ids, a passkey session) at the
    /// clock's current time.
    ///
    /// # Panics
    ///
    /// Never in practice: the user and session ids are constants of this module.
    pub fn ctx(&self) -> RequestCtx {
        RequestCtx::new(Principal::User {
            id: fixed::<UserId>(USER),
            session: fixed::<SessionId>(SESSION),
            strength: AuthStrength::Passkey,
        })
        .at(self.clock.now())
    }

    /// Polls until the job satisfies `pred` and returns it.
    ///
    /// Reads the job every millisecond of real time for up to 10 seconds.
    ///
    /// # Panics
    ///
    /// Panics with the job and its transition log if the job does not satisfy `pred` in
    /// time, and if the job cannot be read.
    pub async fn wait_for(&self, id: JobId, pred: impl Fn(&Job) -> bool) -> Job {
        let polling = async {
            loop {
                let job = self
                    .engine
                    .job(id)
                    .await
                    .unwrap_or_else(|error| panic!("job {id} cannot be read: {error}"));
                if pred(&job) {
                    return job;
                }
                tokio::time::sleep(POLL).await;
            }
        };
        if let Ok(job) = tokio::time::timeout(WAIT_LIMIT, polling).await {
            return job;
        }
        let job = self.engine.job(id).await;
        let log = self.transitions(id).await;
        panic!(
            "job {id} did not reach the awaited condition within {WAIT_LIMIT:?}\njob: {job:#?}\ntransitions: {log:#?}"
        );
    }

    /// Polls until the job is in `state` and returns it.
    ///
    /// # Panics
    ///
    /// Panics with the job and its transition log if the state is not reached in 10
    /// seconds.
    pub async fn wait_for_state(&self, id: JobId, state: JobState) -> Job {
        self.wait_for(id, |job| job.state == state).await
    }

    /// The transition log of a job, oldest first.
    ///
    /// # Panics
    ///
    /// Panics if the job does not exist or the store cannot be read.
    pub async fn transitions(&self, id: JobId) -> Vec<Transition> {
        self.engine
            .detail(id, None)
            .await
            .unwrap_or_else(|error| panic!("job {id} has no detail: {error}"))
            .transitions
    }

    /// Every sealed audit record in [`tables::AUDIT`], in sequence order.
    ///
    /// # Panics
    ///
    /// Panics if the store cannot be read.
    pub async fn audit(&self) -> Vec<AuditRecord> {
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("the store can be read");
        let mut records = Vec::new();
        let all = KeyRange::all();
        let mut range = all.clone();
        loop {
            let page = view
                .scan_typed(&tables::AUDIT, range.clone(), AUDIT_PAGE, false)
                .expect("the audit table can be scanned");
            let full = page.len() == AUDIT_PAGE;
            let last = page.last().map(|(seq, _, _)| tables::AUDIT.key(seq));
            records.extend(page.into_iter().map(|(_, record, _)| record));
            match last {
                Some(last) if full => range = all.clone().after(last),
                _ => return records,
            }
        }
    }

    /// The store revision now.
    pub fn revision(&self) -> Revision {
        self.store.status().revision
    }
}

impl Default for TestEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs a future for at most 10 seconds of real time, so that a test never hangs.
///
/// # Panics
///
/// Panics if the future does not finish in time.
pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT_LIMIT, future)
        .await
        .unwrap_or_else(|_| panic!("the operation did not finish within {WAIT_LIMIT:?}"))
}

type WriteFn = fn(&StepContext) -> StagedWrite;

/// What a [`Scripted`] handler is set up to do. Fixed once the handler is shared.
#[derive(Debug, Clone)]
struct Script {
    kind: StepKind,
    idempotent: bool,
    outcomes: Vec<Result<StepOutcome, StepError>>,
    compensations: Vec<Result<(), StepError>>,
    preview_error: Option<StepError>,
    gated: bool,
    staging: Option<WriteFn>,
    compensation_staging: Option<WriteFn>,
}

/// What a [`Scripted`] handler has seen so far.
#[derive(Debug, Default)]
struct Calls {
    executions: usize,
    compensated: usize,
    compensated_outputs: Vec<Option<Vec<u8>>>,
    running: usize,
    max_running: usize,
    attempts: Vec<u32>,
}

#[derive(Debug)]
struct Shared {
    calls: Mutex<Calls>,
    /// The number of `execute` calls started, for [`Scripted::wait_started`].
    started: watch::Sender<usize>,
    /// One permit per `execute` call a gated handler lets through.
    gate: Semaphore,
}

impl Shared {
    fn calls(&self) -> MutexGuard<'_, Calls> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Counts an `execute` call as in flight until it finishes or is dropped (a timeout or a
/// crash drops the call mid-flight).
struct InFlight<'a>(&'a Shared);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let mut calls = self.0.calls();
        calls.running = calls.running.saturating_sub(1);
    }
}

/// The scripted answer for call number `call`: the entry at that position, else the last.
fn scripted<T: Clone>(answers: &[T], call: usize) -> Option<T> {
    answers.get(call).or_else(|| answers.last()).cloned()
}

/// A configurable step handler. Clones share their state: register one clone with the
/// engine and keep another for assertions.
///
/// By default the step is not idempotent, every `execute` returns
/// `Done { output: Some(b"out-<attempt>") }` (the attempt of the step), `compensate`
/// succeeds, and `preview` answers with the message `jobs.test.preview` and the argument
/// `kind`.
#[derive(Debug, Clone)]
pub struct Scripted {
    script: Script,
    shared: Arc<Shared>,
}

impl Scripted {
    /// A handler for the step kind `kind`, such as `jobs.test.move`.
    ///
    /// # Panics
    ///
    /// Panics if `kind` is not a valid namespaced name.
    pub fn new(kind: &'static str) -> Self {
        let (started, _) = watch::channel(0);
        Self {
            script: Script {
                kind: StepKind::from_static(kind),
                idempotent: false,
                outcomes: Vec::new(),
                compensations: Vec::new(),
                preview_error: None,
                gated: false,
                staging: None,
                compensation_staging: None,
            },
            shared: Arc::new(Shared {
                calls: Mutex::new(Calls::default()),
                started,
                gate: Semaphore::new(0),
            }),
        }
    }

    /// Sets [`StepHandler::idempotent`].
    #[must_use]
    pub fn idempotent(mut self, idempotent: bool) -> Self {
        self.script.idempotent = idempotent;
        self
    }

    /// Outcomes for successive `execute` calls; when they run out the last one repeats.
    #[must_use]
    pub fn outcomes(mut self, outcomes: Vec<Result<StepOutcome, StepError>>) -> Self {
        self.script.outcomes = outcomes;
        self
    }

    /// Results for successive `compensate` calls; when they run out the last one repeats.
    #[must_use]
    pub fn compensations(mut self, results: Vec<Result<(), StepError>>) -> Self {
        self.script.compensations = results;
        self
    }

    /// Makes `preview` fail with this error.
    #[must_use]
    pub fn preview_error(mut self, error: StepError) -> Self {
        self.script.preview_error = Some(error);
        self
    }

    /// Makes `execute` wait on a gate before it returns its outcome;
    /// [`release`](Scripted::release) lets calls through.
    #[must_use]
    pub fn gated(mut self) -> Self {
        self.script.gated = true;
        self
    }

    /// Lets `calls` waiting (or future) `execute` calls of a [gated](Scripted::gated)
    /// handler through.
    pub fn release(&self, calls: usize) {
        self.shared.gate.add_permits(calls);
    }

    /// Stages the write that `write` returns during `execute`, with [`stage`].
    #[must_use]
    pub fn staging(mut self, write: fn(&StepContext) -> StagedWrite) -> Self {
        self.script.staging = Some(write);
        self
    }

    /// Stages the write that `write` returns during `compensate`, with [`stage`].
    #[must_use]
    pub fn compensation_staging(mut self, write: fn(&StepContext) -> StagedWrite) -> Self {
        self.script.compensation_staging = Some(write);
        self
    }

    /// The step kind this handler runs.
    pub fn kind(&self) -> StepKind {
        self.script.kind.clone()
    }

    /// `execute` calls started.
    pub fn executions(&self) -> usize {
        self.shared.calls().executions
    }

    /// `compensate` calls started.
    pub fn compensated(&self) -> usize {
        self.shared.calls().compensated
    }

    /// The `output` argument of each `compensate` call, in call order.
    pub fn compensated_outputs(&self) -> Vec<Option<Vec<u8>>> {
        self.shared.calls().compensated_outputs.clone()
    }

    /// `execute` calls in flight now (a gated call counts while it waits).
    pub fn running(&self) -> usize {
        self.shared.calls().running
    }

    /// The highest number of `execute` calls that were in flight at once.
    pub fn max_running(&self) -> usize {
        self.shared.calls().max_running
    }

    /// The attempt (`StepContext::attempt`) of each `execute` call, in call order.
    pub fn attempts(&self) -> Vec<u32> {
        self.shared.calls().attempts.clone()
    }

    /// Waits, in real time, until at least `calls` `execute` calls have started.
    ///
    /// # Panics
    ///
    /// Panics if that does not happen within 10 seconds.
    pub async fn wait_started(&self, calls: usize) {
        let mut started = self.shared.started.subscribe();
        let reached = tokio::time::timeout(WAIT_LIMIT, started.wait_for(|n| *n >= calls)).await;
        assert!(
            reached.is_ok(),
            "{} did not start {calls} execute calls within {WAIT_LIMIT:?}; it started {}",
            self.script.kind,
            self.executions()
        );
    }
}

#[async_trait::async_trait]
impl StepHandler for Scripted {
    fn kind(&self) -> StepKind {
        Scripted::kind(self)
    }

    fn idempotent(&self) -> bool {
        self.script.idempotent
    }

    async fn preview(
        &self,
        _params: &[u8],
        _view: &dyn ReadView,
    ) -> Result<StepPreview, StepError> {
        if let Some(error) = &self.script.preview_error {
            return Err(error.clone());
        }
        Ok(StepPreview {
            summary: MessageKey::from_static("jobs.test.preview"),
            args: BTreeMap::from([("kind".to_owned(), self.script.kind.to_string())]),
            changes: Vec::new(),
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, _params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let call = {
            let mut calls = self.shared.calls();
            let call = calls.executions;
            calls.executions += 1;
            calls.attempts.push(cx.attempt);
            calls.running += 1;
            calls.max_running = calls.max_running.max(calls.running);
            call
        };
        let _in_flight = InFlight(&self.shared);
        self.shared
            .started
            .send_modify(|started| *started = (*started).max(call + 1));
        if self.script.gated {
            self.shared
                .gate
                .acquire()
                .await
                .expect("the gate is never closed")
                .forget();
        }
        if let Some(write) = self.script.staging {
            stage(cx, write(cx))?;
        }
        scripted(&self.script.outcomes, call).unwrap_or_else(|| {
            Ok(StepOutcome::Done {
                output: Some(Bytes::from(format!("out-{}", cx.attempt))),
            })
        })
    }

    async fn compensate(
        &self,
        _params: &[u8],
        output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        let call = {
            let mut calls = self.shared.calls();
            let call = calls.compensated;
            calls.compensated += 1;
            calls.compensated_outputs.push(output.map(<[u8]>::to_vec));
            call
        };
        if let Some(write) = self.script.compensation_staging {
            stage(cx, write(cx))?;
        }
        scripted(&self.script.compensations, call).unwrap_or(Ok(()))
    }
}

/// A step of `kind` with empty parameters (an empty CBOR map) and no own timeout.
pub fn step(kind: &StepKind) -> StepSpec {
    StepSpec {
        kind: kind.clone(),
        params: HexBytes(vec![0xA0]),
        timeout: None,
    }
}

/// A job `jobs.test` with the given steps, one host target ([`host`]), a timeout of one
/// hour, no group and no idempotency key.
pub fn spec(steps: Vec<StepSpec>) -> JobSpec {
    JobSpec {
        kind: JobKind::from_static("jobs.test"),
        title: MessageKey::from_static("jobs.test.title"),
        targets: vec![ObjectRef::from(host())],
        steps,
        timeout: Duration::from_secs(3600),
        group: None,
        group_limit: None,
        idempotency: None,
        node: None,
    }
}

/// A `jobs.manual` step asking a person to do `instruction` (a message key such as
/// `jobs.test.reconfigure`), with the argument `host = printer-1`. `undo` is the message
/// shown when the job rolls back after the task was done; `timeout` is the step timeout.
///
/// # Panics
///
/// Panics if a message key is invalid.
pub fn manual(
    instruction: &'static str,
    undo: Option<&'static str>,
    timeout: Option<Duration>,
) -> StepSpec {
    let task = ManualTask {
        instruction: MessageKey::from_static(instruction),
        args: BTreeMap::from([("host".to_owned(), "printer-1".to_owned())]),
        undo: undo.map(MessageKey::from_static),
    };
    ManualStep::spec(&task, timeout).expect("a manual task encodes")
}

/// A condition that the address `ip` in `vrf` answers (from `mac`, when given) for the
/// [`host`].
pub fn address_seen(vrf: VrfId, ip: IpAddr, mac: Option<MacAddr>) -> ObservationCondition {
    ObservationCondition {
        subject: host().into(),
        any_of: vec![ObservedPredicate::AddressSeen { vrf, ip, mac }],
    }
}

/// An ARP probe (node 7) that saw `ip` in `vrf` at `at`.
pub fn arp(vrf: VrfId, ip: IpAddr, mac: Option<MacAddr>, at: Timestamp) -> Observation {
    Observation {
        id: ObservationId::generate(),
        source: ObservationSource::Probe {
            node: NodeId(7),
            method: ProbeMethod::Arp,
        },
        subject: Observed::Address { vrf, ip, mac },
        observed_at: at,
        received_at: at,
        expires_at: None,
    }
}

/// A DHCP lease (node 8) of `ip` to `mac` in `vrf`, seen at `at`.
pub fn lease(vrf: VrfId, ip: IpAddr, mac: MacAddr, at: Timestamp) -> Observation {
    Observation {
        id: ObservationId::generate(),
        source: ObservationSource::DhcpLease { node: NodeId(8) },
        subject: Observed::Address {
            vrf,
            ip,
            mac: Some(mac),
        },
        observed_at: at,
        received_at: at,
        expires_at: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(job: JobId, step: u16, attempt: u32) -> StepContext {
        StepContext {
            job,
            step,
            attempt,
            request: RequestCtx::system(tenko_core::SystemComponent::Jobs),
            store: Arc::new(MemStore::default()),
            deadline: None,
        }
    }

    #[test]
    fn scripted_answers_repeat_the_last_entry() {
        assert_eq!(scripted::<u8>(&[], 0), None);
        assert_eq!(scripted(&[1, 2], 0), Some(1));
        assert_eq!(scripted(&[1, 2], 1), Some(2));
        assert_eq!(scripted(&[1, 2], 7), Some(2));
    }

    #[tokio::test]
    async fn the_default_handler_succeeds_with_an_attempt_output() {
        let handler = Scripted::new("jobs.test.move");
        let cx = context(JobId::generate(), 0, 3);
        let outcome = handler.execute(&[0xA0], &cx).await;
        assert_eq!(
            outcome,
            Ok(StepOutcome::Done {
                output: Some(Bytes::from_static(b"out-3"))
            })
        );
        assert_eq!(
            handler.compensate(&[0xA0], Some(b"out-3"), &cx).await,
            Ok(())
        );
        assert_eq!(handler.executions(), 1);
        assert_eq!(handler.compensated(), 1);
        assert_eq!(handler.attempts(), vec![3]);
        assert_eq!(handler.compensated_outputs(), vec![Some(b"out-3".to_vec())]);
        assert_eq!((handler.running(), handler.max_running()), (0, 1));
    }

    #[tokio::test]
    async fn a_gated_handler_waits_for_a_release() {
        let handler = Scripted::new("jobs.test.move").gated();
        let cx = context(JobId::generate(), 0, 1);
        let call = {
            let handler = handler.clone();
            tokio::spawn(async move { handler.execute(&[0xA0], &cx).await })
        };
        handler.wait_started(1).await;
        assert_eq!(handler.running(), 1);
        assert!(!call.is_finished());
        handler.release(1);
        assert!(within(call).await.expect("joined").is_ok());
        assert_eq!(handler.running(), 0);
    }

    #[tokio::test]
    async fn the_harness_builds_specs_and_conditions() {
        let t = TestEngine::new();
        assert_eq!(t.clock.now().to_rfc3339(), "2026-10-09T12:00:00Z");
        let handler = Scripted::new("jobs.test.move");
        let job = spec(vec![
            step(&handler.kind()),
            manual("jobs.test.hand_over", None, None),
        ]);
        assert_eq!(job.steps.len(), 2);
        assert_eq!(job.targets, vec![ObjectRef::from(host())]);
        let preview = handler
            .preview(
                &[0xA0],
                t.store
                    .read(ReadConsistency::Local)
                    .await
                    .expect("view")
                    .as_ref(),
            )
            .await
            .expect("preview");
        assert_eq!(preview.args["kind"], "jobs.test.move");
        let vrf = VrfId::generate();
        let ip: IpAddr = "192.0.2.10".parse().expect("ip");
        let mac: MacAddr = "00:00:5e:00:53:10".parse().expect("mac");
        let condition = address_seen(vrf, ip, Some(mac));
        let other: MacAddr = "00:00:5e:00:53:11".parse().expect("mac");
        assert!(condition.matches(&arp(vrf, ip, Some(mac), t.clock.now()), |_| None));
        assert!(condition.matches(&lease(vrf, ip, mac, t.clock.now()), |_| None));
        assert!(!condition.matches(&lease(vrf, ip, other, t.clock.now()), |_| None));
        assert!(!condition.matches(&arp(vrf, ip, None, t.clock.now()), |_| None));
        assert_eq!(t.audit().await.len(), 0);
        assert_eq!(t.revision(), Revision::ZERO);
    }
}
