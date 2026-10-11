//! WP3.1b acceptance tests of the leader-only job runner on a three-node in-process Raft
//! cluster, one engine per member over that member's `RaftStore`:
//!
//! - two runners, one with the current leader epoch and one with a stale one, never run a
//!   job's step twice: the stale runner is fenced out and the current one runs every job
//!   exactly once;
//! - a deposed leader's runner cannot write: its next write fails on the epoch
//!   precondition and the runner ends with `RunnerExit::Deposed`, and an idle one ends by
//!   itself at its next scan;
//! - a leader lost during a non-idempotent step: the next leader compensates the step and
//!   never runs it again; an idempotent step is run again and never compensated;
//! - a group limit of 10 holds across a thousand jobs submitted through all three members
//!   while only the leader's runner drives them.

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tenko_core::{JobId, NodeId, RequestCtx, SystemComponent, cluster::LEADER_EPOCH};
use tenko_jobs::{
    EngineConfig, GroupKey, Job, JobEngine, JobQuery, JobState, RunnerExit, StepContext, StepError,
    StepHandler, StepKind, StepOutcome, StepPreview, StepState,
    testing::{Scripted, spec, step},
};
use tenko_store::{
    ReadConsistency, ReadView, Store, StoreError, WriteBatch,
    raft::{RaftStore, fixture::InProcessCluster},
    testing::ConformanceConfig,
};

/// How long a test waits for the cluster to reach a state before it fails.
const LIMIT: Duration = Duration::from_secs(90);

/// Runs a future for at most [`LIMIT`], so that a broken engine fails a test instead of
/// hanging it.
async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(LIMIT, future)
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen within {LIMIT:?}"))
}

fn ctx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Jobs)
}

/// An engine over a member's store, with the given step handlers registered.
fn engine_on(member: &RaftStore, handlers: Vec<Arc<dyn StepHandler>>) -> JobEngine {
    let store: Arc<dyn Store> = Arc::new(member.clone());
    let mut engine = JobEngine::new(
        store,
        EngineConfig {
            node: member.node_id(),
            workers: 32,
            ..EngineConfig::default()
        },
    );
    for handler in handlers {
        engine.register(handler);
    }
    engine
}

/// What `take_office` of `tenko serve` does: bumps the leader epoch in a batch that expects
/// its previous value, and returns the new one.
async fn take_office(member: &RaftStore) -> u64 {
    let view = member
        .read(ReadConsistency::Linearizable)
        .await
        .expect("read the epoch");
    let current = view.counter(&LEADER_EPOCH).expect("the epoch counter");
    let mut batch = WriteBatch::for_request(&ctx());
    batch.preconditions.push(tenko_store::fence(current));
    batch.bump(LEADER_EPOCH);
    member.propose(batch).await.expect("take office");
    current + 1
}

/// Polls until the job is in `state` on this engine's member and returns it.
async fn wait_for_state(engine: &JobEngine, id: JobId, state: JobState) -> Job {
    within(&format!("job {id} in {state:?}"), async {
        loop {
            let job = engine.job(id).await.expect("read the job");
            if job.state == state {
                return job;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
}

/// Polls until `count` jobs are in `state`.
async fn wait_for_count(engine: &JobEngine, state: JobState, count: usize) {
    within(&format!("{count} jobs in {state:?}"), async {
        loop {
            let page = engine
                .list(&JobQuery {
                    states: vec![state],
                    limit: 1_000,
                    ..JobQuery::default()
                })
                .await
                .expect("list the jobs");
            if page.items.len() >= count {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

/// What the probe handlers of all engines saw: the engines that ran each job's step, and
/// the steps in flight at once.
#[derive(Default)]
struct Book {
    ran: Mutex<HashMap<JobId, Vec<NodeId>>>,
    running: AtomicUsize,
    max_running: AtomicUsize,
}

impl Book {
    fn ran(&self) -> HashMap<JobId, Vec<NodeId>> {
        self.ran
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

const PROBE: StepKind = StepKind::from_static("jobs.test.probe");

/// A step of one engine that records which engine ran it for which job, and for how many
/// run at once, then takes a little real time.
struct Probe {
    node: NodeId,
    idempotent: bool,
    delay: Duration,
    book: Arc<Book>,
}

#[async_trait::async_trait]
impl StepHandler for Probe {
    fn kind(&self) -> StepKind {
        PROBE
    }

    fn idempotent(&self) -> bool {
        self.idempotent
    }

    async fn preview(
        &self,
        _params: &[u8],
        _view: &dyn ReadView,
    ) -> Result<StepPreview, StepError> {
        Ok(StepPreview {
            summary: tenko_core::MessageKey::from_static("jobs.test.probe"),
            args: BTreeMap::new(),
            changes: Vec::new(),
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, _params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        self.book
            .ran
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(cx.job)
            .or_default()
            .push(self.node);
        let now = self.book.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.book.max_running.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        self.book.running.fetch_sub(1, Ordering::SeqCst);
        Ok(StepOutcome::Done { output: None })
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        Ok(())
    }
}

/// One engine per member, each with its own probe handler over the shared book.
fn probe_engines(
    cluster: &InProcessCluster,
    book: &Arc<Book>,
    idempotent: bool,
    delay: Duration,
) -> Vec<JobEngine> {
    cluster
        .members()
        .iter()
        .map(|member| {
            let probe = Probe {
                node: member.node_id(),
                idempotent,
                delay,
                book: Arc::clone(book),
            };
            engine_on(member, vec![Arc::new(probe)])
        })
        .collect()
}

fn engine_of(engines: &[JobEngine], member: &RaftStore) -> JobEngine {
    engines
        .iter()
        .find(|engine| engine.config().node == member.node_id())
        .expect("an engine on every member")
        .clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_engines_never_run_the_same_job() {
    const JOBS: usize = 50;
    let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
    let book = Arc::new(Book::default());
    let engines = probe_engines(&cluster, &book, false, Duration::from_millis(2));

    // The controller of node 2 held office first (epoch e1) and is stale since the
    // controller of node 3 took office (epoch e2).
    let stale_member = cluster.member(NodeId(2));
    let current_member = cluster.member(NodeId(3));
    let e1 = take_office(stale_member).await;
    let e2 = take_office(current_member).await;
    assert_eq!(e2, e1 + 1);

    // Jobs are submitted through both engines before either runner starts, so both see
    // all of them as claimable.
    let (stale, current) = (&engines[1], &engines[2]);
    let mut ids = Vec::new();
    for n in 0..JOBS {
        let engine = if n % 2 == 0 { stale } else { current };
        ids.push(
            engine
                .submit(spec(vec![step(&PROBE)]), &ctx())
                .await
                .expect("submit"),
        );
    }
    let mut stale_runner = stale.start_leader(e1).expect("stale runner");
    let current_runner = current.start_leader(e2).expect("current runner");

    wait_for_count(current, JobState::Succeeded, JOBS).await;
    assert_eq!(
        within("the stale runner to end", stale_runner.wait()).await,
        RunnerExit::Deposed { epoch: e1 }
    );
    assert!(current_runner.is_running());

    let ran = book.ran();
    assert_eq!(ran.len(), JOBS, "every job's step ran");
    for id in &ids {
        assert_eq!(
            ran[id],
            vec![NodeId(3)],
            "job {id} ran once, on the engine with the current epoch"
        );
    }
    for id in &ids {
        let job = current.job(*id).await.expect("job");
        assert_eq!(job.state, JobState::Succeeded);
        assert_eq!(job.steps[0].attempts, 1);
        assert_eq!(job.runner, Some(NodeId(3)));
    }
    current_runner.stop().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deposed_leaders_job_write_fails_with_the_epoch_precondition() {
    let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
    let book = Arc::new(Book::default());
    let engines = probe_engines(&cluster, &book, true, Duration::from_millis(1));

    let old = cluster.wait_for_leader().await;
    let old_engine = engine_of(&engines, &old);
    let epoch = take_office(&old).await;
    let mut runner = old_engine.start_leader(epoch).expect("runner");

    // While it leads, the runner drives a job.
    let first = old_engine
        .submit(spec(vec![step(&PROBE)]), &ctx())
        .await
        .expect("submit");
    wait_for_state(&old_engine, first, JobState::Succeeded).await;
    assert!(runner.is_running());

    // Another controller takes office.
    let new = cluster.hand_over().await;
    assert_ne!(new.node_id(), old.node_id());
    let next = take_office(&new).await;
    assert_eq!(next, epoch + 1);

    // A fenced write of the old term fails on the epoch precondition ...
    let mut batch = WriteBatch::for_request(&ctx());
    batch.preconditions.push(tenko_store::fence(epoch));
    batch.bump(LEADER_EPOCH);
    let error = old.propose(batch).await.expect_err("the fence holds");
    assert!(
        matches!(error, StoreError::PreconditionFailed(_)),
        "{error:?}"
    );

    // ... so the old runner's next job write fails: it ends deposed and starts no step.
    let second = old_engine
        .submit(spec(vec![step(&PROBE)]), &ctx())
        .await
        .expect("submit");
    assert_eq!(
        within("the old runner to end", runner.wait()).await,
        RunnerExit::Deposed { epoch }
    );
    assert!(!runner.is_running());
    let job = old_engine.job(second).await.expect("job");
    assert_eq!(job.state, JobState::Queued);
    assert_eq!(job.runner, None);
    assert!(!book.ran().contains_key(&second));
    cluster.shutdown().await;
}

#[tokio::test]
async fn an_idle_deposed_runner_ends_by_itself() {
    let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
    let old = cluster.wait_for_leader().await;
    let engine = JobEngine::new(
        Arc::new(old.clone()),
        EngineConfig {
            node: old.node_id(),
            scan_interval: Duration::from_millis(200),
            ..EngineConfig::default()
        },
    );
    let epoch = take_office(&old).await;
    let mut runner = engine.start_leader(epoch).expect("runner");
    let new = cluster.hand_over().await;
    take_office(&new).await;
    // No job, so no write of the old runner fails: its scan sees the epoch move.
    assert_eq!(
        within("the idle runner to end", runner.wait()).await,
        RunnerExit::Deposed { epoch }
    );
    cluster.shutdown().await;
}

/// A job whose step is in flight on the leader when leadership moves to another member;
/// the new leader's runner takes over. Returns what the handler saw and the final job.
async fn lose_the_leader_during_a_step(idempotent: bool) -> (Scripted, Job) {
    let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
    let mover = Scripted::new("jobs.test.move")
        .idempotent(idempotent)
        .gated();
    let engines: Vec<JobEngine> = cluster
        .members()
        .iter()
        .map(|member| engine_on(member, vec![Arc::new(mover.clone())]))
        .collect();

    let old = cluster.wait_for_leader().await;
    let old_engine = engine_of(&engines, &old);
    let epoch = take_office(&old).await;
    let mut old_runner = old_engine.start_leader(epoch).expect("old runner");
    let id = old_engine
        .submit(spec(vec![step(&mover.kind())]), &ctx())
        .await
        .expect("submit");
    mover.wait_started(1).await;
    let job = old_engine.job(id).await.expect("job");
    assert_eq!(job.steps[0].state, StepState::Running);
    assert_eq!(job.runner, Some(old.node_id()));

    // The leader is lost while the step runs; the next one takes office and starts its
    // runner, which takes the job over at once (no lease wait: the clock is a real one
    // and the lease lasts 30 s).
    let new = cluster.hand_over().await;
    let new_engine = engine_of(&engines, &new);
    let next = take_office(&new).await;
    let new_runner = new_engine.start_leader(next).expect("new runner");

    let job = if idempotent {
        mover.wait_started(2).await;
        mover.release(2);
        wait_for_state(&new_engine, id, JobState::Succeeded).await
    } else {
        let job = wait_for_state(&new_engine, id, JobState::RolledBack).await;
        mover.release(1);
        job
    };
    assert_eq!(job.runner, Some(new.node_id()));

    // The old step finishes now. Its result cannot be written; the old runner learns that
    // it lost the job when it reloads it, and that it was deposed with its next write: the
    // claim of a further job fails on the epoch, and that job is never started (the new
    // runner is stopped so that it does not run the job).
    new_runner.stop().await;
    mover.release(2);
    let extra = old_engine
        .submit(spec(vec![step(&mover.kind())]), &ctx())
        .await
        .expect("submit");
    assert_eq!(
        within("the old runner to end", old_runner.wait()).await,
        RunnerExit::Deposed { epoch }
    );
    let late = old_engine.job(extra).await.expect("job");
    assert_eq!(late.state, JobState::Queued);
    let after = new_engine.job(id).await.expect("job");
    assert_eq!(after.state, job.state);
    assert_eq!(after.steps[0].state, job.steps[0].state);
    cluster.shutdown().await;
    (mover, after)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leader_killed_during_a_non_idempotent_step_is_re_run_or_compensated_never_both() {
    let (mover, job) = lose_the_leader_during_a_step(false).await;
    assert_eq!(job.state, JobState::RolledBack);
    assert_eq!(job.steps[0].state, StepState::Compensated);
    assert_eq!(job.error.expect("error").code, "jobs.step.interrupted");
    assert_eq!(
        mover.executions(),
        1,
        "a non-idempotent step never runs twice"
    );
    assert_eq!(
        mover.compensated(),
        1,
        "the interrupted step is compensated"
    );
    assert_eq!(mover.compensated_outputs(), vec![None]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leader_killed_during_an_idempotent_step_re_runs_it_without_compensation() {
    let (mover, job) = lose_the_leader_during_a_step(true).await;
    assert_eq!(job.state, JobState::Succeeded);
    assert_eq!(job.steps[0].state, StepState::Done);
    assert_eq!(job.steps[0].attempts, 2);
    assert_eq!(mover.executions(), 2, "an idempotent step runs again");
    assert_eq!(mover.attempts(), vec![1, 2]);
    assert_eq!(mover.compensated(), 0, "a re-run step is not compensated");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn group_limit_ten_holds_across_a_thousand_jobs_on_three_controllers() {
    const JOBS: usize = 1_000;
    let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
    let book = Arc::new(Book::default());
    let engines = probe_engines(&cluster, &book, true, Duration::from_millis(3));

    let leader = cluster.wait_for_leader().await;
    let leader_engine = engine_of(&engines, &leader);
    let epoch = take_office(&leader).await;
    let group = GroupKey::new("connect.unifi:lab").expect("group");
    let mut ids = Vec::new();
    for n in 0..JOBS {
        let mut job = spec(vec![step(&PROBE)]);
        job.group = Some(group.clone());
        job.group_limit = Some(10);
        ids.push(
            engines[n % engines.len()]
                .submit(job, &ctx())
                .await
                .expect("submit"),
        );
    }
    let runner = leader_engine.start_leader(epoch).expect("runner");
    wait_for_count(&leader_engine, JobState::Succeeded, JOBS).await;

    let max = book.max_running.load(Ordering::SeqCst);
    assert!(max <= 10, "{max} steps of one group ran at once");
    assert!(max >= 2, "the group ran jobs in parallel ({max})");
    let ran = book.ran();
    assert_eq!(ran.len(), JOBS);
    for id in &ids {
        assert_eq!(
            ran[id],
            vec![leader.node_id()],
            "job {id} ran once, on the leader"
        );
    }
    runner.stop().await;
    cluster.shutdown().await;
}
