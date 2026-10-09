//! Parallelism groups (CONN-09): a bulk operation never runs more jobs of one group at
//! once than the group allows, waiting jobs keep their slot, and other jobs are not held
//! back.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tenko_jobs::{
    EngineConfig, GroupKey, JobQuery, JobState, StepContext, StepError, StepHandler, StepKind,
    StepOutcome, StepPreview,
    testing::{TestEngine, manual, spec, step},
};
use tenko_store::ReadView;

/// A step that takes a little real time and records how many run at once.
#[derive(Default)]
struct Slow {
    running: AtomicUsize,
    max: AtomicUsize,
    done: AtomicUsize,
}

const SLOW: StepKind = StepKind::from_static("jobs.test.slow");

#[async_trait::async_trait]
impl StepHandler for Slow {
    fn kind(&self) -> StepKind {
        SLOW
    }

    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(
        &self,
        _params: &[u8],
        _view: &dyn ReadView,
    ) -> Result<StepPreview, StepError> {
        Ok(StepPreview {
            summary: tenko_core::MessageKey::from_static("jobs.test.slow"),
            args: BTreeMap::new(),
            changes: Vec::new(),
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, _params: &[u8], _cx: &StepContext) -> Result<StepOutcome, StepError> {
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.max.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(2)).await;
        self.running.fetch_sub(1, Ordering::SeqCst);
        self.done.fetch_add(1, Ordering::SeqCst);
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

fn group(name: &str) -> GroupKey {
    GroupKey::new(name).expect("group")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_group_limit_of_ten_holds_across_a_thousand_jobs() {
    let mut t = TestEngine::with_config(EngineConfig {
        workers: 32,
        default_group_limit: 10,
        ..EngineConfig::default()
    });
    let slow = Arc::new(Slow::default());
    t.register(slow.clone());
    let unifi = group("connect.unifi:lab");
    let mut ids = Vec::new();
    for _ in 0..1_000 {
        let mut job = spec(vec![step(&SLOW), step(&SLOW)]);
        job.group = Some(unifi.clone());
        ids.push(t.engine.submit(job, &t.ctx()).await.expect("submit"));
    }
    let _runner = t.engine.start().expect("runner");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let page = t
            .engine
            .list(&JobQuery {
                states: vec![JobState::Succeeded],
                limit: 1_000,
                ..JobQuery::default()
            })
            .await
            .expect("list");
        if page.items.len() == 1_000 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "only {} of 1,000 jobs finished",
            page.items.len()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(slow.done.load(Ordering::SeqCst), 2_000);
    let max = slow.max.load(Ordering::SeqCst);
    assert!(max <= 10, "{max} steps of one group ran at once");
    assert!(max >= 2, "the group ran jobs in parallel ({max})");
    assert_eq!(ids.len(), 1_000);
}

#[tokio::test]
async fn waiting_jobs_keep_their_group_slot_and_other_jobs_run() {
    let t = TestEngine::with_config(EngineConfig {
        group_limits: BTreeMap::from([(group("connect.unifi:lab"), 2)]),
        ..EngineConfig::default()
    });
    let _runner = t.engine.start().expect("runner");
    let mut grouped = Vec::new();
    for _ in 0..5 {
        let mut job = spec(vec![manual("jobs.test.move_port", None, None)]);
        job.group = Some(group("connect.unifi:lab"));
        grouped.push(t.engine.submit(job, &t.ctx()).await.expect("submit"));
    }
    let free = t
        .engine
        .submit(spec(vec![manual("jobs.test.label", None, None)]), &t.ctx())
        .await
        .expect("submit");
    t.wait_for_state(grouped[0], JobState::Waiting).await;
    t.wait_for_state(grouped[1], JobState::Waiting).await;
    t.wait_for_state(free, JobState::Waiting).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    for id in &grouped[2..] {
        assert_eq!(
            t.engine.job(*id).await.expect("job").state,
            JobState::Queued
        );
    }
    // Finishing one grouped job frees its slot for the next in submission order.
    t.engine
        .complete_manual(grouped[0], 0, None, &t.ctx())
        .await
        .expect("complete");
    t.wait_for_state(grouped[0], JobState::Succeeded).await;
    t.wait_for_state(grouped[2], JobState::Waiting).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        t.engine.job(grouped[3]).await.expect("job").state,
        JobState::Queued
    );
    // Cancelling a queued job frees nothing and never starts it.
    t.engine.cancel(grouped[4], &t.ctx()).await.expect("cancel");
    assert_eq!(
        t.engine.job(grouped[4]).await.expect("job").state,
        JobState::Cancelled
    );
}

#[tokio::test]
async fn a_job_carried_group_limit_applies_when_the_engine_has_none() {
    let t = TestEngine::with_config(EngineConfig::default());
    let _runner = t.engine.start().expect("runner");
    let mut jobs = Vec::new();
    for _ in 0..3 {
        let mut job = spec(vec![manual("jobs.test.move_port", None, None)]);
        job.group = Some(group("ipam.move:test"));
        job.group_limit = Some(1);
        jobs.push(t.engine.submit(job, &t.ctx()).await.expect("submit"));
    }
    t.wait_for_state(jobs[0], JobState::Waiting).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    for id in &jobs[1..] {
        assert_eq!(
            t.engine.job(*id).await.expect("job").state,
            JobState::Queued
        );
    }
    // Finishing the first job frees the single slot for the next in submission order.
    t.engine
        .complete_manual(jobs[0], 0, None, &t.ctx())
        .await
        .expect("complete");
    t.wait_for_state(jobs[0], JobState::Succeeded).await;
    t.wait_for_state(jobs[1], JobState::Waiting).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        t.engine.job(jobs[2]).await.expect("job").state,
        JobState::Queued
    );
}
