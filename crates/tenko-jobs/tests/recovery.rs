//! Runner restarts, lease takeover and graceful stop.

use std::{sync::Arc, time::Duration};

use tenko_core::{CodedError, NodeId};
use tenko_jobs::{
    EngineConfig, JobState, StepError, StepState, TransitionEvent,
    testing::{Scripted, TestEngine, manual, spec, step},
};

fn node(id: u64) -> EngineConfig {
    EngineConfig {
        node: NodeId(id),
        ..EngineConfig::default()
    }
}

#[tokio::test]
async fn a_restarted_runner_runs_an_interrupted_idempotent_step_again() {
    let mut t = TestEngine::new();
    let step0 = Scripted::new("jobs.test.sync").idempotent(true).gated();
    t.register(Arc::new(step0.clone()));
    let runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(spec(vec![step(&step0.kind())]), &t.ctx())
        .await
        .expect("submit");
    step0.wait_started(1).await;
    runner.abort();
    let job = t.engine.job(id).await.expect("job");
    assert_eq!(
        job.steps[0].state,
        StepState::Running,
        "the crash left the step running"
    );

    step0.release(1);
    let _runner = t.engine.start().expect("restart");
    let job = t.wait_for_state(id, JobState::Succeeded).await;
    assert_eq!(step0.attempts(), vec![1, 2]);
    assert_eq!(job.steps[0].attempts, 2);
}

#[tokio::test]
async fn a_restarted_runner_rolls_back_an_interrupted_non_idempotent_step() {
    let mut t = TestEngine::new();
    let first = Scripted::new("jobs.test.reserve");
    let second = Scripted::new("jobs.test.move").gated();
    t.register(Arc::new(first.clone()));
    t.register(Arc::new(second.clone()));
    let runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(
            spec(vec![step(&first.kind()), step(&second.kind())]),
            &t.ctx(),
        )
        .await
        .expect("submit");
    second.wait_started(1).await;
    runner.abort();

    let _runner = t.engine.start().expect("restart");
    let job = t.wait_for_state(id, JobState::RolledBack).await;
    assert_eq!(
        second.executions(),
        1,
        "a non-idempotent step never runs twice"
    );
    let StepState::Compensated = job.steps[1].state else {
        panic!(
            "the interrupted step is compensated: {:?}",
            job.steps[1].state
        );
    };
    assert_eq!(job.error.expect("error").code, "jobs.step.interrupted");
    assert_eq!(second.compensated_outputs(), vec![None]);
    assert_eq!(first.compensated(), 1);
    let rows = t.transitions(id).await;
    assert!(rows.iter().any(|row| {
        matches!(&row.step_state, Some(StepState::Failed { error }) if error.code == "jobs.step.interrupted")
    }));
}

#[tokio::test]
async fn a_restarted_runner_keeps_waiting_jobs_and_their_deadlines() {
    let t = TestEngine::new();
    let runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(
            spec(vec![manual(
                "jobs.test.reserve",
                None,
                Some(Duration::from_secs(120)),
            )]),
            &t.ctx(),
        )
        .await
        .expect("submit");
    t.wait_for_state(id, JobState::Waiting).await;
    runner.stop().await;
    let _runner = t.engine.start().expect("restart");
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        t.engine.job(id).await.expect("job").state,
        JobState::Waiting
    );
    t.clock.advance(Duration::from_secs(120));
    let job = t.wait_for_state(id, JobState::RolledBack).await;
    assert_eq!(job.error.expect("error").code, "jobs.step.deadline_passed");
}

#[tokio::test]
async fn another_node_takes_over_the_jobs_of_an_expired_lease() {
    let first = TestEngine::with_config(node(1));
    let second = first.sibling(node(2));
    let runner = first.engine.start().expect("runner 1");
    let id = first
        .engine
        .submit(
            spec(vec![manual("jobs.test.reserve", None, None)]),
            &first.ctx(),
        )
        .await
        .expect("submit");
    let job = first.wait_for_state(id, JobState::Waiting).await;
    assert_eq!(job.runner, Some(NodeId(1)));
    runner.abort();

    // While the lease of node 1 is valid, node 2 leaves the job alone.
    let _second_runner = second.engine.start().expect("runner 2");
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        second.engine.job(id).await.expect("job").runner,
        Some(NodeId(1))
    );

    // Past the lease and the next scan, node 2 claims it.
    first
        .clock
        .advance(EngineConfig::default().lease_ttl + Duration::from_secs(1));
    let job = second
        .wait_for(id, |job| job.runner == Some(NodeId(2)))
        .await;
    assert_eq!(job.state, JobState::Waiting);
    let rows = second.transitions(id).await;
    assert!(
        rows.iter()
            .any(|row| row.event == TransitionEvent::Claimed && row.runner == Some(NodeId(2)))
    );
    second
        .engine
        .complete_manual(id, 0, Some("done on node 2".to_owned()), &second.ctx())
        .await
        .expect("complete");
    second.wait_for_state(id, JobState::Succeeded).await;
}

#[tokio::test]
async fn a_takeover_loses_against_a_renewed_lease() {
    let first = TestEngine::with_config(node(1));
    let second = first.sibling(node(2));
    let _runner = first.engine.start().expect("runner 1");
    let id = first
        .engine
        .submit(
            spec(vec![manual("jobs.test.reserve", None, None)]),
            &first.ctx(),
        )
        .await
        .expect("submit");
    first.wait_for_state(id, JobState::Waiting).await;
    // Node 1 keeps running and renews its lease as the clock moves.
    for _ in 0..6 {
        first.clock.advance(Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let job = second.engine.drive_once(id).await.expect("drive");
    assert_eq!(job.runner, Some(NodeId(1)), "a live owner keeps its job");
}

#[tokio::test]
async fn a_graceful_stop_lets_the_step_in_flight_finish() {
    let mut t = TestEngine::new();
    let slow = Scripted::new("jobs.test.slow").gated();
    let next = Scripted::new("jobs.test.next");
    t.register(Arc::new(slow.clone()));
    t.register(Arc::new(next.clone()));
    let runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(spec(vec![step(&slow.kind()), step(&next.kind())]), &t.ctx())
        .await
        .expect("submit");
    slow.wait_started(1).await;
    let stopping = tokio::spawn(runner.stop());
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!stopping.is_finished(), "stop waits for the step in flight");
    slow.release(1);
    tokio::time::timeout(Duration::from_secs(10), stopping)
        .await
        .expect("stopped")
        .expect("joined");
    let job = t.engine.job(id).await.expect("job");
    assert_eq!(job.steps[0].state, StepState::Done);
    assert_eq!(job.steps[1].state, StepState::Pending);
    assert_eq!(next.executions(), 0);

    let _runner = t.engine.start().expect("restart");
    t.wait_for_state(id, JobState::Succeeded).await;
    assert_eq!(slow.executions(), 1);
}

#[tokio::test]
async fn an_engine_runs_one_runner_at_a_time() {
    let t = TestEngine::new();
    let runner = t.engine.start().expect("runner");
    assert!(runner.is_running());
    let error = t.engine.start().expect_err("second runner");
    assert_eq!(
        tenko_core::Coded::code(&error),
        "jobs.runner.already_running"
    );
    runner.stop().await;
    let _again = t.engine.start().expect("after stop");
}

#[tokio::test]
async fn a_failing_compensation_needs_an_operator() {
    let mut t = TestEngine::new();
    let stuck =
        Scripted::new("jobs.test.vlan").compensations(vec![Err(StepError::Coded(Box::new(
            CodedError::new("connect.unifi.unreachable", 503, "controller down"),
        )))]);
    let fail = Scripted::new("jobs.test.fail")
        .outcomes(vec![Err(StepError::InvalidParams("bad".to_owned()))]);
    t.register(Arc::new(stuck.clone()));
    t.register(Arc::new(fail.clone()));
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(
            spec(vec![step(&stuck.kind()), step(&fail.kind())]),
            &t.ctx(),
        )
        .await
        .expect("submit");
    let job = t.wait_for_state(id, JobState::Failed).await;
    assert!(matches!(
        &job.steps[0].state,
        StepState::CompensationFailed { error } if error.code == "connect.unifi.unreachable"
    ));
    assert_eq!(job.error.expect("error").code, "connect.unifi.unreachable");
}
