//! The job transition table through the engine.
//!
//! `JobState::transition` allows twelve transitions. Each one is driven here with a real
//! job: submitted to a `JobEngine` on a `MemStore`, run by scripted step handlers with a
//! runner or with `drive_once`, and pushed along by cancels, manual completions,
//! observations and the mock clock. After every scenario the test checks
//!
//! - the transition log of the job: a `Job` row with the expected `from`, `action` and
//!   `state`, exactly once;
//! - the audit trail: a sealed record that names the job, is headlined `jobs.job.<action>`
//!   and lists the state change (`details.changes`, field `state`, old and new state in
//!   `snake_case`);
//! - the invariants of the whole log: gap-free sequence numbers, every job row allowed by
//!   the table, every row starting where the previous one ended, nothing after a final
//!   state.
//!
//! The second half pins down what the engine refuses: actions the table does not allow, a
//! manual completion for a step that is not waiting for a person, an unknown step index and
//! an unknown job.

use std::{net::IpAddr, sync::Arc, time::Duration};

use tenko_core::{
    Coded, CodedError, JobId, MacAddr, NodeId, ObjectRef, ObservationId, Principal, RequestCtx,
    Revision, SystemComponent, VrfId,
    audit::{AuditOutcome, AuditRecord},
    codec::from_cbor,
    serde_util::HexBytes,
};
use tenko_jobs::{
    Clock, Job, JobAction, JobError, JobState, RunnerHandle, StepError, StepOutcome, StepSpec,
    StepState, Transition, TransitionEvent,
    testing::{Scripted, TestEngine, address_seen, arp, manual, spec, step, within},
};

const MOVE: &str = "jobs.test.move";
const PATCH: &str = "jobs.test.patch";
const HAND_OVER: &str = "jobs.test.hand_over";
const TAKE_BACK: &str = "jobs.test.take_back";

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

fn bad_params() -> StepError {
    StepError::InvalidParams("the parameters were refused".to_owned())
}

fn undo_failed() -> StepError {
    StepError::Coded(Box::new(CodedError::new(
        "jobs.test.undo_failed",
        502,
        "the device did not answer",
    )))
}

/// A test engine with the given handlers registered.
fn engine_with(handlers: &[&Scripted]) -> TestEngine {
    let mut t = TestEngine::new();
    for handler in handlers {
        t.register(Arc::new((*handler).clone()));
    }
    t
}

/// A handler whose step waits for `ip` in `vrf` (from `mac`, when given) for `wait`.
fn waiting_for(
    t: &TestEngine,
    vrf: VrfId,
    ip: IpAddr,
    mac: Option<MacAddr>,
    wait: Duration,
) -> Scripted {
    let deadline = t.clock.now().checked_add(wait).expect("time");
    Scripted::new(MOVE).outcomes(vec![Ok(StepOutcome::Wait {
        condition: address_seen(vrf, ip, mac),
        deadline,
    })])
}

async fn submit(t: &TestEngine, steps: Vec<StepSpec>) -> JobId {
    within(t.engine.submit(spec(steps), &t.ctx()))
        .await
        .expect("the job is accepted")
}

async fn drive(t: &TestEngine, id: JobId) -> Job {
    within(t.engine.drive_once(id))
        .await
        .expect("the job is driven")
}

async fn read(t: &TestEngine, id: JobId) -> Job {
    within(t.engine.job(id)).await.expect("the job is read")
}

fn start(t: &TestEngine) -> RunnerHandle {
    t.engine.start().expect("the runner starts")
}

async fn stop(runner: RunnerHandle) {
    within(runner.stop()).await;
}

async fn cancel(t: &TestEngine, id: JobId) {
    cancel_as(t, id, &t.ctx()).await;
}

async fn cancel_as(t: &TestEngine, id: JobId, ctx: &RequestCtx) {
    within(t.engine.cancel(id, ctx))
        .await
        .expect("the job is cancelled");
}

async fn complete(t: &TestEngine, id: JobId, step: u16, note: Option<&str>) {
    complete_as(t, id, step, note, &t.ctx()).await;
}

async fn complete_as(t: &TestEngine, id: JobId, step: u16, note: Option<&str>, ctx: &RequestCtx) {
    within(
        t.engine
            .complete_manual(id, step, note.map(str::to_owned), ctx),
    )
    .await
    .expect("the manual task is completed");
}

/// The `snake_case` name a job state has in audit records.
fn state_name(state: JobState) -> String {
    serde_json::to_value(state)
        .expect("a state serializes")
        .as_str()
        .expect("a state is a string")
        .to_owned()
}

/// The code of the job's error.
fn error_code(job: &Job) -> Option<&str> {
    job.error.as_ref().map(|error| &*error.code)
}

/// The code of the error a failed step state carries.
fn step_error_code(state: &StepState) -> Option<&str> {
    match state {
        StepState::Failed { error } | StepState::CompensationFailed { error } => Some(&*error.code),
        _ => None,
    }
}

fn step_states(job: &Job) -> Vec<StepState> {
    job.steps
        .iter()
        .map(|record| record.state.clone())
        .collect()
}

/// The log rows that moved a step into `state`.
fn step_rows(rows: &[Transition], index: u16, state: &StepState) -> Vec<Transition> {
    rows.iter()
        .filter(|row| {
            row.event == TransitionEvent::Step
                && row.step == Some(index)
                && row.step_state.as_ref() == Some(state)
        })
        .cloned()
        .collect()
}

/// Checks what must hold for every log, whatever the scenario.
fn assert_log_is_consistent(rows: &[Transition]) {
    let first = rows.first().expect("a job has a log");
    assert_eq!(
        (first.event, first.state),
        (TransitionEvent::Submitted, JobState::Queued),
        "{rows:#?}"
    );
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(
            usize::try_from(row.seq).expect("a sequence number fits"),
            index,
            "sequence numbers are gap-free: {rows:#?}"
        );
        if row.event == TransitionEvent::Job {
            let from = row.from.expect("a job row names its source state");
            let action = row.action.expect("a job row names its action");
            assert_eq!(
                from.transition(action),
                Some(row.state),
                "{from:?} + {action:?} is not in the table: {rows:#?}"
            );
        }
    }
    for pair in rows.windows(2) {
        let (before, after) = (&pair[0], &pair[1]);
        assert!(
            !before.state.is_terminal(),
            "nothing happens after a final state: {rows:#?}"
        );
        if after.event == TransitionEvent::Job {
            assert_eq!(
                after.from,
                Some(before.state),
                "a job row starts where the row before ended: {rows:#?}"
            );
        }
    }
}

/// Asserts that the job went through `from` + `action` -> `to`: one such `Job` row in its
/// log, one audit record headlined `jobs.job.<action>` that names the job and lists the
/// state change, both from the same author at the same time. Returns the row and the
/// record for further checks.
async fn assert_transition(
    t: &TestEngine,
    id: JobId,
    from: JobState,
    action: JobAction,
    to: JobState,
) -> (Transition, AuditRecord) {
    assert_eq!(
        from.transition(action),
        Some(to),
        "{from:?} + {action:?} -> {to:?} is not in the table"
    );

    let rows = t.transitions(id).await;
    assert_log_is_consistent(&rows);
    let matching: Vec<&Transition> = rows
        .iter()
        .filter(|row| {
            row.event == TransitionEvent::Job
                && row.from == Some(from)
                && row.action == Some(action)
                && row.state == to
        })
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "expected one {from:?} + {action:?} -> {to:?} row in {rows:#?}"
    );
    let row = matching[0].clone();

    let job = ObjectRef::from(id);
    let headline = format!("jobs.job.{}", action.as_str());
    let (old, new) = (state_name(from), state_name(to));
    let audit = t.audit().await;
    let records: Vec<AuditRecord> = audit
        .iter()
        .filter(|record| {
            record.draft.objects.contains(&job)
                && record.draft.action.as_str() == headline
                && record.draft.details.changes.iter().any(|change| {
                    change.field == "state"
                        && change.old.as_deref() == Some(old.as_str())
                        && change.new.as_deref() == Some(new.as_str())
                })
        })
        .cloned()
        .collect();
    assert_eq!(
        records.len(),
        1,
        "expected one audit record `{headline}` ({old} -> {new}) in {audit:#?}"
    );
    let record = records[0].clone();
    assert_eq!(record.principal, row.by);
    assert_eq!(record.request, row.request);
    assert_eq!(record.at, row.at);
    (row, record)
}

/// A job after its scenario ran, with the two handlers of its steps.
struct Ran {
    t: TestEngine,
    id: JobId,
    job: Job,
    first: Scripted,
    second: Scripted,
}

/// Two steps; the second one fails with its own error, so the first one is rolled back
/// (its compensation follows `first`).
async fn two_steps(first: Scripted) -> Ran {
    let second = Scripted::new(PATCH).outcomes(vec![Err(bad_params())]);
    let t = engine_with(&[&first, &second]);
    let id = submit(&t, vec![step(&first.kind()), step(&second.kind())]).await;
    let job = drive(&t, id).await;
    Ran {
        t,
        id,
        job,
        first,
        second,
    }
}

/// Two steps, a runner, and a cancel while the second step runs: the second step is held
/// at its gate, the job is cancelled, then the step is let go.
async fn cancelled_mid_run() -> Ran {
    let first = Scripted::new(MOVE);
    let second = Scripted::new(PATCH).gated();
    let t = engine_with(&[&first, &second]);
    let runner = start(&t);
    let id = submit(&t, vec![step(&first.kind()), step(&second.kind())]).await;

    second.wait_started(1).await;
    let running = read(&t, id).await;
    assert_eq!(running.state, JobState::Running);
    assert_eq!(
        step_states(&running),
        vec![StepState::Done, StepState::Running]
    );

    cancel(&t, id).await;
    // The cancel is a request until the step in flight ends.
    let requested = read(&t, id).await;
    assert_eq!(requested.state, JobState::Running);
    assert!(requested.cancel_requested.is_some());

    second.release(1);
    let job = t.wait_for_state(id, JobState::Cancelled).await;
    stop(runner).await;
    Ran {
        t,
        id,
        job,
        first,
        second,
    }
}

/// A job in a final state.
async fn finished(state: JobState) -> (TestEngine, JobId) {
    match state {
        JobState::Succeeded => {
            let only = Scripted::new(MOVE);
            let t = engine_with(&[&only]);
            let id = submit(&t, vec![step(&only.kind())]).await;
            drive(&t, id).await;
            (t, id)
        }
        JobState::RolledBack => {
            let ran = two_steps(Scripted::new(MOVE)).await;
            (ran.t, ran.id)
        }
        JobState::Failed => {
            let ran = two_steps(Scripted::new(MOVE).compensations(vec![Err(undo_failed())])).await;
            (ran.t, ran.id)
        }
        JobState::Cancelled => {
            let only = Scripted::new(MOVE);
            let t = engine_with(&[&only]);
            let id = submit(&t, vec![step(&only.kind())]).await;
            cancel(&t, id).await;
            (t, id)
        }
        other => panic!("{other:?} is not a final state"),
    }
}

// ---------------------------------------------------------------------------------------
// The twelve transitions
// ---------------------------------------------------------------------------------------

/// `Queued` + `Start` -> `Running`: the runner picks up a submitted job.
#[tokio::test]
async fn queued_start() {
    let mover = Scripted::new(MOVE);
    let t = engine_with(&[&mover]);
    let id = submit(&t, vec![step(&mover.kind())]).await;

    // Nothing starts the job without a runner.
    let queued = read(&t, id).await;
    assert_eq!(queued.state, JobState::Queued);
    assert_eq!(queued.runner, None);
    assert_eq!(mover.executions(), 0);

    let runner = start(&t);
    let job = t.wait_for_state(id, JobState::Succeeded).await;
    stop(runner).await;

    assert_eq!(job.runner, Some(NodeId(1)));
    assert_eq!(mover.executions(), 1);
    let (row, _) = assert_transition(
        &t,
        id,
        JobState::Queued,
        JobAction::Start,
        JobState::Running,
    )
    .await;
    // The engine starts the job on behalf of the user who submitted it.
    assert_eq!(row.runner, Some(NodeId(1)));
    assert!(matches!(
        row.by,
        Principal::System {
            component: SystemComponent::Jobs,
            ..
        }
    ));
    assert_eq!(row.by.user(), t.ctx().principal.user());
}

/// `Queued` + `Cancel` -> `Cancelled`: a job that never started ends at once.
#[tokio::test]
async fn queued_cancel() {
    let mover = Scripted::new(MOVE);
    let t = engine_with(&[&mover]);
    let id = submit(&t, vec![step(&mover.kind())]).await;
    let ctx = t.ctx();

    cancel_as(&t, id, &ctx).await;

    let job = read(&t, id).await;
    assert_eq!(job.state, JobState::Cancelled);
    assert_eq!(error_code(&job), Some("jobs.cancelled"));
    assert_eq!(job.finished, Some(t.clock.now()));
    let requested = job
        .cancel_requested
        .clone()
        .expect("the cancel is recorded");
    assert_eq!(requested.by, ctx.principal);
    assert_eq!(step_states(&job), vec![StepState::Pending]);

    let (row, record) = assert_transition(
        &t,
        id,
        JobState::Queued,
        JobAction::Cancel,
        JobState::Cancelled,
    )
    .await;
    assert_eq!(row.by, ctx.principal);
    assert_eq!(row.request, Some(ctx.request));
    assert_eq!(record.draft.outcome, AuditOutcome::Success);

    // A cancelled job is never run.
    let driven = drive(&t, id).await;
    assert_eq!(driven.state, JobState::Cancelled);
    assert_eq!(mover.executions(), 0);
}

/// `Running` + `Wait` -> `Waiting`: a manual step holds the job.
#[tokio::test]
async fn running_wait() {
    let t = engine_with(&[]);
    let id = submit(&t, vec![manual(HAND_OVER, None, None)]).await;

    let job = drive(&t, id).await;

    assert_eq!(job.state, JobState::Waiting);
    assert_eq!(job.finished, None);
    let StepState::WaitingForManual { task } = &job.steps[0].state else {
        panic!("the manual step waits for a person: {job:#?}");
    };
    assert_eq!(task.instruction.as_str(), HAND_OVER);
    assert_eq!(task.args["host"], "printer-1");
    assert_eq!(task.undo, None);
    assert_eq!(job.steps[0].attempts, 1);
    assert_transition(
        &t,
        id,
        JobState::Running,
        JobAction::Wait,
        JobState::Waiting,
    )
    .await;
}

/// `Running` + `Complete` -> `Succeeded`: the last step finishes.
#[tokio::test]
async fn running_complete() {
    let (first, second) = (Scripted::new(MOVE), Scripted::new(PATCH));
    let t = engine_with(&[&first, &second]);
    let id = submit(&t, vec![step(&first.kind()), step(&second.kind())]).await;

    let job = drive(&t, id).await;

    assert_eq!(job.state, JobState::Succeeded);
    assert_eq!(job.error, None);
    assert_eq!(job.finished, Some(t.clock.now()));
    assert_eq!(step_states(&job), vec![StepState::Done, StepState::Done]);
    for record in &job.steps {
        assert_eq!(record.output, Some(HexBytes(b"out-1".to_vec())));
    }
    assert_eq!((first.compensated(), second.compensated()), (0, 0));
    let (row, record) = assert_transition(
        &t,
        id,
        JobState::Running,
        JobAction::Complete,
        JobState::Succeeded,
    )
    .await;
    assert_eq!(record.draft.outcome, AuditOutcome::Success);
    // Completing is the last thing that happens.
    let rows = t.transitions(id).await;
    assert_eq!(rows.last(), Some(&row));
}

/// `Running` + `RollBack` -> `RollingBack`: a step fails with its own error.
#[tokio::test]
async fn running_roll_back() {
    let ran = two_steps(Scripted::new(MOVE)).await;

    assert_eq!(ran.job.state, JobState::RolledBack);
    assert_eq!(error_code(&ran.job), Some("jobs.step.invalid_params"));
    // The step that was done is compensated with its output; the step that failed on its
    // own had no effect and is left alone.
    assert_eq!(ran.first.compensated(), 1);
    assert_eq!(
        ran.first.compensated_outputs(),
        vec![Some(b"out-1".to_vec())]
    );
    assert_eq!(ran.second.executions(), 1);
    assert_eq!(ran.second.compensated(), 0);
    let states = step_states(&ran.job);
    assert_eq!(states[0], StepState::Compensated);
    assert_eq!(
        step_error_code(&states[1]),
        Some("jobs.step.invalid_params")
    );

    let (_, record) = assert_transition(
        &ran.t,
        ran.id,
        JobState::Running,
        JobAction::RollBack,
        JobState::RollingBack,
    )
    .await;
    assert_eq!(
        record.draft.outcome,
        AuditOutcome::Failed {
            code: "jobs.step.invalid_params".into()
        }
    );
}

/// `RollingBack` + `FinishRollback` -> `RolledBack`: every compensation is done.
#[tokio::test]
async fn rolling_back_finish_rollback() {
    let ran = two_steps(Scripted::new(MOVE)).await;

    assert_eq!(ran.job.state, JobState::RolledBack);
    assert_eq!(ran.job.finished, Some(ran.t.clock.now()));
    assert_eq!(ran.job.steps[0].state, StepState::Compensated);
    let (row, _) = assert_transition(
        &ran.t,
        ran.id,
        JobState::RollingBack,
        JobAction::FinishRollback,
        JobState::RolledBack,
    )
    .await;
    // Finishing the rollback is the last thing that happens, and it follows the
    // compensation of the step.
    let rows = ran.t.transitions(ran.id).await;
    assert_eq!(rows.last(), Some(&row));
    let compensated = step_rows(&rows, 0, &StepState::Compensated);
    assert_eq!(compensated.len(), 1);
    assert!(compensated[0].seq < row.seq);
}

/// `Running` + `Cancel` -> `RollingBack`: a cancel during a step takes effect when the step ends.
#[tokio::test]
async fn running_cancel() {
    let ran = cancelled_mid_run().await;
    let ctx = ran.t.ctx();

    assert_eq!(ran.job.state, JobState::Cancelled);
    assert_eq!(error_code(&ran.job), Some("jobs.cancelled"));
    assert_eq!(
        ran.job.cancel_requested.as_ref().map(|stamp| &stamp.by),
        Some(&ctx.principal)
    );
    // The step in flight was not interrupted: it finished, and its effects are undone
    // with the rest, in reverse order.
    assert_eq!(ran.second.executions(), 1);
    assert_eq!(ran.second.compensated(), 1);
    assert_eq!(
        ran.second.compensated_outputs(),
        vec![Some(b"out-1".to_vec())]
    );
    assert_eq!(ran.first.compensated(), 1);
    assert_eq!(
        step_states(&ran.job),
        vec![StepState::Compensated, StepState::Compensated]
    );
    let rows = ran.t.transitions(ran.id).await;
    let undo_second = step_rows(&rows, 1, &StepState::Compensating);
    let undo_first = step_rows(&rows, 0, &StepState::Compensating);
    assert_eq!((undo_second.len(), undo_first.len()), (1, 1));
    assert!(undo_second[0].seq < undo_first[0].seq);

    let (row, record) = assert_transition(
        &ran.t,
        ran.id,
        JobState::Running,
        JobAction::Cancel,
        JobState::RollingBack,
    )
    .await;
    assert_eq!(record.draft.outcome, AuditOutcome::Success);
    let requests: Vec<&Transition> = rows
        .iter()
        .filter(|row| row.event == TransitionEvent::CancelRequested)
        .collect();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].by, ctx.principal);
    assert!(requests[0].seq < row.seq);
}

/// `RollingBack` + `FinishCancel` -> `Cancelled`: a rollback that a cancel started ends in
/// `cancelled`, not `rolled_back`.
#[tokio::test]
async fn rolling_back_finish_cancel() {
    let ran = cancelled_mid_run().await;

    assert_eq!(ran.job.state, JobState::Cancelled);
    assert_eq!(ran.job.finished, Some(ran.t.clock.now()));
    let (row, _) = assert_transition(
        &ran.t,
        ran.id,
        JobState::RollingBack,
        JobAction::FinishCancel,
        JobState::Cancelled,
    )
    .await;
    let rows = ran.t.transitions(ran.id).await;
    assert_eq!(rows.last(), Some(&row));
    // The rollback itself did not end in `rolled_back`.
    assert!(
        rows.iter()
            .all(|row| row.action != Some(JobAction::FinishRollback))
    );
}

/// `Waiting` + `Resume` -> `Running`: a person completes a manual task.
#[tokio::test]
async fn waiting_resume_after_manual_completion() {
    let mover = Scripted::new(MOVE);
    let t = engine_with(&[&mover]);
    let runner = start(&t);
    let id = submit(&t, vec![manual(HAND_OVER, None, None), step(&mover.kind())]).await;

    t.wait_for_state(id, JobState::Waiting).await;
    assert_eq!(mover.executions(), 0, "the next step waits for the person");
    let ctx = t.ctx();
    complete_as(&t, id, 0, Some("moved the cable"), &ctx).await;
    let job = t.wait_for_state(id, JobState::Succeeded).await;
    stop(runner).await;

    assert_eq!(step_states(&job), vec![StepState::Done, StepState::Done]);
    assert_eq!(mover.executions(), 1);
    let (row, record) = assert_transition(
        &t,
        id,
        JobState::Waiting,
        JobAction::Resume,
        JobState::Running,
    )
    .await;
    assert_eq!(row.by, ctx.principal);
    assert_eq!(row.request, Some(ctx.request));
    // The note is kept with the step that was completed, and in the audit record.
    let rows = t.transitions(id).await;
    let done = step_rows(&rows, 0, &StepState::Done);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].note.as_deref(), Some("moved the cable"));
    assert_eq!(
        record.draft.details.context.get("note").map(String::as_str),
        Some("moved the cable")
    );
}

/// `Waiting` + `Resume` -> `Running`: an observation satisfies the condition of a waiting step.
#[tokio::test]
async fn waiting_resume_after_observation() {
    let vrf = VrfId::generate();
    let ip: IpAddr = "192.0.2.20".parse().expect("ip");
    let other_ip: IpAddr = "192.0.2.21".parse().expect("ip");
    let mac: MacAddr = "00:00:5e:00:53:20".parse().expect("mac");
    let other_mac: MacAddr = "00:00:5e:00:53:21".parse().expect("mac");

    let mut t = TestEngine::new();
    let now = t.clock.now();
    let waiter = waiting_for(&t, vrf, ip, Some(mac), Duration::from_secs(60));
    t.register(Arc::new(waiter.clone()));
    let id = submit(&t, vec![step(&waiter.kind())]).await;

    let waiting = drive(&t, id).await;
    assert_eq!(waiting.state, JobState::Waiting);
    assert!(matches!(
        waiting.steps[0].state,
        StepState::WaitingForObservation { .. }
    ));
    assert_eq!(t.engine.waiting_for_observations(), 1);

    // Observations that do not satisfy the condition leave the job waiting.
    for miss in [
        arp(vrf, ip, Some(other_mac), now),
        arp(VrfId::generate(), ip, Some(mac), now),
        arp(vrf, other_ip, Some(mac), now),
        arp(vrf, ip, None, now),
    ] {
        within(t.engine.on_observation(&miss)).await;
        assert_eq!(read(&t, id).await.state, JobState::Waiting, "{miss:?}");
    }

    let seen = arp(vrf, ip, Some(mac), now);
    within(t.engine.on_observation(&seen)).await;

    let resumed = read(&t, id).await;
    assert_eq!(resumed.state, JobState::Running);
    assert_eq!(resumed.steps[0].state, StepState::Done);
    let output = resumed.steps[0]
        .output
        .clone()
        .expect("the observation is the output");
    assert_eq!(
        from_cbor::<ObservationId>(&output.0).expect("an id"),
        seen.id
    );
    assert_eq!(t.engine.waiting_for_observations(), 0);

    // The step is done, not run again.
    let job = drive(&t, id).await;
    assert_eq!(job.state, JobState::Succeeded);
    assert_eq!(waiter.executions(), 1);

    let (row, _) = assert_transition(
        &t,
        id,
        JobState::Waiting,
        JobAction::Resume,
        JobState::Running,
    )
    .await;
    assert_eq!(row.by, Principal::system(SystemComponent::Jobs));
    let rows = t.transitions(id).await;
    let done = step_rows(&rows, 0, &StepState::Done);
    assert_eq!(done.len(), 1);
    assert!(
        done[0]
            .note
            .as_deref()
            .is_some_and(|note| note.contains(&seen.id.to_string()))
    );
}

/// `Waiting` + `RollBack` -> `RollingBack`: the deadline of a waiting step passes.
#[tokio::test]
async fn waiting_roll_back_at_the_deadline() {
    let vrf = VrfId::generate();
    let ip: IpAddr = "198.51.100.30".parse().expect("ip");
    let mut t = TestEngine::new();
    let waiter = waiting_for(&t, vrf, ip, None, Duration::from_secs(60));
    t.register(Arc::new(waiter.clone()));
    let runner = start(&t);
    let id = submit(&t, vec![step(&waiter.kind())]).await;

    t.wait_for_state(id, JobState::Waiting).await;
    // One second before the deadline the job is still waiting.
    t.clock.advance(Duration::from_secs(59));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(read(&t, id).await.state, JobState::Waiting);

    t.clock.advance(Duration::from_secs(2));
    let job = t.wait_for_state(id, JobState::RolledBack).await;
    stop(runner).await;

    assert_eq!(error_code(&job), Some("jobs.step.deadline_passed"));
    // The step may have had effects before it began to wait: it is compensated, without
    // an output.
    assert_eq!(job.steps[0].state, StepState::Compensated);
    assert_eq!(waiter.executions(), 1);
    assert_eq!(waiter.compensated_outputs(), vec![None]);
    let (_, record) = assert_transition(
        &t,
        id,
        JobState::Waiting,
        JobAction::RollBack,
        JobState::RollingBack,
    )
    .await;
    assert_eq!(
        record.draft.outcome,
        AuditOutcome::Failed {
            code: "jobs.step.deadline_passed".into()
        }
    );
    assert_transition(
        &t,
        id,
        JobState::RollingBack,
        JobAction::FinishRollback,
        JobState::RolledBack,
    )
    .await;
}

/// `Waiting` + `Cancel` -> `RollingBack`: a person cancels a job that waits for a manual task.
#[tokio::test]
async fn waiting_cancel() {
    let t = engine_with(&[]);
    let runner = start(&t);
    let id = submit(&t, vec![manual(HAND_OVER, None, None)]).await;

    t.wait_for_state(id, JobState::Waiting).await;
    cancel(&t, id).await;
    let job = t.wait_for_state(id, JobState::Cancelled).await;
    stop(runner).await;

    assert_eq!(error_code(&job), Some("jobs.cancelled"));
    // A task that names no undo message leaves nothing to undo by hand: the step is
    // compensated by the engine.
    assert_eq!(job.steps[0].state, StepState::Compensated);
    let ctx = t.ctx();
    let (row, record) = assert_transition(
        &t,
        id,
        JobState::Waiting,
        JobAction::Cancel,
        JobState::RollingBack,
    )
    .await;
    assert_eq!(record.draft.outcome, AuditOutcome::Success);
    let rows = t.transitions(id).await;
    let request = rows
        .iter()
        .find(|row| row.event == TransitionEvent::CancelRequested)
        .expect("the cancel request is logged");
    assert_eq!(request.by, ctx.principal);
    assert!(request.seq < row.seq);
    assert_transition(
        &t,
        id,
        JobState::RollingBack,
        JobAction::FinishCancel,
        JobState::Cancelled,
    )
    .await;
}

/// `RollingBack` + `Fail` -> `Failed`: a compensation fails.
#[tokio::test]
async fn rolling_back_fail() {
    let ran = two_steps(Scripted::new(MOVE).compensations(vec![Err(undo_failed())])).await;

    assert_eq!(ran.job.state, JobState::Failed);
    assert_eq!(ran.job.finished, Some(ran.t.clock.now()));
    // The compensation error replaces the error that started the rollback.
    assert_eq!(error_code(&ran.job), Some("jobs.test.undo_failed"));
    assert_eq!((ran.first.executions(), ran.first.compensated()), (1, 1));
    assert_eq!((ran.second.executions(), ran.second.compensated()), (1, 0));
    let states = step_states(&ran.job);
    assert_eq!(step_error_code(&states[0]), Some("jobs.test.undo_failed"));
    assert!(matches!(states[0], StepState::CompensationFailed { .. }));
    assert_eq!(
        step_error_code(&states[1]),
        Some("jobs.step.invalid_params")
    );
    assert!(matches!(states[1], StepState::Failed { .. }));

    let (row, record) = assert_transition(
        &ran.t,
        ran.id,
        JobState::RollingBack,
        JobAction::Fail,
        JobState::Failed,
    )
    .await;
    assert_eq!(
        record.draft.outcome,
        AuditOutcome::Failed {
            code: "jobs.test.undo_failed".into()
        }
    );
    let rows = ran.t.transitions(ran.id).await;
    assert_eq!(rows.last(), Some(&row));
    // The rollback did not end in `rolled_back` or `cancelled`.
    assert!(rows.iter().all(|row| !matches!(
        row.action,
        Some(JobAction::FinishRollback | JobAction::FinishCancel)
    )));
}

// ---------------------------------------------------------------------------------------
// Manual undo tasks: the rollback waits for a person
// ---------------------------------------------------------------------------------------

/// A manual task with an `undo` message becomes a manual undo task when the job rolls
/// back; the job stays `rolling_back` until a person completes it, and then finishes the
/// rollback.
#[tokio::test]
async fn manual_undo_task_finishes_a_rollback() {
    let failing = Scripted::new(PATCH).outcomes(vec![Err(bad_params())]);
    let t = engine_with(&[&failing]);
    let id = submit(
        &t,
        vec![
            manual(HAND_OVER, Some(TAKE_BACK), None),
            step(&failing.kind()),
        ],
    )
    .await;

    assert_eq!(drive(&t, id).await.state, JobState::Waiting);
    complete(&t, id, 0, Some("done")).await;
    let parked = drive(&t, id).await;

    // The second step failed; the first one now asks for an undo by hand.
    assert_eq!(parked.state, JobState::RollingBack);
    let StepState::WaitingForManual { task } = &parked.steps[0].state else {
        panic!("the undo task waits for a person: {parked:#?}");
    };
    assert_eq!(task.instruction.as_str(), TAKE_BACK);
    assert_eq!(task.args["host"], "printer-1");
    // A job that is rolling back cannot be cancelled.
    let refused = within(t.engine.cancel(id, &t.ctx())).await;
    assert_eq!(
        refused,
        Err(JobError::InvalidTransition {
            from: JobState::RollingBack,
            action: "cancel"
        })
    );

    complete(&t, id, 0, Some("undone")).await;
    let job = drive(&t, id).await;

    assert_eq!(job.state, JobState::RolledBack);
    assert_eq!(error_code(&job), Some("jobs.step.invalid_params"));
    assert_eq!(job.steps[0].state, StepState::Compensated);
    assert_transition(
        &t,
        id,
        JobState::Running,
        JobAction::RollBack,
        JobState::RollingBack,
    )
    .await;
    assert_transition(
        &t,
        id,
        JobState::RollingBack,
        JobAction::FinishRollback,
        JobState::RolledBack,
    )
    .await;
}

/// The same for a cancel: the undo task of a cancelled job ends it in `cancelled`.
#[tokio::test]
async fn manual_undo_task_finishes_a_cancel() {
    let t = engine_with(&[]);
    let id = submit(&t, vec![manual(HAND_OVER, Some(TAKE_BACK), None)]).await;
    assert_eq!(drive(&t, id).await.state, JobState::Waiting);

    cancel(&t, id).await;
    let parked = drive(&t, id).await;

    assert_eq!(parked.state, JobState::RollingBack);
    let StepState::WaitingForManual { task } = &parked.steps[0].state else {
        panic!("the undo task waits for a person: {parked:#?}");
    };
    assert_eq!(task.instruction.as_str(), TAKE_BACK);
    assert_transition(
        &t,
        id,
        JobState::Waiting,
        JobAction::Cancel,
        JobState::RollingBack,
    )
    .await;

    complete(&t, id, 0, None).await;
    let job = drive(&t, id).await;

    assert_eq!(job.state, JobState::Cancelled);
    assert_eq!(error_code(&job), Some("jobs.cancelled"));
    assert_eq!(job.steps[0].state, StepState::Compensated);
    assert_transition(
        &t,
        id,
        JobState::RollingBack,
        JobAction::FinishCancel,
        JobState::Cancelled,
    )
    .await;
}

// ---------------------------------------------------------------------------------------
// What the engine refuses
// ---------------------------------------------------------------------------------------

/// A final job accepts neither a cancel nor a manual completion, and a refusal writes
/// nothing.
#[tokio::test]
async fn final_jobs_refuse_cancel_and_completion() {
    for state in [
        JobState::Succeeded,
        JobState::Failed,
        JobState::RolledBack,
        JobState::Cancelled,
    ] {
        let (t, id) = finished(state).await;
        assert_eq!(read(&t, id).await.state, state);
        let revision = t.revision();
        let log = t.transitions(id).await;

        let refused = within(t.engine.cancel(id, &t.ctx()))
            .await
            .expect_err("a final job cannot be cancelled");
        assert_eq!(
            refused,
            JobError::InvalidTransition {
                from: state,
                action: "cancel"
            }
        );
        assert_eq!(refused.code(), "jobs.invalid_transition");
        assert_eq!(refused.http_status(), 409);
        assert_eq!(refused.params()["from"], format!("{state:?}"));

        let refused = within(t.engine.complete_manual(id, 0, None, &t.ctx()))
            .await
            .expect_err("a final job has no manual task to complete");
        assert_eq!(
            refused,
            JobError::InvalidTransition {
                from: state,
                action: "complete_manual"
            }
        );

        assert_eq!(read(&t, id).await.state, state);
        assert_eq!(
            t.revision(),
            revision,
            "{state:?}: a refusal writes nothing"
        );
        assert_eq!(t.transitions(id).await, log);
    }
}

/// A manual completion needs a step that waits for a person.
#[tokio::test]
async fn manual_completion_needs_a_task_waiting_for_a_person() {
    let vrf = VrfId::generate();
    let ip: IpAddr = "203.0.113.40".parse().expect("ip");
    let mut t = TestEngine::new();
    let waiter = waiting_for(&t, vrf, ip, None, Duration::from_secs(600));
    t.register(Arc::new(waiter.clone()));
    let refused = |from: JobState| {
        Err::<(), _>(JobError::InvalidTransition {
            from,
            action: "complete_manual",
        })
    };

    // The step has not started.
    let queued = submit(&t, vec![step(&waiter.kind())]).await;
    let result = within(t.engine.complete_manual(queued, 0, None, &t.ctx())).await;
    assert_eq!(result, refused(JobState::Queued));
    assert_eq!(read(&t, queued).await.state, JobState::Queued);

    // The step waits for an observation, not for a person.
    let waiting = submit(&t, vec![step(&waiter.kind())]).await;
    assert_eq!(drive(&t, waiting).await.state, JobState::Waiting);
    let result = within(t.engine.complete_manual(waiting, 0, None, &t.ctx())).await;
    assert_eq!(result, refused(JobState::Waiting));
    let job = read(&t, waiting).await;
    assert_eq!(job.state, JobState::Waiting);
    assert!(matches!(
        job.steps[0].state,
        StepState::WaitingForObservation { .. }
    ));
}

/// The step is running, not waiting.
#[tokio::test]
async fn manual_completion_of_a_running_step_is_refused() {
    let gated = Scripted::new(MOVE).gated();
    let t = engine_with(&[&gated]);
    let runner = start(&t);
    let id = submit(&t, vec![step(&gated.kind())]).await;

    gated.wait_started(1).await;
    let result = within(t.engine.complete_manual(id, 0, None, &t.ctx())).await;
    assert_eq!(
        result,
        Err(JobError::InvalidTransition {
            from: JobState::Running,
            action: "complete_manual"
        })
    );

    gated.release(1);
    t.wait_for_state(id, JobState::Succeeded).await;
    stop(runner).await;
}

/// An index past the last step names no step.
#[tokio::test]
async fn manual_completion_past_the_last_step_is_not_found() {
    let t = engine_with(&[]);
    let id = submit(&t, vec![manual(HAND_OVER, None, None)]).await;
    assert_eq!(drive(&t, id).await.state, JobState::Waiting);
    let revision = t.revision();

    for index in [1, 2, u16::MAX] {
        let refused = within(t.engine.complete_manual(id, index, None, &t.ctx()))
            .await
            .expect_err("there is no such step");
        assert!(
            matches!(refused, JobError::Step(StepError::Coded(_))),
            "{refused:?}"
        );
        assert_eq!(refused.to_coded_error().code, "jobs.step.not_found");
        assert_eq!(refused.http_status(), 404);
        assert_eq!(refused.to_coded_error().params["step"], index.to_string());
    }
    assert_eq!(t.revision(), revision);
    assert_eq!(read(&t, id).await.state, JobState::Waiting);
}

/// A note is limited in size; a long one is refused at once.
#[tokio::test]
async fn long_notes_are_refused() {
    let t = engine_with(&[]);
    let id = submit(&t, vec![manual(HAND_OVER, None, None)]).await;
    assert_eq!(drive(&t, id).await.state, JobState::Waiting);

    let note = "x".repeat(tenko_jobs::MAX_NOTE_BYTES + 1);
    let refused = within(t.engine.complete_manual(id, 0, Some(note), &t.ctx()))
        .await
        .expect_err("the note is too long");
    assert_eq!(refused.to_coded_error().code, "jobs.note.too_long");
    assert_eq!(refused.http_status(), 400);
    assert_eq!(read(&t, id).await.state, JobState::Waiting);

    let note = "x".repeat(tenko_jobs::MAX_NOTE_BYTES);
    complete(&t, id, 0, Some(&note)).await;
    assert_eq!(drive(&t, id).await.state, JobState::Succeeded);
}

/// Cancelling a running or waiting job twice is harmless: one request is recorded.
#[tokio::test]
async fn cancel_twice_is_harmless() {
    let t = engine_with(&[]);
    let id = submit(&t, vec![manual(HAND_OVER, None, None)]).await;
    assert_eq!(drive(&t, id).await.state, JobState::Waiting);

    cancel(&t, id).await;
    let revision = t.revision();
    cancel(&t, id).await;
    assert_eq!(t.revision(), revision, "the second cancel writes nothing");

    let job = read(&t, id).await;
    assert_eq!(
        job.state,
        JobState::Waiting,
        "a request, until the runner acts"
    );
    assert!(job.cancel_requested.is_some());
    let rows = t.transitions(id).await;
    let requests = rows
        .iter()
        .filter(|row| row.event == TransitionEvent::CancelRequested)
        .count();
    assert_eq!(requests, 1);

    let job = drive(&t, id).await;
    assert_eq!(job.state, JobState::Cancelled);
    assert_log_is_consistent(&t.transitions(id).await);

    // Once the job is cancelled there is nothing left to cancel.
    let refused = within(t.engine.cancel(id, &t.ctx())).await;
    assert_eq!(
        refused,
        Err(JobError::InvalidTransition {
            from: JobState::Cancelled,
            action: "cancel"
        })
    );
}

/// An unknown job is not found, whatever is asked of it.
#[tokio::test]
async fn unknown_jobs_are_not_found() {
    let t = engine_with(&[]);
    let id = JobId::generate();
    let missing = JobError::NotFound(id);

    assert_eq!(
        within(t.engine.cancel(id, &t.ctx())).await,
        Err(missing.clone())
    );
    assert_eq!(
        within(t.engine.complete_manual(id, 0, None, &t.ctx())).await,
        Err(missing.clone())
    );
    assert_eq!(within(t.engine.job(id)).await, Err(missing.clone()));
    assert_eq!(
        within(t.engine.detail(id, None)).await.map(|_| ()),
        Err(missing.clone())
    );
    assert_eq!(within(t.engine.drive_once(id)).await, Err(missing.clone()));

    assert_eq!(missing.code(), "jobs.not_found");
    assert_eq!(missing.http_status(), 404);
    assert_eq!(missing.params()["job"], id.to_string());
    assert_eq!(t.revision(), Revision::ZERO, "nothing was written");
}
