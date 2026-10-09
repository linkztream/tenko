//! Engine scenarios: preview, inline jobs, staged writes, rollback, manual undo tasks,
//! deadlines and observation wake-up.

use std::{sync::Arc, time::Duration};

use tenko_core::{
    CodedError, IdempotencyKey, JobId, MessageKey, ObservationId, PrefixId, Revision, TableName,
    VrfId,
    audit::{AuditAction, AuditDraft, AuditOutcome},
    codec::from_cbor,
};
use tenko_jobs::{
    Clock, JobError, JobQuery, JobState, ObservationCondition, ObservedPredicate, StagedWrite,
    StepContext, StepError, StepOutcome, StepState, TransitionEvent,
    testing::{Scripted, TestEngine, address_seen, arp, lease, manual, spec, step},
};
use tenko_store::{ReadConsistency, Store, WriteBatch};

const HOSTS: TableName = TableName::from_static("ipam.test_hosts");

fn coded(code: &'static str, status: u16) -> StepError {
    StepError::Coded(Box::new(CodedError::new(code, status, code)))
}

/// A staged write of one host row with its audit draft.
fn host_write(cx: &StepContext) -> StagedWrite {
    let mut batch = WriteBatch::new(cx.request.principal.clone(), cx.request.now);
    batch
        .put(HOSTS, cx.job.0.as_bytes().to_vec(), vec![0xF6])
        .audit(AuditDraft::success(
            AuditAction::from_static("ipam.host.update"),
            vec![],
        ));
    batch.into()
}

/// A staged write whose precondition fails on the first attempt only.
fn conflicting_once(cx: &StepContext) -> StagedWrite {
    let mut write = host_write(cx);
    if cx.attempt == 1 {
        let mut batch = WriteBatch::new(cx.request.principal.clone(), cx.request.now);
        batch.expect_version(HOSTS, b"elsewhere".to_vec(), Some(Revision(999)));
        write.preconditions = batch.preconditions;
    }
    write
}

/// A staged write whose precondition always fails.
fn always_conflicting(cx: &StepContext) -> StagedWrite {
    let mut batch = WriteBatch::new(cx.request.principal.clone(), cx.request.now);
    batch.expect_version(HOSTS, b"elsewhere".to_vec(), Some(Revision(999)));
    batch.put(HOSTS, cx.job.0.as_bytes().to_vec(), vec![0xF6]);
    batch.into()
}

async fn host_row(t: &TestEngine, job: JobId) -> Option<Revision> {
    let view = t.store.read(ReadConsistency::Local).await.expect("view");
    view.get(&HOSTS, job.0.as_bytes())
        .expect("read")
        .map(|value| value.revision)
}

fn engine_with(handlers: &[&Scripted]) -> TestEngine {
    let mut t = TestEngine::new();
    for handler in handlers {
        t.register(Arc::new((*handler).clone()));
    }
    t
}

// --- Preview -----------------------------------------------------------------------------

#[tokio::test]
async fn preview_runs_every_step_against_a_read_view_without_writing() {
    let a = Scripted::new("jobs.test.a");
    let b = Scripted::new("jobs.test.b");
    let t = engine_with(&[&a, &b]);
    let before = t.revision();
    let preview = t
        .engine
        .preview(
            &spec(vec![
                step(&a.kind()),
                manual("jobs.test.reserve", Some("jobs.test.unreserve"), None),
                step(&b.kind()),
            ]),
            &t.ctx(),
        )
        .await
        .expect("preview");
    assert_eq!(preview.steps.len(), 3);
    assert_eq!(preview.steps[0].args["kind"], "jobs.test.a");
    let task = preview.steps[1].manual.as_ref().expect("manual task");
    assert_eq!(task.instruction.as_str(), "jobs.test.reserve");
    assert_eq!(preview.steps[2].args["kind"], "jobs.test.b");
    assert_eq!(t.revision(), before, "a preview writes nothing");
    assert_eq!(a.executions() + b.executions(), 0);
}

#[tokio::test]
async fn preview_reports_unknown_kinds_and_step_errors() {
    let failing = Scripted::new("jobs.test.bad")
        .preview_error(StepError::InvalidParams("no such prefix".to_owned()));
    let t = engine_with(&[&failing]);
    let unknown = tenko_jobs::StepKind::from_static("jobs.test.unknown");
    let error = t
        .engine
        .preview(&spec(vec![step(&unknown)]), &t.ctx())
        .await
        .expect_err("unknown kind");
    assert_eq!(error, JobError::UnknownStepKind(unknown));
    let error = t
        .engine
        .preview(&spec(vec![step(&failing.kind())]), &t.ctx())
        .await
        .expect_err("invalid params");
    assert!(matches!(error, JobError::Step(StepError::InvalidParams(_))));
    // A job whose preview fails is not accepted.
    let error = t
        .engine
        .submit(spec(vec![step(&failing.kind())]), &t.ctx())
        .await
        .expect_err("refused");
    assert!(matches!(error, JobError::Step(_)));
}

#[tokio::test]
async fn submission_stores_the_preview_and_replays_an_idempotency_key() {
    let a = Scripted::new("jobs.test.a");
    let t = engine_with(&[&a]);
    let ctx = t
        .ctx()
        .with_idempotency(IdempotencyKey::new("move-printer-1").expect("key"));
    let first = t
        .engine
        .submit(spec(vec![step(&a.kind())]), &ctx)
        .await
        .expect("submit");
    let second = t
        .engine
        .submit(spec(vec![step(&a.kind())]), &ctx)
        .await
        .expect("replay");
    assert_eq!(first, second);
    let detail = t.engine.detail(first, None).await.expect("detail");
    assert_eq!(detail.job.state, JobState::Queued);
    assert_eq!(detail.preview.expect("preview").steps.len(), 1);
    assert_eq!(detail.transitions.len(), 1);
    assert_eq!(detail.transitions[0].event, TransitionEvent::Submitted);
    let page = t.engine.list(&JobQuery::default()).await.expect("list");
    assert_eq!(page.items.len(), 1);
}

// --- Inline jobs (decision Q4) -----------------------------------------------------------

#[tokio::test]
async fn an_inline_job_commits_change_job_and_audit_in_one_batch() {
    let write = Scripted::new("jobs.test.write").staging(host_write);
    let t = engine_with(&[&write]);
    let before = t.revision();
    let job = t
        .engine
        .run_inline(spec(vec![step(&write.kind())]), &t.ctx())
        .await
        .expect("inline");
    assert_eq!(job.state, JobState::Succeeded);
    assert_eq!(t.revision(), Revision(before.0 + 1), "one batch");
    assert_eq!(job.revision, t.revision());
    assert_eq!(host_row(&t, job.id).await, Some(job.revision));
    let audit = t.audit().await;
    let in_batch: Vec<_> = audit
        .iter()
        .filter(|record| record.revision == job.revision)
        .map(|record| record.draft.action.as_str().to_owned())
        .collect();
    assert!(
        in_batch.contains(&"jobs.job.complete".to_owned()),
        "{in_batch:?}"
    );
    assert!(
        in_batch.contains(&"ipam.host.update".to_owned()),
        "{in_batch:?}"
    );
    let events: Vec<_> = t
        .transitions(job.id)
        .await
        .into_iter()
        .map(|row| (row.event, row.state))
        .collect();
    assert_eq!(
        events,
        vec![
            (TransitionEvent::Submitted, JobState::Queued),
            (TransitionEvent::Job, JobState::Running),
            (TransitionEvent::Step, JobState::Running),
            (TransitionEvent::Step, JobState::Running),
            (TransitionEvent::Job, JobState::Succeeded),
        ]
    );
}

#[tokio::test]
async fn an_inline_job_with_conflicting_staged_writes_records_nothing() {
    let write = Scripted::new("jobs.test.write").staging(always_conflicting);
    let t = engine_with(&[&write]);
    let before = t.revision();
    let error = t
        .engine
        .run_inline(spec(vec![step(&write.kind())]), &t.ctx())
        .await
        .expect_err("conflict");
    assert!(matches!(
        error,
        JobError::Store(tenko_store::StoreError::PreconditionFailed(_))
    ));
    assert_eq!(t.revision(), before);
    let page = t.engine.list(&JobQuery::default()).await.expect("list");
    assert_eq!(page.items.len(), 0, "nothing is recorded");
}

#[tokio::test]
async fn a_failed_inline_job_is_recorded_and_its_error_returned() {
    let overlap = Scripted::new("jobs.test.write")
        .staging(host_write)
        .outcomes(vec![Err(coded("ipam.prefix.overlap", 409))]);
    let t = engine_with(&[&overlap]);
    let error = t
        .engine
        .run_inline(spec(vec![step(&overlap.kind())]), &t.ctx())
        .await
        .expect_err("fails");
    assert_eq!(
        tenko_core::Coded::to_coded_error(&error).code,
        "ipam.prefix.overlap"
    );
    assert_eq!(tenko_core::Coded::http_status(&error), 409);
    let page = t.engine.list(&JobQuery::default()).await.expect("list");
    assert_eq!(page.items.len(), 1);
    let job = &page.items[0];
    assert_eq!(job.state, JobState::RolledBack);
    assert_eq!(
        job.error.as_ref().expect("error").code,
        "ipam.prefix.overlap"
    );
    assert_eq!(
        host_row(&t, job.id).await,
        None,
        "staged writes of a failed step are dropped"
    );
    let audit = t.audit().await;
    assert!(audit.iter().any(|record| {
        record.draft.outcome
            == AuditOutcome::Failed {
                code: "ipam.prefix.overlap".into(),
            }
    }));
}

#[tokio::test]
async fn an_inline_job_that_needs_a_person_continues_in_the_runner() {
    let t = TestEngine::new();
    let _runner = t.engine.start().expect("runner");
    let job = t
        .engine
        .run_inline(
            spec(vec![manual("jobs.test.reconfigure", None, None)]),
            &t.ctx(),
        )
        .await
        .expect("inline");
    assert_eq!(job.state, JobState::Waiting);
    t.engine
        .complete_manual(job.id, 0, Some("reconfigured".to_owned()), &t.ctx())
        .await
        .expect("complete");
    let job = t.wait_for_state(job.id, JobState::Succeeded).await;
    assert_eq!(job.runner, Some(t.engine.config().node));
}

#[tokio::test]
async fn inline_jobs_have_exactly_one_step() {
    let a = Scripted::new("jobs.test.a");
    let t = engine_with(&[&a]);
    let error = t
        .engine
        .run_inline(spec(vec![step(&a.kind()), step(&a.kind())]), &t.ctx())
        .await
        .expect_err("two steps");
    assert_eq!(
        tenko_core::Coded::to_coded_error(&error).code,
        "jobs.spec.inline_one_step"
    );
}

#[tokio::test]
async fn an_inline_replay_returns_the_first_job() {
    let write = Scripted::new("jobs.test.write").staging(host_write);
    let t = engine_with(&[&write]);
    let ctx = t
        .ctx()
        .with_idempotency(IdempotencyKey::new("edit-1").expect("key"));
    let first = t
        .engine
        .run_inline(spec(vec![step(&write.kind())]), &ctx)
        .await
        .expect("first");
    let again = t
        .engine
        .run_inline(spec(vec![step(&write.kind())]), &ctx)
        .await
        .expect("replay");
    assert_eq!(first.id, again.id);
    assert_eq!(write.executions(), 1);
}

// --- Staged writes in background jobs ----------------------------------------------------

#[tokio::test]
async fn staged_writes_commit_with_the_step_record() {
    let write = Scripted::new("jobs.test.write").staging(host_write);
    let t = engine_with(&[&write]);
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(spec(vec![step(&write.kind())]), &t.ctx())
        .await
        .expect("submit");
    t.wait_for_state(id, JobState::Succeeded).await;
    let written = host_row(&t, id).await.expect("row written");
    let audit = t.audit().await;
    let step_done = audit
        .iter()
        .find(|record| {
            record.draft.details.changes.iter().any(|change| {
                change.field == "steps[0].state" && change.new.as_deref() == Some("done")
            })
        })
        .expect("step done audited");
    assert_eq!(
        step_done.revision, written,
        "change and step record share a batch"
    );
}

#[tokio::test]
async fn an_idempotent_step_runs_again_when_its_staged_writes_conflict() {
    let write = Scripted::new("jobs.test.write")
        .idempotent(true)
        .staging(conflicting_once);
    let t = engine_with(&[&write]);
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(spec(vec![step(&write.kind())]), &t.ctx())
        .await
        .expect("submit");
    let job = t.wait_for_state(id, JobState::Succeeded).await;
    assert_eq!(write.attempts(), vec![1, 2]);
    assert_eq!(job.steps[0].attempts, 2);
    assert!(host_row(&t, id).await.is_some());
}

#[tokio::test]
async fn a_conflicting_non_idempotent_step_fails_the_job() {
    let write = Scripted::new("jobs.test.write").staging(always_conflicting);
    let t = engine_with(&[&write]);
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(spec(vec![step(&write.kind())]), &t.ctx())
        .await
        .expect("submit");
    let job = t.wait_for_state(id, JobState::RolledBack).await;
    assert_eq!(
        job.error.expect("error").code,
        "sys.store.precondition_failed"
    );
    assert_eq!(write.executions(), 1);
    assert_eq!(
        write.compensated(),
        0,
        "a step that failed on its own is not compensated"
    );
}

// --- Rollback ----------------------------------------------------------------------------

#[tokio::test]
async fn rollback_compensates_finished_steps_in_reverse_order() {
    let a = Scripted::new("jobs.test.a");
    let b = Scripted::new("jobs.test.b");
    let c = Scripted::new("jobs.test.c");
    let fail = Scripted::new("jobs.test.fail")
        .outcomes(vec![Err(coded("connect.unifi.verify_mismatch", 502))]);
    let t = engine_with(&[&a, &b, &c, &fail]);
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(
            spec(vec![
                step(&a.kind()),
                step(&b.kind()),
                step(&c.kind()),
                step(&fail.kind()),
            ]),
            &t.ctx(),
        )
        .await
        .expect("submit");
    let job = t.wait_for_state(id, JobState::RolledBack).await;
    assert_eq!(
        job.error.as_ref().expect("error").code,
        "connect.unifi.verify_mismatch"
    );
    let compensated: Vec<u16> = t
        .transitions(id)
        .await
        .into_iter()
        .filter(|row| row.step_state == Some(StepState::Compensated))
        .filter_map(|row| row.step)
        .collect();
    assert_eq!(compensated, vec![2, 1, 0]);
    for handler in [&a, &b, &c] {
        assert_eq!(handler.compensated(), 1);
        assert_eq!(handler.compensated_outputs(), vec![Some(b"out-1".to_vec())]);
    }
    assert_eq!(fail.compensated(), 0);
    assert!(matches!(job.steps[3].state, StepState::Failed { .. }));
}

#[tokio::test]
async fn steps_that_cannot_be_compensated_become_manual_undo_tasks() {
    let a = Scripted::new("jobs.test.a");
    let b = Scripted::new("jobs.test.b").compensations(vec![Err(StepError::NotCompensable)]);
    let fail = Scripted::new("jobs.test.fail").outcomes(vec![Err(coded("jobs.test.broken", 500))]);
    let t = engine_with(&[&a, &b, &fail]);
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(
            spec(vec![step(&a.kind()), step(&b.kind()), step(&fail.kind())]),
            &t.ctx(),
        )
        .await
        .expect("submit");
    // The undo task does not block the compensation of step 0.
    let job = t
        .wait_for(id, |job| {
            matches!(job.steps[0].state, StepState::Compensated)
        })
        .await;
    assert_eq!(job.state, JobState::RollingBack);
    let StepState::WaitingForManual { task, .. } = &job.steps[1].state else {
        panic!("undo task expected: {:?}", job.steps[1].state);
    };
    assert_eq!(task.instruction.as_str(), "jobs.undo.step");
    assert_eq!(task.args["step"], "1");
    assert_eq!(task.args["kind"], "jobs.test.b");
    t.engine
        .complete_manual(id, 1, Some("reverted by hand".to_owned()), &t.ctx())
        .await
        .expect("undo done");
    let job = t.wait_for_state(id, JobState::RolledBack).await;
    assert_eq!(job.steps[1].state, StepState::Compensated);
    assert!(
        t.transitions(id)
            .await
            .iter()
            .any(|row| row.note.as_deref() == Some("reverted by hand"))
    );
}

#[tokio::test]
async fn a_completed_manual_task_with_an_undo_message_becomes_that_undo_task() {
    let fail = Scripted::new("jobs.test.fail").outcomes(vec![Err(coded("jobs.test.broken", 500))]);
    let t = engine_with(&[&fail]);
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(
            spec(vec![
                manual("jobs.test.reserve", Some("jobs.test.unreserve"), None),
                step(&fail.kind()),
            ]),
            &t.ctx(),
        )
        .await
        .expect("submit");
    t.wait_for_state(id, JobState::Waiting).await;
    t.engine
        .complete_manual(id, 0, None, &t.ctx())
        .await
        .expect("reserved");
    let job = t
        .wait_for(id, |job| {
            job.state == JobState::RollingBack
                && matches!(job.steps[0].state, StepState::WaitingForManual { .. })
        })
        .await;
    let StepState::WaitingForManual { task, .. } = &job.steps[0].state else {
        unreachable!()
    };
    assert_eq!(
        task.instruction,
        MessageKey::from_static("jobs.test.unreserve")
    );
    assert_eq!(task.args["host"], "printer-1");
    t.engine
        .complete_manual(id, 0, None, &t.ctx())
        .await
        .expect("unreserved");
    t.wait_for_state(id, JobState::RolledBack).await;
}

#[tokio::test]
async fn a_manual_task_without_undo_leaves_nothing_to_undo() {
    let fail = Scripted::new("jobs.test.fail").outcomes(vec![Err(coded("jobs.test.broken", 500))]);
    let t = engine_with(&[&fail]);
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(
            spec(vec![
                manual("jobs.test.label", None, None),
                step(&fail.kind()),
            ]),
            &t.ctx(),
        )
        .await
        .expect("submit");
    t.wait_for_state(id, JobState::Waiting).await;
    t.engine
        .complete_manual(id, 0, None, &t.ctx())
        .await
        .expect("done");
    let job = t.wait_for_state(id, JobState::RolledBack).await;
    assert_eq!(job.steps[0].state, StepState::Compensated);
}

// --- Deadlines ---------------------------------------------------------------------------

#[tokio::test]
async fn a_step_past_its_timeout_rolls_back_and_is_compensated() {
    let slow = Scripted::new("jobs.test.slow").gated();
    let t = engine_with(&[&slow]);
    let _runner = t.engine.start().expect("runner");
    let mut timed = step(&slow.kind());
    timed.timeout = Some(Duration::from_secs(30));
    let id = t
        .engine
        .submit(spec(vec![timed]), &t.ctx())
        .await
        .expect("submit");
    slow.wait_started(1).await;
    t.clock.advance(Duration::from_secs(29));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        t.engine.job(id).await.expect("job").state,
        JobState::Running
    );
    t.clock.advance(Duration::from_secs(1));
    let job = t.wait_for_state(id, JobState::RolledBack).await;
    assert_eq!(job.error.as_ref().expect("error").code, "jobs.step.timeout");
    // Its effects are unknown, so it is compensated, without an output.
    assert_eq!(slow.compensated_outputs(), vec![None]);
}

#[tokio::test]
async fn a_manual_step_past_its_timeout_rolls_back() {
    let t = TestEngine::new();
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(
            spec(vec![manual(
                "jobs.test.reserve",
                None,
                Some(Duration::from_secs(300)),
            )]),
            &t.ctx(),
        )
        .await
        .expect("submit");
    t.wait_for_state(id, JobState::Waiting).await;
    t.clock.advance(Duration::from_secs(299));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        t.engine.job(id).await.expect("job").state,
        JobState::Waiting
    );
    t.clock.advance(Duration::from_secs(1));
    let job = t.wait_for_state(id, JobState::RolledBack).await;
    assert_eq!(job.error.expect("error").code, "jobs.step.deadline_passed");
}

#[tokio::test]
async fn the_job_timeout_ends_a_wait_without_its_own_deadline() {
    let t = TestEngine::new();
    let _runner = t.engine.start().expect("runner");
    let mut job_spec = spec(vec![manual("jobs.test.reserve", None, None)]);
    job_spec.timeout = Duration::from_secs(3600);
    let id = t.engine.submit(job_spec, &t.ctx()).await.expect("submit");
    t.wait_for_state(id, JobState::Waiting).await;
    t.clock.advance(Duration::from_secs(3600));
    let job = t.wait_for_state(id, JobState::RolledBack).await;
    assert_eq!(job.error.expect("error").code, "jobs.timeout");
}

// --- Observation wake-up -----------------------------------------------------------------

fn waiting_on(condition: ObservationCondition, t: &TestEngine) -> Scripted {
    let deadline = t
        .clock
        .now()
        .checked_add(Duration::from_secs(600))
        .expect("time");
    Scripted::new("jobs.test.wait").outcomes(vec![Ok(StepOutcome::Wait {
        condition,
        deadline,
    })])
}

#[tokio::test]
async fn an_address_seen_observation_wakes_the_waiting_step() {
    let mut t = TestEngine::new();
    let vrf = VrfId::generate();
    let ip = "192.0.2.20".parse().expect("ip");
    let mac = "00:00:5e:00:53:20".parse().expect("mac");
    let wait = waiting_on(address_seen(vrf, ip, Some(mac)), &t);
    let after = Scripted::new("jobs.test.cleanup");
    t.register(Arc::new(wait.clone()));
    t.register(Arc::new(after.clone()));
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(
            spec(vec![step(&wait.kind()), step(&after.kind())]),
            &t.ctx(),
        )
        .await
        .expect("submit");
    t.wait_for_state(id, JobState::Waiting).await;
    assert_eq!(t.engine.waiting_for_observations(), 1);

    let now = t.clock.now();
    let other_mac = "00:00:5e:00:53:99".parse().expect("mac");
    t.engine
        .on_observation(&arp(vrf, ip, Some(other_mac), now))
        .await;
    t.engine
        .on_observation(&arp(VrfId::generate(), ip, Some(mac), now))
        .await;
    t.engine
        .on_observation(&arp(vrf, "192.0.2.21".parse().expect("ip"), Some(mac), now))
        .await;
    assert_eq!(
        t.engine.job(id).await.expect("job").state,
        JobState::Waiting
    );

    let seen = arp(vrf, ip, Some(mac), now);
    t.engine.on_observation(&seen).await;
    let job = t.wait_for_state(id, JobState::Succeeded).await;
    let output = job.steps[0].output.as_ref().expect("output");
    assert_eq!(from_cbor::<ObservationId>(&output.0).expect("id"), seen.id);
    assert_eq!(after.executions(), 1);
    assert_eq!(t.engine.waiting_for_observations(), 0);
}

#[tokio::test]
async fn a_lease_in_prefix_needs_the_prefix_resolver() {
    let mut t = TestEngine::new();
    let vrf = VrfId::generate();
    let prefix = PrefixId::generate();
    let mac = "00:00:5e:00:53:21".parse().expect("mac");
    let condition = ObservationCondition {
        subject: tenko_core::HostId::generate().into(),
        any_of: vec![ObservedPredicate::LeaseInPrefix { prefix, mac }],
    };
    let wait = waiting_on(condition, &t);
    t.register(Arc::new(wait.clone()));
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(spec(vec![step(&wait.kind())]), &t.ctx())
        .await
        .expect("submit");
    t.wait_for_state(id, JobState::Waiting).await;
    let leased = lease(vrf, "198.51.100.7".parse().expect("ip"), mac, t.clock.now());
    t.engine.on_observation(&leased).await;
    assert_eq!(
        t.engine.job(id).await.expect("job").state,
        JobState::Waiting
    );

    t.engine.set_prefix_resolver(Arc::new(move |id: PrefixId| {
        (id == prefix).then(|| "198.51.100.0/24".parse().expect("cidr"))
    }));
    let outside = lease(vrf, "203.0.113.7".parse().expect("ip"), mac, t.clock.now());
    t.engine.on_observation(&outside).await;
    assert_eq!(
        t.engine.job(id).await.expect("job").state,
        JobState::Waiting
    );
    t.engine.on_observation(&leased).await;
    t.wait_for_state(id, JobState::Succeeded).await;
}

#[tokio::test]
async fn observations_older_than_the_wait_do_not_count() {
    let mut t = TestEngine::new();
    let vrf = VrfId::generate();
    let ip = "192.0.2.30".parse().expect("ip");
    let wait = waiting_on(address_seen(vrf, ip, None), &t);
    t.register(Arc::new(wait.clone()));
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(spec(vec![step(&wait.kind())]), &t.ctx())
        .await
        .expect("submit");
    t.wait_for_state(id, JobState::Waiting).await;
    let stale_at = t.clock.now();
    let stale = arp(
        vrf,
        ip,
        None,
        tenko_core::Timestamp::from_unix_nanos(stale_at.unix_nanos() - 3_600_000_000_000)
            .expect("time"),
    );
    t.engine.on_observation(&stale).await;
    assert_eq!(
        t.engine.job(id).await.expect("job").state,
        JobState::Waiting
    );
    t.engine
        .on_observation(&arp(vrf, ip, None, t.clock.now()))
        .await;
    t.wait_for_state(id, JobState::Succeeded).await;
}

#[tokio::test]
async fn an_unanswered_wait_rolls_back_at_its_deadline() {
    let mut t = TestEngine::new();
    let vrf = VrfId::generate();
    let wait = waiting_on(
        address_seen(vrf, "192.0.2.40".parse().expect("ip"), None),
        &t,
    );
    let before = Scripted::new("jobs.test.move");
    t.register(Arc::new(wait.clone()));
    t.register(Arc::new(before.clone()));
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(
            spec(vec![step(&before.kind()), step(&wait.kind())]),
            &t.ctx(),
        )
        .await
        .expect("submit");
    t.wait_for_state(id, JobState::Waiting).await;
    t.clock.advance(Duration::from_secs(600));
    let job = t.wait_for_state(id, JobState::RolledBack).await;
    assert_eq!(job.error.expect("error").code, "jobs.step.deadline_passed");
    assert_eq!(before.compensated(), 1);
    assert_eq!(
        wait.compensated(),
        1,
        "the waiting step ran and is compensated too"
    );
    assert_eq!(t.engine.waiting_for_observations(), 0);
}

// --- Events ------------------------------------------------------------------------------

#[tokio::test]
async fn every_transition_reaches_the_journal_as_a_job_event() {
    use futures::StreamExt;
    use tenko_jobs::{JobEvent, StepStateKind};

    let a = Scripted::new("jobs.test.a");
    let t = engine_with(&[&a]);
    let mut watch = t
        .store
        .watch(Some(Revision::ZERO), JobEvent::watch_filter())
        .expect("watch");
    let _runner = t.engine.start().expect("runner");
    let id = t
        .engine
        .submit(spec(vec![step(&a.kind())]), &t.ctx())
        .await
        .expect("submit");
    t.wait_for_state(id, JobState::Succeeded).await;
    let rows = t.transitions(id).await;
    let mut events = Vec::new();
    while events.len() < rows.len() {
        let changes = tokio::time::timeout(Duration::from_secs(5), watch.next())
            .await
            .expect("journal entry")
            .expect("stream")
            .expect("change set");
        let view = t.store.read(ReadConsistency::Local).await.expect("view");
        events.extend(JobEvent::from_change_set(&changes, view.as_ref()).expect("events"));
    }
    assert!(events.iter().all(|event| event.job == id));
    let seen: Vec<_> = events
        .iter()
        .map(|event| (event.seq, event.state, event.step, event.step_state))
        .collect();
    assert_eq!(
        seen,
        vec![
            (0, JobState::Queued, None, None),
            (1, JobState::Running, None, None),
            (2, JobState::Running, Some(0), Some(StepStateKind::Running)),
            (3, JobState::Running, Some(0), Some(StepStateKind::Done)),
            (4, JobState::Succeeded, None, None),
        ]
    );
    // Revisions only grow, and each event names the revision of its batch.
    assert!(
        events
            .windows(2)
            .all(|pair| pair[0].revision <= pair[1].revision)
    );
}

#[tokio::test]
async fn a_replayed_failed_inline_job_returns_the_same_error() {
    let overlap =
        Scripted::new("jobs.test.write").outcomes(vec![Err(coded("ipam.prefix.overlap", 409))]);
    let t = engine_with(&[&overlap]);
    let ctx = t
        .ctx()
        .with_idempotency(IdempotencyKey::new("edit-2").expect("key"));
    for _ in 0..2 {
        let error = t
            .engine
            .run_inline(spec(vec![step(&overlap.kind())]), &ctx)
            .await
            .expect_err("fails");
        assert_eq!(
            tenko_core::Coded::to_coded_error(&error).code,
            "ipam.prefix.overlap"
        );
    }
    assert_eq!(
        overlap.executions(),
        1,
        "the replay does not run the step again"
    );
}
