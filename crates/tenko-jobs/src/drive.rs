//! Driving one job: the cycle of load, apply results, decide, commit and call a handler
//! (see [`crate::machine`]), with ownership, takeover and retries.
//!
//! # Ownership
//!
//! A job belongs to the runner named in [`Job::runner`]. A runner may drive a job that its
//! [`Scope`] admits and that is queued (starting it claims it), that it owns, that nobody
//! owns, or whose owner's lease in `jobs.runners` has expired; the takeover batch carries
//! a precondition on that lease row, so an owner that renewed in the meantime wins. Every
//! batch carries a precondition on the job record, so a runner that lost the job finds out
//! at its next write and stops.
//!
//! # The leader's runner
//!
//! The runner of the leader (`Scope::Leader`) adds the leader epoch to every batch
//! (`tenko_store::fence`) and takes jobs of other runners over at once, without a lease
//! precondition: once it has taken office, the previous leader's writes fail on the epoch.
//! A failed fence ends the drive with [`DriveEnd::Deposed`]. Before it calls `execute` or
//! `compensate` of a step that is not idempotent, it confirms with a linearizable read
//! (a read index on the leader) that the epoch is still its own; a step that cannot be
//! confirmed is not started: the runner retries the confirmation until it is stopped,
//! and then commits the job without starting the step.
//!
//! # Retries
//!
//! A write that loses against a concurrent change of the job reloads the job and applies
//! the same handler results again. Staged writes that conflict run an idempotent step
//! again; other steps fail. Transient store errors are retried, then the runner backs off
//! and looks at the job later; a step whose result could not be written then counts as
//! interrupted.

use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use futures::FutureExt;
use tenko_core::{
    Coded, CodedError, JobId, NodeId, RequestCtx, Revision, Timestamp, cluster::LEADER_EPOCH,
};
use tenko_store::{FailedPrecondition, ReadConsistency, ReadViewExt, StoreError};

use crate::{
    engine::Inner,
    machine::{Boundary, Machine, ResultOp, step_timeout},
    model::{Job, JobError, JobState, StepContext, StepError, StepKind},
    persist::{self, Author, Loaded},
    runner::Scope,
    stage::{StagedWrite, run_staged},
    tables::{RUNNERS, RunnerLease},
};

/// Concurrent changes of one job a drive tolerates in a row before it backs off.
const RACE_LIMIT: u32 = 100;

/// Longest pause between two attempts to confirm leadership.
const CONFIRM_BACKOFF_MAX: Duration = Duration::from_secs(2);

/// Whether a write failed because the leader epoch moved on: another controller took
/// office after the epoch the batch was fenced with.
pub(crate) fn fenced_out(error: &StoreError) -> bool {
    matches!(error, StoreError::PreconditionFailed(failures) if failures.iter().any(|failure| {
        matches!(failure, FailedPrecondition::Counter { counter, .. } if *counter == LEADER_EPOCH)
    }))
}

/// The outcome of a leadership confirmation.
enum Confirmation {
    /// The epoch is still this runner's: the step may start.
    Leads,
    /// Another controller took office.
    Deposed,
    /// The runner stops before leadership could be confirmed.
    Stopped,
}

/// Confirms with a linearizable read that the leader epoch is still `epoch`, retrying
/// store errors with a growing pause until the runner stops.
async fn confirm(inner: &Inner, id: JobId, epoch: u64, stop: &AtomicBool) -> Confirmation {
    let mut attempt: u32 = 0;
    loop {
        if stop.load(Ordering::SeqCst) {
            return Confirmation::Stopped;
        }
        match inner.store.read(ReadConsistency::Linearizable).await {
            Ok(view) => match view.counter(&LEADER_EPOCH) {
                Ok(current) if current == epoch => return Confirmation::Leads,
                Ok(_) => return Confirmation::Deposed,
                Err(error) => {
                    tracing::warn!(job = %id, %error, "the leader epoch could not be read");
                }
            },
            Err(error) => {
                tracing::warn!(job = %id, %error, "leadership could not be confirmed before a step");
            }
        }
        attempt = attempt.saturating_add(1);
        let pause = Duration::from_millis(100)
            .saturating_mul(attempt)
            .min(CONFIRM_BACKOFF_MAX);
        tokio::time::sleep(pause).await;
    }
}

/// Whether the boundary calls a handler of a step that is not idempotent: the leader's
/// runner confirms leadership before such a call.
fn needs_confirmation(inner: &Inner, job: &Job, boundary: Option<Boundary>) -> bool {
    let Some(Boundary::Execute { step } | Boundary::Compensate { step }) = boundary else {
        return false;
    };
    job.steps
        .get(usize::from(step))
        .and_then(|record| inner.handler_info(&record.kind))
        .is_some_and(|info| !info.idempotent)
}

/// How a drive ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriveEnd {
    /// The job waits; look again at `deadline` or when woken.
    Parked {
        deadline: Option<Timestamp>,
        revision: Revision,
    },
    /// The job is final.
    Terminal { revision: Revision },
    /// Another live runner owns the job.
    NotOwned,
    /// The job does not exist.
    Missing,
    /// The runner is stopping; the job is at a clean boundary.
    Stopped,
    /// Transient store errors: look again later.
    Retry,
    /// A fenced write failed or leadership could not be confirmed: another controller
    /// took office. The runner ends.
    Deposed,
}

/// The lease row this runner writes when it starts or claims a job.
pub(crate) fn lease(inner: &Inner, now: Timestamp) -> RunnerLease {
    RunnerLease {
        node: inner.config.node,
        renewed: now,
        expires: now.checked_add(inner.config.lease_ttl).unwrap_or(now),
    }
}

/// What a drive carries from one cycle to the next.
#[derive(Default)]
struct Pending {
    /// Handler results not yet committed.
    results: Vec<ResultOp>,
    /// Their staged writes.
    staged: StagedWrite,
    write_failures: u32,
    races: u32,
    stage_conflicts: HashMap<u16, u32>,
}

/// One decided cycle, ready to commit.
struct Decided {
    loaded: Loaded,
    job: Job,
    rows: Vec<crate::tables::Transition>,
    boundary: Option<Boundary>,
    execute_deadline: Option<Timestamp>,
    /// The lease row of the previous owner that a takeover expects unchanged (absent for
    /// the leader's runner, which is fenced instead).
    lease_expect: Option<(NodeId, Option<Revision>)>,
    claims: bool,
    now: Timestamp,
}

/// What to do after a commit attempt.
enum Flow {
    /// Committed (or nothing to commit) at this revision.
    Committed(Revision),
    /// Load and decide again.
    Again,
    /// Stop driving.
    End(DriveEnd),
}

/// Drives a job until it parks, ends, is lost or the runner stops.
pub(crate) async fn drive(
    inner: &Arc<Inner>,
    id: JobId,
    stop: &AtomicBool,
    scope: Scope,
) -> DriveEnd {
    let mut pending = Pending::default();
    loop {
        let stopping = stop.load(Ordering::SeqCst);
        let decided = match decide(inner, id, &pending, stopping, scope).await {
            Ok(decided) => decided,
            Err(end) => return end,
        };
        if let Some(epoch) = scope.epoch()
            && needs_confirmation(inner, &decided.job, decided.boundary)
        {
            match confirm(inner, id, epoch, stop).await {
                Confirmation::Leads => {}
                Confirmation::Deposed => return DriveEnd::Deposed,
                // Decide again while stopping: commit what is known, start nothing.
                Confirmation::Stopped => continue,
            }
        }
        let revision = match commit(inner, id, &decided, &mut pending, scope).await {
            Flow::Committed(revision) => revision,
            Flow::Again => continue,
            Flow::End(end) => return end,
        };
        let Decided {
            mut job,
            boundary,
            execute_deadline,
            ..
        } = decided;
        job.revision = revision;
        let Some(boundary) = boundary else {
            return DriveEnd::Stopped;
        };
        match boundary {
            Boundary::Execute { step } => {
                let request = inner.runner_ctx(&job);
                let (op, writes) = run_execute(inner, &job, step, execute_deadline, request).await;
                pending.results.push(op);
                pending.staged = writes;
            }
            Boundary::Compensate { step } => {
                let request = inner.runner_ctx(&job);
                let (op, writes) = run_compensate(inner, &job, step, request).await;
                pending.results.push(op);
                pending.staged = writes;
            }
            Boundary::Park { deadline } => {
                inner.track_waiter(&job);
                return DriveEnd::Parked { deadline, revision };
            }
            Boundary::Terminal => {
                inner.waiters().remove(id);
                return DriveEnd::Terminal { revision };
            }
        }
    }
}

/// Loads the job, checks ownership, applies the pending results and decides up to the
/// next boundary (none while stopping).
async fn decide(
    inner: &Arc<Inner>,
    id: JobId,
    pending: &Pending,
    stopping: bool,
    scope: Scope,
) -> Result<Decided, DriveEnd> {
    let me = inner.config.node;
    let view = inner
        .store
        .read(tenko_store::ReadConsistency::Local)
        .await
        .map_err(|error| {
            tracing::warn!(job = %id, %error, "job could not be read");
            DriveEnd::Retry
        })?;
    let loaded = match persist::load(view.as_ref(), id) {
        Ok(Some(loaded)) => loaded,
        Ok(None) => return Err(DriveEnd::Missing),
        Err(error) => {
            tracing::warn!(job = %id, %error, "job could not be decoded");
            return Err(DriveEnd::Retry);
        }
    };
    if loaded.job.state.is_terminal() {
        inner.waiters().remove(id);
        return Err(DriveEnd::Terminal {
            revision: loaded.revision,
        });
    }
    if !scope.admits(&loaded.job, me) {
        return Err(DriveEnd::NotOwned);
    }
    let now = inner.clock.now();
    let mut takeover = false;
    let mut lease_expect = None;
    if let Some(owner) = loaded.job.runner
        && owner != me
    {
        takeover = true;
        if !scope.takes_over_at_once() {
            match view.get_typed(&RUNNERS, &owner) {
                Ok(Some((lease, _))) if lease.expires > now => return Err(DriveEnd::NotOwned),
                Ok(Some((_, revision))) => lease_expect = Some((owner, Some(revision))),
                Ok(None) => lease_expect = Some((owner, None)),
                Err(error) => {
                    tracing::warn!(job = %id, %error, "runner lease could not be read");
                    return Err(DriveEnd::Retry);
                }
            }
        }
    }
    // The forward manual tasks decide how a rollback undoes manual steps.
    let history = persist::transitions(view.as_ref(), id).map_err(|error| {
        tracing::warn!(job = %id, %error, "job history could not be read");
        DriveEnd::Retry
    })?;
    drop(view);
    let manual_tasks = persist::forward_manual_tasks(&history);
    let handlers = |kind: &StepKind| inner.handler_info(kind);
    let mut machine = Machine::new(
        loaded.job.clone(),
        now,
        Some(me),
        Inner::runner_principal(&loaded.job),
        None,
        &handlers,
        &manual_tasks,
    );
    let claims = takeover || (loaded.job.runner.is_none() && loaded.job.state != JobState::Queued);
    if claims {
        machine.claim();
    }
    for op in &pending.results {
        if !machine.apply(op) {
            tracing::warn!(job = %id, ?op, "a step result no longer fits the job and is dropped");
        }
    }
    // While stopping, commit what is known and start nothing new.
    let boundary = (!stopping).then(|| machine.advance());
    let execute_deadline = match boundary {
        Some(Boundary::Execute { step }) => machine.execute_deadline(step),
        _ => None,
    };
    let rows = std::mem::take(&mut machine.rows);
    Ok(Decided {
        loaded,
        job: machine.job,
        rows,
        boundary,
        execute_deadline,
        lease_expect,
        claims,
        now,
    })
}

/// Commits a decided cycle with the pending staged writes.
async fn commit(
    inner: &Inner,
    id: JobId,
    decided: &Decided,
    pending: &mut Pending,
    scope: Scope,
) -> Flow {
    if decided.rows.is_empty() && pending.staged.is_empty() {
        pending.results.clear();
        return Flow::Committed(decided.loaded.revision);
    }
    let me = inner.config.node;
    let author = Author {
        principal: Inner::runner_principal(&decided.job),
        now: decided.now,
        request: None,
        source_ip: None,
    };
    let starts =
        decided.loaded.job.state == JobState::Queued && decided.job.state != JobState::Queued;
    let batch = persist::batch(
        Some(&decided.loaded),
        &decided.job,
        decided.rows.clone(),
        pending.staged.clone(),
        &author,
    )
    .and_then(|mut batch| {
        if starts || decided.claims {
            batch.put_typed(&RUNNERS, &me, &lease(inner, decided.now))?;
        }
        if let Some((owner, expect)) = decided.lease_expect {
            batch.expect_typed(&RUNNERS, &owner, expect);
        }
        if let Some(epoch) = scope.epoch() {
            batch.preconditions.push(tenko_store::fence(epoch));
        }
        Ok(batch)
    });
    let batch = match batch {
        Ok(batch) => batch,
        Err(error) => {
            tracing::error!(job = %id, %error, "job batch could not be encoded");
            return Flow::End(DriveEnd::Retry);
        }
    };
    match inner.store.propose(batch).await {
        Ok(committed) => {
            pending.write_failures = 0;
            pending.results.clear();
            pending.staged = StagedWrite::default();
            Flow::Committed(committed.revision)
        }
        // Checked first: a deposed runner must not retry anything.
        Err(error) if fenced_out(&error) => Flow::End(DriveEnd::Deposed),
        Err(error) if persist::job_changed(&error, id) => {
            // Someone else wrote the job (a cancel request, a takeover): reload and decide
            // again with the same results and staged writes.
            pending.races += 1;
            if pending.races > RACE_LIMIT {
                tracing::warn!(job = %id, "job keeps changing underneath the runner");
                return Flow::End(DriveEnd::Retry);
            }
            Flow::Again
        }
        Err(error @ StoreError::PreconditionFailed(_)) => {
            // The takeover lost against a renewed lease, or staged writes conflict.
            pending.staged = StagedWrite::default();
            let Some(last) = pending.results.pop() else {
                return Flow::End(DriveEnd::NotOwned);
            };
            let idempotent = |step: u16| {
                decided
                    .loaded
                    .job
                    .steps
                    .get(usize::from(step))
                    .and_then(|record| inner.handler_info(&record.kind))
                    .is_some_and(|info| info.idempotent)
            };
            let replacement = after_conflict(
                inner,
                last,
                &error,
                &mut pending.stage_conflicts,
                idempotent,
            );
            pending.results.extend(replacement);
            Flow::Again
        }
        Err(error) => {
            pending.write_failures += 1;
            tracing::warn!(job = %id, %error, attempt = pending.write_failures, "job write failed");
            if pending.write_failures > inner.config.write_retries {
                return Flow::End(DriveEnd::Retry);
            }
            tokio::time::sleep(Duration::from_millis(
                50 * u64::from(pending.write_failures),
            ))
            .await;
            Flow::Again
        }
    }
}

/// What replaces a handler result whose staged writes conflicted: an idempotent step runs
/// again (a compensating step always does, compensations being idempotent) until the
/// retries are used up, then the step fails.
fn after_conflict(
    inner: &Inner,
    last: ResultOp,
    error: &StoreError,
    conflicts: &mut HashMap<u16, u32>,
    idempotent: impl Fn(u16) -> bool,
) -> Option<ResultOp> {
    match last {
        ResultOp::Executed { step, .. } => {
            let tries = conflicts.entry(step).or_default();
            *tries += 1;
            Some(
                if idempotent(step) && *tries <= inner.config.stage_retries {
                    ResultOp::Retry { step }
                } else {
                    ResultOp::ExecFailed {
                        step,
                        error: error.to_coded_error(),
                    }
                },
            )
        }
        ResultOp::Compensated { step } => {
            let tries = conflicts.entry(step).or_default();
            *tries += 1;
            // Still `compensating` in the store: the next cycle compensates again.
            (*tries > inner.config.stage_retries).then(|| ResultOp::CompensationFailed {
                step,
                error: error.to_coded_error(),
            })
        }
        other => Some(other),
    }
}

/// Calls `execute` of a step with staging, its deadline and panic protection.
pub(crate) async fn run_execute(
    inner: &Inner,
    job: &Job,
    step: u16,
    deadline: Option<Timestamp>,
    request: RequestCtx,
) -> (ResultOp, StagedWrite) {
    let index = usize::from(step);
    let kind = &job.steps[index].kind;
    let Some(handler) = inner.handler(kind) else {
        let error = tenko_core::Coded::to_coded_error(&JobError::UnknownStepKind(kind.clone()));
        return (ResultOp::ExecFailed { step, error }, StagedWrite::default());
    };
    let cx = StepContext {
        job: job.id,
        step,
        attempt: job.steps[index].attempts,
        request,
        store: Arc::clone(&inner.store),
        deadline,
    };
    let params = job.spec.steps[index].params.0.clone();
    let call = run_staged(
        job.id,
        step,
        AssertUnwindSafe(handler.execute(&params, &cx)).catch_unwind(),
    );
    let outcome = match deadline {
        Some(deadline) => {
            tokio::select! {
                outcome = call => Some(outcome),
                () = inner.clock.sleep_until(deadline) => None,
            }
        }
        None => Some(call.await),
    };
    match outcome {
        None | Some((Ok(Err(StepError::Timeout)), _)) => {
            (ResultOp::TimedOut { step }, StagedWrite::default())
        }
        Some((Ok(Ok(outcome)), writes)) => (ResultOp::Executed { step, outcome }, writes),
        Some((Ok(Err(error)), _)) => (
            ResultOp::ExecFailed {
                step,
                error: error.to_coded_error(),
            },
            StagedWrite::default(),
        ),
        Some((Err(_panic), _)) => (
            ResultOp::ExecFailed {
                step,
                error: CodedError::new("jobs.step.panicked", 500, format!("step {step} panicked")),
            },
            StagedWrite::default(),
        ),
    }
}

/// Calls `compensate` of a step with staging, a deadline and panic protection.
pub(crate) async fn run_compensate(
    inner: &Inner,
    job: &Job,
    step: u16,
    request: RequestCtx,
) -> (ResultOp, StagedWrite) {
    let index = usize::from(step);
    let kind = &job.steps[index].kind;
    let Some(handler) = inner.handler(kind) else {
        return (ResultOp::NotCompensable { step }, StagedWrite::default());
    };
    let timeout = job.spec.steps[index].timeout.unwrap_or(job.spec.timeout);
    let deadline = inner.clock.now().checked_add(timeout);
    let cx = StepContext {
        job: job.id,
        step,
        attempt: job.steps[index].attempts,
        request,
        store: Arc::clone(&inner.store),
        deadline,
    };
    let params = job.spec.steps[index].params.0.clone();
    let output = job.steps[index]
        .output
        .as_ref()
        .map(|output| output.0.clone());
    let call = run_staged(
        job.id,
        step,
        AssertUnwindSafe(handler.compensate(&params, output.as_deref(), &cx)).catch_unwind(),
    );
    let outcome = match deadline {
        Some(deadline) => {
            tokio::select! {
                outcome = call => Some(outcome),
                () = inner.clock.sleep_until(deadline) => None,
            }
        }
        None => Some(call.await),
    };
    match outcome {
        Some((Ok(Ok(())), writes)) => (ResultOp::Compensated { step }, writes),
        Some((Ok(Err(StepError::NotCompensable)), _)) => {
            (ResultOp::NotCompensable { step }, StagedWrite::default())
        }
        None => (
            ResultOp::CompensationFailed {
                step,
                error: step_timeout(step),
            },
            StagedWrite::default(),
        ),
        Some((Ok(Err(error)), _)) => (
            ResultOp::CompensationFailed {
                step,
                error: error.to_coded_error(),
            },
            StagedWrite::default(),
        ),
        Some((Err(_panic), _)) => (
            ResultOp::CompensationFailed {
                step,
                error: CodedError::new(
                    "jobs.step.panicked",
                    500,
                    format!("compensation of step {step} panicked"),
                ),
            },
            StagedWrite::default(),
        ),
    }
}
