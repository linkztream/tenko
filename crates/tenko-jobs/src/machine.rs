//! The pure part of the engine: how a job moves from one effect boundary to the next.
//!
//! The runner's driver and inline jobs repeat one cycle: load the job, apply the
//! [`ResultOp`]s of the handler calls since the last commit, let [`Machine::advance`]
//! take every decision that needs no handler (start, complete, roll back, cancel, deadline,
//! next step, next compensation), commit the result with its transition rows, and then
//! make the handler call the returned [`Boundary`] asks for. Because results are re-applied
//! to the freshly loaded job, a concurrent change (a cancel request) merges instead of
//! being overwritten, and a lost write never loses a decision: it is taken again.
//!
//! Rules that the tests pin down:
//!
//! - Steps run in order; the current step is the first one not `done` or `skipped`.
//! - A job past its deadline (first step start plus `JobSpec::timeout`) rolls back with
//!   `jobs.timeout`. A waiting step past its deadline rolls back with
//!   `jobs.step.deadline_passed`: the observation deadline of the step, or for a manual
//!   task the step timeout from the step's first start, whichever of these and the job
//!   deadline is earlier.
//! - A cancel request takes effect at the next boundary: the current step is aborted with
//!   `jobs.cancelled` and the job rolls back, ending in `cancelled` (`FinishCancel`).
//! - A step found `running` with no result to apply was interrupted by a crash: an
//!   idempotent step runs again, any other step fails with `jobs.step.interrupted` and the
//!   job rolls back.
//! - Rollback walks the steps in reverse. A step whose `execute` ran (done, or aborted
//!   while running or waiting) is compensated; a step that failed with its own error had no
//!   effect and is left alone. A step completed as a manual task whose task names an `undo`
//!   message becomes a manual undo task with that message; a handler that answers
//!   `NotCompensable` turns its step into a generic manual undo task (`jobs.undo.step`).
//!   Undo tasks do not block the compensation of earlier steps; the rollback ends when the
//!   last undo task is completed. A failed compensation ends the job in `failed`.

use std::collections::BTreeMap;

use tenko_core::{
    Coded, CodedError, MessageKey, NodeId, Principal, RequestId, Timestamp, serde_util::HexBytes,
};

use crate::{
    model::{Job, JobAction, JobError, JobState, ManualTask, StepKind, StepOutcome, StepState},
    tables::{Transition, TransitionEvent},
};

/// Error code of a step or job aborted by a cancel.
pub const CANCELLED: &str = "jobs.cancelled";
/// Error code of a step that was running when its runner stopped and cannot run again.
pub const INTERRUPTED: &str = "jobs.step.interrupted";
/// Error code of a waiting step whose deadline passed.
pub const DEADLINE_PASSED: &str = "jobs.step.deadline_passed";
/// Error code of a step that exceeded its timeout.
pub const STEP_TIMEOUT: &str = "jobs.step.timeout";
/// Error code of a job that exceeded its timeout.
pub const JOB_TIMEOUT: &str = "jobs.timeout";
/// Message key of the generic manual undo task.
pub const UNDO_STEP: MessageKey = MessageKey::from_static("jobs.undo.step");

/// Codes of errors the engine imposes on a step whose `execute` may have had effects;
/// such steps are compensated.
const ABORT_CODES: [&str; 5] = [
    CANCELLED,
    INTERRUPTED,
    DEADLINE_PASSED,
    STEP_TIMEOUT,
    JOB_TIMEOUT,
];

/// The error stored when a cancel aborts a job.
pub fn cancelled() -> CodedError {
    CodedError::new(CANCELLED, 409, "the job was cancelled")
}

/// The error stored when a crash interrupted a step that cannot run again.
pub fn interrupted(step: u16) -> CodedError {
    CodedError::new(
        INTERRUPTED,
        500,
        format!("step {step} was interrupted and is not idempotent"),
    )
    .with_param("step", step.to_string())
}

/// The error stored when a waiting step's deadline passed.
pub fn deadline_passed(step: u16) -> CodedError {
    CodedError::new(
        DEADLINE_PASSED,
        504,
        format!("step {step} was still waiting at its deadline"),
    )
    .with_param("step", step.to_string())
}

/// The error stored when a step exceeded its timeout.
pub fn step_timeout(step: u16) -> CodedError {
    CodedError::new(STEP_TIMEOUT, 504, format!("step {step} timed out"))
        .with_param("step", step.to_string())
}

/// What a handler call produced, applied to the job before the next decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultOp {
    /// `execute` returned an outcome.
    Executed {
        /// The step.
        step: u16,
        /// The outcome.
        outcome: StepOutcome,
    },
    /// `execute` failed with the handler's own error: no effect, no compensation.
    ExecFailed {
        /// The step.
        step: u16,
        /// The error.
        error: CodedError,
    },
    /// `execute` exceeded the step timeout: effects unknown, compensated.
    TimedOut {
        /// The step.
        step: u16,
    },
    /// The staged writes of an idempotent step conflicted: run it again.
    Retry {
        /// The step.
        step: u16,
    },
    /// An observation satisfied a waiting step.
    Observed {
        /// The step.
        step: u16,
        /// The observation id as CBOR, kept as the step output.
        output: Vec<u8>,
    },
    /// A person completed a manual task or a manual undo task.
    ManualDone {
        /// The step.
        step: u16,
    },
    /// `compensate` succeeded.
    Compensated {
        /// The step.
        step: u16,
    },
    /// The step cannot be undone automatically: a person must.
    NotCompensable {
        /// The step.
        step: u16,
    },
    /// `compensate` failed.
    CompensationFailed {
        /// The step.
        step: u16,
        /// The error.
        error: CodedError,
    },
}

/// Where [`Machine::advance`] stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    /// Run `execute` of the step (already marked `running`).
    Execute {
        /// The step.
        step: u16,
    },
    /// Run `compensate` of the step (already marked `compensating`).
    Compensate {
        /// The step.
        step: u16,
    },
    /// Nothing to do until an observation, a person, a cancel or the deadline.
    Park {
        /// When to look again; `None` waits for a person.
        deadline: Option<Timestamp>,
    },
    /// The job is final.
    Terminal,
}

/// What a handler declares, for decisions that depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerInfo {
    /// [`StepHandler::idempotent`](crate::StepHandler::idempotent).
    pub idempotent: bool,
}

/// One cycle's view of a job: the job being changed and the transition rows produced.
pub struct Machine<'a> {
    /// The job, changed in place.
    pub job: Job,
    /// Rows for the transition log, without sequence numbers yet.
    pub rows: Vec<Transition>,
    now: Timestamp,
    runner: Option<NodeId>,
    by: Principal,
    request: Option<RequestId>,
    handlers: &'a (dyn Fn(&StepKind) -> Option<HandlerInfo> + Sync),
    manual_tasks: &'a BTreeMap<u16, ManualTask>,
}

impl<'a> Machine<'a> {
    /// Starts a cycle on a loaded job.
    pub fn new(
        job: Job,
        now: Timestamp,
        runner: Option<NodeId>,
        by: Principal,
        request: Option<RequestId>,
        handlers: &'a (dyn Fn(&StepKind) -> Option<HandlerInfo> + Sync),
        manual_tasks: &'a BTreeMap<u16, ManualTask>,
    ) -> Self {
        Self {
            job,
            rows: Vec::new(),
            now,
            runner,
            by,
            request,
            handlers,
            manual_tasks,
        }
    }

    fn row(&self, event: TransitionEvent) -> Transition {
        Transition {
            seq: 0,
            at: self.now,
            by: self.by.clone(),
            request: self.request,
            event,
            action: None,
            from: None,
            state: self.job.state,
            step: None,
            step_state: None,
            runner: None,
            note: None,
        }
    }

    /// Applies a job action and records it.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::InvalidTransition`] if the table refuses the action.
    pub fn job_action(&mut self, action: JobAction) -> Result<(), JobError> {
        let from = self.job.state;
        let to = from.apply(action)?;
        self.job.state = to;
        if to.is_terminal() {
            self.job.finished = Some(self.now);
        }
        let mut row = self.row(TransitionEvent::Job);
        row.action = Some(action);
        row.from = Some(from);
        if action == JobAction::Start {
            row.runner = self.job.runner;
        }
        self.rows.push(row);
        Ok(())
    }

    /// Sets a step state and records it.
    pub fn set_step(&mut self, step: u16, state: StepState) {
        let record = &mut self.job.steps[usize::from(step)];
        if matches!(
            state,
            StepState::Done
                | StepState::Skipped
                | StepState::Failed { .. }
                | StepState::Compensated
                | StepState::CompensationFailed { .. }
        ) {
            record.finished = Some(self.now);
        }
        record.state = state.clone();
        let mut row = self.row(TransitionEvent::Step);
        row.step = Some(step);
        row.step_state = Some(state);
        self.rows.push(row);
    }

    /// Attaches a note to the last row of a step.
    pub fn note_step(&mut self, step: u16, note: Option<String>) {
        if let Some(row) = self
            .rows
            .iter_mut()
            .rev()
            .find(|row| row.event == TransitionEvent::Step && row.step == Some(step))
        {
            row.note = note;
        }
    }

    /// Records a takeover by this cycle's runner.
    pub fn claim(&mut self) {
        self.job.runner = self.runner;
        let mut row = self.row(TransitionEvent::Claimed);
        row.runner = self.runner;
        self.rows.push(row);
    }

    /// Records a cancel request.
    pub fn request_cancel(&mut self, stamp: tenko_core::ipam::Stamp) {
        self.job.cancel_requested = Some(stamp);
        self.rows.push(self.row(TransitionEvent::CancelRequested));
    }

    fn state_of(&self, step: u16) -> Option<&StepState> {
        self.job
            .steps
            .get(usize::from(step))
            .map(|record| &record.state)
    }

    /// Applies a handler result. Returns `false` when the result no longer fits the job
    /// (another runner moved it on), in which case nothing changed.
    pub fn apply(&mut self, op: &ResultOp) -> bool {
        use StepState as S;
        match op {
            ResultOp::Executed { step, outcome } => self.executed(*step, outcome),
            ResultOp::ExecFailed { step, error } => self.fail_running(*step, error.clone()),
            ResultOp::TimedOut { step } => self.fail_running(*step, step_timeout(*step)),
            ResultOp::Retry { step } => {
                if !matches!(self.state_of(*step), Some(S::Running)) {
                    return false;
                }
                self.set_step(*step, S::Pending);
                true
            }
            ResultOp::Observed { step, output } => {
                if !matches!(self.state_of(*step), Some(S::WaitingForObservation { .. }))
                    || self.job.state != JobState::Waiting
                {
                    return false;
                }
                self.job.steps[usize::from(*step)].output = Some(HexBytes(output.clone()));
                self.set_step(*step, S::Done);
                self.resume();
                true
            }
            ResultOp::ManualDone { step } => {
                if !matches!(self.state_of(*step), Some(S::WaitingForManual { .. })) {
                    return false;
                }
                match self.job.state {
                    JobState::Waiting => {
                        self.set_step(*step, S::Done);
                        self.resume();
                        true
                    }
                    JobState::RollingBack => {
                        self.set_step(*step, S::Compensated);
                        true
                    }
                    _ => false,
                }
            }
            ResultOp::Compensated { step } => {
                if !matches!(self.state_of(*step), Some(S::Compensating)) {
                    return false;
                }
                self.set_step(*step, S::Compensated);
                true
            }
            ResultOp::NotCompensable { step } => {
                if !matches!(self.state_of(*step), Some(S::Compensating)) {
                    return false;
                }
                let task = self.undo_task(*step, None);
                self.set_step(
                    *step,
                    S::WaitingForManual {
                        task,
                        deadline: None,
                    },
                );
                true
            }
            ResultOp::CompensationFailed { step, error } => {
                if !matches!(self.state_of(*step), Some(S::Compensating))
                    || self.job.state != JobState::RollingBack
                {
                    return false;
                }
                self.set_step(
                    *step,
                    S::CompensationFailed {
                        error: error.clone(),
                    },
                );
                self.job.error = Some(error.clone());
                // RollingBack accepts Fail.
                let _ = self.job_action(JobAction::Fail);
                true
            }
        }
    }

    fn executed(&mut self, step: u16, outcome: &StepOutcome) -> bool {
        if !matches!(self.state_of(step), Some(StepState::Running))
            || self.job.state != JobState::Running
        {
            return false;
        }
        match outcome {
            StepOutcome::Done { output } => {
                self.job.steps[usize::from(step)].output =
                    output.as_ref().map(|bytes| HexBytes(bytes.to_vec()));
                self.set_step(step, StepState::Done);
            }
            StepOutcome::Skip => self.set_step(step, StepState::Skipped),
            StepOutcome::Manual(task) => {
                self.set_step(
                    step,
                    StepState::WaitingForManual {
                        task: task.clone(),
                        deadline: None,
                    },
                );
                self.wait();
            }
            StepOutcome::Wait {
                condition,
                deadline,
            } => {
                self.set_step(
                    step,
                    StepState::WaitingForObservation {
                        condition: condition.clone(),
                        deadline: *deadline,
                    },
                );
                self.wait();
            }
        }
        true
    }

    fn wait(&mut self) {
        if self.job.state == JobState::Running {
            let _ = self.job_action(JobAction::Wait);
        }
    }

    fn resume(&mut self) {
        if self.job.state == JobState::Waiting {
            let _ = self.job_action(JobAction::Resume);
        }
    }

    fn fail_running(&mut self, step: u16, error: CodedError) -> bool {
        if !matches!(self.state_of(step), Some(StepState::Running))
            || self.job.state != JobState::Running
        {
            return false;
        }
        self.set_step(
            step,
            StepState::Failed {
                error: error.clone(),
            },
        );
        self.roll_back(error, JobAction::RollBack);
        true
    }

    fn roll_back(&mut self, error: CodedError, action: JobAction) {
        if self.job.error.is_none() || action == JobAction::Cancel {
            self.job.error = Some(error);
        }
        // Running and Waiting accept RollBack and Cancel.
        let _ = self.job_action(action);
    }

    /// The first step that is neither done nor skipped.
    pub fn current_step(&self) -> Option<u16> {
        self.job
            .steps
            .iter()
            .position(|record| !matches!(record.state, StepState::Done | StepState::Skipped))
            .and_then(|index| u16::try_from(index).ok())
    }

    /// When the job times out: the first step's start plus the job timeout.
    pub fn job_deadline(&self) -> Option<Timestamp> {
        let started = self.job.steps.first()?.started?;
        started.checked_add(self.job.spec.timeout)
    }

    /// The deadline of a manual task: its step timeout from the first start, capped by the
    /// job deadline.
    fn manual_deadline(&self, step: u16) -> Option<Timestamp> {
        let index = usize::from(step);
        let own = self.job.spec.steps[index]
            .timeout
            .zip(self.job.steps[index].started)
            .and_then(|(timeout, started)| started.checked_add(timeout));
        earliest(own, self.job_deadline())
    }

    /// The deadline of an `execute` call starting now.
    pub fn execute_deadline(&self, step: u16) -> Option<Timestamp> {
        let timeout = self.job.spec.steps[usize::from(step)]
            .timeout
            .unwrap_or(self.job.spec.timeout);
        earliest(self.now.checked_add(timeout), self.job_deadline())
    }

    /// Aborts the current step if it was running or waiting.
    fn abort_current(&mut self, error: &CodedError) {
        if let Some(step) = self.current_step()
            && matches!(
                self.state_of(step),
                Some(
                    StepState::Running
                        | StepState::WaitingForObservation { .. }
                        | StepState::WaitingForManual { .. }
                )
            )
        {
            self.set_step(
                step,
                StepState::Failed {
                    error: error.clone(),
                },
            );
        }
    }

    fn undo_task(&self, step: u16, instruction: Option<&ManualTask>) -> ManualTask {
        let index = usize::from(step);
        match instruction {
            Some(task) => ManualTask {
                instruction: task.undo.clone().unwrap_or(UNDO_STEP),
                args: task.args.clone(),
                undo: None,
            },
            None => ManualTask {
                instruction: UNDO_STEP,
                args: BTreeMap::from([
                    ("step".to_owned(), step.to_string()),
                    ("kind".to_owned(), self.job.steps[index].kind.to_string()),
                ]),
                undo: None,
            },
        }
    }

    /// Takes every decision that needs no handler and stops at the next boundary.
    pub fn advance(&mut self) -> Boundary {
        loop {
            match self.job.state {
                JobState::Queued => {
                    self.job.runner = self.runner;
                    let _ = self.job_action(JobAction::Start);
                }
                JobState::Running => {
                    if let Some(boundary) = self.advance_running() {
                        return boundary;
                    }
                }
                JobState::Waiting => {
                    if let Some(boundary) = self.advance_waiting() {
                        return boundary;
                    }
                }
                JobState::RollingBack => return self.advance_rollback(),
                JobState::Succeeded
                | JobState::Failed
                | JobState::RolledBack
                | JobState::Cancelled => {
                    return Boundary::Terminal;
                }
            }
        }
    }

    fn advance_running(&mut self) -> Option<Boundary> {
        if self.job.cancel_requested.is_some() {
            self.abort_current(&cancelled());
            self.roll_back(cancelled(), JobAction::Cancel);
            return None;
        }
        if self
            .job_deadline()
            .is_some_and(|deadline| self.now >= deadline)
        {
            let error = JobError::Timeout.to_coded_error();
            self.abort_current(&error);
            self.roll_back(error, JobAction::RollBack);
            return None;
        }
        let Some(step) = self.current_step() else {
            let _ = self.job_action(JobAction::Complete);
            return Some(Boundary::Terminal);
        };
        let index = usize::from(step);
        match self.job.steps[index].state.clone() {
            StepState::Pending => {
                let record = &mut self.job.steps[index];
                record.attempts = record.attempts.saturating_add(1);
                record.started.get_or_insert(self.now);
                self.set_step(step, StepState::Running);
                Some(Boundary::Execute { step })
            }
            StepState::Running => {
                let kind = self.job.steps[index].kind.clone();
                match (self.handlers)(&kind) {
                    Some(HandlerInfo { idempotent: true }) => {
                        let record = &mut self.job.steps[index];
                        record.attempts = record.attempts.saturating_add(1);
                        self.set_step(step, StepState::Running);
                        Some(Boundary::Execute { step })
                    }
                    Some(HandlerInfo { idempotent: false }) => {
                        let error = interrupted(step);
                        self.set_step(
                            step,
                            StepState::Failed {
                                error: error.clone(),
                            },
                        );
                        self.roll_back(error, JobAction::RollBack);
                        None
                    }
                    None => {
                        let error = JobError::UnknownStepKind(kind).to_coded_error();
                        self.set_step(
                            step,
                            StepState::Failed {
                                error: error.clone(),
                            },
                        );
                        self.roll_back(error, JobAction::RollBack);
                        None
                    }
                }
            }
            StepState::Failed { error } => {
                self.roll_back(error, JobAction::RollBack);
                None
            }
            StepState::WaitingForObservation { .. } | StepState::WaitingForManual { .. } => {
                let _ = self.job_action(JobAction::Wait);
                None
            }
            StepState::Compensating
            | StepState::Compensated
            | StepState::CompensationFailed { .. }
            | StepState::Done
            | StepState::Skipped => {
                let error = CodedError::internal(format!(
                    "step {step} is in a rollback state while the job runs"
                ));
                self.roll_back(error, JobAction::RollBack);
                None
            }
        }
    }

    fn advance_waiting(&mut self) -> Option<Boundary> {
        if self.job.cancel_requested.is_some() {
            self.abort_current(&cancelled());
            self.roll_back(cancelled(), JobAction::Cancel);
            return None;
        }
        let Some(step) = self.current_step() else {
            // Every step finished: carry on to completion.
            let _ = self.job_action(JobAction::Resume);
            return None;
        };
        let deadline = match self.state_of(step) {
            Some(StepState::WaitingForObservation { deadline, .. }) => {
                earliest(Some(*deadline), self.job_deadline())
            }
            Some(StepState::WaitingForManual { .. }) => self.manual_deadline(step),
            _ => {
                // The waiting step finished: carry on.
                let _ = self.job_action(JobAction::Resume);
                return None;
            }
        };
        match deadline {
            Some(deadline) if self.now >= deadline => {
                let error = if self.job_deadline().is_some_and(|job| job <= deadline) {
                    JobError::Timeout.to_coded_error()
                } else {
                    deadline_passed(step)
                };
                self.abort_current(&error);
                self.roll_back(error, JobAction::RollBack);
                None
            }
            deadline => Some(Boundary::Park { deadline }),
        }
    }

    fn advance_rollback(&mut self) -> Boundary {
        let mut undo_pending = false;
        for step in (0..self.job.steps.len()).rev() {
            let Ok(step) = u16::try_from(step) else {
                continue;
            };
            let manual = self.manual_tasks.get(&step);
            let effects = match self.state_of(step) {
                Some(
                    StepState::Done | StepState::Running | StepState::WaitingForObservation { .. },
                ) => true,
                Some(StepState::Failed { error }) => ABORT_CODES.contains(&error.code.as_ref()),
                Some(StepState::Compensating) => {
                    // Interrupted while compensating: compensations run again.
                    return Boundary::Compensate { step };
                }
                Some(StepState::WaitingForManual { .. }) => {
                    undo_pending = true;
                    false
                }
                _ => false,
            };
            if !effects {
                continue;
            }
            match manual {
                Some(task) if task.undo.is_some() => {
                    let task = self.undo_task(step, Some(task));
                    self.set_step(
                        step,
                        StepState::WaitingForManual {
                            task,
                            deadline: None,
                        },
                    );
                    undo_pending = true;
                }
                _ => {
                    self.set_step(step, StepState::Compensating);
                    return Boundary::Compensate { step };
                }
            }
        }
        if undo_pending {
            return Boundary::Park { deadline: None };
        }
        let failed = self
            .job
            .steps
            .iter()
            .any(|record| matches!(record.state, StepState::CompensationFailed { .. }));
        let action = if failed {
            JobAction::Fail
        } else if self
            .job
            .error
            .as_ref()
            .is_some_and(|error| error.code == CANCELLED)
        {
            JobAction::FinishCancel
        } else {
            JobAction::FinishRollback
        };
        let _ = self.job_action(action);
        Boundary::Terminal
    }
}

/// The earlier of two optional times.
pub fn earliest(a: Option<Timestamp>, b: Option<Timestamp>) -> Option<Timestamp> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
