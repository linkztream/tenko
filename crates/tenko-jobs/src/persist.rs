//! Loading jobs and turning transitions into audited write batches.
//!
//! Every write of a job is one [`WriteBatch`] that carries:
//!
//! - a version precondition on the job record (absent for a new job), so concurrent
//!   writers never overwrite each other: the loser reloads and decides again;
//! - the new job record, the state index update and one transition row per transition;
//! - one audit draft naming the job and its targets, whose action is the headline
//!   transition of the batch (`jobs.job.<action>` or `jobs.step.<state>`) and whose
//!   details list every transition of the batch (IPAM-17, IAM-18);
//! - the staged writes of the step that produced the transition, if any.

use std::{collections::BTreeMap, net::IpAddr};

use tenko_core::{
    JobId, ObjectRef, Principal, RequestId, Revision, Timestamp,
    audit::{AuditAction, AuditDetails, AuditDraft, AuditOutcome, FieldChange},
    codec::encode_key,
};
use tenko_store::{FailedPrecondition, KeyRange, ReadView, ReadViewExt, StoreError, WriteBatch};

use crate::{
    event::StepStateKind,
    model::{Job, JobAction, JobState, ManualTask, StepState},
    stage::StagedWrite,
    tables::{BY_STATE, BY_TARGET, JOBS, TRANSITIONS, Transition, TransitionEvent},
};

/// Rows read per scan page.
pub(crate) const PAGE: usize = 256;

/// A job as read for a write: the record, its revision and the next log position.
#[derive(Debug, Clone)]
pub(crate) struct Loaded {
    pub job: Job,
    pub revision: Revision,
    pub next_seq: u32,
}

/// Reads a job with its revision and the next transition sequence number.
pub(crate) fn load(view: &dyn ReadView, id: JobId) -> Result<Option<Loaded>, StoreError> {
    let Some((mut job, revision)) = view.get_typed(&JOBS, &id)? else {
        return Ok(None);
    };
    job.revision = revision;
    let last = view.scan(
        TRANSITIONS.name(),
        KeyRange::prefix(encode_key(&id)),
        1,
        true,
    )?;
    let next_seq = match last.first() {
        Some((key, _)) => TRANSITIONS.decode_key(key)?.1.saturating_add(1),
        None => 0,
    };
    Ok(Some(Loaded {
        job,
        revision,
        next_seq,
    }))
}

/// Every transition row of a job, in log order.
pub(crate) fn transitions(view: &dyn ReadView, id: JobId) -> Result<Vec<Transition>, StoreError> {
    let range = KeyRange::prefix(encode_key(&id));
    let mut rows = Vec::new();
    let mut page = range.clone();
    loop {
        let batch = view.scan_typed(&TRANSITIONS, page.clone(), PAGE, false)?;
        let full = batch.len() == PAGE;
        let last = batch.last().map(|(key, _, _)| TRANSITIONS.key(key));
        rows.extend(batch.into_iter().map(|(_, row, _)| row));
        match last {
            Some(last) if full => page = range.clone().after(last),
            _ => return Ok(rows),
        }
    }
}

/// The manual tasks steps asked for while the job ran forward (not undo tasks), by step;
/// a later task of the same step replaces an earlier one.
pub(crate) fn forward_manual_tasks(rows: &[Transition]) -> BTreeMap<u16, ManualTask> {
    rows.iter()
        .filter(|row| row.state != JobState::RollingBack)
        .filter_map(|row| match (&row.step, &row.step_state) {
            (Some(step), Some(StepState::WaitingForManual { task })) => Some((*step, task.clone())),
            _ => None,
        })
        .collect()
}

/// Who and why: the principal, time and request of a write.
#[derive(Debug, Clone)]
pub(crate) struct Author {
    pub principal: Principal,
    pub now: Timestamp,
    pub request: Option<RequestId>,
    pub source_ip: Option<IpAddr>,
}

/// Builds the batch that writes `job` after `before` (`None` creates it) with its rows.
pub(crate) fn batch(
    before: Option<&Loaded>,
    job: &Job,
    mut rows: Vec<Transition>,
    staged: StagedWrite,
    author: &Author,
) -> Result<WriteBatch, StoreError> {
    let mut batch = WriteBatch::new(author.principal.clone(), author.now);
    batch.request = author.request;
    let first_seq = before.map_or(0, |loaded| loaded.next_seq);
    if let Some(loaded) = before {
        batch.expect_typed(&JOBS, &job.id, Some(loaded.revision));
        if loaded.job.state != job.state {
            batch.delete_typed(&BY_STATE, &(loaded.job.state, job.id));
            batch.put_typed(&BY_STATE, &(job.state, job.id), &())?;
        }
    } else {
        batch.expect_typed(&JOBS, &job.id, None);
        batch.put_typed(&BY_STATE, &(job.state, job.id), &())?;
        for target in &job.spec.targets {
            batch.put_typed(&BY_TARGET, &(*target, job.id), &())?;
        }
    }
    let mut stored = job.clone();
    stored.revision = Revision::ZERO;
    batch.put_typed(&JOBS, &job.id, &stored)?;
    let mut seq = first_seq;
    for row in &mut rows {
        row.seq = seq;
        seq = seq.saturating_add(1);
        batch.put_typed(&TRANSITIONS, &(job.id, row.seq), row)?;
    }
    if !rows.is_empty() {
        batch.audit(audit_draft(job, &rows, author.source_ip));
    }
    staged.add_to(&mut batch);
    Ok(batch)
}

/// The audit draft of a batch's transitions.
fn audit_draft(job: &Job, rows: &[Transition], source_ip: Option<IpAddr>) -> AuditDraft {
    let headline = rows
        .iter()
        .rev()
        .find(|row| row.event == TransitionEvent::Job)
        .or_else(|| {
            rows.iter()
                .rev()
                .find(|row| row.event != TransitionEvent::Step)
        })
        .or_else(|| rows.last());
    let action = headline.map_or_else(|| "jobs.job.update".to_owned(), action_name);
    let failed = rows
        .iter()
        .any(|row| matches!(row.action, Some(JobAction::RollBack | JobAction::Fail)));
    let outcome = match (&job.error, failed) {
        (Some(error), true) => AuditOutcome::Failed {
            code: error.code.clone(),
        },
        _ => AuditOutcome::Success,
    };
    let mut objects: Vec<ObjectRef> = vec![job.id.into()];
    objects.extend(job.spec.targets.iter().copied());
    let changes = rows.iter().map(field_change).collect();
    let mut context = BTreeMap::from([("kind".to_owned(), job.spec.kind.to_string())]);
    if let Some(note) = rows.iter().rev().find_map(|row| row.note.clone()) {
        context.insert("note".to_owned(), note);
    }
    if let Some(runner) = rows.iter().rev().find_map(|row| row.runner) {
        context.insert("runner".to_owned(), runner.to_string());
    }
    if failed && let Some(error) = &job.error {
        context.insert("error".to_owned(), error.code.to_string());
    }
    AuditDraft {
        action: AuditAction::new(action)
            .unwrap_or_else(|_| AuditAction::from_static("jobs.job.update")),
        objects,
        outcome,
        source_ip,
        details: AuditDetails { changes, context },
    }
}

fn action_name(row: &Transition) -> String {
    match row.event {
        TransitionEvent::Submitted => "jobs.job.submit".to_owned(),
        TransitionEvent::Claimed => "jobs.job.claim".to_owned(),
        TransitionEvent::CancelRequested => "jobs.job.cancel_request".to_owned(),
        TransitionEvent::Job => format!(
            "jobs.job.{}",
            row.action.map_or("update", JobAction::as_str)
        ),
        TransitionEvent::Step => format!(
            "jobs.step.{}",
            row.step_state
                .as_ref()
                .map_or("update", |state| step_state_name(StepStateKind::from(
                    state
                )))
        ),
    }
}

/// The `snake_case` name of a step state.
pub(crate) const fn step_state_name(kind: StepStateKind) -> &'static str {
    match kind {
        StepStateKind::Pending => "pending",
        StepStateKind::Running => "running",
        StepStateKind::Done => "done",
        StepStateKind::Skipped => "skipped",
        StepStateKind::WaitingForObservation => "waiting_for_observation",
        StepStateKind::WaitingForManual => "waiting_for_manual",
        StepStateKind::Failed => "failed",
        StepStateKind::Compensating => "compensating",
        StepStateKind::Compensated => "compensated",
        StepStateKind::CompensationFailed => "compensation_failed",
    }
}

/// The `snake_case` name of a job state.
pub(crate) const fn job_state_name(state: JobState) -> &'static str {
    match state {
        JobState::Queued => "queued",
        JobState::Running => "running",
        JobState::Waiting => "waiting",
        JobState::RollingBack => "rolling_back",
        JobState::Succeeded => "succeeded",
        JobState::Failed => "failed",
        JobState::RolledBack => "rolled_back",
        JobState::Cancelled => "cancelled",
    }
}

fn field_change(row: &Transition) -> FieldChange {
    match (row.event, row.step) {
        (TransitionEvent::Step, Some(step)) => FieldChange {
            object: None,
            field: format!("steps[{step}].state"),
            old: None,
            new: row
                .step_state
                .as_ref()
                .map(|state| step_state_name(StepStateKind::from(state)).to_owned()),
        },
        (TransitionEvent::Claimed, _) => FieldChange {
            object: None,
            field: "runner".to_owned(),
            old: None,
            new: row.runner.map(|runner| runner.to_string()),
        },
        (TransitionEvent::CancelRequested, _) => FieldChange {
            object: None,
            field: "cancel_requested".to_owned(),
            old: None,
            new: Some("true".to_owned()),
        },
        _ => FieldChange {
            object: None,
            field: "state".to_owned(),
            old: row.from.map(|state| job_state_name(state).to_owned()),
            new: Some(job_state_name(row.state).to_owned()),
        },
    }
}

/// Whether a store error is a failed precondition on the record of job `id`: someone
/// else wrote the job, so the writer reloads and decides again.
pub(crate) fn job_changed(error: &StoreError, id: JobId) -> bool {
    let key = JOBS.key(&id);
    matches!(error, StoreError::PreconditionFailed(failures) if failures.iter().any(|failure| {
        matches!(failure, FailedPrecondition::Version { table, key: failed, .. }
            if table == JOBS.name() && *failed == key)
    }))
}
