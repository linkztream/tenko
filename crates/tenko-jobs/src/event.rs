//! Job events for the `jobs` SSE topic (ADR 0008, IPAM-17).
//!
//! Every job and step transition appends a row to [`TRANSITIONS`] in the same batch as the
//! change, so the store journal carries one changed key per transition. The SSE layer
//! (WP1.7) watches the `jobs` namespace and turns each journal entry into events:
//!
//! - as plain references, a change of [`JOBS`](crate::tables::JOBS) names the job
//!   (`{ "kind": "job", "id": … }`), and the UI refetches the job;
//! - with [`JobEvent::from_change_set`], each new transition row becomes a [`JobEvent`]
//!   carrying the job id, the job state, the step index and the step state, which is
//!   enough for a job panel to update its badges without refetching.
//!
//! Events never carry parameters, outputs, errors or notes: a client that may see the job
//! fetches those through `GET /jobs/{id}`, which is authorized.

use serde::{Deserialize, Serialize};
use tenko_core::{JobId, ObjectRef, Revision};
use tenko_store::{ChangeSet, ReadView, ReadViewExt, StoreError, WatchFilter};
use utoipa::ToSchema;

use crate::{
    model::{JobState, StepState},
    tables::{TRANSITIONS, TransitionEvent},
};

/// The SSE topic of job events.
pub const TOPIC: &str = "jobs";

/// The state of a step without its data, for events and summaries.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum StepStateKind {
    /// Not started.
    Pending,
    /// Executing.
    Running,
    /// Finished.
    Done,
    /// Skipped by its handler.
    Skipped,
    /// Waiting for an observation.
    WaitingForObservation,
    /// Waiting for a person (a manual task or a manual undo task).
    WaitingForManual,
    /// Failed.
    Failed,
    /// Being compensated.
    Compensating,
    /// Compensated.
    Compensated,
    /// Compensation failed.
    CompensationFailed,
}

impl From<&StepState> for StepStateKind {
    fn from(state: &StepState) -> Self {
        match state {
            StepState::Pending => StepStateKind::Pending,
            StepState::Running => StepStateKind::Running,
            StepState::Done => StepStateKind::Done,
            StepState::Skipped => StepStateKind::Skipped,
            StepState::WaitingForObservation { .. } => StepStateKind::WaitingForObservation,
            StepState::WaitingForManual { .. } => StepStateKind::WaitingForManual,
            StepState::Failed { .. } => StepStateKind::Failed,
            StepState::Compensating => StepStateKind::Compensating,
            StepState::Compensated => StepStateKind::Compensated,
            StepState::CompensationFailed { .. } => StepStateKind::CompensationFailed,
        }
    }
}

/// One job or step transition, as the `jobs` SSE topic carries it.
///
/// JSON: `{ "job": "0190…", "seq": 4, "state": "waiting", "step": 4,
/// "step_state": "waiting_for_observation", "revision": 4712 }`. The SSE event id is
/// `revision`; the object reference of the event is [`JobEvent::object`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JobEvent {
    /// The job.
    pub job: JobId,
    /// Position of the transition in the job's log.
    pub seq: u32,
    /// The job state after the transition.
    pub state: JobState,
    /// The step that changed, for step transitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<u16>,
    /// The step state after the transition, for step transitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_state: Option<StepStateKind>,
    /// The store revision that committed the transition.
    pub revision: Revision,
}

impl JobEvent {
    /// The reference to the job.
    pub fn object(&self) -> ObjectRef {
        self.job.into()
    }

    /// The watch filter that selects the changes [`from_change_set`](Self::from_change_set)
    /// turns into events.
    pub fn watch_filter() -> WatchFilter {
        WatchFilter::tables([TRANSITIONS.name().clone()])
    }

    /// The events of one journal entry: one per new transition row, in log order.
    /// `view` may read at the entry's revision or any later one, since rows never change.
    /// Rows that no longer exist (purged jobs) are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Codec`] if a key or row does not decode, or a storage error.
    pub fn from_change_set(
        changes: &ChangeSet,
        view: &dyn ReadView,
    ) -> Result<Vec<JobEvent>, StoreError> {
        let mut events = Vec::new();
        for change in &changes.changes {
            if change.deleted || &change.table != TRANSITIONS.name() {
                continue;
            }
            let key = TRANSITIONS.decode_key(&change.key)?;
            let Some((row, _)) = view.get_typed(&TRANSITIONS, &key)? else {
                continue;
            };
            let step_event = row.event == TransitionEvent::Step;
            events.push(JobEvent {
                job: key.0,
                seq: key.1,
                state: row.state,
                step: row.step,
                step_state: row
                    .step_state
                    .as_ref()
                    .filter(|_| step_event)
                    .map(StepStateKind::from),
                revision: changes.revision,
            });
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{ObjectKind, Principal, SystemComponent, Timestamp};
    use tenko_store::{MemStore, Store, WriteBatch};

    use super::*;
    use crate::tables::Transition;

    #[tokio::test]
    async fn transition_rows_become_events() {
        let store = MemStore::default();
        let job = JobId::generate();
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Jobs), Timestamp::now());
        for (seq, event, step) in [
            (0, TransitionEvent::Job, None),
            (1, TransitionEvent::Step, Some(0)),
        ] {
            let row = Transition {
                seq,
                at: Timestamp::now(),
                by: Principal::system(SystemComponent::Jobs),
                request: None,
                event,
                action: None,
                from: None,
                state: JobState::Running,
                step,
                step_state: step.map(|_| StepState::Running),
                runner: None,
                note: None,
            };
            batch
                .put_typed(&TRANSITIONS, &(job, seq), &row)
                .expect("row");
        }
        let committed = store.propose(batch).await.expect("commit");
        let mut watch = store
            .watch(Some(Revision::ZERO), JobEvent::watch_filter())
            .expect("watch");
        let changes = futures::StreamExt::next(&mut watch)
            .await
            .expect("entry")
            .expect("change set");
        let view = store
            .read(tenko_store::ReadConsistency::Local)
            .await
            .expect("view");
        let events = JobEvent::from_change_set(&changes, view.as_ref()).expect("events");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].step_state, None);
        assert_eq!(events[1].step, Some(0));
        assert_eq!(events[1].step_state, Some(StepStateKind::Running));
        assert!(
            events
                .iter()
                .all(|e| e.revision == committed.revision && e.job == job)
        );
        assert_eq!(events[0].object().kind, ObjectKind::Job);
        let json = serde_json::to_value(&events[1]).expect("json");
        assert_eq!(json["state"], "running");
        assert_eq!(json["step_state"], "running");
        let json = serde_json::to_value(&events[0]).expect("json");
        assert!(json.get("step").is_none());
    }
}
