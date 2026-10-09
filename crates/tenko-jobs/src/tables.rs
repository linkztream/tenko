//! The `jobs.*` tables and the records stored in them.
//!
//! | Table | Key | Value | Written |
//! |---|---|---|---|
//! | [`JOBS`] | job id | [`Job`] | at every transition |
//! | [`TRANSITIONS`] | job id, sequence number | [`Transition`] | appended at every transition |
//! | [`BY_STATE`] | job state, job id | nothing | when the state changes |
//! | [`BY_TARGET`] | target, job id | nothing | at submission |
//! | [`PREVIEWS`] | job id | [`JobPreview`] | at submission |
//! | [`IDEMPOTENCY`] | principal subject, key | job id | at submission (API-04) |
//! | [`RUNNERS`] | node id | [`RunnerLease`] | by each runner while it owns jobs |
//!
//! Job ids are UUIDv7, so every job-keyed scan runs in submission order. Transition rows
//! are append-only: a reader may fetch the row of a journal change at any later revision
//! and still see what the change wrote.

use serde::{Deserialize, Serialize};
use tenko_core::{
    JobId, NodeId, ObjectRef, Principal, RequestId, Timestamp,
    codec::{KeyCodec, KeyError},
    table::TableDef,
};
use utoipa::ToSchema;

use crate::model::{Job, JobAction, JobPreview, JobState, StepState};

/// Jobs by id.
pub const JOBS: TableDef<JobId, Job> = TableDef::new("jobs.jobs");
/// The transition log of every job: the source of `jobs` events.
pub const TRANSITIONS: TableDef<(JobId, u32), Transition> = TableDef::new("jobs.transitions");
/// Jobs by state, for the runner and for state filters.
pub const BY_STATE: TableDef<(JobState, JobId), ()> = TableDef::new("jobs.by_state");
/// Jobs by target object, for target filters.
pub const BY_TARGET: TableDef<(ObjectRef, JobId), ()> = TableDef::new("jobs.by_target");
/// The preview computed at submission.
pub const PREVIEWS: TableDef<JobId, JobPreview> = TableDef::new("jobs.previews");
/// Jobs by the idempotency key of their submission: principal subject and key.
pub const IDEMPOTENCY: TableDef<(String, String), JobId> = TableDef::new("jobs.idempotency");
/// Runner leases by node.
pub const RUNNERS: TableDef<NodeId, RunnerLease> = TableDef::new("jobs.runners");

impl KeyCodec for JobState {
    fn encode_key(&self, out: &mut Vec<u8>) {
        state_code(*self).encode_key(out);
    }

    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        let code = u8::decode_key(input)?;
        JobState::ALL
            .into_iter()
            .find(|state| state_code(*state) == code)
            .ok_or(KeyError::Invalid("unknown job state"))
    }
}

/// The stable key byte of a state.
const fn state_code(state: JobState) -> u8 {
    match state {
        JobState::Queued => 0,
        JobState::Running => 1,
        JobState::Waiting => 2,
        JobState::RollingBack => 3,
        JobState::Succeeded => 4,
        JobState::Failed => 5,
        JobState::RolledBack => 6,
        JobState::Cancelled => 7,
    }
}

/// What a transition row records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransitionEvent {
    /// The job was accepted (state `queued`).
    Submitted,
    /// The job changed state through [`Transition::action`].
    Job,
    /// A step changed state ([`Transition::step`], [`Transition::step_state`]).
    Step,
    /// A runner took the job over ([`Transition::runner`]).
    Claimed,
    /// Someone asked to cancel; the runner acts on it at the next step boundary.
    CancelRequested,
}

/// One row of a job's transition log. Every transition is also part of an audited write
/// batch (IPAM-17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Transition {
    /// Position in the job's log, from 0.
    pub seq: u32,
    /// When it happened.
    pub at: Timestamp,
    /// Who caused it: the submitting or acting principal, or the job engine.
    pub by: Principal,
    /// The request, when a request caused it.
    #[serde(default)]
    pub request: Option<RequestId>,
    /// What happened.
    pub event: TransitionEvent,
    /// The job action, for [`TransitionEvent::Job`]: `start`, `wait`, `resume`, `complete`,
    /// `roll_back`, `cancel`, `finish_rollback`, `finish_cancel` or `fail`.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub action: Option<JobAction>,
    /// The job state before, for [`TransitionEvent::Job`].
    #[serde(default)]
    pub from: Option<JobState>,
    /// The job state after the transition.
    pub state: JobState,
    /// The step, for [`TransitionEvent::Step`].
    #[serde(default)]
    pub step: Option<u16>,
    /// The step state after the transition, for [`TransitionEvent::Step`].
    #[serde(default)]
    pub step_state: Option<StepState>,
    /// The runner, for [`TransitionEvent::Claimed`] and the start of a job.
    #[serde(default)]
    pub runner: Option<NodeId>,
    /// The note of a completed manual task.
    #[serde(default)]
    pub note: Option<String>,
}

/// A runner's claim on the jobs it owns: other runners take those jobs over once the
/// lease has expired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerLease {
    /// The node.
    pub node: NodeId,
    /// When the lease was last renewed.
    pub renewed: Timestamp,
    /// When the lease expires unless renewed.
    pub expires: Timestamp,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tenko_core::{
        CodedError, HostId, MessageKey, SystemComponent, VrfId,
        codec::{decode_key, encode_key, from_cbor, to_cbor},
    };

    use super::*;
    use crate::model::{ManualTask, ObservationCondition, ObservedPredicate};

    #[test]
    fn state_keys_round_trip_and_are_distinct() {
        let mut seen = std::collections::BTreeSet::new();
        for state in JobState::ALL {
            let key = encode_key(&state);
            assert_eq!(decode_key::<JobState>(&key), Ok(state));
            assert!(seen.insert(key));
        }
        assert!(decode_key::<JobState>(&[9]).is_err());
    }

    fn row(seq: u32, event: TransitionEvent, state: JobState) -> Transition {
        Transition {
            seq,
            at: "2026-10-09T12:00:00Z".parse().expect("time"),
            by: Principal::system(SystemComponent::Jobs),
            request: None,
            event,
            action: None,
            from: None,
            state,
            step: None,
            step_state: None,
            runner: None,
            note: None,
        }
    }

    #[test]
    fn transitions_round_trip_through_cbor_and_json() {
        let waiting = Transition {
            request: Some(RequestId::generate()),
            step: Some(1),
            step_state: Some(StepState::WaitingForObservation {
                condition: ObservationCondition {
                    subject: HostId::generate().into(),
                    any_of: vec![ObservedPredicate::AddressSeen {
                        vrf: VrfId::generate(),
                        ip: "192.0.2.10".parse().expect("ip"),
                        mac: None,
                    }],
                },
                deadline: "2026-10-09T13:00:00Z".parse().expect("time"),
            }),
            runner: Some(NodeId(1)),
            ..row(3, TransitionEvent::Step, JobState::Waiting)
        };
        let rolling_back = Transition {
            action: Some(JobAction::RollBack),
            from: Some(JobState::Waiting),
            step: Some(2),
            step_state: Some(StepState::WaitingForManual {
                task: ManualTask {
                    instruction: MessageKey::from_static("jobs.undo.step"),
                    args: BTreeMap::from([("step".to_owned(), "2".to_owned())]),
                    undo: None,
                },
                deadline: None,
            }),
            note: Some("done by hand".to_owned()),
            ..row(4, TransitionEvent::Job, JobState::RollingBack)
        };
        let failed = Transition {
            step: Some(0),
            step_state: Some(StepState::Failed {
                error: CodedError::new("jobs.step.timeout", 504, "late"),
            }),
            ..row(5, TransitionEvent::Step, JobState::RollingBack)
        };
        for transition in [waiting, rolling_back, failed] {
            let back: Transition = from_cbor(&to_cbor(&transition).expect("cbor")).expect("cbor");
            assert_eq!(back, transition);
            let json = serde_json::to_value(&transition).expect("json");
            assert_eq!(
                serde_json::from_value::<Transition>(json).expect("json"),
                transition
            );
        }
    }

    #[test]
    fn leases_round_trip_through_cbor() {
        let lease = RunnerLease {
            node: NodeId(2),
            renewed: "2026-10-09T12:00:00Z".parse().expect("time"),
            expires: "2026-10-09T12:00:30Z".parse().expect("time"),
        };
        let back: RunnerLease = from_cbor(&to_cbor(&lease).expect("cbor")).expect("cbor");
        assert_eq!(back, lease);
    }
}
