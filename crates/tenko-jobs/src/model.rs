//! The job model (plan section 2.6, IPAM-17, IPAM-19): specifications, persisted state,
//! step handlers and the job state machine. The engine (WP1.6) builds on these types.
//!
//! # Job states
//!
//! [`JobState::transition`] is the complete table; anything not listed is refused.
//!
//! | From | Action | To |
//! |---|---|---|
//! | `Queued` | `Start` | `Running` |
//! | `Queued` | `Cancel` | `Cancelled` |
//! | `Running` | `Wait` | `Waiting` |
//! | `Running` | `Complete` | `Succeeded` |
//! | `Running` | `RollBack` | `RollingBack` |
//! | `Running` | `Cancel` | `RollingBack` |
//! | `Waiting` | `Resume` | `Running` |
//! | `Waiting` | `RollBack` | `RollingBack` |
//! | `Waiting` | `Cancel` | `RollingBack` |
//! | `RollingBack` | `FinishRollback` | `RolledBack` |
//! | `RollingBack` | `FinishCancel` | `Cancelled` |
//! | `RollingBack` | `Fail` | `Failed` |
//!
//! A step returning `Wait` or `Manual` holds the job in `Waiting` until the observation
//! matches, the manual task is completed or the deadline passes. A failed step, a passed
//! deadline or the job timeout starts `RollingBack`: finished steps are compensated in
//! reverse, and steps that cannot be compensated become manual undo tasks. A rollback
//! that completes ends in `RolledBack` ("move failed", IPAM-19), or in `Cancelled` when a
//! cancel started it; a compensation that fails ends in `Failed` (an operator is needed).
//! `Succeeded`, `Failed`, `RolledBack` and `Cancelled` are final. Each transition is an
//! audited store write and a `jobs` SSE event; after a restart only
//! [`StepHandler::idempotent`] steps run again, and a job interrupted in a non-idempotent
//! step rolls back. A single edit is an inline one-step job (Q4).

use std::{collections::BTreeMap, fmt, net::IpAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    Coded, CodedError, IdempotencyKey, JobId, MacAddr, MessageKey, NodeId, ObjectRef, PrefixId,
    RequestCtx, Revision, Timestamp, VrfId,
    error::InvalidValue,
    ipam::Stamp,
    observe::{Observation, Observed},
    serde_util::{HexBytes, duration_ms, option_duration_ms},
};
use tenko_store::{ReadView, Store, StoreError};
use utoipa::ToSchema;

tenko_core::namespaced_name! {
    /// What a job does, namespaced by owning area: `ipam.edit`, `import.apply`,
    /// `ipam.move`.
    JobKind, "job kind"
}

tenko_core::namespaced_name! {
    /// What a step does, namespaced by owning area; one [`StepHandler`] per kind:
    /// `ipam.write`, `jobs.manual`, `connect.unifi.set_client_vlan`.
    StepKind, "step kind"
}

/// Groups jobs that share a parallelism limit, for example every write through one
/// network controller (CONN-09): 1 to 128 visible ASCII characters.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "String", into = "String")]
#[schema(value_type = String)]
pub struct GroupKey(String);

impl GroupKey {
    /// Validates a group key.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] if the key is empty, too long or not visible ASCII.
    pub fn new(key: impl Into<String>) -> Result<Self, InvalidValue> {
        let key = key.into();
        if (1..=128).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_graphic()) {
            Ok(Self(key))
        } else {
            Err(InvalidValue::new(
                "group key",
                &key,
                "must be 1 to 128 visible ASCII characters",
            ))
        }
    }

    /// The key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for GroupKey {
    type Error = InvalidValue;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<GroupKey> for String {
    fn from(key: GroupKey) -> Self {
        key.0
    }
}

impl fmt::Debug for GroupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroupKey({:?})", self.0)
    }
}

impl fmt::Display for GroupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What to run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JobSpec {
    /// The kind of job.
    pub kind: JobKind,
    /// Translatable title.
    pub title: MessageKey,
    /// The objects the job changes.
    pub targets: Vec<ObjectRef>,
    /// The steps, run in order.
    pub steps: Vec<StepSpec>,
    /// Overall timeout; passing it starts the rollback.
    #[serde(with = "duration_ms")]
    #[schema(value_type = u64)]
    pub timeout: Duration,
    /// Parallelism group (CONN-09).
    #[serde(default)]
    pub group: Option<GroupKey>,
    /// Parallelism of the job's group when the engine has no configured limit for it; the
    /// jobs of one group carry the same value (a move job group, IPAM-19, CONN-09).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_limit: Option<u32>,
    /// Idempotency key of the submitting request (API-04).
    #[serde(default)]
    pub idempotency: Option<IdempotencyKey>,
    /// The controller that must run the job when its steps are tied to one host, such as
    /// the install of a release that this controller downloaded (Slice 3). `None`, the
    /// default, lets the job runner of the leader run it wherever that is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeId>,
}

/// One step of a job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StepSpec {
    /// The handler kind.
    pub kind: StepKind,
    /// Handler parameters as CBOR, opaque to the engine.
    pub params: HexBytes,
    /// Step timeout; `None` uses the job timeout.
    #[serde(default, with = "option_duration_ms")]
    #[schema(value_type = Option<u64>)]
    pub timeout: Option<Duration>,
}

/// A job as stored and shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Job {
    /// Identifier.
    pub id: JobId,
    /// What runs.
    pub spec: JobSpec,
    /// Current state.
    pub state: JobState,
    /// One record per step of the spec, same order.
    pub steps: Vec<StepRecord>,
    /// Submission.
    pub created: Stamp,
    /// When the first step started (`None` while queued).
    #[serde(default)]
    pub started: Option<Timestamp>,
    /// The controller running the job (lease holder).
    #[serde(default)]
    pub runner: Option<NodeId>,
    /// Store revision of the last write (filled from the read, like `Meta::revision`).
    #[serde(default)]
    pub revision: Revision,
    /// Who asked to cancel, and when.
    #[serde(default)]
    pub cancel_requested: Option<Stamp>,
    /// Why the job is rolling back, failed or was cancelled.
    #[serde(default)]
    pub error: Option<CodedError>,
    /// When the job reached a final state.
    #[serde(default)]
    pub finished: Option<Timestamp>,
}

/// Persisted state of one step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StepRecord {
    /// Position in the spec.
    pub index: u16,
    /// The handler kind.
    pub kind: StepKind,
    /// Current state.
    pub state: StepState,
    /// Executions started so far.
    #[serde(default)]
    pub attempts: u32,
    /// First start.
    #[serde(default)]
    pub started: Option<Timestamp>,
    /// Reaching `Done`, `Skipped`, `Compensated` or a failure.
    #[serde(default)]
    pub finished: Option<Timestamp>,
    /// Output of `execute`, passed to `compensate`.
    #[serde(default)]
    pub output: Option<HexBytes>,
}

/// States of a job.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Accepted, not started.
    Queued,
    /// Executing steps.
    Running,
    /// Held by a step waiting for an observation or a manual task.
    Waiting,
    /// Compensating finished steps in reverse.
    RollingBack,
    /// Every step finished.
    Succeeded,
    /// A compensation failed; an operator is needed.
    Failed,
    /// Rolled back after a failure or a deadline.
    RolledBack,
    /// Cancelled, before start or after rolling back.
    Cancelled,
}

/// Events that move a job between states.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum JobAction {
    /// The engine starts a queued job.
    Start,
    /// A step returned `Wait` or `Manual`.
    Wait,
    /// The awaited observation arrived or the manual task was completed.
    Resume,
    /// The last step finished.
    Complete,
    /// A step failed, a deadline passed or the job timed out.
    RollBack,
    /// An operator cancelled the job.
    Cancel,
    /// Every compensation finished after a failure.
    FinishRollback,
    /// Every compensation finished after a cancel.
    FinishCancel,
    /// A compensation failed.
    Fail,
}

impl JobAction {
    /// Every action.
    pub const ALL: [JobAction; 9] = [
        JobAction::Start,
        JobAction::Wait,
        JobAction::Resume,
        JobAction::Complete,
        JobAction::RollBack,
        JobAction::Cancel,
        JobAction::FinishRollback,
        JobAction::FinishCancel,
        JobAction::Fail,
    ];

    /// The stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            JobAction::Start => "start",
            JobAction::Wait => "wait",
            JobAction::Resume => "resume",
            JobAction::Complete => "complete",
            JobAction::RollBack => "roll_back",
            JobAction::Cancel => "cancel",
            JobAction::FinishRollback => "finish_rollback",
            JobAction::FinishCancel => "finish_cancel",
            JobAction::Fail => "fail",
        }
    }
}

impl JobState {
    /// Every state.
    pub const ALL: [JobState; 8] = [
        JobState::Queued,
        JobState::Running,
        JobState::Waiting,
        JobState::RollingBack,
        JobState::Succeeded,
        JobState::Failed,
        JobState::RolledBack,
        JobState::Cancelled,
    ];

    /// The state an action leads to, or `None` if the action is not allowed (see the
    /// table in the module documentation).
    pub const fn transition(self, action: JobAction) -> Option<JobState> {
        use JobAction as A;
        use JobState as S;
        match (self, action) {
            (S::Queued, A::Start) | (S::Waiting, A::Resume) => Some(S::Running),
            (S::Queued, A::Cancel) | (S::RollingBack, A::FinishCancel) => Some(S::Cancelled),
            (S::Running, A::Wait) => Some(S::Waiting),
            (S::Running, A::Complete) => Some(S::Succeeded),
            (S::Running | S::Waiting, A::RollBack | A::Cancel) => Some(S::RollingBack),
            (S::RollingBack, A::FinishRollback) => Some(S::RolledBack),
            (S::RollingBack, A::Fail) => Some(S::Failed),
            _ => None,
        }
    }

    /// Whether the action is allowed in this state.
    pub const fn can(self, action: JobAction) -> bool {
        self.transition(action).is_some()
    }

    /// Applies an action.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::InvalidTransition`] if the action is not allowed.
    pub fn apply(self, action: JobAction) -> Result<JobState, JobError> {
        self.transition(action).ok_or(JobError::InvalidTransition {
            from: self,
            action: action.as_str(),
        })
    }

    /// Whether the state is final.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            JobState::Succeeded | JobState::Failed | JobState::RolledBack | JobState::Cancelled
        )
    }
}

/// States of a step.
///
/// Adjacently tagged (`{"state": "...", "data": {...}}`) because waiting states carry
/// IP addresses (see the encoding rules in `tenko_core::codec`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "state", content = "data", rename_all = "snake_case")]
pub enum StepState {
    /// Not started.
    Pending,
    /// Executing.
    Running,
    /// Finished.
    Done,
    /// Skipped by its handler.
    Skipped,
    /// Waiting for an observation.
    WaitingForObservation {
        /// What must be observed.
        condition: ObservationCondition,
        /// When waiting stops and the job rolls back.
        deadline: Timestamp,
    },
    /// Waiting for a person.
    WaitingForManual {
        /// The task.
        task: ManualTask,
        /// When waiting stops and the job rolls back (`None`: the step timeout applies).
        #[serde(default)]
        deadline: Option<Timestamp>,
    },
    /// Failed.
    Failed {
        /// The error.
        error: CodedError,
    },
    /// Being compensated.
    Compensating,
    /// Compensated.
    Compensated,
    /// Compensation failed.
    CompensationFailed {
        /// The error.
        error: CodedError,
    },
}

/// What a step handler reports back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// Finished, with an optional output for `compensate`.
    Done {
        /// Output kept in the step record.
        output: Option<Bytes>,
    },
    /// Nothing to do.
    Skip,
    /// A person must act (DHCP and DNS steps in Phase 1, IPAM-19).
    Manual(ManualTask),
    /// Wait until an observation matches.
    Wait {
        /// What must be observed.
        condition: ObservationCondition,
        /// When waiting stops and the job rolls back.
        deadline: Timestamp,
    },
}

/// A task for a person, with translatable text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ManualTask {
    /// What to do.
    pub instruction: MessageKey,
    /// Message arguments (host name, address, VLAN).
    #[serde(default)]
    pub args: BTreeMap<String, String>,
    /// How to undo it, shown when the job rolls back.
    #[serde(default)]
    pub undo: Option<MessageKey>,
}

/// An observation a waiting step needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ObservationCondition {
    /// The object the job waits for (usually the host).
    pub subject: ObjectRef,
    /// Any one of these satisfies the condition.
    pub any_of: Vec<ObservedPredicate>,
}

impl ObservationCondition {
    /// Whether an observation satisfies the condition. `prefix_cidr` resolves prefixes for
    /// [`ObservedPredicate::LeaseInPrefix`].
    pub fn matches(
        &self,
        observation: &Observation,
        prefix_cidr: impl Fn(PrefixId) -> Option<IpNet>,
    ) -> bool {
        self.any_of
            .iter()
            .any(|predicate| predicate.matches(observation, &prefix_cidr))
    }
}

/// One acceptable observation.
///
/// Adjacently tagged because variants carry IP addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ObservedPredicate {
    /// The address answers (ARP, ND or ping), from the given MAC when set.
    AddressSeen {
        /// The VRF.
        vrf: VrfId,
        /// The address.
        #[schema(value_type = String)]
        ip: IpAddr,
        /// The MAC address, when it matters.
        #[serde(default)]
        mac: Option<MacAddr>,
    },
    /// The MAC holds a DHCP lease inside the prefix (Phase 3).
    LeaseInPrefix {
        /// The prefix.
        prefix: PrefixId,
        /// The client.
        mac: MacAddr,
    },
}

impl ObservedPredicate {
    /// Whether an observation satisfies the predicate.
    pub fn matches(
        &self,
        observation: &Observation,
        prefix_cidr: impl Fn(PrefixId) -> Option<IpNet>,
    ) -> bool {
        let Observed::Address {
            vrf: seen_vrf,
            ip: seen_ip,
            mac: seen_mac,
        } = &observation.subject
        else {
            return false;
        };
        match self {
            ObservedPredicate::AddressSeen { vrf, ip, mac } => {
                seen_vrf == vrf && seen_ip == ip && mac.is_none_or(|mac| *seen_mac == Some(mac))
            }
            ObservedPredicate::LeaseInPrefix { prefix, mac } => {
                matches!(
                    observation.source,
                    tenko_core::observe::ObservationSource::DhcpLease { .. }
                ) && *seen_mac == Some(*mac)
                    && prefix_cidr(*prefix).is_some_and(|cidr| cidr.contains(seen_ip))
            }
        }
    }
}

/// What a step would do, for the preview before apply (API-09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StepPreview {
    /// Translatable summary.
    pub summary: MessageKey,
    /// Message arguments.
    #[serde(default)]
    pub args: BTreeMap<String, String>,
    /// Objects the step changes.
    #[serde(default)]
    pub changes: Vec<ObjectRef>,
    /// The manual task the step will ask for.
    #[serde(default)]
    pub manual: Option<ManualTask>,
    /// Warnings such as a `reserved` host without MAC (IPAM-18).
    #[serde(default)]
    pub warnings: Vec<CodedError>,
}

/// What a whole job would do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JobPreview {
    /// One preview per step.
    pub steps: Vec<StepPreview>,
    /// Job-level warnings.
    #[serde(default)]
    pub warnings: Vec<CodedError>,
}

/// What a step handler gets when it runs.
#[derive(Clone)]
pub struct StepContext {
    /// The job.
    pub job: JobId,
    /// The step index.
    pub step: u16,
    /// The execution attempt, from 1.
    pub attempt: u32,
    /// The request the job runs for (principal, time, request id).
    pub request: RequestCtx,
    /// The store, for reads and for the step's own write batches.
    pub store: Arc<dyn Store>,
    /// When the step must be done.
    pub deadline: Option<Timestamp>,
}

impl fmt::Debug for StepContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StepContext")
            .field("job", &self.job)
            .field("step", &self.step)
            .field("attempt", &self.attempt)
            .field("request", &self.request)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// Executes one kind of step. Registered with the engine, one handler per [`StepKind`].
#[async_trait::async_trait]
pub trait StepHandler: Send + Sync + 'static {
    /// The kind this handler runs.
    fn kind(&self) -> StepKind;

    /// Whether the step may run again after a crash interrupted it.
    fn idempotent(&self) -> bool;

    /// Describes what the step would do, without side effects.
    ///
    /// # Errors
    ///
    /// Returns [`StepError`] if the parameters are invalid or a read fails.
    async fn preview(&self, params: &[u8], view: &dyn ReadView) -> Result<StepPreview, StepError>;

    /// Runs the step.
    ///
    /// # Errors
    ///
    /// Returns [`StepError`]; the job then rolls back.
    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError>;

    /// Undoes a finished step, given its output.
    ///
    /// # Errors
    ///
    /// Returns [`StepError::NotCompensable`] to turn the undo into a manual task, or
    /// another error to fail the job.
    async fn compensate(
        &self,
        params: &[u8],
        output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError>;
}

/// A step failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StepError {
    /// The parameters do not decode or are invalid.
    #[error("invalid step parameters: {0}")]
    InvalidParams(String),
    /// A domain or connector error, with its own code.
    #[error("{0}")]
    Coded(Box<CodedError>),
    /// A store error.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The step exceeded its timeout.
    #[error("step timed out")]
    Timeout,
    /// The step cannot be undone automatically; the engine creates a manual undo task.
    #[error("step cannot be compensated automatically")]
    NotCompensable,
}

impl StepError {
    /// Wraps any coded error.
    pub fn coded(error: &(impl Coded + ?Sized)) -> Self {
        StepError::Coded(Box::new(error.to_coded_error()))
    }
}

impl Coded for StepError {
    fn code(&self) -> &'static str {
        match self {
            StepError::InvalidParams(_) => "jobs.step.invalid_params",
            // A captured error keeps its own code; see `to_coded_error`.
            StepError::Coded(_) => "jobs.step.failed",
            StepError::Store(error) => error.code(),
            StepError::Timeout => "jobs.step.timeout",
            StepError::NotCompensable => "jobs.step.not_compensable",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            StepError::InvalidParams(_) => 400,
            StepError::Coded(error) => error.status,
            StepError::Store(error) => error.http_status(),
            StepError::Timeout => 504,
            StepError::NotCompensable => 409,
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            StepError::Store(error) => error.params(),
            _ => BTreeMap::new(),
        }
    }

    fn to_coded_error(&self) -> CodedError {
        match self {
            StepError::Coded(error) => (**error).clone(),
            other => CodedError {
                code: other.code().into(),
                status: other.http_status(),
                title: other.title().into(),
                detail: other.to_string(),
                params: other
                    .params()
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect(),
                errors: Vec::new(),
            },
        }
    }
}

/// A job operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JobError {
    /// No such job.
    #[error("job {0} not found")]
    NotFound(JobId),
    /// The action is not allowed in the job's state.
    #[error("cannot {action} a job that is {from:?}")]
    InvalidTransition {
        /// The current state.
        from: JobState,
        /// The refused action.
        action: &'static str,
    },
    /// No handler is registered for a step kind.
    #[error("no handler for step kind {0}")]
    UnknownStepKind(StepKind),
    /// A step failed.
    #[error(transparent)]
    Step(StepError),
    /// The spec is not valid (empty, inconsistent steps, a bad timeout).
    #[error("invalid job spec: {0}")]
    InvalidSpec(String),
    /// An inline job must have exactly one step.
    #[error("an inline job must have exactly one step")]
    InlineOneStep,
    /// No such step in the job.
    #[error("job {job} has no step {step}")]
    StepNotFound {
        /// The job.
        job: JobId,
        /// The step index.
        step: u16,
    },
    /// A note exceeds the allowed length.
    #[error("note exceeds {max} characters")]
    NoteTooLong {
        /// The limit.
        max: usize,
    },
    /// A store error.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The job exceeded its timeout.
    #[error("job timed out")]
    Timeout,
}

impl Coded for JobError {
    fn code(&self) -> &'static str {
        match self {
            JobError::NotFound(_) => "jobs.not_found",
            JobError::InvalidTransition { .. } => "jobs.invalid_transition",
            JobError::UnknownStepKind(_) => "jobs.unknown_step_kind",
            JobError::Step(error) => error.code(),
            JobError::Store(error) => error.code(),
            JobError::InvalidSpec(_) => "jobs.spec.invalid",
            JobError::InlineOneStep => "jobs.spec.inline_one_step",
            JobError::StepNotFound { .. } => "jobs.step.not_found",
            JobError::NoteTooLong { .. } => "jobs.note.too_long",
            JobError::Timeout => "jobs.timeout",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            JobError::NotFound(_) | JobError::StepNotFound { .. } => 404,
            JobError::InvalidTransition { .. } => 409,
            JobError::UnknownStepKind(_) => 500,
            JobError::Step(error) => error.http_status(),
            JobError::Store(error) => error.http_status(),
            JobError::InvalidSpec(_) | JobError::InlineOneStep | JobError::NoteTooLong { .. } => {
                400
            }
            JobError::Timeout => 504,
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            JobError::NotFound(id) => BTreeMap::from([("job", id.to_string())]),
            JobError::InvalidTransition { from, action } => BTreeMap::from([
                ("from", format!("{from:?}")),
                ("action", (*action).to_owned()),
            ]),
            JobError::UnknownStepKind(kind) => BTreeMap::from([("kind", kind.to_string())]),
            JobError::Step(error) => error.params(),
            JobError::Store(error) => error.params(),
            JobError::InvalidSpec(reason) => BTreeMap::from([("reason", reason.clone())]),
            JobError::StepNotFound { job, step } => {
                BTreeMap::from([("job", job.to_string()), ("step", step.to_string())])
            }
            JobError::NoteTooLong { max } => BTreeMap::from([("max", max.to_string())]),
            JobError::InlineOneStep | JobError::Timeout => BTreeMap::new(),
        }
    }

    fn to_coded_error(&self) -> CodedError {
        match self {
            JobError::Step(error) => error.to_coded_error(),
            other => CodedError {
                code: other.code().into(),
                status: other.http_status(),
                title: other.title().into(),
                detail: other.to_string(),
                params: other
                    .params()
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect(),
                errors: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use tenko_core::{
        HostId, NodeId, ObservationId, Principal, SystemComponent,
        codec::{from_cbor, to_cbor},
        observe::{ObservationSource, ProbeMethod},
    };

    use super::*;

    /// The expected table, written out independently of `transition`.
    fn expected() -> BTreeMap<(JobState, JobAction), JobState> {
        use JobAction as A;
        use JobState as S;
        BTreeMap::from([
            ((S::Queued, A::Start), S::Running),
            ((S::Queued, A::Cancel), S::Cancelled),
            ((S::Running, A::Wait), S::Waiting),
            ((S::Running, A::Complete), S::Succeeded),
            ((S::Running, A::RollBack), S::RollingBack),
            ((S::Running, A::Cancel), S::RollingBack),
            ((S::Waiting, A::Resume), S::Running),
            ((S::Waiting, A::RollBack), S::RollingBack),
            ((S::Waiting, A::Cancel), S::RollingBack),
            ((S::RollingBack, A::FinishRollback), S::RolledBack),
            ((S::RollingBack, A::FinishCancel), S::Cancelled),
            ((S::RollingBack, A::Fail), S::Failed),
        ])
    }

    #[test]
    fn transition_table_is_exactly_the_documented_one() {
        let expected = expected();
        for state in JobState::ALL {
            for action in JobAction::ALL {
                let actual = state.transition(action);
                assert_eq!(
                    actual,
                    expected.get(&(state, action)).copied(),
                    "{state:?} + {action:?}"
                );
                assert_eq!(state.can(action), actual.is_some());
            }
        }
    }

    #[test]
    fn terminal_states_accept_nothing() {
        for state in JobState::ALL.into_iter().filter(|s| s.is_terminal()) {
            assert!(
                JobAction::ALL.into_iter().all(|action| !state.can(action)),
                "{state:?}"
            );
        }
        let terminal: BTreeSet<_> = JobState::ALL
            .into_iter()
            .filter(|s| s.is_terminal())
            .collect();
        assert_eq!(
            terminal,
            BTreeSet::from([
                JobState::Succeeded,
                JobState::Failed,
                JobState::RolledBack,
                JobState::Cancelled
            ])
        );
    }

    #[test]
    fn every_state_reaches_a_terminal_state() {
        for start in JobState::ALL {
            let mut seen = BTreeSet::from([start]);
            let mut frontier = vec![start];
            while let Some(state) = frontier.pop() {
                for action in JobAction::ALL {
                    if let Some(next) = state.transition(action)
                        && seen.insert(next)
                    {
                        frontier.push(next);
                    }
                }
            }
            assert!(
                seen.iter().any(|s| s.is_terminal()),
                "{start:?} cannot finish"
            );
        }
    }

    #[test]
    fn invalid_transitions_are_coded_errors() {
        let error = JobState::Succeeded
            .apply(JobAction::Cancel)
            .expect_err("final");
        assert_eq!(
            error,
            JobError::InvalidTransition {
                from: JobState::Succeeded,
                action: "cancel"
            }
        );
        assert_eq!(error.code(), "jobs.invalid_transition");
        assert_eq!(error.http_status(), 409);
        assert_eq!(error.params()["action"], "cancel");
        assert_eq!(
            JobState::Queued.apply(JobAction::Start),
            Ok(JobState::Running)
        );
    }

    #[test]
    fn step_errors_keep_the_captured_code() {
        let inner = CodedError::new("ipam.prefix.overlap", 409, "overlap");
        let error = JobError::Step(StepError::Coded(Box::new(inner.clone())));
        assert_eq!(error.to_coded_error(), inner);
        assert_eq!(error.http_status(), 409);
        assert_eq!(
            JobError::Step(StepError::Timeout).to_coded_error().code,
            "jobs.step.timeout"
        );
        assert_eq!(
            JobError::Store(StoreError::NoQuorum).code(),
            "sys.store.no_quorum"
        );
    }

    fn observation(
        source: ObservationSource,
        ip: &str,
        mac: Option<&str>,
        vrf: VrfId,
    ) -> Observation {
        Observation {
            id: ObservationId::generate(),
            source,
            subject: Observed::Address {
                vrf,
                ip: ip.parse().expect("ip"),
                mac: mac.map(|m| m.parse().expect("mac")),
            },
            observed_at: "2026-10-09T12:00:00Z".parse().expect("time"),
            received_at: "2026-10-09T12:00:00Z".parse().expect("time"),
            expires_at: None,
        }
    }

    #[test]
    fn predicates_match_observations() {
        let vrf = VrfId::generate();
        let prefix = PrefixId::generate();
        let probe = ObservationSource::Probe {
            node: NodeId(1),
            method: ProbeMethod::Arp,
        };
        let lease = ObservationSource::DhcpLease { node: NodeId(2) };
        let condition = ObservationCondition {
            subject: HostId::generate().into(),
            any_of: vec![
                ObservedPredicate::AddressSeen {
                    vrf,
                    ip: "192.0.2.20".parse().expect("ip"),
                    mac: Some("00:00:5e:00:53:20".parse().expect("mac")),
                },
                ObservedPredicate::LeaseInPrefix {
                    prefix,
                    mac: "00:00:5e:00:53:21".parse().expect("mac"),
                },
            ],
        };
        let cidr = |id: PrefixId| (id == prefix).then(|| "198.51.100.0/24".parse().expect("cidr"));
        let seen = observation(probe.clone(), "192.0.2.20", Some("00:00:5e:00:53:20"), vrf);
        assert!(condition.matches(&seen, cidr));
        let wrong_mac = observation(probe.clone(), "192.0.2.20", Some("00:00:5e:00:53:99"), vrf);
        assert!(!condition.matches(&wrong_mac, cidr));
        let other_vrf = observation(
            probe,
            "192.0.2.20",
            Some("00:00:5e:00:53:20"),
            VrfId::generate(),
        );
        assert!(!condition.matches(&other_vrf, cidr));
        let leased = observation(
            lease.clone(),
            "198.51.100.7",
            Some("00:00:5e:00:53:21"),
            vrf,
        );
        assert!(condition.matches(&leased, cidr));
        let outside = observation(lease, "203.0.113.7", Some("00:00:5e:00:53:21"), vrf);
        assert!(!condition.matches(&outside, cidr));
    }

    #[test]
    fn jobs_round_trip_through_cbor_and_json() {
        let stamp = Stamp::new(
            "2026-10-09T12:00:00Z".parse().expect("time"),
            Principal::system(SystemComponent::Jobs),
        );
        let condition = ObservationCondition {
            subject: HostId::generate().into(),
            any_of: vec![ObservedPredicate::AddressSeen {
                vrf: VrfId::generate(),
                ip: "2001:db8::20".parse().expect("ip"),
                mac: None,
            }],
        };
        let job = Job {
            id: JobId::generate(),
            spec: JobSpec {
                kind: JobKind::from_static("ipam.move"),
                title: MessageKey::from_static("ipam.move.title"),
                targets: vec![HostId::generate().into()],
                steps: vec![StepSpec {
                    kind: StepKind::from_static("jobs.manual"),
                    params: HexBytes(vec![0xA0]),
                    timeout: Some(Duration::from_secs(60)),
                }],
                timeout: Duration::from_secs(3600),
                group: Some(GroupKey::new("connect.unifi:lab").expect("group")),
                group_limit: None,
                idempotency: None,
                node: None,
            },
            started: None,
            state: JobState::Waiting,
            steps: vec![StepRecord {
                index: 0,
                kind: StepKind::from_static("jobs.manual"),
                state: StepState::WaitingForObservation {
                    condition,
                    deadline: "2026-10-09T13:00:00Z".parse().expect("time"),
                },
                attempts: 1,
                started: Some("2026-10-09T12:00:01Z".parse().expect("time")),
                finished: None,
                output: None,
            }],
            created: stamp,
            runner: Some(NodeId(1)),
            revision: Revision(12),
            cancel_requested: None,
            error: None,
            finished: None,
        };
        let back: Job = from_cbor(&to_cbor(&job).expect("cbor")).expect("cbor");
        assert_eq!(back, job);
        let json = serde_json::to_value(&job).expect("json");
        assert_eq!(json["spec"]["timeout"], 3_600_000);
        assert_eq!(
            json["steps"][0]["state"]["state"],
            "waiting_for_observation"
        );
        assert_eq!(
            serde_json::from_value::<Job>(json.clone()).expect("json"),
            job
        );
        assert!(json["spec"].get("node").is_none(), "no node: not written");

        // A job pinned to one controller keeps its node; a job stored before the field
        // existed reads as not pinned.
        let mut pinned = job.clone();
        pinned.spec.node = Some(NodeId(1002));
        let back: Job = from_cbor(&to_cbor(&pinned).expect("cbor")).expect("cbor");
        assert_eq!(back.spec.node, Some(NodeId(1002)));
        let mut older = serde_json::to_value(&pinned).expect("json");
        older["spec"].as_object_mut().expect("spec").remove("node");
        assert_eq!(
            serde_json::from_value::<Job>(older)
                .expect("json")
                .spec
                .node,
            None
        );
    }

    #[test]
    fn group_keys_validate() {
        assert!(GroupKey::new("connect.unifi:lab").is_ok());
        assert!(GroupKey::new("").is_err());
        assert!(GroupKey::new("has space").is_err());
    }
}
