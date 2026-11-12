//! Job engine: multi-step jobs with persisted state, timeouts and rollback (ADR 0005,
//! IPAM-17, IPAM-19, CONN-09, API-09).
//!
//! # A home of shared code
//!
//! This crate is a home of shared code (`CONTRIBUTING.md`, "Where shared code lives") for
//! how other crates use jobs: `read` (read functions over the job tables, so that no other
//! crate knows their key layout), `stage_or_propose` (stage inside the step or propose),
//! and `handoff` (the inline hand-off of work to a job). A module named here that does not
//! exist yet is created by the change that first needs it, with this charter in its header.
//!
//! - **Never:** a step of another crate's domain; the steps live with their crate.
//! - **Who depends on it:** any crate that runs or reads jobs. An addition inside this
//!   charter needs no permission; a change to [`model`] (the job, step and handler contract)
//!   or to what an existing item does goes through the maintainers.
//!
//! # How it works
//!
//! - **Handlers.** Every step kind has one [`StepHandler`], registered with
//!   [`JobEngine::register`]. A package registers its handlers once at start:
//!
//!   ```ignore
//!   let mut engine = JobEngine::new(store.clone(), EngineConfig::default());
//!   engine.register(Arc::new(IpamWrite::new(ipam.clone())));   // kind `ipam.write`
//!   engine.register(Arc::new(SetClientVlan::new(unifi)));      // kind `connect.unifi.set_client_vlan`
//!   let runner = engine.start()?;
//!   ```
//!
//!   The built-in [`ManualStep`] (`jobs.manual`) asks a person to do something.
//! - **Inline jobs** ([`JobEngine::run_inline`]): a single edit runs its one step inside
//!   the request; the step [stages](stage()) its store writes and the engine commits them
//!   with the job record and every audit draft in one write batch (decision Q4).
//! - **Background jobs** ([`JobEngine::submit`]): the runner ([`runner`]) starts them as
//!   workers and group slots allow, runs the steps in order, commits each step's staged
//!   writes with its state, parks jobs that wait for an observation or a person, and wakes
//!   them on [`JobEngine::on_observation`], [`JobEngine::complete_manual`],
//!   [`JobEngine::cancel`] or their deadline.
//! - **Rollback** ([`machine`]): a failed step, a passed deadline or a cancel compensates the
//!   steps that ran, in reverse; steps that cannot be undone become manual undo tasks.
//!   End states are `succeeded`, `rolled_back`, `canceled` and `failed` (a compensation
//!   failed).
//! - **Persistence** ([`tables`]): jobs, transition logs, indexes and runner leases live in
//!   `jobs.*` tables; every transition is an audited write batch, and its transition row
//!   is what the `jobs` SSE topic forwards ([`event`]). A restarted runner resumes its
//!   jobs and runs again only idempotent steps; others take over the jobs of a runner whose
//!   lease expired.
//! - **A cluster of controllers** ([`leader`], plan section 2.3): the leader runs the one
//!   runner of the installation as the leader-only service `jobs.runner`
//!   ([`JobEngine::leader_service`]); every write it makes carries the leader epoch, so a
//!   deposed leader's next write fails, and the next leader takes the jobs over at once.
//!   Jobs pinned to a controller (`JobSpec::node`) run on that controller's own runner
//!   ([`JobEngine::start_pinned`]).
//! - **Time** ([`clock`]): every timeout, deadline and lease follows a [`Clock`], so tests
//!   drive them with [`MockClock`].
//!
//! The feature `testing` adds the `testing` module for other packages: an
//! engine on a `MemStore` with a mock clock and scripted handlers.

pub mod clock;
mod drive;
pub mod engine;
pub mod event;
pub mod leader;
pub mod machine;
pub mod manual;
pub mod model;
mod persist;
pub mod query;
pub mod runner;
pub mod stage;
pub mod tables;
#[cfg(feature = "testing")]
pub mod testing;
pub mod waiters;

pub use clock::{Clock, MockClock, SystemClock};
pub use engine::{EngineConfig, JobEngine, MAX_NOTE_BYTES};
pub use event::{JobEvent, StepStateKind};
pub use manual::{MANUAL, ManualStep};
pub use model::{
    GroupKey, Job, JobAction, JobError, JobKind, JobPreview, JobSpec, JobState, ManualTask,
    ObservationCondition, ObservedPredicate, StepContext, StepError, StepHandler, StepKind,
    StepOutcome, StepPreview, StepRecord, StepSpec, StepState,
};
pub use query::{JobDetail, JobPage, JobQuery, JobSummary};
pub use runner::{AlreadyRunning, RunnerExit, RunnerHandle};
pub use stage::{StagedWrite, stage};
pub use tables::{Transition, TransitionEvent};
pub use waiters::PrefixResolver;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-jobs";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }
}
