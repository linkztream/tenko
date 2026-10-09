//! Job engine: multi-step jobs with persisted state, timeouts and rollback (ADR 0005,
//! IPAM-17, IPAM-19).
//!
//! # Ownership
//!
//! WP1.0 (the lead builder) owns [`model`]: the job, step and handler contract (plan
//! section 2.6). Other packages never edit it; contract changes go through the lead as a
//! small pull request reviewed by every package that uses the item (plan rule 2.8). WP1.6
//! owns the rest of this crate: the engine (`JobEngine::register`, `preview`, `submit`,
//! `run_inline`, `cancel`, `complete_manual`, `on_observation`), its persistence in
//! `jobs.*` tables and `routes/jobs.rs` of `tenko-api`.

pub mod model;

pub use model::{
    GroupKey, Job, JobAction, JobError, JobKind, JobPreview, JobSpec, JobState, ManualTask,
    ObservationCondition, ObservedPredicate, StepContext, StepError, StepHandler, StepKind,
    StepOutcome, StepPreview, StepRecord, StepSpec, StepState,
};

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
