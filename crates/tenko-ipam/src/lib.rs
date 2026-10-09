//! The IPAM domain of Tenko DDI (ADR 0005, ADR 0011): commands, plans over the store,
//! the per-VRF prefix tree, next free allocation, utilization alarms, history and soft
//! delete. Import and export (WP1.5) build on the same plans.
//!
//! # How a change happens
//!
//! 1. A caller (the API, the import, later the reconciler) builds [`IpamCommand`]s.
//! 2. [`plan()`] computes an [`IpamPlan`] from a read view without writing: the physical
//!    mutations, preconditions (versions of everything read, the per-VRF tree counter and
//!    the per-prefix allocation counter), history rows, audit drafts, warnings and a human
//!    summary. The API dry run and the import preview show this plan.
//! 3. [`IpamService::apply`] proposes the plan as one write batch inside an inline
//!    one-step job ([`JobSink`], decision Q4); [`IpamService::execute`] plans and applies
//!    with retries when concurrent writers invalidate a plan.
//! 4. The store updates the [`PrefixTree`] index on its apply path; the service then
//!    writes utilization alarm transitions ([`alarm`]).
//!
//! # Wiring (server)
//!
//! ```ignore
//! let mut engine = tenko_jobs::JobEngine::new(store.clone(), engine_config);
//! tenko_ipam::jobs::register_steps(&mut engine);
//! let ipam = IpamService::new(store.clone(), Arc::new(engine.clone()), IpamConfig::default())?;
//! let router = router.layer(axum::Extension(ipam.clone()));   // the IPAM routes
//! tokio::spawn(ipam.clone().run_alarms(shutdown));             // alarms of remote changes
//! ```
//!
//! # Import (WP1.5)
//!
//! An importer turns its IR into commands with client-chosen identifiers, so commands can
//! refer to objects created earlier in the same list (prefix, then host, interface and
//! address). [`IpamService::preview`] gives the [`IpamPlan`] of the preview: its
//! [`PlanView`] (summary counts per kind and action, English lines, warnings, every change
//! with before and after) is what the user reviews. [`IpamService::apply`] then commits
//! exactly that plan as one batch and inline job, or fails with `ipam.plan.stale` when the
//! data changed since the preview; [`IpamService::execute`] plans and applies in one go.
//! A plan above the store's batch limit (`IpamPlan::to_batch().payload_size()`) or above
//! [`IpamConfig::max_commands`] is split by the importer into chunks of commands.
//!
//! # Ownership
//!
//! WP1.4 owns this crate except `src/import/`, `src/export/` and `tests/fixtures/`, which
//! belong to WP1.5.
//!
//! # Modules
//!
//! | Module | Contents |
//! |---|---|
//! | [`command`] | commands, inputs and patches |
//! | [`mod@plan`] | planning, plans, warnings, summaries, receipts |
//! | [`service`] | [`IpamService`]: apply, execute, allocation protocol, alarms |
//! | [`tree`] | the prefix tree index, utilization, next free |
//! | [`alarm`] | alarm levels and events (IPAM-10) |
//! | [`jobs`] | the inline job of a change, [`JobSink`], [`DirectJobs`] |
//! | [`history`] | history entries (IPAM-09) |
//! | [`query`] | reads for the API: lists, filters, pagination, search |
//! | [`custom`] | custom field validation (IPAM-08) |
//! | [`tables`] | the `ipam.*` tables and counters |
//! | [`error`] | [`IpamError`] and the `ipam.*` codes |

#![forbid(unsafe_code)]

pub mod alarm;
pub mod alloc;
pub mod command;
pub mod custom;
pub mod diff;
pub mod error;
pub mod history;
pub mod jobs;
pub mod net;
pub mod object;
pub mod plan;
pub mod query;
pub mod service;
pub mod tables;
pub mod tree;

#[cfg(test)]
pub(crate) mod testutil;

pub use alarm::{AlarmEvent, AlarmLevel};
pub use command::IpamCommand;
pub use error::{IpamError, IpamResult, codes};
pub use history::{ChangeAction, HistoryEntry};
/// The network type of the model, re-exported for API callers.
pub use ipnet::IpNet;
pub use jobs::{DirectJobs, IpamWriteStep, JobSink};
pub use object::{Entity, IpamObject};
pub use plan::{Applied, IpamPlan, PlanOptions, PlanSummary, PlanView, PlanWarning, plan};
pub use service::{IpamConfig, IpamService};
pub use tree::{PrefixTree, TreeNode, Utilization, UtilizationView};

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-ipam";

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
