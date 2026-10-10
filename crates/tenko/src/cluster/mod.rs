//! The controller cluster on this host (OPS-03, plan section 2.7 and WP3.1a): start step 3
//! of `tenko serve` and the command `tenko cluster`.
//!
//! WP3.0 created this module with the step and the command line in their final places;
//! the Raft-over-the-cluster-transport package (WP3.1a) fills both.

use std::io::Write;

use clap::Subcommand;
use tenko_store::raft::RaftStore;

use crate::{Pending, config::Resolved, serve::StartError};

/// Start step 3 of `tenko serve`, `cluster`, between the store and the vault.
///
/// In a cluster of controllers this step brings up the peer transport and the Raft service,
/// joins or rejoins the cluster (a member opens its store without bootstrap), fetches key
/// generations it missed during an online KEK rotation, and waits until the local store has
/// caught up with the leader's read index, or starts isolated after
/// `[cluster] catch_up_timeout_secs`. It runs before the vault because the vault cannot
/// open envelopes sealed under a generation this host does not hold yet.
///
/// Every controller's cluster identity lives in `<data_dir>/node/` with a sealed key, like a
/// probe's; the key that the vault holds for controller 1 today moves there when the first
/// peer joins (WP3.1a). On a single controller the step has nothing to do and reports the
/// membership it found.
///
/// # Errors
///
/// None yet; the join and the catch-up gate fail with `cluster.*` codes.
pub fn start(
    resolved: &Resolved,
    store: &RaftStore,
) -> impl Future<Output = Result<((), String), StartError>> + use<> {
    let voters = store
        .raft()
        .metrics()
        .borrow()
        .membership_config
        .membership()
        .voter_ids()
        .count();
    let summary = if voters <= 1 {
        format!(
            "single controller (node {}), nothing to join",
            resolved.node_id
        )
    } else {
        format!(
            "member of a cluster of {voters} voters (node {})",
            resolved.node_id
        )
    };
    std::future::ready(Ok(((), summary)))
}

/// Subcommands of `tenko cluster`. Each one is a stub until WP3.1a (and WP3.6 for
/// `upgrade-check`) implements it: it prints that it is not available in this build and
/// exits with status 2.
#[derive(Debug, Clone, Subcommand)]
pub enum ClusterCommand {
    /// Show this controller's view of the cluster: leader, term, quorum state.
    Status(Pending),
    /// List the members with their role, replication state and version.
    Members(Pending),
    /// Join this host to a cluster as a controller with an enrolment token.
    Join(Pending),
    /// Promote a caught-up learner to a voter.
    Promote(Pending),
    /// Remove a member and revoke its certificates.
    Remove(Pending),
    /// Hand leadership to the most caught-up follower before a planned restart.
    StepDown(Pending),
    /// Compare the state digests of the members.
    Verify(Pending),
    /// List each member's version, protocol majors and the data formats it knows.
    UpgradeCheck(Pending),
}

impl ClusterCommand {
    /// The command as typed, such as `cluster status`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Status(_) => "cluster status",
            Self::Members(_) => "cluster members",
            Self::Join(_) => "cluster join",
            Self::Promote(_) => "cluster promote",
            Self::Remove(_) => "cluster remove",
            Self::StepDown(_) => "cluster step-down",
            Self::Verify(_) => "cluster verify",
            Self::UpgradeCheck(_) => "cluster upgrade-check",
        }
    }
}

/// Runs `tenko cluster …`.
pub fn command(action: &ClusterCommand, err: &mut impl Write) -> u8 {
    crate::not_available(action.name(), err)
}
