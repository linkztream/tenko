//! The controller cluster on this host (OPS-03, plan section 2.7 and WP3.1a): start step 3
//! of `tenko serve` and the command `tenko cluster`.
//!
//! | Module | Contents |
//! |---|---|
//! | `start` | start step 3, `cluster`: the peer layer, the cluster port of a member, the catch-up gate, missing key generations |
//! | `join` | `tenko cluster join`: enrolment as a controller, the key transfer, the copy of the cluster's data, the configuration |
//! | [`admin`] | `tenko cluster status|members|promote|remove|step-down|verify` over `/cluster/*` |
//! | [`upgrade`] | `tenko cluster upgrade-check`: this binary against every member, and the rolling order |

pub mod admin;
mod join;
mod start;
pub mod upgrade;

use std::io::Write;

use clap::Subcommand;
use tenko_store::raft::RaftStore;

pub use self::{
    join::JoinArgs,
    start::{ClusterPeers, OpenPort, Start, catch_up, own_address, peer_config, start_peers},
};
use crate::{client, config::Resolved, serve::StartError};

/// Start step 3 of `tenko serve` before the peer layer is wired into the start order:
/// reports the membership the store holds and does nothing else. `tenko serve` moves to
/// [`start_peers`], which returns the peer layer for the later steps.
///
/// # Errors
///
/// None.
pub fn start(
    resolved: &Resolved,
    store: &RaftStore,
) -> impl Future<Output = Result<((), String), StartError>> + use<> {
    let membership = store.membership();
    let summary = if membership.voters.len() + membership.learners.len() <= 1 {
        format!(
            "single controller (node {}), nothing to join",
            resolved.node_id
        )
    } else {
        format!(
            "member of a cluster of {} voters (node {})",
            membership.voters.len(),
            resolved.node_id
        )
    };
    std::future::ready(Ok(((), summary)))
}

/// Subcommands of `tenko cluster`.
#[derive(Debug, Clone, Subcommand)]
pub enum ClusterCommand {
    /// Show this controller's view of the cluster: leader, term, quorum state.
    Status(admin::StatusArgs),
    /// List the members with their role, replication state and version.
    Members(admin::MembersArgs),
    /// Join this host to a cluster as a controller with a controller enrolment token.
    Join(JoinArgs),
    /// Promote a caught-up learner to a voter.
    Promote(admin::PromoteArgs),
    /// Remove a member and revoke its certificates.
    Remove(admin::RemoveArgs),
    /// Hand leadership to the most caught-up voter before a planned restart.
    StepDown(admin::StepDownArgs),
    /// Compare the state digests of the members.
    Verify(admin::VerifyArgs),
    /// List each member's version, protocol majors, Raft wire version and the data formats
    /// it knows, check that this binary can replace them, and print the rolling order.
    UpgradeCheck(upgrade::UpgradeCheckArgs),
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

    /// Whether the subcommand prints JSON.
    fn json(&self) -> bool {
        match self {
            Self::Status(args) => args.client.json,
            Self::Members(args) => args.client.json,
            Self::Join(args) => args.node.json,
            Self::Promote(args) => args.client.json,
            Self::Remove(args) => args.client.json,
            Self::StepDown(args) => args.client.json,
            Self::Verify(args) => args.client.json,
            Self::UpgradeCheck(args) => args.client.json,
        }
    }
}

/// Runs `tenko cluster …`, printing to standard output.
pub fn command(action: &ClusterCommand, err: &mut impl Write) -> u8 {
    run(action, &mut std::io::stdout(), err)
}

/// Runs `tenko cluster …`.
pub fn run(action: &ClusterCommand, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let name = action.name();
    let json = action.json();
    match action {
        ClusterCommand::UpgradeCheck(args) => {
            client::block_on(name, json, out, err, upgrade::run(args))
        }
        ClusterCommand::Join(args) => {
            crate::logging::init_client();
            client::block_on(name, json, out, err, join::run(args))
        }
        ClusterCommand::Status(args) => client::block_on(name, json, out, err, admin::status(args)),
        ClusterCommand::Members(args) => {
            client::block_on(name, json, out, err, admin::members(args))
        }
        ClusterCommand::Promote(args) => {
            client::block_on(name, json, out, err, admin::promote(args))
        }
        ClusterCommand::Remove(args) => client::block_on(name, json, out, err, admin::remove(args)),
        ClusterCommand::StepDown(args) => {
            client::block_on(name, json, out, err, admin::step_down(args))
        }
        ClusterCommand::Verify(args) => client::block_on(name, json, out, err, admin::verify(args)),
    }
}
