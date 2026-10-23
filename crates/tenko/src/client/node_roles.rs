//! `tenko node roles show|set`: the roles of a node through the API
//! (`GET` and `PUT /nodes/{id}/roles`), with the credentials of `tenko login`.
//!
//! `set` reads the roles first and sends their revision as `If-Match`, so a change made
//! meanwhile by someone else is refused (`node.roles.revision_mismatch`) rather than
//! overwritten. The node applies the set by a restart through its service manager.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use tenko_api::routes::node_roles::{NodeRoles, NodeRolesRequest, RoleRestart};
use tenko_core::{Revision, Role, RoleSet};

use super::{ClientOpts, Failure, Output, Target};
use crate::exit;

/// Subcommands of `tenko node roles`.
#[derive(Debug, Clone, Subcommand)]
pub enum RolesCommand {
    /// Show the roles a node runs and the ones it runs from its next start.
    Show(ShowArgs),
    /// Set the roles a node runs from its next start; it restarts to apply them.
    Set(SetArgs),
}

impl RolesCommand {
    /// The command as typed: `node roles show`.
    pub fn name(&self) -> &'static str {
        match self {
            RolesCommand::Show(_) => "node roles show",
            RolesCommand::Set(_) => "node roles set",
        }
    }

    /// The connection options.
    pub fn client(&self) -> &ClientOpts {
        match self {
            RolesCommand::Show(args) => &args.client,
            RolesCommand::Set(args) => &args.client,
        }
    }
}

/// Arguments of `tenko node roles`.
#[derive(Debug, Clone, Args)]
pub struct RolesArgs {
    /// What to do.
    #[command(subcommand)]
    pub action: RolesCommand,
}

/// Arguments of `tenko node roles show`.
#[derive(Debug, Clone, Args)]
pub struct ShowArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,

    /// The node id.
    #[arg(value_name = "ID")]
    pub id: u64,
}

/// Arguments of `tenko node roles set`.
#[derive(Debug, Clone, Args)]
pub struct SetArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,

    /// The node id.
    #[arg(value_name = "ID")]
    pub id: u64,

    /// The roles, comma-separated: any of `controller`, `dns`, `dhcp` and `probe`, or `all`.
    #[arg(long, value_name = "ROLES")]
    pub roles: String,
}

/// Runs `tenko node roles <command>`.
///
/// # Errors
///
/// The [`Failure`] of the command.
pub async fn run(args: &RolesArgs) -> Result<Output, Failure> {
    match &args.action {
        RolesCommand::Show(args) => show(args).await,
        RolesCommand::Set(args) => set(args).await,
    }
}

fn path(id: u64) -> String {
    format!("/nodes/{id}/roles")
}

fn list(roles: &[Role]) -> String {
    if roles.is_empty() {
        return "(none)".to_owned();
    }
    roles
        .iter()
        .map(|role| role.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

/// The text of an answer.
pub fn render(roles: &NodeRoles) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "node        {}", roles.node);
    let _ = writeln!(text, "configured  {}", list(&roles.configured));
    if let Some(running) = &roles.running {
        let _ = writeln!(text, "running     {}", list(running));
    }
    let source = match (roles.pinned, roles.stored) {
        (true, _) => "pinned by --roles on the node's command line",
        (false, true) => "the node's stored set",
        (false, false) => "no stored set yet",
    };
    let _ = writeln!(text, "source      {source}");
    let restart = match roles.restart {
        RoleRestart::None => "none",
        RoleRestart::Scheduled => "scheduled: the node restarts itself within seconds",
        RoleRestart::Required => "required: restart tenko serve on the node",
        RoleRestart::OnNode => "on the node, when it receives the change",
    };
    let _ = writeln!(text, "restart     {restart}");
    for finding in &roles.findings {
        let _ = writeln!(text, "finding     [{}] {}", finding.code, finding.detail);
    }
    text
}

async fn show(args: &ShowArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let client = target.connect().await?;
    let roles: NodeRoles = client.get(&path(args.id)).await?;
    if target.json {
        return Ok(Output::json(&roles));
    }
    Ok(Output::text(render(&roles)))
}

async fn set(args: &SetArgs) -> Result<Output, Failure> {
    let wanted: RoleSet = args
        .roles
        .parse()
        .map_err(|error| Failure::new(exit::USAGE, format!("--roles: {error}")))?;
    let target = Target::resolve(&args.client, true)?;
    let client = target.connect().await?;
    let current: NodeRoles = client.get(&path(args.id)).await?;
    let request = NodeRolesRequest {
        roles: wanted.roles().collect(),
    };
    let roles: NodeRoles = client
        .put(&path(args.id), &request, current.revision.map(Revision))
        .await?;
    if target.json {
        return Ok(Output::json(&roles));
    }
    Ok(Output::text(render(&roles)).note(format!(
        "the roles of node {} were {}; they are {} from its next start",
        roles.node,
        list(&current.configured),
        list(&roles.configured)
    )))
}

#[cfg(test)]
mod tests {
    use tenko_core::NodeId;

    use super::*;

    #[test]
    fn an_answer_reads_as_lines() {
        let roles = NodeRoles {
            node: NodeId(1),
            configured: vec![Role::Controller, Role::Dns, Role::Dhcp],
            running: Some(vec![Role::Controller, Role::Dns]),
            stored: true,
            origin: None,
            changed_at: None,
            revision: Some(12),
            pinned: false,
            controller: true,
            restart: RoleRestart::Scheduled,
            findings: vec![tenko_api::routes::node_roles::privileges_finding(
                &["probe"],
                &["probe.conf"],
            )],
        };
        let text = render(&roles);
        assert!(text.contains("configured  controller,dns,dhcp\n"), "{text}");
        assert!(text.contains("running     controller,dns\n"), "{text}");
        assert!(
            text.contains("source      the node's stored set\n"),
            "{text}"
        );
        assert!(text.contains("restart     scheduled"), "{text}");
        assert!(text.contains("[node.roles.privileges]"), "{text}");
    }
}
