//! The `ddi` command-line client.
//!
//! Phase 0 only reports its version and the node roles; management commands that talk to
//! the controller API land in a later phase.

use std::fmt::Write as _;

use clap::{Parser, Subcommand};
use ddi_core::Role;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "ddi-cli";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// DDI command-line client.
#[derive(Debug, Parser)]
#[command(name = "ddi", version, arg_required_else_help = true)]
pub struct Cli {
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands of the `ddi` client.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect node roles.
    Roles {
        /// The `roles` subcommand to run.
        #[command(subcommand)]
        action: RolesCommand,
    },
}

/// Subcommands of `ddi roles`.
#[derive(Debug, Subcommand)]
pub enum RolesCommand {
    /// List the roles a DDI node can run.
    List,
}

/// Runs a parsed command and returns the text to print on standard output.
pub fn execute(cli: &Cli) -> String {
    match &cli.command {
        Command::Roles {
            action: RolesCommand::List,
        } => render_roles(),
    }
}

/// Renders the output of `ddi roles list`: one line per role with its description.
pub fn render_roles() -> String {
    let width = Role::ALL
        .iter()
        .map(|role| role.as_str().len())
        .max()
        .unwrap_or_default();
    let mut out = String::new();
    for role in Role::ALL {
        // Writing to a `String` cannot fail.
        let _ = writeln!(out, "{:<width$}  {}", role.as_str(), role.description());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, error::ErrorKind};

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn roles_list_prints_every_role() {
        let cli = Cli::try_parse_from(["ddi", "roles", "list"]).expect("valid arguments");
        let output = execute(&cli);
        assert_eq!(output.lines().count(), Role::ALL.len());
        for role in Role::ALL {
            assert!(output.contains(role.as_str()), "missing role {role}");
        }
    }

    #[test]
    fn version_flag_is_supported() {
        let err = Cli::try_parse_from(["ddi", "--version"]).expect_err("--version exits early");
        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
    }
}
