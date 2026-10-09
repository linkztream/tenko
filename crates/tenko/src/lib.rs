//! The `tenko` binary: one executable that runs the server roles (`tenko serve`) and acts
//! as the command-line client of the public API (`tenko login`, `import`, `export`,
//! `prefix`, `audit verify`), as decided in ADR 0004.
//!
//! Owned by WP1.8 (server and CLI); until then the lead builder maintains this skeleton.
//!
//! The server side only parses its configuration and reports the planned start order; the
//! role runtimes land later. The client commands other than `tenko roles list` are stubs
//! that exit with status 2.

use std::io::Write;

use clap::{Parser, Subcommand};

pub mod client;
pub mod serve;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Tenko DDI: DNS, DHCP and IPAM in one binary, server and command-line client alike.
#[derive(Debug, Parser)]
#[command(
    name = "tenko",
    bin_name = "tenko",
    version,
    arg_required_else_help = true
)]
pub struct Cli {
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands of the `tenko` binary.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the server roles of this node (controller, dns, dhcp, probe).
    Serve(serve::ServeArgs),

    /// Inspect node roles.
    Roles {
        /// The `roles` subcommand to run.
        #[command(subcommand)]
        action: RolesCommand,
    },

    /// Sign in to a controller and keep the session for later commands (not implemented yet).
    ///
    /// Will authenticate against the public API and store the resulting session so that the
    /// other client commands can reuse it.
    Login(client::StubArgs),

    /// Import an IPAM spreadsheet or CSV file into the address tree (not implemented yet).
    ///
    /// Will upload the file to the controller, report the planned changes and apply them
    /// unless a dry run is requested.
    Import(client::StubArgs),

    /// Export the address tree to a spreadsheet or CSV file (not implemented yet).
    ///
    /// Will download the current IPAM data from the controller in a format that `import`
    /// reads back.
    Export(client::StubArgs),

    /// List, inspect and change prefixes of the address tree (not implemented yet).
    ///
    /// Will drive the prefix endpoints of the public API from the command line.
    Prefix(client::StubArgs),

    /// Audit log commands.
    Audit {
        /// The `audit` subcommand to run.
        #[command(subcommand)]
        action: AuditCommand,
    },

    /// Print the OpenAPI document of the API (CI compares it with `docs/api/openapi.json`).
    #[command(hide = true)]
    Openapi,
}

/// Subcommands of `tenko roles`.
#[derive(Debug, Subcommand)]
pub enum RolesCommand {
    /// List the roles a Tenko node can run.
    List,
}

/// Subcommands of `tenko audit`.
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Verify the hash chain of the audit log (not implemented yet).
    ///
    /// Will check every record of an audit export against its predecessor and report the
    /// first break in the chain, without contacting the controller.
    Verify(client::StubArgs),
}

impl Command {
    /// Returns the command as typed on the command line, such as `import` or `audit verify`.
    pub const fn name(&self) -> &'static str {
        match self {
            Command::Serve(_) => "serve",
            Command::Roles {
                action: RolesCommand::List,
            } => "roles list",
            Command::Login(_) => "login",
            Command::Import(_) => "import",
            Command::Export(_) => "export",
            Command::Prefix(_) => "prefix",
            Command::Audit {
                action: AuditCommand::Verify(_),
            } => "audit verify",
            Command::Openapi => "openapi",
        }
    }
}

/// Runs a parsed command, writing regular output to `out` and diagnostics to `err`.
///
/// Returns the process exit status: 0 on success and [`client::NOT_IMPLEMENTED_EXIT_CODE`]
/// for the client commands that are not implemented yet.
///
/// # Errors
///
/// Returns an error if the command fails; see [`serve::run`].
pub fn execute(cli: &Cli, out: &mut impl Write, err: &mut impl Write) -> anyhow::Result<u8> {
    match &cli.command {
        Command::Serve(args) => serve::run(args, out).map(|()| 0),
        Command::Roles {
            action: RolesCommand::List,
        } => {
            write!(out, "{}", client::render_roles())?;
            Ok(0)
        }
        Command::Openapi => {
            write!(out, "{}", tenko_api::openapi_json())?;
            Ok(0)
        }
        command => client::not_implemented(command.name(), err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, error::ErrorKind};
    use tenko_core::Role;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("tenko").chain(args.iter().copied()))
    }

    fn run(args: &[&str]) -> (u8, String, String) {
        let cli = parse(args).expect("valid arguments");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = execute(&cli, &mut out, &mut err).expect("command succeeds");
        (
            status,
            String::from_utf8(out).expect("UTF-8 output"),
            String::from_utf8(err).expect("UTF-8 output"),
        )
    }

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
    fn version_flag_is_supported() {
        let err = parse(&["--version"]).expect_err("--version exits early");
        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
        assert!(err.to_string().starts_with("tenko "), "output: {err}");
    }

    #[test]
    fn bare_invocation_shows_help() {
        let err = parse(&[]).expect_err("a command is required");
        assert_eq!(
            err.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn roles_list_prints_every_role() {
        let (status, output, _) = run(&["roles", "list"]);
        assert_eq!(status, 0);
        assert_eq!(output.lines().count(), Role::ALL.len());
        for role in Role::ALL {
            assert!(output.contains(role.as_str()), "missing role {role}");
        }
    }

    #[test]
    fn serve_through_execute_succeeds() {
        let dir = std::env::temp_dir().join("tenko-lib-test-serve");
        let dir = dir.to_str().expect("UTF-8 temp path");
        let (status, output, err) = run(&["serve", "--roles", "probe", "--data-dir", dir]);
        assert_eq!(status, 0);
        assert!(output.contains("roles are not implemented yet; exiting"));
        assert_eq!(err, "");
    }

    #[test]
    fn openapi_prints_the_generated_document() {
        let (status, output, _) = run(&["openapi"]);
        assert_eq!(status, 0);
        assert_eq!(output, tenko_api::openapi_json());
    }

    #[test]
    fn command_names_match_the_command_line() {
        let cases: [(&[&str], &str); 8] = [
            (&["openapi"], "openapi"),
            (&["serve", "--data-dir", "d"], "serve"),
            (&["roles", "list"], "roles list"),
            (&["login"], "login"),
            (&["import"], "import"),
            (&["export"], "export"),
            (&["prefix"], "prefix"),
            (&["audit", "verify"], "audit verify"),
        ];
        for (args, name) in cases {
            let cli = parse(args).expect("valid arguments");
            assert_eq!(cli.command.name(), name);
        }
    }
}
