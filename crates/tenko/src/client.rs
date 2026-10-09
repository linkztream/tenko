//! Client side of the `tenko` binary: `tenko roles list` and the stubs of the commands that
//! will talk to the public API.
//!
//! The stubs accept any trailing arguments without validating them, print a notice to
//! standard error and exit with status [`NOT_IMPLEMENTED_EXIT_CODE`].

use std::{fmt::Write as _, io::Write};

use anyhow::Context as _;
use clap::Args;
use tenko_core::Role;

/// Exit status of a client command that is not implemented yet.
pub const NOT_IMPLEMENTED_EXIT_CODE: u8 = 2;

/// Trailing arguments of a client command that is not implemented yet.
///
/// Everything after the command name is collected unchanged, including words that look like
/// flags, so that the final command line can already be written down and parsed.
#[derive(Debug, Clone, Default, Args)]
pub struct StubArgs {
    /// Arguments of the command; ignored for now.
    #[arg(
        value_name = "ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub args: Vec<String>,
}

/// Reports that `command` is not implemented yet on `err` and returns the exit status to use.
///
/// # Errors
///
/// Returns an error if writing to `err` fails.
pub fn not_implemented(command: &str, err: &mut impl Write) -> anyhow::Result<u8> {
    writeln!(err, "tenko {command}: not implemented yet").context("writing notice")?;
    Ok(NOT_IMPLEMENTED_EXIT_CODE)
}

/// Renders the output of `tenko roles list`: one line per role with its description.
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
    use crate::{AuditCommand, Cli, Command, execute};
    use clap::Parser as _;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("tenko").chain(args.iter().copied()))
    }

    fn stub_args(command: &Command) -> &StubArgs {
        match command {
            Command::Login(args)
            | Command::Import(args)
            | Command::Export(args)
            | Command::Prefix(args)
            | Command::Audit {
                action: AuditCommand::Verify(args),
            } => args,
            other => panic!("not a client stub: {other:?}"),
        }
    }

    #[test]
    fn roles_render_one_line_per_role() {
        let output = render_roles();
        assert_eq!(output.lines().count(), Role::ALL.len());
        for role in Role::ALL {
            assert!(output.contains(role.as_str()), "missing role {role}");
            assert!(
                output.contains(role.description()),
                "missing text of {role}"
            );
        }
    }

    #[test]
    fn every_stub_parses_and_exits_with_status_2() {
        let cases: [(&[&str], &str); 5] = [
            (&["login"], "login"),
            (&["import"], "import"),
            (&["export"], "export"),
            (&["prefix"], "prefix"),
            (&["audit", "verify"], "audit verify"),
        ];
        for (argv, name) in cases {
            let cli = parse(argv).expect("valid arguments");
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let status = execute(&cli, &mut out, &mut err).expect("stub does not fail");
            assert_eq!(status, 2, "exit status of {name}");
            assert_eq!(status, NOT_IMPLEMENTED_EXIT_CODE);
            assert!(out.is_empty(), "stdout of {name} must stay empty");
            let err = String::from_utf8(err).expect("UTF-8 output");
            assert_eq!(err, format!("tenko {name}: not implemented yet\n"));
        }
    }

    #[test]
    fn import_accepts_trailing_arguments() {
        let cli = parse(&["import", "file.xlsx", "--dry-run"]).expect("valid arguments");
        assert_eq!(stub_args(&cli.command).args, ["file.xlsx", "--dry-run"]);
    }

    #[test]
    fn trailing_arguments_may_start_with_a_flag() {
        let cli = parse(&["export", "--format", "csv", "-o", "out.csv"]).expect("valid arguments");
        assert_eq!(
            stub_args(&cli.command).args,
            ["--format", "csv", "-o", "out.csv"]
        );
    }

    #[test]
    fn audit_verify_accepts_trailing_arguments() {
        let cli = parse(&["audit", "verify", "--chain", "audit.cbor"]).expect("valid arguments");
        assert_eq!(stub_args(&cli.command).args, ["--chain", "audit.cbor"]);
    }

    #[test]
    fn audit_requires_a_subcommand() {
        assert!(parse(&["audit"]).is_err());
    }
}
