//! `tenko serve`: runs the server roles of this node.
//!
//! The role runtimes are not implemented yet. For now the command validates its arguments,
//! reports the selected roles and the planned start order of the controller role, and exits.

use std::{io::Write, path::PathBuf};

use anyhow::{Context as _, ensure};
use clap::Args;
use tenko_core::{Role, RoleSet};

use crate::version;

/// The planned start order of the controller role: step name and what the step brings up.
///
/// Each step depends on the ones before it. The data plane roles (`dns`, `dhcp`) do not
/// appear here because they start from their local copy and never wait for a controller.
pub const CONTROLLER_START_ORDER: [(&str, &str); 6] = [
    ("kek", "key-encryption key provider"),
    ("vault", "envelope encryption of system secrets"),
    ("store", "replicated store (openraft over redb)"),
    ("auth", "users, sessions, passkeys and TOTP"),
    ("ipam", "IPAM domain and job engine"),
    ("api", "HTTP API, web UI and server-sent events"),
];

/// Arguments of `tenko serve`.
#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Roles to run on this node: a comma-separated list of controller, dns, dhcp, and
    /// probe, or `all`.
    #[arg(long, value_name = "ROLES", default_value = "all")]
    pub roles: RoleSet,

    /// Directory that holds the state of this node. It does not have to exist yet.
    #[arg(long, value_name = "PATH")]
    pub data_dir: PathBuf,

    /// Path to the configuration file. It must exist if given.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

/// Runs the server with the given arguments, writing a start-up summary to `out`.
///
/// The role runtimes are not implemented yet, so this reports the selected roles, the
/// planned start order of the controller role and returns.
///
/// # Errors
///
/// Returns an error if a configuration file is given but does not exist, or if writing
/// the summary fails.
pub fn run(args: &ServeArgs, out: &mut impl Write) -> anyhow::Result<()> {
    if let Some(path) = &args.config {
        ensure!(
            path.is_file(),
            "configuration file {} does not exist",
            path.display()
        );
    }

    tracing::info!(
        roles = %args.roles,
        data_dir = %args.data_dir.display(),
        "starting tenko {}",
        version()
    );

    write_summary(args, out).context("writing start-up summary")?;

    tracing::info!("role runtimes are not implemented yet; exiting");
    Ok(())
}

/// Writes the start-up summary of `tenko serve` to `out`.
fn write_summary(args: &ServeArgs, out: &mut impl Write) -> std::io::Result<()> {
    let config = match &args.config {
        Some(path) => path.display().to_string(),
        None => "(none)".to_owned(),
    };
    writeln!(out, "tenko {}", version())?;
    writeln!(out, "roles: {}", args.roles)?;
    writeln!(out, "data dir: {}", args.data_dir.display())?;
    writeln!(out, "config: {config}")?;

    let name_width = CONTROLLER_START_ORDER
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or_default();
    for role in args.roles.roles() {
        if role == Role::Controller {
            writeln!(out, "controller start order:")?;
            for (index, (name, description)) in CONTROLLER_START_ORDER.iter().enumerate() {
                writeln!(out, "  {}. {name:<name_width$}  {description}", index + 1)?;
            }
        } else {
            writeln!(out, "{role} role: arrives in a later phase")?;
        }
    }
    writeln!(out, "roles are not implemented yet; exiting")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser as _;

    fn parse(flags: &[&str]) -> Result<ServeArgs, clap::Error> {
        let line = ["tenko", "serve"].into_iter().chain(flags.iter().copied());
        match Cli::try_parse_from(line)?.command {
            Command::Serve(args) => Ok(args),
            command => panic!("expected the serve command, got {command:?}"),
        }
    }

    /// Parses `args`, always adding a `--data-dir` below the temporary directory.
    fn parse_with_data_dir(extra: &[&str]) -> ServeArgs {
        let dir = std::env::temp_dir().join("tenko-serve-test");
        let dir = dir.to_str().expect("UTF-8 temp path");
        let mut flags = vec!["--data-dir", dir];
        flags.extend_from_slice(extra);
        parse(&flags).expect("valid arguments")
    }

    fn output_of(args: &ServeArgs) -> String {
        let mut out = Vec::new();
        run(args, &mut out).expect("run succeeds");
        String::from_utf8(out).expect("UTF-8 output")
    }

    #[test]
    fn parses_role_list() {
        let args = parse_with_data_dir(&["--roles", "controller,dns"]);
        assert!(args.roles.contains(Role::Controller));
        assert!(args.roles.contains(Role::Dns));
        assert!(!args.roles.contains(Role::Dhcp));
        assert!(!args.roles.contains(Role::Probe));
        assert!(args.config.is_none());
    }

    #[test]
    fn defaults_to_all_roles() {
        let args = parse_with_data_dir(&[]);
        assert_eq!(args.roles, RoleSet::ALL);
    }

    #[test]
    fn rejects_unknown_role() {
        assert!(parse(&["--roles", "dns,ntp", "--data-dir", "d"]).is_err());
    }

    #[test]
    fn requires_data_dir() {
        let err = parse(&["--roles", "dns"]).expect_err("--data-dir is required");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn does_not_create_the_data_dir() {
        let data_dir = std::env::temp_dir().join("tenko-serve-test-never-created");
        let flags = ["--data-dir", data_dir.to_str().expect("UTF-8 temp path")];
        let parsed = parse(&flags).expect("valid arguments");
        let _ = output_of(&parsed);
        assert!(!data_dir.exists());
    }

    #[test]
    fn run_reports_roles_in_canonical_order() {
        let args = parse_with_data_dir(&["--roles", "dhcp,dns"]);
        let text = output_of(&args);
        assert!(text.contains("roles: dns,dhcp"), "output: {text}");
        assert!(text.contains("config: (none)"), "output: {text}");
        assert!(text.contains("data dir: "), "output: {text}");
        assert!(text.starts_with("tenko "), "output: {text}");
    }

    #[test]
    fn run_reports_config_path() {
        let config = std::env::temp_dir().join("tenko-serve-test-config.toml");
        std::fs::write(&config, "").expect("write temporary configuration");
        let args = parse_with_data_dir(&["--config", config.to_str().expect("UTF-8 temp path")]);
        let text = output_of(&args);
        std::fs::remove_file(&config).expect("remove temporary configuration");
        assert!(
            text.contains(&format!("config: {}", config.display())),
            "output: {text}"
        );
    }

    #[test]
    fn run_rejects_missing_config_file() {
        let args = parse_with_data_dir(&["--config", "does/not/exist/tenko.toml"]);
        assert!(run(&args, &mut Vec::new()).is_err());
    }

    #[test]
    fn controller_prints_the_start_order() {
        let args = parse_with_data_dir(&["--roles", "controller"]);
        let text = output_of(&args);
        let expected = [
            "1. kek    key-encryption key provider",
            "2. vault  envelope encryption of system secrets",
            "3. store  replicated store (openraft over redb)",
            "4. auth   users, sessions, passkeys and TOTP",
            "5. ipam   IPAM domain and job engine",
            "6. api    HTTP API, web UI and server-sent events",
        ];
        let mut rest = text.as_str();
        for step in expected {
            let at = rest
                .find(step)
                .unwrap_or_else(|| panic!("missing or misordered step {step:?} in: {text}"));
            rest = &rest[at + step.len()..];
        }
        assert!(
            text.trim_end()
                .ends_with("roles are not implemented yet; exiting"),
            "output: {text}"
        );
    }

    #[test]
    fn dns_prints_no_start_order_and_mentions_the_later_phase() {
        let args = parse_with_data_dir(&["--roles", "dns"]);
        let text = output_of(&args);
        for (name, description) in CONTROLLER_START_ORDER {
            assert!(
                !text.contains(description),
                "unexpected step {name}: {text}"
            );
        }
        assert!(!text.contains("start order"), "output: {text}");
        assert!(
            text.contains("dns role: arrives in a later phase"),
            "output: {text}"
        );
    }

    #[test]
    fn every_non_controller_role_arrives_in_a_later_phase() {
        let args = parse_with_data_dir(&["--roles", "all"]);
        let text = output_of(&args);
        assert!(text.contains("controller start order:"), "output: {text}");
        for role in [Role::Dns, Role::Dhcp, Role::Probe] {
            let line = format!("{role} role: arrives in a later phase");
            assert!(text.contains(&line), "missing {line:?} in: {text}");
        }
        assert!(!text.contains("controller role: arrives"), "output: {text}");
    }
}
