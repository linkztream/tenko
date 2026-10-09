//! The `tenko-server` binary: one executable that runs any combination of the controller,
//! DNS, DHCP, and probe roles.
//!
//! Phase 0 only parses and reports its configuration; the role runtimes land later.

use std::{io::Write, path::PathBuf};

use anyhow::{Context as _, ensure};
use clap::Parser;
use tenko_core::RoleSet;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-server";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Tenko DDI server: DNS, DHCP and IPAM in one binary.
#[derive(Debug, Parser)]
#[command(name = "tenko-server", version)]
pub struct Args {
    /// Roles to run on this node: a comma-separated list of controller, dns, dhcp, and
    /// probe, or `all`.
    #[arg(long, value_name = "ROLES", default_value = "all")]
    pub roles: RoleSet,

    /// Path to the configuration file.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
}

/// Runs the server with the given arguments, writing a start-up summary to `out`.
///
/// Phase 0 reports the selected roles and returns immediately.
///
/// # Errors
///
/// Returns an error if a configuration file is given but does not exist, or if writing
/// the summary fails.
pub fn run(args: &Args, out: &mut impl Write) -> anyhow::Result<()> {
    if let Some(path) = &args.config {
        ensure!(
            path.is_file(),
            "configuration file {} does not exist",
            path.display()
        );
    }

    tracing::info!(roles = %args.roles, "starting tenko-server {}", version());

    let config = match &args.config {
        Some(path) => path.display().to_string(),
        None => "(none)".to_owned(),
    };
    writeln!(out, "tenko-server {}", version()).context("writing start-up summary")?;
    writeln!(out, "roles: {}", args.roles).context("writing start-up summary")?;
    writeln!(out, "config: {config}").context("writing start-up summary")?;

    tracing::info!("role runtimes are not implemented yet (Phase 0); exiting");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenko_core::Role;

    fn parse(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("tenko-server").chain(args.iter().copied()))
    }

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }

    #[test]
    fn parses_role_list() {
        let args = parse(&["--roles", "controller,dns"]).expect("valid arguments");
        assert!(args.roles.contains(Role::Controller));
        assert!(args.roles.contains(Role::Dns));
        assert!(!args.roles.contains(Role::Dhcp));
        assert!(!args.roles.contains(Role::Probe));
        assert!(args.config.is_none());
    }

    #[test]
    fn defaults_to_all_roles() {
        let args = parse(&[]).expect("valid arguments");
        assert_eq!(args.roles, RoleSet::ALL);
    }

    #[test]
    fn rejects_unknown_role() {
        assert!(parse(&["--roles", "dns,ntp"]).is_err());
    }

    #[test]
    fn run_reports_roles_in_canonical_order() {
        let args = parse(&["--roles", "dhcp,dns"]).expect("valid arguments");
        let mut out = Vec::new();
        run(&args, &mut out).expect("run succeeds");
        let text = String::from_utf8(out).expect("UTF-8 output");
        assert!(text.contains("roles: dns,dhcp"), "output: {text}");
        assert!(text.contains("config: (none)"), "output: {text}");
    }

    #[test]
    fn run_rejects_missing_config_file() {
        let args = parse(&["--config", "does/not/exist/tenko.toml"]).expect("valid arguments");
        assert!(run(&args, &mut Vec::new()).is_err());
    }
}
