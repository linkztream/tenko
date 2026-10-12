//! Releases and upgrades (OPS-23, OPS-24, R17).
//!
//! | Module | Contents |
//! |---|---|
//! | [`migrations`] | the format version this binary writes ([`migrations::CURRENT`]) and the migration registry |
//! | [`datadir`] | the format check at start-up: compare the marker, copy the closed store aside, migrate, bump |
//! | [`check`] | `tenko upgrade check`: the same check as a dry run against a copy, with exit codes 0, 10 and 11 |
//! | [`layout`] | the `current` link layout under `<data_dir>/updates` and `tenko upgrade layout` |
//! | [`probation`] | the probation of a newly installed version and the switch back |
//! | [`restart`] | restarts through the service manager (exit status 12) |
//! | [`rolling`] | rolling upgrades of a controller cluster: the leader-gated migration and the format status |
//! | [`source`] | the release source: the manifest and downloads from the pinned origin |
//! | [`updates`] | the update service behind `/system/updates`: check, status, install, uploads, what is new |
//! | [`steps`] | the steps of the install job: fetch, verify, check, switch |
//!
//! `docs/upgrades.md` describes the convention (every change to stored data adds a
//! migration and a fixture) and the operator's procedure.

pub mod check;
pub mod datadir;
pub mod layout;
pub mod migrations;
pub mod probation;
pub mod restart;
pub mod rolling;
pub mod source;
pub mod steps;
pub mod updates;

use std::{io::Write, path::PathBuf};

use clap::{Args, Subcommand};
use tenko_api::dto::release::ReleaseVersion;

use crate::{config, exit};

pub use check::CheckArgs;

/// The version this binary runs as for updates: the crate version.
///
/// Debug builds started with `TENKO_TEST_VERSION_FROM_LAYOUT=1` take the version from the
/// layout directory they run from (`<data_dir>/updates/<version>/tenko`), so that tests can
/// install one build as two versions. Release builds ignore the variable.
pub fn running_version() -> ReleaseVersion {
    let own = crate::version()
        .parse()
        .unwrap_or_else(|_| ReleaseVersion::new(0, 0, 0));
    if cfg!(debug_assertions)
        && std::env::var_os("TENKO_TEST_VERSION_FROM_LAYOUT").is_some_and(|value| value == "1")
        && let Ok(exe) = std::env::current_exe().and_then(std::fs::canonicalize)
        && let Some(parent) = exe.parent()
        && parent
            .parent()
            .and_then(|root| root.file_name())
            .is_some_and(|name| name == layout::UPDATES_DIR)
        && let Some(version) = parent
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.parse().ok())
    {
        return version;
    }
    own
}

/// Arguments of `tenko upgrade layout`.
#[derive(Debug, Clone, Args)]
pub struct LayoutArgs {
    /// The configuration file; it names the data directory.
    #[arg(long, value_name = "FILE", env = "TENKO_CONFIG")]
    pub config: Option<PathBuf>,

    /// The data directory; overrides `data_dir` of the configuration.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,
}

/// Subcommands of `tenko upgrade`.
#[derive(Debug, Clone, Subcommand)]
pub enum UpgradeCommand {
    /// Check whether this binary can open a data directory, and dry-run its migrations
    /// against a copy (exit 0: nothing to do, 10: a migration is needed and passed, 11:
    /// refused). Run it with the new binary before switching, with the server stopped.
    Check(CheckArgs),
    /// Print the data-directory format version this binary writes.
    Format,
    /// Set up the `current` link layout that installation from the UI needs, from this
    /// binary: copy it to `<data_dir>/updates/<version>/` and point `current` at it (also
    /// when it is newer than the current one). The systemd unit runs it before every start.
    Layout(LayoutArgs),
    /// Print the version this binary installs and runs as.
    #[command(hide = true)]
    Version,
}

impl UpgradeCommand {
    /// The command as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Check(_) => "upgrade check",
            Self::Format => "upgrade format",
            Self::Layout(_) => "upgrade layout",
            Self::Version => "upgrade version",
        }
    }
}

/// Runs `tenko upgrade …` and returns the exit status.
pub fn command(command: &UpgradeCommand, out: &mut impl Write, err: &mut impl Write) -> u8 {
    match command {
        UpgradeCommand::Check(args) => {
            crate::logging::init_client();
            check::command(args, out, err)
        }
        UpgradeCommand::Format => {
            let _ = writeln!(out, "{}", migrations::CURRENT);
            exit::OK
        }
        UpgradeCommand::Version => {
            let _ = writeln!(out, "{}", running_version());
            exit::OK
        }
        UpgradeCommand::Layout(args) => layout_command(args, out, err),
    }
}

/// `tenko upgrade layout`.
fn layout_command(args: &LayoutArgs, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let sources = config::Sources {
        file: args.config.clone(),
        data_dir: args.data_dir.clone(),
        roles: None,
    };
    let resolved =
        match config::load(&sources, std::env::vars()).and_then(|loaded| loaded.config.resolve()) {
            Ok(resolved) => resolved,
            Err(error) => {
                let _ = writeln!(err, "tenko upgrade layout: {error}");
                return exit::CONFIG;
            }
        };
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            let _ = writeln!(
                err,
                "tenko upgrade layout: cannot find this executable: {error}"
            );
            return exit::FAILURE;
        }
    };
    match ensure_layout(&resolved.data_dir, &exe, &running_version()) {
        Ok(note) => {
            let layout = layout::Layout::new(&resolved.data_dir);
            let _ = writeln!(out, "{note}");
            let _ = writeln!(out, "run: {}", layout.current_binary().display());
            exit::OK
        }
        Err(error) => {
            let _ = writeln!(err, "tenko upgrade layout: {error}");
            exit::FAILURE
        }
    }
}

/// Sets up the layout from the binary `exe` of version `own`: copies it in when missing,
/// creates `current`, or moves `current` to it when it is newer (an administrator replaced
/// the installed binary by hand). Returns what it did.
///
/// # Errors
///
/// The I/O error.
pub fn ensure_layout(
    data_dir: &std::path::Path,
    exe: &std::path::Path,
    own: &ReleaseVersion,
) -> std::io::Result<String> {
    let layout = layout::Layout::new(data_dir);
    if layout.runs(exe) {
        return Ok(format!(
            "this binary runs from the layout ({})",
            layout.version_dir(own).display()
        ));
    }
    if !layout.binary(own).is_file() {
        layout.install_binary(own, exe)?;
    }
    match layout.current() {
        None => {
            layout.point(layout::CURRENT, own)?;
            Ok(format!("created the layout with version {own}"))
        }
        Some(current) if &current < own => {
            layout.point(layout::PREVIOUS, &current)?;
            layout.point(layout::CURRENT, own)?;
            Ok(format!(
                "switched the layout from {current} to this binary, {own}"
            ))
        }
        Some(current) => Ok(format!(
            "the layout runs {current}; this binary ({own}) is not newer and was kept aside"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layout_adopts_a_newer_binary_and_keeps_a_newer_current() {
        let data = std::env::temp_dir().join(format!("tenko-ensure-layout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        std::fs::create_dir_all(&data).expect("create");
        let exe = data.join("bootstrap-binary");
        std::fs::write(&exe, b"binary").expect("binary");
        let v1: ReleaseVersion = "0.1.0".parse().expect("version");
        let v2: ReleaseVersion = "0.2.0".parse().expect("version");
        let note = ensure_layout(&data, &exe, &v1).expect("create");
        assert!(note.contains("created"), "{note}");
        let layout = layout::Layout::new(&data);
        assert_eq!(layout.current(), Some(v1.clone()));
        let note = ensure_layout(&data, &exe, &v2).expect("adopt");
        assert!(note.contains("switched"), "{note}");
        assert_eq!(layout.current(), Some(v2.clone()));
        assert_eq!(layout.previous(), Some(v1.clone()));
        let note = ensure_layout(&data, &exe, &v1).expect("older");
        assert!(note.contains("not newer"), "{note}");
        assert_eq!(layout.current(), Some(v2.clone()));
        let note = ensure_layout(&data, &layout.current_binary(), &v2).expect("runs");
        assert!(note.contains("runs from the layout"), "{note}");
        std::fs::remove_dir_all(&data).expect("clean up");
    }

    #[test]
    fn format_prints_the_current_version() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(command(&UpgradeCommand::Format, &mut out, &mut err), 0);
        assert_eq!(
            String::from_utf8(out).expect("UTF-8"),
            format!("{}\n", migrations::CURRENT)
        );
        assert_eq!(err, Vec::<u8>::new());
    }
}
