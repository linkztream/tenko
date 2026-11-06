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
//! [`adopt_payload`] is the Windows service's first-start path (ADR 0023, item 11): the
//! running version looks at the installer's file, runs the store check with it and switches
//! the layout to it, all as the service account.
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

use std::{
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use clap::{Args, Subcommand};
use tenko_api::dto::{release::ReleaseVersion, updates::AttemptState};

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
            layout.version_dir(own)?.display()
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
        Some(current) => Ok(kept_aside_note(&current, own, exe, &layout.binary(own))),
    }
}

// ---------------------------------------------------------------------------------------
// The installer's file, adopted by the service at its start (ADR 0023, item 11)
// ---------------------------------------------------------------------------------------

/// The installer's file and what the service passes on to the check it runs with it.
#[derive(Debug, Clone, Copy)]
pub struct Payload<'a> {
    /// The file: `C:\Program Files\Tenko\tenko.exe` under the MSI, or the executable that
    /// ran `service install`. Only administrators and SYSTEM write it; the service account
    /// reads and runs it.
    pub path: &'a Path,
    /// The configuration file the service runs with, for `upgrade check`.
    pub config: Option<&'a Path>,
    /// The data directory of the command line, for `upgrade check`.
    pub data_dir: Option<&'a Path>,
    /// Seconds the adopted version has to become ready (`updates.ready_timeout_secs`).
    pub deadline_secs: u64,
}

/// What the service found when it looked at the installer's file at its start.
#[derive(Debug)]
pub enum Adoption {
    /// The file is not newer than the running version; nothing to do.
    NotNewer {
        /// The file's version.
        payload: ReleaseVersion,
        /// The version that runs.
        running: ReleaseVersion,
    },
    /// An install attempt is under way (the attempt record is `installing` or
    /// `restarting`); the file is looked at again at a later start.
    Busy,
    /// The file's version passed the store check and is in the layout: `current` names it,
    /// the attempt record is `restarting`, and the caller restarts so that it runs on
    /// probation like a version installed from the UI.
    Adopted {
        /// The version that ran.
        from: ReleaseVersion,
        /// The adopted version.
        to: ReleaseVersion,
        /// The report of the store check.
        report: check::Report,
    },
    /// The file's version refused the store; the running version keeps running, and the
    /// file is looked at again at the next start.
    Refused {
        /// The file's version.
        version: ReleaseVersion,
        /// The report of the store check, with the reason.
        report: check::Report,
    },
    /// The file could not be looked at, checked or copied; the running version keeps
    /// running.
    Failed(String),
}

/// The code of an adoption that failed after the attempt record was written.
const ADOPT_FAILED: &str = "upgrade.adopt_failed";

/// The service's first-start path on Windows: looks at the installer's file and, when it
/// is a newer version, runs the store check with it (`<file> upgrade check --json`, the
/// same check and the same refusals as by hand, on a copy of the closed store), copies it
/// into the layout, writes the attempt record and points `previous` at the running version
/// and `current` at the new one. Everything runs as the service account; the file in
/// Program Files is only read and executed. A file that is not newer leaves the layout
/// alone: the layout only moves forward, and a version installed from the UI stays.
pub fn adopt_payload(data_dir: &Path, running: &ReleaseVersion, payload: &Payload<'_>) -> Adoption {
    let layout = layout::Layout::new(data_dir);
    match std::fs::symlink_metadata(payload.path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return Adoption::Failed(format!("{} is not a regular file", payload.path.display()));
        }
        Err(error) => {
            return Adoption::Failed(format!("cannot read {}: {error}", payload.path.display()));
        }
    }
    match probation::read(&layout) {
        Ok(Some(attempt))
            if matches!(
                attempt.state,
                AttemptState::Installing | AttemptState::Restarting
            ) =>
        {
            return Adoption::Busy;
        }
        Ok(_) => {}
        Err(error) => {
            return Adoption::Failed(format!("the attempt record cannot be read: {error}"));
        }
    }
    let version = match payload_version(payload.path) {
        Ok(version) => version,
        Err(error) => return Adoption::Failed(error),
    };
    if &version <= running {
        return Adoption::NotNewer {
            payload: version,
            running: running.clone(),
        };
    }
    let report = match payload_check(payload) {
        Ok(report) => report,
        Err(error) => return Adoption::Failed(error),
    };
    match report.verdict {
        check::Verdict::Fresh | check::Verdict::Current | check::Verdict::MigrationNeeded => {}
        check::Verdict::Refused => return Adoption::Refused { version, report },
        check::Verdict::Failed => {
            return Adoption::Failed(format!(
                "the store check with version {version} could not run: {}",
                problem_text(&report)
            ));
        }
    }
    let from = layout.current().unwrap_or_else(|| running.clone());
    if let Err(error) = layout.install_binary(&version, payload.path) {
        return Adoption::Failed(format!(
            "cannot copy {} into the layout: {error}",
            payload.path.display()
        ));
    }
    let mut attempt =
        probation::Attempt::restarting(from.clone(), version.clone(), None, payload.deadline_secs);
    if let Err(error) = probation::write(&layout, &attempt) {
        return Adoption::Failed(format!("cannot write the attempt record: {error}"));
    }
    if let Err(error) = ensure_layout(data_dir, payload.path, &version) {
        // The record must not say `restarting` for a switch that did not happen: the next
        // start would wait for an attempt that never ends.
        attempt.state = AttemptState::Failed;
        attempt.reason = Some(ADOPT_FAILED.to_owned());
        if let Err(write_error) = probation::write(&layout, &attempt) {
            tracing::warn!(error = %write_error, "cannot record the failed adoption");
        }
        return Adoption::Failed(format!("cannot switch the layout: {error}"));
    }
    Adoption::Adopted {
        from,
        to: version,
        report,
    }
}

/// The code and the message of a report's problem, for a log line.
pub fn problem_text(report: &check::Report) -> String {
    report.problem.as_ref().map_or_else(
        || format!("{:?}", report.verdict).to_lowercase(),
        |problem| format!("{}: {}", problem.code, problem.message),
    )
}

/// Runs `<file> upgrade version` and reads the version it prints.
fn payload_version(path: &Path) -> Result<ReleaseVersion, String> {
    let output = Command::new(path)
        .args(["upgrade", "version"])
        .output()
        .map_err(|error| format!("cannot run {}: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} upgrade version failed ({}): {}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_version_output(&String::from_utf8_lossy(&output.stdout))
        .map_err(|error| format!("{} upgrade version: {error}", path.display()))
}

/// The version in the output of `upgrade version`: its first non-empty line.
///
/// # Errors
///
/// No line, or a line that is not a version.
pub fn parse_version_output(text: &str) -> Result<ReleaseVersion, String> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| "printed no version".to_owned())?;
    line.parse()
        .map_err(|_| format!("printed `{line}`, which is not a version"))
}

/// The arguments of the store check the service runs with the installer's file.
pub fn check_arguments(payload: &Payload<'_>) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = vec!["upgrade".into(), "check".into(), "--json".into()];
    if let Some(config) = payload.config {
        arguments.push("--config".into());
        arguments.push(config.into());
    }
    if let Some(data_dir) = payload.data_dir {
        arguments.push("--data-dir".into());
        arguments.push(data_dir.into());
    }
    arguments
}

/// Runs `<file> upgrade check --json` and reads the report.
fn payload_check(payload: &Payload<'_>) -> Result<check::Report, String> {
    let output = Command::new(payload.path)
        .args(check_arguments(payload))
        .output()
        .map_err(|error| format!("cannot run {}: {error}", payload.path.display()))?;
    parse_check_output(&output.stdout).map_err(|error| {
        format!(
            "{} upgrade check ({}): {error}; {}",
            payload.path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    })
}

/// The report in the output of `upgrade check --json`.
///
/// # Errors
///
/// The output is not a report (the check stopped before it wrote one).
pub fn parse_check_output(stdout: &[u8]) -> Result<check::Report, String> {
    serde_json::from_slice(stdout).map_err(|error| format!("the report is not readable: {error}"))
}

// round2: the wording says where the binary was kept and whether it matches the layout's copy.
/// The note for a binary that is not newer than the layout's `current`: where it was kept, and
/// whether it is byte-identical to the layout's copy of its own version.
fn kept_aside_note(
    current: &ReleaseVersion,
    own: &ReleaseVersion,
    exe: &std::path::Path,
    copy: &std::path::Path,
) -> String {
    let head = format!(
        "the layout runs {current}; this binary ({own}) is not newer and was kept aside at {}",
        exe.display()
    );
    match same_content(exe, copy) {
        Ok(true) => format!("{head}: identical to the layout's copy"),
        Ok(false) => format!(
            "{head}: differs from the layout's copy ({}); {} kept for inspection",
            copy.display(),
            exe.display()
        ),
        Err(error) => format!("{head}: could not be compared with the layout's copy: {error}"),
    }
}

/// Whether two files hold the same bytes.
fn same_content(a: &std::path::Path, b: &std::path::Path) -> std::io::Result<bool> {
    use std::io::Read;
    let (mut a, mut b) = (std::fs::File::open(a)?, std::fs::File::open(b)?);
    if a.metadata()?.len() != b.metadata()?.len() {
        return Ok(false);
    }
    let (mut left, mut right) = (vec![0_u8; 1 << 16], vec![0_u8; 1 << 16]);
    loop {
        let n = a.read(&mut left)?;
        if n == 0 {
            return Ok(true);
        }
        b.read_exact(&mut right[..n])?;
        if left[..n] != right[..n] {
            return Ok(false);
        }
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
    fn the_kept_aside_note_says_where_and_whether_the_copy_is_identical() {
        let data = std::env::temp_dir().join(format!("tenko-kept-aside-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        std::fs::create_dir_all(&data).expect("create");
        let exe = data.join("bootstrap-binary");
        std::fs::write(&exe, b"binary").expect("binary");
        let v1: ReleaseVersion = "0.1.0".parse().expect("version");
        let v2: ReleaseVersion = "0.2.0".parse().expect("version");
        ensure_layout(&data, &exe, &v1).expect("create");
        ensure_layout(&data, &exe, &v2).expect("adopt");
        let layout = layout::Layout::new(&data);
        let where_kept = format!("was kept aside at {}", exe.display());

        let note = ensure_layout(&data, &exe, &v1).expect("identical");
        assert!(note.contains(&where_kept), "{note}");
        assert!(note.ends_with(": identical to the layout's copy"), "{note}");

        std::fs::write(&exe, b"another binary").expect("changed");
        let note = ensure_layout(&data, &exe, &v1).expect("differs");
        let copy = layout.binary(&v1);
        assert!(note.contains(&where_kept), "{note}");
        assert!(
            note.contains(&format!(
                "differs from the layout's copy ({}); {} kept for inspection",
                copy.display(),
                exe.display()
            )),
            "{note}"
        );

        std::fs::write(&exe, b"binarY").expect("same length");
        let note = ensure_layout(&data, &exe, &v1).expect("differs by content");
        assert!(note.contains("differs from the layout's copy"), "{note}");
        std::fs::remove_dir_all(&data).expect("clean up");
    }

    #[test]
    fn the_version_output_is_its_first_line() {
        assert_eq!(
            parse_version_output("0.2.0\n").expect("version"),
            "0.2.0".parse::<ReleaseVersion>().expect("version")
        );
        assert_eq!(
            parse_version_output("\r\n  1.2.3-rc.1  \r\n").expect("version"),
            "1.2.3-rc.1".parse::<ReleaseVersion>().expect("version")
        );
        assert!(parse_version_output("").is_err());
        assert!(parse_version_output("tenko 0.2.0").is_err());
    }

    #[test]
    fn the_check_arguments_name_the_configuration_and_the_data_directory() {
        let payload = Payload {
            path: Path::new("payload"),
            config: Some(Path::new(r"C:\ProgramData\Tenko\tenko.toml")),
            data_dir: Some(Path::new(r"D:\Tenko Data")),
            deadline_secs: 60,
        };
        let text: Vec<String> = check_arguments(&payload)
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            text,
            [
                "upgrade",
                "check",
                "--json",
                "--config",
                r"C:\ProgramData\Tenko\tenko.toml",
                "--data-dir",
                r"D:\Tenko Data"
            ]
        );
        let bare = Payload {
            config: None,
            data_dir: None,
            ..payload
        };
        assert_eq!(check_arguments(&bare).len(), 3);
    }

    #[test]
    fn the_check_report_is_read_back_from_its_json() {
        let json = serde_json::json!({
            "verdict": "refused",
            "exit_code": 11,
            "binary_version": "0.3.0",
            "binary_format": 2,
            "data_dir": "/var/lib/tenko",
            "found_format": 9,
            "legacy": false,
            "steps": [],
            "problem": {"code": "upgrade.format_newer", "message": "format 9 is newer"}
        });
        let report = parse_check_output(json.to_string().as_bytes()).expect("report");
        assert_eq!(report.verdict, check::Verdict::Refused);
        assert_eq!(report.exit_code, 11);
        assert_eq!(
            problem_text(&report),
            "upgrade.format_newer: format 9 is newer"
        );
        assert!(parse_check_output(b"tenko upgrade check: config.read").is_err());
    }

    /// A data directory with a fake installer's file: a shell script that answers `upgrade
    /// version` with `version` and `upgrade check` with a report of `verdict`.
    #[cfg(unix)]
    fn fake_payload(name: &str, version: &str, verdict: &str) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let data = std::env::temp_dir().join(format!("tenko-adopt-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        std::fs::create_dir_all(&data).expect("create");
        let report = serde_json::json!({
            "verdict": verdict,
            "exit_code": if verdict == "refused" { 11 } else { 0 },
            "binary_version": version,
            "binary_format": 1,
            "data_dir": data,
            "found_format": null,
            "legacy": false,
            "steps": [],
            "problem": if verdict == "refused" {
                serde_json::json!({"code": "upgrade.format_newer", "message": "the store is newer"})
            } else {
                serde_json::Value::Null
            }
        });
        let report_path = data.join("report.json");
        std::fs::write(&report_path, report.to_string()).expect("report");
        let payload = data.join("installer-file");
        std::fs::write(
            &payload,
            format!(
                "#!/bin/sh\ncase \"$2\" in\nversion) echo {version} ;;\ncheck) cat '{}' ;;\n*) exit 2 ;;\nesac\n",
                report_path.display()
            ),
        )
        .expect("script");
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).expect("mode");
        (data, payload)
    }

    #[cfg(unix)]
    fn payload_of(path: &Path) -> Payload<'_> {
        Payload {
            path,
            config: None,
            data_dir: None,
            deadline_secs: 90,
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_newer_installer_file_is_checked_copied_and_switched_to() {
        let (data, payload) = fake_payload("adopted", "0.2.0", "fresh");
        let v1: ReleaseVersion = "0.1.0".parse().expect("version");
        let v2: ReleaseVersion = "0.2.0".parse().expect("version");
        let running = data.join("running-binary");
        std::fs::write(&running, b"old").expect("binary");
        ensure_layout(&data, &running, &v1).expect("layout");
        let layout = layout::Layout::new(&data);

        let outcome = adopt_payload(&data, &v1, &payload_of(&payload));
        let Adoption::Adopted { from, to, report } = outcome else {
            panic!("expected an adoption, got {outcome:?}");
        };
        assert_eq!((from, to), (v1.clone(), v2.clone()));
        assert_eq!(report.verdict, check::Verdict::Fresh);
        assert_eq!(layout.current(), Some(v2.clone()));
        assert_eq!(layout.previous(), Some(v1.clone()));
        assert_eq!(
            std::fs::read(layout.binary(&v2)).expect("copied"),
            std::fs::read(&payload).expect("payload")
        );
        let attempt = probation::read(&layout).expect("read").expect("record");
        assert_eq!(attempt.state, AttemptState::Restarting);
        assert_eq!((attempt.from, attempt.to), (v1, v2));
        assert_eq!(attempt.deadline_secs, 90);
        assert_eq!(attempt.job_id, None);

        // While the record is `restarting`, the file is left alone.
        assert!(matches!(
            adopt_payload(
                &data,
                &"0.2.0".parse().expect("version"),
                &payload_of(&payload)
            ),
            Adoption::Busy
        ));
        std::fs::remove_dir_all(&data).expect("clean up");
    }

    #[cfg(unix)]
    #[test]
    fn an_installer_file_that_is_not_newer_or_refuses_the_store_changes_nothing() {
        let (data, payload) = fake_payload("refused", "0.3.0", "refused");
        let v2: ReleaseVersion = "0.2.0".parse().expect("version");
        let v3: ReleaseVersion = "0.3.0".parse().expect("version");
        let running = data.join("running-binary");
        std::fs::write(&running, b"running").expect("binary");
        ensure_layout(&data, &running, &v2).expect("layout");
        let layout = layout::Layout::new(&data);

        let outcome = adopt_payload(&data, &v3, &payload_of(&payload));
        assert!(
            matches!(&outcome, Adoption::NotNewer { payload, running } if payload == &v3 && running == &v3),
            "{outcome:?}"
        );
        let outcome = adopt_payload(&data, &v2, &payload_of(&payload));
        let Adoption::Refused { version, report } = outcome else {
            panic!("expected a refusal, got {outcome:?}");
        };
        assert_eq!(version, v3);
        assert_eq!(
            problem_text(&report),
            "upgrade.format_newer: the store is newer"
        );
        assert_eq!(layout.current(), Some(v2));
        assert_eq!(layout.previous(), None);
        assert!(!layout.binary(&v3).exists());
        assert!(probation::read(&layout).expect("read").is_none());

        let missing = data.join("no-such-file");
        assert!(matches!(
            adopt_payload(
                &data,
                &"0.1.0".parse().expect("version"),
                &payload_of(&missing)
            ),
            Adoption::Failed(_)
        ));
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
