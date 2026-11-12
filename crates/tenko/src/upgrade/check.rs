//! `tenko upgrade check`: can this binary open a data directory, and do its migrations
//! pass? (OPS-23)
//!
//! The check never changes the data directory. It reads the format marker, refuses a newer
//! format or a missing migration at once, and otherwise copies the closed store into a
//! work directory, opens the copy with this binary's store, runs the migrations there and
//! throws the copy away. With `--disposable` the directory is itself a copy (the in-app
//! update hands the new binary a copy of the running state) and is used in place.
//!
//! | Exit | Meaning |
//! |---|---|
//! | 0 | Nothing to do: the directory is at this binary's format, or there is no store yet |
//! | 10 | A migration is needed and the dry run passed |
//! | 11 | Refused: a newer format, a missing migration, records that disagree, or a migration that failed in the dry run |
//! | 1 | The check could not run: the store is open in a running server, or a file operation failed |
//! | 3 | The configuration is invalid |
//!
//! The running binary of an in-app update runs this check of the new binary, so its command
//! line and its report are a contract between versions. Every released install job runs
//! `upgrade check --data-dir <copy> --disposable --node-id <id> --json`, and from this
//! version on with `--config <file>`; every release reads `verdict` and `problem` of the
//! report, ignores keys it does not know and accepts only `current` and `migration_needed`.
//! A later binary keeps those flags and those verdicts; this one reads a verdict it does not
//! know as a refusal ([`Verdict::Unknown`]) and a report without its other keys as their
//! defaults. The golden file `tests/fixtures/upgrade/check-report-0.0.11.json` holds a
//! report as 0.0.11 prints it.

use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::Args;
use serde::{Deserialize, Serialize};
use tenko_core::NodeId;
use tenko_store::{
    format::{self, FormatError},
    raft::{RaftStore, RaftStoreConfig},
};

use super::{
    datadir::{self, Plan, UpgradeError},
    migrations::Registry,
};
use crate::{config, exit};

/// Arguments of `tenko upgrade check`.
#[derive(Debug, Clone, Args)]
pub struct CheckArgs {
    /// The configuration file; it names the data directory and the node id.
    #[arg(long, value_name = "FILE", env = "TENKO_CONFIG")]
    pub config: Option<PathBuf>,

    /// The data directory to check; overrides `data_dir` of the configuration. The server
    /// that uses it must be stopped.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// The directory under which the copy for the dry run goes, in a new subdirectory of its
    /// own that is removed afterwards; the directory itself and what else it holds stay
    /// (default `<data dir>/upgrade-check`, removed afterwards).
    #[arg(long, value_name = "PATH")]
    pub work_dir: Option<PathBuf>,

    /// The data directory is itself a disposable copy: run the dry run in place.
    #[arg(long, hide = true)]
    pub disposable: bool,

    /// The Raft node id of the store (default: `node.id` of the configuration).
    #[arg(long, value_name = "ID", hide = true)]
    pub node_id: Option<u64>,

    /// Print the report as JSON.
    #[arg(long)]
    pub json: bool,
}

/// The verdict of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// No store yet; it is created at this binary's format.
    Fresh,
    /// The directory is at this binary's format.
    Current,
    /// A migration is needed and the dry run passed.
    MigrationNeeded,
    /// This binary refuses the directory.
    Refused,
    /// The check could not run.
    Failed,
    /// A verdict of a newer binary; never printed by this one, and read as a refusal.
    #[serde(other)]
    Unknown,
}

impl Verdict {
    /// The exit status of the verdict.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Fresh | Self::Current => exit::OK,
            Self::MigrationNeeded => exit::MIGRATION_NEEDED,
            Self::Refused | Self::Unknown => exit::UPGRADE_REFUSED,
            Self::Failed => exit::FAILURE,
        }
    }

    /// Whether an in-app install switches to the binary that gave this verdict on a copy of
    /// the running state: the copy is at its format, or its migration passed. A copy of a
    /// running state is never empty, so `fresh` means the copy failed.
    pub const fn lets_install_switch(self) -> bool {
        matches!(self, Self::Current | Self::MigrationNeeded)
    }

    /// Whether the Windows service adopts the installer's binary that gave this verdict on
    /// its data directory, which has no store yet before the first start (`fresh`).
    pub const fn lets_adoption_switch(self) -> bool {
        matches!(self, Self::Fresh | Self::Current | Self::MigrationNeeded)
    }
}

/// One migration of the dry run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// The format the step produces.
    pub to: u32,
    /// What it does.
    pub summary: String,
}

/// Why a check refused or failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    /// The stable code, for example `upgrade.format_newer`.
    pub code: String,
    /// What is wrong, in English.
    pub message: String,
}

/// The report of `tenko upgrade check`, printed as text or as JSON. The JSON is read back by
/// the install job and by the service when it runs the check with the installer's file at
/// its start ([`super::parse_check_output`]); the keys besides `verdict` have defaults so
/// that a report of another version still reads (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// The verdict.
    pub verdict: Verdict,
    /// The exit status.
    #[serde(default)]
    pub exit_code: u8,
    /// The version of this binary.
    #[serde(default)]
    pub binary_version: String,
    /// The data-directory format this binary writes.
    #[serde(default)]
    pub binary_format: u32,
    /// The data directory.
    #[serde(default)]
    pub data_dir: PathBuf,
    /// The format the directory has, when there is a store.
    #[serde(default)]
    pub found_format: Option<u32>,
    /// The directory has no format marker (written before format versions existed).
    #[serde(default)]
    pub legacy: bool,
    /// The migrations the dry run ran, in order.
    #[serde(default)]
    pub steps: Vec<Step>,
    /// Why the check refused or failed.
    #[serde(default)]
    pub problem: Option<Problem>,
}

impl Report {
    fn new(data_dir: &Path, registry: Registry<'_>) -> Self {
        Self {
            verdict: Verdict::Failed,
            exit_code: exit::FAILURE,
            binary_version: crate::version().to_owned(),
            binary_format: registry.current,
            data_dir: data_dir.to_path_buf(),
            found_format: None,
            legacy: false,
            steps: Vec::new(),
            problem: None,
        }
    }

    fn finish(mut self, verdict: Verdict) -> Self {
        self.verdict = verdict;
        self.exit_code = verdict.exit_code();
        self
    }

    fn problem(self, verdict: Verdict, code: &str, message: impl Into<String>) -> Self {
        Self {
            problem: Some(Problem {
                code: code.to_owned(),
                message: message.into(),
            }),
            ..self.finish(verdict)
        }
    }

    /// The report as text for a terminal.
    pub fn text(&self) -> String {
        let mut lines = vec![format!(
            "tenko {} (data format {}) checked {}",
            self.binary_version,
            self.binary_format,
            self.data_dir.display()
        )];
        if let Some(found) = self.found_format {
            lines.push(format!(
                "found: data format {found}{}",
                if self.legacy {
                    " (no format marker: a directory from before format versions)"
                } else {
                    ""
                }
            ));
        }
        for step in &self.steps {
            lines.push(format!(
                "  migrated to format {}: {}",
                step.to, step.summary
            ));
        }
        lines.push(match self.verdict {
            Verdict::Fresh => {
                "result: no store yet; tenko serve creates it at this format (exit 0)".to_owned()
            }
            Verdict::Current => {
                "result: the directory is at this binary's format, nothing to do (exit 0)"
                    .to_owned()
            }
            Verdict::MigrationNeeded => format!(
                "result: a migration is needed and passed on a copy; tenko serve copies the \
                 store aside and migrates at its next start (exit {})",
                exit::MIGRATION_NEEDED
            ),
            Verdict::Refused | Verdict::Unknown => {
                format!("result: refused (exit {})", exit::UPGRADE_REFUSED)
            }
            Verdict::Failed => "result: the check could not run (exit 1)".to_owned(),
        });
        if let Some(problem) = &self.problem {
            lines.push(format!("{}: {}", problem.code, problem.message));
        }
        let mut text = lines.join("\n");
        text.push('\n');
        text
    }
}

/// `tenko upgrade check`: prints the report and returns the exit status.
pub fn command(args: &CheckArgs, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let sources = config::Sources {
        file: args.config.clone(),
        data_dir: args.data_dir.clone(),
        roles: None,
    };
    let resolved =
        match config::load(&sources, std::env::vars()).and_then(|loaded| loaded.config.resolve()) {
            Ok(resolved) => resolved,
            Err(error) => {
                let _ = writeln!(err, "tenko upgrade check: {error}");
                return exit::CONFIG;
            }
        };
    let node = NodeId(args.node_id.unwrap_or(resolved.node_id.0));
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(err, "tenko upgrade check: cannot start a runtime: {error}");
            return exit::FAILURE;
        }
    };
    let options = Options {
        work_dir: args.work_dir.clone(),
        disposable: args.disposable,
        node,
    };
    let report = runtime.block_on(check(&resolved.data_dir, &options, Registry::builtin()));
    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                let _ = writeln!(out, "{json}");
            }
            Err(error) => {
                let _ = writeln!(err, "tenko upgrade check: {error}");
                return exit::FAILURE;
            }
        }
    } else {
        let _ = write!(out, "{}", report.text());
    }
    report.exit_code
}

/// How [`check`] works on the directory.
#[derive(Debug, Clone)]
pub struct Options {
    /// The directory under which the copy goes, in a new subdirectory; default
    /// `<data dir>/upgrade-check`, which belongs to the check.
    pub work_dir: Option<PathBuf>,
    /// Run in place: the directory is a copy.
    pub disposable: bool,
    /// The node id of the store.
    pub node: NodeId,
}

/// Checks `data_dir` against `registry` and returns the report.
pub async fn check(data_dir: &Path, options: &Options, registry: Registry<'_>) -> Report {
    let report = Report::new(data_dir, registry);
    let store_dir = data_dir.join("store");
    let plan = match datadir::preflight(&store_dir, registry) {
        Ok(plan) => plan,
        Err(error) => return refused(report, &error),
    };
    let mut report = report;
    match plan {
        Plan::Fresh => return report.finish(Verdict::Fresh),
        Plan::Current { legacy } => {
            report.found_format = Some(registry.current);
            report.legacy = legacy;
        }
        Plan::Migrate { from, legacy, .. } => {
            report.found_format = Some(from);
            report.legacy = legacy;
        }
    }
    // A directory the operator named that does not exist yet is created by the check and
    // removed again when nothing else is in it; one that existed stays.
    let created = options.work_dir.clone().filter(|named| !named.exists());
    let (dir, cleanup) = if options.disposable {
        (store_dir.clone(), None)
    } else {
        // A directory the operator named is never removed: the copy goes into a new
        // subdirectory of it.
        let work = if let Some(parent) = &options.work_dir {
            parent.join(format!(
                "tenko-upgrade-check-{}",
                uuid::Uuid::now_v7().simple()
            ))
        } else {
            let work = data_dir.join("upgrade-check");
            let _ = std::fs::remove_dir_all(&work);
            work
        };
        if let Err(error) = datadir::check_space(&work, &store_dir) {
            remove_work(&work, created.as_deref());
            return report.problem(Verdict::Failed, error.code(), error.to_string());
        }
        let copy = work.join("store");
        if let Err(error) = format::copy_closed_store(&store_dir, &copy) {
            remove_work(&work, created.as_deref());
            let verdict = match error {
                FormatError::InvalidMarker { .. } => Verdict::Refused,
                _ => Verdict::Failed,
            };
            return report.problem(verdict, error.code(), error.to_string());
        }
        (copy, Some(work))
    };
    let report = dry_run(report, &dir, plan, options.node, registry).await;
    if let Some(work) = cleanup {
        remove_work(&work, created.as_deref());
    }
    // The start that migrates copies the store first; it needs the room for that copy.
    if report.verdict == Verdict::MigrationNeeded
        && let Err(error) = datadir::check_space(&data_dir.join(datadir::BACKUPS_DIR), &store_dir)
    {
        return report.problem(Verdict::Failed, error.code(), error.to_string());
    }
    report
}

/// Removes the work copy, and the named directory `created` that the check made for it.
fn remove_work(work: &Path, created: Option<&Path>) {
    if let Err(error) = std::fs::remove_dir_all(work)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(%error, dir = %work.display(), "cannot remove the work copy");
    }
    if let Some(created) = created {
        // Removes only an empty directory: anything put into it meanwhile stays, with it.
        let _ = std::fs::remove_dir(created);
    }
}

/// Opens the store in `dir` and runs the migrations there.
async fn dry_run(
    mut report: Report,
    dir: &Path,
    plan: Plan,
    node: NodeId,
    registry: Registry<'_>,
) -> Report {
    let mut config = RaftStoreConfig::new(dir);
    config.node_id = node;
    config.fsync_probe_samples = 0;
    config.log_cache_bytes = 1024 * 1024;
    config.sm_cache_bytes = 4 * 1024 * 1024;
    config.write_timeout = Duration::from_secs(120);
    let store = match RaftStore::open(config).await {
        Ok(store) => store,
        Err(error) => {
            return report.problem(
                Verdict::Refused,
                "upgrade.open_failed",
                format!("this binary cannot open the store: {error}"),
            );
        }
    };
    let outcome = datadir::finish(&store, dir, plan, registry, crate::version()).await;
    if let Err(error) = store.shutdown().await {
        tracing::warn!(%error, "the store copy did not close cleanly");
    }
    drop(store);
    match outcome {
        Ok(outcome) => {
            report.steps = outcome
                .migrated
                .iter()
                .map(|to| Step {
                    to: *to,
                    summary: registry
                        .migration(*to)
                        .map(|migration| migration.summary().to_owned())
                        .unwrap_or_default(),
                })
                .collect();
            if outcome.migrated.is_empty() {
                report.found_format = Some(outcome.version);
                report.finish(Verdict::Current)
            } else {
                report.finish(Verdict::MigrationNeeded)
            }
        }
        Err(error) => refused(report, &error),
    }
}

fn refused(report: Report, error: &UpgradeError) -> Report {
    let verdict = match error {
        UpgradeError::Format(FormatError::Io { .. } | FormatError::InUse(_)) => Verdict::Failed,
        _ => Verdict::Refused,
    };
    let found = match error {
        UpgradeError::Newer { found, .. } => Some(*found),
        UpgradeError::MissingMigration { from, .. } => Some(*from),
        _ => report.found_format,
    };
    Report {
        found_format: found,
        ..report.problem(verdict, error.code(), error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tenko_store::{Mutation, ReadView, format::Marker};

    use super::*;
    use crate::upgrade::migrations::{Migration, MigrationError};

    struct ToTwo;

    impl Migration for ToTwo {
        fn to(&self) -> u32 {
            2
        }
        fn summary(&self) -> &'static str {
            "test step"
        }
        fn plan(&self, _view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
            Ok(Vec::new())
        }
    }

    static STEPS: [&dyn Migration; 1] = [&ToTwo];

    fn temp_dir(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tenko-check-test-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create");
        dir
    }

    fn options() -> Options {
        Options {
            work_dir: None,
            disposable: false,
            node: NodeId(1),
        }
    }

    /// A data directory with a real store at format 1.
    async fn data_dir_at_format_1(name: &str) -> PathBuf {
        let dir = temp_dir(name);
        let store_dir = dir.join("store");
        let mut config = RaftStoreConfig::new(&store_dir);
        config.fsync_probe_samples = 0;
        let store = RaftStore::open(config).await.expect("open");
        let one = Registry {
            current: 1,
            migrations: &[],
        };
        datadir::finish(&store, &store_dir, Plan::Fresh, one, "0.1.0")
            .await
            .expect("format 1");
        store.shutdown().await.expect("shutdown");
        dir
    }

    #[tokio::test]
    async fn verdicts_follow_the_format_and_leave_the_directory_alone() {
        let empty = temp_dir("fresh");
        let report = check(&empty, &options(), Registry::builtin()).await;
        assert_eq!(report.verdict, Verdict::Fresh);
        assert_eq!(report.exit_code, 0);

        let dir = data_dir_at_format_1("current").await;
        let current = Registry {
            current: 1,
            migrations: &[],
        };
        let report = check(&dir, &options(), current).await;
        assert_eq!(report.verdict, Verdict::Current, "{report:?}");
        assert_eq!(report.found_format, Some(1));
        assert!(
            !dir.join("upgrade-check").exists(),
            "the work copy is removed"
        );

        let two = Registry {
            current: 2,
            migrations: &STEPS,
        };
        let report = check(&dir, &options(), two).await;
        assert_eq!(report.verdict, Verdict::MigrationNeeded, "{report:?}");
        assert_eq!(report.exit_code, 10);
        assert_eq!(report.steps.len(), 1);
        assert!(report.text().contains("migrated to format 2: test step"));
        // The original is untouched: still format 1.
        let marker = format::read_marker(&dir.join("store")).expect("marker");
        assert_eq!(marker.map(|marker| marker.version), Some(1));

        let missing = Registry {
            current: 2,
            migrations: &[],
        };
        let report = check(&dir, &options(), missing).await;
        assert_eq!(report.verdict, Verdict::Refused);
        assert_eq!(report.exit_code, 11);
        assert_eq!(
            report.problem.as_ref().map(|problem| problem.code.as_str()),
            Some("upgrade.migration_missing")
        );
        std::fs::remove_dir_all(&dir).expect("clean up");
        std::fs::remove_dir_all(&empty).expect("clean up");
    }

    /// The report as 0.0.11 prints it reads; a verdict of a newer binary is a refusal, and
    /// a report with only a verdict still reads.
    #[test]
    fn reports_of_other_versions_read() {
        let released = crate::upgrade::parse_check_output(include_bytes!(
            "../../tests/fixtures/upgrade/check-report-0.0.11.json"
        ))
        .expect("the report of 0.0.11");
        assert_eq!(released.verdict, Verdict::MigrationNeeded);
        assert_eq!(released.steps.len(), 1);
        assert!(released.verdict.lets_install_switch());
        let newer = crate::upgrade::parse_check_output(
            br#"{"verdict":"needs_operator","exit_code":13,"hint":"new key"}"#,
        )
        .expect("a newer report");
        assert_eq!(newer.verdict, Verdict::Unknown);
        assert!(!newer.verdict.lets_install_switch());
        assert!(!newer.verdict.lets_adoption_switch());
        assert_eq!(newer.verdict.exit_code(), exit::UPGRADE_REFUSED);
        let fresh = crate::upgrade::parse_check_output(br#"{"verdict":"fresh"}"#).expect("fresh");
        assert!(!fresh.verdict.lets_install_switch());
        assert!(fresh.verdict.lets_adoption_switch());
    }

    /// The command lines that released install jobs and this one run: a later binary must
    /// keep accepting them.
    #[test]
    fn the_command_lines_of_released_install_jobs_parse() {
        #[derive(clap::Parser)]
        struct Check {
            #[command(flatten)]
            args: CheckArgs,
        }
        let released = <Check as clap::Parser>::try_parse_from([
            "check",
            "--data-dir",
            "/var/lib/tenko/updates/check-0.0.12",
            "--disposable",
            "--node-id",
            "1",
            "--json",
        ])
        .expect("the released command line");
        assert!(released.args.disposable && released.args.json);
        assert_eq!(released.args.node_id, Some(1));
        let with_config = <Check as clap::Parser>::try_parse_from([
            "check",
            "--config",
            "/etc/tenko/tenko.toml",
            "--data-dir",
            "/var/lib/tenko/updates/check-0.0.12",
            "--disposable",
            "--node-id",
            "1",
            "--json",
        ])
        .expect("this version's command line");
        assert_eq!(
            with_config.args.config.as_deref(),
            Some(Path::new("/etc/tenko/tenko.toml"))
        );
    }

    /// `--work-dir` names a directory of the operator's: the check works in a new
    /// subdirectory and leaves the directory and its other files in place.
    #[tokio::test]
    async fn a_named_work_directory_and_its_files_stay() {
        let dir = data_dir_at_format_1("work-dir").await;
        let named = dir.join("operator-tmp");
        std::fs::create_dir(&named).expect("named");
        std::fs::write(named.join("keep.txt"), b"the operator's").expect("file");
        let options = Options {
            work_dir: Some(named.clone()),
            ..options()
        };
        let two = Registry {
            current: 2,
            migrations: &STEPS,
        };
        let report = check(&dir, &options, two).await;
        assert_eq!(report.verdict, Verdict::MigrationNeeded, "{report:?}");
        let left: Vec<_> = std::fs::read_dir(&named)
            .expect("the named directory stays")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("keep.txt")]);
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[tokio::test]
    async fn a_newer_format_is_refused_without_opening_the_store() {
        let dir = temp_dir("newer");
        std::fs::create_dir_all(dir.join("store")).expect("store dir");
        std::fs::write(dir.join("store/log.redb"), b"not even a database").expect("log");
        format::write_marker(&dir.join("store"), &Marker::new(9, "9.0.0")).expect("marker");
        let report = check(&dir, &options(), Registry::builtin()).await;
        assert_eq!(report.verdict, Verdict::Refused);
        assert_eq!(report.found_format, Some(9));
        let problem = report.problem.expect("problem");
        assert_eq!(problem.code, "upgrade.format_newer");
        let json = serde_json::to_value(&report_of(&dir).await).expect("json");
        assert_eq!(json["verdict"], "refused");
        assert_eq!(json["exit_code"], 11);
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    async fn report_of(dir: &Path) -> Report {
        check(dir, &options(), Registry::builtin()).await
    }

    #[tokio::test]
    async fn a_running_store_is_not_checked() {
        let dir = temp_dir("running");
        let mut config = RaftStoreConfig::new(dir.join("store"));
        config.fsync_probe_samples = 0;
        let store = RaftStore::open(config).await.expect("open");
        let report = check(&dir, &options(), Registry::builtin()).await;
        assert_eq!(report.verdict, Verdict::Failed);
        assert_eq!(
            report.problem.as_ref().map(|problem| problem.code.as_str()),
            Some("upgrade.in_use")
        );
        store.shutdown().await.expect("shutdown");
        drop(store);
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[tokio::test]
    async fn a_state_copy_of_a_running_store_checks_in_place() {
        let dir = data_dir_at_format_1("online").await;
        let mut config = RaftStoreConfig::new(dir.join("store"));
        config.fsync_probe_samples = 0;
        let running = RaftStore::open(config).await.expect("reopen");
        let copy = dir.join("copy");
        running
            .copy_state_to(&copy.join("store"))
            .await
            .expect("copy while running");
        let marker = format::read_marker(&dir.join("store"))
            .expect("marker")
            .expect("some");
        format::write_marker(&copy.join("store"), &marker).expect("marker");
        // A work directory under a parent of its own: a check that copied the store would
        // create the parent, and its clean-up removes only the work directory itself.
        let elsewhere = dir.join("not-in-place");
        let options = Options {
            disposable: true,
            work_dir: Some(elsewhere.join("work")),
            ..options()
        };
        // The store was written at format 1; the binary of format 1 finds it current.
        let one = Registry {
            current: 1,
            migrations: &[],
        };
        let report = tokio::time::timeout(Duration::from_secs(60), check(&copy, &options, one))
            .await
            .expect("the check finishes");
        assert_eq!(report.verdict, Verdict::Current, "{report:?}");
        assert!(
            !elsewhere.exists(),
            "the check copied the store instead of running in place"
        );
        running.shutdown().await.expect("shutdown");
        drop(running);
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[tokio::test]
    async fn a_disposable_copy_is_migrated_in_place() {
        let dir = data_dir_at_format_1("disposable").await;
        let two = Registry {
            current: 2,
            migrations: &STEPS,
        };
        let options = Options {
            disposable: true,
            ..options()
        };
        let report = check(&dir, &options, two).await;
        assert_eq!(report.verdict, Verdict::MigrationNeeded, "{report:?}");
        let marker = format::read_marker(&dir.join("store")).expect("marker");
        assert_eq!(marker.map(|marker| marker.version), Some(2));
        std::fs::remove_dir_all(&dir).expect("clean up");
    }
}
