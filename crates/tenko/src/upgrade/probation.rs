//! The probation of a newly installed version and the switch back (OPS-24, R17).
//!
//! The install job ends by writing `<data_dir>/updates/attempt.json` (state `restarting`)
//! and switching the `current` link; the server then restarts through its service manager.
//! Every start of `tenko serve` reads the record first, before the format check:
//!
//! | Record | This binary | What happens |
//! |---|---|---|
//! | `restarting` | the new version, first start | probation: it must become ready within `updates.ready_timeout_secs`; a watchdog switches back otherwise |
//! | `restarting` | the new version, a later start | the first start did not confirm (it crashed): switch back at once |
//! | `rolled_back` with `restore` | the previous version | the store copy taken before the new version migrated is put back before the store opens |
//! | `confirmed`, `failed`, `rolled_back` | any | nothing; the outcome is audited once by the version that runs |
//!
//! A switch back points `current` at the previous version again, records why, and stops
//! with exit status 12 so that the service manager starts the previous version. When the
//! new version had migrated the store, the record asks the previous version to restore the
//! copy that the migration took ([`super::datadir::backup`]); data written by the new
//! version is then lost, but it never became ready, so there is none from users. A member of
//! a controller cluster records no such copy and restores none: its migration waits for the
//! leader, and its store holds what the other controllers wrote meanwhile.
//!
//! Two versions share the record: the previous version reads what the new one wrote after a
//! switch back. Every released version ignores keys it does not know, but refuses to start
//! on a `state` it does not know. So a version writes only the five states below and the
//! keys of schema 1 into a record that an older version may read (the golden files in
//! `tests/fixtures/upgrade/` hold those bytes); a new key may be added, a new state
//! or a changed meaning raises `schema`. This version reads a record with a state it does
//! not know, or a schema above its own, as nothing pending, with a warning.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tenko_api::dto::{release::ReleaseVersion, updates::AttemptState as DtoState};
use tenko_core::{JobId, Timestamp};
use tenko_store::format;

use super::{
    layout::{CURRENT, Layout, PREVIOUS},
    restart::Restart,
};

/// The record of the last install attempt, in `<data_dir>/updates`.
pub const ATTEMPT_FILE: &str = "attempt.json";

/// How long the watchdog lets a graceful stop take before it ends the process.
const HARD_EXIT_AFTER: Duration = Duration::from_secs(45);

/// The schema of the record this version writes and understands.
pub const SCHEMA: u32 = 1;

/// Where an attempt stands, as the record stores it (not the API's type: the bytes of the
/// record must not change with the API).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// The install job runs.
    Installing,
    /// The switch ran; the new version starts on probation.
    Restarting,
    /// The new version became ready.
    Confirmed,
    /// The previous version runs again.
    RolledBack,
    /// The install job failed before the switch.
    Failed,
    /// A state a newer version wrote. Never written; [`read`] drops such a record.
    #[serde(other)]
    Unknown,
}

impl State {
    /// The state of the API.
    const fn to_dto(self) -> DtoState {
        match self {
            Self::Installing => DtoState::Installing,
            Self::Restarting => DtoState::Restarting,
            Self::Confirmed => DtoState::Confirmed,
            Self::RolledBack => DtoState::RolledBack,
            // `read` hands out no record in a state it does not know.
            Self::Failed | Self::Unknown => DtoState::Failed,
        }
    }
}

const fn schema_one() -> u32 {
    1
}

/// The last install attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    /// The version before.
    pub from: ReleaseVersion,
    /// The version installed.
    pub to: ReleaseVersion,
    /// Where it stands.
    pub state: State,
    /// When it reached this state.
    pub at: Timestamp,
    /// The install job.
    #[serde(default)]
    pub job_id: Option<JobId>,
    /// Why it failed or was switched back (a stable code).
    #[serde(default)]
    pub reason: Option<String>,
    /// Seconds the new version has to become ready.
    pub deadline_secs: u64,
    /// Starts of the new version so far.
    #[serde(default)]
    pub starts: u32,
    /// The store copy the new version took before it migrated.
    #[serde(default)]
    pub backup: Option<PathBuf>,
    /// The previous version must put `backup` back before it opens the store.
    #[serde(default)]
    pub restore: bool,
    /// The outcome has been written to the audit log.
    #[serde(default)]
    pub reported: bool,
    /// The schema of the record; a record written before the key existed is schema 1.
    #[serde(default = "schema_one")]
    pub schema: u32,
}

impl Attempt {
    /// A new attempt in state `restarting`.
    pub fn restarting(
        from: ReleaseVersion,
        to: ReleaseVersion,
        job_id: Option<JobId>,
        deadline_secs: u64,
    ) -> Self {
        Self {
            from,
            to,
            state: State::Restarting,
            at: Timestamp::now(),
            job_id,
            reason: None,
            deadline_secs,
            starts: 0,
            backup: None,
            restore: false,
            reported: false,
            schema: SCHEMA,
        }
    }

    /// The DTO of the update status.
    pub fn to_dto(&self) -> tenko_api::dto::updates::UpdateAttempt {
        tenko_api::dto::updates::UpdateAttempt {
            from: self.from.clone(),
            to: self.to.clone(),
            state: self.state.to_dto(),
            at: self.at,
            job_id: self.job_id,
            reason: self.reason.clone(),
        }
    }
}

/// Reads the attempt record of `layout`. A record a newer version wrote in a state or a
/// schema this version does not know is nothing pending: `None`, with a warning.
///
/// # Errors
///
/// The I/O error; a record that does not parse is an error too (it is never guessed at).
pub fn read(layout: &Layout) -> io::Result<Option<Attempt>> {
    let path = layout.root().join(ATTEMPT_FILE);
    let attempt: Attempt = match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {error}", path.display()),
            )
        })?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if attempt.state == State::Unknown || attempt.schema > SCHEMA {
        tracing::warn!(
            file = %path.display(),
            schema = attempt.schema,
            from = %attempt.from,
            to = %attempt.to,
            "the update attempt record was written by a newer version; nothing is pending for this one"
        );
        return Ok(None);
    }
    Ok(Some(attempt))
}

/// Writes the attempt record atomically (aside, synced, renamed).
///
/// # Errors
///
/// The I/O error.
pub fn write(layout: &Layout, attempt: &Attempt) -> io::Result<()> {
    fs::create_dir_all(layout.root())?;
    let path = layout.root().join(ATTEMPT_FILE);
    let part = layout.root().join(format!("{ATTEMPT_FILE}.part"));
    let json = serde_json::to_vec_pretty(attempt).map_err(io::Error::other)?;
    {
        let mut file = fs::File::create(&part)?;
        io::Write::write_all(&mut file, &json)?;
        file.sync_all()?;
    }
    fs::rename(&part, &path)
}

/// What `tenko serve` does with the attempt record at start.
#[derive(Debug)]
pub enum StartAction {
    /// Nothing pending.
    Normal,
    /// This version runs on probation.
    Probation(Probation),
    /// A previous start of this version did not become ready: switch back now.
    SwitchBack(Probation),
}

/// Reads the record at the start of `tenko serve`, before the format check: restores the
/// store for a switched-back previous version and decides on probation.
///
/// # Errors
///
/// An I/O error of the record or of the restore; `tenko serve` refuses to start then.
pub fn on_start(data_dir: &Path, own: &ReleaseVersion) -> io::Result<StartAction> {
    let layout = Layout::new(data_dir);
    let Some(mut attempt) = read(&layout)? else {
        return Ok(StartAction::Normal);
    };
    if attempt.state == State::RolledBack && attempt.restore && &attempt.from == own {
        if let Some(backup) = attempt.backup.clone() {
            restore_store(data_dir, &backup)?;
        }
        attempt.restore = false;
        write(&layout, &attempt)?;
        return Ok(StartAction::Normal);
    }
    if attempt.state != State::Restarting || &attempt.to != own {
        return Ok(StartAction::Normal);
    }
    attempt.starts += 1;
    write(&layout, &attempt)?;
    let first = attempt.starts == 1;
    let probation = Probation::new(layout, attempt, data_dir);
    Ok(if first {
        StartAction::Probation(probation)
    } else {
        StartAction::SwitchBack(probation)
    })
}

/// When the configuration does not load at the start of this version: if the record says
/// this version was just installed and is on probation, switches back to the previous
/// version and returns it, so that the caller stops with exit status 12 and the service
/// manager starts that version, which read the file before. A version that renamed or
/// removed a key the file still uses thus never strands the node. The data directory comes
/// from `--data-dir`, the `TENKO_*` environment, or the top-level `data_dir` of the file,
/// read without the checks that failed.
pub fn switch_back_unconfigured(
    sources: &crate::config::Sources,
    own: &ReleaseVersion,
) -> Option<ReleaseVersion> {
    let data_dir = data_dir_of(sources)?;
    let layout = Layout::new(&data_dir);
    let attempt = read(&layout).ok()??;
    if attempt.state != State::Restarting || &attempt.to != own {
        return None;
    }
    let from = attempt.from.clone();
    Probation::new(layout, attempt, &data_dir)
        .switch_back("upgrade.config_refused")
        .then_some(from)
}

/// The data directory `sources` name, without the configuration's own checks.
fn data_dir_of(sources: &crate::config::Sources) -> Option<PathBuf> {
    let without_file = crate::config::Sources {
        file: None,
        ..sources.clone()
    };
    let named = crate::config::load(&without_file, std::env::vars())
        .ok()
        .and_then(|loaded| loaded.config.data_dir);
    let dir = named.or_else(|| {
        let text = fs::read_to_string(sources.file.as_ref()?).ok()?;
        let table: toml::Table = toml::from_str(&text).ok()?;
        table.get("data_dir")?.as_str().map(PathBuf::from)
    })?;
    std::path::absolute(dir).ok()
}

/// Puts the store copy `backup` (a directory with `store/`) back in place of the store; the
/// replaced store is kept as `store.failed-<time>` for diagnosis.
fn restore_store(data_dir: &Path, backup: &Path) -> io::Result<()> {
    let store = data_dir.join("store");
    let source = backup.join("store");
    if !format::store_exists(&source) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("the store copy {} is missing", source.display()),
        ));
    }
    if store.exists() {
        let aside = data_dir.join(format!(
            "store.failed-{}",
            Timestamp::now().0.unix_timestamp()
        ));
        fs::rename(&store, &aside)?;
        tracing::warn!(
            kept = %aside.display(),
            "the store of the switched-back version is kept aside"
        );
    }
    format::copy_closed_store(&source, &store).map_err(io::Error::other)?;
    tracing::warn!(
        backup = %backup.display(),
        "restored the store copy taken before the failed upgrade"
    );
    Ok(())
}

/// A version on probation.
#[derive(Debug, Clone)]
pub struct Probation {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    layout: Layout,
    attempt: Mutex<Attempt>,
    settled: AtomicBool,
    /// Set while a migration runs: the deadline does not count that time.
    paused: AtomicBool,
}

impl Probation {
    fn new(layout: Layout, attempt: Attempt, _data_dir: &Path) -> Self {
        Self {
            inner: Arc::new(Inner {
                layout,
                attempt: Mutex::new(attempt),
                settled: AtomicBool::new(false),
                paused: AtomicBool::new(false),
            }),
        }
    }

    fn attempt(&self) -> std::sync::MutexGuard<'_, Attempt> {
        self.inner
            .attempt
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The attempt as it stands.
    pub fn snapshot(&self) -> Attempt {
        self.attempt().clone()
    }

    /// Records the store copy taken before this version migrated, so that a switch back
    /// restores it. A member of a controller cluster records none: its store also holds
    /// what the other controllers wrote since, which a restore would roll back.
    pub fn set_backup(&self, backup: &Path, member: bool) {
        if member {
            return;
        }
        let mut attempt = self.attempt();
        attempt.backup = Some(backup.to_path_buf());
        if let Err(error) = write(&self.inner.layout, &attempt) {
            tracing::error!(%error, "cannot record the store copy in the attempt record");
        }
    }

    /// The new version is ready: the attempt is confirmed. Returns `false` when the
    /// watchdog has already switched back.
    pub fn confirm(&self) -> bool {
        if self.inner.settled.swap(true, Ordering::SeqCst) {
            return false;
        }
        let mut attempt = self.attempt();
        attempt.state = State::Confirmed;
        attempt.at = Timestamp::now();
        attempt.reason = None;
        if let Err(error) = write(&self.inner.layout, &attempt) {
            tracing::error!(%error, "cannot record the confirmed upgrade");
        }
        tracing::info!(from = %attempt.from, to = %attempt.to, "the upgrade is confirmed");
        true
    }

    /// Switches back to the previous version: `current` points at it again and the record
    /// says why. Returns `false` when the attempt was already settled.
    pub fn switch_back(&self, reason: &str) -> bool {
        if self.inner.settled.swap(true, Ordering::SeqCst) {
            return false;
        }
        let mut attempt = self.attempt();
        let layout = &self.inner.layout;
        if let Err(error) = layout.point(CURRENT, &attempt.from) {
            tracing::error!(%error, from = %attempt.from, "cannot switch back to the previous version");
        }
        let _ = layout.point(PREVIOUS, &attempt.to);
        attempt.state = State::RolledBack;
        attempt.at = Timestamp::now();
        attempt.reason = Some(reason.to_owned());
        attempt.restore = attempt.backup.is_some();
        if let Err(error) = write(layout, &attempt) {
            tracing::error!(%error, "cannot record the switch back");
        }
        tracing::error!(
            from = %attempt.to,
            to = %attempt.from,
            reason,
            "switched back to the previous version"
        );
        true
    }

    /// Stops the clock of the deadline while the data directory is migrated: a large
    /// migration may take longer than the deadline, and the dry run of the install job has
    /// already shown that it passes. The service manager's own start timeout still applies.
    pub fn pause(&self) {
        self.inner.paused.store(true, Ordering::SeqCst);
    }

    /// Starts the clock of the deadline again after [`Probation::pause`].
    pub fn resume(&self) {
        self.inner.paused.store(false, Ordering::SeqCst);
    }

    /// Starts the watchdog: unless [`Probation::confirm`] runs within the deadline (time in
    /// [`Probation::pause`] not counted), it switches back, asks for a restart, and ends the
    /// process with status 12 when the graceful stop does not finish in time.
    pub fn watch(&self, restart: Restart) {
        let probation = self.clone();
        let deadline = Duration::from_secs(self.attempt().deadline_secs);
        let spawned = std::thread::Builder::new()
            .name("tenko-probation".to_owned())
            .spawn(move || {
                let tick = Duration::from_millis(250);
                let mut counted = Duration::ZERO;
                while counted < deadline {
                    std::thread::sleep(tick);
                    if probation.inner.settled.load(Ordering::SeqCst) {
                        return;
                    }
                    if !probation.inner.paused.load(Ordering::SeqCst) {
                        counted += tick;
                    }
                }
                if !probation.switch_back("upgrade.not_ready") {
                    return;
                }
                restart.request("the new version did not become ready in time");
                std::thread::sleep(HARD_EXIT_AFTER);
                tracing::error!("the graceful stop did not finish; exiting for the restart");
                std::process::exit(i32::from(crate::exit::RESTART));
            });
        if let Err(error) = spawned {
            tracing::error!(%error, "cannot start the probation watchdog");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tenko-probation-test-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create");
        dir
    }

    fn version(text: &str) -> ReleaseVersion {
        text.parse().expect("version")
    }

    fn installed(data: &Path) -> Layout {
        let layout = Layout::new(data);
        let source = data.join("binary");
        fs::write(&source, b"binary").expect("binary");
        for text in ["0.1.0", "0.2.0"] {
            layout
                .install_binary(&version(text), &source)
                .expect("install");
        }
        layout.point(PREVIOUS, &version("0.1.0")).expect("previous");
        layout.point(CURRENT, &version("0.2.0")).expect("current");
        layout
    }

    /// What every released version (0.0.3 to 0.0.11) writes, and what this one writes.
    const RELEASED: &str = include_str!("../../tests/fixtures/upgrade/attempt-released.json");
    const SCHEMA_ONE: &str = include_str!("../../tests/fixtures/upgrade/attempt-v1.json");

    fn golden_attempt() -> Attempt {
        Attempt {
            at: Timestamp(time::macros::datetime!(2026-11-12 10:00 UTC)),
            ..Attempt::restarting(version("0.0.4"), version("0.0.12"), None, 180)
        }
    }

    /// The record of a released version reads as schema 1, and this version writes exactly
    /// the bytes of schema 1.
    #[test]
    fn the_record_keeps_its_bytes() {
        let released: Attempt = serde_json::from_str(RELEASED).expect("released record");
        assert_eq!(released, golden_attempt());
        let written = serde_json::to_string_pretty(&golden_attempt()).expect("json");
        assert_eq!(written, SCHEMA_ONE.trim_end());
    }

    /// The reader every released version has: the API's state with no unknown arm and the
    /// keys of schema 1, unknown keys ignored. What this version writes must stay readable
    /// by it, because a switch back starts the previous version on this record.
    #[derive(Deserialize)]
    #[allow(dead_code, reason = "the fields are read to show that they parse")]
    struct ReleasedReader {
        from: ReleaseVersion,
        to: ReleaseVersion,
        state: DtoState,
        at: Timestamp,
        #[serde(default)]
        job_id: Option<JobId>,
        #[serde(default)]
        reason: Option<String>,
        deadline_secs: u64,
        #[serde(default)]
        starts: u32,
        #[serde(default)]
        backup: Option<PathBuf>,
        #[serde(default)]
        restore: bool,
        #[serde(default)]
        reported: bool,
    }

    #[test]
    fn released_versions_read_every_record_this_version_writes() {
        let mut attempt = golden_attempt();
        for state in [
            State::Installing,
            State::Restarting,
            State::Confirmed,
            State::RolledBack,
            State::Failed,
        ] {
            attempt.state = state;
            attempt.backup = Some(PathBuf::from("upgrade-backups/copy"));
            let bytes = serde_json::to_vec_pretty(&attempt).expect("json");
            let read: ReleasedReader = serde_json::from_slice(&bytes).expect("released reader");
            assert_eq!(read.state, state.to_dto());
        }
    }

    /// A record a newer version wrote, in a state or a schema this one does not know, is
    /// nothing pending: the start goes on instead of refusing.
    #[test]
    fn a_record_of_a_newer_version_is_nothing_pending() {
        let data = temp_dir("newer");
        let layout = installed(&data);
        let path = layout.root().join(ATTEMPT_FILE);
        let newer_state = SCHEMA_ONE.replace(r#""restarting""#, r#""verifying""#);
        fs::write(&path, newer_state).expect("record");
        assert_eq!(read(&layout).expect("read"), None);
        assert!(matches!(
            on_start(&data, &version("0.0.12")).expect("start"),
            StartAction::Normal
        ));
        let newer_schema = SCHEMA_ONE.replace(r#""schema": 1"#, r#""schema": 2"#);
        fs::write(&path, newer_schema).expect("record");
        assert!(matches!(
            on_start(&data, &version("0.0.12")).expect("start"),
            StartAction::Normal
        ));
        fs::write(&path, b"{ not json").expect("record");
        let error = on_start(&data, &version("0.0.12")).expect_err("a broken record");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&data).expect("clean up");
    }

    /// A member of a controller cluster restores no store copy when it switches back: its
    /// store holds what the leader replicated meanwhile.
    #[test]
    fn a_member_switches_back_without_restoring_a_store_copy() {
        let data = temp_dir("member");
        let layout = installed(&data);
        let backup = data.join("upgrade-backups").join("copy");
        fs::create_dir_all(backup.join("store")).expect("backup");
        fs::write(backup.join("store/log.redb"), b"old log").expect("log");
        fs::create_dir_all(data.join("store")).expect("store");
        fs::write(data.join("store/log.redb"), b"replicated log").expect("log");
        write(
            &layout,
            &Attempt::restarting(version("0.1.0"), version("0.2.0"), None, 180),
        )
        .expect("record");
        let StartAction::Probation(probation) = on_start(&data, &version("0.2.0")).expect("start")
        else {
            panic!("probation");
        };
        probation.set_backup(&backup, true);
        assert!(probation.switch_back("upgrade.crashed"));
        let attempt = read(&layout).expect("read").expect("record");
        assert_eq!(attempt.backup, None);
        assert!(!attempt.restore);
        assert!(matches!(
            on_start(&data, &version("0.1.0")).expect("start"),
            StartAction::Normal
        ));
        assert_eq!(
            fs::read(data.join("store/log.redb")).expect("store"),
            b"replicated log"
        );
        fs::remove_dir_all(&data).expect("clean up");
    }

    /// A new version that refuses the configuration on its first start switches back; the
    /// data directory is found in the file even though the file does not load.
    #[test]
    fn a_refused_configuration_switches_back_to_the_version_that_read_it() {
        let data = temp_dir("config");
        let layout = installed(&data);
        let file = data.join("tenko.toml");
        fs::write(
            &file,
            format!(
                "data_dir = {:?}
[cluster]
renamed_key = 1
",
                data.display().to_string()
            ),
        )
        .expect("file");
        let sources = crate::config::Sources {
            file: Some(file),
            ..crate::config::Sources::default()
        };
        // No record: nothing to switch back to.
        assert_eq!(switch_back_unconfigured(&sources, &version("0.2.0")), None);
        write(
            &layout,
            &Attempt::restarting(version("0.1.0"), version("0.2.0"), None, 180),
        )
        .expect("record");
        // The previous version is not the one on probation.
        assert_eq!(switch_back_unconfigured(&sources, &version("0.1.0")), None);
        assert_eq!(
            switch_back_unconfigured(&sources, &version("0.2.0")),
            Some(version("0.1.0"))
        );
        assert_eq!(layout.current(), Some(version("0.1.0")));
        let attempt = read(&layout).expect("read").expect("record");
        assert_eq!(attempt.state, State::RolledBack);
        assert_eq!(attempt.reason.as_deref(), Some("upgrade.config_refused"));
        // The previous version then starts normally.
        assert!(matches!(
            on_start(&data, &version("0.1.0")).expect("start"),
            StartAction::Normal
        ));
        fs::remove_dir_all(&data).expect("clean up");
    }

    #[test]
    fn a_first_start_is_on_probation_and_confirms() {
        let data = temp_dir("confirm");
        let layout = installed(&data);
        assert!(matches!(
            on_start(&data, &version("0.2.0")).expect("no record"),
            StartAction::Normal
        ));
        write(
            &layout,
            &Attempt::restarting(version("0.1.0"), version("0.2.0"), None, 180),
        )
        .expect("record");
        // The previous version is not on probation.
        assert!(matches!(
            on_start(&data, &version("0.1.0")).expect("start"),
            StartAction::Normal
        ));
        let StartAction::Probation(probation) = on_start(&data, &version("0.2.0")).expect("start")
        else {
            panic!("the first start is on probation");
        };
        assert!(probation.confirm());
        assert!(
            !probation.switch_back("too late"),
            "a confirmed attempt stays"
        );
        let attempt = read(&layout).expect("read").expect("record");
        assert_eq!(attempt.state, State::Confirmed);
        assert_eq!(attempt.starts, 1);
        assert_eq!(layout.current(), Some(version("0.2.0")));
        // Later starts of the confirmed version are normal.
        assert!(matches!(
            on_start(&data, &version("0.2.0")).expect("start"),
            StartAction::Normal
        ));
        fs::remove_dir_all(&data).expect("clean up");
    }

    #[test]
    fn a_second_unconfirmed_start_switches_back_and_restores_the_store() {
        let data = temp_dir("switch-back");
        let layout = installed(&data);
        // The store copy the new version took before it migrated.
        let backup = data.join("upgrade-backups").join("copy");
        fs::create_dir_all(backup.join("store")).expect("backup");
        fs::write(backup.join("store/log.redb"), b"old log").expect("log");
        fs::write(backup.join("store/sm.redb"), b"old state").expect("state");
        fs::create_dir_all(data.join("store")).expect("store");
        fs::write(data.join("store/log.redb"), b"migrated log").expect("log");
        write(
            &layout,
            &Attempt::restarting(version("0.1.0"), version("0.2.0"), None, 180),
        )
        .expect("record");
        let StartAction::Probation(first) = on_start(&data, &version("0.2.0")).expect("start")
        else {
            panic!("probation");
        };
        first.set_backup(&backup, false);
        // The process died before it confirmed; the service manager starts it again.
        let StartAction::SwitchBack(second) = on_start(&data, &version("0.2.0")).expect("start")
        else {
            panic!("the second start switches back");
        };
        assert!(second.switch_back("upgrade.crashed"));
        assert_eq!(layout.current(), Some(version("0.1.0")));
        let attempt = read(&layout).expect("read").expect("record");
        assert_eq!(attempt.state, State::RolledBack);
        assert_eq!(attempt.reason.as_deref(), Some("upgrade.crashed"));
        assert!(attempt.restore);
        // The previous version restores the copy before it opens the store.
        assert!(matches!(
            on_start(&data, &version("0.1.0")).expect("start"),
            StartAction::Normal
        ));
        assert_eq!(
            fs::read(data.join("store/log.redb")).expect("restored"),
            b"old log"
        );
        let kept: Vec<String> = fs::read_dir(&data)
            .expect("list")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("store.failed-"))
            .collect();
        assert_eq!(kept.len(), 1);
        assert!(!read(&layout).expect("read").expect("record").restore);
        fs::remove_dir_all(&data).expect("clean up");
    }
}
