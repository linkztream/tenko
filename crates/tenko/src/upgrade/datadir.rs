//! The data-directory format at start-up (OPS-23): compare, back up, migrate, bump.
//!
//! `tenko serve` calls [`preflight`] before the store opens and [`finish`] right after:
//!
//! | Found | What happens |
//! |---|---|
//! | no store | a fresh directory: the store is created and both records say [`CURRENT`] |
//! | the current format | nothing; a missing stored record or marker is written |
//! | an older format | the closed store is copied to `<data_dir>/upgrade-backups/` ([`backup`]), then every migration runs in its own write batch together with the bump of the stored record, and the marker follows each step |
//! | a newer format | refused with `upgrade.format_newer` naming both versions; `tenko serve` exits with status 3 and touches nothing |
//!
//! The marker file is read before the store opens; the stored record is the authority once
//! it is open. They may differ in exactly one harmless way: a migration committed and the
//! process stopped before the marker followed, so the store is ahead of the marker by a
//! format this binary knows; [`finish`] then repairs the marker. Every other disagreement
//! (a store behind its marker, or a state file copied in from elsewhere) is refused with
//! `upgrade.format_mismatch`.
//!
//! [`CURRENT`]: super::migrations::CURRENT

use std::{
    collections::BTreeMap,
    fmt::{self, Write as _},
    path::{Path, PathBuf},
};

use tenko_core::{
    Principal, SystemComponent, Timestamp,
    audit::{AuditAction, AuditDetails, AuditDraft},
};
use tenko_store::{
    ReadConsistency, Store, StoreError, WriteBatch,
    format::{self, FormatError, Marker, StoredFormat},
};

use super::migrations::{INITIAL, Registry};
use crate::exit;

/// The directory under the data directory that keeps the store copies taken before
/// migrations.
pub const BACKUPS_DIR: &str = "upgrade-backups";

/// How many pre-migration copies are kept; older ones are removed after a new one.
pub const KEEP_BACKUPS: usize = 3;

/// Why the data directory cannot be used by this binary.
#[derive(Debug)]
pub enum UpgradeError {
    /// The directory has a newer format than this binary knows.
    Newer {
        /// The format found.
        found: u32,
        /// The newest format this binary knows.
        supported: u32,
    },
    /// A migration between two formats is missing from this binary.
    MissingMigration {
        /// The format of the directory.
        from: u32,
        /// The format of the missing step.
        to: u32,
    },
    /// The marker and the stored record disagree in a way no migration explains.
    Mismatch {
        /// The format of the marker file.
        marker: u32,
        /// The format of the stored record.
        stored: u32,
    },
    /// A migration failed; its batch was not committed.
    Migration {
        /// The format the migration produces.
        to: u32,
        /// What went wrong.
        reason: String,
    },
    /// The format records or the store copy failed.
    Format(FormatError),
    /// The store refused a read or a write.
    Store(StoreError),
}

impl UpgradeError {
    /// The stable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Newer { .. } => "upgrade.format_newer",
            Self::MissingMigration { .. } => "upgrade.migration_missing",
            Self::Mismatch { .. } => "upgrade.format_mismatch",
            Self::Migration { .. } => "upgrade.migration_failed",
            Self::Format(error) => error.code(),
            Self::Store(_) => "upgrade.store",
        }
    }

    /// The exit status of `tenko serve`: 3 for a newer format (a deployment error that a
    /// restart cannot fix), 4 for the rest (a failed start step).
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Newer { .. } => exit::CONFIG,
            _ => exit::START,
        }
    }

    /// Parameters for a report: the versions involved.
    pub fn params(&self) -> BTreeMap<&'static str, String> {
        let mut params = BTreeMap::new();
        match self {
            Self::Newer { found, supported } => {
                params.insert("found", found.to_string());
                params.insert("supported", supported.to_string());
            }
            Self::MissingMigration { from, to } => {
                params.insert("from", from.to_string());
                params.insert("to", to.to_string());
            }
            Self::Mismatch { marker, stored } => {
                params.insert("marker", marker.to_string());
                params.insert("stored", stored.to_string());
            }
            Self::Migration { to, .. } => {
                params.insert("to", to.to_string());
            }
            Self::Format(_) | Self::Store(_) => {}
        }
        params
    }
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Newer { found, supported } => write!(
                f,
                "the data directory has format {found}, newer than format {supported} that tenko \
                 {} reads: run the newer version, or restore the copy taken before the upgrade \
                 (docs/upgrades.md)",
                crate::version()
            ),
            Self::MissingMigration { from, to } => write!(
                f,
                "the data directory has format {from} and this binary has no migration to format \
                 {to}; upgrade through an intermediate release"
            ),
            Self::Mismatch { marker, stored } => write!(
                f,
                "the format marker says {marker} but the store says {stored}: the store files do \
                 not belong to this data directory or the marker was edited; restore a matching \
                 copy"
            ),
            Self::Migration { to, reason } => {
                write!(f, "the migration to format {to} failed: {reason}")
            }
            Self::Format(error) => fmt::Display::fmt(error, f),
            Self::Store(error) => write!(f, "the store refused the format record: {error}"),
        }
    }
}

impl std::error::Error for UpgradeError {}

impl From<FormatError> for UpgradeError {
    fn from(error: FormatError) -> Self {
        Self::Format(error)
    }
}

impl From<StoreError> for UpgradeError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// What [`preflight`] found before the store opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// No store yet: it is created at the current format.
    Fresh,
    /// The directory is at the current format.
    Current {
        /// The marker is missing (a directory from before format versions).
        legacy: bool,
    },
    /// The directory is older; every migration to the current format exists.
    Migrate {
        /// The format of the directory.
        from: u32,
        /// The current format.
        to: u32,
        /// The marker is missing (a directory from before format versions).
        legacy: bool,
    },
}

impl Plan {
    /// Whether a copy of the closed store must be taken before the store opens.
    pub const fn needs_backup(self) -> bool {
        matches!(self, Self::Migrate { .. })
    }
}

/// Compares the marker of `store_dir` with the registry, before the store opens.
///
/// # Errors
///
/// [`UpgradeError::Newer`] for a newer format, [`UpgradeError::MissingMigration`] when a
/// step is missing, [`UpgradeError::Format`] for an unreadable marker.
pub fn preflight(store_dir: &Path, registry: Registry<'_>) -> Result<Plan, UpgradeError> {
    if !format::store_exists(store_dir) {
        return Ok(Plan::Fresh);
    }
    let marker = format::read_marker(store_dir)?;
    let legacy = marker.is_none();
    let found = marker.map_or(INITIAL, |marker| marker.version);
    plan_for(found, legacy, registry)
}

/// The plan for a directory at format `found`.
fn plan_for(found: u32, legacy: bool, registry: Registry<'_>) -> Result<Plan, UpgradeError> {
    if found > registry.current {
        return Err(UpgradeError::Newer {
            found,
            supported: registry.current,
        });
    }
    if found == registry.current {
        return Ok(Plan::Current { legacy });
    }
    if let Some(to) = ((found + 1)..=registry.current).find(|to| registry.migration(*to).is_none())
    {
        return Err(UpgradeError::MissingMigration { from: found, to });
    }
    Ok(Plan::Migrate {
        from: found,
        to: registry.current,
        legacy,
    })
}

/// Copies the closed store of `store_dir` to
/// `<data_dir>/upgrade-backups/<UTC time>-format-<from>-to-<to>/store` and keeps the newest
/// [`KEEP_BACKUPS`] copies. Returns the directory of the copy.
///
/// # Errors
///
/// [`UpgradeError::Format`] when the store is open elsewhere or a file cannot be copied.
pub fn backup(
    data_dir: &Path,
    store_dir: &Path,
    from: u32,
    to: u32,
) -> Result<PathBuf, UpgradeError> {
    let root = data_dir.join(BACKUPS_DIR);
    let name = format!("{}-format-{from}-to-{to}", compact_utc(Timestamp::now()));
    let target = root.join(name);
    let report = format::copy_closed_store(store_dir, &target.join("store"))?;
    tracing::info!(
        backup = %target.display(),
        files = report.files.len(),
        bytes = report.bytes,
        "copied the closed store before migrating from format {from} to {to}"
    );
    prune_backups(&root, KEEP_BACKUPS);
    Ok(target)
}

/// `20261009T201502Z`: sortable and valid in file names on every platform.
fn compact_utc(at: Timestamp) -> String {
    let at = at.0;
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// Removes all but the newest `keep` copies (names sort by time).
fn prune_backups(root: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("-format-"))
        .collect();
    names.sort();
    let excess = names.len().saturating_sub(keep);
    for name in names.into_iter().take(excess) {
        if let Err(error) = std::fs::remove_dir_all(root.join(&name)) {
            tracing::warn!(%error, backup = %name, "cannot remove an old pre-migration copy");
        }
    }
}

/// What [`finish`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// The format of the store now.
    pub version: u32,
    /// The formats migrated to, in order.
    pub migrated: Vec<u32>,
    /// The stored record was missing and has been written.
    pub record_created: bool,
    /// The marker lagged behind a committed migration and has been repaired.
    pub marker_repaired: bool,
}

impl Outcome {
    /// One line for the start log.
    pub fn summary(&self) -> String {
        let mut text = format!("data format {}", self.version);
        if let Some(first) = self.migrated.first() {
            let _ = write!(
                text,
                " (migrated from format {} in {} step(s))",
                first - 1,
                self.migrated.len()
            );
        }
        if self.marker_repaired {
            text.push_str(", marker repaired");
        }
        text
    }
}

/// Reconciles the marker with the stored record of the open `store` (a store created by
/// this start, `plan` [`Plan::Fresh`], starts at the current format) and runs the
/// migrations up to the registry's format, each in one batch with the bump of the stored
/// record and an audit record; the marker follows every committed step. Call it before
/// anything else writes to the store.
///
/// # Errors
///
/// [`UpgradeError::Newer`] or [`UpgradeError::Mismatch`] for records that cannot be
/// reconciled, [`UpgradeError::MissingMigration`], [`UpgradeError::Migration`] when a
/// migration fails (its batch is not committed and the marker is unchanged), or the
/// store's and the file system's errors.
pub async fn finish(
    store: &dyn Store,
    store_dir: &Path,
    plan: Plan,
    registry: Registry<'_>,
    written_by: &str,
) -> Result<Outcome, UpgradeError> {
    let marker = format::read_marker(store_dir)?.map(|marker| marker.version);
    let mut outcome = Outcome::default();
    let fresh = plan == Plan::Fresh;
    let (mut version, mut revision) =
        reconcile(store, marker, fresh, registry, written_by, &mut outcome).await?;
    if marker != Some(version) {
        format::write_marker(store_dir, &Marker::new(version, written_by))?;
    }
    let Some(path) = registry.path(version) else {
        let to = ((version + 1)..=registry.current)
            .find(|to| registry.migration(*to).is_none())
            .unwrap_or(registry.current);
        return Err(UpgradeError::MissingMigration { from: version, to });
    };
    for migration in path {
        let to = migration.to();
        let view = store.read(ReadConsistency::Local).await?;
        let mutations = migration
            .plan(view.as_ref())
            .map_err(|error| UpgradeError::Migration {
                to,
                reason: error.to_string(),
            })?;
        drop(view);
        let mut batch = system_batch();
        batch.mutations = mutations;
        format::stage_stored(&mut batch, revision, &stored_format(to, written_by))?;
        let mut details = AuditDetails::default();
        details
            .context
            .insert("from".to_owned(), version.to_string());
        details.context.insert("to".to_owned(), to.to_string());
        details
            .context
            .insert("summary".to_owned(), migration.summary().to_owned());
        details
            .context
            .insert("binary".to_owned(), written_by.to_owned());
        batch.audit(AuditDraft {
            details,
            ..AuditDraft::success(AuditAction::from_static("sys.upgrade.migrate"), Vec::new())
        });
        let committed = store
            .propose(batch)
            .await
            .map_err(|error| UpgradeError::Migration {
                to,
                reason: error.to_string(),
            })?;
        format::write_marker(store_dir, &Marker::new(to, written_by))?;
        tracing::info!(
            from = version,
            to,
            revision = %committed.revision,
            "migrated the data directory: {}",
            migration.summary()
        );
        outcome.migrated.push(to);
        version = to;
        revision = Some(committed.revision);
    }
    outcome.version = version;
    Ok(outcome)
}

/// The format of the open store and the revision of its stored record, from the stored
/// record and the marker; writes the record of a store from before format records.
async fn reconcile(
    store: &dyn Store,
    marker: Option<u32>,
    fresh: bool,
    registry: Registry<'_>,
    written_by: &str,
    outcome: &mut Outcome,
) -> Result<(u32, Option<tenko_core::Revision>), UpgradeError> {
    let view = store.read(ReadConsistency::Local).await?;
    let stored = format::read_stored(view.as_ref())?;
    drop(view);
    let reconciled = match (stored, marker) {
        (Some((stored, revision)), marker) => {
            if stored.version > registry.current {
                return Err(UpgradeError::Newer {
                    found: stored.version,
                    supported: registry.current,
                });
            }
            match marker {
                Some(marker) if marker > stored.version => {
                    return Err(UpgradeError::Mismatch {
                        marker,
                        stored: stored.version,
                    });
                }
                Some(marker) if marker < stored.version => {
                    tracing::warn!(
                        marker,
                        stored = stored.version,
                        "the format marker lagged behind a committed migration; repairing it"
                    );
                    outcome.marker_repaired = true;
                }
                _ => {}
            }
            (stored.version, Some(revision))
        }
        (None, marker) => {
            // A new store starts at the current format; a store from before format records
            // has the marker's format, or the initial one without a marker.
            let version = if fresh {
                registry.current
            } else {
                marker.unwrap_or(INITIAL)
            };
            if version > registry.current {
                return Err(UpgradeError::Newer {
                    found: version,
                    supported: registry.current,
                });
            }
            let mut batch = system_batch();
            format::stage_stored(&mut batch, None, &stored_format(version, written_by))?;
            let committed = store.propose(batch).await?;
            outcome.record_created = true;
            (version, Some(committed.revision))
        }
    };
    Ok(reconciled)
}

fn system_batch() -> WriteBatch {
    WriteBatch::new(Principal::system(SystemComponent::Store), Timestamp::now())
}

fn stored_format(version: u32, written_by: &str) -> StoredFormat {
    StoredFormat {
        version,
        written_by: written_by.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tenko_core::TableName;
    use tenko_store::{MemStore, Mutation, ReadView};

    use super::*;
    use crate::upgrade::migrations::{Migration, MigrationError};

    const TABLE: TableName = TableName::from_static("ipam.upgrade_test_items");

    /// Format 2 adds a row; format 3 renames it.
    struct AddRow;
    struct RenameRow;
    struct Broken;

    impl Migration for AddRow {
        fn to(&self) -> u32 {
            2
        }
        fn summary(&self) -> &'static str {
            "adds the row"
        }
        fn plan(&self, _view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
            Ok(vec![Mutation::Put {
                table: TABLE,
                key: b"a".to_vec().into(),
                value: b"1".to_vec().into(),
            }])
        }
    }

    impl Migration for RenameRow {
        fn to(&self) -> u32 {
            3
        }
        fn summary(&self) -> &'static str {
            "renames the row"
        }
        fn plan(&self, view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
            let value = view
                .get(&TABLE, b"a")?
                .ok_or_else(|| MigrationError::Data("the row of format 2 is missing".into()))?;
            Ok(vec![
                Mutation::Delete {
                    table: TABLE,
                    key: b"a".to_vec().into(),
                },
                Mutation::Put {
                    table: TABLE,
                    key: b"b".to_vec().into(),
                    value: value.value,
                },
            ])
        }
    }

    impl Migration for Broken {
        fn to(&self) -> u32 {
            3
        }
        fn summary(&self) -> &'static str {
            "always fails"
        }
        fn plan(&self, _view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
            Err(MigrationError::Data("broken on purpose".into()))
        }
    }

    static TWO_STEPS: [&dyn Migration; 2] = [&AddRow, &RenameRow];

    /// The plan `preflight` gives an existing store (its value does not matter to `finish`
    /// beyond not being fresh).
    const OLD: Plan = Plan::Current { legacy: false };
    static BROKEN: [&dyn Migration; 2] = [&AddRow, &Broken];

    fn registry(current: u32) -> Registry<'static> {
        Registry {
            current,
            migrations: &TWO_STEPS,
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tenko-datadir-test-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create");
        dir
    }

    /// A directory that looks like a store to `preflight` (only `log.redb` is checked).
    fn fake_store(dir: &Path, marker: Option<u32>) {
        std::fs::write(dir.join("log.redb"), b"log").expect("log");
        if let Some(version) = marker {
            format::write_marker(dir, &Marker::new(version, "test")).expect("marker");
        }
    }

    async fn stored(store: &MemStore) -> Option<u32> {
        let view = store.read(ReadConsistency::Local).await.expect("view");
        format::read_stored(view.as_ref())
            .expect("read")
            .map(|(stored, _)| stored.version)
    }

    async fn rows(store: &MemStore) -> Vec<Vec<u8>> {
        let view = store.read(ReadConsistency::Local).await.expect("view");
        view.scan(&TABLE, tenko_store::KeyRange::all(), 10, false)
            .expect("scan")
            .into_iter()
            .map(|(key, _)| key.to_vec())
            .collect()
    }

    #[test]
    fn preflight_plans_by_the_marker() {
        let dir = temp_dir("preflight");
        assert_eq!(preflight(&dir, registry(3)).expect("fresh"), Plan::Fresh);
        fake_store(&dir, None);
        assert_eq!(
            preflight(&dir, registry(1)).expect("legacy"),
            Plan::Current { legacy: true }
        );
        assert_eq!(
            preflight(&dir, registry(3)).expect("legacy, older"),
            Plan::Migrate {
                from: 1,
                to: 3,
                legacy: true
            }
        );
        format::write_marker(&dir, &Marker::new(4, "newer")).expect("marker");
        let error = preflight(&dir, registry(3)).expect_err("newer");
        assert_eq!(error.code(), "upgrade.format_newer");
        assert_eq!(error.exit_code(), exit::CONFIG);
        assert!(error.to_string().contains("format 4, newer than format 3"));
        format::write_marker(&dir, &Marker::new(1, "older")).expect("marker");
        let gap = Registry {
            current: 3,
            migrations: &[&AddRow],
        };
        let error = preflight(&dir, gap).expect_err("a missing step");
        assert_eq!(error.code(), "upgrade.migration_missing");
        assert_eq!(error.params().get("to").map(String::as_str), Some("3"));
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[tokio::test]
    async fn a_fresh_store_gets_both_records() {
        let dir = temp_dir("fresh");
        let store = MemStore::default();
        let outcome = finish(&store, &dir, Plan::Fresh, registry(3), "9.9.9")
            .await
            .expect("finish");
        // A new store starts at the current format: nothing to migrate.
        assert_eq!(outcome.version, 3);
        assert!(outcome.record_created);
        assert_eq!(outcome.migrated, Vec::<u32>::new());
        assert_eq!(stored(&store).await, Some(3));
        assert_eq!(
            format::read_marker(&dir).expect("marker"),
            Some(Marker::new(3, "9.9.9"))
        );
        // The second start finds both at the current format and does nothing.
        let again = finish(&store, &dir, OLD, registry(3), "9.9.9")
            .await
            .expect("again");
        assert_eq!(
            again,
            Outcome {
                version: 3,
                ..Outcome::default()
            }
        );
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[tokio::test]
    async fn migrations_run_in_order_with_the_bump_and_an_audit_record() {
        let dir = temp_dir("migrate");
        let store = MemStore::default();
        finish(&store, &dir, Plan::Fresh, registry(1), "0.1.0")
            .await
            .expect("format 1");
        assert_eq!(stored(&store).await, Some(1));
        let outcome = finish(&store, &dir, OLD, registry(3), "0.3.0")
            .await
            .expect("migrate");
        assert_eq!(outcome.migrated, [2, 3]);
        assert_eq!(
            outcome.summary(),
            "data format 3 (migrated from format 1 in 2 step(s))"
        );
        assert_eq!(rows(&store).await, [b"b".to_vec()]);
        assert_eq!(stored(&store).await, Some(3));
        assert_eq!(
            format::read_marker(&dir)
                .expect("marker")
                .map(|m| m.version),
            Some(3)
        );
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let audit = view
            .scan(
                tenko_store::tables::AUDIT.name(),
                tenko_store::KeyRange::all(),
                10,
                false,
            )
            .expect("audit");
        assert_eq!(audit.len(), 2, "one audit record per migration");
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[tokio::test]
    async fn a_failed_migration_leaves_its_step_uncommitted() {
        let dir = temp_dir("broken");
        let store = MemStore::default();
        finish(&store, &dir, Plan::Fresh, registry(1), "0.1.0")
            .await
            .expect("format 1");
        let broken = Registry {
            current: 3,
            migrations: &BROKEN,
        };
        let error = finish(&store, &dir, OLD, broken, "0.3.0")
            .await
            .expect_err("fails");
        assert_eq!(error.code(), "upgrade.migration_failed");
        // Step 2 committed with its marker; step 3 did not.
        assert_eq!(stored(&store).await, Some(2));
        assert_eq!(
            format::read_marker(&dir)
                .expect("marker")
                .map(|m| m.version),
            Some(2)
        );
        // A fixed binary resumes at step 3.
        let outcome = finish(&store, &dir, OLD, registry(3), "0.3.1")
            .await
            .expect("resume");
        assert_eq!(outcome.migrated, [3]);
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[tokio::test]
    async fn a_lagging_marker_is_repaired_and_other_disagreements_refused() {
        let dir = temp_dir("mismatch");
        let store = MemStore::default();
        finish(&store, &dir, Plan::Fresh, registry(2), "0.2.0")
            .await
            .expect("format 2");
        // The process stopped after the commit of step 2, before the marker followed.
        format::write_marker(&dir, &Marker::new(1, "0.1.0")).expect("marker");
        let outcome = finish(&store, &dir, OLD, registry(2), "0.2.0")
            .await
            .expect("repair");
        assert!(outcome.marker_repaired);
        assert_eq!(
            format::read_marker(&dir)
                .expect("marker")
                .map(|m| m.version),
            Some(2)
        );
        // A marker ahead of the store cannot be explained by a migration.
        format::write_marker(&dir, &Marker::new(3, "0.3.0")).expect("marker");
        let error = finish(&store, &dir, OLD, registry(3), "0.3.0")
            .await
            .expect_err("mismatch");
        assert_eq!(error.code(), "upgrade.format_mismatch");
        // A store newer than the binary is refused like a newer marker.
        format::write_marker(&dir, &Marker::new(2, "0.2.0")).expect("marker");
        let error = finish(&store, &dir, OLD, registry(1), "0.1.0")
            .await
            .expect_err("newer store");
        assert_eq!(error.code(), "upgrade.format_newer");
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[tokio::test]
    async fn a_legacy_store_without_records_is_format_1() {
        let dir = temp_dir("legacy");
        let store = MemStore::default();
        let outcome = finish(&store, &dir, OLD, registry(1), "0.1.0")
            .await
            .expect("legacy");
        assert_eq!(outcome.version, 1);
        assert!(outcome.record_created);
        assert_eq!(outcome.migrated, Vec::<u32>::new());
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[test]
    fn backups_are_named_by_time_and_pruned() {
        let dir = temp_dir("backup");
        let store_dir = dir.join("store");
        std::fs::create_dir_all(&store_dir).expect("store dir");
        fake_store(&store_dir, Some(1));
        std::fs::write(store_dir.join("sm.redb"), b"state").expect("state");
        let root = dir.join(BACKUPS_DIR);
        for old in [
            "20200101T000000Z-format-1-to-2",
            "20210101T000000Z-format-1-to-2",
            "20220101T000000Z-format-1-to-2",
        ] {
            std::fs::create_dir_all(root.join(old)).expect("old backup");
        }
        let copy = backup(&dir, &store_dir, 1, 2).expect("backup");
        assert!(copy.join("store/log.redb").is_file());
        assert!(copy.join("store/sm.redb").is_file());
        let mut left: Vec<String> = std::fs::read_dir(&root)
            .expect("list")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left.len(), KEEP_BACKUPS);
        assert!(!left.contains(&"20200101T000000Z-format-1-to-2".to_owned()));
        assert!(
            left.last()
                .is_some_and(|name| name.ends_with("-format-1-to-2"))
        );
        std::fs::remove_dir_all(&dir).expect("clean up");
    }
}
