//! The Raft state machine: apply, snapshots, derived indexes, durability and the state file.
//!
//! # Apply
//!
//! openraft hands committed entries to [`RaftStateMachine::apply`]. All entries of one call
//! apply in ONE redb write transaction (see `apply` for the batch semantics) together with
//! the [`SmMeta`] row (last applied log id, membership, revision, audit head, journal
//! bounds, data size), so the state and its position in the log can never disagree. After
//! the commit the registered derived indexes receive the change sets with exact views
//! (`index`), and only then does openraft answer the proposer: an index is current before
//! `propose` returns.
//!
//! # Durability
//!
//! The Raft log is always fsynced before an entry commits. The state machine either fsyncs
//! every apply ([`SmOptions::durable_apply`]) or commits without fsync and makes the state
//! durable at checkpoints: periodically, before every snapshot and at shutdown. After a
//! crash, redb returns to the last durable commit and openraft re-applies the committed
//! entries after it from the log (`save_committed` and the first election), so no
//! committed write is lost and no batch is half applied. A snapshot always starts with a
//! checkpoint, so the log is never purged beyond the durable state.
//!
//! # The state file
//!
//! The state lives in one redb file in the data directory: `sm.redb` until the first
//! snapshot install, then the file the pointer file `sm.current` names (`sm-<id>.redb`).
//! Installing a snapshot never rewrites the live file. It writes the new state into a new
//! file in one durable transaction, compacts that file while nothing else uses it (redb
//! grows a file by doubling, so a freshly written file is up to half free space; ADR 0002
//! M6), and then switches: the pointer file is replaced atomically (written aside, synced,
//! renamed), the store moves to the new database, and the old file is removed once its last
//! reader is gone (at the latest at the next start). A crash before the rename leaves the old
//! state and pointer untouched; a crash after it finds the new state. The same path rewrites
//! a node's own state into a fresh file ([`StateMachine::rewrite_in_place`]), which is how a
//! single node re-seeds itself.
//!
//! # Snapshots
//!
//! A snapshot streams a redb read transaction to a file (`snapshot`) while applies
//! continue. After an install every registered index is built aside from the new state and
//! installed atomically: a reader of an index sees the old image until the new one is
//! complete, never an empty one (ADR 0002 condition).

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use openraft::{EntryPayload, RaftSnapshotBuilder, storage::RaftStateMachine};
use redb::{
    Database, Durability, ReadTransaction, ReadableTable, TableDefinition, TableHandle,
    WriteTransaction,
};
use tenko_core::{
    AuditSeq, Revision, TableName,
    audit::{AuditRecord, ChainVerifier},
};
use tokio::sync::watch;

use super::{
    apply::{Applier, TxnTables},
    index::{Capture, Registered, Registry, replay},
    snapshot::{FORMAT, Record, SnapshotHeader, SnapshotReader, read_header, write_snapshot},
    stored::{
        META, META_STATE, SmMeta, data_table, is_store_table, sm_write, snapshot_write, storage,
    },
    types::{
        ApplyResponse, Entry, LogId, Snapshot, SnapshotFile, SnapshotMeta, StorageError,
        StoredMembership, TypeConfig,
    },
    view::RedbView,
};
use crate::api::{DerivedIndex, IndexStatus, KeyRange, ReadView, StoreError, tables};

/// The pointer file naming the active state file.
const POINTER: &str = "sm.current";
/// The pointer file while it is written.
const POINTER_PART: &str = "sm.current.part";
/// The state file of a store that never installed a snapshot.
const INITIAL_FILE: &str = "sm.redb";

/// State machine settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SmOptions {
    /// redb page cache of the state file.
    pub(crate) cache_bytes: usize,
    /// Fsync every apply instead of at checkpoints.
    pub(crate) durable_apply: bool,
    /// Verify the whole audit chain at start-up instead of its head.
    pub(crate) verify_full_chain: bool,
}

/// Counters of the snapshot machinery (read by status and the benchmarks).
#[derive(Debug, Default)]
pub(crate) struct SmStats {
    pub(crate) snapshots_built: AtomicU64,
    pub(crate) snapshots_installed: AtomicU64,
    pub(crate) last_build_micros: AtomicU64,
    pub(crate) last_snapshot_bytes: AtomicU64,
    pub(crate) last_install_micros: AtomicU64,
    pub(crate) last_index_rebuild_micros: AtomicU64,
    pub(crate) last_compact_micros: AtomicU64,
    pub(crate) checkpoints: AtomicU64,
    pub(crate) rewrites: AtomicU64,
    // WP9.6: how long the maintenance task held the next build back (ADR 0030).
    /// Milliseconds the trigger of the build in progress was deferred while the commit
    /// queue was deep (0: built when due); read and cleared by the build's log line.
    pub(crate) deferred_ms: AtomicU64,
}

/// The result of rewriting the state into a fresh file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rewritten {
    pub(crate) bytes_before: u64,
    pub(crate) bytes_after: u64,
    pub(crate) micros: u64,
}

struct Shared {
    dir: PathBuf,
    /// The active state database; replaced when a fresh state file takes over.
    db: RwLock<Arc<Database>>,
    /// The active state file.
    file: Mutex<PathBuf>,
    /// Replaced state files that could not be removed yet (a reader still had them open).
    retired: Mutex<Vec<PathBuf>>,
    options: SmOptions,
    /// The committed metadata.
    state: Mutex<SmMeta>,
    /// Indexes and the registration capture; held across every apply transaction and every
    /// switch of the state file.
    registry: Mutex<Registry>,
    /// One registration at a time.
    registration: Mutex<()>,
    /// Index statuses for `status()`, updated after each apply.
    index_status: Mutex<Vec<IndexStatus>>,
    /// The last applied revision.
    applied: watch::Sender<Revision>,
    /// Commits since the last durable one.
    dirty: AtomicBool,
    snapshot_dir: PathBuf,
    /// The current snapshot and the one before it (kept while it may still be streamed).
    snapshots: Mutex<SnapshotFiles>,
    stats: SmStats,
}

#[derive(Default)]
struct SnapshotFiles {
    current: Option<(SnapshotMeta, PathBuf)>,
    previous: Option<PathBuf>,
}

/// The state machine. Cloning shares it.
#[derive(Clone)]
pub(crate) struct StateMachine {
    shared: Arc<Shared>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn micros_since(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// A file-name-safe snapshot id.
fn file_safe(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!("{nanos:x}-{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Whether a file name is a state file (`sm.redb` or `sm-<id>.redb`, the id made of ASCII
/// letters, digits and dashes as `unique_suffix` writes it).
fn is_state_file(name: &str) -> bool {
    name == INITIAL_FILE
        || name
            .strip_prefix("sm-")
            .and_then(|rest| rest.strip_suffix(".redb"))
            .is_some_and(|id| {
                !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            })
}

/// The active state file of `dir`: the one `sm.current` names, or `sm.redb`.
fn active_file(dir: &Path) -> Result<String, StoreError> {
    match fs::read_to_string(dir.join(POINTER)) {
        Ok(name) => {
            let name = name.trim().to_owned();
            if !is_state_file(&name) {
                return Err(StoreError::Storage(format!(
                    "{} names {name:?}, which is not a state file",
                    dir.join(POINTER).display()
                )));
            }
            if !dir.join(&name).is_file() {
                return Err(StoreError::Storage(format!(
                    "{} names {name}, which does not exist",
                    dir.join(POINTER).display()
                )));
            }
            Ok(name)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(INITIAL_FILE.to_owned()),
        Err(error) => Err(storage(error)),
    }
}

/// Points `sm.current` at `name`: written aside, synced and renamed over the old pointer, so
/// a crash leaves either the old or the new pointer.
fn write_pointer(dir: &Path, name: &str) -> Result<(), StoreError> {
    let part = dir.join(POINTER_PART);
    {
        let mut file = fs::File::create(&part).map_err(storage)?;
        file.write_all(name.as_bytes()).map_err(storage)?;
        file.sync_all().map_err(storage)?;
    }
    fs::rename(&part, dir.join(POINTER)).map_err(storage)?;
    sync_dir(dir);
    Ok(())
}

/// Makes a rename in `dir` durable where the platform allows it (directories cannot be
/// opened for syncing on Windows; NTFS journals the rename).
#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(dir) = fs::File::open(dir) {
        let _ = dir.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

/// Removes state files other than the active one (left by an install that stopped before
/// switching, or replaced while a reader still had them open) and a partial pointer.
fn remove_stale_files(dir: &Path, active: &str) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if (is_state_file(&name) && name != active) || name == POINTER_PART {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn open_database(path: &Path, cache_bytes: usize) -> Result<Database, StoreError> {
    Database::builder()
        .set_cache_size(cache_bytes)
        .create(path)
        .map_err(storage)
}

/// Compacts a database nobody else uses until redb reports nothing left to do.
fn compact(database: &mut Database) -> Result<(), StoreError> {
    for _ in 0..16 {
        if !database.compact().map_err(storage)? {
            break;
        }
    }
    Ok(())
}

/// Copies every store table of `source` into `target`, in key order.
fn copy_tables(source: &ReadTransaction, target: &WriteTransaction) -> Result<(), StoreError> {
    let names: Vec<String> = source
        .list_tables()
        .map_err(storage)?
        .map(|handle| handle.name().to_owned())
        .filter(|name| is_store_table(name))
        .collect();
    for name in &names {
        let definition = TableDefinition::<&[u8], &[u8]>::new(name);
        let from = source.open_table(definition).map_err(storage)?;
        let mut to = target.open_table(definition).map_err(storage)?;
        for item in from.iter().map_err(storage)? {
            let (key, value) = item.map_err(storage)?;
            to.insert(key.value(), value.value()).map_err(storage)?;
        }
    }
    Ok(())
}

/// The SHA-256 over every non-empty store table of a read transaction, in table name order
/// and key order: per table `0x01 | u16 BE name length | name`, per row
/// `0x02 | u32 BE key length | key | u32 BE value length | stored value` (the revision that
/// wrote it, then the value). Empty tables are left out, because a replica that applied the
/// log keeps a table that was emptied while one that installed a snapshot may not.
fn digest_tables(source: &ReadTransaction) -> Result<([u8; 32], u64, u64), StoreError> {
    use sha2::{Digest as _, Sha256};

    let mut names: Vec<String> = source
        .list_tables()
        .map_err(storage)?
        .map(|handle| handle.name().to_owned())
        .filter(|name| is_store_table(name))
        .collect();
    names.sort();
    let mut hasher = Sha256::new();
    let (mut tables, mut entries) = (0_u64, 0_u64);
    for name in &names {
        let definition = TableDefinition::<&[u8], &[u8]>::new(name);
        let table = source.open_table(definition).map_err(storage)?;
        let mut rows = table.iter().map_err(storage)?.peekable();
        if rows.peek().is_none() {
            continue;
        }
        tables += 1;
        hasher.update([0x01]);
        hasher.update(u16::try_from(name.len()).unwrap_or(u16::MAX).to_be_bytes());
        hasher.update(name.as_bytes());
        for item in rows {
            let (key, value) = item.map_err(storage)?;
            let (key, value) = (key.value(), value.value());
            hasher.update([0x02]);
            hasher.update(u32::try_from(key.len()).unwrap_or(u32::MAX).to_be_bytes());
            hasher.update(key);
            hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
            hasher.update(value);
            entries += 1;
        }
    }
    Ok((hasher.finalize().into(), tables, entries))
}

/// Writes every record of a snapshot file into `target`.
fn copy_snapshot(reader: &mut SnapshotReader, target: &WriteTransaction) -> Result<(), StoreError> {
    let mut table = None;
    while let Some(record) = reader.next_record()? {
        match record {
            Record::Table(name) => {
                drop(table.take());
                let name = TableName::new(name.to_owned()).map_err(storage)?;
                table = Some(target.open_table(data_table(&name)).map_err(storage)?);
            }
            Record::Row(key, value) => {
                let Some(table) = table.as_mut() else {
                    return Err(StoreError::Storage(
                        "snapshot row before any table".to_owned(),
                    ));
                };
                table.insert(key, value).map_err(storage)?;
            }
        }
    }
    Ok(())
}

impl StateMachine {
    /// Opens or creates the state file and the snapshot directory under `dir`, removes
    /// state files left behind, verifies the audit chain and finds the current snapshot.
    pub(crate) fn open(dir: &Path, options: SmOptions) -> Result<Self, StoreError> {
        let snapshot_dir = dir.join("snapshots");
        fs::create_dir_all(&snapshot_dir).map_err(storage)?;
        let active = active_file(dir)?;
        remove_stale_files(dir, &active);
        let file = dir.join(&active);
        let db = open_database(&file, options.cache_bytes)?;
        {
            let txn = db.begin_write().map_err(storage)?;
            txn.open_table(META).map_err(storage)?;
            txn.commit().map_err(storage)?;
        }
        let db = Arc::new(db);
        let view = RedbView::open(&db)?;
        let meta = view.meta().clone();
        verify_audit(&view, options.verify_full_chain)?;
        drop(view);
        let snapshots = scan_snapshots(&snapshot_dir)?;
        let (applied, _) = watch::channel(meta.revision);
        Ok(Self {
            shared: Arc::new(Shared {
                dir: dir.to_path_buf(),
                db: RwLock::new(db),
                file: Mutex::new(file),
                retired: Mutex::new(Vec::new()),
                options,
                state: Mutex::new(meta),
                registry: Mutex::new(Registry::new()),
                registration: Mutex::new(()),
                index_status: Mutex::new(Vec::new()),
                applied,
                dirty: AtomicBool::new(false),
                snapshot_dir,
                snapshots: Mutex::new(snapshots),
                stats: SmStats::default(),
            }),
        })
    }

    /// The active state database.
    fn db(&self) -> Arc<Database> {
        Arc::clone(
            &self
                .shared
                .db
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// The active state file.
    pub(crate) fn file_path(&self) -> PathBuf {
        lock(&self.shared.file).clone()
    }

    /// The committed metadata.
    pub(crate) fn meta(&self) -> SmMeta {
        lock(&self.shared.state).clone()
    }

    /// A read view at the committed state.
    pub(crate) fn view(&self) -> Result<RedbView, StoreError> {
        RedbView::open(&self.db())
    }

    /// The digest of the committed state ([`super::RaftStore::digest`]); blocking.
    pub(crate) fn digest(&self) -> Result<super::StateDigest, StoreError> {
        let view = self.view()?;
        let (sha256, tables, entries) = digest_tables(view.txn())?;
        Ok(super::StateDigest {
            revision: view.meta().revision,
            sha256,
            tables,
            entries,
        })
    }

    /// Notifications of the applied revision.
    pub(crate) fn subscribe(&self) -> watch::Receiver<Revision> {
        self.shared.applied.subscribe()
    }

    /// Wakes every waiter without changing the revision (used at shutdown).
    pub(crate) fn wake_all(&self) {
        self.shared.applied.send_modify(|_| {});
    }

    /// Live handles of the state machine (the database closes when the last one drops).
    pub(crate) fn handles(&self) -> usize {
        Arc::strong_count(&self.shared)
    }

    /// Index statuses.
    pub(crate) fn index_statuses(&self) -> Vec<IndexStatus> {
        lock(&self.shared.index_status).clone()
    }

    /// Snapshot counters.
    pub(crate) fn stats(&self) -> &SmStats {
        &self.shared.stats
    }

    /// The current snapshot, if any.
    pub(crate) fn current_snapshot(&self) -> Option<(SnapshotMeta, PathBuf)> {
        lock(&self.shared.snapshots).current.clone()
    }

    /// The snapshot directory.
    pub(crate) fn snapshot_dir(&self) -> &Path {
        &self.shared.snapshot_dir
    }

    /// Makes every commit so far durable (no-op when nothing changed since the last one),
    /// and removes replaced state files whose readers are gone.
    pub(crate) fn checkpoint(&self) -> Result<(), StoreError> {
        self.remove_retired();
        if !self.shared.dirty.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        let result = (|| {
            // An empty durable commit persists every earlier non-durable one.
            let txn = self.db().begin_write().map_err(storage)?;
            txn.commit().map_err(storage)
        })();
        if result.is_err() {
            self.shared.dirty.store(true, Ordering::SeqCst);
        } else {
            self.shared
                .stats
                .checkpoints
                .fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn remove_retired(&self) {
        lock(&self.shared.retired).retain(|path| fs::remove_file(path).is_err() && path.exists());
    }

    /// Applies committed entries in one transaction (blocking).
    pub(crate) fn apply_entries(
        &self,
        entries: Vec<Entry>,
    ) -> Result<Vec<ApplyResponse>, StoreError> {
        let shared = &*self.shared;
        let mut registry = lock(&shared.registry);
        // The state file only switches under the registry lock, so `db` stays the active one.
        let db = self.db();
        let mut meta = lock(&shared.state).clone();
        let mut txn = db.begin_write().map_err(storage)?;
        let durability = if shared.options.durable_apply {
            Durability::Immediate
        } else {
            Durability::None
        };
        txn.set_durability(durability).map_err(storage)?;
        let mut responses = Vec::with_capacity(entries.len());
        let applied = {
            let mut applier =
                Applier::new(TxnTables::new(&txn), &mut meta, registry.wants_writes());
            for entry in entries {
                applier.meta().last_applied = Some(entry.log_id);
                match entry.payload {
                    EntryPayload::Blank => responses.push(ApplyResponse::default()),
                    EntryPayload::Membership(membership) => {
                        applier.meta().membership =
                            StoredMembership::new(Some(entry.log_id), membership);
                        responses.push(ApplyResponse::default());
                    }
                    EntryPayload::Normal(proposal) => {
                        let mut outcomes = Vec::with_capacity(proposal.batches.len());
                        for batch in &proposal.batches {
                            outcomes.push(applier.apply(
                                batch,
                                proposal.journal_retention,
                                proposal.journal_max_bytes,
                            )?);
                        }
                        responses.push(ApplyResponse { outcomes });
                    }
                }
            }
            applier.finish()
        };
        write_meta(&txn, &meta)?;
        txn.commit().map_err(storage)?;
        if !shared.options.durable_apply {
            shared.dirty.store(true, Ordering::SeqCst);
        }
        let revision = meta.revision;
        if !applied.is_empty() {
            let base = RedbView::open(&db).map_err(storage)?;
            registry.absorb(&base, applied);
            *lock(&shared.index_status) = registry.statuses();
        }
        // Published once the indexes are current: a status or waiter that sees the revision
        // also finds it in every index.
        *lock(&shared.state) = meta;
        drop(registry);
        shared.applied.send_if_modified(|current| {
            let changed = *current != revision;
            *current = revision;
            changed
        });
        Ok(responses)
    }

    /// Builds, installs and from then on maintains a derived index (blocking).
    pub(crate) fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        let shared = &*self.shared;
        let _one_at_a_time = lock(&shared.registration);
        let filter = index.filter();
        for _attempt in 0..3 {
            // Pin a view and start capturing under the registry lock: every batch applied
            // after the view is captured.
            let view = {
                let mut registry = lock(&shared.registry);
                registry.capture = Capture::Capturing(Vec::new());
                self.view()
            };
            let view = match view {
                Ok(view) => view,
                Err(error) => {
                    lock(&shared.registry).capture = Capture::Idle;
                    return Err(error);
                }
            };
            let built_at = view.revision();
            // Build aside; writers keep going.
            let built = index.build(&view);
            drop(view);

            let mut registry = lock(&shared.registry);
            let captured = std::mem::replace(&mut registry.capture, Capture::Idle);
            let image = built?;
            let Capture::Capturing(captured) = captured else {
                // A snapshot replaced the state during the build.
                continue;
            };
            let base = self.view()?;
            let memory_bytes = image.memory_bytes();
            index.install(image);
            let mut registered = vec![Registered {
                index,
                filter,
                revision: built_at,
                memory_bytes,
            }];
            replay(&base, &captured, &mut registered);
            registry.indexes.append(&mut registered);
            *lock(&shared.index_status) = registry.statuses();
            return Ok(());
        }

        // Snapshots kept replacing the state: build while holding the registry lock.
        let mut registry = lock(&shared.registry);
        let view = self.view()?;
        let image = index.build(&view)?;
        let memory_bytes = image.memory_bytes();
        index.install(image);
        registry.indexes.push(Registered {
            index,
            filter,
            revision: view.revision(),
            memory_bytes,
        });
        *lock(&shared.index_status) = registry.statuses();
        Ok(())
    }

    /// Builds a snapshot of the current state (blocking).
    pub(crate) fn build_snapshot(&self) -> Result<Snapshot, StoreError> {
        let shared = &*self.shared;
        let started = Instant::now();
        // The log is purged up to the snapshot, so the state it covers must be durable.
        self.checkpoint().map_err(storage)?;
        let view = self.view().map_err(storage)?;
        let state = view.meta().clone();
        let index = state.last_applied.as_ref().map_or(0, |log_id| log_id.index);
        let snapshot_id = format!("{index}-{}", unique_suffix());
        let meta = SnapshotMeta {
            last_log_id: state.last_applied,
            last_membership: state.membership.clone(),
            snapshot_id: snapshot_id.clone(),
        };
        let header = SnapshotHeader {
            format: FORMAT,
            meta: meta.clone(),
            state,
        };
        let part = shared.snapshot_dir.join(format!("snap-{snapshot_id}.part"));
        let path = shared.snapshot_dir.join(format!("snap-{snapshot_id}.tnks"));
        let written = match write_snapshot(view.txn(), &header, &part) {
            Ok(written) => written,
            Err(error) => {
                let _ = fs::remove_file(&part);
                return Err(error);
            }
        };
        drop(view);
        fs::rename(&part, &path).map_err(storage)?;
        self.set_current(meta.clone(), path.clone());
        let counters = &shared.stats;
        counters.snapshots_built.fetch_add(1, Ordering::Relaxed);
        counters
            .last_build_micros
            .store(micros_since(started), Ordering::Relaxed);
        counters
            .last_snapshot_bytes
            .store(written.bytes, Ordering::Relaxed);
        let deferred_ms = counters.deferred_ms.swap(0, Ordering::Relaxed);
        tracing::info!(
            snapshot = %snapshot_id,
            bytes = written.bytes,
            rows = written.rows,
            duration_ms = started.elapsed().as_millis(),
            deferred = deferred_ms > 0,
            deferred_ms,
            "store snapshot built"
        );

        Ok(Snapshot {
            meta,
            snapshot: Box::new(SnapshotFile { path }),
        })
    }

    /// Writes a complete state into a new state file in one durable transaction and
    /// compacts it while nothing else uses it. `fill` copies the store tables and returns
    /// the metadata to store with them. Returns the file's name, path and database; on
    /// failure the file is removed.
    fn write_fresh(
        &self,
        fill: impl FnOnce(&WriteTransaction) -> Result<SmMeta, StoreError>,
    ) -> Result<(String, PathBuf, Database), StoreError> {
        let name = format!("sm-{}.redb", unique_suffix());
        let path = self.shared.dir.join(&name);
        let written = (|| {
            let mut database = open_database(&path, self.shared.options.cache_bytes)?;
            let txn = database.begin_write().map_err(storage)?;
            let state = fill(&txn)?;
            write_meta(&txn, &state)?;
            txn.commit().map_err(storage)?;
            let started = Instant::now();
            compact(&mut database)?;
            self.shared
                .stats
                .last_compact_micros
                .store(micros_since(started), Ordering::Relaxed);
            Ok(database)
        })();
        match written {
            Ok(database) => Ok((name, path, database)),
            Err(error) => {
                let _ = fs::remove_file(&path);
                Err(error)
            }
        }
    }

    /// Makes a fresh state file the active one: pointer first, then the database handle;
    /// the replaced file goes once its readers are gone. Called with the registry lock held.
    fn switch_to(&self, name: &str, path: PathBuf, database: Database) -> Result<(), StoreError> {
        if let Err(error) = write_pointer(&self.shared.dir, name) {
            drop(database);
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        let old_path = std::mem::replace(&mut *lock(&self.shared.file), path);
        let old = std::mem::replace(
            &mut *self
                .shared
                .db
                .write()
                .unwrap_or_else(PoisonError::into_inner),
            Arc::new(database),
        );
        // The new file is durable, so nothing of the old one needs a checkpoint any more.
        self.shared.dirty.store(false, Ordering::SeqCst);
        drop(old);
        lock(&self.shared.retired).push(old_path);
        self.remove_retired();
        Ok(())
    }

    /// Installs a complete snapshot file (blocking): writes it into a fresh, compacted state
    /// file, switches to that file, then rebuilds every index aside and swaps it in.
    pub(crate) fn install(&self, meta: &SnapshotMeta, path: &Path) -> Result<(), StoreError> {
        let shared = &*self.shared;
        let started = Instant::now();
        let mut registry = lock(&shared.registry);
        let mut reader = SnapshotReader::open(path).map_err(storage)?;
        if reader.header().meta.last_log_id != meta.last_log_id {
            return Err(StoreError::Storage(format!(
                "snapshot file covers {:?}, the install asks for {:?}",
                reader.header().meta.last_log_id,
                meta.last_log_id
            )));
        }
        let mut state = reader.header().state.clone();
        state.last_applied = meta.last_log_id;
        state.membership = meta.last_membership.clone();

        // The trailing hash is checked before the transaction commits.
        let (name, file, database) = self.write_fresh(|txn| {
            copy_snapshot(&mut reader, txn)?;
            Ok(state.clone())
        })?;
        self.switch_to(&name, file, database)?;
        let revision = state.revision;
        if matches!(registry.capture, Capture::Capturing(_)) {
            registry.capture = Capture::Invalidated;
        }

        // Build every index aside from the new state, then swap; readers keep the old image.
        let rebuild_started = Instant::now();
        if !registry.indexes.is_empty() {
            let view = self.view().map_err(storage)?;
            for registered in &mut registry.indexes {
                let image = registered.index.build(&view).map_err(storage)?;
                registered.memory_bytes = image.memory_bytes();
                registered.index.install(image);
                registered.revision = revision;
            }
            *lock(&shared.index_status) = registry.statuses();
        }
        let rebuild_micros = micros_since(rebuild_started);
        *lock(&shared.state) = state;
        drop(registry);

        let final_path = shared
            .snapshot_dir
            .join(format!("snap-{}.tnks", file_safe(&meta.snapshot_id)));
        if path != final_path {
            fs::rename(path, &final_path).map_err(storage)?;
        }
        self.set_current(meta.clone(), final_path);
        shared.applied.send_if_modified(|current| {
            let changed = *current != revision;
            *current = revision;
            changed
        });
        let counters = &shared.stats;
        counters.snapshots_installed.fetch_add(1, Ordering::Relaxed);
        counters
            .last_install_micros
            .store(micros_since(started), Ordering::Relaxed);
        counters
            .last_index_rebuild_micros
            .store(rebuild_micros, Ordering::Relaxed);
        tracing::info!(
            snapshot = %meta.snapshot_id,
            revision = revision.get(),
            "store snapshot installed"
        );
        Ok(())
    }

    /// Rewrites the current state into a fresh, compacted state file and switches to it: a
    /// re-seed of the node from its own state (blocking). Applies wait until it is done;
    /// reads continue. The state does not change, so indexes keep their images.
    pub(crate) fn rewrite_in_place(&self) -> Result<Rewritten, StoreError> {
        let started = Instant::now();
        let registry = lock(&self.shared.registry);
        let bytes_before = fs::metadata(self.file_path()).map_or(0, |m| m.len());
        let view = self.view()?;
        let state = view.meta().clone();
        let (name, file, database) = self.write_fresh(|txn| {
            copy_tables(view.txn(), txn)?;
            Ok(state)
        })?;
        drop(view);
        self.switch_to(&name, file.clone(), database)?;
        drop(registry);
        self.shared.stats.rewrites.fetch_add(1, Ordering::Relaxed);
        let bytes_after = fs::metadata(&file).map_or(0, |m| m.len());
        tracing::info!(bytes_before, bytes_after, "store state file rewritten");
        Ok(Rewritten {
            bytes_before,
            bytes_after,
            micros: micros_since(started),
        })
    }

    /// Writes the current state into the new state file `target` from one read transaction,
    /// so the copy is consistent at the revision of that view, and returns the revision
    /// (blocking). Applies continue meanwhile. A directory whose `sm.redb` is this file and
    /// which has no log opens as a store at that state: openraft purges the empty log up to
    /// the applied id. The caller makes sure `target` does not exist.
    pub(crate) fn export_state(&self, target: &Path) -> Result<Revision, StoreError> {
        let view = self.view()?;
        let state = view.meta().clone();
        let written = (|| {
            let mut database = open_database(target, self.shared.options.cache_bytes)?;
            let txn = database.begin_write().map_err(storage)?;
            copy_tables(view.txn(), &txn)?;
            write_meta(&txn, &state)?;
            txn.commit().map_err(storage)?;
            compact(&mut database)?;
            Ok(())
        })();
        drop(view);
        if written.is_err() {
            let _ = fs::remove_file(target);
        }
        written.map(|()| state.revision)
    }

    /// A fresh file in the snapshot directory to receive a snapshot into.
    pub(crate) fn receive_path(&self) -> PathBuf {
        self.shared
            .snapshot_dir
            .join(format!("recv-{}.part", unique_suffix()))
    }

    fn set_current(&self, meta: SnapshotMeta, path: PathBuf) {
        let mut files = lock(&self.shared.snapshots);
        let Some((_, old)) = files.current.replace((meta, path)) else {
            return;
        };
        let current = files.current.as_ref().map(|(_, path)| path.clone());
        if current.as_ref() == Some(&old) {
            return;
        }
        if let Some(oldest) = files.previous.replace(old)
            && current.as_ref() != Some(&oldest)
        {
            let _ = fs::remove_file(oldest);
        }
    }
}

fn write_meta(txn: &WriteTransaction, meta: &SmMeta) -> Result<(), StoreError> {
    let encoded = meta.encode()?;
    let mut table = txn.open_table(META).map_err(storage)?;
    table.insert(META_STATE, &encoded[..]).map_err(storage)?;
    Ok(())
}

/// Verifies the audit chain against the committed head: the head record recomputes to the
/// stored hash and links to its predecessor, and nothing follows it. With `full`, every
/// record from 1 is verified.
fn verify_audit(view: &RedbView, full: bool) -> Result<(), StoreError> {
    let head = view.meta().audit_head;
    let fail = |detail: String| {
        StoreError::Storage(format!(
            "the audit chain does not verify at start-up: {detail}"
        ))
    };
    if full {
        let mut verifier = ChainVerifier::new();
        let mut range = KeyRange::all();
        loop {
            let page = view.scan(tables::AUDIT.name(), range.clone(), 1_024, false)?;
            let Some((last, _)) = page.last() else {
                break;
            };
            range = KeyRange::all().after(last.clone());
            for (_, versioned) in page {
                let record = tables::AUDIT.decode(&versioned.value)?;
                verifier
                    .push(&record)
                    .map_err(|error| fail(error.to_string()))?;
            }
        }
        if verifier.head() != head {
            return Err(fail(format!(
                "the chain ends at record {}, the store head is record {}",
                verifier.head().seq,
                head.seq
            )));
        }
        return Ok(());
    }
    let record = |seq: AuditSeq| -> Result<Option<AuditRecord>, StoreError> {
        view.get(tables::AUDIT.name(), &tables::AUDIT.key(&seq))?
            .map(|versioned| {
                tables::AUDIT
                    .decode(&versioned.value)
                    .map_err(StoreError::from)
            })
            .transpose()
    };
    if record(head.seq.next())?.is_some() {
        return Err(fail(format!("a record follows the head {}", head.seq)));
    }
    if head.seq == AuditSeq::NONE {
        return Ok(());
    }
    let Some(last) = record(head.seq)? else {
        return Err(fail(format!("head record {} is missing", head.seq)));
    };
    if last.seq != head.seq || last.hash != head.hash || last.compute_hash()? != last.hash {
        return Err(fail(format!("head record {} has been altered", head.seq)));
    }
    if head.seq.get() > 1 {
        let Some(previous) = record(AuditSeq(head.seq.get() - 1))? else {
            return Err(fail(format!("record {} is missing", head.seq.get() - 1)));
        };
        if previous.compute_hash()? != previous.hash || previous.hash != last.prev {
            return Err(fail(format!(
                "record {} does not link to its predecessor",
                head.seq
            )));
        }
    }
    Ok(())
}

/// Removes partial files and all but the two newest snapshots; returns those two.
fn scan_snapshots(dir: &Path) -> Result<SnapshotFiles, StoreError> {
    let mut complete = Vec::new();
    for entry in fs::read_dir(dir).map_err(storage)? {
        let path = entry.map_err(storage)?.path();
        let is_snapshot = path
            .extension()
            .is_some_and(|extension| extension == "tnks");
        if !is_snapshot {
            if path
                .extension()
                .is_some_and(|extension| extension == "part")
            {
                let _ = fs::remove_file(&path);
            }
            continue;
        }
        match read_header(&path) {
            Ok(header) => complete.push((header.meta, path)),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "removing an unreadable snapshot");
                let _ = fs::remove_file(&path);
            }
        }
    }
    complete.sort_by_key(|(meta, _)| meta.last_log_id);
    let current = complete.pop();
    let previous = complete.pop().map(|(_, path)| path);
    for (_, path) in complete {
        let _ = fs::remove_file(path);
    }
    Ok(SnapshotFiles { current, previous })
}

/// Total size of the files in a directory (not recursive).
pub(crate) fn dir_bytes(dir: &Path) -> u64 {
    fs::read_dir(dir).map_or(0, |entries| {
        entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.metadata().ok())
            .filter(fs::Metadata::is_file)
            .map(|metadata| metadata.len())
            .sum()
    })
}

/// Builds snapshots for openraft.
pub(crate) struct SnapshotBuilder {
    sm: StateMachine,
}

impl RaftSnapshotBuilder<TypeConfig> for SnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot, StorageError> {
        let sm = self.sm.clone();
        tokio::task::spawn_blocking(move || sm.build_snapshot())
            .await
            .map_err(snapshot_write)?
            .map_err(snapshot_write)
    }
}

#[allow(
    clippy::unused_async_trait_impl,
    reason = "openraft declares these methods async; the bodies are short and synchronous"
)]
impl RaftStateMachine<TypeConfig> for StateMachine {
    type SnapshotBuilder = SnapshotBuilder;

    async fn applied_state(&mut self) -> Result<(Option<LogId>, StoredMembership), StorageError> {
        let meta = lock(&self.shared.state);
        Ok((meta.last_applied, meta.membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<ApplyResponse>, StorageError>
    where
        I: IntoIterator<Item = Entry> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<Entry> = entries.into_iter().collect();
        let sm = self.clone();
        tokio::task::spawn_blocking(move || sm.apply_entries(entries))
            .await
            .map_err(sm_write)?
            .map_err(sm_write)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        SnapshotBuilder { sm: self.clone() }
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Box<SnapshotFile>, StorageError> {
        let path = self.receive_path();
        fs::File::create(&path).map_err(snapshot_write)?;
        Ok(Box::new(SnapshotFile { path }))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta,
        snapshot: Box<SnapshotFile>,
    ) -> Result<(), StorageError> {
        let sm = self.clone();
        let meta = meta.clone();
        tokio::task::spawn_blocking(move || sm.install(&meta, &snapshot.path))
            .await
            .map_err(snapshot_write)?
            .map_err(snapshot_write)
    }

    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot>, StorageError> {
        Ok(self.current_snapshot().map(|(meta, path)| Snapshot {
            meta,
            snapshot: Box::new(SnapshotFile { path }),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenko-sm-test-{name}-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn state_file_names() {
        assert!(is_state_file("sm.redb"));
        assert!(is_state_file("sm-18dce4-3.redb"));
        assert!(!is_state_file("log.redb"));
        assert!(!is_state_file("sm-x.redb.part"));
        assert!(!is_state_file("sm-../x.redb"));
    }

    #[test]
    fn pointer_selects_the_active_file_and_stale_files_go() {
        let dir = temp_dir("pointer");
        assert_eq!(active_file(&dir).expect("default"), INITIAL_FILE);
        fs::write(dir.join("sm.redb"), b"old").expect("write");
        fs::write(dir.join("sm-1.redb"), b"new").expect("write");
        fs::write(dir.join("sm-2.redb"), b"abandoned install").expect("write");
        fs::write(dir.join(POINTER_PART), b"sm-2.redb").expect("write");
        fs::write(dir.join("log.redb"), b"log").expect("write");
        write_pointer(&dir, "sm-1.redb").expect("pointer");
        let active = active_file(&dir).expect("active");
        assert_eq!(active, "sm-1.redb");
        remove_stale_files(&dir, &active);
        let mut left: Vec<String> = fs::read_dir(&dir)
            .expect("list")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, vec!["log.redb", "sm-1.redb", "sm.current"]);
        fs::remove_file(dir.join("sm-1.redb")).expect("remove");
        assert!(
            active_file(&dir).is_err(),
            "a pointer to a missing file is an error, never an empty store"
        );
        fs::remove_dir_all(&dir).expect("clean up");
    }
}
