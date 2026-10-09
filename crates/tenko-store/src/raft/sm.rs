//! The Raft state machine over `sm.redb`: apply, snapshots, derived indexes, durability.
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
//! # Snapshots
//!
//! A snapshot streams a redb read transaction to a file (`snapshot`) while applies
//! continue. Installing one replaces every store table in one durable transaction, then
//! builds every registered index aside from the new state and installs it atomically: a
//! reader of an index sees the old image until the new one is complete, never an empty one
//! (ADR 0002 condition).

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use openraft::{EntryPayload, RaftSnapshotBuilder, storage::RaftStateMachine};
use redb::{Database, Durability, TableDefinition, TableHandle};
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

/// State machine settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SmOptions {
    /// redb page cache of `sm.redb`.
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
    pub(crate) checkpoints: AtomicU64,
}

struct Shared {
    db: Database,
    options: SmOptions,
    /// The committed metadata.
    state: Mutex<SmMeta>,
    /// Indexes and the registration capture; held across every apply transaction.
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

impl StateMachine {
    /// Opens or creates `sm.redb` and the snapshot directory under `dir`, verifies the audit
    /// chain and finds the current snapshot.
    pub(crate) fn open(dir: &Path, options: SmOptions) -> Result<Self, StoreError> {
        let snapshot_dir = dir.join("snapshots");
        fs::create_dir_all(&snapshot_dir).map_err(storage)?;
        let db = Database::builder()
            .set_cache_size(options.cache_bytes)
            .create(dir.join("sm.redb"))
            .map_err(storage)?;
        {
            let txn = db.begin_write().map_err(storage)?;
            txn.open_table(META).map_err(storage)?;
            txn.commit().map_err(storage)?;
        }
        let view = RedbView::open(&db)?;
        let meta = view.meta().clone();
        verify_audit(&view, options.verify_full_chain)?;
        drop(view);
        let snapshots = scan_snapshots(&snapshot_dir)?;
        let (applied, _) = watch::channel(meta.revision);
        Ok(Self {
            shared: Arc::new(Shared {
                db,
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

    /// The committed metadata.
    pub(crate) fn meta(&self) -> SmMeta {
        lock(&self.shared.state).clone()
    }

    /// A read view at the committed state.
    pub(crate) fn view(&self) -> Result<RedbView, StoreError> {
        RedbView::open(&self.shared.db)
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

    /// Bytes of the snapshot files.
    pub(crate) fn snapshot_dir(&self) -> &Path {
        &self.shared.snapshot_dir
    }

    /// Makes every commit so far durable (no-op when nothing changed since the last one).
    pub(crate) fn checkpoint(&self) -> Result<(), StoreError> {
        if !self.shared.dirty.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        let result = (|| {
            // An empty durable commit persists every earlier non-durable one.
            let txn = self.shared.db.begin_write().map_err(storage)?;
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

    /// Applies committed entries in one transaction (blocking).
    pub(crate) fn apply_entries(
        &self,
        entries: Vec<Entry>,
    ) -> Result<Vec<ApplyResponse>, StoreError> {
        let shared = &*self.shared;
        let mut registry = lock(&shared.registry);
        let mut meta = lock(&shared.state).clone();
        let mut txn = shared.db.begin_write().map_err(storage)?;
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
                            outcomes.push(applier.apply(batch, proposal.journal_retention)?);
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
            let base = RedbView::open(&shared.db).map_err(storage)?;
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
                RedbView::open(&shared.db)
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
            let base = RedbView::open(&shared.db)?;
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
        let view = RedbView::open(&shared.db)?;
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
        let view = RedbView::open(&shared.db).map_err(storage)?;
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
        tracing::info!(
            snapshot = %snapshot_id,
            bytes = written.bytes,
            rows = written.rows,
            "store snapshot built"
        );
        Ok(Snapshot {
            meta,
            snapshot: Box::new(SnapshotFile { path }),
        })
    }

    /// Installs a complete snapshot file (blocking): replaces the state, then rebuilds every
    /// index aside and swaps it in.
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

        let txn = shared.db.begin_write().map_err(storage)?;
        {
            let names: Vec<String> = txn
                .list_tables()
                .map_err(storage)?
                .map(|handle| handle.name().to_owned())
                .filter(|name| is_store_table(name))
                .collect();
            for name in &names {
                txn.delete_table(TableDefinition::<&[u8], &[u8]>::new(name))
                    .map_err(storage)?;
            }
            let mut table = None;
            while let Some(record) = reader.next_record().map_err(storage)? {
                match record {
                    Record::Table(name) => {
                        drop(table.take());
                        let name = TableName::new(name.to_owned()).map_err(storage)?;
                        table = Some(txn.open_table(data_table(&name)).map_err(storage)?);
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
        }
        write_meta(&txn, &state)?;
        // Durable: an installed snapshot replaces log entries that may be purged.
        txn.commit().map_err(storage)?;
        shared.dirty.store(false, Ordering::SeqCst);
        let revision = state.revision;
        if matches!(registry.capture, Capture::Capturing(_)) {
            registry.capture = Capture::Invalidated;
        }

        // Build every index aside from the new state, then swap; readers keep the old image.
        let rebuild_started = Instant::now();
        if !registry.indexes.is_empty() {
            let view = RedbView::open(&shared.db).map_err(storage)?;
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

fn write_meta(txn: &redb::WriteTransaction, meta: &SmMeta) -> Result<(), StoreError> {
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
