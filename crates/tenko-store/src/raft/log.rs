//! The Raft log store: openraft 0.9 over redb (`log.redb`, one file per node) with group
//! commit.
//!
//! # Why group commit
//!
//! openraft 0.9 awaits each log flush before it takes the next client request (ADR 0002
//! decision 4), so a leader that made one fsync per `append` could never complete more
//! appends per second than the disk can fsync. `append` therefore only encodes the entries,
//! makes them readable from an in-memory pending map and hands them to one dedicated writer
//! thread (`tenko-log-writer`). The writer drains every operation queued so far, applies them
//! in order in ONE redb write transaction committed with `Durability::Immediate` (one fsync
//! for the whole group) and only then fires the `LogFlushed` callbacks. While it commits, new
//! operations queue up and become the next group, so the group size adapts to the load.
//!
//! Votes, truncations and purges go through the same FIFO queue, which keeps all log IO
//! serialized as openraft requires; their callers wait for the commit. `save_committed` never
//! waits and never causes a commit: the value is kept in memory and written by the next group
//! commit that happens anyway (and by a final commit when the store is closed). A persisted
//! `committed` value may therefore lag behind the one last saved, which is harmless: openraft
//! only uses it at start-up to re-apply committed entries. The writer takes the value before
//! it drains its queue, so the persisted `committed` never points past the entries persisted
//! by the same or an earlier commit.
//!
//! # On-disk layout
//!
//! Two redb tables in one file:
//!
//! - `logs: u64 -> bytes`. The key is the log index. The value is
//!   `[u32 big-endian length of the CBOR LogId][CBOR LogId][CBOR Entry]`, so
//!   `get_log_state` decodes only the head (the log id) of the last entry and never its
//!   payload.
//! - `log_meta: str -> bytes` with the keys `vote` (CBOR `Vote`), `last_purged` (CBOR
//!   `LogId`) and `committed` (CBOR `Option<LogId>`).
//!
//! All CBOR goes through `tenko_core::codec`.
//!
//! # Threads and lifecycle
//!
//! The state the writer thread needs (the database and the pending map) lives in an inner
//! structure the thread owns a reference to. The handle all [`LogStore`] clones share owns
//! the sending side of the queue and the thread's join handle, but is never referenced by the
//! thread, so there is no reference cycle. When the last clone is dropped, the queue closes,
//! the writer drains what is queued, commits a pending `committed` value, exits, and the drop
//! waits for it; the redb file is closed when the drop returns. [`LogStore::shutdown`] does
//! the same early: afterwards every write operation fails with a storage error instead of
//! hanging, while reads keep working until the last clone is dropped.

#![allow(
    clippy::unused_async_trait_impl,
    reason = "the trait methods are async; the short redb reads and queue pushes do not yield"
)]
#![allow(
    clippy::result_large_err,
    reason = "openraft's StorageError is the error type of the storage traits and of this API"
)]

use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{Debug, Display},
    io,
    ops::{Bound, RangeBounds},
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
};

use bytes::Bytes;
use openraft::{
    AnyError, LogState, RaftLogReader,
    storage::{LogFlushed, RaftLogStorage},
};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use tenko_core::codec::{CodecError, from_cbor, to_cbor};
use tokio::sync::oneshot;

use super::types::{Entry, LogId, StorageError, StorageIOError, TypeConfig, Vote};
use crate::api::StoreError;

/// Log entries by index.
const LOGS: TableDefinition<u64, &[u8]> = TableDefinition::new("logs");
/// Vote, last purged log id and committed log id.
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("log_meta");
const KEY_VOTE: &str = "vote";
const KEY_PURGED: &str = "last_purged";
const KEY_COMMITTED: &str = "committed";
/// Most operations the writer folds into one commit.
const MAX_GROUP_OPS: usize = 4096;
/// Size of the length prefix in front of the encoded log id.
const HEAD_PREFIX: usize = 4;
/// Name of the writer thread.
const WRITER_NAME: &str = "tenko-log-writer";

/// An encoded log record, shared between the pending map and the queue.
type Encoded = Arc<Vec<u8>>;

/// Counters of the group-commit writer, monotonic since the store was opened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogStats {
    /// Group commits (redb write transactions with one fsync) the writer completed. A group
    /// holds every operation that was queued while the previous commit ran.
    pub commits: u64,
    /// Log entries written by those commits.
    pub entries: u64,
    /// Encoded bytes (log id head plus entry) of the entries written by those commits.
    pub appended_bytes: u64,
}

/// A log-wide operation that needs the whole commit to finish before it returns.
enum SyncOp {
    Vote(Bytes),
    Truncate(u64),
    Purge { last: LogId, encoded: Bytes },
}

/// One unit of work for the writer thread.
enum WriteOp {
    Append {
        entries: Vec<(u64, Encoded)>,
        callback: LogFlushed<TypeConfig>,
    },
    Sync {
        op: SyncOp,
        done: oneshot::Sender<Result<(), String>>,
    },
}

/// What one group commit wrote.
#[derive(Default)]
struct Written {
    entries: u64,
    bytes: u64,
}

#[derive(Default)]
struct Counters {
    commits: AtomicU64,
    entries: AtomicU64,
    appended_bytes: AtomicU64,
}

/// A `committed` log id as saved: never, or a value (which may itself be `None`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum SavedCommitted {
    #[default]
    Unset,
    Set(Option<LogId>),
}

/// The `committed` log id between `save_committed` and the commit that persists it.
#[derive(Default)]
struct CommittedSlot {
    /// What the last `save_committed` of this process stored.
    latest: SavedCommitted,
    /// The encoded value no commit has written yet.
    unwritten: Option<Bytes>,
}

/// The state the writer thread works on.
struct Shared {
    db: Database,
    /// Encoded records appended but not yet committed, by index.
    pending: Mutex<BTreeMap<u64, Encoded>>,
    committed: Mutex<CommittedSlot>,
    counters: Counters,
}

/// What every clone of [`LogStore`] shares. The writer thread holds [`Shared`], never this.
struct Inner {
    shared: Arc<Shared>,
    /// `None` once the store is shut down.
    queue: Mutex<Option<mpsc::Sender<WriteOp>>>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

/// The Raft log store of one node: openraft's [`RaftLogStorage`] and [`RaftLogReader`] over
/// one redb file with group commit (see the module documentation).
///
/// Cloning is cheap; all clones share one writer thread and one file.
#[derive(Clone)]
pub struct LogStore {
    inner: Arc<Inner>,
}

/// Locks a mutex, recovering the data if a panicking holder poisoned it.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn read_err(error: impl Error + 'static) -> StorageError {
    StorageIOError::read_logs(&error).into()
}

fn write_err(error: impl Error + 'static) -> StorageError {
    StorageIOError::write_logs(&error).into()
}

fn write_msg(message: impl ToString) -> StorageError {
    StorageIOError::write_logs(AnyError::error(message)).into()
}

fn storage_error(context: &str, error: impl Display) -> StoreError {
    StoreError::Storage(format!("{context}: {error}"))
}

fn count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Encodes a log record: `[u32 BE head length][CBOR LogId][CBOR Entry]`.
fn encode_record(entry: &Entry) -> Result<Vec<u8>, CodecError> {
    let head = to_cbor(&entry.log_id)?;
    let body = to_cbor(entry)?;
    let head_len = u32::try_from(head.len())
        .map_err(|_| CodecError::Encode("encoded log id is longer than u32::MAX".to_owned()))?;
    let mut record = Vec::with_capacity(HEAD_PREFIX + head.len() + body.len());
    record.extend_from_slice(&head_len.to_be_bytes());
    record.extend_from_slice(&head);
    record.extend_from_slice(&body);
    Ok(record)
}

/// Splits a record into the CBOR log id and the CBOR entry.
fn split_record(record: &[u8]) -> Result<(&[u8], &[u8]), CodecError> {
    let malformed = || CodecError::Decode("log record is shorter than its head".to_owned());
    let (prefix, rest) = record
        .split_first_chunk::<HEAD_PREFIX>()
        .ok_or_else(malformed)?;
    let head_len = usize::try_from(u32::from_be_bytes(*prefix)).map_err(|_| malformed())?;
    rest.split_at_checked(head_len).ok_or_else(malformed)
}

/// Decodes only the log id of a record.
fn decode_head(record: &[u8]) -> Result<LogId, CodecError> {
    from_cbor(split_record(record)?.0)
}

/// Decodes the whole entry of a record.
fn decode_entry(record: &[u8]) -> Result<Entry, CodecError> {
    from_cbor(split_record(record)?.1)
}

/// Inclusive `(first, last)` indexes of a range, or `None` if the range is empty.
fn inclusive_bounds(range: &impl RangeBounds<u64>) -> Option<(u64, u64)> {
    let first = match range.start_bound() {
        Bound::Included(first) => *first,
        Bound::Excluded(before) => before.checked_add(1)?,
        Bound::Unbounded => 0,
    };
    let last = match range.end_bound() {
        Bound::Included(last) => *last,
        Bound::Excluded(after) => after.checked_sub(1)?,
        Bound::Unbounded => u64::MAX,
    };
    (first <= last).then_some((first, last))
}

impl Shared {
    fn take_unwritten_committed(&self) -> Option<Bytes> {
        lock(&self.committed).unwritten.take()
    }

    /// Puts a `committed` value back after it could not be written, unless a newer one has
    /// been saved meanwhile.
    fn restore_committed(&self, encoded: Bytes) {
        let mut slot = lock(&self.committed);
        if slot.unwritten.is_none() {
            slot.unwritten = Some(encoded);
        }
    }

    /// The bytes stored under a `log_meta` key.
    fn meta_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, redb::Error> {
        let read = self.db.begin_read()?;
        let meta = read.open_table(META)?;
        let value = meta.get(key)?.map(|value| value.value().to_vec());
        Ok(value)
    }

    /// The `committed` value of the database; `Unset` if never written.
    fn persisted_committed(&self) -> Result<SavedCommitted, StorageError> {
        match self.meta_bytes(KEY_COMMITTED).map_err(read_err)? {
            Some(bytes) => Ok(SavedCommitted::Set(from_cbor(&bytes).map_err(read_err)?)),
            None => Ok(SavedCommitted::Unset),
        }
    }

    fn last_purged(&self) -> Result<Option<LogId>, StorageError> {
        match self.meta_bytes(KEY_PURGED).map_err(read_err)? {
            Some(bytes) => Ok(Some(from_cbor(&bytes).map_err(read_err)?)),
            None => Ok(None),
        }
    }

    /// First or last index of the committed log.
    fn persisted_edge(&self, last: bool) -> Option<u64> {
        let read = self.db.begin_read().ok()?;
        let logs = read.open_table(LOGS).ok()?;
        let edge = if last { logs.last() } else { logs.first() };
        edge.ok()?.map(|(index, _)| index.value())
    }

    fn log_state(&self) -> Result<LogState<TypeConfig>, StorageError> {
        // Pending first: whatever leaves it afterwards is committed and visible to the read
        // transaction opened below.
        let pending_last = lock(&self.pending)
            .last_key_value()
            .map(|(_, record)| Arc::clone(record));
        let read = self.db.begin_read().map_err(read_err)?;
        let meta = read.open_table(META).map_err(read_err)?;
        let last_purged_log_id = match meta.get(KEY_PURGED).map_err(read_err)? {
            Some(value) => Some(from_cbor::<LogId>(value.value()).map_err(read_err)?),
            None => None,
        };
        let last_log_id = if let Some(record) = pending_last {
            Some(decode_head(&record).map_err(read_err)?)
        } else {
            let logs = read.open_table(LOGS).map_err(read_err)?;
            match logs.last().map_err(read_err)? {
                Some((_, record)) => Some(decode_head(record.value()).map_err(read_err)?),
                None => None,
            }
        };
        Ok(LogState {
            last_purged_log_id,
            last_log_id: last_log_id.or(last_purged_log_id),
        })
    }

    /// Entries of an index range: committed ones from redb, followed by those still waiting
    /// for the group commit. Missing indexes are skipped.
    fn read_range(&self, range: &impl RangeBounds<u64>) -> Result<Vec<Entry>, StorageError> {
        let Some((first, last)) = inclusive_bounds(range) else {
            return Ok(Vec::new());
        };
        // Pending first: whatever leaves it afterwards is committed and visible to the read
        // transaction opened below.
        let pending: Vec<Encoded> = lock(&self.pending)
            .range(first..=last)
            .map(|(_, record)| Arc::clone(record))
            .collect();
        // Pending records are the newest suffix of the log; persisted ones end before them.
        let persisted_last = match pending.first() {
            Some(head) => decode_head(head)
                .map_err(read_err)?
                .index
                .checked_sub(1)
                .map(|before| before.min(last)),
            None => Some(last),
        };
        let mut entries = Vec::new();
        if let Some(persisted_last) = persisted_last.filter(|end| *end >= first) {
            let read = self.db.begin_read().map_err(read_err)?;
            let logs = read.open_table(LOGS).map_err(read_err)?;
            for item in logs.range(first..=persisted_last).map_err(read_err)? {
                let (_, record) = item.map_err(read_err)?;
                entries.push(decode_entry(record.value()).map_err(read_err)?);
            }
        }
        for record in &pending {
            entries.push(decode_entry(record).map_err(read_err)?);
        }
        Ok(entries)
    }

    /// Applies a group in one write transaction with one fsync.
    fn write_group(
        &self,
        ops: &[WriteOp],
        committed: Option<&Bytes>,
    ) -> Result<Written, redb::Error> {
        let mut transaction = self.db.begin_write()?;
        transaction.set_durability(Durability::Immediate)?;
        let mut written = Written::default();
        {
            let mut logs = transaction.open_table(LOGS)?;
            let mut meta = transaction.open_table(META)?;
            for op in ops {
                match op {
                    WriteOp::Append { entries, .. } => {
                        for (index, record) in entries {
                            logs.insert(*index, record.as_slice())?;
                            written.entries += 1;
                            written.bytes += count(record.len());
                        }
                    }
                    WriteOp::Sync {
                        op: SyncOp::Vote(vote),
                        ..
                    } => {
                        meta.insert(KEY_VOTE, &vote[..])?;
                    }
                    WriteOp::Sync {
                        op: SyncOp::Truncate(from),
                        ..
                    } => {
                        logs.retain_in(*from.., |_, _| false)?;
                    }
                    WriteOp::Sync {
                        op: SyncOp::Purge { last, encoded },
                        ..
                    } => {
                        meta.insert(KEY_PURGED, &encoded[..])?;
                        logs.retain_in(..=last.index, |_, _| false)?;
                    }
                }
            }
            if let Some(encoded) = committed {
                meta.insert(KEY_COMMITTED, &encoded[..])?;
            }
        }
        transaction.commit()?;
        Ok(written)
    }

    /// Commits a group, then answers every operation in it.
    fn commit_group(&self, ops: Vec<WriteOp>, committed: Option<Bytes>) {
        let result = self.write_group(&ops, committed.as_ref()).map_err(|error| {
            tracing::error!(%error, "log group commit failed");
            format!("log group commit failed: {error}")
        });
        match &result {
            Ok(written) => {
                self.counters.commits.fetch_add(1, Ordering::Relaxed);
                self.counters
                    .entries
                    .fetch_add(written.entries, Ordering::Relaxed);
                self.counters
                    .appended_bytes
                    .fetch_add(written.bytes, Ordering::Relaxed);
            }
            Err(_) => {
                if let Some(encoded) = committed {
                    self.restore_committed(encoded);
                }
            }
        }
        let outcome = result.map(|_| ());
        for op in ops {
            match op {
                WriteOp::Append { entries, callback } => {
                    // Committed or failed, the records no longer belong in the pending map.
                    self.retire_pending(&entries);
                    callback.log_io_completed(outcome.clone().map_err(io::Error::other));
                }
                WriteOp::Sync { done, .. } => {
                    // The caller may have given up waiting; nothing to do then.
                    let _ = done.send(outcome.clone());
                }
            }
        }
    }

    /// Removes the records of one append from the pending map unless a newer record has
    /// replaced them.
    fn retire_pending(&self, entries: &[(u64, Encoded)]) {
        let mut pending = lock(&self.pending);
        for (index, record) in entries {
            if pending
                .get(index)
                .is_some_and(|current| Arc::ptr_eq(current, record))
            {
                pending.remove(index);
            }
        }
    }

    /// The writer thread: one commit per drained group, until the queue closes.
    fn run_writer(&self, queue: &mpsc::Receiver<WriteOp>) {
        while let Ok(first) = queue.recv() {
            // Taken before the queue is drained: every append that was queued before the
            // `save_committed` of this value is in this group or an earlier one.
            let mut committed = self.take_unwritten_committed();
            let mut ops = vec![first];
            while ops.len() < MAX_GROUP_OPS {
                let Ok(op) = queue.try_recv() else { break };
                ops.push(op);
            }
            if ops.len() >= MAX_GROUP_OPS {
                // The queue may hold appends this value refers to; wait for a later group.
                if let Some(encoded) = committed.take() {
                    self.restore_committed(encoded);
                }
            }
            self.commit_group(ops, committed);
        }
        if let Some(encoded) = self.take_unwritten_committed() {
            self.commit_group(Vec::new(), Some(encoded));
        }
    }
}

impl Inner {
    /// Closes the queue and waits for the writer thread, which drains it first.
    fn stop(&self) {
        drop(lock(&self.queue).take());
        let mut writer = lock(&self.writer);
        if let Some(handle) = writer.take() {
            // A panic of the writer has nothing left to recover here.
            let _ = handle.join();
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop();
    }
}

impl LogStore {
    /// Opens or creates the log database at `path` with a redb cache of `cache_bytes` and
    /// starts the writer thread. Both tables are created in one committed transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the file cannot be opened (also when this process
    /// has it open already), the tables cannot be created or the thread cannot be started.
    pub fn open(path: &Path, cache_bytes: usize) -> Result<Self, StoreError> {
        let db = Database::builder()
            .set_cache_size(cache_bytes)
            .create(path)
            .map_err(|error| storage_error("opening the log database", error))?;
        create_tables(&db).map_err(|error| storage_error("creating the log tables", error))?;
        let shared = Arc::new(Shared {
            db,
            pending: Mutex::new(BTreeMap::new()),
            committed: Mutex::new(CommittedSlot::default()),
            counters: Counters::default(),
        });
        let (sender, queue) = mpsc::channel();
        let worker = Arc::clone(&shared);
        let writer = std::thread::Builder::new()
            .name(WRITER_NAME.to_owned())
            .spawn(move || worker.run_writer(&queue))
            .map_err(|error| storage_error("starting the log writer thread", error))?;
        Ok(Self {
            inner: Arc::new(Inner {
                shared,
                queue: Mutex::new(Some(sender)),
                writer: Mutex::new(Some(writer)),
            }),
        })
    }

    /// Counters of the group-commit writer since the store was opened.
    pub fn stats(&self) -> LogStats {
        let counters = &self.inner.shared.counters;
        LogStats {
            commits: counters.commits.load(Ordering::Relaxed),
            entries: counters.entries.load(Ordering::Relaxed),
            appended_bytes: counters.appended_bytes.load(Ordering::Relaxed),
        }
    }

    /// Number of live `LogStore` handles (clones of this store); the database closes when
    /// the last one drops. The writer thread holds none, so the count settles as soon as the
    /// other owners drop theirs.
    pub fn handles(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Index of the first entry, committed or pending; `None` if the log is empty or cannot
    /// be read.
    pub fn first_index(&self) -> Option<u64> {
        let shared = &self.inner.shared;
        let pending = lock(&shared.pending)
            .first_key_value()
            .map(|(index, _)| *index);
        pending
            .into_iter()
            .chain(shared.persisted_edge(false))
            .min()
    }

    /// Index of the last entry, committed or pending; `None` if the log is empty or cannot
    /// be read.
    pub fn last_index(&self) -> Option<u64> {
        let shared = &self.inner.shared;
        let pending = lock(&shared.pending)
            .last_key_value()
            .map(|(index, _)| *index);
        pending.into_iter().chain(shared.persisted_edge(true)).max()
    }

    /// The last purged log id, or `None` if nothing was purged.
    ///
    /// # Errors
    ///
    /// Returns a read error if the database or the stored value cannot be read.
    pub fn last_purged(&self) -> Result<Option<LogId>, StorageError> {
        self.inner.shared.last_purged()
    }

    /// Stops the writer thread after it has drained and committed the queue, and joins it,
    /// so a caller that then drops the last clone knows the file is closed.
    ///
    /// Afterwards every operation that writes (`append`, `save_vote`, `save_committed`,
    /// `truncate`, `purge`) fails with a storage error. Reads keep working until the last
    /// clone is dropped. Calling it again is harmless.
    pub fn shutdown(&self) {
        self.inner.stop();
    }

    /// Queues an operation for the writer thread.
    fn enqueue(&self, op: WriteOp) -> Result<(), &'static str> {
        let queue = lock(&self.inner.queue);
        let sender = queue.as_ref().ok_or("the log store is shut down")?;
        sender
            .send(op)
            .map_err(|_| "the log writer thread has stopped")
    }

    /// Queues a log-wide operation and waits for the commit that carries it.
    async fn sync_op(
        &self,
        op: SyncOp,
        failure: fn(AnyError) -> StorageIOError,
    ) -> Result<(), StorageError> {
        let (done, committed) = oneshot::channel();
        self.enqueue(WriteOp::Sync { op, done })
            .map_err(|message| failure(AnyError::error(message)))?;
        committed
            .await
            .map_err(|_| failure(AnyError::error("the log writer stopped before the commit")))?
            .map_err(|message| StorageError::from(failure(AnyError::error(message))))
    }

    #[cfg(test)]
    fn persisted_committed(&self) -> SavedCommitted {
        self.inner
            .shared
            .persisted_committed()
            .expect("read the committed log id")
    }
}

/// Creates both tables in one committed transaction.
fn create_tables(db: &Database) -> Result<(), redb::Error> {
    let transaction = db.begin_write()?;
    transaction.open_table(LOGS)?;
    transaction.open_table(META)?;
    transaction.commit()?;
    Ok(())
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry>, StorageError> {
        // Short redb reads run inline: `block_in_place` would panic on a current-thread
        // runtime.
        self.inner.shared.read_range(&range)
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = LogStore;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError> {
        self.inner.shared.log_state()
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote) -> Result<(), StorageError> {
        let encoded = to_cbor(vote).map_err(|error| StorageIOError::write_vote(&error))?;
        self.sync_op(SyncOp::Vote(encoded), StorageIOError::write_vote)
            .await
    }

    async fn read_vote(&mut self) -> Result<Option<Vote>, StorageError> {
        let stored = self
            .inner
            .shared
            .meta_bytes(KEY_VOTE)
            .map_err(|error| StorageIOError::read_vote(&error))?;
        let vote = stored
            .map(|bytes| from_cbor(&bytes))
            .transpose()
            .map_err(|error| StorageIOError::read_vote(&error))?;
        Ok(vote)
    }

    async fn save_committed(&mut self, committed: Option<LogId>) -> Result<(), StorageError> {
        if lock(&self.inner.queue).is_none() {
            return Err(write_msg("the log store is shut down"));
        }
        let encoded = to_cbor(&committed).map_err(write_err)?;
        let mut slot = lock(&self.inner.shared.committed);
        slot.latest = SavedCommitted::Set(committed);
        slot.unwritten = Some(encoded);
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogId>, StorageError> {
        let shared = &self.inner.shared;
        // The value saved in this process, persisted or not, wins; after a restart the
        // persisted one is the only one there is.
        let latest = lock(&shared.committed).latest;
        let saved = match latest {
            SavedCommitted::Unset => shared.persisted_committed()?,
            set @ SavedCommitted::Set(_) => set,
        };
        match saved {
            SavedCommitted::Set(committed) => Ok(committed),
            SavedCommitted::Unset => Ok(None),
        }
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError>
    where
        I: IntoIterator<Item = Entry> + Send,
        I::IntoIter: Send,
    {
        let mut encoded = Vec::new();
        for entry in entries {
            let record = encode_record(&entry).map_err(write_err)?;
            encoded.push((entry.log_id.index, Arc::new(record)));
        }
        {
            let mut pending = lock(&self.inner.shared.pending);
            for (index, record) in &encoded {
                pending.insert(*index, Arc::clone(record));
            }
        }
        let queued = encoded.clone();
        self.enqueue(WriteOp::Append {
            entries: queued,
            callback,
        })
        .map_err(|message| {
            self.inner.shared.retire_pending(&encoded);
            write_msg(message)
        })
    }

    async fn truncate(&mut self, log_id: LogId) -> Result<(), StorageError> {
        drop(lock(&self.inner.shared.pending).split_off(&log_id.index));
        self.sync_op(SyncOp::Truncate(log_id.index), StorageIOError::write_logs)
            .await
    }

    async fn purge(&mut self, log_id: LogId) -> Result<(), StorageError> {
        let encoded = to_cbor(&log_id).map_err(write_err)?;
        {
            let mut pending = lock(&self.inner.shared.pending);
            let kept = pending.split_off(&log_id.index.saturating_add(1));
            *pending = kept;
        }
        let op = SyncOp::Purge {
            last: log_id,
            encoded,
        };
        self.sync_op(op, StorageIOError::write_logs).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        future::Future,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use openraft::{
        BasicNode, Config, EntryPayload, RaftSnapshotBuilder, SnapshotPolicy,
        error::{Fatal, RPCError, RaftError, ReplicationClosed, StreamingError, Unreachable},
        network::{RPCOption, RaftNetwork, RaftNetworkFactory},
        raft::{
            AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, VoteRequest,
            VoteResponse,
        },
        storage::RaftStateMachine,
        testing::{StoreBuilder, Suite, blank_ent, log_id},
    };
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::raft::types::{
        ApplyResponse, Proposal, ProposedBatch, Raft, RaftNodeId, Snapshot, SnapshotFile,
        SnapshotMeta, StoredMembership,
    };

    const CACHE: usize = 1 << 20;

    static DIRS: AtomicU64 = AtomicU64::new(0);

    /// A unique directory under the system temp directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let unique = DIRS.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "tenko-log-{tag}-{}-{unique}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create the test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn log_path(&self) -> PathBuf {
            self.0.join("log.redb")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // A minimal in-memory state machine: just enough for openraft's suite and for a
    // single-node Raft.

    #[derive(Clone, Default, Serialize, Deserialize)]
    struct SmState {
        last_applied: Option<LogId>,
        membership: StoredMembership,
        applied: Vec<LogId>,
    }

    #[derive(Clone)]
    struct CurrentSnapshot {
        meta: SnapshotMeta,
        path: PathBuf,
    }

    struct TestSm {
        state: SmState,
        current: Arc<Mutex<Option<CurrentSnapshot>>>,
        dir: PathBuf,
        next_id: Arc<AtomicU64>,
    }

    struct TestSnapshotBuilder {
        state: SmState,
        current: Arc<Mutex<Option<CurrentSnapshot>>>,
        dir: PathBuf,
        id: u64,
    }

    fn sm_err(error: impl Error + 'static) -> StorageError {
        StorageIOError::write_state_machine(&error).into()
    }

    impl TestSm {
        fn new(dir: PathBuf) -> Self {
            std::fs::create_dir_all(&dir).expect("create the snapshot directory");
            Self {
                state: SmState::default(),
                current: Arc::new(Mutex::new(None)),
                dir,
                next_id: Arc::new(AtomicU64::new(0)),
            }
        }
    }

    impl RaftSnapshotBuilder<TypeConfig> for TestSnapshotBuilder {
        async fn build_snapshot(&mut self) -> Result<Snapshot, StorageError> {
            let path = self.dir.join(format!("snapshot-{}.cbor", self.id));
            std::fs::write(&path, to_cbor(&self.state).map_err(sm_err)?).map_err(sm_err)?;
            let meta = SnapshotMeta {
                last_log_id: self.state.last_applied,
                last_membership: self.state.membership.clone(),
                snapshot_id: format!("snapshot-{}", self.id),
            };
            *lock(&self.current) = Some(CurrentSnapshot {
                meta: meta.clone(),
                path: path.clone(),
            });
            Ok(Snapshot {
                meta,
                snapshot: Box::new(SnapshotFile { path }),
            })
        }
    }

    impl RaftStateMachine<TypeConfig> for TestSm {
        type SnapshotBuilder = TestSnapshotBuilder;

        async fn applied_state(
            &mut self,
        ) -> Result<(Option<LogId>, StoredMembership), StorageError> {
            Ok((self.state.last_applied, self.state.membership.clone()))
        }

        async fn apply<I>(&mut self, entries: I) -> Result<Vec<ApplyResponse>, StorageError>
        where
            I: IntoIterator<Item = Entry> + Send,
            I::IntoIter: Send,
        {
            let mut responses = Vec::new();
            for entry in entries {
                self.state.last_applied = Some(entry.log_id);
                self.state.applied.push(entry.log_id);
                if let EntryPayload::Membership(membership) = entry.payload {
                    self.state.membership = StoredMembership::new(Some(entry.log_id), membership);
                }
                responses.push(ApplyResponse::default());
            }
            Ok(responses)
        }

        async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
            TestSnapshotBuilder {
                state: self.state.clone(),
                current: Arc::clone(&self.current),
                dir: self.dir.clone(),
                id: self.next_id.fetch_add(1, Ordering::Relaxed),
            }
        }

        async fn begin_receiving_snapshot(&mut self) -> Result<Box<SnapshotFile>, StorageError> {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let path = self.dir.join(format!("incoming-{id}.cbor"));
            Ok(Box::new(SnapshotFile { path }))
        }

        async fn install_snapshot(
            &mut self,
            meta: &SnapshotMeta,
            snapshot: Box<SnapshotFile>,
        ) -> Result<(), StorageError> {
            let bytes = std::fs::read(&snapshot.path).map_err(sm_err)?;
            self.state = from_cbor(&bytes).map_err(sm_err)?;
            *lock(&self.current) = Some(CurrentSnapshot {
                meta: meta.clone(),
                path: snapshot.path,
            });
            Ok(())
        }

        async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot>, StorageError> {
            let current = lock(&self.current).clone();
            Ok(current.map(|current| Snapshot {
                meta: current.meta,
                snapshot: Box::new(SnapshotFile { path: current.path }),
            }))
        }
    }

    // A network for a cluster without peers: it is never asked to connect.

    struct NoNetwork;

    fn no_peers() -> Unreachable {
        Unreachable::new(&io::Error::other("the test cluster has no peers"))
    }

    impl RaftNetworkFactory<TypeConfig> for NoNetwork {
        type Network = NoNetwork;

        async fn new_client(&mut self, _target: RaftNodeId, _node: &BasicNode) -> Self::Network {
            NoNetwork
        }
    }

    impl RaftNetwork<TypeConfig> for NoNetwork {
        async fn append_entries(
            &mut self,
            _rpc: AppendEntriesRequest<TypeConfig>,
            _option: RPCOption,
        ) -> Result<
            AppendEntriesResponse<RaftNodeId>,
            RPCError<RaftNodeId, BasicNode, RaftError<RaftNodeId>>,
        > {
            Err(no_peers().into())
        }

        async fn vote(
            &mut self,
            _rpc: VoteRequest<RaftNodeId>,
            _option: RPCOption,
        ) -> Result<VoteResponse<RaftNodeId>, RPCError<RaftNodeId, BasicNode, RaftError<RaftNodeId>>>
        {
            Err(no_peers().into())
        }

        async fn full_snapshot(
            &mut self,
            _vote: Vote,
            _snapshot: Snapshot,
            _cancel: impl Future<Output = ReplicationClosed> + Send + 'static,
            _option: RPCOption,
        ) -> Result<SnapshotResponse<RaftNodeId>, StreamingError<TypeConfig, Fatal<RaftNodeId>>>
        {
            Err(no_peers().into())
        }
    }

    // openraft's own storage suite.

    struct SuiteBuilder;

    impl StoreBuilder<TypeConfig, LogStore, TestSm, TempDir> for SuiteBuilder {
        async fn build(&self) -> Result<(TempDir, LogStore, TestSm), StorageError> {
            let dir = TempDir::new("suite");
            let store = LogStore::open(&dir.log_path(), CACHE)
                .map_err(|error| StorageIOError::write_logs(AnyError::error(error)))?;
            let sm = TestSm::new(dir.path().join("snapshots"));
            Ok((dir, store, sm))
        }
    }

    #[test]
    fn passes_the_openraft_storage_suite() {
        Suite::<TypeConfig, LogStore, TestSm, SuiteBuilder, TempDir>::test_all(SuiteBuilder)
            .expect("openraft's storage suite");
    }

    // Single-node Raft on top of the store: the only way to get a `LogFlushed`.

    fn proposal(seed: u8) -> Proposal {
        Proposal {
            journal_retention: 0,
            journal_max_bytes: 0,
            batches: vec![ProposedBatch {
                batch: Bytes::from(vec![seed; 16 + usize::from(seed)]),
                fingerprint: None,
            }],
        }
    }

    async fn start_node(store: LogStore, dir: &Path) -> Raft {
        let config = Config {
            cluster_name: "log-test".to_owned(),
            heartbeat_interval: 50,
            election_timeout_min: 150,
            election_timeout_max: 300,
            snapshot_policy: SnapshotPolicy::Never,
            ..Default::default()
        };
        let config = Arc::new(config.validate().expect("a valid Raft configuration"));
        let sm = TestSm::new(dir.join("sm"));
        let raft = Raft::new(1, config, NoNetwork, store, sm)
            .await
            .expect("start the Raft node");
        raft.initialize(BTreeMap::from([(1, BasicNode::new("test"))]))
            .await
            .expect("initialize the single-node cluster");
        raft.wait(Some(Duration::from_secs(10)))
            .applied_index_at_least(Some(1), "membership and leader blank entry applied")
            .await
            .expect("the node becomes leader");
        raft
    }

    /// Proposes `count` entries at once; returns their log ids in log order.
    async fn write_all(raft: &Raft, count: u8) -> Vec<LogId> {
        let writes: Vec<_> = (0..count)
            .map(|seed| {
                let raft = raft.clone();
                tokio::spawn(async move {
                    raft.client_write(proposal(seed))
                        .await
                        .expect("client write")
                        .log_id
                })
            })
            .collect();
        let mut ids = Vec::new();
        for write in writes {
            ids.push(write.await.expect("write task"));
        }
        ids.sort();
        ids
    }

    /// Runs a fresh single-node cluster that writes `count` entries, then closes everything.
    /// Returns the log ids of the written entries and the final counters.
    async fn run_cluster(dir: &TempDir, count: u8) -> (Vec<LogId>, LogStats) {
        let store = LogStore::open(&dir.log_path(), CACHE).expect("open the log");
        let raft = start_node(store.clone(), dir.path()).await;
        let ids = write_all(&raft, count).await;
        raft.shutdown().await.expect("stop the Raft node");
        store.shutdown();
        (ids, store.stats())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn log_vote_purge_and_committed_survive_a_reopen() {
        let dir = TempDir::new("roundtrip");
        let (ids, _) = run_cluster(&dir, 5).await;
        let last = *ids.last().expect("written entries");

        let mut store = LogStore::open(&dir.log_path(), CACHE).expect("reopen");
        let before = store.try_get_log_entries(..).await.expect("read the log");
        let vote = store
            .read_vote()
            .await
            .expect("read the vote")
            .expect("a vote");
        assert_eq!(before.last().map(|entry| entry.log_id), Some(last));
        assert_eq!(store.read_committed().await.expect("committed"), Some(last));

        let purged = before[2].log_id;
        store.purge(purged).await.expect("purge");
        store
            .save_committed(Some(last))
            .await
            .expect("save committed");
        store.shutdown();
        drop(store);

        let mut store = LogStore::open(&dir.log_path(), CACHE).expect("reopen again");
        let after = store.try_get_log_entries(..).await.expect("read the log");
        assert_eq!(after, before[3..]);
        assert_eq!(store.read_vote().await.expect("vote"), Some(vote));
        assert_eq!(store.read_committed().await.expect("committed"), Some(last));
        assert_eq!(store.last_purged().expect("last purged"), Some(purged));
        assert_eq!(store.first_index(), Some(purged.index + 1));
        assert_eq!(store.last_index(), Some(last.index));
        let state = store.get_log_state().await.expect("log state");
        assert_eq!(state.last_purged_log_id, Some(purged));
        assert_eq!(state.last_log_id, Some(last));
        let seeds: Vec<u8> = before
            .iter()
            .filter_map(|entry| match &entry.payload {
                EntryPayload::Normal(proposal) => Some(proposal.batches[0].batch[0]),
                _ => None,
            })
            .collect();
        assert_eq!(seeds.len(), 5);
        store.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_proposals_are_all_written_and_counted() {
        let dir = TempDir::new("counters");
        let (ids, stats) = run_cluster(&dir, 64).await;
        assert_eq!(ids.len(), 64);

        let mut store = LogStore::open(&dir.log_path(), CACHE).expect("reopen");
        let entries = store.try_get_log_entries(..).await.expect("read the log");
        assert_eq!(stats.entries, count(entries.len()));
        // Votes and the closing `committed` flush commit too, so commits and entries are
        // not comparable.
        assert!(stats.commits >= 1);
        assert!(stats.appended_bytes > 0);
        assert_eq!(store.stats(), LogStats::default());
        store.shutdown();
    }

    #[test]
    fn operations_queued_while_a_commit_is_blocked_share_one_commit() {
        let dir = TempDir::new("group");
        let store = LogStore::open(&dir.log_path(), CACHE).expect("open");
        let blocker = store
            .inner
            .shared
            .db
            .begin_write()
            .expect("hold the write lock");
        let mut waiting = Vec::new();
        for term in 1..=50 {
            let (done, committed) = oneshot::channel();
            let encoded = to_cbor(&Vote::new(term, 1)).expect("encode a vote");
            store
                .enqueue(WriteOp::Sync {
                    op: SyncOp::Vote(encoded),
                    done,
                })
                .expect("queue a vote");
            waiting.push(committed);
        }
        drop(blocker);
        for committed in waiting {
            committed
                .blocking_recv()
                .expect("answered")
                .expect("committed");
        }
        // The writer took the first operation(s) before it blocked; everything queued behind
        // the blocked commit went into one group.
        assert!(store.stats().commits <= 2, "{:?}", store.stats());
        let vote = store
            .inner
            .shared
            .meta_bytes(KEY_VOTE)
            .expect("read")
            .expect("a vote");
        assert_eq!(from_cbor::<Vote>(&vote).expect("decode"), Vote::new(50, 1));
        store.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn appended_entries_are_readable_before_their_flush_and_flush_after_the_commit() {
        let dir = TempDir::new("pending");
        let mut store = LogStore::open(&dir.log_path(), CACHE).expect("open");
        let raft = start_node(store.clone(), dir.path()).await;
        assert_eq!(store.last_index(), Some(1));
        let blocker = store
            .inner
            .shared
            .db
            .begin_write()
            .expect("hold the write lock");

        let writer = raft.clone();
        let write = tokio::spawn(async move { writer.client_write(proposal(7)).await });
        let deadline = Instant::now() + Duration::from_secs(10);
        while store.last_index() != Some(2) {
            assert!(Instant::now() < deadline, "the entry never became readable");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(store.inner.shared.persisted_edge(true), Some(1));
        let entries = store.try_get_log_entries(2..).await.expect("read pending");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            store.get_log_state().await.expect("state").last_log_id,
            Some(entries[0].log_id)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !write.is_finished(),
            "the write was answered before the commit"
        );

        drop(blocker);
        write.await.expect("write task").expect("client write");
        assert_eq!(store.inner.shared.persisted_edge(true), Some(2));
        raft.shutdown().await.expect("stop the Raft node");
        store.shutdown();
    }

    #[tokio::test]
    async fn save_committed_waits_for_a_commit_that_happens_anyway() {
        let dir = TempDir::new("committed");
        let mut store = LogStore::open(&dir.log_path(), CACHE).expect("open");
        let (first, second) = (log_id(1, 1, 7), log_id(1, 1, 9));
        let before = store.stats().commits;

        store.save_committed(Some(first)).await.expect("save");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            store.stats().commits,
            before,
            "save_committed must not commit"
        );
        assert_eq!(store.persisted_committed(), SavedCommitted::Unset);
        assert_eq!(store.read_committed().await.expect("read"), Some(first));

        store.save_vote(&Vote::new(1, 1)).await.expect("vote");
        assert_eq!(
            store.persisted_committed(),
            SavedCommitted::Set(Some(first))
        );

        store.save_committed(Some(second)).await.expect("save");
        assert_eq!(
            store.persisted_committed(),
            SavedCommitted::Set(Some(first))
        );
        store.shutdown();
        assert_eq!(
            store.persisted_committed(),
            SavedCommitted::Set(Some(second))
        );
        assert_eq!(store.stats().commits, before + 2);
        drop(store);

        let mut store = LogStore::open(&dir.log_path(), CACHE).expect("reopen");
        assert_eq!(store.read_committed().await.expect("read"), Some(second));
        store.save_committed(None).await.expect("save");
        store.shutdown();
        drop(store);
        let mut store = LogStore::open(&dir.log_path(), CACHE).expect("reopen again");
        assert_eq!(store.persisted_committed(), SavedCommitted::Set(None));
        assert_eq!(store.read_committed().await.expect("read"), None);
    }

    #[tokio::test]
    async fn shutdown_fails_writes_and_dropping_every_clone_releases_the_file() {
        let dir = TempDir::new("shutdown");
        let mut store = LogStore::open(&dir.log_path(), CACHE).expect("open");
        store.save_vote(&Vote::new(3, 1)).await.expect("vote");
        store.shutdown();
        store.shutdown();

        assert!(store.save_vote(&Vote::new(4, 1)).await.is_err());
        assert!(store.truncate(log_id(1, 1, 1)).await.is_err());
        assert!(store.purge(log_id(1, 1, 1)).await.is_err());
        assert!(store.save_committed(None).await.is_err());
        assert_eq!(
            store.read_vote().await.expect("read"),
            Some(Vote::new(3, 1))
        );

        // The file stays open until the last clone is gone.
        let clone = store.clone();
        drop(store);
        assert!(LogStore::open(&dir.log_path(), CACHE).is_err());
        drop(clone);

        let mut reopened = LogStore::open(&dir.log_path(), CACHE).expect("reopen");
        assert_eq!(
            reopened.read_vote().await.expect("read"),
            Some(Vote::new(3, 1))
        );
    }

    #[tokio::test]
    async fn dropping_every_clone_without_shutdown_commits_and_releases_the_file() {
        let dir = TempDir::new("drop");
        let mut store = LogStore::open(&dir.log_path(), CACHE).expect("open");
        let mut reader = store.get_log_reader().await;
        store.save_vote(&Vote::new(5, 1)).await.expect("vote");
        store
            .save_committed(Some(log_id(1, 1, 3)))
            .await
            .expect("save");
        drop(store);
        assert!(reader.get_log_state().await.is_ok());
        drop(reader);

        let mut reopened = LogStore::open(&dir.log_path(), CACHE).expect("reopen");
        assert_eq!(
            reopened.read_vote().await.expect("read"),
            Some(Vote::new(5, 1))
        );
        assert_eq!(
            reopened.read_committed().await.expect("read"),
            Some(log_id(1, 1, 3))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_append_after_shutdown_fails_instead_of_hanging() {
        let dir = TempDir::new("append-after-shutdown");
        let store = LogStore::open(&dir.log_path(), CACHE).expect("open");
        let raft = start_node(store.clone(), dir.path()).await;
        store.shutdown();
        let answer = tokio::time::timeout(Duration::from_secs(10), raft.client_write(proposal(1)))
            .await
            .expect("the write must be answered, not hang");
        assert!(answer.is_err());
        let _ = raft.shutdown().await;
    }

    #[tokio::test]
    async fn handles_count_only_live_clones_not_the_writer_thread() {
        let dir = TempDir::new("handles");
        let mut store = LogStore::open(&dir.log_path(), CACHE).expect("open");
        assert_eq!(store.handles(), 1);
        // Let the writer thread run a group, then go idle again.
        store.save_vote(&Vote::new(1, 1)).await.expect("vote");
        assert_eq!(store.handles(), 1);
        let reader = store.get_log_reader().await;
        let clone = store.clone();
        assert_eq!(store.handles(), 3);
        drop(reader);
        drop(clone);
        assert_eq!(store.handles(), 1);
        store.shutdown();
        assert_eq!(store.handles(), 1);
    }

    #[test]
    fn the_writer_thread_is_named() {
        let dir = TempDir::new("thread");
        let store = LogStore::open(&dir.log_path(), CACHE).expect("open");
        let writer = lock(&store.inner.writer);
        let name = writer.as_ref().and_then(|handle| handle.thread().name());
        assert_eq!(name, Some("tenko-log-writer"));
        drop(writer);
        store.shutdown();
    }

    #[test]
    fn poisoned_locks_are_recovered() {
        let dir = TempDir::new("poison");
        let store = LogStore::open(&dir.log_path(), CACHE).expect("open");
        let shared = Arc::clone(&store.inner.shared);
        let poisoner = std::thread::spawn(move || {
            let _held = shared.pending.lock().expect("lock");
            panic!("poison the pending map on purpose");
        });
        assert!(poisoner.join().is_err());
        assert!(store.inner.shared.pending.is_poisoned());
        assert_eq!(store.first_index(), None);
        assert_eq!(store.last_index(), None);
        store.shutdown();
    }

    #[test]
    fn open_reports_storage_errors() {
        let dir = TempDir::new("open-error");
        let missing = dir.path().join("missing").join("log.redb");
        assert!(matches!(
            LogStore::open(&missing, CACHE),
            Err(StoreError::Storage(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_disk_holds_head_prefixed_cbor_records() {
        let dir = TempDir::new("layout");
        let (ids, _) = run_cluster(&dir, 3).await;

        let db = Database::open(dir.log_path()).expect("open the raw database");
        let read = db.begin_read().expect("read transaction");
        let logs = read.open_table(LOGS).expect("logs table");
        let mut indexes = Vec::new();
        for item in logs.iter().expect("iterate") {
            let (index, record) = item.expect("record");
            let (index, record) = (index.value(), record.value());
            let head_len = u32::from_be_bytes(record[..4].try_into().expect("prefix")) as usize;
            let head: LogId = from_cbor(&record[4..4 + head_len]).expect("head");
            let entry: Entry = from_cbor(&record[4 + head_len..]).expect("entry");
            assert_eq!(head, entry.log_id);
            assert_eq!(head.index, index);
            indexes.push(index);
        }
        assert_eq!(
            indexes,
            (0..=ids.last().expect("ids").index).collect::<Vec<_>>()
        );

        let meta = read.open_table(META).expect("meta table");
        let keys: Vec<String> = meta
            .iter()
            .expect("iterate")
            .map(|item| item.expect("meta").0.value().to_owned())
            .collect();
        assert_eq!(keys, ["committed", "vote"]);
        let committed = meta.get(KEY_COMMITTED).expect("get").expect("committed");
        assert_eq!(
            from_cbor::<Option<LogId>>(committed.value()).expect("decode"),
            ids.last().copied()
        );
    }

    #[test]
    fn record_helpers_round_trip_and_reject_short_input() {
        let entry: Entry = blank_ent::<TypeConfig>(2, 1, 41);
        let record = encode_record(&entry).expect("encode");
        assert_eq!(decode_head(&record).expect("head"), entry.log_id);
        assert_eq!(decode_entry(&record).expect("entry"), entry);
        assert!(decode_head(&record[..2]).is_err());
        assert!(decode_entry(&[0, 0, 0, 9, 1]).is_err());
    }

    #[test]
    fn ranges_become_inclusive_bounds() {
        assert_eq!(inclusive_bounds(&(..)), Some((0, u64::MAX)));
        assert_eq!(inclusive_bounds(&(3..6)), Some((3, 5)));
        assert_eq!(inclusive_bounds(&(3..=6)), Some((3, 6)));
        assert_eq!(inclusive_bounds(&(..=6)), Some((0, 6)));
        assert_eq!(inclusive_bounds(&(5..5)), None);
        assert_eq!(inclusive_bounds(&(0..0)), None);
        assert_eq!(
            inclusive_bounds(&(Bound::Excluded(u64::MAX), Bound::Unbounded)),
            None
        );
        assert_eq!(
            inclusive_bounds(&(Bound::Excluded(4), Bound::Included(5))),
            Some((5, 5))
        );
    }
}
