//! Raft log storage over redb (`log.redb` per node) with group commit.
//!
//! openraft 0.9 issues one `append()` per client write on the leader. A synchronous fsync per
//! append would cap a leader at one write per fsync latency, so `append()` only encodes the
//! entries, makes them readable from an in-memory pending map and queues them to a dedicated
//! writer thread. The writer drains everything queued, writes it in ONE redb write
//! transaction committed with `Durability::Immediate` (fsync), and only then fires the
//! `LogFlushed` callbacks. Vote, truncate and purge go through the same FIFO queue (so all
//! log IO stays serialized, as openraft requires) and their callers wait for the commit.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::ops::Bound;
use std::ops::RangeBounds;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::mpsc;

use openraft::LogState;
use openraft::RaftLogReader;
use openraft::storage::LogFlushed;
use openraft::storage::RaftLogStorage;
use redb::Database;
use redb::Durability;
use redb::ReadableDatabase;
use redb::ReadableTable;
use redb::TableDefinition;
use serde::Deserialize;

use crate::raft_types::Entry;
use crate::raft_types::LogId;
use crate::raft_types::StorageError;
use crate::raft_types::StorageIOError;
use crate::raft_types::TypeConfig;
use crate::raft_types::Vote;

const LOGS: TableDefinition<u64, &[u8]> = TableDefinition::new("logs");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("log_meta");
const KEY_VOTE: &str = "vote";
const KEY_PURGED: &str = "last_purged";

type Encoded = Arc<Vec<u8>>;

enum SyncOp {
    Vote(Vec<u8>),
    Truncate(u64),
    Purge(LogId),
}

enum WriteOp {
    Append {
        entries: Vec<(u64, Encoded)>,
        cb: LogFlushed<TypeConfig>,
    },
    Sync {
        op: SyncOp,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}

/// Counters for the group-commit writer.
#[derive(Default)]
pub struct LogIoStats {
    pub commits: AtomicU64,
    pub entries: AtomicU64,
}

struct LogInner {
    db: Database,
    pending: Mutex<BTreeMap<u64, Encoded>>,
    tx: Mutex<mpsc::Sender<WriteOp>>,
    stats: LogIoStats,
}

#[derive(Clone)]
pub struct LogStore {
    inner: Arc<LogInner>,
}

fn io_read(e: impl std::error::Error + 'static) -> StorageError {
    StorageIOError::read_logs(&e).into()
}

fn io_write(e: impl std::error::Error + 'static) -> StorageError {
    StorageIOError::write_logs(&e).into()
}

#[derive(Debug)]
struct Msg(String);
impl std::fmt::Display for Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Msg {}

/// Only the leading `log_id` field of an encoded entry (postcard encodes structs as tuples,
/// so this decodes a prefix of the full entry without touching the payload).
#[derive(Deserialize)]
struct EntryHead {
    log_id: LogId,
}

fn head_of(bytes: &[u8]) -> Result<LogId, StorageError> {
    let (head, _) = postcard::take_from_bytes::<EntryHead>(bytes).map_err(io_read)?;
    Ok(head.log_id)
}

impl LogStore {
    pub fn open(path: &Path, cache_bytes: usize) -> anyhow::Result<Self> {
        let db = Database::builder()
            .set_cache_size(cache_bytes)
            .create(path)?;
        let w = db.begin_write()?;
        {
            w.open_table(LOGS)?;
            w.open_table(META)?;
        }
        w.commit()?;
        let (tx, rx) = mpsc::channel::<WriteOp>();
        let inner = Arc::new(LogInner {
            db,
            pending: Mutex::new(BTreeMap::new()),
            tx: Mutex::new(tx),
            stats: LogIoStats::default(),
        });
        let weak = Arc::downgrade(&inner);
        std::thread::Builder::new()
            .name("log-writer".into())
            .spawn(move || {
                while let Ok(first) = rx.recv() {
                    let Some(inner) = weak.upgrade() else { return };
                    let mut ops = vec![first];
                    while ops.len() < 4096 {
                        match rx.try_recv() {
                            Ok(op) => ops.push(op),
                            Err(_) => break,
                        }
                    }
                    let res = write_group(&inner, &ops).map_err(|e| e.to_string());
                    for op in ops {
                        match op {
                            WriteOp::Append { entries, cb } => {
                                if res.is_ok() {
                                    let mut p = inner.pending.lock().expect("pending lock");
                                    for (i, b) in &entries {
                                        if p.get(i).is_some_and(|cur| Arc::ptr_eq(cur, b)) {
                                            p.remove(i);
                                        }
                                    }
                                }
                                cb.log_io_completed(res.clone().map_err(std::io::Error::other));
                            }
                            WriteOp::Sync { done, .. } => {
                                let _ = done.send(res.clone());
                            }
                        }
                    }
                }
            })?;
        Ok(Self { inner })
    }

    pub fn io_stats(&self) -> (u64, u64) {
        (
            self.inner.stats.commits.load(Ordering::Relaxed),
            self.inner.stats.entries.load(Ordering::Relaxed),
        )
    }

    fn send(&self, op: WriteOp) -> Result<(), StorageError> {
        self.inner
            .tx
            .lock()
            .expect("tx lock")
            .send(op)
            .map_err(|_| io_write(Msg("log writer stopped".into())))
    }

    async fn sync_op(&self, op: SyncOp) -> Result<(), StorageError> {
        let (done, rx) = tokio::sync::oneshot::channel();
        self.send(WriteOp::Sync { op, done })?;
        rx.await
            .map_err(|_| io_write(Msg("log writer dropped reply".into())))?
            .map_err(|e| io_write(Msg(e)))
    }

    fn read_meta<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        let r = self.inner.db.begin_read().map_err(io_read)?;
        let t = r.open_table(META).map_err(io_read)?;
        match t.get(key).map_err(io_read)? {
            Some(v) => Ok(Some(postcard::from_bytes(v.value()).map_err(io_read)?)),
            None => Ok(None),
        }
    }

    /// Read decoded entries in an index range: persisted entries from redb, overlaid with
    /// entries still waiting for the group commit.
    pub fn read_range<RB: RangeBounds<u64>>(&self, range: RB) -> Result<Vec<Entry>, StorageError> {
        let start = match range.start_bound() {
            Bound::Included(s) => *s,
            Bound::Excluded(s) => s + 1,
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(e) => *e,
            Bound::Excluded(e) => {
                if *e == 0 {
                    return Ok(Vec::new());
                }
                e - 1
            }
            Bound::Unbounded => u64::MAX,
        };
        if end < start {
            return Ok(Vec::new());
        }
        // Pending first: anything removed from pending afterwards is already committed and
        // therefore visible to the read transaction opened below.
        let pend: Vec<(u64, Encoded)> = {
            let p = self.inner.pending.lock().expect("pending lock");
            p.range(start..=end).map(|(k, v)| (*k, v.clone())).collect()
        };
        let mut out: BTreeMap<u64, Entry> = BTreeMap::new();
        let first_pending = pend.first().map(|(k, _)| *k).unwrap_or(u64::MAX);
        if first_pending > start {
            let r = self.inner.db.begin_read().map_err(io_read)?;
            let t = r.open_table(LOGS).map_err(io_read)?;
            for item in t
                .range(start..=end.min(first_pending.saturating_sub(1)))
                .map_err(io_read)?
            {
                let (k, v) = item.map_err(io_read)?;
                let e: Entry = postcard::from_bytes(v.value()).map_err(io_read)?;
                out.insert(k.value(), e);
            }
        }
        for (k, b) in pend {
            let e: Entry = postcard::from_bytes(&b).map_err(io_read)?;
            out.insert(k, e);
        }
        Ok(out.into_values().collect())
    }

    /// Index of the last persisted entry, if any.
    pub fn last_index(&self) -> Option<u64> {
        let r = self.inner.db.begin_read().ok()?;
        let t = r.open_table(LOGS).ok()?;
        t.last().ok()?.map(|(k, _)| k.value())
    }

    /// Index of the first persisted entry, if any.
    pub fn first_index(&self) -> Option<u64> {
        let r = self.inner.db.begin_read().ok()?;
        let t = r.open_table(LOGS).ok()?;
        t.first().ok()?.map(|(k, _)| k.value())
    }
}

fn write_group(inner: &LogInner, ops: &[WriteOp]) -> Result<(), StorageError> {
    let mut w = inner.db.begin_write().map_err(io_write)?;
    w.set_durability(Durability::Immediate).map_err(io_write)?;
    let mut n = 0u64;
    {
        let mut t = w.open_table(LOGS).map_err(io_write)?;
        let mut m = w.open_table(META).map_err(io_write)?;
        for op in ops {
            match op {
                WriteOp::Append { entries, .. } => {
                    for (i, b) in entries {
                        t.insert(*i, b.as_slice()).map_err(io_write)?;
                        n += 1;
                    }
                }
                WriteOp::Sync {
                    op: SyncOp::Vote(v),
                    ..
                } => {
                    m.insert(KEY_VOTE, v.as_slice()).map_err(io_write)?;
                }
                WriteOp::Sync {
                    op: SyncOp::Truncate(i),
                    ..
                } => {
                    t.retain_in(*i.., |_, _| false).map_err(io_write)?;
                }
                WriteOp::Sync {
                    op: SyncOp::Purge(l),
                    ..
                } => {
                    let bytes = postcard::to_stdvec(&Some(*l)).map_err(io_write)?;
                    m.insert(KEY_PURGED, bytes.as_slice()).map_err(io_write)?;
                    t.retain_in(..=l.index, |_, _| false).map_err(io_write)?;
                }
            }
        }
    }
    w.commit().map_err(io_write)?;
    inner.stats.commits.fetch_add(1, Ordering::Relaxed);
    inner.stats.entries.fetch_add(n, Ordering::Relaxed);
    Ok(())
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry>, StorageError> {
        tokio::task::block_in_place(|| self.read_range(range))
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError> {
        tokio::task::block_in_place(|| {
            let last_purged_log_id: Option<LogId> =
                self.read_meta::<Option<LogId>>(KEY_PURGED)?.flatten();
            let pending_last = {
                let p = self.inner.pending.lock().expect("pending lock");
                p.last_key_value().map(|(_, v)| v.clone())
            };
            let last = match pending_last {
                Some(b) => Some(head_of(&b)?),
                None => {
                    let r = self.inner.db.begin_read().map_err(io_read)?;
                    let t = r.open_table(LOGS).map_err(io_read)?;
                    match t.last().map_err(io_read)? {
                        Some((_, v)) => Some(head_of(v.value())?),
                        None => None,
                    }
                }
            };
            Ok(LogState {
                last_purged_log_id,
                last_log_id: last.or(last_purged_log_id),
            })
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote) -> Result<(), StorageError> {
        let bytes = postcard::to_stdvec(vote).map_err(io_write)?;
        self.sync_op(SyncOp::Vote(bytes)).await
    }

    async fn read_vote(&mut self) -> Result<Option<Vote>, StorageError> {
        tokio::task::block_in_place(|| self.read_meta(KEY_VOTE))
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
        for e in entries {
            let b: Encoded = Arc::new(postcard::to_stdvec(&e).map_err(io_write)?);
            encoded.push((e.log_id.index, b));
        }
        {
            let mut p = self.inner.pending.lock().expect("pending lock");
            for (i, b) in &encoded {
                p.insert(*i, b.clone());
            }
        }
        self.send(WriteOp::Append {
            entries: encoded,
            cb: callback,
        })
    }

    async fn truncate(&mut self, log_id: LogId) -> Result<(), StorageError> {
        {
            let mut p = self.inner.pending.lock().expect("pending lock");
            let _ = p.split_off(&log_id.index);
        }
        self.sync_op(SyncOp::Truncate(log_id.index)).await
    }

    async fn purge(&mut self, log_id: LogId) -> Result<(), StorageError> {
        {
            let mut p = self.inner.pending.lock().expect("pending lock");
            let rest = p.split_off(&(log_id.index + 1));
            *p = rest;
        }
        self.sync_op(SyncOp::Purge(log_id)).await
    }
}
