//! Raft state machine over redb (`sm.redb` per node) plus the in-memory serving index.
//!
//! Tables:
//! - `records`: encoded record key -> encoded `StoredRRset` (see `model.rs`).
//! - `journal`: change sequence number -> encoded [`JournalRecord`] (the IXFR source).
//! - `sm_meta`: last applied log id, last membership, next journal sequence number.
//!
//! `apply` writes all entries of one call in a single redb write transaction (records,
//! journal and meta together, so they are always consistent), commits it, and then updates
//! the serving index. Snapshots are streamed from a redb read transaction (MVCC, so applies
//! continue while the snapshot is written) into a flat file:
//!
//! ```text
//! "DDISNAP1" | { key_len (u16 BE) | key | value_len (u32 BE) | value }*
//! ```

use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Instant;

use openraft::EntryPayload;
use openraft::RaftSnapshotBuilder;
use openraft::storage::RaftStateMachine;
use redb::Database;
use redb::Durability;
use redb::ReadableDatabase;
use redb::ReadableTable;
use redb::TableDefinition;
use serde::Deserialize;
use serde::Serialize;

use crate::index::ServingIndex;
use crate::model::serving_form_from_value;
use crate::raft_types::Entry;
use crate::raft_types::LogId;
use crate::raft_types::Request;
use crate::raft_types::Response;
use crate::raft_types::Snapshot;
use crate::raft_types::SnapshotFile;
use crate::raft_types::SnapshotMeta;
use crate::raft_types::StorageError;
use crate::raft_types::StorageIOError;
use crate::raft_types::StoredMembership;
use crate::raft_types::TypeConfig;

pub const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("records");
pub const JOURNAL: TableDefinition<u64, &[u8]> = TableDefinition::new("journal");
const SM_META: TableDefinition<&str, &[u8]> = TableDefinition::new("sm_meta");
const KEY_APPLIED: &str = "last_applied";
const KEY_MEMBERSHIP: &str = "membership";
const KEY_JOURNAL_NEXT: &str = "journal_next";

const SNAP_MAGIC: &[u8; 8] = b"DDISNAP1";

/// One entry of the change journal: enough to produce an IXFR delta (old RRset removed, new
/// RRset added).
#[derive(Serialize, Deserialize)]
pub struct JournalRecord {
    pub log_index: u64,
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    pub old: Option<serde_bytes::ByteBuf>,
    #[serde(with = "serde_bytes")]
    pub new: Vec<u8>,
}

/// Timings and sizes recorded by the storage layer itself (read by the benchmark driver).
#[derive(Default)]
pub struct NodeStats {
    pub snapshot_build_ns: AtomicU64,
    pub snapshot_bytes: AtomicU64,
    pub snapshots_built: AtomicU64,
    /// Set by the in-process network on the receiving side.
    pub snapshot_transfer_ns: AtomicU64,
    pub snapshot_install_ns: AtomicU64,
    pub index_rebuild_ns: AtomicU64,
    pub snapshots_installed: AtomicU64,
    pub applied_records: AtomicU64,
}

#[derive(Clone, Copy, Debug)]
pub struct SmOptions {
    pub cache_bytes: usize,
    pub durability: Durability,
    /// Keep at most this many journal records (older ones are trimmed on apply).
    pub journal_retain: u64,
}

struct SmState {
    last_applied: Option<LogId>,
    membership: StoredMembership,
    journal_next: u64,
}

struct SmInner {
    db: Database,
    index: Arc<ServingIndex>,
    snap_dir: PathBuf,
    stats: Arc<NodeStats>,
    opts: SmOptions,
    snapshot_seq: AtomicU64,
    current_snapshot: Mutex<Option<(SnapshotMeta, PathBuf)>>,
    state: Mutex<SmState>,
}

#[derive(Clone)]
pub struct StateMachineStore {
    inner: Arc<SmInner>,
}

fn sm_read(e: impl std::error::Error + 'static) -> StorageError {
    StorageIOError::read_state_machine(&e).into()
}

fn sm_write(e: impl std::error::Error + 'static) -> StorageError {
    StorageIOError::write_state_machine(&e).into()
}

fn snap_err(e: impl std::error::Error + 'static) -> StorageError {
    StorageIOError::write_snapshot(None, &e).into()
}

#[derive(Debug)]
struct Msg(String);
impl std::fmt::Display for Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Msg {}

impl StateMachineStore {
    pub fn open(
        path: &Path,
        snap_dir: &Path,
        index: Arc<ServingIndex>,
        stats: Arc<NodeStats>,
        opts: SmOptions,
    ) -> anyhow::Result<Self> {
        std::fs::create_dir_all(snap_dir)?;
        let db = Database::builder()
            .set_cache_size(opts.cache_bytes)
            .create(path)?;
        let w = db.begin_write()?;
        {
            w.open_table(RECORDS)?;
            w.open_table(JOURNAL)?;
            w.open_table(SM_META)?;
        }
        w.commit()?;
        let (last_applied, membership, journal_next) = {
            let r = db.begin_read()?;
            let m = r.open_table(SM_META)?;
            let la: Option<LogId> = match m.get(KEY_APPLIED)? {
                Some(v) => postcard::from_bytes(v.value())?,
                None => None,
            };
            let mem: StoredMembership = match m.get(KEY_MEMBERSHIP)? {
                Some(v) => postcard::from_bytes(v.value())?,
                None => StoredMembership::default(),
            };
            let jn: u64 = match m.get(KEY_JOURNAL_NEXT)? {
                Some(v) => postcard::from_bytes(v.value())?,
                None => 0,
            };
            (la, mem, jn)
        };
        Ok(Self {
            inner: Arc::new(SmInner {
                db,
                index,
                snap_dir: snap_dir.to_path_buf(),
                stats,
                opts,
                snapshot_seq: AtomicU64::new(0),
                current_snapshot: Mutex::new(None),
                state: Mutex::new(SmState {
                    last_applied,
                    membership,
                    journal_next,
                }),
            }),
        })
    }

    /// Enumerate the last `n` journal records (newest last). Returns (records read, total
    /// encoded bytes). Decodes every record, as an IXFR responder would have to.
    pub fn read_journal_tail(&self, n: u64) -> anyhow::Result<(u64, u64)> {
        let r = self.inner.db.begin_read()?;
        let t = r.open_table(JOURNAL)?;
        let last = match t.last()? {
            Some((k, _)) => k.value(),
            None => return Ok((0, 0)),
        };
        let first = last.saturating_sub(n.saturating_sub(1));
        let mut count = 0u64;
        let mut bytes = 0u64;
        let mut keys = 0u64;
        for item in t.range(first..=last)? {
            let (_, v) = item?;
            let rec: JournalRecord = postcard::from_bytes(v.value())?;
            count += 1;
            bytes += v.value().len() as u64;
            keys += rec.key.len() as u64
                + rec.new.len() as u64
                + rec.old.as_ref().map_or(0, |o| o.len() as u64);
        }
        std::hint::black_box(keys);
        Ok((count, bytes))
    }

    pub fn journal_len(&self) -> anyhow::Result<u64> {
        use redb::ReadableTableMetadata;
        let r = self.inner.db.begin_read()?;
        let t = r.open_table(JOURNAL)?;
        Ok(t.len()?)
    }

    /// redb statistics of the state machine database: (allocated bytes, stored bytes,
    /// metadata bytes, fragmented bytes).
    pub fn redb_stats(&self) -> anyhow::Result<(u64, u64, u64, u64)> {
        let w = self.inner.db.begin_write()?;
        let s = w.stats()?;
        let out = (
            s.allocated_pages() * s.page_size() as u64,
            s.stored_bytes(),
            s.metadata_bytes(),
            s.fragmented_bytes(),
        );
        w.abort()?;
        Ok(out)
    }

    fn apply_blocking(&self, entries: Vec<Entry>) -> Result<Vec<Response>, StorageError> {
        let inner = &self.inner;
        let mut st = inner.state.lock().expect("sm state poisoned");
        let mut w = inner.db.begin_write().map_err(sm_write)?;
        w.set_durability(inner.opts.durability).map_err(sm_write)?;
        let mut index_updates: Vec<(Box<[u8]>, Arc<[u8]>)> = Vec::new();
        let mut responses = Vec::with_capacity(entries.len());
        let mut applied_records = 0u64;
        {
            let mut rec = w.open_table(RECORDS).map_err(sm_write)?;
            let mut jr = w.open_table(JOURNAL).map_err(sm_write)?;
            let mut meta = w.open_table(SM_META).map_err(sm_write)?;
            for entry in entries {
                st.last_applied = Some(entry.log_id);
                match entry.payload {
                    EntryPayload::Blank => responses.push(Response::default()),
                    EntryPayload::Normal(Request::Upsert(batch)) => {
                        // Sorting the batch turns random B-tree inserts into an ordered merge.
                        let mut pairs: Vec<(&[u8], &[u8])> = batch.iter().collect();
                        pairs.sort_unstable_by(|a, b| a.0.cmp(b.0));
                        index_updates.reserve(pairs.len());
                        for (k, v) in pairs {
                            let old = rec
                                .insert(k, v)
                                .map_err(sm_write)?
                                .map(|g| g.value().to_vec());
                            if batch.journal {
                                let jrec = JournalRecord {
                                    log_index: entry.log_id.index,
                                    key: k.to_vec(),
                                    old: old.map(serde_bytes::ByteBuf::from),
                                    new: v.to_vec(),
                                };
                                let enc = postcard::to_stdvec(&jrec).map_err(sm_write)?;
                                jr.insert(st.journal_next, enc.as_slice())
                                    .map_err(sm_write)?;
                                st.journal_next += 1;
                            }
                            let serving = serving_form_from_value(v)
                                .map_err(|e| sm_write(Msg(e.to_string())))?;
                            index_updates.push((k.into(), Arc::from(serving)));
                        }
                        applied_records += batch.count as u64;
                        responses.push(Response {
                            applied: batch.count,
                        });
                    }
                    EntryPayload::Membership(m) => {
                        st.membership = StoredMembership::new(Some(entry.log_id), m);
                        responses.push(Response::default());
                    }
                }
            }
            // Journal retention: trim in steps of 10 % to keep the per-apply cost low.
            let retain = inner.opts.journal_retain.max(1);
            if st.journal_next > retain + retain / 10 {
                let cutoff = st.journal_next - retain;
                jr.retain_in(..cutoff, |_, _| false).map_err(sm_write)?;
            }
            let la = postcard::to_stdvec(&st.last_applied).map_err(sm_write)?;
            meta.insert(KEY_APPLIED, la.as_slice()).map_err(sm_write)?;
            let mem = postcard::to_stdvec(&st.membership).map_err(sm_write)?;
            meta.insert(KEY_MEMBERSHIP, mem.as_slice())
                .map_err(sm_write)?;
            let jn = postcard::to_stdvec(&st.journal_next).map_err(sm_write)?;
            meta.insert(KEY_JOURNAL_NEXT, jn.as_slice())
                .map_err(sm_write)?;
        }
        w.commit().map_err(sm_write)?;
        drop(st);
        if !index_updates.is_empty() {
            inner.index.upsert_many(index_updates);
        }
        inner
            .stats
            .applied_records
            .fetch_add(applied_records, Ordering::Relaxed);
        Ok(responses)
    }

    fn build_snapshot_blocking(&self) -> Result<Snapshot, StorageError> {
        let inner = &self.inner;
        let t0 = Instant::now();
        let r = inner.db.begin_read().map_err(sm_read)?;
        let (last_applied, membership) = {
            let m = r.open_table(SM_META).map_err(sm_read)?;
            let la: Option<LogId> = match m.get(KEY_APPLIED).map_err(sm_read)? {
                Some(v) => postcard::from_bytes(v.value()).map_err(sm_read)?,
                None => None,
            };
            let mem: StoredMembership = match m.get(KEY_MEMBERSHIP).map_err(sm_read)? {
                Some(v) => postcard::from_bytes(v.value()).map_err(sm_read)?,
                None => StoredMembership::default(),
            };
            (la, mem)
        };
        let seq = inner.snapshot_seq.fetch_add(1, Ordering::Relaxed);
        let snapshot_id = match last_applied {
            Some(l) => format!("{}-{}-{}", l.leader_id.term, l.index, seq),
            None => format!("none-{seq}"),
        };
        let path = inner.snap_dir.join(format!("snap-{snapshot_id}.bin"));
        let tmp = inner.snap_dir.join(format!("snap-{snapshot_id}.tmp"));
        let mut bytes = 0u64;
        {
            let f = File::create(&tmp).map_err(snap_err)?;
            let mut out = BufWriter::with_capacity(1 << 20, f);
            out.write_all(SNAP_MAGIC).map_err(snap_err)?;
            bytes += SNAP_MAGIC.len() as u64;
            let t = r.open_table(RECORDS).map_err(sm_read)?;
            for item in t.iter().map_err(sm_read)? {
                let (k, v) = item.map_err(sm_read)?;
                let (k, v) = (k.value(), v.value());
                out.write_all(&(k.len() as u16).to_be_bytes())
                    .map_err(snap_err)?;
                out.write_all(k).map_err(snap_err)?;
                out.write_all(&(v.len() as u32).to_be_bytes())
                    .map_err(snap_err)?;
                out.write_all(v).map_err(snap_err)?;
                bytes += 6 + k.len() as u64 + v.len() as u64;
            }
            let f = out.into_inner().map_err(|e| snap_err(Msg(e.to_string())))?;
            f.sync_all().map_err(snap_err)?;
        }
        std::fs::rename(&tmp, &path).map_err(snap_err)?;
        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership: membership,
            snapshot_id,
        };
        let prev = inner
            .current_snapshot
            .lock()
            .expect("snapshot lock")
            .replace((meta.clone(), path.clone()));
        if let Some((_, p)) = prev
            && p != path
        {
            let _ = std::fs::remove_file(p);
        }
        inner
            .stats
            .snapshot_build_ns
            .store(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        inner.stats.snapshot_bytes.store(bytes, Ordering::Relaxed);
        inner.stats.snapshots_built.fetch_add(1, Ordering::Relaxed);
        Ok(Snapshot {
            meta,
            snapshot: Box::new(SnapshotFile { path }),
        })
    }

    fn install_snapshot_blocking(
        &self,
        meta: &SnapshotMeta,
        file: &Path,
    ) -> Result<(), StorageError> {
        let inner = &self.inner;
        let t0 = Instant::now();
        let mut st = inner.state.lock().expect("sm state poisoned");
        // 1. Replace the records table with the snapshot content in one write transaction.
        let mut w = inner.db.begin_write().map_err(sm_write)?;
        w.set_durability(Durability::Immediate).map_err(sm_write)?;
        w.delete_table(RECORDS).map_err(sm_write)?;
        w.delete_table(JOURNAL).map_err(sm_write)?;
        {
            let mut rec = w.open_table(RECORDS).map_err(sm_write)?;
            w.open_table(JOURNAL).map_err(sm_write)?;
            let mut reader = SnapshotReader::open(file).map_err(snap_err)?;
            while let Some((k, v)) = reader.next_pair().map_err(snap_err)? {
                rec.insert(k, v).map_err(sm_write)?;
            }
            let mut m = w.open_table(SM_META).map_err(sm_write)?;
            let la = postcard::to_stdvec(&meta.last_log_id).map_err(sm_write)?;
            m.insert(KEY_APPLIED, la.as_slice()).map_err(sm_write)?;
            let mem = postcard::to_stdvec(&meta.last_membership).map_err(sm_write)?;
            m.insert(KEY_MEMBERSHIP, mem.as_slice()).map_err(sm_write)?;
            let jn = postcard::to_stdvec(&0u64).map_err(sm_write)?;
            m.insert(KEY_JOURNAL_NEXT, jn.as_slice())
                .map_err(sm_write)?;
        }
        w.commit().map_err(sm_write)?;
        st.last_applied = meta.last_log_id;
        st.membership = meta.last_membership.clone();
        st.journal_next = 0;
        drop(st);

        // 2. Rebuild the serving index from the snapshot file.
        let t1 = Instant::now();
        inner.index.clear();
        let mut reader = SnapshotReader::open(file).map_err(snap_err)?;
        let mut chunk: Vec<(Box<[u8]>, Arc<[u8]>)> = Vec::with_capacity(100_000);
        while let Some((k, v)) = reader.next_pair().map_err(snap_err)? {
            let serving = serving_form_from_value(v).map_err(|e| sm_write(Msg(e.to_string())))?;
            chunk.push((k.into(), Arc::from(serving)));
            if chunk.len() == 100_000 {
                inner.index.upsert_many(std::mem::take(&mut chunk));
                chunk.reserve(100_000);
            }
        }
        if !chunk.is_empty() {
            inner.index.upsert_many(chunk);
        }
        let rebuild = t1.elapsed();

        // 3. Keep the received file as the current snapshot.
        let path = inner
            .snap_dir
            .join(format!("snap-{}.bin", meta.snapshot_id));
        if path != file {
            std::fs::rename(file, &path).map_err(snap_err)?;
        }
        let prev = inner
            .current_snapshot
            .lock()
            .expect("snapshot lock")
            .replace((meta.clone(), path.clone()));
        if let Some((_, p)) = prev
            && p != path
        {
            let _ = std::fs::remove_file(p);
        }
        inner
            .stats
            .index_rebuild_ns
            .store(rebuild.as_nanos() as u64, Ordering::Relaxed);
        inner
            .stats
            .snapshot_install_ns
            .store(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        inner
            .stats
            .snapshots_installed
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Path of a fresh file in this node's snapshot directory for receiving a snapshot.
    pub fn new_receive_path(&self) -> PathBuf {
        let seq = self.inner.snapshot_seq.fetch_add(1, Ordering::Relaxed);
        self.inner.snap_dir.join(format!("recv-{seq}.part"))
    }

    pub fn stats(&self) -> &Arc<NodeStats> {
        &self.inner.stats
    }
}

/// Sequential reader of the snapshot file format.
pub struct SnapshotReader {
    r: BufReader<File>,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl SnapshotReader {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let mut r = BufReader::with_capacity(1 << 20, File::open(path)?);
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if &magic != SNAP_MAGIC {
            return Err(std::io::Error::other("bad snapshot magic"));
        }
        Ok(Self {
            r,
            key: Vec::new(),
            value: Vec::new(),
        })
    }

    pub fn next_pair(&mut self) -> std::io::Result<Option<(&[u8], &[u8])>> {
        let mut kl = [0u8; 2];
        match self.r.read_exact(&mut kl) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let kl = u16::from_be_bytes(kl) as usize;
        self.key.resize(kl, 0);
        self.r.read_exact(&mut self.key)?;
        let mut vl = [0u8; 4];
        self.r.read_exact(&mut vl)?;
        let vl = u32::from_be_bytes(vl) as usize;
        self.value.resize(vl, 0);
        self.r.read_exact(&mut self.value)?;
        Ok(Some((&self.key, &self.value)))
    }
}

pub struct SnapshotBuilder {
    sm: StateMachineStore,
}

impl RaftSnapshotBuilder<TypeConfig> for SnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot, StorageError> {
        let sm = self.sm.clone();
        tokio::task::spawn_blocking(move || sm.build_snapshot_blocking())
            .await
            .map_err(|e| snap_err(Msg(e.to_string())))?
    }
}

impl RaftStateMachine<TypeConfig> for StateMachineStore {
    type SnapshotBuilder = SnapshotBuilder;

    async fn applied_state(&mut self) -> Result<(Option<LogId>, StoredMembership), StorageError> {
        let st = self.inner.state.lock().expect("sm state poisoned");
        Ok((st.last_applied, st.membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Response>, StorageError>
    where
        I: IntoIterator<Item = Entry> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<Entry> = entries.into_iter().collect();
        tokio::task::block_in_place(|| self.apply_blocking(entries))
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        SnapshotBuilder { sm: self.clone() }
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Box<SnapshotFile>, StorageError> {
        let path = self.new_receive_path();
        File::create(&path).map_err(snap_err)?;
        Ok(Box::new(SnapshotFile { path }))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta,
        snapshot: Box<SnapshotFile>,
    ) -> Result<(), StorageError> {
        let meta = meta.clone();
        tokio::task::block_in_place(|| self.install_snapshot_blocking(&meta, &snapshot.path))
    }

    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot>, StorageError> {
        let cur = self
            .inner
            .current_snapshot
            .lock()
            .expect("snapshot lock")
            .clone();
        Ok(cur.map(|(meta, path)| Snapshot {
            meta,
            snapshot: Box::new(SnapshotFile { path }),
        }))
    }
}
