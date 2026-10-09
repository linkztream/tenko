//! M2: crash and restart (ADR 0002; threshold: no lost commit or partial batch, the audit
//! chain verifies).
//!
//! The benchmark binary starts itself in a hidden child mode (`m2-child`) that opens a store
//! in a data directory and writes batches under `bulk` load (two writers, 1,000 rows per
//! batch) or `steady` load (24 concurrent writers, 1 to 4 rows per batch). Every batch writes
//! `m` rows, one manifest row that states `m`, bumps a counter and carries one audit draft, so
//! the counter, the number of manifests, the audit head and the revision must all agree. After
//! `propose` returns, the child appends `batch revision rows` to `acks.log`.
//!
//! The parent kills the child at a random point (`Child::kill`, which is `TerminateProcess` on
//! Windows), reopens the store with `verify_full_audit_chain: true`, times the open, and
//! checks, over the whole store and not only the last run:
//!
//! - every acknowledged batch exists, at the acknowledged revision, with all its rows;
//! - every manifest has exactly `m` contiguous rows at its own revision with the right
//!   content, and there are no rows without a manifest (no partial batch);
//! - the manifests, the counter, the audit head and the revision all agree;
//! - `verify_chain` over `sys.audit` ends at the status head, and every audit record sits at
//!   its own revision;
//! - the journal is contiguous, from `journal_oldest` to the revision, with `journal_len` rows.
//!
//! Then the parent shuts the store down cleanly and the next child starts. A process kill does
//! not lose data that was already handed to the operating system, so this does not exercise
//! the loss of unsynced writes; that needs the VM power cut of Slice 3.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use tenko_core::{
    CounterKey, TableName,
    audit::{AuditAction, AuditDraft, ChainVerifier},
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, Store as _, Versioned, WriteBatch,
    raft::{RaftStore, RaftStoreConfig, SmDurability, SnapshotPolicy},
    tables,
};
use tokio::task::JoinSet;

use crate::{
    Ctx,
    common::{
        Latency, MIB, Machine, Rng, RunClock, RunMeta, ScratchDir, count_f64, machine, new_hist,
        purged_index, record_ns, summarize,
    },
    data::new_batch,
};

const ROWS: TableName = TableName::from_static("ipam.m2_rows");
const MANIFEST: TableName = TableName::from_static("ipam.m2_manifest");
const BATCHES: CounterKey = CounterKey::new("ipam.m2_batches");
const WRITE: AuditAction = AuditAction::from_static("ipam.m2.write");

const ROW_VALUE_LEN: usize = 96;
const BULK_ROWS: u32 = 1_000;
const BULK_WRITERS: usize = 2;
const BULK_CAP_BATCHES: u64 = 60;
const STEADY_WRITERS: usize = 24;
const JOURNAL_RETENTION: usize = 20_000;
const PAGE: usize = 20_000;
const MAX_VIOLATION_SAMPLES: usize = 20;
/// A child that is never killed ends itself after this long.
const CHILD_LIFETIME: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Bulk,
    Steady,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dur {
    Deferred,
    Immediate,
}

impl Dur {
    fn label(self) -> &'static str {
        match self {
            Dur::Deferred => "deferred",
            Dur::Immediate => "immediate",
        }
    }
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Bulk => "bulk",
            Mode::Steady => "steady",
        }
    }
}

#[derive(Debug, Clone, clap::Args)]
pub struct Args {
    /// Kills under bulk load with deferred durability.
    #[arg(long, default_value_t = 50)]
    pub bulk_kills: usize,
    /// Kills under steady load with deferred durability.
    #[arg(long, default_value_t = 50)]
    pub steady_kills: usize,
    /// Kills under bulk load with immediate durability.
    #[arg(long, default_value_t = 10)]
    pub immediate_bulk_kills: usize,
    /// Kills under steady load with immediate durability.
    #[arg(long, default_value_t = 10)]
    pub immediate_steady_kills: usize,
    /// Kills in a separate sequence under bulk load with deferred durability in which every
    /// second kill lands while the child is still opening the store (crash during recovery).
    #[arg(long, default_value_t = 0)]
    pub recovery_kills: usize,
    /// Name of the result file in `raw/` (without extension).
    #[arg(long, default_value = "m2")]
    pub out_name: String,
    /// Seed of the kill times.
    #[arg(long, default_value_t = 0x2026_1009)]
    pub seed: u64,
}

/// The hidden child mode.
#[derive(Debug, Clone, clap::Args)]
pub struct ChildArgs {
    #[arg(long)]
    pub dir: PathBuf,
    #[arg(long, value_enum)]
    pub mode: Mode,
    #[arg(long, value_enum)]
    pub durability: Dur,
    #[arg(long)]
    pub run: u64,
    #[arg(long)]
    pub acks: PathBuf,
    #[arg(long)]
    pub ready: PathBuf,
}

// ---------------------------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------------------------

fn row_key(batch: u64, index: u32) -> Bytes {
    let mut key = Vec::with_capacity(12);
    key.extend_from_slice(&batch.to_be_bytes());
    key.extend_from_slice(&index.to_be_bytes());
    Bytes::from(key)
}

fn row_value(batch: u64, index: u32, rows: u32) -> Bytes {
    let mut value = vec![0_u8; ROW_VALUE_LEN];
    value[..8].copy_from_slice(&batch.to_be_bytes());
    value[8..12].copy_from_slice(&index.to_be_bytes());
    value[12..16].copy_from_slice(&rows.to_be_bytes());
    let mut state = crate::common::mix(batch ^ u64::from(index));
    for chunk in value[16..].chunks_mut(8) {
        state = crate::common::mix(state);
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    Bytes::from(value)
}

fn manifest_key(batch: u64) -> Bytes {
    Bytes::copy_from_slice(&batch.to_be_bytes())
}

fn manifest_value(batch: u64, rows: u32) -> Bytes {
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&rows.to_be_bytes());
    value.extend_from_slice(&batch.to_be_bytes());
    Bytes::from(value)
}

fn batch_of(batch: u64, rows: u32) -> WriteBatch {
    let mut write = new_batch();
    for index in 0..rows {
        write.put(ROWS, row_key(batch, index), row_value(batch, index, rows));
    }
    write.put(MANIFEST, manifest_key(batch), manifest_value(batch, rows));
    write.bump(BATCHES);
    write.audit(AuditDraft::success(WRITE, Vec::new()));
    write
}

fn be_u64(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..at + 8)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_be_bytes)
}

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_be_bytes)
}

// ---------------------------------------------------------------------------------------------
// Store configuration (shared by the child and the parent)
// ---------------------------------------------------------------------------------------------

fn store_config(dir: &Path, durability: Dur, verify_full_audit_chain: bool) -> RaftStoreConfig {
    let mut config = RaftStoreConfig::new(dir);
    config.fsync_probe_samples = 0;
    config.verify_full_audit_chain = verify_full_audit_chain;
    config.journal_retention = JOURNAL_RETENTION;
    config.durability = match durability {
        Dur::Deferred => SmDurability::Deferred {
            checkpoint_interval: Duration::from_secs(1),
        },
        Dur::Immediate => SmDurability::Immediate,
    };
    // Small enough that a snapshot and a purge follow every second of writing.
    config.snapshot = SnapshotPolicy {
        every_entries: 60,
        every_log_bytes: 12 * MIB,
        keep_entries: 10,
    };
    config
}

// ---------------------------------------------------------------------------------------------
// The child
// ---------------------------------------------------------------------------------------------

pub async fn child(args: ChildArgs) -> Result<()> {
    let store = RaftStore::open(store_config(&args.dir, args.durability, false)).await?;
    fs::write(&args.ready, b"ready")?;
    let acks = Arc::new(Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&args.acks)?,
    ));
    let next = Arc::new(AtomicU64::new(0));
    let until = Instant::now() + CHILD_LIFETIME;
    let mut tasks = JoinSet::new();
    match args.mode {
        Mode::Bulk => {
            for _ in 0..BULK_WRITERS {
                tasks.spawn(writer(
                    store.clone(),
                    Arc::clone(&acks),
                    Arc::clone(&next),
                    args.run,
                    Mode::Bulk,
                    0,
                    until,
                ));
            }
        }
        Mode::Steady => {
            for writer_no in 0..STEADY_WRITERS {
                tasks.spawn(writer(
                    store.clone(),
                    Arc::clone(&acks),
                    Arc::clone(&next),
                    args.run,
                    Mode::Steady,
                    writer_no as u64,
                    until,
                ));
            }
        }
    }
    while let Some(done) = tasks.join_next().await {
        done??;
    }
    // Bulk writers stop at their cap; idle until the parent kills this process.
    while Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

async fn writer(
    store: RaftStore,
    acks: Arc<Mutex<File>>,
    next: Arc<AtomicU64>,
    run: u64,
    mode: Mode,
    writer_no: u64,
    until: Instant,
) -> Result<()> {
    let mut rng = Rng::new(run.wrapping_mul(0x9E37_79B9) ^ writer_no);
    while Instant::now() < until {
        let sequence = next.fetch_add(1, Ordering::Relaxed);
        if mode == Mode::Bulk && sequence >= BULK_CAP_BATCHES {
            return Ok(());
        }
        let batch = (run << 32) | sequence;
        let rows = match mode {
            Mode::Bulk => BULK_ROWS,
            Mode::Steady => u32::try_from(rng.between(1, 4))?,
        };
        let committed = store.propose(batch_of(batch, rows)).await?;
        let line = format!("{batch} {} {rows}\n", committed.revision.get());
        acks.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write_all(line.as_bytes())?;
        let pause = match mode {
            Mode::Bulk => 5,
            Mode::Steady => rng.between(0, 3),
        };
        tokio::time::sleep(Duration::from_millis(pause)).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Acknowledgements
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Ack {
    batch: u64,
    revision: u64,
    rows: u32,
}

#[derive(Debug)]
struct AckLog {
    path: PathBuf,
    offset: u64,
    acks: Vec<Ack>,
    max_revision: u64,
}

impl AckLog {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            acks: Vec::new(),
            max_revision: 0,
        }
    }

    /// Reads the complete lines appended since the last call and cuts off a partial last line
    /// (the child was killed while writing it).
    fn refresh(&mut self) -> Result<usize> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        file.seek(SeekFrom::Start(self.offset))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        drop(file);
        let complete = buffer
            .iter()
            .rposition(|&byte| byte == b'\n')
            .map_or(0, |position| position + 1);
        let before = self.acks.len();
        for line in buffer[..complete].split(|&byte| byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let text = std::str::from_utf8(line).context("acks.log is not text")?;
            let mut fields = text.split(' ');
            let mut number = || -> Result<u64> {
                Ok(fields
                    .next()
                    .context("short line in acks.log")?
                    .parse::<u64>()?)
            };
            let ack = Ack {
                batch: number()?,
                revision: number()?,
                rows: u32::try_from(number()?)?,
            };
            self.max_revision = self.max_revision.max(ack.revision);
            self.acks.push(ack);
        }
        if complete < buffer.len() {
            OpenOptions::new()
                .write(true)
                .open(&self.path)?
                .set_len(self.offset + complete as u64)?;
        }
        self.offset += complete as u64;
        Ok(self.acks.len() - before)
    }
}

// ---------------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Violations {
    total: usize,
    samples: Vec<String>,
}

impl Violations {
    fn add(&mut self, message: impl Into<String>) {
        self.total += 1;
        if self.samples.len() < MAX_VIOLATION_SAMPLES {
            self.samples.push(message.into());
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Manifest {
    id: u64,
    rows: u32,
    revision: u64,
}

fn for_each(
    view: &dyn ReadView,
    table: &TableName,
    mut visit: impl FnMut(&Bytes, &Versioned),
) -> Result<()> {
    let mut range = KeyRange::all();
    loop {
        let page = view.scan(table, range.clone(), PAGE, false)?;
        let Some((last, _)) = page.last() else {
            return Ok(());
        };
        range = KeyRange::all().after(last.clone());
        let full = page.len() == PAGE;
        for (key, versioned) in &page {
            visit(key, versioned);
        }
        if !full {
            return Ok(());
        }
    }
}

/// Merge-joins the row table with the sorted manifests.
struct Join<'a> {
    manifests: &'a [Manifest],
    cursor: usize,
    current: Option<usize>,
    count: u32,
    orphan: Option<u64>,
    rows: u64,
    violations: &'a mut Violations,
}

impl Join<'_> {
    fn finish_current(&mut self) {
        if let Some(index) = self.current.take() {
            let manifest = self.manifests[index];
            if self.count != manifest.rows {
                self.violations.add(format!(
                    "batch {:#x} (revision {}) has {} of {} rows: partial batch",
                    manifest.id, manifest.revision, self.count, manifest.rows
                ));
            }
        }
    }

    fn row(&mut self, key: &Bytes, versioned: &Versioned) {
        self.rows += 1;
        let (Some(id), Some(index)) = (be_u64(key, 0), be_u32(key, 8)) else {
            self.violations.add("a row has a malformed key");
            return;
        };
        if let Some(current) = self.current
            && self.manifests[current].id != id
        {
            self.finish_current();
        }
        if self.current.is_none() {
            if self.orphan == Some(id) {
                return;
            }
            while self.cursor < self.manifests.len() && self.manifests[self.cursor].id < id {
                let skipped = self.manifests[self.cursor];
                self.violations.add(format!(
                    "batch {:#x} (revision {}) has a manifest but no rows",
                    skipped.id, skipped.revision
                ));
                self.cursor += 1;
            }
            if self.cursor < self.manifests.len() && self.manifests[self.cursor].id == id {
                self.current = Some(self.cursor);
                self.cursor += 1;
                self.count = 0;
            } else {
                self.violations.add(format!(
                    "rows of batch {id:#x} have no manifest: partial batch"
                ));
                self.orphan = Some(id);
                return;
            }
        }
        let Some(current) = self.current else {
            return;
        };
        let manifest = self.manifests[current];
        if index != self.count {
            self.violations.add(format!(
                "batch {id:#x}: row {index} where row {} was expected",
                self.count
            ));
        }
        if versioned.revision.get() != manifest.revision {
            self.violations.add(format!(
                "batch {id:#x}: row {index} is at revision {}, its manifest at {}",
                versioned.revision.get(),
                manifest.revision
            ));
        }
        if versioned.value != row_value(id, index, manifest.rows) {
            self.violations
                .add(format!("batch {id:#x}: row {index} has the wrong content"));
        }
        self.count += 1;
    }

    fn finish(mut self) -> u64 {
        self.finish_current();
        for skipped in &self.manifests[self.cursor..] {
            self.violations.add(format!(
                "batch {:#x} (revision {}) has a manifest but no rows",
                skipped.id, skipped.revision
            ));
        }
        self.rows
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Checked {
    pub revision: u64,
    pub manifests: u64,
    pub rows: u64,
    pub audit_records: u64,
    pub journal_len: u64,
    pub unacked_committed: u64,
    pub verify_ms: f64,
}

#[allow(clippy::too_many_lines, reason = "one list of invariants")]
async fn verify(store: &RaftStore, acks: &AckLog, violations: &mut Violations) -> Result<Checked> {
    let started = Instant::now();
    let view = store.read(ReadConsistency::Local).await?;
    let status = store.status();
    let revision = view.revision().get();
    if status.revision.get() != revision {
        violations.add(format!(
            "status revision {} differs from the read view revision {revision}",
            status.revision
        ));
    }

    // Manifests, in batch order.
    let mut manifests = Vec::new();
    for_each(view.as_ref(), &MANIFEST, |key, versioned| {
        match (be_u64(key, 0), be_u32(&versioned.value, 0)) {
            (Some(id), Some(rows)) => manifests.push(Manifest {
                id,
                rows,
                revision: versioned.revision.get(),
            }),
            _ => violations.add("a manifest is malformed"),
        }
    })?;
    if !manifests.windows(2).all(|pair| pair[0].id < pair[1].id) {
        violations.add("manifests are not in strictly increasing batch order");
    }
    for manifest in &manifests {
        if manifest.rows == 0 || manifest.revision == 0 || manifest.revision > revision {
            violations.add(format!("manifest {:#x} is inconsistent", manifest.id));
        }
    }

    // Rows against manifests.
    let mut join = Join {
        manifests: &manifests,
        cursor: 0,
        current: None,
        count: 0,
        orphan: None,
        rows: 0,
        violations,
    };
    for_each(view.as_ref(), &ROWS, |key, versioned| {
        join.row(key, versioned);
    })?;
    let rows = join.finish();

    // Acknowledged batches.
    for ack in &acks.acks {
        match manifests.binary_search_by_key(&ack.batch, |manifest| manifest.id) {
            Ok(position) => {
                let manifest = manifests[position];
                if manifest.revision != ack.revision {
                    violations.add(format!(
                        "batch {:#x} was acknowledged at revision {} but is at revision {}",
                        ack.batch, ack.revision, manifest.revision
                    ));
                }
                if manifest.rows != ack.rows {
                    violations.add(format!(
                        "batch {:#x} was acknowledged with {} rows but has {}",
                        ack.batch, ack.rows, manifest.rows
                    ));
                }
            }
            Err(_) => violations.add(format!(
                "acknowledged batch {:#x} (revision {}) is missing: lost commit",
                ack.batch, ack.revision
            )),
        }
    }
    if acks.max_revision > revision {
        violations.add(format!(
            "revision {revision} is behind the highest acknowledged revision {}",
            acks.max_revision
        ));
    }

    // The invariants that tie the tables together.
    let manifest_count = manifests.len() as u64;
    if manifest_count != revision {
        violations.add(format!(
            "{manifest_count} manifests for revision {revision}"
        ));
    }
    let counter = view.counter(&BATCHES)?;
    if counter != revision {
        violations.add(format!(
            "counter {counter} differs from revision {revision}"
        ));
    }
    if status.audit_head.0 != revision {
        violations.add(format!(
            "audit head {} differs from revision {revision}",
            status.audit_head.0
        ));
    }

    // The audit chain.
    let mut verifier = ChainVerifier::new();
    let mut chain_ok = true;
    let mut audit_records = 0_u64;
    for_each(view.as_ref(), tables::AUDIT.name(), |_, versioned| {
        audit_records += 1;
        match tables::AUDIT.decode(&versioned.value) {
            Ok(record) => {
                if record.revision.get() != record.seq.0 {
                    violations.add(format!(
                        "audit record {} sits at revision {}",
                        record.seq.0,
                        record.revision.get()
                    ));
                }
                if chain_ok && let Err(error) = verifier.push(&record) {
                    chain_ok = false;
                    violations.add(format!("audit chain broken: {error}"));
                }
            }
            Err(error) => violations.add(format!("an audit record does not decode: {error}")),
        }
    })?;
    if verifier.head().seq != status.audit_head {
        violations.add(format!(
            "the chain verifies up to {} but the status head is {}",
            verifier.head().seq.0,
            status.audit_head.0
        ));
    }

    // The journal.
    let (mut first, mut previous, mut journal_len) = (None, None::<u64>, 0_u64);
    for_each(view.as_ref(), tables::JOURNAL.name(), |key, _| {
        journal_len += 1;
        match tables::JOURNAL.decode_key(key) {
            Ok(entry) => {
                let entry = entry.get();
                if let Some(previous) = previous
                    && entry != previous + 1
                {
                    violations.add(format!("journal jumps from {previous} to {entry}"));
                }
                first.get_or_insert(entry);
                previous = Some(entry);
            }
            Err(error) => violations.add(format!("a journal key does not decode: {error}")),
        }
    })?;
    if journal_len != status.journal_len {
        violations.add(format!(
            "the journal holds {journal_len} change sets, the status says {}",
            status.journal_len
        ));
    }
    if revision > 0 {
        if previous != Some(revision) {
            violations.add(format!(
                "the journal ends at {previous:?}, not at revision {revision}"
            ));
        }
        if first != status.journal_oldest.map(tenko_core::Revision::get) {
            violations.add(format!(
                "the journal starts at {first:?}, the status says {:?}",
                status.journal_oldest
            ));
        }
    }

    Ok(Checked {
        revision,
        manifests: manifest_count,
        rows,
        audit_records,
        journal_len,
        unacked_committed: revision.saturating_sub(acks.acks.len() as u64),
        verify_ms: started.elapsed().as_secs_f64() * 1_000.0,
    })
}

// ---------------------------------------------------------------------------------------------
// The parent
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iteration {
    pub run: u64,
    pub killed_before_ready: bool,
    pub killed_after_ms: u64,
    pub open_ms: f64,
    pub open_attempts: u32,
    pub acked_this_run: u64,
    pub acked_total: u64,
    pub purged_index: u64,
    pub checked: Checked,
    pub violations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceResult {
    pub name: String,
    pub mode: Mode,
    pub durability: String,
    pub kills: usize,
    pub kills_before_ready: usize,
    pub violations: usize,
    pub violation_samples: Vec<String>,
    pub restart: Latency,
    pub final_revision: u64,
    pub acked_total: u64,
    pub rows_total: u64,
    pub audit_records: u64,
    pub unacked_committed_total: u64,
    pub restarts_with_purged_log: usize,
    pub max_purged_index: u64,
    pub elapsed_secs: f64,
    pub iterations: Vec<Iteration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub bulk: String,
    pub steady: String,
    pub kill_window: String,
    pub snapshot_policy: String,
    pub journal_retention: usize,
    pub parent_open: String,
    pub invariants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub meta: RunMeta,
    pub machine: Machine,
    pub config: Config,
    pub sequences: Vec<SequenceResult>,
    pub kills: usize,
    pub violations: usize,
    pub restart_all: Latency,
    pub pass: bool,
}

struct Plan {
    name: &'static str,
    mode: Mode,
    durability: Dur,
    kills: usize,
    /// Every second kill lands while the child is still opening (recovering) the store.
    alternate: bool,
}

#[allow(clippy::too_many_lines, reason = "one list of plans and one report")]
pub async fn run(args: Args, ctx: &Ctx) -> Result<()> {
    let clock = RunClock::start(&ctx.data_root);
    let plans = [
        Plan {
            name: "bulk-deferred",
            mode: Mode::Bulk,
            durability: Dur::Deferred,
            kills: args.bulk_kills,
            alternate: false,
        },
        Plan {
            name: "steady-deferred",
            mode: Mode::Steady,
            durability: Dur::Deferred,
            kills: args.steady_kills,
            alternate: false,
        },
        Plan {
            name: "bulk-immediate",
            mode: Mode::Bulk,
            durability: Dur::Immediate,
            kills: args.immediate_bulk_kills,
            alternate: false,
        },
        Plan {
            name: "steady-immediate",
            mode: Mode::Steady,
            durability: Dur::Immediate,
            kills: args.immediate_steady_kills,
            alternate: false,
        },
        Plan {
            name: "recovery-bulk-deferred",
            mode: Mode::Bulk,
            durability: Dur::Deferred,
            kills: args.recovery_kills,
            alternate: true,
        },
    ];
    let mut report = Report {
        meta: RunMeta::default(),
        machine: machine(),
        config: Config {
            bulk: format!(
                "{BULK_WRITERS} writers, {BULK_ROWS} rows + manifest per batch, 5 ms pause, \
                 at most {BULK_CAP_BATCHES} batches per run"
            ),
            steady: format!(
                "{STEADY_WRITERS} concurrent writers, 1 to 4 rows + manifest per batch, \
                 0 to 3 ms pause"
            ),
            kill_window: "90 percent of kills 300 to 1500 ms after the child reported the store \
                          open; 10 percent 20 to 400 ms after the process started, whatever it \
                          was doing (often opening the store)"
                .to_owned(),
            snapshot_policy: "every 60 entries or 12 MiB of log, 10 entries kept".to_owned(),
            journal_retention: JOURNAL_RETENTION,
            parent_open: "RaftStore::open with verify_full_audit_chain: true, then verification, \
                          then a clean shutdown"
                .to_owned(),
            invariants: vec![
                "every acknowledged batch exists at the acknowledged revision with all rows"
                    .to_owned(),
                "every manifest has exactly m contiguous rows at its revision with the right \
                 content; no rows without a manifest"
                    .to_owned(),
                "manifests = counter = audit head = revision".to_owned(),
                "verify_chain over sys.audit ends at the status head; audit record seq = revision"
                    .to_owned(),
                "the journal is contiguous from journal_oldest to the revision with \
                 journal_len change sets"
                    .to_owned(),
            ],
        },
        sequences: Vec::new(),
        kills: 0,
        violations: 0,
        restart_all: Latency::default(),
        pass: false,
    };
    let mut rng = Rng::new(args.seed);
    let mut all_restarts = new_hist();
    for plan in &plans {
        if plan.kills == 0 {
            continue;
        }
        println!("M2 {}: {} kills", plan.name, plan.kills);
        let sequence = run_sequence(plan, ctx, &mut rng, &mut all_restarts).await?;
        println!(
            "M2 {}: {} kills, {} violations, restart p50 {:.0} ms p99 {:.0} ms max {:.0} ms, \
             final revision {}, {} acknowledged batches",
            sequence.name,
            sequence.kills,
            sequence.violations,
            count_f64(sequence.restart.p50_ns) / 1e6,
            count_f64(sequence.restart.p99_ns) / 1e6,
            count_f64(sequence.restart.max_ns) / 1e6,
            sequence.final_revision,
            sequence.acked_total,
        );
        report.sequences.push(sequence);
        report.kills = report.sequences.iter().map(|s| s.kills).sum();
        report.violations = report.sequences.iter().map(|s| s.violations).sum();
        report.restart_all = summarize(&all_restarts);
        report.pass = report.violations == 0;
        report.meta = clock.finish();
        ctx.out.write(&args.out_name, &report)?;
    }
    println!(
        "M2: {} kills, {} violations: {}",
        report.kills,
        report.violations,
        if report.pass { "PASS" } else { "FAIL" }
    );
    Ok(())
}

#[allow(clippy::too_many_lines, reason = "one loop over the kills")]
async fn run_sequence(
    plan: &Plan,
    ctx: &Ctx,
    rng: &mut Rng,
    all_restarts: &mut hdrhistogram::Histogram<u64>,
) -> Result<SequenceResult> {
    let started = Instant::now();
    let scratch = ScratchDir::new(&ctx.data_root, &format!("m2-{}", plan.name))?;
    let store_dir = scratch.path().join("store");
    let acks_path = scratch.path().join("acks.log");
    let ready = scratch.path().join("ready");
    let error_log = scratch.path().join("child.err");
    let mut ack_log = AckLog::new(acks_path.clone());
    let exe = std::env::current_exe()?;
    let mut restarts = new_hist();
    let mut result = SequenceResult {
        name: plan.name.to_owned(),
        mode: plan.mode,
        durability: plan.durability.label().to_owned(),
        kills: 0,
        kills_before_ready: 0,
        violations: 0,
        violation_samples: Vec::new(),
        restart: Latency::default(),
        final_revision: 0,
        acked_total: 0,
        rows_total: 0,
        audit_records: 0,
        unacked_committed_total: 0,
        restarts_with_purged_log: 0,
        max_purged_index: 0,
        elapsed_secs: 0.0,
        iterations: Vec::new(),
    };

    for index in 0..plan.kills {
        let run = index as u64 + 1;
        let _ = fs::remove_file(&ready);
        let stderr = File::create(&error_log)?;
        let mut child = Command::new(&exe)
            .arg("m2-child")
            .arg("--dir")
            .arg(&store_dir)
            .args(["--mode", plan.mode.label()])
            .args(["--durability", plan.durability.label()])
            .args(["--run", &run.to_string()])
            .arg("--acks")
            .arg(&acks_path)
            .arg("--ready")
            .arg(&ready)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .context("start the child")?;
        let spawned = Instant::now();
        let mut violations = Violations::default();

        // When to kill.
        let before_ready = if plan.alternate {
            index % 2 == 1
        } else {
            rng.below(10) == 0
        };
        if before_ready {
            // The child opens a store in 50 to 100 ms; the recovery sequence aims at that window.
            let (low, high) = if plan.alternate { (8, 90) } else { (20, 400) };
            tokio::time::sleep(Duration::from_millis(rng.between(low, high))).await;
        } else {
            let waiting = Instant::now();
            while !ready.exists() {
                if child.try_wait()?.is_some() || waiting.elapsed() > Duration::from_secs(180) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            tokio::time::sleep(Duration::from_millis(rng.between(300, 1_500))).await;
        }
        let killed_after_ms = u64::try_from(spawned.elapsed().as_millis()).unwrap_or(u64::MAX);
        let killed_before_ready = !ready.exists();
        if let Some(status) = child.try_wait()? {
            let detail = fs::read_to_string(&error_log).unwrap_or_default();
            violations.add(format!(
                "run {run}: the child ended by itself ({status}) before the kill: {}",
                detail.trim()
            ));
        } else {
            child.kill().context("kill the child")?;
            child.wait()?;
        }
        if killed_before_ready {
            result.kills_before_ready += 1;
        }
        let acked_this_run = ack_log.refresh()? as u64;

        // Restart.
        let mut attempts = 0;
        let (store, open_time) = loop {
            attempts += 1;
            let opened = Instant::now();
            match RaftStore::open(store_config(&store_dir, plan.durability, true)).await {
                Ok(store) => break (Some(store), opened.elapsed()),
                Err(error) if attempts < 4 => {
                    eprintln!("run {run}: open attempt {attempts} failed: {error}");
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                Err(error) => {
                    violations.add(format!(
                        "run {run}: the store does not open after a kill: {error}"
                    ));
                    break (None, opened.elapsed());
                }
            }
        };
        let Some(store) = store else {
            result.kills += 1;
            result.violations += violations.total;
            result.violation_samples.extend(violations.samples);
            println!("  run {run}: the store did not open; the sequence stops");
            break;
        };
        record_ns(&mut restarts, open_time.as_nanos());
        record_ns(all_restarts, open_time.as_nanos());
        let purged = purged_index(&store);
        let checked = verify(&store, &ack_log, &mut violations).await?;
        store.shutdown().await?;
        drop(store);

        result.kills += 1;
        result.violations += violations.total;
        result.violation_samples.extend(
            violations
                .samples
                .iter()
                .map(|sample| format!("[{}] {sample}", plan.name)),
        );
        if purged > 0 {
            result.restarts_with_purged_log += 1;
        }
        result.max_purged_index = result.max_purged_index.max(purged);
        result.final_revision = checked.revision;
        result.rows_total = checked.rows;
        result.audit_records = checked.audit_records;
        result.unacked_committed_total += checked.unacked_committed;
        println!(
            "  run {run:>3}: killed after {killed_after_ms} ms{}, open {:.0} ms, revision {}, \
             acked {} (+{acked_this_run}), rows {}, verify {:.0} ms, violations {}",
            if killed_before_ready {
                " (before ready)"
            } else {
                ""
            },
            open_time.as_secs_f64() * 1_000.0,
            checked.revision,
            ack_log.acks.len(),
            checked.rows,
            checked.verify_ms,
            violations.total
        );
        result.iterations.push(Iteration {
            run,
            killed_before_ready,
            killed_after_ms,
            open_ms: open_time.as_secs_f64() * 1_000.0,
            open_attempts: attempts,
            acked_this_run,
            acked_total: ack_log.acks.len() as u64,
            purged_index: purged,
            checked,
            violations: violations.total,
        });
    }
    result.restart = summarize(&restarts);
    result.acked_total = ack_log.acks.len() as u64;
    result.elapsed_secs = started.elapsed().as_secs_f64();
    if result.kills == 0 {
        bail!("no kill was performed");
    }
    Ok(result)
}
