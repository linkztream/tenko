//! Crash recovery of `RaftStore`: a writer process is killed at random points, and the data
//! directory is reopened and audited, over and over on the same directory.
//!
//! The test binary re-executes itself. The parent spawns the `crash_child` test as a writer
//! process on the data directory, waits for it to print `READY`, lets it write for a random
//! 30 to 600 ms and kills it abruptly (`Child::kill` is `TerminateProcess` on Windows, so
//! nothing is flushed or closed). It then opens the directory in-process, with the whole
//! audit chain verified at start-up, and checks:
//!
//! 1. the store opens;
//! 2. no batch is partial: every manifest row has exactly as many rows as it announces,
//!    every row belongs to a batch with a manifest, all rows of a batch carry the revision of
//!    its manifest, and the counter, the revision and the audit head agree;
//! 3. the audit chain read back from `sys.audit` verifies and ends at the same head;
//! 4. no acknowledged commit is lost: every line of `acks.log` (written after `propose`
//!    returned) names a revision the store has, and a batch that exists in the store or was
//!    deleted by a later batch of the same writer task;
//! 5. the journal is a contiguous run of revisions ending at the store's revision;
//! 6. the recovered store still takes writes and shuts down cleanly.
//!
//! The writers use small snapshot and journal limits, so snapshots, log purges and journal
//! trims happen while they are killed.

use std::{
    collections::{BTreeMap, HashSet},
    fmt::Display,
    io::{BufRead as _, BufReader, ErrorKind, Write as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use tenko_core::{
    CounterKey, Principal, Revision, SystemComponent, TableName, Timestamp,
    audit::{AuditAction, AuditDraft, ChainVerifier},
    codec::{decode_key, encode_key},
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt as _, Store as _, StoreError, StoreStatus,
    Versioned, WriteBatch,
    raft::{RaftStore, RaftStoreConfig, SmDurability, SnapshotPolicy},
    tables,
};

const ROWS: TableName = TableName::from_static("ipam.crash_rows");
const MANIFEST: TableName = TableName::from_static("ipam.crash_manifest");
const BATCHES: CounterKey = CounterKey::new("ipam.crash_batches");
const WRITE: AuditAction = AuditAction::from_static("ipam.crash.write");

const ENV_DIR: &str = "TENKO_CRASH_CHILD_DIR";
const ENV_MODE: &str = "TENKO_CRASH_MODE";
const ENV_DURABILITY: &str = "TENKO_CRASH_DURABILITY";
const ENV_SEED: &str = "TENKO_CRASH_SEED";
const ENV_ATTEMPT: &str = "TENKO_CRASH_ATTEMPT";
/// Parent side: fixes the seed all iteration seeds derive from (printed by every run).
const ENV_BASE_SEED: &str = "TENKO_CRASH_BASE_SEED";

const ACKS: &str = "acks.log";
/// A deleting batch removes the batch of the same task this many sequence numbers earlier.
const DELETE_LAG: u32 = 50;
const BULK_ROWS: u32 = 2_000;
const JOURNAL_RETENTION: usize = 1_000;
/// Attempt ids of the batches the parent writes after a recovery never collide with the
/// iteration numbers the writers use.
const RECOVERY_ATTEMPT_BASE: u32 = 0x8000_0000;
const READY_TIMEOUT: Duration = Duration::from_secs(60);
/// A writer whose parent died ends itself.
const WRITER_LIFETIME: Duration = Duration::from_secs(300);
const PAGE: usize = 2_000;
const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

const SHORT_KILLS: usize = 6;
const LONG_KILLS: usize = 120;

/// Splitmix64: a tiny deterministic generator, seeded per iteration and per writer task.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(GOLDEN);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u32) -> u32 {
        u32::try_from(self.next_u64() % u64::from(n)).unwrap_or(0)
    }

    /// A value in `low..=high`.
    fn between(&mut self, low: u32, high: u32) -> u32 {
        low + self.below(high - low + 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Steady,
    Bulk,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Steady => "steady",
            Mode::Bulk => "bulk",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "steady" => Some(Mode::Steady),
            "bulk" => Some(Mode::Bulk),
            _ => None,
        }
    }

    fn writers(self) -> u32 {
        match self {
            Mode::Steady => 8,
            Mode::Bulk => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Durability {
    Deferred,
    Immediate,
}

impl Durability {
    fn name(self) -> &'static str {
        match self {
            Durability::Deferred => "deferred",
            Durability::Immediate => "immediate",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "deferred" => Some(Durability::Deferred),
            "immediate" => Some(Durability::Immediate),
            _ => None,
        }
    }

    fn sm(self) -> SmDurability {
        match self {
            Durability::Deferred => SmDurability::Deferred {
                checkpoint_interval: Duration::from_millis(300),
            },
            Durability::Immediate => SmDurability::Immediate,
        }
    }
}

/// The store configuration of the writer and of the recovery check: the same limits, so the
/// directory is always opened the way it was written. Only the parent verifies the whole
/// audit chain at start-up.
fn store_config(dir: &Path, durability: Durability, verify_chain: bool) -> RaftStoreConfig {
    let mut config = RaftStoreConfig::new(dir);
    config.fsync_probe_samples = 0;
    config.verify_full_audit_chain = verify_chain;
    config.durability = durability.sm();
    config.journal_retention = JOURNAL_RETENTION;
    config.snapshot = SnapshotPolicy {
        every_entries: 150,
        every_log_bytes: 4 * 1024 * 1024,
        keep_entries: 20,
    };
    config
}

fn at() -> Timestamp {
    Timestamp::from_unix_nanos(1_791_547_200_000_000_000).expect("timestamp")
}

/// The unique id of a batch: the iteration that wrote it, the writer task and a sequence
/// number per task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct BatchId {
    attempt: u32,
    task: u32,
    seq: u32,
}

impl BatchId {
    fn key(self) -> Bytes {
        encode_key(&(self.attempt, self.task, self.seq))
    }

    fn row_key(self, index: u32) -> Bytes {
        encode_key(&(self.attempt, self.task, self.seq, index))
    }
}

/// What one batch writes.
struct Plan {
    id: BatchId,
    rows: u32,
    value_len: usize,
    /// An earlier committed batch of the same task to delete, with its row count.
    delete: Option<(BatchId, u32)>,
    /// Carry a precondition that cannot hold, so the batch fails inside a shared entry.
    fail: bool,
}

fn build(plan: &Plan) -> WriteBatch {
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Ipam), at());
    if plan.fail {
        let previous = BatchId {
            seq: plan.id.seq.saturating_sub(1),
            ..plan.id
        };
        batch.expect_version(MANIFEST, previous.key(), Some(Revision(u64::MAX)));
    }
    let id = plan.id.key();
    let mut value = id.to_vec();
    value.resize(plan.value_len.max(value.len()), b'x');
    for index in 0..plan.rows {
        batch.put(ROWS, plan.id.row_key(index), Bytes::from(value.clone()));
    }
    batch.put(
        MANIFEST,
        id,
        Bytes::copy_from_slice(&u64::from(plan.rows).to_be_bytes()),
    );
    if let Some((victim, rows)) = plan.delete {
        for index in 0..rows {
            batch.delete(ROWS, victim.row_key(index));
        }
        batch.delete(MANIFEST, victim.key());
    }
    batch
        .bump(BATCHES)
        .audit(AuditDraft::success(WRITE, vec![]));
    batch
}

// ---------------------------------------------------------------------------------------
// The writer process.
// ---------------------------------------------------------------------------------------

fn child_fatal(message: impl Display) -> ! {
    eprintln!("crash writer: {message}");
    std::process::exit(3);
}

fn plan_for(mode: Mode, id: BatchId, rng: &mut Rng, committed: &[Option<u32>]) -> Plan {
    match mode {
        Mode::Bulk => Plan {
            id,
            rows: BULK_ROWS,
            value_len: usize::try_from(rng.between(180, 220)).unwrap_or(200),
            delete: None,
            fail: false,
        },
        Mode::Steady => {
            let victim = id.seq.checked_sub(DELETE_LAG).filter(|_| rng.below(3) == 0);
            let delete = victim.and_then(|seq| {
                let rows = committed
                    .get(usize::try_from(seq).ok()?)
                    .copied()
                    .flatten()?;
                Some((BatchId { seq, ..id }, rows))
            });
            Plan {
                id,
                rows: rng.between(1, 8),
                value_len: usize::try_from(rng.between(80, 120)).unwrap_or(100),
                delete,
                fail: rng.below(10) == 0,
            }
        }
    }
}

/// One writer: proposes batch after batch, and logs a line to `acks.log` after each commit.
async fn writer_task(
    store: RaftStore,
    dir: PathBuf,
    mode: Mode,
    attempt: u32,
    task: u32,
    seed: u64,
) {
    let mut acks = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(ACKS))
        .unwrap_or_else(|error| child_fatal(format!("open {ACKS}: {error}")));
    let mut rng = Rng(seed ^ u64::from(task + 1).wrapping_mul(GOLDEN));
    // Rows of every sequence number that committed, for the deleting batches.
    let mut committed: Vec<Option<u32>> = Vec::new();
    for seq in 0_u32.. {
        let id = BatchId { attempt, task, seq };
        let plan = plan_for(mode, id, &mut rng, &committed);
        match store.propose(build(&plan)).await {
            Ok(done) => {
                committed.push(Some(plan.rows));
                let line = format!("{} {attempt} {task} {seq}\n", done.revision.0);
                acks.write_all(line.as_bytes())
                    .and_then(|()| acks.flush())
                    .unwrap_or_else(|error| child_fatal(format!("write {ACKS}: {error}")));
            }
            Err(StoreError::PreconditionFailed(_)) if plan.fail => committed.push(None),
            Err(error) => child_fatal(format!("propose {id:?}: {error}")),
        }
    }
}

/// The writer process: does nothing unless the parent test started it with the environment.
#[test]
#[ignore = "started as the writer process by the crash recovery tests"]
fn crash_child() {
    let Ok(dir) = std::env::var(ENV_DIR) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let var = |name: &str| {
        std::env::var(name).unwrap_or_else(|_| child_fatal(format!("{name} is not set")))
    };
    let mode = Mode::parse(&var(ENV_MODE)).unwrap_or_else(|| child_fatal("bad mode"));
    let durability =
        Durability::parse(&var(ENV_DURABILITY)).unwrap_or_else(|| child_fatal("bad durability"));
    let seed: u64 = var(ENV_SEED)
        .parse()
        .unwrap_or_else(|_| child_fatal("bad seed"));
    let attempt: u32 = var(ENV_ATTEMPT)
        .parse()
        .unwrap_or_else(|_| child_fatal("bad attempt"));

    std::thread::spawn(|| {
        std::thread::sleep(WRITER_LIFETIME);
        child_fatal("the parent never killed this writer");
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap_or_else(|error| child_fatal(format!("runtime: {error}")));
    runtime.block_on(async move {
        let store = RaftStore::open(store_config(&dir, durability, false))
            .await
            .unwrap_or_else(|error| child_fatal(format!("open: {error}")));
        // The test harness leaves its "test ... " prefix unterminated; start a new line.
        println!("\nREADY");
        std::io::stdout()
            .flush()
            .unwrap_or_else(|error| child_fatal(format!("flush: {error}")));
        let tasks: Vec<_> = (0..mode.writers())
            .map(|task| {
                tokio::spawn(writer_task(
                    store.clone(),
                    dir.clone(),
                    mode,
                    attempt,
                    task,
                    seed,
                ))
            })
            .collect();
        let (ended, which, _) = futures::future::select_all(tasks).await;
        child_fatal(format!("writer task {which} ended: {ended:?}"));
    });
}

// ---------------------------------------------------------------------------------------
// The parent: spawn, kill, recover, check.
// ---------------------------------------------------------------------------------------

/// A data directory under the system temporary directory. It is removed when the test
/// passes and kept (and named) when it fails.
struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tenko-crash-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the data directory");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "crash test failed: data directory kept at {}",
                self.0.display()
            );
            return;
        }
        // The store closes its files asynchronously after shutdown; retry briefly.
        for _ in 0..200 {
            if std::fs::remove_dir_all(&self.0).is_ok() || !self.0.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        eprintln!("could not remove {}", self.0.display());
    }
}

/// Where a failure happened, for the panic message.
struct Ctx {
    label: &'static str,
    iteration: u32,
    mode: Mode,
    seed: u64,
    dir: PathBuf,
}

impl Ctx {
    fn violated(&self, invariant: &str, detail: impl Display) -> ! {
        panic!(
            "crash recovery [{}] iteration {} ({} mode, seed {}) violated: {invariant}: \
             {detail}\n  data directory: {}",
            self.label,
            self.iteration,
            self.mode.name(),
            self.seed,
            self.dir.display()
        );
    }
}

/// The writer process as the parent sees it. Dropping it kills it, so no failure path
/// leaves a process behind that holds the directory's file locks.
struct Writer {
    child: Child,
    lines: mpsc::Receiver<String>,
    reader: Option<JoinHandle<()>>,
}

impl Writer {
    fn spawn(ctx: &Ctx, durability: Durability) -> Self {
        let exe = std::env::current_exe().expect("the path of the test binary");
        let mut child = Command::new(exe)
            .args([
                "crash_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env(ENV_DIR, &ctx.dir)
            .env(ENV_MODE, ctx.mode.name())
            .env(ENV_DURABILITY, durability.name())
            .env(ENV_SEED, ctx.seed.to_string())
            .env(ENV_ATTEMPT, ctx.iteration.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| ctx.violated("spawn the writer process", error));
        let stdout = child.stdout.take().expect("piped stdout");
        let (sender, lines) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    return;
                }
            }
        });
        Self {
            child,
            lines,
            reader: Some(reader),
        }
    }

    /// Waits for `READY`; a writer that exits first, or stays silent, fails the test.
    fn wait_ready(&mut self, ctx: &Ctx) {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line.trim() == "READY" => return,
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => ctx.violated(
                    "writer start",
                    format!("no READY within {} s", READY_TIMEOUT.as_secs()),
                ),
                Err(RecvTimeoutError::Disconnected) => {
                    let status = self.child.wait();
                    ctx.violated("writer start", format!("exited before READY: {status:?}"));
                }
            }
        }
    }

    /// Kills the writer abruptly and waits until the operating system has released it.
    fn kill(&mut self, ctx: &Ctx) {
        match self.child.try_wait() {
            Ok(Some(status)) => ctx.violated(
                "writer run",
                format!("the writer ended by itself with {status}"),
            ),
            Ok(None) => {}
            Err(error) => ctx.violated("writer run", format!("cannot poll the writer: {error}")),
        }
        self.child
            .kill()
            .unwrap_or_else(|error| ctx.violated("kill the writer", error));
        self.child
            .wait()
            .unwrap_or_else(|error| ctx.violated("wait for the writer", error));
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One line of `acks.log`: a commit the writer saw acknowledged.
struct Ack {
    revision: u64,
    id: BatchId,
}

fn parse_ack(line: &str) -> Option<Ack> {
    let mut fields = line.split(' ');
    let revision = fields.next()?.parse().ok()?;
    let id = BatchId {
        attempt: fields.next()?.parse().ok()?,
        task: fields.next()?.parse().ok()?,
        seq: fields.next()?.parse().ok()?,
    };
    fields.next().is_none().then_some(Ack { revision, id })
}

/// Reads `acks.log`. A final line without its newline was cut by the kill: it was never
/// acknowledged, and it is cut off so the next writer starts on a fresh line.
fn read_acks(ctx: &Ctx) -> Vec<Ack> {
    let path = ctx.dir.join(ACKS);
    let mut bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
        Err(error) => ctx.violated("acks.log", format!("cannot read it: {error}")),
    };
    let complete = bytes
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |end| end + 1);
    if complete < bytes.len() {
        let len = u64::try_from(complete).expect("length");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_len(len))
            .unwrap_or_else(|error| ctx.violated("acks.log", format!("cannot trim it: {error}")));
        bytes.truncate(complete);
    }
    let text = String::from_utf8(bytes)
        .unwrap_or_else(|error| ctx.violated("acks.log", format!("not text: {error}")));
    text.lines()
        .map(|line| {
            parse_ack(line)
                .unwrap_or_else(|| ctx.violated("acks.log", format!("bad line {line:?}")))
        })
        .collect()
}

/// Calls `each` for every entry of a table, in key order, page by page.
fn scan_all(
    ctx: &Ctx,
    view: &dyn ReadView,
    table: &TableName,
    mut each: impl FnMut(&Bytes, &Versioned),
) {
    let mut range = KeyRange::all();
    loop {
        let page = view
            .scan(table, range.clone(), PAGE, false)
            .unwrap_or_else(|error| ctx.violated("read", format!("scan of {table}: {error}")));
        let Some((last, _)) = page.last() else {
            return;
        };
        range = KeyRange::all().after(last.clone());
        for (key, versioned) in &page {
            each(key, versioned);
        }
    }
}

type Id = (u32, u32, u32);

/// What the store holds after a recovery, as far as the acknowledged commits are concerned.
struct Held {
    /// Rows announced by each manifest, with the revision that wrote it.
    manifest: BTreeMap<Id, (u64, Revision)>,
    /// The highest sequence number with a manifest, per attempt and task. The newest batch
    /// of a task is never deleted, so this is the task's last commit.
    newest: BTreeMap<(u32, u32), u32>,
    rows: u64,
}

/// Invariant 2: no partial batch, and the counter, revision and audit head agree.
fn check_batches(ctx: &Ctx, view: &dyn ReadView) -> Held {
    let revision = view.revision();
    let mut manifest = BTreeMap::new();
    let mut newest = BTreeMap::new();
    let mut revisions = HashSet::new();
    scan_all(ctx, view, &MANIFEST, |key, versioned| {
        let id: Id = decode_key(key)
            .unwrap_or_else(|error| ctx.violated("manifest", format!("bad key: {error}")));
        let Ok(announced) = <[u8; 8]>::try_from(&versioned.value[..]) else {
            ctx.violated("manifest", format!("bad value for {id:?}"));
        };
        let announced = u64::from_be_bytes(announced);
        if versioned.revision > revision || !revisions.insert(versioned.revision) {
            ctx.violated(
                "revisions",
                format!(
                    "batch {id:?} has revision {} (store at {revision})",
                    versioned.revision
                ),
            );
        }
        newest
            .entry((id.0, id.1))
            .and_modify(|seq: &mut u32| *seq = (*seq).max(id.2))
            .or_insert(id.2);
        manifest.insert(id, (announced, versioned.revision));
    });

    let mut counts: BTreeMap<Id, u64> = BTreeMap::new();
    let mut rows = 0_u64;
    scan_all(ctx, view, &ROWS, |key, versioned| {
        let (attempt, task, seq, index): (u32, u32, u32, u32) = decode_key(key)
            .unwrap_or_else(|error| ctx.violated("rows", format!("bad key: {error}")));
        let id = (attempt, task, seq);
        let Some(&(_, written)) = manifest.get(&id) else {
            ctx.violated(
                "partial batch",
                format!("row {index} of batch {id:?} exists but the batch has no manifest"),
            );
        };
        if versioned.revision != written {
            ctx.violated(
                "partial batch",
                format!(
                    "row {index} of batch {id:?} is at revision {}, its manifest at {written}",
                    versioned.revision
                ),
            );
        }
        if versioned.value.len() < 12 || versioned.value[..12] != key[..12] {
            ctx.violated(
                "rows",
                format!("row {index} of batch {id:?} has a wrong value"),
            );
        }
        let count = counts.entry(id).or_insert(0);
        if u64::from(index) != *count {
            ctx.violated(
                "partial batch",
                format!("batch {id:?}: row {index} follows {count} rows (a row is missing)"),
            );
        }
        *count += 1;
        rows += 1;
    });
    for (id, &(announced, _)) in &manifest {
        let found = counts.get(id).copied().unwrap_or(0);
        if found != announced {
            ctx.violated(
                "partial batch",
                format!("batch {id:?} announces {announced} rows and has {found}"),
            );
        }
    }
    Held {
        manifest,
        newest,
        rows,
    }
}

/// Invariants 2 (counters) and 3: the audit chain read back from `sys.audit`.
fn check_audit_and_counters(ctx: &Ctx, view: &dyn ReadView, status: &StoreStatus) {
    let revision = view.revision();
    let mut verifier = ChainVerifier::new();
    let mut records = 0_u64;
    scan_all(ctx, view, tables::AUDIT.name(), |_, versioned| {
        let record = tables::AUDIT
            .decode(&versioned.value)
            .unwrap_or_else(|error| ctx.violated("audit chain", format!("undecodable: {error}")));
        verifier
            .push(&record)
            .unwrap_or_else(|error| ctx.violated("audit chain", error));
        records += 1;
    });
    let head = verifier.head();
    let counter = view
        .counter(&BATCHES)
        .unwrap_or_else(|error| ctx.violated("read", format!("counter: {error}")));
    let facts = [
        ("view revision", revision.0),
        ("status revision", status.revision.0),
        ("batch counter", counter),
        ("status audit head", status.audit_head.0),
        ("verified audit head", head.seq.0),
        ("audit records", records),
    ];
    if facts.iter().any(|&(_, value)| value != revision.0) {
        ctx.violated(
            "counter, revision and audit head agree (one batch, one revision, one audit record)",
            format!("{facts:?}"),
        );
    }
}

/// Invariant 5: the journal is a contiguous run ending at the store's revision, of the
/// length the retention leaves.
fn check_journal(ctx: &Ctx, view: &dyn ReadView, status: &StoreStatus) {
    let revision = view.revision();
    let mut first: Option<Revision> = None;
    let mut last: Option<Revision> = None;
    let mut len = 0_u64;
    scan_all(ctx, view, tables::JOURNAL.name(), |key, _| {
        let at = tables::JOURNAL
            .decode_key(key)
            .unwrap_or_else(|error| ctx.violated("journal", format!("bad key: {error}")));
        match last {
            Some(previous) if at != previous.next() => ctx.violated(
                "journal contiguity",
                format!("revision {at} follows {previous}"),
            ),
            None => first = Some(at),
            Some(_) => {}
        }
        last = Some(at);
        len += 1;
    });
    let retention = u64::try_from(JOURNAL_RETENTION).unwrap_or(u64::MAX);
    let expected_len = revision.0.min(retention);
    let expected_last = (revision.0 > 0).then_some(revision);
    if last != expected_last || len != expected_len {
        ctx.violated(
            "journal ends at the store revision",
            format!(
                "journal holds {len} revisions {first:?}..={last:?}; the store is at {revision} \
                 (expected {expected_len} revisions)"
            ),
        );
    }
    if status.journal_oldest != first || status.journal_len != len {
        ctx.violated(
            "journal status",
            format!(
                "status says oldest {:?}, {} entries; the journal has {first:?}, {len}",
                status.journal_oldest, status.journal_len
            ),
        );
    }
}

/// Invariant 4: no acknowledged commit is lost. Acknowledged batches of the iteration that
/// was just killed are also found in the journal at the revision they were told.
fn check_acks(ctx: &Ctx, view: &dyn ReadView, status: &StoreStatus, held: &Held, acks: &[Ack]) {
    let revision = view.revision();
    let mut revisions = HashSet::new();
    for ack in acks {
        let id = (ack.id.attempt, ack.id.task, ack.id.seq);
        if ack.revision > revision.0 {
            ctx.violated(
                "no lost acknowledged commit",
                format!(
                    "batch {id:?} was acknowledged at revision {} and the store is at {revision}",
                    ack.revision
                ),
            );
        }
        if !revisions.insert(ack.revision) {
            ctx.violated(
                "revisions",
                format!(
                    "two acknowledged batches share revision {} (one is {id:?})",
                    ack.revision
                ),
            );
        }
        match held.manifest.get(&id) {
            Some(&(_, written)) if written.0 == ack.revision => {}
            Some(&(_, written)) => ctx.violated(
                "acknowledged revision",
                format!(
                    "batch {id:?} was acknowledged at {} and committed at {written}",
                    ack.revision
                ),
            ),
            None => {
                // Only a later batch of the same task deletes it, and then the task's newest
                // batch is at least `DELETE_LAG` sequence numbers further.
                let deleted = held
                    .newest
                    .get(&(id.0, id.1))
                    .is_some_and(|&newest| newest >= id.2 + DELETE_LAG);
                if !deleted {
                    ctx.violated(
                        "no lost acknowledged commit",
                        format!(
                            "batch {id:?} was acknowledged at revision {} but has no manifest \
                             and no later batch could have deleted it",
                            ack.revision
                        ),
                    );
                }
            }
        }
        let retained = status
            .journal_oldest
            .is_some_and(|oldest| oldest.0 <= ack.revision);
        if ack.id.attempt == ctx.iteration && retained {
            let entry = view
                .get_typed(&tables::JOURNAL, &Revision(ack.revision))
                .unwrap_or_else(|error| ctx.violated("journal", format!("read: {error}")));
            let lists_batch = entry.is_some_and(|(change_set, _)| {
                change_set
                    .changes
                    .iter()
                    .any(|change| change.table == MANIFEST && change.key == ack.id.key())
            });
            if !lists_batch {
                ctx.violated(
                    "acknowledged revision",
                    format!(
                        "the journal at revision {} does not list batch {id:?}",
                        ack.revision
                    ),
                );
            }
        }
    }
}

/// Invariant 6: the recovered store takes writes. Returns its revision afterwards.
async fn prove_writable(ctx: &Ctx, store: &RaftStore, before: Revision) -> Revision {
    for seq in 0..3_u32 {
        let id = BatchId {
            attempt: RECOVERY_ATTEMPT_BASE + ctx.iteration,
            task: 0,
            seq,
        };
        let plan = Plan {
            id,
            rows: 3,
            value_len: 100,
            delete: None,
            fail: false,
        };
        let done = store
            .propose(build(&plan))
            .await
            .unwrap_or_else(|error| ctx.violated("recovered store takes writes", error));
        if done.revision != Revision(before.0 + u64::from(seq) + 1) {
            ctx.violated(
                "recovered store takes writes",
                format!(
                    "batch {seq} committed at {}, expected {}",
                    done.revision,
                    before.0 + u64::from(seq) + 1
                ),
            );
        }
    }
    let view = store
        .read(ReadConsistency::Local)
        .await
        .unwrap_or_else(|error| ctx.violated("recovered store takes writes", error));
    let revision = view.revision();
    let counter = view
        .counter(&BATCHES)
        .unwrap_or_else(|error| ctx.violated("read", format!("counter: {error}")));
    if revision != Revision(before.0 + 3) || counter != revision.0 {
        ctx.violated(
            "recovered store takes writes",
            format!("revision {revision} and counter {counter} after three batches on {before}"),
        );
    }
    for seq in 0..3_u32 {
        let id = BatchId {
            attempt: RECOVERY_ATTEMPT_BASE + ctx.iteration,
            task: 0,
            seq,
        };
        let stored = view
            .get(&MANIFEST, &id.key())
            .unwrap_or_else(|error| ctx.violated("read", format!("manifest: {error}")));
        if stored.is_none() {
            ctx.violated(
                "recovered store takes writes",
                format!("batch {id:?} committed but is not readable"),
            );
        }
    }
    revision
}

/// What one iteration observed.
struct Outcome {
    iteration: u32,
    mode: Mode,
    kill_after: Duration,
    acked: usize,
    recovered: Revision,
    /// Raft log index of the last snapshot and of the last purge, as recovered.
    snapshot: u64,
    purged: u64,
    batches: usize,
    rows: u64,
    open: Duration,
}

/// One data directory that accumulates state over many kills.
struct Campaign {
    label: &'static str,
    durability: Durability,
    dir: TestDir,
    iterations: u32,
    /// The store's revision at the end of the previous iteration.
    revision: Revision,
}

impl Campaign {
    fn new(label: &'static str, durability: Durability) -> Self {
        Self {
            label,
            durability,
            dir: TestDir::new(label),
            iterations: 0,
            revision: Revision(0),
        }
    }

    async fn iterate(&mut self, mode: Mode, seed: u64) -> Outcome {
        self.iterations += 1;
        let ctx = Ctx {
            label: self.label,
            iteration: self.iterations,
            mode,
            seed,
            dir: self.dir.path().to_path_buf(),
        };
        let kill_after = Duration::from_millis(u64::from(Rng(seed).between(30, 600)));
        let mut writer = Writer::spawn(&ctx, self.durability);
        writer.wait_ready(&ctx);
        tokio::time::sleep(kill_after).await;
        writer.kill(&ctx);
        drop(writer);
        let mut outcome = self.recover(&ctx).await;
        outcome.kill_after = kill_after;
        outcome
    }

    async fn recover(&mut self, ctx: &Ctx) -> Outcome {
        // Invariant 1.
        let started = Instant::now();
        let store = RaftStore::open(store_config(self.dir.path(), self.durability, true))
            .await
            .unwrap_or_else(|error| ctx.violated("the store opens after the kill", error));
        let open = started.elapsed();

        let view = store
            .read(ReadConsistency::Local)
            .await
            .unwrap_or_else(|error| ctx.violated("read", error));
        let status = store.status();
        let recovered = view.revision();
        let (snapshot, purged) = {
            let metrics = store.raft().metrics();
            let metrics = metrics.borrow();
            (
                metrics.snapshot.map_or(0, |log_id| log_id.index),
                metrics.purged.map_or(0, |log_id| log_id.index),
            )
        };
        if recovered < self.revision {
            ctx.violated(
                "no lost commit",
                format!(
                    "the store is at revision {recovered}; it was at {} before",
                    self.revision
                ),
            );
        }
        let held = check_batches(ctx, view.as_ref());
        check_audit_and_counters(ctx, view.as_ref(), &status);
        check_journal(ctx, view.as_ref(), &status);
        let acks = read_acks(ctx);
        check_acks(ctx, view.as_ref(), &status, &held, &acks);
        drop(view);

        self.revision = prove_writable(ctx, &store, recovered).await;
        store
            .shutdown()
            .await
            .unwrap_or_else(|error| ctx.violated("clean shutdown", error));
        drop(store);
        Outcome {
            iteration: ctx.iteration,
            mode: ctx.mode,
            kill_after: Duration::ZERO,
            acked: acks
                .iter()
                .filter(|ack| ack.id.attempt == ctx.iteration)
                .count(),
            recovered,
            snapshot,
            purged,
            batches: held.manifest.len(),
            rows: held.rows,
            open,
        }
    }
}

fn base_seed() -> u64 {
    std::env::var(ENV_BASE_SEED)
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(1, |elapsed| u64::try_from(elapsed.as_nanos()).unwrap_or(1))
        })
}

fn iteration_seed(base: u64, n: usize) -> u64 {
    let n = u64::try_from(n).unwrap_or(0);
    Rng(base ^ n.wrapping_add(1).wrapping_mul(GOLDEN)).next_u64()
}

fn report(label: &str, outcome: &Outcome) {
    eprintln!(
        "[{label}] iteration {:3} mode={:6} killed after {:3} ms, {:5} acknowledged, \
         recovered revision {:7} ({} batches, {} rows; snapshot at log {}, purged to {}), \
         open {} ms",
        outcome.iteration,
        outcome.mode.name(),
        outcome.kill_after.as_millis(),
        outcome.acked,
        outcome.recovered.0,
        outcome.batches,
        outcome.rows,
        outcome.snapshot,
        outcome.purged,
        outcome.open.as_millis()
    );
}

/// Prints how many kills were survived and the spread of the open times.
fn summarize(what: &str, opens: &mut [Duration]) {
    opens.sort();
    let (Some(min), Some(max)) = (opens.first(), opens.last()) else {
        return;
    };
    eprintln!(
        "{what}: {} kills survived; open time min {} ms, median {} ms, max {} ms",
        opens.len(),
        min.as_millis(),
        opens[opens.len() / 2].as_millis(),
        max.as_millis()
    );
}

/// Runs `kills` iterations over `campaigns` in turn; within each campaign the modes
/// alternate.
async fn run(campaigns: &mut [Campaign], kills: usize) {
    let base = base_seed();
    eprintln!("crash recovery: {kills} kills, base seed {base} ({ENV_BASE_SEED} repeats it)");
    let mut opens: Vec<(&str, Duration)> = Vec::new();
    for n in 0..kills {
        let width = campaigns.len();
        let campaign = &mut campaigns[n % width];
        let mode = if (n / width).is_multiple_of(2) {
            Mode::Steady
        } else {
            Mode::Bulk
        };
        let outcome = campaign.iterate(mode, iteration_seed(base, n)).await;
        report(campaign.label, &outcome);
        opens.push((campaign.label, outcome.open));
    }
    for campaign in campaigns.iter() {
        let mut own: Vec<Duration> = opens
            .iter()
            .filter(|(label, _)| *label == campaign.label)
            .map(|&(_, open)| open)
            .collect();
        summarize(campaign.label, &mut own);
    }
    let mut all: Vec<Duration> = opens.iter().map(|&(_, open)| open).collect();
    summarize("total", &mut all);
}

/// A few kills, alternating the two workloads, with deferred state-machine durability.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_recovery_short() {
    let mut campaigns = [Campaign::new("short", Durability::Deferred)];
    run(&mut campaigns, SHORT_KILLS).await;
}

/// More than a hundred kills over two data directories, one per durability mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long: run with --ignored crash_recovery_long"]
async fn crash_recovery_long() {
    let mut campaigns = [
        Campaign::new("long-deferred", Durability::Deferred),
        Campaign::new("long-immediate", Durability::Immediate),
    ];
    run(&mut campaigns, LONG_KILLS).await;
}
