//! The Raft store (WP1.1): [`RaftStore`] implements [`Store`] with openraft 0.9 over redb
//! (ADR 0002, ADR 0011), with the exact semantics of `MemStore` and the same conformance
//! suite.
//!
//! # Data directory
//!
//! | Path | Content |
//! |---|---|
//! | `log.redb` | The Raft log, vote and committed id (`log`), fsynced by group commit |
//! | `sm.redb` | The state machine: one redb table per store table plus `_meta` (`stored`), until the first snapshot install |
//! | `sm-<id>.redb` | The state machine after a snapshot install or an in-place re-seed: a fresh, compacted file |
//! | `sm.current` | Names the active state file once it is not `sm.redb` (replaced atomically) |
//! | `snapshots/` | The current snapshot file and the one before it (`snapshot`) |
//!
//! The directory must be on SSD or `NVMe` storage (ADR 0002 condition 7); [`RaftStore::open`]
//! measures durable commits there first and warns through `tracing` when the median is
//! above 10 ms (OPS-19, [`fsync`]); [`StoreStatus::fsync_p50_micros`] reports it.
//!
//! # Writes
//!
//! [`Store::propose`] validates the batch ([`WriteBatch::validate`]), encodes it once and
//! queues it to the coalescer (`coalescer`), which packs queued batches into Raft entries
//! within [`CoalescerConfig`]. The state machine (`sm`, `apply`) applies the batches of an
//! entry in order, each against its own preconditions, in one redb transaction with the
//! journal, audit chain and idempotency records, then updates the derived indexes with a
//! view at each change set's revision; only then does `propose` return.
//!
//! # Reads and watches
//!
//! Reads are redb read transactions (`view`): `Local` at once, `AtLeast` after waiting for
//! the applied revision, `Linearizable` after openraft confirms leadership and the state
//! machine has caught up. Watches replay `sys.journal` and follow the applied revision
//! (`watch`). A view pins the pages of its revision until it is dropped, so hold views
//! briefly: one kept for hours under writes makes `sm.redb` grow.
//!
//! # Snapshots, purge and recovery
//!
//! A maintenance task builds a snapshot when [`SnapshotPolicy::every_entries`] entries or
//! [`SnapshotPolicy::every_log_bytes`] bytes of log have accumulated since the last one;
//! openraft then purges the log behind it, keeping [`SnapshotPolicy::keep_entries`]
//! (snapshot-and-purge, ADR 0002 condition 4). Opening replays the log into the state
//! machine before it returns, verifies the head of the audit chain (or all of it,
//! [`RaftStoreConfig::verify_full_audit_chain`]) and, should the durable state ever lag
//! behind the purged log, reinstalls the current snapshot first.
//!
//! # Disk usage and re-seeding
//!
//! redb never repacks a file in place: under incremental writes the state file keeps free
//! pages, and below 4 GiB it grows by doubling. A snapshot install therefore never writes
//! into the live file: it writes the state into a fresh file in one transaction, compacts it
//! and switches to it atomically (`sm`). The journal is bounded by
//! [`RaftStoreConfig::journal_max_bytes`] as well as by its change-set count, because the
//! change set of a bulk batch lists every key it wrote.
//!
//! **Re-seed rule (ADR 0002), for the server's maintenance task:** re-seed a node when its
//! state file passes about twice the live data. Apply the rule to the size at start-up,
//! [`DiskUsage::state_ratio_at_open`]: a clean shutdown leaves the file holding only the
//! pages in use (redb trims the rest when it closes). While the store runs, redb keeps up to
//! as much free space again as it has pages in use (it grows a file below 4 GiB by
//! doubling), so the running ratio ([`StoreStatus::sm_file_ratio`], [`DiskUsage::state_ratio`])
//! can read up to about twice the figure at rest: in M6 a freshly re-seeded file read 2.53x
//! after its first write and 1.26x at rest. A running ratio above about 4 corresponds to the
//! 2x rule. All these figures are cached; reading them costs nothing. A member of a cluster
//! can be re-seeded by rejoining with an empty data directory (it catches up by snapshot);
//! any node, a single voter included, can call [`RaftStore::reseed_in_place`], which rewrites
//! its own state into a fresh, compacted file. Writes wait while that runs (it copies the
//! whole state: about 4 s for 1,000,000 records in M6); reads continue. The measured effect is
//! in `bench/phase1-store/results/2026-10-09-windows.md` (M6).
//!
//! # Cluster readiness
//!
//! A store with `bootstrap` set initializes a single-voter cluster on first start (Slice 1).
//! The node id, membership changes ([`RaftStore::add_learner`],
//! [`RaftStore::change_membership`]) and the transport ([`network::PeerTransport`],
//! with [`network::InProcessNetwork`] for tests) are in place for Slice 3, which adds the
//! mTLS transport and write forwarding; until then a follower answers proposals with
//! [`StoreError::NoQuorum`].

pub mod fsync;
pub mod log;
pub mod network;
pub mod types;

mod apply;
mod coalescer;
mod index;
mod sm;
mod snapshot;
mod stored;
mod view;
mod watch;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::PathBuf,
    sync::{
        Arc, Mutex, PoisonError, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use openraft::{BasicNode, ServerState, error::Fatal};
use tenko_core::{NodeId, Revision, codec::to_cbor};
use tokio::{
    io::AsyncWriteExt as _,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use self::{
    coalescer::{CoalescerStats, Queued},
    fsync::FsyncProbe,
    log::LogStore,
    network::{NetworkFactory, NoPeers, PeerTransport},
    sm::{SmOptions, StateMachine},
    types::{ProposedBatch, Raft, RaftNodeId, Snapshot, SnapshotFile, SnapshotMeta, Vote},
};
use crate::api::{
    ChangeStream, CoalescerConfig, Committed, DerivedIndex, ReadConsistency, ReadView, Store,
    StoreError, StoreRole, StoreStatus, WatchFilter, WriteBatch,
};

/// When `sm.redb` makes its commits durable. The Raft log is fsynced before an entry
/// commits in either case, so a crash never loses a committed write: the entries after the
/// last durable state-machine commit are re-applied from the log on the next start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmDurability {
    /// Every apply transaction is fsynced (two fsyncs per write path).
    Immediate,
    /// Applies commit without fsync; the state is made durable every `checkpoint_interval`,
    /// before every snapshot and at shutdown. Halves the fsyncs of the write path.
    Deferred {
        /// Longest time between durable checkpoints.
        checkpoint_interval: Duration,
    },
}

/// When snapshots are built and how much log stays behind them (snapshot-and-purge).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotPolicy {
    /// Build a snapshot after this many applied entries since the last one.
    pub every_entries: u64,
    /// Build a snapshot after this many bytes of appended log since the last one.
    pub every_log_bytes: u64,
    /// Log entries kept behind the snapshot when the log is purged (a lagging follower
    /// within this distance catches up from the log instead of a snapshot).
    pub keep_entries: u64,
}

impl Default for SnapshotPolicy {
    fn default() -> Self {
        Self {
            every_entries: 10_000,
            every_log_bytes: 64 * 1024 * 1024,
            keep_entries: 1_000,
        }
    }
}

/// Raft timers in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaftTimings {
    /// Leader heartbeat interval.
    pub heartbeat_ms: u64,
    /// Minimum election timeout.
    pub election_min_ms: u64,
    /// Maximum election timeout.
    pub election_max_ms: u64,
}

impl Default for RaftTimings {
    fn default() -> Self {
        Self {
            heartbeat_ms: 100,
            election_min_ms: 500,
            election_max_ms: 1_000,
        }
    }
}

/// Configuration of a [`RaftStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftStoreConfig {
    /// The data directory (`log.redb`, `sm.redb`, `snapshots/`). SSD or `NVMe` only.
    pub data_dir: PathBuf,
    /// This node's Raft id.
    pub node_id: NodeId,
    /// The address peers reach this node at (empty for a single voter).
    pub address: String,
    /// Initialize a single-voter cluster on first start and wait for leadership and log
    /// replay at every start. Off for a node that joins an existing cluster as a learner.
    pub bootstrap: bool,
    /// Write coalescing limits and the batch size limit.
    pub coalescer: CoalescerConfig,
    /// Change sets the journal keeps for `watch` replay (at least 1); the upper bound by
    /// count.
    pub journal_retention: usize,
    /// Bytes of change sets the journal keeps at most (home profile default 32 MiB); the
    /// newest change set always stays. Carried in every Raft entry, so every replica trims
    /// its journal identically.
    pub journal_max_bytes: u64,
    /// Revisions a live watcher may fall behind before its stream ends with `Lagged`.
    pub watch_max_lag: u64,
    /// How long `AtLeast` and `Linearizable` reads wait.
    pub read_wait: Duration,
    /// How long `propose` waits for its entry to apply.
    pub write_timeout: Duration,
    /// redb page cache of `log.redb` (home profile default 4 MiB, OPS-15).
    pub log_cache_bytes: usize,
    /// redb page cache of `sm.redb` (home profile default 32 MiB, OPS-15).
    pub sm_cache_bytes: usize,
    /// When `sm.redb` commits become durable.
    pub durability: SmDurability,
    /// Snapshot-and-purge policy.
    pub snapshot: SnapshotPolicy,
    /// Raft timers.
    pub timings: RaftTimings,
    /// How often cached sizes (disk usage) are refreshed for `status()`.
    pub status_refresh: Duration,
    /// Durable commits the start-up fsync probe measures (0 disables the probe).
    pub fsync_probe_samples: usize,
    /// Verify every audit record at start-up instead of the chain head.
    pub verify_full_audit_chain: bool,
}

impl RaftStoreConfig {
    /// A single-voter configuration (node 1) with home-profile defaults.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            node_id: NodeId(1),
            address: String::new(),
            bootstrap: true,
            coalescer: CoalescerConfig::default(),
            journal_retention: 100_000,
            journal_max_bytes: 32 * 1024 * 1024,
            watch_max_lag: 10_000,
            read_wait: Duration::from_secs(5),
            write_timeout: Duration::from_secs(60),
            log_cache_bytes: 4 * 1024 * 1024,
            sm_cache_bytes: 32 * 1024 * 1024,
            durability: SmDurability::Deferred {
                checkpoint_interval: Duration::from_secs(1),
            },
            snapshot: SnapshotPolicy::default(),
            timings: RaftTimings::default(),
            status_refresh: Duration::from_secs(5),
            fsync_probe_samples: fsync::DEFAULT_PROBE_SAMPLES,
            verify_full_audit_chain: false,
        }
    }

    /// The configuration the conformance suite asks for, in a fresh temporary directory.
    #[cfg(feature = "testing")]
    pub fn for_conformance(config: &crate::testing::ConformanceConfig) -> Self {
        let mut store = Self::new(temp_store_dir());
        store.journal_retention = config.journal_retention;
        store.watch_max_lag = config.watch_max_lag;
        store.read_wait = config.read_wait;
        store.coalescer.max_batch_bytes = config.max_batch_bytes;
        store.fsync_probe_samples = 0;
        store.verify_full_audit_chain = true;
        store
    }
}

/// Counters of the engine, for benchmarks and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EngineStats {
    /// Raft entries the coalescer proposed.
    pub entries_proposed: u64,
    /// Batches the coalescer proposed.
    pub batches_proposed: u64,
    /// fsynced commits of the log store.
    pub log_commits: u64,
    /// Entries written to the log store.
    pub log_entries: u64,
    /// Encoded bytes appended to the log store.
    pub log_appended_bytes: u64,
    /// Snapshots built.
    pub snapshots_built: u64,
    /// Bytes of the last snapshot built.
    pub last_snapshot_bytes: u64,
    /// Duration of the last snapshot build.
    pub last_snapshot_build_micros: u64,
    /// Snapshots installed.
    pub snapshots_installed: u64,
    /// Duration of the last install, including the index rebuild.
    pub last_install_micros: u64,
    /// Duration of the index rebuild of the last install.
    pub last_index_rebuild_micros: u64,
    /// Duration of the compaction of the last fresh state file (install or re-seed).
    pub last_compact_micros: u64,
    /// In-place re-seeds ([`RaftStore::reseed_in_place`]).
    pub reseeds_in_place: u64,
    /// Durable checkpoints of the state file (deferred durability).
    pub checkpoints: u64,
}

/// Bytes on disk of a store, from the size cache (refreshed every
/// [`RaftStoreConfig::status_refresh`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DiskUsage {
    /// `log.redb`.
    pub log_bytes: u64,
    /// The active state file.
    pub state_bytes: u64,
    /// The snapshot directory.
    pub snapshot_bytes: u64,
    /// Live keys and values of all tables (`StoreStatus::data_bytes`).
    pub data_bytes: u64,
    /// `state_bytes / data_bytes` while running; includes redb's growth slack (see the module
    /// documentation).
    pub state_ratio: Option<f64>,
    /// The state file when the store opened (before any write of this run).
    pub state_bytes_at_open: u64,
    /// `state_bytes_at_open` over the live data at open; the figure the re-seed rule (about
    /// 2.0, ADR 0002) applies to after a clean shutdown.
    pub state_ratio_at_open: Option<f64>,
}

/// `numerator / denominator` for byte counts, `None` without data.
fn byte_ratio(numerator: u64, denominator: u64) -> Option<f64> {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a ratio of byte counts; f64 is exact far beyond any disk"
    )]
    let ratio = (denominator > 0).then(|| numerator as f64 / denominator as f64);
    ratio
}

/// The result of [`RaftStore::reseed_in_place`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reseeded {
    /// The state file before.
    pub bytes_before: u64,
    /// The fresh state file.
    pub bytes_after: u64,
    /// How long writes waited.
    pub duration: Duration,
}

/// The openraft-over-redb store. Cloning is cheap and shares the store.
#[derive(Clone)]
pub struct RaftStore {
    inner: Arc<Inner>,
}

/// A weak handle (used by transports so they never keep a store alive).
#[derive(Clone)]
pub struct WeakRaftStore {
    inner: Weak<Inner>,
}

impl WeakRaftStore {
    /// The store, if it is still open somewhere.
    pub fn upgrade(&self) -> Option<RaftStore> {
        self.inner.upgrade().map(|inner| RaftStore { inner })
    }
}

struct Inner {
    config: RaftStoreConfig,
    raft: Raft,
    sm: StateMachine,
    log: LogStore,
    queue: Mutex<Option<mpsc::Sender<Queued>>>,
    shutdown: Arc<AtomicBool>,
    closed: AtomicBool,
    fsync: Option<FsyncProbe>,
    disk_bytes: AtomicU64,
    log_bytes: AtomicU64,
    sm_file_bytes: AtomicU64,
    snapshot_bytes: AtomicU64,
    /// State file bytes and live data bytes when the store opened.
    at_open: (u64, u64),
    coalescer: Arc<CoalescerStats>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    /// A temporary data directory removed when the store is dropped.
    temp_dir: Option<PathBuf>,
}

impl std::fmt::Debug for RaftStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaftStore")
            .field("node", &self.inner.config.node_id)
            .field("data_dir", &self.inner.config.data_dir)
            .field("revision", &self.inner.sm.meta().revision)
            .finish_non_exhaustive()
    }
}

/// Why receiving a snapshot failed.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotInstallError {
    /// Writing the received chunks failed.
    #[error("snapshot transfer failed: {0}")]
    Io(#[from] io::Error),
    /// The Raft node stopped.
    #[error(transparent)]
    Fatal(Box<Fatal<RaftNodeId>>),
}

/// Receives a snapshot in chunks into a file and installs it (the receiving side of
/// [`network::PeerTransport::full_snapshot`]).
pub struct SnapshotReceiver {
    raft: Raft,
    path: PathBuf,
    file: Option<tokio::io::BufWriter<tokio::fs::File>>,
}

impl std::fmt::Debug for SnapshotReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotReceiver")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SnapshotReceiver {
    /// Appends the next chunk.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of the write.
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> io::Result<()> {
        match &mut self.file {
            Some(file) => file.write_all(chunk).await,
            None => Err(io::Error::other("snapshot receiver is finished")),
        }
    }

    /// Syncs the received file and installs it with the sender's vote.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be synced, or the node's fatal error.
    pub async fn install(
        mut self,
        vote: Vote,
        meta: SnapshotMeta,
    ) -> Result<openraft::raft::SnapshotResponse<RaftNodeId>, SnapshotInstallError> {
        let Some(mut file) = self.file.take() else {
            return Err(io::Error::other("snapshot receiver is finished").into());
        };
        file.flush().await?;
        file.get_ref().sync_all().await?;
        drop(file);
        let snapshot = Snapshot {
            meta,
            snapshot: Box::new(SnapshotFile {
                path: self.path.clone(),
            }),
        };
        let result = self.raft.install_full_snapshot(vote, snapshot).await;
        // Installed snapshots are renamed; a rejected one is left behind as a `.part` file.
        let _ = fs::remove_file(&self.path);
        result.map_err(|fatal| SnapshotInstallError::Fatal(Box::new(fatal)))
    }
}

impl Drop for SnapshotReceiver {
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn open_error(what: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Storage(format!("{what}: {error}"))
}

/// A unique directory for a temporary store.
fn temp_store_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    temp_root().join(format!(
        "store-{}-{nanos:x}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

fn temp_root() -> PathBuf {
    std::env::temp_dir().join("tenko-store-temp")
}

/// Removes temporary store directories left behind more than an hour ago (a test process
/// that exited before its stores were closed).
fn sweep_temp_dirs() {
    let Ok(entries) = fs::read_dir(temp_root()) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let old = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > Duration::from_secs(3_600));
        if old {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

fn raft_config(config: &RaftStoreConfig) -> Result<openraft::Config, StoreError> {
    let raft = openraft::Config {
        cluster_name: "tenko".to_owned(),
        heartbeat_interval: config.timings.heartbeat_ms,
        election_timeout_min: config.timings.election_min_ms,
        election_timeout_max: config.timings.election_max_ms,
        // Snapshots are triggered by the maintenance task (entries and log bytes).
        snapshot_policy: openraft::SnapshotPolicy::Never,
        max_in_snapshot_log_to_keep: config.snapshot.keep_entries,
        purge_batch_size: 1,
        max_payload_entries: 64,
        install_snapshot_timeout: 30 * 60 * 1_000,
        ..openraft::Config::default()
    };
    raft.validate()
        .map_err(|error| open_error("invalid Raft configuration", error))
}

impl RaftStore {
    /// Opens (or creates) a single-node store without peers.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the data directory cannot be opened, the audit
    /// chain does not verify, or Raft does not start.
    pub async fn open(config: RaftStoreConfig) -> Result<Self, StoreError> {
        Self::open_with(config, Arc::new(NoPeers)).await
    }

    /// Opens a store in a fresh directory under `std::env::temp_dir()`, removed when the
    /// last handle is dropped (tests and benchmarks). `config.data_dir` is replaced.
    ///
    /// # Errors
    ///
    /// As [`RaftStore::open`].
    pub async fn open_temp(mut config: RaftStoreConfig) -> Result<Self, StoreError> {
        sweep_temp_dirs();
        if !config.data_dir.starts_with(temp_root()) {
            config.data_dir = temp_store_dir();
        }
        let dir = config.data_dir.clone();
        let store = Self::open_inner(config, Arc::new(NoPeers), Some(dir.clone())).await;
        if store.is_err() {
            let _ = fs::remove_dir_all(&dir);
        }
        store
    }

    /// Opens (or creates) a store that reaches its peers through `transport`.
    ///
    /// With `bootstrap`, an empty store initializes a single-voter cluster, and every open
    /// waits until this node leads and has re-applied its log, so the first read sees every
    /// write committed before the restart.
    ///
    /// # Errors
    ///
    /// As [`RaftStore::open`].
    pub async fn open_with(
        config: RaftStoreConfig,
        transport: Arc<dyn PeerTransport>,
    ) -> Result<Self, StoreError> {
        Self::open_inner(config, transport, None).await
    }

    async fn open_inner(
        config: RaftStoreConfig,
        transport: Arc<dyn PeerTransport>,
        temp_dir: Option<PathBuf>,
    ) -> Result<Self, StoreError> {
        let dir = config.data_dir.clone();
        fs::create_dir_all(&dir).map_err(|error| open_error("data directory", error))?;
        let samples = config.fsync_probe_samples;
        let fsync = if samples == 0 {
            None
        } else {
            let probe_dir = dir.clone();
            tokio::task::spawn_blocking(move || fsync::probe_and_report(&probe_dir, samples))
                .await
                .map_err(|error| open_error("fsync probe", error))?
        };

        let log = LogStore::open(&dir.join("log.redb"), config.log_cache_bytes)?;
        let options = SmOptions {
            cache_bytes: config.sm_cache_bytes,
            durable_apply: matches!(config.durability, SmDurability::Immediate),
            verify_full_chain: config.verify_full_audit_chain,
        };
        let sm_dir = dir.clone();
        let sm = tokio::task::spawn_blocking(move || StateMachine::open(&sm_dir, options))
            .await
            .map_err(|error| open_error("state machine", error))??;
        recover_purged_gap(&log, &sm).await?;
        // Before Raft re-applies anything: the size the re-seed rule is judged on.
        let at_open = (
            fs::metadata(sm.file_path()).map_or(0, |metadata| metadata.len()),
            sm.meta().data_bytes,
        );

        let raft_config = Arc::new(raft_config(&config)?);
        let node = config.node_id.0;
        let raft = Raft::new(
            node,
            raft_config,
            NetworkFactory { transport },
            log.clone(),
            sm.clone(),
        )
        .await
        .map_err(|error| open_error("Raft start", error))?;

        if config.bootstrap {
            bootstrap(&raft, node, &config.address).await?;
        }

        let (queue, receiver) = mpsc::channel(4_096);
        let coalescer_stats = Arc::new(CoalescerStats::default());
        let retention = (
            u64::try_from(config.journal_retention.max(1)).unwrap_or(u64::MAX),
            config.journal_max_bytes,
        );
        let coalescer = coalescer::spawn(
            raft.clone(),
            config.coalescer,
            retention,
            receiver,
            Arc::clone(&coalescer_stats),
        );
        let inner = Arc::new(Inner {
            config,
            raft,
            sm,
            log,
            queue: Mutex::new(Some(queue)),
            shutdown: Arc::new(AtomicBool::new(false)),
            closed: AtomicBool::new(false),
            fsync,
            disk_bytes: AtomicU64::new(0),
            log_bytes: AtomicU64::new(0),
            sm_file_bytes: AtomicU64::new(0),
            snapshot_bytes: AtomicU64::new(0),
            at_open,
            coalescer: coalescer_stats,
            tasks: Mutex::new(vec![coalescer]),
            temp_dir,
        });
        inner.refresh_sizes();
        let maintenance = tokio::spawn(maintain(Arc::downgrade(&inner)));
        lock(&inner.tasks).push(maintenance);
        Ok(Self { inner })
    }

    /// This node's id.
    pub fn node_id(&self) -> NodeId {
        self.inner.config.node_id
    }

    /// The configuration.
    pub fn config(&self) -> &RaftStoreConfig {
        &self.inner.config
    }

    /// The start-up fsync probe of the data directory (`None` if it did not run).
    pub fn fsync_probe(&self) -> Option<FsyncProbe> {
        self.inner.fsync
    }

    /// The openraft handle (membership, metrics; for tooling and tests).
    pub fn raft(&self) -> &Raft {
        &self.inner.raft
    }

    /// A weak handle.
    pub fn downgrade(&self) -> WeakRaftStore {
        WeakRaftStore {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// The current snapshot file and its metadata, if a snapshot exists (backup tooling and
    /// tests; the file stays valid until the snapshot after next replaces it).
    pub fn current_snapshot(&self) -> Option<(SnapshotMeta, PathBuf)> {
        self.inner.sm.current_snapshot()
    }

    /// Engine counters.
    pub fn engine_stats(&self) -> EngineStats {
        let log = self.inner.log.stats();
        let sm = self.inner.sm.stats();
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        EngineStats {
            entries_proposed: load(&self.inner.coalescer.entries),
            batches_proposed: load(&self.inner.coalescer.batches),
            log_commits: log.commits,
            log_entries: log.entries,
            log_appended_bytes: log.appended_bytes,
            snapshots_built: load(&sm.snapshots_built),
            last_snapshot_bytes: load(&sm.last_snapshot_bytes),
            last_snapshot_build_micros: load(&sm.last_build_micros),
            snapshots_installed: load(&sm.snapshots_installed),
            last_install_micros: load(&sm.last_install_micros),
            last_index_rebuild_micros: load(&sm.last_index_rebuild_micros),
            last_compact_micros: load(&sm.last_compact_micros),
            reseeds_in_place: load(&sm.rewrites),
            checkpoints: load(&sm.checkpoints),
        }
    }

    /// Bytes on disk and the state file ratio, from the size cache.
    pub fn disk_usage(&self) -> DiskUsage {
        let inner = &self.inner;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let state_bytes = load(&inner.sm_file_bytes);
        let data_bytes = inner.sm.meta().data_bytes;
        DiskUsage {
            log_bytes: load(&inner.log_bytes),
            state_bytes,
            snapshot_bytes: load(&inner.snapshot_bytes),
            data_bytes,
            state_ratio: byte_ratio(state_bytes, data_bytes),
            state_bytes_at_open: inner.at_open.0,
            state_ratio_at_open: byte_ratio(inner.at_open.0, inner.at_open.1),
        }
    }

    /// Re-seeds this node from its own state: rewrites the state into a fresh, compacted
    /// file and switches to it atomically (see the module documentation for when to do it).
    /// Writes wait until it is done; reads, watches and indexes are not interrupted, and the
    /// state does not change.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ShuttingDown`], or a storage error; the old file then stays in
    /// use unchanged.
    pub async fn reseed_in_place(&self) -> Result<Reseeded, StoreError> {
        self.inner.check_running()?;
        let sm = self.inner.sm.clone();
        let rewritten = tokio::task::spawn_blocking(move || sm.rewrite_in_place())
            .await
            .map_err(|error| StoreError::Storage(error.to_string()))??;
        self.inner.refresh_sizes();
        Ok(Reseeded {
            bytes_before: rewritten.bytes_before,
            bytes_after: rewritten.bytes_after,
            duration: Duration::from_micros(rewritten.micros),
        })
    }

    /// Builds a snapshot now and waits until it is current (the log behind it is then
    /// purged per the policy).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Timeout`] if the snapshot does not complete within the write
    /// timeout, or [`StoreError::ShuttingDown`].
    pub async fn snapshot_now(&self) -> Result<(), StoreError> {
        self.inner.check_running()?;
        let raft = &self.inner.raft;
        let applied = raft.metrics().borrow().last_applied;
        raft.trigger()
            .snapshot()
            .await
            .map_err(|_| StoreError::ShuttingDown)?;
        raft.wait(Some(self.inner.config.write_timeout))
            .metrics(
                |metrics| metrics.snapshot >= applied,
                "snapshot covers the applied log",
            )
            .await
            .map_err(|_| StoreError::Timeout)?;
        Ok(())
    }

    /// Adds a learner that catches up from the log or a snapshot (Slice 3 grows a cluster
    /// this way). Waits until it has caught up when `blocking`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NoQuorum`] if this node is not the leader, or a storage error.
    pub async fn add_learner(
        &self,
        node: NodeId,
        address: impl Into<String>,
        blocking: bool,
    ) -> Result<(), StoreError> {
        self.inner
            .raft
            .add_learner(node.0, BasicNode::new(address.into()), blocking)
            .await
            .map(|_| ())
            .map_err(|error| map_membership_error(&error))
    }

    /// Changes the voters (joint consensus); learners not listed stay learners.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NoQuorum`] if this node is not the leader, or a storage error.
    pub async fn change_membership(&self, voters: BTreeSet<NodeId>) -> Result<(), StoreError> {
        let voters: BTreeSet<RaftNodeId> = voters.into_iter().map(|node| node.0).collect();
        self.inner
            .raft
            .change_membership(voters, true)
            .await
            .map(|_| ())
            .map_err(|error| map_membership_error(&error))
    }

    /// Handles a replication request from the leader (receiving side of a transport).
    ///
    /// # Errors
    ///
    /// Returns openraft's error for the sender.
    #[allow(
        clippy::result_large_err,
        reason = "openraft's error, passed through unchanged to the transport"
    )]
    pub async fn handle_append_entries(
        &self,
        rpc: openraft::raft::AppendEntriesRequest<types::TypeConfig>,
    ) -> Result<
        openraft::raft::AppendEntriesResponse<RaftNodeId>,
        openraft::error::RaftError<RaftNodeId>,
    > {
        self.inner.raft.append_entries(rpc).await
    }

    /// Handles a vote request (receiving side of a transport).
    ///
    /// # Errors
    ///
    /// Returns openraft's error for the sender.
    #[allow(
        clippy::result_large_err,
        reason = "openraft's error, passed through unchanged to the transport"
    )]
    pub async fn handle_vote(
        &self,
        rpc: openraft::raft::VoteRequest<RaftNodeId>,
    ) -> Result<openraft::raft::VoteResponse<RaftNodeId>, openraft::error::RaftError<RaftNodeId>>
    {
        self.inner.raft.vote(rpc).await
    }

    /// Starts receiving a snapshot (receiving side of a transport): write the chunks, then
    /// [`SnapshotReceiver::install`].
    ///
    /// # Errors
    ///
    /// Returns the I/O error of creating the file.
    pub fn receive_snapshot(&self) -> io::Result<SnapshotReceiver> {
        let path = self.inner.sm.receive_path();
        let file = std::fs::File::create(&path)?;
        Ok(SnapshotReceiver {
            raft: self.inner.raft.clone(),
            path,
            file: Some(tokio::io::BufWriter::with_capacity(
                network::SNAPSHOT_CHUNK,
                tokio::fs::File::from_std(file),
            )),
        })
    }

    /// Stops the store cleanly: refuses new proposals, lets queued entries finish, stops
    /// Raft, makes the state durable and closes both databases once every internal handle
    /// is gone. Read views still held by callers keep `sm.redb` open until they drop.
    ///
    /// # Errors
    ///
    /// Returns the storage error of the final checkpoint.
    pub async fn shutdown(&self) -> Result<(), StoreError> {
        let inner = &self.inner;
        if inner.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // Close the queue: the coalescer proposes what is queued and ends.
        drop(lock(&inner.queue).take());
        let coalescer = lock(&inner.tasks).drain(..).collect::<Vec<_>>();
        let mut handles = coalescer.into_iter();
        if let Some(coalescer) = handles.next() {
            let _ = tokio::time::timeout(inner.config.write_timeout, coalescer).await;
        }
        for task in handles {
            task.abort();
        }
        inner.shutdown.store(true, Ordering::SeqCst);
        let _ = inner.raft.shutdown().await;
        let sm = inner.sm.clone();
        let checkpoint = tokio::task::spawn_blocking(move || sm.checkpoint())
            .await
            .map_err(|error| StoreError::Storage(error.to_string()))?;
        inner.sm.wake_all();
        inner.log.shutdown();
        // openraft's state machine worker and replication tasks release their handles
        // shortly after the core stops.
        let deadline = Instant::now() + Duration::from_secs(10);
        while (inner.sm.handles() > 1 || inner.log.handles() > 1) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        checkpoint
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

type MembershipError = openraft::error::RaftError<
    RaftNodeId,
    openraft::error::ClientWriteError<RaftNodeId, BasicNode>,
>;

fn map_membership_error(error: &MembershipError) -> StoreError {
    match error {
        openraft::error::RaftError::APIError(
            openraft::error::ClientWriteError::ForwardToLeader(_),
        ) => StoreError::NoQuorum,
        openraft::error::RaftError::Fatal(_) => StoreError::ShuttingDown,
        openraft::error::RaftError::APIError(_) => StoreError::Storage(error.to_string()),
    }
}

/// Initializes an empty single-voter cluster, or speeds up the election of a single voter
/// after a restart, then waits until this node leads and has applied its whole log.
async fn bootstrap(raft: &Raft, node: RaftNodeId, address: &str) -> Result<(), StoreError> {
    let initialized = raft
        .is_initialized()
        .await
        .map_err(|error| open_error("Raft state", error))?;
    if initialized {
        let sole_voter = {
            let metrics = raft.metrics().borrow().clone();
            let voters: BTreeSet<RaftNodeId> =
                metrics.membership_config.membership().voter_ids().collect();
            voters.len() == 1 && voters.contains(&node)
        };
        if sole_voter {
            raft.trigger()
                .elect()
                .await
                .map_err(|error| open_error("Raft election", error))?;
        }
    } else {
        let members = BTreeMap::from([(node, BasicNode::new(address))]);
        match raft.initialize(members).await {
            Ok(()) | Err(openraft::error::RaftError::APIError(_)) => {}
            Err(error) => return Err(open_error("Raft initialization", error)),
        }
    }
    raft.wait(Some(Duration::from_secs(60)))
        .metrics(
            |metrics| {
                let applied = metrics.last_applied.map(|log_id| log_id.index);
                metrics.current_leader == Some(node)
                    && metrics.state == ServerState::Leader
                    && applied >= metrics.last_log_index
            },
            "leader with the log applied",
        )
        .await
        .map_err(|error| open_error("waiting for leadership", error))?;
    Ok(())
}

/// If the durable state machine is behind the purged log (which the checkpoint before every
/// snapshot prevents), reinstalls the current snapshot so openraft can replay the rest.
async fn recover_purged_gap(log: &LogStore, sm: &StateMachine) -> Result<(), StoreError> {
    let purged = log
        .last_purged()
        .map_err(|error| open_error("log state", error))?;
    let applied = sm.meta().last_applied;
    if purged <= applied {
        return Ok(());
    }
    match sm.current_snapshot() {
        Some((meta, path)) if meta.last_log_id >= purged => {
            tracing::warn!(
                snapshot = %meta.snapshot_id,
                "the state machine is behind the purged log; reinstalling the current snapshot"
            );
            let sm = sm.clone();
            tokio::task::spawn_blocking(move || sm.install(&meta, &path))
                .await
                .map_err(|error| open_error("snapshot recovery", error))?
                .map_err(|error| open_error("snapshot recovery", error))
        }
        _ => Err(StoreError::Storage(
            "the state machine is behind the purged log and no snapshot covers it".to_owned(),
        )),
    }
}

impl Inner {
    fn check_running(&self) -> Result<(), StoreError> {
        if self.shutdown.load(Ordering::SeqCst) || self.closed.load(Ordering::SeqCst) {
            Err(StoreError::ShuttingDown)
        } else {
            Ok(())
        }
    }

    fn refresh_sizes(&self) {
        let size = |path: &std::path::Path| fs::metadata(path).map_or(0, |m| m.len());
        let log = size(&self.config.data_dir.join("log.redb"));
        let state = size(&self.sm.file_path());
        let snapshots = sm::dir_bytes(self.sm.snapshot_dir());
        self.log_bytes.store(log, Ordering::Relaxed);
        self.sm_file_bytes.store(state, Ordering::Relaxed);
        self.snapshot_bytes.store(snapshots, Ordering::Relaxed);
        self.disk_bytes
            .store(log + state + snapshots, Ordering::Relaxed);
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.sm.wake_all();
        if !self.closed.load(Ordering::SeqCst)
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let raft = self.raft.clone();
            runtime.spawn(async move {
                let _ = raft.shutdown().await;
            });
        }
        if let Some(dir) = self.temp_dir.take() {
            // Raft tasks still hold the files; they release them when they stop (at the
            // latest when the runtime drops them). A blocking task retries the removal, and a
            // runtime waits for its blocking tasks when it is dropped.
            let janitor = move || remove_when_released(&dir);
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => drop(runtime.spawn_blocking(janitor)),
                Err(_) => drop(std::thread::spawn(janitor)),
            }
        }
    }
}

/// Removes a temporary store directory once its files are closed (gives up after 30 s; a
/// later `open_temp` sweeps what is left).
fn remove_when_released(dir: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match fs::remove_dir_all(dir) {
            Ok(()) => return,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                tracing::debug!(dir = %dir.display(), %error, "temporary store left behind");
                return;
            }
        }
    }
}

/// Periodic work: cached sizes, durable checkpoints and the snapshot trigger.
async fn maintain(inner: Weak<Inner>) {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_sizes = Instant::now();
    let mut last_checkpoint = Instant::now();
    let mut last_trigger: Option<Instant> = None;
    let mut log_bytes_at_snapshot: Option<u64> = None;
    loop {
        tick.tick().await;
        let Some(inner) = inner.upgrade() else {
            return;
        };
        if inner.check_running().is_err() {
            return;
        }
        if last_sizes.elapsed() >= inner.config.status_refresh {
            last_sizes = Instant::now();
            inner.refresh_sizes();
        }
        if let SmDurability::Deferred {
            checkpoint_interval,
        } = inner.config.durability
            && last_checkpoint.elapsed() >= checkpoint_interval
        {
            last_checkpoint = Instant::now();
            let sm = inner.sm.clone();
            if let Ok(Err(error)) = tokio::task::spawn_blocking(move || sm.checkpoint()).await {
                tracing::error!(%error, "store checkpoint failed");
            }
        }
        // Snapshot-and-purge.
        let (applied, snapshot) = {
            let metrics = inner.raft.metrics();
            let metrics = metrics.borrow();
            (
                metrics.last_applied.map_or(0, |log_id| log_id.index),
                metrics.snapshot.map_or(0, |log_id| log_id.index),
            )
        };
        let log_bytes = inner.log.stats().appended_bytes;
        let since_bytes = log_bytes.saturating_sub(*log_bytes_at_snapshot.get_or_insert(log_bytes));
        let policy = inner.config.snapshot;
        let due = applied.saturating_sub(snapshot) >= policy.every_entries
            || since_bytes >= policy.every_log_bytes;
        let settled = last_trigger.is_none_or(|at| at.elapsed() >= Duration::from_secs(1));
        if due && settled {
            last_trigger = Some(Instant::now());
            log_bytes_at_snapshot = Some(log_bytes);
            let _ = inner.raft.trigger().snapshot().await;
        }
    }
}

#[async_trait::async_trait]
impl Store for RaftStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        let inner = &self.inner;
        inner.check_running()?;
        batch.validate(inner.config.coalescer.max_batch_bytes)?;
        let fingerprint = match &batch.idempotency {
            Some(_) => Some(batch.fingerprint()?),
            None => None,
        };
        let encoded = to_cbor(&batch)?;
        let sender = lock(&inner.queue).clone().ok_or(StoreError::ShuttingDown)?;
        let (reply, answer) = oneshot::channel();
        sender
            .send(Queued {
                batch: ProposedBatch {
                    batch: encoded,
                    fingerprint,
                },
                reply,
            })
            .await
            .map_err(|_| StoreError::ShuttingDown)?;
        drop(sender);
        match tokio::time::timeout(inner.config.write_timeout, answer).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(StoreError::ShuttingDown),
            Err(_) => Err(StoreError::Timeout),
        }
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        let inner = &self.inner;
        inner.check_running()?;
        match consistency {
            ReadConsistency::Local => {}
            ReadConsistency::AtLeast(target) => {
                let mut applied = inner.sm.subscribe();
                let reached = async {
                    loop {
                        if *applied.borrow_and_update() >= target {
                            return Ok(());
                        }
                        if applied.changed().await.is_err() {
                            return Err(StoreError::ShuttingDown);
                        }
                        inner.check_running()?;
                    }
                };
                tokio::time::timeout(inner.config.read_wait, reached)
                    .await
                    .map_err(|_| StoreError::Timeout)??;
            }
            ReadConsistency::Linearizable => {
                let confirmed =
                    tokio::time::timeout(inner.config.read_wait, inner.raft.ensure_linearizable())
                        .await
                        .map_err(|_| StoreError::Timeout)?;
                confirmed.map_err(|error| match error {
                    openraft::error::RaftError::Fatal(_) => StoreError::ShuttingDown,
                    openraft::error::RaftError::APIError(_) => StoreError::NoQuorum,
                })?;
            }
        }
        Ok(Arc::new(inner.sm.view()?))
    }

    fn watch(
        &self,
        from: Option<Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        let inner = &self.inner;
        inner.check_running()?;
        watch::watch(
            &inner.sm,
            Arc::clone(&inner.shutdown),
            inner.config.watch_max_lag,
            from,
            filter,
        )
    }

    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        self.inner.check_running()?;
        self.inner.sm.register_index(index)
    }

    fn status(&self) -> StoreStatus {
        let inner = &self.inner;
        let (role, leader, lag) = {
            let metrics = inner.raft.metrics();
            let metrics = metrics.borrow();
            let role = match metrics.state {
                ServerState::Leader => StoreRole::Leader,
                ServerState::Follower => StoreRole::Follower,
                ServerState::Learner => StoreRole::Learner,
                ServerState::Candidate => StoreRole::Candidate,
                ServerState::Shutdown => StoreRole::Shutdown,
            };
            let applied = metrics.last_applied.map_or(0, |log_id| log_id.index);
            let lag = metrics
                .last_log_index
                .map(|last| last.saturating_sub(applied))
                .or(Some(0));
            (role, metrics.current_leader.map(NodeId), lag)
        };
        let role = if inner.check_running().is_err() {
            StoreRole::Shutdown
        } else {
            role
        };
        let meta = inner.sm.meta();
        StoreStatus {
            role,
            node: Some(inner.config.node_id),
            leader,
            revision: meta.revision,
            lag,
            audit_head: meta.audit_head.seq,
            journal_oldest: meta.journal_oldest,
            journal_len: meta.journal_len,
            data_bytes: meta.data_bytes,
            disk_bytes: Some(inner.disk_bytes.load(Ordering::Relaxed)),
            sm_file_bytes: Some(inner.sm_file_bytes.load(Ordering::Relaxed)),
            fsync_p50_micros: inner.fsync.map(|probe| probe.p50_micros()),
            indexes: inner.sm.index_statuses(),
        }
    }
}
