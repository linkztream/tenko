//! Result types shared by the benchmark phases, the child-process protocol (JSON) and the
//! Markdown report writer. Pure data: no logic lives here.

use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MachineInfo {
    pub os: String,
    pub cpu_brand: String,
    pub logical_cpus: usize,
    pub total_memory_bytes: u64,
    pub rustc_version: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DepVersion {
    pub name: String,
    pub version: String,
}

/// Static configuration of the cluster used for a run.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunConfig {
    /// "openraft" (real openraft cluster) or "simulated" (fallback replication mode).
    pub mode: String,
    pub voters: u32,
    pub batch_records: u64,
    pub ptr_percent: u8,
    /// redb page cache configured per database file.
    pub redb_cache_bytes: u64,
    /// Where the Raft log lives, e.g. "redb (log.redb per node)".
    pub log_store: String,
    /// e.g. "Immediate (fsync per append)".
    pub log_durability: String,
    /// e.g. "Immediate (fsync per apply batch)".
    pub sm_durability: String,
    pub max_payload_entries: u64,
    /// Free-form description of how in-process RPC works.
    pub network: String,
}

/// Latency distribution, all values in nanoseconds.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LatencySummary {
    pub count: u64,
    pub min_ns: u64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeDiskUsage {
    pub node_id: u64,
    pub log_file_bytes: u64,
    pub sm_file_bytes: u64,
    /// redb statistics of sm.redb: allocated page bytes, stored key+value bytes, fragmented bytes.
    #[serde(default)]
    pub sm_allocated_bytes: u64,
    #[serde(default)]
    pub sm_stored_bytes: u64,
    #[serde(default)]
    pub sm_fragmented_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BulkLoadResult {
    /// Description of the disk holding the node data.
    #[serde(default)]
    pub disk: String,
    /// A records in the single forward zone `example.test`.
    pub forward_zone_records: u64,
    /// All RRsets loaded (forward + PTR).
    pub total_records: u64,
    pub voters: u32,
    pub batch_records: u64,
    /// Number of Raft entries proposed for the load.
    pub raft_entries: u64,
    pub wall_secs: f64,
    pub records_per_sec: f64,
    /// Peak process RSS sampled during the load phase (whole process: all in-process nodes).
    pub peak_rss_bytes: u64,
    /// Process RSS right after the load finished.
    pub rss_after_bytes: u64,
    /// Process RSS before the cluster was started.
    pub rss_before_bytes: u64,
    /// Sum over records of encoded key + value bytes (what the state machine stores logically).
    pub raw_kv_bytes: u64,
    pub avg_entry_bytes: f64,
    pub per_node: Vec<NodeDiskUsage>,
    /// Entries in the serving index of one node.
    pub index_entries: u64,
    /// Computed estimate of the heap held by one node's serving index.
    pub index_estimated_bytes: u64,
    /// Bytes the whole process passed to write calls during the load (all nodes; OS I/O counters).
    #[serde(default)]
    pub process_written_bytes: u64,
    /// Offline compaction of one follower sm.redb after the run, if measured.
    #[serde(default)]
    pub compaction: Option<CompactionResult>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CompactionResult {
    pub node_id: u64,
    pub file_bytes_before: u64,
    pub file_bytes_after: u64,
    pub compact_secs: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CatchUpResult {
    #[serde(default)]
    pub disk: String,
    pub total_records: u64,
    pub snapshot_build_secs: f64,
    pub snapshot_bytes: u64,
    /// In-process transfer (file copy through the in-process network) time.
    pub snapshot_transfer_secs: f64,
    /// Time inside the learner's install_snapshot (redb load + index rebuild).
    pub snapshot_install_secs: f64,
    /// Part of the install spent rebuilding the in-memory serving index.
    pub index_rebuild_secs: f64,
    /// From add_learner() until the learner's last applied log id equals the leader's.
    pub total_catch_up_secs: f64,
    /// snapshot_bytes / 125 MB/s.
    pub theoretical_1gbit_secs: f64,
    pub learner_sm_file_bytes: u64,
    /// Peak process RSS sampled during the catch-up phase.
    pub peak_rss_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LatencyRun {
    pub label: String,
    pub lookup_target_rate: u64,
    pub lookup_achieved_rate: f64,
    pub duration_secs: f64,
    pub lookup_latency: LatencySummary,
    pub write_target_rate: u64,
    pub write_achieved_rate: f64,
    /// client_write() round-trip latency (propose -> committed and applied on the leader).
    pub write_latency: Option<LatencySummary>,
    pub write_errors: u64,
    /// Average number of logical CPUs kept busy by OTHER processes on the machine during the
    /// window (machine-wide busy CPUs minus this process), from OS CPU counters.
    #[serde(default)]
    pub other_cpu_busy: Option<f64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SteadyStateResult {
    #[serde(default)]
    pub disk: String,
    pub total_records: u64,
    pub baseline: LatencyRun,
    pub under_writes: LatencyRun,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChangeFeedResult {
    #[serde(default)]
    pub disk: String,
    /// RRsets in the cluster when the change feed was read.
    #[serde(default)]
    pub total_records: u64,
    pub changes_requested: u64,
    /// Approach used for the primary number, e.g. "change-journal table in the state machine".
    pub approach: String,
    pub journal_changes_read: u64,
    pub journal_secs: f64,
    pub journal_bytes: u64,
    /// Same enumeration done from the Raft log, if the log still held the entries.
    pub log_changes_read: Option<u64>,
    pub log_secs: Option<f64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Criterion {
    pub name: String,
    pub threshold: String,
    pub measured: String,
    pub pass: bool,
}

/// Everything one `all` run produced.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Results {
    /// ISO date of the run, e.g. "2026-10-09".
    pub date: String,
    pub machine: MachineInfo,
    pub deps: Vec<DepVersion>,
    pub config: RunConfig,
    /// Per-node RSS runs (single voter, one node per process) are included here too.
    pub bulk_loads: Vec<BulkLoadResult>,
    pub catch_ups: Vec<CatchUpResult>,
    pub steady: Vec<SteadyStateResult>,
    pub change_feed: Vec<ChangeFeedResult>,
    pub criteria: Vec<Criterion>,
    pub notes: Vec<String>,
}
