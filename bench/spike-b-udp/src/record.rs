//! Machine-readable result records shared by `load`, `matrix` and `report`.
//!
//! One [`RunRecord`] is written per run as one JSON line (JSONL).

use serde::{Deserialize, Serialize};

/// Latency percentiles in microseconds (from an HDR histogram, 3 significant digits).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LatencyUs {
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub p999: f64,
    pub max: f64,
    pub mean: f64,
}

/// Resource usage of the server process during the measurement window,
/// sampled from outside the process with `sysinfo`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerStats {
    pub pid: u32,
    /// CPU time (user + kernel) consumed by the server during the measurement window, seconds.
    pub cpu_seconds: f64,
    /// `cpu_seconds / measured_seconds`: average number of busy cores.
    pub cpu_cores: f64,
    /// Highest resident set size (Windows: working set) seen while sampling every 100 ms, MiB.
    pub peak_rss_mib: f64,
    /// Resident set size at the end of the measurement window, MiB.
    pub end_rss_mib: f64,
}

/// Result of one load-generator run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoadResult {
    pub target: String,
    pub clients: usize,
    pub inflight: usize,
    pub edns: bool,
    pub nx_percent: f64,
    pub warmup_seconds: f64,
    pub measured_seconds: f64,
    /// Queries sent during the measurement window.
    pub sent: u64,
    /// Valid, matched responses received during the measurement window.
    pub received: u64,
    /// Queries that got no response within the timeout (measurement window only).
    pub timeouts: u64,
    /// Responses that matched an outstanding ID but were invalid (malformed,
    /// wrong RCODE for the name, wrong answer count, TC set).
    pub errors: u64,
    /// Responses whose ID was not outstanding (e.g. arrived after a timeout).
    pub unexpected: u64,
    /// `send` calls that failed.
    pub send_errors: u64,
    /// `received / measured_seconds`.
    pub qps: f64,
    pub latency_us: LatencyUs,
    /// Present when `--server-pid` was given.
    pub server: Option<ServerStats>,
    /// CPU used by the load generator itself during the window, in cores.
    pub client_cpu_cores: Option<f64>,
}

/// One line of a results JSONL file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunRecord {
    /// RFC 3339 UTC timestamp at the end of the run.
    pub timestamp: String,
    /// `std::env::consts::OS` of the machine that ran the load.
    pub os: String,
    pub label: Option<String>,
    /// `domain` or `hickory`.
    pub backend: Option<String>,
    /// `tokio` or `threads`.
    pub mode: Option<String>,
    pub workers: Option<usize>,
    pub reuseport: Option<bool>,
    pub result: LoadResult,
}
