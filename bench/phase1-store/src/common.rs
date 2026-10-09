//! Shared helpers: scratch directories, random numbers, latency summaries, disk sizes,
//! machine information, process memory sampling and result files.

use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};
use sysinfo::{
    CpuRefreshKind, Disks, MemoryRefreshKind, Pid, ProcessRefreshKind, ProcessesToUpdate, System,
};
use tenko_core::Timestamp;
use tenko_store::{
    Store, WriteBatch,
    raft::{RaftStore, SnapshotInstallError},
};
use tokio::task::JoinSet;

pub const MIB: u64 = 1 << 20;
pub const GIB: u64 = 1 << 30;

// ---------------------------------------------------------------------------------------------
// Random numbers
// ---------------------------------------------------------------------------------------------

/// The splitmix64 output function.
pub fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A small deterministic generator (splitmix64).
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        let out = mix(self.0);
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        out
    }

    /// A value in `0..n` (`n` must be positive).
    pub fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0);
        u64::try_from((u128::from(self.next_u64()) * u128::from(n)) >> 64).unwrap_or(0)
    }

    /// A value in `low..=high`.
    pub fn between(&mut self, low: u64, high: u64) -> u64 {
        low + self.below(high - low + 1)
    }

    /// Moves `count` distinct random elements of `items` to its front (partial Fisher-Yates)
    /// and returns them.
    pub fn sample<'a>(&mut self, items: &'a mut [u64], count: usize) -> &'a [u64] {
        let count = count.min(items.len());
        for i in 0..count {
            let remaining = u64::try_from(items.len() - i).unwrap_or(1);
            let j = i + usize::try_from(self.below(remaining)).unwrap_or(0);
            items.swap(i, j);
        }
        &items[..count]
    }
}

// ---------------------------------------------------------------------------------------------
// Scratch directories
// ---------------------------------------------------------------------------------------------

/// A directory under the data root, removed on drop. Stores close their files shortly after
/// `shutdown`, so removal is retried for a while.
#[derive(Debug)]
pub struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    pub fn new(root: &Path, name: &str) -> Result<Self> {
        let path = root.join(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The data directory of one node.
    pub fn node(&self, node: u64) -> PathBuf {
        self.path.join(format!("node-{node}"))
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        for _ in 0..400 {
            if fs::remove_dir_all(&self.path).is_ok() || !self.path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        eprintln!("warning: could not remove {}", self.path.display());
    }
}

/// The default data root: a directory under the system temporary directory.
pub fn default_data_root() -> PathBuf {
    std::env::temp_dir().join("tenko-phase1-bench")
}

// ---------------------------------------------------------------------------------------------
// Latency
// ---------------------------------------------------------------------------------------------

/// A histogram of nanoseconds, up to two minutes.
pub fn new_hist() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 120_000_000_000, 3).expect("histogram bounds are valid")
}

pub fn record_ns(hist: &mut Histogram<u64>, nanos: u128) {
    hist.saturating_record(u64::try_from(nanos).unwrap_or(u64::MAX).max(1));
}

/// A latency summary in nanoseconds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Latency {
    pub count: u64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
}

pub fn summarize(hist: &Histogram<u64>) -> Latency {
    if hist.is_empty() {
        return Latency::default();
    }
    Latency {
        count: hist.len(),
        p50_ns: hist.value_at_quantile(0.50),
        p90_ns: hist.value_at_quantile(0.90),
        p99_ns: hist.value_at_quantile(0.99),
        p999_ns: hist.value_at_quantile(0.999),
        max_ns: hist.max(),
        mean_ns: hist.mean(),
    }
}

/// The median of a list (the mean of the two middle values for an even count).
pub fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted[middle]
    } else {
        f64::midpoint(sorted[middle - 1], sorted[middle])
    }
}

// ---------------------------------------------------------------------------------------------
// Disk usage
// ---------------------------------------------------------------------------------------------

/// Sizes of the files of one store data directory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskSizes {
    pub sm_redb: u64,
    pub log_redb: u64,
    pub snapshots: u64,
}

pub fn dir_bytes(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| match entry.metadata() {
            Ok(metadata) if metadata.is_file() => metadata.len(),
            Ok(metadata) if metadata.is_dir() => dir_bytes(&entry.path()),
            _ => 0,
        })
        .sum()
}

pub fn disk_sizes(data_dir: &Path) -> DiskSizes {
    let file = |name: &str| fs::metadata(data_dir.join(name)).map_or(0, |m| m.len());
    DiskSizes {
        sm_redb: file("sm.redb"),
        log_redb: file("log.redb"),
        snapshots: dir_bytes(&data_dir.join("snapshots")),
    }
}

/// Free space of the volume that holds `path`, if it can be determined.
pub fn free_space(path: &Path) -> Option<u64> {
    let disks = Disks::new_with_refreshed_list();
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let wanted = canonical
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_ascii_lowercase();
    disks
        .iter()
        .filter(|disk| {
            let mount = disk.mount_point().to_string_lossy().to_ascii_lowercase();
            wanted.starts_with(&mount)
        })
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map(sysinfo::Disk::available_space)
}

// ---------------------------------------------------------------------------------------------
// Process memory
// ---------------------------------------------------------------------------------------------

fn sample_rss(system: &mut System, pid: Pid) -> u64 {
    let pids = [pid];
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&pids),
        true,
        ProcessRefreshKind::nothing().with_memory(),
    );
    system.process(pid).map_or(0, sysinfo::Process::memory)
}

/// The working set of this process in bytes.
pub fn current_rss() -> u64 {
    sample_rss(&mut System::new(), Pid::from_u32(std::process::id()))
}

/// Samples the working set of this process every 100 ms and keeps the peak.
#[derive(Debug)]
pub struct RssSampler {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicU64>,
    handle: Option<thread::JoinHandle<()>>,
}

impl RssSampler {
    pub fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(0));
        let handle = {
            let (stop, peak) = (Arc::clone(&stop), Arc::clone(&peak));
            thread::spawn(move || {
                let mut system = System::new();
                let pid = Pid::from_u32(std::process::id());
                while !stop.load(Ordering::Relaxed) {
                    peak.fetch_max(sample_rss(&mut system, pid), Ordering::Relaxed);
                    thread::sleep(Duration::from_millis(100));
                }
            })
        };
        Self {
            stop,
            peak,
            handle: Some(handle),
        }
    }

    /// Stops sampling and returns the peak working set in bytes.
    pub fn finish(mut self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.peak.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------------------------
// Machine and run information
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Machine {
    pub os: String,
    pub kernel: String,
    pub cpu: String,
    pub logical_cpus: usize,
    pub ram_bytes: u64,
    pub rustc: String,
}

pub fn machine() -> Machine {
    let mut system = System::new();
    system.refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
    system.refresh_cpu_list(CpuRefreshKind::nothing());
    let cpu = system
        .cpus()
        .first()
        .map(|cpu| cpu.brand().trim().to_owned())
        .unwrap_or_default();
    Machine {
        os: System::long_os_version().unwrap_or_default(),
        kernel: System::kernel_version().unwrap_or_default(),
        cpu,
        logical_cpus: system.cpus().len(),
        ram_bytes: system.total_memory(),
        rustc: command_output("rustc", &["-V"]),
    }
}

/// The trimmed standard output of a command ("unknown" if it cannot be run).
pub fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// When and how a measurement ran, and how busy the machine was meanwhile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunMeta {
    pub started: String,
    pub finished: String,
    pub elapsed_secs: f64,
    pub command: String,
    pub data_root: String,
    pub data_root_free_bytes_before: Option<u64>,
    /// Mean and maximum CPU use of the whole machine (percent of all logical CPUs, sampled
    /// every second), and the mean of this process alone.
    #[serde(default)]
    pub cpu_machine_mean_pct: f64,
    #[serde(default)]
    pub cpu_machine_max_pct: f64,
    #[serde(default)]
    pub cpu_self_mean_pct: f64,
}

/// Samples machine-wide and own CPU use once a second.
#[derive(Debug)]
struct CpuSampler {
    stop: Arc<AtomicBool>,
    samples: Arc<Mutex<Vec<(f32, f32)>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl CpuSampler {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let handle = {
            let (stop, samples) = (Arc::clone(&stop), Arc::clone(&samples));
            thread::spawn(move || {
                let mut system = System::new();
                let pid = Pid::from_u32(std::process::id());
                let pids = [pid];
                system.refresh_cpu_usage();
                while !stop.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_secs(1));
                    system.refresh_cpu_usage();
                    system.refresh_processes_specifics(
                        ProcessesToUpdate::Some(&pids),
                        true,
                        ProcessRefreshKind::nothing().with_cpu(),
                    );
                    let cpus = system.cpus().len().max(1);
                    #[allow(clippy::cast_precision_loss, reason = "a CPU count")]
                    let own =
                        system.process(pid).map_or(0.0, sysinfo::Process::cpu_usage) / cpus as f32;
                    samples
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push((system.global_cpu_usage(), own));
                }
            })
        };
        Self {
            stop,
            samples,
            handle: Some(handle),
        }
    }

    fn summary(&self) -> (f64, f64, f64) {
        let samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        if samples.is_empty() {
            return (0.0, 0.0, 0.0);
        }
        let count = count_f64(samples.len() as u64);
        let total: f64 = samples.iter().map(|s| f64::from(s.0)).sum();
        let own: f64 = samples.iter().map(|s| f64::from(s.1)).sum();
        let max = samples.iter().map(|s| f64::from(s.0)).fold(0.0, f64::max);
        (total / count, max, own / count)
    }
}

impl Drop for CpuSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Debug)]
pub struct RunClock {
    started_at: Timestamp,
    started: Instant,
    command: String,
    data_root: PathBuf,
    free_before: Option<u64>,
    cpu: CpuSampler,
}

impl RunClock {
    pub fn start(data_root: &Path) -> Self {
        let _ = fs::create_dir_all(data_root);
        Self {
            started_at: Timestamp::now(),
            started: Instant::now(),
            command: std::env::args().collect::<Vec<_>>().join(" "),
            data_root: data_root.to_path_buf(),
            free_before: free_space(data_root),
            cpu: CpuSampler::start(),
        }
    }

    pub fn finish(&self) -> RunMeta {
        let (mean, max, own) = self.cpu.summary();
        RunMeta {
            started: self.started_at.to_string(),
            finished: Timestamp::now().to_string(),
            elapsed_secs: self.started.elapsed().as_secs_f64(),
            command: self.command.clone(),
            data_root: self.data_root.display().to_string(),
            data_root_free_bytes_before: self.free_before,
            cpu_machine_mean_pct: mean,
            cpu_machine_max_pct: max,
            cpu_self_mean_pct: own,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------
// Result files
// ---------------------------------------------------------------------------------------------

/// Where results are written.
#[derive(Debug, Clone)]
pub struct Output {
    pub dir: PathBuf,
}

impl Output {
    pub fn raw(&self, name: &str) -> PathBuf {
        self.dir.join("raw").join(format!("{name}.json"))
    }

    pub fn write<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let path = self.raw(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, serde_json::to_vec_pretty(value)?)
            .with_context(|| format!("write {}", path.display()))?;
        println!("wrote {}", path.display());
        Ok(())
    }

    pub fn read<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<Option<T>> {
        let path = self.raw(name);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse {}", path.display()))?,
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Store helpers
// ---------------------------------------------------------------------------------------------

/// Proposes the batches with at most `inflight` proposals outstanding. Returns the number of
/// batches committed.
pub async fn propose_all(
    store: &RaftStore,
    batches: impl Iterator<Item = WriteBatch>,
    inflight: usize,
) -> Result<u64> {
    let mut set: JoinSet<Result<(), tenko_store::StoreError>> = JoinSet::new();
    let mut count = 0_u64;
    for batch in batches {
        while set.len() >= inflight {
            if let Some(done) = set.join_next().await {
                done??;
            }
        }
        let store = store.clone();
        set.spawn(async move { store.propose(batch).await.map(|_| ()) });
        count += 1;
    }
    while let Some(done) = set.join_next().await {
        done??;
    }
    Ok(count)
}

/// Waits until `check` holds, polling every 20 ms.
pub async fn wait_until(
    what: &str,
    limit: Duration,
    mut check: impl FnMut() -> bool,
) -> Result<()> {
    let deadline = Instant::now() + limit;
    while !check() {
        anyhow::ensure!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

/// Waits until the store has applied `revision`.
pub async fn wait_for_revision(store: &RaftStore, revision: tenko_core::Revision) -> Result<()> {
    wait_until("a node to catch up", Duration::from_secs(600), || {
        store.status().revision >= revision
    })
    .await
}

/// Waits until the log behind the leader's snapshot has been purged.
pub async fn wait_for_purge(leader: &RaftStore) -> Result<()> {
    let snapshot = leader.raft().metrics().borrow().snapshot;
    wait_until(
        "the leader to purge its log",
        Duration::from_secs(120),
        || leader.raft().metrics().borrow().purged >= snapshot,
    )
    .await
}

/// Index of the last log entry the leader has purged.
pub fn purged_index(store: &RaftStore) -> u64 {
    store
        .raft()
        .metrics()
        .borrow()
        .purged
        .map_or(0, |log_id| log_id.index)
}

/// Streams the leader's current snapshot to `follower` through its snapshot receiver, as a
/// peer transport does. Returns (transfer seconds, install-call seconds).
pub async fn push_snapshot(leader: &RaftStore, follower: &RaftStore) -> Result<(f64, f64)> {
    let (meta, path) = leader
        .current_snapshot()
        .context("the leader has no snapshot")?;
    let vote = leader.raft().metrics().borrow().vote;
    let mut receiver = follower.receive_snapshot()?;
    let transfer_started = Instant::now();
    let mut file = tokio::fs::File::open(&path).await?;
    let mut chunk = vec![0_u8; tenko_store::raft::network::SNAPSHOT_CHUNK];
    loop {
        let mut filled = 0;
        while filled < chunk.len() {
            let read = tokio::io::AsyncReadExt::read(&mut file, &mut chunk[filled..]).await?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        if filled == 0 {
            break;
        }
        receiver.write_chunk(&chunk[..filled]).await?;
        if filled < chunk.len() {
            break;
        }
    }
    let transfer = transfer_started.elapsed().as_secs_f64();
    let install_started = Instant::now();
    receiver
        .install(vote, meta)
        .await
        .map_err(|error: SnapshotInstallError| anyhow::anyhow!("snapshot install: {error}"))?;
    Ok((transfer, install_started.elapsed().as_secs_f64()))
}

/// How many events at `rate` per second are due after `elapsed`.
pub fn due_count(elapsed: Duration, rate: u64) -> u64 {
    u64::try_from(elapsed.as_nanos() * u128::from(rate) / 1_000_000_000).unwrap_or(u64::MAX)
}

pub fn mib(bytes: u64) -> f64 {
    bytes_f64(bytes) / bytes_f64(MIB)
}

#[allow(clippy::cast_precision_loss, reason = "reporting only")]
pub fn bytes_f64(bytes: u64) -> f64 {
    bytes as f64
}

#[allow(clippy::cast_precision_loss, reason = "reporting only")]
pub fn count_f64(count: u64) -> f64 {
    count as f64
}

pub fn secs(micros: u64) -> f64 {
    count_f64(micros) / 1e6
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_deterministic_and_in_range() {
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        for _ in 0..1_000 {
            let value = a.below(10);
            assert_eq!(value, b.below(10));
            assert!(value < 10);
        }
        assert_eq!(Rng::new(1).between(5, 5), 5);
    }

    #[test]
    fn sample_returns_distinct_elements() {
        let mut items: Vec<u64> = (0..100).collect();
        let picked = Rng::new(3).sample(&mut items, 30).to_vec();
        let mut sorted = picked.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 30);
    }

    #[test]
    fn medians() {
        assert!((median(&[3.0, 1.0, 2.0]) - 2.0).abs() < f64::EPSILON);
        assert!((median(&[1.0, 2.0, 3.0, 4.0]) - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_summary() {
        let mut hist = new_hist();
        for nanos in 1..=1_000_u128 {
            record_ns(&mut hist, nanos * 1_000);
        }
        let summary = summarize(&hist);
        assert_eq!(summary.count, 1_000);
        assert!(summary.p50_ns >= 490_000 && summary.p50_ns <= 510_000);
        assert!(summary.max_ns >= 1_000_000);
    }
}
