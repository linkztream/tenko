//! The start-up fsync probe (OPS-19).
//!
//! The store's write path is bounded by the latency of a durable commit: every Raft log
//! append and every state-machine apply ends in an fsync. ADR 0002 condition 7 makes SSD or
//! `NVMe` storage mandatory for the data directory, because on a spinning disk with shingled
//! recording (SMR) a durable commit takes tens of milliseconds and the store cannot reach
//! its write targets.
//!
//! [`fsync_probe`] measures the problem directly instead of guessing from the device type:
//! it opens a throw-away redb database in the data directory, performs a handful of small
//! durable commits ([`Durability::Immediate`], the same
//! durability the Raft store uses) and times each one from `begin_write` to the return of
//! `commit`. The p50, p99 and maximum are returned as an [`FsyncProbe`]; [`FsyncProbe::is_slow`]
//! compares the p50 against [`FSYNC_WARN_P50`].
//!
//! [`probe_and_report`] is the entry point the store calls once at start-up. It logs the
//! result through `tracing` (a warning when the disk is slow, an info line otherwise) and
//! never fails: a probe that cannot run is itself only a warning. The store keeps the
//! returned [`FsyncProbe`] and reports it through its status, so an operator can read the
//! measured figure at any time.
//!
//! The probe is synchronous and touches the disk; call it from a blocking context (for
//! example `tokio::task::spawn_blocking`).

use std::{
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use redb::{Database, Durability, TableDefinition};
use serde::{Deserialize, Serialize};

/// p50 above which the store warns (OPS-19; Spike A measured 44.5 ms p50 on an SMR disk, under 4 ms on `NVMe`).
pub const FSYNC_WARN_P50: Duration = Duration::from_millis(10);

/// Commits the start-up probe makes by default.
pub const DEFAULT_PROBE_SAMPLES: usize = 20;

/// The single table of the throw-away probe database.
const PROBE_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("fsync_probe");

/// The value every probe commit inserts: small, like a Raft vote or a short log entry.
const PROBE_VALUE: [u8; 64] = [0xA5; 64];

/// Cache size of the probe database. The probe writes a few keys, so a small cache keeps
/// the start-up allocation negligible.
const PROBE_CACHE_BYTES: usize = 64 * 1024;

/// File name prefix of the probe database; the full name adds a unique suffix.
const PROBE_FILE_PREFIX: &str = ".tenko-fsync-probe-";

/// Makes probe file names unique within one process.
static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The measured latency of small durable commits in one directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsyncProbe {
    /// Commits measured (the untimed warm-up commit is not counted).
    pub samples: usize,
    /// Median commit latency (nearest rank).
    pub p50: Duration,
    /// 99th percentile commit latency (nearest rank; with few samples this is the maximum).
    pub p99: Duration,
    /// Slowest commit measured.
    pub max: Duration,
}

impl FsyncProbe {
    /// Returns whether the disk is too slow for the store: the p50 exceeds [`FSYNC_WARN_P50`].
    #[must_use]
    pub fn is_slow(&self) -> bool {
        self.p50 > FSYNC_WARN_P50
    }

    /// Returns the p50 in whole microseconds, saturating at [`u64::MAX`].
    #[must_use]
    pub fn p50_micros(&self) -> u64 {
        u64::try_from(self.p50.as_micros()).unwrap_or(u64::MAX)
    }
}

/// Measures `samples` small durable commits in a throw-away database and returns their
/// latency summary.
///
/// The database `dir/.tenko-fsync-probe-<unique>.redb` is created with a 64 KiB cache, one
/// untimed warm-up commit initialises it, and then `samples` commits are timed, each a redb
/// write transaction with [`Durability::Immediate`] that inserts one small key/value. A
/// `samples` of 0 is treated as 1. The file is deleted before the function returns, also
/// when a commit fails.
///
/// Percentiles use the nearest-rank method on the sorted durations: the p-th percentile of
/// `n` samples is the element at 1-based rank `ceil(p / 100 * n)`.
///
/// This function is synchronous and blocks on disk I/O; call it from a blocking context.
///
/// # Errors
///
/// Returns an error when the directory is missing or not writable, or when redb fails to
/// create the database or to commit; the redb error is wrapped with `io::Error::other`.
pub fn fsync_probe(dir: &Path, samples: usize) -> io::Result<FsyncProbe> {
    let samples = samples.max(1);
    // The guard is declared before the database so that it is dropped after it: the file
    // must be closed before it is removed (required on Windows).
    let file = ProbeFile::new(dir);
    let durations = {
        let db = Database::builder()
            .set_cache_size(PROBE_CACHE_BYTES)
            .create(file.path())
            .map_err(io::Error::other)?;
        measure_commits(&db, samples)?
    };
    drop(file);
    Ok(summarise(durations))
}

/// Runs the probe and logs the result through `tracing`.
///
/// A slow disk (see [`FsyncProbe::is_slow`]) is logged at `warn` level with the p50, p99 and
/// directory; otherwise the result is logged at `info` level. Returns the probe, or `None`
/// after logging a warning if the probe itself failed: a failed probe never stops the store.
///
/// This function is synchronous and blocks on disk I/O; call it from a blocking context.
#[must_use]
pub fn probe_and_report(dir: &Path, samples: usize) -> Option<FsyncProbe> {
    match fsync_probe(dir, samples) {
        Ok(probe) => {
            if probe.is_slow() {
                tracing::warn!(
                    dir = %dir.display(),
                    samples = probe.samples,
                    p50_ms = millis(probe.p50),
                    p99_ms = millis(probe.p99),
                    max_ms = millis(probe.max),
                    warn_p50_ms = millis(FSYNC_WARN_P50),
                    "data directory is on a slow disk; the store requires SSD or NVMe storage \
                     (OPS-19, ADR 0002)"
                );
            } else {
                tracing::info!(
                    dir = %dir.display(),
                    samples = probe.samples,
                    p50_ms = millis(probe.p50),
                    p99_ms = millis(probe.p99),
                    max_ms = millis(probe.max),
                    "fsync probe of the data directory"
                );
            }
            Some(probe)
        }
        Err(error) => {
            tracing::warn!(
                dir = %dir.display(),
                %error,
                "fsync probe of the data directory failed; the disk speed is unknown"
            );
            None
        }
    }
}

/// Deletes the probe database file when dropped, whether the probe succeeded or not.
struct ProbeFile {
    path: PathBuf,
}

impl ProbeFile {
    /// Names a probe file in `dir` that no other probe in any process uses.
    fn new(dir: &Path) -> Self {
        Self {
            path: dir.join(unique_file_name()),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ProbeFile {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            // The database was never created (for example the directory is missing).
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                %error,
                "could not delete the fsync probe file"
            ),
        }
    }
}

/// Builds `.tenko-fsync-probe-<pid>-<nanoseconds>-<counter>.redb`.
fn unique_file_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let counter = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "{PROBE_FILE_PREFIX}{}-{nanos:x}-{counter}.redb",
        std::process::id()
    )
}

/// Makes one untimed warm-up commit, then `samples` timed commits, and returns the timings
/// in commit order.
fn measure_commits(db: &Database, samples: usize) -> io::Result<Vec<Duration>> {
    commit_once(db, 0)?;
    let mut durations = Vec::with_capacity(samples);
    for key in (1_u64..).take(samples) {
        let started = Instant::now();
        commit_once(db, key)?;
        durations.push(started.elapsed());
    }
    Ok(durations)
}

/// One durable commit: a write transaction with immediate durability inserting one key.
fn commit_once(db: &Database, key: u64) -> io::Result<()> {
    let mut txn = db.begin_write().map_err(io::Error::other)?;
    txn.set_durability(Durability::Immediate)
        .map_err(io::Error::other)?;
    {
        let mut table = txn.open_table(PROBE_TABLE).map_err(io::Error::other)?;
        table
            .insert(key, PROBE_VALUE.as_slice())
            .map_err(io::Error::other)?;
    }
    txn.commit().map_err(io::Error::other)
}

/// Sorts `durations` and computes the summary. The slice is never empty here.
fn summarise(mut durations: Vec<Duration>) -> FsyncProbe {
    durations.sort_unstable();
    FsyncProbe {
        samples: durations.len(),
        p50: percentile(&durations, 50),
        p99: percentile(&durations, 99),
        max: durations.last().copied().unwrap_or(Duration::ZERO),
    }
}

/// Nearest-rank percentile of an ascending slice: the element at 1-based rank
/// `ceil(percent / 100 * n)`, clamped to `[1, n]`. `percent` is an integer so the rank is
/// exact. An empty slice yields [`Duration::ZERO`].
fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    let Some(last) = sorted.len().checked_sub(1) else {
        return Duration::ZERO;
    };
    let rank = percent.saturating_mul(sorted.len()).div_ceil(100);
    sorted[rank.saturating_sub(1).min(last)]
}

/// A duration in milliseconds rounded to 0.1 ms, for log fields.
fn millis(duration: Duration) -> f64 {
    (duration.as_secs_f64() * 10_000.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique directory under the system temp directory, removed on drop.
    struct TestDir(PathBuf);

    impl TestDir {
        fn create() -> Self {
            let path = std::env::temp_dir().join(format!(
                "tenko-fsync-test-{}-{}",
                std::process::id(),
                unique_file_name().trim_start_matches(PROBE_FILE_PREFIX),
            ));
            std::fs::create_dir_all(&path).expect("create the test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    fn probe_with_p50(p50: Duration) -> FsyncProbe {
        FsyncProbe {
            samples: 20,
            p50,
            p99: p50,
            max: p50,
        }
    }

    #[test]
    fn probe_measures_the_requested_samples_and_leaves_no_file() {
        let dir = TestDir::create();
        let probe = fsync_probe(dir.path(), 5).expect("probe a temp directory");
        assert_eq!(probe.samples, 5);
        assert!(
            probe.p50 <= probe.p99,
            "p50 {:?} > p99 {:?}",
            probe.p50,
            probe.p99
        );
        assert!(
            probe.p99 <= probe.max,
            "p99 {:?} > max {:?}",
            probe.p99,
            probe.max
        );
        assert!(probe.max > Duration::ZERO);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("list the test directory")
            .map(|entry| entry.expect("read a directory entry").file_name())
            .collect();
        assert!(
            leftovers.is_empty(),
            "probe left files behind: {leftovers:?}"
        );
    }

    #[test]
    fn probe_with_the_default_sample_count_works() {
        let dir = TestDir::create();
        let probe = fsync_probe(dir.path(), DEFAULT_PROBE_SAMPLES).expect("probe a temp directory");
        assert_eq!(probe.samples, DEFAULT_PROBE_SAMPLES);
    }

    #[test]
    fn zero_samples_is_treated_as_one() {
        let dir = TestDir::create();
        let probe = fsync_probe(dir.path(), 0).expect("probe a temp directory");
        assert_eq!(probe.samples, 1);
        assert_eq!(probe.p50, probe.p99);
        assert_eq!(probe.p99, probe.max);
    }

    #[test]
    fn probe_of_a_missing_directory_is_an_error() {
        let dir = TestDir::create();
        let missing = dir.path().join("does-not-exist");
        assert!(fsync_probe(&missing, 3).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn percentile_uses_the_nearest_rank() {
        let twenty: Vec<Duration> = (1..=20).map(ms).collect();
        assert_eq!(percentile(&twenty, 50), ms(10));
        assert_eq!(percentile(&twenty, 99), ms(20));
        assert_eq!(percentile(&twenty, 100), ms(20));
        assert_eq!(percentile(&twenty, 0), ms(1));

        let five: Vec<Duration> = (1..=5).map(ms).collect();
        assert_eq!(percentile(&five, 50), ms(3));
        assert_eq!(percentile(&five, 99), ms(5));

        let four: Vec<Duration> = (1..=4).map(ms).collect();
        assert_eq!(percentile(&four, 50), ms(2));

        let hundred: Vec<Duration> = (1..=100).map(ms).collect();
        assert_eq!(percentile(&hundred, 50), ms(50));
        assert_eq!(percentile(&hundred, 99), ms(99));

        assert_eq!(percentile(&[ms(7)], 50), ms(7));
        assert_eq!(percentile(&[ms(7)], 99), ms(7));
        assert_eq!(percentile(&[], 50), Duration::ZERO);
    }

    #[test]
    fn summarise_sorts_its_input() {
        let probe = summarise(vec![ms(30), ms(10), ms(20), ms(50), ms(40)]);
        assert_eq!(
            probe,
            FsyncProbe {
                samples: 5,
                p50: ms(30),
                p99: ms(50),
                max: ms(50),
            }
        );
    }

    #[test]
    fn is_slow_compares_the_p50_with_the_threshold() {
        assert!(!probe_with_p50(Duration::ZERO).is_slow());
        assert!(!probe_with_p50(ms(4)).is_slow());
        assert!(!probe_with_p50(FSYNC_WARN_P50).is_slow());
        assert!(probe_with_p50(FSYNC_WARN_P50 + Duration::from_micros(1)).is_slow());
        assert!(probe_with_p50(Duration::from_micros(44_500)).is_slow());
        // Only the p50 decides: a slow tail alone is not a slow disk.
        let slow_tail = FsyncProbe {
            samples: 20,
            p50: ms(2),
            p99: ms(80),
            max: ms(120),
        };
        assert!(!slow_tail.is_slow());
    }

    #[test]
    fn p50_micros_converts_and_saturates() {
        assert_eq!(
            probe_with_p50(Duration::from_micros(44_500)).p50_micros(),
            44_500
        );
        assert_eq!(probe_with_p50(Duration::ZERO).p50_micros(), 0);
        assert_eq!(probe_with_p50(Duration::MAX).p50_micros(), u64::MAX);
    }

    #[test]
    fn probe_file_names_are_unique() {
        let first = unique_file_name();
        let second = unique_file_name();
        assert_ne!(first, second);
        assert!(first.starts_with(PROBE_FILE_PREFIX));
        assert!(
            Path::new(&first)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("redb"))
        );
    }

    #[test]
    fn probe_and_report_returns_the_probe() {
        let dir = TestDir::create();
        let probe = probe_and_report(dir.path(), 3).expect("probe a temp directory");
        assert_eq!(probe.samples, 3);
    }

    #[test]
    fn probe_and_report_on_a_missing_directory_returns_none() {
        let dir = TestDir::create();
        let missing = dir.path().join("does-not-exist");
        assert!(probe_and_report(&missing, DEFAULT_PROBE_SAMPLES).is_none());
    }
}
