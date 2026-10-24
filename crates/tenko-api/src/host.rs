//! The host's CPU, memory and free disk space (OPS-20): what the start page, `GET
//! /system/status` and `GET /metrics` show about the machine under the node.
//!
//! [`HostProbe`] reads three things and fails soft on each: a reading that cannot be made is
//! absent from the [`HostSample`], never an error. [`HostMonitor`] keeps the latest sample and
//! reads again when it is older than [`SAMPLE_EVERY`], so every consumer (the samples of the
//! `metrics` topic, the gauge timer, a status request) shares one reading per five seconds and
//! the node keeps no history: the time series is Prometheus' (`tenko_host_*`).
//!
//! - **CPU.** The share of busy time since the previous sample, from the counters of the first
//!   line of `/proc/stat`; absent in the first sample, after a counter that went backwards and
//!   when the previous sample is older than [`CPU_WINDOW_MAX`] (an average over an idle hour is
//!   no reading of now).
//! - **Memory.** `MemTotal` and `MemAvailable` of `/proc/meminfo`: the host's, not the
//!   control group's of a container.
//! - **Disk.** The size and the space available to this process on the file system of the data
//!   directory, on every platform (through `fs4`).
//!
//! CPU and memory are read on Linux only. Another platform adds a module that provides
//! `read_cpu` and `read_memory` beside the Linux ones below; nothing else changes.

#[cfg(any(target_os = "linux", test))]
mod procfs;

use std::{
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use tenko_core::Timestamp;

/// How old the latest sample may be before a consumer reads the host again.
pub const SAMPLE_EVERY: Duration = Duration::from_secs(5);
/// The oldest previous sample a CPU share is taken against.
pub const CPU_WINDOW_MAX: Duration = Duration::from_secs(300);
/// A file system is low on space when less than this share of it is available, or less than
/// [`LOW_DISK_BYTES`], whichever is more.
pub const LOW_DISK_SHARE: u64 = 10;
/// The absolute floor of the disk warning: one GiB.
pub const LOW_DISK_BYTES: u64 = 1 << 30;

/// One reading of the host. A field that could not be read is `None`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HostSample {
    /// The share of the CPU's time that was busy since the previous sample, 0 to 100.
    pub cpu_percent: Option<f32>,
    /// Physical memory in bytes.
    pub memory_total: Option<u64>,
    /// Memory that a program can use without swapping, in bytes (`MemAvailable`).
    pub memory_available: Option<u64>,
    /// The size of the file system of the data directory in bytes.
    pub disk_total: Option<u64>,
    /// The space available to this process on that file system in bytes.
    pub disk_available: Option<u64>,
    /// When the sample was taken.
    pub sampled_at: Timestamp,
}

impl HostSample {
    /// A sample with no reading.
    pub fn blank(sampled_at: Timestamp) -> Self {
        Self {
            cpu_percent: None,
            memory_total: None,
            memory_available: None,
            disk_total: None,
            disk_available: None,
            sampled_at,
        }
    }

    /// Whether nothing could be read.
    pub fn is_blank(&self) -> bool {
        self.cpu_percent.is_none()
            && self.memory_total.is_none()
            && self.memory_available.is_none()
            && self.disk_total.is_none()
            && self.disk_available.is_none()
    }

    /// Whether the data directory's file system is low on space (`node.disk.low`): less than
    /// [`LOW_DISK_SHARE`] percent of it or less than [`LOW_DISK_BYTES`] is available,
    /// whichever is more.
    pub fn disk_is_low(&self) -> bool {
        match (self.disk_total, self.disk_available) {
            (Some(total), Some(available)) => available < low_disk_limit(total),
            _ => false,
        }
    }
}

/// The available space under which a file system of `total` bytes is low.
pub fn low_disk_limit(total: u64) -> u64 {
    (total / 100)
        .saturating_mul(LOW_DISK_SHARE)
        .max(LOW_DISK_BYTES)
}

/// The CPU counters of one reading, in the unit of the platform (ticks): `busy` never exceeds
/// `total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CpuTimes {
    pub(crate) busy: u64,
    pub(crate) total: u64,
}

impl CpuTimes {
    /// The busy share in percent since `earlier`; `None` when a counter went backwards (a wrap
    /// or a reset) or the total did not move.
    fn share_since(self, earlier: Self) -> Option<f32> {
        let busy = self.busy.checked_sub(earlier.busy)?;
        let total = self.total.checked_sub(earlier.total)?;
        if total == 0 || busy > total {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        let share = busy as f64 / total as f64 * 100.0;
        #[allow(clippy::cast_possible_truncation)]
        Some(share as f32)
    }
}

/// The previous CPU reading, which the next one is taken against.
#[derive(Debug, Default)]
struct CpuTracker {
    previous: Option<(Instant, CpuTimes)>,
}

impl CpuTracker {
    /// The share since the previous reading, which `now` replaces. A reading that failed
    /// (`None`) forgets the previous one: the next share would span the gap.
    fn advance(&mut self, at: Instant, now: Option<CpuTimes>) -> Option<f32> {
        let earlier = self.previous.take();
        let now = now?;
        self.previous = Some((at, now));
        let (then, earlier) = earlier?;
        if at.saturating_duration_since(then) > CPU_WINDOW_MAX {
            return None;
        }
        now.share_since(earlier)
    }
}

/// Reads the host. It keeps the previous CPU counters and one text buffer, so a sample
/// allocates nothing of its own.
#[derive(Debug, Default)]
pub struct HostProbe {
    data_dir: Option<PathBuf>,
    cpu: CpuTracker,
    buffer: String,
}

impl HostProbe {
    /// A probe that measures the file system of `data_dir` (none: no disk figures).
    pub fn new(data_dir: Option<PathBuf>) -> Self {
        Self {
            data_dir,
            ..Self::default()
        }
    }

    /// Measures the file system of `data_dir` from now on.
    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.data_dir = Some(data_dir);
    }

    /// The directory whose file system is measured.
    pub fn data_dir(&self) -> Option<&Path> {
        self.data_dir.as_deref()
    }

    /// Reads the host now.
    pub fn sample(&mut self) -> HostSample {
        let mut sample = HostSample::blank(Timestamp::now());
        sample.cpu_percent = {
            let times = read_cpu(&mut self.buffer);
            self.cpu.advance(Instant::now(), times)
        };
        (sample.memory_total, sample.memory_available) = read_memory(&mut self.buffer);
        if let Some(dir) = &self.data_dir {
            sample.disk_total = fs4::total_space(dir).ok();
            sample.disk_available = fs4::available_space(dir).ok();
        }
        sample
    }
}

#[cfg(target_os = "linux")]
fn read_cpu(buffer: &mut String) -> Option<CpuTimes> {
    read_text(buffer, "/proc/stat")?;
    procfs::parse_cpu(buffer)
}

#[cfg(target_os = "linux")]
fn read_memory(buffer: &mut String) -> (Option<u64>, Option<u64>) {
    if read_text(buffer, "/proc/meminfo").is_none() {
        return (None, None);
    }
    procfs::parse_memory(buffer)
}

/// Replaces the contents of `buffer` with the file at `path`.
#[cfg(target_os = "linux")]
fn read_text(buffer: &mut String, path: &str) -> Option<()> {
    use std::io::Read as _;

    buffer.clear();
    std::fs::File::open(path)
        .ok()?
        .read_to_string(buffer)
        .ok()
        .map(|_| ())
}

#[cfg(not(target_os = "linux"))]
fn read_cpu(_buffer: &mut String) -> Option<CpuTimes> {
    None
}

#[cfg(not(target_os = "linux"))]
fn read_memory(_buffer: &mut String) -> (Option<u64>, Option<u64>) {
    (None, None)
}

/// The latest sample of the host, shared by every consumer of this node. Cloning the state
/// that holds it shares it.
#[derive(Debug, Default)]
pub struct HostMonitor {
    inner: Mutex<MonitorInner>,
}

#[derive(Debug, Default)]
struct MonitorInner {
    probe: HostProbe,
    latest: Option<(Instant, HostSample)>,
}

impl HostMonitor {
    /// Measures the file system of `data_dir`; the next reading sees it.
    pub fn set_data_dir(&self, data_dir: PathBuf) {
        let mut inner = self.lock();
        inner.probe.set_data_dir(data_dir);
        inner.latest = None;
    }

    /// The directory whose file system is measured, if the server set one.
    pub fn data_dir(&self) -> Option<PathBuf> {
        self.lock().probe.data_dir().map(Path::to_path_buf)
    }

    /// The latest sample, read again first when it is older than [`SAMPLE_EVERY`]. `None`
    /// when nothing could be read on this host.
    pub fn current(&self) -> Option<HostSample> {
        let mut inner = self.lock();
        let now = Instant::now();
        let fresh = inner
            .latest
            .filter(|(taken, _)| now.saturating_duration_since(*taken) < SAMPLE_EVERY);
        let sample = if let Some((_, sample)) = fresh {
            sample
        } else {
            let sample = inner.probe.sample();
            inner.latest = Some((now, sample));
            sample
        };
        (!sample.is_blank()).then_some(sample)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MonitorInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(
        clippy::unnecessary_wraps,
        reason = "the tracker takes the reading as an Option, as a failed read gives none"
    )]
    fn times(busy: u64, total: u64) -> Option<CpuTimes> {
        Some(CpuTimes { busy, total })
    }

    fn near(share: Option<f32>, expected: f32) -> bool {
        share.is_some_and(|share| (share - expected).abs() < 1e-4)
    }

    #[test]
    fn the_cpu_share_is_the_busy_part_of_the_ticks_since_the_last_sample() {
        let start = Instant::now();
        let mut cpu = CpuTracker::default();
        assert_eq!(cpu.advance(start, times(100, 1_000)), None, "first sample");
        // 50 busy of 200 ticks since.
        let second = cpu.advance(start + Duration::from_secs(5), times(150, 1_200));
        assert!(near(second, 25.0), "{second:?}");
        // All busy, then all idle.
        assert!(near(
            cpu.advance(start + Duration::from_secs(10), times(250, 1_300)),
            100.0
        ));
        assert!(near(
            cpu.advance(start + Duration::from_secs(15), times(250, 1_500)),
            0.0
        ));
    }

    #[test]
    fn a_counter_that_went_backwards_or_stood_still_gives_no_share() {
        let start = Instant::now();
        let at = |seconds| start + Duration::from_secs(seconds);
        let mut cpu = CpuTracker::default();
        cpu.advance(at(0), times(u64::MAX - 10, u64::MAX - 5));
        // The counters wrapped: no share, and the next one is taken against the wrapped values.
        assert_eq!(cpu.advance(at(5), times(40, 100)), None);
        assert!(near(cpu.advance(at(10), times(60, 200)), 20.0));
        // The total did not move.
        assert_eq!(cpu.advance(at(15), times(60, 200)), None);
        // Busy ticks cannot outrun the total.
        assert_eq!(cpu.advance(at(20), times(500, 210)), None);
    }

    #[test]
    fn a_failed_reading_or_a_long_gap_forgets_the_previous_counters() {
        let start = Instant::now();
        let at = |seconds| start + Duration::from_secs(seconds);
        let mut cpu = CpuTracker::default();
        cpu.advance(at(0), times(10, 100));
        assert_eq!(cpu.advance(at(5), None), None);
        assert_eq!(cpu.advance(at(10), times(20, 200)), None, "no previous");
        assert!(near(cpu.advance(at(15), times(30, 300)), 10.0));
        // An hour later the average would say nothing about now.
        assert_eq!(cpu.advance(at(3_615), times(40, 400)), None);
        assert!(near(cpu.advance(at(3_620), times(45, 420)), 25.0));
    }

    #[test]
    fn a_disk_is_low_below_the_larger_of_a_tenth_and_one_gibibyte() {
        let gib = 1_u64 << 30;
        let sample = |total, available| HostSample {
            disk_total: Some(total),
            disk_available: Some(available),
            ..HostSample::blank(Timestamp::now())
        };
        // 100 GiB: the limit is 10 GiB.
        assert!(sample(100 * gib, 10 * gib - 1).disk_is_low());
        assert!(!sample(100 * gib, 10 * gib).disk_is_low());
        // 4 GiB: a tenth is 0.4 GiB, so the floor of 1 GiB counts.
        assert!(sample(4 * gib, gib - 1).disk_is_low());
        assert!(!sample(4 * gib, gib).disk_is_low());
        assert_eq!(low_disk_limit(100 * gib), 10 * gib);
        assert_eq!(low_disk_limit(4 * gib), gib);
        // Nothing read, nothing to warn about.
        assert!(!HostSample::blank(Timestamp::now()).disk_is_low());
    }

    #[test]
    fn the_probe_measures_the_disk_of_its_directory_and_the_monitor_shares_one_reading() {
        let dir = std::env::temp_dir();
        let mut probe = HostProbe::new(Some(dir.clone()));
        let sample = probe.sample();
        let total = sample.disk_total.expect("the size of the temp file system");
        let available = sample.disk_available.expect("its free space");
        assert!(total > 0 && available <= total);
        assert_eq!(HostProbe::new(None).sample().disk_total, None);

        let monitor = HostMonitor::default();
        assert_eq!(monitor.data_dir(), None);
        monitor.set_data_dir(dir.clone());
        assert_eq!(monitor.data_dir(), Some(dir));
        let first = monitor.current().expect("a reading");
        let again = monitor.current().expect("a reading");
        assert_eq!(first.sampled_at, again.sampled_at, "younger than 5 s");
        assert!(first.disk_total.is_some());
        #[cfg(target_os = "linux")]
        {
            assert!(first.memory_total.is_some_and(|total| total > 0));
            assert!(first.memory_available.is_some());
        }
    }
}
