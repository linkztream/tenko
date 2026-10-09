//! Measurement helpers for the benchmark: process memory (RSS) sampling, latency histograms,
//! open-loop paced execution, disk usage, human readable formatting and machine information.
//!
//! Everything here is safe Rust. Memory comes from `sysinfo`, latency histograms from
//! `hdrhistogram`.

#![allow(dead_code)] // General-purpose helpers; not every one is used by every phase.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use sysinfo::{
    CpuRefreshKind, MemoryRefreshKind, Pid, ProcessRefreshKind, ProcessesToUpdate, System,
};

use crate::results::{LatencySummary, MachineInfo};

// ---------------------------------------------------------------------------------------------
// Process memory
// ---------------------------------------------------------------------------------------------

fn own_pid() -> Pid {
    Pid::from_u32(std::process::id())
}

/// Refreshes only the memory of the process `pid` in `sys` and returns its resident set size.
fn sample_process_rss(sys: &mut System, pid: Pid) -> u64 {
    let pids = [pid];
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&pids),
        true,
        ProcessRefreshKind::nothing().with_memory(),
    );
    sys.process(pid).map_or(0, |p| p.memory())
}

/// Resident set size (on Windows: working set) of the current process in bytes, via sysinfo.
pub fn current_rss_bytes() -> u64 {
    let mut sys = System::new();
    sample_process_rss(&mut sys, own_pid())
}

struct SamplerState {
    sys: System,
    pid: Pid,
}

struct SamplerShared {
    state: Mutex<SamplerState>,
    current: AtomicU64,
    peak: AtomicU64,
    stop: AtomicBool,
}

impl SamplerShared {
    fn lock(&self) -> MutexGuard<'_, SamplerState> {
        // A poisoned lock only means the sampler thread panicked; the state is still usable.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes one sample under the state lock (so concurrent samples are serialized), publishes it
    /// as the current value and either raises the peak or, with `reset_peak`, replaces it.
    fn take_sample(&self, reset_peak: bool) -> u64 {
        let mut guard = self.lock();
        let st = &mut *guard;
        let value = sample_process_rss(&mut st.sys, st.pid);
        if reset_peak {
            self.peak.store(value, Ordering::Relaxed);
        } else {
            self.peak.fetch_max(value, Ordering::Relaxed);
        }
        self.current.store(value, Ordering::Relaxed);
        value
    }
}

/// Background thread sampling the current process RSS at a fixed interval and tracking the peak.
///
/// One `sysinfo::System` is reused for every tick and only this process's memory is refreshed.
pub struct RssSampler {
    shared: Arc<SamplerShared>,
    handle: Option<JoinHandle<()>>,
}

impl RssSampler {
    /// Starts sampling immediately (takes one sample synchronously before returning).
    pub fn start(interval: Duration) -> RssSampler {
        let interval = interval.max(Duration::from_millis(1));
        let shared = Arc::new(SamplerShared {
            state: Mutex::new(SamplerState {
                sys: System::new(),
                pid: own_pid(),
            }),
            current: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        });
        shared.take_sample(true);

        let worker = Arc::clone(&shared);
        let handle = thread::Builder::new()
            .name("rss-sampler".to_string())
            .spawn(move || {
                let mut next = Instant::now() + interval;
                loop {
                    // Wait for the next tick; `unpark` from stop()/drop wakes us early.
                    loop {
                        if worker.stop.load(Ordering::Acquire) {
                            return;
                        }
                        let now = Instant::now();
                        if now >= next {
                            break;
                        }
                        thread::park_timeout(next - now);
                    }
                    worker.take_sample(false);
                    next += interval;
                    let now = Instant::now();
                    if next < now {
                        // Sampling took longer than the interval: do not try to catch up.
                        next = now + interval;
                    }
                }
            })
            .expect("failed to spawn the RSS sampler thread");

        RssSampler {
            shared,
            handle: Some(handle),
        }
    }

    /// Most recent sample.
    pub fn current_bytes(&self) -> u64 {
        self.shared.current.load(Ordering::Relaxed)
    }

    /// Highest sample since start or the last `reset_peak()`.
    pub fn peak_bytes(&self) -> u64 {
        self.shared.peak.load(Ordering::Relaxed)
    }

    /// Takes a fresh sample synchronously and sets peak = that sample.
    pub fn reset_peak(&self) {
        self.shared.take_sample(true);
    }

    /// Takes a final sample, stops the thread, returns the peak.
    pub fn stop(mut self) -> u64 {
        self.shared.take_sample(false);
        self.shutdown();
        self.shared.peak.load(Ordering::Relaxed)
    }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            // A panic in the sampler thread is not worth propagating from here.
            let _ = handle.join();
        }
    }
}

impl Drop for RssSampler {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ---------------------------------------------------------------------------------------------
// Latency histogram
// ---------------------------------------------------------------------------------------------

const LATENCY_MIN_NS: u64 = 1;
const LATENCY_MAX_NS: u64 = 60_000_000_000;

/// Latency histogram in nanoseconds (hdrhistogram, 3 significant figures, range 1 ns ..= 60 s;
/// values above the max are clamped, values of 0 are recorded as 1).
#[derive(Clone, Debug)]
pub struct LatencyRecorder {
    hist: Histogram<u64>,
}

impl LatencyRecorder {
    pub fn new() -> Self {
        let hist = Histogram::new_with_bounds(LATENCY_MIN_NS, LATENCY_MAX_NS, 3)
            .expect("valid histogram bounds");
        LatencyRecorder { hist }
    }

    pub fn record(&mut self, d: Duration) {
        self.record_ns(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    }

    pub fn record_ns(&mut self, ns: u64) {
        self.hist
            .saturating_record(ns.clamp(LATENCY_MIN_NS, LATENCY_MAX_NS));
    }

    pub fn merge(&mut self, other: &LatencyRecorder) {
        // Both histograms are created with identical bounds, so adding cannot fail.
        let res = self.hist.add(&other.hist);
        debug_assert!(res.is_ok());
    }

    pub fn len(&self) -> u64 {
        self.hist.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hist.is_empty()
    }

    /// count, min, p50, p90, p99, p99.9, max, mean. All zero if empty.
    pub fn summary(&self) -> LatencySummary {
        let h = &self.hist;
        if h.is_empty() {
            return LatencySummary::default();
        }
        LatencySummary {
            count: h.len(),
            min_ns: h.min(),
            p50_ns: h.value_at_quantile(0.50),
            p90_ns: h.value_at_quantile(0.90),
            p99_ns: h.value_at_quantile(0.99),
            p999_ns: h.value_at_quantile(0.999),
            max_ns: h.max(),
            mean_ns: h.mean(),
        }
    }
}

impl Default for LatencyRecorder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------------------------
// Paced (open-loop) execution
// ---------------------------------------------------------------------------------------------

/// Result of a paced (open-loop) run.
#[derive(Clone, Debug)]
pub struct PacedStats {
    /// Service time of each op call (Instant taken immediately before and after the call).
    pub latency: LatencySummary,
    pub calls: u64,
    pub elapsed: Duration,
    pub achieved_rate: f64,
    /// Worst lateness of a call start versus its scheduled time.
    pub max_lag: Duration,
    /// Number of calls that started more than 1 ms after their scheduled time.
    pub late_calls: u64,
}

/// Remaining wait above which the thread sleeps instead of spinning.
const SPIN_THRESHOLD: Duration = Duration::from_millis(2);
/// Safety margin kept for spinning when a sleep is used.
const SLEEP_MARGIN: Duration = Duration::from_millis(1);
/// Longest single sleep, so the stop flag is noticed promptly even at very low rates.
const MAX_SLEEP_CHUNK: Duration = Duration::from_millis(10);
/// A call that starts later than this after its scheduled time counts as late.
const LATE_THRESHOLD: Duration = Duration::from_millis(1);

/// Waits until `target`. Sleeps while more than `SPIN_THRESHOLD` remains, then spins. Returns the
/// instant at which the wait ended, or `None` if `stop` was set.
fn wait_until(target: Instant, stop: &AtomicBool) -> Option<Instant> {
    loop {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        let now = Instant::now();
        if now >= target {
            return Some(now);
        }
        let remaining = target - now;
        if remaining > SPIN_THRESHOLD {
            thread::sleep((remaining - SLEEP_MARGIN).min(MAX_SLEEP_CHUNK));
        } else {
            std::hint::spin_loop();
        }
    }
}

/// Calls `op(i)` for i = 0, 1, 2, ... at a fixed rate of `rate_per_sec` calls per second for
/// `duration`, on the calling thread.
///
/// Open loop: call `i` is scheduled at `start + i / rate`. The loop waits until the scheduled time
/// (sleeping only while more than about 2 ms remain, then spinning); when it is behind schedule it
/// calls immediately and never skips calls. Each call's service time is measured and recorded. A
/// natural run lasts until `start + duration`; it ends early when `stop` becomes true (checked
/// before every call). A rate of 0 makes no calls.
pub fn run_paced<F: FnMut(u64)>(
    rate_per_sec: u64,
    duration: Duration,
    stop: &AtomicBool,
    mut op: F,
) -> PacedStats {
    let mut recorder = LatencyRecorder::new();
    let mut calls: u64 = 0;
    let mut max_lag = Duration::ZERO;
    let mut late_calls: u64 = 0;

    let start = Instant::now();
    if rate_per_sec > 0 {
        let rate = u128::from(rate_per_sec);
        let mut i: u64 = 0;
        loop {
            let offset_ns = u128::from(i) * 1_000_000_000 / rate;
            let offset = Duration::from_nanos(u64::try_from(offset_ns).unwrap_or(u64::MAX));
            // Past the last scheduled call: wait out the remainder of the duration and finish.
            let finished = offset >= duration;
            let target = start + if finished { duration } else { offset };

            let Some(t0) = wait_until(target, stop) else {
                break;
            };
            if finished {
                break;
            }

            let lag = t0.saturating_duration_since(target);
            if lag > max_lag {
                max_lag = lag;
            }
            if lag > LATE_THRESHOLD {
                late_calls += 1;
            }

            op(i);
            recorder.record(t0.elapsed());
            calls += 1;
            i += 1;
        }
    }
    let elapsed = start.elapsed();

    let secs = elapsed.as_secs_f64();
    PacedStats {
        latency: recorder.summary(),
        calls,
        elapsed,
        achieved_rate: if secs > 0.0 { calls as f64 / secs } else { 0.0 },
        max_lag,
        late_calls,
    }
}

// ---------------------------------------------------------------------------------------------
// Disk usage
// ---------------------------------------------------------------------------------------------

/// Size of a file in bytes, 0 if it does not exist (or is not a regular file).
pub fn file_size_bytes(path: &Path) -> u64 {
    match fs::metadata(path) {
        Ok(md) if md.is_file() => md.len(),
        _ => 0,
    }
}

/// Recursive size of all files below a directory, 0 if it does not exist. Symbolic links are not
/// followed. If `path` is a regular file its size is returned.
pub fn dir_size_bytes(path: &Path) -> u64 {
    if path.is_file() {
        return file_size_bytes(path);
    }
    let mut total: u64 = 0;
    let mut pending = vec![path.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file()
                && let Ok(md) = entry.metadata()
            {
                total = total.saturating_add(md.len());
            }
        }
    }
    total
}

// ---------------------------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------------------------

/// "512 B", "1.50 KiB", "12.34 MiB", "1.23 GiB" (binary units, two decimals above bytes).
pub fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if b < 1024 {
        return format!("{b} B");
    }
    let mut value = b as f64 / 1024.0;
    let mut unit = 1;
    // 1023.995 would print as "1024.00": move to the next unit instead.
    while unit < UNITS.len() - 1 && value >= 1023.995 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

/// "850 ns", "12.3 us", "1.23 ms", "1.234 s" (ASCII "us", no micro sign).
pub fn fmt_ns(ns: u64) -> String {
    if ns < 1_000 {
        return format!("{ns} ns");
    }
    let v = ns as f64;
    // The thresholds keep a rounded value from printing as 1000.0 / 1000.00 in the lower unit.
    if v < 999_950.0 {
        format!("{:.1} us", v / 1e3)
    } else if v < 999_995_000.0 {
        format!("{:.2} ms", v / 1e6)
    } else {
        format!("{:.3} s", v / 1e9)
    }
}

/// "1,234,567" (comma thousands separators).
pub fn fmt_count(n: u64) -> String {
    let digits = n.to_string();
    let len = digits.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// "1,234,567/s" (rounded to integer, comma separators).
pub fn fmt_rate(per_sec: f64) -> String {
    format!("{}/s", fmt_count(per_sec.round().max(0.0) as u64))
}

// ---------------------------------------------------------------------------------------------
// Machine information
// ---------------------------------------------------------------------------------------------

/// OS name and version (sysinfo long_os_version, fallback "unknown"), brand of the first CPU,
/// logical CPU count, total memory in bytes, and the output of `rustc --version` (trimmed;
/// "unknown" if it cannot be run).
pub fn machine_info() -> MachineInfo {
    let mut sys = System::new();
    sys.refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
    sys.refresh_cpu_list(CpuRefreshKind::nothing());

    let cpus = sys.cpus();
    let cpu_brand = cpus
        .first()
        .map(|c| c.brand().trim().to_string())
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let logical_cpus = if cpus.is_empty() {
        thread::available_parallelism().map_or(0, |n| n.get())
    } else {
        cpus.len()
    };

    MachineInfo {
        os: System::long_os_version().unwrap_or_else(|| "unknown".to_string()),
        cpu_brand,
        logical_cpus,
        total_memory_bytes: sys.total_memory(),
        rustc_version: rustc_version(),
    }
}

fn rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::hint::black_box;
    use std::path::PathBuf;

    const MIB: u64 = 1 << 20;

    /// Timing and memory sensitive tests take this lock so they do not disturb each other.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn rss_sampler_sees_allocation() {
        let _guard = serial();

        let rss_now = current_rss_bytes();
        assert!(rss_now > 0, "current_rss_bytes() returned 0");

        let sampler = RssSampler::start(Duration::from_millis(10));
        assert!(sampler.current_bytes() > 0);
        sampler.reset_peak();
        let peak_before = sampler.peak_bytes();
        let current_before = sampler.current_bytes();
        assert!(peak_before > 0);

        let big = vec![1u8; (200 * MIB) as usize];
        let touched =
            u64::from(big[0]) + u64::from(big[big.len() / 2]) + u64::from(big[big.len() - 1]);
        assert_eq!(touched, 3);
        black_box(&big);
        thread::sleep(Duration::from_millis(100));

        let current_during = sampler.current_bytes();
        let peak_during = sampler.peak_bytes();
        println!(
            "rss: current_rss_bytes()={} | before: current={} peak={} | after alloc: current={} peak={} | delta peak={}",
            fmt_bytes(rss_now),
            fmt_bytes(current_before),
            fmt_bytes(peak_before),
            fmt_bytes(current_during),
            fmt_bytes(peak_during),
            fmt_bytes(peak_during.saturating_sub(peak_before)),
        );
        assert!(
            peak_during >= peak_before + 150 * MIB,
            "peak rose by only {} (before {}, after {})",
            fmt_bytes(peak_during.saturating_sub(peak_before)),
            fmt_bytes(peak_before),
            fmt_bytes(peak_during),
        );

        // Free the allocation: a fresh reset_peak() must drop the peak back down.
        drop(big);
        thread::sleep(Duration::from_millis(50));
        sampler.reset_peak();
        let peak_after_reset = sampler.peak_bytes();
        println!(
            "rss: after free and reset_peak: current={} peak={}",
            fmt_bytes(sampler.current_bytes()),
            fmt_bytes(peak_after_reset)
        );
        assert!(peak_after_reset + 100 * MIB <= peak_during);

        let final_peak = sampler.stop();
        println!("rss: stop() returned peak={}", fmt_bytes(final_peak));
        assert!(final_peak > 0);
    }

    #[test]
    fn rss_sampler_drop_and_stop_are_clean() {
        let _guard = serial();
        // Dropped without stop(): must join the thread without panicking.
        let sampler = RssSampler::start(Duration::from_millis(5));
        thread::sleep(Duration::from_millis(20));
        drop(sampler);

        // A long interval must not delay stop().
        let started = Instant::now();
        let sampler = RssSampler::start(Duration::from_secs(30));
        let peak = sampler.stop();
        assert!(peak > 0);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "stop() waited for the interval"
        );

        // Zero interval is clamped, not a busy loop that panics.
        let sampler = RssSampler::start(Duration::ZERO);
        thread::sleep(Duration::from_millis(10));
        assert!(sampler.stop() > 0);
    }

    #[test]
    fn latency_recorder_percentiles() {
        let mut rec = LatencyRecorder::new();
        assert!(rec.is_empty());
        assert_eq!(rec.len(), 0);
        for us in 1..=1000u64 {
            rec.record(Duration::from_micros(us));
        }
        assert_eq!(rec.len(), 1000);
        assert!(!rec.is_empty());
        let s = rec.summary();
        println!("latency summary 1..=1000 us: {s:?}");
        assert_eq!(s.count, 1000);
        let within = |value: u64, expect: u64| {
            let diff = value.abs_diff(expect) as f64 / expect as f64;
            assert!(diff < 0.01, "{value} not within 1% of {expect}");
        };
        within(s.p50_ns, 500_000);
        within(s.p90_ns, 900_000);
        within(s.p99_ns, 990_000);
        within(s.p999_ns, 999_000);
        within(s.min_ns, 1_000);
        within(s.max_ns, 1_000_000);
        assert!((s.mean_ns - 500_500.0).abs() / 500_500.0 < 0.01);

        // Merging adds the counts.
        let mut other = LatencyRecorder::default();
        for us in 1..=1000u64 {
            other.record_ns(us * 1_000);
        }
        rec.merge(&other);
        assert_eq!(rec.len(), 2000);
        assert_eq!(rec.summary().count, 2000);
        assert_eq!(other.len(), 1000);

        // Merging an empty recorder changes nothing.
        rec.merge(&LatencyRecorder::new());
        assert_eq!(rec.len(), 2000);
    }

    #[test]
    fn latency_recorder_empty_and_clamping() {
        let rec = LatencyRecorder::new();
        let s = rec.summary();
        assert_eq!(s.count, 0);
        assert_eq!(s.min_ns, 0);
        assert_eq!(s.p50_ns, 0);
        assert_eq!(s.p90_ns, 0);
        assert_eq!(s.p99_ns, 0);
        assert_eq!(s.p999_ns, 0);
        assert_eq!(s.max_ns, 0);
        assert_eq!(s.mean_ns, 0.0);

        let mut rec = LatencyRecorder::new();
        rec.record_ns(0);
        assert_eq!(rec.summary().min_ns, 1);
        rec.record(Duration::from_secs(100));
        rec.record_ns(u64::MAX);
        assert_eq!(rec.len(), 3);
        let max = rec.summary().max_ns;
        let diff = max.abs_diff(60_000_000_000) as f64 / 60e9;
        assert!(diff < 0.001, "max {max} should be clamped to about 60 s");
    }

    #[test]
    fn paced_50k_per_second() {
        let _guard = serial();
        let stop = AtomicBool::new(false);
        let mut sink: u64 = 0;
        let stats = run_paced(50_000, Duration::from_secs(1), &stop, |i| {
            sink = sink.wrapping_add(black_box(i));
        });
        black_box(sink);
        println!(
            "paced 50,000/s for 1 s: calls={} elapsed={:?} achieved_rate={:.1} max_lag={:?} late_calls={} \
             service p50={} p99={} max={}",
            stats.calls,
            stats.elapsed,
            stats.achieved_rate,
            stats.max_lag,
            stats.late_calls,
            fmt_ns(stats.latency.p50_ns),
            fmt_ns(stats.latency.p99_ns),
            fmt_ns(stats.latency.max_ns),
        );
        assert_eq!(stats.calls, 50_000);
        assert_eq!(stats.latency.count, 50_000);
        let rel = (stats.achieved_rate - 50_000.0).abs() / 50_000.0;
        assert!(
            rel < 0.02,
            "achieved {} vs target 50000",
            stats.achieved_rate
        );
        assert!(stats.elapsed >= Duration::from_secs(1));
    }

    #[test]
    fn paced_low_rate_uses_sleep_path() {
        let _guard = serial();
        let stop = AtomicBool::new(false);
        let mut seen = Vec::new();
        let stats = run_paced(200, Duration::from_millis(500), &stop, |i| seen.push(i));
        println!(
            "paced 200/s for 0.5 s: calls={} elapsed={:?} achieved_rate={:.1} max_lag={:?} late_calls={}",
            stats.calls, stats.elapsed, stats.achieved_rate, stats.max_lag, stats.late_calls
        );
        assert_eq!(stats.calls, 100);
        assert_eq!(seen, (0..100u64).collect::<Vec<_>>());
        let rel = (stats.achieved_rate - 200.0).abs() / 200.0;
        assert!(rel < 0.05, "achieved {}", stats.achieved_rate);
    }

    #[test]
    fn paced_does_not_skip_when_behind() {
        let _guard = serial();
        let stop = AtomicBool::new(false);
        // Each call takes about 2 ms but the schedule asks for one every 1 ms.
        let stats = run_paced(1000, Duration::from_millis(100), &stop, |_| {
            let until = Instant::now() + Duration::from_millis(2);
            while Instant::now() < until {
                std::hint::spin_loop();
            }
        });
        println!(
            "paced overload: calls={} elapsed={:?} achieved_rate={:.1} max_lag={:?} late_calls={} service p50={}",
            stats.calls,
            stats.elapsed,
            stats.achieved_rate,
            stats.max_lag,
            stats.late_calls,
            fmt_ns(stats.latency.p50_ns)
        );
        assert_eq!(stats.calls, 100, "no call may be skipped");
        assert!(stats.elapsed >= Duration::from_millis(200));
        assert!(stats.late_calls > 0);
        assert!(stats.max_lag > Duration::from_millis(50));
        assert!(stats.achieved_rate < 700.0);
    }

    #[test]
    fn paced_stops_early() {
        let _guard = serial();

        // Stop flag raised by another thread while the run is in progress.
        let stop = AtomicBool::new(false);
        let stats = thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(150));
                stop.store(true, Ordering::Relaxed);
            });
            run_paced(1000, Duration::from_secs(10), &stop, |_| {})
        });
        println!(
            "paced early stop: calls={} elapsed={:?} achieved_rate={:.1}",
            stats.calls, stats.elapsed, stats.achieved_rate
        );
        assert!(
            stats.elapsed < Duration::from_secs(2),
            "did not stop early: {:?}",
            stats.elapsed
        );
        assert!(stats.calls > 0 && stats.calls < 10_000);

        // Stop flag raised by the op itself, at a rate high enough to never sleep.
        let stop = AtomicBool::new(false);
        let stats = run_paced(100_000, Duration::from_secs(10), &stop, |i| {
            if i == 999 {
                stop.store(true, Ordering::Relaxed);
            }
        });
        assert!(
            stats.calls >= 1000 && stats.calls <= 1001,
            "calls={}",
            stats.calls
        );
        assert!(stats.elapsed < Duration::from_secs(1));

        // Already stopped: no calls at all.
        let stats = run_paced(1000, Duration::from_secs(10), &stop, |_| {
            panic!("must not be called")
        });
        assert_eq!(stats.calls, 0);
        assert_eq!(stats.latency.count, 0);

        // Rate 0: no calls and returns immediately.
        let stop = AtomicBool::new(false);
        let stats = run_paced(0, Duration::from_secs(10), &stop, |_| {
            panic!("must not be called")
        });
        assert_eq!(stats.calls, 0);
        assert!(stats.elapsed < Duration::from_secs(1));
    }

    #[test]
    fn formatting_helpers() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1023), "1023 B");
        assert_eq!(fmt_bytes(1024), "1.00 KiB");
        assert_eq!(fmt_bytes(1536), "1.50 KiB");
        assert_eq!(fmt_bytes(12_939_428), "12.34 MiB");
        assert_eq!(fmt_bytes(1_320_702_444), "1.23 GiB");
        assert_eq!(fmt_bytes(1_048_575), "1.00 MiB");
        assert_eq!(fmt_bytes(5 << 40), "5.00 TiB");
        assert_eq!(fmt_bytes(u64::MAX), "16.00 EiB");

        assert_eq!(fmt_ns(0), "0 ns");
        assert_eq!(fmt_ns(850), "850 ns");
        assert_eq!(fmt_ns(999), "999 ns");
        assert_eq!(fmt_ns(1_000), "1.0 us");
        assert_eq!(fmt_ns(12_300), "12.3 us");
        assert_eq!(fmt_ns(999_949), "999.9 us");
        assert_eq!(fmt_ns(999_950), "1.00 ms");
        assert_eq!(fmt_ns(1_230_000), "1.23 ms");
        assert_eq!(fmt_ns(999_994_999), "999.99 ms");
        assert_eq!(fmt_ns(999_995_000), "1.000 s");
        assert_eq!(fmt_ns(1_234_000_000), "1.234 s");
        assert_eq!(fmt_ns(60_000_000_000), "60.000 s");

        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(7), "7");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_000), "1,000");
        assert_eq!(fmt_count(12_345), "12,345");
        assert_eq!(fmt_count(123_456), "123,456");
        assert_eq!(fmt_count(1_234_567), "1,234,567");
        assert_eq!(fmt_count(u64::MAX), "18,446,744,073,709,551,615");

        assert_eq!(fmt_rate(0.0), "0/s");
        assert_eq!(fmt_rate(1_234_567.4), "1,234,567/s");
        assert_eq!(fmt_rate(49_999.6), "50,000/s");
        assert_eq!(fmt_rate(-5.0), "0/s");
        assert_eq!(fmt_rate(f64::NAN), "0/s");
    }

    fn test_dir(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("measure-tests")
            .join(format!("{name}-{}", std::process::id()))
    }

    #[test]
    fn dir_and_file_sizes() {
        let root = test_dir("dir-size");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("sub").join("deeper")).unwrap();
        fs::write(root.join("a.bin"), vec![0u8; 1000]).unwrap();
        fs::write(root.join("b.bin"), vec![0u8; 2345]).unwrap();

        assert_eq!(dir_size_bytes(&root), 3345);
        assert_eq!(file_size_bytes(&root.join("a.bin")), 1000);
        assert_eq!(file_size_bytes(&root.join("b.bin")), 2345);

        // Nested files are included.
        fs::write(root.join("sub").join("c.bin"), vec![0u8; 100]).unwrap();
        fs::write(root.join("sub").join("deeper").join("d.bin"), vec![0u8; 7]).unwrap();
        assert_eq!(dir_size_bytes(&root), 3345 + 100 + 7);
        assert_eq!(dir_size_bytes(&root.join("sub")), 107);

        // Missing paths and directories passed to file_size_bytes give 0.
        assert_eq!(file_size_bytes(&root.join("missing.bin")), 0);
        assert_eq!(file_size_bytes(&root), 0);
        assert_eq!(dir_size_bytes(&root.join("missing")), 0);
        // A file passed to dir_size_bytes yields its own size.
        assert_eq!(dir_size_bytes(&root.join("a.bin")), 1000);

        fs::remove_dir_all(&root).unwrap();
        assert_eq!(dir_size_bytes(&root), 0);
    }

    #[test]
    fn machine_info_is_populated() {
        let m = machine_info();
        println!("machine_info: {m:#?}");
        assert!(m.logical_cpus > 0);
        assert!(m.total_memory_bytes > 0);
        assert!(!m.os.is_empty());
        assert!(!m.cpu_brand.is_empty());
        assert!(!m.rustc_version.is_empty());
        println!(
            "machine: {} | {} | {} logical CPUs | {} RAM | {}",
            m.os,
            m.cpu_brand,
            m.logical_cpus,
            fmt_bytes(m.total_memory_bytes),
            m.rustc_version
        );
    }
}
