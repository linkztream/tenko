//! Process CPU and memory sampling with `sysinfo`.
//!
//! The load generator samples the server process from the outside: accumulated
//! CPU time (user + kernel) at the start and end of the measurement window, and
//! the resident set size (Windows: working set) every 100 ms in the background
//! to find the peak.

use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

/// One reading of a process.
#[derive(Debug, Clone, Copy)]
pub struct ProcSample {
    /// Accumulated CPU time (user + kernel) of the process so far.
    /// `sysinfo` reports it in milliseconds.
    pub cpu_time: Duration,
    /// Resident set size (Windows: working set) in bytes.
    pub rss_bytes: u64,
}

/// Refresh only what is read: CPU time and memory.
fn refresh_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .without_tasks()
}

/// Refreshes `pid` in `sys` and reads it. `None` if the process does not exist.
fn read(sys: &mut System, pid: Pid) -> Option<ProcSample> {
    sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), true, refresh_kind());
    let p = sys.process(pid)?;
    Some(ProcSample {
        cpu_time: Duration::from_millis(p.accumulated_cpu_time()),
        rss_bytes: p.memory(),
    })
}

/// Reads accumulated CPU time (user+kernel) and resident set size of `pid` right now.
pub fn sample(pid: u32) -> Option<ProcSample> {
    let mut sys = System::new();
    read(&mut sys, Pid::from_u32(pid))
}

/// Background sampler: polls `pid` every `interval`, tracking the maximum RSS seen.
pub struct RssSampler {
    stop: Option<Sender<()>>,
    handle: Option<JoinHandle<u64>>,
}

impl RssSampler {
    /// Starts the sampling thread. The first sample is taken immediately.
    pub fn start(pid: u32, interval: Duration) -> RssSampler {
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let handle = thread::Builder::new()
            .name("rss-sampler".into())
            .spawn(move || {
                let pid = Pid::from_u32(pid);
                // One System for the whole thread: it keeps the process entry
                // between refreshes.
                let mut sys = System::new();
                let mut max = 0u64;
                loop {
                    if let Some(s) = read(&mut sys, pid) {
                        max = max.max(s.rss_bytes);
                    }
                    match stop_rx.recv_timeout(interval) {
                        Err(RecvTimeoutError::Timeout) => {}
                        // Stop requested, or the RssSampler was dropped.
                        Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                // One last reading so the peak includes the moment of the stop.
                if let Some(s) = read(&mut sys, pid) {
                    max = max.max(s.rss_bytes);
                }
                max
            })
            .ok();
        RssSampler {
            stop: Some(stop_tx),
            handle,
        }
    }

    /// Stops the thread and returns the max RSS seen in bytes (0 if the process was never seen).
    pub fn stop(mut self) -> u64 {
        // Dropping the sender wakes the thread out of `recv_timeout`.
        drop(self.stop.take());
        self.handle.take().and_then(|h| h.join().ok()).unwrap_or(0)
    }
}

impl Drop for RssSampler {
    fn drop(&mut self) {
        // If `stop` was not called, still make the thread exit (it is detached).
        drop(self.stop.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// A pid that no process has (Windows pids are multiples of 4, Linux pid_t is i32).
    const NO_SUCH_PID: u32 = 4_000_000_001;

    #[test]
    fn sample_own_process() {
        let s = sample(std::process::id()).expect("own process must be visible");
        assert!(s.rss_bytes > 0);
    }

    #[test]
    fn sample_missing_process_is_none() {
        assert!(sample(NO_SUCH_PID).is_none());
    }

    #[test]
    fn cpu_time_does_not_go_backwards_and_advances_when_busy() {
        let pid = std::process::id();
        let a = sample(pid).unwrap();
        // Burn roughly 300 ms of CPU on this thread.
        let t0 = Instant::now();
        let mut x = 0u64;
        while t0.elapsed() < Duration::from_millis(300) {
            x = std::hint::black_box(x.wrapping_mul(6364136223846793005).wrapping_add(1));
        }
        std::hint::black_box(x);
        let b = sample(pid).unwrap();
        assert!(b.cpu_time >= a.cpu_time);
        // Generous bound: the accounting granularity of the OS can be ~16 ms.
        assert!(
            b.cpu_time - a.cpu_time >= Duration::from_millis(100),
            "cpu_time advanced only {:?}",
            b.cpu_time - a.cpu_time
        );
    }

    #[test]
    fn rss_sampler_sees_own_process() {
        let s = RssSampler::start(std::process::id(), Duration::from_millis(20));
        thread::sleep(Duration::from_millis(100));
        assert!(s.stop() > 0);
    }

    #[test]
    fn rss_sampler_missing_process_is_zero() {
        let s = RssSampler::start(NO_SUCH_PID, Duration::from_millis(20));
        thread::sleep(Duration::from_millis(60));
        assert_eq!(s.stop(), 0);
    }
}
