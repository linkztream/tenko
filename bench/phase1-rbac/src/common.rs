//! Shared helpers: statistics, a deterministic random generator, process CPU time, machine
//! load sampling and machine information.

use std::process::Command;

use serde::Serialize;
use sysinfo::{
    CpuRefreshKind, MemoryRefreshKind, Pid, ProcessRefreshKind, ProcessesToUpdate, System,
};

// ---------------------------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------------------------

/// The value at quantile `q` (0 to 1) by the nearest-rank method; 0 for no values.
pub fn quantile(values: &[f64], q: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let rank = (q * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

/// The median: the mean of the two middle values for an even count.
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
// Random numbers
// ---------------------------------------------------------------------------------------------

/// A small deterministic generator (splitmix64).
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (`n` must be positive).
    pub fn below(&mut self, n: usize) -> usize {
        debug_assert!(n > 0);
        usize::try_from((u128::from(self.next_u64()) * n as u128) >> 64).unwrap_or(0)
    }

    /// `count` distinct values of `0..n`, in random order.
    pub fn sample(&mut self, n: usize, count: usize) -> Vec<usize> {
        let mut items: Vec<usize> = (0..n).collect();
        let count = count.min(n);
        for i in 0..count {
            let j = i + self.below(n - i);
            items.swap(i, j);
        }
        items.truncate(count);
        items
    }
}

// ---------------------------------------------------------------------------------------------
// CPU time and machine load
// ---------------------------------------------------------------------------------------------

/// Reads the CPU time (user plus kernel) of this process.
pub struct CpuClock {
    system: System,
    pid: Pid,
}

impl CpuClock {
    pub fn new() -> Self {
        Self {
            system: System::new(),
            pid: Pid::from_u32(std::process::id()),
        }
    }

    /// CPU milliseconds used by the process since it started, all threads together.
    pub fn cpu_ms(&mut self) -> u64 {
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu(),
        );
        self.system
            .process(self.pid)
            .map_or(0, sysinfo::Process::accumulated_cpu_time)
    }
}

// ---------------------------------------------------------------------------------------------
// Machine
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
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

/// Rounds to one decimal place for the result tables.
pub fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}
