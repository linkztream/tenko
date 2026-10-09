//! M10: the fsync probe (OPS-19; threshold: warns on an SMR disk, silent on `NVMe`).
//!
//! `fsync_probe(dir, 200)` runs three times in a temporary directory on the `NVMe` drive that
//! holds the benchmark data and three times in a temporary directory created, probed and
//! removed on the repository drive `D:` (the only write the benchmarks make there). The
//! store's own start-up entry point, `probe_and_report`, runs once per drive with a tracing
//! subscriber that captures what it logs, to show whether it warns.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use tenko_store::raft::fsync::{
    DEFAULT_PROBE_SAMPLES, FSYNC_WARN_P50, FsyncProbe, fsync_probe, probe_and_report,
};

use crate::{
    Ctx,
    common::{Machine, RunClock, RunMeta, command_output, machine},
};

#[derive(Debug, Clone, clap::Args)]
pub struct Args {
    /// Commits per probe run.
    #[arg(long, default_value_t = 200)]
    pub samples: usize,
    /// Probe runs per drive.
    #[arg(long, default_value_t = 3)]
    pub repeats: usize,
    /// Root of the slow drive; a temporary directory is created and removed there.
    #[arg(long, default_value = r"D:\")]
    pub slow_root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub samples: usize,
    pub p50_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub is_slow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Drive {
    pub label: String,
    pub probe_dir: String,
    pub runs: Vec<Probe>,
    pub startup_probe: Option<Probe>,
    pub startup_log: Vec<String>,
    pub startup_warned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub meta: RunMeta,
    pub machine: Machine,
    pub threshold_p50_ms: f64,
    pub startup_samples: usize,
    pub drives: Vec<Drive>,
    pub get_physical_disk: String,
    pub get_partition: String,
    pub get_volume: String,
    pub pass: bool,
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn convert(probe: &FsyncProbe) -> Probe {
    Probe {
        samples: probe.samples,
        p50_ms: millis(probe.p50),
        p99_ms: millis(probe.p99),
        max_ms: millis(probe.max),
        is_slow: probe.is_slow(),
    }
}

/// A `tracing` writer that collects what is logged.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A temporary directory removed on drop.
struct Probing {
    path: PathBuf,
}

impl Probing {
    fn create(root: &Path, name: &str) -> Result<Self> {
        let path = root.join(format!("{name}-{}", std::process::id()));
        fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for Probing {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            eprintln!("warning: could not remove {}: {error}", self.path.display());
        }
    }
}

fn probe_drive(label: &str, dir: &Path, args: &Args) -> Result<Drive> {
    let mut runs = Vec::new();
    for run in 1..=args.repeats {
        let probe = fsync_probe(dir, args.samples)
            .with_context(|| format!("fsync probe in {}", dir.display()))?;
        println!(
            "  {label} run {run}: p50 {:.2} ms, p99 {:.2} ms, max {:.2} ms, is_slow {}",
            millis(probe.p50),
            millis(probe.p99),
            millis(probe.max),
            probe.is_slow()
        );
        runs.push(convert(&probe));
    }
    // The store's start-up probe, with its log captured.
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer({
            let capture = capture.clone();
            move || capture.clone()
        })
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let startup = tracing::subscriber::with_default(subscriber, || {
        probe_and_report(dir, DEFAULT_PROBE_SAMPLES)
    });
    let text = String::from_utf8_lossy(&capture.0.lock().unwrap_or_else(PoisonError::into_inner))
        .into_owned();
    let startup_log: Vec<String> = text.lines().map(str::to_owned).collect();
    let startup_warned = startup_log
        .iter()
        .any(|line| line.trim_start().starts_with("WARN"));
    println!(
        "  {label} start-up probe ({DEFAULT_PROBE_SAMPLES} commits): {}",
        startup_log.first().map_or("no log line", String::as_str)
    );
    Ok(Drive {
        label: label.to_owned(),
        probe_dir: dir.display().to_string(),
        runs,
        startup_probe: startup.as_ref().map(convert),
        startup_log,
        startup_warned,
    })
}

fn powershell(script: &str) -> String {
    let text = command_output(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            &format!("{script} | Format-Table -AutoSize | Out-String -Width 200"),
        ],
    );
    // Empty drive letters come out as NUL characters.
    text.replace('\0', " ")
        .replace('\r', "")
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn run(args: &Args, ctx: &Ctx) -> Result<()> {
    let clock = RunClock::start(&ctx.data_root);
    let mut drives = Vec::new();

    let fast_root = ctx.data_root.clone();
    fs::create_dir_all(&fast_root)?;
    let fast = Probing::create(&fast_root, "tenko-fsync-probe")?;
    println!("M10: probing the data drive ({})", fast.path.display());
    drives.push(probe_drive("C: NVMe (data root)", &fast.path, args)?);
    drop(fast);

    let slow = Probing::create(&args.slow_root, "tenko-fsync-probe")?;
    println!(
        "M10: probing the repository drive ({})",
        slow.path.display()
    );
    drives.push(probe_drive("D: repository drive", &slow.path, args)?);
    drop(slow);

    let fast_ok = drives[0]
        .runs
        .iter()
        .all(|run| !run.is_slow && run.p50_ms <= millis(FSYNC_WARN_P50))
        && !drives[0].startup_warned;
    let slow_ok = drives[1].runs.iter().all(|run| run.is_slow) && drives[1].startup_warned;
    let report = Report {
        meta: clock.finish(),
        machine: machine(),
        threshold_p50_ms: millis(FSYNC_WARN_P50),
        startup_samples: DEFAULT_PROBE_SAMPLES,
        drives,
        get_physical_disk: powershell(
            "Get-PhysicalDisk | Select DeviceId,FriendlyName,MediaType,BusType,Size",
        ),
        get_partition: powershell("Get-Partition | Select DriveLetter,DiskNumber"),
        get_volume: powershell(
            "Get-Volume | Where-Object DriveLetter | Select DriveLetter,FileSystemLabel,Size",
        ),
        pass: fast_ok && slow_ok,
    };
    println!(
        "M10: NVMe silent {fast_ok}, SMR warns {slow_ok}: {}",
        if report.pass { "PASS" } else { "FAIL" }
    );
    ctx.out.write("m10", &report)
}
