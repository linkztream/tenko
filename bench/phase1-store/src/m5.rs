//! M5: coalescer ceiling (ADR 0002 decision 4; threshold: at least 1,000 updates/s sustained).
//!
//! A single-voter store with a preloaded table takes open-loop paced single-record updates
//! (one `put` of 150 bytes and one audit draft, like a DNS update) at 1,000, 2,000 and 5,000
//! per second, then a closed-loop run with 256 concurrent writers. Both durability modes run.
//! Open-loop pacing: a dedicated thread issues the number of proposals that are due every
//! millisecond, each as its own task, so a coarse Windows timer delays proposals but never
//! lowers the offered rate.

use std::{
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};
use tenko_store::{
    Store as _,
    raft::{EngineStats, RaftStore, RaftStoreConfig, SmDurability},
};
use tokio::{runtime::Handle, task::JoinSet};

use crate::{
    Ctx,
    common::{
        Latency, Machine, RunClock, RunMeta, ScratchDir, count_f64, disk_sizes, due_count, machine,
        mix, new_hist, propose_all, record_ns, summarize,
    },
    data::{self, BULK_BATCH},
};

#[derive(Debug, Clone, clap::Args)]
pub struct Args {
    /// Records preloaded before the measurements.
    #[arg(long, default_value_t = 1_000_000)]
    pub preload: u64,
    /// Length of each open-loop window in seconds.
    #[arg(long, default_value_t = 30)]
    pub secs: u64,
    /// Offered rates of the open-loop windows, updates per second.
    #[arg(long, value_delimiter = ',', default_value = "1000,2000,5000")]
    pub rates: Vec<u64>,
    /// Concurrent writers of the closed-loop window.
    #[arg(long, default_value_t = 256)]
    pub closed_writers: usize,
    /// Length of the closed-loop window in seconds.
    #[arg(long, default_value_t = 20)]
    pub closed_secs: u64,
    /// Checkpoint interval of deferred durability, in milliseconds.
    #[arg(long, default_value_t = 1_000)]
    pub checkpoint_ms: u64,
    /// Name of the result file in `raw/` (without extension).
    #[arg(long, default_value = "m5")]
    pub out_name: String,
    /// Durability modes to run: `deferred`, `immediate`.
    #[arg(long, value_delimiter = ',', default_value = "deferred,immediate")]
    pub durability: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Level {
    pub kind: String,
    pub offered_per_s: Option<u64>,
    pub writers: Option<usize>,
    pub window_secs: f64,
    pub issued: u64,
    pub completed_ok: u64,
    pub completed_in_window: u64,
    pub errors: u64,
    pub error_samples: Vec<String>,
    pub achieved_per_s: f64,
    pub backlog_at_window_end: u64,
    pub drain_secs: f64,
    pub latency: Latency,
    pub entries: u64,
    pub batches: u64,
    pub batches_per_entry: f64,
    pub log_commits: u64,
    pub log_appended_bytes: u64,
    pub checkpoints: u64,
    pub snapshots_built: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeRun {
    pub durability: String,
    pub preload_records: u64,
    pub preload_secs: f64,
    pub sm_redb_bytes_after_preload: u64,
    pub levels: Vec<Level>,
    /// Open-loop 1,000/s sustained with zero errors.
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub coalescer_max_batches_per_entry: usize,
    pub coalescer_max_entry_bytes: usize,
    pub coalescer_max_inflight_entries: usize,
    pub sm_cache_bytes: usize,
    pub log_cache_bytes: usize,
    pub snapshot_policy: String,
    #[serde(default)]
    pub checkpoint_interval_ms: u64,
    /// Written by the first run of M5 before the field was in milliseconds.
    #[serde(default)]
    pub checkpoint_interval_secs: u64,
    pub update: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub meta: RunMeta,
    pub machine: Machine,
    pub config: Config,
    pub runs: Vec<ModeRun>,
    pub pass: bool,
}

#[derive(Debug)]
struct Counters {
    ok: AtomicU64,
    in_window: AtomicU64,
    errors: AtomicU64,
    done: AtomicU64,
    hist: Mutex<Histogram<u64>>,
    samples: Mutex<Vec<String>>,
}

impl Counters {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            ok: AtomicU64::new(0),
            in_window: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            done: AtomicU64::new(0),
            hist: Mutex::new(new_hist()),
            samples: Mutex::new(Vec::new()),
        })
    }

    fn record(&self, result: Result<(), String>, elapsed: Duration, deadline: Instant) {
        match result {
            Ok(()) => {
                self.ok.fetch_add(1, Ordering::Relaxed);
                if Instant::now() <= deadline {
                    self.in_window.fetch_add(1, Ordering::Relaxed);
                }
                record_ns(
                    &mut self.hist.lock().unwrap_or_else(PoisonError::into_inner),
                    elapsed.as_nanos(),
                );
            }
            Err(message) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
                let mut samples = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
                if samples.len() < 5 && !samples.contains(&message) {
                    samples.push(message);
                }
            }
        }
        self.done.fetch_add(1, Ordering::Release);
    }
}

fn store_config(dir: &ScratchDir, durability: &str, checkpoint_ms: u64) -> Result<RaftStoreConfig> {
    let mut config = RaftStoreConfig::new(dir.node(1));
    config.fsync_probe_samples = 0;
    config.durability = match durability {
        "deferred" => SmDurability::Deferred {
            checkpoint_interval: Duration::from_millis(checkpoint_ms),
        },
        "immediate" => SmDurability::Immediate,
        other => bail!("unknown durability {other:?}"),
    };
    Ok(config)
}

pub async fn run(args: Args, ctx: &Ctx) -> Result<()> {
    let clock = RunClock::start(&ctx.data_root);
    let defaults = RaftStoreConfig::new("unused");
    let mut report = Report {
        meta: RunMeta::default(),
        machine: machine(),
        config: Config {
            coalescer_max_batches_per_entry: defaults.coalescer.max_batches_per_entry,
            coalescer_max_entry_bytes: defaults.coalescer.max_entry_bytes,
            coalescer_max_inflight_entries: defaults.coalescer.max_inflight_entries,
            sm_cache_bytes: defaults.sm_cache_bytes,
            log_cache_bytes: defaults.log_cache_bytes,
            snapshot_policy: "default (10,000 entries or 64 MiB of log, 1,000 entries kept)"
                .to_owned(),
            checkpoint_interval_ms: args.checkpoint_ms,
            checkpoint_interval_secs: 0,
            update: "one put of 128 bytes under a 22-byte key plus one audit draft; a random \
                     existing record"
                .to_owned(),
        },
        runs: Vec::new(),
        pass: false,
    };
    for durability in &args.durability {
        println!("M5 {durability}: starting");
        let run = run_mode(&args, durability, ctx).await?;
        report.runs.push(run);
        report.meta = clock.finish();
        report.pass = report.runs.iter().all(|run| run.pass);
        ctx.out.write(&args.out_name, &report)?;
    }
    Ok(())
}

async fn run_mode(args: &Args, durability: &str, ctx: &Ctx) -> Result<ModeRun> {
    let dir = ScratchDir::new(&ctx.data_root, &format!("m5-{durability}"))?;
    let store = RaftStore::open(store_config(&dir, durability, args.checkpoint_ms)?).await?;

    let started = Instant::now();
    let preload = args.preload;
    let batches = (0..preload).step_by(BULK_BATCH).map(|first| {
        let last = (first + BULK_BATCH as u64).min(preload);
        data::put_batch(&(first..last).collect::<Vec<_>>(), 0)
    });
    propose_all(&store, batches, 4).await?;
    let preload_secs = started.elapsed().as_secs_f64();
    println!("  preloaded {preload} records in {preload_secs:.1} s");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let sm_redb_bytes_after_preload = disk_sizes(&dir.node(1)).sm_redb;

    let mut levels = Vec::new();
    let mut generation = 1_u32;
    for &rate in &args.rates {
        let level = open_loop(&store, rate, args.secs, preload, generation).await?;
        print_level(&level);
        levels.push(level);
        generation += 1;
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    if args.closed_secs > 0 && args.closed_writers > 0 {
        let level = closed_loop(
            &store,
            args.closed_writers,
            args.closed_secs,
            preload,
            generation,
        )
        .await?;
        print_level(&level);
        levels.push(level);
    }

    store.shutdown().await?;
    drop(store);

    let pass = levels
        .iter()
        .find(|level| level.offered_per_s == Some(1_000))
        .is_some_and(|level| level.errors == 0 && level.achieved_per_s >= 0.99 * count_f64(1_000));
    Ok(ModeRun {
        durability: durability.to_owned(),
        preload_records: preload,
        preload_secs,
        sm_redb_bytes_after_preload,
        levels,
        pass,
    })
}

fn deltas(before: &EngineStats, after: &EngineStats) -> (u64, u64, u64, u64, u64, u64) {
    (
        after.entries_proposed - before.entries_proposed,
        after.batches_proposed - before.batches_proposed,
        after.log_commits - before.log_commits,
        after.log_appended_bytes - before.log_appended_bytes,
        after.checkpoints - before.checkpoints,
        after.snapshots_built - before.snapshots_built,
    )
}

async fn update_task(
    store: RaftStore,
    counters: Arc<Counters>,
    sequence: u64,
    preload: u64,
    generation: u32,
    deadline: Instant,
) {
    let id = mix(sequence ^ 0xC0A1_E5CE) % preload;
    let batch = data::update_batch(id, generation);
    let began = Instant::now();
    let result = store.propose(batch).await;
    let elapsed = began.elapsed();
    counters.record(
        result.map(|_| ()).map_err(|error| error.to_string()),
        elapsed,
        deadline,
    );
}

async fn open_loop(
    store: &RaftStore,
    rate: u64,
    secs: u64,
    preload: u64,
    generation: u32,
) -> Result<Level> {
    let counters = Counters::new();
    let before = store.engine_stats();
    let window = Duration::from_secs(secs);
    let start = Instant::now();
    let deadline = start + window;
    let handle = Handle::current();
    let pacer = {
        let store = store.clone();
        let counters = Arc::clone(&counters);
        tokio::task::spawn_blocking(move || {
            let mut issued = 0_u64;
            loop {
                let elapsed = start.elapsed();
                if elapsed >= window {
                    return issued;
                }
                let due = due_count(elapsed, rate);
                while issued < due {
                    handle.spawn(update_task(
                        store.clone(),
                        Arc::clone(&counters),
                        issued,
                        preload,
                        generation,
                        deadline,
                    ));
                    issued += 1;
                }
                thread::sleep(Duration::from_millis(1));
            }
        })
    };
    let issued = pacer.await?;
    let window_end = Instant::now();
    let completed_at_end = counters.done.load(Ordering::Acquire);
    // Let the backlog finish (a proposal gives up after the store's 60 s write timeout).
    while counters.done.load(Ordering::Acquire) < issued {
        if window_end.elapsed() > Duration::from_secs(120) {
            bail!("proposals still outstanding two minutes after the window");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let drain_secs = window_end.elapsed().as_secs_f64();
    Ok(finish_level(
        "open-loop",
        Some(rate),
        None,
        secs,
        (issued, issued.saturating_sub(completed_at_end), drain_secs),
        &counters,
        &before,
        &store.engine_stats(),
    ))
}

async fn closed_loop(
    store: &RaftStore,
    writers: usize,
    secs: u64,
    preload: u64,
    generation: u32,
) -> Result<Level> {
    let counters = Counters::new();
    let before = store.engine_stats();
    let start = Instant::now();
    let deadline = start + Duration::from_secs(secs);
    let issued = Arc::new(AtomicU64::new(0));
    let mut set = JoinSet::new();
    for _ in 0..writers {
        let store = store.clone();
        let counters = Arc::clone(&counters);
        let issued = Arc::clone(&issued);
        set.spawn(async move {
            while Instant::now() < deadline {
                let sequence = issued.fetch_add(1, Ordering::Relaxed);
                update_task(
                    store.clone(),
                    Arc::clone(&counters),
                    sequence,
                    preload,
                    generation,
                    deadline,
                )
                .await;
            }
        });
    }
    while set.join_next().await.is_some() {}
    let total = issued.load(Ordering::Relaxed);
    let drain_secs = start.elapsed().as_secs_f64() - count_f64(secs);
    Ok(finish_level(
        "closed-loop",
        None,
        Some(writers),
        secs,
        (total, 0, drain_secs.max(0.0)),
        &counters,
        &before,
        &store.engine_stats(),
    ))
}

#[allow(clippy::too_many_arguments, reason = "assembles one result row")]
fn finish_level(
    kind: &str,
    offered: Option<u64>,
    writers: Option<usize>,
    secs: u64,
    (issued, backlog, drain_secs): (u64, u64, f64),
    counters: &Counters,
    before: &EngineStats,
    after: &EngineStats,
) -> Level {
    let (entries, batches, log_commits, log_appended_bytes, checkpoints, snapshots_built) =
        deltas(before, after);
    let in_window = counters.in_window.load(Ordering::Relaxed);
    let latency = summarize(&counters.hist.lock().unwrap_or_else(PoisonError::into_inner));
    Level {
        kind: kind.to_owned(),
        offered_per_s: offered,
        writers,
        window_secs: count_f64(secs),
        issued,
        completed_ok: counters.ok.load(Ordering::Relaxed),
        completed_in_window: in_window,
        errors: counters.errors.load(Ordering::Relaxed),
        error_samples: counters
            .samples
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone(),
        achieved_per_s: count_f64(in_window) / count_f64(secs),
        backlog_at_window_end: backlog,
        drain_secs,
        latency,
        entries,
        batches,
        batches_per_entry: if entries > 0 {
            count_f64(batches) / count_f64(entries)
        } else {
            0.0
        },
        log_commits,
        log_appended_bytes,
        checkpoints,
        snapshots_built,
    }
}

fn print_level(level: &Level) {
    let label = level.offered_per_s.map_or_else(
        || format!("closed loop, {} writers", level.writers.unwrap_or(0)),
        |rate| format!("open loop, {rate}/s offered"),
    );
    println!(
        "  {label}: achieved {:.0}/s, p50 {:.1} ms, p99 {:.1} ms, max {:.1} ms, errors {}, \
         {:.1} batches/entry ({} entries), backlog at end {}",
        level.achieved_per_s,
        count_f64(level.latency.p50_ns) / 1e6,
        count_f64(level.latency.p99_ns) / 1e6,
        count_f64(level.latency.max_ns) / 1e6,
        level.errors,
        level.batches_per_entry,
        level.entries,
        level.backlog_at_window_end,
    );
}

impl Config {
    /// The checkpoint interval in milliseconds, whichever field the file has.
    pub fn checkpoint_ms(&self) -> u64 {
        if self.checkpoint_interval_ms > 0 {
            self.checkpoint_interval_ms
        } else {
            self.checkpoint_interval_secs * 1_000
        }
    }
}
