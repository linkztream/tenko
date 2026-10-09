//! Spike A: can an embedded Raft-replicated store (openraft) over an embedded KV store (redb),
//! serving DNS queries from an in-memory index, hold a DNS zone of more than 1 million records?
//!
//! Every subcommand runs a real openraft cluster inside this process; nodes talk over an
//! in-process channel network. See README.md.

#![forbid(unsafe_code)]
// openraft storage traits return large error types and deeply nested generic types by design;
// this benchmark keeps them as-is instead of boxing every error on the measured paths.
#![allow(clippy::result_large_err, clippy::type_complexity)]

mod bench;
mod cluster;
#[path = "gen.rs"]
mod datagen;
mod index;
mod log_store;
mod measure;
mod model;
mod network;
mod raft_types;
mod report;
mod results;
mod state_machine;

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::Context;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use redb::Durability;
use serde::Deserialize;
use serde::Serialize;

use crate::bench::LoadParams;
use crate::bench::SteadyParams;
use crate::cluster::Cluster;
use crate::cluster::ClusterOptions;
use crate::datagen::GenConfig;
use crate::measure::RssSampler;
use crate::measure::current_rss_bytes;
use crate::measure::fmt_bytes;
use crate::measure::fmt_ns;
use crate::results::BulkLoadResult;
use crate::results::CatchUpResult;
use crate::results::ChangeFeedResult;
use crate::results::Criterion;
use crate::results::DepVersion;
use crate::results::Results;
use crate::results::RunConfig;
use crate::results::SteadyStateResult;

const RUN_DATE: &str = "2026-10-09";

#[derive(Parser, Debug)]
#[command(
    name = "spike-a-raft",
    about = "Spike A: openraft + redb store for a 1M+ record DNS zone"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Bulk-load N forward-zone records through the leader; optionally measure steady-state
    /// lookups under writes and the change feed, add a learner that catches up from a
    /// snapshot, and compact one follower sm.redb afterwards.
    Load(LoadArgs),
    /// Run every phase, each in its own child process, and write the results Markdown.
    All(AllArgs),
    /// Re-render the Markdown from a saved results JSON (optionally appending extra Markdown).
    Report(ReportArgs),
    /// Assemble a results JSON + Markdown from phase JSON files (`load --json-out`); an input
    /// may carry a disk label as FILE::LABEL for files that did not record one.
    Collect(CollectArgs),
}

#[derive(Copy, Clone, Debug, ValueEnum, Serialize, Deserialize)]
enum SmDurability {
    /// fsync on every state machine apply transaction.
    Immediate,
    /// No fsync on apply (the Raft log is still fsynced); crash recovery replays the log.
    None,
}

#[derive(Args, Debug, Clone)]
struct CommonArgs {
    /// Directory for node data (redb files, snapshots). Wiped per run.
    #[arg(long, default_value = "data")]
    data_dir: PathBuf,
    /// Human-readable description of the disk that holds --data-dir (shown in the report).
    #[arg(long, default_value = "unspecified disk")]
    disk_label: String,
    /// Records per Raft entry for the bulk load.
    #[arg(long, default_value_t = 10_000)]
    batch: usize,
    /// PTR RRsets generated per 100 forward-zone hosts.
    #[arg(long, default_value_t = 20)]
    ptr_percent: u8,
    /// redb page cache for each node's log.redb, in MiB.
    #[arg(long, default_value_t = 64)]
    log_cache_mb: usize,
    /// redb page cache for each node's sm.redb, in MiB.
    #[arg(long, default_value_t = 256)]
    sm_cache_mb: usize,
    /// Durability of state machine apply transactions.
    #[arg(long, value_enum, default_value_t = SmDurability::Immediate)]
    sm_durability: SmDurability,
    /// Maximum Raft entries per AppendEntries RPC.
    #[arg(long, default_value_t = 4)]
    max_payload_entries: u64,
    /// Outstanding client_write calls during the bulk load.
    #[arg(long, default_value_t = 4)]
    inflight: usize,
    /// Threads generating record batches during the bulk load.
    #[arg(long, default_value_t = 4)]
    producers: usize,
    /// Journal records kept for the change feed.
    #[arg(long, default_value_t = 100_000)]
    journal_retain: u64,
    /// Raft heartbeat interval in ms (openraft also uses it as the AppendEntries RPC timeout).
    #[arg(long, default_value_t = 1000)]
    heartbeat_ms: u64,
    /// Minimum election timeout in ms (maximum is twice this).
    #[arg(long, default_value_t = 5000)]
    election_min_ms: u64,
    /// RSS sampling interval in ms (0 = only explicit samples at phase boundaries).
    #[arg(long, default_value_t = 100)]
    rss_interval_ms: u64,
    #[arg(long, default_value_t = 42)]
    seed: u64,
    /// Write the phase result as JSON to this file.
    #[arg(long)]
    json_out: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
struct LoadArgs {
    /// Number of A RRsets in the single forward zone `example.test`.
    #[arg(long, default_value_t = 1_000_000)]
    records: u64,
    /// Voters in the cluster (1 = one node per process, for per-node RSS).
    #[arg(long, default_value_t = 3)]
    voters: u32,
    /// After the load, run the steady-state lookup/write measurement and the change feed.
    #[arg(long)]
    steady: bool,
    /// After the load (and steady state), snapshot + purge the leader log and add a learner.
    #[arg(long)]
    catch_up: bool,
    /// After everything, shut down and compact one follower's sm.redb offline.
    #[arg(long)]
    compact: bool,
    #[command(flatten)]
    steady_opts: SteadyOpts,
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args, Debug, Clone)]
struct SteadyOpts {
    /// Baseline + under-writes pairs (each phase lasts --seconds).
    #[arg(long, default_value_t = 3)]
    rounds: u32,
    #[arg(long, default_value_t = 60)]
    seconds: u64,
    /// Single-record updates per second through Raft.
    #[arg(long, default_value_t = 1_000)]
    write_rate: u64,
    /// Lookups per second against a follower's in-memory index.
    #[arg(long, default_value_t = 50_000)]
    lookup_rate: u64,
    /// Number of most recent changes to enumerate for the change feed.
    #[arg(long, default_value_t = 10_000)]
    change_feed: u64,
    /// Maximum single-record updates coalesced into one Raft entry.
    #[arg(long, default_value_t = 1_000)]
    max_coalesce: usize,
    /// Coalesced proposals outstanding at once.
    #[arg(long, default_value_t = 4)]
    proposals_inflight: usize,
    /// Duration of the closed-loop one-entry-per-write ceiling probe (0 = skip).
    #[arg(long, default_value_t = 10)]
    ceiling_seconds: u64,
    /// Concurrent writers for the ceiling probe.
    #[arg(long, default_value_t = 16)]
    ceiling_concurrency: usize,
}

impl SteadyOpts {
    fn child_args(&self) -> Vec<String> {
        vec![
            "--rounds".into(),
            self.rounds.to_string(),
            "--seconds".into(),
            self.seconds.to_string(),
            "--write-rate".into(),
            self.write_rate.to_string(),
            "--lookup-rate".into(),
            self.lookup_rate.to_string(),
            "--change-feed".into(),
            self.change_feed.to_string(),
            "--max-coalesce".into(),
            self.max_coalesce.to_string(),
            "--proposals-inflight".into(),
            self.proposals_inflight.to_string(),
            "--ceiling-seconds".into(),
            self.ceiling_seconds.to_string(),
            "--ceiling-concurrency".into(),
            self.ceiling_concurrency.to_string(),
        ]
    }
}

#[derive(Args, Debug, Clone)]
struct AllArgs {
    /// Forward-zone sizes for the 3-voter load + catch-up + compaction runs.
    #[arg(long, value_delimiter = ',', default_value = "1000000,5000000")]
    sizes: Vec<u64>,
    /// Forward-zone size of the run that also measures steady state and the change feed
    /// (combined with the load run of the same size when it is in --sizes).
    #[arg(long, default_value_t = 5_000_000)]
    steady_records: u64,
    /// Skip the single-voter per-node RSS run.
    #[arg(long)]
    skip_single_node: bool,
    /// Skip the steady-state measurement.
    #[arg(long)]
    skip_steady: bool,
    /// Add to the results already in --json instead of starting a new results file.
    #[arg(long)]
    append: bool,
    #[arg(long, default_value = "results/2026-10-09-windows.md")]
    out: PathBuf,
    #[arg(long, default_value = "results/2026-10-09-windows.json")]
    json: PathBuf,
    /// Markdown appended verbatim to the report (e.g. the recommendation).
    #[arg(long)]
    extra: Option<PathBuf>,
    #[command(flatten)]
    steady_opts: SteadyOpts,
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args, Debug, Clone)]
struct ReportArgs {
    #[arg(long, default_value = "results/2026-10-09-windows.json")]
    json: PathBuf,
    #[arg(long, default_value = "results/2026-10-09-windows.md")]
    out: PathBuf,
    #[arg(long)]
    extra: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
struct CollectArgs {
    /// Phase JSON files, in report order (FILE or FILE::DISK-LABEL).
    #[arg(long = "input", required = true)]
    inputs: Vec<String>,
    #[arg(long, default_value = "results/2026-10-09-windows.json")]
    json: PathBuf,
    #[arg(long, default_value = "results/2026-10-09-windows.md")]
    out: PathBuf,
    #[arg(long)]
    extra: Option<PathBuf>,
}

/// What one child process reports back.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PhaseOutput {
    config: RunConfig,
    bulk_load: Option<BulkLoadResult>,
    catch_up: Option<CatchUpResult>,
    #[serde(default)]
    steady: Vec<SteadyStateResult>,
    change_feed: Option<ChangeFeedResult>,
    notes: Vec<String>,
}

fn cluster_options(c: &CommonArgs) -> ClusterOptions {
    ClusterOptions {
        log_cache_bytes: c.log_cache_mb << 20,
        sm_cache_bytes: c.sm_cache_mb << 20,
        sm_durability: match c.sm_durability {
            SmDurability::Immediate => Durability::Immediate,
            SmDurability::None => Durability::None,
        },
        journal_retain: c.journal_retain,
        max_payload_entries: c.max_payload_entries,
        heartbeat_ms: c.heartbeat_ms,
        election_min_ms: c.election_min_ms,
        election_max_ms: c.election_min_ms * 2,
    }
}

fn run_config(c: &CommonArgs, voters: u32) -> RunConfig {
    RunConfig {
        mode: "openraft".into(),
        voters,
        batch_records: c.batch as u64,
        ptr_percent: c.ptr_percent,
        redb_cache_bytes: (c.sm_cache_mb << 20) as u64,
        log_store: format!(
            "redb, separate log.redb per node (page cache {} MiB); sm.redb page cache {} MiB",
            c.log_cache_mb, c.sm_cache_mb
        ),
        log_durability: "Immediate: one fsynced redb commit per append() call".into(),
        sm_durability: match c.sm_durability {
            SmDurability::Immediate => "Immediate: one fsynced redb commit per apply() call".into(),
            SmDurability::None => "None: apply() commits without fsync (log is fsynced)".into(),
        },
        max_payload_entries: c.max_payload_entries,
        network: format!(
            "in-process: per-node RPC task fed by tokio mpsc channels, messages moved (not serialized); snapshots streamed as 1 MiB chunks into a file on the receiver; heartbeat {} ms (= AppendEntries timeout), election timeout {}-{} ms",
            c.heartbeat_ms,
            c.election_min_ms,
            c.election_min_ms * 2
        ),
    }
}

fn gen_config(records: u64, c: &CommonArgs) -> GenConfig {
    GenConfig {
        forward_records: records,
        ptr_percent: c.ptr_percent,
        seed: c.seed,
    }
}

fn write_json<T: Serialize>(path: &Path, v: &T) -> anyhow::Result<()> {
    if let Some(p) = path.parent()
        && !p.as_os_str().is_empty()
    {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(v)?)?;
    Ok(())
}

fn wipe_dir(dir: &Path) -> anyhow::Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    std::fs::create_dir_all(dir)?;
    Ok(())
}

async fn cmd_load(a: LoadArgs) -> anyhow::Result<PhaseOutput> {
    let c = &a.common;
    let so = &a.steady_opts;
    let sampler = RssSampler::start(Duration::from_millis(if c.rss_interval_ms == 0 {
        3_600_000
    } else {
        c.rss_interval_ms
    }));
    let rss_before = current_rss_bytes();
    let dir = c.data_dir.join(format!("load-{}-v{}", a.records, a.voters));
    wipe_dir(&dir)?;
    let mut out = PhaseOutput {
        config: run_config(c, a.voters),
        ..Default::default()
    };
    out.notes.push(commit_probe_note(&dir, &c.disk_label));
    let mut cluster = Cluster::start(&dir, a.voters, cluster_options(c)).await?;
    let cfg = gen_config(a.records, c);
    let params = LoadParams {
        batch: c.batch,
        inflight: c.inflight,
        producers: c.producers,
    };

    // 1. Bulk load.
    let mut bulk = bench::bulk_load_phase(&cluster, cfg, params, &sampler, rss_before).await?;
    bulk.disk = c.disk_label.clone();
    println!("{}", report::bulk_load_table(std::slice::from_ref(&bulk)));
    println!("{}", report::disk_table(std::slice::from_ref(&bulk)));

    // 2. Steady state + change feed.
    if a.steady {
        anyhow::ensure!(a.voters >= 2, "--steady needs a follower (voters >= 2)");
        let sp = SteadyParams {
            rounds: so.rounds,
            seconds: so.seconds,
            write_rate: so.write_rate,
            lookup_rate: so.lookup_rate,
            seed: c.seed,
            max_coalesce: so.max_coalesce,
            proposals_inflight: so.proposals_inflight,
        };
        let (mut steady, mut extras) = bench::steady_phase(&cluster, cfg, &sp).await?;
        for s in &mut steady {
            s.disk = c.disk_label.clone();
        }
        println!("{}", report::steady_table(&steady));
        let mut cf = bench::change_feed_phase(&cluster, so.change_feed).await?;
        cf.disk = c.disk_label.clone();
        cf.total_records = bulk.total_records;
        println!("{}", report::change_feed_table(std::slice::from_ref(&cf)));
        let journal_len = cluster.follower()?.sm.journal_len().unwrap_or(0);
        let (commits, entries) = cluster.leader()?.log.io_stats();
        if so.ceiling_seconds > 0 {
            bench::per_entry_ceiling(
                &cluster,
                cfg,
                so.ceiling_seconds,
                so.ceiling_concurrency,
                &mut extras,
            )
            .await?;
            cluster
                .follower()?
                .raft
                .wait(Some(Duration::from_secs(600)))
                .metrics(|m| m.current_leader.is_some(), "leader after ceiling probe")
                .await?;
        }
        out.notes.push(format!(
            "[{}] Steady state ({} RRsets, lookups on a follower's index, writes through the leader): {} rounds of {} s baseline + {} s under writes. {} single-record updates were coalesced into {} Raft entries ({:.1} updates per entry on average, at most {} per entry, {} proposals in flight). Over the whole run the leader log writer made {} fsynced commits for {} log entries (openraft 0.9 hands the leader one append at a time and waits for its flush, so group commit cannot batch on the leader). The change journal held {} records afterwards.",
            c.disk_label,
            bulk.total_records,
            so.rounds,
            so.seconds,
            so.seconds,
            extras.updates,
            extras.raft_entries,
            extras.updates as f64 / extras.raft_entries.max(1) as f64,
            so.max_coalesce,
            so.proposals_inflight,
            commits,
            entries,
            journal_len
        ));
        if so.ceiling_seconds > 0 {
            out.notes.push(format!(
                "[{}] Per-entry write ceiling ({} RRsets): with one single-record Raft entry per client_write and {} concurrent closed-loop writers for {} s, the leader completed {:.0} writes/s (latency p50 {}, p99 {}, errors {}). openraft 0.9.25 awaits each log flush before it handles the next client request (RaftCore::append_to_log), so without coalescing this ceiling is set by the fsync latency of the data disk.",
                c.disk_label,
                bulk.total_records,
                so.ceiling_concurrency,
                so.ceiling_seconds,
                extras.per_entry_rate,
                fmt_ns(extras.per_entry_latency.p50_ns),
                fmt_ns(extras.per_entry_latency.p99_ns),
                extras.per_entry_errors
            ));
        }
        out.steady = steady;
        out.change_feed = Some(cf);
    }

    // 3. Learner catch-up.
    if a.catch_up {
        let learner_id = a.voters as u64 + 1;
        let mut cu =
            bench::catch_up_phase(&mut cluster, learner_id, cfg.total_records(), &sampler).await?;
        cu.disk = c.disk_label.clone();
        println!("{}", report::catch_up_table(std::slice::from_ref(&cu)));
        out.catch_up = Some(cu);
    }

    // 4. Offline compaction of one follower's state machine file.
    let compact_target = if a.compact {
        let f = cluster.follower()?;
        Some((f.id, f.sm_file()))
    } else {
        None
    };
    cluster.shutdown().await?;
    if let Some((id, path)) = compact_target {
        tokio::time::sleep(Duration::from_millis(500)).await;
        match tokio::task::spawn_blocking(move || bench::compact_file(id, &path)).await? {
            Ok(cr) => {
                eprintln!(
                    "compaction of node {} sm.redb: {} -> {} in {:.2} s",
                    cr.node_id,
                    fmt_bytes(cr.file_bytes_before),
                    fmt_bytes(cr.file_bytes_after),
                    cr.compact_secs
                );
                bulk.compaction = Some(cr);
            }
            Err(e) => out.notes.push(format!(
                "Compaction after the {}-record run was not measured: {e}",
                a.records
            )),
        }
    }
    out.bulk_load = Some(bulk);
    sampler.stop();
    Ok(out)
}

/// Measure small fsynced redb commits on the data disk and describe them in one note.
fn commit_probe_note(dir: &Path, disk: &str) -> String {
    match bench::commit_latency_probe(&dir.join("probe"), 205) {
        Ok(l) => format!(
            "[{disk}] Data disk fsync cost: 200 small redb commits with Durability::Immediate took p50 {}, p99 {}, max {} (idle disk, before the cluster started).",
            fmt_ns(l.p50_ns),
            fmt_ns(l.p99_ns),
            fmt_ns(l.max_ns)
        ),
        Err(e) => format!("[{disk}] Data disk fsync probe failed: {e}"),
    }
}

/// Exact resolved versions of the direct dependencies, read from Cargo.lock.
fn dependency_versions() -> Vec<DepVersion> {
    let direct = [
        "openraft",
        "redb",
        "tokio",
        "clap",
        "serde",
        "postcard",
        "serde_bytes",
        "serde_json",
        "sysinfo",
        "hdrhistogram",
        "rand",
        "anyhow",
        "tracing",
        "tracing-subscriber",
    ];
    let lock = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"))
        .unwrap_or_default();
    // Every (name, version) in the lock file, plus the dependency list of this crate. When a
    // crate appears in several versions, the lock file names the one this crate uses
    // ("rand 0.10.3").
    let mut all: Vec<(String, String)> = Vec::new();
    let mut own: Vec<String> = Vec::new();
    for block in lock.split("[[package]]") {
        let field = |key: &str| {
            block.lines().find_map(|l| {
                l.strip_prefix(key)
                    .map(|v| v.trim().trim_matches('"').to_string())
            })
        };
        let (Some(name), Some(version)) = (field("name = "), field("version = ")) else {
            continue;
        };
        if name == env!("CARGO_PKG_NAME")
            && let Some(deps) = block.split("dependencies = [").nth(1)
        {
            own = deps
                .split(']')
                .next()
                .unwrap_or_default()
                .split(',')
                .map(|d| d.trim().trim_matches('"').to_string())
                .filter(|d| !d.is_empty())
                .collect();
        }
        all.push((name, version));
    }
    let mut out = Vec::new();
    for name in direct {
        let pinned = own.iter().find_map(|d| {
            let mut parts = d.split(' ');
            (parts.next() == Some(name))
                .then(|| parts.next().map(str::to_string))
                .flatten()
        });
        let version =
            pinned.or_else(|| all.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone()));
        if let Some(version) = version {
            out.push(DepVersion {
                name: name.to_string(),
                version,
            });
        }
    }
    out
}

fn run_child(args: &[String], data_dir: &Path) -> anyhow::Result<PhaseOutput> {
    let exe = std::env::current_exe()?;
    let json = data_dir.join(format!(
        "spike-a-phase-{}-{}.json",
        std::process::id(),
        rand_suffix()
    ));
    let mut cmd = Command::new(exe);
    cmd.args(args).arg("--json-out").arg(&json);
    eprintln!("\n=== spike-a-raft {} ===", args.join(" "));
    let status = cmd.status()?;
    anyhow::ensure!(
        status.success(),
        "child `{}` failed with {status}",
        args.join(" ")
    );
    let out: PhaseOutput = serde_json::from_slice(&std::fs::read(&json)?)?;
    let _ = std::fs::remove_file(&json);
    Ok(out)
}

fn rand_suffix() -> u64 {
    use rand::RngExt;
    rand::rng().random::<u64>()
}

fn common_child_args(c: &CommonArgs) -> Vec<String> {
    vec![
        "--data-dir".into(),
        c.data_dir.display().to_string(),
        "--disk-label".into(),
        c.disk_label.clone(),
        "--batch".into(),
        c.batch.to_string(),
        "--ptr-percent".into(),
        c.ptr_percent.to_string(),
        "--log-cache-mb".into(),
        c.log_cache_mb.to_string(),
        "--sm-cache-mb".into(),
        c.sm_cache_mb.to_string(),
        "--sm-durability".into(),
        match c.sm_durability {
            SmDurability::Immediate => "immediate".into(),
            SmDurability::None => "none".into(),
        },
        "--max-payload-entries".into(),
        c.max_payload_entries.to_string(),
        "--inflight".into(),
        c.inflight.to_string(),
        "--producers".into(),
        c.producers.to_string(),
        "--journal-retain".into(),
        c.journal_retain.to_string(),
        "--seed".into(),
        c.seed.to_string(),
        "--rss-interval-ms".into(),
        c.rss_interval_ms.to_string(),
        "--heartbeat-ms".into(),
        c.heartbeat_ms.to_string(),
        "--election-min-ms".into(),
        c.election_min_ms.to_string(),
    ]
}

const TWO_GB: u64 = 2_000_000_000;

/// Distinct data-disk labels in order of first appearance.
fn disks(r: &Results) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let all = r
        .bulk_loads
        .iter()
        .map(|b| &b.disk)
        .chain(r.catch_ups.iter().map(|c| &c.disk))
        .chain(r.steady.iter().map(|s| &s.disk));
    for d in all {
        if !out.contains(d) {
            out.push(d.clone());
        }
    }
    out
}

/// Pass criteria, evaluated separately for every data disk that has the relevant results.
fn criteria(r: &Results) -> Vec<Criterion> {
    let mut out = Vec::new();
    let (mut rss_seen, mut cu_seen, mut steady_seen) = (false, false, false);
    for disk in disks(r) {
        let tag = format!("[{disk}] ");
        // 1. Peak RSS < 2 GB at 5M records, judged on one node per process.
        let biggest_single = r
            .bulk_loads
            .iter()
            .filter(|b| b.voters == 1 && b.disk == disk)
            .max_by_key(|b| b.forward_zone_records);
        if let Some(b) = biggest_single {
            rss_seen = true;
            let three = r
                .bulk_loads
                .iter()
                .filter(|t| t.voters == 3 && t.forward_zone_records == b.forward_zone_records)
                .map(|t| t.peak_rss_bytes)
                .max()
                .map(|p| {
                    format!(
                        "; whole 3-voter process (3 nodes in one process): {}",
                        fmt_bytes(p)
                    )
                })
                .unwrap_or_default();
            out.push(Criterion {
                name: format!(
                    "{tag}Peak RSS of one node at {} forward-zone records ({} RRsets total)",
                    measure::fmt_count(b.forward_zone_records),
                    measure::fmt_count(b.total_records)
                ),
                threshold: "< 2 GB (2,000,000,000 bytes) at >= 5M records".into(),
                measured: format!(
                    "{} ({} bytes), single-voter process{three}",
                    fmt_bytes(b.peak_rss_bytes),
                    measure::fmt_count(b.peak_rss_bytes)
                ),
                pass: b.forward_zone_records >= 5_000_000 && b.peak_rss_bytes < TWO_GB,
            });
        }
        // 2./3. Learner catch-up.
        // Largest size on this disk; if several runs measured it, the slowest one counts.
        let cu_max = r
            .catch_ups
            .iter()
            .filter(|c| c.disk == disk)
            .map(|c| c.total_records)
            .max();
        let worst = r
            .catch_ups
            .iter()
            .filter(|c| c.disk == disk && Some(c.total_records) == cu_max)
            .max_by(|a, b| a.total_catch_up_secs.total_cmp(&b.total_catch_up_secs));
        if let Some(c) = worst {
            cu_seen = true;
            out.push(Criterion {
                name: format!(
                    "{tag}Learner catch-up in-process ({} RRsets)",
                    measure::fmt_count(c.total_records)
                ),
                threshold: "< 5 min".into(),
                measured: format!("{:.2} s", c.total_catch_up_secs),
                pass: c.total_catch_up_secs < 300.0,
            });
            out.push(Criterion {
                name: format!(
                    "{tag}Snapshot transfer at 1 Gbit/s ({} RRsets)",
                    measure::fmt_count(c.total_records)
                ),
                threshold: "snapshot bytes / 125 MB/s < 5 min".into(),
                measured: format!(
                    "{} / 125 MB/s = {:.2} s",
                    fmt_bytes(c.snapshot_bytes),
                    c.theoretical_1gbit_secs
                ),
                pass: c.theoretical_1gbit_secs < 300.0,
            });
        }
        // 4./5. Lookup p99 under write load (median over the rounds of the largest steady run).
        let max_steady = r
            .steady
            .iter()
            .filter(|s| s.disk == disk)
            .map(|s| s.total_records)
            .max();
        if let Some(n) = max_steady {
            steady_seen = true;
            let rounds: Vec<&SteadyStateResult> = r
                .steady
                .iter()
                .filter(|s| s.disk == disk && s.total_records == n)
                .collect();
            let mut base: Vec<u64> = rounds
                .iter()
                .map(|s| s.baseline.lookup_latency.p99_ns)
                .collect();
            let mut load: Vec<u64> = rounds
                .iter()
                .map(|s| s.under_writes.lookup_latency.p99_ns)
                .collect();
            let per_round = rounds
                .iter()
                .map(|s| {
                    format!(
                        "{} vs {}",
                        fmt_ns(s.under_writes.lookup_latency.p99_ns),
                        fmt_ns(s.baseline.lookup_latency.p99_ns)
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            base.sort_unstable();
            load.sort_unstable();
            let b = base[base.len() / 2];
            let w = load[load.len() / 2];
            out.push(Criterion {
                name: format!(
                    "{tag}Lookup p99 under write load vs baseline ({} RRsets, median of {} rounds)",
                    measure::fmt_count(n),
                    rounds.len()
                ),
                threshold: "< 2x baseline p99".into(),
                measured: format!(
                    "{} vs {} ({:.2}x); per round (loaded vs baseline): {per_round}",
                    fmt_ns(w),
                    fmt_ns(b),
                    w as f64 / b.max(1) as f64
                ),
                pass: w < 2 * b,
            });
            let worst = load.last().copied().unwrap_or(0);
            out.push(Criterion {
                name: format!(
                    "{tag}Lookup p99 under write load, absolute ({} RRsets)",
                    measure::fmt_count(n)
                ),
                threshold: "< 1 ms (every round)".into(),
                measured: format!("median {}, worst round {}", fmt_ns(w), fmt_ns(worst)),
                pass: worst < 1_000_000,
            });
        }
    }
    let missing = |name: &str, threshold: &str| Criterion {
        name: name.into(),
        threshold: threshold.into(),
        measured: "not measured".into(),
        pass: false,
    };
    if !rss_seen {
        out.push(missing("Peak RSS of one node at 5M records", "< 2 GB"));
    }
    if !cu_seen {
        out.push(missing("Learner catch-up", "< 5 min"));
    }
    if !steady_seen {
        out.push(missing(
            "Lookup p99 under write load",
            "< 2x baseline and < 1 ms",
        ));
    }
    out
}

fn print_and_write(r: &Results, out: &Path, extra: Option<&Path>) -> anyhow::Result<()> {
    let extra_text = match extra {
        Some(p) => {
            Some(std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?)
        }
        None => None,
    };
    println!("\n{}", report::criteria_table(&r.criteria));
    report::write_markdown(out, r, extra_text.as_deref())?;
    eprintln!("wrote {}", out.display());
    Ok(())
}

fn cmd_all(a: AllArgs) -> anyhow::Result<()> {
    let c = &a.common;
    let common = common_child_args(c);
    let steady_args = a.steady_opts.child_args();
    let mut results = if a.append && a.json.exists() {
        serde_json::from_slice::<Results>(&std::fs::read(&a.json)?)?
    } else {
        Results {
            date: RUN_DATE.into(),
            machine: measure::machine_info(),
            deps: dependency_versions(),
            config: run_config(c, 3),
            ..Default::default()
        }
    };
    let push = |o: PhaseOutput, results: &mut Results| {
        if let Some(b) = o.bulk_load {
            results.bulk_loads.push(b);
        }
        if let Some(cu) = o.catch_up {
            results.catch_ups.push(cu);
        }
        results.steady.extend(o.steady);
        if let Some(cf) = o.change_feed {
            results.change_feed.push(cf);
        }
        results.notes.extend(o.notes);
    };
    let mut steady_done = a.skip_steady;
    for &n in &a.sizes {
        let mut args: Vec<String> = vec![
            "load".into(),
            "--records".into(),
            n.to_string(),
            "--voters".into(),
            "3".into(),
            "--catch-up".into(),
            "--compact".into(),
        ];
        if !steady_done && n == a.steady_records {
            args.push("--steady".into());
            steady_done = true;
        }
        args.extend(steady_args.iter().cloned());
        args.extend(common.iter().cloned());
        let o = run_child(&args, &c.data_dir)?;
        push(o, &mut results);
        results.criteria = criteria(&results);
        write_json(&a.json, &results)?;
        print_and_write(&results, &a.out, a.extra.as_deref())?;
    }
    if !steady_done {
        let mut args: Vec<String> = vec![
            "load".into(),
            "--records".into(),
            a.steady_records.to_string(),
            "--voters".into(),
            "3".into(),
            "--steady".into(),
        ];
        args.extend(steady_args.iter().cloned());
        args.extend(common.iter().cloned());
        let o = run_child(&args, &c.data_dir)?;
        push(o, &mut results);
        results.criteria = criteria(&results);
        write_json(&a.json, &results)?;
        print_and_write(&results, &a.out, a.extra.as_deref())?;
    }
    if !a.skip_single_node {
        let n = *a.sizes.iter().max().unwrap_or(&5_000_000);
        let mut args: Vec<String> = vec![
            "load".into(),
            "--records".into(),
            n.to_string(),
            "--voters".into(),
            "1".into(),
        ];
        args.extend(common.iter().cloned());
        let o = run_child(&args, &c.data_dir)?;
        push(o, &mut results);
    }
    results.criteria = criteria(&results);
    write_json(&a.json, &results)?;
    print_and_write(&results, &a.out, a.extra.as_deref())
}

/// Assemble a results file from phase JSON files written by `load --json-out`.
fn cmd_collect(a: CollectArgs) -> anyhow::Result<()> {
    let mut results = Results {
        date: RUN_DATE.into(),
        machine: measure::machine_info(),
        deps: dependency_versions(),
        ..Default::default()
    };
    for input in &a.inputs {
        let (path, label) = match input.split_once("::") {
            Some((p, l)) => (p.to_string(), Some(l.to_string())),
            None => (input.clone(), None),
        };
        let mut o: PhaseOutput = serde_json::from_slice(
            &std::fs::read(&path).with_context(|| format!("reading {path}"))?,
        )?;
        let phase_total = o.bulk_load.as_ref().map_or(0, |b| b.total_records);
        if let Some(l) = &label {
            if let Some(b) = &mut o.bulk_load
                && b.disk.is_empty()
            {
                b.disk = l.clone();
            }
            if let Some(c) = &mut o.catch_up
                && c.disk.is_empty()
            {
                c.disk = l.clone();
            }
            for s in &mut o.steady {
                if s.disk.is_empty() {
                    s.disk = l.clone();
                }
            }
            if let Some(cf) = &mut o.change_feed
                && cf.disk.is_empty()
            {
                cf.disk = l.clone();
            }
        }
        if results.config.mode.is_empty() || o.config.voters == 3 {
            results.config = o.config.clone();
        }
        if let Some(b) = o.bulk_load {
            results.bulk_loads.push(b);
        }
        if let Some(cu) = o.catch_up {
            results.catch_ups.push(cu);
        }
        results.steady.extend(o.steady);
        if let Some(mut cf) = o.change_feed {
            if cf.total_records == 0 {
                cf.total_records = phase_total;
            }
            results.change_feed.push(cf);
        }
        for n in o.notes {
            match &label {
                Some(l) if !n.starts_with('[') => results.notes.push(format!("[{l}] {n}")),
                _ => results.notes.push(n),
            }
        }
    }
    results.criteria = criteria(&results);
    write_json(&a.json, &results)?;
    print_and_write(&results, &a.out, a.extra.as_deref())
}

fn cmd_report(a: ReportArgs) -> anyhow::Result<()> {
    let mut r: Results = serde_json::from_slice(&std::fs::read(&a.json)?)?;
    r.criteria = criteria(&r);
    print_and_write(&r, &a.out, a.extra.as_deref())
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::All(a) => cmd_all(a),
        Cmd::Report(a) => cmd_report(a),
        Cmd::Collect(a) => cmd_collect(a),
        Cmd::Load(a) => {
            let json_out = a.common.json_out.clone();
            let out = runtime()?.block_on(cmd_load(a))?;
            if let Some(p) = json_out {
                write_json(&p, &out)?;
            }
            Ok(())
        }
    }
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}
