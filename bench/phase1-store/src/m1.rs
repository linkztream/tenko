//! M1: index swap on snapshot install (ADR 0002; threshold: no empty reads, lookup p99 during
//! the install below 2x the baseline p99).
//!
//! A leader (node 1) and a learner (node 2) run in one process over `InProcessNetwork`. The
//! learner holds a `BenchIndex` (sharded maps behind `ArcSwap`). After the learner has caught
//! up from the leader's first snapshot, it is cut off. Each round then updates 10 percent of
//! the records on the leader, snapshots, and forces the install on the learner through its
//! snapshot receiver, while reader threads look up random keys known to exist in the learner's
//! index at a fixed rate. The same readers run for a baseline window without an install.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sysinfo::{MemoryRefreshKind, System};
use tenko_core::NodeId;
use tenko_store::{
    Store as _,
    raft::{RaftStore, RaftStoreConfig, RaftTimings, SnapshotPolicy, network::InProcessNetwork},
};

use crate::{
    Ctx,
    common::{
        GIB, Machine, Rng, RssSampler, RunClock, RunMeta, ScratchDir, count_f64, current_rss,
        free_space, machine, median, mib, propose_all, push_snapshot, secs, wait_for_purge,
        wait_for_revision,
    },
    data::{self, BULK_BATCH, RRSETS},
    index::BenchIndex,
    readers::{ReaderPool, Window},
};

#[derive(Debug, Clone, clap::Args)]
pub struct Args {
    /// Record counts to run, comma separated.
    #[arg(long, value_delimiter = ',', default_value = "1000000")]
    pub records: Vec<u64>,
    /// Update-and-install rounds per record count.
    #[arg(long, default_value_t = 3)]
    pub rounds: usize,
    /// Total lookups per second over all reader threads.
    #[arg(long, default_value_t = 50_000)]
    pub lookups_per_s: u64,
    /// Reader threads.
    #[arg(long, default_value_t = 4)]
    pub readers: usize,
    /// Length of the baseline window in seconds.
    #[arg(long, default_value_t = 8)]
    pub baseline_secs: u64,
    /// Share of the records updated before each install, in percent.
    #[arg(long, default_value_t = 10)]
    pub update_percent: u64,
    /// Name of the result file in `raw/` (without extension).
    #[arg(long, default_value = "m1")]
    pub out_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round {
    pub number: usize,
    pub updated_records: u64,
    pub update_secs: f64,
    pub snapshot_bytes: u64,
    pub snapshot_build_secs: f64,
    pub baseline: Window,
    pub install: Window,
    pub p99_ratio: f64,
    pub transfer_secs: f64,
    pub install_call_secs: f64,
    pub window_secs: f64,
    pub learner_install_secs: f64,
    pub index_rebuild_secs: f64,
    /// Compaction of the fresh state file written by the install (0 before WP1.1b).
    #[serde(default)]
    pub compact_secs: f64,
    pub installs_during_window: u64,
    pub rss_before_mib: f64,
    pub rss_peak_install_mib: f64,
    pub index_records_after: u64,
    pub updated_visible_after: bool,
    pub index_revision_matches: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub empty_reads: u64,
    pub mismatches: u64,
    pub median_baseline_p99_ns: f64,
    pub median_install_p99_ns: f64,
    pub median_p99_ratio: f64,
    pub worst_p99_ratio: f64,
    pub worst_install_p99_ns: u64,
    pub worst_install_max_ns: u64,
    pub median_install_secs: f64,
    pub median_index_rebuild_secs: f64,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeRun {
    pub records: u64,
    pub load_secs: f64,
    pub initial_snapshot_bytes: u64,
    pub initial_snapshot_build_secs: f64,
    pub catch_up_secs: f64,
    pub catch_up_install_secs: f64,
    pub catch_up_index_rebuild_secs: f64,
    pub rss_after_catch_up_mib: f64,
    pub rounds: Vec<Round>,
    pub replication_by_log_after_installs: bool,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skipped {
    pub records: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub rounds: usize,
    pub lookups_per_s: u64,
    pub readers: usize,
    pub baseline_secs: u64,
    pub update_percent: u64,
    pub batch_records: usize,
    pub sm_cache_bytes: usize,
    pub log_cache_bytes: usize,
    pub durability: String,
    pub snapshot_policy: String,
    pub index: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub meta: RunMeta,
    pub machine: Machine,
    pub config: Config,
    pub available_memory_bytes: u64,
    pub runs: Vec<SizeRun>,
    pub skipped: Vec<Skipped>,
}

fn node_config(dir: &ScratchDir, node: u64) -> RaftStoreConfig {
    let mut config = RaftStoreConfig::new(dir.node(node));
    config.node_id = NodeId(node);
    config.address = format!("in-process-{node}");
    config.bootstrap = node == 1;
    config.fsync_probe_samples = 0;
    config.timings = RaftTimings {
        heartbeat_ms: 50,
        election_min_ms: 1_500,
        election_max_ms: 3_000,
    };
    // Snapshots are built on request only.
    config.snapshot = SnapshotPolicy {
        every_entries: u64::MAX,
        every_log_bytes: u64::MAX,
        keep_entries: 0,
    };
    config
}

fn available_memory() -> u64 {
    let mut system = System::new();
    system.refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
    system.available_memory()
}

pub async fn run(args: Args, ctx: &Ctx) -> Result<()> {
    let clock = RunClock::start(&ctx.data_root);
    let defaults = RaftStoreConfig::new("unused");
    let mut report = Report {
        meta: RunMeta::default(),
        machine: machine(),
        config: Config {
            rounds: args.rounds,
            lookups_per_s: args.lookups_per_s,
            readers: args.readers,
            baseline_secs: args.baseline_secs,
            update_percent: args.update_percent,
            batch_records: BULK_BATCH,
            sm_cache_bytes: defaults.sm_cache_bytes,
            log_cache_bytes: defaults.log_cache_bytes,
            durability: "Deferred, 1 s checkpoint interval (the default)".to_owned(),
            snapshot_policy: "manual: snapshots on request only, keep_entries 0".to_owned(),
            index: "64 shards of RwLock<HashMap<Bytes, Bytes>> behind ArcSwap; apply in place, \
                    build by paged scan, install by swap"
                .to_owned(),
        },
        available_memory_bytes: available_memory(),
        runs: Vec::new(),
        skipped: Vec::new(),
    };
    for &records in &args.records {
        // Disk: about 2.7 KB per record for two nodes with snapshots; memory: about 1.5 KB.
        let need_disk = records * 2_700 + 2 * GIB;
        let need_memory = records * 1_500 + 2 * GIB;
        let free_disk = free_space(&ctx.data_root).unwrap_or(0);
        let free_memory = available_memory();
        if free_disk < need_disk || free_memory < need_memory {
            let reason = format!(
                "not run: needs about {:.1} GiB of disk and {:.1} GiB of memory, \
                 {:.1} GiB and {:.1} GiB were free",
                count_f64(need_disk) / count_f64(GIB),
                count_f64(need_memory) / count_f64(GIB),
                count_f64(free_disk) / count_f64(GIB),
                count_f64(free_memory) / count_f64(GIB),
            );
            println!("M1 {records} records: {reason}");
            report.skipped.push(Skipped { records, reason });
            continue;
        }
        println!("M1 {records} records: starting");
        let run = run_size(&args, records, ctx).await?;
        print_run(&run);
        report.runs.push(run);
        report.meta = clock.finish();
        ctx.out.write(&args.out_name, &report)?;
    }
    report.meta = clock.finish();
    ctx.out.write(&args.out_name, &report)
}

#[allow(clippy::too_many_lines, reason = "one linear scenario")]
async fn run_size(args: &Args, records: u64, ctx: &Ctx) -> Result<SizeRun> {
    let dir = ScratchDir::new(&ctx.data_root, &format!("m1-{records}"))?;
    let network = InProcessNetwork::new();
    let leader = RaftStore::open_with(node_config(&dir, 1), Arc::new(network.clone())).await?;
    network.register(&leader);

    // Load.
    let started = Instant::now();
    let batches = (0..records).step_by(BULK_BATCH).map(|first| {
        let last = (first + BULK_BATCH as u64).min(records);
        data::put_batch(&(first..last).collect::<Vec<_>>(), 0)
    });
    propose_all(&leader, batches, 4).await?;
    let load_secs = started.elapsed().as_secs_f64();
    println!("  loaded {records} records in {load_secs:.1} s");

    leader.snapshot_now().await?;
    wait_for_purge(&leader).await?;
    let initial = leader.engine_stats();
    println!(
        "  first snapshot {:.1} MiB in {:.2} s",
        mib(initial.last_snapshot_bytes),
        secs(initial.last_snapshot_build_micros)
    );

    // The learner catches up by snapshot; its first install builds the index.
    let learner = RaftStore::open_with(node_config(&dir, 2), Arc::new(network.clone())).await?;
    network.register(&learner);
    let index = Arc::new(BenchIndex::new(RRSETS));
    learner.register_index(index.clone())?;
    let started = Instant::now();
    leader.add_learner(NodeId(2), "in-process-2", true).await?;
    wait_for_revision(&learner, leader.status().revision).await?;
    let catch_up_secs = started.elapsed().as_secs_f64();
    let caught_up = learner.engine_stats();
    ensure!(
        caught_up.snapshots_installed == 1,
        "the learner caught up by log, not by snapshot"
    );
    ensure!(
        index.len() as u64 == records,
        "the learner's index holds {} of {records} records",
        index.len()
    );
    println!(
        "  learner caught up in {catch_up_secs:.1} s (install {:.2} s, index rebuild {:.2} s)",
        secs(caught_up.last_install_micros),
        secs(caught_up.last_index_rebuild_micros)
    );
    let rss_after_catch_up_mib = mib(current_rss());

    // From here the learner only receives snapshots that the benchmark pushes.
    network.set_isolated(2, true);

    let mut rng = Rng::new(0x5EED_0001);
    let mut ids: Vec<u64> = (0..records).collect();
    let update_count = usize::try_from(records * args.update_percent / 100)?;
    let mut rounds = Vec::new();
    for round in 1..=args.rounds {
        let outcome = run_round(
            args,
            records,
            round,
            update_count,
            &mut ids,
            &mut rng,
            (&leader, &learner),
            &index,
        )
        .await?;
        println!(
            "  round {round}: baseline p99 {} ns, install p99 {} ns (x{:.2}), empty reads {}, \
             install window {:.1} s",
            outcome.baseline.latency.p99_ns,
            outcome.install.latency.p99_ns,
            outcome.p99_ratio,
            outcome.baseline.empty_reads + outcome.install.empty_reads,
            outcome.window_secs
        );
        rounds.push(outcome);
    }

    // Replication continues by log after the installs.
    network.set_isolated(2, false);
    let last = leader.propose(data::put_batch(&[0], 99)).await?;
    let replication_by_log_after_installs =
        wait_for_revision(&learner, last.revision).await.is_ok();

    let summary = summarize_rounds(&rounds);
    learner.shutdown().await?;
    leader.shutdown().await?;
    drop((learner, leader));
    Ok(SizeRun {
        records,
        load_secs,
        initial_snapshot_bytes: initial.last_snapshot_bytes,
        initial_snapshot_build_secs: secs(initial.last_snapshot_build_micros),
        catch_up_secs,
        catch_up_install_secs: secs(caught_up.last_install_micros),
        catch_up_index_rebuild_secs: secs(caught_up.last_index_rebuild_micros),
        rss_after_catch_up_mib,
        rounds,
        replication_by_log_after_installs,
        summary,
    })
}

#[allow(clippy::too_many_arguments, reason = "one scenario step")]
async fn run_round(
    args: &Args,
    records: u64,
    round: usize,
    update_count: usize,
    ids: &mut [u64],
    rng: &mut Rng,
    (leader, learner): (&RaftStore, &RaftStore),
    index: &Arc<BenchIndex>,
) -> Result<Round> {
    let seed = 0xA11C_E000 + round as u64;
    // Baseline: the same readers, no install.
    let mut pool = ReaderPool::start(index, args.readers, args.lookups_per_s, records, seed);
    tokio::time::sleep(Duration::from_secs(1)).await;
    pool.record();
    tokio::time::sleep(Duration::from_secs(args.baseline_secs)).await;
    let baseline = pool.finish();

    // Update a random share of the records on the leader and snapshot.
    let generation = u32::try_from(round)?;
    let updated: Vec<u64> = rng.sample(ids, update_count).to_vec();
    let started = Instant::now();
    let batches = updated
        .chunks(BULK_BATCH)
        .map(|chunk| data::put_batch(chunk, generation));
    propose_all(leader, batches, 4).await?;
    let update_secs = started.elapsed().as_secs_f64();
    leader.snapshot_now().await?;
    let snapshot_stats = leader.engine_stats();
    let target = leader.status().revision;

    // The install window: from the first byte streamed to the learner having applied the
    // snapshot (transfer, durable table replacement, index build aside, swap).
    let installs_before = learner.engine_stats().snapshots_installed;
    let rss_before_mib = mib(current_rss());
    let sampler = RssSampler::start();
    let mut pool = ReaderPool::start(
        index,
        args.readers,
        args.lookups_per_s,
        records,
        seed ^ 0xFF,
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    pool.record();
    let window_started = Instant::now();
    let pushed = push_snapshot(leader, learner).await;
    let reached = wait_for_revision(learner, target).await;
    let window_secs = window_started.elapsed().as_secs_f64();
    let install = pool.finish();
    let rss_peak_install_mib = mib(sampler.finish());
    let (transfer_secs, install_call_secs) = pushed?;
    reached?;

    let stats = learner.engine_stats();
    let updated_visible_after = updated.iter().all(|&id| {
        index
            .get(&data::key_array(id))
            .and_then(|value| data::generation_of(&value))
            == Some(generation)
    });
    let p99_ratio = if baseline.latency.p99_ns > 0 {
        count_f64(install.latency.p99_ns) / count_f64(baseline.latency.p99_ns)
    } else {
        0.0
    };
    Ok(Round {
        number: round,
        updated_records: updated.len() as u64,
        update_secs,
        snapshot_bytes: snapshot_stats.last_snapshot_bytes,
        snapshot_build_secs: secs(snapshot_stats.last_snapshot_build_micros),
        baseline,
        install,
        p99_ratio,
        transfer_secs,
        install_call_secs,
        window_secs,
        learner_install_secs: secs(stats.last_install_micros),
        index_rebuild_secs: secs(stats.last_index_rebuild_micros),
        compact_secs: secs(stats.last_compact_micros),
        installs_during_window: stats.snapshots_installed - installs_before,
        rss_before_mib,
        rss_peak_install_mib,
        index_records_after: index.len() as u64,
        updated_visible_after,
        index_revision_matches: index.revision() == target,
    })
}

fn summarize_rounds(rounds: &[Round]) -> Summary {
    let list = |f: &dyn Fn(&Round) -> f64| rounds.iter().map(f).collect::<Vec<_>>();
    let empty_reads = rounds
        .iter()
        .map(|r| r.baseline.empty_reads + r.install.empty_reads)
        .sum();
    let mismatches = rounds
        .iter()
        .map(|r| r.baseline.mismatches + r.install.mismatches)
        .sum();
    let median_p99_ratio = median(&list(&|r| r.p99_ratio));
    let consistent = rounds.iter().all(|r| {
        r.installs_during_window == 1
            && r.updated_visible_after
            && r.index_revision_matches
            && r.index_records_after > 0
    });
    Summary {
        empty_reads,
        mismatches,
        median_baseline_p99_ns: median(&list(&|r| count_f64(r.baseline.latency.p99_ns))),
        median_install_p99_ns: median(&list(&|r| count_f64(r.install.latency.p99_ns))),
        median_p99_ratio,
        worst_p99_ratio: rounds.iter().map(|r| r.p99_ratio).fold(0.0, f64::max),
        worst_install_p99_ns: rounds
            .iter()
            .map(|r| r.install.latency.p99_ns)
            .max()
            .unwrap_or(0),
        worst_install_max_ns: rounds
            .iter()
            .map(|r| r.install.latency.max_ns)
            .max()
            .unwrap_or(0),
        median_install_secs: median(&list(&|r| r.window_secs)),
        median_index_rebuild_secs: median(&list(&|r| r.index_rebuild_secs)),
        pass: empty_reads == 0 && mismatches == 0 && consistent && median_p99_ratio < 2.0,
    }
}

fn print_run(run: &SizeRun) {
    let s = &run.summary;
    println!(
        "M1 {} records: empty reads {}, median p99 {:.0} ns -> {:.0} ns (x{:.2}, worst x{:.2}), \
         median install window {:.1} s: {}",
        run.records,
        s.empty_reads,
        s.median_baseline_p99_ns,
        s.median_install_p99_ns,
        s.median_p99_ratio,
        s.worst_p99_ratio,
        s.median_install_secs,
        if s.pass { "PASS" } else { "FAIL" }
    );
}
