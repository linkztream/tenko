//! Benchmark phases: bulk load, learner catch-up, steady-state lookups under writes, change
//! feed enumeration, offline compaction.

use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use sysinfo::Pid;
use sysinfo::ProcessRefreshKind;
use sysinfo::ProcessesToUpdate;
use sysinfo::System;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::cluster::Cluster;
use crate::cluster::basic_node;
use crate::datagen;
use crate::datagen::GenConfig;
use crate::index::ServingIndex;
use crate::measure::LatencyRecorder;
use crate::measure::PacedStats;
use crate::measure::RssSampler;
use crate::measure::file_size_bytes;
use crate::measure::fmt_bytes;
use crate::measure::fmt_count;
use crate::measure::run_paced;
use crate::raft_types::NodeId;
use crate::raft_types::RecordBatch;
use crate::raft_types::Request;
use crate::results::BulkLoadResult;
use crate::results::CatchUpResult;
use crate::results::ChangeFeedResult;
use crate::results::CompactionResult;
use crate::results::LatencyRun;
use crate::results::NodeDiskUsage;
use crate::results::SteadyStateResult;

const LONG: Duration = Duration::from_secs(60 * 60);

/// Bytes this process has passed to write calls so far (Windows: GetProcessIoCounters).
pub fn process_written_bytes() -> u64 {
    let pid = Pid::from_u32(std::process::id());
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_disk_usage(),
    );
    sys.process(pid)
        .map_or(0, |p| p.disk_usage().total_written_bytes)
}

#[derive(Clone, Copy, Debug)]
pub struct LoadParams {
    pub batch: usize,
    pub inflight: usize,
    pub producers: usize,
}

/// Propose every generated record through the leader in batches of `batch` records, with up
/// to `inflight` client_write calls outstanding, then wait until every node has applied the
/// last entry. Returns (raft entries proposed, raw key+value bytes).
pub async fn load_records(
    cluster: &Cluster,
    cfg: GenConfig,
    p: LoadParams,
) -> anyhow::Result<(u64, u64)> {
    let total = cfg.total_records();
    let batches = total.div_ceil(p.batch as u64);
    let raw = Arc::new(AtomicU64::new(0));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<RecordBatch>(p.inflight * 2);

    // Producer threads generate and pack batches off the async runtime.
    let mut producers = Vec::new();
    for t in 0..p.producers.max(1) {
        let tx = tx.clone();
        let raw = raw.clone();
        let nprod = p.producers.max(1) as u64;
        let batch = p.batch;
        producers.push(std::thread::spawn(move || {
            let mut b = t as u64;
            while b < batches {
                let pairs = datagen::encoded_batch(&cfg, b * batch as u64, batch);
                let bytes: usize = pairs.iter().map(|(k, v)| k.len() + v.len() + 6).sum();
                let mut rb = RecordBatch::with_capacity(bytes, false);
                let mut kv = 0u64;
                for (k, v) in &pairs {
                    rb.push(k, v);
                    kv += (k.len() + v.len()) as u64;
                }
                raw.fetch_add(kv, Ordering::Relaxed);
                if tx.blocking_send(rb).is_err() {
                    return;
                }
                b += nprod;
            }
        }));
    }
    drop(tx);

    let leader = cluster.leader()?.raft.clone();
    let sem = Arc::new(Semaphore::new(p.inflight));
    let mut js: JoinSet<anyhow::Result<()>> = JoinSet::new();
    let mut sent = 0u64;
    let progress_every = (batches / 10).max(1);
    let t0 = Instant::now();
    while let Some(rb) = rx.recv().await {
        let permit = sem.clone().acquire_owned().await?;
        let raft = leader.clone();
        js.spawn(async move {
            let r = raft.client_write(Request::Upsert(rb)).await;
            drop(permit);
            r.map(|_| ())
                .map_err(|e| anyhow::anyhow!("client_write: {e}"))
        });
        sent += 1;
        if sent.is_multiple_of(progress_every) {
            eprintln!(
                "  proposed {sent}/{batches} entries ({:.1} s)",
                t0.elapsed().as_secs_f64()
            );
        }
        while let Some(res) = js.try_join_next() {
            res??;
        }
    }
    while let Some(res) = js.join_next().await {
        res??;
    }
    for h in producers {
        h.join()
            .map_err(|_| anyhow::anyhow!("producer thread panicked"))?;
    }
    let last = cluster
        .leader()?
        .metrics()
        .last_log_index
        .context("leader has no log")?;
    cluster.wait_all_applied(last, LONG).await?;
    Ok((sent, raw.load(Ordering::Relaxed)))
}

pub fn node_disk_usage(cluster: &Cluster) -> Vec<NodeDiskUsage> {
    cluster
        .nodes
        .values()
        .map(|n| {
            let (alloc, stored, _meta, frag) = n.sm.redb_stats().unwrap_or((0, 0, 0, 0));
            NodeDiskUsage {
                node_id: n.id,
                log_file_bytes: file_size_bytes(&n.log_file()),
                sm_file_bytes: file_size_bytes(&n.sm_file()),
                sm_allocated_bytes: alloc,
                sm_stored_bytes: stored,
                sm_fragmented_bytes: frag,
            }
        })
        .collect()
}

pub async fn bulk_load_phase(
    cluster: &Cluster,
    cfg: GenConfig,
    p: LoadParams,
    sampler: &RssSampler,
    rss_before: u64,
) -> anyhow::Result<BulkLoadResult> {
    let total = cfg.total_records();
    eprintln!(
        "bulk load: {} forward-zone records + {} PTR = {} RRsets, {} voters, batch {}",
        fmt_count(cfg.forward_records),
        fmt_count(cfg.ptr_records()),
        fmt_count(total),
        cluster.nodes.len(),
        p.batch
    );
    sampler.reset_peak();
    let w0 = process_written_bytes();
    let t0 = Instant::now();
    let (entries, raw) = load_records(cluster, cfg, p).await?;
    let wall = t0.elapsed().as_secs_f64();
    let written = process_written_bytes().saturating_sub(w0);
    let peak = sampler.peak_bytes();
    let rss_after = sampler.current_bytes();
    let follower = cluster.follower()?;
    let index_entries = follower.index.len();
    let index_est = follower.index.estimated_heap_bytes();
    let r = BulkLoadResult {
        disk: String::new(),
        forward_zone_records: cfg.forward_records,
        total_records: total,
        voters: cluster.nodes.len() as u32,
        batch_records: p.batch as u64,
        raft_entries: entries,
        wall_secs: wall,
        records_per_sec: total as f64 / wall,
        peak_rss_bytes: peak,
        rss_after_bytes: rss_after,
        rss_before_bytes: rss_before,
        raw_kv_bytes: raw,
        avg_entry_bytes: raw as f64 / total as f64,
        per_node: node_disk_usage(cluster),
        index_entries,
        index_estimated_bytes: index_est,
        process_written_bytes: written,
        compaction: None,
    };
    eprintln!(
        "bulk load done: {:.1} s, {:.0} records/s, peak RSS {}, written {}",
        wall,
        r.records_per_sec,
        fmt_bytes(peak),
        fmt_bytes(written)
    );
    if index_entries != total {
        anyhow::bail!(
            "index of node {} has {} entries, expected {}",
            follower.id,
            index_entries,
            total
        );
    }
    Ok(r)
}

/// Build a snapshot on the leader, purge the log it covers, add a learner and wait until it
/// has applied everything the leader has.
pub async fn catch_up_phase(
    cluster: &mut Cluster,
    learner_id: NodeId,
    total_records: u64,
    sampler: &RssSampler,
) -> anyhow::Result<CatchUpResult> {
    sampler.reset_peak();
    let leader_id = cluster.leader_id()?;
    let (leader_raft, leader_stats) = {
        let l = &cluster.nodes[&leader_id];
        (l.raft.clone(), l.stats.clone())
    };
    let last = leader_raft
        .metrics()
        .borrow()
        .last_log_index
        .context("leader has no log")?;
    eprintln!("catch-up: building snapshot on leader {leader_id} at index {last}");
    let built_before = leader_stats.snapshots_built.load(Ordering::Relaxed);
    leader_raft.trigger().snapshot().await?;
    leader_raft
        .wait(Some(LONG))
        .metrics(
            |m| m.snapshot.map(|s| s.index) >= Some(last),
            "snapshot built",
        )
        .await?;
    anyhow::ensure!(
        leader_stats.snapshots_built.load(Ordering::Relaxed) > built_before,
        "snapshot was not built"
    );
    let build_secs = leader_stats.snapshot_build_ns.load(Ordering::Relaxed) as f64 / 1e9;
    let snapshot_bytes = leader_stats.snapshot_bytes.load(Ordering::Relaxed);
    eprintln!(
        "  snapshot: {} in {:.2} s",
        fmt_bytes(snapshot_bytes),
        build_secs
    );
    leader_raft.trigger().purge_log(last).await?;
    leader_raft
        .wait(Some(Duration::from_secs(600)))
        .metrics(|m| m.purged.map(|p| p.index) >= Some(last), "log purged")
        .await?;
    eprintln!("  leader log purged up to {last}; adding learner {learner_id}");

    cluster.add_node(learner_id).await?;
    let t0 = Instant::now();
    leader_raft
        .add_learner(learner_id, basic_node(learner_id), false)
        .await?;
    let target = leader_raft.metrics().borrow().last_log_index;
    let learner = &cluster.nodes[&learner_id];
    learner
        .raft
        .wait(Some(LONG))
        .applied_index_at_least(target, "learner caught up")
        .await?;
    let total = t0.elapsed().as_secs_f64();
    let ls = &learner.stats;
    anyhow::ensure!(
        ls.snapshots_installed.load(Ordering::Relaxed) >= 1,
        "learner did not install a snapshot"
    );
    anyhow::ensure!(
        learner.index.len() == total_records,
        "learner index has {} entries",
        learner.index.len()
    );
    let r = CatchUpResult {
        disk: String::new(),
        total_records,
        snapshot_build_secs: build_secs,
        snapshot_bytes,
        snapshot_transfer_secs: ls.snapshot_transfer_ns.load(Ordering::Relaxed) as f64 / 1e9,
        snapshot_install_secs: ls.snapshot_install_ns.load(Ordering::Relaxed) as f64 / 1e9,
        index_rebuild_secs: ls.index_rebuild_ns.load(Ordering::Relaxed) as f64 / 1e9,
        total_catch_up_secs: total,
        theoretical_1gbit_secs: snapshot_bytes as f64 / 125_000_000.0,
        learner_sm_file_bytes: file_size_bytes(&learner.sm_file()),
        peak_rss_bytes: sampler.peak_bytes(),
    };
    eprintln!(
        "  learner caught up in {:.2} s (transfer {:.2} s, install {:.2} s of which index {:.2} s)",
        r.total_catch_up_secs,
        r.snapshot_transfer_secs,
        r.snapshot_install_secs,
        r.index_rebuild_secs
    );
    Ok(r)
}

/// Pool of random existing keys for lookups (power-of-two length).
fn key_pool(cfg: &GenConfig, size: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut rng = SmallRng::seed_from_u64(seed);
    let total = cfg.total_records();
    (0..size)
        .map(|_| datagen::key_at(cfg, rng.random_range(0..total)))
        .collect()
}

fn spawn_lookups(
    index: Arc<ServingIndex>,
    pool: Arc<Vec<Vec<u8>>>,
    rate: u64,
    dur: Duration,
) -> std::thread::JoinHandle<(PacedStats, u64)> {
    std::thread::Builder::new()
        .name("lookups".into())
        .spawn(move || {
            let stop = AtomicBool::new(false);
            let mask = pool.len() - 1;
            let mut hits = 0u64;
            let st = run_paced(rate, dur, &stop, |i| {
                if let Some(v) = index.get(&pool[(i as usize) & mask]) {
                    hits += 1;
                    std::hint::black_box(v);
                }
            });
            (st, hits)
        })
        .expect("spawn lookup thread")
}

#[derive(Clone, Copy, Debug)]
pub struct SteadyParams {
    /// Baseline + under-writes pairs to run.
    pub rounds: u32,
    pub seconds: u64,
    pub write_rate: u64,
    pub lookup_rate: u64,
    pub seed: u64,
    /// Maximum single-record updates coalesced into one Raft entry.
    pub max_coalesce: usize,
    /// Coalesced proposals outstanding at once.
    pub proposals_inflight: usize,
}

/// Extra facts gathered by the steady-state phase (reported as notes).
#[derive(Debug, Default)]
pub struct SteadyExtras {
    pub raft_entries: u64,
    pub updates: u64,
    pub per_entry_rate: f64,
    pub per_entry_latency: crate::results::LatencySummary,
    pub per_entry_errors: u64,
}

struct Update {
    key: Vec<u8>,
    value: Vec<u8>,
    t0: Instant,
}

pub async fn steady_phase(
    cluster: &Cluster,
    cfg: GenConfig,
    p: &SteadyParams,
) -> anyhow::Result<(Vec<SteadyStateResult>, SteadyExtras)> {
    let follower = cluster.follower()?;
    let leader = cluster.leader()?;
    eprintln!(
        "steady state: lookups on follower {}, writes through leader {}",
        follower.id, leader.id
    );
    let pool = Arc::new(key_pool(&cfg, 1 << 20, p.seed ^ 0x5eed));
    let mut rounds = Vec::new();
    let mut extras = SteadyExtras::default();
    for round in 1..=p.rounds.max(1) {
        let (r, entries, updates) = steady_round(cluster, cfg, p, pool.clone(), round).await?;
        rounds.push(r);
        extras.raft_entries += entries;
        extras.updates += updates;
    }
    Ok((rounds, extras))
}

async fn steady_round(
    cluster: &Cluster,
    cfg: GenConfig,
    p: &SteadyParams,
    pool: Arc<Vec<Vec<u8>>>,
    round: u32,
) -> anyhow::Result<(SteadyStateResult, u64, u64)> {
    let follower = cluster.follower()?;
    let leader = cluster.leader()?;
    let mut p = SteadyParams { ..*p };
    p.seed ^= round as u64 * 0x9e37;
    let p = &p;
    let dur = Duration::from_secs(p.seconds);

    // Baseline: lookups only.
    eprintln!(
        "  round {round} baseline: {} lookups/s for {} s",
        p.lookup_rate, p.seconds
    );
    let cpu_base = CpuWindow::start();
    let (base, base_hits) = spawn_lookups(follower.index.clone(), pool.clone(), p.lookup_rate, dur)
        .join()
        .map_err(|_| anyhow::anyhow!("lookup thread panicked"))?;
    anyhow::ensure!(
        base_hits == base.calls,
        "baseline lookups missed: {} of {}",
        base.calls - base_hits,
        base.calls
    );
    let base_other_cpu = cpu_base.other_busy();

    // Under writes: paced single-record updates. openraft 0.9 waits for every log append to be
    // flushed before it handles the next client request, so one Raft entry per update would
    // cap the leader at one update per fsync. Updates are therefore queued to a coalescer that
    // packs whatever has arrived (up to max_coalesce) into one entry while earlier entries are
    // in flight. Every update is still an individual single-record change with its own
    // journal record; its latency is measured from enqueue to "applied on the leader".
    eprintln!(
        "  round {round} under writes: {} updates/s + {} lookups/s for {} s",
        p.write_rate, p.lookup_rate, p.seconds
    );
    let raft = leader.raft.clone();
    let wlat = Arc::new(Mutex::new(LatencyRecorder::new()));
    let done = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let (utx, mut urx) = tokio::sync::mpsc::unbounded_channel::<Update>();
    let coalescer = {
        let (wlat, done, errors) = (wlat.clone(), done.clone(), errors.clone());
        let (max_coalesce, inflight) = (p.max_coalesce.max(1), p.proposals_inflight.max(1));
        tokio::spawn(async move {
            let sem = Arc::new(Semaphore::new(inflight));
            let mut js = JoinSet::new();
            let (mut entries, mut updates) = (0u64, 0u64);
            while let Some(first) = urx.recv().await {
                let permit = sem.clone().acquire_owned().await.expect("semaphore closed");
                let mut batch = vec![first];
                while batch.len() < max_coalesce {
                    match urx.try_recv() {
                        Ok(u) => batch.push(u),
                        Err(_) => break,
                    }
                }
                let bytes: usize = batch.iter().map(|u| u.key.len() + u.value.len() + 6).sum();
                let mut rb = RecordBatch::with_capacity(bytes, true);
                for u in &batch {
                    rb.push(&u.key, &u.value);
                }
                let starts: Vec<Instant> = batch.iter().map(|u| u.t0).collect();
                entries += 1;
                updates += starts.len() as u64;
                let (raft, wlat, done, errors) =
                    (raft.clone(), wlat.clone(), done.clone(), errors.clone());
                js.spawn(async move {
                    let res = raft.client_write(Request::Upsert(rb)).await;
                    drop(permit);
                    let now = Instant::now();
                    match res {
                        Ok(_) => {
                            let mut l = wlat.lock().expect("latency lock");
                            for t in &starts {
                                l.record(now - *t);
                            }
                            done.fetch_add(starts.len() as u64, Ordering::Relaxed);
                        }
                        Err(_) => {
                            errors.fetch_add(starts.len() as u64, Ordering::Relaxed);
                        }
                    }
                });
                while js.try_join_next().is_some() {}
            }
            while js.join_next().await.is_some() {}
            (entries, updates)
        })
    };
    let writer = {
        let seed = p.seed;
        let rate = p.write_rate;
        std::thread::Builder::new()
            .name("writer".into())
            .spawn(move || {
                let stop = AtomicBool::new(false);
                let mut rng = SmallRng::seed_from_u64(seed ^ 0x77);
                let total = cfg.total_records();
                run_paced(rate, dur, &stop, |i| {
                    let rec = datagen::updated_record(&cfg, rng.random_range(0..total), i + 1);
                    let (key, value) = rec.encoded();
                    let _ = utx.send(Update {
                        key,
                        value,
                        t0: Instant::now(),
                    });
                })
                // utx is dropped here, which ends the coalescer once the queue is drained.
            })
            .expect("spawn writer thread")
    };
    let cpu_loaded = CpuWindow::start();
    let lookups = spawn_lookups(follower.index.clone(), pool.clone(), p.lookup_rate, dur);
    let (loaded, loaded_hits) = lookups
        .join()
        .map_err(|_| anyhow::anyhow!("lookup thread panicked"))?;
    let loaded_other_cpu = cpu_loaded.other_busy();
    let wstats = writer
        .join()
        .map_err(|_| anyhow::anyhow!("writer thread panicked"))?;
    let completed_in_window = done.load(Ordering::Relaxed);
    let (raft_entries, updates) = tokio::time::timeout(Duration::from_secs(300), coalescer)
        .await
        .context("coalescer did not drain")??;
    anyhow::ensure!(
        loaded_hits == loaded.calls,
        "lookups under writes missed keys"
    );
    let last = leader
        .metrics()
        .last_log_index
        .context("leader has no log")?;
    cluster.wait_all_applied(last, LONG).await?;

    let write_latency = wlat.lock().expect("latency lock").summary();
    let r = SteadyStateResult {
        disk: String::new(),
        total_records: cfg.total_records(),
        baseline: LatencyRun {
            label: format!("round {round}: baseline (no writes)"),
            lookup_target_rate: p.lookup_rate,
            lookup_achieved_rate: base.achieved_rate,
            duration_secs: base.elapsed.as_secs_f64(),
            lookup_latency: base.latency.clone(),
            write_target_rate: 0,
            write_achieved_rate: 0.0,
            write_latency: None,
            write_errors: 0,
            other_cpu_busy: Some(base_other_cpu),
        },
        under_writes: LatencyRun {
            label: format!("round {round}: under write load"),
            lookup_target_rate: p.lookup_rate,
            lookup_achieved_rate: loaded.achieved_rate,
            duration_secs: loaded.elapsed.as_secs_f64(),
            lookup_latency: loaded.latency.clone(),
            write_target_rate: p.write_rate,
            write_achieved_rate: completed_in_window as f64 / wstats.elapsed.as_secs_f64(),
            write_latency: Some(write_latency.clone()),
            write_errors: errors.load(Ordering::Relaxed),
            other_cpu_busy: Some(loaded_other_cpu),
        },
    };
    eprintln!(
        "  lookup p99 baseline {} ns, under writes {} ns; updates issued {}, completed {} ({} in window), errors {}, {} Raft entries ({:.1} updates/entry), write p50 {} ns p99 {} ns",
        base.latency.p99_ns,
        loaded.latency.p99_ns,
        wstats.calls,
        done.load(Ordering::Relaxed),
        completed_in_window,
        errors.load(Ordering::Relaxed),
        raft_entries,
        updates as f64 / raft_entries.max(1) as f64,
        write_latency.p50_ns,
        write_latency.p99_ns
    );
    eprintln!(
        "  pacing: lookup max lag baseline {:?} (late {}), loaded {:?} (late {}); writer max lag {:?}; other processes busy CPUs baseline {:.1}, loaded {:.1}",
        base.max_lag,
        base.late_calls,
        loaded.max_lag,
        loaded.late_calls,
        wstats.max_lag,
        base_other_cpu,
        loaded_other_cpu
    );
    Ok((r, raft_entries, updates))
}

/// Closed-loop write ceiling with one single-record Raft entry per client_write and
/// `concurrency` writers, for `secs` seconds.
pub async fn per_entry_ceiling(
    cluster: &Cluster,
    cfg: GenConfig,
    secs: u64,
    concurrency: usize,
    extras: &mut SteadyExtras,
) -> anyhow::Result<()> {
    let leader = cluster.leader()?;
    let deadline = Instant::now() + Duration::from_secs(secs);
    let total = cfg.total_records();
    let mut js = JoinSet::new();
    let t0 = Instant::now();
    for w in 0..concurrency {
        let raft = leader.raft.clone();
        js.spawn(async move {
            let mut rng = SmallRng::seed_from_u64(0xce11 + w as u64);
            let mut lat = LatencyRecorder::new();
            let (mut ok, mut err) = (0u64, 0u64);
            let mut seq = 1_000_000_000u64 * (w as u64 + 1);
            while Instant::now() < deadline {
                seq += 1;
                let rec = datagen::updated_record(&cfg, rng.random_range(0..total), seq);
                let (k, v) = rec.encoded();
                let mut rb = RecordBatch::with_capacity(k.len() + v.len() + 6, true);
                rb.push(&k, &v);
                let t = Instant::now();
                match raft.client_write(Request::Upsert(rb)).await {
                    Ok(_) => {
                        lat.record(t.elapsed());
                        ok += 1;
                    }
                    Err(_) => err += 1,
                }
            }
            (lat, ok, err)
        });
    }
    let mut lat = LatencyRecorder::new();
    let (mut ok, mut err) = (0u64, 0u64);
    while let Some(r) = js.join_next().await {
        let (l, o, e) = r?;
        lat.merge(&l);
        ok += o;
        err += e;
    }
    let elapsed = t0.elapsed().as_secs_f64();
    extras.per_entry_rate = ok as f64 / elapsed;
    extras.per_entry_latency = lat.summary();
    extras.per_entry_errors = err;
    eprintln!(
        "  per-entry ceiling: {:.0} single-record entries/s with {} concurrent writers (p50 {} ns, p99 {} ns, errors {})",
        extras.per_entry_rate,
        concurrency,
        extras.per_entry_latency.p50_ns,
        extras.per_entry_latency.p99_ns,
        err
    );
    Ok(())
}

/// Latency of small redb commits with `Durability::Immediate` in `dir` (the fsync cost that
/// bounds Raft log appends on this disk).
pub fn commit_latency_probe(
    dir: &Path,
    commits: usize,
) -> anyhow::Result<crate::results::LatencySummary> {
    const T: redb::TableDefinition<u64, &[u8]> = redb::TableDefinition::new("probe");
    std::fs::create_dir_all(dir)?;
    let path = dir.join("commit-probe.redb");
    let _ = std::fs::remove_file(&path);
    let mut lat = LatencyRecorder::new();
    {
        let db = redb::Database::builder()
            .set_cache_size(16 << 20)
            .create(&path)?;
        let payload = vec![7u8; 200];
        for i in 0..commits as u64 {
            let t = Instant::now();
            let w = db.begin_write()?;
            {
                let mut tab = w.open_table(T)?;
                tab.insert(i, payload.as_slice())?;
            }
            w.commit()?;
            if i >= 5 {
                lat.record(t.elapsed());
            }
        }
    }
    let _ = std::fs::remove_file(&path);
    Ok(lat.summary())
}

/// Enumerate the last `n` changes from the change journal (follower) and from the Raft log
/// (leader).
pub async fn change_feed_phase(cluster: &Cluster, n: u64) -> anyhow::Result<ChangeFeedResult> {
    let follower = cluster.follower()?;
    let leader = cluster.leader()?;
    let (jc, jb, jsecs) = tokio::task::block_in_place(|| -> anyhow::Result<(u64, u64, f64)> {
        let t = Instant::now();
        let (c, b) = follower.sm.read_journal_tail(n)?;
        Ok((c, b, t.elapsed().as_secs_f64()))
    })?;
    let (log_changes, log_secs) =
        tokio::task::block_in_place(|| -> anyhow::Result<(Option<u64>, Option<f64>)> {
            let (Some(first), Some(last)) = (leader.log.first_index(), leader.log.last_index())
            else {
                return Ok((None, None));
            };
            let t = Instant::now();
            let mut changes = 0u64;
            let mut hi = last;
            // Walk backwards in windows of 256 entries until n record changes are collected
            // (updates are coalesced, so one entry can carry many changes).
            while changes < n && hi >= first {
                let lo = hi.saturating_sub(255).max(first);
                let entries = leader
                    .log
                    .read_range(lo..=hi)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                for e in entries.iter().rev() {
                    if let openraft::EntryPayload::Normal(Request::Upsert(b)) = &e.payload
                        && b.journal
                    {
                        for (k, v) in b.iter() {
                            if changes == n {
                                break;
                            }
                            std::hint::black_box((k, v));
                            changes += 1;
                        }
                    }
                }
                if lo == first || lo == 0 {
                    break;
                }
                hi = lo - 1;
            }
            let secs = t.elapsed().as_secs_f64();
            if changes < n {
                return Ok((Some(changes), Some(secs)));
            }
            Ok((Some(n.min(changes)), Some(secs)))
        })?;
    Ok(ChangeFeedResult {
        disk: String::new(),
        total_records: 0,
        changes_requested: n,
        approach: "change-journal table in the state machine (redb, written in the same transaction as the records)".into(),
        journal_changes_read: jc,
        journal_secs: jsecs,
        journal_bytes: jb,
        log_changes_read: log_changes,
        log_secs,
    })
}

/// Open a closed sm.redb exclusively and run redb's offline compaction on it.
pub fn compact_file(node_id: NodeId, path: &Path) -> anyhow::Result<CompactionResult> {
    let before = file_size_bytes(path);
    let mut last_err = None;
    for _ in 0..100 {
        match redb::Database::builder()
            .set_cache_size(64 << 20)
            .open(path)
        {
            Ok(mut db) => {
                let t = Instant::now();
                db.compact()?;
                let secs = t.elapsed().as_secs_f64();
                drop(db);
                return Ok(CompactionResult {
                    node_id,
                    file_bytes_before: before,
                    file_bytes_after: file_size_bytes(path),
                    compact_secs: secs,
                });
            }
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Err(anyhow::anyhow!(
        "could not open {} for compaction: {:?}",
        path.display(),
        last_err
    ))
}

/// Machine-wide CPU accounting over a measurement window.
pub struct CpuWindow {
    sys: System,
    pid: Pid,
}

impl CpuWindow {
    pub fn start() -> Self {
        let pid = Pid::from_u32(std::process::id());
        let mut sys = System::new();
        sys.refresh_cpu_usage();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu(),
        );
        Self { sys, pid }
    }

    /// Average logical CPUs busy in other processes since `start()`.
    pub fn other_busy(mut self) -> f64 {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu(),
        );
        let n = self.sys.cpus().len() as f64;
        let global = self.sys.global_cpu_usage() as f64 * n / 100.0;
        let own = self
            .sys
            .process(self.pid)
            .map_or(0.0, |p| p.cpu_usage() as f64 / 100.0);
        (global - own).max(0.0)
    }
}
