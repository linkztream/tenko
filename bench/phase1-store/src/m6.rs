//! M6: disk growth after re-seed (ADR 0002; threshold: `sm.redb` below 2x raw after re-seed).
//!
//! A store is loaded with N records and then runs a compressed week: seven rounds, each
//! updating 10 percent of the records, deleting 1 percent and inserting 1 percent new ones,
//! with the default snapshot policy. After every round the raw size (two definitions) and the
//! sizes of `sm.redb`, `log.redb` and the snapshots are recorded. Then a fresh learner is
//! added: the log is purged, so it catches up by snapshot install, which writes `sm.redb` in
//! key order in one transaction. Its `sm.redb` is compared with the raw size.

use std::{collections::HashSet, sync::Arc, time::Instant};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use tenko_core::NodeId;
use tenko_store::{
    KeyRange, ReadConsistency, Store as _,
    raft::{RaftStore, RaftStoreConfig, RaftTimings, network::InProcessNetwork},
};

use crate::{
    Ctx,
    common::{
        DiskSizes, Machine, Rng, RunClock, RunMeta, ScratchDir, bytes_f64, disk_sizes, machine,
        propose_all, purged_index, push_snapshot, secs, wait_for_revision,
    },
    data::{self, BULK_BATCH, RRSETS},
};

#[derive(Debug, Clone, clap::Args)]
pub struct Args {
    /// Records loaded before the churn.
    #[arg(long, default_value_t = 1_000_000)]
    pub records: u64,
    /// Churn rounds (a compressed week).
    #[arg(long, default_value_t = 7)]
    pub rounds: usize,
    /// Share of the records updated per round, in percent.
    #[arg(long, default_value_t = 10)]
    pub update_percent: u64,
    /// Share of the records deleted per round, in percent.
    #[arg(long, default_value_t = 1)]
    pub delete_percent: u64,
    /// Share of new records inserted per round, in percent.
    #[arg(long, default_value_t = 1)]
    pub insert_percent: u64,
    /// Change sets the journal keeps (`RaftStoreConfig::journal_retention`); the store
    /// default when not given.
    #[arg(long)]
    pub journal_retention: Option<usize>,
    /// Name of the result file in `raw/` (without extension).
    #[arg(long, default_value = "m6")]
    pub out_name: String,
}

/// The store's default journal retention (`RaftStoreConfig::new`).
pub fn default_journal_retention() -> usize {
    RaftStoreConfig::new("unused").journal_retention
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point {
    pub label: String,
    pub live_records: u64,
    /// `status().data_bytes`: keys and values of all tables, including journal and audit.
    pub data_bytes: u64,
    /// Keys plus values of the user table, scanned.
    pub user_bytes: u64,
    pub sizes: DiskSizes,
    pub sm_over_data: f64,
    pub sm_over_user: f64,
    pub snapshots_built: u64,
    pub entries_proposed: u64,
    pub purged_index: u64,
    pub elapsed_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools, reason = "a flat result record")]
pub struct Reseed {
    pub installed_by_snapshot: bool,
    pub fallback_push_used: bool,
    pub catch_up_secs: f64,
    pub install_secs: f64,
    pub revisions_equal: bool,
    pub data_bytes_equal: bool,
    pub point: Point,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub records: u64,
    pub rounds: usize,
    pub update_percent: u64,
    pub delete_percent: u64,
    pub insert_percent: u64,
    pub batch_records: usize,
    pub sm_cache_bytes: usize,
    pub log_cache_bytes: usize,
    pub snapshot_policy: String,
    pub durability: String,
    /// Change sets the journal keeps.
    #[serde(default = "default_journal_retention")]
    pub journal_retention: usize,
}

/// redb's own accounting of one closed `sm.redb`, read offline with redb 4.3.0.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RedbStats {
    pub file_bytes: u64,
    pub page_size: u64,
    pub allocated_pages: u64,
    pub allocated_bytes: u64,
    pub leaf_pages: u64,
    pub branch_pages: u64,
    pub tree_height: u32,
    /// Bytes of keys and values stored in leaf pages, without indexing overhead.
    pub stored_bytes: u64,
    pub metadata_bytes: u64,
    /// Free pages plus unused space inside pages.
    pub fragmented_bytes: u64,
    /// The same accounting per table (store tables and the store's own `_meta`).
    #[serde(default)]
    pub tables: Vec<TableBreakdown>,
}

/// redb's accounting of one table of a closed `sm.redb`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TableBreakdown {
    pub name: String,
    pub rows: u64,
    /// Bytes of keys and values in leaf pages (values include the store's 8-byte revision).
    pub stored_bytes: u64,
    pub leaf_pages: u64,
    pub branch_pages: u64,
    pub metadata_bytes: u64,
    /// Unused space inside the table's pages.
    pub fragmented_bytes: u64,
}

/// Per-table accounting of a database file, largest table first.
fn table_breakdown(database: &redb::Database) -> Option<Vec<TableBreakdown>> {
    use redb::{ReadableDatabase as _, ReadableTableMetadata as _, TableHandle as _};
    let read = database.begin_read().ok()?;
    let mut out = Vec::new();
    for handle in read.list_tables().ok()? {
        let name = handle.name().to_owned();
        let table = read.open_untyped_table(handle).ok()?;
        let stats = table.stats().ok()?;
        out.push(TableBreakdown {
            name,
            rows: table.len().ok()?,
            stored_bytes: stats.stored_bytes(),
            leaf_pages: stats.leaf_pages(),
            branch_pages: stats.branch_pages(),
            metadata_bytes: stats.metadata_bytes(),
            fragmented_bytes: stats.fragmented_bytes(),
        });
    }
    out.sort_by_key(|table| std::cmp::Reverse(table.stored_bytes));
    Some(out)
}

/// Opens a closed database file and reads its storage statistics.
fn redb_stats(path: &std::path::Path) -> Option<RedbStats> {
    let file_bytes = std::fs::metadata(path).ok()?.len();
    let database = redb::Database::open(path).ok()?;
    let transaction = database.begin_write().ok()?;
    let stats = transaction.stats().ok()?;
    let page_size = u64::try_from(stats.page_size()).ok()?;
    let result = RedbStats {
        file_bytes,
        page_size,
        allocated_pages: stats.allocated_pages(),
        allocated_bytes: stats.allocated_pages() * page_size,
        leaf_pages: stats.leaf_pages(),
        branch_pages: stats.branch_pages(),
        tree_height: stats.tree_height(),
        stored_bytes: stats.stored_bytes(),
        metadata_bytes: stats.metadata_bytes(),
        fragmented_bytes: stats.fragmented_bytes(),
        tables: Vec::new(),
    };
    let _ = transaction.abort();
    let tables = table_breakdown(&database).unwrap_or_default();
    Some(RedbStats { tables, ..result })
}

/// File sizes after both nodes have been shut down cleanly (redb may shrink a file on close).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AtRest {
    pub leader: DiskSizes,
    pub learner: DiskSizes,
    pub leader_sm_over_data: f64,
    pub leader_sm_over_user: f64,
    pub learner_sm_over_data: f64,
    pub learner_sm_over_user: f64,
    pub leader_redb: Option<RedbStats>,
    pub learner_redb: Option<RedbStats>,
    /// The closed files after an offline `Database::compact()`.
    #[serde(default)]
    pub leader_compacted: Option<Compacted>,
    #[serde(default)]
    pub learner_compacted: Option<Compacted>,
}

/// An offline `redb::Database::compact()` of a closed `sm.redb`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Compacted {
    pub file_bytes_before: u64,
    pub file_bytes_after: u64,
    pub secs: f64,
    /// `compact()` calls until it reported nothing left to do.
    pub passes: u32,
    pub over_data: f64,
    pub over_user: f64,
}

/// Compacts a closed database file in place and measures it.
fn compact_file(path: &std::path::Path, data_bytes: u64, user_bytes: u64) -> Option<Compacted> {
    let file_bytes_before = std::fs::metadata(path).ok()?.len();
    let started = Instant::now();
    let mut passes = 0;
    {
        let mut database = redb::Database::open(path).ok()?;
        while passes < 20 {
            passes += 1;
            if !database.compact().ok()? {
                break;
            }
        }
    }
    let secs = started.elapsed().as_secs_f64();
    let file_bytes_after = std::fs::metadata(path).ok()?.len();
    Some(Compacted {
        file_bytes_before,
        file_bytes_after,
        secs,
        passes,
        over_data: ratio(file_bytes_after, data_bytes),
        over_user: ratio(file_bytes_after, user_bytes),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub meta: RunMeta,
    pub machine: Machine,
    pub config: Config,
    pub points: Vec<Point>,
    pub reseed: Reseed,
    pub ratio_before_reseed_data: f64,
    pub ratio_before_reseed_user: f64,
    pub ratio_after_reseed_data: f64,
    pub ratio_after_reseed_user: f64,
    pub pass: bool,
    pub at_rest: AtRest,
}

fn ratio(sm_bytes: u64, raw: u64) -> f64 {
    if raw == 0 {
        0.0
    } else {
        bytes_f64(sm_bytes) / bytes_f64(raw)
    }
}

/// Sums keys plus values of the user table with a paged scan.
fn user_table_bytes(view: &dyn tenko_store::ReadView) -> Result<(u64, u64)> {
    let (mut bytes, mut rows) = (0_u64, 0_u64);
    let mut range = KeyRange::all();
    loop {
        let page = view.scan(&RRSETS, range.clone(), 20_000, false)?;
        let Some((last, _)) = page.last() else {
            return Ok((bytes, rows));
        };
        range = KeyRange::all().after(last.clone());
        for (key, versioned) in &page {
            bytes += (key.len() + versioned.value.len()) as u64;
        }
        rows += page.len() as u64;
    }
}

async fn point(label: &str, store: &RaftStore, started: Instant) -> Result<Point> {
    let view = store.read(ReadConsistency::Local).await?;
    let (user_bytes, live_records) = user_table_bytes(view.as_ref())?;
    drop(view);
    let data_bytes = store.status().data_bytes;
    let sizes = disk_sizes(&store.config().data_dir);
    Ok(Point {
        label: label.to_owned(),
        live_records,
        data_bytes,
        user_bytes,
        sizes,
        sm_over_data: ratio(sizes.sm_redb, data_bytes),
        sm_over_user: ratio(sizes.sm_redb, user_bytes),
        snapshots_built: store.engine_stats().snapshots_built,
        entries_proposed: store.engine_stats().entries_proposed,
        purged_index: purged_index(store),
        elapsed_secs: started.elapsed().as_secs_f64(),
    })
}

fn print_point(point: &Point) {
    println!(
        "  {:<22} records {:>9}  data {:>7.1} MiB  user {:>7.1} MiB  sm.redb {:>7.1} MiB \
         ({:.2}x data, {:.2}x user)  log.redb {:>6.1} MiB  snapshots {:>6.1} MiB  built {} purged {} entries {}",
        point.label,
        point.live_records,
        bytes_f64(point.data_bytes) / 1_048_576.0,
        bytes_f64(point.user_bytes) / 1_048_576.0,
        bytes_f64(point.sizes.sm_redb) / 1_048_576.0,
        point.sm_over_data,
        point.sm_over_user,
        bytes_f64(point.sizes.log_redb) / 1_048_576.0,
        bytes_f64(point.sizes.snapshots) / 1_048_576.0,
        point.snapshots_built,
        point.purged_index,
        point.entries_proposed,
    );
}

#[allow(clippy::too_many_lines, reason = "one linear scenario")]
pub async fn run(args: Args, ctx: &Ctx) -> Result<()> {
    let clock = RunClock::start(&ctx.data_root);
    let started = Instant::now();
    let dir = ScratchDir::new(&ctx.data_root, "m6")?;
    let network = InProcessNetwork::new();

    let mut leader_config = RaftStoreConfig::new(dir.node(1));
    "in-process-1".clone_into(&mut leader_config.address);
    leader_config.fsync_probe_samples = 0;
    // The default policy keeps the last 1,000 entries behind a snapshot. Bulk entries carry
    // 10,000 records, so a week of this churn is about 200 entries and the default would
    // never purge; keeping 20 makes snapshots and purges happen, which is what a re-seed
    // needs.
    leader_config.snapshot.keep_entries = 20;
    if let Some(retention) = args.journal_retention {
        leader_config.journal_retention = retention;
    }
    let defaults = leader_config.clone();
    let leader = RaftStore::open_with(leader_config, Arc::new(network.clone())).await?;
    network.register(&leader);

    // Load.
    let records = args.records;
    let load_started = Instant::now();
    let batches = (0..records).step_by(BULK_BATCH).map(|first| {
        let last = (first + BULK_BATCH as u64).min(records);
        data::put_batch(&(first..last).collect::<Vec<_>>(), 0)
    });
    propose_all(&leader, batches, 4).await?;
    println!(
        "M6: loaded {records} records in {:.1} s",
        load_started.elapsed().as_secs_f64()
    );
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let mut points = vec![point("after load", &leader, started).await?];
    print_point(&points[0]);

    // The compressed week.
    let mut rng = Rng::new(0x6006_0001);
    let mut live: Vec<u64> = (0..records).collect();
    let mut next_id = records;
    let update_n = usize::try_from(records * args.update_percent / 100)?;
    let delete_n = usize::try_from(records * args.delete_percent / 100)?;
    let insert_n = usize::try_from(records * args.insert_percent / 100)?;
    for round in 1..=args.rounds {
        let generation = u32::try_from(round)?;
        let picked: Vec<u64> = rng.sample(&mut live, update_n + delete_n).to_vec();
        let (updated, deleted) = picked.split_at(update_n.min(picked.len()));
        let inserted: Vec<u64> = (next_id..next_id + insert_n as u64).collect();
        next_id += insert_n as u64;

        let update_batches = updated
            .chunks(BULK_BATCH)
            .map(|chunk| data::put_batch(chunk, generation));
        let churn = (0..insert_n.max(delete_n).div_ceil(BULK_BATCH)).map(|chunk| {
            let slice = |ids: &[u64]| {
                let from = (chunk * BULK_BATCH).min(ids.len());
                let to = ((chunk + 1) * BULK_BATCH).min(ids.len());
                ids[from..to].to_vec()
            };
            data::mixed_batch(&slice(&inserted), generation, &slice(deleted))
        });
        propose_all(&leader, update_batches.chain(churn), 4).await?;

        let gone: HashSet<u64> = deleted.iter().copied().collect();
        live.retain(|id| !gone.contains(id));
        live.extend(&inserted);

        let label = format!("after round {round}");
        let observed = point(&label, &leader, started).await?;
        print_point(&observed);
        points.push(observed);
    }

    // A final snapshot, so that the re-seed carries the latest state.
    leader.snapshot_now().await?;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let before = point("before re-seed", &leader, started).await?;
    print_point(&before);
    points.push(before.clone());

    // Re-seed: a fresh learner catches up by snapshot install.
    let mut learner_config = RaftStoreConfig::new(dir.node(2));
    learner_config.node_id = NodeId(2);
    "in-process-2".clone_into(&mut learner_config.address);
    learner_config.bootstrap = false;
    learner_config.fsync_probe_samples = 0;
    learner_config.journal_retention = defaults.journal_retention;
    learner_config.timings = RaftTimings {
        heartbeat_ms: 50,
        election_min_ms: 1_500,
        election_max_ms: 3_000,
    };
    let learner = RaftStore::open_with(learner_config, Arc::new(network.clone())).await?;
    network.register(&learner);
    let seed_started = Instant::now();
    leader.add_learner(NodeId(2), "in-process-2", true).await?;
    let target = leader.status().revision;
    wait_for_revision(&learner, target).await?;
    let catch_up_secs = seed_started.elapsed().as_secs_f64();
    let mut installed_by_snapshot = learner.engine_stats().snapshots_installed >= 1;
    let mut fallback_push_used = false;
    if !installed_by_snapshot {
        // The learner caught up from the log; push the snapshot explicitly.
        println!("M6: the learner caught up by log; pushing the snapshot explicitly");
        push_snapshot(&leader, &learner).await?;
        wait_for_revision(&learner, target).await?;
        installed_by_snapshot = learner.engine_stats().snapshots_installed >= 1;
        fallback_push_used = true;
    }
    ensure!(
        installed_by_snapshot,
        "the learner was never seeded by snapshot"
    );
    let install_secs = secs(learner.engine_stats().last_install_micros);
    let after = point("after re-seed (learner)", &learner, started).await?;
    print_point(&after);
    let reseed = Reseed {
        installed_by_snapshot,
        fallback_push_used,
        catch_up_secs,
        install_secs,
        revisions_equal: learner.status().revision == leader.status().revision,
        data_bytes_equal: learner.status().data_bytes == leader.status().data_bytes,
        point: after.clone(),
    };

    let mut report = Report {
        meta: clock.finish(),
        machine: machine(),
        config: Config {
            records,
            rounds: args.rounds,
            update_percent: args.update_percent,
            delete_percent: args.delete_percent,
            insert_percent: args.insert_percent,
            batch_records: BULK_BATCH,
            sm_cache_bytes: defaults.sm_cache_bytes,
            log_cache_bytes: defaults.log_cache_bytes,
            snapshot_policy: "default triggers (10,000 entries or 64 MiB of log) but 20 entries \
                              kept behind a snapshot instead of 1,000, plus one \
                              snapshot_now() after the last round"
                .to_owned(),
            durability: "Deferred, 1 s checkpoint interval (the default)".to_owned(),
            journal_retention: defaults.journal_retention,
        },
        ratio_before_reseed_data: before.sm_over_data,
        ratio_before_reseed_user: before.sm_over_user,
        ratio_after_reseed_data: after.sm_over_data,
        ratio_after_reseed_user: after.sm_over_user,
        pass: after.sm_over_data < 2.0
            && after.sm_over_user < 2.0
            && reseed.data_bytes_equal
            && reseed.revisions_equal,
        at_rest: AtRest::default(),
        points,
        reseed,
    };
    println!(
        "M6: sm.redb / raw before re-seed {:.2}x (all tables) {:.2}x (user table); after re-seed \
         {:.2}x and {:.2}x: {}",
        report.ratio_before_reseed_data,
        report.ratio_before_reseed_user,
        report.ratio_after_reseed_data,
        report.ratio_after_reseed_user,
        if report.pass { "PASS" } else { "FAIL" }
    );
    ctx.out.write(&args.out_name, &report)?;

    learner.shutdown().await?;
    leader.shutdown().await?;
    drop((learner, leader));
    // redb closes its files shortly after the shutdown; then the sizes are those at rest.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let (leader_rest, learner_rest) = (disk_sizes(&dir.node(1)), disk_sizes(&dir.node(2)));
    report.at_rest = AtRest {
        leader: leader_rest,
        learner: learner_rest,
        leader_sm_over_data: ratio(leader_rest.sm_redb, before.data_bytes),
        leader_sm_over_user: ratio(leader_rest.sm_redb, before.user_bytes),
        learner_sm_over_data: ratio(learner_rest.sm_redb, after.data_bytes),
        learner_sm_over_user: ratio(learner_rest.sm_redb, after.user_bytes),
        leader_redb: redb_stats(&dir.node(1).join("sm.redb")),
        learner_redb: redb_stats(&dir.node(2).join("sm.redb")),
        leader_compacted: compact_file(
            &dir.node(1).join("sm.redb"),
            before.data_bytes,
            before.user_bytes,
        ),
        learner_compacted: compact_file(
            &dir.node(2).join("sm.redb"),
            after.data_bytes,
            after.user_bytes,
        ),
    };
    for (node, compacted) in [
        ("leader", &report.at_rest.leader_compacted),
        ("learner", &report.at_rest.learner_compacted),
    ] {
        if let Some(c) = compacted {
            println!(
                "M6: {node} sm.redb after compact(): {:.1} -> {:.1} MiB in {:.1} s ({:.2}x data, \
                 {:.2}x user)",
                bytes_f64(c.file_bytes_before) / 1_048_576.0,
                bytes_f64(c.file_bytes_after) / 1_048_576.0,
                c.secs,
                c.over_data,
                c.over_user,
            );
        }
    }
    println!(
        "M6: at rest after a clean shutdown: leader sm.redb {:.1} MiB ({:.2}x data), learner \
         sm.redb {:.1} MiB ({:.2}x data)",
        bytes_f64(leader_rest.sm_redb) / 1_048_576.0,
        report.at_rest.leader_sm_over_data,
        bytes_f64(learner_rest.sm_redb) / 1_048_576.0,
        report.at_rest.learner_sm_over_data,
    );
    ctx.out.write(&args.out_name, &report)
}
