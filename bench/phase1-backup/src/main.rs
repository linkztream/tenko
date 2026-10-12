//! M14: backup, verify and restore of a backup of the M6 data set.
//!
//! Per run: load the records into a fresh single-voter `RaftStore`, add a few vault
//! secrets, then time `create::from_live` (recipient lock and passphrase lock with the
//! hardened Argon2id parameters), `create::from_closed` (offline), `restore::check` (what
//! `tenko backup verify` runs) and `restore::restore` without dry run. Writes
//! `results/raw/<out-name>.json` and prints a summary.
#![forbid(unsafe_code)]

mod data;

use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::Serialize;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tenko::backup::{
    archive::{KdfParams, OriginRecord, PART_SNAPSHOT, Unlock},
    create::{self, Extras, KeyLock, Request, Target},
    keys::BackupKey,
    restore,
};
use tenko_core::{NodeId, RequestCtx, principal::SystemComponent};
use tenko_store::{
    Store, WriteBatch,
    raft::{RaftStore, RaftStoreConfig},
};
use tenko_vault::{
    KekConfig, KekOptions, KekProtection, KekProvider, KekRing, SecretBytes, SecretPurpose,
    SecretSpec, StoreVault, Vault as _, kek::LocalKek,
};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

const PASSPHRASE: &str = "correct horse battery staple";
const NODE: NodeId = NodeId(1);
/// Proposals in flight during the load (as in M6).
const INFLIGHT: usize = 4;

#[derive(Debug, Parser)]
#[command(name = "phase1-backup", version, about)]
struct Cli {
    /// Records to load (the M6 data set has 1,000,000).
    #[arg(long, default_value_t = 1_000_000)]
    records: u64,
    /// Runs; each run loads a fresh store.
    #[arg(long, default_value_t = 3)]
    runs: usize,
    /// Scratch directory (default: a directory under the system temporary directory).
    #[arg(long)]
    scratch: Option<PathBuf>,
    /// Name of the raw output file (`results/raw/<out-name>.json`).
    #[arg(long, default_value = "m14")]
    out_name: String,
    /// Directory that holds `raw/`.
    #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/results"))]
    results_dir: PathBuf,
}

/// One timed step.
#[derive(Debug, Clone, Serialize)]
#[allow(
    clippy::struct_field_names,
    reason = "the unit is part of each JSON field name"
)]
struct Step {
    name: &'static str,
    seconds: f64,
    /// Peak resident set of this process during the step, in bytes.
    peak_rss_bytes: u64,
    /// Peak allocated size of the whole run directory during the step, in bytes.
    peak_scratch_bytes: u64,
    /// Backup file size, where the step wrote or read one.
    file_bytes: Option<u64>,
    /// Plain size of the `store.snapshot` part.
    snapshot_bytes: Option<u64>,
    /// Rows and envelopes the step saw.
    rows: Option<u64>,
    envelopes: Option<u64>,
}

#[derive(Debug, Serialize)]
struct Run {
    index: usize,
    load_average_start: String,
    store_dir_bytes: u64,
    steps: Vec<Step>,
}

#[derive(Debug, Serialize)]
struct Output {
    records: u64,
    raw_bytes: u64,
    runs: Vec<Run>,
    /// Create of an empty store: recipient and passphrase (Argon2id fixed cost).
    empty_store: Vec<Step>,
}

/// Samples the resident set and the allocated size of a directory every 100 ms.
struct Monitor {
    stop: Arc<AtomicBool>,
    rss: Arc<AtomicU64>,
    disk: Arc<AtomicU64>,
    handle: Option<thread::JoinHandle<()>>,
}

fn dir_bytes(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| match entry.metadata() {
            Ok(meta) if meta.is_dir() => dir_bytes(&entry.path()),
            Ok(meta) => meta.blocks() * 512,
            Err(_) => 0,
        })
        .sum()
}

impl Monitor {
    fn start(root: &Path) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let rss = Arc::new(AtomicU64::new(0));
        let disk = Arc::new(AtomicU64::new(0));
        let handle = {
            let (stop, rss, disk) = (Arc::clone(&stop), Arc::clone(&rss), Arc::clone(&disk));
            let root = root.to_path_buf();
            thread::spawn(move || {
                let mut system = System::new();
                let pid = Pid::from_u32(std::process::id());
                loop {
                    system.refresh_processes_specifics(
                        ProcessesToUpdate::Some(&[pid]),
                        true,
                        ProcessRefreshKind::nothing().with_memory(),
                    );
                    if let Some(process) = system.process(pid) {
                        rss.fetch_max(process.memory(), Ordering::Relaxed);
                    }
                    disk.fetch_max(dir_bytes(&root), Ordering::Relaxed);
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            })
        };
        Self {
            stop,
            rss,
            disk,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> (u64, u64) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        (
            self.rss.load(Ordering::Relaxed),
            self.disk.load(Ordering::Relaxed),
        )
    }
}

/// Times `work` with the monitor running; the closure returns what the step saw.
async fn step<F, Fut>(root: &Path, name: &'static str, work: F) -> Result<Step>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Step>>,
{
    let monitor = Monitor::start(root);
    let started = Instant::now();
    let result = work().await;
    let seconds = started.elapsed().as_secs_f64();
    let (rss, disk) = monitor.finish();
    let mut out = result.with_context(|| format!("step {name}"))?;
    out.name = name;
    out.seconds = seconds;
    out.peak_rss_bytes = rss;
    out.peak_scratch_bytes = disk;
    println!(
        "  {name:<28} {seconds:>9.2} s   rss {:>6} MiB   scratch {:>6} MiB",
        rss >> 20,
        disk >> 20
    );
    Ok(out)
}

fn blank(name: &'static str) -> Step {
    Step {
        name,
        seconds: 0.0,
        peak_rss_bytes: 0,
        peak_scratch_bytes: 0,
        file_bytes: None,
        snapshot_bytes: None,
        rows: None,
        envelopes: None,
    }
}

fn ring() -> Result<KekRing> {
    let keks: Vec<Arc<dyn KekProvider>> = [("mem-00000001", 1_u8), ("mem-00000002", 2_u8)]
        .into_iter()
        .map(|(id, byte)| {
            LocalKek::new(id, KekProtection::Memory, &Zeroizing::new([byte; 32]))
                .map(|kek| Arc::new(kek) as Arc<dyn KekProvider>)
        })
        .collect::<Result<_, _>>()?;
    Ok(KekRing::from_generations(keks)?)
}

fn ctx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Backup)
}

fn request(lock: KeyLock, kdf: KdfParams, target: PathBuf) -> Request {
    Request {
        locks: vec![lock],
        kdf,
        origin: OriginRecord {
            reason: "manual".to_owned(),
            by: "system".to_owned(),
        },
        extras: Extras::default(),
        target: Target::File(target),
    }
}

fn store_config(dir: &Path) -> RaftStoreConfig {
    let mut config = RaftStoreConfig::new(dir);
    config.node_id = NODE;
    config.fsync_probe_samples = 0;
    config
}

/// Loads `records` in batches of 10,000, four proposals in flight.
async fn load(store: &RaftStore, records: u64) -> Result<()> {
    let mut set: JoinSet<Result<(), tenko_store::StoreError>> = JoinSet::new();
    for first in (0..records).step_by(usize::try_from(data::BULK_BATCH)?) {
        while set.len() >= INFLIGHT {
            if let Some(done) = set.join_next().await {
                done??;
            }
        }
        let batch = data::put_batch(first, (first + data::BULK_BATCH).min(records));
        let store = store.clone();
        set.spawn(async move { store.propose(batch).await.map(|_| ()) });
    }
    while let Some(done) = set.join_next().await {
        done??;
    }
    Ok(())
}

/// A handful of vault secrets, so that the envelope checks of `verify` have work to do.
async fn add_secrets(store: &RaftStore, ring: &KekRing) -> Result<()> {
    let vault = StoreVault::open(Arc::new(store.clone()) as Arc<dyn Store>, ring.clone()).await?;
    for index in 0..5_u8 {
        vault
            .put_operator(
                &ctx(),
                SecretSpec::new(SecretPurpose::from_static("connect.backup_bench"))
                    .labelled(format!("secret {index}")),
                SecretBytes::new(format!("secret value {index}").into_bytes()),
            )
            .await?;
    }
    // A small ordinary write so the audit chain has a context-bearing entry too.
    let mut batch = WriteBatch::for_request(&ctx());
    batch.put(
        data::RRSETS,
        b"bench-marker".to_vec(),
        b"192.0.2.1 ns1.example.test".to_vec(),
    );
    store.propose(batch).await?;
    Ok(())
}

fn created_step(created: &create::Created) -> Step {
    let mut out = blank("");
    out.file_bytes = Some(created.bytes);
    out.snapshot_bytes = created.manifest.part(PART_SNAPSHOT).map(|part| part.bytes);
    out.rows = Some(created.manifest.digest.entries);
    out
}

fn restore_target(data_dir: &Path) -> Result<restore::Target> {
    // No `systemd-creds` binary: generations are plain files with mode 0600.
    let kek: KekConfig = serde_json::from_value(serde_json::json!({
        "provider": "systemd_creds",
        "dir": data_dir.join("kek"),
        "tool": data_dir.join("no-such-tool"),
    }))?;
    Ok(restore::Target {
        data_dir: data_dir.to_path_buf(),
        store_dir: data_dir.join("store"),
        node: NODE,
        address: String::new(),
        kek,
        kek_options: KekOptions::default(),
    })
}

fn load_average() -> String {
    fs::read_to_string("/proc/loadavg")
        .map(|text| {
            text.split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

fn file_len(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |meta| meta.len())
}

/// Create of a store with no records: the fixed cost of the two locks.
async fn empty_store(root: &Path, ring: &KekRing, key: &BackupKey) -> Result<Vec<Step>> {
    let dir = root.join("empty");
    let store = RaftStore::open(store_config(&dir.join("source"))).await?;
    add_secrets(&store, ring).await?;
    let mut out = Vec::new();
    for (name, lock, kdf) in [
        (
            "empty create (recipient)",
            KeyLock::Recipient(key.recipient()),
            KdfParams::HARDENED,
        ),
        (
            "empty create (passphrase)",
            KeyLock::Passphrase(Zeroizing::new(PASSPHRASE.to_owned())),
            KdfParams::HARDENED,
        ),
    ] {
        let file = dir.join(format!("{}.tkbk", name.replace([' ', '(', ')'], "-")));
        let result = step(root, name, || async {
            let created = create::from_live(&store, ring, request(lock, kdf, file.clone())).await?;
            Ok(created_step(&created))
        })
        .await?;
        out.push(result);
    }
    store.shutdown().await?;
    drop(store);
    fs::remove_dir_all(&dir)?;
    Ok(out)
}

#[allow(clippy::too_many_lines, reason = "one linear sequence of timed steps")]
async fn one_run(index: usize, cli: &Cli, root: &Path, ring: &KekRing) -> Result<Run> {
    println!("run {index}");
    let load_average_start = load_average();
    let source = root.join("source");
    let backups = root.join("backups");
    fs::create_dir_all(&backups)?;
    let key = BackupKey::generate()?;
    let mut steps = Vec::new();

    let store = RaftStore::open(store_config(&source)).await?;
    steps.push(
        step(root, "load", || async {
            load(&store, cli.records).await?;
            add_secrets(&store, ring).await?;
            Ok(blank(""))
        })
        .await?,
    );
    let store_dir_bytes = dir_bytes(&source);
    println!(
        "  store directory after load: {} MiB",
        store_dir_bytes >> 20
    );

    let fast = backups.join("live-recipient.tkbk");
    steps.push(
        step(root, "create live, recipient", || async {
            let created = create::from_live(
                &store,
                ring,
                request(
                    KeyLock::Recipient(key.recipient()),
                    KdfParams::HARDENED,
                    fast.clone(),
                ),
            )
            .await?;
            Ok(created_step(&created))
        })
        .await?,
    );
    let slow = backups.join("live-passphrase.tkbk");
    steps.push(
        step(root, "create live, passphrase", || async {
            let created = create::from_live(
                &store,
                ring,
                request(
                    KeyLock::Passphrase(Zeroizing::new(PASSPHRASE.to_owned())),
                    KdfParams::HARDENED,
                    slow.clone(),
                ),
            )
            .await?;
            Ok(created_step(&created))
        })
        .await?,
    );
    fs::remove_file(&slow)?;

    // The store-copy part of a live create on its own (`RaftStore::copy_state_to`): the rest
    // of `create::from_live` is the same code as the offline path.
    let copy = backups.join("copy-only");
    steps.push(
        step(root, "copy_state_to alone (live)", || async {
            store.copy_state_to(&copy).await?;
            Ok(blank(""))
        })
        .await?,
    );
    fs::remove_dir_all(&copy)?;

    store.shutdown().await?;
    drop(store);
    let closed = backups.join("closed-recipient.tkbk");
    steps.push(
        step(root, "create closed, recipient", || async {
            let created = create::from_closed(
                &source,
                NODE,
                ring,
                request(
                    KeyLock::Recipient(key.recipient()),
                    KdfParams::HARDENED,
                    closed.clone(),
                ),
            )
            .await?;
            Ok(created_step(&created))
        })
        .await?,
    );
    fs::remove_file(&closed)?;
    // The source store is no longer needed; free its disk for the restore.
    fs::remove_dir_all(&source)?;

    steps.push(
        step(root, "verify", || async {
            let report = restore::check(&fast, Unlock::Key(&key), root, NODE).await?;
            if !report.digest_matches {
                bail!("digest mismatch");
            }
            let mut out = blank("");
            out.file_bytes = Some(file_len(&fast));
            out.rows = Some(report.manifest.digest.entries);
            out.envelopes = Some(report.envelopes);
            Ok(out)
        })
        .await?,
    );

    let data_dir = root.join("restored");
    steps.push(
        step(root, "restore", || async {
            let report =
                restore::restore(&fast, Unlock::Key(&key), &restore_target(&data_dir)?, false)
                    .await?;
            if !report.digest_matches || report.dry_run {
                bail!("restore did not install the store");
            }
            let mut out = blank("");
            out.file_bytes = Some(file_len(&fast));
            out.rows = Some(report.manifest.digest.entries);
            out.envelopes = Some(report.envelopes);
            Ok(out)
        })
        .await?,
    );
    println!(
        "  restored store directory: {} MiB",
        dir_bytes(&data_dir.join("store")) >> 20
    );
    fs::remove_dir_all(root)?;
    Ok(Run {
        index,
        load_average_start,
        store_dir_bytes,
        steps,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let scratch = cli
        .scratch
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("phase1-backup"));
    fs::create_dir_all(&scratch)?;
    let ring = ring()?;
    let raw_bytes = cli.records * (data::KEY_LEN + data::VALUE_LEN) as u64;
    println!(
        "M14: {} records ({} MiB raw), {} runs, scratch {}",
        cli.records,
        raw_bytes >> 20,
        cli.runs,
        scratch.display()
    );
    let key = BackupKey::generate()?;
    let empty = empty_store(&scratch.join("empty-run"), &ring, &key).await?;
    let mut runs = Vec::new();
    for index in 1..=cli.runs {
        let root = scratch.join(format!("run-{index}"));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(&root)?;
        runs.push(one_run(index, &cli, &root, &ring).await?);
    }
    let output = Output {
        records: cli.records,
        raw_bytes,
        runs,
        empty_store: empty,
    };
    let raw = cli.results_dir.join("raw");
    fs::create_dir_all(&raw)?;
    let path = raw.join(format!("{}.json", cli.out_name));
    fs::write(&path, serde_json::to_string_pretty(&output)?)?;
    println!("wrote {}", path.display());
    summary(&output);
    Ok(())
}

fn summary(output: &Output) {
    println!(
        "\nsummary (median / max seconds over {} runs)",
        output.runs.len()
    );
    let names: Vec<&str> = output.runs[0].steps.iter().map(|s| s.name).collect();
    for name in names {
        let mut values: Vec<f64> = output
            .runs
            .iter()
            .filter_map(|run| run.steps.iter().find(|s| s.name == name))
            .map(|s| s.seconds)
            .collect();
        values.sort_by(f64::total_cmp);
        let median = values[values.len() / 2];
        let max = values[values.len() - 1];
        println!("  {name:<28} {median:>9.2} / {max:>9.2}");
    }
}
