//! The write cost of a lease commit (WP9.6, ADR 0030): the rows and the bytes one lease
//! change puts into the synchronous batch, the size of the Raft entries that carry them,
//! and the derived rows the asynchronous writer adds. Each figure fails above a cap written
//! here: the value measured when the cap was set plus a margin of 25 %, so a change that
//! costs store work per lease has to raise the cap in the same commit, visibly.
//!
//! Every test prints its figures on one `WRITE COST` line (`--no-capture` shows them).

mod lease_support;

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use lease_support::{NODE, completions, from_now};
use tenko_core::{
    PrefixId, Timestamp, VrfId,
    dhcp::{BindingState, LeaseEventKind, tables},
};
use tenko_dhcp::{
    lease::{CommitSettings, LeaseIndex, PendingChange, SharedLeases, StoreLeases},
    store::{LeaseStore, Ticket},
};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, Leadership, MemStore, MemStoreConfig, ReadConsistency,
    ReadView, Store, StoreError, StoreStatus, WatchFilter, WriteBatch,
    raft::{RaftStore, RaftStoreConfig},
};
use tokio_util::sync::CancellationToken;

// The figures of 2026-10-31 (WP9.7, ADR 0031), on the shape of `grant` below. Before WP9.6 one
// lease commit was 13 rows and 3,714 bytes in its batch, and appended 3,738 bytes of log per
// lease in entries of 415,321 bytes on average (1,000 concurrent commits). After WP9.6 the
// writer added 11 rows and 3,048 bytes per lease change (357 bytes of log); since ADR 0031
// it adds the history row alone: 1 row and 125 bytes (26 bytes of log).

/// Rows (mutations) of the synchronous batch of one lease commit: the lease row and the
/// client index entry. Measured 2; the cap is 2 plus 25 %.
const CAP_SYNC_ROWS: f64 = 1.25 * 2.0;
/// CBOR bytes of the synchronous batch of one lease commit, as the store encodes it into
/// the Raft entry.
const CAP_SYNC_BYTES: f64 = 1.25 * MEASURED_SYNC_BYTES;
const MEASURED_SYNC_BYTES: f64 = 669.0;
/// Rows the asynchronous writer adds per lease change: the history row (ADR 0031; it also
/// wrote the address, name, OS and vendor facts and their index rows before). Measured 1.
const CAP_DERIVED_ROWS: f64 = 1.25 * 1.0;
/// CBOR bytes of those rows per lease change.
const CAP_DERIVED_BYTES: f64 = 1.25 * MEASURED_DERIVED_BYTES;
const MEASURED_DERIVED_BYTES: f64 = 125.0;
/// Bytes appended to the Raft log per lease commit (the entry's share of one lease, the
/// entry compressed on its way to disk).
const CAP_LOG_BYTES_PER_LEASE: f64 = 1.25 * MEASURED_LOG_BYTES_PER_LEASE;
const MEASURED_LOG_BYTES_PER_LEASE: f64 = 61.0;
/// Bytes of log the writer's batches append per lease change.
const CAP_DERIVED_LOG_BYTES_PER_LEASE: f64 = 1.25 * MEASURED_DERIVED_LOG_BYTES_PER_LEASE;
const MEASURED_DERIVED_LOG_BYTES_PER_LEASE: f64 = 26.0;
/// Bytes of a Raft entry of lease commits on average, on disk, under a load of concurrent
/// commits. The store bounds an entry at 64 KiB of batches before compression
/// (`tenko_store::raft::ENTRY_BOUND`).
const CAP_ENTRY_BYTES: f64 = 1.25 * MEASURED_ENTRY_BYTES;
const MEASURED_ENTRY_BYTES: f64 = 5_114.0;
/// CBOR bytes of the synchronous batch of one renewal: the lease row alone.
const CAP_RENEWAL_BYTES: f64 = 1.25 * 555.0;
/// Octets of the key and the value of a history row (ADR 0031: the lean row; it was about
/// 250 with the host name). Measured 85.
const CAP_HISTORY_PAYLOAD_BYTES: f64 = 100.0;

/// Leases a test commits.
const LEASES: u32 = 1_000;

/// What one proposed batch wrote.
#[derive(Debug, Clone, Copy)]
struct Recorded {
    rows: usize,
    bytes: usize,
    /// A lease commit (it writes `dhcp.leases`), else a flush of the derived writer.
    lease: bool,
    /// Puts into the client index `dhcp.leases.by_client`.
    index: usize,
    history: usize,
    /// Octets of the keys and values of the Puts to `dhcp.history`.
    history_payload: usize,
}

/// A store that records what each batch it is handed writes, over a memory store.
struct Recording {
    inner: MemStore,
    batches: Mutex<Vec<Recorded>>,
}

impl Recording {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MemStore::new(MemStoreConfig::default()),
            batches: Mutex::new(Vec::new()),
        })
    }

    fn take(&self) -> Vec<Recorded> {
        std::mem::take(&mut *self.batches.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

#[async_trait::async_trait]
impl Store for Recording {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        let bytes = tenko_core::codec::to_cbor(&batch).map_or(0, |encoded| encoded.len());
        let writes = |name: &tenko_core::TableName| {
            batch
                .mutations
                .iter()
                .filter(|mutation| {
                    matches!(mutation, tenko_store::Mutation::Put { table, .. } if table == name)
                })
                .count()
        };
        let recorded = Recorded {
            rows: batch.mutations.len(),
            bytes,
            lease: writes(tables::LEASES.name()) > 0,
            index: writes(tables::LEASES_BY_CLIENT.name()),
            history: writes(tables::HISTORY.name()),
            history_payload: batch
                .mutations
                .iter()
                .map(|mutation| match mutation {
                    tenko_store::Mutation::Put { table, key, value }
                        if table == tables::HISTORY.name() =>
                    {
                        key.len() + value.len()
                    }
                    _ => 0,
                })
                .sum(),
        };
        self.batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(recorded);
        self.inner.propose(batch).await
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.inner.read(consistency).await
    }

    fn watch(
        &self,
        from: Option<tenko_core::Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        self.inner.watch(from, filter)
    }

    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> StoreStatus {
        self.inner.status()
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<Leadership>> {
        self.inner.leadership()
    }
}

/// The hardware address of client `k`: RFC 7042 documentation MACs, the last two octets
/// counting.
fn mac(k: u32) -> [u8; 6] {
    let [.., high, low] = k.to_be_bytes();
    [0x00, 0x00, 0x5e, 0x00, high, low]
}

/// A grant to client `k` in 198.51.100.0/22 as a busy office network sends it: a client
/// identifier, a host name, a parameter request list and a vendor class.
fn grant(vrf: VrfId, scope: PrefixId, k: u32) -> PendingChange {
    let [.., high, low] = k.to_be_bytes();
    let addr = std::net::Ipv4Addr::new(198, 51, 100 + (high & 3), low);
    let mut client_id = vec![0x01];
    client_id.extend_from_slice(&mac(k));
    let now = Timestamp::now();
    let mut change = PendingChange::new(
        LeaseEventKind::Granted,
        vrf,
        scope,
        addr,
        1,
        &mac(k),
        Some(&client_id),
        BindingState::Active,
        now,
        from_now(3_600),
    );
    change.hostname.set(format!("desktop-{k:05}").as_bytes());
    let mut fingerprint = tenko_dhcp::lease::PendingFingerprint::default();
    fingerprint
        .parameters
        .set(&[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]);
    fingerprint.vendor_class.set(b"MSFT 5.0");
    change.fingerprint = Some(fingerprint);
    change
}

/// Commits `LEASES` grants through a lease store on `store`; returns the lease store (for the
/// derived writer), its stop token, the VRF and the scope once every grant completed.
async fn commit_all(store: Arc<dyn Store>) -> (StoreLeases, CancellationToken, VrfId, PrefixId) {
    let leases = SharedLeases::new(LeaseIndex::new());
    let (lease_store, committer) = StoreLeases::new(
        Arc::clone(&store),
        leases,
        NODE,
        CommitSettings {
            queue: 8_192,
            // The writer flushes only when the test asks, so that the lease commits and the
            // writer's batches are measured apart.
            derived: tenko_dhcp::lease::derived::DerivedSettings {
                interval: Duration::from_secs(3_600),
                max_items: 100_000,
                ..tenko_dhcp::lease::derived::DerivedSettings::default()
            },
            ..CommitSettings::default()
        },
    );
    let stop = CancellationToken::new();
    tokio::spawn(committer.run(stop.clone()));
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    for k in 0..LEASES {
        lease_store
            .submit(&grant(vrf, scope, k), Ticket(u64::from(k)))
            .expect("the queue has room");
    }
    let done = completions(&lease_store, LEASES as usize, Duration::from_secs(60)).await;
    assert_eq!(done.len(), LEASES as usize);
    assert!(
        done.iter().all(|done| done.outcome.is_ok()),
        "every grant commits"
    );
    (lease_store, stop, vrf, scope)
}

#[allow(clippy::cast_precision_loss, reason = "test figures")]
fn mean(values: impl Iterator<Item = usize>) -> f64 {
    let (sum, count) = values.fold((0usize, 0usize), |(sum, count), value| {
        (sum + value, count + 1)
    });
    sum as f64 / count.max(1) as f64
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::cast_precision_loss, reason = "test figures")]
async fn the_synchronous_batch_of_a_lease_commit_stays_within_its_caps() {
    let recording = Recording::new();
    let store: Arc<dyn Store> = recording.clone();
    let (lease_store, stop, _, _) = commit_all(Arc::clone(&store)).await;
    lease_store.derived().flush().await;
    let batches = recording.take();
    let commits: Vec<_> = batches.iter().filter(|batch| batch.lease).collect();
    assert_eq!(commits.len(), LEASES as usize, "one batch per lease commit");
    let rows = mean(commits.iter().map(|batch| batch.rows));
    let bytes = mean(commits.iter().map(|batch| batch.bytes));
    // The writer's flushes: the derived rows of the same leases, in a few batches.
    let flushes: Vec<_> = batches.iter().filter(|batch| !batch.lease).collect();
    let history: usize = flushes.iter().map(|batch| batch.history).sum();
    assert_eq!(
        history, LEASES as usize,
        "every history row written by the writer"
    );
    let derived_rows =
        flushes.iter().map(|batch| batch.rows).sum::<usize>() as f64 / f64::from(LEASES);
    let derived_bytes =
        flushes.iter().map(|batch| batch.bytes).sum::<usize>() as f64 / f64::from(LEASES);
    let history_payload = flushes
        .iter()
        .map(|batch| batch.history_payload)
        .sum::<usize>() as f64
        / f64::from(LEASES);
    eprintln!(
        "WRITE COST sync batch: rows_per_lease={rows:.2} bytes_per_lease={bytes:.0}; \
         derived: flushes={} rows_per_lease={derived_rows:.2} bytes_per_lease={derived_bytes:.0} \
         history_payload_octets={history_payload:.0}",
        flushes.len()
    );
    assert!(
        rows <= CAP_SYNC_ROWS,
        "{rows:.2} rows per lease commit, cap {CAP_SYNC_ROWS}"
    );
    assert!(
        bytes <= CAP_SYNC_BYTES,
        "{bytes:.0} bytes per lease commit, cap {CAP_SYNC_BYTES}"
    );
    assert!(
        derived_rows <= CAP_DERIVED_ROWS,
        "{derived_rows:.2} derived rows per lease, cap {CAP_DERIVED_ROWS}"
    );
    assert!(
        derived_bytes <= CAP_DERIVED_BYTES,
        "{derived_bytes:.0} derived bytes per lease, cap {CAP_DERIVED_BYTES}"
    );
    assert!(
        history_payload < CAP_HISTORY_PAYLOAD_BYTES,
        "{history_payload:.0} octets in the key and value of a history row, cap {CAP_HISTORY_PAYLOAD_BYTES}"
    );
    stop.cancel();
}

/// The renewal of grant `k` a minute later, as the same client sends it.
fn renewal(vrf: VrfId, scope: PrefixId, k: u32) -> PendingChange {
    let mut change = grant(vrf, scope, k);
    change.kind = LeaseEventKind::Renewed;
    change.cltt = change
        .cltt
        .checked_add(Duration::from_secs(60))
        .expect("a time");
    change.ends = from_now(3_660);
    change
}

/// A renewal changes one row of the binding and moves no client index entry; the writer
/// adds its history row (the figures of 2026-10-31, after ADR 0031).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::cast_precision_loss, reason = "test figures")]
async fn a_renewal_writes_one_lease_row_and_one_history_row() {
    let recording = Recording::new();
    let store: Arc<dyn Store> = recording.clone();
    let (lease_store, stop, vrf, scope) = commit_all(Arc::clone(&store)).await;
    lease_store.derived().flush().await;
    recording.take();

    for k in 0..LEASES {
        lease_store
            .submit(&renewal(vrf, scope, k), Ticket(u64::from(LEASES + k)))
            .expect("the queue has room");
    }
    let done = completions(&lease_store, LEASES as usize, Duration::from_secs(60)).await;
    assert_eq!(done.len(), LEASES as usize);
    assert!(
        done.iter().all(|done| done.outcome.is_ok()),
        "every renewal commits"
    );
    lease_store.derived().flush().await;
    let batches = recording.take();
    let commits: Vec<_> = batches.iter().filter(|batch| batch.lease).collect();
    assert_eq!(commits.len(), LEASES as usize, "one batch per renewal");
    assert!(
        commits
            .iter()
            .all(|batch| batch.rows == 1 && batch.index == 0),
        "a renewal writes its lease row and no client index entry"
    );
    let flushes: Vec<_> = batches.iter().filter(|batch| !batch.lease).collect();
    let history: usize = flushes.iter().map(|batch| batch.history).sum();
    let derived_rows: usize = flushes.iter().map(|batch| batch.rows).sum();
    assert_eq!(history, LEASES as usize, "one history row per renewal");
    assert_eq!(
        derived_rows, history,
        "the history row is all the writer adds"
    );
    let bytes = mean(commits.iter().map(|batch| batch.bytes));
    let derived_bytes =
        flushes.iter().map(|batch| batch.bytes).sum::<usize>() as f64 / f64::from(LEASES);
    let history_payload = flushes
        .iter()
        .map(|batch| batch.history_payload)
        .sum::<usize>() as f64
        / f64::from(LEASES);
    eprintln!(
        "WRITE COST renewal: rows_per_renewal=1 bytes_per_renewal={bytes:.0}; derived: \
         rows_per_renewal=1 bytes_per_renewal={derived_bytes:.0} history_payload_octets={history_payload:.0}"
    );
    assert!(
        bytes <= CAP_RENEWAL_BYTES,
        "{bytes:.0} bytes per renewal, cap {CAP_RENEWAL_BYTES}"
    );
    assert!(
        derived_bytes <= CAP_DERIVED_BYTES,
        "{derived_bytes:.0} derived bytes per renewal, cap {CAP_DERIVED_BYTES}"
    );
    assert!(
        history_payload < CAP_HISTORY_PAYLOAD_BYTES,
        "{history_payload:.0} octets in the key and value of a history row, cap {CAP_HISTORY_PAYLOAD_BYTES}"
    );
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::cast_precision_loss, reason = "test figures")]
async fn the_raft_entries_of_lease_commits_stay_within_their_caps() {
    let dir = tempfile::tempdir().expect("a directory");
    let mut config = RaftStoreConfig::new(dir.path());
    config.fsync_probe_samples = 0;
    let raft = RaftStore::open(config).await.expect("the store");
    let before = raft.engine_stats();
    let store: Arc<dyn Store> = Arc::new(raft.clone());
    let (lease_store, stop, _, _) = commit_all(Arc::clone(&store)).await;
    let after = raft.engine_stats();
    lease_store.derived().flush().await;
    let flushed = raft.engine_stats();
    stop.cancel();
    let entries = after.log_entries - before.log_entries;
    let bytes = after.log_appended_bytes - before.log_appended_bytes;
    let batches = after.batches_proposed - before.batches_proposed;
    let per_lease = bytes as f64 / f64::from(LEASES);
    let per_entry = bytes as f64 / entries.max(1) as f64;
    let derived_bytes = flushed.log_appended_bytes - after.log_appended_bytes;
    let derived_entries = flushed.log_entries - after.log_entries;
    eprintln!(
        "WRITE COST raft: lease commits: entries={entries} batches={batches} log_bytes={bytes} \
         log_bytes_per_lease={per_lease:.0} bytes_per_entry={per_entry:.0} log_commits={} \
         checkpoints={}; derived: entries={derived_entries} log_bytes={derived_bytes} \
         log_bytes_per_lease={:.0}",
        after.log_commits - before.log_commits,
        after.checkpoints - before.checkpoints,
        derived_bytes as f64 / f64::from(LEASES),
    );

    assert!(
        per_lease <= CAP_LOG_BYTES_PER_LEASE,
        "{per_lease:.0} log bytes per lease, cap {CAP_LOG_BYTES_PER_LEASE}"
    );
    assert!(
        per_entry <= CAP_ENTRY_BYTES,
        "{per_entry:.0} bytes per entry, cap {CAP_ENTRY_BYTES}"
    );
    let derived_per_lease = derived_bytes as f64 / f64::from(LEASES);
    assert!(
        derived_per_lease <= CAP_DERIVED_LOG_BYTES_PER_LEASE,
        "{derived_per_lease:.0} log bytes of the writer per lease, cap {CAP_DERIVED_LOG_BYTES_PER_LEASE}"
    );
    // The snapshot of the state, compressed on its way to disk, against the live keys and
    // values it holds.
    raft.snapshot_now().await.expect("a snapshot");
    let snapshot = raft.engine_stats().last_snapshot_bytes;
    let live = store.status().data_bytes;
    eprintln!("WRITE COST snapshot: bytes={snapshot} live_bytes={live}");
    assert!(
        snapshot * 3 < live,
        "a snapshot of {snapshot} bytes for {live} bytes of rows"
    );
    // The fsyncs: one durable redb commit of the log per group (redb's one-phase commit with
    // checksums syncs once), none of the state machine per apply (deferred durability).
    assert!(after.log_commits - before.log_commits <= entries);
    drop(store);

    raft.shutdown().await.expect("the store stops");
}

/// A Raft store in a temporary directory, without the fsync probe.
async fn raft_store(dir: &std::path::Path) -> RaftStore {
    let mut config = RaftStoreConfig::new(dir);
    config.fsync_probe_samples = 0;
    RaftStore::open(config).await.expect("the store")
}

/// Grant `k` at an address of 198.18.0.0/15 (the benchmarking range of RFC 2544), for the
/// runs of more than 1,024 leases.
fn grant_wide(vrf: VrfId, scope: PrefixId, k: u32) -> PendingChange {
    let mut change = grant(vrf, scope, k);
    let [_, high, mid, low] = k.to_be_bytes();
    change.addr = std::net::Ipv4Addr::new(198, 18 + (high & 1), mid, low);
    change
}

/// The writer's rate on a Raft store: 5,000 changes of the office shape queued while the
/// writer waits, then flushed at once, with no lease commit beside it: the background
/// batches fill whole entries (6,900 to 7,500 a second on the workstation). Beside lease
/// commits the writer gets one batch per entry and keeps up with them (the ACK-path runs).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::cast_precision_loss, reason = "test figures")]
#[ignore = "a measurement of the release build: cargo test --release -p tenko-dhcp --test lease_write_cost -- --ignored --nocapture"]
async fn the_writer_outruns_the_lease_commits_it_follows() {
    const CHANGES: u32 = 5_000;
    let dir = tempfile::tempdir().expect("a directory");
    let raft = raft_store(dir.path()).await;
    let store: Arc<dyn Store> = Arc::new(raft.clone());
    let (lease_store, committer) = StoreLeases::new(
        Arc::clone(&store),
        SharedLeases::new(LeaseIndex::new()),
        NODE,
        CommitSettings {
            queue: 8_192,
            derived: tenko_dhcp::lease::derived::DerivedSettings {
                interval: Duration::from_secs(3_600),
                max_items: 100_000,
                ..tenko_dhcp::lease::derived::DerivedSettings::default()
            },
            ..CommitSettings::default()
        },
    );
    let stop = CancellationToken::new();
    let task = tokio::spawn(committer.run(stop.clone()));
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let mut done = 0;
    for k in 0..CHANGES {
        lease_store
            .submit(&grant_wide(vrf, scope, k), Ticket(u64::from(k)))
            .expect("the queue has room");
        if k % 4_000 == 3_999 {
            done += completions(&lease_store, 4_000, Duration::from_secs(60))
                .await
                .len();
        }
    }
    done += completions(
        &lease_store,
        (CHANGES as usize) - done,
        Duration::from_secs(60),
    )
    .await
    .len();
    assert_eq!(done, CHANGES as usize);
    assert_eq!(
        lease_store.derived().stats().written,
        0,
        "nothing flushed yet"
    );
    let started = std::time::Instant::now();
    lease_store.derived().flush().await;
    let took = started.elapsed();
    let stats = lease_store.derived().stats();
    assert_eq!((stats.written, stats.dropped), (u64::from(CHANGES), 0));
    let rate = f64::from(CHANGES) / took.as_secs_f64();
    eprintln!(
        "WRITE COST writer: changes={CHANGES} flush_ms={} changes_per_s={rate:.0}",
        took.as_millis()
    );
    assert!(
        rate > 5_000.0,
        "the writer wrote {rate:.0} changes a second"
    );
    stop.cancel();
    task.await.expect("the committer");
    drop(store);
    raft.shutdown().await.expect("the store stops");
}

/// What the store and the writer did at one moment of an ACK-path run.
#[derive(Debug, Clone, Copy)]
struct Sample {
    at: std::time::Instant,
    checkpoints: u64,
    snapshots: u64,
    written: u64,
}

/// One ACK-path run: lease commits at `rate` a second for `secs` seconds on a Raft store, the
/// writer at its defaults beside them. Each commit's time from its hand-off to its
/// completion is measured, and each commit above 25 ms is matched with what happened while
/// it waited: a durable checkpoint of the state file, a snapshot build, a flush of the
/// writer. Prints one `WRITE COST ack path` line and one `WRITE COST tail` line.
#[allow(
    clippy::cast_precision_loss,
    clippy::too_many_lines,
    reason = "test figures, one run read top to bottom"
)]
async fn ack_path(rate: u32, secs: u32) {
    let leases = rate * secs;
    let dir = tempfile::tempdir().expect("a directory");
    let raft = raft_store(dir.path()).await;
    let store: Arc<dyn Store> = Arc::new(raft.clone());
    let (lease_store, committer) = StoreLeases::new(
        Arc::clone(&store),
        SharedLeases::new(LeaseIndex::new()),
        NODE,
        CommitSettings {
            queue: 16_384,
            ..CommitSettings::default()
        },
    );
    let stop = CancellationToken::new();
    let task = tokio::spawn(committer.run(stop.clone()));
    // The completions, timed as they arrive.
    let done: Arc<Mutex<Vec<(u64, std::time::Instant)>>> = Arc::default();
    let collector = {
        let (lease_store, done, stop) = (lease_store.clone(), Arc::clone(&done), stop.clone());
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            loop {
                tokio::select! {
                    () = stop.cancelled() => return,
                    () = lease_store.completed() => {}
                }
                lease_store.completions(&mut buffer);
                let now = std::time::Instant::now();
                let mut done = done.lock().unwrap_or_else(PoisonError::into_inner);
                for completion in buffer.drain(..) {
                    assert!(completion.outcome.is_ok(), "every lease commits");
                    done.push((completion.ticket.0, now));
                }
            }
        })
    };
    // What the store and the writer do, sampled every millisecond.
    let samples: Arc<Mutex<Vec<Sample>>> = Arc::default();
    let monitor = {
        let (raft, writer, samples, stop) = (
            raft.clone(),
            lease_store.derived().clone(),
            Arc::clone(&samples),
            stop.clone(),
        );
        tokio::spawn(async move {
            while !stop.is_cancelled() {
                let stats = raft.engine_stats();
                samples
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(Sample {
                        at: std::time::Instant::now(),
                        checkpoints: stats.checkpoints,
                        snapshots: stats.snapshots_built,
                        written: writer.stats().written,
                    });
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    };
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let started = tokio::time::Instant::now();
    let mut submitted = Vec::with_capacity(leases as usize);
    let mut most_queued = 0;
    for k in 0..leases {
        let due = started + Duration::from_secs_f64(f64::from(k) / f64::from(rate));
        tokio::time::sleep_until(due).await;
        submitted.push(std::time::Instant::now());
        lease_store
            .submit(&grant_wide(vrf, scope, k), Ticket(u64::from(k)))
            .expect("the queue has room");
        if k % 250 == 0 {
            most_queued = most_queued.max(lease_store.derived().stats().queued);
        }
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while done.lock().unwrap_or_else(PoisonError::into_inner).len() < leases as usize {
        assert!(std::time::Instant::now() < deadline, "the commits complete");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let flush_started = std::time::Instant::now();
    lease_store.derived().flush().await;
    let drained_ms = flush_started.elapsed().as_millis();
    stop.cancel();
    task.await.expect("the committer");
    collector.await.expect("the collector");
    monitor.await.expect("the sampler");
    let stats = lease_store.derived().stats();
    let done = std::mem::take(&mut *done.lock().unwrap_or_else(PoisonError::into_inner));
    let samples = std::mem::take(&mut *samples.lock().unwrap_or_else(PoisonError::into_inner));
    // Each commit's time, and what ran while it waited.
    let mut times: Vec<f64> = Vec::with_capacity(done.len());
    let (mut slow, mut slower) = (0, 0);
    let (mut with_checkpoint, mut with_snapshot, mut with_flush) = (0, 0, 0);
    for (ticket, at) in &done {
        let from = submitted[usize::try_from(*ticket).expect("a ticket")];
        let ms = at.duration_since(from).as_secs_f64() * 1_000.0;
        times.push(ms);
        if ms <= 25.0 {
            continue;
        }
        slow += 1;
        if ms > 100.0 {
            slower += 1;
        }
        let window: Vec<&Sample> = samples
            .iter()
            .filter(|sample| sample.at >= from && sample.at <= *at)
            .collect();
        let moved = |field: fn(&Sample) -> u64| {
            window
                .first()
                .zip(window.last())
                .is_some_and(|(first, last)| field(last) > field(first))
        };
        if moved(|sample| sample.checkpoints) {
            with_checkpoint += 1;
        }
        if moved(|sample| sample.snapshots) {
            with_snapshot += 1;
        }
        if moved(|sample| sample.written) {
            with_flush += 1;
        }
    }
    times.sort_by(f64::total_cmp);
    let pick = |per_mille: usize| times[(times.len() - 1) * per_mille / 1_000];
    let average = times.iter().sum::<f64>() / times.len() as f64;
    eprintln!(
        "WRITE COST ack path at {rate}/s: commits={} avg_ms={average:.2} p50_ms={:.2} \
         p99_ms={:.2} max_ms={:.2} over_25ms={slow} over_100ms={slower}; writer: written={} \
         dropped={} most_queued={most_queued} drained_ms={drained_ms}; store: checkpoints={} \
         snapshots={}",
        times.len(),
        pick(500),
        pick(990),
        pick(1_000),
        stats.written,
        stats.dropped,
        samples.last().map_or(0, |sample| sample.checkpoints),
        samples.last().map_or(0, |sample| sample.snapshots),
    );
    eprintln!(
        "WRITE COST tail at {rate}/s: of {slow} commits above 25 ms, {with_checkpoint} waited \
         over a checkpoint of sm.redb, {with_snapshot} over a snapshot build, {with_flush} \
         over a flush of the writer"
    );
    assert_eq!(stats.dropped, 0, "the writer kept up");
    assert_eq!(stats.written, u64::from(leases));
    drop(store);
    raft.shutdown().await.expect("the store stops");
}

/// The ACK path at 1,000 lease commits a second for ten seconds with the writer beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement of the release build: cargo test --release -p tenko-dhcp --test lease_write_cost -- --ignored --nocapture"]
async fn the_ack_path_at_1000_a_second_with_the_writer_beside_it() {
    ack_path(1_000, 10).await;
}

/// The ACK path at 5,000 lease commits a second for four seconds with the writer beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement of the release build: cargo test --release -p tenko-dhcp --test lease_write_cost -- --ignored --nocapture"]
async fn the_ack_path_at_5000_a_second_with_the_writer_beside_it() {
    ack_path(5_000, 4).await;
}
/// ADR 0030: the facts of a lease change reach the store at most one interval of the writer
/// plus its tolerance after the lease, and every wait of the move step that a lease fact
/// ends is longer than that by far (the verification window at its minimum, the default
/// extension window, the wait for the client to come back).
#[test]
fn the_move_steps_waits_tolerate_the_writers_delay() {
    let writer = tenko_dhcp::lease::derived::DerivedSettings::default();
    let delay = writer.interval + writer.tolerance;
    assert!(delay <= Duration::from_millis(1_250), "{delay:?}");
    let moves = tenko_ipam::moves::settings::MoveSettings::default();
    for (what, secs) in [
        ("the verification window at its minimum", 10),
        ("the default extension window", moves.extend_window_secs),
        (
            "the default wait for the client to come back",
            moves.reappear_secs,
        ),
        ("the default verification window", moves.verify_secs),
    ] {
        assert!(
            Duration::from_secs(u64::from(secs)) >= delay * 8,
            "{what} ({secs} s) is not well above the writer's delay of {delay:?}"
        );
    }
}
