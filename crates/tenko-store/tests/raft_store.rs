//! Behaviour of `RaftStore` beyond the shared conformance suite: restart and recovery, the
//! write coalescer, snapshot-and-purge, snapshot installs that write a fresh state file and
//! swap derived indexes without ever exposing an empty one, the in-place re-seed, and the
//! journal's byte limit.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::StreamExt as _;
use tenko_core::{
    AuditSeq, CounterKey, NodeId, Principal, Revision, SystemComponent, TableName, Timestamp,
    audit::{AuditAction, AuditDraft, verify_chain},
    codec::{encode_key, to_cbor},
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt as _, Store, StoreError, StoreRole,
    WatchFilter, WriteBatch,
    raft::{
        RaftStore, RaftStoreConfig, SmDurability, SnapshotPolicy,
        network::InProcessNetwork,
        types::{BatchOutcome, Proposal, ProposedBatch},
    },
    tables,
    testing::RecordingIndex,
};

const ROWS: TableName = TableName::from_static("ipam.raft_test_rows");
const COUNTER: CounterKey = CounterKey::new("ipam.raft_test_counter");
const WRITE: AuditAction = AuditAction::from_static("ipam.raft_test.write");

/// A data directory under the system temporary directory, removed on drop.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tenko-raft-test-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the test directory");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn node(&self, node: u64) -> PathBuf {
        self.0.join(format!("node-{node}"))
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        // Stores close their files asynchronously after shutdown; retry briefly.
        for _ in 0..200 {
            if std::fs::remove_dir_all(&self.0).is_ok() || !self.0.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

fn config(dir: &Path) -> RaftStoreConfig {
    let mut config = RaftStoreConfig::new(dir);
    config.fsync_probe_samples = 0;
    config.verify_full_audit_chain = true;
    config
}

fn at(second: u64) -> Timestamp {
    Timestamp::from_unix_nanos(1_791_547_200_000_000_000 + i128::from(second) * 1_000_000_000)
        .expect("timestamp")
}

fn batch() -> WriteBatch {
    WriteBatch::new(Principal::system(SystemComponent::Ipam), at(0))
}

fn key(n: u64) -> Bytes {
    encode_key(&n)
}

async fn put(store: &RaftStore, n: u64, value: &str) -> Revision {
    let mut b = batch();
    b.put(ROWS, key(n), Bytes::copy_from_slice(value.as_bytes()))
        .bump(COUNTER)
        .audit(AuditDraft::success(WRITE, vec![]));
    store.propose(b).await.expect("commit").revision
}

fn rows(view: &dyn ReadView) -> BTreeMap<Bytes, Bytes> {
    let mut out = BTreeMap::new();
    let mut range = KeyRange::all();
    loop {
        let page = view.scan(&ROWS, range.clone(), 1_000, false).expect("scan");
        let Some((last, _)) = page.last() else {
            return out;
        };
        range = KeyRange::all().after(last.clone());
        out.extend(page.into_iter().map(|(k, v)| (k, v.value)));
    }
}

fn audit_records(view: &dyn ReadView) -> Vec<tenko_core::audit::AuditRecord> {
    view.scan_typed(&tables::AUDIT, KeyRange::all(), 1_000_000, false)
        .expect("scan audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .collect()
}

async fn restart_round_trip(durability: SmDurability) {
    let dir = TestDir::new("restart");
    let mut cfg = config(dir.path());
    cfg.durability = durability;

    let store = RaftStore::open(cfg.clone()).await.expect("open");
    let index = Arc::new(RecordingIndex::new(ROWS));
    store.register_index(index.clone()).expect("register");
    for n in 1..=50 {
        put(&store, n, &format!("v{n}")).await;
    }
    let mut b = batch();
    b.delete(ROWS, key(7));
    let last = store.propose(b).await.expect("delete").revision;
    assert_eq!(last, Revision(51));
    assert_eq!(index.image().rows.len(), 49);
    let before = rows(
        store
            .read(ReadConsistency::Local)
            .await
            .expect("view")
            .as_ref(),
    );
    store.shutdown().await.expect("shutdown");
    assert_eq!(
        store.propose(batch()).await,
        Err(StoreError::ShuttingDown),
        "a closed store refuses writes"
    );
    drop(store);

    let store = RaftStore::open(cfg).await.expect("reopen");
    let status = store.status();
    assert_eq!(
        status.revision,
        Revision(51),
        "every commit survives the restart"
    );
    assert_eq!(status.audit_head, AuditSeq(50));
    assert_eq!(status.role, StoreRole::Leader);
    let view = store.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(rows(view.as_ref()), before);
    assert_eq!(view.counter(&COUNTER).expect("counter"), 50);
    assert_eq!(
        verify_chain(&audit_records(view.as_ref()))
            .expect("chain")
            .seq,
        AuditSeq(50)
    );
    // Derived indexes are in memory: registering again rebuilds them from the store.
    let rebuilt = Arc::new(RecordingIndex::new(ROWS));
    store
        .register_index(rebuilt.clone())
        .expect("register again");
    assert_eq!(rebuilt.image().rows, before);
    assert_eq!(rebuilt.image().revision, Revision(51));
    // The journal survived too: a watcher resumes from a revision before the restart.
    let mut watch = store
        .watch(Some(Revision(48)), WatchFilter::all())
        .expect("watch");
    for expected in 49..=51 {
        let change_set = tokio::time::timeout(Duration::from_secs(10), watch.next())
            .await
            .expect("in time")
            .expect("open")
            .expect("change set");
        assert_eq!(change_set.revision, Revision(expected));
    }
    assert_eq!(put(&store, 100, "after").await, Revision(52));
    assert_eq!(rebuilt.image().revision, Revision(52));
    drop(watch);
    drop(view);
    store.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_keeps_every_commit_with_deferred_durability() {
    restart_round_trip(SmDurability::Deferred {
        checkpoint_interval: Duration::from_secs(3_600),
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_keeps_every_commit_with_immediate_durability() {
    restart_round_trip(SmDurability::Immediate).await;
}

fn proposed(b: &WriteBatch) -> ProposedBatch {
    ProposedBatch {
        batch: to_cbor(b).expect("encode"),
        fingerprint: None,
    }
}

/// Batches of one entry apply in order, each against its own preconditions; a failing one
/// does not fail the others and consumes no revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batches_in_one_entry_apply_in_order_and_fail_alone() {
    let store = RaftStore::open_temp(config(Path::new("unused")))
        .await
        .expect("open");
    put(&store, 1, "seed").await;

    let mut first = batch();
    first
        .expect_version(ROWS, key(2), None)
        .put(ROWS, key(2), Bytes::from_static(b"a"));
    // Sees the first batch's write (revision 2) because batches apply in order.
    let mut second = batch();
    second.expect_version(ROWS, key(2), Some(Revision(2))).put(
        ROWS,
        key(2),
        Bytes::from_static(b"b"),
    );
    // Stale: fails alone.
    let mut third = batch();
    third.expect_version(ROWS, key(2), Some(Revision(2))).put(
        ROWS,
        key(3),
        Bytes::from_static(b"never"),
    );
    // Applies after the failure with the next revision.
    let mut fourth = batch();
    fourth
        .expect_counter(COUNTER, 1)
        .bump(COUNTER)
        .put(ROWS, key(4), Bytes::from_static(b"d"));
    let proposal = Proposal {
        journal_retention: 1_000,
        journal_max_bytes: 0,
        batches: [&first, &second, &third, &fourth]
            .into_iter()
            .map(proposed)
            .collect(),
    };
    let response = store
        .raft()
        .client_write(proposal)
        .await
        .expect("one entry");
    let outcomes = response.data.outcomes;
    assert_eq!(outcomes.len(), 4);
    let revisions: Vec<Option<Revision>> = outcomes
        .iter()
        .map(|outcome| match outcome {
            BatchOutcome::Committed(committed) => Some(committed.revision),
            _ => None,
        })
        .collect();
    assert_eq!(
        revisions,
        vec![
            Some(Revision(2)),
            Some(Revision(3)),
            None,
            Some(Revision(4))
        ]
    );
    assert!(matches!(outcomes[2], BatchOutcome::PreconditionFailed(_)));
    let view = store.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(view.revision(), Revision(4));
    assert_eq!(
        view.get(&ROWS, &key(2)).expect("get").map(|v| v.value),
        Some(Bytes::from_static(b"b"))
    );
    assert_eq!(view.get(&ROWS, &key(3)).expect("get"), None);
    assert_eq!(view.counter(&COUNTER).expect("counter"), 2);
}

/// Concurrent proposals share entries: far fewer Raft entries than batches.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_proposals_are_coalesced_into_shared_entries() {
    let mut cfg = config(Path::new("unused"));
    cfg.coalescer.max_inflight_entries = 1;
    let store = RaftStore::open_temp(cfg).await.expect("open");
    let before = store.engine_stats();
    let mut tasks = Vec::new();
    for n in 0..400_u64 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move { put(&store, n, "v").await }));
    }
    let mut revisions = Vec::new();
    for task in tasks {
        revisions.push(task.await.expect("task"));
    }
    revisions.sort();
    revisions.dedup();
    assert_eq!(revisions.len(), 400, "distinct revisions");
    let stats = store.engine_stats();
    let entries = stats.entries_proposed - before.entries_proposed;
    let batches = stats.batches_proposed - before.batches_proposed;
    assert_eq!(batches, 400);
    assert!(
        entries < batches / 4,
        "400 concurrent batches travelled in {entries} entries"
    );
    let view = store.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(
        verify_chain(&audit_records(view.as_ref()))
            .expect("chain")
            .seq,
        AuditSeq(400)
    );
}

/// Every committed proposal is timed once in `tenko_store_commit_duration_seconds`; a
/// refused one is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_proposals_are_timed_once() {
    let store = RaftStore::open_temp(config(Path::new("unused")))
        .await
        .expect("open");
    let before = tenko_store::raft::COMMIT_DURATION.get().count();
    for n in 0..3_u64 {
        put(&store, n, "v").await;
    }
    let mut refused = batch();
    refused.put(ROWS, key(9), Bytes::from_static(b"v"));
    refused.expect_version(ROWS, key(0), None);
    assert!(store.propose(refused).await.is_err());
    // Other tests of this binary may commit at the same time, so at least three.
    let after = tenko_store::raft::COMMIT_DURATION.get();
    assert!(after.count() >= before + 3, "{after:?}");
    assert!(after.sum > 0, "{after:?}");
}

/// The entry and batch byte limits split the queue across entries; an oversized batch
/// travels alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn entry_byte_limit_splits_entries() {
    let mut cfg = config(Path::new("unused"));
    cfg.coalescer.max_entry_bytes = 4 * 1024;
    cfg.coalescer.max_inflight_entries = 1;
    let store = RaftStore::open_temp(cfg).await.expect("open");
    let before = store.engine_stats();
    let mut tasks = Vec::new();
    for n in 0..40_u64 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let mut b = batch();
            b.put(ROWS, key(n), vec![7_u8; 1_000]);
            store.propose(b).await.expect("commit")
        }));
    }
    let mut big = batch();
    big.put(ROWS, key(1_000), vec![9_u8; 64 * 1024]);
    store
        .propose(big)
        .await
        .expect("an oversized batch still commits");
    for task in tasks {
        task.await.expect("task");
    }
    let stats = store.engine_stats();
    let entries = stats.entries_proposed - before.entries_proposed;
    // 40 batches of about 1 KiB with at most 4 KiB per entry need at least 10 entries.
    assert!(entries >= 11, "only {entries} entries");
}

/// Snapshots are built by policy, the log is purged behind them, and a restart recovers
/// from the snapshot plus the remaining log.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_and_purge_run_by_policy_and_survive_restart() {
    let dir = TestDir::new("purge");
    let mut cfg = config(dir.path());
    cfg.snapshot = SnapshotPolicy {
        every_entries: 40,
        every_log_bytes: u64::MAX,
        keep_entries: 5,
    };
    let store = RaftStore::open(cfg.clone()).await.expect("open");
    for n in 1..=200 {
        put(&store, n, "v").await;
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let purged = store
            .raft()
            .metrics()
            .borrow()
            .purged
            .map_or(0, |log_id| log_id.index);
        if store.engine_stats().snapshots_built >= 1 && purged > 100 {
            break;
        }
        assert!(Instant::now() < deadline, "no snapshot and purge by policy");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let before = rows(
        store
            .read(ReadConsistency::Local)
            .await
            .expect("view")
            .as_ref(),
    );
    store.shutdown().await.expect("shutdown");
    drop(store);

    let store = RaftStore::open(cfg).await.expect("reopen");
    assert_eq!(store.status().revision, Revision(200));
    let view = store.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(rows(view.as_ref()), before);
    assert_eq!(view.counter(&COUNTER).expect("counter"), 200);
    drop(view);
    store.shutdown().await.expect("shutdown");
}

fn node_config(dir: &TestDir, node: u64) -> RaftStoreConfig {
    let mut cfg = config(&dir.node(node));
    cfg.node_id = NodeId(node);
    cfg.address = format!("in-process-{node}");
    cfg.bootstrap = node == 1;
    cfg.timings.heartbeat_ms = 50;
    cfg.timings.election_min_ms = 1_500;
    cfg.timings.election_max_ms = 3_000;
    cfg.snapshot = SnapshotPolicy {
        every_entries: u64::MAX,
        every_log_bytes: u64::MAX,
        keep_entries: 0,
    };
    cfg
}

async fn wait_for_revision(store: &RaftStore, revision: Revision) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while store.status().revision < revision {
        assert!(Instant::now() < deadline, "node did not catch up");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A learner catches up by snapshot, and a later snapshot install while readers hammer its
/// index replaces the index atomically: no reader ever sees an empty or shrunken image.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_install_swaps_the_index_without_empty_reads() {
    let dir = TestDir::new("install");
    let network = InProcessNetwork::new();
    let leader = RaftStore::open_with(node_config(&dir, 1), Arc::new(network.clone()))
        .await
        .expect("leader");
    network.register(&leader);
    for n in 0..300 {
        put(&leader, n, "first").await;
    }
    leader.snapshot_now().await.expect("snapshot");
    // The purge follows the snapshot; once it is done the learner can only catch up by
    // snapshot.
    let snapshot = leader.raft().metrics().borrow().snapshot;
    let deadline = Instant::now() + Duration::from_secs(20);
    while leader.raft().metrics().borrow().purged < snapshot {
        assert!(
            Instant::now() < deadline,
            "the leader did not purge its log"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let follower = RaftStore::open_with(node_config(&dir, 2), Arc::new(network.clone()))
        .await
        .expect("learner");
    network.register(&follower);
    let index = Arc::new(RecordingIndex::new(ROWS));
    follower.register_index(index.clone()).expect("register");
    leader
        .add_learner(NodeId(2), "in-process-2", true)
        .await
        .expect("add learner");
    wait_for_revision(&follower, leader.status().revision).await;
    assert_eq!(index.image().rows.len(), 300);
    assert_eq!(follower.engine_stats().snapshots_installed, 1);
    assert_eq!(follower.status().role, StoreRole::Learner);

    // Cut the learner off and move on. openraft defers purging logs a replication request
    // still uses, so whether the leader would send a snapshot on reconnect is a race; the
    // second install is therefore streamed explicitly through the transport's receiving
    // side, exactly as a peer transport does.
    network.set_isolated(2, true);
    for n in 300..900 {
        put(&leader, n, "second").await;
    }
    leader.snapshot_now().await.expect("snapshot");
    let target = leader.status().revision;
    let (meta, path) = leader.current_snapshot().expect("leader snapshot");
    let vote = leader.raft().metrics().borrow().vote;

    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let index = index.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut reads = 0_u64;
            let mut smallest = usize::MAX;
            while !stop.load(Ordering::Relaxed) {
                smallest = smallest.min(index.image().rows.len());
                reads += 1;
            }
            (reads, smallest)
        })
    };
    let mut receiver = follower.receive_snapshot().expect("receiver");
    let bytes = std::fs::read(&path).expect("read the snapshot file");
    for chunk in bytes.chunks(64 * 1024) {
        receiver.write_chunk(chunk).await.expect("chunk");
    }
    receiver.install(vote, meta).await.expect("install");
    wait_for_revision(&follower, target).await;
    network.set_isolated(2, false);
    stop.store(true, Ordering::Relaxed);
    let (reads, smallest) = reader.join().expect("reader");
    assert!(reads > 0);
    assert!(
        smallest >= 300,
        "a reader saw {smallest} rows: the index was cleared during the install"
    );
    assert_eq!(follower.engine_stats().snapshots_installed, 2);
    let view = follower.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(index.image().rows, rows(view.as_ref()));
    assert_eq!(index.image().rows.len(), 900);
    let records = audit_records(view.as_ref());
    assert_eq!(verify_chain(&records).expect("chain").seq, AuditSeq(900));
    drop(view);

    // Replication continues by log after the install.
    let last = put(&leader, 5_000, "third").await;
    wait_for_revision(&follower, last).await;
    assert_eq!(index.image().revision, last);

    follower.shutdown().await.expect("shutdown");
    leader.shutdown().await.expect("shutdown");
}

/// Three voters replicate, a follower forwards its writes to the leader, and when the leader
/// is cut off the other two elect a new leader that accepts writes; the old leader catches
/// up after it reconnects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_voters_replicate_and_fail_over() {
    let dir = TestDir::new("cluster");
    let network = InProcessNetwork::new();
    let mut nodes = Vec::new();
    for node in 1..=3 {
        let mut cfg = node_config(&dir, node);
        cfg.snapshot = SnapshotPolicy::default();
        let store = RaftStore::open_with(cfg, Arc::new(network.clone()))
            .await
            .expect("open");
        network.register(&store);
        nodes.push(store);
    }
    let first = nodes[0].clone();
    for node in 2..=3 {
        first
            .add_learner(NodeId(node), format!("in-process-{node}"), true)
            .await
            .expect("learner");
    }
    first
        .change_membership([NodeId(1), NodeId(2), NodeId(3)].into())
        .await
        .expect("three voters");
    let mut last = Revision::ZERO;
    for n in 0..100 {
        last = put(&first, n, "replicated").await;
    }
    for node in &nodes {
        wait_for_revision(node, last).await;
    }
    // A follower forwards the write to the leader and has applied it when it returns.
    let forwarded = put(&nodes[1], 500, "through a follower").await;
    assert!(forwarded > last);
    let local = nodes[1].read(ReadConsistency::Local).await.expect("view");
    assert_eq!(
        rows(local.as_ref()).get(&key(500)),
        Some(&Bytes::from_static(b"through a follower")),
    );
    drop(local);
    last = forwarded;

    // Cut the leader off; the other two elect a new leader.
    network.set_isolated(1, true);
    let deadline = Instant::now() + Duration::from_secs(30);
    let new_leader = loop {
        let leader = nodes[1..]
            .iter()
            .find(|node| node.status().role == StoreRole::Leader)
            .cloned();
        if let Some(leader) = leader {
            break leader;
        }
        assert!(Instant::now() < deadline, "no new leader was elected");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let after = put(&new_leader, 1_000, "after failover").await;
    assert!(after > last);
    network.set_isolated(1, false);
    for node in &nodes {
        wait_for_revision(node, after).await;
    }
    let views =
        futures::future::join_all(nodes.iter().map(|node| node.read(ReadConsistency::Local))).await;
    let contents: Vec<_> = views
        .into_iter()
        .map(|view| rows(view.expect("view").as_ref()))
        .collect();
    assert!(contents.windows(2).all(|pair| pair[0] == pair[1]));
    assert_ne!(nodes[0].status().role, StoreRole::Leader);
    for node in nodes {
        node.shutdown().await.expect("shutdown");
    }
}

/// The state files in a data directory and the name `sm.current` holds, if any.
fn state_files(dir: &Path) -> (Vec<String>, Option<String>) {
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .expect("list the data directory")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            name.starts_with("sm")
                && Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("redb"))
        })
        .collect();
    files.sort();
    let pointer = std::fs::read_to_string(dir.join("sm.current"))
        .ok()
        .map(|name| name.trim().to_owned());
    (files, pointer)
}

/// Writes `rows` records of `size` bytes in batches of 500, then rewrites every third one.
async fn load_and_churn(store: &RaftStore, rows: u64, size: usize) {
    for chunk in (0..rows).collect::<Vec<_>>().chunks(500) {
        let mut b = batch();
        for n in chunk {
            b.put(ROWS, key(*n), vec![1_u8; size]);
        }
        store.propose(b).await.expect("load");
    }
    for chunk in (0..rows).step_by(3).collect::<Vec<_>>().chunks(500) {
        let mut b = batch();
        for n in chunk {
            b.put(ROWS, key(*n), vec![2_u8; size]);
        }
        store.propose(b).await.expect("churn");
    }
}

/// A snapshot install writes the state into a fresh, compacted state file named by
/// `sm.current`; the old file is gone, and the node restarts from the new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn install_writes_a_fresh_state_file_that_survives_restart() {
    let dir = TestDir::new("fresh-install");
    let network = InProcessNetwork::new();
    let leader = RaftStore::open_with(node_config(&dir, 1), Arc::new(network.clone()))
        .await
        .expect("leader");
    network.register(&leader);
    load_and_churn(&leader, 6_000, 512).await;
    leader.snapshot_now().await.expect("snapshot");
    let target = leader.status().revision;
    let (meta, path) = leader.current_snapshot().expect("snapshot file");
    let vote = leader.raft().metrics().borrow().vote;

    let follower_config = node_config(&dir, 2);
    let follower = RaftStore::open_with(follower_config.clone(), Arc::new(network.clone()))
        .await
        .expect("follower");
    let index = Arc::new(RecordingIndex::new(ROWS));
    follower.register_index(index.clone()).expect("register");
    assert_eq!(
        state_files(&dir.node(2)),
        (vec!["sm.redb".to_owned()], None),
        "a new store starts with sm.redb and no pointer"
    );
    let mut receiver = follower.receive_snapshot().expect("receiver");
    receiver
        .write_chunk(&std::fs::read(&path).expect("read the snapshot"))
        .await
        .expect("chunk");
    receiver.install(vote, meta).await.expect("install");
    wait_for_revision(&follower, target).await;

    let (files, pointer) = state_files(&dir.node(2));
    let pointer = pointer.expect("sm.current after an install");
    assert_eq!(
        files,
        vec![pointer.clone()],
        "only the new state file remains"
    );
    assert!(pointer.starts_with("sm-"));
    let leader_view = leader.read(ReadConsistency::Local).await.expect("view");
    let expected = rows(leader_view.as_ref());
    drop(leader_view);
    let view = follower.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(rows(view.as_ref()), expected);
    drop(view);
    assert_eq!(index.image().rows, expected, "the index was rebuilt aside");
    assert!(follower.engine_stats().last_compact_micros > 0);
    // The installed file is compact: no doubling slack around the live data.
    let usage = follower.disk_usage();
    let file = std::fs::metadata(dir.node(2).join(&pointer))
        .expect("state file")
        .len();
    assert!(
        file < 2 * usage.data_bytes,
        "fresh state file of {file} bytes for {} bytes of data",
        usage.data_bytes
    );

    follower.shutdown().await.expect("shutdown");
    drop(follower);
    let follower = RaftStore::open_with(follower_config, Arc::new(network.clone()))
        .await
        .expect("reopen the follower");
    assert_eq!(follower.status().revision, target);
    let view = follower.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(rows(view.as_ref()), expected);
    drop(view);
    assert_eq!(state_files(&dir.node(2)).1, Some(pointer));
    follower.shutdown().await.expect("shutdown");
    leader.shutdown().await.expect("shutdown");
}

/// A node re-seeds itself in place: same state, fresh file, indexes untouched, writes
/// continue afterwards, and a restart opens the new file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reseed_in_place_rewrites_the_state_file() {
    let dir = TestDir::new("reseed");
    let cfg = config(dir.path());
    let store = RaftStore::open(cfg.clone()).await.expect("open");
    let index = Arc::new(RecordingIndex::new(ROWS));
    store.register_index(index.clone()).expect("register");
    load_and_churn(&store, 6_000, 512).await;
    let revision = store.status().revision;
    let before = rows(
        store
            .read(ReadConsistency::Local)
            .await
            .expect("view")
            .as_ref(),
    );
    let image_before = index.image();

    let reseeded = store.reseed_in_place().await.expect("re-seed");
    assert!(
        reseeded.bytes_after <= reseeded.bytes_before,
        "{reseeded:?}"
    );
    assert_eq!(store.engine_stats().reseeds_in_place, 1);
    assert_eq!(
        store.status().revision,
        revision,
        "the state does not change"
    );
    let view = store.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(rows(view.as_ref()), before);
    drop(view);
    assert_eq!(index.image(), image_before, "indexes keep their image");
    let status = store.status();
    assert_eq!(status.sm_file_bytes, Some(reseeded.bytes_after));
    assert!(status.sm_file_ratio().is_some_and(|ratio| ratio < 2.0));
    let (files, pointer) = state_files(dir.path());
    assert_eq!(files, vec![pointer.clone().expect("pointer")]);

    let next = put(&store, 99_999, "after").await;
    assert_eq!(next, revision.next());
    assert_eq!(index.image().revision, next);
    store.shutdown().await.expect("shutdown");
    drop(store);

    let store = RaftStore::open(cfg).await.expect("reopen");
    assert_eq!(store.status().revision, next);
    let usage = store.disk_usage();
    assert!(
        usage.state_ratio_at_open.is_some_and(|ratio| ratio < 2.0),
        "the re-seeded file is compact at start-up: {usage:?}"
    );
    let view = store.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(rows(view.as_ref()).len(), before.len() + 1);
    drop(view);
    assert_eq!(state_files(dir.path()).1, pointer);
    store.shutdown().await.expect("shutdown");
}

/// The journal's byte limit comes from the entry, so a follower configured differently
/// trims exactly like the leader; the newest change set always stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn journal_byte_limit_is_applied_identically_on_every_replica() {
    let dir = TestDir::new("journal-bytes");
    let network = InProcessNetwork::new();
    let mut leader_config = node_config(&dir, 1);
    leader_config.journal_max_bytes = 64 * 1024;
    let leader = RaftStore::open_with(leader_config, Arc::new(network.clone()))
        .await
        .expect("leader");
    network.register(&leader);
    let follower = RaftStore::open_with(node_config(&dir, 2), Arc::new(network.clone()))
        .await
        .expect("follower");
    network.register(&follower);
    leader
        .add_learner(NodeId(2), "in-process-2", true)
        .await
        .expect("learner");

    // 40 batches of 200 keys: each change set is several KiB.
    for round in 0..40_u64 {
        let mut b = batch();
        for n in 0..200 {
            b.put(ROWS, key(round * 1_000 + n), vec![3_u8; 16]);
        }
        leader.propose(b).await.expect("commit");
    }
    let target = leader.status().revision;
    wait_for_revision(&follower, target).await;
    let (on_leader, on_follower) = (leader.status(), follower.status());
    assert!(
        on_leader.journal_len < 40,
        "the byte limit trimmed the journal: {} change sets",
        on_leader.journal_len
    );
    assert!(on_leader.journal_len >= 1);
    assert_eq!(on_leader.journal_len, on_follower.journal_len);
    assert_eq!(on_leader.journal_oldest, on_follower.journal_oldest);
    assert!(matches!(
        leader.watch(Some(Revision(1)), WatchFilter::all()),
        Err(StoreError::Compacted { .. })
    ));
    // One change set larger than the limit on its own still stays.
    let mut big = batch();
    for n in 0..5_000 {
        big.put(ROWS, key(10_000_000 + n), vec![4_u8; 8]);
    }
    let last = leader.propose(big).await.expect("commit").revision;
    assert_eq!(leader.status().journal_len, 1);
    assert_eq!(leader.status().journal_oldest, Some(last));
    let mut watch = leader
        .watch(Some(Revision(last.get() - 1)), WatchFilter::all())
        .expect("watch the newest change set");
    let change_set = tokio::time::timeout(Duration::from_secs(10), watch.next())
        .await
        .expect("in time")
        .expect("open")
        .expect("change set");
    assert_eq!(change_set.revision, last);
    assert_eq!(change_set.changes.len(), 5_000);
    drop(watch);
    follower.shutdown().await.expect("shutdown");
    leader.shutdown().await.expect("shutdown");
}
