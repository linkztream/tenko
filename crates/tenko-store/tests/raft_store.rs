//! Behavior of `RaftStore` beyond the shared conformance suite: restart and recovery, the
//! write coalescer, snapshot-and-purge, snapshot installs that write a fresh state file and
//! swap derived indexes without ever exposing an empty one, the in-place re-seed, and the
//! journal's byte limit.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::StreamExt as _;
use tenko_core::{
    AuditSeq, CounterKey, NodeId, Principal, Revision, SystemComponent, TableName, Timestamp,
    audit::{AuditAction, AuditDraft, verify_chain},
    codec::{encode_key, to_cbor},
    testing::{TempDir, wait_until_async, wait_until_async_within},
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt as _, Store, StoreError, StoreRole,
    WatchFilter, WriteBatch,
    raft::{
        RaftStore, RaftStoreConfig, SmDurability, SnapshotPolicy,
        network::InProcessNetwork,
        openraft,
        types::{BatchOutcome, Proposal, ProposedBatch, StoredMembership, Vote},
    },
    tables,
    testing::RecordingIndex,
};

const ROWS: TableName = TableName::from_static("ipam.raft_test_rows");
const COUNTER: CounterKey = CounterKey::new("ipam.raft_test_counter");
const WRITE: AuditAction = AuditAction::from_static("ipam.raft_test.write");

/// A data directory under the system temporary directory, with a subdirectory per node.
struct TestDir(TempDir);

impl TestDir {
    fn new(name: &str) -> Self {
        Self(TempDir::new(&format!("raft-test-{name}")))
    }

    fn path(&self) -> &Path {
        self.0.path()
    }

    fn node(&self, node: u64) -> PathBuf {
        self.0.join(format!("node-{node}"))
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

/// The term of the store's current snapshot.
fn snapshot_term(store: &RaftStore) -> u64 {
    let (meta, _) = store.current_snapshot().expect("a snapshot");
    meta.last_log_id.expect("a log id").leader_id.term
}

/// A store as a restore leaves it before its first election (`install_at` of `tenko backup
/// restore`): the snapshot of controller 7 at term 1, installed in `dir.node(1)` under the
/// vote of a leader that is not this node, with node 1 as the only voter. Its last applied
/// entry is node 7's. It is open, with elections off, so it stays as the restore left it.
async fn restored_store(dir: &TestDir) -> RaftStore {
    let mut source_config = config(&dir.node(7));
    source_config.node_id = NodeId(7);
    let source = RaftStore::open(source_config).await.expect("source");
    put(&source, 1, "from the source").await;
    source.snapshot_now().await.expect("snapshot");
    let (mut meta, path) = source.current_snapshot().expect("a snapshot");
    let only_this_node = openraft::Membership::new(
        vec![BTreeSet::from([1])],
        BTreeMap::from([(1, openraft::BasicNode::new(""))]),
    );
    meta.last_membership = StoredMembership::new(meta.last_log_id, only_this_node);
    let mut restored_config = config(&dir.node(1));
    restored_config.bootstrap = false;
    restored_config.elect = false;
    let restored = RaftStore::open(restored_config).await.expect("learner");
    let mut receiver = restored.receive_snapshot().expect("receiver");
    for chunk in std::fs::read(&path).expect("read").chunks(64 * 1024) {
        receiver.write_chunk(chunk).await.expect("chunk");
    }
    receiver
        .install(Vote::new_committed(1, u64::MAX), meta)
        .await
        .expect("install");
    source.shutdown().await.expect("shutdown");
    restored
}

/// Two voters, nodes 1 and 2, over an in-process network, with one row on both.
async fn two_voters(dir: &TestDir) -> (RaftStore, RaftStore) {
    let network = InProcessNetwork::new();
    let first = RaftStore::open_with(node_config(dir, 1), Arc::new(network.clone()))
        .await
        .expect("node 1");
    network.register(&first);
    let second = RaftStore::open_with(node_config(dir, 2), Arc::new(network.clone()))
        .await
        .expect("node 2");
    network.register(&second);
    first
        .add_learner(NodeId(2), "in-process-2", true)
        .await
        .expect("learner");
    first
        .change_membership([NodeId(1), NodeId(2)].into())
        .await
        .expect("two voters");
    let last = put(&first, 1, "replicated").await;
    wait_for_revision(&second, last).await;
    (first, second)
}

/// A state copy (`copy_state_to`, as an upgrade check takes one) has no log and so no vote.
/// Its first election must lead a term after its last entry, here one of another node: a
/// lower or equal leader breaks the leader invariant of openraft.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_state_copy_of_a_restored_store_leads_a_term_after_its_last_entry() {
    let dir = TestDir::new("copy-restored");
    let restored = restored_store(&dir).await;
    restored.copy_state_to(&dir.node(2)).await.expect("copy");
    restored.shutdown().await.expect("shutdown");
    drop(restored);

    let copy = RaftStore::open(config(&dir.node(2)))
        .await
        .expect("the copy opens and leads");
    put(&copy, 2, "on the copy").await;
    copy.snapshot_now()
        .await
        .expect("the copy builds a snapshot");
    assert!(
        snapshot_term(&copy) > 1,
        "the copy leads a term after the entry it holds"
    );
    copy.shutdown().await.expect("shutdown");
}

/// The same for a single voter whose entries are of its own later term: a restored store
/// after its own election, the case of a backup taken on a restored controller.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_state_copy_of_a_single_voter_at_a_later_term_leads_a_term_after_its_entries() {
    let dir = TestDir::new("copy-term");
    restored_store(&dir)
        .await
        .shutdown()
        .await
        .expect("shutdown");
    let store = RaftStore::open(config(&dir.node(1))).await.expect("elect");
    put(&store, 2, "at the new term").await;
    store.snapshot_now().await.expect("snapshot");
    let store_term = snapshot_term(&store);
    assert!(store_term > 1, "the election started a new term");
    store.copy_state_to(&dir.node(2)).await.expect("copy");
    store.shutdown().await.expect("shutdown");
    drop(store);

    let copy = RaftStore::open(config(&dir.node(2)))
        .await
        .expect("the copy opens and leads");
    put(&copy, 3, "on the copy").await;
    copy.snapshot_now()
        .await
        .expect("the copy builds a snapshot");
    assert!(
        snapshot_term(&copy) > store_term,
        "the copy leads a term after the entries it holds"
    );
    copy.shutdown().await.expect("shutdown");
}

/// A backup opens its copy with elections off: it never leads, and its snapshot is at the
/// applied position of the source, without an entry of its own. A second copy with elections
/// on and a longer election timeout shows that the first one's timeout has passed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backup_copy_never_elects_and_snapshots_the_position_of_the_source() {
    let dir = TestDir::new("copy-backup");
    let source = RaftStore::open(config(&dir.node(1))).await.expect("source");
    for n in 1..=3 {
        put(&source, n, "on the source").await;
    }
    let applied = source.raft().metrics().borrow().last_applied;
    source.copy_state_to(&dir.node(2)).await.expect("copy");
    source.copy_state_to(&dir.node(3)).await.expect("copy");
    source.shutdown().await.expect("shutdown");
    drop(source);

    let copy_config = |node: u64, elect: bool, election_ms: u64| {
        let mut copy_config = config(&dir.node(node));
        copy_config.bootstrap = false;
        copy_config.elect = elect;
        copy_config.timings.heartbeat_ms = 5;
        copy_config.timings.election_min_ms = election_ms;
        copy_config.timings.election_max_ms = election_ms + 1;
        copy_config
    };
    let backup = RaftStore::open(copy_config(2, false, 10))
        .await
        .expect("backup copy");
    let control = RaftStore::open(copy_config(3, true, 40))
        .await
        .expect("control copy");
    wait_until_async("the control copy to lead", async || {
        control.status().role == StoreRole::Leader
    })
    .await;
    assert_ne!(backup.status().role, StoreRole::Leader);
    backup.snapshot_now().await.expect("snapshot");
    let (meta, _) = backup.current_snapshot().expect("a snapshot");
    assert_eq!(
        meta.last_log_id, applied,
        "the snapshot is at the source's position"
    );
    control.shutdown().await.expect("shutdown");
    backup.shutdown().await.expect("shutdown");
}

/// A copy of a member of several voters holds the vote of its last entry and does not
/// campaign: without its peers an election could only raise the term.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_state_copy_of_a_cluster_member_does_not_elect() {
    let dir = TestDir::new("copy-member");
    let (first, second) = two_voters(&dir).await;
    let applied = first
        .raft()
        .metrics()
        .borrow()
        .last_applied
        .expect("applied");
    first.copy_state_to(&dir.node(3)).await.expect("copy");
    second.shutdown().await.expect("shutdown");
    first.shutdown().await.expect("shutdown");

    let copy = RaftStore::open(config(&dir.node(3)))
        .await
        .expect("the copy opens without a leader");
    assert_ne!(copy.status().role, StoreRole::Leader);
    assert_eq!(
        copy.raft().metrics().borrow().vote,
        Vote::new(applied.leader_id.term, applied.leader_id.node_id),
        "the copy holds the vote of its last entry and has not campaigned"
    );
    copy.shutdown().await.expect("shutdown");
}

/// What a test logs, as text.
#[derive(Clone, Default)]
struct Logged(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Logged {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the log buffer")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Logged {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("the log buffer")).into_owned()
    }
}

/// A single voter whose Raft log was lost (removed, or only the state file restored) goes
/// on from its state with a warning, and its election leads the next term.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_voter_whose_log_is_lost_warns_and_leads_the_next_term() {
    let dir = TestDir::new("lost-log-single");
    let store = RaftStore::open(config(&dir.node(1))).await.expect("open");
    put(&store, 1, "before").await;
    store.snapshot_now().await.expect("snapshot");
    let before = snapshot_term(&store);
    store.shutdown().await.expect("shutdown");
    drop(store);
    std::fs::remove_file(dir.node(1).join("log.redb")).expect("remove the log");

    let logged = Logged::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer({
            let logged = logged.clone();
            move || logged.clone()
        })
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let store = RaftStore::open(config(&dir.node(1)))
        .await
        .expect("the only voter opens");
    drop(guard);
    assert!(
        logged
            .text()
            .contains("the Raft log (log.redb) of this store is lost"),
        "{}",
        logged.text()
    );
    let view = store.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(rows(view.as_ref()).len(), 1, "the state is kept");
    drop(view);
    put(&store, 2, "after").await;
    store.snapshot_now().await.expect("snapshot");
    assert!(snapshot_term(&store) > before, "it leads the next term");
    store.shutdown().await.expect("shutdown");
}

/// A member of several voters whose Raft log was lost does not open: it may have voted in a
/// term the lost log held, and could vote twice in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cluster_member_whose_log_is_lost_does_not_open() {
    let dir = TestDir::new("lost-log-member");
    let (first, second) = two_voters(&dir).await;
    second.shutdown().await.expect("shutdown");
    first.shutdown().await.expect("shutdown");
    drop((first, second));
    std::fs::remove_file(dir.node(2).join("log.redb")).expect("remove the log");

    let Err(StoreError::Storage(message)) = RaftStore::open(node_config(&dir, 2)).await else {
        panic!("a member without its Raft log must not open");
    };
    assert!(
        message.contains("the Raft log (log.redb) of this store is lost")
            && message.contains("voters 1, 2")
            && message.contains("join it to the cluster again"),
        "{message}"
    );
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
        "400 concurrent batches traveled in {entries} entries"
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

/// ADR 0030, the snapshot policy: due by entries, the log bytes a sanity bound; deferred
/// while the commit queue is deeper than one entry, at most 30 s or twice the entries.
#[test]
fn a_due_snapshot_waits_for_a_deep_commit_queue_within_its_bound() {
    use tenko_store::raft::{SNAPSHOT_MAX_DEFERRAL, SnapshotDecision, snapshot_decision};
    let policy = SnapshotPolicy::default();
    assert_eq!(policy.every_entries, 10_000);
    assert_eq!(policy.every_log_bytes, 1024 * 1024 * 1024);
    let decide = |entries, bytes, queued, deferred| {
        snapshot_decision(&policy, entries, bytes, queued, 128, deferred)
    };
    assert_eq!(decide(9_999, 0, 0, None), SnapshotDecision::NotDue);
    // 600 entries of 82 KB: due under the old 64 MiB bound, not under this one.
    assert_eq!(decide(600, 600 * 82_000, 0, None), SnapshotDecision::NotDue);
    assert_eq!(decide(10_000, 0, 0, None), SnapshotDecision::Build);
    assert_eq!(decide(10, 1 << 30, 0, None), SnapshotDecision::Build);
    assert_eq!(decide(10_000, 0, 128, None), SnapshotDecision::Build);
    assert_eq!(decide(10_000, 0, 129, None), SnapshotDecision::Defer);
    assert_eq!(
        decide(10_000, 0, 500, Some(Duration::from_secs(29))),
        SnapshotDecision::Defer
    );
    assert_eq!(
        decide(10_000, 0, 500, Some(SNAPSHOT_MAX_DEFERRAL)),
        SnapshotDecision::Build
    );
    assert_eq!(decide(20_000, 0, 500, None), SnapshotDecision::Build);
}

/// ADR 0030: a snapshot built while commits keep coming never stalls them: its build reads
/// an MVCC view beside the apply path. Every commit of a steady load through several builds
/// completes within the bound. The builds are due by entries, so how many a minute brings
/// depends on the host's commit rate, which the product does not promise: a snapshot every
/// 100 entries needs about 300 entries for three, a fifth of a minute at the 15 entries
/// per second a loaded four-core CI runner made (2026-11-08); the minute is a guard against
/// a hang, not the measure. nextest gives the test four threads (`.config/nextest.toml`),
/// the runtime's workers, so the stall bound is not measured on a machine other tests
/// have taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshots_built_under_load_do_not_stall_the_commits() {
    let dir = TestDir::new("snapshot-load");
    let mut cfg = config(dir.path());
    cfg.snapshot = SnapshotPolicy {
        every_entries: 100,
        every_log_bytes: u64::MAX,
        keep_entries: 50,
    };
    let store = RaftStore::open(cfg).await.expect("open");
    // A state worth copying: 20,000 rows of 200 bytes.
    for chunk in 0..20_u64 {
        let mut b = batch();
        for n in 0..1_000 {
            b.put(ROWS, key(100_000 + chunk * 1_000 + n), vec![3_u8; 200]);
        }
        store.propose(b).await.expect("commit");
    }
    let before = store.engine_stats();
    let mut slowest = Duration::ZERO;
    let started = Instant::now();
    let mut n = 0_u64;
    while store.engine_stats().snapshots_built < before.snapshots_built + 3
        && started.elapsed() < Duration::from_secs(60)
    {
        let mut tasks = Vec::new();
        for _ in 0..16 {
            n += 1;
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                let at = Instant::now();
                put(&store, n, "v").await;
                at.elapsed()
            }));
        }
        for task in tasks {
            slowest = slowest.max(task.await.expect("task"));
        }
    }
    let after = store.engine_stats();
    let built = after.snapshots_built - before.snapshots_built;
    let entries = after.entries_proposed - before.entries_proposed;
    assert!(
        built >= 3,
        "{built} snapshots in {:?} of commits ({entries} entries)",
        started.elapsed()
    );
    assert!(
        slowest < Duration::from_millis(1_500),
        "a commit took {slowest:?} while snapshots were built"
    );
    store.shutdown().await.expect("shutdown");
}

/// ADR 0030, the group commit's bound: a lone batch at idle travels in an entry of its own
/// at once, concurrent batches share entries, and no entry carries more than the default
/// bound of 128 batches or 64 KiB.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn group_commit_never_delays_a_lone_batch_and_keeps_entries_within_the_bound() {
    let cfg = config(Path::new("unused"));
    assert_eq!(cfg.coalescer, tenko_store::raft::ENTRY_BOUND);
    let store = RaftStore::open_temp(cfg).await.expect("open");
    let before = store.engine_stats();
    let started = Instant::now();
    put(&store, 1, "v").await;
    let alone = started.elapsed();
    let stats = store.engine_stats();
    assert_eq!(stats.entries_proposed - before.entries_proposed, 1);
    assert_eq!(stats.batches_proposed - before.batches_proposed, 1);
    assert!(
        alone < Duration::from_secs(1),
        "a lone batch took {alone:?}"
    );

    let before = store.engine_stats();
    let mut tasks = Vec::new();
    for n in 0..2_000_u64 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let mut b = batch();
            b.put(ROWS, key(10 + n), vec![7_u8; 200]);
            store.propose(b).await.expect("commit")
        }));
    }
    for task in tasks {
        task.await.expect("task");
    }
    let stats = store.engine_stats();
    let entries = stats.entries_proposed - before.entries_proposed;
    let batches = stats.batches_proposed - before.batches_proposed;
    let bytes = stats.log_appended_bytes - before.log_appended_bytes;
    assert_eq!(batches, 2_000);
    assert!(
        entries < batches / 4,
        "2,000 batches traveled in {entries} entries"
    );
    assert!(
        entries * 128 >= batches,
        "{batches} batches in {entries} entries: more than 128 in one"
    );
    // Each entry within 64 KiB of batches plus its encoding.
    assert!(
        bytes / entries <= 80 * 1024,
        "{} bytes per entry",
        bytes / entries
    );
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
    wait_until_async("a snapshot and a purge by policy", async || {
        let purged = store
            .raft()
            .metrics()
            .borrow()
            .purged
            .map_or(0, |log_id| log_id.index);
        store.engine_stats().snapshots_built >= 1 && purged > 100
    })
    .await;
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

async fn wait_for_installs(store: &RaftStore, installs: u64) {
    wait_until_async(
        &format!("the node to install snapshot {installs} (not catch up from the log)"),
        async || store.engine_stats().snapshots_installed >= installs,
    )
    .await;
}

async fn wait_for_revision(store: &RaftStore, revision: Revision) {
    wait_until_async_within(
        "the node to catch up",
        Duration::from_secs(60),
        async || store.status().revision >= revision,
    )
    .await;
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
    wait_until_async("the leader to purge its log", async || {
        leader.raft().metrics().borrow().purged >= snapshot
    })
    .await;

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
    // The revision becomes visible a moment before the engine counts the install, so wait
    // for the counter instead of reading it at once; the deadline turns a learner that
    // caught up from the log instead into a failure with a message.
    wait_for_installs(&follower, 1).await;
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
    let new_leader = wait_until_async("a new leader to be elected", async || {
        nodes[1..]
            .iter()
            .find(|node| node.status().role == StoreRole::Leader)
            .cloned()
    })
    .await;
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

/// A fenced store (the cluster recovery) refuses every write, ends its leadership, reports
/// the fence as its quorum state and keeps serving reads; a later, weaker fence does not
/// replace a stricter one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fenced_store_refuses_writes_and_keeps_reads() {
    use tenko_store::{FenceReason, QuorumState};

    let store = RaftStore::open_temp(config(Path::new("unused")))
        .await
        .expect("open");
    let before = put(&store, 1, "kept").await;
    assert!(
        store.leadership().borrow().is_some(),
        "a single voter leads"
    );

    store.fence(FenceReason::Conflict).await;
    store.fence(FenceReason::Superseded).await;
    store.fence(FenceReason::MajorityAlive).await;
    assert_eq!(store.fenced(), Some(FenceReason::Superseded));
    assert!(
        store.leadership().borrow().is_none(),
        "the leadership ended"
    );
    match store.status().quorum {
        QuorumState::Fenced {
            reason, applied, ..
        } => {
            assert_eq!(reason, FenceReason::Superseded);
            assert_eq!(applied, before);
        }
        other => panic!("not fenced: {other:?}"),
    }
    assert!(!store.status().quorum.accepts_writes());

    let mut write = batch();
    write.put(ROWS, key(2), Bytes::from_static(b"refused"));
    let refused = store
        .propose(write)
        .await
        .expect_err("a fenced store writes nothing");
    assert!(matches!(refused, StoreError::NoQuorum), "{refused:?}");
    let view = store
        .read(ReadConsistency::Local)
        .await
        .expect("a local read");
    assert_eq!(view.revision(), before);
    assert_eq!(
        rows(view.as_ref()).get(&key(1)),
        Some(&Bytes::from_static(b"kept"))
    );
}
