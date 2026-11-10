//! A cluster of Raft stores in one process (WP3.1a): write forwarding after a leader
//! change, the quorum state of isolated members, the hand-over of leadership under load,
//! membership changes, state digests and the guards of a store directory (node id, join
//! marker).

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use bytes::Bytes;
use tenko_core::{
    CounterKey, NodeId, Principal, Revision, SystemComponent, TableName, Timestamp,
    codec::encode_key,
};
use tenko_store::{
    QuorumState, ReadConsistency, ReadView, Store, StoreError, StoreRole, WriteBatch,
    raft::{RaftStore, RaftStoreConfig, fixture::InProcessCluster, is_joining, mark_joining},
    testing::ConformanceConfig,
};

const ROWS: TableName = TableName::from_static("ipam.raft_cluster_rows");
const COUNTER: CounterKey = CounterKey::new("ipam.raft_cluster_counter");
const WAIT: Duration = Duration::from_secs(30);

fn batch() -> WriteBatch {
    let at = Timestamp::from_unix_nanos(1_791_547_200_000_000_000).expect("timestamp");
    WriteBatch::new(Principal::system(SystemComponent::Ipam), at)
}

fn key(n: u64) -> Bytes {
    encode_key(&n)
}

async fn put(store: &RaftStore, n: u64, value: &str) -> Result<Revision, StoreError> {
    let mut b = batch();
    b.put(ROWS, key(n), Bytes::copy_from_slice(value.as_bytes()))
        .bump(COUNTER);
    store.propose(b).await.map(|committed| committed.revision)
}

fn value_of(view: &dyn ReadView, n: u64) -> Option<Bytes> {
    view.get(&ROWS, &key(n))
        .expect("get")
        .map(|versioned| versioned.value)
}

async fn wait_until(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Shorter isolation for the quorum tests.
fn quick(config: &mut RaftStoreConfig) {
    config.isolation_after = Duration::from_millis(600);
    config.leader_wait = Duration::from_secs(10);
}

/// A follower whose leader is cut off forwards its write to the leader the other two
/// elect: the first forward fails before anything was queued, so it goes to the new leader.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forwarded_write_follows_a_leader_change() {
    let cluster = InProcessCluster::start_with(3, &ConformanceConfig::default(), quick).await;
    let leader = cluster.wait_for_leader().await;
    let follower = cluster.a_follower().await;
    put(&follower, 1, "before").await.expect("forwarded write");

    cluster.network().set_isolated(leader.node_id().0, true);
    let revision = put(&follower, 2, "after the leader was cut off")
        .await
        .expect("the write reaches the new leader");
    let view = follower.read(ReadConsistency::Local).await.expect("view");
    assert!(
        view.revision() >= revision,
        "read-your-writes on the follower"
    );
    assert_eq!(
        value_of(view.as_ref(), 2).as_deref(),
        Some(b"after the leader was cut off".as_slice())
    );
    drop(view);
    // The cut-off leader still believes it leads; another member took office.
    let others: Vec<&RaftStore> = cluster
        .members()
        .iter()
        .filter(|member| member.node_id() != leader.node_id())
        .collect();
    wait_until("another member takes office", || {
        others.iter().any(|member| {
            member
                .leadership()
                .borrow()
                .is_some_and(|seen| seen.is_self)
        })
    })
    .await;

    // The old leader catches up once it is back, and a linearizable read there sees the
    // write it missed.
    cluster.network().set_isolated(leader.node_id().0, false);
    let read = leader
        .read(ReadConsistency::Linearizable)
        .await
        .expect("a linearizable read on the former leader");
    assert!(read.revision() >= revision);
    drop(read);
    cluster.shutdown().await;
}

/// With one voter of three down, a burst of linearizable reads on the leader goes through
/// the one follower left, a loaded one that answers one message at a time: the reads share
/// their leadership rounds instead of sending one heartbeat each, so the follower's queue
/// stays short and no read fails with `NoQuorum` while a quorum is up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn linearizable_reads_share_leadership_rounds_with_one_voter_down() {
    const READS: usize = 40;
    let cluster = InProcessCluster::start_with(3, &ConformanceConfig::default(), quick).await;
    let leader = cluster.wait_for_leader().await;
    let revision = put(&leader, 1, "before").await.expect("write");
    let followers: Vec<u64> = cluster
        .members()
        .iter()
        .map(|member| member.node_id().0)
        .filter(|id| *id != leader.node_id().0)
        .collect();
    cluster.network().set_isolated(followers[0], true);
    cluster
        .network()
        .set_service_time(followers[1], Some(Duration::from_millis(20)));
    let reads: Vec<_> = (0..READS)
        .map(|_| {
            let leader = leader.clone();
            tokio::spawn(async move {
                leader
                    .read(ReadConsistency::Linearizable)
                    .await
                    .map(|view| view.revision())
            })
        })
        .collect();
    let mut failed = Vec::new();
    for read in reads {
        match read.await.expect("a read task") {
            Ok(seen) => assert!(seen >= revision),
            Err(error) => failed.push(error),
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {READS} linearizable reads failed: {failed:?}",
        failed.len()
    );
    cluster.network().set_service_time(followers[1], None);
    cluster.network().set_isolated(followers[0], false);
    cluster.shutdown().await;
}

/// A leader cut off from both followers, with a burst of reads in flight and more arriving
/// while the others elect a new leader and commit, answers none of them: recent contact
/// with a quorum (the isolation threshold is far away here, so its quorum state still says
/// healthy) only lets a read wait for the next round, and every round fails, so every read
/// ends in `NoQuorum` or `Timeout` and none sees the old state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deposed_leader_answers_no_linearizable_read() {
    let cluster = InProcessCluster::start_with(3, &ConformanceConfig::default(), |config| {
        config.isolation_after = Duration::from_secs(60);
        config.read_wait = Duration::from_secs(2);
        config.leader_wait = Duration::from_secs(10);
    })
    .await;
    let leader = cluster.wait_for_leader().await;
    put(&leader, 1, "before").await.expect("write");
    let follower = cluster.a_follower().await;
    let read = |leader: RaftStore| {
        tokio::spawn(async move {
            leader
                .read(ReadConsistency::Linearizable)
                .await
                .map(|view| view.revision())
        })
    };
    cluster.network().set_isolated(leader.node_id().0, true);
    let mut reads: Vec<_> = (0..10).map(|_| read(leader.clone())).collect();
    let revision = put(&follower, 2, "after the cut")
        .await
        .expect("the others elect a leader and commit");
    reads.extend((0..10).map(|_| read(leader.clone())));
    assert!(
        matches!(*leader.quorum().borrow(), QuorumState::Healthy),
        "the cut-off leader still counts itself in contact"
    );
    for read in reads {
        match read.await.expect("a read task") {
            Ok(seen) => panic!(
                "a deposed leader answered a linearizable read at revision {seen} (the new leader committed {revision})"
            ),
            Err(error) => assert!(
                matches!(error, StoreError::NoQuorum | StoreError::Timeout),
                "{error:?}"
            ),
        }
    }
    cluster.network().set_isolated(leader.node_id().0, false);
    cluster.shutdown().await;
}

/// A cut-off follower and a cut-off leader report `Isolated` after the threshold, with the
/// revision they applied; a reconnected member is healthy again. The leader reports when
/// it last heard from each member.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cut_off_members_report_isolation_and_recover() {
    let cluster = InProcessCluster::start_with(3, &ConformanceConfig::default(), quick).await;
    let leader = cluster.wait_for_leader().await;
    let follower = cluster.a_follower().await;
    let applied = put(&leader, 1, "seen by all").await.expect("write");
    wait_until("the follower applies the write", || {
        follower.status().revision >= applied
    })
    .await;
    assert_eq!(follower.status().quorum, QuorumState::Healthy);
    assert_eq!(leader.status().quorum, QuorumState::Healthy);
    let members = leader.status().members;
    assert_eq!(members.len(), 3);
    assert!(
        members
            .iter()
            .all(|member| member.voter && member.last_contact_ms.is_some()),
        "{members:?}"
    );

    cluster.network().set_isolated(follower.node_id().0, true);
    let mut quorum = follower.quorum();
    let isolated = tokio::time::timeout(
        WAIT,
        quorum.wait_for(|state| matches!(state, QuorumState::Isolated { .. })),
    )
    .await
    .expect("the follower turns isolated")
    .expect("quorum channel");
    let QuorumState::Isolated {
        applied: at_isolation,
        ..
    } = *isolated
    else {
        unreachable!("matched above");
    };
    drop(isolated);
    assert!(at_isolation >= applied);
    assert!(!follower.status().quorum.accepts_writes());
    // The other two keep a quorum.
    assert!(leader.status().quorum.accepts_writes());
    cluster.network().set_isolated(follower.node_id().0, false);
    tokio::time::timeout(
        WAIT,
        quorum.wait_for(|state| *state == QuorumState::Healthy),
    )
    .await
    .expect("the follower recovers")
    .expect("quorum channel");

    // A leader without a quorum is isolated too (it keeps its role until it hears of a
    // higher term).
    let leader = cluster.wait_for_leader().await;
    let mut on_leader = leader.quorum();
    for member in cluster.members() {
        if member.node_id() != leader.node_id() {
            cluster.network().set_isolated(member.node_id().0, true);
        }
    }
    tokio::time::timeout(
        WAIT,
        on_leader.wait_for(|state| matches!(state, QuorumState::Isolated { .. })),
    )
    .await
    .expect("the leader turns isolated")
    .expect("quorum channel");
    for member in cluster.members() {
        cluster.network().set_isolated(member.node_id().0, false);
    }
    cluster.shutdown().await;
}

/// A hand-over of leadership while writes keep arriving on every member: every write
/// commits exactly once (the counter equals the number of writes) and leadership moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_under_load_loses_and_repeats_nothing() {
    let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
    let before = cluster.wait_for_leader().await;
    let writers: Vec<_> = (0..3_u64)
        .map(|writer| {
            let member = cluster.members()[usize::try_from(writer).expect("index")].clone();
            tokio::spawn(async move {
                for n in 0..40 {
                    put(&member, writer * 1_000 + n, "under load")
                        .await
                        .expect("every write commits");
                }
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let after = cluster.hand_over().await;
    assert_ne!(after.node_id(), before.node_id());
    for writer in writers {
        writer.await.expect("writer");
    }
    let view = after
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    assert_eq!(view.counter(&COUNTER).expect("counter"), 120);
    drop(view);
    assert_ne!(before.status().role, StoreRole::Leader);
    cluster.shutdown().await;
}

/// Every member computes the same digest at the same revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_agree_on_the_state_digest() {
    let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
    let leader = cluster.wait_for_leader().await;
    let mut last = Revision::ZERO;
    for n in 0..50 {
        last = put(&leader, n, &format!("row {n}")).await.expect("write");
    }
    let mut digests = Vec::new();
    for member in cluster.members() {
        digests.push(member.digest(Some(last)).await.expect("digest"));
    }
    assert!(digests.iter().all(|digest| digest.revision == last));
    assert!(
        digests.windows(2).all(|pair| pair[0] == pair[1]),
        "{digests:?}"
    );
    assert!(digests[0].entries >= 50);
    // A further write changes it.
    let next = put(&leader, 99, "changed").await.expect("write");
    let changed = leader.digest(Some(next)).await.expect("digest");
    assert_ne!(changed.sha256, digests[0].sha256);
    cluster.shutdown().await;
}

/// A dead voter is replaced in one joint change (the cluster never has two or four
/// voters); a learner can be removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_voter_is_replaced_in_one_change() {
    let cluster = InProcessCluster::start(4, &ConformanceConfig::default()).await;
    // Start from three voters and one learner: node 4 is demoted.
    let leader = cluster.wait_for_leader().await;
    let voters: BTreeSet<NodeId> = [NodeId(1), NodeId(2), NodeId(3)].into();
    let leader = if leader.node_id() == NodeId(4) {
        cluster.hand_over().await
    } else {
        leader
    };
    leader
        .set_voters(voters.clone(), true)
        .await
        .expect("node 4 becomes a learner");
    let membership = leader.membership();
    assert_eq!(membership.voters, voters);
    assert_eq!(membership.learners, [NodeId(4)].into());

    let dead = voters
        .iter()
        .copied()
        .find(|node| *node != leader.node_id())
        .expect("a voter that does not lead");
    cluster.network().set_isolated(dead.0, true);
    let replaced: BTreeSet<NodeId> = voters
        .iter()
        .copied()
        .filter(|node| *node != dead)
        .chain([NodeId(4)])
        .collect();
    leader
        .set_voters(replaced.clone(), false)
        .await
        .expect("replace the dead voter");
    let membership = leader.membership();
    assert_eq!(membership.voters, replaced);
    assert!(!membership.learners.contains(&dead));
    put(&leader, 1, "after the replacement")
        .await
        .expect("writes continue");

    // Back to three voters, then node 4 leaves as a learner.
    let others: BTreeSet<NodeId> = replaced
        .iter()
        .copied()
        .filter(|node| *node != NodeId(4))
        .collect();
    if leader.node_id() != NodeId(4) {
        leader
            .set_voters(others, true)
            .await
            .expect("demote node 4");
        leader
            .remove_learner(NodeId(4))
            .await
            .expect("remove the learner");
        assert!(!leader.membership().learners.contains(&NodeId(4)));
    }
    cluster.network().set_isolated(dead.0, false);
    cluster.shutdown().await;
}

/// A directory under the system temporary directory, removed on drop.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "tenko-raft-cluster-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(dir: &Path, node: u64) -> RaftStoreConfig {
    let mut config = RaftStoreConfig::new(dir);
    config.node_id = NodeId(node);
    config.fsync_probe_samples = 0;
    config
}

/// A store directory belongs to one node id; a directory prepared by `tenko cluster join`
/// is never initialized as a cluster of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_directory_keeps_its_node_id_and_its_join_marker() {
    let dir = TestDir::new("guards");
    let store = RaftStore::open(config(dir.path(), 1))
        .await
        .expect("open as node 1");
    put(&store, 1, "single").await.expect("write");
    store.shutdown().await.expect("shutdown");
    drop(store);
    let refused = RaftStore::open(config(dir.path(), 1001))
        .await
        .expect_err("another node id is refused");
    assert!(
        refused.to_string().contains("belongs to node 1"),
        "{refused}"
    );

    let joining = TestDir::new("joining");
    mark_joining(joining.path()).expect("marker");
    assert!(is_joining(joining.path()));
    let refused = RaftStore::open(config(joining.path(), 1001))
        .await
        .expect_err("a joining directory is not bootstrapped");
    assert!(refused.to_string().contains("joining"), "{refused}");
    let mut learner = config(joining.path(), 1001);
    learner.bootstrap = false;
    let store = RaftStore::open(learner).await.expect("open as a learner");
    assert_eq!(store.membership().voters, BTreeSet::new());
    store.shutdown().await.expect("shutdown");
}
