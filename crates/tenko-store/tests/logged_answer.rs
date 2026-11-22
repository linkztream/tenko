//! `Store::propose_logged` on the Raft store: the signal fires at the Raft commit of the
//! batch's entry, before the apply, on one voter and on three; never for an entry that
//! does not commit (a failed log write, an entry another leader replaced); and for a batch
//! the apply can refuse (preconditions, an idempotency key) only with an `Ok` result.
//!
//! The store's test hooks act through files in a store's data directory
//! (`tenko_store::test_hooks`): `HOLD_APPLY` holds its applies, `FAIL_LOG` fails its log
//! writes. The in-process network loses the answers to one node (`set_deaf`) or cuts it
//! off (`set_isolated`). The kill between the signal and the apply runs in a child process
//! of this test binary, which the test kills and whose store it opens again.

use std::{
    fs,
    io::{BufRead as _, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use bytes::Bytes;
use tenko_core::{
    CounterKey, IdempotencyKey, NodeId, Principal, SystemComponent, TableName, Timestamp,
    codec::encode_key,
    testing::{TempDir, wait_until_async},
};
use tenko_store::{
    Committed, ReadConsistency, Store, StoreError, WriteBatch,
    raft::{RaftStore, RaftStoreConfig, fixture::InProcessCluster},
    test_hooks::{FAIL_LOG, HOLD_APPLY},
    testing::ConformanceConfig,
};
use tokio::{
    sync::oneshot::{self, Receiver, error::TryRecvError},
    task::JoinHandle,
};

const ROWS: TableName = TableName::from_static("ipam.logged_rows");
const COUNTER: CounterKey = CounterKey::new("ipam.logged_counter");
/// A guard against a hang only: every step here takes milliseconds.
const WAIT: Duration = Duration::from_secs(30);

fn put(n: u64) -> WriteBatch {
    let at = Timestamp::from_unix_nanos(1_791_547_200_000_000_000).expect("timestamp");
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Ipam), at);
    batch.put(ROWS, encode_key(&n), Bytes::from_static(b"v"));
    batch
}

/// A batch whose apply checks that the counter is `expect` (it stays 0 here).
fn guarded(n: u64, expect: u64) -> WriteBatch {
    let mut batch = put(n);
    batch.expect_counter(COUNTER, expect);
    batch
}

async fn single() -> RaftStore {
    let mut config = RaftStoreConfig::new("unused");
    config.fsync_probe_samples = 0;
    // Room beyond the four entries a test holds unapplied.
    config.coalescer.max_inflight_entries = 8;
    RaftStore::open_temp(config).await.expect("open")
}

fn last_log_index(store: &RaftStore) -> u64 {
    store.raft().metrics().borrow().last_log_index.unwrap_or(0)
}

/// Proposes `batch` with its signal on a task.
fn propose(
    store: &RaftStore,
    batch: WriteBatch,
) -> (JoinHandle<Result<Committed, StoreError>>, Receiver<()>) {
    let (logged, signal) = oneshot::channel();
    let store = store.clone();
    let task = tokio::spawn(async move { store.propose_logged(batch, logged).await });
    (task, signal)
}

/// As [`propose`], once the batch's entry is in this member's log.
async fn propose_appended(
    store: &RaftStore,
    batch: WriteBatch,
) -> (JoinHandle<Result<Committed, StoreError>>, Receiver<()>) {
    let before = last_log_index(store);
    let proposed = propose(store, batch);
    wait_until_async("the entry is appended", async || {
        last_log_index(store) > before
    })
    .await;
    proposed
}

async fn fired(signal: Receiver<()>) -> bool {
    tokio::time::timeout(WAIT, signal)
        .await
        .expect("the signal fires or closes")
        .is_ok()
}

async fn result(task: JoinHandle<Result<Committed, StoreError>>) -> Result<Committed, StoreError> {
    tokio::time::timeout(WAIT, task)
        .await
        .expect("an answer")
        .expect("the proposing task")
}

/// A test hook's file, removed when dropped: also when a test fails, since a held apply
/// would keep the runtime from closing.
struct Held(PathBuf);

impl Drop for Held {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn hold_applies(store: &RaftStore) -> Held {
    let path = store.config().data_dir.join(HOLD_APPLY);
    fs::write(&path, b"").expect("hold the applies");
    Held(path)
}

/// The member other than `not` that took office.
async fn other_leader(cluster: &InProcessCluster, not: NodeId) -> RaftStore {
    wait_until_async("another member takes office", async || {
        cluster.members().iter().find(|member| {
            member.node_id() != not
                && member
                    .leadership()
                    .borrow()
                    .is_some_and(|seen| seen.is_self)
        })
    })
    .await
    .clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_signal_fires_at_the_commit_while_the_apply_is_held() {
    let store = single().await;
    let held = hold_applies(&store);
    let (task, signal) = propose(&store, put(1));
    assert!(fired(signal).await, "the commit fires the signal");
    assert!(!task.is_finished(), "no result before the apply");
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    assert!(
        view.get(&ROWS, &encode_key(&1_u64)).expect("get").is_none(),
        "not applied yet"
    );
    drop((view, held));
    result(task).await.expect("committed");
    store.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_log_write_fires_nothing() {
    let store = single().await;
    let fail = Held(store.config().data_dir.join(FAIL_LOG));
    fs::write(&fail.0, b"").expect("fail the log writes");
    let (task, signal) = propose(&store, put(1));
    let outcome = result(task).await;
    // The failed write stops Raft: the coalescer answers that the store shuts down.
    assert!(
        matches!(outcome, Err(StoreError::ShuttingDown)),
        "{outcome:?}"
    );
    assert!(!fired(signal).await, "dropped unfired");
    drop(fail);
    let _ = store.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_the_apply_can_refuse_is_signaled_only_with_its_result() {
    let store = single().await;
    let held = hold_applies(&store);
    let mut holds = propose_appended(&store, guarded(1, 0)).await;
    let mut fails = propose_appended(&store, guarded(2, 5)).await;
    let mut keyed = put(3);
    keyed.idempotency = Some(IdempotencyKey::new("logged-3").expect("a key"));
    let mut keyed = propose_appended(&store, keyed).await;
    // A plain batch behind them: its signal shows that every entry before it committed.
    let (plain, plain_signal) = propose(&store, put(4));
    assert!(fired(plain_signal).await);
    for (_, signal) in [&mut holds, &mut fails, &mut keyed] {
        assert_eq!(
            signal.try_recv(),
            Err(TryRecvError::Empty),
            "committed, not signaled"
        );
    }
    drop(held);
    result(holds.0).await.expect("the precondition holds");
    assert!(fired(holds.1).await, "signaled with the result");
    let refused = result(fails.0).await;
    assert!(
        matches!(refused, Err(StoreError::PreconditionFailed(_))),
        "{refused:?}"
    );
    assert!(!fired(fails.1).await, "a refused batch is never signaled");
    result(keyed.0).await.expect("the keyed batch");
    assert!(fired(keyed.1).await);
    result(plain).await.expect("the plain batch");
    store.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_three_voters_the_signal_fires_at_the_quorum_commit_before_the_apply() {
    let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
    let leader = cluster.wait_for_leader().await;
    let held: Vec<Held> = cluster.members().iter().map(hold_applies).collect();
    let (task, signal) = propose(&leader, put(1));
    let (refused, refused_signal) = propose(&leader, guarded(2, 5));
    assert!(fired(signal).await, "the quorum's commit fires the signal");
    assert!(!task.is_finished(), "no result before the apply");
    drop(held);
    result(task).await.expect("committed");
    let refused = result(refused).await;
    assert!(
        matches!(refused, Err(StoreError::PreconditionFailed(_))),
        "{refused:?}"
    );
    assert!(
        !fired(refused_signal).await,
        "a refused batch is never signaled"
    );
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_a_new_leader_replaced_never_fires() {
    let cluster = InProcessCluster::start_with(3, &ConformanceConfig::default(), |config| {
        config.leader_wait = WAIT;
    })
    .await;
    let old = cluster.wait_for_leader().await;
    cluster.network().set_isolated(old.node_id().0, true);
    let (task, mut signal) = propose_appended(&old, put(1)).await;
    let new = other_leader(&cluster, old.node_id()).await;
    new.propose(put(2)).await.expect("the new leader writes");
    cluster.network().set_isolated(old.node_id().0, false);
    // The cut-off entry is truncated; the store forwards the batch to the new leader.
    result(task).await.expect("forwarded and committed");
    // Dropped, so it can never fire, also once this node leads again. The answer usually
    // drops it before the truncation would; the unit test of `truncate` in `raft::log`
    // covers the truncation itself.
    assert_eq!(
        signal.try_recv(),
        Err(TryRecvError::Closed),
        "dropped unfired"
    );
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_former_leaders_entry_the_new_leader_keeps_fires_on_the_follower_path() {
    let cluster = InProcessCluster::start_with(3, &ConformanceConfig::default(), |config| {
        config.leader_wait = WAIT;
    })
    .await;
    let old = cluster.wait_for_leader().await;
    let id = old.node_id().0;
    cluster.network().set_deaf(id, true);
    let (task, mut signal) = propose_appended(&old, put(1)).await;
    let index = last_log_index(&old);
    wait_until_async("the followers hold the entry", async || {
        cluster
            .members()
            .iter()
            .all(|member| last_log_index(member) >= index)
    })
    .await;
    assert_eq!(
        signal.try_recv(),
        Err(TryRecvError::Empty),
        "the leader never learned that a quorum holds it"
    );
    cluster.network().set_isolated(id, true);
    cluster.network().set_deaf(id, false);
    other_leader(&cluster, old.node_id()).await;
    cluster.network().set_isolated(id, false);
    assert!(fired(signal).await, "committed through the new leader");
    result(task).await.expect("committed");
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_forwarded_from_a_follower_is_signaled_with_its_ok() {
    let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
    let follower = cluster.a_follower().await;
    let (task, signal) = propose(&follower, put(1));
    result(task).await.expect("forwarded and committed");
    assert!(fired(signal).await, "an Ok comes with the signal");
    let view = follower.read(ReadConsistency::Local).await.expect("a view");
    assert!(
        view.get(&ROWS, &encode_key(&1_u64)).expect("get").is_some(),
        "readable on the follower at its result"
    );
    drop(view);
    cluster.shutdown().await;
}

const CHILD: &str = "TENKO_LOGGED_ANSWER_CHILD";
const SIGNALED: &str = "SIGNALED";

fn store_config(dir: &Path) -> RaftStoreConfig {
    let mut config = RaftStoreConfig::new(dir.join("data"));
    config.fsync_probe_samples = 0;
    config
}

/// The process is killed after the signal and before the apply: the next start applies the
/// write, although the `committed` value on disk may lag behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_signaled_before_a_kill_is_applied_after_the_restart() {
    let dir = TempDir::new("logged-kill");
    let mut child = Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "child_signaled_then_killed",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD, dir.path())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the child runs");
    let stdout = child.stdout.take().expect("its output");
    let signaled = tokio::task::spawn_blocking(move || {
        BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            // libtest prints the test's name on the same line.
            .any(|line| line.ends_with(SIGNALED))
    });
    let signaled = tokio::time::timeout(WAIT, signaled).await;
    child.kill().expect("kill the child");
    let _ = child.wait();
    assert!(
        matches!(signaled, Ok(Ok(true))),
        "the child printed its signal"
    );

    let data = store_config(dir.path()).data_dir;
    assert!(data.join(HOLD_APPLY).exists(), "killed with the apply held");
    fs::remove_file(data.join(HOLD_APPLY)).expect("release the applies");
    let store = RaftStore::open(store_config(dir.path()))
        .await
        .expect("the store opens again");
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    assert!(
        view.get(&ROWS, &encode_key(&1_u64)).expect("get").is_some(),
        "the signaled write is applied"
    );
    drop(view);
    store.shutdown().await.expect("shutdown");
}

#[test]
#[ignore = "the child process of a_write_signaled_before_a_kill_is_applied_after_the_restart; runner: crates/tenko-store/tests/logged_answer.rs"]
fn child_signaled_then_killed() {
    let Some(dir) = std::env::var_os(CHILD).map(PathBuf::from) else {
        // runner: crates/tenko-store/tests/logged_answer.rs (the parent test sets the variable)
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let store = RaftStore::open(store_config(&dir)).await.expect("open");
        fs::write(store.config().data_dir.join(HOLD_APPLY), b"").expect("hold the applies");
        let (task, signal) = propose(&store, put(1));
        assert!(fired(signal).await, "the commit fires the signal");
        println!("{SIGNALED}");
        // Killed here: the apply stays held. A parent that gave up never kills it, so it ends
        // by itself instead of keeping its files locked.
        let _ = tokio::time::timeout(Duration::from_secs(60), task).await;
        std::process::exit(1);
    });
}
