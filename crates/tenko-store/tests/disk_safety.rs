//! The Raft store on a disk that runs short of room: a snapshot file that cannot be written
//! leaves the store running; a Raft core that stops answers `sys.store.stopped` and asks for
//! a restart only when a start cures it and fits; the disk guard takes only what frees space
//! below its margin, and below its reserve down to a floor; a replay of a committed write
//! is answered without a proposal; and the state file is compacted once after the prunes.
//!
//! The free space comes from the test hook `FREE_BYTES` (a byte count in a file of the data
//! directory, `tenko_store::test_hooks`), so no disk is filled; `FAIL_LOG` fails the log
//! writes and `FAIL_STATE` the applies.

use std::{fs, path::PathBuf, time::Duration};

use bytes::Bytes;
use tenko_core::{
    Coded, IdempotencyKey, Principal, SystemComponent, TableName, Timestamp,
    codec::encode_key,
    testing::{wait_until_async, wait_until_async_within},
};
use tenko_store::{
    Pressure, SignIn, Store, StoreError, WriteBatch,
    raft::{RaftStore, RaftStoreConfig, fixture::InProcessCluster, network::ForwardError},
    test_hooks::{FAIL_CHECKPOINT, FAIL_LOG, FAIL_STATE, FREE_BYTES},
    testing::ConformanceConfig,
};

const ROWS: TableName = TableName::from_static("ipam.disk_safety_rows");
/// The free space below which nothing passes (`raft::disk::FLOOR`).
const FLOOR: u64 = 128 * 1024 * 1024;

fn batch() -> WriteBatch {
    let at = Timestamp::from_unix_nanos(1_791_547_200_000_000_000).expect("timestamp");
    WriteBatch::new(Principal::system(SystemComponent::Ipam), at)
}

fn put(n: u64) -> WriteBatch {
    let mut batch = batch();
    batch.put(ROWS, encode_key(&n), Bytes::from_static(b"value"));
    batch
}

fn delete(n: u64) -> WriteBatch {
    let mut batch = batch();
    batch.delete(ROWS, encode_key(&n));
    batch
}

async fn single() -> RaftStore {
    let mut config = RaftStoreConfig::new("unused");
    config.fsync_probe_samples = 0;
    RaftStore::open_temp(config).await.expect("open")
}

fn data_file(store: &RaftStore, name: &str) -> PathBuf {
    store.config().data_dir.join(name)
}

/// Makes the store see `free` bytes of free space, and waits until it shows `pressure`.
async fn free_space(store: &RaftStore, free: u64, pressure: Pressure) {
    fs::write(data_file(store, FREE_BYTES), free.to_string()).expect("the free space");
    wait_until_async("the store reads its free space", async || {
        let safety = store.safety().expect("safety");
        safety.free_bytes == free && safety.pressure == pressure
    })
    .await;
}

/// Free space halfway between the reserve and the margin (the margin is twice the reserve,
/// so a few rows more of data do not move it across a line).
fn inside_the_margin(store: &RaftStore) -> u64 {
    store.safety().expect("safety").reserve_bytes / 2 * 3
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_snapshot_whose_file_cannot_be_written_leaves_the_store_running_and_is_built_again() {
    let store = single().await;
    store.propose(put(1)).await.expect("a write");
    // A file where the snapshot directory was: no snapshot file can be written.
    let snapshots = data_file(&store, "snapshots");
    fs::remove_dir_all(&snapshots).expect("the snapshot directory");
    fs::write(&snapshots, b"").expect("a file in its place");
    store.raft().trigger().snapshot().await.expect("triggered");
    wait_until_async("the failed snapshot is reported", async || {
        store.safety().expect("safety").snapshot_failed
    })
    .await;
    store
        .propose(put(2))
        .await
        .expect("the store goes on committing");
    let metrics = store.raft().metrics().borrow().clone();
    assert_eq!(metrics.snapshot, None, "no snapshot was taken");
    assert_eq!(metrics.purged, None, "the log keeps its entries");

    fs::remove_file(&snapshots).expect("the file");
    fs::create_dir(&snapshots).expect("the directory again");
    store
        .snapshot_now()
        .await
        .expect("a snapshot once the file can be written");
    assert!(!store.safety().expect("safety").snapshot_failed);
    store.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_core_stopped_on_a_full_disk_answers_its_code_and_restarts_once_a_start_fits() {
    let store = single().await;
    // The hook fails the log writes with the OS error of a full disk.
    fs::write(data_file(&store, FAIL_LOG), b"").expect("fail the log writes");
    let failed = store.propose(put(1)).await;
    assert!(matches!(failed, Err(StoreError::Stopped)), "{failed:?}");
    let refused = store.propose(put(2)).await.expect_err("stopped");
    assert_eq!(refused.code(), StoreError::STOPPED);
    assert_eq!(refused.http_status(), 503);
    let safety = store.safety().expect("safety");
    assert!(safety.restartable, "a full disk: {safety:?}");
    // The stopped store goes on reading its disk, which decides the restart
    // (`StoreSafety::restart_due`, whose minute its unit test covers).
    free_space(&store, 0, Pressure::Reserve).await;
    assert!(
        !store.safety().expect("safety").restart_due(),
        "a start would not fit"
    );
    free_space(&store, u64::MAX, Pressure::Normal).await;
    fs::remove_file(data_file(&store, FAIL_LOG)).expect("heal");
    let _ = store.shutdown().await;
}

/// A write the disk refuses inside an apply is not a batch this binary cannot read: the core
/// stops and the store notes it. Its cause names no full disk, so a start would not cure it
/// and the process stays up, below the margin too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_write_inside_an_apply_is_noted_as_a_stop() {
    let store = single().await;
    free_space(&store, inside_the_margin(&store), Pressure::Margin).await;
    fs::write(data_file(&store, FAIL_STATE), b"").expect("fail the applies");
    let failed = store.propose(delete(1)).await;
    assert!(matches!(failed, Err(StoreError::Stopped)), "{failed:?}");
    let safety = store.safety().expect("safety");
    assert!(
        safety
            .stopped
            .as_deref()
            .is_some_and(|cause| cause.contains("Previous I/O error")),
        "{safety:?}"
    );
    assert!(
        store.status().stopped.is_none(),
        "not an entry this binary cannot apply"
    );
    assert!(!safety.restartable, "no full disk named: {safety:?}");
    free_space(&store, u64::MAX, Pressure::Normal).await;
    assert!(!store.safety().expect("safety").restart_due());
    fs::remove_file(data_file(&store, FAIL_STATE)).expect("heal");
    let _ = store.shutdown().await;
}

/// A full disk the periodic checkpoint met first: redb then answers "Previous I/O error" to
/// every write, which names no code, and the stop is taken as the full disk it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_after_a_checkpoint_on_a_full_disk_is_a_full_disk() {
    let store = single().await;
    store
        .propose(put(1))
        .await
        .expect("a write for the checkpoint");
    let hook = data_file(&store, FAIL_CHECKPOINT);
    fs::write(&hook, b"").expect("fail the next checkpoint");
    wait_until_async("the checkpoint failed", async || !hook.exists()).await;
    fs::write(data_file(&store, FAIL_STATE), b"").expect("fail the applies");
    let failed = store.propose(put(2)).await;
    assert!(matches!(failed, Err(StoreError::Stopped)), "{failed:?}");
    let safety = store.safety().expect("safety");
    assert!(safety.restartable, "{safety:?}");
    assert!(
        safety
            .stopped
            .as_deref()
            .is_some_and(|cause| cause.contains("after a checkpoint failed")),
        "{safety:?}"
    );
    fs::remove_file(data_file(&store, FAIL_STATE)).expect("heal");
    let _ = store.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_only_what_frees_space_passes() {
    let store = single().await;
    store.propose(put(1)).await.expect("a write");
    let mut pressure = store.pressure();
    assert_eq!(*pressure.borrow_and_update(), Pressure::Normal);

    free_space(&store, inside_the_margin(&store), Pressure::Margin).await;
    assert_eq!(*pressure.borrow_and_update(), Pressure::Margin, "the watch");
    let refused = store.propose(put(3)).await.expect_err("a new row");
    assert_eq!(refused.code(), StoreError::DISK_RESERVE);
    assert_eq!(refused.http_status(), 507);
    store
        .propose(delete(1))
        .await
        .expect("a delete frees space");

    free_space(&store, u64::MAX, Pressure::Normal).await;
    assert_eq!(*pressure.borrow_and_update(), Pressure::Normal);
    store.propose(put(3)).await.expect("room again");
    store.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_reserve_a_delete_passes_down_to_the_floor_and_the_snapshot_runs() {
    let store = single().await;
    store.propose(put(1)).await.expect("a write");
    store.propose(put(2)).await.expect("a write");
    let mut rows = batch();
    for n in 0..5_000_u64 {
        rows.put(ROWS, encode_key(&(1_000 + n)), Bytes::from_static(b"value"));
    }
    store.propose(rows).await.expect("rows to prune");
    free_space(&store, FLOOR + 1024 * 1024, Pressure::Reserve).await;
    let refused = store.propose(put(3)).await.expect_err("a new row");
    assert_eq!(refused.code(), StoreError::DISK_RESERVE);
    store
        .propose(delete(1))
        .await
        .expect("a prune passes below the reserve");
    store
        .snapshot_now()
        .await
        .expect("the store's own snapshot runs");

    // A prune batch above 256 KiB is answered with its size and the limit: the caller
    // splits it and retries.
    let mut large = batch();
    for n in 0..20_000_u64 {
        large.delete(ROWS, encode_key(&(1_000 + n)));
    }
    let size = large.payload_size();
    let refused = store
        .propose(large)
        .await
        .expect_err("too large below the reserve");
    assert_eq!(refused.code(), StoreError::BATCH_TOO_LARGE);
    assert_eq!(refused.http_status(), 413);
    assert!(
        matches!(refused, StoreError::BatchTooLarge { size: named, limit: 262_144 } if named == size),
        "{refused:?}"
    );
    let mut half = batch();
    for n in 0..5_000_u64 {
        half.delete(ROWS, encode_key(&(1_000 + n)));
    }
    assert!(half.payload_size() <= 262_144);
    store.propose(half).await.expect("a batch within the limit");
    // Deletes of rows that are not there free nothing: refused below the reserve.
    for round in 0..200_u64 {
        let mut absent = batch();
        for n in 0..10_u64 {
            absent.delete(ROWS, encode_key(&(100_000 + round * 10 + n)));
        }
        let refused = store.propose(absent).await.expect_err("frees nothing");
        assert_eq!(refused.code(), StoreError::DISK_RESERVE);
    }

    free_space(&store, FLOOR - 1, Pressure::Reserve).await;
    let refused = store.propose(delete(2)).await.expect_err("below the floor");
    assert!(
        matches!(refused, StoreError::DiskReserve { needed, .. } if needed == FLOOR),
        "{refused:?}"
    );
    store.shutdown().await.expect("shutdown");
}

/// A retry of a write that committed already is answered from its idempotency record, at
/// any pressure, and appends nothing to the log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replay_of_a_committed_write_appends_nothing() {
    let store = single().await;
    let mut keyed = put(9);
    keyed.idempotency = Some(IdempotencyKey::new("disk-safety-9").expect("a key"));
    let first = store.propose(keyed.clone()).await.expect("the keyed write");
    free_space(&store, FLOOR + 1024 * 1024, Pressure::Reserve).await;
    let last = store.raft().metrics().borrow().last_log_index;
    let replayed = store.propose(keyed).await.expect("its retry");
    assert!(replayed.replayed, "answered from the idempotency record");
    assert_eq!(replayed.revision, first.revision);
    assert_eq!(
        store.raft().metrics().borrow().last_log_index,
        last,
        "nothing was appended"
    );
    store.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_state_file_is_compacted_once_after_the_prunes_go_quiet() {
    let store = single().await;
    store.propose(put(1)).await.expect("a write");
    assert_eq!(store.engine_stats().reseeds_in_place, 0);
    let snapshots = store.engine_stats().snapshots_built;
    free_space(&store, inside_the_margin(&store), Pressure::Margin).await;
    // The prunes run first: a delete keeps the window open.
    store.propose(delete(1)).await.expect("a prune");
    // The window ends 10 s after the last prune (`PRUNE_QUIET`).
    wait_until_async_within(
        "compacted once the prunes went quiet",
        Duration::from_secs(60),
        async || store.engine_stats().reseeds_in_place == 1,
    )
    .await;
    // test-lint: allow sleep the subject is that no second compaction follows in the window
    tokio::time::sleep(Duration::from_secs(11)).await;
    assert_eq!(store.engine_stats().reseeds_in_place, 1, "once an episode");
    assert_eq!(
        store.engine_stats().snapshots_built,
        snapshots,
        "no snapshot beside it"
    );
    assert!(!store.safety().expect("safety").compacting);
    store.shutdown().await.expect("shutdown");
}

/// A retry of a committed write that reaches the leader forwarded is answered from its
/// record there too, and appends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forwarded_replay_of_a_committed_write_appends_nothing() {
    let store = single().await;
    let mut keyed = put(9);
    keyed.idempotency = Some(IdempotencyKey::new("disk-safety-forwarded").expect("a key"));
    let encoded = tenko_core::codec::to_cbor(&keyed).expect("encoded");
    let first = store
        .accept_forwarded(encoded.clone(), None)
        .await
        .expect("the forwarded write");
    free_space(&store, inside_the_margin(&store), Pressure::Margin).await;
    let last = store.raft().metrics().borrow().last_log_index;
    let replayed = store
        .accept_forwarded(encoded, None)
        .await
        .expect("its forwarded retry");
    assert!(replayed.replayed, "answered from the idempotency record");
    assert_eq!(replayed.revision, first.revision);
    assert_eq!(
        store.raft().metrics().borrow().last_log_index,
        last,
        "nothing was appended"
    );
    store.shutdown().await.expect("shutdown");
}

/// A sign-in's batch of about 1 KiB, marked as `kind`.
#[allow(
    clippy::disallowed_methods,
    reason = "the store's own test of the marked batches"
)]
fn sign_in(kind: SignIn, n: u64) -> WriteBatch {
    let principal = Principal::system(SystemComponent::Auth);
    let at = Timestamp::from_unix_nanos(1_791_547_200_000_000_000).expect("timestamp");
    let mut batch = match kind {
        SignIn::Completed => WriteBatch::completed_sign_in(principal, at),
        SignIn::Failed => WriteBatch::failed_sign_in(principal, at),
    };
    batch.put(ROWS, encode_key(&n), Bytes::from(vec![0_u8; 1024]));
    batch
}

/// A follower's sign-in reaches its leader with its mark, beside the batch: below the
/// leader's margin the leader takes it within its own budgets, which its local sign-ins
/// spend too, and refuses an unmarked batch that grows the store, as it refuses a sign-in
/// from an older peer that sends no mark.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forwarded_sign_in_keeps_its_mark_below_the_leaders_margin() {
    let cluster = InProcessCluster::start_with(3, &ConformanceConfig::default(), |config| {
        config.fsync_probe_samples = 0;
    })
    .await;
    let leader = cluster.wait_for_leader().await;
    let follower = cluster.a_follower().await;
    free_space(&leader, inside_the_margin(&leader), Pressure::Margin).await;

    follower
        .propose(sign_in(SignIn::Completed, 1))
        .await
        .expect("a completed sign-in forwarded below the leader's margin");
    let refused = follower.propose(put(2)).await.expect_err("unmarked growth");
    assert_eq!(refused.code(), StoreError::DISK_RESERVE);
    let older = leader
        .accept_forwarded(
            tenko_core::codec::to_cbor(&sign_in(SignIn::Completed, 3)).expect("encoded"),
            None,
        )
        .await
        .expect_err("a sign-in from a peer that sends no mark");
    assert!(
        matches!(older, ForwardError::Store(StoreError::DiskReserve { .. })),
        "{older:?}"
    );
    assert!(older.to_string().contains("12.12"), "{older}");

    // Failures forwarded spend the leader's budget of failures, the one its own spend.
    let mut passed = 0_u64;
    while follower
        .propose(sign_in(SignIn::Failed, 100 + passed))
        .await
        .is_ok()
    {
        passed += 1;
        assert!(passed < 1_000, "the budget of failures never ended");
    }
    assert!(passed > 10, "{passed} failures passed");
    let spent = leader
        .propose(sign_in(SignIn::Failed, 5_000))
        .await
        .expect_err("the leader's own failure, past the shared budget");
    assert_eq!(spent.code(), StoreError::DISK_RESERVE);
    leader
        .propose(sign_in(SignIn::Completed, 5_001))
        .await
        .expect("completed sign-ins keep their own budget");
    cluster.shutdown().await;
}
