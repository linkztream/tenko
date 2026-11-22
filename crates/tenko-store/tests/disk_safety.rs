//! The Raft store on a disk that runs short of room: a snapshot file that cannot be written
//! leaves the store running, a Raft core that stops answers `sys.store.stopped` and asks for
//! a restart only once a start fits, and the disk guard refuses what does not free space
//! below its margin, everything below its reserve, and compacts the state file once the
//! prunes are over.
//!
//! The free space comes from the test hook `FREE_BYTES` (a byte count in a file of the data
//! directory, `tenko_store::test_hooks`), so no disk is filled; `FAIL_LOG` fails the log
//! writes.

use std::{fs, path::PathBuf, time::Duration};

use bytes::Bytes;
use tenko_core::{
    Coded, IdempotencyKey, Principal, SystemComponent, TableName, Timestamp,
    codec::encode_key,
    testing::{wait_until_async, wait_until_async_within},
};
use tenko_store::{
    Pressure, Store, StoreError, WriteBatch,
    raft::{RaftStore, RaftStoreConfig},
    test_hooks::{FAIL_LOG, FREE_BYTES},
};

const ROWS: TableName = TableName::from_static("ipam.disk_safety_rows");

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
        store.safety().expect("safety").pressure == pressure
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
async fn a_stopped_core_answers_its_code_and_asks_for_a_restart_once_a_start_fits() {
    let store = single().await;
    fs::write(data_file(&store, FAIL_LOG), b"").expect("fail the log writes");
    let failed = store.propose(put(1)).await;
    assert!(matches!(failed, Err(StoreError::Stopped)), "{failed:?}");
    assert!(store.safety().expect("safety").stopped.is_some());
    let refused = store.propose(put(2)).await.expect_err("stopped");
    assert_eq!(refused.code(), StoreError::STOPPED);
    assert_eq!(refused.http_status(), 503);

    // The stopped store goes on reading its disk, which decides the restart
    // (`StoreSafety::restart_due`, whose rule its unit test covers).
    free_space(&store, 0, Pressure::Reserve).await;
    assert!(
        !store.safety().expect("safety").restart_due(),
        "a start would not fit"
    );
    free_space(&store, u64::MAX, Pressure::Normal).await;
    fs::remove_file(data_file(&store, FAIL_LOG)).expect("heal");
    let _ = store.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_only_what_frees_space_passes_and_below_the_reserve_nothing() {
    let store = single().await;
    store.propose(put(1)).await.expect("a write");
    store.propose(put(2)).await.expect("a write");
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

    // A retry of a write that committed already passes: the apply answers it from its
    // idempotency record and writes nothing.
    let mut keyed = put(9);
    keyed.idempotency = Some(IdempotencyKey::new("disk-safety-9").expect("a key"));
    let first = store.propose(keyed.clone()).await;
    assert!(
        matches!(first, Err(StoreError::DiskReserve { .. })),
        "a new keyed row is refused: {first:?}"
    );

    free_space(&store, 0, Pressure::Reserve).await;
    assert_eq!(*pressure.borrow_and_update(), Pressure::Reserve);
    let refused = store
        .propose(delete(2))
        .await
        .expect_err("below the reserve");
    assert_eq!(refused.code(), StoreError::DISK_RESERVE);
    store
        .snapshot_now()
        .await
        .expect("the store's own snapshot runs");

    free_space(&store, u64::MAX, Pressure::Normal).await;
    assert_eq!(*pressure.borrow_and_update(), Pressure::Normal);
    store.propose(put(3)).await.expect("room again");
    store.propose(keyed.clone()).await.expect("the keyed write");
    free_space(&store, inside_the_margin(&store), Pressure::Margin).await;
    let replayed = store.propose(keyed).await.expect("its retry");
    assert!(replayed.replayed, "answered from the idempotency record");
    store.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_state_file_is_compacted_once_after_the_prunes_go_quiet() {
    let store = single().await;
    store.propose(put(1)).await.expect("a write");
    assert_eq!(store.engine_stats().reseeds_in_place, 0);
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
    assert!(!store.safety().expect("safety").compacting);
    store.shutdown().await.expect("shutdown");
}
