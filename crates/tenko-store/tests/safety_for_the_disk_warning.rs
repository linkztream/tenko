//! What the disk warning of the server (`tenko_api::host::disk_watch`) relies on from the
//! store's safety reading (`Store::safety`), owned by the warning:
//!
//! - the free space and the margin are read once the store runs, and the free space follows
//!   the file system (here the test hook `FREE_BYTES`), also on a stopped store;
//! - below the margin the pressure is never normal, and it is normal again only 10 percent
//!   above the margin, so free space minus the margin is the room before ordinary writes are
//!   refused;
//! - the reading waits on no work of the store: it answers while the applies are held and
//!   while the log writer is stalled;
//! - the flags of a compaction and a snapshot are down while neither runs.

use std::{fs, path::PathBuf};

use bytes::Bytes;
use tenko_core::{
    Principal, SystemComponent, TableName, Timestamp, codec::encode_key, testing::wait_until_async,
};
use tenko_store::{
    Pressure, Store, StoreError, StoreSafety, WriteBatch,
    raft::{RaftStore, RaftStoreConfig},
    test_hooks::{FAIL_LOG, FREE_BYTES, HOLD_APPLY, STALL_LOG},
};

const ROWS: TableName = TableName::from_static("ipam.disk_warning_rows");

fn put(n: u64) -> WriteBatch {
    let at = Timestamp::from_unix_nanos(1_791_547_200_000_000_000).expect("timestamp");
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Ipam), at);
    batch.put(ROWS, encode_key(&n), Bytes::from_static(b"value"));
    batch
}

async fn single() -> RaftStore {
    let mut config = RaftStoreConfig::new("unused");
    config.fsync_probe_samples = 0;
    RaftStore::open_temp(config).await.expect("open")
}

/// A test hook's file, removed when dropped (also when a test fails).
struct Hook(PathBuf);

impl Hook {
    fn set(store: &RaftStore, name: &str, content: &str) -> Self {
        let path = store.config().data_dir.join(name);
        fs::write(&path, content).expect("the hook");
        Self(path)
    }
}

impl Drop for Hook {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn safety(store: &RaftStore) -> StoreSafety {
    store.safety().expect("a Raft store has a safety reading")
}

/// Makes the store see `free` bytes and waits until its reading shows them.
async fn free_space(store: &RaftStore, free: u64) -> StoreSafety {
    fs::write(store.config().data_dir.join(FREE_BYTES), free.to_string()).expect("the free space");
    wait_until_async("the reading shows the free space", async || {
        Some(safety(store)).filter(|safety| safety.free_bytes == free)
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_free_space_and_the_margin_are_read_and_follow_the_disk() {
    let store = single().await;
    let margin = wait_until_async("the first reading", async || {
        Some(safety(&store).margin_bytes).filter(|margin| *margin > 0)
    })
    .await;
    free_space(&store, margin * 3).await;
    free_space(&store, margin * 4).await;
    store.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_the_pressure_is_never_normal_until_ten_percent_above() {
    let store = single().await;
    let margin = wait_until_async("the first reading", async || {
        Some(safety(&store).margin_bytes).filter(|margin| *margin > 0)
    })
    .await;
    free_space(&store, margin - 1).await;
    wait_until_async("the store enters its margin", async || {
        safety(&store).pressure != Pressure::Normal
    })
    .await;
    for _ in 0..100 {
        let reading = safety(&store);
        assert!(reading.free_bytes >= reading.margin_bytes || reading.pressure != Pressure::Normal);
    }
    let inside = free_space(&store, margin + margin / 20).await;
    assert_eq!(
        inside.pressure,
        Pressure::Margin,
        "5 percent above: still in"
    );
    free_space(&store, margin + margin / 10).await;
    wait_until_async("normal again 10 percent above", async || {
        safety(&store).pressure == Pressure::Normal
    })
    .await;
    store.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reading_waits_on_no_work_of_the_store() {
    let store = single().await;
    for (n, hook) in [(1, HOLD_APPLY), (2, STALL_LOG)] {
        let held = Hook::set(&store, hook, "");
        let writer = store.clone();
        let task = tokio::spawn(async move { writer.propose(put(n)).await });
        if hook == HOLD_APPLY {
            wait_until_async("the entry is in the log and not applied", async || {
                let metrics = store.raft().metrics().borrow().clone();
                metrics.last_log_index > metrics.last_applied.map(|applied| applied.index)
            })
            .await;
        }
        let _ = safety(&store);
        let _ = safety(&store);
        assert!(!task.is_finished(), "{hook}: the write is held");
        drop(held);
        task.await.expect("no panic").expect("the write commits");
    }
    // A store stopped on a failed log write goes on reading its disk.
    let failed = Hook::set(&store, FAIL_LOG, "");
    let outcome = store.propose(put(3)).await;
    assert!(matches!(outcome, Err(StoreError::Stopped)), "{outcome:?}");
    drop(failed);
    let stopped = free_space(&store, 123_456_789).await;
    assert!(stopped.stopped.is_some());
    let _ = store.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_flags_of_a_compaction_and_a_snapshot_are_down_while_neither_runs() {
    let store = single().await;
    store.propose(put(1)).await.expect("a write");
    let idle = safety(&store);
    assert!(!idle.compacting && !idle.snapshotting, "{idle:?}");
    store.reseed_in_place().await.expect("a compaction");
    let after = safety(&store);
    assert!(!after.compacting && !after.snapshotting, "{after:?}");
    store.shutdown().await.expect("shutdown");
}
