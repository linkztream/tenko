use tenko_core::{
    RequestCtx, SystemComponent, Timestamp,
    dns::{TransferStamp, ZoneId, tables::TRANSFER_STATE},
};
use tenko_store::{MemStore, MemStoreConfig, WriteBatch};

use super::*;

fn filter() -> WatchFilter {
    WatchFilter::tables([TRANSFER_STATE.name().clone()])
}

async fn write(store: &MemStore, serial: u32) -> Revision {
    let cx = RequestCtx::system(SystemComponent::Dns);
    let mut batch = WriteBatch::for_request(&cx);
    let zone = ZoneId::generate();
    let stamp = TransferStamp {
        zone,
        serial,
        refreshed: Timestamp::now(),
    };
    batch
        .put_typed(&TRANSFER_STATE, &zone, &stamp)
        .expect("stage");
    store.propose(batch).await.expect("propose").revision
}

async fn changes(follow: &mut Follow) -> Revision {
    match follow.next().await {
        Followed::Changes(set) => set.revision,
        Followed::Reset => panic!("a reset where a change set was due"),
    }
}

#[tokio::test]
async fn the_first_answer_is_a_reset_and_then_every_change_in_order() {
    let store = MemStore::default();
    let mut follow = Follow::new(Arc::new(store.clone()), filter(), "test");
    assert!(matches!(follow.next().await, Followed::Reset));
    let first = write(&store, 1).await;
    let second = write(&store, 2).await;
    assert_eq!(changes(&mut follow).await, first);
    assert_eq!(changes(&mut follow).await, second);
}

#[tokio::test]
async fn a_lagged_stream_resumes_after_the_last_revision_seen_without_a_reset() {
    let store = MemStore::new(MemStoreConfig {
        watch_max_lag: 1,
        ..MemStoreConfig::default()
    });
    let mut follow = Follow::new(Arc::new(store.clone()), filter(), "test");
    assert!(matches!(follow.next().await, Followed::Reset));
    let first = write(&store, 1).await;
    assert_eq!(changes(&mut follow).await, first);
    let mut written = Vec::new();
    for serial in 2..8 {
        written.push(write(&store, serial).await);
    }
    // The stream falls behind and ends; the follower opens it again from `first`, so every
    // change set comes once and in order.
    let mut seen = Vec::new();
    for _ in &written {
        seen.push(changes(&mut follow).await);
    }
    assert_eq!(seen, written);
}

#[tokio::test]
async fn a_gap_the_store_cannot_replay_is_a_reset() {
    let store = MemStore::new(MemStoreConfig {
        watch_max_lag: 1,
        journal_retention: 1,
        ..MemStoreConfig::default()
    });
    let mut follow = Follow::new(Arc::new(store.clone()), filter(), "test");
    assert!(matches!(follow.next().await, Followed::Reset));
    let first = write(&store, 1).await;
    assert_eq!(changes(&mut follow).await, first);
    for serial in 2..8 {
        write(&store, serial).await;
    }
    assert!(matches!(follow.next().await, Followed::Reset));
    let after = write(&store, 9).await;
    assert_eq!(
        changes(&mut follow).await,
        after,
        "followed again after the reset"
    );
}

/// A store that stops is tried once per pause, and the pause doubles: each look ends
/// waiting, never in a loop that tries again at once.
#[tokio::test]
async fn a_stopped_store_is_tried_once_per_growing_pause() {
    use futures::FutureExt as _;
    let store = MemStore::default();
    let mut follow = Follow::new(Arc::new(store.clone()), filter(), "test");
    assert!(matches!(follow.next().await, Followed::Reset));
    store.shutdown();
    let mut next_pauses = Vec::new();
    for _ in 0..10 {
        assert!(follow.next().now_or_never().is_none(), "it waits");
        assert!(follow.retry_at.is_some(), "a time for the next attempt");
        next_pauses.push(follow.backoff.as_millis());
        // The pause is over: the next look tries once more.
        follow.retry_at = None;
    }
    assert_eq!(
        next_pauses,
        [
            200, 400, 800, 1600, 3200, 6400, 12_800, 25_600, 30_000, 30_000
        ]
    );
}

/// A stream that lags before it handed out any change set has no revision to resume
/// from: the follower says to read everything again, so nothing in between is lost.
#[tokio::test]
async fn a_lag_before_the_first_change_set_is_a_reset() {
    let store = MemStore::new(MemStoreConfig {
        watch_max_lag: 1,
        ..MemStoreConfig::default()
    });
    let mut follow = Follow::new(Arc::new(store.clone()), filter(), "test");
    assert!(matches!(follow.next().await, Followed::Reset));
    for serial in 1..8 {
        write(&store, serial).await;
    }
    assert!(matches!(follow.next().await, Followed::Reset));
    let after = write(&store, 9).await;
    assert_eq!(changes(&mut follow).await, after);
}
