//! Clock skew between controllers (risk R35 of the Slice 3 plan).
//!
//! Leader-only execution keeps lease timing out of correctness, but ceremony and token
//! expiry still compare a time written by one controller with the clock of another. The
//! leader service `cluster.clock` therefore writes the record [`CLOCK`] every
//! [`BEAT_INTERVAL`] while the cluster has more than one voter, fenced with the leader
//! epoch. The change set of that write carries the leader's clock (the proposer's time), and
//! every controller compares it with its own clock as soon as the change arrives
//! ([`follow`]); replication adds milliseconds, far below the tolerance. The difference is
//! shown in `GET /system/status` (`leader.clock_skew_ms`, this controller's clock minus the
//! leader's), and more than [`CLOCK_SKEW_TOLERANCE_MS`] is the warning `cluster.clock_skew`
//! and a log line. Without a beat for three intervals (a single controller, no leader) the
//! value is cleared.

use std::{sync::Arc, time::Duration};

use futures::StreamExt as _;
use serde::{Deserialize, Serialize};
use tenko_api::routes::system::CLOCK_SKEW_TOLERANCE_MS;
use tenko_core::{
    NodeId, Principal, SystemComponent, Timestamp, cluster::LeaderService, table::TableDef,
};
use tenko_store::{ChangeSet, QuorumState, Store, WatchFilter, WriteBatch, fence};
use tokio::{sync::watch, task::JoinHandle};

use super::{LeaderView, periodic};

/// The record the leader writes on every beat.
pub(crate) const CLOCK: TableDef<(), LeaderClock> = TableDef::new("sys.leader_clock");

/// How often the leader writes [`CLOCK`].
pub(crate) const BEAT_INTERVAL: Duration = Duration::from_secs(60);

/// How long to wait before subscribing again when the change stream lagged or ended.
const RESUBSCRIBE_DELAY: Duration = Duration::from_secs(5);

/// The value of [`CLOCK`]: who wrote it in which term. The time is the change set's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LeaderClock {
    /// The leader that wrote it.
    pub node: NodeId,
    /// Its leader epoch.
    pub epoch: u64,
}

/// The leader service `cluster.clock` of controller `node`.
pub(crate) fn beat_service(store: Arc<dyn Store>, node: NodeId) -> Arc<dyn LeaderService> {
    periodic("cluster.clock", BEAT_INTERVAL, move |epoch| {
        let store = Arc::clone(&store);
        async move { beat(store.as_ref(), node, epoch).await }
    })
}

/// One beat; nothing is written on a single voter, which has no other clock to compare.
async fn beat(store: &dyn Store, node: NodeId, epoch: u64) -> Result<usize, String> {
    if matches!(store.status().quorum, QuorumState::Single) {
        return Ok(0);
    }
    let mut batch = WriteBatch::new(
        Principal::system(SystemComponent::Cluster),
        Timestamp::now(),
    );
    batch.preconditions.push(fence(epoch));
    batch
        .put_typed(&CLOCK, &(), &LeaderClock { node, epoch })
        .map_err(|error| error.to_string())?;
    store
        .propose(batch)
        .await
        .map(|_| 0)
        .map_err(|error| error.to_string())
}

/// This controller's clock minus the proposer's clock of `set`, in milliseconds.
fn skew_ms(set: &ChangeSet, now: Timestamp) -> i64 {
    let millis = (now.0 - set.at.0).whole_milliseconds();
    i64::try_from(millis).unwrap_or(if millis < 0 { i64::MIN } else { i64::MAX })
}

/// Follows the beats of the leader on this controller and records the skew in `view` until
/// `stop` is set. `None` when the store cannot be watched; the skew is then not shown.
pub(crate) fn follow(
    store: Arc<dyn Store>,
    view: LeaderView,
    stop: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    let changes = match store.watch(None, filter()) {
        Ok(changes) => changes,
        Err(error) => {
            tracing::warn!(%error, "the clock skew between controllers is not measured");
            return None;
        }
    };
    Some(tokio::spawn(run(store, view, changes, stop)))
}

fn filter() -> WatchFilter {
    WatchFilter::tables([CLOCK.name().clone()])
}

async fn run(
    store: Arc<dyn Store>,
    view: LeaderView,
    mut changes: tenko_store::ChangeStream,
    mut stop: watch::Receiver<bool>,
) {
    let mut skewed = false;
    loop {
        let next = tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => return,
            () = tokio::time::sleep(BEAT_INTERVAL * 3) => {
                view.clock_skew(None);
                continue;
            }
            next = changes.next() => next,
        };
        let Some(Ok(set)) = next else {
            // The stream lagged or ended: subscribe again after a pause.
            tokio::select! {
                _ = stop.wait_for(|stopped| *stopped) => return,
                () = tokio::time::sleep(RESUBSCRIBE_DELAY) => {}
            }
            match store.watch(None, filter()) {
                Ok(next) => changes = next,
                Err(error) => {
                    tracing::warn!(%error, "the clock skew between controllers is no longer measured");
                    view.clock_skew(None);
                    return;
                }
            }
            continue;
        };
        if !set
            .changes
            .iter()
            .any(|change| change.table == *CLOCK.name())
        {
            continue;
        }
        let skew = skew_ms(&set, Timestamp::now());
        view.clock_skew(Some(skew));
        let now_skewed = skew.unsigned_abs() > CLOCK_SKEW_TOLERANCE_MS.unsigned_abs();
        if now_skewed && !skewed {
            tracing::warn!(
                skew_ms = skew,
                "the clock of this controller differs from the leader's by more than five \
                 seconds; sign-in ceremonies and tokens may expire early or late"
            );
        } else if !now_skewed && skewed {
            tracing::info!(
                skew_ms = skew,
                "the clock of this controller agrees with the leader's again"
            );
        }
        skewed = now_skewed;
    }
}

#[cfg(test)]
mod tests {
    use tenko_store::MemStore;

    use super::*;

    fn set_at(at: Timestamp) -> ChangeSet {
        ChangeSet {
            revision: tenko_core::Revision::ZERO,
            principal: Principal::system(SystemComponent::Cluster),
            at,
            changes: Vec::new(),
        }
    }

    #[test]
    fn the_skew_is_this_clock_minus_the_leaders() {
        let now = Timestamp::now();
        let leader = now.checked_add(Duration::from_secs(7)).expect("in range");
        assert_eq!(skew_ms(&set_at(leader), now), -7_000);
        let later = now
            .checked_add(Duration::from_millis(1_500))
            .expect("in range");
        assert_eq!(skew_ms(&set_at(now), later), 1_500);
    }

    #[tokio::test]
    async fn a_single_voter_writes_no_beat_and_a_follower_records_the_skew() {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        assert_eq!(beat(store.as_ref(), NodeId(1), 0).await, Ok(0));
        let view = LeaderView::default();
        let (stop_tx, stop) = watch::channel(false);
        let task = follow(Arc::clone(&store), view.clone(), stop).expect("watch");
        // A beat as a leader on another controller writes it, with that leader's clock.
        let leader_clock = Timestamp::now()
            .checked_add(Duration::from_secs(9))
            .expect("in range");
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Cluster), leader_clock);
        batch
            .put_typed(
                &CLOCK,
                &(),
                &LeaderClock {
                    node: NodeId(2),
                    epoch: 1,
                },
            )
            .expect("encode");
        store.propose(batch).await.expect("write");
        let skew = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(skew) = view.status().clock_skew_ms {
                    return skew;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("measured");
        assert!((-9_500..=-8_500).contains(&skew), "{skew}");
        stop_tx.send(true).expect("stop");
        task.await.expect("task");
    }
}
