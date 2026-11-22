//! A lease change the store refuses for room on its disk (`sys.store.disk_reserve`) is a
//! refusal of that change alone: the refusal gate stays open, so a renewal that follows
//! commits. Below the store's margin a renewal rewrites rows of the same size and passes the
//! store's guard, while a new client's lease does not.

mod lease_support;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use lease_support::{addr, change, completions, from_now, mem_store, start};
use tenko_core::{
    PrefixId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, LeaseEventKind},
};
use tenko_dhcp::{
    lease::CommitSettings,
    store::{LeaseStore, Ticket},
};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, Leadership, ReadConsistency, ReadView, Store,
    StoreError, StoreStatus, WatchFilter, WriteBatch,
};

/// A guard against a hang only.
const WAIT: Duration = Duration::from_secs(10);

/// A store that refuses its next lease batch for room on its disk, once.
struct ShortOfRoom {
    inner: Arc<dyn Store>,
    refuse: AtomicBool,
}

#[async_trait::async_trait]
impl Store for ShortOfRoom {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        if self.refuse.swap(false, Ordering::SeqCst) {
            return Err(StoreError::DiskReserve { free: 1, needed: 2 });
        }
        self.inner.propose(batch).await
    }

    // The history goes through the background class: it is not the change refused here.
    async fn propose_background(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        self.inner.propose_background(batch).await
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.inner.read(consistency).await
    }

    fn watch(
        &self,
        from: Option<Revision>,
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

#[tokio::test]
async fn a_lease_refused_for_room_on_the_disk_leaves_the_next_renewal_open() {
    let store = Arc::new(ShortOfRoom {
        inner: mem_store(),
        refuse: AtomicBool::new(false),
    });
    // A gate that closed would stay closed for the whole test.
    let settings = CommitSettings {
        retry_after: Duration::from_secs(600),
        ..CommitSettings::default()
    };
    let (leases, _, stop, task) = start(store.clone(), settings);
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let lease = |kind, last, client, ends| {
        change(
            kind,
            vrf,
            scope,
            addr(last),
            client,
            BindingState::Active,
            Timestamp::now(),
            from_now(ends),
        )
    };
    leases
        .submit(&lease(LeaseEventKind::Granted, 10, 4, 3_600), Ticket(1))
        .expect("queued");
    let done = completions(&leases, 1, WAIT).await;
    assert!(done[0].outcome.is_ok(), "{done:?}");

    store.refuse.store(true, Ordering::SeqCst);
    leases
        .submit(&lease(LeaseEventKind::Granted, 11, 5, 3_600), Ticket(2))
        .expect("queued");
    let done = completions(&leases, 1, WAIT).await;
    assert!(
        matches!(&done[0].outcome, Err(error) if error.to_string().contains("disk")),
        "the new client's lease is refused: {done:?}"
    );

    leases
        .submit(&lease(LeaseEventKind::Renewed, 10, 4, 7_200), Ticket(3))
        .expect("the gate stays open");
    let done = completions(&leases, 1, WAIT).await;
    assert!(done[0].outcome.is_ok(), "the renewal commits: {done:?}");
    stop.cancel();
    task.await.expect("the committer");
}
