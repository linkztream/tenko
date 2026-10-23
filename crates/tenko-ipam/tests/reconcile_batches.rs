//! The reconciler's proposal write in batches under the store's limit: a run with more
//! unknown clients than one batch holds writes several, each a consistent prefix; a batch
//! that fails is tried again as two halves; what fails twice is left for the next run; a
//! lost race in a later batch makes the run read again without counting twice (IPAM-15).

mod common;
mod reconcile_support;

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use common::*;
use reconcile_support::*;
use tenko_core::{
    ObservationId, Revision, Timestamp,
    observe::{Observation, ObservationSource, Observed},
};
use tenko_ipam::{
    IpamCommand, IpamService,
    observe::IngestBatch,
    proposals::{IntentProposalKind, IntentProposalState},
    reconcile::{RUN_ACTION, ReconcileReport, ReconcilerConfig},
};
use tenko_store::{
    ChangeStream, CoalescerConfig, Committed, DerivedIndex, KeyRange, MemStore, MemStoreConfig,
    ReadConsistency, ReadView, ReadViewExt, Store, StoreError, StoreStatus, WatchFilter,
    WriteBatch, tables::AUDIT,
};

/// Unknown clients per ingest (the ingest is one batch too, and must fit the limit).
const CHUNK: usize = 25;

/// An in-memory store whose batch limit is `max_batch_bytes`, through its configuration.
fn small_store(max_batch_bytes: usize) -> MemStore {
    MemStore::new(MemStoreConfig {
        coalescer: CoalescerConfig {
            max_batch_bytes,
            ..CoalescerConfig::default()
        },
        ..MemStoreConfig::default()
    })
}

/// How an armed proposal fails.
type Failure = fn() -> StoreError;

/// A store that fails the proposals it is armed for, then delegates again.
struct Flaky {
    inner: MemStore,
    /// The outcomes of the next proposals: `None` lets one through, `Some` fails it.
    armed: Mutex<VecDeque<Option<Failure>>>,
}

impl Flaky {
    fn new(inner: MemStore) -> Self {
        Self {
            inner,
            armed: Mutex::new(VecDeque::new()),
        }
    }

    /// Lets `pass` proposals through, then fails the next `fail` with `error`.
    fn arm(&self, pass: usize, fail: usize, error: Failure) {
        let mut armed = self.armed.lock().expect("armed");
        armed.clear();
        armed.extend(std::iter::repeat_n(None, pass));
        armed.extend(std::iter::repeat_n(Some(error), fail));
    }
}

#[async_trait::async_trait]
impl Store for Flaky {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        let next = self.armed.lock().expect("armed").pop_front();
        if let Some(Some(error)) = next {
            return Err(error());
        }
        self.inner.propose(batch).await
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

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<tenko_store::Leadership>> {
        self.inner.leadership()
    }

    fn max_batch_bytes(&self) -> usize {
        self.inner.max_batch_bytes()
    }
}

/// A world over `store` with the network 192.0.2.0/24 in the default VRF.
async fn lab(store: Arc<dyn Store>) -> World {
    let service = IpamService::with_direct_jobs(Arc::clone(&store)).expect("service");
    let world = World::over(store, service, ReconcilerConfig::default());
    run(
        &world.service,
        vec![IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24"))],
    )
    .await;
    world
}

/// The MAC address of unknown client `n`.
fn mac_of(n: usize) -> String {
    format!("00:00:5e:00:53:{n:02x}")
}

/// `count` unknown clients (at most 200) seen by the world's connector at `when`, in
/// ingests of [`CHUNK`] so that each ingest batch fits a small store limit too.
async fn seen(world: &World, count: usize, when: Timestamp) {
    assert!(count <= 200, "192.0.2.0/24 holds the clients 1 to 200");
    let source = ObservationSource::Inventory {
        connector: world.connector,
    };
    for first in (1..=count).step_by(CHUNK) {
        let observations = (first..(first + CHUNK).min(count + 1))
            .map(|n| Observation {
                id: ObservationId::generate(),
                source: source.clone(),
                subject: Observed::Host(vm(
                    &format!("qemu/{n}"),
                    Some(&format!("client-{n}")),
                    Some(&mac_of(n)),
                    &[&format!("192.0.2.{n}")],
                )),
                observed_at: when,
                received_at: when,
                expires_at: when.checked_add(Duration::from_secs(900)),
            })
            .collect();
        world
            .reconciler
            .ingest(IngestBatch {
                source: source.clone(),
                observations,
                complete: false,
                received_at: when,
            })
            .await
            .expect("ingest");
    }
}

/// The run records in the audit chain: `(batches, proposals, unwritten)` each.
async fn run_records(world: &World) -> Vec<(u32, u32, u32)> {
    let view = world
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    view.scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit")
        .into_iter()
        .filter(|(_, record, _)| record.draft.action.as_str() == RUN_ACTION)
        .map(|(_, record, _)| {
            let context = &record.draft.details.context;
            let number = |key: &str| {
                context
                    .get(key)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| panic!("{key} in {context:?}"))
            };
            (number("batches"), number("proposals"), number("unwritten"))
        })
        .collect()
}

fn written_in_full(report: &ReconcileReport, count: u32) {
    assert_eq!(report.opened, count, "{report:?}");
    assert_eq!(report.unwritten, 0, "{report:?}");
    assert_eq!(report.failure, None, "{report:?}");
    assert!(report.revision.is_some(), "{report:?}");
}

#[tokio::test]
async fn a_run_with_more_proposals_than_one_batch_holds_writes_several() {
    let store = small_store(32 * 1024);
    let world = lab(Arc::new(store.clone())).await;
    seen(&world, 200, at("08:00")).await;

    let report = world.reconcile(at("08:05")).await;
    written_in_full(&report, 200);
    assert!(report.batches >= 3, "{report:?}");
    assert_eq!(
        report.revision,
        Some(revision_of(&store)),
        "the last batch's"
    );
    let open = world.open(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(open.len(), 200);
    assert_eq!(world.proposals(None).await.len(), 200, "each client once");
    assert_eq!(
        run_records(&world).await,
        vec![(report.batches, 200, 0)],
        "one run record, in the last batch"
    );

    // Nothing left to write: no batch, no record.
    let again = world.reconcile(at("08:06")).await;
    assert_eq!(again.opened, 0, "{again:?}");
    assert_eq!(again.unchanged, 200, "{again:?}");
    assert_eq!(again.batches, 0, "{again:?}");
    assert_eq!(again.revision, None, "{again:?}");
    assert_eq!(run_records(&world).await.len(), 1);
}

#[tokio::test]
async fn the_limit_comes_from_the_store_not_a_constant() {
    // The same clients under the default limit fit one batch.
    let world = lab(Arc::new(MemStore::default())).await;
    seen(&world, 200, at("08:00")).await;
    let report = world.reconcile(at("08:05")).await;
    written_in_full(&report, 200);
    assert_eq!(report.batches, 1, "{report:?}");
    assert_eq!(run_records(&world).await, vec![(1, 200, 0)]);
}

#[tokio::test]
async fn a_batch_that_fails_is_written_again_as_two_halves() {
    let store = Arc::new(Flaky::new(small_store(32 * 1024)));
    let world = lab(Arc::clone(&store) as Arc<dyn Store>).await;
    seen(&world, 200, at("08:00")).await;
    let plain = lab(Arc::new(small_store(32 * 1024))).await;
    seen(&plain, 200, at("08:00")).await;
    let batches = plain.reconcile(at("08:05")).await.batches;

    // The second batch fails once; its halves go through.
    store.arm(1, 1, || StoreError::Timeout);
    let report = world.reconcile(at("08:05")).await;
    written_in_full(&report, 200);
    assert_eq!(report.batches, batches + 1, "{report:?}");
    assert_eq!(
        world.open(IntentProposalKind::DiscoveredHost).await.len(),
        200
    );
    assert_eq!(run_records(&world).await, vec![(batches + 1, 200, 0)]);
}

#[tokio::test]
async fn a_batch_that_fails_twice_keeps_the_earlier_ones_and_the_next_run_writes_the_rest() {
    let store = Arc::new(Flaky::new(small_store(32 * 1024)));
    let world = lab(Arc::clone(&store) as Arc<dyn Store>).await;
    seen(&world, 200, at("08:00")).await;

    // The second batch fails, and so do both of its halves.
    store.arm(1, 3, || {
        StoreError::Storage("the disk went away".to_owned())
    });
    let report = world.reconcile(at("08:05")).await;
    assert!(report.unwritten > 0, "{report:?}");
    assert!(report.opened > 0, "{report:?}");
    assert_eq!(report.opened + report.unwritten, 200, "{report:?}");
    assert_eq!(report.failure.as_deref(), Some("sys.store.storage"));
    assert!(
        report.revision.is_some(),
        "the earlier batches are committed"
    );
    let open = world.open(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(
        u32::try_from(open.len()).expect("count"),
        report.opened,
        "the earlier batches stay"
    );
    assert_eq!(
        run_records(&world).await,
        vec![(report.batches, report.opened, report.unwritten)],
        "the record says what was not written"
    );

    // The store is back: the next run writes what is left, once.
    let next = world.reconcile(at("08:06")).await;
    assert_eq!(next.opened, report.unwritten, "{next:?}");
    assert_eq!(next.unchanged, report.opened, "{next:?}");
    assert_eq!(next.unwritten, 0, "{next:?}");
    assert_eq!(next.failure, None, "{next:?}");
    assert_eq!(
        world.open(IntentProposalKind::DiscoveredHost).await.len(),
        200
    );
    assert_eq!(world.proposals(None).await.len(), 200, "each client once");
    assert_eq!(run_records(&world).await.len(), 2);
}

#[tokio::test]
async fn a_lost_race_in_a_later_batch_makes_the_run_read_again_and_count_each_proposal_once() {
    let store = Arc::new(Flaky::new(small_store(32 * 1024)));
    let world = lab(Arc::clone(&store) as Arc<dyn Store>).await;
    seen(&world, 200, at("08:00")).await;

    // The second batch loses a race: the first stays, the run reads again and writes the
    // rest without counting the first batch's proposals again.
    store.arm(1, 1, || StoreError::PreconditionFailed(Vec::new()));
    let report = world.reconcile(at("08:05")).await;
    written_in_full(&report, 200);
    assert_eq!(report.unchanged, 0, "{report:?}");
    assert!(report.batches >= 3, "{report:?}");
    assert_eq!(
        world.open(IntentProposalKind::DiscoveredHost).await.len(),
        200
    );
    assert_eq!(world.proposals(None).await.len(), 200, "each client once");
    assert_eq!(run_records(&world).await, vec![(report.batches, 200, 0)]);
}

#[tokio::test]
async fn expirations_are_items_of_their_own_and_fit_the_batches_too() {
    let store = small_store(32 * 1024);
    let world = lab(Arc::new(store.clone())).await;
    seen(&world, 200, at("08:00")).await;
    world.reconcile(at("08:05")).await;

    // Every client goes away: the facts expire and the proposals with them.
    let report = world.reconcile(at("09:00")).await;
    assert_eq!(report.expired, 200, "{report:?}");
    assert_eq!(report.opened, 0, "{report:?}");
    assert!(report.batches >= 3, "{report:?}");
    assert_eq!(report.unwritten, 0, "{report:?}");
    assert_eq!(
        world.open(IntentProposalKind::DiscoveredHost).await.len(),
        0
    );
    assert_eq!(
        world
            .proposals(Some(IntentProposalState::Expired))
            .await
            .len(),
        200
    );
}
