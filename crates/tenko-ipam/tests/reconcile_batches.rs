//! The reconciler's proposal write in batches under the store's limit: a run with more
//! unknown clients than one batch holds writes several, each a consistent prefix with one
//! audit record; a batch that fails is tried again as two halves; what fails twice is left
//! for the next run; a lost race in a later batch makes the run read again without counting
//! twice (IPAM-15). And what keeps the table bounded: a flood of new MAC addresses never
//! holds more proposals than the network has addresses and leaves no closed rows behind,
//! closed proposals go after the retention, and each removal is a counted batch that only
//! deletes.

mod common;
mod reconcile_support;

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use common::*;
use reconcile_support::*;
use tenko_core::{
    ObservationId, Revision, Timestamp,
    clock::{Held, Reason, Release, testing},
    codec::to_cbor,
    observe::{Observation, ObservationSource, Observed},
};
use tenko_ipam::{
    IpamCommand, IpamService,
    observe::{IngestBatch, retention::PURGE_ACTION, tables::FACTS},
    proposals::{
        self, IntentProposalKind, IntentProposalState,
        model::{PROPOSALS, REJECTIONS},
    },
    reconcile::{RUN_ACTION, ReconcileReport, ReconcilerConfig},
};
use tenko_store::{
    ChangeStream, CoalescerConfig, Committed, DerivedIndex, KeyRange, MemStore, MemStoreConfig,
    Mutation, ReadConsistency, ReadView, ReadViewExt, Store, StoreError, StoreStatus, WatchFilter,
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

/// A store that fails the proposals it is armed for, then delegates again, and keeps the
/// batches it let through.
struct Flaky {
    inner: MemStore,
    /// The outcomes of the next proposals: `None` lets one through, `Some` fails it.
    armed: Mutex<VecDeque<Option<Failure>>>,
    passed: Mutex<Vec<WriteBatch>>,
}

impl Flaky {
    fn new(inner: MemStore) -> Self {
        Self {
            inner,
            armed: Mutex::new(VecDeque::new()),
            passed: Mutex::new(Vec::new()),
        }
    }

    /// The batches let through that delete a proposal row.
    fn removals(&self) -> Vec<WriteBatch> {
        let deletes = |batch: &WriteBatch| {
            batch.mutations.iter().any(|mutation| {
                matches!(mutation, Mutation::Delete { table, .. } if table == PROPOSALS.name())
            })
        };
        let passed = self.passed.lock().expect("passed");
        passed
            .iter()
            .filter(|batch| deletes(batch))
            .cloned()
            .collect()
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
        self.passed.lock().expect("passed").push(batch.clone());
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

/// The contexts of the run records in the audit chain, oldest first: one per batch.
async fn records(world: &World) -> Vec<BTreeMap<String, String>> {
    let view = world
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    view.scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit")
        .into_iter()
        .filter(|(_, record, _)| record.draft.action.as_str() == RUN_ACTION)
        .map(|(_, record, _)| record.draft.details.context)
        .collect()
}

/// The number under `key` in a record's context.
fn number(context: &BTreeMap<String, String>, key: &str) -> u32 {
    context
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("{key} in {context:?}"))
}

/// `key` summed over records.
fn sum(records: &[BTreeMap<String, String>], key: &str) -> u32 {
    records.iter().map(|context| number(context, key)).sum()
}

/// The runs the records tell, `(batches, proposals, unwritten)` each: the proposal rows of
/// its batches summed, the batches and the unwritten items from its last record.
async fn run_records(world: &World) -> Vec<(u32, u32, u32)> {
    let mut runs = Vec::new();
    let mut proposals = 0;
    for context in records(world).await {
        proposals += number(&context, "proposals");
        if context.contains_key("batches") {
            runs.push((
                number(&context, "batches"),
                proposals,
                number(&context, "unwritten"),
            ));
            proposals = 0;
        }
    }
    runs
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
    assert_eq!(run_records(&world).await, vec![(report.batches, 200, 0)]);
    assert_eq!(
        records(&world).await.len(),
        usize::try_from(report.batches).expect("count"),
        "one record per batch"
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
    let opening = world.reconcile(at("08:05")).await;

    // Every client goes away: the facts expire and the proposals with them. A deletion is
    // a few keys, so they take fewer batches than the rows that opened.
    let report = world.reconcile(at("09:00")).await;
    assert_eq!(report.expired, 200, "{report:?}");
    assert_eq!(report.opened, 0, "{report:?}");
    assert!((1..opening.batches).contains(&report.batches), "{report:?}");
    assert_eq!(report.unwritten, 0, "{report:?}");
    assert_eq!(
        world.proposals(None).await.len(),
        0,
        "a discovered host the reconciler closes is deleted, not kept"
    );
    let records = records(&world).await;
    assert_eq!(sum(&records, "deleted"), 200, "{records:?}");
}

/// Asserts that every batch that deleted a proposal row only deleted, with one audit record
/// of at most 1 KiB, as a store near its disk reserve lets through; returns how many.
fn removals_only_delete(store: &Flaky) -> usize {
    let removals = store.removals();
    for batch in &removals {
        assert!(
            batch
                .mutations
                .iter()
                .all(|mutation| matches!(mutation, Mutation::Delete { .. })),
            "{batch:?}"
        );
        assert_eq!(batch.audit.len(), 1, "{batch:?}");
        assert!(
            to_cbor(&batch.audit[0]).expect("cbor").len() <= 1024,
            "{batch:?}"
        );
    }
    removals.len()
}

/// Asserts that a run that removed anything carries its totals (`batches`) on a batch that
/// only deletes, so a store near its reserve still takes them; returns how many such runs.
fn totals_ride_on_a_removal(store: &Flaky) -> usize {
    let (mut removed, mut runs) = (false, 0);
    for batch in store.passed.lock().expect("passed").iter() {
        let Some(record) = batch
            .audit
            .iter()
            .find(|draft| draft.action.as_str() == RUN_ACTION)
        else {
            continue;
        };
        let deletes = batch
            .mutations
            .iter()
            .all(|m| matches!(m, Mutation::Delete { .. }));
        removed |= deletes;
        if record.details.context.contains_key("batches") {
            assert!(!removed || deletes, "{batch:?}");
            runs += usize::from(removed);
            removed = false;
        }
    }
    runs
}

/// The clock guard holding destruction, as after a jump of the wall clock.
fn hold_the_clock(since: Timestamp) -> testing::Override {
    testing::hold(Held {
        reason: Reason::Jump,
        jump_ms: 3_600_000,
        since,
        release: Release::Wait,
        until: None,
    })
}

#[tokio::test]
async fn new_macs_through_a_network_never_hold_more_proposals_than_its_addresses() {
    let store = Arc::new(Flaky::new(MemStore::default()));
    let world = lab(Arc::clone(&store) as Arc<dyn Store>).await;
    let start = at("08:00");
    let time = |minutes: u64| {
        start
            .checked_add(Duration::from_secs(60 * minutes))
            .expect("time")
    };
    // A device that stays, and one a person rejected.
    let (laptop_mac, tv_mac) = ("00:00:5e:00:53:fe", "00:00:5e:00:53:fd");
    let present = vm("laptop", None, Some(laptop_mac), &["192.0.2.250"]);
    let refused = vm("tv", None, Some(tv_mac), &["192.0.2.251"]);
    world
        .poll(vec![present.clone(), refused.clone()], start)
        .await;
    let mut batches = world.reconcile(start).await.batches;
    let open = world.open(IntentProposalKind::DiscoveredHost).await;
    let of = |text: &str| {
        open.iter()
            .position(|proposal| proposal.subject.mac == Some(mac(text)))
            .expect("proposal")
    };
    let (laptop, tv) = (open[of(laptop_mac)].id, open[of(tv_mac)].id);
    world.reject(&open[of(tv_mac)]).await;

    // 10,000 clients: each round 200 new MAC addresses take the addresses .1 to .200 that
    // the round before released, the first five rounds with a trusted clock and the rest
    // while the clock guard holds expiry.
    let mut held = None;
    for round in 0..50u64 {
        if round == 5 {
            held = Some(hold_the_clock(time(round)));
        }
        let mut hosts: Vec<_> = (1..=200u64)
            .map(|n| {
                vm(
                    &format!("{round}/{n}"),
                    None,
                    Some(&format!("02:00:00:00:{round:02x}:{n:02x}")),
                    &[&format!("192.0.2.{n}")],
                )
            })
            .collect();
        hosts.extend([present.clone(), refused.clone()]);
        world.poll(hosts, time(round + 1)).await;
        batches += world.reconcile(time(round + 1)).await.batches;
        let open = world.open(IntentProposalKind::DiscoveredHost).await;
        assert!(open.len() <= 254, "round {round}: {} open", open.len());
        assert_eq!(
            world.proposals(None).await.len(),
            open.len() + 1,
            "round {round}: the person's rejection is the only closed row"
        );
        assert!(
            open.iter().any(|proposal| proposal.id == laptop),
            "round {round}: the device that is present keeps its proposal"
        );
    }
    assert_eq!(
        world.open(IntentProposalKind::DiscoveredHost).await.len(),
        254,
        "the bound held the open proposals at the network's addresses"
    );

    // The clock is trusted again: what no current sighting stands for goes.
    drop(held);
    world.poll(vec![present, refused], time(60)).await;
    batches += world.reconcile(time(60)).await.batches;
    let left = world.proposals(None).await;
    assert_eq!(left.len(), 2, "{left:#?}");
    assert!(
        left.iter()
            .any(|proposal| proposal.id == tv && proposal.state == IntentProposalState::Rejected),
        "{left:#?}"
    );
    let laptop = left
        .iter()
        .find(|proposal| proposal.id == laptop && proposal.is_open())
        .expect("the present device's proposal, still open");
    // A person can still decide it.
    let decision = world.approve(laptop).await;
    assert_eq!(decision.proposal.state, IntentProposalState::Accepted);

    // One record per batch, and every proposal row the reconciler removed is counted in one.
    let records = records(&world).await;
    assert_eq!(records.len(), usize::try_from(batches).expect("count"));
    let removed = sum(&records, "deleted") + sum(&records, "bounded");
    assert_eq!(
        removed,
        sum(&records, "opened") - 2,
        "every row but the laptop's and the tv's"
    );
    assert!(sum(&records, "bounded") > 0, "the bound removed some");
    assert!(removals_only_delete(&store) > 0);
    // Every round after the first both opened and removed.
    assert!(totals_ride_on_a_removal(&store) >= 49);
}

#[tokio::test]
async fn devices_with_no_network_whose_facts_were_overwritten_leave_while_the_clock_is_held() {
    let store = Arc::new(Flaky::new(MemStore::default()));
    let world = lab(Arc::clone(&store) as Arc<dyn Store>).await;
    let start = at("08:00");
    let _held = hold_the_clock(start);
    // Three polls of the same 200 inventory hosts, each poll with new MAC addresses and no
    // address at all: 600 discovered hosts with no network, and the facts name 200 MACs.
    for round in 0..3u64 {
        let hosts = (1..=200u64)
            .map(|n| {
                let host_mac = format!("02:00:00:01:{round:02x}:{n:02x}");
                vm(&format!("{n}"), None, Some(&host_mac), &[])
            })
            .collect();
        let when = start
            .checked_add(Duration::from_secs(60 * round))
            .expect("time");
        world.poll(hosts, when).await;
        world.reconcile(when).await;
    }
    let open = world.open(IntentProposalKind::DiscoveredHost).await;
    assert!(
        open.iter()
            .all(|proposal| proposal.subject.prefix.is_none())
    );
    // The 200 current ones, and as many without a current sighting as the facts name MAC
    // addresses: the newest of those, so the first poll's are gone.
    assert_eq!(open.len(), 400);
    assert!(
        open.iter()
            .all(|proposal| !proposal.key.contains("02:00:00:01:00:")),
        "the oldest went first"
    );
    assert_eq!(sum(&records(&world).await, "bounded"), 200);
    assert!(removals_only_delete(&store) > 0);
}

#[tokio::test]
async fn removal_and_purge_batches_stay_under_the_bytes_a_store_near_its_reserve_takes() {
    let store = Arc::new(Flaky::new(MemStore::default()));
    let world = lab(Arc::clone(&store) as Arc<dyn Store>).await;
    run(
        &world.service,
        vec![IpamCommand::CreatePrefix(prefix(None, "10.0.0.0/21"))],
    )
    .await;
    let start = at("08:00");
    let hosts = (1..=2_000u32)
        .map(|n| {
            let host_mac = format!("02:00:00:02:{:02x}:{:02x}", n >> 8, n & 0xff);
            let ip = format!("10.0.{}.{}", n >> 8, n & 0xff);
            vm(&format!("{n}"), None, Some(&host_mac), &[&ip])
        })
        .collect();
    world.poll(hosts, start).await;
    world.reconcile(start).await;
    // The clients leave: 2,000 removals in one run, then their facts go after the retention.
    let later = start.checked_add(Duration::from_secs(3_600)).expect("time");
    world.poll(Vec::new(), later).await;
    assert_eq!(world.reconcile(later).await.expired, 2_000);
    world
        .reconciler
        .purge(days_after(start, 31))
        .await
        .expect("purge");
    let passed = store.passed.lock().expect("passed").clone();
    let only_deletes = |batch: &WriteBatch| {
        batch
            .mutations
            .iter()
            .all(|mutation| matches!(mutation, Mutation::Delete { .. }))
    };
    let removals: Vec<_> = passed.iter().filter(|batch| only_deletes(batch)).collect();
    let deleting = |table: &str| {
        let deletes =
            |m: &Mutation| matches!(m, Mutation::Delete { table: t, .. } if t.as_str() == table);
        let batches = removals
            .iter()
            .filter(|batch| batch.mutations.iter().any(deletes));
        batches.count()
    };
    assert!(
        deleting(PROPOSALS.name().as_str()) >= 2,
        "the proposal removals split by bytes"
    );
    assert!(
        deleting(FACTS.name().as_str()) >= 2,
        "the fact purge splits by bytes"
    );
    // What a store near its reserve weighs, the payload or the encoding: both stay under.
    let largest = removals
        .iter()
        .map(|batch| {
            batch
                .payload_size()
                .max(to_cbor(*batch).expect("cbor").len())
        })
        .max();
    assert!(
        largest.is_some_and(|bytes| bytes <= 256 * 1024),
        "{largest:?}"
    );
}

#[tokio::test]
async fn closed_proposals_go_after_the_retention_in_counted_batches_that_only_delete() {
    let store = Arc::new(Flaky::new(MemStore::default()));
    let world = lab(Arc::clone(&store) as Arc<dyn Store>).await;
    let start = at("08:00");
    seen(&world, 3, start).await;
    world.reconcile(start).await;
    let open = world.open(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(open.len(), 3);
    for (proposal, when) in [(&open[0], start), (&open[1], days_after(start, 20))] {
        proposals::reject(&world.service, proposal.id, None, &person().at(when), None)
            .await
            .expect("reject");
    }

    // Past the retention (30 days) for the first rejection only; the clock guard holds it.
    let now = days_after(start, 31);
    {
        let _held = hold_the_clock(now);
        world.reconciler.purge(now).await.expect("purge");
        assert_eq!(
            world.proposals(None).await.len(),
            3,
            "nothing goes while held"
        );
    }
    world.reconciler.purge(now).await.expect("purge");
    let left: Vec<_> = world
        .proposals(None)
        .await
        .into_iter()
        .map(|proposal| proposal.id)
        .collect();
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(
        left.contains(&open[1].id) && left.contains(&open[2].id),
        "the younger closed one and the open one stay"
    );
    let view = world
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    assert!(
        view.get_typed(&REJECTIONS, &open[0].key)
            .expect("read")
            .is_some(),
        "the person's rejection is still remembered"
    );
    let counted: Vec<_> = view
        .scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit")
        .into_iter()
        .filter(|(_, record, _)| record.draft.action.as_str() == PURGE_ACTION)
        .filter_map(|(_, record, _)| record.draft.details.context.get("proposals").cloned())
        .collect();
    assert_eq!(counted, vec!["1".to_owned()]);
    assert_eq!(removals_only_delete(&store), 1);
}
