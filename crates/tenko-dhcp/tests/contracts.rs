//! Tests of the engine contracts of WP7.0 and their in-memory reference implementations:
//! the lease table and the lease store against models, the feed against its image, the
//! configuration image and its exclusions, the reference allocator against the rules of the
//! plan, `grant_time`, the probe, the DDNS queue and the fingerprint rules.

mod support;

use std::{collections::BTreeMap, net::Ipv4Addr, time::Duration};

use ipnet::Ipv4Net;
use proptest::{prelude::*, test_runner::TestRunner};
use support::fixture;
use tenko_core::{
    HostId, InterfaceId, NodeId, PrefixId, RangeId, Revision, Timestamp, VrfId,
    dhcp::{
        BindingState, ClientKey, DdnsPolicy, DhcpSettings, Fingerprint, Lease, LeaseEventKind,
        LeaseTimes, Scope, SharedNetworkId, lease::MAX_IDENTITY, write_identity,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
    serde_util::HexBytes,
};
use tenko_dhcp::{
    allocator::{
        Allocator, Choice, NoOffers, OfferHold, PartnerLimit, ReferenceAllocator, Request,
        SingleNode, grant_time,
    },
    ddns::{DdnsAction, DdnsQueue, DdnsRequest, MemDdnsQueue, QueueFull},
    feed::{Change, Delta, DhcpData, DhcpFeed, FeedError, FeedEvent, MemFeed},
    fingerprint::{Fingerprinter, NoFingerprinter, OsGuess, Rule, RuleTable, fingerprint_of},
    image::{ConfigImage, ImageBuilder, PoolImage, ReservationImage, ScopeImage},
    lease::{LeaseTable, MemLeaseTable, PendingChange},
    probe::{ConflictProbe, MemProbe, NoProbe, ProbeOutcome},
    store::{CommitError, Completion, LeaseStore, MemLeaseStore, SubmitError, Ticket},
    v4::Message,
};

// ---------------------------------------------------------------------------------------
// Helpers

fn t0() -> Timestamp {
    "2026-10-22T12:00:00Z".parse().expect("time")
}

fn at(secs: u64) -> Timestamp {
    t0().checked_add(Duration::from_secs(secs)).expect("a time")
}

fn stamp() -> Stamp {
    Stamp::new(t0(), Principal::system(SystemComponent::Dhcp))
}

/// The hardware address of client `k` (RFC 7042 documentation range).
fn mac(k: u8) -> [u8; 6] {
    [0x00, 0x00, 0x5e, 0x00, 0x53, k]
}

/// Odd clients send a client identifier, even ones are known by their hardware address.
fn client_id(k: u8) -> Option<Vec<u8>> {
    (k % 2 == 1).then(|| vec![0xff, k, 0x00, 0x01])
}

fn identity_of(k: u8) -> Vec<u8> {
    let mut out = [0u8; MAX_IDENTITY];
    let len = write_identity(1, &mac(k), client_id(k).as_deref(), &mut out);
    out[..len].to_vec()
}

fn change(
    vrf: VrfId,
    scope: PrefixId,
    addr: Ipv4Addr,
    client: u8,
    state: BindingState,
    cltt: u64,
    ends: u64,
) -> PendingChange {
    PendingChange::new(
        LeaseEventKind::Granted,
        vrf,
        scope,
        addr,
        1,
        &mac(client),
        client_id(client).as_deref(),
        state,
        at(cltt),
        at(ends),
    )
}

fn pool_state() -> impl Strategy<Value = BindingState> {
    prop::sample::select(vec![
        BindingState::Active,
        BindingState::Expired,
        BindingState::Abandoned,
        BindingState::Released,
    ])
}

// ---------------------------------------------------------------------------------------
// MemLeaseTable

#[derive(Debug, Clone)]
struct Row {
    addr: u8,
    scope: usize,
    client: u8,
    cltt: u64,
    state: BindingState,
}

fn row() -> impl Strategy<Value = Row> {
    (0u8..4, 0usize..2, 0u8..4, 0u64..5, pool_state()).prop_map(
        |(addr, scope, client, cltt, state)| Row {
            addr,
            scope,
            client,
            cltt,
            state,
        },
    )
}

fn lease_of(row: &Row, vrf: VrfId, scopes: &[PrefixId]) -> Lease {
    change(
        vrf,
        scopes[row.scope],
        Ipv4Addr::new(192, 0, 2, 10 + row.addr),
        row.client,
        row.state,
        row.cltt,
        row.cltt + 100,
    )
    .to_lease(NodeId(1), None)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn the_table_keeps_the_row_with_the_greatest_client_time(
        rows in prop::collection::vec(row(), 0..40),
        removed in 0u8..5,
    ) {
        let vrf = VrfId::generate();
        let scopes = [PrefixId::generate(), PrefixId::generate()];
        let leases: Vec<Lease> = rows.iter().map(|r| lease_of(r, vrf, &scopes)).collect();
        let mut table = MemLeaseTable::default();
        let mut model: BTreeMap<Ipv4Addr, Lease> = BTreeMap::new();
        for lease in &leases {
            table.apply(lease.clone());
            // A later row with an equal time replaces the one held.
            if model.get(&lease.addr).is_none_or(|held| held.cltt <= lease.cltt) {
                model.insert(lease.addr, lease.clone());
            }
        }
        prop_assert_eq!(table.len(), model.len());
        prop_assert_eq!(table.is_empty(), model.is_empty());
        let held: Vec<&Lease> = table.rows().values().collect();
        prop_assert_eq!(held, model.values().collect::<Vec<_>>());
        for (addr, lease) in &model {
            prop_assert_eq!(table.get(vrf, *addr), Some(lease));
        }

        // The client index only names rows of the client and the scope.
        for scope in scopes {
            for client in 0..4 {
                let identity = identity_of(client);
                if let Some(found) = table.by_client(scope, &identity) {
                    prop_assert_eq!(found.client.identity(), identity);
                    prop_assert_eq!(found.scope, scope);
                    prop_assert_eq!(table.get(found.vrf, found.addr), Some(found));
                }
            }
        }

        // The rows built in one go are the rows applied one by one.
        let rebuilt = MemLeaseTable::from_rows(leases.clone());
        prop_assert_eq!(rebuilt.rows(), table.rows());

        // Applying every row a second time changes nothing, the client index included.
        let before = table.clone();
        for lease in &leases {
            table.apply(lease.clone());
        }
        prop_assert_eq!(&table, &before);

        // Removing drops the row and its index entry.
        let addr = Ipv4Addr::new(192, 0, 2, 10 + removed);
        let gone = model.remove(&addr);
        table.remove(vrf, addr);
        prop_assert!(table.get(vrf, addr).is_none());
        prop_assert_eq!(table.len(), model.len());
        if let Some(gone) = gone {
            let found = table.by_client(gone.scope, &gone.client.identity());
            prop_assert!(found.is_none_or(|lease| lease.addr != addr));
        } else {
            prop_assert_eq!(table.rows(), before.rows());
        }
        for (key, lease) in table.rows() {
            prop_assert_eq!(model.get(&key.1), Some(lease));
        }
    }

    #[test]
    fn an_older_copy_after_a_newer_one_changes_nothing(
        client_a in 0u8..4,
        client_b in 0u8..4,
        newer in 1u64..100,
        older in 0u64..100,
    ) {
        prop_assume!(older < newer);
        let vrf = VrfId::generate();
        let scope = PrefixId::generate();
        let addr = Ipv4Addr::new(192, 0, 2, 50);
        let now = change(vrf, scope, addr, client_a, BindingState::Active, newer, newer + 100)
            .to_lease(NodeId(1), None);
        let then = change(vrf, scope, addr, client_b, BindingState::Active, older, older + 100)
            .to_lease(NodeId(1), None);
        let mut table = MemLeaseTable::from_rows([now.clone()]);
        let before = table.clone();
        table.apply(then);
        prop_assert_eq!(&table, &before);
        prop_assert_eq!(table.by_client(scope, &identity_of(client_a)), Some(&now));
    }
}

/// A client with two rows in a scope keeps an index entry when the row it was indexed by
/// goes to another client, and a second pass changes nothing (found by the property above:
/// `192.0.2.12` for client 0 at 0, `192.0.2.11` for client 0 at 0, `192.0.2.11` for client
/// 1 at 1 once lost client 0's entry).
#[test]
fn applying_the_rows_again_changes_nothing_in_the_client_index() {
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let row = |last: u8, client: u8, cltt: u64| {
        change(
            vrf,
            scope,
            Ipv4Addr::new(192, 0, 2, last),
            client,
            BindingState::Active,
            cltt,
            cltt + 100,
        )
        .to_lease(NodeId(1), None)
    };
    let rows = [row(12, 0, 0), row(11, 0, 0), row(11, 1, 1)];
    let mut table = MemLeaseTable::default();
    for lease in &rows {
        table.apply(lease.clone());
    }
    assert_eq!(
        table
            .by_client(scope, &rows[0].client.identity())
            .map(|lease| lease.addr),
        Some(Ipv4Addr::new(192, 0, 2, 12))
    );
    let before = table.clone();
    for lease in &rows {
        table.apply(lease.clone());
    }
    assert_eq!(table, before);
}

// ---------------------------------------------------------------------------------------
// MemLeaseStore

#[derive(Debug, Clone)]
struct Submitted {
    addr: u8,
    client: u8,
    state: BindingState,
    cltt: u64,
}

fn submitted() -> impl Strategy<Value = Submitted> {
    (0u8..4, 0u8..4, pool_state(), 0u64..1000).prop_map(|(addr, client, state, cltt)| Submitted {
        addr,
        client,
        state,
        cltt,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn committed_changes_become_rows_an_index_and_history(
        changes in prop::collection::vec(submitted(), 1..30),
        batch in 1usize..8,
    ) {
        let node = NodeId(7);
        let vrf = VrfId::generate();
        let scopes = [PrefixId::generate(), PrefixId::generate()];
        let store = MemLeaseStore::with_capacity(node, batch);
        let mut pending = Vec::new();
        let mut done: Vec<Completion> = Vec::new();
        let mut model: BTreeMap<Ipv4Addr, PendingChange> = BTreeMap::new();
        for (index, spec) in changes.iter().enumerate() {
            // An address belongs to one scope, as it does to one prefix.
            let scope = scopes[usize::from(spec.addr % 2)];
            let addr = Ipv4Addr::new(192, 0, 2, 10 + spec.addr);
            let pending_change = change(vrf, scope, addr, spec.client, spec.state, spec.cltt, spec.cltt + 60);
            prop_assert!(store.accepting());
            prop_assert_eq!(store.submit(&pending_change, Ticket(index as u64)), Ok(()));
            model.insert(addr, pending_change.clone());
            pending.push(pending_change);
            if store.queued() == batch {
                prop_assert_eq!(store.commit(), batch);
            }
            store.completions(&mut done);
        }
        let rest = store.queued();
        prop_assert_eq!(store.commit(), rest);
        store.completions(&mut done);
        prop_assert_eq!(store.queued(), 0);

        // The revision counts the commits, and every completion is a commit in order.
        prop_assert_eq!(store.revision(), Revision(changes.len() as u64));
        prop_assert_eq!(done.len(), changes.len());
        for (index, completion) in done.iter().enumerate() {
            prop_assert_eq!(completion.ticket, Ticket(index as u64));
            prop_assert_eq!(&completion.outcome, &Ok(Revision(index as u64 + 1)));
        }
        let mut more = Vec::new();
        store.completions(&mut more);
        prop_assert!(more.is_empty());

        // One row per address, with the last change's client and state.
        let rows = store.leases();
        prop_assert_eq!(rows.len(), model.len());
        for (addr, last) in &model {
            let lease = rows.get(&(vrf, *addr)).expect("a row");
            prop_assert_eq!(&lease.client, &last.client());
            prop_assert_eq!(lease.state, last.state);
            prop_assert_eq!(lease.scope, last.scope);
            prop_assert_eq!(lease.cltt, last.cltt);
            prop_assert_eq!(lease.node, node);
        }

        // Every index entry names a row of its scope and its client.
        for ((scope, identity), target) in store.client_index() {
            let lease = rows.get(&(target.vrf, target.addr)).expect("the indexed row");
            prop_assert_eq!(lease.scope, scope);
            prop_assert_eq!(lease.client.identity(), identity);
        }

        // One history row per commit, in commit order.
        let history = store.history();
        prop_assert_eq!(history.len(), changes.len());
        for (event, change) in history.iter().zip(&pending) {
            prop_assert_eq!(event, &change.to_event(node));
        }

        // The committed rows feed a lease table that equals them.
        let table = MemLeaseTable::from_rows(rows.values().cloned());
        prop_assert_eq!(table.rows(), &rows);
    }
}

#[test]
fn a_refusing_store_answers_refused_and_fails_what_it_queued() {
    let node = NodeId(1);
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let one = |last: u8| {
        change(
            vrf,
            scope,
            Ipv4Addr::new(192, 0, 2, last),
            1,
            BindingState::Active,
            10,
            70,
        )
    };
    let store = MemLeaseStore::with_capacity(node, 4);
    assert!(store.accepting());
    store.submit(&one(10), Ticket(1)).expect("queued");
    store.submit(&one(11), Ticket(2)).expect("queued");

    store.set_refusing(true);
    assert!(!store.accepting());
    assert_eq!(store.submit(&one(12), Ticket(3)), Err(SubmitError::Refused));
    // The changes queued before the refusal fail when the committer reaches them.
    assert_eq!(store.commit(), 2);
    let mut done = Vec::new();
    store.completions(&mut done);
    assert_eq!(done.len(), 2);
    for (completion, ticket) in done.iter().zip([Ticket(1), Ticket(2)]) {
        assert_eq!(completion.ticket, ticket);
        assert!(
            matches!(completion.outcome, Err(CommitError::Refused(_))),
            "{completion:?}"
        );
    }
    assert!(store.leases().is_empty() && store.history().is_empty());
    assert!(store.client_index().is_empty());
    assert_eq!(store.revision(), Revision::ZERO);

    // Accepting again: the store takes changes and commits them from the revision it had.
    store.set_refusing(false);
    assert!(store.accepting());
    store.submit(&one(12), Ticket(3)).expect("queued");
    assert_eq!(store.commit(), 1);
    store.completions(&mut done);
    assert_eq!(done[2].outcome, Ok(Revision(1)));
}

#[test]
fn a_full_queue_answers_full_until_it_is_committed() {
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let one = |last: u8| {
        change(
            vrf,
            scope,
            Ipv4Addr::new(192, 0, 2, last),
            2,
            BindingState::Active,
            10,
            70,
        )
    };
    let store = MemLeaseStore::with_capacity(NodeId(1), 2);
    store.submit(&one(10), Ticket(1)).expect("queued");
    store.submit(&one(11), Ticket(2)).expect("queued");
    assert_eq!(store.queued(), 2);
    assert_eq!(store.submit(&one(12), Ticket(3)), Err(SubmitError::Full));
    // A full queue still accepts writes.
    assert!(store.accepting());
    assert_eq!(store.commit(), 2);
    store.submit(&one(12), Ticket(3)).expect("room again");
    assert_eq!(store.commit(), 1);
    let mut done = Vec::new();
    store.completions(&mut done);
    let revisions: Vec<_> = done.iter().map(|c| c.outcome.clone()).collect();
    assert_eq!(
        revisions,
        vec![Ok(Revision(1)), Ok(Revision(2)), Ok(Revision(3))]
    );
}

#[test]
fn a_client_that_moves_takes_its_index_entry_along() {
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let store = MemLeaseStore::with_capacity(NodeId(1), 8);
    let first = Ipv4Addr::new(192, 0, 2, 10);
    let second = Ipv4Addr::new(192, 0, 2, 11);
    let grant = |addr, client, cltt| {
        change(
            vrf,
            scope,
            addr,
            client,
            BindingState::Active,
            cltt,
            cltt + 60,
        )
    };
    for (index, pending) in [grant(first, 0, 1), grant(second, 0, 2), grant(first, 2, 3)]
        .iter()
        .enumerate()
    {
        store.submit(pending, Ticket(index as u64)).expect("queued");
    }
    store.commit();
    let index = store.client_index();
    // Client 0 is at the second address, client 2 took the first.
    assert_eq!(
        index.get(&(scope, identity_of(0))).map(|r| r.addr),
        Some(second)
    );
    assert_eq!(
        index.get(&(scope, identity_of(2))).map(|r| r.addr),
        Some(first)
    );
    assert_eq!(index.len(), 2);
}

// ---------------------------------------------------------------------------------------
// MemFeed

/// What the feed tests change.
#[derive(Debug, Clone)]
enum ChangeSpec {
    Settings(Option<u32>),
    Lease(u8, Option<u8>),
    Scope(usize, bool),
}

fn change_spec() -> impl Strategy<Value = ChangeSpec> {
    prop_oneof![
        prop::option::of(1u32..400).prop_map(ChangeSpec::Settings),
        (0u8..4, prop::option::of(0u8..4))
            .prop_map(|(addr, client)| ChangeSpec::Lease(addr, client)),
        (0usize..3, any::<bool>()).prop_map(|(scope, present)| ChangeSpec::Scope(scope, present)),
    ]
}

struct Ids {
    vrf: VrfId,
    scopes: [PrefixId; 3],
}

impl Ids {
    fn new() -> Self {
        Self {
            vrf: VrfId::generate(),
            scopes: [
                PrefixId::generate(),
                PrefixId::generate(),
                PrefixId::generate(),
            ],
        }
    }

    fn change(&self, spec: &ChangeSpec, serial: u64) -> Change {
        match spec {
            ChangeSpec::Settings(days) => Change::Settings(days.map(|history_days| DhcpSettings {
                history_days: Some(history_days),
                ..DhcpSettings::default()
            })),
            ChangeSpec::Lease(addr, client) => {
                let addr = Ipv4Addr::new(192, 0, 2, 10 + addr);
                Change::Lease(
                    (self.vrf, addr),
                    client.map(|client| {
                        change(
                            self.vrf,
                            self.scopes[0],
                            addr,
                            client,
                            BindingState::Active,
                            serial,
                            serial + 60,
                        )
                        .to_lease(NodeId(1), None)
                    }),
                )
            }
            ChangeSpec::Scope(index, present) => {
                let prefix = self.scopes[*index];
                Change::Scope(
                    prefix,
                    present.then(|| Scope {
                        prefix,
                        enabled: true,
                        lease: None,
                        authoritative: None,
                        server_id: None,
                        ddns: DdnsPolicy::default(),
                        shared_network: None,
                        restricted: serial.is_multiple_of(2),
                        classes: Vec::new(),
                        description: None,
                        created: stamp(),
                        updated: stamp(),
                    }),
                )
            }
        }
    }
}

#[derive(Debug, Clone)]
struct FeedCase {
    initial: Vec<ChangeSpec>,
    publishes: Vec<Vec<ChangeSpec>>,
    /// Where in the publishes the consumer takes its snapshot.
    snapshot_at: usize,
    /// Where one reset happens (a position at or after the snapshot), with the image it
    /// installs and how far it moves the revision.
    reset: Option<(usize, Vec<ChangeSpec>, u64)>,
}

fn feed_case() -> impl Strategy<Value = FeedCase> {
    (
        prop::collection::vec(change_spec(), 0..4),
        prop::collection::vec(prop::collection::vec(change_spec(), 0..4), 0..10),
        any::<usize>(),
        prop::option::of((
            any::<usize>(),
            prop::collection::vec(change_spec(), 0..5),
            1u64..5,
        )),
    )
        .prop_map(|(initial, publishes, snapshot, reset)| {
            let snapshot_at = snapshot % (publishes.len() + 1);
            let reset = reset.and_then(|(at, specs, jump)| {
                let room = publishes.len() - snapshot_at;
                (room > 0).then(|| (snapshot_at + at % room, specs, jump))
            });
            FeedCase {
                initial,
                publishes,
                snapshot_at,
                reset,
            }
        })
}

async fn run_feed_case(case: FeedCase) -> Result<(), TestCaseError> {
    let ids = Ids::new();
    let mut serial = 0;
    let mut next_change = |spec: &ChangeSpec| {
        serial += 1;
        ids.change(spec, serial)
    };
    let mut initial = DhcpData::at(Revision(3));
    for spec in &case.initial {
        initial.apply_change(&next_change(spec));
    }
    let (mut feed, handle) = MemFeed::new(initial);
    let mut consumer = None;
    for (index, specs) in case.publishes.iter().enumerate() {
        if index == case.snapshot_at {
            consumer = Some(feed.snapshot().await.expect("a snapshot"));
        }
        if let Some((_, reset_specs, jump)) = case.reset.as_ref().filter(|(at, ..)| *at == index) {
            let mut data = DhcpData::at(Revision(handle.image().revision.get() + jump));
            for spec in reset_specs {
                data.apply_change(&next_change(spec));
            }
            handle.reset(data);
        }
        let changes: Vec<Change> = specs.iter().map(&mut next_change).collect();
        let before = handle.image().revision;
        let published = handle.publish(changes);
        prop_assert_eq!(published, before.next());
        prop_assert_eq!(handle.image().revision, published);
    }
    let mut mine = match consumer {
        Some(data) => data,
        None => feed.snapshot().await.expect("a snapshot"),
    };
    let expected = handle.image();
    // With the writer gone the feed ends once the events are used up.
    drop(handle);
    loop {
        match feed.next().await {
            Ok(FeedEvent::Delta(delta)) => {
                prop_assert!(delta.from < delta.to);
                prop_assert_eq!(delta.from, mine.revision);
                mine.apply(&delta).expect("the delta follows the image");
            }
            Ok(FeedEvent::Reset(data)) => mine = *data,
            Err(error) => {
                prop_assert_eq!(error, FeedError::Closed);
                break;
            }
        }
    }
    prop_assert_eq!(mine, expected);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_consumer_that_follows_the_feed_holds_the_published_image() {
    let handle = tokio::runtime::Handle::current();
    let mut runner = TestRunner::new(ProptestConfig {
        cases: 128,
        failure_persistence: None,
        ..ProptestConfig::default()
    });
    runner
        .run(&feed_case(), |case| {
            tokio::task::block_in_place(|| handle.block_on(run_feed_case(case)))
        })
        .expect("the consumer holds the image");
}

#[tokio::test]
async fn a_waiting_consumer_wakes_for_each_publish_and_for_a_reset() {
    let ids = Ids::new();
    let (mut feed, handle) = MemFeed::new(DhcpData::at(Revision(1)));
    let mut image = feed.snapshot().await.expect("a snapshot");
    assert_eq!(image.revision, Revision(1));
    let consumer = tokio::spawn(async move {
        for _ in 0..3 {
            match feed.next().await.expect("an event") {
                FeedEvent::Delta(delta) => image.apply(&delta).expect("follows"),
                FeedEvent::Reset(data) => image = *data,
            }
        }
        (image, feed)
    });
    handle.publish(vec![ids.change(&ChangeSpec::Settings(Some(30)), 1)]);
    handle.publish(vec![ids.change(&ChangeSpec::Lease(0, Some(1)), 2)]);
    let mut reset = DhcpData::at(Revision(9));
    reset.apply_change(&ids.change(&ChangeSpec::Scope(1, true), 3));
    handle.reset(reset);
    let (image, mut feed) = consumer.await.expect("the consumer");
    assert_eq!(image, handle.image());
    assert_eq!(image.revision, Revision(9));
    assert_eq!(image.scopes.len(), 1);
    assert!(image.leases.is_empty());
    // The next publish continues from the reset image.
    handle.publish(Vec::new());
    let FeedEvent::Delta(delta) = feed.next().await.expect("an event") else {
        panic!("a delta");
    };
    assert_eq!((delta.from, delta.to), (Revision(9), Revision(10)));
    drop(handle);
    assert_eq!(feed.next().await, Err(FeedError::Closed));
}

proptest! {
    #[test]
    fn a_delta_applies_only_where_it_starts(
        held in 0u64..20,
        from in 0u64..20,
        to in 0u64..20,
        specs in prop::collection::vec(change_spec(), 0..5),
    ) {
        let ids = Ids::new();
        let mut data = DhcpData::at(Revision(held));
        data.apply_change(&ids.change(&ChangeSpec::Settings(Some(7)), 0));
        let before = data.clone();
        let changes: Vec<Change> = specs
            .iter()
            .enumerate()
            .map(|(serial, spec)| ids.change(spec, serial as u64 + 1))
            .collect();
        let delta = Delta { from: Revision(from), to: Revision(to), changes: changes.clone() };
        let outcome = data.apply(&delta);
        if from == held && to > from {
            prop_assert_eq!(outcome, Ok(()));
            prop_assert_eq!(data.revision, Revision(to));
            // Applying the changes again, on a copy at the new revision, changes nothing.
            let once = data.clone();
            for change in &changes {
                data.apply_change(change);
            }
            prop_assert_eq!(data, once);
        } else {
            prop_assert_eq!(
                outcome,
                Err(FeedError::Gap { held: Revision(held), from: Revision(from) })
            );
            prop_assert_eq!(data, before);
        }
    }
}

// ---------------------------------------------------------------------------------------
// The image

const NETS: [&str; 3] = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];

fn base_of(network: Ipv4Net) -> [u8; 3] {
    let [a, b, c, _] = network.network().octets();
    [a, b, c]
}

fn host_addr(network: Ipv4Net, last: u8) -> Ipv4Addr {
    let [a, b, c] = base_of(network);
    Ipv4Addr::new(a, b, c, last)
}

/// A scope image of `network` with pools and exclusions given as host octets.
fn scope_image(
    prefix: PrefixId,
    vrf: VrfId,
    network: Ipv4Net,
    pools: &[(u8, u8)],
    excluded: &[(u8, u8)],
    shared_network: Option<SharedNetworkId>,
) -> ScopeImage {
    ScopeImage {
        prefix,
        vrf,
        network,
        authoritative: true,
        restricted: false,
        server_id: None,
        lease: LeaseTimes::default(),
        shared_network,
        pools: pools
            .iter()
            .map(|(first, last)| PoolImage {
                range: RangeId::generate(),
                first: host_addr(network, *first),
                last: host_addr(network, *last),
                lease: LeaseTimes::default(),
                classes: Vec::new(),
                options: Vec::new(),
            })
            .collect(),
        excluded: excluded
            .iter()
            .map(|(first, last)| (host_addr(network, *first), host_addr(network, *last)))
            .collect(),
        options: Vec::new(),
        classes: Vec::new(),
        ddns: DdnsPolicy::default(),
    }
}

fn ordered(pair: (u8, u8)) -> (u8, u8) {
    (pair.0.min(pair.1), pair.0.max(pair.1))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn exclusions_are_merged_and_checked_like_the_given_ranges(
        ranges in prop::collection::vec(any::<(u8, u8)>().prop_map(ordered), 0..10),
        pool in any::<(u8, u8)>().prop_map(ordered),
    ) {
        let network: Ipv4Net = NETS[0].parse().expect("a network");
        let build = |ranges: &[(u8, u8)]| {
            let mut builder = ImageBuilder::new(Revision(4));
            builder.scope(scope_image(
                PrefixId::generate(),
                VrfId::generate(),
                network,
                &[pool],
                ranges,
                None,
            ));
            builder.build()
        };
        let image = build(&ranges);
        prop_assert_eq!(image.revision(), Revision(4));
        let scope = &image.scopes()[0];
        for last in 0..=255u8 {
            let naive = last == 0
                || last == 255
                || ranges.iter().any(|(first, end)| *first <= last && last <= *end);
            let addr = host_addr(network, last);
            prop_assert_eq!(scope.is_excluded(addr), naive, "{}", addr);
            let in_pool = pool.0 <= last && last <= pool.1;
            prop_assert_eq!(scope.is_dynamic(addr), in_pool && !naive, "{}", addr);
            prop_assert_eq!(scope.pool_of(addr).is_some(), in_pool);
        }
        // An address of another network is not excluded by this one's ranges, whatever they
        // are, unless it falls in a merged range by number: the check is by address only.
        // The ranges are sorted, disjoint and do not touch.
        for pair in scope.excluded.windows(2) {
            prop_assert!(u64::from(u32::from(pair[0].1)) + 1 < u64::from(u32::from(pair[1].0)));
        }
        for (first, last) in &scope.excluded {
            prop_assert!(first <= last);
        }
        // The order the ranges are given in does not matter.
        let mut reversed = ranges.clone();
        reversed.reverse();
        let other = build(&reversed);
        prop_assert_eq!(&other.scopes()[0].excluded, &scope.excluded);
    }

    #[test]
    fn selection_takes_the_most_specific_scope_and_siblings_the_shared_network(
        networks in prop::sample::subsequence(
            vec![
                "192.0.2.0/24", "192.0.2.0/25", "192.0.2.128/25", "192.0.2.0/26",
                "198.51.100.0/24", "198.51.100.64/26", "203.0.113.0/25",
            ],
            0..=7,
        ),
        sharing in prop::collection::vec(prop::option::of(0usize..2), 7),
        probes in prop::collection::vec((0usize..4, any::<u8>()), 1..20),
    ) {
        let vrf = VrfId::generate();
        let shared = [SharedNetworkId::generate(), SharedNetworkId::generate()];
        let mut builder = ImageBuilder::new(Revision::ZERO);
        let mut expected: Vec<(Ipv4Net, PrefixId, Option<usize>)> = Vec::new();
        for (index, text) in networks.iter().enumerate() {
            let network: Ipv4Net = text.parse().expect("a network");
            let prefix = PrefixId::generate();
            builder.scope(scope_image(
                prefix,
                vrf,
                network,
                &[(10, 20)],
                &[],
                sharing[index].map(|n| shared[n]),
            ));
            expected.push((network, prefix, sharing[index]));
        }
        let image = builder.build();
        prop_assert_eq!(image.scopes().len(), expected.len());
        // The scopes are sorted by network.
        for pair in image.scopes().windows(2) {
            prop_assert!(pair[0].network.network() <= pair[1].network.network());
        }
        for (base, last) in probes {
            let addr = match base {
                0 => Ipv4Addr::new(192, 0, 2, last),
                1 => Ipv4Addr::new(198, 51, 100, last),
                2 => Ipv4Addr::new(203, 0, 113, last),
                _ => Ipv4Addr::new(10, 0, 0, last),
            };
            let best = expected
                .iter()
                .filter(|(network, ..)| network.contains(&addr))
                .max_by_key(|(network, ..)| network.prefix_len());
            prop_assert_eq!(image.select(addr).map(|s| s.prefix), best.map(|(_, prefix, _)| *prefix));
            if let Some(selected) = image.select(addr) {
                prop_assert!(selected.network.contains(&addr));
            }
        }
        for (_, prefix, sharing) in &expected {
            let scope = image.scope(*prefix).expect("the scope");
            let siblings: Vec<PrefixId> = image.siblings(scope).map(|s| s.prefix).collect();
            prop_assert_eq!(siblings[0], *prefix);
            let mut others: Vec<PrefixId> = siblings[1..].to_vec();
            others.sort();
            let mut wanted: Vec<PrefixId> = expected
                .iter()
                .filter(|(_, other, group)| other != prefix && group.is_some() && group == sharing)
                .map(|(_, other, _)| *other)
                .collect();
            wanted.sort();
            prop_assert_eq!(others, wanted);
        }
    }

    #[test]
    fn the_first_reservation_of_a_client_or_an_address_wins(
        reservations in prop::collection::vec((0u8..4, 0usize..2, 1u8..6), 0..12),
    ) {
        let vrf = VrfId::generate();
        let prefixes = [PrefixId::generate(), PrefixId::generate()];
        let mut builder = ImageBuilder::new(Revision::ZERO);
        for (index, text) in NETS.iter().take(2).enumerate() {
            builder.scope(scope_image(
                prefixes[index],
                vrf,
                text.parse().expect("a network"),
                &[(10, 20)],
                &[],
                None,
            ));
        }
        let nets: Vec<Ipv4Net> = NETS.iter().map(|n| n.parse().expect("a network")).collect();
        let mut kept: Vec<ReservationImage> = Vec::new();
        for (client, scope, last) in reservations {
            let candidate = ReservationImage {
                scope: prefixes[scope],
                addr: host_addr(nets[scope], last),
                host: HostId::generate(),
                interface: InterfaceId::generate(),
                identity: identity_of(client),
                options: Vec::new(),
            };
            let clash = kept.iter().any(|held| {
                held.scope == candidate.scope
                    && (held.identity == candidate.identity || held.addr == candidate.addr)
            });
            let dropped = builder.reservation(candidate.clone());
            prop_assert_eq!(dropped.is_some(), clash);
            if !clash {
                kept.push(candidate);
            }
        }
        let image = builder.build();
        prop_assert_eq!(image.reservations(), kept.as_slice());
        for held in &kept {
            prop_assert_eq!(image.reservation(held.scope, &held.identity), Some(held));
            prop_assert_eq!(image.reserved_at(held.scope, held.addr), Some(held));
        }
    }
}

// ---------------------------------------------------------------------------------------
// The reference allocator

#[derive(Debug, Clone)]
struct ScopeSpec {
    pool_a: (u8, u8),
    pool_b: Option<(u8, u8)>,
    excluded: Vec<(u8, u8)>,
    shared: bool,
}

fn scope_spec() -> impl Strategy<Value = ScopeSpec> {
    (
        (1u8..60, 0u8..40),
        prop::option::of((100u8..180, 0u8..30)),
        prop::collection::vec((1u8..=254, 0u8..30), 0..4),
        any::<bool>(),
    )
        .prop_map(|(pool_a, pool_b, excluded, shared)| ScopeSpec {
            pool_a: (pool_a.0, pool_a.0 + pool_a.1),
            pool_b: pool_b.map(|(first, len)| (first, first + len)),
            excluded: excluded
                .into_iter()
                .map(|(first, len)| (first, first.saturating_add(len).min(254)))
                .collect(),
            shared,
        })
}

#[derive(Debug, Clone)]
struct Step {
    client: u8,
    scope: usize,
    requested: Option<(usize, u8)>,
    advance: u64,
    lease_secs: u64,
}

fn step() -> impl Strategy<Value = Step> {
    (
        0u8..5,
        0usize..3,
        prop::option::of((0usize..3, 1u8..=254)),
        0u64..300,
        60u64..500,
    )
        .prop_map(|(client, scope, requested, advance, lease_secs)| Step {
            client,
            scope,
            requested,
            advance,
            lease_secs,
        })
}

/// An offer held for one client.
struct HeldFor {
    addr: Ipv4Addr,
    owner: Vec<u8>,
}

impl OfferHold for HeldFor {
    fn held_for_other(&self, _: PrefixId, addr: Ipv4Addr, identity: &[u8], _: Timestamp) -> bool {
        addr == self.addr && identity != self.owner
    }
}

struct World {
    image: ConfigImage,
    vrf: VrfId,
    /// The exclusions as given, per scope, to check the image against.
    excluded: BTreeMap<PrefixId, Vec<(Ipv4Addr, Ipv4Addr)>>,
}

fn world(specs: &[ScopeSpec], reservations: &[(u8, usize, u8)]) -> World {
    let vrf = VrfId::generate();
    let shared = SharedNetworkId::generate();
    let mut builder = ImageBuilder::new(Revision(1));
    let mut excluded = BTreeMap::new();
    let mut prefixes = Vec::new();
    let mut networks = Vec::new();
    for (index, spec) in specs.iter().enumerate() {
        let network: Ipv4Net = NETS[index].parse().expect("a network");
        let prefix = PrefixId::generate();
        let mut pools = vec![spec.pool_a];
        pools.extend(spec.pool_b);
        builder.scope(scope_image(
            prefix,
            vrf,
            network,
            &pools,
            &spec.excluded,
            spec.shared.then_some(shared),
        ));
        excluded.insert(
            prefix,
            spec.excluded
                .iter()
                .map(|(first, last)| (host_addr(network, *first), host_addr(network, *last)))
                .collect(),
        );
        prefixes.push(prefix);
        networks.push(network);
    }
    for (client, scope, last) in reservations {
        let index = scope % specs.len();
        // A clash with an earlier reservation is dropped by the builder.
        let _ = builder.reservation(ReservationImage {
            scope: prefixes[index],
            addr: host_addr(networks[index], *last),
            host: HostId::generate(),
            interface: InterfaceId::generate(),
            identity: identity_of(*client),
            options: Vec::new(),
        });
    }
    World {
        image: builder.build(),
        vrf,
        excluded,
    }
}

/// The rules of the plan, written out again: whether `addr` may go to the client.
fn free_for(
    world: &World,
    table: &MemLeaseTable,
    hold: Option<&(Ipv4Addr, Vec<u8>)>,
    scope: &ScopeImage,
    addr: Ipv4Addr,
    identity: &[u8],
    now: Timestamp,
) -> bool {
    let in_pool = scope
        .pools
        .iter()
        .any(|p| p.first <= addr && addr <= p.last);
    let excluded = addr == scope.network.network()
        || addr == scope.network.broadcast()
        || world.excluded[&scope.prefix]
            .iter()
            .any(|(first, last)| *first <= addr && addr <= *last);
    in_pool
        && !excluded
        && world
            .image
            .reserved_at(scope.prefix, addr)
            .is_none_or(|r| r.identity == identity)
        && table
            .get(world.vrf, addr)
            .is_none_or(|l| !l.blocks(now) || l.client.identity() == identity)
        && hold.is_none_or(|(held, owner)| *held != addr || owner == identity)
}

/// The plan's order: reservation, unexpired lease, the address asked for, the first free
/// pool address.
fn expected_choice(
    world: &World,
    table: &MemLeaseTable,
    hold: Option<&(Ipv4Addr, Vec<u8>)>,
    siblings: &[&ScopeImage],
    identity: &[u8],
    requested: Option<Ipv4Addr>,
    now: Timestamp,
) -> Option<Choice> {
    if let Some(reservation) = siblings
        .iter()
        .find_map(|s| world.image.reservation(s.prefix, identity))
    {
        return Some(Choice::Reservation(reservation.addr));
    }
    for scope in siblings {
        if let Some(lease) = table.by_client(scope.prefix, identity)
            && lease.state == BindingState::Active
            && lease.ends > now
            && free_for(world, table, hold, scope, lease.addr, identity, now)
        {
            return Some(Choice::Lease(lease.addr));
        }
    }
    if let Some(asked) = requested
        && siblings.iter().any(|s| {
            s.network.contains(&asked) && free_for(world, table, hold, s, asked, identity, now)
        })
    {
        return Some(Choice::Requested(asked));
    }
    for scope in siblings {
        for pool in &scope.pools {
            for raw in u32::from(pool.first)..=u32::from(pool.last) {
                let addr = Ipv4Addr::from(raw);
                if free_for(world, table, hold, scope, addr, identity, now) {
                    return Some(Choice::Pool(addr));
                }
            }
        }
    }
    None
}

#[allow(
    clippy::too_many_lines,
    reason = "one scenario read top to bottom: build, seed, then check every pick"
)]
fn run_allocation(
    specs: &[ScopeSpec],
    reservations: &[(u8, usize, u8)],
    foreign: &[(usize, u8, u8, u64)],
    steps: &[Step],
    hold: Option<(u8, u8)>,
) -> Result<(), TestCaseError> {
    let world = world(specs, reservations);
    let image = &world.image;
    let mut table = MemLeaseTable::default();
    // Leases of clients that never ask, in every state.
    for (scope, last, state, ends) in foreign {
        let scope = &image.scopes()[scope % specs.len()];
        let state = [
            BindingState::Active,
            BindingState::Abandoned,
            BindingState::Expired,
        ][usize::from(state % 3)];
        table.apply(
            change(
                world.vrf,
                scope.prefix,
                host_addr(scope.network, *last),
                200,
                state,
                0,
                *ends,
            )
            .to_lease(NodeId(1), None),
        );
    }
    // The offer held for one client: the first pool address of the first scope plus a shift.
    let hold = hold.map(|(shift, owner)| {
        let first = image.scopes()[0].pools[0].first;
        (
            Ipv4Addr::from(u32::from(first) + u32::from(shift % 5)),
            identity_of(owner % 6),
        )
    });
    let held_for = hold.as_ref().map(|(addr, owner)| HeldFor {
        addr: *addr,
        owner: owner.clone(),
    });
    let offers: &dyn OfferHold = held_for.as_ref().map_or(&NoOffers, |held| held);

    let mut elapsed = 0;
    for step in steps {
        elapsed += step.advance;
        let now = at(elapsed);
        let scope = &image.scopes()[step.scope % specs.len()];
        let identity = identity_of(step.client);
        let requested = step
            .requested
            .map(|(index, last)| host_addr(image.scopes()[index % specs.len()].network, last));
        let request = Request {
            image,
            scope,
            identity: &identity,
            requested,
            leases: &table,
            offers,
            ownership: &SingleNode,
            now,
        };
        let choice = ReferenceAllocator.pick(&request);
        // The same inputs give the same pick.
        prop_assert_eq!(choice, ReferenceAllocator.pick(&request));

        let siblings: Vec<&ScopeImage> = image.siblings(scope).collect();
        let reservation = siblings
            .iter()
            .find_map(|s| image.reservation(s.prefix, &identity));
        let expected = expected_choice(
            &world,
            &table,
            hold.as_ref(),
            &siblings,
            &identity,
            requested,
            now,
        );
        prop_assert_eq!(choice, expected, "client {} at {}", step.client, elapsed);

        // A client with a reservation always gets it.
        if let Some(reservation) = reservation {
            prop_assert_eq!(choice, Some(Choice::Reservation(reservation.addr)));
        }
        let Some(choice) = choice else { continue };
        let addr = choice.addr();
        if !matches!(choice, Choice::Reservation(_)) {
            // In a pool of the scope or a sibling, not excluded.
            let home = siblings.iter().find(|s| s.network.contains(&addr));
            let home = home.expect("a pick lies in a scope of the shared network");
            prop_assert!(home.pools.iter().any(|p| p.first <= addr && addr <= p.last));
            prop_assert!(!home.is_excluded(addr));
            prop_assert!(home.is_dynamic(addr));
            // Not reserved for another client.
            for sibling in &siblings {
                prop_assert!(
                    image
                        .reserved_at(sibling.prefix, addr)
                        .is_none_or(|r| r.identity == identity)
                );
            }
            // Not held by another client's lease.
            if let Some(lease) = table.get(world.vrf, addr) {
                prop_assert!(!lease.blocks(now) || lease.client.identity() == identity);
            }
            // Not held by an offer for another client.
            if let Some((held, owner)) = &hold {
                prop_assert!(*held != addr || *owner == identity);
            }
            // The lease of the client comes back as it is.
            if let Some(lease) = siblings
                .iter()
                .find_map(|s| table.by_client(s.prefix, &identity))
                && lease.is_bound(now)
                && lease.addr == addr
            {
                prop_assert!(matches!(choice, Choice::Lease(_)));
            }
        }
        // The pick becomes an active lease.
        let home = siblings
            .iter()
            .find(|s| s.network.contains(&addr))
            .expect("a scope holds the address");
        let granted = change(
            world.vrf,
            home.prefix,
            addr,
            step.client,
            BindingState::Active,
            elapsed,
            elapsed + step.lease_secs,
        )
        .to_lease(NodeId(1), table.get(world.vrf, addr));
        table.apply(granted);
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn picks_obey_the_rules_of_the_plan(
        specs in prop::collection::vec(scope_spec(), 1..=3),
        reservations in prop::collection::vec((0u8..5, 0usize..3, 1u8..=254), 0..5),
        foreign in prop::collection::vec((0usize..3, 1u8..=254, 0u8..3, 0u64..700), 0..8),
        steps in prop::collection::vec(step(), 1..25),
        hold in prop::option::of((0u8..5, 0u8..6)),
    ) {
        run_allocation(&specs, &reservations, &foreign, &steps, hold)?;
    }
}

#[test]
fn a_held_offer_is_never_picked_for_another_client() {
    // One scope, one pool of three addresses: the first is held for client 5.
    let world = world(
        &[ScopeSpec {
            pool_a: (10, 12),
            pool_b: None,
            excluded: Vec::new(),
            shared: false,
        }],
        &[],
    );
    let scope = &world.image.scopes()[0];
    let held = HeldFor {
        addr: host_addr(scope.network, 10),
        owner: identity_of(5),
    };
    let table = MemLeaseTable::default();
    let pick = |client: u8, requested: Option<Ipv4Addr>, offers: &dyn OfferHold| {
        let identity = identity_of(client);
        ReferenceAllocator.pick(&Request {
            image: &world.image,
            scope,
            identity: &identity,
            requested,
            leases: &table,
            offers,
            ownership: &SingleNode,
            now: t0(),
        })
    };
    // Another client is passed over it, even when it asks for it.
    assert_eq!(
        pick(1, None, &held),
        Some(Choice::Pool(host_addr(scope.network, 11)))
    );
    assert_eq!(
        pick(1, Some(held.addr), &held),
        Some(Choice::Pool(host_addr(scope.network, 11)))
    );
    // The owner gets it, and without the hold so does everyone.
    assert_eq!(pick(5, None, &held), Some(Choice::Pool(held.addr)));
    assert_eq!(pick(1, None, &NoOffers), Some(Choice::Pool(held.addr)));
    assert_eq!(
        pick(1, Some(held.addr), &NoOffers),
        Some(Choice::Requested(held.addr))
    );
}

#[test]
fn a_scope_without_a_free_address_picks_nothing_and_a_sibling_helps() {
    let vrf = VrfId::generate();
    let shared = SharedNetworkId::generate();
    let mut builder = ImageBuilder::new(Revision::ZERO);
    let first = PrefixId::generate();
    let second = PrefixId::generate();
    let a: Ipv4Net = NETS[0].parse().expect("a network");
    let b: Ipv4Net = NETS[1].parse().expect("a network");
    builder.scope(scope_image(first, vrf, a, &[(10, 10)], &[], Some(shared)));
    builder.scope(scope_image(second, vrf, b, &[(20, 20)], &[], Some(shared)));
    let image = builder.build();
    let scope = image.scope(first).expect("the first scope");
    let mut table = MemLeaseTable::default();
    let identity = identity_of(1);
    let request = |table: &MemLeaseTable, identity: &[u8]| {
        ReferenceAllocator.pick(&Request {
            image: &image,
            scope,
            identity,
            requested: None,
            leases: table,
            offers: &NoOffers,
            ownership: &SingleNode,
            now: t0(),
        })
    };
    // The only address of the scope is leased to another client: the sibling's is next.
    table.apply(
        change(
            vrf,
            first,
            host_addr(a, 10),
            2,
            BindingState::Active,
            0,
            3_600,
        )
        .to_lease(NodeId(1), None),
    );
    assert_eq!(
        request(&table, &identity),
        Some(Choice::Pool(host_addr(b, 20)))
    );
    // Both taken: nothing is left.
    table.apply(
        change(
            vrf,
            second,
            host_addr(b, 20),
            3,
            BindingState::Abandoned,
            0,
            3_600,
        )
        .to_lease(NodeId(1), None),
    );
    assert_eq!(request(&table, &identity), None);
    // The client that holds the first address gets it again.
    assert_eq!(
        request(&table, &identity_of(2)),
        Some(Choice::Lease(host_addr(a, 10)))
    );
}

// ---------------------------------------------------------------------------------------
// grant_time

fn lease_times() -> impl Strategy<Value = LeaseTimes> {
    (1u32..100_000, 0u32..100_000, 0u32..100_000).prop_map(|(min_secs, up, more)| LeaseTimes {
        default_secs: min_secs + up,
        min_secs,
        max_secs: min_secs + up + more,
        t1_secs: None,
        t2_secs: None,
    })
}

proptest! {
    #[test]
    fn the_grant_follows_the_scope_and_is_capped_by_the_partner(
        times in lease_times(),
        requested in any::<Option<u32>>(),
        acknowledged_secs in any::<u32>(),
        mclt_secs in any::<u32>(),
    ) {
        let granted = times.grant(requested);
        prop_assert_eq!(grant_time(&times, requested, None), granted);
        let limit = PartnerLimit { acknowledged_secs, mclt_secs };
        let capped = grant_time(&times, requested, Some(limit));
        prop_assert!(capped <= granted);
        prop_assert!(capped <= acknowledged_secs.saturating_add(mclt_secs));
        prop_assert_eq!(capped, granted.min(acknowledged_secs.saturating_add(mclt_secs)));
        // A new binding (nothing acknowledged yet) gets at most the MCLT.
        let fresh = grant_time(&times, requested, Some(PartnerLimit { acknowledged_secs: 0, mclt_secs }));
        prop_assert!(fresh <= mclt_secs);
    }
}

// ---------------------------------------------------------------------------------------
// Probe, DDNS queue, fingerprints

#[tokio::test]
async fn the_reference_probe_answers_for_squatted_addresses() {
    let probe = MemProbe::default();
    assert!(probe.available());
    let taken = Ipv4Addr::new(192, 0, 2, 50);
    let silent = Ipv4Addr::new(192, 0, 2, 51);
    let free = Ipv4Addr::new(192, 0, 2, 52);
    probe.squat(taken, Some(mac(9)));
    probe.squat(silent, None);
    let wait = Duration::from_millis(300);
    assert_eq!(
        probe.probe(taken, wait).await,
        ProbeOutcome::InUse { mac: Some(mac(9)) }
    );
    assert_eq!(probe.probe(free, wait).await, ProbeOutcome::Clear);
    assert_eq!(
        probe.probe(silent, wait).await,
        ProbeOutcome::InUse { mac: None }
    );
    assert_eq!(
        probe.probe(taken, wait).await,
        ProbeOutcome::InUse { mac: Some(mac(9)) }
    );
    assert_eq!(probe.probed(), vec![taken, free, silent, taken]);
}

#[tokio::test]
async fn no_probe_is_not_available_and_probes_nothing() {
    let probe = NoProbe;
    assert!(!probe.available());
    for last in [1u8, 50, 254] {
        assert_eq!(
            probe
                .probe(Ipv4Addr::new(192, 0, 2, last), Duration::from_millis(300))
                .await,
            ProbeOutcome::Unavailable
        );
    }
}

fn ddns_request(last: u8, action: DdnsAction) -> DdnsRequest {
    DdnsRequest {
        action,
        vrf: VrfId::generate(),
        scope: PrefixId::generate(),
        addr: Ipv4Addr::new(192, 0, 2, last),
        client: ClientKey {
            htype: 1,
            chaddr: HexBytes(mac(last).to_vec()),
            client_id: None,
        },
        fqdn: None,
        hostname: Some(format!("host{last}")),
        fqdn_flags: None,
        policy: DdnsPolicy::default(),
        lease_secs: 3_600,
        ends: at(3_600),
    }
}

#[test]
fn the_ddns_queue_is_bounded_and_first_in_first_out() {
    let queue = MemDdnsQueue::new(2);
    assert!(queue.is_empty());
    assert_eq!(queue.len(), 0);
    let first = ddns_request(10, DdnsAction::Add);
    let second = ddns_request(11, DdnsAction::Remove);
    assert_eq!(queue.enqueue(first.clone()), Ok(()));
    assert_eq!(queue.enqueue(second.clone()), Ok(()));
    assert_eq!(queue.len(), 2);
    assert!(!queue.is_empty());
    assert_eq!(
        queue.enqueue(ddns_request(12, DdnsAction::Add)),
        Err(QueueFull)
    );
    assert_eq!(queue.len(), 2);
    assert_eq!(queue.drain(), vec![first, second]);
    assert!(queue.is_empty());
    assert_eq!(queue.drain(), Vec::new());
    // Room again after a drain.
    assert_eq!(queue.enqueue(ddns_request(12, DdnsAction::Add)), Ok(()));
    assert_eq!(queue.len(), 1);
    // A queue of none takes nothing.
    assert_eq!(
        MemDdnsQueue::new(0).enqueue(ddns_request(1, DdnsAction::Add)),
        Err(QueueFull)
    );
}

fn guess(family: &str, confidence: u8) -> OsGuess {
    OsGuess {
        family: family.to_owned(),
        version: None,
        confidence,
    }
}

fn print(parameters: &[u8], vendor_class: Option<&str>) -> Fingerprint {
    Fingerprint {
        parameters: HexBytes(parameters.to_vec()),
        vendor_class: vendor_class.map(str::to_owned),
        ..Fingerprint::default()
    }
}

#[test]
fn the_first_matching_rule_wins() {
    let table = RuleTable::new(vec![
        Rule {
            parameters: Some(vec![1, 3, 6]),
            vendor_prefix: None,
            guess: guess("linux", 60),
        },
        Rule {
            parameters: None,
            vendor_prefix: Some("MSFT".to_owned()),
            guess: guess("windows", 80),
        },
        Rule {
            parameters: None,
            vendor_prefix: None,
            guess: guess("unknown", 5),
        },
    ]);
    // The parameter list rule is first, whatever the vendor says.
    assert_eq!(
        table.classify(&print(&[1, 3, 6], Some("MSFT 5.0"))),
        Some(guess("linux", 60))
    );
    // The vendor prefix rule, then the catch-all.
    assert_eq!(
        table.classify(&print(&[1, 3, 6, 15], Some("MSFT 5.0"))),
        Some(guess("windows", 80))
    );
    assert_eq!(
        table.classify(&print(&[1, 3, 6, 15], Some("msft"))),
        Some(guess("unknown", 5))
    );
    assert_eq!(table.classify(&print(&[], None)), Some(guess("unknown", 5)));
    // Without the catch-all nothing matches a client without a vendor class.
    let strict = RuleTable::new(vec![Rule {
        parameters: None,
        vendor_prefix: Some("MSFT".to_owned()),
        guess: guess("windows", 80),
    }]);
    assert_eq!(strict.classify(&print(&[1], None)), None);
    assert_eq!(
        RuleTable::default().classify(&print(&[1], Some("MSFT"))),
        None
    );
    // A table that is not asked cannot answer, and none answers none.
    for fingerprint in [print(&[], None), print(&[1, 3, 6], Some("MSFT 5.0"))] {
        assert_eq!(NoFingerprinter.classify(&fingerprint), None);
    }
}

proptest! {
    #[test]
    fn a_rule_table_answers_with_the_first_rule_that_matches(
        rules in prop::collection::vec(
            (
                prop::option::of(prop::collection::vec(0u8..3, 0..3)),
                prop::option::of(prop::sample::select(vec!["a", "ab", "b"])),
            ),
            0..6,
        ),
        parameters in prop::collection::vec(0u8..3, 0..3),
        vendor in prop::option::of(prop::sample::select(vec!["a", "ab", "abc", "b", "ba", ""])),
    ) {
        let table = RuleTable::new(
            rules
                .iter()
                .enumerate()
                .map(|(index, (list, prefix))| Rule {
                    parameters: list.clone(),
                    vendor_prefix: prefix.map(str::to_owned),
                    guess: guess("rule", u8::try_from(index).expect("few rules")),
                })
                .collect(),
        );
        let fingerprint = print(&parameters, vendor);
        let expected = rules.iter().position(|(list, prefix)| {
            list.as_ref().is_none_or(|list| *list == parameters)
                && prefix.is_none_or(|prefix| vendor.is_some_and(|class| class.starts_with(prefix)))
        });
        prop_assert_eq!(
            table.classify(&fingerprint).map(|g| usize::from(g.confidence)),
            expected
        );
    }
}

#[test]
fn the_windows_discover_has_a_fingerprint() {
    let bytes = fixture("windows-discover");
    let message = Message::parse(&bytes).expect("a message");
    let fingerprint = fingerprint_of(&message);
    assert_eq!(
        fingerprint.parameters.0,
        vec![
            0x01, 0x03, 0x06, 0x0f, 0x1f, 0x21, 0x2b, 0x2c, 0x2e, 0x2f, 0x77, 0x79, 0xf9, 0xfc
        ]
    );
    assert_eq!(fingerprint.vendor_class.as_deref(), Some("MSFT 5.0"));
    assert!(!fingerprint.user_class);
    assert!(!fingerprint.client_fqdn);
    assert_eq!(fingerprint.architecture, None);
    // A rule written for the list classifies it.
    let table = RuleTable::new(vec![Rule {
        parameters: Some(fingerprint.parameters.0.clone()),
        vendor_prefix: Some("MSFT".to_owned()),
        guess: guess("windows", 90),
    }]);
    assert_eq!(table.classify(&fingerprint), Some(guess("windows", 90)));
}
