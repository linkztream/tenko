//! The DHCPv6 lease store on the replicated store (WP9.1): `StoreLeases6` and its
//! committer over the in-memory store, as `lease_store.rs` tests the DHCPv4 `StoreLeases`.
//!
//! - One change with two bindings commits two rows at one revision, and its two history
//!   rows follow in one batch of the asynchronous writer (ADR 0030).
//! - Another client's binding is refused whole and nothing is written; an operator's
//!   reclaim and an ended hold do not count as held.
//! - The refusal gate is shared with the DHCPv4 store: a refusing store closes both
//!   hand-offs, in either direction, and one commit opens both.
//! - A burst of concurrent changes for different clients all commit, and rows, history and
//!   table agree.
//! - `Expiry6Service::round` expires an active binding past its end and an abandoned address
//!   past its hold, with a history row of kind `expired` each.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv6Addr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tenko_core::{
    NodeId, PrefixId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, Lease6, Lease6Event, Lease6Kind, LeaseEventKind, tables},
};
use tenko_dhcp::{
    lease::{CommitSettings, ExpirySettings, LeaseIndex, PendingChange, SharedLeases, StoreLeases},
    store::{CommitError, Completion, LeaseStore as _, SubmitError, Ticket},
    v6::lease::{
        Binding6, Lease6Index, Lease6Table as _, PendingChange6, SharedLeases6,
        commit::StoreLeases6, expiry::Expiry6Service, store::Lease6Store as _,
    },
};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, KeyRange, Leadership, MemStore, MemStoreConfig,
    ReadConsistency, ReadView, ReadViewExt as _, Store, StoreError, StoreStatus, WatchFilter,
    WriteBatch,
};
use tokio_util::sync::CancellationToken;

const NODE: NodeId = NodeId(1);

fn ago(secs: u64) -> Timestamp {
    let now = Timestamp::now();
    Timestamp::from_unix_nanos(now.unix_nanos() - i128::from(secs) * 1_000_000_000).expect("a time")
}

fn from_now(secs: u64) -> Timestamp {
    Timestamp::now()
        .checked_add(Duration::from_secs(secs))
        .expect("a time")
}

fn addr(last: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x100 + last)
}

/// The DUID-LL of client `k` (RFC 7042 documentation MACs).
fn duid(k: u32) -> Vec<u8> {
    let k = k.to_be_bytes();
    vec![0, 3, 0, 1, 0x00, 0x00, 0x5e, k[1], k[2], k[3]]
}

fn mem_store() -> Arc<dyn Store> {
    Arc::new(MemStore::new(MemStoreConfig::default()))
}

/// A binding of an address for IAID `iaid`.
fn binding(
    event: LeaseEventKind,
    vrf: VrfId,
    scope: PrefixId,
    iaid: u32,
    address: Ipv6Addr,
    state: BindingState,
    ends: Timestamp,
) -> Binding6 {
    Binding6 {
        event,
        kind: Lease6Kind::Na,
        vrf,
        scope,
        iaid,
        addr: address,
        prefix_len: 128,
        state,
        preferred_ends: ends,
        ends,
    }
}

/// A change of client `k` with `bindings`.
fn change_of(k: u32, cltt: Timestamp, bindings: &[Binding6]) -> PendingChange6 {
    let mut change = PendingChange6::new(&duid(k), cltt);
    for binding in bindings {
        assert!(change.push(*binding), "room for the binding");
    }
    change
}

/// A grant of one address to client `k`.
fn grant(
    k: u32,
    vrf: VrfId,
    scope: PrefixId,
    address: Ipv6Addr,
    cltt: Timestamp,
    ends: Timestamp,
) -> PendingChange6 {
    change_of(
        k,
        cltt,
        &[binding(
            LeaseEventKind::Granted,
            vrf,
            scope,
            1,
            address,
            BindingState::Active,
            ends,
        )],
    )
}

/// A DHCPv6 lease store on `store` with its committer running.
fn start6(
    store: Arc<dyn Store>,
    settings: CommitSettings,
) -> (
    StoreLeases6,
    SharedLeases6,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    let leases = SharedLeases6::new(Lease6Index::new());
    let v4 = SharedLeases::new(LeaseIndex::new());
    let (lease_store4, _committer4) = StoreLeases::new(Arc::clone(&store), v4, NODE, settings);
    let (lease_store, committer) = StoreLeases6::new(
        store,
        leases.clone(),
        NODE,
        settings,
        lease_store4.gate_handle(),
    );
    let stop = CancellationToken::new();
    let task = tokio::spawn(committer.run(stop.clone()));
    (lease_store, leases, stop, task)
}

/// Waits for `count` completions, at most `bound`, and for the asynchronous writer to have
/// written their history rows (ADR 0030).
async fn completions(store: &StoreLeases6, count: usize, bound: Duration) -> Vec<Completion> {
    let deadline = tokio::time::Instant::now() + bound;
    let mut out = Vec::new();
    loop {
        store.completions6(&mut out);
        if out.len() >= count {
            break;
        }
        if tokio::time::timeout_at(deadline, store.completed())
            .await
            .is_err()
        {
            store.completions6(&mut out);
            break;
        }
    }
    store.derived().flush().await;
    out
}

type Leases = BTreeMap<(VrfId, Ipv6Addr), (Lease6, Revision)>;

async fn lease_rows(store: &dyn Store) -> Leases {
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    view.scan_typed(&tables::LEASES6, KeyRange::all(), usize::MAX, false)
        .expect("the leases")
        .into_iter()
        .map(|(key, lease, revision)| (key, (lease, revision)))
        .collect()
}

async fn history_rows(store: &dyn Store) -> Vec<(Lease6Event, Revision)> {
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    view.scan_typed(&tables::HISTORY6, KeyRange::all(), usize::MAX, false)
        .expect("the history")
        .into_iter()
        .map(|(_, event, revision)| (event, revision))
        .collect()
}

#[tokio::test]
async fn one_change_with_two_bindings_commits_two_rows_and_two_history_rows_at_one_revision() {
    let store = mem_store();
    let (leases_store, leases, stop, task) = start6(Arc::clone(&store), CommitSettings::default());
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let cltt = Timestamp::now();
    let ends = from_now(3_600);
    let pending = change_of(
        7,
        cltt,
        &[
            binding(
                LeaseEventKind::Granted,
                vrf,
                scope,
                1,
                addr(1),
                BindingState::Active,
                ends,
            ),
            binding(
                LeaseEventKind::Granted,
                vrf,
                scope,
                2,
                addr(2),
                BindingState::Active,
                ends,
            ),
        ],
    );
    assert_eq!(leases_store.submit6(&pending, Ticket(1)), Ok(()));
    let done = completions(&leases_store, 1, Duration::from_secs(10)).await;
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].ticket, Ticket(1));
    let revision = done[0].outcome.clone().expect("committed");

    // Two rows, at the revision the ticket completed with.
    let found = lease_rows(store.as_ref()).await;
    assert_eq!(found.len(), 2);
    for (iaid, address) in [(1, addr(1)), (2, addr(2))] {
        let (lease, at) = &found[&(vrf, address)];
        assert_eq!(*at, revision, "both rows are one revision");
        assert_eq!(lease.iaid, iaid);
        assert_eq!(lease.state, BindingState::Active);
        assert_eq!(lease.duid.as_bytes(), duid(7));
        assert_eq!(lease.scope, scope);
        assert_eq!(lease.ends, ends);
        assert_eq!(lease.node, NODE);
        // The completion comes after the table applied the commit.
        assert_eq!(leases.read().get(vrf, address), Some(lease));
        assert_eq!(leases.read().row_revision(vrf, address), Some(revision));
    }
    // Two history rows, in one later revision (the writer's batch), of kind granted.
    let history = history_rows(store.as_ref()).await;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].1, history[1].1, "one batch of the writer");
    for (event, at) in &history {
        assert!(*at > revision, "after the lease commit");

        assert_eq!(event.kind, LeaseEventKind::Granted);
        assert_eq!(event.at, cltt);
        assert_eq!(event.vrf, vrf);
        assert_eq!(event.duid.as_bytes(), duid(7));
    }
    let addresses: BTreeSet<Ipv6Addr> = history.iter().map(|(event, _)| event.addr).collect();
    assert_eq!(addresses, BTreeSet::from([addr(1), addr(2)]));
    let stats = leases_store.stats();
    assert_eq!((stats.submitted, stats.committed), (1, 1));

    // A renewal of the first binding only: one row moves to a later revision, the other
    // stays where it was.
    let renewal = change_of(
        7,
        from_now(1),
        &[binding(
            LeaseEventKind::Renewed,
            vrf,
            scope,
            1,
            addr(1),
            BindingState::Active,
            from_now(7_200),
        )],
    );
    leases_store.submit6(&renewal, Ticket(2)).expect("queued");
    let done = completions(&leases_store, 1, Duration::from_secs(10)).await;
    let later = done[0].outcome.clone().expect("committed");
    assert!(later > revision);
    let found = lease_rows(store.as_ref()).await;
    assert_eq!(found[&(vrf, addr(1))].1, later);
    assert_eq!(found[&(vrf, addr(2))].1, revision);
    assert_eq!(history_rows(store.as_ref()).await.len(), 3);
    stop.cancel();
    task.await.expect("the committer");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one store through the cases of the hold rules"
)]
async fn another_clients_binding_is_refused_whole_and_nothing_is_written() {
    let store = mem_store();
    let (leases_store, leases, stop, task) = start6(Arc::clone(&store), CommitSettings::default());
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let first = grant(1, vrf, scope, addr(50), Timestamp::now(), from_now(3_600));
    leases_store.submit6(&first, Ticket(1)).expect("queued");
    let done = completions(&leases_store, 1, Duration::from_secs(10)).await;
    assert!(done[0].outcome.is_ok());
    let before = lease_rows(store.as_ref()).await;
    assert_eq!(before.len(), 1);

    // Client 2 asks for a free address and for client 1's: the whole change is refused, the
    // free address is not written either.
    let greedy = change_of(
        2,
        from_now(1),
        &[
            binding(
                LeaseEventKind::Granted,
                vrf,
                scope,
                1,
                addr(51),
                BindingState::Active,
                from_now(3_600),
            ),
            binding(
                LeaseEventKind::Granted,
                vrf,
                scope,
                2,
                addr(50),
                BindingState::Active,
                from_now(3_600),
            ),
        ],
    );
    leases_store.submit6(&greedy, Ticket(2)).expect("queued");
    let done = completions(&leases_store, 1, Duration::from_secs(10)).await;
    assert_eq!(done[0].ticket, Ticket(2));
    assert!(
        matches!(&done[0].outcome, Err(CommitError::Refused(text)) if text.contains("held by another client")),
        "{:?}",
        done[0]
    );
    assert_eq!(leases_store.stats().held_by_other, 1);
    assert_eq!(lease_rows(store.as_ref()).await, before, "no row written");
    assert_eq!(history_rows(store.as_ref()).await.len(), 1);
    assert!(leases.read().get(vrf, addr(51)).is_none());
    let held = leases.read().get(vrf, addr(50)).cloned().expect("a row");
    assert_eq!(held.duid.as_bytes(), duid(1));

    // The same client may renew and may take a second IAID's address.
    let renewal = grant(1, vrf, scope, addr(50), from_now(2), from_now(7_200));
    leases_store.submit6(&renewal, Ticket(3)).expect("queued");
    assert!(
        completions(&leases_store, 1, Duration::from_secs(10)).await[0]
            .outcome
            .is_ok()
    );

    // An operator's reclaim ends the holder's binding whoever asks.
    let reclaim = change_of(
        2,
        from_now(3),
        &[binding(
            LeaseEventKind::Reclaimed,
            vrf,
            scope,
            1,
            addr(50),
            BindingState::Reset,
            from_now(3),
        )],
    );
    leases_store.submit6(&reclaim, Ticket(4)).expect("queued");
    assert!(
        completions(&leases_store, 1, Duration::from_secs(10)).await[0]
            .outcome
            .is_ok()
    );
    assert_eq!(
        leases.read().get(vrf, addr(50)).map(|lease| lease.state),
        Some(BindingState::Reset)
    );

    // A binding that ran out holds nothing: another client takes the address.
    let old = grant(3, vrf, scope, addr(60), ago(3_600), ago(60));
    leases_store.submit6(&old, Ticket(5)).expect("queued");
    assert!(
        completions(&leases_store, 1, Duration::from_secs(10)).await[0]
            .outcome
            .is_ok()
    );
    let taker = grant(4, vrf, scope, addr(60), Timestamp::now(), from_now(3_600));
    leases_store.submit6(&taker, Ticket(6)).expect("queued");
    assert!(
        completions(&leases_store, 1, Duration::from_secs(10)).await[0]
            .outcome
            .is_ok()
    );
    assert_eq!(
        leases
            .read()
            .get(vrf, addr(60))
            .map(|lease| lease.duid.as_bytes().to_vec()),
        Some(duid(4))
    );

    // A declined address is held for nobody until its hold ends.
    let declined = change_of(
        5,
        Timestamp::now(),
        &[binding(
            LeaseEventKind::Declined,
            vrf,
            scope,
            1,
            addr(70),
            BindingState::Abandoned,
            from_now(600),
        )],
    );
    leases_store.submit6(&declined, Ticket(7)).expect("queued");
    assert!(
        completions(&leases_store, 1, Duration::from_secs(10)).await[0]
            .outcome
            .is_ok()
    );
    let again = grant(5, vrf, scope, addr(70), from_now(1), from_now(3_600));
    leases_store.submit6(&again, Ticket(8)).expect("queued");
    let done = completions(&leases_store, 1, Duration::from_secs(10)).await;
    assert!(
        matches!(&done[0].outcome, Err(CommitError::Refused(_))),
        "{:?}",
        done[0]
    );
    stop.cancel();
    task.await.expect("the committer");
}

#[tokio::test]
async fn a_full_queue_answers_full_and_stopping_fails_what_is_queued() {
    let settings = CommitSettings {
        queue: 2,
        ..CommitSettings::default()
    };
    // No committer runs: the queue fills.
    let v4 = SharedLeases::new(LeaseIndex::new());
    let (lease_store4, _committer4) = StoreLeases::new(mem_store(), v4, NODE, settings);
    let (leases_store, committer) = StoreLeases6::new(
        mem_store(),
        SharedLeases6::new(Lease6Index::new()),
        NODE,
        settings,
        lease_store4.gate_handle(),
    );
    let pending = grant(
        1,
        VrfId::generate(),
        PrefixId::generate(),
        addr(9),
        Timestamp::now(),
        from_now(60),
    );
    assert_eq!(leases_store.submit6(&pending, Ticket(1)), Ok(()));
    assert_eq!(leases_store.submit6(&pending, Ticket(2)), Ok(()));
    assert_eq!(
        leases_store.submit6(&pending, Ticket(3)),
        Err(SubmitError::Full)
    );
    assert_eq!(leases_store.queued(), 2);
    let stop = CancellationToken::new();
    stop.cancel();
    committer.run(stop).await;
    let mut done = Vec::new();
    leases_store.completions6(&mut done);
    assert_eq!(done.len(), 2);
    assert!(done.iter().all(|completion| completion.outcome.is_err()));
}

/// A store whose writes are refused while a flag is set.
struct TestStore {
    inner: Arc<dyn Store>,
    refuse: AtomicBool,
}

#[async_trait::async_trait]
impl Store for TestStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err(StoreError::NoQuorum);
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
    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<Leadership>> {
        self.inner.leadership()
    }
}

/// A DHCPv4 change for the other half of the shared gate.
fn change4(client: u8, last: u8, cltt: Timestamp, ends: Timestamp) -> PendingChange {
    PendingChange::new(
        LeaseEventKind::Granted,
        VrfId::generate(),
        PrefixId::generate(),
        std::net::Ipv4Addr::new(192, 0, 2, last),
        1,
        &[0x00, 0x00, 0x5e, 0x00, 0x53, client],
        None,
        BindingState::Active,
        cltt,
        ends,
    )
}

async fn completions4(store: &StoreLeases, bound: Duration) -> Vec<Completion> {
    let deadline = tokio::time::Instant::now() + bound;
    let mut out = Vec::new();
    loop {
        store.completions(&mut out);
        if !out.is_empty() {
            return out;
        }
        if tokio::time::timeout_at(deadline, store.completed())
            .await
            .is_err()
        {
            store.completions(&mut out);
            return out;
        }
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the gate closed and opened from both sides"
)]
async fn a_refusing_store_closes_the_gate_of_both_families_and_a_commit_opens_it() {
    let store = Arc::new(TestStore {
        inner: mem_store(),
        refuse: AtomicBool::new(false),
    });
    let settings = CommitSettings {
        retry_after: Duration::from_millis(200),
        ..CommitSettings::default()
    };
    let as_store: Arc<dyn Store> = store.clone();
    let v4 = SharedLeases::new(LeaseIndex::new());
    let (lease_store4, committer4) = StoreLeases::new(as_store.clone(), v4, NODE, settings);
    let leases6 = SharedLeases6::new(Lease6Index::new());
    let (lease_store6, committer6) = StoreLeases6::new(
        as_store,
        leases6.clone(),
        NODE,
        settings,
        lease_store4.gate_handle(),
    );
    let stop = CancellationToken::new();
    let task4 = tokio::spawn(committer4.run(stop.clone()));
    let task6 = tokio::spawn(committer6.run(stop.clone()));
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();

    // A DHCPv6 commit goes through.
    let granted = grant(1, vrf, scope, addr(30), Timestamp::now(), from_now(3_600));
    lease_store6.submit6(&granted, Ticket(1)).expect("queued");
    assert!(
        completions(&lease_store6, 1, Duration::from_secs(5)).await[0]
            .outcome
            .is_ok()
    );
    assert!(lease_store6.gate().finding().is_none());
    assert!(lease_store6.accepting6() && lease_store4.accepting());

    // The store refuses: a DHCPv6 renewal fails and the gate closes for both families.
    store.refuse.store(true, Ordering::SeqCst);
    let renewal = change_of(
        1,
        from_now(1),
        &[binding(
            LeaseEventKind::Renewed,
            vrf,
            scope,
            1,
            addr(30),
            BindingState::Active,
            from_now(7_200),
        )],
    );
    lease_store6.submit6(&renewal, Ticket(2)).expect("queued");
    let done = completions(&lease_store6, 1, Duration::from_secs(5)).await;
    assert!(matches!(done[0].outcome, Err(CommitError::Refused(_))));
    assert!(!lease_store6.accepting6());
    assert!(!lease_store4.accepting(), "the DHCPv4 store sees the gate");
    assert_eq!(
        lease_store6.submit6(&renewal, Ticket(3)),
        Err(SubmitError::Refused)
    );
    assert_eq!(
        lease_store4.submit(&change4(1, 10, Timestamp::now(), from_now(60)), Ticket(4)),
        Err(SubmitError::Refused)
    );
    let finding = lease_store4.gate().finding().expect("a finding");
    assert_eq!(finding.code, "dhcp.role.store_refused");
    // The one gate is the same object.
    assert!(lease_store6.gate().finding().is_some());
    // Nothing was written for the renewal.
    assert_eq!(
        leases6.read().get(vrf, addr(30)).map(|lease| lease.ends),
        Some(granted.bindings()[0].ends)
    );

    // The store heals; a DHCPv4 commit (the other family) opens the gate for both.
    store.refuse.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(lease_store6.accepting6());
    lease_store4
        .submit(&change4(1, 10, Timestamp::now(), from_now(60)), Ticket(5))
        .expect("queued");
    assert!(
        completions4(&lease_store4, Duration::from_secs(5)).await[0]
            .outcome
            .is_ok()
    );
    assert!(lease_store6.gate().finding().is_none());
    assert!(lease_store6.accepting6());

    // And the other way round: a DHCPv4 refusal closes the DHCPv6 hand-off.
    store.refuse.store(true, Ordering::SeqCst);
    lease_store4
        .submit(&change4(2, 11, Timestamp::now(), from_now(60)), Ticket(6))
        .expect("queued");
    let done = completions4(&lease_store4, Duration::from_secs(5)).await;
    assert!(matches!(done[0].outcome, Err(CommitError::Refused(_))));
    assert!(!lease_store6.accepting6());
    assert_eq!(
        lease_store6.submit6(&renewal, Ticket(7)),
        Err(SubmitError::Refused)
    );
    store.refuse.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(300)).await;
    lease_store6.submit6(&renewal, Ticket(8)).expect("queued");
    assert!(
        completions(&lease_store6, 1, Duration::from_secs(5)).await[0]
            .outcome
            .is_ok()
    );
    assert!(lease_store4.gate().finding().is_none());
    assert_eq!(
        leases6.read().get(vrf, addr(30)).map(|lease| lease.ends),
        Some(renewal.bindings()[0].ends)
    );
    stop.cancel();
    task4.await.expect("the DHCPv4 committer");
    task6.await.expect("the DHCPv6 committer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_changes_for_different_clients_all_commit() {
    let store = mem_store();
    let (leases_store, leases, stop, task) = start6(Arc::clone(&store), CommitSettings::default());
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let total: u16 = 300;
    for k in 0..total {
        // Every third client holds two addresses (two IAIDs) in its change.
        let mut bindings = vec![binding(
            LeaseEventKind::Granted,
            vrf,
            scope,
            1,
            addr(k),
            BindingState::Active,
            from_now(3_600),
        )];
        if k % 3 == 0 {
            bindings.push(binding(
                LeaseEventKind::Granted,
                vrf,
                scope,
                2,
                addr(1_000 + k),
                BindingState::Active,
                from_now(3_600),
            ));
        }
        let pending = change_of(u32::from(k), Timestamp::now(), &bindings);
        leases_store
            .submit6(&pending, Ticket(u64::from(k)))
            .expect("the queue has room");
    }
    let done = completions(&leases_store, usize::from(total), Duration::from_secs(30)).await;
    assert_eq!(done.len(), usize::from(total));
    let tickets: BTreeSet<Ticket> = done.iter().map(|completion| completion.ticket).collect();
    assert_eq!(
        tickets.len(),
        usize::from(total),
        "every ticket completes once"
    );
    assert!(
        done.iter().all(|completion| completion.outcome.is_ok()),
        "different clients never refuse one another: {:?}",
        done.iter()
            .filter(|c| c.outcome.is_err())
            .collect::<Vec<_>>()
    );
    let highest = done
        .iter()
        .filter_map(|completion| completion.outcome.as_ref().ok().copied())
        .max()
        .expect("a commit");
    assert!(leases.revision() >= highest);
    stop.cancel();
    task.await.expect("the committer");

    let found = lease_rows(store.as_ref()).await;
    let expected_rows = usize::from(total) + usize::from(total.div_ceil(3));
    assert_eq!(found.len(), expected_rows);
    assert_eq!(history_rows(store.as_ref()).await.len(), expected_rows);
    let table = leases.read();
    assert_eq!(table.len(), expected_rows);
    for ((vrf, address), (lease, revision)) in &found {
        assert_eq!(table.get(*vrf, *address), Some(lease));
        assert_eq!(table.row_revision(*vrf, *address), Some(*revision));
    }
    assert_eq!(leases_store.stats().committed, u64::from(total));
    // One revision per change: the two bindings of a change share one.
    for k in (0..total).step_by(3) {
        assert_eq!(found[&(vrf, addr(k))].1, found[&(vrf, addr(1_000 + k))].1);
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the rows, the rounds and the checks of one expiry"
)]
async fn expiry_writes_what_ran_out_as_expired_with_a_history_row_each() {
    let store = mem_store();
    let (leases_store, leases, stop, task) = start6(Arc::clone(&store), CommitSettings::default());
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    // Three bindings past their end (two active, one declined past its hold), one that
    // still holds, one released.
    let mut ticket = 0;
    for (last, client, event, state, ends) in [
        (
            10,
            1,
            LeaseEventKind::Granted,
            BindingState::Active,
            ago(30),
        ),
        (
            11,
            2,
            LeaseEventKind::Granted,
            BindingState::Active,
            ago(10),
        ),
        (
            12,
            3,
            LeaseEventKind::Declined,
            BindingState::Abandoned,
            ago(1),
        ),
        (
            13,
            4,
            LeaseEventKind::Granted,
            BindingState::Active,
            from_now(600),
        ),
        (
            14,
            5,
            LeaseEventKind::Released,
            BindingState::Released,
            ago(60),
        ),
    ] {
        ticket += 1;
        let pending = change_of(
            client,
            ago(3_600),
            &[binding(event, vrf, scope, 1, addr(last), state, ends)],
        );
        leases_store
            .submit6(&pending, Ticket(ticket))
            .expect("queued");
    }
    let done = completions(&leases_store, 5, Duration::from_secs(10)).await;
    assert_eq!(done.len(), 5);
    assert!(done.iter().all(|completion| completion.outcome.is_ok()));
    let history_before = history_rows(store.as_ref()).await.len();
    assert_eq!(history_before, 5);

    let service = Expiry6Service::new(
        Arc::clone(&store),
        NODE,
        ExpirySettings {
            period: Duration::from_secs(10),
            batch: 2,
        },
    )
    .with_table(leases.clone());
    let round = service.round(0, Timestamp::now()).await.expect("a round");
    assert_eq!((round.due, round.expired, round.raced), (3, 3, 0));

    let found = lease_rows(store.as_ref()).await;
    for last in [10, 11, 12] {
        let (lease, _) = &found[&(vrf, addr(last))];
        assert_eq!(lease.state, BindingState::Expired, "{last}");
        assert_eq!(leases.read().get(vrf, addr(last)), Some(lease));
    }
    assert_eq!(found[&(vrf, addr(13))].0.state, BindingState::Active);
    assert_eq!(found[&(vrf, addr(14))].0.state, BindingState::Released);
    let history = history_rows(store.as_ref()).await;
    assert_eq!(history.len(), history_before + 3);
    let expired: BTreeSet<Ipv6Addr> = history
        .iter()
        .filter(|(event, _)| event.kind == LeaseEventKind::Expired)
        .map(|(event, _)| event.addr)
        .collect();
    assert_eq!(expired, BTreeSet::from([addr(10), addr(11), addr(12)]));
    for (event, _) in history
        .iter()
        .filter(|(event, _)| event.kind == LeaseEventKind::Expired)
    {
        assert_eq!(event.state, BindingState::Expired);
        assert_eq!(event.node, NODE);
    }
    // A second round finds nothing.
    let round = service.round(0, Timestamp::now()).await.expect("a round");
    assert_eq!(round.due, 0);

    // Without the table, the store's rows are scanned.
    let pending = grant(9, vrf, scope, addr(20), ago(100), ago(1));
    leases_store.submit6(&pending, Ticket(99)).expect("queued");
    assert_eq!(
        completions(&leases_store, 1, Duration::from_secs(5))
            .await
            .len(),
        1
    );
    let scanning = Expiry6Service::new(Arc::clone(&store), NODE, ExpirySettings::default());
    let round = scanning.round(0, Timestamp::now()).await.expect("a round");
    assert_eq!((round.due, round.expired), (1, 1));
    assert_eq!(
        lease_rows(store.as_ref()).await[&(vrf, addr(20))].0.state,
        BindingState::Expired
    );
    stop.cancel();
    task.await.expect("the committer");
}

// WP9.4: the history keeps the client's link-layer address, so that the MAC filter finds a
// client whose DUID names none.
#[tokio::test]
async fn the_history_rows_keep_the_link_layer_address_the_row_keeps() {
    let store = mem_store();
    let (leases_store, _leases, stop, task) = start6(Arc::clone(&store), CommitSettings::default());
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let mac = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x21];
    // A DUID-EN behind a relay that sends option 79 (RFC 6939).
    let mut first = grant(9, vrf, scope, addr(9), Timestamp::now(), from_now(3_600));
    first.link_layer = Some((1, tenko_dhcp::lease::InlineBytes::new(&mac).0));
    leases_store.submit6(&first, Ticket(1)).expect("queued");
    completions(&leases_store, 1, Duration::from_secs(10)).await[0]
        .outcome
        .clone()
        .expect("committed");
    // A renewal through a relay that does not send it keeps the address the row learned.
    let renewal = change_of(
        9,
        from_now(1),
        &[binding(
            LeaseEventKind::Renewed,
            vrf,
            scope,
            1,
            addr(9),
            BindingState::Active,
            from_now(7_200),
        )],
    );
    leases_store.submit6(&renewal, Ticket(2)).expect("queued");
    completions(&leases_store, 1, Duration::from_secs(10)).await[0]
        .outcome
        .clone()
        .expect("committed");
    let history = history_rows(store.as_ref()).await;
    assert_eq!(history.len(), 2);
    for (event, _) in &history {
        assert_eq!(event.mac(), Some(mac), "{:?}", event.kind);
        assert_eq!(event.link_layer_type, Some(1));
    }
    stop.cancel();
    task.await.expect("the committer");
}
