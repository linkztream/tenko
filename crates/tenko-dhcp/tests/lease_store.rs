//! The lease store on the replicated store (WP7.2 content 1 and 5): every lease change is
//! one batch with its client index rows and its history row; the ticket completes only
//! after the commit and after the role's table applied it; rows, index and table agree with
//! the reference store of WP7.0 and with each other whatever order concurrent commits
//! finish in; another client's binding is never overwritten; a slow commit is reported
//! failed at its bound and still reaches the table; a refusing store closes the gate
//! (P3-Q14) and a commit opens it again.

mod lease_support;

use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use lease_support::{
    NODE, addr, change, completions, from_now, identity_of, mem_store, rows, start,
};
use proptest::prelude::*;
use tenko_core::{
    PrefixId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, Lease, LeaseEventKind},
};
use tenko_dhcp::{
    lease::{
        CommitSettings, LeaseIndex, LeaseTable, MemLeaseTable, PendingChange, SharedLeases,
        StoreLeases, WhileRefused, batch::held_by_other, metrics,
    },
    store::{CommitError, LeaseStore, MemLeaseStore, SubmitError, Ticket},
};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, Leadership, ReadConsistency, ReadView, Store,
    StoreError, StoreStatus, WatchFilter, WriteBatch,
};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime")
}

#[derive(Debug, Clone, Copy)]
struct Spec {
    addr: u8,
    client: u32,
    step: u8,
}

fn spec() -> impl Strategy<Value = Spec> {
    (0u8..4, 0u32..4, 0u8..4).prop_map(|(addr, client, step)| Spec { addr, client, step })
}

/// The change of a spec at second `i` after `base`.
fn change_of(
    spec: Spec,
    i: u64,
    base: Timestamp,
    vrf: VrfId,
    scopes: [PrefixId; 2],
) -> PendingChange {
    let cltt = base.checked_add(Duration::from_secs(i)).expect("a time");
    let (kind, state, ends) = match spec.step {
        0 => (LeaseEventKind::Granted, BindingState::Active, 3_600),
        1 => (LeaseEventKind::Renewed, BindingState::Active, 7_200),
        2 => (LeaseEventKind::Released, BindingState::Released, 0),
        _ => (LeaseEventKind::Declined, BindingState::Abandoned, 600),
    };
    let ends = cltt.checked_add(Duration::from_secs(ends)).expect("a time");
    change(
        kind,
        vrf,
        scopes[usize::from(spec.addr % 2)],
        addr(10 + spec.addr),
        spec.client,
        state,
        cltt,
        ends,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn changes_one_by_one_give_the_rows_of_the_reference_store(
        specs in prop::collection::vec(spec(), 1..24),
    ) {
        let rt = runtime();
        rt.block_on(async {
            let store = mem_store();
            let (leases_store, leases, stop, task) = start(Arc::clone(&store), CommitSettings::default());
            let reference = MemLeaseStore::with_capacity(NODE, 1);
            let vrf = VrfId::generate();
            let scopes = [PrefixId::generate(), PrefixId::generate()];
            let base = Timestamp::now();
            for (i, spec) in specs.iter().enumerate() {
                let pending = change_of(*spec, i as u64, base, vrf, scopes);
                let held = reference.leases().get(&(vrf, pending.addr)).cloned();
                let expect_ok = !held_by_other(&pending, held.as_ref(), Timestamp::now());
                prop_assert_eq!(leases_store.submit(&pending, Ticket(i as u64)), Ok(()));
                let done = completions(&leases_store, 1, Duration::from_secs(10)).await;
                prop_assert_eq!(done.len(), 1);
                prop_assert_eq!(done[0].ticket, Ticket(i as u64));
                prop_assert_eq!(done[0].outcome.is_ok(), expect_ok, "{:?}", &done[0]);
                if let Ok(revision) = done[0].outcome {
                    // The completion comes after the table applied the commit.
                    let table = leases.read();
                    prop_assert!(table.revision() >= revision);
                    prop_assert_eq!(table.row_revision(vrf, pending.addr), Some(revision));
                    drop(table);
                    reference.submit(&pending, Ticket(i as u64)).expect("queued");
                    reference.commit();
                }
            }
            stop.cancel();
            task.await.expect("the committer");
            let found = rows(store.as_ref()).await;
            prop_assert_eq!(&found.leases, &reference.leases());
            prop_assert_eq!(&found.index, &reference.client_index());
            let mut expected_history = reference.history();
            expected_history.sort_by_key(|event| (event.at, event.vrf, event.addr));
            prop_assert_eq!(&found.history, &expected_history);
            let table = leases.read();
            prop_assert_eq!(&table.sorted_rows(), &found.leases);
            prop_assert_eq!(&table.client_index(), &found.index);
            Ok(())
        })?;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_keeps_rows_index_and_table_equal() {
    let store = mem_store();
    let (leases_store, leases, stop, task) = start(Arc::clone(&store), CommitSettings::default());
    let vrf = VrfId::generate();
    let scopes = [PrefixId::generate(), PrefixId::generate()];
    let base = Timestamp::now();
    let total = 400usize;
    for i in 0..400u64 {
        let spec = Spec {
            addr: u8::try_from(i * 7 % 16).expect("small"),
            client: u32::try_from(i * 5 % 24).expect("small"),
            step: u8::try_from(i % 3).expect("small"),
        };
        let pending = change_of(spec, i, base, vrf, scopes);
        leases_store
            .submit(&pending, Ticket(i))
            .expect("the queue has room");
    }
    let done = completions(&leases_store, total, Duration::from_secs(30)).await;
    assert_eq!(done.len(), total);
    let tickets: BTreeSet<Ticket> = done.iter().map(|completion| completion.ticket).collect();
    assert_eq!(tickets.len(), total, "every ticket completes once");
    let committed = done.iter().filter(|c| c.outcome.is_ok()).count();
    assert!(committed > 0);
    let highest = done
        .iter()
        .filter_map(|c| c.outcome.as_ref().ok().copied())
        .max()
        .expect("a commit");
    assert!(leases.revision() >= highest);
    stop.cancel();
    task.await.expect("the committer");

    let found = rows(store.as_ref()).await;
    let table = leases.read();
    assert_eq!(table.sorted_rows(), found.leases);
    assert_eq!(table.client_index(), found.index);
    // The stored index is the one the rows imply (each client's latest row in a scope).
    let reference = MemLeaseTable::from_rows(found.leases.values().cloned());
    for ((scope, identity), target) in &found.index {
        let lease = reference
            .by_client(*scope, identity)
            .expect("an indexed client");
        assert_eq!((lease.vrf, lease.addr), (target.vrf, target.addr));
    }
    for lease in found.leases.values() {
        assert!(
            found
                .index
                .contains_key(&(lease.scope, lease.client.identity()))
        );
    }
    assert_eq!(found.history.len(), committed);
    assert_eq!(leases_store.stats().committed, committed as u64);
}

#[tokio::test]
async fn another_clients_binding_is_never_taken() {
    let store = mem_store();
    let (leases_store, leases, stop, task) = start(Arc::clone(&store), CommitSettings::default());
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let now = Timestamp::now();
    let first = change(
        LeaseEventKind::Granted,
        vrf,
        scope,
        addr(50),
        1,
        BindingState::Active,
        now,
        from_now(3_600),
    );
    let second = change(
        LeaseEventKind::Granted,
        vrf,
        scope,
        addr(50),
        2,
        BindingState::Active,
        from_now(1),
        from_now(3_600),
    );
    leases_store.submit(&first, Ticket(1)).expect("queued");
    leases_store.submit(&second, Ticket(2)).expect("queued");
    let done = completions(&leases_store, 2, Duration::from_secs(10)).await;
    let outcome = |ticket| {
        done.iter()
            .find(|completion| completion.ticket == Ticket(ticket))
            .map(|completion| completion.outcome.clone())
            .expect("a completion")
    };
    assert!(outcome(1).is_ok());
    assert!(matches!(outcome(2), Err(CommitError::Refused(_))));
    assert_eq!(leases_store.stats().held_by_other, 1);
    let held = leases.read().get(vrf, addr(50)).cloned().expect("a row");
    assert_eq!(held.client.identity(), identity_of(1));
    // An operator's reclaim may take it.
    let mut reclaim = second.clone();
    reclaim.kind = LeaseEventKind::Reclaimed;
    reclaim.state = BindingState::Reset;
    reclaim.cltt = from_now(2);
    leases_store.submit(&reclaim, Ticket(3)).expect("queued");
    let done = completions(&leases_store, 1, Duration::from_secs(10)).await;
    assert!(done[0].outcome.is_ok());
    stop.cancel();
    task.await.expect("the committer");
}

#[tokio::test]
async fn a_full_queue_answers_full() {
    let leases = SharedLeases::new(LeaseIndex::new());
    let settings = CommitSettings {
        queue: 2,
        ..CommitSettings::default()
    };
    // No committer runs: the queue fills.
    let (leases_store, _committer) = StoreLeases::new(mem_store(), leases, NODE, settings);
    let pending = change(
        LeaseEventKind::Granted,
        VrfId::generate(),
        PrefixId::generate(),
        addr(9),
        1,
        BindingState::Active,
        Timestamp::now(),
        from_now(60),
    );
    assert_eq!(leases_store.submit(&pending, Ticket(1)), Ok(()));
    assert_eq!(leases_store.submit(&pending, Ticket(2)), Ok(()));
    assert_eq!(
        leases_store.submit(&pending, Ticket(3)),
        Err(SubmitError::Full)
    );
    assert_eq!(leases_store.queued(), 2);
}

/// A store whose writes wait, or are refused while a flag is set.
struct TestStore {
    inner: Arc<dyn Store>,
    delay: Duration,
    refuse: AtomicBool,
}

#[async_trait::async_trait]
impl Store for TestStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err(StoreError::NoQuorum);
        }
        tokio::time::sleep(self.delay).await;
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

#[tokio::test]
async fn a_slow_commit_is_reported_at_its_bound_and_still_reaches_the_table() {
    let store = Arc::new(TestStore {
        inner: mem_store(),
        delay: Duration::from_millis(400),
        refuse: AtomicBool::new(false),
    });
    let settings = CommitSettings {
        commit_wait: Duration::from_millis(50),
        ..CommitSettings::default()
    };
    let (leases_store, leases, stop, task) = start(store.clone(), settings);
    let pending = change(
        LeaseEventKind::Granted,
        VrfId::generate(),
        PrefixId::generate(),
        addr(20),
        3,
        BindingState::Active,
        Timestamp::now(),
        from_now(600),
    );
    leases_store.submit(&pending, Ticket(7)).expect("queued");
    let done = completions(&leases_store, 1, Duration::from_secs(5)).await;
    assert_eq!(done.len(), 1);
    assert!(
        matches!(&done[0].outcome, Err(CommitError::Refused(text)) if text.contains("did not commit within"))
    );
    assert_eq!(leases_store.stats().timed_out, 1);
    // The commit lands later; the table takes it, and no second completion comes.
    assert!(leases.wait_for(Revision(1), Duration::from_secs(5)).await);
    assert!(leases.read().get(pending.vrf, pending.addr).is_some());
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut more = Vec::new();
    leases_store.completions(&mut more);
    assert_eq!(more.len(), 0, "no second completion");
    stop.cancel();
    task.await.expect("the committer");
    assert_eq!(rows(store.as_ref()).await.leases.len(), 1);
}

#[tokio::test]
async fn a_refusing_store_closes_the_gate_until_a_commit() {
    let store = Arc::new(TestStore {
        inner: mem_store(),
        delay: Duration::ZERO,
        refuse: AtomicBool::new(false),
    });
    let settings = CommitSettings {
        retry_after: Duration::from_millis(200),
        ..CommitSettings::default()
    };
    let (leases_store, leases, stop, task) = start(store.clone(), settings);
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let granted = change(
        LeaseEventKind::Granted,
        vrf,
        scope,
        addr(30),
        4,
        BindingState::Active,
        Timestamp::now(),
        from_now(3_600),
    );
    leases_store.submit(&granted, Ticket(1)).expect("queued");
    assert!(
        completions(&leases_store, 1, Duration::from_secs(5)).await[0]
            .outcome
            .is_ok()
    );
    let before: Lease = leases.read().get(vrf, addr(30)).cloned().expect("the row");
    assert!(leases_store.gate().finding().is_none());

    // The store refuses: the renewal's commit fails, and the gate closes.
    store.refuse.store(true, Ordering::SeqCst);
    let refused_before = metrics::STORE_REFUSED.get();
    let dropped_before = metrics::DROPPED.get(metrics::DropReason::StoreRefused as u16);
    let mut renewal = granted.clone();
    renewal.kind = LeaseEventKind::Renewed;
    renewal.cltt = from_now(1);
    renewal.ends = from_now(7_200);
    leases_store.submit(&renewal, Ticket(2)).expect("queued");
    let done = completions(&leases_store, 1, Duration::from_secs(5)).await;
    assert!(matches!(done[0].outcome, Err(CommitError::Refused(_))));
    assert!(!leases_store.accepting());
    assert_eq!(
        leases_store.submit(&renewal, Ticket(3)),
        Err(SubmitError::Refused)
    );
    let finding = leases_store
        .gate()
        .finding()
        .expect("the finding is raised");
    assert_eq!(finding.code, "dhcp.role.store_refused");
    assert!(metrics::STORE_REFUSED.get() > refused_before);

    // The renewal is answered for the time the lease has left; a new client is dropped.
    {
        let table = leases.read();
        let verdict = leases_store
            .gate()
            .decide(&*table, &renewal, Timestamp::now());
        assert!(
            matches!(verdict, WhileRefused::Remaining { secs } if (3_500..=3_600).contains(&secs))
        );
        let newcomer = change(
            LeaseEventKind::Granted,
            vrf,
            scope,
            addr(31),
            5,
            BindingState::Active,
            Timestamp::now(),
            from_now(3_600),
        );
        assert_eq!(
            leases_store
                .gate()
                .decide(&*table, &newcomer, Timestamp::now()),
            WhileRefused::Drop
        );
    }
    assert!(metrics::DROPPED.get(metrics::DropReason::StoreRefused as u16) > dropped_before);
    let finding = leases_store.gate().finding().expect("still raised");
    assert_eq!((finding.answered, finding.dropped), (1, 1));
    // Nothing was written for the renewal.
    assert_eq!(leases.read().get(vrf, addr(30)), Some(&before));
    assert_eq!(
        rows(store.as_ref()).await.leases.get(&(vrf, addr(30))),
        Some(&before)
    );

    // The store heals: after the interval a trial goes through and clears the finding.
    store.refuse.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(leases_store.accepting());
    leases_store.submit(&renewal, Ticket(4)).expect("queued");
    assert!(
        completions(&leases_store, 1, Duration::from_secs(5)).await[0]
            .outcome
            .is_ok()
    );
    assert!(leases_store.gate().finding().is_none());
    assert_eq!(
        leases.read().get(vrf, addr(30)).map(|lease| lease.ends),
        Some(renewal.ends)
    );
    stop.cancel();
    task.await.expect("the committer");
}

#[tokio::test]
async fn stopping_fails_what_is_still_queued() {
    let leases = SharedLeases::new(LeaseIndex::new());
    let (leases_store, committer) =
        StoreLeases::new(mem_store(), leases, NODE, CommitSettings::default());
    let pending = change(
        LeaseEventKind::Granted,
        VrfId::generate(),
        PrefixId::generate(),
        addr(40),
        6,
        BindingState::Active,
        Timestamp::now(),
        from_now(60),
    );
    leases_store.submit(&pending, Ticket(1)).expect("queued");
    let stop = tokio_util::sync::CancellationToken::new();
    stop.cancel();
    committer.run(stop).await;
    let mut done = Vec::new();
    leases_store.completions(&mut done);
    assert_eq!(done.len(), 1);
    assert!(done[0].outcome.is_err());
}
