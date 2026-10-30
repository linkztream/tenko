//! The observation hook of the lease change (WP8.1, plan section 2.8, ADR 0030): the
//! committer builds the IPAM fact of every lease change with its row and hands it to the
//! asynchronous writer once the lease committed; a renewal within the refresh interval
//! writes none and is counted, a release expires it, the row records when its fact was last
//! written, and a change that follows before the writer's flush is judged against the fact
//! of the change before it.

mod lease_support;

use std::{sync::Arc, time::Duration};

use lease_support::{NODE, addr, change, completions, from_now, mac, mem_store, rows};

use tenko_core::{
    MacAddr, PrefixId, Timestamp, VrfId,
    dhcp::{BindingState, LeaseEventKind, tables},
    observe::Observed,
};
use tenko_dhcp::{
    lease::{CommitSettings, LeaseIndex, SharedLeases, StoreLeases, observe::IpamObservations},
    store::{LeaseStore, Ticket},
};
use tenko_ipam::observe::{ObserveConfig, model::FactSubject};
use tenko_store::{ReadConsistency, ReadViewExt, Store};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn the_writer_writes_the_fact_after_the_lease_and_a_renewal_writes_none() {
    let store: Arc<dyn Store> = mem_store();
    let hook = IpamObservations::register(store.as_ref(), NODE, ObserveConfig::default())
        .expect("the hook");
    let leases = SharedLeases::new(LeaseIndex::new());
    let (lease_store, committer) = StoreLeases::with_hook(
        Arc::clone(&store),
        leases.clone(),
        NODE,
        CommitSettings::default(),
        Arc::clone(&hook) as Arc<dyn tenko_dhcp::lease::batch::ObservationHook>,
    );
    let stop = CancellationToken::new();
    let task = tokio::spawn(committer.run(stop.clone()));
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let client = 2;
    let granted = Timestamp::now();
    let commit = |ticket: u64, kind, state, cltt: Timestamp, ends: Timestamp| {
        let pending = change(kind, vrf, scope, addr(10), client, state, cltt, ends);
        lease_store
            .submit(&pending, Ticket(ticket))
            .expect("the queue has room");
    };

    // The grant: the fact of the address, with the client's MAC address, in the same
    // revision as the row; the row records the fact's time.
    commit(
        1,
        LeaseEventKind::Granted,
        BindingState::Active,
        granted,
        from_now(3_600),
    );
    let done = completions(&lease_store, 1, Duration::from_secs(10)).await;
    let revision = *done[0].outcome.as_ref().expect("committed");
    assert_eq!(hook.counts().new, 1);
    lease_store.derived().flush().await;
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let (row, row_revision) = view
        .get_typed(&tables::LEASES, &(vrf, addr(10)))
        .expect("read")
        .expect("the row");
    assert_eq!(row_revision, revision);
    assert_eq!(row.observed_at, Some(row.cltt));
    let subject = FactSubject::Address {
        vrf,
        ip: addr(10).into(),
    };
    let fact = hook.facts().fact(&subject).expect("the fact");
    assert!(
        fact.revision > revision,
        "the fact follows the row in a batch of the writer"
    );
    let fact_revision = fact.revision;
    assert_eq!(
        fact.observed,
        Observed::Address {
            vrf,
            ip: addr(10).into(),
            mac: Some(MacAddr::new(mac(client))),
        }
    );
    drop(view);

    // A renewal a minute later: nothing written beyond the lease rows, counted.
    let renewed = granted
        .checked_add(Duration::from_secs(60))
        .expect("a time");
    commit(
        2,
        LeaseEventKind::Renewed,
        BindingState::Active,
        renewed,
        from_now(3_660),
    );
    completions(&lease_store, 1, Duration::from_secs(10)).await;
    lease_store.derived().flush().await;
    let counts = hook.counts();
    assert_eq!((counts.unchanged, counts.written()), (1, 1), "{counts:?}");
    assert_eq!(
        hook.facts().fact(&subject).expect("the fact").revision,
        fact_revision
    );

    // The release expires the fact in its batch.
    let released = renewed.checked_add(Duration::from_secs(1)).expect("a time");
    commit(
        3,
        LeaseEventKind::Released,
        BindingState::Released,
        released,
        released,
    );
    completions(&lease_store, 1, Duration::from_secs(10)).await;
    lease_store.derived().flush().await;
    assert_eq!(hook.counts().expired, 1);
    let fact = hook.facts().fact(&subject).expect("the fact");
    assert!(!fact.is_current(Timestamp::now()));
    stop.cancel();
    task.await.expect("the committer");
}

#[tokio::test]
async fn a_change_before_the_flush_is_judged_against_the_fact_of_the_change_before_it() {
    let store: Arc<dyn Store> = mem_store();
    let hook = IpamObservations::register(store.as_ref(), NODE, ObserveConfig::default())
        .expect("the hook");
    let leases = SharedLeases::new(LeaseIndex::new());
    // The writer flushes once an hour: every change below commits before any flush.
    let settings = CommitSettings {
        derived: tenko_dhcp::lease::derived::DerivedSettings {
            interval: Duration::from_secs(3_600),
            ..tenko_dhcp::lease::derived::DerivedSettings::default()
        },
        ..CommitSettings::default()
    };
    let (lease_store, committer) = StoreLeases::with_hook(
        Arc::clone(&store),
        leases.clone(),
        NODE,
        settings,
        Arc::clone(&hook) as Arc<dyn tenko_dhcp::lease::batch::ObservationHook>,
    );
    let stop = CancellationToken::new();
    let task = tokio::spawn(committer.run(stop.clone()));
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let granted = Timestamp::now();
    let later = |secs| {
        granted
            .checked_add(Duration::from_secs(secs))
            .expect("a time")
    };
    let steps = [
        (
            LeaseEventKind::Granted,
            BindingState::Active,
            granted,
            from_now(3_600),
        ),
        (
            LeaseEventKind::Released,
            BindingState::Released,
            later(1),
            later(1),
        ),
        (
            LeaseEventKind::Granted,
            BindingState::Active,
            later(2),
            from_now(3_600),
        ),
    ];
    for (ticket, (kind, state, cltt, ends)) in steps.into_iter().enumerate() {
        let pending = change(kind, vrf, scope, addr(20), 3, state, cltt, ends);
        lease_store
            .submit(&pending, Ticket(ticket as u64))
            .expect("the queue has room");
        completions(&lease_store, 1, Duration::from_secs(10)).await;
    }
    let counts = hook.counts();
    assert_eq!(
        (counts.new, counts.expired, counts.changed),
        (1, 1, 1),
        "the release expired the pending fact and the grant revived it: {counts:?}"
    );
    assert_eq!(
        lease_store.derived().stats().written,
        0,
        "nothing flushed yet"
    );
    lease_store.derived().flush().await;
    let subject = FactSubject::Address {
        vrf,
        ip: addr(20).into(),
    };
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let stored = view
        .get_typed(
            &tenko_ipam::observe::tables::FACTS,
            &(
                hook.facts().fact(&subject).expect("the fact").source_key,
                subject.key(),
            ),
        )
        .expect("read")
        .expect("the stored fact");
    assert!(
        stored.0.is_current(Timestamp::now()),
        "the last change wins: the address is bound again"
    );
    assert_eq!(
        rows(store.as_ref()).await.history.len(),
        3,
        "three history rows in one flush"
    );
    stop.cancel();
    task.await.expect("the committer");
}
