//! The leader services of the lease path (WP7.2 content 3 and 4): expiry writes the
//! bindings that ran out as `expired` in batches with a history row each, fenced to the
//! leader's term and never over a row that changed; the offer hold holds an address for one
//! client for its lifetime and is pruned by expiry; the history retention follows the node,
//! the settings and the profile, and the purge deletes exactly the rows older than the
//! retention, audited.

mod lease_support;

use std::{sync::Arc, time::Duration};

use lease_support::{
    NODE, addr, change, completions, from_now, identity_of, mem_store, rows, start,
};
use tenko_core::{
    PrefixId, Principal, SystemComponent, Timestamp, VrfId,
    dhcp::{BindingState, DhcpSettings, LeaseEvent, LeaseEventKind, audit, tables},
};
use tenko_dhcp::{
    allocator::OfferHold,
    lease::{
        CommitSettings, ExpiryService, ExpirySettings, HistoryProfile, HistoryRetention,
        LeaseTable, OfferTable, PurgeService, PurgeSettings, metrics,
    },
    store::{LeaseStore, Ticket},
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadViewExt, StoreError, WriteBatch, tables as store_tables,
};

fn ago(secs: u64) -> Timestamp {
    let now = Timestamp::now();
    Timestamp::from_unix_nanos(now.unix_nanos() - i128::from(secs) * 1_000_000_000).expect("a time")
}

#[tokio::test]
async fn expiry_writes_what_ran_out_and_nothing_else() {
    let store = mem_store();
    let (leases_store, leases, stop, task) = start(Arc::clone(&store), CommitSettings::default());
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    // Five leases that ran out, one declined address past its hold, two that hold.
    let mut ticket = 0;
    for (last, client, state, ends) in [
        (10, 1, BindingState::Active, ago(30)),
        (11, 2, BindingState::Active, ago(20)),
        (12, 3, BindingState::Active, ago(10)),
        (13, 4, BindingState::Active, ago(5)),
        (14, 5, BindingState::Active, ago(1)),
        (15, 6, BindingState::Abandoned, ago(1)),
        (16, 7, BindingState::Active, from_now(600)),
        (17, 8, BindingState::Released, ago(60)),
    ] {
        ticket += 1;
        let kind = match state {
            BindingState::Abandoned => LeaseEventKind::Declined,
            BindingState::Released => LeaseEventKind::Released,
            _ => LeaseEventKind::Granted,
        };
        let pending = change(
            kind,
            vrf,
            scope,
            addr(last),
            client,
            state,
            ago(3_600),
            ends,
        );
        leases_store
            .submit(&pending, Ticket(ticket))
            .expect("queued");
    }
    assert_eq!(
        completions(&leases_store, 8, Duration::from_secs(5))
            .await
            .len(),
        8
    );
    let history_before = rows(store.as_ref()).await.history.len();

    let expired_before = metrics::EXPIRED.get();
    let service = ExpiryService::new(
        Arc::clone(&store),
        NODE,
        ExpirySettings {
            period: Duration::from_secs(10),
            batch: 4,
        },
    )
    .with_table(leases.clone());
    let round = service.round(0, Timestamp::now()).await.expect("a round");
    assert_eq!((round.due, round.expired, round.raced), (6, 6, 0));
    assert_eq!(metrics::EXPIRED.get() - expired_before, 6);

    let found = rows(store.as_ref()).await;
    for last in 10..=15 {
        let lease = &found.leases[&(vrf, addr(last))];
        assert_eq!(lease.state, BindingState::Expired, "{last}");
        assert_eq!(leases.read().get(vrf, addr(last)), Some(lease));
    }
    assert_eq!(found.leases[&(vrf, addr(16))].state, BindingState::Active);
    assert_eq!(found.leases[&(vrf, addr(17))].state, BindingState::Released);
    let expired_events: Vec<&LeaseEvent> = found
        .history
        .iter()
        .filter(|event| event.kind == LeaseEventKind::Expired)
        .collect();
    assert_eq!(expired_events.len(), 6);
    assert_eq!(found.history.len(), history_before + 6);
    // The client index did not move.
    for client in 1..=6 {
        let target = found.index[&(scope, identity_of(client))];
        assert_eq!(target.addr, addr(9 + u8::try_from(client).expect("small")));
    }
    // A second round finds nothing.
    let round = service.round(0, Timestamp::now()).await.expect("a round");
    assert_eq!(round.due, 0);

    // Without the table, the store's rows are scanned.
    let pending = change(
        LeaseEventKind::Granted,
        vrf,
        scope,
        addr(18),
        9,
        BindingState::Active,
        ago(100),
        ago(1),
    );
    leases_store.submit(&pending, Ticket(99)).expect("queued");
    assert_eq!(
        completions(&leases_store, 1, Duration::from_secs(5))
            .await
            .len(),
        1
    );
    let scanning = ExpiryService::new(Arc::clone(&store), NODE, ExpirySettings::default());
    let round = scanning.round(0, Timestamp::now()).await.expect("a round");
    assert_eq!((round.due, round.expired), (1, 1));
    stop.cancel();
    task.await.expect("the committer");
}

#[tokio::test]
async fn expiry_is_fenced_and_loses_to_a_renewal() {
    let store = mem_store();
    let (leases_store, leases, stop, task) = start(Arc::clone(&store), CommitSettings::default());
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let pending = change(
        LeaseEventKind::Granted,
        vrf,
        scope,
        addr(40),
        1,
        BindingState::Active,
        ago(100),
        ago(1),
    );
    leases_store.submit(&pending, Ticket(1)).expect("queued");
    completions(&leases_store, 1, Duration::from_secs(5)).await;

    // Another controller took office: the epoch moved on, the fence fails.
    let mut bump = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    bump.bump(tenko_core::cluster::LEADER_EPOCH);
    store.propose(bump).await.expect("bumped");
    let service = ExpiryService::new(Arc::clone(&store), NODE, ExpirySettings::default());
    assert!(matches!(
        service.round(0, Timestamp::now()).await,
        Err(StoreError::PreconditionFailed(_))
    ));
    assert_eq!(
        rows(store.as_ref()).await.leases[&(vrf, addr(40))].state,
        BindingState::Active
    );

    // A renewal between the read and the write wins: the batch fails on the version.
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    let (_, revision) = view
        .get_typed(&tables::LEASES, &(vrf, addr(40)))
        .expect("read")
        .expect("a row");
    let mut renewal = pending.clone();
    renewal.kind = LeaseEventKind::Renewed;
    renewal.cltt = Timestamp::now();
    renewal.ends = from_now(3_600);
    leases_store.submit(&renewal, Ticket(2)).expect("queued");
    completions(&leases_store, 1, Duration::from_secs(5)).await;
    let mut stale = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    stale.expect_typed(&tables::LEASES, &(vrf, addr(40)), Some(revision));
    assert!(matches!(
        store.propose(stale).await,
        Err(StoreError::PreconditionFailed(_))
    ));
    let round = service.round(1, Timestamp::now()).await.expect("a round");
    assert_eq!(round.expired, 0, "the renewed lease is not due");
    assert_eq!(
        leases.read().get(vrf, addr(40)).map(|lease| lease.state),
        Some(BindingState::Active)
    );
    stop.cancel();
    task.await.expect("the committer");
}

#[test]
fn the_offer_hold_keeps_an_address_for_one_client() {
    let hold = OfferTable::new(Duration::from_secs(10), 2);
    let scope = PrefixId::generate();
    let now = Timestamp::now();
    let (one, two) = (identity_of(1), identity_of(2));
    assert!(hold.hold(scope, addr(50), &one, now));
    assert!(hold.held_for_other(scope, addr(50), &two, now));
    assert!(!hold.held_for_other(scope, addr(50), &one, now));
    assert!(
        !hold.hold(scope, addr(50), &two, now),
        "held for the other client"
    );
    assert!(
        hold.hold(scope, addr(50), &one, now),
        "the same client extends it"
    );
    assert!(hold.hold(scope, addr(51), &two, now));
    // Full of unexpired offers: refused; once they ended, room again.
    assert!(!hold.hold(scope, addr(52), &two, now));
    let later = now.checked_add(Duration::from_secs(11)).expect("a time");
    assert!(!hold.held_for_other(scope, addr(50), &two, later));
    assert!(hold.hold(scope, addr(52), &two, later));
    assert_eq!(hold.prune(later), 1);
    hold.release(scope, addr(52));
    assert!(hold.is_empty());
}

#[tokio::test]
async fn expiry_prunes_the_offer_hold() {
    let hold = Arc::new(OfferTable::new(Duration::from_millis(1), 8));
    let scope = PrefixId::generate();
    assert!(hold.hold(scope, addr(60), &identity_of(1), ago(5)));
    let service = ExpiryService::new(mem_store(), NODE, ExpirySettings::default())
        .with_offers(Arc::clone(&hold));
    service.round(0, Timestamp::now()).await.expect("a round");
    assert!(hold.is_empty());
}

#[test]
fn the_retention_follows_the_node_the_settings_and_the_profile() {
    assert_eq!(HistoryProfile::Home.default_days(), 30);
    assert_eq!(HistoryProfile::Standard.default_days(), 90);
    assert_eq!(HistoryProfile::Hardened.default_days(), 90);
    assert_eq!(HistoryProfile::Lab.default_days(), 7);
    assert_eq!(HistoryProfile::from_name("lab"), Some(HistoryProfile::Lab));
    let retention = HistoryRetention::new(HistoryProfile::Home, None);
    assert_eq!(retention.days(None), 30);
    assert_eq!(retention.days(Some(14)), 14);
    retention.set_profile(HistoryProfile::Lab);
    assert_eq!(retention.days(None), 7);
    let node = HistoryRetention::new(HistoryProfile::Home, Some(3));
    assert_eq!(node.days(Some(14)), 3);
    let now = Timestamp::now();
    let cutoff = node.cutoff(None, now);
    assert_eq!(
        now.saturating_since(cutoff),
        Duration::from_secs(3 * 86_400)
    );
}

#[tokio::test]
async fn the_purge_deletes_what_is_older_than_the_retention() {
    let store = mem_store();
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    // History rows from 40 days ago to today, one per day, and settings of 10 days.
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    for day in 0..40u64 {
        let at = ago(day * 86_400 + 60);
        let row = change(
            LeaseEventKind::Renewed,
            vrf,
            scope,
            addr(70),
            1,
            BindingState::Active,
            at,
            at,
        )
        .to_event(NODE);
        batch
            .put_typed(&tables::HISTORY, &(row.at, row.vrf, row.addr), &row)
            .expect("encodes");
    }
    let settings = DhcpSettings {
        history_days: Some(10),
        ..DhcpSettings::default()
    };
    batch
        .put_typed(&tables::SETTINGS, &(), &settings)
        .expect("encodes");
    store.propose(batch).await.expect("written");

    let purged_before = metrics::HISTORY_PURGED.get();
    let service = PurgeService::new(
        Arc::clone(&store),
        Arc::new(HistoryRetention::new(HistoryProfile::Home, None)),
        PurgeSettings {
            period: Duration::from_secs(3_600),
            batch: 7,
        },
    );
    let round = service.round(0, Timestamp::now()).await.expect("a round");
    assert_eq!(round.purged, 30);
    assert_eq!(metrics::HISTORY_PURGED.get() - purged_before, 30);
    let found = rows(store.as_ref()).await;
    assert_eq!(found.history.len(), 10);
    assert!(found.history.iter().all(|event| event.at >= round.cutoff));
    // One audit record per batch, by the system component.
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    let records = view
        .scan_typed(&store_tables::AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("the audit");
    let purges: Vec<_> = records
        .iter()
        .filter(|(_, record, _)| record.draft.action == audit::HISTORY_PURGE)
        .collect();
    assert_eq!(purges.len(), 5, "30 rows in batches of 7");
    // Nothing more to purge.
    assert_eq!(
        service
            .round(0, Timestamp::now())
            .await
            .expect("a round")
            .purged,
        0
    );
    let count = tenko_dhcp::lease::history::count_rows(view.as_ref()).expect("counted");
    assert_eq!(count, 10);
}
