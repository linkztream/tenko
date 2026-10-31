//! The lean history row and its read (ADR 0031): a row holds what the change was and the
//! revision of the lease row it wrote, not the client's host name; the history read joins
//! the name from the lease row. A row whose lease row is still at its revision answers the
//! name of the change (`lease`); after a renewal of the same client the older events answer
//! the name the row has now (`lease_now`); after the address went to another client they
//! answer none (`unknown`); a row written by an earlier version answers its own name
//! (`stored`). The retention purge deletes lean and old rows alike.

mod lease_support;

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use lease_support::{NODE, addr, at, change, completions, mem_store, rows, start};
use tenko_core::{
    PrefixId, Principal, SystemComponent, Timestamp, VrfId,
    codec::to_cbor,
    dhcp::{
        BindingState, ClientKey, DhcpSettings, HistoryNames, HistoryRow, LeaseEvent,
        LeaseEventKind, tables,
    },
    serde_util::HexBytes,
};
use tenko_dhcp::{
    lease::{
        CommitSettings, HistoryProfile, HistoryRetention, PendingChange, PurgeService,
        PurgeSettings,
    },
    role::commands::{self, HistoryArgs},
    store::{LeaseStore, Ticket},
};
use tenko_store::{ReadConsistency, Store, WriteBatch};

/// A change of client `client` at `addr(10)` at `second` seconds after `t0`, with a host
/// name.
fn named(
    kind: LeaseEventKind,
    vrf: VrfId,
    scope: PrefixId,
    client: u32,
    state: BindingState,
    second: u64,
    name: &str,
) -> PendingChange {
    let ends = if state == BindingState::Active {
        at(second + 3_600)
    } else {
        at(second)
    };
    let mut pending = change(kind, vrf, scope, addr(10), client, state, at(second), ends);
    pending.hostname.set(name.as_bytes());
    pending
}

/// The history of `address`, newest first, as `dhcp.history.read` answers it.
async fn history_of(store: &Arc<dyn Store>, address: Ipv4Addr) -> Vec<LeaseEvent> {
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    commands::read_history(
        view.as_ref(),
        &HistoryArgs {
            addr: Some(address),
            ..HistoryArgs::default()
        },
    )
    .expect("the history reads")
    .items
}

/// The names of the events with the host name they carry, newest first.
fn names(events: &[LeaseEvent]) -> Vec<(LeaseEventKind, Option<HistoryNames>, Option<&str>)> {
    events
        .iter()
        .map(|event| (event.kind, event.names, event.hostname.as_deref()))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_history_read_joins_the_host_name_from_the_lease_row() {
    let store = mem_store();
    let (lease_store, _leases, stop, task) = start(Arc::clone(&store), CommitSettings::default());
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let mut ticket = 0;
    let mut commit = async |pending: PendingChange| {
        ticket += 1;
        lease_store
            .submit(&pending, Ticket(ticket))
            .expect("the queue has room");
        let done = completions(&lease_store, 1, Duration::from_secs(10)).await;
        assert!(done[0].outcome.is_ok(), "{:?}", done[0].outcome);
        lease_store.derived().flush().await;
    };

    // A grant whose lease row is still at the grant's revision: the name of the change.
    commit(named(
        LeaseEventKind::Granted,
        vrf,
        scope,
        1,
        BindingState::Active,
        10,
        "alpha",
    ))
    .await;
    let found = rows(store.as_ref()).await;
    let row_revision = found.revisions[&(vrf, addr(10))];
    let history = history_of(&store, addr(10)).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].revision, Some(row_revision));
    assert_eq!(
        names(&history),
        [(
            LeaseEventKind::Granted,
            Some(HistoryNames::Lease),
            Some("alpha")
        )]
    );

    // A renewal of the same client: the grant now answers the name the row has now, the
    // renewal the name of the change.
    commit(named(
        LeaseEventKind::Renewed,
        vrf,
        scope,
        1,
        BindingState::Active,
        20,
        "alpha",
    ))
    .await;
    let history = history_of(&store, addr(10)).await;
    assert_eq!(
        names(&history),
        [
            (
                LeaseEventKind::Renewed,
                Some(HistoryNames::Lease),
                Some("alpha")
            ),
            (
                LeaseEventKind::Granted,
                Some(HistoryNames::LeaseNow),
                Some("alpha")
            ),
        ]
    );

    // The client lets go and another one gets the address: the first client's events no
    // longer know a name, the second's grant answers its own.
    commit(named(
        LeaseEventKind::Released,
        vrf,
        scope,
        1,
        BindingState::Released,
        30,
        "alpha",
    ))
    .await;
    commit(named(
        LeaseEventKind::Granted,
        vrf,
        scope,
        2,
        BindingState::Active,
        40,
        "beta",
    ))
    .await;
    let history = history_of(&store, addr(10)).await;
    assert_eq!(
        names(&history),
        [
            (
                LeaseEventKind::Granted,
                Some(HistoryNames::Lease),
                Some("beta")
            ),
            (LeaseEventKind::Released, Some(HistoryNames::Unknown), None),
            (LeaseEventKind::Renewed, Some(HistoryNames::Unknown), None),
            (LeaseEventKind::Granted, Some(HistoryNames::Unknown), None),
        ]
    );
    stop.cancel();
    task.await.expect("the committer");
}

/// A whole `LeaseEvent` as an earlier version wrote it: a CBOR map put as raw octets.
fn put_old(batch: &mut WriteBatch, event: &LeaseEvent) {
    batch.put(
        tables::HISTORY.name().clone(),
        tables::HISTORY.key(&(event.at, event.vrf, event.addr)),
        to_cbor(event).expect("the old shape encodes"),
    );
}

fn event_at(
    at: Timestamp,
    vrf: VrfId,
    scope: PrefixId,
    address: Ipv4Addr,
    hostname: Option<&str>,
) -> LeaseEvent {
    LeaseEvent {
        at,
        kind: LeaseEventKind::Renewed,
        addr: address,
        vrf,
        scope,
        client: ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x09]),
            client_id: None,
        },
        state: BindingState::Active,
        ends: at.checked_add(Duration::from_secs(3_600)).expect("a time"),
        hostname: hostname.map(str::to_owned),
        node: NODE,
        revision: None,
        names: None,
    }
}

#[tokio::test]
async fn an_old_full_row_answers_its_own_host_name() {
    let store = mem_store();
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let old = event_at(at(5), vrf, scope, addr(11), Some("legacy"));
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    put_old(&mut batch, &old);
    store.propose(batch).await.expect("the row is written");

    let history = history_of(&store, addr(11)).await;
    assert_eq!(
        names(&history),
        [(
            LeaseEventKind::Renewed,
            Some(HistoryNames::Stored),
            Some("legacy")
        )]
    );
    assert_eq!(history[0].revision, None, "an old row names no lease row");
}

#[tokio::test]
async fn the_purge_deletes_lean_and_old_rows_alike() {
    let store = mem_store();
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let ago = |days: u64, extra: u64| {
        let now = Timestamp::now().unix_nanos();
        Timestamp::from_unix_nanos(now - i128::from(days * 86_400 + extra) * 1_000_000_000)
            .expect("a time")
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    // 20 days old (twenty rows, alternating shapes) and one day old (four rows).
    for (days, count) in [(20, 20u64), (1, 4)] {
        for k in 0..count {
            let event = event_at(ago(days, k * 60 + 60), vrf, scope, addr(12), Some("legacy"));
            if k % 2 == 0 {
                put_old(&mut batch, &event);
            } else {
                batch
                    .put_typed(
                        &tables::HISTORY,
                        &(event.at, event.vrf, event.addr),
                        &HistoryRow::of(&LeaseEvent {
                            revision: Some(tenko_core::Revision(7)),
                            ..event
                        }),
                    )
                    .expect("the lean row encodes");
            }
        }
    }
    batch
        .put_typed(
            &tables::SETTINGS,
            &(),
            &DhcpSettings {
                history_days: Some(10),
                ..DhcpSettings::default()
            },
        )
        .expect("encodes");
    store.propose(batch).await.expect("the rows are written");
    assert_eq!(rows(store.as_ref()).await.history.len(), 24);

    let service = PurgeService::new(
        Arc::clone(&store),
        Arc::new(HistoryRetention::new(HistoryProfile::Home, None)),
        PurgeSettings {
            period: Duration::from_secs(3_600),
            batch: 5,
        },
    );
    let round = service.round(0, Timestamp::now()).await.expect("a round");
    assert_eq!(round.purged, 20, "the old and the lean rows of 20 days ago");
    let left = rows(store.as_ref()).await.history;
    assert_eq!(left.len(), 4);
    assert!(left.iter().all(|event| event.at >= round.cutoff));
    // The rows left decode by their own shapes.
    assert_eq!(
        left.iter()
            .filter(|event| event.names == Some(HistoryNames::Stored))
            .count(),
        2,
        "two old rows and two lean ones"
    );
}
