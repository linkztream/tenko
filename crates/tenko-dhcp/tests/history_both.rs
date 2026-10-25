//! The merged history read of `dhcp.history.read` over `dhcp.history` and `dhcp.history6`
//! (WP9.4): pages of any size, read with the cursors each page gives, answer every row of
//! both tables once, newest first across the families, and a family filter reads one table.

use std::net::{Ipv4Addr, Ipv6Addr};

use tenko_core::{
    NodeId, PrefixId, Principal, SystemComponent, Timestamp, VrfId,
    dhcp::{BindingState, ClientKey, Lease6Event, LeaseEvent, LeaseEventKind, tables},
    net::Duid,
    serde_util::HexBytes,
};
use tenko_dhcp::role::commands::{self, Family, HistoryArgs, Resume};
use tenko_store::{MemStore, ReadConsistency, Store, WriteBatch};

fn at(second: i128) -> Timestamp {
    Timestamp::from_unix_nanos(1_800_000_000_000_000_000 + second * 1_000_000_000).expect("time")
}

fn event4(second: i128, vrf: VrfId, scope: PrefixId) -> LeaseEvent {
    LeaseEvent {
        at: at(second),
        kind: LeaseEventKind::Renewed,
        addr: Ipv4Addr::new(192, 0, 2, 10),
        vrf,
        scope,
        client: ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![0, 0, 0x5e, 0, 0x53, 1]),
            client_id: None,
        },
        state: BindingState::Active,
        ends: at(second + 3_600),
        hostname: None,
        node: NodeId(1),
    }
}

fn event6(second: i128, vrf: VrfId, scope: PrefixId) -> Lease6Event {
    Lease6Event {
        at: at(second),
        kind: LeaseEventKind::Renewed,
        addr: "2001:db8::10".parse::<Ipv6Addr>().expect("address"),
        prefix_len: 128,
        vrf,
        scope,
        iaid: 1,
        duid: "0003000100005e005301".parse::<Duid>().expect("duid"),
        state: BindingState::Active,
        ends: at(second + 3_600),
        node: NodeId(1),
    }
}

/// Rows at the seconds of each family, the DHCPv4 ones on odd seconds and in runs.
async fn store(seconds4: &[i128], seconds6: &[i128]) -> MemStore {
    let store = MemStore::default();
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    for second in seconds4 {
        let event = event4(*second, vrf, scope);
        batch
            .put_typed(&tables::HISTORY, &(event.at, vrf, event.addr), &event)
            .expect("row");
    }
    for second in seconds6 {
        let event = event6(*second, vrf, scope);
        batch
            .put_typed(&tables::HISTORY6, &(event.at, vrf, event.addr), &event)
            .expect("row");
    }
    store.propose(batch).await.expect("rows");
    store
}

/// Reads every page of `limit` as the API does and answers the seconds in the order read,
/// with the family of each.
async fn read_all(store: &MemStore, family: Option<Family>, limit: u32) -> Vec<(i128, bool)> {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let mut args = HistoryArgs {
        family,
        limit,
        ..HistoryArgs::default()
    };
    let mut seen = Vec::new();
    for _ in 0..200 {
        let page = commands::read_history_both(view.as_ref(), &args).expect("page");
        let mut merged: Vec<(Timestamp, bool)> = page
            .items
            .iter()
            .map(|event| (event.at, false))
            .chain(page.items6.iter().map(|event| (event.at, true)))
            .collect();
        merged.sort_by(|a, b| b.cmp(a));
        let base = at(0).unix_nanos();
        seen.extend(
            merged
                .into_iter()
                .map(|(time, six)| ((time.unix_nanos() - base) / 1_000_000_000, six)),
        );
        match (page.resume, page.resume6) {
            (None, None) => return seen,
            (v4, v6) => {
                args.family = match (v4.is_some(), v6.is_some()) {
                    (true, false) => Some(Family::V4),
                    (false, true) => Some(Family::V6),
                    _ => family,
                };
                args.before = v4.and_then(|resume: Resume<_>| resume.key());
                args.before6 = v6.and_then(|resume: Resume<_>| resume.key());
            }
        }
    }
    panic!("the pages did not end");
}

#[tokio::test]
async fn pages_of_any_size_read_both_tables_newest_first() {
    let seconds4: Vec<i128> = [1, 3, 5, 7, 9, 11, 13, 40, 41, 42, 43, 44, 90].to_vec();
    let seconds6: Vec<i128> = [2, 4, 6, 20, 21, 22, 23, 24, 25, 60, 91, 92].to_vec();
    let store = store(&seconds4, &seconds6).await;
    let mut expected: Vec<(i128, bool)> = seconds4
        .iter()
        .map(|second| (*second, false))
        .chain(seconds6.iter().map(|second| (*second, true)))
        .collect();
    expected.sort_by(|a, b| b.cmp(a));
    for limit in [1, 2, 3, 5, 7, 100] {
        assert_eq!(
            read_all(&store, None, limit).await,
            expected,
            "pages of {limit}"
        );
    }
    let only6: Vec<(i128, bool)> = expected.iter().copied().filter(|(_, six)| *six).collect();
    assert_eq!(read_all(&store, Some(Family::V6), 4).await, only6);
    let only4: Vec<(i128, bool)> = expected.iter().copied().filter(|(_, six)| !six).collect();
    assert_eq!(read_all(&store, Some(Family::V4), 4).await, only4);
}

#[tokio::test]
async fn one_empty_table_reads_as_the_other() {
    let store = store(&[], &[5, 6, 7]).await;
    assert_eq!(
        read_all(&store, None, 2).await,
        [(7, true), (6, true), (5, true)]
    );
    let store = store_v4_only().await;
    assert_eq!(read_all(&store, None, 1).await, [(2, false), (1, false)]);
}

async fn store_v4_only() -> MemStore {
    store(&[1, 2], &[]).await
}

#[test]
fn a_duid_names_its_mac_address() {
    let mac = [0, 0, 0x5e, 0, 0x53, 1];
    // DUID-LL, DUID-LLT, then a DUID-EN and a DUID-LL of another hardware type.
    assert_eq!(
        commands::duid_mac(&[0, 3, 0, 1, 0, 0, 0x5e, 0, 0x53, 1]),
        Some(mac)
    );
    assert_eq!(
        commands::duid_mac(&[0, 1, 0, 1, 1, 2, 3, 4, 0, 0, 0x5e, 0, 0x53, 1]),
        Some(mac)
    );
    assert_eq!(commands::duid_mac(&[0, 2, 0, 0, 0, 9, 1, 2]), None);
    assert_eq!(
        commands::duid_mac(&[0, 3, 0, 6, 0, 0, 0x5e, 0, 0x53, 1]),
        None
    );
    assert_eq!(commands::duid_mac(&[0, 3]), None);
}
