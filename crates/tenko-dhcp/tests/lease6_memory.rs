//! What one DHCPv6 lease row costs at a scope's `bindings_per_scope` (65,536 on Standard):
//! the bytes the role's table and IPAM's lease view keep on the heap per row, and the
//! encoded size of the stored row, for an address of a relayed client with a name. The
//! figures count the bytes asked of the allocator; the resident set adds the allocator's
//! own overhead. Each bound is the measured value plus a quarter.
//!
//! The counting allocator counts every thread of the process, so the file has one test.

use std::{
    alloc::System,
    fmt::Write as _,
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};
use tenko_core::{
    NodeId, PrefixId, Principal, Revision, SystemComponent, Timestamp, VrfId,
    dhcp::{BindingState, DdnsState, Lease6, Lease6Kind, Relay6Info, tables::LEASES6},
    dns::DnsName,
    net::Duid,
    serde_util::HexBytes,
};
use tenko_dhcp::v6::lease::Lease6Index;
use tenko_ipam::observe::{ObserveConfig, dhcp::LeaseFacts};
use tenko_store::{MemStore, ReadConsistency, Store, WriteBatch};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Standard's `bindings_per_scope`.
const ROWS: u32 = 65_536;

/// The net bytes a region kept.
fn kept(stats: &Stats) -> usize {
    let held = i64::try_from(stats.bytes_allocated).unwrap_or(i64::MAX)
        + i64::try_from(stats.bytes_reallocated).unwrap_or(0)
        - i64::try_from(stats.bytes_deallocated).unwrap_or(i64::MAX);
    usize::try_from(held).unwrap_or(0)
}

/// The name of the PTR record of `addr` under `ip6.arpa`.
fn ptr(addr: Ipv6Addr) -> String {
    let mut out = String::new();
    for octet in addr.octets().iter().rev() {
        let _ = write!(out, "{:x}.{:x}.", octet & 0x0f, octet >> 4);
    }
    out + "ip6.arpa"
}

/// The row of client `i`: a DUID-LL, a name with its forward and reverse records, a relay
/// with an Interface-Id.
fn row(i: u32, vrf: VrfId, scope: PrefixId, now: Timestamp) -> Lease6 {
    let [_, a, b, c] = i.to_be_bytes();
    let addr = Ipv6Addr::new(
        0x2001,
        0xdb8,
        1,
        0,
        0,
        0,
        u16::from(a),
        u16::from_be_bytes([b, c]),
    );
    let host = format!("laptop-{i:05}");
    Lease6 {
        addr: IpAddr::V6(addr),
        prefix_len: 128,
        kind: Lease6Kind::Na,
        vrf,
        scope,
        iaid: 1,
        duid: Duid::new(vec![0, 3, 0, 1, 0x02, 0x00, 0x5e, a, b, c]).expect("a DUID"),
        link_layer: Some(HexBytes(vec![0x02, 0x00, 0x5e, a, b, c])),
        link_layer_type: Some(1),
        state: BindingState::Active,
        cltt: now,
        ends: now.checked_add(Duration::from_secs(4_000)).expect("a time"),
        preferred_ends: now.checked_add(Duration::from_secs(3_000)).expect("a time"),
        node: NodeId(1),
        fqdn: Some(format!("{host}.example.test")),
        fqdn_flags: Some(0x01),
        relay: Some(Relay6Info {
            link_address: Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1),
            peer_address: Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0200, 0x5eff, 0xfe00, u16::from(c)),
            hops: 1,
            interface_id: Some(HexBytes(b"Gi0/7".to_vec())),
            remote_id: None,
        }),
        observed_at: None,
        ddns: DdnsState {
            forward: DnsName::new(&format!("{host}.example.test")).ok(),
            reverse: DnsName::new(&ptr(addr)).ok(),
            dhcid: Some(HexBytes(vec![0x5a; 35])),
            last_error: None,
            updated: Some(now),
        },
        granted: Some(now),
    }
}

#[tokio::test]
async fn a_dhcpv6_row_costs_this_much_at_the_ceiling() {
    let (vrf, scope, now) = (VrfId::generate(), PrefixId::generate(), Timestamp::now());
    let rows: Vec<Lease6> = (0..ROWS).map(|i| row(i, vrf, scope, now)).collect();
    let per_row = |bytes: usize| bytes / usize::try_from(ROWS).expect("a count");

    // The stored row.
    let stored = LEASES6.encode(&rows[0]).expect("encoded").len();

    // The role's table.
    let region = Region::new(GLOBAL);
    let table = Lease6Index::from_rows(
        rows.iter().cloned().map(|lease| (lease, Revision(1))),
        Revision(1),
    );
    let table_bytes = per_row(kept(&region.change()));
    drop(table);

    // IPAM's lease view, built from the store.
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    for chunk in rows.chunks(4_096) {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
        for lease in chunk {
            batch
                .put_typed(&LEASES6, &(vrf, lease.addr6()), lease)
                .expect("a row");
        }
        store.propose(batch).await.expect("committed");
    }
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    let facts = LeaseFacts::new(ObserveConfig::default());
    let region = Region::new(GLOBAL);
    facts.build(view.as_ref(), now).expect("built");
    let view_bytes = per_row(kept(&region.change()));
    assert_eq!(facts.len(), rows.len());

    println!(
        "LEASE6-ROW rows={ROWS} stored_octets={stored} table_bytes_per_row={table_bytes} \
         ipam_view_bytes_per_row={view_bytes}"
    );
    assert!(stored <= STORED_CAP, "{stored}");
    assert!(table_bytes <= TABLE_CAP, "{table_bytes}");
    assert!(view_bytes <= VIEW_CAP, "{view_bytes}");
}

/// The measured values (2026-11-22: 670 octets stored, 1,382 bytes in the table, 946 in the
/// view per row) plus a quarter.
const STORED_CAP: usize = 838;
const TABLE_CAP: usize = 1_728;
const VIEW_CAP: usize = 1_183;
