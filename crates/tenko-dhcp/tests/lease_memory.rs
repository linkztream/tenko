//! E32 (M30, OPS-15): what the role's lease table of 100,000 leases holds on the heap, for
//! the rows of M30 (`lease_rebuild.rs`: one-hour bindings with a client identifier, nothing
//! else) and for rows with the fields a lease usually gathers (a host name, the DDNS
//! outcome, a fingerprint, a relay, the observation time). The threshold is M30's: the
//! table and its indexes below 50 MiB. The figure counts the bytes asked of the allocator;
//! the resident set adds the allocator's own overhead, which
//! `bench/phase3-dhcp/scripts/m30-lease-memory.ps1` measures for the rows of M30.
//!
//! The counting allocator counts every thread of the process, so the file has one test.

mod lease_support;

use std::{alloc::System, net::Ipv4Addr};

use lease_support::{NODE, change, from_now};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_core::{
    PrefixId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, DdnsState, Fingerprint, Lease, LeaseEventKind, RelayInfo},
    dns::DnsName,
    serde_util::HexBytes,
};
use tenko_dhcp::lease::{LeaseIndex, LeaseTable};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const LEASES: u32 = 100_000;
const MIB: f64 = 1_048_576.0;

/// The key of lease `i`, as `lease_rebuild.rs` spreads them: 400 VRFs of 250 rows.
fn key_of(i: u32, vrfs: &[VrfId]) -> (VrfId, Ipv4Addr) {
    let vrf = vrfs[usize::try_from(i / 250).expect("an index")];
    let host = u8::try_from(i % 250).expect("below 250") + 1;
    (vrf, Ipv4Addr::new(192, 0, 2, host))
}

/// The row of M30.
fn bare(i: u32, vrfs: &[VrfId], scope: PrefixId, now: Timestamp) -> Lease {
    let (vrf, addr) = key_of(i, vrfs);
    change(
        LeaseEventKind::Granted,
        vrf,
        scope,
        addr,
        i + 256,
        BindingState::Active,
        now,
        from_now(3_600),
    )
    .to_lease(NODE, None)
}

/// A row with what a lease of a relayed client with DDNS gathers.
fn usual(i: u32, vrfs: &[VrfId], scope: PrefixId, now: Timestamp) -> Lease {
    let mut lease = bare(i, vrfs, scope, now);
    let host = format!("desktop-{i:06}");
    lease.ddns = DdnsState {
        forward: DnsName::new(&format!("{host}.example.com")).ok(),
        reverse: DnsName::new(&format!("{}.2.0.192.in-addr.arpa", lease.addr.octets()[3])).ok(),
        dhcid: Some(HexBytes(vec![0x5a; 35])),
        last_error: None,
        updated: Some(now),
    };
    lease.hostname = Some(host);
    lease.fingerprint = Some(Fingerprint {
        parameters: HexBytes(vec![
            1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252,
        ]),
        vendor_class: Some("MSFT 5.0".to_owned()),
        user_class: false,
        client_fqdn: true,
        architecture: None,
    });
    lease.relay = Some(RelayInfo {
        giaddr: Ipv4Addr::new(192, 0, 2, 1),
        circuit_id: Some(HexBytes(vec![0, 4, 0, 1])),
        remote_id: Some(HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x01])),
        link_selection: None,
        server_id_override: None,
        raw: HexBytes(vec![
            1, 4, 0, 4, 0, 1, 2, 6, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01,
        ]),
    });
    lease.observed_at = Some(now);
    lease
}

/// The heap the table of `LEASES` rows made by `row` holds, in MiB.
fn table_of(row: impl Fn(u32) -> Lease) -> f64 {
    // Each row is made and dropped inside the region, so only what the table keeps counts.
    let region = Region::new(GLOBAL);
    let mut table = LeaseIndex::new();
    for i in 0..LEASES {
        table.apply_at(row(i), Revision(1));
    }
    let stats = region.change();
    assert_eq!(table.len(), usize::try_from(LEASES).expect("a count"));
    let held = i64::try_from(stats.bytes_allocated).unwrap_or(i64::MAX)
        + i64::try_from(stats.bytes_reallocated).unwrap_or(0)
        - i64::try_from(stats.bytes_deallocated).unwrap_or(i64::MAX);
    let mib = f64::from(i32::try_from(held).unwrap_or(i32::MAX)) / MIB;
    drop(table);
    mib
}

#[test]
fn e32_ops_15_a_table_of_100000_leases_holds_below_50_mib() {
    let vrfs: Vec<VrfId> = (0..400).map(|_| VrfId::generate()).collect();
    let scope = PrefixId::generate();
    let now = Timestamp::now();
    let bare_mib = table_of(|i| bare(i, &vrfs, scope, now));
    let usual_mib = table_of(|i| usual(i, &vrfs, scope, now));
    println!("LEASE-TABLE leases={LEASES} bare_mib={bare_mib:.2} usual_mib={usual_mib:.2}");
    assert!(
        bare_mib < 50.0,
        "the rows of M30 take {bare_mib:.2} MiB in the table"
    );
    assert!(
        usual_mib < 50.0,
        "rows with their usual fields take {usual_mib:.2} MiB in the table"
    );
}
