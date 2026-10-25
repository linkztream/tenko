//! The client index of the DHCPv6 lease table (WP9.2): `Lease6Index::by_client` is keyed by
//! scope, binding kind and client identity, because an `IA_NA` and an `IA_PD` of one client
//! may share an IAID (RFC 8415 section 12: the IAID is unique among the IAs of one type).
//!
//! - An address row and a prefix row of one scope, IAID and DUID are each found by their kind.
//! - Taking one keeps the other indexed.
//! - A row that changes kind at one key is re-indexed, and an older row does not replace a
//!   newer one.
//! - The latest row of a client is the one found; the same identity in another scope is
//!   another entry.

use std::{net::Ipv6Addr, time::Duration};

use tenko_core::{
    NodeId, PrefixId, Revision, Timestamp, VrfId,
    dhcp::{
        BindingState, Lease6, Lease6Kind, LeaseEventKind,
        lease::{MAX_IDENTITY6, write_identity6},
    },
};
use tenko_dhcp::v6::lease::{Binding6, Lease6Index, Lease6Table as _, PendingChange6};

const NODE: NodeId = NodeId(1);

fn vrf() -> VrfId {
    VrfId::from_uuid(uuid::Uuid::nil())
}

fn addr(text: &str) -> Ipv6Addr {
    text.parse().expect("an address")
}

/// The DUID-LL of client `k` (RFC 7042 documentation MACs).
fn duid(k: u8) -> Vec<u8> {
    vec![0, 3, 0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, k]
}

fn at(secs: u64) -> Timestamp {
    Timestamp::from_unix_nanos(1_800_000_000_000_000_000)
        .expect("a time")
        .checked_add(Duration::from_secs(secs))
        .expect("a later time")
}

/// The row of a binding of `kind` at `address`/`len` for `iaid` and client `k` in `scope`,
/// written by the client's transaction at `cltt`.
fn row(
    kind: Lease6Kind,
    scope: PrefixId,
    iaid: u32,
    k: u8,
    (address, len): (Ipv6Addr, u8),
    cltt: Timestamp,
) -> Lease6 {
    let ends = cltt
        .checked_add(Duration::from_secs(4_000))
        .expect("an end");
    let mut change = PendingChange6::new(&duid(k), cltt);
    let binding = Binding6 {
        event: LeaseEventKind::Granted,
        kind,
        vrf: vrf(),
        scope,
        iaid,
        addr: address,
        prefix_len: len,
        state: BindingState::Active,
        preferred_ends: ends,
        ends,
    };
    assert!(change.push(binding));
    change.to_lease(&binding, NODE, None)
}

fn identity(iaid: u32, k: u8) -> Vec<u8> {
    let mut out = [0u8; MAX_IDENTITY6];
    let len = write_identity6(iaid, &duid(k), &mut out);
    out[..len].to_vec()
}

const ADDRESS: &str = "2001:db8:1::100";
const PREFIX: &str = "2001:db8:180:110::";

fn na(scope: PrefixId, iaid: u32, k: u8, cltt: Timestamp) -> Lease6 {
    row(Lease6Kind::Na, scope, iaid, k, (addr(ADDRESS), 128), cltt)
}

fn pd(scope: PrefixId, iaid: u32, k: u8, cltt: Timestamp) -> Lease6 {
    row(Lease6Kind::Pd, scope, iaid, k, (addr(PREFIX), 60), cltt)
}

#[test]
fn an_address_row_and_a_prefix_row_of_one_scope_iaid_and_duid_are_found_by_their_kind() {
    let (scope, other_scope) = (PrefixId::generate(), PrefixId::generate());
    let mut table = Lease6Index::new();
    assert!(table.apply_at(na(scope, 1, 1, at(0)), Revision::ZERO));
    assert!(table.apply_at(pd(scope, 1, 1, at(1)), Revision::ZERO));
    assert_eq!(table.len(), 2);
    let who = identity(1, 1);
    assert_eq!(
        pd(scope, 1, 1, at(1)).identity(),
        who,
        "one identity for both kinds"
    );
    let found_na = table
        .by_client(scope, Lease6Kind::Na, &who)
        .expect("the address");
    assert_eq!(found_na.addr6(), addr(ADDRESS));
    assert_eq!((found_na.kind, found_na.prefix_len), (Lease6Kind::Na, 128));
    let found_pd = table
        .by_client(scope, Lease6Kind::Pd, &who)
        .expect("the prefix");
    assert_eq!(found_pd.addr6(), addr(PREFIX));
    assert_eq!((found_pd.kind, found_pd.prefix_len), (Lease6Kind::Pd, 60));
    // Another scope, IAID or client holds neither.
    for kind in [Lease6Kind::Na, Lease6Kind::Pd] {
        assert!(table.by_client(other_scope, kind, &who).is_none());
        assert!(table.by_client(scope, kind, &identity(2, 1)).is_none());
        assert!(table.by_client(scope, kind, &identity(1, 2)).is_none());
    }
    // The rows are the same by address.
    assert_eq!(table.get(vrf(), addr(ADDRESS)), Some(found_na));
    assert_eq!(table.get(vrf(), addr(PREFIX)), Some(found_pd));
}

#[test]
fn the_same_identity_in_another_scope_is_another_entry() {
    let (one, two) = (PrefixId::generate(), PrefixId::generate());
    let mut table = Lease6Index::new();
    let prefix_two = row(
        Lease6Kind::Pd,
        two,
        1,
        1,
        (addr("2001:db8:181:4200::"), 56),
        at(2),
    );
    assert!(table.apply_at(pd(one, 1, 1, at(1)), Revision::ZERO));
    assert!(table.apply_at(prefix_two, Revision::ZERO));
    let who = identity(1, 1);
    assert_eq!(
        table
            .by_client(one, Lease6Kind::Pd, &who)
            .map(Lease6::addr6),
        Some(addr(PREFIX))
    );
    assert_eq!(
        table
            .by_client(two, Lease6Kind::Pd, &who)
            .map(|lease| (lease.addr6(), lease.prefix_len)),
        Some((addr("2001:db8:181:4200::"), 56))
    );
}

#[test]
fn taking_one_row_keeps_the_other_of_the_pair_indexed() {
    let scope = PrefixId::generate();
    let who = identity(1, 1);
    for take_prefix_first in [false, true] {
        let mut table = Lease6Index::new();
        table.apply_at(na(scope, 1, 1, at(0)), Revision::ZERO);
        table.apply_at(pd(scope, 1, 1, at(1)), Revision::ZERO);
        let (first, kept) = if take_prefix_first {
            (addr(PREFIX), Lease6Kind::Na)
        } else {
            (addr(ADDRESS), Lease6Kind::Pd)
        };
        let gone = if kept == Lease6Kind::Na {
            Lease6Kind::Pd
        } else {
            Lease6Kind::Na
        };
        let taken = table.take(vrf(), first).expect("the row");
        assert_eq!(taken.kind, gone);
        assert_eq!(table.len(), 1);
        assert!(table.by_client(scope, gone, &who).is_none());
        assert!(table.get(vrf(), first).is_none());
        let still = table.by_client(scope, kept, &who).expect("the other row");
        assert_eq!(still.kind, kept);
        // Taking the same row again finds nothing; the other row is untouched.
        assert!(table.take(vrf(), first).is_none());
        assert!(table.by_client(scope, kept, &who).is_some());
        // Taking the last row empties the table and the index.
        let last = if kept == Lease6Kind::Na {
            addr(ADDRESS)
        } else {
            addr(PREFIX)
        };
        assert!(table.take(vrf(), last).is_some());
        assert!(table.is_empty());
        for kind in [Lease6Kind::Na, Lease6Kind::Pd] {
            assert!(table.by_client(scope, kind, &who).is_none());
        }
    }
}

#[test]
fn a_row_that_moves_from_an_address_to_a_prefix_at_one_key_is_indexed_again() {
    let scope = PrefixId::generate();
    let who = identity(1, 1);
    let key = addr(PREFIX);
    let mut table = Lease6Index::new();
    let as_address = row(Lease6Kind::Na, scope, 1, 1, (key, 128), at(0));
    assert!(table.apply_at(as_address, Revision::ZERO));
    assert_eq!(
        table
            .by_client(scope, Lease6Kind::Na, &who)
            .map(Lease6::addr6),
        Some(key)
    );
    assert!(table.by_client(scope, Lease6Kind::Pd, &who).is_none());
    // The same key now holds a delegated prefix.
    let as_prefix = row(Lease6Kind::Pd, scope, 1, 1, (key, 60), at(1));
    assert!(table.apply_at(as_prefix, Revision::ZERO));
    assert_eq!(table.len(), 1);
    assert!(
        table.by_client(scope, Lease6Kind::Na, &who).is_none(),
        "no longer indexed as an address"
    );
    let found = table
        .by_client(scope, Lease6Kind::Pd, &who)
        .expect("indexed as a prefix");
    assert_eq!((found.addr6(), found.prefix_len), (key, 60));
    // And back.
    let again = row(Lease6Kind::Na, scope, 1, 1, (key, 128), at(2));
    assert!(table.apply_at(again, Revision::ZERO));
    assert!(table.by_client(scope, Lease6Kind::Pd, &who).is_none());
    assert_eq!(
        table
            .by_client(scope, Lease6Kind::Na, &who)
            .map(|lease| lease.prefix_len),
        Some(128)
    );
    assert_eq!(table.len(), 1);
    // Taking the row leaves nothing indexed under either kind.
    assert!(table.take(vrf(), key).is_some());
    for kind in [Lease6Kind::Na, Lease6Kind::Pd] {
        assert!(table.by_client(scope, kind, &who).is_none());
    }
}

#[test]
fn a_row_of_another_client_at_the_key_moves_the_index_with_it() {
    let scope = PrefixId::generate();
    let key = addr(PREFIX);
    let mut table = Lease6Index::new();
    table.apply_at(
        row(Lease6Kind::Pd, scope, 1, 1, (key, 60), at(0)),
        Revision::ZERO,
    );
    table.apply_at(
        row(Lease6Kind::Pd, scope, 7, 2, (key, 60), at(1)),
        Revision::ZERO,
    );
    assert!(
        table
            .by_client(scope, Lease6Kind::Pd, &identity(1, 1))
            .is_none()
    );
    assert_eq!(
        table
            .by_client(scope, Lease6Kind::Pd, &identity(7, 2))
            .map(Lease6::addr6),
        Some(key)
    );
}

#[test]
fn an_older_row_does_not_replace_a_newer_one_even_of_another_kind() {
    let scope = PrefixId::generate();
    let who = identity(1, 1);
    let key = addr(PREFIX);
    let mut table = Lease6Index::new();
    let newer = row(Lease6Kind::Pd, scope, 1, 1, (key, 60), at(10));
    assert!(table.apply_at(newer.clone(), Revision::ZERO));
    let older = row(Lease6Kind::Na, scope, 1, 1, (key, 128), at(5));
    assert!(!table.apply_at(older, Revision::ZERO));
    assert_eq!(table.get(vrf(), key), Some(&newer));
    assert!(table.by_client(scope, Lease6Kind::Na, &who).is_none());
    assert_eq!(table.by_client(scope, Lease6Kind::Pd, &who), Some(&newer));
}

#[test]
fn the_latest_prefix_of_a_client_is_the_one_found() {
    let scope = PrefixId::generate();
    let who = identity(3, 1);
    let (first, second) = (addr("2001:db8:180:110::"), addr("2001:db8:180:120::"));
    let mut table = Lease6Index::new();
    table.apply_at(
        row(Lease6Kind::Pd, scope, 3, 1, (first, 60), at(0)),
        Revision::ZERO,
    );
    table.apply_at(
        row(Lease6Kind::Pd, scope, 3, 1, (second, 60), at(100)),
        Revision::ZERO,
    );
    assert_eq!(
        table
            .by_client(scope, Lease6Kind::Pd, &who)
            .map(Lease6::addr6),
        Some(second)
    );
    // Without the later row the earlier one is the client's.
    assert!(table.take(vrf(), second).is_some());
    assert_eq!(
        table
            .by_client(scope, Lease6Kind::Pd, &who)
            .map(Lease6::addr6),
        Some(first)
    );
}
