//! The address list of a prefix starts inside the prefix, whatever cursor the client sends:
//! a cursor below the prefix gives the first page, one above it an empty page, and no row
//! (address or free gap) lies outside the prefix.

mod common;

use std::net::IpAddr;

use common::*;
use tenko_core::PrefixId;
use tenko_ipam::{
    IpamCommand,
    query::{self, PrefixAddressItem},
};

fn number(text: &str) -> u128 {
    match ip(text) {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn cursor_at(text: &str) -> String {
    format!("{:032x}", number(text))
}

/// The address objects of a page, as text.
fn addresses(items: &[PrefixAddressItem]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            PrefixAddressItem::Address(row) => Some(row.address.ip.to_string()),
            PrefixAddressItem::Free { .. } => None,
        })
        .collect()
}

/// Every row of a page lies inside `cidr`.
fn assert_inside(cidr: &str, items: &[PrefixAddressItem]) {
    let net = net(cidr);
    for item in items {
        match item {
            PrefixAddressItem::Address(row) => {
                assert!(
                    net.contains(&row.address.ip),
                    "{} outside {cidr}",
                    row.address.ip
                );
            }
            PrefixAddressItem::Free { first, last, .. } => {
                assert!(net.contains(first), "free {first} outside {cidr}");
                assert!(net.contains(last), "free {last} outside {cidr}");
            }
        }
    }
}

struct Case {
    supernet: &'static str,
    network: &'static str,
    below: &'static str,
    first: &'static str,
    inside: [&'static str; 2],
    last: &'static str,
    above: &'static str,
}

async fn check(case: &Case) {
    let (service, _store) = service();
    let network = prefix(None, case.network);
    let network_id: PrefixId = network.id.expect("id");
    let mut commands = vec![
        IpamCommand::CreatePrefix(supernet(None, case.supernet)),
        IpamCommand::CreatePrefix(network),
    ];
    for ip in [case.below, case.inside[0], case.inside[1], case.above] {
        commands.push(IpamCommand::CreateAddress(address(None, ip)));
    }
    run(&service, commands).await;
    let view = snapshot(&service).await;
    let page = |cursor: Option<&str>, free: bool, limit: usize| {
        query::prefix_addresses(view.as_ref(), network_id, free, cursor, Some(limit)).expect("page")
    };
    let all: Vec<String> = case.inside.iter().map(|ip| (*ip).to_string()).collect();

    // Below the prefix (an address of the same VRF, zero) and at its first address: the
    // first page.
    for cursor in [
        cursor_at(case.below),
        format!("{:032x}", 0_u128),
        cursor_at(case.first),
    ] {
        for free in [false, true] {
            let page = page(Some(&cursor), free, 50);
            assert_inside(case.network, &page.items);
            assert_eq!(addresses(&page.items), all, "cursor {cursor}, free {free}");
            assert!(page.next_cursor.is_none());
        }
    }
    // No cursor is the same page.
    assert_eq!(addresses(&page(None, false, 50).items), all);

    // Inside: the page continues from the cursor, inclusive.
    let inside = page(Some(&cursor_at(case.inside[1])), true, 50);
    assert_inside(case.network, &inside.items);
    assert_eq!(addresses(&inside.items), vec![case.inside[1].to_string()]);

    // At the last address and above the prefix: nothing to list.
    for cursor in [
        cursor_at(case.last),
        cursor_at(case.above),
        format!("{:032x}", u128::MAX),
    ] {
        for free in [false, true] {
            let page = page(Some(&cursor), free, 50);
            assert_inside(case.network, &page.items);
            assert!(addresses(&page.items).is_empty(), "cursor {cursor}");
            assert!(page.next_cursor.is_none());
        }
    }

    // Paging one row at a time from below walks the prefix without leaving it.
    let mut cursor = Some(cursor_at(case.below));
    let mut seen = Vec::new();
    while let Some(current) = cursor {
        let page = page(Some(&current), true, 1);
        assert_inside(case.network, &page.items);
        seen.extend(addresses(&page.items));
        cursor = page.next_cursor;
    }
    assert_eq!(seen, all);
}

#[tokio::test]
async fn ipv4_page_starts_inside_the_prefix() {
    check(&Case {
        supernet: "192.0.2.0/24",
        network: "192.0.2.64/26",
        below: "192.0.2.10",
        first: "192.0.2.64",
        inside: ["192.0.2.70", "192.0.2.100"],
        last: "192.0.2.127",
        above: "192.0.2.200",
    })
    .await;
}

#[tokio::test]
async fn ipv6_page_starts_inside_the_prefix() {
    check(&Case {
        supernet: "2001:db8::/32",
        network: "2001:db8:0:1::100/120",
        below: "2001:db8:0:1::10",
        first: "2001:db8:0:1::100",
        inside: ["2001:db8:0:1::110", "2001:db8:0:1::150"],
        last: "2001:db8:0:1::1ff",
        above: "2001:db8:0:1::200",
    })
    .await;
}
