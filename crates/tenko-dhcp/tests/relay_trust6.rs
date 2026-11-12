//! The trusted relays of the DHCPv6 engine (`dhcp.settings.trusted_relays`): a RELAY-FORW
//! is served only from a trusted relay, and an inner relay that names a link only when the
//! relay above it received its message from a trusted address.

mod engine6_world;

use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};

use engine6_world::{
    LINK1, LINK2, RELAY, World6, addr, addresses, client_options, duid_ll, ia_na, message, relay1,
    relayed,
};
use tenko_dhcp::{
    guard::DhcpProfile,
    v4::engine::DropReason,
    v6::{
        MessageType,
        engine::{Action6, Selector6},
    },
};

fn mac(k: u8) -> [u8; 6] {
    [0x00, 0x00, 0x5e, 0x00, 0x53, k]
}

fn solicit(duid: &[u8]) -> Vec<u8> {
    message(MessageType::Solicit, 0x00_1234, |b| {
        client_options(b, duid);
        ia_na(b, 1, None);
    })
}

fn served(world: &mut World6, bytes: &[u8]) -> bool {
    matches!(world.exchange(bytes).0.action, Action6::Reply { .. })
}

#[test]
fn a_relay_forw_is_served_only_from_a_trusted_relay() {
    let duid = duid_ll(mac(1));
    for profile in [
        DhcpProfile::Home,
        DhcpProfile::Standard,
        DhcpProfile::Hardened,
    ] {
        let mut world = World6::trusting(profile, None);
        let (answer, _) = world.exchange(&relay1(&solicit(&duid)));
        assert_eq!(
            answer.action,
            Action6::Drop(DropReason::UntrustedRelay),
            "{profile:?}"
        );
        let report = world.guard.relay_report(Some(&world.image));
        assert_eq!(report.refused[0].source, IpAddr::V6(RELAY));
        assert_eq!(report.refused[0].relay, IpAddr::V6(LINK1));
    }
    let mut lab = World6::trusting(DhcpProfile::Lab, None);
    assert!(served(&mut lab, &relay1(&solicit(&duid))));
    let mut listed = World6::trusting(DhcpProfile::Home, Some(&["2001:db8:ff::1/128"]));
    assert!(served(&mut listed, &relay1(&solicit(&duid))));
    // A client that wraps its own SOLICIT and sends it from its own address is refused.
    let (answer, _) = listed.exchange(&[]);
    assert!(matches!(answer.action, Action6::Drop(_)));
    let forged = relayed(
        &solicit(&duid),
        &[(LINK2, addr("fe80::200:5eff:fe00:5301"), None)],
        None,
    );
    let answer = listed.handle_from(
        &forged,
        SocketAddrV6::new(addr("2001:db8:1::77"), 547, 0, 0),
    );
    assert_eq!(answer.action, Action6::Drop(DropReason::UntrustedRelay));
    // A client on the listener's link without a relay is served as before.
    let answer = listed.handle_from(
        &solicit(&duid),
        SocketAddrV6::new(addr("fe80::200:5eff:fe00:5301"), 546, 0, 0),
    );
    assert!(matches!(answer.action, Action6::Reply { .. }), "{answer:?}");
    assert_eq!(answer.selector, Some(Selector6::Listener));
}

#[test]
fn an_inner_relay_that_names_a_link_must_have_come_from_a_trusted_address() {
    let duid = duid_ll(mac(2));
    // A client behind the trusted relay wraps its SOLICIT in a RELAY-FORW naming the second
    // link: the trusted relay received it from the client's address, which is not trusted.
    let forged = relayed(
        &solicit(&duid),
        &[
            (LINK2, addr("fe80::1"), None),
            (LINK1, addr("fe80::200:5eff:fe00:5302"), None),
        ],
        None,
    );
    let mut world = World6::trusting(DhcpProfile::Home, Some(&["2001:db8:ff::1/128"]));
    let (answer, _) = world.exchange(&forged);
    assert_eq!(answer.action, Action6::Drop(DropReason::UntrustedRelay));
    let report = world.guard.relay_report(Some(&world.image));
    assert_eq!(
        report.refused[0].source,
        IpAddr::V6(addr("fe80::200:5eff:fe00:5302"))
    );
    // The same chain is served when the inner relay's address is trusted as well.
    let inner: Ipv6Addr = addr("2001:db8:1::2");
    let chain = relayed(
        &solicit(&duid),
        &[(LINK2, addr("fe80::1"), None), (LINK1, inner, None)],
        None,
    );
    let mut world = World6::trusting(
        DhcpProfile::Home,
        Some(&["2001:db8:ff::1/128", "2001:db8:1::2/128"]),
    );
    let (answer, _) = world.exchange(&chain);
    assert!(matches!(answer.action, Action6::Reply { .. }), "{answer:?}");
    assert_eq!(answer.selector, Some(Selector6::LinkAddress));
}

#[test]
fn a_lightweight_relay_s_data_counts_only_when_the_operator_trusts_lightweight_relays() {
    let duid = duid_ll(mac(5));
    // A RELAY-FORW of the lightweight form (link address `::`) that names the Interface-Id
    // of the second scope, below the trusted relay on the first link: what a real
    // lightweight relay sends, and what a client behind a relay without one can forge.
    let wrapped = relayed(
        &solicit(&duid),
        &[
            (Ipv6Addr::UNSPECIFIED, addr("fe80::1"), Some(b"vlan-20")),
            (LINK1, addr("fe80::200:5eff:fe00:5305"), None),
        ],
        Some(mac(0x99)),
    );
    let tune = |_: &mut _, second: &mut tenko_dhcp::v6::image::Scope6Image, _: &mut _| {
        second.interface_id = Some(b"vlan-20".to_vec());
    };
    // Without `fe80::/10` the chain is served by the trusted relay's link: the Interface-Id
    // of the inner relay selects nothing.
    let mut world = World6::trusting_with(DhcpProfile::Home, Some(&["2001:db8:ff::1/128"]), tune);
    let (answer, reply) = world.exchange(&wrapped);
    assert!(matches!(answer.action, Action6::Reply { .. }), "{answer:?}");
    assert_eq!(answer.selector, Some(Selector6::LinkAddress));
    assert_eq!(addresses(&reply.expect("a reply"))[0].1.segments()[2], 1);
    // With `fe80::/10` listed the operator says lightweight relays sit below the relay: the
    // Interface-Id selects the second scope.
    let mut world = World6::trusting_with(
        DhcpProfile::Home,
        Some(&["2001:db8:ff::1/128", "fe80::/10"]),
        tune,
    );
    let (answer, reply) = world.exchange(&wrapped);
    assert_eq!(answer.selector, Some(Selector6::InterfaceId));
    assert_eq!(addresses(&reply.expect("a reply"))[0].1.segments()[2], 2);
    // `fe80::/10` never makes a link-local sender a relay of its own.
    let answer = world.handle_from(
        &relay1(&solicit(&duid)),
        SocketAddrV6::new(addr("fe80::200:5eff:fe00:5305"), 547, 0, 0),
    );
    assert_eq!(answer.action, Action6::Drop(DropReason::UntrustedRelay));
}

fn net(text: &str) -> ipnet::IpNet {
    text.parse().expect("a prefix")
}

/// The refusals of links outside a relay's own: sender, link, count.
fn link_refusals(world: &World6) -> Vec<(IpAddr, Option<ipnet::IpNet>, u64)> {
    world
        .guard
        .relay_report(Some(&world.image))
        .refused
        .iter()
        .filter(|refused| refused.link.is_some())
        .map(|refused| (refused.source, refused.link, refused.count))
        .collect()
}

#[test]
fn a_trusted_relay_names_only_its_own_links_by_link_address_and_interface_id() {
    let duid = duid_ll(mac(6));
    let tune = |_: &mut _, second: &mut tenko_dhcp::v6::image::Scope6Image, _: &mut _| {
        second.interface_id = Some(b"vlan-20".to_vec());
    };
    for profile in [
        DhcpProfile::Lab,
        DhcpProfile::Home,
        DhcpProfile::Standard,
        DhcpProfile::Hardened,
    ] {
        // The relay serves the first link only.
        let mut world =
            World6::trusting_with(profile, Some(&["2001:db8:ff::1/128=2001:db8:1::/64"]), tune);
        // Its own link: served, as before.
        let (answer, _) = world.exchange(&relay1(&solicit(&duid)));
        assert!(matches!(answer.action, Action6::Reply { .. }), "{answer:?}");
        assert_eq!(answer.selector, Some(Selector6::LinkAddress));
        // The second link by link address, and by the Interface-Id of the second scope.
        let by_link = relayed(
            &solicit(&duid),
            &[(LINK2, addr("fe80::200:5eff:fe00:5306"), None)],
            None,
        );
        let by_interface = relayed(
            &solicit(&duid),
            &[(LINK1, addr("fe80::200:5eff:fe00:5306"), Some(b"vlan-20"))],
            None,
        );
        for (bytes, selector) in [
            (&by_link, Selector6::LinkAddress),
            (&by_interface, Selector6::InterfaceId),
        ] {
            let (answer, _) = world.exchange(bytes);
            assert_eq!(
                answer.action,
                Action6::Drop(DropReason::UntrustedRelay),
                "{profile:?} {selector:?}"
            );
            assert_eq!(answer.selector, Some(selector), "{profile:?}");
        }
        assert_eq!(
            link_refusals(&world),
            [(IpAddr::V6(RELAY), Some(net("2001:db8:2::/64")), 2)],
            "{profile:?}"
        );
        let rows = world.guard.relay_report(Some(&world.image)).warnings();
        let row = rows
            .iter()
            .find(|row| row.code == tenko_dhcp::relay::LINK_REFUSED)
            .expect("a link row");
        assert_eq!(row.params["links"], "2001:db8:2::/64");
        assert!(
            row.detail
                .contains("add the link to the relay under the DHCP settings"),
            "{row:?}"
        );
    }
}

#[test]
fn every_trusted_relay_of_a_chain_must_be_bound_to_the_client_s_link() {
    let duid = duid_ll(mac(7));
    let inner: Ipv6Addr = addr("2001:db8:1::2");
    // The inner relay names the second link; the outer relay received the message from it.
    let chain = relayed(
        &solicit(&duid),
        &[(LINK2, addr("fe80::1"), None), (LINK1, inner, None)],
        None,
    );
    let serve = |relays: &[&str]| {
        let mut world = World6::trusting(DhcpProfile::Home, Some(relays));
        let answer = world.exchange(&chain).0;
        (answer, link_refusals(&world))
    };
    // Both relays bound to the second link: served.
    let (answer, refused) = serve(&[
        "2001:db8:ff::1/128=2001:db8:1::/64+2001:db8:2::/64",
        "2001:db8:1::2/128=2001:db8:2::/64",
    ]);
    assert!(matches!(answer.action, Action6::Reply { .. }), "{answer:?}");
    assert_eq!(refused, Vec::new());
    // The outer relay is not: a host that forges its address cannot reach the second link
    // through an inner relay it makes up, even one that is trusted for that link.
    let (answer, refused) = serve(&[
        "2001:db8:ff::1/128=2001:db8:1::/64",
        "2001:db8:1::2/128=2001:db8:2::/64",
    ]);
    assert_eq!(answer.action, Action6::Drop(DropReason::UntrustedRelay));
    assert_eq!(
        refused,
        [(IpAddr::V6(RELAY), Some(net("2001:db8:2::/64")), 1)]
    );
    // The inner relay is not: refused by the peer address the outer relay recorded.
    let (answer, refused) = serve(&[
        "2001:db8:ff::1/128=2001:db8::/32",
        "2001:db8:1::2/128=2001:db8:1::/64",
    ]);
    assert_eq!(answer.action, Action6::Drop(DropReason::UntrustedRelay));
    assert_eq!(
        refused,
        [(IpAddr::V6(inner), Some(net("2001:db8:2::/64")), 1)]
    );
}

#[test]
fn lightweight_relays_below_a_bound_relay_stay_within_its_links() {
    let duid = duid_ll(mac(8));
    let wrapped = relayed(
        &solicit(&duid),
        &[
            (Ipv6Addr::UNSPECIFIED, addr("fe80::1"), Some(b"vlan-20")),
            (LINK1, addr("fe80::200:5eff:fe00:5308"), None),
        ],
        Some(mac(0x98)),
    );
    let tune = |_: &mut _, second: &mut tenko_dhcp::v6::image::Scope6Image, _: &mut _| {
        second.interface_id = Some(b"vlan-20".to_vec());
    };
    // `fe80::/10` for every link trusts the lightweight relays; the relay above them is
    // bound to the first link, so their Interface-Id cannot select the second.
    let mut world = World6::trusting_with(
        DhcpProfile::Hardened,
        Some(&["2001:db8:ff::1/128=2001:db8:1::/64", "fe80::/10=::/0"]),
        tune,
    );
    let (answer, _) = world.exchange(&wrapped);
    assert_eq!(answer.action, Action6::Drop(DropReason::UntrustedRelay));
    assert_eq!(answer.selector, Some(Selector6::InterfaceId));
    // Bound to both links, the relay's lightweight relays select the second.
    let mut world = World6::trusting_with(
        DhcpProfile::Hardened,
        Some(&[
            "2001:db8:ff::1/128=2001:db8:1::/64+2001:db8:2::/64",
            "fe80::/10=::/0",
        ]),
        tune,
    );
    let (answer, _) = world.exchange(&wrapped);
    assert!(matches!(answer.action, Action6::Reply { .. }), "{answer:?}");
    assert_eq!(answer.selector, Some(Selector6::InterfaceId));
    // The link-local prefix for every link is no any-link finding.
    let report = world.guard.relay_report(Some(&world.image));
    assert!(report.any_link.is_empty(), "{report:?}");
}

#[test]
fn a_v6_relay_stored_before_relays_had_links_names_every_link_and_raises_its_row() {
    let duid = duid_ll(mac(9));
    let settings: tenko_core::dhcp::DhcpSettings =
        serde_json::from_str(r#"{"trusted_relays":["2001:db8:ff::1/128"]}"#).expect("json");
    // The old row reads as the relay with every link of its family: the world's entry
    // without links is that entry.
    assert_eq!(
        settings.trusted_relays,
        Some(vec![engine6_world::trusted_relay("2001:db8:ff::1/128")])
    );
    let mut world = World6::trusting(DhcpProfile::Standard, Some(&["2001:db8:ff::1/128"]));
    let by_link = relayed(
        &solicit(&duid),
        &[(LINK2, addr("fe80::200:5eff:fe00:5309"), None)],
        None,
    );
    let (answer, _) = world.exchange(&by_link);
    assert!(matches!(answer.action, Action6::Reply { .. }), "{answer:?}");
    let rows = world.guard.relay_report(Some(&world.image)).warnings();
    let row = rows
        .iter()
        .find(|row| row.code == tenko_dhcp::relay::ANY_LINK)
        .expect("the any-link row");
    assert_eq!(row.params["relays"], "2001:db8:ff::1/128");
}
