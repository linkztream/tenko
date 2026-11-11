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
