//! The trusted relays of the DHCPv4 engine (`dhcp.settings.trusted_relays`,
//! `tenko_dhcp::relay`): relay data counts only from a trusted sender, replies never go to
//! an address a request only names, and a client cannot hide its MAC from the deny list.

mod engine_world;

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

use engine_world::{Ask, RELAY, SERVER, World, ip, mac, t0};
use tenko_dhcp::{
    guard::DhcpProfile,
    v4::{
        Message, MessageType,
        engine::{Action, Answer, Destination, DropReason, Scratch, Selector},
    },
};

/// Sub-option 5 (link selection, RFC 3527) for `addr`.
fn link_selection(addr: &str) -> Vec<u8> {
    let mut out = vec![5, 4];
    out.extend(ip(addr).octets());
    out
}

/// Sub-option 11 (server identifier override, RFC 5107) for `addr`.
fn server_override(addr: &str) -> Vec<u8> {
    let mut out = vec![11, 4];
    out.extend(ip(addr).octets());
    out
}

fn reply<'s>(answer: &Answer, scratch: &'s Scratch) -> (Message<'s>, Destination) {
    let (Action::Reply { len, dest, .. } | Action::CommitThenReply { len, dest, .. }) =
        answer.action
    else {
        panic!("a reply, got {:?}", answer.action);
    };
    (Message::parse(&scratch.reply[..len]).expect("parse"), dest)
}

fn relayed_discover(client: u8) -> Vec<u8> {
    Ask::new(MessageType::Discover, client).bytes()
}

#[test]
fn without_a_list_only_lab_trusts_a_relay_and_a_refused_one_is_reported() {
    for profile in [
        DhcpProfile::Home,
        DhcpProfile::Standard,
        DhcpProfile::Hardened,
    ] {
        let world = World::trusting(profile, None);
        let mut scratch = Scratch::new();
        let answer = world.run(&relayed_discover(0x30), t0(), &mut scratch);
        assert_eq!(
            answer.action,
            Action::Drop(DropReason::UntrustedRelay),
            "{profile:?}"
        );
        let report = world.guard.relay_report(Some(&world.image));
        assert!(!report.listed && !report.trust_any && report.untrusted());
        assert_eq!(report.refused.len(), 1);
        assert_eq!(report.refused[0].source, IpAddr::V4(RELAY));
        assert_eq!(report.refused[0].relay, IpAddr::V4(RELAY));
        assert_eq!(report.refused[0].count, 1);
    }
    let lab = World::trusting(DhcpProfile::Lab, None);
    let mut scratch = Scratch::new();
    let answer = lab.run(&relayed_discover(0x30), t0(), &mut scratch);
    let (offer, dest) = reply(&answer, &scratch);
    assert_eq!(offer.message_type().expect("53"), Some(MessageType::Offer));
    assert_eq!(dest, Destination::Relay(SocketAddrV4::new(RELAY, 67)));
    let report = lab.guard.relay_report(Some(&lab.image));
    assert!(report.trust_any && !report.untrusted());
}

#[test]
fn a_listed_relay_is_served_under_every_profile_and_an_empty_list_refuses_under_lab_too() {
    for profile in [
        DhcpProfile::Lab,
        DhcpProfile::Home,
        DhcpProfile::Standard,
        DhcpProfile::Hardened,
    ] {
        let world = World::trusting(profile, Some(&["192.0.2.0/30"]));
        let mut scratch = Scratch::new();
        let answer = world.run(&relayed_discover(0x30), t0(), &mut scratch);
        let (offer, _) = reply(&answer, &scratch);
        assert!(
            ipnet::Ipv4Net::new(ip("192.0.2.0"), 24)
                .expect("net")
                .contains(&offer.yiaddr()),
            "{profile:?}"
        );
        assert_eq!(answer.selector, Some(Selector::Giaddr));
        // Another sender naming the same relay is refused.
        let other = world.run_from(
            &relayed_discover(0x31),
            SocketAddrV4::new(ip("192.0.2.9"), 67),
            t0(),
            &mut scratch,
        );
        assert_eq!(other.action, Action::Drop(DropReason::UntrustedRelay));
        let report = world.guard.relay_report(Some(&world.image));
        assert!(report.listed && report.relayed.is_empty());
        assert_eq!(report.refused[0].source, IpAddr::V4(ip("192.0.2.9")));
    }
    let world = World::trusting(DhcpProfile::Lab, Some(&[]));
    let mut scratch = Scratch::new();
    let answer = world.run(&relayed_discover(0x30), t0(), &mut scratch);
    assert_eq!(answer.action, Action::Drop(DropReason::UntrustedRelay));
}

#[test]
fn a_trusted_relay_still_selects_by_link_selection_and_option_118() {
    let world = World::trusting(DhcpProfile::Home, Some(&["192.0.2.1/32"]));
    let mut scratch = Scratch::new();
    let mut ask = Ask::new(MessageType::Discover, 0x30);
    ask.relay = Some(link_selection("203.0.113.0"));
    let answer = world.run(&ask.bytes(), t0(), &mut scratch);
    assert_eq!(answer.selector, Some(Selector::LinkSelection));
    let mut ask = Ask::new(MessageType::Discover, 0x31);
    ask.subnet = Some(ip("203.0.113.0"));
    let answer = world.run(&ask.bytes(), t0(), &mut scratch);
    assert_eq!(answer.selector, Some(Selector::SubnetSelection));
    let (offer, _) = reply(&answer, &scratch);
    assert_eq!(offer.yiaddr().octets()[..3], [203, 0, 113]);
}

#[test]
fn a_client_that_is_no_relay_selects_no_scope_and_no_server_identifier_and_its_option_82_is_echoed()
{
    // A client on the listener's link (scope B) names scope C by option 118 and by the link
    // selection sub-option, and a server identifier of its choice by sub-option 11.
    for profile in [DhcpProfile::Home, DhcpProfile::Hardened] {
        let world = World::trusting(profile, Some(&["192.0.2.1/32"]));
        let mut scratch = Scratch::new();
        let mut ask = Ask::new(MessageType::Discover, 0x30);
        ask.giaddr = None;
        ask.subnet = Some(ip("203.0.113.0"));
        let mut relay = link_selection("203.0.113.0");
        relay.extend(server_override("192.0.2.99"));
        ask.relay = Some(relay.clone());
        let answer = world.run(&ask.bytes(), t0(), &mut scratch);
        assert_eq!(answer.selector, Some(Selector::Interface), "{profile:?}");
        let (offer, _) = reply(&answer, &scratch);
        assert_eq!(offer.yiaddr().octets()[..3], [198, 51, 100]);
        assert_eq!(offer.server_identifier().expect("54"), Some(SERVER));
        let echoed = offer
            .relay_agent_info()
            .expect("82")
            .expect("option 82 is echoed");
        assert_eq!(echoed.as_bytes(), relay.as_slice());
        // Nothing was refused: the client sent no `giaddr`.
        assert_eq!(
            world.guard.relay_report(Some(&world.image)).refused,
            Vec::new()
        );
    }
    // Under Lab without a list the same request selects scope C, as before the list.
    let lab = World::trusting(DhcpProfile::Lab, None);
    let mut scratch = Scratch::new();
    let mut ask = Ask::new(MessageType::Discover, 0x30);
    ask.giaddr = None;
    ask.subnet = Some(ip("203.0.113.0"));
    let answer = lab.run(&ask.bytes(), t0(), &mut scratch);
    assert_eq!(answer.selector, Some(Selector::SubnetSelection));
}

#[test]
fn replies_go_to_the_sender_and_never_to_an_address_the_request_only_names() {
    let world = World::trusting(DhcpProfile::Lab, None);
    let mut scratch = Scratch::new();
    let victim = ip("203.0.113.9");
    let sender = ip("198.51.100.7");
    let mut inform = Ask::new(MessageType::Inform, 0x30);
    inform.giaddr = None;
    inform.ciaddr = Some(victim);
    let answer = world.run_from(
        &inform.bytes(),
        SocketAddrV4::new(sender, 68),
        t0(),
        &mut scratch,
    );
    let (_, dest) = reply(&answer, &scratch);
    assert_eq!(dest, Destination::Client(SocketAddrV4::new(sender, 68)));
    // From its own address, the client gets the reply there (RFC 2131 section 4.1).
    let answer = world.run_from(
        &inform.bytes(),
        SocketAddrV4::new(victim, 68),
        t0(),
        &mut scratch,
    );
    let (_, dest) = reply(&answer, &scratch);
    assert_eq!(dest, Destination::Client(SocketAddrV4::new(victim, 68)));
    // A client with an address that sends from no address is answered on its link.
    let answer = world.run_from(
        &inform.bytes(),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
        t0(),
        &mut scratch,
    );
    let (_, dest) = reply(&answer, &scratch);
    assert_eq!(dest, Destination::Broadcast(68));
}

#[test]
fn a_denied_mac_cannot_hide_behind_a_wrong_hardware_length_or_the_ieee_802_type() {
    let world = World::trusting(DhcpProfile::Lab, None);
    let mut scratch = Scratch::new();
    let denied = Ask::new(MessageType::Discover, 0x66).bytes();
    let answer = world.run(&denied, t0(), &mut scratch);
    assert_eq!(answer.action, Action::Drop(DropReason::Filtered));
    // `hlen` 7 with `htype` 1: refused, not served without the filter.
    let mut longer = denied.clone();
    longer[2] = 7;
    let answer = world.run(&longer, t0(), &mut scratch);
    assert_eq!(answer.action, Action::Drop(DropReason::Malformed));
    // `htype` 6 (IEEE 802) with six octets: the filter reads the same MAC.
    let mut ieee = denied;
    ieee[1] = 6;
    let answer = world.run(&ieee, t0(), &mut scratch);
    assert_eq!(answer.action, Action::Drop(DropReason::Filtered));
    // Another hardware type with six octets: the same MAC, filtered.
    let mut token_ring = Ask::new(MessageType::Discover, 0x66).bytes();
    token_ring[1] = 4;
    let answer = world.run(&token_ring, t0(), &mut scratch);
    assert_eq!(answer.action, Action::Drop(DropReason::Filtered));
    // Another hardware type of another length has no MAC to filter and is served.
    let mut other = Ask::new(MessageType::Discover, 0x30).bytes();
    other[1] = 32;
    other[2] = 0;
    let answer = world.run(&other, t0(), &mut scratch);
    assert!(matches!(answer.action, Action::Reply { .. }), "{answer:?}");
    assert_eq!(mac(0x66)[5], 0x66);
}

/// The relay's refusals of links outside its own, as the report keeps them.
fn link_refusals(world: &World) -> Vec<(IpAddr, Option<ipnet::IpNet>, u64)> {
    world
        .guard
        .relay_report(Some(&world.image))
        .refused
        .iter()
        .filter(|refused| refused.link.is_some())
        .map(|refused| (refused.source, refused.link, refused.count))
        .collect()
}

fn net(text: &str) -> ipnet::IpNet {
    text.parse().expect("a prefix")
}

#[test]
fn a_trusted_relay_names_only_its_own_links_by_giaddr_option_82_and_option_118() {
    // The relay at 192.0.2.1 serves the link of scope A only. Whoever sends from its address
    // (the relay, or a host that forges it) is served on that link and nowhere else.
    for profile in [
        DhcpProfile::Lab,
        DhcpProfile::Home,
        DhcpProfile::Standard,
        DhcpProfile::Hardened,
    ] {
        let world = World::trusting(profile, Some(&["192.0.2.1/32=192.0.2.0/24"]));
        let mut scratch = Scratch::new();
        // Its own link: served, as before.
        let answer = world.run(&relayed_discover(0x40), t0(), &mut scratch);
        assert_eq!(answer.selector, Some(Selector::Giaddr), "{profile:?}");
        let (offer, _) = reply(&answer, &scratch);
        assert_eq!(offer.yiaddr().octets()[..3], [192, 0, 2], "{profile:?}");
        assert!(link_refusals(&world).is_empty(), "{profile:?}");
        // Another link by giaddr, by the link selection sub-option and by option 118.
        let mut by_giaddr = Ask::new(MessageType::Discover, 0x41);
        by_giaddr.giaddr = Some(ip("203.0.113.1"));
        let mut by_link = Ask::new(MessageType::Discover, 0x42);
        by_link.relay = Some(link_selection("203.0.113.0"));
        let mut by_subnet = Ask::new(MessageType::Discover, 0x43);
        by_subnet.subnet = Some(ip("203.0.113.0"));
        let mut by_listener = Ask::new(MessageType::Request, 0x44);
        by_listener.giaddr = Some(ip("198.51.100.1"));
        by_listener.requested = Some(ip("198.51.100.150"));
        for (ask, selector) in [
            (&by_giaddr, Selector::Giaddr),
            (&by_link, Selector::LinkSelection),
            (&by_subnet, Selector::SubnetSelection),
            (&by_listener, Selector::Giaddr),
        ] {
            let answer = world.run_from(
                &ask.bytes(),
                SocketAddrV4::new(RELAY, 67),
                t0(),
                &mut scratch,
            );
            assert_eq!(
                answer.action,
                Action::Drop(DropReason::UntrustedRelay),
                "{profile:?} {selector:?}"
            );
            assert_eq!(answer.selector, Some(selector), "{profile:?}");
        }
        // Each refusal is logged with the link it named (one entry per sender, the last
        // link named), and the health row says what to do.
        assert_eq!(
            link_refusals(&world),
            [(IpAddr::V4(RELAY), Some(net("198.51.100.0/24")), 4)],
            "{profile:?}"
        );
        let report = world.guard.relay_report(Some(&world.image));
        let refused: u64 = report.refused.iter().map(|refused| refused.count).sum();
        assert_eq!(refused, 4, "{profile:?}");
        let rows = report.warnings();
        let row = rows
            .iter()
            .find(|row| row.code == tenko_dhcp::relay::LINK_REFUSED)
            .expect("a link row");
        assert_eq!(row.params["senders"], "192.0.2.1", "{profile:?}");
        assert!(
            row.detail
                .contains("add the link to the relay under the DHCP settings"),
            "{row:?}"
        );
        assert!(
            rows.iter()
                .all(|row| row.code != tenko_dhcp::relay::UNTRUSTED),
            "{rows:?}"
        );
    }
}

#[test]
fn a_relay_bound_to_more_links_serves_each_of_them_and_a_client_without_a_relay_is_unchanged() {
    let world = World::trusting(
        DhcpProfile::Standard,
        Some(&["192.0.2.1/32=192.0.2.0/24+203.0.113.0/24"]),
    );
    let mut scratch = Scratch::new();
    let mut ask = Ask::new(MessageType::Discover, 0x50);
    ask.relay = Some(link_selection("203.0.113.0"));
    let answer = world.run(&ask.bytes(), t0(), &mut scratch);
    assert_eq!(answer.selector, Some(Selector::LinkSelection));
    let (offer, _) = reply(&answer, &scratch);
    assert_eq!(offer.yiaddr().octets()[..3], [203, 0, 113]);
    // A link given as the relay's own giaddr (/32) names the scope around it.
    let world = World::trusting(DhcpProfile::Standard, Some(&["192.0.2.1/32=192.0.2.1/32"]));
    let answer = world.run(&relayed_discover(0x51), t0(), &mut scratch);
    assert!(matches!(answer.action, Action::Reply { .. }), "{answer:?}");
    // A client of the listener's link, not relayed, is not a relay's word at all.
    let mut ask = Ask::new(MessageType::Discover, 0x52);
    ask.giaddr = None;
    ask.broadcast = true;
    let answer = world.run_from(
        &ask.bytes(),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
        t0(),
        &mut scratch,
    );
    assert_eq!(answer.selector, Some(Selector::Interface));
    assert!(matches!(answer.action, Action::Reply { .. }), "{answer:?}");
}

#[test]
fn the_most_specific_relay_entry_decides_the_links_of_a_sender() {
    // The routers of 192.0.2.0/24 may name scope C; the one at 192.0.2.1 only scope A.
    let world = World::trusting(
        DhcpProfile::Home,
        Some(&["192.0.2.0/24=203.0.113.0/24", "192.0.2.1/32=192.0.2.0/24"]),
    );
    let mut scratch = Scratch::new();
    let mut to_c = Ask::new(MessageType::Discover, 0x60);
    to_c.giaddr = Some(ip("203.0.113.1"));
    let from = |host: Ipv4Addr| SocketAddrV4::new(host, 67);
    let answer = world.run_from(&to_c.bytes(), from(RELAY), t0(), &mut scratch);
    assert_eq!(answer.action, Action::Drop(DropReason::UntrustedRelay));
    let answer = world.run_from(&to_c.bytes(), from(ip("192.0.2.7")), t0(), &mut scratch);
    assert!(matches!(answer.action, Action::Reply { .. }), "{answer:?}");
    let answer = world.run(&relayed_discover(0x61), t0(), &mut scratch);
    assert!(matches!(answer.action, Action::Reply { .. }), "{answer:?}");
    let mut to_a = Ask::new(MessageType::Discover, 0x62);
    to_a.giaddr = Some(RELAY);
    let answer = world.run_from(&to_a.bytes(), from(ip("192.0.2.7")), t0(), &mut scratch);
    assert_eq!(answer.action, Action::Drop(DropReason::UntrustedRelay));
}

#[test]
fn a_relay_list_stored_before_relays_had_links_works_as_before_and_raises_its_health_row() {
    // The row of the old shape, as the store holds it: plain prefixes.
    #[derive(serde::Serialize)]
    struct OldRow {
        trusted_relays: Vec<ipnet::IpNet>,
    }
    let old = tenko_core::codec::to_cbor(&OldRow {
        trusted_relays: vec![net("192.0.2.1/32")],
    })
    .expect("cbor");
    let settings: tenko_core::dhcp::DhcpSettings =
        tenko_core::codec::from_cbor(&old).expect("the old row reads");
    for profile in [DhcpProfile::Standard, DhcpProfile::Hardened] {
        let world = World::with_relays(profile, settings.trusted_relays.as_deref());
        let mut scratch = Scratch::new();
        // Unchanged: the relay is served on every link, as the plain prefix meant.
        let answer = world.run(&relayed_discover(0x70), t0(), &mut scratch);
        assert!(matches!(answer.action, Action::Reply { .. }), "{answer:?}");
        let mut to_c = Ask::new(MessageType::Discover, 0x71);
        to_c.giaddr = Some(ip("203.0.113.1"));
        let answer = world.run(&to_c.bytes(), t0(), &mut scratch);
        assert!(matches!(answer.action, Action::Reply { .. }), "{answer:?}");
        // Another sender is still refused.
        let answer = world.run_from(
            &to_c.bytes(),
            SocketAddrV4::new(ip("192.0.2.2"), 67),
            t0(),
            &mut scratch,
        );
        assert_eq!(answer.action, Action::Drop(DropReason::UntrustedRelay));
        // The health row names the relay and what to do.
        let rows = world.guard.relay_report(Some(&world.image)).warnings();
        let row = rows
            .iter()
            .find(|row| row.code == tenko_dhcp::relay::ANY_LINK)
            .expect("the any-link row");
        assert_eq!(row.params["relays"], "192.0.2.1/32");
        assert!(
            row.detail.contains("give each relay the links it serves"),
            "{row:?}"
        );
        assert_eq!(
            row.detail
                .contains("the Hardened profile refuses such an entry"),
            profile == DhcpProfile::Hardened,
            "{row:?}"
        );
    }
}
