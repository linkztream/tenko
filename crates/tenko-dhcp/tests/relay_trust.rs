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
