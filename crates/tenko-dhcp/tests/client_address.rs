//! The client's own address (`ciaddr`) and the network a request came from (RFC 2131
//! sections 4.1, 4.3.2 and 4.4.5, `docs/dhcp.md` section 9.1): a request that is not
//! relayed and names a `ciaddr` must come from that address's network, a renewal routed to
//! the server acts only on a lease the client holds, and a broadcast on the listener's link
//! is served as a client of that link.
//!
//! The world of `engine_world`: scope A `192.0.2.0/24` behind the relay 192.0.2.1 (client
//! :10 holds 192.0.2.110), scope B `198.51.100.0/24` the listener's link, scope C
//! `203.0.113.0/24` not authoritative.

mod engine_world;

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

use engine_world::{Ask, RELAY, SERVER, World, ip, t0};
use tenko_core::dhcp::{BindingState, LeaseEventKind};
use tenko_dhcp::{
    lease::LeaseTable,
    relay::WRONG_NETWORK,
    v4::{
        Message, MessageType,
        engine::{Action, Answer, Destination, DropReason, IgnoreReason, Scratch, Selector},
    },
};

/// A host on the listener's link.
const STRANGER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 77);

fn from(addr: Ipv4Addr) -> SocketAddrV4 {
    SocketAddrV4::new(addr, 68)
}

/// A broadcast of a client that uses no source address.
fn broadcast() -> SocketAddrV4 {
    from(Ipv4Addr::UNSPECIFIED)
}

/// A request of client `k` that was not relayed, with `ciaddr`.
fn direct(kind: MessageType, k: u8, ciaddr: &str) -> Ask {
    let mut ask = Ask::new(kind, k);
    ask.giaddr = None;
    ask.ciaddr = Some(ip(ciaddr));
    ask
}

fn renew(k: u8, ciaddr: &str) -> Vec<u8> {
    direct(MessageType::Request, k, ciaddr).bytes()
}

fn release(k: u8, ciaddr: &str) -> Vec<u8> {
    let mut ask = direct(MessageType::Release, k, ciaddr);
    ask.server_id = Some(SERVER);
    ask.bytes()
}

fn reply(answer: &Answer, scratch: &Scratch) -> (MessageType, Ipv4Addr, Destination) {
    let (Action::Reply { len, dest, .. } | Action::CommitThenReply { len, dest, .. }) =
        answer.action
    else {
        panic!("a reply, got {:?}", answer.action);
    };
    let message = Message::parse(&scratch.reply[..len]).expect("parse");
    (
        message.message_type().expect("53").expect("a type"),
        message.yiaddr(),
        dest,
    )
}

/// The refusals of the client-address kind: the sender, the address it named, the
/// network, how often.
fn wrong_network(world: &World) -> Vec<(IpAddr, IpAddr, Option<ipnet::IpNet>, u64)> {
    world
        .guard
        .relay_report(Some(&world.image))
        .wrong_network
        .iter()
        .map(|refused| (refused.source, refused.relay, refused.link, refused.count))
        .collect()
}

fn net(text: &str) -> ipnet::IpNet {
    text.parse().expect("a prefix")
}

#[test]
fn a_request_naming_an_address_of_another_network_than_its_source_s_is_dropped_and_reported() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let selecting = {
        let mut ask = direct(MessageType::Request, 0x32, "192.0.2.141");
        ask.server_id = Some(SERVER);
        ask.requested = Some(ip("192.0.2.141"));
        ask.bytes()
    };
    let cases: [(&str, Vec<u8>, Ipv4Addr); 6] = [
        (
            "renewing a free address",
            renew(0x32, "192.0.2.140"),
            STRANGER,
        ),
        (
            "renewing the address of another client",
            renew(0x32, "192.0.2.110"),
            STRANGER,
        ),
        ("selecting with a ciaddr", selecting, STRANGER),
        (
            "releasing the lease of client :10 as client :10",
            release(0x10, "192.0.2.110"),
            STRANGER,
        ),
        (
            "an inform",
            direct(MessageType::Inform, 0x32, "192.0.2.140").bytes(),
            STRANGER,
        ),
        (
            "renewing from no network of any scope",
            renew(0x32, "192.0.2.140"),
            ip("100.64.0.9"),
        ),
    ];
    for (name, bytes, source) in &cases {
        let answer = world.run_from(bytes, from(*source), t0(), &mut scratch);
        assert_eq!(
            answer.action,
            Action::Drop(DropReason::WrongNetwork),
            "{name}"
        );
        assert_eq!(answer.selector, Some(Selector::ClientAddress), "{name}");
    }
    let lease = world
        .leases
        .get(world.vrf, ip("192.0.2.110"))
        .expect("the lease of :10");
    assert_eq!(
        lease.state,
        BindingState::Active,
        "the release changed nothing"
    );
    // One entry per sender in the relay log, with the address and the network it named last.
    assert_eq!(
        wrong_network(&world),
        vec![
            (
                IpAddr::V4(STRANGER),
                IpAddr::V4(ip("192.0.2.140")),
                Some(net("192.0.2.0/24")),
                5
            ),
            (
                IpAddr::V4(ip("100.64.0.9")),
                IpAddr::V4(ip("192.0.2.140")),
                Some(net("192.0.2.0/24")),
                1
            ),
        ]
    );
    let report = world.guard.relay_report(Some(&world.image));
    assert!(
        report.refused.is_empty(),
        "no relay was refused: {report:?}"
    );
    let row = report
        .warnings()
        .into_iter()
        .find(|row| row.code == WRONG_NETWORK)
        .expect("the health row");
    assert_eq!(row.params["senders"], "198.51.100.77, 100.64.0.9");
    assert_eq!(row.params["refused"], "6");
    assert!(
        row.detail
            .contains("198.51.100.77 (address 192.0.2.140 of 192.0.2.0/24, 5 time(s))"),
        "{row:?}"
    );
}

#[test]
fn a_renewal_routed_to_the_server_acts_only_on_a_lease_the_client_holds() {
    let world = World::new();
    let mut scratch = Scratch::new();
    // From the address it names, but the client holds no lease there: no lease is made and
    // no NAK is broadcast on the listener's link, which the client is not on.
    for (name, bytes, source) in [
        ("a free address", renew(0x32, "192.0.2.140"), "192.0.2.140"),
        (
            "another client's address",
            renew(0x32, "192.0.2.110"),
            "192.0.2.110",
        ),
        (
            "an address of a scope that is not authoritative",
            renew(0x33, "203.0.113.130"),
            "203.0.113.130",
        ),
    ] {
        let answer = world.run_from(&bytes, from(ip(source)), t0(), &mut scratch);
        assert_eq!(
            answer.action,
            Action::Ignore(IgnoreReason::NoRecord),
            "{name}"
        );
    }
    let selecting = {
        let mut ask = direct(MessageType::Request, 0x32, "192.0.2.141");
        ask.server_id = Some(SERVER);
        ask.requested = Some(ip("192.0.2.141"));
        ask.bytes()
    };
    let answer = world.run_from(&selecting, from(ip("192.0.2.141")), t0(), &mut scratch);
    assert_eq!(answer.action, Action::Ignore(IgnoreReason::NoRecord));
    assert!(
        wrong_network(&world).is_empty(),
        "not refusals of the source"
    );
    // The holder renews.
    let answer = world.run_from(
        &renew(0x10, "192.0.2.110"),
        from(ip("192.0.2.110")),
        t0(),
        &mut scratch,
    );
    let (kind, yiaddr, dest) = reply(&answer, &scratch);
    assert_eq!((kind, yiaddr), (MessageType::Ack, ip("192.0.2.110")));
    assert_eq!(dest, Destination::Client(from(ip("192.0.2.110"))));
    assert_eq!(scratch.change.kind, LeaseEventKind::Renewed);
}

#[test]
fn a_release_or_decline_on_the_listener_s_link_cannot_name_a_lease_of_another_network() {
    let world = World::new();
    let mut scratch = Scratch::new();
    // A broadcast from no address is a client of the listener's link, whatever its ciaddr.
    let answer = world.run_from(
        &release(0x10, "192.0.2.110"),
        broadcast(),
        t0(),
        &mut scratch,
    );
    assert_eq!(answer.action, Action::Ignore(IgnoreReason::NotHolder));
    assert_eq!(answer.selector, Some(Selector::Interface));
    for ciaddr in [None, Some(ip("192.0.2.110"))] {
        let mut decline = Ask::new(MessageType::Decline, 0x10);
        decline.giaddr = None;
        decline.ciaddr = ciaddr;
        decline.requested = Some(ip("192.0.2.110"));
        decline.server_id = Some(SERVER);
        // From the listener's link: its scope does not hold the address.
        for source in [broadcast(), from(STRANGER)] {
            let answer = world.run_from(&decline.bytes(), source, t0(), &mut scratch);
            assert_eq!(
                answer.action,
                Action::Ignore(IgnoreReason::NotHolder),
                "{ciaddr:?} from {source}"
            );
        }
        // From the address itself, routed to the listener: not from the listener's link.
        let answer = world.run_from(
            &decline.bytes(),
            from(ip("192.0.2.110")),
            t0(),
            &mut scratch,
        );
        assert_eq!(
            answer.action,
            Action::Drop(DropReason::WrongNetwork),
            "{ciaddr:?}"
        );
    }
    let lease = world
        .leases
        .get(world.vrf, ip("192.0.2.110"))
        .expect("the lease");
    assert_eq!(lease.state, BindingState::Active);
}

#[test]
fn a_client_behind_a_relay_renews_by_unicast_and_rebinds_through_the_relay() {
    let world = World::new();
    let mut scratch = Scratch::new();
    // RENEWING: unicast from its address, straight to the server.
    let answer = world.run_from(
        &renew(0x10, "192.0.2.110"),
        from(ip("192.0.2.110")),
        t0(),
        &mut scratch,
    );
    assert_eq!(reply(&answer, &scratch).0, MessageType::Ack);
    // The relay forwards the client's REQUEST (a unicast to the relay's address under
    // RFC 5107, or the REBINDING broadcast): the relay's link selects, ACK to the relay.
    let mut rebind = Ask::new(MessageType::Request, 0x10);
    rebind.ciaddr = Some(ip("192.0.2.110"));
    let answer = world.run(&rebind.bytes(), t0(), &mut scratch);
    let (kind, yiaddr, dest) = reply(&answer, &scratch);
    assert_eq!((kind, yiaddr), (MessageType::Ack, ip("192.0.2.110")));
    assert_eq!(dest, Destination::Relay(SocketAddrV4::new(RELAY, 67)));
    assert_eq!(scratch.change.kind, LeaseEventKind::Rebound);
    // A client whose lease the server lost renews in vain and then rebinds through its
    // relay, where the lease is taken back.
    let answer = world.run_from(
        &renew(0x32, "192.0.2.140"),
        from(ip("192.0.2.140")),
        t0(),
        &mut scratch,
    );
    assert_eq!(answer.action, Action::Ignore(IgnoreReason::NoRecord));
    let mut rebind = Ask::new(MessageType::Request, 0x32);
    rebind.ciaddr = Some(ip("192.0.2.140"));
    let answer = world.run(&rebind.bytes(), t0(), &mut scratch);
    let (kind, yiaddr, _) = reply(&answer, &scratch);
    assert_eq!((kind, yiaddr), (MessageType::Ack, ip("192.0.2.140")));
    assert_eq!(scratch.change.kind, LeaseEventKind::Granted);
}

#[test]
fn a_client_on_the_listener_s_link_renews_and_takes_a_lost_lease_back() {
    let mut world = World::new();
    world.lease(
        0x60,
        true,
        ip("198.51.100.150"),
        BindingState::Active,
        3_600,
    );
    let mut scratch = Scratch::new();
    for (k, addr, event) in [
        (0x60, "198.51.100.150", LeaseEventKind::Renewed),
        (0x61, "198.51.100.160", LeaseEventKind::Granted),
    ] {
        let answer = world.run_from(&renew(k, addr), from(ip(addr)), t0(), &mut scratch);
        let (kind, yiaddr, dest) = reply(&answer, &scratch);
        assert_eq!((kind, yiaddr), (MessageType::Ack, ip(addr)), "{addr}");
        assert_eq!(dest, Destination::Client(from(ip(addr))));
        assert_eq!(scratch.change.kind, event, "{addr}");
    }
    // Another client's address on the link: NAK, by broadcast on the link.
    let answer = world.run_from(
        &renew(0x62, "198.51.100.150"),
        from(ip("198.51.100.150")),
        t0(),
        &mut scratch,
    );
    let (kind, _, dest) = reply(&answer, &scratch);
    assert_eq!((kind, dest), (MessageType::Nak, Destination::Broadcast(68)));
}

#[test]
fn a_moved_client_gets_a_nak_from_the_link_it_is_on() {
    let world = World::new();
    let mut scratch = Scratch::new();
    // INIT-REBOOT with its old address on the listener's link.
    let mut reboot = Ask::new(MessageType::Request, 0x10);
    reboot.giaddr = None;
    reboot.requested = Some(ip("192.0.2.110"));
    let answer = world.run_from(&reboot.bytes(), broadcast(), t0(), &mut scratch);
    let (kind, _, dest) = reply(&answer, &scratch);
    assert_eq!((kind, dest), (MessageType::Nak, Destination::Broadcast(68)));
    // REBINDING by broadcast on the listener's link from no address.
    let answer = world.run_from(&renew(0x10, "192.0.2.110"), broadcast(), t0(), &mut scratch);
    assert_eq!(answer.selector, Some(Selector::Interface));
    let (kind, _, dest) = reply(&answer, &scratch);
    assert_eq!((kind, dest), (MessageType::Nak, Destination::Broadcast(68)));
    // REBINDING through the relay of the new link: NAK to that relay.
    let mut rebind = Ask::new(MessageType::Request, 0x10);
    rebind.giaddr = Some(ip("198.51.100.1"));
    rebind.ciaddr = Some(ip("192.0.2.110"));
    let answer = world.run_from(
        &rebind.bytes(),
        SocketAddrV4::new(ip("198.51.100.1"), 67),
        t0(),
        &mut scratch,
    );
    let (kind, _, dest) = reply(&answer, &scratch);
    assert_eq!(kind, MessageType::Nak);
    assert_eq!(
        dest,
        Destination::Relay(SocketAddrV4::new(ip("198.51.100.1"), 67))
    );
    // Nothing of that was a refusal of the source.
    assert_eq!(wrong_network(&world), Vec::new());
    // A REBINDING broadcast from its old address on the listener's link looks like a
    // renewal routed to the server, since the listener does not see the broadcast address:
    // it is acknowledged to the old address, where the client does not hear it, and the
    // client keeps the lease until it reboots (INIT-REBOOT above) or the lease ends
    // (`docs/dhcp.md` section 9.1).
    let answer = world.run_from(
        &renew(0x10, "192.0.2.110"),
        from(ip("192.0.2.110")),
        t0(),
        &mut scratch,
    );
    let (kind, _, dest) = reply(&answer, &scratch);
    assert_eq!(
        (kind, dest),
        (
            MessageType::Ack,
            Destination::Client(from(ip("192.0.2.110")))
        )
    );
}

#[test]
fn a_host_with_several_addresses_renews_from_another_address_of_the_same_network() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let answer = world.run_from(
        &renew(0x10, "192.0.2.110"),
        from(ip("192.0.2.7")),
        t0(),
        &mut scratch,
    );
    let (kind, yiaddr, dest) = reply(&answer, &scratch);
    assert_eq!((kind, yiaddr), (MessageType::Ack, ip("192.0.2.110")));
    assert_eq!(dest, Destination::Client(from(ip("192.0.2.7"))));
    // From its address on another network the renewal is refused; it rebinds through the
    // relay of the lease's link instead.
    let answer = world.run_from(
        &renew(0x10, "192.0.2.110"),
        from(ip("203.0.113.7")),
        t0(),
        &mut scratch,
    );
    assert_eq!(answer.action, Action::Drop(DropReason::WrongNetwork));
    let mut rebind = Ask::new(MessageType::Request, 0x10);
    rebind.ciaddr = Some(ip("192.0.2.110"));
    let answer = world.run(&rebind.bytes(), t0(), &mut scratch);
    assert_eq!(reply(&answer, &scratch).0, MessageType::Ack);
}

#[test]
fn a_request_without_ciaddr_from_an_address_of_another_network_is_dropped_and_reported() {
    let mut world = World::new();
    world.lease(
        0x60,
        true,
        ip("198.51.100.150"),
        BindingState::Active,
        3_600,
    );
    let mut scratch = Scratch::new();
    let routed = from(ip("192.0.2.50"));
    let with = |kind: MessageType, k: u8, requested: Option<&str>, server: bool| {
        let mut ask = Ask::new(kind, k);
        ask.giaddr = None;
        ask.requested = requested.map(ip);
        ask.server_id = server.then_some(SERVER);
        ask.bytes()
    };
    // A DISCOVER, a SELECTING REQUEST, an INIT-REBOOT of :60's address with :60's identity
    // and a DECLINE of it, routed to the listener from scope A: a client without an address
    // sends from none (RFC 2131 section 4.1), so none of these came from the listener's link.
    for (name, bytes) in [
        ("discover", with(MessageType::Discover, 0x33, None, false)),
        (
            "selecting",
            with(MessageType::Request, 0x33, Some("198.51.100.160"), true),
        ),
        (
            "init-reboot",
            with(MessageType::Request, 0x60, Some("198.51.100.150"), false),
        ),
        (
            "decline",
            with(MessageType::Decline, 0x60, Some("198.51.100.150"), true),
        ),
    ] {
        let answer = world.run_from(&bytes, routed, t0(), &mut scratch);
        assert_eq!(
            answer.action,
            Action::Drop(DropReason::WrongNetwork),
            "{name}"
        );
        assert_eq!(answer.selector, Some(Selector::Interface), "{name}");
    }
    let lease = world
        .leases
        .get(world.vrf, ip("198.51.100.150"))
        .expect("the lease");
    assert_eq!(
        lease.state,
        BindingState::Active,
        "the decline changed nothing"
    );
    assert_eq!(
        wrong_network(&world),
        vec![(
            IpAddr::V4(ip("192.0.2.50")),
            IpAddr::V4(ip("198.51.100.150")),
            Some(net("198.51.100.0/24")),
            4
        )]
    );
    // The same DISCOVER from no address, or from an address of the listener's link, is
    // served.
    for source in [broadcast(), from(STRANGER)] {
        let answer = world.run_from(
            &with(MessageType::Discover, 0x33, None, false),
            source,
            t0(),
            &mut scratch,
        );
        assert_eq!(reply(&answer, &scratch).0, MessageType::Offer, "{source}");
    }
}

#[test]
fn a_nested_scope_is_another_network() {
    // Scope D 198.51.100.192/26 lies inside scope B, the listener's: a host of D is not on
    // B's network, though B's prefix holds its address.
    let world = World::nested();
    let mut scratch = Scratch::new();
    let answer = world.run_from(
        &renew(0x34, "198.51.100.160"),
        from(ip("198.51.100.209")),
        t0(),
        &mut scratch,
    );
    assert_eq!(answer.action, Action::Drop(DropReason::WrongNetwork));
    // A renewal from D of an address of D is routed from another network than the
    // listener's: without a lease of the client, nothing.
    let answer = world.run_from(
        &renew(0x34, "198.51.100.210"),
        from(ip("198.51.100.210")),
        t0(),
        &mut scratch,
    );
    assert_eq!(answer.action, Action::Ignore(IgnoreReason::NoRecord));
}
