//! The engine against RFC 2131 (WP7.3): table-driven tests per message type and client
//! state, the NAK rules, the server identifier check, the broadcast flag and the reply
//! destinations, the store-refusal answers of P3-Q14, the filters and restricted scopes,
//! the scope selection (RFC 3527, RFC 3011, RFC 5107) and the option assembly.

mod engine_world;

use std::net::{Ipv4Addr, SocketAddrV4};

use engine_world::{Ask, RELAY, SERVER, World, at, identity_with_id, ip, mac, t0};
use tenko_core::{
    dhcp::{BindingState, Filter, FilterId, FilterKind, LeaseEventKind, MacPattern},
    ipam::Stamp,
    principal::{Principal, SystemComponent},
};
use tenko_dhcp::{
    allocator::OfferHold,
    image::{ImageBuilder, ScopeImage},
    lease::LeaseTable,
    v4::{
        ClientFqdn, FLAG_BROADCAST, Message, MessageType,
        engine::{Action, Answer, Destination, DropReason, IgnoreReason, Scratch, Selector},
    },
};

/// What a row expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// A reply of this type, sent now.
    Reply(MessageType),
    /// A reply of this type after the commit.
    AfterCommit(MessageType),
    /// A commit without a reply.
    Commit,
    /// Dropped.
    Drop(DropReason),
    /// Ignored.
    Ignore(IgnoreReason),
}

fn expect_of(answer: &Answer) -> Expect {
    match answer.action {
        Action::Reply { kind, .. } => Expect::Reply(kind),
        Action::CommitThenReply { kind, .. } => Expect::AfterCommit(kind),
        Action::Commit => Expect::Commit,
        Action::Drop(reason) => Expect::Drop(reason),
        Action::Ignore(reason) => Expect::Ignore(reason),
    }
}

fn reply_of<'a>(answer: &Answer, scratch: &'a Scratch) -> (Message<'a>, Destination) {
    match answer.action {
        Action::Reply { len, dest, .. } | Action::CommitThenReply { len, dest, .. } => (
            Message::parse(&scratch.reply[..len]).expect("a reply parses"),
            dest,
        ),
        other => panic!("no reply: {other:?}"),
    }
}

/// The option codes of a reply, in order, instances included.
fn codes(message: &Message<'_>) -> Vec<u8> {
    message
        .options()
        .map(|option| option.expect("well formed").code)
        .collect()
}

fn relay_dest() -> Destination {
    Destination::Relay(SocketAddrV4::new(RELAY, 67))
}

struct Row {
    name: &'static str,
    ask: Ask,
    expect: Expect,
    yiaddr: Option<Ipv4Addr>,
    dest: Option<Destination>,
}

fn row(name: &'static str, ask: Ask, expect: Expect) -> Row {
    Row {
        name,
        ask,
        expect,
        yiaddr: None,
        dest: None,
    }
}

impl Row {
    fn yiaddr(mut self, addr: &str) -> Self {
        self.yiaddr = Some(ip(addr));
        self
    }

    fn dest(mut self, dest: Destination) -> Self {
        self.dest = Some(dest);
        self
    }
}

fn ask(kind: MessageType, client: u8) -> Ask {
    Ask::new(kind, client)
}

fn with(mut ask: Ask, edit: impl FnOnce(&mut Ask)) -> Ask {
    edit(&mut ask);
    ask
}

#[allow(
    clippy::too_many_lines,
    reason = "the table of RFC 2131 states, one row per case"
)]
fn rows() -> Vec<Row> {
    use MessageType::{Ack, Decline, Discover, Inform, Nak, Offer, Release, Request};
    vec![
        // DISCOVER (RFC 2131 section 4.3.1).
        row(
            "discover of a new client",
            ask(Discover, 0x30),
            Expect::Reply(Offer),
        )
        .dest(relay_dest()),
        row(
            "discover asking for a free address gets it",
            with(ask(Discover, 0x30), |a| {
                a.requested = Some(ip("192.0.2.150"));
            }),
            Expect::Reply(Offer),
        )
        .yiaddr("192.0.2.150"),
        row(
            "discover of a client with a lease gets its lease",
            ask(Discover, 0x10),
            Expect::Reply(Offer),
        )
        .yiaddr("192.0.2.110"),
        row(
            "discover asking for an excluded address gets a pool address",
            with(ask(Discover, 0x30), |a| {
                a.requested = Some(ip("192.0.2.101"));
            }),
            Expect::Reply(Offer),
        ),
        row(
            "discover of a reserved client gets the reservation",
            with(ask(Discover, 0x20), |a| a.with_id = false),
            Expect::Reply(Offer),
        )
        .yiaddr("192.0.2.20"),
        row(
            "discover of a denied MAC is dropped",
            ask(Discover, 0x66),
            Expect::Drop(DropReason::Filtered),
        ),
        row(
            "discover from a link without a scope is dropped",
            with(ask(Discover, 0x30), |a| a.giaddr = Some(ip("233.252.0.1"))),
            Expect::Drop(DropReason::NoScope),
        ),
        row(
            "discover with the broadcast flag on the listener's link is broadcast",
            with(ask(Discover, 0x30), |a| {
                a.giaddr = None;
                a.broadcast = true;
            }),
            Expect::Reply(Offer),
        )
        .dest(Destination::Broadcast(68)),
        // REQUEST in SELECTING.
        row(
            "selecting a free address is acknowledged after the commit",
            with(ask(Request, 0x30), |a| {
                a.requested = Some(ip("192.0.2.150"));
                a.server_id = Some(SERVER);
            }),
            Expect::AfterCommit(Ack),
        )
        .yiaddr("192.0.2.150")
        .dest(relay_dest()),
        row(
            "selecting another server is ignored",
            with(ask(Request, 0x30), |a| {
                a.requested = Some(ip("192.0.2.150"));
                a.server_id = Some(ip("198.51.100.99"));
            }),
            Expect::Ignore(IgnoreReason::OtherServer),
        ),
        row(
            "selecting another client's address is refused",
            with(ask(Request, 0x30), |a| {
                a.requested = Some(ip("192.0.2.110"));
                a.server_id = Some(SERVER);
            }),
            Expect::Reply(Nak),
        )
        .dest(relay_dest()),
        row(
            "selecting a reserved address of another client is refused",
            with(ask(Request, 0x30), |a| {
                a.requested = Some(ip("192.0.2.20"));
                a.server_id = Some(SERVER);
            }),
            Expect::Reply(Nak),
        ),
        row(
            "a request with option 54 but no option 50 is ignored",
            with(ask(Request, 0x30), |a| a.server_id = Some(SERVER)),
            Expect::Ignore(IgnoreReason::Incomplete),
        ),
        // REQUEST in INIT-REBOOT.
        row(
            "init-reboot with the client's address is acknowledged",
            with(ask(Request, 0x10), |a| {
                a.requested = Some(ip("192.0.2.110"));
            }),
            Expect::AfterCommit(Ack),
        )
        .yiaddr("192.0.2.110"),
        row(
            "init-reboot with an address of another network is refused",
            with(ask(Request, 0x10), |a| {
                a.requested = Some(ip("203.0.113.77"));
            }),
            Expect::Reply(Nak),
        ),
        row(
            "init-reboot with another address of the network is refused",
            with(ask(Request, 0x10), |a| {
                a.requested = Some(ip("192.0.2.120"));
            }),
            Expect::Reply(Nak),
        ),
        row(
            "init-reboot of a client without a record is ignored",
            with(ask(Request, 0x31), |a| {
                a.requested = Some(ip("192.0.2.120"));
            }),
            Expect::Ignore(IgnoreReason::NoRecord),
        ),
        // REQUEST in RENEWING and REBINDING.
        row(
            "renewing is acknowledged by unicast to ciaddr",
            with(ask(Request, 0x10), |a| {
                a.giaddr = None;
                a.ciaddr = Some(ip("192.0.2.110"));
            }),
            Expect::AfterCommit(Ack),
        )
        .yiaddr("192.0.2.110")
        .dest(Destination::Client(SocketAddrV4::new(
            ip("192.0.2.110"),
            68,
        ))),
        row(
            "rebinding through a relay is acknowledged to the relay",
            with(ask(Request, 0x10), |a| a.ciaddr = Some(ip("192.0.2.110"))),
            Expect::AfterCommit(Ack),
        )
        .dest(relay_dest()),
        row(
            "renewing another client's address is refused by broadcast",
            with(ask(Request, 0x32), |a| {
                a.giaddr = None;
                a.ciaddr = Some(ip("192.0.2.110"));
            }),
            Expect::Reply(Nak),
        )
        .dest(Destination::Broadcast(68)),
        row(
            "renewing a free address without a record recreates the lease",
            with(ask(Request, 0x32), |a| {
                a.giaddr = None;
                a.ciaddr = Some(ip("192.0.2.140"));
            }),
            Expect::AfterCommit(Ack),
        )
        .yiaddr("192.0.2.140"),
        row(
            "renewing on a scope that is not authoritative is not refused",
            with(ask(Request, 0x33), |a| {
                a.giaddr = None;
                a.ciaddr = Some(ip("203.0.113.120"));
            }),
            Expect::Ignore(IgnoreReason::NotAuthoritative),
        ),
        // DECLINE and RELEASE.
        row(
            "a decline of the client's address is committed",
            with(ask(Decline, 0x10), |a| {
                a.requested = Some(ip("192.0.2.110"));
                a.server_id = Some(SERVER);
                a.prl.clear();
            }),
            Expect::Commit,
        ),
        row(
            "a decline of another client's address is ignored",
            with(ask(Decline, 0x30), |a| {
                a.requested = Some(ip("192.0.2.110"));
                a.server_id = Some(SERVER);
            }),
            Expect::Ignore(IgnoreReason::NotHolder),
        ),
        row(
            "a decline for another server is ignored",
            with(ask(Decline, 0x10), |a| {
                a.requested = Some(ip("192.0.2.110"));
                a.server_id = Some(ip("198.51.100.99"));
            }),
            Expect::Ignore(IgnoreReason::OtherServer),
        ),
        row(
            "a release of the client's address is committed",
            with(ask(Release, 0x10), |a| {
                a.giaddr = None;
                a.ciaddr = Some(ip("192.0.2.110"));
                a.server_id = Some(SERVER);
            }),
            Expect::Commit,
        ),
        row(
            "a release of another client's address is ignored",
            with(ask(Release, 0x30), |a| {
                a.giaddr = None;
                a.ciaddr = Some(ip("192.0.2.110"));
                a.server_id = Some(SERVER);
            }),
            Expect::Ignore(IgnoreReason::NotHolder),
        ),
        // INFORM (RFC 2131 section 4.3.5).
        row(
            "inform is acknowledged to ciaddr without an address",
            with(ask(Inform, 0x22), |a| {
                a.giaddr = None;
                a.ciaddr = Some(ip("198.51.100.77"));
            }),
            Expect::Reply(Ack),
        )
        .yiaddr("0.0.0.0")
        .dest(Destination::Client(SocketAddrV4::new(
            ip("198.51.100.77"),
            68,
        ))),
        row(
            "inform without ciaddr is ignored",
            with(ask(Inform, 0x22), |a| a.giaddr = None),
            Expect::Ignore(IgnoreReason::Incomplete),
        ),
        // Types a server does not answer.
        row(
            "an offer from another server is ignored",
            ask(Offer, 0x30),
            Expect::Ignore(IgnoreReason::OtherType),
        ),
    ]
}

#[test]
fn every_state_of_rfc_2131_is_answered_as_the_rfc_says() {
    let mut failures = Vec::new();
    for row in rows() {
        let world = World::new();
        let mut scratch = Scratch::new();
        let answer = world.run(&row.ask.bytes(), t0(), &mut scratch);
        let got = expect_of(&answer);
        if got != row.expect {
            failures.push(format!(
                "{}: expected {:?}, got {got:?}",
                row.name, row.expect
            ));
            continue;
        }
        if matches!(row.expect, Expect::Reply(_) | Expect::AfterCommit(_)) {
            let (reply, dest) = reply_of(&answer, &scratch);
            if let Some(want) = row.yiaddr
                && reply.yiaddr() != want
            {
                failures.push(format!("{}: yiaddr {}", row.name, reply.yiaddr()));
            }
            if let Some(want) = row.dest
                && dest != want
            {
                failures.push(format!("{}: destination {dest:?}", row.name));
            }
            if reply.xid() != 0x5e00_5300 | u32::from(row.ask.client) {
                failures.push(format!("{}: xid", row.name));
            }
            if reply.server_identifier().expect("54") != Some(SERVER) {
                failures.push(format!("{}: server identifier", row.name));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn an_offer_carries_the_lease_times_and_the_client_identifier_and_is_held() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let answer = world.run(
        &ask(MessageType::Discover, 0x30).bytes(),
        t0(),
        &mut scratch,
    );
    let (offer, _) = reply_of(&answer, &scratch);
    let addr = offer.yiaddr();
    assert!(world.scope_of(addr).is_dynamic(addr));
    assert_eq!(offer.lease_time().expect("51"), Some(86_400));
    assert_eq!(offer.renewal_time().expect("58"), Some(43_200));
    assert_eq!(offer.rebinding_time().expect("59"), Some(75_600));
    assert_eq!(offer.ciaddr(), Ipv4Addr::UNSPECIFIED);
    let id = offer.client_identifier().expect("61").expect("echoed");
    assert_eq!(id.as_bytes(), &identity_with_id(0x30)[1..]);
    assert_eq!(
        codes(&offer),
        [53, 54, 51, 58, 59, 1, 3, 6, 15, 61],
        "the server's options, the mask, the asked ones, then option 61"
    );
    // The offer holds the address for this client and no other.
    let scope = world.scope_of(addr).prefix;
    assert!(world.offers.held_for_other(scope, addr, b"other", at(5)));
    assert!(
        !world
            .offers
            .held_for_other(scope, addr, &identity_with_id(0x30), at(5))
    );
    assert!(!world.offers.held_for_other(scope, addr, b"other", at(11)));
    // A second client asking for it gets another address; the first client again gets it.
    let second = with(ask(MessageType::Discover, 0x31), |a| {
        a.requested = Some(addr);
    });
    let answer = world.run(&second.bytes(), at(1), &mut scratch);
    assert_ne!(reply_of(&answer, &scratch).0.yiaddr(), addr);
    let answer = world.run(
        &ask(MessageType::Discover, 0x30).bytes(),
        at(2),
        &mut scratch,
    );
    assert_eq!(reply_of(&answer, &scratch).0.yiaddr(), addr);
}

#[test]
fn an_ack_commits_the_lease_and_the_renewal_moves_its_end() {
    let mut world = World::new();
    let mut scratch = Scratch::new();
    let request = with(ask(MessageType::Request, 0x30), |a| {
        a.requested = Some(ip("192.0.2.150"));
        a.server_id = Some(SERVER);
        a.lease_secs = Some(7_200);
    });
    let answer = world.run(&request.bytes(), t0(), &mut scratch);
    assert!(matches!(answer.action, Action::CommitThenReply { .. }));
    let change = scratch.change.clone();
    assert_eq!(change.kind, LeaseEventKind::Granted);
    assert_eq!(change.state, BindingState::Active);
    assert_eq!(change.addr, ip("192.0.2.150"));
    assert_eq!(change.ends, at(7_200));
    assert_eq!(change.chaddr.as_slice(), mac(0x30));
    assert!(change.relay.is_none(), "no option 82 in the request");
    let fingerprint = change.fingerprint.expect("a fingerprint");
    assert_eq!(fingerprint.parameters.as_slice(), [1, 3, 6]);
    assert_eq!(
        reply_of(&answer, &scratch).0.lease_time().expect("51"),
        Some(7_200)
    );
    world.commit(&change);
    // A short request is raised to the minimum; the renewal is a renewal.
    let renew = with(ask(MessageType::Request, 0x30), |a| {
        a.giaddr = None;
        a.ciaddr = Some(ip("192.0.2.150"));
        a.lease_secs = Some(60);
    });
    let answer = world.run(&renew.bytes(), at(3_000), &mut scratch);
    assert!(matches!(answer.action, Action::CommitThenReply { .. }));
    assert_eq!(scratch.change.kind, LeaseEventKind::Renewed);
    assert_eq!(scratch.change.ends, at(3_000 + 3_600));
    assert_eq!(answer.selector, Some(Selector::ClientAddress));
}

#[test]
fn a_decline_abandons_the_address_for_the_hold_time_for_every_client() {
    let mut world = World::new();
    let mut scratch = Scratch::new();
    let decline = with(ask(MessageType::Decline, 0x10), |a| {
        a.requested = Some(ip("192.0.2.110"));
        a.server_id = Some(SERVER);
    });
    let answer = world.run(&decline.bytes(), t0(), &mut scratch);
    assert_eq!(answer.action, Action::Commit);
    let change = scratch.change.clone();
    assert_eq!(change.kind, LeaseEventKind::Declined);
    assert_eq!(change.state, BindingState::Abandoned);
    assert_eq!(change.ends, at(86_400));
    world.commit(&change);
    for (client, now) in [(0x10, at(60)), (0x34, at(60)), (0x34, at(86_000))] {
        let again = with(ask(MessageType::Discover, client), |a| {
            a.requested = Some(ip("192.0.2.110"));
        });
        let answer = world.run(&again.bytes(), now, &mut scratch);
        assert_ne!(reply_of(&answer, &scratch).0.yiaddr(), ip("192.0.2.110"));
    }
    // After the hold the address is free again.
    let later = with(ask(MessageType::Discover, 0x34), |a| {
        a.requested = Some(ip("192.0.2.110"));
    });
    let answer = world.run(&later.bytes(), at(86_401), &mut scratch);
    assert_eq!(reply_of(&answer, &scratch).0.yiaddr(), ip("192.0.2.110"));
}

#[test]
fn a_release_frees_the_address() {
    let mut world = World::new();
    let mut scratch = Scratch::new();
    let release = with(ask(MessageType::Release, 0x10), |a| {
        a.giaddr = None;
        a.ciaddr = Some(ip("192.0.2.110"));
    });
    assert_eq!(
        world.run(&release.bytes(), at(10), &mut scratch).action,
        Action::Commit
    );
    let change = scratch.change.clone();
    assert_eq!(change.state, BindingState::Released);
    assert_eq!(change.ends, at(10));
    world.commit(&change);
    let other = with(ask(MessageType::Discover, 0x35), |a| {
        a.requested = Some(ip("192.0.2.110"));
    });
    let answer = world.run(&other.bytes(), at(11), &mut scratch);
    assert_eq!(reply_of(&answer, &scratch).0.yiaddr(), ip("192.0.2.110"));
}

#[test]
fn a_nak_carries_only_what_rfc_2131_allows_and_sets_the_broadcast_bit_for_a_relay() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let relay = vec![1, 2, 0, 7, 2, 2, 0, 9];
    let request = with(ask(MessageType::Request, 0x30), |a| {
        a.requested = Some(ip("192.0.2.110"));
        a.server_id = Some(SERVER);
        a.relay = Some(relay.clone());
    });
    let answer = world.run(&request.bytes(), t0(), &mut scratch);
    let (nak, dest) = reply_of(&answer, &scratch);
    assert_eq!(dest, relay_dest());
    assert_eq!(nak.message_type().expect("53"), Some(MessageType::Nak));
    assert_eq!(nak.flags() & FLAG_BROADCAST, FLAG_BROADCAST);
    assert_eq!(nak.yiaddr(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(nak.ciaddr(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(codes(&nak), [53, 54, 56, 61, 82]);
    assert_eq!(
        nak.relay_agent_info()
            .expect("82")
            .expect("echoed")
            .as_bytes(),
        relay
    );
}

#[test]
fn the_reply_follows_the_parameter_request_list_and_splits_long_options() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let mut discover = with(ask(MessageType::Discover, 0x30), |a| {
        a.prl = vec![15, 42, 121, 6, 3, 1, 26, 119];
    });
    discover.with_id = false;
    let mut bytes = discover.bytes();
    // Option 57: 1500, inserted after option 53 so the reply has room for the routes.
    bytes.splice(243..243, [57, 2, 0x05, 0xdc]);
    let answer = world.run(&bytes, t0(), &mut scratch);
    let (offer, _) = reply_of(&answer, &scratch);
    assert_eq!(
        codes(&offer),
        [53, 54, 51, 58, 59, 1, 15, 42, 121, 121, 6, 3, 26, 119]
    );
    let mut buf = [0u8; 1024];
    let routes = offer
        .option_data(121, &mut buf)
        .expect("121")
        .expect("routes");
    assert_eq!(routes, engine_world::routes().as_slice());
    // Without option 57 the reply stays within 548 octets: the routes are left out whole.
    let mut small = discover.clone();
    small.prl = vec![121, 3];
    let answer = world.run(&small.bytes(), t0(), &mut scratch);
    let (offer, _) = reply_of(&answer, &scratch);
    assert!(offer.len() <= 548);
    assert!(!codes(&offer).contains(&121));
    assert!(codes(&offer).contains(&3));
}

#[test]
fn the_reservation_options_win_over_the_scope_options() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let discover = with(ask(MessageType::Discover, 0x20), |a| {
        a.with_id = false;
        a.prl = vec![1, 3, 15, 66, 67];
    });
    let answer = world.run(&discover.bytes(), t0(), &mut scratch);
    let (offer, _) = reply_of(&answer, &scratch);
    assert_eq!(offer.yiaddr(), ip("192.0.2.20"));
    assert_eq!(
        offer.domain_name().expect("15"),
        Some(&b"lab.example.test"[..])
    );
    assert_eq!(
        offer.tftp_server_name().expect("66"),
        Some(&b"tftp.example.test"[..])
    );
    assert_eq!(offer.routers().expect("3").expect("routers").first(), RELAY);
}

#[test]
fn the_fqdn_is_answered_as_a_server_without_dns_updates() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let request = with(ask(MessageType::Request, 0x30), |a| {
        a.requested = Some(ip("192.0.2.150"));
        a.server_id = Some(SERVER);
    });
    let mut bytes = request.bytes();
    // Option 81 with S set and an ASCII name, before the end option.
    let end = bytes.iter().rposition(|b| *b == 255).expect("end");
    bytes.splice(
        end..end,
        [
            81,
            8,
            ClientFqdn::FLAG_S,
            0,
            0,
            b'h',
            b'o',
            b's',
            b't',
            b'1',
        ],
    );
    let answer = world.run(&bytes, t0(), &mut scratch);
    let (ack, _) = reply_of(&answer, &scratch);
    let fqdn = ack.client_fqdn().expect("81").expect("answered");
    assert_eq!(fqdn.flags(), ClientFqdn::FLAG_N | ClientFqdn::FLAG_O);
    assert_eq!(fqdn.rcode1(), 255);
    assert_eq!(scratch.change.fqdn.as_slice(), b"host1");
}

#[test]
fn link_selection_option_118_and_the_server_identifier_override_select_and_answer() {
    let world = World::new();
    let mut scratch = Scratch::new();
    // Option 82: link selection 203.0.113.0, server identifier override 203.0.113.1.
    let relay = vec![5, 4, 203, 0, 113, 0, 11, 4, 203, 0, 113, 1];
    let discover = with(ask(MessageType::Discover, 0x18), |a| {
        a.relay = Some(relay.clone());
    });
    let answer = world.run(&discover.bytes(), t0(), &mut scratch);
    assert_eq!(answer.selector, Some(Selector::LinkSelection));
    let (offer, dest) = reply_of(&answer, &scratch);
    assert_eq!(
        ip("203.0.113.0").octets()[..3],
        offer.yiaddr().octets()[..3]
    );
    assert_eq!(
        offer.server_identifier().expect("54"),
        Some(ip("203.0.113.1"))
    );
    assert_eq!(codes(&offer).last(), Some(&82), "option 82 last");
    assert_eq!(dest, relay_dest(), "the reply still goes to giaddr");
    // The REQUEST names the override as the server: it is ours.
    let request = with(ask(MessageType::Request, 0x18), |a| {
        a.relay = Some(relay);
        a.requested = Some(offer.yiaddr());
        a.server_id = Some(ip("203.0.113.1"));
    });
    let answer = world.run(&request.bytes(), at(1), &mut scratch);
    assert!(matches!(answer.action, Action::CommitThenReply { .. }));
    assert!(scratch.change.relay.is_some());

    let subnet = with(ask(MessageType::Discover, 0x19), |a| {
        a.subnet = Some(ip("203.0.113.0"));
    });
    let answer = world.run(&subnet.bytes(), t0(), &mut scratch);
    assert_eq!(answer.selector, Some(Selector::SubnetSelection));
    assert_eq!(
        reply_of(&answer, &scratch).0.yiaddr().octets()[..3],
        [203, 0, 113]
    );
}

#[test]
fn a_direct_client_without_the_broadcast_flag_is_answered_at_its_hardware_address() {
    let world = World::new();
    let mut scratch = Scratch::new();
    let discover = with(ask(MessageType::Discover, 0x24), |a| a.giaddr = None);
    let answer = world.run_from(
        &discover.bytes(),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
        t0(),
        &mut scratch,
    );
    assert_eq!(answer.selector, Some(Selector::Interface));
    let (offer, dest) = reply_of(&answer, &scratch);
    assert_eq!(
        dest,
        Destination::Link {
            addr: offer.yiaddr(),
            mac: mac(0x24),
            port: 68
        }
    );
    assert_eq!(offer.yiaddr().octets()[..3], [198, 51, 100]);
}

#[test]
fn while_the_store_refuses_only_bound_leases_are_answered_and_nothing_is_written() {
    let mut world = World::new();
    world.accepting = false;
    let mut scratch = Scratch::new();
    let renew = with(ask(MessageType::Request, 0x10), |a| {
        a.giaddr = None;
        a.ciaddr = Some(ip("192.0.2.110"));
    });
    let answer = world.run(&renew.bytes(), at(600), &mut scratch);
    let Action::Reply { kind, .. } = answer.action else {
        panic!("a plain reply: {answer:?}");
    };
    assert_eq!(kind, MessageType::Ack);
    let (ack, _) = reply_of(&answer, &scratch);
    assert_eq!(
        ack.lease_time().expect("51"),
        Some(3_000),
        "the time the lease has left"
    );
    let selecting = with(ask(MessageType::Request, 0x30), |a| {
        a.requested = Some(ip("192.0.2.150"));
        a.server_id = Some(SERVER);
    });
    for (bytes, name) in [
        (selecting.bytes(), "a new lease"),
        (
            ask(MessageType::Discover, 0x30).bytes(),
            "a discover of a new client",
        ),
    ] {
        let answer = world.run(&bytes, t0(), &mut scratch);
        assert_eq!(
            answer.action,
            Action::Drop(DropReason::StoreRefused),
            "{name}"
        );
    }
    let answer = world.run(
        &ask(MessageType::Discover, 0x10).bytes(),
        t0(),
        &mut scratch,
    );
    assert_eq!(reply_of(&answer, &scratch).0.yiaddr(), ip("192.0.2.110"));
}

#[test]
fn a_restricted_scope_serves_allowed_and_reserved_clients_only() {
    let world = World::new();
    let stamp = Stamp::new(t0(), Principal::system(SystemComponent::Dhcp));
    let mut builder = ImageBuilder::new(world.image.revision());
    for scope in world.image.scopes() {
        builder.scope(ScopeImage {
            restricted: true,
            ..scope.clone()
        });
    }
    for reservation in world.image.reservations() {
        builder.reservation(reservation.clone());
    }
    builder.filters(vec![Filter {
        id: FilterId::generate(),
        mac: MacPattern::new("00:00:5e:00:53:41").expect("a pattern"),
        kind: FilterKind::Allow,
        note: None,
        created: stamp.clone(),
        updated: stamp,
    }]);
    let world = World {
        image: builder.build(),
        ..World::new()
    };
    let mut scratch = Scratch::new();
    let cases = [(0x30, true, false), (0x41, true, true), (0x20, false, true)];
    for (client, with_id, served) in cases {
        let discover = with(ask(MessageType::Discover, client), |a| a.with_id = with_id);
        let answer = world.run(&discover.bytes(), t0(), &mut scratch);
        if served {
            assert!(matches!(answer.action, Action::Reply { .. }), "{client:x}");
        } else {
            assert_eq!(
                answer.action,
                Action::Drop(DropReason::Filtered),
                "{client:x}"
            );
        }
    }
}

#[test]
fn a_full_scope_drops_the_discover() {
    let mut world = World::new();
    for host in 100..=150u8 {
        world.lease(
            host,
            false,
            Ipv4Addr::new(203, 0, 113, host),
            BindingState::Active,
            3_600,
        );
    }
    let mut scratch = Scratch::new();
    let discover = with(ask(MessageType::Discover, 0x36), |a| {
        a.subnet = Some(ip("203.0.113.0"));
    });
    let answer = world.run(&discover.bytes(), t0(), &mut scratch);
    assert_eq!(answer.action, Action::Drop(DropReason::PoolFull));
    assert_eq!(world.leases.len(), 52);
}
