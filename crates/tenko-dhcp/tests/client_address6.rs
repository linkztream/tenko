//! DHCPv6 and the network a message came from (RFC 8415 sections 13.1 and 18.3.4 to 18.3.8,
//! `docs/dhcp.md` section 9.1): a message that is not relayed is a client of the listener's
//! link, so an address of another link in its `IA_NA` is neither granted, renewed, released
//! nor declined; and it must come from a link-local address or one of that link, as a
//! DHCPv4 request with an address must come from its network. Only a trusted relay's link
//! address or Interface-Id selects another link (`tests/relay_trust6.rs`).

mod engine6_world;

use std::net::{Ipv6Addr, SocketAddrV6};

use engine6_world::{
    LINK2, SERVER_DUID, World6, addr, addresses, bound, client_options, duid_ll, ia_na, mac,
    message, relayed, statuses,
};
use tenko_dhcp::{
    v4::engine::DropReason,
    v6::{
        MessageType, code,
        engine::{Action6, Selector6},
        status,
    },
};

fn request(duid: &[u8], address: Option<Ipv6Addr>, kind: MessageType) -> Vec<u8> {
    message(kind, 0x00_7777, |b| {
        client_options(b, duid);
        if !matches!(kind, MessageType::Rebind | MessageType::Solicit) {
            b.option(code::SERVERID, &SERVER_DUID).expect("server id");
        }
        ia_na(b, 1, address);
    })
}

/// Through the relay of the second link.
fn relay2(inner: &[u8]) -> Vec<u8> {
    relayed(
        inner,
        &[(LINK2, addr("fe80::200:5eff:fe00:5307"), None)],
        None,
    )
}

/// A binding on the second link, made through its relay.
fn leased(world: &mut World6, duid: &[u8]) -> Ipv6Addr {
    let (_, reply) = world.exchange(&relay2(&request(duid, None, MessageType::Solicit)));
    let offered = addresses(&reply.expect("advertise"))[0].1;
    world.exchange(&relay2(&request(duid, Some(offered), MessageType::Request)));
    assert!(bound(world, offered, duid));
    offered
}

/// Asserts that a message the engine answered binds nothing outside the first link and
/// gives `named` lifetimes of zero.
fn listener_link_only(world: &World6, answer: &tenko_dhcp::v6::engine::Answer6, named: Ipv6Addr) {
    assert_eq!(answer.selector, Some(Selector6::Listener));
    assert!(
        world
            .scratch
            .change
            .bindings()
            .iter()
            .all(|binding| binding.addr.segments()[2] == 1),
        "{named}: {:?}",
        world.scratch.change.bindings()
    );
    let (Action6::Reply { len, .. } | Action6::CommitThenReply { len, .. }) = answer.action else {
        panic!("a reply, got {answer:?}");
    };
    let got = addresses(&world.scratch.reply[..len]);
    assert!(got.contains(&(1, named, 0, 0)), "{named}: {got:?}");
}

#[test]
fn a_message_that_is_not_relayed_is_a_client_of_the_listener_s_link_only() {
    let mut world = World6::new();
    let duid = duid_ll(mac(7));
    let theirs = leased(&mut world, &duid);
    assert_eq!(theirs.segments()[2], 2, "an address of the second link");
    let free = addr("2001:db8:2::1a0");
    let kinds = [
        MessageType::Renew,
        MessageType::Rebind,
        MessageType::Request,
    ];
    // From a link-local address (RFC 8415 section 13.1) or an address of the listener's
    // link: the listener's link, so an address of the second link is neither granted nor
    // renewed, released or declined.
    for source in [addr("fe80::200:5eff:fe00:5307"), addr("2001:db8:1::7")] {
        let from = SocketAddrV6::new(source, 546, 0, 0);
        for kind in kinds {
            for named in [theirs, free] {
                let answer = world.handle_from(&request(&duid, Some(named), kind), from);
                listener_link_only(&world, &answer, named);
            }
        }
        for kind in [MessageType::Release, MessageType::Decline] {
            let answer = world.handle_from(&request(&duid, Some(theirs), kind), from);
            let Action6::Reply { len, .. } = answer.action else {
                panic!("{kind:?} from {source}: {answer:?}");
            };
            assert!(world.scratch.change.is_empty(), "{kind:?} from {source}");
            let reply = world.scratch.reply[..len].to_vec();
            assert_eq!(
                statuses(&reply).0,
                vec![Some(status::NO_BINDING)],
                "{kind:?}"
            );
        }
    }
    // From a global address of another link, the client's own one included: such a
    // message did not come from the listener's link, and is dropped and reported.
    for source in [theirs, addr("2001:db8:2::7"), addr("2001:db8:9::5")] {
        let from = SocketAddrV6::new(source, 546, 0, 0);
        for kind in kinds
            .into_iter()
            .chain([MessageType::Release, MessageType::Solicit])
        {
            let answer = world.handle_from(&request(&duid, Some(theirs), kind), from);
            assert_eq!(
                answer.action,
                Action6::Drop(DropReason::WrongNetwork),
                "{kind:?} from {source}"
            );
        }
    }
    let report = world.guard.relay_report(Some(&world.image));
    assert_eq!(report.wrong_network.len(), 3, "{report:?}");
    assert!(
        report.refused.is_empty(),
        "no relay was refused: {report:?}"
    );
    assert!(
        bound(&world, theirs, &duid),
        "the binding of the second link is untouched"
    );
}
