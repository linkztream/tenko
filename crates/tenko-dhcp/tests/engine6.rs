//! The DHCPv6 engine over the in-memory lease store (RFC 8415 section 18.3): every message
//! type, rapid commit, relay chains two deep, scope selection by link address and by
//! Interface-Id, DUID and MAC reservations, the RFC 6939 link-layer address, the options of
//! RFC 3646 and RFC 5908, the client FQDN of RFC 4704, and the commit before the REPLY.

mod engine6_world;

use engine6_world::{
    LINK1, LINK2, SERVER_DUID, World6, addr, addresses, bound, client_options, duid_ll, ia_na, mac,
    message, relay1, relayed, reservation, statuses, unwrap,
};
use tenko_core::{
    VrfId,
    dhcp::{BindingState, Filter, FilterKind, LeaseEventKind, MacPattern},
};
use tenko_dhcp::{
    v4::engine::DropReason,
    v6::{
        ClientFqdn, Message, MessageType, NtpServer, code,
        engine::{Action6, Ignore6, Selector6},
        image::Reservation6Key,
        lease::Lease6Table,
        status,
    },
};

const NIL: VrfId = VrfId(uuid::Uuid::nil());

fn solicit(duid: &[u8], iaid: u32) -> Vec<u8> {
    message(MessageType::Solicit, 0x00_1234, |b| {
        client_options(b, duid);
        ia_na(b, iaid, None);
    })
}

fn request(duid: &[u8], iaid: u32, address: std::net::Ipv6Addr, kind: MessageType) -> Vec<u8> {
    message(kind, 0x00_5678, |b| {
        client_options(b, duid);
        if matches!(
            kind,
            MessageType::Request | MessageType::Renew | MessageType::Release | MessageType::Decline
        ) {
            b.option(code::SERVERID, &SERVER_DUID).expect("server id");
        }
        ia_na(b, iaid, Some(address));
    })
}

/// SOLICIT, ADVERTISE, REQUEST, REPLY through one relay; returns the address.
fn lease(world: &mut World6, duid: &[u8], iaid: u32) -> std::net::Ipv6Addr {
    let (answer, reply) = world.exchange(&relay1(&solicit(duid, iaid)));
    assert!(matches!(
        answer.action,
        Action6::Reply {
            kind: MessageType::Advertise,
            ..
        }
    ));
    let offered = addresses(&reply.expect("advertise"))[0].1;
    let (answer, reply) =
        world.exchange(&relay1(&request(duid, iaid, offered, MessageType::Request)));
    assert!(
        matches!(
            answer.action,
            Action6::CommitThenReply {
                kind: MessageType::Reply,
                ..
            }
        ),
        "{answer:?}"
    );
    assert_eq!(addresses(&reply.expect("reply"))[0].1, offered);
    offered
}

#[test]
fn a_solicit_gets_an_advertise_from_the_pool_and_writes_nothing() {
    let mut world = World6::new();
    let duid = duid_ll(mac(1));
    let (answer, reply) = world.exchange(&relay1(&solicit(&duid, 7)));
    assert_eq!(answer.selector, Some(Selector6::LinkAddress));
    let Action6::Reply { kind, dest, .. } = answer.action else {
        panic!("{answer:?}");
    };
    assert_eq!(kind, MessageType::Advertise);
    assert_eq!(dest.address().port(), 547);
    let reply = reply.expect("advertise");
    let outer = Message::parse(&reply).expect("parses");
    assert_eq!(outer.kind(), MessageType::RelayRepl);
    assert_eq!(outer.link_address(), LINK1);
    let inner = unwrap(&reply);
    let inner = Message::parse(&inner).expect("inner");
    assert_eq!(inner.transaction_id(), 0x00_1234);
    assert_eq!(
        inner.server_id().expect("sid").expect("present").as_bytes(),
        SERVER_DUID
    );
    assert_eq!(
        inner.client_id().expect("cid").expect("present").as_bytes(),
        duid
    );
    let got = addresses(&reply);
    assert_eq!(got.len(), 1);
    let (iaid, address, preferred, valid) = got[0];
    assert_eq!(iaid, 7);
    assert!(addr("2001:db8:1::100") <= address && address <= addr("2001:db8:1::1ff"));
    assert_eq!((preferred, valid), (3_000, 4_000));
    let ia = inner.ia_nas().next().expect("ia").expect("ok");
    assert_eq!((ia.t1, ia.t2), (1_500, 2_400));
    // RFC 3646 and RFC 5908: the options asked for.
    let dns = inner.option(code::DNS_SERVERS).expect("walk").expect("23");
    assert_eq!(dns, addr("2001:db8::53").octets());
    assert_eq!(
        inner.option(code::DOMAIN_LIST).expect("walk").expect("24"),
        b"\x07example\x04test\x00"
    );
    let ntp =
        NtpServer::parse(inner.option(code::NTP_SERVER).expect("walk").expect("56")).expect("ntp");
    assert_eq!(
        ntp.suboptions().collect::<Vec<_>>(),
        vec![tenko_dhcp::v6::NtpSuboption::ServerAddress(addr(
            "2001:db8::123"
        ))]
    );
    assert_eq!(world.rows(), 0, "an ADVERTISE writes nothing");
    // A second client is not offered the address held for the first.
    let (_, other) = world.exchange(&relay1(&solicit(&duid_ll(mac(2)), 7)));
    assert_ne!(addresses(&other.expect("advertise"))[0].1, address);
}

#[test]
fn a_request_commits_the_binding_before_its_reply_and_a_renewal_extends_it() {
    let mut world = World6::new();
    let duid = duid_ll(mac(3));
    let address = lease(&mut world, &duid, 1);
    assert!(bound(&world, address, &duid));
    let row = world.table.get(NIL, address).expect("row").clone();
    assert_eq!(row.iaid, 1);
    assert_eq!(
        row.link_layer.as_ref().map(|l| l.0.clone()),
        Some(mac(3).to_vec())
    );
    assert_eq!(row.relay.as_ref().map(|r| r.link_address), Some(LINK1));
    assert_eq!(world.store.history()[0].kind, LeaseEventKind::Granted);
    // RENEW: the same address, a later end.
    world.now = world
        .now
        .checked_add(std::time::Duration::from_secs(1_500))
        .expect("t1");
    let (answer, reply) = world.exchange(&relay1(&request(&duid, 1, address, MessageType::Renew)));
    assert!(matches!(answer.action, Action6::CommitThenReply { .. }));
    assert_eq!(addresses(&reply.expect("reply"))[0].1, address);
    let renewed = world.table.get(NIL, address).expect("row");
    assert!(renewed.ends > row.ends);
    assert_eq!(world.store.history()[1].kind, LeaseEventKind::Renewed);
    // REBIND: no server identifier, the same address.
    let (answer, reply) = world.exchange(&relay1(&request(&duid, 1, address, MessageType::Rebind)));
    assert!(matches!(answer.action, Action6::CommitThenReply { .. }));
    assert_eq!(addresses(&reply.expect("reply"))[0].1, address);
    assert_eq!(world.store.history()[2].kind, LeaseEventKind::Rebound);
}

#[test]
fn a_renewal_of_an_address_of_another_link_gets_lifetimes_of_zero() {
    let mut world = World6::new();
    let duid = duid_ll(mac(4));
    let foreign = addr("2001:db8:2::150");
    let (_, reply) = world.exchange(&relay1(&request(&duid, 1, foreign, MessageType::Renew)));
    let got = addresses(&reply.expect("reply"));
    assert!(got.contains(&(1, foreign, 0, 0)), "{got:?}");
    // The client gets an address of its own link beside it.
    assert!(
        got.iter()
            .any(|(_, a, _, valid)| *valid > 0 && LINK1.segments()[2] == a.segments()[2])
    );
}

#[test]
fn release_and_decline_commit_and_reply_success() {
    let mut world = World6::new();
    let duid = duid_ll(mac(5));
    let address = lease(&mut world, &duid, 2);
    let (answer, reply) =
        world.exchange(&relay1(&request(&duid, 2, address, MessageType::Release)));
    assert!(
        matches!(answer.action, Action6::CommitThenReply { .. }),
        "{answer:?}"
    );
    assert_eq!(statuses(&reply.expect("reply")).1, Some(status::SUCCESS));
    assert_eq!(
        world.table.get(NIL, address).expect("row").state,
        BindingState::Released
    );
    // A RELEASE of nothing it holds: NoBinding, nothing written.
    let (answer, reply) =
        world.exchange(&relay1(&request(&duid, 2, address, MessageType::Release)));
    assert!(matches!(answer.action, Action6::Reply { .. }));
    assert_eq!(
        statuses(&reply.expect("reply")).0,
        vec![Some(status::NO_BINDING)]
    );
    // DECLINE: the address is abandoned and offered to nobody, the decliner included.
    let duid2 = duid_ll(mac(6));
    let second = lease(&mut world, &duid2, 1);
    let (answer, _) = world.exchange(&relay1(&request(&duid2, 1, second, MessageType::Decline)));
    assert!(matches!(answer.action, Action6::CommitThenReply { .. }));
    let row = world.table.get(NIL, second).expect("row");
    assert_eq!(row.state, BindingState::Abandoned);
    assert!(row.ends > world.now);
    let (_, reply) = world.exchange(&relay1(&solicit(&duid2, 1)));
    assert_ne!(addresses(&reply.expect("advertise"))[0].1, second);
}

#[test]
fn confirm_says_whether_the_addresses_are_on_the_link() {
    let mut world = World6::new();
    let duid = duid_ll(mac(7));
    let on = request(&duid, 1, addr("2001:db8:1::999"), MessageType::Confirm);
    let (answer, reply) = world.exchange(&relay1(&on));
    assert!(matches!(
        answer.action,
        Action6::Reply {
            kind: MessageType::Reply,
            ..
        }
    ));
    assert_eq!(statuses(&reply.expect("reply")).1, Some(status::SUCCESS));
    let off = request(&duid, 1, addr("2001:db8:2::999"), MessageType::Confirm);
    let (_, reply) = world.exchange(&relay1(&off));
    assert_eq!(
        statuses(&reply.expect("reply")).1,
        Some(status::NOT_ON_LINK)
    );
    let empty = message(MessageType::Confirm, 1, |b| {
        client_options(b, &duid);
        ia_na(b, 1, None);
    });
    assert_eq!(
        world.exchange(&relay1(&empty)).0.action,
        Action6::Ignore(Ignore6::Incomplete)
    );
    assert_eq!(world.rows(), 0);
}

#[test]
fn an_information_request_gets_the_options_and_no_address() {
    let mut world = World6::new();
    let info = message(MessageType::InformationRequest, 9, |b| {
        b.option(code::ORO, &[0, 23, 0, 24]).expect("oro");
    });
    let (answer, reply) = world.exchange(&relay1(&info));
    assert!(matches!(
        answer.action,
        Action6::Reply {
            kind: MessageType::Reply,
            ..
        }
    ));
    let inner = unwrap(&reply.expect("reply"));
    let inner = Message::parse(&inner).expect("parses");
    assert!(inner.option(code::DNS_SERVERS).expect("walk").is_some());
    assert_eq!(inner.ia_nas().count(), 0);
    let with_ia = message(MessageType::InformationRequest, 9, |b| ia_na(b, 1, None));
    assert_eq!(
        world.exchange(&relay1(&with_ia)).0.action,
        Action6::Ignore(Ignore6::Incomplete)
    );
}

#[test]
fn rapid_commit_answers_a_solicit_with_a_committed_reply_where_the_scope_allows_it() {
    let mut world = World6::new();
    let duid = duid_ll(mac(8));
    let rapid = message(MessageType::Solicit, 3, |b| {
        client_options(b, &duid);
        b.option(code::RAPID_COMMIT, &[]).expect("rapid");
        ia_na(b, 4, None);
    });
    let (answer, reply) = world.exchange(&relay1(&rapid));
    assert!(matches!(
        answer.action,
        Action6::CommitThenReply {
            kind: MessageType::Reply,
            ..
        }
    ));
    let reply = reply.expect("reply");
    let inner = unwrap(&reply);
    assert!(Message::parse(&inner).expect("parses").rapid_commit());
    assert!(bound(&world, addresses(&reply)[0].1, &duid));
    // A scope that refuses rapid commit answers with an ADVERTISE.
    let mut strict = World6::with(|first, _, _| first.v6.rapid_commit = Some(false));
    let (answer, _) = strict.exchange(&relay1(&rapid));
    assert!(matches!(
        answer.action,
        Action6::Reply {
            kind: MessageType::Advertise,
            ..
        }
    ));
    assert_eq!(strict.rows(), 0);
}

#[test]
fn a_relay_chain_two_deep_selects_by_the_inner_link_and_the_reply_retraces_it() {
    let mut world = World6::new();
    let duid = duid_ll(mac(9));
    // A lightweight relay (RFC 6221) on the client's link sends a link address of zero and
    // an Interface-Id; the relay above names the link.
    let chain = relayed(
        &solicit(&duid, 1),
        &[
            (
                std::net::Ipv6Addr::UNSPECIFIED,
                addr("fe80::1"),
                Some(b"port-7"),
            ),
            (LINK2, addr("2001:db8:2::2"), None),
        ],
        None,
    );
    let (answer, reply) = world.exchange(&chain);
    assert_eq!(answer.selector, Some(Selector6::LinkAddress));
    let reply = reply.expect("advertise");
    let outer = Message::parse(&reply).expect("outer");
    assert_eq!(outer.kind(), MessageType::RelayRepl);
    assert_eq!((outer.hop_count(), outer.link_address()), (1, LINK2));
    assert_eq!(outer.interface_id().expect("walk"), None);
    let inner = outer.relay_message().expect("walk").expect("inner relay");
    assert_eq!(inner.kind(), MessageType::RelayRepl);
    assert_eq!(inner.peer_address(), addr("fe80::1"));
    assert_eq!(inner.interface_id().expect("walk"), Some(&b"port-7"[..]));
    let address = addresses(&reply)[0].1;
    assert_eq!(
        address.segments()[2],
        2,
        "an address of the second link: {address}"
    );
}

#[test]
fn an_interface_id_a_scope_names_selects_it_before_the_link_address() {
    let mut world = World6::with(|_, second, _| second.interface_id = Some(b"vlan-20".to_vec()));
    let duid = duid_ll(mac(10));
    let chain = relayed(
        &solicit(&duid, 1),
        &[(LINK1, addr("fe80::2"), Some(b"vlan-20"))],
        None,
    );
    let (answer, reply) = world.exchange(&chain);
    assert_eq!(answer.selector, Some(Selector6::InterfaceId));
    assert_eq!(addresses(&reply.expect("advertise"))[0].1.segments()[2], 2);
}

#[test]
fn a_reservation_by_duid_and_one_by_mac_through_rfc_6939_win_over_the_pool() {
    let mut world_prefix = None;
    let duid = vec![0, 2, 0, 0, 0xab, 0x11, 1, 2, 3, 4, 5, 6, 7, 8];
    let mut world = World6::with(|first, _, reservations| {
        world_prefix = Some(first.prefix);
        reservations.push(reservation(
            first.prefix,
            "2001:db8:1::80",
            Reservation6Key::Duid(duid.clone()),
        ));
        reservations.push(reservation(
            first.prefix,
            "2001:db8:1::81",
            Reservation6Key::Mac(mac(12)),
        ));
    });
    let (_, reply) = world.exchange(&relay1(&solicit(&duid, 1)));
    assert_eq!(
        addresses(&reply.expect("advertise"))[0].1,
        addr("2001:db8:1::80")
    );
    // A DUID-EN carries no MAC; the relay's Client Link-Layer Address does (RFC 6939).
    let other = vec![0, 2, 0, 0, 0xab, 0x11, 9, 9, 9, 9];
    let chain = relayed(
        &solicit(&other, 1),
        &[(LINK1, addr("fe80::3"), None)],
        Some(mac(12)),
    );
    let (_, reply) = world.exchange(&chain);
    assert_eq!(
        addresses(&reply.expect("advertise"))[0].1,
        addr("2001:db8:1::81")
    );
    // Nobody else gets a reserved address.
    let (_, reply) = world.exchange(&relay1(&solicit(&duid_ll(mac(13)), 1)));
    let got = addresses(&reply.expect("advertise"))[0].1;
    assert!(got != addr("2001:db8:1::80") && got != addr("2001:db8:1::81"));
    // The lease row keeps the link-layer address of RFC 6939 for the correlation.
    let offered = addr("2001:db8:1::81");
    let req = message(MessageType::Request, 5, |b| {
        client_options(b, &other);
        b.option(code::SERVERID, &SERVER_DUID).expect("sid");
        ia_na(b, 1, Some(offered));
    });
    let chain = relayed(&req, &[(LINK1, addr("fe80::3"), None)], Some(mac(12)));
    world.exchange(&chain);
    let row = world.table.get(NIL, offered).expect("row");
    assert_eq!(row.mac(), Some(mac(12)));
    assert_eq!(row.link_layer_type, Some(1));
}

#[test]
fn the_mac_filters_hold_for_dhcpv6_clients_by_their_link_layer_address() {
    let mut world = World6::new();
    let stamp = tenko_core::ipam::Stamp::new(
        tenko_core::Timestamp::now(),
        tenko_core::Principal::system(tenko_core::SystemComponent::Dhcp),
    );
    let mut builder = tenko_dhcp::image::ImageBuilder::new(tenko_core::Revision(2));
    let prefixes = (world.prefix1, world.prefix2);
    let fresh = engine6_world::image(prefixes.0, prefixes.1, |_, _, _| {});
    for scope in fresh.v6().scopes() {
        builder.v6().add_scope(scope.clone());
    }
    builder.filters(vec![Filter {
        id: tenko_core::dhcp::FilterId::generate(),
        mac: MacPattern::new("00:00:5e:00:53:0e").expect("pattern"),
        kind: FilterKind::Deny,
        note: None,
        created: stamp.clone(),
        updated: stamp,
    }]);
    world.image = builder.build();
    let (answer, _) = world.exchange(&relay1(&solicit(&duid_ll(mac(14)), 1)));
    assert_eq!(answer.action, Action6::Drop(DropReason::Filtered));
    let (answer, _) = world.exchange(&relay1(&solicit(&duid_ll(mac(15)), 1)));
    assert!(matches!(answer.action, Action6::Reply { .. }));
}

#[test]
fn messages_for_another_server_or_without_their_options_are_ignored() {
    let mut world = World6::new();
    let duid = duid_ll(mac(16));
    let other = message(MessageType::Request, 1, |b| {
        client_options(b, &duid);
        b.option(
            code::SERVERID,
            &[0, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )
        .expect("sid");
        ia_na(b, 1, None);
    });
    assert_eq!(
        world.exchange(&relay1(&other)).0.action,
        Action6::Ignore(Ignore6::OtherServer)
    );
    let solicit_with_sid = message(MessageType::Solicit, 1, |b| {
        client_options(b, &duid);
        b.option(code::SERVERID, &SERVER_DUID).expect("sid");
    });
    assert_eq!(
        world.exchange(&relay1(&solicit_with_sid)).0.action,
        Action6::Ignore(Ignore6::Incomplete)
    );
    let advertise = message(MessageType::Advertise, 1, |_| {});
    assert_eq!(
        world.exchange(&relay1(&advertise)).0.action,
        Action6::Ignore(Ignore6::NotRequest)
    );
    assert_eq!(
        world.exchange(&[1, 2]).0.action,
        Action6::Drop(DropReason::Malformed)
    );
    let unknown_link = relayed(
        &solicit(&duid, 1),
        &[(addr("2001:db8:9::1"), addr("fe80::9"), None)],
        None,
    );
    assert_eq!(
        world.exchange(&unknown_link).0.action,
        Action6::Drop(DropReason::NoScope)
    );
}

#[test]
fn the_client_fqdn_of_rfc_4704_reaches_the_lease_and_the_reply_says_what_the_server_does() {
    let mut world = World6::with(|first, _, _| first.ddns.enabled = true);
    let duid = duid_ll(mac(17));
    let fqdn = |b: &mut tenko_dhcp::v6::MessageBuilder<'_>| {
        b.option(code::CLIENT_FQDN, b"\x01\x06laptop")
            .expect("fqdn");
    };
    let sol = message(MessageType::Solicit, 1, |b| {
        client_options(b, &duid);
        ia_na(b, 1, None);
        fqdn(b);
    });
    let (_, reply) = world.exchange(&relay1(&sol));
    let offered = addresses(&reply.clone().expect("advertise"))[0].1;
    let inner = unwrap(&reply.expect("advertise"));
    let answer = ClientFqdn::parse(
        Message::parse(&inner)
            .expect("parses")
            .option(code::CLIENT_FQDN)
            .expect("walk")
            .expect("39"),
    )
    .expect("fqdn");
    assert_eq!(
        answer.flags(),
        ClientFqdn::FLAG_S,
        "the server writes the AAAA record"
    );
    let req = message(MessageType::Request, 2, |b| {
        client_options(b, &duid);
        b.option(code::SERVERID, &SERVER_DUID).expect("sid");
        ia_na(b, 1, Some(offered));
        fqdn(b);
    });
    world.exchange(&relay1(&req));
    let row = world.table.get(NIL, offered).expect("row");
    assert_eq!(row.fqdn.as_deref(), Some("laptop"));
    // S in the layout of option 81, with E (the wire encoding).
    assert_eq!(row.fqdn_flags, Some(0x01 | 0x04));
}

#[test]
fn while_the_store_refuses_a_bound_lease_is_answered_for_its_time_left_and_new_requests_drop() {
    let mut world = World6::new();
    let duid = duid_ll(mac(18));
    let address = lease(&mut world, &duid, 1);
    world.accepting = false;
    let (answer, reply) = world.exchange(&relay1(&request(&duid, 1, address, MessageType::Renew)));
    assert!(
        matches!(answer.action, Action6::Reply { .. }),
        "nothing to commit: {answer:?}"
    );
    let (_, got, _, valid) = addresses(&reply.expect("reply"))[0];
    assert_eq!(got, address);
    assert!(valid <= 4_000 && valid > 0);
    let (answer, _) = world.exchange(&relay1(&solicit(&duid_ll(mac(19)), 1)));
    assert_eq!(answer.action, Action6::Drop(DropReason::StoreRefused));
}

#[test]
fn two_ias_of_one_client_get_two_addresses_in_one_commit() {
    let mut world = World6::new();
    let duid = duid_ll(mac(20));
    let sol = message(MessageType::Solicit, 1, |b| {
        client_options(b, &duid);
        ia_na(b, 1, None);
        ia_na(b, 2, None);
    });
    let (_, reply) = world.exchange(&relay1(&sol));
    let offered = addresses(&reply.expect("advertise"));
    assert_eq!(offered.len(), 2);
    assert_ne!(offered[0].1, offered[1].1);
    let req = message(MessageType::Request, 2, |b| {
        client_options(b, &duid);
        b.option(code::SERVERID, &SERVER_DUID).expect("sid");
        ia_na(b, 1, Some(offered[0].1));
        ia_na(b, 2, Some(offered[1].1));
    });
    let (answer, _) = world.exchange(&relay1(&req));
    assert!(matches!(answer.action, Action6::CommitThenReply { .. }));
    assert_eq!(world.store.history().len(), 2);
    assert!(bound(&world, offered[0].1, &duid) && bound(&world, offered[1].1, &duid));
}
