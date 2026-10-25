//! DHCPv6 prefix delegation in the engine (RFC 8415 sections 6.3 and 18.3): `IA_PD` in
//! SOLICIT, REQUEST, RENEW, REBIND, RELEASE and DECLINE over the in-memory lease store.
//!
//! - **Allocation.** A SOLICIT gets an ADVERTISE with an aligned prefix of the pool's
//!   length inside the pool and writes nothing; a REQUEST commits a binding of kind `pd`
//!   before its REPLY; RENEW and REBIND keep the prefix.
//! - **Hints.** A hinted free prefix of a pool is honoured, a hint of a length only picks
//!   the pool of that length, a prefix outside every pool, unaligned, of another length or
//!   held by another client is not given (lifetimes of zero on RENEW).
//! - **No prefix.** An exhausted pool gives `NoPrefixAvail` inside the `IA_PD`, in the
//!   ADVERTISE as well as in the REPLY; a RENEW of nothing the client holds gives
//!   `NoBinding`.
//! - **Giving back.** RELEASE releases prefixes, DECLINE leaves them alone.
//! - **Neighbours.** An `IA_NA` and an `IA_PD` of one IAID make two bindings of one commit,
//!   an exclusion inside a prefix keeps it out, rapid commit commits, a refusing store
//!   answers a bound prefix for its time left and drops new requests, and a delegation
//!   pool of a sibling scope of a shared network is used.

mod engine6_world;

use std::net::Ipv6Addr;

use engine6_world::{
    LINK1, PD_FIRST, PD_LAST, SERVER_DUID, World6, addr, addresses, client_options, delegated,
    duid_ll, ia_na, ia_pd, mac, message, pd_pool, pd_pool_60, pd_statuses, prefixes, relay1,
    statuses, unwrap,
};
use tenko_core::{
    VrfId,
    dhcp::{
        BindingState, Lease6, Lease6Kind, LeaseEventKind, OptionSpace, OptionValue,
        SharedNetworkId, lease::write_identity6,
    },
    serde_util::HexBytes,
};
use tenko_dhcp::{
    v4::engine::DropReason,
    v6::{
        Message, MessageType, code,
        engine::Action6,
        lease::{Lease6Table, MAX_BINDINGS},
        status,
    },
};

const NIL: VrfId = VrfId(uuid::Uuid::nil());
/// The last address of a pool of the single prefix `2001:db8:180:100::/60`.
const ONE_LAST: &str = "2001:db8:180:10f:ffff:ffff:ffff:ffff";
/// The /56 pool of the second family of tests.
const POOL56_FIRST: &str = "2001:db8:181::";
const POOL56_LAST: &str = "2001:db8:181:ffff:ffff:ffff:ffff:ffff";

fn pd_world() -> World6 {
    World6::with(|first, _, _| first.pd_pools = vec![pd_pool_60()])
}

/// A world whose only prefix to delegate is `2001:db8:180:100::/60`.
fn one_prefix_world() -> World6 {
    World6::with(|first, _, _| first.pd_pools = vec![pd_pool(PD_FIRST, ONE_LAST, 60)])
}

fn p60(text: &str) -> (Ipv6Addr, u8) {
    (addr(text), 60)
}

/// The message of `kind` with one `IA_PD` of `iaid` holding the hints.
fn pd_message(kind: MessageType, duid: &[u8], iaid: u32, hints: &[(Ipv6Addr, u8)]) -> Vec<u8> {
    message(kind, 0x00_2468, |b| {
        client_options(b, duid);
        if matches!(
            kind,
            MessageType::Request | MessageType::Renew | MessageType::Release | MessageType::Decline
        ) {
            b.option(code::SERVERID, &SERVER_DUID).expect("server id");
        }
        ia_pd(b, iaid, hints);
    })
}

/// Whether `prefix` is one of the prefixes of length `len` of the range `first` to `last`.
fn in_range(prefix: Ipv6Addr, first: &str, last: &str, len: u8) -> bool {
    let (prefix, first, last) = (
        u128::from(prefix),
        u128::from(addr(first)),
        u128::from(addr(last)),
    );
    first <= prefix && prefix <= last && (prefix - first) % (1u128 << (128 - u32::from(len))) == 0
}

fn in_pool(prefix: Ipv6Addr) -> bool {
    in_range(prefix, PD_FIRST, PD_LAST, 60)
}

fn advance(world: &mut World6, secs: u64) {
    world.now = world
        .now
        .checked_add(std::time::Duration::from_secs(secs))
        .expect("later");
}

/// SOLICIT, ADVERTISE, REQUEST, REPLY through one relay for one `IA_PD`; the prefix.
fn delegate(world: &mut World6, duid: &[u8], iaid: u32, hints: &[(Ipv6Addr, u8)]) -> Ipv6Addr {
    let (answer, reply) = world.exchange(&relay1(&pd_message(
        MessageType::Solicit,
        duid,
        iaid,
        hints,
    )));
    assert!(
        matches!(
            answer.action,
            Action6::Reply {
                kind: MessageType::Advertise,
                ..
            }
        ),
        "{answer:?}"
    );
    let offered = prefixes(&reply.expect("advertise"));
    assert_eq!(offered.len(), 1, "{offered:?}");
    let (_, prefix, len, _, _) = offered[0];
    let (answer, reply) = world.exchange(&relay1(&pd_message(
        MessageType::Request,
        duid,
        iaid,
        &[(prefix, len)],
    )));
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
    let granted = prefixes(&reply.expect("reply"));
    assert_eq!(granted.len(), 1, "{granted:?}");
    assert_eq!((granted[0].1, granted[0].2), (prefix, len));
    prefix
}

#[test]
fn a_solicit_with_an_ia_pd_gets_an_advertise_with_one_prefix_of_the_pool_and_writes_nothing() {
    let mut world = pd_world();
    let duid = duid_ll(mac(1));
    let solicit = pd_message(MessageType::Solicit, &duid, 7, &[]);
    let (answer, reply) = world.exchange(&relay1(&solicit));
    let Action6::Reply { kind, .. } = answer.action else {
        panic!("{answer:?}");
    };
    assert_eq!(kind, MessageType::Advertise);
    let reply = reply.expect("advertise");
    // The wire form: RELAY-REPL around the ADVERTISE, which the codec reads back whole.
    let outer = Message::parse(&reply).expect("parses");
    assert_eq!(outer.kind(), MessageType::RelayRepl);
    let inner = unwrap(&reply);
    let inner = Message::parse(&inner).expect("inner");
    assert_eq!(inner.kind(), MessageType::Advertise);
    assert_eq!(inner.transaction_id(), 0x00_2468);
    assert_eq!(
        inner.server_id().expect("sid").expect("present").as_bytes(),
        SERVER_DUID
    );
    assert_eq!(
        inner.client_id().expect("cid").expect("present").as_bytes(),
        duid
    );
    assert_eq!(inner.ia_nas().count(), 0, "no IA_NA was asked for");
    assert_eq!(
        inner.option(code::STATUS_CODE).expect("walk"),
        None,
        "no top-level status"
    );
    let mut ias = inner.ia_pds();
    let ia = ias.next().expect("an IA_PD").expect("parses");
    assert!(ias.next().is_none());
    assert_eq!(ia.iaid, 7);
    // T1 and T2 are 0.5 and 0.8 of the preferred lifetime, which the scope sets to 3,000.
    assert_eq!((ia.t1, ia.t2), (1_500, 2_400));
    assert!(ia.status().is_none());
    let mut offered = ia.prefixes();
    let prefix = offered.next().expect("an IA Prefix").expect("parses");
    assert!(offered.next().is_none(), "one prefix");
    assert_eq!(prefix.prefix_len, 60);
    assert!(in_pool(prefix.prefix), "{}", prefix.prefix);
    // The valid lifetime is the pool's (6,000), not the scope's (4,000).
    assert_eq!((prefix.preferred, prefix.valid), (3_000, 6_000));
    // The same prefix through the helper, and the options the client asked for.
    assert_eq!(prefixes(&reply), vec![(7, prefix.prefix, 60, 3_000, 6_000)]);
    let dns = inner.option(code::DNS_SERVERS).expect("walk").expect("23");
    assert_eq!(dns, addr("2001:db8::53").octets());
    assert_eq!(world.rows(), 0, "an ADVERTISE writes nothing");
    assert_eq!(world.store.history().len(), 0);
    // A second client is not offered the prefix held for the first.
    let (_, other) = world.exchange(&relay1(&pd_message(
        MessageType::Solicit,
        &duid_ll(mac(2)),
        7,
        &[],
    )));
    let other = prefixes(&other.expect("advertise"));
    assert_eq!(other.len(), 1);
    assert_ne!(other[0].1, prefix.prefix);
}

#[test]
fn the_same_client_is_offered_the_same_prefix_again() {
    let mut world = pd_world();
    let duid = duid_ll(mac(3));
    let ask = pd_message(MessageType::Solicit, &duid, 1, &[]);
    let first = prefixes(&world.exchange(&relay1(&ask)).1.expect("advertise"));
    let second = prefixes(&world.exchange(&relay1(&ask)).1.expect("advertise"));
    assert_eq!(first, second);
}

#[test]
fn a_request_commits_a_pd_binding_before_its_reply() {
    let mut world = pd_world();
    let duid = duid_ll(mac(4));
    let prefix = delegate(&mut world, &duid, 5, &[]);
    assert!(in_pool(prefix));
    assert!(delegated(&world, prefix, 60, &duid));
    assert_eq!(world.rows(), 1);
    let row = world.table.get(NIL, prefix).expect("row").clone();
    assert_eq!(row.kind, Lease6Kind::Pd);
    assert_eq!(row.prefix_len, 60);
    assert_eq!(row.addr6(), prefix, "keyed by the prefix's first address");
    assert_eq!(row.iaid, 5);
    assert_eq!(row.duid.as_bytes(), duid.as_slice());
    assert_eq!(row.state, BindingState::Active);
    assert_eq!(row.scope, world.prefix1);
    assert_eq!(
        row.link_layer.as_ref().map(|l| l.0.clone()),
        Some(mac(4).to_vec())
    );
    assert_eq!(row.relay.as_ref().map(|r| r.link_address), Some(LINK1));
    // The row ends with the pool's valid lifetime and its preferred lifetime before that.
    let granted_for = row.ends.saturating_since(row.cltt).as_secs();
    assert_eq!(granted_for, 6_000);
    assert_eq!(
        row.preferred_ends.saturating_since(row.cltt).as_secs(),
        3_000
    );
    let history = world.store.history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].kind, LeaseEventKind::Granted);
    assert_eq!((history[0].addr, history[0].prefix_len), (prefix, 60));
    // The client index of the table holds it under the kind `pd` only.
    let mut identity = [0u8; tenko_core::dhcp::lease::MAX_IDENTITY6];
    let len = write_identity6(5, &duid, &mut identity);
    let found = world
        .table
        .by_client(world.prefix1, Lease6Kind::Pd, &identity[..len])
        .expect("by client");
    assert_eq!(found.addr6(), prefix);
    assert!(
        world
            .table
            .by_client(world.prefix1, Lease6Kind::Na, &identity[..len])
            .is_none()
    );
}

#[test]
fn renew_keeps_the_prefix_and_rebind_too() {
    let mut world = pd_world();
    let duid = duid_ll(mac(5));
    let prefix = delegate(&mut world, &duid, 1, &[]);
    let before = world.table.get(NIL, prefix).expect("row").clone();
    advance(&mut world, 1_500);
    let renew = pd_message(MessageType::Renew, &duid, 1, &[(prefix, 60)]);
    let (answer, reply) = world.exchange(&relay1(&renew));
    assert!(
        matches!(answer.action, Action6::CommitThenReply { .. }),
        "{answer:?}"
    );
    assert_eq!(
        prefixes(&reply.expect("reply")),
        vec![(1, prefix, 60, 3_000, 6_000)],
        "the same prefix and nothing zeroed"
    );
    let renewed = world.table.get(NIL, prefix).expect("row");
    assert!(renewed.ends > before.ends);
    assert_eq!(renewed.kind, Lease6Kind::Pd);
    assert_eq!(world.store.history()[1].kind, LeaseEventKind::Renewed);
    assert_eq!(world.rows(), 1);
    // REBIND carries no server identifier and names the same prefix.
    advance(&mut world, 600);
    let rebind = pd_message(MessageType::Rebind, &duid, 1, &[(prefix, 60)]);
    let (answer, reply) = world.exchange(&relay1(&rebind));
    assert!(matches!(answer.action, Action6::CommitThenReply { .. }));
    assert_eq!(prefixes(&reply.expect("reply"))[0].1, prefix);
    assert_eq!(world.store.history()[2].kind, LeaseEventKind::Rebound);
    assert_eq!(world.rows(), 1);
    // A RENEW that names no prefix gets the bound one.
    let (_, reply) = world.exchange(&relay1(&pd_message(MessageType::Renew, &duid, 1, &[])));
    assert_eq!(prefixes(&reply.expect("reply"))[0].1, prefix);
    assert_eq!(world.store.history()[3].kind, LeaseEventKind::Renewed);
}

#[test]
fn a_hinted_free_prefix_of_the_pool_is_honoured() {
    let mut world = pd_world();
    for (client, hint) in [
        (6, "2001:db8:180:1a0::"),
        (7, "2001:db8:180:130::"),
        (8, "2001:db8:180:100::"),
        (9, "2001:db8:180:1f0::"),
    ] {
        let duid = duid_ll(mac(client));
        let (_, reply) = world.exchange(&relay1(&pd_message(
            MessageType::Solicit,
            &duid,
            1,
            &[p60(hint)],
        )));
        assert_eq!(
            prefixes(&reply.expect("advertise")),
            vec![(1, addr(hint), 60, 3_000, 6_000)],
            "{hint}"
        );
        assert_eq!(delegate(&mut world, &duid, 1, &[p60(hint)]), addr(hint));
        assert!(delegated(&world, addr(hint), 60, &duid));
    }
}

#[test]
fn a_hint_of_a_length_only_picks_a_prefix_of_that_length() {
    let mut world = pd_world();
    for client in 10..14 {
        let duid = duid_ll(mac(client));
        let prefix = delegate(&mut world, &duid, 1, &[(Ipv6Addr::UNSPECIFIED, 60)]);
        assert!(in_pool(prefix), "{prefix}");
        assert!(delegated(&world, prefix, 60, &duid));
    }
}

#[test]
fn with_two_pools_the_pool_of_the_hinted_length_is_chosen() {
    let mut world = World6::with(|first, _, _| {
        first.pd_pools = vec![pd_pool_60(), pd_pool(POOL56_FIRST, POOL56_LAST, 56)];
    });
    for client in 20..28 {
        let duid = duid_ll(mac(client));
        let prefix = delegate(&mut world, &duid, 1, &[(Ipv6Addr::UNSPECIFIED, 56)]);
        assert!(
            in_range(prefix, POOL56_FIRST, POOL56_LAST, 56),
            "a /56 of the second pool: {prefix}"
        );
        let row = world.table.get(NIL, prefix).expect("row");
        assert_eq!(row.prefix_len, 56);
    }
    for client in 30..38 {
        let duid = duid_ll(mac(client));
        let prefix = delegate(&mut world, &duid, 1, &[(Ipv6Addr::UNSPECIFIED, 60)]);
        assert!(in_pool(prefix), "a /60 of the first pool: {prefix}");
    }
    // A length no pool delegates is a hint that cannot be met: the client gets a prefix
    // of a pool's own length.
    let duid = duid_ll(mac(40));
    let prefix = delegate(&mut world, &duid, 1, &[(Ipv6Addr::UNSPECIFIED, 52)]);
    assert!(
        in_pool(prefix) || in_range(prefix, POOL56_FIRST, POOL56_LAST, 56),
        "{prefix}"
    );
}

#[test]
fn a_hinted_prefix_of_the_second_pool_is_honoured_with_its_length() {
    let mut world = World6::with(|first, _, _| {
        first.pd_pools = vec![pd_pool_60(), pd_pool(POOL56_FIRST, POOL56_LAST, 56)];
    });
    let duid = duid_ll(mac(41));
    let wanted = addr("2001:db8:181:4200::");
    let (_, reply) = world.exchange(&relay1(&pd_message(
        MessageType::Solicit,
        &duid,
        1,
        &[(wanted, 56)],
    )));
    assert_eq!(
        prefixes(&reply.expect("advertise")),
        vec![(1, wanted, 56, 3_000, 6_000)]
    );
}

#[test]
fn a_hint_outside_the_pools_unaligned_or_of_another_length_is_not_given() {
    let mut world = pd_world();
    let duid = duid_ll(mac(42));
    for (prefix, len) in [
        (addr("2001:db8:999::"), 60),
        // Inside the range but not on a /60 boundary.
        (addr("2001:db8:180:105::"), 60),
        // On a boundary but not of the pool's length.
        (addr("2001:db8:180:140::"), 64),
        (addr("2001:db8:180:140::"), 56),
    ] {
        let (_, reply) = world.exchange(&relay1(&pd_message(
            MessageType::Solicit,
            &duid,
            1,
            &[(prefix, len)],
        )));
        let got = prefixes(&reply.expect("advertise"));
        assert_eq!(got.len(), 1, "{prefix}/{len}: {got:?}");
        assert_ne!((got[0].1, got[0].2), (prefix, len));
        assert!(in_pool(got[0].1) && got[0].2 == 60);
    }
}

#[test]
fn a_renew_of_a_prefix_outside_the_pools_comes_back_with_lifetimes_of_zero() {
    let mut world = pd_world();
    let duid = duid_ll(mac(43));
    let foreign = addr("2001:db8:999::");
    let renew = pd_message(MessageType::Renew, &duid, 1, &[(foreign, 60)]);
    let (_, reply) = world.exchange(&relay1(&renew));
    let got = prefixes(&reply.expect("reply"));
    assert!(got.contains(&(1, foreign, 60, 0, 0)), "{got:?}");
    // The client gets a prefix of the pool beside it, as an IA_NA gets an address.
    assert!(
        got.iter()
            .any(|(_, prefix, len, _, valid)| *valid > 0 && *len == 60 && in_pool(*prefix)),
        "{got:?}"
    );
    // A REBIND does the same.
    let rebind = pd_message(MessageType::Rebind, &duid_ll(mac(44)), 1, &[(foreign, 60)]);
    let (_, reply) = world.exchange(&relay1(&rebind));
    assert!(
        prefixes(&reply.expect("reply")).contains(&(1, foreign, 60, 0, 0)),
        "REBIND"
    );
}

#[test]
fn a_prefix_taken_by_another_client_is_not_given_and_comes_back_with_lifetimes_of_zero() {
    let mut world = pd_world();
    let (first, second) = (duid_ll(mac(45)), duid_ll(mac(46)));
    let taken = delegate(&mut world, &first, 1, &[]);
    // SOLICIT: another prefix.
    let (_, reply) = world.exchange(&relay1(&pd_message(
        MessageType::Solicit,
        &second,
        1,
        &[(taken, 60)],
    )));
    let offered = prefixes(&reply.expect("advertise"));
    assert_eq!(offered.len(), 1);
    assert_ne!(offered[0].1, taken);
    // REQUEST: another prefix, the taken one with lifetimes of zero.
    let request = pd_message(MessageType::Request, &second, 1, &[(taken, 60)]);
    let (answer, reply) = world.exchange(&relay1(&request));
    assert!(matches!(answer.action, Action6::CommitThenReply { .. }));
    let got = prefixes(&reply.expect("reply"));
    assert!(got.contains(&(1, taken, 60, 0, 0)), "{got:?}");
    let own: Vec<_> = got.iter().filter(|entry| entry.4 > 0).collect();
    assert_eq!(own.len(), 1, "{got:?}");
    assert_ne!(own[0].1, taken);
    assert!(delegated(&world, own[0].1, 60, &second));
    // The first client still holds its prefix.
    assert!(delegated(&world, taken, 60, &first));
    // RENEW of the taken prefix by a third client: zero for it, a prefix of its own.
    let third = duid_ll(mac(47));
    let renew = pd_message(MessageType::Renew, &third, 1, &[(taken, 60)]);
    let (_, reply) = world.exchange(&relay1(&renew));
    let got = prefixes(&reply.expect("reply"));
    assert!(got.contains(&(1, taken, 60, 0, 0)), "{got:?}");
    assert!(delegated(&world, taken, 60, &first));
}

#[test]
fn an_exhausted_pool_gives_no_prefix_avail_in_the_reply_and_in_the_advertise() {
    let mut world = one_prefix_world();
    let (holder, other) = (duid_ll(mac(48)), duid_ll(mac(49)));
    let prefix = delegate(&mut world, &holder, 1, &[]);
    assert_eq!(prefix, addr(PD_FIRST));
    let rows = world.rows();
    let history = world.store.history().len();
    // REQUEST: the IA_PD carries the status, nothing is committed.
    let (answer, reply) =
        world.exchange(&relay1(&pd_message(MessageType::Request, &other, 3, &[])));
    let Action6::Reply {
        kind: MessageType::Reply,
        ..
    } = answer.action
    else {
        panic!("{answer:?}");
    };
    let reply = reply.expect("reply");
    assert_eq!(pd_statuses(&reply), vec![Some(status::NO_PREFIX_AVAIL)]);
    assert_eq!(status::NO_PREFIX_AVAIL, 6);
    assert_eq!(prefixes(&reply).len(), 0);
    assert_eq!(statuses(&reply).1, None, "no top-level status");
    // SOLICIT: an ADVERTISE listing the IA_PD with its status inside it.
    let (answer, reply) =
        world.exchange(&relay1(&pd_message(MessageType::Solicit, &other, 3, &[])));
    let Action6::Reply {
        kind: MessageType::Advertise,
        ..
    } = answer.action
    else {
        panic!("{answer:?}");
    };
    let reply = reply.expect("advertise");
    assert_eq!(pd_statuses(&reply), vec![Some(status::NO_PREFIX_AVAIL)]);
    assert_eq!(prefixes(&reply).len(), 0);
    assert_eq!(statuses(&reply).1, None, "no top-level status");
    let inner = unwrap(&reply);
    let inner = Message::parse(&inner).expect("parses");
    assert_eq!(inner.ia_pds().next().expect("ia").expect("ok").iaid, 3);
    // The holder's own RENEW and a fresh SOLICIT still work.
    let renew = pd_message(MessageType::Renew, &holder, 1, &[(prefix, 60)]);
    assert_eq!(
        prefixes(&world.exchange(&relay1(&renew)).1.expect("reply"))[0].1,
        prefix
    );
    assert_eq!(world.rows(), rows);
    assert_eq!(world.store.history().len(), history + 1, "only the RENEW");
}

#[test]
fn a_solicit_for_an_address_and_a_prefix_gets_the_address_when_the_pool_is_exhausted() {
    let mut world = one_prefix_world();
    delegate(&mut world, &duid_ll(mac(50)), 1, &[]);
    let duid = duid_ll(mac(51));
    let solicit = message(MessageType::Solicit, 9, |b| {
        client_options(b, &duid);
        ia_na(b, 1, None);
        ia_pd(b, 2, &[]);
    });
    let (answer, reply) = world.exchange(&relay1(&solicit));
    assert!(matches!(
        answer.action,
        Action6::Reply {
            kind: MessageType::Advertise,
            ..
        }
    ));
    let reply = reply.expect("advertise");
    assert_eq!(addresses(&reply).len(), 1);
    assert_eq!(pd_statuses(&reply), vec![Some(status::NO_PREFIX_AVAIL)]);
    assert_eq!(prefixes(&reply).len(), 0);
}

#[test]
fn a_renew_of_an_ia_pd_the_server_cannot_serve_and_that_names_no_prefix_gets_no_binding() {
    let mut world = one_prefix_world();
    delegate(&mut world, &duid_ll(mac(52)), 1, &[]);
    let rows = world.rows();
    let other = duid_ll(mac(53));
    let renew = pd_message(MessageType::Renew, &other, 4, &[]);
    let (answer, reply) = world.exchange(&relay1(&renew));
    assert!(matches!(answer.action, Action6::Reply { .. }), "{answer:?}");
    let reply = reply.expect("reply");
    assert_eq!(pd_statuses(&reply), vec![Some(status::NO_BINDING)]);
    assert_eq!(prefixes(&reply).len(), 0);
    assert_eq!(world.rows(), rows);
    // With a prefix named, the exhausted pool answers with lifetimes of zero and no status.
    let hinted = pd_message(
        MessageType::Renew,
        &other,
        4,
        &[(addr("2001:db8:999::"), 60)],
    );
    let (_, reply) = world.exchange(&relay1(&hinted));
    let reply = reply.expect("reply");
    assert_eq!(
        prefixes(&reply),
        vec![(4, addr("2001:db8:999::"), 60, 0, 0)]
    );
    assert_eq!(pd_statuses(&reply), vec![None]);
    assert_eq!(world.rows(), rows);
}

#[test]
fn release_gives_the_prefix_back_and_it_can_be_delegated_again() {
    let mut world = one_prefix_world();
    let (holder, other) = (duid_ll(mac(54)), duid_ll(mac(55)));
    let prefix = delegate(&mut world, &holder, 2, &[]);
    // Another client cannot release it, nor the holder with another IAID.
    for (duid, iaid) in [(&other, 2), (&holder, 3)] {
        let release = pd_message(MessageType::Release, duid, iaid, &[(prefix, 60)]);
        let (answer, reply) = world.exchange(&relay1(&release));
        assert!(matches!(answer.action, Action6::Reply { .. }), "{answer:?}");
        assert_eq!(
            pd_statuses(&reply.expect("reply")),
            vec![Some(status::NO_BINDING)]
        );
        assert!(delegated(&world, prefix, 60, &holder));
    }
    // The holder releases it.
    let release = pd_message(MessageType::Release, &holder, 2, &[(prefix, 60)]);
    let (answer, reply) = world.exchange(&relay1(&release));
    assert!(
        matches!(answer.action, Action6::CommitThenReply { .. }),
        "{answer:?}"
    );
    let reply = reply.expect("reply");
    assert_eq!(statuses(&reply).1, Some(status::SUCCESS));
    let row = world.table.get(NIL, prefix).expect("row");
    assert_eq!(row.state, BindingState::Released);
    assert_eq!((row.kind, row.prefix_len), (Lease6Kind::Pd, 60));
    let last = world.store.history().last().expect("event").clone();
    assert_eq!(last.kind, LeaseEventKind::Released);
    assert_eq!((last.addr, last.prefix_len), (prefix, 60));
    // A second RELEASE finds nothing: NoBinding in the IA_PD, nothing written.
    let history = world.store.history().len();
    let (answer, reply) = world.exchange(&relay1(&release));
    assert!(matches!(answer.action, Action6::Reply { .. }));
    assert_eq!(
        pd_statuses(&reply.expect("reply")),
        vec![Some(status::NO_BINDING)]
    );
    assert_eq!(world.store.history().len(), history);
    // The prefix is free for another client once the offer the holder's REQUEST left
    // (ten seconds) has ended.
    advance(&mut world, 11);
    assert_eq!(delegate(&mut world, &other, 1, &[]), prefix);
}

#[test]
fn a_release_of_an_unknown_prefix_gets_an_ia_pd_with_no_binding() {
    let mut world = pd_world();
    let duid = duid_ll(mac(56));
    let release = pd_message(
        MessageType::Release,
        &duid,
        1,
        &[p60("2001:db8:180:140::"), (addr("2001:db8:999::"), 60)],
    );
    let (answer, reply) = world.exchange(&relay1(&release));
    assert!(matches!(answer.action, Action6::Reply { .. }), "{answer:?}");
    let reply = reply.expect("reply");
    assert_eq!(pd_statuses(&reply), vec![Some(status::NO_BINDING)]);
    assert_eq!(statuses(&reply).1, Some(status::SUCCESS));
    assert_eq!(world.rows(), 0);
}

#[test]
fn a_decline_with_only_an_ia_pd_changes_nothing() {
    let mut world = pd_world();
    let duid = duid_ll(mac(57));
    let prefix = delegate(&mut world, &duid, 1, &[]);
    let history = world.store.history().len();
    let before = world.table.get(NIL, prefix).expect("row").clone();
    let decline = pd_message(MessageType::Decline, &duid, 1, &[(prefix, 60)]);
    let (answer, reply) = world.exchange(&relay1(&decline));
    assert!(
        !matches!(answer.action, Action6::CommitThenReply { .. }),
        "nothing to commit: {answer:?}"
    );
    if let Some(reply) = reply {
        assert!(prefixes(&reply).is_empty(), "no prefix is touched");
    }
    assert_eq!(world.store.history().len(), history);
    assert_eq!(world.table.get(NIL, prefix), Some(&before));
    assert!(delegated(&world, prefix, 60, &duid));
}

#[test]
fn an_ia_na_and_an_ia_pd_of_one_iaid_get_an_address_and_a_prefix_in_one_commit() {
    let mut world = pd_world();
    let duid = duid_ll(mac(58));
    let solicit = message(MessageType::Solicit, 1, |b| {
        client_options(b, &duid);
        ia_na(b, 1, None);
        ia_pd(b, 1, &[]);
    });
    let (_, reply) = world.exchange(&relay1(&solicit));
    let reply = reply.expect("advertise");
    let (address, prefix) = (addresses(&reply)[0].1, prefixes(&reply)[0].1);
    assert_eq!(addresses(&reply).len(), 1);
    assert_eq!(prefixes(&reply).len(), 1);
    let both = |kind: MessageType| {
        message(kind, 2, |b| {
            client_options(b, &duid);
            if kind != MessageType::Rebind {
                b.option(code::SERVERID, &SERVER_DUID).expect("sid");
            }
            ia_na(b, 1, Some(address));
            ia_pd(b, 1, &[(prefix, 60)]);
        })
    };
    let (answer, reply) = world.exchange(&relay1(&both(MessageType::Request)));
    assert!(
        matches!(answer.action, Action6::CommitThenReply { .. }),
        "{answer:?}"
    );
    let reply = reply.expect("reply");
    assert_eq!(addresses(&reply)[0].1, address);
    assert_eq!(prefixes(&reply)[0].1, prefix);
    assert_eq!(world.store.history().len(), 2, "one commit, two bindings");
    assert_eq!(world.rows(), 2);
    let na = world.table.get(NIL, address).expect("address row");
    let pd = world.table.get(NIL, prefix).expect("prefix row");
    assert_eq!((na.kind, na.prefix_len, na.iaid), (Lease6Kind::Na, 128, 1));
    assert_eq!((pd.kind, pd.prefix_len, pd.iaid), (Lease6Kind::Pd, 60, 1));
    // The index is per kind: each is found under its own.
    let identity = na.identity();
    assert_eq!(identity, pd.identity(), "one IAID and DUID");
    assert_eq!(
        world
            .table
            .by_client(world.prefix1, Lease6Kind::Na, &identity)
            .map(Lease6::addr6),
        Some(address)
    );
    assert_eq!(
        world
            .table
            .by_client(world.prefix1, Lease6Kind::Pd, &identity)
            .map(Lease6::addr6),
        Some(prefix)
    );
    // RENEW and REBIND find both.
    for (kind, event) in [
        (MessageType::Renew, LeaseEventKind::Renewed),
        (MessageType::Rebind, LeaseEventKind::Rebound),
    ] {
        advance(&mut world, 600);
        let before = world.store.history().len();
        let (answer, reply) = world.exchange(&relay1(&both(kind)));
        assert!(matches!(answer.action, Action6::CommitThenReply { .. }));
        let reply = reply.expect("reply");
        assert_eq!(addresses(&reply).len(), 1);
        assert_eq!(addresses(&reply)[0].1, address);
        assert_eq!(prefixes(&reply).len(), 1, "{kind:?}");
        assert_eq!(prefixes(&reply)[0].1, prefix);
        let history = world.store.history();
        assert_eq!(history.len(), before + 2);
        assert!(history[before..].iter().all(|row| row.kind == event));
    }
    // A RENEW with the IA_PD alone keeps the prefix and leaves the address alone.
    let only = pd_message(MessageType::Renew, &duid, 1, &[(prefix, 60)]);
    let (_, reply) = world.exchange(&relay1(&only));
    assert_eq!(prefixes(&reply.expect("reply"))[0].1, prefix);
    assert_eq!(world.rows(), 2);
}

#[test]
fn several_ia_pds_get_distinct_prefixes_in_the_clients_order() {
    let mut world = pd_world();
    let duid = duid_ll(mac(59));
    let solicit = message(MessageType::Solicit, 1, |b| {
        client_options(b, &duid);
        ia_pd(b, 9, &[]);
        ia_pd(b, 3, &[]);
        ia_pd(b, 5, &[]);
    });
    let (_, reply) = world.exchange(&relay1(&solicit));
    let offered = prefixes(&reply.expect("advertise"));
    assert_eq!(
        offered.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        vec![9, 3, 5]
    );
    let mut distinct: Vec<_> = offered.iter().map(|entry| entry.1).collect();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), 3, "{offered:?}");
    assert!(
        offered
            .iter()
            .all(|entry| in_pool(entry.1) && entry.2 == 60)
    );
    // REQUEST for the three: three bindings in one commit.
    let request = message(MessageType::Request, 2, |b| {
        client_options(b, &duid);
        b.option(code::SERVERID, &SERVER_DUID).expect("sid");
        for (iaid, prefix, len, _, _) in &offered {
            ia_pd(b, *iaid, &[(*prefix, *len)]);
        }
    });
    let (answer, reply) = world.exchange(&relay1(&request));
    assert!(matches!(answer.action, Action6::CommitThenReply { .. }));
    assert_eq!(prefixes(&reply.expect("reply")), offered);
    assert_eq!(world.rows(), 3);
    assert_eq!(world.store.history().len(), 3);
}

#[test]
fn the_ia_pds_follow_the_ia_nas_within_the_bindings_of_one_message() {
    let mut world = pd_world();
    let duid = duid_ll(mac(60));
    let solicit = message(MessageType::Solicit, 1, |b| {
        client_options(b, &duid);
        ia_na(b, 1, None);
        ia_na(b, 2, None);
        for iaid in 1..=8 {
            ia_pd(b, iaid, &[]);
        }
    });
    let (_, reply) = world.exchange(&relay1(&solicit));
    let reply = reply.expect("advertise");
    let got = prefixes(&reply);
    assert_eq!(addresses(&reply).len(), 2);
    assert_eq!(
        got.len(),
        MAX_BINDINGS - 2,
        "the IA_PDs the room left: {got:?}"
    );
    assert_eq!(
        got.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        (1..=6).collect::<Vec<_>>()
    );
}

#[test]
fn an_exclusion_inside_a_prefix_keeps_that_prefix_out_and_one_just_outside_does_not() {
    // Three prefixes: 2001:db8:180:100::/60, 110::/60 and 120::/60. The last address of
    // the first is excluded; so are the address just before the pool and the one just
    // after it, which touch no prefix.
    let mut world = World6::with(|first, _, _| {
        first.pd_pools = vec![pd_pool(
            PD_FIRST,
            "2001:db8:180:12f:ffff:ffff:ffff:ffff",
            60,
        )];
        first.excluded = vec![
            (
                addr("2001:db8:180:0ff:ffff:ffff:ffff:ffff"),
                addr("2001:db8:180:0ff:ffff:ffff:ffff:ffff"),
            ),
            (
                addr("2001:db8:180:10f:ffff:ffff:ffff:ffff"),
                addr("2001:db8:180:10f:ffff:ffff:ffff:ffff"),
            ),
            (addr("2001:db8:180:130::"), addr("2001:db8:180:130::")),
        ];
    });
    let client = duid_ll(mac(61));
    let (_, reply) = world.exchange(&relay1(&pd_message(
        MessageType::Solicit,
        &client,
        1,
        &[p60(PD_FIRST)],
    )));
    let got = prefixes(&reply.expect("advertise"));
    assert_eq!(got.len(), 1);
    assert_ne!(
        got[0].1,
        addr(PD_FIRST),
        "the hinted prefix holds an excluded address"
    );
    let mut given = vec![delegate(&mut world, &client, 1, &[])];
    given.push(delegate(&mut world, &duid_ll(mac(62)), 1, &[]));
    given.sort_unstable();
    assert_eq!(
        given,
        vec![addr("2001:db8:180:110::"), addr("2001:db8:180:120::")],
        "both prefixes the exclusions do not touch, and only those"
    );
    // The pool has no other prefix: the next client gets NoPrefixAvail.
    let (_, reply) = world.exchange(&relay1(&pd_message(
        MessageType::Request,
        &duid_ll(mac(63)),
        1,
        &[],
    )));
    assert_eq!(
        pd_statuses(&reply.expect("reply")),
        vec![Some(status::NO_PREFIX_AVAIL)]
    );
    assert_eq!(world.rows(), 2);
}

#[test]
fn rapid_commit_answers_a_solicit_for_a_prefix_with_a_committed_reply() {
    let mut world = pd_world();
    let duid = duid_ll(mac(64));
    let rapid = message(MessageType::Solicit, 3, |b| {
        client_options(b, &duid);
        b.option(code::RAPID_COMMIT, &[]).expect("rapid");
        ia_pd(b, 4, &[]);
    });
    let (answer, reply) = world.exchange(&relay1(&rapid));
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
    let reply = reply.expect("reply");
    let inner = unwrap(&reply);
    assert!(Message::parse(&inner).expect("parses").rapid_commit());
    let got = prefixes(&reply);
    assert_eq!(got.len(), 1);
    let prefix = got[0].1;
    assert!(in_pool(prefix));
    assert!(delegated(&world, prefix, 60, &duid));
    let row = world.table.get(NIL, prefix).expect("row");
    assert_eq!((row.kind, row.iaid), (Lease6Kind::Pd, 4));
    assert_eq!(world.store.history()[0].kind, LeaseEventKind::Granted);
    // A scope that refuses rapid commit answers with an ADVERTISE and writes nothing.
    let mut strict = World6::with(|first, _, _| {
        first.pd_pools = vec![pd_pool_60()];
        first.v6.rapid_commit = Some(false);
    });
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
fn while_the_store_refuses_a_bound_prefix_is_answered_for_its_time_left_and_new_requests_drop() {
    let mut world = pd_world();
    let duid = duid_ll(mac(65));
    let prefix = delegate(&mut world, &duid, 1, &[]);
    let history = world.store.history().len();
    let before = world.table.get(NIL, prefix).expect("row").clone();
    advance(&mut world, 1_000);
    world.accepting = false;
    let renew = pd_message(MessageType::Renew, &duid, 1, &[(prefix, 60)]);
    let (answer, reply) = world.exchange(&relay1(&renew));
    assert!(
        matches!(answer.action, Action6::Reply { .. }),
        "nothing to commit: {answer:?}"
    );
    let got = prefixes(&reply.expect("reply"));
    assert_eq!(got.len(), 1, "{got:?}");
    let (iaid, answered, len, preferred, valid) = got[0];
    assert_eq!((iaid, answered, len), (1, prefix, 60));
    // 6,000 seconds were granted and 1,000 have gone.
    assert!(valid > 0 && valid <= 5_000, "{valid}");
    assert!(preferred <= valid);
    assert_eq!(world.store.history().len(), history, "nothing is written");
    assert_eq!(world.table.get(NIL, prefix), Some(&before));
    // A new client's SOLICIT and REQUEST are dropped.
    for kind in [MessageType::Solicit, MessageType::Request] {
        let (answer, reply) = world.exchange(&relay1(&pd_message(kind, &duid_ll(mac(66)), 1, &[])));
        assert_eq!(answer.action, Action6::Drop(DropReason::StoreRefused));
        assert!(reply.is_none());
    }
    // So is a RENEW of a prefix the client does not hold.
    let renew = pd_message(MessageType::Renew, &duid_ll(mac(67)), 1, &[(prefix, 60)]);
    let (answer, _) = world.exchange(&relay1(&renew));
    assert_eq!(answer.action, Action6::Drop(DropReason::StoreRefused));
    assert_eq!(world.rows(), 1);
}

#[test]
fn a_delegation_pool_of_a_sibling_scope_of_a_shared_network_is_used() {
    let shared = SharedNetworkId::generate();
    let mut world = World6::with(|first, second, _| {
        first.shared_network = Some(shared);
        second.shared_network = Some(shared);
        second.pd_pools = vec![pd_pool_60()];
    });
    assert_eq!(
        world
            .image
            .v6()
            .scope(world.prefix1)
            .expect("scope 1")
            .pd_pools
            .len(),
        0
    );
    let duid = duid_ll(mac(68));
    // The client is on the first link; the selected scope has no pool of its own.
    let prefix = delegate(&mut world, &duid, 1, &[]);
    assert!(in_pool(prefix), "{prefix}");
    let row = world.table.get(NIL, prefix).expect("row");
    assert_eq!(row.scope, world.prefix2, "the sibling's prefix");
    assert_eq!((row.kind, row.prefix_len), (Lease6Kind::Pd, 60));
    // RENEW through the first link finds the binding in the sibling.
    advance(&mut world, 1_500);
    let renew = pd_message(MessageType::Renew, &duid, 1, &[(prefix, 60)]);
    let (answer, reply) = world.exchange(&relay1(&renew));
    assert!(matches!(answer.action, Action6::CommitThenReply { .. }));
    assert_eq!(prefixes(&reply.expect("reply"))[0].1, prefix);
    assert_eq!(world.store.history()[1].kind, LeaseEventKind::Renewed);
    assert_eq!(world.rows(), 1);
    // While the store refuses, the bound prefix is still answered.
    world.accepting = false;
    let (answer, reply) = world.exchange(&relay1(&renew));
    assert!(matches!(answer.action, Action6::Reply { .. }));
    assert_eq!(prefixes(&reply.expect("reply"))[0].1, prefix);
    world.accepting = true;
    // RELEASE finds it in the sibling too.
    let release = pd_message(MessageType::Release, &duid, 1, &[(prefix, 60)]);
    let (answer, _) = world.exchange(&relay1(&release));
    assert!(matches!(answer.action, Action6::CommitThenReply { .. }));
    assert_eq!(
        world.table.get(NIL, prefix).expect("row").state,
        BindingState::Released
    );
}

#[test]
fn the_pool_options_of_the_delegation_pool_reach_a_reply_for_prefixes_only() {
    let mut pool = pd_pool_60();
    pool.options = vec![OptionValue {
        space: OptionSpace::dhcp6(),
        code: 23,
        data: HexBytes(addr("2001:db8::5353").octets().to_vec()),
    }];
    let mut world = World6::with(|first, _, _| first.pd_pools = vec![pool]);
    let (_, reply) = world.exchange(&relay1(&pd_message(
        MessageType::Solicit,
        &duid_ll(mac(69)),
        1,
        &[],
    )));
    let inner = unwrap(&reply.expect("advertise"));
    let inner = Message::parse(&inner).expect("parses");
    assert_eq!(
        inner.option(code::DNS_SERVERS).expect("walk").expect("23"),
        addr("2001:db8::5353").octets(),
        "the pool's value wins over the scope's"
    );
    // The scope's other options still come.
    assert!(inner.option(code::DOMAIN_LIST).expect("walk").is_some());
}

#[test]
fn a_message_with_a_malformed_ia_pd_is_dropped() {
    let mut world = pd_world();
    let duid = duid_ll(mac(70));
    let bad = message(MessageType::Solicit, 1, |b| {
        client_options(b, &duid);
        // An IA_PD of eight octets: the IAID and T1 only.
        b.option(code::IA_PD, &[0, 0, 0, 1, 0, 0, 0, 0])
            .expect("ia_pd");
    });
    assert_eq!(
        world.exchange(&relay1(&bad)).0.action,
        Action6::Drop(DropReason::Malformed)
    );
    assert_eq!(world.rows(), 0);
}
