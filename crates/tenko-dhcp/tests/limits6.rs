//! The limits per DUID and the DECLINE limit of the DHCPv6 engine: a DUID at its limit gets
//! `NoAddrsAvail` or `NoPrefixAvail` for a new IA while the bindings it holds keep renewing,
//! also from a state above the limit stored before the limit applied; DHCPv6 DECLINEs count
//! in the DHCPv4 limit per client.

mod engine6_world;

use std::{net::Ipv6Addr, sync::Arc, time::Duration};

use engine6_world::{
    SERVER_DUID, World6, addresses, client_options, duid_ll, ia_na, ia_pd, message, pd_pool_60,
    pd_statuses, prefixes, relay1, statuses,
};
use tenko_core::dhcp::{BindingState, Lease6Kind};
use tenko_dhcp::{
    conflict::{ConflictSettings, Conflicts},
    guard::DhcpProfile,
    limits::Limit,
    v4::engine::DropReason,
    v6::{MessageType, code, engine::Action6, lease::Lease6Table as _},
};

const NO_ADDRS_AVAIL: u16 = 2;
const NO_PREFIX_AVAIL: u16 = 6;

fn mac(k: u8) -> [u8; 6] {
    [0x00, 0x00, 0x5e, 0x00, 0x53, k]
}

/// A Rapid Commit SOLICIT of `duid` for one `IA_NA`.
fn rapid(duid: &[u8], iaid: u32) -> Vec<u8> {
    message(MessageType::Solicit, 0x00_1000 + iaid, |b| {
        client_options(b, duid);
        b.option(code::RAPID_COMMIT, &[]).expect("rapid");
        ia_na(b, iaid, None);
    })
}

/// A Rapid Commit SOLICIT of `duid` for one `IA_PD`.
fn rapid_pd(duid: &[u8], iaid: u32) -> Vec<u8> {
    message(MessageType::Solicit, 0x00_2000 + iaid, |b| {
        client_options(b, duid);
        b.option(code::RAPID_COMMIT, &[]).expect("rapid");
        ia_pd(b, iaid, &[]);
    })
}

fn with_server(
    kind: MessageType,
    duid: &[u8],
    body: impl FnOnce(&mut tenko_dhcp::v6::MessageBuilder<'_>),
) -> Vec<u8> {
    message(kind, 0x00_3000, |b| {
        client_options(b, duid);
        b.option(code::SERVERID, &SERVER_DUID).expect("server id");
        body(b);
    })
}

#[test]
fn a_duid_at_its_address_limit_gets_no_new_ia_and_keeps_renewing_from_a_state_above_it() {
    // Under Lab no limit applies: ten IA_NAs of one DUID, the state of an upgrade.
    let mut world = World6::with_trusted_relay(|_, _, _| {});
    let duid = duid_ll(mac(1));
    let mut held = Vec::new();
    for iaid in 1..=10 {
        let (_, reply) = world.exchange(&relay1(&rapid(&duid, iaid)));
        held.push(addresses(&reply.expect("a reply"))[0].1);
    }
    assert_eq!(
        world
            .table
            .duid_bindings(world.prefix1, Lease6Kind::Na, &duid),
        10
    );
    // Hardened: eight per DUID. A new IA gets NoAddrsAvail and nothing is written.
    world.guard.set_profile(DhcpProfile::Hardened);
    let rows = world.rows();
    let (answer, reply) = world.exchange(&relay1(&rapid(&duid, 11)));
    assert!(matches!(answer.action, Action6::Reply { .. }), "{answer:?}");
    let reply = reply.expect("a reply");
    assert_eq!(addresses(&reply), Vec::new());
    let (ias, top) = statuses(&reply);
    assert!(
        ias.contains(&Some(NO_ADDRS_AVAIL)) || top == Some(NO_ADDRS_AVAIL),
        "{ias:?} {top:?}"
    );
    assert_eq!(world.rows(), rows);
    // Every IA it holds renews.
    for (index, addr) in held.iter().enumerate() {
        let iaid = u32::try_from(index).expect("small") + 1;
        let renew = with_server(MessageType::Renew, &duid, |b| ia_na(b, iaid, Some(*addr)));
        let (answer, reply) = world.exchange(&relay1(&renew));
        assert!(
            matches!(answer.action, Action6::CommitThenReply { .. }),
            "{iaid}: {answer:?}"
        );
        assert_eq!(addresses(&reply.expect("a reply"))[0].1, *addr);
    }
    // Another DUID is not concerned.
    let other = duid_ll(mac(2));
    let (_, reply) = world.exchange(&relay1(&rapid(&other, 1)));
    assert_eq!(addresses(&reply.expect("a reply")).len(), 1);
    let report = world.guard.limit_report(Some(&world.image));
    let (refusal, network) = &report.refusals[0];
    assert_eq!(refusal.limit, Limit::AddressesPerDuid);
    assert_eq!((refusal.cap, refusal.held), (8, 10));
    assert_eq!(refusal.client, duid);
    assert_eq!(
        network.map(|net| net.to_string()).as_deref(),
        Some("2001:db8:1::/64")
    );
}

#[test]
fn a_duid_at_its_prefix_limit_gets_no_new_prefix_and_keeps_renewing() {
    let mut world = World6::with_trusted_relay(|first, _, _| first.pd_pools = vec![pd_pool_60()]);
    let duid = duid_ll(mac(3));
    let mut held = Vec::new();
    for iaid in 1..=5 {
        let (_, reply) = world.exchange(&relay1(&rapid_pd(&duid, iaid)));
        let (_, prefix, len, _, _) = prefixes(&reply.expect("a reply"))[0];
        held.push((prefix, len));
    }
    // Hardened: four delegated prefixes per DUID.
    world.guard.set_profile(DhcpProfile::Hardened);
    let (_, reply) = world.exchange(&relay1(&rapid_pd(&duid, 6)));
    let reply = reply.expect("a reply");
    assert_eq!(prefixes(&reply), Vec::new());
    assert_eq!(pd_statuses(&reply), [Some(NO_PREFIX_AVAIL)]);
    for (index, (prefix, len)) in held.iter().enumerate() {
        let iaid = u32::try_from(index).expect("small") + 1;
        let renew = with_server(MessageType::Renew, &duid, |b| {
            ia_pd(b, iaid, &[(*prefix, *len)]);
        });
        let (answer, reply) = world.exchange(&relay1(&renew));
        assert!(
            matches!(answer.action, Action6::CommitThenReply { .. }),
            "{iaid}: {answer:?}"
        );
        assert_eq!(prefixes(&reply.expect("a reply"))[0].1, *prefix);
    }
    let report = world.guard.limit_report(Some(&world.image));
    assert_eq!(report.refusals[0].0.limit, Limit::PrefixesPerDuid);
}

#[test]
fn dhcpv6_declines_count_in_the_dhcpv4_limit_per_client() {
    let mut world = World6::new();
    let conflicts = Arc::new(Conflicts::new(&ConflictSettings {
        decline_limit: 3,
        decline_window: Duration::from_secs(3_600),
        ..ConflictSettings::default()
    }));
    world.guard.share_declines(&conflicts);
    let duid = duid_ll(mac(4));
    let mut held: Vec<Ipv6Addr> = Vec::new();
    for iaid in 1..=5 {
        let (_, reply) = world.exchange(&relay1(&rapid(&duid, iaid)));
        held.push(addresses(&reply.expect("a reply"))[0].1);
    }
    // One DECLINE of all five: three are abandoned, two stay the client's.
    let decline = with_server(MessageType::Decline, &duid, |b| {
        for (index, addr) in held.iter().enumerate() {
            ia_na(b, u32::try_from(index).expect("small") + 1, Some(*addr));
        }
    });
    let (answer, _) = world.exchange(&relay1(&decline));
    assert!(
        matches!(answer.action, Action6::CommitThenReply { .. }),
        "{answer:?}"
    );
    let states: Vec<BindingState> = held
        .iter()
        .map(|addr| {
            world
                .table
                .get(world.image.v6().scopes()[0].vrf, *addr)
                .expect("row")
                .state
        })
        .collect();
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == BindingState::Abandoned)
            .count(),
        3
    );
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == BindingState::Active)
            .count(),
        2
    );
    // A further DECLINE within the hour is dropped and changes nothing.
    let again = with_server(MessageType::Decline, &duid, |b| ia_na(b, 4, Some(held[3])));
    let (answer, _) = world.exchange(&relay1(&again));
    assert_eq!(answer.action, Action6::Drop(DropReason::RateLimited));
}

#[test]
fn the_bindings_a_message_renews_are_counted_once() {
    // Hardened: four prefixes per DUID. A router holds two, and one REQUEST renews both and
    // asks for a third: two held plus one new is within the limit.
    let mut world = World6::with_trusted_relay(|first, _, _| first.pd_pools = vec![pd_pool_60()]);
    world.guard.set_profile(DhcpProfile::Hardened);
    let duid = duid_ll(mac(6));
    let mut held = Vec::new();
    for iaid in 1..=2 {
        let (_, reply) = world.exchange(&relay1(&rapid_pd(&duid, iaid)));
        let (_, prefix, len, _, _) = prefixes(&reply.expect("a reply"))[0];
        held.push((prefix, len));
    }
    let request = with_server(MessageType::Request, &duid, |b| {
        ia_pd(b, 1, &[held[0]]);
        ia_pd(b, 2, &[held[1]]);
        ia_pd(b, 3, &[]);
    });
    let (answer, reply) = world.exchange(&relay1(&request));
    assert!(
        matches!(answer.action, Action6::CommitThenReply { .. }),
        "{answer:?}"
    );
    assert_eq!(prefixes(&reply.expect("a reply")).len(), 3);
}
