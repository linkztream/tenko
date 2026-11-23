//! The limits per DUID and the DECLINE limit of the DHCPv6 engine: a DUID at its limit gets
//! `NoAddrsAvail` or `NoPrefixAvail` for a new IA while the bindings it holds keep renewing,
//! also from a state above the limit stored before the limit applied; DHCPv6 DECLINEs count
//! in the DHCPv4 limit per client.
//!
//! The rows per scope (`bindings_per_scope`): a flood of new DUIDs, a flood of REQUEST and
//! DECLINE under new DUIDs and delegated prefixes all stop at it, named in the limit log with
//! the relay they came through; a client that holds a binding renews, rebinds and restarts
//! in a full scope; a returning client gets its address from its identifier whether its old
//! row is still there or deleted; in a shared network a full scope refuses rather than give
//! an address of its sibling; a RENEW or REBIND the full scope will not bind gets
//! `NoAddrsAvail` or `NoPrefixAvail` and still zeroes what the client may no longer use;
//! declined rows of a full scope yield within a round once their host has gone, and their
//! addresses go to no other client until their hold would have ended.

mod engine6_world;

use std::{net::Ipv6Addr, sync::Arc, time::Duration};

use engine6_world::{
    LINK1, LINK2, PD_FIRST, SERVER_DUID, World6, addr, addresses, client_options, duid_ll, ia_na,
    ia_pd, message, pd_pool_60, pd_statuses, prefixes, relay1, relayed, statuses,
};
use tenko_core::{
    NodeId, Principal, Revision, SystemComponent, VrfId,
    dhcp::{BindingState, DhcpLimits, Lease6Kind, SharedNetworkId, tables::LEASES6},
};
use tenko_dhcp::{
    conflict::{ConflictSettings, Conflicts},
    guard::DhcpProfile,
    lease::ExpirySettings,
    limits::{Limit, REFUSED},
    v4::engine::DropReason,
    v6::{
        MessageType, code,
        engine::Action6,
        lease::{
            Lease6Index, Lease6Table as _, SharedLeases6,
            expiry::{Expiry6Service, expired6},
        },
    },
};
use tenko_store::{MemStore, Store, WriteBatch};

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

/// The stored limits with `bindings_per_scope` alone set (Lab: no other limit).
fn ceiling(cap: u32) -> DhcpLimits {
    DhcpLimits {
        bindings_per_scope: Some(cap),
        ..DhcpLimits::default()
    }
}

/// A new client: a DUID-LL of a locally administered MAC address made from `k`.
fn newcomer(k: u16) -> Vec<u8> {
    let [high, low] = k.to_be_bytes();
    vec![0, 3, 0, 1, 0x02, 0x00, 0x5e, 0x10, high, low]
}

/// `inner` through the relay on the first link, which names its port `Gi0/7` (option 18).
fn via_port(inner: &[u8]) -> Vec<u8> {
    relayed(
        inner,
        &[(LINK1, addr("fe80::200:5eff:fe00:5301"), Some(&b"Gi0/7"[..]))],
        None,
    )
}

/// Whether a reply gives no address and says `NoAddrsAvail`.
fn no_address(reply: &[u8]) -> bool {
    let (ias, top) = statuses(reply);
    addresses(reply).is_empty()
        && (ias.contains(&Some(NO_ADDRS_AVAIL)) || top == Some(NO_ADDRS_AVAIL))
}

#[test]
fn a_flood_of_new_duids_stops_at_the_rows_of_its_scope_and_names_them_and_the_relay() {
    let mut world = World6::limited(ceiling(8), |_, _, _| {});
    for k in 0..40 {
        let (_, reply) = world.exchange(&via_port(&rapid(&newcomer(k), 1)));
        let reply = reply.expect("a reply");
        if k < 8 {
            assert_eq!(addresses(&reply).len(), 1, "{k}");
        } else {
            assert!(no_address(&reply), "{k}");
        }
    }
    assert_eq!(world.rows(), 8);
    assert_eq!(world.table.scope_rows(world.prefix1), 8);
    // The other scope is not concerned.
    let other = relayed(
        &rapid(&newcomer(100), 1),
        &[(LINK2, addr("fe80::200:5eff:fe00:5302"), None)],
        None,
    );
    let (_, reply) = world.exchange(&other);
    assert_eq!(addresses(&reply.expect("a reply")).len(), 1);
    // Every refusal is in the log: the limit, the scope, the client and the relay's port.
    let report = world.guard.limit_report(Some(&world.image));
    assert_eq!((report.refusals.len(), report.unlogged), (32, 0));
    for (refusal, network) in &report.refusals {
        assert_eq!(refusal.limit, Limit::BindingsPerScope);
        assert_eq!(
            (refusal.cap, refusal.held, refusal.scope),
            (8, 8, world.prefix1)
        );
        assert_eq!(refusal.relay.as_deref(), Some("2001:db8:1::1 Gi0/7"));
        assert_eq!(
            network.map(|net| net.to_string()).as_deref(),
            Some("2001:db8:1::/64")
        );
    }
    let warning = &report.warnings()[0];
    assert_eq!(warning.code, REFUSED);
    assert!(
        warning
            .detail
            .contains("in 2001:db8:1::/64 by bindings_per_scope through 2001:db8:1::1 Gi0/7"),
        "{warning:?}"
    );
    let named = report.refusals[0].0.client_text();
    assert!(warning.params["clients"].contains(&named), "{warning:?}");
}

#[test]
fn request_then_decline_under_new_duids_stops_at_the_rows_of_its_scope() {
    let mut world = World6::limited(ceiling(8), |_, _, _| {});
    let mut granted = 0;
    for k in 0..40 {
        let duid = newcomer(k);
        let (_, reply) = world.exchange(&relay1(&rapid(&duid, 1)));
        let Some(&(_, address, _, _)) = addresses(&reply.expect("a reply")).first() else {
            continue;
        };
        granted += 1;
        let decline = with_server(MessageType::Decline, &duid, |b| ia_na(b, 1, Some(address)));
        let (answer, _) = world.exchange(&relay1(&decline));
        assert!(
            matches!(answer.action, Action6::CommitThenReply { .. }),
            "{k}: {answer:?}"
        );
    }
    // The declined rows are held for a day and count: no more than the ceiling.
    assert_eq!(granted, 8);
    assert_eq!(world.rows(), 8);
    assert!(
        world
            .table
            .iter()
            .all(|lease| lease.state == BindingState::Abandoned)
    );
}

#[test]
fn delegated_prefixes_count_in_the_same_rows_as_addresses() {
    let mut world = World6::limited(ceiling(6), |first, _, _| {
        first.pd_pools = vec![pd_pool_60()];
    });
    for k in 0..4 {
        let (_, reply) = world.exchange(&relay1(&rapid(&newcomer(k), 1)));
        assert_eq!(addresses(&reply.expect("a reply")).len(), 1, "{k}");
    }
    let mut delegated = 0;
    for k in 4..12 {
        let (_, reply) = world.exchange(&relay1(&rapid_pd(&newcomer(k), 1)));
        let reply = reply.expect("a reply");
        if prefixes(&reply).is_empty() {
            assert_eq!(pd_statuses(&reply), [Some(NO_PREFIX_AVAIL)], "{k}");
        } else {
            delegated += 1;
        }
    }
    assert_eq!(delegated, 2);
    assert_eq!(world.rows(), 6);
    assert_eq!(world.table.scope_rows(world.prefix1), 6);
    // Full with prefixes, the scope gives no new address either.
    let (_, reply) = world.exchange(&relay1(&rapid(&newcomer(20), 1)));
    assert!(no_address(&reply.expect("a reply")));
}

#[test]
fn a_client_that_holds_a_binding_renews_rebinds_and_restarts_in_a_full_scope() {
    let mut world = World6::limited(ceiling(4), |_, _, _| {});
    let duid = duid_ll(mac(1));
    let (_, reply) = world.exchange(&relay1(&rapid(&duid, 1)));
    let held = addresses(&reply.expect("a reply"))[0].1;
    for k in 0..10 {
        world.exchange(&relay1(&rapid(&newcomer(k), 1)));
    }
    assert_eq!(world.rows(), 4);
    let renew = with_server(MessageType::Renew, &duid, |b| ia_na(b, 1, Some(held)));
    let rebind = message(MessageType::Rebind, 0x00_4000, |b| {
        client_options(b, &duid);
        ia_na(b, 1, Some(held));
    });
    // A restart: the client asks again from the start with its stored DUID.
    for (what, request) in [
        ("renew", renew),
        ("rebind", rebind),
        ("restart", rapid(&duid, 1)),
    ] {
        let (answer, reply) = world.exchange(&relay1(&request));
        assert!(
            matches!(answer.action, Action6::CommitThenReply { .. }),
            "{what}: {answer:?}"
        );
        assert_eq!(addresses(&reply.expect("a reply"))[0].1, held, "{what}");
    }
    assert_eq!(world.rows(), 4);
    // A new client is still refused.
    let (_, reply) = world.exchange(&relay1(&rapid(&newcomer(30), 1)));
    assert!(no_address(&reply.expect("a reply")));
}

#[test]
fn a_returning_client_gets_its_address_whether_its_old_row_is_there_or_deleted() {
    let mut world = World6::limited(ceiling(4), |_, _, _| {});
    let vrf = VrfId::from_uuid(uuid::Uuid::nil());
    let duid = duid_ll(mac(2));
    let (_, reply) = world.exchange(&relay1(&rapid(&duid, 1)));
    let first = addresses(&reply.expect("a reply"))[0].1;
    let expire = |world: &mut World6| {
        let row = world.table.get(vrf, first).expect("the row").clone();
        let ended = expired6(&row, NodeId(1), world.now);
        world.table.apply_at(ended, Revision::ZERO);
    };
    // The scope fills up and its binding ends: the ended row is the client's own address,
    // so taking it back adds no row.
    for k in 0..10 {
        world.exchange(&relay1(&rapid(&newcomer(k), 1)));
    }
    expire(&mut world);
    assert_eq!(world.rows(), 4);
    let (_, reply) = world.exchange(&relay1(&rapid(&duid, 1)));
    assert_eq!(addresses(&reply.expect("a reply"))[0].1, first);
    // Ended again and deleted, as expiry deletes a row whose names are gone: the address
    // comes from the client's own identifier, so it is the same one.
    expire(&mut world);
    assert!(world.table.take(vrf, first).is_some());
    assert_eq!(world.rows(), 3);
    let (_, reply) = world.exchange(&relay1(&rapid(&duid, 1)));
    assert_eq!(addresses(&reply.expect("a reply"))[0].1, first);
}

#[test]
fn in_a_shared_network_a_full_scope_refuses_rather_than_spill_to_its_sibling() {
    let shared = SharedNetworkId::generate();
    let mut world = World6::limited(ceiling(4), |first, second, _| {
        first.shared_network = Some(shared);
        second.shared_network = Some(shared);
    });
    for k in 0..10 {
        let (_, reply) = world.exchange(&relay1(&rapid(&newcomer(k), 1)));
        let reply = reply.expect("a reply");
        assert_eq!(addresses(&reply).len(), usize::from(k < 4), "{k}");
    }
    // The rows count per scope: the clients of the first link fill its scope, the sibling
    // keeps none, and the refusals name the full scope.
    assert_eq!(world.table.scope_rows(world.prefix1), 4);
    assert_eq!(world.table.scope_rows(world.prefix2), 0);
    let report = world.guard.limit_report(Some(&world.image));
    assert_eq!(report.refusals.len(), 6);
    assert!(
        report
            .refusals
            .iter()
            .all(|(refusal, _)| refusal.scope == world.prefix1)
    );
}

#[test]
fn a_renew_or_rebind_the_full_scope_will_not_bind_gets_no_addrs_avail() {
    let mut world = World6::limited(ceiling(4), |first, _, _| {
        first.pd_pools = vec![pd_pool_60()];
    });
    for k in 0..4 {
        world.exchange(&relay1(&rapid(&newcomer(k), 1)));
    }
    assert_eq!(world.rows(), 4);
    // A client asks to renew an address and a prefix the server holds no binding of.
    let duid = duid_ll(mac(5));
    let unknown = addr("2001:db8:1::1f0");
    let renew = with_server(MessageType::Renew, &duid, |b| ia_na(b, 1, Some(unknown)));
    let rebind = message(MessageType::Rebind, 0x00_5000, |b| {
        client_options(b, &duid);
        ia_na(b, 1, Some(unknown));
    });
    for (what, request) in [("renew", renew), ("rebind", rebind)] {
        let (_, reply) = world.exchange(&relay1(&request));
        let reply = reply.expect("a reply");
        // No address, not even at lifetimes of zero: the client keeps it until its own
        // lifetimes end.
        assert_eq!(addresses(&reply), Vec::new(), "{what}");
        assert_eq!(statuses(&reply).0, [Some(NO_ADDRS_AVAIL)], "{what}");
    }
    let renew_pd = with_server(MessageType::Renew, &duid, |b| {
        ia_pd(b, 1, &[(addr(PD_FIRST), 60)]);
    });
    let rebind_pd = message(MessageType::Rebind, 0x00_5001, |b| {
        client_options(b, &duid);
        ia_pd(b, 1, &[(addr(PD_FIRST), 60)]);
    });
    for (what, request) in [("renew", renew_pd), ("rebind", rebind_pd)] {
        let (_, reply) = world.exchange(&relay1(&request));
        let reply = reply.expect("a reply");
        assert_eq!(prefixes(&reply), Vec::new(), "{what}");
        assert_eq!(pd_statuses(&reply), [Some(NO_PREFIX_AVAIL)], "{what}");
    }
    assert_eq!(world.rows(), 4);
}

#[tokio::test]
async fn declined_rows_of_a_full_scope_yield_so_a_new_client_gets_an_address_within_a_round() {
    let mut world = World6::limited(ceiling(4), |_, _, _| {});
    for k in 0..4 {
        let duid = newcomer(k);
        let (_, reply) = world.exchange(&relay1(&rapid(&duid, 1)));
        let (_, address, _, _) = addresses(&reply.expect("a reply"))[0];
        let decline = with_server(MessageType::Decline, &duid, |b| ia_na(b, 1, Some(address)));
        world.exchange(&relay1(&decline));
    }
    assert!(
        world
            .table
            .iter()
            .all(|lease| lease.state == BindingState::Abandoned)
    );
    let (_, reply) = world.exchange(&relay1(&rapid(&newcomer(10), 1)));
    assert!(
        no_address(&reply.expect("a reply")),
        "full of declined rows"
    );
    // The host has gone. In the expiry service's round one period after the declines, the
    // declined rows of the full scope yield their day of hold.
    assert_eq!(expiry_round(&mut world, 4).await, 4);
    let (_, reply) = world.exchange(&relay1(&rapid(&newcomer(10), 1)));
    assert_eq!(addresses(&reply.expect("a reply")).len(), 1);
}

/// One deletion pass of the expiry service over the world's rows, a round period after
/// `world.now`, with the ceiling `rows` and the world's offer table; the world then holds
/// the table the pass leaves, at that time. How many rows the pass deleted.
async fn expiry_round(world: &mut World6, rows: u32) -> usize {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), world.now);
    for lease in world.table.iter() {
        batch
            .put_typed(&LEASES6, &(lease.vrf, lease.addr6()), lease)
            .expect("a row");
    }
    let committed = store.propose(batch).await.expect("committed");
    let table = SharedLeases6::new(Lease6Index::from_rows(
        world
            .table
            .iter()
            .cloned()
            .map(|lease| (lease, committed.revision)),
        committed.revision,
    ));
    let settings = ExpirySettings::default();
    let service = Expiry6Service::new(Arc::clone(&store), NodeId(1), settings)
        .with_table(table.clone())
        .with_ceiling(Arc::new(move || rows))
        .with_offers(Arc::clone(&world.offers));
    let round = world.now.checked_add(settings.period).expect("a time");
    let deleted = service.delete_ended(0, round).await.expect("a pass");
    world.table = table.read().clone();
    world.now = round;
    deleted
}

/// A Rapid Commit SOLICIT of `duid` for one `IA_NA` that names `address`.
fn rapid_for(duid: &[u8], address: Ipv6Addr) -> Vec<u8> {
    message(MessageType::Solicit, 0x00_6000, |b| {
        client_options(b, duid);
        b.option(code::RAPID_COMMIT, &[]).expect("rapid");
        ia_na(b, 1, Some(address));
    })
}

#[tokio::test]
async fn a_yielded_declined_address_goes_to_no_other_client_until_its_hold_ends() {
    let mut world = World6::limited(ceiling(4), |_, _, _| {});
    for k in 0..3 {
        world.exchange(&relay1(&rapid(&newcomer(k), 1)));
    }
    let duid = newcomer(3);
    let (_, reply) = world.exchange(&relay1(&rapid(&duid, 1)));
    let declined = addresses(&reply.expect("a reply"))[0].1;
    let decline = with_server(MessageType::Decline, &duid, |b| ia_na(b, 1, Some(declined)));
    world.exchange(&relay1(&decline));
    let hold_ends = world
        .table
        .get(VrfId::from_uuid(uuid::Uuid::nil()), declined)
        .expect("the declined row")
        .ends;
    // The scope is full; its declined row yields.
    assert_eq!(expiry_round(&mut world, 4).await, 1);
    assert_eq!(world.rows(), 3);
    // Another client that names the declined address gets another one.
    let (_, reply) = world.exchange(&relay1(&rapid_for(&newcomer(20), declined)));
    let given = addresses(&reply.expect("a reply"));
    assert_eq!(given.len(), 1);
    assert_ne!(given[0].1, declined);
    // Once its hold would have ended, the address is free again (and a row has gone, so
    // the scope has room).
    let vrf = VrfId::from_uuid(uuid::Uuid::nil());
    assert!(world.table.take(vrf, given[0].1).is_some());
    world.now = hold_ends
        .checked_add(Duration::from_secs(1))
        .expect("a time");
    let (_, reply) = world.exchange(&relay1(&rapid_for(&newcomer(21), declined)));
    assert_eq!(addresses(&reply.expect("a reply"))[0].1, declined);
}

#[test]
fn a_limited_renew_still_zeroes_what_the_client_may_no_longer_use() {
    let mut world = World6::limited(ceiling(4), |first, _, _| {
        first.pd_pools = vec![pd_pool_60()];
    });
    for k in 0..4 {
        world.exchange(&relay1(&rapid(&newcomer(k), 1)));
    }
    // An address and a prefix off the link, in a full scope: lifetimes of zero, and the
    // status for the binding the server will not create.
    let duid = duid_ll(mac(6));
    let off_link = addr("2001:db8:99::1");
    let renew = with_server(MessageType::Renew, &duid, |b| ia_na(b, 1, Some(off_link)));
    let (_, reply) = world.exchange(&relay1(&renew));
    let reply = reply.expect("a reply");
    assert_eq!(addresses(&reply), [(1, off_link, 0, 0)]);
    assert_eq!(statuses(&reply).0, [Some(NO_ADDRS_AVAIL)]);
    let off_pool = addr("2001:db8:99::");
    let renew_pd = with_server(MessageType::Renew, &duid, |b| {
        ia_pd(b, 1, &[(off_pool, 60)]);
    });
    let (_, reply) = world.exchange(&relay1(&renew_pd));
    let reply = reply.expect("a reply");
    assert_eq!(prefixes(&reply), [(1, off_pool, 60, 0, 0)]);
    assert_eq!(pd_statuses(&reply), [Some(NO_PREFIX_AVAIL)]);
    assert_eq!(world.rows(), 4);
}
