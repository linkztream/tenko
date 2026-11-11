//! The limits per client and per scope of the DHCPv4 engine (`dhcp.settings.limits`,
//! `tenko_dhcp::limits`) and the renewal cache: a client over a limit gets no new binding
//! while the bindings it holds keep renewing, also from a stored state above the limit; a
//! scope's offers to new clients follow its rate; an early renewal is answered from the
//! stored lease, for the time it has left and never past the committed end.

mod engine_world;

use std::net::Ipv4Addr;

use engine_world::{Ask, World, at, ip, mac, t0};
use tenko_core::{
    NodeId, Timestamp,
    dhcp::{BindingState, DhcpLimits, LeaseEventKind},
};
use tenko_dhcp::{
    guard::DhcpProfile,
    lease::{LeaseTable, MemLeaseTable, PendingChange},
    limits::Limit,
    v4::{
        Message, MessageType,
        engine::{Action, Answer, DropReason, Scratch},
    },
};

/// The MAC address every option 61 of these tests shares (a boot chain, a bridge, or one
/// device posing as many clients).
const SHARED: u8 = 0x40;

fn limits(leases_per_mac: u32) -> DhcpLimits {
    DhcpLimits {
        leases_per_mac: Some(leases_per_mac),
        renew_cache_percent: Some(0),
        ..DhcpLimits::default()
    }
}

/// Client `n` of the shared MAC: option 61 of type 0 (a text identifier) with `n`.
fn id(n: u8) -> Vec<u8> {
    vec![0, b'c', b'l', b'i', b'e', b'n', b't', b'-', b'a' + n]
}

/// A lease of the shared MAC's client `n` on `addr`, active for an hour from `t0`.
fn shared_lease(world: &mut World, n: u8, addr: Ipv4Addr) {
    let scope = world.scope_of(addr).prefix;
    let change = PendingChange::new(
        LeaseEventKind::Granted,
        world.vrf,
        scope,
        addr,
        1,
        &mac(SHARED),
        Some(&id(n)),
        BindingState::Active,
        t0(),
        at(3_600),
    );
    world.leases.apply(change.to_lease(NodeId(1), None));
}

fn ask(kind: MessageType, n: u8) -> Ask {
    let mut ask = Ask::new(kind, SHARED);
    ask.id = Some(id(n));
    ask
}

fn reply_of<'s>(answer: &Answer, scratch: &'s Scratch) -> Message<'s> {
    let (Action::Reply { len, .. } | Action::CommitThenReply { len, .. }) = answer.action else {
        panic!("a reply, got {:?}", answer.action);
    };
    Message::parse(&scratch.reply[..len]).expect("parse")
}

#[test]
fn a_mac_at_its_limit_gets_no_new_binding_and_keeps_renewing_from_a_stored_state_above_it() {
    // Six bindings stored by the version before, under a limit of four set afterwards.
    let mut world = World::limited(DhcpProfile::Standard, limits(4));
    for n in 0..6u8 {
        shared_lease(&mut world, n, Ipv4Addr::new(192, 0, 2, 150 + n));
    }
    assert_eq!(
        world
            .leases
            .mac_bindings(world.scope_of(ip("192.0.2.150")).prefix, mac(SHARED)),
        6
    );
    let mut scratch = Scratch::new();
    // A seventh client identifier of the MAC: no offer, no binding.
    let discover = world.run(&ask(MessageType::Discover, 6).bytes(), at(60), &mut scratch);
    assert_eq!(discover.action, Action::Drop(DropReason::Limited));
    let mut request = ask(MessageType::Request, 6);
    request.requested = Some(ip("192.0.2.170"));
    request.server_id = Some(engine_world::SERVER);
    let selecting = world.run(&request.bytes(), at(60), &mut scratch);
    assert_eq!(selecting.action, Action::Drop(DropReason::Limited));
    // Every binding it holds renews (a renewal through the relay, REBINDING).
    for n in 0..6u8 {
        let mut renew = ask(MessageType::Request, n);
        renew.ciaddr = Some(Ipv4Addr::new(192, 0, 2, 150 + n));
        let answer = world.run(&renew.bytes(), at(1_800), &mut scratch);
        assert!(
            matches!(
                answer.action,
                Action::CommitThenReply {
                    kind: MessageType::Ack,
                    ..
                }
            ),
            "{n}: {answer:?}"
        );
    }
    // The refusal is reported with the MAC, the scope, the limit and what it held.
    let report = world.guard.limit_report(Some(&world.image));
    let (refusal, network) = &report.refusals[0];
    assert_eq!(refusal.limit, Limit::LeasesPerMac);
    assert_eq!(refusal.client_text(), "00:00:5e:00:53:40");
    assert_eq!((refusal.cap, refusal.held), (4, 6));
    assert_eq!(
        network.map(|net| net.to_string()).as_deref(),
        Some("192.0.2.0/24")
    );
    assert!(report.warnings()[0].detail.contains("leases_per_mac"));
    // A limit of zero turns it off, and the Lab profile sets none.
    let mut off = World::limited(DhcpProfile::Standard, limits(0));
    let mut lab = World::limited(
        DhcpProfile::Lab,
        DhcpLimits {
            renew_cache_percent: Some(0),
            ..DhcpLimits::default()
        },
    );
    for world in [&mut off, &mut lab] {
        for n in 0..6u8 {
            shared_lease(world, n, Ipv4Addr::new(192, 0, 2, 150 + n));
        }
        let answer = world.run(&ask(MessageType::Discover, 6).bytes(), at(60), &mut scratch);
        assert!(matches!(answer.action, Action::Reply { .. }), "{answer:?}");
    }
}

#[test]
fn a_boot_chain_and_a_dual_boot_machine_stay_below_the_default_limits() {
    // Firmware, loader, installer, installed system and a second system: five identifiers
    // of one MAC; Hardened allows eight, Home and Standard sixteen.
    for profile in [
        DhcpProfile::Home,
        DhcpProfile::Standard,
        DhcpProfile::Hardened,
    ] {
        let mut world = World::limited(
            profile,
            DhcpLimits {
                renew_cache_percent: Some(0),
                ..DhcpLimits::default()
            },
        );
        for n in 0..4u8 {
            shared_lease(&mut world, n, Ipv4Addr::new(192, 0, 2, 150 + n));
        }
        let mut scratch = Scratch::new();
        let answer = world.run(&ask(MessageType::Discover, 4).bytes(), at(60), &mut scratch);
        assert!(
            matches!(answer.action, Action::Reply { .. }),
            "{profile:?}: {answer:?}"
        );
    }
}

#[test]
fn a_scope_offers_to_new_clients_at_its_rate_and_clients_with_a_lease_are_not_counted() {
    let world = World::limited(
        DhcpProfile::Standard,
        DhcpLimits {
            offers_per_second: Some(1),
            renew_cache_percent: Some(0),
            ..DhcpLimits::default()
        },
    );
    let mut scratch = Scratch::new();
    // A burst of ten seconds' worth: ten new clients, then the bucket is empty.
    let offered = (0x70..0x80u8)
        .filter(|client| {
            let answer = world.run(
                &Ask::new(MessageType::Discover, *client).bytes(),
                at(60),
                &mut scratch,
            );
            matches!(answer.action, Action::Reply { .. })
        })
        .count();
    assert_eq!(offered, 10);
    // Client 0x10 holds 192.0.2.110: it is no new client and is served.
    let known = world.run(
        &Ask::new(MessageType::Discover, 0x10).bytes(),
        at(60),
        &mut scratch,
    );
    assert_eq!(reply_of(&known, &scratch).yiaddr(), ip("192.0.2.110"));
    let report = world.guard.limit_report(Some(&world.image));
    let (refusal, _) = &report.refusals[0];
    assert_eq!(refusal.limit, Limit::OffersPerSecond);
    assert_eq!(refusal.count, 6);
    assert!(report.warnings()[0].detail.contains("not for its pool"));
}

#[test]
fn a_reserved_client_is_never_limited() {
    let world = World::limited(
        DhcpProfile::Standard,
        DhcpLimits {
            offers_per_second: Some(1),
            leases_per_mac: Some(1),
            renew_cache_percent: Some(0),
            ..DhcpLimits::default()
        },
    );
    let mut scratch = Scratch::new();
    for client in 0x70..0x7bu8 {
        world.run(
            &Ask::new(MessageType::Discover, client).bytes(),
            at(60),
            &mut scratch,
        );
    }
    // Client 0x20 has the reservation 192.0.2.20.
    let reserved = world.run(
        &Ask::new(MessageType::Discover, 0x20).bytes(),
        at(60),
        &mut scratch,
    );
    assert_eq!(reply_of(&reserved, &scratch).yiaddr(), ip("192.0.2.20"));
}

/// A renewal of client 0x10's lease of 192.0.2.110 (granted at `t0` for an hour) at `now`.
fn renew(world: &World, now: Timestamp, scratch: &mut Scratch) -> Answer {
    let mut renew = Ask::new(MessageType::Request, 0x10);
    renew.giaddr = None;
    renew.ciaddr = Some(ip("192.0.2.110"));
    world.run(&renew.bytes(), now, scratch)
}

#[test]
fn an_early_renewal_is_answered_from_the_stored_lease_and_never_past_its_end() {
    let mut world = World::limited(
        DhcpProfile::Standard,
        DhcpLimits {
            renew_cache_percent: Some(25),
            ..DhcpLimits::default()
        },
    );
    let mut scratch = Scratch::new();
    let cached_before = tenko_dhcp::limits::RENEWALS_CACHED.get();
    // A minute into an hour's lease: an ACK for the 59 minutes it has left, nothing written.
    let early = renew(&world, at(60), &mut scratch);
    let Action::Reply {
        kind: MessageType::Ack,
        ..
    } = early.action
    else {
        panic!("an ACK without a commit, got {:?}", early.action);
    };
    let ack = reply_of(&early, &scratch);
    assert_eq!(ack.yiaddr(), ip("192.0.2.110"));
    let left = ack.lease_time().expect("51").expect("a lease time");
    assert_eq!(left, 3_540);
    // The promise: the answer ends where the committed lease ends.
    let lease = world
        .leases
        .lease(world.vrf, ip("192.0.2.110"))
        .expect("row");
    assert_eq!(at(60 + u64::from(left)), lease.ends);
    assert!(tenko_dhcp::limits::RENEWALS_CACHED.get() > cached_before);
    // A table rebuilt from the stored row alone, after a restart or on a failover peer,
    // answers the same.
    world.leases = MemLeaseTable::from_rows([lease.clone()]);
    let again = renew(&world, at(60), &mut scratch);
    assert_eq!(
        reply_of(&again, &scratch).lease_time().expect("51"),
        Some(3_540)
    );
    // Past a quarter of the lease the renewal commits as before.
    let late = renew(&world, at(1_000), &mut scratch);
    assert!(
        matches!(
            late.action,
            Action::CommitThenReply {
                kind: MessageType::Ack,
                ..
            }
        ),
        "{late:?}"
    );
    // With the cache off every renewal commits.
    let off = World::limited(
        DhcpProfile::Standard,
        DhcpLimits {
            renew_cache_percent: Some(0),
            ..DhcpLimits::default()
        },
    );
    assert!(matches!(
        renew(&off, at(60), &mut scratch).action,
        Action::CommitThenReply { .. }
    ));
}

#[test]
fn a_renewal_the_server_would_grant_shorter_commits() {
    // A lease stored with 100,000 s left (a longer lease time before a policy change): a
    // renewal a minute in that asks for an hour gets the hour committed, not the stored
    // time from the cache.
    let mut world = World::limited(
        DhcpProfile::Standard,
        DhcpLimits {
            renew_cache_percent: Some(25),
            ..DhcpLimits::default()
        },
    );
    world.lease(0x11, true, ip("192.0.2.111"), BindingState::Active, 100_000);
    let mut scratch = Scratch::new();
    let mut renew = Ask::new(MessageType::Request, 0x11);
    renew.giaddr = None;
    renew.ciaddr = Some(ip("192.0.2.111"));
    renew.lease_secs = Some(3_600);
    let answer = world.run(&renew.bytes(), at(60), &mut scratch);
    assert!(
        matches!(answer.action, Action::CommitThenReply { .. }),
        "{answer:?}"
    );
    assert_eq!(
        reply_of(&answer, &scratch).lease_time().expect("51"),
        Some(3_600)
    );
}

#[test]
fn a_request_without_an_offer_counts_in_the_offer_rate_and_one_after_its_offer_does_not() {
    let world = World::limited(
        DhcpProfile::Standard,
        DhcpLimits {
            offers_per_second: Some(1),
            renew_cache_percent: Some(0),
            ..DhcpLimits::default()
        },
    );
    let mut scratch = Scratch::new();
    // Nine DISCOVERs take nine of the ten tokens; their REQUESTs take none.
    for client in 0x70..0x79u8 {
        let offer = world.run(
            &Ask::new(MessageType::Discover, client).bytes(),
            at(60),
            &mut scratch,
        );
        let offered = reply_of(&offer, &scratch).yiaddr();
        let mut request = Ask::new(MessageType::Request, client);
        request.requested = Some(offered);
        request.server_id = Some(engine_world::SERVER);
        let ack = world.run(&request.bytes(), at(60), &mut scratch);
        assert!(
            matches!(ack.action, Action::CommitThenReply { .. }),
            "{client}: {ack:?}"
        );
    }
    // Two REQUESTs of new clients that skipped the DISCOVER: the last token, then none.
    let mut first = Ask::new(MessageType::Request, 0x7a);
    first.requested = Some(ip("192.0.2.180"));
    first.server_id = Some(engine_world::SERVER);
    assert!(matches!(
        world.run(&first.bytes(), at(60), &mut scratch).action,
        Action::CommitThenReply { .. }
    ));
    let mut second = Ask::new(MessageType::Request, 0x7b);
    second.requested = Some(ip("192.0.2.181"));
    second.server_id = Some(engine_world::SERVER);
    assert_eq!(
        world.run(&second.bytes(), at(60), &mut scratch).action,
        Action::Drop(DropReason::Limited)
    );
}

#[test]
fn a_client_releases_at_most_ten_times_an_hour() {
    let mut world = World::limited(
        DhcpProfile::Standard,
        DhcpLimits {
            renew_cache_percent: Some(0),
            ..DhcpLimits::default()
        },
    );
    let mut scratch = Scratch::new();
    for n in 0..=tenko_dhcp::guard::RELEASES_PER_HOUR {
        world.lease(0x12, true, ip("192.0.2.112"), BindingState::Active, 3_600);
        let mut release = Ask::new(MessageType::Release, 0x12);
        release.giaddr = None;
        release.ciaddr = Some(ip("192.0.2.112"));
        let answer = world.run(&release.bytes(), at(60), &mut scratch);
        if n < tenko_dhcp::guard::RELEASES_PER_HOUR {
            assert_eq!(answer.action, Action::Commit, "{n}");
        } else {
            assert_eq!(answer.action, Action::Drop(DropReason::RateLimited));
        }
    }
}
