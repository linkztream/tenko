//! The no-allocation rule of the DHCPv6 path, as a test: a counting global allocator wraps
//! the system allocator, and parsing a message with its relay chain, the typed options,
//! the engine's answer (scope selection, the client, the reservations and lease lookups,
//! the allocator, the offers, the change and the reply, RELAY-REPL around it) and the
//! hand-off of the change to the lease store must not allocate. The first section proves
//! that the counter sees an allocation.
//!
//! The allocator counts every thread of the process, so the file has one test.

mod engine6_world;

use std::{alloc::System, hint::black_box};

use engine6_world::{
    LINK2, SERVER_DUID, World6, addr, client_options, duid_ll, ia_na, mac, message, relay1,
    relayed, reservation,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_dhcp::{
    store::Ticket,
    v6::{
        Message, MessageType, RelayChain, code, engine::Action6, image::Reservation6Key,
        lease::store::Lease6Store,
    },
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn measure(rounds: usize, mut f: impl FnMut()) -> (usize, usize, usize) {
    f();
    let region = Region::new(GLOBAL);
    for _ in 0..rounds {
        f();
    }
    let stats = region.change();
    (
        stats.allocations,
        stats.reallocations,
        stats.bytes_allocated,
    )
}

fn read_all(bytes: &[u8]) -> usize {
    let Ok(message) = Message::parse(bytes) else {
        return 0;
    };
    let Ok(chain) = RelayChain::parse(message) else {
        return 1;
    };
    let client = chain.client();
    let mut sum = chain.depth() + client.transaction_id() as usize;
    sum += chain.interface_id().map_or(0, <[u8]>::len);
    sum += chain
        .link_address()
        .map_or(0, |link| usize::from(link.segments()[0]));
    sum += client
        .client_id()
        .ok()
        .flatten()
        .map_or(0, |id| id.as_bytes().len());
    sum += client
        .option_request()
        .ok()
        .flatten()
        .map_or(0, |oro| oro.codes().map(usize::from).sum());
    for ia in client.ia_nas().flatten() {
        sum += ia.iaid as usize;
        for address in ia.addresses().flatten() {
            sum += address.valid as usize;
        }
    }
    sum += usize::from(client.rapid_commit());
    sum += client
        .client_fqdn()
        .ok()
        .flatten()
        .map_or(0, |f| usize::from(f.flags()));
    sum
}

#[test]
fn the_dhcpv6_path_allocates_nothing_from_the_parse_to_the_hand_off() {
    // The counter bites.
    let (allocations, _, _) = measure(4, || {
        black_box(vec![0u8; 64]);
    });
    assert!(allocations >= 4, "the counter must see allocations");

    let duid = duid_ll(mac(0x51));
    let mut world = World6::with(|first, _, reservations| {
        reservations.push(reservation(
            first.prefix,
            "2001:db8:1::80",
            Reservation6Key::Duid(duid_ll(mac(0x52))),
        ));
    });
    let solicit = message(MessageType::Solicit, 7, |b| {
        client_options(b, &duid);
        b.option(code::CLIENT_FQDN, b"\x01\x06laptop")
            .expect("fqdn");
        ia_na(b, 1, None);
        ia_na(b, 2, None);
    });
    let chain = relayed(
        &solicit,
        &[
            (
                std::net::Ipv6Addr::UNSPECIFIED,
                addr("fe80::1"),
                Some(b"port-7"),
            ),
            (LINK2, addr("2001:db8:2::2"), None),
        ],
        Some(mac(0x51)),
    );
    let relayed1 = relay1(&solicit);
    let (allocations, reallocations, bytes) = measure(200, || {
        black_box(read_all(black_box(&chain)));
        black_box(read_all(black_box(&relayed1)));
    });
    assert_eq!(
        (allocations, reallocations, bytes),
        (0, 0, 0),
        "parsing allocated"
    );

    let (allocations, reallocations, bytes) = measure(200, || {
        let answer = world.handle(black_box(&chain));
        assert!(matches!(answer.action, Action6::Reply { .. }), "{answer:?}");
        let answer = world.handle(black_box(&relayed1));
        black_box(answer);
    });
    assert_eq!(
        (allocations, reallocations, bytes),
        (0, 0, 0),
        "the ADVERTISE path allocated"
    );

    // REQUEST and its hand-off; the reserved client's SOLICIT.
    let request = message(MessageType::Request, 8, |b| {
        client_options(b, &duid);
        b.option(code::SERVERID, &SERVER_DUID).expect("sid");
        ia_na(b, 1, Some(addr("2001:db8:1::150")));
    });
    let request = relay1(&request);
    let reserved = relay1(&message(MessageType::Solicit, 9, |b| {
        client_options(b, &duid_ll(mac(0x52)));
        ia_na(b, 1, None);
    }));
    let store =
        tenko_dhcp::v6::lease::store::MemLease6Store::with_capacity(tenko_core::NodeId(1), 4_096);
    let mut ticket = 0;
    let (allocations, reallocations, bytes) = measure(200, || {
        let answer = world.handle(black_box(&request));
        assert!(
            matches!(answer.action, Action6::CommitThenReply { .. }),
            "{answer:?}"
        );
        ticket += 1;
        store
            .submit6(&world.scratch.change, Ticket(ticket))
            .expect("submit");
        black_box(world.handle(black_box(&reserved)));
    });
    assert_eq!(
        (allocations, reallocations, bytes),
        (0, 0, 0),
        "the REPLY path or the hand-off allocated"
    );
}
