//! The no-allocation rule for the lease path's part of the DORA path (WP7.2): the hand-off
//! of the production lease store (`StoreLeases::submit`), the lookups of the production
//! table through its shared handle, the offer hold and the refusal gate allocate nothing.
//! The counting allocator wraps the system allocator as in `tests/alloc.rs`; the first
//! section proves that it sees an allocation. The allocator counts every thread of the
//! process, so the file has one test and no runtime.

mod lease_support;

use std::{alloc::System, hint::black_box, sync::Arc, time::Duration};

use lease_support::{NODE, addr, change, from_now, identity_of};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_core::{
    PrefixId, Timestamp, VrfId,
    dhcp::{BindingState, LeaseEventKind},
};
use tenko_dhcp::{
    allocator::OfferHold,
    lease::{CommitSettings, LeaseIndex, LeaseTable, OfferTable, SharedLeases, StoreLeases},
    store::{LeaseStore, Ticket},
};
use tenko_store::{MemStore, MemStoreConfig, Store};

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

#[test]
fn the_lease_path_does_not_allocate() {
    // The counter sees an allocation.
    let mut sink = Vec::new();
    let seen = measure(4, || {
        sink.push(black_box(vec![1u8; 64]));
    });
    assert!(seen.0 > 0, "the counting allocator counts");

    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let now = Timestamp::now();
    let rounds = 200;

    // The hand-off: a queue with room, no committer running.
    let store: Arc<dyn Store> = Arc::new(MemStore::new(MemStoreConfig::default()));
    let leases = SharedLeases::new(LeaseIndex::new());
    let settings = CommitSettings {
        queue: rounds + 8,
        ..CommitSettings::default()
    };
    let (leases_store, committer) = StoreLeases::new(store, leases.clone(), NODE, settings);
    let pending = change(
        LeaseEventKind::Granted,
        vrf,
        scope,
        addr(10),
        1,
        BindingState::Active,
        now,
        from_now(3_600),
    );
    let mut ticket = 0;
    let handed = measure(rounds, || {
        ticket += 1;
        black_box(leases_store.submit(black_box(&pending), Ticket(ticket))).expect("room");
        black_box(leases_store.accepting());
    });
    assert_eq!(handed, (0, 0, 0), "StoreLeases::submit");
    drop(committer);

    // The table's lookups through the shared handle.
    let mut table = LeaseIndex::with_capacity(1_024);
    for client in 0..512u32 {
        let lease = change(
            LeaseEventKind::Granted,
            vrf,
            scope,
            std::net::Ipv4Addr::from(0xC000_0200 + client),
            client,
            BindingState::Active,
            now,
            from_now(3_600),
        )
        .to_lease(NODE, None);
        table.apply(lease);
    }
    leases.install(table);
    let identities: Vec<Vec<u8>> = (0..512u32).map(identity_of).collect();
    let mut found = 0usize;
    let looked = measure(rounds, || {
        let table = leases.read();
        for (client, identity) in identities.iter().enumerate().take(64) {
            let at = std::net::Ipv4Addr::from(0xC000_0200 + u32::try_from(client).expect("small"));
            found += usize::from(table.get(vrf, at).is_some());
            found += usize::from(table.by_client(scope, black_box(identity)).is_some());
        }
    });
    assert_eq!(looked, (0, 0, 0), "the table's lookups");
    assert!(found > 0);

    // The offer hold, at its capacity, with offers coming and going.
    let hold = OfferTable::new(Duration::from_secs(10), 64);
    let mut i = 0u32;
    let offered = measure(rounds * 4, || {
        i += 1;
        let at = std::net::Ipv4Addr::from(0xC000_0200 + (i % 64));
        let identity = &identities[(i % 512) as usize];
        black_box(hold.held_for_other(scope, at, identity, now));
        black_box(hold.hold(scope, at, identity, now));
        if i.is_multiple_of(3) {
            hold.release(scope, at);
        }
    });
    assert_eq!(offered, (0, 0, 0), "the offer hold");

    // The refusal gate's checks and verdicts.
    let gate = leases_store.gate();
    gate.refused("test");
    let renewal = {
        let mut renewal = pending.clone();
        renewal.addr = std::net::Ipv4Addr::from(0xC000_0200);
        renewal.kind = LeaseEventKind::Renewed;
        renewal
    };
    let decided = measure(rounds, || {
        black_box(gate.accepting());
        let table = leases.read();
        black_box(gate.decide(&*table, black_box(&renewal), now));
        black_box(gate.decide(&*table, black_box(&pending), now));
    });
    assert_eq!(decided, (0, 0, 0), "the refusal gate");
    gate.committed();
}
