//! E32 (M34, OPS-15): what the `dhcp` role's fixed tables hold on the heap for the three
//! home scopes of M34 (100 pool addresses each): the server's pending commits, offer slots
//! and conflict tables, and the committer's hand-off queue, sized from the image
//! (`tenko_dhcp::sizing`). Before the sizing they took about 27.5 MiB resident whatever the
//! configuration (`bench/phase3-dhcp/results/2026-10-26-e32-rss-leases-metrics.md`).
//!
//! The counting allocator counts every thread of the process, so the file has one test.

mod lease_support;

use std::{
    alloc::System,
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};

use lease_support::NODE;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_core::{
    PrefixId, RangeId, Revision, VrfId,
    dhcp::{DdnsPolicy, LeaseTimes},
};
use tenko_dhcp::{
    image::{ConfigImage, ImageBuilder, PoolImage, ScopeImage},
    lease::{CommitSettings, LeaseIndex, SharedLeases, StoreLeases},
    server::{DhcpServer, Listen, ServerConfig, SocketLayout},
    sizing,
    store::{LeaseStore, MemLeaseStore},
    v4::engine::ListenMode,
};
use tenko_store::{MemStore, MemStoreConfig, Store};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn home() -> ConfigImage {
    let mut builder = ImageBuilder::new(Revision(1));
    let times = LeaseTimes::fixed(3_600);
    for (network, first, last) in [
        ("192.0.2.0/24", "192.0.2.100", "192.0.2.199"),
        ("198.51.100.0/24", "198.51.100.100", "198.51.100.199"),
        ("203.0.113.0/24", "203.0.113.100", "203.0.113.199"),
    ] {
        builder.scope(ScopeImage {
            prefix: PrefixId::generate(),
            vrf: VrfId::generate(),
            network: network.parse().expect("a network"),
            authoritative: true,
            restricted: false,
            server_id: None,
            lease: times,
            shared_network: None,
            pools: vec![PoolImage {
                range: RangeId::generate(),
                first: first.parse().expect("an address"),
                last: last.parse().expect("an address"),
                lease: times,
                classes: Vec::new(),
                options: Vec::new(),
            }],
            excluded: Vec::new(),
            options: Vec::new(),
            classes: Vec::new(),
            ddns: DdnsPolicy::default(),
        });
    }
    builder.build()
}

/// The bytes held on the heap after `f`, less those released.
fn held<T>(f: impl FnOnce() -> T) -> (T, i64) {
    let region = Region::new(GLOBAL);
    let value = f();
    let stats = region.change();
    let held = i64::try_from(stats.bytes_allocated).unwrap_or(i64::MAX)
        + i64::try_from(stats.bytes_reallocated).unwrap_or(0)
        - i64::try_from(stats.bytes_deallocated).unwrap_or(i64::MAX);
    (value, held)
}

#[test]
fn e32_ops_15_the_fixed_tables_of_the_home_scopes_hold_below_4_mib() {
    let image = home();
    let leasable = sizing::leasable(&image);
    assert_eq!(leasable, 300);
    let defaults = ServerConfig::default();
    let config = ServerConfig {
        listen: vec![Listen {
            address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            mode: ListenMode::Relay,
            interface: None,
        }],
        workers: 8,
        layout: SocketLayout::Shared,
        ..defaults
    };
    let commit = CommitSettings {
        queue: sizing::room(leasable, CommitSettings::default().queue),
        ..CommitSettings::default()
    };
    let store: Arc<dyn Store> = Arc::new(MemStore::new(MemStoreConfig::default()));
    let lease_store: Arc<dyn LeaseStore> = Arc::new(MemLeaseStore::with_capacity(NODE, 16));

    let ((server, committer), bytes) = held(|| {
        let server = DhcpServer::start(&config, image, LeaseIndex::new(), lease_store, None)
            .expect("the server starts");
        let committer = StoreLeases::new(store, SharedLeases::default(), NODE, commit);
        (server, committer)
    });
    let mib = f64::from(i32::try_from(bytes).unwrap_or(i32::MAX)) / 1_048_576.0;
    println!(
        "FIXED-TABLES leasable={leasable} room={:?} heap_mib={mib:.2}",
        server.room()
    );
    assert!(
        bytes < 4 * 1_048_576,
        "the fixed tables of three scopes of 100 addresses hold {mib:.2} MiB"
    );
    drop(committer);
    server.stop();
}
