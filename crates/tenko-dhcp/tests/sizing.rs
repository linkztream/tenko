//! E32 (M34, OPS-15): the role's fixed tables are sized from the configuration image
//! (`tenko_dhcp::sizing`): the server's pending commits, offer slots and the conflict
//! probe's tables at start and after a new image, the committer's hand-off queue, the
//! floor of an empty image and the configured sizes as caps. `tests/sizing_alloc.rs`
//! measures what the server's start allocates; `tests/role.rs` follows the tables through
//! the role.

mod lease_support;

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};

use ipnet::Ipv4Net;
use lease_support::{NODE, addr, change, from_now};
use tenko_core::{
    PrefixId, RangeId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, DdnsPolicy, LeaseEventKind, LeaseTimes},
};
use tenko_dhcp::{
    image::{ConfigImage, ImageBuilder, PoolImage, ScopeImage},
    lease::{CommitSettings, LeaseIndex, SharedLeases, StoreLeases},
    server::{DhcpServer, Listen, ServerConfig, SocketLayout},
    sizing::{self, FLOOR, Room},
    store::{LeaseStore, MemLeaseStore, SubmitError, Ticket},
    v4::engine::ListenMode,
};
use tenko_store::{MemStore, MemStoreConfig, Store};

/// An image of one scope per `(network, first, last)`.
fn image(revision: u64, pools: &[(&str, &str, &str)]) -> ConfigImage {
    let mut builder = ImageBuilder::new(Revision(revision));
    let times = LeaseTimes::fixed(3_600);
    for (network, first, last) in pools {
        let network: Ipv4Net = network.parse().expect("a network");
        builder.scope(ScopeImage {
            prefix: PrefixId::generate(),
            vrf: VrfId::generate(),
            network,
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

/// The three home scopes of M34: 100 pool addresses each.
fn home(revision: u64) -> ConfigImage {
    image(
        revision,
        &[
            ("192.0.2.0/24", "192.0.2.100", "192.0.2.199"),
            ("198.51.100.0/24", "198.51.100.100", "198.51.100.199"),
            ("203.0.113.0/24", "203.0.113.100", "203.0.113.199"),
        ],
    )
}

/// The same networks with their whole host range in the pools: 762 addresses.
fn full(revision: u64) -> ConfigImage {
    image(
        revision,
        &[
            ("192.0.2.0/24", "192.0.2.1", "192.0.2.254"),
            ("198.51.100.0/24", "198.51.100.1", "198.51.100.254"),
            ("203.0.113.0/24", "203.0.113.1", "203.0.113.254"),
        ],
    )
}

fn config(pending: usize, offers: usize) -> ServerConfig {
    let mut config = ServerConfig {
        listen: vec![Listen {
            address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            mode: ListenMode::Relay,
            interface: None,
        }],
        workers: 1,
        layout: SocketLayout::Shared,
        pending,
        offers,
        ..ServerConfig::default()
    };
    config.conflict.pending = 1_024;
    config.conflict.cache_entries = 65_536;
    config
}

fn start(config: &ServerConfig, image: ConfigImage) -> DhcpServer<std::sync::RwLock<LeaseIndex>> {
    let store: Arc<dyn LeaseStore> = Arc::new(MemLeaseStore::with_capacity(NODE, 16));
    DhcpServer::start(config, image, LeaseIndex::new(), store, None).expect("the server starts")
}

#[test]
fn the_addresses_an_image_can_lease_are_its_pool_addresses() {
    assert_eq!(sizing::leasable(&ConfigImage::default()), 0);
    assert_eq!(sizing::leasable(&home(1)), 300);
    assert_eq!(sizing::leasable(&full(1)), 762);
}

#[test]
fn the_server_sizes_its_tables_from_the_image_and_grows_them_with_a_new_one() {
    let defaults = ServerConfig::default();
    let server = start(&config(defaults.pending, defaults.offers), home(1));
    assert_eq!(
        server.room(),
        Room {
            pending: 300,
            offers: 300,
            probe_pending: 300,
            probe_cache: 300,
        },
        "three scopes of 100 addresses"
    );

    // A larger image grows every table before the workers see it.
    server.set_image(full(2));
    assert_eq!(server.image().revision(), Revision(2));
    assert_eq!(
        server.room(),
        Room {
            pending: 762,
            offers: 762,
            probe_pending: 762,
            probe_cache: 762,
        }
    );

    // A smaller one, and a snapshot install of it, leave them as they are.
    server.set_image(home(3));
    server.swap(ConfigImage::default(), |_| {});
    assert_eq!(server.room().pending, 762, "the tables never shrink");
    server.stop();
}

#[test]
fn an_empty_image_gets_the_floor_and_the_settings_are_caps() {
    let server = start(&config(4_096, 65_536), ConfigImage::default());
    assert_eq!(
        server.room(),
        Room {
            pending: FLOOR,
            offers: FLOOR,
            probe_pending: FLOOR,
            probe_cache: FLOOR,
        },
        "a role that starts before its first scope"
    );
    // The first scopes arrive through a snapshot install.
    server.swap(home(2), |_| {});
    assert_eq!(server.room().pending, 300);
    server.stop();

    // A configured size below the image's count wins.
    let mut capped = config(500, 400);
    capped.conflict.pending = 64;
    capped.conflict.cache_entries = 700;
    let server = start(&capped, full(1));
    assert_eq!(
        server.room(),
        Room {
            pending: 500,
            offers: 400,
            probe_pending: 64,
            probe_cache: 700,
        }
    );
    server.set_image(full(2));
    assert_eq!(server.room().pending, 500, "never past the cap");
    server.stop();
}

#[test]
fn the_committers_queue_grows_and_keeps_what_waits() {
    let store: Arc<dyn Store> = Arc::new(MemStore::new(MemStoreConfig::default()));
    let leases = SharedLeases::new(LeaseIndex::new());
    let settings = CommitSettings {
        queue: 4,
        ..CommitSettings::default()
    };
    // No committer runs: the queue only fills.
    let (lease_store, _committer) = StoreLeases::new(store, leases, NODE, settings);
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let now = Timestamp::now();
    let pending = |host: u8| {
        change(
            LeaseEventKind::Granted,
            vrf,
            scope,
            addr(host),
            u32::from(host),
            BindingState::Active,
            now,
            from_now(3_600),
        )
    };
    for host in 1..=4u8 {
        assert_eq!(
            lease_store.submit(&pending(host), Ticket(u64::from(host))),
            Ok(())
        );
    }
    assert_eq!(
        lease_store.submit(&pending(5), Ticket(5)),
        Err(SubmitError::Full)
    );
    lease_store.grow(8);
    assert_eq!(lease_store.capacity(), 8);
    assert_eq!(lease_store.queued(), 4, "the waiting changes moved");
    for host in 5..=8u8 {
        assert_eq!(
            lease_store.submit(&pending(host), Ticket(u64::from(host))),
            Ok(())
        );
    }
    assert_eq!(
        lease_store.submit(&pending(9), Ticket(9)),
        Err(SubmitError::Full)
    );
    lease_store.grow(2);
    assert_eq!(lease_store.capacity(), 8, "it never shrinks");
}
