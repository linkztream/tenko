//! The DORA path up to the commit hand-off, for the counting-allocator test of
//! `tests/alloc.rs`: the engine of WP7.3 over the contracts of the crate (it replaces the
//! skeleton of WP7.0), the image it reads, and the measured section with its deliberate
//! failure.

use std::{
    alloc::System,
    hint::black_box,
    net::{Ipv4Addr, SocketAddrV4},
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

use ipnet::Ipv4Net;
use stats_alloc::{Region, StatsAlloc};
use tenko_core::{
    NodeId, PrefixId, RangeId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, DdnsPolicy, LeaseEventKind, LeaseTimes, OptionValue},
};
use tenko_dhcp::{
    allocator::SingleNode,
    image::{ConfigImage, ImageBuilder, PoolImage, ScopeImage},
    lease::{LeaseTable, MemLeaseTable, PendingChange},
    store::{Completion, LeaseStore, MemLeaseStore, SubmitError, Ticket},
    v4::{
        Message,
        engine::{
            self, Action, Context, EngineSettings, HashedAllocator, ListenMode, OfferTable,
            Received, Scratch,
        },
    },
};

/// What the path reads: the image, the lease table, the store, the clock.
pub struct Path<'a> {
    /// The configuration image.
    pub image: &'a ConfigImage,
    /// The lease table.
    pub leases: &'a MemLeaseTable,
    /// The offers held.
    pub offers: &'a OfferTable,
    /// The lease store.
    pub store: &'a dyn LeaseStore,
    /// Now.
    pub now: Timestamp,
    /// The address of the interface a request without `giaddr` arrived on.
    pub interface: Ipv4Addr,
}

// WP7.3: the DORA path is the engine (`tenko_dhcp::v4::engine::handle`) and the hand-off of
// its lease change to the store, as a worker of `tenko_dhcp::server` runs them.
/// The DORA path up to the commit hand-off: the engine answers, and a lease change goes
/// to the store. Returns the reply's length, 0 when nothing is sent.
pub fn dora(path: &Path<'_>, bytes: &[u8], ticket: u64, scratch: &mut Scratch) -> usize {
    let settings = EngineSettings::default();
    let ctx = Context {
        image: path.image,
        leases: path.leases,
        offers: path.offers,
        ownership: &SingleNode,
        allocator: &HashedAllocator,
        settings: &settings,
        accepting: path.store.accepting(),
        now: path.now,
    };
    let received = Received {
        bytes,
        source: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 67),
        local: path.interface,
        mode: ListenMode::Relay,
    };
    match engine::handle(&ctx, &received, scratch).action {
        Action::Reply { len, .. } => len,
        Action::CommitThenReply { len, .. } => {
            if path.store.submit(&scratch.change, Ticket(ticket)).is_err() {
                return 0;
            }
            len
        }
        Action::Commit => {
            let _ = path.store.submit(&scratch.change, Ticket(ticket));
            0
        }
        Action::Drop(_) | Action::Ignore(_) => 0,
    }
}

fn net(addr: Ipv4Addr) -> Ipv4Net {
    Ipv4Net::new(addr, 24).expect("a /24").trunc()
}

/// An image with one /24 scope around each address in `links`: a pool of .100 to .199
/// with .100 to .104 excluded, and the mask, router and DNS server options.
pub fn image(links: &[Ipv4Addr]) -> ConfigImage {
    let mut builder = ImageBuilder::new(Revision::ZERO);
    let mut seen: Vec<Ipv4Net> = Vec::new();
    for link in links {
        let network = net(*link);
        if seen.contains(&network) {
            continue;
        }
        seen.push(network);
        let [a, b, c, _] = network.network().octets();
        builder.scope(ScopeImage {
            prefix: PrefixId::generate(),
            vrf: VrfId::generate(),
            network,
            authoritative: true,
            restricted: false,
            server_id: None,
            lease: LeaseTimes::default(),
            shared_network: None,
            pools: vec![PoolImage {
                range: RangeId::generate(),
                first: Ipv4Addr::new(a, b, c, 100),
                last: Ipv4Addr::new(a, b, c, 199),
                lease: LeaseTimes::default(),
                classes: Vec::new(),
                options: Vec::new(),
            }],
            excluded: vec![(Ipv4Addr::new(a, b, c, 100), Ipv4Addr::new(a, b, c, 104))],
            options: vec![
                OptionValue::v4(1, vec![255, 255, 255, 0]),
                OptionValue::v4(3, vec![a, b, c, 1]),
                OptionValue::v4(6, vec![192, 0, 2, 53, 198, 51, 100, 53]),
            ],
            classes: Vec::new(),
            ddns: DdnsPolicy::default(),
        });
    }
    builder.build()
}

/// A store whose hand-off copies the change onto the heap: the deliberate allocation.
struct AllocatingStore(MemLeaseStore);

impl LeaseStore for AllocatingStore {
    fn submit(&self, change: &PendingChange, ticket: Ticket) -> Result<(), SubmitError> {
        let boxed = black_box(Box::new(change.clone()));
        self.0.submit(&boxed, ticket)
    }
    fn completions(&self, out: &mut Vec<Completion>) {
        self.0.completions(out);
    }
    fn accepting(&self) -> bool {
        self.0.accepting()
    }
}

/// Runs `f` once to warm up, then `rounds` times, and panics when the measured rounds
/// allocated.
fn assert_no_alloc(
    global: &'static StatsAlloc<System>,
    label: &str,
    rounds: usize,
    mut f: impl FnMut(),
) {
    f();
    let region = Region::new(global);
    for _ in 0..rounds {
        f();
    }
    let stats = region.change();
    assert_eq!(
        (
            stats.allocations,
            stats.reallocations,
            stats.bytes_allocated
        ),
        (0, 0, 0),
        "{label}"
    );
}

/// The measured section: the fixture requests through the path, the commits checked, and
/// the deliberate allocation caught.
pub fn section(requests: &[Vec<u8>], global: &'static StatsAlloc<System>) {
    // WP7.3: the listener's address is the server identifier the corpus requests name.
    let interface = Ipv4Addr::new(198, 51, 100, 10);
    let mut links = vec![interface];
    for bytes in requests {
        if let Ok(message) = Message::parse(bytes) {
            if !message.giaddr().is_unspecified() {
                links.push(message.giaddr());
            }
            if let Ok(Some(info)) = message.relay_agent_info()
                && let Some(link) = info.link_selection()
            {
                links.push(link);
            }
        }
    }
    let image = image(&links);
    // Another client's lease in every pool, so the allocator walks past it.
    let mut leases = MemLeaseTable::default();
    let now: Timestamp = "2026-10-22T12:00:00Z".parse().expect("time");
    let ends = now.checked_add(Duration::from_secs(3_600)).expect("a time");
    for scope in image.scopes() {
        let taken = Ipv4Addr::from(u32::from(scope.pools[0].first) + 5);
        let change = PendingChange::new(
            LeaseEventKind::Granted,
            scope.vrf,
            scope.prefix,
            taken,
            1,
            &[0x00, 0x00, 0x5e, 0x00, 0x53, 0xee],
            None,
            BindingState::Active,
            now,
            ends,
        );
        leases.apply(change.to_lease(NodeId(1), None));
    }
    let rounds = 50;
    let store = MemLeaseStore::with_capacity(NodeId(1), requests.len() * (rounds + 1));
    let offers = OfferTable::with_capacity(1_024);
    let path = Path {
        image: &image,
        leases: &leases,
        offers: &offers,
        store: &store,
        now,
        interface,
    };
    let mut scratch = Scratch::new();
    let mut answered = 0;
    let mut ticket = 0;
    assert_no_alloc(global, "the DORA path up to the hand-off", rounds, || {
        for bytes in requests {
            ticket += 1;
            let len = dora(&path, black_box(bytes), ticket, &mut scratch);
            answered += usize::from(len > 0);
            black_box(&scratch.reply[..len]);
        }
    });
    assert!(answered > 0, "the engine answers the fixture requests");

    // The hand-off reached the store: the committed leases lie in the pools, outside the
    // exclusions and the other client's address.
    assert!(store.commit() > 0);
    let committed = store.leases();
    assert!(!committed.is_empty());
    for lease in committed.values() {
        let scope = image.scope(lease.scope).expect("a scope");
        assert!(scope.is_dynamic(lease.addr), "{}", lease.addr);
        assert_ne!(
            lease.addr,
            Ipv4Addr::from(u32::from(scope.pools[0].first) + 5)
        );
    }
    let mut done = Vec::new();
    store.completions(&mut done);
    assert!(!done.is_empty() && done.iter().all(|completion| completion.outcome.is_ok()));

    // The guard bites: the same path with an allocating hand-off fails the section.
    let allocating = AllocatingStore(MemLeaseStore::with_capacity(NodeId(1), 1_000));
    let path = Path {
        store: &allocating,
        ..path
    };
    let failed = catch_unwind(AssertUnwindSafe(|| {
        assert_no_alloc(global, "a deliberate allocation", 5, || {
            for bytes in requests {
                black_box(dora(&path, black_box(bytes), 0, &mut scratch));
            }
        });
    }));
    assert!(
        failed.is_err(),
        "an allocation in the hand-off must fail the section"
    );
}
