//! The DORA path up to the commit hand-off (WP7.0), for the counting-allocator test of
//! `tests/alloc.rs`: a skeleton of the engine over the contracts of the crate, the image it
//! reads, and the measured section with its deliberate failure.

use std::{
    alloc::System,
    hint::black_box,
    net::Ipv4Addr,
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

use ipnet::Ipv4Net;
use stats_alloc::{Region, StatsAlloc};
use tenko_core::{
    NodeId, PrefixId, RangeId, Revision, Timestamp, VrfId,
    dhcp::{
        BindingState, DdnsPolicy, FilterVerdict, LeaseEventKind, LeaseTimes, OptionValue,
        lease::MAX_IDENTITY, write_identity,
    },
};
use tenko_dhcp::{
    allocator::{Allocator, NoOffers, ReferenceAllocator, Request, SingleNode, grant_time},
    image::{ConfigImage, ImageBuilder, PoolImage, ScopeImage},
    lease::{LeaseTable, MemLeaseTable, PendingChange, PendingFingerprint, PendingRelay},
    store::{Completion, LeaseStore, MemLeaseStore, SubmitError, Ticket},
    v4::{Message, MessageBuilder, MessageType},
};

/// What the path reads: the image, the lease table, the store, the clock.
pub struct Path<'a> {
    /// The configuration image.
    pub image: &'a ConfigImage,
    /// The lease table.
    pub leases: &'a MemLeaseTable,
    /// The lease store.
    pub store: &'a dyn LeaseStore,
    /// Now.
    pub now: Timestamp,
    /// The address of the interface a request without `giaddr` arrived on.
    pub interface: Ipv4Addr,
}

/// The skeleton of the DORA path (WP7.3 replaces it with the engine): a DISCOVER is
/// answered with an OFFER and writes nothing; a REQUEST becomes a lease change handed to
/// the store, and the ACK is built for the worker to send when the commit returns. Returns
/// the reply's length, 0 when the request is not answered.
#[allow(
    clippy::too_many_lines,
    reason = "one straight path, read top to bottom as the engine will run it"
)]
pub fn dora(path: &Path<'_>, bytes: &[u8], ticket: u64, out: &mut [u8]) -> usize {
    let Ok(message) = Message::parse(bytes) else {
        return 0;
    };
    let Ok(Some(kind)) = message.message_type() else {
        return 0;
    };
    let reply_kind = match kind {
        MessageType::Discover => MessageType::Offer,
        MessageType::Request => MessageType::Ack,
        _ => return 0,
    };
    let relay = message.relay_agent_info().ok().flatten();
    let giaddr = message.giaddr();
    let selector = relay
        .and_then(|info| info.link_selection())
        .or_else(|| message.subnet_selection().ok().flatten())
        .or_else(|| (!giaddr.is_unspecified()).then_some(giaddr))
        .unwrap_or(path.interface);
    let Some(scope) = path.image.select(selector) else {
        return 0;
    };
    let Ok(chaddr) = message.chaddr() else {
        return 0;
    };
    let client_id = message.client_identifier().ok().flatten();
    let mut identity = [0u8; MAX_IDENTITY];
    let len = write_identity(
        message.htype(),
        chaddr,
        client_id.map(|id| id.as_bytes()),
        &mut identity,
    );
    let identity = &identity[..len];
    if let Ok(mac) = message.mac()
        && path.image.verdict(&mac) == FilterVerdict::Denied
    {
        return 0;
    }
    let client_addr = message.ciaddr();
    let request = Request {
        image: path.image,
        scope,
        identity,
        requested: message
            .requested_address()
            .ok()
            .flatten()
            .or((!client_addr.is_unspecified()).then_some(client_addr)),
        leases: path.leases,
        offers: &NoOffers,
        ownership: &SingleNode,
        now: path.now,
    };
    let Some(choice) = ReferenceAllocator.pick(&request) else {
        return 0;
    };
    let addr = choice.addr();
    let granted = grant_time(&scope.lease, message.lease_time().ok().flatten(), None);
    let (t1, t2) = scope.lease.renewal_times(granted);
    if reply_kind == MessageType::Ack {
        let Some(ends) = path
            .now
            .checked_add(Duration::from_secs(u64::from(granted)))
        else {
            return 0;
        };
        let mut change = PendingChange::new(
            LeaseEventKind::Granted,
            scope.vrf,
            scope.prefix,
            addr,
            message.htype(),
            chaddr,
            client_id.map(|id| id.as_bytes()),
            BindingState::Active,
            path.now,
            ends,
        );
        if let Ok(Some(name)) = message.host_name() {
            change.hostname.set(name);
        }
        if let Some(info) = relay {
            let mut pending = PendingRelay {
                giaddr,
                raw: tenko_dhcp::lease::InlineBytes::default(),
            };
            pending.raw.set(info.as_bytes());
            change.relay = Some(pending);
        }
        let mut fingerprint = PendingFingerprint::default();
        if let Ok(Some(list)) = message.parameter_request_list() {
            fingerprint.parameters.set(list);
        }
        if let Ok(Some(class)) = message.vendor_class_identifier() {
            fingerprint.vendor_class.set(class);
        }
        change.fingerprint = Some(fingerprint);
        if path.store.submit(&change, Ticket(ticket)).is_err() {
            return 0;
        }
    }
    let Ok(mut reply) = MessageBuilder::reply(out, &message, reply_kind) else {
        return 0;
    };
    reply.yiaddr(addr);
    let built = reply
        .server_identifier(scope.server_id.unwrap_or(path.interface))
        .and_then(|b| b.lease_time(granted))
        .and_then(|b| b.renewal_time(t1))
        .and_then(|b| b.rebinding_time(t2));
    if built.is_err() {
        return 0;
    }
    for value in &scope.options {
        if let Ok(code) = u8::try_from(value.code)
            && reply.option(code, &value.data.0).is_err()
        {
            return 0;
        }
    }
    if let Some(info) = relay
        && reply.relay_agent_info(info.as_bytes()).is_err()
    {
        return 0;
    }
    reply.finish().unwrap_or(0)
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
    let interface = Ipv4Addr::new(192, 0, 2, 1);
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
    let path = Path {
        image: &image,
        leases: &leases,
        store: &store,
        now,
        interface,
    };
    let mut out = [0u8; 1500];
    let mut answered = 0;
    let mut ticket = 0;
    assert_no_alloc(global, "the DORA path up to the hand-off", rounds, || {
        for bytes in requests {
            ticket += 1;
            let len = dora(&path, black_box(bytes), ticket, &mut out);
            answered += usize::from(len > 0);
            black_box(&out[..len]);
        }
    });
    assert!(answered > 0, "the skeleton answers the fixture requests");

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
                black_box(dora(&path, black_box(bytes), 0, &mut out));
            }
        });
    }));
    assert!(
        failed.is_err(),
        "an allocation in the hand-off must fail the section"
    );
}
