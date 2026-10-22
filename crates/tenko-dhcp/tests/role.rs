//! The role in the process (WP7.5) over the in-memory store and a relay-mode listener on
//! loopback: the tables built from the store before the listener answers, a DORA exchange
//! committed to `dhcp.leases`, the node commands (list, release, history, stats) and the
//! status report, a scope written after the start reaching the image through the feed, and
//! a snapshot install (the store builds the role's index aside and installs it, as the Raft
//! state machine does after it installed a snapshot) swapping image and table together
//! while the role keeps serving.

mod engine_world;

use std::{
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use engine_world::{Ask, ip};
use tenko_core::{
    NodeId, PrefixId, Principal, RangeId, RequestCtx, Revision, SystemComponent, VrfId,
    codec::to_cbor,
    dhcp::{BindingState, ClientKey, DdnsState, Lease, LeaseEventKind, tables::LEASES},
    ipam::{AllocPolicy, Meta, Prefix, PrefixRole, Range, RangeRole, Stamp, Status},
    serde_util::HexBytes,
};
use tenko_dhcp::{
    config::{ConfigService, scopes::NewScope},
    lease::CommitSettings,
    role::{DhcpNode, Outcome, Output, Role, RoleSettings, commands},
    server::{Listen, ServerConfig, SocketLayout},
    v4::{Message, MessageType, engine::ListenMode},
};
use tenko_ipam::tables::{PREFIX_RANGES, PREFIXES, RANGES};
use tenko_store::{
    ChangeSet, ChangeStream, Committed, DerivedIndex, IndexImage, Leadership, MemStore,
    ReadConsistency, ReadView, ReadViewExt as _, Store, StoreError, StoreStatus, WatchFilter,
    WriteBatch,
};

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// A derived index whose change sets can be held back, as on a follower that misses the
/// entries a snapshot later covers.
struct Gate {
    index: Arc<dyn DerivedIndex>,
    open: Arc<AtomicBool>,
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gate")
    }
}

impl std::fmt::Debug for Installing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Installing")
    }
}

impl DerivedIndex for Gate {
    fn name(&self) -> &'static str {
        tenko_dhcp::store_feed::INDEX
    }

    fn filter(&self) -> WatchFilter {
        self.index.filter()
    }

    fn build(&self, view: &dyn ReadView) -> Result<Box<dyn IndexImage>, StoreError> {
        self.index.build(view)
    }

    fn install(&self, image: Box<dyn IndexImage>) {
        self.index.install(image);
    }

    fn apply(&self, changes: &ChangeSet, view: &dyn ReadView) {
        if self.open.load(Ordering::Relaxed) {
            self.index.apply(changes, view);
        }
    }
}

/// The in-memory store, keeping the derived indexes registered with it so that the test
/// can hold their change sets back and then rebuild and install them as a snapshot install
/// does.
struct Installing {
    inner: Arc<dyn Store>,
    indexes: Mutex<Vec<Arc<dyn DerivedIndex>>>,
    open: Arc<AtomicBool>,
}

impl Installing {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(MemStore::default()),
            indexes: Mutex::new(Vec::new()),
            open: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Holds the change sets back from the indexes, as a lagging follower misses entries.
    fn lag(&self) {
        self.open.store(false, Ordering::Relaxed);
    }

    /// What the state machine does after a snapshot install: every index builds a new
    /// image from the store's state and installs it; change sets reach them again.
    async fn install_snapshot(&self) {
        let view = self.inner.read(ReadConsistency::Local).await.expect("view");
        let indexes = self
            .indexes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for index in indexes {
            let image = index.build(view.as_ref()).expect("build");
            index.install(image);
        }
        self.open.store(true, Ordering::Relaxed);
    }
}

#[async_trait::async_trait]
impl Store for Installing {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        self.inner.propose(batch).await
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.inner.read(consistency).await
    }

    fn watch(
        &self,
        from: Option<Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        self.inner.watch(from, filter)
    }

    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        self.indexes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&index));
        self.inner.register_index(Arc::new(Gate {
            index,
            open: Arc::clone(&self.open),
        }))
    }

    fn status(&self) -> StoreStatus {
        self.inner.status()
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<Leadership>> {
        self.inner.leadership()
    }
}

fn cx() -> RequestCtx {
    RequestCtx::new(Principal::system(SystemComponent::Api))
}

fn meta() -> Meta {
    Meta::new(Stamp::new(
        "2026-10-22T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Api),
    ))
}

/// An IPAM network with a DHCP pool, written straight into the store, and its scope.
async fn network(
    store: &Arc<dyn Store>,
    config: &ConfigService,
    vrf: VrfId,
    cidr: &str,
    pool: (&str, &str),
) -> PrefixId {
    let prefix = Prefix {
        id: PrefixId::generate(),
        vrf,
        cidr: cidr.parse().expect("cidr"),
        role: PrefixRole::Network,
        status: Status::Active,
        vlan: None,
        site: None,
        alarm: None,
        alloc: AllocPolicy::Lowest,
        dns_reverse: None,
        meta: meta(),
    };
    let range = Range {
        id: RangeId::generate(),
        prefix: prefix.id,
        first: pool.0.parse().expect("first"),
        last: pool.1.parse().expect("last"),
        role: RangeRole::DhcpPool,
        lease_secs: None,
        status: Status::Active,
        meta: meta(),
    };
    let mut batch = WriteBatch::new(
        Principal::system(SystemComponent::Api),
        tenko_core::Timestamp::now(),
    );
    batch
        .put_typed(&PREFIXES, &prefix.id, &prefix)
        .expect("prefix");
    batch.put_typed(&RANGES, &range.id, &range).expect("range");
    batch
        .put_typed(&PREFIX_RANGES, &(prefix.id, range.id), &())
        .expect("index");
    store.propose(batch).await.expect("IPAM rows");
    config
        .create_scope(
            &cx(),
            NewScope {
                prefix: prefix.id,
                enabled: None,
                lease: None,
                authoritative: None,
                server_id: None,
                ddns: None,
                shared_network: None,
                restricted: false,
                classes: Vec::new(),
                description: None,
            },
        )
        .await
        .expect("scope");
    prefix.id
}

/// An active lease written by another node.
fn foreign_lease(vrf: VrfId, scope: PrefixId, addr: Ipv4Addr) -> Lease {
    let now = tenko_core::Timestamp::now();
    Lease {
        addr,
        vrf,
        scope,
        client: ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x99]),
            client_id: None,
        },
        state: BindingState::Active,
        cltt: now,
        ends: now
            .checked_add(Duration::from_secs(3_600))
            .expect("an hour on"),
        tstp: None,
        tsfp: None,
        atsfp: None,
        node: NodeId(2),
        share: None,
        hostname: Some("other".to_owned()),
        fqdn: None,
        fqdn_flags: None,
        ddns_policy: None,
        ddns: DdnsState::default(),
        fingerprint: None,
        relay: None,
        observed_at: None,
    }
}

fn relayed(kind: MessageType, client: u8, subnet: &str) -> Ask {
    let mut ask = Ask::new(kind, client);
    ask.giaddr = Some(LOOPBACK);
    ask.subnet = Some(ip(subnet));
    ask
}

/// Sends `ask` until an answer arrives (the image may still be on its way), at most 5 s.
async fn exchange(relay: &Arc<UdpSocket>, server: SocketAddrV4, ask: &Ask) -> Option<Vec<u8>> {
    let relay = Arc::clone(relay);
    let bytes = ask.bytes();
    tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let mut buf = [0u8; 1500];
        while start.elapsed() < Duration::from_secs(5) {
            relay.send_to(&bytes, server).expect("send");
            if let Ok((len, _)) = relay.recv_from(&mut buf) {
                return Some(buf[..len].to_vec());
            }
        }
        None
    })
    .await
    .expect("join")
}

/// A full DORA for `client`; the address of the ACK.
async fn dora(relay: &Arc<UdpSocket>, server: SocketAddrV4, client: u8, subnet: &str) -> Ipv4Addr {
    let offer = exchange(
        relay,
        server,
        &relayed(MessageType::Discover, client, subnet),
    )
    .await
    .expect("offer");
    let offer = Message::parse(&offer).expect("parse");
    assert_eq!(offer.message_type().expect("53"), Some(MessageType::Offer));
    let mut request = relayed(MessageType::Request, client, subnet);
    request.requested = Some(offer.yiaddr());
    request.server_id = offer.server_identifier().expect("54");
    let ack = exchange(relay, server, &request).await.expect("ack");
    let ack = Message::parse(&ack).expect("parse");
    assert_eq!(ack.message_type().expect("53"), Some(MessageType::Ack));
    ack.yiaddr()
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(5), "{what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn active(node: &dyn DhcpNode) -> usize {
    node.status()
        .leases
        .iter()
        .find(|(state, _)| *state == BindingState::Active)
        .map_or(0, |(_, count)| *count)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines, reason = "one role through its whole life")]
async fn the_role_serves_from_the_store_follows_it_and_survives_a_snapshot_install() {
    let installing = Installing::new();
    let store: Arc<dyn Store> = Arc::clone(&installing) as Arc<dyn Store>;
    let config = ConfigService::with_direct_jobs(Arc::clone(&store));
    let vrf = VrfId::generate();
    let first = network(
        &store,
        &config,
        vrf,
        "192.0.2.0/24",
        ("192.0.2.100", "192.0.2.199"),
    )
    .await;

    let relay = UdpSocket::bind(SocketAddrV4::new(LOOPBACK, 0)).expect("bind");
    relay
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let relay_port = relay.local_addr().expect("address").port();
    let relay = Arc::new(relay);
    let mut server = ServerConfig {
        listen: vec![Listen {
            address: SocketAddrV4::new(LOOPBACK, 0),
            mode: ListenMode::Relay,
            interface: None,
        }],
        workers: 2,
        layout: SocketLayout::Shared,
        ..ServerConfig::default()
    };
    server.engine.relay_port = relay_port;
    let role = Role::start(
        Arc::clone(&store),
        NodeId(1),
        RoleSettings {
            server,
            commit: CommitSettings::default(),
            probe: false,
            probe_expected: true,
        },
    )
    .await
    .expect("start");
    let node = role.node();
    let status = node.status();
    assert!(status.serving);
    assert_eq!(
        status.scopes, 1,
        "the image is built before the listener answers"
    );
    assert_eq!(status.listeners.len(), 1);
    assert!(status.accepting);
    assert!(status.probe_expected && !status.probe);
    let address = status.listeners[0].address;

    // A DORA exchange: the ACK leaves after the row is in the store.
    let addr = dora(&relay, address, 0x41, "192.0.2.0").await;
    assert!(addr.octets()[..3] == [192, 0, 2] && addr.octets()[3] >= 100);
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let (row, _) = view
        .get_typed(&LEASES, &(vrf, addr))
        .expect("read")
        .expect("the lease is a row before the ACK");
    assert_eq!(row.state, BindingState::Active);
    assert_eq!(row.scope, first);
    assert_eq!(active(node.as_ref()), 1);
    assert!(node.status().last_commit.is_some());

    // dhcp.leases.list.
    let listed = node
        .execute(
            commands::LEASES_LIST,
            &to_cbor(&commands::LeaseListArgs {
                scope: Some(first),
                ..commands::LeaseListArgs::default()
            })
            .expect("args"),
        )
        .await;
    let Output::Leases(page) = listed.output else {
        panic!("a page: {listed:?}");
    };
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].lease.addr, addr);
    assert!(page.items[0].revision > Revision::ZERO);
    assert!(!page.items[0].reserved);
    assert_eq!(page.next, None);

    // A second client, then a page of one with its cursor.
    let second = dora(&relay, address, 0x42, "192.0.2.0").await;
    assert_ne!(second, addr);
    let one = node
        .execute(
            commands::LEASES_LIST,
            &to_cbor(&commands::LeaseListArgs {
                limit: 1,
                ..commands::LeaseListArgs::default()
            })
            .expect("args"),
        )
        .await;
    let Output::Leases(page) = one.output else {
        panic!("a page");
    };
    assert_eq!(page.items.len(), 1);
    let after = page.next.expect("a next page");
    let rest = node
        .execute(
            commands::LEASES_LIST,
            &to_cbor(&commands::LeaseListArgs {
                after: Some(after),
                ..commands::LeaseListArgs::default()
            })
            .expect("args"),
        )
        .await;
    let Output::Leases(rest) = rest.output else {
        panic!("a page");
    };
    assert_eq!(rest.items.len(), 1);
    assert_ne!(rest.items[0].lease.addr, page.items[0].lease.addr);

    // dhcp.lease.release, twice: the second finds no binding.
    let args = to_cbor(&commands::ReleaseArgs {
        vrf: None,
        addr,
        reason: Some("test".to_owned()),
    })
    .expect("args");
    let released = node.execute(commands::LEASE_RELEASE, &args).await;
    assert_eq!(released.outcome, Outcome::Done, "{}", released.detail);
    let Output::Lease(row) = released.output else {
        panic!("the released lease");
    };
    assert_eq!(row.lease.state, BindingState::Released);
    let again = node.execute(commands::LEASE_RELEASE, &args).await;
    assert_eq!(again.outcome, Outcome::Rejected);
    assert_eq!(again.code, Some(tenko_core::dhcp::codes::LEASE_STATE));
    let missing = node
        .execute(
            commands::LEASE_RELEASE,
            &to_cbor(&commands::ReleaseArgs {
                vrf: Some(vrf),
                addr: ip("192.0.2.250"),
                reason: None,
            })
            .expect("args"),
        )
        .await;
    assert_eq!(missing.code, Some(tenko_core::dhcp::codes::LEASE_NOT_FOUND));
    assert_eq!(active(node.as_ref()), 1);

    // dhcp.history.read: newest first.
    let history = node
        .execute(
            commands::HISTORY_READ,
            &to_cbor(&commands::HistoryArgs {
                addr: Some(addr),
                ..commands::HistoryArgs::default()
            })
            .expect("args"),
        )
        .await;
    let Output::History(page) = history.output else {
        panic!("a page: {}", history.detail);
    };
    let kinds: Vec<LeaseEventKind> = page.items.iter().map(|event| event.kind).collect();
    assert_eq!(kinds, [LeaseEventKind::Reclaimed, LeaseEventKind::Granted]);

    // dhcp.stats.
    let counted = node.execute(commands::STATS, &[]).await;
    let Output::Stats(figures) = counted.output else {
        panic!("stats");
    };
    assert_eq!(figures.engine.packets("discover", "answered"), 2);
    assert_eq!(figures.commits.committed, 2);
    assert_eq!(figures.leases, 2);
    let unknown = node.execute("dhcp.nothing", &[]).await;
    assert_eq!(unknown.outcome, Outcome::Rejected);

    // A scope written after the start reaches the image through the feed.
    let other = network(
        &store,
        &config,
        vrf,
        "198.51.100.0/24",
        ("198.51.100.10", "198.51.100.20"),
    )
    .await;
    until("the second scope is served", || node.status().scopes == 2).await;
    let third = dora(&relay, address, 0x43, "198.51.100.0").await;
    assert_eq!(third.octets()[..3], [198, 51, 100]);
    assert_eq!(active(node.as_ref()), 2);

    // A snapshot install: while the node lags, a scope and the lease of another node are
    // written and its feed does not see them; then the store installs a snapshot, the image
    // and the table are rebuilt from it and swapped together, every lease committed before
    // is still there, the missed rows are in, and the role keeps serving.
    let before = node.leases().read().sorted_rows();
    assert_eq!(node.status().installs, 0);
    installing.lag();
    let late = network(
        &store,
        &config,
        vrf,
        "203.0.113.0/24",
        ("203.0.113.10", "203.0.113.20"),
    )
    .await;
    let foreign = foreign_lease(vrf, first, ip("192.0.2.150"));
    let mut batch = WriteBatch::new(
        Principal::system(SystemComponent::Dhcp),
        tenko_core::Timestamp::now(),
    );
    batch
        .put_typed(&LEASES, &(vrf, foreign.addr), &foreign)
        .expect("lease");
    store.propose(batch).await.expect("the other node's lease");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        node.status().scopes,
        2,
        "the lagging feed has not seen the scope"
    );
    installing.install_snapshot().await;
    until("the new image is installed", || node.status().installs == 1).await;
    assert_eq!(node.status().scopes, 3);
    let after = node.leases().read().sorted_rows();
    for (key, lease) in &before {
        assert_eq!(after.get(key), Some(lease), "{key:?} kept");
    }
    assert_eq!(after.get(&(vrf, foreign.addr)), Some(&foreign));
    let fifth = dora(&relay, address, 0x46, "203.0.113.0").await;
    assert_eq!(fifth.octets()[..3], [203, 0, 113]);
    let _ = late;
    let fourth = dora(&relay, address, 0x44, "198.51.100.0").await;
    assert_ne!(fourth, third);
    let renewal = {
        let mut ask = relayed(MessageType::Request, 0x43, "198.51.100.0");
        ask.ciaddr = Some(third);
        exchange(&relay, address, &ask).await.expect("renewal")
    };
    assert_eq!(
        Message::parse(&renewal)
            .expect("parse")
            .message_type()
            .expect("53"),
        Some(MessageType::Ack),
        "a client of the old table renews after the install"
    );
    let _ = other;

    role.stop().await;
    // The listener is closed: nothing answers any more.
    let gone = {
        let relay = Arc::clone(&relay);
        let bytes = relayed(MessageType::Discover, 0x45, "192.0.2.0").bytes();
        tokio::task::spawn_blocking(move || {
            relay.send_to(&bytes, address).expect("send");
            let mut buf = [0u8; 1500];
            relay.recv_from(&mut buf).is_ok()
        })
        .await
        .expect("join")
    };
    assert!(!gone, "the role stopped answering");
}
