//! The role in the process with both families (WP9.1) over the in-memory store: a DHCPv4
//! relay listener and a DHCPv6 relay listener on loopback, scopes written through
//! `ConfigService`, and clients that speak through a relay agent of the test's own.
//!
//! - The status reports one DHCPv6 listener and one DHCPv6 scope beside the DHCPv4 ones.
//! - SOLICIT, ADVERTISE, REQUEST, REPLY: the REPLY leaves only after the row is in
//!   `dhcp.leases6` and in the role's table, with a `granted` row in `dhcp.history6`.
//! - A client with a reservation by DUID gets its reserved address.
//! - A scope written after the start reaches the image through the feed.
//! - RELEASE gives a REPLY with status success and the row turns `released`; DECLINE
//!   abandons the address.
//! - A snapshot install keeps the DHCPv6 rows the role committed, takes the rows it missed
//!   and the role keeps serving.

mod engine6_world;
mod engine_world;

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use engine_world::{Ask, ip};
use engine6_world::{
    LINK1, LINK2, SERVER_DUID, addr, addresses, client_options, duid_ll, ia_na, mac, message,
    relayed, statuses, unwrap,
};
use tenko_core::{
    AddressId, HostId, InterfaceId, NodeId, PrefixId, Principal, RangeId, RequestCtx, Revision,
    SystemComponent, TenantId, Timestamp, VrfId,
    dhcp::{
        BindingState, LeaseEventKind, LeaseTimes, OptionOwner, OptionSpace, Scope6Settings,
        tables::{HISTORY6, LEASES6},
    },
    ipam::{
        Address, AllocPolicy, AssignmentMode, Host, Interface, Meta, Prefix, PrefixRole, Range,
        RangeRole, Stamp, Status,
    },
    net::{Duid, HostName},
};
use tenko_dhcp::{
    config::{ConfigService, options::OptionInput, scopes::NewScope},
    lease::CommitSettings,
    role::{DhcpNode, LocalNode, Role, RoleSettings},
    server::{Listen, ServerConfig, SocketLayout},
    v4::{Message as Message4, MessageType as MessageType4, engine::ListenMode},
    v6::{
        Message, MessageType, code,
        engine::Engine6Settings,
        lease::Lease6Table as _,
        server::{Listen6, Server6Config},
        status,
    },
};
use tenko_ipam::tables::{
    ADDRESS_IPS, ADDRESSES, HOST_INTERFACES, HOSTS, INTERFACE_ADDRESSES, INTERFACES, PREFIX_RANGES,
    PREFIXES, RANGES,
};
use tenko_store::{
    ChangeSet, ChangeStream, Committed, DerivedIndex, IndexImage, KeyRange, Leadership, MemStore,
    ReadConsistency, ReadView, ReadViewExt as _, Store, StoreError, StoreStatus, WatchFilter,
    WriteBatch,
};

// ---------------------------------------------------------------------------------------
// The store that can hold the feed back and install a snapshot

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

/// The in-memory store, keeping the derived indexes registered with it so that the test can
/// hold their change sets back and then rebuild and install them as a snapshot install does.
struct Installing {
    inner: Arc<dyn Store>,
    indexes: Mutex<Vec<Arc<dyn DerivedIndex>>>,
    open: Arc<AtomicBool>,
}

impl std::fmt::Debug for Installing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Installing")
    }
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

    /// What the state machine does after a snapshot install: every index builds a new image
    /// from the store's state and installs it; change sets reach them again.
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

// ---------------------------------------------------------------------------------------
// IPAM and DHCP rows

fn cx() -> RequestCtx {
    RequestCtx::new(Principal::system(SystemComponent::Api))
}

fn meta() -> Meta {
    Meta::new(Stamp::new(
        "2026-10-22T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Api),
    ))
}

fn lease_times() -> LeaseTimes {
    LeaseTimes {
        default_secs: 4_000,
        min_secs: 600,
        max_secs: 8_000,
        t1_secs: None,
        t2_secs: None,
    }
}

/// An IPAM network with a DHCP pool, written straight into the store, and its scope; a
/// scope on an IPv6 prefix gets DHCPv6 settings with a preferred lifetime of 3000 s.
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
    let v6 = prefix.cidr.addr().is_ipv6();
    let range = Range {
        id: RangeId::generate(),
        prefix: prefix.id,
        first: pool.0.parse().expect("first"),
        last: pool.1.parse().expect("last"),
        role: RangeRole::DhcpPool,
        lease_secs: None,
        delegated_len: None,
        status: Status::Active,
        meta: meta(),
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
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
                v6: v6.then(|| Scope6Settings {
                    preferred_secs: Some(3_000),
                    ..Scope6Settings::default()
                }),
                prefix: prefix.id,
                enabled: None,
                lease: v6.then(lease_times),
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

/// A `reserved` host with one interface that has `duid` and the address `ip` in `prefix`.
async fn reserved_host(
    store: &Arc<dyn Store>,
    vrf: VrfId,
    prefix: PrefixId,
    duid: &[u8],
    ip: &str,
) -> (HostId, InterfaceId) {
    let host = Host {
        id: HostId::generate(),
        tenant: TenantId::generate(),
        name: HostName::new("reserved1").expect("host name"),
        mode: AssignmentMode::Reserved,
        lock: false,
        site: None,
        decommissioned: None,
        meta: meta(),
    };
    let interface = Interface {
        id: InterfaceId::generate(),
        host: host.id,
        name: "eth0".to_owned(),
        mac: None,
        duid: Some(Duid::new(duid.to_vec()).expect("a DUID")),
        client_id: None,
        meta: meta(),
    };
    let address = Address {
        id: AddressId::generate(),
        vrf,
        ip: ip.parse().expect("ip"),
        prefix,
        status: Status::Active,
        interface: Some(interface.id),
        dns_name: None,
        meta: meta(),
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
    batch.put_typed(&HOSTS, &host.id, &host).expect("host");
    batch
        .put_typed(&INTERFACES, &interface.id, &interface)
        .expect("interface");
    batch
        .put_typed(&HOST_INTERFACES, &(host.id, interface.id), &())
        .expect("index");
    batch
        .put_typed(&ADDRESSES, &address.id, &address)
        .expect("address");
    batch
        .put_typed(&ADDRESS_IPS, &(address.vrf, address.ip), &address.id)
        .expect("index");
    batch
        .put_typed(&INTERFACE_ADDRESSES, &(interface.id, address.id), &())
        .expect("index");
    store.propose(batch).await.expect("IPAM rows");
    (host.id, interface.id)
}

// ---------------------------------------------------------------------------------------
// The clients

fn solicit(duid: &[u8], iaid: u32, xid: u32) -> Vec<u8> {
    message(MessageType::Solicit, xid, |b| {
        client_options(b, duid);
        ia_na(b, iaid, None);
    })
}

fn with_address(kind: MessageType, duid: &[u8], iaid: u32, address: Ipv6Addr, xid: u32) -> Vec<u8> {
    message(kind, xid, |b| {
        client_options(b, duid);
        b.option(code::SERVERID, &SERVER_DUID).expect("server id");
        ia_na(b, iaid, Some(address));
    })
}

fn peer() -> Ipv6Addr {
    "fe80::200:5eff:fe00:5301".parse().expect("peer")
}

/// A client message through one relay on the link `link`.
fn via(link: Ipv6Addr, inner: &[u8]) -> Vec<u8> {
    relayed(inner, &[(link, peer(), None)], None)
}

fn xid_of(reply: &[u8]) -> u32 {
    let inner = unwrap(reply);
    Message::parse(&inner).expect("parses").transaction_id()
}

/// Sends `bytes` and waits for the reply of that transaction, at most `wait`.
async fn exchange6(
    relay: &Arc<UdpSocket>,
    server: SocketAddrV6,
    bytes: Vec<u8>,
    xid: u32,
) -> Option<Vec<u8>> {
    let relay = Arc::clone(relay);
    tokio::task::spawn_blocking(move || {
        relay.send_to(&bytes, server).expect("send");
        let start = Instant::now();
        let mut buf = [0u8; 2048];
        while start.elapsed() < Duration::from_secs(3) {
            if let Ok((len, _)) = relay.recv_from(&mut buf)
                && xid_of(&buf[..len]) == xid
            {
                return Some(buf[..len].to_vec());
            }
        }
        None
    })
    .await
    .expect("join")
}

/// Sends a SOLICIT until the reply offers an address (the image may still be on its way),
/// at most 10 s.
async fn offer_with_retry(
    relay: &Arc<UdpSocket>,
    server: SocketAddrV6,
    link: Ipv6Addr,
    duid: &[u8],
    xid: u32,
) -> Option<Vec<u8>> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        let reply = exchange6(relay, server, via(link, &solicit(duid, 1, xid)), xid).await;
        if let Some(reply) = reply
            && !addresses(&reply).is_empty()
        {
            return Some(reply);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// SOLICIT, ADVERTISE, REQUEST, REPLY; the address of the REPLY.
async fn lease6(
    relay: &Arc<UdpSocket>,
    server: SocketAddrV6,
    link: Ipv6Addr,
    duid: &[u8],
    iaid: u32,
    xid: u32,
) -> Ipv6Addr {
    let advertise = exchange6(relay, server, via(link, &solicit(duid, iaid, xid)), xid)
        .await
        .expect("an advertise");
    let inner = unwrap(&advertise);
    assert_eq!(
        Message::parse(&inner).expect("parses").kind(),
        MessageType::Advertise
    );
    let offered = addresses(&advertise)[0].1;
    let request = with_address(MessageType::Request, duid, iaid, offered, xid + 1);
    let reply = exchange6(relay, server, via(link, &request), xid + 1)
        .await
        .expect("a reply");
    let inner = unwrap(&reply);
    assert_eq!(
        Message::parse(&inner).expect("parses").kind(),
        MessageType::Reply
    );
    let granted = addresses(&reply);
    assert_eq!(granted.len(), 1, "{granted:?}");
    assert_eq!(granted[0].1, offered);
    offered
}

fn relay6_socket() -> Arc<UdpSocket> {
    let socket = UdpSocket::bind("[::1]:0").expect("a relay socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    Arc::new(socket)
}

fn relayed4(kind: MessageType4, client: u8, subnet: &str) -> Ask {
    let mut ask = Ask::new(kind, client);
    ask.giaddr = Some(Ipv4Addr::LOCALHOST);
    ask.subnet = Some(ip(subnet));
    ask
}

async fn exchange4(relay: &Arc<UdpSocket>, server: SocketAddrV4, ask: &Ask) -> Vec<u8> {
    let relay = Arc::clone(relay);
    let bytes = ask.bytes();
    tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let mut buf = [0u8; 1500];
        while start.elapsed() < Duration::from_secs(5) {
            relay.send_to(&bytes, server).expect("send");
            if let Ok((len, _)) = relay.recv_from(&mut buf) {
                return buf[..len].to_vec();
            }
        }
        panic!("no DHCPv4 answer");
    })
    .await
    .expect("join")
}

/// A DHCPv4 DORA; the address of the ACK.
async fn dora4(relay: &Arc<UdpSocket>, server: SocketAddrV4, client: u8, subnet: &str) -> Ipv4Addr {
    let offer = exchange4(
        relay,
        server,
        &relayed4(MessageType4::Discover, client, subnet),
    )
    .await;
    let offer = Message4::parse(&offer).expect("parse");
    assert_eq!(offer.message_type().expect("53"), Some(MessageType4::Offer));
    let mut request = relayed4(MessageType4::Request, client, subnet);
    request.requested = Some(offer.yiaddr());
    request.server_id = offer.server_identifier().expect("54");
    let ack = exchange4(relay, server, &request).await;
    let ack = Message4::parse(&ack).expect("parse");
    assert_eq!(ack.message_type().expect("53"), Some(MessageType4::Ack));
    ack.yiaddr()
}

// ---------------------------------------------------------------------------------------
// The fixture

struct Fixture {
    installing: Arc<Installing>,
    store: Arc<dyn Store>,
    config: Arc<ConfigService>,
    vrf: VrfId,
    scope6: PrefixId,
    role: Role,
    node: Arc<LocalNode>,
    relay6: Arc<UdpSocket>,
    relay4: Arc<UdpSocket>,
    server6: SocketAddrV6,
    server4: SocketAddrV4,
    reserved_duid: Vec<u8>,
}

impl Fixture {
    /// Writes the configuration and starts the role with both listeners.
    #[allow(
        clippy::too_many_lines,
        reason = "the configuration and the start of one role"
    )]
    async fn start() -> Self {
        let installing = Installing::new();
        let store: Arc<dyn Store> = Arc::clone(&installing) as Arc<dyn Store>;
        let config = ConfigService::with_direct_jobs(Arc::clone(&store));
        let vrf = VrfId::generate();
        let scope4 = network(
            &store,
            &config,
            vrf,
            "192.0.2.0/24",
            ("192.0.2.100", "192.0.2.199"),
        )
        .await;
        let _ = scope4;
        let scope6 = network(
            &store,
            &config,
            vrf,
            "2001:db8:1::/64",
            ("2001:db8:1::100", "2001:db8:1::1ff"),
        )
        .await;
        // The options of the scope: the DNS servers (23) and the domain list (24).
        config
            .set_option_set(
                &cx(),
                OptionOwner::Scope(scope6),
                vec![
                    OptionInput {
                        space: OptionSpace::dhcp6(),
                        code: 23,
                        data: Some(addr("2001:db8::53").octets().to_vec()),
                        typed: None,
                    },
                    OptionInput {
                        space: OptionSpace::dhcp6(),
                        code: 24,
                        data: Some(b"\x07example\x04test\x00".to_vec()),
                        typed: None,
                    },
                ],
                None,
            )
            .await
            .expect("the scope's options");
        // A reserved host: its interface has a DUID and the address 2001:db8:1::80.
        let reserved_duid = duid_ll(mac(0x50));
        reserved_host(&store, vrf, scope6, &reserved_duid, "2001:db8:1::80").await;

        let relay6 = relay6_socket();
        let relay4 = {
            let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind");
            socket
                .set_read_timeout(Some(Duration::from_millis(300)))
                .expect("timeout");
            Arc::new(socket)
        };
        let mut server4 = ServerConfig {
            listen: vec![Listen {
                address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
                mode: ListenMode::Relay,
                interface: None,
            }],
            workers: 2,
            layout: SocketLayout::Shared,
            ..ServerConfig::default()
        };
        server4.engine.relay_port = relay4.local_addr().expect("address").port();
        let server6 = Server6Config {
            listen: vec![Listen6 {
                address: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0),
                mode: ListenMode::Relay,
                interface: None,
            }],
            workers: 2,
            engine: Engine6Settings {
                relay_port: relay6.local_addr().expect("address").port(),
                ..Engine6Settings::default()
            },
            pending: 16,
            offers: 64,
            server_duid: SERVER_DUID.to_vec(),
            ..Server6Config::default()
        };
        let role = Role::start(
            Arc::clone(&store),
            NodeId(1),
            RoleSettings {
                server: server4,
                commit: CommitSettings::default(),
                probe: false,
                probe_expected: true,
                server6,
            },
        )
        .await
        .expect("the role starts");
        let node = role.node();
        let status = node.status();
        let (server4, server6) = (status.listeners[0].address, status.listeners6[0].address);
        Self {
            installing,
            store,
            config,
            vrf,
            scope6,
            role,
            node,
            relay6,
            relay4,
            server6,
            server4,
            reserved_duid,
        }
    }

    async fn lease_row(&self, address: Ipv6Addr) -> Option<tenko_core::dhcp::Lease6> {
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("a view");
        view.get_typed(&LEASES6, &(self.vrf, address))
            .expect("read")
            .map(|(lease, _)| lease)
    }

    async fn history(&self, address: Ipv6Addr) -> Vec<LeaseEventKind> {
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("a view");
        view.scan_typed(&HISTORY6, KeyRange::all(), usize::MAX, false)
            .expect("history")
            .into_iter()
            .filter(|(_, event, _)| event.addr == address)
            .map(|(_, event, _)| event.kind)
            .collect()
    }

    fn active6(&self) -> usize {
        self.node
            .status()
            .leases6
            .iter()
            .find(|(state, _)| *state == BindingState::Active)
            .map_or(0, |(_, count)| *count)
    }
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(5), "{what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------------------
// The tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_status_reports_both_families_and_each_serves_its_own() {
    let fx = Fixture::start().await;
    let status = fx.node.status();
    assert!(status.serving);
    assert_eq!(status.listeners.len(), 1);
    assert_eq!(status.listeners6.len(), 1);
    assert_eq!(status.listeners6[0].mode, ListenMode::Relay);
    assert_eq!(status.listeners6[0].workers, 2);
    assert_eq!(status.scopes, 1, "the IPv4 scope");
    assert_eq!(status.scopes6, 1, "the IPv6 scope");
    assert_eq!(status.server_duid.as_deref(), Some(&SERVER_DUID[..]));
    assert_eq!(fx.active6(), 0);

    // Both families answer at once.
    let v4 = dora4(&fx.relay4, fx.server4, 0x41, "192.0.2.0").await;
    assert_eq!(v4.octets()[..3], [192, 0, 2]);
    let duid = duid_ll(mac(0x01));
    let v6 = lease6(&fx.relay6, fx.server6, LINK1, &duid, 1, 0x10).await;
    assert!(addr("2001:db8:1::100") <= v6 && v6 <= addr("2001:db8:1::1ff"));
    until("the DHCPv4 lease is counted", || {
        fx.node
            .status()
            .leases
            .iter()
            .any(|(state, count)| *state == BindingState::Active && *count == 1)
    })
    .await;
    assert_eq!(fx.active6(), 1);
    fx.role.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reply_leaves_only_after_the_row_is_in_the_store_and_the_table() {
    let fx = Fixture::start().await;
    let duid = duid_ll(mac(0x02));
    // SOLICIT / ADVERTISE: the offer, with the lifetimes and the options of the scope, and
    // nothing written.
    let advertise = exchange6(
        &fx.relay6,
        fx.server6,
        via(LINK1, &solicit(&duid, 5, 0x20)),
        0x20,
    )
    .await
    .expect("an advertise");
    let inner = unwrap(&advertise);
    let inner = Message::parse(&inner).expect("parses");
    assert_eq!(inner.kind(), MessageType::Advertise);
    assert_eq!(
        inner.server_id().expect("sid").expect("present").as_bytes(),
        SERVER_DUID
    );
    let offered = addresses(&advertise);
    assert_eq!(offered.len(), 1);
    let (iaid, address, preferred, valid) = offered[0];
    assert_eq!(iaid, 5);
    assert!(addr("2001:db8:1::100") <= address && address <= addr("2001:db8:1::1ff"));
    assert_eq!((preferred, valid), (3_000, 4_000));
    assert_eq!(
        inner.option(code::DNS_SERVERS).expect("walk"),
        Some(&addr("2001:db8::53").octets()[..])
    );
    assert_eq!(
        inner.option(code::DOMAIN_LIST).expect("walk"),
        Some(&b"\x07example\x04test\x00"[..])
    );
    assert!(
        fx.lease_row(address).await.is_none(),
        "an ADVERTISE writes nothing"
    );
    assert_eq!(fx.node.leases6().read().len(), 0);

    // REQUEST / REPLY: by the time the REPLY is in the client's hands, the row is in the
    // store, in the role's table, and the history says granted.
    let request = with_address(MessageType::Request, &duid, 5, address, 0x21);
    let reply = exchange6(&fx.relay6, fx.server6, via(LINK1, &request), 0x21)
        .await
        .expect("a reply");
    assert_eq!(addresses(&reply)[0].1, address);
    let (ias, top) = statuses(&reply);
    assert_eq!(
        (ias, top),
        (vec![None], None),
        "no status means success here"
    );
    let row = fx
        .lease_row(address)
        .await
        .expect("the row is in dhcp.leases6 before the REPLY");
    assert_eq!(row.state, BindingState::Active);
    assert_eq!(row.scope, fx.scope6);
    assert_eq!(row.iaid, 5);
    assert_eq!(row.duid.as_bytes(), duid);
    assert!(row.ends > Timestamp::now());
    assert_eq!(
        row.relay.as_ref().map(|relay| relay.link_address),
        Some(LINK1)
    );
    let held = fx
        .node
        .leases6()
        .read()
        .sorted_rows()
        .get(&(fx.vrf, address))
        .cloned();
    assert_eq!(
        held.as_ref(),
        Some(&row),
        "the role's table has the same row"
    );
    assert_eq!(fx.history(address).await, vec![LeaseEventKind::Granted]);
    assert_eq!(fx.active6(), 1);
    let metrics = fx.node.metrics6();
    assert_eq!(metrics.packets("solicit", "answered"), 1);
    assert_eq!(metrics.packets("request", "answered"), 1);
    assert_eq!(fx.node.lease_store6().stats().committed, 1);

    // A RENEW extends the end of the binding and writes a renewed event.
    let renew = with_address(MessageType::Renew, &duid, 5, address, 0x22);
    let renewed = exchange6(&fx.relay6, fx.server6, via(LINK1, &renew), 0x22)
        .await
        .expect("a reply to the renewal");
    assert_eq!(addresses(&renewed)[0].1, address);
    let after = fx.lease_row(address).await.expect("row");
    assert!(after.ends >= row.ends);
    assert_eq!(
        fx.history(address).await,
        vec![LeaseEventKind::Granted, LeaseEventKind::Renewed]
    );
    fx.role.stop().await;
}

/// `DhcpStatus::last_commit` counts the commits of DHCPv6 leases too: a role that commits
/// only DHCPv6 leases reports one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_status_reports_the_last_commit_of_a_dhcpv6_lease() {
    let fx = Fixture::start().await;
    assert!(fx.node.status().last_commit.is_none());
    lease6(&fx.relay6, fx.server6, LINK1, &duid_ll(mac(0x03)), 1, 0x80).await;
    assert_eq!(fx.node.lease_store6().stats().committed, 1);
    assert!(
        fx.node.status().last_commit.is_some(),
        "a DHCPv6 commit is a commit"
    );
    fx.role.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_with_a_reservation_by_duid_gets_the_reserved_address() {
    let fx = Fixture::start().await;
    let reserved = lease6(&fx.relay6, fx.server6, LINK1, &fx.reserved_duid, 1, 0x30).await;
    assert_eq!(reserved, addr("2001:db8:1::80"));
    let row = fx.lease_row(reserved).await.expect("the reserved row");
    assert_eq!(row.duid.as_bytes(), fx.reserved_duid);
    assert_eq!(row.state, BindingState::Active);
    // The reserved address is no pool address: another client never gets it.
    let other = lease6(&fx.relay6, fx.server6, LINK1, &duid_ll(mac(0x51)), 1, 0x32).await;
    assert_ne!(other, reserved);
    fx.role.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scope_written_after_the_start_reaches_the_image_through_the_feed() {
    let fx = Fixture::start().await;
    let duid = duid_ll(mac(0x60));
    // No scope for the second link yet: nothing is offered there.
    let before = exchange6(
        &fx.relay6,
        fx.server6,
        via(LINK2, &solicit(&duid, 1, 0x40)),
        0x40,
    )
    .await;
    assert!(
        before.is_none_or(|reply| addresses(&reply).is_empty()),
        "no address for a link without a scope"
    );
    let second = network(
        &fx.store,
        &fx.config,
        fx.vrf,
        "2001:db8:2::/64",
        ("2001:db8:2::100", "2001:db8:2::1ff"),
    )
    .await;
    until("the second DHCPv6 scope is served", || {
        fx.node.status().scopes6 == 2
    })
    .await;
    let offer = offer_with_retry(&fx.relay6, fx.server6, LINK2, &duid, 0x41)
        .await
        .expect("an offer from the new scope");
    let offered = addresses(&offer)[0].1;
    assert!(addr("2001:db8:2::100") <= offered && offered <= addr("2001:db8:2::1ff"));
    let request = with_address(MessageType::Request, &duid, 1, offered, 0x42);
    let reply = exchange6(&fx.relay6, fx.server6, via(LINK2, &request), 0x42)
        .await
        .expect("a reply");
    assert_eq!(addresses(&reply)[0].1, offered);
    let row = fx.lease_row(offered).await.expect("the row");
    assert_eq!(row.scope, second);
    // The first link still works.
    let first = lease6(&fx.relay6, fx.server6, LINK1, &duid_ll(mac(0x61)), 1, 0x44).await;
    assert_eq!(first.segments()[..3], [0x2001, 0xdb8, 1]);
    fx.role.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn release_and_decline_end_the_binding_and_abandon_the_address() {
    let fx = Fixture::start().await;

    // RELEASE: a REPLY with status success, and the row turns released.
    let duid = duid_ll(mac(0x70));
    let address = lease6(&fx.relay6, fx.server6, LINK1, &duid, 1, 0x50).await;
    let release = with_address(MessageType::Release, &duid, 1, address, 0x52);
    let reply = exchange6(&fx.relay6, fx.server6, via(LINK1, &release), 0x52)
        .await
        .expect("a reply to the release");
    let inner = unwrap(&reply);
    assert_eq!(
        Message::parse(&inner).expect("parses").kind(),
        MessageType::Reply
    );
    assert_eq!(statuses(&reply).1, Some(status::SUCCESS));
    let row = fx.lease_row(address).await.expect("the row");
    assert_eq!(row.state, BindingState::Released);
    assert_eq!(
        fx.node
            .leases6()
            .read()
            .sorted_rows()
            .get(&(fx.vrf, address))
            .map(|lease| lease.state),
        Some(BindingState::Released)
    );
    assert_eq!(
        fx.history(address).await,
        vec![LeaseEventKind::Granted, LeaseEventKind::Released]
    );
    assert_eq!(fx.active6(), 0);

    // DECLINE: a REPLY with status success, the address is abandoned for its hold and
    // another client is not offered it.
    let other = duid_ll(mac(0x71));
    let declined = lease6(&fx.relay6, fx.server6, LINK1, &other, 1, 0x54).await;
    let decline = with_address(MessageType::Decline, &other, 1, declined, 0x56);
    let reply = exchange6(&fx.relay6, fx.server6, via(LINK1, &decline), 0x56)
        .await
        .expect("a reply to the decline");
    assert_eq!(statuses(&reply).1, Some(status::SUCCESS));
    let row = fx.lease_row(declined).await.expect("the row");
    assert_eq!(row.state, BindingState::Abandoned);
    assert!(row.ends > Timestamp::now(), "held for the decline hold");
    assert_eq!(
        fx.history(declined).await,
        vec![LeaseEventKind::Granted, LeaseEventKind::Declined]
    );
    let third = lease6(&fx.relay6, fx.server6, LINK1, &duid_ll(mac(0x72)), 1, 0x58).await;
    assert_ne!(third, declined, "an abandoned address is not given out");
    fx.role.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines, reason = "one role through a snapshot install")]
async fn a_snapshot_install_keeps_the_dhcpv6_rows_and_the_role_keeps_serving() {
    let fx = Fixture::start().await;
    let duid_a = duid_ll(mac(0x80));
    let duid_b = duid_ll(mac(0x81));
    let a = lease6(&fx.relay6, fx.server6, LINK1, &duid_a, 1, 0x60).await;
    let b = lease6(&fx.relay6, fx.server6, LINK1, &duid_b, 1, 0x62).await;
    assert_ne!(a, b);
    let before = fx.node.leases6().read().sorted_rows();
    assert_eq!(before.len(), 2);
    assert_eq!(fx.node.status().installs, 0);

    // While the node lags, a scope and a DHCPv6 lease of another node are written and its
    // feed does not see them.
    fx.installing.lag();
    let late = network(
        &fx.store,
        &fx.config,
        fx.vrf,
        "2001:db8:3::/64",
        ("2001:db8:3::100", "2001:db8:3::1ff"),
    )
    .await;
    let now = Timestamp::now();
    let foreign = tenko_core::dhcp::Lease6 {
        addr: addr("2001:db8:1::1f0").into(),
        prefix_len: 128,
        kind: tenko_core::dhcp::Lease6Kind::Na,
        vrf: fx.vrf,
        scope: fx.scope6,
        iaid: 9,
        duid: Duid::new(duid_ll(mac(0x90))).expect("a DUID"),
        link_layer: None,
        link_layer_type: None,
        state: BindingState::Active,
        cltt: now,
        ends: now
            .checked_add(Duration::from_secs(3_600))
            .expect("an hour"),
        preferred_ends: now.checked_add(Duration::from_secs(1_800)).expect("half"),
        node: NodeId(2),
        fqdn: None,
        fqdn_flags: None,
        relay: None,
        observed_at: None,
        ddns: tenko_core::dhcp::DdnsState::default(),
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    batch
        .put_typed(&LEASES6, &(fx.vrf, foreign.addr6()), &foreign)
        .expect("lease");
    fx.store
        .propose(batch)
        .await
        .expect("the other node's lease");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        fx.node.status().scopes6,
        1,
        "the lagging feed has not seen the scope"
    );
    assert!(
        !fx.node
            .leases6()
            .read()
            .sorted_rows()
            .contains_key(&(fx.vrf, foreign.addr6()))
    );

    // The snapshot: image and table are rebuilt and swapped together.
    fx.installing.install_snapshot().await;
    until("the new image is installed", || {
        fx.node.status().installs == 1
    })
    .await;
    assert_eq!(fx.node.status().scopes6, 2);
    let after = fx.node.leases6().read().sorted_rows();
    for (key, lease) in &before {
        assert_eq!(after.get(key), Some(lease), "{key:?} kept");
    }
    assert_eq!(after.get(&(fx.vrf, foreign.addr6())), Some(&foreign));
    assert_eq!(after.len(), 3);

    // The role keeps serving: a client of the old table renews, the new scope answers, and
    // the other node's address is not given out.
    let renew = with_address(MessageType::Renew, &duid_a, 1, a, 0x64);
    let renewed = exchange6(&fx.relay6, fx.server6, via(LINK1, &renew), 0x64)
        .await
        .expect("a reply to the renewal");
    assert_eq!(addresses(&renewed)[0].1, a);
    let link3: Ipv6Addr = addr("2001:db8:3::1");
    let fresh = lease6(&fx.relay6, fx.server6, link3, &duid_ll(mac(0x82)), 1, 0x66).await;
    assert_eq!(fresh.segments()[..3], [0x2001, 0xdb8, 3]);
    let _ = late;
    let newcomer = lease6(&fx.relay6, fx.server6, LINK1, &duid_ll(mac(0x83)), 1, 0x68).await;
    assert_ne!(newcomer, foreign.addr6());
    assert_ne!(newcomer, a);
    assert_ne!(newcomer, b);

    // A BTreeMap of the rows the store holds agrees with the table.
    let view = fx.store.read(ReadConsistency::Local).await.expect("view");
    let stored: BTreeMap<_, _> = view
        .scan_typed(&LEASES6, KeyRange::all(), usize::MAX, false)
        .expect("rows")
        .into_iter()
        .map(|(key, lease, _)| (key, lease))
        .collect();
    let table = fx.node.leases6().read().sorted_rows();
    assert_eq!(table, stored);

    let node = Arc::clone(&fx.node);
    let relay = Arc::clone(&fx.relay6);
    let server = fx.server6;
    fx.role.stop().await;
    // The listener is closed: nothing answers any more.
    let gone = tokio::task::spawn_blocking(move || {
        let _ = &node;
        relay
            .send_to(&via(LINK1, &solicit(&duid_ll(mac(0x84)), 1, 0x70)), server)
            .expect("send");
        let mut buf = [0u8; 2048];
        relay.recv_from(&mut buf).is_ok()
    })
    .await
    .expect("join");
    assert!(!gone, "the role stopped answering");
}
