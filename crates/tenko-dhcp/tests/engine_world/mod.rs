//! The world of the engine tests (WP7.3): one configuration image, a lease table, the offers
//! held and a request builder, shared by `tests/engine.rs` and `tests/engine_corpus.rs`.
//!
//! The image: scope A `192.0.2.0/24` (relayed through 192.0.2.1, authoritative, pool .100
//! to .199 with .100 to .104 excluded, a reservation of 192.0.2.20 for MAC :20 with host
//! options, 32 classless routes so that option 121 is split), scope B `198.51.100.0/24`
//! (the listener's link, 198.51.100.10), scope C `203.0.113.0/24` (not authoritative, for
//! link selection and option 118), and a deny filter for MAC :66. The table: client :10
//! holds 192.0.2.110 for another hour. Documentation addresses (RFC 5737) and MACs (RFC
//! 7042) only.

#![allow(dead_code, reason = "each test binary uses a part of the world")]

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use ipnet::Ipv4Net;
use tenko_core::{
    HostId, InterfaceId, NodeId, PrefixId, RangeId, Revision, Timestamp, VrfId,
    dhcp::{
        BindingState, DdnsPolicy, Filter, FilterId, FilterKind, LeaseEventKind, LeaseTimes,
        MacPattern, OptionValue,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
};
use tenko_dhcp::{
    allocator::SingleNode,
    image::{ConfigImage, ImageBuilder, PoolImage, ReservationImage, ScopeImage},
    lease::{LeaseTable, MemLeaseTable, PendingChange},
    v4::{
        BOOTREQUEST, MessageBuilder, MessageType, Route, code, encode_classless_routes,
        engine::{
            self, Answer, Context, EngineSettings, HashedAllocator, ListenMode, OfferTable,
            Received, Scratch,
        },
    },
};

/// The listener's address and the server identifier.
pub const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
/// The relay agent.
pub const RELAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// The time of the tests.
pub fn t0() -> Timestamp {
    "2026-10-22T12:00:00Z".parse().expect("time")
}

/// `t0` plus `secs`.
pub fn at(secs: u64) -> Timestamp {
    t0().checked_add(Duration::from_secs(secs)).expect("time")
}

/// The MAC of client `k`.
pub fn mac(k: u8) -> [u8; 6] {
    [0x00, 0x00, 0x5e, 0x00, 0x53, k]
}

/// The identity of client `k` when it sends option 61 of type 1 with its MAC.
pub fn identity_with_id(k: u8) -> Vec<u8> {
    let mut out = vec![1, 1];
    out.extend(mac(k));
    out
}

/// An address of a network.
pub fn ip(text: &str) -> Ipv4Addr {
    text.parse().expect("an address")
}

fn net(text: &str) -> Ipv4Net {
    text.parse().expect("a network")
}

fn stamp() -> Stamp {
    Stamp::new(t0(), Principal::system(SystemComponent::Dhcp))
}

/// The world.
pub struct World {
    /// The image.
    pub image: ConfigImage,
    /// The leases.
    pub leases: MemLeaseTable,
    /// The offers.
    pub offers: OfferTable,
    /// The settings.
    pub settings: EngineSettings,
    /// Whether the store accepts writes.
    pub accepting: bool,
    /// The VRF of every scope.
    pub vrf: VrfId,
}

fn scope(
    prefix: PrefixId,
    vrf: VrfId,
    network: &str,
    pool: (u8, u8),
    authoritative: bool,
    options: Vec<OptionValue>,
) -> ScopeImage {
    let network = net(network);
    let [a, b, c, _] = network.network().octets();
    ScopeImage {
        prefix,
        vrf,
        network,
        authoritative,
        restricted: false,
        server_id: None,
        lease: LeaseTimes::default(),
        shared_network: None,
        pools: vec![PoolImage {
            range: RangeId::generate(),
            first: Ipv4Addr::new(a, b, c, pool.0),
            last: Ipv4Addr::new(a, b, c, pool.1),
            lease: LeaseTimes::default(),
            classes: Vec::new(),
            options: Vec::new(),
        }],
        excluded: Vec::new(),
        options,
        classes: Vec::new(),
        ddns: DdnsPolicy::default(),
    }
}

/// The routes of scope A: 32 host routes, 288 octets, split into two instances.
pub fn routes() -> Vec<u8> {
    let routes: Vec<Route> = (0..32u8)
        .map(|host| Route {
            destination: Ipv4Addr::new(203, 0, 113, host),
            prefix_len: 32,
            router: RELAY,
        })
        .collect();
    let mut out = [0u8; 512];
    let len =
        encode_classless_routes(code::CLASSLESS_STATIC_ROUTES, &routes, &mut out).expect("routes");
    out[..len].to_vec()
}

/// A text option.
fn text(code: u8, value: &str) -> OptionValue {
    OptionValue::v4(code, value.as_bytes().to_vec())
}

impl World {
    /// The world of the module comment.
    pub fn new() -> Self {
        let vrf = VrfId::generate();
        let (a, b, c) = (
            PrefixId::generate(),
            PrefixId::generate(),
            PrefixId::generate(),
        );
        let mut builder = ImageBuilder::new(Revision(1));
        let mut scope_a = scope(
            a,
            vrf,
            "192.0.2.0/24",
            (100, 199),
            true,
            vec![
                OptionValue::v4(code::ROUTERS, RELAY.octets().to_vec()),
                OptionValue::v4(
                    code::DOMAIN_NAME_SERVERS,
                    vec![192, 0, 2, 53, 198, 51, 100, 53],
                ),
                text(code::DOMAIN_NAME, "example.test"),
                OptionValue::v4(code::NTP_SERVERS, vec![192, 0, 2, 123]),
                OptionValue::v4(code::INTERFACE_MTU, vec![0x05, 0xdc]),
                OptionValue::v4(code::CLASSLESS_STATIC_ROUTES, routes()),
                OptionValue::v4(
                    code::DOMAIN_SEARCH,
                    vec![
                        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's', b't', 0,
                    ],
                ),
            ],
        );
        scope_a.excluded = vec![(ip("192.0.2.100"), ip("192.0.2.104"))];
        builder.scope(scope_a);
        builder.scope(scope(
            b,
            vrf,
            "198.51.100.0/24",
            (100, 199),
            true,
            vec![
                OptionValue::v4(code::ROUTERS, vec![198, 51, 100, 1]),
                OptionValue::v4(code::DOMAIN_NAME_SERVERS, vec![198, 51, 100, 53]),
                text(code::DOMAIN_NAME, "example.test"),
            ],
        ));
        builder.scope(scope(
            c,
            vrf,
            "203.0.113.0/24",
            (100, 150),
            false,
            vec![OptionValue::v4(code::ROUTERS, vec![203, 0, 113, 1])],
        ));
        let reserved = builder.reservation(ReservationImage {
            scope: a,
            addr: ip("192.0.2.20"),
            host: HostId::generate(),
            interface: InterfaceId::generate(),
            identity: {
                let mut out = vec![0, 1];
                out.extend(mac(0x20));
                out
            },
            options: vec![
                text(code::DOMAIN_NAME, "lab.example.test"),
                text(code::TFTP_SERVER_NAME, "tftp.example.test"),
                text(code::BOOTFILE_NAME, "boot/x64/bootfile.efi"),
            ],
        });
        assert!(reserved.is_none());
        builder.filters(vec![Filter {
            id: FilterId::generate(),
            mac: MacPattern::new("00:00:5e:00:53:66").expect("a pattern"),
            kind: FilterKind::Deny,
            note: None,
            created: stamp(),
            updated: stamp(),
        }]);
        let image = builder.build();
        let mut world = Self {
            image,
            leases: MemLeaseTable::default(),
            offers: OfferTable::with_capacity(1_024),
            settings: EngineSettings::default(),
            accepting: true,
            vrf,
        };
        world.lease(0x10, true, ip("192.0.2.110"), BindingState::Active, 3_600);
        world.lease(0x50, true, ip("203.0.113.120"), BindingState::Active, 3_600);
        world
    }

    /// The scope whose network holds `addr`.
    pub fn scope_of(&self, addr: Ipv4Addr) -> &ScopeImage {
        self.image.select(addr).expect("a scope")
    }

    /// Gives client `k` (with option 61 when `with_id`) a lease of `addr` in `state`
    /// that ends `secs` after `t0`.
    pub fn lease(&mut self, k: u8, with_id: bool, addr: Ipv4Addr, state: BindingState, secs: u64) {
        let scope = self.scope_of(addr).prefix;
        let id = with_id.then(|| {
            let mut out = vec![1];
            out.extend(mac(k));
            out
        });
        let change = PendingChange::new(
            LeaseEventKind::Granted,
            self.vrf,
            scope,
            addr,
            1,
            &mac(k),
            id.as_deref(),
            state,
            t0(),
            at(secs),
        );
        self.leases.apply(change.to_lease(NodeId(1), None));
    }

    /// Runs the engine on `bytes` at `now`, arriving from `source` at the listener.
    pub fn run_from(
        &self,
        bytes: &[u8],
        source: SocketAddrV4,
        now: Timestamp,
        scratch: &mut Scratch,
    ) -> Answer {
        let ctx = Context {
            image: &self.image,
            leases: &self.leases,
            offers: &self.offers,
            ownership: &SingleNode,
            allocator: &HashedAllocator,
            settings: &self.settings,
            accepting: self.accepting,
            now,
        };
        engine::handle(
            &ctx,
            &Received {
                bytes,
                source,
                local: SERVER,
                mode: ListenMode::Relay,
            },
            scratch,
        )
    }

    /// Runs the engine on `bytes` at `now`, from the relay.
    pub fn run(&self, bytes: &[u8], now: Timestamp, scratch: &mut Scratch) -> Answer {
        self.run_from(bytes, SocketAddrV4::new(RELAY, 67), now, scratch)
    }

    /// Applies a committed change to the table, as the server does after the commit.
    pub fn commit(&mut self, change: &PendingChange) {
        let previous = self.leases.lease(change.vrf, change.addr);
        self.leases
            .apply(change.to_lease(NodeId(1), previous.as_ref()));
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

/// A request as a table row describes it.
#[derive(Debug, Clone)]
pub struct Ask {
    /// Option 53.
    pub kind: MessageType,
    /// The client.
    pub client: u8,
    /// Option 61 of type 1 with the MAC.
    pub with_id: bool,
    /// `giaddr`.
    pub giaddr: Option<Ipv4Addr>,
    /// `ciaddr`.
    pub ciaddr: Option<Ipv4Addr>,
    /// The broadcast flag.
    pub broadcast: bool,
    /// Option 50.
    pub requested: Option<Ipv4Addr>,
    /// Option 54.
    pub server_id: Option<Ipv4Addr>,
    /// Option 51.
    pub lease_secs: Option<u32>,
    /// Option 55.
    pub prl: Vec<u8>,
    /// Option 82.
    pub relay: Option<Vec<u8>>,
    /// Option 118.
    pub subnet: Option<Ipv4Addr>,
}

impl Ask {
    /// A relayed request of client `k` with option 61.
    pub fn new(kind: MessageType, client: u8) -> Self {
        Self {
            kind,
            client,
            with_id: true,
            giaddr: Some(RELAY),
            ciaddr: None,
            broadcast: false,
            requested: None,
            server_id: None,
            lease_secs: None,
            prl: vec![code::SUBNET_MASK, code::ROUTERS, code::DOMAIN_NAME_SERVERS],
            relay: None,
            subnet: None,
        }
    }

    /// The octets.
    pub fn bytes(&self) -> Vec<u8> {
        let mut buf = [0u8; 1024];
        let mut builder = MessageBuilder::new(&mut buf, 1024).expect("a builder");
        builder
            .op(BOOTREQUEST)
            .htype(1)
            .hlen(6)
            .hops(u8::from(self.giaddr.is_some()))
            .xid(0x5e00_5300 | u32::from(self.client))
            .broadcast(self.broadcast)
            .ciaddr(self.ciaddr.unwrap_or(Ipv4Addr::UNSPECIFIED))
            .giaddr(self.giaddr.unwrap_or(Ipv4Addr::UNSPECIFIED));
        builder.chaddr(&mac(self.client)).expect("chaddr");
        builder.message_type(self.kind).expect("53");
        if self.with_id {
            let mut id = vec![1];
            id.extend(mac(self.client));
            builder.option(code::CLIENT_IDENTIFIER, &id).expect("61");
        }
        if let Some(addr) = self.requested {
            builder
                .option(code::REQUESTED_ADDRESS, &addr.octets())
                .expect("50");
        }
        if let Some(addr) = self.server_id {
            builder.server_identifier(addr).expect("54");
        }
        if let Some(secs) = self.lease_secs {
            builder.lease_time(secs).expect("51");
        }
        if let Some(addr) = self.subnet {
            builder
                .option(code::SUBNET_SELECTION, &addr.octets())
                .expect("118");
        }
        if !self.prl.is_empty() {
            builder
                .option(code::PARAMETER_REQUEST_LIST, &self.prl)
                .expect("55");
        }
        if let Some(relay) = &self.relay {
            builder.relay_agent_info(relay).expect("82");
        }
        let len = builder.finish().expect("finish");
        buf[..len].to_vec()
    }
}
