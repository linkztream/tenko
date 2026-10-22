//! The world of the class, policy and boot tests (WP8.4), shared by `tests/classes.rs` and
//! the allocation test: one configuration image with classes, policies, a restricted pool
//! and reservations, and a request builder with the options classes test.
//!
//! The image: scope L `192.0.2.0/24` (relayed through 192.0.2.1; pool .100 to .199, and
//! pool .200 to .209 for the class `pxe` only; option 150 names the TFTP server 192.0.2.5),
//! scope K `198.51.100.0/24` (relayed through 198.51.100.1; it admits the class `printers`
//! only), and these policies of scope L, in order:
//!
//! 1. `ipxe` (user class `iPXE`): option 67 `http://192.0.2.5/boot.ipxe`;
//! 2. `http-boot` (vendor class prefix `HTTPClient`): option 67
//!    `http://192.0.2.5/ipxe.efi`;
//! 3. `uefi` (architecture 7 or 9): option 67 `ipxe.efi`;
//! 4. `bios` (architecture 0 and vendor class prefix `PXEClient`): option 67
//!    `undionly.kpxe`, options 209 and 210 (PXELINUX);
//! 5. `printers` (vendor class prefix `Printer`): the range .150 to .159 and option 15
//!    `printers.example.test`;
//! 6. `iot` (MAC `00:00:5e:*:*:45`, a wildcard pattern): lease times of 600 s.
//!
//! Reservations: 192.0.2.20 for the MAC :20 (keyed by MAC), 192.0.2.30 for the client
//! identifier `ff 00 00 00 01 00 01 ...` (keyed by a DUID-style client identifier), and for
//! client :31 both: 192.0.2.31 by MAC and 192.0.2.32 by its client identifier of type 1.
//! Documentation addresses (RFC 5737) and MACs (RFC 7042) only.

#![allow(dead_code, reason = "each test binary uses a part of the world")]

use std::net::{Ipv4Addr, SocketAddrV4};

use ipnet::Ipv4Net;
use tenko_core::{
    HostId, InterfaceId, PrefixId, RangeId, Revision, Timestamp, VrfId,
    dhcp::{
        AddressRange, Class, ClassId, Condition, DdnsPolicy, Join, LeaseTimes, MacPattern, Match,
        OptionValue, Policy, PolicyAction, PolicyId, Term,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
};
use tenko_dhcp::{
    allocator::SingleNode,
    image::{ConfigImage, ImageBuilder, PoolImage, ReservationImage, ScopeImage},
    lease::MemLeaseTable,
    v4::{
        BOOTREQUEST, MessageBuilder, MessageType, code,
        engine::{
            self, Answer, Context, EngineSettings, HashedAllocator, ListenMode, OfferTable,
            Received, Scratch,
        },
    },
};

/// The listener's address.
pub const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
/// The relay of scope L.
pub const RELAY_L: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// The relay of scope K.
pub const RELAY_K: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
/// The TFTP and HTTP boot server.
pub const BOOT_SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 5);

/// The time of the tests.
pub fn t0() -> Timestamp {
    "2026-10-22T12:00:00Z".parse().expect("time")
}

/// The MAC of client `k`.
pub fn mac(k: u8) -> [u8; 6] {
    [0x00, 0x00, 0x5e, 0x00, 0x53, k]
}

/// An address.
pub fn ip(text: &str) -> Ipv4Addr {
    text.parse().expect("an address")
}

fn stamp() -> Stamp {
    Stamp::new(t0(), Principal::system(SystemComponent::Dhcp))
}

fn text(code: u8, value: &str) -> OptionValue {
    OptionValue::v4(code, value.as_bytes().to_vec())
}

/// The DUID-style client identifier of the reservation of 192.0.2.30 (RFC 4361: type 255,
/// an IAID and a DUID-LLT).
pub fn duid_id() -> Vec<u8> {
    let mut id = vec![0xff, 0, 0, 0, 1, 0, 1, 0, 1, 0x2a, 0x2b, 0x2c, 0x2d, 0, 1];
    id.extend(mac(0x30));
    id
}

/// Option 61 of type 1 with the MAC of client `k`, as Windows sends it.
pub fn type1_id(k: u8) -> Vec<u8> {
    let mut id = vec![1];
    id.extend(mac(k));
    id
}

fn class(name: &str, matches: Vec<Match>) -> Class {
    Class {
        id: ClassId::generate(),
        name: name.to_owned(),
        matches,
        description: None,
        created: stamp(),
        updated: stamp(),
    }
}

fn policy(scope: PrefixId, order: u32, join: Join, terms: Vec<Term>) -> Policy {
    Policy {
        id: PolicyId::generate(),
        name: format!("policy-{order}"),
        scope: Some(scope),
        order,
        enabled: true,
        condition: Condition { join, terms },
        action: PolicyAction::default(),
        description: None,
        created: stamp(),
        updated: stamp(),
    }
}

fn pool(network: Ipv4Net, first: u8, last: u8, classes: Vec<ClassId>) -> PoolImage {
    let [a, b, c, _] = network.network().octets();
    PoolImage {
        range: RangeId::generate(),
        first: Ipv4Addr::new(a, b, c, first),
        last: Ipv4Addr::new(a, b, c, last),
        lease: LeaseTimes::default(),
        classes,
        options: Vec::new(),
    }
}

fn scope(
    prefix: PrefixId,
    vrf: VrfId,
    network: &str,
    pools: Vec<(u8, u8, Vec<ClassId>)>,
    classes: Vec<ClassId>,
    options: Vec<OptionValue>,
) -> ScopeImage {
    let network: Ipv4Net = network.parse().expect("a network");
    ScopeImage {
        prefix,
        vrf,
        network,
        authoritative: true,
        restricted: false,
        server_id: None,
        lease: LeaseTimes::default(),
        shared_network: None,
        pools: pools
            .into_iter()
            .map(|(first, last, classes)| pool(network, first, last, classes))
            .collect(),
        excluded: Vec::new(),
        options,
        classes,
        ddns: DdnsPolicy::default(),
    }
}

/// The world.
pub struct World {
    /// The image.
    pub image: ConfigImage,
    /// The leases (none).
    pub leases: MemLeaseTable,
    /// The offers held.
    pub offers: OfferTable,
    /// The settings.
    pub settings: EngineSettings,
    /// Scope L.
    pub l: PrefixId,
    /// Scope K.
    pub k: PrefixId,
}

impl World {
    /// The world of the module comment.
    #[allow(clippy::too_many_lines, reason = "the world, read top to bottom")]
    pub fn new() -> Self {
        let vrf = VrfId::generate();
        let (l, k) = (PrefixId::generate(), PrefixId::generate());
        let prefix = |value: &str| Match::VendorClass {
            value: value.to_owned(),
            prefix: true,
        };
        let ipxe = class(
            "ipxe",
            vec![Match::UserClass {
                value: "iPXE".to_owned(),
            }],
        );
        let http = class("http-boot", vec![prefix("HTTPClient")]);
        let uefi = class(
            "uefi",
            vec![
                Match::Architecture { code: 7 },
                Match::Architecture { code: 9 },
            ],
        );
        let bios = class("bios", vec![Match::Architecture { code: 0 }]);
        let pxe = class("pxe", vec![prefix("PXEClient")]);
        let printers = class("printers", vec![prefix("Printer")]);
        let iot = class(
            "iot",
            vec![Match::Mac {
                pattern: MacPattern::new("00:00:5e:*:*:45").expect("a pattern"),
            }],
        );
        let mut builder = ImageBuilder::new(Revision(1));
        builder.scope(scope(
            l,
            vrf,
            "192.0.2.0/24",
            vec![(100, 199, Vec::new()), (200, 209, vec![pxe.id])],
            Vec::new(),
            vec![
                OptionValue::v4(code::ROUTERS, RELAY_L.octets().to_vec()),
                text(code::DOMAIN_NAME, "example.test"),
                OptionValue::v4(150, BOOT_SERVER.octets().to_vec()),
            ],
        ));
        builder.scope(scope(
            k,
            vrf,
            "198.51.100.0/24",
            vec![(100, 199, Vec::new())],
            vec![printers.id],
            vec![OptionValue::v4(code::ROUTERS, RELAY_K.octets().to_vec())],
        ));
        let mut policies = vec![
            policy(l, 1, Join::Or, vec![Term::Class(ipxe.id)]),
            policy(l, 2, Join::Or, vec![Term::Class(http.id)]),
            policy(l, 3, Join::Or, vec![Term::Class(uefi.id)]),
            policy(
                l,
                4,
                Join::And,
                vec![Term::Class(bios.id), Term::Class(pxe.id)],
            ),
            policy(l, 5, Join::Or, vec![Term::Class(printers.id)]),
            policy(l, 6, Join::Or, vec![Term::Class(iot.id)]),
        ];
        policies[4].action.range = Some(AddressRange {
            first: ip("192.0.2.150").into(),
            last: ip("192.0.2.159").into(),
        });
        policies[5].action.lease = Some(LeaseTimes::fixed(600));
        let sets = [
            vec![text(code::BOOTFILE_NAME, "http://192.0.2.5/boot.ipxe")],
            vec![text(code::BOOTFILE_NAME, "http://192.0.2.5/ipxe.efi")],
            vec![text(code::BOOTFILE_NAME, "ipxe.efi")],
            vec![
                text(code::BOOTFILE_NAME, "undionly.kpxe"),
                text(209, "pxelinux.cfg/default"),
                text(210, "/tftpboot/"),
            ],
            vec![text(code::DOMAIN_NAME, "printers.example.test")],
            Vec::new(),
        ];
        for (policy, set) in policies.iter().zip(sets) {
            builder.policy_options(policy.id, set);
        }
        let reservation = |addr: &str, identity: Vec<u8>| ReservationImage {
            scope: l,
            addr: ip(addr),
            host: HostId::generate(),
            interface: InterfaceId::generate(),
            identity,
            options: vec![text(code::DOMAIN_NAME, "reserved.example.test")],
        };
        let hardware = |k: u8| {
            let mut out = vec![0, 1];
            out.extend(mac(k));
            out
        };
        let mut by_id = vec![1];
        by_id.extend(type1_id(0x31));
        let mut duid = vec![1];
        duid.extend(duid_id());
        for held in [
            reservation("192.0.2.20", hardware(0x20)),
            reservation("192.0.2.30", duid),
            reservation("192.0.2.31", hardware(0x31)),
            reservation("192.0.2.32", by_id),
        ] {
            assert!(builder.reservation(held).is_none());
        }
        builder
            .classes(vec![ipxe, http, uefi, bios, pxe, printers, iot])
            .policies(policies);
        Self {
            image: builder.build(),
            leases: MemLeaseTable::default(),
            offers: OfferTable::with_capacity(1_024),
            settings: EngineSettings::default(),
            l,
            k,
        }
    }

    fn ctx(&self) -> Context<'_> {
        Context {
            image: &self.image,
            leases: &self.leases,
            offers: &self.offers,
            ownership: &SingleNode,
            allocator: &HashedAllocator,
            settings: &self.settings,
            accepting: true,
            now: t0(),
        }
    }

    /// Runs the engine on `bytes`, from `source`.
    pub fn run_from(&self, bytes: &[u8], source: SocketAddrV4, scratch: &mut Scratch) -> Answer {
        engine::handle(
            &self.ctx(),
            &Received {
                bytes,
                source,
                local: SERVER,
                mode: ListenMode::Relay,
            },
            scratch,
        )
    }

    /// Runs the engine on `bytes` from the relay of scope L.
    pub fn run(&self, bytes: &[u8], scratch: &mut Scratch) -> Answer {
        self.run_from(bytes, SocketAddrV4::new(RELAY_L, 67), scratch)
    }

    /// Runs the proxy DHCP path on `bytes`, from `source`.
    pub fn proxy(&self, bytes: &[u8], source: SocketAddrV4, scratch: &mut Scratch) -> Answer {
        engine::boot::proxy(
            &self.ctx(),
            &Received {
                bytes,
                source,
                local: SERVER,
                mode: ListenMode::Relay,
            },
            scratch,
        )
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

/// A request.
#[derive(Debug, Clone)]
pub struct Ask {
    /// Option 53.
    pub kind: MessageType,
    /// The client (the last octet of its MAC).
    pub client: u8,
    /// Option 61.
    pub client_id: Option<Vec<u8>>,
    /// `giaddr`.
    pub giaddr: Option<Ipv4Addr>,
    /// `ciaddr`.
    pub ciaddr: Option<Ipv4Addr>,
    /// Option 50.
    pub requested: Option<Ipv4Addr>,
    /// Option 54.
    pub server_id: Option<Ipv4Addr>,
    /// Option 55.
    pub prl: Vec<u8>,
    /// Option 60.
    pub vendor_class: Option<Vec<u8>>,
    /// Option 77.
    pub user_class: Option<Vec<u8>>,
    /// Option 93.
    pub architecture: Option<u16>,
    /// Option 97 (a UUID of type 0).
    pub machine_id: bool,
}

impl Ask {
    /// A DISCOVER of client `k` through the relay of scope L, without option 61.
    pub fn discover(client: u8) -> Self {
        Self {
            kind: MessageType::Discover,
            client,
            client_id: None,
            giaddr: Some(RELAY_L),
            ciaddr: None,
            requested: None,
            server_id: None,
            prl: vec![code::SUBNET_MASK, code::ROUTERS, code::DOMAIN_NAME],
            vendor_class: None,
            user_class: None,
            architecture: None,
            machine_id: false,
        }
    }

    /// A PXE firmware DISCOVER of client `k` for the architecture `arch`: option 60
    /// `PXEClient:Arch:<arch>:UNDI:002001`, options 93, 94 and 97, the PXE parameter list.
    pub fn pxe(client: u8, arch: u16) -> Self {
        Self {
            vendor_class: Some(format!("PXEClient:Arch:{arch:05}:UNDI:002001").into_bytes()),
            architecture: Some(arch),
            machine_id: true,
            prl: vec![
                1, 2, 3, 5, 6, 11, 12, 13, 15, 16, 17, 18, 43, 54, 60, 67, 128, 129,
            ],
            ..Self::discover(client)
        }
    }

    /// Option 61.
    pub fn with_id(mut self, id: Vec<u8>) -> Self {
        self.client_id = Some(id);
        self
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
            .xid(0x5e00_8400 | u32::from(self.client))
            .ciaddr(self.ciaddr.unwrap_or(Ipv4Addr::UNSPECIFIED))
            .giaddr(self.giaddr.unwrap_or(Ipv4Addr::UNSPECIFIED));
        builder.chaddr(&mac(self.client)).expect("chaddr");
        builder.message_type(self.kind).expect("53");
        if let Some(id) = &self.client_id {
            builder.option(code::CLIENT_IDENTIFIER, id).expect("61");
        }
        if let Some(addr) = self.requested {
            builder
                .option(code::REQUESTED_ADDRESS, &addr.octets())
                .expect("50");
        }
        if let Some(addr) = self.server_id {
            builder.server_identifier(addr).expect("54");
        }
        if let Some(class) = &self.vendor_class {
            builder
                .option(code::VENDOR_CLASS_IDENTIFIER, class)
                .expect("60");
        }
        if let Some(class) = &self.user_class {
            builder.option(code::USER_CLASS, class).expect("77");
        }
        if let Some(arch) = self.architecture {
            builder
                .option(code::CLIENT_ARCHITECTURE, &arch.to_be_bytes())
                .expect("93");
            builder
                .option(code::CLIENT_NETWORK_INTERFACE, &[1, 2, 1])
                .expect("94");
        }
        if self.machine_id {
            let mut uuid = vec![0];
            uuid.extend([0x5e; 16]);
            builder
                .option(code::CLIENT_MACHINE_IDENTIFIER, &uuid)
                .expect("97");
        }
        if !self.prl.is_empty() {
            builder
                .option(code::PARAMETER_REQUEST_LIST, &self.prl)
                .expect("55");
        }
        let len = builder.finish().expect("finish");
        buf[..len].to_vec()
    }
}
