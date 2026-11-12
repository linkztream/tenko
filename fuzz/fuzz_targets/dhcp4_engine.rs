#![no_main]
//! The DHCPv4 engine behind the codec: what the server does with a datagram that a client
//! or a relay sent, on a configuration of three scopes (`tenko_dhcp::v4::engine::handle`),
//! with the client's fingerprint, its class facts and the DDNS name of a committed lease.
//!
//! The input is one control octet and up to four datagrams, each behind a two-octet length
//! (the last one may run to the end of the input). The engine handles them in turn at ten
//! seconds apart and commits what it asks to commit, so an offer can be requested and a
//! lease renewed, declined or released. The control octet picks the sender (bits 0 and 1:
//! the relay, the client's `ciaddr`, `0.0.0.0`, a sender that is not a trusted relay), the
//! listener's mode (bit 2), the security profile (bits 3 and 4) and whether the store
//! refuses writes (bit 5).
//!
//! It checks that every reply parses, is a BOOTREPLY with the request's `xid` and the
//! message type the engine named, carries option 82 back as the request sent it, goes to
//! the relay agent of a relayed request, and offers or acknowledges only an address of a
//! configured scope; and that a DDNS name made from a committed lease is a host name under
//! its zone. A datagram is cut at the 4,096 octets the server's socket reads.

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use ipnet::Ipv4Net;
use libfuzzer_sys::fuzz_target;
use tenko_core::{
    HostId, InterfaceId, NodeId, PrefixId, RangeId, Revision, VrfId,
    dhcp::{BindingState, DdnsPolicy, LeaseEventKind, LeaseTimes, OptionValue, TrustedRelay},
    dns::DnsName,
};
use tenko_dhcp::{
    allocator::SingleNode,
    class::facts::Facts,
    ddns::names::{forward_name, is_host_label},
    fingerprint::fingerprint_of,
    guard::{DhcpProfile, Guard},
    image::{ConfigImage, ImageBuilder, PoolImage, ReservationImage, ScopeImage},
    lease::{LeaseTable, MemLeaseTable, PendingChange},
    v4::{
        BOOTREPLY, Message, MessageType, code,
        engine::{
            self, Action, Context, Destination, EngineSettings, HashedAllocator, ListenMode,
            OfferTable, Received, Scratch,
        },
    },
};
use tenko_fuzz::{datagrams, mac, t0};

/// The listener's address and the server identifier.
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
/// The receive buffer of the server: a longer datagram is cut by the socket.
const RECEIVE_BUFFER: usize = 4096;
/// The relay agent of scope A.
const RELAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// A sender outside the trusted relays.
const STRANGER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);

fn scope(prefix: PrefixId, vrf: VrfId, network: &str, authoritative: bool) -> ScopeImage {
    let network: Ipv4Net = network.parse().expect("a network");
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
            first: Ipv4Addr::new(a, b, c, 100),
            last: Ipv4Addr::new(a, b, c, 199),
            lease: LeaseTimes::default(),
            classes: Vec::new(),
            options: Vec::new(),
        }],
        excluded: Vec::new(),
        options: vec![
            OptionValue::v4(code::ROUTERS, vec![a, b, c, 1]),
            OptionValue::v4(code::DOMAIN_NAME_SERVERS, vec![a, b, c, 53]),
            OptionValue::v4(code::DOMAIN_NAME, b"example.test".to_vec()),
        ],
        classes: Vec::new(),
        ddns: DdnsPolicy::default(),
    }
}

/// The image: scope A `192.0.2.0/24` behind the relay with a reservation, scope B
/// `198.51.100.0/24` on the listener's link, scope C `203.0.113.0/24` not authoritative;
/// client `:10` holds 192.0.2.110.
struct World {
    image: ConfigImage,
    leases: MemLeaseTable,
    offers: OfferTable,
    settings: EngineSettings,
    guard: Guard,
    vrf: VrfId,
}

impl World {
    fn new(profile: DhcpProfile) -> Self {
        let vrf = VrfId::generate();
        let (a, b, c) = (
            PrefixId::generate(),
            PrefixId::generate(),
            PrefixId::generate(),
        );
        let mut builder = ImageBuilder::new(Revision(1));
        let mut scope_a = scope(a, vrf, "192.0.2.0/24", true);
        scope_a.excluded = vec![(Ipv4Addr::new(192, 0, 2, 100), Ipv4Addr::new(192, 0, 2, 104))];
        builder.scope(scope_a);
        builder.scope(scope(b, vrf, "198.51.100.0/24", true));
        builder.scope(scope(c, vrf, "203.0.113.0/24", false));
        let _ = builder.reservation(ReservationImage {
            scope: a,
            addr: Ipv4Addr::new(192, 0, 2, 20),
            host: HostId::generate(),
            interface: InterfaceId::generate(),
            identity: [&[0, 1][..], &mac(0x20)].concat(),
            options: vec![OptionValue::v4(
                code::BOOTFILE_NAME,
                b"boot/x64/bootfile.efi".to_vec(),
            )],
        });
        // The relay may name the links of two scopes; the third is not its to name.
        let relay = TrustedRelay {
            relay: "192.0.2.1/32".parse().expect("a prefix"),
            links: ["192.0.2.0/24", "198.51.100.0/24"]
                .map(|link| link.parse().expect("a prefix"))
                .to_vec(),
        };
        builder.relays(tenko_dhcp::relay::RelayTrust::new(Some(&[relay])));
        let guard = Guard::new(profile);
        let mut world = Self {
            image: builder.build(),
            leases: MemLeaseTable::default(),
            offers: OfferTable::with_capacity(64),
            settings: EngineSettings::default(),
            guard,
            vrf,
        };
        let held = PendingChange::new(
            LeaseEventKind::Granted,
            vrf,
            a,
            Ipv4Addr::new(192, 0, 2, 110),
            1,
            &mac(0x10),
            Some(&[&[1][..], &mac(0x10)].concat()),
            BindingState::Active,
            t0(),
            t0().checked_add(Duration::from_secs(3_600)).expect("time"),
        );
        world.leases.apply(held.to_lease(NodeId(1), None));
        world
    }

    fn commit(&mut self, change: &PendingChange) {
        let previous = self.leases.lease(change.vrf, change.addr);
        self.leases
            .apply(change.to_lease(NodeId(1), previous.as_ref()));
    }
}

/// Option 82 as a message carries it, every instance joined (RFC 3396).
fn relay_info(message: &Message<'_>) -> Option<Vec<u8>> {
    let mut scratch = [0u8; 1024];
    message
        .option_data(code::RELAY_AGENT_INFORMATION, &mut scratch)
        .ok()
        .flatten()
        .map(<[u8]>::to_vec)
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, rest)) = data.split_first() else {
        return;
    };
    let profile = match (control >> 3) & 3 {
        0 => DhcpProfile::Lab,
        1 => DhcpProfile::Home,
        2 => DhcpProfile::Standard,
        _ => DhcpProfile::Hardened,
    };
    let mode = if control & 4 == 0 {
        ListenMode::Relay
    } else {
        ListenMode::Direct
    };
    let mut world = World::new(profile);
    let mut scratch = Scratch::new();
    let zone = DnsName::new("example.test").expect("a zone");
    for (step, bytes) in datagrams(rest, 4).into_iter().enumerate() {
        let bytes = &bytes[..bytes.len().min(RECEIVE_BUFFER)];
        let request = Message::parse(bytes).ok();
        let source = match (control & 3, &request) {
            (0, _) => SocketAddrV4::new(RELAY, 67),
            (1, Some(message)) => SocketAddrV4::new(message.ciaddr(), 68),
            (3, _) => SocketAddrV4::new(STRANGER, 67),
            _ => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
        };
        let now = t0()
            .checked_add(Duration::from_secs(10 * step as u64))
            .expect("time");
        if let Some(message) = &request {
            let _ = fingerprint_of(message);
            let facts = Facts::of(message);
            let _ = facts.architecture();
            let _ = facts.has_user_class(b"iPXE");
        }
        let answer = {
            let ctx = Context {
                image: &world.image,
                leases: &world.leases,
                offers: &world.offers,
                ownership: &SingleNode,
                allocator: &HashedAllocator,
                settings: &world.settings,
                guard: &world.guard,
                accepting: control & 0x20 == 0,
                now,
            };
            engine::handle(
                &ctx,
                &Received {
                    bytes,
                    source,
                    local: SERVER,
                    mode,
                },
                &mut scratch,
            )
        };
        let (kind, len, dest, commit) = match answer.action {
            Action::Reply { kind, len, dest } => (Some(kind), len, Some(dest), false),
            Action::CommitThenReply { kind, len, dest } => (Some(kind), len, Some(dest), true),
            Action::Commit => (None, 0, None, true),
            Action::Drop(_) | Action::Ignore(_) => (None, 0, None, false),
        };
        if let Some(kind) = kind {
            let request = request
                .as_ref()
                .expect("a reply answers a request that parses");
            let reply = Message::parse(&scratch.reply[..len]).expect("a reply parses");
            assert_eq!(reply.op(), BOOTREPLY);
            assert_eq!(reply.xid(), request.xid());
            assert_eq!(reply.message_type(), Ok(Some(kind)));
            assert_eq!(relay_info(&reply), relay_info(request));
            // A relayed request is answered through its relay agent (RFC 2131 section 4.1).
            if !request.giaddr().is_unspecified() {
                assert_eq!(
                    dest,
                    Some(Destination::Relay(SocketAddrV4::new(
                        request.giaddr(),
                        world.settings.relay_port
                    )))
                );
            }
            if matches!(kind, MessageType::Offer | MessageType::Ack)
                && !reply.yiaddr().is_unspecified()
            {
                assert!(world.image.select(reply.yiaddr()).is_some());
            }
        }
        if commit {
            let change = scratch.change.clone();
            assert!(world.image.select(change.addr).is_some());
            assert_eq!(change.vrf, world.vrf);
            let fqdn = change.fqdn.to_text();
            let hostname = change.hostname.to_text();
            let policy = DdnsPolicy {
                legacy_clients: true,
                ..DdnsPolicy::default()
            };
            if let Ok(name) = forward_name(fqdn.as_deref(), hostname.as_deref(), &policy, &zone) {
                assert!(name != zone && name.is_subdomain_of(&zone));
                assert!(name.labels().all(is_host_label));
                assert_eq!(name.as_str(), name.as_str().to_ascii_lowercase());
            }
            world.commit(&change);
        }
    }
});
