#![no_main]
//! The DHCPv6 engine behind the codec: what the server does with a datagram that a client
//! or a relay sent, on a configuration of three scopes (`tenko_dhcp::v6::engine::handle`),
//! with the `IA_NA` and `IA_PD` options, the relay chain and the trusted relays.
//!
//! The input is one control octet and up to four datagrams, each behind a two-octet length
//! (the last one may run to the end of the input). The engine handles them in turn at ten
//! seconds apart and commits what it asks to commit, so an address can be solicited and
//! requested, and a lease renewed, declined or released. The control octet picks the sender
//! (bits 0 and 1: the trusted relay, a client's link-local address, a sender that is not a
//! trusted relay, the trusted relay with a listener address on no scope), the listener's
//! mode (bit 2), the security profile (bits 3 and 4) and whether the store refuses writes
//! (bit 5).
//!
//! It checks that every reply fits the reply buffer, parses, and goes to the sender on the
//! port of its kind; that a reply to a relayed request is a RELAY-REPL per relay of the
//! request, with the hop count, the link and peer addresses and the Interface-Id as the
//! relay sent them; that the innermost reply has the request's transaction id, the message
//! type the engine named, the server's DUID and the client's; that an address or a prefix
//! the reply gives lies in a configured scope or delegation pool; and that a committed
//! change binds only such addresses and prefixes of the scope that holds them. The decoded
//! request is also read through the typed accessors the engine uses.

use std::{
    net::{Ipv6Addr, SocketAddrV6},
    time::Duration,
};

use ipnet::{IpNet, Ipv6Net};
use libfuzzer_sys::fuzz_target;
use tenko_core::{
    HostId, InterfaceId, NodeId, PrefixId, RangeId, Revision, VrfId,
    dhcp::{
        BindingState, DdnsPolicy, Lease6Kind, LeaseEventKind, LeaseTimes, OptionSpace, OptionValue,
        Scope6Settings, TrustedRelay,
    },
    serde_util::HexBytes,
};
use tenko_dhcp::{
    guard::{DhcpProfile, Guard},
    image::{ConfigImage, ImageBuilder},
    relay::RelayTrust,
    v4::engine::ListenMode,
    v6::{
        Message, MessageType, RelayChain,
        engine::{
            Action6, Context6, Destination6, Engine6Settings, Offers6, REPLY_CAPACITY6, Received6,
            Scratch6, handle,
        },
        image::{PdPool6Image, Pool6Image, Reservation6Image, Reservation6Key, Scope6Image},
        lease::{Binding6, Lease6Index, Lease6Table, PendingChange6},
    },
};
use tenko_fuzz::{datagrams, mac, t0};

/// The server's DUID: DUID-UUID.
const SERVER_DUID: [u8; 18] = [
    0, 4, 0x2b, 0x5c, 0x7e, 0x11, 0x2a, 0x9d, 0x4e, 0x0f, 0x8c, 0x31, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e,
    0xaf,
];

/// The trusted relay's address on the server's side.
const RELAY: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xff, 0, 0, 0, 0, 1);
/// A client's link-local address.
const CLIENT: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0200, 0x5eff, 0xfe00, 0x5301);
/// A sender outside the trusted relays.
const STRANGER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xdead, 0, 0, 0, 0, 0x77);
/// The listener's address, on the link of scope B.
const LISTENER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 3, 0, 0, 0, 0, 0x53);
/// A listener address that no scope holds.
const ELSEWHERE: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 9, 0, 0, 0, 0, 0x53);

/// A DUID-LL of a MAC.
fn duid_ll(mac: [u8; 6]) -> Vec<u8> {
    let mut out = vec![0, 3, 0, 1];
    out.extend(mac);
    out
}

fn addr(text: &str) -> Ipv6Addr {
    text.parse().expect("an address")
}

fn option(code: u16, data: Vec<u8>) -> OptionValue {
    OptionValue {
        space: OptionSpace::dhcp6(),
        code,
        data: HexBytes(data),
    }
}

fn times(valid: u32) -> LeaseTimes {
    LeaseTimes {
        default_secs: valid,
        min_secs: 600,
        max_secs: 8_000,
        t1_secs: None,
        t2_secs: None,
    }
}

/// A scope on `network` with one pool of `first` to `last`.
fn scope(
    prefix: PrefixId,
    vrf: VrfId,
    network: &str,
    (first, last): (&str, &str),
    interface_id: Option<&[u8]>,
) -> Scope6Image {
    let network: Ipv6Net = network.parse().expect("a network");
    Scope6Image {
        prefix,
        vrf,
        network,
        authoritative: true,
        restricted: false,
        lease: times(4_000),
        v6: Scope6Settings {
            preferred_secs: Some(3_000),
            ..Scope6Settings::default()
        },
        interface_id: interface_id.map(<[u8]>::to_vec),
        shared_network: None,
        pools: vec![Pool6Image {
            range: RangeId::generate(),
            first: addr(first),
            last: addr(last),
            lease: times(4_000),
            options: Vec::new(),
        }],
        pd_pools: Vec::new(),
        excluded: Vec::new(),
        options: vec![
            option(23, addr("2001:db8::53").octets().to_vec()),
            option(24, b"\x07example\x04test\x00".to_vec()),
            option(56, addr("2001:db8::123").octets().to_vec()),
        ],
        ddns: DdnsPolicy::default(),
    }
}

/// A delegation pool of `first` to `last` in prefixes of `len`.
fn pd_pool(first: &str, last: &str, len: u8) -> PdPool6Image {
    PdPool6Image {
        range: RangeId::generate(),
        first: addr(first),
        last: addr(last),
        delegated_len: len,
        lease: times(6_000),
        options: Vec::new(),
    }
}

/// The image: scope A `2001:db8:1::/64` behind the relay with the Interface-Id `eth1`, a
/// pool, a delegation pool of sixteen /60 prefixes and two reservations (one by DUID, one
/// by MAC); scope B `2001:db8:3::/64` on the listener's link with an exclusion; scope C
/// `2001:db8:2::/64` behind the relay with the Interface-Id `vlan2`, two addresses, two /64
/// prefixes and no Rapid Commit; client `:10` holds `2001:db8:1::110`.
struct World {
    image: ConfigImage,
    table: Lease6Index,
    offers: Offers6,
    settings: Engine6Settings,
    guard: Guard,
}

impl World {
    fn new(profile: DhcpProfile) -> Self {
        let vrf = VrfId::generate();
        let (a, b, c) = (
            PrefixId::generate(),
            PrefixId::generate(),
            PrefixId::generate(),
        );
        let mut scope_a = scope(
            a,
            vrf,
            "2001:db8:1::/64",
            ("2001:db8:1::100", "2001:db8:1::1ff"),
            Some(b"eth1"),
        );
        scope_a.pd_pools = vec![pd_pool(
            "2001:db8:180:100::",
            "2001:db8:180:1ff:ffff:ffff:ffff:ffff",
            60,
        )];
        let mut scope_b = scope(
            b,
            vrf,
            "2001:db8:3::/64",
            ("2001:db8:3::100", "2001:db8:3::10f"),
            None,
        );
        scope_b.excluded = vec![(addr("2001:db8:3::108"), addr("2001:db8:3::109"))];
        let mut scope_c = scope(
            c,
            vrf,
            "2001:db8:2::/64",
            ("2001:db8:2::100", "2001:db8:2::101"),
            Some(b"vlan2"),
        );
        scope_c.v6.rapid_commit = Some(false);
        scope_c.pd_pools = vec![pd_pool(
            "2001:db8:ac::",
            "2001:db8:ac:1:ffff:ffff:ffff:ffff",
            64,
        )];
        // The global relay may name the links of two scopes, the third is not its to name;
        // the link-local relays any link.
        let prefix = |text: &str| -> IpNet { text.parse().expect("a prefix") };
        let relays = [
            TrustedRelay {
                relay: prefix("2001:db8:ff::1/128"),
                links: vec![prefix("2001:db8:1::/64"), prefix("2001:db8:3::/64")],
            },
            TrustedRelay::any_link(prefix("fe80::/10")),
        ];
        let mut builder = ImageBuilder::new(Revision(1));
        builder.relays(RelayTrust::new(Some(&relays)));
        builder.v6().add_scope(scope_a);
        builder.v6().add_scope(scope_b);
        builder.v6().add_scope(scope_c);
        for (key, address) in [
            (Reservation6Key::Duid(duid_ll(mac(0x20))), "2001:db8:1::50"),
            (Reservation6Key::Mac(mac(0x21)), "2001:db8:1::51"),
        ] {
            let _ = builder.v6().add_reservation(Reservation6Image {
                scope: a,
                addr: addr(address),
                host: HostId::generate(),
                interface: InterfaceId::generate(),
                key,
                options: Vec::new(),
            });
        }
        let mut world = Self {
            image: builder.build(),
            table: Lease6Index::new(),
            offers: Offers6::with_capacity(256),
            settings: Engine6Settings::default(),
            guard: Guard::new(profile),
        };
        let mut held = PendingChange6::new(&duid_ll(mac(0x10)), t0());
        let pushed = held.push(Binding6 {
            event: LeaseEventKind::Granted,
            kind: Lease6Kind::Na,
            vrf,
            scope: a,
            iaid: 1,
            addr: addr("2001:db8:1::110"),
            prefix_len: 128,
            state: BindingState::Active,
            preferred_ends: t0().checked_add(Duration::from_secs(2_000)).expect("time"),
            ends: t0().checked_add(Duration::from_secs(3_600)).expect("time"),
        });
        assert!(pushed);
        world.commit(&held);
        world
    }

    /// Applies the rows of a change to the table, as the store does once it commits.
    fn commit(&mut self, change: &PendingChange6) {
        for binding in change.bindings() {
            let previous = self.table.get(binding.vrf, binding.addr).cloned();
            self.table.apply_at(
                change.to_lease(binding, NodeId(1), previous.as_ref()),
                Revision::ZERO,
            );
        }
    }
}

/// Reads a decoded request through the typed accessors the engine uses.
fn read_request(chain: &RelayChain<'_>) {
    for relay in chain.relays() {
        let _ = relay.interface_id();
        let _ = relay
            .remote_id()
            .ok()
            .flatten()
            .map(|remote| remote.as_bytes().len());
        let _ = relay
            .client_link_layer()
            .ok()
            .flatten()
            .map(|link| link.mac());
    }
    let _ = chain.link_address();
    let _ = chain.interface_id();
    let client = chain.client();
    if let Ok(Some(duid)) = client.client_id() {
        let _ = (duid.kind(), duid.body(), duid.link_layer());
        let _ = (duid.time(), duid.enterprise(), duid.uuid());
    }
    let _ = client.server_id();
    if let Ok(Some(request)) = client.option_request() {
        let _ = request.codes().count();
    }
    let _ = client.elapsed_time();
    let _ = client.rapid_commit();
    if let Ok(Some(fqdn)) = client.client_fqdn() {
        let _ = (fqdn.flags(), fqdn.flags_v4(), fqdn.name_bytes());
    }
    for ia in client.ia_nas().flatten() {
        for address in ia.addresses().flatten() {
            let _ = (ia.iaid, address.addr, address.preferred, address.valid);
        }
    }
    for ia in client.ia_pds().flatten() {
        for prefix in ia.prefixes().flatten() {
            let _ = (ia.iaid, prefix.prefix, prefix.prefix_len, prefix.valid);
        }
    }
}

/// Checks the reply in `reply` against the request it answers.
fn check_reply(
    world: &World,
    chain: &RelayChain<'_>,
    reply: &[u8],
    kind: MessageType,
    dest: Destination6,
    source: SocketAddrV6,
) {
    let client = chain.client();
    let mut layer = Message::parse(reply).expect("a reply parses");
    // `RelayChain::parse` walks RELAY-FORW only, so the RELAY-REPL layers are walked here.
    for relay in chain.relays() {
        assert_eq!(layer.kind(), MessageType::RelayRepl);
        assert_eq!(layer.hop_count(), relay.hop_count());
        assert_eq!(layer.link_address(), relay.link_address());
        assert_eq!(layer.peer_address(), relay.peer_address());
        assert_eq!(
            layer.interface_id().ok().flatten(),
            relay.interface_id().ok().flatten()
        );
        layer = layer
            .relay_message()
            .expect("the relayed reply parses")
            .expect("a RELAY-REPL carries a message");
    }
    assert!(!layer.is_relay());
    assert_eq!(layer.kind(), kind);
    assert_eq!(layer.transaction_id(), client.transaction_id());
    layer
        .validate()
        .expect("the options of a reply are well formed");
    assert_eq!(
        layer
            .server_id()
            .expect("a walk")
            .map(|duid| duid.as_bytes()),
        Some(&SERVER_DUID[..])
    );
    assert_eq!(
        layer
            .client_id()
            .expect("a walk")
            .map(|duid| duid.as_bytes()),
        client
            .client_id()
            .ok()
            .flatten()
            .map(|duid| duid.as_bytes())
    );
    match dest {
        Destination6::Relay(to) => {
            assert!(chain.is_relayed());
            assert_eq!(to.port(), world.settings.relay_port);
            assert_eq!(to.ip(), source.ip());
        }
        Destination6::Client(to) => {
            assert!(!chain.is_relayed());
            assert_eq!(to.port(), world.settings.client_port);
            assert_eq!(to.ip(), source.ip());
        }
    }
    let scopes = world.image.v6().scopes();
    for ia in layer.ia_nas() {
        let ia = ia.expect("an IA_NA of a reply parses");
        for address in ia.addresses() {
            let address = address.expect("an address of a reply parses");
            if address.valid != 0 {
                assert!(address.preferred <= address.valid);
                assert!(
                    scopes
                        .iter()
                        .any(|scope| scope.network.contains(&address.addr))
                );
            }
        }
    }
    for ia in layer.ia_pds() {
        let ia = ia.expect("an IA_PD of a reply parses");
        for prefix in ia.prefixes() {
            let prefix = prefix.expect("a prefix of a reply parses");
            if prefix.valid != 0 {
                assert!(prefix.preferred <= prefix.valid);
                assert!(
                    scopes
                        .iter()
                        .any(|scope| scope.pd_pool_of(prefix.prefix, prefix.prefix_len).is_some())
                );
            }
        }
    }
}

/// Checks that a change binds only addresses and prefixes of the scope it names.
fn check_change(world: &World, change: &PendingChange6) {
    for binding in change.bindings() {
        let scope = world
            .image
            .v6()
            .scope(binding.scope)
            .expect("a binding names a configured scope");
        assert_eq!(binding.vrf, scope.vrf);
        match binding.kind {
            Lease6Kind::Na => {
                assert_eq!(binding.prefix_len, 128);
                assert!(scope.network.contains(&binding.addr));
            }
            Lease6Kind::Pd => {
                assert!(scope.pd_pool_of(binding.addr, binding.prefix_len).is_some());
            }
        }
    }
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
    let (ip, port, local) = match control & 3 {
        0 => (RELAY, 547, LISTENER),
        1 => (CLIENT, 546, LISTENER),
        2 => (STRANGER, 547, LISTENER),
        _ => (RELAY, 547, ELSEWHERE),
    };
    let source = SocketAddrV6::new(ip, port, 0, 0);
    let accepting = control & 0x20 == 0;
    let mut world = World::new(profile);
    let mut scratch = Scratch6::new();
    for (step, bytes) in datagrams(rest, 4).into_iter().enumerate() {
        let request = Message::parse(bytes)
            .ok()
            .and_then(|message| RelayChain::parse(message).ok());
        if let Some(chain) = &request {
            read_request(chain);
        }
        let now = t0()
            .checked_add(Duration::from_secs(10 * step as u64))
            .expect("time");
        let answer = {
            let ctx = Context6 {
                image: &world.image,
                leases: &world.table,
                offers: &world.offers,
                settings: &world.settings,
                guard: &world.guard,
                server_duid: &SERVER_DUID,
                accepting,
                now,
            };
            handle(
                &ctx,
                &Received6 {
                    bytes,
                    source,
                    local,
                    mode,
                },
                &mut scratch,
            )
        };
        let (kind, len, dest, commit) = match answer.action {
            Action6::Reply { kind, len, dest } => (Some(kind), len, Some(dest), false),
            Action6::CommitThenReply { kind, len, dest } => (Some(kind), len, Some(dest), true),
            Action6::Drop(_) | Action6::Ignore(_) => (None, 0, None, false),
        };
        if let (Some(kind), Some(dest)) = (kind, dest) {
            let chain = request
                .as_ref()
                .expect("a reply answers a request that parses");
            assert!(len <= REPLY_CAPACITY6);
            assert_eq!(answer.request, Some(chain.client().kind()));
            match chain.client().kind() {
                MessageType::Solicit => {
                    assert!(matches!(kind, MessageType::Advertise | MessageType::Reply));
                }
                _ => assert_eq!(kind, MessageType::Reply),
            }
            check_reply(&world, chain, &scratch.reply[..len], kind, dest, source);
        }
        if commit {
            // A change commits only while the store takes writes, and binds something.
            assert!(accepting);
            assert!(!scratch.change.is_empty());
            check_change(&world, &scratch.change);
            world.commit(&scratch.change);
        }
    }
});
