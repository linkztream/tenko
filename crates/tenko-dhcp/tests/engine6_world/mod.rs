//! The world of the DHCPv6 engine tests: an image with scopes on `2001:db8:1::/64` and
//! `2001:db8:2::/64`, a lease table, the offers, the in-memory lease store, and clients that
//! write their messages with the codec's builder (documentation addresses, RFC 7042 MACs).

#![allow(dead_code, reason = "each test binary uses a part of the world")]

use std::net::{Ipv6Addr, SocketAddrV6};

use tenko_core::{
    HostId, InterfaceId, NodeId, PrefixId, RangeId, Timestamp, VrfId,
    dhcp::{DdnsPolicy, LeaseTimes, OptionValue, Scope6Settings},
    serde_util::HexBytes,
};
use tenko_dhcp::{
    image::{ConfigImage, ImageBuilder},
    store::Ticket,
    v4::engine::ListenMode,
    v6::{
        Message, MessageBuilder, MessageType, code,
        engine::{
            Action6, Answer6, Context6, Engine6Settings, Offers6, Received6, Scratch6, handle,
        },
        image::{PdPool6Image, Pool6Image, Reservation6Image, Reservation6Key, Scope6Image},
        lease::{
            Lease6Index, Lease6Table,
            store::{Lease6Store, MemLease6Store},
        },
    },
};

/// The server's DUID: DUID-UUID.
pub const SERVER_DUID: [u8; 18] = [
    0, 4, 0x2b, 0x5c, 0x7e, 0x11, 0x2a, 0x9d, 0x4e, 0x0f, 0x8c, 0x31, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e,
    0xaf,
];

/// The relay's address on the server's side.
pub const RELAY: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xff, 0, 0, 0, 0, 1);
/// The relay's link address on the first client link.
pub const LINK1: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
/// The relay's link address on the second client link.
pub const LINK2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1);
/// The listener's address.
pub const LISTENER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x53);

/// A DUID-LL of a MAC.
pub fn duid_ll(mac: [u8; 6]) -> Vec<u8> {
    let mut out = vec![0, 3, 0, 1];
    out.extend(mac);
    out
}

/// A MAC of the documentation range.
pub const fn mac(last: u8) -> [u8; 6] {
    [0, 0, 0x5e, 0, 0x53, last]
}

pub fn addr(text: &str) -> Ipv6Addr {
    text.parse().expect("an address")
}

/// A scope on `network` with one pool.
pub fn scope(prefix: PrefixId, network: &str, first: &str, last: &str) -> Scope6Image {
    Scope6Image {
        prefix,
        vrf: VrfId::from_uuid(uuid::Uuid::nil()),
        network: network.parse().expect("network"),
        authoritative: true,
        restricted: false,
        lease: LeaseTimes {
            default_secs: 4_000,
            min_secs: 600,
            max_secs: 8_000,
            t1_secs: None,
            t2_secs: None,
        },
        v6: Scope6Settings {
            preferred_secs: Some(3_000),
            ..Scope6Settings::default()
        },
        interface_id: None,
        shared_network: None,
        pools: vec![Pool6Image {
            range: RangeId::generate(),
            first: addr(first),
            last: addr(last),
            lease: LeaseTimes {
                default_secs: 4_000,
                min_secs: 600,
                max_secs: 8_000,
                t1_secs: None,
                t2_secs: None,
            },
            options: Vec::new(),
        }],
        pd_pools: Vec::new(),
        excluded: Vec::new(),
        options: vec![
            OptionValue {
                space: tenko_core::dhcp::OptionSpace::dhcp6(),
                code: 23,
                data: HexBytes(addr("2001:db8::53").octets().to_vec()),
            },
            OptionValue {
                space: tenko_core::dhcp::OptionSpace::dhcp6(),
                code: 24,
                data: HexBytes(b"\x07example\x04test\x00".to_vec()),
            },
            OptionValue {
                space: tenko_core::dhcp::OptionSpace::dhcp6(),
                code: 56,
                data: HexBytes(addr("2001:db8::123").octets().to_vec()),
            },
        ],
        ddns: DdnsPolicy::default(),
    }
}

/// The world.
pub struct World6 {
    pub image: ConfigImage,
    pub table: Lease6Index,
    pub offers: Offers6,
    pub store: MemLease6Store,
    pub settings: Engine6Settings,
    pub scratch: Box<Scratch6>,
    pub accepting: bool,
    pub now: Timestamp,
    pub prefix1: PrefixId,
    pub prefix2: PrefixId,
    ticket: u64,
}

/// Builds the image of the two scopes; `tune` changes them and adds reservations.
pub fn image(
    prefix1: PrefixId,
    prefix2: PrefixId,
    tune: impl FnOnce(&mut Scope6Image, &mut Scope6Image, &mut Vec<Reservation6Image>),
) -> ConfigImage {
    let mut first = scope(
        prefix1,
        "2001:db8:1::/64",
        "2001:db8:1::100",
        "2001:db8:1::1ff",
    );
    let mut second = scope(
        prefix2,
        "2001:db8:2::/64",
        "2001:db8:2::100",
        "2001:db8:2::1ff",
    );
    let mut reservations = Vec::new();
    tune(&mut first, &mut second, &mut reservations);
    let mut builder = ImageBuilder::new(tenko_core::Revision(1));
    builder.v6().add_scope(first);
    builder.v6().add_scope(second);
    for reservation in reservations {
        assert!(builder.v6().add_reservation(reservation).is_none());
    }
    builder.build()
}

/// A reservation of `address` for `key`.
pub fn reservation(scope: PrefixId, address: &str, key: Reservation6Key) -> Reservation6Image {
    Reservation6Image {
        scope,
        addr: addr(address),
        host: HostId::generate(),
        interface: InterfaceId::generate(),
        key,
        options: Vec::new(),
    }
}

impl World6 {
    /// The world with the default scopes.
    pub fn new() -> Self {
        Self::with(|_, _, _| {})
    }

    /// The world with scopes tuned by `tune`.
    pub fn with(
        tune: impl FnOnce(&mut Scope6Image, &mut Scope6Image, &mut Vec<Reservation6Image>),
    ) -> Self {
        let (prefix1, prefix2) = (PrefixId::generate(), PrefixId::generate());
        Self {
            image: image(prefix1, prefix2, tune),
            table: Lease6Index::new(),
            offers: Offers6::with_capacity(256),
            store: MemLease6Store::with_capacity(NodeId(1), 64),
            settings: Engine6Settings::default(),
            scratch: Scratch6::new(),
            accepting: true,
            now: Timestamp::now(),
            prefix1,
            prefix2,
            ticket: 0,
        }
    }

    /// Runs the engine on `bytes` received from `source`.
    pub fn handle_from(&mut self, bytes: &[u8], source: SocketAddrV6) -> Answer6 {
        let ctx = Context6 {
            image: &self.image,
            leases: &self.table,
            offers: &self.offers,
            settings: &self.settings,
            server_duid: &SERVER_DUID,
            accepting: self.accepting,
            now: self.now,
        };
        handle(
            &ctx,
            &Received6 {
                bytes,
                source,
                local: LISTENER,
                mode: ListenMode::Relay,
            },
            &mut self.scratch,
        )
    }

    /// Runs the engine on a relayed message (from the relay's address).
    pub fn handle(&mut self, bytes: &[u8]) -> Answer6 {
        self.handle_from(bytes, SocketAddrV6::new(RELAY, 547, 0, 0))
    }

    /// Runs the engine and, for a change to commit, commits it to the in-memory store
    /// and applies the rows to the table before the reply is read: what the server does.
    pub fn exchange(&mut self, bytes: &[u8]) -> (Answer6, Option<Vec<u8>>) {
        let answer = self.handle(bytes);
        let reply = match answer.action {
            Action6::Reply { len, .. } => Some(self.scratch.reply[..len].to_vec()),
            Action6::CommitThenReply { len, .. } => {
                self.ticket += 1;
                self.store
                    .submit6(&self.scratch.change, Ticket(self.ticket))
                    .expect("the store takes the change");
                for row in self.store.commit(self.now) {
                    self.table.apply_at(row, tenko_core::Revision::ZERO);
                }
                let mut done = Vec::new();
                self.store.completions6(&mut done);
                assert!(
                    done.iter().all(|completion| completion.outcome.is_ok()),
                    "{done:?}"
                );
                Some(self.scratch.reply[..len].to_vec())
            }
            Action6::Drop(_) | Action6::Ignore(_) => None,
        };
        (answer, reply)
    }

    /// The rows committed.
    pub fn rows(&self) -> usize {
        self.table.len()
    }
}

/// A client message: the type, the transaction id, its options written by `body`.
pub fn message(kind: MessageType, xid: u32, body: impl FnOnce(&mut MessageBuilder<'_>)) -> Vec<u8> {
    let mut buf = vec![0u8; 1500];
    let mut builder = MessageBuilder::new(&mut buf, 1500).expect("builder");
    builder.message(kind, xid).expect("header");
    body(&mut builder);
    let len = builder.finish().expect("balanced");
    buf.truncate(len);
    buf
}

/// The options of a client: Client ID, Elapsed Time, the ORO asking for 23, 24 and 56.
pub fn client_options(builder: &mut MessageBuilder<'_>, duid: &[u8]) {
    builder.option(code::CLIENTID, duid).expect("client id");
    builder
        .option(code::ELAPSED_TIME, &[0, 0])
        .expect("elapsed");
    builder
        .option(code::ORO, &[0, 23, 0, 24, 0, 56])
        .expect("oro");
}

/// An `IA_NA` with `iaid` and, when given, one address.
pub fn ia_na(builder: &mut MessageBuilder<'_>, iaid: u32, address: Option<Ipv6Addr>) {
    let mark = builder.begin_ia_na(iaid, 0, 0).expect("ia");
    if let Some(address) = address {
        builder.ia_address(address, 0, 0).expect("address");
    }
    builder.end(mark).expect("end");
}

/// Wraps `inner` in RELAY-FORW layers, innermost first in `layers`: each a link address,
/// a peer address and an optional Interface-Id; with `link_layer`, the innermost relay adds
/// the Client Link-Layer Address option (RFC 6939).
pub fn relayed(
    inner: &[u8],
    layers: &[(Ipv6Addr, Ipv6Addr, Option<&[u8]>)],
    link_layer: Option<[u8; 6]>,
) -> Vec<u8> {
    let mut current = inner.to_vec();
    for (depth, (link, peer, interface_id)) in layers.iter().enumerate() {
        let mut buf = vec![0u8; 1500];
        let mut builder = MessageBuilder::new(&mut buf, 1500).expect("builder");
        builder
            .relay(
                MessageType::RelayForw,
                u8::try_from(depth).expect("depth"),
                *link,
                *peer,
            )
            .expect("relay");
        if let Some(id) = interface_id {
            builder
                .option(code::INTERFACE_ID, id)
                .expect("interface id");
        }
        if depth == 0
            && let Some(mac) = link_layer
        {
            let mut value = vec![0, 1];
            value.extend(mac);
            builder
                .option(code::CLIENT_LINKLAYER_ADDR, &value)
                .expect("link layer");
        }
        builder
            .option(code::RELAY_MSG, &current)
            .expect("relay msg");
        let len = builder.finish().expect("balanced");
        buf.truncate(len);
        current = buf;
    }
    current
}

/// One relay on the first link, the client's link-local address as the peer.
pub fn relay1(inner: &[u8]) -> Vec<u8> {
    relayed(
        inner,
        &[(LINK1, addr("fe80::200:5eff:fe00:5301"), None)],
        None,
    )
}

/// The client message inside a reply chain.
pub fn unwrap(reply: &[u8]) -> Vec<u8> {
    let mut message = Message::parse(reply).expect("reply parses");
    while message.kind() == MessageType::RelayRepl {
        message = message
            .relay_message()
            .expect("relay msg")
            .expect("present");
    }
    message.as_bytes().to_vec()
}

/// The addresses of the `IA_NA`s of a reply, in order: (IAID, address, preferred, valid).
pub fn addresses(reply: &[u8]) -> Vec<(u32, Ipv6Addr, u32, u32)> {
    let inner = unwrap(reply);
    let message = Message::parse(&inner).expect("parses");
    let mut out = Vec::new();
    for ia in message.ia_nas() {
        let ia = ia.expect("ia");
        for address in ia.addresses() {
            let address = address.expect("address");
            out.push((ia.iaid, address.addr, address.preferred, address.valid));
        }
    }
    out
}

/// The status codes of the reply's IAs and its own, in order.
pub fn statuses(reply: &[u8]) -> (Vec<Option<u16>>, Option<u16>) {
    let inner = unwrap(reply);
    let message = Message::parse(&inner).expect("parses");
    let ias = message
        .ia_nas()
        .map(|ia| ia.expect("ia").status().map(|status| status.code))
        .collect();
    let top = message
        .option(code::STATUS_CODE)
        .expect("walk")
        .map(|data| u16::from_be_bytes([data[0], data[1]]));
    (ias, top)
}

/// Whether the table holds an active binding of `address` for `duid`.
pub fn bound(world: &World6, address: Ipv6Addr, duid: &[u8]) -> bool {
    world
        .table
        .get(VrfId::from_uuid(uuid::Uuid::nil()), address)
        .is_some_and(|lease| lease.is_bound(world.now) && lease.duid.as_bytes() == duid)
}

// WP9.2: delegation pools and IA_PD.

/// The first address of the default delegation pool (inside a /48 of the documentation
/// range).
pub const PD_FIRST: &str = "2001:db8:180:100::";
/// The last address of the default delegation pool: sixteen /60 prefixes.
pub const PD_LAST: &str = "2001:db8:180:1ff:ffff:ffff:ffff:ffff";

/// A delegation pool of `first` to `last` cut into prefixes of `len`; its lease times (a
/// valid lifetime of 6,000 seconds) differ from the scope's so that a test sees which one
/// a reply used.
pub fn pd_pool(first: &str, last: &str, len: u8) -> PdPool6Image {
    PdPool6Image {
        range: RangeId::generate(),
        first: addr(first),
        last: addr(last),
        delegated_len: len,
        lease: LeaseTimes {
            default_secs: 6_000,
            min_secs: 600,
            max_secs: 8_000,
            t1_secs: None,
            t2_secs: None,
        },
        options: Vec::new(),
    }
}

/// The default delegation pool: `PD_FIRST` to `PD_LAST` in /60 prefixes.
pub fn pd_pool_60() -> PdPool6Image {
    pd_pool(PD_FIRST, PD_LAST, 60)
}

/// An `IA_PD` with `iaid` and the hints `prefixes` (a prefix of `::` is a hint of the
/// length only).
pub fn ia_pd(builder: &mut MessageBuilder<'_>, iaid: u32, prefixes: &[(Ipv6Addr, u8)]) {
    let mark = builder.begin_ia_pd(iaid, 0, 0).expect("ia_pd");
    for (prefix, len) in prefixes {
        builder.ia_prefix(*prefix, *len, 0, 0).expect("ia prefix");
    }
    builder.end(mark).expect("end");
}

/// The prefixes of the `IA_PD`s of a reply, in order: (IAID, prefix, length, preferred,
/// valid).
pub fn prefixes(reply: &[u8]) -> Vec<(u32, Ipv6Addr, u8, u32, u32)> {
    let inner = unwrap(reply);
    let message = Message::parse(&inner).expect("parses");
    let mut out = Vec::new();
    for ia in message.ia_pds() {
        let ia = ia.expect("ia_pd");
        for prefix in ia.prefixes() {
            let prefix = prefix.expect("prefix");
            out.push((
                ia.iaid,
                prefix.prefix,
                prefix.prefix_len,
                prefix.preferred,
                prefix.valid,
            ));
        }
    }
    out
}

/// The status codes inside the reply's `IA_PD`s, in order.
pub fn pd_statuses(reply: &[u8]) -> Vec<Option<u16>> {
    let inner = unwrap(reply);
    let message = Message::parse(&inner).expect("parses");
    message
        .ia_pds()
        .map(|ia| ia.expect("ia_pd").status().map(|status| status.code))
        .collect()
}

/// Whether the table holds an active delegation of `prefix`/`len` for `duid`.
pub fn delegated(world: &World6, prefix: Ipv6Addr, len: u8, duid: &[u8]) -> bool {
    world
        .table
        .get(VrfId::from_uuid(uuid::Uuid::nil()), prefix)
        .is_some_and(|lease| {
            lease.is_bound(world.now)
                && lease.kind == tenko_core::dhcp::Lease6Kind::Pd
                && lease.prefix_len == len
                && lease.duid.as_bytes() == duid
        })
}
