//! Acceptance of DHCPv6 through the real binary (WP9.5, the binary half of E29's rows; the
//! lab round `dhcp6` of `deploy/compose/lab-dhcp` runs them with dhclient,
//! systemd-networkd and ISC's relay). One node with `--roles controller,dhcp`, a DHCPv4
//! relay listener on 127.0.0.1 and a DHCPv6 relay listener on `[::1]`, both on test ports.
//! The test is the relay agent of both families: DHCPv4 with option 118 as in
//! `acceptance_dhcp.rs`, DHCPv6 as RELAY-FORW with the link address of the client's link
//! (RFC 8415 section 19) and, for one client, the Client Link-Layer Address option
//! (RFC 6939).
//!
//! - An IPv6 network with a `dhcp_pool` range, a `dhcp_pd_pool` range of /60 prefixes and
//!   its scope are made through the API, and a reserved host whose interface has a DUID
//!   and an address in that network.
//! - `IA_NA` from the pool: SOLICIT, ADVERTISE, REQUEST, REPLY, and the lease row.
//! - `IA_PD` from the delegation pool with Rapid Commit: a /60 inside the pool, and the
//!   lease row of kind `pd`.
//! - The DUID reservation from IPAM intent: the reserved client gets its address, not one
//!   of the pool, and the lease names the host.
//! - The correlation of RFC 6939: a client with a DUID-UUID, whose relay adds its MAC, is
//!   listed with that MAC and with its DHCPv4 lease of the same MAC as its peer.
//! - `GET /nodes/{id}/dhcp` reports the DHCPv6 listener, the scope and the leases.
//!
//! Not here: the names of RFC 4704 in a Tenko zone (`crates/tenko-dhcp/tests/ddns6.rs`
//! and the lab), the M and O flag check of DHCP-10 (it needs a raw `ICMPv6` socket and
//! router advertisements: `crates/tenko-dhcp/tests/ra.rs` and the lab rows `v6.ra.*`).

mod serve_support;

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use serve_support::{Node, api::Api, wait_for_setup_token};
use tenko_dhcp::{
    v4,
    v6::{Message, MessageBuilder, MessageType, code},
};

const NETWORK: &str = "2001:db8:180::/48";
/// The relay's address on the client link, inside the network: it selects the scope.
const LINK: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x180, 0, 0, 0, 0, 1);
const RESERVED: &str = "2001:db8:180::50";
/// The documentation MAC (RFC 7042) of the dual-stack client.
const DUAL_MAC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x42];

fn udp_port() -> u16 {
    UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind")
        .local_addr()
        .expect("address")
        .port()
}

fn udp6_port() -> u16 {
    UdpSocket::bind("[::1]:0")
        .expect("bind")
        .local_addr()
        .expect("address")
        .port()
}

/// A DUID-LL (RFC 8415 section 11.4) of a documentation MAC.
fn duid_ll(last: u8) -> Vec<u8> {
    vec![0, 3, 0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, last]
}

/// A DUID-UUID (RFC 6355): no MAC can be read from it.
fn duid_uuid(last: u8) -> Vec<u8> {
    let mut out = vec![0, 4];
    out.extend_from_slice(&[0x2b, 0x5c, 0x7e, 0x11, 0x2a, 0x9d, 0x4e, 0x0f]);
    out.extend_from_slice(&[0x8c, 0x31, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, last]);
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// What one client asks.
#[derive(Clone, Copy, Default)]
struct Ask6<'a> {
    duid: &'a [u8],
    /// An `IA_NA`.
    na: bool,
    /// The address the `IA_NA` requests.
    requested: Option<Ipv6Addr>,
    /// An `IA_PD` with a hint of the length only.
    pd: Option<u8>,
    rapid: bool,
    server: Option<&'a [u8]>,
    /// The MAC the relay adds (RFC 6939).
    link_layer: Option<[u8; 6]>,
}

impl Ask6<'_> {
    fn bytes(&self, kind: MessageType, xid: u32) -> Vec<u8> {
        let mut inner = vec![0u8; 1500];
        let len = {
            let mut b = MessageBuilder::new(&mut inner, 1500).expect("builder");
            b.message(kind, xid).expect("header");
            b.option(code::CLIENTID, self.duid).expect("client id");
            b.option(code::ELAPSED_TIME, &[0, 0]).expect("elapsed");
            b.option(code::ORO, &[0, 23, 0, 24]).expect("oro");
            if let Some(server) = self.server {
                b.option(code::SERVERID, server).expect("server id");
            }
            if self.rapid {
                b.option(code::RAPID_COMMIT, &[]).expect("rapid commit");
            }
            if self.na {
                let mark = b.begin_ia_na(1, 0, 0).expect("ia_na");
                if let Some(address) = self.requested {
                    b.ia_address(address, 0, 0).expect("address");
                }
                b.end(mark).expect("end");
            }
            if let Some(len) = self.pd {
                let mark = b.begin_ia_pd(2, 0, 0).expect("ia_pd");
                b.ia_prefix(Ipv6Addr::UNSPECIFIED, len, 0, 0)
                    .expect("ia prefix");
                b.end(mark).expect("end");
            }
            b.finish().expect("balanced")
        };
        inner.truncate(len);
        let mut out = vec![0u8; 1500];
        let len = {
            let mut b = MessageBuilder::new(&mut out, 1500).expect("builder");
            let peer: Ipv6Addr = "fe80::200:5eff:fe00:5301".parse().expect("peer");
            b.relay(MessageType::RelayForw, 0, LINK, peer)
                .expect("relay");
            if let Some(mac) = self.link_layer {
                let mut value = vec![0, 1];
                value.extend(mac);
                b.option(code::CLIENT_LINKLAYER_ADDR, &value)
                    .expect("link layer");
            }
            b.option(code::RELAY_MSG, &inner).expect("relay msg");
            b.finish().expect("balanced")
        };
        out.truncate(len);
        out
    }
}

/// The client message inside a RELAY-REPL.
fn unwrap(reply: &[u8]) -> Vec<u8> {
    let mut message = Message::parse(reply).expect("reply parses");
    while message.kind() == MessageType::RelayRepl {
        message = message
            .relay_message()
            .expect("relay msg")
            .expect("present");
    }
    message.as_bytes().to_vec()
}

/// The reply's kind, its server DUID, its `IA_NA` addresses and its `IA_PD` prefixes.
struct Reply6 {
    kind: MessageType,
    server: Vec<u8>,
    addresses: Vec<Ipv6Addr>,
    prefixes: Vec<(Ipv6Addr, u8)>,
}

fn read(reply: &[u8]) -> Reply6 {
    let inner = unwrap(reply);
    let message = Message::parse(&inner).expect("parses");
    let mut addresses = Vec::new();
    for ia in message.ia_nas() {
        for address in ia.expect("ia_na").addresses() {
            addresses.push(address.expect("address").addr);
        }
    }
    let mut prefixes = Vec::new();
    for ia in message.ia_pds() {
        for prefix in ia.expect("ia_pd").prefixes() {
            let prefix = prefix.expect("prefix");
            prefixes.push((prefix.prefix, prefix.prefix_len));
        }
    }
    Reply6 {
        kind: message.kind(),
        server: message
            .option(code::SERVERID)
            .expect("walk")
            .map(<[u8]>::to_vec)
            .unwrap_or_default(),
        addresses,
        prefixes,
    }
}

/// The DHCPv6 relay agent of the test.
struct Relay6 {
    socket: UdpSocket,
    server: SocketAddrV6,
}

impl Relay6 {
    fn new(port: u16, server: u16) -> Self {
        let socket = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0))
            .expect("bind the relay");
        socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        Self {
            socket,
            server: SocketAddrV6::new(Ipv6Addr::LOCALHOST, server, 0, 0),
        }
    }

    /// Sends until a reply of `expect` with something in it comes, at most `within`.
    fn exchange(
        &self,
        ask: &Ask6<'_>,
        kind: MessageType,
        expect: MessageType,
        xid: u32,
        within: Duration,
    ) -> Option<Reply6> {
        let start = Instant::now();
        let mut buf = [0u8; 2048];
        while start.elapsed() < within {
            self.socket
                .send_to(&ask.bytes(kind, xid), self.server)
                .expect("send");
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                let Ok((len, _)) = self.socket.recv_from(&mut buf) else {
                    break;
                };
                let inner = unwrap(&buf[..len]);
                let Ok(message) = Message::parse(&inner) else {
                    continue;
                };
                if message.transaction_id() != xid || message.kind() != expect {
                    continue;
                }
                let reply = read(&buf[..len]);
                if !reply.addresses.is_empty() || !reply.prefixes.is_empty() {
                    return Some(reply);
                }
            }
        }
        None
    }

    /// SOLICIT, ADVERTISE, REQUEST, REPLY for an `IA_NA`; the address of the REPLY.
    fn lease(&self, ask: Ask6<'_>, xid: u32) -> Ipv6Addr {
        let advertise = self
            .exchange(
                &Ask6 { na: true, ..ask },
                MessageType::Solicit,
                MessageType::Advertise,
                xid,
                Duration::from_secs(10),
            )
            .expect("an ADVERTISE");
        let offered = advertise.addresses[0];
        let reply = self
            .exchange(
                &Ask6 {
                    na: true,
                    requested: Some(offered),
                    server: Some(&advertise.server),
                    ..ask
                },
                MessageType::Request,
                MessageType::Reply,
                xid + 1,
                Duration::from_secs(5),
            )
            .expect("a REPLY");
        assert_eq!(reply.addresses, vec![offered]);
        offered
    }
}

/// One DHCPv4 DORA through the relay at 127.0.0.1 with option 118 for 192.0.2.0; the
/// address of the ACK.
fn dora4(port: u16, relay_port: u16, mac: [u8; 6]) -> Ipv4Addr {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, relay_port)).expect("bind");
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let server = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let packet = |kind: u8, requested: Option<(Ipv4Addr, Ipv4Addr)>| {
        let mut out = vec![0u8; 240];
        out[..4].copy_from_slice(&[1, 1, 6, 1]);
        out[4..8].copy_from_slice(&[0x7e, 0x57, kind, mac[5]]);
        out[24..28].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
        out[28..34].copy_from_slice(&mac);
        out[236..240].copy_from_slice(&[99, 130, 83, 99]);
        out.extend_from_slice(&[53, 1, kind, 118, 4, 192, 0, 2, 0]);
        if let Some((address, server)) = requested {
            out.extend_from_slice(&[50, 4]);
            out.extend_from_slice(&address.octets());
            out.extend_from_slice(&[54, 4]);
            out.extend_from_slice(&server.octets());
        }
        out.push(255);
        out
    };
    let ask = |bytes: &[u8], expect: v4::MessageType| -> Option<Vec<u8>> {
        let start = Instant::now();
        let mut buf = [0u8; 1500];
        while start.elapsed() < Duration::from_secs(10) {
            socket.send_to(bytes, server).expect("send");
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                let Ok((len, _)) = socket.recv_from(&mut buf) else {
                    break;
                };
                let Ok(message) = v4::Message::parse(&buf[..len]) else {
                    continue;
                };
                if message.message_type().ok().flatten() == Some(expect) {
                    return Some(buf[..len].to_vec());
                }
            }
        }
        None
    };
    let offer = ask(&packet(1, None), v4::MessageType::Offer).expect("an OFFER");
    let offer = v4::Message::parse(&offer).expect("parse");
    let id = offer.server_identifier().expect("54").expect("present");
    let ack = ask(&packet(3, Some((offer.yiaddr(), id))), v4::MessageType::Ack).expect("an ACK");
    v4::Message::parse(&ack).expect("parse").yiaddr()
}

fn leases6(api: &Api) -> Vec<Value> {
    api.get("/dhcp/leases?family=v6").expect(200)["items"]
        .as_array()
        .expect("items")
        .clone()
}

fn lease_of<'a>(items: &'a [Value], addr: &str) -> &'a Value {
    items
        .iter()
        .find(|item| item["addr"] == addr)
        .unwrap_or_else(|| panic!("no lease of {addr} in {items:?}"))
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn e29_dhcp_09_ia_na_ia_pd_a_duid_reservation_and_the_rfc_6939_peer_through_the_binary() {
    let port4 = udp_port();
    let relay4 = udp_port();
    let port6 = udp6_port();
    let relay6_port = udp6_port();
    let relay = Relay6::new(relay6_port, port6);
    let mut node = Node::new()
        .with_args(&["--roles", "controller,dhcp"])
        .with_config(&format!(
            "[dhcp]\nlisten = [{{ address = \"127.0.0.1\", mode = \"relay\" }}, \
             {{ address = \"::1\", mode = \"relay\" }}]\nport = {port4}\nrelay_port = {relay4}\n\
             workers = 2\n[dhcp.v6]\nport = {port6}\nrelay_port = {relay6_port}\n"
        ));
    let mut server = node.start();
    let line = format!("dhcp role answering on 127.0.0.1:{port4} (relay)");
    server
        .wait_stdout_line(Duration::from_secs(10), |text| text.starts_with(&line))
        .unwrap_or_else(|| panic!("no dhcp line\n{}", server.diagnostics()));
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);

    // The DHCPv4 scope for the dual-stack client.
    let prefix4 = api
        .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
        .expect(201)["item"]["id"]
        .as_str()
        .expect("a prefix id")
        .to_owned();
    api.post(
        &format!("/prefixes/{prefix4}/ranges"),
        &json!({ "first": "192.0.2.100", "last": "192.0.2.199", "role": "dhcp_pool" }),
    )
    .expect(201);
    api.post("/dhcp/scopes", &json!({ "prefix": prefix4 }))
        .expect(201);

    // The IPv6 network: a pool, a delegation pool of /60 prefixes and the scope.
    let prefix6 = api
        .post("/prefixes", &json!({ "cidr": NETWORK }))
        .expect(201)["item"]["id"]
        .as_str()
        .expect("a prefix id")
        .to_owned();
    api.post(
        &format!("/prefixes/{prefix6}/ranges"),
        &json!({ "first": "2001:db8:180::1000", "last": "2001:db8:180::1fff", "role": "dhcp_pool" }),
    )
    .expect(201);
    api.post(
        &format!("/prefixes/{prefix6}/ranges"),
        &json!({
            "first": "2001:db8:180:100::",
            "last": "2001:db8:180:1ff:ffff:ffff:ffff:ffff",
            "role": "dhcp_pd_pool",
            "delegated_len": 60,
        }),
    )
    .expect(201);
    let scope = api
        .post("/dhcp/scopes", &json!({ "prefix": prefix6 }))
        .expect(201);
    assert_eq!(scope["family"], "v6", "{scope}");

    // The reserved host: an interface with a DUID and an address in the network.
    let reserved_duid = duid_ll(0x50);
    let host = api
        .post(
            "/hosts",
            &json!({
                "name": "reserved6",
                "mode": "reserved",
                "interfaces": [{ "name": "eth0", "duid": hex(&reserved_duid) }],
            }),
        )
        .expect(201)["item"]["id"]
        .as_str()
        .expect("a host id")
        .to_owned();
    let interfaces = api.get(&format!("/hosts/{host}/interfaces")).expect(200);
    let interface = interfaces["items"][0]["id"]
        .as_str()
        .expect("the interface")
        .to_owned();
    api.post(
        "/addresses",
        &json!({ "ip": RESERVED, "interface": interface }),
    )
    .expect(201);

    // IA_NA from the pool, four messages.
    let pool_duid = duid_ll(0x10);
    let pooled = relay.lease(
        Ask6 {
            duid: &pool_duid,
            ..Ask6::default()
        },
        0x100,
    );
    let pool_first: Ipv6Addr = "2001:db8:180::1000".parse().expect("first");
    let pool_last: Ipv6Addr = "2001:db8:180::1fff".parse().expect("last");
    assert!(
        (pool_first..=pool_last).contains(&pooled),
        "{pooled} is not in the pool"
    );

    // IA_PD from the delegation pool, with Rapid Commit: the REPLY comes committed.
    let pd_duid = duid_ll(0x20);
    let delegated = relay
        .exchange(
            &Ask6 {
                duid: &pd_duid,
                pd: Some(60),
                rapid: true,
                ..Ask6::default()
            },
            MessageType::Solicit,
            MessageType::Reply,
            0x200,
            Duration::from_secs(10),
        )
        .expect("a REPLY with a prefix");
    assert_eq!(delegated.kind, MessageType::Reply);
    assert_eq!(delegated.prefixes.len(), 1, "{:?}", delegated.prefixes);
    let (prefix, len) = delegated.prefixes[0];
    assert_eq!(len, 60);
    let pd_first: Ipv6Addr = "2001:db8:180:100::".parse().expect("first");
    let pd_last: Ipv6Addr = "2001:db8:180:1ff:ffff:ffff:ffff:ffff"
        .parse()
        .expect("last");
    assert!(
        (pd_first..=pd_last).contains(&prefix),
        "{prefix}/{len} is not in the delegation pool"
    );

    // The DUID reservation from IPAM intent.
    let reserved = relay.lease(
        Ask6 {
            duid: &reserved_duid,
            ..Ask6::default()
        },
        0x300,
    );
    assert_eq!(reserved.to_string(), RESERVED);

    // RFC 6939: a DUID-UUID client whose relay adds its MAC, with a DHCPv4 lease of the
    // same MAC.
    let addr4 = dora4(port4, relay4, DUAL_MAC);
    let dual_duid = duid_uuid(0x42);
    let dual = relay.lease(
        Ask6 {
            duid: &dual_duid,
            link_layer: Some(DUAL_MAC),
            ..Ask6::default()
        },
        0x400,
    );

    // The lease rows.
    let items = leases6(&api);
    let row = lease_of(&items, &pooled.to_string());
    assert_eq!(row["family"], "v6", "{row}");
    assert_eq!(row["kind"], "na", "{row}");
    assert_eq!(row["state"], "active", "{row}");
    assert_eq!(row["duid"], hex(&pool_duid), "{row}");
    let row = lease_of(&items, &prefix.to_string());
    assert_eq!(row["kind"], "pd", "{row}");
    assert_eq!(row["prefix_len"], 60, "{row}");
    assert_eq!(row["duid"], hex(&pd_duid), "{row}");
    let row = lease_of(&items, RESERVED);
    assert_eq!(row["reserved"], true, "{row}");
    assert_eq!(row["host"], host.as_str(), "{row}");
    let row = lease_of(&items, &dual.to_string());
    assert_eq!(row["mac"], "00:00:5e:00:53:42", "{row}");
    assert_eq!(row["peer"]["family"], "v4", "{row}");
    assert_eq!(row["peer"]["addr"], addr4.to_string(), "{row}");

    // The node's report.
    let status = api.get("/system/status").expect(200);
    let node_id = status["node"]["id"].as_u64().expect("a node id");
    let report = api.get(&format!("/nodes/{node_id}/dhcp")).expect(200);
    assert_eq!(report["scopes6"], 1, "{report}");
    let listener = &report["listeners6"][0];
    assert_eq!(listener["address"], "::1", "{report}");
    assert_eq!(listener["port"], port6, "{report}");
    assert_eq!(listener["mode"], "relay", "{report}");
    assert!(
        report["server_duid"]
            .as_str()
            .is_some_and(|duid| !duid.is_empty()),
        "{report}"
    );

    server.stop().assert_graceful_shutdown();
}
