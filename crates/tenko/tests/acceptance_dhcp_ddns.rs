//! Acceptance of DDNS from DHCP (WP8.3, E26, plan section 2.9, ADR 0020) through the real
//! binary: one node with `--roles controller,dns,dhcp` under the Home profile, a DNS
//! listener and a relay-mode DHCP listener on loopback ports; the test is the relay agent
//! as in `acceptance_dhcp.rs` and asks the DNS listener what it serves.
//!
//! - The forward zone and the reverse zone are made through the API, then the IPAM
//!   network, its pool and the scope with DDNS on and the forward zone named.
//! - A client with option 81 (flag S) and a legacy client with option 12 only get, on
//!   ACK, their A record, their DHCID (RFC 4701) and their PTR, served by the DNS role; the
//!   ACK's option 81 says the server writes the A record (flag S); the lease rows show the
//!   names and the DHCID.
//! - A second client that claims the first one's name is refused by name protection
//!   (RFC 4703): the name still points at the first client, and the lease says why.
//! - The first client's DHCPRELEASE removes its records; the legacy client's lease runs out
//!   and the expiry removes its records.
//!
//! The rows of E26 in the lab (a dhclient with option 81, Playwright on the leases page)
//! wait for WP7.6's lab.

mod serve_support;

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use serve_support::{Node, api::Api, free_port, wait_for_setup_token};
use tenko_dhcp::v4::{ClientFqdn, Message, MessageType};
use tenko_dns::wire;

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_DHCID: u16 = 49;
const NOERROR: u8 = 0;
const NXDOMAIN: u8 = 3;
const LEASE_SECS: u32 = 20;

/// A UDP port that was free a moment ago.
fn udp_port() -> u16 {
    UdpSocket::bind(SocketAddrV4::new(LOOPBACK, 0))
        .expect("bind")
        .local_addr()
        .expect("address")
        .port()
}

/// What the test relays for one client.
#[derive(Debug, Clone)]
struct Ask {
    kind: u8,
    client: u8,
    ciaddr: Option<Ipv4Addr>,
    requested: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
    hostname: Option<String>,
    /// Option 81: the flags and a partial name in the canonical wire form (flag E).
    fqdn: Option<(u8, String)>,
}

impl Ask {
    fn new(kind: MessageType, client: u8) -> Self {
        Self {
            kind: match kind {
                MessageType::Discover => 1,
                MessageType::Request => 3,
                MessageType::Release => 7,
                other => panic!("{other:?} is not sent here"),
            },
            client,
            ciaddr: None,
            requested: None,
            server_id: None,
            hostname: None,
            fqdn: None,
        }
    }

    fn mac(&self) -> [u8; 6] {
        [0x00, 0x00, 0x5e, 0x00, 0x53, self.client]
    }

    /// The BOOTREQUEST as a relay agent at 127.0.0.1 forwards it (RFC 2131, RFC 3011).
    fn bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; 240];
        out[0] = 1;
        out[1] = 1;
        out[2] = 6;
        out[3] = 1;
        out[4..8].copy_from_slice(&[0x7e, 0x57, self.kind, self.client]);
        if let Some(ciaddr) = self.ciaddr {
            out[12..16].copy_from_slice(&ciaddr.octets());
        }
        out[24..28].copy_from_slice(&LOOPBACK.octets());
        out[28..34].copy_from_slice(&self.mac());
        out[236..240].copy_from_slice(&[99, 130, 83, 99]);
        out.extend_from_slice(&[53, 1, self.kind]);
        out.extend_from_slice(&[61, 7, 1]);
        out.extend_from_slice(&self.mac());
        out.extend_from_slice(&[118, 4, 192, 0, 2, 0]);
        if let Some(hostname) = &self.hostname {
            out.extend_from_slice(&[12, u8::try_from(hostname.len()).expect("short")]);
            out.extend_from_slice(hostname.as_bytes());
        }
        if let Some((flags, name)) = &self.fqdn {
            let mut data = vec![*flags | ClientFqdn::FLAG_E, 0, 0];
            for label in name.split('.') {
                data.push(u8::try_from(label.len()).expect("short"));
                data.extend_from_slice(label.as_bytes());
            }
            out.extend_from_slice(&[81, u8::try_from(data.len()).expect("short")]);
            out.extend_from_slice(&data);
        }
        if let Some(requested) = self.requested {
            out.extend_from_slice(&[50, 4]);
            out.extend_from_slice(&requested.octets());
        }
        if let Some(server) = self.server_id {
            out.extend_from_slice(&[54, 4]);
            out.extend_from_slice(&server.octets());
        }
        out.push(255);
        out
    }
}

/// The relay agent of the test.
struct Relay {
    socket: UdpSocket,
    server: SocketAddrV4,
}

impl Relay {
    fn new(port: u16, server: u16) -> Self {
        let socket = UdpSocket::bind(SocketAddrV4::new(LOOPBACK, port)).expect("bind the relay");
        socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        Self {
            socket,
            server: SocketAddrV4::new(LOOPBACK, server),
        }
    }

    /// Sends `ask` until an answer of the expected type comes, at most `within`.
    fn exchange(&self, ask: &Ask, expect: MessageType, within: Duration) -> Option<Vec<u8>> {
        let start = Instant::now();
        let mut buf = [0u8; 1500];
        while start.elapsed() < within {
            self.socket
                .send_to(&ask.bytes(), self.server)
                .expect("send");
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                let Ok((len, _)) = self.socket.recv_from(&mut buf) else {
                    break;
                };
                let Ok(message) = Message::parse(&buf[..len]) else {
                    continue;
                };
                if message.xid() == u32::from_be_bytes([0x7e, 0x57, ask.kind, ask.client])
                    && message.message_type().ok().flatten() == Some(expect)
                {
                    return Some(buf[..len].to_vec());
                }
            }
        }
        None
    }

    /// A DORA exchange with the client's names; the ACK.
    fn dora(&self, template: &Ask, within: Duration) -> Vec<u8> {
        let mut discover = template.clone();
        discover.kind = 1;
        let offer = self
            .exchange(&discover, MessageType::Offer, within)
            .unwrap_or_else(|| panic!("no OFFER for client {}", template.client));
        let offer = Message::parse(&offer).expect("parse");
        let mut request = template.clone();
        request.kind = 3;
        request.requested = Some(offer.yiaddr());
        request.server_id = offer.server_identifier().expect("54");
        self.exchange(&request, MessageType::Ack, Duration::from_secs(5))
            .unwrap_or_else(|| panic!("no ACK for client {}", template.client))
    }

    /// A DHCPRELEASE; the server sends no answer.
    fn release(&self, ask: &Ask) {
        self.socket
            .send_to(&ask.bytes(), self.server)
            .expect("send");
    }
}

/// A query for `name` and `qtype`.
fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(&mut out, id, name, qtype, Some(1232));
    out
}

fn udp(server: SocketAddr, name: &str, qtype: u16) -> Vec<u8> {
    let socket = UdpSocket::bind((LOOPBACK, 0)).expect("bind a client");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let id = free_port();
    for _ in 0..3 {
        socket
            .send_to(&query(id, name, qtype), server)
            .expect("send");
        let mut buf = vec![0u8; 65_535];
        if let Ok((len, _)) = socket.recv_from(&mut buf) {
            buf.truncate(len);
            return buf;
        }
    }
    panic!("no UDP answer from {server} for {name}");
}

/// The rcode and the answer count of an answer.
fn rcode_and_answers(answer: &[u8]) -> (u8, u16) {
    let head = wire::parse_header(answer).expect("a header");
    (head.rcode, head.ancount)
}

fn holds(answer: &[u8], bytes: &[u8]) -> bool {
    answer.windows(bytes.len()).any(|window| window == bytes)
}

/// The name in DNS wire form, for finding a PTR target in an answer.
fn wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(u8::try_from(label.len()).expect("short"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// Waits until `done` holds, at most `within`.
fn until(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < within {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out after {within:?} waiting for {what}");
}

fn a_answer(dns: SocketAddr, name: &str, address: Ipv4Addr) -> bool {
    let answer = udp(dns, name, TYPE_A);
    rcode_and_answers(&answer) == (NOERROR, 1) && holds(&answer, &address.octets())
}

fn gone(dns: SocketAddr, name: &str, qtype: u16) -> bool {
    let (rcode, answers) = rcode_and_answers(&udp(dns, name, qtype));
    answers == 0 && (rcode == NXDOMAIN || rcode == NOERROR)
}

fn ptr_name(address: Ipv4Addr) -> String {
    let [a, b, c, d] = address.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

fn lease(api: &Api, address: Ipv4Addr) -> Value {
    api.get(&format!("/dhcp/leases/{address}")).expect(200)
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn ddns_writes_names_on_ack_refuses_a_stolen_name_and_removes_names_on_release_and_expiry() {
    let port = udp_port();
    let relay_port = udp_port();
    let relay = Relay::new(relay_port, port);
    let dns_port = free_port();
    let dns: SocketAddr = (LOOPBACK, dns_port).into();
    let mut node = Node::new()
        .with_args(&["--roles", "controller,dns,dhcp"])
        .with_config(&format!(
            "[dns]\nlisten = [\"{dns}\"]\nworkers = 1\n\
             [dhcp]\nlisten = [{{ address = \"127.0.0.1\", mode = \"relay\" }}]\nport = {port}\n\
             relay_port = {relay_port}\nworkers = 2\n[dhcp.ddns]\nbackoff_ms = 100\n"
        ));
    let mut server = node.start();
    let line = format!("dhcp role answering on 127.0.0.1:{port} (relay)");
    server
        .wait_stdout_line(Duration::from_secs(15), |text| text.starts_with(&line))
        .unwrap_or_else(|| panic!("no dhcp line\n{}", server.diagnostics()));
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);

    // The zones, the network, its pool and the scope with DDNS on.
    let zone = |name: &str| -> String {
        api.post(
            "/dns/zones",
            &json!({
                "name": name,
                "kind": "primary",
                "serial": "counter",
                "soa": {"mname": "ns1.example.test", "rname": "hostmaster.example.test"},
                "name_servers": ["ns1.example.test"],
            }),
        )
        .expect(201)["id"]
            .as_str()
            .expect("a zone id")
            .to_owned()
    };
    let forward = zone("lan.example.test");
    zone("2.0.192.in-addr.arpa");
    let prefix = api
        .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
        .expect(201)["item"]["id"]
        .as_str()
        .expect("a prefix id")
        .to_owned();
    api.post(
        &format!("/prefixes/{prefix}/ranges"),
        &json!({ "first": "192.0.2.100", "last": "192.0.2.199", "role": "dhcp_pool" }),
    )
    .expect(201);
    api.post(
        "/dhcp/scopes",
        &json!({
            "prefix": prefix,
            "lease": { "default_secs": LEASE_SECS, "min_secs": LEASE_SECS, "max_secs": LEASE_SECS },
            "ddns": { "enabled": true, "forward_zone": forward },
        }),
    )
    .expect(201);

    // A client with option 81 and a legacy client with option 12 only.
    let mut modern = Ask::new(MessageType::Discover, 1);
    modern.fqdn = Some((ClientFqdn::FLAG_S, "laptop".to_owned()));
    let mut legacy = Ask::new(MessageType::Discover, 2);
    legacy.hostname = Some("printer".to_owned());
    let ack = relay.dora(&modern, Duration::from_secs(15));
    let ack = Message::parse(&ack).expect("parse");
    let laptop = ack.yiaddr();
    let fqdn = ack
        .client_fqdn()
        .expect("81")
        .expect("option 81 in the ACK");
    assert_eq!(
        fqdn.flags() & (ClientFqdn::FLAG_S | ClientFqdn::FLAG_O | ClientFqdn::FLAG_N),
        ClientFqdn::FLAG_S,
        "the server writes the A record"
    );
    let printer = Message::parse(&relay.dora(&legacy, Duration::from_secs(5)))
        .expect("parse")
        .yiaddr();
    let acked = Instant::now();
    until("the A records", Duration::from_secs(10), || {
        a_answer(dns, "laptop.lan.example.test", laptop)
            && a_answer(dns, "printer.lan.example.test", printer)
    });
    let to_answer = acked.elapsed();
    let ptr = udp(dns, &ptr_name(laptop), TYPE_PTR);
    assert_eq!(rcode_and_answers(&ptr), (NOERROR, 1));
    assert!(holds(&ptr, &wire_name("laptop.lan.example.test")));
    until("the legacy PTR", Duration::from_secs(5), || {
        holds(
            &udp(dns, &ptr_name(printer), TYPE_PTR),
            &wire_name("printer.lan.example.test"),
        )
    });
    let dhcid = udp(dns, "laptop.lan.example.test", TYPE_DHCID);
    assert_eq!(rcode_and_answers(&dhcid), (NOERROR, 1));
    until("the outcome on the rows", Duration::from_secs(5), || {
        lease(&api, laptop)["ddns"]["dhcid"].is_string()
            && lease(&api, printer)["ddns"]["reverse"].is_string()
    });
    let row = lease(&api, laptop);
    assert_eq!(row["ddns"]["forward"], "laptop.lan.example.test", "{row}");
    assert_eq!(row["ddns"]["reverse"], ptr_name(laptop), "{row}");
    assert!(row["ddns"].get("last_error").is_none(), "{row}");
    assert_eq!(row["fqdn_flags"], 5, "{row}");
    let row = lease(&api, printer);
    assert_eq!(row["ddns"]["forward"], "printer.lan.example.test", "{row}");

    // A second client claims the first one's name: refused by name protection.
    let mut thief = Ask::new(MessageType::Discover, 3);
    thief.fqdn = Some((ClientFqdn::FLAG_S, "laptop".to_owned()));
    let stolen = Message::parse(&relay.dora(&thief, Duration::from_secs(5)))
        .expect("parse")
        .yiaddr();
    until("the refusal on the lease", Duration::from_secs(10), || {
        lease(&api, stolen)["ddns"]["last_error"]
            .as_str()
            .is_some_and(|error| error.contains("name protection"))
    });
    assert!(a_answer(dns, "laptop.lan.example.test", laptop));
    assert!(gone(dns, &ptr_name(stolen), TYPE_PTR));

    // The first client releases its address: its records go.
    let mut release = Ask::new(MessageType::Release, 1);
    release.ciaddr = Some(laptop);
    release.server_id = ack.server_identifier().expect("54");
    relay.release(&release);
    until(
        "the records gone after the release",
        Duration::from_secs(10),
        || {
            gone(dns, "laptop.lan.example.test", TYPE_A)
                && gone(dns, "laptop.lan.example.test", TYPE_DHCID)
                && gone(dns, &ptr_name(laptop), TYPE_PTR)
        },
    );
    assert_eq!(lease(&api, laptop)["state"], "released");

    // The legacy client's lease runs out: the expiry removes its records.
    until(
        "the records gone after the expiry",
        Duration::from_secs(u64::from(LEASE_SECS) + 30),
        || gone(dns, "printer.lan.example.test", TYPE_A) && gone(dns, &ptr_name(printer), TYPE_PTR),
    );
    assert_eq!(lease(&api, printer)["state"], "expired");
    let metrics = api.get("/metrics").text;
    assert!(
        metrics
            .lines()
            .any(|line| line.starts_with("tenko_dhcp_ddns_total{outcome=\"written\"}")),
        "{metrics}"
    );
    println!("ACK to the answered A records of two clients: {to_answer:?}");
    server.stop().assert_graceful_shutdown();
}
