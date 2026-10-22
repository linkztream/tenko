//! Acceptance of the `dhcp` role in the process (WP7.5, plan section 2.10) through the real
//! binary: one node with `--roles controller,dhcp`, the DHCP module on and a relay-mode
//! listener on a loopback port. The test is the relay agent: it binds the port replies to
//! relays go to (`[dhcp] relay_port`), sends with `giaddr` 127.0.0.1 and selects the scope
//! with option 118 (RFC 3011), as perfdhcp does as a relay.
//!
//! - The IPAM network, its pool and the scope are made through the API; the role serves
//!   the scope once the feed brings it, and a DORA exchange is answered with an address
//!   of the pool.
//! - `GET /nodes/{id}/dhcp` reports the role (serving, the listener, one scope, the lease,
//!   the last commit); `GET /dhcp/leases`, `GET /dhcp/leases/{addr}` and `GET /dhcp/history`
//!   answer from the role's table and the history; `GET /system/status` lists the role
//!   and raises none of its health rows.
//! - More clients than the store's snapshot interval get leases, so the store snapshots
//!   and drops the log behind it; after a restart the node serves the same leases: a
//!   renewal is acknowledged with its address and a returning client is offered its
//!   address again, and the table holds every lease.
//! - A release through the API ends the binding, and the history shows it.
//! - A node with the role and no listener says so in the health view.
//!
//! On Windows the listener is the one shared UDP socket of the workers; on Linux the
//! workers have a socket each with `SO_REUSEPORT` (`docs/dhcp.md` section 10).

mod serve_support;

use std::{
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use serve_support::{Node, api::Api, wait_for_setup_token};
use tenko_dhcp::v4::{Message, MessageType};

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
const CLIENTS: u8 = 60;

/// A UDP port that was free a moment ago.
fn udp_port() -> u16 {
    UdpSocket::bind(SocketAddrV4::new(LOOPBACK, 0))
        .expect("bind")
        .local_addr()
        .expect("address")
        .port()
}

/// What the test relays for one client.
#[derive(Debug, Clone, Copy)]
struct Ask {
    kind: u8,
    client: u8,
    ciaddr: Option<Ipv4Addr>,
    requested: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
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
        out.extend_from_slice(&[12, 8]);
        out.extend_from_slice(format!("client{:02}", self.client).as_bytes());
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
                // A late answer to an earlier try of another client or kind is skipped.
                if message.xid() == u32::from_be_bytes([0x7e, 0x57, ask.kind, ask.client])
                    && message.message_type().ok().flatten() == Some(expect)
                {
                    return Some(buf[..len].to_vec());
                }
            }
        }
        None
    }

    /// A DORA exchange; the address of the ACK.
    fn dora(&self, client: u8, within: Duration) -> Ipv4Addr {
        let offer = self
            .exchange(
                &Ask::new(MessageType::Discover, client),
                MessageType::Offer,
                within,
            )
            .unwrap_or_else(|| panic!("no OFFER for client {client}"));
        let offer = Message::parse(&offer).expect("parse");
        let mut request = Ask::new(MessageType::Request, client);
        request.requested = Some(offer.yiaddr());
        request.server_id = offer.server_identifier().expect("54");
        let ack = self
            .exchange(&request, MessageType::Ack, Duration::from_secs(5))
            .unwrap_or_else(|| panic!("no ACK for client {client}"));
        let ack = Message::parse(&ack).expect("parse");
        assert_eq!(ack.yiaddr(), offer.yiaddr());
        ack.yiaddr()
    }
}

fn warning_codes(status: &Value) -> Vec<String> {
    status["warnings"]
        .as_array()
        .map(|warnings| {
            warnings
                .iter()
                .filter_map(|warning| warning["code"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn active(report: &Value) -> u64 {
    report["leases"]
        .as_array()
        .expect("leases by state")
        .iter()
        .find(|count| count["state"] == "active")
        .and_then(|count| count["count"].as_u64())
        .unwrap_or(0)
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn the_dhcp_role_answers_dora_and_serves_the_same_leases_after_a_restart() {
    let port = udp_port();
    let relay_port = udp_port();
    let relay = Relay::new(relay_port, port);
    let mut node = Node::new()
        .with_args(&["--roles", "controller,dhcp"])
        .with_config(&format!(
            "[dhcp]\nlisten = [{{ address = \"127.0.0.1\", mode = \"relay\" }}]\nport = {port}\n\
             relay_port = {relay_port}\nworkers = 2\n\
             [store]\nsnapshot_every_entries = 40\nsnapshot_keep_entries = 5\n"
        ));
    let mut server = node.start();
    let line = format!("dhcp role answering on 127.0.0.1:{port} (relay)");
    server
        .wait_stdout_line(Duration::from_secs(10), |text| text.starts_with(&line))
        .unwrap_or_else(|| panic!("no dhcp line\n{}", server.diagnostics()));
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);

    // The network, its pool and the scope.
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
    api.post("/dhcp/scopes", &json!({ "prefix": prefix }))
        .expect(201);

    // DORA: the scope reaches the role through the feed.
    let first = relay.dora(1, Duration::from_secs(10));
    assert!(
        first.octets()[..3] == [192, 0, 2] && (100..=199).contains(&first.octets()[3]),
        "{first}"
    );

    // The report of the role, the lease and history routes, the system status.
    let status = api.get("/system/status").expect(200);
    let node_id = status["node"]["id"].as_u64().expect("a node id");
    assert!(
        status["node"]["roles"]
            .as_array()
            .expect("roles")
            .contains(&json!("dhcp")),
        "{status}"
    );
    let codes = warning_codes(&status);
    assert!(
        codes.iter().all(|code| !code.starts_with("dhcp.")),
        "{codes:?}"
    );
    let report = api.get(&format!("/nodes/{node_id}/dhcp")).expect(200);
    assert_eq!(report["serving"], true, "{report}");
    assert_eq!(report["accepting"], true, "{report}");
    assert_eq!(report["scopes"], 1, "{report}");
    assert_eq!(active(&report), 1, "{report}");
    assert!(report["last_commit_ms"].as_f64().is_some(), "{report}");
    let listener = &report["listeners"][0];
    assert_eq!(listener["address"], "127.0.0.1", "{report}");
    assert_eq!(listener["port"], port, "{report}");
    assert_eq!(listener["mode"], "relay", "{report}");
    assert_eq!(listener["workers"], 2, "{report}");
    let leases = api.get("/dhcp/leases").expect(200);
    let items = leases["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{leases}");
    assert_eq!(items[0]["addr"], first.to_string());
    assert_eq!(items[0]["state"], "active");
    assert_eq!(items[0]["hostname"], "client01");
    let one = api.get(&format!("/dhcp/leases/{first}")).expect(200);
    assert_eq!(one["addr"], first.to_string());
    api.get("/dhcp/leases/192.0.2.250").expect(404);
    let history = api.get("/dhcp/history").expect(200);
    assert_eq!(history["items"][0]["kind"], "granted", "{history}");
    assert_eq!(history["items"][0]["addr"], first.to_string());
    let node_leases = api
        .get(&format!("/nodes/{node_id}/dhcp/leases?limit=1"))
        .expect(200);
    assert_eq!(node_leases["items"].as_array().map(Vec::len), Some(1));

    // More clients than the snapshot interval: the store snapshots behind them.
    let mut addresses = vec![first];
    for client in 2..=CLIENTS {
        let addr = relay.dora(client, Duration::from_secs(5));
        assert!(!addresses.contains(&addr), "{addr} twice");
        addresses.push(addr);
    }
    let report = api.get(&format!("/nodes/{node_id}/dhcp")).expect(200);
    assert_eq!(active(&report), u64::from(CLIENTS), "{report}");

    // A restart: the role serves the same leases from the store.
    server.stop().assert_graceful_shutdown();
    let mut server = node.start();
    server
        .wait_stdout_line(Duration::from_secs(10), |text| text.starts_with(&line))
        .unwrap_or_else(|| panic!("no dhcp line after the restart\n{}", server.diagnostics()));
    let report = api.get(&format!("/nodes/{node_id}/dhcp")).expect(200);
    assert_eq!(active(&report), u64::from(CLIENTS), "{report}");
    let mut renew = Ask::new(MessageType::Request, 1);
    renew.ciaddr = Some(first);
    let renewed = relay
        .exchange(&renew, MessageType::Ack, Duration::from_secs(5))
        .expect("the renewal is acknowledged");
    assert_eq!(Message::parse(&renewed).expect("parse").yiaddr(), first);
    let returning = relay
        .exchange(
            &Ask::new(MessageType::Discover, 2),
            MessageType::Offer,
            Duration::from_secs(5),
        )
        .expect("an offer for a returning client");
    assert_eq!(
        Message::parse(&returning).expect("parse").yiaddr(),
        addresses[1],
        "a client is offered its address again"
    );
    let all = api.get("/dhcp/leases?limit=1000").expect(200);
    let listed: Vec<String> = all["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["addr"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(listed.len(), usize::from(CLIENTS));
    for addr in &addresses {
        assert!(
            listed.contains(&addr.to_string()),
            "{addr} after the restart"
        );
    }

    // A release through the API.
    let released = api
        .post(
            &format!("/dhcp/leases/{first}/release"),
            &json!({ "reason": "acceptance" }),
        )
        .expect(200);
    assert_eq!(released["state"], "released", "{released}");
    api.post(&format!("/dhcp/leases/{first}/release"), &json!({}))
        .expect(409);
    let history = api.get(&format!("/dhcp/history?addr={first}")).expect(200);
    assert_eq!(history["items"][0]["kind"], "reclaimed", "{history}");
    server.stop().assert_graceful_shutdown();
}

#[test]
fn a_dhcp_role_without_a_listener_says_so() {
    let mut node = Node::new().with_args(&["--roles", "controller,dhcp"]);
    let server = node.start();
    server
        .wait_stdout_line(Duration::from_secs(10), |text| {
            text.starts_with("dhcp role answering on no listener")
        })
        .unwrap_or_else(|| panic!("no dhcp line\n{}", server.diagnostics()));
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    let status = api.get("/system/status").expect(200);
    assert!(
        warning_codes(&status).contains(&"dhcp.role.not_serving".to_owned()),
        "{status}"
    );
    let node_id = status["node"]["id"].as_u64().expect("a node id");
    let report = api.get(&format!("/nodes/{node_id}/dhcp")).expect(200);
    assert_eq!(report["serving"], false, "{report}");
    api.get(&format!("/nodes/{}/dhcp", node_id + 7)).expect(404);
    let mut server = server;
    server.stop().assert_graceful_shutdown();
}
