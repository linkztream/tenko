//! E28 (Phase 3, WP8.2) against the real binary, through the public API and the CLI: the
//! reconciliation view of IPAM-21 shows the four truths for the lab data with the ghost,
//! rogue, orphan, PTR-mismatch and conflict lists and the rule that wins in each, and a
//! lease's options 55 and 60 set the OS field of an unmanaged host (DHCP-14).
//!
//! One node with the `dhcp` role in relay mode on loopback (the test is the relay agent and
//! selects the scope with option 118), two networks with Tenko scopes, and:
//!
//! - intent: a `reserved` printer in 198.51.100.0/24, whose scope grants three-second
//!   leases, that never asks for one (the ghost); a `reserved` camera at 192.0.2.10; a
//!   `static` NAS at 192.0.2.80 with its DNS name; an `unmanaged` TV;
//! - leases through the role: the camera's reservation, the TV's pool lease with Android's
//!   option 55 and 60, and a pool lease of a Windows laptop nobody knows (the rogue);
//! - DNS records written by hand: an A record of 192.0.2.70 without a host (the orphan) and
//!   a PTR of 192.0.2.80 that names another host (the PTR mismatch);
//! - sightings: the bundled sample connector, whose inventory host reports 192.0.2.10 with
//!   another MAC address than the camera's lease (the conflict of IPAM-23). A probe's own
//!   sighting needs a network beyond the loopback, so the connector stands for the scans.
//!
//! The view lists exactly these five rows, the health view names the conflict, the TV's
//! host truths carry the DHCP fingerprint's guess, and `tenko ipam reconcile` prints the
//! same rows.

mod serve_support;

use std::{
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use serve_support::{Node, api::Api, wait_for_setup_token};
use tenko_dhcp::v4::{Message, MessageType};

const NET_A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 0);
const NET_B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 0);
const ZONE: &str = "example.test";
const REVERSE: &str = "2.0.192.in-addr.arpa";

/// Windows 10 and 11's parameter request list (option 55).
const WINDOWS: &[u8] = &[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252];
/// Android 13's.
const ANDROID: &[u8] = &[1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114, 108];

fn udp_port() -> u16 {
    UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind")
        .local_addr()
        .expect("address")
        .port()
}

/// One request the test relays for a device `00:00:5e:00:53:<client>` on `link`.
#[derive(Debug, Clone, Copy)]
struct Ask {
    kind: MessageType,
    client: u8,
    link: Ipv4Addr,
    requested: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
    parameters: &'static [u8],
    vendor: Option<&'static str>,
}

impl Ask {
    fn code(&self) -> u8 {
        match self.kind {
            MessageType::Discover => 1,
            MessageType::Request => 3,
            other => panic!("{other:?} is not sent here"),
        }
    }

    fn xid(&self) -> u32 {
        u32::from_be_bytes([0x28, self.link.octets()[0], self.code(), self.client])
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; 240];
        out[..4].copy_from_slice(&[1, 1, 6, 1]);
        out[4..8].copy_from_slice(&self.xid().to_be_bytes());
        out[24..28].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
        out[28..34].copy_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, self.client]);
        out[236..240].copy_from_slice(&[99, 130, 83, 99]);
        out.extend_from_slice(&[53, 1, self.code()]);
        out.extend_from_slice(&[118, 4]);
        out.extend_from_slice(&self.link.octets());
        if !self.parameters.is_empty() {
            out.push(55);
            out.push(u8::try_from(self.parameters.len()).expect("short"));
            out.extend_from_slice(self.parameters);
        }
        if let Some(vendor) = self.vendor {
            out.push(60);
            out.push(u8::try_from(vendor.len()).expect("short"));
            out.extend_from_slice(vendor.as_bytes());
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
        let socket =
            UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).expect("bind the relay");
        socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        Self {
            socket,
            server: SocketAddrV4::new(Ipv4Addr::LOCALHOST, server),
        }
    }

    fn exchange(&self, ask: &Ask, expect: MessageType) -> Option<Vec<u8>> {
        let start = Instant::now();
        let mut buf = [0u8; 1500];
        while start.elapsed() < Duration::from_secs(15) {
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
                if message.xid() == ask.xid()
                    && message.message_type().ok().flatten() == Some(expect)
                {
                    return Some(buf[..len].to_vec());
                }
            }
        }
        None
    }

    /// A DORA exchange; the address of the ACK.
    fn dora(
        &self,
        client: u8,
        link: Ipv4Addr,
        parameters: &'static [u8],
        vendor: Option<&'static str>,
    ) -> Ipv4Addr {
        let discover = Ask {
            kind: MessageType::Discover,
            client,
            link,
            requested: None,
            server_id: None,
            parameters,
            vendor,
        };
        let offer = self
            .exchange(&discover, MessageType::Offer)
            .unwrap_or_else(|| panic!("no OFFER for device {client:02x}"));
        let offer = Message::parse(&offer).expect("parse");
        let request = Ask {
            kind: MessageType::Request,
            requested: Some(offer.yiaddr()),
            server_id: offer.server_identifier().expect("54"),
            ..discover
        };
        let ack = self
            .exchange(&request, MessageType::Ack)
            .unwrap_or_else(|| panic!("no ACK for device {client:02x}"));
        Message::parse(&ack).expect("parse").yiaddr()
    }
}

fn id_of(reply: &Value) -> String {
    reply["item"]["id"]
        .as_str()
        .or_else(|| reply["id"].as_str())
        .unwrap_or_else(|| panic!("an id in {reply}"))
        .to_owned()
}

/// A host with one interface `00:00:5e:00:53:<client>` and, when given, an address.
fn host(api: &Api, name: &str, mode: &str, client: u8, ip: &str, dns: Option<&str>) -> String {
    let host = id_of(
        &api.post(
            "/hosts",
            &json!({
                "name": name,
                "mode": mode,
                "interfaces": [{ "name": "eth0", "mac": format!("00-00-5E-00-53-{client:02X}") }],
            }),
        )
        .expect(201),
    );
    let interfaces = api.get(&format!("/hosts/{host}/interfaces")).expect(200);
    let interface = interfaces["items"][0]["id"].as_str().expect("an interface");
    let mut address = json!({ "ip": ip, "interface": interface });
    if let Some(dns) = dns {
        address["dns_name"] = json!(dns);
    }
    api.post("/addresses", &address).expect(201);
    host
}

fn zone(api: &Api, name: &str) -> String {
    id_of(
        &api.post(
            "/dns/zones",
            &json!({
                "name": name,
                "kind": "primary",
                "soa": { "mname": "ns1.example.test", "rname": "hostmaster.example.test" },
                "name_servers": ["ns1.example.test"],
            }),
        )
        .expect(201),
    )
}

/// The rows of the view as (address, kind).
fn rows(page: &Value) -> Vec<(String, String)> {
    page["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|row| {
            (
                row["address"].as_str().expect("address").to_owned(),
                row["kind"].as_str().expect("kind").to_owned(),
            )
        })
        .collect()
}

fn row<'a>(page: &'a Value, kind: &str) -> &'a Value {
    page["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|row| row["kind"] == kind)
        .unwrap_or_else(|| panic!("no {kind} row in {page}"))
}

#[test]
#[allow(clippy::too_many_lines)] // One acceptance scenario: seed the four truths, read the view.
fn e28_the_view_lists_every_seeded_case_and_a_lease_sets_the_os_of_an_unmanaged_host() {
    let port = udp_port();
    let relay_port = udp_port();
    let relay = Relay::new(relay_port, port);
    let mut node = Node::new()
        .with_args(&["--roles", "controller,dhcp"])
        .with_config(&format!(
            "[dhcp]\nlisten = [{{ address = \"127.0.0.1\", mode = \"relay\" }}]\n\
             port = {port}\nrelay_port = {relay_port}\nworkers = 2\n"
        ));
    let mut server = node.start();
    let line = format!("dhcp role answering on 127.0.0.1:{port} (relay)");
    server
        .wait_stdout_line(Duration::from_secs(10), |text| text.starts_with(&line))
        .unwrap_or_else(|| panic!("no dhcp line\n{}", server.diagnostics()));
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    // The runs the test asks for do the work; the DNS actuator stays off, so that the
    // records are the ones written here.
    api.put(
        "/settings/reconciler",
        &json!({
            "interval_secs": 86_400,
            "debounce_secs": 300,
            "orphan_after_secs": 604_800,
            "retention_secs": 2_592_000,
            "refresh_secs": 900,
            "purge_interval_secs": 3_600,
            "adopt": false,
            "dns_actuator": false,
            "dns_orphans": "propose"
        }),
    )
    .expect(200);

    // Intent: two networks with pools and Tenko scopes; B grants three-second leases.
    for (cidr, pool, lease) in [
        ("192.0.2.0/24", ("192.0.2.100", "192.0.2.199"), 3_600),
        ("198.51.100.0/24", ("198.51.100.100", "198.51.100.199"), 3),
    ] {
        let prefix = id_of(&api.post("/prefixes", &json!({ "cidr": cidr })).expect(201));
        api.post(
            &format!("/prefixes/{prefix}/ranges"),
            &json!({ "first": pool.0, "last": pool.1, "role": "dhcp_pool" }),
        )
        .expect(201);
        api.post(
            "/dhcp/scopes",
            &json!({
                "prefix": prefix,
                "lease": { "default_secs": lease, "min_secs": 1, "max_secs": 86_400 },
            }),
        )
        .expect(201);
    }
    let printer = host(&api, "printer", "reserved", 0x20, "198.51.100.20", None);
    host(&api, "camera", "reserved", 0x61, "192.0.2.10", None);
    let nas = host(
        &api,
        "nas",
        "static",
        0x80,
        "192.0.2.80",
        Some("nas.example.test"),
    );
    let tv = host(&api, "tv", "unmanaged", 0x90, "192.0.2.90", None);
    let ghost_since = Instant::now();

    // DNS: an A record without a host, and a PTR that names another host than the NAS.
    let forward = zone(&api, ZONE);
    let reverse = zone(&api, REVERSE);
    api.post(
        &format!("/dns/zones/{forward}/records/batch"),
        &json!({ "changes": [
            { "op": "set", "name": "old.example.test", "type": "A",
              "records": [{ "type": "A", "address": "192.0.2.70" }] },
            { "op": "set", "name": "nas.example.test", "type": "A",
              "records": [{ "type": "A", "address": "192.0.2.80" }] },
        ]}),
    )
    .expect(200);
    api.post(
        &format!("/dns/zones/{reverse}/records/batch"),
        &json!({ "changes": [
            { "op": "set", "name": "80.2.0.192.in-addr.arpa", "type": "PTR",
              "records": [{ "type": "PTR", "target": "storage.example.test" }] },
        ]}),
    )
    .expect(200);

    // Leases through the role: the camera's reservation, the TV's and a stranger's pool
    // leases with the options of Android and Windows.
    let camera = {
        let start = Instant::now();
        loop {
            let got = relay.dora(0x61, NET_A, &[1, 3, 6, 15], None);
            if got == Ipv4Addr::new(192, 0, 2, 10) || start.elapsed() > Duration::from_secs(20) {
                break got;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    assert_eq!(
        camera,
        Ipv4Addr::new(192, 0, 2, 10),
        "the camera's reservation"
    );
    let tv_lease = relay.dora(0x90, NET_A, ANDROID, Some("android-dhcp-13"));
    let laptop = relay.dora(0x50, NET_A, WINDOWS, Some("MSFT 5.0"));
    assert!(tv_lease.octets()[3] >= 100 && laptop.octets()[3] >= 100);
    let _ = NET_B;

    // Sightings: the sample connector's one inventory host at 192.0.2.10 with its own MAC.
    let connector = id_of(
        &api.post(
            "/connectors",
            &json!({ "plugin": "sample", "name": "Lab inventory", "settings": { "hosts": 1 } }),
        )
        .expect(201),
    );
    let start = Instant::now();
    while api.get(&format!("/connectors/{connector}")).ok()["health"]["process"]["state"]
        != "running"
    {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "the connector does not run"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let run = api
        .post(&format!("/connectors/{connector}/run"), &json!({}))
        .expect(202);
    let job = run["job"].as_str().expect("a job").to_owned();
    let detail = api.wait_for_job(&job, Duration::from_secs(60));
    assert_eq!(detail["job"]["state"], "succeeded", "{detail}");

    // The ghost needs more than its scope's three seconds unseen.
    if let Some(left) = Duration::from_secs(4).checked_sub(ghost_since.elapsed()) {
        std::thread::sleep(left);
    }
    // A run ingests the zones' records and proposes the stranger as a discovered host.
    api.post("/proposals/reconcile", &json!({})).expect(200);

    let page = api.get("/ipam/reconcile").expect(200);
    let laptop_text = laptop.to_string();
    let mut expected = vec![
        ("192.0.2.10".to_owned(), "conflict".to_owned()),
        ("192.0.2.70".to_owned(), "orphan".to_owned()),
        ("192.0.2.80".to_owned(), "ptr_mismatch".to_owned()),
        (laptop_text.clone(), "rogue".to_owned()),
        ("198.51.100.20".to_owned(), "ghost".to_owned()),
    ];
    expected.sort_by_key(|(ip, _)| ip.parse::<Ipv4Addr>().expect("ip"));
    assert_eq!(rows(&page), expected, "{page}");

    let ghost = row(&page, "ghost");
    assert_eq!(ghost["host"], json!(printer));
    assert_eq!(
        (&ghost["rule_id"], &ghost["winner"]),
        (&json!("intent_managed"), &json!("intent"))
    );
    let rogue = row(&page, "rogue");
    assert_eq!(rogue["rule_id"], "newest_sighting");
    assert_eq!(rogue["winner"], "lease");
    assert!(
        rogue["proposal"].is_string(),
        "the discovered-host proposal: {rogue}"
    );
    assert_eq!(
        rogue["os"]["guess"],
        "Windows 10 or 11 (or Server 2016 and later)"
    );
    assert_eq!(rogue["vendors"], json!(["MSFT 5.0"]));
    let conflict = row(&page, "conflict");
    assert_eq!(conflict["rule_id"], "never_automatic");
    assert!(conflict.get("winner").is_none(), "{conflict}");
    assert_eq!(
        conflict["macs"],
        json!(["00:00:5e:00:53:00", "00:00:5e:00:53:61"])
    );
    assert!(
        conflict["lease"]["sources"][0]
            .as_str()
            .expect("source")
            .starts_with("dhcp:")
    );
    assert!(
        conflict["scan"]["sources"][0]
            .as_str()
            .expect("source")
            .starts_with("inventory:")
    );
    let orphan = row(&page, "orphan");
    assert_eq!(
        (&orphan["rule_id"], &orphan["winner"]),
        (&json!("manual_record"), &json!("dns"))
    );
    let mismatch = row(&page, "ptr_mismatch");
    assert_eq!(mismatch["host"], json!(nas));
    assert_eq!(mismatch["dns"]["ptr"], json!(["storage.example.test"]));
    assert_eq!(mismatch["winner"], "intent");

    // The filters: one kind, one host.
    let ghosts = api.get("/ipam/reconcile?kind=ghost").expect(200);
    assert_eq!(
        rows(&ghosts),
        [("198.51.100.20".to_owned(), "ghost".to_owned())]
    );

    // The unmanaged TV: its lease's options 55 and 60 set the OS field.
    let tv_view = api.get(&format!("/ipam/reconcile?host={tv}")).expect(200);
    assert_eq!(rows(&tv_view), Vec::<(String, String)>::new());
    let os = &tv_view["host"]["os"];
    assert_eq!(os["guess"], "Android 13", "{tv_view}");
    assert_eq!(os["truth"], "lease");
    assert_eq!(os["confidence"], 90);
    assert!(os["source"].as_str().expect("source").starts_with("dhcp:"));
    assert_eq!(tv_view["host"]["vendors"], json!(["android-dhcp-13"]));

    // The health view names the conflict.
    let status = api.get("/system/status").expect(200);
    let warning = status["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .find(|warning| warning["code"] == "ipam.lease_conflict")
        .unwrap_or_else(|| panic!("no lease conflict in {status}"));
    assert_eq!(warning["params"]["addresses"], "192.0.2.10");

    // The CLI prints the same rows.
    node.login().assert_code(0);
    let cli_rows = node.client(&["ipam", "reconcile", "--json"]);
    cli_rows.assert_code(0);
    assert_eq!(rows(&cli_rows.json()), expected);
    let kinds = node.client(&["ipam", "reconcile", "--kind", "conflict"]);
    kinds.assert_code(0);
    let text = kinds.stdout.clone();
    assert!(
        text.contains("192.0.2.10") && text.contains("never_automatic"),
        "{text}"
    );
    let _ = tv_lease;

    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
}
