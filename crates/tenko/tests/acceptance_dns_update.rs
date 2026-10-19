//! Acceptance of dynamic updates (WP6.2, E18 with the lab's `nsupdate` round) through the
//! real binary: one node with `--roles controller,dns` and an RFC 2136 client in the test,
//! over UDP and TCP.
//!
//! - Add, replace, delete a record and delete a name, signed with TSIG: each is answered
//!   NOERROR and the next query sees it, since the node answers only once its index holds
//!   the commit.
//! - Each prerequisite of RFC 2136 section 2.4, held and not held.
//! - REFUSED without the key and outside the access lists; NOTAUTH for a key the node does
//!   not know.
//! - An RRset of origin `ipam` (the actuator's) is refused until the zone allows updates to
//!   replace it.
//! - SERVFAIL while the store refuses writes (the store's test hook, feature `test-hooks`),
//!   with nothing written; the same update goes through once the store writes again.

mod serve_support;

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use serve_support::{Node, Proc, READY_TIMEOUT, api::Api, free_port, wait_for_setup_token};
use tenko_core::dns::{DnsName, TsigAlgorithm};
use tenko_dns::{
    tsig::{self, Signer, TsigKey, Verifier},
    update::message::{
        CLASS_ANY, CLASS_IN, CLASS_NONE, TYPE_ANY, push_record, rcode, write_request,
    },
    wire::{self, MAX_MESSAGE_LEN},
};

const KEY: &str = "update.example.test";
const ZONE: &str = "example.test";
const TYPE_A: u16 = 1;
/// The key's secret, 32 octets, in base64 as the API takes it.
const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const SECRET_BASE64: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

fn wire_name(text: &str) -> Vec<u8> {
    DnsName::new(text).expect("name").to_wire()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// An UPDATE of `zone` under construction.
struct Msg {
    zone: String,
    prereq: (u16, Vec<u8>),
    update: (u16, Vec<u8>),
}

impl Msg {
    fn of(zone: &str) -> Self {
        Self {
            zone: zone.to_owned(),
            prereq: (0, Vec::new()),
            update: (0, Vec::new()),
        }
    }

    fn pre(mut self, owner: &str, rtype: u16, class: u16, data: &[u8]) -> Self {
        push_record(&mut self.prereq.1, &wire_name(owner), rtype, class, 0, data);
        self.prereq.0 += 1;
        self
    }

    fn add(mut self, owner: &str, ttl: u32, address: [u8; 4]) -> Self {
        push_record(
            &mut self.update.1,
            &wire_name(owner),
            TYPE_A,
            CLASS_IN,
            ttl,
            &address,
        );
        self.update.0 += 1;
        self
    }

    fn delete(mut self, owner: &str, rtype: u16) -> Self {
        push_record(
            &mut self.update.1,
            &wire_name(owner),
            rtype,
            CLASS_ANY,
            0,
            &[],
        );
        self.update.0 += 1;
        self
    }

    fn delete_record(mut self, owner: &str, address: [u8; 4]) -> Self {
        push_record(
            &mut self.update.1,
            &wire_name(owner),
            TYPE_A,
            CLASS_NONE,
            0,
            &address,
        );
        self.update.0 += 1;
        self
    }

    fn bytes(&self, key: Option<&Arc<TsigKey>>) -> (Vec<u8>, Option<Signer>) {
        let mut out = Vec::new();
        write_request(
            &mut out,
            0x2136,
            &wire_name(&self.zone),
            (self.prereq.0, &self.prereq.1),
            (self.update.0, &self.update.1),
        );
        // EDNS, so that the answer carries its extended error.
        out.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        out[11] = 1;
        let signer = key.map(|key| {
            let mut signer = Signer::request(Arc::clone(key));
            assert!(signer.sign(&mut out, now(), 0, &[], MAX_MESSAGE_LEN));
            signer
        });
        (out, signer)
    }
}

/// The RCODE, the TSIG error and the extended error text of an answer, its signature
/// checked when the request was signed.
#[derive(Debug)]
struct Got {
    rcode: u8,
    tsig_error: Option<u16>,
    text: Option<String>,
}

fn read(answer: &[u8], signer: Option<&Signer>) -> Got {
    let header = wire::parse_header(answer).expect("header");
    assert!(header.qr && header.opcode == 5, "an UPDATE answer");
    let tsig_error = tsig::find(answer).expect("tsig").map(|view| view.error);
    if let (Some(signer), None | Some(0)) = (signer, tsig_error) {
        let mut verifier = Verifier::new(
            Arc::clone(signer.key()),
            signer.last_mac().expect("request MAC"),
        );
        verifier
            .verify(answer, now())
            .expect("the answer is signed");
    }
    let mut text = None;
    let mut pos = wire::questions_end(answer, header.qdcount).expect("zone");
    for _ in 0..header.arcount {
        let record = wire::read_record(answer, pos).expect("record");
        if record.rtype == wire::TYPE_OPT {
            for (code, value) in wire::options(record.data(answer)) {
                if code == wire::OPTION_EXTENDED_ERROR && value.len() >= 2 {
                    text = Some(String::from_utf8_lossy(&value[2..]).into_owned());
                }
            }
        }
        pos = record.end();
    }
    Got {
        rcode: header.rcode,
        tsig_error,
        text,
    }
}

fn udp_exchange(server: SocketAddr, message: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a client");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    socket.send_to(message, server).expect("send");
    let mut buf = vec![0u8; 4096];
    let (len, _) = socket.recv_from(&mut buf).expect("an answer");
    buf.truncate(len);
    buf
}

fn tcp_exchange(server: SocketAddr, message: &[u8]) -> Vec<u8> {
    let mut stream =
        TcpStream::connect_timeout(&server, Duration::from_secs(3)).expect("connect over TCP");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let len = u16::try_from(message.len()).expect("length");
    stream.write_all(&len.to_be_bytes()).expect("write");
    stream.write_all(message).expect("write");
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).expect("the answer's length");
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut answer).expect("the answer");
    answer
}

fn query_a(server: SocketAddr, name: &str) -> Vec<u8> {
    let mut query = Vec::new();
    wire::write_query(&mut query, 7, name, TYPE_A, Some(1232));
    udp_exchange(server, &query)
}

fn holds(answer: &[u8], address: [u8; 4]) -> bool {
    wire::parse_header(answer).expect("header").ancount > 0
        && answer.windows(4).any(|window| window == address)
}

struct Lab {
    node: Node,
    _server: Proc,
    api: Api,
    dns: SocketAddr,
    key: Arc<TsigKey>,
    zone: String,
    acl: String,
}

impl Lab {
    fn send(&self, msg: &Msg, key: Option<&Arc<TsigKey>>) -> Got {
        let (message, signer) = msg.bytes(key);
        read(&udp_exchange(self.dns, &message), signer.as_ref())
    }

    fn signed(&self, msg: &Msg) -> Got {
        self.send(msg, Some(&self.key))
    }

    fn refuse_file(&self) -> std::path::PathBuf {
        self.node.root().join("refuse-writes")
    }
}

fn zone_body(name: &str, allowed: &[&str], may_replace_ipam: bool) -> Value {
    json!({
        "name": name,
        "kind": "primary",
        "serial": "counter",
        "soa": { "mname": "ns1.example.test", "rname": "hostmaster.example.test" },
        "name_servers": ["ns1.example.test"],
        "update": { "allowed": allowed, "require_tsig": true, "may_replace_ipam": may_replace_ipam },
    })
}

fn start() -> Lab {
    let dns: SocketAddr = (Ipv4Addr::LOCALHOST, free_port()).into();
    let node = Node::new()
        .with_args(&["--roles", "controller,dns"])
        .with_config(&format!("[dns]\nlisten = [\"{dns}\"]\nworkers = 1\n"));
    node.write_config();
    let mut command = node.serve_command();
    command.env(
        "TENKO_TEST_REFUSE_WRITES_FILE",
        node.root().join("refuse-writes"),
    );
    let server = Proc::spawn(command);
    server
        .wait_stdout_line(READY_TIMEOUT, |line| {
            line.starts_with(&format!("dns role answering on {dns}"))
        })
        .unwrap_or_else(|| panic!("no dns line\n{}", server.diagnostics()));
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    api.post("/dns/keys", &json!({"name": KEY, "secret": SECRET_BASE64}))
        .expect(201);
    let key = Arc::new(TsigKey::new(
        &DnsName::new(KEY).expect("key name"),
        TsigAlgorithm::HmacSha256,
        SECRET,
    ));
    let acl = api
        .post(
            "/dns/acls",
            &json!({"name": "updaters", "entries": [{"kind": "key", "name": KEY}]}),
        )
        .expect(201);
    let acl = acl["id"].as_str().expect("acl id").to_owned();
    let zone = api
        .post("/dns/zones", &zone_body(ZONE, &[&acl], false))
        .expect(201);
    let zone = zone["id"].as_str().expect("zone id").to_owned();
    Lab {
        node,
        _server: server,
        api,
        dns,
        key,
        zone,
        acl,
    }
}

const A_9: [u8; 4] = [192, 0, 2, 9];
const A_10: [u8; 4] = [192, 0, 2, 10];

/// E18, DNS-11, TGL-09: updates signed with TSIG applied through the store and answered from the
/// index, refused without the key and outside the access lists, the IPAM origin rule, and
/// SERVFAIL while the store refuses writes.
#[test]
#[allow(clippy::too_many_lines, reason = "one node, the whole round in order")]
fn updates_are_applied_through_the_store_and_answered_from_the_index() {
    let lab = start();
    let new = "new.example.test";

    // Add: NOERROR, and the very next query is answered with it.
    let got = lab.signed(&Msg::of(ZONE).add(new, 120, A_9));
    assert_eq!(got.rcode, 0, "{got:?}");
    assert!(
        holds(&query_a(lab.dns, new), A_9),
        "the index holds the add"
    );
    let records = lab
        .api
        .list_all(&format!("/dns/zones/{}/records", lab.zone));
    let rrset = records
        .iter()
        .find(|rrset| rrset["name"] == new && rrset["type"] == "A")
        .expect("the RRset");
    assert_eq!(
        (rrset["origin"].as_str(), rrset["key"].as_str()),
        (Some("dynamic"), Some(KEY))
    );

    // Replace over TCP: delete the RRset and add, in one update.
    let (message, signer) = Msg::of(ZONE)
        .delete(new, TYPE_A)
        .add(new, 120, A_10)
        .bytes(Some(&lab.key));
    let got = read(&tcp_exchange(lab.dns, &message), signer.as_ref());
    assert_eq!(got.rcode, 0, "{got:?}");
    let answer = query_a(lab.dns, new);
    assert!(holds(&answer, A_10) && !holds(&answer, A_9), "replaced");

    // Delete one record, then a name.
    let got = lab.signed(&Msg::of(ZONE).add(new, 120, A_9).delete_record(new, A_10));
    assert_eq!(got.rcode, 0, "{got:?}");
    let answer = query_a(lab.dns, new);
    assert!(holds(&answer, A_9) && !holds(&answer, A_10));
    let got = lab.signed(&Msg::of(ZONE).delete(new, TYPE_ANY));
    assert_eq!(got.rcode, 0, "{got:?}");
    assert_eq!(
        wire::parse_header(&query_a(lab.dns, new))
            .expect("header")
            .rcode,
        3,
        "NXDOMAIN"
    );

    // The prerequisites.
    let absent = "absent.example.test";
    let cases = [
        (Msg::of(ZONE).pre(ZONE, 2, CLASS_ANY, &[]), 0),
        (
            Msg::of(ZONE).pre(absent, TYPE_A, CLASS_ANY, &[]),
            rcode::NXRRSET,
        ),
        (Msg::of(ZONE).pre(ZONE, 2, CLASS_NONE, &[]), rcode::YXRRSET),
        (Msg::of(ZONE).pre(absent, TYPE_A, CLASS_NONE, &[]), 0),
        (Msg::of(ZONE).pre(ZONE, TYPE_ANY, CLASS_ANY, &[]), 0),
        (
            Msg::of(ZONE).pre(absent, TYPE_ANY, CLASS_ANY, &[]),
            rcode::NXDOMAIN,
        ),
        (
            Msg::of(ZONE).pre(ZONE, TYPE_ANY, CLASS_NONE, &[]),
            rcode::YXDOMAIN,
        ),
        (Msg::of(ZONE).pre(absent, TYPE_ANY, CLASS_NONE, &[]), 0),
        // Compared in canonical form: the server's name in another case.
        (
            Msg::of(ZONE).pre(ZONE, 2, CLASS_IN, b"\x03NS1\x07Example\x04Test\x00"),
            0,
        ),
        (
            Msg::of(ZONE).pre(ZONE, 2, CLASS_IN, &wire_name(absent)),
            rcode::NXRRSET,
        ),
    ];
    for (index, (msg, want)) in cases.iter().enumerate() {
        let got = lab.signed(msg);
        assert_eq!(
            u16::from(got.rcode),
            *want,
            "prerequisite case {index}: {got:?}"
        );
    }
    let got = lab.signed(
        &Msg::of(ZONE)
            .pre(absent, TYPE_ANY, CLASS_ANY, &[])
            .add(absent, 60, A_9),
    );
    assert_eq!(u16::from(got.rcode), rcode::NXDOMAIN);
    assert!(
        !holds(&query_a(lab.dns, absent), A_9),
        "a prerequisite stops the update"
    );

    // Without the key, with a key the node does not know, outside the access lists.
    let got = lab.send(&Msg::of(ZONE).add(new, 60, A_9), None);
    assert_eq!(u16::from(got.rcode), rcode::REFUSED, "{got:?}");
    let stranger = Arc::new(TsigKey::new(
        &DnsName::new("stranger.example.test").expect("name"),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef",
    ));
    let got = lab.send(&Msg::of(ZONE).add(new, 60, A_9), Some(&stranger));
    assert_eq!(
        (u16::from(got.rcode), got.tsig_error),
        (rcode::NOTAUTH, Some(17))
    );
    let remote = lab
        .api
        .post(
            "/dns/acls",
            &json!({"name": "remote", "entries": [{"kind": "prefix", "prefix": "192.0.2.0/24"}]}),
        )
        .expect(201);
    let remote = remote["id"].as_str().expect("acl id").to_owned();
    lab.api
        .post("/dns/zones", &zone_body("other.test", &[&remote], false))
        .expect(201);
    let got = lab.signed(&Msg::of("other.test").add("www.other.test", 60, A_9));
    assert_eq!(u16::from(got.rcode), rcode::REFUSED, "{got:?}");
    assert_eq!(
        got.text.as_deref(),
        Some("the client is not in the zone's update access lists")
    );
    assert!(!holds(&query_a(lab.dns, new), A_9));

    // The origin rule: the actuator's record is refused, until the zone allows it.
    lab.api
        .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
        .expect(201);
    lab.api
        .post(
            "/addresses",
            &json!({ "ip": "192.0.2.70", "dns_name": "cam.example.test" }),
        )
        .expect(201);
    let run = lab
        .api
        .post_unkeyed("/proposals/reconcile", &json!({}))
        .expect(200);
    assert!(run["dns"]["failures"].is_null(), "{run}");
    assert!(holds(
        &query_a(lab.dns, "cam.example.test"),
        [192, 0, 2, 70]
    ));
    let replace = Msg::of(ZONE)
        .delete("cam.example.test", TYPE_A)
        .add("cam.example.test", 60, A_9);
    let got = lab.signed(&replace);
    assert_eq!(u16::from(got.rcode), rcode::REFUSED, "{got:?}");
    assert!(
        got.text
            .as_deref()
            .is_some_and(|text| text.starts_with("cam.example.test A belongs to IPAM")),
        "{got:?}"
    );
    lab.api
        .patch(
            &format!("/dns/zones/{}", lab.zone),
            &json!({"update": {"allowed": [lab.acl], "require_tsig": true, "may_replace_ipam": true}}),
            None,
        )
        .expect(200);
    // The update path reads the zone row from its directory, which follows the store.
    let mut got = lab.signed(&replace);
    for _ in 0..50 {
        if got.rcode == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        got = lab.signed(&replace);
    }
    assert_eq!(got.rcode, 0, "{got:?}");
    assert!(holds(&query_a(lab.dns, "cam.example.test"), A_9));

    // A write the store refuses: SERVFAIL, nothing written; then the retry goes through.
    if cfg!(feature = "test-hooks") {
        std::fs::write(lab.refuse_file(), b"").expect("cut the quorum");
        let got = lab.signed(&Msg::of(ZONE).add("late.example.test", 60, A_9));
        assert_eq!(u16::from(got.rcode), rcode::SERVFAIL, "{got:?}");
        assert!(
            got.text
                .as_deref()
                .is_some_and(|text| text.contains("sys.store.no_quorum")),
            "{got:?}"
        );
        assert!(!holds(&query_a(lab.dns, "late.example.test"), A_9));
        std::fs::remove_file(lab.refuse_file()).expect("heal");
        let got = lab.signed(&Msg::of(ZONE).add("late.example.test", 60, A_9));
        assert_eq!(got.rcode, 0, "{got:?}");
        assert!(holds(&query_a(lab.dns, "late.example.test"), A_9));
    }
}
