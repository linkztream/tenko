//! Acceptance of the `dns` role in the process (WP4.3, plan section 2.10) through the real
//! binary: one node with `--roles controller,dns` and the DNS module on.
//!
//! - A zone and its records created through the API are answered over UDP and TCP on a
//!   loopback port, with the SOA in NXDOMAIN and NODATA answers (RFC 2308).
//! - A client asking for a name outside the zones gets the answer of an upstream through
//!   the forwarder, with RA set; the upstream is a UDP responder in the test.
//! - `GET /nodes/{id}/dns` reports the role; the cache flush and the query log read are node
//!   commands executed in place; `GET /system/status` lists the role.
//! - A batch of 1,000 records is answered within one second of its commit.
//! - After a restart the node answers its zones again, from the store.
//! - The resolver side (WP5.1): a forwarding rule created through the API routes its names
//!   to its own upstream; the second answer comes from the cache (the upstream is not asked
//!   again and the status counts the hit); a flush by suffix empties it; and a client that is
//!   not on loopback is refused until IPAM knows a prefix that holds its address.
//! - Block lists (WP5.2): a hosts list fetched from an HTTP server in the test blocks its
//!   names and the names under them with NXDOMAIN and the extended error "Blocked"; a second
//!   fetch sends the entity tag, gets 304 and keeps the version; the node status counts the
//!   blocked queries of the list; a disabled list blocks nothing.

mod serve_support;

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use serve_support::{Node, api::Api, free_port, wait_for_setup_token};
use tenko_dns::wire;

const ZONE: &str = "example.test";
const OUTSIDE: &str = "outside.example.org";
const TYPE_A: u16 = 1;
const TYPE_SOA: u16 = 6;
const NOERROR: u8 = 0;
const NXDOMAIN: u8 = 3;

/// An upstream resolver in the test: answers every A query with 203.0.113.9.
fn upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    upstream_answering([203, 0, 113, 9])
}

/// An upstream resolver in the test that answers every A query with `address`.
fn upstream_answering(answer_address: [u8; 4]) -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the upstream");
    let address = socket.local_addr().expect("address");
    let seen = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((len, from)) = socket.recv_from(&mut buf) {
            let query = &buf[..len];
            let Some(end) = wire::questions_end(query, 1) else {
                continue;
            };
            count.fetch_add(1, Ordering::Relaxed);
            let mut answer = Vec::with_capacity(end + 16);
            answer.extend_from_slice(&query[..2]);
            answer.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            answer.extend_from_slice(&query[wire::HEADER_LEN..end]);
            answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            answer.extend_from_slice(&answer_address);
            let _ = socket.send_to(&answer, from);
        }
    });
    (address, seen)
}

/// A query for `name` and `qtype` with RD set.
fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(&mut out, id, name, qtype, Some(1232));
    out[2] |= 0x01;
    out
}

fn udp(server: SocketAddr, name: &str, qtype: u16) -> Vec<u8> {
    udp_from(Ipv4Addr::LOCALHOST, server, name, qtype)
}

/// A UDP query from a socket bound to `local`.
fn udp_from(local: Ipv4Addr, server: SocketAddr, name: &str, qtype: u16) -> Vec<u8> {
    let socket = UdpSocket::bind((local, 0)).expect("bind a client");
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
            assert_eq!(wire::parse_header(&buf).expect("header").id, id);
            return buf;
        }
    }
    panic!("no UDP answer from {server} for {name}");
}

fn tcp(server: SocketAddr, name: &str, qtype: u16) -> Vec<u8> {
    let mut stream =
        TcpStream::connect_timeout(&server, Duration::from_secs(3)).expect("connect over TCP");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let message = query(42, name, qtype);
    let len = u16::try_from(message.len()).expect("length");
    stream.write_all(&len.to_be_bytes()).expect("write");
    stream.write_all(&message).expect("write");
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).expect("the answer's length");
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut answer).expect("the answer");
    answer
}

/// Whether `answer` holds the four octets of `address` in a record.
fn holds(answer: &[u8], address: [u8; 4]) -> bool {
    answer.windows(4).any(|window| window == address)
}

fn header(answer: &[u8]) -> wire::RawHeader {
    wire::parse_header(answer).expect("a header")
}

fn set_a(name: &str, address: &str) -> Value {
    json!({
        "op": "set", "name": name, "type": "A", "ttl": 300,
        "records": [{"type": "A", "address": address}],
    })
}

fn batch(api: &Api, zone: &str, changes: &[Value]) {
    api.post(
        &format!("/dns/zones/{zone}/records/batch"),
        &json!({ "changes": changes }),
    )
    .expect(200);
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn the_dns_role_serves_zones_forwards_and_survives_a_restart() {
    let began = Instant::now();
    let (upstream, asked) = upstream();
    let port = free_port();
    let dns: SocketAddr = (Ipv4Addr::LOCALHOST, port).into();
    let mut node = Node::new()
        .with_args(&["--roles", "controller,dns"])
        .with_config(&format!(
            "[dns]\nlisten = [\"{dns}\"]\nworkers = 2\nforwarders = [\"{upstream}\"]\n\
             forward_timeout_ms = 1000\n[dns.log]\nenabled = true\npseudonymise = false\n"
        ));
    let mut server = node.start();
    server
        .wait_stdout_line(Duration::from_secs(5), |line| {
            line.starts_with(&format!("dns role answering on {dns}"))
        })
        .unwrap_or_else(|| panic!("no dns line\n{}", server.diagnostics()));
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);

    // A zone with a record.
    let zone = api
        .post(
            "/dns/zones",
            &json!({
                "name": ZONE,
                "kind": "primary",
                "serial": "counter",
                "soa": {"mname": "ns1.example.test", "rname": "hostmaster.example.test"},
                "name_servers": ["ns1.example.test"],
            }),
        )
        .expect(201);
    let zone_id = zone["id"].as_str().expect("a zone id").to_owned();
    batch(
        &api,
        &zone_id,
        &[
            set_a("www.example.test", "192.0.2.10"),
            set_a("ns1.example.test", "192.0.2.53"),
        ],
    );

    // Answers over UDP and TCP.
    let deadline = Instant::now() + Duration::from_secs(2);
    let answer = loop {
        let answer = udp(dns, "www.example.test", TYPE_A);
        if holds(&answer, [192, 0, 2, 10]) || Instant::now() > deadline {
            break answer;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let head = header(&answer);
    assert!(head.qr && head.aa, "{head:?}");
    assert_eq!((head.rcode, head.ancount), (NOERROR, 1));
    assert!(holds(&answer, [192, 0, 2, 10]));
    let over_tcp = tcp(dns, "www.example.test", TYPE_A);
    assert_eq!(header(&over_tcp).ancount, 1);
    assert!(holds(&over_tcp, [192, 0, 2, 10]));

    // NXDOMAIN and NODATA carry the SOA; the SOA at the apex.
    let missing = udp(dns, "missing.example.test", TYPE_A);
    let head = header(&missing);
    assert_eq!((head.rcode, head.ancount, head.nscount), (NXDOMAIN, 0, 1));
    let nodata = udp(dns, "www.example.test", 28);
    let head = header(&nodata);
    assert_eq!((head.rcode, head.ancount, head.nscount), (NOERROR, 0, 1));
    let soa = udp(dns, ZONE, TYPE_SOA);
    assert_eq!((header(&soa).rcode, header(&soa).ancount), (NOERROR, 1));

    // A name outside the zones goes to the upstream.
    let outside = udp(dns, OUTSIDE, TYPE_A);
    let head = header(&outside);
    assert!(head.ra && !head.aa, "{head:?}");
    assert_eq!((head.rcode, head.ancount), (NOERROR, 1));
    assert!(holds(&outside, [203, 0, 113, 9]));
    assert!(asked.load(Ordering::Relaxed) >= 1);
    let outside_tcp = tcp(dns, OUTSIDE, TYPE_A);
    assert!(holds(&outside_tcp, [203, 0, 113, 9]));

    // The role in the status, the report, the commands.
    let status = api.get("/system/status").expect(200);
    let node_id = status["node"]["id"].as_u64().expect("a node id");
    assert!(
        status["node"]["roles"]
            .as_array()
            .expect("roles")
            .contains(&json!("dns")),
        "{status}"
    );
    let report = api.get(&format!("/nodes/{node_id}/dns")).expect(200);
    assert_eq!(report["serving"], true, "{report}");
    assert_eq!(report["zones"], 1, "{report}");
    assert_eq!(report["lag"], 0, "{report}");
    // The TCP query for the outside name was answered from the cache.
    assert_eq!(report["cache_entries"], 1, "{report}");
    assert!(report["cache_hits"].as_u64().unwrap_or(0) >= 1, "{report}");
    assert!(report["index_bytes"].as_u64().unwrap_or(0) > 0, "{report}");
    let workers = report["udp_workers"].as_array().expect("the UDP workers");
    assert_eq!(workers.len(), 2, "{report}");
    let received: u64 = workers
        .iter()
        .map(|worker| worker["received"].as_u64().unwrap_or(0))
        .sum();
    assert!(received >= 5, "{report}");
    let listeners = report["listeners"].as_array().expect("listeners");
    for transport in ["udp", "tcp"] {
        assert!(
            listeners
                .iter()
                .any(|listener| listener["transport"] == transport
                    && listener["address"] == dns.to_string()),
            "{report}"
        );
    }
    api.get(&format!("/nodes/{}/dns", node_id + 1000))
        .expect(404);
    let flushed = api
        .post(&format!("/nodes/{node_id}/dns/cache/flush"), &json!({}))
        .expect(202);
    assert!(flushed["command_id"].is_string(), "{flushed}");
    let report = api.get(&format!("/nodes/{node_id}/dns")).expect(200);
    assert_eq!(report["cache_entries"], 0, "{report}");
    let log_deadline = Instant::now() + Duration::from_secs(3);
    let log = loop {
        let log = api
            .get(&format!(
                "/nodes/{node_id}/dns/log?limit=50&qname=www.example.test"
            ))
            .expect(200);
        let lines = log["items"].as_array().map_or(0, Vec::len);
        if lines >= 2 || Instant::now() > log_deadline {
            break log;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let lines = log["items"].as_array().expect("log lines");
    assert!(lines.len() >= 2, "{log}");
    assert_eq!(lines[0]["qname"], "www.example.test", "{log}");
    assert_eq!(lines[0]["client"], "127.0.0.1", "{log}");
    // WP5.4: the filters, the audit record of every read, the kill switch.
    let by_client = api
        .get(&format!(
            "/nodes/{node_id}/dns/log?limit=5&client=127.0.0.1&rcode=0"
        ))
        .expect(200);
    assert!(
        !by_client["items"].as_array().expect("lines").is_empty(),
        "{by_client}"
    );
    let audited = api.get("/audit?action=dns.log.read&limit=10").expect(200);
    assert!(
        audited["items"].as_array().expect("records").len() >= 2,
        "{audited}"
    );
    api.post(&format!("/nodes/{node_id}/dns/log/stop"), &json!({}))
        .expect(202);
    let report = api.get(&format!("/nodes/{node_id}/dns")).expect(200);
    assert_eq!(report["query_log"]["state"], "stopped", "{report}");
    api.post(&format!("/nodes/{node_id}/dns/log/start"), &json!({}))
        .expect(202);
    let report = api.get(&format!("/nodes/{node_id}/dns")).expect(200);
    assert_eq!(report["query_log"]["state"], "on", "{report}");
    assert_eq!(report["query_log"]["client"], "address", "{report}");

    // 1,000 records in one batch, answered within one second of the commit.
    let changes: Vec<Value> = (0..1_000)
        .map(|n| {
            set_a(
                &format!("host-{n}.example.test"),
                &format!("198.51.100.{}", n % 250 + 1),
            )
        })
        .collect();
    batch(&api, &zone_id, &changes);
    let committed = Instant::now();
    loop {
        let answer = udp(dns, "host-999.example.test", TYPE_A);
        if header(&answer).ancount == 1 {
            break;
        }
        assert!(
            committed.elapsed() < Duration::from_secs(1),
            "the batch is not answered one second after its commit"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let visible = committed.elapsed();
    assert!(holds(
        &udp(dns, "host-999.example.test", TYPE_A),
        [198, 51, 100, 250]
    ));
    let report = api.get(&format!("/nodes/{node_id}/dns")).expect(200);
    assert_eq!(report["lag"], 0, "{report}");

    // A restart: the node answers its zones from the store again.
    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
    outcome.assert_stderr_contains("dns role stopped");
    let mut server = node.start();
    let mut api = Api::new(&node);
    api.login(None);
    let again = udp(dns, "www.example.test", TYPE_A);
    assert!(holds(&again, [192, 0, 2, 10]));
    assert!(holds(
        &udp(dns, "host-999.example.test", TYPE_A),
        [198, 51, 100, 250]
    ));
    assert_eq!(
        header(&tcp(dns, "missing.example.test", TYPE_A)).rcode,
        NXDOMAIN
    );
    let report = api.get(&format!("/nodes/{node_id}/dns")).expect(200);
    assert_eq!(report["zones"], 1, "{report}");
    server.stop().assert_graceful_shutdown();
    eprintln!(
        "acceptance_dns: 1,000 records answered {} ms after the commit; the scenario took {} s",
        visible.as_millis(),
        began.elapsed().as_secs()
    );
}

/// This host's IPv4 address towards the documentation range, when it has one that is not
/// loopback (no packet is sent: a UDP socket only picks its route).
fn host_address() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(address) if !address.is_loopback() && !address.is_unspecified() => {
            Some(address)
        }
        _ => None,
    }
}

/// Asks until `done` holds for the answer or `within` passes; returns the last answer.
fn until(
    within: Duration,
    mut ask: impl FnMut() -> Vec<u8>,
    done: impl Fn(&[u8]) -> bool,
) -> Vec<u8> {
    let deadline = Instant::now() + within;
    loop {
        let answer = ask();
        if done(&answer) || Instant::now() > deadline {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn the_forwarder_follows_rules_caches_flushes_and_refuses_strangers() {
    let (default_upstream, _) = upstream();
    let (rule_upstream, asked) = upstream_answering([203, 0, 113, 20]);
    let port = free_port();
    let dns: SocketAddr = (Ipv4Addr::LOCALHOST, port).into();
    let host = host_address();
    let mut listen = vec![format!("\"{dns}\"")];
    if let Some(host) = host {
        listen.push(format!("\"{host}:{port}\""));
    }
    let mut node = Node::new()
        .with_args(&["--roles", "controller,dns"])
        .with_config(&format!(
            "[dns]\nlisten = [{}]\nworkers = 1\nforwarders = [\"{default_upstream}\"]\n\
             forward_timeout_ms = 1000\n",
            listen.join(", ")
        ));
    let mut server = node.start();
    server
        .wait_stdout_line(Duration::from_secs(5), |line| {
            line.starts_with("dns role answering on")
        })
        .unwrap_or_else(|| panic!("no dns line\n{}", server.diagnostics()));
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);

    // A rule for example.net sends its names to its own upstream.
    let rule = api
        .post(
            "/dns/forwarders",
            &json!({
                "suffix": "example.net",
                "upstreams": [{"address": "127.0.0.1", "port": rule_upstream.port()}],
                "description": "the test's second upstream",
            }),
        )
        .expect(201);
    assert_eq!(rule["transport"], "plain", "{rule}");
    let rules = api.get("/dns/forwarders").expect(200);
    assert_eq!(rules["items"].as_array().map_or(0, Vec::len), 1, "{rules}");
    let first = until(
        Duration::from_secs(3),
        || udp(dns, "www.example.net", TYPE_A),
        |answer| holds(answer, [203, 0, 113, 20]),
    );
    assert!(
        holds(&first, [203, 0, 113, 20]),
        "the rule's upstream answers"
    );
    assert!(holds(
        &udp(dns, "www.example.org", TYPE_A),
        [203, 0, 113, 9]
    ));

    // The second answer comes from the cache: the upstream is not asked again.
    let before = asked.load(Ordering::Relaxed);
    let second = udp(dns, "www.example.net", TYPE_A);
    assert!(holds(&second, [203, 0, 113, 20]));
    assert_eq!(
        asked.load(Ordering::Relaxed),
        before,
        "answered from the cache"
    );
    let node_id = api.get("/system/status").expect(200)["node"]["id"]
        .as_u64()
        .expect("a node id");
    let report = api.get(&format!("/nodes/{node_id}/dns")).expect(200);
    assert!(report["cache_hits"].as_u64().unwrap_or(0) >= 1, "{report}");
    assert!(
        report["cache_entries"].as_u64().unwrap_or(0) >= 2,
        "{report}"
    );
    assert!(report["cache_hit_ratio"].as_f64().is_some(), "{report}");

    // A flush by suffix: example.net goes, example.org stays.
    api.post(
        &format!("/nodes/{node_id}/dns/cache/flush?suffix=example.net"),
        &json!({}),
    )
    .expect(202);
    api.post(
        &format!("/nodes/{node_id}/dns/cache/flush?suffix=not..a..name"),
        &json!({}),
    )
    .expect(400);
    let report = api.get(&format!("/nodes/{node_id}/dns")).expect(200);
    assert_eq!(report["cache_entries"], 1, "{report}");
    let third = udp(dns, "www.example.net", TYPE_A);
    assert!(holds(&third, [203, 0, 113, 20]));
    assert_eq!(
        asked.load(Ordering::Relaxed),
        before + 1,
        "asked again after the flush"
    );

    // The rule's deletion sends example.net to the default upstream.
    let id = rule["id"].as_str().expect("a rule id");
    api.delete(&format!("/dns/forwarders/{id}"), None)
        .expect(204);
    let fresh = until(
        Duration::from_secs(3),
        || udp(dns, "new.example.net", TYPE_A),
        |answer| holds(answer, [203, 0, 113, 9]),
    );
    assert!(holds(&fresh, [203, 0, 113, 9]), "the default forwarder");

    // A client that is not on loopback may recurse once IPAM knows its prefix (Home profile).
    if let Some(host) = host {
        let at: SocketAddr = (host, port).into();
        let refused = udp_from(host, at, "www.example.org", TYPE_A);
        assert_eq!(header(&refused).rcode, 5, "REFUSED for a stranger");
        let network = u32::from(host) & 0xffff_ff00;
        api.post(
            "/prefixes",
            &json!({ "cidr": format!("{}/24", Ipv4Addr::from(network)) }),
        )
        .expect(201);
        let allowed = until(
            Duration::from_secs(3),
            || udp_from(host, at, "www.example.org", TYPE_A),
            |answer| header(answer).rcode == NOERROR,
        );
        assert_eq!(header(&allowed).rcode, NOERROR, "IPAM knows the prefix now");
    } else {
        eprintln!("acceptance_dns: no address but loopback; the recursion check is not run");
    }
    server.stop().assert_graceful_shutdown();
}

/// The extended DNS error info code of an answer's OPT record, if any.
fn ede(answer: &[u8]) -> Option<u16> {
    let header = wire::parse_header(answer)?;
    let mut pos = wire::questions_end(answer, header.qdcount)?;
    let records = u32::from(header.ancount) + u32::from(header.nscount) + u32::from(header.arcount);
    for _ in 0..records {
        let record = wire::read_record(answer, pos)?;
        pos = record.end();
        if record.rtype == wire::TYPE_OPT {
            return wire::options(record.data(answer))
                .find(|(code, _)| *code == wire::OPTION_EXTENDED_ERROR)
                .and_then(|(_, value)| value.get(..2))
                .map(|code| u16::from_be_bytes([code[0], code[1]]));
        }
    }
    None
}

/// What the list server of the test saw.
#[derive(Default)]
struct Served {
    requests: AtomicUsize,
    not_modified: AtomicUsize,
}

/// An HTTP server in the test that serves `body` as a hosts file with the entity tag
/// `"v1"`, and answers `304 Not Modified` to a request that sends that tag.
fn list_server(body: &'static str) -> (SocketAddr, Arc<Served>) {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let address = listener.local_addr().expect("address");
    let served = Arc::new(Served::default());
    let seen = Arc::clone(&served);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(len) => request.extend_from_slice(&buf[..len]),
                }
            }
            seen.requests.fetch_add(1, Ordering::Relaxed);
            let text = String::from_utf8_lossy(&request).to_ascii_lowercase();
            let reply = if text.contains("if-none-match: \"v1\"") {
                seen.not_modified.fetch_add(1, Ordering::Relaxed);
                "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n".to_owned()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nETag: \"v1\"\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    (address, served)
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn a_fetched_block_list_blocks_its_names_with_the_extended_error() {
    let (upstream, _) = upstream();
    let (lists, fetches) = list_server(
        "# a hosts file\n127.0.0.1 localhost\n0.0.0.0 ads.example.org\n\
         0.0.0.0 tracker.example.org metrics.example.org\n",
    );
    let port = free_port();
    let dns: SocketAddr = (Ipv4Addr::LOCALHOST, port).into();
    let mut node = Node::new()
        .with_args(&["--roles", "controller,dns"])
        .with_config(&format!(
            "[dns]\nlisten = [\"{dns}\"]\nworkers = 1\nforwarders = [\"{upstream}\"]\n\
             forward_timeout_ms = 1000\n"
        ));
    let mut server = node.start();
    server
        .wait_stdout_line(Duration::from_secs(5), |line| {
            line.starts_with("dns role answering on")
        })
        .unwrap_or_else(|| panic!("no dns line\n{}", server.diagnostics()));
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);

    // A URL list in hosts form, fetched now as a job.
    let list = api
        .post(
            "/dns/lists",
            &json!({
                "name": "ads",
                "source": {"kind": "url", "url": format!("http://{lists}/hosts")},
                "format": "hosts",
                "action": {"kind": "nxdomain"},
            }),
        )
        .expect(201);
    let id = list["id"].as_str().expect("a list id").to_owned();
    let started = api
        .post(&format!("/dns/lists/{id}/fetch"), &json!({}))
        .expect(202);
    let job = started["job_id"].as_str().expect("a job id").to_owned();
    let done = api.wait_for_job(&job, Duration::from_secs(20));
    assert_eq!(done["job"]["state"], "succeeded", "{done}");
    let read = api.get(&format!("/dns/lists/{id}")).expect(200);
    assert_eq!(read["version"]["revision"], 1, "{read}");
    assert_eq!(read["version"]["entries"], 3, "{read}");
    assert_eq!(read["version"]["etag"], "\"v1\"", "{read}");

    // A listed name and a name under it answer NXDOMAIN with "Blocked"; others are forwarded.
    let blocked = until(
        Duration::from_secs(3),
        || udp(dns, "ads.example.org", TYPE_A),
        |answer| header(answer).rcode == NXDOMAIN,
    );
    assert_eq!(header(&blocked).rcode, NXDOMAIN, "the list blocks");
    assert_eq!(ede(&blocked), Some(15), "the extended error Blocked");
    let below = udp(dns, "cdn.tracker.example.org", TYPE_A);
    assert_eq!((header(&below).rcode, ede(&below)), (NXDOMAIN, Some(15)));
    let clean = udp(dns, "www.example.org", TYPE_A);
    assert!(holds(&clean, [203, 0, 113, 9]), "a clean name is forwarded");
    assert_eq!(ede(&clean), None);

    // A second fetch sends the entity tag, sees 304 and keeps the version.
    let started = api
        .post(&format!("/dns/lists/{id}/fetch"), &json!({}))
        .expect(202);
    let job = started["job_id"].as_str().expect("a job id").to_owned();
    let done = api.wait_for_job(&job, Duration::from_secs(20));
    assert_eq!(done["job"]["state"], "succeeded", "{done}");
    assert_eq!(fetches.not_modified.load(Ordering::Relaxed), 1);
    assert_eq!(fetches.requests.load(Ordering::Relaxed), 2);
    let read = api.get(&format!("/dns/lists/{id}")).expect(200);
    assert_eq!(read["version"]["revision"], 1, "{read}");
    assert!(read.get("last_error").is_none(), "{read}");
    assert!(read["last_checked"].is_string(), "{read}");

    // The node counts the blocked queries per list.
    let node_id = api.get("/system/status").expect(200)["node"]["id"]
        .as_u64()
        .expect("a node id");
    let report = api.get(&format!("/nodes/{node_id}/dns")).expect(200);
    let ads = report["blocked"]
        .as_array()
        .and_then(|lists| lists.iter().find(|entry| entry["list"] == "ads"))
        .cloned()
        .unwrap_or_else(|| panic!("no count for the list: {report}"));
    assert!(ads["count"].as_u64().unwrap_or(0) >= 2, "{report}");

    // A disabled list blocks nothing.
    let revision = read["revision"].as_u64();
    api.patch(
        &format!("/dns/lists/{id}"),
        &json!({"enabled": false}),
        revision,
    )
    .expect(200);
    let open = until(
        Duration::from_secs(3),
        || udp(dns, "ads.example.org", TYPE_A),
        |answer| header(answer).rcode == NOERROR,
    );
    assert!(holds(&open, [203, 0, 113, 9]), "forwarded once disabled");
    server.stop().assert_graceful_shutdown();
}
