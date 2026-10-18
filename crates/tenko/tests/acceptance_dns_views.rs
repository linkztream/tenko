//! Acceptance of views, scopes and weights (WP6.4, DNS-20) through the real binary: one
//! node with `--roles controller,dns`, the views made with `tenko dns view`, every answer
//! read off the wire. The clients are loopback addresses (127.0.0.0/8), each a socket
//! bound to its own source address.
//!
//! - Two views with `ClientSubnet` rules on one zone with two scopes answer each client
//!   from its view's scope; a view moved first takes every client it matches.
//! - The `Transport` and `Interface` rules select: TCP from one client and a query to a
//!   second server address see another scope than UDP to the first.
//! - A 700/300 scope pair splits 500 clients within 5 percentage points of the share, and
//!   each client keeps its scope.
//! - Recursion follows each view's access list: a list that refuses everything refuses the
//!   view's clients, the profile's default lets loopback recurse again.
//! - A cached answer of one view never reaches a client of another: two views asking the
//!   same name outside the zones get the upstream's two different answers, each from its
//!   own cache entry afterwards.
//! - A zone scope a view names cannot be removed (`dns.view.in_use`).

mod serve_support;

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use serve_support::{Node, api::Api, free_port, wait_for_setup_token};
use tenko_dns::wire;

const ZONE: &str = "example.test";
const WWW: &str = "www.example.test";
const OUTSIDE: &str = "www.example.net";
const TYPE_A: u16 = 1;
const REFUSED: u8 = 5;

/// An upstream in the test that answers every A query with 203.0.113.N, N counting up from
/// 1 with each query it answers.
fn counting_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the upstream");
    let address = socket.local_addr().expect("address");
    let seen = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&seen);
    let next = AtomicU8::new(1);
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
            answer.extend_from_slice(&[203, 0, 113, next.fetch_add(1, Ordering::Relaxed)]);
            let _ = socket.send_to(&answer, from);
        }
    });
    (address, seen)
}

/// A query for `name` with RD set.
fn query(id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(&mut out, id, name, TYPE_A, Some(1232));
    out[2] |= 0x01;
    out
}

/// A UDP query from a socket bound to `local`.
fn udp_from(local: Ipv4Addr, server: SocketAddr, name: &str) -> Vec<u8> {
    let socket = UdpSocket::bind((local, 0)).expect("bind a client");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let id = free_port();
    for _ in 0..3 {
        socket.send_to(&query(id, name), server).expect("send");
        let mut buf = vec![0u8; 65_535];
        if let Ok((len, _)) = socket.recv_from(&mut buf) {
            buf.truncate(len);
            assert_eq!(wire::parse_header(&buf).expect("header").id, id);
            return buf;
        }
    }
    panic!("no UDP answer from {server} for {name} to {local}");
}

fn tcp(server: SocketAddr, name: &str) -> Vec<u8> {
    let mut stream =
        TcpStream::connect_timeout(&server, Duration::from_secs(3)).expect("connect over TCP");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let message = query(42, name);
    let len = u16::try_from(message.len()).expect("length");
    stream.write_all(&len.to_be_bytes()).expect("write");
    stream.write_all(&message).expect("write");
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).expect("the answer's length");
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut answer).expect("the answer");
    answer
}

fn rcode(answer: &[u8]) -> u8 {
    wire::parse_header(answer).expect("a header").rcode
}

/// The last octet of the first A record of an answer; 0 when there is none.
fn last_octet(answer: &[u8]) -> u8 {
    let Some(end) = wire::questions_end(answer, 1) else {
        return 0;
    };
    match wire::read_record(answer, end) {
        Some(record) if record.rtype == TYPE_A && record.rdlen == 4 => answer[record.rdata + 3],
        _ => 0,
    }
}

/// Asks until `done` holds for the answer or three seconds pass; returns the last answer.
fn until(mut ask: impl FnMut() -> Vec<u8>, done: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let answer = ask();
        if done(&answer) || Instant::now() > deadline {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn set_a(scope: &str, address: &str) -> Value {
    json!({
        "op": "set", "scope": scope, "name": WWW, "type": "A", "ttl": 300,
        "records": [{"type": "A", "address": address}],
    })
}

/// Whether this host routes all of 127.0.0.0/8 to loopback (a socket bound to 127.0.0.2
/// reaches one on 127.0.0.1).
fn loopback_aliases() -> bool {
    let (Ok(server), Ok(client)) = (
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)),
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)),
    ) else {
        return false;
    };
    let _ = server.set_read_timeout(Some(Duration::from_secs(1)));
    let Ok(to) = server.local_addr() else {
        return false;
    };
    for _ in 0..3 {
        let _ = client.send_to(b"probe", to);
        let mut buf = [0u8; 8];
        if let Ok((5, from)) = server.recv_from(&mut buf) {
            return from.ip() == Ipv4Addr::new(127, 0, 0, 2);
        }
    }
    false
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn views_split_one_zone_by_client_transport_interface_and_weight_without_a_cache_leak() {
    if !loopback_aliases() {
        eprintln!("acceptance_dns_views: 127.0.0.0/8 is not all loopback here; not run");
        return;
    }
    let (upstream, asked) = counting_upstream();
    let port = free_port();
    let first: SocketAddr = (Ipv4Addr::LOCALHOST, port).into();
    let second: SocketAddr = (Ipv4Addr::new(127, 0, 0, 3), port).into();
    let mut node = Node::new()
        .with_args(&["--roles", "controller,dns"])
        .with_config(&format!(
            "[dns]\nlisten = [\"{first}\", \"{second}\"]\nworkers = 1\nforwarders = \
             [\"{upstream}\"]\nforward_timeout_ms = 1000\n"
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
    node.login().assert_code(0);

    // One zone, three scopes: www is .1 by default, .10 inside, .20 outside.
    let zone = api
        .post(
            "/dns/zones",
            &json!({
                "name": ZONE,
                "kind": "primary",
                "serial": "counter",
                "soa": {"mname": "ns1.example.test", "rname": "hostmaster.example.test"},
                "name_servers": ["ns1.example.test"],
                "scopes": [{"name": "inside"}, {"name": "outside"}],
            }),
        )
        .expect(201);
    let zone_id = zone["id"].as_str().expect("a zone id").to_owned();
    api.post(
        &format!("/dns/zones/{zone_id}/records/batch"),
        &json!({"changes": [
            set_a("default", "192.0.2.1"),
            set_a("inside", "192.0.2.10"),
            set_a("outside", "192.0.2.20"),
        ]}),
    )
    .expect(200);
    let lan = Ipv4Addr::LOCALHOST;
    let office = Ipv4Addr::new(127, 0, 0, 2);
    let default_answer = until(|| udp_from(lan, first, WWW), |a| last_octet(a) == 1);
    assert_eq!(last_octet(&default_answer), 1, "no view: the default scope");

    // Access lists for recursion: one that refuses, one for loopback.
    node.client(&["dns", "acl", "create", "nobody", "--entry", "any,deny"])
        .assert_code(0);
    node.client(&["dns", "acl", "create", "loopback", "--entry", "127.0.0.0/8"])
        .assert_code(0);

    // The views, made with the client.
    node.client(&[
        "dns",
        "view",
        "create",
        "office",
        "--client-subnet",
        "127.0.0.2/32",
        "--scope",
        "example.test:inside",
        "--recursion",
        "nobody",
        "--description",
        "the office",
    ])
    .assert_code(0)
    .assert_stdout_contains("created view office at order 1");
    node.client(&[
        "dns",
        "view",
        "create",
        "tcp clients",
        "--transport",
        "tcp",
        "--scope",
        "example.test:inside",
    ])
    .assert_code(0)
    .assert_stdout_contains("at order 2");
    node.client(&[
        "dns",
        "view",
        "create",
        "second address",
        "--interface",
        "127.0.0.3",
        "--scope",
        "example.test:default",
    ])
    .assert_code(0);
    node.client(&[
        "dns",
        "view",
        "create",
        "weighted",
        "--client-subnet",
        "127.0.1.0/24",
        "--client-subnet",
        "127.0.2.0/24",
        "--scope",
        "example.test:inside:700",
        "--scope",
        "example.test:outside:300",
    ])
    .assert_code(0);
    node.client(&[
        "dns",
        "view",
        "create",
        "everyone",
        "--scope",
        "example.test:outside",
        "--recursion",
        "loopback",
    ])
    .assert_code(0)
    .assert_stdout_contains("at order 5");
    node.client(&["dns", "view", "list"])
        .assert_code(0)
        .assert_stdout_contains("client in 127.0.0.2/32")
        .assert_stdout_contains("example.test:inside:700 example.test:outside:300")
        .assert_stdout_contains("every query");
    node.client(&["dns", "view", "get", "office"])
        .assert_code(0)
        .assert_stdout_contains("recursion    nobody")
        .assert_stdout_contains("scope        example.test:inside:1");
    node.client(&["dns", "view", "create", "bad", "--time", "25:00-01:00"])
        .assert_code(2);
    node.client(&[
        "dns",
        "view",
        "create",
        "bad",
        "--scope",
        "example.test:missing",
    ])
    .assert_code(5)
    .assert_stderr_contains("error[dns.view.invalid]");

    // Client subnets on one zone: the office sees inside, everyone else outside.
    let inside = until(|| udp_from(office, first, WWW), |a| last_octet(a) == 10);
    assert_eq!(last_octet(&inside), 10, "the office view");
    let outside = until(|| udp_from(lan, first, WWW), |a| last_octet(a) == 20);
    assert_eq!(last_octet(&outside), 20, "the view of everyone");
    // Transport and interface.
    assert_eq!(last_octet(&tcp(first, WWW)), 10, "TCP: the tcp view");
    assert_eq!(
        last_octet(&udp_from(lan, second, WWW)),
        1,
        "the second address: its view maps the default scope"
    );
    // The view of everyone moved first takes the office too; then back.
    node.client(&["dns", "view", "update", "everyone", "--order", "1"])
        .assert_code(0)
        .assert_stdout_contains("updated view everyone at order 1");
    let moved = until(|| udp_from(office, first, WWW), |a| last_octet(a) == 20);
    assert_eq!(last_octet(&moved), 20, "the first view in order wins");
    node.client(&["dns", "view", "update", "everyone", "--order", "5"])
        .assert_code(0);
    let back = until(|| udp_from(office, first, WWW), |a| last_octet(a) == 10);
    assert_eq!(last_octet(&back), 10);

    // A 700/300 pair over 500 clients; each client keeps its scope.
    let clients: Vec<Ipv4Addr> = [1u8, 2]
        .iter()
        .flat_map(|net| (1..=250u8).map(move |host| Ipv4Addr::new(127, 0, *net, host)))
        .collect();
    let mut inside_count = 0usize;
    for (index, client) in clients.iter().enumerate() {
        let got = last_octet(&udp_from(*client, first, WWW));
        assert!(got == 10 || got == 20, "{client}: {got}");
        if got == 10 {
            inside_count += 1;
        }
        if index % 25 == 0 {
            assert_eq!(
                last_octet(&udp_from(*client, first, WWW)),
                got,
                "{client} keeps its scope"
            );
        }
    }
    #[allow(clippy::cast_precision_loss, reason = "test counts")]
    let share = inside_count as f64 / clients.len() as f64;
    eprintln!(
        "acceptance_dns_views: 700/300 gives inside to {inside_count} of 500 clients ({share:.3})"
    );
    assert!((share - 0.7).abs() <= 0.05, "share {share}");

    // Recursion per view: the office's list refuses; the profile's default allows loopback.
    let refused = udp_from(office, first, OUTSIDE);
    assert_eq!(rcode(&refused), REFUSED, "the office's list refuses");
    assert_eq!(asked.load(Ordering::Relaxed), 0);
    node.client(&["dns", "view", "update", "office", "--default-recursion"])
        .assert_code(0);
    // The cache is per view: the office's answer is .1, the view of everyone asks again and
    // gets .2, and each keeps its own entry.
    let office_first = until(|| udp_from(office, first, OUTSIDE), |a| rcode(a) == 0);
    assert_eq!(
        rcode(&office_first),
        0,
        "the profile's default allows loopback"
    );
    assert_eq!(last_octet(&office_first), 1);
    assert_eq!(asked.load(Ordering::Relaxed), 1);
    assert_eq!(
        last_octet(&udp_from(office, first, OUTSIDE)),
        1,
        "from the cache"
    );
    assert_eq!(asked.load(Ordering::Relaxed), 1);
    let everyone_first = udp_from(lan, first, OUTSIDE);
    assert_eq!(
        last_octet(&everyone_first),
        2,
        "not the office's cached answer"
    );
    assert_eq!(asked.load(Ordering::Relaxed), 2);
    assert_eq!(
        last_octet(&udp_from(lan, first, OUTSIDE)),
        2,
        "its own entry"
    );
    assert_eq!(
        last_octet(&udp_from(office, first, OUTSIDE)),
        1,
        "the office's entry"
    );
    assert_eq!(asked.load(Ordering::Relaxed), 2);

    // A scope a view names stays in the zone; the list a view names stays too.
    let refused = api.patch(
        &format!("/dns/zones/{zone_id}"),
        &json!({"scopes": [{"name": "default"}, {"name": "outside"}]}),
        None,
    );
    let problem = refused.expect(409);
    assert_eq!(problem["code"], "dns.view.in_use", "{problem}");
    node.client(&["dns", "acl", "delete", "loopback"])
        .assert_code(5)
        .assert_stderr_contains("error[dns.acl.in_use]");
    node.client(&["dns", "view", "delete", "everyone"])
        .assert_code(0)
        .assert_stdout_contains("deleted view everyone");
    node.client(&["dns", "acl", "delete", "loopback"])
        .assert_code(0);
    let list = node.client(&["dns", "view", "list", "--json"]);
    list.assert_code(0);
    assert_eq!(list.json()["items"].as_array().map(Vec::len), Some(4));
    server.stop().assert_graceful_shutdown();
}
