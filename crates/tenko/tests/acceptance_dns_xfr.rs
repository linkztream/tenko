//! Acceptance of zone transfers (WP6.1) through the real binary: two nodes on loopback, each
//! with `--roles controller,dns`, one the primary of the other.
//!
//! - The primary's zone reaches the secondary by AXFR with TSIG; the secondary answers it,
//!   its transfer route shows the serial and the primary's success.
//! - A record added on the primary reaches the secondary within seconds: the primary's
//!   NOTIFY, then IXFR, written on the secondary as one journal step with the change only.
//! - The secondary's records are read-only (409 `dns.zone.secondary`); `POST .../transfer`
//!   queues a refresh (202).
//! - An AXFR without the key, or for a zone without transfer access lists, is refused.
//! - Catalog zones: a zone with transfers allowed appears in the primary's catalog zone;
//!   the secondary's catalog zone makes it a secondary zone there, and removes it when it
//!   leaves the catalog.
//! - A copy whose primary is gone expires: the zone answers SERVFAIL.

mod serve_support;

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use serve_support::{Node, Proc, api::Api, free_port, wait_for_setup_token};
use tenko_dns::wire;

const TYPE_A: u16 = 1;
const TYPE_SOA: u16 = 6;
const TYPE_AXFR: u16 = 252;
const KEY: &str = "xfr.example.test";

fn udp(server: SocketAddr, name: &str, qtype: u16) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a client");
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    let mut query = Vec::new();
    wire::write_query(&mut query, 7, name, qtype, Some(1232));
    socket.send_to(&query, server).expect("send");
    let mut buf = vec![0u8; 4096];
    let (len, _) = socket.recv_from(&mut buf).ok()?;
    buf.truncate(len);
    Some(buf)
}

fn holds(answer: &[u8], address: [u8; 4]) -> bool {
    answer.windows(4).any(|window| window == address)
}

fn rcode(answer: &[u8]) -> u8 {
    wire::parse_header(answer).expect("header").rcode
}

/// Waits until `check` holds, up to `limit`; returns the time it took.
fn wait_until(limit: Duration, what: &str, mut check: impl FnMut() -> bool) -> Duration {
    let began = Instant::now();
    while began.elapsed() < limit {
        if check() {
            return began.elapsed();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{what} did not happen within {limit:?}");
}

/// The first message of a TCP AXFR answer, unsigned.
fn tcp_axfr(server: SocketAddr, zone: &str) -> Vec<u8> {
    let mut stream =
        TcpStream::connect_timeout(&server, Duration::from_secs(3)).expect("connect over TCP");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let mut query = Vec::new();
    wire::write_query(&mut query, 9, zone, TYPE_AXFR, None);
    let len = u16::try_from(query.len()).expect("length");
    stream.write_all(&len.to_be_bytes()).expect("write");
    stream.write_all(&query).expect("write");
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).expect("the answer's length");
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut answer).expect("the answer");
    answer
}

struct Side {
    node: Node,
    server: Proc,
    api: Api,
    dns: SocketAddr,
}

fn start() -> Side {
    let dns: SocketAddr = (Ipv4Addr::LOCALHOST, free_port()).into();
    let mut node = Node::new()
        .with_args(&["--roles", "controller,dns"])
        .with_config(&format!("[dns]\nlisten = [\"{dns}\"]\nworkers = 1\n"));
    let server = node.start();
    server
        .wait_stdout_line(Duration::from_secs(10), |line| {
            line.starts_with(&format!("dns role answering on {dns}"))
        })
        .unwrap_or_else(|| panic!("no dns line\n{}", server.diagnostics()));
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    Side {
        node,
        server,
        api,
        dns,
    }
}

fn soa(refresh: u32, retry: u32, expire: u32) -> Value {
    json!({
        "mname": "ns1.example.test", "rname": "hostmaster.example.test",
        "refresh": refresh, "retry": retry, "expire": expire, "minimum": 60, "ttl": 60,
    })
}

fn primary_zone(
    api: &Api,
    name: &str,
    acl: &str,
    notify: Option<SocketAddr>,
    catalog: bool,
) -> Value {
    let notify: Vec<Value> = notify
        .map(|to| json!({"address": to.ip().to_string(), "port": to.port(), "key": KEY}))
        .into_iter()
        .collect();
    api.post(
        "/dns/zones",
        &json!({
            "name": name,
            "kind": "primary",
            "serial": "counter",
            "soa": soa(3600, 600, 86_400),
            "name_servers": ["ns1.example.test"],
            "transfer": {"allow": [acl], "notify": notify, "require_tsig": true},
            "catalog": catalog,
        }),
    )
    .expect(201)
}

fn secondary_zone(api: &Api, name: &str, primary: SocketAddr, catalog: bool) -> Value {
    api.post(
        "/dns/zones",
        &json!({
            "name": name,
            "kind": "secondary",
            "soa": soa(3600, 600, 86_400),
            "source": {"primaries": [{"address": primary.ip().to_string(), "port": primary.port(), "key": KEY}]},
            "catalog": catalog,
        }),
    )
    .expect(201)
}

fn add_a(api: &Api, zone: &str, name: &str, address: &str) {
    api.post(
        &format!("/dns/zones/{zone}/records/batch"),
        &json!({"changes": [{
            "op": "set", "name": name, "type": "A", "ttl": 300,
            "records": [{"type": "A", "address": address}],
        }]}),
    )
    .expect(200);
}

fn zone_named(api: &Api, name: &str) -> Option<Value> {
    api.list_all("/dns/zones")
        .into_iter()
        .find(|zone| zone["name"] == name)
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn zones_transfer_between_two_nodes_with_tsig_notify_ixfr_and_catalogs() {
    let began = Instant::now();
    let mut primary = start();
    let mut secondary = start();

    // The key on both sides, and the primary's access list naming it.
    let created = primary
        .api
        .post("/dns/keys", &json!({"name": KEY}))
        .expect(201);
    let secret = created["secret"].as_str().expect("the secret").to_owned();
    secondary
        .api
        .post("/dns/keys", &json!({"name": KEY, "secret": secret}))
        .expect(201);
    let acl = primary
        .api
        .post(
            "/dns/acls",
            &json!({"name": "secondaries", "entries": [{"kind": "key", "name": KEY}]}),
        )
        .expect(201);
    let acl = acl["id"].as_str().expect("acl id").to_owned();

    // The primary zone with a record, NOTIFY to the secondary.
    let zone = primary_zone(
        &primary.api,
        "example.test",
        &acl,
        Some(secondary.dns),
        false,
    );
    let zone_id = zone["id"].as_str().expect("zone id").to_owned();
    add_a(&primary.api, &zone_id, "www.example.test", "192.0.2.10");

    // Without the key, and for a zone nobody may transfer, AXFR is refused.
    assert_eq!(
        rcode(&tcp_axfr(primary.dns, "example.test")),
        5,
        "REFUSED without TSIG"
    );
    assert_eq!(
        rcode(&tcp_axfr(primary.dns, "nothere.test")),
        9,
        "NOTAUTH outside the zones"
    );

    // The secondary: its first transfer is an AXFR.
    let copy = secondary_zone(&secondary.api, "example.test", primary.dns, false);
    let copy_id = copy["id"].as_str().expect("copy id").to_owned();
    let first = wait_until(Duration::from_secs(15), "the first transfer", || {
        udp(secondary.dns, "www.example.test", TYPE_A)
            .is_some_and(|answer| holds(&answer, [192, 0, 2, 10]))
    });
    let served = primary
        .api
        .get(&format!("/dns/zones/{zone_id}"))
        .expect(200);
    // The copy answers queries before the transfer's status row is written, so the row is
    // waited for like the answer was.
    let mut status = Value::Null;
    wait_until(Duration::from_secs(15), "the transfer status", || {
        status = secondary
            .api
            .get(&format!("/dns/zones/{copy_id}/transfer"))
            .expect(200);
        status["serial"] == served["soa_serial"]
            && status["primaries"][0]["last_success"].is_string()
    });
    assert!(status["next_refresh"].is_string(), "{status}");

    // A change on the primary: NOTIFY, then IXFR with the change only.
    let changed = Instant::now();
    add_a(&primary.api, &zone_id, "new.example.test", "192.0.2.77");
    let latency = wait_until(Duration::from_secs(5), "the IXFR after NOTIFY", || {
        udp(secondary.dns, "new.example.test", TYPE_A)
            .is_some_and(|answer| holds(&answer, [192, 0, 2, 77]))
    });
    let journal = secondary
        .api
        .get(&format!("/dns/zones/{copy_id}/journal"))
        .expect(200);
    let steps = journal["items"].as_array().expect("journal items");
    assert_eq!(steps.len(), 1, "{journal}");
    assert_eq!(
        (steps[0]["added"].as_u64(), steps[0]["removed"].as_u64()),
        (Some(1), Some(0))
    );
    let _ = changed;

    // Read-only on the secondary; a refresh now.
    let refused = secondary.api.post(
        &format!("/dns/zones/{copy_id}/records/batch"),
        &json!({"changes": [{
            "op": "set", "name": "x.example.test", "type": "A", "ttl": 300,
            "records": [{"type": "A", "address": "192.0.2.1"}],
        }]}),
    );
    assert_eq!(refused.code().as_deref(), Some("dns.zone.secondary"));
    let queued = secondary
        .api
        .post(&format!("/dns/zones/{copy_id}/transfer"), &json!({}))
        .expect(202);
    assert_eq!(queued["zone"], copy_id.as_str());
    let primary_zone_refused = primary
        .api
        .post(&format!("/dns/zones/{zone_id}/transfer"), &json!({}));
    assert_eq!(
        primary_zone_refused.code().as_deref(),
        Some("dns.zone.invalid")
    );

    // Catalog zones: the primary lists its zones with transfers, the secondary follows.
    let catalog = primary_zone(
        &primary.api,
        "catalog.example.test",
        &acl,
        Some(secondary.dns),
        true,
    );
    let _ = catalog;
    secondary_zone(&secondary.api, "catalog.example.test", primary.dns, true);
    let member = primary_zone(&primary.api, "member.test", &acl, None, false);
    let member_id = member["id"].as_str().expect("member id").to_owned();
    add_a(&primary.api, &member_id, "www.member.test", "192.0.2.20");
    wait_until(
        Duration::from_secs(20),
        "the catalog member on the secondary",
        || {
            udp(secondary.dns, "www.member.test", TYPE_A)
                .is_some_and(|answer| holds(&answer, [192, 0, 2, 20]))
        },
    );
    let created = zone_named(&secondary.api, "member.test").expect("the member zone");
    assert_eq!(created["kind"], "secondary");
    assert_eq!(
        created["description"],
        "Member of the catalog zone catalog.example.test"
    );
    // The member leaves the catalog when nobody may transfer it any more.
    primary
        .api
        .patch(
            &format!("/dns/zones/{member_id}"),
            &json!({"transfer": {"allow": [], "notify": [], "require_tsig": true}}),
            None,
        )
        .expect(200);
    wait_until(
        Duration::from_secs(20),
        "the member to leave the secondary",
        || zone_named(&secondary.api, "member.test").is_none(),
    );

    // Expiry: a zone whose primary forgets it expires on the secondary.
    let short = primary
        .api
        .post(
            "/dns/zones",
            &json!({
                "name": "short.test",
                "kind": "primary",
                "soa": soa(1, 1, 4),
                "name_servers": ["ns1.example.test"],
                "transfer": {"allow": [acl], "require_tsig": true},
            }),
        )
        .expect(201);
    let short_id = short["id"].as_str().expect("short id").to_owned();
    secondary
        .api
        .post(
            "/dns/zones",
            &json!({
                "name": "short.test",
                "kind": "secondary",
                "soa": soa(1, 1, 4),
                "source": {"primaries": [{"address": "127.0.0.1", "port": primary.dns.port(), "key": KEY}]},
            }),
        )
        .expect(201);
    wait_until(Duration::from_secs(15), "the short zone's transfer", || {
        udp(secondary.dns, "short.test", TYPE_SOA).is_some_and(|answer| rcode(&answer) == 0)
    });
    primary
        .api
        .delete(&format!("/dns/zones/{short_id}"), None)
        .expect(204);
    wait_until(Duration::from_secs(20), "the copy to expire", || {
        udp(secondary.dns, "short.test", TYPE_SOA).is_some_and(|answer| rcode(&answer) == 2)
    });

    let stopped = secondary.server.stop();
    stopped.assert_graceful_shutdown();
    let stopped = primary.server.stop();
    stopped.assert_graceful_shutdown();
    let _ = (&secondary.node, &primary.node);
    eprintln!(
        "first transfer {first:?}, NOTIFY to answer {latency:?}, whole scenario {:?}",
        began.elapsed()
    );
}
