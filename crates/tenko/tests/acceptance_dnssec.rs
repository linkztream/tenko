//! E19 (WP6.3, DNS-12, OPS-09) through the real binary: one node with `--roles
//! controller,dns`, a zone signed online by the signer, checked by an external validator.
//!
//! - `tenko dns dnssec enable` signs the zone (ECDSAP256SHA256, NSEC); `status` shows the
//!   keys and the DS for the parent; the answers with DO carry RRSIGs, without DO none.
//! - The validator is `delv` from the BIND 9 image, with the zone's DS as its trust anchor
//!   (`+root`): a positive answer, NXDOMAIN, NODATA and a wildcard answer are each "fully
//!   validated"; `dnssec-verify` checks the exported zone file.
//! - The same after switching to NSEC3 (RFC 9276 parameters).
//! - A ZSK rollover with the zone's TTLs at a second runs to its end while the validator
//!   keeps validating; afterwards the new ZSK signs and the old one is gone; the CDS lists
//!   the KSK.
//!
//! The validator runs through Docker: `TENKO_DNSSEC_DOCKER` gives the command that runs
//! `docker` (by default `docker`; on the Windows machine with Docker in WSL for instance
//! `wsl -d Ubuntu-24.04 -u root -- docker`). Without the image the validator steps are
//! skipped with a message on the standard error, and the rest of the scenario still runs.

mod serve_support;

use std::{
    fmt::Write as _,
    io::Write as _,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use serve_support::{Node, api::Api, free_port};
use tenko_dns::wire;

const ZONE: &str = "example.test";
const IMAGE: &str = "internetsystemsconsortium/bind9:9.20";

/// The command that runs `docker`, when the BIND image is there.
fn docker() -> Option<Vec<String>> {
    let prefix: Vec<String> = std::env::var("TENKO_DNSSEC_DOCKER")
        .unwrap_or_else(|_| "docker".to_owned())
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect();
    let (program, args) = prefix.split_first()?;
    let present = Command::new(program)
        .args(args)
        .args(["image", "inspect", IMAGE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if present {
        Some(prefix)
    } else {
        eprintln!(
            "acceptance_dnssec: the image {IMAGE} is not available through `{}`; the external \
             validation is skipped (set TENKO_DNSSEC_DOCKER)",
            prefix.join(" ")
        );
        None
    }
}

/// Runs a shell script in the BIND image with `input` on its standard input, on the host
/// network; the standard output and error together.
fn in_bind(docker: &[String], script: &str, input: &str) -> String {
    let (program, args) = docker.split_first().expect("a docker command");
    let mut child = Command::new(program)
        .args(args)
        .args([
            "run",
            "--rm",
            "-i",
            "--network",
            "host",
            "--entrypoint",
            "sh",
            IMAGE,
            "-c",
            script,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("docker runs");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("input");
    let output = child.wait_with_output().expect("docker ends");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The trust anchor file of `delv` from the zone's DS records.
fn anchors(status: &Value) -> String {
    let mut out = String::from("trust-anchors {\n");
    for ds in status["ds"].as_array().expect("DS records") {
        let _ = writeln!(
            out,
            "  {ZONE}. static-ds {} {} {} \"{}\";",
            ds["key_tag"],
            ds["algorithm"],
            ds["digest_type"],
            ds["digest"].as_str().expect("digest")
        );
    }
    out.push_str("};\n");
    out
}

/// `delv` for `name` and `qtype` against the node, with the zone's DS as the trust anchor;
/// its output.
fn delv(docker: &[String], dns: SocketAddr, anchor: &str, name: &str, qtype: &str) -> String {
    let script = format!(
        "cat > /tmp/anchors.conf && delv @{} -p {} -a /tmp/anchors.conf +root={ZONE} +tcp {name} {qtype}",
        dns.ip(),
        dns.port()
    );
    in_bind(docker, &script, anchor)
}

/// Asserts that `delv` validated the answer for `name` and `qtype`; returns the output.
#[track_caller]
fn validated(docker: &[String], dns: SocketAddr, anchor: &str, name: &str, qtype: &str) -> String {
    let output = delv(docker, dns, anchor, name, qtype);
    assert!(
        output.contains("fully validated"),
        "delv did not validate {name} {qtype}:\n{output}"
    );
    eprintln!("delv {name} {qtype}: {}", validation_line(&output));
    output
}

fn validation_line(output: &str) -> &str {
    output
        .lines()
        .find(|line| line.contains("validated"))
        .unwrap_or_default()
}

/// A UDP query with DO set; the answer.
fn ask_do(server: SocketAddr, name: &str, qtype: u16, dnssec: bool) -> Vec<u8> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a client");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let mut query = Vec::new();
    wire::write_query(&mut query, 7, name, qtype, Some(1232));
    if dnssec {
        // The DO bit: the high bit of the OPT TTL's third octet, at the end of the query.
        let at = query.len() - 4;
        query[at] |= 0x80;
    }
    for _ in 0..3 {
        socket.send_to(&query, server).expect("send");
        let mut buf = vec![0u8; 65_535];
        if let Ok((len, _)) = socket.recv_from(&mut buf) {
            buf.truncate(len);
            return buf;
        }
    }
    panic!("no answer from {server} for {name}");
}

/// The types of the records in the answer section.
fn answer_types(message: &[u8]) -> Vec<u16> {
    let header = wire::parse_header(message).expect("header");
    let mut pos = wire::questions_end(message, header.qdcount).expect("question");
    let mut types = Vec::new();
    for _ in 0..header.ancount {
        let record = wire::read_record(message, pos).expect("record");
        types.push(record.rtype);
        pos = record.end();
    }
    types
}

/// `GET /dns/zones/{id}/dnssec` until `wanted` accepts it.
#[track_caller]
fn wait_status(api: &Api, zone: &str, wanted: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = api.get(&format!("/dns/zones/{zone}/dnssec")).expect(200);
        if wanted(&status) {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "the signer did not get there: {status}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn zsk_tags(status: &Value, state: &str) -> Vec<u64> {
    status["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .filter(|key| key["role"] == "zsk" && key["state"] == state)
        .filter_map(|key| key["key_tag"].as_u64())
        .collect()
}

/// The positive, NXDOMAIN, NODATA and wildcard answers, each validated.
fn validate_all(docker: &[String], dns: SocketAddr, anchor: &str) {
    validated(docker, dns, anchor, "www.example.test", "A");
    validated(docker, dns, anchor, "missing.example.test", "A");
    validated(docker, dns, anchor, "www.example.test", "AAAA");
    validated(docker, dns, anchor, "host.wild.example.test", "TXT");
}

/// `dnssec-verify` over the exported zone file.
fn verify_export(docker: &[String], api: &Api, zone: &str) {
    let reply = api.get(&format!("/dns/zones/{zone}/records/export"));
    assert_eq!(reply.status, 200, "{reply:?}");
    let text = reply.text.clone();
    let output = in_bind(
        docker,
        &format!("cat > /tmp/zone.db && dnssec-verify -o {ZONE} /tmp/zone.db"),
        &text,
    );
    assert!(
        output.contains("Zone fully signed"),
        "dnssec-verify:\n{output}\n{text}"
    );
    eprintln!(
        "dnssec-verify: {}",
        output
            .lines()
            .filter(|line| line.contains("Zone fully signed") || line.contains("Algorithm"))
            .collect::<Vec<_>>()
            .join(" | ")
    );
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn a_signed_zone_validates_with_nsec_and_nsec3_and_through_a_zsk_rollover() {
    let docker = docker();
    let port = free_port();
    let dns: SocketAddr = (Ipv4Addr::LOCALHOST, port).into();
    let mut node = Node::new()
        .with_args(&["--roles", "controller,dns"])
        .with_config(&format!("[dns]\nlisten = [\"{dns}\"]\nworkers = 1\n"));
    let mut server = node.start();
    server
        .wait_stdout_line(Duration::from_secs(5), |line| {
            line.starts_with(&format!("dns role answering on {dns}"))
        })
        .unwrap_or_else(|| panic!("no dns line\n{}", server.diagnostics()));
    node.setup_and_login(&server);
    let mut api = Api::new(&node);
    api.login_password();

    // A zone with TTLs of a second, so the rollover's waits take seconds.
    let zone = api
        .post(
            "/dns/zones",
            &json!({
                "name": ZONE,
                "kind": "primary",
                "serial": "counter",
                "soa": {
                    "mname": "ns1.example.test", "rname": "hostmaster.example.test",
                    "ttl": 1, "minimum": 1,
                },
                "name_servers": ["ns1.example.test"],
            }),
        )
        .expect(201);
    let zone_id = zone["id"].as_str().expect("a zone id").to_owned();
    assert_eq!(
        zone["dnssec"]["mode"], "off",
        "the Home profile signs nothing by itself"
    );
    let set = |name: &str, rtype: &str, record: Value| json!({"op": "set", "name": name, "type": rtype, "ttl": 1, "records": [record]});
    api.post(
        &format!("/dns/zones/{zone_id}/records/batch"),
        &json!({"changes": [
            set("ns1.example.test", "A", json!({"type": "A", "address": "192.0.2.53"})),
            set("www.example.test", "A", json!({"type": "A", "address": "192.0.2.10"})),
            set("*.wild.example.test", "TXT", json!({"type": "TXT", "strings": ["wild"]})),
            set("sub.example.test", "NS", json!({"type": "NS", "host": "ns.sub.example.test"})),
            set("ns.sub.example.test", "A", json!({"type": "A", "address": "192.0.2.54"})),
        ]}),
    )
    .expect(200);

    // Signing on through the client.
    node.client(&["dns", "dnssec", "enable", ZONE])
        .assert_code(0)
        .assert_stdout_contains("dnssec online");
    let status = wait_status(&api, &zone_id, |status| {
        status["signed_serial"].is_u64() && !status["ds"].as_array().is_none_or(Vec::is_empty)
    });
    assert_eq!(
        status["keys"].as_array().expect("keys").len(),
        2,
        "{status}"
    );
    node.client(&["dns", "dnssec", "status", ZONE])
        .assert_code(0)
        .assert_stdout_contains("DS records for the parent zone:")
        .assert_stdout_contains("example.test. IN DS ");
    // The answer path: RRSIGs with DO only.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let signed = answer_types(&ask_do(dns, "www.example.test", 1, true));
        if signed == [1, 46] {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no RRSIG in the answer: {signed:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        answer_types(&ask_do(dns, "www.example.test", 1, false)),
        [1]
    );

    let anchor = anchors(&status);
    if let Some(docker) = &docker {
        eprintln!("NSEC:");
        validate_all(docker, dns, &anchor);
        verify_export(docker, &api, &zone_id);
    }

    // NSEC3.
    let current = api.get(&format!("/dns/zones/{zone_id}")).expect(200);
    let mut policy = current["dnssec"].clone();
    policy["denial"] = json!({"kind": "nsec3", "iterations": 0, "salt": ""});
    api.patch(
        &format!("/dns/zones/{zone_id}"),
        &json!({"dnssec": policy}),
        None,
    )
    .expect(200);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let records = api
            .get(&format!(
                "/dns/zones/{zone_id}/records?origin=dnssec&type=NSEC3PARAM"
            ))
            .expect(200);
        if !records["items"].as_array().is_none_or(Vec::is_empty) {
            break;
        }
        assert!(Instant::now() < deadline, "no NSEC3PARAM: {records}");
        std::thread::sleep(Duration::from_millis(100));
    }
    if let Some(docker) = &docker {
        eprintln!("NSEC3:");
        validate_all(docker, dns, &anchor);
        verify_export(docker, &api, &zone_id);
    }

    // A ZSK rollover, validated while it runs.
    let old_zsk = zsk_tags(&status, "active");
    let started = node.client(&["dns", "dnssec", "rollover", ZONE, "--json"]);
    started.assert_code(0);
    let job = started.json()["job_id"].as_str().expect("a job").to_owned();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut checks = 0;
    loop {
        let detail = api.get(&format!("/jobs/{job}")).expect(200);
        let state = detail["job"]["state"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if let Some(docker) = &docker {
            validated(docker, dns, &anchor, "www.example.test", "A");
            validated(docker, dns, &anchor, "missing.example.test", "A");
            checks += 1;
        }
        if state == "succeeded" {
            break;
        }
        assert!(
            !matches!(state.as_str(), "failed" | "rolled_back" | "cancelled"),
            "the rollover ended as {state}: {detail}"
        );
        assert!(
            Instant::now() < deadline,
            "the rollover did not end: {detail}"
        );
        if docker.is_none() {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    let after = wait_status(&api, &zone_id, |status| status["rollover_job"].is_null());
    let new_zsk = zsk_tags(&after, "active");
    assert_eq!(new_zsk.len(), 1, "{after}");
    assert_ne!(new_zsk, old_zsk, "{after}");
    assert_eq!(zsk_tags(&after, "removed"), old_zsk, "{after}");
    let cds = api
        .get(&format!(
            "/dns/zones/{zone_id}/records?origin=dnssec&type=CDS"
        ))
        .expect(200);
    assert_eq!(cds["items"].as_array().map_or(0, Vec::len), 1, "{cds}");
    if let Some(docker) = &docker {
        eprintln!("after the ZSK rollover ({checks} checks while it ran):");
        validate_all(docker, dns, &anchor);
        verify_export(docker, &api, &zone_id);
    }
    // The audit trail of the rollover.
    let audited = api
        .get("/audit?action=dns.dnssec.rollover&limit=20")
        .expect(200);
    assert!(
        audited["items"]
            .as_array()
            .is_some_and(|items| items.len() >= 3),
        "{audited}"
    );

    // Signing off removes the signer's rows.
    node.client(&["dns", "dnssec", "disable", ZONE])
        .assert_code(0);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let rows = api
            .get(&format!("/dns/zones/{zone_id}/records?origin=dnssec"))
            .expect(200);
        if rows["items"].as_array().is_some_and(Vec::is_empty) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the signer's rows stayed: {rows}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(answer_types(&ask_do(dns, "www.example.test", 1, true)), [1]);
    server.stop().assert_graceful_shutdown();
}
