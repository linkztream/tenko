//! End-to-end smoke test of the binary: `zonegen` writes a data set, `load` runs
//! for one second against a tiny in-test UDP responder, `report` renders the
//! JSON line it wrote.

use std::fs;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

fn loopback() -> std::net::IpAddr {
    std::env::var("PHASE2_DNS_LOOPBACK")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

/// Answers every query with NOERROR, AA and one A record (127.0.0.1), or with
/// NXDOMAIN and one authority record for names starting with `nohost-`.
fn respond(q: &[u8], out: &mut Vec<u8>) -> bool {
    if q.len() < 12 {
        return false;
    }
    // With the OPT record the query ends in an 11-octet pseudo-record.
    let qend = if u16::from_be_bytes([q[10], q[11]]) == 1 {
        q.len() - 11
    } else {
        q.len()
    };
    let nx = q[13..].starts_with(b"nohost-");
    out.clear();
    out.extend_from_slice(&q[..qend]);
    out[2] |= 0x84; // QR, AA
    out[10..12].copy_from_slice(&[0, 0]);
    if nx {
        out[3] = 3;
        out[8..10].copy_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&[0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 0, 60, 0, 0]);
    } else {
        out[3] = 0;
        out[6..8].copy_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
    }
    true
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp")
        .join(format!("cli-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn zonegen_load_report() {
    let bin = env!("CARGO_BIN_EXE_phase2-dns");
    let dir = scratch_dir("smoke");

    // zonegen: a small data set with a query file.
    let data = dir.join("data");
    let out = Command::new(bin)
        .args([
            "zonegen",
            "--records",
            "2000",
            "--queries",
            "400",
            "--out-dir",
        ])
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for f in [
        "example.test.zone",
        "2.0.192.in-addr.arpa.zone",
        "100.51.198.in-addr.arpa.zone",
        "113.0.203.in-addr.arpa.zone",
        "queries.txt",
    ] {
        assert!(data.join(f).is_file(), "missing {f}");
    }

    // A tiny UDP responder on an ephemeral port.
    let sock = UdpSocket::bind((loopback(), 0)).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let addr = sock.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let responder = thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let mut out = Vec::new();
        while !stop2.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = sock.recv_from(&mut buf)
                && respond(&buf[..n], &mut out)
            {
                let _ = sock.send_to(&out, peer);
            }
        }
    });

    // load: one second, two clients, writes one JSON line.
    let jsonl = dir.join("run.jsonl");
    let out = Command::new(bin)
        .args(["load", "--target", &addr.to_string(), "--names"])
        .arg(data.join("queries.txt"))
        .args([
            "--clients",
            "2",
            "--inflight",
            "8",
            "--duration",
            "1s",
            "--warmup",
            "100ms",
            "--require-aa",
            "--workers",
            "1",
            "--label",
            "smoke",
            "--json",
        ])
        .arg(&jsonl)
        .output()
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    responder.join().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = fs::read_to_string(&jsonl).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1);
    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let r = &v["result"];
    assert_eq!(v["label"], "smoke");
    assert_eq!(v["workers"], 1);
    assert_eq!(r["transport"], "udp");
    assert_eq!(r["names"], 400);
    assert!(r["received"].as_u64().unwrap() > 0, "{v}");
    assert_eq!(r["errors"], 0, "{v}");
    assert_eq!(r["timeouts"], 0, "{v}");
    assert!(r["answers"].as_u64().unwrap() > 0 && r["nxdomain"].as_u64().unwrap() > 0);

    // report: renders the line.
    let out = Command::new(bin)
        .args(["report", "--input"])
        .arg(&jsonl)
        .output()
        .unwrap();
    assert!(out.status.success());
    let md = String::from_utf8(out.stdout).unwrap();
    assert!(md.contains("### smoke, UDP, EDNS on"), "{md}");
    assert!(md.contains("### All runs"), "{md}");

    let _ = fs::remove_dir_all(&dir);
}
