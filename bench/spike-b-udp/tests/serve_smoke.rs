//! End-to-end check of `serve`: every compiled backend in both I/O modes
//! answers real UDP queries on loopback.
#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use spike_b_udp::backend::BackendKind;
use spike_b_udp::wire::{self, RCODE_NOERROR, RCODE_NXDOMAIN};
use spike_b_udp::zone::Zone;

fn loopback() -> std::net::IpAddr {
    wire::test_loopback()
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(backend: &str, mode: &str, workers: usize) -> (Server, SocketAddr) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_spike-b-udp"))
        .args([
            "serve",
            "--listen",
            &format!("{}:0", loopback()),
            "--backend",
            backend,
            "--mode",
            mode,
        ])
        .args(["--workers", &workers.to_string(), "--zone-size", "1000"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn server");
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.starts_with("ready "), "unexpected first line: {line}");
    let listen = line
        .split_whitespace()
        .find_map(|kv| kv.strip_prefix("listen="))
        .expect("listen= in ready line")
        .parse()
        .unwrap();
    (Server(child), listen)
}

#[test]
fn every_backend_and_mode_answers() {
    for backend in BackendKind::all() {
        for mode in ["tokio", "threads"] {
            let (_server, addr) = start(backend.as_str(), mode, 2);
            let sock = UdpSocket::bind((loopback(), 0)).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            sock.connect(addr).unwrap();
            let mut q = Vec::new();
            let mut buf = [0u8; 1500];
            for (i, (n, nx)) in [(42u32, false), (7, true), (999, false)]
                .into_iter()
                .enumerate()
            {
                let id = 100 + i as u16;
                wire::write_host_query(&mut q, id, n, nx, Some(1232));
                sock.send(&q).unwrap();
                let len = sock.recv(&mut buf).expect("response");
                let h = wire::parse_header(&buf[..len]).unwrap();
                assert_eq!(h.id, id, "{} {mode}", backend.as_str());
                assert!(h.qr && h.aa && !h.tc);
                if nx {
                    assert_eq!((h.rcode, h.ancount, h.nscount), (RCODE_NXDOMAIN, 0, 1));
                } else {
                    assert_eq!((h.rcode, h.ancount), (RCODE_NOERROR, 1));
                    // A RDATA sits right before the 11-octet OPT record.
                    assert_eq!(&buf[len - 15..len - 11], &Zone::address_for(n).octets());
                }
            }
        }
    }
}

/// SO_REUSEPORT: N sockets on one port, each worker with its own; queries
/// from many source ports must all be answered.
#[cfg(target_os = "linux")]
#[test]
fn reuseport_answers_from_many_source_ports() {
    for backend in BackendKind::all() {
        for mode in ["tokio", "threads"] {
            let mut child = Command::new(env!("CARGO_BIN_EXE_spike-b-udp"))
                .args([
                    "serve",
                    "--listen",
                    &format!("{}:0", loopback()),
                    "--backend",
                    backend.as_str(),
                    "--mode",
                    mode,
                ])
                .args(["--workers", "4", "--zone-size", "1000", "--reuseport"])
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn server");
            let mut line = String::new();
            BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            let _server = Server(child);
            assert!(line.contains("reuseport=true"), "{line}");
            let addr: SocketAddr = line
                .split_whitespace()
                .find_map(|kv| kv.strip_prefix("listen="))
                .unwrap()
                .parse()
                .unwrap();
            let mut q = Vec::new();
            let mut buf = [0u8; 1500];
            for i in 0..32u16 {
                let sock = UdpSocket::bind((loopback(), 0)).unwrap();
                sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                sock.connect(addr).unwrap();
                wire::write_host_query(&mut q, i, u32::from(i), false, None);
                sock.send(&q).unwrap();
                let len = sock.recv(&mut buf).expect("response");
                let h = wire::parse_header(&buf[..len]).unwrap();
                assert_eq!((h.id, h.rcode, h.ancount), (i, RCODE_NOERROR, 1));
            }
        }
    }
}
