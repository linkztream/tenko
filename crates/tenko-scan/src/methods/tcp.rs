//! `tcp_connect`: a TCP connect scan of a port list through the operating system, with a
//! TLS hint per open port (SCAN-04, SCAN-08).
//!
//! A port counts as open when the connection completes. With the TLS hint on, the scanner
//! then sends one TLS `ClientHello` without a server name and reads at most five bytes: a
//! TLS record header (handshake or alert, version 3.x) marks the port as TLS. Nothing else
//! is sent, no banner is read, and the connection is closed at once.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use futures::{StreamExt, stream::FuturesUnordered};
use tenko_cluster::probe::SightingSubject;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    config::TcpTargets,
    error::ScanError,
    method::{Availability, Found, Method, MethodKind, MethodOutput, RunContext},
    methods::icmp::sweep_targets,
};

/// How long the TLS hint waits for the first bytes of an answer.
const TLS_WAIT: Duration = Duration::from_millis(1500);

/// A TLS `ClientHello` (record version 3.1, handshake version 3.3) without a server name,
/// offering TLS 1.3 and 1.2 with common cipher suites, groups and signature schemes, so
/// that any TLS server answers with a `ServerHello` or an alert.
pub const CLIENT_HELLO: [u8; 149] = [
    // Record: handshake, version 3.1, length 144.
    0x16, 0x03, 0x01, 0x00, 0x90, // Handshake: `ClientHello`, length 140.
    0x01, 0x00, 0x00, 0x8c, // Version 3.3.
    0x03, 0x03, // Random (32 bytes).
    0x74, 0x65, 0x6e, 0x6b, 0x6f, 0x2d, 0x73, 0x63, 0x61, 0x6e, 0x2d, 0x74, 0x6c, 0x73, 0x2d, 0x68,
    0x69, 0x6e, 0x74, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, // Session id: empty.
    0x00, // Cipher suites: 12 bytes, six suites.
    0x00, 0x0c, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9c,
    // Compression: null.
    0x01, 0x00, // Extensions: 87 bytes.
    0x00, 0x57, // supported_groups: x25519, secp256r1, secp384r1.
    0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
    // signature_algorithms: six schemes.
    0x00, 0x0d, 0x00, 0x0e, 0x00, 0x0c, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05,
    0x05, 0x01, // ec_point_formats: uncompressed.
    0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, // supported_versions: TLS 1.3, TLS 1.2.
    0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03,
    // key_share: x25519 with a fixed public value (the hint never completes a handshake).
    0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
];

/// Whether the first bytes of an answer are a TLS record: a handshake or an alert with a
/// protocol version 3.0 to 3.4.
pub fn looks_like_tls(head: &[u8]) -> bool {
    matches!(head, [0x16 | 0x15, 0x03, minor, ..] if *minor <= 0x04)
}

/// What one connection attempt showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// The connection completed; `tls` when the TLS hint got a TLS answer.
    Open {
        /// The TLS hint.
        tls: bool,
    },
    /// The host refused the connection: it is there, the port is closed.
    Refused,
    /// No answer, or another error.
    Silent,
}

/// Connects to `addr` and, with `tls_hint`, sends the `ClientHello`.
pub async fn probe_port(addr: SocketAddr, timeout: Duration, tls_hint: bool) -> PortState {
    let stream = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            return PortState::Refused;
        }
        _ => return PortState::Silent,
    };
    let tls = tls_hint && tls_answer(stream).await;
    PortState::Open { tls }
}

async fn tls_answer(mut stream: TcpStream) -> bool {
    let exchange = async {
        stream.write_all(&CLIENT_HELLO).await.ok()?;
        let mut head = [0u8; 5];
        let mut read = 0;
        while read < 3 {
            let n = stream.read(&mut head[read..]).await.ok()?;
            if n == 0 {
                break;
            }
            read += n;
        }
        Some(looks_like_tls(&head[..read]))
    };
    let answer = tokio::time::timeout(TLS_WAIT, exchange)
        .await
        .ok()
        .flatten()
        .unwrap_or(false);
    let _ = stream.shutdown().await;
    answer
}

/// The `tcp_connect` method.
#[derive(Debug, Clone)]
pub struct TcpConnect {
    ports: Vec<u16>,
    timeout: Duration,
    tls_hint: bool,
    targets: TcpTargets,
}

impl TcpConnect {
    /// A scan of `ports`.
    pub fn new(ports: Vec<u16>, timeout: Duration, tls_hint: bool, targets: TcpTargets) -> Self {
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();
        Self {
            ports,
            timeout,
            tls_hint,
            targets,
        }
    }
}

#[async_trait]
impl Method for TcpConnect {
    fn kind(&self) -> MethodKind {
        MethodKind::TcpConnect
    }

    fn availability(&self) -> Availability {
        Availability::Ready
    }

    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        let hosts: Vec<IpAddr> = match self.targets {
            TcpTargets::Known => ctx
                .known
                .iter()
                .copied()
                .filter(|ip| ctx.scope.contains(*ip))
                .collect(),
            TcpTargets::All => {
                let mut all = sweep_targets(ctx);
                all.extend(
                    ctx.known
                        .iter()
                        .copied()
                        .filter(|ip| ctx.scope.contains(*ip)),
                );
                all.sort();
                all.dedup();
                all
            }
        };
        // Ports first, hosts inside: consecutive probes go to different hosts.
        let mut addresses = Vec::with_capacity(hosts.len() * self.ports.len());
        for port in &self.ports {
            for ip in &hosts {
                addresses.push(SocketAddr::new(*ip, *port));
            }
        }
        let mut queue = addresses.into_iter();
        let total = hosts.len() * self.ports.len();
        let limit = ctx.pacer.limits().concurrency.max(1);
        let mut pending = FuturesUnordered::new();
        let mut open: BTreeMap<IpAddr, (BTreeSet<u16>, BTreeSet<u16>)> = BTreeMap::new();
        let mut done = 0usize;
        let mut output = MethodOutput::default();
        loop {
            while pending.len() < limit && !ctx.cancel.is_cancelled() {
                let Some(addr) = queue.next() else { break };
                let pacer = Arc::clone(&ctx.pacer);
                let (timeout, tls_hint) = (self.timeout, self.tls_hint);
                pending.push(async move {
                    let _permit = pacer.acquire(addr.ip()).await;
                    (addr, probe_port(addr, timeout, tls_hint).await)
                });
            }
            let next = tokio::select! {
                next = pending.next() => next,
                () = ctx.cancel.cancelled() => break,
            };
            let Some((addr, state)) = next else { break };
            done += 1;
            output.probes += 1;
            if let PortState::Open { tls } = state {
                let entry = open.entry(addr.ip()).or_default();
                entry.0.insert(addr.port());
                if tls {
                    entry.1.insert(addr.port());
                }
            }
        }
        output.found = open
            .into_iter()
            .map(|(ip, (ports, tls))| {
                Found::now(SightingSubject::Services {
                    ip,
                    open_tcp: ports.into_iter().collect(),
                    tls_tcp: tls.into_iter().collect(),
                })
            })
            .collect();
        output.covered_all = done == total && !ctx.cancel.is_cancelled();
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_hello_is_well_formed() {
        let record_len = usize::from(u16::from_be_bytes([CLIENT_HELLO[3], CLIENT_HELLO[4]]));
        assert_eq!(record_len, CLIENT_HELLO.len() - 5);
        let handshake_len = usize::from(CLIENT_HELLO[7]) << 8 | usize::from(CLIENT_HELLO[8]);
        assert_eq!(handshake_len, record_len - 4);
        // Version, random, session id, suites, compression, then the extensions length.
        let at = 5 + 4 + 2 + 32 + 1;
        let suites = usize::from(u16::from_be_bytes([CLIENT_HELLO[at], CLIENT_HELLO[at + 1]]));
        let at = at + 2 + suites;
        assert_eq!(CLIENT_HELLO[at], 1, "one compression method");
        let at = at + 2;
        let extensions = usize::from(u16::from_be_bytes([CLIENT_HELLO[at], CLIENT_HELLO[at + 1]]));
        assert_eq!(at + 2 + extensions, CLIENT_HELLO.len());
        // Every extension's length adds up.
        let mut at = at + 2;
        while at < CLIENT_HELLO.len() {
            let len = usize::from(u16::from_be_bytes([
                CLIENT_HELLO[at + 2],
                CLIENT_HELLO[at + 3],
            ]));
            at += 4 + len;
        }
        assert_eq!(at, CLIENT_HELLO.len());
    }

    #[test]
    fn tls_records_are_recognised() {
        assert!(looks_like_tls(&[0x16, 0x03, 0x03, 0x00, 0x5a]));
        assert!(looks_like_tls(&[0x15, 0x03, 0x01, 0x00, 0x02]));
        assert!(!looks_like_tls(b"HTTP/1.1 400 Bad Request"));
        assert!(!looks_like_tls(b"SSH-2.0-OpenSSH"));
        assert!(!looks_like_tls(&[0x16, 0x03]));
        assert!(!looks_like_tls(&[0x16, 0x03, 0x09]));
    }
}
