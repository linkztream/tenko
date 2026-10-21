//! `tcp_syn` (SCAN-04, active): a half-open TCP SYN scan over raw sockets, and
//! `os_fingerprint` (SCAN-04), which shares the same SYN engine and classifies the
//! SYN-ACKs instead of reporting open ports. A SYN-ACK marks a port open, an RST marks it
//! closed, silence marks it filtered; an open port is closed with an RST. Both resolve the
//! on-link MAC of each target with ARP first (a half-open scan is a link-layer send), so a
//! target that does not answer ARP is skipped with a note. IPv6 SYN scanning is a
//! follow-up; the methods scan IPv4 targets.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tenko_cluster::probe::SightingSubject;
use tenko_core::MacAddr;

use super::{
    RawSupport,
    arp::resolve_macs,
    fingerprint::{self, Observed},
    link::RawLink,
    source_ipv4,
};
use crate::{
    config::{OsFingerprintMethod, TcpSynMethod, TcpTargets, expand_ports},
    error::ScanError,
    frame::{
        ethernet::{self, Protocol},
        ipv4,
        tcp::{self, Tcp},
    },
    method::{Availability, Found, Method, MethodKind, MethodOutput, RunContext},
    methods::icmp::sweep_targets,
};

/// The source port the scan sends from; replies to it are the scan's own.
const SOURCE_PORT: u16 = 54_321;
/// The sequence number the SYNs carry.
const SEQUENCE: u32 = 0x5445_4e4b;

/// What one host answered.
#[derive(Debug, Default, Clone)]
struct HostResult {
    open: BTreeSet<u16>,
    closed: BTreeSet<u16>,
    /// The first SYN-ACK, for the fingerprint.
    fingerprint: Option<Observed>,
}

/// Builds an Ethernet frame carrying the IPv4 packet `ip_packet` to `dest_mac`.
fn ethernet_frame(dest_mac: MacAddr, source_mac: MacAddr, ip_packet: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + ip_packet.len());
    frame.extend_from_slice(&dest_mac.octets());
    frame.extend_from_slice(&source_mac.octets());
    frame.extend_from_slice(&ethernet::ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(ip_packet);
    frame
}

/// Reads a TCP reply to our scan in an Ethernet frame: the IPv4 source, the port it came
/// from and the parsed segment, when it is a reply to [`SOURCE_PORT`].
fn reply_in(frame: &[u8]) -> Option<(Ipv4Addr, ipv4::Ipv4<'_>, Tcp)> {
    let parsed = ethernet::parse(frame)?;
    if parsed.protocol != Protocol::EtherType(ethernet::ETHERTYPE_IPV4) {
        return None;
    }
    let ip = ipv4::parse(parsed.payload)?;
    if ip.protocol != ipv4::PROTO_TCP {
        return None;
    }
    let tcp = tcp::parse(ip.payload)?;
    (tcp.destination_port == SOURCE_PORT).then_some((ip.source, ip, tcp))
}

/// Sends a SYN to every (host, port) pair and classifies the replies. `macs` gives the
/// on-link MAC of each host. Honours the pacer (one permit per SYN) and the kill switch;
/// sends an RST to close every open port.
async fn syn_scan(
    link: &dyn RawLink,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    macs: &BTreeMap<Ipv4Addr, MacAddr>,
    hosts: &[Ipv4Addr],
    ports: &[u16],
    timeout: Duration,
    ctx: &RunContext,
) -> (BTreeMap<Ipv4Addr, HostResult>, u64) {
    let mut results: BTreeMap<Ipv4Addr, HostResult> = BTreeMap::new();
    let mut sent = 0u64;
    let mut outstanding = 0usize;
    // Ports outer, hosts inner: consecutive SYNs go to different hosts.
    'ports: for port in ports {
        for host in hosts {
            if ctx.cancel.is_cancelled() {
                break 'ports;
            }
            let Some(dest_mac) = macs.get(host) else {
                continue;
            };
            let _permit = ctx.pacer.acquire(IpAddr::V4(*host)).await;
            let packet = tcp::syn_packet(source_ip, *host, SOURCE_PORT, *port, SEQUENCE);
            let frame = ethernet_frame(*dest_mac, source_mac, &packet);
            if link.send(&frame).await.is_ok() {
                sent += 1;
                outstanding += 1;
            }
            // Pick up replies that arrived between sends.
            while let Ok(Some(frame)) = link.recv(Duration::from_millis(1)).await {
                if classify(link, source_mac, source_ip, macs, &frame, &mut results).await {
                    outstanding = outstanding.saturating_sub(1);
                }
            }
        }
    }
    // Collect for the rest of the window.
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline && !ctx.cancel.is_cancelled() && outstanding > 0 {
        if let Ok(Some(frame)) = link.recv(Duration::from_millis(100)).await
            && classify(link, source_mac, source_ip, macs, &frame, &mut results).await
        {
            outstanding = outstanding.saturating_sub(1);
        }
    }
    (results, sent)
}

/// Classifies one received frame into `results`; sends an RST for a SYN-ACK. Returns
/// whether the frame was a reply to the scan.
async fn classify(
    link: &dyn RawLink,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    macs: &BTreeMap<Ipv4Addr, MacAddr>,
    frame: &[u8],
    results: &mut BTreeMap<Ipv4Addr, HostResult>,
) -> bool {
    let Some((ip, packet, tcp)) = reply_in(frame) else {
        return false;
    };
    if !macs.contains_key(&ip) {
        return false;
    }
    let port = tcp.source_port;
    let entry = results.entry(ip).or_default();
    if tcp.is_syn_ack() {
        entry.open.insert(port);
        if entry.fingerprint.is_none() {
            entry.fingerprint = Some(Observed::from_ipv4_tcp(&packet, &tcp));
        }
        if let Some(dest_mac) = macs.get(&ip) {
            let rst = tcp::rst_packet(
                source_ip,
                ip,
                SOURCE_PORT,
                port,
                tcp.acknowledgement,
                tcp.sequence.wrapping_add(1),
            );
            let _ = link
                .send(&ethernet_frame(*dest_mac, source_mac, &rst))
                .await;
        }
        true
    } else if tcp.is_rst() {
        entry.closed.insert(port);
        true
    } else {
        false
    }
}

/// The IPv4 hosts a scan targets, from the known addresses and (for `all`) the sweep.
fn ipv4_hosts(ctx: &RunContext, targets: TcpTargets) -> Vec<Ipv4Addr> {
    let mut hosts: Vec<Ipv4Addr> = match targets {
        TcpTargets::Known => ctx
            .known
            .iter()
            .copied()
            .filter(|ip| ctx.scope.contains(*ip))
            .filter_map(ipv4)
            .collect(),
        TcpTargets::All => {
            let mut all: Vec<Ipv4Addr> = sweep_targets(ctx).into_iter().filter_map(ipv4).collect();
            all.extend(
                ctx.known
                    .iter()
                    .copied()
                    .filter(|ip| ctx.scope.contains(*ip))
                    .filter_map(ipv4),
            );
            all
        }
    };
    hosts.sort();
    hosts.dedup();
    hosts
}

fn ipv4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// Resolves the hosts' MACs and runs the SYN engine; shared by both methods. Returns the
/// results, the probes sent and a note about hosts that could not be resolved.
async fn scan(
    support: &RawSupport,
    interface: Option<&str>,
    targets: TcpTargets,
    ports: &[u16],
    timeout: Duration,
    ctx: &RunContext,
) -> Result<(BTreeMap<Ipv4Addr, HostResult>, u64, bool, Vec<String>), ScanError> {
    let link = support.open(&ctx.scope, interface).await?;
    let source_mac = link.interface().mac;
    let source_ip = source_ipv4(link.interface())?;
    let hosts = ipv4_hosts(ctx, targets);
    let total = hosts.len();
    let (macs, arp_probes) =
        resolve_macs(link.as_ref(), source_mac, source_ip, &hosts, timeout, ctx).await;
    let resolved: Vec<Ipv4Addr> = hosts
        .iter()
        .copied()
        .filter(|ip| macs.contains_key(ip))
        .collect();
    let (results, syn_probes) = syn_scan(
        link.as_ref(),
        source_mac,
        source_ip,
        &macs,
        &resolved,
        ports,
        timeout,
        ctx,
    )
    .await;
    let mut notes = Vec::new();
    let unresolved = total - resolved.len();
    if unresolved > 0 {
        notes.push(format!(
            "{unresolved} target(s) did not answer ARP and were not scanned"
        ));
    }
    let covered_all = unresolved == 0 && !ctx.cancel.is_cancelled();
    Ok((results, arp_probes + syn_probes, covered_all, notes))
}

/// The `tcp_syn` method.
#[derive(Debug, Clone)]
pub struct TcpSynScan {
    support: RawSupport,
    ports: Vec<u16>,
    targets: TcpTargets,
    timeout: Duration,
    interface: Option<String>,
}

impl TcpSynScan {
    /// The method for `config` on a host with `support`.
    pub fn new(support: RawSupport, config: &TcpSynMethod) -> Self {
        Self {
            support,
            ports: expand_ports(&config.ports, "tcp_syn").unwrap_or_default(),
            targets: config.targets,
            timeout: Duration::from_millis(config.timeout_ms),
            interface: config.interface.clone(),
        }
    }
}

#[async_trait]
impl Method for TcpSynScan {
    fn kind(&self) -> MethodKind {
        MethodKind::TcpSyn
    }

    fn availability(&self) -> Availability {
        self.support.availability()
    }

    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        let (results, probes, covered_all, notes) = scan(
            &self.support,
            self.interface.as_deref(),
            self.targets,
            &self.ports,
            self.timeout,
            ctx,
        )
        .await?;
        let mut output = MethodOutput {
            covered_all,
            probes,
            notes,
            ..MethodOutput::default()
        };
        for (ip, result) in results {
            if !result.open.is_empty() {
                output.found.push(Found::now(SightingSubject::Services {
                    ip: IpAddr::V4(ip),
                    open_tcp: result.open.into_iter().collect(),
                    tls_tcp: Vec::new(),
                }));
            }
        }
        Ok(output)
    }
}

/// The `os_fingerprint` method: the SYN engine over a short port list, classifying the
/// first SYN-ACK of each host into an `os` fact.
#[derive(Debug, Clone)]
pub struct OsFingerprintScan {
    support: RawSupport,
    ports: Vec<u16>,
    timeout: Duration,
    interface: Option<String>,
}

impl OsFingerprintScan {
    /// The method for `config` on a host with `support`.
    pub fn new(support: RawSupport, config: &OsFingerprintMethod) -> Self {
        Self {
            support,
            ports: expand_ports(&config.ports, "os_fingerprint").unwrap_or_default(),
            timeout: Duration::from_millis(config.timeout_ms),
            interface: config.interface.clone(),
        }
    }
}

#[async_trait]
impl Method for OsFingerprintScan {
    fn kind(&self) -> MethodKind {
        MethodKind::OsFingerprint
    }

    fn availability(&self) -> Availability {
        self.support.availability()
    }

    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        // Fingerprinting works on the known hosts and the sweep, like a deeper scan.
        let (results, probes, covered_all, notes) = scan(
            &self.support,
            self.interface.as_deref(),
            TcpTargets::All,
            &self.ports,
            self.timeout,
            ctx,
        )
        .await?;
        let mut output = MethodOutput {
            covered_all,
            probes,
            notes,
            ..MethodOutput::default()
        };
        for (ip, result) in results {
            if let Some(observed) = result.fingerprint {
                let guess = fingerprint::classify(&observed);
                output.found.push(Found::now(SightingSubject::Os {
                    ip: IpAddr::V4(ip),
                    guess: guess.family,
                    confidence: guess.confidence,
                }));
            }
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        frame::arp,
        limit::{PaceLimits, Pacer},
        method::Cancel,
        methods::raw::link::{MockLink, MockLinkFactory},
        scope::Scope,
    };

    const PROBE_MAC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x05];
    const TARGET_MAC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x0a];

    fn ctx(known: Vec<IpAddr>) -> RunContext {
        RunContext {
            scope: Arc::new(Scope::parse(&["192.0.2.0/29".to_owned()], &[], 4096).expect("scope")),
            narrowed: false,
            known,
            pacer: Arc::new(Pacer::new(PaceLimits {
                per_second: None,
                per_host_interval: Duration::ZERO,
                concurrency: 8,
            })),
            cancel: Cancel::never(),
        }
    }

    fn arp_reply(ip: Ipv4Addr) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&PROBE_MAC);
        frame.extend_from_slice(&TARGET_MAC);
        frame.extend_from_slice(&ethernet::ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
        frame.extend_from_slice(&TARGET_MAC);
        frame.extend_from_slice(&ip.octets());
        frame.extend_from_slice(&PROBE_MAC);
        frame.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 5).octets());
        frame
    }

    /// A SYN-ACK from `ip:port` back to the probe, with a Linux-like window and options.
    fn syn_ack(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut options = vec![0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a];
        options.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x03, 0x03, 0x07]);
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&port.to_be_bytes());
        tcp.extend_from_slice(&SOURCE_PORT.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 1]); // seq
        tcp.extend_from_slice(&SEQUENCE.wrapping_add(1).to_be_bytes()); // ack
        tcp.push(
            u8::try_from((20 + options.len()) / 4).expect("a TCP header is at most 60 bytes") << 4,
        );
        tcp.push(tcp::FLAG_SYN | tcp::FLAG_ACK);
        tcp.extend_from_slice(&65160u16.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]);
        tcp.extend_from_slice(&options);
        let mut ip_packet = vec![
            0x45,
            0x00,
            0,
            0,
            0,
            0,
            0x40,
            0x00,
            0x40,
            ipv4::PROTO_TCP,
            0,
            0,
        ];
        ip_packet.extend_from_slice(&ip.octets());
        ip_packet.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 5).octets());
        let total = u16::try_from(ip_packet.len() + tcp.len()).expect("test IP length fits a u16");
        ip_packet[2..4].copy_from_slice(&total.to_be_bytes());
        ip_packet.extend_from_slice(&tcp);
        ethernet_frame(
            MacAddr::new(PROBE_MAC),
            MacAddr::new(TARGET_MAC),
            &ip_packet,
        )
    }

    #[tokio::test]
    async fn the_syn_scan_finds_an_open_port_and_sends_a_rst() {
        let target = Ipv4Addr::new(192, 0, 2, 3);
        // The ARP reply resolves the MAC (after the request), then a SYN-ACK opens port 22
        // (after the SYN, which is the second frame sent).
        let incoming = vec![(1, arp_reply(target)), (2, syn_ack(target, 22))];
        let link = Arc::new(MockLink::scripted(incoming));
        let factory = Arc::new(MockLinkFactory::new(link.clone()));
        let method = TcpSynScan {
            support: RawSupport::mock(factory),
            ports: vec![22, 80],
            targets: TcpTargets::Known,
            timeout: Duration::from_millis(30),
            interface: None,
        };
        let output = method
            .run(&ctx(vec![IpAddr::V4(target)]))
            .await
            .expect("run");
        let services: Vec<_> = output
            .found
            .iter()
            .filter_map(|f| match &f.subject {
                SightingSubject::Services { ip, open_tcp, .. } => Some((*ip, open_tcp.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(services, vec![(IpAddr::V4(target), vec![22])]);
        // Frames sent: 1 ARP request, 2 SYNs (ports 22 and 80), 1 RST for the open port.
        let sent = link.sent();
        let rst = sent.iter().any(|frame| {
            reply_in(frame).is_none()
                && ethernet::parse(frame)
                    .and_then(|e| ipv4::parse(e.payload))
                    .and_then(|ip| tcp::parse(ip.payload))
                    .is_some_and(|t| t.is_rst())
        });
        assert!(rst, "a RST was sent to close the open port");
    }

    #[tokio::test]
    async fn the_fingerprint_classifies_the_syn_ack_as_linux() {
        let target = Ipv4Addr::new(192, 0, 2, 3);
        let incoming = vec![(1, arp_reply(target)), (2, syn_ack(target, 22))];
        let link = Arc::new(MockLink::scripted(incoming));
        let factory = Arc::new(MockLinkFactory::new(link));
        let method = OsFingerprintScan {
            support: RawSupport::mock(factory),
            ports: vec![22],
            timeout: Duration::from_millis(30),
            interface: None,
        };
        // A single-host scope, so the fingerprint's `all` sweep sends one ARP then one SYN.
        let mut context = ctx(vec![IpAddr::V4(target)]);
        context.scope =
            Arc::new(Scope::parse(&["192.0.2.3/32".to_owned()], &[], 4096).expect("scope"));
        let output = method.run(&context).await.expect("run");
        let os: Vec<_> = output
            .found
            .iter()
            .filter_map(|f| match &f.subject {
                SightingSubject::Os { ip, guess, .. } => Some((*ip, guess.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(os, vec![(IpAddr::V4(target), "Linux".to_owned())]);
    }

    #[tokio::test]
    async fn an_unresolved_target_is_noted() {
        let target = Ipv4Addr::new(192, 0, 2, 3);
        // No ARP reply, so the target is never scanned.
        let _ = arp::OP_REQUEST;
        let link = Arc::new(MockLink::new(Vec::new()));
        let factory = Arc::new(MockLinkFactory::new(link));
        let method = TcpSynScan {
            support: RawSupport::mock(factory),
            ports: vec![22],
            targets: TcpTargets::Known,
            timeout: Duration::from_millis(10),
            interface: None,
        };
        let output = method
            .run(&ctx(vec![IpAddr::V4(target)]))
            .await
            .expect("run");
        assert!(!output.covered_all);
        assert!(
            output
                .notes
                .iter()
                .any(|n| n.contains("did not answer ARP"))
        );
    }
}
