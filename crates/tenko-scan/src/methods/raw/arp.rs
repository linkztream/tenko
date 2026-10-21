//! `arp_sweep` (SCAN-04, active): sends an ARP request for every IPv4 address of the scope
//! from the probe's interface and collects the replies for a bounded time. It emits the
//! same facts the passive `arp` method emits (address with MAC, vendor), so the host view
//! and the IPAM observation path see no difference. IPv6 is left to the passive `nd`
//! method: a neighbour-solicitation sweep is a follow-up, and the method says so in a note.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use ipnet::IpNet;
use tenko_cluster::probe::SightingSubject;
use tenko_core::MacAddr;

use super::{RawSupport, link::RawLink, source_ipv4};
use crate::{
    config::ArpSweepMethod,
    error::ScanError,
    frame::{
        arp,
        ethernet::{self, Protocol},
    },
    method::{Availability, Found, Method, MethodKind, MethodOutput, RunContext},
    methods::neighbours::usable_mac,
    oui,
};

/// Reads the ARP reply in an Ethernet frame, when it is one.
fn reply_in(frame: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
    let parsed = ethernet::parse(frame)?;
    if parsed.protocol != Protocol::EtherType(ethernet::ETHERTYPE_ARP) {
        return None;
    }
    let message = arp::parse(parsed.payload)?;
    (message.operation == arp::OP_REPLY).then_some((message.sender_ip, message.sender_mac))
}

/// Sends an ARP request to every address in `targets` from `source`, then listens for
/// `timeout` after the last request, returning the sender IPv4/MAC pairs seen whose
/// address is a target. Honours the pacer (one permit per request) and the kill switch.
/// Returns the map and how many requests were sent.
pub(super) async fn resolve_macs(
    link: &dyn RawLink,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    targets: &[Ipv4Addr],
    timeout: Duration,
    ctx: &RunContext,
) -> (BTreeMap<Ipv4Addr, MacAddr>, u64) {
    let wanted: std::collections::BTreeSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut found = BTreeMap::new();
    let mut sent = 0u64;
    // One request or reply may be lost when the segment is busy, because a single Ethernet
    // channel captures every frame and drops some when it fills. So the sweep runs in
    // rounds: each round asks only the targets still unresolved and then collects replies
    // for a slice of the window. A target that answers once is never asked again.
    let deadline = Instant::now() + timeout;
    let rounds = 3u32;
    let slice = (timeout / rounds).max(Duration::from_millis(200));
    for round in 0..rounds {
        if ctx.cancel.is_cancelled() || found.len() == wanted.len() || Instant::now() >= deadline {
            break;
        }
        let pending: Vec<Ipv4Addr> = targets
            .iter()
            .copied()
            .filter(|ip| !found.contains_key(ip))
            .collect();
        for target in pending {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let _permit = ctx.pacer.acquire(IpAddr::V4(target)).await;
            let frame = arp::request_frame(source_mac, source_ip, target);
            if link.send(&frame).await.is_ok() {
                sent += 1;
            }
            // Read what is already queued between sends, without blocking the rate.
            drain_replies(link, &wanted, &mut found, Duration::from_millis(1)).await;
        }
        // Collect for this round's slice, and for the rest of the window on the last round.
        let until = if round + 1 == rounds {
            deadline
        } else {
            (Instant::now() + slice).min(deadline)
        };
        while Instant::now() < until && !ctx.cancel.is_cancelled() && found.len() < wanted.len() {
            drain_replies(link, &wanted, &mut found, Duration::from_millis(100)).await;
        }
    }
    (found, sent)
}

/// Reads one frame within `wait` and records it when it is an ARP reply from a wanted
/// address with a usable MAC.
async fn drain_replies(
    link: &dyn RawLink,
    wanted: &std::collections::BTreeSet<Ipv4Addr>,
    found: &mut BTreeMap<Ipv4Addr, MacAddr>,
    wait: Duration,
) {
    if let Ok(Some(frame)) = link.recv(wait).await
        && let Some((ip, mac)) = reply_in(&frame)
        && wanted.contains(&ip)
        && usable_mac(mac)
    {
        found.entry(ip).or_insert(mac);
    }
}

/// The IPv4 addresses the scope enumerates (the sweep's targets).
fn ipv4_targets(ctx: &RunContext) -> Vec<Ipv4Addr> {
    ctx.scope
        .hosts()
        .addresses
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// The `arp_sweep` method.
#[derive(Debug, Clone)]
pub struct ArpSweep {
    support: RawSupport,
    timeout: Duration,
    interface: Option<String>,
}

impl ArpSweep {
    /// The method for `config` on a host with `support`.
    pub fn new(support: RawSupport, config: &ArpSweepMethod) -> Self {
        Self {
            support,
            timeout: Duration::from_millis(config.timeout_ms),
            interface: config.interface.clone(),
        }
    }
}

#[async_trait]
impl Method for ArpSweep {
    fn kind(&self) -> MethodKind {
        MethodKind::ArpSweep
    }

    fn availability(&self) -> Availability {
        self.support.availability()
    }

    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        let link = self
            .support
            .open(&ctx.scope, self.interface.as_deref())
            .await?;
        let source_mac = link.interface().mac;
        let source_ip = source_ipv4(link.interface())?;
        let targets = ipv4_targets(ctx);
        let total = targets.len();
        let (found, sent) = resolve_macs(
            link.as_ref(),
            source_mac,
            source_ip,
            &targets,
            self.timeout,
            ctx,
        )
        .await;
        let mut output = MethodOutput {
            probes: sent,
            ..MethodOutput::default()
        };
        let mut vendors = std::collections::BTreeSet::new();
        for (ip, mac) in found {
            output.found.push(Found::now(SightingSubject::Address {
                ip: IpAddr::V4(ip),
                mac: Some(mac),
            }));
            if vendors.insert(mac)
                && let Some(vendor) = oui::vendor(mac)
            {
                output.found.push(Found::now(SightingSubject::Vendor {
                    mac,
                    vendor: vendor.to_owned(),
                }));
            }
        }
        output.covered_all = sent == total as u64 && !ctx.cancel.is_cancelled();
        let has_ipv6 = ctx
            .scope
            .prefixes()
            .iter()
            .any(|net| matches!(net, IpNet::V6(_)));
        if has_ipv6 {
            output.notes.push(
                "IPv6 is covered by the passive nd method; an ND solicitation sweep is a \
                 follow-up"
                    .to_owned(),
            );
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        limit::{PaceLimits, Pacer},
        method::Cancel,
        methods::raw::link::{MockLink, MockLinkFactory},
        scope::Scope,
    };

    fn ctx(scope: Scope) -> RunContext {
        RunContext {
            scope: Arc::new(scope),
            narrowed: false,
            known: Vec::new(),
            pacer: Arc::new(Pacer::new(PaceLimits {
                per_second: None,
                per_host_interval: Duration::ZERO,
                concurrency: 8,
            })),
            cancel: Cancel::never(),
        }
    }

    /// Builds an ARP reply Ethernet frame from `sender_ip`/`sender_mac` to the probe.
    fn reply_frame(sender_ip: Ipv4Addr, sender_mac: [u8; 6]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x05]); // to the probe
        frame.extend_from_slice(&sender_mac);
        frame.extend_from_slice(&ethernet::ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
        frame.extend_from_slice(&sender_mac);
        frame.extend_from_slice(&sender_ip.octets());
        frame.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x05]);
        frame.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 5).octets());
        frame
    }

    #[tokio::test]
    async fn the_sweep_sends_requests_and_reports_replies_with_vendor() {
        let scope = Scope::parse(&["192.0.2.0/29".to_owned()], &[], 4096).expect("scope");
        let replies = vec![reply_frame(
            Ipv4Addr::new(192, 0, 2, 3),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x0a],
        )];
        let link = Arc::new(MockLink::new(replies));
        let factory = Arc::new(MockLinkFactory::new(link.clone()));
        let method = ArpSweep {
            support: RawSupport::mock(factory),
            timeout: Duration::from_millis(20),
            interface: None,
        };
        let output = method.run(&ctx(scope)).await.expect("run");
        assert!(output.covered_all, "every request was sent");
        // 192.0.2.0/29 has usable hosts .1 to .6, so six requests.
        assert_eq!(output.probes, 6);
        assert_eq!(link.sent().len(), 6);
        let addresses: Vec<_> = output
            .found
            .iter()
            .filter(|f| matches!(f.subject, SightingSubject::Address { .. }))
            .collect();
        assert_eq!(addresses.len(), 1);
        assert!(
            output
                .found
                .iter()
                .any(|f| matches!(&f.subject, SightingSubject::Address { ip, mac: Some(_) } if *ip == IpAddr::V4(Ipv4Addr::new(192,0,2,3))))
        );
    }

    #[tokio::test]
    async fn a_cancelled_sweep_is_not_complete() {
        let scope = Scope::parse(&["192.0.2.0/29".to_owned()], &[], 4096).expect("scope");
        let link = Arc::new(MockLink::new(Vec::new()));
        let factory = Arc::new(MockLinkFactory::new(link));
        let (stop, receiver) = tokio::sync::watch::channel(true);
        let mut context = ctx(scope);
        context.cancel = Cancel::new(receiver);
        let method = ArpSweep {
            support: RawSupport::mock(factory),
            timeout: Duration::from_millis(10),
            interface: None,
        };
        let output = method.run(&context).await.expect("run");
        assert!(!output.covered_all);
        assert_eq!(output.probes, 0);
        drop(stop);
    }
}
