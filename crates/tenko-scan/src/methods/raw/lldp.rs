//! Passive `lldp` (SCAN-02, SCAN-05): listens on the probe's interface for LLDP (ethertype
//! `0x88cc`) and, when `cdp` is on, CDP (SNAP, Cisco OUI, protocol `0x2000`) frames for the
//! listen window, parses the TLVs and emits neighbor facts in the shape of the SNMP LLDP
//! neighbors, so the port mapping of section 3 merges them: a link between the probe's
//! interface and the switch port, the probe's own MAC attached to that port and VLAN, and
//! the switch's management address, name and OS when in scope. It sends nothing, so
//! blackout windows do not hold it; its batch is never complete, like the other
//! best-effort listeners.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tenko_cluster::probe::SightingSubject;
use tenko_core::observe::{Endpoint, LinkKind};

use super::RawSupport;
use crate::{
    config::LldpMethod,
    error::ScanError,
    frame::{
        Neighbor, cdp,
        ethernet::{self, CISCO_OUI, Protocol, SNAP_PROTOCOL_CDP},
        lldp,
    },
    method::{Availability, Found, Method, MethodKind, MethodOutput, RunContext},
    oui,
};

/// Parses one frame into a neighbor, when it is an LLDP frame or (with `cdp`) a CDP frame.
fn neighbor_in(frame: &[u8], cdp_on: bool) -> Option<Neighbor> {
    let parsed = ethernet::parse(frame)?;
    match parsed.protocol {
        Protocol::EtherType(ethernet::ETHERTYPE_LLDP) => lldp::parse(parsed.payload),
        Protocol::Snap { oui, protocol }
            if cdp_on && oui == CISCO_OUI && protocol == SNAP_PROTOCOL_CDP =>
        {
            cdp::parse(parsed.payload)
        }
        _ => None,
    }
}

/// A key that deduplicates repeated frames from the same neighbor on the same port.
fn key(neighbor: &Neighbor) -> String {
    format!(
        "{}|{}",
        neighbor
            .system_name
            .as_deref()
            .or(neighbor.chassis_id.as_deref())
            .unwrap_or("?"),
        neighbor.port_id.as_deref().unwrap_or("?")
    )
}

/// The most neighbors one listen window keeps. A probe's segment has a few switches and
/// access points on its link, a few hundred at the very most; frames of further neighbors are
/// dropped and counted.
pub const MAX_NEIGHBORS: usize = 512;

/// The neighbors of one listen window, at most [`MAX_NEIGHBORS`], and how many frames of
/// further neighbors were dropped.
#[derive(Debug, Default)]
struct Neighbors {
    by_key: BTreeMap<String, Neighbor>,
    dropped: usize,
}

impl Neighbors {
    /// Keeps the first frame of each neighbor while the window has room.
    fn add(&mut self, neighbor: Neighbor) {
        let key = key(&neighbor);
        if self.by_key.contains_key(&key) {
            return;
        }
        if self.by_key.len() >= MAX_NEIGHBORS {
            self.dropped += 1;
            return;
        }
        self.by_key.insert(key, neighbor);
    }

    /// The note of a full window, `None` when nothing was dropped.
    fn note(&self) -> Option<String> {
        (self.dropped > 0).then(|| {
            format!(
                "the neighbors were cut to {MAX_NEIGHBORS}; {} frame(s) of further neighbors \
                 were dropped",
                self.dropped
            )
        })
    }
}

/// The `lldp` method (with CDP folded in).
#[derive(Debug, Clone)]
pub struct LldpListen {
    support: RawSupport,
    window: Duration,
    cdp: bool,
    interface: Option<String>,
}

impl LldpListen {
    /// The method for `config` on a host with `support`.
    pub fn new(support: RawSupport, config: &LldpMethod) -> Self {
        Self {
            support,
            window: Duration::from_secs(config.window_secs()),
            cdp: config.cdp,
            interface: config.interface.clone(),
        }
    }
}

#[async_trait]
impl Method for LldpListen {
    fn kind(&self) -> MethodKind {
        MethodKind::Lldp
    }

    fn availability(&self) -> Availability {
        self.support.availability()
    }

    fn deadline(&self) -> Duration {
        self.window + Duration::from_secs(30)
    }

    fn completes(&self) -> bool {
        // LLDP and CDP announce periodically; one window may miss a frame, so absence
        // proves nothing and the facts expire by their lifetime.
        false
    }

    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        let link = self
            .support
            .open(&ctx.scope, self.interface.as_deref())
            .await?;
        let own_mac = link.interface().mac;
        let if_name = link.interface().name.clone();
        let mut neighbors = Neighbors::default();
        let deadline = Instant::now() + self.window;
        while Instant::now() < deadline && !ctx.cancel.is_canceled() {
            if let Ok(Some(frame)) = link.recv(Duration::from_millis(200)).await
                && let Some(neighbor) = neighbor_in(&frame, self.cdp)
            {
                neighbors.add(neighbor);
            }
        }
        let mut output = MethodOutput {
            covered_all: !ctx.cancel.is_canceled(),
            notes: neighbors.note().into_iter().collect(),
            ..MethodOutput::default()
        };
        let local = Endpoint {
            device: own_mac.to_string(),
            port: Some(if_name),
        };
        for neighbor in neighbors.by_key.values() {
            let switch = neighbor
                .system_name
                .clone()
                .or_else(|| neighbor.chassis_id.clone());
            let Some(switch) = switch else { continue };
            // The topology edge between the probe and the switch.
            output.found.push(Found::now(SightingSubject::Link {
                a: local.clone(),
                b: Endpoint {
                    device: switch.clone(),
                    port: neighbor.port_id.clone(),
                },
                kind: LinkKind::Lldp,
            }));
            // The probe's own MAC attached to that switch port and VLAN.
            output.found.push(Found::now(SightingSubject::Attachment {
                mac: own_mac,
                device: switch.clone(),
                port: neighbor.port_id.clone(),
                vlan: neighbor.vlan,
            }));
            // The switch's management addresses, when in scope.
            for ip in &neighbor.mgmt_addrs {
                if !ctx.scope.contains(*ip) {
                    continue;
                }
                output
                    .found
                    .push(Found::now(SightingSubject::Address { ip: *ip, mac: None }));
                if let Some(name) = &neighbor.system_name {
                    output.found.push(Found::now(SightingSubject::Name {
                        ip: *ip,
                        name: name.clone(),
                    }));
                }
                if let Some(desc) = &neighbor.system_desc {
                    output.found.push(Found::now(SightingSubject::Os {
                        ip: *ip,
                        guess: desc.chars().take(120).collect(),
                        confidence: 50,
                    }));
                }
            }
            // The vendor of the chassis MAC, when the chassis id is one.
            if let Some(mac) = neighbor.chassis_mac()
                && let Some(vendor) = oui::vendor(mac)
            {
                output.found.push(Found::now(SightingSubject::Vendor {
                    mac,
                    vendor: vendor.to_owned(),
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
    use std::net::IpAddr;

    use crate::{
        limit::{PaceLimits, Pacer},
        method::Cancel,
        methods::raw::link::{MockLink, MockLinkFactory},
        scope::Scope,
    };

    fn ctx() -> RunContext {
        RunContext {
            scope: Arc::new(Scope::parse(&["192.0.2.0/24".to_owned()], &[], 4096).expect("scope")),
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

    fn lldp_frame() -> Vec<u8> {
        lldp_frame_named(b"switch-a.example.test")
    }

    fn lldp_frame_named(system_name: &[u8]) -> Vec<u8> {
        // Destination 01:80:c2:00:00:0e (LLDP multicast), source the switch.
        let mut frame = vec![0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];
        frame.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]);
        frame.extend_from_slice(&ethernet::ETHERTYPE_LLDP.to_be_bytes());
        let tlv = |t: u8, v: &[u8]| {
            let header =
                (u16::from(t) << 9) | u16::try_from(v.len()).expect("test value fits a u16");
            let mut out = header.to_be_bytes().to_vec();
            out.extend_from_slice(v);
            out
        };
        frame.extend(tlv(1, &[4, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02])); // chassis MAC
        frame.extend(tlv(2, &[5, b'G', b'i', b'0', b'/', b'1'])); // port Gi0/1
        frame.extend(tlv(3, &[0x00, 0x78])); // TTL
        frame.extend(tlv(5, system_name)); // system name
        frame.extend(tlv(8, &[5, 1, 192, 0, 2, 2, 2, 0, 0, 0, 1, 0])); // mgmt 192.0.2.2
        frame.extend(tlv(127, &[0x00, 0x80, 0xc2, 1, 0x00, 0x64])); // PVID 100
        frame.extend(tlv(0, &[]));
        frame
    }

    #[tokio::test]
    async fn a_listen_emits_the_link_attachment_and_management_address() {
        let link = Arc::new(MockLink::new(vec![lldp_frame()]));
        let factory = Arc::new(MockLinkFactory::new(link));
        let method = LldpListen {
            support: RawSupport::mock(factory),
            window: Duration::from_millis(30),
            cdp: true,
            interface: None,
        };
        let output = method.run(&ctx()).await.expect("run");
        assert!(!method.completes());
        let has_link = output.found.iter().any(|f| matches!(
            &f.subject,
            SightingSubject::Link { b, kind: LinkKind::Lldp, .. } if b.device == "switch-a.example.test"
        ));
        assert!(has_link, "a link to the switch");
        let attach = output.found.iter().any(|f| matches!(
            &f.subject,
            SightingSubject::Attachment { device, vlan: Some(100), .. } if device == "switch-a.example.test"
        ));
        assert!(attach, "the probe's MAC attached on VLAN 100");
        let mgmt = output.found.iter().any(|f| {
            matches!(
                &f.subject,
                SightingSubject::Address { ip, .. } if *ip == "192.0.2.2".parse::<IpAddr>().unwrap()
            )
        });
        assert!(mgmt, "the management address in scope");
    }

    fn named(n: usize) -> Neighbor {
        Neighbor {
            system_name: Some(format!("switch-{n}.example.test")),
            port_id: Some("Gi0/1".to_owned()),
            ..Neighbor::default()
        }
    }

    #[test]
    fn the_window_keeps_at_most_the_cap_and_counts_the_rest() {
        let mut neighbors = Neighbors::default();
        for n in 0..MAX_NEIGHBORS + 5 {
            neighbors.add(named(n));
        }
        // A repeated frame of a kept neighbor is not a drop.
        neighbors.add(named(0));
        assert_eq!(neighbors.by_key.len(), MAX_NEIGHBORS);
        assert_eq!(neighbors.dropped, 5);
        let note = neighbors.note().expect("a note");
        assert!(note.contains("cut to 512"), "{note}");
        assert!(note.contains("5 frame(s)"), "{note}");
    }

    #[test]
    fn neighbors_below_the_cap_are_kept_unchanged_and_not_noted() {
        let mut neighbors = Neighbors::default();
        neighbors.add(named(1));
        neighbors.add(named(2));
        neighbors.add(named(1));
        assert_eq!(neighbors.by_key.len(), 2);
        assert_eq!(neighbors.dropped, 0);
        assert_eq!(neighbors.note(), None);
        assert!(neighbors.by_key.values().any(|n| *n == named(2)));
    }

    #[tokio::test]
    async fn a_full_window_is_noted_in_the_run() {
        let frames: Vec<Vec<u8>> = (0..MAX_NEIGHBORS + 3)
            .map(|n| lldp_frame_named(format!("switch-{n}.example.test").as_bytes()))
            .collect();
        let link = Arc::new(MockLink::new(frames));
        let factory = Arc::new(MockLinkFactory::new(link));
        let method = LldpListen {
            support: RawSupport::mock(factory),
            window: Duration::from_millis(300),
            cdp: true,
            interface: None,
        };
        let output = method.run(&ctx()).await.expect("run");
        let links = output
            .found
            .iter()
            .filter(|f| matches!(&f.subject, SightingSubject::Link { .. }))
            .count();
        assert_eq!(links, MAX_NEIGHBORS);
        assert!(
            output.notes.iter().any(|n| n.contains("3 frame(s)")),
            "{:?}",
            output.notes
        );
    }
}
