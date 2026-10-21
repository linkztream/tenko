//! Passive `lldp` (SCAN-02, SCAN-05): listens on the probe's interface for LLDP (ethertype
//! `0x88cc`) and, when `cdp` is on, CDP (SNAP, Cisco OUI, protocol `0x2000`) frames for the
//! listen window, parses the TLVs and emits neighbour facts in the shape of the SNMP LLDP
//! neighbours, so the port mapping of section 3 merges them: a link between the probe's
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
        Neighbour, cdp,
        ethernet::{self, CISCO_OUI, Protocol, SNAP_PROTOCOL_CDP},
        lldp,
    },
    method::{Availability, Found, Method, MethodKind, MethodOutput, RunContext},
    oui,
};

/// Parses one frame into a neighbour, when it is an LLDP frame or (with `cdp`) a CDP frame.
fn neighbour_in(frame: &[u8], cdp_on: bool) -> Option<Neighbour> {
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

/// A key that deduplicates repeated frames from the same neighbour on the same port.
fn key(neighbour: &Neighbour) -> String {
    format!(
        "{}|{}",
        neighbour
            .system_name
            .as_deref()
            .or(neighbour.chassis_id.as_deref())
            .unwrap_or("?"),
        neighbour.port_id.as_deref().unwrap_or("?")
    )
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
        let mut neighbours: BTreeMap<String, Neighbour> = BTreeMap::new();
        let deadline = Instant::now() + self.window;
        while Instant::now() < deadline && !ctx.cancel.is_cancelled() {
            if let Ok(Some(frame)) = link.recv(Duration::from_millis(200)).await
                && let Some(neighbour) = neighbour_in(&frame, self.cdp)
            {
                neighbours.entry(key(&neighbour)).or_insert(neighbour);
            }
        }
        let mut output = MethodOutput {
            covered_all: !ctx.cancel.is_cancelled(),
            ..MethodOutput::default()
        };
        let local = Endpoint {
            device: own_mac.to_string(),
            port: Some(if_name),
        };
        for neighbour in neighbours.values() {
            let switch = neighbour
                .system_name
                .clone()
                .or_else(|| neighbour.chassis_id.clone());
            let Some(switch) = switch else { continue };
            // The topology edge between the probe and the switch.
            output.found.push(Found::now(SightingSubject::Link {
                a: local.clone(),
                b: Endpoint {
                    device: switch.clone(),
                    port: neighbour.port_id.clone(),
                },
                kind: LinkKind::Lldp,
            }));
            // The probe's own MAC attached to that switch port and VLAN.
            output.found.push(Found::now(SightingSubject::Attachment {
                mac: own_mac,
                device: switch.clone(),
                port: neighbour.port_id.clone(),
                vlan: neighbour.vlan,
            }));
            // The switch's management addresses, when in scope.
            for ip in &neighbour.mgmt_addrs {
                if !ctx.scope.contains(*ip) {
                    continue;
                }
                output
                    .found
                    .push(Found::now(SightingSubject::Address { ip: *ip, mac: None }));
                if let Some(name) = &neighbour.system_name {
                    output.found.push(Found::now(SightingSubject::Name {
                        ip: *ip,
                        name: name.clone(),
                    }));
                }
                if let Some(desc) = &neighbour.system_desc {
                    output.found.push(Found::now(SightingSubject::Os {
                        ip: *ip,
                        guess: desc.chars().take(120).collect(),
                        confidence: 50,
                    }));
                }
            }
            // The vendor of the chassis MAC, when the chassis id is one.
            if let Some(mac) = neighbour.chassis_mac()
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
        frame.extend(tlv(5, b"switch-a.example.test")); // system name
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
}
