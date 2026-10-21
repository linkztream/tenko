//! `dhcp_snoop` (SCAN-03, passive): listens for DHCPv4 DISCOVER, REQUEST and ACK on the
//! segment (UDP 67 and 68, broadcast and relayed) and reports, for each client, the MAC,
//! the host name (option 12), the vendor class (60), the client id (61), the address
//! offered or acknowledged (`yiaddr`) and the server that answered (54). The client id and
//! the server go into the run's notes, since no sighting subject carries them; the lease
//! facts proper come with Tenko DHCP. The parse is the small local one of
//! [`crate::frame::dhcp`], to be replaced by `tenko-dhcp`'s codec once it merges. It sends
//! nothing, so blackout windows do not hold it, and its batch is never complete.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tenko_cluster::probe::SightingSubject;

use super::RawSupport;
use crate::{
    config::DhcpSnoopMethod,
    error::ScanError,
    frame::{
        dhcp::{self, Dhcp},
        ethernet::{self, Protocol},
        ipv4,
    },
    method::{Availability, Found, Method, MethodKind, MethodOutput, RunContext},
    methods::neighbours::usable_mac,
    oui,
};

/// Most note lines kept, so a busy segment does not fill the status.
const MAX_NOTES: usize = 32;

/// Parses a DHCPv4 message carried in an Ethernet/IPv4/UDP frame to or from ports 67/68.
fn dhcp_in(frame: &[u8]) -> Option<Dhcp> {
    let parsed = ethernet::parse(frame)?;
    if parsed.protocol != Protocol::EtherType(ethernet::ETHERTYPE_IPV4) {
        return None;
    }
    let ip = ipv4::parse(parsed.payload)?;
    if ip.protocol != ipv4::PROTO_UDP {
        return None;
    }
    let source_port = u16::from_be_bytes(ip.payload.get(0..2)?.try_into().ok()?);
    let destination_port = u16::from_be_bytes(ip.payload.get(2..4)?.try_into().ok()?);
    let is_dhcp = matches!(source_port, 67 | 68) || matches!(destination_port, 67 | 68);
    if !is_dhcp {
        return None;
    }
    dhcp::parse(ip.payload.get(8..)?)
}

/// A low-confidence OS guess from the vendor class (option 60).
fn os_from_vendor_class(vendor_class: &str) -> Option<(String, u8)> {
    let lower = vendor_class.to_ascii_lowercase();
    if lower.starts_with("msft") {
        Some(("Windows".to_owned(), 55))
    } else if lower.starts_with("android-dhcp") {
        Some(("Android".to_owned(), 55))
    } else if lower.contains("dhcpcd") || lower.contains("udhcp") || lower.starts_with("linux") {
        Some(("Linux".to_owned(), 50))
    } else {
        None
    }
}

/// The `dhcp_snoop` method.
#[derive(Debug, Clone)]
pub struct DhcpSnoop {
    support: RawSupport,
    window: Duration,
    interface: Option<String>,
}

impl DhcpSnoop {
    /// The method for `config` on a host with `support`.
    pub fn new(support: RawSupport, config: &DhcpSnoopMethod) -> Self {
        Self {
            support,
            window: Duration::from_secs(config.listen_secs),
            interface: config.interface.clone(),
        }
    }
}

#[async_trait]
impl Method for DhcpSnoop {
    fn kind(&self) -> MethodKind {
        MethodKind::DhcpSnoop
    }

    fn availability(&self) -> Availability {
        self.support.availability()
    }

    fn deadline(&self) -> Duration {
        self.window + Duration::from_secs(30)
    }

    fn completes(&self) -> bool {
        false
    }

    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        let link = self
            .support
            .open(&ctx.scope, self.interface.as_deref())
            .await?;
        let mut output = MethodOutput::default();
        let mut seen_clients: BTreeSet<(Option<String>, Ipv4Addr)> = BTreeSet::new();
        let mut vendors = BTreeSet::new();
        let mut noted = BTreeSet::new();
        let deadline = Instant::now() + self.window;
        while Instant::now() < deadline && !ctx.cancel.is_cancelled() {
            let Ok(Some(frame)) = link.recv(Duration::from_millis(200)).await else {
                continue;
            };
            let Some(message) = dhcp_in(&frame) else {
                continue;
            };
            record(
                &message,
                ctx,
                &mut output,
                &mut seen_clients,
                &mut vendors,
                &mut noted,
            );
        }
        output.covered_all = !ctx.cancel.is_cancelled();
        Ok(output)
    }
}

/// Turns one DHCP message into facts and notes.
fn record(
    message: &Dhcp,
    ctx: &RunContext,
    output: &mut MethodOutput,
    seen_clients: &mut BTreeSet<(Option<String>, Ipv4Addr)>,
    vendors: &mut BTreeSet<[u8; 6]>,
    noted: &mut BTreeSet<String>,
) {
    output.probes += 1;
    let client_mac = message.client_mac.filter(|mac| usable_mac(*mac));
    // The vendor of the client, from its MAC OUI.
    if let Some(mac) = client_mac
        && vendors.insert(mac.octets())
        && let Some(vendor) = oui::vendor(mac)
    {
        output.found.push(Found::now(SightingSubject::Vendor {
            mac,
            vendor: vendor.to_owned(),
        }));
    }
    // The offered or acknowledged address, when present and in scope.
    let yiaddr = message.your_ip;
    if !yiaddr.is_unspecified() && ctx.scope.contains(IpAddr::V4(yiaddr)) {
        let dedup = (message.host_name.clone(), yiaddr);
        if seen_clients.insert(dedup) {
            output.found.push(Found::now(SightingSubject::Address {
                ip: IpAddr::V4(yiaddr),
                mac: client_mac,
            }));
            if let Some(name) = &message.host_name {
                output.found.push(Found::now(SightingSubject::Name {
                    ip: IpAddr::V4(yiaddr),
                    name: name.clone(),
                }));
            }
            if let Some((guess, confidence)) = message
                .vendor_class
                .as_deref()
                .and_then(os_from_vendor_class)
            {
                output.found.push(Found::now(SightingSubject::Os {
                    ip: IpAddr::V4(yiaddr),
                    guess,
                    confidence,
                }));
            }
        }
    }
    // The client id and the server go into the notes only.
    if output.notes.len() < MAX_NOTES {
        let kind = message.message_type.map_or("DHCP", dhcp::MessageType::name);
        let mac = client_mac.map_or_else(|| "?".to_owned(), |m| m.to_string());
        let note = match (&message.client_id, message.server_id) {
            (Some(id), Some(server)) => {
                format!("{kind} from {mac}: client-id {id}, server {server}")
            }
            (Some(id), None) => format!("{kind} from {mac}: client-id {id}"),
            (None, Some(server)) => format!("{kind} from {mac}: server {server}"),
            (None, None) => format!("{kind} from {mac}"),
        };
        if noted.insert(note.clone()) {
            output.notes.push(note);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use tenko_core::MacAddr;

    const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

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

    /// An Ethernet/IPv4/UDP frame carrying a DHCP message with the given options.
    fn dhcp_frame(op: u8, yiaddr: Ipv4Addr, chaddr: [u8; 6], options: &[u8]) -> Vec<u8> {
        let mut dhcp = vec![0u8; 240];
        dhcp[0] = op;
        dhcp[1] = 1;
        dhcp[2] = 6;
        dhcp[4..8].copy_from_slice(&0xabcd_0001u32.to_be_bytes());
        dhcp[16..20].copy_from_slice(&yiaddr.octets());
        dhcp[28..34].copy_from_slice(&chaddr);
        dhcp[236..240].copy_from_slice(&MAGIC_COOKIE);
        dhcp.extend_from_slice(options);
        dhcp.push(255);
        let mut udp = Vec::new();
        udp.extend_from_slice(&67u16.to_be_bytes());
        udp.extend_from_slice(&68u16.to_be_bytes());
        let udp_len = u16::try_from(dhcp.len() + 8).expect("test UDP length fits a u16");
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(&dhcp);
        let mut ip = vec![
            0x45,
            0x00,
            0,
            0,
            0,
            0,
            0x00,
            0x00,
            0x40,
            ipv4::PROTO_UDP,
            0,
            0,
        ];
        ip.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
        ip.extend_from_slice(&Ipv4Addr::BROADCAST.octets());
        let total = u16::try_from(ip.len() + udp.len()).expect("test IP length fits a u16");
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&udp);
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
        frame.extend_from_slice(&ethernet::ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame
    }

    #[tokio::test]
    async fn an_ack_yields_address_name_and_notes() {
        let chaddr = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x0a];
        let options = [
            53, 1, 5, // ACK
            12, 6, b'l', b'a', b'p', b't', b'o', b'p', // host name
            60, 4, b'M', b'S', b'F', b'T', // vendor class -> Windows
            54, 4, 192, 0, 2, 1, // server
        ];
        let frame = dhcp_frame(
            dhcp::OP_REPLY,
            Ipv4Addr::new(192, 0, 2, 50),
            chaddr,
            &options,
        );
        let link = Arc::new(MockLink::new(vec![frame]));
        let factory = Arc::new(MockLinkFactory::new(link));
        let method = DhcpSnoop {
            support: RawSupport::mock(factory),
            window: Duration::from_millis(30),
            interface: None,
        };
        let output = method.run(&ctx()).await.expect("run");
        assert!(output.found.iter().any(|f| matches!(
            &f.subject,
            SightingSubject::Address { ip, mac: Some(m) }
                if *ip == IpAddr::V4(Ipv4Addr::new(192,0,2,50)) && *m == MacAddr::new(chaddr)
        )));
        assert!(output.found.iter().any(|f| matches!(
            &f.subject,
            SightingSubject::Name { name, .. } if name == "laptop"
        )));
        assert!(output.found.iter().any(|f| matches!(
            &f.subject,
            SightingSubject::Os { guess, .. } if guess == "Windows"
        )));
        assert!(output.notes.iter().any(|n| n.contains("server 192.0.2.1")));
    }
}
