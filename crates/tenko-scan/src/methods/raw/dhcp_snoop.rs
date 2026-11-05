//! `dhcp_snoop` (SCAN-03, passive): listens for DHCPv4 DISCOVER, REQUEST and ACK on the
//! segment (UDP 67 and 68, broadcast and relayed) and reports, for each client, the MAC,
//! the host name (option 12), the vendor class (60), the client id (61), the address
//! offered or acknowledged (`yiaddr`) and the server that answered (54). The client id and
//! the server go into the run's notes, since no sighting subject carries them; the lease
//! facts proper come with Tenko DHCP. The parse is the small local one of
//! [`crate::frame::dhcp`], to be replaced by `tenko-dhcp`'s codec once it merges. It sends
//! nothing, so blackout windows do not hold it, and its batch is never complete.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tenko_cluster::probe::SightingSubject;
use tenko_core::MacAddr;

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
    methods::neighbors::usable_mac,
    oui,
};

/// Most note lines kept, so a busy segment does not fill the status.
const MAX_NOTES: usize = 32;

/// Most host names one listen window reports for one address. A client that renames itself
/// shows both names; further names for the same address are dropped and counted.
pub const MAX_NAMES_PER_ADDRESS: usize = 2;

/// Most sightings one listen window reports. A segment of 4,096 clients, each with an
/// address, a name, an OS hint and a vendor, fits.
pub const MAX_SIGHTINGS: usize = 16_384;

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
        let mut window = Window::new(MAX_SIGHTINGS);
        let deadline = Instant::now() + self.window;
        while Instant::now() < deadline && !ctx.cancel.is_canceled() {
            let Ok(Some(frame)) = link.recv(Duration::from_millis(200)).await else {
                continue;
            };
            let Some(message) = dhcp_in(&frame) else {
                continue;
            };
            window.record(&message, ctx, &mut output);
        }
        output.notes.extend(window.notes());
        output.covered_all = !ctx.cancel.is_canceled();
        Ok(output)
    }
}

/// What one listen window has seen, within its bounds: at most [`MAX_NAMES_PER_ADDRESS`] host
/// names per address and `max_sightings` sightings in all, with a count of what was dropped.
#[derive(Debug)]
struct Window {
    /// The host names (or none) reported for each address.
    clients: BTreeMap<Ipv4Addr, Vec<Option<String>>>,
    /// The client MACs whose vendor was reported.
    vendors: BTreeSet<[u8; 6]>,
    /// The notes written, to write each once.
    noted: BTreeSet<String>,
    max_sightings: usize,
    /// Host names beyond the bound of their address.
    dropped_names: usize,
    /// Sightings beyond the bound of the window.
    dropped_sightings: usize,
}

impl Window {
    fn new(max_sightings: usize) -> Self {
        Self {
            clients: BTreeMap::new(),
            vendors: BTreeSet::new(),
            noted: BTreeSet::new(),
            max_sightings,
            dropped_names: 0,
            dropped_sightings: 0,
        }
    }

    /// Whether `count` more sightings fit; counts them as dropped when they do not.
    fn room_for(&mut self, output: &MethodOutput, count: usize) -> bool {
        if output.found.len() + count <= self.max_sightings {
            true
        } else {
            self.dropped_sightings += count;
            false
        }
    }

    /// Turns one DHCP message into facts and notes.
    fn record(&mut self, message: &Dhcp, ctx: &RunContext, output: &mut MethodOutput) {
        output.probes += 1;
        let client_mac = message.client_mac.filter(|mac| usable_mac(*mac));
        // The vendor of the client, from its MAC OUI.
        if let Some(mac) = client_mac
            && !self.vendors.contains(&mac.octets())
            && let Some(vendor) = oui::vendor(mac)
            && self.room_for(output, 1)
        {
            self.vendors.insert(mac.octets());
            output.found.push(Found::now(SightingSubject::Vendor {
                mac,
                vendor: vendor.to_owned(),
            }));
        }
        // The offered or acknowledged address, when present and in scope.
        let yiaddr = message.your_ip;
        if !yiaddr.is_unspecified() && ctx.scope.contains(IpAddr::V4(yiaddr)) {
            self.record_client(message, yiaddr, client_mac, output);
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
            if self.noted.insert(note.clone()) {
                output.notes.push(note);
            }
        }
    }

    /// The address, name and OS sightings of a client the first time its address is seen with
    /// this host name, within the bounds of the window.
    fn record_client(
        &mut self,
        message: &Dhcp,
        yiaddr: Ipv4Addr,
        client_mac: Option<MacAddr>,
        output: &mut MethodOutput,
    ) {
        let names = self.clients.get(&yiaddr);
        if names.is_some_and(|names| names.contains(&message.host_name)) {
            return;
        }
        if names.is_some_and(|names| names.len() >= MAX_NAMES_PER_ADDRESS) {
            self.dropped_names += 1;
            return;
        }
        let os = message
            .vendor_class
            .as_deref()
            .and_then(os_from_vendor_class);
        let count = 1 + usize::from(message.host_name.is_some()) + usize::from(os.is_some());
        if !self.room_for(output, count) {
            return;
        }
        self.clients
            .entry(yiaddr)
            .or_default()
            .push(message.host_name.clone());
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
        if let Some((guess, confidence)) = os {
            output.found.push(Found::now(SightingSubject::Os {
                ip: IpAddr::V4(yiaddr),
                guess,
                confidence,
            }));
        }
    }

    /// The notes of a window that reached a bound, written after the per-message notes and
    /// outside their limit.
    fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.dropped_names > 0 {
            notes.push(format!(
                "host names were cut to {MAX_NAMES_PER_ADDRESS} per address; {} more were \
                 dropped",
                self.dropped_names
            ));
        }
        if self.dropped_sightings > 0 {
            notes.push(format!(
                "the window was cut to {} sightings; {} more were dropped",
                self.max_sightings, self.dropped_sightings
            ));
        }
        notes
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

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

    /// An ACK for `yiaddr` with `host_name`, from a client with an RFC 7042 MAC.
    fn ack(yiaddr: Ipv4Addr, last: u8, host_name: Option<&str>) -> Dhcp {
        Dhcp {
            op: dhcp::OP_REPLY,
            xid: 1,
            client_mac: Some(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, last])),
            your_ip: yiaddr,
            message_type: Some(dhcp::MessageType::Ack),
            host_name: host_name.map(str::to_owned),
            vendor_class: Some("MSFT 5.0".to_owned()),
            client_id: None,
            requested_ip: None,
            server_id: None,
        }
    }

    fn names_of(output: &MethodOutput, ip: Ipv4Addr) -> Vec<String> {
        output
            .found
            .iter()
            .filter_map(|f| match &f.subject {
                SightingSubject::Name { ip: at, name } if *at == IpAddr::V4(ip) => {
                    Some(name.clone())
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_names_of_an_address_are_capped_and_counted() {
        let ctx = ctx();
        let ip = Ipv4Addr::new(192, 0, 2, 60);
        let mut window = Window::new(MAX_SIGHTINGS);
        let mut output = MethodOutput::default();
        for n in 0..10 {
            window.record(
                &ack(ip, 0x10, Some(&format!("host-{n}"))),
                &ctx,
                &mut output,
            );
        }
        // A repeat of a kept name is neither a sighting nor a drop.
        window.record(&ack(ip, 0x10, Some("host-0")), &ctx, &mut output);
        assert_eq!(names_of(&output, ip), vec!["host-0", "host-1"]);
        assert_eq!(window.dropped_names, 8);
        let notes = window.notes();
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("2 per address; 8 more"), "{notes:?}");
    }

    #[test]
    fn the_sightings_of_a_window_are_capped_and_counted() {
        let ctx = ctx();
        let mut window = Window::new(20);
        let mut output = MethodOutput::default();
        for host in 1..=50u8 {
            window.record(
                &ack(Ipv4Addr::new(192, 0, 2, host), host, Some("client")),
                &ctx,
                &mut output,
            );
        }
        assert!(output.found.len() <= 20, "{}", output.found.len());
        assert!(window.dropped_sightings > 0);
        let notes = window.notes();
        assert!(
            notes
                .iter()
                .any(|n| n.contains("cut to 20 sightings") && n.contains("more were dropped")),
            "{notes:?}"
        );
        // The per-message notes keep their own limit.
        assert!(output.notes.len() <= MAX_NOTES);
    }

    #[test]
    fn a_window_below_its_bounds_reports_everything_and_notes_nothing() {
        let ctx = ctx();
        let mut window = Window::new(MAX_SIGHTINGS);
        let mut output = MethodOutput::default();
        let ip = Ipv4Addr::new(192, 0, 2, 61);
        window.record(&ack(ip, 0x11, Some("laptop")), &ctx, &mut output);
        window.record(&ack(ip, 0x11, Some("laptop")), &ctx, &mut output);
        window.record(&ack(ip, 0x11, Some("laptop-renamed")), &ctx, &mut output);
        assert_eq!(names_of(&output, ip), vec!["laptop", "laptop-renamed"]);
        let addresses = output
            .found
            .iter()
            .filter(|f| matches!(f.subject, SightingSubject::Address { .. }))
            .count();
        assert_eq!(addresses, 2);
        assert_eq!(window.notes(), Vec::<String>::new());
        assert_eq!(window.dropped_names + window.dropped_sightings, 0);
    }

    #[test]
    fn the_default_bounds_hold_a_full_segment() {
        // An address, a name, an OS hint and a vendor for each of 4,096 clients.
        const _: () = assert!(4096 * 4 <= MAX_SIGHTINGS);
        assert_eq!(MAX_NAMES_PER_ADDRESS, 2);
    }
}
