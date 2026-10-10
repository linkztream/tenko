//! `arp` and `nd`: the neighbour tables of the probe host, read from the operating system
//! without sending a frame (SCAN-02).
//!
//! | Platform | IPv4 (`arp`) | IPv6 (`nd`) |
//! |---|---|---|
//! | Linux | `/proc/net/arp` | `ip -6 neigh show` |
//! | Windows | `Get-NetNeighbor -AddressFamily IPv4` (PowerShell) | `Get-NetNeighbor -AddressFamily IPv6` |
//!
//! Entries that are incomplete, failed or unreachable, and entries with a zero, broadcast
//! or multicast MAC address are left out, as is everything outside the scope.

use std::{collections::BTreeSet, net::IpAddr, path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use tenko_cluster::probe::SightingSubject;
use tenko_core::MacAddr;

use crate::{
    error::ScanError,
    method::{Availability, Found, Method, MethodKind, MethodOutput, RunContext},
    oui,
    scope::canonical,
    sys::System,
};

/// Longest a table read may take.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// One neighbour table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Neighbour {
    /// The address.
    pub ip: IpAddr,
    /// The MAC address behind it.
    pub mac: MacAddr,
}

/// Whether a MAC address can belong to one device: not zero, not broadcast, not group.
pub fn usable_mac(mac: MacAddr) -> bool {
    let octets = mac.octets();
    octets != [0; 6] && octets[0] & 0x01 == 0
}

fn parse_mac(text: &str) -> Option<MacAddr> {
    text.trim()
        .parse::<MacAddr>()
        .ok()
        .filter(|mac| usable_mac(*mac))
}

/// Parses `/proc/net/arp`: a header, then `IP address  HW type  Flags  HW address  Mask
/// Device` per line. Only complete entries (flag `0x2`) count.
pub fn parse_proc_net_arp(text: &str) -> Vec<Neighbour> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [ip, _hw_type, flags, mac, ..] = fields.as_slice() else {
            continue;
        };
        let complete = u32::from_str_radix(flags.trim_start_matches("0x"), 16)
            .is_ok_and(|flags| flags & 0x2 != 0);
        if !complete {
            continue;
        }
        if let (Ok(ip), Some(mac)) = (ip.parse::<IpAddr>(), parse_mac(mac)) {
            out.push(Neighbour {
                ip: canonical(ip),
                mac,
            });
        }
    }
    out
}

/// Parses the output of `ip neigh show`: `<address> dev <if> lladdr <mac> [router]
/// <STATE>`. Entries in the states `FAILED`, `INCOMPLETE` and `NONE`, or without `lladdr`,
/// do not count.
pub fn parse_ip_neigh(text: &str) -> Vec<Neighbour> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(ip) = fields.first().and_then(|text| text.parse::<IpAddr>().ok()) else {
            continue;
        };
        let Some(mac) = fields
            .iter()
            .position(|field| *field == "lladdr")
            .and_then(|index| fields.get(index + 1))
            .and_then(|text| parse_mac(text))
        else {
            continue;
        };
        let state = fields.last().copied().unwrap_or_default();
        if matches!(state, "FAILED" | "INCOMPLETE" | "NONE") {
            continue;
        }
        out.push(Neighbour {
            ip: canonical(ip),
            mac,
        });
    }
    out
}

/// Splits one CSV line with double-quoted fields (as `ConvertTo-Csv` writes them).
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => fields.push(std::mem::take(&mut field)),
            (c, _) => field.push(c),
        }
    }
    fields.push(field);
    fields
}

/// Parses the CSV of `Get-NetNeighbor | Select-Object IPAddress,LinkLayerAddress,State |
/// ConvertTo-Csv -NoTypeInformation`. The columns are found by their header; the states
/// `Incomplete` and `Unreachable` do not count.
pub fn parse_get_net_neighbor_csv(text: &str) -> Vec<Neighbour> {
    let mut lines = text
        .lines()
        .map(|line| line.trim_start_matches('\u{feff}').trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let Some(header) = lines.next().map(csv_fields) else {
        return Vec::new();
    };
    let column = |name: &str| {
        header
            .iter()
            .position(|field| field.eq_ignore_ascii_case(name))
    };
    let (Some(ip_at), Some(mac_at)) = (column("IPAddress"), column("LinkLayerAddress")) else {
        return Vec::new();
    };
    let state_at = column("State");
    let mut out = Vec::new();
    for line in lines {
        let fields = csv_fields(line);
        let state = state_at.and_then(|at| fields.get(at)).map(String::as_str);
        if matches!(state, Some("Incomplete" | "Unreachable")) {
            continue;
        }
        let ip = fields
            .get(ip_at)
            .and_then(|text| text.split('%').next())
            .and_then(|text| text.parse::<IpAddr>().ok());
        let mac = fields.get(mac_at).and_then(|text| parse_mac(text));
        if let (Some(ip), Some(mac)) = (ip, mac) {
            out.push(Neighbour {
                ip: canonical(ip),
                mac,
            });
        }
    }
    out
}

/// Reads one neighbour table of this host.
///
/// # Errors
///
/// `scan.io` when the table cannot be read.
pub async fn read_table(system: &dyn System, ipv6: bool) -> Result<Vec<Neighbour>, ScanError> {
    if cfg!(windows) {
        let family = if ipv6 { "IPv6" } else { "IPv4" };
        let script = format!(
            "Get-NetNeighbor -AddressFamily {family} -ErrorAction SilentlyContinue | \
             Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Csv -NoTypeInformation"
        );
        let output = system
            .run(
                "powershell.exe",
                &["-NoProfile", "-NonInteractive", "-Command", &script],
                READ_TIMEOUT,
            )
            .await?;
        if !output.success() {
            return Err(ScanError::io(format!(
                "Get-NetNeighbor failed: {}",
                output.stderr.lines().next().unwrap_or_default()
            )));
        }
        Ok(parse_get_net_neighbor_csv(&output.stdout))
    } else if ipv6 {
        let output = system
            .run("ip", &["-6", "neigh", "show"], READ_TIMEOUT)
            .await?;
        if !output.success() {
            return Err(ScanError::io(format!(
                "ip -6 neigh show failed: {}",
                output.stderr.lines().next().unwrap_or_default()
            )));
        }
        Ok(parse_ip_neigh(&output.stdout))
    } else {
        Ok(parse_proc_net_arp(
            &system.read(Path::new("/proc/net/arp"))?,
        ))
    }
}

/// The findings of a table: an address sighting per entry inside the scope and a vendor
/// per MAC address the OUI table knows.
pub fn findings(entries: &[Neighbour], contains: impl Fn(IpAddr) -> bool) -> Vec<Found> {
    let mut found = Vec::new();
    let mut entries: Vec<Neighbour> = entries.iter().copied().filter(|n| contains(n.ip)).collect();
    entries.sort();
    entries.dedup();
    let mut vendors = BTreeSet::new();
    for neighbour in &entries {
        found.push(Found::now(SightingSubject::Address {
            ip: neighbour.ip,
            mac: Some(neighbour.mac),
        }));
        if vendors.insert(neighbour.mac)
            && let Some(vendor) = oui::vendor(neighbour.mac)
        {
            found.push(Found::now(SightingSubject::Vendor {
                mac: neighbour.mac,
                vendor: vendor.to_owned(),
            }));
        }
    }
    found
}

/// The `arp` or `nd` method.
#[derive(Debug, Clone)]
pub struct NeighbourTable {
    ipv6: bool,
    system: Arc<dyn System>,
}

impl NeighbourTable {
    /// The method over the IPv4 (`arp`) or the IPv6 (`nd`) table.
    pub fn new(ipv6: bool, system: Arc<dyn System>) -> Self {
        Self { ipv6, system }
    }
}

#[async_trait]
impl Method for NeighbourTable {
    fn kind(&self) -> MethodKind {
        if self.ipv6 {
            MethodKind::Nd
        } else {
            MethodKind::Arp
        }
    }

    fn availability(&self) -> Availability {
        Availability::Ready
    }

    fn deadline(&self) -> Duration {
        READ_TIMEOUT * 2
    }

    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        let entries = read_table(self.system.as_ref(), self.ipv6).await?;
        let family = |ip: &IpAddr| ip.is_ipv6() == self.ipv6;
        let found = findings(
            &entries
                .into_iter()
                .filter(|n| family(&n.ip))
                .collect::<Vec<_>>(),
            |ip| ctx.scope.contains(ip),
        );
        Ok(MethodOutput {
            found,
            covered_all: true,
            probes: 0,
            notes: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(text: &str) -> MacAddr {
        text.parse().expect("mac")
    }

    const PROC_NET_ARP: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.0.2.1        0x1         0x2         00:00:5e:00:53:01     *        eth0
192.0.2.20       0x1         0x0         00:00:00:00:00:00     *        eth0
192.0.2.21       0x1         0x2         00:00:5e:00:53:21     *        eth0
192.0.2.22       0x1         0x6         00:00:5E:00:53:22     *        eth0
198.51.100.9     0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth1
garbage line
";

    const IP_NEIGH: &str = "\
2001:db8::1 dev eth0 lladdr 00:00:5e:00:53:01 router REACHABLE
2001:db8::20 dev eth0 lladdr 00:00:5e:00:53:20 STALE
2001:db8::21 dev eth0  FAILED
2001:db8::22 dev eth0 lladdr 00:00:5e:00:53:22 INCOMPLETE
fe80::1 dev eth0 lladdr 00:00:5e:00:53:01 router DELAY
2001:db8::23 dev eth0 lladdr 33:33:00:00:00:01 PERMANENT
";

    const GET_NET_NEIGHBOR: &str = "\u{feff}\"IPAddress\",\"LinkLayerAddress\",\"State\"
\"192.0.2.1\",\"00-00-5E-00-53-01\",\"Reachable\"
\"192.0.2.30\",\"00-00-5E-00-53-30\",\"Stale\"
\"192.0.2.31\",\"00-00-00-00-00-00\",\"Unreachable\"
\"192.0.2.32\",\"\",\"Incomplete\"
\"192.0.2.255\",\"FF-FF-FF-FF-FF-FF\",\"Permanent\"
\"224.0.0.22\",\"01-00-5E-00-00-16\",\"Permanent\"
\"fe80::1%12\",\"00-00-5E-00-53-01\",\"Reachable\"
";

    #[test]
    fn proc_net_arp_keeps_complete_unicast_entries() {
        let entries = parse_proc_net_arp(PROC_NET_ARP);
        assert_eq!(
            entries,
            [
                Neighbour {
                    ip: "192.0.2.1".parse().expect("ip"),
                    mac: mac("00:00:5e:00:53:01")
                },
                Neighbour {
                    ip: "192.0.2.21".parse().expect("ip"),
                    mac: mac("00:00:5e:00:53:21")
                },
                Neighbour {
                    ip: "192.0.2.22".parse().expect("ip"),
                    mac: mac("00:00:5e:00:53:22")
                },
            ]
        );
    }

    #[test]
    fn ip_neigh_skips_failed_incomplete_and_multicast() {
        let ips: Vec<String> = parse_ip_neigh(IP_NEIGH)
            .iter()
            .map(|n| n.ip.to_string())
            .collect();
        assert_eq!(ips, ["2001:db8::1", "2001:db8::20", "fe80::1"]);
    }

    #[test]
    fn get_net_neighbor_csv_is_read_by_header() {
        let entries = parse_get_net_neighbor_csv(GET_NET_NEIGHBOR);
        let ips: Vec<String> = entries.iter().map(|n| n.ip.to_string()).collect();
        assert_eq!(ips, ["192.0.2.1", "192.0.2.30", "fe80::1"]);
        assert_eq!(entries[1].mac, mac("00:00:5e:00:53:30"));
        // Another column order and a localized interface column do not matter.
        let reordered = "\"State\",\"InterfaceAlias\",\"LinkLayerAddress\",\"IPAddress\"\n\
                         \"Reachable\",\"Ethernet \"\"2\"\"\",\"00-00-5E-00-53-40\",\"192.0.2.40\"\n";
        let entries = parse_get_net_neighbor_csv(reordered);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].mac, mac("00:00:5e:00:53:40"));
        assert_eq!(parse_get_net_neighbor_csv("not,a,table\n1,2,3"), []);
    }

    #[test]
    fn findings_stay_in_scope_and_name_vendors_once() {
        let entries = parse_proc_net_arp(PROC_NET_ARP);
        let found = findings(&entries, |ip| {
            ip != "192.0.2.22".parse::<IpAddr>().expect("ip")
        });
        let subjects: Vec<&SightingSubject> = found.iter().map(|f| &f.subject).collect();
        assert_eq!(subjects.len(), 4, "{subjects:?}");
        assert!(matches!(
            subjects[1],
            SightingSubject::Vendor { vendor, .. } if vendor == "ICANN, IANA Department"
        ));
    }

    proptest::proptest! {
        #[test]
        fn the_parsers_never_panic(text in "(?s).{0,2048}") {
            for entries in [
                parse_proc_net_arp(&text),
                parse_ip_neigh(&text),
                parse_get_net_neighbor_csv(&text),
            ] {
                let _ = findings(&entries, |_| true);
            }
        }

        #[test]
        fn recorded_tables_with_noise_never_panic(cut in 0usize..400, byte in 0u8..=255) {
            for table in [PROC_NET_ARP, IP_NEIGH, GET_NET_NEIGHBOR] {
                let mut bytes = table.as_bytes().to_vec();
                let at = cut % bytes.len();
                bytes[at] = byte;
                let text = String::from_utf8_lossy(&bytes[..=at]).into_owned();
                let _ = parse_proc_net_arp(&text);
                let _ = parse_ip_neigh(&text);
                let _ = parse_get_net_neighbor_csv(&text);
            }
        }
    }

    #[tokio::test]
    async fn the_method_reads_the_table_of_its_platform() {
        let system = crate::sys::RecordedSystem::new()
            .file("/proc/net/arp", PROC_NET_ARP)
            .command("ip -6 neigh show", 0, IP_NEIGH)
            .command(
                "powershell.exe -NoProfile -NonInteractive -Command Get-NetNeighbor \
                 -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object \
                 IPAddress,LinkLayerAddress,State | ConvertTo-Csv -NoTypeInformation",
                0,
                GET_NET_NEIGHBOR,
            );
        let entries = read_table(&system, false).await.expect("table");
        assert!(
            entries
                .iter()
                .any(|n| n.ip == "192.0.2.1".parse::<IpAddr>().expect("ip"))
        );
    }
}
