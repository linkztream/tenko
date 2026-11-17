//! `arp` and `nd`: the neighbor tables of the probe host, read from the operating system
//! without sending a frame (SCAN-02).
//!
//! | Platform | IPv4 (`arp`) | IPv6 (`nd`) |
//! |---|---|---|
//! | Linux | `ip -4 neigh show` | `ip -6 neigh show` |
//! | Windows | `Get-NetNeighbor -AddressFamily IPv4` (PowerShell) | `Get-NetNeighbor -AddressFamily IPv6` |
//!
//! `ip` (iproute2) asks the kernel over netlink, which the shipped systemd unit allows;
//! `/proc/net/arp` is hidden there (`ProcSubset=pid`). Another platform runs `ip` too.
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
    sys::{CommandOutput, System},
};

/// Longest a table read may take.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// One neighbor table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Neighbor {
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

/// Parses the output of `ip -4 neigh show` and `ip -6 neigh show`: `<address> dev <if>
/// lladdr <mac> [router] <STATE>`. Entries in the states `FAILED`, `INCOMPLETE` and `NONE`,
/// or without `lladdr`, do not count.
pub fn parse_ip_neigh(text: &str) -> Vec<Neighbor> {
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
        // The state is last in iproute2's text; flags such as `proto <name>` may follow it.
        if fields
            .iter()
            .any(|field| matches!(*field, "FAILED" | "INCOMPLETE" | "NONE"))
        {
            continue;
        }
        out.push(Neighbor {
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
pub fn parse_get_net_neighbor_csv(text: &str) -> Vec<Neighbor> {
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
            out.push(Neighbor {
                ip: canonical(ip),
                mac,
            });
        }
    }
    out
}

/// Reads one neighbor table of this host.
///
/// # Errors
///
/// `scan.io` when the table cannot be read.
pub async fn read_table(system: &dyn System, ipv6: bool) -> Result<Vec<Neighbor>, ScanError> {
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
    } else {
        let family = if ipv6 { "-6" } else { "-4" };
        Ok(parse_ip_neigh(
            &run_ip(system, &[family, "neigh", "show"]).await?,
        ))
    }
}

/// Where `ip` is looked for: the usual system directories, never the service's `PATH`.
const IP_PATHS: [&str; 4] = ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"];

/// Runs `ip` (iproute2) with fixed `args` and answers its standard output. The neighbor
/// tables and the server's default routes are read through it.
///
/// # Errors
///
/// `scan.io` naming the cause: `ip` is not installed, cannot start, does not finish within
/// [`READ_TIMEOUT`], or fails (its exit status and first line of standard error).
pub async fn run_ip(system: &dyn System, args: &[&str]) -> Result<String, ScanError> {
    let program = IP_PATHS
        .into_iter()
        .find(|path| system.exists(Path::new(path)))
        .ok_or_else(|| {
            ScanError::io(format!(
                "the ip command is not installed (looked for {}); the package iproute2 \
                 provides it",
                IP_PATHS.join(", ")
            ))
        })?;
    let output = system.run(program, args, READ_TIMEOUT).await?;
    if output.success() {
        Ok(output.stdout)
    } else {
        Err(ip_failed(args, &output))
    }
}

/// The error of an `ip` that failed: the command, how it ended and the first line of
/// standard error that says something.
fn ip_failed(args: &[&str], output: &CommandOutput) -> ScanError {
    let status = output.status.map_or_else(
        || "killed by a signal".to_owned(),
        |code| format!("exit status {code}"),
    );
    let message = output
        .stderr
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("nothing on standard error");
    ScanError::io(format!(
        "ip {} failed ({status}): {message}",
        args.join(" ")
    ))
}

/// The findings of a table: an address sighting per entry inside the scope and a vendor
/// per MAC address the OUI table knows.
pub fn findings(entries: &[Neighbor], contains: impl Fn(IpAddr) -> bool) -> Vec<Found> {
    let mut found = Vec::new();
    let mut entries: Vec<Neighbor> = entries.iter().copied().filter(|n| contains(n.ip)).collect();
    entries.sort();
    entries.dedup();
    let mut vendors = BTreeSet::new();
    for neighbor in &entries {
        found.push(Found::now(SightingSubject::Address {
            ip: neighbor.ip,
            mac: Some(neighbor.mac),
        }));
        if vendors.insert(neighbor.mac)
            && let Some(vendor) = oui::vendor(neighbor.mac)
        {
            found.push(Found::now(SightingSubject::Vendor {
                mac: neighbor.mac,
                vendor: vendor.to_owned(),
            }));
        }
    }
    found
}

/// The `arp` or `nd` method.
#[derive(Debug, Clone)]
pub struct NeighborTable {
    ipv6: bool,
    system: Arc<dyn System>,
}

impl NeighborTable {
    /// The method over the IPv4 (`arp`) or the IPv6 (`nd`) table.
    pub fn new(ipv6: bool, system: Arc<dyn System>) -> Self {
        Self { ipv6, system }
    }
}

#[async_trait]
impl Method for NeighborTable {
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
    use crate::sys::RecordedSystem;

    fn mac(text: &str) -> MacAddr {
        text.parse().expect("mac")
    }

    fn ips(entries: &[Neighbor]) -> Vec<String> {
        entries.iter().map(|n| n.ip.to_string()).collect()
    }

    // `ip -4 neigh show` of iproute2 6.1 (Debian 12): a failed and an incomplete entry
    // without `lladdr` (two spaces before the state), a broadcast and a zero MAC address
    // (`NOARP`), a flag before the state and `proto` after it; then the `-s` form of 4.18
    // (RHEL 8) and BusyBox, with counters before the state.
    const IP4_NEIGH: &str = "\
192.0.2.1 dev eth0 lladdr 00:00:5e:00:53:01 REACHABLE
192.0.2.20 dev eth0 lladdr 00:00:5e:00:53:20 STALE
192.0.2.21 dev eth0  FAILED
192.0.2.22 dev eth0  INCOMPLETE
192.0.2.23 dev eth0 lladdr 00:00:5E:00:53:23 PERMANENT
192.0.2.24 dev eth0 lladdr 00:00:5e:00:53:24 DELAY
192.0.2.25 dev eth0 lladdr 00:00:5e:00:53:25 PROBE
192.0.2.255 dev eth0 lladdr ff:ff:ff:ff:ff:ff NOARP
198.51.100.9 dev eth1 lladdr 00:00:00:00:00:00 NOARP
192.0.2.26 dev eth0 lladdr 00:00:5e:00:53:26 extern_learn STALE proto zebra
192.0.2.27 dev eth0 lladdr 00:00:5e:00:53:27 ref 1 used 12/12/9 probes 1 REACHABLE
192.0.2.28 dev eth0 lladdr 00:00:5e:00:53:28 used 61/121/58 probes 6 FAILED
";

    // `ip -6 neigh show`: a router, a link-local router, an entry without `lladdr`, a
    // multicast MAC address and the states of IP4_NEIGH.
    const IP6_NEIGH: &str = "\
2001:db8::1 dev eth0 lladdr 00:00:5e:00:53:01 router REACHABLE
2001:db8::20 dev eth0 lladdr 00:00:5e:00:53:20 STALE
2001:db8::21 dev eth0  FAILED
2001:db8::22 dev eth0 lladdr 00:00:5e:00:53:22 INCOMPLETE
fe80::1 dev eth0 lladdr 00:00:5e:00:53:01 router DELAY
fe80::5efe:c000:20a dev eth1 router STALE
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
    fn ip_neigh_keeps_usable_unicast_entries_of_both_families() {
        let entries = parse_ip_neigh(IP4_NEIGH);
        assert_eq!(
            ips(&entries),
            [
                "192.0.2.1",
                "192.0.2.20",
                "192.0.2.23",
                "192.0.2.24",
                "192.0.2.25",
                "192.0.2.26",
                "192.0.2.27"
            ]
        );
        assert_eq!(entries[2].mac, mac("00:00:5e:00:53:23"));
        assert_eq!(
            ips(&parse_ip_neigh(IP6_NEIGH)),
            ["2001:db8::1", "2001:db8::20", "fe80::1"]
        );
    }

    #[test]
    fn get_net_neighbor_csv_is_read_by_header() {
        let entries = parse_get_net_neighbor_csv(GET_NET_NEIGHBOR);
        assert_eq!(ips(&entries), ["192.0.2.1", "192.0.2.30", "fe80::1"]);
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
        let entries = parse_ip_neigh(IP4_NEIGH);
        let found = findings(&entries, |ip| {
            ["192.0.2.1", "192.0.2.20"].contains(&ip.to_string().as_str())
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
            for entries in [parse_ip_neigh(&text), parse_get_net_neighbor_csv(&text)] {
                let _ = findings(&entries, |_| true);
            }
        }

        #[test]
        fn recorded_tables_with_noise_never_panic(cut in 0usize..400, byte in 0u8..=255) {
            for table in [IP4_NEIGH, IP6_NEIGH, GET_NET_NEIGHBOR] {
                let mut bytes = table.as_bytes().to_vec();
                let at = cut % bytes.len();
                bytes[at] = byte;
                let text = String::from_utf8_lossy(&bytes[..=at]).into_owned();
                let _ = parse_ip_neigh(&text);
                let _ = parse_get_net_neighbor_csv(&text);
            }
        }
    }

    #[tokio::test]
    async fn the_method_reads_the_table_of_its_platform() {
        let system = RecordedSystem::new()
            .file("/usr/sbin/ip", "")
            .command("/usr/sbin/ip -4 neigh show", 0, IP4_NEIGH)
            .command("/usr/sbin/ip -6 neigh show", 0, IP6_NEIGH)
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

    #[tokio::test]
    async fn ip_is_found_in_the_system_directories() {
        let system = RecordedSystem::new().file("/bin/ip", "").command(
            "/bin/ip -4 route show default",
            0,
            "default via 192.0.2.1\n",
        );
        let text = run_ip(&system, &["-4", "route", "show", "default"])
            .await
            .expect("ip");
        assert_eq!(text, "default via 192.0.2.1\n");
        assert_eq!(system.calls(), ["/bin/ip -4 route show default"]);
    }

    #[tokio::test]
    async fn a_missing_or_refused_ip_names_the_cause() {
        let missing = run_ip(&RecordedSystem::new(), &["-4", "neigh", "show"])
            .await
            .expect_err("no ip");
        assert!(
            missing
                .to_string()
                .starts_with("[scan.io] the ip command is not installed")
                && missing.to_string().contains("iproute2"),
            "{missing}"
        );
        let refused = RecordedSystem::new().file("/usr/sbin/ip", "").command(
            "/usr/sbin/ip -6 neigh show",
            1,
            "",
        );
        assert_eq!(
            run_ip(&refused, &["-6", "neigh", "show"])
                .await
                .expect_err("refused")
                .to_string(),
            "[scan.io] ip -6 neigh show failed (exit status 1): nothing on standard error"
        );
        let output = CommandOutput {
            status: Some(255),
            stdout: String::new(),
            stderr: "\nCannot open netlink socket: Address family not supported by protocol\n"
                .to_owned(),
        };
        assert_eq!(
            ip_failed(&["-4", "neigh", "show"], &output).to_string(),
            "[scan.io] ip -4 neigh show failed (exit status 255): Cannot open netlink socket: \
             Address family not supported by protocol"
        );
        let killed = CommandOutput {
            status: None,
            ..CommandOutput::default()
        };
        assert!(
            ip_failed(&["-4", "neigh", "show"], &killed)
                .to_string()
                .contains("(killed by a signal)")
        );
    }
}
