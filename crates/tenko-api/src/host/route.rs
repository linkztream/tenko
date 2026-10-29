//! The next hops of this node's default routes: the second source of the topology root
//! (UI-Q10, `docs/topology.md` section 6.1), read as the service account can, with no
//! privilege and no capability.
//!
//! | Platform | IPv4 | IPv6 |
//! |---|---|---|
//! | Linux | `/proc/net/route` (world-readable) | `/proc/net/ipv6_route` (world-readable) |
//! | Windows | `Get-NetRoute -DestinationPrefix 0.0.0.0/0` (PowerShell, readable by every account) | `Get-NetRoute -DestinationPrefix ::/0` |
//! | other | nothing: the controller's gateway alone names the root | |
//!
//! The answer is ordered by preference: IPv4 before IPv6, the lowest metric first, and
//! kept for [`ROUTE_TTL`]. A table that cannot be read answers nothing, never an error.

use std::{
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use tenko_ipam::topology::DefaultRoute;

/// How long a read of the routing table is kept.
pub const ROUTE_TTL: Duration = Duration::from_secs(60);

/// The routing table of the host Tenko runs on.
#[derive(Debug, Default)]
pub struct OsDefaultRoute {
    kept: Mutex<Option<(Instant, Vec<IpAddr>)>>,
}

impl OsDefaultRoute {
    /// A reader with nothing kept yet.
    pub fn new() -> Self {
        Self::default()
    }
}

impl DefaultRoute for OsDefaultRoute {
    fn next_hops(&self) -> Pin<Box<dyn Future<Output = Vec<IpAddr>> + Send + '_>> {
        Box::pin(async move {
            if let Some((at, hops)) = self
                .kept
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                && at.elapsed() < ROUTE_TTL
            {
                return hops.clone();
            }
            let hops = read().await;
            *self.kept.lock().unwrap_or_else(PoisonError::into_inner) =
                Some((Instant::now(), hops.clone()));
            hops
        })
    }
}

#[cfg(target_os = "linux")]
async fn read() -> Vec<IpAddr> {
    let v4 = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    let v6 = std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default();
    let mut hops = parse_proc_route(&v4);
    hops.extend(parse_proc_ipv6_route(&v6));
    hops
}

#[cfg(windows)]
async fn read() -> Vec<IpAddr> {
    const SCRIPT: &str = "Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' \
        -ErrorAction SilentlyContinue | Sort-Object RouteMetric | \
        ForEach-Object { $_.NextHop }";
    let mut command = tokio::process::Command::new("powershell.exe");
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    // CREATE_NO_WINDOW: a service or a console session gets no flashing window.
    command.creation_flags(0x0800_0000);
    let Ok(child) = command.spawn() else {
        return Vec::new();
    };
    match tokio::time::timeout(Duration::from_secs(10), child.wait_with_output()).await {
        Ok(Ok(output)) if output.status.success() => {
            parse_next_hops(&String::from_utf8_lossy(&output.stdout))
        }
        _ => Vec::new(),
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
async fn read() -> Vec<IpAddr> {
    Vec::new()
}

/// `RTF_UP | RTF_GATEWAY` of the route flags.
#[cfg(any(target_os = "linux", test))]
const UP_GATEWAY: u32 = 0x0003;

/// The gateways of the IPv4 default routes in `/proc/net/route`, the lowest metric first:
/// a header, then `Iface Destination Gateway Flags RefCnt Use Metric Mask ...` with the
/// addresses as hexadecimal numbers in host byte order (little-endian on every platform
/// Tenko ships for).
#[cfg(any(target_os = "linux", test))]
pub fn parse_proc_route(text: &str) -> Vec<IpAddr> {
    let mut hops: Vec<(u32, std::net::Ipv4Addr)> = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (destination, gateway, flags, metric, mask) = (
                fields.get(1)?,
                fields.get(2)?,
                fields.get(3)?,
                fields.get(6)?,
                fields.get(7)?,
            );
            let flags = u32::from_str_radix(flags, 16).ok()?;
            if *destination != "00000000" || *mask != "00000000" || flags & UP_GATEWAY != UP_GATEWAY
            {
                return None;
            }
            let gateway = u32::from_str_radix(gateway, 16).ok()?;
            if gateway == 0 {
                return None;
            }
            Some((
                metric.parse().ok()?,
                std::net::Ipv4Addr::from(gateway.to_le_bytes()),
            ))
        })
        .collect();
    hops.sort();
    hops.dedup_by_key(|(_, ip)| *ip);
    hops.into_iter().map(|(_, ip)| IpAddr::V4(ip)).collect()
}

/// The next hops of the IPv6 default routes in `/proc/net/ipv6_route`, the lowest metric
/// first: `dest dest_len src src_len next_hop metric refcnt use flags iface`, the addresses
/// as 32 hexadecimal digits.
#[cfg(any(target_os = "linux", test))]
pub fn parse_proc_ipv6_route(text: &str) -> Vec<IpAddr> {
    let mut hops: Vec<(u32, std::net::Ipv6Addr)> = text
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (destination, length, next_hop, metric, flags) = (
                fields.first()?,
                fields.get(1)?,
                fields.get(4)?,
                fields.get(5)?,
                fields.get(8)?,
            );
            let flags = u32::from_str_radix(flags, 16).ok()?;
            if destination.chars().any(|c| c != '0')
                || *length != "00"
                || flags & UP_GATEWAY != UP_GATEWAY
            {
                return None;
            }
            let hop = std::net::Ipv6Addr::from(u128::from_str_radix(next_hop, 16).ok()?);
            if hop.is_unspecified() {
                return None;
            }
            Some((u32::from_str_radix(metric, 16).ok()?, hop))
        })
        .collect();
    hops.sort();
    hops.dedup_by_key(|(_, ip)| *ip);
    hops.into_iter().map(|(_, ip)| IpAddr::V6(ip)).collect()
}

/// The addresses of `Get-NetRoute ... | ForEach-Object NextHop`, one per line, IPv4 first;
/// the unspecified next hop of an on-link route is left out.
#[cfg(any(windows, test))]
pub fn parse_next_hops(text: &str) -> Vec<IpAddr> {
    let mut hops: Vec<IpAddr> = Vec::new();
    for hop in text
        .lines()
        .filter_map(|line| line.trim().parse::<IpAddr>().ok())
    {
        if !hop.is_unspecified() && !hops.contains(&hop) {
            hops.push(hop);
        }
    }
    // A stable sort keeps the metric order within each family.
    hops.sort_by_key(IpAddr::is_ipv6);
    hops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ipv4_default_routes_come_by_metric() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t000200C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
            wlan0\t00000000\t016433C6\t0003\t0\t0\t50\t00000000\t0\t0\t0\n\
            down0\t00000000\t017100CB\t0002\t0\t0\t1\t00000000\t0\t0\t0\n";
        assert_eq!(
            parse_proc_route(table),
            [
                IpAddr::from([198, 51, 100, 1]),
                IpAddr::from([192, 0, 2, 1])
            ]
        );
        assert!(parse_proc_route("").is_empty(), "an empty table");
        assert!(
            parse_proc_route("header\nbroken line\n").is_empty(),
            "a broken line"
        );
    }

    #[test]
    fn the_ipv6_default_routes_come_by_metric() {
        let table = "\
            00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n\
            20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n\
            00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 00000001 00000000 00000003     eth0\n";
        assert_eq!(
            parse_proc_ipv6_route(table),
            [
                "fe80::1".parse::<IpAddr>().expect("ip"),
                "2001:db8::1".parse::<IpAddr>().expect("ip")
            ]
        );
    }

    #[test]
    fn powershell_next_hops_put_ipv4_first_and_skip_on_link_routes() {
        let text = "2001:db8::1\r\n192.0.2.1\r\n0.0.0.0\r\n\r\n198.51.100.1\r\n192.0.2.1\r\n::\r\n";
        assert_eq!(
            parse_next_hops(text),
            [
                IpAddr::from([192, 0, 2, 1]),
                IpAddr::from([198, 51, 100, 1]),
                "2001:db8::1".parse::<IpAddr>().expect("ip")
            ]
        );
    }
}
