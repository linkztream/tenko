//! The next hops of this node's default routes: the second source of the topology root
//! (UI-Q10, `docs/topology.md` section 6.1), read as the service account can, with no
//! privilege and no capability.
//!
//! | Platform | IPv4 | IPv6 |
//! |---|---|---|
//! | Linux | `ip -4 route show default` (netlink, which the shipped unit allows; `/proc/net` is hidden there) | `ip -6 route show default` |
//! | Windows | `Get-NetRoute -DestinationPrefix 0.0.0.0/0` (PowerShell, readable by every account) | `Get-NetRoute -DestinationPrefix ::/0` |
//! | other | nothing: the controller's gateway alone names the root | |
//!
//! The answer is ordered by preference: IPv4 before IPv6, the lowest metric first, and
//! kept for [`ROUTE_TTL`]. A table that cannot be read answers nothing, never an error; on
//! Linux the log says why.

use std::{
    future::Future,
    net::IpAddr,
    pin::Pin,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

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

    /// The kept answer while it is fresh, else the answer of `read`. The lock is held
    /// across the read, so callers that arrive while it runs wait for it instead of each
    /// starting the child processes again.
    async fn cached<F: Future<Output = Vec<IpAddr>>>(
        &self,
        read: impl FnOnce() -> F,
    ) -> Vec<IpAddr> {
        let mut kept = self.kept.lock().await;
        if let Some((at, hops)) = kept.as_ref()
            && at.elapsed() < ROUTE_TTL
        {
            return hops.clone();
        }
        let hops = read().await;
        *kept = Some((Instant::now(), hops.clone()));
        hops
    }
}

impl DefaultRoute for OsDefaultRoute {
    fn next_hops(&self) -> Pin<Box<dyn Future<Output = Vec<IpAddr>> + Send + '_>> {
        Box::pin(self.cached(read))
    }
}

#[cfg(target_os = "linux")]
async fn read() -> Vec<IpAddr> {
    // A warning once per process: a host without iproute2 (the container image) would
    // repeat it at every read.
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let mut hops = Vec::new();
    for family in ["-4", "-6"] {
        let args = [family, "route", "show", "default"];
        match tenko_scan::methods::neighbors::run_ip(&tenko_scan::sys::HostSystem, &args).await {
            Ok(text) => hops.extend(parse_ip_route(&text)),
            Err(error) if WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) => {
                tracing::debug!(%error, "the default routes cannot be read");
            }
            Err(error) => tracing::warn!(%error, "the default routes cannot be read"),
        }
    }
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

/// The next hops of `ip -4 route show default` or `ip -6 route show default`, the lowest
/// metric first: a route per line (`default [nhid <n>] via <hop> dev <if> ... [metric <n>]`,
/// no metric is 0) with the hops of a multipath route on the indented lines after it
/// (`nexthop via [inet6] <hop> dev <if> weight <n>`). A route without `via` is on-link and
/// names no hop; another route type (`unreachable default`, ...) and a `dead` hop do not
/// count.
#[cfg(any(target_os = "linux", test))]
pub fn parse_ip_route(text: &str) -> Vec<IpAddr> {
    let mut hops: Vec<(u32, IpAddr)> = Vec::new();
    let mut route: Option<u32> = None;
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let after = |name: &str| {
            let at = fields.iter().position(|field| *field == name)?;
            fields.get(at + 1).copied()
        };
        if !line.starts_with(char::is_whitespace) {
            route = (fields.first() == Some(&"default")).then(|| {
                after("metric")
                    .and_then(|metric| metric.parse().ok())
                    .unwrap_or(0)
            });
        }
        let Some(metric) = route else { continue };
        if fields.contains(&"dead") {
            continue;
        }
        let mut via = fields.iter().skip_while(|field| **field != "via").skip(1);
        let hop = via
            .next()
            .filter(|field| !matches!(**field, "inet" | "inet6"))
            .or_else(|| via.next())
            .and_then(|field| field.parse::<IpAddr>().ok());
        if let Some(hop) = hop.filter(|hop| !hop.is_unspecified()) {
            hops.push((metric, hop));
        }
    }
    hops.sort();
    let mut seen = std::collections::BTreeSet::new();
    hops.into_iter()
        .filter_map(|(_, hop)| seen.insert(hop).then_some(hop))
        .collect()
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

    fn ips(text: &[&str]) -> Vec<IpAddr> {
        text.iter().map(|ip| ip.parse().expect("ip")).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_callers_share_one_read() {
        let route = OsDefaultRoute::new();
        let reads = std::sync::atomic::AtomicUsize::new(0);
        let read = || async {
            reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(50)).await;
            ips(&["192.0.2.1"])
        };
        let (a, b, c) = tokio::join!(route.cached(read), route.cached(read), route.cached(read));
        assert!([a, b, c].iter().all(|hops| *hops == ips(&["192.0.2.1"])));
        assert_eq!(reads.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn the_ipv4_default_routes_come_by_metric() {
        // `ip -4 route show default` of iproute2 6.1: DHCP routes, an on-link route, a route
        // through a next-hop object, and a multipath route with a dead hop.
        let table = "\
default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.10 metric 100 \n\
default via 198.51.100.1 dev wlan0 proto dhcp src 198.51.100.20 metric 600 \n\
default dev wg0 scope link \n\
default nhid 12 via 203.0.113.1 dev eth2 metric 50 \n\
default proto static metric 20 \n\
\tnexthop via 192.0.2.254 dev eth0 weight 1 \n\
\tnexthop via 198.51.100.254 dev wlan0 weight 1 dead linkdown \n\
default via 192.0.2.1 dev eth1 \n";
        assert_eq!(
            parse_ip_route(table),
            ips(&["192.0.2.1", "192.0.2.254", "203.0.113.1", "198.51.100.1"])
        );
        // A route of an older iproute2 without a metric, and one through an IPv6 next hop.
        assert_eq!(
            parse_ip_route(
                "default via 192.0.2.1 dev eth0 \ndefault via inet6 fe80::1 dev eth1 metric 5\n"
            ),
            ips(&["192.0.2.1", "fe80::1"])
        );
        assert!(parse_ip_route("").is_empty(), "no default route");
        assert!(
            parse_ip_route("default via\nbroken line\n\tnexthop via 192.0.2.9\n").is_empty(),
            "broken lines"
        );
    }

    #[test]
    fn the_ipv6_default_routes_come_by_metric() {
        // `ip -6 route show default`: a router advertisement, a static route, an unreachable
        // default route, and the multipath form of iproute2 4.x and later.
        let table = "\
default via fe80::1 dev eth0 proto ra metric 1024 expires 1797sec hoplimit 64 pref medium\n\
default via 2001:db8::1 dev eth0 proto static metric 100 pref medium\n\
unreachable default dev lo proto kernel metric 4294967295 error -101 pref medium\n\
default proto ra metric 2048 expires 1795sec pref medium\n\
\tnexthop via fe80::2 dev eth1 weight 1 \n\
\tnexthop via fe80::3 dev eth1 weight 1 \n";
        assert_eq!(
            parse_ip_route(table),
            ips(&["2001:db8::1", "fe80::1", "fe80::2", "fe80::3"])
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
