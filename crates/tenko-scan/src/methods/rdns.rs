//! `reverse_dns`: PTR lookups of the addresses this probe discovered, sent to the
//! configured DNS servers or to the resolvers of the probe host.
//!
//! Only addresses another method saw recently are looked up; a PTR record alone is not a
//! sighting, so the method reports names, never addresses.

use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use futures::{StreamExt, stream::FuturesUnordered};
use tenko_cluster::probe::SightingSubject;
use tokio::net::UdpSocket;

use crate::{
    dns::{QueryOptions, QueryType, build_query, parse_response, ptr_names, reverse_name},
    error::ScanError,
    limit::Pacer,
    method::{Availability, Found, Method, MethodKind, MethodOutput, RunContext},
    sys::System,
};

/// Placeholder resolvers Windows lists on interfaces without DNS configuration.
const WINDOWS_PLACEHOLDERS: [&str; 3] =
    ["fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"];

/// The `nameserver` entries of a `resolv.conf`.
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let Some(address) = fields.next() else {
            continue;
        };
        // A link-local server may carry a zone (`fe80::1%eth0`); it cannot be used from
        // here without the interface index, so it is left out.
        if let Ok(ip) = address.parse::<IpAddr>() {
            let server = SocketAddr::new(ip, 53);
            if !out.contains(&server) {
                out.push(server);
            }
        }
    }
    out
}

/// The server addresses PowerShell prints, one per line.
pub fn parse_server_lines(text: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if WINDOWS_PLACEHOLDERS.contains(&line) {
            continue;
        }
        if let Ok(ip) = line.parse::<IpAddr>() {
            let server = SocketAddr::new(ip, 53);
            if !out.contains(&server) {
                out.push(server);
            }
        }
    }
    out
}

/// The resolvers of the probe host.
///
/// # Errors
///
/// `scan.io` when the configuration cannot be read.
pub async fn system_resolvers(system: &dyn System) -> Result<Vec<SocketAddr>, ScanError> {
    if cfg!(windows) {
        let output = system
            .run(
                "powershell.exe",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | \
                     Where-Object { $_.ServerAddresses }).ServerAddresses",
                ],
                Duration::from_secs(30),
            )
            .await?;
        Ok(parse_server_lines(&output.stdout))
    } else {
        Ok(parse_resolv_conf(
            &system.read(Path::new("/etc/resolv.conf"))?,
        ))
    }
}

/// What one lookup gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// An answer: the names, possibly none (no PTR record).
    Answered(Vec<String>),
    /// No server answered in time.
    Unanswered,
}

/// Looks up the PTR names of `ip`, trying `servers` in turn.
pub async fn lookup(
    ip: IpAddr,
    servers: &[SocketAddr],
    timeout: Duration,
    pacer: &Pacer,
) -> Lookup {
    let name = reverse_name(ip);
    for server in servers {
        let id = query_id(ip, *server);
        let Ok(query) = build_query(
            &name,
            QueryType::Ptr,
            QueryOptions {
                id,
                recursion_desired: true,
                unicast_response: false,
            },
        ) else {
            return Lookup::Unanswered;
        };
        let _permit = pacer.acquire(server.ip()).await;
        if let Some(names) = ask(*server, &query, id, ip, timeout).await {
            return Lookup::Answered(names);
        }
    }
    Lookup::Unanswered
}

/// A query id that differs per address and server and per process.
fn query_id(ip: IpAddr, server: SocketAddr) -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write(ip.to_string().as_bytes());
    hasher.write(server.to_string().as_bytes());
    let value = hasher.finish();
    u16::try_from(value & 0xffff).unwrap_or_default()
}

async fn ask(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    ip: IpAddr,
    timeout: Duration,
) -> Option<Vec<String>> {
    let bind: SocketAddr = if server.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind).await.ok()?;
    socket.connect(server).await.ok()?;
    socket.send(query).await.ok()?;
    let wait = async {
        let mut buffer = vec![0u8; 4096];
        loop {
            let len = socket.recv(&mut buffer).await.ok()?;
            let Ok(response) = parse_response(&buffer[..len]) else {
                continue;
            };
            if response.is_response && response.id == id {
                // NXDOMAIN and an empty answer are answers too: no name.
                return Some(ptr_names(&response, ip));
            }
        }
    };
    tokio::time::timeout(timeout, wait).await.ok().flatten()
}

/// The `reverse_dns` method.
#[derive(Debug, Clone)]
pub struct ReverseDns {
    servers: Vec<SocketAddr>,
    timeout: Duration,
    system: Arc<dyn System>,
}

impl ReverseDns {
    /// Lookups at `servers`, or at the host's resolvers when empty.
    pub fn new(servers: Vec<SocketAddr>, timeout: Duration, system: Arc<dyn System>) -> Self {
        Self {
            servers,
            timeout,
            system,
        }
    }
}

#[async_trait]
impl Method for ReverseDns {
    fn kind(&self) -> MethodKind {
        MethodKind::ReverseDns
    }

    fn availability(&self) -> Availability {
        Availability::Ready
    }

    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        let servers = if self.servers.is_empty() {
            system_resolvers(self.system.as_ref()).await?
        } else {
            self.servers.clone()
        };
        if servers.is_empty() {
            return Err(ScanError::unavailable(
                "no DNS server: set scan.reverse_dns.servers or configure a resolver",
            ));
        }
        let targets: Vec<IpAddr> = ctx
            .known
            .iter()
            .copied()
            .filter(|ip| ctx.scope.contains(*ip))
            .collect();
        let total = targets.len();
        let mut queue = targets.into_iter();
        let limit = ctx.pacer.limits().concurrency.clamp(1, 8);
        let mut pending = FuturesUnordered::new();
        let mut output = MethodOutput::default();
        let mut answered = 0usize;
        let mut done = 0usize;
        loop {
            while pending.len() < limit && !ctx.cancel.is_cancelled() {
                let Some(ip) = queue.next() else { break };
                let (servers, pacer, timeout) =
                    (servers.clone(), Arc::clone(&ctx.pacer), self.timeout);
                pending.push(async move { (ip, lookup(ip, &servers, timeout, &pacer).await) });
            }
            let next = tokio::select! {
                next = pending.next() => next,
                () = ctx.cancel.cancelled() => break,
            };
            let Some((ip, result)) = next else { break };
            done += 1;
            output.probes += 1;
            if let Lookup::Answered(names) = result {
                answered += 1;
                if let Some(name) = names.into_iter().next() {
                    output
                        .found
                        .push(Found::now(SightingSubject::Name { ip, name }));
                }
            }
        }
        if answered < done {
            output.notes.push(format!(
                "{} of {done} lookups got no answer from {}",
                done - answered,
                servers
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        output.covered_all = done == total && answered == done && !ctx.cancel.is_cancelled();
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_lists_nameservers_once() {
        let text = "# generated\nsearch example.net\nnameserver 192.0.2.53\nnameserver 2001:db8::53\n\
                    nameserver 192.0.2.53\nnameserver fe80::1%eth0\noptions edns0\n";
        assert_eq!(
            parse_resolv_conf(text),
            [
                "192.0.2.53:53".parse::<SocketAddr>().expect("addr"),
                "[2001:db8::53]:53".parse().expect("addr")
            ]
        );
    }

    #[test]
    fn windows_placeholders_are_skipped() {
        let text = "192.0.2.53\r\nfec0:0:0:ffff::1\r\nfec0:0:0:ffff::2\r\n2001:db8::53\r\n";
        assert_eq!(parse_server_lines(text).len(), 2);
    }
}
