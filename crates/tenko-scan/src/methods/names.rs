//! `mdns` and `llmnr`: names, services and OS hints from the link-local name protocols
//! (SCAN-02, SCAN-03).
//!
//! `mdns` sends a DNS-SD service browse to the mDNS group from an ephemeral port (RFC 6762
//! legacy unicast: responders answer that port directly), asks each announced service
//! type once, and sends a unicast reverse query to port 5353 of every known address.
//! With `passive` on it also listens on port 5353 for the announcements of the window,
//! sharing the port with other mDNS responders on the host. `llmnr` sends a unicast
//! reverse query to port 5355 of every known address (RFC 4795). Both report an address
//! sighting for every responder inside the scope, its name, and for mDNS the TCP ports of
//! its services and an OS hint.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use async_trait::async_trait;
use tenko_cluster::probe::SightingSubject;
use tokio::{net::UdpSocket, time::Instant};

use crate::{
    dns::{
        NameFindings, QueryOptions, QueryType, build_query, llmnr, mdns, parse_response,
        reverse_name,
    },
    error::ScanError,
    method::{Availability, Found, Method, MethodKind, MethodOutput, RunContext},
    scope::{Scope, canonical},
};

/// Most service types one run asks about.
const MAX_SERVICE_TYPES: usize = 32;

/// Most known addresses one run sends a unicast query to.
const MAX_UNICAST: usize = 4096;

/// Largest datagram read.
const MAX_DATAGRAM: usize = 9000;

/// Which protocol a [`NameQuery`] speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Multicast DNS.
    Mdns,
    /// LLMNR.
    Llmnr,
}

/// The `mdns` or `llmnr` method.
#[derive(Debug, Clone)]
pub struct NameQuery {
    protocol: Protocol,
    /// Where the multicast browse goes (mDNS only).
    group: Option<SocketAddr>,
    /// The port of the unicast queries to known addresses.
    unicast_port: u16,
    /// How long answers are collected after the last query.
    window: Duration,
    /// Listen on the protocol port for announcements (mDNS only).
    passive: bool,
}

impl NameQuery {
    /// The `mdns` method: browse at `group`, unicast queries to `unicast_port`, a window of
    /// `window`, optionally listening on the group's port.
    pub fn mdns(group: SocketAddr, unicast_port: u16, window: Duration, passive: bool) -> Self {
        Self {
            protocol: Protocol::Mdns,
            group: Some(group),
            unicast_port,
            window,
            passive,
        }
    }

    /// The `llmnr` method: unicast queries to `port`, answers collected for `window`.
    pub fn llmnr(port: u16, window: Duration) -> Self {
        Self {
            protocol: Protocol::Llmnr,
            group: None,
            unicast_port: port,
            window,
            passive: false,
        }
    }
}

fn query(name: &str, qtype: QueryType, id: u16) -> Option<Vec<u8>> {
    build_query(
        name,
        qtype,
        QueryOptions {
            id,
            recursion_desired: false,
            unicast_response: false,
        },
    )
    .ok()
}

async fn bind(ipv6: bool) -> Option<UdpSocket> {
    let address: SocketAddr = if ipv6 {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    UdpSocket::bind(address).await.ok()
}

/// A socket on the mDNS port of `group`, shared with other responders, joined to the
/// group; `None` when the port is held exclusively or the group cannot be joined.
fn passive_socket(group: SocketAddr) -> Option<UdpSocket> {
    let IpAddr::V4(group_ip) = group.ip() else {
        return None;
    };
    if !group_ip.is_multicast() {
        return None;
    }
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    socket.set_reuse_address(true).ok()?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true).ok()?;
    socket.set_nonblocking(true).ok()?;
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), group.port());
    socket.bind(&local.into()).ok()?;
    socket
        .join_multicast_v4(&group_ip, &Ipv4Addr::UNSPECIFIED)
        .ok()?;
    UdpSocket::from_std(std::net::UdpSocket::from(socket)).ok()
}

/// Collects datagrams on `sockets` until `deadline`, interpreting each answer; with
/// `types`, also the service types of DNS-SD browse answers (mDNS).
async fn collect(
    sockets: &[&UdpSocket],
    protocol: Protocol,
    deadline: Instant,
    ctx: &RunContext,
    findings: &mut NameFindings,
    mut types: Option<&mut Vec<String>>,
) {
    let mut buffers: Vec<Vec<u8>> = sockets.iter().map(|_| vec![0u8; MAX_DATAGRAM]).collect();
    loop {
        if ctx.cancel.is_cancelled() {
            return;
        }
        let received = {
            let listeners = sockets
                .iter()
                .zip(buffers.iter_mut())
                .map(|(socket, buffer)| {
                    Box::pin(async move {
                        let (len, from) = socket.recv_from(buffer).await.ok()?;
                        Some((buffer[..len].to_vec(), from))
                    })
                });
            let any = futures::future::select_all(listeners);
            tokio::select! {
                (received, _, _) = any => received,
                () = tokio::time::sleep_until(deadline) => return,
                () = ctx.cancel.cancelled() => return,
            }
        };
        let Some((bytes, from)) = received else {
            continue;
        };
        let Ok(response) = parse_response(&bytes) else {
            continue;
        };
        if !response.is_response {
            continue;
        }
        if let Some(types) = types.as_deref_mut() {
            for service in mdns::service_types(&response) {
                if !types.contains(&service) {
                    types.push(service);
                }
            }
        }
        let source = canonical(from.ip());
        let found = match protocol {
            Protocol::Mdns => mdns::interpret(source, &response),
            Protocol::Llmnr => llmnr::interpret(source, &response),
        };
        findings.merge(found);
    }
}

/// The sightings of `findings` inside `scope`: an address per responder, a name, the TCP
/// ports of announced services and an OS hint.
pub fn to_found(findings: &NameFindings, scope: &Scope) -> Vec<Found> {
    let mut found = Vec::new();
    for ip in findings
        .addresses
        .iter()
        .copied()
        .filter(|ip| scope.contains(*ip))
    {
        found.push(Found::now(SightingSubject::Address { ip, mac: None }));
    }
    for (ip, name) in findings.names.iter().filter(|(ip, _)| scope.contains(**ip)) {
        found.push(Found::now(SightingSubject::Name {
            ip: *ip,
            name: name.clone(),
        }));
    }
    for (ip, ports) in findings
        .services
        .iter()
        .filter(|(ip, _)| scope.contains(**ip))
    {
        if !ports.is_empty() {
            found.push(Found::now(SightingSubject::Services {
                ip: *ip,
                open_tcp: ports.iter().copied().collect(),
                tls_tcp: Vec::new(),
            }));
        }
    }
    for (ip, (guess, confidence)) in findings.os.iter().filter(|(ip, _)| scope.contains(**ip)) {
        found.push(Found::now(SightingSubject::Os {
            ip: *ip,
            guess: guess.clone(),
            confidence: *confidence,
        }));
    }
    found
}

#[async_trait]
impl Method for NameQuery {
    fn kind(&self) -> MethodKind {
        match self.protocol {
            Protocol::Mdns => MethodKind::Mdns,
            Protocol::Llmnr => MethodKind::Llmnr,
        }
    }

    fn availability(&self) -> Availability {
        Availability::Ready
    }

    fn deadline(&self) -> Duration {
        Duration::from_secs(1800)
    }

    fn completes(&self) -> bool {
        false
    }

    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        let v4 = bind(false)
            .await
            .ok_or_else(|| ScanError::io("cannot open a UDP socket"))?;
        let v6 = bind(true).await;
        let passive = if self.passive {
            self.group.and_then(passive_socket)
        } else {
            None
        };
        let mut output = MethodOutput::default();
        if self.passive && passive.is_none() {
            output
                .notes
                .push("the mDNS port is not shared on this host; queries only".to_owned());
        }
        let mut findings = NameFindings::default();
        let mut sockets: Vec<&UdpSocket> = vec![&v4];
        sockets.extend(v6.as_ref());
        sockets.extend(passive.as_ref());
        let mut id: u16 = 0x2a00;
        let mut sent_all = true;

        // The browse and the service types (mDNS).
        if let (Protocol::Mdns, Some(group)) = (self.protocol, self.group) {
            if let Some(browse) = query(mdns::SERVICES_QUERY, QueryType::Ptr, 0) {
                let _permit = ctx.pacer.acquire(group.ip()).await;
                if v4.send_to(&browse, group).await.is_ok() {
                    output.probes += 1;
                } else {
                    sent_all = false;
                }
            }
            let mut types = Vec::new();
            let deadline = Instant::now() + self.window / 2;
            let mut browse_findings = NameFindings::default();
            collect(
                &sockets,
                Protocol::Mdns,
                deadline,
                ctx,
                &mut browse_findings,
                Some(&mut types),
            )
            .await;
            findings.merge(browse_findings);
            types.truncate(MAX_SERVICE_TYPES);
            for service in &types {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                if let Some(ask) = query(service, QueryType::Ptr, 0) {
                    let _permit = ctx.pacer.acquire(group.ip()).await;
                    if v4.send_to(&ask, group).await.is_ok() {
                        output.probes += 1;
                    }
                }
            }
        }

        // Unicast reverse queries to the known addresses.
        let targets: Vec<IpAddr> = ctx
            .known
            .iter()
            .copied()
            .filter(|ip| ctx.scope.contains(*ip))
            .take(MAX_UNICAST)
            .collect();
        for ip in targets {
            if ctx.cancel.is_cancelled() {
                sent_all = false;
                break;
            }
            id = id.wrapping_add(1);
            let Some(ask) = query(&reverse_name(ip), QueryType::Ptr, id) else {
                continue;
            };
            let socket = if ip.is_ipv6() { v6.as_ref() } else { Some(&v4) };
            let Some(socket) = socket else {
                sent_all = false;
                continue;
            };
            let _permit = ctx.pacer.acquire(ip).await;
            if socket
                .send_to(&ask, SocketAddr::new(ip, self.unicast_port))
                .await
                .is_ok()
            {
                output.probes += 1;
            } else {
                sent_all = false;
            }
        }

        // Answers and announcements until the window closes.
        let deadline = Instant::now() + self.window;
        collect(&sockets, self.protocol, deadline, ctx, &mut findings, None).await;
        output.found = to_found(&findings, &ctx.scope);
        output.covered_all = sent_all && !ctx.cancel.is_cancelled();
        Ok(output)
    }
}
