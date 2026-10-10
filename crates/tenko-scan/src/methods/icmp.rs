//! `icmp`: echo requests through the operating system, without raw sockets (SCAN-04).
//!
//! Linux uses unprivileged ICMP datagram sockets when `net.ipv4.ping_group_range` admits
//! the group of the process, else the `ping` command. Windows uses `ping.exe`: the safe
//! wrappers of `IcmpSendEcho` are unmaintained, and a command per address within the rate
//! limit is cheap enough for the prefixes a probe covers. An echo to an on-link address
//! also fills the operating system's neighbour table, so the next `arp` run sees the
//! address with its MAC address even when the host drops ICMP.

use std::{net::IpAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::{StreamExt, stream::FuturesUnordered};
use tenko_cluster::probe::SightingSubject;

use crate::{
    capability::{IcmpSupport, ping_program},
    error::ScanError,
    method::{Availability, Found, Method, MethodKind, MethodOutput, RunContext},
    sys::System,
};

/// Sends one echo request and waits for its reply.
#[async_trait]
pub trait Pinger: Send + Sync + std::fmt::Debug {
    /// Whether `ip` answered within `timeout`.
    ///
    /// # Errors
    ///
    /// `scan.io` when the echo could not be sent at all.
    async fn ping(&self, ip: IpAddr, timeout: Duration) -> Result<bool, ScanError>;
}

/// Whether the output of the platform's `ping` command shows a reply from `ip`.
///
/// Windows prints `TTL=` only in replies (in every language) for IPv4, and a reply line
/// naming the target for IPv6; an unreachable answer comes from another address and has
/// no `TTL=`. Linux `ping` exits with 0 only after a reply.
pub fn ping_output_replied(windows: bool, ip: IpAddr, status: Option<i32>, stdout: &str) -> bool {
    if status != Some(0) {
        return false;
    }
    if !windows {
        return true;
    }
    match ip {
        IpAddr::V4(_) => stdout.contains("TTL="),
        IpAddr::V6(v6) => {
            let target = format!("{v6}:");
            stdout
                .lines()
                .any(|line| line.contains(&target) && line.contains("ms"))
        }
    }
}

/// Pings through the `ping` command.
#[derive(Debug, Clone)]
pub struct CommandPinger {
    system: Arc<dyn System>,
}

impl CommandPinger {
    /// A pinger that runs the platform's `ping`.
    pub fn new(system: Arc<dyn System>) -> Self {
        Self { system }
    }
}

#[async_trait]
impl Pinger for CommandPinger {
    async fn ping(&self, ip: IpAddr, timeout: Duration) -> Result<bool, ScanError> {
        let millis = timeout.as_millis().clamp(10, 60_000).to_string();
        let secs = timeout.as_secs().clamp(1, 60).to_string();
        let target = ip.to_string();
        let args: Vec<&str> = if cfg!(windows) {
            vec!["-n", "1", "-w", &millis, &target]
        } else {
            vec!["-c", "1", "-W", &secs, &target]
        };
        let output = self
            .system
            .run(ping_program(), &args, timeout + Duration::from_secs(5))
            .await?;
        Ok(ping_output_replied(
            cfg!(windows),
            ip,
            output.status,
            &output.stdout,
        ))
    }
}

/// Pings through an unprivileged ICMP datagram socket (Linux).
#[derive(Debug, Clone, Copy, Default)]
pub struct DatagramPinger;

#[cfg(target_os = "linux")]
mod datagram {
    use std::{
        net::{IpAddr, SocketAddr},
        time::Duration,
    };

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    use crate::error::ScanError;

    /// An echo request with sequence 1; the kernel sets the identifier and the checksum.
    fn echo_request(ipv6: bool) -> [u8; 16] {
        let mut packet = [0u8; 16];
        packet[0] = if ipv6 { 128 } else { 8 };
        packet[7] = 1;
        packet[8..].copy_from_slice(b"tenko-sc");
        packet
    }

    pub(super) async fn ping(ip: IpAddr, timeout: Duration) -> Result<bool, ScanError> {
        let ipv6 = ip.is_ipv6();
        let (domain, protocol) = if ipv6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(protocol))
            .map_err(|error| ScanError::io(format!("ICMP datagram socket: {error}")))?;
        socket.set_nonblocking(true)?;
        socket.connect(&SockAddr::from(SocketAddr::new(ip, 0)))?;
        let socket = tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(socket))?;
        socket.send(&echo_request(ipv6)).await?;
        let reply = if ipv6 { 129 } else { 0 };
        let wait = async {
            let mut buffer = [0u8; 1500];
            loop {
                match socket.recv(&mut buffer).await {
                    Ok(len) if len >= 8 && buffer[0] == reply => return true,
                    Ok(_) => {}
                    Err(_) => return false,
                }
            }
        };
        Ok(tokio::time::timeout(timeout, wait).await.unwrap_or(false))
    }
}

#[async_trait]
impl Pinger for DatagramPinger {
    async fn ping(&self, ip: IpAddr, timeout: Duration) -> Result<bool, ScanError> {
        #[cfg(target_os = "linux")]
        {
            datagram::ping(ip, timeout).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (ip, timeout);
            Err(ScanError::unavailable(
                "ICMP datagram sockets exist on Linux only",
            ))
        }
    }
}

/// The pinger for what the host supports; `None` when it supports none.
pub fn pinger_for(support: IcmpSupport, system: Arc<dyn System>) -> Option<Arc<dyn Pinger>> {
    match support {
        IcmpSupport::DatagramSocket => Some(Arc::new(DatagramPinger)),
        IcmpSupport::PingCommand => Some(Arc::new(CommandPinger::new(system))),
        IcmpSupport::Unavailable => None,
    }
}

/// The `icmp` method.
#[derive(Debug, Clone)]
pub struct IcmpSweep {
    pinger: Option<Arc<dyn Pinger>>,
    timeout: Duration,
}

impl IcmpSweep {
    /// A sweep with `pinger`, waiting `timeout` per reply.
    pub fn new(pinger: Option<Arc<dyn Pinger>>, timeout: Duration) -> Self {
        Self { pinger, timeout }
    }
}

/// The targets of a sweep: every address a sweep may enumerate, plus the known addresses
/// of prefixes too large to enumerate (IPv6 networks).
pub fn sweep_targets(ctx: &RunContext) -> Vec<IpAddr> {
    let hosts = ctx.scope.hosts();
    let mut targets = hosts.addresses;
    targets.extend(
        ctx.known
            .iter()
            .copied()
            .filter(|ip| hosts.skipped.iter().any(|net| net.contains(ip)))
            .filter(|ip| ctx.scope.contains(*ip)),
    );
    targets.sort();
    targets.dedup();
    targets
}

#[async_trait]
impl Method for IcmpSweep {
    fn kind(&self) -> MethodKind {
        MethodKind::Icmp
    }

    fn availability(&self) -> Availability {
        if self.pinger.is_some() {
            Availability::Ready
        } else if cfg!(target_os = "linux") {
            Availability::Unavailable(
                "no ICMP: the group of the process is outside net.ipv4.ping_group_range and \
                 no ping command was found"
                    .to_owned(),
            )
        } else {
            Availability::Unavailable("no ping command was found".to_owned())
        }
    }

    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        let Some(pinger) = self.pinger.clone() else {
            return Err(ScanError::unavailable("this host cannot send ICMP echo"));
        };
        let targets = sweep_targets(ctx);
        let total = targets.len();
        let mut pending = FuturesUnordered::new();
        let mut queue = targets.into_iter();
        let mut output = MethodOutput::default();
        let mut errors = 0usize;
        let mut done = 0usize;
        let limit = ctx.pacer.limits().concurrency.max(1);
        loop {
            while pending.len() < limit && !ctx.cancel.is_cancelled() {
                let Some(ip) = queue.next() else { break };
                let pinger = Arc::clone(&pinger);
                let pacer = Arc::clone(&ctx.pacer);
                let timeout = self.timeout;
                pending.push(async move {
                    let _permit = pacer.acquire(ip).await;
                    (ip, pinger.ping(ip, timeout).await)
                });
            }
            let next = tokio::select! {
                next = pending.next() => next,
                () = ctx.cancel.cancelled() => break,
            };
            let Some((ip, result)) = next else { break };
            done += 1;
            output.probes += 1;
            match result {
                Ok(true) => output
                    .found
                    .push(Found::now(SightingSubject::Address { ip, mac: None })),
                Ok(false) => {}
                Err(error) => {
                    errors += 1;
                    if errors == 1 {
                        output.notes.push(format!("{ip}: {}", error.detail()));
                    }
                }
            }
        }
        output.covered_all = done == total && errors == 0 && !ctx.cancel.is_cancelled();
        if errors > 1 {
            output
                .notes
                .push(format!("{errors} echo requests could not be sent"));
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Mutex};

    use super::*;
    use crate::{
        limit::{PaceLimits, Pacer},
        method::Cancel,
        scope::Scope,
    };

    #[derive(Debug, Default)]
    struct FakePinger {
        alive: BTreeSet<IpAddr>,
        asked: Mutex<Vec<IpAddr>>,
    }

    #[async_trait]
    impl Pinger for FakePinger {
        async fn ping(&self, ip: IpAddr, _timeout: Duration) -> Result<bool, ScanError> {
            self.asked.lock().expect("lock").push(ip);
            Ok(self.alive.contains(&ip))
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    fn context(known: Vec<IpAddr>) -> RunContext {
        RunContext {
            scope: Arc::new(
                Scope::parse(
                    &["192.0.2.0/29".to_owned(), "2001:db8::/64".to_owned()],
                    &["192.0.2.6".to_owned()],
                    4096,
                )
                .expect("scope"),
            ),
            narrowed: false,
            known,
            pacer: Arc::new(Pacer::new(PaceLimits {
                per_second: None,
                per_host_interval: Duration::ZERO,
                concurrency: 4,
            })),
            cancel: Cancel::never(),
        }
    }

    #[tokio::test]
    async fn a_sweep_covers_the_prefix_and_the_known_ipv6_addresses() {
        let pinger = Arc::new(FakePinger {
            alive: [ip("192.0.2.1"), ip("192.0.2.5"), ip("2001:db8::7")].into(),
            ..FakePinger::default()
        });
        let sweep = IcmpSweep::new(Some(pinger.clone()), Duration::from_millis(50));
        let ctx = context(vec![
            ip("2001:db8::7"),
            ip("2001:db8::8"),
            ip("2001:db8:1::9"),
        ]);
        let output = sweep.run(&ctx).await.expect("run");
        assert!(output.covered_all);
        assert_eq!(
            output.probes, 7,
            "five IPv4 hosts without the excluded one, two IPv6"
        );
        let mut seen: Vec<IpAddr> = output
            .found
            .iter()
            .map(|found| match &found.subject {
                SightingSubject::Address { ip, mac: None } => *ip,
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        seen.sort();
        assert_eq!(seen, [ip("192.0.2.1"), ip("192.0.2.5"), ip("2001:db8::7")]);
        assert!(
            !pinger
                .asked
                .lock()
                .expect("lock")
                .contains(&ip("2001:db8:1::9"))
        );
    }

    #[tokio::test]
    async fn a_cancelled_sweep_is_not_complete() {
        let (stop, receiver) = tokio::sync::watch::channel(true);
        let mut ctx = context(Vec::new());
        ctx.cancel = Cancel::new(receiver);
        let sweep = IcmpSweep::new(Some(Arc::new(FakePinger::default())), Duration::ZERO);
        let output = sweep.run(&ctx).await.expect("run");
        assert!(!output.covered_all);
        assert_eq!(output.probes, 0);
        drop(stop);
    }

    #[test]
    fn ping_output_is_judged_per_platform() {
        let v4 = ip("192.0.2.1");
        let reply = "Reply from 192.0.2.1: bytes=32 time<1ms TTL=64\r\n";
        let svar = "Svar fr\u{e5}n 192.0.2.1: byte=32 tid<1 ms TTL=64\r\n";
        let unreachable = "Reply from 192.0.2.99: Destination host unreachable.\r\n";
        assert!(ping_output_replied(true, v4, Some(0), reply));
        assert!(ping_output_replied(true, v4, Some(0), svar));
        assert!(!ping_output_replied(true, v4, Some(0), unreachable));
        assert!(!ping_output_replied(true, v4, Some(1), reply));
        let v6 = ip("2001:db8::1");
        assert!(ping_output_replied(
            true,
            v6,
            Some(0),
            "Reply from 2001:db8::1: time<1ms\r\n"
        ));
        assert!(!ping_output_replied(
            true,
            v6,
            Some(0),
            "Reply from 2001:db8::99: Destination host unreachable.\r\n"
        ));
        assert!(ping_output_replied(false, v4, Some(0), ""));
        assert!(!ping_output_replied(false, v4, Some(1), ""));
    }

    /// The loopback answers echo requests in the kernel; no network is involved. Hosts
    /// whose `net.ipv4.ping_group_range` excludes the test's group skip the check.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn datagram_echo_reaches_the_loopback() {
        if !matches!(
            crate::capability::Capabilities::detect(&crate::sys::HostSystem).icmp,
            IcmpSupport::DatagramSocket
        ) {
            eprintln!("ICMP datagram sockets are not allowed here; skipped");
            return;
        }
        let pinger = DatagramPinger;
        assert!(
            pinger
                .ping(ip("127.0.0.1"), Duration::from_secs(2))
                .await
                .expect("ping")
        );
    }

    #[tokio::test]
    async fn the_command_pinger_runs_the_platform_ping() {
        let line = if cfg!(windows) {
            "ping.exe -n 1 -w 1000 192.0.2.1"
        } else {
            "ping -c 1 -W 1 192.0.2.1"
        };
        let system = crate::sys::RecordedSystem::new().command(
            line,
            0,
            "Reply from 192.0.2.1: bytes=32 time<1ms TTL=64\n",
        );
        let pinger = CommandPinger::new(Arc::new(system));
        assert!(
            pinger
                .ping(ip("192.0.2.1"), Duration::from_secs(1))
                .await
                .expect("ping")
        );
        assert!(
            pinger
                .ping(ip("192.0.2.2"), Duration::from_secs(1))
                .await
                .is_err()
        );
    }
}
