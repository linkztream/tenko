//! The production [`ConflictProbe`] over `tenko-scan` (plan section 2.7, P3-Q7): the same
//! methods and privileges the `probe` role uses, so the `dhcp` role needs none of its own.
//!
//! - **ARP** where this node sits on the address's link: an interface with an IPv4 network
//!   that holds the address. The request goes out through `tenko-scan`'s raw link
//!   (`AF_PACKET` through `pnet_datalink`, Linux with `CAP_NET_RAW`, WP3.14) with the
//!   frame builder and parser of `tenko_scan::frame::arp`; it is sent again halfway to the
//!   deadline (at most 100 ms in), so one lost frame does not hide a squatter. Any ARP
//!   frame whose sender is the address, from a usable MAC address other than this node's,
//!   is an answer, and its MAC address is the squatter's. One link per interface opens on
//!   the first probe and closes after ten idle seconds; a reader hands each frame to the
//!   probes waiting for its sender.
//! - **ICMP echo** otherwise (a relayed scope, no `CAP_NET_RAW`, Windows): `tenko-scan`'s
//!   [`Pinger`], an unprivileged ICMP datagram socket on Linux when
//!   `net.ipv4.ping_group_range` admits the process, else the `ping` command; `ping.exe`
//!   on Windows. A reply is an answer without a MAC address. A host that drops ICMP is not
//!   seen; on the link, ARP sees it.
//!
//! A probe that hears nothing within its time answers [`ProbeOutcome::Clear`]; one that
//! cannot send answers [`ProbeOutcome::Unavailable`], and the offer goes out.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use tenko_scan::{
    capability::Capabilities,
    methods::icmp::{Pinger, pinger_for},
    sys::HostSystem,
};

use crate::probe::{ConflictProbe, ProbeOutcome};

/// The probe of the process: ARP on the node's links, ICMP echo elsewhere.
#[derive(Debug, Clone)]
pub struct ScanProbe {
    pinger: Option<Arc<dyn Pinger>>,
    arp: Option<Arc<arp::ArpProbe>>,
    describe: String,
}

impl ScanProbe {
    /// Detects what this host supports, as the scanner does (`docs/scanning.md` section 9).
    pub fn detect() -> Self {
        let capabilities = Capabilities::detect(&HostSystem);
        let pinger = pinger_for(capabilities.icmp, Arc::new(HostSystem));
        let arp = arp::ArpProbe::detect(&capabilities).map(Arc::new);
        let icmp = match capabilities.icmp {
            tenko_scan::capability::IcmpSupport::DatagramSocket => "ICMP datagram sockets",
            tenko_scan::capability::IcmpSupport::PingCommand => "the ping command",
            tenko_scan::capability::IcmpSupport::Unavailable => "no ICMP",
        };
        let describe = match (&arp, &pinger) {
            (Some(_), Some(_)) => format!("ARP on this node's links, {icmp} elsewhere"),
            (Some(_), None) => "ARP on this node's links, nothing elsewhere".to_owned(),
            (None, Some(_)) => format!(
                "{icmp} (ARP needs CAP_NET_RAW on Linux: {})",
                if capabilities.raw_detail.is_empty() {
                    "unsupported here"
                } else {
                    capabilities.raw_detail.as_str()
                }
            ),
            (None, None) => "nothing: neither ICMP nor raw sockets are available".to_owned(),
        };
        Self {
            pinger,
            arp,
            describe,
        }
    }

    /// A probe over `pinger` alone (tests, and hosts without raw sockets).
    pub fn with_pinger(pinger: Arc<dyn Pinger>) -> Self {
        Self {
            pinger: Some(pinger),
            arp: None,
            describe: "ICMP".to_owned(),
        }
    }

    /// What the probe uses, for the role's log line.
    pub fn describe(&self) -> &str {
        &self.describe
    }

    async fn run(&self, addr: Ipv4Addr, timeout: Duration) -> ProbeOutcome {
        if let Some(arp) = &self.arp
            && let Some(outcome) = arp.probe(addr, timeout).await
        {
            return outcome;
        }
        match &self.pinger {
            Some(pinger) => match pinger.ping(std::net::IpAddr::V4(addr), timeout).await {
                Ok(true) => ProbeOutcome::InUse { mac: None },
                Ok(false) => ProbeOutcome::Clear,
                Err(_) => ProbeOutcome::Unavailable,
            },
            None => ProbeOutcome::Unavailable,
        }
    }
}

/// The probe of a `dhcp` role: [`ScanProbe`] when the `probe` role runs in the process
/// (`probe_role`) and can use ICMP or ARP, else none. Says which once (one log line per
/// start, plan section 2.7).
pub fn choose(probe_role: bool) -> Option<super::ProbeHandle> {
    if !probe_role {
        tracing::warn!(
            "conflict detection is off: no probe role runs in this process, so the dhcp role \
             offers addresses without a probe (add probe to the roles to turn it on)"
        );
        return None;
    }
    let probe = ScanProbe::detect();
    if !ConflictProbe::available(&probe) {
        tracing::warn!(
            "conflict detection is off: the probe role runs but can use {}",
            probe.describe()
        );
        return None;
    }
    tracing::info!(
        method = probe.describe(),
        "the dhcp role probes an address never leased to the client before it offers it"
    );
    Some(super::ProbeHandle::new(probe))
}

impl ConflictProbe for ScanProbe {
    fn available(&self) -> bool {
        self.pinger.is_some() || self.arp.is_some()
    }

    fn probe(
        &self,
        addr: Ipv4Addr,
        timeout: Duration,
    ) -> impl Future<Output = ProbeOutcome> + Send {
        self.run(addr, timeout)
    }
}

#[cfg(not(target_os = "linux"))]
mod arp {
    use std::{net::Ipv4Addr, time::Duration};

    use tenko_scan::capability::Capabilities;

    use crate::probe::ProbeOutcome;

    /// Raw sockets need Npcap on Windows, which Tenko does not bundle.
    #[derive(Debug)]
    pub(super) struct ArpProbe;

    impl ArpProbe {
        pub(super) fn detect(_capabilities: &Capabilities) -> Option<Self> {
            None
        }

        #[allow(clippy::unused_self, reason = "the Linux probe's signature")]
        pub(super) fn probe(
            &self,
            _addr: Ipv4Addr,
            _timeout: Duration,
        ) -> std::future::Ready<Option<ProbeOutcome>> {
            std::future::ready(None)
        }
    }
}

#[cfg(target_os = "linux")]
mod arp {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
        sync::{Arc, Mutex, MutexGuard, PoisonError},
        time::{Duration, Instant},
    };

    use tenko_core::MacAddr;
    use tenko_scan::{
        capability::Capabilities,
        frame::{
            arp,
            ethernet::{self, Protocol},
        },
        methods::{
            neighbours::usable_mac,
            raw::link::{HostLinkFactory, LinkFactory, RawLink},
        },
    };
    use tokio::sync::oneshot;

    use crate::probe::ProbeOutcome;

    /// How long an unused link stays open.
    const IDLE: Duration = Duration::from_secs(10);
    /// How long the reader waits for a frame before it looks at its waiters again.
    const READ: Duration = Duration::from_millis(50);
    /// The latest a request is sent again.
    const RESEND: Duration = Duration::from_millis(100);

    type Waiters = HashMap<Ipv4Addr, Vec<oneshot::Sender<MacAddr>>>;

    /// One open link and the probes waiting on it.
    #[derive(Debug)]
    struct Link {
        raw: Arc<dyn RawLink>,
        mac: MacAddr,
        waiters: Mutex<Waiters>,
        last_use: Mutex<Instant>,
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// ARP probes through `tenko-scan`'s raw links.
    #[derive(Debug)]
    pub(super) struct ArpProbe {
        factory: HostLinkFactory,
        links: Arc<Mutex<HashMap<String, Arc<Link>>>>,
    }

    /// The interface whose IPv4 network holds `addr`, with this node's address on it and
    /// its MAC address.
    fn on_link(addr: Ipv4Addr) -> Option<(String, Ipv4Addr, MacAddr)> {
        pnet_datalink::interfaces()
            .into_iter()
            .filter(|iface| iface.is_up() && !iface.is_loopback())
            .find_map(|iface| {
                let mac = iface.mac?;
                iface.ips.iter().find_map(|net| match net.ip() {
                    IpAddr::V4(own) if net.prefix() < 32 && net.contains(IpAddr::V4(addr)) => {
                        Some((iface.name.clone(), own, MacAddr::new(mac.octets())))
                    }
                    _ => None,
                })
            })
    }

    impl ArpProbe {
        pub(super) fn detect(capabilities: &Capabilities) -> Option<Self> {
            capabilities.raw_sockets.then(|| Self {
                factory: HostLinkFactory,
                links: Arc::new(Mutex::new(HashMap::new())),
            })
        }

        /// The open link of `name`, opened when there is none.
        async fn link(&self, name: &str) -> Option<Arc<Link>> {
            if let Some(link) = lock(&self.links).get(name) {
                *lock(&link.last_use) = Instant::now();
                return Some(Arc::clone(link));
            }
            let interface = self
                .factory
                .interfaces()
                .into_iter()
                .find(|iface| iface.name == name)?;
            let raw = match self.factory.open(&interface).await {
                Ok(raw) => raw,
                Err(error) => {
                    tracing::debug!(interface = name, %error, "the conflict probe cannot open a raw link; it uses ICMP");
                    return None;
                }
            };
            let fresh = Arc::new(Link {
                mac: raw.interface().mac,
                raw,
                waiters: Mutex::new(HashMap::new()),
                last_use: Mutex::new(Instant::now()),
            });
            let mut links = lock(&self.links);
            if let Some(link) = links.get(name) {
                return Some(Arc::clone(link));
            }
            links.insert(name.to_owned(), Arc::clone(&fresh));
            drop(links);
            tokio::spawn(read(
                Arc::clone(&self.links),
                name.to_owned(),
                Arc::clone(&fresh),
            ));
            Some(fresh)
        }

        /// Probes `addr` by ARP when this node is on its link; `None` otherwise (ICMP then).
        pub(super) async fn probe(
            &self,
            addr: Ipv4Addr,
            timeout: Duration,
        ) -> Option<ProbeOutcome> {
            let (name, own, mac) = on_link(addr)?;
            if own == addr {
                return Some(ProbeOutcome::InUse {
                    mac: Some(mac.octets()),
                });
            }
            let link = self.link(&name).await?;
            let (tx, mut rx) = oneshot::channel();
            {
                // Under the links' lock, so that the reader does not close the link while
                // this probe registers.
                let _links = lock(&self.links);
                *lock(&link.last_use) = Instant::now();
                lock(&link.waiters).entry(addr).or_default().push(tx);
            }
            let frame = arp::request_frame(link.mac, own, addr);
            if link.raw.send(&frame).await.is_err() {
                return None;
            }
            let start = Instant::now();
            let resend = (timeout / 2).min(RESEND);
            if let Ok(answer) = tokio::time::timeout(resend, &mut rx).await {
                return Some(answered(answer.ok()));
            }
            let _ = link.raw.send(&frame).await;
            let left = timeout.saturating_sub(start.elapsed());
            Some(match tokio::time::timeout(left, rx).await {
                Ok(answer) => answered(answer.ok()),
                Err(_) => ProbeOutcome::Clear,
            })
        }
    }

    fn answered(answer: Option<MacAddr>) -> ProbeOutcome {
        match answer {
            Some(mac) => ProbeOutcome::InUse {
                mac: Some(mac.octets()),
            },
            // The reader stopped (the link failed): nothing was heard.
            None => ProbeOutcome::Clear,
        }
    }

    /// The reader of one link: hands each ARP frame to the probes waiting for its sender,
    /// and closes the link when it failed or no probe used it for [`IDLE`].
    async fn read(links: Arc<Mutex<HashMap<String, Arc<Link>>>>, name: String, link: Arc<Link>) {
        loop {
            match link.raw.recv(READ).await {
                Ok(Some(frame)) => deliver(&link, &frame),
                Ok(None) => {}
                Err(error) => {
                    tracing::debug!(interface = name, %error, "the conflict probe's raw link failed");
                    lock(&links).remove(&name);
                    return;
                }
            }
            let mut held = lock(&links);
            let mut waiters = lock(&link.waiters);
            waiters.retain(|_, senders| {
                senders.retain(|sender| !sender.is_closed());
                !senders.is_empty()
            });
            if waiters.is_empty() && lock(&link.last_use).elapsed() >= IDLE {
                held.remove(&name);
                return;
            }
        }
    }

    fn deliver(link: &Link, frame: &[u8]) {
        let Some(parsed) = ethernet::parse(frame) else {
            return;
        };
        if parsed.protocol != Protocol::EtherType(ethernet::ETHERTYPE_ARP) {
            return;
        }
        let Some(message) = arp::parse(parsed.payload) else {
            return;
        };
        if !usable_mac(message.sender_mac) || message.sender_mac == link.mac {
            return;
        }
        if let Some(senders) = lock(&link.waiters).remove(&message.sender_ip) {
            for sender in senders {
                let _ = sender.send(message.sender_mac);
            }
        }
    }
}
