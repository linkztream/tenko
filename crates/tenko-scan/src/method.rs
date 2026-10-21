//! Scan methods: what each one is, what it needs, and the interface the scheduler drives.
//!
//! Every method maps to one [`ProbeMethod`], so its batches form one observation source
//! `probe:<node>:<method>`, and every run yields one batch. A method reports whether it
//! covered everything it was asked to cover; the scheduler marks the batch complete only
//! then, and only for a run over the whole configured scope.

use std::{fmt, net::IpAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tenko_cluster::probe::SightingSubject;
use tenko_core::{Timestamp, observe::ProbeMethod};
use tokio::sync::watch;

use crate::{error::ScanError, limit::Pacer, scope::Scope};

/// A scan method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodKind {
    /// IPv4 neighbours from the operating system's ARP table; sends nothing.
    Arp,
    /// IPv6 neighbours from the operating system's neighbour table; sends nothing.
    Nd,
    /// ICMP echo through the operating system.
    Icmp,
    /// TCP connect scan of a port list, with a TLS hint per open port.
    TcpConnect,
    /// Reverse DNS of the addresses this probe discovered.
    ReverseDns,
    /// Multicast DNS queries and listening.
    Mdns,
    /// LLMNR queries and listening.
    Llmnr,
    /// SNMPv3 polling of configured switches.
    Snmp,
    /// ARP sweep over raw sockets (not implemented yet).
    ArpSweep,
    /// TCP SYN scan over raw sockets (not implemented yet).
    TcpSyn,
    /// OS fingerprinting over raw sockets (WP3.14).
    OsFingerprint,
    /// Passive LLDP and CDP listening over raw sockets (WP3.14).
    Lldp,
    /// Passive DHCPv4 snooping over raw sockets (WP3.14).
    DhcpSnoop,
}

impl MethodKind {
    /// Every method, in scheduling order.
    pub const ALL: [MethodKind; 13] = [
        MethodKind::Arp,
        MethodKind::Nd,
        MethodKind::Icmp,
        MethodKind::Mdns,
        MethodKind::Llmnr,
        MethodKind::Snmp,
        MethodKind::TcpConnect,
        MethodKind::ReverseDns,
        MethodKind::ArpSweep,
        MethodKind::TcpSyn,
        MethodKind::OsFingerprint,
        MethodKind::Lldp,
        MethodKind::DhcpSnoop,
    ];

    /// The name in the configuration, the CLI and the source key.
    pub const fn name(self) -> &'static str {
        match self {
            MethodKind::Arp => "arp",
            MethodKind::Nd => "nd",
            MethodKind::Icmp => "icmp",
            MethodKind::TcpConnect => "tcp_connect",
            MethodKind::ReverseDns => "reverse_dns",
            MethodKind::Mdns => "mdns",
            MethodKind::Llmnr => "llmnr",
            MethodKind::Snmp => "snmp",
            MethodKind::ArpSweep => "arp_sweep",
            MethodKind::TcpSyn => "tcp_syn",
            MethodKind::OsFingerprint => "os_fingerprint",
            MethodKind::Lldp => "lldp",
            MethodKind::DhcpSnoop => "dhcp_snoop",
        }
    }

    /// The method of a name; `-` and `_` are the same.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim().to_ascii_lowercase().replace('-', "_");
        Self::ALL.into_iter().find(|kind| kind.name() == text)
    }

    /// The observation method of its batches.
    pub const fn probe_method(self) -> ProbeMethod {
        match self {
            MethodKind::Arp => ProbeMethod::Arp,
            MethodKind::Nd => ProbeMethod::Nd,
            MethodKind::Icmp => ProbeMethod::Icmp,
            MethodKind::TcpConnect => ProbeMethod::TcpConnect,
            MethodKind::ReverseDns => ProbeMethod::ReverseDns,
            MethodKind::Mdns => ProbeMethod::Mdns,
            MethodKind::Llmnr => ProbeMethod::Llmnr,
            MethodKind::Snmp => ProbeMethod::Snmp,
            MethodKind::ArpSweep => ProbeMethod::ArpSweep,
            MethodKind::TcpSyn => ProbeMethod::TcpSyn,
            MethodKind::OsFingerprint => ProbeMethod::OsFingerprint,
            MethodKind::Lldp => ProbeMethod::Lldp,
            MethodKind::DhcpSnoop => ProbeMethod::DhcpSnoop,
        }
    }

    /// Whether the method needs raw sockets (`CAP_NET_RAW` on Linux, Npcap on Windows).
    pub const fn needs_raw_sockets(self) -> bool {
        matches!(
            self,
            MethodKind::ArpSweep
                | MethodKind::TcpSyn
                | MethodKind::OsFingerprint
                | MethodKind::Lldp
                | MethodKind::DhcpSnoop
        )
    }

    /// Whether the method is active probing in the sense of TGL-18: it sends probes to
    /// every address of a prefix or to many ports. Off when `[scan] active = false`.
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            MethodKind::Icmp
                | MethodKind::TcpConnect
                | MethodKind::ArpSweep
                | MethodKind::TcpSyn
                | MethodKind::OsFingerprint
        )
    }

    /// Whether the method sends packets at all; blackout windows hold every method that
    /// does. The neighbour tables are read from the operating system and send nothing.
    pub const fn sends_packets(self) -> bool {
        !matches!(
            self,
            MethodKind::Arp | MethodKind::Nd | MethodKind::Lldp | MethodKind::DhcpSnoop
        )
    }

    /// Whether the method works on the addresses the other methods discovered, so its
    /// first run waits until they have reported once.
    pub const fn uses_known_addresses(self) -> bool {
        matches!(self, MethodKind::TcpConnect | MethodKind::ReverseDns)
    }
}

impl fmt::Display for MethodKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Whether a method can run on this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum Availability {
    /// It can run.
    Ready,
    /// It cannot run here, with the reason (missing capability, nothing configured).
    Unavailable(String),
}

impl Availability {
    /// Whether the method can run.
    pub fn is_ready(&self) -> bool {
        matches!(self, Availability::Ready)
    }
}

/// Stops a run: the kill switch, a blackout window that begins, or the shutdown of the
/// process. A sender of `true` cancels.
#[derive(Debug, Clone)]
pub struct Cancel(watch::Receiver<bool>);

impl Cancel {
    /// A cancel signal fed by `receiver`.
    pub fn new(receiver: watch::Receiver<bool>) -> Self {
        Self(receiver)
    }

    /// A signal that never fires (tests, one-shot runs without a kill switch).
    pub fn never() -> Self {
        let (sender, receiver) = watch::channel(false);
        // The receiver keeps the last value when the sender is gone.
        drop(sender);
        Self(receiver)
    }

    /// Whether the run must stop.
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves when the run must stop; never, when the sender is gone without firing.
    pub async fn cancelled(&self) {
        let mut receiver = self.0.clone();
        if receiver.wait_for(|stop| *stop).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// What a run gets from the scheduler.
#[derive(Debug, Clone)]
pub struct RunContext {
    /// The prefixes to cover: the configured scope, or a narrower target of an on-demand
    /// run inside it.
    pub scope: Arc<Scope>,
    /// Whether `scope` is narrower than the configured scope (the batch is then never
    /// complete).
    pub narrowed: bool,
    /// Addresses inside `scope` that this probe saw recently through any method, sorted.
    pub known: Vec<IpAddr>,
    /// The rate limits of the probe.
    pub pacer: Arc<Pacer>,
    /// Stops the run.
    pub cancel: Cancel,
}

/// One thing a method saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// When.
    pub at: Timestamp,
    /// What.
    pub subject: SightingSubject,
}

impl Found {
    /// A finding seen now.
    pub fn now(subject: SightingSubject) -> Self {
        Self {
            at: Timestamp::now(),
            subject,
        }
    }
}

/// What a run produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MethodOutput {
    /// The findings.
    pub found: Vec<Found>,
    /// Whether the method covered everything it was asked to cover (every target probed,
    /// every device polled, every table read).
    pub covered_all: bool,
    /// Probes sent (packets, connection attempts, queries).
    pub probes: u64,
    /// Problems worth showing in the status (a switch that did not answer), without
    /// secrets.
    pub notes: Vec<String>,
}

/// A scan method as the scheduler drives it.
#[async_trait]
pub trait Method: Send + Sync {
    /// Which method this is.
    fn kind(&self) -> MethodKind;

    /// Whether it can run on this host with this configuration.
    fn availability(&self) -> Availability;

    /// The longest a run may take before the scheduler stops it.
    fn deadline(&self) -> Duration {
        Duration::from_secs(3600)
    }

    /// Whether a run that covered everything is the method's whole picture, so that its
    /// batch may be complete. Best-effort protocols (mDNS, LLMNR) answer when they like:
    /// their batches are never complete, and their facts expire by their lifetime instead.
    fn completes(&self) -> bool {
        true
    }

    /// Runs once over `ctx.scope`.
    ///
    /// # Errors
    ///
    /// A [`ScanError`] when the method could not run at all; partial results are an
    /// output with `covered_all` false.
    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_parse_back_and_map_to_probe_methods() {
        for kind in MethodKind::ALL {
            assert_eq!(MethodKind::parse(kind.name()), Some(kind));
            let probe = serde_json::to_value(kind.probe_method()).expect("json");
            assert_eq!(probe, kind.name(), "the source key uses the same name");
            assert_eq!(
                serde_json::to_value(kind).expect("json"),
                kind.name(),
                "serde name"
            );
        }
        assert_eq!(
            MethodKind::parse("TCP-Connect"),
            Some(MethodKind::TcpConnect)
        );
        assert_eq!(MethodKind::parse("ping"), None);
    }

    #[test]
    fn raw_methods_are_flagged() {
        let raw: Vec<_> = MethodKind::ALL
            .into_iter()
            .filter(|kind| kind.needs_raw_sockets())
            .collect();
        assert_eq!(
            raw,
            [
                MethodKind::ArpSweep,
                MethodKind::TcpSyn,
                MethodKind::OsFingerprint,
                MethodKind::Lldp,
                MethodKind::DhcpSnoop
            ]
        );
        assert!(!MethodKind::Arp.sends_packets());
        assert!(MethodKind::Icmp.is_active());
        assert!(!MethodKind::Snmp.is_active());
    }

    #[tokio::test]
    async fn a_cancel_without_sender_never_fires() {
        let cancel = Cancel::never();
        assert!(!cancel.is_cancelled());
        let fired = tokio::time::timeout(Duration::from_millis(20), cancel.cancelled()).await;
        assert!(fired.is_err());
        let (sender, receiver) = watch::channel(false);
        let cancel = Cancel::new(receiver);
        sender.send(true).expect("send");
        cancel.cancelled().await;
        assert!(cancel.is_cancelled());
    }
}
