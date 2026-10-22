//! Conflict detection before an offer (plan section 2.7, P3-Q7, DHCP-06, TGL-16).
//!
//! The role asks the in-process probe through [`ConflictProbe`] before it offers an
//! address that has no lease history for the client and was not probed clean within the
//! probe cache's time: ARP where the probe sits on the address's link, ICMP echo otherwise
//! (`tenko-scan`'s `Pinger`). The DISCOVER waits in a pending table, not in a worker; the
//! OFFER goes out on [`ProbeOutcome::Clear`] or at the cap (about 300 ms,
//! `[dhcp.probe] timeout_ms`), whichever comes first. A node without the `probe` role uses
//! [`NoProbe`]: it offers without probing, logs once per start that conflict detection is
//! off and shows it in the health view (`dhcp.probe.missing`). WP8.5 builds the production
//! probe; [`MemProbe`] is the reference for tests.

use std::{
    collections::BTreeMap,
    future::Future,
    net::Ipv4Addr,
    sync::{Mutex, PoisonError},
    time::Duration,
};

/// What a probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Nobody answered within the time: the address may be offered.
    Clear,
    /// A host answered: the address is a conflict for the decline hold time, an IPAM-23
    /// observation is written and the next address is offered.
    InUse {
        /// The answering host's MAC address, when ARP gave it.
        mac: Option<[u8; 6]>,
    },
    /// No probe runs (or it cannot reach the address): offer without probing.
    Unavailable,
}

/// Probes an address before an offer.
pub trait ConflictProbe: Send + Sync {
    /// Whether a probe runs; false makes the role skip probing and report it once.
    fn available(&self) -> bool;

    /// Probes `addr`, answering within `timeout`; an implementation that does not hear
    /// back in time answers [`ProbeOutcome::Clear`].
    fn probe(&self, addr: Ipv4Addr, timeout: Duration)
    -> impl Future<Output = ProbeOutcome> + Send;
}

/// No probe on this node.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProbe;

impl ConflictProbe for NoProbe {
    fn available(&self) -> bool {
        false
    }

    fn probe(
        &self,
        _addr: Ipv4Addr,
        _timeout: Duration,
    ) -> impl Future<Output = ProbeOutcome> + Send {
        std::future::ready(ProbeOutcome::Unavailable)
    }
}

/// The reference probe: addresses marked in use answer, every other address is clear.
#[derive(Debug, Default)]
pub struct MemProbe {
    in_use: Mutex<BTreeMap<Ipv4Addr, Option<[u8; 6]>>>,
    probes: Mutex<Vec<Ipv4Addr>>,
}

impl MemProbe {
    /// Marks an address as answering, with the MAC address ARP would report.
    pub fn squat(&self, addr: Ipv4Addr, mac: Option<[u8; 6]>) {
        self.in_use
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(addr, mac);
    }

    /// The addresses probed so far, in order.
    pub fn probed(&self) -> Vec<Ipv4Addr> {
        self.probes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ConflictProbe for MemProbe {
    fn available(&self) -> bool {
        true
    }

    fn probe(
        &self,
        addr: Ipv4Addr,
        _timeout: Duration,
    ) -> impl Future<Output = ProbeOutcome> + Send {
        self.probes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(addr);
        let outcome = match self
            .in_use
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&addr)
        {
            Some(mac) => ProbeOutcome::InUse { mac: *mac },
            None => ProbeOutcome::Clear,
        };
        std::future::ready(outcome)
    }
}
