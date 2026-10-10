//! The accumulator behind [`mdns::interpret`](super::mdns::interpret) and
//! [`llmnr::interpret`](super::llmnr::interpret).
//!
//! It keeps one rule in one place: every address that has a name, a port or an operating
//! system guess is also in `addresses`, no unusable address gets in, and nothing grows beyond
//! the bounds below, whatever a responder sends.

use std::net::IpAddr;

use super::NameFindings;

/// The most addresses one message can contribute.
pub(super) const MAX_ADDRESSES: usize = 256;
/// The most service ports kept per address.
const MAX_PORTS_PER_ADDRESS: usize = 64;

/// An address a host can have: not unspecified, not loopback, not multicast and not the IPv4
/// broadcast address.
pub(super) fn usable_address(ip: IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_broadcast(),
        IpAddr::V6(_) => true,
    }
}

/// True for a name that only exists to look up an address (`*.arpa`).
fn is_reverse_zone(name: &str) -> bool {
    name == "arpa"
        || name
            .rsplit_once('.')
            .is_some_and(|(_, last)| last == "arpa")
}

/// Collects the findings of one message.
#[derive(Debug, Default)]
pub(super) struct Collector {
    findings: NameFindings,
}

impl Collector {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Admits the address a message came from. The sender of a datagram is a real peer even on
    /// loopback, so only addresses that cannot send (unspecified, multicast) are refused.
    pub(super) fn admit_source(&mut self, source: IpAddr) -> bool {
        if source.is_unspecified() || source.is_multicast() {
            return false;
        }
        self.findings.addresses.len() < MAX_ADDRESSES && {
            self.findings.addresses.insert(source);
            true
        }
    }

    /// Admits an address named in a record. True when the address is (now) part of the
    /// findings.
    pub(super) fn admit(&mut self, ip: IpAddr) -> bool {
        if self.findings.addresses.contains(&ip) {
            return true;
        }
        if !usable_address(ip) || self.findings.addresses.len() >= MAX_ADDRESSES {
            return false;
        }
        self.findings.addresses.insert(ip);
        true
    }

    /// The name recorded for an address so far.
    pub(super) fn name_of(&self, ip: IpAddr) -> Option<&str> {
        self.findings.names.get(&ip).map(String::as_str)
    }

    /// Records the name of an address. The first name wins, except that a name under `arpa`
    /// gives way to any other name.
    pub(super) fn set_name(&mut self, ip: IpAddr, name: &str) {
        if name.is_empty() || !self.admit(ip) {
            return;
        }
        match self.findings.names.get_mut(&ip) {
            None => {
                self.findings.names.insert(ip, name.to_string());
            }
            Some(existing) => {
                if is_reverse_zone(existing) && !is_reverse_zone(name) {
                    *existing = name.to_string();
                }
            }
        }
    }

    /// Records a TCP port of an address.
    pub(super) fn add_port(&mut self, ip: IpAddr, port: u16) {
        if port == 0 || !self.admit(ip) {
            return;
        }
        let ports = self.findings.services.entry(ip).or_default();
        if ports.len() < MAX_PORTS_PER_ADDRESS || ports.contains(&port) {
            ports.insert(port);
        }
    }

    /// Records an operating system guess. A guess with a higher confidence replaces a lower
    /// one; on a tie the first guess stays.
    pub(super) fn set_os(&mut self, ip: IpAddr, os: &str, confidence: u8) {
        if os.is_empty() || !self.admit(ip) {
            return;
        }
        match self.findings.os.get_mut(&ip) {
            None => {
                self.findings.os.insert(ip, (os.to_string(), confidence));
            }
            Some(existing) => {
                if existing.1 < confidence {
                    *existing = (os.to_string(), confidence);
                }
            }
        }
    }

    pub(super) fn finish(self) -> NameFindings {
        self.findings
    }
}
