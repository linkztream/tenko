//! The addresses this probe saw recently, by the methods that saw them. `tcp_connect`,
//! `reverse_dns` and the unicast queries of `mdns` and `llmnr` work on them, so a probe
//! only probes deeper what answered before. The set is kept on disk, so a restarted probe
//! does not start from nothing.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::Path,
};

use serde::{Deserialize, Serialize};
use tenko_cluster::probe::SightingSubject;
use tenko_core::Timestamp;

use crate::{error::ScanError, method::MethodKind};

/// Most addresses kept.
const MAX_ADDRESSES: usize = 65_536;

/// The known addresses: per address, the methods that saw it and until when that counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownAddresses {
    addresses: BTreeMap<IpAddr, BTreeMap<MethodKind, Timestamp>>,
}

impl KnownAddresses {
    /// Records the presence sightings of one run of `kind`: every address sighting (and
    /// every address with open ports) counts until `until`. A complete run drops what the
    /// method saw before and no longer sees.
    pub fn record<'a>(
        &mut self,
        kind: MethodKind,
        subjects: impl IntoIterator<Item = &'a SightingSubject>,
        complete: bool,
        until: Timestamp,
    ) {
        let seen: BTreeSet<IpAddr> = subjects
            .into_iter()
            .filter_map(|subject| match subject {
                SightingSubject::Address { ip, .. } | SightingSubject::Services { ip, .. } => {
                    Some(*ip)
                }
                _ => None,
            })
            .collect();
        if complete {
            for (ip, methods) in &mut self.addresses {
                if !seen.contains(ip) {
                    methods.remove(&kind);
                }
            }
        }
        for ip in seen {
            if self.addresses.len() >= MAX_ADDRESSES && !self.addresses.contains_key(&ip) {
                break;
            }
            self.addresses.entry(ip).or_default().insert(kind, until);
        }
        self.addresses.retain(|_, methods| !methods.is_empty());
    }

    /// Drops what expired before `now`.
    pub fn prune(&mut self, now: Timestamp) {
        for methods in self.addresses.values_mut() {
            methods.retain(|_, until| *until > now);
        }
        self.addresses.retain(|_, methods| !methods.is_empty());
    }

    /// The addresses that count at `now`, sorted.
    pub fn current(&self, now: Timestamp) -> Vec<IpAddr> {
        self.addresses
            .iter()
            .filter(|(_, methods)| methods.values().any(|until| *until > now))
            .map(|(ip, _)| *ip)
            .collect()
    }

    /// Number of addresses kept.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Whether no address is kept.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Reads the set from `path`; an absent or unreadable file is an empty set.
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Writes the set to `path` atomically.
    ///
    /// # Errors
    ///
    /// `scan.io` when the file cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), ScanError> {
        let bytes = serde_json::to_vec(self).map_err(|error| ScanError::io(error.to_string()))?;
        crate::status::write_atomically(path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        text.parse().expect("time")
    }

    fn address(text: &str) -> SightingSubject {
        SightingSubject::Address {
            ip: text.parse().expect("ip"),
            mac: None,
        }
    }

    #[test]
    fn complete_runs_drop_what_their_method_no_longer_sees() {
        let mut known = KnownAddresses::default();
        let until = at("2026-10-10T12:00:00Z");
        known.record(
            MethodKind::Arp,
            &[address("192.0.2.1"), address("192.0.2.2")],
            true,
            until,
        );
        known.record(MethodKind::Icmp, &[address("192.0.2.2")], true, until);
        known.record(MethodKind::Arp, &[address("192.0.2.3")], true, until);
        let now = at("2026-10-10T11:00:00Z");
        let ips: Vec<String> = known.current(now).iter().map(ToString::to_string).collect();
        assert_eq!(ips, ["192.0.2.2", "192.0.2.3"], "ICMP still sees .2");
        // A partial run only adds.
        known.record(MethodKind::Arp, &[address("192.0.2.9")], false, until);
        assert_eq!(known.len(), 3);
        // Name facts are not presence.
        known.record(
            MethodKind::ReverseDns,
            &[SightingSubject::Name {
                ip: "192.0.2.50".parse().expect("ip"),
                name: "host.example.net".to_owned(),
            }],
            true,
            until,
        );
        assert_eq!(known.len(), 3);
        assert_eq!(
            known.current(at("2026-10-10T12:00:01Z")),
            Vec::<IpAddr>::new()
        );
        known.prune(at("2026-10-10T12:00:01Z"));
        assert!(known.is_empty());
    }

    #[test]
    fn the_set_survives_a_restart() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("known.json");
        let mut known = KnownAddresses::default();
        known.record(
            MethodKind::Nd,
            &[address("2001:db8::7")],
            true,
            at("2026-10-10T12:00:00Z"),
        );
        known.save(&path).expect("save");
        assert_eq!(KnownAddresses::load(&path), known);
        assert!(KnownAddresses::load(&dir.path().join("missing.json")).is_empty());
    }
}
