//! Where the readers of the observation layer take their facts from (ADR 0031): the stored
//! facts of `ipam.obs.facts` for the sources that write them (probes, connectors, the zones'
//! records) and the lease view ([`LeaseFacts`]) for the sources `dhcp:<node>`, behind one
//! trait, [`FactSource`], and joined by [`Observations`].
//!
//! The reconciler's rules, the move step, the reconciliation view, the findings, the
//! observation API and the topology read through [`Observations`]; none of them reads
//! `ipam.obs.facts` or its index tables directly. A stored fact of a source `dhcp:<node>`
//! (written by a version before ADR 0031) is never read: the lease view stands for it, and
//! the retention purge deletes it once its last sighting is older than the retention.

use std::net::IpAddr;

use ipnet::IpNet;
use tenko_core::{Timestamp, codec::encode_key};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use super::{
    dhcp::{LeaseFacts, Naming},
    model::ObservedFact,
    tables::{BY_IP, BY_MAC, BY_NAME, FACTS},
};
use crate::{error::IpamResult, net::contains_ip};

/// The prefix of the source keys of the lease view, whose stored facts are not read.
pub const LEASE_SOURCE_PREFIX: &str = "dhcp:";

/// Whether a source key is one of the lease view (`dhcp:<node>`).
pub fn is_lease_source(source_key: &str) -> bool {
    source_key.starts_with(LEASE_SOURCE_PREFIX)
}

/// A source of facts for the readers of a view (ADR 0031): the stored facts, or the lease
/// view.
pub trait FactSource {
    /// Every fact, current or not, at `now`.
    ///
    /// # Errors
    ///
    /// Store and decoding errors.
    fn facts(&self, view: &dyn ReadView, now: Timestamp) -> IpamResult<Vec<ObservedFact>>;

    /// The facts that name a MAC address, an IP address or a name: "the current facts of a
    /// subject" are those of them that are current at `now`.
    ///
    /// # Errors
    ///
    /// Store and decoding errors.
    fn facts_naming(
        &self,
        view: &dyn ReadView,
        naming: &Naming,
        now: Timestamp,
    ) -> IpamResult<Vec<ObservedFact>>;

    /// The facts that name an IP address inside `net`.
    ///
    /// # Errors
    ///
    /// Store and decoding errors.
    fn facts_within(
        &self,
        view: &dyn ReadView,
        net: &IpNet,
        now: Timestamp,
    ) -> IpamResult<Vec<ObservedFact>> {
        Ok(self
            .facts(view, now)?
            .into_iter()
            .filter(|fact| fact.ips().iter().any(|ip| contains_ip(net, *ip)))
            .collect())
    }
}

/// The stored facts of `ipam.obs.facts`, without those of the lease sources.
#[derive(Debug, Clone, Copy, Default)]
pub struct StoredFacts;

impl FactSource for StoredFacts {
    fn facts(&self, view: &dyn ReadView, _now: Timestamp) -> IpamResult<Vec<ObservedFact>> {
        Ok(view
            .scan_typed(&FACTS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .filter(|((source, _), _, _)| !is_lease_source(source))
            .map(|(_, mut fact, revision)| {
                fact.revision = revision;
                fact
            })
            .collect())
    }

    fn facts_naming(
        &self,
        view: &dyn ReadView,
        naming: &Naming,
        _now: Timestamp,
    ) -> IpamResult<Vec<ObservedFact>> {
        let keys: Vec<(String, String)> = match naming {
            Naming::Mac(mac) => view
                .scan_typed(
                    &BY_MAC,
                    KeyRange::prefix(encode_key(&(*mac,))),
                    usize::MAX,
                    false,
                )?
                .into_iter()
                .map(|((_, source, subject), (), _)| (source, subject))
                .collect(),
            Naming::Ip(ip) => view
                .scan_typed(
                    &BY_IP,
                    KeyRange::prefix(encode_key(&(*ip,))),
                    usize::MAX,
                    false,
                )?
                .into_iter()
                .map(|((_, source, subject), (), _)| (source, subject))
                .collect(),
            Naming::Name(name) => view
                .scan_typed(
                    &BY_NAME,
                    KeyRange::prefix(encode_key(&(name.trim().to_ascii_lowercase(),))),
                    usize::MAX,
                    false,
                )?
                .into_iter()
                .map(|((_, source, subject), (), _)| (source, subject))
                .collect(),
        };
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            if is_lease_source(&key.0) {
                continue;
            }
            if let Some((mut fact, revision)) = view.get_typed(&FACTS, &key)? {
                fact.revision = revision;
                out.push(fact);
            }
        }
        out.sort_by(|a, b| (&a.source_key, &a.subject_key).cmp(&(&b.source_key, &b.subject_key)));
        out.dedup_by(|a, b| a.source_key == b.source_key && a.subject_key == b.subject_key);
        Ok(out)
    }
}

impl FactSource for LeaseFacts {
    fn facts(&self, view: &dyn ReadView, now: Timestamp) -> IpamResult<Vec<ObservedFact>> {
        self.ensure(view)?;
        Ok(LeaseFacts::facts(self, now))
    }

    fn facts_naming(
        &self,
        view: &dyn ReadView,
        naming: &Naming,
        now: Timestamp,
    ) -> IpamResult<Vec<ObservedFact>> {
        self.ensure(view)?;
        Ok(LeaseFacts::facts_naming(self, naming, now))
    }
}

/// The facts a reader of one view sees: the stored facts of `view` and, when given, the
/// lease view (a reader without one, such as the probes' baseline, sees no lease facts).
#[derive(Clone, Copy)]
pub struct Observations<'a> {
    view: &'a dyn ReadView,
    leases: Option<&'a LeaseFacts>,
}

impl std::fmt::Debug for Observations<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observations")
            .field("revision", &self.view.revision())
            .field("leases", &self.leases.map(LeaseFacts::revision))
            .finish()
    }
}

impl<'a> Observations<'a> {
    /// The facts of `view` with those of `leases`.
    pub fn new(view: &'a dyn ReadView, leases: Option<&'a LeaseFacts>) -> Self {
        Self { view, leases }
    }

    /// The read view.
    pub fn view(&self) -> &'a dyn ReadView {
        self.view
    }

    /// The lease view, if the reader has one.
    pub fn leases(&self) -> Option<&'a LeaseFacts> {
        self.leases
    }

    fn sources(&self) -> impl Iterator<Item = &'a dyn FactSource> {
        [
            Some(&StoredFacts as &dyn FactSource),
            self.leases.map(|leases| leases as &dyn FactSource),
        ]
        .into_iter()
        .flatten()
    }

    /// Every fact of every source, current or not, at `now`.
    ///
    /// # Errors
    ///
    /// Store and decoding errors.
    pub fn facts(&self, now: Timestamp) -> IpamResult<Vec<ObservedFact>> {
        let mut out = Vec::new();
        for source in self.sources() {
            out.extend(source.facts(self.view, now)?);
        }
        Ok(out)
    }

    /// The facts of every source that name `naming`.
    ///
    /// # Errors
    ///
    /// Store and decoding errors.
    pub fn facts_naming(&self, naming: &Naming, now: Timestamp) -> IpamResult<Vec<ObservedFact>> {
        let mut out = Vec::new();
        for source in self.sources() {
            out.extend(source.facts_naming(self.view, naming, now)?);
        }
        Ok(out)
    }

    /// The facts of every source that name an address inside `net`.
    ///
    /// # Errors
    ///
    /// Store and decoding errors.
    pub fn facts_within(&self, net: &IpNet, now: Timestamp) -> IpamResult<Vec<ObservedFact>> {
        let mut out = Vec::new();
        for source in self.sources() {
            out.extend(source.facts_within(self.view, net, now)?);
        }
        Ok(out)
    }

    /// The current facts of every source that name the address `ip`.
    ///
    /// # Errors
    ///
    /// Store and decoding errors.
    pub fn current_at(&self, ip: IpAddr, now: Timestamp) -> IpamResult<Vec<ObservedFact>> {
        Ok(self
            .facts_naming(&Naming::Ip(ip), now)?
            .into_iter()
            .filter(|fact| fact.is_current(now))
            .collect())
    }
}
