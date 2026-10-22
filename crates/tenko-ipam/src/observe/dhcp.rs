//! Leases as observations (plan section 2.8, decision P3-Q8, WP8.1): the facts of the source
//! `dhcp:<node>` ([`ObservationSource::DhcpLease`]), written by the `dhcp` role in the batch
//! of the lease change itself, with no polling and no second commit.
//!
//! # The facts of a lease
//!
//! | Subject | Fact | When |
//! |---|---|---|
//! | `address:<vrf>/<ip>` | `Observed::Address` with the lease's address and the client's MAC | the lease binds |
//! | `name:<ip>` | `Observed::Name` with the client's FQDN (option 81), else its host name (option 12) | the lease binds and the client sent a name |
//! | `address:<vrf>/<ip>` | `Observed::Address` with the MAC address that answered the conflict probe (an ARP answer), else none (ICMP, a DECLINE) | the row is `abandoned` (a conflict, WP8.5), until its hold ends |
//! | `os:<ip>` | `Observed::Os` with the guess of the lease's fingerprint (options 55, 60, 77, 81, 93) and its confidence | the lease binds and the [`LeaseClassifier`] knows the fingerprint (WP8.2) |
//! | `vendor:<mac>` | `Observed::Vendor` with the vendor class of option 60 | the lease binds, the client has a MAC address and sent a vendor class (WP8.2) |
//!
//! The guess comes from the classifier the role hands the index ([`LeaseFacts::set_classifier`],
//! the rule table of `tenko_dhcp::fingerprint`); without one no OS fact is written. A
//! fact's `last_seen` is the lease's client transaction time, its `expires_at` the end of
//! the binding as it was when the fact was written, so a binding that runs out takes its
//! facts with it without a write.
//!
//! # The rules
//!
//! The rules of [`super::ingest()`], applied to one lease change:
//!
//! - A subject without a fact gets a new one with one sighting.
//! - A known fact is written again only when its attributes changed (another MAC, another
//!   name), when it had expired, or when its refresh is due ([`ObserveConfig::refresh`]
//!   since its last sighting, or less than half of the fresh lifetime left). A renewal or a
//!   repeated request within the refresh interval writes nothing and is counted
//!   ([`FactOutcome::Unchanged`]).
//! - A sighting is counted at most once per refresh interval.
//! - A lease that no longer binds (released, declined, reclaimed by an operator) expires the
//!   current facts of its address: their `expires_at` becomes the time of the change. An
//!   expiry needs no write: the facts end with the binding.
//!
//! # The stored facts
//!
//! The rules need the stored fact, and the role builds the batch without a store read
//! (the committer runs off the DORA path but never waits on a read view). [`LeaseFacts`]
//! is therefore a derived index of the store: it keeps the facts of its source in memory,
//! built from `ipam.obs.facts` at registration and on a snapshot install, and follows every
//! change set that touches the table. The role is the only writer of its source, so its
//! writes carry no version precondition: a lease change never fails on its observation.
//! The retention purge of the reconciler deletes facts with a precondition and loses a
//! race against the role, not the other way round.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, OnceLock, PoisonError, RwLock},
};

use tenko_core::{
    MacAddr, NodeId, ObservationId, Revision, Timestamp,
    codec::encode_key,
    dhcp::{BindingState, Fingerprint, Lease},
    observe::{ObservationSource, Observed},
};
use tenko_store::{
    ChangeSet, DerivedIndex, IndexImage, KeyRange, ReadView, ReadViewExt, Store, StoreError,
    WatchFilter, WriteBatch, downcast_image,
};

use super::{
    ObserveConfig,
    ingest::{IndexRows, refresh_due},
    model::{FactSubject, ObservedFact, observed_macs, source_key},
    tables::FACTS,
};

/// Facts read per page when the index is built.
const PAGE: usize = 10_000;

/// What one lease change did to one fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactOutcome {
    /// No fact is involved: the lease does not bind and no current fact names its address
    /// (or the client sent no name).
    None,
    /// A new fact.
    New,
    /// An attribute changed (or the fact had expired): written.
    Changed,
    /// The refresh was due: written with the new sighting.
    Refreshed,
    /// Nothing changed and no refresh was due: nothing written.
    Unchanged,
    /// The lease no longer binds: the fact expired.
    Expired,
}

impl FactOutcome {
    /// Whether the outcome wrote the fact.
    pub const fn wrote(self) -> bool {
        matches!(
            self,
            FactOutcome::New | FactOutcome::Changed | FactOutcome::Refreshed | FactOutcome::Expired
        )
    }

    /// The label of the outcome (`new`, `changed`, `refreshed`, `unchanged`, `expired`), or
    /// `None` for [`FactOutcome::None`].
    pub const fn label(self) -> Option<&'static str> {
        match self {
            FactOutcome::None => None,
            FactOutcome::New => Some("new"),
            FactOutcome::Changed => Some("changed"),
            FactOutcome::Refreshed => Some("refreshed"),
            FactOutcome::Unchanged => Some("unchanged"),
            FactOutcome::Expired => Some("expired"),
        }
    }
}

/// What a lease change did to the facts of its address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseObservation {
    /// The address fact.
    pub address: FactOutcome,
    /// The name fact.
    pub name: FactOutcome,
    /// The OS fact (the fingerprint's guess, WP8.2).
    pub os: FactOutcome,
    /// The vendor fact (option 60, WP8.2).
    pub vendor: FactOutcome,
    /// The time to record as the lease row's `observed_at` when a fact was written.
    pub observed_at: Option<Timestamp>,
}

impl LeaseObservation {
    /// Whether the change wrote a fact.
    pub const fn wrote(&self) -> bool {
        self.address.wrote() || self.name.wrote() || self.os.wrote() || self.vendor.wrote()
    }
}

/// An OS guess for a lease's fingerprint (DHCP-14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsReading {
    /// The guess as a person reads it, such as `Windows 10 or 11`.
    pub guess: String,
    /// How strong the match is, 0 to 100.
    pub confidence: u8,
}

/// Maps a lease's fingerprint to an OS guess: the rule table of `tenko_dhcp::fingerprint`
/// (P3-Q15), handed to [`LeaseFacts::set_classifier`] by the role. Runs on the commit side.
pub trait LeaseClassifier: Send + Sync {
    /// The guess, or `None` when no rule knows the fingerprint.
    fn os(&self, fingerprint: &Fingerprint) -> Option<OsReading>;
}

/// The vendor class a lease reports (option 60), without surrounding blanks; `None` when
/// the client sent none or only blanks.
pub fn lease_vendor(lease: &Lease) -> Option<String> {
    lease
        .fingerprint
        .as_ref()
        .and_then(|fingerprint| fingerprint.vendor_class.as_deref())
        .map(str::trim)
        .filter(|vendor| !vendor.is_empty())
        .map(str::to_owned)
}

/// The client's MAC address, when its hardware type is Ethernet.
pub fn lease_mac(lease: &Lease) -> Option<MacAddr> {
    lease.client.mac().map(MacAddr::new)
}

/// The name a lease reports: the FQDN of option 81, else the host name of option 12,
/// without a trailing dot; `None` when the client sent neither or only blanks.
pub fn lease_name(lease: &Lease) -> Option<String> {
    [lease.fqdn.as_deref(), lease.hostname.as_deref()]
        .into_iter()
        .flatten()
        .map(|name| name.trim().trim_end_matches('.'))
        .find(|name| !name.is_empty())
        .map(str::to_owned)
}

/// The image of the index: the facts of the source by subject key.
struct Image {
    revision: Revision,
    facts: HashMap<String, ObservedFact>,
}

impl IndexImage for Image {
    fn revision(&self) -> Revision {
        self.revision
    }

    fn memory_bytes(&self) -> usize {
        self.facts.len() * 320
    }
}

/// The lease facts of one DHCP node: the rules of the module documentation over the facts
/// of its source, kept as a derived index of the store.
pub struct LeaseFacts {
    source: ObservationSource,
    source_key: String,
    config: ObserveConfig,
    image: RwLock<Image>,
    classifier: OnceLock<Arc<dyn LeaseClassifier>>,
}

impl std::fmt::Debug for LeaseFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseFacts")
            .field("source", &self.source_key)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The fact a binding lease asks for.
struct Wanted {
    observed: Observed,
    seen: Timestamp,
    expires: Timestamp,
}

impl LeaseFacts {
    /// The facts of the node `node` under `config`; [`LeaseFacts::register`] fills them.
    pub fn new(node: NodeId, config: ObserveConfig) -> Arc<Self> {
        let source = ObservationSource::DhcpLease { node };
        Arc::new(Self {
            source_key: source_key(&source),
            source,
            config,
            image: RwLock::new(Image {
                revision: Revision::ZERO,
                facts: HashMap::new(),
            }),
            classifier: OnceLock::new(),
        })
    }

    /// Sets the classifier of the fingerprints, once (later calls change nothing); `true`
    /// when this call set it.
    pub fn set_classifier(&self, classifier: Arc<dyn LeaseClassifier>) -> bool {
        self.classifier.set(classifier).is_ok()
    }

    /// Registers the index with `store`, which builds it from the stored facts.
    ///
    /// # Errors
    ///
    /// The store's error when the facts cannot be read.
    pub fn register(self: &Arc<Self>, store: &dyn Store) -> Result<(), StoreError> {
        store.register_index(Arc::clone(self) as Arc<dyn DerivedIndex>)
    }

    /// The source, `dhcp:<node>`.
    pub fn source(&self) -> &ObservationSource {
        &self.source
    }

    /// The stored fact of a subject, as the index holds it.
    pub fn fact(&self, subject: &FactSubject) -> Option<ObservedFact> {
        self.image
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .facts
            .get(&subject.key())
            .cloned()
    }

    /// The number of facts the index holds.
    pub fn len(&self) -> usize {
        self.image
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .facts
            .len()
    }

    /// Whether the index holds no fact.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Adds the facts of `lease` (the row after the change) to `batch` by the rules of the
    /// module documentation, at `now`, against the stored facts of its address.
    ///
    /// # Errors
    ///
    /// A fact that does not encode.
    pub fn observe(
        &self,
        lease: &Lease,
        now: Timestamp,
        batch: &mut WriteBatch,
    ) -> Result<LeaseObservation, StoreError> {
        let ip = IpAddr::V4(lease.addr);
        // A conflict (a probe answer or a DECLINE, WP8.5) is an `abandoned` row: its
        // address fact names the answering MAC address (an ARP answer stores it as the
        // row's `chaddr` with hardware type 1), or none (ICMP, a DECLINE), until the hold
        // ends. It replaces the decliner's lease fact; the name fact ends.
        let conflict = lease.state == BindingState::Abandoned && lease.ends > now;
        let bound = lease.is_bound(now);
        let address = Observed::Address {
            vrf: lease.vrf,
            ip,
            mac: lease_mac(lease),
        };
        let name = lease_name(lease).map(|name| Observed::Name { ip, name });
        let wanted = |observed: Observed| Wanted {
            observed,
            seen: lease.cltt.min(now),
            expires: lease.ends,
        };
        // WP8.2: the fingerprint's guess and the vendor class, while the lease binds.
        let os = self
            .classifier
            .get()
            .zip(lease.fingerprint.as_ref())
            .and_then(|(classifier, fingerprint)| classifier.os(fingerprint))
            .filter(|reading| !reading.guess.trim().is_empty())
            .map(|reading| Observed::Os {
                ip,
                guess: reading.guess,
                confidence: reading.confidence.min(100),
            });
        let mac = lease_mac(lease);
        let vendor = mac
            .zip(lease_vendor(lease))
            .map(|(mac, vendor)| Observed::Vendor { mac, vendor });
        let address_subject = FactSubject::of(&address);
        let name_subject = FactSubject::Name { ip };
        let os_subject = FactSubject::Os { ip };
        let vendor_subject = mac.map(|mac| FactSubject::Vendor { mac });
        let image = self.image.read().unwrap_or_else(PoisonError::into_inner);
        let stored_address = image.facts.get(&address_subject.key()).cloned();
        let stored_name = image.facts.get(&name_subject.key()).cloned();
        let stored_os = image.facts.get(&os_subject.key()).cloned();
        let stored_vendor = vendor_subject
            .as_ref()
            .and_then(|subject| image.facts.get(&subject.key()).cloned());
        drop(image);
        let address = self.apply(
            &address_subject,
            stored_address.as_ref(),
            (bound || conflict).then(|| wanted(address)),
            now,
            batch,
        )?;
        let name = self.apply(
            &name_subject,
            stored_name.as_ref(),
            name.filter(|_| bound).map(wanted),
            now,
            batch,
        )?;
        let os = self.apply(
            &os_subject,
            stored_os.as_ref(),
            os.filter(|_| bound).map(wanted),
            now,
            batch,
        )?;
        let vendor = match &vendor_subject {
            Some(subject) => self.apply(
                subject,
                stored_vendor.as_ref(),
                vendor.filter(|_| bound).map(wanted),
                now,
                batch,
            )?,
            None => FactOutcome::None,
        };
        // The row records when its facts were last written.
        let wrote = address.wrote() || name.wrote() || os.wrote() || vendor.wrote();
        let observed_at = wrote.then_some(if bound || conflict {
            lease.cltt.min(now)
        } else {
            now
        });
        Ok(LeaseObservation {
            address,
            name,
            os,
            vendor,
            observed_at,
        })
    }

    /// One fact: the write the rules ask for, and what it was.
    fn apply(
        &self,
        subject: &FactSubject,
        stored: Option<&ObservedFact>,
        wanted: Option<Wanted>,
        now: Timestamp,
        batch: &mut WriteBatch,
    ) -> Result<FactOutcome, StoreError> {
        let subject_key = subject.key();
        let key = (self.source_key.clone(), subject_key.clone());
        let Some(wanted) = wanted else {
            // The lease does not bind (or sent no name): a current fact expires.
            let Some(old) = stored.filter(|fact| fact.is_current(now)) else {
                return Ok(FactOutcome::None);
            };
            let mut fact = old.clone();
            fact.expires_at = Some(now);
            fact.received_at = now;
            fact.revision = Revision::ZERO;
            batch.put_typed(&FACTS, &key, &fact)?;
            return Ok(FactOutcome::Expired);
        };
        let rows = IndexRows::of(&wanted.observed);
        let Some(old) = stored else {
            let fact = ObservedFact {
                source: self.source.clone(),
                source_key: self.source_key.clone(),
                subject: subject.clone(),
                subject_key: subject_key.clone(),
                observed: wanted.observed,
                observation: ObservationId::generate(),
                first_seen: wanted.seen,
                last_seen: wanted.seen,
                received_at: now,
                expires_at: Some(wanted.expires),
                sightings: 1,
                counted_at: Some(wanted.seen),
                revision: Revision::ZERO,
            };
            batch.put_typed(&FACTS, &key, &fact)?;
            index(
                &rows,
                &IndexRows::default(),
                &self.source_key,
                &subject_key,
                batch,
            )?;
            return Ok(FactOutcome::New);
        };
        let changed = old.observed != wanted.observed;
        let revived = !old.is_current(now);
        let due = refresh_due(
            old,
            wanted.seen,
            now,
            Some(wanted.expires),
            self.config.refresh,
        );
        if !(changed || revived || due) {
            return Ok(FactOutcome::Unchanged);
        }
        // Another client on the address is another device: its fact starts again. Otherwise
        // ingest's rules: the sighting counts once per refresh interval, or after a gap.
        let other_device = observed_macs(&old.observed) != observed_macs(&wanted.observed);
        let counted_since = old.counted_at.unwrap_or(old.first_seen);
        let counts = revived || wanted.seen.saturating_since(counted_since) >= self.config.refresh;
        let before = IndexRows::of(&old.observed);
        let mut fact = old.clone();
        fact.observed = wanted.observed;
        if changed {
            fact.observation = ObservationId::generate();
        }
        if other_device {
            fact.first_seen = wanted.seen;
            fact.last_seen = wanted.seen;
            fact.sightings = 1;
            fact.counted_at = Some(wanted.seen);
        } else {
            fact.first_seen = fact.first_seen.min(wanted.seen);
            fact.last_seen = fact.last_seen.max(wanted.seen);
            if counts {
                fact.sightings = fact.sightings.saturating_add(1);
                fact.counted_at = Some(wanted.seen);
            }
        }
        fact.received_at = now;
        fact.expires_at = Some(wanted.expires);
        fact.revision = Revision::ZERO;
        batch.put_typed(&FACTS, &key, &fact)?;
        index(&rows, &before, &self.source_key, &subject_key, batch)?;
        Ok(if changed || revived {
            FactOutcome::Changed
        } else {
            FactOutcome::Refreshed
        })
    }

    fn build_image(&self, view: &dyn ReadView) -> Result<Image, StoreError> {
        let prefix = encode_key(&(self.source_key.clone(),));
        let mut range = KeyRange::prefix(prefix.clone());
        let mut facts = HashMap::new();
        loop {
            let rows = view.scan_typed(&FACTS, range.clone(), PAGE, false)?;
            let full = rows.len() == PAGE;
            let mut last = None;
            for ((source, subject), mut fact, revision) in rows {
                fact.revision = revision;
                last = Some(FACTS.key(&(source, subject.clone())));
                facts.insert(subject, fact);
            }
            match (full, last) {
                (true, Some(last)) => range = KeyRange::prefix(prefix.clone()).after(last),
                _ => break,
            }
        }
        Ok(Image {
            revision: view.revision(),
            facts,
        })
    }
}

/// The index rows of a fact write, with the error of the IPAM rows as a store error.
fn index(
    rows: &IndexRows,
    before: &IndexRows,
    source: &str,
    subject: &str,
    batch: &mut WriteBatch,
) -> Result<(), StoreError> {
    rows.write(before, source, subject, batch)
        .map_err(|error| StoreError::Codec(error.to_string()))
}

impl DerivedIndex for LeaseFacts {
    fn name(&self) -> &'static str {
        "ipam.obs.dhcp"
    }

    fn filter(&self) -> WatchFilter {
        WatchFilter::tables([FACTS.name().clone()])
    }

    fn build(&self, view: &dyn ReadView) -> Result<Box<dyn IndexImage>, StoreError> {
        Ok(Box::new(self.build_image(view)?))
    }

    fn install(&self, image: Box<dyn IndexImage>) {
        if let Some(image) = downcast_image::<Image>(image) {
            *self.image.write().unwrap_or_else(PoisonError::into_inner) = *image;
        }
    }

    fn apply(&self, changes: &ChangeSet, view: &dyn ReadView) {
        let prefix = encode_key(&(self.source_key.clone(),));
        let mut image = self.image.write().unwrap_or_else(PoisonError::into_inner);
        image.revision = changes.revision;
        for change in &changes.changes {
            if change.table != *FACTS.name() || !change.key.starts_with(&prefix) {
                continue;
            }
            let Ok((source, subject)) = FACTS.decode_key(&change.key) else {
                continue;
            };
            if source != self.source_key {
                continue;
            }
            if change.deleted {
                image.facts.remove(&subject);
                continue;
            }
            match view.get_typed(&FACTS, &(source, subject.clone())) {
                Ok(Some((mut fact, revision))) => {
                    fact.revision = revision;
                    image.facts.insert(subject, fact);
                }
                Ok(None) => {
                    image.facts.remove(&subject);
                }
                Err(error) => {
                    tracing::warn!(%error, %subject, "a lease fact could not be read into the index");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
