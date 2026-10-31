//! What a change set means to the reconciler: whether it schedules a run, whether the run
//! evaluates the rules, and whether it changed what the DNS steps read (the zones' records
//! and the planner's inputs).
//!
//! The reconciler watches the intent tables, the adoption policies, the facts, the reverse
//! templates and the DNS zones and records. Four kinds of change set pass by:
//!
//! - **DHCP's names only.** A change set whose watched rows are all RRsets of the origin
//!   `dhcp` (the DDNS worker's A, AAAA, DHCID and PTR sets, with the SOA serial step of
//!   the same batch) schedules nothing: the zones' observations take `ipam` and `manual`
//!   records only ([`crate::observe::dns`]), the leases are read through the lease view (ADR
//!   0031), and the DNS planner writes `ipam` sets only. A deleted RRset
//!   cannot be read any more, so a deletion counts as DHCP's when the DHCP role
//!   (`system:dhcp`) wrote the change set, the only writer of `dhcp` sets.
//! - **Lease facts only.** Stored facts of the sources `dhcp:<node>` are no longer written
//!   (ADR 0031: the lease tables are the source; the purge of rows of earlier versions still
//!   passes here). A lease change does not pass this signal at all: the lease view wakes the
//!   loop after it took the change in (up to a thousand change sets a second), for a
//!   light run: the move jobs that wait for a device are confirmed, the rules wait for the
//!   next periodic run (or a change of another kind), so a busy DHCP server does not make
//!   the leader evaluate every fact every few seconds.
//! - **Other facts.** An ingest (a probe, a connector, the zones' records) schedules a run
//!   of the rules, but the zones and the planner's inputs are as they were: the run takes
//!   the zones' facts and the DNS findings of the last run that read them instead of
//!   reading every zone again.
//! - **Everything else.** An RRset of any other origin (a hand-written or an `ipam` set in
//!   the same change set as DHCP's included), a zone, the intent, a reverse template or an
//!   adoption policy schedules a run of the rules, and the DNS steps read the zones again
//!   (the plan alone for the intent and the templates).
//!
//! The SOA set and the signer's rows (`dnssec` origin) are neither: no step of the
//! reconciler reads them. The periodic run always does the full pass, so a change the
//! classification leaves out (a DHCP name that took over a record of another origin under
//! `replace`) is seen within the run interval.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use tenko_core::{
    Principal, Revision, SystemComponent,
    dns::{Origin, Rtype, tables::RRSETS},
};
use tenko_store::{
    ChangeSet, DerivedIndex, IndexImage, ReadView, ReadViewExt, StoreError, WatchFilter,
};
use tokio::sync::Notify;

use super::names::{NAME_AUTHORITY, NAME_CHOICES};
use crate::{dns::REVERSE_TEMPLATES, observe::tables::FACTS, proposals::model::ADOPTION, tables};

/// What one change set means to the reconciler.
#[allow(
    clippy::struct_excessive_bools,
    reason = "four independent consequences of one change set, joined field by field"
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Relevance {
    /// The change set schedules a run.
    pub run: bool,
    /// The run evaluates the rules (else it only confirms waiting moves).
    pub rules: bool,
    /// The zones' `ipam` and `manual` records may have changed: the run ingests the zones
    /// again.
    pub records: bool,
    /// The DNS planner's inputs may have changed (the records, the zones, the intent, the
    /// reverse templates): the run plans again.
    pub plan: bool,
}

impl Relevance {
    fn join(&mut self, other: Relevance) {
        self.run |= other.run;
        self.rules |= other.rules;
        self.records |= other.records;
        self.plan |= other.plan;
    }

    pub(crate) const EVERYTHING: Relevance = Relevance {
        run: true,
        rules: true,
        records: true,
        plan: true,
    };

    /// A run of the rules that reads no zone.
    const RULES: Relevance = Relevance {
        run: true,
        rules: true,
        records: false,
        plan: false,
    };

    /// A run of the rules with a new DNS plan.
    const PLAN: Relevance = Relevance {
        run: true,
        rules: true,
        records: false,
        plan: true,
    };

    /// A light run: waiting moves only.
    const LIGHT: Relevance = Relevance {
        run: true,
        rules: false,
        records: false,
        plan: false,
    };
}

/// Whether an RRset of `rtype` and `origin` matters to the reconciler.
fn rrset_matters(rtype: Rtype, origin: Option<Origin>) -> bool {
    if rtype == Rtype::SOA {
        return false;
    }
    !matches!(origin, Some(Origin::Dhcp | Origin::Dnssec))
}

/// Whether a fact's key is of a source `dhcp:<node>` (a lease fact).
fn lease_fact(key: &[u8]) -> bool {
    FACTS
        .decode_key(key)
        .is_ok_and(|(source, _)| source.starts_with("dhcp:"))
}

/// Classifies one change set against the view it produced.
pub(crate) fn classify(changes: &ChangeSet, view: &dyn ReadView) -> Relevance {
    let by_dhcp = matches!(
        changes.principal,
        Principal::System {
            component: SystemComponent::Dhcp,
            ..
        }
    );
    let rrsets = RRSETS.name();
    let mut out = Relevance::default();
    for change in &changes.changes {
        if change.table == *FACTS.name() {
            out.join(if lease_fact(&change.key) {
                Relevance::LIGHT
            } else {
                Relevance::RULES
            });
        } else if change.table == *rrsets {
            let Ok(key) = RRSETS.decode_key(&change.key) else {
                out.join(Relevance::EVERYTHING);
                continue;
            };
            let origin = if change.deleted {
                by_dhcp.then_some(Origin::Dhcp)
            } else {
                match view.get_typed(&RRSETS, &key) {
                    Ok(Some((rrset, _))) => Some(rrset.origin),
                    // Gone again, or unreadable: count it.
                    _ => None,
                }
            };
            if rrset_matters(key.rtype, origin) {
                out.join(Relevance::EVERYTHING);
            }
        } else if change.table == *ADOPTION.name()
            || change.table == *NAME_AUTHORITY.name()
            || change.table == *NAME_CHOICES.name()
        {
            out.join(Relevance::RULES);
        } else if change.table == *tenko_core::dns::tables::ZONES.name() {
            out.join(Relevance::EVERYTHING);
        } else {
            // The intent tables and the reverse templates.
            out.join(Relevance::PLAN);
        }
        if out == Relevance::EVERYTHING {
            break;
        }
    }
    out
}

/// The change counters a run compares with those of the run before it.
#[derive(Debug, Default)]
pub(crate) struct Epochs {
    /// Bumped by every change set that needs the rules evaluated.
    pub rules: AtomicU64,
    /// Bumped by every change set that may have changed the zones' records.
    pub records: AtomicU64,
    /// Bumped by every change set that may have changed the DNS planner's inputs.
    pub plan: AtomicU64,
}

impl Epochs {
    /// The counters now: (rules, records, plan).
    pub(crate) fn now(&self) -> (u64, u64, u64) {
        (
            self.rules.load(Ordering::Acquire),
            self.records.load(Ordering::Acquire),
            self.plan.load(Ordering::Acquire),
        )
    }

    pub(crate) fn bump(&self, relevance: Relevance) {
        if relevance.rules {
            self.rules.fetch_add(1, Ordering::AcqRel);
        }
        if relevance.records {
            self.records.fetch_add(1, Ordering::AcqRel);
        }
        if relevance.plan {
            self.plan.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// A derived index that only signals: the store calls it on its apply path for every
/// change set touching the watched tables, on every controller. It bumps the epochs before
/// it wakes the loop, so a run that the wake starts sees them moved. Reading the origin of
/// a written RRset is one point read per RRset on the apply path.
pub(crate) struct ChangeSignal {
    pub notify: Arc<Notify>,
    pub epochs: Arc<Epochs>,
}

/// The image of [`ChangeSignal`]: nothing but the revision.
struct NoImage(Revision);

impl IndexImage for NoImage {
    fn revision(&self) -> Revision {
        self.0
    }
}

impl DerivedIndex for ChangeSignal {
    fn filter(&self) -> WatchFilter {
        WatchFilter::tables(
            [
                tables::TENANTS.name(),
                tables::VRFS.name(),
                tables::PREFIXES.name(),
                tables::RANGES.name(),
                tables::ADDRESSES.name(),
                tables::HOSTS.name(),
                tables::INTERFACES.name(),
                ADOPTION.name(),
                NAME_AUTHORITY.name(),
                NAME_CHOICES.name(),
                FACTS.name(),
                REVERSE_TEMPLATES.name(),
                tenko_core::dns::tables::ZONES.name(),
                RRSETS.name(),
            ]
            .into_iter()
            .cloned(),
        )
    }

    fn build(&self, view: &dyn ReadView) -> Result<Box<dyn IndexImage>, StoreError> {
        Ok(Box::new(NoImage(view.revision())))
    }

    fn install(&self, _image: Box<dyn IndexImage>) {
        // At the registration and when a snapshot replaced the rows: the next run reads
        // everything again (the leader runs at once when it takes office).
        self.epochs.bump(Relevance::EVERYTHING);
    }

    fn apply(&self, changes: &ChangeSet, view: &dyn ReadView) {
        let relevance = classify(changes, view);
        self.epochs.bump(relevance);
        if relevance.run {
            self.notify.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        Timestamp,
        dns::{DnsName, RrSet, RrSetKey, ScopeName, ZoneId},
        ipam::Stamp,
    };
    use tenko_store::{Change, MemStore, ReadConsistency, Store, WriteBatch};

    use super::*;

    fn rrset(zone: ZoneId, owner: &str, rtype: Rtype, origin: Origin) -> RrSet {
        RrSet {
            zone,
            scope: ScopeName::DEFAULT,
            name: DnsName::new(owner).expect("name"),
            rtype,
            ttl: 300,
            rdata: Vec::new(),
            origin,
            key: None,
            updated: Stamp::new(Timestamp::now(), Principal::system(SystemComponent::Dhcp)),
        }
    }

    fn change(key: &RrSetKey, deleted: bool) -> Change {
        Change {
            table: RRSETS.name().clone(),
            key: RRSETS.key(key),
            deleted,
        }
    }

    fn set(principal: Principal, changes: Vec<Change>) -> ChangeSet {
        ChangeSet {
            revision: Revision::ZERO,
            principal,
            at: Timestamp::now(),
            changes,
        }
    }

    fn other(table: &tenko_core::TableName) -> Change {
        Change {
            table: table.clone(),
            key: bytes::Bytes::from_static(b"row"),
            deleted: false,
        }
    }

    #[tokio::test]
    async fn dhcp_names_alone_schedule_nothing() {
        let store = MemStore::default();
        let zone = ZoneId::generate();
        let dhcp_a = rrset(zone, "laptop.example.test", Rtype::A, Origin::Dhcp);
        let dhcid = rrset(zone, "laptop.example.test", Rtype(49), Origin::Dhcp);
        let soa = rrset(zone, "example.test", Rtype::SOA, Origin::Manual);
        let manual = rrset(zone, "nas.example.test", Rtype::A, Origin::Manual);
        let ipam = rrset(zone, "server.example.test", Rtype::A, Origin::Ipam);
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
        for row in [&dhcp_a, &dhcid, &soa, &manual, &ipam] {
            batch.put_typed(&RRSETS, &row.key(), row).expect("put");
        }
        store.propose(batch).await.expect("write");
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let dhcp = Principal::system(SystemComponent::Dhcp);
        let api = Principal::system(SystemComponent::Api);

        // The DDNS worker's batch: its sets, the serial step, a removal.
        let gone = rrset(zone, "phone.example.test", Rtype::PTR, Origin::Dhcp).key();
        let names = vec![
            change(&dhcp_a.key(), false),
            change(&dhcid.key(), false),
            change(&soa.key(), false),
            change(&gone, true),
        ];
        assert_eq!(
            classify(&set(dhcp.clone(), names.clone()), view.as_ref()),
            Relevance::default()
        );
        // A deletion by another writer may be of any origin.
        assert_eq!(
            classify(&set(api.clone(), vec![change(&gone, true)]), view.as_ref()),
            Relevance::EVERYTHING
        );
        // A hand-written or an `ipam` set beside DHCP's makes it the full pass.
        for written in [&manual, &ipam] {
            let mut with = names.clone();
            with.push(change(&written.key(), false));
            assert_eq!(
                classify(&set(dhcp.clone(), with), view.as_ref()),
                Relevance::EVERYTHING
            );
        }
        // Facts schedule a run that reads no zone.
        assert_eq!(
            classify(&set(api.clone(), vec![other(FACTS.name())]), view.as_ref()),
            Relevance::RULES
        );
        // A lease fact: a light run.
        let lease = Change {
            table: FACTS.name().clone(),
            key: FACTS.key(&("dhcp:1".to_owned(), "address:x/192.0.2.50".to_owned())),
            deleted: false,
        };
        let probe = Change {
            table: FACTS.name().clone(),
            key: FACTS.key(&("probe:1:arp".to_owned(), "address:x/192.0.2.50".to_owned())),
            deleted: false,
        };
        assert_eq!(
            classify(&set(dhcp.clone(), vec![lease.clone()]), view.as_ref()),
            Relevance::LIGHT
        );
        assert_eq!(
            classify(&set(api.clone(), vec![lease, probe]), view.as_ref()),
            Relevance::RULES
        );
        // The intent and the reverse templates: a run and a new plan.
        for table in [tables::ADDRESSES.name(), REVERSE_TEMPLATES.name()] {
            assert_eq!(
                classify(&set(api.clone(), vec![other(table)]), view.as_ref()),
                Relevance::PLAN
            );
        }
        // A zone: everything.
        assert_eq!(
            classify(
                &set(api, vec![other(tenko_core::dns::tables::ZONES.name())]),
                view.as_ref()
            ),
            Relevance::EVERYTHING
        );
    }
}
