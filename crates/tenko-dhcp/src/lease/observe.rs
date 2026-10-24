//! The observation hook of the lease batch (plan section 2.8, P3-Q8, WP8.1): every lease
//! change carries the IPAM facts of the source `dhcp:<node>` in its own batch, built by
//! `tenko_ipam::observe::dhcp` so that the rules of `observe::ingest` stay in one crate.
//!
//! [`IpamObservations`] is the production [`ObservationHook`]: the committer calls it for
//! every change it builds, and the operator's release (`dhcp.lease.release`) for its row.
//! A renewal within the refresh interval writes no fact; every outcome is counted in
//! [`LEASE_FACTS`] (`tenko_dhcp_lease_facts_total{outcome}`) and in the hook's own
//! [`FactCounts`], which the tests read.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use tenko_core::{
    NodeId, Timestamp,
    dhcp::Lease,
    metrics::{CounterVec, Desc},
};
use tenko_ipam::observe::{
    ObserveConfig,
    dhcp::{FactOutcome, LeaseFacts},
};
use tenko_store::{Store, StoreError, WriteBatch};

use super::batch::ObservationHook;

/// The outcomes of `tenko_dhcp_lease_facts_total`, in series order.
pub const OUTCOMES: [&str; 5] = ["new", "changed", "refreshed", "unchanged", "expired"];

/// `tenko_dhcp_lease_facts_total{outcome}`: what lease changes did to their IPAM facts
/// (the address fact and the name fact count separately).
pub static LEASE_FACTS: CounterVec = CounterVec::fixed(
    Desc::counter(
        "tenko_dhcp_lease_facts",
        "IPAM observation facts of DHCP lease changes, by outcome",
    )
    .labels(&["outcome"]),
    &[
        &["new"],
        &["changed"],
        &["refreshed"],
        &["unchanged"],
        &["expired"],
    ],
);

/// The counts of one hook since its start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FactCounts {
    /// Facts written for the first time.
    pub new: u64,
    /// Facts written because an attribute changed or they had expired.
    pub changed: u64,
    /// Facts written because their refresh was due.
    pub refreshed: u64,
    /// Facts left as they were (a renewal within the refresh interval).
    pub unchanged: u64,
    /// Facts expired by a release, a decline or an operator's release.
    pub expired: u64,
}

impl FactCounts {
    /// The facts written.
    pub const fn written(&self) -> u64 {
        self.new + self.changed + self.refreshed + self.expired
    }
}

#[derive(Debug, Default)]
struct Counters([AtomicU64; 5]);

fn series(outcome: FactOutcome) -> Option<u16> {
    match outcome {
        FactOutcome::None => None,
        FactOutcome::New => Some(0),
        FactOutcome::Changed => Some(1),
        FactOutcome::Refreshed => Some(2),
        FactOutcome::Unchanged => Some(3),
        FactOutcome::Expired => Some(4),
    }
}

/// The hook over the lease facts of IPAM.
#[derive(Debug)]
pub struct IpamObservations {
    facts: Arc<LeaseFacts>,
    counters: Counters,
}

impl IpamObservations {
    /// The hook of `node`: registers its index of the stored facts with `store`.
    ///
    /// # Errors
    ///
    /// The store's error when the stored facts cannot be read.
    pub fn register(
        store: &dyn Store,
        node: NodeId,
        config: ObserveConfig,
    ) -> Result<Arc<Self>, StoreError> {
        let facts = LeaseFacts::new(node, config);
        // WP8.2: the facts classify each lease's fingerprint by the project's rule table
        // (DHCP-14, P3-Q15): the guess is the fact `os:<ip>` of the source `dhcp:<node>`.
        crate::fingerprint::classify_leases(&facts);
        facts.register(store)?;
        Ok(Arc::new(Self {
            facts,
            counters: Counters::default(),
        }))
    }

    /// The facts of the node.
    pub fn facts(&self) -> &Arc<LeaseFacts> {
        &self.facts
    }

    /// The counts since the start.
    pub fn counts(&self) -> FactCounts {
        let get = |index: usize| self.counters.0[index].load(Ordering::Relaxed);
        FactCounts {
            new: get(0),
            changed: get(1),
            refreshed: get(2),
            unchanged: get(3),
            expired: get(4),
        }
    }

    fn count(&self, outcome: FactOutcome) {
        if let Some(series) = series(outcome) {
            self.counters.0[usize::from(series)].fetch_add(1, Ordering::Relaxed);
            LEASE_FACTS.inc(series);
        }
    }
}

impl ObservationHook for IpamObservations {
    fn observe(
        &self,
        lease: &Lease,
        _previous: Option<&Lease>,
        batch: &mut WriteBatch,
    ) -> Result<Option<Timestamp>, StoreError> {
        let now = batch.proposed_at;
        let observation = self.facts.observe(lease, now, batch)?;
        self.count(observation.address);
        self.count(observation.name);
        Ok(observation.observed_at)
    }
}

// WP9.1: the facts of the DHCPv6 lease batch, by the same rules and counters.
impl crate::v6::lease::commit::Observation6Hook for IpamObservations {
    fn observe6(
        &self,
        lease: &tenko_core::dhcp::Lease6,
        _previous: Option<&tenko_core::dhcp::Lease6>,
        batch: &mut WriteBatch,
    ) -> Result<Option<Timestamp>, StoreError> {
        let now = batch.proposed_at;
        let observation = self.facts.observe6(lease, now, batch)?;
        self.count(observation.address);
        self.count(observation.name);
        Ok(observation.observed_at)
    }
}
