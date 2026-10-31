//! The observation layer (IPAM-12, ADR 0005 decision 2): what sources see, kept apart from
//! intent and never written into it.
//!
//! # Facts
//!
//! A source (a connector instance, later a probe, the DNS and DHCP engines) reports
//! [`Observation`](tenko_core::observe::Observation)s. Each becomes a **fact**: one
//! source's knowledge of one subject ([`FactSubject`]: an inventory host by its external
//! id, an address in a VRF, a client attachment by MAC, the services or OS of an address,
//! a link), with first and last sighting, the number of sightings, the expiry the source
//! gave and every raw attribute it reported (name, MAC and IP addresses, OS, platform,
//! hypervisor node, tags, attachment, open ports). Facts of different sources about the
//! same device are never merged: [`view`] computes the picture across sources when it is
//! read, by MAC address, IP address or name.
//!
//! # Writing
//!
//! [`ingest()`] writes one batch per poll and is idempotent on repeated polls: unchanged
//! facts are not rewritten until a refresh is due ([`ObserveConfig::refresh`]), and a
//! complete batch expires the facts its source no longer reports. The reconciler
//! ([`crate::reconcile::Reconciler`]) wraps it: after an ingest it wakes jobs that wait for
//! the observations and schedules a reconcile run.
//!
//! # The leases (ADR 0031)
//!
//! The DHCP leases are not ingested: the lease tables are the source `dhcp:<node>`, and
//! [`dhcp::LeaseFacts`] presents each lease row as the facts it stands for. The readers take
//! the stored facts and the lease facts together through [`source::Observations`]; an
//! ingest refuses observations of a lease source, and a stored fact of one (written before
//! ADR 0031) is never read and leaves with the retention.
//!
//! # Retention
//!
//! [`retention::purge`] deletes facts whose last sighting is older than
//! [`ObserveConfig::retention`] (30 days by default); the reconciler runs it periodically.
//!
//! # Tables
//!
//! See [`tables`]: `ipam.obs.facts` with the indexes `ipam.obs.by_mac`, `ipam.obs.by_ip`
//! and `ipam.obs.by_name`, and `ipam.obs.last_seen` for the last sighting of addresses and
//! interfaces of intent.

// ADR 0031: the lease tables as the source `dhcp:<node>`, read through the lease view.
pub mod dhcp;
pub mod dns;
pub mod ingest;
pub mod model;
pub mod retention;
// ADR 0031: the stored facts and the lease view behind one trait.
pub mod source;
pub mod tables;
pub mod view;

use std::time::Duration;

pub use ingest::ingest;
pub use model::{FactSubject, IngestBatch, IngestReport, IntentSighting, ObservedFact, source_key};

/// Settings of the observation layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObserveConfig {
    /// How often an unchanged fact is rewritten with a new last sighting, and the
    /// shortest interval between two counted sightings (15 minutes, R9).
    pub refresh: Duration,
    /// How long a fact is kept after its last sighting (30 days).
    pub retention: Duration,
    /// Attempts of an ingest that loses races with other writers.
    pub max_attempts: u32,
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            refresh: Duration::from_secs(15 * 60),
            retention: Duration::from_secs(30 * 24 * 3600),
            max_attempts: 8,
        }
    }
}
