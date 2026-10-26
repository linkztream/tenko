//! The findings model (U1): one object type for everything Tenko noticed that a person may
//! need to decide on, with a severity, a subject, the evidence and a default action.
//!
//! The same idea lives in five sources under their own names: open proposals
//! (`ipam.proposals`), utilization alarms (`ipam.alarms`, IPAM-10), the rows of the
//! reconciliation view (derived on read, IPAM-21), jobs waiting for a person (`jobs.jobs`)
//! and the health conditions of `GET /system/status`. The [`FindingsIndex`] is one derived,
//! in-memory index over them, with no stored table of its own: every surface (the
//! dashboard, the status bar, the rail, the lists) reads the same index and one live topic,
//! so a count never differs between two screens. The sources and their routes stay as they
//! are; the index only reads them.
//!
//! # The mapping
//!
//! | Source | Kind | Severity | Default action |
//! |---|---|---|---|
//! | conflict proposal (every rule of the kind `conflict`) | `conflict` | act | resolve |
//! | discovered host | `unknown_device` | review | adopt |
//! | orphaned DNS record (`dns_orphaned_record`) | `orphaned_record` | review | delete record |
//! | orphaned address (`orphaned_address`) | `orphaned_address` | review | decide |
//! | address mismatch | `intent_differs` | review | open host |
//! | outside prefixes, VLAN, host name, other DNS proposals | `outside_prefixes`, `vlan`, `host_name`, `dns` | review | decide |
//! | utilization alarm, critical / warning | `utilization` | act / review | open prefix |
//! | job with a step waiting for a person | `job_waiting` | act | open manual step |
//! | view `conflict` (no open conflict proposal of the address) | `conflict` | act | resolve |
//! | view `orphan` of a record written by hand | `orphaned_record` | review | delete record |
//! | view `ptr_mismatch` | `ptr_mismatch` | review | fix PTR |
//! | view `ghost` | `ghost` | info; review after `ghost_review_after_secs` | none; decommission |
//! | view `rogue` without an open proposal (decided) | `unknown_device` | info | none |
//! | sighting of a network's edge address | `scan_artifact` | info | none |
//! | health condition: error / warning / informational | `health` | act / review / info | open status |
//!
//! An open proposal always waits for a person, so it is never information, and every
//! proposal belongs to the Discovery area: the Discovery inbox and its badge count the same
//! open proposals. A view row that an open proposal stands for (a rogue's discovered host,
//! an orphan's orphaned record, a conflict row of an address with an open conflict proposal)
//! is not listed twice. Information is listed but never counted as a problem.
//!
//! # The guard rail
//!
//! A network's edge address (the network and broadcast address of an IPv4 network up to
//! /30, the subnet-router anycast address of an IPv6 network up to /126,
//! [`crate::net::edge_address`]) is never held by a device. A sighting of one is a scan
//! artifact: the reconciler's rules never see it (no conflict, no discovered host, no
//! mismatch), and the findings list it as `scan_artifact`. An open conflict about such an
//! address expires at the next run with the reason in its audit record.
//!
//! # Keeping it current
//!
//! [`FindingsIndex::apply`] applies a store change set: each changed proposal, alarm and job
//! is read once and its finding replaced or removed. The findings of the reconciliation view
//! are replaced as a whole by [`FindingsIndex::refresh_view`] when a table the view reads
//! changed, at most once per `reconcile_refresh_secs`, and once a minute for what ages with
//! time (ghosts). Health conditions are set with [`FindingsIndex::set_health`] by the status.
//! The counts are cached until the next change.

mod index;
pub mod map;
pub mod model;

pub use index::{
    Applied, DEFAULT_LIMIT, FindingPage, FindingQuery, FindingsIndex, MAX_LIMIT, view_input,
};
pub use map::{HealthItem, finding_id, of_alarm, of_health, of_job, of_proposal};
pub use model::{
    AreaCounts, Finding, FindingAction, FindingArea, FindingCounts, FindingEvidence, FindingKind,
    FindingLevel, FindingSource, FindingSubject, FindingsConfig, GHOST_REVIEW_AFTER_SECS,
    LevelCounts, SourceCounts, SubjectKind,
};

#[cfg(test)]
mod tests;
