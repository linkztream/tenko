//! The DDNS series (`docs/dhcp-contracts.md` section 8): `tenko_dhcp_ddns_total{outcome}`
//! and `tenko_dhcp_ddns_queue`, registered by the role's metrics with the other families.

use tenko_core::metrics::{CounterVec, Gauge};

use crate::metrics as families;

/// What became of one DDNS request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Outcome {
    /// Names written (the forward set with its DHCID, the PTR, or both).
    Written = 0,
    /// Names removed on release, expiry or a change of name.
    Removed = 1,
    /// Refused: name protection, another origin's RRset, a zone that does not allow DHCP,
    /// a name outside the host-name rules.
    Refused = 2,
    /// The zone service or the store failed after the retries.
    Failed = 3,
    /// Nothing to do for DDNS: IPAM manages the address's names, or the scope has no zone.
    Skipped = 4,
    /// The queue was full; the request is read again from the lease rows.
    Dropped = 5,
}

impl Outcome {
    /// Counts one.
    pub fn count(self) {
        OUTCOMES.inc(self as u16);
    }

    /// The label.
    pub fn label(self) -> &'static str {
        LABELS[self as usize][0]
    }
}

const LABELS: &[&[&str]] = &[
    &["written"],
    &["removed"],
    &["refused"],
    &["failed"],
    &["skipped"],
    &["dropped"],
];

/// `tenko_dhcp_ddns_total{outcome}`.
pub static OUTCOMES: CounterVec = CounterVec::fixed(families::DDNS, LABELS);

/// `tenko_dhcp_ddns_queue`: requests waiting for the worker.
pub static QUEUE: Gauge = Gauge::new(families::DDNS_QUEUE);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_follow_the_series() {
        assert_eq!(Outcome::Refused.label(), "refused");
        assert_eq!(Outcome::Dropped.label(), "dropped");
        assert_eq!(LABELS.len(), Outcome::Dropped as usize + 1);
        let before = OUTCOMES.get(Outcome::Skipped as u16);
        Outcome::Skipped.count();
        assert!(OUTCOMES.get(Outcome::Skipped as u16) > before);
    }
}
