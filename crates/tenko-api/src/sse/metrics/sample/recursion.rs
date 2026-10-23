//! The recursive resolver's part of a sample's DNS figures (WP10.4, recursion plan section
//! 2.11): the validation outcomes and the sub-queries per second, beside the upstream figures
//! on the dashboard. The part is there while the registry holds one of the resolver's families
//! (`tenko_dns_validation_total`, `tenko_dns_authority_queries_total`, registered by the role
//! when recursion is on).
//!
//! - `validation`: the change of `tenko_dns_validation_total{state}` per state (`secure`,
//!   `insecure`, `bogus`, `indeterminate`), summed over the reasons.
//! - `subqueries_per_second`: the change of `tenko_dns_authority_queries_total`, every query
//!   the resolver sent to an authority (the sub-queries of the validator included), whatever
//!   its transport and outcome.
//!
//! The cluster sums the rates.

use std::collections::BTreeMap;

use tenko_core::metrics::Snapshot;

use super::{as_f64, counter_by, counter_total};
use crate::dto::events::{MetricsDnsRecursion, MetricsDnsValidation};

/// `tenko_dns_validation_total{state,reason}`.
pub(crate) const DNS_VALIDATION: &str = "tenko_dns_validation";
/// `tenko_dns_authority_queries_total{transport,outcome}`.
pub(crate) const DNS_AUTHORITY_QUERIES: &str = "tenko_dns_authority_queries";

/// The running totals of the resolver in one snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct RecursionTotals {
    /// Validation outcomes by `state`.
    validation: BTreeMap<String, u64>,
    /// Queries sent to authorities.
    subqueries: u64,
}

impl RecursionTotals {
    /// The totals, or `None` when the registry holds none of the resolver's families.
    pub(super) fn of(snapshot: &Snapshot) -> Option<Self> {
        if snapshot.family(DNS_VALIDATION).is_none()
            && snapshot.family(DNS_AUTHORITY_QUERIES).is_none()
        {
            return None;
        }
        Some(Self {
            validation: counter_by(snapshot, DNS_VALIDATION, "state"),
            subqueries: counter_total(snapshot, DNS_AUTHORITY_QUERIES, None),
        })
    }
}

/// The resolver's figures against the totals `before` taken `seconds` earlier; zero rates
/// without `before`, as in a first sample.
pub(super) fn recursion_sample(
    totals: &RecursionTotals,
    before: Option<(&RecursionTotals, f64)>,
) -> MetricsDnsRecursion {
    let Some((before, seconds)) = before.filter(|(_, seconds)| *seconds > 0.0) else {
        return MetricsDnsRecursion::default();
    };
    let rate = |now: u64, then: u64| as_f64(now.saturating_sub(then)) / seconds;
    let state = |name: &str| {
        rate(
            totals.validation.get(name).copied().unwrap_or_default(),
            before.validation.get(name).copied().unwrap_or_default(),
        )
    };
    MetricsDnsRecursion {
        subqueries_per_second: rate(totals.subqueries, before.subqueries),
        validation: MetricsDnsValidation {
            secure: state("secure"),
            insecure: state("insecure"),
            bogus: state("bogus"),
            indeterminate: state("indeterminate"),
        },
    }
}

/// Adds a controller's resolver figures to the cluster's.
pub(super) fn add_recursion(sum: &mut Option<MetricsDnsRecursion>, part: &MetricsDnsRecursion) {
    let sum = sum.get_or_insert_with(MetricsDnsRecursion::default);
    sum.subqueries_per_second += part.subqueries_per_second;
    sum.validation.secure += part.validation.secure;
    sum.validation.insecure += part.validation.insecure;
    sum.validation.bogus += part.validation.bogus;
    sum.validation.indeterminate += part.validation.indeterminate;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn totals(secure: u64, bogus: u64, subqueries: u64) -> RecursionTotals {
        RecursionTotals {
            validation: BTreeMap::from([
                ("secure".to_owned(), secure),
                ("bogus".to_owned(), bogus),
            ]),
            subqueries,
        }
    }

    #[test]
    fn the_rates_are_the_change_over_the_interval() {
        let sample = recursion_sample(&totals(30, 4, 100), Some((&totals(10, 2, 40), 2.0)));
        assert!((sample.validation.secure - 10.0).abs() < f64::EPSILON);
        assert!((sample.validation.bogus - 1.0).abs() < f64::EPSILON);
        assert!(sample.validation.insecure.abs() < f64::EPSILON);
        assert!((sample.subqueries_per_second - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_first_sample_or_an_empty_interval_has_no_rates() {
        assert_eq!(
            recursion_sample(&totals(30, 4, 100), None),
            MetricsDnsRecursion::default()
        );
        assert_eq!(
            recursion_sample(&totals(30, 4, 100), Some((&totals(10, 2, 40), 0.0))),
            MetricsDnsRecursion::default()
        );
    }

    #[test]
    fn the_cluster_sums_the_rates() {
        let part = recursion_sample(&totals(30, 4, 100), Some((&totals(10, 2, 40), 2.0)));
        let mut sum = None;
        add_recursion(&mut sum, &part);
        add_recursion(&mut sum, &part);
        let sum = sum.expect("sum");
        assert!((sum.validation.secure - 20.0).abs() < f64::EPSILON);
        assert!((sum.subqueries_per_second - 60.0).abs() < f64::EPSILON);
    }
}
