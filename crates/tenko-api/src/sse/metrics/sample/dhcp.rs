//! The `dhcp` part of a sample (WP8.7, OPS-20): the families of the `dhcp` role
//! (`docs/dhcp-contracts.md` section 8) read the way the DNS part reads the `dns` role's. The
//! part is there while the registry holds the role's packet counter (`tenko_dhcp_packets_total`,
//! registered when the role starts).
//!
//! - `leases_per_second`: the change of `tenko_dhcp_packets_total{type="request",
//!   outcome="answered"}`, the REQUESTs answered with an ACK.
//! - `ack_p99_ms`: the change of `tenko_dhcp_exchange_duration_seconds{step="ack"}`.
//! - `naks_per_second`, `declines_per_second`: the change of `tenko_dhcp_naks_total` and
//!   `tenko_dhcp_declines_total`.
//! - `active_leases`, `abandoned_leases`: the lazy gauge `tenko_dhcp_leases{state}`.
//! - `scopes`, `fullest`: the lazy gauge `tenko_dhcp_pool_utilization{scope}`, its series and
//!   the three highest.
//! - `ddns`: the change of `tenko_dhcp_ddns_total{outcome}` and the gauge
//!   `tenko_dhcp_ddns_queue`.
//!
//! The cluster sums the rates and counts, takes the highest quantile and keeps the three
//! fullest scopes over every controller (a scope two controllers report counts at its highest).

use std::collections::BTreeMap;

use tenko_core::metrics::{Snapshot, Value};

use super::{as_count, as_f64, delta, gauge, label, labelled_gauge, max_of, quantile_ms};
use crate::dto::events::{MetricsDhcp, MetricsDhcpDdns, MetricsDhcpPool};

/// `tenko_dhcp_packets_total{family,type,outcome}`: its presence says the `dhcp` role runs.
pub(crate) const DHCP_PACKETS: &str = "tenko_dhcp_packets";
/// `tenko_dhcp_exchange_duration_seconds{step}`.
pub(crate) const DHCP_EXCHANGE: &str = "tenko_dhcp_exchange_duration_seconds";
/// `tenko_dhcp_leases{state}`.
pub(crate) const DHCP_LEASES: &str = "tenko_dhcp_leases";
/// `tenko_dhcp_pool_utilization{scope}`.
pub(crate) const DHCP_POOLS: &str = "tenko_dhcp_pool_utilization";
/// `tenko_dhcp_naks_total`.
pub(crate) const DHCP_NAKS: &str = "tenko_dhcp_naks";
/// `tenko_dhcp_declines_total`.
pub(crate) const DHCP_DECLINES: &str = "tenko_dhcp_declines";
/// `tenko_dhcp_ddns_total{outcome}`.
pub(crate) const DHCP_DDNS: &str = "tenko_dhcp_ddns";
/// `tenko_dhcp_ddns_queue`.
pub(crate) const DHCP_DDNS_QUEUE: &str = "tenko_dhcp_ddns_queue";

/// The scopes a sample names, the fullest first.
pub(crate) const FULLEST: usize = 3;

/// The running totals of the `dhcp` role in one snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct DhcpTotals {
    /// REQUESTs answered with an ACK.
    acks: u64,
    /// Cumulative bucket counts of the REQUEST to ACK time.
    ack_durations: Vec<u64>,
    naks: u64,
    declines: u64,
    /// DDNS change sets by `outcome`.
    ddns: BTreeMap<String, u64>,
}

impl DhcpTotals {
    /// The totals, or `None` when the registry has no packet counter of the role.
    pub(super) fn of(snapshot: &Snapshot) -> Option<Self> {
        snapshot.family(DHCP_PACKETS)?;
        Some(Self {
            acks: counter_where(
                snapshot,
                DHCP_PACKETS,
                &[("type", "request"), ("outcome", "answered")],
            ),
            ack_durations: histogram_where(snapshot, DHCP_EXCHANGE, ("step", "ack")),
            naks: counter_where(snapshot, DHCP_NAKS, &[]),
            declines: counter_where(snapshot, DHCP_DECLINES, &[]),
            ddns: super::counter_by(snapshot, DHCP_DDNS, "outcome"),
        })
    }
}

/// The sum of a counter family's series whose labels hold every `(name, value)` of `only`.
fn counter_where(snapshot: &Snapshot, name: &str, only: &[(&str, &str)]) -> u64 {
    let Some(family) = snapshot.family(name) else {
        return 0;
    };
    family
        .series
        .iter()
        .filter(|series| {
            only.iter()
                .all(|(label_name, value)| label(family, series, label_name) == Some(*value))
        })
        .filter_map(|series| match series.value {
            Value::Counter(total) => Some(total),
            Value::Gauge(value) => Some(as_count(value)),
            Value::Histogram(_) => None,
        })
        .fold(0, u64::wrapping_add)
}

/// The cumulative bucket counts of the series of a histogram family whose label `name` is
/// `value`, summed.
fn histogram_where(snapshot: &Snapshot, family: &str, (name, value): (&str, &str)) -> Vec<u64> {
    let Some(family) = snapshot.family(family) else {
        return Vec::new();
    };
    let mut total: Vec<u64> = Vec::new();
    for series in &family.series {
        if label(family, series, name) != Some(value) {
            continue;
        }
        if let Value::Histogram(histogram) = &series.value {
            if total.len() < histogram.buckets.len() {
                total.resize(histogram.buckets.len(), 0);
            }
            for (sum, count) in total.iter_mut().zip(&histogram.buckets) {
                *sum = sum.wrapping_add(*count);
            }
        }
    }
    total
}

/// Every series of the utilization gauge, by scope.
fn pools(snapshot: &Snapshot) -> Vec<MetricsDhcpPool> {
    let Some(family) = snapshot.family(DHCP_POOLS) else {
        return Vec::new();
    };
    family
        .series
        .iter()
        .filter_map(|series| match series.value {
            Value::Gauge(utilization) if utilization.is_finite() => Some(MetricsDhcpPool {
                scope: label(family, series, "scope")?.to_owned(),
                utilization: utilization.clamp(0.0, 1.0),
            }),
            _ => None,
        })
        .collect()
}

/// The fullest first, then by scope; at most [`FULLEST`].
fn fullest(mut pools: Vec<MetricsDhcpPool>) -> Vec<MetricsDhcpPool> {
    pools.sort_by(|a, b| {
        b.utilization
            .total_cmp(&a.utilization)
            .then_with(|| a.scope.cmp(&b.scope))
    });
    pools.truncate(FULLEST);
    pools
}

/// The `dhcp` part of a sample: the gauges of `snapshot`, and against the totals `before` taken
/// `seconds` earlier the rates and the quantile (none without `before`, as in a first sample).
pub(super) fn dhcp_sample(
    snapshot: &Snapshot,
    totals: &DhcpTotals,
    before: Option<(&DhcpTotals, f64)>,
) -> MetricsDhcp {
    let all = pools(snapshot);
    let mut dhcp = MetricsDhcp {
        active_leases: labelled_gauge(snapshot, DHCP_LEASES, "state", "active").unwrap_or_default(),
        abandoned_leases: labelled_gauge(snapshot, DHCP_LEASES, "state", "abandoned")
            .unwrap_or_default(),
        scopes: u64::try_from(all.len()).unwrap_or(u64::MAX),
        fullest: fullest(all),
        ddns: MetricsDhcpDdns {
            queue: gauge(snapshot, DHCP_DDNS_QUEUE).unwrap_or_default(),
            ..MetricsDhcpDdns::default()
        },
        ..MetricsDhcp::default()
    };
    let Some((before, seconds)) = before else {
        return dhcp;
    };
    let rate = |count: u64| {
        if seconds > 0.0 {
            as_f64(count) / seconds
        } else {
            0.0
        }
    };
    dhcp.leases_per_second = rate(totals.acks.saturating_sub(before.acks));
    dhcp.naks_per_second = rate(totals.naks.saturating_sub(before.naks));
    dhcp.declines_per_second = rate(totals.declines.saturating_sub(before.declines));
    let durations = delta(&totals.ack_durations, &before.ack_durations);
    dhcp.ack_p99_ms = quantile_ms(snapshot, DHCP_EXCHANGE, &durations, 0.99);
    let outcome = |name: &str| {
        let now = totals.ddns.get(name).copied().unwrap_or_default();
        let then = before.ddns.get(name).copied().unwrap_or_default();
        rate(now.saturating_sub(then))
    };
    dhcp.ddns.written = outcome("written");
    dhcp.ddns.removed = outcome("removed");
    dhcp.ddns.refused = outcome("refused");
    dhcp.ddns.failed = outcome("failed");
    dhcp.ddns.skipped = outcome("skipped");
    dhcp.ddns.dropped = outcome("dropped");
    dhcp
}

/// Adds a controller's `dhcp` part to the cluster's: rates and counts summed, the quantile at
/// its highest, the scopes at their highest count, the three fullest scopes over both.
pub(super) fn add_dhcp(sum: &mut MetricsDhcp, dhcp: &MetricsDhcp) {
    sum.leases_per_second += dhcp.leases_per_second;
    sum.ack_p99_ms = max_of(sum.ack_p99_ms, dhcp.ack_p99_ms);
    sum.naks_per_second += dhcp.naks_per_second;
    sum.declines_per_second += dhcp.declines_per_second;
    sum.active_leases = sum.active_leases.saturating_add(dhcp.active_leases);
    sum.abandoned_leases = sum.abandoned_leases.saturating_add(dhcp.abandoned_leases);
    sum.scopes = sum.scopes.max(dhcp.scopes);
    let mut pools = std::mem::take(&mut sum.fullest);
    for pool in &dhcp.fullest {
        match pools.iter_mut().find(|known| known.scope == pool.scope) {
            Some(known) => known.utilization = known.utilization.max(pool.utilization),
            None => pools.push(pool.clone()),
        }
    }
    sum.fullest = fullest(pools);
    sum.ddns.written += dhcp.ddns.written;
    sum.ddns.removed += dhcp.ddns.removed;
    sum.ddns.refused += dhcp.ddns.refused;
    sum.ddns.failed += dhcp.ddns.failed;
    sum.ddns.skipped += dhcp.ddns.skipped;
    sum.ddns.dropped += dhcp.ddns.dropped;
    sum.ddns.queue = sum.ddns.queue.saturating_add(dhcp.ddns.queue);
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use tenko_core::{
        NodeId, Timestamp,
        metrics::{Collect, Counter, CounterVec, Desc, Gauge, GaugeVec, HistogramVec, Registry},
    };

    use super::{super::SampleBuilder, *};
    use crate::dto::events::MetricsSample;

    /// Bounds in microseconds: 1 ms, 10 ms, 100 ms.
    const BOUNDS: [u64; 3] = [1_000, 10_000, 100_000];

    static PACKETS: CounterVec = CounterVec::fixed(
        Desc::counter(DHCP_PACKETS, "Packets.").labels(&["family", "type", "outcome"]),
        &[
            &["v4", "discover", "answered"],
            &["v4", "request", "answered"],
            &["v4", "request", "nak"],
            &["v4", "inform", "answered"],
        ],
    );
    static EXCHANGE: HistogramVec = HistogramVec::fixed(
        Desc::histogram(DHCP_EXCHANGE, "Exchanges.", &BOUNDS, 1_000_000).labels(&["step"]),
        &[&["offer"], &["ack"]],
    );
    static LEASES: GaugeVec = GaugeVec::fixed(
        Desc::gauge(DHCP_LEASES, "Leases.").labels(&["state"]),
        &[&["active"], &["expired"], &["abandoned"]],
    );
    static POOLS: GaugeVec = GaugeVec::fixed(
        Desc::gauge(DHCP_POOLS, "Pools.").labels(&["scope"]),
        &[
            &["192.0.2.0/26"],
            &["192.0.2.64/26"],
            &["198.51.100.0/24"],
            &["203.0.113.0/24"],
        ],
    );
    static NAKS: Counter = Counter::new(Desc::counter(DHCP_NAKS, "NAKs."));
    static DECLINES: Counter = Counter::new(Desc::counter(DHCP_DECLINES, "Declines."));
    static DDNS: CounterVec = CounterVec::fixed(
        Desc::counter(DHCP_DDNS, "DDNS.").labels(&["outcome"]),
        &[
            &["written"],
            &["removed"],
            &["refused"],
            &["failed"],
            &["skipped"],
            &["dropped"],
        ],
    );
    static QUEUE: Gauge = Gauge::new(Desc::gauge(DHCP_DDNS_QUEUE, "Queue."));

    fn registry() -> Registry {
        let registry = Registry::new();
        for family in [
            &PACKETS as &'static dyn Collect,
            &EXCHANGE,
            &LEASES,
            &POOLS,
            &NAKS,
            &DECLINES,
            &DDNS,
            &QUEUE,
        ] {
            registry.register(family);
        }
        registry
    }

    /// Two seconds: 100 ACKs (90 below 1 ms, 10 between 10 and 100 ms), 30 OFFERs, 4 NAKs, 2
    /// DECLINEs, 12 INFORMs answered (which are no leases), and DDNS change sets.
    fn two_seconds_of_dhcp() {
        PACKETS.add(0, 30);
        PACKETS.add(1, 100);
        PACKETS.add(2, 4);
        PACKETS.add(3, 12);
        for _ in 0..30 {
            EXCHANGE.observe(0, 50_000);
        }
        for _ in 0..90 {
            EXCHANGE.observe(1, 400);
        }
        for _ in 0..10 {
            EXCHANGE.observe(1, 40_000);
        }
        NAKS.add(4);
        DECLINES.add(2);
        DDNS.add(0, 40);
        DDNS.add(1, 6);
        DDNS.add(2, 2);
        DDNS.add(4, 10);
        LEASES.set(0, 812.0);
        LEASES.set(1, 40.0);
        LEASES.set(2, 3.0);
        POOLS.set(0, 0.25);
        POOLS.set(1, 0.92);
        POOLS.set(2, 0.5);
        POOLS.set(3, 0.92);
        QUEUE.set(7.0);
    }

    #[test]
    fn a_node_with_the_dhcp_role_has_its_leases_pools_and_ddns_in_the_sample() {
        let registry = registry();
        let mut builder = SampleBuilder::new();
        let start = Instant::now();
        let at = Timestamp::now();
        let first = builder.build(
            Some(NodeId(1)),
            at,
            start,
            &registry.snapshot(),
            &BTreeMap::new(),
        );
        let dhcp = first.dhcp.expect("the role's families are registered");
        assert!(dhcp.leases_per_second.abs() < f64::EPSILON);
        assert_eq!(dhcp.ack_p99_ms, None);

        two_seconds_of_dhcp();
        let second = builder.build(
            Some(NodeId(1)),
            at,
            start + Duration::from_secs(2),
            &registry.snapshot(),
            &BTreeMap::new(),
        );
        let dhcp = second.dhcp.clone().expect("dhcp");
        let near = |a: f64, b: f64| (a - b).abs() < 1e-9;
        assert!(near(dhcp.leases_per_second, 50.0), "{dhcp:?}");
        assert!(near(dhcp.naks_per_second, 2.0));
        assert!(near(dhcp.declines_per_second, 1.0));
        // The 99th of the 100 ACKs: 9 of the 10 in the 10 to 100 ms bucket; the OFFERs' times
        // do not count.
        let p99 = dhcp.ack_p99_ms.expect("p99");
        assert!((p99 - (10.0 + 90.0 * 0.9)).abs() < 1e-6, "{dhcp:?}");
        assert_eq!(dhcp.active_leases, 812);
        assert_eq!(dhcp.abandoned_leases, 3);
        assert_eq!(dhcp.scopes, 4);
        assert_eq!(
            dhcp.fullest
                .iter()
                .map(|pool| (pool.scope.as_str(), pool.utilization))
                .collect::<Vec<_>>(),
            vec![
                ("192.0.2.64/26", 0.92),
                ("203.0.113.0/24", 0.92),
                ("198.51.100.0/24", 0.5)
            ]
        );
        assert!(near(dhcp.ddns.written, 20.0));
        assert!(near(dhcp.ddns.removed, 3.0));
        assert!(near(dhcp.ddns.refused, 1.0));
        assert!(near(dhcp.ddns.skipped, 5.0));
        assert!(dhcp.ddns.failed.abs() < f64::EPSILON);
        assert_eq!(dhcp.ddns.queue, 7);

        // A quiet second: no rates and no quantile, the gauges stay.
        let third = builder.build(
            Some(NodeId(1)),
            at,
            start + Duration::from_secs(3),
            &registry.snapshot(),
            &BTreeMap::new(),
        );
        let dhcp = third.dhcp.expect("dhcp");
        assert!(dhcp.leases_per_second.abs() < f64::EPSILON);
        assert_eq!(dhcp.ack_p99_ms, None);
        assert_eq!(dhcp.active_leases, 812);

        let json = serde_json::to_value(&second).expect("json");
        assert_eq!(json["dhcp"]["leases_per_second"], 50.0);
        assert_eq!(json["dhcp"]["fullest"][0]["scope"], "192.0.2.64/26");
        assert_eq!(json["dhcp"]["ddns"]["queue"], 7);
        let back: MetricsSample = serde_json::from_value(json).expect("back");
        assert_eq!(back, second);
    }

    #[test]
    fn the_dhcp_part_is_absent_without_the_role() {
        let none = Registry::new();
        let mut builder = SampleBuilder::new();
        let sample = builder.build(
            None,
            Timestamp::now(),
            Instant::now(),
            &none.snapshot(),
            &BTreeMap::new(),
        );
        assert_eq!(sample.dhcp, None);
        let json = serde_json::to_value(&sample).expect("json");
        assert!(json.get("dhcp").is_none());
        // An older peer's sample without the field reads as one without the role.
        let back: MetricsSample = serde_json::from_value(json).expect("back");
        assert_eq!(back.dhcp, None);
    }

    fn part(leases: f64, p99: f64, active: u64, pools: &[(&str, f64)]) -> MetricsDhcp {
        MetricsDhcp {
            leases_per_second: leases,
            ack_p99_ms: Some(p99),
            naks_per_second: 1.0,
            declines_per_second: 0.5,
            active_leases: active,
            abandoned_leases: 1,
            scopes: u64::try_from(pools.len()).expect("few"),
            fullest: pools
                .iter()
                .map(|(scope, utilization)| MetricsDhcpPool {
                    scope: (*scope).to_owned(),
                    utilization: *utilization,
                })
                .collect(),
            ddns: MetricsDhcpDdns {
                written: leases / 2.0,
                queue: 2,
                ..MetricsDhcpDdns::default()
            },
        }
    }

    #[test]
    fn the_cluster_sums_the_dhcp_rates_and_keeps_the_three_fullest_scopes() {
        let at = Timestamp::now();
        let mut one = MetricsSample::empty(Some(NodeId(1)), at);
        one.dhcp = Some(part(
            40.0,
            3.0,
            500,
            &[("192.0.2.0/26", 0.9), ("192.0.2.64/26", 0.4)],
        ));
        let mut two = MetricsSample::empty(Some(NodeId(2)), at);
        two.dhcp = Some(part(
            10.0,
            12.0,
            100,
            &[
                ("198.51.100.0/24", 0.7),
                ("192.0.2.64/26", 0.6),
                ("203.0.113.0/24", 0.1),
            ],
        ));
        let three = MetricsSample::empty(Some(NodeId(3)), at);
        let mut stale = MetricsSample::empty(Some(NodeId(4)), at);
        stale.stale = true;
        stale.dhcp = Some(part(1_000.0, 900.0, 1, &[("203.0.113.0/24", 1.0)]));

        let sum = super::super::cluster_sum(&[one, two, three, stale], at);
        let dhcp = sum.dhcp.expect("two controllers run the role");
        assert!((dhcp.leases_per_second - 50.0).abs() < 1e-9);
        assert_eq!(dhcp.ack_p99_ms, Some(12.0));
        assert!((dhcp.naks_per_second - 2.0).abs() < 1e-9);
        assert_eq!(dhcp.active_leases, 600);
        assert_eq!(dhcp.scopes, 3);
        assert_eq!(
            dhcp.fullest
                .iter()
                .map(|pool| (pool.scope.as_str(), pool.utilization))
                .collect::<Vec<_>>(),
            vec![
                ("192.0.2.0/26", 0.9),
                ("198.51.100.0/24", 0.7),
                ("192.0.2.64/26", 0.6)
            ]
        );
        assert!((dhcp.ddns.written - 25.0).abs() < 1e-9);
        assert_eq!(dhcp.ddns.queue, 4);

        let without = super::super::cluster_sum(&[MetricsSample::empty(Some(NodeId(1)), at)], at);
        assert_eq!(without.dhcp, None);
    }
}
