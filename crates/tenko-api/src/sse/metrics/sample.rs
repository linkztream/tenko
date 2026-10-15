//! The per-controller sample of the `metrics` topic: [`SampleBuilder`] turns two consecutive
//! snapshots of the metrics registry into a [`MetricsSample`], and [`cluster_sum`] merges the
//! samples of the controllers into the cluster's.
//!
//! Rates are the change of a counter over the interval between the two snapshots; quantiles
//! are interpolated linearly inside the bucket of the histogram's change that holds them (as
//! Prometheus' `histogram_quantile` does), so a quantile in the `+Inf` bucket reads as the
//! highest bound. Everything else is the gauge value of the newer snapshot.

use std::{collections::BTreeMap, time::Instant};

use tenko_core::{
    NodeId, Timestamp,
    metrics::{FamilySnapshot, Kind, Series, Snapshot, Value},
};

use crate::dto::events::{
    MetricsIngest, MetricsJobs, MetricsLag, MetricsNode, MetricsRaft, MetricsSample, MetricsSse,
};

/// `tenko_http_requests_total{route,method,status}`.
pub(crate) const HTTP_REQUESTS: &str = "tenko_http_requests";
/// `tenko_http_request_duration_seconds{class}`.
pub(crate) const HTTP_DURATION: &str = "tenko_http_request_duration_seconds";
/// The route and class of the web UI's files, which the API figures leave out.
const UI_ROUTE: &str = "ui";
/// `tenko_store_commit_duration_seconds`.
pub(crate) const STORE_COMMIT: &str = "tenko_store_commit_duration_seconds";
/// `tenko_ipam_ingest_batches_total`.
pub(crate) const INGEST_BATCHES: &str = "tenko_ipam_ingest_batches";
/// `tenko_ipam_ingest_facts_total`.
pub(crate) const INGEST_FACTS: &str = "tenko_ipam_ingest_facts";
const STORE_DATA_BYTES: &str = "tenko_store_data_bytes";
const STORE_FILE_BYTES: &str = "tenko_store_file_bytes";
const RAFT_ROLE: &str = "tenko_raft_role";
const RAFT_TERM: &str = "tenko_raft_term";
const RAFT_LAG: &str = "tenko_raft_lag_entries";
const JOBS: &str = "tenko_jobs";
const SSE_SUBSCRIBERS: &str = "tenko_sse_subscribers";
const NODE_BUFFER: &str = "tenko_node_buffer_batches";

/// The running totals of one snapshot that the next sample's rates and quantiles are
/// computed against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Totals {
    requests: u64,
    /// Cumulative bucket counts of the request duration, summed over the route classes.
    durations: Vec<u64>,
    commits: Vec<u64>,
    ingest_batches: u64,
    ingest_facts: u64,
}

impl Totals {
    fn of(snapshot: &Snapshot) -> Self {
        Self {
            requests: counter_total(snapshot, HTTP_REQUESTS, Some(("route", UI_ROUTE))),
            durations: histogram_total(snapshot, HTTP_DURATION, Some(("class", UI_ROUTE))),
            commits: histogram_total(snapshot, STORE_COMMIT, None),
            ingest_batches: counter_total(snapshot, INGEST_BATCHES, None),
            ingest_facts: counter_total(snapshot, INGEST_FACTS, None),
        }
    }
}

/// Builds the samples of one controller, each against the snapshot before it.
#[derive(Debug, Default)]
pub struct SampleBuilder {
    previous: Option<(Instant, Totals)>,
}

impl SampleBuilder {
    /// A builder without a previous snapshot: its first sample has no rates.
    pub fn new() -> Self {
        Self::default()
    }

    /// The sample of `node` from `snapshot`, taken at `now` (`at` by the wall clock), against
    /// the snapshot of the previous call. `drops` are the dropped batches of the connected
    /// nodes as the node registry reports them.
    pub fn build(
        &mut self,
        node: Option<NodeId>,
        at: Timestamp,
        now: Instant,
        snapshot: &Snapshot,
        drops: &BTreeMap<NodeId, u64>,
    ) -> MetricsSample {
        let totals = Totals::of(snapshot);
        let mut sample = MetricsSample::empty(node, at);
        if let Some((then, before)) = self.previous.take() {
            let interval = now.saturating_duration_since(then);
            sample.interval_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
            let seconds = interval.as_secs_f64();
            if seconds > 0.0 {
                let rate =
                    |current: u64, earlier: u64| as_f64(current.saturating_sub(earlier)) / seconds;
                sample.api.requests_per_second = rate(totals.requests, before.requests);
                sample.ingest = MetricsIngest {
                    batches_per_second: rate(totals.ingest_batches, before.ingest_batches),
                    facts_per_second: rate(totals.ingest_facts, before.ingest_facts),
                };
            }
            let durations = delta(&totals.durations, &before.durations);
            sample.api.p50_ms = quantile_ms(snapshot, HTTP_DURATION, &durations, 0.5);
            sample.api.p99_ms = quantile_ms(snapshot, HTTP_DURATION, &durations, 0.99);
            let commits = delta(&totals.commits, &before.commits);
            sample.store.commit_p99_ms = quantile_ms(snapshot, STORE_COMMIT, &commits, 0.99);
        }
        self.previous = Some((now, totals));
        sample.store.data_bytes = gauge(snapshot, STORE_DATA_BYTES).unwrap_or_default();
        sample.store.file_bytes = gauge_sum(snapshot, STORE_FILE_BYTES);
        sample.raft = raft(snapshot);
        sample.jobs = MetricsJobs {
            running: labelled_gauge(snapshot, JOBS, "state", "running").unwrap_or_default(),
            waiting: labelled_gauge(snapshot, JOBS, "state", "waiting").unwrap_or_default(),
        };
        sample.sse = MetricsSse {
            subscribers: gauge(snapshot, SSE_SUBSCRIBERS).unwrap_or_default(),
        };
        sample.nodes = by_node(snapshot, NODE_BUFFER)
            .into_iter()
            .map(|(node, buffer_batches)| MetricsNode {
                node,
                buffer_batches,
                drops: drops.get(&node).copied(),
            })
            .collect();
        sample
    }
}

/// The cluster's sample at `at`: rates, sizes and counts summed over `samples` that are
/// current (neither stale nor unsupported), the jobs, terms, quantiles and lags at their
/// highest, the connected nodes of every controller. Without a current sample, an empty one.
pub fn cluster_sum(samples: &[MetricsSample], at: Timestamp) -> MetricsSample {
    let mut sum = MetricsSample::empty(None, at);
    let mut lags: BTreeMap<NodeId, u64> = BTreeMap::new();
    let mut nodes: BTreeMap<NodeId, MetricsNode> = BTreeMap::new();
    let current = samples
        .iter()
        .filter(|sample| !sample.stale && !sample.unsupported);
    for sample in current {
        sum.interval_ms = sum.interval_ms.max(sample.interval_ms);
        sum.api.requests_per_second += sample.api.requests_per_second;
        sum.api.p50_ms = max_of(sum.api.p50_ms, sample.api.p50_ms);
        sum.api.p99_ms = max_of(sum.api.p99_ms, sample.api.p99_ms);
        sum.store.data_bytes = sum.store.data_bytes.saturating_add(sample.store.data_bytes);
        sum.store.file_bytes = match (sum.store.file_bytes, sample.store.file_bytes) {
            (Some(a), Some(b)) => Some(a.saturating_add(b)),
            (a, b) => a.or(b),
        };
        sum.store.commit_p99_ms = max_of(sum.store.commit_p99_ms, sample.store.commit_p99_ms);
        sum.raft.term = sum.raft.term.max(sample.raft.term);
        for lag in &sample.raft.lag {
            let entries = lags.entry(lag.node).or_default();
            *entries = (*entries).max(lag.entries);
        }
        sum.jobs.running = sum.jobs.running.max(sample.jobs.running);
        sum.jobs.waiting = sum.jobs.waiting.max(sample.jobs.waiting);
        sum.ingest.batches_per_second += sample.ingest.batches_per_second;
        sum.ingest.facts_per_second += sample.ingest.facts_per_second;
        sum.sse.subscribers = sum.sse.subscribers.saturating_add(sample.sse.subscribers);
        for node in &sample.nodes {
            nodes
                .entry(node.node)
                .and_modify(|known| {
                    known.buffer_batches = known.buffer_batches.max(node.buffer_batches);
                    known.drops = max_of(known.drops, node.drops);
                })
                .or_insert_with(|| node.clone());
        }
    }
    sum.raft.lag = lags
        .into_iter()
        .map(|(node, entries)| MetricsLag { node, entries })
        .collect();
    sum.nodes = nodes.into_values().collect();
    sum
}

fn max_of<T: PartialOrd>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if b > a { b } else { a }),
        (a, b) => a.or(b),
    }
}

#[allow(clippy::cast_precision_loss)]
fn as_f64(value: u64) -> f64 {
    value as f64
}

/// A gauge value as a whole count (negative and fractional values are cut).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn as_count(value: f64) -> u64 {
    if value.is_finite() && value > 0.0 {
        value as u64
    } else {
        0
    }
}

/// The position of label `name` in the family's labels.
fn label_index(family: &FamilySnapshot, name: &str) -> Option<usize> {
    family.desc.labels.iter().position(|label| *label == name)
}

fn label<'a>(family: &FamilySnapshot, series: &'a Series, name: &str) -> Option<&'a str> {
    label_index(family, name).and_then(|index| series.labels.get(index))
}

/// Whether a series is the excluded one (`label` equal to `value`).
fn excluded(family: &FamilySnapshot, series: &Series, exclude: Option<(&str, &str)>) -> bool {
    exclude.is_some_and(|(name, value)| label(family, series, name) == Some(value))
}

/// The sum of a counter family's series, without the excluded ones.
fn counter_total(snapshot: &Snapshot, name: &str, exclude: Option<(&str, &str)>) -> u64 {
    let Some(family) = snapshot.family(name) else {
        return 0;
    };
    family
        .series
        .iter()
        .filter(|series| !excluded(family, series, exclude))
        .filter_map(|series| match series.value {
            Value::Counter(total) => Some(total),
            Value::Gauge(value) => Some(as_count(value)),
            Value::Histogram(_) => None,
        })
        .fold(0, u64::wrapping_add)
}

/// The cumulative bucket counts of a histogram family, summed over its series without the
/// excluded ones.
fn histogram_total(snapshot: &Snapshot, name: &str, exclude: Option<(&str, &str)>) -> Vec<u64> {
    let Some(family) = snapshot.family(name) else {
        return Vec::new();
    };
    let mut total: Vec<u64> = Vec::new();
    for series in &family.series {
        if excluded(family, series, exclude) {
            continue;
        }
        if let Value::Histogram(value) = &series.value {
            if total.len() < value.buckets.len() {
                total.resize(value.buckets.len(), 0);
            }
            for (sum, count) in total.iter_mut().zip(&value.buckets) {
                *sum = sum.wrapping_add(*count);
            }
        }
    }
    total
}

/// The change of cumulative bucket counts (empty when the shapes differ).
fn delta(now: &[u64], then: &[u64]) -> Vec<u64> {
    if then.is_empty() {
        return now.to_vec();
    }
    if now.len() != then.len() {
        return Vec::new();
    }
    now.iter()
        .zip(then)
        .map(|(now, then)| now.saturating_sub(*then))
        .collect()
}

/// Quantile `q` of the cumulative bucket counts `buckets` of histogram family `name`, in
/// milliseconds; `None` without observations.
fn quantile_ms(snapshot: &Snapshot, name: &str, buckets: &[u64], q: f64) -> Option<f64> {
    let family = snapshot.family(name)?;
    let Kind::Histogram { bounds, per_second } = family.desc.kind else {
        return None;
    };
    let value = quantile(bounds, buckets, q)?;
    Some(value * 1_000.0 / as_f64(per_second))
}

/// Quantile `q` of cumulative bucket counts (one per bound and `+Inf` last), in the unit of
/// the bounds, interpolated linearly inside its bucket; the highest bound when it falls in
/// `+Inf`.
fn quantile(bounds: &[u64], buckets: &[u64], q: f64) -> Option<f64> {
    let total = *buckets.last()?;
    if total == 0 {
        return None;
    }
    let rank = q.clamp(0.0, 1.0) * as_f64(total);
    let mut below = 0_u64;
    let mut lower = 0.0;
    for (index, count) in buckets.iter().enumerate() {
        if as_f64(*count) >= rank && *count > below {
            let Some(upper) = bounds.get(index) else {
                return Some(lower);
            };
            let upper = as_f64(*upper);
            let fraction = (rank - as_f64(below)) / as_f64(count - below);
            return Some(lower + (upper - lower) * fraction.clamp(0.0, 1.0));
        }
        below = *count;
        if let Some(bound) = bounds.get(index) {
            lower = as_f64(*bound);
        }
    }
    Some(lower)
}

/// The value of a gauge family of one series.
fn gauge(snapshot: &Snapshot, name: &str) -> Option<u64> {
    let family = snapshot.family(name)?;
    family.series.iter().find_map(|series| match series.value {
        Value::Gauge(value) => Some(as_count(value)),
        Value::Counter(total) => Some(total),
        Value::Histogram(_) => None,
    })
}

/// The sum of a gauge family's series; `None` when it has none.
fn gauge_sum(snapshot: &Snapshot, name: &str) -> Option<u64> {
    let family = snapshot.family(name)?;
    let mut sum = None;
    for series in &family.series {
        if let Value::Gauge(value) = series.value {
            sum = Some(sum.unwrap_or(0_u64).saturating_add(as_count(value)));
        }
    }
    sum
}

/// The value of the series of a gauge family whose label `name` is `value`.
fn labelled_gauge(snapshot: &Snapshot, family: &str, name: &str, value: &str) -> Option<u64> {
    let family = snapshot.family(family)?;
    family.series.iter().find_map(|series| match series.value {
        Value::Gauge(gauge) if label(family, series, name) == Some(value) => Some(as_count(gauge)),
        _ => None,
    })
}

/// The series of a gauge family with a `node` label, by node id.
fn by_node(snapshot: &Snapshot, name: &str) -> Vec<(NodeId, u64)> {
    let Some(family) = snapshot.family(name) else {
        return Vec::new();
    };
    let mut values: Vec<(NodeId, u64)> = family
        .series
        .iter()
        .filter_map(|series| {
            let node = label(family, series, "node")?.parse::<u64>().ok()?;
            match series.value {
                Value::Gauge(value) => Some((NodeId(node), as_count(value))),
                _ => None,
            }
        })
        .collect();
    values.sort_by_key(|(node, _)| *node);
    values
}

fn raft(snapshot: &Snapshot) -> MetricsRaft {
    let role = snapshot.family(RAFT_ROLE).and_then(|family| {
        family.series.iter().find_map(|series| match series.value {
            Value::Gauge(value) if value >= 1.0 => label(family, series, "role").map(str::to_owned),
            _ => None,
        })
    });
    MetricsRaft {
        role,
        term: gauge(snapshot, RAFT_TERM).unwrap_or_default(),
        lag: by_node(snapshot, RAFT_LAG)
            .into_iter()
            .map(|(node, entries)| MetricsLag { node, entries })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tenko_core::metrics::{
        Collect, Counter, CounterVec, Desc, Gauge, GaugeVec, Histogram, HistogramVec, Registry,
    };

    use super::*;

    /// Bounds in microseconds: 1 ms, 10 ms, 100 ms.
    const BOUNDS: [u64; 3] = [1_000, 10_000, 100_000];

    static REQUESTS: CounterVec = CounterVec::fixed(
        Desc::counter(HTTP_REQUESTS, "Requests.").labels(&["route", "method", "status"]),
        &[
            &["/api/v1/prefixes", "GET", "200"],
            &["/api/v1/hosts", "POST", "201"],
            &["ui", "GET", "200"],
        ],
    );
    static DURATION: HistogramVec = HistogramVec::fixed(
        Desc::histogram(HTTP_DURATION, "Durations.", &BOUNDS, 1_000_000).labels(&["class"]),
        &[&["prefixes"], &["ui"]],
    );
    static COMMIT: Histogram = Histogram::new(Desc::histogram(
        STORE_COMMIT,
        "Commits.",
        &BOUNDS,
        1_000_000,
    ));
    static BATCHES: Counter = Counter::new(Desc::counter(INGEST_BATCHES, "Batches."));
    static FACTS: Counter = Counter::new(Desc::counter(INGEST_FACTS, "Facts."));
    static DATA: Gauge = Gauge::new(Desc::gauge(STORE_DATA_BYTES, "Data.").unit("bytes"));
    static FILES: GaugeVec = GaugeVec::fixed(
        Desc::gauge(STORE_FILE_BYTES, "Files.")
            .labels(&["file"])
            .unit("bytes"),
        &[&["log"], &["state"], &["snapshots"]],
    );
    static ROLE: GaugeVec = GaugeVec::fixed(
        Desc::gauge(RAFT_ROLE, "Role.").labels(&["role"]),
        &[&["leader"], &["follower"]],
    );
    static TERM: Gauge = Gauge::new(Desc::gauge(RAFT_TERM, "Term."));
    static LAG: GaugeVec = GaugeVec::new(Desc::gauge(RAFT_LAG, "Lag.").labels(&["node"]));
    static JOB_STATES: GaugeVec = GaugeVec::fixed(
        Desc::gauge(JOBS, "Jobs.").labels(&["state"]),
        &[&["queued"], &["running"], &["waiting"]],
    );
    static SUBSCRIBERS: Gauge = Gauge::new(Desc::gauge(SSE_SUBSCRIBERS, "Streams."));
    static BUFFERS: GaugeVec =
        GaugeVec::new(Desc::gauge(NODE_BUFFER, "Buffers.").labels(&["node"]));

    fn registry() -> Registry {
        LAG.seal_slots(9);
        BUFFERS.seal_slots(16);
        let registry = Registry::new();
        for family in [
            &REQUESTS as &'static dyn Collect,
            &DURATION,
            &COMMIT,
            &BATCHES,
            &FACTS,
            &DATA,
            &FILES,
            &ROLE,
            &TERM,
            &LAG,
            &JOB_STATES,
            &SUBSCRIBERS,
            &BUFFERS,
        ] {
            registry.register(family);
        }
        registry
    }

    fn close(a: Option<f64>, b: f64) -> bool {
        a.is_some_and(|a| (a - b).abs() < 1e-6)
    }

    #[test]
    fn quantiles_interpolate_inside_their_bucket() {
        // 10 observations: 4 below 1 ms, 4 between 1 and 10 ms, 2 between 10 and 100 ms.
        let buckets = [4, 8, 10, 10];
        assert!(close(
            quantile(&BOUNDS, &buckets, 0.5),
            1_000.0 + 9_000.0 * 0.25
        ));
        assert!(close(quantile(&BOUNDS, &buckets, 0.2), 500.0));
        assert!(close(
            quantile(&BOUNDS, &buckets, 0.9),
            10_000.0 + 90_000.0 * 0.5
        ));
        // In the +Inf bucket: the highest bound.
        assert!(close(quantile(&BOUNDS, &[0, 0, 1, 3], 0.99), 100_000.0));
        assert_eq!(quantile(&BOUNDS, &[0, 0, 0, 0], 0.5), None);
        assert_eq!(quantile(&BOUNDS, &[], 0.5), None);
    }

    /// One second: 30 API requests (and 50 for the UI, which do not count), 4 batches of 25
    /// facts, 10 commits, and the gauges set.
    fn one_second_of_traffic() {
        REQUESTS.add(0, 20);
        REQUESTS.add(1, 10);
        REQUESTS.add(2, 50);
        for _ in 0..8 {
            DURATION.observe(0, 500);
        }
        DURATION.observe(0, 5_000);
        DURATION.observe(0, 50_000);
        for _ in 0..40 {
            DURATION.observe(1, 90_000);
        }
        BATCHES.add(4);
        FACTS.add(100);
        for _ in 0..10 {
            COMMIT.observe(2_000);
        }
        DATA.set(4_096.0);
        FILES.set(0, 1_000.0);
        FILES.set(1, 2_000.0);
        FILES.set(2, 500.0);
        ROLE.set_one_of(0..2, 0);
        TERM.set(3.0);
        LAG.set_labels(&["2"], 7.0);
        LAG.set_labels(&["1"], 0.0);
        JOB_STATES.set(1, 2.0);
        JOB_STATES.set(2, 1.0);
        SUBSCRIBERS.set(5.0);
        BUFFERS.set_labels(&["1001"], 12.0);
        BUFFERS.set_labels(&["1002"], 0.0);
    }

    #[test]
    fn a_sample_reads_rates_and_quantiles_from_two_snapshots_and_gauges_from_the_newer() {
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
        assert_eq!(first.interval_ms, 0);
        assert!(first.api.requests_per_second.abs() < f64::EPSILON);
        assert_eq!(first.api.p50_ms, None);
        assert_eq!(first.store.commit_p99_ms, None);

        one_second_of_traffic();
        let drops = BTreeMap::from([(NodeId(1001), 3)]);

        let second = builder.build(
            Some(NodeId(1)),
            at,
            start + Duration::from_secs(1),
            &registry.snapshot(),
            &drops,
        );
        assert_eq!(second.node, Some(NodeId(1)));
        assert_eq!(second.interval_ms, 1_000);
        assert!((second.api.requests_per_second - 30.0).abs() < 1e-9);
        // 10 API observations: 8 below 1 ms; the median is at 0.625 of the first bucket.
        assert!(close(second.api.p50_ms, 0.625), "{:?}", second.api);
        // The 99th: 9.9 of 10, in the 10 to 100 ms bucket.
        assert!(
            close(second.api.p99_ms, 10.0 + 90.0 * 0.9),
            "{:?}",
            second.api
        );
        assert!(close(second.store.commit_p99_ms, 1.0 + 9.0 * 0.99));
        assert!((second.ingest.batches_per_second - 4.0).abs() < 1e-9);
        assert!((second.ingest.facts_per_second - 100.0).abs() < 1e-9);
        assert_eq!(second.store.data_bytes, 4_096);
        assert_eq!(second.store.file_bytes, Some(3_500));
        assert_eq!(second.raft.role.as_deref(), Some("leader"));
        assert_eq!(second.raft.term, 3);
        assert_eq!(
            second.raft.lag,
            vec![
                MetricsLag {
                    node: NodeId(1),
                    entries: 0
                },
                MetricsLag {
                    node: NodeId(2),
                    entries: 7
                }
            ]
        );
        assert_eq!(
            second.jobs,
            MetricsJobs {
                running: 2,
                waiting: 1
            }
        );
        assert_eq!(second.sse.subscribers, 5);
        assert_eq!(
            second.nodes,
            vec![
                MetricsNode {
                    node: NodeId(1001),
                    buffer_batches: 12,
                    drops: Some(3)
                },
                MetricsNode {
                    node: NodeId(1002),
                    buffer_batches: 0,
                    drops: None
                }
            ]
        );

        // Half a second without traffic: no rates, no quantiles.
        let third = builder.build(
            Some(NodeId(1)),
            at,
            start + Duration::from_millis(1_500),
            &registry.snapshot(),
            &drops,
        );
        assert_eq!(third.interval_ms, 500);
        assert!(third.api.requests_per_second.abs() < f64::EPSILON);
        assert_eq!(third.api.p99_ms, None);
        assert_eq!(third.store.commit_p99_ms, None);
        assert_eq!(third.store.data_bytes, 4_096);

        let json = serde_json::to_value(&second).expect("json");
        assert_eq!(json["node"], 1);
        assert_eq!(json["raft"]["role"], "leader");
        assert!(json.get("stale").is_none() && json.get("unsupported").is_none());
        assert_eq!(json["nodes"][1].get("drops"), None);
    }

    #[test]
    fn a_registry_without_the_families_gives_an_empty_sample() {
        let registry = Registry::new();
        let mut builder = SampleBuilder::new();
        let now = Instant::now();
        builder.build(
            None,
            Timestamp::now(),
            now,
            &registry.snapshot(),
            &BTreeMap::new(),
        );
        let sample = builder.build(
            None,
            Timestamp::now(),
            now + Duration::from_secs(1),
            &registry.snapshot(),
            &BTreeMap::new(),
        );
        assert_eq!(sample.store.file_bytes, None);
        assert_eq!(sample.raft, MetricsRaft::default());
        assert_eq!(sample.nodes, Vec::<MetricsNode>::new());
        assert_eq!(sample.api.p50_ms, None);
    }

    fn sample(node: u64, requests: f64, p99: Option<f64>) -> MetricsSample {
        let mut sample = MetricsSample::empty(Some(NodeId(node)), Timestamp::now());
        sample.interval_ms = 1_000;
        sample.api.requests_per_second = requests;
        sample.api.p99_ms = p99;
        sample.store.data_bytes = 1_000;
        sample.store.file_bytes = Some(5_000);
        sample.store.commit_p99_ms = p99;
        sample.raft.role = Some(if node == 1 { "leader" } else { "follower" }.to_owned());
        sample.raft.term = node;
        sample.jobs.running = node;
        sample.ingest.facts_per_second = 10.0;
        sample.sse.subscribers = 2;
        sample
    }

    #[test]
    fn the_cluster_sums_rates_and_sizes_and_takes_the_highest_quantiles_and_lags() {
        let mut leader = sample(1, 30.0, Some(4.0));
        leader.raft.lag = vec![
            MetricsLag {
                node: NodeId(1),
                entries: 0,
            },
            MetricsLag {
                node: NodeId(2),
                entries: 5,
            },
        ];
        leader.nodes = vec![MetricsNode {
            node: NodeId(1001),
            buffer_batches: 3,
            drops: Some(1),
        }];
        let mut follower = sample(2, 12.5, Some(9.0));
        follower.raft.lag = vec![MetricsLag {
            node: NodeId(2),
            entries: 8,
        }];
        follower.nodes = vec![MetricsNode {
            node: NodeId(1002),
            buffer_batches: 4,
            drops: None,
        }];
        let mut stale = sample(3, 1_000.0, Some(500.0));
        stale.stale = true;
        let mut unsupported = MetricsSample::empty(Some(NodeId(4)), Timestamp::now());
        unsupported.unsupported = true;

        let at = Timestamp::now();
        let sum = cluster_sum(&[leader, follower, stale, unsupported], at);
        assert_eq!(sum.node, None);
        assert_eq!(sum.at, at);
        assert!((sum.api.requests_per_second - 42.5).abs() < 1e-9);
        assert_eq!(sum.api.p99_ms, Some(9.0));
        assert_eq!(sum.store.commit_p99_ms, Some(9.0));
        assert_eq!(sum.store.data_bytes, 2_000);
        assert_eq!(sum.store.file_bytes, Some(10_000));
        assert_eq!(sum.raft.role, None);
        assert_eq!(sum.raft.term, 2);
        assert_eq!(
            sum.raft.lag,
            vec![
                MetricsLag {
                    node: NodeId(1),
                    entries: 0
                },
                MetricsLag {
                    node: NodeId(2),
                    entries: 8
                }
            ]
        );
        assert_eq!(
            sum.jobs.running, 2,
            "the jobs are shared: the highest count"
        );
        assert!((sum.ingest.facts_per_second - 20.0).abs() < 1e-9);
        assert_eq!(sum.sse.subscribers, 4);
        assert_eq!(
            sum.nodes.iter().map(|node| node.node.0).collect::<Vec<_>>(),
            vec![1001, 1002]
        );
        assert_eq!(sum.interval_ms, 1_000);

        let none = cluster_sum(&[], at);
        assert_eq!(none, MetricsSample::empty(None, at));
    }
}
