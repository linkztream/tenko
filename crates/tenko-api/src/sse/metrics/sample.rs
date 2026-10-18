//! The per-controller sample of the `metrics` topic: [`SampleBuilder`] turns two consecutive
//! snapshots of the metrics registry into a [`MetricsSample`], and [`cluster_sum`] merges the
//! samples of the controllers into the cluster's.
//!
//! Rates are the change of a counter over the interval between the two snapshots; quantiles
//! are interpolated linearly inside the bucket of the histogram's change that holds them (as
//! Prometheus' `histogram_quantile` does), so a quantile in the `+Inf` bucket reads as the
//! highest bound. Everything else is the gauge value of the newer snapshot.
//!
//! The DNS part ([`MetricsDns`]) is there while the registry holds the query counter of the
//! `dns` role (`tenko_dns_queries_total`, registered when the role starts); the families of
//! the encrypted transports and of the block lists are read when they are registered.

use std::{collections::BTreeMap, time::Instant};

use tenko_core::{
    NodeId, Timestamp,
    metrics::{FamilySnapshot, Kind, Series, Snapshot, Value},
};

use crate::dto::events::{
    MetricsDns, MetricsDnsBlocked, MetricsDnsCache, MetricsDnsConnections, MetricsDnsRcodes,
    MetricsDnsTransports, MetricsDnsUpstreams, MetricsIngest, MetricsJobs, MetricsLag, MetricsNode,
    MetricsRaft, MetricsSample, MetricsSse,
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
/// `tenko_dns_queries_total{proto,view,rcode}`: its presence says the `dns` role runs.
pub(crate) const DNS_QUERIES: &str = "tenko_dns_queries";
/// `tenko_dns_query_duration_seconds{proto}`.
pub(crate) const DNS_DURATION: &str = "tenko_dns_query_duration_seconds";
/// `tenko_dns_cache_hits_total{view}`.
pub(crate) const DNS_CACHE_HITS: &str = "tenko_dns_cache_hits";
/// `tenko_dns_cache_misses_total{view}`.
pub(crate) const DNS_CACHE_MISSES: &str = "tenko_dns_cache_misses";
/// `tenko_dns_cache_stale_total`.
pub(crate) const DNS_CACHE_STALE: &str = "tenko_dns_cache_stale";
/// `tenko_dns_cache_entries`.
pub(crate) const DNS_CACHE_ENTRIES: &str = "tenko_dns_cache_entries";
/// `tenko_dns_upstream_queries_total{rule,upstream,transport,outcome}`.
pub(crate) const DNS_UPSTREAM_QUERIES: &str = "tenko_dns_upstream_queries";
/// `tenko_dns_upstream_rtt_seconds{upstream}`.
pub(crate) const DNS_UPSTREAM_RTT: &str = "tenko_dns_upstream_rtt_seconds";
/// `tenko_dns_blocked_total{list}`.
pub(crate) const DNS_BLOCKED: &str = "tenko_dns_blocked";
/// `tenko_dns_connections{proto}`.
pub(crate) const DNS_CONNECTIONS: &str = "tenko_dns_connections";
/// `tenko_dns_log_dropped_total`.
pub(crate) const DNS_LOG_DROPPED: &str = "tenko_dns_log_dropped";

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
    /// The `dns` role's, while it runs.
    dns: Option<DnsTotals>,
}

impl Totals {
    fn of(snapshot: &Snapshot) -> Self {
        Self {
            requests: counter_total(snapshot, HTTP_REQUESTS, Some(("route", UI_ROUTE))),
            durations: histogram_total(snapshot, HTTP_DURATION, Some(("class", UI_ROUTE))),
            commits: histogram_total(snapshot, STORE_COMMIT, None),
            ingest_batches: counter_total(snapshot, INGEST_BATCHES, None),
            ingest_facts: counter_total(snapshot, INGEST_FACTS, None),
            dns: DnsTotals::of(snapshot),
        }
    }
}

/// The running totals of the `dns` role in one snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DnsTotals {
    /// Queries by `proto`.
    transports: BTreeMap<String, u64>,
    /// Queries by `rcode`.
    rcodes: BTreeMap<String, u64>,
    /// Cumulative bucket counts of the query duration, summed over the transports.
    durations: Vec<u64>,
    cache_hits: u64,
    cache_misses: u64,
    cache_stale: u64,
    upstream_queries: u64,
    /// Cumulative bucket counts of the upstream round-trip time, summed over the upstreams.
    upstream_rtt: Vec<u64>,
    /// Blocked queries by `list`.
    blocked: BTreeMap<String, u64>,
    log_dropped: u64,
}

impl DnsTotals {
    /// The totals, or `None` when the registry has no query counter of the role.
    fn of(snapshot: &Snapshot) -> Option<Self> {
        snapshot.family(DNS_QUERIES)?;
        Some(Self {
            transports: counter_by(snapshot, DNS_QUERIES, "proto"),
            rcodes: counter_by(snapshot, DNS_QUERIES, "rcode"),
            durations: histogram_total(snapshot, DNS_DURATION, None),
            cache_hits: counter_total(snapshot, DNS_CACHE_HITS, None),
            cache_misses: counter_total(snapshot, DNS_CACHE_MISSES, None),
            cache_stale: counter_total(snapshot, DNS_CACHE_STALE, None),
            upstream_queries: counter_total(snapshot, DNS_UPSTREAM_QUERIES, None),
            upstream_rtt: histogram_total(snapshot, DNS_UPSTREAM_RTT, None),
            blocked: counter_by(snapshot, DNS_BLOCKED, "list"),
            log_dropped: counter_total(snapshot, DNS_LOG_DROPPED, None),
        })
    }
}

/// The RCODE values a sample names; the others count as `other`.
const NAMED_RCODES: [&str; 4] = ["noerror", "nxdomain", "servfail", "refused"];

/// The DNS part of a sample: the gauges of `snapshot`, and against the totals `before` taken
/// `seconds` earlier the rates and quantiles (none without `before`, as in a first sample).
fn dns_sample(
    snapshot: &Snapshot,
    totals: &DnsTotals,
    before: Option<(&DnsTotals, f64)>,
) -> MetricsDns {
    let mut dns = MetricsDns {
        cache: MetricsDnsCache {
            entries: gauge(snapshot, DNS_CACHE_ENTRIES).unwrap_or_default(),
            ..MetricsDnsCache::default()
        },
        connections: snapshot
            .family(DNS_CONNECTIONS)
            .map(|_| MetricsDnsConnections {
                dot: labelled_gauge(snapshot, DNS_CONNECTIONS, "proto", "dot").unwrap_or_default(),
                doh: labelled_gauge(snapshot, DNS_CONNECTIONS, "proto", "doh").unwrap_or_default(),
            }),
        ..MetricsDns::default()
    };
    let Some((before, seconds)) = before else {
        return dns;
    };
    let rate = |count: u64| {
        if seconds > 0.0 {
            as_f64(count) / seconds
        } else {
            0.0
        }
    };
    let by = |now: &BTreeMap<String, u64>, then: &BTreeMap<String, u64>, key: &str| {
        now.get(key)
            .copied()
            .unwrap_or_default()
            .saturating_sub(then.get(key).copied().unwrap_or_default())
    };
    let transport = |name: &str| rate(by(&totals.transports, &before.transports, name));
    dns.transports = MetricsDnsTransports {
        udp: transport("udp"),
        tcp: transport("tcp"),
        dot: transport("dot"),
        doh: transport("doh"),
    };
    let rcode = |name: &str| by(&totals.rcodes, &before.rcodes, name);
    let answered: u64 = totals.rcodes.keys().map(|name| rcode(name)).sum();
    let named: u64 = NAMED_RCODES.iter().map(|name| rcode(name)).sum();
    dns.queries_per_second = rate(answered);
    dns.rcodes = MetricsDnsRcodes {
        noerror: rate(rcode("noerror")),
        nxdomain: rate(rcode("nxdomain")),
        servfail: rate(rcode("servfail")),
        refused: rate(rcode("refused")),
        other: rate(answered.saturating_sub(named)),
    };
    let durations = delta(&totals.durations, &before.durations);
    dns.p50_ms = quantile_ms(snapshot, DNS_DURATION, &durations, 0.5);
    dns.p99_ms = quantile_ms(snapshot, DNS_DURATION, &durations, 0.99);
    let hits = totals.cache_hits.saturating_sub(before.cache_hits);
    let misses = totals.cache_misses.saturating_sub(before.cache_misses);
    dns.cache.hits_per_second = rate(hits);
    dns.cache.misses_per_second = rate(misses);
    dns.cache.hit_ratio = ratio(hits, misses);
    dns.cache.stale_per_second = rate(totals.cache_stale.saturating_sub(before.cache_stale));
    let rtt = delta(&totals.upstream_rtt, &before.upstream_rtt);
    dns.upstreams = MetricsDnsUpstreams {
        queries_per_second: rate(
            totals
                .upstream_queries
                .saturating_sub(before.upstream_queries),
        ),
        p99_ms: quantile_ms(snapshot, DNS_UPSTREAM_RTT, &rtt, 0.99),
    };
    dns.blocked = totals
        .blocked
        .keys()
        .map(|list| MetricsDnsBlocked {
            list: list.clone(),
            per_second: rate(by(&totals.blocked, &before.blocked, list)),
        })
        .collect();
    dns.log_dropped_per_second = rate(totals.log_dropped.saturating_sub(before.log_dropped));
    dns
}

/// `part` over `part + rest`; `None` when both are zero.
fn ratio(part: u64, rest: u64) -> Option<f64> {
    let whole = part.saturating_add(rest);
    (whole > 0).then(|| as_f64(part) / as_f64(whole))
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
        let previous = self.previous.take();
        sample.dns = totals.dns.as_ref().map(|dns| {
            let before = previous.as_ref().and_then(|(then, before)| {
                let seconds = now.saturating_duration_since(*then).as_secs_f64();
                before.dns.as_ref().map(|before| (before, seconds))
            });
            dns_sample(snapshot, dns, before)
        });
        if let Some((then, before)) = previous {
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
        if let Some(dns) = &sample.dns {
            add_dns(sum.dns.get_or_insert_with(MetricsDns::default), dns);
        }
    }
    if let Some(dns) = &mut sum.dns {
        let hits = dns.cache.hits_per_second;
        let lookups = hits + dns.cache.misses_per_second;
        dns.cache.hit_ratio = (lookups > 0.0).then(|| hits / lookups);
    }
    sum.raft.lag = lags
        .into_iter()
        .map(|(node, entries)| MetricsLag { node, entries })
        .collect();
    sum.nodes = nodes.into_values().collect();
    sum
}

/// Adds a controller's DNS figures to the cluster's: rates, entries and connections summed,
/// the quantiles at their highest, the block lists by name. The hit ratio is set after the
/// last one, from the summed hits and misses.
fn add_dns(sum: &mut MetricsDns, dns: &MetricsDns) {
    sum.queries_per_second += dns.queries_per_second;
    sum.transports.udp += dns.transports.udp;
    sum.transports.tcp += dns.transports.tcp;
    sum.transports.dot += dns.transports.dot;
    sum.transports.doh += dns.transports.doh;
    sum.p50_ms = max_of(sum.p50_ms, dns.p50_ms);
    sum.p99_ms = max_of(sum.p99_ms, dns.p99_ms);
    sum.rcodes.noerror += dns.rcodes.noerror;
    sum.rcodes.nxdomain += dns.rcodes.nxdomain;
    sum.rcodes.servfail += dns.rcodes.servfail;
    sum.rcodes.refused += dns.rcodes.refused;
    sum.rcodes.other += dns.rcodes.other;
    sum.cache.hits_per_second += dns.cache.hits_per_second;
    sum.cache.misses_per_second += dns.cache.misses_per_second;
    sum.cache.stale_per_second += dns.cache.stale_per_second;
    sum.cache.entries = sum.cache.entries.saturating_add(dns.cache.entries);
    sum.upstreams.queries_per_second += dns.upstreams.queries_per_second;
    sum.upstreams.p99_ms = max_of(sum.upstreams.p99_ms, dns.upstreams.p99_ms);
    for blocked in &dns.blocked {
        match sum
            .blocked
            .iter_mut()
            .find(|known| known.list == blocked.list)
        {
            Some(known) => known.per_second += blocked.per_second,
            None => sum.blocked.push(blocked.clone()),
        }
    }
    sum.blocked.sort_by(|a, b| a.list.cmp(&b.list));
    if let Some(connections) = &dns.connections {
        let total = sum.connections.get_or_insert_with(Default::default);
        total.dot = total.dot.saturating_add(connections.dot);
        total.doh = total.doh.saturating_add(connections.doh);
    }
    sum.log_dropped_per_second += dns.log_dropped_per_second;
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

/// The totals of a counter family by the value of its label `name`, summed over the other
/// labels; empty without the family.
fn counter_by(snapshot: &Snapshot, family: &str, name: &str) -> BTreeMap<String, u64> {
    let mut totals: BTreeMap<String, u64> = BTreeMap::new();
    let Some(family) = snapshot.family(family) else {
        return totals;
    };
    for series in &family.series {
        let Some(value) = label(family, series, name) else {
            continue;
        };
        let count = match series.value {
            Value::Counter(total) => total,
            Value::Gauge(value) => as_count(value),
            Value::Histogram(_) => continue,
        };
        let total = totals.entry(value.to_owned()).or_default();
        *total = total.wrapping_add(count);
    }
    totals
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

    static DNS_QUERY_COUNTER: CounterVec = CounterVec::fixed(
        Desc::counter(DNS_QUERIES, "Queries.").labels(&["proto", "view", "rcode"]),
        &[
            &["udp", "default", "noerror"],
            &["udp", "default", "nxdomain"],
            &["tcp", "named", "noerror"],
            &["dot", "default", "servfail"],
            &["doh", "default", "refused"],
            &["udp", "default", "formerr"],
            &["udp", "named", "other"],
        ],
    );
    static DNS_LATENCY: HistogramVec = HistogramVec::fixed(
        Desc::histogram(DNS_DURATION, "Durations.", &BOUNDS, 1_000_000).labels(&["proto"]),
        &[&["udp"], &["tcp"]],
    );
    static DNS_HITS: CounterVec = CounterVec::fixed(
        Desc::counter(DNS_CACHE_HITS, "Hits.").labels(&["view"]),
        &[&["default"], &["named"]],
    );
    static DNS_MISSES: CounterVec = CounterVec::fixed(
        Desc::counter(DNS_CACHE_MISSES, "Misses.").labels(&["view"]),
        &[&["default"], &["named"]],
    );
    static DNS_STALE: Counter = Counter::new(Desc::counter(DNS_CACHE_STALE, "Stale."));
    static DNS_ENTRIES: Gauge = Gauge::new(Desc::gauge(DNS_CACHE_ENTRIES, "Entries."));
    static DNS_UPSTREAM: CounterVec = CounterVec::fixed(
        Desc::counter(DNS_UPSTREAM_QUERIES, "Upstream.").labels(&[
            "rule",
            "upstream",
            "transport",
            "outcome",
        ]),
        &[
            &["default", "192.0.2.1:53", "plain", "ok"],
            &["example.test", "198.51.100.53:853", "dot", "timeout"],
        ],
    );
    static DNS_RTT: HistogramVec = HistogramVec::fixed(
        Desc::histogram(DNS_UPSTREAM_RTT, "Round trips.", &BOUNDS, 1_000_000).labels(&["upstream"]),
        &[&["192.0.2.1:53"]],
    );
    static DNS_BLOCKS: CounterVec = CounterVec::fixed(
        Desc::counter(DNS_BLOCKED, "Blocked.").labels(&["list"]),
        &[&["ads"], &["malware"]],
    );
    static DNS_OPEN: GaugeVec = GaugeVec::fixed(
        Desc::gauge(DNS_CONNECTIONS, "Connections.").labels(&["proto"]),
        &[&["dot"], &["doh"]],
    );
    static DNS_DROPPED: Counter = Counter::new(Desc::counter(DNS_LOG_DROPPED, "Dropped."));

    /// A registry with the families of the `dns` role: the query path and the cache always,
    /// the upstreams, the block lists, the encrypted transports and the log when `full`.
    fn dns_registry(full: bool) -> Registry {
        let registry = Registry::new();
        for family in [
            &DNS_QUERY_COUNTER as &'static dyn Collect,
            &DNS_LATENCY,
            &DNS_HITS,
            &DNS_MISSES,
            &DNS_STALE,
            &DNS_ENTRIES,
        ] {
            registry.register(family);
        }
        if full {
            for family in [
                &DNS_UPSTREAM as &'static dyn Collect,
                &DNS_RTT,
                &DNS_BLOCKS,
                &DNS_OPEN,
                &DNS_DROPPED,
            ] {
                registry.register(family);
            }
        }
        registry
    }

    /// Two seconds of DNS traffic: 200 queries (120 NOERROR, 40 NXDOMAIN, 10 SERVFAIL over
    /// DoT, 10 REFUSED over DoH, 20 others), 90 cache hits and 30 misses, 4 stale answers, 30
    /// upstream exchanges, 50 and 6 blocked queries, 2 dropped log entries.
    fn two_seconds_of_dns() {
        DNS_QUERY_COUNTER.add(0, 100);
        DNS_QUERY_COUNTER.add(1, 40);
        DNS_QUERY_COUNTER.add(2, 20);
        DNS_QUERY_COUNTER.add(3, 10);
        DNS_QUERY_COUNTER.add(4, 10);
        DNS_QUERY_COUNTER.add(5, 12);
        DNS_QUERY_COUNTER.add(6, 8);
        // 100 answers: 90 below 1 ms, 10 between 10 and 100 ms.
        for _ in 0..90 {
            DNS_LATENCY.observe(0, 200);
        }
        for _ in 0..10 {
            DNS_LATENCY.observe(1, 40_000);
        }
        DNS_HITS.add(0, 80);
        DNS_HITS.add(1, 10);
        DNS_MISSES.add(0, 30);
        DNS_STALE.add(4);
        DNS_ENTRIES.set(1_234.0);
        DNS_UPSTREAM.add(0, 24);
        DNS_UPSTREAM.add(1, 6);
        for _ in 0..24 {
            DNS_RTT.observe(0, 5_000);
        }
        DNS_BLOCKS.add(0, 50);
        DNS_BLOCKS.add(1, 6);
        DNS_OPEN.set(0, 3.0);
        DNS_OPEN.set(1, 1.0);
        DNS_DROPPED.add(2);
    }

    #[test]
    fn a_node_with_the_dns_role_has_its_queries_cache_upstreams_and_lists_in_the_sample() {
        let registry = dns_registry(true);
        let mut builder = SampleBuilder::new();
        let start = Instant::now();
        let at = Timestamp::now();
        let first = builder.build(None, at, start, &registry.snapshot(), &BTreeMap::new());
        let dns = first.dns.expect("the role's families are registered");
        assert!(dns.queries_per_second.abs() < f64::EPSILON);
        assert_eq!(dns.p50_ms, None);
        assert_eq!(dns.cache.hit_ratio, None);
        assert_eq!(
            dns.connections,
            Some(MetricsDnsConnections { dot: 0, doh: 0 })
        );

        two_seconds_of_dns();
        let second = builder.build(
            None,
            at,
            start + Duration::from_secs(2),
            &registry.snapshot(),
            &BTreeMap::new(),
        );
        let dns = second.dns.clone().expect("dns");
        let near = |a: f64, b: f64| (a - b).abs() < 1e-9;
        assert!(near(dns.queries_per_second, 100.0), "{dns:?}");
        assert_eq!(
            dns.transports,
            MetricsDnsTransports {
                udp: 80.0,
                tcp: 10.0,
                dot: 5.0,
                doh: 5.0,
            }
        );
        assert_eq!(
            dns.rcodes,
            MetricsDnsRcodes {
                noerror: 60.0,
                nxdomain: 20.0,
                servfail: 5.0,
                refused: 5.0,
                other: 10.0,
            }
        );
        // The median at 50 of 100, in the first bucket of 90: 0.5 / 0.9 of 1 ms.
        assert!(close(dns.p50_ms, 50.0 / 90.0), "{dns:?}");
        // The 99th at 99 of 100: 9 of the 10 in the 10 to 100 ms bucket.
        assert!(close(dns.p99_ms, 10.0 + 90.0 * 0.9), "{dns:?}");
        assert!(close(dns.cache.hit_ratio, 0.75));
        assert!(near(dns.cache.hits_per_second, 45.0));
        assert!(near(dns.cache.misses_per_second, 15.0));
        assert!(near(dns.cache.stale_per_second, 2.0));
        assert_eq!(dns.cache.entries, 1_234);
        assert!(near(dns.upstreams.queries_per_second, 15.0));
        // 24 round trips of 5 ms: the 99th in the 1 to 10 ms bucket.
        assert!(close(dns.upstreams.p99_ms, 1.0 + 9.0 * 0.99), "{dns:?}");
        assert_eq!(
            dns.blocked,
            vec![
                MetricsDnsBlocked {
                    list: "ads".to_owned(),
                    per_second: 25.0
                },
                MetricsDnsBlocked {
                    list: "malware".to_owned(),
                    per_second: 3.0
                }
            ]
        );
        assert_eq!(
            dns.connections,
            Some(MetricsDnsConnections { dot: 3, doh: 1 })
        );
        assert!(near(dns.log_dropped_per_second, 1.0));

        // A quiet second: no rates and no quantiles, the gauges stay.
        let third = builder.build(
            None,
            at,
            start + Duration::from_secs(3),
            &registry.snapshot(),
            &BTreeMap::new(),
        );
        let dns = third.dns.expect("dns");
        assert!(dns.queries_per_second.abs() < f64::EPSILON);
        assert_eq!(
            (dns.p50_ms, dns.p99_ms, dns.upstreams.p99_ms),
            (None, None, None)
        );
        assert_eq!(dns.cache.hit_ratio, None);
        assert_eq!(dns.cache.entries, 1_234);
        assert!(
            dns.blocked
                .iter()
                .all(|list| list.per_second.abs() < f64::EPSILON)
        );

        let json = serde_json::to_value(&second).expect("json");
        assert_eq!(json["dns"]["transports"]["dot"], 5.0);
        assert_eq!(json["dns"]["blocked"][0]["list"], "ads");
        assert_eq!(json["dns"]["connections"]["dot"], 3);
        let back: MetricsSample = serde_json::from_value(json).expect("back");
        assert_eq!(back, second);
    }

    #[test]
    fn the_dns_part_is_absent_without_the_role_and_optional_parts_without_their_families() {
        let none = Registry::new();
        let mut builder = SampleBuilder::new();
        let sample = builder.build(
            None,
            Timestamp::now(),
            Instant::now(),
            &none.snapshot(),
            &BTreeMap::new(),
        );
        assert_eq!(sample.dns, None);
        let json = serde_json::to_value(&sample).expect("json");
        assert!(json.get("dns").is_none());

        // The role without DoT and DoH and before the block lists: no connections, no lists.
        let registry = dns_registry(false);
        let mut builder = SampleBuilder::new();
        let start = Instant::now();
        builder.build(
            None,
            Timestamp::now(),
            start,
            &registry.snapshot(),
            &BTreeMap::new(),
        );
        let sample = builder.build(
            None,
            Timestamp::now(),
            start + Duration::from_secs(1),
            &registry.snapshot(),
            &BTreeMap::new(),
        );
        let dns = sample.dns.expect("dns");
        assert_eq!(dns.connections, None);
        assert_eq!(dns.blocked, Vec::new());
        assert_eq!(dns.upstreams, MetricsDnsUpstreams::default());
        let json = serde_json::to_value(&dns).expect("json");
        assert!(json.get("connections").is_none() && json.get("p99_ms").is_none());
    }

    #[test]
    fn the_cluster_sums_the_dns_rates_and_takes_the_highest_quantiles() {
        let dns = |qps: f64, hits: f64, misses: f64, p99: f64, lists: &[(&str, f64)]| MetricsDns {
            queries_per_second: qps,
            transports: MetricsDnsTransports {
                udp: qps,
                ..MetricsDnsTransports::default()
            },
            p50_ms: Some(p99 / 10.0),
            p99_ms: Some(p99),
            rcodes: MetricsDnsRcodes {
                noerror: qps,
                ..MetricsDnsRcodes::default()
            },
            cache: MetricsDnsCache {
                hit_ratio: ratio(1, 1),
                hits_per_second: hits,
                misses_per_second: misses,
                stale_per_second: 1.0,
                entries: 100,
            },
            upstreams: MetricsDnsUpstreams {
                queries_per_second: misses,
                p99_ms: Some(p99 * 2.0),
            },
            blocked: lists
                .iter()
                .map(|(list, per_second)| MetricsDnsBlocked {
                    list: (*list).to_owned(),
                    per_second: *per_second,
                })
                .collect(),
            connections: Some(MetricsDnsConnections { dot: 2, doh: 1 }),
            log_dropped_per_second: 0.5,
        };
        let mut one = sample(1, 1.0, None);
        one.dns = Some(dns(
            100.0,
            30.0,
            10.0,
            4.0,
            &[("malware", 1.0), ("ads", 5.0)],
        ));
        let mut two = sample(2, 1.0, None);
        two.dns = Some(dns(50.0, 10.0, 30.0, 12.0, &[("ads", 2.0)]));
        let three = sample(3, 1.0, None);
        let mut stale = sample(4, 1.0, None);
        stale.stale = true;
        stale.dns = Some(dns(1_000.0, 1.0, 1.0, 900.0, &[]));

        let sum = cluster_sum(&[one, two, three, stale], Timestamp::now());
        let dns = sum.dns.expect("two controllers run the role");
        assert!((dns.queries_per_second - 150.0).abs() < 1e-9);
        assert!((dns.transports.udp - 150.0).abs() < 1e-9);
        assert!((dns.rcodes.noerror - 150.0).abs() < 1e-9);
        assert_eq!(dns.p50_ms, Some(1.2));
        assert_eq!(dns.p99_ms, Some(12.0));
        assert_eq!(dns.upstreams.p99_ms, Some(24.0));
        // 40 hits of 80 lookups, not the mean of the two ratios.
        assert_eq!(dns.cache.hit_ratio, Some(0.5));
        assert_eq!(dns.cache.entries, 200);
        assert!((dns.cache.stale_per_second - 2.0).abs() < 1e-9);
        assert_eq!(
            dns.blocked,
            vec![
                MetricsDnsBlocked {
                    list: "ads".to_owned(),
                    per_second: 7.0
                },
                MetricsDnsBlocked {
                    list: "malware".to_owned(),
                    per_second: 1.0
                }
            ]
        );
        assert_eq!(
            dns.connections,
            Some(MetricsDnsConnections { dot: 4, doh: 2 })
        );
        assert!((dns.log_dropped_per_second - 1.0).abs() < 1e-9);

        let without = cluster_sum(&[sample(1, 1.0, None)], Timestamp::now());
        assert_eq!(without.dns, None);
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
