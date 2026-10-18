//! The metric families of the DNS engine (plan section 3.3, OPS-21), declared once so that
//! every package registers the same names. The engine counts per worker shard; the
//! registry of `tenko_core::metrics` sums the shards when it encodes (docs/observability.md).
//! Counter names carry no `_total`: the encoder adds it.

use tenko_core::{
    dns::QueryTransport,
    metrics::{Counter, CounterVec, Desc, Gauge, HistogramVec, Registry},
};

/// Query latency buckets in microseconds: 50 µs to 2 s.
pub const LATENCY_BUCKETS_US: &[u64] = &[
    50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000, 2_000_000,
];

/// Signing duration buckets in microseconds: 1 ms to 5 min.
pub const SIGNING_BUCKETS_US: &[u64] = &[
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    60_000_000,
    300_000_000,
];

/// Queries answered, by transport (`udp`, `tcp`, `dot`, `doh`), view and RCODE.
pub const QUERIES: Desc =
    Desc::counter("tenko_dns_queries", "DNS queries answered").labels(&["proto", "view", "rcode"]);

/// Time from a query's arrival to its answer.
pub const QUERY_DURATION: Desc = Desc::histogram(
    "tenko_dns_query_duration_seconds",
    "Time from a DNS query's arrival to its answer",
    LATENCY_BUCKETS_US,
    1_000_000,
)
.labels(&["proto"]);

/// Answers from the cache, by view (`default`, `named`).
pub const CACHE_HITS: Desc =
    Desc::counter("tenko_dns_cache_hits", "DNS answers from the cache").labels(&["view"]);

/// Forwarded queries the cache could not answer, by view.
pub const CACHE_MISSES: Desc = Desc::counter(
    "tenko_dns_cache_misses",
    "DNS queries the cache could not answer",
)
.labels(&["view"]);

/// Stale answers served while the upstreams failed or were slow (RFC 8767).
pub const CACHE_STALE: Desc = Desc::counter(
    "tenko_dns_cache_stale",
    "Stale DNS answers served while upstreams failed",
);

/// Entries in the cache.
pub const CACHE_ENTRIES: Desc = Desc::gauge("tenko_dns_cache_entries", "Entries in the DNS cache");

/// Exchanges with upstreams, by rule, upstream, transport and outcome (`ok`, `servfail`,
/// `timeout`, `unreachable`, `malformed`); read from the pool ([`crate::pool`]).
pub const UPSTREAM_QUERIES: Desc = Desc::counter(
    "tenko_dns_upstream_queries",
    "DNS queries sent to upstream resolvers",
)
.labels(&["rule", "upstream", "transport", "outcome"]);

/// Round-trip time of answered exchanges, by upstream.
pub const UPSTREAM_RTT: Desc = Desc::histogram(
    "tenko_dns_upstream_rtt_seconds",
    "Round-trip time of DNS queries to upstream resolvers",
    LATENCY_BUCKETS_US,
    1_000_000,
)
.labels(&["upstream"]);

/// Responses dropped by response rate limiting, by response kind (`answer`, `nodata`,
/// `nxdomain`, `referral`, `error`); read from the limiter ([`crate::rate::limiter`]).
pub const RRL_DROPPED: Desc = Desc::counter(
    "tenko_dns_rrl_dropped",
    "DNS responses dropped by rate limiting",
)
.labels(&["kind"]);

/// Responses rate limiting sent as an empty truncated answer (the slip).
pub const RRL_SLIPPED: Desc = Desc::counter(
    "tenko_dns_rrl_slipped",
    "DNS responses rate limiting sent truncated",
);

/// Queries dropped by the per-client query limit.
pub const CLIENT_LIMITED: Desc = Desc::counter(
    "tenko_dns_client_limited",
    "DNS queries dropped by the per-client limit",
);

/// Queries blocked by a block list or an RPZ zone, by list (an RPZ zone under its zone
/// name); read from the policy's counters ([`crate::policy::counters`]).
pub const BLOCKED: Desc =
    Desc::counter("tenko_dns_blocked", "DNS queries blocked by policy").labels(&["list"]);

/// The serial each zone serves, by zone.
pub const ZONE_SERIAL: Desc =
    Desc::gauge("tenko_dns_zone_serial", "SOA serial served per zone").labels(&["zone"]);

/// Signing runs, by outcome (`ok`, `failed`).
pub const SIGNING_RUNS: Desc =
    Desc::counter("tenko_dns_signing_runs", "DNSSEC signing runs").labels(&["outcome"]);

/// Duration of signing runs.
pub const SIGNING_DURATION: Desc = Desc::histogram(
    "tenko_dns_signing_duration_seconds",
    "Duration of DNSSEC signing runs",
    SIGNING_BUCKETS_US,
    1_000_000,
);

/// Query log entries dropped because the log buffer was full.
pub const LOG_DROPPED: Desc =
    Desc::counter("tenko_dns_log_dropped", "DNS query log entries dropped");

/// Every family of the engine, for registration and the contracts document.
pub const ALL: [&Desc; 16] = [
    &QUERIES,
    &QUERY_DURATION,
    &CACHE_HITS,
    &CACHE_MISSES,
    &CACHE_STALE,
    &CACHE_ENTRIES,
    &UPSTREAM_QUERIES,
    &UPSTREAM_RTT,
    &RRL_DROPPED,
    &RRL_SLIPPED,
    &CLIENT_LIMITED,
    &BLOCKED,
    &ZONE_SERIAL,
    &SIGNING_RUNS,
    &SIGNING_DURATION,
    &LOG_DROPPED,
];

/// The query counter of the engine: [`QUERIES`] by transport, view and RCODE, counted on
/// the calling worker's shard. Sealed by [`seal`].
pub static QUERY_COUNTER: CounterVec = CounterVec::new(QUERIES);

/// The latency histogram of the engine: [`QUERY_DURATION`] by transport, in microseconds.
/// Sealed by [`seal`].
pub static QUERY_LATENCY: HistogramVec = HistogramVec::new(QUERY_DURATION);

/// [`CACHE_HITS`] by view, in the order of [`VIEWS`].
pub static CACHE_HIT_COUNTER: CounterVec =
    CounterVec::fixed(CACHE_HITS, &[&["default"], &["named"]]);

/// [`CACHE_MISSES`] by view, in the order of [`VIEWS`].
pub static CACHE_MISS_COUNTER: CounterVec =
    CounterVec::fixed(CACHE_MISSES, &[&["default"], &["named"]]);

/// [`CACHE_STALE`].
pub static CACHE_STALE_COUNTER: Counter = Counter::new(CACHE_STALE);

/// [`CACHE_ENTRIES`], set by the cache as it changes.
pub static CACHE_ENTRY_GAUGE: Gauge = Gauge::new(CACHE_ENTRIES);

/// The series index of a view in the cache counters: 1 for a view of the table, 0 for the
/// implicit default view.
pub fn view_index(named: bool) -> u16 {
    u16::from(named)
}

/// The `proto` label values, in the order of [`proto_index`].
pub const PROTOS: [&str; 4] = ["udp", "tcp", "dot", "doh"];

/// The `view` label values: the implicit default view, and any view of the view table.
/// Per-view series come with the management of views (WP6.4), when the view names are
/// known at sealing.
pub const VIEWS: [&str; 2] = ["default", "named"];

/// The `rcode` label values, in the order of [`rcode_index`]; `other` is every RCODE not
/// listed.
pub const RCODES: [&str; 10] = [
    "noerror",
    "formerr",
    "servfail",
    "nxdomain",
    "notimp",
    "refused",
    "notauth",
    "badvers",
    "badcookie",
    "other",
];

/// The series index of a transport in [`QUERY_LATENCY`].
pub fn proto_index(transport: QueryTransport) -> u16 {
    match transport {
        QueryTransport::Udp => 0,
        QueryTransport::Tcp => 1,
        QueryTransport::Dot => 2,
        QueryTransport::Doh => 3,
    }
}

/// The position of an RCODE in [`RCODES`].
pub fn rcode_index(rcode: u16) -> u16 {
    match rcode {
        0..=5 => rcode,
        9 => 6,
        16 => 7,
        23 => 8,
        _ => 9,
    }
}

/// The series index of [`QUERY_COUNTER`] for a transport, a view (`named`: a view of the
/// table matched) and an RCODE.
pub fn query_index(transport: QueryTransport, named: bool, rcode: u16) -> u16 {
    // 4 x 2 x 10 series, so the products stay far below u16::MAX.
    (proto_index(transport) * 2 + u16::from(named)) * 10 + rcode_index(rcode)
}

/// Seals the engine's own families with every series, once per process. Allocates; the
/// updates after it do not.
pub fn seal() {
    let mut rows: Vec<[&str; 3]> = Vec::with_capacity(PROTOS.len() * VIEWS.len() * RCODES.len());
    for proto in PROTOS {
        for view in VIEWS {
            for rcode in RCODES {
                rows.push([proto, view, rcode]);
            }
        }
    }
    let series: Vec<&[&str]> = rows.iter().map(|row| &row[..]).collect();
    QUERY_COUNTER.seal(&series);
    let protos: Vec<[&str; 1]> = PROTOS.iter().map(|proto| [*proto]).collect();
    let series: Vec<&[&str]> = protos.iter().map(|row| &row[..]).collect();
    QUERY_LATENCY.seal(&series);
    // The fixed families seal at their first use; using them once here keeps that
    // allocation off the query path.
    CACHE_HIT_COUNTER.add(0, 0);
    CACHE_MISS_COUNTER.add(0, 0);
    CACHE_STALE_COUNTER.add(0);
}

/// Seals the engine's families and registers them with `registry` (the role start step of
/// WP4.3 calls it with the process registry): the queries and their latency, the cache
/// (WP5.1) and the upstreams of the pool.
pub fn register(registry: &Registry) {
    seal();
    registry.register(&QUERY_COUNTER);
    registry.register(&QUERY_LATENCY);
    registry.register(&CACHE_HIT_COUNTER);
    registry.register(&CACHE_MISS_COUNTER);
    registry.register(&CACHE_STALE_COUNTER);
    registry.register(&CACHE_ENTRY_GAUGE);
    registry.register(&crate::pool::UPSTREAM_QUERY_FAMILY);
    registry.register(&crate::pool::UPSTREAM_RTT_FAMILY);
}

#[cfg(test)]
mod tests {
    use tenko_core::metrics::{check, encode};

    use super::*;

    #[test]
    fn the_engine_families_encode_and_check() {
        let registry = Registry::new();
        register(&registry);
        QUERY_COUNTER.inc(query_index(QueryTransport::Tcp, true, 3));
        QUERY_LATENCY.observe(proto_index(QueryTransport::Udp), 120);
        let mut text = String::new();
        encode(&registry.snapshot(), &mut text);
        check(&text).expect("valid OpenMetrics");
        assert!(text.contains(
            "tenko_dns_queries_total{proto=\"tcp\",view=\"named\",rcode=\"nxdomain\"} 1
"
        ));
        assert!(text.contains(
            "tenko_dns_query_duration_seconds_bucket{proto=\"udp\",le=\"0.00025\"} 1
"
        ));
        assert_eq!(QUERY_COUNTER.len(), 80);
        let mut seen = std::collections::BTreeSet::new();
        for transport in [
            QueryTransport::Udp,
            QueryTransport::Tcp,
            QueryTransport::Dot,
            QueryTransport::Doh,
        ] {
            for named in [false, true] {
                for rcode in [0, 1, 2, 3, 4, 5, 9, 16, 23, 7] {
                    assert!(seen.insert(query_index(transport, named, rcode)));
                }
            }
        }
        assert_eq!(seen.len(), 80);
        assert!(seen.iter().all(|index| *index < 80));
    }
}
