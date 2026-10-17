//! The metric families of the DNS engine (plan section 3.3, OPS-21), declared once so that
//! every package registers the same names. The engine counts per worker shard; the
//! registry of `tenko_core::metrics` sums the shards when it encodes (docs/observability.md).
//! Counter names carry no `_total`: the encoder adds it.

use tenko_core::metrics::Desc;

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

/// Answers from the cache.
pub const CACHE_HITS: Desc = Desc::counter("tenko_dns_cache_hits", "DNS answers from the cache");

/// Queries the cache could not answer.
pub const CACHE_MISSES: Desc = Desc::counter(
    "tenko_dns_cache_misses",
    "DNS queries the cache could not answer",
);

/// Stale answers served while the upstreams failed (RFC 8767).
pub const CACHE_STALE: Desc = Desc::counter(
    "tenko_dns_cache_stale",
    "Stale DNS answers served while upstreams failed",
);

/// Queries sent to upstreams, by upstream and outcome (`ok`, `timeout`, `error`).
pub const UPSTREAM_QUERIES: Desc = Desc::counter(
    "tenko_dns_upstream_queries",
    "DNS queries sent to upstream resolvers",
)
.labels(&["upstream", "outcome"]);

/// Round-trip time to upstreams.
pub const UPSTREAM_DURATION: Desc = Desc::histogram(
    "tenko_dns_upstream_duration_seconds",
    "Round-trip time of DNS queries to upstream resolvers",
    LATENCY_BUCKETS_US,
    1_000_000,
)
.labels(&["upstream"]);

/// Responses dropped by response rate limiting.
pub const RRL_DROPPED: Desc = Desc::counter(
    "tenko_dns_rrl_dropped",
    "DNS responses dropped by rate limiting",
);

/// Queries blocked by a block list or an RPZ zone, by list.
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
pub const ALL: [&Desc; 13] = [
    &QUERIES,
    &QUERY_DURATION,
    &CACHE_HITS,
    &CACHE_MISSES,
    &CACHE_STALE,
    &UPSTREAM_QUERIES,
    &UPSTREAM_DURATION,
    &RRL_DROPPED,
    &BLOCKED,
    &ZONE_SERIAL,
    &SIGNING_RUNS,
    &SIGNING_DURATION,
    &LOG_DROPPED,
];
