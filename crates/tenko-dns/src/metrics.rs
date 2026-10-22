//! The metric families of the DNS engine (plan section 3.3, OPS-21), declared once so that
//! every package registers the same names. The engine counts per worker shard; the
//! registry of `tenko_core::metrics` sums the shards when it encodes (docs/observability.md).
//! Counter names carry no `_total`: the encoder adds it.

use tenko_core::{
    dns::QueryTransport,
    metrics::{
        Counter, CounterVec, Desc, Gauge, GaugeVec, Histogram, HistogramVec, MAX_SHARDS, Registry,
    },
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

/// Round-trip time of answered exchanges, by rule and upstream.
pub const UPSTREAM_RTT: Desc = Desc::histogram(
    "tenko_dns_upstream_rtt_seconds",
    "Round-trip time of DNS queries to upstream resolvers",
    LATENCY_BUCKETS_US,
    1_000_000,
)
.labels(&["rule", "upstream"]);

/// The health of an upstream, by rule and upstream: 1 answering, 0.5 failing, 0 in
/// back-off; computed at the scrape ([`crate::pool::UpstreamHealthGauge`]).
pub const UPSTREAM_HEALTH: Desc = Desc::gauge(
    "tenko_dns_upstream_health",
    "Health of upstream resolvers (1 up, 0.5 failing, 0 in back-off)",
)
.labels(&["rule", "upstream"]);

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

// WP10.0: the families of the recursive resolver (recursion plan section 2.11), declared
// with their labels; registered by the role only when recursion is on
// ([`register_recursion`]), counted per shard with relaxed atomics (OPS-21).

/// Buckets of the queries sent per client query, 1 to 32 (the work budget).
pub const SUBQUERY_BUCKETS: &[u64] = &[1, 2, 3, 4, 6, 8, 12, 16, 24, 32];

/// Resolutions the engine ended, by outcome (`answered`, `servfail`, `budget`, `timeout`,
/// `local`).
pub const RECURSION: Desc = Desc::counter(
    "tenko_dns_recursion",
    "DNS resolutions of the recursive resolver",
)
.labels(&["outcome"]);

/// The `outcome` values of [`RECURSION`].
pub const RECURSION_OUTCOMES: [&str; 5] = ["answered", "servfail", "budget", "timeout", "local"];

/// Time from the hand-off to the answer of a recursed query (the forwarder's buckets).
pub const RECURSION_DURATION: Desc = Desc::histogram(
    "tenko_dns_recursion_duration_seconds",
    "Time from the hand-off to the answer of a recursed DNS query",
    LATENCY_BUCKETS_US,
    1_000_000,
);

/// Queries sent to authorities per client query, sub-queries included (no unit).
pub const RECURSION_SUBQUERIES: Desc = Desc {
    unit: None,
    ..Desc::histogram(
        "tenko_dns_recursion_subqueries",
        "Queries sent to authorities per recursed DNS query",
        SUBQUERY_BUCKETS,
        1,
    )
};

/// Exchanges with authorities, by transport (`udp`, `tcp`) and outcome (`ok`,
/// `referral`, `lame`, `timeout`, `unreachable`, `malformed`, `tc`, `badcookie`).
pub const AUTHORITY_QUERIES: Desc = Desc::counter(
    "tenko_dns_authority_queries",
    "DNS queries sent to authoritative servers",
)
.labels(&["transport", "outcome"]);

/// The `outcome` values of [`AUTHORITY_QUERIES`].
pub const AUTHORITY_OUTCOMES: [&str; 8] = [
    "ok",
    "referral",
    "lame",
    "timeout",
    "unreachable",
    "malformed",
    "tc",
    "badcookie",
];

/// Round-trip time of answered exchanges with authorities: one histogram, the figures
/// per server are in the infrastructure cache's view (the root alone has hundreds of
/// addresses).
pub const AUTHORITY_RTT: Desc = Desc::histogram(
    "tenko_dns_authority_rtt_seconds",
    "Round-trip time of DNS queries to authoritative servers",
    LATENCY_BUCKETS_US,
    1_000_000,
);

/// Validation outcomes, by state (`secure`, `insecure`, `bogus`, `indeterminate`) and,
/// for bogus, the reason (`signature`, `expired`, `not_yet_valid`, `missing_key`,
/// `missing_rrsig`, `nsec`, `cap`, `algorithm`; empty otherwise).
pub const VALIDATION: Desc = Desc::counter("tenko_dns_validation", "DNSSEC validation outcomes")
    .labels(&["state", "reason"]);

/// Signature verifications the validator ran (the cost of validation, M38).
pub const VALIDATION_VERIFICATIONS: Desc = Desc::counter(
    "tenko_dns_validation_verifications",
    "DNSSEC signature verifications",
);

/// Entries of the infrastructure cache, by kind (`zone`, `server`); computed at the
/// scrape.
pub const INFRA_ENTRIES: Desc = Desc::gauge(
    "tenko_dns_infra_entries",
    "Entries in the DNS infrastructure cache",
)
.labels(&["kind"]);

/// Answers synthesised from the denial cache, by kind (`nxdomain`, `nodata`,
/// `wildcard`, `nxdomain_cut`).
pub const DENIAL: Desc = Desc::counter(
    "tenko_dns_denial",
    "DNS answers synthesised from validated denial records",
)
.labels(&["kind"]);

/// Answers from the failure cache (RFC 9520).
pub const FAILURE_CACHE_HITS: Desc = Desc::counter(
    "tenko_dns_failure_cache_hits",
    "DNS answers from the resolution failure cache",
);

/// Priming runs, by outcome (`ok`, `failed`).
pub const PRIMING: Desc =
    Desc::counter("tenko_dns_priming", "DNS root priming runs").labels(&["outcome"]);

/// Trust anchor keys, by zone and RFC 5011 state; a gauge the controller registers and
/// sets from the rows at the scrape.
pub const TRUST_ANCHOR_KEYS: Desc = Desc::gauge(
    "tenko_dns_trust_anchor_keys",
    "DNSSEC trust anchor keys by zone and state",
)
.labels(&["zone", "state"]);

/// The families of the recursive resolver, for the contracts document.
pub const RECURSION_ALL: [&Desc; 12] = [
    &RECURSION,
    &RECURSION_DURATION,
    &RECURSION_SUBQUERIES,
    &AUTHORITY_QUERIES,
    &AUTHORITY_RTT,
    &VALIDATION,
    &VALIDATION_VERIFICATIONS,
    &INFRA_ENTRIES,
    &DENIAL,
    &FAILURE_CACHE_HITS,
    &PRIMING,
    &TRUST_ANCHOR_KEYS,
];

/// [`RECURSION`] by outcome, in the order of [`RECURSION_OUTCOMES`].
pub static RECURSION_COUNTER: CounterVec = CounterVec::fixed(
    RECURSION,
    &[
        &["answered"],
        &["servfail"],
        &["budget"],
        &["timeout"],
        &["local"],
    ],
);

/// [`RECURSION_DURATION`], in microseconds.
pub static RECURSION_LATENCY: Histogram = Histogram::new(RECURSION_DURATION);

/// [`RECURSION_SUBQUERIES`].
pub static RECURSION_SUBQUERY_HISTOGRAM: Histogram = Histogram::new(RECURSION_SUBQUERIES);

/// [`AUTHORITY_QUERIES`] by transport and outcome: the transport's index times eight plus
/// the outcome's index in [`AUTHORITY_OUTCOMES`] ([`authority_index`]).
pub static AUTHORITY_QUERY_COUNTER: CounterVec = CounterVec::fixed(
    AUTHORITY_QUERIES,
    &[
        &["udp", "ok"],
        &["udp", "referral"],
        &["udp", "lame"],
        &["udp", "timeout"],
        &["udp", "unreachable"],
        &["udp", "malformed"],
        &["udp", "tc"],
        &["udp", "badcookie"],
        &["tcp", "ok"],
        &["tcp", "referral"],
        &["tcp", "lame"],
        &["tcp", "timeout"],
        &["tcp", "unreachable"],
        &["tcp", "malformed"],
        &["tcp", "tc"],
        &["tcp", "badcookie"],
    ],
);

/// The series of [`AUTHORITY_QUERY_COUNTER`]: `tcp` and the outcome's index.
pub fn authority_index(tcp: bool, outcome: &str) -> Option<u16> {
    let at = AUTHORITY_OUTCOMES
        .iter()
        .position(|known| *known == outcome)?;
    u16::try_from(at + if tcp { 8 } else { 0 }).ok()
}

/// [`AUTHORITY_RTT`], in microseconds.
pub static AUTHORITY_LATENCY: Histogram = Histogram::new(AUTHORITY_RTT);

/// [`VALIDATION`] by state and reason: the four states with an empty reason, then bogus
/// with each reason of `recursion::validator::BogusReason::ALL` in order
/// ([`validation_index`]).
pub static VALIDATION_COUNTER: CounterVec = CounterVec::fixed(
    VALIDATION,
    &[
        &["secure", ""],
        &["insecure", ""],
        &["bogus", ""],
        &["indeterminate", ""],
        &["bogus", "signature"],
        &["bogus", "expired"],
        &["bogus", "not_yet_valid"],
        &["bogus", "missing_key"],
        &["bogus", "missing_rrsig"],
        &["bogus", "nsec"],
        &["bogus", "cap"],
        &["bogus", "algorithm"],
    ],
);

/// The series of [`VALIDATION_COUNTER`] for a state and, for bogus, its reason.
pub fn validation_index(
    state: tenko_core::dns::SecurityState,
    reason: Option<crate::recursion::BogusReason>,
) -> Option<u16> {
    use tenko_core::dns::SecurityState;
    match (state, reason) {
        (SecurityState::Secure, _) => Some(0),
        (SecurityState::Insecure, _) => Some(1),
        (SecurityState::Bogus, None) => Some(2),
        (SecurityState::Indeterminate, _) => Some(3),
        (SecurityState::Bogus, Some(reason)) => crate::recursion::BogusReason::ALL
            .iter()
            .position(|known| *known == reason)
            .and_then(|at| u16::try_from(at + 4).ok()),
        (SecurityState::Unvalidated, _) => None,
    }
}

/// [`VALIDATION_VERIFICATIONS`].
pub static VALIDATION_VERIFICATION_COUNTER: Counter = Counter::new(VALIDATION_VERIFICATIONS);

/// [`INFRA_ENTRIES`] by kind (`zone`, `server`), set from the cache's sizes before a
/// scrape (lazy: the cache is read only then).
pub static INFRA_ENTRY_GAUGE: GaugeVec = GaugeVec::fixed(INFRA_ENTRIES, &[&["zone"], &["server"]]);

/// [`DENIAL`] by kind, in the order of `recursion::denial::DenialKind::ALL`.
pub static DENIAL_COUNTER: CounterVec = CounterVec::fixed(
    DENIAL,
    &[&["nxdomain"], &["nodata"], &["wildcard"], &["nxdomain_cut"]],
);

/// [`FAILURE_CACHE_HITS`].
pub static FAILURE_CACHE_HIT_COUNTER: Counter = Counter::new(FAILURE_CACHE_HITS);

/// [`PRIMING`] by outcome (`ok`, `failed`).
pub static PRIMING_COUNTER: CounterVec = CounterVec::fixed(PRIMING, &[&["ok"], &["failed"]]);

/// [`TRUST_ANCHOR_KEYS`] by zone and state: labels set at the scrape from the rows (the
/// controller registers it).
pub static TRUST_ANCHOR_KEY_GAUGE: GaugeVec = GaugeVec::new(TRUST_ANCHOR_KEYS);

/// Registers the recursive resolver's families with `registry` (the role, when recursion
/// is on), and uses each fixed family once so that its first use is off the query path.
/// The trust anchor gauge is the controller's ([`register_trust_anchors`]).
pub fn register_recursion(registry: &Registry) {
    RECURSION_COUNTER.add(0, 0);
    AUTHORITY_QUERY_COUNTER.add(0, 0);
    VALIDATION_COUNTER.add(0, 0);
    VALIDATION_VERIFICATION_COUNTER.add(0);
    DENIAL_COUNTER.add(0, 0);
    FAILURE_CACHE_HIT_COUNTER.add(0);
    PRIMING_COUNTER.add(0, 0);
    registry.register(&RECURSION_COUNTER);
    registry.register(&RECURSION_LATENCY);
    registry.register(&RECURSION_SUBQUERY_HISTOGRAM);
    registry.register(&AUTHORITY_QUERY_COUNTER);
    registry.register(&AUTHORITY_LATENCY);
    registry.register(&VALIDATION_COUNTER);
    registry.register(&VALIDATION_VERIFICATION_COUNTER);
    registry.register(&INFRA_ENTRY_GAUGE);
    registry.register(&DENIAL_COUNTER);
    registry.register(&FAILURE_CACHE_HIT_COUNTER);
    registry.register(&PRIMING_COUNTER);
}

/// Registers the trust anchor gauge with `registry` (the controller), with room for
/// `slots` series of zone and state.
pub fn register_trust_anchors(registry: &Registry, slots: u16) {
    TRUST_ANCHOR_KEY_GAUGE.seal_slots(slots);
    registry.register(&TRUST_ANCHOR_KEY_GAUGE);
}
// WP10.0: end.

/// Every family of the engine, for registration and the contracts document.
pub const ALL: [&Desc; 17] = [
    &QUERIES,
    &QUERY_DURATION,
    &CACHE_HITS,
    &CACHE_MISSES,
    &CACHE_STALE,
    &CACHE_ENTRIES,
    &UPSTREAM_QUERIES,
    &UPSTREAM_RTT,
    &UPSTREAM_HEALTH,
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

/// The shards of the query families: one for each UDP worker, up to the most a family has.
pub const QUERY_SHARDS: usize = MAX_SHARDS;

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
    // M22: the query path counts on a shard per UDP worker (each pins its own, numbered
    // across every listen address), so these two families take the most shards rather
    // than one per CPU: a node listening on two addresses runs twice as many workers as
    // CPUs by default. About 38 KiB for both.
    QUERY_COUNTER.seal_with_shards(&series, QUERY_SHARDS);
    let protos: Vec<[&str; 1]> = PROTOS.iter().map(|proto| [*proto]).collect();
    let series: Vec<&[&str]> = protos.iter().map(|row| &row[..]).collect();
    QUERY_LATENCY.seal_with_shards(&series, QUERY_SHARDS);
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
    registry.register(&crate::pool::UPSTREAM_HEALTH_FAMILY);
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
        assert_eq!(QUERY_COUNTER.shards(), QUERY_SHARDS, "a shard per worker");
        assert_eq!(QUERY_LATENCY.shards(), QUERY_SHARDS);
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

    // WP10.0: the recursive resolver's families encode and check.
    #[test]
    fn the_recursion_families_encode_and_check() {
        use tenko_core::dns::SecurityState;

        use crate::recursion::BogusReason;

        let registry = Registry::new();
        register_recursion(&registry);
        register_trust_anchors(&registry, 16);
        RECURSION_COUNTER.inc(0);
        RECURSION_LATENCY.observe(1_500);
        RECURSION_SUBQUERY_HISTOGRAM.observe(3);
        AUTHORITY_QUERY_COUNTER.inc(authority_index(true, "tc").expect("series"));
        AUTHORITY_LATENCY.observe(400);
        let bogus = validation_index(SecurityState::Bogus, Some(BogusReason::Expired));
        VALIDATION_COUNTER.inc(bogus.expect("series"));
        INFRA_ENTRY_GAUGE.set(0, 12.0);
        assert!(TRUST_ANCHOR_KEY_GAUGE.set_labels(&[".", "valid"], 2.0));
        let mut text = String::new();
        encode(&registry.snapshot(), &mut text);
        check(&text).expect("valid OpenMetrics");
        for line in [
            "tenko_dns_recursion_total{outcome=\"answered\"} 1",
            "tenko_dns_authority_queries_total{transport=\"tcp\",outcome=\"tc\"} 1",
            "tenko_dns_validation_total{state=\"bogus\",reason=\"expired\"} 1",
            "tenko_dns_infra_entries{kind=\"zone\"} 12",
            "tenko_dns_trust_anchor_keys{zone=\".\",state=\"valid\"} 2",
            "tenko_dns_recursion_subqueries_bucket{le=\"3.0\"} 1",
        ] {
            assert!(text.contains(line), "{line}\n{text}");
        }
        assert_eq!(authority_index(false, "nothing"), None);
        assert_eq!(validation_index(SecurityState::Unvalidated, None), None);
        let names: Vec<&str> = RECURSION_ALL.iter().map(|desc| desc.name).collect();
        assert!(names.iter().all(|name| name.starts_with("tenko_dns_")));
    }
}
