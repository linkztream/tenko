//! Server-sent events (API-05): topics and the JSON carried in each event's `data` field.
//!
//! Events carry references, not bodies: the UI refetches what it shows, so no event leaks a
//! field the principal may not read. The SSE `event` field is the topic name for data
//! events, and `reset` or `shutdown` for the two control events that every subscriber
//! receives whatever its topic filter.

use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use tenko_core::{AuditSeq, InvalidValue, NodeId, ObjectRef, Revision, Timestamp};
use utoipa::ToSchema;

/// An event topic. `GET /events?topics=ipam,jobs` subscribes to a subset; no `topics`
/// parameter subscribes to all of them except `metrics`, which a client names to receive it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Topic {
    /// IPAM objects: tenants, VRFs, sites, VLANs, prefixes, ranges, addresses, hosts,
    /// interfaces and custom fields.
    Ipam,
    /// Jobs and their steps.
    Jobs,
    /// New audit records.
    Audit,
    /// Imports.
    Import,
    /// Alarms (utilization, break-glass use, lockouts).
    System,
    /// Users, sessions, tokens and security settings.
    Admin,
    /// Connector plugins and connector instances.
    Connectors,
    /// Observations of connectors and probes: per-source facts and last sightings.
    Discovery,
    /// Operator secrets: metadata, reveals and host credential bindings (never values).
    Secrets,
    /// Cluster nodes, enrollment tokens and controller members.
    Cluster,
    /// The live metrics of the dashboard (OPS-20): first one `metrics.history` event with the
    /// history of every tile ([`MetricsHistory`]), then one `metrics.snapshot` per second
    /// ([`MetricsSnapshot`]); published by the metrics collector, not from the store journal,
    /// and never replayed.
    Metrics,
    /// The DNS module (Phase 2): zones and their records, views, forwarders, access lists,
    /// keys and block lists, and the serial, transfer and signing events of zones.
    Dns,
    // WP7.0
    /// The DHCP module (Phase 3): the configuration, and lease events for the live lease
    /// view (sampled to at most 50 a second per subscriber, with counts when sampled).
    Dhcp,
    /// The findings index (U1): published by the index after it applied a change, kind
    /// `findings.changed` with the source records whose findings changed (proposals,
    /// prefixes, jobs) or none for the reconciliation view and health; `params.revision` is
    /// the store revision the index applied. Not from the journal and never replayed: a
    /// client reloads `GET /findings/counts` when it connects.
    Findings,
}

impl Topic {
    /// Every topic, in declaration order.
    pub const ALL: [Topic; 14] = [
        Topic::Ipam,
        Topic::Jobs,
        Topic::Audit,
        Topic::Import,
        Topic::System,
        Topic::Admin,
        Topic::Connectors,
        Topic::Discovery,
        Topic::Secrets,
        Topic::Cluster,
        Topic::Metrics,
        Topic::Dns,
        Topic::Dhcp,
        Topic::Findings,
    ];

    /// The stable lower-case name, also the SSE `event` field.
    pub const fn as_str(self) -> &'static str {
        match self {
            Topic::Ipam => "ipam",
            Topic::Jobs => "jobs",
            Topic::Audit => "audit",
            Topic::Import => "import",
            Topic::System => "system",
            Topic::Admin => "admin",
            Topic::Connectors => "connectors",
            Topic::Discovery => "discovery",
            Topic::Secrets => "secrets",
            Topic::Cluster => "cluster",
            Topic::Metrics => "metrics",
            Topic::Dns => "dns",
            Topic::Dhcp => "dhcp",
            Topic::Findings => "findings",
        }
    }

    /// The topic's bit in a [`TopicSet`].
    pub const fn bit(self) -> u16 {
        1 << (self as u16)
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Topic {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Topic::ALL
            .into_iter()
            .find(|topic| topic.as_str() == s)
            .ok_or_else(|| InvalidValue::new("event topic", s, "unknown topic"))
    }
}

/// A set of topics, as a bit mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TopicSet(u16);

impl TopicSet {
    /// Every topic.
    pub const ALL: TopicSet = TopicSet(0b11_1111_1111_1111);
    /// No topic.
    pub const EMPTY: TopicSet = TopicSet(0);
    /// The topics of a subscription that names none: every topic except `metrics`, whose
    /// one-second snapshots only a client that asks for them receives.
    pub const DEFAULT: TopicSet = TopicSet(Self::ALL.0 & !Topic::Metrics.bit());

    /// Parses a comma-separated list such as `ipam,jobs`; blanks around names are ignored
    /// and an empty list means [`TopicSet::DEFAULT`].
    ///
    /// # Errors
    ///
    /// Returns the first unknown name.
    pub fn parse(list: &str) -> Result<Self, InvalidValue> {
        let mut set = TopicSet::EMPTY;
        for name in list
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            set.insert(name.parse()?);
        }
        Ok(if set == TopicSet::EMPTY {
            TopicSet::DEFAULT
        } else {
            set
        })
    }

    /// Adds a topic.
    pub fn insert(&mut self, topic: Topic) {
        self.0 |= topic.bit();
    }

    /// Removes a topic.
    pub fn remove(&mut self, topic: Topic) {
        self.0 &= !topic.bit();
    }

    /// Whether the set holds the topic.
    pub const fn contains(self, topic: Topic) -> bool {
        self.0 & topic.bit() != 0
    }

    /// The topics of the set, in declaration order.
    pub fn topics(self) -> impl Iterator<Item = Topic> {
        Topic::ALL
            .into_iter()
            .filter(move |topic| self.contains(*topic))
    }
}

/// The `data` of a topic event.
///
/// Data events from the store have `revision` (also the SSE id, so `Last-Event-ID`
/// resumes after it) and list the objects written or deleted by that revision. System
/// events that do not come from a store change have no revision and no SSE id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct EventData {
    /// The topic.
    pub topic: Topic,
    /// Store revision of the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
    /// Objects created or changed (including soft deletes, which are changes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<ObjectRef>,
    /// Objects removed from the store.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deleted: Vec<ObjectRef>,
    /// New audit records (topic `audit`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit: Vec<AuditSeq>,
    /// Changed tables that carry no object reference (topic `admin`, some `system` alarms).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
    /// Kind of a system event that did not come from the store, for example an alarm code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Parameters of such an event, for the UI's translated message.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    /// The metrics of the controllers (topic `metrics`, kind `metrics.snapshot`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsSnapshot>,
    // WP18.0: the first event of a subscription to the `metrics` topic.
    /// The history of the dashboard's tiles (topic `metrics`, kind `metrics.history`): the
    /// first event of the topic on every stream that receives it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<MetricsHistory>,
}

impl EventData {
    /// An empty event of a topic.
    pub fn new(topic: Topic, revision: Option<Revision>) -> Self {
        Self {
            topic,
            revision,
            objects: Vec::new(),
            deleted: Vec::new(),
            audit: Vec::new(),
            tables: Vec::new(),
            kind: None,
            params: BTreeMap::new(),
            metrics: None,
            history: None,
        }
    }

    /// Whether the event carries nothing beyond its topic.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
            && self.deleted.is_empty()
            && self.audit.is_empty()
            && self.tables.is_empty()
            && self.kind.is_none()
            && self.metrics.is_none()
            && self.history.is_none()
    }
}

/// The `kind` of the per-second event of the `metrics` topic, whose `metrics` is a
/// [`MetricsSnapshot`].
pub const METRICS_SNAPSHOT_KIND: &str = "metrics.snapshot";
// WP18.0: the history of the tiles.
/// The `kind` of the first event of the `metrics` topic on a stream, whose `history` is a
/// [`MetricsHistory`].
///
/// What a client receives, in this order: the stream's `hello` comment; the replay and the
/// live events of its other topics as usual (they may come before or between the two below);
/// one `metrics.history`, before any `metrics.snapshot` of the stream; then one
/// `metrics.snapshot` per second. A client that connects late, reconnects or opens a second
/// page therefore draws every tile from that one event, without a request per tile. The
/// history a new stream gets is the cached frame of the newest tick before its first
/// snapshot, so the first `closed` overlaps it or continues it and never leaves a hole.
///
/// A later `metrics.history` may arrive on the same stream at any time: the serving
/// controller sends a rebuilt history to the open streams when the past changed (a controller
/// answers again after missing calls, a controller restarted, a role started). It replaces
/// everything the client holds. Like the snapshots, the history has no SSE id and is never
/// replayed; a client that receives the stream's `reset` event, or finds a hole in the bucket
/// starts of a `closed` (see [`MetricsSnapshot::closed`]), opens the stream again and
/// receives a fresh history. The topic's permission (the read of the metrics object) admits
/// both kinds.
pub const METRICS_HISTORY_KIND: &str = "metrics.history";

/// The data of a `metrics.snapshot` event (topic `metrics`, OPS-20): one sample per
/// controller and their sum, once per second while a client listens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsSnapshot {
    /// One sample per controller of the cluster, the publishing controller first.
    pub nodes: Vec<MetricsSample>,
    /// The cluster: rates, sizes and counts summed over the controllers whose sample is
    /// current, the highest quantiles, terms and lags. On a single controller, its own
    /// sample without its node id.
    pub cluster: MetricsSample,
    // WP18.0: the buckets of the history that closed since the event before.
    /// The buckets of the tiles' history that closed in this tick or in the tick before,
    /// combined for the cluster as in [`MetricsHistory`]: per figure, the tiers that have such
    /// a bucket (normally the two newest one-second buckets, and a coarser tier's bucket in the
    /// two ticks after its step ended); no bucket of a `closed` is open. Absent when nothing
    /// closed, and from a server of the previous release.
    ///
    /// Every closed bucket therefore arrives in two consecutive snapshots, so one missed second
    /// loses nothing. The buckets of a tier here are consecutive like a history's, and the
    /// client keeps one bucket per tier and start: a bucket whose start it already holds
    /// replaces the one it holds (the open bucket of the history, or a combined bucket the
    /// serving controller completed when a late controller's part arrived); a bucket after the
    /// newest it holds is appended, and the oldest are dropped beyond the tier's `ring`. A
    /// client that finds a hole between the newest start it holds and the oldest start of a
    /// tier here, or a figure or tier its history lacks, opens the stream again for a fresh
    /// [`MetricsHistory`]. The client only appends and never aggregates. About 2 KB a second
    /// with 25 figures.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub closed: Vec<MetricsClosed>,
}

// WP18.0: the history of the dashboard's tiles (dashboard history plan, sections 2 to 5).

/// The significant digits of the history's values on the event stream; the tiles show three.
pub const HISTORY_SIGNIFICANT_DIGITS: u32 = 4;

/// The reach of the history: two days (DH-Q2 (b)).
pub const HISTORY_REACH_MS: u64 = 2 * 86_400_000;

/// The bytes of one [`MetricsBucket`] in memory, the unit of the history's memory budget.
pub const BUCKET_BYTES: usize = 32;

/// One tier of a figure's history: the length of its buckets and the size of its ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierSpec {
    /// The length of one bucket in milliseconds. A bucket starts at a whole multiple of it
    /// since the Unix epoch, on the controller's clock in UTC.
    pub step_ms: u32,
    /// The buckets of the ring, the open one included: the tier's span, plus the buckets that
    /// cover the time until the next coarser bucket starts (so every drawn bucket is whole),
    /// plus the open bucket the fold is filling.
    pub buckets: usize,
}

/// The tiers of every figure but the ratios, finest first: two days in 279 buckets (71 × 1 s,
/// 61 × 10 s, 61 × 1 min, 37 × 10 min, 49 × 1 h), 8.7 KiB a figure. A ring holds its newest
/// buckets, the open one included, so a ring of `r` buckets of step `s` reaches back
/// `(r − 1) × s` in the worst case (its open bucket just started). Each finer ring reaches the
/// age at which the next coarser tier takes over, `(r − 1) × s` less the coarser step: 60 s,
/// 9 min, 50 min and 5 h; the hour ring reaches the whole two days by itself (48 h), because
/// its newest buckets overlap the finer tiers.
pub const HISTORY_TIERS: [TierSpec; 5] = [
    TierSpec {
        step_ms: 1_000,
        buckets: 71,
    },
    TierSpec {
        step_ms: 10_000,
        buckets: 61,
    },
    TierSpec {
        step_ms: 60_000,
        buckets: 61,
    },
    TierSpec {
        step_ms: 600_000,
        buckets: 37,
    },
    TierSpec {
        step_ms: 3_600_000,
        buckets: 49,
    },
];

/// The tiers of the two ratio figures (the cache hit ratio and the NOERROR share): 5 seconds
/// as the finest step (15 × 5 s), because a share over one second at a few queries a second
/// jumps between 0, 50 and 100 %; the coarser tiers as [`HISTORY_TIERS`].
pub const RATIO_HISTORY_TIERS: [TierSpec; 5] = [
    TierSpec {
        step_ms: 5_000,
        buckets: 15,
    },
    HISTORY_TIERS[1],
    HISTORY_TIERS[2],
    HISTORY_TIERS[3],
    HISTORY_TIERS[4],
];

/// Bytes in a GiB, the unit of the disk figure.
const GIB: f64 = 1_073_741_824.0;

/// A figure of the dashboard: one tile, one history. The name is the tile's
/// (`metrics-tile-<name>` in the UI), and [`MetricsFigure::value`] is the number the tile shows
/// for a sample, in the tile's unit; the history keeps the lowest, highest and mean of that
/// number per bucket. The figures of a role exist while a controller of the cluster runs the
/// role. 25 figures: the controller's 8, the host's 3, DNS 8 and DHCP 6.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum MetricsFigure {
    /// API requests per second (`api.requests_per_second`). Summed.
    Requests,
    /// The store's commit p99 in milliseconds (`store.commit_p99_ms`; none without writes).
    /// Highest.
    Commit,
    /// The store's size in bytes: on disk (`store.file_bytes`), or the live data
    /// (`store.data_bytes`) for an in-memory store. Summed.
    Store,
    /// The highest replication lag in log entries (`raft.lag`; 0 without members). Highest.
    Raft,
    /// Jobs running (`jobs.running`). Highest (every controller counts the same jobs).
    Jobs,
    /// Observations per second (`ingest.facts_per_second`). Summed.
    Ingest,
    /// Open event streams (`sse.subscribers`). Summed.
    Sse,
    /// Observation batches waiting in the buffers of the connected nodes (the sum of
    /// `nodes[].buffer_batches`). Summed.
    Nodes,
    /// The host's busy CPU in percent (`host.cpu_percent`). Highest.
    HostCpu,
    /// The host's memory in use in percent of its total (`host.memory_total` less
    /// `host.memory_available`). The controller with the least available.
    HostMemory,
    /// The space available on the data directory's file system in GiB
    /// (`host.disk_available`, with `host.disk_total` for the share available). The controller
    /// with the least available.
    HostDisk,
    /// DNS queries answered per second (`dns.queries_per_second`). Summed.
    DnsQueries,
    /// The cache hit ratio in percent: hits over hits and misses. A ratio.
    DnsCache,
    /// The NOERROR share of the answers in percent. A ratio.
    DnsAnswers,
    /// Queries blocked per second over every list (the sum of `dns.blocked[].per_second`).
    /// Summed.
    DnsBlocked,
    /// Exchanges with upstream resolvers per second (`dns.upstreams.queries_per_second`).
    /// Summed.
    DnsUpstreams,
    /// Queries the recursive resolver sent to authorities per second
    /// (`dns.recursion.subqueries_per_second`; none while recursion is off). Summed.
    DnsSubqueries,
    /// DNSSEC validation outcomes per second, every state (`dns.recursion.validation`; none
    /// while recursion is off). Summed.
    DnsValidation,
    /// Open DoT and DoH connections (`dns.connections`; none while the role serves neither).
    /// Summed.
    DnsEncrypted,
    /// DHCP leases granted per second (`dhcp.leases_per_second`). Summed.
    DhcpLeases,
    /// The REQUEST to ACK p99 in milliseconds (`dhcp.ack_p99_ms`; none without an ACK).
    /// Highest.
    DhcpAck,
    /// Active leases (`dhcp.active_leases`). Summed.
    DhcpActive,
    /// The fullest scope's utilization in percent (`dhcp.fullest[0]`; none without a pool).
    /// Highest.
    DhcpPools,
    /// NAKs sent and DECLINEs received per second. Summed.
    DhcpNaks,
    /// DDNS names written per second (`dhcp.ddns.written`). Summed.
    DhcpDdns,
}

/// How the cluster combines a figure's buckets from each controller's own (plan section 4,
/// the per-field rule of the live sample). A sum of maxima is not the maximum of the sum, so
/// each rule says what its numbers are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MetricsMerge {
    /// Rates, sizes and counts: the mean is the sum of the controllers' means (exact where
    /// every controller covered the whole bucket); the lowest and the highest are the sums of
    /// the controllers' lowests and highests, an envelope that contains the true range.
    Sum,
    /// Quantiles, the lag, the jobs and the CPU: the highest is the highest of the highests
    /// (exact); the mean (the highest mean) and the lowest (the highest lowest) are lower
    /// bounds.
    Highest,
    /// The host's memory and disk: the values of the controller whose mean share available is
    /// the smallest in that bucket, its own lowest, mean and highest.
    LeastAvailable,
    /// The hit ratio and the NOERROR share: the mean is recomputed from the summed counts
    /// (exact); the lowest and the highest are the lowest and highest of any controller, an
    /// envelope.
    Ratio,
}

/// What one sample adds to the buckets of a figure.
///
/// A sample covers the interval `[at − interval_ms, at)` of its controller's clock, which is
/// not aligned to whole seconds and may be longer than one (a late tick). The fold splits that
/// interval over the buckets of each tier it overlaps: each overlapped bucket takes the lowest
/// and highest `value`, adds `sum` and `second`, each times the overlap in milliseconds, to its
/// sums, and adds the overlap to its covered time. A bucket's covered time therefore never
/// exceeds its step, and a second that one long interval spans is covered, not a gap. Time
/// that falls into a bucket that already closed (a clock that jumped back) goes into the open
/// bucket instead, its covered time held at the step. The split is a few comparisons per tier
/// and allocates nothing. A sample without the figure (its role is not in the sample, a
/// quantile without traffic, a ratio without a lookup) has no reading and adds nothing, not
/// even covered time.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reading {
    /// The number the tile shows ([`MetricsFigure::value`]).
    pub value: f64,
    /// Added to [`MetricsBucket::sum`] per millisecond: the value; for a ratio, the rate that
    /// counts (cache hits, NOERROR answers).
    pub sum: f64,
    /// Added to [`MetricsBucket::second`] per millisecond: 0; for a ratio, the rate of
    /// everything (hits and misses, all answers); for the host's memory and disk, the share
    /// available, 0 to 1, which picks the controller with the least available.
    pub second: f64,
}

impl MetricsFigure {
    /// Every figure, in the order of the history's `figures` and of the tiles.
    pub const ALL: [MetricsFigure; 25] = [
        MetricsFigure::Requests,
        MetricsFigure::Commit,
        MetricsFigure::Store,
        MetricsFigure::Raft,
        MetricsFigure::Jobs,
        MetricsFigure::Ingest,
        MetricsFigure::Sse,
        MetricsFigure::Nodes,
        MetricsFigure::HostCpu,
        MetricsFigure::HostMemory,
        MetricsFigure::HostDisk,
        MetricsFigure::DnsQueries,
        MetricsFigure::DnsCache,
        MetricsFigure::DnsAnswers,
        MetricsFigure::DnsBlocked,
        MetricsFigure::DnsUpstreams,
        MetricsFigure::DnsSubqueries,
        MetricsFigure::DnsValidation,
        MetricsFigure::DnsEncrypted,
        MetricsFigure::DhcpLeases,
        MetricsFigure::DhcpAck,
        MetricsFigure::DhcpActive,
        MetricsFigure::DhcpPools,
        MetricsFigure::DhcpNaks,
        MetricsFigure::DhcpDdns,
    ];

    /// The figure's place in [`MetricsFigure::ALL`], for arrays indexed by figure.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The tile's name, also the serialized form.
    pub const fn as_str(self) -> &'static str {
        match self {
            MetricsFigure::Requests => "requests",
            MetricsFigure::Commit => "commit",
            MetricsFigure::Store => "store",
            MetricsFigure::Raft => "raft",
            MetricsFigure::Jobs => "jobs",
            MetricsFigure::Ingest => "ingest",
            MetricsFigure::Sse => "sse",
            MetricsFigure::Nodes => "nodes",
            MetricsFigure::HostCpu => "host-cpu",
            MetricsFigure::HostMemory => "host-memory",
            MetricsFigure::HostDisk => "host-disk",
            MetricsFigure::DnsQueries => "dns-queries",
            MetricsFigure::DnsCache => "dns-cache",
            MetricsFigure::DnsAnswers => "dns-answers",
            MetricsFigure::DnsBlocked => "dns-blocked",
            MetricsFigure::DnsUpstreams => "dns-upstreams",
            MetricsFigure::DnsSubqueries => "dns-subqueries",
            MetricsFigure::DnsValidation => "dns-validation",
            MetricsFigure::DnsEncrypted => "dns-encrypted",
            MetricsFigure::DhcpLeases => "dhcp-leases",
            MetricsFigure::DhcpAck => "dhcp-ack",
            MetricsFigure::DhcpActive => "dhcp-active",
            MetricsFigure::DhcpPools => "dhcp-pools",
            MetricsFigure::DhcpNaks => "dhcp-naks",
            MetricsFigure::DhcpDdns => "dhcp-ddns",
        }
    }

    /// How the cluster combines the figure.
    pub const fn merge(self) -> MetricsMerge {
        match self {
            MetricsFigure::Commit
            | MetricsFigure::Raft
            | MetricsFigure::Jobs
            | MetricsFigure::HostCpu
            | MetricsFigure::DhcpAck
            | MetricsFigure::DhcpPools => MetricsMerge::Highest,
            MetricsFigure::HostMemory | MetricsFigure::HostDisk => MetricsMerge::LeastAvailable,
            MetricsFigure::DnsCache | MetricsFigure::DnsAnswers => MetricsMerge::Ratio,
            _ => MetricsMerge::Sum,
        }
    }

    /// The figure's tiers, finest first.
    pub const fn tiers(self) -> &'static [TierSpec; 5] {
        match self.merge() {
            MetricsMerge::Ratio => &RATIO_HISTORY_TIERS,
            _ => &HISTORY_TIERS,
        }
    }

    /// The number the tile shows for `sample`, in the tile's unit; `None` when the sample has
    /// none (the role is not in it, a quantile without traffic, a ratio without a lookup).
    /// Reads the sample only: no allocation, no lock.
    pub fn value(self, sample: &MetricsSample) -> Option<f64> {
        self.reading(sample).map(|reading| reading.value)
    }

    /// What `sample` adds to a bucket of the figure ([`Reading`]); `None` as for
    /// [`MetricsFigure::value`]. Reads the sample only: no allocation, no lock.
    #[allow(clippy::cast_precision_loss, reason = "counts shown to people")]
    pub fn reading(self, sample: &MetricsSample) -> Option<Reading> {
        let plain = |value: f64| Reading {
            value,
            sum: value,
            second: 0.0,
        };
        let ratio = |part: f64, whole: f64| {
            (whole > 0.0).then(|| Reading {
                value: part * 100.0 / whole,
                sum: part,
                second: whole,
            })
        };
        let dns = sample.dns.as_ref();
        let dhcp = sample.dhcp.as_ref();
        let host = sample.host.as_ref();
        match self {
            MetricsFigure::Requests => Some(plain(sample.api.requests_per_second)),
            MetricsFigure::Commit => sample.store.commit_p99_ms.map(plain),
            MetricsFigure::Store => Some(plain(
                sample.store.file_bytes.unwrap_or(sample.store.data_bytes) as f64,
            )),
            MetricsFigure::Raft => Some(plain(
                sample
                    .raft
                    .lag
                    .iter()
                    .map(|lag| lag.entries)
                    .max()
                    .unwrap_or(0) as f64,
            )),
            MetricsFigure::Jobs => Some(plain(sample.jobs.running as f64)),
            MetricsFigure::Ingest => Some(plain(sample.ingest.facts_per_second)),
            MetricsFigure::Sse => Some(plain(sample.sse.subscribers as f64)),
            MetricsFigure::Nodes => Some(plain(
                sample
                    .nodes
                    .iter()
                    .map(|node| node.buffer_batches as f64)
                    .sum(),
            )),
            MetricsFigure::HostCpu => host.and_then(|host| host.cpu_percent).map(plain),
            MetricsFigure::HostMemory => {
                let host = host?;
                let (total, available) = (host.memory_total?, host.memory_available?);
                (total > 0).then(|| Reading {
                    second: available as f64 / total as f64,
                    ..plain(total.saturating_sub(available) as f64 * 100.0 / total as f64)
                })
            }
            MetricsFigure::HostDisk => {
                let host = host?;
                let (total, available) = (host.disk_total?, host.disk_available?);
                (total > 0).then(|| Reading {
                    second: available as f64 / total as f64,
                    ..plain(available as f64 / GIB)
                })
            }
            MetricsFigure::DnsQueries => dns.map(|dns| plain(dns.queries_per_second)),
            MetricsFigure::DnsCache => dns.and_then(|dns| {
                let hits = dns.cache.hits_per_second;
                ratio(hits, hits + dns.cache.misses_per_second)
            }),
            MetricsFigure::DnsAnswers => dns.and_then(|dns| {
                let rcodes = &dns.rcodes;
                ratio(
                    rcodes.noerror,
                    rcodes.noerror
                        + rcodes.nxdomain
                        + rcodes.servfail
                        + rcodes.refused
                        + rcodes.other,
                )
            }),
            MetricsFigure::DnsBlocked => {
                dns.map(|dns| plain(dns.blocked.iter().map(|list| list.per_second).sum()))
            }
            MetricsFigure::DnsUpstreams => dns.map(|dns| plain(dns.upstreams.queries_per_second)),
            MetricsFigure::DnsSubqueries => dns
                .and_then(|dns| dns.recursion.as_ref())
                .map(|recursion| plain(recursion.subqueries_per_second)),
            MetricsFigure::DnsValidation => {
                dns.and_then(|dns| dns.recursion.as_ref()).map(|recursion| {
                    let v = &recursion.validation;
                    plain(v.secure + v.insecure + v.bogus + v.indeterminate)
                })
            }
            MetricsFigure::DnsEncrypted => dns
                .and_then(|dns| dns.connections.as_ref())
                .map(|connections| plain(connections.dot.saturating_add(connections.doh) as f64)),
            MetricsFigure::DhcpLeases => dhcp.map(|dhcp| plain(dhcp.leases_per_second)),
            MetricsFigure::DhcpAck => dhcp.and_then(|dhcp| dhcp.ack_p99_ms).map(plain),
            MetricsFigure::DhcpActive => dhcp.map(|dhcp| plain(dhcp.active_leases as f64)),
            MetricsFigure::DhcpPools => dhcp
                .and_then(|dhcp| dhcp.fullest.first())
                .map(|pool| plain(pool.utilization * 100.0)),
            MetricsFigure::DhcpNaks => {
                dhcp.map(|dhcp| plain(dhcp.naks_per_second + dhcp.declines_per_second))
            }
            MetricsFigure::DhcpDdns => dhcp.map(|dhcp| plain(dhcp.ddns.written)),
        }
    }
}

impl fmt::Display for MetricsFigure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The history of the dashboard's tiles: the data of the `metrics.history` event, the first
/// event of the `metrics` topic on a stream (see [`METRICS_HISTORY_KIND`] for the order).
///
/// Two days of every figure in five tiers (DH-Q2 (b); [`HISTORY_TIERS`]), combined for the
/// cluster from each controller's own tiers (DH-Q5 (a), [`MetricsMerge`]); on a single
/// controller, its own. The serving controller builds it as buckets close and encodes it once
/// per change; every new subscriber gets that one cached frame, so nothing is built per
/// subscription. Kept in memory only (DH-Q3 (a)): a controller that restarted has no history
/// before its start. With 25 figures and three controllers the frame stays under 300 KB
/// (M84); its values carry [`HISTORY_SIGNIFICANT_DIGITS`] significant digits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsHistory {
    /// The moment the history ends, by the serving controller's clock: the end (`at`) of the
    /// newest sample folded into it. The chart draws at the controller's time, not the
    /// browser's.
    pub at: Timestamp,
    /// The controllers whose tiers the history combines, the serving controller first, the
    /// others as in `MetricsSnapshot.nodes`.
    pub controllers: Vec<MetricsHistoryController>,
    /// The figures, in the order of `MetricsFigure`: those a controller of the cluster
    /// produces (its roles run them). A figure that is missing has no tile.
    pub figures: Vec<MetricsFigureHistory>,
}

/// A controller whose tiers a [`MetricsHistory`] combines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MetricsHistoryController {
    /// The controller; absent on a single controller without a node id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeId>,
    /// When its history starts: the controller's start, by its own clock. A history kept in
    /// memory has nothing before it, so the chart marks it as a restart and hatches the time
    /// before it ("No history before 07:21, when this controller restarted"). Absent while the
    /// controller has sent no history (it has not answered yet, or it runs the previous
    /// release).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<Timestamp>,
    /// The controller runs a release without the history (it answered `Metrics.History` with
    /// `UNIMPLEMENTED`): it is missing from every bucket, drawn and worded like a controller
    /// that is down.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unsupported: bool,
}

/// One figure of a [`MetricsHistory`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsFigureHistory {
    /// The figure.
    pub figure: MetricsFigure,
    /// How the cluster combined it, which the readout says ("The mean is exact; the true
    /// range lies inside").
    pub merge: MetricsMerge,
    /// Its tiers, finest first, at most five; a tier without a bucket yet is left out.
    pub tiers: Vec<MetricsTier>,
}

/// One figure's buckets that closed, in a [`MetricsSnapshot::closed`]. A bucket is closed once
/// its step has ended on the controller's clock and the fold has moved to the next one: a
/// controller never changes it again (a clock that jumps back folds into the open bucket, never
/// into a closed one). Only the serving controller's combination may send a closed bucket again
/// with a late controller's part added.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsClosed {
    /// The figure.
    pub figure: MetricsFigure,
    /// The tiers with a bucket that closed in this tick or the tick before, finest first;
    /// `open` is never set here.
    pub tiers: Vec<MetricsTier>,
}

/// Consecutive buckets of one tier of a figure, oldest first, as columns: element `i` of every
/// array is bucket `i`, and every array has the same length, at least one.
///
/// Bucket `i` covers `[start − (n − 1 − i) × step_ms, … + step_ms)` where `n` is the length:
/// the buckets follow each other without a hole, and the starts are whole multiples of
/// `step_ms` since the Unix epoch on the controller's clock in UTC (a minute bucket starts at a
/// whole minute, an hour bucket at a whole hour). A bucket without any data is still in the
/// arrays: its `covered_ms` and `controllers` are 0 and its `lowest`, `highest` and `mean` are
/// null; the chart hatches it. A bucket with some time missing has values and a
/// `covered_ms` below `step_ms` ("41 s of 1 min"). A finer tier covers the time until the next
/// coarser bucket starts, so the client holds both where they overlap. A history never has
/// more buckets in a tier than its ring ([`TierSpec::buckets`]), and none before the
/// controllers' start.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsTier {
    /// The length of a bucket in milliseconds: 1,000 (5,000 for the ratio figures), 10,000,
    /// 60,000, 600,000 or 3,600,000.
    pub step_ms: u32,
    /// The start of the newest bucket, the last of the arrays.
    pub start: Timestamp,
    /// The newest bucket is the open one, still filling: its values change until its step
    /// ends, and a `closed` of a later snapshot replaces it. Only in a history; absent when
    /// every bucket is closed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub open: bool,
    /// The most buckets the client keeps of this tier, the open one included (the ring of the
    /// controllers, [`TierSpec::buckets`]): after appending the buckets of a `closed`, the
    /// client drops the oldest beyond it. Present in a history, absent in a `closed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring: Option<u16>,
    /// The lowest value of each bucket, in the figure's unit; null without data.
    #[serde(serialize_with = "significant")]
    pub lowest: Vec<Option<f64>>,
    /// The highest value of each bucket, in the figure's unit; null without data. With
    /// `lowest`, the band of the chart.
    #[serde(serialize_with = "significant")]
    pub highest: Vec<Option<f64>>,
    /// The mean of each bucket over its covered time, in the figure's unit (a ratio's
    /// recomputed from the counts); null without data. The line of the chart.
    #[serde(serialize_with = "significant")]
    pub mean: Vec<Option<f64>>,
    /// The time each bucket had data, in milliseconds, at most `step_ms`: the parts of the
    /// samples' intervals that fall into it (see [`Reading`]), so a second without a sample of
    /// its own is not a gap when a longer interval covers it. For the cluster, the longest of
    /// the controllers' covered times.
    pub covered_ms: Vec<u32>,
    /// How many controllers each bucket covers; below the number of `controllers` of the
    /// history, the chart draws a lighter band and a bar under the baseline ("2 of 3
    /// controllers reported"). 0 for a bucket without data.
    pub controllers: Vec<u16>,
}

impl MetricsTier {
    /// The number of buckets.
    pub fn len(&self) -> usize {
        self.covered_ms.len()
    }

    /// Whether the tier has no bucket.
    pub fn is_empty(&self) -> bool {
        self.covered_ms.is_empty()
    }

    /// Whether the columns hold together: equal lengths within the ring, values exactly where
    /// there is data, lowest at most highest, covered time within a step.
    pub fn is_consistent(&self) -> bool {
        let n = self.len();
        if self.ring.is_some_and(|ring| n > usize::from(ring))
            || self.lowest.len() != n
            || self.highest.len() != n
            || self.mean.len() != n
            || self.controllers.len() != n
        {
            return false;
        }
        (0..n).all(|i| {
            let data = self.covered_ms[i] > 0;
            let values = [self.lowest[i], self.highest[i], self.mean[i]];
            self.covered_ms[i] <= self.step_ms
                && (self.controllers[i] > 0) == data
                && values.iter().all(|value| value.is_some() == data)
                && match (self.lowest[i], self.highest[i]) {
                    (Some(low), Some(high)) => low <= high,
                    _ => true,
                }
        })
    }
}

/// `value` rounded to [`HISTORY_SIGNIFICANT_DIGITS`] significant digits (`9876.5` to `9877`,
/// `0.0123456` to `0.01235`); 0, a value that is not finite and one beyond 10^±22 unchanged.
pub fn round_significant(value: f64) -> f64 {
    const POW10: [f64; 23] = [
        1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16,
        1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
    ];
    if value == 0.0 || !value.is_finite() {
        return value;
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the decimal exponent of an f64"
    )]
    let mut magnitude = value.abs().log10().floor() as i32;
    // `log10` may miss an exact power of ten by one.
    let power = |exponent: i32| {
        let index = usize::try_from(exponent.unsigned_abs()).unwrap_or(usize::MAX);
        POW10
            .get(index)
            .map(|scale| if exponent < 0 { 1.0 / scale } else { *scale })
    };
    if power(magnitude + 1).is_some_and(|next| value.abs() >= next) {
        magnitude += 1;
    } else if power(magnitude).is_some_and(|this| value.abs() < this) {
        magnitude -= 1;
    }
    #[allow(clippy::cast_possible_wrap, reason = "four digits")]
    let shift = HISTORY_SIGNIFICANT_DIGITS as i32 - 1 - magnitude;
    let Some(scale) = usize::try_from(shift.unsigned_abs())
        .ok()
        .and_then(|index| POW10.get(index))
    else {
        return value;
    };
    if shift >= 0 {
        (value * scale).round() / scale
    } else {
        (value / scale).round() * scale
    }
}

/// Serializes a column of values with [`round_significant`], a whole number without a
/// fraction (`752`, not `752.0`), and null for a missing or non-finite value. Writes element by
/// element: no allocation beyond the output.
fn significant<S: serde::Serializer>(
    values: &[Option<f64>],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq as _;

    /// Below 2^53, every whole f64 is an exact i64.
    const EXACT: f64 = 9_007_199_254_740_992.0;
    let mut seq = serializer.serialize_seq(Some(values.len()))?;
    for value in values {
        match value.map(round_significant) {
            Some(v) if v.is_finite() && v.fract() == 0.0 && v.abs() < EXACT => {
                #[allow(clippy::cast_possible_truncation, reason = "a whole number below 2^53")]
                seq.serialize_element(&(v as i64))?;
            }
            Some(v) if v.is_finite() => seq.serialize_element(&v)?,
            _ => seq.serialize_element(&None::<f64>)?,
        }
    }
    seq.end()
}

// Between controllers: each controller's own tiers, in CBOR (never on the HTTP API).

/// The encoding of [`ControllerTiers`] in the `payload` of `Metrics.History` and the `closed`
/// of `Metrics.Snapshot`: CBOR, the same name as the sample's encoding
/// (`tenko_cluster::metrics::SAMPLE_ENCODING`).
pub const CONTROLLER_TIERS_ENCODING: &str = "cbor/1";

/// One bucket of a controller's own tier: [`BUCKET_BYTES`] (32) bytes in memory, the element
/// of the rings the fold fills, and five numbers in CBOR (an array, not a map).
///
/// The fold of a sample with a [`Reading`] takes `lowest` and `highest` of the reading's value,
/// adds the reading's `sum` and `second` times the part of the sample's interval that falls
/// into the bucket to `sum` and `second`, and that part to `covered_ms` (see [`Reading`]);
/// [`MetricsBucket::EMPTY`] is the start, so the fold needs no branch. The fold changes the
/// rings in place and allocates nothing (M82). The combination of the controllers' buckets
/// works in `f64`, so a sum of finite `f32` values cannot overflow.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(from = "BucketWire", into = "BucketWire")]
pub struct MetricsBucket {
    /// The lowest value folded, in the figure's unit; +∞ while empty.
    pub lowest: f32,
    /// The highest value folded; −∞ while empty.
    pub highest: f32,
    /// Σ [`Reading::sum`] × the milliseconds of each sample in the bucket.
    pub sum: f64,
    /// Σ [`Reading::second`] × the milliseconds of each sample in the bucket: a ratio's whole,
    /// the host's share available, otherwise 0.
    pub second: f64,
    /// The milliseconds of the samples' intervals in the bucket, at most the bucket's step.
    pub covered_ms: u32,
}

/// [`MetricsBucket`] in CBOR: `[lowest, highest, sum, second, covered_ms]`.
type BucketWire = (f32, f32, f64, f64, u32);

impl From<BucketWire> for MetricsBucket {
    fn from((lowest, highest, sum, second, covered_ms): BucketWire) -> Self {
        Self {
            lowest,
            highest,
            sum,
            second,
            covered_ms,
        }
    }
}

impl From<MetricsBucket> for BucketWire {
    fn from(bucket: MetricsBucket) -> Self {
        (
            bucket.lowest,
            bucket.highest,
            bucket.sum,
            bucket.second,
            bucket.covered_ms,
        )
    }
}

impl MetricsBucket {
    /// A bucket without data.
    pub const EMPTY: MetricsBucket = MetricsBucket {
        lowest: f32::INFINITY,
        highest: f32::NEG_INFINITY,
        sum: 0.0,
        second: 0.0,
        covered_ms: 0,
    };

    /// The mean over the covered time, in the figure's unit: `sum / covered_ms`, a ratio's
    /// `100 × sum / second`; `None` without data (or a ratio without a lookup).
    pub fn mean(&self, merge: MetricsMerge) -> Option<f64> {
        if self.covered_ms == 0 {
            return None;
        }
        match merge {
            MetricsMerge::Ratio => (self.second > 0.0).then(|| self.sum * 100.0 / self.second),
            _ => Some(self.sum / f64::from(self.covered_ms)),
        }
    }

    /// Whether the bucket is one the fold can produce for a figure with `merge`: without data
    /// exactly [`MetricsBucket::EMPTY`]; with data finite values with the lowest at most the
    /// highest, and sums that agree with them: a ratio's part between 0 and its whole and its
    /// shares between 0 and 100 %, the host's share available between 0 and 1 per millisecond,
    /// no second sum otherwise, and the mean between the lowest and the highest. A peer's
    /// bucket that is not sound would let one controller decide a combination (a negative
    /// share available wins every bucket) or turn a value into infinity.
    pub fn is_sound(&self, merge: MetricsMerge) -> bool {
        if self.covered_ms == 0 {
            return self.lowest.is_infinite()
                && self.lowest.is_sign_positive()
                && self.highest.is_infinite()
                && self.highest.is_sign_negative()
                && self.sum == 0.0
                && self.second == 0.0;
        }
        let (low, high) = (f64::from(self.lowest), f64::from(self.highest));
        let finite =
            low.is_finite() && high.is_finite() && self.sum.is_finite() && self.second.is_finite();
        if !finite || low > high {
            return false;
        }
        let covered = f64::from(self.covered_ms);
        // The f32 values and the f64 sums round differently.
        let slack = 1e-4 * low.abs().max(high.abs()).max(1.0);
        match merge {
            MetricsMerge::Ratio => {
                self.sum >= 0.0
                    && self.second > 0.0
                    && self.sum <= self.second * (1.0 + 1e-9)
                    && low >= -slack
                    && high <= 100.0 + slack
            }
            MetricsMerge::LeastAvailable => {
                let mean = self.sum / covered;
                (0.0..=covered * (1.0 + 1e-9)).contains(&self.second)
                    && mean >= low - slack
                    && mean <= high + slack
            }
            MetricsMerge::Sum | MetricsMerge::Highest => {
                let mean = self.sum / covered;
                self.second == 0.0 && mean >= low - slack && mean <= high + slack
            }
        }
    }
}

/// A controller's own tiers as it sends them to the other controllers: the whole history in
/// the answer to `Metrics.History` (fetched when a peer first appears and when it answers
/// again after missing calls, never per subscription), and the buckets that closed in its last
/// two ticks in the `closed` of its answer to `Metrics.Snapshot`, which a controller with the
/// history always sends (with its `started` and no figure when nothing closed), so the serving
/// controller sees a restart within a second. About 230 KB for a whole history of 25 figures,
/// under the caller's limit of 1 MiB.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControllerTiers {
    /// When this controller's history starts (its start, memory only). A change tells the
    /// serving controller that the peer restarted: it fetches the peer's history again.
    pub started: Timestamp,
    /// The figures this controller's roles produce, in the order of [`MetricsFigure::ALL`].
    pub figures: Vec<ControllerFigure>,
}

/// One figure of [`ControllerTiers`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControllerFigure {
    /// The figure.
    pub figure: MetricsFigure,
    /// Its tiers, finest first; one of [`MetricsFigure::tiers`] each, at most once.
    pub tiers: Vec<ControllerTier>,
}

/// Consecutive buckets of one tier of a controller, oldest first; the starts as in
/// [`MetricsTier`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControllerTier {
    /// The length of a bucket in milliseconds.
    pub step_ms: u32,
    /// The start of the newest bucket, the last of `buckets`.
    pub start: Timestamp,
    /// The newest bucket is the open one (only in the answer to `Metrics.History`).
    pub open: bool,
    /// The buckets, at most the ring's [`TierSpec::buckets`].
    pub buckets: Vec<MetricsBucket>,
}

/// [`ControllerTiers`] as a newer peer may send it: figures by name, so that a figure or a step
/// this build does not know is skipped rather than refusing the whole answer during a rolling
/// update.
#[derive(Deserialize)]
struct LenientTiers {
    started: Timestamp,
    figures: Vec<LenientFigure>,
}

#[derive(Deserialize)]
struct LenientFigure {
    figure: String,
    tiers: Vec<ControllerTier>,
}

impl ControllerTiers {
    /// Decodes and checks a peer's tiers. A figure this build does not know, and a tier whose
    /// step is not one of the figure's here, are skipped (a newer peer during a rolling
    /// update); everything else must pass [`ControllerTiers::check`].
    ///
    /// # Errors
    ///
    /// A text for the log when `encoding` is not [`CONTROLLER_TIERS_ENCODING`], the bytes do
    /// not decode, or [`ControllerTiers::check`] refuses them.
    pub fn decode(encoding: &str, payload: &[u8]) -> Result<Self, String> {
        if encoding != CONTROLLER_TIERS_ENCODING {
            return Err(format!("the tiers are in an unknown encoding {encoding}"));
        }
        let lenient: LenientTiers = tenko_core::codec::from_cbor(payload)
            .map_err(|error| format!("the tiers do not decode: {error}"))?;
        let figures = lenient
            .figures
            .into_iter()
            .filter_map(|wire| {
                let figure = MetricsFigure::ALL
                    .into_iter()
                    .find(|known| known.as_str() == wire.figure)?;
                let steps = figure.tiers();
                let tiers = wire
                    .tiers
                    .into_iter()
                    .filter(|tier| steps.iter().any(|spec| spec.step_ms == tier.step_ms))
                    .collect();
                Some(ControllerFigure { figure, tiers })
            })
            .collect();
        let tiers = Self {
            started: lenient.started,
            figures,
        };
        tiers.check()?;
        Ok(tiers)
    }

    /// Checks what the combination relies on, so that a peer's tiers cannot make it index out
    /// of bounds or poison a bucket: each figure once and in order, each tier one of the
    /// figure's steps and in order, no more buckets than the ring, starts on the step, covered
    /// time within the step, and [`MetricsBucket::is_sound`] for every bucket.
    ///
    /// # Errors
    ///
    /// A text for the log that names the first fault.
    pub fn check(&self) -> Result<(), String> {
        let mut last_figure: Option<MetricsFigure> = None;
        for figure in &self.figures {
            if last_figure.is_some_and(|last| last >= figure.figure) {
                return Err(format!("the figure {} is out of order", figure.figure));
            }
            last_figure = Some(figure.figure);
            let specs = figure.figure.tiers();
            let mut next_spec = 0;
            for tier in &figure.tiers {
                let Some(offset) = specs[next_spec..]
                    .iter()
                    .position(|spec| spec.step_ms == tier.step_ms)
                else {
                    return Err(format!(
                        "the figure {} has a tier of {} ms out of order or unknown",
                        figure.figure, tier.step_ms
                    ));
                };
                let spec = specs[next_spec + offset];
                next_spec += offset + 1;
                if tier.buckets.is_empty() || tier.buckets.len() > spec.buckets {
                    return Err(format!(
                        "the figure {} has {} buckets of {} ms",
                        figure.figure,
                        tier.buckets.len(),
                        tier.step_ms
                    ));
                }
                let step_nanos = i128::from(tier.step_ms) * 1_000_000;
                if tier.start.unix_nanos().rem_euclid(step_nanos) != 0 {
                    return Err(format!(
                        "the figure {} has a tier of {} ms that does not start on its step",
                        figure.figure, tier.step_ms
                    ));
                }
                let merge = figure.figure.merge();
                if !tier
                    .buckets
                    .iter()
                    .all(|bucket| bucket.covered_ms <= tier.step_ms && bucket.is_sound(merge))
                {
                    return Err(format!(
                        "the figure {} has a bucket of {} ms that does not hold together",
                        figure.figure, tier.step_ms
                    ));
                }
            }
        }
        Ok(())
    }
}

/// One controller's metrics over one interval (about a second), built from two consecutive
/// snapshots of its metrics registry: rates and quantiles from the change of the counters
/// and histograms, the rest from the gauges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsSample {
    /// The controller; absent on the cluster sum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeId>,
    /// When the sample was taken, by the controller's clock.
    pub at: Timestamp,
    /// The span of the rates and quantiles in milliseconds; 0 for a first sample, which
    /// has no rates and no quantiles.
    pub interval_ms: u64,
    /// The controller did not answer this second: the sample is its last good one, or, with
    /// no role, an empty one when it has not answered yet.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
    /// The controller runs an older build without the metrics exchange: it has no figures.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unsupported: bool,
    /// The HTTP API.
    pub api: MetricsApi,
    /// The store.
    pub store: MetricsStore,
    /// Raft.
    pub raft: MetricsRaft,
    /// The jobs that are not finished.
    pub jobs: MetricsJobs,
    /// The observations the reconciler ingests.
    pub ingest: MetricsIngest,
    /// The event stream.
    pub sse: MetricsSse,
    /// The nodes connected to the controller and their buffers.
    pub nodes: Vec<MetricsNode>,
    /// The `dns` role of the controller's process; absent when the process does not run it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<MetricsDns>,
    // WP8.7: the `dhcp` role's part of the sample (OPS-20, the DHCP tiles).
    /// The `dhcp` role of the controller's process; absent when the process does not run it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<MetricsDhcp>,
    /// The host under the controller: CPU, memory and the file system of the data directory,
    /// as the node last read them (every five seconds); absent when none could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<MetricsHost>,
}

impl MetricsSample {
    /// A sample without figures (a controller that did not answer, or the sum of none).
    pub fn empty(node: Option<NodeId>, at: Timestamp) -> Self {
        Self {
            node,
            at,
            interval_ms: 0,
            stale: false,
            unsupported: false,
            api: MetricsApi::default(),
            store: MetricsStore::default(),
            raft: MetricsRaft::default(),
            jobs: MetricsJobs::default(),
            ingest: MetricsIngest::default(),
            sse: MetricsSse::default(),
            nodes: Vec::new(),
            dns: None,
            // WP8.7: the `dhcp` role's part.
            dhcp: None,
            host: None,
        }
    }
}

/// The HTTP API of a sample: requests under `/api/v1` (the files of the web UI do not count).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsApi {
    /// Requests per second.
    pub requests_per_second: f64,
    /// The median time to the response head in milliseconds; absent without requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p50_ms: Option<f64>,
    /// The 99th percentile in milliseconds; absent without requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p99_ms: Option<f64>,
}

/// The store of a sample.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsStore {
    /// Bytes of live data (keys and values).
    pub data_bytes: u64,
    /// Bytes on disk: the Raft log, the state file and the snapshots; absent for an
    /// in-memory store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_bytes: Option<u64>,
    /// The 99th percentile of the time from a proposal to its commit in milliseconds;
    /// absent without writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_p99_ms: Option<f64>,
}

/// Raft in a sample.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsRaft {
    /// The member's role: `leader`, `follower`, `learner`, `candidate`, `shutdown` or
    /// `memory`; absent on the cluster sum and for a controller without figures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The term the member knows.
    pub term: u64,
    /// Log entries members are behind the leader: every member on the leader, this member
    /// on a follower.
    pub lag: Vec<MetricsLag>,
}

/// The replication lag of one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MetricsLag {
    /// The member.
    pub node: NodeId,
    /// Log entries it is behind the leader.
    pub entries: u64,
}

/// The jobs of a sample. The jobs are shared by the cluster, so every controller counts the
/// same ones and the cluster takes the highest count.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MetricsJobs {
    /// Jobs running.
    pub running: u64,
    /// Jobs waiting for a person or an observation.
    pub waiting: u64,
}

/// The ingest of observations in a sample.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsIngest {
    /// Observation batches per second.
    pub batches_per_second: f64,
    /// Observations (facts) per second.
    pub facts_per_second: f64,
}

/// The event stream of a sample.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MetricsSse {
    /// Open event streams.
    pub subscribers: u64,
}

/// A node connected to the controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MetricsNode {
    /// The node.
    pub node: NodeId,
    /// Observation batches waiting in its disk buffer.
    pub buffer_batches: u64,
    /// Batches its buffer dropped since the node started, as its last heartbeat reported;
    /// absent when the node registry does not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drops: Option<u64>,
}

/// The `dns` role in a sample (OPS-20): the queries it answered, the cache, the upstreams, the
/// block lists, the encrypted transports and the query log over the interval.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsDns {
    /// Queries answered per second, over every transport.
    pub queries_per_second: f64,
    /// Queries answered per second by transport.
    pub transports: MetricsDnsTransports,
    /// The median time from a query's arrival to its answer in milliseconds; absent without
    /// queries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p50_ms: Option<f64>,
    /// The 99th percentile in milliseconds; absent without queries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p99_ms: Option<f64>,
    /// Answers per second by RCODE.
    pub rcodes: MetricsDnsRcodes,
    /// The cache.
    pub cache: MetricsDnsCache,
    /// The exchanges with upstream resolvers.
    pub upstreams: MetricsDnsUpstreams,
    /// Queries blocked per second by each block list or policy zone that blocked one since
    /// the role started, by list name.
    pub blocked: Vec<MetricsDnsBlocked>,
    /// Open DoT and DoH connections; absent when the role serves neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connections: Option<MetricsDnsConnections>,
    /// Query log entries dropped per second (the ring was full or the disk failed).
    pub log_dropped_per_second: f64,
    // WP10.4: the recursive resolver's figures.
    /// The recursive resolver: the validation outcomes and the queries it sent to
    /// authorities; absent while recursion is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recursion: Option<MetricsDnsRecursion>,
}

/// The recursive resolver in a sample (recursion plan section 2.11).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsDnsRecursion {
    /// Queries sent to authorities per second (`tenko_dns_authority_queries_total`), the
    /// validator's DS and DNSKEY queries included.
    pub subqueries_per_second: f64,
    /// Validation outcomes per second.
    pub validation: MetricsDnsValidation,
}

/// DNSSEC validation outcomes per second, by state (`tenko_dns_validation_total`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsDnsValidation {
    /// Answers proven secure.
    pub secure: f64,
    /// Answers proven insecure (no chain of trust, or a negative trust anchor).
    pub insecure: f64,
    /// Answers that failed validation (SERVFAIL unless the client set CD).
    pub bogus: f64,
    /// Answers no trust anchor covers.
    pub indeterminate: f64,
}
// WP10.4: end.

/// Queries answered per second by transport.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsDnsTransports {
    /// Over UDP.
    pub udp: f64,
    /// Over TCP.
    pub tcp: f64,
    /// Over DNS over TLS.
    pub dot: f64,
    /// Over DNS over HTTPS.
    pub doh: f64,
}

/// Answers per second by RCODE.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsDnsRcodes {
    /// NOERROR, with or without records.
    pub noerror: f64,
    /// NXDOMAIN.
    pub nxdomain: f64,
    /// SERVFAIL.
    pub servfail: f64,
    /// REFUSED.
    pub refused: f64,
    /// Every other RCODE.
    pub other: f64,
}

/// The cache of the `dns` role in a sample.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsDnsCache {
    /// Hits over hits and misses in the interval, 0 to 1; absent without a lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hit_ratio: Option<f64>,
    /// Forwarded queries the cache answered, per second.
    pub hits_per_second: f64,
    /// Forwarded queries the cache could not answer, per second.
    pub misses_per_second: f64,
    /// Stale answers (RFC 8767) per second.
    pub stale_per_second: f64,
    /// Entries in the cache.
    pub entries: u64,
}

/// The upstream resolvers in a sample.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsDnsUpstreams {
    /// Exchanges with upstreams per second, whatever their outcome.
    pub queries_per_second: f64,
    /// The 99th percentile of the round-trip time of the answered exchanges in milliseconds;
    /// absent without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p99_ms: Option<f64>,
}

/// The queries one block list blocked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsDnsBlocked {
    /// The list, as the `list` label of `tenko_dns_blocked_total` names it.
    pub list: String,
    /// Queries blocked per second.
    pub per_second: f64,
}

/// The open connections of the encrypted transports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MetricsDnsConnections {
    /// Open DNS over TLS connections.
    pub dot: u64,
    /// Open DNS over HTTPS connections.
    pub doh: u64,
}

// WP8.7: the `dhcp` role in a sample (OPS-20, the DHCP tiles of the start page).
/// The host in a sample (OPS-20): the latest reading of the machine under the controller. It is
/// read every five seconds, so consecutive samples repeat it. A figure that could not be read is
/// absent. The cluster's sample holds, for each figure, the controller that is worst off: the
/// busiest CPU, the smallest share of memory and of disk available.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsHost {
    /// The share of the CPU's time that was busy since the previous reading, 0 to 100; absent in
    /// the first reading and where the CPU is not read (Windows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<f64>,
    /// Physical memory in bytes; absent where memory is not read (Windows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_total: Option<u64>,
    /// Memory a program can use without swapping, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_available: Option<u64>,
    /// The size of the file system of the data directory in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_total: Option<u64>,
    /// The space available on that file system in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_available: Option<u64>,
}

/// The `dhcp` role in a sample (OPS-20): the leases it granted, the time from a REQUEST to its
/// ACK, the leases it holds, the fullest pools, the NAKs and DECLINEs and the DDNS outcomes over
/// the interval.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsDhcp {
    /// Leases granted per second: REQUESTs answered with an ACK (new, renewed, rebound and
    /// after a reboot).
    pub leases_per_second: f64,
    /// The 99th percentile of the time from a REQUEST's arrival to its ACK in milliseconds,
    /// the commit included; absent without an ACK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_p99_ms: Option<f64>,
    /// NAKs sent per second.
    pub naks_per_second: f64,
    /// DECLINEs received per second.
    pub declines_per_second: f64,
    /// Leases in the role's table whose binding is active.
    pub active_leases: u64,
    /// Leases held back as abandoned (a conflict found by the probe, or a DECLINE).
    pub abandoned_leases: u64,
    /// Scopes with a pool that the role serves.
    pub scopes: u64,
    /// The three fullest scopes, the fullest first.
    pub fullest: Vec<MetricsDhcpPool>,
    /// DDNS change sets per second by outcome.
    pub ddns: MetricsDhcpDdns,
}

/// How full the pools of one scope are.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsDhcpPool {
    /// The scope by its network (`192.0.2.0/24`), as the `scope` label of
    /// `tenko_dhcp_pool_utilization` names it.
    pub scope: String,
    /// Active bindings in the scope's pools over the pools' addresses, 0 to 1.
    pub utilization: f64,
}

/// DDNS change sets per second by outcome (`tenko_dhcp_ddns_total{outcome}`), and the queue.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MetricsDhcpDdns {
    /// Names written.
    pub written: f64,
    /// Names removed on release, expiry or a change of name.
    pub removed: f64,
    /// Refused: name protection, another origin's records, a zone that takes no DHCP updates.
    pub refused: f64,
    /// The zone service or the store failed after the retries.
    pub failed: f64,
    /// Nothing to write: IPAM names the address, or the scope names no zone.
    pub skipped: f64,
    /// Dropped from a full queue; the lease rows are read again.
    pub dropped: f64,
    /// Requests waiting for the worker.
    pub queue: u64,
}

/// Why a `reset` event was sent: the client must reload its state at `revision` or later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResetReason {
    /// The client fell too far behind the live stream.
    Lagged,
    /// `Last-Event-ID` is unknown, in the future, or older than the retained journal.
    Gap,
    /// The server lost its own position in the store journal.
    Journal,
}

/// The `data` of a `reset` event. Its SSE id is `revision`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ResetData {
    /// Why the client must reload.
    pub reason: ResetReason,
    /// Reload at this revision or later (`at_least` on list endpoints).
    pub revision: Revision,
}

/// Why the server ended an event stream with an `end` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// The session or token the stream was opened with no longer acts: it was signed out,
    /// revoked or expired, the password changed, or the account was disabled or deleted. A
    /// new stream with it is refused with 401, as any request is: sign in again.
    AccessEnded,
    /// What the credential may read changed (a role or a grant), or could not be confirmed:
    /// open the stream again to receive what it may read now.
    AccessChanged,
}

/// The `data` of an `end` event, the last event of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EndData {
    /// Why the stream ended.
    pub reason: EndReason,
}

#[cfg(test)]
mod tests {
    use tenko_core::ObjectKind;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn topics_parse_and_print() {
        for topic in Topic::ALL {
            assert_eq!(topic.as_str().parse::<Topic>().expect("parse"), topic);
            assert_eq!(
                serde_json::to_value(topic).expect("json"),
                serde_json::Value::String(topic.as_str().to_owned())
            );
        }
        assert!("ntp".parse::<Topic>().is_err());
    }

    #[test]
    fn topic_sets() {
        assert_eq!(TopicSet::parse("").expect("empty"), TopicSet::DEFAULT);
        assert!(!TopicSet::DEFAULT.contains(Topic::Metrics));
        assert_eq!(
            TopicSet::DEFAULT.topics().count(),
            Topic::ALL.len() - 1,
            "only metrics is left out"
        );
        assert!(
            TopicSet::parse("metrics")
                .expect("metrics")
                .contains(Topic::Metrics)
        );
        let set = TopicSet::parse(" ipam , jobs,").expect("set");
        assert!(set.contains(Topic::Ipam) && set.contains(Topic::Jobs));
        assert!(!set.contains(Topic::Audit));
        assert_eq!(set.topics().count(), 2);
        assert_eq!(TopicSet::ALL.topics().count(), Topic::ALL.len());
        assert!(TopicSet::parse("ipam,ntp").is_err());
        let mut both = TopicSet::parse("metrics,jobs").expect("set");
        both.remove(Topic::Metrics);
        assert_eq!(both, TopicSet::parse("jobs").expect("jobs"));
    }

    #[test]
    fn a_metrics_event_carries_the_samples_and_marks_stale_ones() {
        let at = Timestamp::from_unix_nanos(1_791_547_200_000_000_000).expect("time");
        let mut own = MetricsSample::empty(Some(tenko_core::NodeId(1)), at);
        own.api.requests_per_second = 2.5;
        own.raft.role = Some("leader".to_owned());
        let mut peer = MetricsSample::empty(Some(tenko_core::NodeId(2)), at);
        peer.stale = true;
        let mut data = EventData::new(Topic::Metrics, None);
        data.kind = Some("metrics.snapshot".to_owned());
        data.metrics = Some(MetricsSnapshot {
            cluster: MetricsSample::empty(None, at),
            nodes: vec![own, peer],
            closed: Vec::new(),
        });
        assert!(!data.is_empty());
        let json = serde_json::to_value(&data).expect("json");
        assert_eq!(json["topic"], "metrics");
        assert_eq!(json["kind"], "metrics.snapshot");
        assert!(json.get("revision").is_none());
        let nodes = &json["metrics"]["nodes"];
        assert_eq!(nodes[0]["node"], 1);
        assert_eq!(nodes[0]["api"]["requests_per_second"], 2.5);
        assert!(
            nodes[0]["api"].get("p50_ms").is_none(),
            "no requests, no quantile"
        );
        assert!(nodes[0].get("stale").is_none());
        assert_eq!(nodes[1]["stale"], true);
        assert!(json["metrics"]["cluster"].get("node").is_none());
        let back: EventData = serde_json::from_value(json).expect("back");
        assert_eq!(back, data);
    }

    #[test]
    fn event_data_shape_matches_the_plan() {
        let mut data = EventData::new(Topic::Ipam, Some(Revision(4712)));
        data.objects.push(ObjectRef::new(
            ObjectKind::Address,
            Uuid::from_u128(0x0190_d1c2_0000_7000_8000_0000_0000_0001),
        ));
        assert_eq!(
            serde_json::to_value(&data).expect("json"),
            serde_json::json!({
                "topic": "ipam",
                "revision": 4712,
                "objects": [{ "kind": "address", "id": "0190d1c2-0000-7000-8000-000000000001" }]
            })
        );
        assert!(!data.is_empty());
        assert!(EventData::new(Topic::Jobs, None).is_empty());
    }

    // WP18.0: the contracts of the dashboard's history.

    /// The golden example of the `metrics` topic: one `metrics.history` and one
    /// `metrics.snapshot` with `closed`, one compact JSON document a line, as the `data:` lines
    /// of the stream carry them. The UI's contract test reads the same bytes
    /// (`ui/src/api/metrics-history.contract.test.ts`).
    const GOLDEN_STREAM: &str = include_str!("../../../../docs/api/examples/metrics-stream.jsonl");
    /// The number of every figure for the cluster sample of the golden snapshot, which the UI's
    /// `tileValue` must give too.
    const GOLDEN_FIGURES: &str = include_str!("../../../../docs/api/examples/metrics-figures.json");

    /// A whole hour of the controller's clock.
    const T0: i128 = 1_791_547_200;

    fn time(seconds: i128, millis: i128) -> Timestamp {
        Timestamp::from_unix_nanos((seconds * 1_000 + millis) * 1_000_000).expect("time")
    }

    fn full_sample(node: Option<NodeId>) -> MetricsSample {
        let mut sample = MetricsSample::empty(node, time(T0 + 3, 400));
        sample.interval_ms = 1_000;
        sample.api.requests_per_second = 2.5;
        sample.store = MetricsStore {
            data_bytes: 6_300_000,
            file_bytes: Some(25_100_000),
            commit_p99_ms: Some(3.25),
        };
        sample.raft = MetricsRaft {
            role: node.map(|_| "leader".to_owned()),
            term: 3,
            lag: vec![
                MetricsLag {
                    node: NodeId(2),
                    entries: 4,
                },
                MetricsLag {
                    node: NodeId(3),
                    entries: 1,
                },
            ],
        };
        sample.jobs = MetricsJobs {
            running: 1,
            waiting: 1,
        };
        sample.ingest = MetricsIngest {
            batches_per_second: 0.75,
            facts_per_second: 30.5,
        };
        sample.sse.subscribers = 2;
        sample.nodes = vec![
            MetricsNode {
                node: NodeId(1001),
                buffer_batches: 3,
                drops: Some(0),
            },
            MetricsNode {
                node: NodeId(1002),
                buffer_batches: 2,
                drops: None,
            },
        ];
        sample.dns = Some(dns_part());
        sample.dhcp = Some(MetricsDhcp {
            leases_per_second: 1.5,
            ack_p99_ms: Some(3.5),
            naks_per_second: 0.25,
            declines_per_second: 0.25,
            active_leases: 300,
            abandoned_leases: 2,
            scopes: 6,
            fullest: vec![MetricsDhcpPool {
                scope: "192.0.2.0/24".to_owned(),
                utilization: 0.625,
            }],
            ddns: MetricsDhcpDdns {
                written: 1.25,
                ..MetricsDhcpDdns::default()
            },
        });
        sample.host = Some(MetricsHost {
            cpu_percent: Some(12.5),
            memory_total: Some(8_000_000_000),
            memory_available: Some(5_000_000_000),
            disk_total: Some(120 * 1_073_741_824),
            disk_available: Some(67_108_864_000),
        });
        sample
    }

    fn dns_part() -> MetricsDns {
        MetricsDns {
            queries_per_second: 750.0,
            transports: MetricsDnsTransports {
                udp: 700.0,
                tcp: 20.0,
                dot: 20.0,
                doh: 10.0,
            },
            p50_ms: Some(0.25),
            p99_ms: Some(20.0),
            rcodes: MetricsDnsRcodes {
                noerror: 600.0,
                nxdomain: 100.0,
                servfail: 30.0,
                refused: 20.0,
                other: 0.0,
            },
            cache: MetricsDnsCache {
                hit_ratio: Some(0.75),
                hits_per_second: 300.0,
                misses_per_second: 100.0,
                stale_per_second: 0.5,
                entries: 8_500,
            },
            upstreams: MetricsDnsUpstreams {
                queries_per_second: 100.0,
                p99_ms: Some(44.0),
            },
            blocked: vec![
                MetricsDnsBlocked {
                    list: "ads".to_owned(),
                    per_second: 12.5,
                },
                MetricsDnsBlocked {
                    list: "malware".to_owned(),
                    per_second: 0.5,
                },
            ],
            connections: Some(MetricsDnsConnections { dot: 6, doh: 3 }),
            log_dropped_per_second: 0.0,
            recursion: Some(MetricsDnsRecursion {
                subqueries_per_second: 40.0,
                validation: MetricsDnsValidation {
                    secure: 30.0,
                    insecure: 5.0,
                    bogus: 1.0,
                    indeterminate: 0.5,
                },
            }),
        }
    }

    fn tier(
        step_ms: u32,
        start: Timestamp,
        open: bool,
        buckets: &[(f64, f64, f64, u32, u16)],
    ) -> MetricsTier {
        let value = |v: f64, covered: u32| (covered > 0).then_some(v);
        // A history's tiers name their ring; a `closed` (nothing open) does not.
        let ring = HISTORY_TIERS
            .iter()
            .chain(&RATIO_HISTORY_TIERS)
            .find(|spec| spec.step_ms == step_ms)
            .filter(|_| open)
            .map(|spec| u16::try_from(spec.buckets).expect("a ring size"));
        MetricsTier {
            step_ms,
            start,
            open,
            ring,
            lowest: buckets.iter().map(|b| value(b.0, b.3)).collect(),
            highest: buckets.iter().map(|b| value(b.1, b.3)).collect(),
            mean: buckets.iter().map(|b| value(b.2, b.3)).collect(),
            covered_ms: buckets.iter().map(|b| b.3).collect(),
            controllers: buckets.iter().map(|b| b.4).collect(),
        }
    }

    /// The history of the golden example, at `T0 + 2.4 s`: controller 1 since long, controller
    /// 2 restarted at `T0 − 1.6 s` (so the buckets before cover one controller), controller 3
    /// of the previous release; the queries with a gap, the cache hit ratio in 5-second
    /// buckets, the disk.
    fn golden_history() -> MetricsHistory {
        MetricsHistory {
            at: time(T0 + 2, 400),
            controllers: vec![
                MetricsHistoryController {
                    node: Some(NodeId(1)),
                    started: Some(time(T0 - 7 * 3_600, 0)),
                    unsupported: false,
                },
                MetricsHistoryController {
                    node: Some(NodeId(2)),
                    started: Some(time(T0 - 2, 400)),
                    unsupported: false,
                },
                MetricsHistoryController {
                    node: Some(NodeId(3)),
                    started: None,
                    unsupported: true,
                },
            ],
            figures: vec![
                MetricsFigureHistory {
                    figure: MetricsFigure::DnsQueries,
                    merge: MetricsFigure::DnsQueries.merge(),
                    tiers: vec![
                        tier(
                            1_000,
                            time(T0 + 2, 0),
                            true,
                            &[
                                (700.0, 700.0, 700.0, 1_000, 1),
                                (0.0, 0.0, 0.0, 0, 0),
                                (1_234.56, 1_480.04, 1_351.2, 1_000, 2),
                                (9_876.5, 9_876.5, 9_876.5, 1_000, 2),
                                (752.31, 760.0, 756.0, 1_000, 2),
                                (750.0, 750.0, 750.0, 400, 2),
                            ],
                        ),
                        tier(
                            10_000,
                            time(T0, 0),
                            true,
                            &[
                                (688.0, 712.25, 700.125, 10_000, 1),
                                (690.5, 9_876.5, 2_655.137, 2_400, 2),
                            ],
                        ),
                        tier(
                            3_600_000,
                            time(T0, 0),
                            true,
                            &[
                                (210.0, 9_812.0, 742.6666, 3_600_000, 1),
                                (690.5, 9_876.5, 2_655.137, 2_400, 2),
                            ],
                        ),
                    ],
                },
                MetricsFigureHistory {
                    figure: MetricsFigure::DnsCache,
                    merge: MetricsFigure::DnsCache.merge(),
                    tiers: vec![tier(
                        5_000,
                        time(T0, 0),
                        true,
                        &[
                            (31.0, 87.654_32, 79.123_45, 5_000, 1),
                            (74.5, 76.25, 75.0, 2_400, 2),
                        ],
                    )],
                },
                MetricsFigureHistory {
                    figure: MetricsFigure::HostDisk,
                    merge: MetricsFigure::HostDisk.merge(),
                    tiers: vec![tier(
                        1_000,
                        time(T0 + 2, 0),
                        true,
                        &[(62.412_34, 62.412_34, 62.412_34, 400, 1)],
                    )],
                },
            ],
        }
    }

    fn golden_events() -> [EventData; 2] {
        let mut history = EventData::new(Topic::Metrics, None);
        history.kind = Some(METRICS_HISTORY_KIND.to_owned());
        history.history = Some(golden_history());
        let mut snapshot = EventData::new(Topic::Metrics, None);
        snapshot.kind = Some(METRICS_SNAPSHOT_KIND.to_owned());
        snapshot.metrics = Some(MetricsSnapshot {
            nodes: vec![full_sample(Some(NodeId(1)))],
            cluster: full_sample(None),
            closed: vec![MetricsClosed {
                figure: MetricsFigure::DnsQueries,
                tiers: vec![tier(
                    1_000,
                    time(T0 + 2, 0),
                    false,
                    &[
                        (752.31, 760.0, 756.0, 1_000, 2),
                        (750.0, 750.0, 750.0, 1_000, 2),
                    ],
                )],
            }],
        });
        [history, snapshot]
    }

    #[test]
    fn the_golden_stream_is_what_the_server_writes() {
        let written: String = golden_events()
            .iter()
            .map(|event| serde_json::to_string(event).expect("json") + "\n")
            .collect();
        let golden = GOLDEN_STREAM.replace('\r', "");
        assert_eq!(
            written, golden,
            "regenerate docs/api/examples/metrics-stream.jsonl:\n{written}"
        );
        // Each line reads back into the types and writes the same bytes again.
        for line in golden.lines() {
            let event: EventData = serde_json::from_str(line).expect("an event");
            assert_eq!(serde_json::to_string(&event).expect("json"), line);
            if let Some(history) = &event.history {
                for figure in &history.figures {
                    assert!(figure.tiers.iter().all(MetricsTier::is_consistent));
                }
            }
        }
    }

    #[test]
    fn the_golden_history_shows_the_wire_rules() {
        let json = serde_json::to_value(&golden_events()[0]).expect("json");
        assert_eq!(json["kind"], "metrics.history");
        assert!(json.get("revision").is_none(), "never replayed");
        let history = &json["history"];
        assert_eq!(history["controllers"][2]["unsupported"], true);
        assert!(history["controllers"][0].get("unsupported").is_none());
        let queries = &history["figures"][0];
        assert_eq!(queries["figure"], "dns-queries");
        assert_eq!(queries["merge"], "sum");
        let seconds = &queries["tiers"][0];
        assert_eq!(seconds["step_ms"], 1_000);
        assert_eq!(seconds["open"], true);
        assert_eq!(seconds["ring"], 71);
        // Four significant digits, whole numbers without a fraction, null for no data.
        assert_eq!(
            seconds["lowest"],
            serde_json::json!([700, null, 1235, 9877, 752.3, 750])
        );
        assert_eq!(
            seconds["covered_ms"],
            serde_json::json!([1000, 0, 1000, 1000, 1000, 400])
        );
        assert_eq!(
            seconds["controllers"],
            serde_json::json!([1, 0, 2, 2, 2, 2])
        );
        assert_eq!(history["figures"][1]["merge"], "ratio");
        assert_eq!(history["figures"][1]["tiers"][0]["step_ms"], 5_000);
        assert_eq!(history["figures"][1]["tiers"][0]["highest"][0], 87.65);
        assert_eq!(history["figures"][2]["merge"], "least_available");
        let closed = &serde_json::to_value(&golden_events()[1]).expect("json")["metrics"]["closed"];
        assert!(
            closed[0]["tiers"][0].get("open").is_none(),
            "nothing open in closed"
        );
        assert!(
            closed[0]["tiers"][0].get("ring").is_none(),
            "the ring is the history's"
        );
    }

    #[test]
    fn a_snapshot_without_closed_buckets_and_an_event_without_history_keep_their_old_shape() {
        let at = time(T0, 0);
        let snapshot = MetricsSnapshot {
            nodes: Vec::new(),
            cluster: MetricsSample::empty(None, at),
            closed: Vec::new(),
        };
        let json = serde_json::to_value(&snapshot).expect("json");
        assert!(json.get("closed").is_none());
        // A snapshot of the previous release reads as one with nothing closed.
        let old: MetricsSnapshot = serde_json::from_value(serde_json::json!({
            "nodes": [],
            "cluster": serde_json::to_value(MetricsSample::empty(None, at)).expect("sample"),
        }))
        .expect("an old snapshot");
        assert_eq!(old.closed, Vec::<MetricsClosed>::new());
        let data = EventData::new(Topic::Metrics, None);
        assert!(
            serde_json::to_value(&data)
                .expect("json")
                .get("history")
                .is_none()
        );
    }

    #[test]
    fn every_figure_reads_the_number_its_tile_shows() {
        let golden: BTreeMap<String, Option<f64>> =
            serde_json::from_str(GOLDEN_FIGURES).expect("figures");
        let snapshot = golden_events()[1].metrics.clone().expect("snapshot");
        assert_eq!(golden.len(), MetricsFigure::ALL.len());
        for figure in MetricsFigure::ALL {
            let expected = golden.get(figure.as_str()).copied().flatten();
            let value = figure.value(&snapshot.cluster);
            match (value, expected) {
                (Some(value), Some(expected)) => {
                    assert!(
                        (value - expected).abs() < 1e-9,
                        "{figure}: {value} != {expected}"
                    );
                }
                (value, expected) => assert_eq!(value, expected, "{figure}"),
            }
        }
        // A sample without the roles has only the controller's figures; the quantile needs
        // traffic and the ratios a lookup.
        let bare = MetricsSample::empty(None, time(T0, 0));
        let present: Vec<_> = MetricsFigure::ALL
            .into_iter()
            .filter(|figure| figure.value(&bare).is_some())
            .collect();
        assert_eq!(
            present,
            [
                MetricsFigure::Requests,
                MetricsFigure::Store,
                MetricsFigure::Raft,
                MetricsFigure::Jobs,
                MetricsFigure::Ingest,
                MetricsFigure::Sse,
                MetricsFigure::Nodes,
            ]
        );
        let mut idle = full_sample(None);
        if let Some(dns) = &mut idle.dns {
            dns.cache.hits_per_second = 0.0;
            dns.cache.misses_per_second = 0.0;
        }
        assert_eq!(MetricsFigure::DnsCache.reading(&idle), None);
        // A ratio's reading keeps its counts; the host's memory and disk their share available.
        let full = full_sample(None);
        let cache = MetricsFigure::DnsCache.reading(&full).expect("reading");
        assert_eq!((cache.sum, cache.second), (300.0, 400.0));
        let disk = MetricsFigure::HostDisk.reading(&full).expect("reading");
        assert!((disk.second - 67_108_864_000.0 / 128_849_018_880.0).abs() < 1e-12);
        let requests = MetricsFigure::Requests.reading(&full).expect("reading");
        assert_eq!(
            (requests.value, requests.sum, requests.second),
            (2.5, 2.5, 0.0)
        );
    }

    #[test]
    fn the_figures_are_the_tiles_in_order() {
        for (index, figure) in MetricsFigure::ALL.into_iter().enumerate() {
            assert_eq!(figure.index(), index);
            assert_eq!(
                serde_json::to_value(figure).expect("json"),
                serde_json::Value::String(figure.as_str().to_owned())
            );
            assert_eq!(figure.to_string(), figure.as_str());
        }
        let merges = |merge| {
            MetricsFigure::ALL
                .into_iter()
                .filter(|figure| figure.merge() == merge)
                .count()
        };
        assert_eq!(merges(MetricsMerge::Ratio), 2);
        assert_eq!(merges(MetricsMerge::LeastAvailable), 2);
        assert_eq!(merges(MetricsMerge::Highest), 6);
        assert_eq!(merges(MetricsMerge::Sum), 15);
    }

    /// The memory budget of section 2 of the plan (OPS-21): 32 bytes a bucket, 279 buckets a
    /// figure, about 214 KiB a controller with 25 figures.
    #[test]
    fn the_tiers_hold_two_days_within_the_budget() {
        assert_eq!(std::mem::size_of::<MetricsBucket>(), BUCKET_BYTES);
        let buckets = |tiers: &[TierSpec]| tiers.iter().map(|tier| tier.buckets).sum::<usize>();
        assert_eq!(buckets(&HISTORY_TIERS), 279);
        assert_eq!(
            buckets(&HISTORY_TIERS) * BUCKET_BYTES,
            8_928,
            "8.7 KiB a figure"
        );
        assert_eq!(buckets(&RATIO_HISTORY_TIERS), 223);
        let controller: usize = MetricsFigure::ALL
            .into_iter()
            .map(|figure| buckets(figure.tiers()) * BUCKET_BYTES)
            .sum();
        assert_eq!(controller, 219_616, "214 KiB a controller");
        // A ring of r buckets of step s reaches back (r − 1) × s at least.
        let reach = |tier: TierSpec| {
            u64::from(tier.step_ms) * (u64::try_from(tier.buckets).expect("a ring size") - 1)
        };
        for tiers in [&HISTORY_TIERS, &RATIO_HISTORY_TIERS] {
            // Each step a whole multiple of the one before; each ring reaches past the next
            // coarser step, so a coarser tier takes over before the finer one ends.
            for pair in tiers.windows(2) {
                assert_eq!(pair[1].step_ms % pair[0].step_ms, 0);
                assert!(reach(pair[0]) > u64::from(pair[1].step_ms));
            }
            // The coarsest ring alone reaches the whole two days: its newest buckets overlap
            // the finer tiers.
            assert!(reach(tiers[4]) >= HISTORY_REACH_MS);
        }
        // The ages at which the next coarser tier takes over: 60 s, 9 min, 50 min, 5 h.
        let hand_over: Vec<u64> = HISTORY_TIERS
            .windows(2)
            .map(|pair| reach(pair[0]) - u64::from(pair[1].step_ms))
            .collect();
        assert_eq!(hand_over, [60_000, 540_000, 3_000_000, 18_000_000]);
    }

    /// A whole history of 25 figures and three controllers, every ring full, on the event
    /// stream (M84's size, under 300 KB) and between controllers (under the caller's 1 MiB).
    #[test]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        reason = "made-up figures"
    )]
    fn a_full_history_fits_its_frames() {
        let at = time(T0, 0);
        let value = |i: usize| 1_000.0 * (1.0 + (i as f64 * 0.37).sin()) + 0.123;
        let figures: Vec<MetricsFigureHistory> = MetricsFigure::ALL
            .into_iter()
            .map(|figure| MetricsFigureHistory {
                figure,
                merge: figure.merge(),
                tiers: figure
                    .tiers()
                    .iter()
                    .map(|spec| {
                        let buckets: Vec<_> = (0..spec.buckets)
                            .map(|i| (value(i) * 0.9, value(i) * 1.1, value(i), spec.step_ms, 3))
                            .collect();
                        tier(spec.step_ms, at, true, &buckets)
                    })
                    .collect(),
            })
            .collect();
        let mut data = EventData::new(Topic::Metrics, None);
        data.kind = Some(METRICS_HISTORY_KIND.to_owned());
        data.history = Some(MetricsHistory {
            at,
            controllers: (1..=3)
                .map(|node| MetricsHistoryController {
                    node: Some(NodeId(node)),
                    started: Some(at),
                    unsupported: false,
                })
                .collect(),
            figures,
        });
        let json = serde_json::to_vec(&data).expect("json");
        assert!(
            json.len() < 300_000,
            "the history frame is {} bytes",
            json.len()
        );

        let own = ControllerTiers {
            started: at,
            figures: MetricsFigure::ALL
                .into_iter()
                .map(|figure| ControllerFigure {
                    figure,
                    tiers: figure
                        .tiers()
                        .iter()
                        .map(|spec| ControllerTier {
                            step_ms: spec.step_ms,
                            start: at,
                            open: true,
                            buckets: (0..spec.buckets)
                                .map(|i| {
                                    let step = f64::from(spec.step_ms);
                                    let (low, mean, high, second) = match figure.merge() {
                                        MetricsMerge::Ratio => (61.23, 0.7712, 93.45, step),
                                        MetricsMerge::LeastAvailable => (
                                            value(i) * 0.9,
                                            value(i),
                                            value(i) * 1.1,
                                            0.371_234_567 * step,
                                        ),
                                        _ => (value(i) * 0.9, value(i), value(i) * 1.1, 0.0),
                                    };
                                    MetricsBucket {
                                        lowest: low as f32,
                                        highest: high as f32,
                                        sum: mean * step,
                                        second,
                                        covered_ms: spec.step_ms,
                                    }
                                })
                                .collect(),
                        })
                        .collect(),
                })
                .collect(),
        };
        let cbor = tenko_core::codec::to_cbor(&own).expect("cbor");
        assert!(
            cbor.len() < 300_000,
            "a controller's tiers are {} bytes",
            cbor.len()
        );
        let back = ControllerTiers::decode(CONTROLLER_TIERS_ENCODING, &cbor).expect("decode");
        assert_eq!(back, own);
        eprintln!(
            "the history frame: {} bytes; a controller's tiers: {} bytes",
            json.len(),
            cbor.len()
        );
    }

    #[test]
    fn values_carry_four_significant_digits() {
        for (value, rounded) in [
            (9_876.5, 9_877.0),
            (0.012_345_6, 0.012_35),
            (752.31, 752.3),
            (1_000.0, 1_000.0),
            (99_995.0, 100_000.0),
            (123_456_789.0, 123_500_000.0),
            (1.234_56e-7, 1.235e-7),
            (-42.424_2, -42.42),
            (0.0, 0.0),
        ] {
            assert_eq!(round_significant(value), rounded, "{value}");
        }
        assert!(round_significant(f64::NAN).is_nan());
        assert_eq!(round_significant(f64::INFINITY), f64::INFINITY);
        let tier = tier(
            1_000,
            time(T0, 0),
            false,
            &[(0.1, 2.0 / 3.0, 1e21, 1_000, 1)],
        );
        let json = serde_json::to_string(&tier).expect("json");
        assert!(json.contains(r#""lowest":[0.1]"#), "{json}");
        assert!(json.contains(r#""highest":[0.6667]"#), "{json}");
        assert!(json.contains(r#""mean":[1e+21]"#), "{json}");
    }

    fn one_figure(tier: ControllerTier) -> ControllerTiers {
        ControllerTiers {
            started: time(T0, 0),
            figures: vec![ControllerFigure {
                figure: MetricsFigure::DnsQueries,
                tiers: vec![tier],
            }],
        }
    }

    fn sound_tier() -> ControllerTier {
        ControllerTier {
            step_ms: 10_000,
            start: time(T0 + 10, 0),
            open: false,
            buckets: vec![
                MetricsBucket::EMPTY,
                MetricsBucket {
                    lowest: 1.0,
                    highest: 2.0,
                    sum: 15_000.0,
                    second: 0.0,
                    covered_ms: 10_000,
                },
            ],
        }
    }

    #[test]
    fn a_bucket_is_sound_only_as_the_fold_makes_it() {
        let bucket = sound_tier().buckets[1];
        assert_eq!(bucket.mean(MetricsMerge::Sum), Some(1.5));
        assert_eq!(MetricsBucket::EMPTY.mean(MetricsMerge::Sum), None);
        let ratio = MetricsBucket {
            second: 20_000.0,
            ..bucket
        };
        assert_eq!(ratio.mean(MetricsMerge::Ratio), Some(75.0));
        assert!(ratio.is_sound(MetricsMerge::Ratio));
        // A ratio's part above its whole, a share above 100 %, a negative share available.
        assert!(
            !MetricsBucket {
                sum: 30_000.0,
                ..ratio
            }
            .is_sound(MetricsMerge::Ratio)
        );
        assert!(
            !MetricsBucket {
                highest: 101.0,
                ..ratio
            }
            .is_sound(MetricsMerge::Ratio)
        );
        let disk = MetricsBucket {
            second: 3_000.0,
            ..bucket
        };
        assert!(disk.is_sound(MetricsMerge::LeastAvailable));
        assert!(
            !MetricsBucket {
                second: -1.0,
                ..disk
            }
            .is_sound(MetricsMerge::LeastAvailable)
        );
        assert!(
            !MetricsBucket {
                second: 10_001.0,
                ..disk
            }
            .is_sound(MetricsMerge::LeastAvailable)
        );
        assert!(MetricsBucket::EMPTY.is_sound(MetricsMerge::Sum));
    }

    #[test]
    fn a_peers_tiers_are_checked_before_they_are_combined() {
        assert_eq!(one_figure(sound_tier()).check(), Ok(()));
        let bucket = sound_tier().buckets[1];
        let refused = |tiers: ControllerTiers| tiers.check().expect_err("refused");
        // A step that is not the figure's, or a tier twice.
        assert!(
            refused(one_figure(ControllerTier {
                step_ms: 5_000,
                ..sound_tier()
            }))
            .contains("unknown")
        );
        let mut twice = one_figure(sound_tier());
        twice.figures[0].tiers.push(sound_tier());
        assert!(refused(twice).contains("out of order"));
        // More buckets than the ring, a start off the step, a bucket longer than its step, a
        // value that is not a number.
        assert!(
            refused(one_figure(ControllerTier {
                buckets: vec![MetricsBucket::EMPTY; 62],
                ..sound_tier()
            }))
            .contains("62 buckets")
        );
        assert!(
            refused(one_figure(ControllerTier {
                start: time(T0 + 10, 1),
                ..sound_tier()
            }))
            .contains("does not start on its step")
        );
        for poisoned in [
            MetricsBucket {
                covered_ms: 10_001,
                ..bucket
            },
            MetricsBucket {
                highest: f32::NAN,
                ..bucket
            },
            MetricsBucket {
                lowest: 3.0,
                ..bucket
            },
            MetricsBucket {
                lowest: f32::NAN,
                ..MetricsBucket::EMPTY
            },
            MetricsBucket {
                sum: f64::INFINITY,
                ..MetricsBucket::EMPTY
            },
            // An empty bucket with values, a second sum on a summed figure, a mean far beyond
            // the highest.
            MetricsBucket {
                sum: 5.0,
                ..MetricsBucket::EMPTY
            },
            MetricsBucket {
                second: 5.0,
                ..bucket
            },
            MetricsBucket {
                sum: 1e300,
                ..bucket
            },
        ] {
            let mut tier = sound_tier();
            tier.buckets[1] = poisoned;
            assert!(refused(one_figure(tier)).contains("does not hold together"));
        }
        // A figure twice, or out of order.
        let mut figures = one_figure(sound_tier());
        figures.figures.insert(
            0,
            ControllerFigure {
                figure: MetricsFigure::DhcpDdns,
                tiers: Vec::new(),
            },
        );
        assert!(refused(figures).contains("out of order"));

        // The encoding and the bytes.
        let cbor = tenko_core::codec::to_cbor(&one_figure(sound_tier())).expect("cbor");
        assert!(ControllerTiers::decode(CONTROLLER_TIERS_ENCODING, &cbor).is_ok());
        assert!(
            ControllerTiers::decode("json/1", &cbor)
                .expect_err("unknown")
                .contains("unknown encoding")
        );
        assert!(
            ControllerTiers::decode(CONTROLLER_TIERS_ENCODING, &[0xff, 0x00])
                .expect_err("garbage")
                .contains("do not decode")
        );
        // A bucket is an array of five numbers in CBOR, not a map.
        let encoded = tenko_core::codec::to_cbor(&bucket).expect("cbor");
        assert_eq!(encoded[0], 0x85, "an array of five");
        assert_eq!(
            tenko_core::codec::from_cbor::<MetricsBucket>(&encoded).expect("back"),
            bucket
        );
    }

    /// A newer peer's figure and step that this build does not know are skipped, not refused,
    /// so a rolling update keeps the peer in the combination.
    #[test]
    fn a_newer_peers_unknown_figures_and_steps_are_skipped() {
        #[derive(Serialize)]
        struct NewerFigure {
            figure: &'static str,
            tiers: Vec<ControllerTier>,
        }
        #[derive(Serialize)]
        struct NewerTiers {
            started: Timestamp,
            figures: Vec<NewerFigure>,
        }
        let newer = NewerTiers {
            started: time(T0, 0),
            figures: vec![
                NewerFigure {
                    figure: "dns-queries",
                    tiers: vec![
                        sound_tier(),
                        ControllerTier {
                            step_ms: 21_600_000,
                            start: time(T0 - 3 * 3_600, 0),
                            ..sound_tier()
                        },
                    ],
                },
                NewerFigure {
                    figure: "dns-something-new",
                    tiers: vec![sound_tier()],
                },
            ],
        };
        let cbor = tenko_core::codec::to_cbor(&newer).expect("cbor");
        assert_eq!(
            ControllerTiers::decode(CONTROLLER_TIERS_ENCODING, &cbor).expect("lenient"),
            one_figure(sound_tier())
        );
    }
}
