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
    /// Cluster nodes, enrolment tokens and controller members.
    Cluster,
    /// One metrics snapshot per second while a client listens (OPS-20); published by the
    /// metrics collector, not from the store journal, and never replayed.
    Metrics,
    /// The DNS module (Phase 2): zones and their records, views, forwarders, access lists,
    /// keys and block lists, and the serial, transfer and signing events of zones.
    Dns,
    // WP7.0
    /// The DHCP module (Phase 3): the configuration, and lease events for the live lease
    /// view (sampled to at most 50 a second per subscriber, with counts when sampled).
    Dhcp,
}

impl Topic {
    /// Every topic, in declaration order.
    pub const ALL: [Topic; 13] = [
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
    pub const ALL: TopicSet = TopicSet(0b1_1111_1111_1111);
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
    }
}

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
}
