//! Server-sent events (API-05) per ADR 0008 decision 4 and ADR 0011 decision 6.
//!
//! - **One hub per controller** ([`EventHub`]). A feeder task follows the store journal
//!   (`Store::watch`) and turns every `ChangeSet` into at most one event per topic. Each
//!   event is encoded once into its SSE frame (`Bytes`); fan-out to N subscribers is N
//!   reference-count increments and N socket writes.
//! - **Event ids are store revisions**, so `Last-Event-ID` (or `?from=<revision>` on the
//!   first connection, taken from a list's `revision`) resumes after a known state, on any
//!   controller and across restarts.
//! - **Replay**: a ring of the last frames serves recent ids; an id older than the ring is
//!   replayed from the store journal (`sys.journal`); an id the journal no longer holds, an
//!   id from the future or a malformed id gets a `reset` event, and so does a subscriber
//!   that falls behind the live channel. `reset` carries the revision to reload at.
//! - **Topics and authorization**: `?topics=ipam,jobs` selects topics ([`Topic`]); every
//!   frame also passes the [`EventFilter`] of the hub (all frames until RBAC scopes land).
//!   Events carry references, never bodies. `reset` and `shutdown` reach every subscriber.
//! - **One keep-alive timer** for all streams (15 s by default), **optional coalescing**
//!   (events published within a window go out as one write), and **shutdown** ends every
//!   stream with a `shutdown` event so the HTTP server can drain.
//!
//! Table to topic routing is [`EventRoutes`]: `ipam.*` primary tables to `ipam` with an
//! object reference, `ipam.alarms` and `auth.alarms` to `system`, `jobs.jobs` to `jobs`,
//! `import.imports` to `import`, `sys.audit` to `audit`, and every other `auth.*` or
//! `users.*` table to `admin` as a table-level event. Tables without a route (secondary
//! indexes, bookkeeping) produce no event.
//!
//! Slice 3 adds (plan section 2.7): `cluster.*` (members, commands, ingest cursors) to
//! `cluster`; `scan.*` (probe configuration, scopes) to `discovery`; `i18n.*`, `backup.*`
//! and the `sys.audit_export*` tables to `system`; `auth.grants` and `auth.scoped_tokens`
//! to `admin` (through the `auth` namespace). The topic `metrics` carries one snapshot per
//! second from the metrics collector, not from the journal ([`metrics`]). RBAC scopes
//! install their [`EventFilter`] with [`EventHub::set_filter`].

pub mod filter;
mod hub;
pub mod metrics;

use std::{collections::HashMap, time::Duration};

use tenko_core::{ObjectKind, ObjectRef, Principal, TableName};

pub use hub::EventHub;
pub(crate) use hub::event_stream;

pub use crate::dto::events::{EventData, ResetData, ResetReason, Topic, TopicSet};

/// Settings of the event hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseConfig {
    /// Events a subscriber may fall behind the live stream before it gets `reset`.
    pub channel_capacity: usize,
    /// Frames kept in memory for `Last-Event-ID` replay (older ids come from the journal).
    pub ring_capacity: usize,
    /// Interval of the shared keep-alive comment.
    pub keepalive: Duration,
    /// Coalescing window: events published within it go out as one write per subscriber.
    /// `None` (the default) sends every event at once; ADR 0008 suggests enabling it above
    /// about 1,000 subscribers.
    pub coalesce: Option<Duration>,
    /// Most journal change sets replayed for one reconnecting subscriber; beyond this it
    /// gets `reset`, which is cheaper than a long replay.
    pub journal_replay_limit: usize,
    /// Reconnection delay suggested to clients (`retry:` field).
    pub retry: Duration,
    /// Most object references in one event; a larger change sends `truncated: true` and no
    /// references, and the client reloads its view.
    pub max_objects_per_event: usize,
}

impl Default for SseConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 1_024,
            ring_capacity: 256,
            keepalive: Duration::from_secs(15),
            coalesce: None,
            journal_replay_limit: 10_000,
            retry: Duration::from_secs(3),
            max_objects_per_event: 500,
        }
    }
}

/// Where a store table's changes go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The topic of the event.
    pub topic: Topic,
    /// The kind of the objects, when the table is keyed by the object's 16-byte id; `None`
    /// sends a table-level event that names the table.
    pub kind: Option<ObjectKind>,
}

/// Routing of store tables to event topics.
///
/// [`EventRoutes::default`] holds the Slice 1 tables confirmed by the area packages; a
/// package adds its own with [`EventRoutes::table`] and [`EventRoutes::namespace`] through
/// `StateOptions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRoutes {
    tables: HashMap<TableName, Route>,
    /// Table-name prefixes, longest first.
    prefixes: Vec<(String, Topic)>,
    namespaces: HashMap<String, Topic>,
}

impl EventRoutes {
    /// No routes at all.
    pub fn empty() -> Self {
        Self {
            tables: HashMap::new(),
            prefixes: Vec::new(),
            namespaces: HashMap::new(),
        }
    }

    /// Routes one table. `kind` makes each changed key (a 16-byte id) an object reference.
    pub fn table(&mut self, table: TableName, topic: Topic, kind: Option<ObjectKind>) -> &mut Self {
        self.tables.insert(table, Route { topic, kind });
        self
    }

    /// Routes every otherwise unrouted table whose name starts with `prefix` (such as
    /// `sys.audit_export` for `sys.audit_export_cursors`) to a topic, as table-level events.
    /// A prefix route wins over a namespace route; the longest matching prefix wins.
    pub fn table_prefix(&mut self, prefix: &str, topic: Topic) -> &mut Self {
        self.prefixes.retain(|(known, _)| known != prefix);
        self.prefixes.push((prefix.to_owned(), topic));
        self.prefixes
            .sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        self
    }

    /// Routes every otherwise unrouted table of a namespace to a topic, as table-level
    /// events.
    pub fn namespace(&mut self, namespace: &str, topic: Topic) -> &mut Self {
        self.namespaces.insert(namespace.to_owned(), topic);
        self
    }

    /// The route of a table, if it has one. The audit table (`sys.audit`) is handled by
    /// the hub itself.
    pub fn lookup(&self, table: &TableName) -> Option<Route> {
        if let Some(route) = self.tables.get(table) {
            return Some(*route);
        }
        if let Some((_, topic)) = self
            .prefixes
            .iter()
            .find(|(prefix, _)| table.as_str().starts_with(prefix.as_str()))
        {
            return Some(Route {
                topic: *topic,
                kind: None,
            });
        }
        self.namespaces.get(table.namespace()).map(|topic| Route {
            topic: *topic,
            kind: None,
        })
    }
}

impl Default for EventRoutes {
    fn default() -> Self {
        let mut routes = Self::empty();
        for (table, kind) in [
            ("ipam.tenants", ObjectKind::Tenant),
            ("ipam.vrfs", ObjectKind::Vrf),
            ("ipam.sites", ObjectKind::Site),
            ("ipam.vlans", ObjectKind::Vlan),
            ("ipam.prefixes", ObjectKind::Prefix),
            ("ipam.ranges", ObjectKind::Range),
            ("ipam.addresses", ObjectKind::Address),
            ("ipam.hosts", ObjectKind::Host),
            ("ipam.interfaces", ObjectKind::Interface),
            ("ipam.custom_fields", ObjectKind::CustomField),
        ] {
            routes.table(TableName::from_static(table), Topic::Ipam, Some(kind));
        }
        routes
            .table(
                TableName::from_static("ipam.alarms"),
                Topic::System,
                Some(ObjectKind::Prefix),
            )
            .table(TableName::from_static("auth.alarms"), Topic::System, None)
            .table(
                TableName::from_static("jobs.jobs"),
                Topic::Jobs,
                Some(ObjectKind::Job),
            )
            .table(
                TableName::from_static("import.imports"),
                Topic::Import,
                Some(ObjectKind::Import),
            )
            .table(
                TableName::from_static("connect.instances"),
                Topic::Connectors,
                Some(ObjectKind::Connector),
            )
            .table(
                TableName::from_static("connect.runs"),
                Topic::Connectors,
                Some(ObjectKind::Connector),
            )
            .namespace("connect", Topic::Connectors)
            .table(
                TableName::from_static("ipam.proposals"),
                Topic::Ipam,
                Some(ObjectKind::Proposal),
            )
            .table(
                TableName::from_static("ipam.adoption"),
                Topic::Ipam,
                Some(ObjectKind::Prefix),
            )
            .table(
                TableName::from_static("ipam.obs.facts"),
                Topic::Discovery,
                None,
            )
            .table(
                TableName::from_static("ipam.obs.last_seen"),
                Topic::Discovery,
                None,
            )
            .table(
                TableName::from_static("vault.operator_meta"),
                Topic::Secrets,
                Some(ObjectKind::Secret),
            )
            .table(
                TableName::from_static("vault.reveals"),
                Topic::Secrets,
                Some(ObjectKind::Secret),
            )
            .table(
                TableName::from_static("vault.host_bindings"),
                Topic::Secrets,
                None,
            )
            .table(
                TableName::from_static("dns.zones"),
                Topic::Dns,
                Some(ObjectKind::Zone),
            )
            .namespace("dns", Topic::Dns)
            .namespace("cluster", Topic::Cluster)
            .namespace("scan", Topic::Discovery)
            .table_prefix("vault.kek", Topic::System)
            .table(TableName::from_static("vault.alarms"), Topic::System, None)
            .namespace("i18n", Topic::System)
            .namespace("backup", Topic::System)
            .table_prefix("sys.audit_export", Topic::System)
            .namespace("auth", Topic::Admin)
            .namespace("users", Topic::Admin);
        routes
    }
}

/// The authorization hook of the event stream: what a subscriber may see of an event.
///
/// Called once per subscriber and event with the references the event carries. Frames are
/// shared, so a filter answers with an [`Admission`]: the whole event, nothing, or only some
/// of its references, in which case the hub re-encodes the event for that subscriber. The
/// default admits everything; RBAC scopes (Slice 3) install a real filter with
/// [`EventHub::set_filter`].
pub trait EventFilter: Send + Sync + 'static {
    /// Whether `principal` may receive an event of `topic` about `objects`.
    fn admit(&self, principal: &Principal, topic: Topic, objects: &[ObjectRef]) -> bool;

    /// What of an event `principal` may see; by default all of it when [`EventFilter::admit`]
    /// says so, else nothing. A scoped filter narrows the references instead.
    fn select(&self, principal: &Principal, topic: Topic, objects: &[ObjectRef]) -> Admission {
        if self.admit(principal, topic, objects) {
            Admission::All
        } else {
            Admission::None
        }
    }
}

/// What a subscriber may see of one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The whole event.
    All,
    /// Nothing: the event is not sent to this subscriber.
    None,
    /// Only these of the event's object references (a subset of `objects` and `deleted`);
    /// the hub re-encodes the event without the others for this subscriber and sends nothing
    /// when none is left.
    Only(Vec<ObjectRef>),
}

/// The filter that admits every event.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdmitAll;

impl EventFilter for AdmitAll {
    fn admit(&self, _principal: &Principal, _topic: Topic, _objects: &[ObjectRef]) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_routes_follow_the_slice_1_rules() {
        let routes = EventRoutes::default();
        let route = |name: &'static str| routes.lookup(&TableName::from_static(name));
        assert_eq!(
            route("ipam.prefixes"),
            Some(Route {
                topic: Topic::Ipam,
                kind: Some(ObjectKind::Prefix)
            })
        );
        assert_eq!(route("ipam.alarms").map(|r| r.topic), Some(Topic::System));
        assert_eq!(
            route("auth.alarms"),
            Some(Route {
                topic: Topic::System,
                kind: None
            })
        );
        assert_eq!(
            route("auth.sessions"),
            Some(Route {
                topic: Topic::Admin,
                kind: None
            })
        );
        assert_eq!(
            route("jobs.jobs").and_then(|r| r.kind),
            Some(ObjectKind::Job)
        );
        assert_eq!(
            route("connect.runs"),
            Some(Route {
                topic: Topic::Connectors,
                kind: Some(ObjectKind::Connector)
            }),
            "a run names its instance"
        );
        assert_eq!(route("ipam.prefix_cidrs"), None, "secondary index");
        assert_eq!(route("jobs.transitions"), None);
        assert_eq!(route("vault.secrets"), None);
        assert_eq!(route("sys.audit"), None, "handled by the hub");
    }

    #[test]
    fn slice_3_namespaces_route_to_their_topics() {
        let routes = EventRoutes::default();
        let topic = |name: &'static str| {
            routes
                .lookup(&TableName::from_static(name))
                .map(|route| route.topic)
        };
        assert_eq!(topic("cluster.members"), Some(Topic::Cluster));
        assert_eq!(topic("cluster.node_commands"), Some(Topic::Cluster));
        assert_eq!(topic("scan.probe_config"), Some(Topic::Discovery));
        assert_eq!(topic("scan.scopes"), Some(Topic::Discovery));
        assert_eq!(topic("i18n.packs"), Some(Topic::System));
        assert_eq!(topic("backup.settings"), Some(Topic::System));
        assert_eq!(topic("sys.audit_export_cursors"), Some(Topic::System));
        assert_eq!(topic("sys.audit_export_sinks"), Some(Topic::System));
        assert_eq!(topic("auth.grants"), Some(Topic::Admin));
        assert_eq!(topic("auth.scoped_tokens"), Some(Topic::Admin));
        assert_eq!(topic("sys.journal"), None);
        assert_eq!(
            topic("sys.audit"),
            None,
            "the audit table is not an export table"
        );
        let mut custom = EventRoutes::empty();
        custom
            .table_prefix("sys.a", Topic::Jobs)
            .table_prefix("sys.audit_export", Topic::System);
        assert_eq!(
            custom
                .lookup(&TableName::from_static("sys.audit_export_cursors"))
                .map(|route| route.topic),
            Some(Topic::System),
            "the longest prefix wins"
        );
    }
}
