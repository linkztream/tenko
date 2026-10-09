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

mod hub;

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
    namespaces: HashMap<String, Topic>,
}

impl EventRoutes {
    /// No routes at all.
    pub fn empty() -> Self {
        Self {
            tables: HashMap::new(),
            namespaces: HashMap::new(),
        }
    }

    /// Routes one table. `kind` makes each changed key (a 16-byte id) an object reference.
    pub fn table(&mut self, table: TableName, topic: Topic, kind: Option<ObjectKind>) -> &mut Self {
        self.tables.insert(table, Route { topic, kind });
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
            .namespace("connect", Topic::Connectors)
            .namespace("auth", Topic::Admin)
            .namespace("users", Topic::Admin);
        routes
    }
}

/// The authorization hook of the event stream: whether a subscriber may see an event.
///
/// Called once per subscriber and event with the references the event carries; frames are
/// shared, so a filter can drop an event but not edit it. The default admits everything;
/// RBAC scopes (Slice 3) install a real filter with [`EventHub::set_filter`].
pub trait EventFilter: Send + Sync + 'static {
    /// Whether `principal` may receive an event of `topic` about `objects`.
    fn admit(&self, principal: &Principal, topic: Topic, objects: &[ObjectRef]) -> bool;
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
        assert_eq!(route("ipam.prefix_cidrs"), None, "secondary index");
        assert_eq!(route("jobs.transitions"), None);
        assert_eq!(route("vault.secrets"), None);
        assert_eq!(route("sys.audit"), None, "handled by the hub");
    }
}
