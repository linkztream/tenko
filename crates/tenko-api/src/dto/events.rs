//! Server-sent events (API-05): topics and the JSON carried in each event's `data` field.
//!
//! Events carry references, not bodies: the UI refetches what it shows, so no event leaks a
//! field the principal may not read. The SSE `event` field is the topic name for data
//! events, and `reset` or `shutdown` for the two control events that every subscriber
//! receives whatever its topic filter.

use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use tenko_core::{AuditSeq, InvalidValue, ObjectRef, Revision};
use utoipa::ToSchema;

/// An event topic. `GET /events?topics=ipam,jobs` subscribes to a subset; no `topics`
/// parameter subscribes to all of them.
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
}

impl Topic {
    /// Every topic, in declaration order.
    pub const ALL: [Topic; 9] = [
        Topic::Ipam,
        Topic::Jobs,
        Topic::Audit,
        Topic::Import,
        Topic::System,
        Topic::Admin,
        Topic::Connectors,
        Topic::Discovery,
        Topic::Secrets,
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
    pub const ALL: TopicSet = TopicSet(0b1_1111_1111);
    /// No topic.
    pub const EMPTY: TopicSet = TopicSet(0);

    /// Parses a comma-separated list such as `ipam,jobs`; blanks around names are ignored
    /// and an empty list means every topic.
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
            TopicSet::ALL
        } else {
            set
        })
    }

    /// Adds a topic.
    pub fn insert(&mut self, topic: Topic) {
        self.0 |= topic.bit();
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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
        }
    }

    /// Whether the event carries nothing beyond its topic.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
            && self.deleted.is_empty()
            && self.audit.is_empty()
            && self.tables.is_empty()
            && self.kind.is_none()
    }
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
        assert!("dns".parse::<Topic>().is_err());
    }

    #[test]
    fn topic_sets() {
        assert_eq!(TopicSet::parse("").expect("empty"), TopicSet::ALL);
        let set = TopicSet::parse(" ipam , jobs,").expect("set");
        assert!(set.contains(Topic::Ipam) && set.contains(Topic::Jobs));
        assert!(!set.contains(Topic::Audit));
        assert_eq!(set.topics().count(), 2);
        assert_eq!(TopicSet::ALL.topics().count(), Topic::ALL.len());
        assert!(TopicSet::parse("ipam,dns").is_err());
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
