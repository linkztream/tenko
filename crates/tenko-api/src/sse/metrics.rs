//! The `metrics` topic of the event stream (OPS-20, plan section 2.7): one metrics
//! snapshot per second, per node and cluster-wide, while at least one subscriber asked for
//! the topic. The snapshots come from the metrics collector, not from the store journal,
//! so they have no revision and are never replayed; a reconnecting client simply receives
//! the next one.
//!
//! The observability package (WP3.5) fills this module: the snapshot type, the publisher
//! the collector calls, and the hub hook that sends a snapshot only to subscribers of
//! [`Topic::Metrics`](crate::dto::events::Topic::Metrics). Until then the topic exists and
//! carries nothing.
