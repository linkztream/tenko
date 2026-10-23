//! The query log (plan section 2.9, DNS-26, TGL-15): per node, off by default, written from
//! the per-shard ring buffers to a local file, never through the store.
//!
//! The query path hands each entry to a [`QueryLogSink`], which must not block: a full
//! buffer drops the entry and counts it (`tenko_dns_log_dropped_total`).
//! [`crate::querylog::FileLog`] is the sink of the role: the ring, JSON lines and dnstap,
//! rotation, retention and pseudonymisation; [`NullLog`] discards.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use tenko_core::dns::{BlockListId, QueryTransport, ViewId};

// WP10.1: how an answer was found (recursion plan section 2.11).
/// How the answer of a logged query was found: the query log's `resolution`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// A zone of the node.
    Zone,
    /// The answer cache.
    Cache,
    /// The denial cache (RFC 8198, WP10.3).
    Denial,
    /// A stale entry of the cache (RFC 8767).
    Stale,
    /// An upstream of a forwarding rule, a stub zone or the default forwarder.
    Forward,
    /// The recursive resolver.
    Recurse,
    /// A locally served zone of the recursive resolver (RFC 6761, RFC 6303).
    Local,
    /// The policy: a block list or an RPZ zone.
    Policy,
    /// Refused.
    Refused,
}

impl Resolution {
    /// The stable name (the JSON lines' `resolution`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Resolution::Zone => "zone",
            Resolution::Cache => "cache",
            Resolution::Denial => "denial",
            Resolution::Stale => "stale",
            Resolution::Forward => "forward",
            Resolution::Recurse => "recurse",
            Resolution::Local => "local",
            Resolution::Policy => "policy",
            Resolution::Refused => "refused",
        }
    }
}
// WP10.1: end.

/// One logged query. Borrowed fields are copied by the sink if it keeps them.
#[derive(Debug, Clone, Copy)]
pub struct QueryLogEntry<'a> {
    /// Microseconds since 1970 when the query arrived.
    pub at_micros: u64,
    /// The client; the sink pseudonymises it per the settings.
    pub client: IpAddr,
    /// The transport.
    pub transport: QueryTransport,
    /// The query name in lowercase wire form.
    pub qname: &'a [u8],
    /// The query type.
    pub qtype: u16,
    /// The RCODE answered.
    pub rcode: u16,
    /// The view that matched.
    pub view: Option<ViewId>,
    /// The list that blocked the query, if any.
    pub blocked: Option<BlockListId>,
    /// Answered from the cache.
    pub cached: bool,
    /// Microseconds from arrival to the answer.
    pub duration_micros: u32,
    // WP10.1: how the answer was found and what it cost.
    /// How the answer was found; `None` when the logger does not know.
    pub resolution: Option<Resolution>,
    /// Queries the recursive resolver sent to authorities for it.
    pub subqueries: u16,
    // WP10.2: the validator's state and the extended error (recursion plan section 2.11).
    /// The DNSSEC state of the answer; `None` when nothing validated it.
    pub validation: Option<tenko_core::dns::SecurityState>,
    /// The extended error code the answer carried (RFC 8914); `None` for none.
    pub ede: Option<u16>,
}

/// Where the query path hands its log entries.
pub trait QueryLogSink: Send + Sync {
    /// Takes one entry without blocking; drops it when the buffer is full.
    fn record(&self, entry: &QueryLogEntry<'_>);

    /// How many entries were dropped since the start.
    fn dropped(&self) -> u64;
}

/// The sink that discards (the query log is off).
#[derive(Debug, Clone, Copy, Default)]
pub struct NullLog;

impl QueryLogSink for NullLog {
    fn record(&self, _entry: &QueryLogEntry<'_>) {}

    fn dropped(&self) -> u64 {
        0
    }
}
