//! The query log (plan section 2.9, DNS-26, TGL-15): per node, off by default, written from
//! the per-shard ring buffers to a local file, never through the store.
//!
//! The query path hands each entry to a [`QueryLogSink`], which must not block: a full
//! buffer drops the entry and counts it (`tenko_dns_log_dropped_total`).
//! [`crate::querylog::FileLog`] is the sink of the role: the ring, JSON lines and dnstap,
//! rotation, retention and pseudonymisation; [`NullLog`] discards.

use std::net::IpAddr;

use tenko_core::dns::{BlockListId, QueryTransport, ViewId};

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
