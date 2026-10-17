//! The one lookup path of every transport (plan section 2.2).
//!
//! A [`Resolver`] answers a parsed query into an [`AnswerBuf`]: view selection, then the
//! authoritative lookup, then the policy zones, then the forwarder and cache, in that
//! order, with EDNS, cookies, minimal responses and RFC 8482 decided here and not in the
//! transport. UDP workers, TCP, DoT and DoH all call the same resolver. A query that has to
//! wait for an upstream is handed back as [`Resolution::Forward`]; the transport runs the
//! [`Upstream`](crate::upstream::Upstream) exchange and writes its answer.
//!
//! WP4.1 implements the authoritative half on the [`Index`](crate::index::Index), WP4.3
//! the plain forwarder of Slice 4, WP5.1 the cache and the forwarder rules behind the same
//! trait.

use std::net::SocketAddr;

use tenko_core::dns::{ForwardRuleId, QueryTransport, ViewId};

use crate::codec::{AnswerBuf, Request};

/// What the resolver knows about a query besides its content.
#[derive(Debug, Clone, Copy)]
pub struct QueryContext<'a> {
    /// The parsed query.
    pub request: &'a Request,
    /// The client's address and port.
    pub client: SocketAddr,
    /// The local address the query arrived on (the interface test of a view).
    pub local: SocketAddr,
    /// The transport.
    pub transport: QueryTransport,
    /// The minute of the day in UTC, 0 to 1439 (the time test of a view), read once per
    /// batch by the worker.
    pub minute_of_day: u16,
}

/// What the resolver did with a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// The answer is in the buffer; the transport writes it.
    Answered {
        /// The view that matched; `None` for the implicit default view.
        view: Option<ViewId>,
    },
    /// The query goes to the upstreams of a forwarding rule (or the default forwarder);
    /// the buffer is untouched.
    Forward {
        /// The view that matched.
        view: Option<ViewId>,
        /// The rule; `None` for the default forwarder of the configuration.
        rule: Option<ForwardRuleId>,
    },
    /// No answer: dropped by the rate limiter or the policy.
    Drop,
}

/// The lookup path.
pub trait Resolver: Send + Sync {
    /// Answers `query` into `answer` (cleared by the caller). Reads memory only, takes no
    /// lock that a writer holds for long and allocates nothing (ADR 0009); an answer that
    /// does not fit the buffer is SERVFAIL.
    fn resolve(&self, query: &QueryContext<'_>, answer: &mut AnswerBuf) -> Resolution;
}
