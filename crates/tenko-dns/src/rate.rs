//! Response rate limiting and per-client limits (DNS-17, TGL-11).
//!
//! [`limiter::Limiter`] implements both with BIND's semantics:
//!
//! - **RRL**: identical responses to one client prefix (/24 and /56 by default) are
//!   counted per second: positive answers and NODATA by query name and type, NXDOMAIN and
//!   referrals by zone, errors by kind alone. Each key has a token bucket that fills at the
//!   rate (`responses_per_second`, `errors_per_second` for NXDOMAIN and errors) up to one
//!   second's worth and may fall `window` seconds into debt; a response without a token is
//!   limited, and a limited response is debited too, so a client that keeps asking above
//!   the rate is answered only by slips until it slows down for the window (BIND's
//!   behaviour). Every `slip`-th limited response (default 2) is sent as an empty truncated
//!   answer, so that a real client behind a spoofed flood retries over TCP; the others are
//!   dropped. TCP, DoT and DoH queries are not limited by RRL: their source cannot be
//!   spoofed.
//! - **Per-client limits**: queries per second per client address (an IPv6 client by its
//!   /64) with a burst; a query over the limit is dropped before the lookup.
//!
//! Exempt clients (the configured prefixes and, when set, the prefixes IPAM knows and
//! loopback) are never limited. The tables are fixed at start (a slot per key hash,
//! sharded behind short locks; a new key takes over its slot with a full bucket), so the
//! query path allocates nothing; [`Unlimited`] admits everything.

pub mod limiter;

use std::{net::IpAddr, time::Instant};

/// The kind of a response, as RRL accounts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseKind {
    /// A positive answer.
    Answer,
    /// NODATA.
    NoData,
    /// NXDOMAIN.
    NxDomain,
    /// A referral.
    Referral,
    /// An error (SERVFAIL, REFUSED, FORMERR).
    Error,
}

impl ResponseKind {
    /// The `kind` label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Answer => "answer",
            Self::NoData => "nodata",
            Self::NxDomain => "nxdomain",
            Self::Referral => "referral",
            Self::Error => "error",
        }
    }

    /// The series index of the kind in the RRL counter.
    pub fn index(self) -> u16 {
        match self {
            Self::Answer => 0,
            Self::NoData => 1,
            Self::NxDomain => 2,
            Self::Referral => 3,
            Self::Error => 4,
        }
    }
}

/// What makes two responses identical for RRL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseKey<'a> {
    /// The kind.
    pub kind: ResponseKind,
    /// The query name for answers and NODATA, the zone apex for NXDOMAIN and referrals
    /// (lowercase wire form); ignored for errors.
    pub name: &'a [u8],
    /// The query type (answers and NODATA).
    pub qtype: u16,
    /// Whether the query came over UDP (only UDP responses are limited).
    pub udp: bool,
}

/// What the limiter says about a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// Send it.
    Send,
    /// Send a truncated answer instead, so a real client retries over TCP (the slip).
    Slip,
    /// Send nothing.
    Drop,
}

/// Response rate limiting and per-client query limits.
pub trait RateLimiter: Send + Sync {
    /// Whether a query from `client` is admitted at all (the per-client limit).
    fn admit_query(&self, client: IpAddr, now: Instant) -> bool;

    /// What to do with a response to `client`. Allocates nothing.
    fn admit_response(&self, client: IpAddr, key: &ResponseKey<'_>, now: Instant) -> RateDecision;
}

/// The limiter that admits everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unlimited;

impl RateLimiter for Unlimited {
    fn admit_query(&self, _client: IpAddr, _now: Instant) -> bool {
        true
    }

    fn admit_response(
        &self,
        _client: IpAddr,
        _key: &ResponseKey<'_>,
        _now: Instant,
    ) -> RateDecision {
        RateDecision::Send
    }
}
