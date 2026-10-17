//! Response rate limiting and per-client limits (DNS-17, TGL-11).
//!
//! WP5.2 implements RRL with BIND's semantics (responses per second per client prefix and
//! response kind, slip 2) and the per-client query limit; [`Unlimited`] admits everything.

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

    /// What to do with a response of `kind` for names under `zone` (lowercase wire form)
    /// to `client`. Counts lock-free per worker and allocates nothing.
    fn admit_response(
        &self,
        client: IpAddr,
        kind: ResponseKind,
        zone: &[u8],
        now: Instant,
    ) -> RateDecision;
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
        _kind: ResponseKind,
        _zone: &[u8],
        _now: Instant,
    ) -> RateDecision {
        RateDecision::Send
    }
}
