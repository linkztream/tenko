//! The recursive resolver's contracts (recursion plan section 3.3, ADR 0021, WP10.0).
//!
//! The resolver is Tenko's own iterative engine on the forwarder's task pool (WP10.1,
//! `tenko_dns::recurse`), validating with Tenko's own validator (WP10.2), with QNAME
//! minimisation, the denial cache and the failure cache (WP10.3). This module holds what
//! those packages share, with in-memory references that are simple and correct and serve
//! as the test oracles, so that the engine is tested without sockets:
//!
//! | Module | Contract | Reference |
//! |---|---|---|
//! | [`authority`] | [`Authority`]: one exchange with one authority server | [`MemAuthority`], scripted from zone data |
//! | [`infra`] | [`InfraCache`]: zone cuts, name servers, server capabilities, lameness, cookies, DS states and key sets | [`MemInfra`] |
//! | [`validator`] | [`Validator`]: an answer and its chain context in, a state and an extended error out | [`Unvalidating`] |
//! | [`anchors`] | [`TrustAnchors`] (the rows through the catalog), [`AnchorResolver`] (for the leader service) | [`MemAnchors`] |
//! | [`denial`] | [`DenialCache`]: RFC 8198 and RFC 8020 on the worker | [`NoDenial`] |
//! | [`failure`] | [`FailureCache`]: RFC 9520 | [`MemFailures`] |
//! | [`shipped`] | the root trust anchors of RFC 7958 and the root hints, embedded | |
//!
//! The answer cache's key and entry (`crate::cache`: one entry per view, name, type and
//! class with its [`tenko_core::dns::SecurityState`], rendered per client) and the route
//! of a `recurse` rule (`crate::forward`) are the other half of the contract.

pub mod anchors;
pub mod authority;
pub mod denial;
pub mod failure;
pub mod infra;
pub mod shipped;
pub mod validator;

use std::time::Duration;

pub use anchors::{AnchorError, AnchorResolver, DnskeySet, MemAnchors, TrustAnchors};
pub use authority::{
    Asked, Authority, AuthorityError, AuthorityQuery, AuthorityTransport, Exchange, MemAuthority,
    MemServer, MemZone, Quirks, ServerCookie,
};
pub use denial::{DenialCache, DenialHit, DenialKind, NoDenial};
pub use failure::{FailureCache, FailureCause, MemFailures};
pub use infra::{
    AddressOrigin, DsState, InfraBounds, InfraCache, InfraSizes, MemInfra, NameServer, ServerState,
    ZoneCut,
};
pub use validator::{
    BogusReason, ChainContext, KeyFetch, Unvalidating, Validation, ValidationCaps, Validator,
};

/// The identifier of a zone cut in the infrastructure cache: the key of the upstream set
/// of its name servers ([`crate::pool::PoolKey::Delegation`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CutId(pub u64);

/// The work budget of one client query (REC-Q12, recursion plan section 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkBudget {
    /// Queries sent to authorities, sub-queries included (`budget_queries`).
    pub queries: u16,
    /// CNAME and DNAME restarts (`budget_restarts`; the index's chain limit).
    pub restarts: u8,
    /// Levels of name-server address lookups (`budget_depth`).
    pub depth: u8,
    /// Attempts per server.
    pub attempts: u8,
    /// Wall clock from the hand-off (`budget_ms`).
    pub wall: Duration,
    /// Name-server address lookups allowed at each depth (Unbound's
    /// `target-fetch-policy`), none below the last.
    pub fetch_policy: [u8; 4],
}

impl WorkBudget {
    /// The defaults of REC-Q12.
    pub const DEFAULT: Self = Self {
        queries: 32,
        restarts: 8,
        depth: 6,
        attempts: 3,
        wall: Duration::from_secs(10),
        fetch_policy: [3, 2, 1, 0],
    };

    /// The address lookups allowed at `depth` (0 the client's resolution).
    pub fn lookups_at(&self, depth: u8) -> u8 {
        self.fetch_policy
            .get(usize::from(depth))
            .copied()
            .unwrap_or(0)
    }
}

impl Default for WorkBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The bound of the work budget a resolution hit: the counters say which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetBound {
    /// The queries sent.
    Queries,
    /// The restarts.
    Restarts,
    /// The depth of the name-server lookups.
    Depth,
    /// The wall clock.
    Time,
}

/// How the resolver reaches authorities over IP (REC-Q9, `[dns.recursion] outbound`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Outbound {
    /// Both families; an address that fails at once is skipped for six hours.
    #[default]
    Auto,
    /// IPv4 only.
    V4,
    /// IPv6 only.
    V6,
    /// Both families, never skipped.
    Both,
}

/// QNAME minimisation (RFC 9156, REC-Q8, `[dns.recursion] qname_minimisation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Minimisation {
    /// Minimise, falling back to the full name for a zone whose servers break on it.
    #[default]
    Relaxed,
    /// Minimise, never fall back.
    Strict,
    /// Send the full name.
    Off,
}

/// The settings of the recursive resolver, from `[dns.recursion]` and the profile (the
/// role maps the configuration onto them; WP10.1 consumes them).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent switches of the configuration section"
)]
pub struct RecursionSettings {
    /// The resolver runs.
    pub enabled: bool,
    /// Validation on (TGL-12).
    pub validate: bool,
    /// The address families.
    pub outbound: Outbound,
    /// The longest time one attempt has (`timeout_ms`).
    pub timeout: Duration,
    /// The work budget.
    pub budget: WorkBudget,
    /// The infrastructure cache's bounds.
    pub infra: InfraBounds,
    /// QNAME minimisation.
    pub minimisation: Minimisation,
    /// The denial cache on (RFC 8198).
    pub aggressive_nsec: bool,
    /// The denial cache's bound.
    pub denial_entries: usize,
    /// The longest hold of the failure cache.
    pub failure_max: Duration,
    /// RFC 8145 trust anchor signalling.
    pub signalling: bool,
    /// RFC 8509 root key sentinel.
    pub key_sentinel: bool,
    /// A fresh source port per exchange with an authority.
    pub fresh_port: bool,
    /// The cost caps of validation.
    pub caps: ValidationCaps,
}

impl Default for RecursionSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            validate: true,
            outbound: Outbound::Auto,
            timeout: Duration::from_millis(2_000),
            budget: WorkBudget::DEFAULT,
            infra: InfraBounds::STANDARD,
            minimisation: Minimisation::Relaxed,
            aggressive_nsec: true,
            denial_entries: 20_000,
            failure_max: failure::FAILURE_MAX,
            signalling: true,
            key_sentinel: true,
            fresh_port: true,
            caps: ValidationCaps::DEFAULT,
        }
    }
}

/// How the resolver answers a locally served name nothing of the node answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAnswer {
    /// NXDOMAIN (RFC 6761: `localhost`, `invalid`, `test`, `example`, `onion`, `local`,
    /// `home.arpa`).
    Nxdomain,
    /// An empty NOERROR with the zone's SOA (RFC 6303: the reverse zones of private,
    /// link-local, loopback and documentation ranges).
    Empty,
}

/// The special-use and locally served zones that never reach an authority (RFC 6761,
/// RFC 6303, RFC 8375, RFC 7686; recursion plan section 2.1), with the answer the resolver
/// gives when no zone or rule of the node answers them. `[dns.recursion]
/// local_zones_except` lifts entries (the lab lifts `test`).
pub const LOCAL_ZONES: &[(&str, LocalAnswer)] = &[
    ("localhost", LocalAnswer::Nxdomain),
    ("invalid", LocalAnswer::Nxdomain),
    ("test", LocalAnswer::Nxdomain),
    ("example", LocalAnswer::Nxdomain),
    ("onion", LocalAnswer::Nxdomain),
    ("local", LocalAnswer::Nxdomain),
    ("home.arpa", LocalAnswer::Nxdomain),
    ("10.in-addr.arpa", LocalAnswer::Empty),
    ("16.172.in-addr.arpa", LocalAnswer::Empty),
    ("17.172.in-addr.arpa", LocalAnswer::Empty),
    ("18.172.in-addr.arpa", LocalAnswer::Empty),
    ("19.172.in-addr.arpa", LocalAnswer::Empty),
    ("20.172.in-addr.arpa", LocalAnswer::Empty),
    ("21.172.in-addr.arpa", LocalAnswer::Empty),
    ("22.172.in-addr.arpa", LocalAnswer::Empty),
    ("23.172.in-addr.arpa", LocalAnswer::Empty),
    ("24.172.in-addr.arpa", LocalAnswer::Empty),
    ("25.172.in-addr.arpa", LocalAnswer::Empty),
    ("26.172.in-addr.arpa", LocalAnswer::Empty),
    ("27.172.in-addr.arpa", LocalAnswer::Empty),
    ("28.172.in-addr.arpa", LocalAnswer::Empty),
    ("29.172.in-addr.arpa", LocalAnswer::Empty),
    ("30.172.in-addr.arpa", LocalAnswer::Empty),
    ("31.172.in-addr.arpa", LocalAnswer::Empty),
    ("168.192.in-addr.arpa", LocalAnswer::Empty),
    ("0.in-addr.arpa", LocalAnswer::Empty),
    ("127.in-addr.arpa", LocalAnswer::Empty),
    ("254.169.in-addr.arpa", LocalAnswer::Empty),
    ("2.0.192.in-addr.arpa", LocalAnswer::Empty),
    ("100.51.198.in-addr.arpa", LocalAnswer::Empty),
    ("113.0.203.in-addr.arpa", LocalAnswer::Empty),
    ("255.255.255.255.in-addr.arpa", LocalAnswer::Empty),
    (
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        LocalAnswer::Empty,
    ),
    (
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        LocalAnswer::Empty,
    ),
    ("c.f.ip6.arpa", LocalAnswer::Empty),
    ("d.f.ip6.arpa", LocalAnswer::Empty),
    ("8.e.f.ip6.arpa", LocalAnswer::Empty),
    ("9.e.f.ip6.arpa", LocalAnswer::Empty),
    ("a.e.f.ip6.arpa", LocalAnswer::Empty),
    ("b.e.f.ip6.arpa", LocalAnswer::Empty),
    ("8.b.d.0.1.0.0.2.ip6.arpa", LocalAnswer::Empty),
];

#[cfg(test)]
mod tests;
