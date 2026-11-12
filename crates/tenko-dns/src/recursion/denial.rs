//! The denial cache's contract ([`DenialCache`], RFC 8198 and RFC 8020, recursion plan
//! section 2.2): validated NSEC and NSEC3 records with their SOA, per zone, in canonical
//! order; a name the answer cache has nothing for is answered NXDOMAIN, NODATA or from a
//! wildcard by synthesis on the worker, without allocating and without asking anyone.
//! WP10.3 builds it (`tenko_dns::cache::denial`); [`NoDenial`] is the reference for
//! `aggressive_nsec = false`.

use std::time::Instant;

use tenko_core::dns::{ForwardRuleId, ViewId, ZoneId};

use crate::cache::{Client, Verdict};

/// What a synthesized answer proves: the `kind` label of `tenko_dns_denial_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenialKind {
    /// The name does not exist (a covering record and the wildcard's denial).
    Nxdomain,
    /// The name exists without the type (the type bitmap).
    Nodata,
    /// A wildcard answers the name.
    Wildcard,
    /// An ancestor does not exist, so neither does the name (RFC 8020).
    NxdomainCut,
}

impl DenialKind {
    /// Every kind, in label order.
    pub const ALL: [DenialKind; 4] = [
        DenialKind::Nxdomain,
        DenialKind::Nodata,
        DenialKind::Wildcard,
        DenialKind::NxdomainCut,
    ];

    /// The label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            DenialKind::Nxdomain => "nxdomain",
            DenialKind::Nodata => "nodata",
            DenialKind::Wildcard => "wildcard",
            DenialKind::NxdomainCut => "nxdomain_cut",
        }
    }
}

/// Where an answer the denial cache is given came from: what it may take from an
/// NXDOMAIN of an unsigned zone (RFC 8020) depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The engine's resolution: each name of an alias chain was asked of the servers of its
    /// own zone, and a negative step's SOA is that zone's (`recurse::message::classify`).
    Recursion,
    /// An upstream's answer to a forwarded question: the question name is the upstream's
    /// to deny, the names an alias chain leads to are not.
    Forwarder,
}

/// The route that resolves a name: a forwarding rule, a stub zone, or neither (the view's
/// default resolution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DenialRoute {
    /// The view's default resolution (the resolver or the default upstreams).
    #[default]
    Default,
    /// A forwarding rule (of any mode).
    Rule(ForwardRuleId),
    /// A stub zone.
    Stub(ZoneId),
}

/// The resolution path a denial belongs to: the view and the route. A denial proves only
/// what the servers of its own path would answer (RFC 8198 section 5.1 speaks of one
/// resolver's view of one zone), so the cache answers a name only from records that an
/// answer of the path the name takes taught: a name under a forwarding rule or a stub zone
/// is never denied from a public zone's proofs, nor one view's names from another's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DenialScope {
    /// The view.
    pub view: Option<ViewId>,
    /// The route.
    pub route: DenialRoute,
}

impl DenialScope {
    /// The default resolution of `view`.
    pub const fn of_view(view: Option<ViewId>) -> Self {
        Self {
            view,
            route: DenialRoute::Default,
        }
    }
}

/// A synthesized answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenialHit {
    /// What it proves.
    pub kind: DenialKind,
    /// Its RCODE.
    pub rcode: u8,
}

/// The denial cache; see the module documentation.
pub trait DenialCache: Send + Sync {
    /// Synthesizes the answer to `qname` (lowercase wire form) and `qtype` on the path
    /// `scope` for `client` into `out` when a validated record taught on that path proves
    /// it (the worker: allocates nothing when `out` has room for 65,535 octets).
    fn answer(
        &self,
        scope: DenialScope,
        qname: &[u8],
        qtype: u16,
        client: &Client<'_>,
        now: Instant,
        out: &mut Vec<u8>,
    ) -> Option<DenialHit>;

    /// Keeps the NSEC or NSEC3 records and the SOA of the validated negative (or
    /// wildcard) answer `answer`, which came from `origin` (the runtime) on the path
    /// `scope`, under the zone that signed them. Returns whether anything was kept: the
    /// records only from a `secure` verdict, the name an NXDOMAIN of an unsigned zone
    /// denies (RFC 8020) from any verdict but `bogus`.
    fn insert(
        &self,
        scope: DenialScope,
        answer: &[u8],
        verdict: &Verdict,
        origin: Origin,
        now: Instant,
    ) -> bool;

    /// Removes every record, or those of the zones at or below `suffix` (lowercase wire
    /// form). Returns how many.
    fn flush(&self, suffix: Option<&[u8]>) -> usize;

    /// Records held.
    fn len(&self) -> usize;

    /// Whether none is held.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// No denial cache: nothing is synthesized.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDenial;

impl DenialCache for NoDenial {
    fn answer(
        &self,
        _scope: DenialScope,
        _qname: &[u8],
        _qtype: u16,
        _client: &Client<'_>,
        _now: Instant,
        _out: &mut Vec<u8>,
    ) -> Option<DenialHit> {
        None
    }

    fn insert(
        &self,
        _scope: DenialScope,
        _answer: &[u8],
        _verdict: &Verdict,
        _origin: Origin,
        _now: Instant,
    ) -> bool {
        false
    }

    fn flush(&self, _suffix: Option<&[u8]>) -> usize {
        0
    }

    fn len(&self) -> usize {
        0
    }
}
