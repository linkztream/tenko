//! The denial cache's contract ([`DenialCache`], RFC 8198 and RFC 8020, recursion plan
//! section 2.2): validated NSEC and NSEC3 records with their SOA, per zone, in canonical
//! order; a name the answer cache has nothing for is answered NXDOMAIN, NODATA or from a
//! wildcard by synthesis on the worker, without allocating and without asking anyone.
//! WP10.3 builds it (`tenko_dns::cache::denial`); [`NoDenial`] is the reference for
//! `aggressive_nsec = false`.

use std::time::Instant;

use tenko_core::dns::{DnsName, ViewId};

use crate::cache::{Client, Verdict};

/// What a synthesised answer proves: the `kind` label of `tenko_dns_denial_total`.
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

/// A synthesised answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenialHit {
    /// What it proves.
    pub kind: DenialKind,
    /// Its RCODE.
    pub rcode: u8,
}

/// The denial cache; see the module documentation.
pub trait DenialCache: Send + Sync {
    /// Synthesises the answer to `qname` (lowercase wire form) and `qtype` in `view` for
    /// `client` into `out` when a validated record proves it (the worker: allocates
    /// nothing when `out` has room for 65,535 octets).
    fn answer(
        &self,
        view: Option<ViewId>,
        qname: &[u8],
        qtype: u16,
        client: &Client<'_>,
        now: Instant,
        out: &mut Vec<u8>,
    ) -> Option<DenialHit>;

    /// Keeps the NSEC or NSEC3 records and the SOA of the validated negative (or
    /// wildcard) answer `answer` of `zone` (the runtime). Returns whether anything was
    /// kept: the records only from a `secure` verdict, the name an NXDOMAIN of an unsigned
    /// zone denies (RFC 8020) from any verdict but `bogus`.
    fn insert(
        &self,
        view: Option<ViewId>,
        zone: &DnsName,
        answer: &[u8],
        verdict: &Verdict,
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

/// No denial cache: nothing is synthesised.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDenial;

impl DenialCache for NoDenial {
    fn answer(
        &self,
        _view: Option<ViewId>,
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
        _view: Option<ViewId>,
        _zone: &DnsName,
        _answer: &[u8],
        _verdict: &Verdict,
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
