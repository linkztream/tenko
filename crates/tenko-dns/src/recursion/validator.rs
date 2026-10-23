//! The validator's contract ([`Validator`], recursion plan section 2.3): an answer plus
//! the chain context in, a [`SecurityState`] and the extended error out. It sits on the
//! runtime between the authority's (or the upstream's) answer and the cache insert; the
//! worker never validates. `validate::DnssecValidator` implements it over
//! `dnssec::crypto` and the proofs of `validate::nsec` and `validate::nsec3` (REC-Q4:
//! Tenko's own code). [`Unvalidating`] is the reference for
//! validation off (the Lab profile may switch it off, TGL-12).

use std::{future::Future, time::SystemTime};

use tenko_core::dns::{DnsName, ExtendedError, Rtype, SecurityState};

use super::{anchors::TrustAnchors, infra::InfraCache};
use crate::cache::Verdict;

/// The cost caps of the `KeyTrap` class (`CVE-2023-50387`) and RFC 9276 (section 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationCaps {
    /// Signature verifications per RRset.
    pub per_rrset: u32,
    /// DNSKEY candidates per key tag.
    pub key_candidates: u32,
    /// NSEC3 hash computations per proof step.
    pub nsec3_hashes_per_step: u32,
    /// Signature verifications per client query.
    pub per_query: u32,
    /// Above this many NSEC3 iterations a zone is insecure (RFC 9276).
    pub nsec3_insecure_above: u16,
    /// Above this many the answer is SERVFAIL with extended error 27.
    pub nsec3_servfail_above: u16,
}

impl ValidationCaps {
    /// The caps of the plan.
    pub const DEFAULT: Self = Self {
        per_rrset: 8,
        key_candidates: 16,
        nsec3_hashes_per_step: 4,
        per_query: 32,
        nsec3_insecure_above: 100,
        nsec3_servfail_above: 500,
    };
}

impl Default for ValidationCaps {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why an answer is bogus: the `reason` label of `tenko_dns_validation_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BogusReason {
    /// A signature does not verify.
    Signature,
    /// A signature expired.
    Expired,
    /// A signature is not valid yet.
    NotYetValid,
    /// No DNSKEY matches the DS or the RRSIG.
    MissingKey,
    /// An RRset that should be signed is not.
    MissingRrsig,
    /// A denial proof fails or is missing.
    Nsec,
    /// A cost cap was hit.
    Cap,
    /// An algorithm or digest makes the chain bogus rather than insecure.
    Algorithm,
}

impl BogusReason {
    /// Every reason, in label order.
    pub const ALL: [BogusReason; 8] = [
        BogusReason::Signature,
        BogusReason::Expired,
        BogusReason::NotYetValid,
        BogusReason::MissingKey,
        BogusReason::MissingRrsig,
        BogusReason::Nsec,
        BogusReason::Cap,
        BogusReason::Algorithm,
    ];

    /// The label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            BogusReason::Signature => "signature",
            BogusReason::Expired => "expired",
            BogusReason::NotYetValid => "not_yet_valid",
            BogusReason::MissingKey => "missing_key",
            BogusReason::MissingRrsig => "missing_rrsig",
            BogusReason::Nsec => "nsec",
            BogusReason::Cap => "cap",
            BogusReason::Algorithm => "algorithm",
        }
    }

    /// The extended error that names the fault (RFC 8914).
    pub const fn ede(self) -> ExtendedError {
        match self {
            BogusReason::Signature | BogusReason::Cap => ExtendedError::DNSSEC_BOGUS,
            BogusReason::Expired => ExtendedError::SIGNATURE_EXPIRED,
            BogusReason::NotYetValid => ExtendedError::SIGNATURE_NOT_YET_VALID,
            BogusReason::MissingKey => ExtendedError::DNSKEY_MISSING,
            BogusReason::MissingRrsig => ExtendedError::RRSIGS_MISSING,
            BogusReason::Nsec => ExtendedError::NSEC_MISSING,
            BogusReason::Algorithm => ExtendedError::UNSUPPORTED_DNSKEY_ALGORITHM,
        }
    }
}

/// The validator's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validation {
    /// The state.
    pub state: SecurityState,
    /// Why it is bogus.
    pub reason: Option<BogusReason>,
    /// The extended error the answer goes with (a bogus one's fault, 5 for
    /// indeterminate).
    pub ede: Option<ExtendedError>,
    /// The earliest expiry of the signatures that made it secure.
    pub signature_expiry: Option<SystemTime>,
    /// The signature verifications it cost.
    pub verifications: u32,
}

impl Validation {
    /// Validation off.
    pub const UNVALIDATED: Self = Self {
        state: SecurityState::Unvalidated,
        reason: None,
        ede: None,
        signature_expiry: None,
        verifications: 0,
    };

    /// The cache's verdict, a bogus answer living at most `failure_ttl` seconds (RFC 9520).
    pub fn verdict(&self, failure_ttl: u32) -> Verdict {
        Verdict {
            state: self.state,
            ede: self.ede,
            signature_expiry: self.signature_expiry,
            max_ttl: (self.state == SecurityState::Bogus).then_some(failure_ttl),
        }
    }
}

/// An answer to a sub-query the chain walk needed (DS of a parent, DNSKEY of a zone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The message.
    pub message: Vec<u8>,
    /// The zone whose server answered.
    pub zone: DnsName,
}

/// Why a sub-query of the chain walk failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// No server answered.
    #[error("no server answered the sub-query")]
    Unreachable,
    /// The client query's work budget is spent.
    #[error("the work budget is spent")]
    Budget,
}

/// The sub-queries of the chain walk: through the engine (counted in the work budget), or
/// through the rule's upstream for a forwarded answer.
#[async_trait::async_trait]
pub trait KeyFetch: Send + Sync {
    /// The answer to `name`/`rtype` (DS or DNSKEY), with DO.
    ///
    /// # Errors
    ///
    /// [`FetchError`] when no server answered or the budget is spent.
    async fn fetch(&self, name: &DnsName, rtype: Rtype) -> Result<Fetched, FetchError>;
}

/// What the validator knows around an answer.
#[derive(Clone, Copy)]
pub struct ChainContext<'a> {
    /// The question's name.
    pub qname: &'a DnsName,
    /// The question's type.
    pub qtype: u16,
    /// The zone whose server gave the answer (the cut the engine asked).
    pub zone: &'a DnsName,
    /// The client set CD: validate for the cache, but never wait for a sub-query the
    /// resolution did not need.
    pub cd: bool,
    /// The anchors.
    pub anchors: &'a dyn TrustAnchors,
    /// The validated key sets and DS states.
    pub infra: &'a dyn InfraCache,
    /// The sub-queries.
    pub fetch: &'a dyn KeyFetch,
    /// The node's clock (OPS-09).
    pub now: SystemTime,
    /// The caps.
    pub caps: ValidationCaps,
}

impl std::fmt::Debug for ChainContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainContext")
            .field("qname", self.qname)
            .field("qtype", &self.qtype)
            .field("zone", self.zone)
            .field("cd", &self.cd)
            .finish_non_exhaustive()
    }
}

/// The validator; see the module documentation.
pub trait Validator: Send + Sync {
    /// The state of `answer` (a whole message) in `context`.
    fn validate<'a>(
        &'a self,
        answer: &'a [u8],
        context: &'a ChainContext<'a>,
    ) -> impl Future<Output = Validation> + Send + 'a;
}

/// Validation off: every answer is `unvalidated`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unvalidating;

impl Validator for Unvalidating {
    fn validate<'a>(
        &'a self,
        _answer: &'a [u8],
        _context: &'a ChainContext<'a>,
    ) -> impl Future<Output = Validation> + Send + 'a {
        std::future::ready(Validation::UNVALIDATED)
    }
}
