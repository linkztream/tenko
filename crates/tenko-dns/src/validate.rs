//! The DNSSEC validator (WP10.2, recursion plan section 2.3, DNS-13, OPS-09, TGL-12):
//! Tenko's own code over the signer's canonical form, crypto and NSEC3 hashing (REC-Q4),
//! behind the [`Validator`] contract of WP10.0. It sits on the runtime between an
//! authority's (or an upstream's) answer and the cache insert; the worker only renders
//! the state it stores.
//!
//! **One answer** ([`DnssecValidator::validate`]) is judged RRset by RRset: each signed
//! RRset is checked with the keys of its signer, found by the chain walk from the nearest
//! trust anchor ([`chain`]: DS of the parent, DNSKEY of the child, kept in the
//! [`keys::KeyTable`] and the infrastructure cache's DS slot); an unsigned RRset takes
//! the state of the zone it lives in (insecure below a delegation without DS, bogus for a
//! missing signature in a secure zone, indeterminate when no anchor covers it). A
//! negative answer and a wildcard answer must carry the NSEC ([`nsec`]) or NSEC3
//! ([`nsec3`]) proof of the zone that signed them; a proof under an opt-out span makes
//! the answer insecure (RFC 5155 section 9.2). The answer's state is the worst of its
//! parts: bogus before indeterminate before insecure before secure.
//!
//! **The caps** (`CVE-2023-50387`, [`ValidationCaps`]): verifications per RRset, DNSKEY
//! candidates per key tag, NSEC3 hashes per proof step and verifications per client
//! query; past a cap the answer is bogus with extended error 6 and the reason `cap`.
//!
//! **CD** (RFC 4035 section 3.2.2): the forwarder gives a query with CD a [`KeyFetch`]
//! that refuses every sub-query ([`NoFetch`]), so the validator judges from what the key
//! table holds and reports the answer unvalidated when it would have to ask.
//!
//! **The clock** (OPS-09): when the root's DNSKEY set fails as expired or not yet valid,
//! [`DnssecValidator::clock_wrong`] is set (the finding `dns.validation.clock`) and
//! validation goes on failing rather than switching itself off.

pub mod chain;
pub mod keys;
pub mod nsec;
pub mod nsec3;
pub mod rrset;

use std::{
    future::Future,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use tenko_core::dns::{DnsName, ExtendedError, Rtype, SecurityState};

use crate::{
    metrics,
    recurse::message::{self, Parsed, substitute, types},
    recursion::{
        Authority, BogusReason, ChainContext, KeyFetch, Validation, ValidationCaps, Validator,
        validator::{FetchError, Fetched},
    },
};

use self::{
    chain::{Incomplete, Walker, fault_reason},
    keys::{KeyTable, ZoneState},
    nsec::{Nsec, ProofFault},
    nsec3::{Chain, Nsec3},
    rrset::{RrSet, Sig, group, verify},
};

/// The validator's counters since the role started.
#[derive(Debug, Default)]
pub struct Counters {
    secure: AtomicU64,
    insecure: AtomicU64,
    bogus: AtomicU64,
    indeterminate: AtomicU64,
    verifications: AtomicU64,
    caps: AtomicU64,
}

/// A copy of [`Counters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CounterValues {
    /// Answers validated secure.
    pub secure: u64,
    /// Answers validated insecure.
    pub insecure: u64,
    /// Answers validated bogus.
    pub bogus: u64,
    /// Answers no anchor covered.
    pub indeterminate: u64,
    /// Signature verifications run.
    pub verifications: u64,
    /// Answers bogus for a cost cap.
    pub caps: u64,
}

/// The validator's part of the node status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorReport {
    /// Zones in the key table.
    pub key_sets: usize,
    /// The table's bound.
    pub key_sets_bound: usize,
    /// The counters.
    pub counters: CounterValues,
    /// The root's DNSKEY set fails on time: the clock is probably wrong.
    pub clock_wrong: bool,
}

/// The validator; see the module documentation.
pub struct DnssecValidator {
    caps: ValidationCaps,
    table: Mutex<KeyTable>,
    counters: Counters,
    clock_wrong: AtomicBool,
    metrics: bool,
}

impl std::fmt::Debug for DnssecValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnssecValidator")
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

/// The rank of a state when states combine: the worst wins.
const fn rank(state: SecurityState) -> u8 {
    match state {
        SecurityState::Secure => 0,
        SecurityState::Unvalidated | SecurityState::Insecure => 1,
        SecurityState::Indeterminate => 2,
        SecurityState::Bogus => 3,
    }
}

/// The state of one RRset.
#[derive(Debug, Clone, Copy)]
struct Judged {
    state: SecurityState,
    reason: Option<BogusReason>,
    ede: Option<ExtendedError>,
    /// The expiration of the signature that made it secure.
    expiration: Option<u32>,
    /// The labels of the signer's name for a wildcard expansion.
    wildcard_labels: Option<u8>,
}

impl Judged {
    const fn secure(expiration: u32, wildcard_labels: Option<u8>) -> Self {
        Self {
            state: SecurityState::Secure,
            reason: None,
            ede: None,
            expiration: Some(expiration),
            wildcard_labels,
        }
    }

    const fn of(state: SecurityState) -> Self {
        Self {
            state,
            reason: None,
            ede: None,
            expiration: None,
            wildcard_labels: None,
        }
    }

    const fn bogus(reason: BogusReason, ede: ExtendedError) -> Self {
        Self {
            state: SecurityState::Bogus,
            reason: Some(reason),
            ede: Some(ede),
            expiration: None,
            wildcard_labels: None,
        }
    }

    fn from_zone(state: &ZoneState) -> Self {
        match state {
            ZoneState::Secure(_) | ZoneState::NotACut => Self::of(SecurityState::Secure),
            ZoneState::Insecure => Self::of(SecurityState::Insecure),
            ZoneState::Indeterminate => Self::of(SecurityState::Indeterminate),
            ZoneState::Bogus(reason, ede) => Self::bogus(*reason, *ede),
        }
    }
}

/// The running verdict of an answer.
#[derive(Debug, Clone, Copy)]
struct Verdict {
    state: SecurityState,
    reason: Option<BogusReason>,
    ede: Option<ExtendedError>,
    expiration: Option<u32>,
}

impl Verdict {
    const SECURE: Self = Self {
        state: SecurityState::Secure,
        reason: None,
        ede: None,
        expiration: None,
    };

    fn merge(&mut self, judged: &Judged) {
        if rank(judged.state) > rank(self.state) {
            self.state = judged.state;
            self.reason = judged.reason;
            self.ede = judged.ede;
        }
        if let Some(expiration) = judged.expiration {
            self.expiration = Some(match self.expiration {
                Some(known) if crate::dnssec::sign::seconds_until(known, expiration) < 0 => known,
                _ => expiration,
            });
        }
    }
}

/// The denial records of one zone, verified.
struct Denials<'a> {
    zone: Vec<u8>,
    nsecs: Vec<Nsec<'a>>,
    nsec3s: Vec<Nsec3<'a>>,
}

impl DnssecValidator {
    /// A validator with `caps` and a key table of at most `key_sets` zones.
    pub fn new(caps: ValidationCaps, key_sets: usize, metrics: bool) -> Self {
        Self {
            caps,
            table: Mutex::new(KeyTable::new(key_sets)),
            counters: Counters::default(),
            clock_wrong: AtomicBool::new(false),
            metrics,
        }
    }

    /// The caps.
    pub fn caps(&self) -> ValidationCaps {
        self.caps
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, KeyTable> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the root's DNSKEY set last failed on time (OPS-09).
    pub fn clock_wrong(&self) -> bool {
        self.clock_wrong.load(Ordering::Relaxed)
    }

    /// The counters.
    pub fn counters(&self) -> CounterValues {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        CounterValues {
            secure: read(&self.counters.secure),
            insecure: read(&self.counters.insecure),
            bogus: read(&self.counters.bogus),
            indeterminate: read(&self.counters.indeterminate),
            verifications: read(&self.counters.verifications),
            caps: read(&self.counters.caps),
        }
    }

    /// The report for the status.
    pub fn report(&self) -> ValidatorReport {
        let table = self.lock();
        ValidatorReport {
            key_sets: table.len(),
            key_sets_bound: table.bound(),
            counters: self.counters(),
            clock_wrong: self.clock_wrong(),
        }
    }

    /// Forgets the validated key sets, or those at or below `suffix` (lowercase wire
    /// form). Returns how many.
    pub fn flush(&self, suffix: Option<&[u8]>) -> usize {
        self.lock().flush(suffix)
    }

    /// Drops the key sets past their time.
    pub fn purge(&self, now: Instant) {
        self.lock().purge(now);
    }

    fn tally(&self, validation: &Validation, caps: bool) {
        let counter = match validation.state {
            SecurityState::Secure => &self.counters.secure,
            SecurityState::Insecure => &self.counters.insecure,
            SecurityState::Bogus => &self.counters.bogus,
            SecurityState::Indeterminate => &self.counters.indeterminate,
            SecurityState::Unvalidated => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.counters
            .verifications
            .fetch_add(u64::from(validation.verifications), Ordering::Relaxed);
        if caps {
            self.counters.caps.fetch_add(1, Ordering::Relaxed);
        }
        if self.metrics {
            if let Some(index) = metrics::validation_index(validation.state, validation.reason) {
                metrics::VALIDATION_COUNTER.inc(index);
            }
            metrics::VALIDATION_VERIFICATION_COUNTER.add(u64::from(validation.verifications));
        }
    }

    /// The state of one RRset: its signer's keys and the signature, or the zone's state
    /// for an unsigned set.
    async fn judge(&self, walker: &mut Walker<'_>, set: &RrSet<'_>) -> Result<Judged, Incomplete> {
        let signer = set
            .sigs
            .iter()
            .filter(|sig| sig.type_covered == set.rtype)
            .map(Sig::signer_lower)
            .filter(|signer| crate::name::is_within(set.owner, signer))
            .max_by_key(|signer| crate::name::label_count(signer));
        let Some(signer) = signer else {
            return Ok(match walker.state_at(set.owner).await? {
                ZoneState::Secure(_) | ZoneState::NotACut => {
                    Judged::bogus(BogusReason::MissingRrsig, ExtendedError::RRSIGS_MISSING)
                }
                other => Judged::from_zone(&other),
            });
        };
        let zone_state = walker.keys_for(&signer).await?;
        let ZoneState::Secure(keys) = &zone_state else {
            return Ok(Judged::from_zone(&zone_state));
        };
        let keys: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
        let now32 = walker.now32;
        let caps = walker.caps();
        Ok(
            match verify(
                set,
                &signer,
                &keys,
                &|_| true,
                now32,
                &caps,
                &mut walker.budget,
            ) {
                Ok(verified) => Judged::secure(verified.expiration, verified.wildcard_labels),
                Err(fault) => {
                    let (reason, ede) = fault_reason(fault);
                    Judged::bogus(reason, ede)
                }
            },
        )
    }

    /// The state of a CNAME a DNAME synthesised (RFC 6672 section 3.4): it carries no
    /// signature of its own and takes the DNAME's state, when a DNAME at a strict
    /// ancestor of its owner substitutes to its target.
    fn synthesised(
        cname: &RrSet<'_>,
        judged: &[(usize, Judged)],
        sets: &[RrSet<'_>],
    ) -> Option<Judged> {
        let target = cname.records.first()?;
        judged.iter().find_map(|(index, state)| {
            let dname = &sets[*index];
            if dname.rtype != types::DNAME
                || dname.owner == cname.owner
                || !crate::name::is_within(cname.owner, dname.owner)
            {
                return None;
            }
            let substituted = substitute(cname.owner, dname.owner, dname.records.first()?)?;
            (substituted == *target).then_some(*state)
        })
    }

    /// The last name of the CNAME chain from `qname` in the answer section.
    fn final_name(parsed: &Parsed, qtype: u16) -> Vec<u8> {
        let mut name = parsed.qname.clone();
        if qtype == types::CNAME {
            return name;
        }
        for _ in 0..message::MAX_RECORDS {
            let Some(cname) = parsed
                .answer
                .iter()
                .find(|rr| rr.owner == name && rr.rtype == types::CNAME)
            else {
                break;
            };
            let Some(target) = cname.target() else {
                break;
            };
            if target == name {
                break;
            }
            name = target;
        }
        name
    }

    /// Judges the negative or wildcard part of an answer with the denial records of
    /// `zone`.
    fn prove(walker: &mut Walker<'_>, denials: &Denials<'_>, proof: Proof<'_>) -> Judged {
        let caps = walker.caps();
        let bogus = Judged::bogus(BogusReason::Nsec, ExtendedError::NSEC_MISSING);
        let cap = Judged::bogus(BogusReason::Cap, ExtendedError::DNSSEC_BOGUS);
        if !denials.nsecs.is_empty() {
            let result = match proof {
                Proof::Nxdomain(name) => nsec::prove_nxdomain(&denials.nsecs, name, &denials.zone),
                Proof::Nodata(name, qtype) => {
                    nsec::prove_nodata(&denials.nsecs, name, qtype, &denials.zone).map(|_| ())
                }
                Proof::Wildcard(name, _) => {
                    nsec::prove_wildcard(&denials.nsecs, name, &denials.zone)
                }
            };
            return match result {
                Ok(()) => Judged::of(SecurityState::Secure),
                Err(_) => bogus,
            };
        }
        let Some(chain) = Chain::new(&denials.nsec3s, &denials.zone) else {
            return bogus;
        };
        if chain.iterations() > caps.nsec3_servfail_above {
            return Judged::bogus(
                BogusReason::Nsec,
                ExtendedError::UNSUPPORTED_NSEC3_ITERATIONS,
            );
        }
        if chain.iterations() > caps.nsec3_insecure_above {
            return Judged::of(SecurityState::Insecure);
        }
        walker.budget.hashes = 0;
        let result = match proof {
            Proof::Nxdomain(name) => chain.prove_nxdomain(name, &caps, &mut walker.budget),
            Proof::Nodata(name, qtype) => chain
                .prove_nodata(name, qtype, &caps, &mut walker.budget)
                .map(|(_, opt_out)| opt_out),
            Proof::Wildcard(name, labels) => {
                chain.prove_wildcard(name, labels, &caps, &mut walker.budget)
            }
        };
        match result {
            Ok(false) => Judged::of(SecurityState::Secure),
            // RFC 5155 section 9.2: under an opt-out span the answer is not secure.
            Ok(true) => Judged::of(SecurityState::Insecure),
            Err(ProofFault::Cap) => cap,
            Err(_) => bogus,
        }
    }

    /// The whole judgement of one answer.
    async fn run(&self, answer: &[u8], ctx: &ChainContext<'_>) -> Validation {
        let Some(parsed) = message::parse(answer) else {
            return Validation::UNVALIDATED;
        };
        if parsed.rcode != 0 && parsed.rcode != 3 {
            return Validation::UNVALIDATED;
        }
        let mut walker = Walker::new(ctx, &self.table);
        let outcome = self.run_parsed(&mut walker, &parsed, ctx.qtype).await;
        if let Some(clock) = walker.clock_fault {
            self.clock_wrong.store(clock, Ordering::Relaxed);
        }
        let Ok(verdict) = outcome else {
            return Validation {
                verifications: walker.budget.verifications,
                ..Validation::UNVALIDATED
            };
        };
        let signature_expiry = verdict.expiration.map(|expiration| {
            let left = crate::dnssec::sign::seconds_until(expiration, walker.now32).max(0);
            ctx.now + Duration::from_secs(u64::try_from(left).unwrap_or(0))
        });
        let validation = Validation {
            state: verdict.state,
            reason: verdict.reason,
            ede: match verdict.state {
                SecurityState::Indeterminate => Some(ExtendedError::DNSSEC_INDETERMINATE),
                SecurityState::Bogus => verdict.ede.or(Some(ExtendedError::DNSSEC_BOGUS)),
                _ => None,
            },
            signature_expiry: (verdict.state == SecurityState::Secure)
                .then_some(signature_expiry)
                .flatten(),
            verifications: walker.budget.verifications,
        };
        self.tally(&validation, verdict.reason == Some(BogusReason::Cap));
        validation
    }

    #[allow(clippy::too_many_lines, reason = "one answer from parse to verdict")]
    async fn run_parsed(
        &self,
        walker: &mut Walker<'_>,
        parsed: &Parsed,
        qtype: u16,
    ) -> Result<Verdict, Incomplete> {
        let answer_sets = group(&parsed.answer);
        // An unsigned NS set in the authority section is the delegation the answer came
        // through (RFC 4035 section 2.2: never signed at the parent); it is not judged.
        let authority_sets = group(&parsed.authority)
            .into_iter()
            .filter(|set| set.rtype != types::NS || !set.sigs.is_empty())
            .collect::<Vec<_>>();
        let answer_count = answer_sets.len();
        let sets: Vec<RrSet<'_>> = answer_sets.into_iter().chain(authority_sets).collect();
        let mut verdict = Verdict::SECURE;
        let mut judged: Vec<(usize, Judged)> = Vec::with_capacity(sets.len());
        let mut deferred_cnames: Vec<usize> = Vec::new();
        for (index, set) in sets.iter().enumerate() {
            if set.rtype == types::CNAME && set.sigs.is_empty() && index < answer_count {
                deferred_cnames.push(index);
                continue;
            }
            let state = self.judge(walker, set).await?;
            judged.push((index, state));
        }
        for index in deferred_cnames {
            let set = &sets[index];
            let state = match Self::synthesised(set, &judged, &sets) {
                Some(state) => state,
                None => self.judge(walker, set).await?,
            };
            judged.push((index, state));
        }
        for (_, state) in &judged {
            verdict.merge(state);
        }
        if verdict.state != SecurityState::Secure {
            return Ok(verdict);
        }
        // The denial records of each zone that proved secure.
        let mut denials: Vec<Denials<'_>> = Vec::new();
        for (index, state) in &judged {
            let set = &sets[*index];
            if state.state != SecurityState::Secure
                || (set.rtype != types::NSEC && set.rtype != types::NSEC3)
            {
                continue;
            }
            let Some(zone) = set.sigs.first().map(Sig::signer_lower) else {
                continue;
            };
            let entry = if let Some(index) = denials.iter().position(|entry| entry.zone == zone) {
                &mut denials[index]
            } else {
                denials.push(Denials {
                    zone,
                    nsecs: Vec::new(),
                    nsec3s: Vec::new(),
                });
                denials.last_mut().ok_or(Incomplete)?
            };
            for data in &set.records {
                match set.rtype {
                    types::NSEC => entry.nsecs.extend(Nsec::parse(set.owner, data)),
                    _ => entry
                        .nsec3s
                        .extend(Nsec3::parse(set.owner, data, &entry.zone)),
                }
            }
        }
        // Wildcard expansions need the proof that no closer name exists.
        for (index, state) in &judged {
            let Some(labels) = state.wildcard_labels else {
                continue;
            };
            let set = &sets[*index];
            let Some(zone) = set.sigs.first().map(Sig::signer_lower) else {
                continue;
            };
            let proved = match denials.iter().find(|entry| entry.zone == zone) {
                Some(entry) => Self::prove(walker, entry, Proof::Wildcard(set.owner, labels)),
                None => Judged::bogus(BogusReason::Nsec, ExtendedError::NSEC_MISSING),
            };
            verdict.merge(&proved);
        }
        if verdict.state != SecurityState::Secure {
            return Ok(verdict);
        }
        // A negative answer needs its proof from the zone that signed the SOA.
        let final_name = Self::final_name(parsed, qtype);
        let positive = qtype != types::ANY
            && sets[..answer_count]
                .iter()
                .any(|set| set.owner == final_name.as_slice() && set.rtype == qtype)
            || qtype == types::ANY
                && sets[..answer_count]
                    .iter()
                    .any(|set| set.owner == final_name.as_slice());
        if positive {
            return Ok(verdict);
        }
        let soa_zone = sets[answer_count..]
            .iter()
            .find(|set| set.rtype == types::SOA)
            .and_then(|set| set.sigs.first().map(Sig::signer_lower))
            .or_else(|| denials.first().map(|entry| entry.zone.clone()));
        let Some(soa_zone) = soa_zone else {
            // Nothing says who denies: the zone's state decides.
            let state = walker.state_at(&final_name).await?;
            let proved = match state {
                ZoneState::Secure(_) | ZoneState::NotACut => {
                    Judged::bogus(BogusReason::Nsec, ExtendedError::NSEC_MISSING)
                }
                other => Judged::from_zone(&other),
            };
            verdict.merge(&proved);
            return Ok(verdict);
        };
        let proof = if parsed.rcode == 3 {
            Proof::Nxdomain(&final_name)
        } else {
            Proof::Nodata(&final_name, qtype)
        };
        let proved = match denials.iter().find(|entry| entry.zone == soa_zone) {
            Some(entry) => Self::prove(walker, entry, proof),
            None => Judged::bogus(BogusReason::Nsec, ExtendedError::NSEC_MISSING),
        };
        verdict.merge(&proved);
        Ok(verdict)
    }
}

/// What a denial must prove.
#[derive(Debug, Clone, Copy)]
enum Proof<'a> {
    Nxdomain(&'a [u8]),
    Nodata(&'a [u8], u16),
    Wildcard(&'a [u8], u8),
}

impl Validator for DnssecValidator {
    fn validate<'a>(
        &'a self,
        answer: &'a [u8],
        context: &'a ChainContext<'a>,
    ) -> impl Future<Output = Validation> + Send + 'a {
        self.run(answer, context)
    }
}

/// A [`KeyFetch`] that refuses every sub-query: the validator judges from the key table
/// alone (a query with CD, recursion plan section 2.3).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoFetch;

#[async_trait::async_trait]
impl KeyFetch for NoFetch {
    async fn fetch(&self, _name: &DnsName, _rtype: Rtype) -> Result<Fetched, FetchError> {
        Err(FetchError::Budget)
    }
}

/// The sub-queries of the chain walk through the iterative engine: each one a
/// resolution of its own (joined with any in flight, counted in the engine's figures),
/// never through the answer cache.
pub struct EngineFetch<A> {
    engine: Arc<crate::recurse::Engine<A>>,
    sent: AtomicU64,
}

impl<A> std::fmt::Debug for EngineFetch<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineFetch").finish_non_exhaustive()
    }
}

impl<A: Authority + 'static> EngineFetch<A> {
    /// Sub-queries through `engine`.
    pub fn new(engine: Arc<crate::recurse::Engine<A>>) -> Self {
        Self {
            engine,
            sent: AtomicU64::new(0),
        }
    }

    /// The queries the sub-queries sent to authorities.
    pub fn subqueries(&self) -> u16 {
        u16::try_from(self.sent.load(Ordering::Relaxed)).unwrap_or(u16::MAX)
    }
}

#[async_trait::async_trait]
impl<A: Authority + 'static> KeyFetch for EngineFetch<A> {
    async fn fetch(&self, name: &DnsName, rtype: Rtype) -> Result<Fetched, FetchError> {
        let qname = name.to_wire();
        let resolved = self
            .engine
            .resolve(crate::recurse::Question {
                qname: &qname,
                qtype: rtype.0,
                qclass: 1,
                view: None,
            })
            .await;
        self.sent
            .fetch_add(u64::from(resolved.subqueries), Ordering::Relaxed);
        match resolved.outcome {
            crate::recurse::Outcome::Answered => Ok(Fetched {
                message: resolved.message.clone(),
                zone: name.clone(),
            }),
            _ => Err(FetchError::Unreachable),
        }
    }
}

/// The sub-queries of the chain walk through a forwarding rule's upstream set, as a
/// validating forwarder asks its upstream.
pub struct UpstreamFetch {
    set: Arc<crate::pool::UpstreamSet>,
    budget: crate::pool::Budget,
}

impl std::fmt::Debug for UpstreamFetch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamFetch").finish_non_exhaustive()
    }
}

impl UpstreamFetch {
    /// Sub-queries through `set` within `budget`.
    pub fn new(set: Arc<crate::pool::UpstreamSet>, budget: crate::pool::Budget) -> Self {
        Self { set, budget }
    }
}

#[async_trait::async_trait]
impl KeyFetch for UpstreamFetch {
    async fn fetch(&self, name: &DnsName, rtype: Rtype) -> Result<Fetched, FetchError> {
        let qname = name.to_wire();
        let question = crate::outbound::Question {
            qname: &qname,
            qtype: rtype.0,
            qclass: 1,
            rd: true,
            cd: false,
            dnssec_ok: true,
        };
        let mut answer = Vec::new();
        self.set
            .query(&question, self.budget, &mut answer)
            .await
            .map_err(|_| FetchError::Unreachable)?;
        Ok(Fetched {
            message: answer,
            zone: name.clone(),
        })
    }
}

/// The RFC 8509 sentinel: what the first label of a name asks of a validating resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sentinel {
    /// `root-key-sentinel-is-ta-<tag>`: answer only when the tag is a trusted root key.
    IsTrustAnchor(u16),
    /// `root-key-sentinel-not-ta-<tag>`: answer only when it is not.
    NotTrustAnchor(u16),
}

/// Reads the sentinel label of `qname` (lowercase wire form), if its first label is one
/// (RFC 8509 section 2: the label, then a decimal key tag).
pub fn sentinel(qname: &[u8]) -> Option<Sentinel> {
    let len = usize::from(*qname.first()?);
    let label = qname.get(1..1 + len)?;
    let (rest, is) = if let Some(rest) = label.strip_prefix(b"root-key-sentinel-is-ta-") {
        (rest, true)
    } else {
        (label.strip_prefix(b"root-key-sentinel-not-ta-")?, false)
    };
    if rest.is_empty() || rest.len() > 5 || !rest.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let tag: u32 = std::str::from_utf8(rest).ok()?.parse().ok()?;
    let tag = u16::try_from(tag).ok()?;
    Some(if is {
        Sentinel::IsTrustAnchor(tag)
    } else {
        Sentinel::NotTrustAnchor(tag)
    })
}

/// Whether a secure A or AAAA answer to a sentinel name is answered (RFC 8509 section
/// 3), given the key tags of the trusted root anchors.
pub fn sentinel_answers(sentinel: Sentinel, tags: &[u16]) -> bool {
    match sentinel {
        Sentinel::IsTrustAnchor(tag) => tags.contains(&tag),
        Sentinel::NotTrustAnchor(tag) => !tags.contains(&tag),
    }
}

/// The name of RFC 8145's trust anchor signalling query (section 4.1): `_ta-<tag>[-<tag>]`
/// with the tags in ascending order as four hexadecimal digits each, at the root; `None`
/// without a tag.
pub fn signalling_name(tags: &[u16]) -> Option<DnsName> {
    if tags.is_empty() {
        return None;
    }
    let mut sorted = tags.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let label: Vec<String> = sorted.iter().map(|tag| format!("{tag:04x}")).collect();
    DnsName::new(&format!("_ta-{}", label.join("-"))).ok()
}

/// The age at which the signalling query is sent again: once a day.
pub const SIGNALLING_PERIOD: Duration = Duration::from_secs(86_400);

/// The current time as the validator's context wants it.
pub fn now() -> SystemTime {
    SystemTime::now()
}

#[cfg(test)]
mod tests;
