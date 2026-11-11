//! The denial cache (WP10.3, recursion plan section 2.2, RFC 8198, RFC 8020, DNS-34):
//! [`Denials`], the [`DenialCache`] of a node.
//!
//! - **What it holds.** Per view and zone: the zone's SOA with its signatures; the NSEC
//!   records in canonical order (RFC 4034 section 6.1, an order key per owner, [`order`]);
//!   the NSEC3 records by hashed owner under the chain's parameters (one salt and iteration
//!   count per zone, at most the iterations the validator still calls secure, RFC 9276); the
//!   wildcard RRsets a validated expansion showed; each with its signatures and a lifetime of
//!   its smallest TTL, never past an original TTL or a signature's expiration. They come from
//!   answers the validator called `secure` only, never from insecure, bogus or unvalidated
//!   ones, and each is kept under the zone that signed it: the signer the validator checked
//!   it under ([`rrset::signer_of`]), which must be the zone of the answer's SOA (else of its
//!   first denial record); a wildcard RRset only when its signature's labels reach at least
//!   that zone's. An NXDOMAIN of an unsigned (or unvalidated) zone keeps the name it denies
//!   instead (RFC 8020), with the SOA, for at most `negative_ttl`: on the recursion path the
//!   last name of a CNAME chain, below the SOA's zone; from a forwarder the question name
//!   only. A signed SOA in such an answer keeps nothing, and an insecure answer never
//!   replaces a zone held from secure ones.
//! - **The delegation** of a zone, when the answer that taught its records carried one (the
//!   resolver's answers do while an RPZ zone has NSDNAME or NSIP triggers): the NS records
//!   at the apex, or at the parent's cut when the zone's servers answer for the parent as
//!   well, and the addresses of those name servers, at most
//!   [`store::MAX_DELEGATION_SERVERS`] and [`store::MAX_DELEGATION_ADDRESSES`] (more keeps
//!   none), living as long as the shortest of them. [`Denials::answer_carrying`] writes into
//!   the synthesized answer what the resolver's own answer would carry, for those triggers
//!   to judge: the zone's delegation; for a zone without a cut of its own on the resolver's
//!   path, none in a negative answer and the parent's in a wildcard answer. Under the carry
//!   it answers nothing from a zone whose answers it does not know.
//! - **The bound** (`denial_entries`: 2,000 under Home, 20,000 otherwise) counts records and
//!   names; past it the least recently used sixteenth goes.
//! - **The lookup** ([`Denials::answer`], the worker): for a name the answer cache has
//!   nothing for, the closest enclosing zone the cache holds, under the store's read lock
//!   and without allocating: a name below a cached NXDOMAIN of an unsigned zone is NXDOMAIN
//!   (`nxdomain_cut`); in a signed zone the NSEC3 proof (the closest encloser from the apex
//!   down, at most [`store::MAX_HASHES`] hashes in fixed buffers, an opt-out span proving
//!   nothing) or the NSEC proof (the covering record, the closest encloser and the wildcard
//!   at it) makes NXDOMAIN, NODATA (also for an empty non-terminal and a wildcard without the
//!   type) or the wildcard answer. A record of a delegation or a DNAME above the name proves
//!   nothing below it. DS, ANY and the DNSSEC and meta types are never synthesized. The
//!   answer is written by [`synth`]. A miss falls through to the runtime.
//! - **`aggressive_nsec = false`** turns the lookup off and keeps filling the records.
//! - **Flush**: everything, or the zones at or below a suffix and the records of the zones
//!   above it whose owners are at or below it.

pub mod order;
pub mod store;
pub mod synth;

use std::{
    collections::HashMap,
    sync::{
        PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Instant, SystemTime},
};

use tenko_core::dns::{SecurityState, ViewId};

use self::store::{Chain3, Cut, Nsec, Nsec3, Set, Zone, nsec3_params, wildcard_key};
use crate::{
    cache::{Client, Verdict},
    dnssec::chain::base32hex_decode,
    name,
    recurse::message::{self, Rr, types},
    recursion::{
        ValidationCaps,
        denial::{DenialCache, DenialHit, DenialKind, Origin},
    },
    validate::rrset::{self, Sig},
};

/// The longest key of a zone: the view's tag and id, and the apex.
const ZONE_KEY_MAX: usize = 1 + 16 + order::NAME_MAX;

/// The denial cache's settings (`[dns.recursion]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenialSettings {
    /// The lookup on (`aggressive_nsec`).
    pub aggressive: bool,
    /// The most records and names it holds (`denial_entries`).
    pub entries: usize,
    /// The most NSEC3 iterations of a chain it keeps (the validator's insecure cap).
    pub nsec3_iterations: u16,
    /// The longest a negative answer is kept, in seconds (the answer cache's
    /// `negative_ttl`): an SOA and the names of RFC 8020 live no longer.
    pub negative_ttl: u32,
}

impl Default for DenialSettings {
    fn default() -> Self {
        Self {
            aggressive: true,
            entries: 20_000,
            nsec3_iterations: ValidationCaps::DEFAULT.nsec3_insecure_above,
            negative_ttl: 3_600,
        }
    }
}

#[derive(Debug, Default)]
struct Store {
    zones: HashMap<Box<[u8]>, Zone>,
    records: usize,
}

/// The denial cache; see the module documentation.
#[derive(Debug)]
pub struct Denials {
    settings: DenialSettings,
    epoch: Instant,
    store: RwLock<Store>,
    synthesized: [AtomicU64; 4],
}

/// The key of a zone in a view, on the stack.
fn zone_key<'a>(view: Option<ViewId>, apex: &[u8], buf: &'a mut [u8; ZONE_KEY_MAX]) -> &'a [u8] {
    let mut at = 1;
    match view {
        Some(view) => {
            buf[0] = 1;
            buf[1..17].copy_from_slice(view.uuid().as_bytes());
            at = 17;
        }
        None => buf[0] = 0,
    }
    let len = apex.len().min(order::NAME_MAX);
    buf[at..at + len].copy_from_slice(&apex[..len]);
    &buf[..at + len]
}

/// The apex in a zone key.
fn apex_of(key: &[u8]) -> &[u8] {
    let at = if key.first() == Some(&1) { 17 } else { 1 };
    key.get(at..).unwrap_or_default()
}

/// Whether the type is never synthesized: DS (the parent's), ANY, the DNSSEC types and the
/// meta types.
fn unsynthesized(qtype: u16) -> bool {
    matches!(
        qtype,
        0 | types::DS | types::RRSIG | types::NSEC | types::NSEC3 | 41
    ) || (128..=255).contains(&qtype)
}

/// The signer `rrset` (records at one owner of `rtype`, with `sigs`) is checked under
/// by the validator ([`rrset::signer_of`]): for a secure answer, the zone that vouched
/// for it.
fn verified_signer(owner: &[u8], rtype: u16, sigs: &[&Rr]) -> Option<Vec<u8>> {
    rrset::signer_of(
        owner,
        rtype,
        sigs.iter().filter_map(|rr| Sig::parse(&rr.data)),
    )
}

/// The signatures of `sigs` whose signer is `apex`.
fn by_signer<'a>(sigs: &[&'a Rr], apex: &[u8]) -> Vec<&'a Rr> {
    sigs.iter()
        .copied()
        .filter(|rr| Sig::parse(&rr.data).is_some_and(|sig| sig.signer_lower() == apex))
        .collect()
}

/// The labels field of an RRSIG.
fn sig_labels(rrsig: &Rr) -> Option<u8> {
    rrsig.data.get(3).copied()
}

fn unix_now() -> u32 {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    #[allow(
        clippy::cast_possible_truncation,
        reason = "signature times are serial numbers modulo 2^32 (RFC 4034 section 3.1.5)"
    )]
    let secs = secs as u32;
    secs
}

/// The records of `section` at `owner` of `rtype`, and the signatures covering them.
fn rrset<'a>(section: &'a [Rr], owner: &[u8], rtype: u16) -> (Vec<&'a Rr>, Vec<&'a Rr>) {
    let at_owner = || section.iter().filter(move |rr| rr.owner == owner);
    (
        at_owner().filter(|rr| rr.rtype == rtype).collect(),
        at_owner()
            .filter(|rr| rr.covered() == Some(rtype))
            .collect(),
    )
}

/// What one answer adds to a zone.
#[derive(Debug, Default)]
struct Learned {
    apex: Vec<u8>,
    soa: Option<Set>,
    nsec: Vec<Nsec>,
    nsec3: Vec<Nsec3>,
    params: Option<(Box<[u8]>, u16)>,
    wildcards: Vec<(u16, Set)>,
    cut: Option<(Vec<u8>, u32)>,
}

impl Learned {
    fn is_empty(&self) -> bool {
        self.nsec.is_empty()
            && self.nsec3.is_empty()
            && self.wildcards.is_empty()
            && self.cut.is_none()
    }
}

impl Denials {
    /// An empty cache.
    pub fn new(settings: DenialSettings) -> Self {
        Self {
            settings: DenialSettings {
                entries: settings.entries.max(1),
                ..settings
            },
            epoch: Instant::now(),
            store: RwLock::new(Store::default()),
            synthesized: Default::default(),
        }
    }

    /// The settings.
    pub fn settings(&self) -> &DenialSettings {
        &self.settings
    }

    fn secs(&self, now: Instant) -> u32 {
        u32::try_from(now.saturating_duration_since(self.epoch).as_secs()).unwrap_or(u32::MAX)
    }

    /// Answers synthesized since the start, by kind in the order of [`DenialKind::ALL`].
    pub fn synthesized(&self) -> [u64; 4] {
        let mut out = [0; 4];
        for (slot, counter) in out.iter_mut().zip(&self.synthesized) {
            *slot = counter.load(Ordering::Relaxed);
        }
        out
    }

    /// The zones held.
    pub fn zones(&self) -> usize {
        self.store
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .zones
            .len()
    }

    /// Drops what expired before `now` (housekeeping; the bound holds without it).
    pub fn purge(&self, now: Instant) -> usize {
        let now = self.secs(now);
        let mut store = self.store.write().unwrap_or_else(PoisonError::into_inner);
        let mut removed = 0;
        store.zones.retain(|_, zone| {
            removed += zone.retain(|_, expires, _| expires > now);
            if zone.soa.as_ref().is_some_and(|soa| !soa.fresh(now)) {
                zone.soa = None;
            }
            // A zone known from wildcard answers alone has no SOA and stays while it
            // holds records.
            zone.count() > 0
        });
        store.records = store.records.saturating_sub(removed);
        removed
    }

    /// The SOA set at `apex` in `parsed` with the signatures of `signer` (all of them for
    /// `None`), never living past `negative_ttl`.
    fn soa(
        &self,
        parsed: &message::Parsed,
        apex: &[u8],
        signer: Option<&[u8]>,
        now: u32,
    ) -> Option<Set> {
        let (records, sigs) = rrset(&parsed.authority, apex, types::SOA);
        let sigs = match signer {
            Some(signer) => by_signer(&sigs, signer),
            None => sigs,
        };
        let mut soa = Set::build(apex, &records, &sigs, now, unix_now())?;
        soa.expires = soa
            .expires
            .min(now.saturating_add(self.settings.negative_ttl));
        soa.fresh(now).then_some(soa)
    }

    /// What `parsed`, an answer the validator did not call secure, adds: the name its
    /// NXDOMAIN denies in an unsigned zone (RFC 8020), under the zone of its SOA, for the
    /// negative TTL at most `negative_ttl`. Only an SOA the path vouches for counts: on
    /// the recursion path each name of an alias chain was asked of its own zone's servers,
    /// so the last name is denied; a forwarder's answer denies the question name alone. A
    /// signed SOA keeps nothing: a signed zone is answered from its validated NSEC or NSEC3
    /// records only.
    fn learn_cut(&self, parsed: &message::Parsed, origin: Origin, now: u32) -> Option<Learned> {
        if parsed.rcode != 3 {
            return None;
        }
        let apex = parsed
            .authority
            .iter()
            .find(|rr| rr.rtype == types::SOA)?
            .owner
            .clone();
        if parsed
            .authority
            .iter()
            .any(|rr| rr.owner == apex && rr.covered() == Some(types::SOA))
        {
            return None;
        }
        // RFC 8020: the name the NXDOMAIN denies is the last of the chain.
        let mut denied = parsed.qname.clone();
        for _ in 0..16 {
            let Some(target) = parsed
                .answer
                .iter()
                .find(|rr| rr.owner == denied && rr.rtype == types::CNAME)
                .and_then(Rr::target)
            else {
                break;
            };
            denied = target;
        }
        if origin == Origin::Forwarder && denied != parsed.qname {
            return None;
        }
        if !name::is_within(&denied, &apex) || denied == apex {
            return None;
        }
        let soa = self.soa(parsed, &apex, None, now)?;
        let ttl = soa.left(now).min(soa.soa_minimum().unwrap_or(u32::MAX));
        if ttl == 0 {
            return None;
        }
        Some(Learned {
            soa: Some(soa),
            cut: Some((denied, now.saturating_add(ttl))),
            apex,
            ..Learned::default()
        })
    }

    /// What `parsed`, an answer the validator called secure, adds: the records the zone
    /// of its SOA signed (else the zone of its first NSEC or NSEC3 record), each kept only
    /// when the signer the validator checked it under is that zone.
    fn learn_secure(&self, parsed: &message::Parsed, now: u32) -> Option<Learned> {
        let unix = unix_now();
        let apex = match parsed.authority.iter().find(|rr| rr.rtype == types::SOA) {
            Some(soa) => {
                let (_, sigs) = rrset(&parsed.authority, &soa.owner, types::SOA);
                // The zone's own SOA is signed by the zone.
                let signer = verified_signer(&soa.owner, types::SOA, &sigs)?;
                (signer == soa.owner).then_some(signer)?
            }
            None => [&parsed.authority, &parsed.answer]
                .into_iter()
                .find_map(|section| {
                    let rr = section
                        .iter()
                        .find(|rr| matches!(rr.rtype, types::NSEC | types::NSEC3))?;
                    let (_, sigs) = rrset(section, &rr.owner, rr.rtype);
                    Some(verified_signer(&rr.owner, rr.rtype, &sigs))
                })
                .flatten()?,
        };
        let mut learned = Learned {
            soa: self.soa(parsed, &apex, Some(&apex), now),
            apex,
            ..Learned::default()
        };
        let apex = learned.apex.clone();
        let mut owners: Vec<&[u8]> = Vec::new();
        for rr in parsed.answer.iter().chain(&parsed.authority) {
            if matches!(rr.rtype, types::NSEC | types::NSEC3)
                && name::is_within(&rr.owner, &apex)
                && !owners.contains(&rr.owner.as_slice())
            {
                owners.push(&rr.owner);
            }
        }
        for owner in owners {
            for rtype in [types::NSEC, types::NSEC3] {
                let section = if parsed
                    .authority
                    .iter()
                    .any(|rr| rr.owner == owner && rr.rtype == rtype)
                {
                    &parsed.authority
                } else {
                    &parsed.answer
                };
                let (records, sigs) = rrset(section, owner, rtype);
                if records.is_empty()
                    || verified_signer(owner, rtype, &sigs).as_deref() != Some(apex.as_slice())
                {
                    continue;
                }
                let sigs = by_signer(&sigs, &apex);
                let Some(set) = Set::build(owner, &records[..1], &sigs, now, unix) else {
                    continue;
                };
                if rtype == types::NSEC {
                    // The next name of a zone's record lies within the zone (the last one's
                    // is the apex).
                    learned.nsec.extend(
                        Nsec::of(set).filter(|record| name::is_within(&record.next_name, &apex)),
                    );
                    continue;
                }
                // An NSEC3 owner is the hash's label right below the apex.
                if name::label_count(owner) != name::label_count(&apex) + 1
                    || name::suffix(owner, 1) != apex
                {
                    continue;
                }
                let Some((_, iterations, salt, _)) = nsec3_params(&records[0].data) else {
                    continue;
                };
                if iterations > self.settings.nsec3_iterations {
                    continue;
                }
                let params = (Box::<[u8]>::from(salt), iterations);
                if learned
                    .params
                    .as_ref()
                    .is_some_and(|known| *known != params)
                {
                    continue;
                }
                let label = name::Labels::new(owner).next().unwrap_or_default();
                if base32hex_decode(label).is_none() {
                    continue;
                }
                if let Some(record) = Nsec3::of(set) {
                    learned.params = Some(params);
                    learned.nsec3.push(record);
                }
            }
        }
        Self::learn_wildcards(parsed, &apex, &mut learned.wildcards, now, unix);
        Some(learned)
    }

    /// The wildcard RRsets of a secure expansion in `parsed` that the zone `apex` signed.
    fn learn_wildcards(
        parsed: &message::Parsed,
        apex: &[u8],
        wildcards: &mut Vec<(u16, Set)>,
        now: u32,
        unix: u32,
    ) {
        // The wildcard RRsets of an expansion: a signature by the zone with fewer labels
        // than its owner and at least the zone's own (RFC 4035 sections 5.3.1 and 5.3.4).
        let apex_labels = name::label_count(apex);
        for sig in parsed.answer.iter().filter(|rr| rr.rtype == types::RRSIG) {
            let (Some(covered), Some(labels)) = (sig.covered(), sig_labels(sig)) else {
                continue;
            };
            let owner_labels = name::label_count(&sig.owner);
            let labels = usize::from(labels);
            if labels >= owner_labels
                || labels < apex_labels
                || !name::is_within(&sig.owner, apex)
                || Sig::parse(&sig.data).is_none_or(|parsed| parsed.signer_lower() != apex)
            {
                continue;
            }
            let (records, sigs) = rrset(&parsed.answer, &sig.owner, covered);
            if verified_signer(&sig.owner, covered, &sigs).as_deref() != Some(apex) {
                continue;
            }
            let encloser = name::suffix(&sig.owner, owner_labels - labels);
            let mut buf = [0u8; order::NAME_MAX];
            let Some(wildcard) = order::wildcard_of(encloser, &mut buf) else {
                continue;
            };
            if wildcards
                .iter()
                .any(|(rtype, set)| *rtype == covered && *set.owner == *wildcard)
            {
                continue;
            }
            // Only the expansion's own signatures, by the zone with these labels.
            let sigs: Vec<&Rr> = by_signer(&sigs, apex)
                .into_iter()
                .filter(|rr| sig_labels(rr).map(usize::from) == Some(labels))
                .collect();
            if let Some(set) = Set::build(wildcard, &records, &sigs, now, unix) {
                wildcards.push((covered, set));
            }
        }
    }

    /// Bounds the store: past the bound the least recently used sixteenth goes.
    fn trim(&self, store: &mut Store) {
        let bound = self.settings.entries;
        if store.records <= bound {
            return;
        }
        let mut times = Vec::with_capacity(store.records);
        for zone in store.zones.values() {
            zone.used_times(&mut times);
        }
        if times.is_empty() {
            return;
        }
        let drop = (store.records - bound)
            .max(bound / 16)
            .clamp(1, times.len());
        let (_, cut, _) = times.select_nth_unstable(drop - 1);
        let cut = *cut;
        let mut left = drop;
        let mut removed = 0;
        store.zones.retain(|_, zone| {
            removed += zone.retain(|_, _, used| {
                if left > 0 && used <= cut {
                    left -= 1;
                    false
                } else {
                    true
                }
            });
            zone.count() > 0
        });
        store.records = store.records.saturating_sub(removed);
    }
}

impl Denials {
    /// Synthesizes as [`DenialCache::answer`] does; with `carry` (the resolver's answers
    /// carry their delegation for the RPZ triggers NSDNAME and NSIP) with what the
    /// resolver's own answer would carry, so that the triggers judge it as they judge an
    /// answer from the answer cache: the zone's delegation, held and fresh; for a zone whose
    /// servers are its parent's, the parent's cut in a wildcard answer and nothing in a
    /// negative one ([`Zone::above_until`]). A zone whose answers under the carry are not
    /// known is left to the resolver, whose answer carries it and teaches the zone.
    #[allow(
        clippy::too_many_arguments,
        reason = "the trait's arguments and the carry"
    )]
    pub fn answer_carrying(
        &self,
        view: Option<ViewId>,
        qname: &[u8],
        qtype: u16,
        client: &Client<'_>,
        now: Instant,
        out: &mut Vec<u8>,
        carry: bool,
    ) -> Option<DenialHit> {
        if !self.settings.aggressive || unsynthesized(qtype) {
            return None;
        }
        let now = self.secs(now);
        let store = self.store.read().unwrap_or_else(PoisonError::into_inner);
        if store.zones.is_empty() {
            return None;
        }
        let mut buf = [0u8; ZONE_KEY_MAX];
        let labels = name::label_count(qname);
        let zone = (0..=labels).find_map(|skip| {
            store
                .zones
                .get(zone_key(view, name::suffix(qname, skip), &mut buf))
        })?;
        let mut synth = zone.lookup(qname, qtype, now)?;
        if carry {
            let negative = synth.answer.is_none();
            match zone
                .delegation
                .as_ref()
                .filter(|delegation| delegation.fresh(now))
            {
                // The zone's own cut: every answer of the resolver in the zone carries it.
                Some(delegation) if *delegation.ns.owner == *zone.apex => {
                    synth.delegation = Some(delegation);
                }
                // A cut above the zone: the resolver's positive answers carry it.
                Some(delegation) if !negative => synth.delegation = Some(delegation),
                // Its negative answers carry nothing beside the zone's SOA.
                _ if negative && zone.above_until > now => {}
                // The resolver's answers for the zone carry a delegation the cache does not
                // hold (or it is not known what they carry), so a synthesized one may not go
                // without it. A zone only forwarders taught, whose answers never carried one,
                // is synthesized as before.
                _ if zone.from_recursion || zone.delegated => return None,
                _ => {}
            }
        }
        let rcode = synth::write(&synth, client, now, out)?;
        let index = DenialKind::ALL
            .iter()
            .position(|kind| *kind == synth.kind)
            .unwrap_or(0);
        self.synthesized[index].fetch_add(1, Ordering::Relaxed);
        Some(DenialHit {
            kind: synth.kind,
            rcode,
        })
    }

    /// Keeps what `answer` proves, as [`DenialCache::insert`] does. `carried` says that the
    /// resolver composed it while answers carry their delegation: the NS records it holds are
    /// then the cut the resolver followed, and an answer without the zone's own says that the
    /// resolver's answers in the zone carry none of it (see [`Zone::above_until`]).
    pub fn insert_carried(
        &self,
        view: Option<ViewId>,
        answer: &[u8],
        verdict: &Verdict,
        origin: Origin,
        now: Instant,
        carried: bool,
    ) -> bool {
        if verdict.state == SecurityState::Bogus {
            return false;
        }
        let now = self.secs(now);
        let Some(parsed) = message::parse(answer) else {
            return false;
        };
        let secure = verdict.state == SecurityState::Secure;
        let learned = if secure {
            self.learn_secure(&parsed, now)
        } else {
            self.learn_cut(&parsed, origin, now)
        };
        let Some(learned) = learned.filter(|learned| !learned.is_empty()) else {
            return false;
        };
        let apex = learned.apex;
        // The delegation the answer carried, built before the lock is taken.
        let shown =
            store::delegation_of(&apex, &parsed.authority, &parsed.additional, now, carried);
        // Negative as the resolver judges it when it composes the delegation: an RCODE or
        // an SOA (a NODATA at the end of a CNAME chain as well).
        let negative =
            parsed.rcode != 0 || parsed.authority.iter().any(|rr| rr.rtype == types::SOA);
        // The answer's records live until the first of them expires.
        let lives = parsed
            .answer
            .iter()
            .chain(&parsed.authority)
            .map(|rr| rr.ttl)
            .min()
            .map_or(now, |ttl| now.saturating_add(ttl));
        let mut buf = [0u8; ZONE_KEY_MAX];
        let key: Box<[u8]> = zone_key(view, &apex, &mut buf).into();
        let mut guard = self.store.write().unwrap_or_else(PoisonError::into_inner);
        let store = &mut *guard;
        let entry = store
            .zones
            .entry(key)
            .or_insert_with(|| Zone::new(&apex, secure));
        let before = if entry.secure == secure {
            entry.count()
        } else if entry.secure {
            // An answer that is not secure never displaces what secure answers proved; the
            // secure records go when they expire or are flushed.
            return false;
        } else {
            // The zone is signed now (a negative trust anchor went): start over.
            let count = entry.count();
            *entry = Zone::new(&apex, secure);
            store.records = store.records.saturating_sub(count);
            0
        };
        if learned.soa.is_some() {
            entry.soa = learned.soa;
        }
        for record in learned.nsec {
            if let Some(key) = order::OrderKey::of(&record.set.owner) {
                entry.nsec.insert(key.as_bytes().into(), record);
            }
        }
        if let Some((salt, iterations)) = learned.params {
            let chain = entry.nsec3.get_or_insert_with(Chain3::default);
            if chain.salt != salt || chain.iterations != iterations {
                *chain = Chain3 {
                    salt,
                    iterations,
                    records: std::collections::BTreeMap::new(),
                };
            }
            for record in learned.nsec3 {
                let label = name::Labels::new(&record.set.owner)
                    .next()
                    .unwrap_or_default();
                if let Some(hash) = base32hex_decode(label) {
                    chain.records.insert(hash, record);
                }
            }
        }
        for (rtype, set) in learned.wildcards {
            let mut buf = [0u8; order::NAME_MAX + 2];
            let key: Box<[u8]> = wildcard_key(&set.owner, rtype, &mut buf).into();
            entry.wildcards.insert(key, set);
        }
        if let Some((denied, expires)) = learned.cut {
            entry.cuts.insert(
                denied.into_boxed_slice(),
                Cut {
                    expires,
                    used: now.into(),
                },
            );
        }
        if origin == Origin::Recursion {
            entry.from_recursion = true;
        }
        entry.learn_delegation(shown, carried, negative, lives);
        let after = entry.count();
        store.records = (store.records + after).saturating_sub(before);
        self.trim(store);
        true
    }
}

impl DenialCache for Denials {
    fn answer(
        &self,
        view: Option<ViewId>,
        qname: &[u8],
        qtype: u16,
        client: &Client<'_>,
        now: Instant,
        out: &mut Vec<u8>,
    ) -> Option<DenialHit> {
        self.answer_carrying(view, qname, qtype, client, now, out, false)
    }

    fn insert(
        &self,
        view: Option<ViewId>,
        answer: &[u8],
        verdict: &Verdict,
        origin: Origin,
        now: Instant,
    ) -> bool {
        self.insert_carried(view, answer, verdict, origin, now, false)
    }

    fn flush(&self, suffix: Option<&[u8]>) -> usize {
        let mut store = self.store.write().unwrap_or_else(PoisonError::into_inner);
        let Some(suffix) = suffix else {
            let removed = store.records;
            *store = Store::default();
            return removed;
        };
        let mut removed = 0;
        store.zones.retain(|key, zone| {
            if name::is_within(apex_of(key), suffix) {
                removed += zone.count();
                return false;
            }
            removed += zone.retain(|owner, _, _| !name::is_within(owner, suffix));
            zone.count() > 0
        });
        store.records = store.records.saturating_sub(removed);
        removed
    }

    fn len(&self) -> usize {
        self.store
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .records
    }
}

#[cfg(test)]
mod tests;
