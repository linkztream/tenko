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
//!   ones. An NXDOMAIN of an unsigned (or unvalidated) zone keeps the name it denies instead
//!   (RFC 8020: the last name of a CNAME chain, below the SOA's zone), with the SOA.
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
//!   nothing below it. DS, ANY and the DNSSEC and meta types are never synthesised. The
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

use tenko_core::dns::{DnsName, SecurityState, ViewId};

use self::store::{Chain3, Cut, Nsec, Nsec3, Set, Zone, nsec3_params, wildcard_key};
use crate::{
    cache::{Client, Verdict},
    dnssec::chain::base32hex_decode,
    name,
    recurse::message::{self, Rr, types},
    recursion::{
        ValidationCaps,
        denial::{DenialCache, DenialHit, DenialKind},
    },
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
}

impl Default for DenialSettings {
    fn default() -> Self {
        Self {
            aggressive: true,
            entries: 20_000,
            nsec3_iterations: ValidationCaps::DEFAULT.nsec3_insecure_above,
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
    synthesised: [AtomicU64; 4],
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

/// Whether the type is never synthesised: DS (the parent's), ANY, the DNSSEC types and the
/// meta types.
fn unsynthesised(qtype: u16) -> bool {
    matches!(
        qtype,
        0 | types::DS | types::RRSIG | types::NSEC | types::NSEC3 | 41
    ) || (128..=255).contains(&qtype)
}

/// The zone whose denial records `answer` carries: the owner of its SOA, else the signer of
/// its NSEC or NSEC3 records; for the forwarder to pass to [`DenialCache::insert`].
pub fn zone_of(answer: &[u8]) -> Option<DnsName> {
    let parsed = message::parse(answer)?;
    let wire = parsed
        .authority
        .iter()
        .find(|rr| rr.rtype == types::SOA)
        .map(|rr| rr.owner.clone())
        .or_else(|| {
            parsed
                .authority
                .iter()
                .find(|rr| matches!(rr.covered(), Some(types::NSEC | types::NSEC3)))
                .and_then(|rr| signer(rr).map(<[u8]>::to_ascii_lowercase))
        })?;
    DnsName::from_wire(&wire).ok().map(|(name, _)| name)
}

/// The signer's name of an RRSIG's data (uncompressed, as the parser leaves it).
fn signer(rrsig: &Rr) -> Option<&[u8]> {
    let data = rrsig.data.get(18..)?;
    let end = crate::wire::skip_name(data, 0)?;
    Some(&data[..end])
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
struct Learnt {
    soa: Option<Set>,
    nsec: Vec<Nsec>,
    nsec3: Vec<Nsec3>,
    params: Option<(Box<[u8]>, u16)>,
    wildcards: Vec<(u16, Set)>,
    cut: Option<(Vec<u8>, u32)>,
}

impl Learnt {
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
            synthesised: Default::default(),
        }
    }

    /// The settings.
    pub fn settings(&self) -> &DenialSettings {
        &self.settings
    }

    fn secs(&self, now: Instant) -> u32 {
        u32::try_from(now.saturating_duration_since(self.epoch).as_secs()).unwrap_or(u32::MAX)
    }

    /// Answers synthesised since the start, by kind in the order of [`DenialKind::ALL`].
    pub fn synthesised(&self) -> [u64; 4] {
        let mut out = [0; 4];
        for (slot, counter) in out.iter_mut().zip(&self.synthesised) {
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

    /// What `answer`, the validated answer of `zone` (`apex`), adds.
    fn learn(&self, apex: &[u8], answer: &[u8], verdict: &Verdict, now: u32) -> Option<Learnt> {
        let parsed = message::parse(answer)?;
        let unix = unix_now();
        let mut learnt = Learnt::default();
        let (soa, sigs) = rrset(&parsed.authority, apex, types::SOA);
        learnt.soa = Set::build(apex, &soa, &sigs, now, unix);
        if verdict.state == SecurityState::Secure {
            self.learn_secure(apex, &parsed, &mut learnt, now, unix);
        } else if parsed.rcode == 3 && learnt.soa.is_some() {
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
            if name::is_within(&denied, apex) && denied != apex {
                let soa = learnt.soa.as_ref()?;
                let ttl = soa.left(now).min(soa.soa_minimum().unwrap_or(u32::MAX));
                learnt.cut = Some((denied, now.saturating_add(ttl)));
            }
        }
        (!learnt.is_empty()).then_some(learnt)
    }

    fn learn_secure(
        &self,
        apex: &[u8],
        parsed: &message::Parsed,
        learnt: &mut Learnt,
        now: u32,
        unix: u32,
    ) {
        let mut owners: Vec<&[u8]> = Vec::new();
        for rr in parsed.answer.iter().chain(&parsed.authority) {
            if matches!(rr.rtype, types::NSEC | types::NSEC3)
                && name::is_within(&rr.owner, apex)
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
                if records.is_empty() || sigs.is_empty() {
                    continue;
                }
                let Some(set) = Set::build(owner, &records[..1], &sigs, now, unix) else {
                    continue;
                };
                if rtype == types::NSEC {
                    learnt.nsec.extend(Nsec::of(set));
                    continue;
                }
                // An NSEC3 owner is the hash's label right below the apex.
                if name::label_count(owner) != name::label_count(apex) + 1
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
                if learnt.params.as_ref().is_some_and(|known| *known != params) {
                    continue;
                }
                let label = name::Labels::new(owner).next().unwrap_or_default();
                if base32hex_decode(label).is_none() {
                    continue;
                }
                if let Some(record) = Nsec3::of(set) {
                    learnt.params = Some(params);
                    learnt.nsec3.push(record);
                }
            }
        }
        // The wildcard RRsets of an expansion: a signature with fewer labels than its owner
        // (RFC 4035 section 5.3.4).
        for sig in parsed.answer.iter().filter(|rr| rr.rtype == types::RRSIG) {
            let (Some(covered), Some(labels)) = (sig.covered(), sig_labels(sig)) else {
                continue;
            };
            let owner_labels = name::label_count(&sig.owner);
            if usize::from(labels) >= owner_labels || !name::is_within(&sig.owner, apex) {
                continue;
            }
            let encloser = name::suffix(&sig.owner, owner_labels - usize::from(labels));
            let mut buf = [0u8; order::NAME_MAX];
            let Some(wildcard) = order::wildcard_of(encloser, &mut buf) else {
                continue;
            };
            let (records, sigs) = rrset(&parsed.answer, &sig.owner, covered);
            if learnt
                .wildcards
                .iter()
                .any(|(rtype, set)| *rtype == covered && *set.owner == *wildcard)
            {
                continue;
            }
            if let Some(set) = Set::build(wildcard, &records, &sigs, now, unix) {
                learnt.wildcards.push((covered, set));
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
        if !self.settings.aggressive || unsynthesised(qtype) {
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
        let synth = zone.lookup(qname, qtype, now)?;
        let rcode = synth::write(&synth, client, now, out)?;
        let index = DenialKind::ALL
            .iter()
            .position(|kind| *kind == synth.kind)
            .unwrap_or(0);
        self.synthesised[index].fetch_add(1, Ordering::Relaxed);
        Some(DenialHit {
            kind: synth.kind,
            rcode,
        })
    }

    fn insert(
        &self,
        view: Option<ViewId>,
        zone: &DnsName,
        answer: &[u8],
        verdict: &Verdict,
        now: Instant,
    ) -> bool {
        if verdict.state == SecurityState::Bogus {
            return false;
        }
        let now = self.secs(now);
        let apex = zone.to_wire();
        let Some(learnt) = self.learn(&apex, answer, verdict, now) else {
            return false;
        };
        let secure = verdict.state == SecurityState::Secure;
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
        } else {
            // The zone changed sides (a negative trust anchor came or went): start over.
            let count = entry.count();
            *entry = Zone::new(&apex, secure);
            store.records = store.records.saturating_sub(count);
            0
        };
        if learnt.soa.is_some() {
            entry.soa = learnt.soa;
        }
        for record in learnt.nsec {
            if let Some(key) = order::OrderKey::of(&record.set.owner) {
                entry.nsec.insert(key.as_bytes().into(), record);
            }
        }
        if let Some((salt, iterations)) = learnt.params {
            let chain = entry.nsec3.get_or_insert_with(Chain3::default);
            if chain.salt != salt || chain.iterations != iterations {
                *chain = Chain3 {
                    salt,
                    iterations,
                    records: std::collections::BTreeMap::new(),
                };
            }
            for record in learnt.nsec3 {
                let label = name::Labels::new(&record.set.owner)
                    .next()
                    .unwrap_or_default();
                if let Some(hash) = base32hex_decode(label) {
                    chain.records.insert(hash, record);
                }
            }
        }
        for (rtype, set) in learnt.wildcards {
            let mut buf = [0u8; order::NAME_MAX + 2];
            let key: Box<[u8]> = wildcard_key(&set.owner, rtype, &mut buf).into();
            entry.wildcards.insert(key, set);
        }
        if let Some((denied, expires)) = learnt.cut {
            entry.cuts.insert(
                denied.into_boxed_slice(),
                Cut {
                    expires,
                    used: now.into(),
                },
            );
        }
        let after = entry.count();
        store.records = store.records + after - before.min(after);
        self.trim(store);
        true
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
