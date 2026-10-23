//! What the denial cache holds per zone and how a name is looked up in it (the worker:
//! nothing here allocates on the lookup side; the building side runs on the runtime).

use std::{
    collections::{BTreeMap, HashMap},
    ops::Bound,
    sync::atomic::{AtomicU32, Ordering},
};

use super::order::{
    NAME_MAX, OrderKey, TYPE_CNAME, TYPE_DNAME, common_labels, has_type, is_delegation, wildcard_of,
};
use crate::{
    dnssec::chain::{HASH_LEN, nsec3_hash},
    name,
    recurse::message::Rr,
    recursion::denial::DenialKind,
};

/// The most NSEC3 hashes one lookup computes: the apex, the names from the apex down to
/// the closest encloser and the next closer name, and the wildcard.
pub const MAX_HASHES: usize = 8;

/// One RRset as the synthesis writes it: the owner once, then per record its type, class,
/// original TTL, data length and data, the signatures last.
#[derive(Debug)]
pub struct Set {
    /// The owner, lowercase wire form.
    pub owner: Box<[u8]>,
    /// The records.
    pub data: Box<[u8]>,
    /// The records before the signatures.
    pub plain: u16,
    /// The signatures.
    pub sigs: u16,
    /// Where the signatures start in `data`.
    pub sig_at: usize,
    /// When it expires, in the cache's seconds.
    pub expires: u32,
    /// When it was used last, in the cache's seconds.
    pub used: AtomicU32,
}

impl Set {
    /// The set of `records` (one owner and type) with their signatures `sigs`, stored at
    /// `now` (the cache's seconds; `unix` the wall clock): it lives for the smallest TTL,
    /// never past an original TTL or a signature's expiration (RFC 4035 section 4.5).
    /// `None` when it is empty, a signature expired or nothing is left of its lifetime.
    pub fn build(owner: &[u8], records: &[&Rr], sigs: &[&Rr], now: u32, unix: u32) -> Option<Self> {
        if records.is_empty() {
            return None;
        }
        let mut ttl = u32::MAX;
        let mut data = Vec::new();
        let push = |data: &mut Vec<u8>, rr: &Rr| -> Option<()> {
            data.extend_from_slice(&rr.rtype.to_be_bytes());
            data.extend_from_slice(&rr.class.to_be_bytes());
            data.extend_from_slice(&rr.ttl.to_be_bytes());
            data.extend_from_slice(&u16::try_from(rr.data.len()).ok()?.to_be_bytes());
            data.extend_from_slice(&rr.data);
            Some(())
        };
        for rr in records {
            ttl = ttl.min(rr.ttl);
            push(&mut data, rr)?;
        }
        let sig_at = data.len();
        for sig in sigs {
            ttl = ttl.min(sig.ttl);
            if sig.data.len() >= 18 {
                let original =
                    u32::from_be_bytes([sig.data[4], sig.data[5], sig.data[6], sig.data[7]]);
                let expiration =
                    u32::from_be_bytes([sig.data[8], sig.data[9], sig.data[10], sig.data[11]]);
                // Serial number arithmetic (RFC 1982): past the expiration the left time
                // wraps above half the range.
                let left = expiration.wrapping_sub(unix);
                if left > i32::MAX.unsigned_abs() {
                    return None;
                }
                ttl = ttl.min(original).min(left);
            }
            push(&mut data, sig)?;
        }
        if ttl == 0 {
            return None;
        }
        Some(Self {
            owner: owner.into(),
            data: data.into_boxed_slice(),
            plain: u16::try_from(records.len()).ok()?,
            sigs: u16::try_from(sigs.len()).ok()?,
            sig_at,
            expires: now.saturating_add(ttl),
            used: AtomicU32::new(now),
        })
    }

    /// Whether it is still alive at `now`.
    pub fn fresh(&self, now: u32) -> bool {
        self.expires > now
    }

    /// The seconds left at `now`.
    pub fn left(&self, now: u32) -> u32 {
        self.expires.saturating_sub(now)
    }

    /// Marks it used at `now`.
    pub fn touch(&self, now: u32) {
        self.used.store(now, Ordering::Relaxed);
    }

    fn used(&self) -> u32 {
        self.used.load(Ordering::Relaxed)
    }

    /// The data of the first record.
    pub fn first_rdata(&self) -> &[u8] {
        let len = usize::from(u16::from_be_bytes([self.data[8], self.data[9]]));
        self.data.get(10..10 + len).unwrap_or_default()
    }

    /// The SOA's MINIMUM, when this is an SOA set.
    pub fn soa_minimum(&self) -> Option<u32> {
        let rdata = self.first_rdata();
        let at = rdata.len().checked_sub(4)?;
        (rdata.len() >= 22)
            .then(|| u32::from_be_bytes([rdata[at], rdata[at + 1], rdata[at + 2], rdata[at + 3]]))
    }
}

/// An NSEC record: its set, the order key and the wire form of the next name, its types.
#[derive(Debug)]
pub struct Nsec {
    /// The record and its signatures.
    pub set: Set,
    /// The next owner's order key.
    pub next: Box<[u8]>,
    /// The next owner, wire form.
    pub next_name: Box<[u8]>,
    /// The type bitmap.
    pub bitmap: Box<[u8]>,
}

impl Nsec {
    /// The NSEC record of `set`; `None` when its data does not parse.
    pub fn of(set: Set) -> Option<Self> {
        let rdata = set.first_rdata();
        let end = crate::wire::skip_name(rdata, 0)?;
        let mut next_name = crate::name::NameBuf::from_wire(&rdata[..end])
            .ok()?
            .as_wire()
            .to_vec();
        next_name.make_ascii_lowercase();
        let next = OrderKey::of(&next_name)?;
        Some(Self {
            next: next.as_bytes().into(),
            next_name: next_name.into_boxed_slice(),
            bitmap: rdata[end..].into(),
            set,
        })
    }
}

/// An NSEC3 record: its set, the next hash, the opt-out flag and its types.
#[derive(Debug)]
pub struct Nsec3 {
    /// The record and its signatures.
    pub set: Set,
    /// The next hashed owner.
    pub next: [u8; HASH_LEN],
    /// The opt-out flag.
    pub opt_out: bool,
    /// The type bitmap.
    pub bitmap: Box<[u8]>,
}

/// The parameters of an NSEC3 record's data: the flags, the iterations, the salt, and
/// where the next hash starts.
pub fn nsec3_params(rdata: &[u8]) -> Option<(u8, u16, &[u8], usize)> {
    let (&algorithm, rest) = rdata.split_first()?;
    if algorithm != 1 || rest.len() < 4 {
        return None;
    }
    let flags = rest[0];
    let iterations = u16::from_be_bytes([rest[1], rest[2]]);
    let salt_len = usize::from(rest[3]);
    let salt = rdata.get(5..5 + salt_len)?;
    Some((flags, iterations, salt, 5 + salt_len))
}

impl Nsec3 {
    /// The NSEC3 record of `set`; `None` when its data does not parse.
    pub fn of(set: Set) -> Option<Self> {
        let rdata = set.first_rdata();
        let (flags, _, _, at) = nsec3_params(rdata)?;
        let hash_len = usize::from(*rdata.get(at)?);
        if hash_len != HASH_LEN {
            return None;
        }
        let next = <[u8; HASH_LEN]>::try_from(rdata.get(at + 1..at + 1 + HASH_LEN)?).ok()?;
        let bitmap = rdata[at + 1 + HASH_LEN..].into();
        Some(Self {
            next,
            opt_out: flags & 1 == 1,
            bitmap,
            set,
        })
    }
}

/// A zone's NSEC3 chain under one set of parameters.
#[derive(Debug, Default)]
pub struct Chain3 {
    /// The salt.
    pub salt: Box<[u8]>,
    /// The iterations.
    pub iterations: u16,
    /// The records by hashed owner.
    pub records: BTreeMap<[u8; HASH_LEN], Nsec3>,
}

impl Chain3 {
    fn exact(&self, hash: &[u8; HASH_LEN], now: u32) -> Option<&Nsec3> {
        self.records
            .get(hash)
            .filter(|record| record.set.fresh(now))
    }

    fn cover(&self, hash: &[u8; HASH_LEN], now: u32) -> Option<&Nsec3> {
        let (owner, record) = self
            .records
            .range(..*hash)
            .next_back()
            .or_else(|| self.records.iter().next_back())?;
        let covers = if owner < &record.next {
            owner < hash && hash < &record.next
        } else {
            // The last record of the chain: its next is the first.
            hash > owner || hash < &record.next
        };
        (covers && record.set.fresh(now)).then_some(record)
    }
}

/// A name known not to exist in an unsigned zone (RFC 8020).
#[derive(Debug)]
pub struct Cut {
    /// When it expires, in the cache's seconds.
    pub expires: u32,
    /// When it was used last.
    pub used: AtomicU32,
}

/// What the cache holds for one zone.
#[derive(Debug, Default)]
pub struct Zone {
    /// The apex, lowercase wire form.
    pub apex: Box<[u8]>,
    /// Whether its records came from secure answers (NSEC, NSEC3, wildcards) or from
    /// insecure ones (the names of RFC 8020).
    pub secure: bool,
    /// The SOA and its signatures.
    pub soa: Option<Set>,
    /// The NSEC records by the order key of their owner.
    pub nsec: BTreeMap<Box<[u8]>, Nsec>,
    /// The NSEC3 chain.
    pub nsec3: Option<Chain3>,
    /// The wildcard RRsets an expansion showed: keyed by the type and the wildcard owner.
    pub wildcards: HashMap<Box<[u8]>, Set>,
    /// The names of RFC 8020, wire form.
    pub cuts: HashMap<Box<[u8]>, Cut>,
}

/// The key of a wildcard RRset: the type, then the owner.
pub fn wildcard_key<'a>(owner: &[u8], rtype: u16, buf: &'a mut [u8; NAME_MAX + 2]) -> &'a [u8] {
    let len = (owner.len() + 2).min(buf.len());
    buf[..2].copy_from_slice(&rtype.to_be_bytes());
    buf[2..len].copy_from_slice(&owner[..len - 2]);
    &buf[..len]
}

/// What a lookup found: what to write and what it proves.
#[derive(Debug)]
pub struct Synth<'a> {
    /// What it proves.
    pub kind: DenialKind,
    /// The RCODE.
    pub rcode: u8,
    /// Whether the records are secure (AD) or from an unsigned zone.
    pub secure: bool,
    /// The SOA of a negative answer.
    pub soa: Option<&'a Set>,
    /// The wildcard RRset of a wildcard answer.
    pub answer: Option<&'a Set>,
    /// The NSEC or NSEC3 records of the proof, each once.
    pub proofs: [Option<&'a Set>; 3],
}

impl<'a> Synth<'a> {
    fn new(kind: DenialKind, soa: Option<&'a Set>, proofs: &[&'a Set]) -> Self {
        let mut unique: [Option<&'a Set>; 3] = [None; 3];
        let mut count = 0;
        for set in proofs {
            if count < unique.len()
                && !unique[..count]
                    .iter()
                    .flatten()
                    .any(|seen| std::ptr::eq(*seen, *set))
            {
                unique[count] = Some(set);
                count += 1;
            }
        }
        Self {
            kind,
            rcode: u8::from(kind == DenialKind::Nxdomain || kind == DenialKind::NxdomainCut) * 3,
            secure: kind != DenialKind::NxdomainCut,
            soa,
            answer: None,
            proofs: unique,
        }
    }

    /// Every set it writes.
    pub fn sets(&self) -> impl Iterator<Item = &'a Set> + '_ {
        self.soa
            .into_iter()
            .chain(self.answer)
            .chain(self.proofs.iter().flatten().copied())
    }
}

impl Zone {
    /// An empty zone at `apex`.
    pub fn new(apex: &[u8], secure: bool) -> Self {
        Self {
            apex: apex.into(),
            secure,
            ..Self::default()
        }
    }

    /// The records it holds, as the bound counts them.
    pub fn count(&self) -> usize {
        self.nsec.len()
            + self.nsec3.as_ref().map_or(0, |chain| chain.records.len())
            + self.wildcards.len()
            + self.cuts.len()
    }

    /// The answer to `qname`/`qtype` this zone's records prove at `now`, if any.
    pub fn lookup(&self, qname: &[u8], qtype: u16, now: u32) -> Option<Synth<'_>> {
        // A negative answer needs the SOA; a wildcard answer does not.
        let soa = self.soa.as_ref().filter(|soa| soa.fresh(now));
        if !self.secure {
            return self.cut(qname, soa?, now);
        }
        let found = match &self.nsec3 {
            Some(chain) => self
                .nsec3_lookup(chain, soa, qname, qtype, now)
                .or_else(|| self.nsec_lookup(soa, qname, qtype, now)),
            None => self.nsec_lookup(soa, qname, qtype, now),
        }?;
        (found.kind == DenialKind::Wildcard || found.soa.is_some()).then_some(found)
    }

    /// RFC 8020: the name or an ancestor below the apex is a cached NXDOMAIN.
    fn cut<'a>(&'a self, qname: &[u8], soa: &'a Set, now: u32) -> Option<Synth<'a>> {
        let below = name::label_count(qname).checked_sub(name::label_count(&self.apex))?;
        (0..below).find_map(|skip| {
            let cut = self
                .cuts
                .get(name::suffix(qname, skip))
                .filter(|cut| cut.expires > now)?;
            cut.used.store(now, Ordering::Relaxed);
            Some(Synth::new(DenialKind::NxdomainCut, Some(soa), &[]))
        })
    }

    /// The NSEC record at or before `key` in canonical order, with its owner's key.
    fn nsec_before(&self, key: &[u8], now: u32) -> Option<(&[u8], &Nsec)> {
        let (owner, record) = self
            .nsec
            .range::<[u8], _>((Bound::Unbounded, Bound::Included(key)))
            .next_back()?;
        record.set.fresh(now).then_some((&**owner, record))
    }

    /// Whether `record` at `owner` covers `key` (strictly between its owner and its next).
    fn covers(owner: &[u8], record: &Nsec, key: &[u8]) -> bool {
        owner < key && (key < &*record.next || record.next.as_ref() <= owner)
    }

    fn wildcard(&self, owner: &[u8], qtype: u16, now: u32) -> Option<&Set> {
        let mut buf = [0u8; NAME_MAX + 2];
        self.wildcards
            .get(wildcard_key(owner, qtype, &mut buf))
            .filter(|set| set.fresh(now))
    }

    fn nsec_lookup<'a>(
        &'a self,
        soa: Option<&'a Set>,
        qname: &[u8],
        qtype: u16,
        now: u32,
    ) -> Option<Synth<'a>> {
        let key = OrderKey::of(qname)?;
        let (owner, found) = self.nsec_before(key.as_bytes(), now)?;
        if owner == key.as_bytes() {
            // The name exists: NODATA when the type is not there (RFC 4035 section 3.1.3.1).
            if has_type(&found.bitmap, qtype)
                || has_type(&found.bitmap, TYPE_CNAME)
                || is_delegation(&found.bitmap)
            {
                return None;
            }
            return Some(Synth::new(DenialKind::Nodata, soa, &[&found.set]));
        }
        if !Self::covers(owner, found, key.as_bytes()) {
            return None;
        }
        // An ancestor that delegates or redirects: its record proves nothing below it.
        if name::is_within(qname, &found.set.owner)
            && (is_delegation(&found.bitmap) || has_type(&found.bitmap, TYPE_DNAME))
        {
            return None;
        }
        // The next name below the name: an empty non-terminal, which exists without data.
        if name::is_within(&found.next_name, qname) {
            return Some(Synth::new(DenialKind::Nodata, soa, &[&found.set]));
        }
        // The closest encloser and the wildcard at it (RFC 4035 section 5.4).
        let shared =
            common_labels(qname, &found.set.owner).max(common_labels(qname, &found.next_name));
        let labels = name::label_count(qname);
        if shared < name::label_count(&self.apex) {
            return None;
        }
        let encloser = name::suffix(qname, labels - shared);
        let mut buf = [0u8; NAME_MAX];
        let wildcard = wildcard_of(encloser, &mut buf)?;
        // A validated expansion of the wildcard proves it holds the type (RFC 4035 section
        // 5.3.4); the name itself does not exist, so the wildcard answers it.
        if let Some(answer) = self.wildcard(wildcard, qtype, now) {
            let mut synth = Synth::new(DenialKind::Wildcard, None, &[&found.set]);
            synth.answer = Some(answer);
            return Some(synth);
        }
        let wildcard_key = OrderKey::of(wildcard)?;
        let (wild_owner, wild) = self.nsec_before(wildcard_key.as_bytes(), now)?;
        if wild_owner == wildcard_key.as_bytes() {
            if has_type(&wild.bitmap, qtype) || has_type(&wild.bitmap, TYPE_CNAME) {
                return None;
            }
            return Some(Synth::new(
                DenialKind::Nodata,
                soa,
                &[&found.set, &wild.set],
            ));
        }
        if !Self::covers(wild_owner, wild, wildcard_key.as_bytes()) {
            return None;
        }
        Some(Synth::new(
            DenialKind::Nxdomain,
            soa,
            &[&found.set, &wild.set],
        ))
    }

    fn nsec3_lookup<'a>(
        &'a self,
        chain: &'a Chain3,
        soa: Option<&'a Set>,
        qname: &[u8],
        qtype: u16,
        now: u32,
    ) -> Option<Synth<'a>> {
        let labels = name::label_count(qname);
        let apex_labels = name::label_count(&self.apex);
        let mut spent = 0usize;
        let mut hash = |name: &[u8]| {
            spent += 1;
            (spent <= MAX_HASHES).then(|| nsec3_hash(name, &chain.salt, chain.iterations))
        };
        // Down from the apex: the deepest ancestor that exists is the closest encloser,
        // the name one label below it the next closer (RFC 5155 section 8.3).
        let mut encloser: Option<(&[u8], &Nsec3)> = None;
        let mut next_closer: Option<&Nsec3> = None;
        for depth in apex_labels + 1..=labels {
            let candidate = name::suffix(qname, labels - depth);
            let hashed = hash(candidate)?;
            if let Some(matched) = chain.exact(&hashed, now) {
                if is_delegation(&matched.bitmap)
                    || (depth < labels && has_type(&matched.bitmap, TYPE_DNAME))
                {
                    return None;
                }
                encloser = Some((candidate, matched));
                continue;
            }
            next_closer = Some(chain.cover(&hashed, now)?);
            break;
        }
        let (encloser_name, encloser_match) = match encloser {
            Some(found) => found,
            None => (&*self.apex, chain.exact(&hash(&self.apex)?, now)?),
        };
        let Some(cover) = next_closer else {
            // The name exists: NODATA when the type is not there.
            if has_type(&encloser_match.bitmap, qtype)
                || has_type(&encloser_match.bitmap, TYPE_CNAME)
            {
                return None;
            }
            return Some(Synth::new(DenialKind::Nodata, soa, &[&encloser_match.set]));
        };
        // An opt-out span may hide an insecure delegation (RFC 8198 section 4.3).
        if cover.opt_out {
            return None;
        }
        let mut buf = [0u8; NAME_MAX];
        let wildcard = wildcard_of(encloser_name, &mut buf)?;
        if let Some(answer) = self.wildcard(wildcard, qtype, now) {
            let mut synth = Synth::new(DenialKind::Wildcard, None, &[&cover.set]);
            synth.answer = Some(answer);
            return Some(synth);
        }
        let hashed = hash(wildcard)?;
        if let Some(wild) = chain.exact(&hashed, now) {
            if has_type(&wild.bitmap, qtype) || has_type(&wild.bitmap, TYPE_CNAME) {
                return None;
            }
            return Some(Synth::new(
                DenialKind::Nodata,
                soa,
                &[&encloser_match.set, &cover.set, &wild.set],
            ));
        }
        let wild = chain.cover(&hashed, now)?;
        Some(Synth::new(
            DenialKind::Nxdomain,
            soa,
            &[&encloser_match.set, &cover.set, &wild.set],
        ))
    }

    /// The `used` times of every record.
    pub fn used_times(&self, out: &mut Vec<u32>) {
        out.extend(self.nsec.values().map(|record| record.set.used()));
        if let Some(chain) = &self.nsec3 {
            out.extend(chain.records.values().map(|record| record.set.used()));
        }
        out.extend(self.wildcards.values().map(Set::used));
        out.extend(
            self.cuts
                .values()
                .map(|cut| cut.used.load(Ordering::Relaxed)),
        );
    }

    /// Drops the records `keep` refuses; returns how many went.
    pub fn retain(&mut self, mut keep: impl FnMut(&[u8], u32, u32) -> bool) -> usize {
        let before = self.count();
        self.nsec
            .retain(|_, record| keep(&record.set.owner, record.set.expires, record.set.used()));
        if let Some(chain) = &mut self.nsec3 {
            chain
                .records
                .retain(|_, record| keep(&record.set.owner, record.set.expires, record.set.used()));
        }
        self.wildcards
            .retain(|_, set| keep(&set.owner, set.expires, set.used()));
        self.cuts
            .retain(|owner, cut| keep(owner, cut.expires, cut.used.load(Ordering::Relaxed)));
        before - self.count()
    }
}
