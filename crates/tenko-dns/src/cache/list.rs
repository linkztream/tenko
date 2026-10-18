//! The listing of the cache ([`Cache::list`]): what a node's cache holds, as `rndc dumpdb
//! -cache` and the cache view of Windows DNS show it, a page at a time in the canonical
//! order of the names (RFC 4034 section 6.1), then by type, view and the DO and CD bits.
//!
//! A page is chosen in two steps, so that the query path never waits longer than for a
//! flush:
//!
//! 1. Each shard is locked in turn, one at a time, for one pass over its map, as the flush
//!    does: an entry within its stale window, in the view asked for, at or below the suffix
//!    and after the cursor is compared with the largest key kept so far, and kept in a heap
//!    of `limit + 1` keys reserved before the first lock (the pass allocates nothing).
//! 2. Each chosen entry is looked up and copied under its shard's lock, one lookup each,
//!    and its records are decoded with no lock held. An entry that went between the steps
//!    is left out of the page; the cursor still moves past it.
//!
//! Every page is a fresh pass, so an entry stored while the pages are read appears when it
//! sorts after the cursor, and one that went is not repeated.

use std::{cmp::Ordering, collections::BinaryHeap, time::Instant};

use tenko_core::dns::{DnsName, RecordData, Rtype, ViewId};

use super::{Cache, CacheKey, KEY_MAX};
use crate::{
    name::{self, NameBuf},
    tree::canonical_cmp,
    wire::{self, RawRecord},
};

/// Entries a page holds when the caller does not say.
pub const DEFAULT_LIST: usize = 200;

/// Entries a page holds at most.
pub const MAX_LIST: usize = 1_000;

/// The views a listing covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViewFilter {
    /// Every view.
    #[default]
    All,
    /// The entries asked outside any view.
    Default,
    /// One view.
    View(ViewId),
}

impl ViewFilter {
    /// Parses `default` or a view's identifier.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "" => Some(Self::All),
            "default" => Some(Self::Default),
            other => other.parse::<ViewId>().ok().map(Self::View),
        }
    }

    fn admits(self, key: &[u8]) -> bool {
        match self {
            Self::All => true,
            Self::Default => key.first() == Some(&0),
            Self::View(view) => {
                key.first() == Some(&1) && key.get(1..17) == Some(view.uuid().as_bytes())
            }
        }
    }
}

/// Where the next page starts: the key of the last entry of a page, in hexadecimal.
#[derive(Clone)]
pub struct ListCursor(CacheKey);

impl std::fmt::Debug for ListCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ListCursor").field(&self.0).finish()
    }
}

impl PartialEq for ListCursor {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Eq for ListCursor {}

impl ListCursor {
    /// Parses a cursor a page gave out; `None` when it is not one.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.as_bytes();
        if !text.len().is_multiple_of(2) || text.len() / 2 > KEY_MAX {
            return None;
        }
        let mut bytes = Vec::with_capacity(text.len() / 2);
        for [high, low] in text.as_chunks::<2>().0 {
            let high = char::from(*high).to_digit(16)?;
            let low = char::from(*low).to_digit(16)?;
            bytes.push(u8::try_from(high << 4 | low).ok()?);
        }
        let name_at = match bytes.first()? {
            0 => 6,
            1 => 22,
            _ => return None,
        };
        // A lowercase, uncompressed name that ends the key exactly.
        let name = bytes.get(name_at..)?;
        let mut buf = NameBuf::default();
        if wire::read_name(name, 0, &mut buf) != Some(name.len()) || buf.as_wire() != name {
            return None;
        }
        Some(Self(CacheKey::from_bytes(&bytes)))
    }

    /// The cursor's text.
    pub fn encode(&self) -> String {
        use std::fmt::Write as _;
        let bytes = self.0.as_bytes();
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

/// One entry of a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedEntry {
    /// The name asked.
    pub name: DnsName,
    /// The type asked.
    pub rtype: Rtype,
    /// The class asked.
    pub class: u16,
    /// The view the entry belongs to; `None` outside any view.
    pub view: Option<ViewId>,
    /// Asked with the DO bit.
    pub dnssec_ok: bool,
    /// Asked with the CD bit.
    pub checking_disabled: bool,
    /// The RCODE of the answer (0 NOERROR, 3 NXDOMAIN).
    pub rcode: u8,
    /// Seconds the entry stays fresh; 0 once it is stale.
    pub ttl: u32,
    /// Expired, but within the stale window: it answers only when the upstreams fail.
    pub stale: bool,
    /// Answers from the entry since it was stored.
    pub hits: u32,
    /// The records of the answer section, in the order received (empty for a negative
    /// answer); a record whose data does not decode is left out.
    pub records: Vec<RecordData>,
}

/// A page of a listing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CachePage {
    /// The entries, in the listing's order.
    pub entries: Vec<CachedEntry>,
    /// Where the next page starts, when there is one.
    pub next: Option<ListCursor>,
}

/// The order of a listing between two keys: the name in canonical order, then the type,
/// the view (none first), the DO and CD bits and the class.
fn order(a: &[u8], b: &[u8]) -> Ordering {
    let (view_a, rest_a) = split(a);
    let (view_b, rest_b) = split(b);
    canonical_cmp(&rest_a[5..], &rest_b[5..])
        .then_with(|| rest_a[..2].cmp(&rest_b[..2]))
        .then_with(|| view_a.cmp(view_b))
        .then_with(|| rest_a[4].cmp(&rest_b[4]))
        .then_with(|| rest_a[2..4].cmp(&rest_b[2..4]))
}

/// The view part of a key (empty for none) and the rest: type, class, flags, name.
fn split(key: &[u8]) -> (&[u8], &[u8]) {
    if key.first() == Some(&1) {
        (&key[1..17], &key[17..])
    } else {
        (&[], &key[1..])
    }
}

/// A key in the heap, ordered by [`order`].
struct Ordered(CacheKey);

impl PartialEq for Ordered {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Ordered {}

impl PartialOrd for Ordered {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ordered {
    fn cmp(&self, other: &Self) -> Ordering {
        order(self.0.as_bytes(), other.0.as_bytes())
    }
}

/// What step 2 copies of an entry under its shard's lock.
struct Copied {
    wire: Vec<u8>,
    question_end: usize,
    ttl: u32,
    stale: bool,
    hits: u32,
}

impl Cache {
    /// A page of the entries in `view` whose name is `suffix` or under it (lowercase wire
    /// form; every name when `None`), after `cursor`, at most `limit` (1 to [`MAX_LIST`]),
    /// as they stand at `now`. Entries past their stale window are not listed.
    pub fn list(
        &self,
        view: ViewFilter,
        suffix: Option<&[u8]>,
        limit: usize,
        cursor: Option<&ListCursor>,
        now: Instant,
    ) -> CachePage {
        let limit = limit.clamp(1, MAX_LIST);
        let now = self.secs(now);
        let stale = u32::try_from(self.settings.stale.as_secs()).unwrap_or(u32::MAX);
        let mut heap: BinaryHeap<Ordered> = BinaryHeap::with_capacity(limit + 1);
        for shard in &*self.shards {
            let shard = Self::lock(shard);
            for (key, index) in &shard.map {
                let admitted = view.admits(key)
                    && cursor.is_none_or(|cursor| order(key, cursor.0.as_bytes()).is_gt())
                    && suffix.is_none_or(|suffix| name::is_within(&split(key).1[5..], suffix))
                    && shard.slots[*index as usize]
                        .entry
                        .as_ref()
                        .is_some_and(|entry| entry.age(now) < entry.ttl.saturating_add(stale));
                if !admitted {
                    continue;
                }
                if heap.len() <= limit {
                    heap.push(Ordered(CacheKey::from_bytes(key)));
                } else if let Some(mut largest) = heap.peek_mut()
                    && order(key, largest.0.as_bytes()).is_lt()
                {
                    *largest = Ordered(CacheKey::from_bytes(key));
                }
            }
        }
        let mut chosen = heap.into_sorted_vec();
        let next = (chosen.len() > limit).then(|| ListCursor(chosen[limit - 1].0.clone()));
        chosen.truncate(limit);
        let entries = chosen
            .into_iter()
            .filter_map(|Ordered(key)| {
                let copied = self.copy(&key, now, stale)?;
                decode(&key, &copied)
            })
            .collect();
        CachePage { entries, next }
    }

    /// Copies the entry of `key` under its shard's lock, when it is still listed.
    fn copy(&self, key: &CacheKey, now: u32, stale: u32) -> Option<Copied> {
        let shard = Self::lock(self.shard(key.as_bytes()));
        let index = *shard.map.get(key.as_bytes())?;
        let entry = shard.slots[index as usize].entry.as_ref()?;
        let age = entry.age(now);
        if age >= entry.ttl.saturating_add(stale) {
            return None;
        }
        Some(Copied {
            wire: entry.wire.to_vec(),
            question_end: usize::from(entry.question_end),
            ttl: entry.ttl.saturating_sub(age),
            stale: !entry.fresh(now),
            hits: entry.hits,
        })
    }
}

/// The entry of a listing from the copy of a stored answer.
fn decode(key: &CacheKey, copied: &Copied) -> Option<CachedEntry> {
    let (name, _) = DnsName::from_wire(key.qname()).ok()?;
    let header = wire::parse_header(&copied.wire)?;
    let mut records = Vec::with_capacity(usize::from(header.ancount));
    let mut pos = copied.question_end;
    for _ in 0..header.ancount {
        let Some(record) = wire::read_record(&copied.wire, pos) else {
            break;
        };
        if let Some(data) = record_data(&copied.wire, &record) {
            records.push(data);
        }
        pos = record.end();
    }
    Some(CachedEntry {
        name,
        rtype: Rtype(key.qtype()),
        class: key.qclass(),
        view: key.view(),
        dnssec_ok: key.dnssec_ok(),
        checking_disabled: key.cd(),
        rcode: copied.wire[3] & 0x0f,
        ttl: if copied.stale { 0 } else { copied.ttl },
        stale: copied.stale,
        hits: copied.hits,
        records,
    })
}

/// The typed data of a record of a stored answer, its names expanded: the types of RFC
/// 1035 whose names may be compressed (RFC 3597 section 4), and SRV, which some servers
/// compress although they should not.
fn record_data(message: &[u8], record: &RawRecord) -> Option<RecordData> {
    let rtype = Rtype(record.rtype);
    // The octets before the first name and the number of names.
    let (prefix, names) = match record.rtype {
        2 | 5 | 12 => (0, 1),
        6 => (0, 2),
        15 => (2, 1),
        33 => (6, 1),
        _ => return RecordData::from_wire(rtype, record.data(message)).ok(),
    };
    let end = record.end();
    let mut data = Vec::with_capacity(record.rdlen + 64);
    data.extend_from_slice(message.get(record.rdata..record.rdata + prefix)?);
    let mut pos = record.rdata + prefix;
    let mut buf = NameBuf::default();
    for _ in 0..names {
        pos = wire::read_name(message, pos, &mut buf)?;
        if pos > end {
            return None;
        }
        data.extend_from_slice(buf.as_wire());
    }
    data.extend_from_slice(message.get(pos..end)?);
    RecordData::from_wire(rtype, &data).ok()
}

#[cfg(test)]
mod tests;
