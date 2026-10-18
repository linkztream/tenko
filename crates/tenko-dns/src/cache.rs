//! The resolver's cache (plan section 2.8, DNS-23): per node and per view, keyed by view,
//! name, type and class (and the DO and CD bits, so a client that asks without DNSSEC
//! never gets the signatures another client asked for), bounded by entries and by octets.
//!
//! - **Entries.** An entry is the upstream's answer in wire form without its OPT record:
//!   the header (id 0), the question in lower case and the records as received, with the
//!   positions of their TTLs. Positive answers live for the smallest TTL of their records,
//!   at most `max_ttl`; negative answers (NXDOMAIN and NODATA, RFC 2308) for the smaller of
//!   the SOA's TTL and its MINIMUM, at most `negative_ttl`; a negative answer without an
//!   SOA, a truncated answer and any other RCODE are not cached.
//! - **A hit** ([`Cache::answer`]) on the query path copies the entry into the answer
//!   buffer the worker owns: the client's id and question (its own case), RA, the client's
//!   RD and CD, AD clear (no validation in Phase 2), each TTL lowered by the entry's age, an
//!   OPT record with the server's size, the DO bit and the client's cookie when the client
//!   sent EDNS, and TC with no records when the answer does not fit the client's limit. The
//!   lookup hashes a key built on the stack and the shard's lock is held for the copy: a
//!   hit allocates nothing.
//! - **Bounds.** The entries are spread over shards by a hash of the key, each shard
//!   holding its share of `entries` and `max_bytes` and dropping its least recently used
//!   entry when a new one does not fit, so the cache never holds more than `entries`.
//! - **Serve-stale** (RFC 8767): an expired entry stays until `stale` has passed; the
//!   forwarder answers from it ([`Cache::answer_stale`]) with a TTL of [`STALE_TTL`] when
//!   the upstreams fail or are slower than the stale budget, and refreshes it.
//! - **Prefetch**: a hit on an entry that has been asked before and has less than a tenth
//!   of its lifetime left queues its key once ([`Cache::take_prefetch`]); the forwarder
//!   asks the upstream again before the entry expires.
//! - **Flush** ([`Cache::flush`]): everything, or the names at or below a suffix.

use std::{
    collections::HashMap,
    hash::{BuildHasher, Hasher},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tenko_core::dns::{ForwardRuleId, ViewId};

use crate::{
    metrics,
    name::{self, MAX_NAME_LEN},
    wire::{self, HEADER_LEN, OPTION_COOKIE, TYPE_OPT},
};

/// The TTL of a stale answer (RFC 8767 section 4).
pub const STALE_TTL: u32 = 30;

/// The longest key: a view tag and id, type, class, flags and the name.
pub const KEY_MAX: usize = 1 + 16 + 2 + 2 + 1 + MAX_NAME_LEN;

/// Prefetch requests waiting at most; a full queue drops the request (the entry is asked
/// again when it expires).
pub const PREFETCH_QUEUE: usize = 1_024;

/// Entries live at least this long before a prefetch: a TTL under it is not prefetched.
pub const PREFETCH_MIN_TTL: u32 = 10;

/// The type of an SOA record.
const TYPE_SOA: u16 = 6;

/// The type of a TSIG record.
const TYPE_TSIG: u16 = 250;

/// The settings of the cache (`[dns.cache]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheSettings {
    /// Entries at most (the Home profile's default is 10,000, the others' 100,000).
    pub entries: usize,
    /// Octets of keys, answers and bookkeeping at most (a lower bound of the memory).
    pub max_bytes: usize,
    /// How long an expired entry may still answer while the upstreams fail.
    pub stale: Duration,
    /// The longest lifetime of a positive entry, in seconds.
    pub max_ttl: u32,
    /// The longest lifetime of a negative entry, in seconds.
    pub negative_ttl: u32,
    /// Prefetch popular entries before they expire.
    pub prefetch: bool,
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            entries: 100_000,
            max_bytes: 128 * 1024 * 1024,
            stale: Duration::from_secs(86_400),
            max_ttl: 86_400,
            negative_ttl: 3_600,
            prefetch: true,
        }
    }
}

/// A cache key, built on the stack.
#[derive(Clone)]
pub struct CacheKey {
    buf: [u8; KEY_MAX],
    len: u16,
    name_at: u16,
}

impl std::fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheKey")
            .field("qtype", &self.qtype())
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl CacheKey {
    /// The key of a question in a view: `qname` in lowercase wire form.
    pub fn new(
        view: Option<ViewId>,
        qname: &[u8],
        qtype: u16,
        qclass: u16,
        dnssec_ok: bool,
        cd: bool,
    ) -> Self {
        let mut buf = [0u8; KEY_MAX];
        let mut at = 0;
        match view {
            Some(view) => {
                buf[0] = 1;
                buf[1..17].copy_from_slice(view.uuid().as_bytes());
                at = 17;
            }
            None => at += 1,
        }
        buf[at..at + 2].copy_from_slice(&qtype.to_be_bytes());
        buf[at + 2..at + 4].copy_from_slice(&qclass.to_be_bytes());
        buf[at + 4] = u8::from(dnssec_ok) | u8::from(cd) << 1;
        at += 5;
        let name = &qname[..qname.len().min(MAX_NAME_LEN)];
        buf[at..at + name.len()].copy_from_slice(name);
        Self {
            buf,
            len: u16::try_from(at + name.len()).unwrap_or(0),
            name_at: u16::try_from(at).unwrap_or(0),
        }
    }

    /// The key's octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }

    /// The name in lowercase wire form.
    pub fn qname(&self) -> &[u8] {
        &self.buf[usize::from(self.name_at)..usize::from(self.len)]
    }

    /// The type.
    pub fn qtype(&self) -> u16 {
        let at = usize::from(self.name_at) - 5;
        u16::from_be_bytes([self.buf[at], self.buf[at + 1]])
    }

    /// The class.
    pub fn qclass(&self) -> u16 {
        let at = usize::from(self.name_at) - 3;
        u16::from_be_bytes([self.buf[at], self.buf[at + 1]])
    }

    /// The DNSSEC OK bit the entry was asked with.
    pub fn dnssec_ok(&self) -> bool {
        self.buf[usize::from(self.name_at) - 1] & 1 != 0
    }

    /// The CD bit the entry was asked with.
    pub fn cd(&self) -> bool {
        self.buf[usize::from(self.name_at) - 1] & 2 != 0
    }

    /// The view.
    pub fn view(&self) -> Option<ViewId> {
        (self.buf[0] == 1).then(|| {
            let mut id = [0u8; 16];
            id.copy_from_slice(&self.buf[1..17]);
            ViewId::from_uuid(uuid::Uuid::from_bytes(id))
        })
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut buf = [0u8; KEY_MAX];
        buf[..bytes.len()].copy_from_slice(bytes);
        let name_at = if bytes.first() == Some(&1) { 22 } else { 6 };
        Self {
            buf,
            len: u16::try_from(bytes.len()).unwrap_or(0),
            name_at,
        }
    }
}

/// What the cache needs to know about the client to answer it.
#[derive(Debug, Clone, Copy)]
pub struct Client<'a> {
    /// The client's query.
    pub message: &'a [u8],
    /// The end of its question.
    pub question_end: usize,
    /// Its id.
    pub id: u16,
    /// Its RD bit.
    pub rd: bool,
    /// Its CD bit.
    pub cd: bool,
    /// Its EDNS, when it sent an OPT record.
    pub edns: Option<ClientEdns>,
    /// The largest answer it takes over its transport.
    pub max_len: usize,
}

/// The OPT record of an answer from the cache.
#[derive(Debug, Clone, Copy)]
pub struct ClientEdns {
    /// The server's EDNS UDP size (`edns.udp_size`).
    pub udp_size: u16,
    /// Echo the DO bit.
    pub dnssec_ok: bool,
    /// The cookie option's data: the client cookie and a fresh server cookie.
    pub cookie: Option<[u8; 24]>,
}

/// What a lookup found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    /// A fresh entry answered; the RCODE is in the answer.
    Fresh {
        /// The RCODE.
        rcode: u8,
    },
    /// An entry exists but expired (it may still answer stale).
    Expired,
    /// No entry.
    Miss,
}

struct Entry {
    wire: Box<[u8]>,
    ttls: Box<[u16]>,
    question_end: u16,
    stored: u32,
    ttl: u32,
    hits: u32,
    prefetching: bool,
    rule: Option<ForwardRuleId>,
}

impl Entry {
    fn age(&self, now: u32) -> u32 {
        now.saturating_sub(self.stored)
    }

    fn fresh(&self, now: u32) -> bool {
        self.age(now) < self.ttl
    }

    fn cost(&self, key_len: usize) -> usize {
        key_len * 2
            + self.wire.len()
            + self.ttls.len() * 2
            + std::mem::size_of::<Slot>()
            + std::mem::size_of::<(Box<[u8]>, u32)>()
            + 8
    }
}

const NIL: u32 = u32::MAX;

struct Slot {
    key: Box<[u8]>,
    entry: Option<Entry>,
    cost: usize,
    prev: u32,
    next: u32,
}

struct Shard {
    map: HashMap<Box<[u8]>, u32>,
    slots: Vec<Slot>,
    free: Vec<u32>,
    head: u32,
    tail: u32,
    bytes: usize,
    cap: usize,
    byte_cap: usize,
}

impl Shard {
    fn new(cap: usize, byte_cap: usize) -> Self {
        Self {
            map: HashMap::with_capacity(cap.min(1 << 16)),
            slots: Vec::new(),
            free: Vec::new(),
            head: NIL,
            tail: NIL,
            bytes: 0,
            cap,
            byte_cap,
        }
    }

    fn unlink(&mut self, index: u32) {
        let (prev, next) = {
            let slot = &self.slots[index as usize];
            (slot.prev, slot.next)
        };
        if prev == NIL {
            self.head = next;
        } else {
            self.slots[prev as usize].next = next;
        }
        if next == NIL {
            self.tail = prev;
        } else {
            self.slots[next as usize].prev = prev;
        }
    }

    fn push_front(&mut self, index: u32) {
        let head = self.head;
        {
            let slot = &mut self.slots[index as usize];
            slot.prev = NIL;
            slot.next = head;
        }
        if head == NIL {
            self.tail = index;
        } else {
            self.slots[head as usize].prev = index;
        }
        self.head = index;
    }

    fn touch(&mut self, index: u32) {
        if self.head != index {
            self.unlink(index);
            self.push_front(index);
        }
    }

    fn remove(&mut self, index: u32) -> usize {
        self.unlink(index);
        let slot = &mut self.slots[index as usize];
        let key = std::mem::take(&mut slot.key);
        slot.entry = None;
        let cost = slot.cost;
        slot.cost = 0;
        self.map.remove(&key);
        self.free.push(index);
        self.bytes -= cost;
        cost
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

/// The cache of one node; see the module documentation.
pub struct Cache {
    shards: Box<[Mutex<Shard>]>,
    hasher: std::collections::hash_map::RandomState,
    settings: CacheSettings,
    epoch: Instant,
    entries: AtomicUsize,
    bytes: AtomicUsize,
    prefetch: Mutex<Vec<CacheKey>>,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("settings", &self.settings)
            .field("entries", &self.len())
            .finish_non_exhaustive()
    }
}

/// What a flush removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flushed {
    /// Entries removed.
    pub entries: usize,
}

/// A copy of the cache's figures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheStats {
    /// Entries held.
    pub entries: usize,
    /// Octets accounted (keys, answers, bookkeeping).
    pub bytes: usize,
    /// The entry bound.
    pub max_entries: usize,
    /// The octet bound.
    pub max_bytes: usize,
}

impl Cache {
    /// An empty cache with these settings; `entries` and `max_bytes` are at least 1.
    pub fn new(settings: CacheSettings) -> Self {
        let entries = settings.entries.max(1);
        let max_bytes = settings.max_bytes.max(1);
        let count = (entries / 256).clamp(1, 64);
        let shards = (0..count)
            .map(|_| Mutex::new(Shard::new(entries / count, max_bytes / count)))
            .collect();
        Self {
            shards,
            hasher: std::collections::hash_map::RandomState::new(),
            settings: CacheSettings {
                entries,
                max_bytes,
                ..settings
            },
            epoch: Instant::now(),
            entries: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            prefetch: Mutex::new(Vec::with_capacity(PREFETCH_QUEUE)),
        }
    }

    /// The settings.
    pub fn settings(&self) -> &CacheSettings {
        &self.settings
    }

    /// Entries held.
    pub fn len(&self) -> usize {
        self.entries.load(Ordering::Relaxed)
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The figures.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.len(),
            bytes: self.bytes.load(Ordering::Relaxed),
            max_entries: self.shards.len() * (self.settings.entries / self.shards.len()),
            max_bytes: self.settings.max_bytes,
        }
    }

    fn secs(&self, now: Instant) -> u32 {
        u32::try_from(now.saturating_duration_since(self.epoch).as_secs()).unwrap_or(u32::MAX)
    }

    fn shard(&self, key: &[u8]) -> &Mutex<Shard> {
        let mut hasher = self.hasher.build_hasher();
        hasher.write(key);
        let hash = hasher.finish();
        let index = usize::try_from(hash % self.shards.len() as u64).unwrap_or(0);
        &self.shards[index]
    }

    fn lock(shard: &Mutex<Shard>) -> std::sync::MutexGuard<'_, Shard> {
        shard.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn account(&self, entries: isize, bytes: isize) {
        if entries >= 0 {
            self.entries
                .fetch_add(entries.unsigned_abs(), Ordering::Relaxed);
        } else {
            self.entries
                .fetch_sub(entries.unsigned_abs(), Ordering::Relaxed);
        }
        if bytes >= 0 {
            self.bytes
                .fetch_add(bytes.unsigned_abs(), Ordering::Relaxed);
        } else {
            self.bytes
                .fetch_sub(bytes.unsigned_abs(), Ordering::Relaxed);
        }
        #[allow(clippy::cast_precision_loss, reason = "an entry count for a gauge")]
        metrics::CACHE_ENTRY_GAUGE.set(self.len() as f64);
    }

    /// Answers `client` from a fresh entry of `key` into `out` (the query path; allocates
    /// nothing when `out` has room for 65,535 octets).
    pub fn answer(
        &self,
        key: &CacheKey,
        now: Instant,
        client: &Client<'_>,
        out: &mut Vec<u8>,
    ) -> Hit {
        let now = self.secs(now);
        let shard = self.shard(key.as_bytes());
        let mut shard = Self::lock(shard);
        let Some(&index) = shard.map.get(key.as_bytes()) else {
            return Hit::Miss;
        };
        let prefetch = {
            let Some(entry) = shard.slots[index as usize].entry.as_mut() else {
                return Hit::Miss;
            };
            if !entry.fresh(now) {
                return Hit::Expired;
            }
            let age = entry.age(now);
            let ttl = entry.ttl;
            let Some(rcode) = write(entry, client, out, |original| {
                original.min(ttl) - age.min(original.min(ttl))
            }) else {
                return Hit::Miss;
            };
            entry.hits = entry.hits.saturating_add(1);
            let prefetch = self.settings.prefetch
                && !entry.prefetching
                && entry.hits >= 1
                && entry.ttl >= PREFETCH_MIN_TTL
                && (entry.ttl - age) * 10 <= entry.ttl;
            if prefetch {
                entry.prefetching = true;
            }
            (rcode, prefetch)
        };
        shard.touch(index);
        drop(shard);
        if prefetch.1 {
            let mut queue = self.prefetch.lock().unwrap_or_else(PoisonError::into_inner);
            if queue.len() < queue.capacity() {
                queue.push(key.clone());
            }
        }
        Hit::Fresh { rcode: prefetch.0 }
    }

    /// Answers `client` from an entry of `key` that is fresh or within the stale window,
    /// every TTL [`STALE_TTL`] for an expired one (the forwarder, off the query path).
    /// Returns the RCODE, or `None` when there is no such entry.
    pub fn answer_stale(
        &self,
        key: &CacheKey,
        now: Instant,
        client: &Client<'_>,
        out: &mut Vec<u8>,
    ) -> Option<u8> {
        let now = self.secs(now);
        let stale = u32::try_from(self.settings.stale.as_secs()).unwrap_or(u32::MAX);
        let mut shard = Self::lock(self.shard(key.as_bytes()));
        let index = *shard.map.get(key.as_bytes())?;
        let entry = shard.slots[index as usize].entry.as_mut()?;
        let age = entry.age(now);
        if age >= entry.ttl.saturating_add(stale) {
            return None;
        }
        let ttl = entry.ttl;
        if entry.fresh(now) {
            write(entry, client, out, |original| {
                original.min(ttl) - age.min(original.min(ttl))
            })
        } else {
            write(entry, client, out, |_| STALE_TTL)
        }
    }

    /// Whether an entry of `key` could answer stale now.
    pub fn has_stale(&self, key: &CacheKey, now: Instant) -> bool {
        let now = self.secs(now);
        let stale = u32::try_from(self.settings.stale.as_secs()).unwrap_or(u32::MAX);
        let shard = Self::lock(self.shard(key.as_bytes()));
        shard
            .map
            .get(key.as_bytes())
            .and_then(|index| shard.slots[*index as usize].entry.as_ref())
            .is_some_and(|entry| entry.age(now) < entry.ttl.saturating_add(stale))
    }

    /// Stores the upstream answer `message` for `key`, asked through `rule`. Returns
    /// whether it was cached (see the module documentation for what is not).
    pub fn insert(
        &self,
        key: &CacheKey,
        message: &[u8],
        now: Instant,
        rule: Option<ForwardRuleId>,
    ) -> bool {
        let Some(entry) = self.entry(message, self.secs(now), rule) else {
            return false;
        };
        let cost = entry.cost(key.as_bytes().len());
        let mut shard = Self::lock(self.shard(key.as_bytes()));
        if cost > shard.byte_cap {
            return false;
        }
        let (mut entries, mut bytes) = (0isize, 0isize);
        if let Some(&index) = shard.map.get(key.as_bytes()) {
            bytes -= isize::try_from(shard.remove(index)).unwrap_or(0);
            entries -= 1;
        }
        while shard.tail != NIL && (shard.len() >= shard.cap || shard.bytes + cost > shard.byte_cap)
        {
            let tail = shard.tail;
            bytes -= isize::try_from(shard.remove(tail)).unwrap_or(0);
            entries -= 1;
        }
        let slot = Slot {
            key: key.as_bytes().into(),
            entry: Some(entry),
            cost,
            prev: NIL,
            next: NIL,
        };
        let index = if let Some(index) = shard.free.pop() {
            shard.slots[index as usize] = slot;
            index
        } else {
            shard.slots.push(slot);
            u32::try_from(shard.slots.len() - 1).unwrap_or(NIL)
        };
        shard.map.insert(key.as_bytes().into(), index);
        shard.push_front(index);
        shard.bytes += cost;
        drop(shard);
        self.account(entries + 1, bytes + isize::try_from(cost).unwrap_or(0));
        true
    }

    /// The entry an upstream answer makes, or `None` when it is not cached.
    fn entry(&self, message: &[u8], now: u32, rule: Option<ForwardRuleId>) -> Option<Entry> {
        let header = wire::parse_header(message)?;
        if !header.qr || header.tc || header.opcode != 0 || header.qdcount != 1 {
            return None;
        }
        let negative = match header.rcode {
            0 => header.ancount == 0,
            3 => true,
            _ => return None,
        };
        let question_end = wire::questions_end(message, 1)?;
        let total =
            usize::from(header.ancount) + usize::from(header.nscount) + usize::from(header.arcount);
        let authority =
            usize::from(header.ancount)..usize::from(header.ancount) + usize::from(header.nscount);
        let mut ttls = Vec::with_capacity(total);
        let mut pos = question_end;
        let mut end = message.len();
        let mut opt = false;
        let mut smallest = u32::MAX;
        let mut soa_ttl = None;
        for index in 0..total {
            let record = wire::read_record(message, pos)?;
            if record.rtype == TYPE_TSIG {
                return None;
            }
            if record.rtype == TYPE_OPT {
                // The OPT record goes; only as the last record, so no pointer moves.
                if index + 1 != total || opt {
                    return None;
                }
                opt = true;
                end = record.start;
                break;
            }
            smallest = smallest.min(record.ttl);
            if authority.contains(&index) && record.rtype == TYPE_SOA && record.rdlen >= 20 {
                let data = record.data(message);
                let minimum = u32::from_be_bytes([
                    data[data.len() - 4],
                    data[data.len() - 3],
                    data[data.len() - 2],
                    data[data.len() - 1],
                ]);
                soa_ttl = Some(record.ttl.min(minimum));
            }
            ttls.push(u16::try_from(record.fixed + 4).ok()?);
            pos = record.end();
        }
        if !opt {
            end = pos;
        }
        let ttl = if negative {
            soa_ttl?.min(self.settings.negative_ttl)
        } else {
            smallest.min(self.settings.max_ttl)
        };
        if ttl == 0 {
            return None;
        }
        let mut stored = message[..end].to_vec();
        stored[..2].copy_from_slice(&[0, 0]);
        if opt {
            let arcount = header.arcount - 1;
            stored[10..12].copy_from_slice(&arcount.to_be_bytes());
        }
        stored[HEADER_LEN..question_end - 4].make_ascii_lowercase();
        Some(Entry {
            wire: stored.into_boxed_slice(),
            ttls: ttls.into_boxed_slice(),
            question_end: u16::try_from(question_end).ok()?,
            stored: now,
            ttl,
            hits: 0,
            prefetching: false,
            rule,
        })
    }

    /// The keys queued for a prefetch since the last call, with the rule each entry was
    /// asked through.
    pub fn take_prefetch(&self) -> Vec<(CacheKey, Option<ForwardRuleId>)> {
        let keys: Vec<CacheKey> = {
            let mut queue = self.prefetch.lock().unwrap_or_else(PoisonError::into_inner);
            let mut taken = Vec::with_capacity(queue.len());
            taken.append(&mut queue);
            queue.reserve(PREFETCH_QUEUE);
            taken
        };
        keys.into_iter()
            .map(|key| {
                let rule = {
                    let shard = Self::lock(self.shard(key.as_bytes()));
                    shard
                        .map
                        .get(key.as_bytes())
                        .and_then(|index| shard.slots[*index as usize].entry.as_ref())
                        .and_then(|entry| entry.rule)
                };
                (key, rule)
            })
            .collect()
    }

    /// Lets an entry whose prefetch failed be queued again by a later hit.
    pub fn prefetch_failed(&self, key: &CacheKey) {
        let mut shard = Self::lock(self.shard(key.as_bytes()));
        if let Some(&index) = shard.map.get(key.as_bytes())
            && let Some(entry) = shard.slots[index as usize].entry.as_mut()
        {
            entry.prefetching = false;
        }
    }

    /// Removes every entry, or those whose name is at or below `suffix` (lowercase wire
    /// form).
    pub fn flush(&self, suffix: Option<&[u8]>) -> Flushed {
        let mut removed = 0usize;
        let mut freed = 0usize;
        for shard in &*self.shards {
            let mut shard = Self::lock(shard);
            let doomed: Vec<u32> = shard
                .map
                .iter()
                .filter(|(key, _)| {
                    suffix.is_none_or(|suffix| {
                        name::is_within(CacheKey::from_bytes(key).qname(), suffix)
                    })
                })
                .map(|(_, index)| *index)
                .collect();
            for index in doomed {
                freed += shard.remove(index);
                removed += 1;
            }
        }
        self.account(
            -isize::try_from(removed).unwrap_or(0),
            -isize::try_from(freed).unwrap_or(0),
        );
        Flushed { entries: removed }
    }

    /// Drops the entries whose stale window has passed (housekeeping; the bound holds
    /// without it).
    pub fn purge(&self, now: Instant) -> usize {
        let now = self.secs(now);
        let stale = u32::try_from(self.settings.stale.as_secs()).unwrap_or(u32::MAX);
        let mut removed = 0usize;
        let mut freed = 0usize;
        for shard in &*self.shards {
            let mut shard = Self::lock(shard);
            let doomed: Vec<u32> = shard
                .map
                .values()
                .copied()
                .filter(|index| {
                    shard.slots[*index as usize]
                        .entry
                        .as_ref()
                        .is_some_and(|entry| entry.age(now) >= entry.ttl.saturating_add(stale))
                })
                .collect();
            for index in doomed {
                freed += shard.remove(index);
                removed += 1;
            }
        }
        if removed > 0 {
            self.account(
                -isize::try_from(removed).unwrap_or(0),
                -isize::try_from(freed).unwrap_or(0),
            );
        }
        removed
    }
}

/// Writes the answer of `entry` for `client` into `out`, each TTL mapped by `ttl`. Returns
/// the RCODE, or `None` when the client's question does not have the entry's length.
fn write(
    entry: &Entry,
    client: &Client<'_>,
    out: &mut Vec<u8>,
    ttl: impl Fn(u32) -> u32,
) -> Option<u8> {
    assemble(
        &entry.wire,
        usize::from(entry.question_end),
        &entry.ttls,
        client,
        out,
        ttl,
        true,
    )
}

/// Relays an upstream answer `message` to `client` into `out`: the client's id, question
/// and flags as for a cache hit, the upstream's records with their TTLs, the upstream's OPT
/// record replaced by this node's. Returns the RCODE, or `None` when `message` does not
/// parse or its question differs from the client's in length.
pub fn relay(message: &[u8], client: &Client<'_>, out: &mut Vec<u8>) -> Option<u8> {
    let header = wire::parse_header(message)?;
    let question_end = wire::questions_end(message, 1)?;
    let total =
        usize::from(header.ancount) + usize::from(header.nscount) + usize::from(header.arcount);
    let mut pos = question_end;
    let mut end = None;
    for index in 0..total {
        let record = wire::read_record(message, pos)?;
        if record.rtype == TYPE_OPT && index + 1 == total {
            end = Some(record.start);
        }
        pos = record.end();
    }
    match end {
        Some(end) => {
            let mut trimmed = [0u8; HEADER_LEN];
            trimmed.copy_from_slice(&message[..HEADER_LEN]);
            let arcount = header.arcount - 1;
            trimmed[10..12].copy_from_slice(&arcount.to_be_bytes());
            assemble_parts(
                &trimmed,
                &message[HEADER_LEN..end],
                question_end,
                &[],
                client,
                out,
                |ttl| ttl,
                true,
            )
        }
        // No OPT record at the end: the records go as they are, without one of ours.
        None => assemble_parts(
            &message[..HEADER_LEN],
            &message[HEADER_LEN..pos],
            question_end,
            &[],
            client,
            out,
            |ttl| ttl,
            false,
        ),
    }
}

#[allow(clippy::too_many_arguments, reason = "the parts of one answer")]
fn assemble(
    stored: &[u8],
    question_end: usize,
    ttls: &[u16],
    client: &Client<'_>,
    out: &mut Vec<u8>,
    ttl: impl Fn(u32) -> u32,
    opt: bool,
) -> Option<u8> {
    assemble_parts(
        &stored[..HEADER_LEN],
        &stored[HEADER_LEN..],
        question_end,
        ttls,
        client,
        out,
        ttl,
        opt,
    )
}

/// Writes an answer from a header (`header`, 12 octets: the counts and the RCODE are used),
/// the octets after it (`body`: the question, replaced by the client's, and the records),
/// the TTL positions to map, and an OPT record when `opt` and the client sent EDNS.
#[allow(clippy::too_many_arguments, reason = "the parts of one answer")]
fn assemble_parts(
    header: &[u8],
    body: &[u8],
    question_end: usize,
    ttls: &[u16],
    client: &Client<'_>,
    out: &mut Vec<u8>,
    ttl: impl Fn(u32) -> u32,
    opt: bool,
) -> Option<u8> {
    if client.question_end != question_end
        || client.message.len() < question_end
        || body.len() < question_end - HEADER_LEN
    {
        return None;
    }
    let rcode = header[3] & 0x0f;
    out.clear();
    out.extend_from_slice(&client.id.to_be_bytes());
    out.push(0x80 | u8::from(client.rd));
    out.push(0x80 | if client.cd { 0x10 } else { 0 } | rcode);
    out.extend_from_slice(&header[4..HEADER_LEN]);
    out.extend_from_slice(&client.message[HEADER_LEN..question_end]);
    out.extend_from_slice(&body[question_end - HEADER_LEN..]);
    for offset in ttls {
        let at = usize::from(*offset);
        let original = u32::from_be_bytes([out[at], out[at + 1], out[at + 2], out[at + 3]]);
        out[at..at + 4].copy_from_slice(&ttl(original).to_be_bytes());
    }
    let edns = client.edns.filter(|_| opt);
    if let Some(edns) = &edns {
        push_opt(out, edns);
    }
    if out.len() > client.max_len {
        out.truncate(question_end);
        out[2] |= 0x02;
        out[6..12].copy_from_slice(&[0; 6]);
        if let Some(edns) = &edns {
            push_opt(out, edns);
        }
    }
    Some(rcode)
}

/// Appends the OPT record of an answer and counts it.
fn push_opt(out: &mut Vec<u8>, edns: &ClientEdns) {
    out.push(0);
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&edns.udp_size.to_be_bytes());
    out.extend_from_slice(&[0, 0, if edns.dnssec_ok { 0x80 } else { 0 }, 0]);
    match &edns.cookie {
        Some(cookie) => {
            out.extend_from_slice(&28u16.to_be_bytes());
            out.extend_from_slice(&OPTION_COOKIE.to_be_bytes());
            out.extend_from_slice(&24u16.to_be_bytes());
            out.extend_from_slice(cookie);
        }
        None => out.extend_from_slice(&[0, 0]),
    }
    let arcount = u16::from_be_bytes([out[10], out[11]]).saturating_add(1);
    out[10..12].copy_from_slice(&arcount.to_be_bytes());
}

// cache-browse: the listing of what the cache holds (`cache/list.rs`).
mod list;

pub use list::{CachePage, CachedEntry, DEFAULT_LIST, ListCursor, MAX_LIST, ViewFilter};
// cache-browse: end.

#[cfg(test)]
mod tests;
