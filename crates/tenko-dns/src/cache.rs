//! The resolver's cache (plan section 2.8, DNS-23; recursion plan section 2.2): per node
//! and per view, keyed by view, name, type and class, bounded by entries and by octets.
//! The DO and CD bits are not part of the key (WP10.0): every query to an upstream or an
//! authority asks with DO, so one entry holds the answer with its signatures and its
//! validation state, and a hit renders it for the client's flags.
//!
//! - **Entries.** An entry is the upstream's answer in wire form without its OPT record:
//!   the header (id 0), the question in lower case and the records as received, with the
//!   positions of their TTLs, the positions of the DNSSEC records a client without DO does
//!   not get (`rrsig_offsets`: every RRSIG, NSEC and NSEC3 record except those of the type
//!   asked in the answer section), the [`SecurityState`] the validator gave it, the extended
//!   error of a bogus answer and the earliest signature expiry. Positive answers live for
//!   the smallest TTL of their records, at most `max_ttl` and never past the earliest
//!   signature expiry (RFC 4035 section 4.5); negative answers (NXDOMAIN and NODATA, RFC
//!   2308) for the smaller of the SOA's TTL and its MINIMUM, at most `negative_ttl`; the
//!   validator may cap a lifetime further (a bogus entry lives for the failure time of RFC
//!   9520). A negative answer without an SOA, a truncated answer and any other RCODE are
//!   not cached.
//! - **A hit** ([`Cache::answer`]) on the query path copies the entry into the answer
//!   buffer the worker owns, rendered by [`SecurityState::render`]: the client's id and
//!   question (its own case), RA, the client's RD and CD, AD for a secure entry when the
//!   client asked with AD or DO, the DNSSEC records only for a client with DO (the counts
//!   lowered), SERVFAIL with the stored extended error for a bogus entry unless the client
//!   set CD, each TTL lowered by the entry's age, an OPT record with the server's size, the
//!   DO bit, the client's cookie and the extended error when the client sent EDNS, and TC
//!   with no records when the answer does not fit the client's limit. The lookup hashes a
//!   key built on the stack and the shard's lock is held for the copy: a hit allocates
//!   nothing (`tests/alloc.rs` binds the secure, the plain and the bogus hit). An answer
//!   whose names point into its DNSSEC records (a compressor that reuses an NSEC owner)
//!   cannot lose them without breaking, so it goes to every client with them.
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
    time::{Duration, Instant, SystemTime},
};

use tenko_core::dns::{ClientFlags, ExtendedError, ForwardRuleId, SecurityState, ViewId};

use crate::{
    metrics,
    name::{self, MAX_NAME_LEN},
    wire::{self, HEADER_LEN, OPTION_COOKIE, OPTION_EXTENDED_ERROR, TYPE_OPT},
};

/// The TTL of a stale answer (RFC 8767 section 4).
pub const STALE_TTL: u32 = 30;

/// The longest key: a view tag and id, type, class and the name.
pub const KEY_MAX: usize = 1 + 16 + 2 + 2 + MAX_NAME_LEN;

/// Prefetch requests waiting at most; a full queue drops the request (the entry is asked
/// again when it expires).
pub const PREFETCH_QUEUE: usize = 1_024;

/// Entries live at least this long before a prefetch: a TTL under it is not prefetched.
pub const PREFETCH_MIN_TTL: u32 = 10;

/// The type of an SOA record.
const TYPE_SOA: u16 = 6;

/// The type of a TSIG record.
const TYPE_TSIG: u16 = 250;

/// The DNSSEC types a client without DO does not get (RFC 4035 section 3.2.1).
const TYPE_RRSIG: u16 = 46;
const TYPE_NSEC: u16 = 47;
const TYPE_NSEC3: u16 = 50;

/// The signature expiry of an entry without one.
const NO_EXPIRY: u32 = u32::MAX;

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
    /// The key of a question in a view: `qname` in lowercase wire form. The client's DO and
    /// CD bits are not part of it (recursion plan section 2.2).
    pub fn new(view: Option<ViewId>, qname: &[u8], qtype: u16, qclass: u16) -> Self {
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
        at += 4;
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

    /// The name in lowercase wire form of a key's octets ([`CacheKey::as_bytes`]).
    pub fn qname_of(key: &[u8]) -> &[u8] {
        let name_at = if key.first() == Some(&1) { 21 } else { 5 };
        key.get(name_at..).unwrap_or_default()
    }

    /// The name in lowercase wire form.
    pub fn qname(&self) -> &[u8] {
        &self.buf[usize::from(self.name_at)..usize::from(self.len)]
    }

    /// The type.
    pub fn qtype(&self) -> u16 {
        let at = usize::from(self.name_at) - 4;
        u16::from_be_bytes([self.buf[at], self.buf[at + 1]])
    }

    /// The class.
    pub fn qclass(&self) -> u16 {
        let at = usize::from(self.name_at) - 2;
        u16::from_be_bytes([self.buf[at], self.buf[at + 1]])
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
        let name_at = if bytes.first() == Some(&1) { 21 } else { 5 };
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
    /// Its AD bit (RFC 6840 section 5.7: a client that sets it wants AD back).
    pub ad: bool,
    /// Its EDNS, when it sent an OPT record.
    pub edns: Option<ClientEdns>,
    /// The largest answer it takes over its transport.
    pub max_len: usize,
}

impl Client<'_> {
    /// The flags that decide the rendering.
    pub fn flags(&self) -> ClientFlags {
        ClientFlags {
            dnssec_ok: self.edns.is_some_and(|edns| edns.dnssec_ok),
            ad: self.ad,
            cd: self.cd,
        }
    }
}

/// The OPT record of an answer from the cache.
#[derive(Debug, Clone, Copy)]
pub struct ClientEdns {
    /// The server's EDNS UDP size (`edns.udp_size`).
    pub udp_size: u16,
    /// The client's DO bit: echoed, and the DNSSEC records go to it.
    pub dnssec_ok: bool,
    /// The cookie option's data: the client cookie and a fresh server cookie.
    pub cookie: Option<[u8; 24]>,
}

/// What a lookup found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    /// A fresh entry answered; the RCODE is in the answer.
    Fresh {
        /// The RCODE (SERVFAIL for a bogus entry to a client without CD).
        rcode: u8,
        /// The entry's validation state.
        state: SecurityState,
    },
    /// An entry exists but expired (it may still answer stale).
    Expired,
    /// No entry.
    Miss,
}

/// What the validator says about an answer before it goes into the cache (WP10.2); the
/// forwarder's answers are [`Verdict::UNVALIDATED`] until then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// The validation state.
    pub state: SecurityState,
    /// The extended error a bogus answer is answered with (6 "DNSSEC Bogus" when absent).
    pub ede: Option<ExtendedError>,
    /// The earliest expiry of the signatures that made the answer secure: the entry lives
    /// no longer (RFC 4035 section 4.5).
    pub signature_expiry: Option<SystemTime>,
    /// A cap of the lifetime in seconds (a bogus answer lives for the failure time of RFC
    /// 9520).
    pub max_ttl: Option<u32>,
}

impl Verdict {
    /// An answer nobody validated (validation off, or a rule with `validate = false`).
    pub const UNVALIDATED: Self = Self {
        state: SecurityState::Unvalidated,
        ede: None,
        signature_expiry: None,
        max_ttl: None,
    };
}

impl Default for Verdict {
    fn default() -> Self {
        Self::UNVALIDATED
    }
}

/// A DNSSEC record of a stored answer that a client without DO does not get: its octets
/// and its section (0 answer, 1 authority, 2 additional).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Skip {
    start: u16,
    end: u16,
    section: u8,
}

impl Skip {
    fn contains(self, at: usize) -> bool {
        (usize::from(self.start)..usize::from(self.end)).contains(&at)
    }

    fn len(self) -> usize {
        usize::from(self.end - self.start)
    }
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
    // WP10.0: the validation state and the rendering by flags (recursion plan 2.2).
    state: SecurityState,
    ede: Option<ExtendedError>,
    /// The earliest signature expiry, in the cache's seconds; [`NO_EXPIRY`] for none.
    signature_expiry: u32,
    rrsig_offsets: Box<[Skip]>,
    /// The DNSSEC records can be left out without breaking a name.
    strip_safe: bool,
}

impl Entry {
    fn age(&self, now: u32) -> u32 {
        now.saturating_sub(self.stored)
    }

    fn stored(&self) -> Stored<'_> {
        Stored {
            rcode: self.wire[3] & 0x0f,
            counts: [
                u16::from_be_bytes([self.wire[6], self.wire[7]]),
                u16::from_be_bytes([self.wire[8], self.wire[9]]),
                u16::from_be_bytes([self.wire[10], self.wire[11]]),
            ],
            body: &self.wire[HEADER_LEN..],
            question_end: usize::from(self.question_end),
            ttls: &self.ttls,
            skips: &self.rrsig_offsets,
            strip_safe: self.strip_safe,
            state: self.state,
            ede: self.ede,
        }
    }

    fn fresh(&self, now: u32) -> bool {
        self.age(now) < self.ttl
    }

    fn cost(&self, key_len: usize) -> usize {
        key_len * 2
            + self.wire.len()
            + self.ttls.len() * 2
            + self.rrsig_offsets.len() * std::mem::size_of::<Skip>()
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
            let state = entry.state;
            let Some(rcode) = render(&entry.stored(), client, out, true, |original| {
                original.min(ttl) - age.min(original.min(ttl))
            }) else {
                return Hit::Miss;
            };
            let rcode = (rcode, state);
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
        Hit::Fresh {
            rcode: prefetch.0.0,
            state: prefetch.0.1,
        }
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
            render(&entry.stored(), client, out, true, |original| {
                original.min(ttl) - age.min(original.min(ttl))
            })
        } else {
            render(&entry.stored(), client, out, true, |_| STALE_TTL)
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

    /// Stores the upstream answer `message` for `key`, asked through `rule`, as
    /// [`Verdict::UNVALIDATED`]. Returns whether it was cached (see the module
    /// documentation for what is not).
    pub fn insert(
        &self,
        key: &CacheKey,
        message: &[u8],
        now: Instant,
        rule: Option<ForwardRuleId>,
    ) -> bool {
        self.insert_with(key, message, now, rule, &Verdict::UNVALIDATED)
    }

    /// Stores the answer `message` for `key`, asked through `rule`, with the validator's
    /// `verdict` (recursion plan section 2.2). Returns whether it was cached.
    pub fn insert_with(
        &self,
        key: &CacheKey,
        message: &[u8],
        now: Instant,
        rule: Option<ForwardRuleId>,
        verdict: &Verdict,
    ) -> bool {
        let Some(entry) = self.entry(message, self.secs(now), rule, verdict) else {
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

    /// The entry an answer makes, or `None` when it is not cached.
    fn entry(
        &self,
        message: &[u8],
        now: u32,
        rule: Option<ForwardRuleId>,
        verdict: &Verdict,
    ) -> Option<Entry> {
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
        let layout = Layout::of(message, &header, question_end)?;
        if layout.tsig || layout.opt_misplaced {
            return None;
        }
        let mut ttl = if negative {
            layout.soa_ttl?.min(self.settings.negative_ttl)
        } else {
            layout.smallest.min(self.settings.max_ttl)
        };
        if let Some(cap) = verdict.max_ttl {
            ttl = ttl.min(cap);
        }
        let signature_expiry = match verdict.signature_expiry {
            Some(expiry) => {
                let left = expiry
                    .duration_since(SystemTime::now())
                    .map_or(0, |left| u32::try_from(left.as_secs()).unwrap_or(u32::MAX));
                ttl = ttl.min(left);
                now.saturating_add(left).min(NO_EXPIRY - 1)
            }
            None => NO_EXPIRY,
        };
        if ttl == 0 {
            return None;
        }
        let end = layout.end;
        let mut stored = message[..end].to_vec();
        stored[..2].copy_from_slice(&[0, 0]);
        if layout.opt {
            let arcount = header.arcount - 1;
            stored[10..12].copy_from_slice(&arcount.to_be_bytes());
        }
        stored[HEADER_LEN..question_end - 4].make_ascii_lowercase();
        Some(Entry {
            wire: stored.into_boxed_slice(),
            ttls: layout.ttls.into_boxed_slice(),
            question_end: u16::try_from(question_end).ok()?,
            stored: now,
            ttl,
            hits: 0,
            prefetching: false,
            rule,
            state: verdict.state,
            ede: verdict.ede,
            signature_expiry,
            rrsig_offsets: layout.skips.into_boxed_slice(),
            strip_safe: layout.strip_safe,
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

/// The records of an answer as the cache and the relay need them.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent facts of one pass over the records"
)]
struct Layout {
    /// The TTL positions of the records before the OPT record.
    ttls: Vec<u16>,
    /// The DNSSEC records a client without DO does not get.
    skips: Vec<Skip>,
    /// No kept name points into a skipped record.
    strip_safe: bool,
    /// The end of the records before the OPT record.
    end: usize,
    /// The last record is an OPT record (left out of `end`).
    opt: bool,
    /// An OPT record that is not the last one, or a second one.
    opt_misplaced: bool,
    /// A TSIG record.
    tsig: bool,
    /// The smallest TTL.
    smallest: u32,
    /// The negative TTL of an SOA in the authority section (RFC 2308).
    soa_ttl: Option<u32>,
}

impl Layout {
    /// The layout of `message`, whose question ends at `question_end`; `None` when a
    /// record does not parse or the message is longer than a position holds.
    fn of(message: &[u8], header: &wire::RawHeader, question_end: usize) -> Option<Self> {
        let qtype = u16::from_be_bytes([message[question_end - 4], message[question_end - 3]]);
        let (answers, authority) = (usize::from(header.ancount), usize::from(header.nscount));
        let total = answers + authority + usize::from(header.arcount);
        let mut layout = Layout {
            ttls: Vec::with_capacity(total),
            skips: Vec::new(),
            strip_safe: true,
            end: message.len(),
            opt: false,
            opt_misplaced: false,
            tsig: false,
            smallest: u32::MAX,
            soa_ttl: None,
        };
        let mut pos = question_end;
        for index in 0..total {
            let record = wire::read_record(message, pos)?;
            let section = if index < answers {
                0
            } else if index < answers + authority {
                1
            } else {
                2
            };
            match record.rtype {
                TYPE_TSIG => layout.tsig = true,
                TYPE_OPT => {
                    // The OPT record goes; only as the last record, so no pointer moves.
                    if index + 1 != total || layout.opt {
                        layout.opt_misplaced = true;
                    } else {
                        layout.opt = true;
                        layout.end = record.start;
                    }
                    break;
                }
                _ => {}
            }
            layout.smallest = layout.smallest.min(record.ttl);
            if section == 1 && record.rtype == TYPE_SOA && record.rdlen >= 20 {
                let data = record.data(message);
                let minimum = u32::from_be_bytes([
                    data[data.len() - 4],
                    data[data.len() - 3],
                    data[data.len() - 2],
                    data[data.len() - 1],
                ]);
                layout.soa_ttl = Some(record.ttl.min(minimum));
            }
            layout.ttls.push(u16::try_from(record.fixed + 4).ok()?);
            let dnssec = matches!(record.rtype, TYPE_RRSIG | TYPE_NSEC | TYPE_NSEC3);
            if dnssec && !(section == 0 && record.rtype == qtype) {
                layout.skips.push(Skip {
                    start: u16::try_from(record.start).ok()?,
                    end: u16::try_from(record.end()).ok()?,
                    section,
                });
            }
            pos = record.end();
        }
        if !layout.opt {
            layout.end = pos;
        }
        if !layout.skips.is_empty() {
            layout.strip_safe = Self::strip_safe(message, question_end, layout.end, &layout.skips);
        }
        Some(layout)
    }

    /// Whether no name outside `skips` points into one of them.
    fn strip_safe(message: &[u8], question_end: usize, end: usize, skips: &[Skip]) -> bool {
        let mut pos = question_end;
        while pos < end {
            let Some(record) = wire::read_record(message, pos) else {
                return false;
            };
            pos = record.end();
            if skips.iter().any(|skip| skip.contains(record.start)) {
                continue;
            }
            if points_into(message, record.start, skips) {
                return false;
            }
            // The names in the data of the types of RFC 1035 that may be compressed, and
            // SRV (as `cache/list.rs` reads them).
            let (prefix, names) = match record.rtype {
                2 | 5 | 12 | 39 => (0, 1),
                6 => (0, 2),
                15 => (2, 1),
                33 => (6, 1),
                _ => continue,
            };
            let mut at = record.rdata + prefix;
            for _ in 0..names {
                if at >= record.end() {
                    break;
                }
                if points_into(message, at, skips) {
                    return false;
                }
                match wire::skip_name(message, at) {
                    Some(next) => at = next,
                    None => return false,
                }
            }
        }
        true
    }
}

/// Whether the name at `pos` ends in a pointer into one of `skips`.
fn points_into(message: &[u8], mut pos: usize, skips: &[Skip]) -> bool {
    loop {
        let Some(&len) = message.get(pos) else {
            return true;
        };
        match len {
            0 => return false,
            1..=63 => pos += 1 + usize::from(len),
            0xc0..=0xff => {
                let Some(&low) = message.get(pos + 1) else {
                    return true;
                };
                let target = usize::from(u16::from_be_bytes([len & 0x3f, low]));
                return skips.iter().any(|skip| skip.contains(target));
            }
            _ => return true,
        }
    }
}

/// A stored answer, or an upstream's answer to relay, as the renderer reads it.
struct Stored<'a> {
    /// The RCODE.
    rcode: u8,
    /// The answer, authority and additional counts without the OPT record.
    counts: [u16; 3],
    /// The octets after the header: the question and the records, without the OPT record.
    body: &'a [u8],
    /// The end of the question (a position in the whole message).
    question_end: usize,
    /// The TTL positions to map.
    ttls: &'a [u16],
    /// The DNSSEC records a client without DO does not get.
    skips: &'a [Skip],
    /// They can be left out.
    strip_safe: bool,
    /// The validation state.
    state: SecurityState,
    /// The extended error of a bogus answer.
    ede: Option<ExtendedError>,
}

/// Writes the answer `stored` for `client` into `out` by its state and the client's flags
/// ([`SecurityState::render`]), each TTL mapped by `ttl`, with an OPT record when `opt` and
/// the client sent EDNS. Returns the RCODE, or `None` when the client's question does not
/// have the answer's length. Allocates nothing when `out` has room for 65,535 octets.
fn render(
    stored: &Stored<'_>,
    client: &Client<'_>,
    out: &mut Vec<u8>,
    opt: bool,
    ttl: impl Fn(u32) -> u32,
) -> Option<u8> {
    let question_end = stored.question_end;
    if client.question_end != question_end
        || client.message.len() < question_end
        || stored.body.len() < question_end - HEADER_LEN
    {
        return None;
    }
    let rendering = stored.state.render(client.flags(), stored.ede);
    let edns = client.edns.filter(|_| opt);
    let ede = rendering.ede;
    out.clear();
    out.extend_from_slice(&client.id.to_be_bytes());
    out.push(0x80 | u8::from(client.rd));
    let cd = if client.cd { 0x10 } else { 0 };
    if rendering.servfail {
        out.push(0x80 | cd | 2);
        out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&client.message[HEADER_LEN..question_end]);
        if let Some(edns) = &edns {
            push_opt(out, edns, ede);
        }
        return Some(2);
    }
    let ad = if rendering.ad { 0x20 } else { 0 };
    out.push(0x80 | ad | cd | stored.rcode);
    let strip = !rendering.dnssec_records && stored.strip_safe && !stored.skips.is_empty();
    let mut counts = stored.counts;
    if strip {
        for skip in stored.skips {
            counts[usize::from(skip.section)] = counts[usize::from(skip.section)].saturating_sub(1);
        }
    }
    out.extend_from_slice(&1u16.to_be_bytes());
    for count in counts {
        out.extend_from_slice(&count.to_be_bytes());
    }
    out.extend_from_slice(&client.message[HEADER_LEN..question_end]);
    let records = &stored.body[question_end - HEADER_LEN..];
    if strip {
        let mut from = question_end;
        for skip in stored.skips {
            out.extend_from_slice(
                &records[from - question_end..usize::from(skip.start) - question_end],
            );
            from = usize::from(skip.end);
        }
        out.extend_from_slice(&records[from - question_end..]);
    } else {
        out.extend_from_slice(records);
    }
    // The TTL positions, moved back by the skipped records before them.
    let mut skips = stored.skips.iter().peekable();
    let mut shift = 0;
    for offset in stored.ttls {
        let at = usize::from(*offset);
        if strip {
            while let Some(skip) = skips.peek() {
                if usize::from(skip.end) <= at {
                    shift += skip.len();
                    skips.next();
                } else {
                    break;
                }
            }
            if skips.peek().is_some_and(|skip| skip.contains(at)) {
                continue;
            }
        }
        let at = at - shift;
        let original = u32::from_be_bytes([out[at], out[at + 1], out[at + 2], out[at + 3]]);
        out[at..at + 4].copy_from_slice(&ttl(original).to_be_bytes());
    }
    if let Some(edns) = &edns {
        push_opt(out, edns, ede);
    }
    if out.len() > client.max_len {
        out.truncate(question_end);
        out[2] |= 0x02;
        out[6..12].copy_from_slice(&[0; 6]);
        if let Some(edns) = &edns {
            push_opt(out, edns, ede);
        }
    }
    Some(stored.rcode)
}

/// Relays an upstream answer `message` to `client` into `out`: the client's id, question
/// and flags as for a cache hit, the upstream's records with their TTLs (without the
/// DNSSEC records for a client without DO), the upstream's OPT record replaced by this
/// node's. The answer is rendered as `unvalidated`; [`relay_with`] takes the validator's
/// state and extended error instead.
/// Returns the RCODE, or `None` when `message` does not parse or its question differs from
/// the client's in length.
pub fn relay(message: &[u8], client: &Client<'_>, out: &mut Vec<u8>) -> Option<u8> {
    relay_with(message, client, out, SecurityState::Unvalidated, None)
}

// WP10.2: a fresh answer rendered by the validator's state, as a hit is.
/// [`relay`] with the answer's validation `state` and extended error `ede` (recursion
/// plan section 2.3): SERVFAIL for a bogus answer unless the client set CD, AD for a
/// secure one, the DNSSEC records for DO clients only.
pub fn relay_with(
    message: &[u8],
    client: &Client<'_>,
    out: &mut Vec<u8>,
    state: SecurityState,
    ede: Option<ExtendedError>,
) -> Option<u8> {
    let header = wire::parse_header(message)?;
    let question_end = wire::questions_end(message, 1)?;
    if header.qdcount != 1 {
        return None;
    }
    let layout = Layout::of(message, &header, question_end)?;
    if layout.opt_misplaced {
        // An OPT record that is not the last one: the records go as they are, as received,
        // without one of ours.
        let stored = Stored {
            rcode: header.rcode & 0x0f,
            counts: [header.ancount, header.nscount, header.arcount],
            body: &message[HEADER_LEN..],
            question_end,
            ttls: &[],
            skips: &[],
            strip_safe: false,
            state,
            ede,
        };
        return render(&stored, client, out, false, |ttl| ttl);
    }
    let arcount = header.arcount - u16::from(layout.opt);
    let stored = Stored {
        rcode: header.rcode & 0x0f,
        counts: [header.ancount, header.nscount, arcount],
        body: &message[HEADER_LEN..layout.end],
        question_end,
        ttls: &[],
        skips: &layout.skips,
        strip_safe: layout.strip_safe,
        state,
        ede,
    };
    // No OPT record from the upstream: none of ours either.
    render(&stored, client, out, layout.opt, |ttl| ttl)
}
// WP10.2: end.

/// Appends the OPT record of an answer, with the client's cookie and the extended error
/// (RFC 8914, no text), and counts it.
fn push_opt(out: &mut Vec<u8>, edns: &ClientEdns, ede: Option<ExtendedError>) {
    out.push(0);
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&edns.udp_size.to_be_bytes());
    out.extend_from_slice(&[0, 0, if edns.dnssec_ok { 0x80 } else { 0 }, 0]);
    let rdlen = if edns.cookie.is_some() { 28 } else { 0 } + if ede.is_some() { 6 } else { 0 };
    out.extend_from_slice(&u16::to_be_bytes(rdlen));
    if let Some(cookie) = &edns.cookie {
        out.extend_from_slice(&OPTION_COOKIE.to_be_bytes());
        out.extend_from_slice(&24u16.to_be_bytes());
        out.extend_from_slice(cookie);
    }
    if let Some(ede) = ede {
        out.extend_from_slice(&OPTION_EXTENDED_ERROR.to_be_bytes());
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(&ede.code().to_be_bytes());
    }
    let arcount = u16::from_be_bytes([out[10], out[11]]).saturating_add(1);
    out[10..12].copy_from_slice(&arcount.to_be_bytes());
}

// cache-browse: the listing of what the cache holds (`cache/list.rs`).
mod list;

pub use list::{CachePage, CachedEntry, DEFAULT_LIST, ListCursor, MAX_LIST, ViewFilter};
// cache-browse: end.

// WP10.3: the denial cache (RFC 8198, RFC 8020) and the failure cache (RFC 9520).
pub mod denial;
pub mod failure;

pub use denial::{DenialSettings, Denials};
pub use failure::Failures;
// WP10.3: end.

#[cfg(test)]
mod tests;

#[cfg(test)]
mod render_tests;
