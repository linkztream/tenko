//! The failure cache of RFC 9520 (WP10.3, recursion plan section 2.2): [`Failures`], the
//! [`FailureCache`] of a node, kept beside the answer cache under the same key.
//!
//! A resolution that ends in SERVFAIL for a cause of the server's (no reachable authority,
//! the work budget, a network error, a bogus answer) is held for 5 seconds, doubling on
//! each repeat while the last hold or as long again runs, up to `failure_cache_max_secs`
//! (300). A cause of the client's (FORMERR of the question) never reaches it. The worker
//! looks a key up after a miss of the answer cache ([`Failures::lookup`], nothing allocated)
//! and answers SERVFAIL with the stored extended error ([`render`]); a bogus failure is not
//! answered there for a client with CD, which gets the data. The failures are spread over
//! shards by a hash of the key, each holding its share of the bound and dropping its least
//! recently used sixteenth when full: the cache never empties itself wholesale. It is
//! flushed with the answer cache, everything or at or below a suffix.

use std::{
    collections::HashMap,
    hash::{BuildHasher, Hasher},
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use tenko_core::dns::ExtendedError;

use super::{CacheKey, Client, push_opt};
use crate::{
    name,
    recursion::{FailureCache, FailureCause, failure::FAILURE_MIN},
    wire::HEADER_LEN,
};

#[derive(Debug, Clone, Copy)]
struct Failed {
    cause: FailureCause,
    until: Instant,
    hold: Duration,
    used: u64,
}

#[derive(Debug, Default)]
struct Shard {
    map: HashMap<Box<[u8]>, Failed>,
    tick: u64,
}

/// The failure cache; see the module documentation.
#[derive(Debug)]
pub struct Failures {
    max: Duration,
    shard_cap: usize,
    shards: Box<[Mutex<Shard>]>,
    hasher: std::collections::hash_map::RandomState,
}

impl Failures {
    /// An empty cache whose holds double up to `max` and that keeps at most `bound`
    /// failures.
    pub fn new(max: Duration, bound: usize) -> Self {
        let bound = bound.max(16);
        let count = (bound / 1_024).clamp(1, 16);
        Self {
            max: max.max(FAILURE_MIN),
            shard_cap: bound / count,
            shards: (0..count).map(|_| Mutex::new(Shard::default())).collect(),
            hasher: std::collections::hash_map::RandomState::new(),
        }
    }

    /// The bound.
    pub fn bound(&self) -> usize {
        self.shard_cap * self.shards.len()
    }

    fn shard(&self, key: &[u8]) -> std::sync::MutexGuard<'_, Shard> {
        let mut hasher = self.hasher.build_hasher();
        hasher.write(key);
        let index = usize::try_from(hasher.finish() % self.shards.len() as u64).unwrap_or(0);
        self.shards[index]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Drops the failures that ended before `now` (housekeeping; the bound holds without
    /// it).
    pub fn purge(&self, now: Instant) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                let mut shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
                let before = shard.map.len();
                // Kept while a repeat would still double the hold.
                shard
                    .map
                    .retain(|_, failed| failed.until + failed.hold > now);
                before - shard.map.len()
            })
            .sum()
    }
}

impl FailureCache for Failures {
    fn record(&self, key: &CacheKey, cause: FailureCause, now: Instant) -> Duration {
        let mut shard = self.shard(key.as_bytes());
        shard.tick += 1;
        let used = shard.tick;
        let hold = match shard.map.get(key.as_bytes()) {
            // A repeat while the last hold or as long again runs doubles it.
            Some(last) if now < last.until + last.hold => (last.hold * 2).min(self.max),
            _ => FAILURE_MIN,
        };
        shard.map.insert(
            key.as_bytes().into(),
            Failed {
                cause,
                until: now + hold,
                hold,
                used,
            },
        );
        crate::infra::trim(&mut shard.map, self.shard_cap, |failed| failed.used);
        hold
    }

    fn lookup(&self, key: &CacheKey, now: Instant) -> Option<FailureCause> {
        let mut shard = self.shard(key.as_bytes());
        shard.tick += 1;
        let tick = shard.tick;
        let failed = shard.map.get_mut(key.as_bytes())?;
        if failed.until <= now {
            return None;
        }
        failed.used = tick;
        Some(failed.cause)
    }

    fn flush(&self, suffix: Option<&[u8]>) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                let mut shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
                let before = shard.map.len();
                match suffix {
                    None => shard.map.clear(),
                    Some(suffix) => shard
                        .map
                        .retain(|key, _| !name::is_within(CacheKey::qname_of(key), suffix)),
                }
                before - shard.map.len()
            })
            .sum()
    }

    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .map
                    .len()
            })
            .sum()
    }
}

/// Writes SERVFAIL for `client` with the extended error `ede` into `out` (the worker,
/// nothing allocated when `out` has room): the client's id and question, RA, its RD and
/// CD, and the OPT record when it sent EDNS. Returns `None` when its question cannot be
/// echoed.
pub fn render(client: &Client<'_>, ede: ExtendedError, out: &mut Vec<u8>) -> Option<u8> {
    let question_end = client.question_end;
    if question_end < HEADER_LEN || client.message.len() < question_end {
        return None;
    }
    out.clear();
    out.extend_from_slice(&client.id.to_be_bytes());
    out.push(0x80 | u8::from(client.rd));
    out.push(0x80 | if client.cd { 0x10 } else { 0 } | 2);
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&client.message[HEADER_LEN..question_end]);
    if let Some(edns) = &client.edns {
        push_opt(out, edns, Some(ede));
    }
    Some(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::BudgetBound;

    fn key(name: &[u8]) -> CacheKey {
        CacheKey::new(None, name, 1, 1)
    }

    #[test]
    fn holds_double_up_to_the_cap_and_end() {
        let failures = Failures::new(Duration::from_secs(20), 100);
        let key = key(b"\x01a\x04test\x00");
        let now = Instant::now();
        let cause = FailureCause::NoReachableAuthority;
        assert_eq!(failures.record(&key, cause, now), Duration::from_secs(5));
        assert_eq!(
            failures.lookup(&key, now + Duration::from_secs(4)),
            Some(cause)
        );
        assert_eq!(failures.lookup(&key, now + Duration::from_secs(5)), None);
        let later = now + Duration::from_secs(6);
        assert_eq!(failures.record(&key, cause, later), Duration::from_secs(10));
        let later = later + Duration::from_secs(11);
        assert_eq!(failures.record(&key, cause, later), Duration::from_secs(20));
        let later = later + Duration::from_secs(21);
        assert_eq!(failures.record(&key, cause, later), Duration::from_secs(20));
        // Long after: back to the first hold.
        let later = later + Duration::from_secs(100);
        assert_eq!(failures.record(&key, cause, later), Duration::from_secs(5));
    }

    #[test]
    fn the_bound_drops_the_least_recently_used_and_never_everything() {
        let failures = Failures::new(Duration::from_secs(300), 64);
        let now = Instant::now();
        let first = key(b"\x05first\x04test\x00");
        failures.record(&first, FailureCause::Network, now);
        for index in 0..500u16 {
            let name = format!("n{index}");
            let mut wire = vec![u8::try_from(name.len()).expect("len")];
            wire.extend_from_slice(name.as_bytes());
            wire.extend_from_slice(b"\x04test\x00");
            failures.record(&key(&wire), FailureCause::Budget(BudgetBound::Queries), now);
            // The first stays in use.
            assert!(failures.lookup(&first, now).is_some(), "{index}");
            assert!(failures.len() <= failures.bound());
        }
        assert!(failures.len() > failures.bound() / 2);
        assert_eq!(failures.flush(Some(b"\x05first\x04test\x00")), 1);
        assert!(failures.flush(None) > 0);
        assert!(failures.is_empty());
    }

    #[test]
    fn servfail_carries_the_extended_error() {
        let mut query = Vec::new();
        crate::wire::write_query(&mut query, 7, "a.test", 1, Some(1232));
        let question_end = crate::wire::questions_end(&query, 1).expect("question");
        let client = Client {
            message: &query,
            question_end,
            id: 7,
            rd: true,
            cd: false,
            ad: false,
            edns: Some(crate::cache::ClientEdns {
                udp_size: 1232,
                dnssec_ok: false,
                cookie: None,
            }),
            max_len: 512,
        };
        let mut out = Vec::new();
        assert_eq!(
            render(&client, ExtendedError::NO_REACHABLE_AUTHORITY, &mut out),
            Some(2)
        );
        let header = crate::wire::parse_header(&out).expect("header");
        assert_eq!((header.rcode, header.arcount), (2, 1));
        assert!(out.ends_with(&[0, 15, 0, 2, 0, 22]));
    }
}
