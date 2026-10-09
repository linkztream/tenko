//! In-memory serving index: what DNS queries are answered from. Lookups never touch redb or
//! Raft. The map is sharded so that applying a batch only write-locks the shards it touches,
//! and readers of other shards are never blocked.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::hash::RandomState;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

const SHARDS: usize = 64;

type Shard = HashMap<Box<[u8]>, Arc<[u8]>>;

pub struct ServingIndex {
    hasher: RandomState,
    shards: Vec<RwLock<Shard>>,
    key_bytes: AtomicU64,
    value_bytes: AtomicU64,
}

impl Default for ServingIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl ServingIndex {
    pub fn new() -> Self {
        Self {
            hasher: RandomState::new(),
            shards: (0..SHARDS).map(|_| RwLock::new(HashMap::new())).collect(),
            key_bytes: AtomicU64::new(0),
            value_bytes: AtomicU64::new(0),
        }
    }

    fn shard_of(&self, key: &[u8]) -> usize {
        (self.hasher.hash_one(key) as usize) % SHARDS
    }

    /// Look up the serving form of an RRset by encoded key.
    pub fn get(&self, key: &[u8]) -> Option<Arc<[u8]>> {
        let shard = self.shards[self.shard_of(key)]
            .read()
            .expect("index shard poisoned");
        shard.get(key).cloned()
    }

    /// Insert or replace a set of entries. Entries are grouped per shard so each shard lock is
    /// taken once per call.
    pub fn upsert_many(&self, entries: Vec<(Box<[u8]>, Arc<[u8]>)>) {
        let mut per_shard: Vec<Vec<(Box<[u8]>, Arc<[u8]>)>> =
            (0..SHARDS).map(|_| Vec::new()).collect();
        for (k, v) in entries {
            let s = self.shard_of(&k);
            per_shard[s].push((k, v));
        }
        let mut dk: i64 = 0;
        let mut dv: i64 = 0;
        for (s, items) in per_shard.into_iter().enumerate() {
            if items.is_empty() {
                continue;
            }
            let mut shard = self.shards[s].write().expect("index shard poisoned");
            for (k, v) in items {
                let kl = k.len() as i64;
                let vl = v.len() as i64;
                match shard.insert(k, v) {
                    Some(old) => dv += vl - old.len() as i64,
                    None => {
                        dk += kl;
                        dv += vl;
                    }
                }
            }
        }
        add_signed(&self.key_bytes, dk);
        add_signed(&self.value_bytes, dv);
    }

    /// Drop all entries (used before a snapshot install rebuilds the index).
    pub fn clear(&self) {
        for s in &self.shards {
            let mut shard = s.write().expect("index shard poisoned");
            *shard = HashMap::new();
        }
        self.key_bytes.store(0, Ordering::Relaxed);
        self.value_bytes.store(0, Ordering::Relaxed);
    }

    pub fn len(&self) -> u64 {
        self.shards
            .iter()
            .map(|s| s.read().expect("index shard poisoned").len() as u64)
            .sum()
    }

    /// Estimate of the heap held by the index, computed from entry sizes and table capacity:
    /// per entry one key allocation (`Box<[u8]>`) and one value allocation (`Arc<[u8]>`, 16 byte
    /// reference-count header), each rounded up to 16 bytes plus 16 bytes of allocator overhead;
    /// per table slot 16 + 16 bytes of fat pointers + 1 control byte. This is a computed
    /// estimate, not a measurement.
    pub fn estimated_heap_bytes(&self) -> u64 {
        let mut slots = 0u64;
        let mut alloc = 0u64;
        for s in &self.shards {
            let shard = s.read().expect("index shard poisoned");
            slots += shard.capacity() as u64;
            for (k, v) in shard.iter() {
                alloc += round16(k.len() as u64) + 16;
                alloc += round16(16 + v.len() as u64) + 16;
            }
        }
        alloc + slots * 33
    }

    #[allow(dead_code)]
    pub fn key_bytes(&self) -> u64 {
        self.key_bytes.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn value_bytes(&self) -> u64 {
        self.value_bytes.load(Ordering::Relaxed)
    }
}

fn round16(n: u64) -> u64 {
    n.div_ceil(16) * 16
}

fn add_signed(a: &AtomicU64, d: i64) {
    if d >= 0 {
        a.fetch_add(d as u64, Ordering::Relaxed);
    } else {
        a.fetch_sub((-d) as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_get_clear() {
        let idx = ServingIndex::new();
        idx.upsert_many(vec![
            (b"a".to_vec().into(), Arc::from(&b"1"[..])),
            (b"b".to_vec().into(), Arc::from(&b"22"[..])),
        ]);
        assert_eq!(idx.get(b"a").as_deref(), Some(&b"1"[..]));
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.value_bytes(), 3);
        idx.upsert_many(vec![(b"a".to_vec().into(), Arc::from(&b"333"[..]))]);
        assert_eq!(idx.value_bytes(), 5);
        assert!(idx.estimated_heap_bytes() > 0);
        idx.clear();
        assert!(idx.get(b"a").is_none());
    }
}
