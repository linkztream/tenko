//! The validator's table of what the chain walk found per zone: the validated DNSKEY set
//! of a secure zone, an insecure zone (its DS proven absent, or only unsupported
//! algorithms), a name that is no zone cut (the parent's keys go on applying), or a
//! bogus chain, each until a time. Bounded like the infrastructure cache's cuts (1,000
//! under Home, 10,000 elsewhere), the least recently used entry going first; an entry
//! made with an older generation of the trust anchors is not read (recursion plan section
//! 2.3). The infrastructure cache's DS slot stays the source for zones that have a cut;
//! this table covers the rest.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};

use tenko_core::dns::ExtendedError;

use crate::{name, recursion::BogusReason};

/// What the chain walk knows about a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneState {
    /// A DS chain from an anchor proves the DNSKEY set (record data).
    Secure(Arc<[Vec<u8>]>),
    /// The parent proves there is no DS, or the DS names only unsupported algorithms:
    /// the zone and everything below it are insecure.
    Insecure,
    /// The name is no delegation: the parent's keys apply below it.
    NotACut,
    /// The chain fails here.
    Bogus(BogusReason, ExtendedError),
    /// No trust anchor covers the zone.
    Indeterminate,
}

#[derive(Debug, Clone)]
struct Entry {
    state: ZoneState,
    until: Instant,
    generation: u64,
    used: u64,
}

/// The longest a chain finding is kept, whatever the TTLs say: one day.
pub const MAX_HOLD: Duration = Duration::from_secs(86_400);

/// How long a bogus chain is remembered (RFC 9520 section 3.2: at least five seconds, at
/// most five minutes).
pub const BOGUS_HOLD: Duration = Duration::from_secs(60);

/// The table; see the module documentation. Beside the map an index of the zones by their
/// last use, so that the least recently used zone is found without a scan: a read, an
/// insert and an eviction each cost a logarithm of the bound, under the validator's lock.
#[derive(Debug)]
pub struct KeyTable {
    map: HashMap<Arc<[u8]>, Entry>,
    /// The zones by the tick of their last use (each tick is used once).
    order: BTreeMap<u64, Arc<[u8]>>,
    bound: usize,
    tick: u64,
}

impl KeyTable {
    /// An empty table of at most `bound` zones.
    pub fn new(bound: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: BTreeMap::new(),
            bound: bound.max(1),
            tick: 0,
        }
    }

    /// The bound.
    pub fn bound(&self) -> usize {
        self.bound
    }

    /// Zones held.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn remove(&mut self, zone: &[u8]) {
        if let Some(entry) = self.map.remove(zone) {
            self.order.remove(&entry.used);
        }
    }

    /// The state of `zone` (lowercase wire form) at `now` under the anchors' `generation`.
    pub fn get(&mut self, zone: &[u8], generation: u64, now: Instant) -> Option<ZoneState> {
        self.tick += 1;
        let tick = self.tick;
        let entry = self.map.get_mut(zone)?;
        if entry.until <= now || entry.generation != generation {
            self.remove(zone);
            return None;
        }
        if let Some(key) = self.order.remove(&entry.used) {
            self.order.insert(tick, key);
        }
        entry.used = tick;
        Some(entry.state.clone())
    }

    /// Stores the state of `zone` until `until`; over the bound the least recently used
    /// zone goes.
    pub fn put(&mut self, zone: &[u8], state: ZoneState, until: Instant, generation: u64) {
        self.tick += 1;
        let used = self.tick;
        self.remove(zone);
        let key: Arc<[u8]> = zone.into();
        self.order.insert(used, Arc::clone(&key));
        self.map.insert(
            key,
            Entry {
                state,
                until,
                generation,
                used,
            },
        );
        while self.map.len() > self.bound {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.map.remove(&oldest);
        }
    }

    /// Removes every zone, or those at or below `suffix`. Returns how many.
    pub fn flush(&mut self, suffix: Option<&[u8]>) -> usize {
        let before = self.map.len();
        match suffix {
            None => {
                self.map.clear();
                self.order.clear();
            }
            Some(suffix) => {
                self.map.retain(|zone, _| !name::is_within(zone, suffix));
                self.order.retain(|_, zone| !name::is_within(zone, suffix));
            }
        }
        before - self.map.len()
    }

    /// Drops the entries past their time.
    pub fn purge(&mut self, now: Instant) {
        let order = &mut self.order;
        self.map.retain(|_, entry| {
            let keep = entry.until > now;
            if !keep {
                order.remove(&entry.used);
            }
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_bounded_and_generation_aware() {
        let now = Instant::now();
        let later = now + Duration::from_secs(10);
        let mut table = KeyTable::new(2);
        table.put(b"\x01a\x00", ZoneState::Insecure, later, 1);
        table.put(b"\x01b\x00", ZoneState::NotACut, later, 1);
        assert_eq!(table.get(b"\x01a\x00", 1, now), Some(ZoneState::Insecure));
        table.put(b"\x01c\x00", ZoneState::Indeterminate, later, 1);
        // b was the least recently used.
        assert_eq!(table.len(), 2);
        assert_eq!(table.get(b"\x01b\x00", 1, now), None);
        assert_eq!(table.get(b"\x01a\x00", 2, now), None, "an older generation");
        assert_eq!(table.get(b"\x01c\x00", 1, later), None, "past its time");
        table.put(b"\x01x\x01a\x00", ZoneState::Insecure, later, 1);
        table.put(b"\x01a\x00", ZoneState::Insecure, later, 1);
        assert_eq!(table.flush(Some(b"\x01a\x00")), 2);
        assert!(table.is_empty());
        assert!(table.order.is_empty());
    }

    /// The zone of `n` in wire form.
    fn zone(n: u64) -> Vec<u8> {
        let label = format!("z{n}");
        let mut wire = vec![u8::try_from(label.len()).expect("label")];
        wire.extend_from_slice(label.as_bytes());
        wire.push(0);
        wire
    }

    #[test]
    fn eviction_follows_the_last_use_as_a_plain_list_would() {
        // A reference: the zones in the order of their last use, oldest first.
        let now = Instant::now();
        let later = now + Duration::from_secs(60);
        let mut table = KeyTable::new(64);
        let mut model: Vec<Vec<u8>> = Vec::new();
        let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
        for _ in 0..20_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let key = zone(seed % 200);
            if seed.is_multiple_of(3) {
                let found = table.get(&key, 1, now).is_some();
                let at = model.iter().position(|zone| *zone == key);
                assert_eq!(found, at.is_some());
                if let Some(at) = at {
                    let zone = model.remove(at);
                    model.push(zone);
                }
            } else {
                table.put(&key, ZoneState::Insecure, later, 1);
                model.retain(|zone| *zone != key);
                model.push(key);
                if model.len() > 64 {
                    model.remove(0);
                }
            }
            assert_eq!(table.len(), model.len());
            assert_eq!(table.order.len(), table.map.len());
        }
        for zone in &model {
            assert!(table.map.contains_key(zone.as_slice()));
        }
        // Purge and an expired read keep the index in step.
        table.purge(later);
        assert!(table.is_empty() && table.order.is_empty());
    }
}
