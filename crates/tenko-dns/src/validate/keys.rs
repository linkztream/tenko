//! The validator's table of what the chain walk found per zone: the validated DNSKEY set
//! of a secure zone, an insecure zone (its DS proven absent, or only unsupported
//! algorithms), a name that is no zone cut (the parent's keys go on applying), or a
//! bogus chain, each until a time. Bounded like the infrastructure cache's cuts (1,000
//! under Home, 10,000 elsewhere), the least recently used entry going first; an entry
//! made with an older generation of the trust anchors is not read (recursion plan section
//! 2.3). The infrastructure cache's DS slot stays the source for zones that have a cut;
//! this table covers the rest.

use std::{
    collections::HashMap,
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

/// The table; see the module documentation.
#[derive(Debug)]
pub struct KeyTable {
    map: HashMap<Vec<u8>, Entry>,
    bound: usize,
    tick: u64,
}

impl KeyTable {
    /// An empty table of at most `bound` zones.
    pub fn new(bound: usize) -> Self {
        Self {
            map: HashMap::new(),
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

    /// The state of `zone` (lowercase wire form) at `now` under the anchors' `generation`.
    pub fn get(&mut self, zone: &[u8], generation: u64, now: Instant) -> Option<ZoneState> {
        self.tick += 1;
        let tick = self.tick;
        let entry = self.map.get_mut(zone)?;
        if entry.until <= now || entry.generation != generation {
            self.map.remove(zone);
            return None;
        }
        entry.used = tick;
        Some(entry.state.clone())
    }

    /// Stores the state of `zone` until `until`.
    pub fn put(&mut self, zone: &[u8], state: ZoneState, until: Instant, generation: u64) {
        self.tick += 1;
        let used = self.tick;
        self.map.insert(
            zone.to_vec(),
            Entry {
                state,
                until,
                generation,
                used,
            },
        );
        while self.map.len() > self.bound {
            let Some(oldest) = self
                .map
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(zone, _)| zone.clone())
            else {
                break;
            };
            self.map.remove(&oldest);
        }
    }

    /// Removes every zone, or those at or below `suffix`. Returns how many.
    pub fn flush(&mut self, suffix: Option<&[u8]>) -> usize {
        let before = self.map.len();
        match suffix {
            None => self.map.clear(),
            Some(suffix) => self.map.retain(|zone, _| !name::is_within(zone, suffix)),
        }
        before - self.map.len()
    }

    /// Drops the entries past their time.
    pub fn purge(&mut self, now: Instant) {
        self.map.retain(|_, entry| entry.until > now);
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
    }
}
