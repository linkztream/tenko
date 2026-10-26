//! The probe cache: an address probed clean is not probed again for the cache's time
//! (`[dhcp.probe] cache_secs`, 10 minutes), so a client that sends its DISCOVER again, or
//! the next client offered the same address, gets its OFFER at once.
//!
//! A fixed table made at start, as the offer table is: stripes of slots behind one mutex
//! each, open addressing with a bounded probe; an insert into a full window replaces the
//! entry that ends first. Neither a lookup nor an insert allocates.

use std::{
    net::Ipv4Addr,
    sync::{
        Mutex, MutexGuard, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

use tenko_core::{Timestamp, VrfId};

use super::{hash_bytes, mix};

/// How many slots a lookup or an insert looks at.
const PROBE: usize = 8;
/// Stripes of the table.
const STRIPES: usize = 16;

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    key: u64,
    addr: u32,
    until: i128,
}

impl Slot {
    fn live(&self, now: i128) -> bool {
        self.until > now
    }
}

/// Addresses probed clean, until when.
#[derive(Debug)]
pub struct ProbeCache {
    stripes: Box<[Mutex<Box<[Slot]>>]>,
    // E32: the cache grows with the image; a stripe's window starts by its own length.
    capacity: AtomicUsize,
}

/// Where the probe window of `key` starts in a stripe of `len` slots.
fn start_of(key: u64, len: usize) -> usize {
    #[allow(clippy::cast_possible_truncation, reason = "the low bits of a hash")]
    let high = (key >> 32) as usize;
    high % len.max(1)
}

/// Writes a result into `slots`: over the same address's slot, else over the one of the
/// window that ends first.
fn insert_into(slots: &mut [Slot], key: u64, addr: u32, until: i128) {
    let len = slots.len();
    let start = start_of(key, len);
    let mut at = start;
    for step in 0..PROBE.min(len) {
        let index = (start + step) % len;
        let slot = slots[index];
        if slot.key == key && slot.addr == addr {
            at = index;
            break;
        }
        if slot.until < slots[at].until {
            at = index;
        }
    }
    slots[at] = Slot { key, addr, until };
}

impl ProbeCache {
    /// A cache for about `capacity` addresses (at least 64 slots per stripe).
    pub fn with_capacity(capacity: usize) -> Self {
        let per_stripe = (capacity / STRIPES).max(64);
        let stripes = (0..STRIPES)
            .map(|_| Mutex::new(vec![Slot::default(); per_stripe].into_boxed_slice()))
            .collect();
        Self {
            stripes,
            capacity: AtomicUsize::new(capacity),
        }
    }

    // E32: the cache grows with the image.
    /// The addresses the cache is made for.
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Relaxed)
    }

    /// Grows the cache to about `capacity` addresses; a smaller one changes nothing. Each
    /// stripe is made anew outside its lock and its results move in under it. Allocates:
    /// never on the DORA path.
    pub fn grow(&self, capacity: usize) {
        if capacity <= self.capacity() {
            return;
        }
        let per_stripe = (capacity / STRIPES).max(64);
        for stripe in 0..STRIPES {
            let mut grown = vec![Slot::default(); per_stripe].into_boxed_slice();
            let old = {
                let mut held = self.lock(stripe);
                if held.len() >= per_stripe {
                    continue;
                }
                for slot in held.iter().filter(|slot| slot.until > i128::MIN) {
                    insert_into(&mut grown, slot.key, slot.addr, slot.until);
                }
                std::mem::replace(&mut *held, grown)
            };
            drop(old);
        }
        self.capacity.fetch_max(capacity, Ordering::Relaxed);
    }

    fn place(vrf: VrfId, addr: Ipv4Addr) -> (u64, u32, usize) {
        let addr = u32::from(addr);
        let key = mix(hash_bytes(vrf.0.as_bytes()) ^ u64::from(addr));
        #[allow(clippy::cast_possible_truncation, reason = "the low bits of a hash")]
        let stripe = (key as usize) % STRIPES;
        (key, addr, stripe)
    }

    fn lock(&self, stripe: usize) -> MutexGuard<'_, Box<[Slot]>> {
        self.stripes[stripe]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether `addr` of `vrf` was probed clean and the result holds at `now`.
    pub fn is_clean(&self, vrf: VrfId, addr: Ipv4Addr, now: Timestamp) -> bool {
        let (key, addr, stripe) = Self::place(vrf, addr);
        let now = now.unix_nanos();
        let slots = self.lock(stripe);
        let start = start_of(key, slots.len());
        (0..PROBE.min(slots.len())).any(|step| {
            let slot = &slots[(start + step) % slots.len()];
            slot.key == key && slot.addr == addr && slot.live(now)
        })
    }

    /// Remembers `addr` of `vrf` as clean until `until`.
    pub fn insert(&self, vrf: VrfId, addr: Ipv4Addr, until: Timestamp) {
        let (key, addr, stripe) = Self::place(vrf, addr);
        insert_into(&mut self.lock(stripe), key, addr, until.unix_nanos());
    }

    /// Forgets `addr` of `vrf` (a DECLINE or a conflict).
    pub fn forget(&self, vrf: VrfId, addr: Ipv4Addr) {
        let (key, addr, stripe) = Self::place(vrf, addr);
        let mut slots = self.lock(stripe);
        let len = slots.len();
        let start = start_of(key, len);
        for step in 0..PROBE.min(len) {
            let slot = &mut slots[(start + step) % len];
            if slot.key == key && slot.addr == addr {
                slot.until = i128::MIN;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn at(secs: u64) -> Timestamp {
        let base: Timestamp = "2026-10-22T12:00:00Z".parse().expect("time");
        base.checked_add(Duration::from_secs(secs)).expect("time")
    }

    #[test]
    fn a_clean_address_stays_clean_until_its_time_and_a_decline_forgets_it() {
        let cache = ProbeCache::with_capacity(16);
        let vrf = VrfId::generate();
        let addr = Ipv4Addr::new(192, 0, 2, 10);
        assert!(!cache.is_clean(vrf, addr, at(0)));
        cache.insert(vrf, addr, at(600));
        assert!(cache.is_clean(vrf, addr, at(599)));
        assert!(!cache.is_clean(vrf, addr, at(600)));
        assert!(!cache.is_clean(VrfId::generate(), addr, at(1)));
        cache.forget(vrf, addr);
        assert!(!cache.is_clean(vrf, addr, at(1)));
    }

    #[test]
    fn a_full_cache_forgets_the_entries_that_end_first() {
        let cache = ProbeCache::with_capacity(1);
        let vrf = VrfId::generate();
        for host in 0..10_000u32 {
            cache.insert(
                vrf,
                Ipv4Addr::from(0xc000_0200 + host),
                at(100 + u64::from(host)),
            );
        }
        assert!(cache.is_clean(vrf, Ipv4Addr::from(0xc000_0200 + 9_999), at(1)));
    }
}

// E32: the cache grows with the image.
#[cfg(test)]
mod grow_tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_grown_cache_keeps_its_clean_results() {
        let cache = ProbeCache::with_capacity(16);
        let vrf = VrfId::generate();
        let now = Timestamp::now();
        let until = now.checked_add(Duration::from_secs(600)).expect("a time");
        for host in 1..=200u8 {
            cache.insert(vrf, Ipv4Addr::new(192, 0, 2, host), until);
        }
        let clean = |cache: &ProbeCache| {
            (1..=200u8)
                .filter(|host| cache.is_clean(vrf, Ipv4Addr::new(192, 0, 2, *host), now))
                .count()
        };
        let before = clean(&cache);
        cache.grow(10_000);
        assert_eq!(cache.capacity(), 10_000);
        assert_eq!(clean(&cache), before, "every result moved");
        for host in 1..=200u8 {
            cache.insert(vrf, Ipv4Addr::new(198, 51, 100, host), until);
        }
        assert_eq!(
            (1..=200u8)
                .filter(|host| cache.is_clean(vrf, Ipv4Addr::new(198, 51, 100, *host), now))
                .count(),
            200,
            "room for the larger image"
        );
        cache.grow(16);
        assert_eq!(cache.capacity(), 10_000, "it never shrinks");
    }
}
