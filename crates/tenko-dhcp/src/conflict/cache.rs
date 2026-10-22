//! The probe cache: an address probed clean is not probed again for the cache's time
//! (`[dhcp.probe] cache_secs`, 10 minutes), so a client that sends its DISCOVER again, or
//! the next client offered the same address, gets its OFFER at once.
//!
//! A fixed table made at start, as the offer table is: stripes of slots behind one mutex
//! each, open addressing with a bounded probe; an insert into a full window replaces the
//! entry that ends first. Neither a lookup nor an insert allocates.

use std::{
    net::Ipv4Addr,
    sync::{Mutex, MutexGuard, PoisonError},
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
    per_stripe: usize,
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
            per_stripe,
        }
    }

    fn place(&self, vrf: VrfId, addr: Ipv4Addr) -> (u64, u32, usize, usize) {
        let addr = u32::from(addr);
        let key = mix(hash_bytes(vrf.0.as_bytes()) ^ u64::from(addr));
        #[allow(clippy::cast_possible_truncation, reason = "the low bits of a hash")]
        let (stripe, start) = (
            (key as usize) % STRIPES,
            ((key >> 32) as usize) % self.per_stripe,
        );
        (key, addr, stripe, start)
    }

    fn lock(&self, stripe: usize) -> MutexGuard<'_, Box<[Slot]>> {
        self.stripes[stripe]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether `addr` of `vrf` was probed clean and the result holds at `now`.
    pub fn is_clean(&self, vrf: VrfId, addr: Ipv4Addr, now: Timestamp) -> bool {
        let (key, addr, stripe, start) = self.place(vrf, addr);
        let now = now.unix_nanos();
        let slots = self.lock(stripe);
        (0..PROBE.min(slots.len())).any(|step| {
            let slot = &slots[(start + step) % slots.len()];
            slot.key == key && slot.addr == addr && slot.live(now)
        })
    }

    /// Remembers `addr` of `vrf` as clean until `until`.
    pub fn insert(&self, vrf: VrfId, addr: Ipv4Addr, until: Timestamp) {
        let (key, addr, stripe, start) = self.place(vrf, addr);
        let until = until.unix_nanos();
        let mut slots = self.lock(stripe);
        let len = slots.len();
        let mut at = start % len;
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

    /// Forgets `addr` of `vrf` (a DECLINE or a conflict).
    pub fn forget(&self, vrf: VrfId, addr: Ipv4Addr) {
        let (key, addr, stripe, start) = self.place(vrf, addr);
        let mut slots = self.lock(stripe);
        let len = slots.len();
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
