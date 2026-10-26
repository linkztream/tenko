//! The offers held in memory (plan section 2.1): a DISCOVER writes nothing to the store, so
//! the address it was offered is held here for the offer lifetime (`[dhcp] offer_secs`,
//! 10 seconds), and the allocator skips it for every other client
//! ([`OfferHold::held_for_other`]).
//!
//! [`OfferTable`] is a fixed table made when the role starts: stripes of slots behind one
//! mutex each, open addressing with a bounded probe, so that holding and looking up an
//! offer never allocates and the workers rarely meet on a lock. A slot holds the scope and
//! the address (as hashes and the address itself), the hash of the client identity it was
//! offered to and the end of the hold. An expired slot is free for reuse; when every slot of
//! a probe window is live, the one that ends first gives way, so a full table forgets the
//! oldest offers first (that client's REQUEST is then checked against the leases as any
//! other is). The worker that offers an address claims it with [`OfferBook::hold`], which
//! fails when another client holds it, so two workers cannot offer one address to two
//! clients.
//!
//! E32: the table is made for the offers the image can need ([`crate::sizing`]) and grows
//! with a new image ([`OfferTable::grow`]): stripe by stripe, a larger stripe is made
//! outside its lock and the live offers move into it under the lock.

use std::{
    net::Ipv4Addr,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

use tenko_core::{PrefixId, Timestamp};

use super::hash;
use crate::allocator::OfferHold;

/// The offers the engine reads and writes.
pub trait OfferBook: OfferHold + Send + Sync {
    /// Holds `addr` of `scope` for the client of `identity` until `until`. False when an
    /// unexpired offer holds it for another client (nothing changes then).
    fn hold(
        &self,
        scope: PrefixId,
        addr: Ipv4Addr,
        identity: &[u8],
        until: Timestamp,
        now: Timestamp,
    ) -> bool;
}

/// How many slots a lookup or an insert looks at.
const PROBE: usize = 16;

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    used: bool,
    scope: u64,
    addr: u32,
    who: u64,
    until: i128,
}

impl Slot {
    fn is_key(&self, scope: u64, addr: u32) -> bool {
        self.used && self.scope == scope && self.addr == addr
    }

    fn live(&self, now: i128) -> bool {
        self.used && self.until > now
    }
}

/// The stripes of the table.
const STRIPES: usize = 64;

/// The reference [`OfferBook`]: fixed stripes of slots.
#[derive(Debug)]
pub struct OfferTable {
    stripes: Box<[Mutex<Box<[Slot]>>]>,
    // E32: the table grows with the image; a stripe's slot count is its own length.
    capacity: AtomicUsize,
}

/// The slots of one stripe for about `capacity` live offers in the whole table.
fn per_stripe(capacity: usize) -> usize {
    (capacity.saturating_mul(2) / STRIPES).max(64)
}

/// The stripe of a scope's hash and an address, and the hash the probe window starts at.
fn spot(scope: u64, addr: u32) -> (usize, u64) {
    let key = hash::mix(scope ^ u64::from(addr));
    // The table is small; the cast keeps the low bits of the hash.
    #[allow(clippy::cast_possible_truncation, reason = "the low bits of a hash")]
    ((key as usize) % STRIPES, key >> 32)
}

/// Where a probe window starts in a stripe of `len` slots.
fn start_in(high: u64, len: usize) -> usize {
    // The stripe is small; the cast keeps the low bits of the hash.
    #[allow(clippy::cast_possible_truncation, reason = "the low bits of a hash")]
    let high = high as usize;
    high % len.max(1)
}

impl OfferTable {
    /// A table for about `capacity` live offers (at least 64 slots per stripe): the
    /// addresses the image can offer ([`crate::sizing`]), or for a load the number of
    /// DISCOVERs a second times the offer lifetime.
    pub fn with_capacity(capacity: usize) -> Self {
        let slots = per_stripe(capacity);
        let stripes = (0..STRIPES)
            .map(|_| Mutex::new(vec![Slot::default(); slots].into_boxed_slice()))
            .collect();
        Self {
            stripes,
            capacity: AtomicUsize::new(capacity),
        }
    }

    /// The live offers the table is made for.
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Relaxed)
    }

    // E32: the offers grow with the image.
    /// Grows the table to about `capacity` live offers; a smaller one changes nothing.
    /// Each stripe is made anew outside its lock and its live offers move in under it, so
    /// the workers wait at most for one stripe's move. Allocates: never on the DORA path.
    pub fn grow(&self, capacity: usize) {
        if capacity <= self.capacity() {
            return;
        }
        let slots = per_stripe(capacity);
        let now = Timestamp::now().unix_nanos();
        for stripe in 0..self.stripes.len() {
            if self.lock(stripe).len() >= slots {
                continue;
            }
            let mut grown = vec![Slot::default(); slots].into_boxed_slice();
            let old = {
                let mut held = self.lock(stripe);
                if held.len() >= slots {
                    continue;
                }
                let len = grown.len();
                for slot in held.iter().filter(|slot| slot.live(now)) {
                    let (_, high) = spot(slot.scope, slot.addr);
                    let start = start_in(high, len);
                    let mut at = start;
                    for step in 0..PROBE.min(len) {
                        let index = (start + step) % len;
                        if !grown[index].used {
                            at = index;
                            break;
                        }
                        if grown[index].until < grown[at].until {
                            at = index;
                        }
                    }
                    grown[at] = *slot;
                }
                std::mem::replace(&mut *held, grown)
            };
            drop(old);
        }
        self.capacity.fetch_max(capacity, Ordering::Relaxed);
    }

    fn place(scope: PrefixId, addr: Ipv4Addr) -> (u64, u32, usize, u64) {
        let scope = hash::of(&scope);
        let addr = u32::from(addr);
        let (stripe, high) = spot(scope, addr);
        (scope, addr, stripe, high)
    }

    fn lock(&self, stripe: usize) -> std::sync::MutexGuard<'_, Box<[Slot]>> {
        self.stripes[stripe]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The number of unexpired offers (for tests and the health view; walks every slot).
    pub fn live(&self, now: Timestamp) -> usize {
        let now = now.unix_nanos();
        (0..self.stripes.len())
            .map(|stripe| self.lock(stripe).iter().filter(|s| s.live(now)).count())
            .sum()
    }
}

impl OfferHold for OfferTable {
    fn held_for_other(
        &self,
        scope: PrefixId,
        addr: Ipv4Addr,
        identity: &[u8],
        now: Timestamp,
    ) -> bool {
        let (scope, addr, stripe, high) = Self::place(scope, addr);
        let now = now.unix_nanos();
        let slots = self.lock(stripe);
        let start = start_in(high, slots.len());
        for step in 0..PROBE.min(slots.len()) {
            let slot = &slots[(start + step) % slots.len()];
            if !slot.used {
                return false;
            }
            if slot.is_key(scope, addr) {
                return slot.live(now) && slot.who != hash::of_bytes(identity);
            }
        }
        false
    }
}

impl OfferBook for OfferTable {
    fn hold(
        &self,
        scope: PrefixId,
        addr: Ipv4Addr,
        identity: &[u8],
        until: Timestamp,
        now: Timestamp,
    ) -> bool {
        let (scope, addr, stripe, high) = Self::place(scope, addr);
        let (now, until) = (now.unix_nanos(), until.unix_nanos());
        let who = hash::of_bytes(identity);
        let mut slots = self.lock(stripe);
        let len = slots.len();
        let start = start_in(high, len);
        let mut free = None;
        let mut oldest = start % len;
        for step in 0..PROBE.min(len) {
            let at = (start + step) % len;
            let slot = slots[at];
            if slot.is_key(scope, addr) {
                if slot.live(now) && slot.who != who {
                    return false;
                }
                free = Some(at);
                break;
            }
            if !slot.live(now) {
                free.get_or_insert(at);
                if !slot.used {
                    break;
                }
            } else if slot.until < slots[oldest].until {
                oldest = at;
            }
        }
        // A key further on in the window would be shadowed by the slot chosen here; the
        // window is walked again to clear it so that one key never sits twice.
        let at = free.unwrap_or(oldest);
        for step in 0..PROBE.min(len) {
            let other = (start + step) % len;
            if other != at && slots[other].is_key(scope, addr) {
                // A tombstone: used (lookups walk past it), expired, no key.
                slots[other] = Slot {
                    used: true,
                    until: i128::MIN,
                    ..Slot::default()
                };
            }
        }
        slots[at] = Slot {
            used: true,
            scope,
            addr,
            who,
            until,
        };
        true
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
    fn an_offer_holds_its_address_for_its_client_until_it_ends() {
        let table = OfferTable::with_capacity(16);
        let scope = PrefixId::generate();
        let addr = Ipv4Addr::new(192, 0, 2, 10);
        assert!(!table.held_for_other(scope, addr, b"a", at(0)));
        assert!(table.hold(scope, addr, b"a", at(10), at(0)));
        assert!(table.held_for_other(scope, addr, b"b", at(5)));
        assert!(!table.held_for_other(scope, addr, b"a", at(5)));
        assert!(!table.hold(scope, addr, b"b", at(15), at(5)));
        // The holder renews it; after the end another client may take it.
        assert!(table.hold(scope, addr, b"a", at(20), at(5)));
        assert!(table.held_for_other(scope, addr, b"b", at(15)));
        assert!(!table.held_for_other(scope, addr, b"b", at(20)));
        assert!(table.hold(scope, addr, b"b", at(30), at(20)));
        assert!(table.held_for_other(scope, addr, b"a", at(21)));
        assert_eq!(table.live(at(21)), 1);
        // Another scope's address is another key.
        assert!(!table.held_for_other(PrefixId::generate(), addr, b"a", at(21)));
    }

    #[test]
    fn a_full_table_forgets_the_oldest_offers_first() {
        let table = OfferTable::with_capacity(1);
        let scope = PrefixId::generate();
        for host in 0..20_000u32 {
            let addr = Ipv4Addr::from(0xc000_0000 + host);
            let identity = host.to_be_bytes();
            assert!(table.hold(scope, addr, &identity, at(100 + u64::from(host)), at(0)));
        }
        // The last offers are still held; the table is bounded.
        let last = Ipv4Addr::from(0xc000_0000 + 19_999);
        assert!(table.held_for_other(scope, last, b"x", at(1)));
        assert!(table.live(at(1)) <= 64 * 64);
    }

    #[test]
    fn a_grown_table_keeps_its_offers_and_holds_more() {
        let table = OfferTable::with_capacity(1);
        let scope = PrefixId::generate();
        let now = Timestamp::now();
        let until = now.checked_add(Duration::from_secs(600)).expect("a time");
        for host in 0..2_000u32 {
            let addr = Ipv4Addr::from(0xc000_0000 + host);
            assert!(table.hold(scope, addr, &host.to_be_bytes(), until, now));
        }
        let before = table.live(now);
        table.grow(100_000);
        assert_eq!(table.capacity(), 100_000);
        assert_eq!(table.live(now), before, "every live offer moved");
        for host in 0..2_000u32 {
            let addr = Ipv4Addr::from(0xc000_0000 + host);
            let identity = host.to_be_bytes();
            if table.held_for_other(scope, addr, b"another", now) {
                assert!(!table.held_for_other(scope, addr, &identity, now));
            }
        }
        for host in 2_000..60_000u32 {
            let addr = Ipv4Addr::from(0xc000_0000 + host);
            assert!(table.hold(scope, addr, &host.to_be_bytes(), until, now));
        }
        assert!(
            table.live(now) > 55_000,
            "room for the larger image's offers"
        );
        table.grow(10);
        assert_eq!(table.capacity(), 100_000, "it never shrinks");
    }
}
