//! The addresses an ADVERTISE offered, held in memory for the offer lifetime (`[dhcp]
//! offer_secs`): a SOLICIT writes nothing to the store (plan section 2.1), and the
//! allocator skips an address held for another client, so that two clients soliciting at
//! once are not offered one address. The table of [`crate::v4::engine::OfferTable`] with
//! IPv6 addresses: fixed stripes of slots behind one mutex each, a bounded probe, no
//! allocation; a full window forgets the offer that ends first.
//!
//! A declined address that yielded in a full scope is parked for no client
//! ([`Offers6::park`]). A park never costs a client anything: it takes only a free slot, and
//! a client's offer that meets a full window takes the park that ends first before it
//! forgets another client's offer.

use std::{
    net::Ipv6Addr,
    sync::{Mutex, PoisonError},
};

use tenko_core::{PrefixId, Timestamp};

use crate::v4::engine::hash_of_bytes;

/// How many slots a lookup or an insert looks at.
const PROBE: usize = 16;

/// The holder of a parked address: no client identity is three octets long (an IAID and a
/// DUID are at least six).
const PARKED: &[u8] = b"\xff\xff\xff";

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    used: bool,
    scope: u64,
    addr: u128,
    who: u64,
    until: i128,
    parked: bool,
}

impl Slot {
    fn live(&self, now: i128) -> bool {
        self.used && self.until > now
    }
}

/// The DHCPv6 offers held.
#[derive(Debug)]
pub struct Offers6 {
    stripes: Box<[Mutex<Box<[Slot]>>]>,
    slots_per_stripe: usize,
}

fn nanos(at: Timestamp) -> i128 {
    at.unix_nanos()
}

impl Offers6 {
    /// A table for about `capacity` live offers.
    pub fn with_capacity(capacity: usize) -> Self {
        let stripes = 64;
        let slots_per_stripe = (capacity.saturating_mul(2) / stripes).max(64);
        Self {
            stripes: (0..stripes)
                .map(|_| Mutex::new(vec![Slot::default(); slots_per_stripe].into_boxed_slice()))
                .collect(),
            slots_per_stripe,
        }
    }

    fn place(&self, scope: PrefixId, addr: Ipv6Addr) -> (u64, u128, usize, usize) {
        let scope_hash = hash_of_bytes(scope.0.as_bytes());
        let addr = u128::from(addr);
        let mixed = scope_hash ^ hash_of_bytes(&addr.to_be_bytes());
        let stripe = usize::try_from(mixed % self.stripes.len() as u64).unwrap_or(0);
        let start = usize::try_from((mixed >> 8) % self.slots_per_stripe as u64).unwrap_or(0);
        (scope_hash, addr, stripe, start)
    }

    /// Holds `addr` of `scope` for the client of `identity` until `until`; false when an
    /// unexpired offer holds it for another client.
    pub fn hold(
        &self,
        scope: PrefixId,
        addr: Ipv6Addr,
        identity: &[u8],
        until: Timestamp,
        now: Timestamp,
    ) -> bool {
        let (scope_hash, addr, stripe, start) = self.place(scope, addr);
        let who = hash_of_bytes(identity);
        let now = nanos(now);
        let mut slots = self.stripes[stripe]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let len = slots.len();
        let mut free = None;
        let mut oldest = (i128::MAX, start);
        let mut parked = (i128::MAX, None);
        for step in 0..PROBE.min(len) {
            let at = (start + step) % len;
            let slot = slots[at];
            if slot.used && slot.scope == scope_hash && slot.addr == addr {
                if slot.live(now) && slot.who != who {
                    return false;
                }
                slots[at] = Slot {
                    used: true,
                    scope: scope_hash,
                    addr,
                    who,
                    until: nanos(until),
                    parked: false,
                };
                return true;
            }
            if !slot.live(now) && free.is_none() {
                free = Some(at);
            }
            if slot.parked && slot.until < parked.0 {
                parked = (slot.until, Some(at));
            }
            if slot.until < oldest.0 {
                oldest = (slot.until, at);
            }
        }
        // A full window gives up a parked address before another client's offer.
        let at = free.or(parked.1).unwrap_or(oldest.1);
        slots[at] = Slot {
            used: true,
            scope: scope_hash,
            addr,
            who,
            until: nanos(until),
            parked: false,
        };
        true
    }

    /// Parks `addr` of `scope` for no client until `until`, in a free slot only: in a full
    /// window nothing is placed, and the address may be offered again. False then, and when
    /// a client's live offer holds the address.
    pub fn park(&self, scope: PrefixId, addr: Ipv6Addr, until: Timestamp, now: Timestamp) -> bool {
        let (scope_hash, addr, stripe, start) = self.place(scope, addr);
        let now = nanos(now);
        let mut slots = self.stripes[stripe]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let len = slots.len();
        let mut free = None;
        for step in 0..PROBE.min(len) {
            let at = (start + step) % len;
            let slot = slots[at];
            if slot.used && slot.scope == scope_hash && slot.addr == addr {
                if slot.live(now) && !slot.parked {
                    return false;
                }
                free = Some(at);
                break;
            }
            if !slot.live(now) && free.is_none() {
                free = Some(at);
            }
        }
        let Some(at) = free else {
            return false;
        };
        slots[at] = Slot {
            used: true,
            scope: scope_hash,
            addr,
            who: hash_of_bytes(PARKED),
            until: nanos(until),
            parked: true,
        };
        true
    }

    /// Whether `addr` of `scope` is held at `now` for the client of `identity` itself.
    pub fn held_for(
        &self,
        scope: PrefixId,
        addr: Ipv6Addr,
        identity: &[u8],
        now: Timestamp,
    ) -> bool {
        let (scope_hash, addr, stripe, start) = self.place(scope, addr);
        let who = hash_of_bytes(identity);
        let now = nanos(now);
        let slots = self.stripes[stripe]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let len = slots.len();
        (0..PROBE.min(len)).any(|step| {
            let slot = slots[(start + step) % len];
            slot.used
                && slot.scope == scope_hash
                && slot.addr == addr
                && slot.live(now)
                && slot.who == who
        })
    }

    /// Whether `addr` of `scope` is held at `now` for a client other than `identity`.
    pub fn held_for_other(
        &self,
        scope: PrefixId,
        addr: Ipv6Addr,
        identity: &[u8],
        now: Timestamp,
    ) -> bool {
        let (scope_hash, addr, stripe, start) = self.place(scope, addr);
        let who = hash_of_bytes(identity);
        let now = nanos(now);
        let slots = self.stripes[stripe]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let len = slots.len();
        (0..PROBE.min(len)).any(|step| {
            let slot = slots[(start + step) % len];
            slot.used
                && slot.scope == scope_hash
                && slot.addr == addr
                && slot.live(now)
                && slot.who != who
        })
    }

    /// Drops the offers that ended; how many.
    pub fn prune(&self, now: Timestamp) -> usize {
        let now = nanos(now);
        let mut pruned = 0;
        for stripe in &self.stripes {
            let mut slots = stripe.lock().unwrap_or_else(PoisonError::into_inner);
            for slot in slots.iter_mut() {
                if slot.used && !slot.live(now) {
                    slot.used = false;
                    pruned += 1;
                }
            }
        }
        pruned
    }

    /// The offers live at `now`.
    pub fn live(&self, now: Timestamp) -> usize {
        let now = nanos(now);
        self.stripes
            .iter()
            .map(|stripe| {
                stripe
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                    .filter(|slot| slot.live(now))
                    .count()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn an_offer_holds_its_address_for_its_client_until_it_ends() {
        let offers = Offers6::with_capacity(16);
        let scope = PrefixId::generate();
        let addr: Ipv6Addr = "2001:db8::10".parse().expect("addr");
        let now = Timestamp::now();
        let until = now.checked_add(Duration::from_secs(10)).expect("later");
        assert!(offers.hold(scope, addr, b"a", until, now));
        assert!(offers.hold(scope, addr, b"a", until, now));
        assert!(!offers.hold(scope, addr, b"b", until, now));
        assert!(offers.held_for_other(scope, addr, b"b", now));
        assert!(!offers.held_for_other(scope, addr, b"a", now));
        let later = until.checked_add(Duration::from_secs(1)).expect("later");
        assert!(!offers.held_for_other(scope, addr, b"b", later));
        assert!(offers.hold(scope, addr, b"b", later, later));
        assert_eq!(offers.live(now), 1);
        assert_eq!(
            offers.prune(later.checked_add(Duration::from_secs(1)).expect("x")),
            1
        );
    }

    /// The `n`th address of the tests below.
    fn addr(n: u32) -> Ipv6Addr {
        Ipv6Addr::from(0x2001_0db8_0001_0000_0000_0000_0000_0000_u128 + u128::from(n))
    }

    fn at(now: Timestamp, secs: u64) -> Timestamp {
        now.checked_add(Duration::from_secs(secs)).expect("later")
    }

    #[test]
    fn parked_addresses_never_cost_a_client_its_offer() {
        // The smallest table: 64 stripes of 64 slots. Two bursts of parks, each as large as
        // the table, held for a day, fill every window.
        let offers = Offers6::with_capacity(1);
        let scope = PrefixId::from_uuid(uuid::Uuid::nil());
        let now = Timestamp::now();
        for n in 0..8_192 {
            offers.park(scope, addr(n), at(now, 86_400), now);
        }
        assert!(offers.live(now) > 4_096 * 9 / 10, "{}", offers.live(now));
        // Clients' offers then take the parks' slots, never one another's.
        let clients: Vec<u32> = (100_000..100_512).collect();
        for n in &clients {
            assert!(offers.hold(scope, addr(*n), &n.to_be_bytes(), at(now, 10), now));
        }
        for n in &clients {
            assert!(
                offers.held_for(scope, addr(*n), &n.to_be_bytes(), now),
                "{n}"
            );
        }
        // The parked address itself goes to no client.
        let parked = (0..8_192)
            .map(addr)
            .find(|a| offers.held_for_other(scope, *a, b"client", now))
            .expect("a park kept");
        assert!(!offers.hold(scope, parked, b"client", at(now, 10), now));
    }

    #[test]
    fn a_park_meeting_a_window_of_offers_is_not_placed() {
        let offers = Offers6::with_capacity(1);
        let scope = PrefixId::from_uuid(uuid::Uuid::nil());
        let now = Timestamp::now();
        for n in 0..8_192u32 {
            offers.hold(scope, addr(n), &n.to_be_bytes(), at(now, 10), now);
        }
        let kept: Vec<u32> = (0..8_192u32)
            .filter(|n| offers.held_for(scope, addr(*n), &n.to_be_bytes(), now))
            .collect();
        let placed = (100_000..105_000)
            .filter(|n| offers.park(scope, addr(*n), at(now, 86_400), now))
            .count();
        // A park took only a slot no offer held, and every offer stays.
        assert!(placed <= 4_096 - kept.len(), "{placed} of {}", kept.len());
        assert_eq!(offers.live(now), kept.len() + placed);
        for n in &kept {
            assert!(
                offers.held_for(scope, addr(*n), &n.to_be_bytes(), now),
                "{n}"
            );
        }
    }
}
