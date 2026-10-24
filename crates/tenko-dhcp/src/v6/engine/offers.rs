//! The addresses an ADVERTISE offered, held in memory for the offer lifetime (`[dhcp]
//! offer_secs`): a SOLICIT writes nothing to the store (plan section 2.1), and the
//! allocator skips an address held for another client, so that two clients soliciting at
//! once are not offered one address. The table of [`crate::v4::engine::OfferTable`] with
//! IPv6 addresses: fixed stripes of slots behind one mutex each, a bounded probe, no
//! allocation; a full window forgets the offer that ends first.

use std::{
    net::Ipv6Addr,
    sync::{Mutex, PoisonError},
};

use tenko_core::{PrefixId, Timestamp};

use crate::v4::engine::hash_of_bytes;

/// How many slots a lookup or an insert looks at.
const PROBE: usize = 16;

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    used: bool,
    scope: u64,
    addr: u128,
    who: u64,
    until: i128,
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
                };
                return true;
            }
            if !slot.live(now) && free.is_none() {
                free = Some(at);
            }
            if slot.until < oldest.0 {
                oldest = (slot.until, at);
            }
        }
        let at = free.unwrap_or(oldest.1);
        slots[at] = Slot {
            used: true,
            scope: scope_hash,
            addr,
            who,
            until: nanos(until),
        };
        true
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
}
