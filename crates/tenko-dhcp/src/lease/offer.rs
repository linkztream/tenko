//! The offer hold (plan section 2.1): an OFFER writes nothing to the store; the offered
//! address is held in the role's memory for the offer lifetime (`[dhcp] offer_secs`,
//! default 10 s), so that another client is not offered it meanwhile. A crash forgets only
//! offers.
//!
//! [`OfferTable`] is the hold: a map by scope and address with the client's identity
//! inline and the end of the offer, allocated once for a fixed number of offers so that
//! holding an address on the DISCOVER path never allocates. When it is full, expired
//! offers are dropped first; if none has expired, [`OfferTable::hold`] refuses and the
//! DISCOVER is dropped as `pool_full` (more open offers than the table was sized for).
//! Expiry prunes it on its timer ([`OfferTable::prune`]).

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Mutex, PoisonError},
    time::Duration,
};

use tenko_core::{PrefixId, Timestamp};

use super::InlineBytes;
use crate::allocator::OfferHold;
use tenko_core::dhcp::lease::MAX_IDENTITY;

/// The default offer lifetime.
pub const OFFER_SECS: u64 = 10;

/// The default number of open offers the hold has room for.
pub const OFFER_CAPACITY: usize = 16_384;

#[derive(Debug, Clone, Copy)]
struct Offer {
    identity: InlineBytes<MAX_IDENTITY>,
    until: Timestamp,
}

/// Offers held in memory for their lifetime.
#[derive(Debug)]
pub struct OfferTable {
    lifetime: Duration,
    capacity: usize,
    offers: Mutex<HashMap<(PrefixId, Ipv4Addr), Offer>>,
}

impl Default for OfferTable {
    fn default() -> Self {
        Self::new(Duration::from_secs(OFFER_SECS), OFFER_CAPACITY)
    }
}

impl OfferTable {
    /// A hold of `capacity` offers that last `lifetime` each.
    pub fn new(lifetime: Duration, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            lifetime,
            capacity,
            // Twice the room: at most half full, so a rehash after many removals happens in
            // place and never allocates.
            offers: Mutex::new(HashMap::with_capacity(capacity.saturating_mul(2))),
        }
    }

    /// The offer lifetime.
    pub fn lifetime(&self) -> Duration {
        self.lifetime
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(PrefixId, Ipv4Addr), Offer>> {
        self.offers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Holds `addr` of `scope` for the client of `identity` from `now` for the lifetime
    /// (a new offer to the same client extends it). Returns `false` when another client's
    /// unexpired offer holds the address, or when the table is full of unexpired offers.
    /// Does not allocate.
    pub fn hold(&self, scope: PrefixId, addr: Ipv4Addr, identity: &[u8], now: Timestamp) -> bool {
        let Some(until) = now.checked_add(self.lifetime) else {
            return false;
        };
        let mut offers = self.lock();
        if let Some(held) = offers.get_mut(&(scope, addr)) {
            if held.until > now && held.identity.as_slice() != identity {
                return false;
            }
            held.identity.set(identity);
            held.until = until;
            return true;
        }
        if offers.len() >= self.capacity {
            offers.retain(|_, offer| offer.until > now);
            if offers.len() >= self.capacity {
                return false;
            }
        }
        offers.insert(
            (scope, addr),
            Offer {
                identity: InlineBytes::new(identity).0,
                until,
            },
        );
        true
    }

    /// Ends the offer of an address (the client's REQUEST committed, or it declined).
    pub fn release(&self, scope: PrefixId, addr: Ipv4Addr) {
        self.lock().remove(&(scope, addr));
    }

    /// Drops the offers that ended at `now`; returns how many are left.
    pub fn prune(&self, now: Timestamp) -> usize {
        let mut offers = self.lock();
        offers.retain(|_, offer| offer.until > now);
        offers.len()
    }

    /// The offers held, expired or not.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no offer is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
        self.lock()
            .get(&(scope, addr))
            .is_some_and(|offer| offer.until > now && offer.identity.as_slice() != identity)
    }
}
