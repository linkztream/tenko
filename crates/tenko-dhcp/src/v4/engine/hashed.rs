//! The allocator of the engine (plan sections 2.3 and 2.12): the order of
//! [`ReferenceAllocator`](crate::allocator::ReferenceAllocator) for the reservation, the
//! client's unexpired lease and the address it asks for, and then the pools walked in a
//! hashed order instead of from the lowest address.
//!
//! Each client starts its walk of a pool at a point the hash of its identity and the pool's
//! place give, and goes on upwards, wrapping at the end of the pool. Two effects follow: two
//! nodes of a Phase 5 pair (each owning a part of the pool through
//! [`PoolOwnership`](crate::allocator::PoolOwnership)) do not both reach for the lowest free
//! address, and a client that comes back after its lease ended finds its old address first
//! when nobody took it, without a rule of its own. Every address the walk considers passes
//! [`Request::is_free`], the rules the reference allocator keeps, so the two agree on
//! everything but which free pool address comes first (`tests/engine_allocator.rs`).

use std::net::Ipv4Addr;

use super::hash;
use crate::allocator::{Allocator, Choice, Request};

/// The hashed-order allocator.
#[derive(Debug, Clone, Copy, Default)]
pub struct HashedAllocator;

impl HashedAllocator {
    /// Where the client of `identity` starts in pool `index` of `size` addresses.
    pub fn start(identity: &[u8], index: usize, size: u64) -> u64 {
        let seed = hash::of_bytes(identity) ^ hash::mix(index as u64 + 1);
        hash::mix(seed) % size.max(1)
    }
}

impl Allocator for HashedAllocator {
    fn pick(&self, request: &Request<'_>) -> Option<Choice> {
        let image = request.image;
        // WP8.4: by client identity, then by hardware address.
        if let Some(reservation) = request.reservation() {
            return Some(Choice::Reservation(reservation.addr));
        }
        for scope in image.siblings(request.scope) {
            if let Some(lease) = request.leases.by_client(scope.prefix, request.identity)
                && lease.is_bound(request.now)
                && request.is_free(scope, lease.addr)
            {
                return Some(Choice::Lease(lease.addr));
            }
        }
        if let Some(asked) = request.requested {
            for scope in image.siblings(request.scope) {
                if scope.network.contains(&asked) && request.is_free(scope, asked) {
                    return Some(Choice::Requested(asked));
                }
            }
        }
        let mut index = 0;
        for scope in image.siblings(request.scope) {
            for pool in &scope.pools {
                let size = pool.size();
                let start = Self::start(request.identity, index, size);
                index += 1;
                // WP8.4: a pool the client's classes and policies keep it out of (after
                // the index, so a client's starts do not move with its classes).
                if !request.admission.admits_pool(scope, pool) {
                    continue;
                }
                let first = u64::from(u32::from(pool.first));
                for step in 0..size {
                    let offset = (start + step) % size;
                    let Ok(raw) = u32::try_from(first + offset) else {
                        continue;
                    };
                    let addr = Ipv4Addr::from(raw);
                    if request.is_free(scope, addr) {
                        return Some(Choice::Pool(addr));
                    }
                }
            }
        }
        None
    }
}
