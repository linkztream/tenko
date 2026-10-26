//! Address allocation (plan sections 2.3 and 2.12): which address a client gets.
//!
//! The order is fixed by the plan: the client's reservation wins; then its unexpired lease;
//! then the address it asks for (option 50 or `ciaddr`) when that one is free; then a free
//! address of a pool. An address is free when it lies in a pool of the scope, is not
//! excluded, is not reserved for another client, no committed lease of another client
//! blocks it, no unexpired offer holds it for another client ([`OfferHold`]) and this node
//! owns it ([`PoolOwnership`]). Every lease time comes from [`grant_time`].
//!
//! [`ReferenceAllocator`] walks the pools in address order and is the oracle; WP7.3's
//! allocator walks them in a hashed order (so two nodes in Phase 5 do not collide on the
//! lowest free address) and must agree with it on every rule above. Neither allocates.

use std::net::Ipv4Addr;

use tenko_core::{PrefixId, Timestamp, dhcp::LeaseTimes};

use crate::{
    image::{ConfigImage, PoolImage, ReservationImage, ScopeImage},
    lease::{LeaseTable, LeaseView},
};

// WP8.4: the class and policy restrictions on which addresses a client may get.
/// Which addresses a client may be given beyond the rules of the module comment: the
/// classes a scope or a pool admits and the address ranges of policies (plan section 2.4,
/// [`crate::class`]). Reservations are not subject to it.
pub trait Admission {
    /// Whether `addr` of `scope` may go to the client.
    fn admits(&self, scope: &ScopeImage, addr: Ipv4Addr) -> bool;

    /// Whether `pool` may give the client any address; a pool it refuses is not walked.
    fn admits_pool(&self, scope: &ScopeImage, pool: &PoolImage) -> bool {
        let _ = (scope, pool);
        true
    }
}

/// No restriction: every address the other rules allow.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdmitAll;

impl Admission for AdmitAll {
    fn admits(&self, _scope: &ScopeImage, _addr: Ipv4Addr) -> bool {
        true
    }
}

impl Admission for crate::class::Decision<'_> {
    fn admits(&self, scope: &ScopeImage, addr: Ipv4Addr) -> bool {
        crate::class::Decision::admits(self, scope, addr)
    }

    fn admits_pool(&self, scope: &ScopeImage, pool: &PoolImage) -> bool {
        crate::class::Decision::admits_pool(self, scope, pool)
    }
}

/// Which addresses this node may hand out (plan section 2.12). On one node every address
/// is the node's ([`SingleNode`]); in Phase 5 the RFC 3074 bucket of the client in load
/// balance, or the backup share in hot standby, answers.
pub trait PoolOwnership: Send + Sync {
    /// Whether this node may offer `addr` of `scope` to the client of `identity`.
    fn owns(&self, scope: PrefixId, addr: Ipv4Addr, identity: &[u8]) -> bool;
}

/// One node: every address is its own.
#[derive(Debug, Clone, Copy, Default)]
pub struct SingleNode;

impl PoolOwnership for SingleNode {
    fn owns(&self, _scope: PrefixId, _addr: Ipv4Addr, _identity: &[u8]) -> bool {
        true
    }
}

/// What the failover partner acknowledged, for [`grant_time`] (Phase 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartnerLimit {
    /// Seconds from now until the end the partner acknowledged for the binding (zero for a
    /// new binding).
    pub acknowledged_secs: u32,
    /// The maximum client lead time.
    pub mclt_secs: u32,
}

/// The lease time to grant (plan section 2.12): the scope's rule for the requested time,
/// and with a failover partner at most the acknowledged end plus the MCLT. On one node
/// `partner` is `None`.
pub fn grant_time(
    times: &LeaseTimes,
    requested: Option<u32>,
    partner: Option<PartnerLimit>,
) -> u32 {
    let granted = times.grant(requested);
    match partner {
        Some(limit) => granted.min(limit.acknowledged_secs.saturating_add(limit.mclt_secs)),
        None => granted,
    }
}

/// Offers held in memory for their lifetime (plan section 2.1): a DISCOVER writes nothing,
/// so the allocator asks the hold whether another client was offered an address.
pub trait OfferHold {
    /// Whether an unexpired offer holds `addr` of `scope` for a client other than
    /// `identity`.
    fn held_for_other(
        &self,
        scope: PrefixId,
        addr: Ipv4Addr,
        identity: &[u8],
        now: Timestamp,
    ) -> bool;
}

/// No offers held.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOffers;

impl OfferHold for NoOffers {
    fn held_for_other(&self, _: PrefixId, _: Ipv4Addr, _: &[u8], _: Timestamp) -> bool {
        false
    }
}

/// What the allocator reads for one request.
pub struct Request<'a> {
    /// The image.
    pub image: &'a ConfigImage,
    /// The selected scope.
    pub scope: &'a ScopeImage,
    /// The client identity (`ClientKey::identity`).
    pub identity: &'a [u8],
    // WP8.4: the hardware identity for MAC-keyed reservations, and the admission.
    /// The client's hardware identity (`0`, `htype`, `chaddr`), which a reservation keyed by
    /// MAC holds; equal to `identity` for a client without option 61.
    pub hardware: &'a [u8],
    /// The class and policy restrictions ([`AdmitAll`] for none).
    pub admission: &'a dyn Admission,
    /// The address the client asks for.
    pub requested: Option<Ipv4Addr>,
    /// The leases.
    pub leases: &'a dyn LeaseTable,
    /// The offers held.
    pub offers: &'a dyn OfferHold,
    /// The ownership rule.
    pub ownership: &'a dyn PoolOwnership,
    /// Now.
    pub now: Timestamp,
}

impl<'a> Request<'a> {
    /// Whether `addr` may be given to this client: the rules of the module comment.
    pub fn is_free(&self, scope: &ScopeImage, addr: Ipv4Addr) -> bool {
        if !scope.is_dynamic(addr) {
            return false;
        }
        // WP8.4: reserved for another client; the client's own reservation is found by
        // identity or by hardware address.
        if let Some(reservation) = self.image.reserved_at(scope.prefix, addr)
            && !self.is_own(reservation)
        {
            return false;
        }
        if self
            .leases
            .get(scope.vrf, addr)
            .is_some_and(|lease| lease.blocks(self.now) && !is_client(&lease, self.identity))
        {
            return false;
        }
        !self
            .offers
            .held_for_other(scope.prefix, addr, self.identity, self.now)
            && self.ownership.owns(scope.prefix, addr, self.identity)
            // WP8.4: the classes and the policy ranges.
            && self.admission.admits(scope, addr)
    }

    // WP8.4: reservations by identity or by hardware address.
    /// The client's reservation in the scope or its siblings
    /// ([`ConfigImage::client_reservation`]).
    pub fn reservation(&self) -> Option<&'a ReservationImage> {
        self.image
            .client_reservation(self.scope, self.identity, self.hardware)
    }

    /// Whether `reservation` is the client's own.
    fn is_own(&self, reservation: &ReservationImage) -> bool {
        reservation.identity == self.identity
            || (reservation.identity == self.hardware
                && self
                    .reservation()
                    .is_some_and(|own| std::ptr::eq(own, reservation)))
    }
}

fn is_client(lease: &LeaseView<'_>, identity: &[u8]) -> bool {
    lease.client.is(identity)
}

/// Why the allocator chose an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// The client's reservation.
    Reservation(Ipv4Addr),
    /// The client's unexpired lease.
    Lease(Ipv4Addr),
    /// The address the client asked for.
    Requested(Ipv4Addr),
    /// A free pool address.
    Pool(Ipv4Addr),
}

impl Choice {
    /// The address.
    pub fn addr(self) -> Ipv4Addr {
        match self {
            Self::Reservation(addr)
            | Self::Lease(addr)
            | Self::Requested(addr)
            | Self::Pool(addr) => addr,
        }
    }
}

/// Picks an address for a request.
pub trait Allocator {
    /// The address for the request and why; `None` when the scope and its siblings have
    /// no free address (the request is dropped and counted).
    fn pick(&self, request: &Request<'_>) -> Option<Choice>;
}

/// The reference allocator: the plan's order, pools walked in address order.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReferenceAllocator;

impl Allocator for ReferenceAllocator {
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
        for scope in image.siblings(request.scope) {
            // WP8.4: the pools the client's classes and policies keep it out of.
            for pool in scope
                .pools
                .iter()
                .filter(|pool| request.admission.admits_pool(scope, pool))
            {
                let (first, last) = (u32::from(pool.first), u32::from(pool.last));
                for raw in first..=last {
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
