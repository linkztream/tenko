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

use tenko_core::{
    PrefixId, Timestamp,
    dhcp::{Lease, LeaseTimes},
};

use crate::{
    image::{ConfigImage, ScopeImage},
    lease::LeaseTable,
};

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

impl Request<'_> {
    /// Whether `addr` may be given to this client: the rules of the module comment.
    pub fn is_free(&self, scope: &ScopeImage, addr: Ipv4Addr) -> bool {
        if !scope.is_dynamic(addr) {
            return false;
        }
        if self
            .image
            .reserved_at(scope.prefix, addr)
            .is_some_and(|reservation| reservation.identity != self.identity)
        {
            return false;
        }
        if self
            .leases
            .get(scope.vrf, addr)
            .is_some_and(|lease| lease.blocks(self.now) && !is_client(lease, self.identity))
        {
            return false;
        }
        !self
            .offers
            .held_for_other(scope.prefix, addr, self.identity, self.now)
            && self.ownership.owns(scope.prefix, addr, self.identity)
    }
}

fn is_client(lease: &Lease, identity: &[u8]) -> bool {
    let mut held = [0u8; tenko_core::dhcp::lease::MAX_IDENTITY];
    let len = tenko_core::dhcp::write_identity(
        lease.client.htype,
        &lease.client.chaddr.0,
        lease.client.client_id.as_ref().map(|id| id.0.as_slice()),
        &mut held,
    );
    &held[..len] == identity
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
        for scope in image.siblings(request.scope) {
            if let Some(reservation) = image.reservation(scope.prefix, request.identity) {
                return Some(Choice::Reservation(reservation.addr));
            }
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
            for pool in &scope.pools {
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
