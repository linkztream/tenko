//! The DHCPv6 allocator (plan section 2.3): for one `IA_NA`, the client's reservation, its
//! bound lease, an address it hinted in the IA when that one is free, then a free pool
//! address walked in a hashed order, as the DHCPv4 [`HashedAllocator`] walks.
//!
//! A pool of a /64 has 2^64 addresses, so the walk does not visit every one: it starts at
//! the point the hash of the client's identity (IAID and DUID) gives and probes at most
//! [`MAX_PROBES`] addresses from there. In a pool that is mostly free the first probe is
//! the address, and a client that comes back after its lease ended finds its old address
//! first when nobody took it.
//!
//! Free means: inside a pool of the scope (or a sibling of its shared network), not
//! excluded, not another client's reservation, no other client's unexpired binding or
//! abandoned address, no other client's offer, and not taken by another IA of the same
//! message.
//!
//! For an `IA_PD` (WP9.2), [`pick_pd`] does the same over the prefixes of the delegation
//! pools: the client's bound prefix, a hinted prefix when free, then a hashed walk over the
//! pool's prefixes of its delegated length.
//!
//! [`HashedAllocator`]: crate::v4::engine::HashedAllocator

use std::net::Ipv6Addr;

use tenko_core::dhcp::{
    BindingState, Lease6Kind, LeaseTimes, OptionValue,
    lease::{MAX_IDENTITY6, write_identity6},
};

use super::Context6;
use crate::v4::engine::{hash_mix, hash_of_bytes};
use crate::v6::image::{PdPool6Image, Pool6Image, Scope6Image};

/// How many pool addresses the walk looks at for one IA.
pub const MAX_PROBES: u128 = 4_096;

/// Where an address came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The client's reservation.
    Reservation,
    /// The client's bound lease.
    Lease,
    /// An address the client put in the IA.
    Hint,
    /// The pool.
    Pool,
}

/// An address for one IA.
#[derive(Debug, Clone, Copy)]
pub struct Pick<'a> {
    /// The scope that holds it.
    pub home: &'a Scope6Image,
    /// The address.
    pub addr: Ipv6Addr,
    /// Where it came from.
    pub source: Source,
    /// The reservation's options, for a reserved address.
    pub host_options: Option<&'a [OptionValue]>,
}

/// The client as the allocator sees it.
#[derive(Debug, Clone, Copy)]
pub struct Client<'c> {
    /// The DUID.
    pub duid: &'c [u8],
    /// The client's Ethernet address, when known.
    pub mac: Option<[u8; 6]>,
}

/// The identity of a binding: IAID and DUID.
pub fn identity(iaid: u32, duid: &[u8], out: &mut [u8; MAX_IDENTITY6]) -> usize {
    write_identity6(iaid, duid, out)
}

/// Whether `addr` of `scope` may go to the client of `identity` now, apart from the pool
/// rule: no other client's reservation, binding, abandoned address or offer, and not taken.
fn available(
    ctx: &Context6<'_>,
    scope: &Scope6Image,
    addr: Ipv6Addr,
    client: Client<'_>,
    (iaid, identity): (u32, &[u8]),
    taken: &[Ipv6Addr],
) -> bool {
    if taken.contains(&addr) {
        return false;
    }
    if let Some(reservation) = ctx.image.v6().reserved_at(scope.prefix, addr) {
        let mine = match &reservation.key {
            crate::v6::image::Reservation6Key::Duid(duid) => duid.as_slice() == client.duid,
            crate::v6::image::Reservation6Key::Mac(mac) => Some(*mac) == client.mac,
        };
        if !mine {
            return false;
        }
    }
    if let Some(lease) = ctx.leases.get(scope.vrf, addr)
        && lease.blocks(ctx.now)
        && (lease.state == BindingState::Abandoned
            || lease.iaid != iaid
            || lease.duid.as_bytes() != client.duid)
    {
        return false;
    }
    !ctx.offers
        .held_for_other(scope.prefix, addr, identity, ctx.now)
}

/// Whether `addr` is a free dynamic address of `scope` for the client.
pub fn is_free(
    ctx: &Context6<'_>,
    scope: &Scope6Image,
    addr: Ipv6Addr,
    client: Client<'_>,
    who: (u32, &[u8]),
    taken: &[Ipv6Addr],
) -> bool {
    scope.is_dynamic(addr) && available(ctx, scope, addr, client, who, taken)
}

/// Where the client of `identity` starts in pool `index` of `size` addresses.
pub fn start(identity: &[u8], index: usize, size: u128) -> u128 {
    let seed = hash_of_bytes(identity) ^ hash_mix(index as u64 + 1);
    let high = u128::from(hash_mix(seed));
    let low = u128::from(hash_mix(seed ^ 0x9e37_79b9_7f4a_7c15));
    ((high << 64) | low) % size.max(1)
}

/// The address for the IA `iaid` of the client in `scope` (and its siblings), or none.
pub fn pick<'a>(
    ctx: &Context6<'a>,
    client: Client<'_>,
    scope: &'a Scope6Image,
    iaid: u32,
    hints: &[Ipv6Addr],
    taken: &[Ipv6Addr],
) -> Option<Pick<'a>> {
    let image = ctx.image.v6();
    let mut buf = [0u8; MAX_IDENTITY6];
    let len = identity(iaid, client.duid, &mut buf);
    let identity = &buf[..len];
    let who = (iaid, identity);
    if let Some(reservation) = image.client_reservation(scope, client.duid, client.mac)
        && let Some(home) = image
            .siblings(scope)
            .find(|sibling| sibling.prefix == reservation.scope)
        && available(ctx, home, reservation.addr, client, who, taken)
    {
        return Some(Pick {
            home,
            addr: reservation.addr,
            source: Source::Reservation,
            host_options: Some(reservation.options.as_slice()),
        });
    }
    for sibling in image.siblings(scope) {
        if let Some(lease) = ctx
            .leases
            .by_client(sibling.prefix, Lease6Kind::Na, identity)
            && lease.is_bound(ctx.now)
            && is_free(ctx, sibling, lease.addr6(), client, who, taken)
        {
            return Some(Pick {
                home: sibling,
                addr: lease.addr6(),
                source: Source::Lease,
                host_options: None,
            });
        }
    }
    for hint in hints {
        if let Some(home) = image
            .siblings(scope)
            .find(|sibling| sibling.network.contains(hint))
            && is_free(ctx, home, *hint, client, who, taken)
        {
            return Some(Pick {
                home,
                addr: *hint,
                source: Source::Hint,
                host_options: None,
            });
        }
    }
    let mut index = 0;
    for sibling in image.siblings(scope) {
        for pool in &sibling.pools {
            let size = pool.size();
            let first = u128::from(pool.first);
            let from = start(identity, index, size);
            index += 1;
            for step in 0..size.min(MAX_PROBES) {
                let offset = (from + step) % size;
                let addr = Ipv6Addr::from(first.saturating_add(offset));
                if is_free(ctx, sibling, addr, client, who, taken) {
                    return Some(Pick {
                        home: sibling,
                        addr,
                        source: Source::Pool,
                        host_options: None,
                    });
                }
            }
        }
    }
    None
}

// WP9.2: delegated prefixes (RFC 8415 section 6.3).
/// A delegated prefix for one `IA_PD`.
#[derive(Debug, Clone, Copy)]
pub struct PickPd<'a> {
    /// The scope that holds its delegation pool (the selected scope or a sibling of its
    /// shared network).
    pub home: &'a Scope6Image,
    /// The delegation pool.
    pub pool: &'a PdPool6Image,
    /// The prefix's first address.
    pub prefix: Ipv6Addr,
    /// Its length.
    pub len: u8,
    /// Where it came from (never a reservation: IPAM has no intent for a delegated prefix).
    pub source: Source,
}

/// Whether the prefix at `prefix` of `scope` may go to the client of `identity` now, apart
/// from the pool rule: no other binding of it (another client's, an address's, an
/// abandoned one), no other client's offer, and not taken by another IA of the message.
fn prefix_available(
    ctx: &Context6<'_>,
    scope: &Scope6Image,
    prefix: Ipv6Addr,
    client: Client<'_>,
    (iaid, identity): (u32, &[u8]),
    taken: &[Ipv6Addr],
) -> bool {
    if taken.contains(&prefix) {
        return false;
    }
    if let Some(lease) = ctx.leases.get(scope.vrf, prefix)
        && lease.blocks(ctx.now)
        && (lease.state == BindingState::Abandoned
            || lease.kind != Lease6Kind::Pd
            || lease.iaid != iaid
            || lease.duid.as_bytes() != client.duid)
    {
        return false;
    }
    !ctx.offers
        .held_for_other(scope.prefix, prefix, identity, ctx.now)
}

/// Whether `prefix`/`len` is a free delegable prefix of `scope` for the client.
pub fn is_free_prefix(
    ctx: &Context6<'_>,
    scope: &Scope6Image,
    (prefix, len): (Ipv6Addr, u8),
    client: Client<'_>,
    who: (u32, &[u8]),
    taken: &[Ipv6Addr],
) -> bool {
    scope.is_delegable(prefix, len) && prefix_available(ctx, scope, prefix, client, who, taken)
}

/// The delegated prefix for the `IA_PD` `iaid` of the client in `scope` (and its
/// siblings), or none: its bound prefix, a prefix it hinted when that one is free, then a
/// free prefix of a delegation pool walked in a hashed order, the pools of a hinted length
/// first (RFC 8415 section 18.3.9: the server may use the prefix and the length of an IA
/// Prefix as hints).
pub fn pick_pd<'a>(
    ctx: &Context6<'a>,
    client: Client<'_>,
    scope: &'a Scope6Image,
    iaid: u32,
    hints: &[(Ipv6Addr, u8)],
    taken: &[Ipv6Addr],
) -> Option<PickPd<'a>> {
    let image = ctx.image.v6();
    let mut buf = [0u8; MAX_IDENTITY6];
    let len = identity(iaid, client.duid, &mut buf);
    let identity = &buf[..len];
    let who = (iaid, identity);
    for sibling in image.siblings(scope) {
        if let Some(lease) = ctx
            .leases
            .by_client(sibling.prefix, Lease6Kind::Pd, identity)
            && lease.is_bound(ctx.now)
            && let Some(pool) = sibling.pd_pool_of(lease.addr6(), lease.prefix_len)
            && is_free_prefix(
                ctx,
                sibling,
                (lease.addr6(), lease.prefix_len),
                client,
                who,
                taken,
            )
        {
            return Some(PickPd {
                home: sibling,
                pool,
                prefix: lease.addr6(),
                len: lease.prefix_len,
                source: Source::Lease,
            });
        }
    }
    for (prefix, hint_len) in hints {
        if prefix.is_unspecified() {
            continue;
        }
        if let Some((home, pool)) = image.siblings(scope).find_map(|sibling| {
            sibling
                .pd_pool_of(*prefix, *hint_len)
                .map(|pool| (sibling, pool))
        }) && is_free_prefix(ctx, home, (*prefix, *hint_len), client, who, taken)
        {
            return Some(PickPd {
                home,
                pool,
                prefix: *prefix,
                len: *hint_len,
                source: Source::Hint,
            });
        }
    }
    let wanted = hints.iter().map(|(_, len)| *len).find(|len| *len > 0);
    let passes: &[Option<bool>] = if wanted.is_some() {
        &[Some(true), Some(false)]
    } else {
        &[None]
    };
    for pass in passes {
        let mut index = 0;
        for sibling in image.siblings(scope) {
            for pool in &sibling.pd_pools {
                let at = index;
                index += 1;
                let matches = Some(pool.delegated_len) == wanted;
                if pass.is_some_and(|want| want != matches) {
                    continue;
                }
                let size = pool.blocks();
                let from = start(identity, at, size);
                for step in 0..size.min(MAX_PROBES) {
                    let prefix = pool.block((from + step) % size);
                    if is_free_prefix(
                        ctx,
                        sibling,
                        (prefix, pool.delegated_len),
                        client,
                        who,
                        taken,
                    ) {
                        return Some(PickPd {
                            home: sibling,
                            pool,
                            prefix,
                            len: pool.delegated_len,
                            source: Source::Pool,
                        });
                    }
                }
            }
        }
    }
    None
}

/// The lifetimes of a prefix of a delegation pool of `home`: as [`lifetimes`], from the
/// pool's lease times.
pub fn pd_lifetimes(home: &Scope6Image, pool: &PdPool6Image) -> Lifetimes {
    times_of(home, pool.lease)
}

/// The lifetimes of an address of `home` (the pool's lease times, else the scope's):
/// valid, preferred, T1 and T2, with T1 at most T2 at most the preferred lifetime (RFC
/// 8415 section 21.4 recommends 0.5 and 0.8 of the preferred lifetime, which the
/// defaults are).
pub fn lifetimes(home: &Scope6Image, pool: Option<&Pool6Image>) -> Lifetimes {
    times_of(home, pool.map_or(home.lease, |pool| pool.lease))
}

fn times_of(home: &Scope6Image, times: LeaseTimes) -> Lifetimes {
    let valid = times.grant(None).max(1);
    let preferred = home.v6.preferred(valid).max(1);
    let (t1, t2) = if times.t1_secs.is_some() || times.t2_secs.is_some() {
        times.renewal_times(valid)
    } else {
        (
            preferred / 2,
            u32::try_from(u64::from(preferred) * 4 / 5).unwrap_or(preferred),
        )
    };
    let t2 = t2.min(preferred);
    let t1 = t1.min(t2);
    Lifetimes {
        valid,
        preferred,
        t1,
        t2,
    }
}

/// The lifetimes of one granted address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetimes {
    /// The valid lifetime.
    pub valid: u32,
    /// The preferred lifetime.
    pub preferred: u32,
    /// T1.
    pub t1: u32,
    /// T2.
    pub t2: u32,
}
