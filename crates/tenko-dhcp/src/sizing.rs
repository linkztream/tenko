//! The room of the role's fixed tables, from the configuration image (E32, M34, OPS-15).
//!
//! The DORA path allocates nothing (ADR 0019 point 7), so every table it writes is made
//! before it runs: the workers' pending commits (a reply and a lease change per slot), the
//! committer's hand-off queue, the offer slots, and the conflict probe's pending table and
//! cache. These used to be made at their largest whatever the configuration (4,096
//! commits, 65,536 offers), about 27.5 MiB resident before any scope existed. Their room
//! now follows the addresses the image can lease ([`leasable`]: the pool addresses of every
//! scope and the reservations), because none of them holds more than about one entry per
//! such address at a time: an offer claims its address, a client has one request in
//! commit, a probe looks at one offered address. The room is that count with a floor
//! ([`FLOOR`]) for a tiny or empty configuration, and the configured size as its cap
//! ([`room`]): the `pending` and `offers` of the server's settings, the committer's
//! `queue`, `[dhcp.probe] pending` and the probe cache's entries are upper bounds.
//!
//! A new image grows the tables when it can lease more (the role's follower calls the
//! growth when it installs the image, never a worker); they do not shrink while the role
//! runs, so a ticket or a slot index handed out earlier stays valid, and a restart sizes
//! them anew. A table that is full drops the request as `queue` (or sends the offer
//! unprobed) as before, and the client retries.

use crate::{image::ConfigImage, v6::image::Image6};

/// The least room of a table, whatever the configuration: a role that starts before its
/// first scope exists, or a scope of a few addresses, still takes a burst.
pub const FLOOR: usize = 256;

/// The addresses a DHCPv4 image can lease: the pool addresses of every scope and the
/// reservations (a reservation outside a pool is leased too).
pub fn leasable(image: &ConfigImage) -> u64 {
    let pools = image
        .scopes()
        .iter()
        .flat_map(|scope| scope.pools.iter())
        .fold(0u64, |sum, pool| sum.saturating_add(pool.size()));
    pools.saturating_add(u64::try_from(image.reservations().len()).unwrap_or(u64::MAX))
}

/// The bindings a DHCPv6 image can lease, saturated at `u64::MAX`: the addresses of every
/// pool, the prefixes of every delegation pool and the reservations.
pub fn leasable6(image: &Image6) -> u64 {
    let mut sum = u64::try_from(image.reservations().len()).unwrap_or(u64::MAX);
    for scope in image.scopes() {
        for pool in &scope.pools {
            sum = sum.saturating_add(u64::try_from(pool.size()).unwrap_or(u64::MAX));
        }
        for pool in &scope.pd_pools {
            let span = u128::from(pool.last)
                .saturating_sub(u128::from(pool.first))
                .saturating_add(1);
            let prefixes = span
                .checked_shr(128 - u32::from(pool.delegated_len.min(128)))
                .unwrap_or(1)
                .max(1);
            sum = sum.saturating_add(u64::try_from(prefixes).unwrap_or(u64::MAX));
        }
    }
    sum
}

/// The room of a table for `leasable` addresses with `cap` its configured size: the count,
/// at least [`FLOOR`], at most `cap` (and at least one).
pub fn room(leasable: u64, cap: usize) -> usize {
    usize::try_from(leasable)
        .unwrap_or(usize::MAX)
        .max(FLOOR)
        .min(cap.max(1))
}

/// The room of the DHCPv4 server's tables for one image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Room {
    /// The workers' pending commits.
    pub pending: usize,
    /// The offers the offer table holds about.
    pub offers: usize,
    /// The conflict probe's parked offers.
    pub probe_pending: usize,
    /// The addresses the probe cache holds about.
    pub probe_cache: usize,
}

/// The configured sizes, each the cap of its table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// `ServerConfig::pending`.
    pub pending: usize,
    /// `ServerConfig::offers`.
    pub offers: usize,
    /// `[dhcp.probe] pending`.
    pub probe_pending: usize,
    /// The probe cache's entries.
    pub probe_cache: usize,
}

impl Limits {
    /// The room of each table for `leasable` addresses.
    pub fn room(&self, leasable: u64) -> Room {
        Room {
            pending: room(leasable, self.pending),
            offers: room(leasable, self.offers),
            probe_pending: room(leasable, self.probe_pending),
            probe_cache: room(leasable, self.probe_cache),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_room_is_the_count_between_the_floor_and_the_cap() {
        assert_eq!(room(0, 4_096), FLOOR, "an empty image gets the floor");
        assert_eq!(room(10, 4_096), FLOOR, "a tiny one too");
        assert_eq!(room(300, 4_096), 300, "three pools of 100");
        assert_eq!(room(131_070, 4_096), 4_096, "a large pool stops at the cap");
        assert_eq!(room(u64::MAX, 65_536), 65_536, "a saturated count too");
        assert_eq!(room(300, 8), 8, "a cap below the floor wins");
        assert_eq!(room(300, 0), 1, "at least one");
    }

    #[test]
    fn the_limits_size_each_table() {
        let limits = Limits {
            pending: 4_096,
            offers: 65_536,
            probe_pending: 1_024,
            probe_cache: 65_536,
        };
        assert_eq!(
            limits.room(2_000),
            Room {
                pending: 2_000,
                offers: 2_000,
                probe_pending: 1_024,
                probe_cache: 2_000,
            }
        );
    }
}
