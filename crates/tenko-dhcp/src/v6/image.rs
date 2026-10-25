//! The DHCPv6 part of the configuration image (plan sections 2.2 and 2.3): the enabled
//! scopes on IPv6 networks with their pools, exclusions and effective options, and the
//! reservations derived from IPAM by DUID (or by MAC address), held in
//! [`ConfigImage::v6`](crate::image::ConfigImage::v6) beside the DHCPv4 part.
//!
//! Every lookup the engine makes ([`Image6::select`], [`Image6::by_interface_id`],
//! [`Image6::reservation`], [`Image6::reserved_at`], [`Scope6Image::is_excluded`]) reads
//! without allocating. The build from the rows is [`crate::config::image::build`].

use std::{collections::BTreeMap, net::Ipv6Addr};

use ipnet::Ipv6Net;
use tenko_core::{
    HostId, InterfaceId, PrefixId, RangeId, VrfId,
    dhcp::{DdnsPolicy, LeaseTimes, OptionValue, Scope6Settings, SharedNetworkId},
};

/// One pool of a DHCPv6 scope: an IPAM range of role `dhcp_pool` on an IPv6 network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool6Image {
    /// The range.
    pub range: RangeId,
    /// The first address.
    pub first: Ipv6Addr,
    /// The last address.
    pub last: Ipv6Addr,
    /// The lease times (the valid lifetime): the pool settings', else the range's
    /// `lease_secs`, else the scope's.
    pub lease: LeaseTimes,
    /// The pool's own options.
    pub options: Vec<OptionValue>,
}

impl Pool6Image {
    /// Whether `addr` lies in the pool.
    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        self.first <= addr && addr <= self.last
    }

    /// The number of addresses (at least 1).
    pub fn size(&self) -> u128 {
        u128::from(self.last)
            .saturating_sub(u128::from(self.first))
            .saturating_add(1)
    }
}

// WP9.2: delegation pools.
/// One delegation pool of a DHCPv6 scope: an IPAM range of role `dhcp_pd_pool` on an IPv6
/// network, cut into prefixes of its delegated length (RFC 8415 section 6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdPool6Image {
    /// The range.
    pub range: RangeId,
    /// The first address, on a boundary of the delegated length.
    pub first: Ipv6Addr,
    /// The last address, the end of a delegated prefix.
    pub last: Ipv6Addr,
    /// The length of the prefixes it delegates, 1 to 64.
    pub delegated_len: u8,
    /// The lease times (the valid lifetime): the pool settings', else the range's
    /// `lease_secs`, else the scope's.
    pub lease: LeaseTimes,
    /// The pool's own options.
    pub options: Vec<OptionValue>,
}

impl PdPool6Image {
    /// The addresses of one delegated prefix.
    pub fn block_size(&self) -> u128 {
        1u128 << (128 - u32::from(self.delegated_len.clamp(1, 128)))
    }

    /// The number of prefixes the pool delegates (at least 1).
    pub fn blocks(&self) -> u128 {
        (u128::from(self.last).saturating_sub(u128::from(self.first)) / self.block_size())
            .saturating_add(1)
    }

    /// The first address of prefix `index`.
    pub fn block(&self, index: u128) -> Ipv6Addr {
        Ipv6Addr::from(
            u128::from(self.first).saturating_add(index.saturating_mul(self.block_size())),
        )
    }

    /// Whether `prefix`/`len` is one of the pool's prefixes: of its length, on its
    /// boundary, inside it.
    pub fn holds(&self, prefix: Ipv6Addr, len: u8) -> bool {
        len == self.delegated_len
            && self.first <= prefix
            && prefix <= self.last
            && (u128::from(prefix) - u128::from(self.first)) % self.block_size() == 0
    }

    /// The last address of the prefix that starts at `prefix`.
    pub fn block_last(&self, prefix: Ipv6Addr) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(prefix).saturating_add(self.block_size() - 1))
    }
}

/// One enabled DHCPv6 scope, precompiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope6Image {
    /// The prefix.
    pub prefix: PrefixId,
    /// The prefix's VRF.
    pub vrf: VrfId,
    /// The network.
    pub network: Ipv6Net,
    /// Whether the scope answers for addresses of other links (a REBIND or CONFIRM of an
    /// address that is not on the link gets lifetimes of zero or `NotOnLink`).
    pub authoritative: bool,
    /// Only clients an allow filter matches (by their link-layer address) or with a
    /// reservation are served.
    pub restricted: bool,
    /// The lease times; the default is the valid lifetime.
    pub lease: LeaseTimes,
    /// The DHCPv6 settings.
    pub v6: Scope6Settings,
    /// The relay Interface-Id that selects the scope, as octets.
    pub interface_id: Option<Vec<u8>>,
    /// The shared network.
    pub shared_network: Option<SharedNetworkId>,
    /// The pools, by first address.
    pub pools: Vec<Pool6Image>,
    /// The delegation pools, by first address (WP9.2).
    pub pd_pools: Vec<PdPool6Image>,
    /// The excluded ranges, sorted and merged.
    pub excluded: Vec<(Ipv6Addr, Ipv6Addr)>,
    /// The effective options of the scope: server, shared network and scope merged (the
    /// `dhcp6` values are the scope's DHCPv6 options).
    pub options: Vec<OptionValue>,
    /// DDNS.
    pub ddns: DdnsPolicy,
}

impl Scope6Image {
    /// Whether `addr` is excluded from allocation: the explicit and implicit exclusions,
    /// and the network's first address, the Subnet-Router anycast address (RFC 4291
    /// section 2.6.1).
    pub fn is_excluded(&self, addr: Ipv6Addr) -> bool {
        if addr == self.network.network() {
            return true;
        }
        let at = self.excluded.partition_point(|(first, _)| *first <= addr);
        at > 0 && self.excluded[at - 1].1 >= addr
    }

    /// The pool `addr` lies in.
    pub fn pool_of(&self, addr: Ipv6Addr) -> Option<&Pool6Image> {
        self.pools.iter().find(|pool| pool.contains(addr))
    }

    /// Whether `addr` may be leased dynamically: inside a pool and not excluded.
    pub fn is_dynamic(&self, addr: Ipv6Addr) -> bool {
        self.pool_of(addr).is_some() && !self.is_excluded(addr)
    }

    /// The delegation pool that holds the prefix `prefix`/`len`.
    pub fn pd_pool_of(&self, prefix: Ipv6Addr, len: u8) -> Option<&PdPool6Image> {
        self.pd_pools.iter().find(|pool| pool.holds(prefix, len))
    }

    /// Whether the prefix `prefix`/`len` may be delegated: one of a delegation pool's
    /// prefixes, and no excluded address inside it (an exclusion, a `reserved` or
    /// `infrastructure` range, an address of a host that is not `dynamic`).
    pub fn is_delegable(&self, prefix: Ipv6Addr, len: u8) -> bool {
        let Some(pool) = self.pd_pool_of(prefix, len) else {
            return false;
        };
        let last = pool.block_last(prefix);
        let at = self.excluded.partition_point(|(first, _)| *first <= last);
        !(at > 0 && self.excluded[at - 1].1 >= prefix)
    }

    // WP9.4: the delegable prefixes as intervals, for the pool sizes and the Kea export.
    /// The delegable part of `pool` as intervals of whole prefixes, by address: the pool
    /// without every prefix an excluded address lies in, so that each interval starts on a
    /// boundary of the delegated length and ends at the last address of a prefix, and
    /// [`Self::is_delegable`] holds for every prefix inside one and for no other.
    pub fn delegable(&self, pool: &PdPool6Image) -> Vec<(Ipv6Addr, Ipv6Addr)> {
        let size = pool.block_size();
        let (first, last) = (u128::from(pool.first), u128::from(pool.last));
        let block_of = |addr: u128| first + (addr - first) / size * size;
        let mut out = Vec::new();
        let mut cursor = first;
        for &(from, to) in &self.excluded {
            let (low, high) = (u128::from(from).max(first), u128::from(to).min(last));
            if low > high || high < cursor {
                continue;
            }
            let start = block_of(low);
            if start > cursor {
                out.push((Ipv6Addr::from(cursor), Ipv6Addr::from(start - 1)));
            }
            match block_of(high).checked_add(size) {
                Some(after) if after <= last => cursor = cursor.max(after),
                _ => return out,
            }
        }
        if cursor <= last {
            out.push((Ipv6Addr::from(cursor), Ipv6Addr::from(last)));
        }
        out
    }

    /// The number of prefixes of `pool` that may be delegated ([`Self::delegable`]).
    pub fn delegable_count(&self, pool: &PdPool6Image) -> u128 {
        let size = pool.block_size();
        self.delegable(pool)
            .iter()
            .map(|(first, last)| (u128::from(*last) - u128::from(*first)) / size + 1)
            .fold(0, u128::saturating_add)
    }

    /// The first option of `code` in the `dhcp6` space.
    pub fn option(&self, code: u16) -> Option<&OptionValue> {
        self.options
            .iter()
            .find(|value| value.space.is_dhcp6() && value.code == code)
    }
}

/// What a DHCPv6 reservation is keyed by.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reservation6Key {
    /// The interface's DUID (IPAM `Interface::duid`).
    Duid(Vec<u8>),
    /// The interface's MAC address, matched against the client's link-layer address (RFC
    /// 6939, or a DUID-LLT or DUID-LL), for an interface without a DUID.
    Mac([u8; 6]),
}

/// A DHCPv6 reservation derived from IPAM: an address of an interface of a `reserved` host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation6Image {
    /// The scope.
    pub scope: PrefixId,
    /// The address.
    pub addr: Ipv6Addr,
    /// The host.
    pub host: HostId,
    /// The interface.
    pub interface: InterfaceId,
    /// What the client is known by.
    pub key: Reservation6Key,
    /// The reservation's options (the interface's option set).
    pub options: Vec<OptionValue>,
}

/// The DHCPv6 part of the image.
#[derive(Debug, Clone, Default)]
pub struct Image6 {
    scopes: Vec<Scope6Image>,
    reservations: Vec<Reservation6Image>,
    by_key: BTreeMap<(PrefixId, Reservation6Key), usize>,
    by_addr: BTreeMap<(PrefixId, Ipv6Addr), usize>,
}

impl Image6 {
    /// The scopes, sorted by network.
    pub fn scopes(&self) -> &[Scope6Image] {
        &self.scopes
    }

    /// The scope with this prefix.
    pub fn scope(&self, prefix: PrefixId) -> Option<&Scope6Image> {
        self.scopes.iter().find(|scope| scope.prefix == prefix)
    }

    /// The scope whose network holds `addr`, the most specific when networks nest.
    pub fn select(&self, addr: Ipv6Addr) -> Option<&Scope6Image> {
        self.scopes
            .iter()
            .filter(|scope| scope.network.contains(&addr))
            .max_by_key(|scope| scope.network.prefix_len())
    }

    /// The scope a relay's Interface-Id selects.
    pub fn by_interface_id(&self, interface_id: &[u8]) -> Option<&Scope6Image> {
        self.scopes
            .iter()
            .find(|scope| scope.interface_id.as_deref() == Some(interface_id))
    }

    /// The scopes of the same shared network as `scope`, `scope` first.
    pub fn siblings<'a>(&'a self, scope: &'a Scope6Image) -> impl Iterator<Item = &'a Scope6Image> {
        std::iter::once(scope).chain(self.scopes.iter().filter(move |other| {
            other.prefix != scope.prefix
                && scope.shared_network.is_some()
                && other.shared_network == scope.shared_network
        }))
    }

    /// The reservation of a client in a scope: by its DUID, then by its MAC address.
    pub fn reservation(
        &self,
        scope: PrefixId,
        duid: &[u8],
        mac: Option<[u8; 6]>,
    ) -> Option<&Reservation6Image> {
        // A lookup by a borrowed DUID without building the owned key: the map is ordered
        // by (scope, key) and `Duid` sorts before `Mac`, so a range scan finds it.
        let found = self
            .by_key
            .range((scope, Reservation6Key::Duid(Vec::new()))..)
            .take_while(|((held, key), _)| {
                *held == scope && matches!(key, Reservation6Key::Duid(_))
            })
            .find(|((_, key), _)| matches!(key, Reservation6Key::Duid(held) if held == duid))
            .map(|(_, index)| *index)
            .or_else(|| {
                let mac = mac?;
                self.by_key
                    .get(&(scope, Reservation6Key::Mac(mac)))
                    .copied()
            })?;
        self.reservations.get(found)
    }

    /// The reservation of a client in `scope` and its shared network's siblings: one by
    /// DUID in any of them first, then one by MAC address.
    pub fn client_reservation<'a>(
        &'a self,
        scope: &'a Scope6Image,
        duid: &[u8],
        mac: Option<[u8; 6]>,
    ) -> Option<&'a Reservation6Image> {
        self.siblings(scope)
            .find_map(|sibling| self.reservation(sibling.prefix, duid, None))
            .or_else(|| {
                mac?;
                self.siblings(scope)
                    .find_map(|sibling| self.reservation(sibling.prefix, &[], mac))
            })
    }

    /// The reservation that holds an address of a scope.
    pub fn reserved_at(&self, scope: PrefixId, addr: Ipv6Addr) -> Option<&Reservation6Image> {
        let index = *self.by_addr.get(&(scope, addr))?;
        self.reservations.get(index)
    }

    /// The reservations.
    pub fn reservations(&self) -> &[Reservation6Image] {
        &self.reservations
    }

    /// Adds a scope; its pools are sorted and its exclusions sorted and merged.
    pub fn add_scope(&mut self, mut scope: Scope6Image) {
        scope.pools.sort_by_key(|pool| pool.first);
        scope.pd_pools.sort_by_key(|pool| pool.first);
        scope.excluded.sort_unstable();
        let mut merged: Vec<(Ipv6Addr, Ipv6Addr)> = Vec::with_capacity(scope.excluded.len());
        for (first, last) in scope.excluded.drain(..) {
            match merged.last_mut() {
                Some(previous) if u128::from(first) <= u128::from(previous.1).saturating_add(1) => {
                    previous.1 = previous.1.max(last);
                }
                _ => merged.push((first, last)),
            }
        }
        scope.excluded = merged;
        self.scopes.push(scope);
        self.scopes
            .sort_by_key(|scope| (scope.network.network(), scope.network.prefix_len()));
    }

    /// Adds a reservation; a second one for the same key or address in a scope is dropped
    /// and returned (the first wins; IPAM-23 reports the conflict).
    pub fn add_reservation(&mut self, reservation: Reservation6Image) -> Option<Reservation6Image> {
        let key = (reservation.scope, reservation.key.clone());
        if self.by_key.contains_key(&key)
            || self
                .by_addr
                .contains_key(&(reservation.scope, reservation.addr))
        {
            return Some(reservation);
        }
        let index = self.reservations.len();
        self.by_key.insert(key, index);
        self.by_addr
            .insert((reservation.scope, reservation.addr), index);
        self.reservations.push(reservation);
        None
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{HostId, InterfaceId, PrefixId, RangeId, VrfId};

    use super::*;

    fn scope(prefix: PrefixId, network: &str, shared: Option<SharedNetworkId>) -> Scope6Image {
        let network: Ipv6Net = network.parse().expect("a network");
        Scope6Image {
            prefix,
            vrf: VrfId::generate(),
            network,
            authoritative: true,
            restricted: false,
            lease: LeaseTimes::default(),
            v6: Scope6Settings::default(),
            interface_id: None,
            shared_network: shared,
            pools: vec![Pool6Image {
                range: RangeId::generate(),
                first: "2001:db8::100".parse().expect("first"),
                last: "2001:db8::1ff".parse().expect("last"),
                lease: LeaseTimes::default(),
                options: Vec::new(),
            }],
            pd_pools: Vec::new(),
            excluded: vec![
                (
                    "2001:db8::150".parse().expect("a"),
                    "2001:db8::150".parse().expect("a"),
                ),
                (
                    "2001:db8::140".parse().expect("a"),
                    "2001:db8::14f".parse().expect("a"),
                ),
            ],
            options: Vec::new(),
            ddns: DdnsPolicy::default(),
        }
    }

    #[test]
    fn exclusions_merge_and_the_anycast_address_is_never_leased() {
        let mut image = Image6::default();
        let prefix = PrefixId::generate();
        image.add_scope(scope(prefix, "2001:db8::/64", None));
        let held = image.scope(prefix).expect("scope");
        assert_eq!(held.excluded.len(), 1);
        assert!(held.is_excluded("2001:db8::".parse().expect("anycast")));
        assert!(held.is_excluded("2001:db8::148".parse().expect("a")));
        assert!(!held.is_excluded("2001:db8::151".parse().expect("a")));
        assert!(held.is_dynamic("2001:db8::151".parse().expect("a")));
        assert!(!held.is_dynamic("2001:db8::2ff".parse().expect("a")));
    }

    fn ip(text: &str) -> Ipv6Addr {
        text.parse().expect("an address")
    }

    /// Sixteen /60 prefixes: `2001:db8:180:100::/60` to `2001:db8:180:1f0::/60`.
    fn pd_pool() -> PdPool6Image {
        PdPool6Image {
            range: RangeId::generate(),
            first: ip("2001:db8:180:100::"),
            last: ip("2001:db8:180:1ff:ffff:ffff:ffff:ffff"),
            delegated_len: 60,
            lease: LeaseTimes::default(),
            options: Vec::new(),
        }
    }

    #[test]
    fn a_delegation_pool_counts_and_places_its_prefixes() {
        let pool = pd_pool();
        assert_eq!(pool.block_size(), 1u128 << 68);
        assert_eq!(pool.blocks(), 16);
        assert_eq!(pool.block(0), ip("2001:db8:180:100::"));
        assert_eq!(pool.block(1), ip("2001:db8:180:110::"));
        assert_eq!(pool.block(10), ip("2001:db8:180:1a0::"));
        assert_eq!(pool.block(15), ip("2001:db8:180:1f0::"));
        for index in 0..pool.blocks() {
            assert!(pool.holds(pool.block(index), 60), "block {index}");
        }
        assert_eq!(
            pool.block_last(pool.block(0)),
            ip("2001:db8:180:10f:ffff:ffff:ffff:ffff")
        );
        assert_eq!(pool.block_last(pool.block(15)), pool.last);
        // The blocks tile the range: each starts where the one before it ended.
        for index in 1..pool.blocks() {
            assert_eq!(
                u128::from(pool.block(index)),
                u128::from(pool.block_last(pool.block(index - 1))) + 1
            );
        }
        // One prefix, and a /64 pool of a whole /48.
        let mut one = pd_pool();
        one.last = ip("2001:db8:180:10f:ffff:ffff:ffff:ffff");
        assert_eq!(one.blocks(), 1);
        assert_eq!(one.block(0), one.first);
        let wide = PdPool6Image {
            first: ip("2001:db8:180::"),
            last: ip("2001:db8:180:ffff:ffff:ffff:ffff:ffff"),
            delegated_len: 64,
            ..pd_pool()
        };
        assert_eq!(wide.block_size(), 1u128 << 64);
        assert_eq!(wide.blocks(), 65_536);
        assert_eq!(wide.block(65_535), ip("2001:db8:180:ffff::"));
        // An index past the end saturates and does not panic.
        assert_eq!(pool.block(u128::MAX), Ipv6Addr::from(u128::MAX));
    }

    // WP9.4: the delegable prefixes as intervals.
    #[test]
    fn the_delegable_part_leaves_out_every_prefix_an_exclusion_touches() {
        let mut held = scope(PrefixId::generate(), "2001:db8:180::/48", None);
        held.pools.clear();
        held.excluded.clear();
        let pool = pd_pool();
        held.pd_pools = vec![pool.clone()];
        assert_eq!(held.delegable(&pool), vec![(pool.first, pool.last)]);
        assert_eq!(held.delegable_count(&pool), 16);
        // One address in the second prefix, a range over the ends of the eighth and the
        // ninth, and one before the pool that reaches into its first prefix.
        held.excluded = vec![
            (ip("2001:db8:180:ff::"), ip("2001:db8:180:100::1")),
            (ip("2001:db8:180:115::5"), ip("2001:db8:180:115::5")),
            (ip("2001:db8:180:17f::"), ip("2001:db8:180:180::")),
        ];
        assert_eq!(
            held.delegable(&pool),
            vec![
                (
                    ip("2001:db8:180:120::"),
                    ip("2001:db8:180:16f:ffff:ffff:ffff:ffff")
                ),
                (
                    ip("2001:db8:180:190::"),
                    ip("2001:db8:180:1ff:ffff:ffff:ffff:ffff")
                ),
            ]
        );
        assert_eq!(held.delegable_count(&pool), 12);
        // An exclusion in the last prefix ends the delegable part before it; one past the
        // pool changes nothing.
        held.excluded = vec![
            (ip("2001:db8:180:1f8::"), ip("2001:db8:180:1f8::")),
            (ip("2001:db8:180:300::"), ip("2001:db8:180:300::")),
        ];
        assert_eq!(
            held.delegable(&pool),
            vec![(pool.first, ip("2001:db8:180:1ef:ffff:ffff:ffff:ffff"))]
        );
        // Every prefix excluded: nothing is delegable.
        held.excluded = vec![(ip("2001:db8:180::"), ip("2001:db8:180:ffff::"))];
        assert_eq!(held.delegable(&pool), Vec::new());
        assert_eq!(held.delegable_count(&pool), 0);
    }

    proptest::proptest! {
        /// A prefix lies in the delegable part exactly when `is_delegable` says it may be
        /// delegated.
        #[test]
        fn the_delegable_part_is_what_the_engine_delegates(
            cuts in proptest::collection::vec((0u128..18, 0u128..(1u128 << 68), 0u128..(1u128 << 70)), 0..5)
        ) {
            let mut held = scope(PrefixId::generate(), "2001:db8:180::/48", None);
            held.pools.clear();
            let pool = pd_pool();
            let base = u128::from(ip("2001:db8:180:100::")) - (1u128 << 68);
            let mut excluded: Vec<(u128, u128)> = cuts
                .iter()
                .map(|(block, offset, span)| {
                    let first = base + block * (1u128 << 68) + offset;
                    (first, first + span)
                })
                .collect();
            excluded.sort_unstable();
            let mut merged: Vec<(u128, u128)> = Vec::new();
            for (first, last) in excluded {
                match merged.last_mut() {
                    Some((_, end)) if first <= end.saturating_add(1) => *end = (*end).max(last),
                    _ => merged.push((first, last)),
                }
            }
            held.excluded = merged
                .into_iter()
                .map(|(first, last)| (Ipv6Addr::from(first), Ipv6Addr::from(last)))
                .collect();
            held.pd_pools = vec![pool.clone()];
            let parts = held.delegable(&pool);
            let mut count = 0u128;
            for index in 0..pool.blocks() {
                let prefix = pool.block(index);
                let inside = parts.iter().any(|(first, last)| *first <= prefix && prefix <= *last);
                proptest::prop_assert_eq!(inside, held.is_delegable(prefix, 60), "prefix {}", prefix);
                count += u128::from(inside);
            }
            proptest::prop_assert_eq!(held.delegable_count(&pool), count);
            for (first, last) in parts {
                proptest::prop_assert_eq!((u128::from(first) - u128::from(pool.first)) % pool.block_size(), 0);
                proptest::prop_assert_eq!((u128::from(last) + 1 - u128::from(pool.first)) % pool.block_size(), 0);
            }
        }
    }

    #[test]
    fn a_delegation_pool_holds_only_aligned_prefixes_of_its_length_inside_it() {
        let pool = pd_pool();
        assert!(pool.holds(ip("2001:db8:180:100::"), 60));
        assert!(pool.holds(ip("2001:db8:180:1f0::"), 60));
        // The wrong length, on a boundary of the pool's.
        assert!(!pool.holds(ip("2001:db8:180:100::"), 64));
        assert!(!pool.holds(ip("2001:db8:180:100::"), 56));
        assert!(!pool.holds(ip("2001:db8:180:100::"), 0));
        // Not on a boundary of the length.
        assert!(!pool.holds(ip("2001:db8:180:105::"), 60));
        assert!(!pool.holds(ip("2001:db8:180:100::1"), 60));
        assert!(!pool.holds(ip("2001:db8:180:1f8::"), 60));
        // The last address of the range is not the start of a prefix.
        assert!(!pool.holds(pool.last, 60));
        // Aligned, but outside the range.
        assert!(!pool.holds(ip("2001:db8:180:0f0::"), 60));
        assert!(!pool.holds(ip("2001:db8:180:200::"), 60));
        assert!(!pool.holds(ip("2001:db8:181::"), 60));
        assert!(!pool.holds(ip("::"), 60));
        assert!(!pool.holds(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0"), 60));
    }

    #[test]
    fn an_exclusion_inside_a_prefix_keeps_it_from_being_delegated_and_one_just_outside_does_not() {
        let mut image = Image6::default();
        let prefix = PrefixId::generate();
        let mut held = scope(prefix, "2001:db8:180::/48", None);
        held.pd_pools = vec![pd_pool()];
        held.excluded = vec![
            // Inside the prefix 130::/60.
            (ip("2001:db8:180:135::1"), ip("2001:db8:180:135::1")),
            // The last address of 140::/60; 150::/60 starts one past it.
            (
                ip("2001:db8:180:14f:ffff:ffff:ffff:ffff"),
                ip("2001:db8:180:14f:ffff:ffff:ffff:ffff"),
            ),
            // The first address of 160::/60; 150::/60 ends one before it.
            (ip("2001:db8:180:160::"), ip("2001:db8:180:160::")),
            // Two whole prefixes, 170::/60 and 180::/60; 190::/60 starts one past them.
            (
                ip("2001:db8:180:170::"),
                ip("2001:db8:180:18f:ffff:ffff:ffff:ffff"),
            ),
            // A range that starts in 1a0::/60 and ends in 1b0::/60.
            (
                ip("2001:db8:180:1af:ffff:ffff:ffff:fff0"),
                ip("2001:db8:180:1b0::5"),
            ),
        ];
        image.add_scope(held);
        let held = image.scope(prefix).expect("scope");
        let delegable = |text: &str| held.is_delegable(ip(text), 60);
        for text in [
            "2001:db8:180:100::",
            "2001:db8:180:110::",
            "2001:db8:180:120::",
            "2001:db8:180:150::",
            "2001:db8:180:190::",
            "2001:db8:180:1c0::",
            "2001:db8:180:1d0::",
            "2001:db8:180:1e0::",
            "2001:db8:180:1f0::",
        ] {
            assert!(delegable(text), "{text}");
        }
        for text in [
            "2001:db8:180:130::",
            "2001:db8:180:140::",
            "2001:db8:180:160::",
            "2001:db8:180:170::",
            "2001:db8:180:180::",
            "2001:db8:180:1a0::",
            "2001:db8:180:1b0::",
        ] {
            assert!(!delegable(text), "{text}");
        }
        // What the pool does not hold is not delegable, excluded or not.
        assert!(!held.is_delegable(ip("2001:db8:181::"), 60));
        assert!(!held.is_delegable(ip("2001:db8:180:105::"), 60));
        assert!(!held.is_delegable(ip("2001:db8:180:110::"), 64));
        assert!(!held.is_delegable(ip("2001:db8:180:110::"), 56));
        // A scope without a delegation pool delegates nothing.
        let mut bare = scope(PrefixId::generate(), "2001:db8:180::/48", None);
        bare.excluded.clear();
        assert!(!bare.is_delegable(ip("2001:db8:180:110::"), 60));
    }

    #[test]
    fn a_delegation_pool_is_found_by_the_prefix_it_holds_and_the_pools_are_sorted() {
        let mut image = Image6::default();
        let prefix = PrefixId::generate();
        let mut held = scope(prefix, "2001:db8:180::/47", None);
        let far = PdPool6Image {
            first: ip("2001:db8:181::"),
            last: ip("2001:db8:181:ffff:ffff:ffff:ffff:ffff"),
            delegated_len: 56,
            ..pd_pool()
        };
        // Added out of order.
        held.pd_pools = vec![far, pd_pool()];
        image.add_scope(held);
        let held = image.scope(prefix).expect("scope");
        assert_eq!(
            held.pd_pools[0].delegated_len, 60,
            "sorted by first address"
        );
        assert_eq!(held.pd_pools[1].delegated_len, 56);
        assert_eq!(
            held.pd_pool_of(ip("2001:db8:180:120::"), 60)
                .map(|pool| pool.delegated_len),
            Some(60)
        );
        assert_eq!(
            held.pd_pool_of(ip("2001:db8:181:4200::"), 56)
                .map(|pool| pool.delegated_len),
            Some(56)
        );
        assert!(held.pd_pool_of(ip("2001:db8:181:4200::"), 60).is_none());
        assert!(held.pd_pool_of(ip("2001:db8:182::"), 56).is_none());
    }

    #[test]
    fn a_reservation_is_found_by_duid_then_by_mac() {
        let mut image = Image6::default();
        let shared = Some(SharedNetworkId::generate());
        let (a, b) = (PrefixId::generate(), PrefixId::generate());
        image.add_scope(scope(a, "2001:db8::/64", shared));
        image.add_scope(scope(b, "2001:db8:0:1::/64", shared));
        let duid = vec![0, 3, 0, 1, 0, 0, 0x5e, 0, 0x53, 1];
        let mac = [0, 0, 0x5e, 0, 0x53, 2];
        let add = |image: &mut Image6, scope, addr: &str, key| {
            image.add_reservation(Reservation6Image {
                scope,
                addr: addr.parse().expect("addr"),
                host: HostId::generate(),
                interface: InterfaceId::generate(),
                key,
                options: Vec::new(),
            })
        };
        assert!(
            add(
                &mut image,
                b,
                "2001:db8:0:1::10",
                Reservation6Key::Duid(duid.clone())
            )
            .is_none()
        );
        assert!(add(&mut image, a, "2001:db8::20", Reservation6Key::Mac(mac)).is_none());
        assert!(add(&mut image, a, "2001:db8::20", Reservation6Key::Mac([2; 6])).is_some());
        let first = image.scope(a).expect("scope a").clone();
        let by_duid = image
            .client_reservation(&first, &duid, Some(mac))
            .expect("by duid");
        assert_eq!(by_duid.addr.to_string(), "2001:db8:0:1::10");
        let by_mac = image
            .client_reservation(&first, &[0, 1], Some(mac))
            .expect("by mac");
        assert_eq!(by_mac.addr.to_string(), "2001:db8::20");
        assert!(image.client_reservation(&first, &[0, 1], None).is_none());
        assert!(
            image
                .reserved_at(a, "2001:db8::20".parse().expect("addr"))
                .is_some()
        );
    }
}
