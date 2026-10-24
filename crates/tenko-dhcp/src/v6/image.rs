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
