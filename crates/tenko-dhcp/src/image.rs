//! The configuration image (plan sections 2.2 to 2.4): what the DORA path reads instead of
//! the store.
//!
//! A [`ConfigImage`] is immutable once built and swapped whole on a change. It holds the
//! enabled DHCPv4 scopes with their pools, exclusions and effective options precompiled
//! (server, shared network and scope merged per code), the reservations derived from IPAM
//! by client identity and by address, the MAC filters, and the classes and policies for the
//! matcher of WP8.4. Every lookup the DORA path makes ([`ConfigImage::select`],
//! [`ConfigImage::reservation`], [`ConfigImage::reserved_at`],
//! [`ScopeImage::is_excluded`], [`ConfigImage::verdict`]) reads the image without
//! allocating.
//!
//! The image is put together with [`ImageBuilder`]. Building it from the rows of a
//! [`DhcpData`](crate::feed::DhcpData) (scopes, IPAM ranges, the addresses of hosts that
//! are not `dynamic`, reserved hosts, option sets) is WP7.4's, which proves its build
//! against a reference over random configurations; WP7.0 fixes the shape the engine (WP7.3)
//! and the allocator read.

use std::{collections::BTreeMap, net::Ipv4Addr};

// WP8.4: the compiled classes and policies.
use crate::class::Matcher;

use ipnet::Ipv4Net;
use tenko_core::{
    HostId, InterfaceId, PrefixId, RangeId, Revision, VrfId,
    dhcp::{
        Class, ClassId, DdnsPolicy, Filter, FilterVerdict, LeaseTimes, OptionValue, Policy,
        SharedNetworkId, filter_verdict,
    },
};

/// One pool of a scope: an IPAM range of role `dhcp_pool`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolImage {
    /// The range.
    pub range: RangeId,
    /// The first address.
    pub first: Ipv4Addr,
    /// The last address.
    pub last: Ipv4Addr,
    /// The lease times: the pool settings', else the range's `lease_secs`, else the
    /// scope's.
    pub lease: LeaseTimes,
    /// The classes the pool admits; empty: every client the scope admits.
    pub classes: Vec<ClassId>,
    /// The pool's own options (level `pool`), merged over the scope's by the engine.
    pub options: Vec<OptionValue>,
}

impl PoolImage {
    /// Whether `addr` lies in the pool.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        self.first <= addr && addr <= self.last
    }

    /// The number of addresses.
    pub fn size(&self) -> u64 {
        u64::from(u32::from(self.last)) - u64::from(u32::from(self.first)) + 1
    }
}

/// One enabled DHCPv4 scope, precompiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeImage {
    /// The prefix.
    pub prefix: PrefixId,
    /// The prefix's VRF.
    pub vrf: VrfId,
    /// The network.
    pub network: Ipv4Net,
    /// Authoritative (NAK for addresses of other networks).
    pub authoritative: bool,
    /// Only allowed clients are served.
    pub restricted: bool,
    /// The server identifier; none: the listener's address.
    pub server_id: Option<Ipv4Addr>,
    /// The scope's lease times (the server's when it sets none).
    pub lease: LeaseTimes,
    /// The shared network.
    pub shared_network: Option<SharedNetworkId>,
    /// The pools, by first address.
    pub pools: Vec<PoolImage>,
    /// The excluded ranges, sorted and merged: explicit exclusions, the prefix's `reserved`
    /// and `infrastructure` ranges, and the addresses of hosts that are not `dynamic`.
    pub excluded: Vec<(Ipv4Addr, Ipv4Addr)>,
    /// The effective options of the scope: server, shared network and scope merged.
    pub options: Vec<OptionValue>,
    /// The classes the scope admits; empty: every client.
    pub classes: Vec<ClassId>,
    /// DDNS.
    pub ddns: DdnsPolicy,
}

impl ScopeImage {
    /// Whether `addr` is excluded from allocation (the network and broadcast addresses
    /// always are).
    pub fn is_excluded(&self, addr: Ipv4Addr) -> bool {
        if addr == self.network.network() || addr == self.network.broadcast() {
            return true;
        }
        let at = self.excluded.partition_point(|(first, _)| *first <= addr);
        at > 0 && self.excluded[at - 1].1 >= addr
    }

    /// The pool `addr` lies in.
    pub fn pool_of(&self, addr: Ipv4Addr) -> Option<&PoolImage> {
        self.pools.iter().find(|pool| pool.contains(addr))
    }

    /// Whether `addr` may be leased dynamically: inside a pool and not excluded.
    pub fn is_dynamic(&self, addr: Ipv4Addr) -> bool {
        self.pool_of(addr).is_some() && !self.is_excluded(addr)
    }

    /// The first option of `code` in the `dhcp4` space.
    pub fn option(&self, code: u8) -> Option<&OptionValue> {
        self.options
            .iter()
            .find(|value| value.space.is_dhcp4() && value.code == u16::from(code))
    }
}

/// A reservation derived from IPAM (plan section 2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationImage {
    /// The scope.
    pub scope: PrefixId,
    /// The address.
    pub addr: Ipv4Addr,
    /// The host.
    pub host: HostId,
    /// The interface.
    pub interface: InterfaceId,
    /// The client identity (`ClientKey::identity`).
    pub identity: Vec<u8>,
    /// The reservation's options (the interface's option set).
    pub options: Vec<OptionValue>,
}

/// Why a scope was selected for a request (logged at debug level, risk R60).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// The link selection sub-option of option 82 (RFC 3527).
    LinkSelection,
    /// Option 118 (RFC 3011).
    SubnetSelection,
    /// The relay's `giaddr`.
    Giaddr,
    /// The address of the interface the request arrived on.
    Interface,
}

/// The configuration image of the `dhcp` role.
#[derive(Debug, Clone, Default)]
pub struct ConfigImage {
    revision: Revision,
    scopes: Vec<ScopeImage>,
    reservations: Vec<ReservationImage>,
    /// Scope index, then identity, to the reservation's index.
    by_identity: BTreeMap<PrefixId, BTreeMap<Vec<u8>, usize>>,
    /// Address to the reservation's index (one VRF per scope, so the scope qualifies it).
    by_addr: BTreeMap<(PrefixId, Ipv4Addr), usize>,
    filters: Vec<Filter>,
    classes: Vec<Class>,
    policies: Vec<Policy>,
    // WP8.4: the classes and policies compiled for the DORA path.
    matcher: Matcher,
    // WP9.1: the DHCPv6 scopes and reservations.
    v6: crate::v6::image::Image6,
}

impl ConfigImage {
    /// The store revision the image was built from.
    pub fn revision(&self) -> Revision {
        self.revision
    }

    /// The scopes, sorted by network.
    pub fn scopes(&self) -> &[ScopeImage] {
        &self.scopes
    }

    /// The scope with this prefix.
    pub fn scope(&self, prefix: PrefixId) -> Option<&ScopeImage> {
        self.scopes.iter().find(|scope| scope.prefix == prefix)
    }

    /// The scope whose network holds `addr`: the selection by link selection, option 118,
    /// `giaddr` or the receiving interface's address (plan section 2.5). The most specific
    /// network wins when networks nest.
    pub fn select(&self, addr: Ipv4Addr) -> Option<&ScopeImage> {
        self.scopes
            .iter()
            .filter(|scope| scope.network.contains(&addr))
            .max_by_key(|scope| scope.network.prefix_len())
    }

    /// The scopes of the same shared network as `scope`, `scope` first; just `scope` when
    /// it belongs to none.
    pub fn siblings<'a>(&'a self, scope: &'a ScopeImage) -> impl Iterator<Item = &'a ScopeImage> {
        std::iter::once(scope).chain(self.scopes.iter().filter(move |other| {
            other.prefix != scope.prefix
                && scope.shared_network.is_some()
                && other.shared_network == scope.shared_network
        }))
    }

    /// The reservation of a client identity in a scope.
    pub fn reservation(&self, scope: PrefixId, identity: &[u8]) -> Option<&ReservationImage> {
        let index = *self.by_identity.get(&scope)?.get(identity)?;
        self.reservations.get(index)
    }

    /// The reservation that holds an address of a scope.
    pub fn reserved_at(&self, scope: PrefixId, addr: Ipv4Addr) -> Option<&ReservationImage> {
        let index = *self.by_addr.get(&(scope, addr))?;
        self.reservations.get(index)
    }

    /// The filters' verdict on a hardware address (DHCP-08).
    pub fn verdict(&self, mac: &[u8; 6]) -> FilterVerdict {
        filter_verdict(&self.filters, mac)
    }

    /// The classes.
    pub fn classes(&self) -> &[Class] {
        &self.classes
    }

    /// The policies, by scope and order (server-level ones last).
    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    /// The reservations.
    pub fn reservations(&self) -> &[ReservationImage] {
        &self.reservations
    }

    // WP8.4: the reservation of a client by its identity or its hardware address, and the
    // compiled matcher.
    /// The reservation of a client in a scope: by its client identity first (option 61
    /// when it sent one), then by its hardware identity (`0`, `htype`, `chaddr`), so that
    /// a reservation keyed by MAC holds for a client whose `chaddr` it names whether or not
    /// that client sends option 61 (Windows sends one of type 1), and a reservation keyed
    /// by a client identifier holds only for that identifier and wins over a MAC-keyed one.
    /// `hardware` equals `identity` for a client without option 61.
    pub fn reservation_of(
        &self,
        scope: PrefixId,
        identity: &[u8],
        hardware: &[u8],
    ) -> Option<&ReservationImage> {
        self.reservation(scope, identity).or_else(|| {
            if hardware == identity {
                None
            } else {
                self.reservation(scope, hardware)
            }
        })
    }

    /// The reservation of a client in `scope` and its shared network's siblings: one by
    /// client identity in any of them first, then one by hardware identity, in the order
    /// of [`ConfigImage::reservation_of`].
    pub fn client_reservation<'a>(
        &'a self,
        scope: &'a ScopeImage,
        identity: &[u8],
        hardware: &[u8],
    ) -> Option<&'a ReservationImage> {
        self.siblings(scope)
            .find_map(|sibling| self.reservation(sibling.prefix, identity))
            .or_else(|| {
                if hardware == identity {
                    None
                } else {
                    self.siblings(scope)
                        .find_map(|sibling| self.reservation(sibling.prefix, hardware))
                }
            })
    }

    /// The compiled classes and policies.
    pub fn matcher(&self) -> &Matcher {
        &self.matcher
    }

    // WP9.1: the DHCPv6 part.
    /// The DHCPv6 scopes and reservations.
    pub fn v6(&self) -> &crate::v6::image::Image6 {
        &self.v6
    }
}

/// Puts a [`ConfigImage`] together.
#[derive(Debug, Default)]
pub struct ImageBuilder {
    image: ConfigImage,
    // WP8.4: the policies' option sets, compiled with them.
    policy_options: BTreeMap<tenko_core::dhcp::PolicyId, Vec<OptionValue>>,
}

impl ImageBuilder {
    /// A builder for the image of `revision`.
    pub fn new(revision: Revision) -> Self {
        Self {
            image: ConfigImage {
                revision,
                ..ConfigImage::default()
            },
            policy_options: BTreeMap::new(),
        }
    }

    /// Adds a scope; its pools are sorted and its exclusions sorted and merged.
    pub fn scope(&mut self, mut scope: ScopeImage) -> &mut Self {
        scope.pools.sort_by_key(|pool| pool.first);
        scope.excluded.sort_unstable();
        let mut merged: Vec<(Ipv4Addr, Ipv4Addr)> = Vec::with_capacity(scope.excluded.len());
        for (first, last) in scope.excluded.drain(..) {
            match merged.last_mut() {
                Some(previous)
                    if u64::from(u32::from(first)) <= u64::from(u32::from(previous.1)) + 1 =>
                {
                    previous.1 = previous.1.max(last);
                }
                _ => merged.push((first, last)),
            }
        }
        scope.excluded = merged;
        self.image.scopes.push(scope);
        self.image
            .scopes
            .sort_by_key(|scope| (scope.network.network(), scope.network.prefix_len()));
        self
    }

    /// Adds a reservation; a second one for the same identity or address in a scope is
    /// dropped and returned (the image keeps the first; IPAM-23 reports the conflict).
    pub fn reservation(&mut self, reservation: ReservationImage) -> Option<ReservationImage> {
        let identities = self.image.by_identity.entry(reservation.scope).or_default();
        if identities.contains_key(&reservation.identity)
            || self
                .image
                .by_addr
                .contains_key(&(reservation.scope, reservation.addr))
        {
            return Some(reservation);
        }
        let index = self.image.reservations.len();
        identities.insert(reservation.identity.clone(), index);
        self.image
            .by_addr
            .insert((reservation.scope, reservation.addr), index);
        self.image.reservations.push(reservation);
        None
    }

    // WP9.1: the DHCPv6 part, put together by its own methods.
    /// The DHCPv6 part, to add scopes and reservations to.
    pub fn v6(&mut self) -> &mut crate::v6::image::Image6 {
        &mut self.image.v6
    }

    /// Sets the filters.
    pub fn filters(&mut self, filters: Vec<Filter>) -> &mut Self {
        self.image.filters = filters;
        self
    }

    /// Sets the classes.
    pub fn classes(&mut self, classes: Vec<Class>) -> &mut Self {
        self.image.classes = classes;
        self
    }

    /// Sets the policies; they are sorted by scope (scope policies first) and order.
    pub fn policies(&mut self, mut policies: Vec<Policy>) -> &mut Self {
        policies.sort_by_key(|policy| (policy.scope.is_none(), policy.scope, policy.order));
        self.image.policies = policies;
        self
    }

    // WP8.4: a policy's option set, and the matcher compiled at the build.
    /// Sets the option set of a policy (its options when it matches).
    pub fn policy_options(
        &mut self,
        policy: tenko_core::dhcp::PolicyId,
        values: Vec<OptionValue>,
    ) -> &mut Self {
        self.policy_options.insert(policy, values);
        self
    }

    /// The image, with the classes and policies compiled into its matcher.
    pub fn build(mut self) -> ConfigImage {
        let options = std::mem::take(&mut self.policy_options);
        self.image.matcher = Matcher::compile(
            &self.image.classes,
            &self.image.policies,
            &self.image.scopes,
            |id| options.get(&id).cloned().unwrap_or_default(),
        );
        self.image
    }
}

// WP8.4: the reservation lookup by client identity and hardware address.
#[cfg(test)]
mod tests {
    use tenko_core::{HostId, InterfaceId, PrefixId, RangeId, Revision, VrfId, dhcp::DdnsPolicy};

    use super::*;

    fn scope(prefix: PrefixId, network: &str, shared: Option<SharedNetworkId>) -> ScopeImage {
        let network: Ipv4Net = network.parse().expect("a network");
        ScopeImage {
            prefix,
            vrf: VrfId::generate(),
            network,
            authoritative: true,
            restricted: false,
            server_id: None,
            lease: LeaseTimes::default(),
            shared_network: shared,
            pools: vec![PoolImage {
                range: RangeId::generate(),
                first: network.network(),
                last: network.broadcast(),
                lease: LeaseTimes::default(),
                classes: Vec::new(),
                options: Vec::new(),
            }],
            excluded: Vec::new(),
            options: Vec::new(),
            classes: Vec::new(),
            ddns: DdnsPolicy::default(),
        }
    }

    fn reservation(scope: PrefixId, addr: &str, identity: Vec<u8>) -> ReservationImage {
        ReservationImage {
            scope,
            addr: addr.parse().expect("an address"),
            host: HostId::generate(),
            interface: InterfaceId::generate(),
            identity,
            options: Vec::new(),
        }
    }

    #[test]
    fn a_reservation_is_found_by_client_identity_then_by_hardware_address() {
        const MAC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x20];
        let mut hardware = vec![0, 1];
        hardware.extend(MAC);
        let mut client_id = vec![1, 1];
        client_id.extend(MAC);
        let mut other_id = vec![1, 0xff, 0, 0, 0, 1];
        other_id.extend(MAC);
        let shared = Some(SharedNetworkId::generate());
        let (a, b, c) = (
            PrefixId::generate(),
            PrefixId::generate(),
            PrefixId::generate(),
        );
        let mut builder = ImageBuilder::new(Revision(1));
        builder
            .scope(scope(a, "192.0.2.0/25", shared))
            .scope(scope(b, "192.0.2.128/25", shared))
            .scope(scope(c, "198.51.100.0/24", None));
        // Scope A: the MAC's reservation; scope B: the client identifier's; scope C: the
        // MAC's only.
        for held in [
            reservation(a, "192.0.2.20", hardware.clone()),
            reservation(b, "192.0.2.150", client_id.clone()),
            reservation(c, "198.51.100.20", hardware.clone()),
        ] {
            assert!(builder.reservation(held).is_none());
        }
        let image = builder.build();
        let addr = |found: Option<&ReservationImage>| found.map(|held| held.addr.to_string());
        // A client without option 61 (its identity is its hardware identity).
        assert_eq!(
            addr(image.reservation_of(a, &hardware, &hardware)),
            Some("192.0.2.20".to_owned())
        );
        // A Windows-style client: option 61 of type 1 with the MAC. In scope C only the
        // MAC's reservation exists, and it holds.
        assert_eq!(
            addr(image.reservation_of(c, &client_id, &hardware)),
            Some("198.51.100.20".to_owned())
        );
        // Another identifier from the same MAC: the MAC's reservation holds too.
        assert_eq!(
            addr(image.reservation_of(c, &other_id, &hardware)),
            Some("198.51.100.20".to_owned())
        );
        // A reservation keyed by client identifier holds for that identifier only.
        assert_eq!(image.reservation_of(b, &other_id, &hardware), None);
        assert_eq!(image.reservation_of(b, &hardware, &hardware), None);
        // Across the shared network the client identifier's reservation wins, although
        // the MAC's is in the first sibling.
        let first = image.scope(a).expect("scope A");
        assert_eq!(
            addr(image.client_reservation(first, &client_id, &hardware)),
            Some("192.0.2.150".to_owned())
        );
        assert_eq!(
            addr(image.client_reservation(first, &other_id, &hardware)),
            Some("192.0.2.20".to_owned())
        );
    }
}
