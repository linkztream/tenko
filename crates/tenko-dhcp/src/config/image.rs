//! The configuration image built from the rows (plan sections 2.2 to 2.4): what the
//! `dhcp` role serves from, put together with [`ImageBuilder`].
//!
//! [`build`] takes a [`DhcpData`] (the `dhcp` rows and the IPAM rows) and gives the image,
//! the findings of the reservation check (IPAM-18, IPAM-23) and the reservations the image
//! dropped because an earlier one holds their identity or address. The rules:
//!
//! - **Scopes.** An enabled scope whose prefix is a live IPv4 network. Its lease times are
//!   its own, else the server's; it is authoritative as it says, else as the server says;
//!   its server identifier counts when it is IPv4. Its options are the server's, its shared
//!   network's and its own, merged per code in that order.
//! - **Pools.** The live IPv4 ranges of the prefix with role `dhcp_pool`. A pool's lease
//!   times are its settings' (`dhcp.pools`), else the range's `lease_secs` as one fixed
//!   time, else the scope's; its classes are its settings'; its options its own set.
//! - **Exclusions.** The scope's explicit exclusion ranges, the prefix's live ranges of role
//!   `reserved` and `infrastructure`, and every live address of the prefix that does not
//!   belong to a live host of mode `dynamic` (a static server inside a pool is never
//!   offered, plan section 2.3). The builder sorts and merges them.
//! - **Reservations.** For every live host of mode `reserved` (by id), its live interfaces
//!   (by id) and their live IPv4 addresses of status `active` or `planned` (by id) inside a
//!   scope of the image: a reservation of the address for the interface's client identity
//!   (the client identifier when it has one, else the MAC address), with the interface's
//!   option set. An interface with neither gives no reservation and the warning
//!   `no_identity` (IPAM-18). The first reservation of an identity or an address in a scope
//!   wins; the check reports the collision (IPAM-23).
//! - **The rest.** Every filter and class by id; the enabled policies of the server and of
//!   the scopes in the image, sorted by the builder.
//! - **DHCPv6** (WP9.1, [`crate::v6::image`]). An enabled scope whose prefix is a live IPv6
//!   network, with the same rules for lease times, pools, exclusions and options (its
//!   `dhcp6` values are the DHCPv6 options), its DHCPv6 settings and the Interface-Id that
//!   selects it; reservations for the live IPv6 addresses of status `active` or `planned` of
//!   `reserved` hosts, keyed by the interface's DUID, else by its MAC address (matched
//!   against the client's link-layer address); an interface with neither gives
//!   `no_identity`. Their findings are [`Built::warnings6`]. Classes and policies are
//!   DHCPv4 only.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnet::IpNet;
use tenko_core::{
    HostId, InterfaceId, PrefixId,
    dhcp::{
        LeaseTimes, OptionOwner, OptionValue, ReservationCandidate, ReservationWarning,
        check_reservations, merge, write_identity,
    },
    ipam::{Address, AssignmentMode, Interface, PrefixRole, Range, RangeRole, Status},
};

use crate::{
    feed::DhcpData,
    image::{ConfigImage, ImageBuilder, PoolImage, ReservationImage, ScopeImage},
};

/// What [`build`] gives.
#[derive(Debug, Clone, Default)]
pub struct Built {
    /// The image.
    pub image: ConfigImage,
    /// The findings of the reservation check, in the order `check_reservations` gives.
    pub warnings: Vec<ReservationWarning>,
    /// Reservations left out because an earlier one holds the identity or the address.
    pub dropped: Vec<ReservationImage>,
    // WP9.1: the findings of the DHCPv6 reservations, apart from the DHCPv4 ones.
    /// The findings of the DHCPv6 reservation check.
    pub warnings6: Vec<ReservationWarning>,
    /// DHCPv6 reservations left out because an earlier one holds the key or the address.
    pub dropped6: Vec<crate::v6::image::Reservation6Image>,
}

/// The client identity of an interface: the client identifier when it has one, else its
/// MAC address as an Ethernet `chaddr`; none without either (IPAM-18).
pub fn interface_identity(interface: &Interface) -> Option<Vec<u8>> {
    let mac = interface.mac.map(tenko_core::net::MacAddr::octets);
    let client_id = interface.client_id.as_ref().map(|id| id.0.as_slice());
    if client_id.is_none() && mac.is_none() {
        return None;
    }
    let mut out = [0u8; tenko_core::dhcp::lease::MAX_IDENTITY];
    let chaddr = mac.as_ref().map_or(&[][..], |octets| octets.as_slice());
    let len = write_identity(1, chaddr, client_id, &mut out);
    Some(out[..len].to_vec())
}

fn v4(address: IpAddr) -> Option<Ipv4Addr> {
    match address {
        IpAddr::V4(address) => Some(address),
        IpAddr::V6(_) => None,
    }
}

fn values(data: &DhcpData, owner: OptionOwner) -> &[OptionValue] {
    data.option_sets
        .get(&owner)
        .map_or(&[][..], |set| set.values.as_slice())
}

/// Indexes of the IPAM rows, live rows only, in id order.
struct Index<'a> {
    ranges: BTreeMap<PrefixId, Vec<&'a Range>>,
    by_prefix: BTreeMap<PrefixId, Vec<&'a Address>>,
    by_interface: BTreeMap<InterfaceId, Vec<&'a Address>>,
    interfaces: BTreeMap<HostId, Vec<&'a Interface>>,
}

impl<'a> Index<'a> {
    fn new(data: &'a DhcpData) -> Self {
        let mut index = Self {
            ranges: BTreeMap::new(),
            by_prefix: BTreeMap::new(),
            by_interface: BTreeMap::new(),
            interfaces: BTreeMap::new(),
        };
        for range in data.ranges.values().filter(|r| !r.meta.is_deleted()) {
            index.ranges.entry(range.prefix).or_default().push(range);
        }
        for address in data.addresses.values().filter(|a| !a.meta.is_deleted()) {
            index
                .by_prefix
                .entry(address.prefix)
                .or_default()
                .push(address);
            if let Some(interface) = address.interface {
                index
                    .by_interface
                    .entry(interface)
                    .or_default()
                    .push(address);
            }
        }
        for interface in data.interfaces.values().filter(|i| !i.meta.is_deleted()) {
            index
                .interfaces
                .entry(interface.host)
                .or_default()
                .push(interface);
        }
        index
    }
}

/// Whether an address belongs to a live host of mode `dynamic` through a live interface.
fn is_dynamic(data: &DhcpData, address: &Address) -> bool {
    address
        .interface
        .and_then(|id| data.interfaces.get(&id))
        .filter(|interface| !interface.meta.is_deleted())
        .and_then(|interface| data.hosts.get(&interface.host))
        .is_some_and(|host| !host.meta.is_deleted() && host.mode == AssignmentMode::Dynamic)
}

fn scope_image(data: &DhcpData, index: &Index<'_>, prefix: PrefixId) -> Option<ScopeImage> {
    let scope = data.scopes.get(&prefix)?;
    let row = data.prefixes.get(&prefix)?;
    if !scope.enabled || row.meta.is_deleted() || row.role != PrefixRole::Network {
        return None;
    }
    let IpNet::V4(network) = row.cidr else {
        return None;
    };
    let settings = data.settings.clone().unwrap_or_default();
    let lease = scope.lease.unwrap_or(settings.lease);
    let ranges = index.ranges.get(&prefix).map_or(&[][..], Vec::as_slice);
    let mut pools = Vec::new();
    let mut excluded = Vec::new();
    for range in ranges {
        let (Some(first), Some(last)) = (v4(range.first), v4(range.last)) else {
            continue;
        };
        match range.role {
            RangeRole::DhcpPool => {
                let pool = data.pools.get(&range.id);
                pools.push(PoolImage {
                    range: range.id,
                    first,
                    last,
                    lease: pool
                        .and_then(|pool| pool.lease)
                        .or_else(|| range.lease_secs.map(LeaseTimes::fixed))
                        .unwrap_or(lease),
                    classes: pool.map(|pool| pool.classes.clone()).unwrap_or_default(),
                    options: values(data, OptionOwner::Pool(range.id)).to_vec(),
                });
            }
            RangeRole::Reserved | RangeRole::Infrastructure => excluded.push((first, last)),
        }
    }
    for exclusion in data
        .exclusions
        .range((prefix, tenko_core::dhcp::ExclusionId(uuid::Uuid::nil()))..)
        .take_while(|((scope, _), _)| *scope == prefix)
        .map(|(_, exclusion)| exclusion)
    {
        if let (Some(first), Some(last)) = (v4(exclusion.first), v4(exclusion.last)) {
            excluded.push((first, last));
        }
    }
    for address in index.by_prefix.get(&prefix).map_or(&[][..], Vec::as_slice) {
        if let Some(ip) = v4(address.ip)
            && !is_dynamic(data, address)
        {
            excluded.push((ip, ip));
        }
    }
    let mut levels: Vec<&[OptionValue]> = vec![values(data, OptionOwner::Server)];
    if let Some(network) = scope.shared_network {
        levels.push(values(data, OptionOwner::SharedNetwork(network)));
    }
    levels.push(values(data, OptionOwner::Scope(prefix)));
    Some(ScopeImage {
        prefix,
        vrf: row.vrf,
        network,
        authoritative: scope.authoritative.unwrap_or(settings.authoritative),
        restricted: scope.restricted,
        server_id: scope.server_id.and_then(v4),
        lease,
        shared_network: scope.shared_network,
        pools,
        excluded,
        options: merge(levels),
        classes: scope.classes.clone(),
        ddns: scope.ddns.clone(),
    })
}

fn v6(address: IpAddr) -> Option<Ipv6Addr> {
    match address {
        IpAddr::V6(address) => Some(address),
        IpAddr::V4(_) => None,
    }
}

// WP9.1: a scope on an IPv6 network.
fn scope6_image(
    data: &DhcpData,
    index: &Index<'_>,
    prefix: PrefixId,
) -> Option<crate::v6::image::Scope6Image> {
    use crate::v6::image::{Pool6Image, Scope6Image};
    let scope = data.scopes.get(&prefix)?;
    let row = data.prefixes.get(&prefix)?;
    if !scope.enabled || row.meta.is_deleted() || row.role != PrefixRole::Network {
        return None;
    }
    let IpNet::V6(network) = row.cidr else {
        return None;
    };
    let settings = data.settings.clone().unwrap_or_default();
    let lease = scope.lease.unwrap_or(settings.lease);
    let mut pools = Vec::new();
    let mut excluded = Vec::new();
    for range in index.ranges.get(&prefix).map_or(&[][..], Vec::as_slice) {
        let (Some(first), Some(last)) = (v6(range.first), v6(range.last)) else {
            continue;
        };
        match range.role {
            RangeRole::DhcpPool => {
                let pool = data.pools.get(&range.id);
                pools.push(Pool6Image {
                    range: range.id,
                    first,
                    last,
                    lease: pool
                        .and_then(|pool| pool.lease)
                        .or_else(|| range.lease_secs.map(LeaseTimes::fixed))
                        .unwrap_or(lease),
                    options: values(data, OptionOwner::Pool(range.id)).to_vec(),
                });
            }
            RangeRole::Reserved | RangeRole::Infrastructure => excluded.push((first, last)),
        }
    }
    for exclusion in data
        .exclusions
        .range((prefix, tenko_core::dhcp::ExclusionId(uuid::Uuid::nil()))..)
        .take_while(|((scope, _), _)| *scope == prefix)
        .map(|(_, exclusion)| exclusion)
    {
        if let (Some(first), Some(last)) = (v6(exclusion.first), v6(exclusion.last)) {
            excluded.push((first, last));
        }
    }
    for address in index.by_prefix.get(&prefix).map_or(&[][..], Vec::as_slice) {
        if let Some(ip) = v6(address.ip)
            && !is_dynamic(data, address)
        {
            excluded.push((ip, ip));
        }
    }
    let mut levels: Vec<&[OptionValue]> = vec![values(data, OptionOwner::Server)];
    if let Some(network) = scope.shared_network {
        levels.push(values(data, OptionOwner::SharedNetwork(network)));
    }
    levels.push(values(data, OptionOwner::Scope(prefix)));
    let v6_settings = scope.v6.clone().unwrap_or_default();
    Some(Scope6Image {
        prefix,
        vrf: row.vrf,
        network,
        authoritative: scope.authoritative.unwrap_or(settings.authoritative),
        restricted: scope.restricted,
        lease,
        interface_id: v6_settings
            .interface_id
            .as_ref()
            .map(|id| id.as_bytes().to_vec()),
        v6: v6_settings,
        shared_network: scope.shared_network,
        pools,
        excluded,
        options: merge(levels),
        ddns: scope.ddns.clone(),
    })
}

/// The DHCPv6 key of an interface: its DUID, else its MAC address.
fn interface_key6(interface: &Interface) -> Option<crate::v6::image::Reservation6Key> {
    use crate::v6::image::Reservation6Key;
    interface
        .duid
        .as_ref()
        .map(|duid| Reservation6Key::Duid(duid.as_bytes().to_vec()))
        .or_else(|| {
            interface
                .mac
                .map(|mac| Reservation6Key::Mac(tenko_core::net::MacAddr::octets(mac)))
        })
}

// WP9.1: the DHCPv6 scopes and reservations.
fn build6(
    data: &DhcpData,
    index: &Index<'_>,
    builder: &mut ImageBuilder,
) -> (
    Vec<ReservationWarning>,
    Vec<crate::v6::image::Reservation6Image>,
) {
    use crate::v6::image::{Reservation6Image, Reservation6Key};
    let mut served = BTreeSet::new();
    for prefix in data.scopes.keys() {
        if let Some(scope) = scope6_image(data, index, *prefix) {
            served.insert(*prefix);
            builder.v6().add_scope(scope);
        }
    }
    let mut candidates = Vec::new();
    let mut dropped = Vec::new();
    for host in data
        .hosts
        .values()
        .filter(|host| !host.meta.is_deleted() && host.mode == AssignmentMode::Reserved)
    {
        for interface in index
            .interfaces
            .get(&host.id)
            .map_or(&[][..], Vec::as_slice)
        {
            let key = interface_key6(interface);
            // The check's identity: the kind of key and its octets.
            let identity = key.as_ref().map(|key| match key {
                Reservation6Key::Duid(duid) => [b"D".as_slice(), duid].concat(),
                Reservation6Key::Mac(mac) => [b"M".as_slice(), mac].concat(),
            });
            for address in index
                .by_interface
                .get(&interface.id)
                .map_or(&[][..], Vec::as_slice)
            {
                let Some(ip) = v6(address.ip) else {
                    continue;
                };
                if !matches!(address.status, Status::Active | Status::Planned)
                    || !served.contains(&address.prefix)
                {
                    continue;
                }
                candidates.push(ReservationCandidate {
                    host: host.id,
                    scope: address.prefix,
                    address: address.ip,
                    identity: identity.clone(),
                });
                if let Some(key) = &key {
                    let reservation = Reservation6Image {
                        scope: address.prefix,
                        addr: ip,
                        host: host.id,
                        interface: interface.id,
                        key: key.clone(),
                        options: values(data, OptionOwner::Host(interface.id)).to_vec(),
                    };
                    if let Some(refused) = builder.v6().add_reservation(reservation) {
                        dropped.push(refused);
                    }
                }
            }
        }
    }
    (check_reservations(&candidates), dropped)
}

/// The DHCPv6 part of the image of `data`, added to `builder`: the findings and the
/// reservations left out (the reference of `image_tests.rs` builds the DHCPv4 part its own
/// way and takes this part as it is; `v6::image` and the engine's tests cover it).
#[cfg(test)]
pub(crate) fn build_v6_into(
    data: &DhcpData,
    builder: &mut ImageBuilder,
) -> (
    Vec<ReservationWarning>,
    Vec<crate::v6::image::Reservation6Image>,
) {
    build6(data, &Index::new(data), builder)
}

/// Builds the image of `data`.
pub fn build(data: &DhcpData) -> Built {
    let index = Index::new(data);
    let mut builder = ImageBuilder::new(data.revision);
    let mut served = BTreeSet::new();
    for prefix in data.scopes.keys() {
        if let Some(scope) = scope_image(data, &index, *prefix) {
            served.insert(*prefix);
            builder.scope(scope);
        }
    }
    // WP9.1: the DHCPv6 part.
    let (warnings6, dropped6) = build6(data, &index, &mut builder);
    let mut candidates = Vec::new();
    let mut dropped = Vec::new();
    for host in data
        .hosts
        .values()
        .filter(|host| !host.meta.is_deleted() && host.mode == AssignmentMode::Reserved)
    {
        for interface in index
            .interfaces
            .get(&host.id)
            .map_or(&[][..], Vec::as_slice)
        {
            let identity = interface_identity(interface);
            for address in index
                .by_interface
                .get(&interface.id)
                .map_or(&[][..], Vec::as_slice)
            {
                let Some(ip) = v4(address.ip) else {
                    continue;
                };
                if !matches!(address.status, Status::Active | Status::Planned)
                    || !served.contains(&address.prefix)
                {
                    continue;
                }
                candidates.push(ReservationCandidate {
                    host: host.id,
                    scope: address.prefix,
                    address: address.ip,
                    identity: identity.clone(),
                });
                if let Some(identity) = &identity {
                    let reservation = ReservationImage {
                        scope: address.prefix,
                        addr: ip,
                        host: host.id,
                        interface: interface.id,
                        identity: identity.clone(),
                        options: values(data, OptionOwner::Host(interface.id)).to_vec(),
                    };
                    if let Some(refused) = builder.reservation(reservation) {
                        dropped.push(refused);
                    }
                }
            }
        }
    }
    // WP8.4: the option sets of the policies the image holds, for the matcher.
    for policy in data.policies.values().filter(|policy| policy.enabled) {
        let set = values(data, OptionOwner::Policy(policy.id));
        if !set.is_empty() {
            builder.policy_options(policy.id, set.to_vec());
        }
    }
    builder
        .filters(data.filters.values().cloned().collect())
        .classes(data.classes.values().cloned().collect())
        .policies(
            data.policies
                .values()
                .filter(|policy| {
                    policy.enabled && policy.scope.is_none_or(|scope| served.contains(&scope))
                })
                .cloned()
                .collect(),
        );
    Built {
        image: builder.build(),
        warnings: check_reservations(&candidates),
        dropped,
        warnings6,
        dropped6,
    }
}
