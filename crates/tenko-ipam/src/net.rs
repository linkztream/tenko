//! Address arithmetic shared by the planner and the prefix tree.
//!
//! Addresses are mapped to `u128` within their family, so IPv4 and IPv6 share one code
//! path; a value never mixes families because every structure keeps the two apart.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

/// The address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl Family {
    /// The family of an address.
    pub fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }

    /// The family of a network.
    pub fn of_net(net: &IpNet) -> Self {
        match net {
            IpNet::V4(_) => Family::V4,
            IpNet::V6(_) => Family::V6,
        }
    }

    /// Address width in bits.
    pub const fn bits(self) -> u8 {
        match self {
            Family::V4 => 32,
            Family::V6 => 128,
        }
    }

    /// Index for two-element arrays (`0` for IPv4).
    pub const fn index(self) -> usize {
        match self {
            Family::V4 => 0,
            Family::V6 => 1,
        }
    }
}

/// An address as a number within its family.
pub fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// A number back to an address of `family`.
pub fn u128_to_ip(family: Family, value: u128) -> IpAddr {
    match family {
        // Values of the IPv4 family never exceed `u32::MAX`; truncation is the intent.
        #[allow(clippy::cast_possible_truncation)]
        Family::V4 => IpAddr::V4(Ipv4Addr::from(value as u32)),
        Family::V6 => IpAddr::V6(Ipv6Addr::from(value)),
    }
}

/// The host mask of a prefix length: the low `bits - len` bits set.
pub fn host_mask(family: Family, len: u8) -> u128 {
    let host_bits = u32::from(family.bits().saturating_sub(len));
    if host_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    }
}

/// First and last address of a network as numbers.
pub fn bounds(net: &IpNet) -> (u128, u128) {
    let family = Family::of_net(net);
    let first = ip_to_u128(net.network());
    (first, first | host_mask(family, net.prefix_len()))
}

/// Builds a network from a number and a length; host bits are cleared.
pub fn net_from(family: Family, value: u128, len: u8) -> IpNet {
    let network = value & !host_mask(family, len);
    match u128_to_ip(family, network) {
        IpAddr::V4(v4) => IpNet::V4(Ipv4Net::new(v4, len.min(32)).unwrap_or_default()),
        IpAddr::V6(v6) => IpNet::V6(Ipv6Net::new(v6, len.min(128)).unwrap_or_default()),
    }
}

/// Number of addresses in `[first, last]`, saturating at `u128::MAX`.
pub fn span(first: u128, last: u128) -> u128 {
    if last < first {
        0
    } else {
        (last - first).saturating_add(1)
    }
}

/// Whether a network has host bits set (is not in canonical form).
pub fn has_host_bits(net: &IpNet) -> bool {
    net.addr() != net.network()
}

/// Whether `inner` lies within `outer` (same family; equal networks count).
pub fn contains_net(outer: &IpNet, inner: &IpNet) -> bool {
    Family::of_net(outer) == Family::of_net(inner)
        && outer.prefix_len() <= inner.prefix_len()
        && outer.contains(&inner.network())
}

/// Whether `ip` lies within `net`.
pub fn contains_ip(net: &IpNet, ip: IpAddr) -> bool {
    Family::of_net(net) == Family::of(ip) && net.contains(&ip)
}

/// The assignable host addresses of a network prefix, as numbers: IPv4 networks up to
/// /30 lose the network and broadcast address, IPv6 networks up to /126 lose the
/// subnet-router anycast address (RFC 4291); /31, /32, /127 and /128 keep every address.
pub fn host_bounds(net: &IpNet) -> (u128, u128) {
    let (first, last) = bounds(net);
    match (Family::of_net(net), net.prefix_len()) {
        (Family::V4, len) if len <= 30 => (first + 1, last - 1),
        (Family::V6, len) if len <= 126 => (first + 1, last),
        _ => (first, last),
    }
}

/// What an address at the edge of a network prefix is: the addresses [`host_bounds`] leaves
/// out, which no device holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeAddress {
    /// The first address of an IPv4 network up to /30.
    Network,
    /// The last address of an IPv4 network up to /30.
    Broadcast,
    /// The first address of an IPv6 network up to /126 (RFC 4291 section 2.6.1).
    SubnetRouterAnycast,
}

impl EdgeAddress {
    /// The `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            EdgeAddress::Network => "network",
            EdgeAddress::Broadcast => "broadcast",
            EdgeAddress::SubnetRouterAnycast => "subnet_router_anycast",
        }
    }

    /// The address in English: "the network address".
    pub const fn text(self) -> &'static str {
        match self {
            EdgeAddress::Network => "the network address",
            EdgeAddress::Broadcast => "the broadcast address",
            EdgeAddress::SubnetRouterAnycast => "the subnet-router anycast address",
        }
    }
}

/// Whether `ip` is an edge address of the network prefix `net` ([`EdgeAddress`]): the network
/// and broadcast address of an IPv4 network up to /30, the subnet-router anycast address of
/// an IPv6 network up to /126. A /31, /32, /127 or /128 has none, and an address outside
/// `net` is none of them.
pub fn edge_address(net: &IpNet, ip: IpAddr) -> Option<EdgeAddress> {
    if !contains_ip(net, ip) {
        return None;
    }
    let value = ip_to_u128(ip);
    let (first, last) = bounds(net);
    let (host_first, host_last) = host_bounds(net);
    match Family::of_net(net) {
        Family::V4 if value == first && host_first != first => Some(EdgeAddress::Network),
        Family::V4 if value == last && host_last != last => Some(EdgeAddress::Broadcast),
        Family::V6 if value == first && host_first != first => {
            Some(EdgeAddress::SubnetRouterAnycast)
        }
        _ => None,
    }
}

/// Number of assignable addresses of a network prefix (see [`host_bounds`]).
pub fn host_capacity(net: &IpNet) -> u128 {
    let (first, last) = host_bounds(net);
    span(first, last)
}

/// The smallest multiple of the block size of `len` that is at least `value`, or `None`
/// on overflow.
pub fn align_up(family: Family, value: u128, len: u8) -> Option<u128> {
    let mask = host_mask(family, len);
    if value & mask == 0 {
        Some(value)
    } else {
        (value | mask).checked_add(1)
    }
}

/// The largest multiple of the block size of `len` that is at most `value`.
pub fn align_down(family: Family, value: u128, len: u8) -> u128 {
    value & !host_mask(family, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> IpNet {
        text.parse().expect("net")
    }

    #[test]
    fn bounds_and_capacity() {
        let v4 = net("192.0.2.0/24");
        assert_eq!(bounds(&v4).1 - bounds(&v4).0, 255);
        assert_eq!(host_capacity(&v4), 254);
        assert_eq!(host_capacity(&net("192.0.2.0/31")), 2);
        assert_eq!(host_capacity(&net("192.0.2.1/32")), 1);
        assert_eq!(host_capacity(&net("2001:db8::/120")), 255);
        assert_eq!(host_capacity(&net("2001:db8::/127")), 2);
        assert_eq!(span(0, u128::MAX), u128::MAX);
        assert_eq!(host_mask(Family::V6, 0), u128::MAX);
    }

    #[test]
    fn conversions_round_trip() {
        for text in ["192.0.2.7", "2001:db8::7"] {
            let ip: IpAddr = text.parse().expect("ip");
            assert_eq!(u128_to_ip(Family::of(ip), ip_to_u128(ip)), ip);
        }
        assert_eq!(
            net_from(
                Family::V4,
                ip_to_u128("192.0.2.77".parse().expect("ip")),
                26
            ),
            net("192.0.2.64/26")
        );
        assert!(has_host_bits(&net("192.0.2.1/24")));
        assert!(contains_net(&net("192.0.2.0/24"), &net("192.0.2.128/25")));
        assert!(!contains_net(&net("192.0.2.128/25"), &net("192.0.2.0/24")));
        assert!(!contains_net(&net("192.0.2.0/24"), &net("2001:db8::/64")));
    }

    #[test]
    fn edge_addresses_of_both_families() {
        let ip = |text: &str| -> IpAddr { text.parse().expect("ip") };
        let v4 = net("192.0.2.0/24");
        assert_eq!(
            edge_address(&v4, ip("192.0.2.0")),
            Some(EdgeAddress::Network)
        );
        assert_eq!(
            edge_address(&v4, ip("192.0.2.255")),
            Some(EdgeAddress::Broadcast)
        );
        assert_eq!(edge_address(&v4, ip("192.0.2.1")), None);
        assert_eq!(edge_address(&v4, ip("198.51.100.0")), None, "outside");
        assert_eq!(
            edge_address(&net("192.0.2.4/30"), ip("192.0.2.7")),
            Some(EdgeAddress::Broadcast)
        );
        assert_eq!(
            edge_address(&net("192.0.2.0/31"), ip("192.0.2.0")),
            None,
            "RFC 3021"
        );
        assert_eq!(edge_address(&net("192.0.2.9/32"), ip("192.0.2.9")), None);
        let v6 = net("2001:db8::/64");
        assert_eq!(
            edge_address(&v6, ip("2001:db8::")),
            Some(EdgeAddress::SubnetRouterAnycast)
        );
        assert_eq!(
            edge_address(&v6, ip("2001:db8::ffff:ffff:ffff:ffff")),
            None,
            "IPv6 has no broadcast"
        );
        assert_eq!(
            edge_address(&net("2001:db8::/127"), ip("2001:db8::")),
            None,
            "RFC 6164"
        );
        assert_eq!(edge_address(&v6, ip("192.0.2.0")), None, "other family");
    }

    #[test]
    fn alignment() {
        assert_eq!(align_up(Family::V4, 5, 30), Some(8));
        assert_eq!(align_up(Family::V4, 8, 30), Some(8));
        assert_eq!(align_down(Family::V4, 11, 30), 8);
        assert_eq!(align_up(Family::V6, u128::MAX, 64), None);
    }
}
