//! Reverse names (plan section 2.6, DNS-22): the PTR name of an address, the reverse zones
//! that cover a prefix, and the RFC 2317 form for an IPv4 network smaller than a /24.
//!
//! | Network | Zones |
//! |---|---|
//! | IPv4 /0 to /24 | one zone per octet boundary at or below the prefix length: a /16 is `b.a.in-addr.arpa`, a /22 is four /24 zones, a /12 sixteen /16 zones |
//! | IPv4 /25 to /32 | one RFC 2317 zone `<first>/<len>.c.b.a.in-addr.arpa` (`64/26.2.0.192.in-addr.arpa`), with the CNAME of each address in the parent `c.b.a.in-addr.arpa` |
//! | IPv6 /0 to /124 | one zone per nibble boundary at or below the prefix length: a /48 is one zone of 12 nibbles, a /62 four zones of 16 nibbles |
//!
//! A prefix length off the boundary rounds up, so the zones cover the prefix and nothing
//! outside it: a reverse zone wider than the prefix would shadow addresses Tenko does not
//! own. An IPv6 prefix longer than /124 gets no zone.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tenko_core::dns::DnsName;

/// `in-addr.arpa`.
pub const IN_ADDR: &str = "in-addr.arpa";
/// `ip6.arpa`.
pub const IP6: &str = "ip6.arpa";

/// The longest IPv6 prefix that gets a reverse zone.
pub const MAX_V6_LEN: u8 = 124;

/// A reverse zone that covers part of a prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReverseZone {
    /// A zone on an octet (IPv4) or nibble (IPv6) boundary.
    Plain {
        /// The apex.
        name: DnsName,
        /// The network it covers.
        net: IpNet,
    },
    /// The RFC 2317 zone of an IPv4 network smaller than a /24.
    Classless {
        /// The apex, `<first>/<len>.c.b.a.in-addr.arpa`.
        name: DnsName,
        /// The network it covers.
        net: Ipv4Net,
        /// The `/24` zone above it, `c.b.a.in-addr.arpa`, where the CNAMEs go.
        parent: DnsName,
    },
}

impl ReverseZone {
    /// The apex.
    pub fn name(&self) -> &DnsName {
        match self {
            ReverseZone::Plain { name, .. } | ReverseZone::Classless { name, .. } => name,
        }
    }

    /// The network it covers.
    pub fn net(&self) -> IpNet {
        match self {
            ReverseZone::Plain { net, .. } => *net,
            ReverseZone::Classless { net, .. } => IpNet::V4(*net),
        }
    }
}

fn name(text: &str) -> DnsName {
    // Every caller builds the text from digits, hexadecimal nibbles, `/` and the two
    // suffixes, which are valid DNS names by construction.
    DnsName::new(text).unwrap_or_else(|_| DnsName::root())
}

fn octets_reversed(octets: &[u8]) -> String {
    octets
        .iter()
        .rev()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn nibbles_reversed(ip: Ipv6Addr, count: usize) -> String {
    let bits = u128::from(ip);
    (0..count)
        .rev()
        .map(|index| {
            let shift = 124 - 4 * index;
            format!("{:x}", (bits >> shift) & 0xf)
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// The PTR owner name of an address in the plain tree: `10.2.0.192.in-addr.arpa`, or the
/// 32 nibbles under `ip6.arpa`.
pub fn ptr_name(ip: IpAddr) -> DnsName {
    match ip {
        IpAddr::V4(ip) => name(&format!("{}.{IN_ADDR}", octets_reversed(&ip.octets()))),
        IpAddr::V6(ip) => name(&format!("{}.{IP6}", nibbles_reversed(ip, 32))),
    }
}

/// The PTR owner name of an IPv4 address inside an RFC 2317 zone:
/// `70.64/26.2.0.192.in-addr.arpa`.
pub fn classless_ptr_name(ip: Ipv4Addr, zone: &DnsName) -> DnsName {
    name(&format!("{}.{zone}", ip.octets()[3]))
}

/// The zone apex of a network on an octet or nibble boundary.
fn plain_zone(net: IpNet) -> DnsName {
    match net {
        IpNet::V4(net) => {
            let count = usize::from(net.prefix_len() / 8);
            let octets = net.network().octets();
            if count == 0 {
                name(IN_ADDR)
            } else {
                name(&format!("{}.{IN_ADDR}", octets_reversed(&octets[..count])))
            }
        }
        IpNet::V6(net) => {
            let count = usize::from(net.prefix_len() / 4);
            if count == 0 {
                name(IP6)
            } else {
                name(&format!("{}.{IP6}", nibbles_reversed(net.network(), count)))
            }
        }
    }
}

/// The RFC 2317 zone of an IPv4 network of /25 to /32.
pub fn classless_zone(net: Ipv4Net) -> ReverseZone {
    let octets = net.network().octets();
    let parent = name(&format!("{}.{IN_ADDR}", octets_reversed(&octets[..3])));
    ReverseZone::Classless {
        name: name(&format!("{}/{}.{parent}", octets[3], net.prefix_len())),
        net,
        parent,
    }
}

/// The reverse zones that cover `cidr` exactly (see the module documentation); empty for
/// an IPv6 prefix longer than [`MAX_V6_LEN`].
pub fn zones_for(cidr: IpNet) -> Vec<ReverseZone> {
    let cidr = cidr.trunc();
    match cidr {
        IpNet::V4(net) if net.prefix_len() > 24 => vec![classless_zone(net)],
        IpNet::V4(net) => {
            let boundary = net.prefix_len().div_ceil(8) * 8;
            net.subnets(boundary)
                .map(|subnets| {
                    subnets
                        .map(|sub| ReverseZone::Plain {
                            name: plain_zone(IpNet::V4(sub)),
                            net: IpNet::V4(sub),
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
        IpNet::V6(net) if net.prefix_len() > MAX_V6_LEN => Vec::new(),
        IpNet::V6(net) => {
            let boundary = net.prefix_len().div_ceil(4) * 4;
            net.subnets(boundary)
                .map(|subnets| {
                    subnets
                        .map(|sub| ReverseZone::Plain {
                            name: plain_zone(IpNet::V6(sub)),
                            net: IpNet::V6(sub),
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
    }
}

/// The network of a reverse zone apex: a plain zone on an octet or nibble boundary, or an
/// RFC 2317 zone in the `<first>/<len>` form; `None` for any other name.
pub fn parse_zone(apex: &DnsName) -> Option<ReverseZone> {
    let text = apex.as_str();
    if let Some(rest) = text
        .strip_suffix(IN_ADDR)
        .map(|rest| rest.strip_suffix('.').unwrap_or(rest))
    {
        let labels: Vec<&str> = if rest.is_empty() {
            Vec::new()
        } else {
            rest.split('.').collect()
        };
        if let [first, a, b, c] = labels.as_slice()
            && let Some((start, len)) = first.split_once('/')
        {
            let octets = [c, b, a].map(|label| label.parse::<u8>().ok());
            let [Some(c), Some(b), Some(a)] = octets else {
                return None;
            };
            let start: u8 = canonical_number(start)?;
            let len: u8 = canonical_number(len)?;
            if !(25..=32).contains(&len) {
                return None;
            }
            let net = Ipv4Net::new(Ipv4Addr::new(c, b, a, start), len).ok()?;
            if net.network() != Ipv4Addr::new(c, b, a, start) {
                return None;
            }
            return Some(classless_zone(net));
        }
        if labels.len() > 4 {
            return None;
        }
        let mut octets = [0u8; 4];
        for (index, label) in labels.iter().rev().enumerate() {
            octets[index] = canonical_number(label)?;
        }
        let len = u8::try_from(labels.len() * 8).ok()?;
        let net = Ipv4Net::new(Ipv4Addr::from(octets), len).ok()?;
        return Some(ReverseZone::Plain {
            name: apex.clone(),
            net: IpNet::V4(net),
        });
    }
    let rest = text
        .strip_suffix(IP6)
        .map(|rest| rest.strip_suffix('.').unwrap_or(rest))?;
    let labels: Vec<&str> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split('.').collect()
    };
    if labels.len() > 32 {
        return None;
    }
    let mut bits = 0u128;
    for (index, label) in labels.iter().rev().enumerate() {
        let [digit] = label.as_bytes() else {
            return None;
        };
        let value = char::from(*digit).to_digit(16)?;
        if char::from(*digit).is_ascii_uppercase() {
            return None;
        }
        bits |= u128::from(value) << (124 - 4 * index);
    }
    let len = u8::try_from(labels.len() * 4).ok()?;
    let net = Ipv6Net::new(Ipv6Addr::from(bits), len).ok()?;
    Some(ReverseZone::Plain {
        name: apex.clone(),
        net: IpNet::V6(net),
    })
}

/// A decimal number without leading zeros.
fn canonical_number(text: &str) -> Option<u8> {
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse().ok()
}

/// The RFC 2317 lines an operator adds to the parent zone when Tenko does not serve it: the
/// delegation and, as the BIND `$GENERATE` line, the CNAME of every address of the block.
pub fn delegation_lines(zone: &ReverseZone, name_servers: &[DnsName]) -> Vec<String> {
    let ReverseZone::Classless { name, net, parent } = zone else {
        return Vec::new();
    };
    let mut lines: Vec<String> = name_servers
        .iter()
        .map(|server| format!("{name}. IN NS {server}."))
        .collect();
    let first = net.network().octets()[3];
    let last = net.broadcast().octets()[3];
    lines.push(format!(
        "$GENERATE {first}-{last} $.{parent}. IN CNAME $.{name}."
    ));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> IpNet {
        text.parse().expect("net")
    }

    fn names(cidr: &str) -> Vec<String> {
        zones_for(net(cidr))
            .iter()
            .map(|zone| zone.name().to_string())
            .collect()
    }

    #[test]
    fn ptr_names_of_both_families() {
        assert_eq!(
            ptr_name("192.0.2.10".parse().expect("ip")).as_str(),
            "10.2.0.192.in-addr.arpa"
        );
        assert_eq!(
            ptr_name("2001:db8::1".parse().expect("ip")).as_str(),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn ipv4_zones_round_up_to_the_octet() {
        assert_eq!(names("192.0.2.0/24"), ["2.0.192.in-addr.arpa"]);
        assert_eq!(names("198.51.0.0/16"), ["51.198.in-addr.arpa"]);
        assert_eq!(names("198.0.0.0/8"), ["198.in-addr.arpa"]);
        assert_eq!(
            names("198.51.100.0/22"),
            [
                "100.51.198.in-addr.arpa",
                "101.51.198.in-addr.arpa",
                "102.51.198.in-addr.arpa",
                "103.51.198.in-addr.arpa"
            ]
        );
        assert_eq!(zones_for(net("198.16.0.0/12")).len(), 16);
        assert_eq!(names("0.0.0.0/0"), ["in-addr.arpa"]);
    }

    #[test]
    fn small_ipv4_networks_get_the_rfc_2317_form() {
        let zones = zones_for(net("192.0.2.64/26"));
        assert_eq!(
            zones,
            [ReverseZone::Classless {
                name: DnsName::new("64/26.2.0.192.in-addr.arpa").expect("name"),
                net: "192.0.2.64/26".parse().expect("net"),
                parent: DnsName::new("2.0.192.in-addr.arpa").expect("name"),
            }]
        );
        assert_eq!(names("192.0.2.128/25"), ["128/25.2.0.192.in-addr.arpa"]);
        assert_eq!(names("192.0.2.7/32"), ["7/32.2.0.192.in-addr.arpa"]);
        let zone = &zones[0];
        assert_eq!(
            classless_ptr_name("192.0.2.70".parse().expect("ip"), zone.name()).as_str(),
            "70.64/26.2.0.192.in-addr.arpa"
        );
    }

    #[test]
    fn ipv6_zones_round_up_to_the_nibble() {
        assert_eq!(names("2001:db8::/32"), ["8.b.d.0.1.0.0.2.ip6.arpa"]);
        assert_eq!(
            names("2001:db8:1::/48"),
            ["1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"]
        );
        assert_eq!(
            names("2001:db8:1:4::/62"),
            [
                "4.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
                "5.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
                "6.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
                "7.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
            ]
        );
        assert_eq!(zones_for(net("2001:db8::/126")), Vec::<ReverseZone>::new());
        assert_eq!(zones_for(net("2001:db8::/124")).len(), 1);
    }

    #[test]
    fn zone_names_parse_back_to_their_networks() {
        for cidr in [
            "192.0.2.0/24",
            "198.51.0.0/16",
            "198.0.0.0/8",
            "192.0.2.64/26",
            "192.0.2.7/32",
            "2001:db8::/32",
            "2001:db8:1:4::/64",
        ] {
            for zone in zones_for(net(cidr)) {
                assert_eq!(parse_zone(zone.name()), Some(zone.clone()), "{cidr}");
            }
        }
        for text in [
            "example.test",
            "300.2.0.192.in-addr.arpa",
            "02.0.192.in-addr.arpa",
            "65/26.2.0.192.in-addr.arpa",
            "0/24.2.0.192.in-addr.arpa",
            "1.2.3.4.5.in-addr.arpa",
            "ab.ip6.arpa",
        ] {
            let name = DnsName::new(text).expect("name");
            assert_eq!(parse_zone(&name), None, "{text}");
        }
    }

    #[test]
    fn the_delegation_lines_name_the_block() {
        let zone = classless_zone("192.0.2.64/26".parse().expect("net"));
        let servers = [DnsName::new("ns1.example.test").expect("name")];
        assert_eq!(
            delegation_lines(&zone, &servers),
            [
                "64/26.2.0.192.in-addr.arpa. IN NS ns1.example.test.",
                "$GENERATE 64-127 $.2.0.192.in-addr.arpa. IN CNAME $.64/26.2.0.192.in-addr.arpa."
            ]
        );
    }
}
