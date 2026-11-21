//! Reverse names (RFC 1035 section 3.5 for `in-addr.arpa`, RFC 3596 section 2.5 for
//! `ip6.arpa`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The network a reverse zone of octet or nibble boundaries covers: `2.0.192.in-addr.arpa`
/// is `192.0.2.0/24`, `8.b.d.0.1.0.0.2.ip6.arpa` is `2001:db8::/32`. `name` is in canonical
/// form (lowercase, no trailing dot). `None` for any other name: another tree, a label that
/// is not a decimal octet without a leading zero or a single hexadecimal digit, more labels
/// than the address has, or the trees' own apexes (they name no network a zone of one site
/// covers). An RFC 2317 delegation label (`0/26`) is not an octet, so it is `None` too.
pub fn zone_network(name: &str) -> Option<(IpAddr, u8)> {
    if let Some(labels) = name.strip_suffix(".in-addr.arpa") {
        let mut octets = [0u8; 4];
        let count = fill(labels, &mut octets, |label| {
            let valid = !label.is_empty()
                && label.len() <= 3
                && label.bytes().all(|b| b.is_ascii_digit())
                && (label == "0" || !label.starts_with('0'));
            valid.then(|| label.parse().ok()).flatten()
        })?;
        return Some((IpAddr::V4(Ipv4Addr::from(octets)), count * 8));
    }
    let labels = name.strip_suffix(".ip6.arpa")?;
    let mut nibbles = [0u8; 32];
    let count = fill(labels, &mut nibbles, |label| match label.as_bytes() {
        [digit @ b'0'..=b'9'] => Some(digit - b'0'),
        [digit @ b'a'..=b'f'] => Some(digit - b'a' + 10),
        _ => None,
    })?;
    let mut octets = [0u8; 16];
    for (index, nibble) in nibbles.iter().enumerate() {
        octets[index / 2] |= nibble << if index % 2 == 0 { 4 } else { 0 };
    }
    Some((IpAddr::V6(Ipv6Addr::from(octets)), count * 4))
}

/// Writes the labels of `labels`, read from the right, into `out` from the left; the number
/// of labels, or `None` when one does not parse or there are more than `out` holds.
fn fill(labels: &str, out: &mut [u8], parse: impl Fn(&str) -> Option<u8>) -> Option<u8> {
    let mut count = 0;
    for label in labels.rsplit('.') {
        *out.get_mut(count)? = parse(label)?;
        count += 1;
    }
    u8::try_from(count).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str, len: u8) -> (IpAddr, u8) {
        (text.parse().expect("an address"), len)
    }

    #[test]
    fn reverse_zones_name_their_networks() {
        for (zone, address, len) in [
            ("2.0.192.in-addr.arpa", "192.0.2.0", 24),
            ("192.in-addr.arpa", "192.0.0.0", 8),
            ("10.2.0.192.in-addr.arpa", "192.0.2.10", 32),
            ("8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::", 32),
            ("2.ip6.arpa", "2000::", 4),
        ] {
            assert_eq!(zone_network(zone), Some(net(address, len)), "{zone}");
        }
    }

    #[test]
    fn other_names_name_no_network() {
        for name in [
            "in-addr.arpa",
            "ip6.arpa",
            ".in-addr.arpa",
            "corp.example.test",
            "02.0.192.in-addr.arpa",
            "256.0.192.in-addr.arpa",
            "0/26.2.0.192.in-addr.arpa",
            "1.10.2.0.192.in-addr.arpa",
            "x.0.192.in-addr.arpa",
            "ab.8.b.d.0.1.0.0.2.ip6.arpa",
            "B.d.0.1.0.0.2.ip6.arpa",
            "2.0.192.in-addr.arpa.example.test",
        ] {
            assert_eq!(zone_network(name), None, "{name}");
        }
        let full = "1.".repeat(32) + "ip6.arpa";
        assert_eq!(
            zone_network(&full).map(|(_, len)| len),
            Some(128),
            "32 nibbles"
        );
        let over = "1.".repeat(33) + "ip6.arpa";
        assert_eq!(zone_network(&over), None, "33 nibbles");
    }
}
