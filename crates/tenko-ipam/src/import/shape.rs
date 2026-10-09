//! Value shapes and the lenient parsers behind them.
//!
//! The mapping step shows, for every column, how many values look like an address, a
//! network in CIDR notation, an address range, a MAC address, a DUID, a number or text,
//! and suggests a target from the dominant shape when the header says nothing. The same
//! parsers turn cells into model values during translation, so a value that is counted
//! as an address is also imported as one.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{MacAddr, net::Duid};
use utoipa::ToSchema;

/// The shape of one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Shape {
    /// Nothing.
    Empty,
    /// An IPv4 or IPv6 address (`192.0.2.10`, `2001:db8::10`).
    Address,
    /// A network or an address with a prefix length (`192.0.2.0/24`, `192.0.2.5/24`).
    Cidr,
    /// An address range (`192.0.2.10-20`, `192.0.2.10-192.0.2.20`).
    Range,
    /// A MAC address in any common notation.
    Mac,
    /// A DHCPv6 DUID: hexadecimal octets, more than six.
    Duid,
    /// A number.
    Number,
    /// Anything else.
    Text,
}

/// How many values of a column have each shape.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ShapeCounts {
    /// Empty cells.
    pub empty: usize,
    /// Addresses.
    pub address: usize,
    /// Networks and addresses with a prefix length.
    pub cidr: usize,
    /// Address ranges.
    pub range: usize,
    /// MAC addresses.
    pub mac: usize,
    /// DUIDs.
    pub duid: usize,
    /// Numbers.
    pub number: usize,
    /// Text.
    pub text: usize,
}

impl ShapeCounts {
    /// Counts one value.
    pub fn add(&mut self, shape: Shape) {
        let slot = match shape {
            Shape::Empty => &mut self.empty,
            Shape::Address => &mut self.address,
            Shape::Cidr => &mut self.cidr,
            Shape::Range => &mut self.range,
            Shape::Mac => &mut self.mac,
            Shape::Duid => &mut self.duid,
            Shape::Number => &mut self.number,
            Shape::Text => &mut self.text,
        };
        *slot += 1;
    }

    /// Values that are not empty.
    pub fn filled(&self) -> usize {
        self.address + self.cidr + self.range + self.mac + self.duid + self.number + self.text
    }

    /// The count of one shape.
    pub fn get(&self, shape: Shape) -> usize {
        match shape {
            Shape::Empty => self.empty,
            Shape::Address => self.address,
            Shape::Cidr => self.cidr,
            Shape::Range => self.range,
            Shape::Mac => self.mac,
            Shape::Duid => self.duid,
            Shape::Number => self.number,
            Shape::Text => self.text,
        }
    }

    /// The shape of at least `percent` of the non-empty values, if any. Addresses and
    /// ranges count together as addresses (a range cell in an address column).
    pub fn dominant(&self, percent: usize) -> Option<Shape> {
        let filled = self.filled();
        if filled == 0 {
            return None;
        }
        let candidates = [
            (Shape::Address, self.address + self.range),
            (Shape::Cidr, self.cidr),
            (Shape::Mac, self.mac),
            (Shape::Duid, self.duid),
            (Shape::Number, self.number),
            (Shape::Text, self.text),
        ];
        candidates
            .into_iter()
            .find(|(_, count)| count * 100 >= filled * percent)
            .map(|(shape, _)| shape)
    }
}

/// The most octets a DUID can have (RFC 8415).
const MAX_DUID_OCTETS: usize = 130;

/// The shape of a value (surrounding whitespace ignored).
///
/// The checks run in this order: empty, address, network, range, MAC, DUID, number, text.
/// A dotted-quad netmask (`255.255.255.0`) is an [`Shape::Address`]: masks are recognized by
/// their column header, not by their shape. Two refinements keep common values apart from
/// the hexadecimal shapes: plain digits are a [`Shape::Number`] (never a DUID, and never a
/// MAC), and eight colon-separated octets (`00:01:00:01:2a:3b:4c:5d`) are a DUID although
/// they would also read as an IPv6 address.
pub fn shape_of(value: &str) -> Shape {
    let value = value.trim();
    if value.is_empty() {
        return Shape::Empty;
    }
    if !is_eight_octets(value) && parse_address(value).is_some() {
        return Shape::Address;
    }
    if parse_cidr(value).is_some() {
        return Shape::Cidr;
    }
    if parse_range(value).is_some() {
        return Shape::Range;
    }
    if parse_mac(value).is_some() {
        return Shape::Mac;
    }
    let plain_digits = value.bytes().all(|byte| byte.is_ascii_digit());
    if !plain_digits && parse_duid(value).is_some() {
        return Shape::Duid;
    }
    if is_number(value) {
        return Shape::Number;
    }
    Shape::Text
}

/// Parses an address leniently: IPv4 octets may carry leading zeros (`192.000.002.010`),
/// IPv6 in any standard form, optionally in brackets (`[2001:db8::1]`); surrounding
/// whitespace is ignored.
pub fn parse_address(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    if value.contains(':') {
        let inner = value
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(value);
        inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
    } else {
        parse_ipv4(value).map(IpAddr::V4)
    }
}

/// Parses a network or an address with a prefix length: `192.0.2.0/24`,
/// `192.0.2.5/24` (host bits kept: the caller decides), `192.0.2.0/255.255.255.0` (a
/// contiguous mask), `2001:db8::/32`.
pub fn parse_cidr(value: &str) -> Option<IpNet> {
    let (address, length) = value.trim().split_once('/')?;
    let address = parse_address(address)?;
    let length = length.trim();
    let prefix = match address {
        IpAddr::V4(_) if length.contains('.') => mask_length(parse_ipv4(length)?)?,
        IpAddr::V4(_) => parse_length(length, false)?,
        IpAddr::V6(_) => parse_length(length, true)?,
    };
    IpNet::new(address, prefix).ok()
}

/// Parses an address range into its first and last address, both of one family and
/// ascending: `192.0.2.10-20` (last octet shorthand), `192.0.2.10-192.0.2.20`,
/// `192.0.2.10 - 192.0.2.20`, `2001:db8::10-2001:db8::1f`.
pub fn parse_range(value: &str) -> Option<(IpAddr, IpAddr)> {
    let (first, last) = value.trim().split_once('-')?;
    if last.contains('-') {
        return None;
    }
    let first = parse_address(first)?;
    let last = last.trim();
    let last = match first {
        IpAddr::V4(start) if !last.contains('.') && !last.contains(':') => {
            let [a, b, c, _] = start.octets();
            IpAddr::V4(Ipv4Addr::new(a, b, c, parse_octet(last)?))
        }
        _ => parse_address(last)?,
    };
    let ascending = match (first, last) {
        (IpAddr::V4(first), IpAddr::V4(last)) => first <= last,
        (IpAddr::V6(first), IpAddr::V6(last)) => first <= last,
        _ => false,
    };
    ascending.then_some((first, last))
}

/// Parses a subnet mask (`255.255.255.0`) or a prefix length (`24`, `/24`) into a prefix
/// length, for the family given by `ipv6`. A non-contiguous mask is refused, and so is a
/// dotted mask for IPv6.
pub fn parse_mask(value: &str, ipv6: bool) -> Option<u8> {
    let value = value.trim();
    let value = value.strip_prefix('/').unwrap_or(value).trim();
    if value.contains('.') {
        if ipv6 {
            return None;
        }
        mask_length(parse_ipv4(value)?)
    } else {
        parse_length(value, ipv6)
    }
}

/// Parses a MAC address in colon, hyphen, Cisco dot or plain hexadecimal notation, any
/// case. Plain digits without separators or hexadecimal letters are not taken as a MAC.
pub fn parse_mac(value: &str) -> Option<MacAddr> {
    let value = value.trim();
    let bytes = if let Some(separator) = separator_of(value) {
        let groups: Vec<&str> = value.split(separator).collect();
        if groups.len() != 6 || groups.iter().any(|group| group.len() != 2) {
            return None;
        }
        decode_hex(groups)?
    } else if value.contains('.') {
        let groups: Vec<&str> = value.split('.').collect();
        if groups.len() != 3 || groups.iter().any(|group| group.len() != 4) {
            return None;
        }
        decode_hex(groups)?
    } else {
        // Twelve digits are a number unless a letter proves the hexadecimal reading.
        if value.len() != 12 || !value.bytes().any(|byte| byte.is_ascii_alphabetic()) {
            return None;
        }
        decode_hex([value])?
    };
    let octets: [u8; 6] = bytes.try_into().ok()?;
    Some(MacAddr::new(octets))
}

/// Parses a DUID: hexadecimal octets (with `:` or `-` separators, or none), more than
/// six octets and at most 130.
pub fn parse_duid(value: &str) -> Option<Duid> {
    let value = value.trim();
    let bytes = if let Some(separator) = separator_of(value) {
        let groups: Vec<&str> = value.split(separator).collect();
        if groups.iter().any(|group| group.len() != 2) {
            return None;
        }
        decode_hex(groups)?
    } else {
        decode_hex([value])?
    };
    // Six octets are a MAC address, not a DUID.
    if bytes.len() <= 6 || bytes.len() > MAX_DUID_OCTETS {
        return None;
    }
    Duid::new(bytes).ok()
}

/// The separator (`:` or `-`) a hexadecimal value uses, `None` when it has neither.
fn separator_of(value: &str) -> Option<char> {
    [':', '-']
        .into_iter()
        .find(|separator| value.contains(*separator))
}

/// Whether `value` is eight colon-separated groups of exactly two hexadecimal digits.
fn is_eight_octets(value: &str) -> bool {
    let mut groups = 0;
    for group in value.split(':') {
        groups += 1;
        if group.len() != 2 || !group.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return false;
        }
    }
    groups == 8
}

/// Decodes the hexadecimal digits of all `groups`, which together must hold an even
/// number of digits.
fn decode_hex<'a>(groups: impl IntoIterator<Item = &'a str>) -> Option<Vec<u8>> {
    let mut nibbles = Vec::new();
    for group in groups {
        for byte in group.bytes() {
            let digit = char::from(byte).to_digit(16)?;
            nibbles.push(u8::try_from(digit).ok()?);
        }
    }
    if nibbles.len() % 2 != 0 {
        return None;
    }
    let (pairs, _) = nibbles.as_chunks::<2>();
    Some(pairs.iter().map(|[high, low]| (high << 4) | low).collect())
}

/// Parses one decimal octet of one to three digits (leading zeros allowed).
fn parse_octet(part: &str) -> Option<u8> {
    if part.is_empty() || part.len() > 3 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    part.parse::<u8>().ok()
}

/// Parses a dotted-quad IPv4 address, leading zeros allowed (and read as decimal).
fn parse_ipv4(value: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut parts = value.split('.');
    for slot in &mut octets {
        *slot = parse_octet(parts.next()?)?;
    }
    parts.next().is_none().then(|| Ipv4Addr::from(octets))
}

/// The prefix length of a contiguous netmask, `None` for a mask with holes.
fn mask_length(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    let rest = bits.checked_shl(ones).unwrap_or(0);
    if rest == 0 {
        u8::try_from(ones).ok()
    } else {
        None
    }
}

/// Parses a plain prefix length within the bits of the family.
fn parse_length(text: &str, ipv6: bool) -> Option<u8> {
    if text.is_empty() || text.len() > 3 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let length = text.parse::<u8>().ok()?;
    (length <= if ipv6 { 128 } else { 32 }).then_some(length)
}

/// Whether `value` reads as a number: an integer or a decimal with a point or a comma.
fn is_number(value: &str) -> bool {
    let rest = value.strip_prefix(['+', '-']).unwrap_or(value);
    if let Some((whole, fraction)) = rest.split_once(',') {
        // A decimal comma: digits on both sides, and only one comma.
        return !whole.is_empty()
            && !fraction.is_empty()
            && whole.bytes().all(|byte| byte.is_ascii_digit())
            && fraction.bytes().all(|byte| byte.is_ascii_digit());
    }
    // The leading digit or point keeps words such as `inf` and `nan` out.
    matches!(rest.bytes().next(), Some(b'0'..=b'9' | b'.')) && rest.parse::<f64>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    #[test]
    fn empty_values() {
        assert_eq!(shape_of(""), Shape::Empty);
        assert_eq!(shape_of("   \t"), Shape::Empty);
    }

    #[test]
    fn address_shapes() {
        assert_eq!(shape_of("192.0.2.10"), Shape::Address);
        assert_eq!(shape_of(" 192.000.002.010 "), Shape::Address);
        assert_eq!(shape_of("2001:db8::10"), Shape::Address);
        assert_eq!(shape_of("[2001:db8::1]"), Shape::Address);
        assert_eq!(shape_of("::1"), Shape::Address);
        // A netmask is an address; the header tells it apart.
        assert_eq!(shape_of("255.255.255.0"), Shape::Address);
    }

    #[test]
    fn address_parsing() {
        assert_eq!(parse_address("192.0.2.10"), Some(addr("192.0.2.10")));
        assert_eq!(parse_address("192.000.002.010"), Some(addr("192.0.2.10")));
        assert_eq!(
            parse_address("  198.51.100.7\t"),
            Some(addr("198.51.100.7"))
        );
        assert_eq!(parse_address("2001:db8::1"), Some(addr("2001:db8::1")));
        assert_eq!(parse_address("[2001:DB8::1]"), Some(addr("2001:db8::1")));
        assert_eq!(
            parse_address("2001:0db8:0000:0000:0000:0000:0000:0001"),
            Some(addr("2001:db8::1"))
        );
        assert_eq!(parse_address("0.0.0.0"), Some(addr("0.0.0.0")));
        assert_eq!(
            parse_address("255.255.255.255"),
            Some(addr("255.255.255.255"))
        );
    }

    #[test]
    fn address_rejections() {
        for bad in [
            "",
            "192.0.2",
            "192.0.2.256",
            "192.0.2.10.1",
            "192.0.2.",
            ".192.0.2.10",
            "192.0.2.1000",
            "192.0.+2.10",
            "192.0.2.-1",
            "192.0.2.a",
            "[192.0.2.1]",
            "[2001:db8::1",
            "2001:db8::g",
            "12345",
            "example.test",
        ] {
            assert_eq!(parse_address(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn cidr_shapes_and_parsing() {
        assert_eq!(shape_of("192.0.2.0/24"), Shape::Cidr);
        assert_eq!(shape_of("192.0.2.5/24"), Shape::Cidr);
        assert_eq!(shape_of("192.0.2.0/255.255.255.0"), Shape::Cidr);
        assert_eq!(shape_of("2001:db8::/32"), Shape::Cidr);

        let net = parse_cidr("192.0.2.0/24").unwrap();
        assert_eq!(net.to_string(), "192.0.2.0/24");
        // Host bits are kept.
        let host = parse_cidr("192.0.2.5/24").unwrap();
        assert_eq!(host.addr(), addr("192.0.2.5"));
        assert_eq!(host.prefix_len(), 24);
        let masked = parse_cidr("198.51.100.0/255.255.255.128").unwrap();
        assert_eq!(masked.prefix_len(), 25);
        assert_eq!(
            parse_cidr("203.0.113.9/255.255.255.255")
                .unwrap()
                .prefix_len(),
            32
        );
        assert_eq!(parse_cidr("0.0.0.0/0").unwrap().prefix_len(), 0);
        assert_eq!(
            parse_cidr(" 192.000.002.000 / 24 ").unwrap().to_string(),
            "192.0.2.0/24"
        );
        let v6 = parse_cidr("2001:db8::5/64").unwrap();
        assert_eq!(v6.addr(), addr("2001:db8::5"));
        assert_eq!(v6.prefix_len(), 64);
        assert_eq!(parse_cidr("2001:db8::/128").unwrap().prefix_len(), 128);
    }

    #[test]
    fn cidr_rejections() {
        for bad in [
            "192.0.2.0",
            "192.0.2.0/",
            "192.0.2.0/33",
            "2001:db8::/129",
            "192.0.2.0/255.0.255.0",
            "192.0.2.0/0.0.0.255",
            "192.0.2.0/24/8",
            "192.0.2.0/-1",
            "192.0.2.0/ab",
            "/24",
            "2001:db8::/255.255.255.0",
            "example.test/24",
        ] {
            assert_eq!(parse_cidr(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn range_shapes_and_parsing() {
        assert_eq!(shape_of("192.0.2.10-20"), Shape::Range);
        assert_eq!(shape_of("192.0.2.10-192.0.2.20"), Shape::Range);
        assert_eq!(shape_of("192.0.2.10 - 192.0.2.20"), Shape::Range);
        assert_eq!(shape_of("2001:db8::10-2001:db8::1f"), Shape::Range);

        assert_eq!(
            parse_range("192.0.2.10-20"),
            Some((addr("192.0.2.10"), addr("192.0.2.20")))
        );
        assert_eq!(
            parse_range("192.0.2.10 - 20"),
            Some((addr("192.0.2.10"), addr("192.0.2.20")))
        );
        assert_eq!(
            parse_range("198.51.100.1-198.51.101.9"),
            Some((addr("198.51.100.1"), addr("198.51.101.9")))
        );
        assert_eq!(
            parse_range(" 192.0.2.10 - 192.0.2.20 "),
            Some((addr("192.0.2.10"), addr("192.0.2.20")))
        );
        assert_eq!(
            parse_range("2001:db8::10-2001:db8::1f"),
            Some((addr("2001:db8::10"), addr("2001:db8::1f")))
        );
        assert_eq!(
            parse_range("192.0.2.10-10"),
            Some((addr("192.0.2.10"), addr("192.0.2.10")))
        );
    }

    #[test]
    fn range_rejections() {
        for bad in [
            "192.0.2.20-10",
            "192.0.2.20-192.0.2.10",
            "192.0.2.10-256",
            "192.0.2.10-",
            "-192.0.2.10",
            "192.0.2.10-2001:db8::1",
            "2001:db8::10-192.0.2.20",
            "2001:db8::1f-2001:db8::10",
            "192.0.2.10-20-30",
            "192.0.2.10-x",
            "2026-10-09",
            "10-20",
        ] {
            assert_eq!(parse_range(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn mask_parsing() {
        assert_eq!(parse_mask("255.255.255.0", false), Some(24));
        assert_eq!(parse_mask("0.0.0.0", false), Some(0));
        assert_eq!(parse_mask("255.255.255.255", false), Some(32));
        assert_eq!(parse_mask("255.255.254.0", false), Some(23));
        assert_eq!(parse_mask("128.0.0.0", false), Some(1));
        assert_eq!(parse_mask("24", false), Some(24));
        assert_eq!(parse_mask("/24", false), Some(24));
        assert_eq!(parse_mask(" /26 ", false), Some(26));
        assert_eq!(parse_mask("0", false), Some(0));
        assert_eq!(parse_mask("32", false), Some(32));
        assert_eq!(parse_mask("33", false), None);
        assert_eq!(parse_mask("64", true), Some(64));
        assert_eq!(parse_mask("/128", true), Some(128));
        assert_eq!(parse_mask("129", true), None);
        assert_eq!(parse_mask("255.255.255.0", true), None);
        assert_eq!(parse_mask("255.0.255.0", false), None);
        assert_eq!(parse_mask("0.0.0.255", false), None);
        assert_eq!(parse_mask("255.255.255.256", false), None);
        assert_eq!(parse_mask("", false), None);
        assert_eq!(parse_mask("/", false), None);
        assert_eq!(parse_mask("-1", false), None);
        assert_eq!(parse_mask("abc", false), None);
    }

    #[test]
    fn mac_notations() {
        let expected = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
        for text in [
            "00:00:5E:00:53:01",
            "00:00:5e:00:53:01",
            "00-00-5e-00-53-01",
            "00-00-5E-00-53-01",
            "0000.5e00.5301",
            "0000.5E00.5301",
            "00005e005301",
            "00005E005301",
            "  00:00:5e:00:53:01  ",
        ] {
            assert_eq!(parse_mac(text), Some(expected), "{text:?}");
            assert_eq!(shape_of(text), Shape::Mac, "{text:?}");
        }
    }

    #[test]
    fn mac_rejections() {
        for bad in [
            "",
            // Plain digits stay numbers.
            "123456789012",
            "000000000000",
            "00:00:5e:00:53",
            "00:00:5e:00:53:01:02",
            "00:00:5e:00:53:0",
            "00:00-5e:00:53:01",
            "0000.5e00",
            "0000.5e00.5301.0000",
            "0000:5e00:5301",
            "00005e00530",
            "00005e0053011",
            "00:00:5g:00:53:01",
            "0:0:5e:0:53:1",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad:?}");
        }
        assert_eq!(shape_of("123456789012"), Shape::Number);
    }

    #[test]
    fn duid_forms() {
        let colon = "00:03:00:01:00:00:5e:00:53:01";
        let duid = parse_duid(colon).unwrap();
        assert_eq!(duid.as_bytes().len(), 10);
        assert_eq!(duid.to_string(), colon);
        assert_eq!(parse_duid("00-03-00-01-00-00-5e-00-53-01").unwrap(), duid);
        assert_eq!(parse_duid("0003000100005e005301").unwrap(), duid);
        assert_eq!(parse_duid("0003000100005E005301").unwrap(), duid);
        assert_eq!(shape_of(colon), Shape::Duid);
        assert_eq!(shape_of("00030001-0000-5e00-5301"), Shape::Text);
        // Seven octets is the shortest DUID this parser takes.
        assert!(parse_duid("00:01:02:03:04:05:06").is_some());
        // Eight colon-separated octets are also a valid IPv6 address; the shape is a DUID.
        assert_eq!(shape_of("00:01:00:01:2a:3b:4c:5d"), Shape::Duid);
        // A DUID of 130 octets is the longest.
        let longest = vec!["ab"; 130].join(":");
        assert_eq!(parse_duid(&longest).unwrap().as_bytes().len(), 130);
        let too_long = vec!["ab"; 131].join(":");
        assert_eq!(parse_duid(&too_long), None);
    }

    #[test]
    fn duid_rejections() {
        for bad in [
            "",
            // Six octets are a MAC address.
            "00:00:5e:00:53:01",
            "00005e005301",
            // Odd number of digits without separators.
            "00030001000053010",
            "00:03:00:01:00:00:5e:00:53:1",
            "00:03:00:01:00:00:5e:00:53:xx",
            "00:03:00-01:00:00:5e:00:53:01",
            "0x00030001000053010a",
            "zz030001000053010a",
        ] {
            assert_eq!(parse_duid(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn long_digit_strings_stay_numbers() {
        assert_eq!(shape_of("12345678901234"), Shape::Number);
        assert_eq!(shape_of("20261009123045"), Shape::Number);
    }

    #[test]
    fn number_shapes() {
        for number in [
            "0", "1234", "-5", "+7", "12.5", "-0.5", ".5", "5.", "1,5", "-12,25", "1e3", "2.5E-3",
            "007",
        ] {
            assert_eq!(shape_of(number), Shape::Number, "{number:?}");
        }
    }

    #[test]
    fn text_shapes() {
        for text in [
            "web01",
            "example.test",
            "inf",
            "NaN",
            "infinity",
            "1,234,567",
            "1,2,3",
            ",5",
            "5,",
            "--5",
            "+-5",
            "192.0.2",
            "192.0.2.256",
            "192.0.2.0/33",
            "2026-10-09",
            "10-20",
            "0x10",
            "1_000",
            "12%",
            "n/a",
        ] {
            assert_eq!(shape_of(text), Shape::Text, "{text:?}");
        }
    }

    #[test]
    fn counts_add_filled_and_get() {
        let mut counts = ShapeCounts::default();
        for shape in [
            Shape::Empty,
            Shape::Address,
            Shape::Address,
            Shape::Cidr,
            Shape::Range,
            Shape::Mac,
            Shape::Duid,
            Shape::Number,
            Shape::Text,
        ] {
            counts.add(shape);
        }
        assert_eq!(counts.get(Shape::Address), 2);
        assert_eq!(counts.get(Shape::Empty), 1);
        assert_eq!(counts.filled(), 8);
    }

    fn counts_of(values: &[&str]) -> ShapeCounts {
        let mut counts = ShapeCounts::default();
        for value in values {
            counts.add(shape_of(value));
        }
        counts
    }

    #[test]
    fn dominant_shape() {
        assert_eq!(ShapeCounts::default().dominant(60), None);
        let only_empty = counts_of(&["", " "]);
        assert_eq!(only_empty.dominant(60), None);

        let addresses = counts_of(&["192.0.2.1", "192.0.2.2", "192.0.2.3", "", "n/a"]);
        assert_eq!(addresses.dominant(60), Some(Shape::Address));
        // 3 of 4 filled values: above 75, not above 80.
        assert_eq!(addresses.dominant(75), Some(Shape::Address));
        assert_eq!(addresses.dominant(80), None);

        // Ranges count as addresses.
        let mixed = counts_of(&["192.0.2.1", "192.0.2.10-20", "192.0.2.3", "x"]);
        assert_eq!(mixed.dominant(75), Some(Shape::Address));
        assert_eq!(mixed.dominant(100), None);

        let networks = counts_of(&["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]);
        assert_eq!(networks.dominant(100), Some(Shape::Cidr));

        let macs = counts_of(&["00:00:5e:00:53:01", "00-00-5e-00-53-02"]);
        assert_eq!(macs.dominant(100), Some(Shape::Mac));

        let duids = counts_of(&["00:03:00:01:00:00:5e:00:53:01"]);
        assert_eq!(duids.dominant(100), Some(Shape::Duid));

        let numbers = counts_of(&["1", "2", "3.5", "text"]);
        assert_eq!(numbers.dominant(75), Some(Shape::Number));

        let words = counts_of(&["alpha", "beta", "gamma"]);
        assert_eq!(words.dominant(50), Some(Shape::Text));

        let split = counts_of(&["192.0.2.1", "alpha"]);
        assert_eq!(split.dominant(60), None);
        assert_eq!(split.dominant(50), Some(Shape::Address));
    }
}
