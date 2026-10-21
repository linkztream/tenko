//! The IPv4 header fields the raw methods read: the TTL and the don't-fragment flag for
//! the fingerprint, the protocol to tell TCP from UDP, the addresses, and where the
//! payload begins (past the variable-length options). The checksum is not verified: the
//! kernel delivered the frame, and the methods read only what they need.

use std::net::Ipv4Addr;

/// IP protocol number for TCP.
pub const PROTO_TCP: u8 = 6;
/// IP protocol number for UDP.
pub const PROTO_UDP: u8 = 17;

/// A parsed IPv4 header and its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4<'a> {
    /// The time to live (the hop count left); the basis of the fingerprint's TTL guess.
    pub ttl: u8,
    /// Whether the don't-fragment flag is set.
    pub dont_fragment: bool,
    /// The upper-layer protocol ([`PROTO_TCP`], [`PROTO_UDP`]).
    pub protocol: u8,
    /// The source address.
    pub source: Ipv4Addr,
    /// The destination address.
    pub destination: Ipv4Addr,
    /// The payload after the header and its options.
    pub payload: &'a [u8],
}

fn ipv4_at(bytes: &[u8], at: usize) -> Option<Ipv4Addr> {
    let slice: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(Ipv4Addr::from(slice))
}

/// Parses an IPv4 packet. The payload is bounded by the header's total-length field when
/// that is within the slice, so trailing padding of a short Ethernet frame is dropped.
pub fn parse(bytes: &[u8]) -> Option<Ipv4<'_>> {
    let first = *bytes.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(first & 0x0f) * 4;
    if header_len < 20 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?));
    let flags = *bytes.get(6)?;
    let dont_fragment = flags & 0x40 != 0;
    let ttl = *bytes.get(8)?;
    let protocol = *bytes.get(9)?;
    let source = ipv4_at(bytes, 12)?;
    let destination = ipv4_at(bytes, 16)?;
    let rest = bytes.get(header_len..)?;
    // Trust the total length only when it fits and covers at least the header.
    let payload = if total_len >= header_len && total_len <= bytes.len() {
        &bytes[header_len..total_len]
    } else {
        rest
    };
    Some(Ipv4 {
        ttl,
        dont_fragment,
        protocol,
        source,
        destination,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tcp_header_is_read() {
        let packet = [
            0x45, 0x00, 0x00, 0x1c, // version/IHL, DSCP, total length 28
            0x00, 0x00, 0x40, 0x00, // id, flags (DF), fragment offset
            0x40, 0x06, 0x00, 0x00, // TTL 64, protocol TCP, checksum
            0xc0, 0x00, 0x02, 0x09, // source 192.0.2.9
            0xc0, 0x00, 0x02, 0x05, // destination 192.0.2.5
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, // 8-byte payload
        ];
        let ip = parse(&packet).expect("ipv4");
        assert_eq!(ip.ttl, 64);
        assert!(ip.dont_fragment);
        assert_eq!(ip.protocol, PROTO_TCP);
        assert_eq!(ip.source, Ipv4Addr::new(192, 0, 2, 9));
        assert_eq!(ip.payload.len(), 8);
    }

    #[test]
    fn options_are_skipped() {
        let mut packet = vec![
            0x46, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x20, 0x11, 0x00, 0x00, 0xc0, 0x00,
            0x02, 0x01, 0xc0, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, // 4-byte option
        ];
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let ip = parse(&packet).expect("ipv4");
        assert!(!ip.dont_fragment);
        assert_eq!(ip.protocol, PROTO_UDP);
        assert_eq!(ip.payload, &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn a_non_ipv4_first_octet_is_rejected() {
        assert!(parse(&[0x60, 0x00]).is_none());
        assert!(parse(&[0x40, 0x00]).is_none());
    }
}
