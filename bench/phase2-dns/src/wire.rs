//! Raw DNS wire helpers for the load generator.
//!
//! The harness depends on no DNS crate: it builds queries from pre-encoded
//! names and reads only the fixed header of a response.

/// Size of the DNS header.
pub const HEADER_LEN: usize = 12;
/// Length of an OPT pseudo-record without options.
pub const OPT_LEN: usize = 11;
/// Octets reserved in front of every query for the TCP length prefix.
pub const FRAME_PREFIX: usize = 2;

pub const QCLASS_IN: u16 = 1;
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_NXDOMAIN: u8 = 3;

/// Loopback address used by tests: `$PHASE2_DNS_LOOPBACK` or 127.0.0.1.
///
/// WSL2 may intercept traffic to 127.0.0.1, so tests there can run with
/// `PHASE2_DNS_LOOPBACK=127.0.0.2`.
pub fn test_loopback() -> std::net::IpAddr {
    std::env::var("PHASE2_DNS_LOOPBACK")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

/// Decoded fixed header fields of a DNS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawHeader {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    /// Low four bits of the RCODE (the header part).
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

/// Parses the 12-byte header. Returns `None` if `buf` is shorter than that.
pub fn parse_header(buf: &[u8]) -> Option<RawHeader> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let u16_at = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]);
    Some(RawHeader {
        id: u16_at(0),
        qr: buf[2] & 0x80 != 0,
        opcode: (buf[2] >> 3) & 0x0f,
        aa: buf[2] & 0x04 != 0,
        tc: buf[2] & 0x02 != 0,
        rd: buf[2] & 0x01 != 0,
        ra: buf[3] & 0x80 != 0,
        rcode: buf[3] & 0x0f,
        qdcount: u16_at(4),
        ancount: u16_at(6),
        nscount: u16_at(8),
        arcount: u16_at(10),
    })
}

/// Writes a query into `out` (cleared first) and returns the length of the
/// message without the OPT record (the end of the question section).
///
/// `out` starts with [`FRAME_PREFIX`] zero octets, then the DNS message: a
/// UDP datagram is `out[FRAME_PREFIX..]`, a TCP frame is all of `out` once
/// the prefix is set to the message length. The returned length is relative to
/// the message. `rd` sets the recursion-desired bit.
pub fn write_query(
    out: &mut Vec<u8>,
    id: u16,
    qname_wire: &[u8],
    qtype: u16,
    edns_udp: Option<u16>,
    rd: bool,
) -> usize {
    out.clear();
    out.extend_from_slice(&[0; FRAME_PREFIX]);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[u8::from(rd), 0x00]);
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&u16::from(edns_udp.is_some()).to_be_bytes());
    out.extend_from_slice(qname_wire);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&QCLASS_IN.to_be_bytes());
    let qend = out.len() - FRAME_PREFIX;
    if let Some(udp) = edns_udp {
        out.push(0); // root owner
        out.extend_from_slice(&41u16.to_be_bytes()); // TYPE OPT
        out.extend_from_slice(&udp.to_be_bytes()); // CLASS = UDP payload size
        out.extend_from_slice(&[0, 0, 0, 0]); // ext-rcode, version, DO + Z
        out.extend_from_slice(&0u16.to_be_bytes()); // RDLEN
    }
    qend
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_layout() {
        let name = b"\x04host\x07example\x04test\x00";
        let mut q = Vec::new();
        let qend = write_query(&mut q, 0x1234, name, 1, Some(1232), false);
        assert_eq!(qend, HEADER_LEN + name.len() + 4);
        assert_eq!(q.len(), FRAME_PREFIX + qend + OPT_LEN);
        let h = parse_header(&q[FRAME_PREFIX..]).unwrap();
        assert_eq!(h.id, 0x1234);
        assert!(!h.qr && !h.rd);
        assert_eq!((h.qdcount, h.arcount), (1, 1));
        let qn = FRAME_PREFIX + HEADER_LEN;
        assert_eq!(&q[qn..qn + name.len()], name);

        let qend = write_query(&mut q, 7, name, 12, None, true);
        assert_eq!(q.len(), FRAME_PREFIX + qend);
        let h = parse_header(&q[FRAME_PREFIX..]).unwrap();
        assert!(h.rd);
        assert_eq!(h.arcount, 0);
    }

    #[test]
    fn short_header_is_none() {
        assert!(parse_header(&[0; 11]).is_none());
        assert!(parse_header(&[0; 12]).is_some());
    }
}
