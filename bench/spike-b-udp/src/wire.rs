//! Crate-independent raw wire helpers.
//!
//! Used by the load generator (to build queries and check responses without
//! depending on either DNS crate), by the criterion benches (to produce the
//! captured query packets) and by the server for the FORMERR fallback.

/// Size of the DNS header.
pub const HEADER_LEN: usize = 12;
/// Length of an OPT pseudo-record without options.
pub const OPT_LEN: usize = 11;
/// EDNS UDP payload size the server advertises (DNS flag day 2020).
pub const SERVER_EDNS_UDP: u16 = 1232;

pub const QTYPE_A: u16 = 1;
pub const QTYPE_SOA: u16 = 6;
pub const QTYPE_AAAA: u16 = 28;
pub const QCLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

/// The zone apex used throughout the spike.
pub const APEX: &str = "example.test";

/// Loopback address used by tests: `$SPIKE_B_LOOPBACK` or 127.0.0.1.
///
/// WSL2 intercepts traffic to 127.0.0.1 (it is forwarded to the Windows
/// host), so tests there run with `SPIKE_B_LOOPBACK=127.0.0.2`.
pub fn test_loopback() -> std::net::IpAddr {
    std::env::var("SPIKE_B_LOOPBACK")
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

/// Appends a decimal number without allocating.
fn push_decimal(out: &mut Vec<u8>, mut n: u32) {
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[i..]);
}

fn push_header(out: &mut Vec<u8>, id: u16, arcount: u16) {
    out.extend_from_slice(&id.to_be_bytes());
    // QR=0, OPCODE=QUERY, RD=0 (authoritative server), all other bits zero.
    out.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&arcount.to_be_bytes());
}

fn push_tail(out: &mut Vec<u8>, qtype: u16, edns_udp: Option<u16>) {
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&QCLASS_IN.to_be_bytes());
    if let Some(udp) = edns_udp {
        out.push(0); // root owner
        out.extend_from_slice(&41u16.to_be_bytes()); // TYPE OPT
        out.extend_from_slice(&udp.to_be_bytes()); // CLASS = UDP payload size
        out.extend_from_slice(&[0, 0, 0, 0]); // ext-rcode, version, DO + Z
        out.extend_from_slice(&0u16.to_be_bytes()); // RDLEN
    }
}

/// Writes a query for `qname` (presentation format without trailing dot,
/// labels separated by '.', no escapes) into `out` (cleared first).
pub fn write_query(out: &mut Vec<u8>, id: u16, qname: &str, qtype: u16, edns_udp: Option<u16>) {
    out.clear();
    push_header(out, id, u16::from(edns_udp.is_some()));
    for label in qname.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    push_tail(out, qtype, edns_udp);
}

/// Writes an A query for `host-{n}.example.test` (or `nohost-{n}.example.test`
/// when `nx` is set, a name that does not exist in the zone) into `out`
/// (cleared first). Does not allocate once `out` has capacity.
pub fn write_host_query(out: &mut Vec<u8>, id: u16, n: u32, nx: bool, edns_udp: Option<u16>) {
    out.clear();
    push_header(out, id, u16::from(edns_udp.is_some()));
    let len_pos = out.len();
    out.push(0);
    out.extend_from_slice(if nx { b"nohost-" } else { b"host-" });
    push_decimal(out, n);
    out[len_pos] = (out.len() - len_pos - 1) as u8;
    out.extend_from_slice(b"\x07example\x04test\x00");
    push_tail(out, QTYPE_A, edns_udp);
}

/// Shared fallback when a query cannot be parsed by the backend crate but has
/// a readable header: a header-only FORMERR response that copies ID, OPCODE
/// and RD. Returns false (drop the packet) if `req` is too short or is itself
/// a response.
pub fn write_formerr(req: &[u8], out: &mut Vec<u8>) -> bool {
    let Some(h) = parse_header(req) else {
        return false;
    };
    if h.qr {
        return false;
    }
    out.clear();
    out.extend_from_slice(&h.id.to_be_bytes());
    out.push(0x80 | (h.opcode << 3) | u8::from(h.rd));
    out.push(RCODE_FORMERR);
    out.extend_from_slice(&[0; 8]);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_query_matches_generic_writer() {
        let mut a = Vec::new();
        let mut b = Vec::new();
        write_host_query(&mut a, 0x1234, 98765, false, Some(1232));
        write_query(
            &mut b,
            0x1234,
            "host-98765.example.test",
            QTYPE_A,
            Some(1232),
        );
        assert_eq!(a, b);
        write_host_query(&mut a, 7, 0, true, None);
        write_query(&mut b, 7, "nohost-0.example.test", QTYPE_A, None);
        assert_eq!(a, b);
    }

    #[test]
    fn formerr_copies_id() {
        let mut q = Vec::new();
        write_query(&mut q, 0xbeef, "x.example.test", QTYPE_A, None);
        let mut out = Vec::new();
        assert!(write_formerr(&q, &mut out));
        let h = parse_header(&out).unwrap();
        assert_eq!(h.id, 0xbeef);
        assert!(h.qr);
        assert_eq!(h.rcode, RCODE_FORMERR);
    }
}
