//! Raw wire helpers that need no DNS crate: the fixed header, the FORMERR fallback, names
//! with compression pointers, the walk over the records of a message and the TSIG record
//! appended to a finished response. None of them allocates once the output buffer has its
//! capacity.

use crate::name::{MAX_NAME_LEN, NameBuf};

/// The length of the DNS header.
pub const HEADER_LEN: usize = 12;

/// The length of an OPT record without options.
pub const OPT_LEN: usize = 11;

/// The UDP payload size Tenko advertises and answers up to (DNS flag day 2020).
pub const SERVER_UDP_PAYLOAD: u16 = 1232;

/// The UDP answer size without EDNS (RFC 1035).
pub const CLASSIC_UDP_LEN: usize = 512;

/// The largest message (TCP, RFC 1035).
pub const MAX_MESSAGE_LEN: usize = 65_535;

/// The record type of OPT.
pub const TYPE_OPT: u16 = 41;

/// The record type of TSIG.
pub const TYPE_TSIG: u16 = 250;

/// The class ANY, which a TSIG record carries.
pub const CLASS_ANY: u16 = 255;

/// The EDNS option code of cookies (RFC 7873).
pub const OPTION_COOKIE: u16 = 10;

/// The EDNS option code of extended DNS errors (RFC 8914).
pub const OPTION_EXTENDED_ERROR: u16 = 15;

/// The most compression pointers followed in one name.
const MAX_POINTERS: usize = 64;

/// The fixed header fields of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the header flags of RFC 1035 are bits"
)]
pub struct RawHeader {
    /// The message id.
    pub id: u16,
    /// A response (QR).
    pub qr: bool,
    /// The opcode.
    pub opcode: u8,
    /// Authoritative answer (AA).
    pub aa: bool,
    /// Truncated (TC).
    pub tc: bool,
    /// Recursion desired (RD).
    pub rd: bool,
    /// Recursion available (RA).
    pub ra: bool,
    /// Authentic data (AD).
    pub ad: bool,
    /// Checking disabled (CD).
    pub cd: bool,
    /// The low four bits of the RCODE.
    pub rcode: u8,
    /// Questions.
    pub qdcount: u16,
    /// Answer records.
    pub ancount: u16,
    /// Authority records.
    pub nscount: u16,
    /// Additional records.
    pub arcount: u16,
}

fn u16_at(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]))
}

fn u32_at(buf: &[u8], pos: usize) -> Option<u32> {
    let bytes = buf.get(pos..pos + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The header of a message, or `None` when it is shorter than 12 octets.
pub fn parse_header(buf: &[u8]) -> Option<RawHeader> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    Some(RawHeader {
        id: u16_at(buf, 0)?,
        qr: buf[2] & 0x80 != 0,
        opcode: (buf[2] >> 3) & 0x0f,
        aa: buf[2] & 0x04 != 0,
        tc: buf[2] & 0x02 != 0,
        rd: buf[2] & 0x01 != 0,
        ra: buf[3] & 0x80 != 0,
        ad: buf[3] & 0x20 != 0,
        cd: buf[3] & 0x10 != 0,
        rcode: buf[3] & 0x0f,
        qdcount: u16_at(buf, 4)?,
        ancount: u16_at(buf, 6)?,
        nscount: u16_at(buf, 8)?,
        arcount: u16_at(buf, 10)?,
    })
}

/// Writes the header-only FORMERR answer to a query the codec could not parse: the id,
/// the opcode and RD copied, every count zero. Returns `false` (drop the packet) for a
/// message shorter than a header or a response, so that two servers never loop.
pub fn write_formerr(query: &[u8], out: &mut Vec<u8>) -> bool {
    let Some(header) = parse_header(query) else {
        return false;
    };
    if header.qr {
        return false;
    }
    out.clear();
    out.extend_from_slice(&header.id.to_be_bytes());
    out.push(0x80 | (header.opcode << 3) | u8::from(header.rd));
    out.push(1);
    out.extend_from_slice(&[0; 8]);
    true
}

/// The position after the name that starts at `pos` (a pointer ends a name).
pub fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    let mut wire_len = 0;
    loop {
        let len = *buf.get(pos)?;
        match len {
            0 => return Some(pos + 1),
            1..=63 => {
                wire_len += 1 + usize::from(len);
                if wire_len >= MAX_NAME_LEN {
                    return None;
                }
                pos += 1 + usize::from(len);
            }
            0xc0..=0xff => {
                buf.get(pos + 1)?;
                return Some(pos + 2);
            }
            _ => return None,
        }
    }
}

/// Reads the name at `pos`, following compression pointers backwards only, into `out` in
/// lowercase; returns the position after the name where it started.
pub fn read_name(buf: &[u8], pos: usize, out: &mut NameBuf) -> Option<usize> {
    out.clear();
    let mut cursor = pos;
    let mut end = None;
    let mut pointers = 0;
    loop {
        let len = *buf.get(cursor)?;
        match len {
            0 => return Some(end.unwrap_or(cursor + 1)),
            1..=63 => {
                let label = buf.get(cursor + 1..cursor + 1 + usize::from(len))?;
                out.push_label(label).ok()?;
                cursor += 1 + usize::from(len);
            }
            0xc0..=0xff => {
                let target = usize::from(u16_at(buf, cursor)? & 0x3fff);
                if target >= cursor || pointers == MAX_POINTERS {
                    return None;
                }
                pointers += 1;
                end.get_or_insert(cursor + 2);
                cursor = target;
            }
            _ => return None,
        }
    }
}

/// One resource record of a message, as positions in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawRecord {
    /// Where the record starts (its owner name).
    pub start: usize,
    /// Where the owner name ends (the type field).
    pub fixed: usize,
    /// The type.
    pub rtype: u16,
    /// The class (the UDP payload size for OPT).
    pub class: u16,
    /// The TTL (the extended RCODE, version and flags for OPT).
    pub ttl: u32,
    /// Where the data starts.
    pub rdata: usize,
    /// The data length.
    pub rdlen: usize,
}

impl RawRecord {
    /// The position after the record.
    pub fn end(&self) -> usize {
        self.rdata + self.rdlen
    }

    /// The record data.
    pub fn data<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.rdata..self.end()]
    }
}

/// Reads the record at `pos`.
pub fn read_record(buf: &[u8], pos: usize) -> Option<RawRecord> {
    let fixed = skip_name(buf, pos)?;
    let rtype = u16_at(buf, fixed)?;
    let class = u16_at(buf, fixed + 2)?;
    let ttl = u32_at(buf, fixed + 4)?;
    let rdlen = usize::from(u16_at(buf, fixed + 8)?);
    let rdata = fixed + 10;
    buf.get(rdata..rdata + rdlen)?;
    Some(RawRecord {
        start: pos,
        fixed,
        rtype,
        class,
        ttl,
        rdata,
        rdlen,
    })
}

/// The position after the question section, or `None` when it does not parse.
pub fn questions_end(buf: &[u8], qdcount: u16) -> Option<usize> {
    let mut pos = HEADER_LEN;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)? + 4;
        if pos > buf.len() {
            return None;
        }
    }
    Some(pos)
}

/// The EDNS options of OPT record data, as (code, value) pairs.
pub fn options(data: &[u8]) -> Options<'_> {
    Options { data }
}

/// An iterator over EDNS options; it stops at the first malformed option and then reports
/// it through [`Options::malformed`].
#[derive(Debug, Clone)]
pub struct Options<'a> {
    data: &'a [u8],
}

impl Options<'_> {
    /// Whether octets remain that do not form an option.
    pub fn malformed(&self) -> bool {
        !self.data.is_empty()
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<(u16, &'a [u8])> {
        let code = u16_at(self.data, 0)?;
        let len = usize::from(u16_at(self.data, 2)?);
        let value = self.data.get(4..4 + len)?;
        self.data = &self.data[4 + len..];
        Some((code, value))
    }
}

/// A TSIG record to append to a finished message (RFC 8945, section 4.2). The MAC is
/// computed by the caller over the message and the TSIG variables.
#[derive(Debug, Clone, Copy)]
pub struct TsigRecord<'a> {
    /// The key name in uncompressed wire form.
    pub key: &'a [u8],
    /// The algorithm name in uncompressed wire form.
    pub algorithm: &'a [u8],
    /// Seconds since 1970, 48 bits.
    pub time_signed: u64,
    /// Permitted clock error in seconds.
    pub fudge: u16,
    /// The MAC.
    pub mac: &'a [u8],
    /// The id of the original message.
    pub original_id: u16,
    /// The TSIG error (BADSIG 16, BADKEY 17, BADTIME 18, BADTRUNC 22).
    pub error: u16,
    /// Other data (the server time of a BADTIME answer).
    pub other: &'a [u8],
}

/// Appends a TSIG record to the message in `out` and raises its ARCOUNT. Returns `false`
/// and leaves `out` unchanged when the message has no header, the record would push it
/// past `max_len`, or the counts would overflow.
pub fn append_tsig(out: &mut Vec<u8>, tsig: &TsigRecord<'_>, max_len: usize) -> bool {
    let Some(arcount) = u16_at(out, 10) else {
        return false;
    };
    let (Ok(mac_size), Ok(other_size)) = (
        u16::try_from(tsig.mac.len()),
        u16::try_from(tsig.other.len()),
    ) else {
        return false;
    };
    let rdlen = tsig.algorithm.len() + 6 + 2 + 2 + tsig.mac.len() + 2 + 2 + 2 + tsig.other.len();
    let total = tsig.key.len() + 10 + rdlen;
    let (Some(new_arcount), Ok(rdlen16)) = (arcount.checked_add(1), u16::try_from(rdlen)) else {
        return false;
    };
    if out.len() + total > max_len || tsig.time_signed >= 1 << 48 {
        return false;
    }
    out.extend_from_slice(tsig.key);
    out.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    out.extend_from_slice(&CLASS_ANY.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&rdlen16.to_be_bytes());
    out.extend_from_slice(tsig.algorithm);
    out.extend_from_slice(&tsig.time_signed.to_be_bytes()[2..]);
    out.extend_from_slice(&tsig.fudge.to_be_bytes());
    out.extend_from_slice(&mac_size.to_be_bytes());
    out.extend_from_slice(tsig.mac);
    out.extend_from_slice(&tsig.original_id.to_be_bytes());
    out.extend_from_slice(&tsig.error.to_be_bytes());
    out.extend_from_slice(&other_size.to_be_bytes());
    out.extend_from_slice(tsig.other);
    out[10..12].copy_from_slice(&new_arcount.to_be_bytes());
    true
}

/// Writes a query for tests and tools: `qname` in presentation form without escapes, one
/// question, an OPT record with `edns_udp` when given. Clears `out` first.
pub fn write_query(out: &mut Vec<u8>, id: u16, qname: &str, qtype: u16, edns_udp: Option<u16>) {
    out.clear();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
    out.push(u8::from(edns_udp.is_some()));
    for label in qname.split('.').filter(|label| !label.is_empty()) {
        out.push(u8::try_from(label.len()).unwrap_or(63));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    if let Some(udp) = edns_udp {
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&udp.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_parses_and_formerr_copies_the_id() {
        let mut query = Vec::new();
        write_query(&mut query, 0xbeef, "x.example.test", 1, None);
        let header = parse_header(&query).expect("header");
        assert_eq!((header.id, header.qdcount, header.qr), (0xbeef, 1, false));
        let mut out = Vec::new();
        assert!(write_formerr(&query, &mut out));
        let answer = parse_header(&out).expect("answer");
        assert_eq!(
            (answer.id, answer.qr, answer.rcode, answer.qdcount),
            (0xbeef, true, 1, 0)
        );
        query[2] |= 0x80;
        assert!(!write_formerr(&query, &mut out));
        assert!(!write_formerr(&[0; 5], &mut out));
    }

    #[test]
    fn names_follow_pointers_backwards_only() {
        // Header, then `example.test` at 12, then `www` + pointer to 12 at 26.
        let mut buf = vec![0u8; 12];
        buf.extend_from_slice(b"\x07Example\x04test\x00");
        buf.extend_from_slice(b"\x03WWW\xc0\x0c");
        let mut name = NameBuf::root();
        assert_eq!(read_name(&buf, 26, &mut name), Some(32));
        assert_eq!(name.to_string(), "www.example.test");
        assert_eq!(skip_name(&buf, 26), Some(32));
        // A pointer to itself or forwards is refused.
        let mut looped = vec![0u8; 12];
        looped.extend_from_slice(b"\xc0\x0c");
        assert_eq!(read_name(&looped, 12, &mut name), None);
        assert_eq!(read_name(b"\x03ab", 0, &mut name), None);
        assert_eq!(skip_name(b"\x40", 0), None);
    }

    #[test]
    fn records_and_options_walk() {
        let mut query = Vec::new();
        write_query(&mut query, 1, "example.test", 1, Some(1232));
        let end = questions_end(&query, 1).expect("question");
        let opt = read_record(&query, end).expect("opt");
        assert_eq!(
            (opt.rtype, opt.class, opt.rdlen, opt.end()),
            (TYPE_OPT, 1232, 0, query.len())
        );
        let data = [0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 99, 0, 0, 0xff];
        let mut options = options(&data);
        assert_eq!(options.next(), Some((10, &data[4..12])));
        assert_eq!(options.next(), Some((99, &[][..])));
        assert_eq!(options.next(), None);
        assert!(options.malformed());
    }

    #[test]
    fn a_tsig_record_appends_and_counts() {
        let mut out = Vec::new();
        write_query(&mut out, 7, "example.test", 6, None);
        let before = out.len();
        let tsig = TsigRecord {
            key: b"\x03key\x00",
            algorithm: b"\x0bhmac-sha256\x00",
            time_signed: 1_790_000_000,
            fudge: 300,
            mac: &[0xaa; 32],
            original_id: 7,
            error: 0,
            other: &[],
        };
        assert!(append_tsig(&mut out, &tsig, MAX_MESSAGE_LEN));
        assert_eq!(parse_header(&out).expect("header").arcount, 1);
        let record = read_record(&out, before).expect("record");
        assert_eq!(
            (record.rtype, record.class, record.end()),
            (TYPE_TSIG, CLASS_ANY, out.len())
        );
        let full = out.len();
        assert!(!append_tsig(&mut out, &tsig, full + 10), "over the limit");
        assert_eq!(out.len(), full);
    }
}
