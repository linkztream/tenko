//! The UPDATE message (RFC 2136 section 2) and its answer.
//!
//! An UPDATE has the header of a query with opcode 5 and four sections: the zone section
//! (ZOCOUNT, one record of type SOA naming the zone), the prerequisite section (PRCOUNT,
//! in the place of the answer section), the update section (UPCOUNT, in the place of the
//! authority section) and the additional section (OPT and TSIG; anything else is ignored,
//! section 3.8).
//!
//! [`parse`] reads the message and applies the format rules of sections 2.4, 3.2 and the
//! prescan of 3.4.1: FORMERR for a zone section that is not one SOA question, a
//! prerequisite with a TTL other than zero, a class or data that the section does not
//! allow, or a meta type where data is expected; NOTZONE for a name outside the zone;
//! NOTAUTH for a class other than IN (Tenko serves IN only). Names come out in lowercase,
//! record data in Tenko's stored form (names uncompressed and lowercase), so that the
//! prerequisites compare in canonical form.
//!
//! [`write_answer`] writes the answer: the header with the RCODE, the zone section echoed,
//! and an OPT record with an extended error (RFC 8914) when the request carried EDNS. The
//! caller signs it when the request was signed.

use tenko_core::dns::{DnsName, Rdata, Rtype};

use crate::{
    name::NameBuf,
    wire::{self, HEADER_LEN, TYPE_OPT, TYPE_TSIG},
};

/// The opcode of an UPDATE.
pub const OPCODE_UPDATE: u8 = 5;

/// The class IN.
pub const CLASS_IN: u16 = 1;

/// The class NONE (RFC 2136 section 1.3).
pub const CLASS_NONE: u16 = 254;

/// The class ANY.
pub const CLASS_ANY: u16 = 255;

/// The type ANY (`*`, ALL in RFC 2136).
pub const TYPE_ANY: u16 = 255;

/// The type SOA.
const TYPE_SOA: u16 = 6;

/// The RCODEs of an UPDATE answer (RFC 1035, RFC 2136 section 2.2).
pub mod rcode {
    /// Done.
    pub const NOERROR: u16 = 0;
    /// The message is malformed.
    pub const FORMERR: u16 = 1;
    /// The server could not do it (the store refused, the index did not follow).
    pub const SERVFAIL: u16 = 2;
    /// A name that should exist does not (prerequisite).
    pub const NXDOMAIN: u16 = 3;
    /// The server does not do this.
    pub const NOTIMP: u16 = 4;
    /// The server refuses for policy reasons.
    pub const REFUSED: u16 = 5;
    /// A name that should not exist does (prerequisite).
    pub const YXDOMAIN: u16 = 6;
    /// An RRset that should not exist does (prerequisite).
    pub const YXRRSET: u16 = 7;
    /// An RRset that should exist does not (prerequisite).
    pub const NXRRSET: u16 = 8;
    /// The server is not authoritative for the zone, or the TSIG did not verify.
    pub const NOTAUTH: u16 = 9;
    /// A name is outside the zone of the zone section.
    pub const NOTZONE: u16 = 10;
}

/// The extended error codes of an UPDATE answer (RFC 8914).
pub mod ede {
    /// Anything else, with a text.
    pub const OTHER: u16 = 0;
    /// The server is not ready (the index does not hold the commit yet).
    pub const NOT_READY: u16 = 14;
    /// The update is not allowed.
    pub const PROHIBITED: u16 = 18;
    /// The server is not authoritative for the zone.
    pub const NOT_AUTHORITATIVE: u16 = 20;
    /// The operation is not supported.
    pub const NOT_SUPPORTED: u16 = 21;
}

/// Whether a message is an UPDATE request: a header with QR clear and opcode 5. Reads one
/// octet; the query path calls it for every message.
#[inline]
pub fn is_update(message: &[u8]) -> bool {
    message.len() >= HEADER_LEN && message[2] & 0xf8 == OPCODE_UPDATE << 3
}

/// A prerequisite (RFC 2136 section 2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prerequisite {
    /// At least one RRset of this type exists at the name (2.4.1, class ANY).
    Exists {
        /// The owner.
        name: DnsName,
        /// The type.
        rtype: Rtype,
    },
    /// The RRset exists with exactly these records (2.4.2, the zone's class), compared in
    /// canonical form.
    Equals {
        /// The owner.
        name: DnsName,
        /// The type.
        rtype: Rtype,
        /// The records of the temporary RRset, without duplicates.
        rdata: Vec<Rdata>,
    },
    /// No RRset of this type exists at the name (2.4.3, class NONE).
    NotExists {
        /// The owner.
        name: DnsName,
        /// The type.
        rtype: Rtype,
    },
    /// The name owns at least one record (2.4.4, class ANY, type ANY).
    NameInUse {
        /// The name.
        name: DnsName,
    },
    /// The name owns no record (2.4.5, class NONE, type ANY).
    NameNotInUse {
        /// The name.
        name: DnsName,
    },
}

impl Prerequisite {
    /// The name it tests.
    pub fn name(&self) -> &DnsName {
        match self {
            Prerequisite::Exists { name, .. }
            | Prerequisite::Equals { name, .. }
            | Prerequisite::NotExists { name, .. }
            | Prerequisite::NameInUse { name }
            | Prerequisite::NameNotInUse { name } => name,
        }
    }
}

/// An update (RFC 2136 section 2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    /// Add a record to an RRset (2.5.1, the zone's class).
    Add {
        /// The owner.
        name: DnsName,
        /// The type.
        rtype: Rtype,
        /// The TTL.
        ttl: u32,
        /// The record.
        rdata: Rdata,
    },
    /// Delete an RRset (2.5.2, class ANY).
    DeleteRrset {
        /// The owner.
        name: DnsName,
        /// The type.
        rtype: Rtype,
    },
    /// Delete every RRset of a name (2.5.3, class ANY, type ANY).
    DeleteName {
        /// The name.
        name: DnsName,
    },
    /// Delete one record from an RRset (2.5.4, class NONE).
    DeleteRecord {
        /// The owner.
        name: DnsName,
        /// The type.
        rtype: Rtype,
        /// The record.
        rdata: Rdata,
    },
}

impl Update {
    /// The owner it changes.
    pub fn name(&self) -> &DnsName {
        match self {
            Update::Add { name, .. }
            | Update::DeleteRrset { name, .. }
            | Update::DeleteName { name }
            | Update::DeleteRecord { name, .. } => name,
        }
    }
}

/// A parsed UPDATE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage {
    /// The message id.
    pub id: u16,
    /// The zone of the zone section.
    pub zone: DnsName,
    /// The prerequisites, in order.
    pub prerequisites: Vec<Prerequisite>,
    /// The updates, in order.
    pub updates: Vec<Update>,
    /// The requester's EDNS UDP size when the request carried an OPT record.
    pub edns: Option<u16>,
    /// Where the zone section ends (the answer echoes it).
    pub zone_end: usize,
}

/// Why an UPDATE was not parsed, with the RCODE of the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Not an UPDATE request (a response, a runt): no answer.
    #[error("not an UPDATE request")]
    NotUpdate,
    /// Malformed (FORMERR); `zone_end` when the zone section parsed and can be echoed.
    #[error("malformed UPDATE: {reason}")]
    Format {
        /// Why.
        reason: &'static str,
        /// The end of the zone section, when it parsed.
        zone_end: Option<usize>,
    },
    /// A name outside the zone (NOTZONE).
    #[error("a name is outside the zone")]
    NotZone {
        /// The end of the zone section.
        zone_end: usize,
    },
    /// A class other than IN (NOTAUTH: Tenko serves IN only).
    #[error("the zone class is not IN")]
    Class {
        /// The end of the zone section.
        zone_end: usize,
    },
}

impl ParseError {
    /// The RCODE of the answer.
    pub const fn rcode(&self) -> Option<u16> {
        match self {
            ParseError::NotUpdate => None,
            ParseError::Format { .. } => Some(rcode::FORMERR),
            ParseError::NotZone { .. } => Some(rcode::NOTZONE),
            ParseError::Class { .. } => Some(rcode::NOTAUTH),
        }
    }

    /// The end of the zone section to echo.
    pub const fn zone_end(&self) -> Option<usize> {
        match self {
            ParseError::NotUpdate => None,
            ParseError::Format { zone_end, .. } => *zone_end,
            ParseError::NotZone { zone_end } | ParseError::Class { zone_end } => Some(*zone_end),
        }
    }
}

fn u16_at(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]))
}

/// Types RFC 2136 forbids in an update besides the meta types: ALL, AXFR, MAILA, MAILB
/// (all of them meta types, 128 to 255).
fn is_meta(rtype: u16) -> bool {
    Rtype(rtype).is_meta()
}

/// Parses an UPDATE request.
///
/// # Errors
///
/// [`ParseError`] with the RCODE of the answer.
#[allow(
    clippy::too_many_lines,
    reason = "the sections of RFC 2136 in their order read best whole"
)]
pub fn parse(message: &[u8]) -> Result<UpdateMessage, ParseError> {
    let header = wire::parse_header(message).ok_or(ParseError::NotUpdate)?;
    if header.qr || header.opcode != OPCODE_UPDATE {
        return Err(ParseError::NotUpdate);
    }
    let format = |reason, zone_end| ParseError::Format { reason, zone_end };
    if header.qdcount != 1 {
        return Err(format("the zone section holds one zone", None));
    }
    // The zone section.
    let mut zone_buf = NameBuf::root();
    let after = wire::read_name(message, HEADER_LEN, &mut zone_buf)
        .ok_or(format("the zone name does not parse", None))?;
    let ztype = u16_at(message, after).ok_or(format("the zone section is cut short", None))?;
    let zclass = u16_at(message, after + 2).ok_or(format("the zone section is cut short", None))?;
    let zone_end = after + 4;
    let echo = Some(zone_end);
    if ztype != TYPE_SOA {
        return Err(format("the zone section names type SOA", echo));
    }
    if zclass != CLASS_IN {
        return Err(ParseError::Class { zone_end });
    }
    let zone = zone_buf
        .to_dns_name()
        .ok_or(format("the zone name is not a host name", echo))?;
    let mut pos = zone_end;
    let mut owner = NameBuf::root();
    let mut read = |pos: usize| -> Result<(wire::RawRecord, DnsName), ParseError> {
        let record =
            wire::read_record(message, pos).ok_or(format("a record does not parse", echo))?;
        wire::read_name(message, record.start, &mut owner)
            .ok_or(format("an owner name does not parse", echo))?;
        let name = owner
            .to_dns_name()
            .ok_or(format("an owner name is not a host name", echo))?;
        if !name.is_subdomain_of(&zone) {
            return Err(ParseError::NotZone { zone_end });
        }
        Ok((record, name))
    };

    // The prerequisite section (section 3.2).
    let mut prerequisites: Vec<Prerequisite> = Vec::with_capacity(usize::from(header.ancount));
    for _ in 0..header.ancount {
        let (record, name) = read(pos)?;
        pos = record.end();
        if record.ttl != 0 {
            return Err(format("a prerequisite has a TTL of zero", echo));
        }
        let rtype = Rtype(record.rtype);
        match record.class {
            CLASS_ANY | CLASS_NONE if record.rdlen != 0 => {
                return Err(format(
                    "a prerequisite of class ANY or NONE has no data",
                    echo,
                ));
            }
            CLASS_ANY if record.rtype == TYPE_ANY => {
                prerequisites.push(Prerequisite::NameInUse { name });
            }
            CLASS_ANY => prerequisites.push(Prerequisite::Exists { name, rtype }),
            CLASS_NONE if record.rtype == TYPE_ANY => {
                prerequisites.push(Prerequisite::NameNotInUse { name });
            }
            CLASS_NONE => prerequisites.push(Prerequisite::NotExists { name, rtype }),
            CLASS_IN => {
                if is_meta(record.rtype) {
                    return Err(format(
                        "a prerequisite of the zone's class names a data type",
                        echo,
                    ));
                }
                let data = decompress(message, record.rtype, record.rdata, record.end())
                    .ok_or(format("a prerequisite's data does not parse", echo))?;
                let rdata = Rdata::from_wire(rtype, &data)
                    .map_err(|_| format("a prerequisite's data is not valid for its type", echo))?;
                // The records of one name and type form one temporary RRset (3.2.5).
                let existing = prerequisites.iter_mut().find(|prerequisite| {
                    matches!(prerequisite, Prerequisite::Equals { name: n, rtype: t, .. } if *n == name && *t == rtype)
                });
                match existing {
                    Some(Prerequisite::Equals { rdata: set, .. }) => {
                        if !set.contains(&rdata) {
                            set.push(rdata);
                        }
                    }
                    _ => prerequisites.push(Prerequisite::Equals {
                        name,
                        rtype,
                        rdata: vec![rdata],
                    }),
                }
            }
            _ => {
                return Err(format(
                    "a prerequisite has a class RFC 2136 does not allow",
                    echo,
                ));
            }
        }
    }

    // The update section (the prescan of section 3.4.1).
    let mut updates = Vec::with_capacity(usize::from(header.nscount));
    for _ in 0..header.nscount {
        let (record, name) = read(pos)?;
        pos = record.end();
        let rtype = Rtype(record.rtype);
        match record.class {
            CLASS_IN => {
                if is_meta(record.rtype) {
                    return Err(format("an added record has a data type", echo));
                }
                let data = decompress(message, record.rtype, record.rdata, record.end())
                    .ok_or(format("an added record's data does not parse", echo))?;
                let rdata = Rdata::from_wire(rtype, &data).map_err(|_| {
                    format("an added record's data is not valid for its type", echo)
                })?;
                updates.push(Update::Add {
                    name,
                    rtype,
                    ttl: record.ttl,
                    rdata,
                });
            }
            CLASS_ANY => {
                if record.ttl != 0 || record.rdlen != 0 {
                    return Err(format(
                        "a deletion of class ANY has no TTL and no data",
                        echo,
                    ));
                }
                if record.rtype == TYPE_ANY {
                    updates.push(Update::DeleteName { name });
                } else if is_meta(record.rtype) {
                    return Err(format("a deletion names a data type or ANY", echo));
                } else {
                    updates.push(Update::DeleteRrset { name, rtype });
                }
            }
            CLASS_NONE => {
                if record.ttl != 0 {
                    return Err(format("a deletion of class NONE has no TTL", echo));
                }
                if is_meta(record.rtype) {
                    return Err(format("a deletion of one record names a data type", echo));
                }
                let data = decompress(message, record.rtype, record.rdata, record.end())
                    .ok_or(format("a deleted record's data does not parse", echo))?;
                let rdata = Rdata::from_wire(rtype, &data).map_err(|_| {
                    format("a deleted record's data is not valid for its type", echo)
                })?;
                updates.push(Update::DeleteRecord { name, rtype, rdata });
            }
            _ => {
                return Err(format(
                    "an update has a class RFC 2136 does not allow",
                    echo,
                ));
            }
        }
    }

    // The additional section: OPT and TSIG (last); anything else is ignored.
    let mut edns = None;
    let additional = usize::from(header.arcount);
    for index in 0..additional {
        let record = wire::read_record(message, pos)
            .ok_or(format("an additional record does not parse", echo))?;
        match record.rtype {
            TYPE_OPT => {
                if edns.is_some() || message.get(record.start) != Some(&0) {
                    return Err(format("one OPT record, owned by the root", echo));
                }
                edns = Some(record.class.max(512));
            }
            TYPE_TSIG if index + 1 != additional => {
                return Err(format("the TSIG record is the last record", echo));
            }
            _ => {}
        }
        pos = record.end();
    }
    if pos != message.len() {
        return Err(format("octets follow the last record", echo));
    }
    Ok(UpdateMessage {
        id: header.id,
        zone,
        prerequisites,
        updates,
        edns,
        zone_end,
    })
}

/// The parts of a type's data: fixed octets, a name, or a character string.
#[derive(Clone, Copy)]
enum Part {
    Fixed(usize),
    Name,
    Text,
}

const NAME: &[Part] = &[Part::Name];
const SOA: &[Part] = &[Part::Name, Part::Name, Part::Fixed(20)];
const TWO_NAMES: &[Part] = &[Part::Name, Part::Name];
const PREF_NAME: &[Part] = &[Part::Fixed(2), Part::Name];
const PX: &[Part] = &[Part::Fixed(2), Part::Name, Part::Name];
const SRV: &[Part] = &[Part::Fixed(6), Part::Name];
const NAPTR: &[Part] = &[
    Part::Fixed(4),
    Part::Text,
    Part::Text,
    Part::Text,
    Part::Name,
];

/// The layout of a type whose data holds names a sender may have compressed (RFC 3597
/// section 4: only the types of RFC 1035 and a few early ones).
fn layout(rtype: u16) -> Option<&'static [Part]> {
    Some(match rtype {
        // NS, MD, MF, CNAME, MB, MG, MR, PTR, DNAME
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 39 => NAME,
        6 => SOA,
        // MINFO, RP
        14 | 17 => TWO_NAMES,
        // MX, AFSDB, RT, KX
        15 | 18 | 21 | 36 => PREF_NAME,
        26 => PX,
        33 => SRV,
        35 => NAPTR,
        _ => return None,
    })
}

/// The record data at `start..end` of `message` with its names decompressed.
fn decompress(message: &[u8], rtype: u16, start: usize, end: usize) -> Option<Vec<u8>> {
    let Some(parts) = layout(rtype) else {
        return Some(message.get(start..end)?.to_vec());
    };
    let mut out = Vec::with_capacity(end - start + 32);
    let mut pos = start;
    let mut name = NameBuf::root();
    for part in parts {
        match part {
            Part::Fixed(len) => {
                out.extend_from_slice(message.get(pos..pos + len)?);
                pos += len;
            }
            Part::Text => {
                let len = usize::from(*message.get(pos)?);
                out.extend_from_slice(message.get(pos..=pos + len)?);
                pos += 1 + len;
            }
            Part::Name => {
                pos = wire::read_name(message, pos, &mut name)?;
                out.extend_from_slice(name.as_wire());
            }
        }
        if pos > end {
            return None;
        }
    }
    (pos == end).then_some(out)
}

/// The longest extended error text an answer carries, so that a signed answer fits in
/// 512 octets.
pub const MAX_EDE_TEXT: usize = 200;

/// The OPT record of an answer: the server's UDP size and an extended error.
#[derive(Debug, Clone, Copy)]
pub struct AnswerEdns<'a> {
    /// The UDP size to advertise.
    pub udp_size: u16,
    /// The extended error code and text.
    pub error: Option<(u16, &'a str)>,
}

/// Writes the answer to `request` into `out`: the header with `rcode` (the id copied, QR
/// set, opcode UPDATE), the zone section of the request when `zone_end` is given, and an
/// OPT record when `edns` is. Returns `false` (send nothing) for a request shorter than a
/// header or a response.
pub fn write_answer(
    request: &[u8],
    zone_end: Option<usize>,
    rcode: u16,
    edns: Option<AnswerEdns<'_>>,
    out: &mut Vec<u8>,
) -> bool {
    let Some(header) = wire::parse_header(request) else {
        return false;
    };
    if header.qr {
        return false;
    }
    out.clear();
    out.extend_from_slice(&header.id.to_be_bytes());
    out.push(0x80 | (OPCODE_UPDATE << 3));
    out.push(u8::try_from(rcode & 0x0f).unwrap_or(0));
    let zone = zone_end.and_then(|end| request.get(HEADER_LEN..end));
    out.extend_from_slice(&u16::from(zone.is_some()).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&u16::from(edns.is_some()).to_be_bytes());
    if let Some(zone) = zone {
        out.extend_from_slice(zone);
    }
    if let Some(edns) = edns {
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&edns.udp_size.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        match edns.error {
            Some((code, text)) => {
                let text = &text.as_bytes()[..text.len().min(MAX_EDE_TEXT)];
                let len = u16::try_from(text.len() + 2).unwrap_or(2);
                out.extend_from_slice(&(len + 4).to_be_bytes());
                out.extend_from_slice(&wire::OPTION_EXTENDED_ERROR.to_be_bytes());
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&code.to_be_bytes());
                out.extend_from_slice(text);
            }
            None => out.extend_from_slice(&[0, 0]),
        }
    }
    true
}

/// Writes an UPDATE request for tests, tools and the load generator of M21: `zone` in
/// lowercase wire form, the prerequisite and update records already in wire form (owner,
/// type, class, TTL, RDLENGTH and data) with their counts. Clears `out` first.
pub fn write_request(
    out: &mut Vec<u8>,
    id: u16,
    zone: &[u8],
    prerequisites: (u16, &[u8]),
    updates: (u16, &[u8]),
) {
    out.clear();
    out.extend_from_slice(&id.to_be_bytes());
    out.push(OPCODE_UPDATE << 3);
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&prerequisites.0.to_be_bytes());
    out.extend_from_slice(&updates.0.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(zone);
    out.extend_from_slice(&TYPE_SOA.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(prerequisites.1);
    out.extend_from_slice(updates.1);
}

/// Appends one record in wire form (for [`write_request`]).
pub fn push_record(out: &mut Vec<u8>, owner: &[u8], rtype: u16, class: u16, ttl: u32, data: &[u8]) {
    out.extend_from_slice(owner);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE: &[u8] = b"\x07example\x04test\x00";

    fn owner(label: &str) -> Vec<u8> {
        let mut out = vec![u8::try_from(label.len()).expect("label")];
        out.extend_from_slice(label.as_bytes());
        out.extend_from_slice(ZONE);
        out
    }

    #[test]
    fn every_section_reads() {
        let mut prereq = Vec::new();
        push_record(&mut prereq, &owner("www"), 1, CLASS_ANY, 0, &[]);
        push_record(&mut prereq, &owner("new"), TYPE_ANY, CLASS_NONE, 0, &[]);
        push_record(&mut prereq, &owner("mx"), 1, CLASS_IN, 0, &[192, 0, 2, 1]);
        push_record(&mut prereq, &owner("mx"), 1, CLASS_IN, 0, &[192, 0, 2, 2]);
        let mut updates = Vec::new();
        push_record(
            &mut updates,
            &owner("new"),
            1,
            CLASS_IN,
            300,
            &[192, 0, 2, 9],
        );
        push_record(&mut updates, &owner("old"), TYPE_ANY, CLASS_ANY, 0, &[]);
        push_record(&mut updates, &owner("www"), 16, CLASS_ANY, 0, &[]);
        push_record(
            &mut updates,
            &owner("www"),
            1,
            CLASS_NONE,
            0,
            &[192, 0, 2, 1],
        );
        let mut message = Vec::new();
        write_request(&mut message, 7, ZONE, (4, &prereq), (4, &updates));
        assert!(is_update(&message));
        let parsed = parse(&message).expect("update");
        assert_eq!(parsed.zone.as_str(), "example.test");
        assert_eq!(
            parsed.prerequisites.len(),
            3,
            "the two A records form one RRset"
        );
        assert!(
            matches!(&parsed.prerequisites[2], Prerequisite::Equals { rdata, .. } if rdata.len() == 2)
        );
        assert_eq!(parsed.updates.len(), 4);
        assert!(matches!(parsed.updates[1], Update::DeleteName { .. }));
    }

    #[test]
    fn the_format_rules_answer_formerr_notzone_and_notauth() {
        let mut message = Vec::new();
        let mut bad = Vec::new();
        push_record(&mut bad, &owner("www"), 1, CLASS_ANY, 60, &[]);
        write_request(&mut message, 1, ZONE, (1, &bad), (0, &[]));
        assert_eq!(parse(&message).unwrap_err().rcode(), Some(rcode::FORMERR));
        let mut outside = Vec::new();
        push_record(
            &mut outside,
            b"\x03www\x05other\x04test\x00",
            1,
            CLASS_IN,
            60,
            &[192, 0, 2, 1],
        );
        write_request(&mut message, 1, ZONE, (0, &[]), (1, &outside));
        assert_eq!(parse(&message).unwrap_err().rcode(), Some(rcode::NOTZONE));
        let mut meta = Vec::new();
        push_record(&mut meta, &owner("www"), 252, CLASS_IN, 60, &[]);
        write_request(&mut message, 1, ZONE, (0, &[]), (1, &meta));
        assert_eq!(parse(&message).unwrap_err().rcode(), Some(rcode::FORMERR));
        write_request(&mut message, 1, ZONE, (0, &[]), (0, &[]));
        let class = message.len() - 1;
        message[class] = 3;
        assert_eq!(parse(&message).unwrap_err().rcode(), Some(rcode::NOTAUTH));
        message[class] = 1;
        message[5] = 2;
        assert_eq!(parse(&message).unwrap_err().rcode(), Some(rcode::FORMERR));
        message[2] |= 0x80;
        assert_eq!(parse(&message).unwrap_err(), ParseError::NotUpdate);
    }

    #[test]
    fn the_answer_echoes_the_zone_with_an_extended_error() {
        let mut message = Vec::new();
        write_request(&mut message, 0x1234, ZONE, (0, &[]), (0, &[]));
        let parsed = parse(&message).expect("update");
        let mut out = Vec::new();
        let edns = AnswerEdns {
            udp_size: 1232,
            error: Some((ede::PROHIBITED, "no")),
        };
        assert!(write_answer(
            &message,
            Some(parsed.zone_end),
            rcode::REFUSED,
            Some(edns),
            &mut out
        ));
        let header = wire::parse_header(&out).expect("header");
        assert_eq!(
            (
                header.id,
                header.qr,
                header.opcode,
                header.rcode,
                header.qdcount,
                header.arcount
            ),
            (0x1234, true, OPCODE_UPDATE, 5, 1, 1)
        );
        let end = wire::questions_end(&out, 1).expect("zone");
        let opt = wire::read_record(&out, end).expect("opt");
        let (code, value) = wire::options(opt.data(&out)).next().expect("option");
        assert_eq!(
            (code, value),
            (wire::OPTION_EXTENDED_ERROR, &[0, 18, b'n', b'o'][..])
        );
    }
}
