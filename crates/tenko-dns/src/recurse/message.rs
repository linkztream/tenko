//! The authority's answer as the engine reads it, and the answer the engine gives.
//!
//! [`parse`] reads a message into owned records with lowercase owners and the names in
//! their data decompressed (RFC 3597 section 4 lists the types whose data may carry
//! compressed names), so that the records can move into another message. [`classify`]
//! reads it as RFC 2181 section 5.4 ranks it and RFC 9471 bounds it, for the zone the
//! server was asked as: an answer, a CNAME or DNAME to follow, a referral with its glue, a
//! negative answer, or a lame answer. [`compose`] writes the answer of a resolution in the
//! form of an authority's answer, which the forwarder's cache stores and relays.
//!
//! Everything here allocates; it runs on the runtime, never on the worker. The parser is
//! bounded: at most [`MAX_RECORDS`] records are read, and every name and length is checked
//! (the fuzz target `dns_referral` drives [`parse`] and [`classify`]).

use std::net::IpAddr;

use crate::{
    name::{self, NameBuf},
    recursion::ServerCookie,
    wire::{self, HEADER_LEN, OPTION_COOKIE, TYPE_OPT},
};

/// The most records the parser reads from one message.
pub const MAX_RECORDS: usize = 512;

/// Record types the engine reads.
pub mod types {
    /// A.
    pub const A: u16 = 1;
    /// NS.
    pub const NS: u16 = 2;
    /// CNAME.
    pub const CNAME: u16 = 5;
    /// SOA.
    pub const SOA: u16 = 6;
    /// AAAA.
    pub const AAAA: u16 = 28;
    /// DNAME.
    pub const DNAME: u16 = 39;
    /// DS.
    pub const DS: u16 = 43;
    /// RRSIG.
    pub const RRSIG: u16 = 46;
    /// NSEC.
    pub const NSEC: u16 = 47;
    /// NSEC3.
    pub const NSEC3: u16 = 50;
    /// ANY.
    pub const ANY: u16 = 255;
}

use types::{A, AAAA, ANY, CNAME, DNAME, NS, NSEC, NSEC3, RRSIG, SOA};

/// One record with its owner in lowercase wire form and its data with names decompressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rr {
    /// The owner, lowercase uncompressed wire form.
    pub owner: Vec<u8>,
    /// The type.
    pub rtype: u16,
    /// The class.
    pub class: u16,
    /// The TTL.
    pub ttl: u32,
    /// The data, names decompressed.
    pub data: Vec<u8>,
}

impl Rr {
    /// The type an RRSIG covers (its first two octets).
    pub fn covered(&self) -> Option<u16> {
        (self.rtype == RRSIG && self.data.len() >= 2)
            .then(|| u16::from_be_bytes([self.data[0], self.data[1]]))
    }

    /// The name in the data of an NS, CNAME or DNAME record.
    pub fn target(&self) -> Option<Vec<u8>> {
        matches!(self.rtype, NS | CNAME | DNAME)
            .then(|| NameBuf::from_wire(&self.data).ok())
            .flatten()
            .map(|name| name.as_wire().to_vec())
    }

    /// The address of an A or AAAA record.
    pub fn address(&self) -> Option<IpAddr> {
        match (self.rtype, self.data.len()) {
            (A, 4) => Some(IpAddr::from(<[u8; 4]>::try_from(&self.data[..]).ok()?)),
            (AAAA, 16) => Some(IpAddr::from(<[u8; 16]>::try_from(&self.data[..]).ok()?)),
            _ => None,
        }
    }

    /// Whether this record belongs to the RRset of `rtype` at its owner: the records of the
    /// type and their signatures.
    pub fn of_type(&self, rtype: u16) -> bool {
        self.rtype == rtype || self.covered() == Some(rtype)
    }

    /// Appends the record in uncompressed wire form.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.owner);
        out.extend_from_slice(&self.rtype.to_be_bytes());
        out.extend_from_slice(&self.class.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        out.extend_from_slice(&u16::try_from(self.data.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&self.data);
    }
}

/// The OPT record of an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opt {
    /// The UDP payload size.
    pub udp_size: u16,
    /// The upper eight bits of the extended RCODE.
    pub ext_rcode: u8,
    /// The DO bit.
    pub dnssec_ok: bool,
    /// The cookie option: the client cookie and the server cookie, when one came.
    pub cookie: Option<([u8; 8], Option<ServerCookie>)>,
    /// A cookie option that is malformed (RFC 7873 section 5.3: the answer is discarded).
    pub bad_cookie_option: bool,
}

/// A parsed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The id.
    pub id: u16,
    /// The RCODE with the OPT record's upper bits (BADCOOKIE is 23).
    pub rcode: u16,
    /// Authoritative answer.
    pub aa: bool,
    /// Truncated.
    pub tc: bool,
    /// The question name, lowercase.
    pub qname: Vec<u8>,
    /// The question type.
    pub qtype: u16,
    /// The answer section.
    pub answer: Vec<Rr>,
    /// The authority section.
    pub authority: Vec<Rr>,
    /// The additional section, the OPT record not included.
    pub additional: Vec<Rr>,
    /// The OPT record.
    pub opt: Option<Opt>,
}

/// How the data of a type is laid out, for the decompression of its names.
#[derive(Debug, Clone, Copy)]
enum Part {
    Fixed(usize),
    Name,
}

const NAME: &[Part] = &[Part::Name];
const SOA_PARTS: &[Part] = &[Part::Name, Part::Name, Part::Fixed(20)];
const TWO_NAMES: &[Part] = &[Part::Name, Part::Name];
const PREF_NAME: &[Part] = &[Part::Fixed(2), Part::Name];
const PX: &[Part] = &[Part::Fixed(2), Part::Name, Part::Name];
const SRV: &[Part] = &[Part::Fixed(6), Part::Name];

fn layout(rtype: u16) -> Option<&'static [Part]> {
    Some(match rtype {
        // NS, MD, MF, CNAME, MB, MG, MR, PTR, DNAME
        2..=5 | 7..=9 | 12 | 39 => NAME,
        6 => SOA_PARTS,
        // MINFO, RP
        14 | 17 => TWO_NAMES,
        // MX, AFSDB, RT, KX
        15 | 18 | 21 | 36 => PREF_NAME,
        26 => PX,
        33 => SRV,
        _ => return None,
    })
}

/// The data at `start..end` of `message` with its names decompressed, or `None` when it
/// does not parse.
fn decompress(message: &[u8], rtype: u16, start: usize, end: usize) -> Option<Vec<u8>> {
    let Some(parts) = layout(rtype) else {
        return Some(message.get(start..end)?.to_vec());
    };
    let mut out = Vec::with_capacity(end.saturating_sub(start) + 32);
    let mut pos = start;
    let mut name = NameBuf::root();
    for part in parts {
        match part {
            Part::Fixed(len) => {
                out.extend_from_slice(message.get(pos..pos + len)?);
                pos += len;
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

fn read_opt(record: &wire::RawRecord, message: &[u8]) -> Opt {
    let mut opt = Opt {
        udp_size: record.class,
        ext_rcode: u8::try_from(record.ttl >> 24).unwrap_or(0),
        dnssec_ok: record.ttl & 0x8000 != 0,
        cookie: None,
        bad_cookie_option: false,
    };
    let mut options = wire::options(record.data(message));
    for (code, value) in options.by_ref() {
        if code != OPTION_COOKIE {
            continue;
        }
        // RFC 7873 section 4: a client cookie of 8 octets, a server cookie of 8 to 32.
        let client: Option<[u8; 8]> = value.get(..8).and_then(|bytes| bytes.try_into().ok());
        match (client, value.len()) {
            (Some(client), 8) => opt.cookie = Some((client, None)),
            (Some(client), 16..=40) => {
                opt.cookie = Some((client, ServerCookie::new(&value[8..])));
            }
            _ => opt.bad_cookie_option = true,
        }
    }
    if options.malformed() {
        opt.bad_cookie_option = true;
    }
    opt
}

/// Reads `message`; `None` when it does not parse, has not one question, or holds more than
/// [`MAX_RECORDS`] records.
pub fn parse(message: &[u8]) -> Option<Parsed> {
    let header = wire::parse_header(message)?;
    if header.qdcount != 1 {
        return None;
    }
    let mut qname = NameBuf::root();
    let after = wire::read_name(message, HEADER_LEN, &mut qname)?;
    let qtype = u16::from_be_bytes(message.get(after..after + 2)?.try_into().ok()?);
    let mut pos = after + 4;
    if pos > message.len() {
        return None;
    }
    let counts = [header.ancount, header.nscount, header.arcount];
    if counts
        .iter()
        .map(|count| usize::from(*count))
        .sum::<usize>()
        > MAX_RECORDS
    {
        return None;
    }
    let mut sections: [Vec<Rr>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    let mut opt = None;
    let mut owner = NameBuf::root();
    for (index, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            let record = wire::read_record(message, pos)?;
            pos = record.end();
            if record.rtype == TYPE_OPT {
                // One OPT record, in the additional section, owned by the root.
                if index != 2 || opt.is_some() || message.get(record.start) != Some(&0) {
                    return None;
                }
                opt = Some(read_opt(&record, message));
                continue;
            }
            wire::read_name(message, record.start, &mut owner)?;
            let data = decompress(message, record.rtype, record.rdata, record.end())?;
            if data.len() > usize::from(u16::MAX) {
                return None;
            }
            sections[index].push(Rr {
                owner: owner.as_wire().to_vec(),
                rtype: record.rtype,
                class: record.class,
                ttl: record.ttl,
                data,
            });
        }
    }
    let [answer, authority, additional] = sections;
    let ext = opt.map_or(0, |opt| u16::from(opt.ext_rcode));
    Some(Parsed {
        id: header.id,
        rcode: (ext << 4) | u16::from(header.rcode & 0x0f),
        aa: header.aa,
        tc: header.tc,
        qname: qname.as_wire().to_vec(),
        qtype,
        answer,
        authority,
        additional,
        opt,
    })
}

/// Glue as the bailiwick rule reads it (RFC 9471).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlueKind {
    /// The name server is at or below the delegated zone: in-domain glue, cached.
    InDomain,
    /// The name server is in a sibling zone under the same parent: used for this step and
    /// marked unconfirmed.
    Sibling,
}

/// A referral: the delegated zone, its name servers and the glue the bailiwick rule keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Referral {
    /// The delegated zone, lowercase wire form.
    pub zone: Vec<u8>,
    /// The NS records of the delegation (data: the server names).
    pub ns: Vec<Rr>,
    /// The NS set's TTL (the smallest).
    pub ttl: u32,
    /// The glue kept: server name, address, TTL and kind.
    pub glue: Vec<(Vec<u8>, IpAddr, u32, GlueKind)>,
    /// The DS records and their signatures from the authority section (for WP10.2).
    pub ds: Vec<Rr>,
}

/// What an answer means for the resolution, for the zone the server was asked as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The data: the records of the chain within the zone (CNAMEs first) and the RRset
    /// asked with its signatures.
    Answer {
        /// The records.
        records: Vec<Rr>,
    },
    /// A CNAME (or a DNAME's synthesised CNAME) to an alias the server did not answer:
    /// the records of the chain so far and the name to go on with.
    Alias {
        /// The chain's records within the zone.
        records: Vec<Rr>,
        /// The next name, lowercase wire form.
        target: Vec<u8>,
    },
    /// A delegation further down.
    Referral(Referral),
    /// NXDOMAIN (RCODE 3) or NODATA (0): the chain's records, then the authority section's
    /// SOA and denial records within the zone.
    Negative {
        /// 3 for NXDOMAIN, 0 for NODATA.
        rcode: u8,
        /// The chain's records.
        records: Vec<Rr>,
        /// The SOA, NSEC and NSEC3 records and their signatures.
        authority: Vec<Rr>,
    },
    /// The server is lame for the zone, or its answer cannot be used.
    Lame(&'static str),
}

/// Whether `name` is at or below `zone` (both lowercase wire form).
pub fn within(name: &[u8], zone: &[u8]) -> bool {
    name::is_within(name, zone)
}

/// The name `qname` with its suffix `owner` replaced by `target` (a DNAME, RFC 6672), or
/// `None` when the result is longer than 255 octets.
pub fn substitute(qname: &[u8], owner: &[u8], target: &[u8]) -> Option<Vec<u8>> {
    let prefix_len = qname.len().checked_sub(owner.len())?;
    let mut out = qname[..prefix_len].to_vec();
    out.extend_from_slice(target);
    (out.len() <= name::MAX_NAME_LEN).then_some(out)
}

/// The records at `owner` of `rtype` (or of every type but RRSIG for ANY) with the
/// signatures that cover them, within `zone`.
fn rrset_at(section: &[Rr], owner: &[u8], rtype: u16) -> Vec<Rr> {
    section
        .iter()
        .filter(|rr| rr.owner == owner)
        .filter(|rr| {
            if rtype == ANY {
                true
            } else {
                rr.of_type(rtype)
            }
        })
        .cloned()
        .collect()
}

/// The longest chain an answer may hold (the work budget's restarts bound it as well).
const MAX_WALK: usize = 16;

/// Reads `parsed`, the answer of a server asked as an authority of `zone` for
/// `qname`/`qtype` (all names lowercase wire form); see the module documentation.
pub fn classify(parsed: &Parsed, zone: &[u8], qname: &[u8], qtype: u16) -> Step {
    match parsed.rcode {
        0 | 3 => {}
        _ => return Step::Lame("the server answered with an error"),
    }
    if parsed.qname != qname || parsed.qtype != qtype {
        return Step::Lame("the answer is to another question");
    }
    // The chain within the zone, from the name asked.
    let mut records: Vec<Rr> = Vec::new();
    let mut name = qname.to_vec();
    let mut seen: Vec<Vec<u8>> = vec![name.clone()];
    for _ in 0..MAX_WALK {
        if !within(&name, zone) {
            // A target outside the zone: the server's records for it are not its to give.
            return Step::Alias {
                records,
                target: name,
            };
        }
        let found = rrset_at(&parsed.answer, &name, qtype);
        if found.iter().any(|rr| qtype == ANY || rr.rtype == qtype) {
            if !parsed.aa {
                return Step::Lame("a non-authoritative answer");
            }
            records.extend(found);
            return Step::Answer { records };
        }
        if qtype != CNAME
            && let Some(cname) = parsed
                .answer
                .iter()
                .find(|rr| rr.owner == name && rr.rtype == CNAME)
        {
            let Some(target) = cname.target() else {
                return Step::Lame("a CNAME that does not parse");
            };
            records.extend(rrset_at(&parsed.answer, &name, CNAME));
            if seen.contains(&target) {
                // A loop inside the answer: the caller sees the repeat and stops.
                return Step::Alias { records, target };
            }
            seen.push(target.clone());
            name = target;
            continue;
        }
        // A DNAME at an ancestor of the name, within the zone (RFC 6672 section 3.2).
        if qtype != DNAME
            && let Some(dname) = parsed.answer.iter().find(|rr| {
                rr.rtype == DNAME
                    && rr.owner != name
                    && within(&name, &rr.owner)
                    && within(&rr.owner, zone)
            })
        {
            let Some(target) = dname
                .target()
                .and_then(|target| substitute(&name, &dname.owner, &target))
            else {
                return Step::Lame("a DNAME whose substitution is too long");
            };
            records.extend(rrset_at(&parsed.answer, &dname.owner, DNAME));
            // The CNAME the DNAME stands for, synthesised here (RFC 6672 section 3.4).
            records.push(Rr {
                owner: name.clone(),
                rtype: CNAME,
                class: dname.class,
                ttl: dname.ttl,
                data: target.clone(),
            });
            if seen.contains(&target) {
                return Step::Alias { records, target };
            }
            seen.push(target.clone());
            name = target;
            continue;
        }
        break;
    }
    if name != qname {
        if !parsed.aa {
            return Step::Lame("a non-authoritative alias");
        }
        // The chain ended at a name the answer has nothing for: an alias to follow, unless
        // the server says the target does not exist or has no data.
        if parsed.rcode == 3 || has_soa(parsed, zone) {
            return negative(parsed, zone, records);
        }
        return Step::Alias {
            records,
            target: name,
        };
    }
    if parsed.rcode == 0
        && !parsed.aa
        && let Some(referral) = referral(parsed, zone, qname, qtype)
    {
        return referral;
    }
    if parsed.aa || has_soa(parsed, zone) {
        return negative(parsed, zone, records);
    }
    Step::Lame("neither an answer nor a referral")
}

fn has_soa(parsed: &Parsed, zone: &[u8]) -> bool {
    parsed
        .authority
        .iter()
        .any(|rr| rr.rtype == SOA && within(&rr.owner, zone))
}

fn negative(parsed: &Parsed, zone: &[u8], records: Vec<Rr>) -> Step {
    // An SOA above the zone asked: the server answers from a parent zone and is not an
    // authority of this one (a lame delegation to a server of the parent).
    if parsed
        .authority
        .iter()
        .any(|rr| rr.rtype == SOA && !within(&rr.owner, zone))
    {
        return Step::Lame("a negative answer from a zone above the one asked");
    }
    let authority: Vec<Rr> = parsed
        .authority
        .iter()
        .filter(|rr| within(&rr.owner, zone))
        .filter(|rr| {
            matches!(rr.rtype, SOA | NSEC | NSEC3)
                || matches!(rr.covered(), Some(SOA | NSEC | NSEC3))
        })
        .cloned()
        .collect();
    Step::Negative {
        rcode: u8::try_from(parsed.rcode).unwrap_or(0),
        records,
        authority,
    }
}

/// A referral in the authority section: NS records owned by one zone strictly below the
/// zone asked and at or above the name asked (for DS, strictly above it).
fn referral(parsed: &Parsed, zone: &[u8], qname: &[u8], qtype: u16) -> Option<Step> {
    let ns: Vec<&Rr> = parsed
        .authority
        .iter()
        .filter(|rr| rr.rtype == NS)
        .collect();
    let child = &ns.first()?.owner;
    if ns.iter().any(|rr| &rr.owner != child) {
        return Some(Step::Lame("a referral to more than one zone"));
    }
    let below_zone = within(child, zone) && child.as_slice() != zone;
    let above_name = within(qname, child) && !(qtype == types::DS && child.as_slice() == qname);
    if !below_zone || !above_name {
        // An upward or sideways referral: the server does not serve the zone.
        return Some(Step::Lame("an upward or sideways referral"));
    }
    let ttl = ns.iter().map(|rr| rr.ttl).min().unwrap_or(0);
    let hosts: Vec<Vec<u8>> = ns.iter().filter_map(|rr| rr.target()).collect();
    if hosts.is_empty() {
        return Some(Step::Lame("a referral whose NS records do not parse"));
    }
    let mut glue = Vec::new();
    for rr in &parsed.additional {
        let Some(address) = rr.address() else {
            continue;
        };
        if !hosts.contains(&rr.owner) {
            continue;
        }
        let kind = if within(&rr.owner, child) {
            GlueKind::InDomain
        } else if within(&rr.owner, zone) {
            GlueKind::Sibling
        } else {
            // Out of bailiwick: never used.
            continue;
        };
        glue.push((rr.owner.clone(), address, rr.ttl, kind));
    }
    let ds = parsed
        .authority
        .iter()
        .filter(|rr| &rr.owner == child && rr.of_type(types::DS))
        .cloned()
        .collect();
    Some(Step::Referral(Referral {
        zone: child.clone(),
        ns: ns.into_iter().cloned().collect(),
        ttl,
        glue,
        ds,
    }))
}

/// What [`compose`] writes.
#[derive(Debug, Clone, Default)]
pub struct Composed<'a> {
    /// The name asked, lowercase wire form.
    pub qname: &'a [u8],
    /// The type asked.
    pub qtype: u16,
    /// The class asked.
    pub qclass: u16,
    /// The RCODE (0, 2 or 3).
    pub rcode: u8,
    /// The answer section.
    pub answer: &'a [Rr],
    /// The authority section.
    pub authority: &'a [Rr],
    /// The additional section.
    pub additional: &'a [Rr],
}

/// Writes the answer of a resolution as an authority's answer looks: id 0, QR, RD and RA
/// set, AA clear, one question, the sections without compression, and an OPT record of
/// 1,232 octets with DO (the forwarder's cache keeps the signatures for DO clients and
/// relays its own OPT record).
pub fn compose(answer: &Composed<'_>) -> Vec<u8> {
    let size = answer
        .answer
        .iter()
        .chain(answer.authority)
        .chain(answer.additional)
        .map(|rr| rr.owner.len() + 10 + rr.data.len())
        .sum::<usize>();
    let mut out = Vec::with_capacity(HEADER_LEN + answer.qname.len() + 4 + size + 11);
    let count = |records: &[Rr]| u16::try_from(records.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&[0, 0, 0x81, 0x80 | (answer.rcode & 0x0f), 0, 1]);
    out.extend_from_slice(&count(answer.answer).to_be_bytes());
    out.extend_from_slice(&count(answer.authority).to_be_bytes());
    out.extend_from_slice(&count(answer.additional).saturating_add(1).to_be_bytes());
    out.extend_from_slice(answer.qname);
    out.extend_from_slice(&answer.qtype.to_be_bytes());
    out.extend_from_slice(&answer.qclass.to_be_bytes());
    for rr in answer
        .answer
        .iter()
        .chain(answer.authority)
        .chain(answer.additional)
    {
        rr.write(&mut out);
    }
    out.push(0);
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&crate::recursion::authority::AUTHORITY_UDP_SIZE.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0x80, 0, 0, 0]);
    out
}

#[cfg(test)]
mod tests;
