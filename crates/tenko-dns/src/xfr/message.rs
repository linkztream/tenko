//! The messages of transfers and NOTIFY: a writer of answers in messages of a bounded size,
//! and a reader of the answers of other servers (names decompressed, record data in the
//! stored uncompressed form).
//!
//! The writer copies the question into every message and compresses an owner name that
//! ends in the question name with a pointer to it (offset 12), which is most owners of a
//! zone; record data is written uncompressed, as stored. The reader follows compression
//! pointers backwards only and decompresses the names inside the record data of the types
//! RFC 3597 section 4 lets a sender compress, and of the later types some servers compress
//! anyway (RP, AFSDB, RT, PX, SRV, NAPTR, KX, DNAME); every other type is taken as it is.

use tenko_core::dns::{DnsName, Rdata, Rtype};

use crate::{
    name::NameBuf,
    wire::{self, HEADER_LEN},
};

/// The largest transfer message Tenko writes (RFC 5936 leaves the size to the server; 16
/// KiB keeps a message within a few TCP segments and below every client's buffer).
pub const MAX_TRANSFER_MESSAGE: usize = 16 * 1024;

/// Room kept free in a message for its TSIG record (the longest key name, the longest
/// algorithm name and a 64-octet MAC).
pub const TSIG_ROOM: usize = 255 + 10 + 13 + 10 + 64 + 6 + 6;

/// The opcode of a query.
pub const OPCODE_QUERY: u8 = 0;
/// The opcode of NOTIFY (RFC 1996).
pub const OPCODE_NOTIFY: u8 = 4;

/// IXFR.
pub const TYPE_IXFR: u16 = 251;
/// AXFR.
pub const TYPE_AXFR: u16 = 252;
/// SOA.
pub const TYPE_SOA: u16 = 6;
/// Class IN.
pub const CLASS_IN: u16 = 1;

/// A question of a transfer request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The name in lowercase wire form.
    pub name: NameBuf,
    /// The type.
    pub qtype: u16,
    /// The class.
    pub qclass: u16,
}

/// The facts of a request the transfer path handles: the header, the one question and,
/// for IXFR, the client's serial from the SOA in the authority section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequest {
    /// The message id.
    pub id: u16,
    /// The opcode.
    pub opcode: u8,
    /// The question.
    pub question: Question,
    /// The serial of the SOA in the authority section (IXFR, a NOTIFY's answer section).
    pub serial: Option<u32>,
    /// Where the question ends.
    pub question_end: usize,
}

/// Reads a request of the transfer path. `None` for a response, a runt or a message that
/// does not hold exactly one question.
pub fn read_request(message: &[u8]) -> Option<TransferRequest> {
    let header = wire::parse_header(message)?;
    if header.qr || header.qdcount != 1 {
        return None;
    }
    let mut name = NameBuf::root();
    let after_name = wire::read_name(message, HEADER_LEN, &mut name)?;
    let fixed = message.get(after_name..after_name + 4)?;
    let qtype = u16::from_be_bytes([fixed[0], fixed[1]]);
    let qclass = u16::from_be_bytes([fixed[2], fixed[3]]);
    let question_end = after_name + 4;
    let mut serial = None;
    let mut pos = question_end;
    let records = usize::from(header.ancount) + usize::from(header.nscount);
    for _ in 0..records {
        let record = wire::read_record(message, pos)?;
        if record.rtype == TYPE_SOA && serial.is_none() {
            serial = soa_serial_at(message, record.rdata);
        }
        pos = record.end();
    }
    Some(TransferRequest {
        id: header.id,
        opcode: header.opcode,
        question: Question {
            name,
            qtype,
            qclass,
        },
        serial,
        question_end,
    })
}

/// The serial of SOA data that starts at `pos` in a message (names may be compressed).
fn soa_serial_at(message: &[u8], pos: usize) -> Option<u32> {
    let mailbox = wire::skip_name(message, pos)?;
    let numbers = wire::skip_name(message, mailbox)?;
    let bytes = message.get(numbers..numbers + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The serial of stored SOA data.
pub fn soa_serial(rdata: &[u8]) -> Option<u32> {
    soa_serial_at(rdata, 0)
}

/// The header flags of an answer: QR, the opcode, AA and the RCODE.
fn flags(opcode: u8, authoritative: bool, rcode: u8) -> [u8; 2] {
    [
        0x80 | (opcode << 3) | if authoritative { 0x04 } else { 0 },
        rcode & 0x0f,
    ]
}

/// Writes the answers of a transfer in messages of at most `limit` octets, each starting
/// with the header and the question.
#[derive(Debug)]
pub struct MessageWriter {
    buf: Vec<u8>,
    limit: usize,
    count: u16,
    id: u16,
    opcode: u8,
    question: Vec<u8>,
    qname_len: usize,
}

impl MessageWriter {
    /// A writer of answers to `request` (its id, opcode and question copied from
    /// `message`) in messages of at most `limit` octets including the TSIG room.
    pub fn new(message: &[u8], request: &TransferRequest, limit: usize) -> Self {
        let question = message
            .get(HEADER_LEN..request.question_end)
            .unwrap_or_default()
            .to_vec();
        let mut writer = Self {
            buf: Vec::with_capacity(limit),
            limit: limit.saturating_sub(TSIG_ROOM),
            count: 0,
            id: request.id,
            opcode: request.opcode,
            qname_len: request.question.name.as_wire().len(),
            question,
        };
        writer.start();
        writer
    }

    fn start(&mut self) {
        self.buf.clear();
        self.buf.extend_from_slice(&self.id.to_be_bytes());
        self.buf.extend_from_slice(&flags(self.opcode, true, 0));
        self.buf.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        self.buf.extend_from_slice(&self.question);
        self.count = 0;
    }

    /// Whether the current message holds no record.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Adds a record to the current message; `false` when it does not fit (finish the
    /// message and add it to the next).
    pub fn push(&mut self, owner: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) -> bool {
        let mark = self.buf.len();
        self.write_owner(owner);
        let Ok(rdlen) = u16::try_from(rdata.len()) else {
            self.buf.truncate(mark);
            return false;
        };
        self.buf.extend_from_slice(&rtype.to_be_bytes());
        self.buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        self.buf.extend_from_slice(&ttl.to_be_bytes());
        self.buf.extend_from_slice(&rdlen.to_be_bytes());
        self.buf.extend_from_slice(rdata);
        if self.buf.len() > self.limit || self.count == u16::MAX {
            self.buf.truncate(mark);
            return false;
        }
        self.count += 1;
        let count = self.count.to_be_bytes();
        self.buf[6..8].copy_from_slice(&count);
        true
    }

    /// The owner, compressed against the question name when it ends with it.
    fn write_owner(&mut self, owner: &[u8]) {
        let qname = &self.question[..self.qname_len.min(self.question.len())];
        if qname.len() > 1 && owner.len() >= qname.len() && owner.ends_with(qname) {
            let head = owner.len() - qname.len();
            // The suffix must start at a label boundary of the owner.
            let mut pos = 0;
            while pos < head {
                pos += 1 + usize::from(owner[pos]);
            }
            if pos == head {
                self.buf.extend_from_slice(&owner[..head]);
                self.buf.extend_from_slice(&[0xc0, 0x0c]);
                return;
            }
        }
        self.buf.extend_from_slice(owner);
    }

    /// Takes the current message and starts the next.
    pub fn take(&mut self) -> Vec<u8> {
        let message = std::mem::replace(&mut self.buf, Vec::with_capacity(self.limit));
        self.start();
        message
    }
}

/// A header-only answer to a request (with its question): an error or an empty NOTIFY
/// answer.
pub fn short_answer(message: &[u8], request: &TransferRequest, rcode: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(request.question_end + TSIG_ROOM);
    out.extend_from_slice(&request.id.to_be_bytes());
    out.extend_from_slice(&flags(request.opcode, rcode == 0, rcode));
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(
        message
            .get(HEADER_LEN..request.question_end)
            .unwrap_or_default(),
    );
    out
}

/// Writes a request: a query for a transfer or SOA, or a NOTIFY, with one question and,
/// when given, an SOA record in the authority section (the client's serial of an IXFR) or
/// the answer section (the serial of a NOTIFY).
pub fn write_request(
    out: &mut Vec<u8>,
    id: u16,
    opcode: u8,
    zone: &[u8],
    qtype: u16,
    soa: Option<(u32, &[u8])>,
) {
    out.clear();
    out.extend_from_slice(&id.to_be_bytes());
    // NOTIFY sets AA (RFC 1996 section 3.7).
    out.push((opcode << 3) | if opcode == OPCODE_NOTIFY { 0x04 } else { 0 });
    out.push(0);
    let (answers, authority) = match (soa.is_some(), opcode) {
        (true, OPCODE_NOTIFY) => (1u16, 0u16),
        (true, _) => (0, 1),
        (false, _) => (0, 0),
    };
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&authority.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(zone);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    if let Some((ttl, rdata)) = soa {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&TYPE_SOA.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(rdata);
    }
}

/// One record of an answer, decompressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The owner.
    pub name: DnsName,
    /// The type.
    pub rtype: Rtype,
    /// The class.
    pub class: u16,
    /// The TTL.
    pub ttl: u32,
    /// The data in stored form (names uncompressed and lowercase).
    pub rdata: Rdata,
}

/// Why an answer could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// The message does not parse.
    #[error("the message does not parse")]
    Malformed,
    /// A record's data is not valid for its type.
    #[error("a record of type {rtype} is invalid: {reason}")]
    Invalid {
        /// The type.
        rtype: Rtype,
        /// Why.
        reason: String,
    },
}

/// The facts of an answer: its header and the records of its answer section (OPT and TSIG
/// in the additional section are not records of the zone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The message id.
    pub id: u16,
    /// The opcode.
    pub opcode: u8,
    /// The RCODE (low four bits).
    pub rcode: u8,
    /// Authoritative answer.
    pub authoritative: bool,
    /// Truncated.
    pub truncated: bool,
    /// The answer section.
    pub answers: Vec<Record>,
}

/// Reads an answer: the header, the question skipped, the answer section decompressed.
///
/// # Errors
///
/// [`ReadError`] for a message that does not parse or a record that is not valid.
pub fn read_answer(message: &[u8]) -> Result<Answer, ReadError> {
    let header = wire::parse_header(message).ok_or(ReadError::Malformed)?;
    if !header.qr {
        return Err(ReadError::Malformed);
    }
    let mut pos = wire::questions_end(message, header.qdcount).ok_or(ReadError::Malformed)?;
    let mut answers = Vec::with_capacity(usize::from(header.ancount));
    let mut owner = NameBuf::root();
    for _ in 0..header.ancount {
        let record = wire::read_record(message, pos).ok_or(ReadError::Malformed)?;
        wire::read_name(message, record.start, &mut owner).ok_or(ReadError::Malformed)?;
        let rtype = Rtype(record.rtype);
        let name = owner.to_dns_name().ok_or(ReadError::Malformed)?;
        let data = decompress(message, record.rtype, record.rdata, record.end())
            .ok_or(ReadError::Malformed)?;
        let rdata = Rdata::from_wire(rtype, &data).map_err(|error| ReadError::Invalid {
            rtype,
            reason: error.to_string(),
        })?;
        answers.push(Record {
            name,
            rtype,
            class: record.class,
            ttl: record.ttl,
            rdata,
        });
        pos = record.end();
    }
    Ok(Answer {
        id: header.id,
        opcode: header.opcode,
        rcode: header.rcode,
        authoritative: header.aa,
        truncated: header.tc,
        answers,
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

/// The layout of a type whose data holds names a sender may have compressed.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_compressed_answer_reads_back_in_stored_form() {
        // An AXFR answer for example.test: the SOA with both names compressed, then an MX
        // whose exchange points into the owner.
        let mut query = Vec::new();
        let zone = b"\x07example\x04test\x00";
        write_request(&mut query, 7, OPCODE_QUERY, zone, TYPE_AXFR, None);
        let request = read_request(&query).expect("request");
        assert_eq!(request.question.qtype, TYPE_AXFR);
        let mut writer = MessageWriter::new(&query, &request, MAX_TRANSFER_MESSAGE);
        let soa = Rdata::from_wire(
            Rtype::SOA,
            b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x2a\x00\x00\x0e\x10\x00\x00\x03\x84\x00\x09\x3a\x80\x00\x00\x01\x2c",
        )
        .expect("soa");
        assert!(writer.push(zone, 6, 3600, soa.as_bytes()));
        assert!(writer.push(b"\x04mail\x07example\x04test\x00", 1, 300, &[192, 0, 2, 25]));
        let mut message = writer.take();
        // Make it an answer as a server would compress it: the MX of a peer.
        message.extend_from_slice(&[0xc0, 0x0c, 0, 15, 0, 1, 0, 0, 1, 0x2c, 0, 4, 0, 10]);
        message.extend_from_slice(&[0xc0, 0x0c]);
        let count = u16::from_be_bytes([message[6], message[7]]) + 1;
        message[6..8].copy_from_slice(&count.to_be_bytes());
        let answer = read_answer(&message).expect("answer");
        assert_eq!(answer.answers.len(), 3);
        assert_eq!(answer.answers[0].rdata, soa);
        assert_eq!(soa_serial(soa.as_bytes()), Some(42));
        assert_eq!(answer.answers[1].name.as_str(), "mail.example.test");
        assert_eq!(
            answer.answers[2].rdata.as_bytes(),
            b"\x00\x0a\x07example\x04test\x00"
        );
    }

    #[test]
    fn messages_break_before_the_limit() {
        let mut query = Vec::new();
        let zone = b"\x07example\x04test\x00";
        write_request(&mut query, 1, OPCODE_QUERY, zone, TYPE_AXFR, None);
        let request = read_request(&query).expect("request");
        let mut writer = MessageWriter::new(&query, &request, 1024);
        let mut messages = Vec::new();
        for index in 0..200u8 {
            let owner = [&[1u8, b'a' + index % 26][..], zone].concat();
            if !writer.push(&owner, 16, 60, &[20; 21]) {
                messages.push(writer.take());
                assert!(writer.push(&owner, 16, 60, &[20; 21]));
            }
        }
        messages.push(writer.take());
        assert!(messages.len() > 5);
        let mut total = 0;
        for message in &messages {
            assert!(message.len() <= 1024 - TSIG_ROOM);
            total += read_answer(message).expect("answer").answers.len();
        }
        assert_eq!(total, 200);
    }

    #[test]
    fn a_notify_and_an_ixfr_request_carry_their_serial() {
        let zone = b"\x07example\x04test\x00";
        let soa = b"\x00\x00\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01";
        let mut out = Vec::new();
        write_request(&mut out, 9, OPCODE_NOTIFY, zone, TYPE_SOA, Some((60, soa)));
        let request = read_request(&out).expect("notify");
        assert_eq!((request.opcode, request.serial), (OPCODE_NOTIFY, Some(7)));
        write_request(&mut out, 9, OPCODE_QUERY, zone, TYPE_IXFR, Some((60, soa)));
        let request = read_request(&out).expect("ixfr");
        assert_eq!(
            (request.question.qtype, request.serial),
            (TYPE_IXFR, Some(7))
        );
        let answer = short_answer(&out, &request, 9);
        let header = wire::parse_header(&answer).expect("header");
        assert_eq!((header.qr, header.rcode, header.qdcount), (true, 9, 1));
    }
}
