//! The TKEY query and answer on the wire (RFC 2930 sections 2 and 4, RFC 3645 section 4).
//!
//! A TKEY query is a QUERY (opcode 0) with one question `<key name> TKEY` and a TKEY
//! record of the same owner, normally in the additional section; Windows 2000 put it in
//! the answer section, so that is looked at second, as BIND does. The record's data is the
//! algorithm name (uncompressed), inception and expiration (Unix seconds, 32 bits), the
//! mode, the error, the key data with its length and the other data with its length.
//! Every length is checked against the octets that are there; nothing is allocated before
//! the record has been read.
//!
//! The answer echoes the question, carries the TKEY record in the answer section and an
//! OPT record when the query had one; the caller signs it. An answer larger than the
//! transport takes is sent as the header and the question with TC set, so that the client
//! asks again over TCP.

use crate::{
    name::NameBuf,
    wire::{self, CLASS_ANY, HEADER_LEN, TYPE_OPT, TYPE_TSIG},
};

/// The record type of TKEY.
pub const TYPE_TKEY: u16 = 249;

/// The modes of RFC 2930 section 2.5 that Tenko takes.
pub mod mode {
    /// GSS-API negotiation (RFC 3645).
    pub const GSSAPI: u16 = 3;
    /// Key deletion.
    pub const DELETE: u16 = 5;
}

/// The TKEY error codes (RFC 2930 section 2.6, RFC 8945 section 3).
pub mod error {
    /// The negotiation failed (a token that does not verify, no Kerberos).
    pub const BADKEY: u16 = 17;
    /// A mode Tenko does not take.
    pub const BADMODE: u16 = 19;
    /// The key name is in use, or not the question's.
    pub const BADNAME: u16 = 20;
    /// An algorithm other than `gss-tsig`.
    pub const BADALG: u16 = 21;
}

/// The largest key data Tenko reads: a SPNEGO token with a ticket and a PAC of many groups
/// stays well below it.
pub const MAX_KEY_DATA: usize = 16 * 1024;

/// A TKEY query, as positions and slices of the message.
#[derive(Debug, Clone)]
pub struct TkeyQuery<'a> {
    /// The message id.
    pub id: u16,
    /// Recursion desired, copied into the answer.
    pub rd: bool,
    /// Where the question ends (the answer echoes the question).
    pub question_end: usize,
    /// The key name in lowercase wire form (the question's name).
    pub name: NameBuf,
    /// The algorithm name in wire form, as written.
    pub algorithm: &'a [u8],
    /// Inception, Unix seconds.
    pub inception: u32,
    /// Expiration, Unix seconds.
    pub expiration: u32,
    /// The mode.
    pub mode: u16,
    /// The key data: the initiator's token in mode 3.
    pub key: &'a [u8],
    /// The requester's EDNS UDP size, when it sent OPT.
    pub edns: Option<u16>,
    /// Whether the message carries a TSIG record.
    pub signed: bool,
}

/// Why a TKEY query does not parse (FORMERR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TkeyFormError {
    /// Not a query with one TKEY question.
    #[error("not a TKEY query")]
    NotTkey,
    /// The message does not parse.
    #[error("the message does not parse")]
    Message,
    /// No TKEY record of the question's name.
    #[error("no TKEY record for the key name")]
    Missing,
    /// The TKEY record's data does not parse.
    #[error("malformed TKEY record")]
    Record,
    /// The key data is larger than Tenko reads.
    #[error("the key data is too large")]
    TooLarge,
}

fn u16_at(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]))
}

fn u32_at(buf: &[u8], pos: usize) -> Option<u32> {
    let b = buf.get(pos..pos + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Whether `message` is a TKEY query: a QUERY whose single question has the type TKEY.
/// Reads the header and skips one name; for the hand-off off the query path, which has
/// parsed the question already and compares its type.
pub fn is_tkey(message: &[u8]) -> bool {
    let Some(header) = wire::parse_header(message) else {
        return false;
    };
    if header.qr || header.opcode != 0 || header.qdcount != 1 {
        return false;
    }
    wire::skip_name(message, HEADER_LEN).and_then(|end| u16_at(message, end)) == Some(TYPE_TKEY)
}

/// An uncompressed name at `pos`: its end.
fn uncompressed_name_end(buf: &[u8], mut pos: usize) -> Option<usize> {
    let start = pos;
    loop {
        let len = usize::from(*buf.get(pos)?);
        if len == 0 {
            return (pos + 1 - start <= 255).then_some(pos + 1);
        }
        if len > 63 {
            return None;
        }
        pos += 1 + len;
    }
}

/// Parses a TKEY query.
///
/// # Errors
///
/// [`TkeyFormError`].
pub fn parse(message: &[u8]) -> Result<TkeyQuery<'_>, TkeyFormError> {
    let header = wire::parse_header(message).ok_or(TkeyFormError::Message)?;
    if header.qr || header.opcode != 0 || header.qdcount != 1 {
        return Err(TkeyFormError::NotTkey);
    }
    let mut name = NameBuf::default();
    let qname_end =
        wire::read_name(message, HEADER_LEN, &mut name).ok_or(TkeyFormError::Message)?;
    if u16_at(message, qname_end) != Some(TYPE_TKEY) {
        return Err(TkeyFormError::NotTkey);
    }
    let question_end = qname_end + 4;
    if message.len() < question_end {
        return Err(TkeyFormError::Message);
    }
    let answers = usize::from(header.ancount);
    let authority = usize::from(header.nscount);
    let additional = usize::from(header.arcount);
    let mut pos = question_end;
    let mut in_answer = None;
    let mut in_additional = None;
    let mut edns = None;
    let mut signed = false;
    let mut owner = NameBuf::default();
    for index in 0..answers + authority + additional {
        let record = wire::read_record(message, pos).ok_or(TkeyFormError::Message)?;
        let section_answer = index < answers;
        let section_additional = index >= answers + authority;
        match record.rtype {
            TYPE_TKEY => {
                wire::read_name(message, record.start, &mut owner).ok_or(TkeyFormError::Message)?;
                if owner.as_wire() == name.as_wire() {
                    if section_additional && in_additional.is_none() {
                        in_additional = Some(record);
                    } else if section_answer && in_answer.is_none() {
                        in_answer = Some(record);
                    }
                }
            }
            TYPE_OPT if section_additional => edns = Some(record.class.max(512)),
            TYPE_TSIG => signed = true,
            _ => {}
        }
        pos = record.end();
    }
    let record = in_additional.or(in_answer).ok_or(TkeyFormError::Missing)?;
    let data = record.data(message);
    let bad = TkeyFormError::Record;
    let algorithm_end = uncompressed_name_end(data, 0).ok_or(bad)?;
    let algorithm = &data[..algorithm_end];
    let fixed = algorithm_end;
    let inception = u32_at(data, fixed).ok_or(bad)?;
    let expiration = u32_at(data, fixed + 4).ok_or(bad)?;
    let mode = u16_at(data, fixed + 8).ok_or(bad)?;
    let key_len = usize::from(u16_at(data, fixed + 12).ok_or(bad)?);
    if key_len > MAX_KEY_DATA {
        return Err(TkeyFormError::TooLarge);
    }
    let key_start = fixed + 14;
    let key = data.get(key_start..key_start + key_len).ok_or(bad)?;
    let other_len = usize::from(u16_at(data, key_start + key_len).ok_or(bad)?);
    let other_end = key_start + key_len + 2 + other_len;
    if other_end != data.len() {
        return Err(bad);
    }
    Ok(TkeyQuery {
        id: header.id,
        rd: header.rd,
        question_end,
        name,
        algorithm,
        inception,
        expiration,
        mode,
        key,
        edns,
        signed,
    })
}

/// The TKEY record of an answer.
#[derive(Debug, Clone, Copy)]
pub struct TkeyAnswer<'a> {
    /// The algorithm name in wire form.
    pub algorithm: &'a [u8],
    /// Inception, Unix seconds.
    pub inception: u32,
    /// Expiration, Unix seconds.
    pub expiration: u32,
    /// The mode.
    pub mode: u16,
    /// The TKEY error.
    pub error: u16,
    /// The key data: the acceptor's token.
    pub key: &'a [u8],
}

/// Writes the answer to `query` (the octets of `request`) into `out`: the header with
/// `rcode` (QR and AA set, RD copied), the question, the TKEY record when given, and an OPT
/// record of `udp_size` when the query had one. When the answer would exceed `max_len` it
/// is the header and the question with TC set and no record. Returns `false` when not even
/// that fits.
pub fn write_answer(
    request: &[u8],
    query: &TkeyQuery<'_>,
    rcode: u8,
    tkey: Option<&TkeyAnswer<'_>>,
    udp_size: u16,
    max_len: usize,
    out: &mut Vec<u8>,
) -> bool {
    let question = &request[HEADER_LEN..query.question_end];
    let name = query.name.as_wire();
    let tkey_len = tkey.map_or(0, |t| {
        name.len() + 10 + t.algorithm.len() + 16 + t.key.len()
    });
    let opt_len = if query.edns.is_some() { 11 } else { 0 };
    let full = HEADER_LEN + question.len() + tkey_len + opt_len;
    let truncated = full > max_len;
    if HEADER_LEN + question.len() > max_len {
        return false;
    }
    out.clear();
    out.extend_from_slice(&query.id.to_be_bytes());
    out.push(0x80 | 0x04 | u8::from(truncated) << 1 | u8::from(query.rd));
    out.push(rcode & 0x0f);
    out.extend_from_slice(&1_u16.to_be_bytes());
    let (answer_count, extra_count) = if truncated {
        (0_u16, 0_u16)
    } else {
        (u16::from(tkey.is_some()), u16::from(query.edns.is_some()))
    };
    out.extend_from_slice(&answer_count.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&extra_count.to_be_bytes());
    out.extend_from_slice(question);
    if truncated {
        return true;
    }
    if let Some(t) = tkey {
        out.extend_from_slice(name);
        out.extend_from_slice(&TYPE_TKEY.to_be_bytes());
        out.extend_from_slice(&CLASS_ANY.to_be_bytes());
        out.extend_from_slice(&0_u32.to_be_bytes());
        let rdlen = u16::try_from(t.algorithm.len() + 16 + t.key.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&rdlen.to_be_bytes());
        out.extend_from_slice(t.algorithm);
        out.extend_from_slice(&t.inception.to_be_bytes());
        out.extend_from_slice(&t.expiration.to_be_bytes());
        out.extend_from_slice(&t.mode.to_be_bytes());
        out.extend_from_slice(&t.error.to_be_bytes());
        let key_len = u16::try_from(t.key.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&key_len.to_be_bytes());
        out.extend_from_slice(t.key);
        out.extend_from_slice(&0_u16.to_be_bytes());
    }
    if query.edns.is_some() {
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&udp_size.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
    true
}

/// Writes an answer of the header and the question with `rcode` and no record (REFUSED on
/// a node without keys, SERVFAIL over the update path's bounds): the id and RD copied,
/// QR set, opcode QUERY. Returns `false` for a message that is not a TKEY query.
pub fn write_header_answer(request: &[u8], rcode: u16, out: &mut Vec<u8>) -> bool {
    let Some(header) = wire::parse_header(request) else {
        return false;
    };
    if header.qr || header.opcode != 0 || header.qdcount != 1 {
        return false;
    }
    let Some(question_end) = wire::questions_end(request, 1).filter(|end| *end <= request.len())
    else {
        return false;
    };
    out.clear();
    out.extend_from_slice(&header.id.to_be_bytes());
    out.push(0x80 | u8::from(header.rd));
    out.push(u8::try_from(rcode & 0x0f).unwrap_or(2));
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&request[HEADER_LEN..question_end]);
    true
}

/// Writes the answer to a TKEY query that comes over UDP: the header and the question with
/// TC set and no record, so that the client asks again over TCP. Returns `false` when the
/// question is malformed.
pub fn write_truncated(request: &[u8], query: &TkeyQuery<'_>, out: &mut Vec<u8>) -> bool {
    let Some(question) = request.get(HEADER_LEN..query.question_end) else {
        return false;
    };
    out.clear();
    out.extend_from_slice(&query.id.to_be_bytes());
    out.push(0x80 | 0x04 | 0x02 | u8::from(query.rd));
    out.push(0);
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(question);
    true
}

/// Writes a TKEY query for tests, tools and the lab: one question `<name> TKEY ANY` and the
/// TKEY record in the additional section, unsigned. `name` and `algorithm` are uncompressed
/// wire names. Clears `out` first.
pub fn write_query(
    out: &mut Vec<u8>,
    id: u16,
    name: &[u8],
    algorithm: &[u8],
    mode: u16,
    key: &[u8],
    now: u32,
) {
    out.clear();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
    out.extend_from_slice(name);
    out.extend_from_slice(&TYPE_TKEY.to_be_bytes());
    out.extend_from_slice(&CLASS_ANY.to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&TYPE_TKEY.to_be_bytes());
    out.extend_from_slice(&CLASS_ANY.to_be_bytes());
    out.extend_from_slice(&0_u32.to_be_bytes());
    let rdlen = u16::try_from(algorithm.len() + 16 + key.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&rdlen.to_be_bytes());
    out.extend_from_slice(algorithm);
    out.extend_from_slice(&now.to_be_bytes());
    out.extend_from_slice(&now.saturating_add(3_600).to_be_bytes());
    out.extend_from_slice(&mode.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    let key_len = u16::try_from(key.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&key_len.to_be_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(&0_u16.to_be_bytes());
}

/// The mode, the error and the key data of an answer's TKEY record.
pub type AnswerRecord<'a> = (u16, u16, &'a [u8]);

/// The TKEY record of an answer, read back (tests, tools, the fuzz target).
///
/// # Errors
///
/// [`TkeyFormError`].
pub fn answer_record(message: &[u8]) -> Result<Option<AnswerRecord<'_>>, TkeyFormError> {
    let header = wire::parse_header(message).ok_or(TkeyFormError::Message)?;
    let mut pos = wire::questions_end(message, header.qdcount).ok_or(TkeyFormError::Message)?;
    for _ in 0..header.ancount {
        let record = wire::read_record(message, pos).ok_or(TkeyFormError::Message)?;
        if record.rtype == TYPE_TKEY {
            let data = record.data(message);
            let fixed = uncompressed_name_end(data, 0).ok_or(TkeyFormError::Record)?;
            let mode = u16_at(data, fixed + 8).ok_or(TkeyFormError::Record)?;
            let error = u16_at(data, fixed + 10).ok_or(TkeyFormError::Record)?;
            let key_len = usize::from(u16_at(data, fixed + 12).ok_or(TkeyFormError::Record)?);
            let key = data
                .get(fixed + 14..fixed + 14 + key_len)
                .ok_or(TkeyFormError::Record)?;
            return Ok(Some((mode, error, key)));
        }
        pos = record.end();
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tsig::GSS_TSIG;

    const NAME: &[u8] = b"\x0asig-pc01-1\x07example\x04test\x00";

    /// DNS-28: a TKEY query written by the test client parses back, the hand-off test
    /// recognizes it, and an answer echoes the question with the TKEY record.
    #[test]
    fn dns_28_a_tkey_query_parses_and_its_answer_round_trips() {
        let mut query = Vec::new();
        write_query(
            &mut query,
            7,
            NAME,
            GSS_TSIG,
            mode::GSSAPI,
            b"token",
            1_790_000_000,
        );
        assert!(is_tkey(&query));
        let parsed = parse(&query).expect("parses");
        assert_eq!(parsed.name.as_wire(), NAME);
        assert_eq!(parsed.algorithm, GSS_TSIG);
        assert_eq!(parsed.mode, mode::GSSAPI);
        assert_eq!(parsed.key, b"token");
        assert_eq!(parsed.inception, 1_790_000_000);
        assert!(!parsed.signed);
        let mut out = Vec::new();
        let tkey = TkeyAnswer {
            algorithm: GSS_TSIG,
            inception: 1,
            expiration: 2,
            mode: mode::GSSAPI,
            error: 0,
            key: b"reply",
        };
        assert!(write_answer(
            &query,
            &parsed,
            0,
            Some(&tkey),
            1232,
            512,
            &mut out
        ));
        assert_eq!(&out[..2], &[0, 7]);
        assert_eq!(out[2] & 0x80, 0x80);
        assert_eq!(
            answer_record(&out),
            Ok(Some((mode::GSSAPI, 0, &b"reply"[..])))
        );
        // Too large for the transport: the header and the question with TC.
        assert!(write_answer(
            &query,
            &parsed,
            0,
            Some(&tkey),
            1232,
            60,
            &mut out
        ));
        assert_eq!(out[2] & 0x02, 0x02);
        assert_eq!(answer_record(&out), Ok(None));
    }

    /// DNS-28: what is not a well-formed TKEY query is refused, never a panic: another
    /// type, a missing record, a record of another name, a compressed algorithm name,
    /// lengths beyond the data.
    #[test]
    fn dns_28_malformed_tkey_queries_are_refused() {
        let mut query = Vec::new();
        write_query(&mut query, 7, NAME, GSS_TSIG, mode::GSSAPI, b"token", 1);
        let mut other = query.clone();
        let qtype = HEADER_LEN + NAME.len();
        other[qtype + 1] = 1;
        assert!(!is_tkey(&other));
        assert_eq!(parse(&other).map(|_| ()), Err(TkeyFormError::NotTkey));
        let mut missing = query.clone();
        missing[11] = 0;
        assert_eq!(parse(&missing).map(|_| ()), Err(TkeyFormError::Missing));
        let mut renamed = query.clone();
        let owner = HEADER_LEN + NAME.len() + 4 + 1;
        renamed[owner] = b'x';
        assert_eq!(parse(&renamed).map(|_| ()), Err(TkeyFormError::Missing));
        let rdata = HEADER_LEN + NAME.len() * 2 + 4 + 10;
        let mut compressed = query.clone();
        compressed[rdata] = 0xc0;
        assert!(parse(&compressed).is_err());
        let mut long = query.clone();
        let key_len = rdata + GSS_TSIG.len() + 12;
        long[key_len] = 0xff;
        assert!(parse(&long).is_err());
        for cut in 0..query.len() {
            let _ = parse(&query[..cut]);
        }
    }
}
