//! The wire codec behind one small trait (ADR 0009, ADR 0017).
//!
//! [`Codec::parse`] turns a query into a crate-independent [`Request`] (header, the one
//! question, EDNS with the cookie, TSIG with the positions its verification needs) and a
//! crate-specific query that [`Codec::build`] echoes. The engine fills an [`AnswerBuf`]
//! from the index and the codec writes it, with EDNS, extended errors, cookies and the
//! truncation rules. Both calls allocate nothing once the buffers have their capacity: the
//! request lives in fixed-size fields, the answer in an arena reserved per worker, and the
//! output reuses its vector. `tests/alloc.rs` fails when either allocates.
//!
//! The production codec is [`DomainCodec`] on `domain` 0.12.3; the differential tests build
//! the same answers with `hickory-proto` and compare the bytes.
//!
//! # Truncation
//!
//! The header and the question always fit (a question is at most 259 octets). The OPT
//! record, with the cookie and the extended error, is reserved before any record. When an
//! answer or authority record does not fit, the response is the header, the question and
//! OPT with TC set (RFC 2181, section 9; RFC 6891, section 7). Additional records that do
//! not fit are left out without TC; [`BuildOutcome::additional_dropped`] counts them, except
//! the ones the resolver marked required ([`AnswerBuf::require_additional`], the in-domain
//! glue of a referral, RFC 9471), which truncate like an answer record. A resolver can also
//! ask for the truncated form outright ([`AnswerBuf::truncated`], the slip of rate limiting).

use crate::{
    name::NameBuf,
    wire::{CLASSIC_UDP_LEN, OPT_LEN, SERVER_UDP_PAYLOAD},
};

mod domain_codec;

pub use domain_codec::{DomainCodec, DomainQuery};

/// Why a message could not be parsed or an answer not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// Shorter than a header, or a response (QR set): dropped, never answered.
    #[error("not a query")]
    NotAQuery,
    /// The header or the question section does not parse.
    #[error("malformed header or question")]
    Question,
    /// Not exactly one question.
    #[error("the message does not have exactly one question")]
    QuestionCount,
    /// A record of the answer, authority or additional section does not parse.
    #[error("malformed record")]
    Record,
    /// A second OPT record, an OPT record not owned by the root, or a malformed option or
    /// cookie (RFC 6891, RFC 7873).
    #[error("malformed EDNS")]
    Edns,
    /// A TSIG record that is not the last record, or whose data does not parse (RFC 8945).
    #[error("malformed TSIG")]
    Tsig,
    /// The answer could not be written within the size limit.
    #[error("the answer does not fit")]
    Build,
}

/// A server or client cookie (RFC 7873): the client part, and the server part when the
/// client sent one.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cookie {
    client: [u8; 8],
    server: [u8; 32],
    server_len: u8,
}

impl Cookie {
    /// A cookie from its option value: 8 octets of client cookie and 0 or 8 to 32 octets of
    /// server cookie.
    pub fn from_option(value: &[u8]) -> Option<Self> {
        let (client, server) = (value.get(..8)?, &value[8..]);
        if !(server.is_empty() || (8..=32).contains(&server.len())) {
            return None;
        }
        let mut cookie = Self {
            client: [0; 8],
            server: [0; 32],
            server_len: u8::try_from(server.len()).ok()?,
        };
        cookie.client.copy_from_slice(client);
        cookie.server[..server.len()].copy_from_slice(server);
        Some(cookie)
    }

    /// The client cookie.
    pub fn client(&self) -> &[u8; 8] {
        &self.client
    }

    /// The server cookie the client returned; empty on a first contact.
    pub fn server(&self) -> &[u8] {
        &self.server[..usize::from(self.server_len)]
    }
}

impl std::fmt::Debug for Cookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cookie(client: {:02x?}, server: {} octets)",
            self.client, self.server_len
        )
    }
}

/// EDNS(0) information from the query's OPT record (RFC 6891).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edns {
    /// The requester's UDP payload size.
    pub udp_size: u16,
    /// The EDNS version; anything but 0 gets BADVERS.
    pub version: u8,
    /// The DNSSEC OK bit (RFC 3225).
    pub dnssec_ok: bool,
    /// The cookie option, if any.
    pub cookie: Option<Cookie>,
}

/// The TSIG record of a query (RFC 8945), with the positions its verification needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigInfo {
    /// The key name, lowercased.
    pub key: NameBuf,
    /// The algorithm name, lowercased.
    pub algorithm: NameBuf,
    /// Seconds since 1970 (48 bits).
    pub time_signed: u64,
    /// Permitted clock error in seconds.
    pub fudge: u16,
    /// The original message id.
    pub original_id: u16,
    /// The TSIG error field.
    pub error: u16,
    /// Where the TSIG record starts in the message: the MAC covers the octets before it
    /// (with ARCOUNT lowered by one and the id replaced by `original_id`).
    pub record_start: usize,
    mac: (usize, usize),
    other: (usize, usize),
}

impl TsigInfo {
    /// The MAC, from the message it was parsed from.
    pub fn mac<'a>(&self, message: &'a [u8]) -> &'a [u8] {
        message
            .get(self.mac.0..self.mac.0 + self.mac.1)
            .unwrap_or_default()
    }

    /// The other data, from the message it was parsed from.
    pub fn other<'a>(&self, message: &'a [u8]) -> &'a [u8] {
        message
            .get(self.other.0..self.other.0 + self.other.1)
            .unwrap_or_default()
    }
}

/// The crate-independent facts of a parsed query. Filled in place by [`Codec::parse`];
/// reused between queries without allocating.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request {
    /// The message id.
    pub id: u16,
    /// The opcode (0 QUERY, 4 NOTIFY, 5 UPDATE).
    pub opcode: u8,
    /// Recursion desired.
    pub rd: bool,
    /// Checking disabled.
    pub cd: bool,
    /// Authentic data requested (RFC 6840).
    pub ad: bool,
    /// The question name, lowercased.
    pub qname: NameBuf,
    /// The question type.
    pub qtype: u16,
    /// The question class.
    pub qclass: u16,
    /// The OPT record, if any.
    pub edns: Option<Edns>,
    /// The TSIG record, if any.
    pub tsig: Option<TsigInfo>,
}

impl Request {
    /// The largest UDP answer for this request: 512 octets without EDNS, else the
    /// requester's size clamped to 512 to 1232 (DNS flag day 2020).
    pub fn max_udp_len(&self) -> usize {
        self.udp_len(SERVER_UDP_PAYLOAD)
    }

    /// The largest UDP answer for this request when the server's EDNS size is `server`:
    /// 512 octets without EDNS, else the requester's size clamped to 512 to `server`.
    pub fn udp_len(&self, server: u16) -> usize {
        match self.edns {
            Some(edns) => usize::from(edns.udp_size.clamp(512, server.max(512))),
            None => CLASSIC_UDP_LEN,
        }
    }
}

/// A section of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Section {
    /// The answer section.
    Answer,
    /// The authority section.
    Authority,
    /// The additional section.
    Additional,
}

/// The owner of a record in an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner<'a> {
    /// The question name as the client wrote it (its case kept), for answers at the
    /// question name and records synthesized from a wildcard.
    Qname,
    /// A name in lowercase, uncompressed wire form.
    Name(&'a [u8]),
}

/// Why a record could not be added to an [`AnswerBuf`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AnswerError {
    /// The record or arena capacity is used up (the buffer never grows).
    #[error("the answer buffer is full")]
    Full,
    /// A section before one already written.
    #[error("sections are written in order: answer, authority, additional")]
    OutOfOrder,
    /// A value too long for its field (extended error text, cookie).
    #[error("a value is too long")]
    TooLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerSpan {
    Qname,
    Arena { start: usize, len: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecordSpan {
    section: Section,
    owner: OwnerSpan,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: (usize, usize),
}

/// One record of an [`AnswerBuf`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordView<'a> {
    /// The section.
    pub section: Section,
    /// The owner.
    pub owner: Owner<'a>,
    /// The type.
    pub rtype: u16,
    /// The class.
    pub class: u16,
    /// The TTL.
    pub ttl: u32,
    /// The data in uncompressed wire form.
    pub rdata: &'a [u8],
}

/// An answer to write: the header bits, the records of the three sections and the EDNS
/// extras. The records and their names and data live in buffers reserved once; pushing
/// past their capacity fails instead of allocating.
#[derive(Debug, Clone)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the header flags of RFC 1035 are bits"
)]
pub struct AnswerBuf {
    /// The RCODE, 12 bits; above 15 only with EDNS (BADVERS 16, BADCOOKIE 23).
    pub rcode: u16,
    /// Authoritative answer.
    pub authoritative: bool,
    /// Recursion available.
    pub recursion_available: bool,
    /// Authentic data.
    pub authenticated: bool,
    /// Answer with the header, the question and OPT only, with TC set, whatever the
    /// records (the slip of response rate limiting, an answer too large for the buffer).
    pub truncated: bool,
    /// The UDP payload size the OPT record advertises: the server's EDNS size (1232 unless
    /// configured). A setting of the buffer: [`AnswerBuf::clear`] keeps it.
    pub udp_payload: u16,
    records: Vec<RecordSpan>,
    required_additional: usize,
    arena: Vec<u8>,
    extended_error: Option<(u16, usize, usize)>,
    cookie: Option<(usize, usize)>,
}

impl AnswerBuf {
    /// A buffer for `records` records with `arena` octets of names, data and text.
    pub fn with_capacity(records: usize, arena: usize) -> Self {
        Self {
            rcode: 0,
            authoritative: false,
            recursion_available: false,
            authenticated: false,
            truncated: false,
            udp_payload: SERVER_UDP_PAYLOAD,
            records: Vec::with_capacity(records),
            required_additional: 0,
            arena: Vec::with_capacity(arena),
            extended_error: None,
            cookie: None,
        }
    }

    /// Empties the buffer for the next query, keeping its capacity and its UDP payload size.
    pub fn clear(&mut self) {
        self.rcode = 0;
        self.authoritative = false;
        self.recursion_available = false;
        self.authenticated = false;
        self.truncated = false;
        self.records.clear();
        self.required_additional = 0;
        self.arena.clear();
        self.extended_error = None;
        self.cookie = None;
    }

    fn store(&mut self, bytes: &[u8]) -> Result<(usize, usize), AnswerError> {
        if self.arena.len() + bytes.len() > self.arena.capacity() {
            return Err(AnswerError::Full);
        }
        let start = self.arena.len();
        self.arena.extend_from_slice(bytes);
        Ok((start, bytes.len()))
    }

    /// Adds a record (class IN unless [`AnswerBuf::push_class`] says otherwise).
    ///
    /// # Errors
    ///
    /// [`AnswerError`] when the buffer is full or the section comes before one written.
    pub fn push(
        &mut self,
        section: Section,
        owner: Owner<'_>,
        rtype: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> Result<(), AnswerError> {
        self.push_class(section, owner, rtype, 1, ttl, rdata)
    }

    /// Adds a record of any class.
    ///
    /// # Errors
    ///
    /// [`AnswerError`] when the buffer is full or the section comes before one written.
    pub fn push_class(
        &mut self,
        section: Section,
        owner: Owner<'_>,
        rtype: u16,
        class: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> Result<(), AnswerError> {
        if self
            .records
            .last()
            .is_some_and(|last| last.section > section)
        {
            return Err(AnswerError::OutOfOrder);
        }
        if self.records.len() == self.records.capacity() || rdata.len() > usize::from(u16::MAX) {
            return Err(AnswerError::Full);
        }
        let mark = self.arena.len();
        let owner = match owner {
            Owner::Qname => OwnerSpan::Qname,
            Owner::Name(wire) => {
                let (start, len) = self.store(wire)?;
                OwnerSpan::Arena { start, len }
            }
        };
        let rdata = match self.store(rdata) {
            Ok(span) => span,
            Err(error) => {
                self.arena.truncate(mark);
                return Err(error);
            }
        };
        self.records.push(RecordSpan {
            section,
            owner,
            rtype,
            class,
            ttl,
            rdata,
        });
        Ok(())
    }

    /// Marks every additional record pushed so far as required: when one of them does not
    /// fit, the answer is truncated (TC) instead of leaving it out (RFC 9471, in-domain glue).
    pub fn require_additional(&mut self) {
        self.required_additional = self
            .records
            .iter()
            .filter(|record| record.section == Section::Additional)
            .count();
    }

    /// The number of leading additional records that must fit.
    pub fn required_additional(&self) -> usize {
        self.required_additional
    }

    /// The number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the buffer holds no record.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Sets the extended DNS error (RFC 8914): an info code and an optional English text.
    ///
    /// # Errors
    ///
    /// [`AnswerError`] when the text does not fit.
    pub fn set_extended_error(&mut self, code: u16, text: &str) -> Result<(), AnswerError> {
        if text.len() > 512 {
            return Err(AnswerError::TooLong);
        }
        let (start, len) = self.store(text.as_bytes())?;
        self.extended_error = Some((code, start, len));
        Ok(())
    }

    /// Sets the cookie option of the answer: the client cookie and the server cookie
    /// (RFC 7873, 16 to 40 octets).
    ///
    /// # Errors
    ///
    /// [`AnswerError`] for a length outside 16 to 40 octets, or a full arena.
    pub fn set_cookie(&mut self, cookie: &[u8]) -> Result<(), AnswerError> {
        if !(16..=40).contains(&cookie.len()) {
            return Err(AnswerError::TooLong);
        }
        self.cookie = Some(self.store(cookie)?);
        Ok(())
    }

    /// The records in order.
    pub fn records(&self) -> impl Iterator<Item = RecordView<'_>> {
        self.records.iter().map(|span| RecordView {
            section: span.section,
            owner: match span.owner {
                OwnerSpan::Qname => Owner::Qname,
                OwnerSpan::Arena { start, len } => Owner::Name(&self.arena[start..start + len]),
            },
            rtype: span.rtype,
            class: span.class,
            ttl: span.ttl,
            rdata: &self.arena[span.rdata.0..span.rdata.0 + span.rdata.1],
        })
    }

    /// The records of one section.
    pub fn section(&self, section: Section) -> impl Iterator<Item = RecordView<'_>> {
        self.records()
            .filter(move |record| record.section == section)
    }

    /// The extended error, if set.
    pub fn extended_error(&self) -> Option<(u16, &str)> {
        self.extended_error.map(|(code, start, len)| {
            (
                code,
                std::str::from_utf8(&self.arena[start..start + len]).unwrap_or_default(),
            )
        })
    }

    /// The cookie option value, if set.
    pub fn cookie(&self) -> Option<&[u8]> {
        self.cookie
            .map(|(start, len)| &self.arena[start..start + len])
    }

    /// The length of the OPT record this answer needs, with its options, when the request
    /// has EDNS.
    pub fn opt_len(&self) -> usize {
        OPT_LEN
            + self.cookie.map_or(0, |(_, len)| 4 + len)
            + self.extended_error.map_or(0, |(_, _, len)| 4 + 2 + len)
    }
}

/// What [`Codec::build`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BuildOutcome {
    /// The answer or authority section did not fit: TC is set and every section is empty.
    pub truncated: bool,
    /// Additional records left out because they did not fit.
    pub additional_dropped: usize,
}

/// Parse and build with one DNS wire-format crate.
pub trait Codec: Send + Sync + 'static {
    /// The crate's parsed form of a query; it may borrow the message.
    type Query<'a>;

    /// Parses the header, the one question, the OPT record and the TSIG record of a query
    /// into `request` (overwritten) and the crate's query.
    ///
    /// # Errors
    ///
    /// [`CodecError::NotAQuery`] for a runt or a response (drop it); every other error
    /// answers FORMERR through [`crate::wire::write_formerr`].
    fn parse<'a>(
        &self,
        message: &'a [u8],
        request: &mut Request,
    ) -> Result<Self::Query<'a>, CodecError>;

    /// Writes the answer to `query` into `out` (its contents are replaced, its capacity
    /// kept) in at most `max_len` octets: [`Request::max_udp_len`] for UDP, 65,535 for TCP.
    /// The OPT record is written when the request had one: the payload size of
    /// [`AnswerBuf::udp_payload`] (1232 by default), the DO bit
    /// echoed, the extended RCODE, the cookie and the extended error of `answer`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Build`] when even the header, the question and OPT do not fit.
    fn build(
        &self,
        query: &Self::Query<'_>,
        request: &Request,
        answer: &AnswerBuf,
        max_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<BuildOutcome, CodecError>;
}

#[cfg(test)]
mod tests;
