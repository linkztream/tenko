//! The codec on `domain`, the production codec (ADR 0009).
//!
//! Parsing is zero-copy: the header and the question come from `Message<&[u8]>`, the
//! question name stays a `ParsedName` borrowing the message, and the OPT and TSIG records
//! are read with the raw walker of [`crate::wire`], which also records the positions TSIG
//! verification needs. Building writes into the caller's vector through a
//! `StaticCompressor` (compression with a fixed table, no heap). Record data is stored
//! uncompressed; the five RFC 1035 types whose names may be compressed (NS, CNAME, SOA,
//! PTR, MX) are pushed as typed data over borrowed names so the compressor shortens them,
//! every other type is copied as it is.

use domain::{
    base::{
        Message, Name, Question, Serial, Ttl,
        iana::{Class, Opcode, OptRcode, OptionCode, Rcode, Rtype},
        message_builder::{
            AdditionalBuilder, AnswerBuilder, MessageBuilder, PushError, RecordSectionBuilder,
            StaticCompressor,
        },
        name::{ParsedName, ToName},
        rdata::{ComposeRecordData, RecordData},
        wire::Composer,
    },
    dep::octseq::builder::OctetsBuilder,
    rdata::{Cname, Mx, Ns, Ptr, Soa},
};

use super::{
    AnswerBuf, BuildOutcome, Codec, CodecError, Cookie, Edns, Owner, RecordView, Request, Section,
    TsigInfo,
};
use crate::{
    name::NameBuf,
    wire::{
        self, CLASS_ANY, OPTION_COOKIE, OPTION_EXTENDED_ERROR, RawRecord, SERVER_UDP_PAYLOAD,
        TYPE_OPT, TYPE_TSIG,
    },
};

type Target = StaticCompressor<Vec<u8>>;

/// The query as `domain` parsed it: the question (its name borrowing the message) and the
/// opcode.
pub struct DomainQuery<'a> {
    question: Question<ParsedName<&'a [u8]>>,
    opcode: Opcode,
}

/// The codec on `domain` 0.12.3.
#[derive(Debug, Default, Clone, Copy)]
pub struct DomainCodec;

impl DomainCodec {
    /// The codec.
    pub const fn new() -> Self {
        Self
    }
}

/// Record data copied as it is.
struct RawData<'a> {
    rtype: Rtype,
    data: &'a [u8],
}

impl RecordData for RawData<'_> {
    fn rtype(&self) -> Rtype {
        self.rtype
    }
}

impl ComposeRecordData for RawData<'_> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        u16::try_from(self.data.len()).ok()
    }

    fn compose_rdata<T: Composer + ?Sized>(&self, target: &mut T) -> Result<(), T::AppendError> {
        target.append_slice(self.data)
    }

    fn compose_canonical_rdata<T: Composer + ?Sized>(
        &self,
        target: &mut T,
    ) -> Result<(), T::AppendError> {
        target.append_slice(self.data)
    }
}

/// The length of the uncompressed name at the front of `data`.
fn name_len(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    loop {
        let len = usize::from(*data.get(pos)?);
        if len == 0 {
            return Some(pos + 1);
        }
        if len > 63 {
            return None;
        }
        pos += 1 + len;
    }
}

/// The uncompressed name at the front of `data` and the octets after it.
fn split_name(data: &[u8]) -> Option<(&Name<[u8]>, &[u8])> {
    let len = name_len(data)?;
    let name = Name::from_slice(&data[..len]).ok()?;
    Some((name, &data[len..]))
}

/// The uncompressed name that is all of `data`.
fn whole_name(data: &[u8]) -> Option<&Name<[u8]>> {
    let (name, rest) = split_name(data)?;
    rest.is_empty().then_some(name)
}

fn u32_at(data: &[u8], pos: usize) -> Option<u32> {
    let bytes = data.get(pos..pos + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Pushes one record with the given owner, compressing the names of the RFC 1035 types.
fn push_owned<N: ToName, B: RecordSectionBuilder<Target>>(
    builder: &mut B,
    owner: N,
    record: &RecordView<'_>,
) -> Result<(), PushError> {
    let class = Class::from_int(record.class);
    let ttl = Ttl::from_secs(record.ttl);
    let data = record.rdata;
    match record.rtype {
        2 => {
            if let Some(name) = whole_name(data) {
                return builder.push((owner, class, ttl, Ns::new(name)));
            }
        }
        5 => {
            if let Some(name) = whole_name(data) {
                return builder.push((owner, class, ttl, Cname::new(name)));
            }
        }
        12 => {
            if let Some(name) = whole_name(data) {
                return builder.push((owner, class, ttl, Ptr::new(name)));
            }
        }
        15 => {
            if let Some((preference, rest)) = data.split_first_chunk::<2>()
                && let Some(name) = whole_name(rest)
            {
                return builder.push((
                    owner,
                    class,
                    ttl,
                    Mx::new(u16::from_be_bytes(*preference), name),
                ));
            }
        }
        6 => {
            if let Some((mname, rest)) = split_name(data)
                && let Some((rname, rest)) = split_name(rest)
                && rest.len() == 20
                && let (Some(serial), Some(refresh), Some(retry), Some(expire), Some(minimum)) = (
                    u32_at(rest, 0),
                    u32_at(rest, 4),
                    u32_at(rest, 8),
                    u32_at(rest, 12),
                    u32_at(rest, 16),
                )
            {
                let soa = Soa::new(
                    mname,
                    rname,
                    Serial(serial),
                    Ttl::from_secs(refresh),
                    Ttl::from_secs(retry),
                    Ttl::from_secs(expire),
                    Ttl::from_secs(minimum),
                );
                return builder.push((owner, class, ttl, soa));
            }
        }
        _ => {}
    }
    builder.push((
        owner,
        class,
        ttl,
        RawData {
            rtype: Rtype::from_int(record.rtype),
            data,
        },
    ))
}

/// Pushes one record of the answer.
fn push_record<B: RecordSectionBuilder<Target>>(
    builder: &mut B,
    query: &DomainQuery<'_>,
    record: &RecordView<'_>,
) -> Result<(), PushError> {
    match record.owner {
        Owner::Qname => push_owned(builder, query.question.qname(), record),
        Owner::Name(wire) => match Name::from_slice(wire) {
            Ok(name) => push_owned(builder, name, record),
            Err(_) => Err(PushError::ShortBuf),
        },
    }
}

impl DomainCodec {
    /// Starts an answer: the header and the question.
    fn start(
        target: Target,
        query: &DomainQuery<'_>,
        request: &Request,
        answer: &AnswerBuf,
        limit: usize,
    ) -> Result<AnswerBuilder<Target>, CodecError> {
        let mut message = MessageBuilder::from_target(target).map_err(|_| CodecError::Build)?;
        message.set_push_limit(limit);
        let header = message.header_mut();
        header.set_id(request.id);
        header.set_qr(true);
        header.set_opcode(query.opcode);
        header.set_rd(request.rd);
        header.set_cd(request.cd);
        header.set_aa(answer.authoritative);
        header.set_ra(answer.recursion_available);
        header.set_ad(answer.authenticated);
        // The low four bits; the rest goes into OPT.
        header.set_rcode(Rcode::masked_from_int((answer.rcode & 0x0f) as u8));
        let mut question = message.question();
        question
            .push(query.question)
            .map_err(|_| CodecError::Build)?;
        Ok(question.answer())
    }

    /// Writes the answer and authority sections; `false` when a record did not fit.
    fn push_sections(
        mut answers: AnswerBuilder<Target>,
        query: &DomainQuery<'_>,
        answer: &AnswerBuf,
    ) -> (AdditionalBuilder<Target>, bool, usize) {
        for record in answer.section(Section::Answer) {
            if push_record(&mut answers, query, &record).is_err() {
                return (answers.additional(), false, 0);
            }
        }
        let mut authority = answers.authority();
        for record in answer.section(Section::Authority) {
            if push_record(&mut authority, query, &record).is_err() {
                return (authority.additional(), false, 0);
            }
        }
        let mut additional = authority.additional();
        let mut dropped = 0;
        for record in answer.section(Section::Additional) {
            if dropped > 0 || push_record(&mut additional, query, &record).is_err() {
                dropped += 1;
            }
        }
        (additional, true, dropped)
    }

    /// Writes the OPT record: payload size, DO, the extended RCODE, cookie and extended
    /// error.
    fn push_opt(
        additional: &mut AdditionalBuilder<Target>,
        answer: &AnswerBuf,
        dnssec_ok: bool,
    ) -> Result<(), CodecError> {
        additional
            .opt(|opt| {
                opt.set_udp_payload_size(SERVER_UDP_PAYLOAD);
                opt.set_dnssec_ok(dnssec_ok);
                if answer.rcode > 0x0f {
                    opt.set_rcode(OptRcode::masked_from_int(answer.rcode));
                }
                if let Some(cookie) = answer.cookie() {
                    let len = u16::try_from(cookie.len()).unwrap_or(0);
                    opt.push_raw_option(OptionCode::from_int(OPTION_COOKIE), len, |target| {
                        target.append_slice(cookie)
                    })?;
                }
                if let Some((code, text)) = answer.extended_error() {
                    let len = u16::try_from(2 + text.len()).unwrap_or(2);
                    opt.push_raw_option(
                        OptionCode::from_int(OPTION_EXTENDED_ERROR),
                        len,
                        |target| {
                            target.append_slice(&code.to_be_bytes())?;
                            target.append_slice(text.as_bytes())
                        },
                    )?;
                }
                Ok(())
            })
            .map_err(|_| CodecError::Build)
    }
}

/// Reads the TSIG record at `record` (the last of the message).
fn parse_tsig(message: &[u8], record: &RawRecord) -> Result<TsigInfo, CodecError> {
    let bad = CodecError::Tsig;
    if record.class != CLASS_ANY || record.ttl != 0 {
        return Err(bad);
    }
    let mut key = NameBuf::root();
    wire::read_name(message, record.start, &mut key).ok_or(bad)?;
    let mut algorithm = NameBuf::root();
    let end = record.end();
    let mut pos = wire::read_name(message, record.rdata, &mut algorithm).ok_or(bad)?;
    let fixed = message.get(pos..pos + 10).ok_or(bad)?;
    let time_signed = u64::from_be_bytes([
        0, 0, fixed[0], fixed[1], fixed[2], fixed[3], fixed[4], fixed[5],
    ]);
    let fudge = u16::from_be_bytes([fixed[6], fixed[7]]);
    let mac_len = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
    pos += 10;
    let mac = (pos, mac_len);
    pos += mac_len;
    let tail = message.get(pos..pos + 6).ok_or(bad)?;
    let original_id = u16::from_be_bytes([tail[0], tail[1]]);
    let error = u16::from_be_bytes([tail[2], tail[3]]);
    let other_len = usize::from(u16::from_be_bytes([tail[4], tail[5]]));
    pos += 6;
    let other = (pos, other_len);
    pos += other_len;
    if pos != end {
        return Err(bad);
    }
    Ok(TsigInfo {
        key,
        algorithm,
        time_signed,
        fudge,
        original_id,
        error,
        record_start: record.start,
        mac,
        other,
    })
}

/// Reads the additional section: at most one OPT record (owned by the root) and a TSIG
/// record, which must be the last record of the message.
fn parse_additional(message: &[u8], request: &mut Request) -> Result<(), CodecError> {
    let header = wire::parse_header(message).ok_or(CodecError::NotAQuery)?;
    let mut pos = wire::questions_end(message, header.qdcount).ok_or(CodecError::Question)?;
    for _ in 0..u32::from(header.ancount) + u32::from(header.nscount) {
        pos = wire::read_record(message, pos)
            .ok_or(CodecError::Record)?
            .end();
    }
    for index in 0..header.arcount {
        let record = wire::read_record(message, pos).ok_or(CodecError::Record)?;
        pos = record.end();
        match record.rtype {
            TYPE_OPT => {
                if request.edns.is_some()
                    || message[record.start] != 0
                    || record.fixed != record.start + 1
                {
                    return Err(CodecError::Edns);
                }
                let mut options = wire::options(record.data(message));
                let mut cookie = None;
                for (code, value) in options.by_ref() {
                    if code == OPTION_COOKIE {
                        if cookie.is_some() {
                            return Err(CodecError::Edns);
                        }
                        cookie = Some(Cookie::from_option(value).ok_or(CodecError::Edns)?);
                    }
                }
                if options.malformed() {
                    return Err(CodecError::Edns);
                }
                request.edns = Some(Edns {
                    udp_size: record.class,
                    version: ((record.ttl >> 16) & 0xff) as u8,
                    dnssec_ok: record.ttl & 0x8000 != 0,
                    cookie,
                });
            }
            TYPE_TSIG => {
                if index + 1 != header.arcount {
                    return Err(CodecError::Tsig);
                }
                request.tsig = Some(parse_tsig(message, &record)?);
            }
            _ => {}
        }
    }
    Ok(())
}

impl Codec for DomainCodec {
    type Query<'a> = DomainQuery<'a>;

    fn parse<'a>(
        &self,
        message: &'a [u8],
        request: &mut Request,
    ) -> Result<DomainQuery<'a>, CodecError> {
        let header = wire::parse_header(message).ok_or(CodecError::NotAQuery)?;
        if header.qr {
            return Err(CodecError::NotAQuery);
        }
        if header.qdcount != 1 {
            return Err(CodecError::QuestionCount);
        }
        let parsed = Message::from_octets(message).map_err(|_| CodecError::Question)?;
        let question = parsed.sole_question().map_err(|_| CodecError::Question)?;
        request.edns = None;
        request.tsig = None;
        request.qname.clear();
        for label in question.qname() {
            if !label.is_root() {
                request
                    .qname
                    .push_label(label.as_slice())
                    .map_err(|_| CodecError::Question)?;
            }
        }
        let flags = parsed.header();
        request.id = flags.id();
        request.opcode = flags.opcode().to_int();
        request.rd = flags.rd();
        request.cd = flags.cd();
        request.ad = flags.ad();
        request.qtype = question.qtype().to_int();
        request.qclass = question.qclass().to_int();
        parse_additional(message, request)?;
        Ok(DomainQuery {
            question,
            opcode: flags.opcode(),
        })
    }

    fn build(
        &self,
        query: &DomainQuery<'_>,
        request: &Request,
        answer: &AnswerBuf,
        max_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<BuildOutcome, CodecError> {
        let edns = request.edns;
        let reserve = if edns.is_some() { answer.opt_len() } else { 0 };
        // The builder refuses a push that makes the message reach its limit, hence the + 1.
        let limit = max_len.checked_sub(reserve).ok_or(CodecError::Build)? + 1;
        let message = Self::start(
            StaticCompressor::new(std::mem::take(out)),
            query,
            request,
            answer,
            limit,
        )?;
        let (mut additional, fits, dropped) = Self::push_sections(message, query, answer);
        let mut outcome = BuildOutcome {
            truncated: !fits,
            additional_dropped: dropped,
        };
        if !fits {
            // Header, question and OPT only, with TC.
            let target = additional.finish();
            let mut message = Self::start(target, query, request, answer, limit)?;
            message.header_mut().set_tc(true);
            additional = message.additional();
            outcome.additional_dropped = 0;
        }
        additional.clear_push_limit();
        if let Some(edns) = edns {
            Self::push_opt(&mut additional, answer, edns.dnssec_ok)?;
        }
        let finished = additional.finish().into_target();
        if finished.len() > max_len {
            *out = finished;
            return Err(CodecError::Build);
        }
        *out = finished;
        Ok(outcome)
    }
}
