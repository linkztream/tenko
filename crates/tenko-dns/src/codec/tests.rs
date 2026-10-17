//! Behaviour of [`DomainCodec`]: answers are decoded again with `hickory-proto` (an
//! independent decoder) and with the raw header helpers.

use hickory_proto::op::Message as HickoryMessage;

use super::*;
use crate::wire::{self, MAX_MESSAGE_LEN, TsigRecord, parse_header, read_record, write_query};

const A: u16 = 1;
const NS: u16 = 2;
const SOA: u16 = 6;
const MX: u16 = 15;
const TXT: u16 = 16;

fn query(name: &str, qtype: u16, edns: Option<u16>) -> Vec<u8> {
    let mut out = Vec::new();
    write_query(&mut out, 0x4242, name, qtype, edns);
    out
}

fn soa_rdata() -> Vec<u8> {
    let mut data = b"\x03ns1\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00".to_vec();
    for value in [2_026_101_701u32, 3600, 900, 1_209_600, 300] {
        data.extend_from_slice(&value.to_be_bytes());
    }
    data
}

const APEX: &[u8] = b"\x07example\x04test\x00";

fn build(message: &[u8], answer: &AnswerBuf, max_len: Option<usize>) -> (Vec<u8>, BuildOutcome) {
    let codec = DomainCodec::new();
    let mut request = Request::default();
    let query = codec.parse(message, &mut request).expect("parse");
    let mut out = Vec::with_capacity(MAX_MESSAGE_LEN);
    let limit = max_len.unwrap_or_else(|| request.max_udp_len());
    let outcome = codec
        .build(&query, &request, answer, limit, &mut out)
        .expect("build");
    (out, outcome)
}

fn decode(message: &[u8]) -> HickoryMessage {
    HickoryMessage::from_vec(message).expect("an independent decoder reads the answer")
}

fn answer_a() -> AnswerBuf {
    let mut answer = AnswerBuf::with_capacity(16, 4096);
    answer.authoritative = true;
    answer
        .push(Section::Answer, Owner::Qname, A, 300, &[192, 0, 2, 7])
        .expect("push");
    answer
}

#[test]
fn a_positive_answer_echoes_the_question_and_adds_opt() {
    let message = query("WWW.Example.TEST", A, Some(4096));
    let (out, outcome) = build(&message, &answer_a(), None);
    assert_eq!(outcome, BuildOutcome::default());
    let header = parse_header(&out).expect("header");
    assert_eq!(
        (header.id, header.qr, header.aa, header.tc, header.rcode),
        (0x4242, true, true, false, 0)
    );
    assert_eq!(
        (
            header.qdcount,
            header.ancount,
            header.nscount,
            header.arcount
        ),
        (1, 1, 0, 1)
    );
    // The question is echoed octet for octet, its case kept.
    let question_len = 4 + 1 + 7 + 1 + 4 + 1 + 4;
    assert_eq!(&out[12..12 + question_len], &message[12..12 + question_len]);
    let decoded = decode(&out);
    assert_eq!(
        decoded
            .edns
            .as_ref()
            .map(hickory_proto::op::Edns::max_payload),
        Some(1232)
    );
    assert_eq!(decoded.answers.len(), 1);
    // Without EDNS there is no OPT.
    let (out, _) = build(&query("www.example.test", A, None), &answer_a(), None);
    assert_eq!(parse_header(&out).expect("header").arcount, 0);
    assert!(decode(&out).edns.is_none());
}

#[test]
fn a_negative_answer_carries_the_soa_with_compressed_names() {
    let mut answer = AnswerBuf::with_capacity(16, 4096);
    answer.authoritative = true;
    answer.rcode = 3;
    answer
        .push(
            Section::Authority,
            Owner::Name(APEX),
            SOA,
            300,
            &soa_rdata(),
        )
        .expect("push");
    let (out, _) = build(&query("nohost.example.test", A, Some(1232)), &answer, None);
    let header = parse_header(&out).expect("header");
    assert_eq!(
        (header.rcode, header.ancount, header.nscount, header.arcount),
        (3, 0, 1, 1)
    );
    // Uncompressed, the SOA owner and data alone would take 13 + 10 + 54 octets after the
    // question; compression points at the question's `example.test`.
    assert!(out.len() < 12 + 25 + 13 + 10 + 54);
    let decoded = decode(&out);
    let soa = decoded.authorities[0].data.clone();
    assert_eq!(
        soa.to_string().split_whitespace().next(),
        Some("ns1.example.test.")
    );
}

#[test]
fn records_that_do_not_fit_truncate() {
    let mut answer = AnswerBuf::with_capacity(64, 16_384);
    for last in 0..40u8 {
        answer
            .push(Section::Answer, Owner::Qname, A, 300, &[192, 0, 2, last])
            .expect("push");
    }
    let message = query("many.example.test", A, None);
    let (out, outcome) = build(&message, &answer, None);
    assert!(outcome.truncated);
    let header = parse_header(&out).expect("header");
    assert!(header.tc);
    assert_eq!((header.ancount, header.nscount, header.arcount), (0, 0, 0));
    assert!(out.len() <= 512);
    // Over TCP everything fits.
    let (out, outcome) = build(&message, &answer, Some(MAX_MESSAGE_LEN));
    assert!(!outcome.truncated);
    assert_eq!(parse_header(&out).expect("header").ancount, 40);
}

#[test]
fn additional_records_that_do_not_fit_are_left_out_without_tc() {
    let mut answer = AnswerBuf::with_capacity(64, 16_384);
    answer
        .push(
            Section::Answer,
            Owner::Qname,
            MX,
            300,
            b"\x00\x0a\x04mail\x07example\x04test\x00",
        )
        .expect("push");
    for last in 0..40u8 {
        answer
            .push(
                Section::Additional,
                Owner::Name(b"\x04mail\x07example\x04test\x00"),
                A,
                300,
                &[192, 0, 2, last],
            )
            .expect("push");
    }
    let (out, outcome) = build(&query("example.test", MX, Some(1232)), &answer, Some(512));
    assert!(!outcome.truncated);
    assert!(outcome.additional_dropped > 0);
    let header = parse_header(&out).expect("header");
    assert!(!header.tc);
    assert_eq!(header.ancount, 1);
    // The additional count holds the addresses that fit plus OPT.
    assert_eq!(
        usize::from(header.arcount),
        40 - outcome.additional_dropped + 1
    );
    assert!(out.len() <= 512);
    assert!(decode(&out).edns.is_some());
}

#[test]
fn the_extended_rcode_cookie_and_extended_error_go_into_opt() {
    let mut message = query("www.example.test", A, Some(1232));
    // EDNS version 1 and the DO bit.
    let opt_ttl = message.len() - 6;
    message[opt_ttl + 1] = 1;
    message[opt_ttl + 2] = 0x80;
    let mut answer = AnswerBuf::with_capacity(4, 1024);
    answer.rcode = 16;
    answer
        .set_cookie(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        .expect("cookie");
    answer.set_extended_error(15, "blocked").expect("ede");
    let (out, _) = build(&message, &answer, None);
    assert_eq!(parse_header(&out).expect("header").rcode, 0);
    let opt = read_record(&out, wire::questions_end(&out, 1).expect("question")).expect("opt");
    assert_eq!(opt.rtype, wire::TYPE_OPT);
    assert_eq!(
        opt.ttl >> 24,
        1,
        "BADVERS is 16: the upper eight bits are 1"
    );
    assert_ne!(opt.ttl & 0x8000, 0, "DO is echoed");
    let options: Vec<(u16, Vec<u8>)> = wire::options(opt.data(&out))
        .map(|(code, value)| (code, value.to_vec()))
        .collect();
    assert_eq!(options[0], (10, (1..=16).collect()));
    assert_eq!(options[1], (15, [&[0, 15][..], b"blocked"].concat()));
    let decoded = decode(&out);
    assert_eq!(u16::from(decoded.metadata.response_code), 16);
}

#[test]
fn edns_options_and_cookies_parse() {
    let codec = DomainCodec::new();
    let mut request = Request::default();
    let mut message = query("www.example.test", A, Some(1400));
    // A cookie option: client cookie and an 8-octet server cookie.
    let cookie: Vec<u8> = (1..=16).collect();
    let option = [&[0, 10, 0, 16][..], &cookie].concat();
    let rdlen = message.len() - 2;
    message[rdlen..].copy_from_slice(&u16::try_from(option.len()).expect("len").to_be_bytes());
    message.extend_from_slice(&option);
    codec.parse(&message, &mut request).expect("parse");
    let edns = request.edns.expect("edns");
    assert_eq!(edns.udp_size, 1400);
    let cookie = edns.cookie.expect("cookie");
    assert_eq!(cookie.client(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(cookie.server(), &[9, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(request.max_udp_len(), 1232);
    assert_eq!(request.qname.to_string(), "www.example.test");
    // A cookie of 9 octets is malformed (RFC 7873, section 5.2.2).
    let mut bad = query("www.example.test", A, Some(1400));
    let rdlen = bad.len() - 2;
    bad[rdlen..].copy_from_slice(&13u16.to_be_bytes());
    bad.extend_from_slice(&[0, 10, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(
        codec.parse(&bad, &mut request).err(),
        Some(CodecError::Edns)
    );
}

#[test]
fn a_tsig_record_parses_with_its_positions() {
    let codec = DomainCodec::new();
    let mut message = query("example.test", SOA, None);
    let unsigned = message.len();
    let tsig = TsigRecord {
        key: b"\x07xfr-key\x00",
        algorithm: b"\x0bHMAC-SHA256\x00",
        time_signed: 1_790_000_000,
        fudge: 300,
        mac: &[0xab; 32],
        original_id: 0x4242,
        error: 0,
        other: &[],
    };
    assert!(wire::append_tsig(&mut message, &tsig, MAX_MESSAGE_LEN));
    let mut request = Request::default();
    codec.parse(&message, &mut request).expect("parse");
    let parsed = request.tsig.clone().expect("tsig");
    assert_eq!(parsed.key.to_string(), "xfr-key");
    assert_eq!(parsed.algorithm.to_string(), "hmac-sha256");
    assert_eq!(
        (parsed.time_signed, parsed.fudge, parsed.original_id),
        (1_790_000_000, 300, 0x4242)
    );
    assert_eq!(parsed.mac(&message), &[0xab; 32]);
    assert_eq!(parsed.record_start, unsigned);
    // A TSIG record before another record is refused.
    let mut misplaced = message.clone();
    misplaced[11] = 2;
    misplaced.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        codec.parse(&misplaced, &mut request).err(),
        Some(CodecError::Tsig)
    );
}

#[test]
fn malformed_queries_are_refused() {
    let codec = DomainCodec::new();
    let mut request = Request::default();
    assert_eq!(
        codec.parse(&[0; 5], &mut request).err(),
        Some(CodecError::NotAQuery)
    );
    let mut response = query("example.test", A, None);
    response[2] |= 0x80;
    assert_eq!(
        codec.parse(&response, &mut request).err(),
        Some(CodecError::NotAQuery)
    );
    let mut two = query("example.test", A, None);
    two[5] = 2;
    assert_eq!(
        codec.parse(&two, &mut request).err(),
        Some(CodecError::QuestionCount)
    );
    let mut cut = query("example.test", A, None);
    cut.truncate(20);
    assert!(codec.parse(&cut, &mut request).is_err());
    // Two OPT records.
    let mut double = query("example.test", A, Some(1232));
    double[11] = 2;
    double.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        codec.parse(&double, &mut request).err(),
        Some(CodecError::Edns)
    );
    // An answer record that runs past the end.
    let mut record = query("example.test", A, None);
    record[7] = 1;
    record.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 9, 1]);
    assert_eq!(
        codec.parse(&record, &mut request).err(),
        Some(CodecError::Record)
    );
}

#[test]
fn the_answer_buffer_never_grows() {
    let mut answer = AnswerBuf::with_capacity(2, 16);
    answer
        .push(Section::Answer, Owner::Qname, TXT, 1, b"\x05hello")
        .expect("push");
    assert_eq!(
        answer.push(Section::Answer, Owner::Name(APEX), NS, 1, b"\x03ns1\x00"),
        Err(AnswerError::Full),
        "the arena is full"
    );
    answer
        .push(Section::Authority, Owner::Qname, NS, 1, b"\x00")
        .expect("push");
    assert_eq!(
        answer.push(Section::Additional, Owner::Qname, A, 1, &[192, 0, 2, 1]),
        Err(AnswerError::Full),
        "the record slots are full"
    );
    let mut ordered = AnswerBuf::with_capacity(4, 64);
    ordered
        .push(Section::Authority, Owner::Qname, NS, 1, b"\x00")
        .expect("push");
    assert_eq!(
        ordered.push(Section::Answer, Owner::Qname, A, 1, &[192, 0, 2, 1]),
        Err(AnswerError::OutOfOrder)
    );
    assert_eq!(ordered.set_cookie(&[0; 8]), Err(AnswerError::TooLong));
    let capacity = answer.records.capacity();
    answer.clear();
    assert_eq!(answer.records().count(), 0);
    assert_eq!(answer.records.capacity(), capacity);
}
