//! The differential test of the codec (ADR 0009, risk R38): a second implementation of
//! the `Codec` trait on `hickory-proto` (a dev-dependency, never shipped) parses the same
//! queries and builds the same answers, and the two must agree: the same `Request` from
//! every query, the same octets for every answer of the corpus. A change of `domain` that
//! moves the encoding shows up here.
//!
//! The corpus leaves out what the two crates do differently by design: hickory sets TC when
//! an additional record does not fit (Tenko drops it), and it writes EDNS options in its
//! own order; both are covered by the codec's own tests.

use std::net::Ipv4Addr;

use hickory_proto::{
    op::{Edns, Header, Metadata, Query, ResponseCode, emit_message_parts},
    rr::{DNSClass, Name, RData, Record, RecordType},
    serialize::binary::{BinDecodable, BinDecoder, BinEncoder, Restrict},
};
use tenko_core::dns::{DnsName, Rdata, RecordData, Rtype, SvcParam, TextBytes};
use tenko_dns::{
    AnswerBuf, Codec, CodecError, DomainCodec, Request,
    codec::{Edns as TenkoEdns, Owner, RecordView, Section},
    wire::{self, MAX_MESSAGE_LEN, SERVER_UDP_PAYLOAD},
};

/// A query as hickory parsed it.
struct HickoryQuery {
    metadata: Metadata,
    query: Query,
}

/// The codec on `hickory-proto`.
struct HickoryCodec;

fn bad<E>(error: CodecError) -> impl FnOnce(E) -> CodecError {
    move |_| error
}

impl Codec for HickoryCodec {
    type Query<'a> = HickoryQuery;

    fn parse(&self, message: &[u8], request: &mut Request) -> Result<HickoryQuery, CodecError> {
        let raw = wire::parse_header(message).ok_or(CodecError::NotAQuery)?;
        if raw.qr {
            return Err(CodecError::NotAQuery);
        }
        let mut decoder = BinDecoder::new(message);
        let header = Header::read(&mut decoder).map_err(bad(CodecError::Question))?;
        if header.counts.queries != 1 {
            return Err(CodecError::QuestionCount);
        }
        let query = Query::read(&mut decoder).map_err(bad(CodecError::Question))?;
        request.qname.clear();
        for label in query.name() {
            request
                .qname
                .push_label(label)
                .map_err(bad(CodecError::Question))?;
        }
        for _ in 0..u32::from(header.counts.answers) + u32::from(header.counts.authorities) {
            Record::<RData>::read(&mut decoder).map_err(bad(CodecError::Record))?;
        }
        request.edns = None;
        request.tsig = None;
        for _ in 0..header.counts.additionals {
            let record = Record::<RData>::read(&mut decoder).map_err(bad(CodecError::Record))?;
            if record.record_type() == RecordType::OPT {
                let edns = Edns::from(&record);
                request.edns = Some(TenkoEdns {
                    udp_size: edns.max_payload(),
                    version: edns.version(),
                    dnssec_ok: edns.flags().dnssec_ok,
                    cookie: None,
                });
            }
        }
        let metadata = header.metadata;
        request.id = metadata.id;
        request.opcode = u8::from(metadata.op_code);
        request.rd = metadata.recursion_desired;
        request.cd = metadata.checking_disabled;
        request.ad = metadata.authentic_data;
        request.qtype = u16::from(query.query_type());
        request.qclass = u16::from(query.query_class());
        Ok(HickoryQuery { metadata, query })
    }

    fn build(
        &self,
        query: &HickoryQuery,
        request: &Request,
        answer: &AnswerBuf,
        max_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<tenko_dns::codec::BuildOutcome, CodecError> {
        let mut metadata = Metadata::response_from_request(&query.metadata);
        metadata.authoritative = answer.authoritative;
        metadata.recursion_available = answer.recursion_available;
        metadata.authentic_data = answer.authenticated;
        metadata.response_code = ResponseCode::from(
            u8::try_from(answer.rcode >> 4).unwrap_or(u8::MAX),
            u8::try_from(answer.rcode & 0x0f).unwrap_or(0),
        );
        let convert = |record: RecordView<'_>| -> Result<Record, CodecError> {
            let name = match record.owner {
                Owner::Qname => query.query.name().clone(),
                Owner::Name(wire) => {
                    Name::read(&mut BinDecoder::new(wire)).map_err(bad(CodecError::Build))?
                }
            };
            let len = u16::try_from(record.rdata.len()).map_err(bad(CodecError::Build))?;
            let rdata = RData::read(
                &mut BinDecoder::new(record.rdata),
                RecordType::from(record.rtype),
                Restrict::new(len),
            )
            .map_err(bad(CodecError::Build))?;
            let mut converted = Record::from_rdata(name, record.ttl, rdata);
            converted.dns_class = DNSClass::from(record.class);
            Ok(converted)
        };
        let section = |which| {
            answer
                .section(which)
                .map(convert)
                .collect::<Result<Vec<_>, _>>()
        };
        let (answers, authorities, additionals) = (
            section(Section::Answer)?,
            section(Section::Authority)?,
            section(Section::Additional)?,
        );
        let edns = request.edns.map(|requested| {
            let mut edns = Edns::new();
            edns.set_max_payload(SERVER_UDP_PAYLOAD);
            edns.set_version(0);
            edns.set_dnssec_ok(requested.dnssec_ok);
            edns
        });
        let emit =
            |metadata: &Metadata, records: bool, out: &mut Vec<u8>| -> Result<Header, CodecError> {
                out.clear();
                let mut encoder = BinEncoder::new(out);
                encoder.set_max_size(u16::try_from(max_len).unwrap_or(u16::MAX));
                let empty: [Record; 0] = [];
                let pick = |records_of: &'_ [Record]| {
                    if records {
                        records_of.to_vec()
                    } else {
                        empty.to_vec()
                    }
                };
                emit_message_parts(
                    metadata,
                    &mut std::iter::once(&query.query),
                    &mut pick(&answers).iter(),
                    &mut pick(&authorities).iter(),
                    &mut pick(&additionals).iter(),
                    edns.as_ref(),
                    None,
                    &mut encoder,
                )
                .map_err(bad(CodecError::Build))
            };
        let header = emit(&metadata, true, out)?;
        let truncated = header.metadata.truncation;
        if truncated {
            metadata.truncation = true;
            emit(&metadata, false, out)?;
        }
        Ok(tenko_dns::codec::BuildOutcome {
            truncated,
            additional_dropped: 0,
        })
    }
}

fn wire_of(text: &str) -> Vec<u8> {
    DnsName::new(text).expect("name").to_wire()
}

fn rdata(data: &RecordData) -> Vec<u8> {
    Rdata::from_data(data).as_bytes().to_vec()
}

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn soa() -> Vec<u8> {
    rdata(&RecordData::Soa {
        mname: name("ns1.example.test"),
        rname: name("hostmaster.example.test"),
        serial: 2_026_101_701,
        refresh: 3600,
        retry: 900,
        expire: 1_209_600,
        minimum: 300,
    })
}

fn a(last: u8) -> Vec<u8> {
    rdata(&RecordData::A {
        address: Ipv4Addr::new(192, 0, 2, last),
    })
}

/// One case: a query, how the answer is built, and the size limit.
struct Case {
    label: &'static str,
    qname: &'static str,
    qtype: u16,
    edns: Option<u16>,
    max_len: Option<usize>,
    flags: fn(&mut Vec<u8>),
    answer: fn(&mut AnswerBuf),
}

fn no_flags(_: &mut Vec<u8>) {}

#[allow(clippy::too_many_lines, reason = "the corpus reads best as one list")]
fn corpus() -> Vec<Case> {
    vec![
        Case {
            label: "A with EDNS, mixed case",
            qname: "WWW.Example.TEST",
            qtype: 1,
            edns: Some(1232),
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                answer
                    .push(Section::Answer, Owner::Qname, 1, 300, &a(1))
                    .expect("push");
            },
        },
        Case {
            label: "an RRset of three A without EDNS",
            qname: "www.example.test",
            qtype: 1,
            edns: None,
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                for last in 1..=3 {
                    answer
                        .push(Section::Answer, Owner::Qname, 1, 300, &a(last))
                        .expect("push");
                }
            },
        },
        Case {
            label: "AAAA",
            qname: "www.example.test",
            qtype: 28,
            edns: Some(4096),
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                let data = rdata(&RecordData::Aaaa {
                    address: "2001:db8::1".parse().expect("ip"),
                });
                answer
                    .push(Section::Answer, Owner::Qname, 28, 300, &data)
                    .expect("push");
            },
        },
        Case {
            label: "NXDOMAIN with the SOA",
            qname: "nohost.example.test",
            qtype: 1,
            edns: Some(1232),
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                answer.rcode = 3;
                answer
                    .push(
                        Section::Authority,
                        Owner::Name(&wire_of("example.test")),
                        6,
                        300,
                        &soa(),
                    )
                    .expect("push");
            },
        },
        Case {
            label: "NODATA with the SOA",
            qname: "www.example.test",
            qtype: 15,
            edns: None,
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                answer
                    .push(
                        Section::Authority,
                        Owner::Name(&wire_of("example.test")),
                        6,
                        300,
                        &soa(),
                    )
                    .expect("push");
            },
        },
        Case {
            label: "the apex SOA",
            qname: "example.test",
            qtype: 6,
            edns: None,
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                answer
                    .push(Section::Answer, Owner::Qname, 6, 3600, &soa())
                    .expect("push");
            },
        },
        Case {
            label: "a referral with glue",
            qname: "host.child.example.test",
            qtype: 1,
            edns: Some(1232),
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                let ns = rdata(&RecordData::Ns {
                    host: name("ns.child.example.test"),
                });
                answer
                    .push(
                        Section::Authority,
                        Owner::Name(&wire_of("child.example.test")),
                        2,
                        3600,
                        &ns,
                    )
                    .expect("push");
                answer
                    .push(
                        Section::Additional,
                        Owner::Name(&wire_of("ns.child.example.test")),
                        1,
                        3600,
                        &a(54),
                    )
                    .expect("push");
            },
        },
        Case {
            label: "a CNAME and its target",
            qname: "alias.example.test",
            qtype: 1,
            edns: None,
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                let cname = rdata(&RecordData::Cname {
                    target: name("www.example.test"),
                });
                answer
                    .push(Section::Answer, Owner::Qname, 5, 300, &cname)
                    .expect("push");
                answer
                    .push(
                        Section::Answer,
                        Owner::Name(&wire_of("www.example.test")),
                        1,
                        300,
                        &a(1),
                    )
                    .expect("push");
            },
        },
        Case {
            label: "MX with the exchange's address",
            qname: "example.test",
            qtype: 15,
            edns: Some(1232),
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                let mx = rdata(&RecordData::Mx {
                    preference: 10,
                    exchange: name("mail.example.test"),
                });
                answer
                    .push(Section::Answer, Owner::Qname, 15, 300, &mx)
                    .expect("push");
                answer
                    .push(
                        Section::Additional,
                        Owner::Name(&wire_of("mail.example.test")),
                        1,
                        300,
                        &a(25),
                    )
                    .expect("push");
            },
        },
        Case {
            label: "TXT split at 255 octets",
            qname: "long.example.test",
            qtype: 16,
            edns: Some(1232),
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                let txt = rdata(&RecordData::txt(&"v=DKIM1; k=rsa; p=".repeat(20)));
                answer
                    .push(Section::Answer, Owner::Qname, 16, 300, &txt)
                    .expect("push");
            },
        },
        Case {
            label: "PTR",
            qname: "10.2.0.192.in-addr.arpa",
            qtype: 12,
            edns: None,
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                let ptr = rdata(&RecordData::Ptr {
                    target: name("host.example.test"),
                });
                answer
                    .push(Section::Answer, Owner::Qname, 12, 300, &ptr)
                    .expect("push");
            },
        },
        Case {
            label: "SRV, CAA, TLSA, DS and an unknown type",
            qname: "_ldap._tcp.example.test",
            qtype: 33,
            edns: Some(1232),
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                let srv = rdata(&RecordData::Srv {
                    priority: 0,
                    weight: 100,
                    port: 389,
                    target: name("dc1.example.test"),
                });
                answer
                    .push(Section::Answer, Owner::Qname, 33, 600, &srv)
                    .expect("push");
                let caa = rdata(&RecordData::Caa {
                    flags: 0,
                    tag: "issue".to_owned(),
                    value: TextBytes::from_text("ca.example.net"),
                });
                answer
                    .push(Section::Answer, Owner::Qname, 257, 600, &caa)
                    .expect("push");
                let tlsa = rdata(&RecordData::Tlsa {
                    usage: 3,
                    selector: 1,
                    matching_type: 1,
                    data: vec![0x5a; 32].into(),
                });
                answer
                    .push(Section::Answer, Owner::Qname, 52, 600, &tlsa)
                    .expect("push");
                let ds = rdata(&RecordData::Ds {
                    key_tag: 4242,
                    algorithm: 13,
                    digest_type: 2,
                    digest: vec![0x11; 32].into(),
                });
                answer
                    .push(Section::Answer, Owner::Qname, 43, 600, &ds)
                    .expect("push");
                answer
                    .push(Section::Answer, Owner::Qname, 65280, 600, &[1, 2, 3])
                    .expect("push");
            },
        },
        Case {
            label: "HTTPS with parameters",
            qname: "example.test",
            qtype: 65,
            edns: Some(1232),
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                let https = rdata(&RecordData::Https {
                    priority: 1,
                    target: tenko_core::dns::DnsName::root(),
                    params: vec![
                        SvcParam {
                            key: 1,
                            value: b"\x02h2\x02h3".to_vec().into(),
                        },
                        SvcParam {
                            key: 3,
                            value: vec![0x01, 0xbb].into(),
                        },
                    ],
                });
                answer
                    .push(Section::Answer, Owner::Qname, Rtype::HTTPS.0, 300, &https)
                    .expect("push");
            },
        },
        Case {
            label: "BADVERS",
            qname: "www.example.test",
            qtype: 1,
            edns: Some(1232),
            max_len: None,
            flags: |message| {
                let version = message.len() - 5;
                message[version] = 1;
            },
            answer: |answer| answer.rcode = 16,
        },
        Case {
            label: "REFUSED, recursion desired",
            qname: "www.example.org",
            qtype: 1,
            edns: None,
            max_len: None,
            flags: |message| message[2] |= 0x01,
            answer: |answer| answer.rcode = 5,
        },
        Case {
            label: "RA and AD set, DO echoed",
            qname: "www.example.test",
            qtype: 1,
            edns: Some(1232),
            max_len: None,
            flags: |message| {
                let flags = message.len() - 4;
                message[flags] = 0x80;
                message[2] |= 0x01;
            },
            answer: |answer| {
                answer.recursion_available = true;
                answer.authenticated = true;
                answer
                    .push(Section::Answer, Owner::Qname, 1, 60, &a(1))
                    .expect("push");
            },
        },
        Case {
            label: "truncation over UDP",
            qname: "many.example.test",
            qtype: 1,
            edns: None,
            max_len: None,
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                for last in 0..60 {
                    answer
                        .push(Section::Answer, Owner::Qname, 1, 300, &a(last))
                        .expect("push");
                }
            },
        },
        Case {
            label: "the same over TCP",
            qname: "many.example.test",
            qtype: 1,
            edns: None,
            max_len: Some(MAX_MESSAGE_LEN),
            flags: no_flags,
            answer: |answer| {
                answer.authoritative = true;
                for last in 0..60 {
                    answer
                        .push(Section::Answer, Owner::Qname, 1, 300, &a(last))
                        .expect("push");
                }
            },
        },
    ]
}

fn run<C: Codec>(codec: &C, message: &[u8], case: &Case) -> (Request, Vec<u8>, bool) {
    let mut request = Request::default();
    let query = codec.parse(message, &mut request).expect("parse");
    let mut answer = AnswerBuf::with_capacity(128, 32_768);
    (case.answer)(&mut answer);
    let limit = case.max_len.unwrap_or_else(|| request.max_udp_len());
    let mut out = Vec::with_capacity(MAX_MESSAGE_LEN);
    let outcome = codec
        .build(&query, &request, &answer, limit, &mut out)
        .expect("build");
    (request, out, outcome.truncated)
}

#[test]
fn both_codecs_agree_on_every_case_of_the_corpus() {
    let mut failures = Vec::new();
    for case in corpus() {
        let mut message = Vec::new();
        wire::write_query(&mut message, 0x5a5a, case.qname, case.qtype, case.edns);
        (case.flags)(&mut message);
        let (domain_request, domain_out, domain_tc) = run(&DomainCodec::new(), &message, &case);
        let (hickory_request, hickory_out, hickory_tc) = run(&HickoryCodec, &message, &case);
        if domain_request != hickory_request {
            failures.push(format!(
                "{}: requests differ\n  domain  {domain_request:?}\n  hickory {hickory_request:?}",
                case.label
            ));
        }
        if domain_tc != hickory_tc || domain_out != hickory_out {
            failures.push(format!(
                "{}: answers differ (tc {domain_tc} / {hickory_tc})\n  domain  {domain_out:02x?}\n  hickory {hickory_out:02x?}",
                case.label
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn malformed_queries_fail_in_both() {
    let mut message = Vec::new();
    wire::write_query(&mut message, 1, "example.test", 1, Some(1232));
    for cut in [5, 13, 20, message.len() - 3] {
        let mut request = Request::default();
        let short = &message[..cut];
        assert!(
            DomainCodec::new().parse(short, &mut request).is_err(),
            "domain accepted {cut}"
        );
        assert!(
            HickoryCodec.parse(short, &mut request).is_err(),
            "hickory accepted {cut}"
        );
    }
}
