//! The reading of authority answers: `parse` against hand-built messages (with compressed
//! names in the data of the types RFC 3597 lists), `classify` against the answers an
//! authority gives (RFC 2181 section 5.4, RFC 9471, RFC 6672), `compose` read back through
//! `parse`, and `substitute`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

const IN: u16 = 1;
const TXT: u16 = 16;
const MX: u16 = 15;
const DS_TYPE: u16 = types::DS;
const OPT: u16 = TYPE_OPT;
const ZONE: &str = "example.test";
const QNAME: &str = "www.example.test";

// ---------------------------------------------------------------------------------------
// Building messages

/// A name in uncompressed wire form, in the case given; `""` is the root.
fn wire_name(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if !text.is_empty() {
        for label in text.split('.') {
            out.push(u8::try_from(label.len()).expect("a label of at most 63 octets"));
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    out
}

/// A compression pointer to the label `skip` of the question name (the question starts at
/// octet 12 of the message).
fn pointer_into(qname: &str, skip: usize) -> [u8; 2] {
    let offset = 12
        + qname
            .split('.')
            .take(skip)
            .map(|label| label.len() + 1)
            .sum::<usize>();
    let value = 0xc000 | u16::try_from(offset).expect("an offset below 16,384");
    value.to_be_bytes()
}

/// Labels followed by a pointer to the suffix of the question name from label `skip`.
fn compressed(labels: &[&str], qname: &str, skip: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for label in labels {
        out.push(u8::try_from(label.len()).expect("a short label"));
        out.extend_from_slice(label.as_bytes());
    }
    out.extend_from_slice(&pointer_into(qname, skip));
    out
}

/// A record as written into a message, and the `Rr` the parser should make of it.
#[derive(Clone)]
struct Rec {
    owner: Vec<u8>,
    plain_owner: Vec<u8>,
    rtype: u16,
    ttl: u32,
    data: Vec<u8>,
    plain_data: Vec<u8>,
}

impl Rec {
    fn new(owner: &str, rtype: u16, ttl: u32, data: Vec<u8>) -> Self {
        Self {
            owner: wire_name(owner),
            plain_owner: wire_name(&owner.to_ascii_lowercase()),
            rtype,
            ttl,
            plain_data: data.clone(),
            data,
        }
    }

    /// The owner written as a pointer to the question name.
    fn pointing_at_the_question(mut self) -> Self {
        self.owner = vec![0xc0, 0x0c];
        self
    }

    /// The data as written (compressed); the `Rr` expected keeps the plain data.
    fn written(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    fn rr(&self) -> Rr {
        Rr {
            owner: self.plain_owner.clone(),
            rtype: self.rtype,
            class: IN,
            ttl: self.ttl,
            data: self.plain_data.clone(),
        }
    }
}

fn a_rec(owner: &str, ttl: u32, address: [u8; 4]) -> Rec {
    Rec::new(owner, A, ttl, address.to_vec())
}

fn aaaa_rec(owner: &str, ttl: u32, address: Ipv6Addr) -> Rec {
    Rec::new(owner, AAAA, ttl, address.octets().to_vec())
}

fn ns_rec(owner: &str, ttl: u32, host: &str) -> Rec {
    Rec::new(owner, NS, ttl, wire_name(host))
}

fn cname_rec(owner: &str, ttl: u32, target: &str) -> Rec {
    Rec::new(owner, CNAME, ttl, wire_name(target))
}

fn dname_rec(owner: &str, ttl: u32, target: &str) -> Rec {
    Rec::new(owner, DNAME, ttl, wire_name(target))
}

fn soa_rec(owner: &str, ttl: u32) -> Rec {
    let mut data = wire_name("ns.example.test");
    data.extend_from_slice(&wire_name("hostmaster.example.test"));
    data.extend_from_slice(&[
        0, 0, 0, 1, 0, 0, 0x0e, 0x10, 0, 0, 0x02, 0x58, 0, 0x09, 0x3a, 0x80, 0, 0, 0, 60,
    ]);
    Rec::new(owner, SOA, ttl, data)
}

fn ds_rec(owner: &str, ttl: u32) -> Rec {
    Rec::new(
        owner,
        DS_TYPE,
        ttl,
        vec![0x30, 0x39, 13, 2, 0xaa, 0xbb, 0xcc, 0xdd],
    )
}

fn rrsig_rec(owner: &str, ttl: u32, covered: u16) -> Rec {
    let mut data = covered.to_be_bytes().to_vec();
    data.extend_from_slice(&[13, 2, 0, 0, 1, 0x2c, 0, 0, 0, 0, 0, 0, 0, 0]);
    Rec::new(owner, RRSIG, ttl, data)
}

fn nsec_rec(owner: &str, ttl: u32, next: &str) -> Rec {
    let mut data = wire_name(next);
    data.extend_from_slice(&[0, 1, 0x40]);
    Rec::new(owner, NSEC, ttl, data)
}

fn nsec3_rec(owner: &str, ttl: u32) -> Rec {
    Rec::new(
        owner,
        NSEC3,
        ttl,
        vec![1, 0, 0, 0, 0, 4, 1, 2, 3, 4, 0, 0, 1, 0x40],
    )
}

fn opt_rec() -> Rec {
    Rec::new("", OPT, 0, Vec::new())
}

/// An EDNS option.
fn option(code: u16, value: &[u8]) -> Vec<u8> {
    let mut out = code.to_be_bytes().to_vec();
    out.extend_from_slice(
        &u16::try_from(value.len())
            .expect("a short value")
            .to_be_bytes(),
    );
    out.extend_from_slice(value);
    out
}

#[derive(Clone, Default)]
struct OptSpec {
    udp: u16,
    ext: u8,
    dnssec_ok: bool,
    options: Vec<u8>,
}

/// A message to encode: a response with one question.
#[derive(Clone)]
struct Msg {
    id: u16,
    aa: bool,
    tc: bool,
    rcode: u8,
    qname: String,
    qtype: u16,
    answer: Vec<Rec>,
    authority: Vec<Rec>,
    additional: Vec<Rec>,
    opt: Option<OptSpec>,
}

fn octets(data: &[u8]) -> u16 {
    u16::try_from(data.len()).expect("a short record")
}

impl Msg {
    fn new(qname: &str, qtype: u16) -> Self {
        Self {
            id: 0x4242,
            aa: false,
            tc: false,
            rcode: 0,
            qname: qname.to_owned(),
            qtype,
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            opt: None,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let count = |records: &[Rec]| u16::try_from(records.len()).expect("a few records");
        let mut out = Vec::new();
        out.extend_from_slice(&self.id.to_be_bytes());
        out.push(0x80 | if self.aa { 0x04 } else { 0 } | if self.tc { 0x02 } else { 0 });
        out.push(self.rcode & 0x0f);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&count(&self.answer).to_be_bytes());
        out.extend_from_slice(&count(&self.authority).to_be_bytes());
        let additional = count(&self.additional) + u16::from(self.opt.is_some());
        out.extend_from_slice(&additional.to_be_bytes());
        out.extend_from_slice(&wire_name(&self.qname));
        out.extend_from_slice(&self.qtype.to_be_bytes());
        out.extend_from_slice(&IN.to_be_bytes());
        for rec in self
            .answer
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
        {
            out.extend_from_slice(&rec.owner);
            out.extend_from_slice(&rec.rtype.to_be_bytes());
            out.extend_from_slice(&IN.to_be_bytes());
            out.extend_from_slice(&rec.ttl.to_be_bytes());
            out.extend_from_slice(&octets(&rec.data).to_be_bytes());
            out.extend_from_slice(&rec.data);
        }
        if let Some(opt) = &self.opt {
            out.push(0);
            out.extend_from_slice(&OPT.to_be_bytes());
            out.extend_from_slice(&opt.udp.to_be_bytes());
            let ttl = (u32::from(opt.ext) << 24) | if opt.dnssec_ok { 0x8000 } else { 0 };
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&octets(&opt.options).to_be_bytes());
            out.extend_from_slice(&opt.options);
        }
        out
    }

    fn parsed(&self) -> Parsed {
        parse(&self.encode()).expect("the message parses")
    }
}

fn classify_as(msg: &Msg, zone: &str, qname: &str, qtype: u16) -> Step {
    classify(&msg.parsed(), &wire_name(zone), &wire_name(qname), qtype)
}

/// The step for the usual question: `www.example.test` A, asked as the authority of
/// `example.test`.
fn step(msg: &Msg) -> Step {
    classify_as(msg, ZONE, QNAME, A)
}

fn authoritative(answer: Vec<Rec>) -> Msg {
    Msg {
        aa: true,
        answer,
        ..Msg::new(QNAME, A)
    }
}

fn rrs(records: &[&Rec]) -> Vec<Rr> {
    records.iter().map(|rec| rec.rr()).collect()
}

fn is_lame(step: &Step) -> bool {
    matches!(step, Step::Lame(_))
}

// ---------------------------------------------------------------------------------------
// parse

#[test]
fn parse_reads_the_header_the_question_and_the_three_sections() {
    let msg = Msg {
        id: 0xbeef,
        aa: true,
        tc: true,
        rcode: 3,
        answer: vec![a_rec(QNAME, 300, [192, 0, 2, 1])],
        authority: vec![soa_rec(ZONE, 60)],
        additional: vec![a_rec("ns.example.test", 90, [192, 0, 2, 53])],
        ..Msg::new("WWW.Example.TEST", A)
    };
    let parsed = msg.parsed();
    assert_eq!(parsed.id, 0xbeef);
    assert!(parsed.aa && parsed.tc, "AA and TC are read");
    assert_eq!(parsed.rcode, 3);
    assert_eq!(
        parsed.qname,
        wire_name(QNAME),
        "the question name is lowercased"
    );
    assert_eq!(parsed.qtype, A);
    assert_eq!(parsed.answer, rrs(&[&msg.answer[0]]));
    assert_eq!(parsed.authority, rrs(&[&msg.authority[0]]));
    assert_eq!(parsed.additional, rrs(&[&msg.additional[0]]));
    assert_eq!(parsed.opt, None);
}

#[test]
fn parse_lowercases_owners_and_decompresses_the_names_in_the_data() {
    // The names of NS, CNAME, MX and SOA data point into the question name, as an
    // authority compresses them (RFC 3597 section 4 lists these types).
    let cname = cname_rec(QNAME, 300, "cdn.example.test")
        .pointing_at_the_question()
        .written(compressed(&["cdn"], QNAME, 1));
    let ns =
        ns_rec("EXAMPLE.Test", 400, "ns1.example.test").written(compressed(&["ns1"], QNAME, 1));
    let mut mx_plain = vec![0, 10];
    mx_plain.extend_from_slice(&wire_name("mail.example.test"));
    let mut mx_written = vec![0, 10];
    mx_written.extend_from_slice(&compressed(&["mail"], QNAME, 1));
    let mx = Rec::new(ZONE, MX, 500, mx_plain).written(mx_written);
    let soa = soa_rec(ZONE, 600);
    let mut soa_written = compressed(&["ns"], QNAME, 1);
    soa_written.extend_from_slice(&compressed(&["hostmaster"], QNAME, 1));
    soa_written.extend_from_slice(&soa.data[soa.data.len() - 20..]);
    let soa = soa.written(soa_written);
    // Data of a type without names is not touched, even when it looks like a pointer.
    let txt = Rec::new(ZONE, TXT, 700, vec![0xc0, 0x0c, 1, 2]);
    let msg = Msg {
        answer: vec![cname.clone(), ns.clone()],
        authority: vec![soa.clone(), txt.clone()],
        additional: vec![mx.clone()],
        ..Msg::new(QNAME, A)
    };
    let encoded = msg.encode();
    assert!(
        encoded.windows(2).any(|pair| pair == [0xc0, 0x10]),
        "the message really carries compression pointers"
    );
    let parsed = parse(&encoded).expect("the message parses");
    assert_eq!(parsed.answer, rrs(&[&cname, &ns]));
    assert_eq!(
        parsed.answer[0].owner,
        wire_name(QNAME),
        "an owner given as a pointer"
    );
    assert_eq!(
        parsed.answer[1].owner,
        wire_name(ZONE),
        "an owner in mixed case"
    );
    assert_eq!(parsed.authority, rrs(&[&soa, &txt]));
    assert_eq!(parsed.additional, rrs(&[&mx]));
    assert_eq!(
        parsed.answer[0].data,
        wire_name("cdn.example.test"),
        "the CNAME target is whole"
    );
    assert_eq!(
        parsed.authority[0].data.len(),
        17 + 25 + 20,
        "the SOA is whole"
    );
}

#[test]
fn the_record_helpers_read_targets_addresses_and_covered_types() {
    let v6: Ipv6Addr = "2001:db8::7".parse().expect("address");
    let parsed = Msg {
        answer: vec![
            cname_rec(QNAME, 300, "target.example.test"),
            a_rec(QNAME, 1, [192, 0, 2, 7]),
            aaaa_rec(QNAME, 1, v6),
            rrsig_rec(QNAME, 1, A),
        ],
        ..Msg::new(QNAME, A)
    }
    .parsed();
    let [cname, a, aaaa, sig] = &parsed.answer[..] else {
        panic!("four records expected");
    };
    assert_eq!(cname.target(), Some(wire_name("target.example.test")));
    assert_eq!(a.target(), None, "an A record has no target");
    assert_eq!(a.address(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))));
    assert_eq!(aaaa.address(), Some(IpAddr::V6(v6)));
    assert_eq!(cname.address(), None);
    assert_eq!(sig.covered(), Some(A));
    assert_eq!(a.covered(), None);
    assert!(sig.of_type(A) && a.of_type(A) && !a.of_type(AAAA));
    let mut written = Vec::new();
    a.write(&mut written);
    let record = wire::read_record(&written, 0).expect("the record reads back");
    assert_eq!((record.rtype, record.class, record.ttl), (A, IN, 1));
    assert_eq!(record.data(&written), &[192, 0, 2, 7]);
}

#[test]
fn parse_refuses_a_message_without_exactly_one_question() {
    let encoded = Msg::new(QNAME, A).encode();
    for count in [0u16, 2] {
        let mut changed = encoded.clone();
        changed[4..6].copy_from_slice(&count.to_be_bytes());
        assert_eq!(parse(&changed), None, "{count} questions");
    }
    assert!(parse(&encoded).is_some(), "the unchanged message parses");
}

#[test]
fn parse_refuses_an_opt_record_outside_the_additional_section_or_not_owned_by_the_root() {
    let cases = [
        (
            "the answer section",
            Msg {
                answer: vec![opt_rec()],
                ..Msg::new(QNAME, A)
            },
        ),
        (
            "the authority section",
            Msg {
                authority: vec![opt_rec()],
                ..Msg::new(QNAME, A)
            },
        ),
        (
            "an owner that is not the root",
            Msg {
                additional: vec![Rec::new(ZONE, OPT, 0, Vec::new())],
                ..Msg::new(QNAME, A)
            },
        ),
    ];
    for (what, msg) in cases {
        assert_eq!(parse(&msg.encode()), None, "an OPT record in {what}");
    }
    let one = Msg {
        additional: vec![opt_rec()],
        ..Msg::new(QNAME, A)
    };
    let parsed = parse(&one.encode()).expect("one OPT record in the additional section");
    assert!(parsed.opt.is_some() && parsed.additional.is_empty());
}

#[test]
fn parse_refuses_two_opt_records() {
    let two_in_the_section = Msg {
        additional: vec![opt_rec(), opt_rec()],
        ..Msg::new(QNAME, A)
    };
    assert_eq!(parse(&two_in_the_section.encode()), None);
    let one_more_after_the_spec = Msg {
        additional: vec![opt_rec()],
        opt: Some(OptSpec::default()),
        ..Msg::new(QNAME, A)
    };
    assert_eq!(parse(&one_more_after_the_spec.encode()), None);
}

#[test]
fn parse_reads_at_most_max_records_records() {
    let record = a_rec(QNAME, 1, [192, 0, 2, 1]).pointing_at_the_question();
    let at_the_bound = Msg {
        answer: vec![record.clone(); MAX_RECORDS],
        ..Msg::new(QNAME, A)
    };
    let parsed = parse(&at_the_bound.encode()).expect("MAX_RECORDS records parse");
    assert_eq!(parsed.answer.len(), MAX_RECORDS);
    let over = Msg {
        answer: vec![record; MAX_RECORDS + 1],
        ..Msg::new(QNAME, A)
    };
    assert_eq!(parse(&over.encode()), None, "one more record is refused");
    let one = a_rec(QNAME, 1, [192, 0, 2, 1]);
    let spread = Msg {
        answer: vec![one.clone(); 200],
        authority: vec![one.clone(); 200],
        additional: vec![one; 112],
        opt: Some(OptSpec::default()),
        ..Msg::new(QNAME, A)
    };
    assert_eq!(
        parse(&spread.encode()),
        None,
        "the bound is over all three sections, the OPT record included"
    );
}

#[test]
fn parse_refuses_every_truncation_of_a_message() {
    let msg = Msg {
        aa: true,
        answer: vec![a_rec(QNAME, 300, [192, 0, 2, 1])],
        authority: vec![ns_rec(ZONE, 300, "ns1.example.test"), soa_rec(ZONE, 60)],
        additional: vec![a_rec("ns1.example.test", 300, [192, 0, 2, 53])],
        opt: Some(OptSpec {
            udp: 1232,
            options: option(wire::OPTION_COOKIE, &[7; 16]),
            ..OptSpec::default()
        }),
        ..Msg::new(QNAME, A)
    };
    let encoded = msg.encode();
    assert!(parse(&encoded).is_some());
    for cut in 0..encoded.len() {
        assert_eq!(
            parse(&encoded[..cut]),
            None,
            "cut at {cut} of {}",
            encoded.len()
        );
    }
}

#[test]
fn parse_refuses_data_that_does_not_fit_its_type() {
    let soa_short = [wire_name("a.test"), wire_name("b.test"), vec![0; 19]].concat();
    let cname_long = [wire_name("a.example.test"), vec![9]].concat();
    let cases = [
        (
            "a CNAME with octets after the name",
            Rec::new(QNAME, CNAME, 1, cname_long),
        ),
        (
            "an NS name pointing forward",
            Rec::new(QNAME, NS, 1, vec![0xc0, 0xff]),
        ),
        ("an MX without a name", Rec::new(QNAME, MX, 1, vec![0, 10])),
        ("an MX of one octet", Rec::new(QNAME, MX, 1, vec![0])),
        (
            "an SOA whose fixed part is short",
            Rec::new(QNAME, SOA, 1, soa_short),
        ),
        (
            "a name whose label runs past the data",
            Rec::new(QNAME, CNAME, 1, vec![5, b'a', b'b', 0]),
        ),
    ];
    for (what, record) in cases {
        let msg = Msg {
            answer: vec![record],
            ..Msg::new(QNAME, A)
        };
        assert_eq!(parse(&msg.encode()), None, "{what}");
    }
}

#[test]
fn parse_adds_the_opt_records_upper_bits_to_the_rcode() {
    let badcookie = Msg {
        rcode: 7,
        opt: Some(OptSpec {
            udp: 1232,
            ext: 1,
            ..OptSpec::default()
        }),
        ..Msg::new(QNAME, A)
    };
    assert_eq!(badcookie.parsed().rcode, 23, "BADCOOKIE is 1 << 4 | 7");
    let plain = Msg {
        rcode: 7,
        ..Msg::new(QNAME, A)
    };
    assert_eq!(
        plain.parsed().rcode,
        7,
        "without an OPT record the header's bits stand"
    );
    let nxdomain = Msg {
        rcode: 3,
        opt: Some(OptSpec::default()),
        ..Msg::new(QNAME, A)
    };
    assert_eq!(nxdomain.parsed().rcode, 3);
}

fn opt_of_options(options: Vec<u8>) -> Opt {
    Msg {
        opt: Some(OptSpec {
            udp: 1232,
            options,
            ..OptSpec::default()
        }),
        ..Msg::new(QNAME, A)
    }
    .parsed()
    .opt
    .expect("an OPT record")
}

#[test]
fn parse_reads_the_size_and_the_do_bit_of_the_opt_record() {
    let with = Msg {
        opt: Some(OptSpec {
            udp: 1232,
            dnssec_ok: true,
            ..OptSpec::default()
        }),
        ..Msg::new(QNAME, A)
    }
    .parsed()
    .opt
    .expect("an OPT record");
    assert_eq!(with.udp_size, 1232);
    assert!(with.dnssec_ok);
    assert_eq!(with.cookie, None);
    assert!(!with.bad_cookie_option);
    let without = Msg {
        opt: Some(OptSpec {
            udp: 512,
            ..OptSpec::default()
        }),
        ..Msg::new(QNAME, A)
    }
    .parsed()
    .opt
    .expect("an OPT record");
    assert!(!without.dnssec_ok);
    assert_eq!(without.udp_size, 512);
}

#[test]
fn parse_reads_the_cookie_option_into_the_client_and_the_server_cookie() {
    let client = [1, 2, 3, 4, 5, 6, 7, 8];
    for server_len in [0usize, 8, 16, 32] {
        let server: Vec<u8> = (0..server_len)
            .map(|n| u8::try_from(n + 100).expect("an octet"))
            .collect();
        let mut value = client.to_vec();
        value.extend_from_slice(&server);
        let opt = opt_of_options(option(wire::OPTION_COOKIE, &value));
        assert!(
            !opt.bad_cookie_option,
            "a server cookie of {server_len} octets is fine"
        );
        let expected = (server_len > 0).then(|| ServerCookie::new(&server).expect("a cookie"));
        assert_eq!(
            opt.cookie,
            Some((client, expected)),
            "a server cookie of {server_len} octets"
        );
    }
}

#[test]
fn parse_flags_a_malformed_cookie_option() {
    // 0 and 7: shorter than a client cookie; 9 to 15: a server cookie under 8 octets;
    // 41: a server cookie over 32.
    for len in [0usize, 7, 9, 15, 41] {
        let opt = opt_of_options(option(wire::OPTION_COOKIE, &vec![9; len]));
        assert!(
            opt.bad_cookie_option,
            "a cookie option of {len} octets is malformed"
        );
        assert_eq!(opt.cookie, None, "{len} octets: no cookie is taken");
    }
    // An option that claims more octets than the record holds.
    let mut cut = option(wire::OPTION_COOKIE, &[9; 16]);
    cut.truncate(7);
    let opt = opt_of_options(cut);
    assert!(opt.bad_cookie_option && opt.cookie.is_none());
}

#[test]
fn parse_ignores_options_that_are_not_cookies() {
    let mut options = option(wire::OPTION_EXTENDED_ERROR, &[0, 22, b'x']);
    options.extend_from_slice(&option(wire::OPTION_COOKIE, &[3; 8]));
    let opt = opt_of_options(options);
    assert_eq!(opt.cookie, Some(([3; 8], None)));
    assert!(!opt.bad_cookie_option);
    let opt = opt_of_options(option(wire::OPTION_EXTENDED_ERROR, &[0, 22]));
    assert_eq!(opt.cookie, None);
    assert!(!opt.bad_cookie_option);
}

// ---------------------------------------------------------------------------------------
// classify: answers and aliases

#[test]
fn an_authoritative_answer_keeps_the_rrset_and_its_signature() {
    let a = a_rec(QNAME, 300, [192, 0, 2, 1]);
    let sig = rrsig_rec(QNAME, 300, A);
    let elsewhere = a_rec("other.example.test", 300, [192, 0, 2, 9]);
    let other_type = Rec::new(QNAME, TXT, 300, vec![1, b'x']);
    let msg = authoritative(vec![a.clone(), sig.clone(), elsewhere, other_type]);
    assert_eq!(
        step(&msg),
        Step::Answer {
            records: rrs(&[&a, &sig])
        },
        "only the RRset asked and its signature"
    );
}

#[test]
fn an_answer_without_aa_is_lame() {
    let msg = Msg {
        answer: vec![a_rec(QNAME, 300, [192, 0, 2, 1])],
        ..Msg::new(QNAME, A)
    };
    assert_eq!(
        step(&msg),
        Step::Lame("a non-authoritative answer"),
        "a recursive server's copy is not an authority's answer"
    );
}

#[test]
fn a_cname_chain_within_the_zone_ends_in_the_answer() {
    let first = cname_rec(QNAME, 100, "a.example.test");
    let first_sig = rrsig_rec(QNAME, 100, CNAME);
    let second = cname_rec("a.example.test", 200, "b.example.test");
    let end = a_rec("b.example.test", 300, [192, 0, 2, 2]);
    let end_sig = rrsig_rec("b.example.test", 300, A);
    // The records come in an order other than the chain's.
    let msg = authoritative(vec![
        end.clone(),
        second.clone(),
        end_sig.clone(),
        first.clone(),
        first_sig.clone(),
    ]);
    assert_eq!(
        step(&msg),
        Step::Answer {
            records: rrs(&[&first, &first_sig, &second, &end, &end_sig])
        },
        "the CNAMEs in chain order, then the RRset asked"
    );
}

#[test]
fn a_cname_asked_for_is_the_answer() {
    let cname = cname_rec(QNAME, 100, "a.example.test");
    let msg = Msg {
        aa: true,
        answer: vec![cname.clone()],
        ..Msg::new(QNAME, CNAME)
    };
    assert_eq!(
        classify_as(&msg, ZONE, QNAME, CNAME),
        Step::Answer {
            records: rrs(&[&cname])
        }
    );
}

#[test]
fn a_cname_to_a_target_outside_the_zone_is_an_alias_to_follow() {
    let cname = cname_rec(QNAME, 100, "host.elsewhere.test");
    let sig = rrsig_rec(QNAME, 100, CNAME);
    // A record the server adds for the target is not its to give.
    let stray = a_rec("host.elsewhere.test", 300, [192, 0, 2, 66]);
    let msg = authoritative(vec![cname.clone(), sig.clone(), stray]);
    assert_eq!(
        step(&msg),
        Step::Alias {
            records: rrs(&[&cname, &sig]),
            target: wire_name("host.elsewhere.test"),
        }
    );
}

#[test]
fn a_cname_chain_that_ends_without_data_is_an_alias_unless_the_server_denies_it() {
    let cname = cname_rec(QNAME, 100, "a.example.test");
    let alias = authoritative(vec![cname.clone()]);
    assert_eq!(
        step(&alias),
        Step::Alias {
            records: rrs(&[&cname]),
            target: wire_name("a.example.test"),
        },
        "the target may have data the server did not add"
    );
    let soa = soa_rec(ZONE, 60);
    let nodata = Msg {
        authority: vec![soa.clone()],
        ..alias.clone()
    };
    assert_eq!(
        step(&nodata),
        Step::Negative {
            rcode: 0,
            records: rrs(&[&cname]),
            authority: rrs(&[&soa]),
        },
        "an SOA says the target has no data of the type"
    );
    let nxdomain = Msg {
        rcode: 3,
        ..alias.clone()
    };
    assert!(
        matches!(step(&nxdomain), Step::Negative { rcode: 3, .. }),
        "NXDOMAIN at the end of the chain"
    );
    let not_authoritative = Msg { aa: false, ..alias };
    assert!(is_lame(&step(&not_authoritative)), "no AA, no alias");
}

#[test]
fn a_cname_loop_inside_one_answer_stops_at_the_repeat() {
    let first = cname_rec(QNAME, 100, "a.example.test");
    let second = cname_rec("a.example.test", 100, QNAME);
    let msg = authoritative(vec![first.clone(), second.clone()]);
    assert_eq!(
        step(&msg),
        Step::Alias {
            records: rrs(&[&first, &second]),
            target: wire_name(QNAME),
        },
        "the caller sees the repeated name and gives up"
    );
    let selfish = authoritative(vec![cname_rec(QNAME, 100, QNAME)]);
    assert!(
        matches!(step(&selfish), Step::Alias { ref target, .. } if *target == wire_name(QNAME)),
        "a CNAME to itself"
    );
}

#[test]
fn a_dname_at_an_ancestor_gives_a_synthesised_cname_with_the_dnames_ttl() {
    let qname = "a.b.dn.example.test";
    let dname = dname_rec("dn.example.test", 111, "dest.example.test");
    let sig = rrsig_rec("dn.example.test", 111, DNAME);
    let end = a_rec("a.b.dest.example.test", 60, [192, 0, 2, 3]);
    let msg = Msg {
        aa: true,
        answer: vec![dname.clone(), sig.clone(), end.clone()],
        ..Msg::new(qname, A)
    };
    let synthesised = Rr {
        owner: wire_name(qname),
        rtype: CNAME,
        class: IN,
        ttl: 111,
        data: wire_name("a.b.dest.example.test"),
    };
    let mut records = rrs(&[&dname, &sig]);
    records.push(synthesised);
    records.push(end.rr());
    assert_eq!(classify_as(&msg, ZONE, qname, A), Step::Answer { records });
}

#[test]
fn a_dname_to_another_zone_is_an_alias_with_the_substituted_name() {
    let qname = "a.b.dn.example.test";
    let dname = dname_rec("dn.example.test", 111, "dest.elsewhere.test");
    let msg = Msg {
        aa: true,
        answer: vec![dname.clone()],
        ..Msg::new(qname, A)
    };
    let got = classify_as(&msg, ZONE, qname, A);
    let Step::Alias { records, target } = got else {
        panic!("an alias expected, got {got:?}");
    };
    assert_eq!(
        target,
        wire_name("a.b.dest.elsewhere.test"),
        "RFC 6672: prefix + target"
    );
    assert_eq!(records.len(), 2, "the DNAME and the CNAME made from it");
    assert_eq!(records[0], dname.rr());
    assert_eq!(
        (records[1].rtype, records[1].ttl, &records[1].owner),
        (CNAME, 111, &wire_name(qname))
    );
    assert_eq!(records[1].data, target);
}

#[test]
fn a_dname_at_the_name_asked_does_not_rewrite_the_name() {
    // The owner of a DNAME is not below it (RFC 6672 section 2.3): with no data at it the
    // answer is a negative one.
    let dname = dname_rec(QNAME, 111, "dest.example.test");
    let soa = soa_rec(ZONE, 60);
    let msg = Msg {
        aa: true,
        answer: vec![dname],
        authority: vec![soa.clone()],
        ..Msg::new(QNAME, A)
    };
    assert_eq!(
        step(&msg),
        Step::Negative {
            rcode: 0,
            records: Vec::new(),
            authority: rrs(&[&soa]),
        }
    );
}

#[test]
fn a_dname_whose_substitution_is_too_long_is_lame() {
    let long = |letter: char| letter.to_string().repeat(63);
    let qname = format!("{}.{}.{}.dn.example.test", long('p'), long('q'), long('r'));
    assert!(wire_name(&qname).len() <= 255, "the name asked is valid");
    let target = format!("{}.{}.x.example.test", long('a'), long('b'));
    let msg = Msg {
        aa: true,
        answer: vec![dname_rec("dn.example.test", 111, &target)],
        ..Msg::new(&qname, A)
    };
    assert_eq!(
        classify_as(&msg, ZONE, &qname, A),
        Step::Lame("a DNAME whose substitution is too long")
    );
}

#[test]
fn substitute_replaces_the_suffix_and_refuses_what_is_too_long() {
    let qname = wire_name("a.b.dn.example.test");
    let owner = wire_name("dn.example.test");
    assert_eq!(
        substitute(&qname, &owner, &wire_name("dest.test")),
        Some(wire_name("a.b.dest.test"))
    );
    assert_eq!(
        substitute(&owner, &owner, &wire_name("dest.test")),
        Some(wire_name("dest.test")),
        "nothing left of the prefix"
    );
    assert_eq!(
        substitute(&owner, &qname, &wire_name("dest.test")),
        None,
        "an owner longer than the name"
    );
    // A target of 193 octets (three labels of 63) and a prefix of 62 make exactly 255; one
    // more octet in the prefix is too long.
    let target = wire_name(&format!(
        "{}.{}.{}",
        "x".repeat(63),
        "y".repeat(63),
        "z".repeat(63)
    ));
    assert_eq!(target.len(), 193);
    let at_the_limit = wire_name(&format!("{}.dn.example.test", "p".repeat(61)));
    let substituted = substitute(&at_the_limit, &owner, &target).expect("255 octets fit");
    assert_eq!(substituted.len(), 255);
    let over = wire_name(&format!("{}.dn.example.test", "p".repeat(62)));
    assert_eq!(
        substitute(&over, &owner, &target),
        None,
        "256 octets do not"
    );
}

#[test]
fn the_names_of_an_answer_are_read_without_regard_to_case() {
    // The parser lowercases, so a server that echoes mixed case is read the same.
    let a = a_rec("WWW.EXAMPLE.TEST", 300, [192, 0, 2, 1]);
    let msg = Msg {
        aa: true,
        answer: vec![a.clone()],
        ..Msg::new("WwW.Example.TesT", A)
    };
    assert_eq!(
        step(&msg),
        Step::Answer {
            records: rrs(&[&a])
        }
    );
}

#[test]
fn an_answer_to_another_question_is_lame() {
    let msg = authoritative(vec![a_rec(QNAME, 300, [192, 0, 2, 1])]);
    assert_eq!(
        classify_as(&msg, ZONE, "other.example.test", A),
        Step::Lame("the answer is to another question"),
        "another name"
    );
    assert!(
        is_lame(&classify_as(&msg, ZONE, QNAME, AAAA)),
        "another type"
    );
}

#[test]
fn an_error_rcode_makes_the_server_lame() {
    let soa = soa_rec(ZONE, 60);
    for (rcode, what) in [
        (1u8, "FORMERR"),
        (2, "SERVFAIL"),
        (4, "NOTIMP"),
        (5, "REFUSED"),
    ] {
        let msg = Msg {
            aa: true,
            rcode,
            authority: vec![soa.clone()],
            ..Msg::new(QNAME, A)
        };
        assert_eq!(
            step(&msg),
            Step::Lame("the server answered with an error"),
            "{what}"
        );
    }
    let badcookie = Msg {
        rcode: 7,
        opt: Some(OptSpec {
            ext: 1,
            ..OptSpec::default()
        }),
        ..Msg::new(QNAME, A)
    };
    assert!(
        is_lame(&step(&badcookie)),
        "BADCOOKIE from the OPT record's bits"
    );
}

// ---------------------------------------------------------------------------------------
// classify: referrals

const CHILD_QNAME: &str = "www.child.example.test";

fn referral_msg(authority: Vec<Rec>, additional: Vec<Rec>) -> Msg {
    Msg {
        authority,
        additional,
        ..Msg::new(CHILD_QNAME, A)
    }
}

fn referral_step(msg: &Msg) -> Step {
    classify_as(msg, ZONE, CHILD_QNAME, A)
}

#[test]
fn a_referral_keeps_in_domain_glue_with_the_smallest_ns_ttl() {
    let ns1 = ns_rec("child.example.test", 300, "ns1.child.example.test").written(compressed(
        &["ns1"],
        CHILD_QNAME,
        1,
    ));
    let ns2 = ns_rec("child.example.test", 200, "ns2.child.example.test").written(compressed(
        &["ns2"],
        CHILD_QNAME,
        1,
    ));
    let glue1 = a_rec("ns1.child.example.test", 150, [192, 0, 2, 53]);
    let v6: Ipv6Addr = "2001:db8::53".parse().expect("address");
    let glue2 = aaaa_rec("ns2.child.example.test", 160, v6);
    let msg = referral_msg(vec![ns1.clone(), ns2.clone()], vec![glue1, glue2]);
    assert!(
        msg.encode().windows(2).any(|pair| pair == [0xc0, 0x10]),
        "the NS data is compressed"
    );
    assert_eq!(
        referral_step(&msg),
        Step::Referral(Referral {
            zone: wire_name("child.example.test"),
            ns: rrs(&[&ns1, &ns2]),
            ttl: 200,
            glue: vec![
                (
                    wire_name("ns1.child.example.test"),
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
                    150,
                    GlueKind::InDomain
                ),
                (
                    wire_name("ns2.child.example.test"),
                    IpAddr::V6(v6),
                    160,
                    GlueKind::InDomain
                ),
            ],
            ds: Vec::new(),
        })
    );
}

#[test]
fn a_referral_marks_glue_from_a_sibling_zone_as_sibling() {
    let ns = ns_rec("child.example.test", 300, "ns1.other.example.test");
    let glue = a_rec("ns1.other.example.test", 120, [192, 0, 2, 54]);
    let msg = referral_msg(vec![ns.clone()], vec![glue]);
    assert_eq!(
        referral_step(&msg),
        Step::Referral(Referral {
            zone: wire_name("child.example.test"),
            ns: rrs(&[&ns]),
            ttl: 300,
            glue: vec![(
                wire_name("ns1.other.example.test"),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54)),
                120,
                GlueKind::Sibling
            )],
            ds: Vec::new(),
        })
    );
}

#[test]
fn a_referral_drops_glue_out_of_bailiwick_and_glue_for_names_it_does_not_delegate_to() {
    let in_domain = ns_rec("child.example.test", 300, "ns1.child.example.test");
    let outside = ns_rec("child.example.test", 300, "ns.elsewhere.test");
    let kept = a_rec("ns1.child.example.test", 100, [192, 0, 2, 53]);
    let msg = referral_msg(
        vec![in_domain.clone(), outside.clone()],
        vec![
            a_rec("ns.elsewhere.test", 100, [192, 0, 2, 66]),
            // In the child's domain but not a server of the delegation.
            a_rec("stray.child.example.test", 100, [192, 0, 2, 67]),
            // A record that is not an address.
            Rec::new("ns1.child.example.test", TXT, 100, vec![1, b'x']),
            kept,
        ],
    );
    let Step::Referral(referral) = referral_step(&msg) else {
        panic!("a referral expected");
    };
    assert_eq!(
        referral.ns,
        rrs(&[&in_domain, &outside]),
        "the NS set is whole"
    );
    assert_eq!(
        referral.glue,
        vec![(
            wire_name("ns1.child.example.test"),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
            100,
            GlueKind::InDomain
        )],
        "only the glue of a delegated name inside the bailiwick"
    );
    let only_outside = referral_msg(
        vec![outside],
        vec![a_rec("ns.elsewhere.test", 100, [192, 0, 2, 66])],
    );
    let Step::Referral(referral) = referral_step(&only_outside) else {
        panic!("a referral without usable glue is still a referral");
    };
    assert!(
        referral.glue.is_empty(),
        "glue out of bailiwick is never used"
    );
}

#[test]
fn a_referral_carries_the_ds_records_of_the_delegation_and_their_signatures() {
    let ns = ns_rec("child.example.test", 300, "ns1.child.example.test");
    let ds = ds_rec("child.example.test", 3600);
    let sig = rrsig_rec("child.example.test", 3600, DS_TYPE);
    let other_ds = ds_rec("other.example.test", 3600);
    let msg = referral_msg(vec![ns, ds.clone(), other_ds, sig.clone()], Vec::new());
    let Step::Referral(referral) = referral_step(&msg) else {
        panic!("a referral expected");
    };
    assert_eq!(referral.ds, rrs(&[&ds, &sig]));
    assert_eq!(referral.ns.len(), 1, "the DS records are not in the NS set");
}

#[test]
fn an_upward_or_sideways_referral_is_lame() {
    let cases = [
        ("a parent of the zone", ns_rec("test", 300, "ns.test")),
        ("the zone itself", ns_rec(ZONE, 300, "ns.example.test")),
        ("a sibling zone", ns_rec("other.test", 300, "ns.other.test")),
        (
            "a zone below that is not above the name asked",
            ns_rec("elsewhere.example.test", 300, "ns.elsewhere.example.test"),
        ),
    ];
    for (what, ns) in cases {
        let msg = Msg {
            authority: vec![ns],
            ..Msg::new(QNAME, A)
        };
        assert_eq!(
            step(&msg),
            Step::Lame("an upward or sideways referral"),
            "{what}"
        );
    }
}

#[test]
fn a_referral_to_two_zones_at_once_is_lame() {
    let msg = referral_msg(
        vec![
            ns_rec("child.example.test", 300, "ns1.child.example.test"),
            ns_rec("example.test", 300, "ns1.example.test"),
        ],
        Vec::new(),
    );
    assert_eq!(
        referral_step(&msg),
        Step::Lame("a referral to more than one zone")
    );
    let two_children = Msg {
        authority: vec![
            ns_rec("a.example.test", 300, "ns1.a.example.test"),
            ns_rec("b.example.test", 300, "ns1.b.example.test"),
        ],
        ..Msg::new(QNAME, A)
    };
    assert!(is_lame(&step(&two_children)));
}

#[test]
fn a_referral_to_the_child_asked_for_its_ds_is_not_a_referral() {
    // DS lives at the parent: asked at the child's apex, an NS set for the child is the
    // wrong side of the cut (RFC 4035 section 3.1.4.1).
    let qname = "child.example.test";
    let ns = ns_rec(qname, 300, "ns1.child.example.test");
    let msg = Msg {
        authority: vec![ns.clone()],
        ..Msg::new(qname, DS_TYPE)
    };
    assert!(
        is_lame(&classify_as(&msg, ZONE, qname, DS_TYPE)),
        "a referral to the child for the child's DS"
    );
    // The same delegation is a referral for an ordinary type, and for a DS below the cut.
    let msg_a = Msg {
        authority: vec![ns.clone()],
        ..Msg::new(qname, A)
    };
    assert!(matches!(
        classify_as(&msg_a, ZONE, qname, A),
        Step::Referral(_)
    ));
    let below = "x.child.example.test";
    let msg_below = Msg {
        authority: vec![ns],
        ..Msg::new(below, DS_TYPE)
    };
    assert!(matches!(
        classify_as(&msg_below, ZONE, below, DS_TYPE),
        Step::Referral(_)
    ));
}

#[test]
fn the_parent_answers_a_ds_query_for_a_child_from_its_own_data() {
    let qname = "child.example.test";
    let ds = ds_rec(qname, 3600);
    let sig = rrsig_rec(qname, 3600, DS_TYPE);
    let positive = Msg {
        aa: true,
        answer: vec![ds.clone(), sig.clone()],
        ..Msg::new(qname, DS_TYPE)
    };
    assert_eq!(
        classify_as(&positive, ZONE, qname, DS_TYPE),
        Step::Answer {
            records: rrs(&[&ds, &sig])
        }
    );
    let soa = soa_rec(ZONE, 60);
    let negative = Msg {
        aa: true,
        authority: vec![soa.clone()],
        ..Msg::new(qname, DS_TYPE)
    };
    assert_eq!(
        classify_as(&negative, ZONE, qname, DS_TYPE),
        Step::Negative {
            rcode: 0,
            records: Vec::new(),
            authority: rrs(&[&soa])
        }
    );
}

// ---------------------------------------------------------------------------------------
// classify: negative answers

#[test]
fn nxdomain_keeps_the_soa_and_the_denial_records_of_the_zone_and_drops_the_rest() {
    let hashed = "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.test";
    let soa = soa_rec(ZONE, 60);
    let soa_sig = rrsig_rec(ZONE, 60, SOA);
    let nsec = nsec_rec("a.example.test", 60, "c.example.test");
    let nsec_sig = rrsig_rec("a.example.test", 60, NSEC);
    let hashed_rec = nsec3_rec(hashed, 60);
    let hashed_sig = rrsig_rec(hashed, 60, NSEC3);
    let msg = Msg {
        aa: true,
        rcode: 3,
        authority: vec![
            soa.clone(),
            soa_sig.clone(),
            ns_rec("child.example.test", 60, "ns1.child.example.test"),
            a_rec("junk.example.test", 60, [192, 0, 2, 99]),
            nsec.clone(),
            nsec_sig.clone(),
            nsec_rec("a.other.test", 60, "c.other.test"),
            hashed_rec.clone(),
            hashed_sig.clone(),
            rrsig_rec("junk.example.test", 60, A),
        ],
        ..Msg::new(QNAME, A)
    };
    assert_eq!(
        step(&msg),
        Step::Negative {
            rcode: 3,
            records: Vec::new(),
            authority: rrs(&[&soa, &soa_sig, &nsec, &nsec_sig, &hashed_rec, &hashed_sig]),
        }
    );
}

#[test]
fn nodata_is_a_negative_answer_with_rcode_zero() {
    let soa = soa_rec(ZONE, 60);
    let msg = Msg {
        aa: true,
        authority: vec![soa.clone()],
        ..Msg::new(QNAME, AAAA)
    };
    assert_eq!(
        classify_as(&msg, ZONE, QNAME, AAAA),
        Step::Negative {
            rcode: 0,
            records: Vec::new(),
            authority: rrs(&[&soa])
        }
    );
    let without_aa = Msg { aa: false, ..msg };
    assert!(
        matches!(
            classify_as(&without_aa, ZONE, QNAME, AAAA),
            Step::Negative { rcode: 0, .. }
        ),
        "an SOA of the zone makes it a negative answer even without AA"
    );
}

#[test]
fn a_negative_answer_without_aa_and_without_an_soa_is_lame() {
    let nodata = Msg::new(QNAME, A);
    assert_eq!(
        step(&nodata),
        Step::Lame("neither an answer nor a referral")
    );
    let nxdomain = Msg {
        rcode: 3,
        ..Msg::new(QNAME, A)
    };
    assert_eq!(
        step(&nxdomain),
        Step::Lame("neither an answer nor a referral")
    );
}

#[test]
fn a_negative_answer_from_a_zone_above_the_one_asked_is_lame() {
    // The delegation led to a server of the parent: its SOA is above the zone.
    let msg = Msg {
        aa: true,
        rcode: 3,
        authority: vec![soa_rec("test", 60)],
        ..Msg::new(QNAME, A)
    };
    assert_eq!(
        step(&msg),
        Step::Lame("a negative answer from a zone above the one asked")
    );
    let nodata = Msg { rcode: 0, ..msg };
    assert!(is_lame(&step(&nodata)), "the same for NODATA");
}

// ---------------------------------------------------------------------------------------
// compose

#[test]
fn compose_writes_the_answer_of_a_resolution_as_an_authority_would() {
    let a = a_rec(QNAME, 300, [192, 0, 2, 1]);
    let sig = rrsig_rec(QNAME, 300, A);
    let soa = soa_rec(ZONE, 60);
    let extra = a_rec("ns.example.test", 90, [192, 0, 2, 53]);
    let (answer, authority, additional) = (rrs(&[&a, &sig]), rrs(&[&soa]), rrs(&[&extra]));
    let qname = wire_name(QNAME);
    let encoded = compose(&Composed {
        qname: &qname,
        qtype: A,
        qclass: IN,
        rcode: 0,
        answer: &answer,
        authority: &authority,
        additional: &additional,
    });
    let header = wire::parse_header(&encoded).expect("a header");
    assert_eq!(header.id, 0);
    assert!(header.qr && header.rd && header.ra, "QR, RD and RA are set");
    assert!(!header.aa && !header.tc && !header.ad, "AA is clear");
    assert_eq!(
        (
            header.qdcount,
            header.ancount,
            header.nscount,
            header.arcount
        ),
        (1, 2, 1, 2),
        "the additional section counts the OPT record"
    );
    let parsed = parse(&encoded).expect("the composed message parses");
    assert_eq!(
        (parsed.qname.as_slice(), parsed.qtype),
        (qname.as_slice(), A)
    );
    assert_eq!(parsed.rcode, 0);
    assert!(!parsed.aa);
    assert_eq!(parsed.answer, answer);
    assert_eq!(parsed.authority, authority);
    assert_eq!(
        parsed.additional, additional,
        "the OPT record is not among them"
    );
    let opt = parsed.opt.expect("an OPT record");
    assert_eq!(opt.udp_size, 1_232);
    assert!(opt.dnssec_ok, "DO");
    assert_eq!(opt.ext_rcode, 0);
    assert_eq!(opt.cookie, None);
}

#[test]
fn compose_writes_nxdomain_and_an_empty_answer() {
    let soa = soa_rec(ZONE, 60);
    let authority = rrs(&[&soa]);
    let qname = wire_name(QNAME);
    let encoded = compose(&Composed {
        qname: &qname,
        qtype: AAAA,
        qclass: IN,
        rcode: 3,
        authority: &authority,
        ..Composed::default()
    });
    let header = wire::parse_header(&encoded).expect("a header");
    assert_eq!(header.rcode, 3);
    assert_eq!(
        (header.ancount, header.nscount, header.arcount),
        (0, 1, 1),
        "only the OPT record in the additional section"
    );
    let parsed = parse(&encoded).expect("the composed message parses");
    assert_eq!(parsed.rcode, 3);
    assert_eq!(parsed.qtype, AAAA);
    assert!(parsed.answer.is_empty() && parsed.additional.is_empty());
    assert_eq!(parsed.authority, authority);
}

#[test]
fn a_composed_answer_is_never_read_as_an_authoritys() {
    // The forwarder's cache stores what compose wrote; the records come back whole, and
    // AA is clear, so the engine would not take it for an authority's answer.
    let a = a_rec(QNAME, 300, [192, 0, 2, 1]);
    let answer = rrs(&[&a]);
    let qname = wire_name(QNAME);
    let encoded = compose(&Composed {
        qname: &qname,
        qtype: A,
        qclass: IN,
        answer: &answer,
        ..Composed::default()
    });
    let parsed = parse(&encoded).expect("the composed message parses");
    assert_eq!(parsed.answer, answer);
    assert_eq!(
        classify(&parsed, &wire_name(ZONE), &qname, A),
        Step::Lame("a non-authoritative answer")
    );
}
