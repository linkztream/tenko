//! The reader and the writer on their own: entries, directives, every type's
//! presentation form, the losses and the exact lines of errors.

use std::net::Ipv4Addr;

use tenko_core::{
    dns::{RecordData, SvcParam, TextBytes, codes},
    serde_util::HexBytes,
};

use super::*;

fn apex() -> DnsName {
    DnsName::new("example.test").expect("name")
}

/// Reads every item the way the fuzz target `dns_zonefile` does, until the end or the
/// first error.
fn read_all(text: &str) -> ZoneResult<Vec<Item>> {
    let mut reader = Reader::new(text, &apex(), 256)?;
    let mut items = Vec::new();
    while let Some(item) = reader.next_item()? {
        items.push(item);
    }
    Ok(items)
}

fn records(text: &str) -> Vec<FileRecord> {
    read_all(text)
        .expect("the file reads")
        .into_iter()
        .map(|item| match item {
            Item::Record(record) => record,
            Item::Loss(loss) => panic!("unexpected loss {loss:?}"),
        })
        .collect()
}

fn one(text: &str) -> FileRecord {
    let mut all = records(text);
    assert_eq!(all.len(), 1, "{all:?}");
    all.remove(0)
}

fn data(text: &str) -> RecordData {
    let record = one(text);
    record.rdata.decode(record.rtype).expect("decodes")
}

fn error(text: &str) -> (usize, String) {
    let error = read_all(text).expect_err("the file is refused");
    assert!(error.is(codes::ZONE_FILE_INVALID), "{error:?}");
    let coded = error.coded();
    let line = coded
        .params
        .get("line")
        .expect("line")
        .parse()
        .expect("number");
    (line, coded.params.get("reason").expect("reason").clone())
}

fn losses(text: &str) -> Vec<(usize, &'static str, String)> {
    read_all(text)
        .expect("the file reads")
        .into_iter()
        .filter_map(|item| match item {
            Item::Loss(loss) => Some((loss.line, loss.code, loss.detail)),
            Item::Record(_) => None,
        })
        .collect()
}

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn assert_unclosed(text: &str, line: usize) {
    let (at, reason) = error(text);
    assert_eq!(at, line, "{reason}");
    assert!(reason.contains("parenthesis"), "{reason}");
}

/// The input the fuzz target `dns_zonefile` found against 0.0.10: a TXT record whose
/// parenthesis is still open at the end of the file made the scanner of `domain` index
/// past its buffer.
#[test]
fn a_parenthesis_open_at_the_end_of_the_file_is_refused_without_a_panic() {
    let text = "txt IN TXT \"hello world\" \"second string\" ( \"third\" llo worN CAA 0 \
                iss\" ueca.example.test\"\n_sip._tpc IN SRV 61 60 506i p0$ORIGIN \
                examsple.t.";
    assert_eq!(text.len(), 139);
    assert_unclosed(text, 1);
    assert_unclosed("www IN TXT ( \"a\"", 1);
    assert_unclosed("www IN TXT ( \"a\"\n", 1);
    assert_unclosed(
        "www IN A 192.0.2.1\nwww IN TXT \"a\" (\n \"b\" ; ) a comment\n",
        2,
    );
    // The lines `$GENERATE` makes count too.
    assert_unclosed("$GENERATE 1-2 host$ TXT ( \"a\"\n", 1);
    // A quote open at the end is refused with the line that opened it.
    assert_eq!(error("www IN TXT \"a").0, 1);
    assert_eq!(error("www IN A 192.0.2.1\n\nx TXT \"a\nb\n").0, 3);
}

#[test]
fn parentheses_closed_by_the_end_of_the_file_still_read() {
    let items = read_all("www IN TXT ( \"a\" \"(\"\n \"b\" ) ; ( in a comment\n").expect("reads");
    assert_eq!(items.len(), 1);
    let items = read_all("www IN TXT ( \"a\"\n )").expect("reads");
    assert_eq!(items.len(), 1);
}

#[test]
fn owners_ttls_and_classes_follow_rfc_1035() {
    let all = records(
        "; a comment\n\
         @ IN SOA ns1 hostmaster ( 1 ; serial\n 1h 15m 2w 300 )\n\
         \n\
         www 600 IN A 192.0.2.10\n\
         \tIN 700 AAAA 2001:db8::10\n\
         \x20 A 192.0.2.11\n\
         $TTL 1d\n\
         mail MX 10 mx\n\
         ; a line without an entry\n\
         $ORIGIN sub.example.test.\n\
         host 30m A 192.0.2.12\n\
         @ TXT x\n\
         $ORIGIN deeper\n\
         a A 192.0.2.13\n",
    );
    let summary: Vec<(usize, String, Rtype, u32)> = all
        .iter()
        .map(|record| {
            (
                record.line,
                record.name.to_string(),
                record.rtype,
                record.ttl,
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (2, "example.test".to_owned(), Rtype::SOA, 3_600),
            (5, "www.example.test".to_owned(), Rtype::A, 600),
            (6, "www.example.test".to_owned(), Rtype::AAAA, 700),
            (7, "www.example.test".to_owned(), Rtype::A, 700),
            (9, "mail.example.test".to_owned(), Rtype::MX, 86_400),
            (12, "host.sub.example.test".to_owned(), Rtype::A, 1_800),
            (13, "sub.example.test".to_owned(), Rtype::TXT, 86_400),
            (15, "a.deeper.sub.example.test".to_owned(), Rtype::A, 86_400),
        ]
    );
    assert_eq!(
        all[0].rdata.decode(Rtype::SOA).expect("soa"),
        RecordData::Soa {
            mname: name("ns1.example.test"),
            rname: name("hostmaster.example.test"),
            serial: 1,
            refresh: 3_600,
            retry: 900,
            expire: 1_209_600,
            minimum: 300,
        }
    );
}

#[test]
fn without_ttl_the_last_one_is_kept_until_dollar_ttl() {
    let ttls: Vec<u32> = records("a A 192.0.2.1\nb 60 A 192.0.2.1\nc A 192.0.2.1\n$TTL 5\nd A 192.0.2.1\ne 7 A 192.0.2.1\nf A 192.0.2.1\n")
        .iter()
        .map(|record| record.ttl)
        .collect();
    assert_eq!(ttls, [3_600, 60, 60, 5, 7, 5]);
}

#[test]
fn losses_name_their_line_and_cause() {
    assert_eq!(
        losses(
            "chaos CH TXT \"x\"\n\
             c3 CLASS3 TXT \"x\"\n\
             out.other.test. IN A 192.0.2.3\n\
             bad\\.label A 192.0.2.4\n\
             loc LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m\n\
             loc LOC \\# 2 0000\n\
             opt OPT \\# 0\n\
             any ANY \\# 0\n\
             caa CAA 0 \"is sue\" \"x\"\n\
             cname CNAME a\\@b\n"
        ),
        [
            (1, LOSS_CLASS, "a record of class CH is not served".to_owned()),
            (2, LOSS_CLASS, "a record of class CH is not served".to_owned()),
            (3, LOSS_OUTSIDE, "out.other.test is outside the zone example.test".to_owned()),
            (
                4,
                LOSS_DATA,
                "owner name refused: a label holds an octet outside the allowed characters".to_owned()
            ),
            (
                5,
                LOSS_DATA,
                "loc.example.test LOC: the data of this type is read only in the generic form \\# (RFC 3597)".to_owned()
            ),
            (
                7,
                LOSS_DATA,
                "opt.example.test OPT: a meta type is not zone data".to_owned()
            ),
            (
                8,
                LOSS_DATA,
                "any.example.test ANY: a meta type is not zone data".to_owned()
            ),
            (
                9,
                LOSS_DATA,
                "caa.example.test CAA: a CAA tag is 1 to 15 letters or digits".to_owned()
            ),
            (
                10,
                LOSS_DATA,
                "cname.example.test CNAME: only letters, digits, `-`, `_`, `/` and a leftmost `*` are allowed".to_owned()
            ),
        ]
    );
    // The generic form of a type without a presentation parser is read.
    let record = one("loc LOC \\# 2 0000\n");
    assert_eq!(record.rtype, Rtype(29));
    assert_eq!(record.rdata.as_bytes(), [0, 0]);
}

#[test]
#[allow(clippy::too_many_lines, reason = "one case per error")]
fn syntax_errors_carry_the_exact_line() {
    for (text, line, reason) in [
        (
            "www A 192.0.2.1\nbad IN A not-an-address\n",
            2,
            "`not-an-address` is not an IPv4 address",
        ),
        (
            "www TXT (\n\"a\"\n\"b\" )\nx MX ( 10\n\n mx\n ten )\n",
            7,
            "`ten` is more data than the type takes",
        ),
        ("x MX (\n 10 )\n", 2, "the exchange is missing"),
        ("x 300 IN\n", 1, "the record type is missing"),
        (
            "x 300 IN BOGUS 1\n",
            1,
            "`BOGUS` is not a TTL, a class or a record type",
        ),
        (
            "x 300 300 A 192.0.2.1\n",
            1,
            "`300` is not a TTL, a class or a record type",
        ),
        ("  A 192.0.2.1\n", 1, "the first record has no owner name"),
        ("a..b A 192.0.2.1\n", 1, "the owner name: an empty label"),
        ("$FOO bar\n", 1, "$FOO is not a directive the reader knows"),
        ("$TTL\n", 1, "$TTL: the TTL is missing"),
        (
            "$TTL 1x\n",
            1,
            "$TTL is a number of seconds or a duration such as 1h30m, not `1x`",
        ),
        (
            "$ORIGIN a b\n",
            1,
            "$ORIGIN: `b` is more than the directive takes",
        ),
        ("a\n$INCLUDE other.zone\n", 1, "the record type is missing"),
        (
            "$INCLUDE other.zone\n",
            1,
            "$INCLUDE is refused: the import reads one file",
        ),
        (
            "x A 192.0.2.1 )\n",
            1,
            "a closing parenthesis without an opening one",
        ),
        ("x TXT\n", 1, "a TXT record has at least one string"),
        (
            "x TXT \"a\\\"\n",
            1,
            "the quote opened on this line is not closed by the end of the file",
        ),
        ("x TXT a\\25\n", 1, "`\\DDD` needs three decimal digits"),
        (
            "x A \\# 4 c00002\n",
            1,
            "the generic data has 3 octets, not the 4 its length says",
        ),
        (
            "x A \\# 4 c00002010\n",
            1,
            "the generic data: hexadecimal comes in pairs of digits",
        ),
        (
            "x TYPE65280 \\# 65536\n",
            1,
            "the length of the generic data is a number from 0 to 65535, not `65536`",
        ),
        (
            "x DNSKEY 257 3 13 AQI\n",
            1,
            "the public key: base64 comes in groups of four characters",
        ),
        (
            "x RRSIG A 13 2 300 20261301000000 20260101000000 1 example.test. AQID\n",
            1,
            "the expiration is YYYYMMDDHHmmSS or a number of seconds, not `20261301000000`",
        ),
        ("x HTTPS 1 . alpn\n", 1, "the parameter alpn needs a value"),
        (
            "x HTTPS 1 . port=1 port=2\n",
            1,
            "the parameter port is given twice",
        ),
        ("x SVCB 1 . bogus=1\n", 1, "`bogus` is not a parameter key"),
        (
            "$GENERATE 1-300 h$ A 192.0.2.1\n",
            1,
            "$GENERATE: the range makes 300 records, more than 256",
        ),
        (
            "$GENERATE 1-3 h$ A\n",
            1,
            "$GENERATE: the type and the data are missing",
        ),
        (
            "$GENERATE 1-3 h${0,3 A 192.0.2.1\n",
            1,
            "$GENERATE: an unclosed ${",
        ),
        (
            "$GENERATE 1-3 \\$x A 192.0.2.1\n",
            1,
            "$GENERATE: a generated line is a directive",
        ),
    ] {
        assert_eq!(error(text), (line, reason.to_owned()), "{text:?}");
    }
}

#[test]
fn reading_stops_after_an_error() {
    let mut reader =
        Reader::new("a A 192.0.2.1\nb A x\nc A 192.0.2.2\n", &apex(), 1).expect("reader");
    assert!(matches!(reader.next_item(), Ok(Some(Item::Record(_)))));
    assert!(reader.next_item().is_err());
    assert_eq!(reader.next_item(), Ok(None));
}

#[test]
fn generate_expands_with_the_directive_line() {
    let all = records(
        "$ORIGIN example.test.\n\
         $GENERATE 1-20/10 host-${0,3,d} IN A 198.51.100.$ ; comment\n\
         $GENERATE 0-1 ${0,1,n}.rev 60 IN PTR host-$.example.test.\n\
         $GENERATE 1-1 q TXT \"a  b\" key=\"v\"\n",
    );
    let summary: Vec<(usize, String, u32)> = all
        .iter()
        .map(|record| (record.line, record.name.to_string(), record.ttl))
        .collect();
    assert_eq!(
        summary,
        [
            (2, "host-001.example.test".to_owned(), 3_600),
            (2, "host-011.example.test".to_owned(), 3_600),
            (3, "0.rev.example.test".to_owned(), 60),
            (3, "1.rev.example.test".to_owned(), 60),
            (4, "q.example.test".to_owned(), 60),
        ]
    );
    assert_eq!(
        all[4].rdata.decode(Rtype::TXT).expect("txt"),
        RecordData::Txt {
            strings: vec![
                TextBytes::from_text("a  b"),
                TextBytes::from_text("key="),
                TextBytes::from_text("v")
            ]
        }
    );
}

#[test]
#[allow(clippy::too_many_lines, reason = "one sample per record type")]
fn every_model_type_reads_its_presentation_form() {
    assert_eq!(
        data("x A 192.0.2.1"),
        RecordData::A {
            address: Ipv4Addr::new(192, 0, 2, 1)
        }
    );
    assert_eq!(
        data("x CNAME WWW.Example.Test."),
        RecordData::Cname {
            target: name("www.example.test")
        }
    );
    assert_eq!(
        data("x DNAME @"),
        RecordData::Dname {
            target: name("example.test")
        }
    );
    assert_eq!(
        data("x SRV 0 5 389 dc1"),
        RecordData::Srv {
            priority: 0,
            weight: 5,
            port: 389,
            target: name("dc1.example.test")
        }
    );
    assert_eq!(
        data("x TXT unquoted \"with \\\"quote\\\" and \\240\" \"\""),
        RecordData::Txt {
            strings: vec![
                TextBytes::from_text("unquoted"),
                TextBytes(b"with \"quote\" and \xf0".to_vec()),
                TextBytes::default(),
            ]
        }
    );
    let long = "a".repeat(300);
    assert_eq!(
        data(&format!("x TXT \"{long}\"")),
        RecordData::Txt {
            strings: vec![TextBytes(vec![b'a'; 255]), TextBytes(vec![b'a'; 45])]
        }
    );
    assert_eq!(
        data("x CAA 128 issue \"ca.example.net; account=1\""),
        RecordData::Caa {
            flags: 128,
            tag: "issue".to_owned(),
            value: TextBytes::from_text("ca.example.net; account=1")
        }
    );
    assert_eq!(
        data("x DS 12345 ECDSAP256SHA256 2 ( ab01\n CDEF )"),
        RecordData::Ds {
            key_tag: 12345,
            algorithm: 13,
            digest_type: 2,
            digest: HexBytes(vec![0xab, 0x01, 0xcd, 0xef])
        }
    );
    assert_eq!(
        data("x DNSKEY 257 3 13 ( AQID\n BA== )"),
        RecordData::Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: HexBytes(vec![1, 2, 3, 4])
        }
    );
    assert_eq!(
        data("x RRSIG A 13 3 1h 20260101000000 1767225500 12345 example.test. AgIC AgIC"),
        RecordData::Rrsig {
            type_covered: Rtype::A,
            algorithm: 13,
            labels: 3,
            original_ttl: 3_600,
            expiration: 1_767_225_600,
            inception: 1_767_225_500,
            key_tag: 12345,
            signer: name("example.test"),
            signature: HexBytes(vec![2; 6])
        }
    );
    assert_eq!(
        data("x NSEC b.example.test. A mx RRSIG NSEC TYPE1234 A"),
        RecordData::Nsec {
            next: name("b.example.test"),
            types: vec![Rtype::A, Rtype::MX, Rtype::RRSIG, Rtype::NSEC, Rtype(1234)]
        }
    );
    assert_eq!(
        data("x NSEC b"),
        RecordData::Nsec {
            next: name("b.example.test"),
            types: Vec::new()
        }
    );
    assert_eq!(
        data("x NSEC3 1 1 10 - 0s3ge1o70s3ge1o70s3ge1o70s3ge1o7 A RRSIG"),
        RecordData::Nsec3 {
            hash_algorithm: 1,
            flags: 1,
            iterations: 10,
            salt: HexBytes(Vec::new()),
            next_hashed: HexBytes(vec![7; 20]),
            types: vec![Rtype::A, Rtype::RRSIG]
        }
    );
    assert_eq!(
        data("x NSEC3PARAM 1 0 5 AbCd"),
        RecordData::Nsec3param {
            hash_algorithm: 1,
            flags: 0,
            iterations: 5,
            salt: HexBytes(vec![0xab, 0xcd])
        }
    );
    assert_eq!(
        data("x TLSA 3 1 1 DEAD beef"),
        RecordData::Tlsa {
            usage: 3,
            selector: 1,
            matching_type: 1,
            data: HexBytes(vec![0xde, 0xad, 0xbe, 0xef])
        }
    );
    let param = |key, value: &[u8]| SvcParam {
        key,
        value: HexBytes(value.to_vec()),
    };
    assert_eq!(
        data(
            "x HTTPS 1 . ( alpn=\"h2,h3\" port=443 mandatory=port,alpn no-default-alpn\n \
             ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=\"2001:db8::1\" ech=AQID dohpath=/q{?dns} \
             ohttp key65000=\"a b\" key65001 )"
        ),
        RecordData::Https {
            priority: 1,
            target: DnsName::root(),
            params: vec![
                param(0, &[0, 1, 0, 3]),
                param(1, b"\x02h2\x02h3"),
                param(2, b""),
                param(3, &[1, 187]),
                param(4, &[192, 0, 2, 1, 192, 0, 2, 2]),
                param(5, &[1, 2, 3]),
                param(
                    6,
                    &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                ),
                param(7, b"/q{?dns}"),
                param(8, b""),
                param(65_000, b"a b"),
                param(65_001, b""),
            ]
        }
    );
    assert_eq!(
        data("x SVCB 0 svc.example.net."),
        RecordData::Svcb {
            priority: 0,
            target: name("svc.example.net"),
            params: Vec::new()
        }
    );
    assert_eq!(
        data("x HTTPS 1 . alpn=a\\\\\\\\\\\\,b,c"),
        RecordData::Https {
            priority: 1,
            target: DnsName::root(),
            params: vec![param(1, b"\x04a\\,b\x01c")]
        },
        "a backslash and a comma inside an identifier"
    );
    assert_eq!(
        data("x HTTPS 1 . key1=\\005h2"),
        RecordData::Https {
            priority: 1,
            target: DnsName::root(),
            params: vec![param(1, b"\x05h2")]
        },
        "the generic form of a known key keeps its value"
    );
}

#[test]
fn opaque_types_read_their_presentation_and_the_generic_form() {
    let raw = |text: &str| one(text).rdata.as_bytes().to_vec();
    assert_eq!(raw("x HINFO \"cpu\" os"), b"\x03cpu\x02os");
    assert_eq!(raw("x CDS 12345 13 2 AB"), [0x30, 0x39, 13, 2, 0xab]);
    assert_eq!(raw("x CDNSKEY 257 3 13 AQID"), [1, 1, 3, 13, 1, 2, 3]);
    assert_eq!(raw("x SSHFP 1 2 ab"), [1, 2, 0xab]);
    assert_eq!(
        raw("x NAPTR 10 100 u E2U+sip \"\" www"),
        b"\x00\x0a\x00\x64\x01u\x07E2U+sip\x00\x03www\x07example\x04test\x00"
    );
    assert_eq!(
        raw("x RP Admin.Mail. txt"),
        b"\x05Admin\x04Mail\x00\x03txt\x07example\x04test\x00"
    );
    assert_eq!(raw("x ZONEMD 1 1 1 abcd"), [0, 0, 0, 1, 1, 1, 0xab, 0xcd]);
    assert_eq!(raw("x TYPE65280 \\# 4 c0 00 0201"), [192, 0, 2, 1]);
    assert_eq!(raw("x TYPE65280 \\# 0"), [0u8; 0]);
    assert_eq!(
        raw("x A \\# 4 C0000201"),
        [192, 0, 2, 1],
        "a known type in the generic form"
    );
    assert_eq!(raw("x SPF \\# 3 026869"), b"\x02hi");
}

#[test]
#[allow(clippy::too_many_lines, reason = "one sample per record type")]
fn every_written_record_reads_back_the_same() {
    let param = |key, value: &[u8]| SvcParam {
        key,
        value: HexBytes(value.to_vec()),
    };
    let samples = [
        RecordData::Soa {
            mname: name("ns1.example.test"),
            rname: name("hostmaster.example.test"),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 300,
        },
        RecordData::Txt {
            strings: vec![
                TextBytes(b"a \"q\" \\ ;()".to_vec()),
                TextBytes(vec![0, 9, 127, 0xc3, 0xa5]),
                TextBytes::default(),
            ],
        },
        RecordData::Caa {
            flags: 128,
            tag: "issue".to_owned(),
            value: TextBytes::from_text("ca.example.net; x=\"y\""),
        },
        RecordData::Caa {
            flags: 0,
            tag: "iodef".to_owned(),
            value: TextBytes::default(),
        },
        RecordData::Ds {
            key_tag: 1,
            algorithm: 8,
            digest_type: 1,
            digest: HexBytes(Vec::new()),
        },
        RecordData::Dnskey {
            flags: 256,
            protocol: 3,
            algorithm: 15,
            public_key: HexBytes(Vec::new()),
        },
        RecordData::Rrsig {
            type_covered: Rtype(1234),
            algorithm: 200,
            labels: 0,
            original_ttl: 0,
            expiration: 5,
            inception: u32::MAX,
            key_tag: 0,
            signer: DnsName::root(),
            signature: HexBytes(vec![1]),
        },
        RecordData::Nsec3 {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: HexBytes(vec![0xaa, 0xbb]),
            next_hashed: HexBytes(vec![0xff; 3]),
            types: Vec::new(),
        },
        RecordData::Tlsa {
            usage: 3,
            selector: 1,
            matching_type: 1,
            data: HexBytes(Vec::new()),
        },
        RecordData::Svcb {
            priority: 1,
            target: DnsName::root(),
            params: vec![
                param(0, &[0, 3, 0, 1]),
                param(1, b"\x02h2\x03a,b\x02c\\\x01\""),
                param(3, &[1]),
                param(7, b"/dns-query{?dns} x"),
                param(65_000, b"a b\"\\\x00\xff;()"),
            ],
        },
        RecordData::Unknown {
            rtype: Rtype(13),
            data: HexBytes(b"\x03cpu".to_vec()),
        },
        RecordData::Unknown {
            rtype: Rtype(35),
            data: HexBytes(b"\x00\x0a\x00\x64\x01u\x07E2U+sip\x00\x03w.w\x02@$\x00".to_vec()),
        },
        RecordData::Unknown {
            rtype: Rtype(99),
            data: HexBytes(b"\x05v=spf".to_vec()),
        },
        RecordData::Unknown {
            rtype: Rtype(65280),
            data: HexBytes(Vec::new()),
        },
    ];
    for sample in samples {
        let rtype = sample.rtype();
        let rdata = Rdata::from_data(&sample);
        let text = presentation(rtype, &rdata).expect("presents");
        let line = format!("x 300 IN {} {text}\n", type_name(rtype));
        let record = one(&line);
        assert_eq!((record.rtype, &record.rdata), (rtype, &rdata), "{line}");
    }
}

#[test]
fn the_writer_keeps_the_forms_of_the_export() {
    let text =
        |data: &RecordData| presentation(data.rtype(), &Rdata::from_data(data)).expect("presents");
    assert_eq!(
        text(&RecordData::Txt {
            strings: vec![
                TextBytes(b"a \"q\" \\ ;()".to_vec()),
                TextBytes(vec![0, 9, 127, 0xc3, 0xa5]),
                TextBytes::default()
            ]
        }),
        "\"a \\\"q\\\" \\\\ ;()\" \"\\000\\009\\127\\195\\165\" \"\""
    );
    assert_eq!(
        text(&RecordData::Ds {
            key_tag: 12345,
            algorithm: 13,
            digest_type: 2,
            digest: HexBytes(vec![0xab, 0x01])
        }),
        "12345 13 2 AB01"
    );
    assert_eq!(
        text(&RecordData::Rrsig {
            type_covered: Rtype::A,
            algorithm: 13,
            labels: 3,
            original_ttl: 300,
            expiration: 1_800_000_000,
            inception: 1_790_000_000,
            key_tag: 12345,
            signer: name("example.test"),
            signature: HexBytes(vec![2; 10])
        }),
        "A 13 3 300 1800000000 1790000000 12345 example.test. AgICAgICAgICAg=="
    );
    assert_eq!(
        text(&RecordData::Nsec {
            next: name("b.example.test"),
            types: vec![
                Rtype::A,
                Rtype(13),
                Rtype::MX,
                Rtype::RRSIG,
                Rtype::NSEC,
                Rtype(99),
                Rtype::CAA,
                Rtype(1234)
            ]
        }),
        "b.example.test. A HINFO MX RRSIG NSEC SPF CAA TYPE1234"
    );
    assert_eq!(
        text(&RecordData::Nsec3 {
            hash_algorithm: 1,
            flags: 1,
            iterations: 10,
            salt: HexBytes(Vec::new()),
            next_hashed: HexBytes(vec![7; 20]),
            types: vec![Rtype::A, Rtype::RRSIG]
        }),
        "1 1 10 - 0S3GE1O70S3GE1O70S3GE1O70S3GE1O7 A RRSIG"
    );
    assert_eq!(
        text(&RecordData::Unknown {
            rtype: Rtype(65280),
            data: HexBytes(vec![0xc0, 0, 2, 1])
        }),
        "\\# 4 c0 00 02 01"
    );
    assert_eq!(
        text(&RecordData::Unknown {
            rtype: Rtype(65280),
            data: HexBytes(Vec::new())
        }),
        "\\# 0"
    );
    assert_eq!(
        text(&RecordData::Unknown {
            rtype: Rtype(13),
            data: HexBytes(b"\x03cpu".to_vec())
        }),
        "\\# 4 03 63 70 75",
        "opaque data that does not parse as its type is written generically"
    );
    assert_eq!(
        text(&RecordData::Ds {
            key_tag: 1,
            algorithm: 8,
            digest_type: 1,
            digest: HexBytes(Vec::new())
        }),
        "\\# 4 00 01 08 01"
    );
    assert_eq!(type_name(Rtype(99)), "SPF");
    assert_eq!(type_name(Rtype(65280)), "TYPE65280");
}

#[test]
fn hostile_input_is_refused_or_read_without_a_panic() {
    let long_label = format!("{} A 192.0.2.1\n", "a".repeat(64));
    let deep_parens = format!("x TXT {}\"a\"{}\n", "(".repeat(10_000), ")".repeat(10_000));
    let many_tokens = format!("x TXT {}\n", "a ".repeat(40_000));
    let inputs = [
        "\u{0}\u{1}\u{2}",
        "\\",
        "x\\",
        "\"",
        "x TXT \"\\",
        "x TXT \\\u{e5}",
        "$",
        "$GENERATE",
        "$GENERATE 1-2",
        "$GENERATE 1-2 $",
        "$GENERATE 1-2 $ A",
        "x HTTPS 1 . alpn=\"",
        "x HTTPS 1 . alpn=\"a\"\"b\"",
        "x HTTPS 1 . \"alpn=h2\"",
        "x HTTPS 1 . key65535=\\255",
        "x NSEC3 1 1 1 - - A",
        "x RRSIG A 1 1 1 99999999999999 1 1 . AA==",
        "@ SOA . . 1 1 1 1",
        "x CAA 0 issue",
        long_label.as_str(),
        deep_parens.as_str(),
        many_tokens.as_str(),
    ];
    for input in inputs {
        let _ = read_all(input);
    }
    // A TXT record of more than 65,535 octets is a syntax error, not an allocation; so are
    // an entry of more tokens and a token longer than any record data.
    let huge = format!("x TXT {}\n", "\"a\" ".repeat(33_000));
    assert_eq!(error(&huge).1, "the TXT data is longer than 65535 octets");
    let tokens = format!("x TXT (\n{})\n", "a ".repeat(300_000));
    assert_eq!(
        error(&tokens),
        (2, "an entry has more than 262144 tokens".to_owned())
    );
    let token = format!("x TXT \"{}\"\n", "a".repeat(300_000));
    assert_eq!(
        error(&token).1,
        "a token is longer than any record data can be written"
    );
    let hex = format!("x TYPE65280 \\# 65535 {}\n", "ab ".repeat(140_000));
    assert_eq!(
        error(&hex).1,
        "the generic data is longer than any record data"
    );
}

// WP13.4: the Windows dialect (MIG-07).

fn read_windows(text: &str) -> ZoneResult<Vec<Item>> {
    let mut reader = Reader::with_dialect(text, &apex(), 256, Dialect::Windows)?;
    let mut items = Vec::new();
    while let Some(item) = reader.next_item()? {
        items.push(item);
    }
    Ok(items)
}

fn windows_records(text: &str) -> Vec<(String, bool)> {
    read_windows(text)
        .expect("the file reads")
        .into_iter()
        .filter_map(|item| match item {
            Item::Record(record) => Some((record.name.to_string(), record.aged)),
            Item::Loss(_) => None,
        })
        .collect()
}

/// MIG-07: a file the Windows DNS Server wrote: the aging mark after the owner (also on a
/// line that continues the previous owner) makes a record aged when its hours are above
/// zero; a record without one, or with `[AGE:0]`, is static.
#[test]
fn mig_07_the_aging_mark_of_a_windows_file() {
    let text = "\
@                       3600    NS      ns1.example.test.
ws01                    [AGE:3660412]   1200    A       192.0.2.21
                        [age:3660412]   1200    A       192.0.2.22
srv01                   1200    A       192.0.2.10
old                     [AGE:0] 1200    A       192.0.2.30
_ldap._tcp              [AGE:3660413]   600     SRV     0 100 389 dc1.example.test.
";
    assert_eq!(
        windows_records(text),
        [
            ("example.test".to_owned(), false),
            ("ws01.example.test".to_owned(), true),
            ("ws01.example.test".to_owned(), true),
            ("srv01.example.test".to_owned(), false),
            ("old.example.test".to_owned(), false),
            ("_ldap._tcp.example.test".to_owned(), true),
        ]
    );
}

/// MIG-07: WINS and WINS-R records are losses of a Windows file, not syntax errors; data
/// that reads `WINS` after a known type is data.
#[test]
fn mig_07_wins_records_are_losses_and_wins_as_data_is_data() {
    let items = read_windows(
        "@ WINS L1 C900 ( 192.0.2.9 )\n@ [AGE:0] 3600 WINS-R L1 C900 ( example.test. )\nnote TXT WINS\n",
    )
    .expect("reads");
    let codes: Vec<&str> = items
        .iter()
        .map(|item| match item {
            Item::Loss(loss) => loss.code,
            Item::Record(_) => "record",
        })
        .collect();
    assert_eq!(codes, [LOSS_WINS, LOSS_WINS, "record"]);
}

/// MIG-07: a malformed mark is a syntax error with its line; in the RFC 1035 dialect, the
/// default, a mark is the syntax error it is in any other zone file.
#[test]
fn mig_07_a_malformed_mark_and_a_mark_outside_the_dialect() {
    for (text, reason) in [
        ("a [AGE:] 300 A 192.0.2.1\n", "digits only"),
        ("a [AGE:12x] 300 A 192.0.2.1\n", "digits only"),
        ("a [AGE:12345678901] 300 A 192.0.2.1\n", "digits only"),
        ("a [AGE:9999999999] 300 A 192.0.2.1\n", "too large"),
    ] {
        let error = read_windows(text).expect_err(text);
        assert!(error.is(codes::ZONE_FILE_INVALID), "{error:?}");
        assert!(
            error
                .coded()
                .params
                .get("reason")
                .is_some_and(|got| got.contains(reason)),
            "{text}: {error:?}"
        );
    }
    let (line, _) = error("ok 300 A 192.0.2.1\na [AGE:3660412] 300 A 192.0.2.1\n");
    assert_eq!(line, 2);
    // A second mark is no mark: the token is neither a TTL, a class nor a type.
    assert!(read_windows("a [AGE:1] [AGE:2] 300 A 192.0.2.1\n").is_err());
}
