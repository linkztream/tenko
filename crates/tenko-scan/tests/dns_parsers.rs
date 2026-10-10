//! The DNS message layer against recorded responses and hostile input.
//!
//! The recorded messages are hex files under `tests/fixtures/dns`, one message per file, with
//! `#` comment lines that say what the message is. Nothing here touches a network.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use domain::base::iana::Class;
use domain::base::message_builder::AnswerBuilder;
use domain::base::{CharStr, MessageBuilder, Name, Rtype};
use domain::rdata::{A, Hinfo, Ptr, Srv, Txt};
use proptest::prelude::*;
use tenko_scan::dns::message::{MAX_MESSAGE_LEN, MAX_QUESTIONS, MAX_RECORDS, MAX_TEXT_CHARS};
use tenko_scan::dns::{
    NameFindings, QueryOptions, QueryType, Record, RecordData, Response, Section, build_query,
    llmnr, mdns, parse_response, ptr_names, reverse_name,
};

/// Every fixture file, for the tests that run all of them.
const FIXTURES: &[&str] = &[
    "mdns_printer.hex",
    "mdns_nas.hex",
    "mdns_studio.hex",
    "mdns_esphome.hex",
    "mdns_services_browse.hex",
    "mdns_reverse_ptr.hex",
    "mdns_query_qu.hex",
    "llmnr_a.hex",
    "llmnr_ptr.hex",
    "dns_reverse_resolver.hex",
    "bad_truncated_header.hex",
    "bad_compression_loop.hex",
    "bad_record_length.hex",
];

/// Reads a fixture: hex bytes separated by white space, `#` starts a comment.
fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", "dns", name]
        .iter()
        .collect();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let mut bytes = Vec::new();
    for line in text.lines() {
        let content = line.split('#').next().unwrap_or("");
        for token in content.split_whitespace() {
            let byte = u8::from_str_radix(token, 16)
                .unwrap_or_else(|_| panic!("{name}: {token:?} is not a hex byte"));
            bytes.push(byte);
        }
    }
    bytes
}

fn parsed(name: &str) -> Response {
    parse_response(&fixture(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn set<T: Ord>(items: impl IntoIterator<Item = T>) -> BTreeSet<T> {
    items.into_iter().collect()
}

fn names(pairs: &[(&str, &str)]) -> BTreeMap<IpAddr, String> {
    pairs
        .iter()
        .map(|(address, name)| (ip(address), (*name).to_string()))
        .collect()
}

fn record(section: Section, name: &str, ttl: u32, cache_flush: bool, data: RecordData) -> Record {
    Record {
        section,
        name: name.to_string(),
        ttl,
        cache_flush,
        data,
    }
}

// ---- recorded responses ------------------------------------------------------------------

#[test]
fn dns_printer_response_parses_into_its_records() {
    let response = parsed("mdns_printer.hex");
    assert_eq!(response.id, 0);
    assert!(response.is_response);
    assert!(!response.truncated);
    assert_eq!(response.rcode, 0);
    assert_eq!(response.questions, Vec::<(String, u16)>::new());
    let instance = "office printer._ipp._tcp.local";
    let expected = vec![
        record(
            Section::Answer,
            "_ipp._tcp.local",
            4500,
            false,
            RecordData::Ptr(instance.to_string()),
        ),
        record(
            Section::Answer,
            instance,
            120,
            true,
            RecordData::Srv {
                priority: 0,
                weight: 0,
                port: 631,
                target: "printer.local".to_string(),
            },
        ),
        record(
            Section::Answer,
            instance,
            4500,
            true,
            RecordData::Txt(
                [
                    "txtvers=1",
                    "qtotal=1",
                    "rp=ipp/print",
                    "ty=Example Printer 9000",
                    "product=(Example 9000)",
                    "adminurl=http://printer.local:80/",
                    "pdl=application/pdf,image/urf",
                ]
                .map(String::from)
                .to_vec(),
            ),
        ),
        record(
            Section::Answer,
            "printer.local",
            120,
            true,
            RecordData::A(Ipv4Addr::new(192, 0, 2, 40)),
        ),
        record(
            Section::Additional,
            "printer.local",
            120,
            true,
            RecordData::Other(47),
        ),
    ];
    assert_eq!(response.records, expected);
}

#[test]
fn dns_printer_findings() {
    let response = parsed("mdns_printer.hex");
    let printer = ip("192.0.2.40");
    let findings = mdns::interpret(printer, &response);
    assert_eq!(
        findings,
        NameFindings {
            addresses: set([printer]),
            names: names(&[("192.0.2.40", "printer.local")]),
            services: BTreeMap::from([(printer, set([631]))]),
            os: BTreeMap::new(),
        }
    );
    assert!(!findings.is_empty());
}

#[test]
fn dns_linux_host_findings_cover_both_address_families() {
    let response = parsed("mdns_nas.hex");
    assert_eq!(response.records.len(), 9);
    assert!(response.records.iter().any(|r| r.data
        == RecordData::Hinfo {
            cpu: "X86_64".to_string(),
            os: "LINUX".to_string(),
        }));
    assert!(
        response
            .records
            .iter()
            .any(|r| r.data == RecordData::Txt(Vec::new())
                || r.data == RecordData::Txt(vec![String::new()]))
    );
    let v4 = ip("192.0.2.41");
    let v6 = ip("2001:db8::41");
    let findings = mdns::interpret(v4, &response);
    assert_eq!(findings.addresses, set([v4, v6]));
    assert_eq!(
        findings.names,
        names(&[("192.0.2.41", "nas.local"), ("2001:db8::41", "nas.local")])
    );
    // The workstation marker on port 9 is not a service; ssh on 22 is.
    assert_eq!(
        findings.services,
        BTreeMap::from([(v4, set([22])), (v6, set([22]))])
    );
    assert_eq!(
        findings.os,
        BTreeMap::from([
            (v4, ("Linux".to_string(), 60)),
            (v6, ("Linux".to_string(), 60)),
        ])
    );
}

#[test]
fn dns_mac_findings_use_the_model_and_the_os_version() {
    let response = parsed("mdns_studio.hex");
    let mac = ip("192.0.2.42");
    let findings = mdns::interpret(mac, &response);
    assert_eq!(findings.addresses, set([mac]));
    assert_eq!(findings.names, names(&[("192.0.2.42", "studio.local")]));
    // Port 0 of the device-info service is not a service.
    assert!(findings.services.is_empty());
    // model= gives 60, osxvers= gives 70; the higher confidence wins inside one message.
    assert_eq!(
        findings.os,
        BTreeMap::from([(mac, ("macOS".to_string(), 70))])
    );
}

#[test]
fn dns_esphome_findings() {
    let response = parsed("mdns_esphome.hex");
    let node = ip("192.0.2.43");
    let findings = mdns::interpret(node, &response);
    assert_eq!(findings.names, names(&[("192.0.2.43", "sensor.local")]));
    assert_eq!(findings.services, BTreeMap::from([(node, set([6053]))]));
    assert_eq!(
        findings.os,
        BTreeMap::from([(node, ("ESPHome".to_string(), 60))])
    );
}

#[test]
fn dns_service_browse_lists_the_service_types() {
    let response = parsed("mdns_services_browse.hex");
    assert_eq!(
        mdns::service_types(&response),
        vec!["_ipp._tcp.local", "_ssh._tcp.local", "_http._tcp.local"]
    );
    let source = ip("192.0.2.60");
    let findings = mdns::interpret(source, &response);
    assert_eq!(findings.addresses, set([source]));
    assert!(findings.names.is_empty() && findings.services.is_empty() && findings.os.is_empty());
}

#[test]
fn dns_unicast_reverse_answer_names_the_address() {
    let response = parsed("mdns_reverse_ptr.hex");
    assert_eq!(response.id, 0x1234);
    assert_eq!(
        response.questions,
        vec![("40.2.0.192.in-addr.arpa".to_string(), 12)]
    );
    let printer = ip("192.0.2.40");
    assert_eq!(ptr_names(&response, printer), vec!["printer.local"]);
    assert_eq!(ptr_names(&response, ip("192.0.2.41")), Vec::<String>::new());
    let findings = mdns::interpret(printer, &response);
    assert_eq!(findings.addresses, set([printer]));
    assert_eq!(findings.names, names(&[("192.0.2.40", "printer.local")]));
}

#[test]
fn dns_a_query_with_known_answers_is_not_interpreted() {
    let response = parsed("mdns_query_qu.hex");
    assert!(!response.is_response);
    assert_eq!(
        response.questions,
        vec![("_services._dns-sd._udp.local".to_string(), 12)]
    );
    assert_eq!(response.records.len(), 1);
    assert_eq!(mdns::service_types(&response), Vec::<String>::new());
    assert!(mdns::interpret(ip("192.0.2.61"), &response).is_empty());
    assert!(llmnr::interpret(ip("192.0.2.61"), &response).is_empty());
}

#[test]
fn dns_llmnr_a_answer_names_the_host() {
    let response = parsed("llmnr_a.hex");
    assert_eq!(response.id, 0x5a5a);
    assert_eq!(response.questions, vec![("fileserver".to_string(), 1)]);
    let host = ip("192.0.2.50");
    let findings = llmnr::interpret(host, &response);
    assert_eq!(
        findings,
        NameFindings {
            addresses: set([host]),
            names: names(&[("192.0.2.50", "fileserver")]),
            services: BTreeMap::new(),
            os: BTreeMap::new(),
        }
    );
}

#[test]
fn dns_llmnr_ptr_answer_names_the_ipv6_address() {
    let response = parsed("llmnr_ptr.hex");
    let host = ip("2001:db8::50");
    assert_eq!(ptr_names(&response, host), vec!["fileserver"]);
    let findings = llmnr::interpret(host, &response);
    assert_eq!(findings.addresses, set([host]));
    assert_eq!(findings.names, names(&[("2001:db8::50", "fileserver")]));
}

#[test]
fn dns_resolver_answer_has_three_sections_and_no_opt_record() {
    let response = parsed("dns_reverse_resolver.hex");
    assert_eq!(response.id, 0xbeef);
    assert!(response.is_response);
    assert_eq!(response.rcode, 0);
    assert_eq!(
        response.questions,
        vec![("7.100.51.198.in-addr.arpa".to_string(), 12)]
    );
    assert_eq!(
        response.records,
        vec![
            record(
                Section::Answer,
                "7.100.51.198.in-addr.arpa",
                3600,
                false,
                RecordData::Ptr("gw.example.net".to_string()),
            ),
            record(
                Section::Authority,
                "100.51.198.in-addr.arpa",
                3600,
                false,
                RecordData::Other(2),
            ),
            record(
                Section::Additional,
                "ns1.example.net",
                3600,
                false,
                RecordData::A(Ipv4Addr::new(198, 51, 100, 53)),
            ),
        ],
        "the OPT record carries a payload size in its class and is skipped"
    );
    assert_eq!(
        ptr_names(&response, ip("198.51.100.7")),
        vec!["gw.example.net"]
    );
}

// ---- malformed input ---------------------------------------------------------------------

#[test]
fn dns_a_truncated_header_is_an_error() {
    let error = parse_response(&fixture("bad_truncated_header.hex")).unwrap_err();
    assert!(error.detail().contains("header"), "{error}");
}

#[test]
fn dns_a_compression_loop_ends_the_records_and_keeps_what_was_read() {
    let response = parsed("bad_compression_loop.hex");
    assert_eq!(
        response.records,
        vec![record(
            Section::Answer,
            "printer.local",
            120,
            true,
            RecordData::A(Ipv4Addr::new(192, 0, 2, 40)),
        )]
    );
}

#[test]
fn dns_a_record_with_a_bad_length_is_skipped() {
    let response = parsed("bad_record_length.hex");
    assert_eq!(response.records.len(), 1, "{:?}", response.records);
    assert_eq!(response.records[0].name, "nas.local");
    assert_eq!(
        response.records[0].data,
        RecordData::Aaaa("2001:db8::41".parse().unwrap())
    );
}

#[test]
fn dns_an_oversized_message_is_refused() {
    let bytes = fixture("bad_oversized.hex");
    assert_eq!(bytes.len(), MAX_MESSAGE_LEN + 1);
    let error = parse_response(&bytes).unwrap_err();
    assert!(error.detail().contains("9001"), "{error}");
    // The same message is well formed once it fits: cut the last TXT string and its length.
    let mut shorter = bytes[..bytes.len() - 10].to_vec();
    let rdlen_at = 12 + 9 + 2 + 2 + 4;
    let rdlen = u16::from_be_bytes([shorter[rdlen_at], shorter[rdlen_at + 1]]) - 10;
    shorter[rdlen_at..rdlen_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    let response = parse_response(&shorter).expect("8991 bytes are fine");
    assert_eq!(response.records.len(), 1);
    match &response.records[0].data {
        RecordData::Txt(strings) => {
            assert_eq!(strings.len(), 35);
            assert!(strings.iter().all(|s| s.len() == MAX_TEXT_CHARS));
        }
        other => panic!("expected TXT, got {other:?}"),
    }
}

// ---- wire-level cases built with the same library ----------------------------------------

fn name(text: &str) -> Name<Vec<u8>> {
    Name::vec_from_str(text).unwrap()
}

fn response_message(fill: impl FnOnce(&mut AnswerBuilder<Vec<u8>>)) -> Vec<u8> {
    let mut builder = MessageBuilder::new_vec().answer();
    builder.header_mut().set_qr(true);
    builder.header_mut().set_aa(true);
    fill(&mut builder);
    builder.finish()
}

fn txt_data(strings: &[&[u8]]) -> Txt<Vec<u8>> {
    let mut wire = Vec::new();
    for string in strings {
        wire.push(u8::try_from(string.len()).unwrap());
        wire.extend_from_slice(string);
    }
    Txt::from_octets(wire).unwrap()
}

#[test]
fn dns_records_of_other_classes_are_skipped_and_the_cache_flush_bit_is_split_off() {
    let bytes = response_message(|b| {
        let a = |last| A::new(Ipv4Addr::new(192, 0, 2, last));
        b.push((name("in.local"), Class::IN, 10, a(1))).unwrap();
        b.push((name("flush.local"), Class::from_int(0x8001), 11, a(2)))
            .unwrap();
        b.push((name("chaos.local"), Class::CH, 12, a(3))).unwrap();
        b.push((name("chaos-flush.local"), Class::from_int(0x8003), 13, a(4)))
            .unwrap();
        b.push((name("any.local"), Class::ANY, 14, a(5))).unwrap();
    });
    let response = parse_response(&bytes).unwrap();
    let seen: Vec<(&str, bool)> = response
        .records
        .iter()
        .map(|r| (r.name.as_str(), r.cache_flush))
        .collect();
    assert_eq!(seen, vec![("in.local", false), ("flush.local", true)]);
}

#[test]
fn dns_at_most_256_records_are_read() {
    let bytes = response_message(|b| {
        for index in 0..300u16 {
            let [high, low] = index.to_be_bytes();
            b.push((
                name(&format!("h{index}.local")),
                Class::IN,
                10,
                A::new(Ipv4Addr::new(192, 0, high, low)),
            ))
            .unwrap();
        }
    });
    let response = parse_response(&bytes).unwrap();
    assert_eq!(response.records.len(), MAX_RECORDS);
    assert_eq!(response.records[255].name, "h255.local");
    // The addresses of one message are bounded as well; none of them is routable here, but
    // the findings stay consistent.
    let findings = mdns::interpret(ip("192.0.2.9"), &response);
    assert!(findings.addresses.len() <= 256);
}

#[test]
fn dns_at_most_32_questions_are_read() {
    let mut builder = MessageBuilder::new_vec().question();
    for index in 0..40 {
        builder
            .push((name(&format!("q{index}.local")), Rtype::A))
            .unwrap();
    }
    let response = parse_response(&builder.finish()).unwrap();
    assert_eq!(response.questions.len(), MAX_QUESTIONS);
    assert_eq!(response.questions[0].0, "q0.local");
}

#[test]
fn dns_flags_and_the_response_code_are_reported() {
    let mut builder = MessageBuilder::new_vec().answer();
    builder.header_mut().set_id(0xabcd);
    builder.header_mut().set_qr(true);
    builder.header_mut().set_tc(true);
    builder
        .header_mut()
        .set_rcode(domain::base::iana::Rcode::NXDOMAIN);
    let response = parse_response(&builder.finish()).unwrap();
    assert_eq!(response.id, 0xabcd);
    assert!(response.is_response);
    assert!(response.truncated);
    assert_eq!(response.rcode, 3);
    assert!(mdns::interpret(ip("192.0.2.1"), &response).is_empty());
}

#[test]
fn dns_names_and_text_are_lower_case_clean_and_bounded() {
    let bytes = response_message(|b| {
        b.push((
            name("Printer.LOCAL"),
            Class::IN,
            10,
            A::new(Ipv4Addr::new(192, 0, 2, 70)),
        ))
        .unwrap();
        let long = vec![b'z'; 255];
        b.push((
            name("text.local"),
            Class::IN,
            10,
            txt_data(&[
                b"a\x00b\x1b[0m\x7f",
                b"\xe2\x80\xaeevil",
                b"caf\xc3\xa9",
                b"\xff\xfe",
                &long,
            ]),
        ))
        .unwrap();
        b.push((
            name("hinfo.local"),
            Class::IN,
            10,
            Hinfo::new(
                CharStr::from_octets(b"cpu\x01".to_vec()).unwrap(),
                CharStr::from_octets(b"os\x00 name".to_vec()).unwrap(),
            ),
        ))
        .unwrap();
    });
    let response = parse_response(&bytes).unwrap();
    assert_eq!(response.records[0].name, "printer.local");
    assert_eq!(
        response.records[1].data,
        RecordData::Txt(vec![
            "ab[0m".to_string(),
            "evil".to_string(),
            "caf\u{e9}".to_string(),
            "\u{fffd}\u{fffd}".to_string(),
            "z".repeat(255),
        ])
    );
    assert_eq!(
        response.records[2].data,
        RecordData::Hinfo {
            cpu: "cpu".to_string(),
            os: "os name".to_string(),
        }
    );
}

#[test]
fn dns_labels_with_control_bytes_lose_them() {
    let mut message = response_message(|b| {
        b.push((
            name("xxxx.local"),
            Class::IN,
            10,
            A::new(Ipv4Addr::new(192, 0, 2, 71)),
        ))
        .unwrap();
    });
    // Replace the label "xxxx" in place: a bell, an escape, a delete and a letter.
    let at = message.windows(4).position(|w| w == b"xxxx").unwrap();
    message[at..at + 4].copy_from_slice(&[0x07, 0x1b, 0x7f, b'k']);
    let response = parse_response(&message).unwrap();
    assert_eq!(response.records[0].name, "k.local");
}

#[test]
fn dns_ptr_and_srv_targets_are_read_through_compression() {
    let bytes = response_message(|b| {
        b.push((
            name("_ipp._tcp.local"),
            Class::IN,
            4500,
            Ptr::new(name(r"Lab\ Printer._ipp._tcp.local")),
        ))
        .unwrap();
        b.push((
            name(r"Lab\ Printer._ipp._tcp.local"),
            Class::IN,
            120,
            Srv::new(1, 2, 631, name("lab-printer.local")),
        ))
        .unwrap();
    });
    let response = parse_response(&bytes).unwrap();
    assert_eq!(
        response.records[0].data,
        RecordData::Ptr("lab printer._ipp._tcp.local".to_string())
    );
    assert_eq!(
        response.records[1].data,
        RecordData::Srv {
            priority: 1,
            weight: 2,
            port: 631,
            target: "lab-printer.local".to_string(),
        }
    );
}

#[test]
fn dns_a_built_query_is_parsed_back() {
    let options = QueryOptions {
        id: 7,
        recursion_desired: true,
        unicast_response: false,
    };
    let ip = ip("2001:db8::50");
    let bytes = build_query(&reverse_name(ip), QueryType::Ptr, options).unwrap();
    let query = parse_response(&bytes).unwrap();
    assert_eq!(query.id, 7);
    assert!(!query.is_response);
    assert_eq!(query.questions, vec![(reverse_name(ip), 12)]);
    assert_eq!(query.records, Vec::<Record>::new());
}

// ---- merging -----------------------------------------------------------------------------

#[test]
fn dns_merge_keeps_first_names_and_guesses_and_unites_the_sets() {
    let a = ip("192.0.2.40");
    let b = ip("192.0.2.41");
    let mut first = NameFindings {
        addresses: set([a]),
        names: BTreeMap::from([(a, "first.local".to_string())]),
        services: BTreeMap::from([(a, set([80]))]),
        os: BTreeMap::from([(a, ("Linux".to_string(), 60))]),
    };
    let second = NameFindings {
        addresses: set([a, b]),
        names: BTreeMap::from([(a, "second.local".to_string()), (b, "b.local".to_string())]),
        services: BTreeMap::from([(a, set([22, 80])), (b, set([443]))]),
        os: BTreeMap::from([
            (a, ("Windows".to_string(), 90)),
            (b, ("macOS".to_string(), 70)),
        ]),
    };
    first.merge(second);
    assert_eq!(first.addresses, set([a, b]));
    assert_eq!(first.names[&a], "first.local");
    assert_eq!(first.names[&b], "b.local");
    assert_eq!(first.services[&a], set([22, 80]));
    assert_eq!(first.services[&b], set([443]));
    assert_eq!(first.os[&a], ("Linux".to_string(), 60));
    assert_eq!(first.os[&b], ("macOS".to_string(), 70));

    let mut empty = NameFindings::default();
    assert!(empty.is_empty());
    empty.merge(NameFindings::default());
    assert!(empty.is_empty());
    empty.merge(first.clone());
    assert_eq!(empty, first);
}

// ---- hostile input -----------------------------------------------------------------------

/// Runs everything a received datagram goes through and checks the bounds.
fn exercise(bytes: &[u8]) {
    let Ok(response) = parse_response(bytes) else {
        return;
    };
    assert!(response.records.len() <= MAX_RECORDS);
    assert!(response.questions.len() <= MAX_QUESTIONS);
    for record in &response.records {
        assert_text(&record.name);
        match &record.data {
            RecordData::Ptr(text) => assert_text(text),
            RecordData::Srv { target, .. } => assert_text(target),
            RecordData::Txt(strings) => strings.iter().for_each(|s| assert_text(s)),
            RecordData::Hinfo { cpu, os } => {
                assert_text(cpu);
                assert_text(os);
            }
            _ => {}
        }
    }
    for source in [ip("192.0.2.1"), ip("2001:db8::1"), ip("127.0.0.1")] {
        for findings in [
            mdns::interpret(source, &response),
            llmnr::interpret(source, &response),
        ] {
            assert!(findings.addresses.len() <= 256);
            for key in findings
                .names
                .keys()
                .chain(findings.services.keys())
                .chain(findings.os.keys())
            {
                assert!(
                    findings.addresses.contains(key),
                    "{key} has no address entry"
                );
            }
            for ports in findings.services.values() {
                assert!(!ports.contains(&0));
            }
        }
        for target in [source, ip("192.0.2.40"), ip("198.51.100.7")] {
            let _ = ptr_names(&response, target);
        }
    }
    assert!(mdns::service_types(&response).len() <= 64);
}

fn assert_text(text: &str) {
    assert!(
        text.chars().count() <= MAX_TEXT_CHARS,
        "{} characters",
        text.chars().count()
    );
    assert!(
        !text.chars().any(char::is_control),
        "control character in {text:?}"
    );
}

#[test]
fn dns_every_truncation_and_byte_change_of_every_fixture_is_handled() {
    for name in FIXTURES {
        let original = fixture(name);
        for cut in 0..=original.len() {
            exercise(&original[..cut]);
        }
        for position in 0..original.len() {
            for value in [0x00, 0x01, 0x3f, 0x40, 0x80, 0xc0, 0xff] {
                let mut changed = original.clone();
                changed[position] = value;
                exercise(&changed);
            }
        }
    }
}

proptest! {
    #[test]
    fn dns_arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        exercise(&bytes);
    }

    #[test]
    fn dns_arbitrary_bytes_after_a_plausible_header_never_panic(
        flags in any::<u16>(),
        counts in proptest::array::uniform4(0u16..64),
        body in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut message = vec![0x12, 0x34];
        message.extend_from_slice(&flags.to_be_bytes());
        for count in counts {
            message.extend_from_slice(&count.to_be_bytes());
        }
        message.extend_from_slice(&body);
        exercise(&message);
    }

    #[test]
    fn dns_truncated_fixtures_never_panic(index in 0..FIXTURES.len(), cut in 0usize..2048) {
        let original = fixture(FIXTURES[index]);
        let end = cut.min(original.len());
        exercise(&original[..end]);
    }

    #[test]
    fn dns_mutated_fixtures_never_panic(
        index in 0..FIXTURES.len(),
        flips in proptest::collection::vec((0usize..2048, any::<u8>()), 1..6),
    ) {
        let mut bytes = fixture(FIXTURES[index]);
        for (position, value) in flips {
            let at = position % bytes.len();
            bytes[at] = value;
        }
        exercise(&bytes);
    }

    #[test]
    fn dns_built_queries_always_parse_back(
        labels in proptest::collection::vec("[a-z0-9_-]{1,20}", 1..5),
        id in any::<u16>(),
        rd in any::<bool>(),
        qu in any::<bool>(),
    ) {
        let text = labels.join(".");
        let options = QueryOptions { id, recursion_desired: rd, unicast_response: qu };
        let bytes = build_query(&text, QueryType::Any, options).unwrap();
        let query = parse_response(&bytes).unwrap();
        prop_assert_eq!(query.id, id);
        prop_assert!(!query.is_response);
        prop_assert_eq!(query.questions, vec![(text, 255)]);
    }
}
