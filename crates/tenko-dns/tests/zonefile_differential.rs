//! The differential test of Tenko's zone file reader: the reader of 0.0.10 on `domain`'s
//! zone file scanner (the dev-dependency feature `zonefile`, never shipped; the copy in
//! `zonefile_support`) reads the same text, and the two must agree on every record (owner,
//! type, TTL, wire form of the data, line), every loss (code and line) and the first error
//! (its line).
//!
//! The corpus: the seeds of the fuzz target `dns_zonefile` (the four test zones and the
//! inputs the fuzz target found), the model's record samples written by the writer and read
//! back, the same samples as 0.0.10 wrote them (a file exported by an earlier version still
//! reads to the same records), and a generated corpus of records of every type with random
//! data and random formatting (white space, parentheses across lines with comments, the
//! case of mnemonics, the order of TTL and class, escapes).
//!
//! The accepted differences are listed in [`KNOWN`], each with its reason; every seed that
//! differs must name one in [`SEED_DIFFERENCES`], and every seed named there must still
//! differ, so the list neither hides a new difference nor keeps a stale one.

mod zonefile_support;

use std::{
    fmt::Write as _,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use proptest::prelude::*;
use tenko_core::{
    RequestCtx, SystemComponent,
    dns::{
        DnsName, Origin, Rdata, RecordData, RrSet, Rtype, ScopeName, SvcParam, TextBytes, ZoneId,
    },
    ipam::Stamp,
    serde_util::HexBytes,
};
use tenko_dns::zone::zonefile::{Item, header, presentation, type_name, write_rrset};
use zonefile_support::{Outcome, old_presentation, old_type_name, read_new, read_old};

/// The accepted differences between the two readers: a name and the reason.
const KNOWN: &[(&str, &str)] = &[
    (
        "include-before-records",
        "the reader of 0.0.10 refused a file with $INCLUDE before reading any record; Tenko's \
         reader refuses it at the directive, after the records above it (the same error and \
         line; the import stops at the error either way)",
    ),
    (
        "domain-panics",
        "domain's scanner panics on the input (NLnetLabs/domain#763 and the inputs the fuzz \
         target found); the reader of 0.0.10 refused the known trigger before the scan",
    ),
    (
        "ttl-units",
        "Tenko reads BIND's TTL units (1h30m, 2d, 1w) in TTLs, $TTL, the SOA timers and the \
         RRSIG original TTL; domain reads seconds only",
    ),
    (
        "type-without-parser",
        "a record of a type Tenko reads only in the generic form (LOC, URI, ...) and that is \
         written in its own form is a loss with its line; domain stops the file with a syntax \
         error",
    ),
    (
        "long-txt",
        "a TXT string longer than 255 octets is split into strings of at most 255 octets, as \
         the model splits it (DNS-24); domain refuses it",
    ),
    (
        "raw-octets-in-text",
        "Tenko takes octets outside printable ASCII (UTF-8, tabs) inside a character string as \
         they are; domain refuses them",
    ),
    (
        "error-line",
        "Tenko names the line of the token where an error is, and for a quote left open the \
         line that opened it; the reader of 0.0.10 named the line where the entry (or the \
         blank lines before it) started, or for a quote left open the line its scanner had \
         reached",
    ),
    (
        "record-lines",
        "the reader of 0.0.10 gave a record the line where the previous entry ended when a \
         directive came between them; Tenko gives the line of the record's first token, \
         exactly (the generated corpus checks it)",
    ),
    (
        "svcb-key-digits",
        "domain refuses the digit 9 and the letter z in an SVCB parameter key (its character \
         check ends one short: `key65009`, `key9`); the generated corpus leaves such keys out",
    ),
    (
        "svcb-writer",
        "domain writes SVCB and HTTPS parameters in a form neither reader reads back (`alpn` \
         as wire octets, `nodefaultalpn`); Tenko writes RFC 9460's form",
    ),
];

/// The seeds that differ, with the entry of [`KNOWN`] each one meets.
const SEED_DIFFERENCES: &[(&str, &str)] = &[
    ("conflicts.zone", "include-before-records"),
    ("units.zone", "ttl-units"),
    ("unknown-types.zone", "type-without-parser"),
    ("long-txt.zone", "long-txt"),
    ("utf8-text.zone", "raw-octets-in-text"),
];

fn apex() -> DnsName {
    DnsName::new("example.test").expect("name")
}

/// A comparable view of an item: records by owner, type, TTL and data, losses by code (the
/// reasons are worded by each reader, and the lines of 0.0.10 were approximate: KNOWN
/// "record-lines"; the generated corpus checks Tenko's lines against the lines it wrote).
fn view(item: &Item) -> String {
    match item {
        Item::Record(record) => format!(
            "{} {} {} {:?}",
            record.name, record.rtype, record.ttl, record.rdata
        ),
        Item::Loss(loss) => format!("loss {}", loss.code),
    }
}

/// The difference between the two readers on `text`, or `None` when they agree.
fn difference(text: &str) -> Option<String> {
    let new = read_new(text, &apex(), 256);
    let Some(old) = read_old(text, &apex(), 256) else {
        return Some("domain-panics".to_owned());
    };
    describe(&new, &old)
}

fn describe(new: &Outcome, old: &Outcome) -> Option<String> {
    let new_items: Vec<String> = new.items.iter().map(view).collect();
    let old_items: Vec<String> = old.items.iter().map(view).collect();
    if new_items != old_items {
        return Some(format!(
            "items differ:\n  new {new_items:#?}\n  old {old_items:#?}\n  new error {:?}\n  old error {:?}",
            new.error, old.error
        ));
    }
    match (&new.error, &old.error) {
        (None, None) => None,
        // The line of 0.0.10 is where the entry (or the blank lines before it) started,
        // Tenko's the line of the token in error: KNOWN "error-line".
        (Some((new_line, _)), Some((old_line, _))) if old_line <= new_line => None,
        _ => Some(format!(
            "errors differ: new {:?}, old {:?}",
            new.error, old.error
        )),
    }
}

fn seeds() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/dns_zonefile");
    let mut seeds: Vec<(String, String)> = std::fs::read_dir(&dir)
        .expect("the seed directory")
        .map(|entry| {
            let path = entry.expect("entry").path();
            let bytes = std::fs::read(&path).expect("seed");
            (
                path.file_name()
                    .expect("name")
                    .to_string_lossy()
                    .into_owned(),
                // The fuzz target reads the input this way.
                String::from_utf8_lossy(&bytes).into_owned(),
            )
        })
        .collect();
    seeds.sort();
    seeds
}

#[test]
fn the_known_differences_are_named_and_explained_once() {
    for (index, (name, reason)) in KNOWN.iter().enumerate() {
        assert!(reason.len() > 40, "{name} needs its reason");
        assert!(
            KNOWN[..index].iter().all(|(other, _)| other != name),
            "{name} twice"
        );
    }
    for (_, known) in SEED_DIFFERENCES {
        assert!(
            KNOWN.iter().any(|(name, _)| name == known),
            "{known} is not in KNOWN"
        );
    }
}

#[test]
fn the_readers_agree_on_every_seed_but_the_known_differences() {
    let seeds = seeds();
    assert!(seeds.len() >= 5, "{seeds:?}");
    let mut agreed = 0;
    for (name, text) in &seeds {
        let listed = SEED_DIFFERENCES.iter().find(|(seed, _)| seed == name);
        match (difference(text), listed) {
            (None, None) => agreed += 1,
            (Some(difference), None) => {
                panic!("{name}: the readers differ and no known difference names it: {difference}")
            }
            (None, Some((_, known))) => {
                panic!("{name}: listed as {known}, but the readers agree")
            }
            (Some(difference), Some((_, known))) => {
                println!("{name}: {known}: {difference}");
            }
        }
    }
    println!(
        "{agreed} of {} seeds read the same; {} differ as listed",
        seeds.len(),
        seeds.len() - agreed
    );
}

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn param(key: u16, value: &[u8]) -> SvcParam {
    SvcParam {
        key,
        value: HexBytes(value.to_vec()),
    }
}

/// Samples of every type of the model and of the opaque types with a form of their own.
#[allow(clippy::too_many_lines, reason = "one sample per record type")]
fn samples() -> Vec<RecordData> {
    vec![
        RecordData::A {
            address: Ipv4Addr::new(192, 0, 2, 1),
        },
        RecordData::Aaaa {
            address: "2001:db8::1".parse().expect("ip"),
        },
        RecordData::Cname {
            target: name("www.example.test"),
        },
        RecordData::Dname {
            target: name("example.net"),
        },
        RecordData::Mx {
            preference: 10,
            exchange: name("mail.example.test"),
        },
        RecordData::Ns {
            host: name("ns1.example.test"),
        },
        RecordData::Ptr {
            target: name("host.example.test"),
        },
        RecordData::Soa {
            mname: name("ns1.example.test"),
            rname: name("hostmaster.example.test"),
            serial: 2_026_101_701,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 300,
        },
        RecordData::Srv {
            priority: 0,
            weight: 5,
            port: 389,
            target: name("_dc1.example.test"),
        },
        RecordData::txt("v=spf1 -all"),
        RecordData::Txt {
            strings: vec![
                TextBytes(b"a \"q\" \\ ;()".to_vec()),
                TextBytes(vec![0, 9, 127, 0xc3, 0xa5]),
                TextBytes::default(),
            ],
        },
        RecordData::Caa {
            flags: 0,
            tag: "issue".to_owned(),
            value: TextBytes::from_text("ca.example.net"),
        },
        RecordData::Caa {
            flags: 128,
            tag: "iodef".to_owned(),
            value: TextBytes::from_text("mailto:x@example.test; \"q\""),
        },
        RecordData::Ds {
            key_tag: 12345,
            algorithm: 13,
            digest_type: 2,
            digest: HexBytes(vec![0xab; 32]),
        },
        RecordData::Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: HexBytes(vec![1; 64]),
        },
        RecordData::Rrsig {
            type_covered: Rtype::A,
            algorithm: 13,
            labels: 3,
            original_ttl: 300,
            expiration: 1_800_000_000,
            inception: 1_790_000_000,
            key_tag: 12345,
            signer: name("example.test"),
            signature: HexBytes(vec![2; 64]),
        },
        RecordData::Nsec {
            next: name("b.example.test"),
            types: vec![Rtype::A, Rtype::MX, Rtype::RRSIG, Rtype::NSEC, Rtype::CAA],
        },
        RecordData::Nsec {
            next: name("*.b.example.test"),
            types: vec![Rtype(1234), Rtype(13), Rtype(99)],
        },
        RecordData::Nsec3 {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: HexBytes(Vec::new()),
            next_hashed: HexBytes(vec![7; 20]),
            types: vec![Rtype::A, Rtype::RRSIG],
        },
        RecordData::Nsec3param {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: HexBytes(vec![0xaa, 0xbb]),
        },
        RecordData::Tlsa {
            usage: 3,
            selector: 1,
            matching_type: 1,
            data: HexBytes(vec![9; 32]),
        },
        RecordData::Svcb {
            priority: 1,
            target: DnsName::root(),
            params: vec![param(1, b"\x02h2"), param(3, &[0x01, 0xbb])],
        },
        RecordData::Https {
            priority: 1,
            target: name("svc.example.net"),
            params: vec![
                param(0, &[0, 1, 0, 3]),
                param(1, b"\x02h2\x02h3"),
                param(2, b""),
                param(3, &[1, 187]),
                param(4, &[192, 0, 2, 1, 192, 0, 2, 2]),
                param(5, &[1, 2, 3, 4]),
                param(
                    6,
                    &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ),
                param(65_000, b"value"),
            ],
        },
        RecordData::Https {
            priority: 0,
            target: name("cdn.example.net"),
            params: Vec::new(),
        },
        RecordData::Unknown {
            rtype: Rtype(65280),
            data: HexBytes(vec![1, 2, 3]),
        },
        RecordData::Unknown {
            rtype: Rtype(65280),
            data: HexBytes(Vec::new()),
        },
        RecordData::Unknown {
            rtype: Rtype(13),
            data: HexBytes(b"\x03cpu\x02os".to_vec()),
        },
        RecordData::Unknown {
            rtype: Rtype(59),
            data: HexBytes(vec![0x30, 0x39, 13, 2, 0xab, 0xcd]),
        },
        RecordData::Unknown {
            rtype: Rtype(60),
            data: HexBytes(vec![1, 1, 3, 13, 1, 2, 3, 4]),
        },
        RecordData::Unknown {
            rtype: Rtype(44),
            data: HexBytes(vec![1, 2, 0xab, 0xcd]),
        },
        RecordData::Unknown {
            rtype: Rtype(35),
            data: HexBytes(
                b"\x00\x0a\x00\x64\x01u\x07E2U+sip\x00\x03www\x07example\x04test\x00".to_vec(),
            ),
        },
        RecordData::Unknown {
            rtype: Rtype(17),
            data: HexBytes(b"\x05admin\x04mail\x00\x03txt\x07example\x04test\x00".to_vec()),
        },
        RecordData::Unknown {
            rtype: Rtype(99),
            data: HexBytes(b"\x05v=spf".to_vec()),
        },
    ]
}

fn line(rtype: Rtype, text: &str) -> String {
    format!("x 300 IN {} {text}\n", type_name(rtype))
}

#[test]
fn the_readers_agree_on_the_model_samples_as_tenko_writes_them() {
    for sample in samples() {
        let rtype = sample.rtype();
        let rdata = Rdata::from_data(&sample);
        let text = line(rtype, &presentation(rtype, &rdata).expect("presents"));
        let new = read_new(&text, &apex(), 1);
        assert!(new.error.is_none(), "{text}: {new:?}");
        let Some(Item::Record(record)) = new.items.first() else {
            panic!("{text}: {new:?}");
        };
        assert_eq!((record.rtype, &record.rdata), (rtype, &rdata), "{text}");
        assert_eq!(difference(&text), None, "{text}");
    }
}

#[test]
fn files_written_by_earlier_versions_read_to_the_same_records() {
    let mut read = 0;
    for sample in samples() {
        let rtype = sample.rtype();
        let rdata = Rdata::from_data(&sample);
        let Some(old) = old_presentation(rtype, &rdata) else {
            continue;
        };
        let text = format!("x 300 IN {} {old}\n", old_type_name(rtype));
        let new = read_new(&text, &apex(), 1);
        let svcb_params = matches!(&sample, RecordData::Svcb { params, .. } | RecordData::Https { params, .. } if !params.is_empty());
        if svcb_params {
            // KNOWN "svcb-writer".
            continue;
        }
        assert!(new.error.is_none(), "{text}: {new:?}");
        let Some(Item::Record(record)) = new.items.first() else {
            panic!("{text}: {new:?}");
        };
        assert_eq!((record.rtype, &record.rdata), (rtype, &rdata), "{text}");
        read += 1;
    }
    assert!(read >= 25, "{read}");
}

/// An RRset of the zone `example.test` as the export holds it.
fn rrset(name: DnsName, rtype: Rtype, ttl: u32, rdata: Vec<Rdata>) -> RrSet {
    let cx = RequestCtx::system(SystemComponent::Dns);
    RrSet {
        zone: ZoneId::generate(),
        scope: ScopeName::DEFAULT,
        name,
        rtype,
        ttl,
        rdata,
        origin: Origin::Manual,
        key: None,
        principal: None,
        updated: Stamp::new(cx.now, cx.principal),
    }
}

/// The records of an export read back.
fn read_export(rrsets: &[RrSet]) -> Vec<(DnsName, Rtype, u32, Rdata)> {
    let mut text = header(&apex(), 3_600);
    for rrset in rrsets {
        write_rrset(&mut text, &apex(), rrset).expect("writes");
    }
    let new = read_new(&text, &apex(), 1);
    assert!(new.error.is_none(), "{text}\n{new:?}");
    new.items
        .into_iter()
        .map(|item| match item {
            Item::Record(record) => (record.name, record.rtype, record.ttl, record.rdata),
            Item::Loss(loss) => panic!("{text}\n{loss:?}"),
        })
        .collect()
}

#[test]
fn the_seeds_written_as_an_export_read_back_to_the_same_records() {
    let mut checked = 0;
    for (name, text) in seeds() {
        let read = read_new(&text, &apex(), 256);
        let records: Vec<(DnsName, Rtype, u32, Rdata)> = read
            .items
            .into_iter()
            .filter_map(|item| match item {
                Item::Record(record) => Some((record.name, record.rtype, record.ttl, record.rdata)),
                Item::Loss(_) => None,
            })
            .collect();
        if records.is_empty() {
            continue;
        }
        let rrsets: Vec<RrSet> = records
            .iter()
            .map(|(name, rtype, ttl, rdata)| rrset(name.clone(), *rtype, *ttl, vec![rdata.clone()]))
            .collect();
        assert_eq!(read_export(&rrsets), records, "{name}");
        checked += 1;
    }
    assert!(checked >= 8, "{checked}");
}

// ----- the generated corpus -------------------------------------------------------------

fn label() -> impl Strategy<Value = String> {
    "[a-z0-9_-]{1,12}"
}

fn name_strategy() -> impl Strategy<Value = DnsName> {
    (any::<bool>(), prop::collection::vec(label(), 1..=4)).prop_map(|(wildcard, labels)| {
        let mut text = labels.join(".");
        if wildcard {
            text = format!("*.{text}");
        }
        DnsName::new(&text).expect("generated names are valid")
    })
}

fn hex(min: usize, max: usize) -> impl Strategy<Value = HexBytes> {
    prop::collection::vec(any::<u8>(), min..=max).prop_map(HexBytes)
}

fn bitmap() -> impl Strategy<Value = Vec<Rtype>> {
    prop::collection::vec(
        prop::sample::select(vec![
            Rtype::A,
            Rtype::NS,
            Rtype::SOA,
            Rtype::MX,
            Rtype::TXT,
            Rtype::AAAA,
            Rtype::RRSIG,
            Rtype::NSEC,
            Rtype::DNSKEY,
            Rtype::CAA,
            Rtype(13),
            Rtype(99),
            Rtype(1234),
            Rtype(65280),
        ]),
        0..6,
    )
    .prop_map(|mut types| {
        types.sort();
        types.dedup();
        types
    })
}

/// A character string: printable text mostly, any octet sometimes.
fn text_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => "[ -~]{0,40}".prop_map(String::into_bytes),
        1 => prop::collection::vec(any::<u8>(), 0..=max),
    ]
}

fn svc_params() -> impl Strategy<Value = Vec<SvcParam>> {
    let alpn = prop::collection::vec("[a-z0-9]{1,8}", 1..3).prop_map(|ids| {
        let mut value = Vec::new();
        for id in ids {
            value.push(u8::try_from(id.len()).expect("short"));
            value.extend_from_slice(id.as_bytes());
        }
        param(1, &value)
    });
    let port = any::<u16>().prop_map(|port| param(3, &port.to_be_bytes()));
    let v4 = prop::collection::vec(any::<[u8; 4]>(), 1..3)
        .prop_map(|addresses| param(4, &addresses.concat()));
    let v6 = prop::collection::vec(any::<[u8; 16]>(), 1..3)
        .prop_map(|addresses| param(6, &addresses.concat()));
    let ech = prop::collection::vec(any::<u8>(), 1..20).prop_map(|value| param(5, &value));
    // KNOWN "svcb-key-digits": no `9` in a generated key.
    let generic = (
        (65_000u16..=65_088).prop_filter("domain refuses a 9 in a key", |key| {
            !key.to_string().contains('9')
        }),
        "[a-z0-9]{0,10}",
    )
        .prop_map(|(key, value)| param(key, value.as_bytes()));
    (
        prop::option::of(alpn),
        any::<bool>(),
        prop::option::of(port),
        prop::option::of(v4),
        prop::option::of(ech),
        prop::option::of(v6),
        prop::option::of(generic),
    )
        .prop_map(|(alpn, no_default, port, v4, ech, v6, generic)| {
            let mut params: Vec<SvcParam> = Vec::new();
            params.extend(alpn);
            if no_default && !params.is_empty() {
                params.push(param(2, b""));
            }
            params.extend(port);
            params.extend(v4);
            params.extend(ech);
            params.extend(v6);
            params.extend(generic);
            params
        })
}

/// Valid data of every type of the model and of the opaque types with a form of their own.
#[allow(clippy::too_many_lines, reason = "one strategy per record type")]
fn record_data() -> impl Strategy<Value = RecordData> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|o| RecordData::A {
            address: Ipv4Addr::from(o)
        }),
        any::<[u8; 16]>().prop_map(|o| RecordData::Aaaa {
            address: Ipv6Addr::from(o)
        }),
        name_strategy().prop_map(|target| RecordData::Cname { target }),
        name_strategy().prop_map(|target| RecordData::Dname { target }),
        name_strategy().prop_map(|host| RecordData::Ns { host }),
        name_strategy().prop_map(|target| RecordData::Ptr { target }),
        (any::<u16>(), name_strategy()).prop_map(|(preference, exchange)| RecordData::Mx {
            preference,
            exchange
        }),
        (name_strategy(), name_strategy(), any::<[u32; 5]>()).prop_map(|(mname, rname, v)| {
            RecordData::Soa {
                mname,
                rname,
                serial: v[0],
                refresh: v[1],
                retry: v[2],
                expire: v[3],
                minimum: v[4],
            }
        }),
        (any::<[u16; 3]>(), name_strategy()).prop_map(|(v, target)| RecordData::Srv {
            priority: v[0],
            weight: v[1],
            port: v[2],
            target
        }),
        prop::collection::vec(text_bytes(255), 1..4).prop_map(|strings| RecordData::Txt {
            strings: strings.into_iter().map(TextBytes).collect()
        }),
        (any::<u8>(), "[a-z0-9]{1,15}", text_bytes(60)).prop_map(|(flags, tag, value)| {
            RecordData::Caa {
                flags,
                tag,
                value: TextBytes(value),
            }
        }),
        (any::<u16>(), any::<u8>(), any::<u8>(), hex(1, 64)).prop_map(
            |(key_tag, algorithm, digest_type, digest)| RecordData::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest
            }
        ),
        (any::<u16>(), any::<u8>(), hex(1, 100)).prop_map(|(flags, algorithm, public_key)| {
            RecordData::Dnskey {
                flags,
                protocol: 3,
                algorithm,
                public_key,
            }
        }),
        (
            any::<u16>(),
            any::<[u8; 2]>(),
            any::<[u32; 3]>(),
            any::<u16>(),
            name_strategy(),
            hex(1, 100)
        )
            .prop_map(
                |(covered, b, t, key_tag, signer, signature)| RecordData::Rrsig {
                    type_covered: Rtype(covered),
                    algorithm: b[0],
                    labels: b[1],
                    original_ttl: t[0],
                    expiration: t[1],
                    inception: t[2],
                    key_tag,
                    signer,
                    signature
                }
            ),
        (name_strategy(), bitmap()).prop_map(|(next, types)| RecordData::Nsec { next, types }),
        (
            any::<[u8; 2]>(),
            any::<u16>(),
            hex(0, 32),
            hex(1, 32),
            bitmap()
        )
            .prop_map(
                |(b, iterations, salt, next_hashed, types)| RecordData::Nsec3 {
                    hash_algorithm: b[0],
                    flags: b[1],
                    iterations,
                    salt,
                    next_hashed,
                    types
                }
            ),
        (any::<[u8; 2]>(), any::<u16>(), hex(0, 32)).prop_map(|(b, iterations, salt)| {
            RecordData::Nsec3param {
                hash_algorithm: b[0],
                flags: b[1],
                iterations,
                salt,
            }
        }),
        (any::<[u8; 3]>(), hex(1, 64)).prop_map(|(b, data)| RecordData::Tlsa {
            usage: b[0],
            selector: b[1],
            matching_type: b[2],
            data
        }),
        (any::<u16>(), name_strategy(), svc_params()).prop_map(|(priority, target, params)| {
            RecordData::Https {
                priority,
                target,
                params,
            }
        }),
        (any::<u16>(), svc_params()).prop_map(|(priority, params)| RecordData::Svcb {
            priority,
            target: DnsName::root(),
            params
        }),
        (text_bytes(255), text_bytes(255)).prop_map(|(cpu, os)| {
            let mut data = Vec::new();
            for part in [cpu, os] {
                let part = &part[..part.len().min(255)];
                data.push(u8::try_from(part.len()).expect("short"));
                data.extend_from_slice(part);
            }
            RecordData::Unknown {
                rtype: Rtype(13),
                data: HexBytes(data),
            }
        }),
        (any::<[u8; 2]>(), hex(1, 32)).prop_map(|(b, fingerprint)| {
            let mut data = b.to_vec();
            data.extend_from_slice(&fingerprint.0);
            RecordData::Unknown {
                rtype: Rtype(44),
                data: HexBytes(data),
            }
        }),
        (65_280u16..=65_534, hex(0, 64)).prop_map(|(rtype, data)| RecordData::Unknown {
            rtype: Rtype(rtype),
            data
        }),
    ]
}

/// How one record is written: the separators, parentheses, case and order.
#[derive(Debug, Clone)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is one choice of the style"
)]
struct Style {
    separators: Vec<&'static str>,
    parentheses: bool,
    comment: bool,
    lower_type: bool,
    class_first: bool,
    omit_class: bool,
    omit_ttl: bool,
    escape_owner: bool,
}

fn style() -> impl Strategy<Value = Style> {
    (
        prop::collection::vec(prop::sample::select(vec![" ", "\t", "  ", " \t "]), 1..8),
        any::<[bool; 7]>(),
    )
        .prop_map(|(separators, flags)| Style {
            separators,
            parentheses: flags[0],
            comment: flags[1],
            lower_type: flags[2],
            class_first: flags[3],
            omit_class: flags[4],
            omit_ttl: flags[5],
            escape_owner: flags[6],
        })
}

/// Splits presentation data at spaces outside quotes.
fn tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            '"' => {
                quoted = !quoted;
                current.push(c);
            }
            ' ' if !quoted => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// One record in a style.
fn styled(owner: &str, ttl: u32, rtype: Rtype, data: &str, style: &Style) -> String {
    let mut separators = style.separators.iter().cycle();
    let mut sep = || *separators.next().unwrap_or(&" ");
    let owner = if style.escape_owner {
        // The first octet of the owner as `\DDD`.
        let mut bytes = owner.bytes();
        let first = bytes.next().unwrap_or(b'x');
        format!("\\{first:03}{}", owner.get(1..).unwrap_or_default())
    } else {
        owner.to_owned()
    };
    let mut head = vec![owner];
    let ttl = (!style.omit_ttl).then(|| ttl.to_string());
    let class = (!style.omit_class).then(|| "IN".to_owned());
    if style.class_first {
        head.extend(class);
        head.extend(ttl);
    } else {
        head.extend(ttl);
        head.extend(class);
    }
    let name = type_name(rtype);
    head.push(if style.lower_type {
        name.to_ascii_lowercase()
    } else {
        name
    });
    let mut out = String::new();
    for part in &head {
        if !out.is_empty() {
            out.push_str(sep());
        }
        out.push_str(part);
    }
    let data = tokens(data);
    if style.parentheses && !data.is_empty() {
        out.push_str(sep());
        out.push('(');
        for (index, token) in data.iter().enumerate() {
            out.push_str(sep());
            out.push_str(token);
            if index % 2 == 0 {
                if style.comment {
                    out.push_str(" ; a comment ( \" ;");
                }
                out.push('\n');
            }
        }
        out.push_str(sep());
        out.push(')');
    } else {
        for token in &data {
            out.push_str(sep());
            out.push_str(token);
        }
    }
    if style.comment {
        out.push_str(" ; the end");
    }
    out.push('\n');
    out
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1024,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Records of every type with random data, in random styles, several to a file: both
    /// readers read the same records with the same lines, and Tenko's reader reads back
    /// exactly what the model holds.
    #[test]
    fn the_readers_agree_on_generated_records(
        records in prop::collection::vec(
            (label(), 0u32..=2_147_483_647, record_data(), style()),
            1..6,
        )
    ) {
        let mut text = String::from("$ORIGIN example.test.\n");
        let mut expected = Vec::new();
        for (owner, ttl, data, style) in &records {
            let rtype = data.rtype();
            let rdata = Rdata::from_data(data);
            let presented = presentation(rtype, &rdata).expect("presents");
            let ttl = if style.omit_ttl {
                // The last TTL given (the generated file has no $TTL), or 3600.
                expected.last().map_or(3_600, |(_, _, ttl, _, _)| *ttl)
            } else {
                *ttl
            };
            let line = text.lines().count() + 1;
            let _ = write!(text, "{}", styled(owner, ttl, rtype, &presented, style));
            expected.push((line, owner.clone(), ttl, rtype, rdata));
        }
        let new = read_new(&text, &apex(), 1);
        prop_assert!(new.error.is_none(), "{text}\n{new:?}");
        let read: Vec<(usize, String, u32, Rtype, Rdata)> = new
            .items
            .iter()
            .map(|item| match item {
                Item::Record(record) => (
                    record.line,
                    record.name.as_str().strip_suffix(".example.test").unwrap_or_default().to_owned(),
                    record.ttl,
                    record.rtype,
                    record.rdata.clone(),
                ),
                Item::Loss(loss) => panic!("{text}\n{loss:?}"),
            })
            .collect();
        prop_assert_eq!(&read, &expected, "{}", text);
        // TXT and CAA values with raw octets are written escaped, so domain reads them too.
        let difference = difference(&text);
        prop_assert!(difference.is_none(), "{}\n{}", text, difference.unwrap_or_default());
    }

    /// RRsets of every type written as the export writes them read back to the same
    /// RRsets: the records of each in canonical order, the TTL, the owner.
    #[test]
    fn exported_rrsets_read_back_the_same(
        data in prop::collection::vec(record_data(), 1..12),
        ttl in 0u32..=2_147_483_647,
    ) {
        let mut groups: std::collections::BTreeMap<Rtype, Vec<Rdata>> = std::collections::BTreeMap::new();
        for data in &data {
            let rdata = Rdata::from_data(data);
            let group = groups.entry(data.rtype()).or_default();
            if !group.contains(&rdata) {
                group.push(rdata);
            }
        }
        let rrsets: Vec<RrSet> = groups
            .into_iter()
            .enumerate()
            .map(|(index, (rtype, rdata))| {
                rrset(name(&format!("o{index}.example.test")), rtype, ttl, rdata)
            })
            .collect();
        let mut expected = Vec::new();
        for rrset in &rrsets {
            let mut sorted = rrset.rdata.clone();
            sorted.sort();
            for rdata in sorted {
                expected.push((rrset.name.clone(), rrset.rtype, rrset.ttl, rdata));
            }
        }
        prop_assert_eq!(read_export(&rrsets), expected);
    }

    /// TTLs with units read as their seconds (Tenko's reader only; KNOWN "ttl-units").
    #[test]
    fn ttl_units_read_as_seconds(weeks in 0u32..4, days in 0u32..7, hours in 0u32..24, minutes in 0u32..60, seconds in 0u32..60) {
        let total = weeks * 604_800 + days * 86_400 + hours * 3_600 + minutes * 60 + seconds;
        let text = format!("x {weeks}w{days}D{hours}h{minutes}M{seconds}s IN A 192.0.2.1\n$TTL {weeks}W{days}d{hours}H{minutes}m{seconds}\ny A 192.0.2.2\n");
        let new = read_new(&text, &apex(), 1);
        let ttls: Vec<u32> = new.items.iter().map(|item| match item {
            Item::Record(record) => record.ttl,
            Item::Loss(loss) => panic!("{loss:?}"),
        }).collect();
        prop_assert_eq!(ttls, vec![total, total]);
    }
}
