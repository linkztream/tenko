//! The rendering of an entry by its validation state and the client's flags (WP10.0,
//! recursion plan section 2.2): AD for a secure entry, the DNSSEC records only for DO,
//! SERVFAIL with the extended error for a bogus entry unless CD, the lifetime capped by the
//! signatures.

use std::time::{Duration, Instant, SystemTime};

use tenko_core::dns::{ExtendedError, SecurityState};

use super::*;

const A: u16 = 1;
const SOA: u16 = 6;
const RRSIG: u16 = 46;
const NSEC: u16 = 47;

fn wire_name(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in text.split('.').filter(|label| !label.is_empty()) {
        out.push(u8::try_from(label.len()).expect("label"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// A record with its owner in wire form (a pointer or a full name).
struct Rec {
    owner: Vec<u8>,
    rtype: u16,
    ttl: u32,
    data: Vec<u8>,
}

fn at_question(rtype: u16, ttl: u32, data: Vec<u8>) -> Rec {
    Rec {
        owner: vec![0xc0, 0x0c],
        rtype,
        ttl,
        data,
    }
}

fn soa(ttl: u32) -> Rec {
    let mut data = wire_name("ns1.example.test");
    data.extend_from_slice(&wire_name("hostmaster.example.test"));
    for value in [1u32, 3600, 900, 1_209_600, ttl] {
        data.extend_from_slice(&value.to_be_bytes());
    }
    at_question(SOA, ttl, data)
}

/// An RRSIG covering `covered` (the data's content does not matter to the cache).
fn rrsig(covered: u16, ttl: u32) -> Rec {
    let mut data = covered.to_be_bytes().to_vec();
    data.extend_from_slice(&[13, 3]);
    data.extend_from_slice(&ttl.to_be_bytes());
    data.extend_from_slice(&[0; 10]);
    data.extend_from_slice(&wire_name("example.test"));
    data.extend_from_slice(&[0xaa; 64]);
    at_question(RRSIG, ttl, data)
}

fn nsec(ttl: u32) -> Rec {
    let mut data = wire_name("z.example.test");
    data.extend_from_slice(&[0, 1, 0x40]);
    at_question(NSEC, ttl, data)
}

/// An answer to `qname`/`qtype` with three sections and an OPT record.
fn message(qname: &str, qtype: u16, rcode: u8, sections: [&[Rec]; 3]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x4242u16.to_be_bytes());
    out.extend_from_slice(&[0x81, 0x80 | rcode, 0, 1]);
    for (index, section) in sections.iter().enumerate() {
        let count = section.len() + usize::from(index == 2);
        out.extend_from_slice(&u16::try_from(count).expect("count").to_be_bytes());
    }
    out.extend_from_slice(&wire_name(qname));
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    for record in sections.iter().flat_map(|section| section.iter()) {
        out.extend_from_slice(&record.owner);
        out.extend_from_slice(&record.rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&record.ttl.to_be_bytes());
        out.extend_from_slice(&u16::try_from(record.data.len()).expect("len").to_be_bytes());
        out.extend_from_slice(&record.data);
    }
    out.push(0);
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&1232u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0x80, 0, 0, 0]);
    out
}

fn query(qname: &str, qtype: u16, edns: bool) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(&mut out, 0x1234, qname, qtype, edns.then_some(1232));
    out
}

/// A client: `dnssec_ok` with EDNS, `None` without.
fn client(message: &[u8], dnssec_ok: Option<bool>, ad: bool, cd: bool) -> Client<'_> {
    Client {
        message,
        question_end: wire::questions_end(message, 1).expect("question"),
        id: 0x1234,
        rd: true,
        cd,
        ad,
        edns: dnssec_ok.map(|dnssec_ok| ClientEdns {
            udp_size: 1232,
            dnssec_ok,
            cookie: None,
        }),
        max_len: 65_535,
    }
}

/// The types of the records of `out`, by section, and the OPT record's options.
fn sections(out: &[u8]) -> ([Vec<u16>; 3], Vec<u32>, Option<Vec<u8>>) {
    let header = wire::parse_header(out).expect("header");
    let mut pos = wire::questions_end(out, 1).expect("question");
    let mut types: [Vec<u16>; 3] = Default::default();
    let mut ttls = Vec::new();
    let mut options = None;
    let counts = [header.ancount, header.nscount, header.arcount];
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            let record = wire::read_record(out, pos).expect("record");
            if record.rtype == TYPE_OPT {
                options = Some(record.data(out).to_vec());
            } else {
                types[section].push(record.rtype);
                ttls.push(record.ttl);
            }
            pos = record.end();
        }
    }
    assert_eq!(pos, out.len(), "nothing after the records");
    (types, ttls, options)
}

fn key(qname: &str, qtype: u16) -> CacheKey {
    CacheKey::new(None, &wire_name(qname), qtype, 1)
}

fn verdict(state: SecurityState) -> Verdict {
    Verdict {
        state,
        ..Verdict::UNVALIDATED
    }
}

fn signed_answer() -> Vec<u8> {
    message(
        "www.example.test",
        A,
        0,
        [
            &[at_question(A, 300, vec![192, 0, 2, 1]), rrsig(A, 300)],
            &[],
            &[],
        ],
    )
}

#[test]
fn a_secure_entry_sets_ad_and_gives_signatures_to_do_clients_only() {
    let cache = Cache::new(CacheSettings::default());
    let now = Instant::now();
    let k = key("www.example.test", A);
    assert!(cache.insert_with(
        &k,
        &signed_answer(),
        now,
        None,
        &verdict(SecurityState::Secure)
    ));
    let asked = query("www.example.test", A, true);
    let plain = query("www.example.test", A, false);
    let mut out = Vec::with_capacity(65_535);
    let later = now + Duration::from_secs(100);

    let hit = cache.answer(
        &k,
        later,
        &client(&asked, Some(true), false, false),
        &mut out,
    );
    assert_eq!(
        hit,
        Hit::Fresh {
            rcode: 0,
            state: SecurityState::Secure
        }
    );
    let header = wire::parse_header(&out).expect("header");
    assert!(header.ad, "DO asks for AD");
    let (types, ttls, _) = sections(&out);
    assert_eq!(types[0], [A, RRSIG]);
    assert_eq!(ttls, [200, 200]);

    cache.answer(
        &k,
        later,
        &client(&asked, Some(false), true, false),
        &mut out,
    );
    let header = wire::parse_header(&out).expect("header");
    assert!(header.ad, "AD asks for AD");
    let (types, ttls, _) = sections(&out);
    assert_eq!(types[0], [A], "no signatures without DO");
    assert_eq!(ttls, [200]);

    cache.answer(
        &k,
        later,
        &client(&asked, Some(false), false, false),
        &mut out,
    );
    assert!(!wire::parse_header(&out).expect("header").ad);
    cache.answer(&k, later, &client(&plain, None, false, false), &mut out);
    let header = wire::parse_header(&out).expect("header");
    assert!(!header.ad);
    assert_eq!((header.ancount, header.arcount), (1, 0));
}

#[test]
fn an_unvalidated_entry_never_sets_ad() {
    let cache = Cache::new(CacheSettings::default());
    let now = Instant::now();
    let k = key("www.example.test", A);
    assert!(cache.insert(&k, &signed_answer(), now, None));
    let asked = query("www.example.test", A, true);
    let mut out = Vec::new();
    cache.answer(&k, now, &client(&asked, Some(true), true, false), &mut out);
    assert!(!wire::parse_header(&out).expect("header").ad);
    assert_eq!(sections(&out).0[0], [A, RRSIG]);
}

#[test]
fn the_denial_records_go_to_do_clients_only_with_their_ttls_in_place() {
    let cache = Cache::new(CacheSettings::default());
    let now = Instant::now();
    let k = key("www.example.test", A);
    let nodata = message(
        "www.example.test",
        A,
        0,
        [
            &[],
            &[soa(60), rrsig(SOA, 60), nsec(50), rrsig(NSEC, 50)],
            &[],
        ],
    );
    assert!(cache.insert_with(&k, &nodata, now, None, &verdict(SecurityState::Secure)));
    let asked = query("www.example.test", A, true);
    let mut out = Vec::new();
    let later = now + Duration::from_secs(10);
    cache.answer(
        &k,
        later,
        &client(&asked, Some(false), false, false),
        &mut out,
    );
    let (types, ttls, _) = sections(&out);
    assert_eq!(types[1], [SOA]);
    assert_eq!(ttls, [50]);
    cache.answer(
        &k,
        later,
        &client(&asked, Some(true), false, false),
        &mut out,
    );
    let (types, ttls, _) = sections(&out);
    assert_eq!(types[1], [SOA, RRSIG, NSEC, RRSIG]);
    assert_eq!(ttls, [50, 50, 40, 40]);
}

#[test]
fn a_query_for_the_dnssec_type_gets_it_without_do() {
    let cache = Cache::new(CacheSettings::default());
    let now = Instant::now();
    let k = key("www.example.test", RRSIG);
    let answer = message(
        "www.example.test",
        RRSIG,
        0,
        [&[rrsig(A, 300), rrsig(NSEC, 300)], &[], &[]],
    );
    assert!(cache.insert(&k, &answer, now, None));
    let asked = query("www.example.test", RRSIG, false);
    let mut out = Vec::new();
    cache.answer(&k, now, &client(&asked, None, false, false), &mut out);
    assert_eq!(sections(&out).0[0], [RRSIG, RRSIG]);
}

#[test]
fn a_bogus_entry_is_servfail_with_its_error_unless_cd() {
    let cache = Cache::new(CacheSettings::default());
    let now = Instant::now();
    let k = key("www.example.test", A);
    let bogus = Verdict {
        state: SecurityState::Bogus,
        ede: Some(ExtendedError::SIGNATURE_EXPIRED),
        signature_expiry: None,
        max_ttl: Some(5),
    };
    assert!(cache.insert_with(&k, &signed_answer(), now, None, &bogus));
    let asked = query("www.example.test", A, true);
    let mut out = Vec::new();
    let hit = cache.answer(&k, now, &client(&asked, Some(true), true, false), &mut out);
    assert_eq!(
        hit,
        Hit::Fresh {
            rcode: 2,
            state: SecurityState::Bogus
        }
    );
    let header = wire::parse_header(&out).expect("header");
    assert_eq!((header.rcode, header.ancount, header.nscount), (2, 0, 0));
    assert!(!header.ad);
    let (_, _, options) = sections(&out);
    assert_eq!(options.expect("an OPT record"), [0, 15, 0, 2, 0, 7]);

    let hit = cache.answer(&k, now, &client(&asked, Some(true), false, true), &mut out);
    assert_eq!(
        hit,
        Hit::Fresh {
            rcode: 0,
            state: SecurityState::Bogus
        }
    );
    let header = wire::parse_header(&out).expect("header");
    assert!(header.cd && !header.ad);
    let (types, _, options) = sections(&out);
    assert_eq!(types[0], [A, RRSIG], "CD gets the data");
    assert_eq!(options.expect("an OPT record"), [0, 15, 0, 2, 0, 7]);

    let plain = query("www.example.test", A, false);
    cache.answer(&k, now, &client(&plain, None, false, false), &mut out);
    let header = wire::parse_header(&out).expect("header");
    assert_eq!((header.rcode, header.arcount), (2, 0));
    // The failure time caps the lifetime.
    assert_eq!(
        cache.answer(
            &k,
            now + Duration::from_secs(5),
            &client(&plain, None, false, false),
            &mut out
        ),
        Hit::Expired
    );
}

#[test]
fn an_indeterminate_entry_says_so_in_the_opt_record() {
    let cache = Cache::new(CacheSettings::default());
    let now = Instant::now();
    let k = key("www.example.test", A);
    let answer = verdict(SecurityState::Indeterminate);
    assert!(cache.insert_with(&k, &signed_answer(), now, None, &answer));
    let asked = query("www.example.test", A, true);
    let mut out = Vec::new();
    cache.answer(&k, now, &client(&asked, Some(true), false, false), &mut out);
    let header = wire::parse_header(&out).expect("header");
    assert_eq!((header.rcode, header.ad), (0, false));
    let (types, _, options) = sections(&out);
    assert_eq!(types[0], [A, RRSIG]);
    assert_eq!(options.expect("an OPT record"), [0, 15, 0, 2, 0, 5]);
}

#[test]
fn the_earliest_signature_expiry_caps_the_lifetime() {
    let cache = Cache::new(CacheSettings::default());
    let now = Instant::now();
    let k = key("www.example.test", A);
    let secure = Verdict {
        signature_expiry: Some(SystemTime::now() + Duration::from_secs(30)),
        ..verdict(SecurityState::Secure)
    };
    assert!(cache.insert_with(&k, &signed_answer(), now, None, &secure));
    let asked = query("www.example.test", A, false);
    let mut out = Vec::new();
    assert!(matches!(
        cache.answer(
            &k,
            now + Duration::from_secs(25),
            &client(&asked, None, false, false),
            &mut out
        ),
        Hit::Fresh { .. }
    ));
    assert_eq!(
        cache.answer(
            &k,
            now + Duration::from_secs(31),
            &client(&asked, None, false, false),
            &mut out
        ),
        Hit::Expired
    );
    let page = cache.list(ViewFilter::All, None, 10, None, now);
    let entry = &page.entries[0];
    assert_eq!(entry.state, SecurityState::Secure);
    assert!(entry.signature_expiry.is_some());
    // Signatures that already expired make no entry.
    let expired = Verdict {
        signature_expiry: Some(SystemTime::now() - Duration::from_secs(1)),
        ..verdict(SecurityState::Secure)
    };
    assert!(!cache.insert_with(&k, &signed_answer(), now, None, &expired));
}

#[test]
fn names_that_point_into_the_dnssec_records_keep_them() {
    let cache = Cache::new(CacheSettings::default());
    let now = Instant::now();
    let k = key("www.example.test", A);
    // The NSEC's owner is written in full at offset 34 (after the 12-octet header and the
    // 22-octet question); the additional record's owner points at it.
    let mut owned = nsec(60);
    owned.owner = wire_name("a.example.test");
    let pointer = Rec {
        owner: vec![0xc0, 34],
        rtype: A,
        ttl: 60,
        data: vec![192, 0, 2, 9],
    };
    let answer = message(
        "www.example.test",
        A,
        0,
        [&[], &[owned, soa(60)], &[pointer]],
    );
    assert!(cache.insert(&k, &answer, now, None));
    let asked = query("www.example.test", A, false);
    let mut out = Vec::new();
    cache.answer(&k, now, &client(&asked, None, false, false), &mut out);
    let (types, _, _) = sections(&out);
    assert_eq!(types[1], [NSEC, SOA], "kept: the pointer needs it");
    assert_eq!(types[2], [A]);
}

#[test]
fn a_relayed_answer_loses_its_signatures_for_a_client_without_do() {
    let answer = signed_answer();
    let asked = query("www.example.test", A, true);
    let mut out = Vec::new();
    assert_eq!(
        relay(&answer, &client(&asked, Some(false), true, false), &mut out),
        Some(0)
    );
    let header = wire::parse_header(&out).expect("header");
    assert!(!header.ad, "a relayed answer is unvalidated");
    assert_eq!(sections(&out).0[0], [A]);
    relay(&answer, &client(&asked, Some(true), false, false), &mut out);
    assert_eq!(sections(&out).0[0], [A, RRSIG]);
}
