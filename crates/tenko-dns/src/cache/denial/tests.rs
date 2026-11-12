//! The denial cache against hand-built signed answers: the NSEC and NSEC3 proofs of
//! NXDOMAIN, NODATA, an empty non-terminal and a wildcard (RFC 8198), RFC 8020 in an
//! unsigned zone, what is never kept or never synthesized, the rendering by the client's
//! flags, the bound, the flush and the expiry.

use std::time::{Duration, Instant};

use tenko_core::dns::{DnsName, SecurityState, ViewId};

use super::*;
use crate::{
    cache::{Client, ClientEdns, Verdict},
    dnssec::chain::{base32hex, nsec3_hash},
    recurse::message::{Composed, Rr, compose, parse, types},
    recursion::denial::{DenialCache, DenialKind, DenialRoute, DenialScope, Origin},
    wire,
};

const A: u16 = types::A;
const AAAA: u16 = types::AAAA;
const MX: u16 = 15;

/// The default resolution of no view.
const PUBLIC: DenialScope = DenialScope::of_view(None);

fn wire_name(text: &str) -> Vec<u8> {
    DnsName::new(text).expect("name").to_wire()
}

fn rr(owner: &str, rtype: u16, ttl: u32, data: Vec<u8>) -> Rr {
    Rr {
        owner: wire_name(owner),
        rtype,
        class: 1,
        ttl,
        data,
    }
}

/// The type bitmap of `types` (window 0 only).
fn bitmap(types: &[u16]) -> Vec<u8> {
    let mut bits = [0u8; 32];
    for rtype in types {
        bits[usize::from(*rtype / 8)] |= 0x80 >> (rtype % 8);
    }
    let len = bits
        .iter()
        .rposition(|octet| *octet != 0)
        .map_or(0, |at| at + 1);
    let mut out = vec![0, u8::try_from(len).expect("len")];
    out.extend_from_slice(&bits[..len]);
    out
}

fn soa(zone: &str, ttl: u32) -> Rr {
    let mut data = wire_name(&format!("ns.{zone}"));
    data.extend(wire_name(&format!("hostmaster.{zone}")));
    for value in [1u32, 3600, 900, 1_209_600, 300] {
        data.extend_from_slice(&value.to_be_bytes());
    }
    rr(zone, types::SOA, ttl, data)
}

fn now_unix() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("2106")
}

/// A signature of `covered` at `owner` by `signer` with `labels`, valid for an hour.
fn rrsig(owner: &str, covered: u16, labels: u8, signer: &str, ttl: u32) -> Rr {
    let now = now_unix();
    let mut data = covered.to_be_bytes().to_vec();
    data.extend_from_slice(&[13, labels]);
    data.extend_from_slice(&ttl.to_be_bytes());
    data.extend_from_slice(&(now + 3600).to_be_bytes());
    data.extend_from_slice(&(now - 3600).to_be_bytes());
    data.extend_from_slice(&[0x12, 0x34]);
    data.extend(wire_name(signer));
    data.extend_from_slice(&[0x5a; 64]);
    rr(owner, types::RRSIG, ttl, data)
}

fn labels_of(owner: &str) -> u8 {
    u8::try_from(DnsName::new(owner).expect("name").label_count()).expect("labels")
}

/// An NSEC record of `zone` and its signature.
fn nsec(zone: &str, owner: &str, next: &str, types_at: &[u16], ttl: u32) -> [Rr; 2] {
    let mut data = wire_name(next);
    data.extend(bitmap(types_at));
    [
        rr(owner, types::NSEC, ttl, data),
        rrsig(owner, types::NSEC, labels_of(owner), zone, ttl),
    ]
}

fn signed_soa(zone: &str, ttl: u32) -> [Rr; 2] {
    [
        soa(zone, ttl),
        rrsig(zone, types::SOA, labels_of(zone), zone, ttl),
    ]
}

fn message(qname: &str, qtype: u16, rcode: u8, answer: &[Rr], authority: &[Rr]) -> Vec<u8> {
    compose(&Composed {
        qname: &wire_name(qname),
        qtype,
        qclass: 1,
        rcode,
        answer,
        authority,
        additional: &[],
    })
}

const SECURE: Verdict = Verdict {
    state: SecurityState::Secure,
    ..Verdict::UNVALIDATED
};

const INSECURE: Verdict = Verdict {
    state: SecurityState::Insecure,
    ..Verdict::UNVALIDATED
};

fn denials() -> Denials {
    Denials::new(DenialSettings::default())
}

/// The NSEC zone `example.test`: the apex, `a` (A), `m` (A, MX), `sub` (a delegation),
/// `*.w` (A) under the empty non-terminal `w`. Two NXDOMAIN answers give the records
/// `example.test -> a`, `a -> m`, `m -> sub` and `sub -> *.w`.
fn nsec_zone(cache: &Denials, view: Option<ViewId>) {
    nsec_zone_on(cache, DenialScope::of_view(view));
}

/// [`nsec_zone`], taught on the path `scope`.
fn nsec_zone_on(cache: &Denials, scope: DenialScope) {
    let mut authority: Vec<Rr> = signed_soa("example.test", 300).into();
    authority.extend(nsec(
        "example.test",
        "example.test",
        "a.example.test",
        &[2, 6, 46, 47, 48],
        300,
    ));
    authority.extend(nsec(
        "example.test",
        "a.example.test",
        "m.example.test",
        &[A, 46, 47],
        300,
    ));
    let answer = message("b.example.test", A, 3, &[], &authority);
    assert!(cache.insert(scope, &answer, &SECURE, Origin::Recursion, Instant::now()));
    let mut authority: Vec<Rr> = signed_soa("example.test", 300).into();
    authority.extend(nsec(
        "example.test",
        "m.example.test",
        "sub.example.test",
        &[A, MX, 46, 47],
        300,
    ));
    authority.extend(nsec(
        "example.test",
        "sub.example.test",
        "*.w.example.test",
        &[2, 47],
        300,
    ));
    let answer = message("n.example.test", A, 3, &[], &authority);
    assert!(cache.insert(scope, &answer, &SECURE, Origin::Recursion, Instant::now()));
}

struct Asked {
    query: Vec<u8>,
    question_end: usize,
}

fn ask(qname: &str, qtype: u16) -> Asked {
    let mut query = Vec::new();
    wire::write_query(&mut query, 0x4242, qname, qtype, Some(1232));
    let question_end = wire::questions_end(&query, 1).expect("question");
    Asked {
        query,
        question_end,
    }
}

fn client(asked: &Asked, dnssec_ok: bool, max_len: usize) -> Client<'_> {
    Client {
        message: &asked.query,
        question_end: asked.question_end,
        id: 0x4242,
        rd: true,
        cd: false,
        ad: false,
        edns: Some(ClientEdns {
            udp_size: 1232,
            dnssec_ok,
            cookie: None,
        }),
        max_len,
    }
}

/// A record of an answer: section, owner, type, TTL.
type Record = (usize, String, u16, u32);

/// What the cache answers: the hit, the header and the records (section, owner, type).
fn synthesize(
    cache: &Denials,
    view: Option<ViewId>,
    qname: &str,
    qtype: u16,
    dnssec_ok: bool,
) -> Option<(DenialHit, wire::RawHeader, Vec<Record>)> {
    let asked = ask(qname, qtype);
    let mut out = Vec::with_capacity(65_535);
    let hit = cache.answer(
        DenialScope::of_view(view),
        &wire_name(qname),
        qtype,
        &client(&asked, dnssec_ok, 1232),
        Instant::now(),
        &mut out,
    )?;
    let header = wire::parse_header(&out).expect("header");
    let parsed = parse(&out).expect("parses");
    let mut records = Vec::new();
    for (section, list) in [parsed.answer, parsed.authority].into_iter().enumerate() {
        for rr in list {
            let owner = DnsName::from_wire(&rr.owner).expect("owner").0;
            records.push((section, owner.as_str().to_owned(), rr.rtype, rr.ttl));
        }
    }
    Some((hit, header, records))
}

fn kinds(records: &[Record]) -> Vec<(usize, &str, u16)> {
    records
        .iter()
        .map(|(section, owner, rtype, _)| (*section, owner.as_str(), *rtype))
        .collect()
}

#[test]
fn a_covered_name_is_nxdomain_with_the_soa_and_both_proofs() {
    let cache = denials();
    nsec_zone(&cache, None);
    let (hit, header, records) = synthesize(&cache, None, "c.example.test", A, true).expect("hit");
    assert_eq!(hit.kind, DenialKind::Nxdomain);
    assert_eq!((header.rcode, header.ad, header.qr), (3, true, true));
    assert_eq!(
        kinds(&records),
        vec![
            (1, "example.test", types::SOA),
            (1, "example.test", types::RRSIG),
            (1, "a.example.test", types::NSEC),
            (1, "a.example.test", types::RRSIG),
            (1, "example.test", types::NSEC),
            (1, "example.test", types::RRSIG),
        ]
    );
    // The TTL is the smallest left, never above the SOA's MINIMUM.
    assert!(
        records
            .iter()
            .all(|(_, _, _, ttl)| *ttl <= 300 && *ttl > 290)
    );

    // A client without DO gets the SOA alone and no AD.
    let (_, header, records) = synthesize(&cache, None, "c.example.test", A, false).expect("hit");
    assert_eq!((header.rcode, header.ad), (3, false));
    assert_eq!(kinds(&records), vec![(1, "example.test", types::SOA)]);

    // Below an existing name: the closest encloser is `a`, its wildcard covered by the
    // same record.
    let (hit, _, records) = synthesize(&cache, None, "x.a.example.test", AAAA, true).expect("hit");
    assert_eq!(hit.kind, DenialKind::Nxdomain);
    assert_eq!(
        records
            .iter()
            .filter(|record| record.2 == types::NSEC)
            .count(),
        1,
        "one record proves both"
    );
}

#[test]
fn an_existing_name_without_the_type_is_nodata_and_with_it_a_miss() {
    let cache = denials();
    nsec_zone(&cache, None);
    let (hit, header, records) =
        synthesize(&cache, None, "m.example.test", AAAA, true).expect("hit");
    assert_eq!(hit.kind, DenialKind::Nodata);
    assert_eq!((header.rcode, header.ancount), (0, 0));
    assert_eq!(
        kinds(&records),
        vec![
            (1, "example.test", types::SOA),
            (1, "example.test", types::RRSIG),
            (1, "m.example.test", types::NSEC),
            (1, "m.example.test", types::RRSIG),
        ]
    );
    assert!(synthesize(&cache, None, "m.example.test", MX, true).is_none());
    assert!(synthesize(&cache, None, "m.example.test", A, true).is_none());
    // The empty non-terminal `w` (the next name lies below it): NODATA.
    let (hit, _, _) = synthesize(&cache, None, "w.example.test", A, true).expect("hit");
    assert_eq!(hit.kind, DenialKind::Nodata);
}

/// What the cache synthesizes for `qname` (type A) on the path `scope`.
fn kind_on(cache: &Denials, scope: DenialScope, qname: &str) -> Option<DenialKind> {
    let asked = ask(qname, A);
    let mut out = Vec::with_capacity(65_535);
    cache
        .answer(
            scope,
            &wire_name(qname),
            A,
            &client(&asked, true, 1232),
            Instant::now(),
            &mut out,
        )
        .map(|hit| hit.kind)
}

fn rule_path(view: Option<ViewId>) -> DenialScope {
    DenialScope {
        view,
        route: DenialRoute::Rule(tenko_core::dns::ForwardRuleId::from_uuid(
            uuid::Uuid::from_u128(7),
        )),
    }
}

#[test]
fn a_name_a_forwarding_rule_routes_is_denied_only_from_what_the_rule_taught() {
    let cache = denials();
    // The public zone's proofs, from the default resolution: `c` lies in the span a..m.
    nsec_zone(&cache, None);
    assert_eq!(
        kind_on(&cache, PUBLIC, "dc1.c.example.test"),
        Some(DenialKind::Nxdomain),
        "the default path is answered from its own proofs"
    );
    // A rule sends `c.example.test` to other servers: the public proofs deny nothing there.
    assert_eq!(kind_on(&cache, rule_path(None), "dc1.c.example.test"), None);
    // What the rule's own servers proved denies its names.
    nsec_zone_on(&cache, rule_path(None));
    assert_eq!(
        kind_on(&cache, rule_path(None), "dc1.c.example.test"),
        Some(DenialKind::Nxdomain)
    );
}

#[test]
fn a_name_in_a_stub_zone_is_denied_only_from_what_the_stub_zone_taught() {
    let cache = denials();
    let stub = DenialScope {
        view: None,
        route: DenialRoute::Stub(tenko_core::dns::ZoneId::from_uuid(uuid::Uuid::from_u128(9))),
    };
    nsec_zone(&cache, None);
    assert_eq!(kind_on(&cache, stub, "dc1.c.example.test"), None);
    nsec_zone_on(&cache, stub);
    assert_eq!(
        kind_on(&cache, stub, "dc1.c.example.test"),
        Some(DenialKind::Nxdomain)
    );
    // And the stub zone's proofs deny nothing on the default path.
    let cache = denials();
    nsec_zone_on(&cache, stub);
    assert_eq!(kind_on(&cache, PUBLIC, "dc1.c.example.test"), None);
}

#[test]
fn a_view_is_answered_only_from_what_its_own_paths_taught() {
    let cache = denials();
    let inside = Some(ViewId::from_uuid(uuid::Uuid::from_u128(11)));
    nsec_zone(&cache, inside);
    assert_eq!(
        kind_on(&cache, DenialScope::of_view(inside), "c.example.test"),
        Some(DenialKind::Nxdomain)
    );
    assert_eq!(
        kind_on(&cache, PUBLIC, "c.example.test"),
        None,
        "another view"
    );
    assert_eq!(
        kind_on(&cache, rule_path(inside), "c.example.test"),
        None,
        "the same view, another route"
    );
}

#[test]
fn a_name_below_a_private_delegation_is_not_cut_off_by_a_public_nxdomain() {
    let cache = denials();
    // The public servers deny `corp.plain.test` (unsigned, RFC 8020) on the default path.
    let answer = message("corp.plain.test", A, 3, &[], &[soa("plain.test", 600)]);
    assert!(cache.insert(
        PUBLIC,
        &answer,
        &INSECURE,
        Origin::Recursion,
        Instant::now()
    ));
    assert_eq!(
        kind_on(&cache, PUBLIC, "dc1.corp.plain.test"),
        Some(DenialKind::NxdomainCut)
    );
    // A rule delegates `corp.plain.test` to internal servers: its names are theirs to deny.
    assert_eq!(
        kind_on(&cache, rule_path(None), "dc1.corp.plain.test"),
        None
    );
}

#[test]
fn a_delegation_proves_nothing_below_it_and_some_types_are_never_synthesized() {
    let cache = denials();
    nsec_zone(&cache, None);
    // `sub` is a delegation: the parent's record says nothing about its children, and
    // nothing about its data but DS.
    assert!(synthesize(&cache, None, "x.sub.example.test", A, true).is_none());
    assert!(synthesize(&cache, None, "sub.example.test", A, true).is_none());
    for qtype in [types::DS, types::ANY, types::RRSIG, types::NSEC, 252] {
        assert!(
            synthesize(&cache, None, "c.example.test", qtype, true).is_none(),
            "{qtype}"
        );
    }
    // A name the records do not cover (after `*.w`), and a zone the cache does not hold.
    assert!(synthesize(&cache, None, "zz.example.test", A, true).is_none());
    assert!(synthesize(&cache, None, "c.other.test", A, true).is_none());
    // Another view holds nothing.
    assert!(synthesize(&cache, Some(ViewId::generate()), "c.example.test", A, true).is_none());
}

#[test]
fn a_validated_wildcard_expansion_answers_other_names_under_it() {
    let cache = denials();
    nsec_zone(&cache, None);
    // `one.w.example.test` answered from `*.w.example.test` (labels 3), with the record
    // covering the name in the authority section.
    let answer = [
        rr("one.w.example.test", A, 120, vec![192, 0, 2, 7]),
        rrsig("one.w.example.test", A, 3, "example.test", 120),
    ];
    let authority = nsec(
        "example.test",
        "*.w.example.test",
        "example.test",
        &[A, 46, 47],
        300,
    );
    let message = message("one.w.example.test", A, 0, &answer, &authority);
    assert!(cache.insert(PUBLIC, &message, &SECURE, Origin::Recursion, Instant::now()));
    let (hit, header, records) =
        synthesize(&cache, None, "two.w.example.test", A, true).expect("hit");
    assert_eq!(hit.kind, DenialKind::Wildcard);
    assert_eq!((header.rcode, header.ancount, header.ad), (0, 2, true));
    assert_eq!(
        kinds(&records),
        vec![
            (0, "two.w.example.test", A),
            (0, "two.w.example.test", types::RRSIG),
            (1, "*.w.example.test", types::NSEC),
            (1, "*.w.example.test", types::RRSIG),
        ]
    );
    assert!(records.iter().all(|(_, _, _, ttl)| *ttl <= 120));
    // Without DO: the address alone.
    let (_, header, records) =
        synthesize(&cache, None, "two.w.example.test", A, false).expect("hit");
    assert_eq!((header.ancount, header.nscount), (1, 0));
    assert_eq!(kinds(&records), vec![(0, "two.w.example.test", A)]);
    // The wildcard has no AAAA: wildcard NODATA.
    let (hit, _, records) =
        synthesize(&cache, None, "two.w.example.test", AAAA, true).expect("hit");
    assert_eq!(hit.kind, DenialKind::Nodata);
    assert!(records.iter().any(|record| record.1 == "*.w.example.test"));
}

#[test]
fn nothing_is_kept_from_bogus_answers_and_only_names_from_insecure_ones() {
    let cache = denials();
    let mut authority: Vec<Rr> = signed_soa("example.test", 300).into();
    authority.extend(nsec(
        "example.test",
        "a.example.test",
        "m.example.test",
        &[A, 46, 47],
        300,
    ));
    let answer = message("b.example.test", A, 3, &[], &authority);
    let bogus = Verdict {
        state: SecurityState::Bogus,
        ..Verdict::UNVALIDATED
    };
    assert!(!cache.insert(PUBLIC, &answer, &bogus, Origin::Recursion, Instant::now()));
    assert!(cache.is_empty());
    // An insecure answer whose SOA is signed keeps nothing: a signed zone is denied by its
    // validated records only.
    assert!(!cache.insert(
        PUBLIC,
        &answer,
        &INSECURE,
        Origin::Recursion,
        Instant::now()
    ));
    assert!(cache.is_empty());
    // With the SOA unsigned the NSEC is still not kept; the name of the NXDOMAIN is (RFC
    // 8020).
    let mut authority = vec![soa("example.test", 300)];
    authority.extend(nsec(
        "example.test",
        "a.example.test",
        "m.example.test",
        &[A, 46, 47],
        300,
    ));
    let answer = message("b.example.test", A, 3, &[], &authority);
    assert!(cache.insert(
        PUBLIC,
        &answer,
        &INSECURE,
        Origin::Recursion,
        Instant::now()
    ));
    assert_eq!(cache.len(), 1);
    assert!(synthesize(&cache, None, "c.example.test", A, true).is_none());
    assert!(synthesize(&cache, None, "x.b.example.test", A, true).is_some());
}

#[test]
fn names_below_a_cached_nxdomain_of_an_unsigned_zone_are_nxdomain() {
    let cache = denials();
    let answer = message("gone.plain.test", A, 3, &[], &[soa("plain.test", 600)]);
    assert!(cache.insert(
        PUBLIC,
        &answer,
        &Verdict::UNVALIDATED,
        Origin::Recursion,
        Instant::now()
    ));
    for name in [
        "x.gone.plain.test",
        "y.x.gone.plain.test",
        "gone.plain.test",
    ] {
        let (hit, header, records) = synthesize(&cache, None, name, MX, true).expect(name);
        assert_eq!(hit.kind, DenialKind::NxdomainCut, "{name}");
        assert_eq!((header.rcode, header.ad), (3, false), "{name}");
        assert_eq!(kinds(&records), vec![(1, "plain.test", types::SOA)]);
        // The SOA's MINIMUM bounds the TTL.
        assert!(records[0].3 <= 300);
    }
    assert!(synthesize(&cache, None, "other.plain.test", A, true).is_none());
    assert!(synthesize(&cache, None, "plain.test", A, true).is_none());

    // The NXDOMAIN at the end of a CNAME chain denies the target, not the name asked.
    let answer = message(
        "alias.plain.test",
        A,
        3,
        &[rr(
            "alias.plain.test",
            types::CNAME,
            600,
            wire_name("target.plain.test"),
        )],
        &[soa("plain.test", 600)],
    );
    assert!(cache.insert(
        PUBLIC,
        &answer,
        &INSECURE,
        Origin::Recursion,
        Instant::now()
    ));
    assert!(synthesize(&cache, None, "x.target.plain.test", A, false).is_some());
    assert!(synthesize(&cache, None, "x.alias.plain.test", A, false).is_none());
}

/// The NSEC3 zone `n3.test` (no salt, no iterations) with the apex and `www` (A): two
/// records, the whole chain.
fn nsec3_zone(cache: &Denials, opt_out: bool) {
    let answer = nsec3_answer(opt_out);
    assert!(cache.insert(PUBLIC, &answer, &SECURE, Origin::Recursion, Instant::now()));
}

/// The NXDOMAIN of `nothing.n3.test` with the NSEC3 records of the apex and `www`.
fn nsec3_answer(opt_out: bool) -> Vec<u8> {
    nsec3_chain(
        &[("n3.test", &[2, 6, 46, 48, 51]), ("www.n3.test", &[A, 46])],
        opt_out,
        0,
    )
}

/// The NXDOMAIN of `nothing.n3.test` with the NSEC3 records of `owners` (each with its
/// types), no salt, `iterations`.
fn nsec3_chain(owners: &[(&str, &[u16])], opt_out: bool, iterations: u16) -> Vec<u8> {
    let mut hashes: Vec<([u8; 20], Vec<u16>)> = owners
        .iter()
        .map(|(owner, types_at)| {
            (
                nsec3_hash(&wire_name(owner), &[], iterations),
                types_at.to_vec(),
            )
        })
        .collect();
    hashes.sort();
    let mut authority: Vec<Rr> = signed_soa("n3.test", 300).into();
    for index in 0..hashes.len() {
        let (hash, types_at) = &hashes[index];
        let next = hashes[(index + 1) % hashes.len()].0;
        let owner = format!(
            "{}.n3.test",
            std::str::from_utf8(&base32hex(hash)).expect("ascii")
        );
        let [high, low] = iterations.to_be_bytes();
        let mut data = vec![1, u8::from(opt_out), high, low, 0, 20];
        data.extend_from_slice(&next);
        data.extend(bitmap(types_at));
        authority.push(rr(&owner, types::NSEC3, 300, data));
        authority.push(rrsig(&owner, types::NSEC3, 3, "n3.test", 300));
    }
    message("nothing.n3.test", A, 3, &[], &authority)
}

#[test]
fn nsec3_proves_nxdomain_and_nodata_by_hashed_owner() {
    let cache = denials();
    nsec3_zone(&cache, false);
    let (hit, header, records) = synthesize(&cache, None, "other.n3.test", A, true).expect("hit");
    assert_eq!(hit.kind, DenialKind::Nxdomain);
    assert_eq!((header.rcode, header.ad), (3, true));
    // The SOA, then the closest encloser's match, the next closer's cover and the
    // wildcard's cover, each once: two records here.
    let nsec3: Vec<_> = records
        .iter()
        .filter(|record| record.2 == types::NSEC3)
        .collect();
    assert_eq!(nsec3.len(), 2);
    let (hit, _, _) = synthesize(&cache, None, "deep.other.n3.test", A, true).expect("hit");
    assert_eq!(hit.kind, DenialKind::Nxdomain);
    let (hit, header, _) = synthesize(&cache, None, "www.n3.test", AAAA, true).expect("hit");
    assert_eq!((hit.kind, header.rcode), (DenialKind::Nodata, 0));
    assert!(synthesize(&cache, None, "www.n3.test", A, true).is_none());
}

#[test]
fn an_nsec3_lookup_spends_no_more_hash_work_than_a_validator_step() {
    // Three names that exist below the apex: a name under the deepest one needs five
    // hashes (three matches, the next closer, the wildcard).
    let owners: [(&str, &[u16]); 4] = [
        ("n3.test", &[2, 6, 46, 48, 51]),
        ("a.n3.test", &[A, 46]),
        ("b.a.n3.test", &[A, 46]),
        ("c.b.a.n3.test", &[A, 46]),
    ];
    let cheap = denials();
    assert!(cheap.insert(
        PUBLIC,
        &nsec3_chain(&owners, false, 0),
        &SECURE,
        Origin::Recursion,
        Instant::now()
    ));
    let (hit, _, _) = synthesize(&cheap, None, "x.c.b.a.n3.test", A, true).expect("hit");
    assert_eq!(
        hit.kind,
        DenialKind::Nxdomain,
        "five hashes of one round each"
    );
    // At the most iterations kept, a step's work is four hashes: five are left to the
    // runtime, three are still answered.
    let costly = denials();
    let iterations = ValidationCaps::DEFAULT.nsec3_insecure_above;
    assert!(costly.insert(
        PUBLIC,
        &nsec3_chain(&owners, false, iterations),
        &SECURE,
        Origin::Recursion,
        Instant::now()
    ));
    assert!(synthesize(&costly, None, "x.c.b.a.n3.test", A, true).is_none());
    let (hit, _, _) = synthesize(&costly, None, "other.n3.test", A, true).expect("hit");
    assert_eq!(hit.kind, DenialKind::Nxdomain);
}

#[test]
fn an_opt_out_span_proves_no_nxdomain() {
    let cache = denials();
    nsec3_zone(&cache, true);
    assert!(synthesize(&cache, None, "other.n3.test", A, true).is_none());
    // NODATA for a name that exists still holds.
    assert!(synthesize(&cache, None, "www.n3.test", AAAA, true).is_some());
}

#[test]
fn the_switch_the_truncation_the_flush_and_the_bound() {
    let off = Denials::new(DenialSettings {
        aggressive: false,
        ..DenialSettings::default()
    });
    nsec_zone(&off, None);
    assert!(off.len() > 0, "kept");
    assert!(
        synthesize(&off, None, "c.example.test", A, true).is_none(),
        "not used"
    );

    let cache = denials();
    nsec_zone(&cache, None);
    nsec3_zone(&cache, false);
    // A client whose limit the answer does not fit: TC, no records.
    let asked = ask("c.example.test", A);
    let mut out = Vec::with_capacity(65_535);
    let hit = cache.answer(
        PUBLIC,
        &wire_name("c.example.test"),
        A,
        &client(&asked, true, 100),
        Instant::now(),
        &mut out,
    );
    assert!(hit.is_some());
    let header = wire::parse_header(&out).expect("header");
    assert!(header.tc);
    assert_eq!((header.ancount, header.nscount), (0, 0));
    assert_eq!(cache.synthesized()[0], 1);

    let before = cache.len();
    assert_eq!(cache.flush(Some(&wire_name("n3.test"))), 2);
    assert_eq!(cache.len(), before - 2);
    assert!(synthesize(&cache, None, "other.n3.test", A, true).is_none());
    assert!(cache.flush(Some(&wire_name("sub.example.test"))) >= 1);
    assert!(cache.flush(None) > 0);
    assert!(cache.is_empty());

    // The bound: the least recently used go, never everything.
    let small = Denials::new(DenialSettings {
        entries: 16,
        ..DenialSettings::default()
    });
    for index in 0..40u32 {
        let zone = format!("z{index}.test");
        let answer = message(&format!("gone.{zone}"), A, 3, &[], &[soa(&zone, 600)]);
        assert!(small.insert(
            PUBLIC,
            &answer,
            &INSECURE,
            Origin::Recursion,
            Instant::now()
        ));
        assert!(small.len() <= 16, "{index}");
    }
    assert!(small.len() >= 8);
    assert!(small.zones() <= 16);
}

#[test]
fn records_expire_with_their_ttl() {
    let cache = denials();
    let mut authority: Vec<Rr> = signed_soa("example.test", 2).into();
    authority.extend(nsec(
        "example.test",
        "a.example.test",
        "m.example.test",
        &[A, 46, 47],
        2,
    ));
    authority.extend(nsec(
        "example.test",
        "example.test",
        "a.example.test",
        &[2, 6, 46, 47],
        2,
    ));
    let answer = message("b.example.test", A, 3, &[], &authority);
    let now = Instant::now();
    assert!(cache.insert(PUBLIC, &answer, &SECURE, Origin::Recursion, now));
    assert!(synthesize(&cache, None, "c.example.test", A, true).is_some());
    let asked = ask("c.example.test", A);
    let mut out = Vec::new();
    let later = now + Duration::from_secs(3);
    assert!(
        cache
            .answer(
                PUBLIC,
                &wire_name("c.example.test"),
                A,
                &client(&asked, true, 1232),
                later,
                &mut out
            )
            .is_none()
    );
    assert_eq!(cache.purge(later), 2);
    assert!(cache.is_empty());
}

#[test]
fn canonical_order_is_byte_order() {
    let names = [
        "example",
        "a.example",
        "yljkjljk.a.example",
        "z.a.example",
        "zabc.a.example",
        "z.example",
        "*.z.example",
    ];
    let keys: Vec<Vec<u8>> = names
        .iter()
        .map(|name| {
            order::OrderKey::of(&wire_name(name))
                .expect("key")
                .as_bytes()
                .to_vec()
        })
        .collect();
    for pair in keys.windows(2) {
        assert!(pair[0] < pair[1], "{pair:?}");
    }
    assert!(order::has_type(&bitmap(&[1, 46, 47]), 46));
    assert!(!order::has_type(&bitmap(&[1, 46, 47]), 28));
    assert_eq!(
        order::common_labels(
            &wire_name("x.a.example.test"),
            &wire_name("b.a.example.test")
        ),
        3
    );
}

#[test]
fn a_wildcard_expansion_alone_answers_other_names_under_it() {
    // The zone known only from one positive wildcard answer: no SOA, one NSEC record.
    let cache = denials();
    let answer = [
        rr("one.wild.example.test", A, 300, vec![192, 0, 2, 20]),
        rrsig("one.wild.example.test", A, 3, "wild.example.test", 300),
    ];
    let authority = nsec(
        "wild.example.test",
        "*.wild.example.test",
        "host.wild.example.test",
        &[A, 46, 47],
        300,
    );
    let message = message("one.wild.example.test", A, 0, &answer, &authority);
    assert!(cache.insert(PUBLIC, &message, &SECURE, Origin::Recursion, Instant::now()));
    let (hit, header, _) = synthesize(&cache, None, "foo.wild.example.test", A, true).expect("hit");
    assert_eq!((hit.kind, header.ancount), (DenialKind::Wildcard, 2));
    // A name after `host` is not in the range the record covers.
    assert!(synthesize(&cache, None, "two.wild.example.test", A, true).is_none());
    // The purge keeps a zone without an SOA while its records live.
    assert_eq!(cache.purge(Instant::now()), 0);
    assert!(synthesize(&cache, None, "foo.wild.example.test", A, true).is_some());
}

/// The apexes of the zones held.
fn apexes(cache: &Denials) -> Vec<String> {
    let store = cache.store.read().expect("store");
    let mut out: Vec<String> = store
        .zones
        .keys()
        .map(|key| {
            DnsName::from_wire(apex_of(key))
                .expect("apex")
                .0
                .as_str()
                .to_owned()
        })
        .collect();
    out.sort();
    out
}

/// An SOA of `zone` whose TTL and MINIMUM are both `ttl`.
fn lasting_soa(zone: &str, ttl: u32) -> Rr {
    let mut soa = soa(zone, ttl);
    let at = soa.data.len() - 4;
    soa.data[at..].copy_from_slice(&ttl.to_be_bytes());
    soa
}

#[test]
fn records_are_kept_only_under_the_zone_whose_signature_they_carry() {
    // A secure wildcard answer of 0.example, no SOA: its NSEC carries an RRSIG naming
    // `example` before the one of 0.example, and the expansion's RRSIG has labels 1.
    let cache = denials();
    let answer = [
        rr("www.0.example", A, 300, vec![192, 0, 2, 1]),
        rrsig("www.0.example", A, 1, "0.example", 300),
    ];
    let [record, own] = nsec(
        "0.example",
        "0.example",
        "zz.0.example",
        &[2, 6, 46, 47],
        300,
    );
    let other = rrsig("0.example", types::NSEC, 2, "example", 300);
    let authority = [record, other, own];
    let wildcard = message("www.0.example", A, 0, &answer, &authority);
    assert!(cache.insert(
        PUBLIC,
        &wildcard,
        &SECURE,
        Origin::Recursion,
        Instant::now()
    ));
    assert_eq!(apexes(&cache), vec!["0.example"]);
    // The NSEC record alone: no wildcard RRset is kept from a signature above its signer.
    assert_eq!(cache.len(), 1);
    for name in ["www.example", "other.example", "a.0.example"] {
        assert!(synthesize(&cache, None, name, A, true).is_none(), "{name}");
    }

    // The same expansion with labels 2, the signer's own: `*.0.example` answers.
    let answer = [
        rr("www.0.example", A, 300, vec![192, 0, 2, 1]),
        rrsig("www.0.example", A, 2, "0.example", 300),
    ];
    let wildcard = message("www.0.example", A, 0, &answer, &authority);
    assert!(cache.insert(
        PUBLIC,
        &wildcard,
        &SECURE,
        Origin::Recursion,
        Instant::now()
    ));
    let (hit, _, records) = synthesize(&cache, None, "a.0.example", A, true).expect("hit");
    assert_eq!(hit.kind, DenialKind::Wildcard);
    // Only the signature of the zone goes out with the record.
    assert_eq!(
        records
            .iter()
            .filter(|record| record.2 == types::RRSIG)
            .count(),
        2
    );
    assert!(synthesize(&cache, None, "www.example", A, true).is_none());

    // An NXDOMAIN whose SOA is the parent's: the NSEC of 0.example is not the parent's to
    // keep, and nothing else is learned.
    let cache = denials();
    let mut authority: Vec<Rr> = signed_soa("example", 300).into();
    authority.extend(nsec(
        "0.example",
        "0.example",
        "zz.0.example",
        &[2, 6, 46, 47],
        300,
    ));
    let answer = message("a.0.example", A, 3, &[], &authority);
    assert!(!cache.insert(PUBLIC, &answer, &SECURE, Origin::Recursion, Instant::now()));
    assert!(cache.is_empty());
}

#[test]
fn a_record_whose_next_name_leaves_its_zone_proves_nothing_there() {
    // The zone `example` held from a secure NXDOMAIN: its SOA and `example -> a.example`.
    let cache = denials();
    let mut authority: Vec<Rr> = signed_soa("example", 300).into();
    authority.extend(nsec(
        "example",
        "example",
        "a.example",
        &[2, 6, 46, 47],
        300,
    ));
    let answer = message("0a.example", A, 3, &[], &authority);
    assert!(cache.insert(PUBLIC, &answer, &SECURE, Origin::Recursion, Instant::now()));
    // A record of attacker.example whose next name is `\000.www.example`, carrying an
    // RRSIG that names `example` as well as its own.
    let mut next = vec![1, 0];
    next.extend(wire_name("www.example"));
    next.extend(bitmap(&[2, 6, 46, 47]));
    let authority = [
        rr("attacker.example", types::NSEC, 300, next),
        rrsig("attacker.example", types::NSEC, 2, "example", 300),
        rrsig("attacker.example", types::NSEC, 2, "attacker.example", 300),
    ];
    let answer = message("x.attacker.example", A, 3, &[], &authority);
    assert!(!cache.insert(PUBLIC, &answer, &SECURE, Origin::Recursion, Instant::now()));
    assert_eq!(apexes(&cache), vec!["example"]);
    for qtype in [A, AAAA, MX] {
        assert!(synthesize(&cache, None, "www.example", qtype, true).is_none());
    }
    // The zone's own records still prove what they cover.
    assert!(synthesize(&cache, None, "0b.example", A, true).is_some());
}

#[test]
fn an_unvalidated_nxdomain_cuts_only_what_its_path_vouches_for() {
    let cache = Denials::new(DenialSettings {
        negative_ttl: 60,
        ..DenialSettings::default()
    });
    let alias = [rr(
        "x.0.example",
        types::CNAME,
        300,
        wire_name("www.example"),
    )];
    // A forwarded NXDOMAIN at the end of a CNAME to another zone, with the parent's SOA:
    // the target is not the forwarder's question, so nothing is cut.
    let answer = message(
        "x.0.example",
        A,
        3,
        &alias,
        &[lasting_soa("example", 1 << 30)],
    );
    for verdict in [&Verdict::UNVALIDATED, &INSECURE] {
        assert!(!cache.insert(PUBLIC, &answer, verdict, Origin::Forwarder, Instant::now()));
    }
    // A signed SOA beside an unsigned CNAME: the zone is signed, so a bare NXDOMAIN cuts
    // nothing on either path.
    let authority = [
        lasting_soa("example", 1 << 30),
        rrsig("example", types::SOA, 1, "example", 1 << 30),
    ];
    let answer = message("x.0.example", A, 3, &alias, &authority);
    for origin in [Origin::Recursion, Origin::Forwarder] {
        assert!(!cache.insert(PUBLIC, &answer, &INSECURE, origin, Instant::now()));
    }
    assert!(cache.is_empty());
    for name in ["www.example", "a.www.example"] {
        assert!(synthesize(&cache, None, name, A, false).is_none(), "{name}");
    }

    // The forwarder's question itself: cut, for at most `negative_ttl`.
    let answer = message(
        "gone.0.example",
        A,
        3,
        &[],
        &[lasting_soa("0.example", 1 << 30)],
    );
    let now = Instant::now();
    assert!(cache.insert(
        PUBLIC,
        &answer,
        &Verdict::UNVALIDATED,
        Origin::Forwarder,
        now
    ));
    let (hit, _, records) = synthesize(&cache, None, "a.gone.0.example", A, false).expect("hit");
    assert_eq!(hit.kind, DenialKind::NxdomainCut);
    assert!(records.iter().all(|record| record.3 <= 60));
    let asked = ask("a.gone.0.example", A);
    let mut out = Vec::new();
    assert!(
        cache
            .answer(
                PUBLIC,
                &wire_name("a.gone.0.example"),
                A,
                &client(&asked, false, 1232),
                now + Duration::from_secs(61),
                &mut out,
            )
            .is_none()
    );
}

#[test]
fn an_answer_that_is_not_secure_leaves_a_secure_zone_as_it_is() {
    let cache = denials();
    nsec_zone(&cache, None);
    let before = cache.len();
    let answer = message("gone.example.test", A, 3, &[], &[soa("example.test", 600)]);
    for verdict in [&INSECURE, &Verdict::UNVALIDATED] {
        assert!(!cache.insert(PUBLIC, &answer, verdict, Origin::Recursion, Instant::now()));
    }
    assert_eq!(cache.len(), before);
    let (hit, header, _) = synthesize(&cache, None, "c.example.test", A, true).expect("hit");
    assert_eq!((hit.kind, header.ad), (DenialKind::Nxdomain, true));
    assert!(
        synthesize(&cache, None, "x.gone.example.test", A, true)
            .is_none_or(|(hit, ..)| hit.kind != DenialKind::NxdomainCut)
    );
}

#[test]
fn a_delegation_covering_the_wildcard_proves_nothing_below_it() {
    // `sub.example.test` is a delegation whose record covers `*.sub.example.test`; a
    // record below it covers `x.sub.example.test`.
    let cache = denials();
    let mut authority: Vec<Rr> = signed_soa("example.test", 300).into();
    authority.extend(nsec(
        "example.test",
        "sub.example.test",
        "a.sub.example.test",
        &[2, 46, 47],
        300,
    ));
    authority.extend(nsec(
        "example.test",
        "a.sub.example.test",
        "z.sub.example.test",
        &[A, 46, 47],
        300,
    ));
    let answer = message("b.sub.example.test", A, 3, &[], &authority);
    assert!(cache.insert(PUBLIC, &answer, &SECURE, Origin::Recursion, Instant::now()));
    assert!(synthesize(&cache, None, "x.sub.example.test", A, true).is_none());
}

// The delegation kept beside the denials for the RPZ triggers NSDNAME and NSIP.

/// An NXDOMAIN of the unsigned zone `zone` for `qname` as the resolver composes it while
/// answers carry their delegation: the SOA and `servers` NS records at the apex in the
/// authority section (NS TTL `ns_ttl`), `per_server` A records of each in the additional.
fn carried(qname: &str, zone: &str, servers: &[String], per_server: u8, ns_ttl: u32) -> Vec<u8> {
    let mut authority = vec![soa(zone, 600)];
    let mut additional = Vec::new();
    for (index, server) in servers.iter().enumerate() {
        authority.push(rr(zone, types::NS, ns_ttl, wire_name(server)));
        for last in 0..per_server {
            let third = u8::try_from(index).expect("index");
            additional.push(rr(
                &server.to_ascii_lowercase(),
                A,
                600,
                vec![198, 51, third, last + 1],
            ));
        }
    }
    compose(&Composed {
        qname: &wire_name(qname),
        qtype: A,
        qclass: 1,
        rcode: 3,
        answer: &[],
        authority: &authority,
        additional: &additional,
    })
}

/// What the cache synthesizes with `carry` at `now`: the records of every section.
fn synthesize_carrying(
    cache: &Denials,
    qname: &str,
    now: Instant,
    carry: bool,
    max_len: usize,
) -> Option<(wire::RawHeader, Vec<Record>)> {
    synthesize_type(cache, qname, A, now, carry, max_len)
}

/// As [`synthesize_carrying`], for `qtype`.
fn synthesize_type(
    cache: &Denials,
    qname: &str,
    qtype: u16,
    now: Instant,
    carry: bool,
    max_len: usize,
) -> Option<(wire::RawHeader, Vec<Record>)> {
    let asked = ask(qname, qtype);
    let mut out = Vec::with_capacity(65_535);
    cache.answer_carrying(
        PUBLIC,
        &wire_name(qname),
        qtype,
        &client(&asked, false, max_len),
        now,
        &mut out,
        carry,
    )?;
    let header = wire::parse_header(&out).expect("header");
    let parsed = parse(&out).expect("parses");
    let mut records = Vec::new();
    for (section, list) in [parsed.answer, parsed.authority, parsed.additional]
        .into_iter()
        .enumerate()
    {
        for rr in list {
            let owner = DnsName::from_wire(&rr.owner).expect("owner").0;
            records.push((section, owner.as_str().to_owned(), rr.rtype, rr.ttl));
        }
    }
    Some((header, records))
}

fn servers(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn a_carried_delegation_is_kept_beside_the_denials_and_written_under_the_carry() {
    let cache = denials();
    let now = Instant::now();
    let answer = carried(
        "gone.plain.test",
        "plain.test",
        &servers(&["ns1.plain.test", "NS2.Elsewhere.test"]),
        1,
        120,
    );
    assert!(cache.insert(PUBLIC, &answer, &INSECURE, Origin::Recursion, now));
    // The name of RFC 8020, two NS records and two addresses.
    assert_eq!(DenialCache::len(&cache), 5);
    let (header, records) =
        synthesize_carrying(&cache, "x.gone.plain.test", now, true, 1232).expect("synthesized");
    assert_eq!(header.rcode, 3);
    assert_eq!(
        kinds(&records),
        vec![
            (1, "plain.test", types::SOA),
            (1, "plain.test", types::NS),
            (1, "plain.test", types::NS),
            (2, "ns1.plain.test", A),
            (2, "ns2.elsewhere.test", A),
        ]
    );
    assert!(
        records.iter().all(|record| record.3 <= 120),
        "no record outlives the NS set: {records:?}"
    );
    // Without the carry the answer is the one it always was.
    let (_, records) =
        synthesize_carrying(&cache, "x.gone.plain.test", now, false, 1232).expect("synthesized");
    assert_eq!(kinds(&records), vec![(1, "plain.test", types::SOA)]);
}

#[test]
fn under_the_carry_a_zone_without_its_delegation_is_left_to_the_resolver() {
    let cache = denials();
    let now = Instant::now();
    let answer = message("gone.plain.test", A, 3, &[], &[soa("plain.test", 600)]);
    assert!(cache.insert(PUBLIC, &answer, &INSECURE, Origin::Recursion, now));
    assert!(synthesize_carrying(&cache, "x.gone.plain.test", now, false, 1232).is_some());
    assert!(
        synthesize_carrying(&cache, "x.gone.plain.test", now, true, 1232).is_none(),
        "a synthesized answer without the delegation would pass the NSDNAME and NSIP triggers"
    );
    // An answer that carries it later gives the zone its delegation.
    let answer = carried(
        "other.plain.test",
        "plain.test",
        &servers(&["ns1.plain.test"]),
        1,
        600,
    );
    assert!(cache.insert(PUBLIC, &answer, &INSECURE, Origin::Recursion, now));
    assert!(synthesize_carrying(&cache, "x.gone.plain.test", now, true, 1232).is_some());
}

#[test]
fn an_expired_delegation_stops_the_synthesis_under_the_carry() {
    let cache = denials();
    let now = Instant::now();
    let answer = carried(
        "gone.plain.test",
        "plain.test",
        &servers(&["ns1.plain.test"]),
        1,
        2,
    );
    assert!(cache.insert(PUBLIC, &answer, &INSECURE, Origin::Recursion, now));
    let (_, records) =
        synthesize_carrying(&cache, "x.gone.plain.test", now, true, 1232).expect("synthesized");
    assert!(records.iter().all(|record| record.3 <= 2), "{records:?}");
    let later = now + Duration::from_secs(3);
    assert!(
        synthesize_carrying(&cache, "x.gone.plain.test", later, true, 1232).is_none(),
        "stale name servers are never written"
    );
    assert!(synthesize_carrying(&cache, "x.gone.plain.test", later, false, 1232).is_some());
    // The purge takes the expired delegation out of the count.
    assert_eq!(cache.purge(later), 2);
    assert_eq!(DenialCache::len(&cache), 1);
}

#[test]
fn a_delegation_over_the_caps_is_kept_with_none() {
    let many: Vec<String> = (0..=store::MAX_DELEGATION_SERVERS)
        .map(|index| format!("ns{index}.plain.test"))
        .collect();
    let cache = denials();
    let now = Instant::now();
    // One within the caps first, then an answer with one name server too many.
    let answer = carried("gone.plain.test", "plain.test", &many[..2], 1, 600);
    assert!(cache.insert(PUBLIC, &answer, &INSECURE, Origin::Recursion, now));
    assert!(synthesize_carrying(&cache, "x.gone.plain.test", now, true, 1232).is_some());
    let answer = carried("other.plain.test", "plain.test", &many, 1, 600);
    assert!(cache.insert(PUBLIC, &answer, &INSECURE, Origin::Recursion, now));
    assert!(
        synthesize_carrying(&cache, "x.gone.plain.test", now, true, 1232).is_none(),
        "a truncated set could miss the server a trigger names"
    );
    assert_eq!(DenialCache::len(&cache), 2, "the two names, no delegation");
    // Within the name servers but over the addresses.
    let cache = denials();
    let per_server =
        u8::try_from(store::MAX_DELEGATION_ADDRESSES / 2 + 1).expect("addresses per server");
    let answer = carried("gone.plain.test", "plain.test", &many[..2], per_server, 600);
    assert!(cache.insert(PUBLIC, &answer, &INSECURE, Origin::Recursion, now));
    assert!(synthesize_carrying(&cache, "x.gone.plain.test", now, true, 1232).is_none());
}

/// A name server name of 255 octets in wire form under `plain.test`, told apart by `tag`.
fn longest_server(tag: usize) -> String {
    let first = format!("{tag:02}{}", "a".repeat(61));
    format!(
        "{first}.{}.{}.{}.plain.test",
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(50)
    )
}

#[test]
fn a_full_delegation_with_names_at_the_length_limit_is_kept_counted_and_written() {
    let names: Vec<String> = (0..store::MAX_DELEGATION_SERVERS)
        .map(longest_server)
        .collect();
    assert_eq!(wire_name(&names[0]).len(), 255);
    let per_server = u8::try_from(store::MAX_DELEGATION_ADDRESSES / store::MAX_DELEGATION_SERVERS)
        .expect("addresses per server");
    let cache = denials();
    let now = Instant::now();
    let answer = carried("gone.plain.test", "plain.test", &names, per_server, 600);
    assert!(cache.insert(PUBLIC, &answer, &INSECURE, Origin::Recursion, now));
    assert_eq!(
        DenialCache::len(&cache),
        1 + store::MAX_DELEGATION_SERVERS + store::MAX_DELEGATION_ADDRESSES
    );
    let (header, records) =
        synthesize_carrying(&cache, "x.gone.plain.test", now, true, 65_535).expect("synthesized");
    assert!(!header.tc);
    let ns = records
        .iter()
        .filter(|record| record.2 == types::NS)
        .count();
    let addresses = records.iter().filter(|record| record.0 == 2).count();
    assert_eq!(
        (ns, addresses),
        (
            store::MAX_DELEGATION_SERVERS,
            store::MAX_DELEGATION_ADDRESSES
        )
    );
    // Over UDP it does not fit: truncated, with no record, so the client asks over TCP.
    let (header, records) =
        synthesize_carrying(&cache, "x.gone.plain.test", now, true, 1232).expect("synthesized");
    assert!(header.tc);
    assert_eq!(records.len(), 0, "{records:?}");
    // A flush of the zone takes the delegation with it.
    assert_eq!(
        DenialCache::flush(&cache, Some(&wire_name("plain.test"))),
        1 + store::MAX_DELEGATION_SERVERS + store::MAX_DELEGATION_ADDRESSES
    );
    assert!(cache.is_empty());
}

#[test]
fn a_trim_with_full_delegations_takes_a_sixteenth_and_never_the_whole_cache() {
    let bound = 2_000;
    let cache = Denials::new(DenialSettings {
        entries: bound,
        ..DenialSettings::default()
    });
    let per_server = u8::try_from(store::MAX_DELEGATION_ADDRESSES / store::MAX_DELEGATION_SERVERS)
        .expect("addresses per server");
    // The most one item counts for: a full delegation.
    let largest = store::MAX_DELEGATION_SERVERS + store::MAX_DELEGATION_ADDRESSES;
    let now = Instant::now();
    for index in 0..200 {
        let zone = format!("z{index}.test");
        let names: Vec<String> = (0..store::MAX_DELEGATION_SERVERS)
            .map(|server| format!("ns{server}.{zone}"))
            .collect();
        let answer = carried(&format!("gone.{zone}"), &zone, &names, per_server, 600);
        assert!(cache.insert(PUBLIC, &answer, &INSECURE, Origin::Recursion, now));
        let held = DenialCache::len(&cache);
        assert!(held <= bound, "{index}: {held}");
        if index > bound / largest {
            assert!(
                held + bound / 16 + 2 * largest > bound,
                "{index}: one trim took {} of {bound} records",
                bound - held
            );
        }
    }
}

// One server answers for the parent and for the zone below it (the DNS lab's authority
// serves the root, the TLD and the zones under them), so the resolver follows the parent's
// cut. Under the carry its negative answers then carry no NS record (the cut is not the
// zone of the SOA, RFC 2308 section 2.2) and its positive answers the parent's.

/// The signed NXDOMAIN of `nothing.example.test` as the resolver composes it under the
/// carry from the root's cut: the SOA and two NSEC records, no NS record.
fn nxdomain_from_the_parents_cut() -> Vec<u8> {
    let mut authority: Vec<Rr> = signed_soa("example.test", 300).into();
    authority.extend(nsec(
        "example.test",
        "example.test",
        "a.example.test",
        &[2, 6, 46, 47, 48],
        300,
    ));
    authority.extend(nsec(
        "example.test",
        "m.example.test",
        "sub.example.test",
        &[A, MX, 46, 47],
        300,
    ));
    message("nothing.example.test", A, 3, &[], &authority)
}

fn no_ns(records: &[Record]) -> bool {
    records.iter().all(|record| record.2 != types::NS)
}

#[test]
fn under_the_carry_the_denials_of_a_zone_its_parents_servers_answer_are_synthesized() {
    let now = Instant::now();
    // NXDOMAIN from the NSEC: after nothing.example.test, nope.example.test.
    let cache = denials();
    let answer = nxdomain_from_the_parents_cut();
    assert!(cache.insert_carried(PUBLIC, &answer, &SECURE, Origin::Recursion, now, true));
    let (header, records) = synthesize_type(&cache, "nope.example.test", A, now, true, 1232)
        .expect("synthesized under the carry");
    assert_eq!(header.rcode, 3);
    assert!(
        no_ns(&records),
        "as the resolver's own answer, no NS: {records:?}"
    );
    // NODATA from the NSEC: after m.example.test AAAA, TXT.
    let cache = denials();
    let mut authority: Vec<Rr> = signed_soa("example.test", 300).into();
    authority.extend(nsec(
        "example.test",
        "m.example.test",
        "sub.example.test",
        &[A, MX, 46, 47],
        300,
    ));
    let answer = message("m.example.test", AAAA, 0, &[], &authority);
    assert!(cache.insert_carried(PUBLIC, &answer, &SECURE, Origin::Recursion, now, true));
    let (header, records) = synthesize_type(&cache, "m.example.test", 16, now, true, 1232)
        .expect("NODATA under the carry");
    assert_eq!((header.rcode, header.ancount), (0, 0));
    assert!(no_ns(&records), "{records:?}");
    // NXDOMAIN and NODATA from the NSEC3 chain.
    let cache = denials();
    let answer = nsec3_answer(false);
    assert!(cache.insert_carried(PUBLIC, &answer, &SECURE, Origin::Recursion, now, true));
    let (header, _) = synthesize_type(&cache, "other.n3.test", A, now, true, 1232)
        .expect("NSEC3 NXDOMAIN under the carry");
    assert_eq!(header.rcode, 3);
    let (header, _) = synthesize_type(&cache, "www.n3.test", AAAA, now, true, 1232)
        .expect("NSEC3 NODATA under the carry");
    assert_eq!(header.rcode, 0);
    // RFC 8020 in an unsigned zone.
    let cache = denials();
    let answer = message("gone.plain.test", A, 3, &[], &[soa("plain.test", 600)]);
    assert!(cache.insert_carried(PUBLIC, &answer, &INSECURE, Origin::Recursion, now, true));
    let (header, records) = synthesize_type(&cache, "x.gone.plain.test", A, now, true, 1232)
        .expect("RFC 8020 under the carry");
    assert_eq!(header.rcode, 3);
    assert!(no_ns(&records), "{records:?}");
    // The same answers taught before the carry (not carried) leave the zone to the
    // resolver: whether its answers carry a delegation is not known.
    let cache = denials();
    let answer = nxdomain_from_the_parents_cut();
    assert!(cache.insert(PUBLIC, &answer, &SECURE, Origin::Recursion, now));
    assert!(synthesize_type(&cache, "nope.example.test", A, now, true, 1232).is_none());
    assert!(synthesize_type(&cache, "nope.example.test", A, now, false, 1232).is_some());
    // The next answer of the zone under the carry brings the synthesis back.
    let answer = nxdomain_from_the_parents_cut();
    assert!(cache.insert_carried(PUBLIC, &answer, &SECURE, Origin::Recursion, now, true));
    assert!(synthesize_type(&cache, "nope.example.test", A, now, true, 1232).is_some());
}

#[test]
fn under_the_carry_a_wildcard_answer_carries_the_parents_delegation_it_came_through() {
    let now = Instant::now();
    let cache = denials();
    let answer = [
        rr("one.wild.example.test", A, 300, vec![192, 0, 2, 20]),
        rrsig("one.wild.example.test", A, 3, "wild.example.test", 300),
    ];
    let mut authority: Vec<Rr> = nsec(
        "wild.example.test",
        "*.wild.example.test",
        "host.wild.example.test",
        &[A, 46, 47],
        300,
    )
    .into();
    // The root's cut, as the resolver adds it to a positive answer under the carry.
    authority.push(rr(".", types::NS, 3600, wire_name("a.root.test")));
    let additional = [rr("a.root.test", A, 3600, vec![192, 0, 2, 1])];
    let wildcard = compose(&Composed {
        qname: &wire_name("one.wild.example.test"),
        qtype: A,
        qclass: 1,
        rcode: 0,
        answer: &answer,
        authority: &authority,
        additional: &additional,
    });
    assert!(cache.insert_carried(PUBLIC, &wildcard, &SECURE, Origin::Recursion, now, true));
    let (header, records) = synthesize_type(&cache, "foo.wild.example.test", A, now, true, 1232)
        .expect("synthesized under the carry");
    assert_eq!((header.rcode, header.ancount), (0, 1));
    let sections: Vec<(usize, u16)> = records.iter().map(|record| (record.0, record.2)).collect();
    assert_eq!(
        sections,
        vec![(0, A), (1, types::NS), (2, A)],
        "the root's NS and its address, as the resolver's answer carries them"
    );
    // A delegation of the zone's own replaces it: the resolver follows that cut now.
    let cache = denials();
    let answer = message("gone.plain.test", A, 3, &[], &[soa("plain.test", 600)]);
    assert!(cache.insert_carried(PUBLIC, &answer, &INSECURE, Origin::Recursion, now, true));
    let answer = carried(
        "other.plain.test",
        "plain.test",
        &servers(&["ns1.plain.test"]),
        1,
        600,
    );
    assert!(cache.insert_carried(PUBLIC, &answer, &INSECURE, Origin::Recursion, now, true));
    let (_, records) =
        synthesize_type(&cache, "x.gone.plain.test", A, now, true, 1232).expect("synthesized");
    assert_eq!(
        kinds(&records),
        vec![
            (1, "plain.test", types::SOA),
            (1, "plain.test", types::NS),
            (2, "ns1.plain.test", A),
        ]
    );
}

#[test]
fn the_mark_of_a_cut_above_follows_the_answers_that_taught_it() {
    let now = Instant::now();
    let bare = message("gone.plain.test", A, 3, &[], &[soa("plain.test", 600)]);
    // Set by a negative answer composed under the carry without an NS record...
    let cache = denials();
    assert!(cache.insert_carried(PUBLIC, &bare, &INSECURE, Origin::Recursion, now, true));
    assert!(synthesize_type(&cache, "x.gone.plain.test", A, now, true, 1232).is_some());
    // ...and cleared by one taught without the carry: what the resolver's answers in the
    // zone carry is not known again.
    assert!(cache.insert(PUBLIC, &bare, &INSECURE, Origin::Recursion, now));
    assert!(synthesize_type(&cache, "x.gone.plain.test", A, now, true, 1232).is_none());
    // Cleared by an answer with more name servers at the apex than kept.
    let cache = denials();
    assert!(cache.insert_carried(PUBLIC, &bare, &INSECURE, Origin::Recursion, now, true));
    let names: Vec<String> = (0..=store::MAX_DELEGATION_SERVERS)
        .map(|index| format!("ns{index}.plain.test"))
        .collect();
    let large = carried("other.plain.test", "plain.test", &names, 1, 600);
    assert!(cache.insert_carried(PUBLIC, &large, &INSECURE, Origin::Recursion, now, true));
    assert!(synthesize_type(&cache, "x.gone.plain.test", A, now, true, 1232).is_none());
    // The zone's own delegation wins over a later answer without it: a fresh one is
    // written.
    let cache = denials();
    let own = carried(
        "other.plain.test",
        "plain.test",
        &servers(&["ns1.plain.test"]),
        1,
        600,
    );
    assert!(cache.insert_carried(PUBLIC, &own, &INSECURE, Origin::Recursion, now, true));
    assert!(cache.insert_carried(PUBLIC, &bare, &INSECURE, Origin::Recursion, now, true));
    let (_, records) =
        synthesize_type(&cache, "x.gone.plain.test", A, now, true, 1232).expect("synthesized");
    assert!(!no_ns(&records), "{records:?}");
}

#[test]
fn a_positive_answer_through_a_cut_above_does_not_mark_the_zone() {
    let mut zone = store::Zone::new(&wire_name("wild.example.test"), true);
    let authority = [rr(".", types::NS, 3600, wire_name("a.root.test"))];
    let additional = [rr("a.root.test", A, 3600, vec![192, 0, 2, 1])];
    let shown = store::delegation_of(&zone.apex, &authority, &additional, 100, true);
    assert!(matches!(shown, store::Shown::Delegation(_)));
    zone.learn_delegation(shown, true, false, 400);
    assert_eq!(
        zone.above_until, 0,
        "only a negative answer says its cut is above"
    );
    assert!(zone.delegated);
    // Without the carry no cut above the apex is taken.
    let shown = store::delegation_of(&zone.apex, &authority, &additional, 100, false);
    assert!(matches!(shown, store::Shown::Nothing));
}
