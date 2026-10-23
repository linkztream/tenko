//! The denial proofs against the example zones: RFC 4035 appendix A (NSEC) with the
//! responses of appendix B, and RFC 5155 appendix A (NSEC3, 12 iterations, salt
//! `aabbccdd`, opt-out) with the responses of its appendix B. The records are the zones'
//! own; the signatures are checked elsewhere, the proofs only read the records.

use tenko_core::dns::DnsName;

use crate::{
    dnssec::chain::{base32hex_decode, nsec3_hash},
    recursion::ValidationCaps,
    validate::{
        nsec::{self, CutProof, Nodata, Nsec, ProofFault},
        nsec3::{Chain, Nsec3},
        rrset::Budget,
    },
};

fn wire(name: &str) -> Vec<u8> {
    DnsName::new(name).expect("name").to_wire()
}

/// A type bitmap (window 0 only) of the named types.
fn bitmap(types: &[&str]) -> Vec<u8> {
    let mut map = [0u8; 32];
    let mut highest = 0;
    for name in types {
        let rtype: u16 = match *name {
            "A" => 1,
            "NS" => 2,
            "SOA" => 6,
            "HINFO" => 13,
            "MX" => 15,
            "AAAA" => 28,
            "DS" => 43,
            "RRSIG" => 46,
            "NSEC" => 47,
            "DNSKEY" => 48,
            "NSEC3PARAM" => 51,
            other => panic!("no such type {other}"),
        };
        let octet = usize::from(rtype >> 3);
        map[octet] |= 0x80 >> (rtype & 7);
        highest = highest.max(octet);
    }
    let mut out = vec![0, u8::try_from(highest + 1).expect("len")];
    out.extend_from_slice(&map[..=highest]);
    out
}

/// An NSEC record's data: the next name and the bitmap.
fn nsec_data(next: &str, types: &[&str]) -> Vec<u8> {
    let mut out = wire(next);
    out.extend_from_slice(&bitmap(types));
    out
}

/// The NSEC chain of RFC 4035 appendix A.
const CHAIN_4035: [(&str, &str, &[&str]); 10] = [
    (
        "example",
        "a.example",
        &["NS", "SOA", "MX", "RRSIG", "NSEC", "DNSKEY"],
    ),
    ("a.example", "ai.example", &["NS", "DS", "RRSIG", "NSEC"]),
    (
        "ai.example",
        "b.example",
        &["A", "HINFO", "AAAA", "RRSIG", "NSEC"],
    ),
    ("b.example", "ns1.example", &["NS", "RRSIG", "NSEC"]),
    ("ns1.example", "ns2.example", &["A", "RRSIG", "NSEC"]),
    ("ns2.example", "*.w.example", &["A", "RRSIG", "NSEC"]),
    ("*.w.example", "x.w.example", &["MX", "RRSIG", "NSEC"]),
    ("x.w.example", "x.y.w.example", &["MX", "RRSIG", "NSEC"]),
    ("x.y.w.example", "xx.example", &["MX", "RRSIG", "NSEC"]),
    (
        "xx.example",
        "example",
        &["A", "HINFO", "AAAA", "RRSIG", "NSEC"],
    ),
];

struct NsecZone {
    owners: Vec<Vec<u8>>,
    data: Vec<Vec<u8>>,
}

impl NsecZone {
    fn rfc4035() -> Self {
        Self {
            owners: CHAIN_4035.iter().map(|(owner, _, _)| wire(owner)).collect(),
            data: CHAIN_4035
                .iter()
                .map(|(_, next, types)| nsec_data(next, types))
                .collect(),
        }
    }

    /// The records of the named owners (every record when `None`).
    fn records(&self, only: Option<&[&str]>) -> Vec<Nsec<'_>> {
        self.owners
            .iter()
            .zip(&self.data)
            .filter(|(owner, _)| {
                only.is_none_or(|only| only.iter().any(|name| wire(name) == **owner))
            })
            .map(|(owner, data)| Nsec::parse(owner, data).expect("nsec"))
            .collect()
    }
}

const A: u16 = 1;
const MX: u16 = 15;
const AAAA: u16 = 28;
const DS: u16 = 43;

#[test]
fn rfc4035_appendix_b_name_error() {
    let zone = NsecZone::rfc4035();
    let apex = wire("example");
    // B.2: ml.example, with the records the response carries.
    let records = zone.records(Some(&["b.example", "example"]));
    assert_eq!(
        nsec::prove_nxdomain(&records, &wire("ml.example"), &apex),
        Ok(())
    );
    // Without the record covering the wildcard the proof is missing.
    let records = zone.records(Some(&["b.example"]));
    assert_eq!(
        nsec::prove_nxdomain(&records, &wire("ml.example"), &apex),
        Err(ProofFault::Missing)
    );
    // A name that exists is not proven absent, nor is an empty non-terminal.
    let records = zone.records(None);
    assert_eq!(
        nsec::prove_nxdomain(&records, &wire("ns1.example"), &apex),
        Err(ProofFault::Exists)
    );
    assert_eq!(
        nsec::prove_nxdomain(&records, &wire("y.w.example"), &apex),
        Err(ProofFault::Exists)
    );
    // A name under the wildcard is not a name error: the wildcard exists.
    assert_eq!(
        nsec::prove_nxdomain(&records, &wire("a.z.w.example"), &apex),
        Err(ProofFault::Exists)
    );
    // A name below a delegation is the child's business: the parent's NSEC does not
    // cover it (RFC 6840 section 4.1).
    assert_eq!(
        nsec::prove_nxdomain(&records, &wire("foo.b.example"), &apex),
        Err(ProofFault::Missing)
    );
    // The last record wraps around to the apex.
    assert_eq!(
        nsec::prove_nxdomain(&records, &wire("zz.example"), &apex),
        Ok(())
    );
}

#[test]
fn rfc4035_appendix_b_no_data() {
    let zone = NsecZone::rfc4035();
    let apex = wire("example");
    // B.3: ns1.example MX.
    let records = zone.records(Some(&["ns1.example"]));
    assert_eq!(
        nsec::prove_nodata(&records, &wire("ns1.example"), MX, &apex),
        Ok(Nodata::Plain)
    );
    assert_eq!(
        nsec::prove_nodata(&records, &wire("ns1.example"), A, &apex),
        Err(ProofFault::Exists)
    );
    // The empty non-terminal y.w.example.
    let records = zone.records(Some(&["x.w.example"]));
    assert_eq!(
        nsec::prove_nodata(&records, &wire("y.w.example"), A, &apex),
        Ok(Nodata::EmptyNonTerminal)
    );
    // B.6: a.z.w.example AAAA, a wildcard NODATA.
    let records = zone.records(Some(&["x.y.w.example", "*.w.example"]));
    assert_eq!(
        nsec::prove_nodata(&records, &wire("a.z.w.example"), AAAA, &apex),
        Ok(Nodata::Wildcard)
    );
    assert_eq!(
        nsec::prove_nodata(&records, &wire("a.z.w.example"), MX, &apex),
        Err(ProofFault::Exists)
    );
    // The parent's NSEC at a delegation proves nothing about the child's data.
    let records = zone.records(Some(&["b.example"]));
    assert_eq!(
        nsec::prove_nodata(&records, &wire("b.example"), A, &apex),
        Err(ProofFault::Missing)
    );
    // ... but it proves the DS absent: an insecure delegation (B.7).
    assert_eq!(
        nsec::prove_nodata(&records, &wire("b.example"), DS, &apex),
        Ok(Nodata::Plain)
    );
    assert_eq!(
        nsec::delegation(&records, &wire("b.example"), &apex),
        Some(CutProof::Insecure)
    );
    // a.example has a DS: no insecure delegation there.
    let records = zone.records(Some(&["a.example"]));
    assert_eq!(
        nsec::delegation(&records, &wire("a.example"), &apex),
        Some(CutProof::Bogus)
    );
    // ns1.example is no delegation at all; a covered name is none either.
    let records = zone.records(None);
    assert_eq!(
        nsec::delegation(&records, &wire("ns1.example"), &apex),
        Some(CutProof::NotACut)
    );
    assert_eq!(
        nsec::delegation(&records, &wire("ml.example"), &apex),
        Some(CutProof::NotACut)
    );
}

#[test]
fn rfc4035_appendix_b_wildcard() {
    let zone = NsecZone::rfc4035();
    let apex = wire("example");
    // B.5: a.z.w.example MX answered from *.w.example.
    let records = zone.records(Some(&["x.y.w.example"]));
    assert_eq!(
        nsec::prove_wildcard(&records, &wire("a.z.w.example"), &apex),
        Ok(())
    );
    assert_eq!(
        nsec::prove_wildcard(&records, &wire("x.w.example"), &apex),
        Err(ProofFault::Missing)
    );
    let records = zone.records(None);
    assert_eq!(
        nsec::prove_wildcard(&records, &wire("x.w.example"), &apex),
        Err(ProofFault::Exists)
    );
}

/// The NSEC3 chain of RFC 5155 appendix A: the hashed owner, the next hash and the
/// types; flags 1 (opt-out), 12 iterations, salt `aabbccdd`.
const CHAIN_5155: [(&str, &str, &[&str]); 12] = [
    (
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
        &["MX", "DNSKEY", "NS", "SOA", "NSEC3PARAM", "RRSIG"],
    ),
    (
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
        "2vptu5timamqttgl4luu9kg21e0aor3s",
        &["A", "RRSIG"],
    ),
    (
        "2vptu5timamqttgl4luu9kg21e0aor3s",
        "35mthgpgcu1qg68fab165klnsnk3dpvl",
        &["MX", "RRSIG"],
    ),
    (
        "35mthgpgcu1qg68fab165klnsnk3dpvl",
        "b4um86eghhds6nea196smvmlo4ors995",
        &["NS", "DS", "RRSIG"],
    ),
    (
        "b4um86eghhds6nea196smvmlo4ors995",
        "gjeqe526plbf1g8mklp59enfd789njgi",
        &["MX", "RRSIG"],
    ),
    (
        "gjeqe526plbf1g8mklp59enfd789njgi",
        "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
        &["HINFO", "A", "AAAA", "RRSIG"],
    ),
    (
        "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
        "k8udemvp1j2f7eg6jebps17vp3n8i58h",
        &[],
    ),
    (
        "k8udemvp1j2f7eg6jebps17vp3n8i58h",
        "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
        &[],
    ),
    (
        "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
        "q04jkcevqvmu85r014c7dkba38o0ji5r",
        &["A", "RRSIG"],
    ),
    (
        "q04jkcevqvmu85r014c7dkba38o0ji5r",
        "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
        &["A", "RRSIG"],
    ),
    (
        "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
        "t644ebqk9bibcna874givr6joj62mlhv",
        &["MX", "RRSIG"],
    ),
    (
        "t644ebqk9bibcna874givr6joj62mlhv",
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
        &["HINFO", "A", "AAAA", "RRSIG"],
    ),
];

const SALT: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];

/// An NSEC3 record's data: SHA-1, opt-out, 12 iterations, the salt, the next hash and
/// the bitmap.
fn nsec3_data(next: &str, types: &[&str]) -> Vec<u8> {
    let mut out = vec![1, 1, 0, 12, 4];
    out.extend_from_slice(&SALT);
    let next = base32hex_decode(next.as_bytes()).expect("hash");
    out.push(20);
    out.extend_from_slice(&next);
    out.extend_from_slice(&bitmap(types));
    out
}

struct Nsec3Zone {
    owners: Vec<Vec<u8>>,
    data: Vec<Vec<u8>>,
}

impl Nsec3Zone {
    fn rfc5155() -> Self {
        Self {
            owners: CHAIN_5155
                .iter()
                .map(|(owner, _, _)| wire(&format!("{owner}.example")))
                .collect(),
            data: CHAIN_5155
                .iter()
                .map(|(_, next, types)| nsec3_data(next, types))
                .collect(),
        }
    }

    fn records(&self, only: Option<&[&str]>) -> Vec<Nsec3<'_>> {
        let apex = wire("example");
        self.owners
            .iter()
            .zip(&self.data)
            .filter(|(owner, _)| {
                only.is_none_or(|only| {
                    only.iter()
                        .any(|label| owner.starts_with(&[32]) && &owner[1..33] == label.as_bytes())
                })
            })
            .map(|(owner, data)| Nsec3::parse(owner, data, &apex).expect("nsec3"))
            .collect()
    }
}

#[test]
fn rfc5155_appendix_a_hashes_the_names_as_listed() {
    for (name, label) in [
        ("example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
        ("x.y.w.example", "2vptu5timamqttgl4luu9kg21e0aor3s"),
        ("c.x.w.example", "0va5bpr2ou0vk0lbqeeljri88laipsfh"),
        ("*.x.w.example", "92pqneegtaue7pjatc3l3qnk738c6v5m"),
        ("c.example", "4g6p9u5gvfshp30pqecj98b3maqbn1ck"),
        ("z.w.example", "qlu7gtfaeh0ek0c05ksfhdpbcgglbe03"),
    ] {
        let hash = nsec3_hash(&wire(name), &SALT, 12);
        assert_eq!(
            crate::dnssec::chain::base32hex(&hash).as_slice(),
            label.as_bytes(),
            "{name}"
        );
    }
}

#[test]
fn rfc5155_appendix_b_name_error() {
    let zone = Nsec3Zone::rfc5155();
    let apex = wire("example");
    let caps = ValidationCaps::DEFAULT;
    // B.1: a.c.x.w.example with the three records of the response.
    let records = zone.records(Some(&[
        "b4um86eghhds6nea196smvmlo4ors995",
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
        "35mthgpgcu1qg68fab165klnsnk3dpvl",
    ]));
    let chain = Chain::new(&records, &apex).expect("chain");
    let mut budget = Budget::default();
    let qname = wire("a.c.x.w.example");
    let (encloser, _, next_closer) = chain
        .closest_encloser(&qname, &caps, &mut budget)
        .expect("the closest encloser");
    assert_eq!(encloser, wire("x.w.example").as_slice());
    assert!(next_closer.opt_out());
    // The zone is opt-out, so the name error is proven but not secure (section 9.2).
    assert_eq!(
        chain.prove_nxdomain(&wire("a.c.x.w.example"), &caps, &mut budget),
        Ok(true)
    );
    // The hashes of one step stay within the cap: three for the search (the name, the
    // next closer name, the encloser), then one for the wildcard.
    assert!(budget.hashes <= caps.nsec3_hashes_per_step, "{budget:?}");
    // Without the record covering the wildcard, or the next closer name, nothing is
    // proven.
    let records = zone.records(Some(&[
        "b4um86eghhds6nea196smvmlo4ors995",
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
    ]));
    let chain = Chain::new(&records, &apex).expect("chain");
    assert_eq!(
        chain.prove_nxdomain(&wire("a.c.x.w.example"), &caps, &mut budget),
        Err(ProofFault::Missing)
    );
    // A name that exists.
    let records = zone.records(None);
    let chain = Chain::new(&records, &apex).expect("chain");
    assert_eq!(
        chain.prove_nxdomain(&wire("ns1.example"), &caps, &mut budget),
        Err(ProofFault::Exists)
    );
    // A deeper name than the cap allows is a cap, not a proof.
    let tight = ValidationCaps {
        nsec3_hashes_per_step: 2,
        ..caps
    };
    assert_eq!(
        chain.prove_nxdomain(&wire("a.c.x.w.example"), &tight, &mut budget),
        Err(ProofFault::Cap)
    );
}

#[test]
fn rfc5155_appendix_b_no_data_and_wildcards() {
    let zone = Nsec3Zone::rfc5155();
    let apex = wire("example");
    let caps = ValidationCaps::DEFAULT;
    let records = zone.records(None);
    let chain = Chain::new(&records, &apex).expect("chain");
    let mut budget = Budget::default();
    // B.2: ns1.example MX.
    assert_eq!(
        chain.prove_nodata(&wire("ns1.example"), MX, &caps, &mut budget),
        Ok((Nodata::Plain, false))
    );
    assert_eq!(
        chain.prove_nodata(&wire("ns1.example"), A, &caps, &mut budget),
        Err(ProofFault::Exists)
    );
    // B.2.1: the empty non-terminal y.w.example.
    assert_eq!(
        chain.prove_nodata(&wire("y.w.example"), A, &caps, &mut budget),
        Ok((Nodata::Plain, false))
    );
    // B.5: a.z.w.example AAAA, a wildcard NODATA under an opt-out span.
    assert_eq!(
        chain.prove_nodata(&wire("a.z.w.example"), AAAA, &caps, &mut budget),
        Ok((Nodata::Wildcard, true))
    );
    assert_eq!(
        chain.prove_nodata(&wire("a.z.w.example"), MX, &caps, &mut budget),
        Err(ProofFault::Exists)
    );
    // B.4: a.z.w.example MX answered from *.w.example (the encloser has two labels).
    assert_eq!(
        chain.prove_wildcard(&wire("a.z.w.example"), 2, &caps, &mut budget),
        Ok(true)
    );
    assert_eq!(
        chain.prove_wildcard(&wire("x.w.example"), 2, &caps, &mut budget),
        Err(ProofFault::Exists)
    );
    // B.3: the referral to the unsigned c.example under the opt-out span.
    assert_eq!(
        chain.delegation(&wire("c.example"), &caps, &mut budget),
        Ok(Some(CutProof::Insecure))
    );
    assert_eq!(
        chain.prove_nodata(&wire("c.example"), DS, &caps, &mut budget),
        Ok((Nodata::Plain, true))
    );
    // a.example has its DS; ns1.example is no delegation.
    assert_eq!(
        chain.delegation(&wire("a.example"), &caps, &mut budget),
        Ok(Some(CutProof::Bogus))
    );
    assert_eq!(
        chain.delegation(&wire("ns1.example"), &caps, &mut budget),
        Ok(Some(CutProof::NotACut))
    );
    // Records of other parameters are left out of the chain.
    let mut other = zone.data[0].clone();
    other[3] = 13;
    let mixed = [
        Nsec3::parse(&zone.owners[0], &other, &apex).expect("nsec3"),
        Nsec3::parse(&zone.owners[1], &zone.data[1], &apex).expect("nsec3"),
    ];
    let chain = Chain::new(&mixed, &apex).expect("chain");
    assert_eq!(chain.iterations(), 13);
    assert_eq!(
        chain.prove_nodata(&wire("ns1.example"), MX, &caps, &mut budget),
        Err(ProofFault::Missing)
    );
    // An owner of another zone, or of another hash algorithm, is not a record.
    assert!(
        Nsec3::parse(
            &wire("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.other"),
            &zone.data[0],
            &apex
        )
        .is_none()
    );
    let mut sha256 = zone.data[0].clone();
    sha256[0] = 2;
    assert!(Nsec3::parse(&zone.owners[0], &sha256, &apex).is_none());
}
