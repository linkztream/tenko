//! The signature and DS vectors of RFC 5702 section 6 (RSA/SHA-256 and RSA/SHA-512), RFC
//! 6605 section 6 (P-256 and P-384) and RFC 8080 section 6 (Ed25519), through
//! [`crypto::verify`] and [`rrset::verify`].

use tenko_core::dns::DnsName;

use crate::{
    anchors::base64,
    dnssec::{canonical, crypto},
    recursion::ValidationCaps,
    validate::rrset::{self, Budget, Fault, RrSet, Sig},
};

fn wire(name: &str) -> Vec<u8> {
    DnsName::new(name).expect("name").to_wire()
}

fn hex(text: &str) -> Vec<u8> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// Seconds since 1970 of a `YYYYMMDDHHMMSS` time (RFC 4034 section 3.2), modulo 2^32.
fn at(text: &str) -> u32 {
    let field =
        |from: usize, len: usize| -> i64 { text[from..from + len].parse().expect("digits") };
    let (y, m, d) = (field(0, 4), field(4, 2), field(6, 2));
    let (hh, mm, ss) = (field(8, 2), field(10, 2), field(12, 2));
    // Days from civil (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u32::try_from((days * 86_400 + hh * 3600 + mm * 60 + ss).rem_euclid(1 << 32)).expect("u32")
}

/// A DNSKEY record's data.
fn dnskey(flags: u16, algorithm: u8, key: &str) -> Vec<u8> {
    let mut out = flags.to_be_bytes().to_vec();
    out.push(3);
    out.push(algorithm);
    out.extend_from_slice(&base64::decode(key).expect("base64 key"));
    out
}

/// An RRSIG record's data.
#[allow(clippy::too_many_arguments, reason = "the fields of the record")]
fn rrsig(
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer: &str,
    signature: &str,
) -> Vec<u8> {
    let mut out = type_covered.to_be_bytes().to_vec();
    out.push(algorithm);
    out.push(labels);
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&expiration.to_be_bytes());
    out.extend_from_slice(&inception.to_be_bytes());
    out.extend_from_slice(&key_tag.to_be_bytes());
    out.extend_from_slice(&wire(signer));
    out.extend_from_slice(&base64::decode(signature).expect("base64 signature"));
    out
}

/// A DS record's data.
fn ds(key_tag: u16, algorithm: u8, digest_type: u8, digest: &str) -> Vec<u8> {
    let mut out = key_tag.to_be_bytes().to_vec();
    out.push(algorithm);
    out.push(digest_type);
    out.extend_from_slice(&hex(digest));
    out
}

struct Vector {
    zone: &'static str,
    owner: &'static str,
    rtype: u16,
    ttl: u32,
    rdata: Vec<u8>,
    key: Vec<u8>,
    sig: Vec<u8>,
    ds: Option<Vec<u8>>,
    key_tag: u16,
    now: u32,
}

fn a(address: [u8; 4]) -> Vec<u8> {
    address.to_vec()
}

fn mx(preference: u16, host: &str) -> Vec<u8> {
    let mut out = preference.to_be_bytes().to_vec();
    out.extend_from_slice(&wire(host));
    out
}

#[allow(clippy::too_many_lines, reason = "the RFC vectors as printed")]
fn vectors() -> Vec<Vector> {
    vec![
        // RFC 5702 section 6.2: RSA/SHA-512, a 1,024-bit key.
        Vector {
            zone: "example.net",
            owner: "www.example.net",
            rtype: 1,
            ttl: 3600,
            rdata: a([192, 0, 2, 91]),
            key: dnskey(
                256,
                10,
                "AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL",
            ),
            sig: rrsig(
                1,
                10,
                3,
                3600,
                at("20300101000000"),
                at("20000101000000"),
                3740,
                "example.net",
                "tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw=",
            ),
            ds: None,
            key_tag: 3740,
            now: at("20200101000000"),
        },
        // RFC 6605 section 6.1: P-256.
        Vector {
            zone: "example.net",
            owner: "www.example.net",
            rtype: 1,
            ttl: 3600,
            rdata: a([192, 0, 2, 1]),
            key: dnskey(
                257,
                13,
                "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
            ),
            sig: rrsig(
                1,
                13,
                3,
                3600,
                at("20100909100439"),
                at("20100812100439"),
                55648,
                "example.net",
                "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==",
            ),
            ds: Some(ds(
                55648,
                13,
                2,
                "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17",
            )),
            key_tag: 55648,
            now: at("20100901000000"),
        },
        // RFC 6605 section 6.2: P-384.
        Vector {
            zone: "example.net",
            owner: "www.example.net",
            rtype: 1,
            ttl: 3600,
            rdata: a([192, 0, 2, 1]),
            key: dnskey(
                257,
                14,
                "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40",
            ),
            sig: rrsig(
                1,
                14,
                3,
                3600,
                at("20100909102025"),
                at("20100812102025"),
                10771,
                "example.net",
                "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm",
            ),
            ds: Some(ds(
                10771,
                14,
                4,
                "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6",
            )),
            key_tag: 10771,
            now: at("20100901000000"),
        },
        // RFC 8080 section 6.1: Ed25519, the first example.
        Vector {
            zone: "example.com",
            owner: "example.com",
            rtype: 15,
            ttl: 3600,
            rdata: mx(10, "mail.example.com"),
            key: dnskey(257, 15, "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="),
            sig: rrsig(
                15,
                15,
                3,
                3600,
                1_440_021_600,
                1_438_207_200,
                3613,
                "example.com",
                "Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkjH5GaMWeG96GUVZu6ECKOQmemHDg==",
            ),
            ds: Some(ds(
                3613,
                15,
                2,
                "3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b",
            )),
            key_tag: 3613,
            now: 1_439_000_000,
        },
        // RFC 8080 section 6.1: the second example.
        Vector {
            zone: "example.com",
            owner: "example.com",
            rtype: 15,
            ttl: 3600,
            rdata: mx(10, "mail.example.com"),
            key: dnskey(257, 15, "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs="),
            sig: rrsig(
                15,
                15,
                3,
                3600,
                1_440_021_600,
                1_438_207_200,
                35217,
                "example.com",
                "5LL2obmzdqjWI+Xto5eP5adXt/T5tMhasWvwcyW4L3SzfcRawOle9bodhC+oip9ayUGjY9T/rL4rN3bOuESGDA==",
            ),
            ds: Some(ds(
                35217,
                15,
                2,
                "401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c6614c",
            )),
            key_tag: 35217,
            now: 1_439_000_000,
        },
    ]
}

fn set<'a>(vector: &'a Vector, owner: &'a [u8]) -> RrSet<'a> {
    RrSet {
        owner,
        rtype: vector.rtype,
        ttl: vector.ttl,
        records: vec![&vector.rdata],
        sigs: vec![Sig::parse(&vector.sig).expect("sig")],
    }
}

#[test]
fn the_published_vectors_verify() {
    for vector in vectors() {
        assert_eq!(
            crypto::key_tag(&vector.key),
            vector.key_tag,
            "the key tag of {}",
            vector.zone
        );
        let owner = wire(vector.owner);
        let zone = wire(vector.zone);
        let sig = Sig::parse(&vector.sig).expect("sig");
        let signed = canonical::signed_data_wire(
            &sig.head(),
            &owner,
            tenko_core::dns::Rtype(vector.rtype),
            vector.ttl,
            [vector.rdata.as_slice()],
        );
        let key = rrset::Key::parse(&vector.key).expect("key");
        assert!(
            crypto::verify(key.algorithm, key.public_key, &signed, sig.signature),
            "algorithm {} verifies the vector",
            key.algorithm
        );
        let mut spoiled = signed.clone();
        spoiled[signed.len() - 1] ^= 1;
        assert!(!crypto::verify(
            key.algorithm,
            key.public_key,
            &spoiled,
            sig.signature
        ));
        if let Some(ds) = &vector.ds {
            assert!(
                crypto::ds_matches(&zone, &vector.key, ds),
                "the DS of {}",
                vector.key_tag
            );
            let mut wrong = ds.clone();
            wrong[4] ^= 1;
            assert!(!crypto::ds_matches(&zone, &vector.key, &wrong));
        }
        // The same through the RRset layer, within the caps (RFC 8080's examples print
        // a labels field above the owner's count, which the layer passes over).
        if usize::from(sig.labels) > crate::name::label_count(&owner) {
            continue;
        }
        let keys: Vec<&[u8]> = vec![&vector.key];
        let mut budget = Budget::default();
        let verified = rrset::verify(
            &set(&vector, &owner),
            &zone,
            &keys,
            &|_| true,
            vector.now,
            &ValidationCaps::DEFAULT,
            &mut budget,
        )
        .expect("verifies");
        assert_eq!(verified.key_tag, vector.key_tag);
        assert_eq!(verified.wildcard_labels, None);
        assert_eq!(budget.verifications, 1);
        // Out of the validity window.
        let late = rrset::verify(
            &set(&vector, &owner),
            &zone,
            &keys,
            &|_| true,
            sig.expiration.wrapping_add(10),
            &ValidationCaps::DEFAULT,
            &mut budget,
        );
        assert_eq!(late.unwrap_err(), Fault::Expired);
        let early = rrset::verify(
            &set(&vector, &owner),
            &zone,
            &keys,
            &|_| true,
            sig.inception.wrapping_sub(10),
            &ValidationCaps::DEFAULT,
            &mut budget,
        );
        assert_eq!(early.unwrap_err(), Fault::NotYetValid);
    }
}

/// RFC 5702 section 6.1 signs with a 512-bit RSA key, below the 1,024 bits RFC 8624
/// section 3.1 requires; the crypto refuses it.
#[test]
fn a_512_bit_rsa_key_is_refused() {
    let key = dnskey(
        256,
        8,
        "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=",
    );
    assert_eq!(crypto::key_tag(&key), 9033);
    let sig = rrsig(
        1,
        8,
        3,
        3600,
        at("20300101000000"),
        at("20000101000000"),
        9033,
        "example.net",
        "kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg==",
    );
    let owner = wire("www.example.net");
    let sig = Sig::parse(&sig).expect("sig");
    let signed = canonical::signed_data_wire(
        &sig.head(),
        &owner,
        tenko_core::dns::Rtype(1),
        3600,
        [a([192, 0, 2, 91]).as_slice()],
    );
    let key = rrset::Key::parse(&key).expect("key");
    assert!(!crypto::verify(8, key.public_key, &signed, sig.signature));
}

/// The shipped root anchors (RFC 7958): the DS digests of the file match the public keys
/// it carries, through the RSA key tag and the SHA-256 digest.
#[test]
fn the_root_anchors_match_their_public_keys() {
    let root = wire(".");
    for (tag, public_key, digest) in [
        (
            20326u16,
            "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
            "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        ),
        (
            38696,
            "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=",
            "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
        ),
    ] {
        let key = dnskey(257, 8, public_key);
        assert_eq!(crypto::key_tag(&key), tag);
        assert!(crypto::ds_matches(&root, &key, &ds(tag, 8, 2, digest)));
        assert!(crypto::supported_algorithm(8));
        assert!(!crypto::supported_algorithm(16));
        assert!(!crypto::supported_algorithm(1));
        assert!(crypto::supported_digest(4));
        assert!(!crypto::supported_digest(3));
    }
}

/// The caps of the `KeyTrap` class: the candidates per key tag and the verifications per
/// RRset and per query are bounded, and past a cap the set is a cap fault.
#[test]
fn colliding_key_tags_cost_at_most_the_caps() {
    let vector = &vectors()[1];
    let owner = wire(vector.owner);
    let zone = wire(vector.zone);
    // Thirty fake keys with the real key's tag, algorithm and length, sorted before the
    // real one.
    let mut keys: Vec<Vec<u8>> = Vec::new();
    for index in 0..30u16 {
        let mut fake = vec![1, 1, 3, 13];
        fake.extend_from_slice(&[0u8; 60]);
        fake.extend_from_slice(&index.to_be_bytes());
        // Fix the last two octets so that the key tag collides.
        for candidate in 0..=u16::MAX {
            let len = fake.len();
            fake[len - 2..].copy_from_slice(&candidate.to_be_bytes());
            if crypto::key_tag(&fake) == vector.key_tag {
                break;
            }
        }
        assert_eq!(crypto::key_tag(&fake), vector.key_tag);
        keys.push(fake);
    }
    keys.push(vector.key.clone());
    let keys: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    let mut budget = Budget::default();
    let caps = ValidationCaps::DEFAULT;
    let result = rrset::verify(
        &set(vector, &owner),
        &zone,
        &keys,
        &|_| true,
        vector.now,
        &caps,
        &mut budget,
    );
    assert_eq!(result.unwrap_err(), Fault::Cap);
    assert!(budget.verifications <= caps.per_rrset, "{budget:?}");
    // With room for every candidate the real key is found.
    let wide = ValidationCaps {
        per_rrset: 64,
        key_candidates: 64,
        per_query: 64,
        ..caps
    };
    let mut budget = Budget::default();
    let verified = rrset::verify(
        &set(vector, &owner),
        &zone,
        &keys,
        &|_| true,
        vector.now,
        &wide,
        &mut budget,
    )
    .expect("found past the fakes");
    assert_eq!(verified.key_tag, vector.key_tag);
    assert_eq!(budget.verifications, 31);
    // The query-wide cap stops a second set.
    let mut spent = Budget {
        verifications: caps.per_query,
        ..Budget::default()
    };
    let result = rrset::verify(
        &set(vector, &owner),
        &zone,
        &keys,
        &|_| true,
        vector.now,
        &caps,
        &mut spent,
    );
    assert_eq!(result.unwrap_err(), Fault::Cap);
}
