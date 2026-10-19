//! The published DNSSEC test vectors against the public API of `tenko_dns::dnssec`: the
//! Ed25519 examples of RFC 8080, the ECDSA P-256 example of RFC 6605, the key tags of the
//! example keys of RFC 4034, RFC 4035, RFC 5155, RFC 5702, RFC 6605 and RFC 8080, RSA
//! signatures of RFC 4035 and RFC 5702 (an algorithm the signer does not produce) over the
//! canonical form and the RRSIG head of `dnssec::canonical`, and the NSEC3 hashes and the
//! chain of RFC 5155, appendix A.
//!
//! Every value is copied from the RFC text. The domain names in the vectors (`example`,
//! `example.com`, `example.net`) are the documentation names of the RFCs.

use aws_lc_rs::{
    digest,
    signature::{
        RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY, RsaParameters, RsaPublicKeyComponents,
    },
};
use tenko_core::{
    dns::{DnsName, DnssecAlgorithm, KeyRole, RecordData, Rtype},
    serde_util::HexBytes,
};
use tenko_dns::dnssec::{
    canonical::{RrsigHead, rrsig_labels, signed_data, signed_data_wire},
    chain::{base32hex, nsec3_hash},
    crypto::{DIGEST_SHA256, FLAGS_KSK, KeyPair, dnskey_wire, ds, key_tag, verify},
};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn b64(text: &str) -> Vec<u8> {
    domain::utils::base64::decode(text).expect("base64")
}

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "an even number of hex digits");
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).expect("ascii");
            u8::from_str_radix(digits, 16).expect("hex digits")
        })
        .collect()
}

/// The record data of an MX record.
fn mx(preference: u16, exchange: &str) -> Vec<u8> {
    let mut out = preference.to_be_bytes().to_vec();
    out.extend_from_slice(&name(exchange).to_wire());
    out
}

/// The record data of a DNSKEY record from its presentation fields.
fn dnskey_rdata(flags: u16, algorithm: u8, public_key: &[u8]) -> Vec<u8> {
    let mut out = flags.to_be_bytes().to_vec();
    out.push(3);
    out.push(algorithm);
    out.extend_from_slice(public_key);
    out
}

/// The exponent and the modulus of an RSA public key in the DNSKEY form of RFC 3110,
/// section 2.
fn rsa_parts(public_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (&first, rest) = public_key.split_first().expect("a key");
    let (length, rest) = if first == 0 {
        let (length, rest) = rest.split_at(2);
        (
            usize::from(u16::from_be_bytes([length[0], length[1]])),
            rest,
        )
    } else {
        (usize::from(first), rest)
    };
    let (exponent, modulus) = rest.split_at(length);
    (exponent.to_vec(), modulus.to_vec())
}

/// Whether an RSA signature verifies, and that it stops verifying when the data change.
fn rsa_verifies(params: &'static RsaParameters, public_key: &[u8], data: &[u8], signature: &[u8]) {
    let (e, n) = rsa_parts(public_key);
    let key = RsaPublicKeyComponents { n, e };
    key.verify(params, data, signature)
        .expect("the published signature verifies");
    let mut other = data.to_vec();
    let last = other.last_mut().expect("data");
    *last ^= 1;
    assert!(
        key.verify(params, &other, signature).is_err(),
        "altered data must not verify"
    );
}

/// RFC 8080, section 6.1: the two Ed25519 examples. The key loads from its seed, the
/// DNSKEY has the published key tag and DS digest, and the signature over the MX RRset is
/// reproduced exactly (Ed25519 is deterministic) and verifies. The RRSIG of the RFC carries
/// the labels field 3 for the two-label owner `example.com`, which the signatures cover.
#[test]
fn rfc8080_ed25519_examples() {
    struct Example {
        seed: &'static str,
        public_key: &'static str,
        tag: u16,
        digest: &'static str,
        signature: &'static str,
    }
    let examples = [
        Example {
            seed: "ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=",
            public_key: "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
            tag: 3613,
            digest: concat!(
                "3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79",
                "a304b"
            ),
            signature: concat!(
                "Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkj",
                "H5GaMWeG96GUVZu6ECKOQmemHDg=="
            ),
        },
        Example {
            seed: "DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=",
            public_key: "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=",
            tag: 35217,
            digest: concat!(
                "401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c",
                "6614c"
            ),
            signature: concat!(
                "5LL2obmzdqjWI+Xto5eP5adXt/T5tMhasWvwcyW4L3SzfcRawOle9bodhC+",
                "oip9ayUGjY9T/rL4rN3bOuESGDA=="
            ),
        },
    ];
    let owner = name("example.com");
    let signer = name("example.com");
    let mx_data = mx(10, "mail.example.com");
    for example in examples {
        let pair = KeyPair::ed25519_from_seed(&b64(example.seed)).expect("seed");
        assert_eq!(pair.algorithm(), DnssecAlgorithm::Ed25519);
        let public_key = pair.public_key();
        assert_eq!(public_key, b64(example.public_key), "tag {}", example.tag);

        let rdata = dnskey_wire(KeyRole::Ksk, DnssecAlgorithm::Ed25519, &public_key);
        assert_eq!(rdata, dnskey_rdata(FLAGS_KSK, 15, &public_key));
        assert_eq!(key_tag(&rdata), example.tag);
        assert_eq!(
            ds(&owner, KeyRole::Ksk, DnssecAlgorithm::Ed25519, &public_key),
            RecordData::Ds {
                key_tag: example.tag,
                algorithm: 15,
                digest_type: DIGEST_SHA256,
                digest: HexBytes(hex(example.digest)),
            }
        );

        // The RRSIG of the RFC prints the labels field 3, although `example.com` has two
        // labels (RFC 4034, section 3.1.3); the published signatures are over 3.
        assert_eq!(rrsig_labels(&owner), 2);
        let head = RrsigHead {
            type_covered: Rtype::MX,
            algorithm: 15,
            labels: 3,
            original_ttl: 3600,
            expiration: 1_440_021_600,
            inception: 1_438_207_200,
            key_tag: example.tag,
            signer: &signer,
        };
        let data = signed_data(&head, &owner, Rtype::MX, [mx_data.as_slice()]);
        let signature = pair.sign(&data).expect("sign");
        assert_eq!(signature, b64(example.signature), "tag {}", example.tag);
        assert!(verify(15, &public_key, &data, &signature));
        assert!(verify(15, &public_key, &data, &b64(example.signature)));
        assert!(!verify(15, &public_key, b"other data", &signature));
    }
}

/// RFC 6605, section 6.1: the ECDSA P-256 example. The DNSKEY has the published key tag
/// and DS digest, and the published RRSIG over the A record verifies. ECDSA signing is
/// randomized, so only the verification is compared.
#[test]
fn rfc6605_p256_example() {
    let public_key = b64(concat!(
        "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb",
        "krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="
    ));
    assert_eq!(public_key.len(), 64);
    let rdata = dnskey_wire(KeyRole::Ksk, DnssecAlgorithm::EcdsaP256Sha256, &public_key);
    assert_eq!(rdata, dnskey_rdata(257, 13, &public_key));
    assert_eq!(key_tag(&rdata), 55648);

    let apex = name("example.net");
    assert_eq!(
        ds(
            &apex,
            KeyRole::Ksk,
            DnssecAlgorithm::EcdsaP256Sha256,
            &public_key
        ),
        RecordData::Ds {
            key_tag: 55648,
            algorithm: 13,
            digest_type: DIGEST_SHA256,
            digest: HexBytes(hex(concat!(
                "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1",
                "e2770ce6d6e37df61d17"
            ))),
        }
    );

    let owner = name("www.example.net");
    // 20100909100439 and 20100812100439, UTC.
    let head = RrsigHead {
        type_covered: Rtype::A,
        algorithm: 13,
        labels: rrsig_labels(&owner),
        original_ttl: 3600,
        expiration: 1_284_026_679,
        inception: 1_281_607_479,
        key_tag: 55648,
        signer: &apex,
    };
    assert_eq!(head.labels, 3);
    let address = [192, 0, 2, 1];
    let data = signed_data(&head, &owner, Rtype::A, [address.as_slice()]);
    let signature = b64(concat!(
        "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA",
        "yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw=="
    ));
    assert_eq!(signature.len(), 64);
    assert!(verify(13, &public_key, &data, &signature));
    let other = signed_data(&head, &owner, Rtype::A, [[192, 0, 2, 2].as_slice()]);
    assert!(!verify(13, &public_key, &other, &signature));
}

/// The example DNSKEYs with a published key tag: source, flags, algorithm, public key
/// and tag.
const KEY_TAGS: [(&str, u16, u8, &str, u16); 14] = [
    (
        "RFC 4034, section 2.3",
        256,
        5,
        concat!(
            "AQPSKmynfzW4kyBv015MUG2DeIQ3",
            "Cbl+BBZH4b/0PY1kxkmvHjcZc8no",
            "kfzj31GajIQKY+5CptLr3buXA10h",
            "WqTkF7H6RfoRqXQeogmMHfpftf6z",
            "Mv1LyBUgia7za6ZEzOJBOztyvhjL",
            "742iU/TpPSEDhm2SNKLijfUppn1U",
            "aNvv4w=="
        ),
        2642,
    ),
    (
        "RFC 4034, section 5.4",
        256,
        5,
        concat!(
            "AQOeiiR0GOMYkDshWoSKz9Xz",
            "fwJr1AYtsmx3TGkJaNXVbfi/",
            "2pHm822aJ5iI9BMzNXxeYCmZ",
            "DRD99WYwYqUSdjMmmAphXdvx",
            "egXd/M5+X7OrzKBaMbCVdFLU",
            "Uh6DhweJBjEVv5f2wwjM9Xzc",
            "nOf+EPbtG9DMBmADjFDc2w/r",
            "ljwvFw=="
        ),
        60485,
    ),
    (
        "RFC 4035, appendix A, ZSK",
        256,
        5,
        concat!(
            "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBV",
            "rZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e",
            "k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFo",
            "vBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI",
            "ySFNsgEYvh0z2542lzMKR4Dh8uZffQ=="
        ),
        38519,
    ),
    (
        "RFC 4035, appendix A, KSK",
        257,
        5,
        concat!(
            "AQOeX7+baTmvpVHb2CcLnL1dMRWbuscRvHXl",
            "LnXwDzvqp4tZVKp1sZMepFb8MvxhhW3y/0QZ",
            "syCjczGJ1qk8vJe52iOhInKROVLRwxGpMfzP",
            "RLMlGybr51bOV/1se0ODacj3DomyB4QB5gKT",
            "Yot/K9alk5/j8vfd4jWCWD+E1Sze0Q=="
        ),
        9465,
    ),
    (
        "RFC 5155, appendix A, ZSK",
        256,
        7,
        concat!(
            "AwEAAaetidLzsKWUt4swWR8yu0wPHPiUi8LU",
            "sAD0QPWU+wzt89epO6tHzkMBVDkC7qphQO2h",
            "TY4hHn9npWFRw5BYubE="
        ),
        40430,
    ),
    (
        "RFC 5155, appendix A, KSK",
        257,
        7,
        concat!(
            "AwEAAcUlFV1vhmqx6NSOUOq2R/dsR7Xm3upJ",
            "j7IommWSpJABVfW8Q0rOvXdM6kzt+TAu92L9",
            "AbsUdblMFin8CVF3n4s="
        ),
        12708,
    ),
    (
        "RFC 5702, section 6.1",
        256,
        8,
        concat!(
            "AwEAAcFcGsaxxdgiuuGmCkVI",
            "my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P",
            "kxUdp6p/DlUmObdk="
        ),
        9033,
    ),
    (
        "RFC 5702, section 6.2",
        256,
        10,
        concat!(
            "AwEAAdHoNTOW+et86KuJOWRD",
            "p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD",
            "xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g",
            "pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL"
        ),
        3740,
    ),
    (
        "RFC 6605, section 6.1",
        257,
        13,
        concat!(
            "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb",
            "krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="
        ),
        55648,
    ),
    (
        "RFC 6605, section 6.2",
        257,
        14,
        concat!(
            "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1",
            "w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8",
            "/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40"
        ),
        10771,
    ),
    (
        "RFC 8080, section 6.1, first",
        257,
        15,
        "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
        3613,
    ),
    (
        "RFC 8080, section 6.1, second",
        257,
        15,
        "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=",
        35217,
    ),
    (
        "RFC 8080, section 6.2, first",
        257,
        16,
        concat!(
            "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx",
            "1FYYUcJKm1MDpJtIA"
        ),
        9713,
    ),
    (
        "RFC 8080, section 6.2, second",
        257,
        16,
        concat!(
            "kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3tDjeMCJcVMRDmgcN",
            "Lp5HlHAMy12VoISsA"
        ),
        38353,
    ),
];

/// RFC 4034, section 2.3, section 3.3 and section 5.4 (appendix B is the algorithm), RFC
/// 4035 appendix A, RFC 5155 appendix A, RFC 5702 section 6, RFC 6605 section 6 and RFC
/// 8080 section 6: the key tag of every example DNSKEY the RFCs give a tag for. RFC 4034
/// section 3.3 names tag 2642 for the example.com key of section 2.3; RFC 5702 prints the
/// tags in comments after the DNSKEYs; the others are the RRSIG and DS key tags.
#[test]
fn key_tags_of_the_example_keys() {
    for (source, flags, algorithm, public_key, tag) in KEY_TAGS {
        let rdata = dnskey_rdata(flags, algorithm, &b64(public_key));
        assert_eq!(key_tag(&rdata), tag, "{source}");
    }
}

/// RFC 4034, section 5.4: the DS digest of the example DNSKEY is SHA-1 over the owner and
/// the DNSKEY record data (digest type 1; Tenko computes only SHA-256, so the digest is
/// taken here from the same canonical inputs).
#[test]
fn rfc4034_ds_example_digest() {
    let public_key = b64(concat!(
        "AQOeiiR0GOMYkDshWoSKz9Xz",
        "fwJr1AYtsmx3TGkJaNXVbfi/",
        "2pHm822aJ5iI9BMzNXxeYCmZ",
        "DRD99WYwYqUSdjMmmAphXdvx",
        "egXd/M5+X7OrzKBaMbCVdFLU",
        "Uh6DhweJBjEVv5f2wwjM9Xzc",
        "nOf+EPbtG9DMBmADjFDc2w/r",
        "ljwvFw=="
    ));
    let rdata = dnskey_rdata(256, 5, &public_key);
    assert_eq!(key_tag(&rdata), 60485);
    let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(&name("dskey.example.com").to_wire());
    context.update(&rdata);
    assert_eq!(
        context.finish().as_ref(),
        hex(concat!("2BB183AF5F22588179A53B0A", "98631FAD1A292118")).as_slice()
    );
}

/// The zone signing key and the key signing key of RFC 4035, appendix A.
const RFC4035_ZSK: &str = concat!(
    "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBV",
    "rZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e",
    "k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFo",
    "vBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI",
    "ySFNsgEYvh0z2542lzMKR4Dh8uZffQ=="
);
const RFC4035_KSK: &str = concat!(
    "AQOeX7+baTmvpVHb2CcLnL1dMRWbuscRvHXl",
    "LnXwDzvqp4tZVKp1sZMepFb8MvxhhW3y/0QZ",
    "syCjczGJ1qk8vJe52iOhInKROVLRwxGpMfzP",
    "RLMlGybr51bOV/1se0ODacj3DomyB4QB5gKT",
    "Yot/K9alk5/j8vfd4jWCWD+E1Sze0Q=="
);

const RFC4035_SIG_SOA: &str = concat!(
    "ONx0k36rcjaxYtcNgq6iQnpNV5+drqYAsC9h",
    "7TSJaHCqbhE67Sr6aH2xDUGcqQWu/n0UVzrF",
    "vkgO9ebarZ0GWDKcuwlM6eNB5SiX2K74l5LW",
    "DA7S/Un/IbtDq4Ay8NMNLQI7Dw7n4p8/rjkB",
    "jV7j86HyQgM5e7+miRAz8V01b0I="
);
const RFC4035_SIG_NS: &str = concat!(
    "gl13F00f2U0R+SWiXXLHwsMY+qStYy5k6zfd",
    "EuivWc+wd1fmbNCyql0Tk7lHTX6UOxc8AgNf",
    "4ISFve8XqF4q+o9qlnqIzmppU3LiNeKT4FZ8",
    "RO5urFOvoMRTbQxW3U0hXWuggE4g3ZpsHv48",
    "0HjMeRaZB/FRPGfJPajngcq6Kwg="
);
const RFC4035_SIG_MX: &str = concat!(
    "HyDHYVT5KHSZ7HtO/vypumPmSZQrcOP3tzWB",
    "2qaKkHVPfau/DgLgS/IKENkYOGL95G4N+NzE",
    "VyNU8dcTOckT+ChPcGeVjguQ7a3Ao9Z/ZkUO",
    "6gmmUW4b89rz1PUxW4jzUxj66PTwoVtUU/iM",
    "W6OISukd1EQt7a0kygkg+PEDxdI="
);
const RFC4035_SIG_DNSKEY_KSK: &str = concat!(
    "ZxgauAuIj+k1YoVEOSlZfx41fcmKzTFHoweZ",
    "xYnz99JVQZJ33wFS0Q0jcP7VXKkaElXk9nYJ",
    "XevO/7nAbo88iWsMkSpSR6jWzYYKwfrBI/L9",
    "hjYmyVO9m6FjQ7uwM4dCP/bIuV/DKqOAK9NY",
    "NC3AHfvCV1Tp4VKDqxqG7R5tTVM="
);
const RFC4035_SIG_DNSKEY_ZSK: &str = concat!(
    "eGL0s90glUqcOmloo/2y+bSzyEfKVOQViD9Z",
    "DNhLz/Yn9CQZlDVRJffACQDAUhXpU/oP34ri",
    "bKBpysRXosczFrKqS5Oa0bzMOfXCXup9qHAp",
    "eFIku28Vqfr8Nt7cigZLxjK+u0Ws/4lIRjKk",
    "7z5OXogYVaFzHKillDt3HRxHIZM="
);
const RFC4035_SIG_A: &str = concat!(
    "pAOtzLP2MU0tDJUwHOKE5FPIIHmdYsCgTb5B",
    "ERGgpnJluA9ixOyf6xxVCgrEJW0WNZSsJicd",
    "hBHXfDmAGKUajUUlYSAH8tS4ZnrhyymIvk3u",
    "ArDu2wfT130e9UHnumaHHMpUTosKe22PblOy",
    "6zrTpg9FkS0XGVmYRvOTNYx2HvQ="
);

/// RFC 4035, appendix A: RSASHA1 (algorithm 5, 1024-bit key) RRSIGs of the signed zone
/// `example.` verified over `canonical::signed_data_wire` and the RRSIG head of
/// `RrsigHead`: the SOA, NS, MX and A RRsets signed by the ZSK 38519, and the DNSKEY RRset
/// signed by both the KSK 9465 and the ZSK 38519. This checks the owner and RRSIG head
/// encodings, the record data order and the TTL of the canonical form with an algorithm
/// the signer does not use.
#[test]
fn rfc4035_appendix_a_rsasha1_signatures() {
    let zsk = b64(RFC4035_ZSK);
    let ksk = b64(RFC4035_KSK);
    let zsk_rdata = dnskey_rdata(256, 5, &zsk);
    let ksk_rdata = dnskey_rdata(257, 5, &ksk);
    assert_eq!(key_tag(&zsk_rdata), 38519);
    assert_eq!(key_tag(&ksk_rdata), 9465);

    // example. SOA ns1.example. bugs.x.w.example. 1081539377 3600 300 3600000 3600
    let mut soa = name("ns1.example").to_wire();
    soa.extend_from_slice(&name("bugs.x.w.example").to_wire());
    for number in [1_081_539_377_u32, 3600, 300, 3_600_000, 3600] {
        soa.extend_from_slice(&number.to_be_bytes());
    }
    let ns = [name("ns1.example").to_wire(), name("ns2.example").to_wire()];
    let ns: Vec<&[u8]> = ns.iter().map(Vec::as_slice).collect();
    let mx_data = mx(1, "xx.example");
    let address = [192, 0, 2, 9];
    let dnskeys = [zsk_rdata.as_slice(), ksk_rdata.as_slice()];

    let apex = name("example");
    let host = name("ai.example");
    let cases = [
        (
            "SOA",
            Rtype::SOA,
            &apex,
            vec![soa.as_slice()],
            38519,
            RFC4035_SIG_SOA,
        ),
        ("NS", Rtype::NS, &apex, ns, 38519, RFC4035_SIG_NS),
        (
            "MX",
            Rtype::MX,
            &apex,
            vec![mx_data.as_slice()],
            38519,
            RFC4035_SIG_MX,
        ),
        (
            "DNSKEY by the KSK",
            Rtype::DNSKEY,
            &apex,
            dnskeys.to_vec(),
            9465,
            RFC4035_SIG_DNSKEY_KSK,
        ),
        (
            "DNSKEY by the ZSK",
            Rtype::DNSKEY,
            &apex,
            dnskeys.to_vec(),
            38519,
            RFC4035_SIG_DNSKEY_ZSK,
        ),
        (
            "A of ai.example.",
            Rtype::A,
            &host,
            vec![address.as_slice()],
            38519,
            RFC4035_SIG_A,
        ),
    ];
    for (label, rtype, owner, rdata, tag, signature) in cases {
        // 20040509183619 and 20040409183619, UTC.
        let head = RrsigHead {
            type_covered: rtype,
            algorithm: 5,
            labels: rrsig_labels(owner),
            original_ttl: 3600,
            expiration: 1_084_127_779,
            inception: 1_081_535_779,
            key_tag: tag,
            signer: &apex,
        };
        // The same octets through the head's wire form and the owner's wire form.
        let data = signed_data_wire(&head.wire(), &owner.to_wire(), rtype, 3600, rdata.clone());
        assert_eq!(
            data,
            signed_data(&head, owner, rtype, rdata),
            "{label}: the two entry points agree"
        );
        let key = if tag == 9465 { &ksk } else { &zsk };
        rsa_verifies(
            &RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            key,
            &data,
            &b64(signature),
        );
    }
}

/// RFC 5702, section 6.2: RSASHA512 (algorithm 10, 1024-bit key) RRSIG over the A record
/// of `www.example.net.`, inception 2000-01-01 and expiration 2030-01-01, verified over
/// the canonical form. (The RSASHA256 example of section 6.1 has a 512-bit key, which
/// aws-lc-rs does not verify.)
#[test]
fn rfc5702_rsasha512_signature() {
    let public_key = b64(concat!(
        "AwEAAdHoNTOW+et86KuJOWRD",
        "p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD",
        "xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g",
        "pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL"
    ));
    let apex = name("example.net");
    let owner = name("www.example.net");
    let head = RrsigHead {
        type_covered: Rtype::A,
        algorithm: 10,
        labels: rrsig_labels(&owner),
        original_ttl: 3600,
        expiration: 1_893_456_000,
        inception: 946_684_800,
        key_tag: 3740,
        signer: &apex,
    };
    let address = [192, 0, 2, 91];
    let data = signed_data(&head, &owner, Rtype::A, [address.as_slice()]);
    let signature = b64(concat!(
        "tsb4wnjRUDnB1BUi+t",
        "6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa",
        "eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL",
        "DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw",
        "="
    ));
    rsa_verifies(
        &RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
        &public_key,
        &data,
        &signature,
    );
}

/// RFC 5155, appendix A: the hashes of the names of the example zone (salt `aabbccdd`, 12
/// iterations), including the hashed owner name of the A record that is a name in the
/// zone itself, and the NSEC3 chain: the hashes in order, each followed by the next hashed
/// owner of the NSEC3 records, the last pointing back to the first.
#[test]
fn rfc5155_appendix_a_hashes_and_chain() {
    let salt = hex("aabbccdd");
    let hashes = [
        ("example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
        ("a.example", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
        ("ai.example", "gjeqe526plbf1g8mklp59enfd789njgi"),
        ("ns1.example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
        ("ns2.example", "q04jkcevqvmu85r014c7dkba38o0ji5r"),
        ("w.example", "k8udemvp1j2f7eg6jebps17vp3n8i58h"),
        ("*.w.example", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
        ("x.w.example", "b4um86eghhds6nea196smvmlo4ors995"),
        ("y.w.example", "ji6neoaepv8b5o6k4ev33abha8ht9fgc"),
        ("x.y.w.example", "2vptu5timamqttgl4luu9kg21e0aor3s"),
        ("xx.example", "t644ebqk9bibcna874givr6joj62mlhv"),
        (
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example",
            "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
        ),
    ];
    let mut labels = Vec::new();
    for (owner, label) in hashes {
        let hash = nsec3_hash(&name(owner).to_wire(), &salt, 12);
        assert_eq!(base32hex(&hash).as_slice(), label.as_bytes(), "{owner}");
        labels.push(label);
    }
    // The NSEC3 records of the appendix: owner hash and the next hashed owner.
    let chain = [
        (
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
        ),
        (
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
            "2vptu5timamqttgl4luu9kg21e0aor3s",
        ),
        (
            "2vptu5timamqttgl4luu9kg21e0aor3s",
            "35mthgpgcu1qg68fab165klnsnk3dpvl",
        ),
        (
            "35mthgpgcu1qg68fab165klnsnk3dpvl",
            "b4um86eghhds6nea196smvmlo4ors995",
        ),
        (
            "b4um86eghhds6nea196smvmlo4ors995",
            "gjeqe526plbf1g8mklp59enfd789njgi",
        ),
        (
            "gjeqe526plbf1g8mklp59enfd789njgi",
            "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
        ),
        (
            "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
            "k8udemvp1j2f7eg6jebps17vp3n8i58h",
        ),
        (
            "k8udemvp1j2f7eg6jebps17vp3n8i58h",
            "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
        ),
        (
            "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
            "q04jkcevqvmu85r014c7dkba38o0ji5r",
        ),
        (
            "q04jkcevqvmu85r014c7dkba38o0ji5r",
            "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
        ),
        (
            "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
            "t644ebqk9bibcna874givr6joj62mlhv",
        ),
        (
            "t644ebqk9bibcna874givr6joj62mlhv",
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
        ),
    ];
    // The hashes sort in the order of the base32hex labels, which is the order of the
    // chain; every hash is followed by its successor and the last wraps around.
    labels.sort_unstable();
    assert_eq!(labels.len(), chain.len());
    for (index, (owner, next)) in chain.iter().enumerate() {
        assert_eq!(labels[index], *owner);
        assert_eq!(labels[(index + 1) % labels.len()], *next, "after {owner}");
    }
}
