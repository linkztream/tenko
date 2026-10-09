//! Published test vectors for the TOTP implementation: RFC 6238 Appendix B (SHA-1, SHA-256 and
//! SHA-512 at eight digits) and RFC 4226 Appendix D (HOTP, six digits).
//!
//! The seeds are the ASCII strings of the RFCs: "12345678901234567890" (20 bytes) for SHA-1,
//! the same text repeated up to 32 bytes for SHA-256 and up to 64 bytes for SHA-512.

use tenko_auth::totp::{TotpAlgorithm, TotpParams, code_at, hotp, step_at, verify};

/// The seed of RFC 6238 for `algorithm`: "1234567890" repeated and cut to the key length
/// of the hash (20, 32 and 64 bytes).
fn rfc6238_seed(algorithm: TotpAlgorithm) -> Vec<u8> {
    let length = match algorithm {
        TotpAlgorithm::Sha1 => 20,
        TotpAlgorithm::Sha256 => 32,
        TotpAlgorithm::Sha512 => 64,
    };
    b"1234567890".iter().copied().cycle().take(length).collect()
}

/// RFC 6238 Appendix B: time in seconds, then the expected eight-digit values for SHA-1,
/// SHA-256 and SHA-512.
const RFC_6238_TABLE: [(u64, &str, &str, &str); 6] = [
    (59, "94287082", "46119246", "90693936"),
    (1_111_111_109, "07081804", "68084774", "25091201"),
    (1_111_111_111, "14050471", "67062674", "99943326"),
    (1_234_567_890, "89005924", "91819424", "93441116"),
    (2_000_000_000, "69279037", "90698825", "38618901"),
    (20_000_000_000, "65353130", "77737706", "47863826"),
];

/// RFC 4226 Appendix D: the HOTP values for counters 0 to 9.
const RFC_4226_TABLE: [&str; 10] = [
    "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
    "520489",
];

fn params(algorithm: TotpAlgorithm, digits: u32, period: u64, skew: u64) -> TotpParams {
    TotpParams {
        algorithm,
        digits,
        period,
        skew,
    }
}

#[test]
fn seeds_have_the_lengths_of_the_rfc() {
    assert_eq!(rfc6238_seed(TotpAlgorithm::Sha1), b"12345678901234567890");
    assert_eq!(
        rfc6238_seed(TotpAlgorithm::Sha256),
        b"12345678901234567890123456789012"
    );
    assert_eq!(
        rfc6238_seed(TotpAlgorithm::Sha512),
        b"1234567890123456789012345678901234567890123456789012345678901234"
    );
}

#[test]
fn rfc_6238_sha1() {
    let seed = rfc6238_seed(TotpAlgorithm::Sha1);
    let p = params(TotpAlgorithm::Sha1, 8, 30, 1);
    for (time, sha1, _, _) in RFC_6238_TABLE {
        assert_eq!(&**code_at(&seed, &p, time), sha1, "SHA1 at {time}");
    }
}

#[test]
fn rfc_6238_sha256() {
    let seed = rfc6238_seed(TotpAlgorithm::Sha256);
    let p = params(TotpAlgorithm::Sha256, 8, 30, 1);
    for (time, _, sha256, _) in RFC_6238_TABLE {
        assert_eq!(&**code_at(&seed, &p, time), sha256, "SHA256 at {time}");
    }
}

#[test]
fn rfc_6238_sha512() {
    let seed = rfc6238_seed(TotpAlgorithm::Sha512);
    let p = params(TotpAlgorithm::Sha512, 8, 30, 1);
    for (time, _, _, sha512) in RFC_6238_TABLE {
        assert_eq!(&**code_at(&seed, &p, time), sha512, "SHA512 at {time}");
    }
}

#[test]
fn rfc_6238_time_steps() {
    // The "T" column of Appendix B, as the 64-bit counter in hexadecimal.
    let p = params(TotpAlgorithm::Sha1, 8, 30, 1);
    for (time, step) in [
        (59, 0x0000_0000_0000_0001),
        (1_111_111_109, 0x0000_0000_0235_23EC),
        (1_111_111_111, 0x0000_0000_0235_23ED),
        (1_234_567_890, 0x0000_0000_0273_EF07),
        (2_000_000_000, 0x0000_0000_03F9_40AA),
        (20_000_000_000, 0x0000_0000_27BC_86AA),
    ] {
        assert_eq!(step_at(&p, time), step, "step at {time}");
    }
}

#[test]
fn rfc_6238_values_verify_at_their_own_time() {
    for (time, sha1, sha256, sha512) in RFC_6238_TABLE {
        for (algorithm, expected) in [
            (TotpAlgorithm::Sha1, sha1),
            (TotpAlgorithm::Sha256, sha256),
            (TotpAlgorithm::Sha512, sha512),
        ] {
            let seed = rfc6238_seed(algorithm);
            let p = params(algorithm, 8, 30, 1);
            assert_eq!(
                verify(&seed, &p, expected, time, None),
                Some(step_at(&p, time)),
                "{algorithm:?} at {time}"
            );
        }
    }
}

#[test]
fn rfc_4226_hotp_values() {
    let seed = rfc6238_seed(TotpAlgorithm::Sha1);
    for (counter, expected) in (0_u64..).zip(RFC_4226_TABLE) {
        assert_eq!(
            &**hotp(&seed, TotpAlgorithm::Sha1, 6, counter),
            expected,
            "HOTP counter {counter}"
        );
    }
}

#[test]
fn rfc_4226_values_through_the_time_based_path() {
    // A period of one second at a Unix time equal to the counter makes the time step the
    // HOTP counter.
    let seed = rfc6238_seed(TotpAlgorithm::Sha1);
    let p = params(TotpAlgorithm::Sha1, 6, 1, 0);
    for (counter, expected) in (0_u64..).zip(RFC_4226_TABLE) {
        assert_eq!(
            &**code_at(&seed, &p, counter),
            expected,
            "TOTP at time {counter}"
        );
        assert_eq!(
            verify(&seed, &p, expected, counter, None),
            Some(counter),
            "verify at time {counter}"
        );
    }
}

#[test]
fn rfc_4226_values_are_refused_at_other_counters() {
    // With no drift window, the value of counter n is not accepted at counter n + 1, and a
    // used step cannot be used again.
    let seed = rfc6238_seed(TotpAlgorithm::Sha1);
    let p = params(TotpAlgorithm::Sha1, 6, 1, 0);
    for (counter, expected) in (0_u64..).zip(RFC_4226_TABLE) {
        assert_eq!(verify(&seed, &p, expected, counter + 1, None), None);
        assert_eq!(verify(&seed, &p, expected, counter, Some(counter)), None);
    }
}
