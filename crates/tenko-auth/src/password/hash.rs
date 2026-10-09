//! Argon2id password hashing (IAM-03).
//!
//! Passwords are hashed in their NFKC form (see [`normalize`](super::policy::normalize))
//! with a fresh 16-byte salt, and stored as a PHC string. The work is synchronous and
//! costs tens of milliseconds and many megabytes: callers run it in `spawn_blocking`.
//!
//! The parameters follow the OWASP Password Storage Cheat Sheet. Verification takes them
//! from the stored string, so a hash made with older parameters stays verifiable;
//! [`needs_rehash`] tells the caller to store a new one after a successful login.

use std::{fmt, sync::OnceLock};

use argon2::{
    ARGON2D_IDENT, ARGON2I_IDENT, ARGON2ID_IDENT, Algorithm, Argon2, Params, PasswordHasher,
    PasswordVerifier, Version,
    password_hash::{Error as HashError, phc::PasswordHash as PhcHash},
};
use serde::{Deserialize, Serialize};

use crate::{error::AuthError, random};

/// Length of the salt in bytes.
const SALT_LEN: usize = 16;
/// Length of the hash output in bytes.
const OUTPUT_LEN: usize = 32;
/// A password that nobody uses, for the dummy hashes.
const DUMMY_PASSWORD: &str = "tenko-dummy-verification-password";

/// How expensive a hash is to compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashStrength {
    /// The OWASP baseline for Argon2id: 19,456 KiB of memory, 2 passes, 1 lane.
    Baseline,
    /// The Hardened security profile: 65,536 KiB of memory, 3 passes, 1 lane.
    Hardened,
}

const BASELINE: Params = match Params::new(19_456, 2, 1, Some(OUTPUT_LEN)) {
    Ok(params) => params,
    Err(_) => panic!("the baseline Argon2 parameters are valid"),
};

const HARDENED: Params = match Params::new(65_536, 3, 1, Some(OUTPUT_LEN)) {
    Ok(params) => params,
    Err(_) => panic!("the hardened Argon2 parameters are valid"),
};

/// The Argon2 parameters of a strength, with a 32-byte output.
pub fn params(strength: HashStrength) -> Params {
    match strength {
        HashStrength::Baseline => BASELINE,
        HashStrength::Hardened => HARDENED,
    }
}

/// A password hash as a PHC string: `$argon2id$v=19$m=...,t=...,p=...$salt$hash`.
///
/// Serializes as that string. The salt and the hash are not secret, but the type keeps
/// them out of logs: `Debug` prints a placeholder.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PasswordHash(String);

impl PasswordHash {
    /// The PHC string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Wraps a stored PHC string after checking that it is an Argon2 hash with parameters,
    /// a salt and an output.
    ///
    /// # Errors
    ///
    /// [`AuthError::Invalid`] if the string is not a complete Argon2 PHC string.
    pub fn from_phc(phc: String) -> Result<Self, AuthError> {
        let parsed = PhcHash::new(&phc).map_err(|_| not_a_hash())?;
        let is_argon2 = [ARGON2D_IDENT, ARGON2I_IDENT, ARGON2ID_IDENT].contains(&parsed.algorithm);
        if !is_argon2
            || parsed.salt.is_none()
            || parsed.hash.is_none()
            || Params::try_from(&parsed).is_err()
        {
            return Err(not_a_hash());
        }
        Ok(Self(phc))
    }
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordHash(<redacted>)")
    }
}

fn not_a_hash() -> AuthError {
    AuthError::invalid("password_hash", "not an Argon2 PHC string")
}

/// Hashes a password with a fresh random salt. `normalized` is the NFKC form of the
/// password, from [`normalize`](super::policy::normalize).
///
/// # Errors
///
/// [`AuthError::Internal`] if the system random source or the hash computation fails
/// (for example when the memory cannot be allocated).
pub fn hash_password(normalized: &str, strength: HashStrength) -> Result<PasswordHash, AuthError> {
    let salt: [u8; SALT_LEN] = random::array()?;
    hash_with_salt(normalized, params(strength), &salt)
}

fn hash_with_salt(
    normalized: &str,
    params: Params,
    salt: &[u8],
) -> Result<PasswordHash, AuthError> {
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let phc = hasher
        .hash_password_with_salt(normalized.as_bytes(), salt)
        .map_err(|_| AuthError::internal("password hashing failed"))?;
    Ok(PasswordHash(phc.to_string()))
}

/// Checks a password against a stored hash with the parameters stored in the hash.
/// `normalized` is the NFKC form of the password. Returns `Ok(false)` for a wrong
/// password; the comparison of the output is constant-time.
///
/// # Errors
///
/// [`AuthError::Internal`] if the stored hash cannot be parsed or verified.
pub fn verify_password(normalized: &str, hash: &PasswordHash) -> Result<bool, AuthError> {
    let parsed = PhcHash::new(hash.as_str())
        .map_err(|_| AuthError::internal("stored password hash cannot be parsed"))?;
    match Argon2::default().verify_password(normalized.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(HashError::PasswordInvalid) => Ok(false),
        Err(_) => Err(AuthError::internal(
            "stored password hash cannot be verified",
        )),
    }
}

/// Whether a stored hash is weaker than `strength` and should be replaced by a new hash
/// after the next successful login: it is not Argon2id, not version 19, or its memory
/// cost, number of passes, lanes or output length is below the target. A hash that cannot
/// be parsed also needs replacing.
pub fn needs_rehash(hash: &PasswordHash, strength: HashStrength) -> bool {
    let Ok(parsed) = PhcHash::new(hash.as_str()) else {
        return true;
    };
    if parsed.algorithm != ARGON2ID_IDENT || parsed.version != Some(u32::from(Version::V0x13)) {
        return true;
    }
    let Ok(current) = Params::try_from(&parsed) else {
        return true;
    };
    let target = params(strength);
    current.m_cost() < target.m_cost()
        || current.t_cost() < target.t_cost()
        || current.p_cost() < target.p_cost()
        || current.output_len().is_some_and(|len| len < OUTPUT_LEN)
}

/// Spends the cost of one verification without a stored hash, so that a login with an
/// unknown user name takes as long as one with a known user name. Pick the strength that
/// the stored hashes have.
///
/// The first call for a strength also computes the dummy hash it verifies against, and is
/// slower; call it once at start-up to keep that out of a login. If the dummy hash cannot
/// be built, the call hashes the password instead, which costs the same.
pub fn dummy_verify(normalized: &str, strength: HashStrength) {
    match dummy_hash(strength) {
        Some(dummy) => {
            let _ = verify_password(normalized, dummy);
        }
        None => {
            let _ = hash_password(normalized, strength);
        }
    }
}

/// The dummy hash of a strength, built on first use. `None` if building it failed.
fn dummy_hash(strength: HashStrength) -> Option<&'static PasswordHash> {
    static BASELINE_DUMMY: OnceLock<Option<PasswordHash>> = OnceLock::new();
    static HARDENED_DUMMY: OnceLock<Option<PasswordHash>> = OnceLock::new();
    let cell = match strength {
        HashStrength::Baseline => &BASELINE_DUMMY,
        HashStrength::Hardened => &HARDENED_DUMMY,
    };
    cell.get_or_init(|| hash_password(DUMMY_PASSWORD, strength).ok())
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password::policy::normalize;

    // The Argon2id vector of the Argon2 reference implementation, as shipped in
    // `tests/phc_strings.rs` of the `argon2` crate 0.6.0 (adapted there from `src/test.c`
    // of phc-winner-argon2): the password `password`, the salt `somesalt`, m = 65,536 KiB,
    // t = 2, p = 1, a 32-byte output.
    const KAT_PASSWORD: &str = "password";
    const KAT_SALT: &[u8] = b"somesalt";
    const KAT_PHC: &str =
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";

    const SALT_B64: &str = "c29tZXNhbHQ";
    const OUTPUT_B64: &str = "CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";
    const SHORT_OUTPUT_B64: &str = "AAAAAAAAAAAAAAAAAAAAAA";

    fn stored(phc: &str) -> PasswordHash {
        PasswordHash::from_phc(phc.to_owned()).expect("a well-formed PHC string")
    }

    #[test]
    fn parameters_follow_the_cheat_sheet() {
        let baseline = params(HashStrength::Baseline);
        assert_eq!(
            (baseline.m_cost(), baseline.t_cost(), baseline.p_cost()),
            (19_456, 2, 1)
        );
        assert_eq!(baseline.output_len(), Some(32));
        let hardened = params(HashStrength::Hardened);
        assert_eq!(
            (hardened.m_cost(), hardened.t_cost(), hardened.p_cost()),
            (65_536, 3, 1)
        );
        assert_eq!(hardened.output_len(), Some(32));
    }

    #[test]
    fn known_answer_from_the_argon2_reference_vectors() {
        let reference = Params::new(65_536, 2, 1, Some(32)).expect("valid parameters");
        let computed = hash_with_salt(KAT_PASSWORD, reference, KAT_SALT).expect("hash");
        assert_eq!(computed.as_str(), KAT_PHC);
        assert!(verify_password(KAT_PASSWORD, &stored(KAT_PHC)).expect("verify"));
    }

    #[test]
    fn baseline_round_trip_with_the_stored_parameters() {
        let password = normalize("correct horse battery staple");
        let hash = hash_password(&password, HashStrength::Baseline).expect("hash");
        assert!(
            hash.as_str().starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{hash:?}"
        );
        assert!(verify_password(&password, &hash).expect("verify"));
        assert!(!verify_password("correct horse battery stapl", &hash).expect("verify"));
        assert!(!needs_rehash(&hash, HashStrength::Baseline));
        assert!(needs_rehash(&hash, HashStrength::Hardened));
        // The hash can be stored and loaded again.
        assert_eq!(PasswordHash::from_phc(hash.as_str().to_owned()), Ok(hash));
    }

    #[test]
    fn hardened_uses_more_memory_and_passes() {
        let hash =
            hash_password("an obviously fake password", HashStrength::Hardened).expect("hash");
        assert!(
            hash.as_str().starts_with("$argon2id$v=19$m=65536,t=3,p=1$"),
            "{hash:?}"
        );
        assert!(verify_password("an obviously fake password", &hash).expect("verify"));
        assert!(!needs_rehash(&hash, HashStrength::Hardened));
        assert!(!needs_rehash(&hash, HashStrength::Baseline));
    }

    #[test]
    fn every_hash_has_its_own_salt() {
        let cheap = Params::new(32, 1, 1, Some(32)).expect("valid parameters");
        let a = hash_with_salt("fake", cheap.clone(), &[1; SALT_LEN]).expect("hash");
        let b = hash_with_salt("fake", cheap, &[2; SALT_LEN]).expect("hash");
        assert_ne!(a, b);
        let c = hash_password("fake", HashStrength::Baseline).expect("hash");
        let d = hash_password("fake", HashStrength::Baseline).expect("hash");
        assert_ne!(c, d);
    }

    #[test]
    fn composed_and_decomposed_passwords_are_one_password() {
        let composed = normalize("caf\u{e9} cr\u{e8}me");
        let decomposed = normalize("cafe\u{301} cre\u{300}me");
        let hash = hash_password(&composed, HashStrength::Baseline).expect("hash");
        assert!(verify_password(&decomposed, &hash).expect("verify"));
    }

    #[test]
    fn from_phc_accepts_complete_argon2_strings_only() {
        for variant in ["argon2id", "argon2i", "argon2d"] {
            let phc = format!("${variant}$v=19$m=32,t=1,p=1${SALT_B64}${OUTPUT_B64}");
            assert!(PasswordHash::from_phc(phc).is_ok(), "{variant}");
        }
        for garbage in [
            "",
            "garbage",
            "$",
            "$argon2id$",
            "$argon2id$v=19$m=32,t=1,p=1",
            "$argon2id$v=19$m=32,t=1,p=1$c29tZXNhbHQ",
            "$argon2id$v=19$m=32,t=1,p=1$c29tZXNhbHQ$!!!",
            "$argon2id$v=19$m=0,t=1,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
            "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E",
            "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
        ] {
            let error = PasswordHash::from_phc(garbage.to_owned()).expect_err(garbage);
            assert_eq!(error, not_a_hash(), "{garbage}");
        }
    }

    #[test]
    fn debug_does_not_print_the_hash() {
        let hash = stored(KAT_PHC);
        let printed = format!("{hash:?}");
        assert_eq!(printed, "PasswordHash(<redacted>)");
        assert!(!printed.contains("argon2"));
        assert!(!format!("{hash:#?}").contains(OUTPUT_B64));
    }

    #[test]
    fn serializes_as_a_plain_string() {
        let hash = stored(KAT_PHC);
        let json = serde_json::to_string(&hash).expect("serialize");
        assert_eq!(json, format!("\"{KAT_PHC}\""));
        let back: PasswordHash = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, hash);
    }

    #[test]
    fn an_unparsable_stored_hash_is_an_error_not_a_mismatch() {
        let broken: PasswordHash = serde_json::from_str("\"not a hash\"").expect("any string");
        assert!(matches!(
            verify_password("fake", &broken),
            Err(AuthError::Internal(_))
        ));
        assert!(needs_rehash(&broken, HashStrength::Baseline));
    }

    #[test]
    fn rehash_is_needed_when_any_cost_is_below_the_target() {
        let with = |prefix: &str, output: &str| stored(&format!("{prefix}${SALT_B64}${output}"));
        let id = |params: &str| with(&format!("$argon2id$v=19${params}"), OUTPUT_B64);

        // At the baseline: current for Baseline, weak for Hardened.
        let baseline = id("m=19456,t=2,p=1");
        assert!(!needs_rehash(&baseline, HashStrength::Baseline));
        assert!(needs_rehash(&baseline, HashStrength::Hardened));
        // Parameters in another order, more lanes than the target.
        assert!(!needs_rehash(
            &id("p=2,t=2,m=19456"),
            HashStrength::Baseline
        ));
        // One cost below the baseline.
        assert!(needs_rehash(&id("m=19455,t=2,p=1"), HashStrength::Baseline));
        assert!(needs_rehash(&id("m=19456,t=1,p=1"), HashStrength::Baseline));
        // Above the baseline in memory but not in passes.
        let reference = stored(KAT_PHC);
        assert!(!needs_rehash(&reference, HashStrength::Baseline));
        assert!(needs_rehash(&reference, HashStrength::Hardened));
        // At and just below the hardened target.
        let hardened = id("m=65536,t=3,p=1");
        assert!(!needs_rehash(&hardened, HashStrength::Hardened));
        assert!(!needs_rehash(&hardened, HashStrength::Baseline));
        assert!(needs_rehash(&id("m=65535,t=3,p=1"), HashStrength::Hardened));
        // Another variant, an old version, no version, a short output.
        let other = |prefix: &str| with(prefix, OUTPUT_B64);
        assert!(needs_rehash(
            &other("$argon2i$v=19$m=65536,t=3,p=1"),
            HashStrength::Baseline
        ));
        assert!(needs_rehash(
            &other("$argon2d$v=19$m=65536,t=3,p=1"),
            HashStrength::Baseline
        ));
        assert!(needs_rehash(
            &other("$argon2id$v=16$m=65536,t=3,p=1"),
            HashStrength::Baseline
        ));
        assert!(needs_rehash(
            &other("$argon2id$m=65536,t=3,p=1"),
            HashStrength::Baseline
        ));
        assert!(needs_rehash(
            &with("$argon2id$v=19$m=65536,t=3,p=1", SHORT_OUTPUT_B64),
            HashStrength::Baseline
        ));
    }

    #[test]
    fn dummy_verify_builds_its_hash_once() {
        dummy_verify("a fake password nobody has", HashStrength::Baseline);
        // The dummy hash is built once and reused.
        let first = dummy_hash(HashStrength::Baseline).expect("dummy hash");
        let second = dummy_hash(HashStrength::Baseline).expect("dummy hash");
        assert!(std::ptr::eq(first, second));
        assert!(!needs_rehash(first, HashStrength::Baseline));
        assert!(verify_password(DUMMY_PASSWORD, first).expect("verify"));
    }
}
