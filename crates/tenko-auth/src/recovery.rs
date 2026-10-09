//! Recovery codes (IAM-06): generated in a batch, shown once, stored hashed.
//!
//! A code carries 80 random bits and is displayed as 16 characters of the RFC 4648 base32
//! alphabet in four groups (`ABCD-EFGH-IJKL-MNOP`). Only the salted SHA-256 of the normalized
//! code is kept; at 80 bits of entropy a fast hash is sufficient, since the search space is
//! out of reach for an attacker who holds the store. A used code is marked with the time of
//! use and never matches again.
//!
//! Nothing in this module logs a code, and the `Debug` output of the types never contains
//! one (or a full hash or salt).

use std::fmt;

use aws_lc_rs::constant_time::verify_slices_are_equal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenko_core::Timestamp;
use zeroize::Zeroizing;

use crate::{
    encoding::{base32_encode, hex_encode},
    error::AuthError,
    random,
};

/// How many recovery codes a batch holds.
pub const RECOVERY_CODE_COUNT: usize = 10;

/// Random bytes per code: 80 bits, which are exactly 16 base32 characters.
const CODE_BYTES: usize = 10;
/// Characters of a normalized code.
const CODE_CHARS: usize = 16;
/// Characters per displayed group.
const GROUP_CHARS: usize = 4;
/// Bytes of the per-code salt.
const SALT_LEN: usize = 16;

/// One stored recovery code: a per-code salt and `SHA-256(salt || normalized code)`.
///
/// `Debug` shows a short redacted prefix of the salt and the hash, never their full bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRecoveryCode {
    /// The per-code random salt.
    pub salt: [u8; 16],
    /// SHA-256 over the salt followed by the normalized code.
    pub hash: [u8; 32],
    /// When the code was used; `None` while it is unused.
    pub used_at: Option<Timestamp>,
}

impl StoredRecoveryCode {
    /// Whether the code was used already.
    pub const fn is_used(&self) -> bool {
        self.used_at.is_some()
    }
}

impl fmt::Debug for StoredRecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredRecoveryCode")
            .field("salt", &format_args!("{}..", redacted_prefix(&self.salt)))
            .field("hash", &format_args!("{}..", redacted_prefix(&self.hash)))
            .field("used_at", &self.used_at)
            .finish()
    }
}

/// The first two bytes in hexadecimal: enough to tell entries apart in a log line, far from
/// enough to use.
fn redacted_prefix(bytes: &[u8]) -> String {
    hex_encode(bytes.get(..2).unwrap_or_default())
}

/// A freshly generated batch of recovery codes.
///
/// `display` holds the codes to show to the user once; `stored` holds the matching entries to
/// persist, in the same order. `Debug` redacts the display codes.
pub struct GeneratedRecoveryCodes {
    /// The codes as shown once, `ABCD-EFGH-IJKL-MNOP`. Zeroized on drop.
    pub display: Vec<Zeroizing<String>>,
    /// The entries to store, one per displayed code.
    pub stored: Vec<StoredRecoveryCode>,
}

impl fmt::Debug for GeneratedRecoveryCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedRecoveryCodes")
            .field(
                "display",
                &format_args!("[{} codes redacted]", self.display.len()),
            )
            .field("stored", &self.stored)
            .finish()
    }
}

/// Generates [`RECOVERY_CODE_COUNT`] codes of 80 random bits each, with a random salt per
/// code. The display form is returned once and must not be stored; persist `stored`.
///
/// # Errors
///
/// [`AuthError::Internal`] if the system random source fails.
pub fn generate() -> Result<GeneratedRecoveryCodes, AuthError> {
    let mut display = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut stored = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut raw = Zeroizing::new([0_u8; CODE_BYTES]);
        random::fill(raw.as_mut_slice())?;
        let normalized = Zeroizing::new(base32_encode(raw.as_slice()));
        let salt = random::array::<SALT_LEN>()?;
        stored.push(StoredRecoveryCode {
            salt,
            hash: hash_code(&salt, &normalized),
            used_at: None,
        });
        display.push(group(&normalized));
    }
    Ok(GeneratedRecoveryCodes { display, stored })
}

/// Brings user input to the stored form: ASCII letters in uppercase, whitespace and hyphens
/// dropped. Other characters are kept, so input that is not a code never normalizes into one.
pub fn normalize(input: &str) -> Zeroizing<String> {
    Zeroizing::new(
        input
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    )
}

/// The index of the unused stored code that matches `input`, if any.
///
/// The input is normalized first. The hash of every stored code is computed and compared in
/// constant time, with no early exit on a match; used codes never match. Input that cannot
/// be a code (wrong length or characters outside the base32 alphabet) matches nothing.
pub fn find(input: &str, stored: &[StoredRecoveryCode]) -> Option<usize> {
    let normalized = normalize(input);
    if !is_well_formed(&normalized) {
        return None;
    }
    let mut found = None;
    for (index, entry) in stored.iter().enumerate() {
        let candidate = hash_code(&entry.salt, &normalized);
        let equal = verify_slices_are_equal(&candidate, &entry.hash).is_ok();
        if equal && !entry.is_used() && found.is_none() {
            found = Some(index);
        }
    }
    found
}

/// How many stored codes are still unused.
pub fn remaining(stored: &[StoredRecoveryCode]) -> usize {
    stored.iter().filter(|entry| !entry.is_used()).count()
}

/// `SHA-256(salt || normalized code)`.
fn hash_code(salt: &[u8; SALT_LEN], normalized: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(normalized.as_bytes());
    hasher.finalize().into()
}

/// Whether the text has the length and alphabet (A-Z, 2-7) of a normalized code.
fn is_well_formed(normalized: &str) -> bool {
    normalized.len() == CODE_CHARS
        && normalized
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
}

/// `ABCDEFGHIJKLMNOP` as `ABCD-EFGH-IJKL-MNOP`.
fn group(normalized: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(CODE_CHARS + CODE_CHARS / GROUP_CHARS));
    for (index, c) in normalized.chars().enumerate() {
        if index > 0 && index % GROUP_CHARS == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether `code` looks like `XXXX-XXXX-XXXX-XXXX` over the base32 alphabet.
    fn has_display_shape(code: &str) -> bool {
        let groups: Vec<&str> = code.split('-').collect();
        groups.len() == 4
            && groups.iter().all(|group| {
                group.len() == 4
                    && group
                        .bytes()
                        .all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
            })
    }

    fn batch() -> GeneratedRecoveryCodes {
        generate().expect("generate")
    }

    #[test]
    fn a_batch_has_ten_codes_in_the_display_format() {
        let codes = batch();
        assert_eq!(RECOVERY_CODE_COUNT, 10);
        assert_eq!(codes.display.len(), RECOVERY_CODE_COUNT);
        assert_eq!(codes.stored.len(), RECOVERY_CODE_COUNT);
        for code in &codes.display {
            assert_eq!(code.len(), 19, "{}", code.as_str());
            assert!(has_display_shape(code), "{}", code.as_str());
        }
    }

    #[test]
    fn codes_and_salts_are_unique_and_unused() {
        let codes = batch();
        for (i, a) in codes.display.iter().enumerate() {
            for b in &codes.display[i + 1..] {
                assert_ne!(**a, **b);
            }
        }
        for (i, a) in codes.stored.iter().enumerate() {
            assert!(!a.is_used());
            assert_eq!(a.used_at, None);
            for b in &codes.stored[i + 1..] {
                assert_ne!(a.salt, b.salt);
                assert_ne!(a.hash, b.hash);
            }
        }
        // A second batch shares nothing with the first.
        let other = batch();
        assert!(
            codes
                .display
                .iter()
                .all(|code| !other.display.contains(code))
        );
    }

    #[test]
    fn the_stored_hash_is_the_salted_sha256_of_the_normalized_code() {
        let codes = batch();
        for (display, stored) in codes.display.iter().zip(&codes.stored) {
            let mut hasher = Sha256::new();
            hasher.update(stored.salt);
            hasher.update(display.replace('-', "").as_bytes());
            let expected: [u8; 32] = hasher.finalize().into();
            assert_eq!(stored.hash, expected);
        }
    }

    #[test]
    fn find_accepts_the_displayed_form() {
        let codes = batch();
        for (index, code) in codes.display.iter().enumerate() {
            assert_eq!(find(code, &codes.stored), Some(index));
        }
    }

    #[test]
    fn find_ignores_hyphens_spaces_and_case() {
        let codes = batch();
        let code = codes.display[3].as_str();
        let plain = code.replace('-', "");
        assert_eq!(find(&plain, &codes.stored), Some(3));
        assert_eq!(find(&code.to_lowercase(), &codes.stored), Some(3));
        assert_eq!(find(&plain.to_lowercase(), &codes.stored), Some(3));
        assert_eq!(find(&code.replace('-', " "), &codes.stored), Some(3));
        assert_eq!(find(&format!("  {code}\n"), &codes.stored), Some(3));
    }

    #[test]
    fn find_skips_used_codes() {
        let mut codes = batch();
        let code = codes.display[5].as_str().to_owned();
        assert_eq!(find(&code, &codes.stored), Some(5));
        codes.stored[5].used_at = Some(Timestamp::now());
        assert!(codes.stored[5].is_used());
        assert_eq!(find(&code, &codes.stored), None);
        // The others still work.
        assert_eq!(find(codes.display[4].as_str(), &codes.stored), Some(4));
        assert_eq!(find(codes.display[6].as_str(), &codes.stored), Some(6));
    }

    #[test]
    fn find_returns_none_for_unknown_or_malformed_input() {
        let codes = batch();
        assert_eq!(find("AAAA-AAAA-AAAA-AAAA", &codes.stored), None);
        assert_eq!(find("", &codes.stored), None);
        assert_eq!(find("----", &codes.stored), None);
        let code = codes.display[0].as_str();
        assert_eq!(find(&code[..code.len() - 1], &codes.stored), None);
        assert_eq!(find(&format!("{code}A"), &codes.stored), None);
        // A character outside the alphabet.
        let with_digit = format!("{}1", &code[..code.len() - 1]);
        assert_eq!(find(&with_digit, &codes.stored), None);
        assert_eq!(find(code, &[]), None);
    }

    #[test]
    fn a_code_does_not_match_another_batch() {
        let first = batch();
        let second = batch();
        for code in &first.display {
            assert_eq!(find(code, &second.stored), None);
        }
    }

    #[test]
    fn remaining_counts_unused_codes() {
        let mut codes = batch();
        assert_eq!(remaining(&codes.stored), 10);
        codes.stored[0].used_at = Some(Timestamp::now());
        codes.stored[9].used_at = Some(Timestamp::now());
        assert_eq!(remaining(&codes.stored), 8);
        for entry in &mut codes.stored {
            entry.used_at = Some(Timestamp::now());
        }
        assert_eq!(remaining(&codes.stored), 0);
        assert_eq!(remaining(&[]), 0);
    }

    #[test]
    fn normalize_uppercases_and_drops_separators() {
        assert_eq!(&**normalize("abcd-efgh ijkl\tmnop"), "ABCDEFGHIJKLMNOP");
        assert_eq!(&**normalize(" a-b c "), "ABC");
        assert_eq!(&**normalize(""), "");
        // Non-ASCII characters are kept as they are, never folded into the alphabet.
        assert_eq!(&**normalize("\u{17f}"), "\u{17f}");
    }

    #[test]
    fn debug_output_contains_no_code_and_no_full_hash() {
        let codes = batch();
        let text = format!("{codes:?}");
        for (display, stored) in codes.display.iter().zip(&codes.stored) {
            assert!(!text.contains(display.as_str()));
            assert!(!text.contains(&display.replace('-', "")));
            assert!(!text.contains(&hex_encode(&stored.hash)));
            assert!(!text.contains(&hex_encode(&stored.salt)));
        }
        assert!(text.contains("10 codes redacted"));
        let one = format!("{:?}", codes.stored[0]);
        assert!(one.contains("StoredRecoveryCode"));
        assert!(one.contains(&format!("{}..", hex_encode(&codes.stored[0].hash[..2]))));
        assert!(!one.contains(&hex_encode(&codes.stored[0].hash)));
        assert!(!one.contains(&hex_encode(&codes.stored[0].salt)));
        assert!(!one.contains(&format!("{:?}", codes.stored[0].hash)));
    }

    #[test]
    fn stored_codes_round_trip_through_cbor_and_json() {
        let mut codes = batch();
        codes.stored[1].used_at = Some(Timestamp::now());
        for entry in &codes.stored {
            let mut cbor = Vec::new();
            ciborium::into_writer(entry, &mut cbor).expect("encode");
            let back: StoredRecoveryCode = ciborium::from_reader(cbor.as_slice()).expect("decode");
            assert_eq!(&back, entry);
            let json = serde_json::to_string(entry).expect("json");
            let back: StoredRecoveryCode = serde_json::from_str(&json).expect("from json");
            assert_eq!(&back, entry);
        }
        // The restored entries still match the displayed codes.
        let restored: Vec<StoredRecoveryCode> = codes
            .stored
            .iter()
            .map(|entry| {
                let json = serde_json::to_string(entry).expect("json");
                serde_json::from_str(&json).expect("from json")
            })
            .collect();
        assert_eq!(find(codes.display[2].as_str(), &restored), Some(2));
        assert_eq!(find(codes.display[1].as_str(), &restored), None);
    }
}
