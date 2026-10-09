//! Time-based one-time passwords (RFC 6238 over the HOTP of RFC 4226, IAM-06).
//!
//! The defaults are what authenticator apps support: HMAC-SHA1, six digits, a 30 second step.
//! A code is accepted within a small window of steps either side of now (clock drift) and
//! never twice: [`verify`] returns the matched step, the caller stores it as the last used
//! step and passes it back on the next login, which refuses that step and every earlier one.
//!
//! Secrets and the codes derived from them are handed out in [`Zeroizing`] containers.
//! Nothing in this module logs a secret or a code.

use std::fmt::Write as _;

use aws_lc_rs::{constant_time::verify_slices_are_equal, hmac};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::{encoding::base32_encode, error::AuthError, random};

/// Length of a generated secret in bytes: 160 bits, the recommendation of RFC 4226 section 4.
pub const SECRET_LEN: usize = 20;

/// The fewest digits a code may have.
pub const MIN_DIGITS: u32 = 6;

/// The most digits a code may have. A truncated HOTP value has 31 bits, so nine digits is the
/// hard limit of the algorithm; authenticator apps support up to eight.
pub const MAX_DIGITS: u32 = 8;

/// The longest step accepted by [`TotpParams::validate`], in seconds.
pub const MAX_PERIOD: u64 = 3600;

/// The widest drift window accepted by [`TotpParams::validate`], in steps either side of now.
/// This is a guard against a mis-set value (the work of [`verify`] grows with the window), not
/// a recommendation.
pub const MAX_SKEW: u64 = 10;

/// The HMAC hash of a TOTP configuration (RFC 6238 section 1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TotpAlgorithm {
    /// HMAC-SHA1, the algorithm every authenticator app supports.
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl TotpAlgorithm {
    /// The name in the `algorithm` parameter of an `otpauth://` URI.
    pub const fn uri_name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    fn hmac_algorithm(self) -> hmac::Algorithm {
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha512 => hmac::HMAC_SHA512,
        }
    }
}

/// The parameters of a TOTP enrolment.
///
/// The secret is not part of the parameters. Stored parameters can be checked with
/// [`TotpParams::validate`]; [`verify`] refuses parameters that fail the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TotpParams {
    /// The HMAC hash.
    pub algorithm: TotpAlgorithm,
    /// The number of digits of a code, 6 to 8.
    pub digits: u32,
    /// The length of a time step in seconds.
    pub period: u64,
    /// How many steps either side of the current one [`verify`] accepts.
    pub skew: u64,
}

impl Default for TotpParams {
    /// HMAC-SHA1, six digits, a 30 second step and one step of drift either side: what
    /// authenticator apps support.
    fn default() -> Self {
        Self {
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            skew: 1,
        }
    }
}

impl TotpParams {
    /// Checks the bounds: 6 to 8 digits, a period of 1 to [`MAX_PERIOD`] seconds and a skew
    /// of at most [`MAX_SKEW`] steps.
    ///
    /// # Errors
    ///
    /// [`AuthError::Invalid`] naming the field that is out of range.
    pub fn validate(&self) -> Result<(), AuthError> {
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&self.digits) {
            return Err(AuthError::invalid("digits", "must be between 6 and 8"));
        }
        if !(1..=MAX_PERIOD).contains(&self.period) {
            return Err(AuthError::invalid(
                "period",
                "must be between 1 and 3600 seconds",
            ));
        }
        if self.skew > MAX_SKEW {
            return Err(AuthError::invalid("skew", "must be at most 10 steps"));
        }
        Ok(())
    }
}

/// A new random secret of [`SECRET_LEN`] bytes.
///
/// # Errors
///
/// [`AuthError::Internal`] if the system random source fails.
pub fn generate_secret() -> Result<Zeroizing<Vec<u8>>, AuthError> {
    let mut secret = Zeroizing::new(vec![0_u8; SECRET_LEN]);
    random::fill(&mut secret)?;
    Ok(secret)
}

/// The time step that contains `unix_seconds`. A period of zero is treated as one second, so
/// the function is total.
pub fn step_at(params: &TotpParams, unix_seconds: u64) -> u64 {
    unix_seconds / params.period.max(1)
}

/// The HOTP value of RFC 4226 for `counter`, zero-padded to `digits` (clamped to 6 to 8).
///
/// [`code_at`] is this function with the counter set to the time step.
pub fn hotp(
    secret: &[u8],
    algorithm: TotpAlgorithm,
    digits: u32,
    counter: u64,
) -> Zeroizing<String> {
    let digits = digits.clamp(MIN_DIGITS, MAX_DIGITS);
    let key = hmac::Key::new(algorithm.hmac_algorithm(), secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let bytes = tag.as_ref();
    // Dynamic truncation (RFC 4226 section 5.3): four bytes at an offset taken from the low
    // nibble of the last byte, top bit cleared. Every supported hash is at least 20 bytes
    // long, so the window is always inside the tag.
    let offset = usize::from(bytes.last().copied().unwrap_or(0) & 0x0f);
    let mut word = [0_u8; 4];
    if let Some(window) = bytes.get(offset..offset + 4) {
        word.copy_from_slice(window);
    }
    let value = (u32::from_be_bytes(word) & 0x7fff_ffff) % 10_u32.pow(digits);
    let width = usize::try_from(digits).unwrap_or(8);
    Zeroizing::new(format!("{value:0width$}"))
}

/// The code of the step that contains `unix_seconds`, zero-padded to `params.digits`.
pub fn code_at(secret: &[u8], params: &TotpParams, unix_seconds: u64) -> Zeroizing<String> {
    hotp(
        secret,
        params.algorithm,
        params.digits,
        step_at(params, unix_seconds),
    )
}

/// Checks a code typed by the user.
///
/// The code is accepted when it equals the code of any step within `params.skew` steps of
/// `unix_seconds`, except a step at or before `last_used_step` (replay protection). Returns
/// the matched step, which the caller stores as the new last used step; when the code
/// matches several eligible steps (a collision of the truncated values) the latest wins.
///
/// Spaces (any whitespace) in the input are ignored; a code with non-digits or a length other
/// than `params.digits` is refused, as are parameters that fail [`TotpParams::validate`].
/// Every candidate step is computed and compared in constant time, with no early exit on a
/// match.
pub fn verify(
    secret: &[u8],
    params: &TotpParams,
    code: &str,
    unix_seconds: u64,
    last_used_step: Option<u64>,
) -> Option<u64> {
    params.validate().ok()?;
    let presented: Zeroizing<String> =
        Zeroizing::new(code.chars().filter(|c| !c.is_whitespace()).collect());
    if presented.len() != usize::try_from(params.digits).ok()?
        || !presented.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let now = step_at(params, unix_seconds);
    let first = now.saturating_sub(params.skew);
    let last = now.saturating_add(params.skew);
    let mut matched = None;
    for step in first..=last {
        let candidate = hotp(secret, params.algorithm, params.digits, step);
        let equal = verify_slices_are_equal(candidate.as_bytes(), presented.as_bytes()).is_ok();
        if equal && last_used_step.is_none_or(|used| step > used) {
            matched = Some(step);
        }
    }
    matched
}

/// The `otpauth://totp/` URI for the enrolment QR code or manual entry:
/// `otpauth://totp/{issuer}:{account}?secret={BASE32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30`.
///
/// Issuer and account are percent-encoded (RFC 3986: letters, digits and `-._~` stay, every
/// other byte of the UTF-8 text becomes `%XX`), so a colon inside either cannot be mistaken
/// for the separator. An empty issuer leaves out both the label prefix and the parameter.
/// The URI contains the secret and is returned in a [`Zeroizing`] string.
pub fn otpauth_uri(
    secret: &[u8],
    params: &TotpParams,
    issuer: &str,
    account: &str,
) -> Zeroizing<String> {
    let encoded_secret = Zeroizing::new(base32_encode(secret));
    let issuer = percent_encode(issuer);
    let account = percent_encode(account);
    let mut uri = Zeroizing::new(String::from("otpauth://totp/"));
    if !issuer.is_empty() {
        uri.push_str(&issuer);
        uri.push(':');
    }
    uri.push_str(&account);
    uri.push_str("?secret=");
    uri.push_str(&encoded_secret);
    if !issuer.is_empty() {
        uri.push_str("&issuer=");
        uri.push_str(&issuer);
    }
    let _ = write!(
        uri,
        "&algorithm={}&digits={}&period={}",
        params.algorithm.uri_name(),
        params.digits.clamp(MIN_DIGITS, MAX_DIGITS),
        params.period.max(1),
    );
    uri
}

/// RFC 3986 percent-encoding: unreserved characters stay, every other byte of the UTF-8 text
/// becomes `%XX` in uppercase hexadecimal.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An obviously fake secret (the RFC 4226 test secret).
    const SECRET: &[u8] = b"12345678901234567890";
    /// A moment in time with an ordinary step number.
    const NOW: u64 = 1_700_000_000;

    fn params() -> TotpParams {
        TotpParams::default()
    }

    #[test]
    fn defaults_match_authenticator_apps() {
        let defaults = TotpParams::default();
        assert_eq!(defaults.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(defaults.digits, 6);
        assert_eq!(defaults.period, 30);
        assert_eq!(defaults.skew, 1);
        assert!(defaults.validate().is_ok());
    }

    #[test]
    fn validation_bounds() {
        let ok = params();
        for digits in [MIN_DIGITS, 7, MAX_DIGITS] {
            assert!(TotpParams { digits, ..ok }.validate().is_ok());
        }
        for digits in [0, 5, 9, 10] {
            assert!(TotpParams { digits, ..ok }.validate().is_err());
        }
        for (period, valid) in [
            (0, false),
            (1, true),
            (MAX_PERIOD, true),
            (MAX_PERIOD + 1, false),
        ] {
            assert_eq!(TotpParams { period, ..ok }.validate().is_ok(), valid);
        }
        for (skew, valid) in [(0, true), (MAX_SKEW, true), (MAX_SKEW + 1, false)] {
            assert_eq!(TotpParams { skew, ..ok }.validate().is_ok(), valid);
        }
    }

    #[test]
    fn algorithm_serializes_in_snake_case() {
        for (algorithm, name) in [
            (TotpAlgorithm::Sha1, "sha1"),
            (TotpAlgorithm::Sha256, "sha256"),
            (TotpAlgorithm::Sha512, "sha512"),
        ] {
            let json = serde_json::to_string(&algorithm).expect("serialize");
            assert_eq!(json, format!("\"{name}\""));
            let back: TotpAlgorithm = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, algorithm);
        }
    }

    #[test]
    fn params_round_trip_through_json() {
        let original = TotpParams {
            algorithm: TotpAlgorithm::Sha512,
            digits: 8,
            period: 60,
            skew: 2,
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let back: TotpParams = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, original);
    }

    #[test]
    fn steps_follow_the_period() {
        let p = params();
        assert_eq!(step_at(&p, 0), 0);
        assert_eq!(step_at(&p, 29), 0);
        assert_eq!(step_at(&p, 30), 1);
        assert_eq!(step_at(&p, 59), 1);
        assert_eq!(step_at(&p, 60), 2);
        let long = TotpParams { period: 60, ..p };
        assert_eq!(step_at(&long, 119), 1);
        // A period of zero is treated as one second instead of dividing by zero.
        let zero = TotpParams { period: 0, ..p };
        assert_eq!(step_at(&zero, 42), 42);
    }

    #[test]
    fn codes_are_zero_padded_to_the_digit_count() {
        for digits in [6, 7, 8] {
            for counter in 0..64 {
                let code = hotp(SECRET, TotpAlgorithm::Sha1, digits, counter);
                assert_eq!(code.len(), usize::try_from(digits).expect("small"));
                assert!(code.bytes().all(|b| b.is_ascii_digit()));
            }
        }
        // RFC 6238 Appendix B, SHA1 at 1111111109, keeps its leading zero.
        let p = TotpParams {
            digits: 8,
            ..params()
        };
        assert_eq!(&**code_at(SECRET, &p, 1_111_111_109), "07081804");
    }

    #[test]
    fn digits_are_clamped_instead_of_panicking() {
        assert_eq!(hotp(SECRET, TotpAlgorithm::Sha1, 0, 0).len(), 6);
        assert_eq!(hotp(SECRET, TotpAlgorithm::Sha1, 20, 0).len(), 8);
    }

    #[test]
    fn accepts_the_current_step_and_returns_it() {
        let p = params();
        let code = code_at(SECRET, &p, NOW);
        assert_eq!(verify(SECRET, &p, &code, NOW, None), Some(step_at(&p, NOW)));
    }

    #[test]
    fn drift_window_accepts_one_step_either_side_with_skew_one() {
        let p = params();
        let previous = code_at(SECRET, &p, NOW - p.period);
        let next = code_at(SECRET, &p, NOW + p.period);
        assert_eq!(
            verify(SECRET, &p, &previous, NOW, None),
            Some(step_at(&p, NOW) - 1)
        );
        assert_eq!(
            verify(SECRET, &p, &next, NOW, None),
            Some(step_at(&p, NOW) + 1)
        );
        let too_old = code_at(SECRET, &p, NOW - 2 * p.period);
        let too_new = code_at(SECRET, &p, NOW + 2 * p.period);
        assert_eq!(verify(SECRET, &p, &too_old, NOW, None), None);
        assert_eq!(verify(SECRET, &p, &too_new, NOW, None), None);
    }

    #[test]
    fn skew_zero_accepts_only_the_current_step() {
        let p = TotpParams {
            skew: 0,
            ..params()
        };
        let previous = code_at(SECRET, &p, NOW - p.period);
        let next = code_at(SECRET, &p, NOW + p.period);
        assert_eq!(verify(SECRET, &p, &previous, NOW, None), None);
        assert_eq!(verify(SECRET, &p, &next, NOW, None), None);
        let current = code_at(SECRET, &p, NOW);
        assert!(verify(SECRET, &p, &current, NOW, None).is_some());
    }

    #[test]
    fn a_wider_skew_widens_the_window() {
        let p = TotpParams {
            skew: 2,
            ..params()
        };
        let two_back = code_at(SECRET, &p, NOW - 2 * p.period);
        assert!(verify(SECRET, &p, &two_back, NOW, None).is_some());
        let three_back = code_at(SECRET, &p, NOW - 3 * p.period);
        assert_eq!(verify(SECRET, &p, &three_back, NOW, None), None);
    }

    #[test]
    fn replay_of_the_same_step_is_refused() {
        let p = params();
        let code = code_at(SECRET, &p, NOW);
        let step = verify(SECRET, &p, &code, NOW, None).expect("first use");
        assert_eq!(verify(SECRET, &p, &code, NOW, Some(step)), None);
        // Still refused a few seconds later, while the step is inside the window.
        assert_eq!(verify(SECRET, &p, &code, NOW + 31, Some(step)), None);
    }

    #[test]
    fn earlier_steps_are_refused_after_a_later_one_was_used() {
        let p = params();
        let next = code_at(SECRET, &p, NOW + p.period);
        let step = verify(SECRET, &p, &next, NOW, None).expect("next step");
        let current = code_at(SECRET, &p, NOW);
        let previous = code_at(SECRET, &p, NOW - p.period);
        assert_eq!(verify(SECRET, &p, &current, NOW, Some(step)), None);
        assert_eq!(verify(SECRET, &p, &previous, NOW, Some(step)), None);
    }

    #[test]
    fn a_step_after_the_last_used_one_is_accepted() {
        let p = params();
        let current_step = step_at(&p, NOW);
        let code = code_at(SECRET, &p, NOW);
        assert_eq!(
            verify(SECRET, &p, &code, NOW, Some(current_step - 1)),
            Some(current_step)
        );
        // A last used step far in the past does not matter.
        assert_eq!(verify(SECRET, &p, &code, NOW, Some(0)), Some(current_step));
    }

    #[test]
    fn spaces_in_the_input_are_ignored() {
        let p = params();
        let code = code_at(SECRET, &p, NOW);
        let spaced = format!(" {} {} ", &code[..3], &code[3..]);
        assert_eq!(spaced.len(), 9);
        assert_eq!(
            verify(SECRET, &p, &spaced, NOW, None),
            Some(step_at(&p, NOW))
        );
        let tabbed = format!("{}\t{}", &code[..3], &code[3..]);
        assert!(verify(SECRET, &p, &tabbed, NOW, None).is_some());
    }

    #[test]
    fn wrong_length_and_non_digits_are_refused() {
        let p = params();
        let code = code_at(SECRET, &p, NOW);
        assert_eq!(verify(SECRET, &p, "", NOW, None), None);
        assert_eq!(verify(SECRET, &p, "   ", NOW, None), None);
        assert_eq!(verify(SECRET, &p, &code[..5], NOW, None), None);
        let too_long = format!("{}0", code.as_str());
        assert_eq!(verify(SECRET, &p, &too_long, NOW, None), None);
        let letter = format!("{}a", &code[..5]);
        assert_eq!(verify(SECRET, &p, &letter, NOW, None), None);
        for bad in ["abcdef", "12-456", "+12345", "12345e", "0x1234"] {
            assert_eq!(verify(SECRET, &p, bad, NOW, None), None, "{bad}");
        }
        // Six characters, but Arabic-Indic digits are not ASCII digits.
        let indic = "\u{661}\u{662}\u{663}\u{664}\u{665}\u{666}";
        assert_eq!(verify(SECRET, &p, indic, NOW, None), None);
    }

    #[test]
    fn a_wrong_code_is_refused() {
        let p = params();
        let code = code_at(SECRET, &p, NOW);
        let mut digits: Vec<u8> = code.bytes().collect();
        digits[0] = if digits[0] == b'0' { b'1' } else { b'0' };
        let wrong = String::from_utf8(digits).expect("ascii");
        assert_eq!(verify(SECRET, &p, &wrong, NOW, None), None);
        let other_secret = b"abcdefghijklmnopqrst";
        assert_eq!(verify(other_secret, &p, &code, NOW, None), None);
    }

    #[test]
    fn invalid_parameters_fail_closed() {
        let wide = TotpParams {
            skew: u64::MAX,
            ..params()
        };
        let code = code_at(SECRET, &wide, NOW);
        assert_eq!(verify(SECRET, &wide, &code, NOW, None), None);
        let long = TotpParams {
            digits: 10,
            ..params()
        };
        let code = code_at(SECRET, &long, NOW);
        assert_eq!(verify(SECRET, &long, &code, NOW, None), None);
    }

    #[test]
    fn verification_at_the_ends_of_the_time_range_does_not_overflow() {
        let p = TotpParams {
            skew: 3,
            ..params()
        };
        let code = code_at(SECRET, &p, 0);
        assert_eq!(verify(SECRET, &p, &code, 0, None), Some(0));
        let late = u64::MAX;
        let code = code_at(SECRET, &p, late);
        assert_eq!(
            verify(SECRET, &p, &code, late, None),
            Some(step_at(&p, late))
        );
    }

    #[test]
    fn every_algorithm_and_digit_count_verifies() {
        for algorithm in [
            TotpAlgorithm::Sha1,
            TotpAlgorithm::Sha256,
            TotpAlgorithm::Sha512,
        ] {
            for digits in [6, 7, 8] {
                let p = TotpParams {
                    algorithm,
                    digits,
                    ..params()
                };
                let code = code_at(SECRET, &p, NOW);
                assert_eq!(
                    verify(SECRET, &p, &code, NOW, None),
                    Some(step_at(&p, NOW)),
                    "{algorithm:?} {digits}"
                );
            }
        }
    }

    #[test]
    fn generated_secrets_have_the_recommended_length_and_differ() {
        let a = generate_secret().expect("secret");
        let b = generate_secret().expect("secret");
        assert_eq!(SECRET_LEN, 20);
        assert_eq!(a.len(), SECRET_LEN);
        assert_eq!(b.len(), SECRET_LEN);
        assert_ne!(*a, *b);
        assert!(a.iter().any(|&byte| byte != 0));
    }

    #[test]
    fn otpauth_uri_has_the_documented_shape() {
        let uri = otpauth_uri(SECRET, &params(), "Tenko DDI", "admin@tenko.example.test");
        assert_eq!(
            &**uri,
            "otpauth://totp/Tenko%20DDI:admin%40tenko.example.test\
             ?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
             &issuer=Tenko%20DDI&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn otpauth_uri_reflects_the_parameters() {
        let p = TotpParams {
            algorithm: TotpAlgorithm::Sha512,
            digits: 8,
            period: 60,
            skew: 1,
        };
        let uri = otpauth_uri(SECRET, &p, "Tenko", "root");
        assert!(
            uri.ends_with("&algorithm=SHA512&digits=8&period=60"),
            "{}",
            &**uri
        );
        assert!(uri.starts_with("otpauth://totp/Tenko:root?secret="));
        let secret_part = uri
            .split("secret=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .expect("secret parameter");
        assert_eq!(
            crate::encoding::base32_decode(secret_part).expect("base32"),
            SECRET
        );
    }

    #[test]
    fn otpauth_uri_protects_the_label_separators() {
        let uri = otpauth_uri(SECRET, &params(), "A:B/C?D#E&F", "x y+z=w");
        assert!(
            uri.starts_with("otpauth://totp/A%3AB%2FC%3FD%23E%26F:x%20y%2Bz%3Dw?secret="),
            "{}",
            &**uri
        );
        assert!(uri.contains("&issuer=A%3AB%2FC%3FD%23E%26F&"));
    }

    #[test]
    fn otpauth_uri_without_an_issuer_has_no_prefix() {
        let uri = otpauth_uri(SECRET, &params(), "", "admin");
        assert!(
            uri.starts_with("otpauth://totp/admin?secret="),
            "{}",
            &**uri
        );
        assert!(!uri.contains("issuer"));
    }

    #[test]
    fn percent_encoding_follows_rfc_3986() {
        assert_eq!(percent_encode(""), "");
        assert_eq!(percent_encode("AZaz09-._~"), "AZaz09-._~");
        assert_eq!(percent_encode("Tenko DDI"), "Tenko%20DDI");
        assert_eq!(percent_encode("a@b"), "a%40b");
        assert_eq!(percent_encode("%"), "%25");
        // UTF-8 bytes, uppercase hexadecimal.
        assert_eq!(percent_encode("\u{e9}"), "%C3%A9");
        assert_eq!(percent_encode("\u{20ac}"), "%E2%82%AC");
        assert_eq!(percent_encode("\u{1f510}"), "%F0%9F%94%90");
    }
}
