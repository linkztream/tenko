//! Password policy presets (IAM-03, TGL-01) with NIST SP 800-63B semantics.
//!
//! A policy checks length, a few trivial patterns and context-specific words. It has no
//! composition rules ("needs an uppercase letter"); only the Custom preset takes a pattern
//! the operator chose. Every check runs on the NFKC-normalized password, the same form
//! that is hashed, and lengths count Unicode scalar values. The breached-password check
//! is not part of this module (IAM-04).

use std::collections::BTreeMap;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::error::AuthError;

/// Words of the product itself. A password that contains one is rejected as
/// context-specific (NIST SP 800-63B, section 3.1.1.2).
pub const PRODUCT_WORDS: &[&str] = &["tenko"];

/// The maximum password length of the Standard and Hardened presets, and the default
/// maximum of the Custom preset, in Unicode characters.
pub const DEFAULT_MAX_LENGTH: usize = 256;

const PIN_MIN_LENGTH: usize = 4;
const PIN_MAX_LENGTH: usize = 64;
const STANDARD_MIN_LENGTH: usize = 12;
const HARDENED_MIN_LENGTH: usize = 16;

/// Bounds of the Custom preset. NIST SP 800-63B asks verifiers to allow at least 64
/// characters.
const CUSTOM_MIN_LENGTH_FLOOR: usize = 4;
const CUSTOM_MAX_LENGTH_FLOOR: usize = 64;
const CUSTOM_MAX_LENGTH_CEILING: usize = 1024;
/// Compiled size limit of a Custom pattern, in bytes.
const PATTERN_SIZE_LIMIT: usize = 1 << 20;

/// Shortest user name, host name and host label that count as context.
const MIN_SHORT_CONTEXT_CHARS: usize = 3;
/// Shortest display name and display name part that count as context.
const MIN_DISPLAY_CONTEXT_CHARS: usize = 4;
/// Longest unit of a repeated pattern such as `abcabc`.
const MAX_REPEATED_UNIT: usize = 3;

/// Which context-specific word a password contained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    /// The user name.
    UserName,
    /// The display name.
    DisplayName,
    /// The installation's host name.
    HostName,
    /// The product name.
    Product,
}

impl ContextKind {
    /// The stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserName => "user_name",
            Self::DisplayName => "display_name",
            Self::HostName => "host_name",
            Self::Product => "product",
        }
    }
}

/// One way a password breaks the policy. Each has a stable code under `auth.password.`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyViolation {
    /// Shorter than the preset's minimum (in Unicode characters after normalization).
    TooShort {
        /// The minimum length.
        min: usize,
    },
    /// Longer than the preset's maximum.
    TooLong {
        /// The maximum length.
        max: usize,
    },
    /// The PIN preset takes digits only.
    PinDigitsOnly,
    /// A repeated or sequential pattern such as `0000`, `1234` or `aaaaaaaaaaaa`.
    Trivial,
    /// Contains a context-specific word (NIST SP 800-63B, section 3.1.1.2).
    ContextSpecific {
        /// Which word.
        context: ContextKind,
    },
    /// Does not match the pattern of the Custom preset.
    PatternMismatch,
    /// Appears in a breach corpus (IAM-04).
    Breached {
        /// How often it appears, when the source reports it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        count: Option<u64>,
    },
    /// Contains control characters.
    InvalidCharacters,
}

impl PolicyViolation {
    /// The stable code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooShort { .. } => "auth.password.too_short",
            Self::TooLong { .. } => "auth.password.too_long",
            Self::PinDigitsOnly => "auth.password.pin_digits_only",
            Self::Trivial => "auth.password.trivial",
            Self::ContextSpecific { .. } => "auth.password.context_specific",
            Self::PatternMismatch => "auth.password.pattern_mismatch",
            Self::Breached { .. } => "auth.password.breached",
            Self::InvalidCharacters => "auth.password.invalid_characters",
        }
    }

    /// Named parameters for the translated message.
    pub fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            Self::TooShort { min } => BTreeMap::from([("min", min.to_string())]),
            Self::TooLong { max } => BTreeMap::from([("max", max.to_string())]),
            Self::ContextSpecific { context } => {
                BTreeMap::from([("context", context.as_str().to_owned())])
            }
            Self::Breached { count: Some(count) } => BTreeMap::from([("count", count.to_string())]),
            _ => BTreeMap::new(),
        }
    }
}

fn default_max_length() -> usize {
    DEFAULT_MAX_LENGTH
}

/// The password policy of a security profile (TGL-01).
///
/// The presets differ in length only. There are no composition rules (NIST SP 800-63B,
/// section 3.1.1.2); the Custom preset adds an operator-chosen pattern. Serialized as an
/// object tagged by `preset`: `{"preset": "standard"}`, or for Custom
/// `{"preset": "custom", "min_length": 10, "max_length": 128, "pattern": "..."}`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(tag = "preset", rename_all = "snake_case")]
pub enum PasswordPolicy {
    /// Digits only, 4 to 64 of them. Allowed only while the vault holds no operator
    /// secrets (IAM-07).
    Pin,
    /// At least 12 characters.
    #[default]
    Standard,
    /// At least 16 characters.
    Hardened,
    /// Operator-chosen limits and an optional pattern.
    Custom(CustomPolicy),
}

/// The limits and the pattern of the Custom preset.
///
/// [`PasswordPolicy::validate`] checks the bounds when the setting is saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CustomPolicy {
    /// The minimum length in Unicode characters after normalization: 4 or more, and not
    /// more than `max_length`.
    pub min_length: usize,
    /// The maximum length in Unicode characters after normalization: from 64 to 1024.
    /// Defaults to 256.
    #[serde(default = "default_max_length")]
    pub max_length: usize,
    /// A regular expression (Rust `regex` syntax) that the whole normalized password must
    /// match (it is anchored at both ends for you). Perl classes such as `\d` and `\w` and
    /// Unicode property classes such as `\p{L}` work. Without a pattern, only the length
    /// limits apply.
    #[serde(default)]
    pub pattern: Option<String>,
}

/// What a password must not contain besides the policy's own rules: words that an attacker
/// guesses first (NIST SP 800-63B, section 3.1.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordContext<'a> {
    /// The user name of the account.
    pub user_name: &'a str,
    /// The display name of the account, if it has one.
    pub display_name: Option<&'a str>,
    /// The host name of this installation, if it is known.
    pub host_name: Option<&'a str>,
}

impl PasswordPolicy {
    /// The minimum length in Unicode characters after normalization.
    pub const fn min_length(&self) -> usize {
        match self {
            Self::Pin => PIN_MIN_LENGTH,
            Self::Standard => STANDARD_MIN_LENGTH,
            Self::Hardened => HARDENED_MIN_LENGTH,
            Self::Custom(custom) => custom.min_length,
        }
    }

    /// The maximum length in Unicode characters after normalization.
    pub const fn max_length(&self) -> usize {
        match self {
            Self::Pin => PIN_MAX_LENGTH,
            Self::Standard | Self::Hardened => DEFAULT_MAX_LENGTH,
            Self::Custom(custom) => custom.max_length,
        }
    }

    /// Whether this is the PIN preset.
    pub const fn is_pin(&self) -> bool {
        matches!(self, Self::Pin)
    }

    /// Checks the policy itself. Only the Custom preset can be invalid: its minimum is at
    /// least 4 and at most the maximum, its maximum is from 64 to 1024 (NIST SP 800-63B
    /// asks verifiers to accept at least 64 characters), and its pattern, if any, is a
    /// valid regular expression of bounded size.
    ///
    /// # Errors
    ///
    /// [`AuthError::Invalid`] for the field `password_policy`, with the broken rule as the
    /// reason.
    pub fn validate(&self) -> Result<(), AuthError> {
        let Self::Custom(custom) = self else {
            return Ok(());
        };
        let invalid = |reason: String| AuthError::invalid("password_policy", reason);
        if custom.min_length < CUSTOM_MIN_LENGTH_FLOOR {
            return Err(invalid(format!(
                "min_length must be at least {CUSTOM_MIN_LENGTH_FLOOR}"
            )));
        }
        if custom.max_length < CUSTOM_MAX_LENGTH_FLOOR {
            return Err(invalid(format!(
                "max_length must be at least {CUSTOM_MAX_LENGTH_FLOOR}"
            )));
        }
        if custom.max_length > CUSTOM_MAX_LENGTH_CEILING {
            return Err(invalid(format!(
                "max_length must not exceed {CUSTOM_MAX_LENGTH_CEILING}"
            )));
        }
        if custom.min_length > custom.max_length {
            return Err(invalid("min_length must not exceed max_length".to_owned()));
        }
        if let Some(pattern) = &custom.pattern {
            compile_pattern(pattern).map_err(|reason| invalid(reason.to_owned()))?;
        }
        Ok(())
    }

    /// Checks a password against the policy and returns every violation, not only the
    /// first. The password is normalized first (see [`normalize`]). The order is:
    /// [`InvalidCharacters`](PolicyViolation::InvalidCharacters),
    /// [`PinDigitsOnly`](PolicyViolation::PinDigitsOnly),
    /// [`TooShort`](PolicyViolation::TooShort), [`TooLong`](PolicyViolation::TooLong),
    /// [`Trivial`](PolicyViolation::Trivial), one
    /// [`ContextSpecific`](PolicyViolation::ContextSpecific) per matching word (user name,
    /// display name, host name, product) and
    /// [`PatternMismatch`](PolicyViolation::PatternMismatch).
    ///
    /// An empty result means the password meets the policy. A Custom pattern that does not
    /// compile (see [`validate`](Self::validate)) matches nothing, so the check fails
    /// closed. The breached-password check is separate (IAM-04).
    pub fn check(&self, password: &str, context: &PasswordContext<'_>) -> Vec<PolicyViolation> {
        let normalized = normalize(password);
        let text = normalized.as_str();
        let mut violations = Vec::new();

        if text.chars().any(char::is_control) {
            violations.push(PolicyViolation::InvalidCharacters);
        }
        if self.is_pin() && !text.chars().all(|c| c.is_ascii_digit()) {
            violations.push(PolicyViolation::PinDigitsOnly);
        }
        let length = text.chars().count();
        if length < self.min_length() {
            violations.push(PolicyViolation::TooShort {
                min: self.min_length(),
            });
        }
        if length > self.max_length() {
            violations.push(PolicyViolation::TooLong {
                max: self.max_length(),
            });
        }
        let folded = fold(text);
        if is_trivial(&folded) {
            violations.push(PolicyViolation::Trivial);
        }
        violations.extend(context_violations(&folded, context));
        if let Self::Custom(CustomPolicy {
            pattern: Some(pattern),
            ..
        }) = self
            && !matches_pattern(pattern, text)
        {
            violations.push(PolicyViolation::PatternMismatch);
        }
        violations
    }
}

/// Normalizes a password to Unicode NFKC (NIST SP 800-63B, section 3.1.1.2). Policy checks
/// and hashing both use this form, so the same characters typed with another keyboard or
/// stored in another composition still produce the same password. The result is wiped
/// when dropped.
pub fn normalize(password: &str) -> Zeroizing<String> {
    let mut normalized = Zeroizing::new(String::with_capacity(password.len()));
    if password.is_ascii() {
        // ASCII is unchanged by NFKC.
        normalized.push_str(password);
    } else {
        normalized.extend(password.nfkc());
    }
    normalized
}

/// Lowercases per character, for case-insensitive comparison. Applied to both sides of
/// every comparison, so it needs no more than to be consistent.
fn fold(text: &str) -> Zeroizing<String> {
    let mut folded = Zeroizing::new(String::with_capacity(text.len()));
    folded.extend(text.chars().flat_map(char::to_lowercase));
    folded
}

/// Whether a case-folded password is a trivial pattern: one unit of one to three
/// characters repeated (`0000`, `1212`, `abcabcabcabc`), or a run that goes up (`1234`,
/// `abcdefghijklmnop`) or down (`4321`) by one code point at every step.
fn is_trivial(folded: &str) -> bool {
    is_repeated_unit(folded) || is_run(folded)
}

fn is_repeated_unit(folded: &str) -> bool {
    let length = folded.chars().count();
    (1..=MAX_REPEATED_UNIT).any(|unit| {
        length >= 2 * unit
            && length.is_multiple_of(unit)
            && folded
                .chars()
                .zip(folded.chars().take(unit).cycle())
                .all(|(actual, expected)| actual == expected)
    })
}

fn is_run(folded: &str) -> bool {
    let mut points = folded.chars().map(u32::from);
    let Some(mut previous) = points.next() else {
        return false;
    };
    let (mut ascending, mut descending, mut steps) = (true, true, 0_usize);
    for point in points {
        ascending &= point == previous + 1;
        descending &= previous == point + 1;
        previous = point;
        steps += 1;
        if !ascending && !descending {
            return false;
        }
    }
    steps > 0
}

fn context_violations(folded: &str, context: &PasswordContext<'_>) -> Vec<PolicyViolation> {
    [
        ContextKind::UserName,
        ContextKind::DisplayName,
        ContextKind::HostName,
        ContextKind::Product,
    ]
    .into_iter()
    .filter(|&kind| {
        context_needles(kind, context)
            .iter()
            .any(|needle| folded.contains(needle.as_str()))
    })
    .map(|context| PolicyViolation::ContextSpecific { context })
    .collect()
}

/// The folded words of one context kind that a password must not contain.
fn context_needles(kind: ContextKind, context: &PasswordContext<'_>) -> Vec<String> {
    let mut needles = Vec::new();
    match kind {
        ContextKind::UserName => {
            needles.extend(needle(context.user_name, MIN_SHORT_CONTEXT_CHARS));
        }
        ContextKind::DisplayName => {
            if let Some(name) = context.display_name {
                needles.extend(needle(name, MIN_DISPLAY_CONTEXT_CHARS));
                needles.extend(
                    name.split_whitespace()
                        .filter_map(|part| needle(part, MIN_DISPLAY_CONTEXT_CHARS)),
                );
            }
        }
        ContextKind::HostName => {
            if let Some(host) = context.host_name {
                let host = host.trim().trim_end_matches('.');
                needles.extend(needle(host, MIN_SHORT_CONTEXT_CHARS));
                if let Some(label) = host.split('.').next() {
                    needles.extend(needle(label, MIN_SHORT_CONTEXT_CHARS));
                }
            }
        }
        ContextKind::Product => {
            needles.extend(PRODUCT_WORDS.iter().filter_map(|word| needle(word, 1)));
        }
    }
    needles
}

/// A normalized, folded context word, or `None` if it is shorter than `min_chars`.
fn needle(raw: &str, min_chars: usize) -> Option<String> {
    let folded = fold(&normalize(raw.trim()));
    (folded.chars().count() >= min_chars).then(|| folded.as_str().to_owned())
}

/// Compiles a Custom pattern so that it must match the whole password. The pattern is
/// compiled on its own first: wrapping alone would let an unbalanced group such as `a)(b`
/// through.
fn compile_pattern(pattern: &str) -> Result<Regex, &'static str> {
    if pattern.is_empty() {
        return Err("pattern must not be empty");
    }
    let build = |source: &str| {
        RegexBuilder::new(source)
            .size_limit(PATTERN_SIZE_LIMIT)
            .build()
            .map_err(|error| match error {
                regex::Error::CompiledTooBig(_) => "pattern is too complex",
                _ => "pattern is not a valid regular expression",
            })
    };
    build(pattern)?;
    build(&format!(r"\A(?:{pattern})\z"))
}

fn matches_pattern(pattern: &str, text: &str) -> bool {
    compile_pattern(pattern).is_ok_and(|regex| regex.is_match(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom(min_length: usize, max_length: usize, pattern: Option<&str>) -> PasswordPolicy {
        PasswordPolicy::Custom(CustomPolicy {
            min_length,
            max_length,
            pattern: pattern.map(str::to_owned),
        })
    }

    const NO_CONTEXT: PasswordContext<'static> = PasswordContext {
        user_name: "",
        display_name: None,
        host_name: None,
    };

    fn invalid(reason: &'static str) -> AuthError {
        AuthError::invalid("password_policy", reason)
    }

    #[test]
    fn presets_have_their_lengths() {
        let limits = |policy: &PasswordPolicy| (policy.min_length(), policy.max_length());
        assert_eq!(limits(&PasswordPolicy::Pin), (4, 64));
        assert_eq!(limits(&PasswordPolicy::Standard), (12, 256));
        assert_eq!(limits(&PasswordPolicy::Hardened), (16, 256));
        assert_eq!(limits(&custom(9, 99, None)), (9, 99));
        assert_eq!(DEFAULT_MAX_LENGTH, 256);
        assert!(PasswordPolicy::Pin.is_pin());
        assert!(!PasswordPolicy::Standard.is_pin());
        assert!(!custom(9, 99, None).is_pin());
    }

    #[test]
    fn standard_is_the_default() {
        assert_eq!(PasswordPolicy::default(), PasswordPolicy::Standard);
    }

    #[test]
    fn serializes_tagged_by_preset() {
        for (policy, json) in [
            (PasswordPolicy::Pin, r#"{"preset":"pin"}"#),
            (PasswordPolicy::Standard, r#"{"preset":"standard"}"#),
            (PasswordPolicy::Hardened, r#"{"preset":"hardened"}"#),
            (
                custom(10, 128, Some("[a-z]+")),
                r#"{"preset":"custom","min_length":10,"max_length":128,"pattern":"[a-z]+"}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&policy).expect("serialize"), json);
            let back: PasswordPolicy = serde_json::from_str(json).expect("deserialize");
            assert_eq!(back, policy);
        }
    }

    #[test]
    fn custom_defaults_the_maximum_and_the_pattern() {
        let policy: PasswordPolicy =
            serde_json::from_str(r#"{"preset":"custom","min_length":10}"#).expect("deserialize");
        assert_eq!(policy, custom(10, DEFAULT_MAX_LENGTH, None));
    }

    #[test]
    fn unknown_presets_are_refused() {
        assert!(serde_json::from_str::<PasswordPolicy>(r#"{"preset":"lax"}"#).is_err());
        assert!(serde_json::from_str::<PasswordPolicy>(r#"{"min_length":10}"#).is_err());
        assert!(serde_json::from_str::<PasswordPolicy>(r#"{"preset":"custom"}"#).is_err());
    }

    #[test]
    fn validate_accepts_the_presets_and_sane_custom_values() {
        for policy in [
            PasswordPolicy::Pin,
            PasswordPolicy::Standard,
            PasswordPolicy::Hardened,
            custom(4, 64, None),
            custom(64, 64, None),
            custom(8, 1024, Some("[[:alpha:]]+[0-9]+")),
        ] {
            assert_eq!(policy.validate(), Ok(()), "{policy:?}");
        }
    }

    #[test]
    fn validate_refuses_bad_bounds() {
        assert_eq!(
            custom(3, 64, None).validate(),
            Err(invalid("min_length must be at least 4"))
        );
        assert_eq!(
            custom(4, 63, None).validate(),
            Err(invalid("max_length must be at least 64"))
        );
        assert_eq!(
            custom(4, 1025, None).validate(),
            Err(invalid("max_length must not exceed 1024"))
        );
        assert_eq!(
            custom(65, 64, None).validate(),
            Err(invalid("min_length must not exceed max_length"))
        );
    }

    #[test]
    fn validate_refuses_bad_patterns() {
        let not_valid = invalid("pattern is not a valid regular expression");
        for pattern in ["(", "[a-", "a)(b", "*", r"\p{NoSuchClass}+"] {
            assert_eq!(
                custom(8, 64, Some(pattern)).validate(),
                Err(not_valid.clone()),
                "{pattern}"
            );
        }
        assert_eq!(
            custom(8, 64, Some("")).validate(),
            Err(invalid("pattern must not be empty"))
        );
        assert_eq!(
            custom(8, 64, Some(r"((a{1000}){1000}){1000}")).validate(),
            Err(invalid("pattern is too complex"))
        );
    }

    #[test]
    fn unicode_classes_work_in_every_build() {
        let letters = custom(8, 64, Some(r"\p{L}+"));
        assert_eq!(letters.validate(), Ok(()));
        let context = PasswordContext {
            user_name: "someone",
            display_name: None,
            host_name: None,
        };
        assert_eq!(letters.check("crèmebrûlée", &context), Vec::new());
        assert_eq!(
            letters.check("letters and spaces", &context),
            vec![PolicyViolation::PatternMismatch]
        );
    }

    #[test]
    fn normalization_is_nfkc() {
        assert_eq!(normalize("plain ASCII 123").as_str(), "plain ASCII 123");
        assert_eq!(normalize("\u{ff11}\u{ff12}\u{ff13}").as_str(), "123");
        assert_eq!(normalize("e\u{301}").as_str(), "\u{e9}");
        assert_eq!(normalize("\u{fb01}sh").as_str(), "fish");
        assert_eq!(normalize("").as_str(), "");
    }

    #[test]
    fn repeated_units_are_trivial() {
        for trivial in [
            "aa",
            "0000",
            "1212",
            "abab",
            "abcabc",
            "abcabcabcabc",
            "\u{e9}\u{e9}\u{e9}",
            "ab ab ",
            "xyzxyz",
        ] {
            assert!(is_repeated_unit(trivial), "{trivial}");
        }
        for fine in [
            "", "a", "ab", "abc", "abba", "abcd", "abcabd", "abcdabcd", "aabb", "aba", "abcab",
        ] {
            assert!(!is_repeated_unit(fine), "{fine}");
        }
    }

    #[test]
    fn runs_are_trivial_in_both_directions() {
        for trivial in ["12", "1234", "4321", "abcdefghijklmnop", "ponmlk", "xyz{|}"] {
            assert!(is_run(trivial), "{trivial}");
        }
        for fine in [
            "", "1", "a", "1235", "1243", "13", "1232", "abcdcba", "a1b2c3",
        ] {
            assert!(!is_run(fine), "{fine}");
        }
    }

    #[test]
    fn triviality_ignores_case() {
        assert!(is_trivial(&fold("AbCdEfGh")));
        assert!(is_trivial(&fold("QqQqQq")));
        assert!(is_trivial(&fold("ABCabcABCabc")));
        assert!(!is_trivial(&fold("Correct Horse")));
    }

    #[test]
    fn context_words_need_a_minimum_length() {
        assert_eq!(needle("ab", 3), None);
        assert_eq!(needle("  Abc ", 3), Some("abc".to_owned()));
        assert_eq!(needle("", 1), None);
        // Counted after normalization: the ligature is two characters.
        assert_eq!(needle("\u{fb01}", 2), Some("fi".to_owned()));
    }

    #[test]
    fn context_needles_follow_the_rules_per_kind() {
        let context = PasswordContext {
            user_name: "Ann",
            display_name: Some("Ann Bo  Carter"),
            host_name: Some("Gate1.Corp.Test."),
        };
        assert_eq!(context_needles(ContextKind::UserName, &context), ["ann"]);
        // Parts below four characters are skipped; the whole name counts.
        assert_eq!(
            context_needles(ContextKind::DisplayName, &context),
            ["ann bo  carter", "carter"]
        );
        assert_eq!(
            context_needles(ContextKind::HostName, &context),
            ["gate1.corp.test", "gate1"]
        );
        assert_eq!(context_needles(ContextKind::Product, &context), ["tenko"]);
        for kind in [
            ContextKind::UserName,
            ContextKind::DisplayName,
            ContextKind::HostName,
        ] {
            assert_eq!(
                context_needles(kind, &NO_CONTEXT),
                Vec::<String>::new(),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn patterns_must_match_the_whole_password() {
        assert!(matches_pattern("[a-z]+[0-9]+", "abc123"));
        assert!(!matches_pattern("[a-z]+[0-9]+", "abc123!"));
        assert!(!matches_pattern("[a-z]+[0-9]+", "!abc123"));
        // An alternation is anchored as a whole, not per branch.
        assert!(!matches_pattern("ab|cd", "abcd"));
        assert!(!matches_pattern("ab|cd", "xcd"));
        assert!(matches_pattern("ab|cd", "cd"));
        // Flags inside the pattern stay inside.
        assert!(matches_pattern("(?i)abc", "ABC"));
        assert!(!matches_pattern("(?i)abc", "ABCD"));
        assert!(!matches_pattern("(?m)abc", "abc\nabc"));
        // A pattern that does not compile matches nothing.
        assert!(!matches_pattern("(", "("));
        assert!(!matches_pattern("a)(b", "ab"));
    }

    #[test]
    fn violations_come_in_the_documented_order() {
        let context = PasswordContext {
            user_name: "kestrel",
            display_name: Some("Kestrel Moon"),
            host_name: Some("ns-gateway.lab.test"),
        };
        // Control character, not a digit, too short.
        assert_eq!(
            PasswordPolicy::Pin.check("ab\n", &context),
            [
                PolicyViolation::InvalidCharacters,
                PolicyViolation::PinDigitsOnly,
                PolicyViolation::TooShort { min: 4 },
            ]
        );
        // Too short, trivial (a run), not matching the pattern.
        assert_eq!(
            custom(8, 64, Some("[0-9]+")).check("ABCDEFG", &NO_CONTEXT),
            [
                PolicyViolation::TooShort { min: 8 },
                PolicyViolation::Trivial,
                PolicyViolation::PatternMismatch,
            ]
        );
        // One entry per kind, in the order user name, display name, host name, product.
        let kinds: Vec<_> = PasswordPolicy::Standard
            .check("tenko-ns-gateway.lab.test-kestrel-moon", &context)
            .into_iter()
            .map(|violation| match violation {
                PolicyViolation::ContextSpecific { context } => context,
                other => panic!("unexpected violation {other:?}"),
            })
            .collect();
        assert_eq!(
            kinds,
            [
                ContextKind::UserName,
                ContextKind::DisplayName,
                ContextKind::HostName,
                ContextKind::Product,
            ]
        );
    }
}
