//! Enrollment tokens: the single-use, time-limited secret a new data-plane node presents to a
//! controller to obtain its certificate (OPS-04, OPS-08).
//!
//! An administrator creates a token on a controller, the controller shows it once, and the
//! controller keeps only a [`TokenDigest`] of it. This module is the token format, its
//! generation, its parsing and its digest. Where digests are stored and when a token expires
//! is decided elsewhere.
//!
//! # Text form
//!
//! ```text
//! tnk2.<id>.<secret>.<fingerprint>
//! tnk1.<id>.<secret>
//! ```
//!
//! * `tnk2` (or `tnk1`) is the prefix; the digit is the format version.
//! * `<id>` is the identifier of the token record as 32 lowercase hexadecimal digits (the
//!   "simple" form of a UUID). It is not secret: a controller uses it to find the record.
//! * `<secret>` is [`SECRET_LEN`] random bytes as unpadded base64url (RFC 4648 section 5,
//!   alphabet `A-Z a-z 0-9 - _`), which is 43 characters.
//! * `<fingerprint>`, in `tnk2` only, is the [`CaFingerprint`] of the controller's CA root:
//!   the SHA-256 of its DER encoding, 32 bytes as unpadded base64url, 43 characters. It is
//!   not secret and takes no part in the digest; it lets the node verify the CA root it
//!   fetches from the controller without a separate fingerprint.
//!
//! A controller renders `tnk2`, [`TOKEN_TEXT_LEN`] characters long. `tnk1` is the format of
//! 0.0.11 and earlier, [`LEGACY_TOKEN_TEXT_LEN`] characters long, and is still read.
//! [`EnrollmentToken::parse`] is strict: exactly the parts of the version, no padding, and only
//! the canonical base64url spelling of a secret or a fingerprint.
//!
//! # Digest
//!
//! The digest is SHA-256 over the domain separator `tenko-enrolment-token-v1\0` (spelling: stored key), the 16 bytes
//! of the id and the 32 bytes of the secret, in that order. The secret is full-entropy random
//! data, so a plain hash is enough and no slow key-derivation function is needed. Binding the
//! id into the digest means a secret cannot be moved to another token record. Digests are
//! compared in constant time.
//!
//! # Secrecy
//!
//! [`EnrollmentToken`] is deliberately not `Clone`, `Display`, `Serialize` or `Deserialize`, and
//! its `Debug` output hides the secret, so a token cannot leak into a log line or a JSON body
//! by accident. Buffers that hold the secret or its text are wiped when they are dropped.

use std::fmt;

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{Context, SHA256};
use aws_lc_rs::rand;
use serde::de::{self, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tenko_core::Coded;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The text a token with a CA fingerprint starts with; the digit is the format version.
pub const TOKEN_PREFIX: &str = "tnk2";

/// The text a token of 0.0.11 and earlier starts with: no CA fingerprint.
pub const LEGACY_TOKEN_PREFIX: &str = "tnk1";

/// The number of random bytes in the secret of a token.
pub const SECRET_LEN: usize = 32;

/// The length of the text form of a `tnk2` token: the prefix, a dot, 32 hexadecimal digits of
/// the id, a dot, 43 characters of secret, a dot and 43 characters of fingerprint
/// (4 + 1 + 32 + 1 + 43 + 1 + 43).
pub const TOKEN_TEXT_LEN: usize = 125;

/// The length of the text form of a `tnk1` token: the prefix, a dot, 32 hexadecimal digits of
/// the id, a dot and 43 characters of secret (4 + 1 + 32 + 1 + 43).
pub const LEGACY_TOKEN_TEXT_LEN: usize = 81;

/// The length of the secret, and of a fingerprint, as unpadded base64url.
const SECRET_TEXT_LEN: usize = 43;

/// The length of the id as hexadecimal digits.
const ID_HEX_LEN: usize = 32;

/// The length of a SHA-256 digest in bytes.
const DIGEST_LEN: usize = 32;

/// The domain separator that starts the hashed input of a digest. Stored digests depend on
/// these bytes, so they keep the spelling of 0.0.11.
const DIGEST_DOMAIN: &[u8] = b"tenko-enrolment-token-v1\0"; // spelling: stored key

/// The base64url alphabet of RFC 4648 section 5.
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The lowercase hexadecimal digits.
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

const _: () = assert!(SECRET_TEXT_LEN == (SECRET_LEN * 4).div_ceil(3));
const _: () = assert!(
    LEGACY_TOKEN_PREFIX.len() + 1 + ID_HEX_LEN + 1 + SECRET_TEXT_LEN == LEGACY_TOKEN_TEXT_LEN
);
const _: () = assert!(LEGACY_TOKEN_TEXT_LEN + 1 + SECRET_TEXT_LEN == TOKEN_TEXT_LEN);
const _: () = assert!(TOKEN_PREFIX.len() == LEGACY_TOKEN_PREFIX.len());

/// Why an enrollment token could not be created or read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// The text is not an enrollment token; the reason is a short English phrase that never
    /// contains part of the text.
    #[error("the enrollment token is malformed: {reason}")]
    Malformed {
        /// What is wrong with the text.
        reason: &'static str,
    },
    /// The system random number generator failed, so no secret could be drawn.
    #[error("the system random number generator failed")]
    Random,
}

impl Coded for TokenError {
    fn code(&self) -> &'static str {
        match self {
            Self::Malformed { .. } => "cluster.enrollment.invalid_token",
            Self::Random => "cluster.enrollment.random",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            Self::Malformed { .. } => 401,
            Self::Random => 500,
        }
    }
}

/// Builds a [`TokenError::Malformed`].
const fn malformed(reason: &'static str) -> TokenError {
    TokenError::Malformed { reason }
}

/// A single-use enrollment token: the id of its record and its secret.
///
/// The secret is wiped from memory when the token is dropped. The type has no `Clone`,
/// `Display`, `Serialize` or `Deserialize` on purpose; the only way to get the text is
/// [`EnrollmentToken::to_text`], which is meant to be shown once.
pub struct EnrollmentToken {
    id: Uuid,
    secret: Zeroizing<[u8; SECRET_LEN]>,
    ca_fingerprint: Option<CaFingerprint>,
}

impl EnrollmentToken {
    /// Creates a token for the record `id` with a fresh secret from the system random number
    /// generator, and without a CA fingerprint (see [`with_ca_fingerprint`]).
    ///
    /// [`with_ca_fingerprint`]: EnrollmentToken::with_ca_fingerprint
    ///
    /// # Errors
    ///
    /// [`TokenError::Random`] when the random number generator fails.
    pub fn generate(id: Uuid) -> Result<Self, TokenError> {
        let mut secret = Zeroizing::new([0_u8; SECRET_LEN]);
        rand::fill(secret.as_mut_slice()).map_err(|_| TokenError::Random)?;
        Ok(Self {
            id,
            secret,
            ca_fingerprint: None,
        })
    }

    /// Creates a token from a known id and secret, for tests and fixtures.
    ///
    /// The caller's copy of `secret` is not wiped.
    pub fn from_parts(id: Uuid, secret: [u8; SECRET_LEN]) -> Self {
        Self {
            id,
            secret: Zeroizing::new(secret),
            ca_fingerprint: None,
        }
    }

    /// The token with the fingerprint of the CA root of the controller that issued it; its
    /// text form is then `tnk2`. The digest does not change.
    #[must_use]
    pub fn with_ca_fingerprint(mut self, fingerprint: CaFingerprint) -> Self {
        self.ca_fingerprint = Some(fingerprint);
        self
    }

    /// The id of the token record.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// The fingerprint of the issuing controller's CA root: `Some` for a `tnk2` token, `None`
    /// for a `tnk1` token.
    pub fn ca_fingerprint(&self) -> Option<CaFingerprint> {
        self.ca_fingerprint
    }

    /// The text form (see the module documentation): `tnk2.<id>.<secret>.<fingerprint>` with a
    /// CA fingerprint, `tnk1.<id>.<secret>` without one.
    ///
    /// The returned buffer is wiped when it is dropped.
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::with_capacity(TOKEN_TEXT_LEN));
        text.push_str(if self.ca_fingerprint.is_some() {
            TOKEN_PREFIX
        } else {
            LEGACY_TOKEN_PREFIX
        });
        text.push('.');
        text.push_str(self.id.simple().encode_lower(&mut Uuid::encode_buffer()));
        text.push('.');
        push_base64url(&mut text, self.secret.as_slice());
        if let Some(fingerprint) = &self.ca_fingerprint {
            text.push('.');
            push_base64url(&mut text, &fingerprint.0);
        }
        text
    }

    /// Reads the text form, `tnk2` or `tnk1`.
    ///
    /// Leading and trailing ASCII whitespace is ignored. The id may be written in either
    /// case; the secret and the fingerprint must be the canonical unpadded base64url spelling.
    ///
    /// # Errors
    ///
    /// [`TokenError::Malformed`] when the text is not a token of these formats; the reason
    /// names the first rule that failed.
    pub fn parse(text: &str) -> Result<Self, TokenError> {
        let mut parts = text.trim_ascii().split('.');
        let with_fingerprint = check_prefix(parts.next().unwrap_or_default())?;
        let id = parts
            .next()
            .ok_or(malformed("the token has too few parts"))?;
        let secret = parts
            .next()
            .ok_or(malformed("the token has too few parts"))?;
        let fingerprint = if with_fingerprint {
            Some(
                parts
                    .next()
                    .ok_or(malformed("the token has too few parts"))?,
            )
        } else {
            None
        };
        if parts.next().is_some() {
            return Err(malformed("the token has too many parts"));
        }
        let id = decode_hex::<16>(id)
            .map(Uuid::from_bytes)
            .ok_or(malformed("the token id is not 32 hexadecimal digits"))?;
        let secret = decode_base64url_32(secret).map_err(|fault| {
            malformed(match fault {
                Base64Fault::Padded => "the token secret must not be padded",
                Base64Fault::Length => "the token secret is not 43 characters long",
                Base64Fault::Alphabet => {
                    "the token secret has a character outside the base64url alphabet"
                }
                Base64Fault::NonCanonical => "the token secret is not in canonical form",
            })
        })?;
        let ca_fingerprint = fingerprint
            .map(|text| {
                decode_base64url_32(text)
                    .map(|bytes| CaFingerprint(*bytes))
                    .map_err(|fault| {
                        malformed(match fault {
                            Base64Fault::Padded => "the token CA fingerprint must not be padded",
                            Base64Fault::Length => {
                                "the token CA fingerprint is not 43 characters long"
                            }
                            Base64Fault::Alphabet => {
                                "the token CA fingerprint has a character outside the base64url alphabet"
                            }
                            Base64Fault::NonCanonical => {
                                "the token CA fingerprint is not in canonical form"
                            }
                        })
                    })
            })
            .transpose()?;
        Ok(Self {
            id,
            secret,
            ca_fingerprint,
        })
    }

    /// The digest a controller stores in place of the token.
    pub fn digest(&self) -> TokenDigest {
        let mut context = Context::new(&SHA256);
        context.update(DIGEST_DOMAIN);
        context.update(self.id.as_bytes());
        context.update(self.secret.as_slice());
        let output = context.finish();
        let mut bytes = [0_u8; DIGEST_LEN];
        // SHA-256 output is always `DIGEST_LEN` bytes long.
        bytes.copy_from_slice(output.as_ref());
        TokenDigest(bytes)
    }
}

impl fmt::Debug for EnrollmentToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollmentToken")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .field("ca_fingerprint", &self.ca_fingerprint)
            .finish()
    }
}

/// The SHA-256 of a CA root certificate's DER encoding, as a `tnk2` token carries it.
///
/// Its text form here is 64 lowercase hexadecimal digits, the form the controller prints at
/// start, shows beside every token and accepts in `--ca-fingerprint`; in a token it is
/// unpadded base64url.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CaFingerprint([u8; DIGEST_LEN]);

impl CaFingerprint {
    /// The fingerprint of the certificate `der`.
    pub fn of_der(der: &[u8]) -> Self {
        let output = aws_lc_rs::digest::digest(&SHA256, der);
        let mut bytes = [0_u8; DIGEST_LEN];
        // SHA-256 output is always `DIGEST_LEN` bytes long.
        bytes.copy_from_slice(output.as_ref());
        Self(bytes)
    }

    /// Reads a fingerprint from exactly 64 hexadecimal digits, in either case.
    ///
    /// # Errors
    ///
    /// [`TokenError::Malformed`] when the text has another length or a character that is not a
    /// hexadecimal digit.
    pub fn from_hex(text: &str) -> Result<Self, TokenError> {
        decode_hex::<DIGEST_LEN>(text)
            .map(Self)
            .ok_or(malformed("the CA fingerprint is not 64 hexadecimal digits"))
    }

    /// The fingerprint as 64 lowercase hexadecimal digits.
    pub fn to_hex(&self) -> String {
        let mut text = String::with_capacity(DIGEST_LEN * 2);
        push_hex(&mut text, &self.0);
        text
    }
}

impl fmt::Debug for CaFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CaFingerprint({})", self.to_hex())
    }
}

impl fmt::Display for CaFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The SHA-256 digest of an [`EnrollmentToken`], as a controller stores it.
///
/// Its text form is 64 hexadecimal digits; it serializes as that string.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenDigest([u8; DIGEST_LEN]);

impl TokenDigest {
    /// Reads a digest from exactly 64 hexadecimal digits, in either case.
    ///
    /// # Errors
    ///
    /// [`TokenError::Malformed`] when the text has another length or a character that is not a
    /// hexadecimal digit.
    pub fn from_hex(text: &str) -> Result<Self, TokenError> {
        decode_hex::<DIGEST_LEN>(text)
            .map(Self)
            .ok_or(malformed("the digest is not 64 hexadecimal digits"))
    }

    /// The digest as 64 lowercase hexadecimal digits.
    pub fn to_hex(&self) -> String {
        let mut text = String::with_capacity(DIGEST_LEN * 2);
        push_hex(&mut text, &self.0);
        text
    }

    /// Whether `token` is the token this digest was made from, compared in constant time.
    pub fn matches(&self, token: &EnrollmentToken) -> bool {
        verify_slices_are_equal(&self.0, &token.digest().0).is_ok()
    }
}

impl fmt::Debug for TokenDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenDigest({})", self.to_hex())
    }
}

impl Serialize for TokenDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for TokenDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(DigestVisitor)
    }
}

/// Reads a [`TokenDigest`] from its hexadecimal string.
struct DigestVisitor;

impl Visitor<'_> for DigestVisitor {
    type Value = TokenDigest;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a SHA-256 digest as 64 hexadecimal digits")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<TokenDigest, E> {
        TokenDigest::from_hex(value).map_err(|_| E::invalid_value(Unexpected::Str(value), &self))
    }
}

/// Checks the first part of a token: `tnk2` (true: a fingerprint follows) or `tnk1` (false),
/// or a better message for another version.
fn check_prefix(prefix: &str) -> Result<bool, TokenError> {
    if prefix == TOKEN_PREFIX {
        return Ok(true);
    }
    if prefix == LEGACY_TOKEN_PREFIX {
        return Ok(false);
    }
    // `tnk` followed by digits is a token of a format version this code does not know.
    let other_version = prefix
        .strip_prefix("tnk")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()));
    Err(malformed(if other_version {
        "the token format version is unknown"
    } else {
        "the token does not start with tnk2 or tnk1"
    }))
}

/// Appends `bytes` as unpadded base64url.
fn push_base64url(out: &mut String, bytes: &[u8]) {
    for chunk in bytes.chunks(3) {
        let (b0, b1, b2, chars) = match *chunk {
            [b0, b1, b2] => (b0, b1, b2, 4),
            [b0, b1] => (b0, b1, 0, 3),
            [b0] => (b0, 0, 0, 2),
            _ => continue,
        };
        let sextets = Zeroizing::new([
            b0 >> 2,
            ((b0 & 0x03) << 4) | (b1 >> 4),
            ((b1 & 0x0f) << 2) | (b2 >> 6),
            b2 & 0x3f,
        ]);
        for &sextet in sextets.iter().take(chars) {
            out.push(char::from(BASE64URL[usize::from(sextet)]));
        }
    }
}

/// The 6-bit value of a base64url character, or `None` for any other byte.
const fn sextet_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// What is wrong with the base64url spelling of 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base64Fault {
    /// It has padding.
    Padded,
    /// It is not 43 characters long.
    Length,
    /// A character is outside the alphabet.
    Alphabet,
    /// The unused low bits of the last character are not zero.
    NonCanonical,
}

/// Decodes the 43 characters of 32 bytes, a secret or a fingerprint; refuses padding, other
/// characters and any spelling that is not the canonical one.
fn decode_base64url_32(text: &str) -> Result<Zeroizing<[u8; SECRET_LEN]>, Base64Fault> {
    let text = text.as_bytes();
    if text.contains(&b'=') {
        return Err(Base64Fault::Padded);
    }
    if text.len() != SECRET_TEXT_LEN {
        return Err(Base64Fault::Length);
    }
    let mut sextets = Zeroizing::new([0_u8; SECRET_TEXT_LEN]);
    for (slot, &byte) in sextets.iter_mut().zip(text) {
        *slot = sextet_value(byte).ok_or(Base64Fault::Alphabet)?;
    }
    let mut secret = Zeroizing::new([0_u8; SECRET_LEN]);
    for (group, dest) in sextets.chunks(4).zip(secret.chunks_mut(3)) {
        match (group, dest) {
            ([s0, s1, s2, s3], [o0, o1, o2]) => {
                *o0 = (*s0 << 2) | (*s1 >> 4);
                *o1 = (*s1 << 4) | (*s2 >> 2);
                *o2 = (*s2 << 6) | *s3;
            }
            ([s0, s1, s2], [o0, o1]) => {
                // The two unused low bits of the last character must be zero.
                if *s2 & 0x03 != 0 {
                    return Err(Base64Fault::NonCanonical);
                }
                *o0 = (*s0 << 2) | (*s1 >> 4);
                *o1 = (*s1 << 4) | (*s2 >> 2);
            }
            _ => return Err(Base64Fault::Length),
        }
    }
    Ok(secret)
}

/// The value of a hexadecimal digit of either case.
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes exactly `2 * N` hexadecimal digits of either case.
fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let text = text.as_bytes();
    if text.len() != N * 2 {
        return None;
    }
    let mut bytes = [0_u8; N];
    // The length check above leaves no remainder.
    let (pairs, _) = text.as_chunks::<2>();
    for (slot, &[high, low]) in bytes.iter_mut().zip(pairs) {
        *slot = (hex_value(high)? << 4) | hex_value(low)?;
    }
    Some(bytes)
}

/// Appends `bytes` as lowercase hexadecimal digits.
fn push_hex(out: &mut String, bytes: &[u8]) {
    for &byte in bytes {
        out.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        out.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The id of the known-answer token.
    const KNOWN_ID: Uuid = Uuid::from_u128(0x0190_d1c2_0000_7000_8000_0000_0000_0001);

    /// The secret of the known-answer token as base64url: 32 bytes of 0x42.
    const KNOWN_SECRET_TEXT: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";

    /// The text of the known-answer token.
    const KNOWN_TEXT: &str =
        "tnk1.0190d1c2000070008000000000000001.QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";

    /// The digest of the known-answer token: SHA-256 over the bytes
    /// `"tenko-enrollment-token-v1\0"`, then the 16 bytes of `KNOWN_ID`, then 32 bytes of 0x42.
    const KNOWN_DIGEST: &str = "7b5f2bacfacffaa5379cfbb771e97ca6acf1e79c0acd97ea70960ae7bdf0dd75";

    fn known() -> EnrollmentToken {
        EnrollmentToken::from_parts(KNOWN_ID, [0x42; SECRET_LEN])
    }

    /// The reason of the `Malformed` error that parsing `text` must give.
    fn reason(text: &str) -> &'static str {
        match EnrollmentToken::parse(text) {
            Err(TokenError::Malformed { reason }) => reason,
            Err(other) => panic!("unexpected error for {text:?}: {other}"),
            Ok(_) => panic!("{text:?} was accepted"),
        }
    }

    /// The known token's text with its secret replaced.
    fn with_secret(secret: &str) -> String {
        format!("tnk1.0190d1c2000070008000000000000001.{secret}")
    }

    /// The known token's text with its id replaced.
    fn with_id(id: &str) -> String {
        format!("tnk1.{id}.{KNOWN_SECRET_TEXT}")
    }

    #[test]
    fn generated_token_round_trips_through_its_text() {
        let id = Uuid::now_v7();
        let token = EnrollmentToken::generate(id).unwrap();
        let text = token.to_text();
        let parsed = EnrollmentToken::parse(&text).unwrap();
        assert_eq!(parsed.id(), id);
        assert_eq!(parsed.digest(), token.digest());
        assert!(token.digest().matches(&parsed));
        assert_eq!(*parsed.to_text(), *text);
    }

    #[test]
    fn text_has_the_fixed_length_and_prefix() {
        let token = EnrollmentToken::generate(Uuid::now_v7()).unwrap();
        let text = token.to_text();
        assert_eq!(text.len(), LEGACY_TOKEN_TEXT_LEN);
        assert_eq!(text.len(), 81);
        assert!(text.starts_with("tnk1."));
        assert!(text.starts_with(&format!("{LEGACY_TOKEN_PREFIX}.")));
        assert!(text.is_ascii());
        let parts: Vec<&str> = text.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], token.id().simple().to_string());
        assert_eq!(parts[2].len(), 43);
    }

    /// The fingerprint of the known-answer `tnk2` token: the SHA-256 of no bytes.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// [`EMPTY_SHA256`] as unpadded base64url.
    const EMPTY_SHA256_TEXT: &str = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

    /// The known-answer token's text in `tnk2` with the fingerprint replaced.
    fn with_fingerprint(fingerprint: &str) -> String {
        format!("tnk2{}.{fingerprint}", &KNOWN_TEXT[4..])
    }

    #[test]
    fn a_token_with_a_fingerprint_renders_as_tnk2() {
        let fingerprint = CaFingerprint::of_der(b"");
        assert_eq!(fingerprint.to_hex(), EMPTY_SHA256);
        let token = known().with_ca_fingerprint(fingerprint);
        let text = token.to_text();
        assert_eq!(*text, with_fingerprint(EMPTY_SHA256_TEXT));
        assert_eq!(text.len(), TOKEN_TEXT_LEN);
        assert_eq!(text.len(), 125);
        assert!(text.starts_with("tnk2."));
        assert!(text.is_ascii());
        let parts: Vec<&str> = text.split('.').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[3], EMPTY_SHA256_TEXT);
        // The fingerprint takes no part in the digest.
        assert_eq!(token.digest().to_hex(), KNOWN_DIGEST);
        assert_eq!(token.ca_fingerprint(), Some(fingerprint));
    }

    #[test]
    fn tnk2_parses_and_its_fingerprint_is_read() {
        let parsed = EnrollmentToken::parse(&with_fingerprint(EMPTY_SHA256_TEXT)).unwrap();
        assert_eq!(parsed.id(), KNOWN_ID);
        assert_eq!(parsed.digest().to_hex(), KNOWN_DIGEST);
        assert_eq!(
            parsed
                .ca_fingerprint()
                .map(|fingerprint| fingerprint.to_hex()),
            Some(EMPTY_SHA256.to_owned())
        );
        assert_eq!(*parsed.to_text(), with_fingerprint(EMPTY_SHA256_TEXT));

        let generated = EnrollmentToken::generate(Uuid::now_v7())
            .unwrap()
            .with_ca_fingerprint(CaFingerprint([0xfb; DIGEST_LEN]));
        let parsed = EnrollmentToken::parse(&generated.to_text()).unwrap();
        assert_eq!(parsed.ca_fingerprint(), generated.ca_fingerprint());
        assert!(generated.digest().matches(&parsed));
        assert_eq!(*parsed.to_text(), *generated.to_text());
    }

    #[test]
    fn tnk1_still_parses_without_a_fingerprint() {
        let parsed = EnrollmentToken::parse(KNOWN_TEXT).unwrap();
        assert_eq!(parsed.ca_fingerprint(), None);
        assert_eq!(*parsed.to_text(), KNOWN_TEXT);
        // The same id and secret with a fingerprint match the same digest.
        let tnk2 = EnrollmentToken::parse(&with_fingerprint(EMPTY_SHA256_TEXT)).unwrap();
        assert!(parsed.digest().matches(&tnk2));
    }

    #[test]
    fn tnk2_refuses_a_bad_fingerprint() {
        let long = format!("{EMPTY_SHA256_TEXT}A");
        let padded = format!("{EMPTY_SHA256_TEXT}=");
        let plus = EMPTY_SHA256_TEXT.replace('-', "+");
        // 'U' ends the fingerprint; 'V' sets one of the two unused low bits.
        let spoiled = format!("{}V", &EMPTY_SHA256_TEXT[..42]);
        assert!(EMPTY_SHA256_TEXT.ends_with('U'));
        for (fingerprint, expected) in [
            (
                &EMPTY_SHA256_TEXT[..42],
                "the token CA fingerprint is not 43 characters long",
            ),
            (
                long.as_str(),
                "the token CA fingerprint is not 43 characters long",
            ),
            ("", "the token CA fingerprint is not 43 characters long"),
            (
                EMPTY_SHA256,
                "the token CA fingerprint is not 43 characters long",
            ),
            (
                padded.as_str(),
                "the token CA fingerprint must not be padded",
            ),
            (
                plus.as_str(),
                "the token CA fingerprint has a character outside the base64url alphabet",
            ),
            (
                spoiled.as_str(),
                "the token CA fingerprint is not in canonical form",
            ),
        ] {
            assert_eq!(
                reason(&with_fingerprint(fingerprint)),
                expected,
                "{fingerprint:?}"
            );
        }
        // A tnk2 token needs its fourth part, and a tnk1 token must not have one.
        assert_eq!(
            reason(&format!("tnk2{}", &KNOWN_TEXT[4..])),
            "the token has too few parts"
        );
        assert_eq!(
            reason(&format!("{KNOWN_TEXT}.{EMPTY_SHA256_TEXT}")),
            "the token has too many parts"
        );
        assert_eq!(
            reason(&format!(
                "{}.{EMPTY_SHA256_TEXT}",
                with_fingerprint(EMPTY_SHA256_TEXT)
            )),
            "the token has too many parts"
        );
    }

    #[test]
    fn ca_fingerprint_hex_round_trips() {
        let fingerprint = CaFingerprint::from_hex(EMPTY_SHA256).unwrap();
        assert_eq!(fingerprint, CaFingerprint::of_der(b""));
        assert_eq!(fingerprint.to_string(), EMPTY_SHA256);
        assert_eq!(
            CaFingerprint::from_hex(&EMPTY_SHA256.to_ascii_uppercase()).unwrap(),
            fingerprint
        );
        assert_eq!(
            format!("{fingerprint:?}"),
            format!("CaFingerprint({EMPTY_SHA256})")
        );
        for bad in ["", &EMPTY_SHA256[..63], EMPTY_SHA256_TEXT] {
            assert!(CaFingerprint::from_hex(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn two_generated_tokens_differ() {
        let id = Uuid::now_v7();
        let first = EnrollmentToken::generate(id).unwrap();
        let second = EnrollmentToken::generate(id).unwrap();
        assert_ne!(*first.to_text(), *second.to_text());
        assert_ne!(first.digest(), second.digest());
        assert!(!first.digest().matches(&second));
    }

    #[test]
    fn known_answer() {
        let token = known();
        assert_eq!(*token.to_text(), KNOWN_TEXT);
        assert_eq!(token.digest().to_hex(), KNOWN_DIGEST);
        assert_eq!(KNOWN_TEXT.len(), LEGACY_TOKEN_TEXT_LEN);
        assert!(KNOWN_TEXT.ends_with(KNOWN_SECRET_TEXT));

        let parsed = EnrollmentToken::parse(KNOWN_TEXT).unwrap();
        assert_eq!(parsed.id(), KNOWN_ID);
        assert_eq!(parsed.digest().to_hex(), KNOWN_DIGEST);
    }

    #[test]
    fn digest_is_bound_to_the_id() {
        let first = EnrollmentToken::from_parts(KNOWN_ID, [0x42; SECRET_LEN]);
        let second = EnrollmentToken::from_parts(Uuid::from_u128(2), [0x42; SECRET_LEN]);
        assert_ne!(first.digest(), second.digest());
    }

    #[test]
    fn encoder_matches_the_rfc_4648_vectors_without_padding() {
        let vectors = [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in vectors {
            let mut out = String::new();
            push_base64url(&mut out, plain.as_bytes());
            assert_eq!(out, encoded, "encoding {plain:?}");
        }
        let mut out = String::new();
        push_base64url(&mut out, &[0xfb, 0xff, 0xbf]);
        assert_eq!(out, "-_-_");
    }

    #[test]
    fn secrets_round_trip_for_edge_patterns() {
        let mut counting = [0_u8; SECRET_LEN];
        for (index, byte) in counting.iter_mut().enumerate() {
            *byte = u8::try_from(index * 8 + 3).unwrap();
        }
        for secret in [
            [0x00; SECRET_LEN],
            [0xff; SECRET_LEN],
            [0xfb; SECRET_LEN],
            counting,
        ] {
            let token = EnrollmentToken::from_parts(KNOWN_ID, secret);
            let parsed = EnrollmentToken::parse(&token.to_text()).unwrap();
            assert_eq!(parsed.digest(), token.digest());
            assert_eq!(*parsed.secret, secret);
        }
    }

    #[test]
    fn parse_accepts_surrounding_whitespace() {
        let padded = format!(" \t{KNOWN_TEXT}\r\n");
        let parsed = EnrollmentToken::parse(&padded).unwrap();
        assert_eq!(parsed.id(), KNOWN_ID);
        assert_eq!(parsed.digest().to_hex(), KNOWN_DIGEST);
    }

    #[test]
    fn parse_accepts_an_uppercase_id() {
        let parsed = EnrollmentToken::parse(&with_id("0190D1C2000070008000000000000001")).unwrap();
        assert_eq!(parsed.id(), KNOWN_ID);
        assert_eq!(parsed.digest().to_hex(), KNOWN_DIGEST);
        // The text form is always lowercase.
        assert_eq!(*parsed.to_text(), KNOWN_TEXT);
    }

    #[test]
    fn parse_refuses_a_wrong_prefix() {
        let id_and_secret = &KNOWN_TEXT[5..];
        for text in [
            String::new(),
            "tnk".to_owned(),
            format!("TNK1.{id_and_secret}"),
            format!("tok1.{id_and_secret}"),
            format!("tnk.{id_and_secret}"),
            format!(".{id_and_secret}"),
            id_and_secret.to_owned(),
        ] {
            assert_eq!(
                reason(&text),
                "the token does not start with tnk2 or tnk1",
                "{text:?}"
            );
        }
    }

    #[test]
    fn parse_refuses_another_format_version() {
        let id_and_secret = &KNOWN_TEXT[5..];
        for version in ["tnk0", "tnk3", "tnk9", "tnk10"] {
            let text = format!("{version}.{id_and_secret}");
            assert_eq!(
                reason(&text),
                "the token format version is unknown",
                "{text:?}"
            );
        }
    }

    #[test]
    fn parse_refuses_missing_and_extra_parts() {
        assert_eq!(reason("tnk1"), "the token has too few parts");
        assert_eq!(reason("tnk1."), "the token has too few parts");
        assert_eq!(
            reason("tnk1.0190d1c2000070008000000000000001"),
            "the token has too few parts"
        );
        assert_eq!(
            reason(&format!("{KNOWN_TEXT}.extra")),
            "the token has too many parts"
        );
        assert_eq!(
            reason(&format!("{KNOWN_TEXT}.")),
            "the token has too many parts"
        );
    }

    #[test]
    fn parse_refuses_empty_parts() {
        assert_eq!(
            reason("tnk1.."),
            "the token id is not 32 hexadecimal digits"
        );
        assert_eq!(
            reason(&with_id("")),
            "the token id is not 32 hexadecimal digits"
        );
        assert_eq!(
            reason(&with_secret("")),
            "the token secret is not 43 characters long"
        );
    }

    #[test]
    fn parse_refuses_a_bad_id() {
        let id = "0190d1c2000070008000000000000001";
        let too_long = format!("{id}0");
        // 32 bytes, but not 32 ASCII digits.
        let non_ascii = format!("\u{e9}{}", &id[2..]);
        assert_eq!(non_ascii.len(), 32);
        for bad in [
            // 31 digits.
            &id[..31],
            // 33 digits.
            too_long.as_str(),
            // Not hexadecimal.
            "0190d1c200007000800000000000000g",
            // The hyphenated form is not accepted.
            "0190d1c2-0000-7000-8000-000000000001",
            non_ascii.as_str(),
        ] {
            assert_eq!(
                reason(&with_id(bad)),
                "the token id is not 32 hexadecimal digits",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn parse_refuses_a_secret_of_the_wrong_length() {
        let short = &KNOWN_SECRET_TEXT[..42];
        let long = format!("{KNOWN_SECRET_TEXT}Q");
        assert_eq!(short.len(), 42);
        assert_eq!(long.len(), 44);
        for secret in [short, long.as_str()] {
            assert_eq!(
                reason(&with_secret(secret)),
                "the token secret is not 43 characters long",
                "{secret:?}"
            );
        }
    }

    #[test]
    fn parse_refuses_padding() {
        let padded = format!("{KNOWN_SECRET_TEXT}=");
        assert_eq!(
            reason(&with_secret(&padded)),
            "the token secret must not be padded"
        );
        let padded_short = format!("{}=", &KNOWN_SECRET_TEXT[..42]);
        assert_eq!(
            reason(&with_secret(&padded_short)),
            "the token secret must not be padded"
        );
    }

    #[test]
    fn parse_refuses_characters_outside_the_alphabet() {
        for bad in ['+', '/', ' ', '*'] {
            let mut secret = KNOWN_SECRET_TEXT.to_owned();
            // Replace the first character, so the canonical check cannot be the cause.
            secret.replace_range(0..1, &bad.to_string());
            assert_eq!(
                reason(&with_secret(&secret)),
                "the token secret has a character outside the base64url alphabet",
                "{bad:?}"
            );
        }
        // A character of two bytes makes the secret 44 bytes long.
        let mut secret = KNOWN_SECRET_TEXT.to_owned();
        secret.replace_range(0..1, "\u{e9}");
        assert_eq!(
            reason(&with_secret(&secret)),
            "the token secret is not 43 characters long"
        );
    }

    #[test]
    fn parse_refuses_interior_whitespace() {
        let text = KNOWN_TEXT.replacen('.', ". ", 1);
        assert_eq!(reason(&text), "the token id is not 32 hexadecimal digits");
        let text = KNOWN_TEXT.replacen("QkJC", "Qk C", 1);
        assert_eq!(
            reason(&text),
            "the token secret has a character outside the base64url alphabet"
        );
    }

    #[test]
    fn parse_refuses_a_non_canonical_last_character() {
        // 'I' is 0b001000; 'J' sets one of the two unused low bits.
        let spoiled = format!("{}J", &KNOWN_SECRET_TEXT[..42]);
        assert!(KNOWN_SECRET_TEXT.ends_with('I'));
        assert_eq!(
            reason(&with_secret(&spoiled)),
            "the token secret is not in canonical form"
        );
    }

    #[test]
    fn only_alphabet_positions_divisible_by_four_end_a_secret() {
        let head = &KNOWN_SECRET_TEXT[..42];
        for (index, &last) in BASE64URL.iter().enumerate() {
            let text = with_secret(&format!("{head}{}", char::from(last)));
            let parsed = EnrollmentToken::parse(&text);
            assert_eq!(
                parsed.is_ok(),
                index % 4 == 0,
                "last character {}",
                char::from(last)
            );
            if let Ok(token) = parsed {
                // Canonical spelling means the text round trips unchanged.
                assert_eq!(*token.to_text(), text);
            }
        }
    }

    #[test]
    fn digest_matches_only_its_own_token() {
        let token = known();
        let digest = token.digest();
        assert!(digest.matches(&token));
        assert!(digest.matches(&EnrollmentToken::parse(KNOWN_TEXT).unwrap()));

        let other_secret = EnrollmentToken::from_parts(KNOWN_ID, [0x43; SECRET_LEN]);
        assert!(!digest.matches(&other_secret));

        let mut one_bit = [0x42; SECRET_LEN];
        one_bit[SECRET_LEN - 1] ^= 0x01;
        assert!(!digest.matches(&EnrollmentToken::from_parts(KNOWN_ID, one_bit)));

        let other_id = EnrollmentToken::from_parts(Uuid::from_u128(2), [0x42; SECRET_LEN]);
        assert!(!digest.matches(&other_id));
    }

    #[test]
    fn debug_output_shows_the_id_and_hides_the_secret() {
        let token = known();
        let shown = format!("{token:?}");
        assert!(shown.contains(&KNOWN_ID.to_string()), "{shown}");
        assert!(shown.contains("\"<redacted>\""), "{shown}");
        assert!(!shown.contains(KNOWN_SECRET_TEXT), "{shown}");
        assert!(!shown.contains("QkJC"), "{shown}");
        assert!(!shown.contains("66, 66"), "{shown}");
        assert!(!shown.contains("0x42"), "{shown}");
    }

    #[test]
    fn digest_debug_shows_the_hex() {
        let digest = known().digest();
        assert_eq!(
            format!("{digest:?}"),
            format!("TokenDigest({KNOWN_DIGEST})")
        );
    }

    #[test]
    fn digest_hex_round_trips() {
        let digest = TokenDigest::from_hex(KNOWN_DIGEST).unwrap();
        assert_eq!(digest, known().digest());
        assert_eq!(digest.to_hex(), KNOWN_DIGEST);
        assert_eq!(digest.to_hex().len(), 64);

        let upper = TokenDigest::from_hex(&KNOWN_DIGEST.to_ascii_uppercase()).unwrap();
        assert_eq!(upper, digest);
        assert_eq!(upper.to_hex(), KNOWN_DIGEST);

        let fresh = EnrollmentToken::generate(Uuid::now_v7()).unwrap().digest();
        assert_eq!(TokenDigest::from_hex(&fresh.to_hex()).unwrap(), fresh);
    }

    #[test]
    fn digest_hex_refuses_bad_text() {
        let wrong = TokenError::Malformed {
            reason: "the digest is not 64 hexadecimal digits",
        };
        let too_long = format!("{KNOWN_DIGEST}0");
        let non_hex = format!("{}g", &KNOWN_DIGEST[..63]);
        let non_ascii = "\u{e9}".repeat(32);
        let padded = format!(" {KNOWN_DIGEST}");
        for text in [
            "",
            &KNOWN_DIGEST[..63],
            too_long.as_str(),
            non_hex.as_str(),
            non_ascii.as_str(),
            padded.as_str(),
            "0x7b5f2bacfacffaa5379cfbb771e97ca6acf1e79c0acd97ea70960ae7bdf0dd",
        ] {
            assert_eq!(TokenDigest::from_hex(text), Err(wrong.clone()), "{text:?}");
        }
    }

    #[test]
    fn digest_serializes_as_a_hex_string() {
        let digest = known().digest();
        let json = serde_json::to_string(&digest).unwrap();
        assert_eq!(json, format!("\"{KNOWN_DIGEST}\""));
        assert_eq!(serde_json::from_str::<TokenDigest>(&json).unwrap(), digest);

        let value = serde_json::to_value(digest).unwrap();
        assert!(value.is_string());
        assert_eq!(
            serde_json::from_value::<TokenDigest>(value).unwrap(),
            digest
        );

        let upper = format!("\"{}\"", KNOWN_DIGEST.to_ascii_uppercase());
        assert_eq!(serde_json::from_str::<TokenDigest>(&upper).unwrap(), digest);
    }

    #[test]
    fn digest_deserialization_refuses_other_json() {
        let too_long = format!("\"{KNOWN_DIGEST}00\"");
        let non_hex = format!("\"{}z\"", &KNOWN_DIGEST[..63]);
        for json in [
            "\"\"",
            "\"abcd\"",
            "42",
            "null",
            "[1, 2]",
            too_long.as_str(),
            non_hex.as_str(),
        ] {
            assert!(serde_json::from_str::<TokenDigest>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn errors_carry_stable_codes_and_statuses() {
        let malformed = TokenError::Malformed { reason: "x" };
        assert_eq!(malformed.code(), "cluster.enrollment.invalid_token");
        assert_eq!(malformed.http_status(), 401);
        assert_eq!(
            malformed.to_string(),
            "the enrollment token is malformed: x"
        );
        assert!(malformed.params().is_empty());

        assert_eq!(TokenError::Random.code(), "cluster.enrollment.random");
        assert_eq!(TokenError::Random.http_status(), 500);
        assert_eq!(
            TokenError::Random.to_string(),
            "the system random number generator failed"
        );
    }

    #[test]
    fn error_text_never_contains_the_input() {
        let secret_looking = with_secret("QkJC-not-a-secret!");
        let error = EnrollmentToken::parse(&secret_looking).unwrap_err();
        assert!(!error.to_string().contains("QkJC"));
    }
}
