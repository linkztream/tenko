//! Bearer secrets: session cookies, personal API tokens and the one-time setup token.
//!
//! Each secret is generated here, handed to the client once and stored only as its
//! SHA-256 hash. The secrets carry 256 bits (sessions and tokens) or 100 bits (the setup
//! token, which is typed by hand and lives for one start of the server), so a fast hash is
//! enough: there is nothing to brute-force.

use std::fmt;

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{
    encoding::{base32_encode, base64url_decode, base64url_encode},
    error::AuthError,
    random,
};

/// Prefix of personal API tokens, so secret scanners can recognize them.
pub const TOKEN_PREFIX: &str = "tnk_";

/// A secret as the client receives it. `Debug` redacts it; there is no `Display`.
#[derive(Clone, PartialEq, Eq)]
pub struct BearerSecret(Zeroizing<String>);

impl BearerSecret {
    /// The secret text, to put into a cookie or show once. Never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The hash the store keys the secret by.
    pub fn hash(&self) -> Vec<u8> {
        hash_secret(&self.0)
    }
}

impl fmt::Debug for BearerSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerSecret(<redacted>)")
    }
}

/// SHA-256 of a presented secret.
pub fn hash_secret(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

/// A new session secret: 256 random bits, base64url (43 characters).
///
/// # Errors
///
/// [`AuthError::Internal`] if the random source fails.
pub fn new_session_secret() -> Result<BearerSecret, AuthError> {
    let bytes = Zeroizing::new(random::array::<32>()?);
    Ok(BearerSecret(Zeroizing::new(base64url_encode(&*bytes))))
}

/// Whether a presented cookie value has the shape of a session secret.
pub fn looks_like_session_secret(value: &str) -> bool {
    value.len() == 43 && base64url_decode(value).is_ok_and(|bytes| bytes.len() == 32)
}

/// A new personal API token: `tnk_` and 256 random bits, base64url.
///
/// # Errors
///
/// [`AuthError::Internal`] if the random source fails.
pub fn new_api_token() -> Result<BearerSecret, AuthError> {
    let bytes = Zeroizing::new(random::array::<32>()?);
    let mut text = Zeroizing::new(String::with_capacity(47));
    text.push_str(TOKEN_PREFIX);
    text.push_str(&base64url_encode(&*bytes));
    Ok(BearerSecret(text))
}

/// The one-time setup token of a new installation (API-10). WP1.8 prints it to the console
/// and the log at start while setup is open; the operator types it into the wizard.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupToken(Zeroizing<String>);

impl SetupToken {
    /// A new token: 100 random bits as 20 base32 characters in groups of five
    /// (`ABCDE-FGHIJ-KLMNO-PQRST`), and its verifier.
    ///
    /// # Errors
    ///
    /// [`AuthError::Internal`] if the random source fails.
    pub fn generate() -> Result<(Self, SetupTokenVerifier), AuthError> {
        let bytes = Zeroizing::new(random::array::<13>()?);
        let encoded = Zeroizing::new(base32_encode(&*bytes));
        let mut text = Zeroizing::new(String::with_capacity(23));
        for (index, chunk) in encoded.as_bytes()[..20].chunks(5).enumerate() {
            if index > 0 {
                text.push('-');
            }
            text.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        }
        let verifier = SetupTokenVerifier {
            hash: normalized_hash(&text),
        };
        Ok((Self(text), verifier))
    }

    /// The token text, to print once. Never store it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SetupToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SetupToken(<redacted>)")
    }
}

/// Verifies a presented setup token without keeping the token itself.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupTokenVerifier {
    hash: Vec<u8>,
}

impl SetupTokenVerifier {
    /// Whether `presented` is the token, ignoring case, spaces and hyphens. Constant time.
    pub fn verify(&self, presented: &str) -> bool {
        aws_lc_rs::constant_time::verify_slices_are_equal(&normalized_hash(presented), &self.hash)
            .is_ok()
    }
}

impl fmt::Debug for SetupTokenVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SetupTokenVerifier(<redacted>)")
    }
}

fn normalized_hash(text: &str) -> Vec<u8> {
    let normalized: Zeroizing<String> = Zeroizing::new(
        text.chars()
            .filter(|c| !matches!(c, '-' | ' '))
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    );
    hash_secret(&normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_secrets_have_256_bits_and_differ() {
        let a = new_session_secret().expect("secret");
        let b = new_session_secret().expect("secret");
        assert_ne!(a, b);
        assert!(looks_like_session_secret(a.expose()));
        assert!(!looks_like_session_secret("not-a-session"));
        assert_eq!(a.hash().len(), 32);
        assert_eq!(format!("{a:?}"), "BearerSecret(<redacted>)");
    }

    #[test]
    fn api_tokens_carry_the_prefix() {
        let token = new_api_token().expect("token");
        assert!(token.expose().starts_with(TOKEN_PREFIX));
        assert_eq!(token.expose().len(), 47);
        assert_eq!(token.hash(), hash_secret(token.expose()));
    }

    #[test]
    fn setup_tokens_verify_leniently_and_only_themselves() {
        let (token, verifier) = SetupToken::generate().expect("token");
        let text = token.expose().to_owned();
        assert_eq!(text.len(), 23);
        assert_eq!(text.matches('-').count(), 3);
        assert!(verifier.verify(&text));
        assert!(verifier.verify(&text.to_lowercase().replace('-', " ")));
        assert!(!verifier.verify("AAAAA-AAAAA-AAAAA-AAAAA"));
        let (_, other) = SetupToken::generate().expect("token");
        assert!(!other.verify(&text));
        assert!(!format!("{token:?}").contains(&text));
    }
}
