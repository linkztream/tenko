//! The user-based security model: keys, authentication and privacy.
//!
//! - Password to key and key localization: RFC 3414, appendix A.2 and section 2.6, with the
//!   hash of the authentication protocol (RFC 7860 for the SHA-2 family).
//! - Authentication: HMAC over the whole message with the authentication parameters set
//!   to zeros, truncated to 12 (SHA-1), 16, 24, 32 or 48 octets (RFC 3414, RFC 7860).
//! - Privacy: AES-128 in CFB mode with a 128-bit feedback (RFC 3826); the key is the first
//!   16 octets of the privacy key localized with the hash of the authentication protocol.
//!
//! MD5 and DES are not implemented.

use std::{fmt, ops::Range};

use aws_lc_rs::{
    cipher::{
        AES_128, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext,
        UnboundCipherKey,
    },
    constant_time, digest, hmac,
    iv::FixedLength,
    rand,
};
use zeroize::Zeroizing;

use super::AuthProtocol;

/// The shortest password RFC 3414 accepts, in characters.
pub const MIN_PASSWORD_CHARS: usize = 8;

/// The number of octets of the repeated password that are hashed (RFC 3414, A.2.1).
const PASSWORD_HASH_OCTETS: usize = 1_048_576;

/// The length of the AES-128 key and of the AES block.
const AES_KEY_LEN: usize = 16;

/// The length of the salt in `msgPrivacyParameters`.
pub const SALT_LEN: usize = 8;

/// A failure of the security model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsmError(&'static str);

impl fmt::Display for UsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for UsmError {}

impl AuthProtocol {
    /// The number of octets of the digest in `msgAuthenticationParameters`.
    pub const fn mac_len(self) -> usize {
        match self {
            AuthProtocol::Sha1 => 12,
            AuthProtocol::Sha224 => 16,
            AuthProtocol::Sha256 => 24,
            AuthProtocol::Sha384 => 32,
            AuthProtocol::Sha512 => 48,
        }
    }

    fn digest_algorithm(self) -> &'static digest::Algorithm {
        match self {
            AuthProtocol::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            AuthProtocol::Sha224 => &digest::SHA224,
            AuthProtocol::Sha256 => &digest::SHA256,
            AuthProtocol::Sha384 => &digest::SHA384,
            AuthProtocol::Sha512 => &digest::SHA512,
        }
    }

    fn hmac_algorithm(self) -> hmac::Algorithm {
        match self {
            AuthProtocol::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            AuthProtocol::Sha224 => hmac::HMAC_SHA224,
            AuthProtocol::Sha256 => hmac::HMAC_SHA256,
            AuthProtocol::Sha384 => hmac::HMAC_SHA384,
            AuthProtocol::Sha512 => hmac::HMAC_SHA512,
        }
    }
}

/// Checks the length of a password.
///
/// # Errors
/// A password shorter than [`MIN_PASSWORD_CHARS`] characters. The error never shows the
/// password.
pub fn check_password(password: &str) -> Result<(), UsmError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        Err(UsmError(
            "a password needs at least 8 characters (RFC 3414)",
        ))
    } else {
        Ok(())
    }
}

/// The master key `Ku` of a password: the hash of 1 MiB of the repeated password.
///
/// An empty password gives the hash of nothing; [`check_password`] keeps those out.
pub fn password_to_key(protocol: AuthProtocol, password: &str) -> Zeroizing<Vec<u8>> {
    let password = password.as_bytes();
    let mut context = digest::Context::new(protocol.digest_algorithm());
    if password.is_empty() {
        return Zeroizing::new(context.finish().as_ref().to_vec());
    }
    let mut block = Zeroizing::new([0u8; 64]);
    let mut index = 0usize;
    for _ in 0..PASSWORD_HASH_OCTETS / block.len() {
        for slot in block.iter_mut() {
            *slot = password[index % password.len()];
            index += 1;
        }
        context.update(&block[..]);
    }
    Zeroizing::new(context.finish().as_ref().to_vec())
}

/// The key of one engine: `H(Ku || engineID || Ku)` (RFC 3414, section 2.6).
pub fn localize_key(protocol: AuthProtocol, master: &[u8], engine_id: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut context = digest::Context::new(protocol.digest_algorithm());
    context.update(master);
    context.update(engine_id);
    context.update(master);
    Zeroizing::new(context.finish().as_ref().to_vec())
}

/// A localized authentication key.
pub struct AuthKey {
    protocol: AuthProtocol,
    key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthKey")
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

impl AuthKey {
    /// A key from its localized octets.
    pub fn new(protocol: AuthProtocol, localized: Zeroizing<Vec<u8>>) -> Self {
        Self {
            protocol,
            key: localized,
        }
    }

    /// The authentication protocol.
    pub fn protocol(&self) -> AuthProtocol {
        self.protocol
    }

    /// The digest of `message` with the octets in `auth_params` taken as zeros,
    /// truncated; `None` when the range is outside the message.
    pub fn digest(&self, message: &[u8], auth_params: &Range<usize>) -> Option<Vec<u8>> {
        if auth_params.start > auth_params.end {
            return None;
        }
        let before = message.get(..auth_params.start)?;
        let after = message.get(auth_params.end..)?;
        let key = hmac::Key::new(self.protocol.hmac_algorithm(), &self.key);
        let mut context = hmac::Context::with_key(&key);
        context.update(before);
        context.update(&vec![0u8; auth_params.len()]);
        context.update(after);
        let tag = context.sign();
        Some(tag.as_ref()[..self.protocol.mac_len()].to_vec())
    }

    /// Writes the digest of `message` into its authentication parameters.
    ///
    /// # Errors
    /// The range is outside the message or is not as long as the digest.
    pub fn sign(&self, message: &mut [u8], auth_params: &Range<usize>) -> Result<(), UsmError> {
        if auth_params.len() != self.protocol.mac_len() {
            return Err(UsmError(
                "the authentication parameters have the wrong length",
            ));
        }
        let tag = self.digest(message, auth_params).ok_or(UsmError(
            "the authentication parameters are outside the message",
        ))?;
        message[auth_params.clone()].copy_from_slice(&tag);
        Ok(())
    }

    /// Whether the authentication parameters of `message` are the digest of the rest.
    pub fn verify(&self, message: &[u8], auth_params: &Range<usize>) -> bool {
        if auth_params.len() != self.protocol.mac_len() {
            return false;
        }
        let Some(expected) = self.digest(message, auth_params) else {
            return false;
        };
        constant_time::verify_slices_are_equal(&expected, &message[auth_params.clone()]).is_ok()
    }
}

/// A localized AES-128 privacy key.
pub struct PrivKey {
    key: Zeroizing<[u8; AES_KEY_LEN]>,
}

impl fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivKey").finish_non_exhaustive()
    }
}

impl PrivKey {
    /// A key from a localized key: its first 16 octets.
    ///
    /// # Errors
    /// The localized key is shorter than 16 octets.
    pub fn new(localized: &[u8]) -> Result<Self, UsmError> {
        let mut key = Zeroizing::new([0u8; AES_KEY_LEN]);
        let head = localized
            .get(..AES_KEY_LEN)
            .ok_or(UsmError("the privacy key is shorter than 16 octets"))?;
        key.copy_from_slice(head);
        Ok(Self { key })
    }

    /// The initialization vector: boots, time and salt (RFC 3826, section 3.1.2.1).
    pub fn iv(boots: u32, time: u32, salt: &[u8; SALT_LEN]) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[..4].copy_from_slice(&boots.to_be_bytes());
        iv[4..8].copy_from_slice(&time.to_be_bytes());
        iv[8..].copy_from_slice(salt);
        iv
    }

    /// Encrypts `data` in place.
    ///
    /// # Errors
    /// The cipher failed.
    pub fn encrypt(
        &self,
        boots: u32,
        time: u32,
        salt: &[u8; SALT_LEN],
        data: &mut [u8],
    ) -> Result<(), UsmError> {
        let key = UnboundCipherKey::new(&AES_128, &self.key[..])
            .and_then(EncryptingKey::cfb128)
            .map_err(|_| UsmError("the AES key was refused"))?;
        let iv = FixedLength::from(Self::iv(boots, time, salt));
        key.less_safe_encrypt(data, EncryptionContext::Iv128(iv))
            .map(|_| ())
            .map_err(|_| UsmError("AES encryption failed"))
    }

    /// Decrypts `data` in place.
    ///
    /// # Errors
    /// The salt is not 8 octets or the cipher failed.
    pub fn decrypt(
        &self,
        boots: u32,
        time: u32,
        salt: &[u8],
        data: &mut [u8],
    ) -> Result<(), UsmError> {
        let salt: &[u8; SALT_LEN] = salt
            .try_into()
            .map_err(|_| UsmError("the privacy parameters are not 8 octets"))?;
        let key = UnboundCipherKey::new(&AES_128, &self.key[..])
            .and_then(DecryptingKey::cfb128)
            .map_err(|_| UsmError("the AES key was refused"))?;
        let iv = FixedLength::from(Self::iv(boots, time, salt));
        key.decrypt(data, DecryptionContext::Iv128(iv))
            .map(|_| ())
            .map_err(|_| UsmError("AES decryption failed"))
    }
}

/// Hands out salts: a 64-bit counter seeded from the system random generator
/// (RFC 3826, section 3.1.2.1).
#[derive(Debug)]
pub struct SaltGenerator {
    next: u64,
}

impl SaltGenerator {
    /// A generator with a random start.
    ///
    /// # Errors
    /// The system random generator failed.
    pub fn new() -> Result<Self, UsmError> {
        let mut seed = [0u8; 8];
        rand::fill(&mut seed).map_err(|_| UsmError("the system random generator failed"))?;
        Ok(Self {
            next: u64::from_be_bytes(seed),
        })
    }

    /// A generator with a given start (for tests).
    pub fn starting_at(next: u64) -> Self {
        Self { next }
    }

    /// The next salt.
    pub fn next_salt(&mut self) -> [u8; SALT_LEN] {
        let salt = self.next.to_be_bytes();
        self.next = self.next.wrapping_add(1);
        salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    const ENGINE_ID: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    #[test]
    fn sha1_key_derivation_matches_rfc_3414_appendix_a_3_2() {
        let master = password_to_key(AuthProtocol::Sha1, "maplesyrup");
        assert_eq!(hex(&master), "9fb5cc0381497b3793528939ff788d5d79145211");
        let localized = localize_key(AuthProtocol::Sha1, &master, &ENGINE_ID);
        assert_eq!(hex(&localized), "6695febc9288e36282235fc7151f128497b38f3f");
    }

    #[test]
    fn sha2_key_derivation_matches_independent_values() {
        // Computed independently with Node.js node:crypto from the algorithm of RFC 3414
        // appendix A.2.1 and section 2.6: password "maplesyrup" repeated to 1,048,576
        // octets and hashed, then H(Ku || engineID || Ku) with the engine id of the RFC
        // 3414 appendix A.3 samples (eleven zero octets and 02).
        let cases = [
            (
                AuthProtocol::Sha224,
                "282a5867ee9aac639ad59df9572c7d3ac0fbc13a905b6df07dbbf00b",
                "0bd8827c6e29f8065e08e09237f177e410f69b90e1782be682075674",
            ),
            (
                AuthProtocol::Sha256,
                "ab51014d1e077f6017df2b12bee5f5aa72993177e9bb569c4dff5a4ca0b4afac",
                "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b",
            ),
            (
                AuthProtocol::Sha384,
                "e06eccdf2c68a06ed034723c9c26e0db3b669e1e2efed49150b55377a2e98f383c86fb836857444654b287c93f51ff64",
                "3b298f16164a11184279d5432bf169e2d2a48307de02b3d3f7e2b4f36eb6f0455a53689a3937eea07319a633d2ccba78",
            ),
            (
                AuthProtocol::Sha512,
                "7e4396de5aadc77be853819b98c9406265b3a9c37cc3176569847a4e4f6fba63dd3a73d04924d31a63f95a601f9385af6be4ed1b37f87d040f7c6ed6f8d38a91",
                "22a5a36cedfcc085807a128d7bc6c2382167ad6c0dbc5fdff856740f3d84c099ad1ea87a8db096714d9788bd544047c9021e4229ce27e4c0a69250adfcffbb0b",
            ),
        ];
        for (protocol, master_hex, localized_hex) in cases {
            let master = password_to_key(protocol, "maplesyrup");
            assert_eq!(hex(&master), master_hex, "{protocol} master key");
            let localized = localize_key(protocol, &master, &ENGINE_ID);
            assert_eq!(hex(&localized), localized_hex, "{protocol} localized key");
        }
    }

    #[test]
    fn digests_are_truncated_per_protocol() {
        // Computed independently with Node.js node:crypto (HMAC with the localized key of
        // the test above over the message below), truncated per RFC 3414 (SHA-1) and
        // RFC 7860 (SHA-2) to 12, 16, 24, 32 and 48 octets.
        let message = b"tenko snmp usm authentication test message";
        let cases = [
            (AuthProtocol::Sha1, "39cf72a087ac0e6f8e9011a5"),
            (AuthProtocol::Sha224, "8f9cdaaf683908e94df4cb65e4597389"),
            (
                AuthProtocol::Sha256,
                "3f80570e899f0d6df7e3536c447edd6623ac08725b0c3eb4",
            ),
            (
                AuthProtocol::Sha384,
                "d718f85389c20cb87362b8630aedad2b6015e0379fe2df94b59665224fda5ee7",
            ),
            (
                AuthProtocol::Sha512,
                "bd317e0da97a185e10687beabdc5f3be135bc4cbfb292ed6b60e3080182b8de64aa9cd90698be0df10d73882523ab73e",
            ),
        ];
        for (protocol, expected) in cases {
            let master = password_to_key(protocol, "maplesyrup");
            let key = AuthKey::new(protocol, localize_key(protocol, &master, &ENGINE_ID));
            assert_eq!(expected.len(), protocol.mac_len() * 2);
            // The message has no authentication parameters: an empty range at its end.
            let tag = key
                .digest(message, &(message.len()..message.len()))
                .expect("digest");
            assert_eq!(hex(&tag), expected, "{protocol}");
        }
    }

    #[test]
    fn signing_and_verifying_use_zeroed_parameters() {
        let protocol = AuthProtocol::Sha256;
        let master = password_to_key(protocol, "maplesyrup");
        let key = AuthKey::new(protocol, localize_key(protocol, &master, &ENGINE_ID));
        let range = 10..10 + protocol.mac_len();
        let mut message: Vec<u8> = (0..80).collect();
        message[range.clone()].fill(0);
        let zeroed = message.clone();
        key.sign(&mut message, &range).expect("sign");
        assert_ne!(message, zeroed);
        assert!(key.verify(&message, &range));
        // The digest does not depend on what the parameters held when it was computed.
        let tag = key.digest(&message, &range).expect("digest");
        assert_eq!(tag, message[range.clone()]);

        let mut tampered = message.clone();
        tampered[60] ^= 1;
        assert!(!key.verify(&tampered, &range));
        let mut tampered = message.clone();
        tampered[range.start] ^= 1;
        assert!(!key.verify(&tampered, &range));
        // Wrong lengths and ranges outside the message.
        assert!(!key.verify(&message, &(10..20)));
        assert!(!key.verify(&message, &(70..70 + protocol.mac_len())));
        assert!(key.sign(&mut message, &(10..20)).is_err());
        // A key of another engine does not verify.
        let other = AuthKey::new(protocol, localize_key(protocol, &master, &[1, 2, 3, 4, 5]));
        assert!(!other.verify(&message, &range));
    }

    #[test]
    fn aes_cfb_matches_an_independent_implementation() {
        // Computed independently with Node.js node:crypto: the privacy key is the first 16
        // octets of H(Ku || engineID || Ku) for the password "privacy-secret" with SHA-256
        // (RFC 3414 section 2.6 and RFC 3826 section 1.2), the IV is boots 5, time 1000 and
        // the salt 0102030405060708 (RFC 3826 section 3.1.2.1), the cipher aes-128-cfb.
        let master = password_to_key(AuthProtocol::Sha256, "privacy-secret");
        let localized = localize_key(AuthProtocol::Sha256, &master, &ENGINE_ID);
        let key = PrivKey::new(&localized).expect("key");
        assert_eq!(hex(&localized[..16]), "d47054466d42ec0c48537254006acaeb");
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let plaintext = b"scoped pdu plaintext, 37 bytes long";
        let expected = "441403e5d8c053208c6cbf4bfbcca1cf4f40c099bb4270d59da63db92ecd815e8fc37a";

        let mut data = plaintext.to_vec();
        key.encrypt(5, 1000, &salt, &mut data).expect("encrypt");
        assert_eq!(hex(&data), expected);
        key.decrypt(5, 1000, &salt, &mut data).expect("decrypt");
        assert_eq!(&data, plaintext);
    }

    #[test]
    fn decryption_depends_on_every_iv_part() {
        let master = password_to_key(AuthProtocol::Sha1, "privacy-secret");
        let localized = localize_key(AuthProtocol::Sha1, &master, &ENGINE_ID);
        let key = PrivKey::new(&localized).expect("key");
        let salt = [9u8; 8];
        let plaintext = vec![
            0x30, 0x10, 0x04, 0x00, 0x04, 0x00, 0xA2, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        ];
        let mut data = plaintext.clone();
        key.encrypt(1, 2, &salt, &mut data).expect("encrypt");
        assert_ne!(data, plaintext);
        for (boots, time, salt) in [(2, 2, salt), (1, 3, salt), (1, 2, [8u8; 8])] {
            let mut wrong = data.clone();
            key.decrypt(boots, time, &salt, &mut wrong)
                .expect("decrypt");
            assert_ne!(wrong, plaintext);
        }
        assert!(key.decrypt(1, 2, &salt[..7], &mut data).is_err());
    }

    #[test]
    fn the_iv_is_boots_time_and_salt() {
        let iv = PrivKey::iv(0x0102_0304, 0x0506_0708, &[9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(iv, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    }

    #[test]
    fn salts_count_up_from_a_random_start() {
        let mut salts = SaltGenerator::starting_at(u64::MAX);
        assert_eq!(salts.next_salt(), [0xFF; 8]);
        assert_eq!(salts.next_salt(), [0; 8]);
        assert_eq!(salts.next_salt(), [0, 0, 0, 0, 0, 0, 0, 1]);
        let mut first = SaltGenerator::new().expect("random");
        let mut second = SaltGenerator::new().expect("random");
        assert_ne!(first.next_salt(), second.next_salt());
    }

    #[test]
    fn short_passwords_are_refused_without_naming_them() {
        assert!(check_password("1234567").is_err());
        assert!(check_password("12345678").is_ok());
        // Characters, not octets.
        assert!(check_password("\u{e5}\u{e4}\u{f6}\u{e5}\u{e4}\u{f6}\u{e5}").is_err());
        let message = check_password("short").expect_err("short").to_string();
        assert!(!message.contains("short"));
    }

    #[test]
    fn debug_output_hides_key_material() {
        let master = password_to_key(AuthProtocol::Sha1, "maplesyrup");
        let key = AuthKey::new(
            AuthProtocol::Sha1,
            localize_key(AuthProtocol::Sha1, &master, &ENGINE_ID),
        );
        let priv_key = PrivKey::new(&[0x42; 20]).expect("key");
        let text = format!("{key:?} {priv_key:?}");
        assert!(!text.contains("6695") && !text.contains("42"));
    }
}
