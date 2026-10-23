//! The signing algorithms over `aws-lc-rs` (P2-Q4): ECDSA P-256 with SHA-256 (algorithm
//! 13, RFC 6605) and Ed25519 (algorithm 15, RFC 8080), the DNSKEY record of a key, its key
//! tag (RFC 4034, appendix B) and the DS digest with SHA-256 (digest type 2, RFC 4509).
//!
//! A private key is kept as PKCS#8 in the vault and loaded into a [`KeyPair`] when the
//! signer needs it. ECDSA signatures are the fixed 64-octet form `r || s` that RFC 6605
//! puts in the RRSIG; the DNSKEY holds the public point without its leading 0x04.
//!
//! The validator (WP10.2, RFC 8624) verifies more than the signer signs: RSA with SHA-1
//! (5 and 7), SHA-256 (8) and SHA-512 (10), ECDSA P-384 with SHA-384 (14), and the DS
//! digests SHA-1 (1) and SHA-384 (4) beside SHA-256; see [`verify`], [`ds_matches`] and
//! [`supported_algorithm`].

use aws_lc_rs::{
    digest,
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED, ED25519,
        EcdsaKeyPair, EcdsaVerificationAlgorithm, Ed25519KeyPair, KeyPair as _,
        RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY, RsaPublicKeyComponents, UnparsedPublicKey,
    },
};
use tenko_core::{
    dns::{DnsName, DnssecAlgorithm, KeyRole, RecordData},
    serde_util::HexBytes,
};
use zeroize::Zeroizing;

/// DNSKEY flags of a zone-signing key: the zone key bit.
pub const FLAGS_ZSK: u16 = 256;

/// DNSKEY flags of a key-signing or combined key: the zone key and the secure entry point.
pub const FLAGS_KSK: u16 = 257;

/// The DNSKEY protocol, always 3.
pub const PROTOCOL: u8 = 3;

/// The DS digest type Tenko computes: SHA-256.
pub const DIGEST_SHA256: u8 = 2;

/// A key could not be made, loaded or used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CryptoError(pub &'static str);

/// A private key loaded for signing.
pub enum KeyPair {
    /// ECDSA P-256 with SHA-256.
    Ecdsa(EcdsaKeyPair),
    /// Ed25519.
    Ed25519(Ed25519KeyPair),
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("KeyPair").field(&self.algorithm()).finish()
    }
}

impl KeyPair {
    /// A new key of `algorithm` and its PKCS#8 form for the vault.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the library cannot make one.
    pub fn generate(algorithm: DnssecAlgorithm) -> Result<(Self, Zeroizing<Vec<u8>>), CryptoError> {
        match algorithm {
            DnssecAlgorithm::EcdsaP256Sha256 => {
                let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
                    .map_err(|_| CryptoError("no ECDSA key could be generated"))?;
                let der = pair
                    .to_pkcs8v1()
                    .map_err(|_| CryptoError("the ECDSA key has no PKCS#8 form"))?;
                Ok((Self::Ecdsa(pair), Zeroizing::new(der.as_ref().to_vec())))
            }
            DnssecAlgorithm::Ed25519 => {
                let pair = Ed25519KeyPair::generate()
                    .map_err(|_| CryptoError("no Ed25519 key could be generated"))?;
                let der = pair
                    .to_pkcs8()
                    .map_err(|_| CryptoError("the Ed25519 key has no PKCS#8 form"))?;
                Ok((Self::Ed25519(pair), Zeroizing::new(der.as_ref().to_vec())))
            }
        }
    }

    /// Loads a key from its PKCS#8 form.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the bytes are not a key of `algorithm`.
    pub fn from_pkcs8(algorithm: DnssecAlgorithm, der: &[u8]) -> Result<Self, CryptoError> {
        match algorithm {
            DnssecAlgorithm::EcdsaP256Sha256 => {
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)
                    .map(Self::Ecdsa)
                    .map_err(|_| CryptoError("the stored key is not an ECDSA P-256 key"))
            }
            DnssecAlgorithm::Ed25519 => Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
                .map(Self::Ed25519)
                .map_err(|_| CryptoError("the stored key is not an Ed25519 key")),
        }
    }

    /// Loads an Ed25519 key from its 32-octet seed (the RFC 8080 test vectors).
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the seed is not 32 octets.
    pub fn ed25519_from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        Ed25519KeyPair::from_seed_unchecked(seed)
            .map(Self::Ed25519)
            .map_err(|_| CryptoError("an Ed25519 seed is 32 octets"))
    }

    /// The algorithm.
    pub fn algorithm(&self) -> DnssecAlgorithm {
        match self {
            Self::Ecdsa(_) => DnssecAlgorithm::EcdsaP256Sha256,
            Self::Ed25519(_) => DnssecAlgorithm::Ed25519,
        }
    }

    /// The public key as the DNSKEY carries it: the point `x || y` for P-256 (RFC 6605,
    /// section 4), the 32 octets for Ed25519 (RFC 8080, section 3).
    pub fn public_key(&self) -> Vec<u8> {
        match self {
            Self::Ecdsa(pair) => {
                let point = pair.public_key().as_ref();
                point.get(1..).unwrap_or_default().to_vec()
            }
            Self::Ed25519(pair) => pair.public_key().as_ref().to_vec(),
        }
    }

    /// Signs `message`.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the library fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::Ecdsa(pair) => pair
                .sign(&SystemRandom::new(), message)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| CryptoError("the ECDSA signature failed")),
            Self::Ed25519(pair) => Ok(pair.sign(message).as_ref().to_vec()),
        }
    }
}

/// The algorithm of a DNSKEY algorithm number Tenko knows.
pub fn algorithm_of(number: u8) -> Option<DnssecAlgorithm> {
    match number {
        13 => Some(DnssecAlgorithm::EcdsaP256Sha256),
        15 => Some(DnssecAlgorithm::Ed25519),
        _ => None,
    }
}

// WP10.2: the validator's algorithms (RFC 8624 section 3.1) and DS digests (section 3.3).
/// Whether the validator verifies signatures of algorithm `number`: RSASHA1 (5),
/// RSASHA1-NSEC3-SHA1 (7), RSASHA256 (8), RSASHA512 (10), ECDSAP256SHA256 (13),
/// ECDSAP384SHA384 (14) and ED25519 (15). ED448 (16) and the GOST algorithms (12, 23) are
/// not supported, so a zone signed with them alone is insecure; RSAMD5 (1) and DSA (3, 6)
/// are refused as RFC 8624 says they must be.
pub const fn supported_algorithm(number: u8) -> bool {
    matches!(number, 5 | 7 | 8 | 10 | 13 | 14 | 15)
}

/// Whether the validator computes DS digests of `digest_type`: SHA-1 (1), SHA-256 (2) and
/// SHA-384 (4). GOST (3) is not supported.
pub const fn supported_digest(digest_type: u8) -> bool {
    matches!(digest_type, 1 | 2 | 4)
}

/// The public key of an RSA DNSKEY (RFC 3110 section 2): the exponent's length in one
/// octet, or in the two that follow a zero octet, then the exponent and the modulus.
fn rsa_components(public_key: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = match *public_key {
        [0, high, low, ref rest @ ..] => (usize::from(u16::from_be_bytes([high, low])), rest),
        [len, ref rest @ ..] => (usize::from(len), rest),
        [] => return None,
    };
    if len == 0 || rest.len() <= len {
        return None;
    }
    Some(rest.split_at(len))
}

/// Whether `signature` over `message` verifies with the DNSKEY public key `public_key` of
/// algorithm `number` ([`supported_algorithm`]). Unknown and unsupported algorithms never
/// verify; RSA keys below 1,024 bits are refused by the crypto (RFC 8624 section 3.1 asks
/// for at least that).
pub fn verify(number: u8, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match number {
        5 | 7 | 8 | 10 => {
            let Some((e, n)) = rsa_components(public_key) else {
                return false;
            };
            let parameters = match number {
                5 | 7 => &RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                8 => &RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                _ => &RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
            };
            RsaPublicKeyComponents { n, e }
                .verify(parameters, message, signature)
                .is_ok()
        }
        13 | 14 => {
            let (parameters, len): (&'static EcdsaVerificationAlgorithm, usize) = if number == 13 {
                (&ECDSA_P256_SHA256_FIXED, 64)
            } else {
                (&ECDSA_P384_SHA384_FIXED, 96)
            };
            if public_key.len() != len {
                return false;
            }
            let mut point = Vec::with_capacity(len + 1);
            point.push(4);
            point.extend_from_slice(public_key);
            UnparsedPublicKey::new(parameters, point)
                .verify(message, signature)
                .is_ok()
        }
        15 => UnparsedPublicKey::new(&ED25519, public_key)
            .verify(message, signature)
            .is_ok(),
        _ => false,
    }
}

/// The DS digest of `digest_type` over the owner (lowercase wire form) and the DNSKEY
/// record data (RFC 4034 section 5.1.4); `None` for an unsupported type.
pub fn ds_digest(digest_type: u8, owner_wire: &[u8], dnskey_rdata: &[u8]) -> Option<Vec<u8>> {
    let algorithm = match digest_type {
        1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        2 => &digest::SHA256,
        4 => &digest::SHA384,
        _ => return None,
    };
    let mut context = digest::Context::new(algorithm);
    context.update(owner_wire);
    context.update(dnskey_rdata);
    Some(context.finish().as_ref().to_vec())
}

/// Whether the DS record data `ds_rdata` (key tag, algorithm, digest type, digest) is the
/// DS of the DNSKEY record data `dnskey_rdata` at `owner_wire`: the tag, the algorithm and
/// the digest agree. An unsupported digest type never matches.
pub fn ds_matches(owner_wire: &[u8], dnskey_rdata: &[u8], ds_rdata: &[u8]) -> bool {
    let [tag_high, tag_low, algorithm, digest_type, digest @ ..] = ds_rdata else {
        return false;
    };
    if dnskey_rdata.get(3) != Some(algorithm)
        || key_tag(dnskey_rdata) != u16::from_be_bytes([*tag_high, *tag_low])
    {
        return false;
    }
    ds_digest(*digest_type, owner_wire, dnskey_rdata).is_some_and(|computed| computed == digest)
}
// WP10.2: end.

/// The DNSKEY flags of a key role.
pub fn flags_of(role: KeyRole) -> u16 {
    match role {
        KeyRole::Zsk => FLAGS_ZSK,
        KeyRole::Ksk | KeyRole::Csk => FLAGS_KSK,
    }
}

/// The DNSKEY record of a public key.
pub fn dnskey(role: KeyRole, algorithm: DnssecAlgorithm, public_key: &[u8]) -> RecordData {
    RecordData::Dnskey {
        flags: flags_of(role),
        protocol: PROTOCOL,
        algorithm: algorithm.number(),
        public_key: HexBytes(public_key.to_vec()),
    }
}

/// The wire form of DNSKEY record data.
pub fn dnskey_wire(role: KeyRole, algorithm: DnssecAlgorithm, public_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + public_key.len());
    out.extend_from_slice(&flags_of(role).to_be_bytes());
    out.push(PROTOCOL);
    out.push(algorithm.number());
    out.extend_from_slice(public_key);
    out
}

/// The key tag of DNSKEY record data (RFC 4034, appendix B; algorithm 1 is not used).
pub fn key_tag(dnskey_rdata: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for (index, &byte) in dnskey_rdata.iter().enumerate() {
        sum += if index % 2 == 0 {
            u32::from(byte) << 8
        } else {
            u32::from(byte)
        };
    }
    sum += (sum >> 16) & 0xffff;
    u16::try_from(sum & 0xffff).unwrap_or_default()
}

/// The DS record of a key (RFC 4034, section 5.1.4): SHA-256 over the owner's wire form
/// and the DNSKEY record data.
pub fn ds(
    owner: &DnsName,
    role: KeyRole,
    algorithm: DnssecAlgorithm,
    public_key: &[u8],
) -> RecordData {
    let rdata = dnskey_wire(role, algorithm, public_key);
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(&owner.to_wire());
    context.update(&rdata);
    RecordData::Ds {
        key_tag: key_tag(&rdata),
        algorithm: algorithm.number(),
        digest_type: DIGEST_SHA256,
        digest: HexBytes(context.finish().as_ref().to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_sign_and_verify_with_their_dnskey() {
        for algorithm in [DnssecAlgorithm::EcdsaP256Sha256, DnssecAlgorithm::Ed25519] {
            let (pair, der) = KeyPair::generate(algorithm).expect("key");
            let again = KeyPair::from_pkcs8(algorithm, &der).expect("load");
            assert_eq!(pair.public_key(), again.public_key());
            let expected = match algorithm {
                DnssecAlgorithm::EcdsaP256Sha256 => 64,
                DnssecAlgorithm::Ed25519 => 32,
            };
            assert_eq!(pair.public_key().len(), expected);
            let signature = again.sign(b"zone data").expect("sign");
            assert_eq!(signature.len(), 64);
            assert!(verify(
                algorithm.number(),
                &pair.public_key(),
                b"zone data",
                &signature
            ));
            assert!(!verify(
                algorithm.number(),
                &pair.public_key(),
                b"other data",
                &signature
            ));
            assert!(KeyPair::from_pkcs8(other(algorithm), &der).is_err());
        }
        assert!(!verify(8, &[1, 2, 3], b"x", b"y"));
    }

    fn other(algorithm: DnssecAlgorithm) -> DnssecAlgorithm {
        match algorithm {
            DnssecAlgorithm::EcdsaP256Sha256 => DnssecAlgorithm::Ed25519,
            DnssecAlgorithm::Ed25519 => DnssecAlgorithm::EcdsaP256Sha256,
        }
    }
}
