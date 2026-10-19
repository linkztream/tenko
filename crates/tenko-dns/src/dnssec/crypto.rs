//! The signing algorithms over `aws-lc-rs` (P2-Q4): ECDSA P-256 with SHA-256 (algorithm
//! 13, RFC 6605) and Ed25519 (algorithm 15, RFC 8080), the DNSKEY record of a key, its key
//! tag (RFC 4034, appendix B) and the DS digest with SHA-256 (digest type 2, RFC 4509).
//!
//! A private key is kept as PKCS#8 in the vault and loaded into a [`KeyPair`] when the
//! signer needs it. ECDSA signatures are the fixed 64-octet form `r || s` that RFC 6605
//! puts in the RRSIG; the DNSKEY holds the public point without its leading 0x04.

use aws_lc_rs::{
    digest,
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ED25519, EcdsaKeyPair,
        Ed25519KeyPair, KeyPair as _, UnparsedPublicKey,
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

/// Whether `signature` over `message` verifies with the DNSKEY public key `public_key` of
/// algorithm `number`. Unknown algorithms never verify.
pub fn verify(number: u8, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match algorithm_of(number) {
        Some(DnssecAlgorithm::EcdsaP256Sha256) => {
            let mut point = Vec::with_capacity(public_key.len() + 1);
            point.push(4);
            point.extend_from_slice(public_key);
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                .verify(message, signature)
                .is_ok()
        }
        Some(DnssecAlgorithm::Ed25519) => UnparsedPublicKey::new(&ED25519, public_key)
            .verify(message, signature)
            .is_ok(),
        None => false,
    }
}

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
