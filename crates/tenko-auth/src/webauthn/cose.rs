//! COSE public keys (RFC 9052, RFC 9053) of the three supported algorithms, and signature
//! verification with `aws-lc-rs`.

use aws_lc_rs::signature::{self, ParsedPublicKey, RsaPublicKeyComponents};
use ciborium::Value;

use super::{
    WebAuthnError,
    types::{ALG_EDDSA, ALG_ES256, ALG_RS256},
};

const KTY: i128 = 1;
const ALG: i128 = 3;
const CRV_OR_N: i128 = -1;
const X_OR_E: i128 = -2;
const Y: i128 = -3;

const KTY_OKP: i128 = 1;
const KTY_EC2: i128 = 2;
const KTY_RSA: i128 = 3;
const CRV_P256: i128 = 1;
const CRV_ED25519: i128 = 6;

/// Smallest RSA modulus accepted, in bytes (2048 bits).
const RSA_MIN_BYTES: usize = 256;
/// Largest RSA modulus accepted, in bytes (8192 bits).
const RSA_MAX_BYTES: usize = 1024;

const MALFORMED: WebAuthnError = WebAuthnError::Malformed("credential public key");

/// A credential public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoseKey {
    /// ES256: an uncompressed P-256 point (`0x04 || x || y`).
    Es256 {
        /// The point.
        point: Vec<u8>,
    },
    /// `EdDSA` over Ed25519.
    Ed25519 {
        /// The 32-byte public key.
        x: Vec<u8>,
    },
    /// RS256.
    Rs256 {
        /// The modulus, big-endian.
        n: Vec<u8>,
        /// The public exponent, big-endian.
        e: Vec<u8>,
    },
}

impl CoseKey {
    /// Parses a COSE key from its CBOR encoding and checks that the key material is usable.
    ///
    /// # Errors
    ///
    /// [`WebAuthnError::UnsupportedAlgorithm`] for any algorithm other than ES256, `EdDSA` and
    /// RS256, [`WebAuthnError::Malformed`] for a key that does not decode or does not
    /// match its algorithm.
    pub fn parse(bytes: &[u8]) -> Result<Self, WebAuthnError> {
        let mut reader = bytes;
        let value: Value = ciborium::de::from_reader(&mut reader).map_err(|_| MALFORMED)?;
        if !reader.is_empty() {
            return Err(MALFORMED);
        }
        Self::from_value(&value)
    }

    /// Parses a COSE key from a decoded CBOR value.
    ///
    /// # Errors
    ///
    /// As [`CoseKey::parse`].
    pub fn from_value(value: &Value) -> Result<Self, WebAuthnError> {
        let Value::Map(entries) = value else {
            return Err(MALFORMED);
        };
        let mut seen = Vec::with_capacity(entries.len());
        for (key, _) in entries {
            let key = integer(key).ok_or(MALFORMED)?;
            if seen.contains(&key) {
                return Err(MALFORMED);
            }
            seen.push(key);
        }
        let get = |label: i128| {
            entries
                .iter()
                .find(|(key, _)| integer(key) == Some(label))
                .map(|(_, value)| value)
        };
        let kty = get(KTY).and_then(integer).ok_or(MALFORMED)?;
        let alg = get(ALG).and_then(integer).ok_or(MALFORMED)?;
        let bytes = |label: i128| -> Result<&Vec<u8>, WebAuthnError> {
            match get(label) {
                Some(Value::Bytes(bytes)) => Ok(bytes),
                _ => Err(MALFORMED),
            }
        };
        let key = match i64::try_from(alg).map_err(|_| MALFORMED)? {
            ALG_ES256 => {
                if kty != KTY_EC2 || get(CRV_OR_N).and_then(integer) != Some(CRV_P256) {
                    return Err(MALFORMED);
                }
                let (x, y) = (bytes(X_OR_E)?, bytes(Y)?);
                if x.len() != 32 || y.len() != 32 {
                    return Err(MALFORMED);
                }
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend_from_slice(x);
                point.extend_from_slice(y);
                CoseKey::Es256 { point }
            }
            ALG_EDDSA => {
                if kty != KTY_OKP || get(CRV_OR_N).and_then(integer) != Some(CRV_ED25519) {
                    return Err(MALFORMED);
                }
                let x = bytes(X_OR_E)?;
                if x.len() != 32 {
                    return Err(MALFORMED);
                }
                CoseKey::Ed25519 { x: x.clone() }
            }
            ALG_RS256 => {
                if kty != KTY_RSA {
                    return Err(MALFORMED);
                }
                let (n, e) = (bytes(CRV_OR_N)?, bytes(X_OR_E)?);
                if !(RSA_MIN_BYTES..=RSA_MAX_BYTES).contains(&n.len())
                    || n.first() == Some(&0)
                    || e.is_empty()
                    || e.len() > 8
                {
                    return Err(MALFORMED);
                }
                CoseKey::Rs256 {
                    n: n.clone(),
                    e: e.clone(),
                }
            }
            other => return Err(WebAuthnError::UnsupportedAlgorithm(other)),
        };
        key.check()?;
        Ok(key)
    }

    /// The COSE algorithm identifier.
    pub const fn alg(&self) -> i64 {
        match self {
            CoseKey::Es256 { .. } => ALG_ES256,
            CoseKey::Ed25519 { .. } => ALG_EDDSA,
            CoseKey::Rs256 { .. } => ALG_RS256,
        }
    }

    /// Checks that the key material is a valid key of its algorithm (a P-256 point on the
    /// curve, a valid Ed25519 key).
    fn check(&self) -> Result<(), WebAuthnError> {
        match self {
            CoseKey::Es256 { point } => {
                ParsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point)
                    .map(|_| ())
                    .map_err(|_| MALFORMED)
            }
            CoseKey::Ed25519 { x } => ParsedPublicKey::new(&signature::ED25519, x)
                .map(|_| ())
                .map_err(|_| MALFORMED),
            CoseKey::Rs256 { .. } => Ok(()),
        }
    }

    /// Verifies a WebAuthn signature: ECDSA signatures are ASN.1 DER encoded, as
    /// authenticators produce them.
    ///
    /// # Errors
    ///
    /// [`WebAuthnError::SignatureInvalid`].
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<(), WebAuthnError> {
        let result = match self {
            CoseKey::Es256 { point } => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point)
                    .verify(message, signature_bytes)
            }
            CoseKey::Ed25519 { x } => signature::UnparsedPublicKey::new(&signature::ED25519, x)
                .verify(message, signature_bytes),
            CoseKey::Rs256 { n, e } => RsaPublicKeyComponents {
                n: n.as_slice(),
                e: e.as_slice(),
            }
            .verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                message,
                signature_bytes,
            ),
        };
        result.map_err(|_| WebAuthnError::SignatureInvalid)
    }
}

fn integer(value: &Value) -> Option<i128> {
    match value {
        Value::Integer(integer) => Some(i128::from(*integer)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair};

    use super::*;

    fn encode(entries: Vec<(i64, Value)>) -> Vec<u8> {
        let map = Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (Value::Integer(key.into()), value))
                .collect(),
        );
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).expect("cbor");
        out
    }

    fn es256_key(pair: &EcdsaKeyPair) -> Vec<u8> {
        let point = pair.public_key().as_ref();
        encode(vec![
            (1, Value::Integer(2.into())),
            (3, Value::Integer((-7).into())),
            (-1, Value::Integer(1.into())),
            (-2, Value::Bytes(point[1..33].to_vec())),
            (-3, Value::Bytes(point[33..65].to_vec())),
        ])
    }

    #[test]
    fn es256_keys_verify_der_signatures() {
        let pair = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).expect("key");
        let key = CoseKey::parse(&es256_key(&pair)).expect("cose");
        assert_eq!(key.alg(), ALG_ES256);
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let sig = pair.sign(&rng, b"message").expect("sign");
        key.verify(b"message", sig.as_ref()).expect("verifies");
        assert_eq!(
            key.verify(b"other", sig.as_ref()),
            Err(WebAuthnError::SignatureInvalid)
        );
    }

    #[test]
    fn ed25519_keys_verify() {
        let pair = Ed25519KeyPair::generate().expect("key");
        let bytes = encode(vec![
            (1, Value::Integer(1.into())),
            (3, Value::Integer((-8).into())),
            (-1, Value::Integer(6.into())),
            (-2, Value::Bytes(pair.public_key().as_ref().to_vec())),
        ]);
        let key = CoseKey::parse(&bytes).expect("cose");
        let sig = pair.sign(b"message");
        key.verify(b"message", sig.as_ref()).expect("verifies");
        assert!(key.verify(b"message!", sig.as_ref()).is_err());
    }

    #[test]
    fn unsupported_and_inconsistent_keys_are_refused() {
        // ES384 (-35).
        let es384 = encode(vec![
            (1, Value::Integer(2.into())),
            (3, Value::Integer((-35).into())),
            (-1, Value::Integer(2.into())),
        ]);
        assert_eq!(
            CoseKey::parse(&es384),
            Err(WebAuthnError::UnsupportedAlgorithm(-35))
        );
        // ES256 with an Ed25519 curve.
        let mixed = encode(vec![
            (1, Value::Integer(2.into())),
            (3, Value::Integer((-7).into())),
            (-1, Value::Integer(6.into())),
            (-2, Value::Bytes(vec![1; 32])),
            (-3, Value::Bytes(vec![2; 32])),
        ]);
        assert!(CoseKey::parse(&mixed).is_err());
        // A point that is not on the curve.
        let off_curve = encode(vec![
            (1, Value::Integer(2.into())),
            (3, Value::Integer((-7).into())),
            (-1, Value::Integer(1.into())),
            (-2, Value::Bytes(vec![1; 32])),
            (-3, Value::Bytes(vec![2; 32])),
        ]);
        assert_eq!(CoseKey::parse(&off_curve), Err(MALFORMED));
        // A small RSA modulus.
        let small_rsa = encode(vec![
            (1, Value::Integer(3.into())),
            (3, Value::Integer((-257).into())),
            (-1, Value::Bytes(vec![0xc1; 128])),
            (-2, Value::Bytes(vec![1, 0, 1])),
        ]);
        assert_eq!(CoseKey::parse(&small_rsa), Err(MALFORMED));
        // Duplicate labels.
        let duplicate = encode(vec![
            (1, Value::Integer(1.into())),
            (1, Value::Integer(1.into())),
        ]);
        assert_eq!(CoseKey::parse(&duplicate), Err(MALFORMED));
        assert_eq!(CoseKey::parse(&[0xff]), Err(MALFORMED));
    }
}
