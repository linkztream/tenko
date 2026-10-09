//! Secret references and the vault envelope marker (NEVER-01, IAM-15).
//!
//! Plaintext secrets never enter a write batch. A secret-bearing table (see
//! [`TableName::is_secret_bearing`](crate::names::TableName::is_secret_bearing)) accepts
//! only values that are a [`VaultEnvelope`]: the store checks the marker before a batch
//! enters the log. The vault (`tenko-vault`) defines what goes inside `payload` (the
//! wrapped data key, nonce and ciphertext); this crate only fixes the container so the
//! store can recognize it without depending on the vault.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    codec::cbor::{CodecError, from_cbor, to_cbor},
    id::SecretId,
};

/// CBOR tag number that marks a vault envelope (`"TKVE"`, from the first-come range).
pub const VAULT_ENVELOPE_TAG: u64 = 0x544B_5645;

/// The first five bytes of every encoded envelope: the CBOR head of
/// [`VAULT_ENVELOPE_TAG`] (major type 6 with a four-byte argument).
pub const VAULT_ENVELOPE_MARKER: [u8; 5] = [0xDA, 0x54, 0x4B, 0x56, 0x45];

/// An encrypted secret as stored. Opaque outside the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEnvelope {
    /// Envelope format version, chosen by the vault.
    pub format: u16,
    /// Identifier of the key-encryption key that wraps the data key.
    pub key_id: String,
    /// Wrapped data key, nonce and ciphertext, laid out by the vault.
    pub payload: Bytes,
}

impl VaultEnvelope {
    /// Encodes the envelope as tagged CBOR; the result starts with
    /// [`VAULT_ENVELOPE_MARKER`].
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if encoding fails.
    pub fn to_bytes(&self) -> Result<Bytes, CodecError> {
        to_cbor(&ciborium::tag::Required::<_, VAULT_ENVELOPE_TAG>(self))
    }

    /// Decodes an envelope.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if the bytes are not a tagged envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        if !Self::is_envelope(bytes) {
            return Err(CodecError::Decode("not a vault envelope".to_owned()));
        }
        from_cbor::<ciborium::tag::Required<VaultEnvelope, VAULT_ENVELOPE_TAG>>(bytes)
            .map(|tagged| tagged.0)
    }

    /// Whether a stored value carries the envelope marker. This is the check the store
    /// applies to secret-bearing tables.
    pub fn is_envelope(bytes: &[u8]) -> bool {
        bytes.starts_with(&VAULT_ENVELOPE_MARKER)
    }
}

/// A reference to a vault secret, resolved at call time (ADR 0006). Connectors and other
/// consumers store references, never secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct SecretRef {
    /// The secret.
    pub secret: SecretId,
}

/// Classes of secrets (Q3, accepted): system secrets are never revealable; operator
/// secrets are revealable with an audit record (IAM-16, Slice 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretClass {
    /// TOTP seeds, CA and TLS keys: used by Tenko, never shown.
    System,
    /// Connector credentials and other secrets an operator may reveal.
    Operator,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes_carry_the_marker_and_round_trip() {
        let envelope = VaultEnvelope {
            format: 1,
            key_id: "kek-1".to_owned(),
            payload: Bytes::from_static(&[1, 2, 3]),
        };
        let bytes = envelope.to_bytes().expect("encode");
        assert!(bytes.starts_with(&VAULT_ENVELOPE_MARKER));
        assert!(VaultEnvelope::is_envelope(&bytes));
        assert_eq!(VaultEnvelope::from_bytes(&bytes).expect("decode"), envelope);
    }

    #[test]
    fn plain_values_are_not_envelopes() {
        let plain = to_cbor(&"JBSWY3DPEHPK3PXP").expect("encode");
        assert!(!VaultEnvelope::is_envelope(&plain));
        assert!(VaultEnvelope::from_bytes(&plain).is_err());
        assert!(!VaultEnvelope::is_envelope(&[]));
    }
}
