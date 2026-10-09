//! The envelope payload (format 1) and the additional authenticated data (AAD).
//!
//! A stored secret is a [`VaultEnvelope`] (tagged CBOR, see `tenko_core::secret`) with
//! `format = 1`, `key_id` = the identifier of the KEK that wrapped the data key, and this
//! payload (integers big-endian):
//!
//! ```text
//! offset  size  field
//! 0       1     class: 1 = system, 2 = operator
//! 1       4     DEK generation (1 on creation, +1 per DEK rotation or replacement)
//! 5       2     W = length of the wrapped DEK
//! 7       W     wrapped DEK, as the KEK provider returned it (built-in providers:
//!               nonce 12 || AES-256-GCM(DEK) 32 || tag 16)
//! 7+W     12    data nonce (random)
//! 19+W    rest  AES-256-GCM(value) || tag 16
//! ```
//!
//! The value is encrypted under the DEK with the *data AAD*, and the DEK is wrapped under
//! the KEK with the *wrap AAD*:
//!
//! ```text
//! data AAD = "tenko-vault-data\0" | format u16 | class u8 | DEK generation u32
//!            | table length u16 | table | key length u32 | key
//! wrap AAD = "tenko-vault-dek\0"  | format u16 | class u8 | DEK generation u32
//!            | KEK id length u16 | KEK id | table length u16 | table | key length u32 | key
//! ```
//!
//! Both bind the row (table name and encoded key) and the class, so an envelope copied to
//! another row, or relabelled from system to operator to make it revealable, fails
//! authentication. The data AAD leaves out the KEK identifier, so KEK rotation re-wraps
//! the DEK without touching the ciphertext.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use bytes::Bytes;
use tenko_core::{TableName, secret::SecretClass, secret::VaultEnvelope};
use zeroize::Zeroizing;

use crate::{
    MAX_SECRET_LEN, SecretBytes, VaultError,
    kek::{DataKey, KekProvider, KekRing},
};

/// The envelope format this module writes.
pub const FORMAT_V1: u16 = 1;

const DATA_AAD_LABEL: &[u8] = b"tenko-vault-data\0";
const WRAP_AAD_LABEL: &[u8] = b"tenko-vault-dek\0";
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 7;

/// The row an envelope belongs to: the table and the encoded key.
#[derive(Debug, Clone, Copy)]
pub struct RowBinding<'a> {
    /// The table.
    pub table: &'a TableName,
    /// The encoded key.
    pub key: &'a [u8],
}

/// What an envelope says about itself without decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeInfo {
    /// The format.
    pub format: u16,
    /// The KEK that wraps the data key.
    pub key_id: String,
    /// The class (authenticated only on decryption).
    pub class: SecretClass,
    /// The DEK generation.
    pub dek_generation: u32,
}

/// A decrypted envelope.
#[derive(Debug)]
pub struct Opened {
    /// The class.
    pub class: SecretClass,
    /// The DEK generation.
    pub dek_generation: u32,
    /// The plaintext.
    pub value: SecretBytes,
}

struct Payload<'a> {
    class: SecretClass,
    dek_generation: u32,
    wrapped_dek: &'a [u8],
    nonce: [u8; NONCE_LEN],
    ciphertext: &'a [u8],
}

/// Encrypts `value` under a fresh DEK wrapped by `kek`.
///
/// # Errors
///
/// [`VaultError::TooLarge`], [`VaultError::Crypto`] or the KEK provider's error.
pub fn seal(
    kek: &dyn KekProvider,
    row: RowBinding<'_>,
    class: SecretClass,
    dek_generation: u32,
    value: &[u8],
) -> Result<VaultEnvelope, VaultError> {
    if value.len() > MAX_SECRET_LEN {
        return Err(VaultError::TooLarge {
            size: value.len(),
            limit: MAX_SECRET_LEN,
        });
    }
    let dek = DataKey::generate()?;
    let mut nonce = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| VaultError::Crypto {
        operation: "random nonce",
    })?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(value.len() + TAG_LEN));
    buffer.extend_from_slice(value);
    data_key(&dek)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(data_aad(row, class, dek_generation)),
            &mut *buffer,
        )
        .map_err(|_| VaultError::Crypto {
            operation: "encrypt secret",
        })?;
    let wrapped_dek = kek.wrap(&dek, &wrap_aad(row, class, dek_generation, kek.id()))?;
    let payload = Payload {
        class,
        dek_generation,
        wrapped_dek: &wrapped_dek,
        nonce,
        ciphertext: &buffer,
    };
    Ok(VaultEnvelope {
        format: FORMAT_V1,
        key_id: kek.id().to_owned(),
        payload: payload.encode()?,
    })
}

/// Decrypts an envelope stored at `row`.
///
/// # Errors
///
/// [`VaultError::UnknownKek`] when the ring lacks the envelope's KEK,
/// [`VaultError::Integrity`] when any authenticated part was altered or the envelope was
/// moved, [`VaultError::UnsupportedFormat`] or [`VaultError::Malformed`].
pub fn open(
    ring: &KekRing,
    row: RowBinding<'_>,
    envelope: &VaultEnvelope,
) -> Result<Opened, VaultError> {
    let payload = Payload::decode(envelope)?;
    let dek = unwrap_dek(ring, row, envelope, &payload)?;
    let mut buffer = Zeroizing::new(payload.ciphertext.to_vec());
    let plain_len = data_key(&dek)?
        .open_in_place(
            Nonce::assume_unique_for_key(payload.nonce),
            Aad::from(data_aad(row, payload.class, payload.dek_generation)),
            buffer.as_mut_slice(),
        )
        .map_err(|_| VaultError::Integrity)?
        .len();
    buffer.truncate(plain_len);
    Ok(Opened {
        class: payload.class,
        dek_generation: payload.dek_generation,
        value: SecretBytes::from(buffer),
    })
}

/// Checks that the ring can unwrap the envelope's data key (start-up check), without
/// decrypting the value.
///
/// # Errors
///
/// As [`open`].
pub fn verify_kek(
    ring: &KekRing,
    row: RowBinding<'_>,
    envelope: &VaultEnvelope,
) -> Result<(), VaultError> {
    let payload = Payload::decode(envelope)?;
    unwrap_dek(ring, row, envelope, &payload).map(drop)
}

/// Re-wraps the data key under the ring's active KEK, keeping nonce and ciphertext.
/// Returns `None` when the envelope already uses the active KEK.
///
/// # Errors
///
/// As [`open`], plus the active KEK's wrap error.
pub fn rewrap(
    ring: &KekRing,
    row: RowBinding<'_>,
    envelope: &VaultEnvelope,
) -> Result<Option<VaultEnvelope>, VaultError> {
    let active = ring.active();
    if envelope.key_id == active.id() {
        return Ok(None);
    }
    let payload = Payload::decode(envelope)?;
    let dek = unwrap_dek(ring, row, envelope, &payload)?;
    let wrapped_dek = active.wrap(
        &dek,
        &wrap_aad(row, payload.class, payload.dek_generation, active.id()),
    )?;
    let payload = Payload {
        wrapped_dek: &wrapped_dek,
        ..payload
    };
    Ok(Some(VaultEnvelope {
        format: FORMAT_V1,
        key_id: active.id().to_owned(),
        payload: payload.encode()?,
    }))
}

/// Reads the unauthenticated header of an envelope.
///
/// # Errors
///
/// [`VaultError::UnsupportedFormat`] or [`VaultError::Malformed`].
pub fn inspect(envelope: &VaultEnvelope) -> Result<EnvelopeInfo, VaultError> {
    let payload = Payload::decode(envelope)?;
    Ok(EnvelopeInfo {
        format: envelope.format,
        key_id: envelope.key_id.clone(),
        class: payload.class,
        dek_generation: payload.dek_generation,
    })
}

fn unwrap_dek(
    ring: &KekRing,
    row: RowBinding<'_>,
    envelope: &VaultEnvelope,
    payload: &Payload<'_>,
) -> Result<DataKey, VaultError> {
    let kek = ring
        .get(&envelope.key_id)
        .ok_or_else(|| VaultError::UnknownKek {
            key_id: envelope.key_id.clone(),
        })?;
    kek.unwrap(
        payload.wrapped_dek,
        &wrap_aad(row, payload.class, payload.dek_generation, kek.id()),
    )
}

fn data_key(dek: &DataKey) -> Result<LessSafeKey, VaultError> {
    UnboundKey::new(&AES_256_GCM, dek.as_bytes())
        .map(LessSafeKey::new)
        .map_err(|_| VaultError::Crypto {
            operation: "data key setup",
        })
}

const fn class_code(class: SecretClass) -> u8 {
    match class {
        SecretClass::System => 1,
        SecretClass::Operator => 2,
    }
}

fn data_aad(row: RowBinding<'_>, class: SecretClass, dek_generation: u32) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(DATA_AAD_LABEL.len() + 13 + row.table.as_str().len() + row.key.len());
    aad.extend_from_slice(DATA_AAD_LABEL);
    common_aad(&mut aad, class, dek_generation);
    row_aad(&mut aad, row);
    aad
}

fn wrap_aad(row: RowBinding<'_>, class: SecretClass, dek_generation: u32, kek_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        WRAP_AAD_LABEL.len() + 15 + kek_id.len() + row.table.as_str().len() + row.key.len(),
    );
    aad.extend_from_slice(WRAP_AAD_LABEL);
    common_aad(&mut aad, class, dek_generation);
    // Identifiers and table names are short (KEK ids are built by this crate, table
    // names are at most 128 bytes); saturating keeps the encoding total.
    aad.extend_from_slice(
        &u16::try_from(kek_id.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    aad.extend_from_slice(kek_id.as_bytes());
    row_aad(&mut aad, row);
    aad
}

fn common_aad(aad: &mut Vec<u8>, class: SecretClass, dek_generation: u32) {
    aad.extend_from_slice(&FORMAT_V1.to_be_bytes());
    aad.push(class_code(class));
    aad.extend_from_slice(&dek_generation.to_be_bytes());
}

fn row_aad(aad: &mut Vec<u8>, row: RowBinding<'_>) {
    let table = row.table.as_str().as_bytes();
    aad.extend_from_slice(&u16::try_from(table.len()).unwrap_or(u16::MAX).to_be_bytes());
    aad.extend_from_slice(table);
    aad.extend_from_slice(
        &u32::try_from(row.key.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    aad.extend_from_slice(row.key);
}

impl<'a> Payload<'a> {
    fn encode(&self) -> Result<Bytes, VaultError> {
        let wrapped_len =
            u16::try_from(self.wrapped_dek.len()).map_err(|_| VaultError::Malformed {
                what: "wrapped data key",
            })?;
        let mut out = Vec::with_capacity(
            HEADER_LEN + self.wrapped_dek.len() + NONCE_LEN + self.ciphertext.len(),
        );
        out.push(class_code(self.class));
        out.extend_from_slice(&self.dek_generation.to_be_bytes());
        out.extend_from_slice(&wrapped_len.to_be_bytes());
        out.extend_from_slice(self.wrapped_dek);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(self.ciphertext);
        Ok(Bytes::from(out))
    }

    fn decode(envelope: &'a VaultEnvelope) -> Result<Self, VaultError> {
        const MALFORMED: VaultError = VaultError::Malformed { what: "envelope" };
        if envelope.format != FORMAT_V1 {
            return Err(VaultError::UnsupportedFormat {
                format: envelope.format,
            });
        }
        let bytes = envelope.payload.as_ref();
        let (&class, rest) = bytes.split_first().ok_or(MALFORMED)?;
        let class = match class {
            1 => SecretClass::System,
            2 => SecretClass::Operator,
            _ => return Err(MALFORMED),
        };
        let (generation, rest) = rest.split_first_chunk::<4>().ok_or(MALFORMED)?;
        let (wrapped_len, rest) = rest.split_first_chunk::<2>().ok_or(MALFORMED)?;
        let (wrapped_dek, rest) = rest
            .split_at_checked(usize::from(u16::from_be_bytes(*wrapped_len)))
            .ok_or(MALFORMED)?;
        let (nonce, ciphertext) = rest.split_first_chunk::<NONCE_LEN>().ok_or(MALFORMED)?;
        if ciphertext.len() < TAG_LEN {
            return Err(MALFORMED);
        }
        Ok(Self {
            class,
            dek_generation: u32::from_be_bytes(*generation),
            wrapped_dek,
            nonce: *nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::kek::MemKek;

    static TABLE: TableName = TableName::from_static("vault.secrets");
    static OTHER_TABLE: TableName = TableName::from_static("auth.totp_secrets");

    fn ring() -> KekRing {
        KekRing::new(Arc::new(MemKek::generate("mem-1")))
    }

    fn row(key: &[u8]) -> RowBinding<'_> {
        RowBinding { table: &TABLE, key }
    }

    #[test]
    fn round_trip() {
        let ring = ring();
        let envelope = seal(
            ring.active().as_ref(),
            row(b"k1"),
            SecretClass::System,
            1,
            b"top secret",
        )
        .expect("seal");
        assert_eq!(envelope.format, FORMAT_V1);
        assert_eq!(envelope.key_id, "mem-1");
        let opened = open(&ring, row(b"k1"), &envelope).expect("open");
        assert_eq!(opened.value.expose(), b"top secret");
        assert_eq!(opened.class, SecretClass::System);
        assert_eq!(opened.dek_generation, 1);
        let info = inspect(&envelope).expect("inspect");
        assert_eq!(info.class, SecretClass::System);
        assert_eq!(info.key_id, "mem-1");
        // The stored form never contains the plaintext.
        let bytes = envelope.to_bytes().expect("bytes");
        assert!(!bytes.windows(10).any(|w| w == b"top secret"));
    }

    #[test]
    fn empty_values_round_trip_and_large_ones_are_refused() {
        let ring = ring();
        let envelope = seal(
            ring.active().as_ref(),
            row(b"k"),
            SecretClass::Operator,
            1,
            b"",
        )
        .expect("seal");
        assert!(
            open(&ring, row(b"k"), &envelope)
                .expect("open")
                .value
                .is_empty()
        );
        let big = vec![0u8; MAX_SECRET_LEN + 1];
        assert!(matches!(
            seal(
                ring.active().as_ref(),
                row(b"k"),
                SecretClass::Operator,
                1,
                &big
            ),
            Err(VaultError::TooLarge { .. })
        ));
    }

    #[test]
    fn every_byte_of_the_payload_is_authenticated() {
        let ring = ring();
        let envelope = seal(
            ring.active().as_ref(),
            row(b"k1"),
            SecretClass::Operator,
            1,
            b"value",
        )
        .expect("seal");
        for index in 0..envelope.payload.len() {
            let mut payload = envelope.payload.to_vec();
            payload[index] ^= 0x01;
            let tampered = VaultEnvelope {
                payload: Bytes::from(payload),
                ..envelope.clone()
            };
            assert!(
                open(&ring, row(b"k1"), &tampered).is_err(),
                "flipping payload byte {index} went unnoticed"
            );
        }
    }

    #[test]
    fn moving_an_envelope_fails() {
        let ring = ring();
        let envelope = seal(
            ring.active().as_ref(),
            row(b"k1"),
            SecretClass::System,
            1,
            b"value",
        )
        .expect("seal");
        assert_eq!(
            open(&ring, row(b"k2"), &envelope).expect_err("key"),
            VaultError::Integrity
        );
        let other = RowBinding {
            table: &OTHER_TABLE,
            key: b"k1",
        };
        assert_eq!(
            open(&ring, other, &envelope).expect_err("table"),
            VaultError::Integrity
        );
    }

    #[test]
    fn relabelling_the_class_fails() {
        let ring = ring();
        let envelope = seal(
            ring.active().as_ref(),
            row(b"k1"),
            SecretClass::System,
            1,
            b"value",
        )
        .expect("seal");
        let mut payload = envelope.payload.to_vec();
        payload[0] = class_code(SecretClass::Operator);
        let relabelled = VaultEnvelope {
            payload: Bytes::from(payload),
            ..envelope
        };
        assert_eq!(
            open(&ring, row(b"k1"), &relabelled).expect_err("class"),
            VaultError::Integrity
        );
    }

    #[test]
    fn unknown_kek_and_format_are_reported() {
        let ring = ring();
        let envelope = seal(
            ring.active().as_ref(),
            row(b"k1"),
            SecretClass::System,
            1,
            b"value",
        )
        .expect("seal");
        let foreign = KekRing::new(Arc::new(MemKek::generate("mem-9")));
        assert_eq!(
            open(&foreign, row(b"k1"), &envelope).expect_err("kek"),
            VaultError::UnknownKek {
                key_id: "mem-1".to_owned()
            }
        );
        // Same identifier, different key: the wrap does not authenticate.
        let impostor = KekRing::new(Arc::new(MemKek::generate("mem-1")));
        assert_eq!(
            open(&impostor, row(b"k1"), &envelope).expect_err("impostor"),
            VaultError::Integrity
        );
        let future = VaultEnvelope {
            format: 2,
            ..envelope.clone()
        };
        assert_eq!(
            open(&ring, row(b"k1"), &future).expect_err("format"),
            VaultError::UnsupportedFormat { format: 2 }
        );
        let renamed = VaultEnvelope {
            key_id: "mem-2".to_owned(),
            ..envelope
        };
        assert!(open(&ring, row(b"k1"), &renamed).is_err());
    }

    #[test]
    fn rewrap_moves_to_the_active_kek_and_keeps_the_ciphertext() {
        let old = ring();
        let envelope = seal(
            old.active().as_ref(),
            row(b"k1"),
            SecretClass::Operator,
            3,
            b"value",
        )
        .expect("seal");
        let new = old.rotated_to(Arc::new(MemKek::generate("mem-2")));
        let rewrapped = rewrap(&new, row(b"k1"), &envelope)
            .expect("rewrap")
            .expect("changed");
        assert_eq!(rewrapped.key_id, "mem-2");
        assert!(
            rewrap(&new, row(b"k1"), &rewrapped)
                .expect("noop")
                .is_none()
        );
        let tail = |e: &VaultEnvelope| e.payload[e.payload.len() - 21..].to_vec();
        assert_eq!(tail(&rewrapped), tail(&envelope));
        let only_new = KekRing::new(Arc::clone(new.active()));
        let opened = open(&only_new, row(b"k1"), &rewrapped).expect("open");
        assert_eq!(opened.value.expose(), b"value");
        assert_eq!(opened.dek_generation, 3);
        verify_kek(&only_new, row(b"k1"), &rewrapped).expect("verify");
        assert!(verify_kek(&only_new, row(b"k1"), &envelope).is_err());
    }

    #[test]
    fn truncated_payloads_are_malformed() {
        let ring = ring();
        let envelope = seal(
            ring.active().as_ref(),
            row(b"k1"),
            SecretClass::System,
            1,
            b"value",
        )
        .expect("seal");
        for len in 0..HEADER_LEN + 60 + NONCE_LEN + TAG_LEN {
            let cut = VaultEnvelope {
                payload: envelope.payload.slice(..len),
                ..envelope.clone()
            };
            assert!(open(&ring, row(b"k1"), &cut).is_err(), "length {len}");
        }
    }
}
