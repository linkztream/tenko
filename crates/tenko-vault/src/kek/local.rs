//! A KEK held in process memory, wrapping with AES-256-GCM.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use zeroize::Zeroizing;

use super::{DataKey, KekProtection, KekProvider};
use crate::VaultError;

/// Length of an AES-GCM tag.
pub(crate) const TAG_LEN: usize = 16;

/// Length of a key wrapped by a [`LocalKek`]: nonce, wrapped key and tag.
pub(crate) const WRAPPED_LEN: usize = NONCE_LEN + DataKey::LEN + TAG_LEN;

/// A 256-bit KEK in memory that wraps data keys with AES-256-GCM under a random 96-bit
/// nonce: `nonce (12) || ciphertext (32) || tag (16)`. Every built-in provider loads its
/// key into one of these.
pub struct LocalKek {
    id: String,
    protection: KekProtection,
    key: LessSafeKey,
    /// The key bytes, kept for the sealed transfer to another controller only.
    material: Zeroizing<[u8; DataKey::LEN]>,
}

impl LocalKek {
    /// Builds a KEK from key bytes. The caller zeroizes its copy (pass a `Zeroizing`).
    ///
    /// # Errors
    ///
    /// [`VaultError::Crypto`] if the key is rejected.
    pub fn new(
        id: impl Into<String>,
        protection: KekProtection,
        key: &Zeroizing<[u8; DataKey::LEN]>,
    ) -> Result<Self, VaultError> {
        let unbound =
            UnboundKey::new(&AES_256_GCM, key.as_ref()).map_err(|_| VaultError::Crypto {
                operation: "KEK setup",
            })?;
        Ok(Self {
            id: id.into(),
            protection,
            key: LessSafeKey::new(unbound),
            material: key.clone(),
        })
    }
}

impl std::fmt::Debug for LocalKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKek")
            .field("id", &self.id)
            .field("protection", &self.protection)
            .finish_non_exhaustive()
    }
}

impl KekProvider for LocalKek {
    fn id(&self) -> &str {
        &self.id
    }

    fn protection(&self) -> KekProtection {
        self.protection
    }

    fn wrap(&self, dek: &DataKey, aad: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| VaultError::Crypto {
            operation: "random nonce",
        })?;
        // Sized for the tag so sealing never reallocates and leaves no stray copy of the
        // plaintext key behind; the buffer is zeroized on drop either way.
        let mut body = Zeroizing::new(Vec::with_capacity(DataKey::LEN + TAG_LEN));
        body.extend_from_slice(dek.as_bytes());
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut *body,
            )
            .map_err(|_| VaultError::Crypto {
                operation: "wrap data key",
            })?;
        let mut out = Vec::with_capacity(WRAPPED_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        Ok(out)
    }

    fn export_material(&self) -> Option<Zeroizing<[u8; DataKey::LEN]>> {
        Some(self.material.clone())
    }

    fn unwrap(&self, wrapped: &[u8], aad: &[u8]) -> Result<DataKey, VaultError> {
        if wrapped.len() != WRAPPED_LEN {
            return Err(VaultError::Malformed {
                what: "wrapped data key",
            });
        }
        let (nonce, body) = wrapped.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| VaultError::Malformed {
            what: "wrapped data key",
        })?;
        let mut buffer = Zeroizing::new(body.to_vec());
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(aad), buffer.as_mut_slice())
            .map_err(|_| VaultError::Integrity)?;
        let mut key = Zeroizing::new([0u8; DataKey::LEN]);
        if plain.len() != DataKey::LEN {
            return Err(VaultError::Malformed {
                what: "wrapped data key",
            });
        }
        key.copy_from_slice(plain);
        Ok(DataKey::from_bytes(key))
    }
}

/// A KEK that lives only in memory, for tests (feature `testing`).
#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub struct MemKek(LocalKek);

#[cfg(any(test, feature = "testing"))]
impl MemKek {
    /// A random KEK with the given identifier.
    ///
    /// # Panics
    ///
    /// Panics if the random number generator fails (tests only).
    pub fn generate(id: &str) -> Self {
        let mut key = Zeroizing::new([0u8; DataKey::LEN]);
        aws_lc_rs::rand::fill(key.as_mut()).expect("random KEK");
        Self::from_bytes(id, &key)
    }

    /// A KEK with fixed bytes.
    ///
    /// # Panics
    ///
    /// Panics if the key is rejected (it never is for 32 bytes).
    pub fn from_bytes(id: &str, key: &Zeroizing<[u8; DataKey::LEN]>) -> Self {
        Self(LocalKek::new(id, KekProtection::Memory, key).expect("AES-256 key"))
    }
}

#[cfg(any(test, feature = "testing"))]
impl KekProvider for MemKek {
    fn id(&self) -> &str {
        self.0.id()
    }

    fn protection(&self) -> KekProtection {
        self.0.protection()
    }

    fn wrap(&self, dek: &DataKey, aad: &[u8]) -> Result<Vec<u8>, VaultError> {
        self.0.wrap(dek, aad)
    }

    fn unwrap(&self, wrapped: &[u8], aad: &[u8]) -> Result<DataKey, VaultError> {
        self.0.unwrap(wrapped, aad)
    }

    fn export_material(&self) -> Option<Zeroizing<[u8; DataKey::LEN]>> {
        self.0.export_material()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_round_trips_and_binds_aad() {
        let kek = MemKek::generate("mem-1");
        let dek = DataKey::generate().expect("dek");
        let wrapped = kek.wrap(&dek, b"row-a").expect("wrap");
        assert_eq!(wrapped.len(), WRAPPED_LEN);
        let back = kek.unwrap(&wrapped, b"row-a").expect("unwrap");
        assert_eq!(back.as_bytes(), dek.as_bytes());
        assert_eq!(
            kek.unwrap(&wrapped, b"row-b").expect_err("aad"),
            VaultError::Integrity
        );
        let other = MemKek::generate("mem-1");
        assert_eq!(
            other.unwrap(&wrapped, b"row-a").expect_err("key"),
            VaultError::Integrity
        );
    }

    #[test]
    fn wraps_use_fresh_nonces() {
        let kek = MemKek::generate("mem-1");
        let dek = DataKey::generate().expect("dek");
        assert_ne!(
            kek.wrap(&dek, b"x").expect("wrap"),
            kek.wrap(&dek, b"x").expect("wrap")
        );
    }

    #[test]
    fn tampered_wraps_fail() {
        let kek = MemKek::generate("mem-1");
        let dek = DataKey::generate().expect("dek");
        let mut wrapped = kek.wrap(&dek, b"x").expect("wrap");
        wrapped[20] ^= 1;
        assert_eq!(
            kek.unwrap(&wrapped, b"x").expect_err("tamper"),
            VaultError::Integrity
        );
        assert!(matches!(
            kek.unwrap(&wrapped[..10], b"x"),
            Err(VaultError::Malformed { .. })
        ));
    }
}
