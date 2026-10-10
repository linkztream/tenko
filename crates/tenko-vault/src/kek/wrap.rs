//! The wrap sealer: KEK generation files wrapped under a root key.
//!
//! The `file` and systemd credential providers hold their root key outside the data
//! directory (a mounted key file, a credential the service manager decrypts). Generations
//! made later (by a rotation, or received from another controller) cannot be sealed by the
//! operating system for the service account, so they are wrapped under the root key and
//! inherit its protection: whoever cannot read the root key cannot read them either.
//!
//! A file `kek-<generation>.wrap` holds
//!
//! ```text
//! nonce (12) | AES-256-GCM(root key, generation file, aad) | tag (16)
//! aad = "tenko-kek-wrap-v1:" | label (the file stem, for example kek-000002)
//! ```
//!
//! The label binds the file name, so a wrapped file renamed to another generation does not
//! unseal. New files are wrapped under the active root; unsealing tries the retired roots
//! too, so generations survive a change of the root key that keeps the old one listed as
//! retired.

use std::fmt;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use zeroize::Zeroizing;

use super::{KekProtection, KekProvider, KekSealer, local::TAG_LEN};
use crate::VaultError;

const AAD_PREFIX: &[u8] = b"tenko-kek-wrap-v1:";

/// Seals KEK generation files under one or more root keys (the active root first).
pub struct WrapSealer {
    roots: Vec<LessSafeKey>,
    protection: KekProtection,
}

impl fmt::Debug for WrapSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrapSealer")
            .field("roots", &self.roots.len())
            .field("protection", &self.protection)
            .finish()
    }
}

impl WrapSealer {
    /// A sealer over the material of `roots`, the active root first, giving the
    /// protection of the roots.
    ///
    /// # Errors
    ///
    /// [`VaultError::KekUnavailable`] when a root cannot export its key or there is none,
    /// [`VaultError::Crypto`] if a key is rejected.
    pub fn from_roots<'a>(
        protection: KekProtection,
        roots: impl IntoIterator<Item = &'a std::sync::Arc<dyn KekProvider>>,
    ) -> Result<Self, VaultError> {
        let mut keys = Vec::new();
        for root in roots {
            let material = root.export_material().ok_or_else(|| {
                VaultError::kek_unavailable(format!(
                    "the root key {} cannot wrap key generations",
                    root.id()
                ))
            })?;
            keys.push(key(&material)?);
        }
        if keys.is_empty() {
            return Err(VaultError::kek_unavailable("no root key"));
        }
        Ok(Self {
            roots: keys,
            protection,
        })
    }
}

fn key(material: &Zeroizing<[u8; 32]>) -> Result<LessSafeKey, VaultError> {
    UnboundKey::new(&AES_256_GCM, material.as_ref())
        .map(LessSafeKey::new)
        .map_err(|_| VaultError::Crypto {
            operation: "root key setup",
        })
}

fn aad(label: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + label.len());
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(label.as_bytes());
    aad
}

impl KekSealer for WrapSealer {
    fn name(&self) -> &'static str {
        "wrap"
    }

    fn protection(&self) -> KekProtection {
        self.protection
    }

    fn seal(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| VaultError::Crypto {
            operation: "random nonce",
        })?;
        let mut body = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_LEN));
        body.extend_from_slice(plaintext);
        self.roots[0]
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(label)),
                &mut *body,
            )
            .map_err(|_| VaultError::Crypto {
                operation: "wrap key generation",
            })?;
        let mut out = Vec::with_capacity(NONCE_LEN + body.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        Ok(out)
    }

    fn unseal(&self, label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let Some((nonce, body)) = sealed.split_at_checked(NONCE_LEN) else {
            return Err(VaultError::kek_unavailable(format!(
                "{label}.wrap is too short to be a wrapped key generation"
            )));
        };
        for root in &self.roots {
            let nonce =
                Nonce::try_assume_unique_for_key(nonce).map_err(|_| VaultError::Malformed {
                    what: "wrapped key generation",
                })?;
            let mut buffer = Zeroizing::new(body.to_vec());
            if let Ok(plain) =
                root.open_in_place(nonce, Aad::from(aad(label)), buffer.as_mut_slice())
            {
                let len = plain.len();
                buffer.truncate(len);
                return Ok(buffer);
            }
        }
        Err(VaultError::kek_unavailable(format!(
            "{label}.wrap does not open under the configured root key: it was wrapped under \
             another key, renamed, or damaged"
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::kek::MemKek;

    fn root(id: &str) -> Arc<dyn KekProvider> {
        Arc::new(MemKek::generate(id))
    }

    #[test]
    fn wraps_round_trip_and_bind_the_label() {
        let roots = [root("root-1")];
        let wrap = WrapSealer::from_roots(KekProtection::PlainFile, roots.iter()).expect("sealer");
        let blob = wrap.seal("kek-000002", b"generation").expect("seal");
        assert!(!blob.windows(10).any(|w| w == b"generation"));
        let opened = wrap.unseal("kek-000002", &blob).expect("unseal");
        assert_eq!(opened.as_slice(), b"generation");
        assert!(wrap.unseal("kek-000003", &blob).is_err());
        assert!(wrap.unseal("kek-000002", &blob[..5]).is_err());
        assert_eq!(wrap.name(), "wrap");
        assert!(!format!("{wrap:?}").contains("generation"));
    }

    #[test]
    fn retired_roots_still_unseal() {
        let old = root("root-1");
        let new = root("root-2");
        let before = WrapSealer::from_roots(KekProtection::PlainFile, [&old]).expect("sealer");
        let sealed = before.seal("kek-000002", b"generation").expect("seal");
        let after = WrapSealer::from_roots(KekProtection::PlainFile, [&new, &old]).expect("sealer");
        assert_eq!(
            after
                .unseal("kek-000002", &sealed)
                .expect("unseal")
                .as_slice(),
            b"generation"
        );
        let without = WrapSealer::from_roots(KekProtection::PlainFile, [&new]).expect("sealer");
        assert!(matches!(
            without.unseal("kek-000002", &sealed),
            Err(VaultError::KekUnavailable { .. })
        ));
    }
}
