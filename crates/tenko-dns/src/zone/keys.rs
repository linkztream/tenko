//! TSIG keys (RFC 8945, DNS-11, TGL-09): the metadata in `dns.keys.meta`, the secret in
//! the vault.
//!
//! A key is generated with the length of its algorithm's hash, or imported from base64
//! (16 to 1,024 octets). The secret is a system secret of the vault (purpose `dns.tsig`,
//! owned by the key): Tenko uses it to sign and verify and never shows it again after the
//! answer that created the key. In Phase 5 a `dns` node receives it through node sync
//! under the role purpose `tsig` (`tenko_core::dns::TSIG_PURPOSE`).
//!
//! The batch of a key holds the vault envelope, so it is proposed directly with its audit
//! record (`dns.key.create`, `dns.key.delete`) instead of through an inline job, whose
//! record would keep a copy of the envelope after the key is deleted; the operator secrets
//! of the vault are written the same way. A KEK rotation that starts between staging and
//! proposing makes the batch stale, and the key is staged again.

use std::sync::Arc;

use tenko_core::{
    ObjectRef, RequestCtx, Revision,
    audit::AuditDraft,
    dns::{DnsKeyId, KeyMeta, KeyName, TsigAlgorithm, audit, codes, tables::KEYS_META},
    error::codes as sys,
    ipam::Stamp,
    secret::SecretClass,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, StoreError, WriteBatch};
use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec, Vault};
use zeroize::Zeroizing;

use super::{ZoneError, ZoneResult, ZoneService};

/// The vault purpose of TSIG secrets.
pub const VAULT_PURPOSE: &str = "dns.tsig";

/// Attempts of a key write that a KEK rotation made stale.
const ATTEMPTS: u32 = 4;

/// A new key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewKey {
    /// The key name, as the peers know it.
    pub name: KeyName,
    /// The algorithm.
    pub algorithm: TsigAlgorithm,
    /// The secret in base64 to import; generated when absent.
    pub secret: Option<String>,
    /// Free text.
    pub description: Option<String>,
}

/// A created key and its secret, shown this once.
pub struct CreatedKey {
    /// The metadata.
    pub key: KeyMeta,
    /// The secret in base64.
    pub secret: Zeroizing<String>,
    /// The revision of the write.
    pub revision: Revision,
}

impl std::fmt::Debug for CreatedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedKey")
            .field("key", &self.key)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

/// The secret length of an algorithm: the length of its hash output.
pub const fn secret_len(algorithm: TsigAlgorithm) -> usize {
    match algorithm {
        TsigAlgorithm::HmacSha256 => 32,
        TsigAlgorithm::HmacSha384 => 48,
        TsigAlgorithm::HmacSha512 => 64,
        TsigAlgorithm::HmacSha1 => 20,
    }
}

fn not_found(name: &KeyName) -> ZoneError {
    ZoneError::new(
        codes::KEY_NOT_FOUND,
        404,
        format!("TSIG key {name} does not exist"),
    )
    .param("name", name.as_str())
}

fn invalid(field: &str, reason: &str) -> ZoneError {
    ZoneError::new(sys::INVALID_VALUE, 400, format!("{field}: {reason}"))
        .param("field", field)
        .param("reason", reason)
}

impl ZoneService {
    fn vault(&self) -> ZoneResult<&Arc<dyn Vault>> {
        self.vault.as_ref().ok_or_else(|| {
            ZoneError::new(
                "vault.unavailable",
                503,
                "TSIG keys need the vault, which this server does not run",
            )
        })
    }

    /// Every key, by name.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn keys(view: &dyn ReadView) -> ZoneResult<Vec<(KeyMeta, Revision)>> {
        Ok(view
            .scan_typed(&KEYS_META, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, key, revision)| (key, revision))
            .collect())
    }

    /// One key.
    ///
    /// # Errors
    ///
    /// `dns.key.not_found`, or the store's error.
    pub fn key(view: &dyn ReadView, name: &KeyName) -> ZoneResult<(KeyMeta, Revision)> {
        view.get_typed(&KEYS_META, name)?
            .ok_or_else(|| not_found(name))
    }

    /// Generates or imports a key.
    ///
    /// # Errors
    ///
    /// `sys.invalid_value` for a bad secret or name, `dns.key.exists`, 503 without a vault,
    /// or a vault or store error.
    pub async fn create_key(&self, cx: &RequestCtx, new: NewKey) -> ZoneResult<CreatedKey> {
        if new.name.is_root() || new.name.is_wildcard() {
            return Err(invalid(
                "name",
                "a key name is a DNS name of one or more labels",
            ));
        }
        let secret = if let Some(text) = &new.secret {
            let bytes: Vec<u8> = domain::utils::base64::decode(text.trim())
                .map_err(|_| invalid("secret", "the secret is not base64"))?;
            if !(16..=1024).contains(&bytes.len()) {
                return Err(invalid("secret", "a secret is 16 to 1024 octets"));
            }
            SecretBytes::new(bytes)
        } else {
            let mut bytes = vec![0u8; secret_len(new.algorithm)];
            aws_lc_rs::rand::fill(&mut bytes)
                .map_err(|_| ZoneError::new(sys::INTERNAL, 500, "no random bytes for the key"))?;
            SecretBytes::new(bytes)
        };
        let vault = Arc::clone(self.vault()?);
        let id = DnsKeyId::generate();
        let description = new
            .description
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty());
        for attempt in 1..=ATTEMPTS {
            let view = self.view(None).await?;
            if view.get_typed(&KEYS_META, &new.name)?.is_some() {
                return Err(ZoneError::new(
                    codes::KEY_EXISTS,
                    409,
                    format!("a TSIG key {} exists", new.name),
                )
                .param("name", new.name.as_str()));
            }
            drop(view);
            let mut batch = WriteBatch::for_request(cx);
            batch.idempotency = None;
            let spec = SecretSpec::new(SecretPurpose::from_static(VAULT_PURPOSE))
                .owned_by(ObjectRef::from(id))
                .labelled(new.name.as_str());
            let secret_ref = vault.stage_put(&mut batch, cx, SecretClass::System, spec, &secret)?;
            let key = KeyMeta {
                id,
                name: new.name.clone(),
                algorithm: new.algorithm,
                secret: secret_ref,
                description: description.clone(),
                created: Stamp::new(cx.now, cx.principal.clone()),
            };
            batch.expect_typed(&KEYS_META, &key.name, None);
            batch.put_typed(&KEYS_META, &key.name, &key)?;
            batch.audit(
                AuditDraft::success(audit::KEY_CREATE, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", key.name.as_str())
                    .with_context("algorithm", key.algorithm.wire_name())
                    .with_context(
                        "origin",
                        if new.secret.is_some() {
                            "imported"
                        } else {
                            "generated"
                        },
                    ),
            );
            match self.store.propose(batch).await {
                Ok(committed) => {
                    return Ok(CreatedKey {
                        key,
                        secret: Zeroizing::new(domain::utils::base64::encode_string(
                            secret.expose(),
                        )),
                        revision: committed.revision,
                    });
                }
                Err(StoreError::PreconditionFailed(_)) if attempt < ATTEMPTS => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(ZoneError::new(
            "sys.store.precondition_failed",
            409,
            "the key could not be written",
        ))
    }

    /// Deletes a key and its secret.
    ///
    /// # Errors
    ///
    /// `dns.key.not_found`, 503 without a vault, or a store error.
    pub async fn delete_key(&self, cx: &RequestCtx, name: &KeyName) -> ZoneResult<Revision> {
        let vault = Arc::clone(self.vault()?);
        for attempt in 1..=ATTEMPTS {
            let view = self.view(None).await?;
            let (key, revision) = Self::key(view.as_ref(), name)?;
            drop(view);
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&KEYS_META, name, Some(revision));
            batch.delete_typed(&KEYS_META, name);
            vault.stage_delete(&mut batch, cx, key.secret);
            batch.audit(
                AuditDraft::success(audit::KEY_DELETE, vec![ObjectRef::from(key.id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", name.as_str()),
            );
            match self.store.propose(batch).await {
                Ok(committed) => return Ok(committed.revision),
                Err(StoreError::PreconditionFailed(_)) if attempt < ATTEMPTS => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(ZoneError::new(
            "sys.store.precondition_failed",
            409,
            "the key could not be deleted",
        ))
    }
}
