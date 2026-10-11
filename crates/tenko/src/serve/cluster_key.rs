//! The cluster key of an installation (`sys.cluster_key`, plan WP3.1b item 5).
//!
//! 32 random bytes, created once by the first controller that starts with this release and
//! kept as a system secret in the vault (an envelope under the installation's KEK, so it
//! replicates to every controller like any other secret and is never in the store in
//! plain). The record `sys.cluster_key` points at the secret. Every controller loads it at
//! start, after the vault opens, and derives purpose keys from it with HKDF-SHA-256 (salt
//! `tenko cluster key v1`): the key of the idempotency fingerprints (info
//! `idempotency fingerprint`), so a retried request that reaches another controller
//! replays the first answer, and the key that seals pending sign-in ceremonies into their
//! challenge ids (info `ceremony sealing`), so a ceremony started on one controller
//! finishes on another. The raw key stays in this module, zeroized on drop.
//!
//! Creation is race-free: the record is written with an "absent" precondition, so of two
//! controllers creating it at once one wins and the other reads the winner's key.

#![allow(
    clippy::result_large_err,
    reason = "the errors are the coded errors of the store and the vault, logged as they are"
)]

use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, RequestCtx, SystemComponent, Timestamp,
    secret::{SecretClass, SecretRef},
    table::TableDef,
};
use tenko_store::{ReadConsistency, ReadViewExt as _, Store, StoreError, WriteBatch};
use tenko_vault::{DataKey, SecretBytes, SecretPurpose, SecretSpec, Vault};

/// The record that names the secret of the cluster key.
pub const TABLE: TableDef<(), ClusterKeyRecord> = TableDef::new("sys.cluster_key");

/// The vault purpose of the cluster key.
pub const PURPOSE: SecretPurpose = SecretPurpose::from_static("sys.cluster_key");

/// How often creation is attempted when concurrent writes (another controller creating
/// the key, a KEK rotation) refuse the batch.
const ATTEMPTS: usize = 5;

/// The stored record of the cluster key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterKeyRecord {
    /// The system secret that holds the 32 bytes.
    pub secret: SecretRef,
    /// When it was created.
    pub created_at: Timestamp,
}

/// The cluster key in memory, zeroized on drop. `Debug` is redacted.
pub struct ClusterKey {
    /// Exactly [`DataKey::LEN`] bytes.
    material: SecretBytes,
}

impl std::fmt::Debug for ClusterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClusterKey(<redacted>)")
    }
}

impl ClusterKey {
    /// Reads the cluster key, or creates it when the installation has none yet. Returns the
    /// key and whether this call created it.
    ///
    /// # Errors
    ///
    /// The store's or the vault's error as a coded error: the store cannot be read or
    /// written (no quorum), the envelope does not open, or the secret is not 32 bytes.
    pub async fn load_or_create(
        store: &dyn Store,
        vault: &dyn Vault,
    ) -> Result<(Self, bool), CodedError> {
        let ctx = RequestCtx::system(SystemComponent::Cluster);
        let mut last = None;
        for _ in 0..ATTEMPTS {
            let view = store
                .read(ReadConsistency::Local)
                .await
                .map_err(|error| CodedError::from_coded(&error))?;
            let existing = view
                .get_typed(&TABLE, &())
                .map_err(|error| CodedError::from_coded(&error))?;
            drop(view);
            if let Some((record, _)) = existing {
                let secret = vault
                    .get_system(&ctx, record.secret)
                    .await
                    .map_err(|error| CodedError::from_coded(&error))?;
                return Ok((Self::from_secret(secret)?, false));
            }
            let key = DataKey::generate().map_err(|error| CodedError::from_coded(&error))?;
            let value = SecretBytes::new(key.as_bytes().to_vec());
            let mut batch = WriteBatch::for_request(&ctx);
            batch.expect_typed(&TABLE, &(), None);
            let secret = vault
                .stage_put(
                    &mut batch,
                    &ctx,
                    SecretClass::System,
                    SecretSpec::new(PURPOSE),
                    &value,
                )
                .map_err(|error| CodedError::from_coded(&error))?;
            batch
                .put_typed(
                    &TABLE,
                    &(),
                    &ClusterKeyRecord {
                        secret,
                        created_at: ctx.now,
                    },
                )
                .map_err(|error| CodedError::from_coded(&error))?;
            match store.propose(batch).await {
                Ok(_) => return Ok((Self { material: value }, true)),
                // Another controller created the key, or a KEK rotation started: read again.
                Err(error @ StoreError::PreconditionFailed(_)) => last = Some(error),
                Err(error) => return Err(CodedError::from_coded(&error)),
            }
        }
        Err(last.map_or_else(
            || CodedError::internal("the cluster key could not be created"),
            |error| CodedError::from_coded(&error),
        ))
    }

    fn from_secret(secret: SecretBytes) -> Result<Self, CodedError> {
        if secret.expose().len() != DataKey::LEN {
            return Err(CodedError::internal(
                "the cluster key in the vault does not have 32 bytes",
            ));
        }
        Ok(Self { material: secret })
    }

    /// The 32 bytes.
    fn bytes(&self) -> &[u8; DataKey::LEN] {
        self.material
            .expose()
            .try_into()
            .expect("checked when the key was loaded")
    }

    /// The key of the idempotency fingerprints of the API.
    pub fn fingerprint_key(&self) -> tenko_api::middleware::idempotency::FingerprintKey {
        tenko_api::middleware::idempotency::FingerprintKey::from_cluster_key(self.bytes())
    }

    /// The key that seals pending sign-in ceremonies into their challenge ids.
    pub fn ceremony_key(&self) -> tenko_auth::challenge::CeremonyKey {
        tenko_auth::challenge::CeremonyKey::from_cluster_key(self.bytes())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tenko_store::MemStore;
    use tenko_vault::MemVault;

    use super::*;

    #[tokio::test]
    async fn the_key_is_created_once_and_read_back_on_every_controller() {
        let mem = Arc::new(MemStore::default());
        let vault = MemVault::with_store(Arc::clone(&mem));
        let store: Arc<dyn Store> = mem;
        let (first, created) = ClusterKey::load_or_create(store.as_ref(), &vault)
            .await
            .expect("created");
        assert!(created);
        let (second, created) = ClusterKey::load_or_create(store.as_ref(), &vault)
            .await
            .expect("read back");
        assert!(!created);
        assert_eq!(first.bytes(), second.bytes());
        assert_eq!(first.fingerprint_key().id(), second.fingerprint_key().id());
        // Both purposes derive the same key on every controller: a ceremony sealed with
        // one controller's key opens with the other's.
        let ceremonies = tenko_auth::challenge::Ceremonies::with_key(4, first.ceremony_key());
        let elsewhere = tenko_auth::challenge::Ceremonies::with_key(4, second.ceremony_key());
        let now = Timestamp::now();
        let id = ceremonies
            .open(
                tenko_auth::challenge::Pending::SecondFactor {
                    user: tenko_core::UserId::generate(),
                    first: tenko_core::AuthStrength::Password,
                    attempts: 0,
                },
                now,
            )
            .expect("sealed");
        assert!(elsewhere.take(&id, now).is_ok());
        assert_eq!(format!("{first:?}"), "ClusterKey(<redacted>)");
        // Only the envelope is in the store: the record names a system secret.
        let view = store.read(ReadConsistency::Local).await.expect("a view");
        let (record, _) = view
            .get_typed(&TABLE, &())
            .expect("a read")
            .expect("the record");
        let meta = vault
            .meta(record.secret)
            .await
            .expect("meta")
            .expect("a secret");
        assert_eq!(meta.class, SecretClass::System);
    }
}
