//! Test helpers (feature `testing`): [`MemVault`], a [`StoreVault`] over a fresh
//! [`MemStore`] with a [`MemKek`].

use std::{ops::Deref, sync::Arc};

use tenko_core::{RequestCtx, secret::SecretClass, secret::SecretRef};
use tenko_store::{Store, WriteBatch, mem::MemStore};

use crate::{
    RevealAudit, SecretBytes, SecretMeta, SecretSpec, StoreVault, Vault, VaultError,
    kek::{KekProvider, KekRing, MemKek},
};

/// A vault for tests: [`MemStore`] plus an in-memory KEK. Dereferences to the
/// [`StoreVault`] for `rotate_kek`, `list` and `ring`.
#[derive(Debug)]
pub struct MemVault {
    store: Arc<MemStore>,
    vault: StoreVault,
}

impl MemVault {
    /// A vault over a new, empty [`MemStore`].
    pub fn new() -> Self {
        Self::with_store(Arc::new(MemStore::default()))
    }

    /// A vault over an existing store (shared with the code under test).
    pub fn with_store(store: Arc<MemStore>) -> Self {
        let kek: Arc<dyn KekProvider> = Arc::new(MemKek::generate("mem-1"));
        Self::with_ring(store, KekRing::new(kek))
    }

    /// A vault over an existing store with the given KEKs, without the start-up check.
    pub fn with_ring(store: Arc<MemStore>, ring: KekRing) -> Self {
        let dyn_store: Arc<dyn Store> = Arc::clone(&store) as Arc<dyn Store>;
        Self {
            vault: StoreVault::unchecked(dyn_store, ring),
            store,
        }
    }

    /// The underlying store.
    pub fn mem_store(&self) -> &Arc<MemStore> {
        &self.store
    }
}

impl Default for MemVault {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for MemVault {
    type Target = StoreVault;

    fn deref(&self) -> &StoreVault {
        &self.vault
    }
}

#[async_trait::async_trait]
impl Vault for MemVault {
    async fn put_system(
        &self,
        ctx: &RequestCtx,
        spec: SecretSpec,
        value: SecretBytes,
    ) -> Result<SecretRef, VaultError> {
        self.vault.put_system(ctx, spec, value).await
    }

    async fn get_system(
        &self,
        ctx: &RequestCtx,
        secret: SecretRef,
    ) -> Result<SecretBytes, VaultError> {
        self.vault.get_system(ctx, secret).await
    }

    async fn put_operator(
        &self,
        ctx: &RequestCtx,
        spec: SecretSpec,
        value: SecretBytes,
    ) -> Result<SecretRef, VaultError> {
        self.vault.put_operator(ctx, spec, value).await
    }

    async fn reveal(&self, ctx: &RequestCtx, secret: SecretRef) -> Result<SecretBytes, VaultError> {
        self.vault.reveal(ctx, secret).await
    }

    async fn reveal_with(
        &self,
        ctx: &RequestCtx,
        secret: SecretRef,
        batch: WriteBatch,
        audit: RevealAudit,
    ) -> Result<SecretBytes, VaultError> {
        self.vault.reveal_with(ctx, secret, batch, audit).await
    }

    async fn rotate_dek(&self, ctx: &RequestCtx, secret: SecretRef) -> Result<(), VaultError> {
        self.vault.rotate_dek(ctx, secret).await
    }

    async fn replace(
        &self,
        ctx: &RequestCtx,
        secret: SecretRef,
        value: SecretBytes,
    ) -> Result<(), VaultError> {
        self.vault.replace(ctx, secret, value).await
    }

    async fn delete(&self, ctx: &RequestCtx, secret: SecretRef) -> Result<(), VaultError> {
        self.vault.delete(ctx, secret).await
    }

    async fn meta(&self, secret: SecretRef) -> Result<Option<SecretMeta>, VaultError> {
        self.vault.meta(secret).await
    }

    async fn has_operator_secrets(&self) -> Result<bool, VaultError> {
        self.vault.has_operator_secrets().await
    }

    fn stage_put(
        &self,
        batch: &mut WriteBatch,
        ctx: &RequestCtx,
        class: SecretClass,
        spec: SecretSpec,
        value: &SecretBytes,
    ) -> Result<SecretRef, VaultError> {
        self.vault.stage_put(batch, ctx, class, spec, value)
    }

    fn stage_delete(&self, batch: &mut WriteBatch, ctx: &RequestCtx, secret: SecretRef) {
        self.vault.stage_delete(batch, ctx, secret);
    }

    async fn stage_replace(
        &self,
        batch: &mut WriteBatch,
        ctx: &RequestCtx,
        secret: SecretRef,
        value: &SecretBytes,
    ) -> Result<(), VaultError> {
        self.vault.stage_replace(batch, ctx, secret, value).await
    }
}

/// The peers of a controller in an in-process cluster (tests): a fetch is answered from
/// the ring of another controller's vault, sealed under the fetch context of the asking
/// controller, as `Cluster.TransferKek` would answer it. Without a source (a member that
/// cannot be reached) the fetch fails.
#[derive(Debug)]
pub struct MemPeers {
    asking: tenko_core::NodeId,
    source: std::sync::RwLock<Option<Arc<StoreVault>>>,
    fetches: std::sync::atomic::AtomicUsize,
}

impl MemPeers {
    /// Peers of the controller `asking` that fetch from `source`.
    pub fn new(asking: tenko_core::NodeId, source: Option<Arc<StoreVault>>) -> Self {
        Self {
            asking,
            source: std::sync::RwLock::new(source),
            fetches: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Answers from another controller from now on (`None`: nobody answers).
    pub fn set_source(&self, source: Option<Arc<StoreVault>>) {
        *self
            .source
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = source;
    }

    /// How many fetches were asked for.
    pub fn fetches(&self) -> usize {
        self.fetches.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl crate::distribution::KekPeers for MemPeers {
    async fn fetch(
        &self,
        recipient: [u8; crate::transfer::PUBLIC_KEY_LEN],
    ) -> Result<crate::transfer::SealedKeks, VaultError> {
        self.fetches
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let source = self
            .source
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| VaultError::kek_unavailable("no cluster member answers"))?;
        crate::transfer::seal_ring(
            &source.ring(),
            &recipient,
            &crate::transfer::fetch_context(self.asking),
        )
    }
}
