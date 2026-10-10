//! The [`Vault`] over the replicated store.

use std::{
    collections::BTreeSet,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::Bytes;
use tenko_core::{
    CounterKey, ObjectRef, RequestCtx, Revision, SecretId,
    audit::{AuditAction, AuditDraft},
    codec::key::encode_key,
    secret::{SecretClass, SecretRef, VaultEnvelope},
};
use tenko_store::{
    FailedPrecondition, KeyRange, Precondition, ReadConsistency, ReadView, ReadViewExt, Store,
    StoreError, WriteBatch,
};

use crate::{
    RevealAudit, SecretBytes, SecretMeta, SecretSpec, Vault, VaultError,
    envelope::{self, RowBinding},
    kek::{KekProvider, KekRing},
};

/// The vault's store tables.
pub mod tables {
    use tenko_core::{SecretId, TableName, table::TableDef};

    use crate::SecretMeta;

    /// Envelopes by encoded [`SecretId`]. Secret-bearing: the store accepts only
    /// [`VaultEnvelope`](tenko_core::secret::VaultEnvelope)s.
    pub const SECRETS: TableName = TableName::from_static("vault.secrets");
    /// Non-secret metadata by secret.
    pub const META: TableDef<SecretId, SecretMeta> = TableDef::new("vault.secret_meta");
    /// One row per operator secret: makes `has_operator_secrets` a one-row scan.
    pub const OPERATOR_INDEX: TableDef<SecretId, ()> = TableDef::new("vault.operator_index");
}

/// Audit actions of the vault.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// A secret was created.
    pub const CREATE: AuditAction = AuditAction::from_static("vault.secret.create");
    /// A secret's value was replaced.
    pub const REPLACE: AuditAction = AuditAction::from_static("vault.secret.replace");
    /// A secret was deleted.
    pub const DELETE: AuditAction = AuditAction::from_static("vault.secret.delete");
    /// A secret was re-encrypted under a fresh DEK.
    pub const ROTATE_DEK: AuditAction = AuditAction::from_static("vault.secret.rotate_dek");
    /// A secret was revealed to a person (or the reveal was refused).
    pub const REVEAL: AuditAction = AuditAction::from_static("vault.secret.reveal");
    /// Every envelope was re-wrapped under a new KEK.
    pub const ROTATE_KEK: AuditAction = AuditAction::from_static("vault.kek.rotate");
}

/// The KEK epoch: bumped by every KEK rotation before it re-wraps anything. Every batch
/// that carries a new envelope expects the epoch its KEK belongs to, so an envelope wrapped
/// by the previous KEK can no longer commit once a rotation has started; the vault's own
/// writes then retry under the new KEK, and callers of
/// [`stage_put`](crate::Vault::stage_put) see a precondition failure and retry.
pub const KEK_EPOCH: CounterKey = CounterKey::new("vault.kek_epoch");

const PAGE: usize = 512;

/// Attempts of a vault write that lost the race against a KEK rotation.
const EPOCH_RETRIES: usize = 4;

/// Payload bound of one re-wrap batch, well below the store's batch limit.
const REWRAP_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// The outcome of [`StoreVault::rotate_kek`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KekRotation {
    /// The new active KEK.
    pub active: String,
    /// Envelopes re-wrapped.
    pub rewrapped: usize,
    /// KEKs no envelope uses any more; their files may now be removed
    /// ([`KekConfig::remove_retired`](crate::KekConfig::remove_retired)).
    pub retired: Vec<String>,
}

/// The production [`Vault`]: envelopes in the store, KEKs from a [`KekRing`].
pub struct StoreVault {
    store: Arc<dyn Store>,
    keys: RwLock<Arc<Keys>>,
    rotating: AtomicBool,
}

/// The KEKs and the epoch they belong to, swapped together.
#[derive(Debug)]
struct Keys {
    ring: Arc<KekRing>,
    /// The [`KEK_EPOCH`] the active KEK belongs to; `None` for a vault built without the
    /// start-up check (tests), whose writes then carry no epoch precondition until its
    /// first rotation.
    epoch: Option<u64>,
}

impl std::fmt::Debug for StoreVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys = self.keys();
        f.debug_struct("StoreVault")
            .field("ring", &keys.ring)
            .field("epoch", &keys.epoch)
            .finish_non_exhaustive()
    }
}

/// Clears the rotation flag when a rotation ends, also on error.
struct RotationGuard<'a>(&'a AtomicBool);

impl Drop for RotationGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl StoreVault {
    /// Opens the vault after checking that the ring opens the store: every envelope must
    /// decode in a known format and name a loaded KEK, and one data key per KEK identifier
    /// must unwrap. This is the start-up check that keeps the server down without its KEK.
    ///
    /// # Errors
    ///
    /// [`VaultError::KekUnavailable`] naming the missing or wrong KEK,
    /// [`VaultError::UnsupportedFormat`] or [`VaultError::Malformed`] for an envelope this
    /// build cannot read, or the store's error.
    pub async fn open(store: Arc<dyn Store>, ring: KekRing) -> Result<Self, VaultError> {
        let view = store.read(ReadConsistency::Local).await?;
        let epoch = view.counter(&KEK_EPOCH)?;
        let mut checked: BTreeSet<String> = BTreeSet::new();
        let mut count = 0usize;
        for_each_envelope(view.as_ref(), |key, envelope| {
            count += 1;
            envelope::inspect(&envelope)?;
            if checked.contains(&envelope.key_id) {
                return Ok(());
            }
            let row = RowBinding {
                table: &tables::SECRETS,
                key,
            };
            envelope::verify_kek(&ring, row, &envelope).map_err(|error| match error {
                VaultError::UnknownKek { key_id } => VaultError::kek_unavailable(format!(
                    "the store holds secrets wrapped by KEK {key_id}, which is not loaded; \
                     restore its KEK file"
                )),
                VaultError::Integrity => VaultError::kek_unavailable(format!(
                    "KEK {} does not open its envelopes; the KEK file was replaced",
                    envelope.key_id
                )),
                other => other,
            })?;
            checked.insert(envelope.key_id);
            Ok(())
        })?;
        let active = ring.active();
        tracing::info!(
            secrets = count,
            kek = %active.id(),
            epoch,
            protection = active.protection().describe(),
            "vault opened"
        );
        Ok(Self::build(store, ring, Some(epoch)))
    }

    /// A vault without the start-up check (an empty store, tests). Its writes carry no
    /// epoch precondition until its first KEK rotation.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn unchecked(store: Arc<dyn Store>, ring: KekRing) -> Self {
        Self::build(store, ring, None)
    }

    fn build(store: Arc<dyn Store>, ring: KekRing, epoch: Option<u64>) -> Self {
        Self {
            store,
            keys: RwLock::new(Arc::new(Keys {
                ring: Arc::new(ring),
                epoch,
            })),
            rotating: AtomicBool::new(false),
        }
    }

    fn keys(&self) -> Arc<Keys> {
        Arc::clone(
            &self
                .keys
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// The loaded KEKs.
    pub fn ring(&self) -> Arc<KekRing> {
        Arc::clone(&self.keys().ring)
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// Makes `kek` the active KEK and re-wraps every envelope under it, page by page.
    ///
    /// The rotation first bumps [`KEK_EPOCH`] in the store and only then activates `kek`
    /// locally, so a write that encrypted under the previous KEK and commits after the bump
    /// fails its epoch precondition and is redone under `kek`, while every envelope
    /// committed before the bump is visible to the re-wrap passes. A row that changes
    /// during a pass was written under `kek` and is skipped. Ends with a
    /// `vault.kek.rotate` audit record.
    ///
    /// Crash-safe: until it returns, keep every previous KEK loaded; afterwards the KEKs in
    /// [`KekRotation::retired`] may be removed. Run it again after a failure.
    ///
    /// # Errors
    ///
    /// [`VaultError::RotationInProgress`] while another rotation runs, a decryption failure
    /// of an envelope (rotation stops; nothing is lost), a KEK error or the store's error.
    pub async fn rotate_kek(
        &self,
        ctx: &RequestCtx,
        kek: Arc<dyn KekProvider>,
    ) -> Result<KekRotation, VaultError> {
        if self
            .rotating
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(VaultError::RotationInProgress);
        }
        let _guard = RotationGuard(&self.rotating);

        let view = self.store.read(ReadConsistency::Local).await?;
        let epoch = view.counter(&KEK_EPOCH)?;
        let mut bump = Self::batch(ctx);
        bump.expect_counter(KEK_EPOCH, epoch).bump(KEK_EPOCH);
        self.store.propose(bump).await?;
        let epoch = epoch + 1;
        let ring = {
            let mut keys = self
                .keys
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ring = Arc::new(keys.ring.rotated_to(kek));
            *keys = Arc::new(Keys {
                ring: Arc::clone(&ring),
                epoch: Some(epoch),
            });
            ring
        };

        // One pass normally suffices; the next one only confirms that nothing is left.
        let mut rewrapped = 0usize;
        let mut passes = 0u32;
        loop {
            passes += 1;
            let done = self.rewrap_pass(ctx, &ring, epoch).await?;
            rewrapped += done;
            if done == 0 {
                break;
            }
            if passes >= 8 {
                return Err(StoreError::Timeout.into());
            }
        }
        let active = ring.active().id().to_owned();
        let retired: Vec<String> = ring.retired_ids().map(str::to_owned).collect();
        let mut batch = Self::batch(ctx);
        batch.audit(
            AuditDraft::success(actions::ROTATE_KEK, Vec::new())
                .with_source_ip(ctx.source_ip)
                .with_context("kek", active.clone())
                .with_context("retired", retired.join(","))
                .with_context("rewrapped", rewrapped.to_string())
                .with_context("epoch", epoch.to_string()),
        );
        self.store.propose(batch).await?;
        tracing::info!(kek = %active, rewrapped, epoch, "key-encryption key rotated");
        Ok(KekRotation {
            active,
            rewrapped,
            retired,
        })
    }

    /// One pass of [`rotate_kek`](StoreVault::rotate_kek) over a fresh view: re-wraps every
    /// envelope not under the active KEK, in batches bounded by count and size, and
    /// returns how many it committed.
    async fn rewrap_pass(
        &self,
        ctx: &RequestCtx,
        ring: &KekRing,
        epoch: u64,
    ) -> Result<usize, VaultError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let mut pending: Vec<(Bytes, Revision, Bytes)> = Vec::new();
        let mut pending_bytes = 0usize;
        let mut committed = 0usize;
        let mut after: Option<Bytes> = None;
        loop {
            let range = match &after {
                Some(key) => KeyRange::all().after(key.clone()),
                None => KeyRange::all(),
            };
            let page = view.scan(&tables::SECRETS, range, PAGE, false)?;
            let last_page = page.len() < PAGE;
            if let Some((last, _)) = page.last() {
                after = Some(last.clone());
            }
            for (key, versioned) in &page {
                let envelope = VaultEnvelope::from_bytes(&versioned.value)?;
                let row = RowBinding {
                    table: &tables::SECRETS,
                    key,
                };
                if let Some(new) = envelope::rewrap(ring, row, &envelope)? {
                    let bytes = new.to_bytes()?;
                    pending_bytes += key.len() + bytes.len();
                    pending.push((key.clone(), versioned.revision, bytes));
                }
                if pending.len() >= PAGE || pending_bytes >= REWRAP_BATCH_BYTES {
                    committed += self
                        .commit_rewraps(ctx, epoch, std::mem::take(&mut pending))
                        .await?;
                    pending_bytes = 0;
                }
            }
            if last_page {
                break;
            }
        }
        committed += self.commit_rewraps(ctx, epoch, pending).await?;
        Ok(committed)
    }

    /// Commits re-wrapped envelopes, each guarded by the revision it was read at. A row
    /// that changed meanwhile was rewritten under the new KEK (the epoch guarantees it) and
    /// is dropped from the batch instead of failing it.
    async fn commit_rewraps(
        &self,
        ctx: &RequestCtx,
        epoch: u64,
        mut rows: Vec<(Bytes, Revision, Bytes)>,
    ) -> Result<usize, VaultError> {
        while !rows.is_empty() {
            let mut batch = Self::batch(ctx);
            batch.expect_counter(KEK_EPOCH, epoch);
            for (key, revision, bytes) in &rows {
                batch.expect_version(tables::SECRETS.clone(), key.clone(), Some(*revision));
                batch.put(tables::SECRETS.clone(), key.clone(), bytes.clone());
            }
            match self.store.propose(batch).await {
                Ok(_) => return Ok(rows.len()),
                Err(StoreError::PreconditionFailed(failures)) => {
                    let mut changed = BTreeSet::new();
                    for failure in failures {
                        match failure {
                            FailedPrecondition::Version { table, key, .. }
                                if table == tables::SECRETS =>
                            {
                                changed.insert(key);
                            }
                            other => {
                                return Err(StoreError::PreconditionFailed(vec![other]).into());
                            }
                        }
                    }
                    rows.retain(|(key, ..)| !changed.contains(key));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(0)
    }

    /// A batch for the vault's own writes. They are parts of a caller's operation and
    /// carry random identifiers, keys and nonces, so they never take the request's
    /// idempotency key: a replay could never match the first fingerprint.
    fn batch(ctx: &RequestCtx) -> WriteBatch {
        let mut batch = WriteBatch::for_request(ctx);
        batch.idempotency = None;
        batch
    }

    /// Metadata of every secret, in identifier order.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn list(&self) -> Result<Vec<SecretMeta>, VaultError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let mut out = Vec::new();
        let mut after: Option<Bytes> = None;
        loop {
            let range = match &after {
                Some(key) => KeyRange::all().after(key.clone()),
                None => KeyRange::all(),
            };
            let page = view.scan_typed(&tables::META, range, PAGE, false)?;
            let Some((last, ..)) = page.last() else { break };
            after = Some(tables::META.key(last));
            out.extend(page.into_iter().map(|(_, meta, _)| meta));
        }
        Ok(out)
    }

    async fn read_envelope(
        &self,
        secret: SecretId,
    ) -> Result<(Arc<dyn ReadView>, VaultEnvelope, tenko_core::Revision), VaultError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let key = encode_key(&secret);
        let versioned = view
            .get(&tables::SECRETS, &key)?
            .ok_or(VaultError::NotFound { secret })?;
        let envelope = VaultEnvelope::from_bytes(&versioned.value)?;
        Ok((view, envelope, versioned.revision))
    }

    fn decrypt(
        &self,
        secret: SecretId,
        envelope: &VaultEnvelope,
    ) -> Result<envelope::Opened, VaultError> {
        let key = encode_key(&secret);
        envelope::open(
            &self.ring(),
            RowBinding {
                table: &tables::SECRETS,
                key: &key,
            },
            envelope,
        )
    }

    /// Seals `value` for the row of `secret` under the active KEK of `keys` and makes the
    /// batch expect the epoch that KEK belongs to.
    fn encrypt_into(
        keys: &Keys,
        batch: &mut WriteBatch,
        secret: SecretId,
        class: SecretClass,
        dek_generation: u32,
        value: &[u8],
    ) -> Result<Bytes, VaultError> {
        let key = encode_key(&secret);
        let envelope = envelope::seal(
            keys.ring.active().as_ref(),
            RowBinding {
                table: &tables::SECRETS,
                key: &key,
            },
            class,
            dek_generation,
            value,
        )?;
        if let Some(epoch) = keys.epoch {
            let expected = batch.preconditions.iter().any(|precondition| {
                matches!(precondition, Precondition::Counter { counter, .. } if *counter == KEK_EPOCH)
            });
            if !expected {
                batch.expect_counter(KEK_EPOCH, epoch);
            }
        }
        Ok(envelope.to_bytes()?)
    }

    /// Re-encrypts an existing secret with a new value (or its own value) under a fresh
    /// DEK, guarded by the row's revision; redone when a KEK rotation intervened.
    async fn rewrite(
        &self,
        ctx: &RequestCtx,
        secret: SecretRef,
        value: Option<SecretBytes>,
        action: AuditAction,
    ) -> Result<(), VaultError> {
        let id = secret.secret;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let (view, envelope, revision) = self.read_envelope(id).await?;
            let opened = self.decrypt(id, &envelope)?;
            let generation = opened
                .dek_generation
                .checked_add(1)
                .ok_or(VaultError::Malformed {
                    what: "DEK generation",
                })?;
            let keys = self.keys();
            let mut batch = Self::batch(ctx);
            let plain = value.as_ref().unwrap_or(&opened.value);
            let bytes = Self::encrypt_into(
                &keys,
                &mut batch,
                id,
                opened.class,
                generation,
                plain.expose(),
            )?;
            let class = opened.class;
            drop(opened);
            let key = encode_key(&id);
            batch.expect_version(tables::SECRETS.clone(), key.clone(), Some(revision));
            batch.put(tables::SECRETS.clone(), key, bytes);
            let mut objects = vec![ObjectRef::from(id)];
            if let Some((mut meta, _)) = view.get_typed(&tables::META, &id)? {
                meta.updated_at = ctx.now;
                objects.extend(meta.owner);
                batch.put_typed(&tables::META, &id, &meta)?;
            }
            batch.audit(
                AuditDraft::success(action.clone(), objects)
                    .with_source_ip(ctx.source_ip)
                    .with_context("class", class_name(class))
                    .with_context("kek", keys.ring.active().id()),
            );
            match self.store.propose(batch).await {
                Ok(_) => return Ok(()),
                Err(StoreError::PreconditionFailed(failures))
                    if attempt < EPOCH_RETRIES && lost_to_rotation(&failures) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn put(
        &self,
        ctx: &RequestCtx,
        class: SecretClass,
        spec: SecretSpec,
        value: SecretBytes,
    ) -> Result<SecretRef, VaultError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut batch = Self::batch(ctx);
            let secret = self.stage_put(&mut batch, ctx, class, spec.clone(), &value)?;
            match self.store.propose(batch).await {
                Ok(_) => return Ok(secret),
                Err(StoreError::PreconditionFailed(failures))
                    if attempt < EPOCH_RETRIES && lost_to_rotation(&failures) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Records a reveal that failed before a value was produced (IAM-16). Best effort:
    /// the caller gets the original error either way.
    async fn audit_failed_reveal(
        &self,
        ctx: &RequestCtx,
        id: SecretId,
        error: &VaultError,
        audit: &RevealAudit,
    ) {
        let mut batch = Self::batch(ctx);
        batch.audit(reveal_draft(
            AuditDraft::failed(actions::REVEAL, reveal_objects(id, audit), error),
            ctx,
            audit,
        ));
        if let Err(audit_error) = self.store.propose(batch).await {
            tracing::warn!(%audit_error, secret = %id, "could not audit a failed reveal");
        }
    }
}

/// Whether a batch failed only because a KEK rotation bumped the epoch.
fn lost_to_rotation(failures: &[FailedPrecondition]) -> bool {
    !failures.is_empty()
        && failures.iter().all(|failure| {
            matches!(failure, FailedPrecondition::Counter { counter, .. } if *counter == KEK_EPOCH)
        })
}

/// The objects of a reveal's audit record: the secret, then the caller's.
fn reveal_objects(id: SecretId, audit: &RevealAudit) -> Vec<ObjectRef> {
    let mut objects = vec![ObjectRef::from(id)];
    objects.extend(audit.objects.iter().copied());
    objects
}

/// Adds the source address and the caller's context to a reveal's audit draft.
fn reveal_draft(mut draft: AuditDraft, ctx: &RequestCtx, audit: &RevealAudit) -> AuditDraft {
    draft = draft.with_source_ip(ctx.source_ip);
    for (key, value) in &audit.context {
        draft = draft.with_context(key.clone(), value.clone());
    }
    draft
}

fn class_name(class: SecretClass) -> &'static str {
    match class {
        SecretClass::System => "system",
        SecretClass::Operator => "operator",
    }
}

/// Calls `f` for every envelope in `vault.secrets`, page by page.
fn for_each_envelope(
    view: &dyn ReadView,
    mut f: impl FnMut(&[u8], VaultEnvelope) -> Result<(), VaultError>,
) -> Result<(), VaultError> {
    let mut after: Option<Bytes> = None;
    loop {
        let range = match &after {
            Some(key) => KeyRange::all().after(key.clone()),
            None => KeyRange::all(),
        };
        let page = view.scan(&tables::SECRETS, range, PAGE, false)?;
        let Some((last, _)) = page.last() else {
            return Ok(());
        };
        after = Some(last.clone());
        for (key, versioned) in page {
            f(&key, VaultEnvelope::from_bytes(&versioned.value)?)?;
        }
    }
}

#[async_trait::async_trait]
impl Vault for StoreVault {
    async fn put_system(
        &self,
        ctx: &RequestCtx,
        spec: SecretSpec,
        value: SecretBytes,
    ) -> Result<SecretRef, VaultError> {
        self.put(ctx, SecretClass::System, spec, value).await
    }

    async fn get_system(
        &self,
        _ctx: &RequestCtx,
        secret: SecretRef,
    ) -> Result<SecretBytes, VaultError> {
        let (_, envelope, _) = self.read_envelope(secret.secret).await?;
        Ok(self.decrypt(secret.secret, &envelope)?.value)
    }

    async fn put_operator(
        &self,
        ctx: &RequestCtx,
        spec: SecretSpec,
        value: SecretBytes,
    ) -> Result<SecretRef, VaultError> {
        self.put(ctx, SecretClass::Operator, spec, value).await
    }

    async fn reveal(&self, ctx: &RequestCtx, secret: SecretRef) -> Result<SecretBytes, VaultError> {
        self.reveal_with(ctx, secret, Self::batch(ctx), RevealAudit::default())
            .await
    }

    async fn reveal_with(
        &self,
        ctx: &RequestCtx,
        secret: SecretRef,
        mut batch: WriteBatch,
        audit: RevealAudit,
    ) -> Result<SecretBytes, VaultError> {
        let id = secret.secret;
        let opened = match self.read_envelope(id).await {
            Ok((_, envelope, _)) => self.decrypt(id, &envelope),
            Err(error) => Err(error),
        };
        let opened = match opened {
            Ok(opened) => opened,
            Err(error) => {
                self.audit_failed_reveal(ctx, id, &error, &audit).await;
                return Err(error);
            }
        };
        if opened.class == SecretClass::System {
            drop(opened);
            let mut refusal = Self::batch(ctx);
            refusal.audit(
                reveal_draft(
                    AuditDraft::denied(actions::REVEAL, reveal_objects(id, &audit)),
                    ctx,
                    &audit,
                )
                .with_context("class", "system"),
            );
            self.store.propose(refusal).await?;
            return Err(VaultError::NotRevealable { secret: id });
        }
        // The reveal never takes the request's idempotency key: a replay must not return
        // the value without a new audit record.
        batch.idempotency = None;
        batch.audit(
            reveal_draft(
                AuditDraft::success(actions::REVEAL, reveal_objects(id, &audit)),
                ctx,
                &audit,
            )
            .with_context("class", "operator"),
        );
        if let Err(error) = self.store.propose(batch).await {
            drop(opened);
            let error = VaultError::from(error);
            self.audit_failed_reveal(ctx, id, &error, &audit).await;
            return Err(error);
        }
        Ok(opened.value)
    }

    async fn rotate_dek(&self, ctx: &RequestCtx, secret: SecretRef) -> Result<(), VaultError> {
        self.rewrite(ctx, secret, None, actions::ROTATE_DEK).await
    }

    async fn replace(
        &self,
        ctx: &RequestCtx,
        secret: SecretRef,
        value: SecretBytes,
    ) -> Result<(), VaultError> {
        if value.len() > crate::MAX_SECRET_LEN {
            return Err(VaultError::TooLarge {
                size: value.len(),
                limit: crate::MAX_SECRET_LEN,
            });
        }
        self.rewrite(ctx, secret, Some(value), actions::REPLACE)
            .await
    }

    async fn delete(&self, ctx: &RequestCtx, secret: SecretRef) -> Result<(), VaultError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        if view
            .get(&tables::SECRETS, &encode_key(&secret.secret))?
            .is_none()
        {
            return Ok(());
        }
        let mut batch = Self::batch(ctx);
        self.stage_delete(&mut batch, ctx, secret);
        self.store.propose(batch).await?;
        Ok(())
    }

    async fn meta(&self, secret: SecretRef) -> Result<Option<SecretMeta>, VaultError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        Ok(view
            .get_typed(&tables::META, &secret.secret)?
            .map(|(meta, _)| meta))
    }

    async fn has_operator_secrets(&self) -> Result<bool, VaultError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        Ok(!view
            .scan(tables::OPERATOR_INDEX.name(), KeyRange::all(), 1, false)?
            .is_empty())
    }

    fn stage_put(
        &self,
        batch: &mut WriteBatch,
        ctx: &RequestCtx,
        class: SecretClass,
        spec: SecretSpec,
        value: &SecretBytes,
    ) -> Result<SecretRef, VaultError> {
        let id = SecretId::generate();
        let keys = self.keys();
        let bytes = Self::encrypt_into(&keys, batch, id, class, 1, value.expose())?;
        let key = encode_key(&id);
        batch.expect_version(tables::SECRETS.clone(), key.clone(), None);
        batch.put(tables::SECRETS.clone(), key, bytes);
        let meta = SecretMeta {
            id,
            class,
            purpose: spec.purpose,
            owner: spec.owner,
            label: spec.label,
            created_at: ctx.now,
            updated_at: ctx.now,
        };
        batch.put_typed(&tables::META, &id, &meta)?;
        if class == SecretClass::Operator {
            batch.put_typed(&tables::OPERATOR_INDEX, &id, &())?;
        }
        let mut objects = vec![ObjectRef::from(id)];
        objects.extend(meta.owner);
        batch.audit(
            AuditDraft::success(actions::CREATE, objects)
                .with_source_ip(ctx.source_ip)
                .with_context("class", class_name(class))
                .with_context("purpose", meta.purpose.as_str())
                .with_context("kek", keys.ring.active().id()),
        );
        Ok(SecretRef { secret: id })
    }

    fn stage_delete(&self, batch: &mut WriteBatch, ctx: &RequestCtx, secret: SecretRef) {
        let id = secret.secret;
        batch.delete(tables::SECRETS.clone(), encode_key(&id));
        batch.delete_typed(&tables::META, &id);
        batch.delete_typed(&tables::OPERATOR_INDEX, &id);
        batch.audit(
            AuditDraft::success(actions::DELETE, vec![ObjectRef::from(id)])
                .with_source_ip(ctx.source_ip),
        );
    }

    async fn stage_replace(
        &self,
        batch: &mut WriteBatch,
        ctx: &RequestCtx,
        secret: SecretRef,
        value: &SecretBytes,
    ) -> Result<(), VaultError> {
        if value.len() > crate::MAX_SECRET_LEN {
            return Err(VaultError::TooLarge {
                size: value.len(),
                limit: crate::MAX_SECRET_LEN,
            });
        }
        let id = secret.secret;
        let (view, envelope, revision) = self.read_envelope(id).await?;
        let opened = self.decrypt(id, &envelope)?;
        let generation = opened
            .dek_generation
            .checked_add(1)
            .ok_or(VaultError::Malformed {
                what: "DEK generation",
            })?;
        let class = opened.class;
        drop(opened);
        let keys = self.keys();
        let bytes = Self::encrypt_into(&keys, batch, id, class, generation, value.expose())?;
        let key = encode_key(&id);
        batch.expect_version(tables::SECRETS.clone(), key.clone(), Some(revision));
        batch.put(tables::SECRETS.clone(), key, bytes);
        let mut objects = vec![ObjectRef::from(id)];
        if let Some((mut meta, _)) = view.get_typed(&tables::META, &id)? {
            meta.updated_at = ctx.now;
            objects.extend(meta.owner);
            batch.put_typed(&tables::META, &id, &meta)?;
        }
        batch.audit(
            AuditDraft::success(actions::REPLACE, objects)
                .with_source_ip(ctx.source_ip)
                .with_context("class", class_name(class))
                .with_context("kek", keys.ring.active().id()),
        );
        Ok(())
    }
}
