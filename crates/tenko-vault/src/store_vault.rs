//! The [`Vault`] over the replicated store.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::Bytes;
use tenko_core::{
    CounterKey, NodeId, ObjectRef, RequestCtx, Revision, SecretId, SystemComponent,
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
    kek_state::{self, KekState, ProtectionRecord, VaultAlarm, VaultAlarmKind},
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

/// What [`StoreVault::open_checked`] found besides the vault.
struct OpenedState {
    /// The installation's KEK state, when the store has one.
    state: Option<KekState>,
    /// A key the configuration introduced on a single controller, to make active.
    adopt: Option<String>,
}

/// Clears the rotation flag when a rotation ends, also on error.
struct RotationGuard<'a>(&'a AtomicBool);

impl Drop for RotationGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Who opens the vault at start ([`StoreVault::start`]).
#[derive(Debug, Clone)]
pub struct VaultStart {
    /// This controller.
    pub node: NodeId,
    /// The configured provider ([`KekConfig::provider_name`](crate::KekConfig::provider_name)).
    pub provider: String,
}

/// The result of [`StoreVault::refresh`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refresh {
    /// The store holds no KEK state yet (a store from before Slice 3, or a test).
    NoState,
    /// The vault already wraps with the active generation of the installation.
    Current,
    /// The vault switched to the active generation of the installation.
    Switched {
        /// The generation now active.
        active: String,
        /// Its epoch.
        epoch: u64,
    },
    /// The installation's active generation is not loaded on this controller; it must be
    /// fetched from a member first.
    Missing {
        /// The generation.
        id: String,
    },
}

impl StoreVault {
    /// Opens the vault after checking that the ring opens the store: every envelope must
    /// decode in a known format and name a loaded KEK, and one data key per KEK identifier
    /// must unwrap. This is the start-up check that keeps the server down without its KEK.
    ///
    /// When the store holds the installation's KEK state, the generation it names becomes
    /// active, whatever generation of the ring is the newest on this host (a controller
    /// that received a generation during an online rotation keeps wrapping with the
    /// previous one until the rotation activates it).
    ///
    /// # Errors
    ///
    /// [`VaultError::KekUnavailable`] naming the missing or wrong KEK,
    /// [`VaultError::UnsupportedFormat`] or [`VaultError::Malformed`] for an envelope this
    /// build cannot read, or the store's error.
    pub async fn open(store: Arc<dyn Store>, ring: KekRing) -> Result<Self, VaultError> {
        Ok(Self::open_checked(store, ring, false).await?.0)
    }

    /// Opens the vault as [`open`](StoreVault::open) does, then records this controller's
    /// side of the KEK state (best effort; a controller that starts isolated logs a warning
    /// and records it at its next start):
    ///
    /// - the installation's KEK state, when the store has none yet;
    /// - the protection of the active KEK in `vault.kek_protection`, with the audit record
    ///   and alarm `vault.kek.downgrade` when it is weaker than the strongest protection
    ///   this controller had (R15);
    /// - an alarm and audit record for every plain generation the load refused
    ///   ([`KekRing::refused`]).
    ///
    /// On a single controller a key that the configuration introduced (a new key file of
    /// the `file` provider, with the old one listed as retired) becomes the installation's
    /// active generation, with a new KEK epoch; in a cluster such a key is not used and a
    /// warning says to rotate online instead.
    ///
    /// # Errors
    ///
    /// As [`open`](StoreVault::open), plus the store's error when a key introduced by the
    /// configuration cannot be made active.
    pub async fn start(
        store: Arc<dyn Store>,
        ring: KekRing,
        start: &VaultStart,
    ) -> Result<Self, VaultError> {
        let single = matches!(store.status().quorum, tenko_store::QuorumState::Single);
        let (vault, opened) = Self::open_checked(store, ring, single).await?;
        let ctx = RequestCtx::system(SystemComponent::Vault);
        if let Some(adopted) = &opened.adopt {
            vault.adopt(&ctx, adopted, start.node).await?;
        }
        if opened.state.is_none()
            && let Err(error) = vault.init_state(&ctx, start.node).await
        {
            tracing::warn!(%error, "could not record the KEK state; it is recorded at the next start");
        }
        if let Err(error) = vault.record_protection(&ctx, start).await {
            tracing::warn!(
                %error,
                "could not record the KEK protection of this controller; it is recorded at the \
                 next start"
            );
        }
        Ok(vault)
    }

    /// The shared part of [`open`](StoreVault::open) and [`start`](StoreVault::start).
    async fn open_checked(
        store: Arc<dyn Store>,
        ring: KekRing,
        may_adopt: bool,
    ) -> Result<(Self, OpenedState), VaultError> {
        let view = store.read(ReadConsistency::Local).await?;
        let epoch = view.counter(&KEK_EPOCH)?;
        let state = kek_state::read_state(view.as_ref())?.map(|(state, _)| state);
        let mut adopt = None;
        let ring = match &state {
            None => ring,
            Some(state) => {
                let natural = ring.active().id().to_owned();
                if !state.knows(&natural) && may_adopt && !state.rotating() {
                    tracing::warn!(
                        kek = %natural,
                        previous = %state.active,
                        "the configuration introduced a new key-encryption key; it becomes \
                         active, and existing secrets move to it with the next rotation"
                    );
                    adopt = Some(natural);
                    ring
                } else if ring.contains(&state.active) {
                    if !state.knows(&natural) {
                        tracing::warn!(
                            kek = %natural,
                            active = %state.active,
                            "the configuration introduced a key-encryption key that the \
                             cluster does not know; it is not used. Rotate online \
                             (POST /system/kek/rotate) instead"
                        );
                    }
                    ring.activate(&state.active)?
                } else {
                    return Err(VaultError::kek_unavailable(format!(
                        "the active key-encryption key of the installation, {}, is not on \
                         this host; a cluster member hands it over at start (cluster step) \
                         when a member is reachable",
                        state.active
                    )));
                }
            }
        };
        let count = Self::check_envelopes(view.as_ref(), &ring)?;
        let active = ring.active();
        tracing::info!(
            secrets = count,
            kek = %active.id(),
            epoch,
            protection = active.protection().describe(),
            "vault opened"
        );
        Ok((
            Self::build(store, ring, Some(epoch)),
            OpenedState { state, adopt },
        ))
    }

    /// Checks that `ring` opens one envelope per KEK identifier; returns the count.
    fn check_envelopes(view: &dyn ReadView, ring: &KekRing) -> Result<usize, VaultError> {
        let mut checked: BTreeSet<String> = BTreeSet::new();
        let mut count = 0usize;
        for_each_envelope(view, |key, envelope| {
            count += 1;
            envelope::inspect(&envelope)?;
            if checked.contains(&envelope.key_id) {
                return Ok(());
            }
            let row = RowBinding {
                table: &tables::SECRETS,
                key,
            };
            envelope::verify_kek(ring, row, &envelope).map_err(|error| match error {
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
        Ok(count)
    }

    /// Makes a key the configuration introduced the installation's active generation (a
    /// single controller only).
    async fn adopt(&self, ctx: &RequestCtx, id: &str, node: NodeId) -> Result<(), VaultError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let epoch = view.counter(&KEK_EPOCH)?;
        let (mut state, revision) = kek_state::read_state(view.as_ref())?
            .ok_or_else(|| VaultError::kek_unavailable("the KEK state disappeared"))?;
        state.list(id, ctx.now, Some(node));
        id.clone_into(&mut state.active);
        state.epoch = epoch + 1;
        let mut batch = Self::batch(ctx);
        batch
            .expect_counter(KEK_EPOCH, epoch)
            .bump(KEK_EPOCH)
            .expect_typed(&kek_state::tables::STATE, &(), Some(revision));
        batch.put_typed(&kek_state::tables::STATE, &(), &state)?;
        batch.audit(
            AuditDraft::success(kek_state::actions::ACTIVATE, Vec::new())
                .with_context("kek", id)
                .with_context("epoch", state.epoch.to_string())
                .with_context("cause", "configuration"),
        );
        self.store.propose(batch).await?;
        let ring = self.ring();
        self.set_keys(ring.as_ref().clone(), Some(epoch + 1));
        Ok(())
    }

    /// Writes the installation's KEK state from this ring, when the store has none.
    async fn init_state(&self, ctx: &RequestCtx, node: NodeId) -> Result<(), VaultError> {
        let keys = self.keys();
        let epoch = keys.epoch.unwrap_or_default();
        let mut state = KekState {
            epoch,
            active: keys.ring.active().id().to_owned(),
            generations: Vec::new(),
            pending: None,
            rotation: None,
            abandoned: Vec::new(),
        };
        let active = keys.ring.active().id().to_owned();
        for id in keys.ring.ids().filter(|id| *id != active) {
            state.list(id, ctx.now, None);
        }
        state.list(&active, ctx.now, Some(node));
        let mut batch = Self::batch(ctx);
        batch
            .expect_counter(KEK_EPOCH, epoch)
            .expect_typed(&kek_state::tables::STATE, &(), None);
        batch.put_typed(&kek_state::tables::STATE, &(), &state)?;
        match self.store.propose(batch).await {
            Ok(_) | Err(StoreError::PreconditionFailed(_)) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Records the protection of this controller's active KEK and raises the alarms of R15.
    async fn record_protection(
        &self,
        ctx: &RequestCtx,
        start: &VaultStart,
    ) -> Result<(), VaultError> {
        let ring = self.ring();
        let active = ring.active();
        let current = active.protection();
        let view = self.store.read(ReadConsistency::Local).await?;
        let previous = kek_state::read_protection(view.as_ref(), start.node)?;
        let mut batch = Self::batch(ctx);
        let record = if let Some((record, revision)) = &previous {
            {
                batch.expect_typed(&kek_state::tables::PROTECTION, &start.node, Some(*revision));
                let strongest = if current.rank() > record.strongest.rank() {
                    current
                } else {
                    record.strongest
                };
                // A transition into a weaker protection raises the alarm once; the status
                // keeps the warning while it lasts.
                if current.rank() < record.strongest.rank()
                    && current.rank() < record.current.rank()
                {
                    let params = BTreeMap::from([
                        ("from".to_owned(), record.current.code().to_owned()),
                        ("to".to_owned(), current.code().to_owned()),
                        ("strongest".to_owned(), record.strongest.code().to_owned()),
                    ]);
                    tracing::error!(
                        from = record.current.describe(),
                        to = current.describe(),
                        "THE KEY-ENCRYPTION KEY PROTECTION OF THIS CONTROLLER WAS DOWNGRADED"
                    );
                    Self::stage_alarm(
                        &mut batch,
                        ctx,
                        &view,
                        &kek_state::downgrade_alarm_key(start.node),
                        VaultAlarmKind::KekDowngrade,
                        start.node,
                        params,
                    )?;
                }
                ProtectionRecord {
                    strongest,
                    current,
                    provider: start.provider.clone(),
                    kek: active.id().to_owned(),
                    updated_at: ctx.now,
                }
            }
        } else {
            batch.expect_typed(&kek_state::tables::PROTECTION, &start.node, None);
            ProtectionRecord {
                strongest: current,
                current,
                provider: start.provider.clone(),
                kek: active.id().to_owned(),
                updated_at: ctx.now,
            }
        };
        batch.put_typed(&kek_state::tables::PROTECTION, &start.node, &record)?;
        for refused in ring.refused() {
            let file = refused
                .path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let params = BTreeMap::from([
                ("cause".to_owned(), "plain_generation".to_owned()),
                ("generation".to_owned(), refused.generation.to_string()),
                ("file".to_owned(), file),
                ("from".to_owned(), refused.sealed.code().to_owned()),
                ("to".to_owned(), refused.protection.code().to_owned()),
            ]);
            Self::stage_alarm(
                &mut batch,
                ctx,
                &view,
                &kek_state::refused_alarm_key(start.node, refused.generation),
                VaultAlarmKind::PlainRefused,
                start.node,
                params,
            )?;
        }
        self.store.propose(batch).await?;
        Ok(())
    }

    /// Adds an alarm (or raises an existing one again) and its audit record to `batch`.
    fn stage_alarm(
        batch: &mut WriteBatch,
        ctx: &RequestCtx,
        view: &Arc<dyn ReadView>,
        key: &str,
        kind: VaultAlarmKind,
        node: NodeId,
        params: BTreeMap<String, String>,
    ) -> Result<(), VaultError> {
        let key = key.to_owned();
        let previous = view.get_typed(&kek_state::tables::ALARMS, &key)?;
        let alarm = VaultAlarm {
            kind,
            code: kek_state::DOWNGRADE_CODE.to_owned(),
            node,
            at: ctx.now,
            first_at: previous
                .as_ref()
                .map_or(ctx.now, |(alarm, _)| alarm.first_at),
            count: previous
                .as_ref()
                .map_or(1, |(alarm, _)| alarm.count.saturating_add(1)),
            params: params.clone(),
        };
        batch.put_typed(&kek_state::tables::ALARMS, &key, &alarm)?;
        let mut draft =
            AuditDraft::success(kek_state::actions::DOWNGRADE, vec![ObjectRef::node(node)])
                .with_source_ip(ctx.source_ip);
        for (name, value) in params {
            draft = draft.with_context(name, value);
        }
        batch.audit(draft);
        Ok(())
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

    /// Replaces the ring and the epoch it belongs to.
    pub(crate) fn set_keys(&self, ring: KekRing, epoch: Option<u64>) {
        let mut keys = self
            .keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *keys = Arc::new(Keys {
            ring: Arc::new(ring),
            epoch,
        });
    }

    /// The loaded KEKs.
    pub fn ring(&self) -> Arc<KekRing> {
        Arc::clone(&self.keys().ring)
    }

    /// The [`KEK_EPOCH`] the active KEK belongs to (`None` for a vault built without the
    /// start-up check).
    pub fn epoch(&self) -> Option<u64> {
        self.keys().epoch
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// Adds the generations of `ring` this vault does not hold yet (fetched from another
    /// controller), keeping the active one.
    pub fn merge(&self, ring: &KekRing) {
        let mut keys = self
            .keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut merged = keys.ring.as_ref().clone();
        let mut added = false;
        for kek in ring.generations() {
            if !merged.contains(kek.id()) {
                merged = merged.with_newer(Arc::clone(kek));
                added = true;
            }
        }
        if added {
            *keys = Arc::new(Keys {
                ring: Arc::new(merged),
                epoch: keys.epoch,
            });
        }
    }

    /// Brings the active generation and the epoch in line with the installation's KEK
    /// state in the store (a controller follows an online rotation, or retries a write
    /// that lost the race against one).
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn refresh(&self) -> Result<Refresh, VaultError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let epoch = view.counter(&KEK_EPOCH)?;
        match kek_state::read_state(view.as_ref())? {
            Some((state, _)) => Ok(self.apply_state(&state, epoch)),
            None => Ok(Refresh::NoState),
        }
    }

    /// As [`refresh`](StoreVault::refresh), from a state and epoch read together.
    pub fn apply_state(&self, state: &KekState, epoch: u64) -> Refresh {
        let mut keys = self
            .keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if keys.ring.active().id() == state.active && keys.epoch.is_none_or(|e| e >= epoch) {
            return Refresh::Current;
        }
        if keys.epoch.is_some_and(|e| e > epoch) {
            // A stale view: this vault already follows a newer epoch.
            return Refresh::Current;
        }
        let Ok(ring) = keys.ring.activate(&state.active) else {
            return Refresh::Missing {
                id: state.active.clone(),
            };
        };
        tracing::info!(kek = %state.active, epoch, "key-encryption key switched");
        *keys = Arc::new(Keys {
            ring: Arc::new(ring),
            epoch: Some(epoch),
        });
        Refresh::Switched {
            active: state.active.clone(),
            epoch,
        }
    }

    /// Makes `kek` the active KEK and re-wraps every envelope under it, page by page: the
    /// rotation of a stopped single controller (`tenko kek rotate`).
    ///
    /// The rotation first bumps [`KEK_EPOCH`] in the store, together with the
    /// installation's KEK state, and only then activates `kek` locally, so a write that
    /// encrypted under the previous KEK and commits after the bump fails its epoch
    /// precondition and is redone under `kek`, while every envelope committed before the
    /// bump is visible to the re-wrap passes. A row that changes during a pass was written
    /// under `kek` and is skipped. Ends with a `vault.kek.rotate` audit record.
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
        let ring = Arc::new(self.ring().rotated_to(Arc::clone(&kek)));
        let state = if let Some((mut state, revision)) = kek_state::read_state(view.as_ref())? {
            bump.expect_typed(&kek_state::tables::STATE, &(), Some(revision));
            if state.rotating() {
                return Err(VaultError::RotationInProgress);
            }
            state.list(kek.id(), ctx.now, None);
            kek.id().clone_into(&mut state.active);
            state.epoch = epoch + 1;
            state
        } else {
            bump.expect_typed(&kek_state::tables::STATE, &(), None);
            let mut state = KekState {
                epoch: epoch + 1,
                active: kek.id().to_owned(),
                generations: Vec::new(),
                pending: None,
                rotation: None,
                abandoned: Vec::new(),
            };
            for id in ring.ids() {
                state.list(id, ctx.now, None);
            }
            state
        };
        bump.put_typed(&kek_state::tables::STATE, &(), &state)?;
        self.store.propose(bump).await?;
        let epoch = epoch + 1;
        self.set_keys(ring.as_ref().clone(), Some(epoch));

        let rewrapped = self.rewrap_all(ctx, &ring, epoch, None, |_| {}).await?;
        let active = ring.active().id().to_owned();
        let retired: Vec<String> = ring.retired_ids().map(str::to_owned).collect();
        let mut batch = Self::batch(ctx);
        // Every envelope is under the active generation now: the state stops listing the
        // others, so no controller fetches them.
        let view = self.store.read(ReadConsistency::Local).await?;
        if let Some((mut state, revision)) = kek_state::read_state(view.as_ref())?
            && state.active == active
        {
            state.keep_active_only();
            batch.expect_typed(&kek_state::tables::STATE, &(), Some(revision));
            batch.put_typed(&kek_state::tables::STATE, &(), &state)?;
        }
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

    /// Re-wraps every envelope not under the active KEK of `ring`, pass after pass until a
    /// pass finds nothing; every batch expects `epoch` and `fence` (the leader epoch of an
    /// online rotation). `progress` sees the running total.
    pub(crate) async fn rewrap_all(
        &self,
        ctx: &RequestCtx,
        ring: &KekRing,
        epoch: u64,
        fence: Option<&Precondition>,
        mut progress: impl FnMut(usize),
    ) -> Result<usize, VaultError> {
        // One pass normally suffices; the next one only confirms that nothing is left.
        let mut rewrapped = 0usize;
        let mut passes = 0u32;
        loop {
            passes += 1;
            let done = self.rewrap_pass(ctx, ring, epoch, fence).await?;
            rewrapped += done;
            progress(rewrapped);
            if done == 0 {
                return Ok(rewrapped);
            }
            if passes >= 8 {
                return Err(StoreError::Timeout.into());
            }
        }
    }

    /// One pass of [`rewrap_all`](StoreVault::rewrap_all) over a fresh view: re-wraps
    /// every envelope not under the active KEK, in batches bounded by count and size, and
    /// returns how many it committed.
    async fn rewrap_pass(
        &self,
        ctx: &RequestCtx,
        ring: &KekRing,
        epoch: u64,
        fence: Option<&Precondition>,
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
                        .commit_rewraps(ctx, epoch, fence, std::mem::take(&mut pending))
                        .await?;
                    pending_bytes = 0;
                }
            }
            if last_page {
                break;
            }
        }
        committed += self.commit_rewraps(ctx, epoch, fence, pending).await?;
        Ok(committed)
    }

    /// Commits re-wrapped envelopes, each guarded by the revision it was read at. A row
    /// that changed meanwhile was rewritten under the new KEK (the epoch guarantees it) and
    /// is dropped from the batch instead of failing it.
    async fn commit_rewraps(
        &self,
        ctx: &RequestCtx,
        epoch: u64,
        fence: Option<&Precondition>,
        mut rows: Vec<(Bytes, Revision, Bytes)>,
    ) -> Result<usize, VaultError> {
        while !rows.is_empty() {
            let mut batch = Self::batch(ctx);
            batch.expect_counter(KEK_EPOCH, epoch);
            if let Some(fence) = fence {
                batch.preconditions.push(fence.clone());
            }
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

    /// After a write lost the race against a KEK rotation: switch to the generation the
    /// installation activated, if it is loaded (best effort; the retry tells).
    async fn follow_rotation(&self) {
        match self.refresh().await {
            Ok(Refresh::Missing { id }) => {
                tracing::warn!(kek = %id, "a write waits for a key generation this controller lacks");
            }
            Ok(_) => {}
            Err(error) => tracing::debug!(%error, "could not read the KEK state"),
        }
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
                    if attempt < EPOCH_RETRIES && lost_to_rotation(&failures) =>
                {
                    self.follow_rotation().await;
                }
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
                    if attempt < EPOCH_RETRIES && lost_to_rotation(&failures) =>
                {
                    self.follow_rotation().await;
                }
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
