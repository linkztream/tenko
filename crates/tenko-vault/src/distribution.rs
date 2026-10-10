//! KEK distribution and online rotation in a cluster of controllers (ADR 0014, S3-Q5, R22).
//!
//! # Pieces
//!
//! - [`KekPeers`]: how a controller asks a member for the installation's generations. The
//!   cluster transport implements it over `Cluster.TransferKek` with an empty join token
//!   (a fetch); the answer is sealed to a one-time key of the asking controller
//!   ([`crate::transfer`]).
//! - [`fetch_missing`]: start step 3 (`cluster`). A controller that was stopped during an
//!   online rotation fetches the generations the replicated state lists and it lacks, and
//!   seals them with its own provider, before the vault opens.
//! - [`KekAdmin`]: the KEK service of one controller: its status (`GET /system/kek`, the
//!   fragment of `/system/status`), the request of an online rotation
//!   (`POST /system/kek/rotate`), and [`KekAdmin::run`], the task every controller runs to
//!   follow the replicated state: fetch a new generation, acknowledge it, switch to it when
//!   it becomes active.
//! - [`KekAdmin::rotation_service`]: the leader-only service that performs an online
//!   rotation in two phases.
//!
//! # Online rotation
//!
//! 1. An administrator asks for it; the request is a record in `vault.kek_state`, so any
//!    controller takes it and the leader carries it out.
//! 2. **Distribute.** The leader creates the next generation with its provider, lists it
//!    as pending and acknowledges it. Every running controller sees the pending generation,
//!    fetches it from a member, seals it with its own provider and acknowledges it. The
//!    leader waits for every member it can reach (contact within the last ten seconds);
//!    members it cannot reach are recorded and fetch the generation when they start. A
//!    reachable member that does not acknowledge within two minutes fails the rotation;
//!    nothing changed for the envelopes then.
//! 3. **Activate and re-wrap.** In one batch the leader bumps
//!    [`KEK_EPOCH`](crate::KEK_EPOCH) and makes the new generation active; every
//!    controller switches on the state change, and a write that encrypted under the old
//!    generation fails its epoch precondition and is redone. The leader re-wraps every
//!    envelope in paged batches and ends with the audit record `vault.kek.rotate`.
//!
//! Every write of the leader carries the leader epoch (`tenko_store::fence`), so a deposed
//! leader's writes fail; the next leader continues from the recorded phase.

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use futures::StreamExt;
use serde::Serialize;
use tenko_core::{
    NodeId, RequestCtx, SystemComponent, Timestamp,
    audit::AuditDraft,
    cluster::{LEADER_EPOCH, LeaderService},
};
use tenko_store::{
    FailedPrecondition, Precondition, ReadConsistency, ReadView, Store, StoreError, WatchFilter,
    WriteBatch, fence,
};
use tokio_util::sync::CancellationToken;

use crate::{
    KEK_EPOCH, StoreVault, VaultError, actions,
    kek::{KekConfig, KekOptions, KekProtection, KekRing},
    kek_state::{
        self, DOWNGRADE_CODE, KekAck, KekGeneration, KekState, RotationPhase, RotationRecord,
    },
    store_vault::Refresh,
    transfer::{self, SealedKeks, TransferKey},
};

/// A member counts as reachable when the leader heard from it within this time.
pub const REACHABLE_MS: u64 = 10_000;
/// How long the leader waits for reachable members to take a new generation.
pub const DISTRIBUTE_TIMEOUT: Duration = Duration::from_secs(120);
/// How often a controller compares its keys with the replicated state without a change.
const RESYNC: Duration = Duration::from_secs(30);
/// The pause after a failed round.
const BACKOFF: Duration = Duration::from_secs(5);
/// The pause of the rotation service between checks while it waits.
const TICK: Duration = Duration::from_secs(1);

/// How a controller reaches the members of its cluster for KEK generations.
#[async_trait::async_trait]
pub trait KekPeers: Send + Sync + 'static {
    /// Asks a member that holds the installation's generations (the leader first, then
    /// the others) for all of them, sealed to `recipient` under
    /// [`transfer::fetch_context`] of this controller: `Cluster.TransferKek` with the
    /// one-time public key and an empty join token.
    ///
    /// # Errors
    ///
    /// [`VaultError::KekUnavailable`] when no member answers, or the transfer's error.
    async fn fetch(
        &self,
        recipient: [u8; transfer::PUBLIC_KEY_LEN],
    ) -> Result<SealedKeks, VaultError>;
}

/// The peers of a single controller: there are none.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPeers;

#[async_trait::async_trait]
impl KekPeers for NoPeers {
    async fn fetch(
        &self,
        _recipient: [u8; transfer::PUBLIC_KEY_LEN],
    ) -> Result<SealedKeks, VaultError> {
        Err(VaultError::kek_unavailable(
            "no cluster member to fetch key generations from",
        ))
    }
}

/// Fetches every generation from a member and seals the ones this host lacks with its
/// provider; returns the ring loaded afterwards.
async fn fetch_and_import(
    config: &KekConfig,
    options: &KekOptions,
    node: NodeId,
    peers: &dyn KekPeers,
) -> Result<KekRing, VaultError> {
    let key = TransferKey::generate()?;
    let sealed = peers.fetch(key.public_key()).await?;
    let received = key.open(
        sealed.format,
        &sealed.sealed,
        &transfer::fetch_context(node),
    )?;
    let config = config.clone();
    let options = options.clone();
    let ring = tokio::task::spawn_blocking(move || config.import_with(&received, &options))
        .await
        .map_err(|error| VaultError::kek_unavailable(format!("import task: {error}")))??;
    tracing::info!(
        generations = ring.ids().count(),
        "key generations received from a cluster member"
    );
    Ok(ring)
}

/// The generations the state lists that `ring` lacks.
fn missing(state: &KekState, ring: &KekRing) -> Vec<String> {
    state
        .ids()
        .filter(|id| !ring.contains(id))
        .map(str::to_owned)
        .collect()
}

/// Start step 3 (`cluster`): fetches the generations that the installation's KEK state
/// lists and `ring` lacks (a controller that was stopped during an online rotation),
/// seals them with this host's provider and returns the reloaded ring. Without a state, or
/// with nothing missing, returns `ring` unchanged and contacts nobody.
///
/// # Errors
///
/// [`VaultError::KekUnavailable`] when generations are missing and no member hands them
/// over (the vault would not open), a transfer or provider error, or the store's error.
pub async fn fetch_missing(
    store: &dyn Store,
    config: &KekConfig,
    options: &KekOptions,
    ring: KekRing,
    node: NodeId,
    peers: &dyn KekPeers,
) -> Result<KekRing, VaultError> {
    let view = store.read(ReadConsistency::Local).await?;
    let Some((state, _)) = kek_state::read_state(view.as_ref())? else {
        return Ok(ring);
    };
    let wanted = missing(&state, &ring);
    if wanted.is_empty() {
        return Ok(ring);
    }
    tracing::info!(missing = %wanted.join(","), "fetching key generations from a cluster member");
    fetch_and_import(config, options, node, peers).await?;
    let config = config.clone();
    let options = options.clone();
    let reloaded =
        tokio::task::spawn_blocking(move || config.load_with(crate::KekInit::Require, &options))
            .await
            .map_err(|error| VaultError::kek_unavailable(format!("load task: {error}")))??;
    let still = missing(&state, &reloaded);
    if still.is_empty() {
        Ok(reloaded)
    } else {
        Err(VaultError::kek_unavailable(format!(
            "the cluster member did not hand over the key generations {}",
            still.join(", ")
        )))
    }
}

/// A condition of the KEK an administrator should look at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KekWarning {
    /// The stable code: `vault.kek.weak`, `vault.kek.downgrade`, `vault.kek.missing` or
    /// `vault.kek.rotation_failed`.
    pub code: String,
    /// An English description.
    pub detail: String,
    /// Parameters for a localized message.
    pub params: BTreeMap<String, String>,
}

impl KekWarning {
    fn new(code: &str, detail: impl Into<String>, params: &[(&str, String)]) -> Self {
        Self {
            code: code.to_owned(),
            detail: detail.into(),
            params: params
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.clone()))
                .collect(),
        }
    }
}

/// One generation as the status shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GenerationStatus {
    /// The identifier.
    pub id: String,
    /// Whether it wraps new data keys.
    pub active: bool,
    /// Whether this controller holds it.
    pub loaded: bool,
    /// How this controller protects it (when loaded).
    pub protection: Option<KekProtection>,
    /// When the installation listed it.
    pub created_at: Option<Timestamp>,
}

/// A generation file the load refused (R15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefusedStatus {
    /// The generation number of the file.
    pub generation: u32,
    /// The file name.
    pub file: String,
    /// Its protection (plain).
    pub protection: KekProtection,
}

/// How one controller protects its KEK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControllerProtection {
    /// The controller.
    pub node: NodeId,
    /// Its provider.
    pub provider: String,
    /// The protection at its last start.
    pub protection: KekProtection,
    /// The strongest protection it ever had.
    pub strongest: KekProtection,
    /// When it last started.
    pub updated_at: Timestamp,
}

/// The KEK status of one controller and of the installation (`GET /system/kek`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KekStatus {
    /// This controller.
    pub node: NodeId,
    /// Its provider.
    pub provider: String,
    /// The protection of its active KEK.
    pub protection: KekProtection,
    /// The active generation.
    pub active: String,
    /// The KEK epoch of the active generation.
    pub epoch: u64,
    /// Every generation of the installation and every generation loaded here, oldest
    /// first.
    pub generations: Vec<GenerationStatus>,
    /// Generations of the installation this controller does not hold.
    pub missing: Vec<String>,
    /// Plain generation files this controller refused (R15).
    pub refused: Vec<RefusedStatus>,
    /// The strongest protection this controller ever had.
    pub strongest: Option<KekProtection>,
    /// The protection of every controller.
    pub controllers: Vec<ControllerProtection>,
    /// The online rotation in progress, or the last one.
    pub rotation: Option<RotationRecord>,
    /// Conditions to look at.
    pub warnings: Vec<KekWarning>,
}

/// The KEK fragment of `/system/status` (computed when the state changes, read without
/// I/O).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KekSummary {
    /// This controller's provider.
    pub provider: String,
    /// The protection of its active KEK.
    pub protection: KekProtection,
    /// The active generation.
    pub active: String,
    /// The number of generations loaded here.
    pub generations: usize,
    /// The KEK epoch.
    pub epoch: u64,
    /// The phase of a running or the last online rotation.
    pub rotation: Option<RotationPhase>,
    /// Conditions to look at.
    pub warnings: Vec<KekWarning>,
}

impl From<&KekStatus> for KekSummary {
    fn from(status: &KekStatus) -> Self {
        Self {
            provider: status.provider.clone(),
            protection: status.protection,
            active: status.active.clone(),
            generations: status.generations.iter().filter(|g| g.loaded).count(),
            epoch: status.epoch,
            rotation: status.rotation.as_ref().map(|rotation| rotation.phase),
            warnings: status.warnings.clone(),
        }
    }
}

/// What one step of the rotation service did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStep {
    /// Nothing to do now; wait for a change.
    Idle,
    /// A phase changed; run the next step at once.
    Advanced,
}

/// The KEK service of one controller.
pub struct KekAdmin {
    vault: Arc<StoreVault>,
    config: KekConfig,
    options: KekOptions,
    node: NodeId,
    peers: Arc<dyn KekPeers>,
    summary: RwLock<Option<KekSummary>>,
    distribute_timeout: RwLock<Duration>,
}

impl std::fmt::Debug for KekAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KekAdmin")
            .field("node", &self.node)
            .field("provider", &self.config.provider_name())
            .finish_non_exhaustive()
    }
}

impl KekAdmin {
    /// The service of controller `node` over its vault, its provider configuration and its
    /// peers ([`NoPeers`] on a single controller).
    pub fn new(
        vault: Arc<StoreVault>,
        config: KekConfig,
        options: KekOptions,
        node: NodeId,
        peers: Arc<dyn KekPeers>,
    ) -> Arc<Self> {
        Arc::new(Self {
            vault,
            config,
            options,
            node,
            peers,
            summary: RwLock::new(None),
            distribute_timeout: RwLock::new(DISTRIBUTE_TIMEOUT),
        })
    }

    /// Changes how long the leader waits for reachable members to take a new generation
    /// (default [`DISTRIBUTE_TIMEOUT`]).
    pub fn set_distribute_timeout(&self, timeout: Duration) {
        *self
            .distribute_timeout
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = timeout;
    }

    fn distribute_timeout(&self) -> Duration {
        *self
            .distribute_timeout
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The vault.
    pub fn vault(&self) -> &Arc<StoreVault> {
        &self.vault
    }

    /// This controller.
    pub fn node(&self) -> NodeId {
        self.node
    }

    /// The status of this controller and of the installation.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn status(&self) -> Result<KekStatus, VaultError> {
        let view = self.vault.store().read(ReadConsistency::Local).await?;
        let status = self.build_status(view.as_ref())?;
        self.cache(&status);
        Ok(status)
    }

    /// The KEK fragment of `/system/status` as of the last change this controller saw;
    /// `None` before the first one.
    pub fn summary(&self) -> Option<KekSummary> {
        self.summary
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn cache(&self, status: &KekStatus) {
        *self
            .summary
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(KekSummary::from(status));
    }

    fn build_status(&self, view: &dyn ReadView) -> Result<KekStatus, VaultError> {
        let ring = self.vault.ring();
        let active = ring.active();
        let state = kek_state::read_state(view)?.map(|(state, _)| state);
        let epoch = self
            .vault
            .epoch()
            .map_or_else(|| view.counter(&KEK_EPOCH), Ok)?;
        let mut generations = Vec::new();
        let mut push = |id: &str| {
            if generations.iter().any(|g: &GenerationStatus| g.id == id) {
                return;
            }
            let loaded = ring.get(id);
            generations.push(GenerationStatus {
                id: id.to_owned(),
                active: id == active.id(),
                loaded: loaded.is_some(),
                protection: loaded.map(|kek| kek.protection()),
                created_at: state.as_ref().and_then(|state| state.created_at(id)),
            });
        };
        if let Some(state) = &state {
            for id in state.ids() {
                push(id);
            }
        }
        for id in ring.ids() {
            push(id);
        }
        let missing = state
            .as_ref()
            .map(|state| missing(state, &ring))
            .unwrap_or_default();
        let refused: Vec<RefusedStatus> = ring
            .refused()
            .iter()
            .map(|refused| RefusedStatus {
                generation: refused.generation,
                file: refused
                    .path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                protection: refused.protection,
            })
            .collect();
        let controllers: Vec<ControllerProtection> = kek_state::protection_records(view)?
            .into_iter()
            .map(|(node, record)| ControllerProtection {
                node,
                provider: record.provider,
                protection: record.current,
                strongest: record.strongest,
                updated_at: record.updated_at,
            })
            .collect();
        let own = kek_state::read_protection(view, self.node)?.map(|(record, _)| record);
        let protection = active.protection();
        let rotation = state.as_ref().and_then(|state| state.rotation.clone());
        let warnings = warnings(
            protection,
            own.as_ref(),
            &refused,
            &missing,
            rotation.as_ref(),
        );
        Ok(KekStatus {
            node: self.node,
            provider: self.config.provider_name().to_owned(),
            protection,
            active: active.id().to_owned(),
            epoch,
            generations,
            missing,
            refused,
            strongest: own.map(|own| own.strongest),
            controllers,
            rotation,
            warnings,
        })
    }

    /// Asks for an online rotation (`POST /system/kek/rotate`): records the request in the
    /// installation's KEK state with the audit record `vault.kek.rotate_request`; the
    /// leader carries it out. The caller checks the administrator's rights and the
    /// step-up.
    ///
    /// # Errors
    ///
    /// [`VaultError::RotationInProgress`] while a rotation runs, or the store's error (a
    /// concurrent request answers a precondition failure).
    pub async fn request_rotation(&self, ctx: &RequestCtx) -> Result<KekStatus, VaultError> {
        let view = self.vault.store().read(ReadConsistency::Local).await?;
        let mut batch = WriteBatch::for_request(ctx);
        batch.idempotency = None;
        let mut state = if let Some((state, revision)) = kek_state::read_state(view.as_ref())? {
            batch.expect_typed(&kek_state::tables::STATE, &(), Some(revision));
            state
        } else {
            batch.expect_typed(&kek_state::tables::STATE, &(), None);
            let ring = self.vault.ring();
            let active = ring.active().id().to_owned();
            let mut state = KekState {
                epoch: view.counter(&KEK_EPOCH)?,
                active: active.clone(),
                generations: Vec::new(),
                pending: None,
                rotation: None,
                abandoned: Vec::new(),
            };
            for id in ring.ids().filter(|id| *id != active) {
                state.list(id, ctx.now, None);
            }
            state.list(&active, ctx.now, Some(self.node));
            state
        };
        if state.rotating() {
            return Err(VaultError::RotationInProgress);
        }
        state.rotation = Some(RotationRecord::requested(ctx.now, ctx.principal.subject()));
        batch.put_typed(&kek_state::tables::STATE, &(), &state)?;
        batch.audit(
            AuditDraft::success(kek_state::actions::ROTATE_REQUEST, Vec::new())
                .with_source_ip(ctx.source_ip)
                .with_context("kek", state.active.clone())
                .with_context("epoch", state.epoch.to_string()),
        );
        self.vault.store().propose(batch).await?;
        self.status().await
    }

    /// One round of following the replicated state: fetches generations this controller
    /// lacks, switches to the active one, acknowledges a pending one it holds, and
    /// refreshes the summary.
    ///
    /// # Errors
    ///
    /// A fetch, provider or store error; the next round tries again.
    pub async fn sync_once(&self) -> Result<(), VaultError> {
        let store = self.vault.store();
        let view = store.read(ReadConsistency::Local).await?;
        let epoch = view.counter(&KEK_EPOCH)?;
        let Some((state, _)) = kek_state::read_state(view.as_ref())? else {
            let status = self.build_status(view.as_ref())?;
            self.cache(&status);
            return Ok(());
        };
        let mut result = Ok(());
        if !missing(&state, &self.vault.ring()).is_empty() {
            match fetch_and_import(&self.config, &self.options, self.node, self.peers.as_ref())
                .await
            {
                Ok(ring) => self.vault.merge(&ring),
                Err(error) => result = Err(error),
            }
        }
        if let Refresh::Missing { id } = self.vault.apply_state(&state, epoch) {
            tracing::warn!(kek = %id, "the active key generation of the installation is not on this controller yet");
        }
        if let Some(pending) = &state.pending
            && self.vault.ring().contains(&pending.id)
            && !kek_state::acks_of(view.as_ref(), &pending.id)?.contains(&self.node)
        {
            let ctx = RequestCtx::system(SystemComponent::Vault);
            let mut batch = WriteBatch::for_request(&ctx);
            batch.expect_typed(
                &kek_state::tables::ACKS,
                &(pending.id.clone(), self.node),
                None,
            );
            batch.put_typed(
                &kek_state::tables::ACKS,
                &(pending.id.clone(), self.node),
                &KekAck { at: ctx.now },
            )?;
            match store.propose(batch).await {
                Ok(_) => tracing::info!(kek = %pending.id, "acknowledged a new key generation"),
                Err(StoreError::PreconditionFailed(_)) => {}
                Err(error) => result = Err(error.into()),
            }
        }
        let view = store.read(ReadConsistency::Local).await?;
        let status = self.build_status(view.as_ref())?;
        self.cache(&status);
        result
    }

    /// The task every controller runs (after the vault step) until `stop`: one
    /// [`sync_once`](KekAdmin::sync_once) at start, then one after every change of the
    /// KEK state and every 30 seconds.
    pub async fn run(self: Arc<Self>, stop: CancellationToken) {
        let filter = WatchFilter::tables([kek_state::tables::STATE.name().clone()]);
        let mut changes = None;
        loop {
            if changes.is_none() {
                changes = self.vault.store().watch(None, filter.clone()).ok();
            }
            let pause = match self.sync_once().await {
                Ok(()) => RESYNC,
                Err(error) => {
                    tracing::warn!(%error, "could not follow the key-encryption key state");
                    BACKOFF
                }
            };
            let next = async {
                match changes.as_mut() {
                    Some(stream) => stream.next().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(pause) => {}
                change = next => {
                    if !matches!(change, Some(Ok(_))) {
                        changes = None;
                    }
                }
            }
        }
    }

    /// The leader-only service of online rotations (`vault.kek_rotation`).
    pub fn rotation_service(self: &Arc<Self>) -> Arc<dyn LeaderService> {
        Arc::new(RotationService {
            admin: Arc::clone(self),
        })
    }

    /// One step of the online rotation on the leader, fenced by `leader_epoch`.
    ///
    /// # Errors
    ///
    /// A provider or store error; a precondition failure on the leader epoch means this
    /// controller was deposed ([`deposed`]).
    pub async fn rotation_step(&self, leader_epoch: u64) -> Result<RotationStep, VaultError> {
        let store = self.vault.store();
        let view = store.read(ReadConsistency::Local).await?;
        let Some((state, revision)) = kek_state::read_state(view.as_ref())? else {
            return Ok(RotationStep::Idle);
        };
        let Some(rotation) = state.rotation.clone() else {
            return Ok(RotationStep::Idle);
        };
        let ctx = RequestCtx::system(SystemComponent::Vault);
        let guard = fence(leader_epoch);
        match rotation.phase {
            RotationPhase::Requested => {
                self.create_generation(&ctx, &guard, state, revision, rotation)
                    .await
            }
            RotationPhase::Distributing => {
                self.distribute(&ctx, &guard, view.as_ref(), state, revision, rotation)
                    .await
            }
            RotationPhase::Rewrapping => self.rewrap(&ctx, &guard, state).await,
            RotationPhase::Done | RotationPhase::Failed => Ok(RotationStep::Idle),
        }
    }

    /// Phase 1: the new generation, created with this controller's provider.
    async fn create_generation(
        &self,
        ctx: &RequestCtx,
        guard: &Precondition,
        mut state: KekState,
        revision: tenko_core::Revision,
        mut rotation: RotationRecord,
    ) -> Result<RotationStep, VaultError> {
        let config = self.config.clone();
        let options = self.options.clone();
        let created = tokio::task::spawn_blocking(move || config.create_next_with(&options))
            .await
            .map_err(|error| VaultError::kek_unavailable(format!("create task: {error}")))?;
        let kek = match created {
            Ok(kek) => kek,
            Err(error) => {
                tracing::error!(%error, "the key rotation could not create a new generation");
                rotation.phase = RotationPhase::Failed;
                rotation.error = Some(error.to_string());
                rotation.updated_at = ctx.now;
                rotation.finished_at = Some(ctx.now);
                state.rotation = Some(rotation);
                self.write_state(
                    ctx,
                    guard,
                    &state,
                    revision,
                    Some(failed_audit(&error.to_string())),
                )
                .await?;
                return Ok(RotationStep::Advanced);
            }
        };
        self.vault.merge(&KekRing::new(Arc::clone(&kek)));
        let id = kek.id().to_owned();
        state.pending = Some(KekGeneration {
            id: id.clone(),
            created_at: ctx.now,
            created_by: Some(self.node),
        });
        rotation.phase = RotationPhase::Distributing;
        rotation.generation = Some(id.clone());
        rotation.distributing_since = Some(ctx.now);
        rotation.updated_at = ctx.now;
        state.rotation = Some(rotation);
        let mut batch = Self::leader_batch(ctx, guard);
        batch.expect_typed(&kek_state::tables::STATE, &(), Some(revision));
        batch.put_typed(&kek_state::tables::STATE, &(), &state)?;
        batch.put_typed(
            &kek_state::tables::ACKS,
            &(id.clone(), self.node),
            &KekAck { at: ctx.now },
        )?;
        self.vault.store().propose(batch).await?;
        tracing::info!(kek = %id, "key rotation: distributing a new generation");
        Ok(RotationStep::Advanced)
    }

    /// Phase 2: wait for the reachable members, then activate.
    async fn distribute(
        &self,
        ctx: &RequestCtx,
        guard: &Precondition,
        view: &dyn ReadView,
        mut state: KekState,
        revision: tenko_core::Revision,
        mut rotation: RotationRecord,
    ) -> Result<RotationStep, VaultError> {
        let Some(pending) = state.pending.clone() else {
            let error = "the new key generation is missing from the state";
            rotation.phase = RotationPhase::Failed;
            rotation.error = Some(error.to_owned());
            rotation.updated_at = ctx.now;
            rotation.finished_at = Some(ctx.now);
            state.rotation = Some(rotation);
            self.write_state(ctx, guard, &state, revision, Some(failed_audit(error)))
                .await?;
            return Ok(RotationStep::Advanced);
        };
        if !self.vault.ring().contains(&pending.id) {
            // A new leader that has not fetched the generation yet: its own sync does.
            return Ok(RotationStep::Idle);
        }
        let acks = kek_state::acks_of(view, &pending.id)?;
        let mut waiting = Vec::new();
        let mut unreachable = Vec::new();
        for member in self.vault.store().status().members {
            if member.node == self.node || acks.contains(&member.node) {
                continue;
            }
            if member.last_contact_ms.is_some_and(|ms| ms <= REACHABLE_MS) {
                waiting.push(member.node);
            } else {
                unreachable.push(member.node);
            }
        }
        if waiting.is_empty() {
            return self
                .activate(
                    ctx,
                    guard,
                    view,
                    state,
                    revision,
                    rotation,
                    pending,
                    unreachable,
                )
                .await;
        }
        let since = rotation.distributing_since.unwrap_or(rotation.updated_at);
        let timeout = self.distribute_timeout();
        if ctx.now.saturating_since(since) > timeout {
            let error = format!(
                "the controllers {} did not take the new key generation within {} seconds",
                nodes(&waiting),
                timeout.as_secs()
            );
            tracing::error!("key rotation failed: {error}");
            rotation.phase = RotationPhase::Failed;
            rotation.error = Some(error.clone());
            rotation.waiting_for = waiting;
            rotation.unreachable = unreachable;
            rotation.updated_at = ctx.now;
            rotation.finished_at = Some(ctx.now);
            state.rotation = Some(rotation);
            state.abandon_pending();
            self.write_state(ctx, guard, &state, revision, Some(failed_audit(&error)))
                .await?;
            return Ok(RotationStep::Advanced);
        }
        if rotation.waiting_for != waiting || rotation.unreachable != unreachable {
            rotation.waiting_for = waiting;
            rotation.unreachable = unreachable;
            rotation.updated_at = ctx.now;
            state.rotation = Some(rotation);
            self.write_state(ctx, guard, &state, revision, None).await?;
        }
        Ok(RotationStep::Idle)
    }

    /// The new generation becomes active, with a new KEK epoch.
    #[allow(clippy::too_many_arguments)]
    async fn activate(
        &self,
        ctx: &RequestCtx,
        guard: &Precondition,
        view: &dyn ReadView,
        mut state: KekState,
        revision: tenko_core::Revision,
        mut rotation: RotationRecord,
        pending: KekGeneration,
        unreachable: Vec<tenko_core::NodeId>,
    ) -> Result<RotationStep, VaultError> {
        let epoch = view.counter(&KEK_EPOCH)?;
        if !state.generations.iter().any(|g| g.id == pending.id) {
            state.generations.push(pending.clone());
        }
        pending.id.clone_into(&mut state.active);
        state.epoch = epoch + 1;
        state.pending = None;
        rotation.phase = RotationPhase::Rewrapping;
        rotation.waiting_for = Vec::new();
        rotation.unreachable.clone_from(&unreachable);
        rotation.updated_at = ctx.now;
        state.rotation = Some(rotation);
        let mut batch = Self::leader_batch(ctx, guard);
        batch
            .expect_counter(KEK_EPOCH, epoch)
            .bump(KEK_EPOCH)
            .expect_typed(&kek_state::tables::STATE, &(), Some(revision));
        batch.put_typed(&kek_state::tables::STATE, &(), &state)?;
        batch.audit(
            AuditDraft::success(kek_state::actions::ACTIVATE, Vec::new())
                .with_context("kek", pending.id.clone())
                .with_context("epoch", state.epoch.to_string())
                .with_context("cause", "rotation")
                .with_context("unreachable", nodes(&unreachable)),
        );
        self.vault.store().propose(batch).await?;
        self.vault.apply_state(&state, state.epoch);
        tracing::info!(kek = %pending.id, epoch = state.epoch, "key rotation: new generation active");
        Ok(RotationStep::Advanced)
    }

    /// Phase 3: re-wrap every envelope, then record the end.
    async fn rewrap(
        &self,
        ctx: &RequestCtx,
        guard: &Precondition,
        state: KekState,
    ) -> Result<RotationStep, VaultError> {
        if let Refresh::Missing { .. } = self.vault.apply_state(&state, state.epoch) {
            return Ok(RotationStep::Idle);
        }
        let ring = self.vault.ring();
        let rewrapped = self
            .vault
            .rewrap_all(ctx, &ring, state.epoch, Some(guard), |_| {})
            .await?;
        let view = self.vault.store().read(ReadConsistency::Local).await?;
        let Some((mut state, revision)) = kek_state::read_state(view.as_ref())? else {
            return Ok(RotationStep::Idle);
        };
        let Some(mut rotation) = state.rotation.clone() else {
            return Ok(RotationStep::Idle);
        };
        rotation.phase = RotationPhase::Done;
        rotation.rewrapped = rotation.rewrapped.saturating_add(rewrapped as u64);
        rotation.updated_at = ctx.now;
        rotation.finished_at = Some(ctx.now);
        state.rotation = Some(rotation);
        state.keep_active_only();
        let retired: Vec<String> = ring.retired_ids().map(str::to_owned).collect();
        let audit = AuditDraft::success(actions::ROTATE_KEK, Vec::new())
            .with_context("kek", state.active.clone())
            .with_context("retired", retired.join(","))
            .with_context("rewrapped", rewrapped.to_string())
            .with_context("epoch", state.epoch.to_string())
            .with_context("online", "true");
        self.write_state(ctx, guard, &state, revision, Some(audit))
            .await?;
        tracing::info!(kek = %state.active, rewrapped, "key rotation finished");
        Ok(RotationStep::Idle)
    }

    fn leader_batch(ctx: &RequestCtx, guard: &Precondition) -> WriteBatch {
        let mut batch = WriteBatch::for_request(ctx);
        batch.idempotency = None;
        batch.preconditions.push(guard.clone());
        batch
    }

    async fn write_state(
        &self,
        ctx: &RequestCtx,
        guard: &Precondition,
        state: &KekState,
        revision: tenko_core::Revision,
        audit: Option<AuditDraft>,
    ) -> Result<(), VaultError> {
        let mut batch = Self::leader_batch(ctx, guard);
        batch.expect_typed(&kek_state::tables::STATE, &(), Some(revision));
        batch.put_typed(&kek_state::tables::STATE, &(), state)?;
        if let Some(audit) = audit {
            batch.audit(audit);
        }
        self.vault.store().propose(batch).await?;
        Ok(())
    }
}

/// The conditions of a controller's KEK an administrator should look at.
fn warnings(
    protection: KekProtection,
    own: Option<&kek_state::ProtectionRecord>,
    refused: &[RefusedStatus],
    missing: &[String],
    rotation: Option<&RotationRecord>,
) -> Vec<KekWarning> {
    let mut warnings = Vec::new();
    if protection.is_weak() {
        warnings.push(KekWarning::new(
            "vault.kek.weak",
            format!(
                "the active key-encryption key of this controller has no OS protection \
                 ({})",
                protection.describe()
            ),
            &[("protection", protection.code().to_owned())],
        ));
    }
    if let Some(own) = own
        && protection.rank() < own.strongest.rank()
    {
        warnings.push(KekWarning::new(
            DOWNGRADE_CODE,
            format!(
                "the key-encryption key of this controller is protected by {}, weaker than \
                 {} before",
                protection.describe(),
                own.strongest.describe()
            ),
            &[
                ("cause", "provider".to_owned()),
                ("from", own.strongest.code().to_owned()),
                ("to", protection.code().to_owned()),
            ],
        ));
    }
    for refused in refused {
        warnings.push(KekWarning::new(
            DOWNGRADE_CODE,
            format!(
                "a plain key generation ({}) beside sealed ones was refused",
                refused.file
            ),
            &[
                ("cause", "plain_generation".to_owned()),
                ("generation", refused.generation.to_string()),
                ("file", refused.file.clone()),
            ],
        ));
    }
    if !missing.is_empty() {
        warnings.push(KekWarning::new(
            "vault.kek.missing",
            format!(
                "this controller lacks the key generations {}",
                missing.join(", ")
            ),
            &[("generations", missing.join(","))],
        ));
    }
    if let Some(rotation) = rotation
        && rotation.phase == RotationPhase::Failed
    {
        warnings.push(KekWarning::new(
            "vault.kek.rotation_failed",
            format!(
                "the last key rotation failed: {}",
                rotation.error.as_deref().unwrap_or("unknown")
            ),
            &[("error", rotation.error.clone().unwrap_or_default())],
        ));
    }
    warnings
}

fn failed_audit(error: &str) -> AuditDraft {
    AuditDraft::success(kek_state::actions::ROTATE_FAILED, Vec::new())
        .with_context("error", error.to_owned())
}

fn nodes(nodes: &[NodeId]) -> String {
    nodes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Whether an error says that this controller lost its term of office (a leader-only write
/// failed its leader epoch precondition).
pub fn deposed(error: &VaultError) -> bool {
    matches!(
        error,
        VaultError::Store(StoreError::PreconditionFailed(failures))
            if failures.iter().any(|failure| matches!(
                failure,
                FailedPrecondition::Counter { counter, .. } if *counter == LEADER_EPOCH
            ))
    )
}

/// The leader-only service of online rotations.
struct RotationService {
    admin: Arc<KekAdmin>,
}

#[async_trait::async_trait]
impl LeaderService for RotationService {
    fn name(&self) -> &'static str {
        "vault.kek_rotation"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let store = Arc::clone(self.admin.vault.store());
        let filter = WatchFilter::tables([
            kek_state::tables::STATE.name().clone(),
            kek_state::tables::ACKS.name().clone(),
        ]);
        let mut changes = None;
        loop {
            if changes.is_none() {
                changes = store.watch(None, filter.clone()).ok();
            }
            let pause = match self.admin.rotation_step(epoch).await {
                Ok(RotationStep::Advanced) => continue,
                Ok(RotationStep::Idle) => TICK,
                Err(error) if deposed(&error) => {
                    tracing::info!("key rotation: this controller is no longer the leader");
                    stop.cancelled().await;
                    return Ok(());
                }
                Err(error) => {
                    tracing::warn!(%error, "key rotation step failed; retrying");
                    BACKOFF
                }
            };
            let next = async {
                match changes.as_mut() {
                    Some(stream) => stream.next().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = tokio::time::sleep(pause) => {}
                change = next => {
                    if !matches!(change, Some(Ok(_))) {
                        changes = None;
                    }
                }
            }
        }
    }
}
