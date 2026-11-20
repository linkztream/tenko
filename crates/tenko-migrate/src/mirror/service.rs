//! The mirror service (plan sections 2.1 to 2.4 and 2.12, ADR 0033 decisions 1, 3, 5 to 8).
//!
//! The rows live in the replicated store; the freshness lives in this controller's memory
//! ([`Memory`]): the time of the last push, the last accepted sequence, the floor between two
//! pushes and the last refusal that was audited. A push whose content hashes like the stored
//! snapshot writes nothing, unless the row's freshness is older than
//! [`FRESHNESS_WRITE_SECS`]; a changed push writes the snapshot, the row and one audit
//! record in one batch. After a restart or on another controller the row's values stand in,
//! so a mirror reads as stale until its next push at most (decision 8).
//!
//! The content hash covers the envelope without its `sequence` and `taken_at`, which every
//! push changes: an unchanged source is an unchanged hash.

use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use ipnet::IpNet;
use serde::Serialize;
use tenko_auth::{AuthService, service::types::CreatedToken};
use tenko_core::{
    MirrorId, Revision, Timestamp, UserId,
    audit::AuditDraft,
    codec::{canonical_sha256, encode_key},
    ipam::Stamp,
    ir::{LossEntry, MirrorOrigin, MirrorSnapshot, SourceKindLabel},
    metrics::{GaugeVec, Registry},
    migrate::{
        DEFAULT_INTERVAL_SECS, FRESHNESS_WRITE_SECS, LossAck, MAX_LOSSES, MIN_PUSH_INTERVAL_SECS,
        Mirror, Snapshot, TOKEN_EXPIRING_DAYS, TakeoverState, audit, findings, metrics,
        mirror_object, tables,
    },
    serde_util::{HexBytes, to_hex},
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError, WriteBatch,
};

use super::{
    MirrorError, MirrorItem, MirrorLossItem, MirrorLosses, MirrorPatch, MirroredScope, ScopeDiff,
    SnapshotAccepted, SnapshotCounts,
};

/// The mirrors with metric series (three push outcomes and one age each).
const MIRROR_SLOTS: u16 = 32;

/// A refused push is audited at most this often per mirror (plan section 2.12).
const REFUSAL_AUDIT_SECS: u64 = 60;

/// `tenko_migrate_mirror_pushes_total{mirror, outcome}`, set from memory by the metrics timer.
pub static PUSHES: GaugeVec = GaugeVec::new(metrics::PUSHES);

/// `tenko_migrate_mirror_age_seconds{mirror}`, set by the metrics timer.
pub static AGE: GaugeVec = GaugeVec::new(metrics::AGE);

/// Seals the module's metric families and registers them.
pub fn register_metrics(registry: &Registry) {
    PUSHES.seal_slots(MIRROR_SLOTS * 3);
    AGE.seal_slots(MIRROR_SLOTS);
    registry.register(&PUSHES);
    registry.register(&AGE);
}

/// What the freshness of one mirror holds in this controller's memory.
#[derive(Debug, Default)]
struct Memory {
    /// The last push let through the floor, accepted or not.
    admitted: Option<Timestamp>,
    /// The last accepted push.
    pushed: Option<Timestamp>,
    /// The last accepted sequence.
    sequence: Option<u64>,
    /// The last refusal written to the audit log.
    refusal_audited: Option<Timestamp>,
    /// Pushes by outcome, in the order of `metrics::PUSH_OUTCOMES`.
    outcomes: [u64; 3],
    /// What the stored snapshot holds, by its hash.
    summary: Option<Arc<Summary>>,
}

/// What the card, the losses and the findings read of a stored snapshot, kept beside its
/// hash so that a card does not decode the snapshot.
#[derive(Debug)]
struct Summary {
    hash: Vec<u8>,
    counts: SnapshotCounts,
    source: MirrorOrigin,
    /// The loss entries' keys with the hash of each entry and its scope.
    losses: Vec<(String, Vec<u8>, Option<IpNet>)>,
    scopes: Vec<MirroredScope>,
}

impl Summary {
    fn of(hash: Vec<u8>, snapshot: &MirrorSnapshot) -> Result<Self, MirrorError> {
        let scopes: Vec<IpNet> = snapshot
            .dhcp
            .scopes
            .iter()
            .map(|scope| scope.cidr)
            .collect();
        let losses = snapshot
            .losses
            .entries
            .iter()
            .map(|entry| Ok((entry.key(), entry_hash(entry)?, entry_scope(entry, &scopes))))
            .collect::<Result<_, MirrorError>>()?;
        Ok(Self {
            hash,
            counts: SnapshotCounts {
                scopes: count(snapshot.dhcp.scopes.len()),
                reservations: count(snapshot.reservation_count()),
                leases: count(snapshot.dhcp.leases.len()),
                losses: count(snapshot.losses.entries.len()),
            },
            source: snapshot.source.clone(),
            losses,
            scopes: snapshot
                .dhcp
                .scopes
                .iter()
                .map(|scope| MirroredScope {
                    cidr: scope.cidr,
                    name: scope.name.clone(),
                    active: scope.active,
                })
                .collect(),
        })
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The hash of a snapshot's content: the envelope without its sequence and its time.
///
/// # Errors
///
/// A codec error.
pub fn content_hash(snapshot: &MirrorSnapshot) -> Result<Vec<u8>, MirrorError> {
    #[derive(Serialize)]
    struct Content<'a> {
        format: u16,
        source: &'a MirrorOrigin,
        dhcp: &'a tenko_core::ir::dhcp::DhcpIr,
        losses: &'a tenko_core::ir::LossReport,
    }
    Ok(canonical_sha256(&Content {
        format: snapshot.format,
        source: &snapshot.source,
        dhcp: &snapshot.dhcp,
        losses: &snapshot.losses,
    })?
    .to_vec())
}

fn entry_hash(entry: &LossEntry) -> Result<Vec<u8>, MirrorError> {
    Ok(canonical_sha256(entry)?.to_vec())
}

/// The scope a loss entry belongs to: the scope holding the first address its location's
/// column names (`ScopeId=192.0.2.0`, `IPAddress=192.0.2.198`); none when it names none, and
/// such an entry belongs to every scope.
pub fn entry_scope(entry: &LossEntry, scopes: &[IpNet]) -> Option<IpNet> {
    let column = entry.location.column.as_deref()?;
    column
        .split(',')
        .filter_map(|part| part.split_once('=')?.1.trim().parse::<IpAddr>().ok())
        .find_map(|ip| scopes.iter().find(|scope| scope.contains(&ip)).copied())
}

/// A health finding of the mirrors (plan section 2.12): the code and the names of the
/// mirrors it holds for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// One of `tenko_core::migrate::findings::ALL`.
    pub code: &'static str,
    /// The mirrors, by name.
    pub mirrors: Vec<String>,
}

/// A new mirror.
#[derive(Debug, Clone)]
pub struct NewMirror {
    /// The name.
    pub name: String,
    /// The kind of source.
    pub kind: SourceKindLabel,
    /// The expected interval; 60 s when absent.
    pub interval_secs: Option<u32>,
    /// The token's lifetime in days; the TGL-05 maximum when absent.
    pub token_expires_in_days: Option<u32>,
}

/// The mirror service. Shared as `Arc<MirrorService>`; the API reaches it as a request
/// extension.
pub struct MirrorService {
    store: Arc<dyn Store>,
    auth: Arc<AuthService>,
    memory: Mutex<HashMap<MirrorId, Memory>>,
    /// The floor between two pushes of one mirror, in seconds.
    floor_secs: u64,
}

impl std::fmt::Debug for MirrorService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MirrorService").finish_non_exhaustive()
    }
}

fn later(a: Option<Timestamp>, b: Option<Timestamp>) -> Option<Timestamp> {
    a.max(b)
}

impl MirrorService {
    /// A service over `store`, minting the mirrors' credentials through `auth`.
    pub fn new(store: Arc<dyn Store>, auth: Arc<AuthService>) -> Self {
        Self {
            store,
            auth,
            memory: Mutex::new(HashMap::new()),
            floor_secs: u64::from(MIN_PUSH_INTERVAL_SECS),
        }
    }

    /// The service with another floor between two pushes: the route tests, which run on the
    /// real clock, push without waiting with a floor of zero.
    #[must_use]
    pub fn with_floor(mut self, secs: u64) -> Self {
        self.floor_secs = secs;
        self
    }

    fn memory(&self) -> MutexGuard<'_, HashMap<MirrorId, Memory>> {
        self.memory.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn view(&self) -> Result<Arc<dyn ReadView>, MirrorError> {
        Ok(self.store.read(ReadConsistency::Local).await?)
    }

    fn row(view: &dyn ReadView, id: MirrorId) -> Result<(Mirror, Revision), MirrorError> {
        view.get_typed(&tables::MIRRORS, &id)?
            .ok_or(MirrorError::NotFound(id))
    }

    fn rows(view: &dyn ReadView) -> Result<Vec<Mirror>, MirrorError> {
        let mut rows: Vec<Mirror> = view
            .scan_typed(&tables::MIRRORS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, mirror, _)| mirror)
            .collect();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(rows)
    }

    /// The row with the freshness this controller holds in memory.
    fn fresh(&self, mut mirror: Mirror) -> Mirror {
        if let Some(memory) = self.memory().get(&mirror.id) {
            mirror.last_push = later(mirror.last_push, memory.pushed);
            mirror.last_sequence = mirror.last_sequence.max(memory.sequence);
        }
        mirror
    }

    fn summary(
        &self,
        view: &dyn ReadView,
        mirror: &Mirror,
    ) -> Result<Option<Arc<Summary>>, MirrorError> {
        let Some(hash) = &mirror.last_hash else {
            return Ok(None);
        };
        if let Some(summary) = self
            .memory()
            .get(&mirror.id)
            .and_then(|memory| memory.summary.clone())
            .filter(|summary| summary.hash == hash.0)
        {
            return Ok(Some(summary));
        }
        let Some((snapshot, _)) = view.get_typed(&tables::SNAPSHOTS, &mirror.id)? else {
            return Ok(None);
        };
        let summary = Arc::new(Summary::of(snapshot.hash.0.clone(), &snapshot.envelope)?);
        self.memory().entry(mirror.id).or_default().summary = Some(Arc::clone(&summary));
        Ok(Some(summary))
    }

    fn acks(view: &dyn ReadView, id: MirrorId) -> Result<BTreeMap<String, LossAck>, MirrorError> {
        Ok(view
            .scan_typed(
                &tables::LOSS_ACKS,
                KeyRange::prefix(encode_key(&(id,))),
                MAX_LOSSES,
                false,
            )?
            .into_iter()
            .map(|((_, key), ack, _)| (key, ack))
            .collect())
    }

    /// The entries of `summary` that no acknowledgment holds for, within `scope` when given
    /// (an entry without a scope counts for every scope).
    fn open(summary: &Summary, acks: &BTreeMap<String, LossAck>, scope: Option<IpNet>) -> u32 {
        count(
            summary
                .losses
                .iter()
                .filter(|(key, hash, of)| {
                    scope.is_none_or(|scope| of.is_none_or(|of| of == scope))
                        && acks.get(key).is_none_or(|ack| ack.entry_hash.0 != *hash)
                })
                .count(),
        )
    }

    fn item(
        &self,
        view: &dyn ReadView,
        mirror: Mirror,
        now: Timestamp,
    ) -> Result<MirrorItem, MirrorError> {
        let mirror = self.fresh(mirror);
        let summary = self.summary(view, &mirror)?;
        let losses_open = match &summary {
            Some(summary) => Self::open(summary, &Self::acks(view, mirror.id)?, None),
            None => 0,
        };
        Ok(MirrorItem {
            age_secs: mirror
                .last_push
                .map(|at| now.saturating_since(at).as_secs()),
            stale: mirror.is_stale(now),
            token_expires_at: AuthService::scoped_token_expiry(view, mirror.account, mirror.token)?,
            counts: summary.as_ref().map(|summary| summary.counts),
            source: summary.as_ref().map(|summary| summary.source.clone()),
            scopes: summary
                .as_ref()
                .map(|summary| summary.scopes.clone())
                .unwrap_or_default(),
            ca_fingerprint: None,
            losses_open,
            mirror,
        })
    }

    /// Every mirror, by name.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn list(&self, now: Timestamp) -> Result<Vec<MirrorItem>, MirrorError> {
        let view = self.view().await?;
        Self::rows(view.as_ref())?
            .into_iter()
            .map(|mirror| self.item(view.as_ref(), mirror, now))
            .collect()
    }

    /// One mirror.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotFound`], a store error.
    pub async fn get(&self, id: MirrorId, now: Timestamp) -> Result<MirrorItem, MirrorError> {
        let view = self.view().await?;
        let (mirror, _) = Self::row(view.as_ref(), id)?;
        self.item(view.as_ref(), mirror, now)
    }

    fn name_free(
        view: &dyn ReadView,
        name: &str,
        other_than: Option<MirrorId>,
    ) -> Result<(), MirrorError> {
        if Self::rows(view)?
            .iter()
            .any(|mirror| mirror.name == name && Some(mirror.id) != other_than)
        {
            return Err(MirrorError::Exists(name.to_owned()));
        }
        Ok(())
    }

    fn settings(mirror: &Mirror) -> Result<(), MirrorError> {
        mirror.validate().map_err(|error| match error {
            tenko_core::migrate::MigrateError::Invalid { field, reason } => {
                MirrorError::Settings { field, reason }
            }
        })
    }

    async fn commit(&self, batch: WriteBatch, name: &str) -> Result<Revision, MirrorError> {
        match self.store.propose(batch).await {
            Ok(committed) => Ok(committed.revision),
            Err(StoreError::PreconditionFailed(_)) => Err(MirrorError::Exists(name.to_owned())),
            Err(error) => Err(error.into()),
        }
    }

    /// Creates a mirror with its service account and token (plan section 2.1, rule 2);
    /// audited as `migrate.mirror.create`.
    ///
    /// # Errors
    ///
    /// [`MirrorError::Settings`], [`MirrorError::Exists`], the minting's errors (a session
    /// that signed in within five minutes), a store error.
    pub async fn create(
        &self,
        ctx: &tenko_core::RequestCtx,
        new: NewMirror,
    ) -> Result<(MirrorItem, CreatedToken), MirrorError> {
        let stamp = Stamp::new(ctx.now, ctx.principal.clone());
        let mut mirror = Mirror {
            id: MirrorId::generate(),
            name: new.name,
            kind: new.kind,
            enabled: true,
            token: tenko_core::ApiTokenId::generate(),
            account: UserId::generate(),
            interval_secs: new.interval_secs.unwrap_or(DEFAULT_INTERVAL_SECS),
            last_sequence: None,
            last_hash: None,
            last_push: None,
            last_change: None,
            created: stamp.clone(),
            updated: stamp,
        };
        Self::settings(&mirror)?;
        let view = self.view().await?;
        Self::name_free(view.as_ref(), &mirror.name, None)?;
        let mut batch = WriteBatch::for_request(ctx);
        let credentials = self
            .auth
            .stage_mirror_account(
                ctx,
                view.as_ref(),
                &mut batch,
                mirror.id,
                &mirror.name,
                new.token_expires_in_days,
            )
            .await?;
        mirror.account = credentials.account;
        mirror.token = credentials.token.info.id;
        batch.expect_typed(&tables::MIRRORS, &mirror.id, None);
        batch.put_typed(&tables::MIRRORS, &mirror.id, &mirror)?;
        batch.audit(
            AuditDraft::success(audit::MIRROR_CREATE, vec![mirror_object(mirror.id)])
                .with_source_ip(ctx.source_ip)
                .with_context("name", mirror.name.clone())
                .with_context("kind", mirror.kind.to_string())
                .with_context("interval_secs", mirror.interval_secs.to_string()),
        );
        self.commit(batch, &mirror.name).await?;
        let item = self.item(view.as_ref(), mirror, ctx.now)?;
        Ok((
            MirrorItem {
                token_expires_at: credentials.token.info.expires_at,
                ..item
            },
            credentials.token,
        ))
    }

    /// Changes a mirror; audited as `migrate.mirror.update`.
    ///
    /// # Errors
    ///
    /// As [`MirrorService::create`], and [`MirrorError::NotFound`].
    pub async fn update(
        &self,
        ctx: &tenko_core::RequestCtx,
        id: MirrorId,
        patch: MirrorPatch,
    ) -> Result<MirrorItem, MirrorError> {
        let view = self.view().await?;
        let (mut mirror, revision) = Self::row(view.as_ref(), id)?;
        let mut draft = AuditDraft::success(audit::MIRROR_UPDATE, vec![mirror_object(id)])
            .with_source_ip(ctx.source_ip);
        if let Some(name) = patch.name {
            draft = draft.with_context("name", name.clone());
            mirror.name = name;
        }
        if let Some(enabled) = patch.enabled {
            draft = draft.with_context("enabled", enabled.to_string());
            mirror.enabled = enabled;
        }
        if let Some(interval) = patch.interval_secs {
            draft = draft.with_context("interval_secs", interval.to_string());
            mirror.interval_secs = interval;
        }
        Self::settings(&mirror)?;
        Self::name_free(view.as_ref(), &mirror.name, Some(id))?;
        mirror.updated = Stamp::new(ctx.now, ctx.principal.clone());
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&tables::MIRRORS, &id, Some(revision));
        batch.put_typed(&tables::MIRRORS, &id, &mirror)?;
        batch.audit(draft);
        self.commit(batch, &mirror.name).await?;
        self.item(view.as_ref(), mirror, ctx.now)
    }

    /// Deletes a mirror with its snapshot, its acknowledgments, its account and its token;
    /// the takeover records stay. Audited as `migrate.mirror.delete`.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotFound`], a store error.
    pub async fn delete(
        &self,
        ctx: &tenko_core::RequestCtx,
        id: MirrorId,
    ) -> Result<(), MirrorError> {
        let view = self.view().await?;
        let (mirror, revision) = Self::row(view.as_ref(), id)?;
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&tables::MIRRORS, &id, Some(revision));
        batch.delete_typed(&tables::MIRRORS, &id);
        batch.delete_typed(&tables::SNAPSHOTS, &id);
        for key in Self::acks(view.as_ref(), id)?.into_keys() {
            batch.delete_typed(&tables::LOSS_ACKS, &(id, key));
        }
        self.auth
            .stage_mirror_account_removal(ctx, view.as_ref(), &mut batch, mirror.account)?;
        batch.audit(
            AuditDraft::success(audit::MIRROR_DELETE, vec![mirror_object(id)])
                .with_source_ip(ctx.source_ip)
                .with_context("name", mirror.name.clone()),
        );
        self.commit(batch, &mirror.name).await?;
        self.memory().remove(&id);
        Ok(())
    }

    /// Replaces the mirror's token; the old one stops at the commit. Audited as
    /// `migrate.mirror.token`.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotFound`], the minting's errors, a store error.
    pub async fn replace_token(
        &self,
        ctx: &tenko_core::RequestCtx,
        id: MirrorId,
        expires_in_days: Option<u32>,
    ) -> Result<(MirrorItem, CreatedToken), MirrorError> {
        let view = self.view().await?;
        let (mut mirror, revision) = Self::row(view.as_ref(), id)?;
        let mut batch = WriteBatch::for_request(ctx);
        let token = self
            .auth
            .stage_mirror_token(
                ctx,
                view.as_ref(),
                &mut batch,
                mirror.account,
                id,
                mirror.token,
                expires_in_days,
            )
            .await?;
        mirror.token = token.info.id;
        mirror.updated = Stamp::new(ctx.now, ctx.principal.clone());
        batch.expect_typed(&tables::MIRRORS, &id, Some(revision));
        batch.put_typed(&tables::MIRRORS, &id, &mirror)?;
        batch.audit(
            AuditDraft::success(audit::MIRROR_TOKEN, vec![mirror_object(id)])
                .with_source_ip(ctx.source_ip),
        );
        self.commit(batch, &mirror.name).await?;
        let item = self.item(view.as_ref(), mirror, ctx.now)?;
        Ok((
            MirrorItem {
                token_expires_at: token.info.expires_at,
                ..item
            },
            token,
        ))
    }

    /// Lets a push of `id` through before its body is read: the mirror exists, is enabled,
    /// and its last admitted push is at least [`MIN_PUSH_INTERVAL_SECS`] old.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotFound`], [`MirrorError::Disabled`], [`MirrorError::Rate`].
    pub async fn admit(&self, id: MirrorId, now: Timestamp) -> Result<(), MirrorError> {
        let view = self.view().await?;
        let (mirror, _) = Self::row(view.as_ref(), id)?;
        if !mirror.enabled {
            return Err(MirrorError::Disabled(id));
        }
        let mut memory = self.memory();
        let memory = memory.entry(id).or_default();
        let floor = self.floor_secs;
        if let Some(last) = memory.admitted {
            let since = now.saturating_since(last).as_secs();
            if since < floor {
                return Err(MirrorError::Rate {
                    retry_after: floor - since,
                });
            }
        }
        memory.admitted = Some(now);
        Ok(())
    }

    /// Accepts a decoded push of `id` (plan section 2.1, rule 6; section 2.4): a sequence
    /// above the last accepted one; an unchanged content writes nothing (but the row's
    /// freshness every [`FRESHNESS_WRITE_SECS`]); a changed one writes the snapshot, the row
    /// and `migrate.mirror.push`.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotFound`], [`MirrorError::Disabled`], [`MirrorError::Sequence`],
    /// [`MirrorError::TooLarge`] for a snapshot the store's batch cannot hold, a store error.
    pub async fn push(
        &self,
        ctx: &tenko_core::RequestCtx,
        id: MirrorId,
        snapshot: MirrorSnapshot,
    ) -> Result<SnapshotAccepted, MirrorError> {
        let view = self.view().await?;
        let (mut mirror, revision) = Self::row(view.as_ref(), id)?;
        if !mirror.enabled {
            return Err(MirrorError::Disabled(id));
        }
        let last = self.fresh(mirror.clone()).last_sequence;
        if let Some(last) = last.filter(|last| snapshot.sequence <= *last) {
            return Err(MirrorError::Sequence {
                sequence: snapshot.sequence,
                last,
            });
        }
        let hash = content_hash(&snapshot)?;
        let sequence = snapshot.sequence;
        let changed = mirror
            .last_hash
            .as_ref()
            .is_none_or(|stored| stored.0 != hash);
        let row_age = mirror
            .last_push
            .map_or(Duration::MAX, |at| ctx.now.saturating_since(at));
        if changed || row_age.as_secs() >= u64::from(FRESHNESS_WRITE_SECS) {
            mirror.last_sequence = Some(sequence);
            mirror.last_push = Some(ctx.now);
            let mut batch = WriteBatch::for_request(ctx);
            batch.expect_typed(&tables::MIRRORS, &id, Some(revision));
            if changed {
                mirror.last_hash = Some(HexBytes(hash.clone()));
                mirror.last_change = Some(ctx.now);
                let summary = Summary::of(hash.clone(), &snapshot)?;
                batch.audit(
                    AuditDraft::success(audit::MIRROR_PUSH, vec![mirror_object(id)])
                        .with_source_ip(ctx.source_ip)
                        .with_context("sequence", sequence.to_string())
                        .with_context("scopes", summary.counts.scopes.to_string())
                        .with_context("reservations", summary.counts.reservations.to_string())
                        .with_context("leases", summary.counts.leases.to_string())
                        .with_context("losses", summary.counts.losses.to_string())
                        .with_context("hash", to_hex(&hash)),
                );
                let row = Snapshot {
                    mirror: id,
                    sequence,
                    hash: HexBytes(hash),
                    received: ctx.now,
                    envelope: snapshot,
                };
                batch.put_typed(&tables::SNAPSHOTS, &id, &row)?;
                self.memory().entry(id).or_default().summary = Some(Arc::new(summary));
            }
            batch.put_typed(&tables::MIRRORS, &id, &mirror)?;
            match self.store.propose(batch).await {
                Ok(_) => {}
                // Another push of the mirror committed first: this one is behind it.
                Err(StoreError::PreconditionFailed(_)) => {
                    return Err(MirrorError::Sequence {
                        sequence,
                        last: sequence,
                    });
                }
                Err(StoreError::BatchTooLarge { limit, .. }) => {
                    return Err(MirrorError::TooLarge { limit });
                }
                Err(error) => return Err(error.into()),
            }
        }
        let mut memory = self.memory();
        let memory = memory.entry(id).or_default();
        memory.pushed = Some(ctx.now);
        memory.sequence = Some(sequence);
        memory.outcomes[usize::from(!changed)] += 1;
        Ok(SnapshotAccepted { sequence, changed })
    }

    /// Counts a refused push of `id` and writes `migrate.mirror.refuse` with the code and
    /// the client's address, at most once a minute per mirror. Nothing of the push is kept.
    pub async fn refused(&self, ctx: &tenko_core::RequestCtx, id: MirrorId, error: &MirrorError) {
        {
            let mut memory = self.memory();
            let memory = memory.entry(id).or_default();
            memory.outcomes[2] += 1;
            if memory
                .refusal_audited
                .is_some_and(|at| ctx.now.saturating_since(at).as_secs() < REFUSAL_AUDIT_SECS)
            {
                return;
            }
            memory.refusal_audited = Some(ctx.now);
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.idempotency = None;
        batch.audit(
            AuditDraft::failed(audit::MIRROR_REFUSE, vec![mirror_object(id)], error)
                .with_source_ip(ctx.source_ip)
                .with_context("code", tenko_core::Coded::code(error)),
        );
        if let Err(store_error) = self.store.propose(batch).await {
            tracing::warn!(error = %store_error, mirror = %id, "could not record a refused push");
        }
    }

    async fn stored(&self, id: MirrorId) -> Result<(Arc<dyn ReadView>, Snapshot), MirrorError> {
        let view = self.view().await?;
        Self::row(view.as_ref(), id)?;
        let (snapshot, _) = view
            .get_typed(&tables::SNAPSHOTS, &id)?
            .ok_or(MirrorError::NoSnapshot(id))?;
        Ok((view, snapshot))
    }

    /// The latest snapshot as stored.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotFound`], [`MirrorError::NoSnapshot`], a store error.
    pub async fn snapshot(&self, id: MirrorId) -> Result<Snapshot, MirrorError> {
        Ok(self.stored(id).await?.1)
    }

    /// The loss report of the latest snapshot with the acknowledgments that hold.
    ///
    /// # Errors
    ///
    /// As [`MirrorService::snapshot`].
    pub async fn losses(&self, id: MirrorId) -> Result<MirrorLosses, MirrorError> {
        let (view, snapshot) = self.stored(id).await?;
        let acks = Self::acks(view.as_ref(), id)?;
        let scopes: Vec<IpNet> = snapshot
            .envelope
            .dhcp
            .scopes
            .iter()
            .map(|scope| scope.cidr)
            .collect();
        let entries = snapshot
            .envelope
            .losses
            .entries
            .into_iter()
            .map(|entry| {
                let key = entry.key();
                let hash = entry_hash(&entry)?;
                Ok(MirrorLossItem {
                    ack: acks
                        .get(&key)
                        .filter(|ack| ack.entry_hash.0 == hash)
                        .cloned(),
                    scope: entry_scope(&entry, &scopes),
                    key,
                    entry,
                })
            })
            .collect::<Result<_, MirrorError>>()?;
        Ok(MirrorLosses {
            mirror: id,
            sequence: snapshot.sequence,
            entries,
        })
    }

    /// Acknowledges loss entries of the latest snapshot by their keys; an acknowledgment
    /// holds while the entry recurs unchanged. Audited as `migrate.mirror.losses_ack`.
    ///
    /// # Errors
    ///
    /// [`MirrorError::Request`] for a key the snapshot does not hold or no key at all, as
    /// [`MirrorService::snapshot`].
    pub async fn ack(
        &self,
        ctx: &tenko_core::RequestCtx,
        id: MirrorId,
        keys: &[String],
    ) -> Result<(Vec<LossAck>, Revision), MirrorError> {
        let by = ctx
            .principal
            .user()
            .ok_or(MirrorError::Auth(tenko_auth::AuthError::Unauthenticated))?;
        let losses = self.losses(id).await?;
        if keys.is_empty() {
            return Err(MirrorError::Request("name at least one entry".to_owned()));
        }
        let mut acks: BTreeMap<&str, LossAck> = BTreeMap::new();
        for key in keys {
            let entry = losses
                .entries
                .iter()
                .find(|item| item.key == *key)
                .ok_or_else(|| {
                    MirrorError::Request("a key names no entry of the latest snapshot".to_owned())
                })?;
            acks.insert(
                key,
                LossAck {
                    mirror: id,
                    key: key.clone(),
                    entry_hash: HexBytes(entry_hash(&entry.entry)?),
                    by,
                    at: ctx.now,
                },
            );
        }
        let mut batch = WriteBatch::for_request(ctx);
        for ack in acks.values() {
            batch.put_typed(&tables::LOSS_ACKS, &(id, ack.key.clone()), ack)?;
        }
        batch.audit(
            AuditDraft::success(audit::MIRROR_LOSSES_ACK, vec![mirror_object(id)])
                .with_source_ip(ctx.source_ip)
                .with_context("sequence", losses.sequence.to_string())
                .with_context("count", acks.len().to_string()),
        );
        let revision = self.store.propose(batch).await?.revision;
        Ok((acks.into_values().collect(), revision))
    }

    /// The diff of a mirrored scope against Tenko's scope of the same network.
    ///
    /// # Errors
    ///
    /// As [`MirrorService::snapshot`], and [`MirrorError::ScopeNotFound`].
    pub async fn diff(&self, id: MirrorId, scope: IpNet) -> Result<ScopeDiff, MirrorError> {
        let (view, snapshot) = self.stored(id).await?;
        let (mirror, _) = Self::row(view.as_ref(), id)?;
        let open = match self.summary(view.as_ref(), &mirror)? {
            Some(summary) => Self::open(&summary, &Self::acks(view.as_ref(), id)?, Some(scope)),
            None => 0,
        };
        super::diff::diff(view.as_ref(), &snapshot, scope, open)
    }

    /// The health findings of the mirrors (plan section 2.12): stale mirrors, tokens that
    /// expire within [`TOKEN_EXPIRING_DAYS`] days, and taken-over scopes the source serves
    /// again.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn findings(&self, now: Timestamp) -> Result<Vec<Finding>, MirrorError> {
        let view = self.view().await?;
        let taken: Vec<(MirrorId, IpNet)> = view
            .scan_typed(&tables::TAKEOVERS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .filter(|(_, takeover, _)| takeover.state == TakeoverState::Done)
            .map(|(_, takeover, _)| (takeover.mirror, takeover.scope))
            .collect();
        let mut found: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
        let soon = Duration::from_secs(u64::from(TOKEN_EXPIRING_DAYS) * 86_400);
        for mirror in Self::rows(view.as_ref())? {
            let mirror = self.fresh(mirror);
            if mirror.is_stale(now) {
                found
                    .entry(findings::MIRROR_STALE)
                    .or_default()
                    .push(mirror.name.clone());
            }
            if AuthService::scoped_token_expiry(view.as_ref(), mirror.account, mirror.token)?
                .is_some_and(|end| end.saturating_since(now) <= soon)
            {
                found
                    .entry(findings::MIRROR_TOKEN_EXPIRING)
                    .or_default()
                    .push(mirror.name.clone());
            }
            if let Some(summary) = self.summary(view.as_ref(), &mirror)?
                && taken.iter().any(|(of, scope)| {
                    *of == mirror.id && summary.scopes.iter().any(|s| s.cidr == *scope && s.active)
                })
            {
                found
                    .entry(findings::MIRROR_SCOPE_ACTIVE)
                    .or_default()
                    .push(mirror.name.clone());
            }
        }
        Ok(found
            .into_iter()
            .map(|(code, mirrors)| Finding { code, mirrors })
            .collect())
    }

    /// Sets the metric series of every mirror from memory: the pushes by outcome and the
    /// age of the last push. Run by the metrics timer.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn refresh_metrics(&self, now: Timestamp) -> Result<(), MirrorError> {
        let view = self.view().await?;
        for mirror in Self::rows(view.as_ref())? {
            let mirror = self.fresh(mirror);
            let id = mirror.id.to_string();
            let outcomes = self
                .memory()
                .get(&mirror.id)
                .map(|memory| memory.outcomes)
                .unwrap_or_default();
            for (outcome, total) in metrics::PUSH_OUTCOMES.into_iter().zip(outcomes) {
                PUSHES.set_labels_total(&[id.as_str(), outcome], total);
            }
            if let Some(at) = mirror.last_push {
                #[allow(clippy::cast_precision_loss, reason = "seconds of an age")]
                AGE.set_labels(&[id.as_str()], now.saturating_since(at).as_secs() as f64);
            }
        }
        PUSHES.sweep();
        AGE.sweep();
        Ok(())
    }
}
