//! The signer (plan section 2.7, P2-Q4, ADR 0018): the leader-only service `dns.signer`
//! that keeps every zone with `dnssec.mode = online` signed, and watches the imported ones.
//!
//! # When it signs
//!
//! - When it takes office: every signed zone gets a full pass. When the store still holds
//!   the changes since the zones' `signed_revision`, the pass keeps the signatures it finds
//!   and the replayed changes re-sign what changed; when it does not, every kept signature
//!   must verify first.
//! - On every commit that changes the RRsets or the settings of a signed zone (the store's
//!   change stream of `dns.rrsets` and `dns.zones`, gathered for [`SignerConfig::debounce`]):
//!   an incremental pass over the changed RRsets, or a full pass after a change of the zone
//!   settings. Its own commits are left out.
//! - On its timer ([`SignerConfig::tick`]): a zone whose `next_resign` has come gets a full
//!   pass that renews every signature with less than `resign_before_days` and a day left;
//!   a zone whose ZSK is older than `zsk_rollover_days` gets a rollover job; an imported
//!   zone has its signatures' expiry read again every hour.
//! - When a rollover step asks ([`Signer::sync`]).
//!
//! # Modes
//!
//! `online` generates the keys at the first pass (a KSK and a ZSK, or a CSK), or takes the
//! retired keys of an earlier online period up again so the DS at the parent stays valid.
//! `off` and `imported` remove every row of the signer and retire the keys; `imported`
//! then serves the zone's own signatures and records their earliest expiry for the health
//! findings ([`super::health`]).
//!
//! Passes of one signer run one at a time. Keys are decrypted from the vault when a pass
//! needs them and kept in memory while the signer leads.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use futures::StreamExt as _;
use tenko_core::{
    ObjectRef, Revision, Timestamp,
    audit::AuditDraft,
    cluster::LeaderService,
    dns::{
        DnsKeyId, DnsName, DnssecMode, KeyRole, KeyState, RrSet, RrSetKey, Rtype, ScopeName,
        SignState, Zone, ZoneId, audit, codes,
        tables::{RRSETS, SIGN_STATE, ZONES},
    },
    ipam::Stamp,
};
use tenko_store::{ReadView, ReadViewExt, StoreError, WatchError, WatchFilter};
use tenko_vault::Vault;
use tokio_util::sync::CancellationToken;

use super::{
    chain::{HASH_LEN, is_generated},
    keys::{self, KeySet},
    pass::{self, Incremental, Limits, Pass, RowChange, ScopeOutcome, earlier},
    rollover,
    sign::{self, DAY_SECS, Times},
};
use crate::zone::{
    ZoneError, ZoneResult, ZoneService, holds_data,
    signing::{
        SoaStep, next_soa, signer_batch, signer_ctx, soa_key, stage_changes, stage_soa_step,
    },
};

/// The settings of the signer.
#[derive(Debug, Clone, Copy)]
pub struct SignerConfig {
    /// How long changes are gathered before a pass.
    pub debounce: Duration,
    /// How often the timer looks at the zones.
    pub tick: Duration,
    /// The chunks and threads of a full pass.
    pub limits: Limits,
}

impl Default for SignerConfig {
    fn default() -> Self {
        Self {
            debounce: Duration::from_millis(50),
            tick: Duration::from_secs(60),
            limits: Limits::default(),
        }
    }
}

/// What starts a pass.
#[derive(Debug, Clone, Default)]
pub struct Trigger {
    /// Sign every owner; otherwise only the changed RRsets and their neighbours.
    pub full: bool,
    /// A full pass verifies every signature it keeps.
    pub verify: bool,
    /// A pass of the timer renews ahead of the due time.
    pub timer: bool,
    /// The changed RRsets by scope.
    pub changed: HashMap<ScopeName, HashSet<(DnsName, Rtype)>>,
    /// The store revision the changes run to, recorded as `signed_revision`.
    pub position: Option<Revision>,
}

impl Trigger {
    /// A full pass.
    pub fn full(verify: bool) -> Self {
        Self {
            full: true,
            verify,
            ..Self::default()
        }
    }
}

/// What a pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Rows written.
    pub rows: usize,
    /// The serial of the default scope after the pass, when it moved.
    pub serial: Option<u32>,
    /// The pass was full.
    pub full: bool,
}

/// Loaded keys with the key ids and states they were loaded for.
type CachedKeys = (Vec<(DnsKeyId, KeyState)>, Arc<KeySet>);

#[derive(Default)]
struct Work {
    /// Loaded keys by zone.
    keys: HashMap<ZoneId, CachedKeys>,
    /// The NSEC3 chain of each zone scope after the last pass.
    hashes: HashMap<(ZoneId, ScopeName), BTreeSet<[u8; HASH_LEN]>>,
}

/// The signer. Shared by the leader service and the rollover steps.
pub struct Signer {
    zones: Arc<ZoneService>,
    vault: Arc<dyn Vault>,
    config: SignerConfig,
    work: tokio::sync::Mutex<Work>,
    epoch: AtomicU64,
    own: std::sync::Mutex<VecDeque<Revision>>,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

fn failed(zone: &Zone, reason: impl Into<String>) -> ZoneError {
    let reason = reason.into();
    ZoneError::new(
        codes::DNSSEC_SIGNING_FAILED,
        500,
        format!("zone {} could not be signed: {reason}", zone.name),
    )
    .param("zone", zone.name.as_str())
    .param("reason", reason)
}

fn now() -> Timestamp {
    Timestamp::now()
}

impl Signer {
    /// A signer over the zone service and the vault.
    pub fn new(zones: Arc<ZoneService>, vault: Arc<dyn Vault>, config: SignerConfig) -> Arc<Self> {
        Arc::new(Self {
            zones,
            vault,
            config,
            work: tokio::sync::Mutex::new(Work::default()),
            epoch: AtomicU64::new(0),
            own: std::sync::Mutex::new(VecDeque::new()),
        })
    }

    /// The zone service.
    pub fn zones(&self) -> &Arc<ZoneService> {
        &self.zones
    }

    /// The leader service `dns.signer`.
    pub fn leader_service(self: &Arc<Self>) -> Arc<dyn LeaderService> {
        Arc::new(SignerService(Arc::clone(self)))
    }

    /// The leader epoch the signer writes with while it leads.
    pub(crate) fn epoch(&self) -> Option<u64> {
        match self.epoch.load(Ordering::Relaxed) {
            0 => None,
            epoch => Some(epoch),
        }
    }

    fn remember(&self, revision: Revision) {
        let mut own = self
            .own
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        own.push_back(revision);
        while own.len() > 4_096 {
            own.pop_front();
        }
    }

    fn is_own(&self, revision: Revision) -> bool {
        self.own
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&revision)
    }

    async fn propose(&self, batch: tenko_store::WriteBatch) -> Result<Revision, StoreError> {
        let committed = self.zones.store().propose(batch).await?;
        self.remember(committed.revision);
        Ok(committed.revision)
    }

    /// Brings one zone to what its policy says: signs it (online), or removes the rows of
    /// the signer and records the imported signatures' expiry (off, imported).
    ///
    /// # Errors
    ///
    /// A store, vault or signing error.
    pub async fn sync(&self, id: ZoneId, trigger: Trigger) -> ZoneResult<Report> {
        let mut work = self.work.lock().await;
        let started = std::time::Instant::now();
        let view = self.zones.view(None).await?;
        let zone = match ZoneService::zone(view.as_ref(), id) {
            Ok(row) => row.zone,
            Err(error) if error.is(codes::ZONE_NOT_FOUND) => {
                work.keys.remove(&id);
                work.hashes.retain(|(zone, _), _| *zone != id);
                return Ok(Report::default());
            }
            Err(error) => return Err(error),
        };
        let result = if zone.dnssec.mode == DnssecMode::Online && holds_data(zone.kind) {
            self.online(&mut work, view, zone, trigger).await
        } else {
            work.keys.remove(&id);
            work.hashes.retain(|(zone, _), _| *zone != id);
            self.unsigned(view, zone, trigger).await
        };
        match &result {
            // A full pass is rare and may take a while: the operator sees it.
            Ok(report) if report.full && report.rows > 0 => tracing::info!(
                zone = %id,
                rows = report.rows,
                ms = started.elapsed().as_millis(),
                "zone signed in a full pass"
            ),
            Ok(report) if report.rows > 0 => tracing::debug!(
                zone = %id,
                rows = report.rows,
                full = report.full,
                ms = started.elapsed().as_millis(),
                "zone signed"
            ),
            Ok(_) => {}
            Err(error) => tracing::warn!(zone = %id, %error, "signing failed"),
        }
        result
    }

    // ----- online ------------------------------------------------------------------------

    #[allow(
        clippy::too_many_lines,
        reason = "one pass from keys to the final write"
    )]
    async fn online(
        &self,
        work: &mut Work,
        view: Arc<dyn ReadView>,
        zone: Zone,
        mut trigger: Trigger,
    ) -> ZoneResult<Report> {
        let mut view = view;
        let state = ZoneService::sign_state(view.as_ref(), zone.id)?;
        let usable = state.as_ref().is_some_and(|(state, _)| {
            state
                .keys
                .iter()
                .any(|key| key.state == KeyState::Active && keys::signs_data(key.role))
                && state
                    .keys
                    .iter()
                    .any(|key| key.state == KeyState::Active && keys::signs_keys(key.role))
        });
        if !usable {
            self.enable(&zone, state).await?;
            view = self.zones.view(None).await?;
            trigger.full = true;
        }
        let Some((state, _)) = ZoneService::sign_state(view.as_ref(), zone.id)? else {
            return Err(failed(&zone, "the signing state is missing"));
        };
        let keys = self.keys(work, &zone, &state).await?;
        if !keys.complete() {
            return Err(failed(&zone, "no active key signs the zone"));
        }
        if state.signed_serial.is_none() {
            trigger.full = true;
        }
        let at = now();
        let stamp = Stamp::new(at, signer_ctx().principal);
        let mut outcomes: Vec<(ScopeName, ScopeOutcome)> = Vec::new();
        let mut full = trigger.full;
        for scope in zone.scopes.iter().map(|scope| scope.name.clone()) {
            let dirty = trigger.changed.remove(&scope).unwrap_or_default();
            let times = Times::new(at, &zone.dnssec, trigger.timer);
            let mut outcome = None;
            if !trigger.full {
                if dirty.is_empty() {
                    continue;
                }
                let hashes = work.hashes.remove(&(zone.id, scope.clone()));
                let (result, hashes) = self
                    .incremental(
                        &view,
                        &zone,
                        &scope,
                        &keys,
                        times,
                        &stamp,
                        dirty.clone(),
                        hashes,
                    )
                    .await?;
                match result {
                    Ok(done) => {
                        if let Some(hashes) = hashes {
                            work.hashes.insert((zone.id, scope.clone()), hashes);
                        }
                        outcome = Some(done);
                    }
                    Err(Incremental::NeedsFull) => full = true,
                    Err(Incremental::Failed(error)) => return Err(error),
                }
            }
            let outcome = if let Some(outcome) = outcome {
                outcome
            } else {
                let mut done = self
                    .full(
                        &view,
                        &zone,
                        &scope,
                        &keys,
                        times,
                        &stamp,
                        trigger.verify,
                        dirty,
                    )
                    .await?;
                if let Some(hashes) = done.hashes.take() {
                    work.hashes.insert((zone.id, scope.clone()), hashes);
                }
                done
            };
            outcomes.push((scope, outcome));
        }
        let mut report = self
            .finish(
                &zone,
                &keys,
                &stamp,
                outcomes,
                full,
                trigger.timer,
                trigger.position,
            )
            .await?;
        report.full = full;
        Ok(report)
    }

    /// Loads the keys of a zone, from memory when they did not change.
    async fn keys(
        &self,
        work: &mut Work,
        zone: &Zone,
        state: &SignState,
    ) -> ZoneResult<Arc<KeySet>> {
        let fingerprint: Vec<(DnsKeyId, KeyState)> =
            state.keys.iter().map(|key| (key.id, key.state)).collect();
        if let Some((known, keys)) = work.keys.get(&zone.id)
            && *known == fingerprint
        {
            return Ok(Arc::clone(keys));
        }
        let keys = Arc::new(
            keys::load(self.vault.as_ref(), &signer_ctx(), state)
                .await
                .map_err(|reason| failed(zone, reason))?,
        );
        work.keys.insert(zone.id, (fingerprint, Arc::clone(&keys)));
        Ok(keys)
    }

    /// Gives a zone its keys: the retired keys of an earlier online period of the policy's
    /// shape, else new ones, all active.
    #[allow(clippy::too_many_lines, reason = "the keys of one zone in one batch")]
    async fn enable(&self, zone: &Zone, state: Option<(SignState, Revision)>) -> ZoneResult<()> {
        let cx = signer_ctx();
        for _ in 0..4 {
            let (mut sign_state, revision) = match &state {
                Some((state, revision)) => (state.clone(), Some(*revision)),
                None => (
                    SignState {
                        zone: zone.id,
                        keys: Vec::new(),
                        signed_serial: None,
                        last_signed: None,
                        next_resign: None,
                        signed_revision: None,
                        expires: None,
                        rollover_job: None,
                    },
                    None,
                ),
            };
            let roles: &[KeyRole] = if zone.dnssec.csk {
                &[KeyRole::Csk]
            } else {
                &[KeyRole::Ksk, KeyRole::Zsk]
            };
            let mut batch = signer_batch(self.epoch());
            let at = now();
            for role in roles {
                let active = sign_state
                    .keys
                    .iter()
                    .any(|key| key.role == *role && key.state == KeyState::Active);
                if active {
                    continue;
                }
                // Take up the newest retired key of the role and algorithm again.
                let retired = sign_state
                    .keys
                    .iter_mut()
                    .filter(|key| {
                        key.role == *role
                            && key.algorithm == zone.dnssec.algorithm
                            && matches!(key.state, KeyState::Retired | KeyState::Published)
                    })
                    .max_by_key(|key| key.created.at);
                if let Some(key) = retired {
                    keys::set_state(key, KeyState::Active, at);
                    batch.audit(
                        AuditDraft::success(
                            audit::DNSSEC_KEY_STATE,
                            vec![ObjectRef::from(zone.id)],
                        )
                        .with_context("zone", zone.name.as_str())
                        .with_context("role", keys::role_name(*role))
                        .with_context("key_tag", key.key_tag.to_string())
                        .with_context("state", "active"),
                    );
                    continue;
                }
                let taken: Vec<u16> = sign_state.keys.iter().map(|key| key.key_tag).collect();
                let cx = tenko_core::RequestCtx {
                    now: at,
                    ..cx.clone()
                };
                let key = keys::stage_new_key(
                    self.vault.as_ref(),
                    &mut batch,
                    &cx,
                    zone.id,
                    &zone.name,
                    *role,
                    zone.dnssec.algorithm,
                    KeyState::Active,
                    &taken,
                )
                .map_err(|error| failed(zone, error.to_string()))?;
                batch.audit(
                    AuditDraft::success(audit::DNSSEC_KEY_CREATE, vec![ObjectRef::from(zone.id)])
                        .with_context("zone", zone.name.as_str())
                        .with_context("role", keys::role_name(*role))
                        .with_context("key_tag", key.key_tag.to_string()),
                );
                sign_state.keys.push(key);
            }
            // Keys of an earlier period that were not taken up again leave the DNSKEY set
            // and the vault.
            for key in &mut sign_state.keys {
                if matches!(
                    key.state,
                    KeyState::Retired | KeyState::Published | KeyState::Generated
                ) {
                    key.state = KeyState::Removed;
                    self.vault.stage_delete(&mut batch, &cx, key.secret);
                    batch.audit(
                        AuditDraft::success(
                            audit::DNSSEC_KEY_STATE,
                            vec![ObjectRef::from(zone.id)],
                        )
                        .with_context("zone", zone.name.as_str())
                        .with_context("role", keys::role_name(key.role))
                        .with_context("key_tag", key.key_tag.to_string())
                        .with_context("state", "removed"),
                    );
                }
            }
            batch.audit(
                AuditDraft::success(audit::DNSSEC_ENABLE, vec![ObjectRef::from(zone.id)])
                    .with_context("zone", zone.name.as_str())
                    .with_context("algorithm", algorithm_name(zone))
                    .with_context("denial", denial_name(zone)),
            );
            batch.expect_typed(&SIGN_STATE, &zone.id, revision);
            batch.put_typed(&SIGN_STATE, &zone.id, &sign_state)?;
            match self.propose(batch).await {
                Ok(_) => return Ok(()),
                Err(StoreError::PreconditionFailed(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(failed(zone, "the signing state kept changing"))
    }

    #[allow(clippy::too_many_arguments, reason = "the parts of one pass")]
    async fn incremental(
        &self,
        view: &Arc<dyn ReadView>,
        zone: &Zone,
        scope: &ScopeName,
        keys: &Arc<KeySet>,
        times: Times,
        stamp: &Stamp,
        dirty: HashSet<(DnsName, Rtype)>,
        hashes: Option<BTreeSet<[u8; HASH_LEN]>>,
    ) -> ZoneResult<(
        Result<ScopeOutcome, Incremental>,
        Option<BTreeSet<[u8; HASH_LEN]>>,
    )> {
        let view = Arc::clone(view);
        let zone = zone.clone();
        let scope = scope.clone();
        let keys = Arc::clone(keys);
        let stamp = stamp.clone();
        tokio::task::spawn_blocking(move || {
            let pass = Pass {
                zone: &zone,
                scope: &scope,
                keys: &keys,
                times,
                verify: false,
                stamp,
                dirty: &dirty,
            };
            let mut hashes = match hashes {
                Some(hashes) => Some(hashes),
                None if pass.nsec3_zone() => {
                    match pass::stored_hashes(view.as_ref(), &zone, &scope) {
                        Ok(hashes) => Some(hashes),
                        Err(error) => return (Err(Incremental::Failed(error)), None),
                    }
                }
                None => None,
            };
            let changed: BTreeSet<DnsName> = dirty.iter().map(|(name, _)| name.clone()).collect();
            let result = pass::incremental(&pass, view.as_ref(), &changed, hashes.as_mut());
            (result, hashes)
        })
        .await
        .map(Ok)
        .map_err(|_| {
            ZoneError::new(
                codes::DNSSEC_SIGNING_FAILED,
                500,
                "the signing task stopped",
            )
        })?
    }

    #[allow(clippy::too_many_arguments, reason = "the parts of one pass")]
    async fn full(
        &self,
        view: &Arc<dyn ReadView>,
        zone: &Zone,
        scope: &ScopeName,
        keys: &Arc<KeySet>,
        times: Times,
        stamp: &Stamp,
        verify: bool,
        dirty: HashSet<(DnsName, Rtype)>,
    ) -> ZoneResult<ScopeOutcome> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<RowChange>>(2);
        let task_view = Arc::clone(view);
        let task_zone = zone.clone();
        let task_scope = scope.clone();
        let task_keys = Arc::clone(keys);
        let task_stamp = stamp.clone();
        let limits = self.config.limits;
        let handle = tokio::task::spawn_blocking(move || {
            let pass = Pass {
                zone: &task_zone,
                scope: &task_scope,
                keys: &task_keys,
                times,
                verify,
                stamp: task_stamp,
                dirty: &dirty,
            };
            let mut flush = |chunk: Vec<RowChange>| {
                tx.blocking_send(chunk)
                    .map_err(|_| failed(&task_zone, "the writer of the pass stopped"))
            };
            pass::full(&pass, task_view.as_ref(), limits, &mut flush)
        });
        while let Some(chunk) = rx.recv().await {
            let mut batch = signer_batch(self.epoch());
            stage_changes(&mut batch, &chunk)?;
            self.propose(batch).await?;
        }
        handle
            .await
            .map_err(|_| failed(zone, "the signing task stopped"))?
    }

    /// The final write of a pass: the remaining row changes, the apex with the next serial
    /// of each scope that changed, the journal and the signing state; planned again when
    /// the zone changed meanwhile.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the parts of one pass and its one final write"
    )]
    async fn finish(
        &self,
        zone: &Zone,
        keys: &Arc<KeySet>,
        stamp: &Stamp,
        outcomes: Vec<(ScopeName, ScopeOutcome)>,
        full: bool,
        timer: bool,
        position: Option<Revision>,
    ) -> ZoneResult<Report> {
        let limits = self.zones.journal_limits();
        let no_dirty = HashSet::new();
        for _ in 0..16 {
            let view = self.zones.view(None).await?;
            let Some((mut state, state_revision)) =
                ZoneService::sign_state(view.as_ref(), zone.id)?
            else {
                return Err(failed(zone, "the signing state is missing"));
            };
            let pass_times = Times::new(stamp.at, &zone.dnssec, timer);
            let mut batch = signer_batch(self.epoch());
            let mut rows = 0;
            let mut serial = None;
            let mut expires = if full {
                None
            } else {
                state.expires.map(sign::unix32)
            };
            for (scope, outcome) in &outcomes {
                let pass = Pass {
                    zone,
                    scope,
                    keys,
                    times: pass_times,
                    verify: false,
                    stamp: stamp.clone(),
                    dirty: &no_dirty,
                };
                let key = soa_key(zone, scope);
                let Some((old_soa, soa_revision)) = view.get_typed(&RRSETS, &key)? else {
                    continue;
                };
                let apex_rows = pass::rows_of(view.as_ref(), zone, scope, &zone.name)?;
                let probe = pass::apex_job(
                    &pass,
                    apex_rows.clone(),
                    &old_soa,
                    false,
                    outcome.apex_next.as_ref(),
                );
                let (probe_changes, probe_expires) = pass.run(probe)?;
                expires = earlier(expires, outcome.expires, pass_times.now);
                if probe_changes.is_empty() && outcome.pending.is_empty() && outcome.flushed == 0 {
                    expires = earlier(expires, probe_expires, pass_times.now);
                    continue;
                }
                let new_soa = next_soa(zone, scope, &old_soa, stamp);
                let job =
                    pass::apex_job(&pass, apex_rows, &new_soa, true, outcome.apex_next.as_ref());
                let (apex_changes, apex_expires) = pass.run(job)?;
                expires = earlier(expires, apex_expires, pass_times.now);
                let mut changes = outcome.pending.clone();
                changes.extend(apex_changes);
                stage_changes(&mut batch, &changes)?;
                stage_soa_step(
                    &mut batch,
                    view.as_ref(),
                    zone,
                    &SoaStep {
                        scope: scope.clone(),
                        old: (old_soa, soa_revision),
                        new: new_soa.clone(),
                    },
                    &changes,
                    outcome.flushed == 0,
                    limits,
                )?;
                rows += outcome.flushed + changes.len() + 1;
                if scope == &ScopeName::DEFAULT || serial.is_none() {
                    serial = crate::zone::soa_serial(&new_soa);
                }
            }
            let before = state.clone();
            if rows > 0 {
                state.last_signed = Some(stamp.at);
                state.signed_serial = serial.or(state.signed_serial);
            } else if state.signed_serial.is_none() {
                state.signed_serial =
                    ZoneService::scope_serial(view.as_ref(), zone, &ScopeName::DEFAULT)?;
                state.last_signed.get_or_insert(stamp.at);
            }
            if let Some(expires) = expires {
                let at = sign::time_of(expires, stamp.at);
                state.expires = Some(at);
                let resign = Duration::from_secs(
                    u64::from(zone.dnssec.resign_before_days) * u64::from(DAY_SECS),
                );
                state.next_resign = Some(
                    Timestamp::from_unix_nanos(
                        at.unix_nanos() - i128::try_from(resign.as_nanos()).unwrap_or(0),
                    )
                    .unwrap_or(at),
                );
            }
            if let Some(position) = position {
                state.signed_revision = Some(position);
            } else if full {
                state.signed_revision = Some(view.revision());
            }
            if rows == 0 && state == before {
                return Ok(Report::default());
            }
            batch.expect_typed(&SIGN_STATE, &zone.id, Some(state_revision));
            batch.put_typed(&SIGN_STATE, &zone.id, &state)?;
            match self.propose(batch).await {
                Ok(_) => return Ok(Report { rows, serial, full }),
                Err(StoreError::PreconditionFailed(_)) => {
                    tracing::debug!(zone = %zone.name, "the zone changed during the pass; writing the apex again");
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(failed(zone, "the zone kept changing during the pass"))
    }

    // ----- off and imported --------------------------------------------------------------

    #[allow(
        clippy::too_many_lines,
        reason = "the removal, the serial steps and the state in one place"
    )]
    async fn unsigned(
        &self,
        view: Arc<dyn ReadView>,
        zone: Zone,
        trigger: Trigger,
    ) -> ZoneResult<Report> {
        let state = ZoneService::sign_state(view.as_ref(), zone.id)?;
        let imported = zone.dnssec.mode == DnssecMode::Imported;
        let mut report = Report::default();
        // The rows of the signer go, in chunks, with one serial step per scope at the end.
        let mut steps: Vec<(ScopeName, Vec<RowChange>, bool)> = Vec::new();
        for scope in zone.scopes.iter().map(|scope| scope.name.clone()) {
            let rows = pass::generated_rows(view.as_ref(), &zone, &scope)?;
            if rows.is_empty() {
                continue;
            }
            let mut changes: Vec<RowChange> = rows
                .into_iter()
                .map(|(row, revision)| RowChange {
                    key: row.key(),
                    old: Some((row, revision)),
                    new: None,
                })
                .collect();
            let chunked = changes.len() > self.config.limits.rows;
            while changes.len() > self.config.limits.rows {
                let rest = changes.split_off(self.config.limits.rows);
                let mut batch = signer_batch(self.epoch());
                stage_changes(&mut batch, &changes)?;
                self.propose(batch).await?;
                report.rows += changes.len();
                changes = rest;
            }
            steps.push((scope, changes, chunked));
        }
        let had_keys = state.as_ref().is_some_and(|(state, _)| {
            state
                .keys
                .iter()
                .any(|key| key.state != KeyState::Retired && key.state != KeyState::Removed)
        });
        let mut expires = None;
        let check_imported = imported
            && (trigger.full
                || !trigger.changed.is_empty()
                || state
                    .as_ref()
                    .is_none_or(|(state, _)| state.next_resign.is_none_or(|due| due <= now())));
        if check_imported {
            let at = sign::unix32(now());
            for scope in &zone.scopes {
                let (found, _) =
                    pass::scan_signatures(view.as_ref(), &zone, &scope.name, false, at)?;
                expires = earlier(expires, found, at);
            }
        }
        if steps.is_empty() && !had_keys && !check_imported {
            return Ok(report);
        }
        let stamp = Stamp::new(now(), signer_ctx().principal);
        for _ in 0..16 {
            let view = self.zones.view(None).await?;
            let mut batch = signer_batch(self.epoch());
            let mut wrote = !steps.is_empty();
            for (scope, changes, chunked) in &steps {
                let Some((old, revision)) = view.get_typed(&RRSETS, &soa_key(&zone, scope))? else {
                    stage_changes(&mut batch, changes)?;
                    continue;
                };
                let new = next_soa(&zone, scope, &old, &stamp);
                stage_changes(&mut batch, changes)?;
                stage_soa_step(
                    &mut batch,
                    view.as_ref(),
                    &zone,
                    &SoaStep {
                        scope: scope.clone(),
                        old: (old, revision),
                        new,
                    },
                    changes,
                    !chunked,
                    self.zones.journal_limits(),
                )?;
            }
            let current = ZoneService::sign_state(view.as_ref(), zone.id)?;
            let mut next = current.as_ref().map_or_else(
                || SignState {
                    zone: zone.id,
                    keys: Vec::new(),
                    signed_serial: None,
                    last_signed: None,
                    next_resign: None,
                    signed_revision: None,
                    expires: None,
                    rollover_job: None,
                },
                |(state, _)| state.clone(),
            );
            for key in &mut next.keys {
                if matches!(
                    key.state,
                    KeyState::Published | KeyState::Active | KeyState::Generated
                ) {
                    keys::set_state(key, KeyState::Retired, stamp.at);
                }
            }
            next.rollover_job = None;
            if imported {
                if check_imported {
                    next.expires = expires.map(|field| sign::time_of(field, stamp.at));
                    next.next_resign = stamp.at.checked_add(Duration::from_secs(3_600));
                }
            } else {
                next.expires = None;
                next.next_resign = None;
            }
            next.signed_serial = None;
            if !steps.is_empty() {
                batch.audit(
                    AuditDraft::success(audit::DNSSEC_DISABLE, vec![ObjectRef::from(zone.id)])
                        .with_context("zone", zone.name.as_str())
                        .with_context("mode", if imported { "imported" } else { "off" }),
                );
            }
            if current.as_ref().map(|(state, _)| state) != Some(&next) || !steps.is_empty() {
                batch.expect_typed(
                    &SIGN_STATE,
                    &zone.id,
                    current.as_ref().map(|(_, revision)| *revision),
                );
                batch.put_typed(&SIGN_STATE, &zone.id, &next)?;
                wrote = true;
            }
            if !wrote {
                return Ok(report);
            }
            match self.propose(batch).await {
                Ok(_) => {
                    report.rows += steps
                        .iter()
                        .map(|(_, changes, _)| changes.len())
                        .sum::<usize>();
                    return Ok(report);
                }
                Err(StoreError::PreconditionFailed(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(failed(
            &zone,
            "the zone kept changing while its signatures were removed",
        ))
    }

    // ----- the leader loop ---------------------------------------------------------------

    /// The zones the signer looks after: signed online or imported, or with a signing
    /// state left to clean up; with the earliest `signed_revision` of the online ones.
    fn tracked(
        view: &dyn ReadView,
    ) -> ZoneResult<(BTreeMap<ZoneId, DnssecMode>, Option<Revision>)> {
        let mut tracked = BTreeMap::new();
        for row in ZoneService::zones(view)? {
            if row.zone.dnssec.mode != DnssecMode::Off {
                tracked.insert(row.zone.id, row.zone.dnssec.mode);
            }
        }
        let mut from: Option<Revision> = None;
        let mut fresh = false;
        for (id, state, _) in
            view.scan_typed(&SIGN_STATE, tenko_store::KeyRange::all(), usize::MAX, false)?
        {
            let mode = tracked.entry(id).or_insert(DnssecMode::Off);
            if *mode == DnssecMode::Online {
                match state.signed_revision {
                    Some(revision) => {
                        from = Some(from.map_or(revision, |known: Revision| known.min(revision)));
                    }
                    None => fresh = true,
                }
            }
        }
        if fresh {
            from = None;
        }
        Ok((tracked, from))
    }

    async fn run_leader(
        self: &Arc<Self>,
        epoch: u64,
        stop: CancellationToken,
    ) -> Result<(), String> {
        self.epoch.store(epoch, Ordering::Relaxed);
        let result = self.lead(stop).await;
        self.epoch.store(0, Ordering::Relaxed);
        let mut work = self.work.lock().await;
        *work = Work::default();
        result
    }

    /// The loop of the service: the passes at the start, then the changes the drain task
    /// gathers, and the timer. The store's change stream is read by its own task
    /// ([`drain`]), so a long pass never lets it fall behind.
    async fn lead(self: &Arc<Self>, stop: CancellationToken) -> Result<(), String> {
        let store = Arc::clone(self.zones.store());
        let view = self
            .zones
            .view(None)
            .await
            .map_err(|error| error.to_string())?;
        let (tracked, from) = Self::tracked(view.as_ref()).map_err(|error| error.to_string())?;
        let start = view.revision();
        drop(view);
        let (stream, verify) = match from {
            Some(from) => match store.watch(Some(from), watch_filter()) {
                Ok(stream) => (stream, false),
                Err(_) => (
                    store
                        .watch(Some(start), watch_filter())
                        .map_err(|error| error.to_string())?,
                    true,
                ),
            },
            None => (
                store
                    .watch(Some(start), watch_filter())
                    .map_err(|error| error.to_string())?,
                true,
            ),
        };
        let shared = Arc::new(Shared {
            inbox: std::sync::Mutex::new(Inbox {
                position: start,
                ..Inbox::default()
            }),
            tracked: std::sync::Mutex::new(tracked.clone()),
            notify: tokio::sync::Notify::new(),
        });
        let drain_stop = stop.child_token();
        let drainer = tokio::spawn(drain(
            Arc::clone(self),
            store,
            stream,
            Arc::clone(&shared),
            drain_stop.clone(),
        ));
        let result = self.serve(&shared, &tracked, start, verify, &stop).await;
        drain_stop.cancel();
        let _ = drainer.await;
        result
    }

    async fn serve(
        &self,
        shared: &Shared,
        tracked: &BTreeMap<ZoneId, DnssecMode>,
        start: Revision,
        verify: bool,
        stop: &CancellationToken,
    ) -> Result<(), String> {
        for (id, mode) in tracked {
            if stop.is_cancelled() {
                return Ok(());
            }
            let trigger = Trigger {
                position: Some(start),
                ..Trigger::full(verify && *mode == DnssecMode::Online)
            };
            if let Err(error) = self.sync(*id, trigger).await {
                tracing::warn!(zone = %id, %error, "the zone could not be signed at the start");
            }
        }
        let mut tick = tokio::time::interval(self.config.tick);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = shared.notify.notified() => {
                    tokio::time::sleep(self.config.debounce).await;
                    let (pending, position, failed) = {
                        let mut inbox = shared.inbox.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        (std::mem::take(&mut inbox.zones), inbox.position, inbox.failed.take())
                    };
                    if let Some(failed) = failed {
                        return Err(failed);
                    }
                    for (id, mut trigger) in pending {
                        trigger.position = Some(position);
                        if let Err(error) = self.sync(id, trigger).await {
                            tracing::warn!(zone = %id, %error, "signing failed");
                        }
                        if let Ok(view) = self.zones.view(None).await
                            && let Ok(row) = ZoneService::zone(view.as_ref(), id)
                        {
                            shared
                                .tracked
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .insert(id, row.zone.dnssec.mode);
                        }
                    }
                }
                _ = tick.tick() => {
                    let tracked = shared
                        .tracked
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    if let Err(error) = self.on_timer(&tracked).await {
                        tracing::warn!(%error, "the signing timer could not look at the zones");
                    }
                }
            }
        }
    }

    /// The timer: re-signs zones that are due, starts scheduled rollovers, reads the
    /// expiry of imported zones again.
    async fn on_timer(&self, tracked: &BTreeMap<ZoneId, DnssecMode>) -> ZoneResult<()> {
        let at = now();
        for (id, mode) in tracked {
            let view = self.zones.view(None).await?;
            let Ok(row) = ZoneService::zone(view.as_ref(), *id) else {
                continue;
            };
            let state = ZoneService::sign_state(view.as_ref(), *id)?.map(|(state, _)| state);
            drop(view);
            let due = state
                .as_ref()
                .and_then(|state| state.next_resign)
                .is_some_and(|due| due <= at);
            match mode {
                DnssecMode::Online => {
                    if due {
                        let trigger = Trigger {
                            timer: true,
                            ..Trigger::full(false)
                        };
                        self.sync(*id, trigger).await?;
                    }
                    if let Some(state) = &state {
                        rollover::schedule(self, &row.zone, state, at).await;
                    }
                }
                DnssecMode::Imported if due => {
                    self.sync(*id, Trigger::default()).await?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// The tables the signer watches.
fn watch_filter() -> WatchFilter {
    WatchFilter::tables([ZONES.name().clone(), RRSETS.name().clone()])
}

/// The changes gathered for the next passes.
#[derive(Default)]
struct Inbox {
    /// The pass each zone needs.
    zones: HashMap<ZoneId, Trigger>,
    /// The revision the gathered changes run to.
    position: Revision,
    /// Why the change stream ended, which stops the service.
    failed: Option<String>,
}

/// What the drain task and the loop of the service share.
struct Shared {
    inbox: std::sync::Mutex<Inbox>,
    tracked: std::sync::Mutex<BTreeMap<ZoneId, DnssecMode>>,
    notify: tokio::sync::Notify,
}

impl Shared {
    fn inbox(&self) -> std::sync::MutexGuard<'_, Inbox> {
        self.inbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn tracked(&self) -> std::sync::MutexGuard<'_, BTreeMap<ZoneId, DnssecMode>> {
        self.tracked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Every zone gets a full pass that verifies the signatures it keeps.
    fn everything_again(&self) {
        let tracked = self.tracked().clone();
        let mut inbox = self.inbox();
        for id in tracked.keys() {
            inbox.zones.insert(*id, Trigger::full(true));
        }
    }

    /// Stops the service with `reason` at its next look at the inbox.
    fn fail(&self, reason: String) {
        self.inbox().failed = Some(reason);
        self.notify.notify_one();
    }

    /// Gathers one change set; whether it asks for a pass.
    fn gather(&self, signer: &Signer, changes: &tenko_store::ChangeSet) -> bool {
        let mut tracked = self.tracked();
        let mut inbox = self.inbox();
        inbox.position = changes.revision;
        if signer.is_own(changes.revision) {
            return false;
        }
        let mut any = false;
        for change in &changes.changes {
            if change.table == *ZONES.name() {
                let Ok(id) = ZONES.decode_key(&change.key) else {
                    continue;
                };
                inbox.zones.entry(id).or_default().full = true;
                tracked.entry(id).or_insert(DnssecMode::Off);
                any = true;
            } else if change.table == *RRSETS.name() {
                let Ok(key) = RRSETS.decode_key(&change.key) else {
                    continue;
                };
                let Some(mode) = tracked.get(&key.zone) else {
                    continue;
                };
                if is_generated(key.rtype) && *mode != DnssecMode::Imported {
                    continue;
                }
                let RrSetKey {
                    zone,
                    scope,
                    name,
                    rtype,
                } = key;
                inbox
                    .zones
                    .entry(zone)
                    .or_default()
                    .changed
                    .entry(scope)
                    .or_default()
                    .insert((name, rtype));
                any = true;
            }
        }
        any
    }
}

/// Reads the store's change stream and gathers the changes of the zones the signer looks
/// after, leaving out its own commits: a zone's settings ask for a full pass, its RRsets
/// for an incremental one. A stream that fell behind is opened again where it stopped; when
/// the store no longer holds those revisions, every zone gets a full pass that verifies the
/// signatures it keeps.
async fn drain(
    signer: Arc<Signer>,
    store: Arc<dyn tenko_store::Store>,
    mut stream: tenko_store::ChangeStream,
    shared: Arc<Shared>,
    stop: CancellationToken,
) {
    loop {
        let item = tokio::select! {
            () = stop.cancelled() => return,
            item = stream.next() => item,
        };
        let reopen = match item {
            Some(Ok(changes)) => {
                if shared.gather(&signer, &changes) {
                    shared.notify.notify_one();
                }
                continue;
            }
            Some(Err(WatchError::Lagged { last })) => {
                tracing::warn!(%last, "the signer fell behind the store's change stream; reading it again from there");
                match store.watch(Some(last), watch_filter()) {
                    Ok(again) => {
                        stream = again;
                        continue;
                    }
                    Err(_) => true,
                }
            }
            Some(Err(WatchError::Compacted { .. })) => true,
            None => {
                shared.fail("the change stream of the store ended".to_owned());
                return;
            }
        };
        if reopen {
            tracing::warn!(
                "the store no longer holds the changes the signer missed; every zone gets a full pass"
            );
            shared.everything_again();
            match store.watch(None, watch_filter()) {
                Ok(again) => stream = again,
                Err(error) => {
                    shared.fail(error.to_string());
                    return;
                }
            }
            shared.notify.notify_one();
        }
    }
}

/// The stable name of the zone's algorithm.
pub fn algorithm_name(zone: &Zone) -> &'static str {
    match zone.dnssec.algorithm {
        tenko_core::dns::DnssecAlgorithm::EcdsaP256Sha256 => "ecdsap256sha256",
        tenko_core::dns::DnssecAlgorithm::Ed25519 => "ed25519",
    }
}

/// The stable name of the zone's denial.
pub fn denial_name(zone: &Zone) -> &'static str {
    match zone.dnssec.denial {
        tenko_core::dns::Denial::Nsec => "nsec",
        tenko_core::dns::Denial::Nsec3 { .. } => "nsec3",
    }
}

/// The leader service of the signer.
struct SignerService(Arc<Signer>);

#[async_trait::async_trait]
impl LeaderService for SignerService {
    fn name(&self) -> &'static str {
        "dns.signer"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        self.0.run_leader(epoch, stop).await
    }
}

/// The largest TTL of the RRsets of a zone and the earliest expiration of its signatures,
/// for the waits of a rollover.
///
/// # Errors
///
/// The store's error.
pub fn max_ttl(view: &dyn ReadView, zone: &Zone) -> ZoneResult<u32> {
    let mut largest = 0;
    for scope in &zone.scopes {
        let (_, ttl) = pass::scan_signatures(view, zone, &scope.name, true, 0)?;
        largest = largest.max(ttl);
    }
    Ok(largest)
}

/// Shared with the rollover: a pass of one zone that renews nothing ahead of time.
pub fn key_trigger() -> Trigger {
    Trigger::full(false)
}

/// The rows of a zone the signer wrote, by type, for tests and tools.
///
/// # Errors
///
/// The store's error.
pub fn generated(view: &dyn ReadView, zone: &Zone) -> ZoneResult<Vec<RrSet>> {
    let mut out = Vec::new();
    for scope in &zone.scopes {
        out.extend(
            pass::generated_rows(view, zone, &scope.name)?
                .into_iter()
                .map(|(row, _)| row),
        );
    }
    Ok(out)
}
