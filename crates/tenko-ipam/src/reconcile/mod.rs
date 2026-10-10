//! The reconciler (IPAM-13, ADR 0005 decision 3): compares intent with observation and
//! keeps `ipam.proposals` in step with what it finds.
//!
//! # A run
//!
//! 1. One read view: the live intent, every fact, the open proposals, the remembered
//!    rejections, the adoption policies and the last sightings ([`snapshot`]).
//! 2. The last sightings of addresses and interfaces of intent are brought up to date from
//!    the current facts (`ipam.obs.last_seen`, at most once per refresh interval).
//! 3. The rules ([`rules`]) say which proposals should be open; [`crate::proposals`]
//!    opens, refreshes, supersedes and expires accordingly. Steps 2 and 3 commit as one
//!    batch (`system:reconciler`), which a concurrent writer makes the run repeat.
//! 4. Open proposals that an adoption policy covers are applied, each in its own inline
//!    job as `system:reconciler`.
//! 5. Move jobs waiting at their observation step are confirmed when a current fact shows
//!    the device at its new address ([`moves`]).
//!
//! # When it runs
//!
//! [`Reconciler::run`] runs on an interval (five minutes by default), shortly after every
//! ingest, after changes to the intent tables and adoption policies (debounced), and
//! purges old facts every hour. [`Reconciler::reconcile`] runs once on demand
//! (`POST /proposals/reconcile`). Runs never overlap on one controller; in a cluster
//! every controller runs its own loop and the preconditions keep their writes apart
//! (leader-only scheduling is a Slice 3 item).
//!
//! # Observations and waiting jobs
//!
//! [`Reconciler::ingest`] writes a batch of observations ([`crate::observe::ingest()`]),
//! hands every observed address to the jobs that wait for one (the job engine's
//! observation wake-up), confirms waiting move steps at once, and schedules a run.

pub mod moves;
pub(crate) mod rules;
pub(crate) mod snapshot;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    ObjectRef, Principal, RequestCtx, Revision, SystemComponent, Timestamp,
    observe::{Observation, Observed},
};
use tenko_store::{ReadConsistency, StoreError, WatchFilter, WriteBatch};
use tokio::sync::Notify;
use utoipa::ToSchema;

pub use self::rules::{DISCOVERED_TAG, rule};
use self::{
    moves::WaitingMove,
    rules::RuleConfig,
    snapshot::{Intent, Placement, Snapshot},
};
use crate::{
    error::{IpamError, IpamResult},
    observe::{
        self, IngestBatch, IngestReport, ObserveConfig,
        model::{IntentSighting, observed_ips, observed_macs},
        tables::LAST_SEEN,
    },
    plan::PlanOptions,
    proposals::{
        adoption,
        decide::{self, Applier},
        model::ADOPTION,
        sync::{self, SyncConfig},
    },
    service::IpamService,
    tables,
};

/// Settings of the reconciler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconcilerConfig {
    /// The observation layer.
    pub observe: ObserveConfig,
    /// Interval of periodic runs.
    pub interval: Duration,
    /// Delay of a run after an ingest or an intent change, collecting what follows.
    pub debounce: Duration,
    /// How long an intended address may go unseen (after it was seen) before it is
    /// proposed as orphaned (7 days).
    pub orphan_after: Duration,
    /// Interval of retention purges.
    pub purge_interval: Duration,
    /// Runs repeated after losing races with other writers.
    pub max_attempts: u32,
    /// Whether adoption policies are applied (off: every proposal waits for a person).
    pub adopt: bool,
}

impl Default for ReconcilerConfig {
    fn default() -> Self {
        Self {
            observe: ObserveConfig::default(),
            interval: Duration::from_secs(300),
            debounce: Duration::from_secs(2),
            orphan_after: Duration::from_secs(7 * 24 * 3600),
            purge_interval: Duration::from_secs(3600),
            max_attempts: 8,
            adopt: true,
        }
    }
}

/// What one run did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ReconcileReport {
    /// When the run started.
    pub at: Timestamp,
    /// Proposals opened.
    pub opened: u32,
    /// Open proposals whose evidence was refreshed.
    pub refreshed: u32,
    /// Open proposals left as they were.
    pub unchanged: u32,
    /// Proposals replaced by newer ones.
    pub superseded: u32,
    /// Proposals whose observation no longer holds.
    pub expired: u32,
    /// Subjects not opened again because a person rejected the same evidence.
    pub suppressed: u32,
    /// Proposals adopted by a policy.
    pub adopted: u32,
    /// Adoptions that failed (recorded on the proposal).
    pub adoption_failures: u32,
    /// Last sightings of intent objects written.
    pub sightings: u32,
    /// Move jobs whose observation step was confirmed.
    pub moves_confirmed: u32,
    /// The revision of the proposal write; `null` when nothing changed.
    #[schema(value_type = Option<u64>)]
    pub revision: Option<Revision>,
}

impl ReconcileReport {
    /// A report of a run at `at` that did nothing yet.
    pub fn empty(at: Timestamp) -> Self {
        Self {
            at,
            opened: 0,
            refreshed: 0,
            unchanged: 0,
            superseded: 0,
            expired: 0,
            suppressed: 0,
            adopted: 0,
            adoption_failures: 0,
            sightings: 0,
            moves_confirmed: 0,
            revision: None,
        }
    }
}

/// The reconciler of one controller. Shared as `Arc<Reconciler>`; the API reaches it as a
/// request extension.
pub struct Reconciler {
    ipam: Arc<IpamService>,
    config: ReconcilerConfig,
    wake: Notify,
    changed: Arc<Notify>,
    run_lock: tokio::sync::Mutex<()>,
    last: Mutex<Option<ReconcileReport>>,
}

/// A derived index that only signals: the store calls it on its apply path for every
/// change set touching the intent tables or the adoption policies.
struct ChangeSignal {
    notify: Arc<Notify>,
}

/// The image of [`ChangeSignal`]: nothing but the revision.
struct NoImage(Revision);

impl tenko_store::IndexImage for NoImage {
    fn revision(&self) -> Revision {
        self.0
    }
}

impl tenko_store::DerivedIndex for ChangeSignal {
    fn filter(&self) -> WatchFilter {
        WatchFilter::tables(
            [
                tables::TENANTS.name(),
                tables::VRFS.name(),
                tables::PREFIXES.name(),
                tables::RANGES.name(),
                tables::ADDRESSES.name(),
                tables::HOSTS.name(),
                tables::INTERFACES.name(),
                ADOPTION.name(),
            ]
            .into_iter()
            .cloned(),
        )
    }

    fn build(
        &self,
        view: &dyn tenko_store::ReadView,
    ) -> Result<Box<dyn tenko_store::IndexImage>, StoreError> {
        Ok(Box::new(NoImage(view.revision())))
    }

    fn install(&self, _image: Box<dyn tenko_store::IndexImage>) {}

    fn apply(&self, _changes: &tenko_store::ChangeSet, _view: &dyn tenko_store::ReadView) {
        self.notify.notify_one();
    }
}

impl std::fmt::Debug for Reconciler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reconciler")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

fn reconciler_cx(now: Timestamp) -> RequestCtx {
    let mut cx = RequestCtx::system(SystemComponent::Reconciler);
    cx.now = now;
    cx
}

impl Reconciler {
    /// A reconciler over the IPAM service; registers a change signal with the store so
    /// that intent changes schedule a run.
    ///
    /// # Errors
    ///
    /// The store's error if the signal cannot be registered.
    pub fn new(ipam: Arc<IpamService>, config: ReconcilerConfig) -> IpamResult<Arc<Self>> {
        let changed = Arc::new(Notify::new());
        ipam.store().register_index(Arc::new(ChangeSignal {
            notify: Arc::clone(&changed),
        }) as Arc<dyn tenko_store::DerivedIndex>)?;
        Ok(Arc::new(Self {
            ipam,
            config,
            wake: Notify::new(),
            changed,
            run_lock: tokio::sync::Mutex::new(()),
            last: Mutex::new(None),
        }))
    }

    /// The IPAM service.
    pub fn ipam(&self) -> &Arc<IpamService> {
        &self.ipam
    }

    /// The settings.
    pub fn config(&self) -> &ReconcilerConfig {
        &self.config
    }

    /// The report of the last run on this controller.
    pub fn last_report(&self) -> Option<ReconcileReport> {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Asks the loop for a run soon.
    pub fn nudge(&self) {
        self.wake.notify_one();
    }

    /// Writes a batch of observations, wakes the jobs that wait for them and schedules a
    /// run (see the module documentation). This is the sink of the connector host and,
    /// later, of probes.
    ///
    /// # Errors
    ///
    /// The ingest's errors; failures to wake jobs are logged.
    pub async fn ingest(&self, batch: IngestBatch) -> IpamResult<IngestReport> {
        let report = observe::ingest(self.ipam.store(), &batch, &self.config.observe).await?;
        if let Err(error) = self.wake_jobs(&batch.observations, report.revision).await {
            tracing::warn!(error = %error.code_str(), "observations did not reach waiting jobs");
        }
        if report.wrote() {
            self.nudge();
        }
        Ok(report)
    }

    /// Hands the addresses of `observations` to waiting jobs and confirms waiting moves.
    async fn wake_jobs(
        &self,
        observations: &[Observation],
        at_least: Option<Revision>,
    ) -> IpamResult<()> {
        let view = self.ipam.view(at_least).await?;
        if !moves::any_waiting(view.as_ref())? {
            return Ok(());
        }
        let intent = Intent::load(view.as_ref())?;
        let waiting = moves::waiting_moves(view.as_ref())?;
        drop(view);
        let mut confirmed = Vec::new();
        for observation in observations {
            for (vrf, ip, mac) in address_pairs(observation, &intent) {
                let address = match &observation.subject {
                    Observed::Address { .. } => observation.clone(),
                    _ => Observation {
                        subject: Observed::Address { vrf, ip, mac },
                        ..observation.clone()
                    },
                };
                self.ipam.jobs().on_observation(&address).await;
                for waiting_move in &waiting {
                    if !confirmed.contains(&waiting_move.job)
                        && waiting_move.confirmed_by(Some(vrf), ip, mac, observation.observed_at)
                    {
                        confirmed.push(waiting_move.job);
                        self.confirm_move(
                            waiting_move,
                            &observation.source,
                            observation.observed_at,
                        )
                        .await;
                    }
                }
            }
        }
        Ok(())
    }

    /// Completes the observation step of a waiting move.
    async fn confirm_move(
        &self,
        waiting: &WaitingMove,
        source: &tenko_core::observe::ObservationSource,
        seen_at: Timestamp,
    ) -> bool {
        let note = format!(
            "{} seen at {seen_at} by {}",
            waiting.ip,
            observe::source_key(source)
        );
        let cx = reconciler_cx(Timestamp::now());
        match self
            .ipam
            .jobs()
            .complete_manual(waiting.job, waiting.step, Some(note), &cx)
            .await
        {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(job = %waiting.job, error = %tenko_core::Coded::to_coded_error(&error).code, "move observation not confirmed");
                false
            }
        }
    }

    /// Deletes facts older than the retention (see [`observe::retention::purge`]).
    ///
    /// # Errors
    ///
    /// Store errors.
    pub async fn purge(&self, now: Timestamp) -> IpamResult<usize> {
        observe::retention::purge(self.ipam.store(), &self.config.observe, now).await
    }

    /// One run at `now` (see the module documentation).
    ///
    /// # Errors
    ///
    /// Store errors, or `ipam.contended` when concurrent writers kept invalidating the
    /// proposal write. Failed adoptions are recorded on their proposals, not returned.
    pub async fn reconcile(&self, now: Timestamp) -> IpamResult<ReconcileReport> {
        let _guard = self.run_lock.lock().await;
        let mut report = ReconcileReport::empty(now);
        let attempts = self.config.max_attempts.max(1);
        let mut committed = None;
        for attempt in 0..attempts {
            let consistency = if attempt == 0 {
                ReadConsistency::Local
            } else {
                ReadConsistency::Linearizable
            };
            let view = self.ipam.store().read(consistency).await?;
            let snapshot = Snapshot::load(view.as_ref(), now)?;
            drop(view);
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Reconciler), now);
            let sightings = self.sightings(&snapshot, &mut batch, &mut report)?;
            let candidates = rules::candidates(
                &snapshot,
                &sightings,
                RuleConfig {
                    orphan_after: self.config.orphan_after,
                },
            );
            let counts = sync::sync(
                &snapshot,
                &candidates,
                &SyncConfig {
                    refresh: self.config.observe.refresh,
                },
                &mut batch,
            )?;
            if batch.mutations.is_empty() {
                report.unchanged = counts.unchanged;
                report.suppressed = counts.suppressed;
                break;
            }
            match self.ipam.store().propose(batch).await {
                Ok(done) => {
                    report.opened = counts.opened;
                    report.refreshed = counts.refreshed;
                    report.unchanged = counts.unchanged;
                    report.superseded = counts.superseded;
                    report.expired = counts.expired;
                    report.suppressed = counts.suppressed;
                    report.revision = Some(done.revision);
                    committed = Some(done.revision);
                    break;
                }
                Err(StoreError::PreconditionFailed(_)) if attempt + 1 < attempts => {
                    report.sightings = 0;
                    tracing::debug!(attempt, "reconcile write stale; running again");
                }
                Err(StoreError::PreconditionFailed(_)) => {
                    return Err(IpamError::contended(attempts));
                }
                Err(error) => return Err(error.into()),
            }
        }
        if self.config.adopt {
            self.adopt(committed, now, &mut report).await?;
        }
        report.moves_confirmed = self.confirm_moves(now).await?;
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(report.clone());
        Ok(report)
    }

    /// Brings the last sightings of addresses and interfaces up to date in `batch` and
    /// returns them as they will be.
    fn sightings(
        &self,
        snapshot: &Snapshot,
        batch: &mut WriteBatch,
        report: &mut ReconcileReport,
    ) -> IpamResult<BTreeMap<ObjectRef, IntentSighting>> {
        let intent = &snapshot.intent;
        let mut newest: BTreeMap<ObjectRef, IntentSighting> = BTreeMap::new();
        let mut offer = |object: ObjectRef, sighting: IntentSighting| {
            newest
                .entry(object)
                .and_modify(|current| {
                    if sighting.at > current.at {
                        *current = sighting.clone();
                    }
                })
                .or_insert(sighting);
        };
        for pair in &snapshot.seen {
            let fact = &snapshot.facts[pair.fact];
            let sighting = IntentSighting {
                at: fact.last_seen,
                source: fact.source_key.clone(),
                observation: fact.observation,
            };
            if let (Some(ip), Some(placement)) = (pair.ip, pair.placement)
                && let Some(vrf) = placement.vrf()
                && let Some(address) = intent.address_by_ip.get(&(vrf, ip))
            {
                offer(ObjectRef::from(*address), sighting.clone());
            }
            if let Some(mac) = pair.mac {
                for interface in intent.interfaces_by_mac.get(&mac).into_iter().flatten() {
                    offer(ObjectRef::from(*interface), sighting.clone());
                }
            }
        }
        let mut merged: BTreeMap<ObjectRef, IntentSighting> = snapshot
            .sightings
            .iter()
            .map(|(object, (sighting, _))| (*object, sighting.clone()))
            .collect();
        for (object, sighting) in newest {
            let stored = snapshot.sightings.get(&object);
            let due = stored.is_none_or(|(current, _)| {
                sighting.at.saturating_since(current.at) >= self.config.observe.refresh
            });
            if !due {
                continue;
            }
            batch.put_typed(&LAST_SEEN, &object, &sighting)?;
            batch.expect_typed(&LAST_SEEN, &object, stored.map(|(_, revision)| *revision));
            report.sightings += 1;
            merged.insert(object, sighting);
        }
        Ok(merged)
    }

    /// Applies the open proposals that an adoption policy covers.
    async fn adopt(
        &self,
        at_least: Option<Revision>,
        now: Timestamp,
        report: &mut ReconcileReport,
    ) -> IpamResult<()> {
        let view = self.ipam.view(at_least).await?;
        let any_policy = tenko_store::ReadViewExt::scan_typed(
            view.as_ref(),
            &ADOPTION,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )?
        .iter()
        .any(|(_, stored, _)| stored.policy.mode != crate::proposals::AdoptionMode::Manual);
        if !any_policy {
            return Ok(());
        }
        let snapshot = Snapshot::load(view.as_ref(), now)?;
        drop(view);
        let cx = reconciler_cx(now);
        for (proposal, _) in snapshot.open.values() {
            let Some((prefix, host_mode)) =
                adoption::adopter(&snapshot.intent, &snapshot.policies, proposal)
            else {
                continue;
            };
            let applier = Applier::Policy { prefix, host_mode };
            match decide::apply(
                &self.ipam,
                proposal.id,
                &cx,
                &PlanOptions::default(),
                false,
                None,
                applier,
            )
            .await
            {
                Ok(_) => report.adopted += 1,
                Err(error) => {
                    tracing::info!(proposal = %proposal.id, error = %error.code_str(), "adoption failed");
                    report.adoption_failures += 1;
                    if let Err(error) =
                        decide::record_adoption_failure(&self.ipam, proposal.id, &error, &cx).await
                    {
                        tracing::warn!(error = %error.code_str(), "adoption failure not recorded");
                    }
                }
            }
        }
        Ok(())
    }

    /// Confirms move jobs waiting at their observation step from the current facts.
    async fn confirm_moves(&self, now: Timestamp) -> IpamResult<u32> {
        let view = self.ipam.store().read(ReadConsistency::Local).await?;
        let waiting = moves::waiting_moves(view.as_ref())?;
        if waiting.is_empty() {
            return Ok(0);
        }
        let snapshot = Snapshot::load(view.as_ref(), now)?;
        drop(view);
        let mut confirmed = 0;
        for waiting_move in &waiting {
            let hit = snapshot.seen.iter().find(|pair| {
                pair.ip.is_some_and(|ip| {
                    waiting_move.confirmed_by(
                        pair.placement.and_then(Placement::vrf),
                        ip,
                        pair.mac,
                        snapshot.facts[pair.fact].last_seen,
                    )
                })
            });
            if let Some(pair) = hit {
                let fact = &snapshot.facts[pair.fact];
                if self
                    .confirm_move(waiting_move, &fact.source, fact.last_seen)
                    .await
                {
                    confirmed += 1;
                }
            }
        }
        Ok(confirmed)
    }

    /// Runs until `shutdown` completes: periodic runs, runs shortly after ingests and
    /// intent changes, and hourly purges. Errors are logged; the loop goes on.
    pub async fn run(self: Arc<Self>, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        let mut tick = tokio::time::interval(self.config.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut purge = tokio::time::interval(self.config.purge_interval);
        purge.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = &mut shutdown => return,
                _ = tick.tick() => {}
                () = self.wake.notified() => {
                    tokio::time::sleep(self.config.debounce).await;
                }
                () = self.changed.notified() => {
                    tokio::time::sleep(self.config.debounce).await;
                }
                _ = purge.tick() => {
                    match self.purge(Timestamp::now()).await {
                        Ok(0) => {}
                        Ok(count) => tracing::info!(count, "observation facts purged"),
                        Err(error) => tracing::warn!(error = %error.code_str(), "observation purge failed"),
                    }
                    continue;
                }
            }
            match self.reconcile(Timestamp::now()).await {
                Ok(report) => tracing::debug!(?report, "reconcile run"),
                Err(error) => tracing::warn!(error = %error.code_str(), "reconcile run failed"),
            }
        }
    }
}

/// The (VRF, address, MAC) pairs of one observation, placed against the intent.
fn address_pairs(
    observation: &Observation,
    intent: &Intent,
) -> Vec<(
    tenko_core::VrfId,
    std::net::IpAddr,
    Option<tenko_core::MacAddr>,
)> {
    let macs = observed_macs(&observation.subject);
    let mac = match macs.as_slice() {
        [mac] => Some(*mac),
        _ => None,
    };
    let hint = match &observation.subject {
        Observed::Address { vrf, .. } => Some(*vrf),
        _ => None,
    };
    // A name or a vendor is not a sighting of the address.
    if matches!(
        observation.subject,
        Observed::Link { .. }
            | Observed::Attachment { .. }
            | Observed::Name { .. }
            | Observed::Vendor { .. }
    ) {
        return Vec::new();
    }
    observed_ips(&observation.subject)
        .into_iter()
        .filter(|ip| snapshot::trackable(*ip))
        .filter_map(|ip| intent.place(ip, hint).vrf().map(|vrf| (vrf, ip, mac)))
        .collect()
}
