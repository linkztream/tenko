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
//! On the controller that leads, the leader service `ipam.reconcile`
//! ([`Reconciler::leader_service`]) runs it right after taking office and then on an
//! interval (five minutes by default), shortly after every ingest and every new fact
//! (debounced: an ingest on another controller reaches the leader as a write to
//! `ipam.obs.facts`), after changes to the intent tables and adoption policies, and purges
//! old facts on its own timer (hourly by default). Its writes are fenced with the leader
//! epoch, so a deposed leader's late run commits nothing. [`Reconciler::reconcile`] runs
//! once on demand (`POST /proposals/reconcile`) on any controller. Runs never overlap on
//! one controller.
//!
//! # Settings
//!
//! The intervals, the orphan age, the retention, the refresh and adoption are settings in
//! the store ([`settings`], `ipam.reconciler_settings`), read at every run, so a change
//! applies at the next run without a restart; `max_attempts` is a code constant.
//!
//! # Observations and waiting jobs
//!
//! [`Reconciler::ingest`] writes a batch of observations ([`crate::observe::ingest()`]),
//! hands every observed address to the jobs that wait for one (the job engine's
//! observation wake-up), confirms waiting move steps at once, and schedules a run.

pub mod moves;
pub(crate) mod rules;
pub mod scopes;
pub mod settings;
pub(crate) mod snapshot;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    ObjectRef, Principal, RequestCtx, Revision, SystemComponent, Timestamp,
    cluster::{LEADER_EPOCH, LeaderService},
    observe::{Observation, Observed},
};
use tenko_store::{ReadConsistency, StoreError, WatchFilter, WriteBatch, fence};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
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
        tables::{FACTS, LAST_SEEN},
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

/// The name of the leader service that runs the reconciler.
pub const LEADER_SERVICE: &str = "ipam.reconcile";

/// `tenko_ipam_ingest_batches_total`: observation batches [`Reconciler::ingest`] wrote on
/// this controller. The server registers the family with its metrics registry.
pub static INGEST_BATCHES: tenko_core::metrics::Counter =
    tenko_core::metrics::Counter::new(tenko_core::metrics::Desc::counter(
        "tenko_ipam_ingest_batches",
        "Observation batches ingested by this controller.",
    ));

/// `tenko_ipam_ingest_facts_total`: the observations (facts) in those batches.
pub static INGEST_FACTS: tenko_core::metrics::Counter =
    tenko_core::metrics::Counter::new(tenko_core::metrics::Desc::counter(
        "tenko_ipam_ingest_facts",
        "Observations in the batches ingested by this controller.",
    ));

/// Settings of the reconciler: the code defaults, which the settings in the store
/// ([`settings`]) override at every run.
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
/// change set touching the intent tables, the adoption policies or the facts (an ingest on
/// any controller), on every controller.
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
                FACTS.name(),
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

    /// The settings it was built with (the code defaults in the server); the settings in
    /// the store override them ([`Self::effective`]).
    pub fn config(&self) -> &ReconcilerConfig {
        &self.config
    }

    /// The settings in force now: the stored settings over [`Self::config`], or
    /// [`Self::config`] while none are stored or the store cannot be read.
    pub async fn effective(&self) -> ReconcilerConfig {
        match settings::read_stored(self.ipam.store().as_ref()).await {
            Ok(Some(stored)) => stored.apply(self.config),
            Ok(None) => self.config,
            Err(error) => {
                tracing::warn!(error = %error.code_str(), "the reconciler settings could not be read; the defaults apply");
                self.config
            }
        }
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
        let config = self.effective().await;
        let report = observe::ingest(self.ipam.store(), &batch, &config.observe).await?;
        INGEST_BATCHES.inc();
        INGEST_FACTS.add(u64::try_from(batch.observations.len()).unwrap_or(u64::MAX));
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
        self.purge_fenced(now, None).await
    }

    async fn purge_fenced(&self, now: Timestamp, epoch: Option<u64>) -> IpamResult<usize> {
        let config = self.effective().await;
        observe::retention::purge_fenced(self.ipam.store(), &config.observe, now, epoch).await
    }

    /// One run at `now` (see the module documentation).
    ///
    /// # Errors
    ///
    /// Store errors, or `ipam.contended` when concurrent writers kept invalidating the
    /// proposal write. Failed adoptions are recorded on their proposals, not returned.
    pub async fn reconcile(&self, now: Timestamp) -> IpamResult<ReconcileReport> {
        self.reconcile_fenced(now, None).await
    }

    /// [`reconcile`](Self::reconcile), with the proposal write fenced with the leader
    /// `epoch` when given; a deposed leader's run ends with `ipam.reconcile.deposed`.
    async fn reconcile_fenced(
        &self,
        now: Timestamp,
        epoch: Option<u64>,
    ) -> IpamResult<ReconcileReport> {
        let _guard = self.run_lock.lock().await;
        let config = self.effective().await;
        let mut report = ReconcileReport::empty(now);
        let attempts = config.max_attempts.max(1);
        let mut committed = None;
        for attempt in 0..attempts {
            let consistency = if attempt == 0 {
                ReadConsistency::Local
            } else {
                ReadConsistency::Linearizable
            };
            let view = self.ipam.store().read(consistency).await?;
            if let Some(epoch) = epoch
                && view.counter(&LEADER_EPOCH)? != epoch
            {
                return Err(deposed());
            }
            let snapshot = Snapshot::load(view.as_ref(), now)?;
            drop(view);
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Reconciler), now);
            if let Some(epoch) = epoch {
                batch.preconditions.push(fence(epoch));
            }
            let sightings = Self::sightings(&snapshot, &mut batch, &mut report, &config)?;
            let candidates = rules::candidates(
                &snapshot,
                &sightings,
                RuleConfig {
                    orphan_after: config.orphan_after,
                },
            );
            let counts = sync::sync(
                &snapshot,
                &candidates,
                &SyncConfig {
                    refresh: config.observe.refresh,
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
                Err(StoreError::PreconditionFailed(_)) => {
                    if let Some(epoch) = epoch
                        && self.deposed(epoch).await
                    {
                        return Err(deposed());
                    }
                    if attempt + 1 >= attempts {
                        return Err(IpamError::contended(attempts));
                    }
                    report.sightings = 0;
                    tracing::debug!(attempt, "reconcile write stale; running again");
                }
                Err(error) => return Err(error.into()),
            }
        }
        if config.adopt {
            self.adopt(committed, now, &mut report).await?;
        }
        report.moves_confirmed = self.confirm_moves(now).await?;
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(report.clone());
        Ok(report)
    }

    /// Brings the last sightings of addresses and interfaces up to date in `batch` and
    /// returns them as they will be.
    fn sightings(
        snapshot: &Snapshot,
        batch: &mut WriteBatch,
        report: &mut ReconcileReport,
        config: &ReconcilerConfig,
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
                sighting.at.saturating_since(current.at) >= config.observe.refresh
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
            let Some((prefix, host_mode)) = adoption::adopter(
                &snapshot.intent,
                &snapshot.policies,
                &snapshot.vendors,
                proposal,
            ) else {
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

    /// Whether the leader epoch moved past `epoch` (another controller took office).
    async fn deposed(&self, epoch: u64) -> bool {
        match self.ipam.store().read(ReadConsistency::Local).await {
            Ok(view) => view
                .counter(&LEADER_EPOCH)
                .is_ok_and(|current| current != epoch),
            Err(_) => false,
        }
    }

    /// The leader service `ipam.reconcile` (see the module documentation).
    pub fn leader_service(self: &Arc<Self>) -> Arc<dyn LeaderService> {
        Arc::new(ReconcileService(Arc::clone(self)))
    }

    /// The loop of the leader service until `stop` fires: a run right away and then every
    /// interval, a run shortly after every ingest and intent change, and purges on their
    /// own timer. The settings are read again before every wait, so a changed interval
    /// applies from the next wait. Errors are logged; the loop goes on, except when the
    /// controller was deposed.
    async fn serve(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        use tokio::time::{Instant, sleep, sleep_until};
        let mut last_run: Option<Instant> = None;
        let mut last_purge = Instant::now();
        loop {
            let config = self.effective().await;
            let next_run = last_run.map_or_else(Instant::now, |at| at + config.interval);
            let next_purge = last_purge + config.purge_interval;
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = sleep_until(next_run) => {}
                () = self.wake.notified() => {
                    tokio::select! {
                        () = stop.cancelled() => return Ok(()),
                        () = sleep(config.debounce) => {}
                    }
                }
                () = self.changed.notified() => {
                    tokio::select! {
                        () = stop.cancelled() => return Ok(()),
                        () = sleep(config.debounce) => {}
                    }
                }
                () = sleep_until(next_purge) => {
                    last_purge = Instant::now();
                    match self.purge_fenced(Timestamp::now(), Some(epoch)).await {
                        Ok(0) => {}
                        Ok(count) => tracing::info!(count, "observation facts purged"),
                        Err(error) => tracing::warn!(error = %error.code_str(), "observation purge failed"),
                    }
                    continue;
                }
            }
            last_run = Some(Instant::now());
            match self.reconcile_fenced(Timestamp::now(), Some(epoch)).await {
                Ok(report) => tracing::debug!(?report, "reconcile run"),
                Err(error) if error.code_str() == DEPOSED => {
                    return Err("this controller no longer leads".to_owned());
                }
                Err(error) => tracing::warn!(error = %error.code_str(), "reconcile run failed"),
            }
        }
    }
}

/// The code of a run of a deposed leader.
const DEPOSED: &str = "ipam.reconcile.deposed";

fn deposed() -> IpamError {
    IpamError::new(
        DEPOSED,
        409,
        "this controller no longer leads; the run was not committed",
    )
}

/// The leader service `ipam.reconcile`.
struct ReconcileService(Arc<Reconciler>);

#[async_trait::async_trait]
impl LeaderService for ReconcileService {
    fn name(&self) -> &'static str {
        LEADER_SERVICE
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        self.0.serve(epoch, stop).await
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
