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
//!    opens, refreshes, supersedes and expires accordingly. Steps 2 and 3 are written as
//!    `system:reconciler` in batches under the store's limit (one when it all fits), in
//!    subject-key order, each fenced with the leader epoch; the last batch carries the
//!    run's audit record (`ipam.reconcile.run`). A batch that fails is tried once more as
//!    two halves, and what still fails is counted on the report as unwritten for the next
//!    run to write. A concurrent writer makes the run read again and write what is left.
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
//! one controller. A change set of DHCP's names alone schedules no run, and a run after
//! facts alone reads no zone ([`signal`]); the periodic run always reads everything.
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

pub(crate) mod dormant;
pub mod moves;
pub(crate) mod rules;
pub mod scopes;
pub mod settings;
// The follow-ups of Slice 8: which change sets schedule a run and which change the DNS
// steps' inputs (M31).
pub(crate) mod signal;
pub(crate) mod snapshot;
// WP8.2: the reconciliation view of the four truths (IPAM-21, IPAM-23).
pub mod view;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    ObjectRef, RequestCtx, Revision, SystemComponent, Timestamp,
    audit::{AuditAction, AuditDraft},
    cluster::{LEADER_EPOCH, LeaderService},
    observe::{Observation, Observed},
};
use tenko_store::{ReadConsistency, StoreError, fence};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use utoipa::ToSchema;

pub use self::rules::{DISCOVERED_TAG, rule};
use self::{
    moves::WaitingMove,
    rules::RuleConfig,
    signal::{ChangeSignal, Epochs},
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
        sync::{self, Item, SyncConfig, SyncCounts},
    },
    service::IpamService,
};

/// The name of the leader service that runs the reconciler.
pub const LEADER_SERVICE: &str = "ipam.reconcile";

/// The audit action of a run that wrote something: its context says how many batches it
/// took, how many proposal rows and sightings it wrote, and how many items it could not
/// write.
pub const RUN_ACTION: &str = "ipam.reconcile.run";

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
    /// Whether the DNS actuator writes after every run (when the server gave the
    /// reconciler one, [`Reconciler::set_dns`]).
    pub dns_actuator: bool,
    /// What happens to an `ipam` RRset that nothing wants any more.
    pub dns_orphans: crate::dns::OrphanRule,
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
            dns_actuator: true,
            dns_orphans: crate::dns::OrphanRule::Remove,
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
    /// What the DNS actuator wrote; `null` without the DNS module or with the actuator
    /// off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<crate::dns::DnsActuation>,
    /// The revision of the proposal write (its last batch); `null` when nothing changed.
    #[schema(value_type = Option<u64>)]
    pub revision: Option<Revision>,
    /// Batches the proposal write took: one when it fits the store's batch limit, more
    /// when it does not; 0 when nothing changed.
    #[serde(default)]
    pub batches: u32,
    /// Proposal writes and sightings not written: those of a batch that failed and failed
    /// again as two halves. The next run writes them.
    #[serde(default)]
    pub unwritten: u32,
    /// The error code of the last batch that failed; `null` when every batch was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
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
            dns: None,
            revision: None,
            batches: 0,
            unwritten: 0,
            failure: None,
        }
    }
}

/// What the batches of one run wrote so far, kept across the passes of a run that read
/// again after a failed precondition: the keys an earlier pass committed are not counted
/// again by the next.
#[derive(Debug, Default)]
struct Written {
    batches: u32,
    counts: SyncCounts,
    revision: Option<Revision>,
    keys: BTreeSet<String>,
    unwritten: u32,
    failure: Option<String>,
}

/// How writing a run's items ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Every batch was tried; what failed twice is counted as unwritten.
    Done,
    /// A batch lost a race with another writer: what was committed stays, the run reads
    /// again.
    Contended,
}

/// The size budget of one batch: three quarters of the store's limit, the rest a margin
/// for the fence, the item sizes' rounding and the run's audit record.
fn batch_budget(max_batch_bytes: usize) -> usize {
    max_batch_bytes / 4 * 3
}

/// The run's audit record.
fn run_record(batches: u32, counts: SyncCounts, unwritten: u32) -> AuditDraft {
    AuditDraft::success(AuditAction::from_static(RUN_ACTION), Vec::new())
        .with_context("batches", batches.to_string())
        .with_context("proposals", counts.proposals().to_string())
        .with_context("sightings", counts.sightings.to_string())
        .with_context("unwritten", unwritten.to_string())
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
    dns: std::sync::OnceLock<Arc<crate::dns::DnsActuator>>,
    epochs: Arc<Epochs>,
    memo: Mutex<DnsMemo>,
}

/// What the last runs read and decided, with the change epochs they saw ([`signal`]): a
/// run whose rules epoch did not move confirms waiting moves only, and one whose DNS epochs
/// did not move takes over the DNS steps' results instead of reading every zone again.
#[derive(Debug, Default)]
struct DnsMemo {
    /// The rules epoch of the last run of the rules (successful or not: a failed pass is
    /// tried again by the next change of another kind or the periodic run, not by every
    /// lease).
    ruled: Option<u64>,
    /// Runs of the rules.
    rule_passes: u64,
    /// The records epoch of the last complete ingest of the zones.
    ingested: Option<u64>,
    /// The key of the last plan, with its findings.
    planned: Option<(PlanKey, Vec<crate::dns::DnsFinding>)>,
    /// The key of the last actuation that wrote everything it planned (no failures).
    actuated: Option<PlanKey>,
    /// Runs whose DNS steps read the zones (an ingest or a plan).
    passes: u64,
}

/// What a DNS plan depends on besides the rows the epochs follow.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanKey {
    epoch: u64,
    moves: Vec<crate::dns::MoveOverride>,
    orphans: crate::dns::OrphanRule,
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
        let epochs = Arc::new(Epochs::default());
        ipam.store().register_index(Arc::new(ChangeSignal {
            notify: Arc::clone(&changed),
            epochs: Arc::clone(&epochs),
        }) as Arc<dyn tenko_store::DerivedIndex>)?;
        Ok(Arc::new(Self {
            ipam,
            config,
            wake: Notify::new(),
            changed,
            run_lock: tokio::sync::Mutex::new(()),
            last: Mutex::new(None),
            dns: std::sync::OnceLock::new(),
            epochs,
            memo: Mutex::new(DnsMemo::default()),
        }))
    }

    /// Gives the reconciler the DNS actuator (the server does when the DNS module runs):
    /// its findings join the proposals, it writes after every run while the setting
    /// `dns_actuator` is on, and the zones' records become observations. A second call
    /// changes nothing.
    pub fn set_dns(&self, actuator: Arc<crate::dns::DnsActuator>) {
        let _ = self.dns.set(actuator);
    }

    /// The DNS actuator, when the server gave one.
    pub fn dns(&self) -> Option<&Arc<crate::dns::DnsActuator>> {
        self.dns.get()
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

    /// The runs on this controller whose DNS steps read the zones again (an ingest of the
    /// zones' records or a DNS plan); a run after facts or DHCP's names alone reads
    /// nothing (`docs/reconciliation.md` section 3.1).
    pub fn dns_passes(&self) -> u64 {
        self.memo().passes
    }

    /// The runs on this controller that evaluated the rules; a run after lease facts alone
    /// only confirms waiting moves (`docs/reconciliation.md` section 3.1).
    pub fn rule_passes(&self) -> u64 {
        self.memo().rule_passes
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
                        && waiting_move.confirmed_by_source(
                            &observation.source,
                            Some(vrf),
                            ip,
                            mac,
                            observation.observed_at,
                        )
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
        self.reconcile_fenced(now, None, true).await
    }

    /// A run after a change, as the loop starts one: the DNS steps read the zones again
    /// only when a change set since the last run that read them touched the zones, a
    /// record of another origin than `dhcp`, the intent or a reverse template
    /// (`docs/reconciliation.md` section 3.1).
    ///
    /// # Errors
    ///
    /// Those of [`reconcile`](Self::reconcile).
    pub async fn reconcile_changed(&self, now: Timestamp) -> IpamResult<ReconcileReport> {
        self.reconcile_fenced(now, None, false).await
    }

    /// [`reconcile`](Self::reconcile), with the proposal write fenced with the leader
    /// `epoch` when given; a deposed leader's run ends with `ipam.reconcile.deposed`.
    /// `full` makes the DNS steps read the zones whatever the epochs say (the periodic
    /// run, the run on demand).
    #[allow(
        clippy::too_many_lines,
        reason = "the steps of one run read best in order"
    )]
    async fn reconcile_fenced(
        &self,
        now: Timestamp,
        epoch: Option<u64>,
        full: bool,
    ) -> IpamResult<ReconcileReport> {
        let _guard = self.run_lock.lock().await;
        let config = self.effective().await;
        let mut report = ReconcileReport::empty(now);
        // Read before the views, so that a change landing in between makes the next run
        // read again rather than be missed.
        let (rules_epoch, records_epoch, plan_epoch) = self.epochs.now();
        if !full && self.memo().ruled == Some(rules_epoch) {
            // Lease facts alone since the last run of the rules: the waiting moves only.
            report.moves_confirmed = self.confirm_moves(now).await?;
            *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(report.clone());
            return Ok(report);
        }
        {
            let mut memo = self.memo();
            memo.ruled = Some(rules_epoch);
            memo.rule_passes += 1;
        }
        let mut read_zones = false;
        if self.dns.get().is_some() {
            let ingested = self.memo().ingested;
            if full || ingested != Some(records_epoch) {
                read_zones = true;
                match observe::dns::ingest_zones(self.ipam.store(), &config.observe, now).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::debug!(count, "DNS records ingested as observations");
                        }
                        self.memo().ingested = Some(records_epoch);
                    }
                    Err(error) => {
                        tracing::warn!(error = %error.code_str(), "the zones' records were not ingested");
                    }
                }
            }
        }
        let dns_options = crate::dns::PlanOptions {
            orphans: config.dns_orphans,
            ..crate::dns::PlanOptions::default()
        };
        let attempts = config.max_attempts.max(1);
        let mut written = Written::default();
        let mut left = (0, 0);
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
            let dns_findings = match self.dns.get() {
                Some(_) => {
                    let (findings, planned) =
                        self.findings(view.as_ref(), &dns_options, plan_epoch, full)?;
                    read_zones |= planned;
                    findings
                }
                None => Vec::new(),
            };
            drop(view);
            let (mut items, sightings) = Self::sightings(&snapshot, now, &config)?;
            let candidates = rules::candidates(
                &snapshot,
                &sightings,
                RuleConfig {
                    orphan_after: config.orphan_after,
                },
                &dns_findings,
            );
            let mut plan = sync::sync(
                &snapshot,
                &candidates,
                &SyncConfig {
                    refresh: config.observe.refresh,
                },
                &written.keys,
            )?;
            left = (plan.unchanged, plan.suppressed);
            // The sightings first (a key of `None`), then the proposals in key order.
            items.append(&mut plan.items);
            if items.is_empty() {
                break;
            }
            match self.write_items(items, now, epoch, &mut written).await? {
                Outcome::Done => break,
                Outcome::Contended => {
                    if let Some(epoch) = epoch
                        && self.deposed(epoch).await
                    {
                        return Err(deposed());
                    }
                    if attempt + 1 >= attempts {
                        tracing::warn!(
                            batches = written.batches,
                            "reconcile write kept losing races; what was committed stays"
                        );
                        return Err(IpamError::contended(attempts));
                    }
                    tracing::debug!(
                        attempt,
                        batches = written.batches,
                        "reconcile write stale; running again"
                    );
                }
            }
        }
        report.opened = written.counts.opened;
        report.refreshed = written.counts.refreshed;
        report.superseded = written.counts.superseded;
        report.expired = written.counts.expired;
        report.sightings = written.counts.sightings;
        report.unchanged = left.0;
        report.suppressed = left.1;
        report.revision = written.revision;
        report.batches = written.batches;
        report.unwritten = written.unwritten;
        report.failure = written.failure;
        let committed = written.revision;
        if config.adopt {
            self.adopt(committed, now, &mut report).await?;
        }
        let deposed = match epoch {
            Some(epoch) => self.deposed(epoch).await,
            None => false,
        };
        if let Some(actuator) = self.dns.get()
            && config.dns_actuator
            && !deposed
        {
            report.dns = Some(self.actuate(actuator, now, &dns_options, full).await?);
        }
        if read_zones {
            self.memo().passes += 1;
        }
        report.moves_confirmed = self.confirm_moves(now).await?;
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(report.clone());
        Ok(report)
    }

    fn memo(&self) -> std::sync::MutexGuard<'_, DnsMemo> {
        self.memo.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The DNS findings of `view`: those of the last plan when nothing it depends on moved
    /// since (and the run is not `full`), else a new plan. The flag says whether it
    /// planned.
    fn findings(
        &self,
        view: &dyn tenko_store::ReadView,
        options: &crate::dns::PlanOptions,
        epoch: u64,
        full: bool,
    ) -> IpamResult<(Vec<crate::dns::DnsFinding>, bool)> {
        let mut moves = crate::dns::plan::moves_in_flight(view, &options.ignore_jobs)?;
        moves.extend(options.moves.iter().copied());
        let key = PlanKey {
            epoch,
            moves,
            orphans: options.orphans,
        };
        if !full
            && let Some((planned, findings)) = &self.memo().planned
            && *planned == key
        {
            return Ok((findings.clone(), false));
        }
        let world = crate::dns::plan::World::load(view)?;
        let findings =
            crate::dns::plan::plan_world(view, &world, &key.moves, options.orphans)?.findings;
        self.memo().planned = Some((key, findings.clone()));
        Ok((findings, true))
    }

    /// The DNS actuator's step: skipped (nothing written) when its last run wrote all it
    /// planned and nothing it plans from moved since, unless the run is `full`.
    async fn actuate(
        &self,
        actuator: &crate::dns::DnsActuator,
        now: Timestamp,
        options: &crate::dns::PlanOptions,
        full: bool,
    ) -> IpamResult<crate::dns::DnsActuation> {
        // The plan epoch now: the adoptions of this run may have changed the intent.
        let (_, _, epoch) = self.epochs.now();
        let key = self.memo().planned.as_ref().map(|(key, _)| PlanKey {
            epoch,
            ..key.clone()
        });
        if !full && key.is_some() && self.memo().actuated == key {
            return Ok(crate::dns::DnsActuation::default());
        }
        let actuation = actuator.run(&reconciler_cx(now), options).await?;
        self.memo().actuated = if actuation.failures.is_empty() {
            key
        } else {
            None
        };
        Ok(actuation)
    }

    /// Writes `items` in batches under the store's budget, in order, each fenced with
    /// `epoch`; the last batch carries the run's audit record. A batch that fails is tried
    /// once more as two halves, and what still fails is counted as unwritten while the run
    /// goes on. A failed precondition stops the writing: what was committed stays, and the
    /// run reads again.
    async fn write_items(
        &self,
        items: Vec<Item>,
        now: Timestamp,
        epoch: Option<u64>,
        written: &mut Written,
    ) -> IpamResult<Outcome> {
        let budget = batch_budget(self.ipam.store().max_batch_bytes());
        let mut groups: Vec<Vec<Item>> = Vec::new();
        let mut current: Vec<Item> = Vec::new();
        let mut size = 0;
        for item in items {
            if !current.is_empty() && size + item.size > budget {
                groups.push(std::mem::take(&mut current));
                size = 0;
            }
            size += item.size;
            current.push(item);
        }
        if !current.is_empty() {
            groups.push(current);
        }
        let total = groups.len();
        for (index, group) in groups.into_iter().enumerate() {
            let last = index + 1 == total;
            if self.commit_group(group, now, epoch, written, last).await? == Outcome::Contended {
                return Ok(Outcome::Contended);
            }
        }
        Ok(Outcome::Done)
    }

    /// Commits one group of items; on a failure other than a precondition, once more as
    /// two halves.
    async fn commit_group(
        &self,
        group: Vec<Item>,
        now: Timestamp,
        epoch: Option<u64>,
        written: &mut Written,
        last: bool,
    ) -> IpamResult<Outcome> {
        let error = match self.commit(&group, now, epoch, written, last).await {
            Ok(()) => return Ok(Outcome::Done),
            Err(StoreError::PreconditionFailed(_)) => return Ok(Outcome::Contended),
            Err(error) => error,
        };
        tracing::warn!(
            items = group.len(),
            error = %tenko_core::Coded::code(&error),
            "a batch of the reconcile run failed; trying it as two halves"
        );
        if group.len() < 2 {
            written.unwritten += 1;
            written.failure = Some(tenko_core::Coded::code(&error).to_owned());
            if last {
                self.record_alone(now, epoch, written).await;
            }
            return Ok(Outcome::Done);
        }
        let mut head = group;
        let tail = head.split_off(head.len() / 2);
        for (half, half_last) in [(head, false), (tail, last)] {
            match self.commit(&half, now, epoch, written, half_last).await {
                Ok(()) => {}
                Err(StoreError::PreconditionFailed(_)) => return Ok(Outcome::Contended),
                Err(error) => {
                    tracing::warn!(
                        items = half.len(),
                        error = %tenko_core::Coded::code(&error),
                        "half of a batch of the reconcile run failed again; left for the next run"
                    );
                    written.unwritten += u32::try_from(half.len()).unwrap_or(u32::MAX);
                    written.failure = Some(tenko_core::Coded::code(&error).to_owned());
                    if half_last {
                        self.record_alone(now, epoch, written).await;
                    }
                }
            }
        }
        Ok(Outcome::Done)
    }

    /// Commits `items` as one fenced batch, with the run's record when it is the last, and
    /// counts them as written.
    async fn commit(
        &self,
        items: &[Item],
        now: Timestamp,
        epoch: Option<u64>,
        written: &mut Written,
        last: bool,
    ) -> Result<(), StoreError> {
        let mut batch = sync::scratch(now);
        if let Some(epoch) = epoch {
            batch.preconditions.push(fence(epoch));
        }
        let mut counts = SyncCounts::default();
        for item in items {
            item.add_to(&mut batch);
            counts.add(item.counts);
        }
        if last {
            let mut total = written.counts;
            total.add(counts);
            batch.audit(run_record(written.batches + 1, total, written.unwritten));
        }
        let done = self.ipam.store().propose(batch).await?;
        written.batches += 1;
        written.counts.add(counts);
        written.revision = Some(done.revision);
        written
            .keys
            .extend(items.iter().filter_map(|item| item.key.clone()));
        Ok(())
    }

    /// Writes the run's record on its own when the batch that should have carried it
    /// failed; a failure here is logged.
    async fn record_alone(&self, now: Timestamp, epoch: Option<u64>, written: &Written) {
        let mut batch = sync::scratch(now);
        if let Some(epoch) = epoch {
            batch.preconditions.push(fence(epoch));
        }
        batch.audit(run_record(
            written.batches,
            written.counts,
            written.unwritten,
        ));
        if let Err(error) = self.ipam.store().propose(batch).await {
            tracing::warn!(error = %tenko_core::Coded::code(&error), "the reconcile run's audit record was not written");
        }
    }

    /// Brings the last sightings of addresses and interfaces up to date, one item each in
    /// object order, and returns them as they will be.
    fn sightings(
        snapshot: &Snapshot,
        now: Timestamp,
        config: &ReconcilerConfig,
    ) -> IpamResult<(Vec<Item>, BTreeMap<ObjectRef, IntentSighting>)> {
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
        let mut items = Vec::new();
        for (object, sighting) in newest {
            let stored = snapshot.sightings.get(&object);
            let due = stored.is_none_or(|(current, _)| {
                sighting.at.saturating_since(current.at) >= config.observe.refresh
            });
            if !due {
                continue;
            }
            let mut batch = sync::scratch(now);
            batch.put_typed(&LAST_SEEN, &object, &sighting)?;
            batch.expect_typed(&LAST_SEEN, &object, stored.map(|(_, revision)| *revision));
            let counts = SyncCounts {
                sightings: 1,
                ..SyncCounts::default()
            };
            items.push(Item::new(None, counts, batch));
            merged.insert(object, sighting);
        }
        Ok((items, merged))
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
                let fact = &snapshot.facts[pair.fact];
                pair.ip.is_some_and(|ip| {
                    waiting_move.confirmed_by_source(
                        &fact.source,
                        pair.placement.and_then(Placement::vrf),
                        ip,
                        pair.mac,
                        fact.last_seen,
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
            // The periodic run (and the first) does the full pass; a run after a change
            // reads the zones only when the change touched what the DNS steps read.
            let full = tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = sleep_until(next_run) => true,
                () = self.wake.notified() => {
                    tokio::select! {
                        () = stop.cancelled() => return Ok(()),
                        () = sleep(config.debounce) => false,
                    }
                }
                () = self.changed.notified() => {
                    tokio::select! {
                        () = stop.cancelled() => return Ok(()),
                        () = sleep(config.debounce) => false,
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
            };
            last_run = Some(Instant::now());
            match self
                .reconcile_fenced(Timestamp::now(), Some(epoch), full)
                .await
            {
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
