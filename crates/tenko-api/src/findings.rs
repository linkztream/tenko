//! The findings service of a controller (U1): the [`FindingsIndex`] kept current from the
//! store journal, the health conditions of the status, and the live topic `findings`.
//!
//! One task ([`FindingsService::spawn`]) loads the index from the store, then follows the
//! journal: each change set is applied record by record (proposals, alarms, jobs), and a
//! change of a table the reconciliation view reads schedules a refresh of the view's
//! findings, debounced by two seconds and at most once per `reconcile_refresh_secs`; the
//! view is also refreshed once a minute, for what ages with time. After every change the
//! service publishes a `findings` event (kind `findings.changed`) with the source records
//! whose findings changed, so every surface reads one query and one subscription. A
//! subscriber that falls behind or a journal gap reloads the index from the store.
//!
//! The topology's findings (its root and the WLAN rules, U7) come from the topology service
//! ([`FindingsService::set_topology`]): they are derived again with the view's findings and
//! at least every [`TOPOLOGY_EVERY`], in a task of their own so that a slow network
//! controller never holds the journal.
//!
//! Health conditions are the warnings of `GET /system/status`: the status sets them on every
//! read, and the findings routes assemble them again when they are older than
//! [`HEALTH_TTL`]. The lease-conflict warning (`ipam.lease_conflict`) is left out, because
//! the conflict rows of the view are findings of their own. A condition of
//! [`ACT_NOW_HEALTH`] is to act on whatever its diagnostics severity (U3: low disk).

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use futures::StreamExt;
use tenko_core::{ObjectRef, Revision, Timestamp};
use tenko_ipam::{
    findings::{FindingLevel, FindingsConfig, FindingsIndex, HealthItem},
    topology::TopologyService,
};
use tenko_store::{ReadConsistency, Store, StoreError, WatchError, WatchFilter};
use tokio::{sync::watch, task::JoinHandle};

use crate::{
    dto::{
        events::{EventData, Topic},
        system::{FindingSeverity, StatusWarning},
    },
    routes::system::{DISK_LOW, IPAM_LEASE_CONFLICT, diagnostics::severity_of},
    sse::EventHub,
};

/// How old the health conditions may be before a findings request assembles them again.
pub const HEALTH_TTL: Duration = Duration::from_secs(15);

/// U3: the health conditions that are to act on although their diagnostics severity is a
/// warning: a data directory running out of room stops the store long before anything else
/// fails (`docs/plans/ui-plan.md` section 2.2, "Low disk ... Act now").
pub const ACT_NOW_HEALTH: &[&str] = &[DISK_LOW];

/// The severity of the finding of a health condition: [`ACT_NOW_HEALTH`] is to act on, an
/// error of the diagnostics is to act on, a warning to review, an informational state is
/// information.
pub fn health_level(code: &str) -> FindingLevel {
    if ACT_NOW_HEALTH.contains(&code) {
        return FindingLevel::Act;
    }
    match severity_of(code) {
        FindingSeverity::Error => FindingLevel::Act,
        FindingSeverity::Warning => FindingLevel::Review,
        FindingSeverity::Info => FindingLevel::Info,
    }
}

/// The kind of the events of the topic `findings`.
pub const CHANGED: &str = "findings.changed";

/// How long a burst of changes to the view's inputs is collected before the view's
/// findings are refreshed.
const DEBOUNCE: Duration = Duration::from_secs(2);

/// The view's findings are refreshed at least this often, for what ages with time.
const PERIODIC: Duration = Duration::from_secs(60);

/// The topology's findings are derived again at least this often: the controllers' tables
/// change without a write to the store.
pub const TOPOLOGY_EVERY: Duration = Duration::from_secs(30);

/// The findings index of this controller with the task that keeps it current.
pub struct FindingsService {
    index: FindingsIndex,
    store: Arc<dyn Store>,
    /// Whether the IPAM module runs: without it there is no reconciliation view.
    with_view: bool,
    events: EventHub,
    loaded: watch::Sender<bool>,
    health_at: Mutex<Option<Instant>>,
    topology: Mutex<Option<Arc<TopologyService>>>,
    topology_running: AtomicBool,
}

impl std::fmt::Debug for FindingsService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FindingsService")
            .field("findings", &self.index.len())
            .field("with_view", &self.with_view)
            .finish_non_exhaustive()
    }
}

impl FindingsService {
    /// A service over `store` that publishes on `events`; `with_view` when the IPAM module
    /// runs. The index is empty until [`FindingsService::spawn`] loaded it.
    pub fn new(
        store: Arc<dyn Store>,
        config: FindingsConfig,
        with_view: bool,
        events: EventHub,
    ) -> Arc<Self> {
        Arc::new(Self {
            index: FindingsIndex::new(config),
            store,
            with_view,
            events,
            loaded: watch::channel(false).0,
            health_at: Mutex::new(None),
            topology: Mutex::new(None),
            topology_running: AtomicBool::new(false),
        })
    }

    /// Sets the topology service whose findings (the root, the WLAN rules) the index holds.
    pub fn set_topology(&self, topology: Arc<TopologyService>) {
        *self.topology.lock().unwrap_or_else(PoisonError::into_inner) = Some(topology);
    }

    /// Derives the topology's findings again in a task of its own, unless a derivation runs;
    /// publishes a `findings` event when they changed.
    pub fn refresh_topology(self: &Arc<Self>) {
        let Some(topology) = self
            .topology
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        else {
            return;
        };
        if self.topology_running.swap(true, Ordering::AcqRel) {
            return;
        }
        let service = Arc::clone(self);
        tokio::spawn(async move {
            match topology.findings(None).await {
                Ok(findings) => {
                    if service.index.set_topology(findings, Timestamp::now()) {
                        service.publish(&[]);
                    }
                }
                Err(error) => {
                    tracing::debug!(error = %error.code_str(), "the topology's findings cannot be derived now");
                }
            }
            service.topology_running.store(false, Ordering::Release);
        });
    }

    /// The index.
    pub fn index(&self) -> &FindingsIndex {
        &self.index
    }

    /// Waits until the index was loaded once, at most `limit`.
    pub async fn wait_loaded(&self, limit: Duration) {
        let mut loaded = self.loaded.subscribe();
        let _ = tokio::time::timeout(limit, loaded.wait_for(|loaded| *loaded)).await;
    }

    /// Whether the health conditions are older than [`HEALTH_TTL`] or were never set.
    pub fn health_stale(&self) -> bool {
        self.health_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none_or(|at| at.elapsed() >= HEALTH_TTL)
    }

    /// Sets the health conditions from the warnings of the status at `now`, and publishes a
    /// `findings` event when they changed.
    pub fn set_health(&self, warnings: &[StatusWarning], now: Timestamp) {
        let items: Vec<HealthItem> = warnings
            .iter()
            .filter(|warning| warning.code != IPAM_LEASE_CONFLICT)
            .map(|warning| HealthItem {
                code: warning.code.clone(),
                detail: warning.detail.clone(),
                params: warning.params.clone(),
                level: health_level(&warning.code),
            })
            .collect();
        *self
            .health_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        if self.index.set_health(&items, now) {
            self.publish(&[]);
        }
    }

    /// Publishes a `findings` event naming `objects` (none: the view or health changed).
    fn publish(&self, objects: &[ObjectRef]) {
        let mut data = EventData::new(Topic::Findings, None);
        data.kind = Some(CHANGED.to_owned());
        data.objects = objects.to_vec();
        data.params = BTreeMap::from([(
            "revision".to_owned(),
            self.index.revision().get().to_string(),
        )]);
        self.events.publish_system(&data);
    }

    /// Starts the task that loads the index and follows the journal; it ends when `stop`
    /// turns true or the store shuts down.
    pub fn spawn(self: &Arc<Self>, stop: watch::Receiver<bool>) -> JoinHandle<()> {
        let service = Arc::clone(self);
        tokio::spawn(async move { service.run(stop).await })
    }

    /// Loads everything from the store; answers the revision loaded.
    async fn load(self: &Arc<Self>) -> Result<Revision, StoreError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let revision = view.revision();
        let service = Arc::clone(self);
        let loaded = tokio::task::spawn_blocking(move || {
            service
                .index
                .load(view.as_ref(), Timestamp::now(), service.with_view)
        })
        .await;
        match loaded {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(error = %error.code_str(), "the findings index could not be loaded");
            }
            Err(error) => tracing::warn!(%error, "the findings index load stopped"),
        }
        self.loaded.send_replace(true);
        self.publish(&[]);
        self.refresh_topology();
        Ok(revision)
    }

    /// Refreshes the view's findings from the newest local state.
    async fn refresh_view(self: &Arc<Self>) {
        let view = match self.store.read(ReadConsistency::Local).await {
            Ok(view) => view,
            Err(error) => {
                tracing::debug!(%error, "the findings of the view cannot be refreshed now");
                return;
            }
        };
        let service = Arc::clone(self);
        let refreshed = tokio::task::spawn_blocking(move || {
            service.index.refresh_view(view.as_ref(), Timestamp::now())
        })
        .await;
        match refreshed {
            Ok(Ok(true)) => self.publish(&[]),
            Ok(Ok(false)) => {}
            Ok(Err(error)) => {
                tracing::warn!(error = %error.code_str(), "the findings of the view could not be refreshed");
            }
            Err(error) => tracing::warn!(%error, "the refresh of the findings stopped"),
        }
    }

    async fn run(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        loop {
            if *stop.borrow() {
                return;
            }
            let from = match self.load().await {
                Ok(revision) => revision,
                Err(StoreError::ShuttingDown) => return,
                Err(error) => {
                    tracing::warn!(%error, "the findings index cannot read the store; retrying");
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_secs(1)) => continue,
                        _ = stop.changed() => return,
                    }
                }
            };
            let mut changes = match self.store.watch(Some(from), WatchFilter::all()) {
                Ok(changes) => changes,
                Err(StoreError::ShuttingDown) => return,
                Err(error) => {
                    tracing::warn!(%error, "the findings index cannot follow the store; retrying");
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_secs(1)) => continue,
                        _ = stop.changed() => return,
                    }
                }
            };
            let mut dirty: Option<Instant> = None;
            let mut refreshed = Instant::now();
            let mut topology_at = Instant::now();
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    item = changes.next() => match item {
                        Some(Ok(change_set)) => {
                            // Most change sets (leases, facts, audit) touch no record the
                            // index follows: they cost no read.
                            let (records, inputs) = FindingsIndex::touches(&change_set);
                            if inputs && self.with_view {
                                dirty.get_or_insert_with(Instant::now);
                            }
                            if !records {
                                self.index.advance(change_set.revision);
                                continue;
                            }
                            let view = match self
                                .store
                                .read(ReadConsistency::AtLeast(change_set.revision))
                                .await
                            {
                                Ok(view) => view,
                                Err(StoreError::ShuttingDown) => return,
                                Err(_) => break,
                            };
                            match self.index.apply(view.as_ref(), &change_set) {
                                Ok(applied) => {
                                    if !applied.changed.is_empty() {
                                        self.publish(&applied.changed);
                                    }
                                }
                                Err(error) => {
                                    tracing::warn!(error = %error.code_str(), "a change could not be applied to the findings; reloading");
                                    break;
                                }
                            }
                        }
                        Some(Err(WatchError::Lagged { .. } | WatchError::Compacted { .. })) => break,
                        None => return,
                    },
                    _ = tick.tick() => {
                        if !self.with_view {
                            continue;
                        }
                        let due = dirty.is_some_and(|since| {
                            since.elapsed() >= DEBOUNCE
                                && refreshed.elapsed() >= self.index.config().reconcile_refresh()
                        });
                        if due || refreshed.elapsed() >= PERIODIC {
                            dirty = None;
                            refreshed = Instant::now();
                            self.refresh_view().await;
                            topology_at = Instant::now();
                            self.refresh_topology();
                        } else if topology_at.elapsed() >= TOPOLOGY_EVERY {
                            topology_at = Instant::now();
                            self.refresh_topology();
                        }
                    }
                    _ = stop.changed() => return,
                }
            }
        }
    }
}
