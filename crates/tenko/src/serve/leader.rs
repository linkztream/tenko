//! The leader supervisor (plan section 2.3, WP3.1b): runs the leader-only services
//! ([`LeaderService`]) on the controller that leads, and nowhere else.
//!
//! # Registration
//!
//! A start step registers the services of its package in the [`LeaderRegistry`] that the
//! start sequence hands around; the supervisor takes the list when it starts, after the
//! `api` step. A service registered later is refused with an error in the log.
//!
//! # Terms of office
//!
//! When the store says this controller leads ([`Store::leadership`] with `is_self`, which
//! turns true only after the new leader applied its first commit of the term), the
//! supervisor takes office: it bumps the counter [`LEADER_EPOCH`] in a batch fenced on the
//! counter's current value, so the epoch is exact, and starts every registered service
//! with that epoch. A service fences its writes with it (`tenko_store::fence`), so once
//! another controller took office every write of a deposed one fails. The term ends when
//! the store reports another leader or term, when the supervisor stops, or when a service
//! gives up while the epoch moved past this term's (another controller bumped it): the
//! services are cancelled, and a controller that still leads takes office again with a
//! new epoch.
//!
//! # Services
//!
//! Each service runs in its own task. One that gives up (returns an error or panics) is
//! restarted after a pause that doubles from one second up to a minute. One that returns
//! without being stopped has finished its work for the term. Every transition is a log
//! line and a `cluster` event: `cluster.leader` when this controller takes or leaves
//! office (params `leads`, `epoch`), `cluster.leader.service` when a service starts,
//! gives up, finishes or stops (params `service`, `state`, and `error` after a failure).
//! `GET /system/status` shows the office and the state of every service ([`LeaderView`]);
//! a service waiting for its restart is the warning `cluster.leader.service_failing`.
//!
//! The leader service `cluster.clock` and the follower of its beats ([`clock`]) measure the
//! clock skew between this controller and the leader (R35).

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use tenko_api::{
    dto::system::{LeaderServiceState, LeaderServiceStatus, LeaderStatus},
    routes::system::LeaderSource,
    sse::{EventData, EventHub, Topic},
};
use tenko_core::{
    RequestCtx, SystemComponent, Timestamp,
    cluster::{LEADER_EPOCH, LeaderService},
};
use tenko_store::{Leadership, ReadConsistency, Store, StoreError, WriteBatch, fence};
use tokio::{
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

/// Event kind of a change of office.
pub(crate) const OFFICE_EVENT: &str = "cluster.leader";
/// Event kind of a change of a leader service.
pub(crate) const SERVICE_EVENT: &str = "cluster.leader.service";

/// How long to wait before trying to take office again after a store error.
const RETRY: Duration = Duration::from_secs(5);
/// How long a cancelled service may take to end before it is aborted.
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// A cancellation token that fires when `stop` is set (or its sender is gone).
pub(crate) fn stop_token(mut stop: watch::Receiver<bool>) -> CancellationToken {
    let token = CancellationToken::new();
    let fire = token.clone();
    tokio::spawn(async move {
        while !*stop.borrow_and_update() {
            if stop.changed().await.is_err() {
                break;
            }
        }
        fire.cancel();
    });
    token
}

/// Registered leader services, in registration order.
type Services = Vec<Arc<dyn LeaderService>>;

/// The leader services registered during start, for the supervisor.
#[derive(Clone)]
pub(crate) struct LeaderRegistry {
    /// `None` once the supervisor has taken the list.
    services: Arc<Mutex<Option<Services>>>,
}

impl Default for LeaderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for LeaderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaderRegistry")
            .field("services", &self.names())
            .finish()
    }
}

impl LeaderRegistry {
    /// An empty registry.
    pub(crate) fn new() -> Self {
        Self {
            services: Arc::new(Mutex::new(Some(Vec::new()))),
        }
    }

    /// Registers a service; the supervisor runs services in registration order.
    pub(crate) fn register(&self, service: Arc<dyn LeaderService>) {
        let mut services = self.services.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(services) = services.as_mut() {
            services.push(service);
        } else {
            tracing::error!(
                service = service.name(),
                "a leader service was registered after the supervisor started; it does not run"
            );
        }
    }

    /// Registers several services.
    pub(crate) fn extend(&self, services: impl IntoIterator<Item = Arc<dyn LeaderService>>) {
        for service in services {
            self.register(service);
        }
    }

    /// The names of the registered services.
    pub(crate) fn names(&self) -> Vec<&'static str> {
        self.services
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|services| services.iter().map(|service| service.name()).collect())
            .unwrap_or_default()
    }

    fn take(&self) -> Vec<Arc<dyn LeaderService>> {
        self.services
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .unwrap_or_default()
    }
}

/// Timings of the supervisor.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SupervisorConfig {
    /// The first pause before a service that gave up is restarted.
    pub backoff_min: Duration,
    /// The longest pause; a service that ran at least this long before it gave up starts
    /// again from `backoff_min`.
    pub backoff_max: Duration,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
        }
    }
}

/// What `GET /system/status` shows of the supervisor: shared with its tasks.
#[derive(Clone, Default)]
pub(crate) struct LeaderView {
    state: Arc<Mutex<LeaderStatus>>,
}

impl std::fmt::Debug for LeaderView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaderView").finish_non_exhaustive()
    }
}

impl LeaderView {
    /// The office and the services now.
    pub(crate) fn status(&self) -> LeaderStatus {
        self.lock().clone()
    }

    /// The request extension of `GET /system/status`.
    pub(crate) fn source(&self) -> LeaderSource {
        let view = self.clone();
        LeaderSource::new(move || view.status())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LeaderStatus> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn registered(&self, names: &[&'static str]) {
        let mut state = self.lock();
        state.services = names
            .iter()
            .map(|name| LeaderServiceStatus {
                name: (*name).to_owned(),
                state: LeaderServiceState::Idle,
                restarts: 0,
                last_error: None,
                since: None,
            })
            .collect();
    }

    fn office(&self, epoch: Option<u64>) {
        let now = Timestamp::now();
        let mut state = self.lock();
        state.leads = epoch.is_some();
        state.epoch = epoch;
        state.since = Some(now);
        for service in &mut state.services {
            service.restarts = 0;
            service.last_error = None;
            if epoch.is_none() {
                service.state = LeaderServiceState::Idle;
                service.since = Some(now);
            }
        }
    }

    /// Records the clock skew to the leader, or that it is not known.
    pub(crate) fn clock_skew(&self, skew_ms: Option<i64>) {
        self.lock().clock_skew_ms = skew_ms;
    }

    fn service(&self, name: &str, change: impl FnOnce(&mut LeaderServiceStatus)) {
        let mut state = self.lock();
        if let Some(service) = state
            .services
            .iter_mut()
            .find(|service| service.name == name)
        {
            let before = service.state;
            change(service);
            if service.state != before {
                service.since = Some(Timestamp::now());
            }
        }
    }
}

/// Where the supervisor publishes its `cluster` events; nowhere in tests without an API.
#[derive(Clone, Default)]
struct Events(Option<EventHub>);

impl Events {
    fn office(&self, epoch: Option<u64>) {
        let Some(hub) = &self.0 else {
            return;
        };
        let mut event = EventData::new(Topic::Cluster, None);
        event.kind = Some(OFFICE_EVENT.to_owned());
        event
            .params
            .insert("leads".to_owned(), epoch.is_some().to_string());
        if let Some(epoch) = epoch {
            event.params.insert("epoch".to_owned(), epoch.to_string());
        }
        hub.publish_system(&event);
    }

    fn service(&self, name: &str, state: LeaderServiceState, error: Option<&str>) {
        let Some(hub) = &self.0 else {
            return;
        };
        let mut event = EventData::new(Topic::Cluster, None);
        event.kind = Some(SERVICE_EVENT.to_owned());
        event.params.insert("service".to_owned(), name.to_owned());
        let state = match state {
            LeaderServiceState::Idle => "idle",
            LeaderServiceState::Running => "running",
            LeaderServiceState::Restarting => "restarting",
            LeaderServiceState::Finished => "finished",
        };
        event.params.insert("state".to_owned(), state.to_owned());
        if let Some(error) = error {
            event.params.insert("error".to_owned(), error.to_owned());
        }
        hub.publish_system(&event);
    }
}

/// The running supervisor.
pub(crate) struct SupervisorHandle {
    stop: CancellationToken,
    task: JoinHandle<()>,
}

impl SupervisorHandle {
    /// Cancels the leader services, waits until they ended, and stops the supervisor.
    pub(crate) async fn stop(mut self, timeout: Duration) {
        self.stop.cancel();
        if tokio::time::timeout(timeout, &mut self.task).await.is_err() {
            tracing::warn!("the leader services did not stop in time");
            self.task.abort();
        }
    }
}

/// Starts the supervisor of `registry`'s services over `store`, publishing its events to
/// `events` and its state to `view`.
pub(crate) fn spawn(
    store: Arc<dyn Store>,
    registry: &LeaderRegistry,
    view: LeaderView,
    events: Option<EventHub>,
    config: SupervisorConfig,
) -> SupervisorHandle {
    let services = registry.take();
    let names: Vec<&'static str> = services.iter().map(|service| service.name()).collect();
    view.registered(&names);
    tracing::info!(services = ?names, "leader supervisor started");
    let stop = CancellationToken::new();
    let supervisor = Supervisor {
        store,
        services,
        view,
        events: Events(events),
        config,
        stop: stop.clone(),
    };
    SupervisorHandle {
        stop,
        task: tokio::spawn(supervisor.run()),
    }
}

/// Why a term of office ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TermEnd {
    /// The supervisor stops.
    Shutdown,
    /// The store reports another leader or term.
    Lost,
    /// Another controller bumped the epoch while this one leads.
    Fenced,
}

struct Supervisor {
    store: Arc<dyn Store>,
    services: Vec<Arc<dyn LeaderService>>,
    view: LeaderView,
    events: Events,
    config: SupervisorConfig,
    stop: CancellationToken,
}

/// The term of office this controller holds now, if it leads.
fn office(leadership: &mut watch::Receiver<Option<Leadership>>) -> Option<u64> {
    leadership
        .borrow_and_update()
        .as_ref()
        .filter(|leadership| leadership.is_self)
        .map(|leadership| leadership.term)
}

impl Supervisor {
    async fn run(self) {
        let mut leadership = self.store.leadership();
        loop {
            let Some(term) = office(&mut leadership) else {
                tokio::select! {
                    () = self.stop.cancelled() => return,
                    changed = leadership.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        continue;
                    }
                }
            };
            let epoch = match take_office(self.store.as_ref()).await {
                Ok(epoch) => epoch,
                Err(error) => {
                    tracing::warn!(%error, "could not record the leader epoch; retrying");
                    tokio::select! {
                        () = self.stop.cancelled() => return,
                        () = tokio::time::sleep(RETRY) => continue,
                    }
                }
            };
            // A leadership change while the bump was on its way (a forwarded write) leaves
            // this controller without office; the new leader takes office itself.
            if office(&mut leadership) != Some(term) {
                tracing::info!(epoch, "leadership moved while taking office");
                continue;
            }
            let end = self.serve_term(epoch, term, &mut leadership).await;
            if end == TermEnd::Shutdown {
                return;
            }
        }
    }

    /// Runs the services for one term of office and returns why it ended.
    async fn serve_term(
        &self,
        epoch: u64,
        term: u64,
        leadership: &mut watch::Receiver<Option<Leadership>>,
    ) -> TermEnd {
        tracing::info!(
            epoch,
            term,
            services = self.services.len(),
            "this controller leads: starting the leader services"
        );
        self.view.office(Some(epoch));
        self.events.office(Some(epoch));
        let cancel = self.stop.child_token();
        let (gave_up, mut gave_up_rx) = mpsc::unbounded_channel();
        let mut set = JoinSet::new();
        for service in &self.services {
            set.spawn(supervise(
                Arc::clone(service),
                epoch,
                cancel.clone(),
                self.view.clone(),
                self.events.clone(),
                self.config,
                gave_up.clone(),
            ));
        }
        drop(gave_up);
        let end = loop {
            tokio::select! {
                () = self.stop.cancelled() => break TermEnd::Shutdown,
                changed = leadership.changed() => {
                    if changed.is_err() {
                        break TermEnd::Shutdown;
                    }
                    if office(leadership) != Some(term) {
                        break TermEnd::Lost;
                    }
                }
                Some(()) = gave_up_rx.recv() => {
                    if epoch_moved(self.store.as_ref(), epoch).await {
                        tracing::warn!(
                            epoch,
                            "the leader epoch moved on while this controller leads; taking office again"
                        );
                        break TermEnd::Fenced;
                    }
                }
            }
        };
        cancel.cancel();
        while set.join_next().await.is_some() {}
        self.view.office(None);
        self.events.office(None);
        match end {
            TermEnd::Shutdown => tracing::info!(epoch, "the leader services stopped"),
            TermEnd::Lost | TermEnd::Fenced => tracing::info!(
                epoch,
                "this controller left office: the leader services stopped"
            ),
        }
        end
    }
}

/// Whether the leader epoch is no longer `epoch`.
async fn epoch_moved(store: &dyn Store, epoch: u64) -> bool {
    match store.read(ReadConsistency::Local).await {
        Ok(view) => view
            .counter(&LEADER_EPOCH)
            .is_ok_and(|current| current != epoch),
        Err(_) => false,
    }
}

/// Runs one service for a term of office, restarting it with a backoff when it gives up.
async fn supervise(
    service: Arc<dyn LeaderService>,
    epoch: u64,
    cancel: CancellationToken,
    view: LeaderView,
    events: Events,
    config: SupervisorConfig,
    gave_up: mpsc::UnboundedSender<()>,
) {
    let name = service.name();
    let mut backoff = config.backoff_min;
    loop {
        view.service(name, |status| status.state = LeaderServiceState::Running);
        events.service(name, LeaderServiceState::Running, None);
        tracing::info!(service = name, epoch, "leader service started");
        let began = Instant::now();
        let task = {
            let service = Arc::clone(&service);
            let cancel = cancel.clone();
            tokio::spawn(async move { service.run(epoch, cancel).await })
        };
        let outcome = join(task, &cancel, name).await;
        if cancel.is_cancelled() {
            view.service(name, |status| status.state = LeaderServiceState::Idle);
            events.service(name, LeaderServiceState::Idle, None);
            tracing::info!(service = name, "leader service stopped");
            return;
        }
        let error = match outcome {
            Ok(Ok(())) => {
                view.service(name, |status| status.state = LeaderServiceState::Finished);
                events.service(name, LeaderServiceState::Finished, None);
                tracing::info!(service = name, "leader service finished");
                return;
            }
            Ok(Err(error)) => error,
            Err(error) if error.is_panic() => "the service panicked".to_owned(),
            Err(_) => "the service was aborted".to_owned(),
        };
        if began.elapsed() >= config.backoff_max {
            backoff = config.backoff_min;
        }
        view.service(name, |status| {
            status.state = LeaderServiceState::Restarting;
            status.restarts = status.restarts.saturating_add(1);
            status.last_error = Some(error.clone());
        });
        events.service(name, LeaderServiceState::Restarting, Some(&error));
        tracing::error!(
            service = name,
            %error,
            retry_in_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
            "leader service gave up; restarting"
        );
        let _ = gave_up.send(());
        tokio::select! {
            () = cancel.cancelled() => {
                view.service(name, |status| status.state = LeaderServiceState::Idle);
                events.service(name, LeaderServiceState::Idle, None);
                return;
            }
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = backoff.saturating_mul(2).min(config.backoff_max);
    }
}

/// Waits for a service task; after `cancel`, gives it [`SERVICE_STOP_TIMEOUT`] to end and
/// aborts it then.
async fn join(
    mut task: JoinHandle<Result<(), String>>,
    cancel: &CancellationToken,
    name: &'static str,
) -> Result<Result<(), String>, tokio::task::JoinError> {
    tokio::select! {
        result = &mut task => return result,
        () = cancel.cancelled() => {}
    }
    if let Ok(result) = tokio::time::timeout(SERVICE_STOP_TIMEOUT, &mut task).await {
        return result;
    }
    tracing::warn!(
        service = name,
        "leader service did not stop in time; aborted"
    );
    task.abort();
    task.await
}

/// How often the leader purges expired records (idempotency records, used challenges).
pub(crate) const PURGE_INTERVAL: Duration = Duration::from_secs(3_600);

/// A leader service that runs `work` with the epoch of the term right after taking office
/// and then every `interval`. `work` returns how many records it removed; an error ends
/// the service, so the supervisor restarts it with its backoff (and takes office again if
/// the epoch moved).
struct Periodic<F> {
    name: &'static str,
    interval: Duration,
    work: F,
}

/// A periodic leader service (see [`Periodic`]).
pub(crate) fn periodic<F, Fut>(
    name: &'static str,
    interval: Duration,
    work: F,
) -> Arc<dyn LeaderService>
where
    F: Fn(u64) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<usize, String>> + Send + 'static,
{
    Arc::new(Periodic {
        name,
        interval,
        work,
    })
}

#[async_trait::async_trait]
impl<F, Fut> LeaderService for Periodic<F>
where
    F: Fn(u64) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<usize, String>> + Send + 'static,
{
    fn name(&self) -> &'static str {
        self.name
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let mut tick = tokio::time::interval(self.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                _ = tick.tick() => {}
            }
            match (self.work)(epoch).await {
                Ok(0) => {}
                Ok(removed) => {
                    tracing::info!(service = self.name, removed, "expired records removed");
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// The hourly purge of expired idempotency records (`api.idempotency_purge`), fenced with
/// the leader epoch.
pub(crate) fn idempotency_purge(store: Arc<dyn Store>, ttl: Duration) -> Arc<dyn LeaderService> {
    periodic("api.idempotency_purge", PURGE_INTERVAL, move |epoch| {
        let store = Arc::clone(&store);
        async move {
            tenko_api::middleware::idempotency::purge_expired(
                store.as_ref(),
                ttl,
                Timestamp::now(),
                Some(epoch),
            )
            .await
            .map_err(|error| error.to_string())
        }
    })
}

/// The hourly purge of the rows of used sign-in ceremonies whose challenges have expired
/// (`auth.used_challenges_purge`), fenced with the leader epoch.
pub(crate) fn used_challenges_purge(store: Arc<dyn Store>) -> Arc<dyn LeaderService> {
    periodic("auth.used_challenges_purge", PURGE_INTERVAL, move |epoch| {
        let store = Arc::clone(&store);
        async move {
            tenko_auth::challenge::purge_used(store.as_ref(), Timestamp::now(), Some(epoch))
                .await
                .map_err(|error| error.to_string())
        }
    })
}

/// Bumps [`LEADER_EPOCH`] against its current value and returns the new epoch.
async fn take_office(store: &dyn Store) -> Result<u64, StoreError> {
    let view = store.read(ReadConsistency::Local).await?;
    let current = view.counter(&LEADER_EPOCH)?;
    let ctx = RequestCtx::system(SystemComponent::Cluster);
    let mut batch = WriteBatch::for_request(&ctx);
    batch.preconditions.push(fence(current));
    batch.bump(LEADER_EPOCH);
    store.propose(batch).await?;
    Ok(current + 1)
}

pub(crate) mod clock;

#[cfg(test)]
mod tests;
