//! The runner: one task per engine that decides which jobs run when.
//!
//! - **Workers.** At most `EngineConfig::workers` jobs are driven at once; a job holds a
//!   worker only while the engine works on it (a handler call or a write), never while it
//!   waits for an observation or a person.
//! - **Groups (CONN-09).** A job with a [`GroupKey`] holds a slot of its group from its
//!   start until it is final, including while it waits, so a bulk move of 60 devices with
//!   a limit of 10 has at most 10 devices between "moved" and "confirmed". Queued jobs
//!   start in submission order as slots free up. Jobs resumed after a restart or taken
//!   over keep their slot even if that briefly exceeds the limit. Limits apply per runner;
//!   Slice 1 has one runner.
//! - **Deadlines.** Waiting jobs are parked with their deadline; the runner looks at them
//!   again when the deadline passes on its [`Clock`](crate::Clock), when someone changes
//!   them, or when an observation resumes them.
//! - **Discovery.** Local calls wake the runner directly; a store watch on `jobs.jobs`
//!   wakes it for changes made through other engines; a periodic scan of `jobs.by_state`
//!   finds jobs whose runner's lease expired (takeover) and anything a watch missed.
//! - **Lease.** While it owns unfinished jobs, the runner renews its row in
//!   `jobs.runners` every third of `EngineConfig::lease_ttl`.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    sync::{
        Arc, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use futures::StreamExt;
use tenko_core::{Coded, JobId, Revision, Timestamp, codec::encode_key};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WatchFilter, WriteBatch};
use tokio::{
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};

use crate::{
    drive::{DriveEnd, drive, lease},
    engine::Inner,
    model::{GroupKey, JobState},
    persist::{self, PAGE},
    tables::{BY_STATE, JOBS, RUNNERS},
};

/// Messages to the runner.
#[derive(Debug)]
pub(crate) enum Msg {
    /// A job changed (at `revision`, when known).
    Wake {
        job: JobId,
        revision: Option<Revision>,
    },
    /// Look for jobs again.
    Rescan,
    /// A drive ended.
    Driven { job: JobId, end: DriveEnd },
    /// Stop after the drives in flight reach a boundary.
    Stop,
}

/// [`JobEngine::start`](crate::JobEngine::start) was called while the engine's runner runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the job runner of this engine is already running")]
pub struct AlreadyRunning;

impl Coded for AlreadyRunning {
    fn code(&self) -> &'static str {
        "jobs.runner.already_running"
    }
    fn http_status(&self) -> u16 {
        409
    }
}

/// The running runner of an engine. Dropping the handle aborts the runner like
/// [`abort`](RunnerHandle::abort).
pub struct RunnerHandle {
    task: Option<JoinHandle<()>>,
    tx: mpsc::UnboundedSender<Msg>,
    stop: Arc<AtomicBool>,
    inner: Arc<Inner>,
}

impl std::fmt::Debug for RunnerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerHandle")
            .field("node", &self.inner.config.node)
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl RunnerHandle {
    /// Stops gracefully: no new step starts, steps in flight finish and their results are
    /// written, then the runner ends. Jobs stay owned by this node and resume when a runner
    /// starts again (or move to another node once the lease expires).
    pub async fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.tx.send(Msg::Stop);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        self.detach();
    }

    /// Ends the runner at once, as a crash would: steps in flight are dropped where they
    /// are and nothing more is written.
    pub fn abort(mut self) {
        self.abort_now();
    }

    /// Whether the runner task still runs.
    pub fn is_running(&self) -> bool {
        self.task.as_ref().is_some_and(|task| !task.is_finished())
    }

    fn abort_now(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        self.detach();
    }

    fn detach(&self) {
        let mut slot = self
            .inner
            .runner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if slot.as_ref().is_some_and(|tx| tx.same_channel(&self.tx)) {
            *slot = None;
        }
    }
}

impl Drop for RunnerHandle {
    fn drop(&mut self) {
        self.abort_now();
    }
}

/// Spawns the runner of an engine.
pub(crate) fn start(inner: &Arc<Inner>) -> Result<RunnerHandle, AlreadyRunning> {
    let mut slot = inner.runner.lock().unwrap_or_else(PoisonError::into_inner);
    if slot.as_ref().is_some_and(|tx| !tx.is_closed()) {
        return Err(AlreadyRunning);
    }
    let (tx, rx) = mpsc::unbounded_channel();
    *slot = Some(tx.clone());
    drop(slot);
    let stop = Arc::new(AtomicBool::new(false));
    let watcher = AbortOnDrop(tokio::spawn(watch(Arc::clone(inner), tx.clone())));
    let now = inner.clock.now();
    let actor = Actor {
        inner: Arc::clone(inner),
        rx,
        tx: tx.clone(),
        stop: Arc::clone(&stop),
        tasks: JoinSet::new(),
        task_jobs: HashMap::new(),
        tracked: HashMap::new(),
        queues: BTreeMap::new(),
        ready: VecDeque::new(),
        in_use: HashMap::new(),
        in_flight: 0,
        timers: BTreeSet::new(),
        finished: HashMap::new(),
        next_scan: now,
        next_renew: None,
        stopping: false,
        _watcher: watcher,
    };
    let task = tokio::spawn(actor.run());
    Ok(RunnerHandle {
        task: Some(task),
        tx,
        stop,
        inner: Arc::clone(inner),
    })
}

/// Aborts a task when dropped.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Wakes the runner for every change of `jobs.jobs`, also those made by other engines.
async fn watch(inner: Arc<Inner>, tx: mpsc::UnboundedSender<Msg>) {
    loop {
        match inner
            .store
            .watch(None, WatchFilter::tables([JOBS.name().clone()]))
        {
            Ok(mut stream) => {
                while let Some(item) = stream.next().await {
                    match item {
                        Ok(changes) => {
                            for change in &changes.changes {
                                let Ok(job) = JOBS.decode_key(&change.key) else {
                                    continue;
                                };
                                let wake = Msg::Wake {
                                    job,
                                    revision: Some(changes.revision),
                                };
                                if tx.send(wake).is_err() {
                                    return;
                                }
                            }
                        }
                        Err(error) => {
                            tracing::debug!(%error, "job watch ended; rescanning");
                            break;
                        }
                    }
                }
                if tx.send(Msg::Rescan).is_err() {
                    return;
                }
            }
            Err(error) => tracing::warn!(%error, "jobs cannot be watched"),
        }
        if tx.is_closed() {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for a group slot and a worker.
    Queued,
    /// Holds its slot, waiting for a worker.
    Ready,
    /// A drive is in flight; `dirty` is the newest change seen meanwhile.
    Driving { dirty: Option<Revision> },
    /// Waiting for an observation, a person or a deadline.
    Parked,
}

#[derive(Debug)]
struct Tracked {
    group: Option<GroupKey>,
    slot: bool,
    phase: Phase,
    revision: Revision,
    timer: Option<Timestamp>,
}

/// Finished jobs remembered to ignore late wake-ups, before the memory is cleared.
const FINISHED_MEMORY: usize = 10_000;

enum Event {
    Msg(Option<Msg>),
    Timer,
    Joined(Option<Result<(tokio::task::Id, ()), tokio::task::JoinError>>),
}

struct Actor {
    inner: Arc<Inner>,
    rx: mpsc::UnboundedReceiver<Msg>,
    tx: mpsc::UnboundedSender<Msg>,
    stop: Arc<AtomicBool>,
    tasks: JoinSet<()>,
    task_jobs: HashMap<tokio::task::Id, JobId>,
    tracked: HashMap<JobId, Tracked>,
    queues: BTreeMap<Option<GroupKey>, VecDeque<JobId>>,
    ready: VecDeque<JobId>,
    in_use: HashMap<GroupKey, usize>,
    in_flight: usize,
    timers: BTreeSet<(Timestamp, JobId)>,
    finished: HashMap<JobId, Revision>,
    next_scan: Timestamp,
    next_renew: Option<Timestamp>,
    stopping: bool,
    _watcher: AbortOnDrop,
}

impl Actor {
    async fn run(mut self) {
        self.rescan().await;
        loop {
            self.dispatch();
            if self.stopping && self.in_flight == 0 {
                break;
            }
            let sleep = match self.next_timer() {
                Some(at) => self.inner.clock.sleep_until(at),
                None => Box::pin(futures::future::pending()),
            };
            let event = tokio::select! {
                message = self.rx.recv() => Event::Msg(message),
                () = sleep => Event::Timer,
                joined = self.tasks.join_next_with_id(), if !self.tasks.is_empty() => Event::Joined(joined),
            };
            match event {
                Event::Msg(None) => break,
                Event::Msg(Some(message)) => self.handle(message).await,
                Event::Timer => self.on_timer().await,
                Event::Joined(joined) => self.on_joined(joined),
            }
        }
    }

    async fn handle(&mut self, message: Msg) {
        match message {
            Msg::Wake { job, revision } => self.wake(job, revision).await,
            Msg::Rescan => self.rescan().await,
            Msg::Driven { job, end } => self.driven(job, end),
            Msg::Stop => self.stopping = true,
        }
    }

    fn next_timer(&self) -> Option<Timestamp> {
        let mut next = Some(self.next_scan);
        for candidate in [self.timers.first().map(|(at, _)| *at), self.next_renew] {
            next = crate::machine::earliest(next, candidate);
        }
        next
    }

    async fn wake(&mut self, job: JobId, revision: Option<Revision>) {
        if let Some(revision) = revision
            && self
                .finished
                .get(&job)
                .is_some_and(|last| revision <= *last)
        {
            return;
        }
        let seen = revision.unwrap_or(Revision(u64::MAX));
        let Some(tracked) = self.tracked.get_mut(&job) else {
            let view = match self
                .inner
                .store
                .read(tenko_store::ReadConsistency::Local)
                .await
            {
                Ok(view) => view,
                Err(error) => {
                    tracing::warn!(%error, "runner cannot read the store");
                    return;
                }
            };
            self.discover(view.as_ref(), job);
            return;
        };
        match &mut tracked.phase {
            Phase::Driving { dirty } => {
                *dirty = Some(dirty.map_or(seen, |dirty| dirty.max(seen)));
            }
            Phase::Parked => {
                if seen > tracked.revision {
                    if let Some(at) = tracked.timer.take() {
                        self.timers.remove(&(at, job));
                    }
                    tracked.phase = Phase::Ready;
                    self.ready.push_back(job);
                }
            }
            Phase::Queued | Phase::Ready => {}
        }
    }

    /// Starts tracking a job this runner may drive.
    fn discover(&mut self, view: &dyn ReadView, id: JobId) {
        let loaded = match persist::load(view, id) {
            Ok(Some(loaded)) => loaded,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(job = %id, %error, "runner cannot read a job");
                return;
            }
        };
        let job = &loaded.job;
        if job.state.is_terminal() {
            self.remember_finished(id, loaded.revision);
            return;
        }
        if job.state == JobState::Waiting {
            self.inner.track_waiter(job);
        }
        let me = self.inner.config.node;
        if let Some(owner) = job.runner
            && owner != me
        {
            let now = self.inner.clock.now();
            match view.get_typed(&RUNNERS, &owner) {
                Ok(Some((lease, _))) if lease.expires > now => return,
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(job = %id, %error, "runner cannot read a lease");
                    return;
                }
            }
        }
        let group = job.spec.group.clone();
        if job.state == JobState::Queued {
            self.tracked.insert(
                id,
                Tracked {
                    group: group.clone(),
                    slot: false,
                    phase: Phase::Queued,
                    revision: loaded.revision,
                    timer: None,
                },
            );
            self.queues.entry(group).or_default().push_back(id);
        } else {
            let slot = group.is_some();
            if let Some(group) = &group {
                *self.in_use.entry(group.clone()).or_default() += 1;
            }
            self.tracked.insert(
                id,
                Tracked {
                    group,
                    slot,
                    phase: Phase::Ready,
                    revision: loaded.revision,
                    timer: None,
                },
            );
            self.ready.push_back(id);
            if self.next_renew.is_none() {
                self.next_renew = Some(self.inner.clock.now());
            }
        }
    }

    fn remember_finished(&mut self, job: JobId, revision: Revision) {
        if self.finished.len() >= FINISHED_MEMORY {
            self.finished.clear();
        }
        self.finished.insert(job, revision);
    }

    /// Looks for every unfinished job and tracks those it may drive.
    async fn rescan(&mut self) {
        let now = self.inner.clock.now();
        self.next_scan = now
            .checked_add(self.inner.config.scan_interval)
            .unwrap_or(now);
        let view = match self
            .inner
            .store
            .read(tenko_store::ReadConsistency::Local)
            .await
        {
            Ok(view) => view,
            Err(error) => {
                tracing::warn!(%error, "runner cannot scan jobs");
                return;
            }
        };
        for state in [
            JobState::Queued,
            JobState::Running,
            JobState::Waiting,
            JobState::RollingBack,
        ] {
            let range = KeyRange::prefix(encode_key(&state));
            let mut page = range.clone();
            loop {
                let entries = match view.scan_typed(&BY_STATE, page.clone(), PAGE, false) {
                    Ok(entries) => entries,
                    Err(error) => {
                        tracing::warn!(%error, "runner cannot scan jobs");
                        return;
                    }
                };
                let full = entries.len() == PAGE;
                let last = entries.last().map(|(key, (), _)| BY_STATE.key(key));
                for ((_, id), (), _) in entries {
                    if !self.tracked.contains_key(&id) {
                        self.discover(view.as_ref(), id);
                    }
                }
                match last {
                    Some(last) if full => page = range.clone().after(last),
                    _ => break,
                }
            }
        }
    }

    fn dispatch(&mut self) {
        if self.stopping {
            return;
        }
        while self.in_flight < self.inner.config.workers.max(1) {
            let next = match self.ready.pop_front() {
                Some(job) => Some(job),
                None => next_queued(
                    &mut self.queues,
                    &mut self.tracked,
                    &mut self.in_use,
                    &self.inner.config,
                ),
            };
            let Some(job) = next else {
                break;
            };
            let Some(tracked) = self.tracked.get_mut(&job) else {
                continue;
            };
            if !matches!(tracked.phase, Phase::Ready | Phase::Queued) {
                continue;
            }
            tracked.phase = Phase::Driving { dirty: None };
            if let Some(at) = tracked.timer.take() {
                self.timers.remove(&(at, job));
            }
            if self.next_renew.is_none() {
                self.next_renew = Some(self.inner.clock.now());
            }
            self.in_flight += 1;
            let inner = Arc::clone(&self.inner);
            let tx = self.tx.clone();
            let stop = Arc::clone(&self.stop);
            let handle = self.tasks.spawn(async move {
                let end = drive(&inner, job, &stop).await;
                let _ = tx.send(Msg::Driven { job, end });
            });
            self.task_jobs.insert(handle.id(), job);
        }
    }

    fn driven(&mut self, job: JobId, end: DriveEnd) {
        self.in_flight = self.in_flight.saturating_sub(1);
        let Some(tracked) = self.tracked.get_mut(&job) else {
            return;
        };
        let dirty = match tracked.phase {
            Phase::Driving { dirty } => dirty,
            _ => None,
        };
        match end {
            DriveEnd::Parked { deadline, revision } => {
                tracked.revision = revision;
                tracked.phase = Phase::Parked;
                if dirty.is_some_and(|dirty| dirty > revision) {
                    tracked.phase = Phase::Ready;
                    self.ready.push_back(job);
                } else if let Some(at) = deadline {
                    tracked.timer = Some(at);
                    self.timers.insert((at, job));
                }
            }
            DriveEnd::Retry => {
                let now = self.inner.clock.now();
                let at = now
                    .checked_add(self.inner.config.retry_backoff)
                    .unwrap_or(now);
                tracked.phase = Phase::Parked;
                tracked.timer = Some(at);
                self.timers.insert((at, job));
            }
            DriveEnd::Terminal { revision } => {
                self.release(job);
                self.remember_finished(job, revision);
            }
            DriveEnd::NotOwned | DriveEnd::Missing | DriveEnd::Stopped => self.release(job),
        }
    }

    fn release(&mut self, job: JobId) {
        let Some(tracked) = self.tracked.remove(&job) else {
            return;
        };
        if let Some(at) = tracked.timer {
            self.timers.remove(&(at, job));
        }
        if tracked.slot
            && let Some(group) = &tracked.group
            && let Some(count) = self.in_use.get_mut(group)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.in_use.remove(group);
            }
        }
    }

    fn on_joined(&mut self, joined: Option<Result<(tokio::task::Id, ()), tokio::task::JoinError>>) {
        match joined {
            Some(Ok((id, ()))) => {
                self.task_jobs.remove(&id);
            }
            Some(Err(error)) => {
                if let Some(job) = self.task_jobs.remove(&error.id()) {
                    tracing::error!(%job, %error, "a job drive ended abnormally");
                    self.driven(job, DriveEnd::Retry);
                }
            }
            None => {}
        }
    }

    async fn on_timer(&mut self) {
        let now = self.inner.clock.now();
        while let Some(&(at, job)) = self.timers.first() {
            if at > now {
                break;
            }
            self.timers.pop_first();
            if let Some(tracked) = self.tracked.get_mut(&job)
                && tracked.phase == Phase::Parked
                && tracked.timer == Some(at)
            {
                tracked.timer = None;
                tracked.phase = Phase::Ready;
                self.ready.push_back(job);
            }
        }
        if now >= self.next_scan {
            self.rescan().await;
        }
        if self.next_renew.is_some_and(|at| now >= at) {
            self.renew(now).await;
        }
    }

    /// Renews the lease while this runner holds unfinished jobs.
    async fn renew(&mut self, now: Timestamp) {
        let active = self
            .tracked
            .values()
            .any(|tracked| tracked.phase != Phase::Queued);
        if !active {
            self.next_renew = None;
            return;
        }
        let mut batch = WriteBatch::new(
            tenko_core::Principal::system(tenko_core::SystemComponent::Jobs),
            now,
        );
        let renewed = batch
            .put_typed(&RUNNERS, &self.inner.config.node, &lease(&self.inner, now))
            .map(|_| ());
        match renewed {
            Ok(()) => {
                if let Err(error) = self.inner.store.propose(batch).await {
                    tracing::warn!(%error, "runner lease could not be renewed");
                }
            }
            Err(error) => tracing::error!(%error, "runner lease does not encode"),
        }
        let period = self.inner.config.lease_ttl / 3;
        self.next_renew = Some(now.checked_add(period).unwrap_or(now));
    }
}

/// Takes the oldest queued job whose group has a free slot, and takes the slot.
fn next_queued(
    queues: &mut BTreeMap<Option<GroupKey>, VecDeque<JobId>>,
    tracked: &mut HashMap<JobId, Tracked>,
    in_use: &mut HashMap<GroupKey, usize>,
    config: &crate::EngineConfig,
) -> Option<JobId> {
    let mut best: Option<(JobId, Option<GroupKey>)> = None;
    for (group, queue) in queues.iter_mut() {
        while let Some(front) = queue.front() {
            if tracked
                .get(front)
                .is_some_and(|tracked| tracked.phase == Phase::Queued)
            {
                break;
            }
            queue.pop_front();
        }
        let Some(front) = queue.front().copied() else {
            continue;
        };
        if let Some(group) = group
            && in_use.get(group).copied().unwrap_or(0) >= config.group_limit(group)
        {
            continue;
        }
        if best.as_ref().is_none_or(|(oldest, _)| front < *oldest) {
            best = Some((front, group.clone()));
        }
    }
    queues.retain(|_, queue| !queue.is_empty());
    let (job, group) = best?;
    if let Some(queue) = queues.get_mut(&group) {
        queue.pop_front();
        if queue.is_empty() {
            queues.remove(&group);
        }
    }
    if let Some(group) = group {
        *in_use.entry(group).or_default() += 1;
        if let Some(tracked) = tracked.get_mut(&job) {
            tracked.slot = true;
        }
    }
    Some(job)
}
