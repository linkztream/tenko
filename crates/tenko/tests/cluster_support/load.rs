//! The lab's write load: addresses created and changed at a steady rate through one
//! controller's API, open loop (a write starts on every tick, whatever the earlier ones
//! do), each with an `Idempotency-Key`, so a slow or failing cluster shows as latency and
//! failures instead of a lower rate.
//!
//! Every fifth write, and every write until the first create has committed, creates an
//! address in a documentation prefix of its own (`2001:db8:<tag>::/64`, created before the
//! load starts); the others change the description of an address created before
//! (`PATCH` with `If-Match: *`). Each write is recorded with its start, its latency, its
//! outcome and the revision of the answer; [`LoadReport`] summarizes them.

use std::{
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use reqwest::Method;
use serde_json::{Value, json};

use super::{http::send, lab::ClusterLab};

/// How long one write may take before it counts as unanswered.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// The most writes in flight; a tick beyond it is recorded as skipped.
pub const MAX_IN_FLIGHT: usize = 2048;

/// The outcome of one write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Committed at this revision.
    Committed(u64),
    /// Answered with an error status and its code.
    Refused(u16, Option<String>),
    /// No answer: a timeout or a broken connection (its fate is unknown).
    NoAnswer(String),
    /// Not sent: too many writes were in flight.
    Skipped,
}

/// What one write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `POST /addresses`.
    Create,
    /// `PATCH /addresses/{id}`.
    Update,
}

/// One write of the load.
#[derive(Debug, Clone)]
pub struct WriteRecord {
    /// Its number, from 1.
    pub seq: u64,
    /// Create or update.
    pub kind: Kind,
    /// When it started.
    pub start: Instant,
    /// How long it took until the answer (or the failure).
    pub latency: Duration,
    /// What came back.
    pub outcome: Outcome,
    /// The id of the address it created or changed.
    pub object: Option<String>,
}

impl WriteRecord {
    /// The revision it committed at.
    pub fn revision(&self) -> Option<u64> {
        match self.outcome {
            Outcome::Committed(revision) => Some(revision),
            _ => None,
        }
    }

    /// When the answer came.
    pub fn end(&self) -> Instant {
        self.start + self.latency
    }
}

/// What a load did, write by write.
#[derive(Debug, Clone)]
pub struct LoadReport {
    /// The controller the writes went to.
    pub target: String,
    /// The writes per second asked for.
    pub rate: u32,
    /// When the first write was due.
    pub started: Instant,
    /// When the last write was due.
    pub ended: Instant,
    /// Every write, by number.
    pub records: Vec<WriteRecord>,
}

/// The quantile `q` (0.0 to 1.0) of sorted durations, nearest rank.
pub fn quantile(sorted: &[Duration], q: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "a rank within the slice"
    )]
    let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// Milliseconds with three decimals, for reports.
pub fn ms(duration: Duration) -> f64 {
    (duration.as_secs_f64() * 1_000_000.0).round() / 1000.0
}

impl LoadReport {
    /// The committed writes.
    pub fn committed(&self) -> impl Iterator<Item = &WriteRecord> {
        self.records
            .iter()
            .filter(|record| record.revision().is_some())
    }

    /// The newest revision a write committed at (0 without any).
    pub fn committed_revision(&self) -> u64 {
        self.committed()
            .filter_map(WriteRecord::revision)
            .max()
            .unwrap_or(0)
    }

    /// Every write started, skipped ones included.
    pub fn count(&self) -> usize {
        self.records.len()
    }

    /// The committed writes.
    pub fn committed_count(&self) -> usize {
        self.committed().count()
    }

    /// The writes that did not commit, by outcome: refused, unanswered, skipped.
    pub fn failures(&self) -> (usize, usize, usize) {
        let mut counts = (0, 0, 0);
        for record in &self.records {
            match record.outcome {
                Outcome::Committed(_) => {}
                Outcome::Refused(..) => counts.0 += 1,
                Outcome::NoAnswer(_) => counts.1 += 1,
                Outcome::Skipped => counts.2 += 1,
            }
        }
        counts
    }

    /// The writes the cluster failed: refused, unanswered or not sent, except the refusals
    /// of `ipam.contended`, which are the load's own concurrent changes of one address
    /// invalidating each other's plans, not an outage.
    pub fn failed_writes(&self) -> usize {
        self.records
            .iter()
            .filter(|record| match &record.outcome {
                Outcome::Committed(_) => false,
                Outcome::Refused(_, code) => code.as_deref() != Some("ipam.contended"),
                Outcome::NoAnswer(_) | Outcome::Skipped => true,
            })
            .count()
    }

    /// The latencies of the committed writes, sorted.
    pub fn latencies(&self) -> Vec<Duration> {
        let mut latencies: Vec<Duration> = self.committed().map(|record| record.latency).collect();
        latencies.sort_unstable();
        latencies
    }

    /// The median latency of the committed writes.
    pub fn p50(&self) -> Duration {
        quantile(&self.latencies(), 0.50)
    }

    /// The 99th percentile latency of the committed writes.
    pub fn p99(&self) -> Duration {
        quantile(&self.latencies(), 0.99)
    }

    /// The longest time without a committed answer: between the start and the first
    /// commit, between two commits, and between the last commit and the end.
    pub fn longest_stall(&self) -> Duration {
        let mut ends: Vec<Instant> = self.committed().map(WriteRecord::end).collect();
        ends.sort_unstable();
        let mut longest = Duration::ZERO;
        let mut previous = self.started;
        for end in ends {
            longest = longest.max(end.saturating_duration_since(previous));
            previous = previous.max(end);
        }
        longest.max(self.ended.saturating_duration_since(previous))
    }

    /// The time from `at` until the answer of the first committed write that started at or
    /// after `at`: how long writes took to resume after a fault.
    pub fn resumed_after(&self, at: Instant) -> Option<Duration> {
        self.committed()
            .filter(|record| record.start >= at)
            .map(|record| record.end().saturating_duration_since(at))
            .min()
    }

    /// The committed writes per second over the load.
    pub fn committed_rate(&self) -> f64 {
        let seconds = self
            .ended
            .saturating_duration_since(self.started)
            .as_secs_f64();
        #[allow(clippy::cast_precision_loss, reason = "a count of writes")]
        let count = self.committed_count() as f64;
        if seconds > 0.0 { count / seconds } else { 0.0 }
    }

    /// The addresses the load created and the revision of each create.
    pub fn created(&self) -> Vec<(String, u64)> {
        self.records
            .iter()
            .filter(|record| record.kind == Kind::Create)
            .filter_map(|record| Some((record.object.clone()?, record.revision()?)))
            .collect()
    }

    /// A summary as JSON (counts, quantiles and the stall in milliseconds).
    pub fn summary(&self) -> Value {
        let (refused, unanswered, skipped) = self.failures();
        let mut codes = std::collections::BTreeMap::<String, usize>::new();
        for record in &self.records {
            if let Outcome::Refused(status, code) = &record.outcome {
                let key = format!("{status} {}", code.as_deref().unwrap_or("-"));
                *codes.entry(key).or_default() += 1;
            }
        }
        json!({
            "refused_by_code": codes,
            "target": self.target,
            "rate": self.rate,
            "seconds": self.ended.saturating_duration_since(self.started).as_secs_f64(),
            "writes": self.count(),
            "committed": self.committed_count(),
            "refused": refused,
            "unanswered": unanswered,
            "skipped": skipped,
            "committed_per_second": self.committed_rate(),
            "p50_ms": ms(self.p50()),
            "p99_ms": ms(self.p99()),
            "max_ms": ms(self.latencies().last().copied().unwrap_or_default()),
            "longest_stall_ms": ms(self.longest_stall()),
            "committed_revision": self.committed_revision(),
        })
    }
}

/// A load that runs until [`LoadHandle::stop`].
pub struct LoadHandle {
    stopping: Arc<AtomicBool>,
    runtime: Arc<tokio::runtime::Runtime>,
    records: Arc<Mutex<Vec<WriteRecord>>>,
    task: Option<tokio::task::JoinHandle<LoadReport>>,
}

impl LoadHandle {
    /// While the load runs: the time from `at` until the answer of the first committed
    /// write that started at or after `at`, once there is one.
    pub fn resumed_after(&self, at: Instant) -> Option<Duration> {
        self.records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|record| record.start >= at && record.revision().is_some())
            .map(|record| record.end().saturating_duration_since(at))
            .min()
    }

    /// Stops issuing writes, waits for the ones in flight and returns the report.
    pub fn stop(mut self) -> LoadReport {
        self.stopping.store(true, Ordering::SeqCst);
        let task = self.task.take().expect("a running load");
        self.runtime.block_on(task).expect("the load task")
    }
}

impl Drop for LoadHandle {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Distinguishes the prefixes of the loads of one process.
static LOADS: AtomicU64 = AtomicU64::new(0);

impl ClusterLab {
    /// Starts a write load of `rate` writes per second through controller `target`.
    #[track_caller]
    pub fn start_load(&self, target: u64, rate: u32) -> LoadHandle {
        assert!(rate > 0, "a load writes");
        let base = self.url(target);
        let tag = 0x1000
            + (u64::from(std::process::id()) * 64 + LOADS.fetch_add(1, Ordering::Relaxed)) % 0xE000;
        let cidr = format!("2001:db8:{tag:x}::/64");
        let reply = self
            .http()
            .send(
                Method::POST,
                &base,
                "/prefixes",
                Some(self.cookie()),
                Some(&json!({ "cidr": cidr, "description": "lab load" })),
                &[("Idempotency-Key", uuid::Uuid::now_v7().to_string())],
            )
            .unwrap_or_else(|error| panic!("the load prefix: {error}\n{}", self.diagnostics()));
        assert!(
            (200..300).contains(&reply.status),
            "the load prefix {cidr}: HTTP {} {}",
            reply.status,
            reply.text
        );
        let stopping = Arc::new(AtomicBool::new(false));
        let records = Arc::new(Mutex::new(Vec::new()));
        let runtime = Arc::clone(self.http().runtime());
        let task = runtime.spawn(generate(Generator {
            client: self.http().client().clone(),
            base,
            cookie: self.cookie().to_owned(),
            rate,
            tag,
            stopping: Arc::clone(&stopping),
            records: Arc::clone(&records),
        }));
        LoadHandle {
            stopping,
            runtime,
            records,
            task: Some(task),
        }
    }

    /// The addresses a load created and committed that controller `on` does not show once
    /// it has applied the load's last committed revision: a committed write it lost.
    pub fn missing_creates(&self, report: &LoadReport, on: u64) -> Vec<String> {
        let at_least = report.committed_revision();
        report
            .created()
            .into_iter()
            .filter(|(id, _)| {
                self.get(on, &format!("/addresses/{id}?at_least={at_least}"))
                    .is_none_or(|reply| reply.status != 200)
            })
            .map(|(id, _)| id)
            .collect()
    }

    /// Runs a write load of `rate` writes per second through controller `target` for
    /// `duration` and returns its report.
    #[track_caller]
    pub fn write_load(&self, target: u64, rate: u32, duration: Duration) -> LoadReport {
        let load = self.start_load(target, rate);
        thread::sleep(duration);
        load.stop()
    }
}

struct Generator {
    client: reqwest::Client,
    base: String,
    cookie: String,
    rate: u32,
    tag: u64,
    stopping: Arc<AtomicBool>,
    records: Arc<Mutex<Vec<WriteRecord>>>,
}

#[allow(
    clippy::too_many_lines,
    reason = "the tick loop and one write read best together"
)]
async fn generate(generator: Generator) -> LoadReport {
    let Generator {
        client,
        base,
        cookie,
        rate,
        tag,
        stopping,
        records,
    } = generator;
    let objects: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let creates = Arc::new(AtomicU64::new(0));
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
    let mut ticker = tokio::time::interval(Duration::from_secs_f64(1.0 / f64::from(rate)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let mut tasks = tokio::task::JoinSet::new();
    let started = Instant::now();
    let mut seq = 0_u64;
    while !stopping.load(Ordering::SeqCst) {
        ticker.tick().await;
        seq += 1;
        let start = Instant::now();
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            records
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(WriteRecord {
                    seq,
                    kind: Kind::Update,
                    start,
                    latency: Duration::ZERO,
                    outcome: Outcome::Skipped,
                    object: None,
                });
            continue;
        };
        let target = {
            let objects = objects.lock().unwrap_or_else(PoisonError::into_inner);
            if seq % 5 == 1 || objects.is_empty() {
                None
            } else {
                let index = usize::try_from(seq).unwrap_or(0) % objects.len();
                Some(objects[index].clone())
            }
        };
        let client = client.clone();
        let base = base.clone();
        let cookie = cookie.clone();
        let records = Arc::clone(&records);
        let objects = Arc::clone(&objects);
        let creates = Arc::clone(&creates);
        tasks.spawn(async move {
            let key = ("Idempotency-Key", uuid::Uuid::now_v7().to_string());
            let (kind, reply) = if let Some(id) = &target {
                let body = json!({ "description": format!("lab load write {seq}") });
                (
                    Kind::Update,
                    send(
                        &client,
                        Method::PATCH,
                        &base,
                        &format!("/addresses/{id}"),
                        Some(&cookie),
                        Some(&body),
                        &[key, ("If-Match", "*".to_owned())],
                        WRITE_TIMEOUT,
                    )
                    .await,
                )
            } else {
                let number = creates.fetch_add(1, Ordering::Relaxed) + 1;
                let ip = format!("2001:db8:{tag:x}::{:x}:{:x}", number >> 16, number & 0xFFFF);
                let body = json!({ "ip": ip, "description": format!("lab load write {seq}") });
                (
                    Kind::Create,
                    send(
                        &client,
                        Method::POST,
                        &base,
                        "/addresses",
                        Some(&cookie),
                        Some(&body),
                        &[key],
                        WRITE_TIMEOUT,
                    )
                    .await,
                )
            };
            let latency = start.elapsed();
            let (outcome, object) = match reply {
                Ok(reply) if (200..300).contains(&reply.status) => {
                    let body = reply.json();
                    let object = body["item"]["id"]
                        .as_str()
                        .map(str::to_owned)
                        .or_else(|| target.clone());
                    match body["revision"].as_u64() {
                        Some(revision) => (Outcome::Committed(revision), object),
                        None => (
                            Outcome::Refused(reply.status, Some("no revision".to_owned())),
                            object,
                        ),
                    }
                }
                Ok(reply) => (Outcome::Refused(reply.status, reply.code()), target.clone()),
                Err(error) => (Outcome::NoAnswer(error), target.clone()),
            };
            if kind == Kind::Create
                && matches!(outcome, Outcome::Committed(_))
                && let Some(id) = &object
            {
                objects
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(id.clone());
            }
            records
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(WriteRecord {
                    seq,
                    kind,
                    start,
                    latency,
                    outcome,
                    object,
                });
            drop(permit);
        });
        // Reap finished writes so the set stays small.
        while tasks.try_join_next().is_some() {}
    }
    let ended = Instant::now();
    while tasks.join_next().await.is_some() {}
    let mut records = records
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    records.sort_by_key(|record| record.seq);
    LoadReport {
        target: base,
        rate,
        started,
        ended,
        records,
    }
}

/// One read of a read load.
#[derive(Debug, Clone)]
pub struct ReadRecord {
    /// When it started.
    pub start: Instant,
    /// How long it took.
    pub latency: Duration,
    /// The status, `None` without an answer.
    pub status: Option<u16>,
    /// A 200 whose `items`, when the answer is a list, are not empty.
    pub ok: bool,
}

/// What a read load did.
#[derive(Debug, Clone)]
pub struct ReadReport {
    /// When the first read was due.
    pub started: Instant,
    /// When the last read was due.
    pub ended: Instant,
    /// Every read, in start order.
    pub records: Vec<ReadRecord>,
}

impl ReadReport {
    /// The reads that started between `from` and `to`.
    pub fn window(&self, from: Instant, to: Instant) -> Self {
        Self {
            started: from,
            ended: to,
            records: self
                .records
                .iter()
                .filter(|record| record.start >= from && record.start < to)
                .cloned()
                .collect(),
        }
    }

    /// The latencies of the good reads, sorted.
    pub fn latencies(&self) -> Vec<Duration> {
        let mut latencies: Vec<Duration> = self
            .records
            .iter()
            .filter(|record| record.ok)
            .map(|record| record.latency)
            .collect();
        latencies.sort_unstable();
        latencies
    }

    /// The reads that failed or came back empty.
    pub fn bad(&self) -> usize {
        self.records.iter().filter(|record| !record.ok).count()
    }

    /// The 99th percentile latency of the good reads.
    pub fn p99(&self) -> Duration {
        quantile(&self.latencies(), 0.99)
    }

    /// A summary as JSON.
    pub fn summary(&self) -> Value {
        let latencies = self.latencies();
        json!({
            "seconds": self.ended.saturating_duration_since(self.started).as_secs_f64(),
            "reads": self.records.len(),
            "bad": self.bad(),
            "p50_ms": ms(quantile(&latencies, 0.50)),
            "p99_ms": ms(quantile(&latencies, 0.99)),
            "max_ms": ms(latencies.last().copied().unwrap_or_default()),
        })
    }
}

/// A read load that runs until [`ReadHandle::stop`].
pub struct ReadHandle {
    stopping: Arc<AtomicBool>,
    runtime: Arc<tokio::runtime::Runtime>,
    task: Option<tokio::task::JoinHandle<ReadReport>>,
}

impl ReadHandle {
    /// Stops reading and returns the report.
    pub fn stop(mut self) -> ReadReport {
        self.stopping.store(true, Ordering::SeqCst);
        let task = self.task.take().expect("a running read load");
        self.runtime.block_on(task).expect("the read task")
    }
}

impl Drop for ReadHandle {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl ClusterLab {
    /// Starts `rate` reads per second of the API path `path` on controller `target`, open
    /// loop.
    pub fn start_reads(&self, target: u64, rate: u32, path: &str) -> ReadHandle {
        assert!(rate > 0, "a read load reads");
        let stopping = Arc::new(AtomicBool::new(false));
        let runtime = Arc::clone(self.http().runtime());
        let task = runtime.spawn(read_loop(
            self.http().client().clone(),
            self.url(target),
            self.cookie().to_owned(),
            path.to_owned(),
            rate,
            Arc::clone(&stopping),
        ));
        ReadHandle {
            stopping,
            runtime,
            task: Some(task),
        }
    }
}

async fn read_loop(
    client: reqwest::Client,
    base: String,
    cookie: String,
    path: String,
    rate: u32,
    stopping: Arc<AtomicBool>,
) -> ReadReport {
    let records = Arc::new(Mutex::new(Vec::new()));
    let mut ticker = tokio::time::interval(Duration::from_secs_f64(1.0 / f64::from(rate)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let mut tasks = tokio::task::JoinSet::new();
    let started = Instant::now();
    while !stopping.load(Ordering::SeqCst) {
        ticker.tick().await;
        let start = Instant::now();
        let (client, base, cookie, path) =
            (client.clone(), base.clone(), cookie.clone(), path.clone());
        let records = Arc::clone(&records);
        tasks.spawn(async move {
            let reply = send(
                &client,
                Method::GET,
                &base,
                &path,
                Some(&cookie),
                None,
                &[],
                WRITE_TIMEOUT,
            )
            .await;
            let latency = start.elapsed();
            let (status, ok) = match reply {
                Ok(reply) => {
                    let empty = reply.json()["items"].as_array().is_some_and(Vec::is_empty);
                    (Some(reply.status), reply.status == 200 && !empty)
                }
                Err(_) => (None, false),
            };
            records
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(ReadRecord {
                    start,
                    latency,
                    status,
                    ok,
                });
        });
        while tasks.try_join_next().is_some() {}
    }
    let ended = Instant::now();
    while tasks.join_next().await.is_some() {}
    let mut records = records
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    records.sort_by_key(|record| record.start);
    ReadReport {
        started,
        ended,
        records,
    }
}
