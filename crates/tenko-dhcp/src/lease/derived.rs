//! The asynchronous writer of the rows derived from a lease change (ADR 0030, WP9.6).
//!
//! A lease commit holds the lease row and the client index entries it moves, nothing else
//! (DHCP-17: the lease row is committed before the ACK). What derives from the row, the
//! lean history row (ADR 0031; before it also the IPAM observation facts, which IPAM now
//! reads from the lease table), goes here once the lease committed:
//! [`DerivedWriter::push`] puts the mutations into a bounded queue without waiting, and the [`DerivedFlusher`] writes
//! everything queued every [`DerivedSettings::interval`] (250 ms) or as soon as
//! [`DerivedSettings::max_items`] changes wait, whichever comes first. A flush is one store
//! batch for the changes of a quiet interval and, under load, waves of up to
//! [`DerivedSettings::in_flight`] (32) batches of at most [`DerivedSettings::batch_bytes`]
//! (16 KiB) proposed at once in the store's background class
//! ([`tenko_store::Store::propose_background`], ADR 0030): the coalescer packs the lease
//! commits waiting first and carries one such batch beside them per entry, so a lease
//! commit never waits behind more than one background batch in the append and the apply.
//!
//! # Guarantees
//!
//! - **Eventual within one second.** A change's derived rows are written by the first flush
//!   after its lease committed: within the interval plus one commit. A store that refuses
//!   keeps them queued and the flusher retries every interval.
//! - **Never blocking the ACK.** A full queue drops the change's derived rows and counts
//!   them (`tenko_dhcp_derived_dropped_total`); when the queue stays full for longer than
//!   [`DerivedSettings::tolerance`], the health finding [`FINDING`] is raised until a
//!   flush succeeds again. A dropped history row is lost (the catch-up of the next start
//!   rebuilds it only for the changes of its window).
//! - **Order.** A later change of a row always lands after an earlier one: inside one
//!   batch a later mutation of a key wins, and two batches in flight together never write
//!   the same row (the change that would ends the wave).
//! - **A crash** loses the queue: at most the derived rows of the last interval. The role's
//!   start rebuilds them from the lease table ([`catch_up`]), see ADR 0030.
//! - **Shutdown** flushes what is queued before the flusher ends.

use std::{
    collections::{HashSet, VecDeque},
    net::Ipv4Addr,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tenko_core::{
    Principal, SystemComponent, Timestamp, VrfId,
    dhcp::{BindingState, Lease, LeaseEvent, LeaseEventKind, tables},
    metrics::{Counter, Desc, Gauge, Registry},
};
use tenko_store::{
    KeyRange, Mutation, ReadConsistency, ReadViewExt, Store, StoreError, WriteBatch,
};
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;

use super::{batch::put_history, metrics::HISTORY_WRITTEN};

/// The code of the health finding while the derived rows are dropped.
pub const FINDING: &str = "dhcp.role.derived_dropped";

/// `tenko_dhcp_derived_written_total`: lease changes whose derived rows were written.
pub static WRITTEN: Counter = Counter::new(Desc::counter(
    "tenko_dhcp_derived_written",
    "DHCP lease changes whose history rows the asynchronous writer wrote",
));

/// `tenko_dhcp_derived_dropped_total`: lease changes whose derived rows were dropped.
pub static DROPPED: Counter = Counter::new(Desc::counter(
    "tenko_dhcp_derived_dropped",
    "DHCP lease changes whose history rows were dropped (queue full)",
));

/// `tenko_dhcp_derived_rebuilt_total`: derived rows rebuilt from the lease table at start.
pub static REBUILT: Counter = Counter::new(Desc::counter(
    "tenko_dhcp_derived_rebuilt",
    "DHCP history rows rebuilt from the lease table at start",
));

/// `tenko_dhcp_derived_queue`: lease changes waiting for the asynchronous writer.
pub static QUEUED: Gauge = Gauge::new(Desc::gauge(
    "tenko_dhcp_derived_queue",
    "DHCP lease changes waiting for the asynchronous writer of their history rows",
));

/// Registers the writer's series.
pub fn register(registry: &Registry) {
    registry.register(&WRITTEN);
    registry.register(&DROPPED);
    registry.register(&REBUILT);
    registry.register(&QUEUED);
}

/// Publishes the queue length. The series is a gauge, so it takes a float; a gauge's
/// `set_total` is for a mirrored counter and would store the count as the bits of a float.
fn set_queued(len: usize) {
    #[allow(clippy::cast_precision_loss)]
    QUEUED.set(len as f64);
}

/// The writer's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedSettings {
    /// Longest time a pushed change waits for its flush.
    pub interval: Duration,
    /// Changes that start a flush at once.
    pub max_items: usize,
    /// Payload bytes of one store batch of a flush at most (at least one change): 16 KiB,
    /// about five changes of an office client, within the background share the coalescer
    /// carries beside the lease commits of one entry (`tenko_store::raft::BACKGROUND_SHARE`).
    pub batch_bytes: usize,
    /// Store batches of one flush proposed at once (at least one): enough that one waits
    /// for every entry the lease commits make, and that a backlog reaches the coalescer's
    /// cap on the background wait. Batches in flight together never write the same row: a
    /// change that does ends the wave and goes into the next.
    pub in_flight: usize,
    /// Changes the queue holds; a push to a full queue drops the change's derived rows.
    pub queue: usize,
    /// How long the queue may stay full before the finding is raised (ADR 0030: the
    /// eventual consistency of one second).
    pub tolerance: Duration,
}

impl Default for DerivedSettings {
    fn default() -> Self {
        Self {
            interval: Duration::from_millis(250),
            max_items: 1_000,
            batch_bytes: 16 * 1024,
            in_flight: 32,
            queue: 65_536,
            tolerance: Duration::from_secs(1),
        }
    }
}

/// The derived rows of one lease change.
#[derive(Debug)]
struct Item {
    mutations: Vec<Mutation>,
    history: u64,
    bytes: usize,
    /// Hashes of the table and key of every row it writes: two changes that share one are
    /// never in two store batches in flight at once, so the later always lands last.
    keys: Vec<u64>,
}

/// The hash of one row's table and key.
fn row_key(mutation: &Mutation) -> Option<u64> {
    use std::hash::{BuildHasher, BuildHasherDefault, DefaultHasher};
    let hasher = BuildHasherDefault::<DefaultHasher>::default();
    match mutation {
        Mutation::Put { table, key, .. } | Mutation::Delete { table, key } => {
            Some(hasher.hash_one((table.as_str(), &key[..])))
        }
        Mutation::Bump { .. } => None,
    }
}

/// The health finding while it is raised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedFinding {
    /// [`FINDING`].
    pub code: &'static str,
    /// When the queue was first found full.
    pub since: Timestamp,
    /// Changes dropped since then.
    pub dropped: u64,
}

#[derive(Debug, Default)]
struct Full {
    since: Option<(Instant, Timestamp)>,
    dropped_since: u64,
}

#[derive(Debug)]
struct Shared {
    settings: DerivedSettings,
    queue: Mutex<VecDeque<Item>>,
    wake: Notify,
    pushed: AtomicU64,
    /// The sequence number of the last change written or dropped by a flush.
    done: watch::Sender<u64>,
    written: AtomicU64,
    dropped: AtomicU64,
    full: Mutex<Full>,
}

/// The hand-off side of the writer, shared by the committer and the role.
#[derive(Debug, Clone)]
pub struct DerivedWriter {
    shared: Arc<Shared>,
}

/// The flushing task of a [`DerivedWriter`]; run it with [`DerivedFlusher::run`].
pub struct DerivedFlusher {
    shared: Arc<Shared>,
    store: Arc<dyn Store>,
}

impl std::fmt::Debug for DerivedFlusher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedFlusher")
            .field("settings", &self.shared.settings)
            .finish_non_exhaustive()
    }
}

/// What the writer has done since it started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DerivedStats {
    /// Changes pushed.
    pub pushed: u64,
    /// Changes whose rows were written.
    pub written: u64,
    /// Changes whose rows were dropped.
    pub dropped: u64,
    /// Changes waiting now.
    pub queued: usize,
}

impl DerivedWriter {
    /// A writer that flushes into `store`, and its flusher.
    pub fn new(store: Arc<dyn Store>, settings: DerivedSettings) -> (Self, DerivedFlusher) {
        let shared = Arc::new(Shared {
            settings,
            queue: Mutex::new(VecDeque::new()),
            wake: Notify::new(),
            pushed: AtomicU64::new(0),
            done: watch::channel(0).0,
            written: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            full: Mutex::new(Full::default()),
        });
        (
            Self {
                shared: Arc::clone(&shared),
            },
            DerivedFlusher { shared, store },
        )
    }

    /// Queues the derived rows of one committed change; never waits. `false` when the
    /// queue was full and the rows were dropped (counted). An empty batch is not queued.
    pub fn push(&self, derived: WriteBatch) -> bool {
        if derived.mutations.is_empty() {
            return true;
        }
        let history = derived
            .mutations
            .iter()
            .filter(|mutation| {
                matches!(mutation, Mutation::Put { table, .. }
                    if table == tables::HISTORY.name() || table == tables::HISTORY6.name())
            })
            .count();
        let item = Item {
            bytes: derived.payload_size(),
            keys: derived.mutations.iter().filter_map(row_key).collect(),
            mutations: derived.mutations,
            history: u64::try_from(history).unwrap_or(u64::MAX),
        };
        let shared = &*self.shared;
        let (accepted, len) = {
            let mut queue = shared.queue.lock().unwrap_or_else(PoisonError::into_inner);
            if queue.len() >= shared.settings.queue.max(1) {
                (false, queue.len())
            } else {
                queue.push_back(item);
                (true, queue.len())
            }
        };
        shared.pushed.fetch_add(1, Ordering::AcqRel);
        set_queued(len);
        if accepted {
            if len >= shared.settings.max_items.max(1) {
                shared.wake.notify_one();
            }
        } else {
            shared.dropped.fetch_add(1, Ordering::Relaxed);
            DROPPED.inc();
            let mut full = shared.full.lock().unwrap_or_else(PoisonError::into_inner);
            if full.since.is_none() {
                full.since = Some((Instant::now(), Timestamp::now()));
                tracing::warn!(
                    queue = shared.settings.queue,
                    "the writer of the lease history is full; history rows are dropped"
                );
            }
            full.dropped_since += 1;
            drop(full);
            // A dropped change counts as done for the waiters of `flush` (which may then
            // return a little early while the queue is full: the rows are dropped anyway).
            shared.done.send_modify(|done| *done += 1);
        }
        accepted
    }

    /// Waits until every change pushed before the call is written (or dropped): the
    /// tests, the tools that read the history right after a commit and the shutdown. Wakes the
    /// flusher at once.
    pub async fn flush(&self) {
        let target = self.shared.pushed.load(Ordering::Acquire);
        let mut done = self.shared.done.subscribe();
        loop {
            if *done.borrow_and_update() >= target {
                return;
            }
            self.shared.wake.notify_one();
            if tokio::time::timeout(self.shared.settings.interval, done.changed())
                .await
                .is_ok_and(|changed| changed.is_err())
            {
                return;
            }
        }
    }

    /// The counts since the start.
    pub fn stats(&self) -> DerivedStats {
        let shared = &*self.shared;
        DerivedStats {
            pushed: shared.pushed.load(Ordering::Relaxed),
            written: shared.written.load(Ordering::Relaxed),
            dropped: shared.dropped.load(Ordering::Relaxed),
            queued: shared
                .queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len(),
        }
    }

    /// The health finding: raised when the queue has been full for longer than the
    /// tolerance, cleared by the next successful flush.
    pub fn finding(&self) -> Option<DroppedFinding> {
        let full = self
            .shared
            .full
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (began, since) = full.since?;
        (began.elapsed() >= self.shared.settings.tolerance).then(|| DroppedFinding {
            code: FINDING,
            since,
            dropped: full.dropped_since,
        })
    }
}

impl DerivedFlusher {
    /// Flushes every interval, or when the queue reaches the flush size, until `stop`
    /// fires; then flushes what is queued and ends.
    pub async fn run(self, stop: CancellationToken) {
        let interval = self.shared.settings.interval;
        loop {
            tokio::select! {
                biased;
                () = stop.cancelled() => break,
                () = self.shared.wake.notified() => {}
                () = tokio::time::sleep(interval) => {}
            }
            self.flush_all(false).await;
        }
        self.flush_all(true).await;
    }

    /// Writes what is queued at the start, in waves of up to [`DerivedSettings::in_flight`]
    /// store batches of at most [`DerivedSettings::batch_bytes`] each, proposed at once; on
    /// a refusal the rest stays queued for the next interval (or, at shutdown, is given up).
    async fn flush_all(&self, last: bool) {
        let mut left = self
            .shared
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        while left > 0 {
            match self.flush_wave(left).await {
                Flushed::Wrote(count) => left = left.saturating_sub(count),
                Flushed::Empty => return,
                Flushed::Refused => {
                    if last {
                        tracing::warn!(
                            queued = self
                                .shared
                                .queue
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .len(),
                            "the store refused the last flush of the lease history at shutdown; \
                             the start rebuilds what its window covers"
                        );
                    }
                    return;
                }
            }
        }
    }

    /// Takes the next wave from the queue, in queue order: up to `limit` changes in up to
    /// [`DerivedSettings::in_flight`] batches of at most the byte bound. A change that
    /// writes a row a closed batch of the wave writes too ends the wave, so that it goes
    /// into a later wave and lands after that batch (inside one batch a later mutation of
    /// a key wins anyway).
    fn take_wave(&self, limit: usize) -> Vec<Vec<Item>> {
        let settings = &self.shared.settings;
        let mut queue = self
            .shared
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut wave: Vec<Vec<Item>> = Vec::new();
        let mut closed: HashSet<u64> = HashSet::new();
        let (mut current, mut current_keys, mut bytes) = (Vec::new(), Vec::new(), 0);
        let mut taken = 0;
        while taken < limit {
            let Some(next) = queue.front() else {
                break;
            };
            if !current.is_empty() && bytes + next.bytes > settings.batch_bytes {
                if wave.len() + 1 >= settings.in_flight.max(1) {
                    break;
                }
                closed.extend(current_keys.drain(..));
                wave.push(std::mem::take(&mut current));
                bytes = 0;
            }
            if next.keys.iter().any(|key| closed.contains(key)) {
                break;
            }
            let Some(item) = queue.pop_front() else {
                break;
            };
            bytes += item.bytes;
            current_keys.extend(item.keys.iter().copied());
            current.push(item);
            taken += 1;
        }
        if !current.is_empty() {
            wave.push(current);
        }
        wave
    }

    /// Proposes one wave's batches at once and counts each batch's changes as written or
    /// dropped; the changes of a refused batch go back to the front of the queue in order.
    async fn flush_wave(&self, limit: usize) -> Flushed {
        let shared = &*self.shared;
        let wave = self.take_wave(limit);
        if wave.is_empty() {
            return Flushed::Empty;
        }
        let proposals = wave.iter().map(|items| {
            let mut batch =
                WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
            batch.mutations = items
                .iter()
                .flat_map(|item| item.mutations.iter().cloned())
                .collect();
            self.store.propose_background(batch)
        });
        let results = futures::future::join_all(proposals).await;
        let (mut taken, mut refused) = (0, Vec::new());
        for (items, result) in wave.into_iter().zip(results) {
            let count = u64::try_from(items.len()).unwrap_or(u64::MAX);
            taken += items.len();
            match result {
                Ok(_) => {
                    let history: u64 = items.iter().map(|item| item.history).sum();
                    shared.written.fetch_add(count, Ordering::Relaxed);
                    WRITTEN.add(count);
                    HISTORY_WRITTEN.fetch_add(history, Ordering::Relaxed);
                    self.mark_done(count);
                    shared
                        .full
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .since = None;
                }
                Err(error) if is_refusal(&error) => {
                    tracing::debug!(%error, "the store refused a flush of the lease history");
                    refused.push(items);
                }
                Err(error) => {
                    tracing::warn!(%error, changes = count, "a flush of the lease history failed; its rows are dropped");
                    shared.dropped.fetch_add(count, Ordering::Relaxed);
                    DROPPED.add(count);
                    self.mark_done(count);
                }
            }
        }
        let mut queue = shared.queue.lock().unwrap_or_else(PoisonError::into_inner);
        let refused_any = !refused.is_empty();
        for item in refused.into_iter().flatten().rev() {
            queue.push_front(item);
        }
        set_queued(queue.len());
        if refused_any {
            Flushed::Refused
        } else {
            Flushed::Wrote(taken)
        }
    }

    fn mark_done(&self, count: u64) {
        self.shared.done.send_modify(|done| *done += count);
    }
}

enum Flushed {
    Empty,
    Wrote(usize),
    Refused,
}

fn is_refusal(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::NoQuorum
            | StoreError::Timeout
            | StoreError::ShuttingDown
            | StoreError::Storage(_)
    )
}

/// How far behind the newest history row the catch-up looks for leases whose derived rows
/// a crash may have lost: the writer's interval with room for a clock that stepped.
pub const CATCH_UP_WINDOW: Duration = Duration::from_secs(10);

/// What the catch-up rebuilt.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CatchUp {
    /// Leases the catch-up looked at.
    pub leases: u64,
    /// History rows written again.
    pub history: u64,
    /// The addresses whose history row was written again: their history may miss earlier
    /// changes of the lost interval.
    pub addresses: Vec<(VrfId, Ipv4Addr)>,
}

/// The history event that a lease row stands for, when its own was lost: the row's state
/// read as the change that leads to it.
fn rebuilt_kind(state: BindingState) -> LeaseEventKind {
    match state {
        BindingState::Released => LeaseEventKind::Released,
        BindingState::Expired => LeaseEventKind::Expired,
        BindingState::Abandoned => LeaseEventKind::Conflict,
        BindingState::Free | BindingState::Backup | BindingState::Reset => {
            LeaseEventKind::Reclaimed
        }
        BindingState::Active => LeaseEventKind::Granted,
    }
}

/// Rebuilds at start what a crash may have lost of the derived rows of acknowledged
/// changes (ADR 0030): every lease row whose client transaction time is not older than
/// [`CATCH_UP_WINDOW`] before the newest history row (all rows when there is none) gets its
/// history row when it is missing, naming the lease row's revision (ADR 0031). The rows go
/// through `writer`. There are no facts to rebuild: IPAM reads the lease table itself.
///
/// Only the last change of an address can be rebuilt: an earlier change of the same
/// address in the lost interval is not in the lease table any more, and its history row
/// stays lost.
///
/// # Errors
///
/// The store's error when the history cannot be read or a row does not encode.
pub async fn catch_up(
    store: &dyn Store,
    leases: impl IntoIterator<Item = Lease>,
    writer: &DerivedWriter,
) -> Result<CatchUp, StoreError> {
    let view = store.read(ReadConsistency::Local).await?;
    let newest = view
        .scan_typed(&tables::HISTORY, KeyRange::all(), 1, true)?
        .into_iter()
        .next()
        .map(
            |((at, _, _), _, _): (
                (Timestamp, VrfId, Ipv4Addr),
                tenko_core::dhcp::HistoryRow,
                _,
            )| at,
        );
    let from = newest.map(|at| at.checked_sub(CATCH_UP_WINDOW).unwrap_or(at));
    let now = Timestamp::now();
    let mut out = CatchUp::default();
    for lease in leases {
        if from.is_some_and(|from| lease.cltt < from) {
            continue;
        }
        out.leases += 1;
        let key = (lease.cltt, lease.vrf, lease.addr);
        if view.get_typed(&tables::HISTORY, &key)?.is_some() {
            continue;
        }
        let revision = view
            .get_typed(&tables::LEASES, &(lease.vrf, lease.addr))?
            .map(|(_, revision): (Lease, _)| revision);
        let event = LeaseEvent::of(&lease, rebuilt_kind(lease.state), lease.cltt);
        let mut derived = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
        put_history(&mut derived, &event, revision)?;
        out.history += 1;
        out.addresses.push((lease.vrf, lease.addr));
        writer.push(derived);
    }
    REBUILT.add(out.history);
    if out.history > 0 {
        tracing::info!(
            history = out.history,
            looked_at = out.leases,
            "the lease history a crash lost was rebuilt from the lease table"
        );
    }
    Ok(out)
}

// WP9.1 rows: the DHCPv6 leases by the same rule.
/// [`catch_up`] for the DHCPv6 leases (`dhcp.history6`, whose rows keep the whole event);
/// the addresses it reports are not filled (they are IPv4 addresses).
///
/// # Errors
///
/// As [`catch_up`].
pub async fn catch_up6(
    store: &dyn Store,
    leases: impl IntoIterator<Item = tenko_core::dhcp::Lease6>,
    writer: &DerivedWriter,
) -> Result<CatchUp, StoreError> {
    let view = store.read(ReadConsistency::Local).await?;
    let newest = view
        .scan_typed(&tables::HISTORY6, KeyRange::all(), 1, true)?
        .into_iter()
        .next()
        .map(|((at, _, _), _, _)| at);
    let from = newest.map(|at| at.checked_sub(CATCH_UP_WINDOW).unwrap_or(at));
    let now = Timestamp::now();
    let mut out = CatchUp::default();
    for lease in leases {
        if from.is_some_and(|from| lease.cltt < from) {
            continue;
        }
        out.leases += 1;
        let mut derived = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
        let key = (lease.cltt, lease.vrf, lease.addr6());
        if view.get_typed(&tables::HISTORY6, &key)?.is_none() {
            let event =
                tenko_core::dhcp::Lease6Event::of(&lease, rebuilt_kind(lease.state), lease.cltt);
            derived.put_typed(&tables::HISTORY6, &key, &event)?;
            out.history += 1;
        }
        if !derived.mutations.is_empty() {
            writer.push(derived);
        }
    }
    REBUILT.add(out.history);
    if out.history > 0 {
        tracing::info!(
            history = out.history,
            looked_at = out.leases,
            "the DHCPv6 lease history a crash lost was rebuilt from the lease table"
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenko_store::{MemStore, MemStoreConfig};

    fn row(key: u8) -> WriteBatch {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
        batch.put(
            tenko_core::TableName::from_static("dhcp.test"),
            vec![key],
            vec![key],
        );
        batch
    }

    #[tokio::test]
    async fn a_flush_writes_the_queue_as_one_batch_within_its_interval() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new(MemStoreConfig::default()));
        let settings = DerivedSettings {
            interval: Duration::from_millis(50),
            ..DerivedSettings::default()
        };
        let (writer, flusher) = DerivedWriter::new(Arc::clone(&store), settings);
        let stop = CancellationToken::new();
        let task = tokio::spawn(flusher.run(stop.clone()));
        let before = store.status().revision;
        for key in 0..10 {
            assert!(writer.push(row(key)));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let stats = writer.stats();
        assert_eq!((stats.written, stats.queued), (10, 0), "{stats:?}");
        assert_eq!(
            store.status().revision.0 - before.0,
            1,
            "ten changes, one store batch"
        );
        stop.cancel();
        task.await.expect("the flusher");
    }

    #[tokio::test]
    async fn a_flush_under_load_splits_into_batches_within_the_byte_bound() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new(MemStoreConfig::default()));
        // One change is 11 payload bytes (`dhcp.test`, a key and a value octet).
        let settings = DerivedSettings {
            interval: Duration::from_secs(3_600),
            batch_bytes: 25,
            ..DerivedSettings::default()
        };
        let (writer, flusher) = DerivedWriter::new(Arc::clone(&store), settings);
        let stop = CancellationToken::new();
        let task = tokio::spawn(flusher.run(stop.clone()));
        let before = store.status().revision;
        for key in 0..10 {
            assert!(writer.push(row(key)));
        }
        writer.flush().await;
        assert_eq!(writer.stats().written, 10);
        assert_eq!(
            store.status().revision.0 - before.0,
            5,
            "two changes per store batch"
        );
        stop.cancel();
        task.await.expect("the flusher");
    }

    /// A memory store whose commits take a millisecond, and that counts the proposals in
    /// flight at once.
    struct Slow {
        inner: MemStore,
        now: AtomicU64,
        most: AtomicU64,
    }

    #[async_trait::async_trait]
    impl Store for Slow {
        async fn propose(&self, batch: WriteBatch) -> Result<tenko_store::Committed, StoreError> {
            let now = self.now.fetch_add(1, Ordering::SeqCst) + 1;
            self.most.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(1)).await;
            self.now.fetch_sub(1, Ordering::SeqCst);
            self.inner.propose(batch).await
        }

        async fn read(
            &self,
            consistency: ReadConsistency,
        ) -> Result<Arc<dyn tenko_store::ReadView>, StoreError> {
            self.inner.read(consistency).await
        }

        fn watch(
            &self,
            from: Option<tenko_core::Revision>,
            filter: tenko_store::WatchFilter,
        ) -> Result<tenko_store::ChangeStream, StoreError> {
            self.inner.watch(from, filter)
        }

        fn register_index(
            &self,
            index: Arc<dyn tenko_store::DerivedIndex>,
        ) -> Result<(), StoreError> {
            self.inner.register_index(index)
        }

        fn status(&self) -> tenko_store::StoreStatus {
            self.inner.status()
        }

        fn leadership(&self) -> tokio::sync::watch::Receiver<Option<tenko_store::Leadership>> {
            self.inner.leadership()
        }
    }

    /// Writes `changes` of one row each through a writer over a store whose commits take a
    /// millisecond, two changes per batch; returns the time and the most proposals in
    /// flight at once.
    async fn through_slow_store(changes: u8, in_flight: usize) -> (Duration, u64) {
        let slow = Arc::new(Slow {
            inner: MemStore::new(MemStoreConfig::default()),
            now: AtomicU64::new(0),
            most: AtomicU64::new(0),
        });
        let store: Arc<dyn Store> = slow.clone();
        let settings = DerivedSettings {
            interval: Duration::from_secs(3_600),
            batch_bytes: 25,
            in_flight,
            ..DerivedSettings::default()
        };
        let (writer, flusher) = DerivedWriter::new(store, settings);
        let stop = CancellationToken::new();
        let task = tokio::spawn(flusher.run(stop.clone()));
        for key in 0..changes {
            assert!(writer.push(row(key)));
        }
        let started = std::time::Instant::now();
        writer.flush().await;
        let took = started.elapsed();
        assert_eq!(writer.stats().written, u64::from(changes));
        stop.cancel();
        task.await.expect("the flusher");
        (took, slow.most.load(Ordering::SeqCst))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_flush_proposes_its_batches_at_once_and_outruns_a_sequential_one() {
        let (sequential, alone) = through_slow_store(200, 1).await;
        assert_eq!(alone, 1, "one batch in flight");
        let (concurrent, most) = through_slow_store(200, 32).await;
        assert!(most > 1, "the batches of a flush are in flight together");
        assert!(
            concurrent * 4 < sequential,
            "100 batches took {concurrent:?} at once against {sequential:?} one by one"
        );
    }

    #[tokio::test]
    async fn a_change_of_a_row_in_flight_waits_for_the_next_wave() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new(MemStoreConfig::default()));
        let settings = DerivedSettings {
            interval: Duration::from_secs(3_600),
            batch_bytes: 25,
            ..DerivedSettings::default()
        };
        let (writer, flusher) = DerivedWriter::new(Arc::clone(&store), settings);
        // Six changes, two per batch: the fifth writes the key of the first again.
        for key in [1, 2, 3, 4, 1, 6] {
            writer.push(row(key));
        }
        let first = flusher.take_wave(usize::MAX);
        let sizes: Vec<usize> = first.iter().map(Vec::len).collect();
        assert_eq!(sizes, [2, 2], "the wave ends before the change of key 1");
        let second = flusher.take_wave(usize::MAX);
        assert_eq!(second.iter().map(Vec::len).collect::<Vec<_>>(), [2]);
    }

    #[tokio::test]
    async fn a_full_queue_drops_and_counts_and_raises_the_finding_after_the_tolerance() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new(MemStoreConfig::default()));
        let settings = DerivedSettings {
            queue: 2,
            tolerance: Duration::from_millis(20),
            ..DerivedSettings::default()
        };
        // No flusher runs: the queue fills.
        let (writer, _flusher) = DerivedWriter::new(store, settings);
        assert!(writer.push(row(1)));
        assert!(writer.push(row(2)));
        assert!(
            !writer.push(row(3)),
            "the third change finds the queue full"
        );
        assert_eq!(writer.stats().dropped, 1);
        assert!(writer.finding().is_none(), "not before the tolerance");
        tokio::time::sleep(Duration::from_millis(40)).await;
        let finding = writer.finding().expect("the finding");
        assert_eq!((finding.code, finding.dropped), (FINDING, 1));
    }

    #[tokio::test]
    async fn the_queue_gauge_reads_as_the_count() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new(MemStoreConfig::default()));
        let settings = DerivedSettings {
            queue: 8,
            ..DerivedSettings::default()
        };
        // No flusher runs: the pushed changes stay queued.
        let (writer, _flusher) = DerivedWriter::new(store, settings);
        for i in 1..=3 {
            assert!(writer.push(row(i)));
        }
        assert_eq!(
            QUEUED.get(),
            Some(3.0),
            "the gauge holds the count as a number, not as the bits of one"
        );
    }

    #[tokio::test]
    async fn shutdown_flushes_what_is_queued() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new(MemStoreConfig::default()));
        let settings = DerivedSettings {
            interval: Duration::from_secs(3_600),
            ..DerivedSettings::default()
        };
        let (writer, flusher) = DerivedWriter::new(Arc::clone(&store), settings);
        let stop = CancellationToken::new();
        let task = tokio::spawn(flusher.run(stop.clone()));
        writer.push(row(7));
        stop.cancel();
        task.await.expect("the flusher");
        assert_eq!(writer.stats().written, 1);
    }

    #[tokio::test]
    async fn flush_waits_for_the_changes_pushed_before_it() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new(MemStoreConfig::default()));
        let settings = DerivedSettings {
            interval: Duration::from_secs(3_600),
            ..DerivedSettings::default()
        };
        let (writer, flusher) = DerivedWriter::new(Arc::clone(&store), settings);
        let stop = CancellationToken::new();
        let task = tokio::spawn(flusher.run(stop.clone()));
        writer.push(row(1));
        writer.push(row(2));
        tokio::time::timeout(Duration::from_secs(5), writer.flush())
            .await
            .expect("the flush ends at once, not after the interval");
        assert_eq!(writer.stats().written, 2);
        stop.cancel();
        task.await.expect("the flusher");
    }
}
