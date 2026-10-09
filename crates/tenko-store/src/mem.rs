//! `MemStore`: the in-memory [`Store`] with the full contract semantics.
//!
//! Every Phase 1 package builds and tests against `MemStore` until the Raft store (WP1.1)
//! merges; both pass the same conformance suite (`tenko_store::testing`).
//!
//! Data is kept as multi-version chains per key, so read views are true snapshots at a
//! revision (like redb's MVCC read transactions) and long-running readers such as an index
//! build never block writers. Old versions are pruned once no live view needs them. The
//! journal, audit records, counters and idempotency records live in the same versioned
//! tables as user data (`sys.*`), as they will in the Raft store's state machine.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Arc, Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tenko_core::{
    AuditSeq, CounterKey, Revision, TableName,
    audit::{AuditRecord, ChainHead, Digest},
    codec::{encode_key, from_cbor, to_cbor},
};
use tokio::sync::watch;

use crate::api::{
    Change, ChangeSet, ChangeStream, CoalescerConfig, Committed, DerivedIndex, FailedPrecondition,
    IndexStatus, KeyRange, Mutation, Precondition, ReadConsistency, ReadView, Store, StoreError,
    StoreRole, StoreStatus, Versioned, WatchError, WatchFilter, WriteBatch, tables,
};

/// Configuration of a [`MemStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemStoreConfig {
    /// Change sets kept in the journal for `watch` replay (at least 1).
    pub journal_retention: usize,
    /// How many revisions a live watcher may fall behind before its stream ends with
    /// `WatchError::Lagged`.
    pub watch_max_lag: u64,
    /// How long `ReadConsistency::AtLeast` waits before `StoreError::Timeout`.
    pub read_wait: Duration,
    /// Batch limits; only `max_batch_bytes` applies to `MemStore`.
    pub coalescer: CoalescerConfig,
}

impl Default for MemStoreConfig {
    fn default() -> Self {
        Self {
            journal_retention: 100_000,
            watch_max_lag: 10_000,
            read_wait: Duration::from_secs(5),
            coalescer: CoalescerConfig::default(),
        }
    }
}

/// The in-memory store. Cloning is cheap and shares the store.
#[derive(Clone)]
pub struct MemStore {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for MemStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemStore")
            .field("revision", &self.inner.read_state().revision)
            .finish_non_exhaustive()
    }
}

impl Default for MemStore {
    fn default() -> Self {
        Self::new(MemStoreConfig::default())
    }
}

impl MemStore {
    /// Creates an empty store.
    pub fn new(config: MemStoreConfig) -> Self {
        let (notify, _) = watch::channel(Revision::ZERO);
        Self {
            inner: Arc::new(Inner {
                config,
                state: RwLock::new(State::default()),
                views: Mutex::new(BTreeMap::new()),
                notify,
                shutdown: AtomicBool::new(false),
            }),
        }
    }

    /// Stops the store: proposals and reads fail with `StoreError::ShuttingDown` and watch
    /// streams end.
    pub fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner.notify.send_modify(|_| {});
    }

    /// The configuration.
    pub fn config(&self) -> &MemStoreConfig {
        &self.inner.config
    }
}

const JOURNAL_CHUNK: usize = 256;

/// Versions of one key, oldest first; `None` is a deletion.
type Chain = Vec<(Revision, Option<Bytes>)>;

/// Staged writes of one batch, by table and key; `None` is a deletion.
type Overlay = BTreeMap<(TableName, Bytes), Option<Bytes>>;

struct Inner {
    config: MemStoreConfig,
    state: RwLock<State>,
    /// Revisions of live read views, with counts; versions they can see are kept.
    views: Mutex<BTreeMap<Revision, usize>>,
    /// The last applied revision, for watchers and `AtLeast` readers.
    notify: watch::Sender<Revision>,
    shutdown: AtomicBool,
}

impl Inner {
    fn read_state(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn check_running(&self) -> Result<(), StoreError> {
        if self.shutdown.load(Ordering::SeqCst) {
            Err(StoreError::ShuttingDown)
        } else {
            Ok(())
        }
    }

    /// Registers a view at the current revision.
    fn view(self: &Arc<Self>) -> MemView {
        let state = self.read_state();
        let revision = state.revision;
        *self
            .views
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(revision)
            .or_default() += 1;
        drop(state);
        MemView {
            inner: Arc::clone(self),
            revision,
        }
    }

    /// The oldest revision a live view reads at, or `current` when there is none.
    fn min_live(&self, current: Revision) -> Revision {
        self.views
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .next()
            .copied()
            .unwrap_or(current)
            .min(current)
    }

    fn propose(&self, batch: &WriteBatch) -> Result<Committed, StoreError> {
        self.check_running()?;
        batch.validate(self.config.coalescer.max_batch_bytes)?;
        let idempotency = match &batch.idempotency {
            Some(key) => Some((
                encode_key(&(batch.principal.subject(), key.as_str().to_owned())),
                batch.fingerprint()?,
            )),
            None => None,
        };

        let mut state = self.write_state();

        // 1. Idempotency: a repeated key returns the first commit.
        if let Some((key, fingerprint)) = &idempotency
            && let Some(existing) = state.latest(&tables::IDEMPOTENCY, key)
        {
            let record: IdempotencyRecord = from_cbor(&existing.value)?;
            return if record.fingerprint == *fingerprint {
                Ok(Committed {
                    replayed: true,
                    ..record.committed
                })
            } else {
                Err(StoreError::IdempotencyMismatch)
            };
        }

        // 2. Preconditions, all reported together.
        let failures = state.check_preconditions(&batch.preconditions)?;
        if !failures.is_empty() {
            return Err(StoreError::PreconditionFailed(failures));
        }

        // 3. Stage every write in an overlay; nothing may fail once the commit starts.
        let revision = state.revision.next();
        let mut overlay = state.stage_mutations(&batch.mutations)?;
        let (head, sequence) = state.stage_audit(batch, revision, &mut overlay)?;
        let committed = Committed {
            revision,
            audit: sequence,
            replayed: false,
        };
        if let Some((key, fingerprint)) = idempotency {
            let record = IdempotencyRecord {
                fingerprint,
                committed: committed.clone(),
            };
            overlay.insert((tables::IDEMPOTENCY, key), Some(to_cbor(&record)?));
        }
        let change_set = ChangeSet {
            revision,
            principal: batch.principal.clone(),
            at: batch.proposed_at,
            changes: state.change_list(&overlay),
        };
        let (journal_oldest, journal_len) =
            state.stage_journal(&change_set, self.config.journal_retention, &mut overlay)?;

        // 6. Commit.
        let touched: Vec<(TableName, Bytes)> = overlay.keys().cloned().collect();
        for ((table, key), value) in overlay {
            state.write(table, key, value, revision);
        }
        state.revision = revision;
        state.audit_head = head;
        state.journal_oldest = Some(journal_oldest);
        state.journal_len = journal_len;

        // 7. Derived indexes, in revision order, before the proposer hears back.
        let mut indexes = std::mem::take(&mut state.indexes);
        {
            let view = LockedView {
                state: &state,
                revision,
            };
            for registered in &mut indexes {
                if let Some(filtered) = registered.filter.apply(&change_set) {
                    registered.index.apply(&filtered, &view);
                    registered.revision = revision;
                }
            }
        }
        state.indexes = indexes;

        // 8. Drop versions no view can see any more.
        let min_live = self.min_live(revision);
        state.collect_garbage(min_live, touched);
        drop(state);

        self.notify.send_replace(revision);
        Ok(committed)
    }

    fn register_index(self: &Arc<Self>, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        let filter = index.filter();
        for _attempt in 0..3 {
            // Build aside from a pinned view; writers keep going meanwhile.
            let view = self.view();
            let built_at = view.revision;
            let image = index.build(&view)?;
            let memory_bytes = image.memory_bytes();

            let mut state = self.write_state();
            let current = state.revision;
            let journal_covers = current == built_at
                || state
                    .journal_oldest
                    .is_some_and(|oldest| oldest <= built_at.next());
            if !journal_covers {
                continue;
            }
            index.install(image);
            catch_up(&state, index.as_ref(), &filter, built_at, current)?;
            state.indexes.push(Registered {
                index,
                filter,
                revision: current,
                memory_bytes,
            });
            return Ok(());
        }

        // Writers outpaced the journal three times: build while holding the write lock.
        let mut state = self.write_state();
        let revision = state.revision;
        let image = index.build(&LockedView {
            state: &state,
            revision,
        })?;
        let memory_bytes = image.memory_bytes();
        index.install(image);
        state.indexes.push(Registered {
            index,
            filter,
            revision,
            memory_bytes,
        });
        Ok(())
    }
}

/// Applies the journal entries in `(from, to]` to a freshly installed index.
fn catch_up(
    state: &State,
    index: &dyn DerivedIndex,
    filter: &WatchFilter,
    from: Revision,
    to: Revision,
) -> Result<(), StoreError> {
    let mut cursor = from;
    while cursor < to {
        let range = KeyRange::all().after(tables::JOURNAL.key(&cursor));
        let entries = state.scan(tables::JOURNAL.name(), &range, JOURNAL_CHUNK, false, to);
        if entries.is_empty() {
            return Err(StoreError::Storage(
                "journal ends before the current revision".to_owned(),
            ));
        }
        for (_, versioned) in entries {
            let change_set = tables::JOURNAL.decode(&versioned.value)?;
            if let Some(filtered) = filter.apply(&change_set) {
                index.apply(
                    &filtered,
                    &LockedView {
                        state,
                        revision: change_set.revision,
                    },
                );
            }
            cursor = change_set.revision;
        }
    }
    Ok(())
}

/// Tables whose changes appear in change sets.
fn is_journaled(table: &TableName) -> bool {
    *table != tables::COUNTERS && *table != tables::IDEMPOTENCY && table != tables::JOURNAL.name()
}

fn decode_counter(value: Option<&[u8]>) -> Result<u64, StoreError> {
    match value {
        None => Ok(0),
        Some(bytes) => <[u8; 8]>::try_from(bytes)
            .map(u64::from_be_bytes)
            .map_err(|_| StoreError::Codec("counter value is not eight bytes".to_owned())),
    }
}

#[derive(Serialize, Deserialize)]
struct IdempotencyRecord {
    fingerprint: Digest,
    committed: Committed,
}

struct Registered {
    index: Arc<dyn DerivedIndex>,
    filter: WatchFilter,
    revision: Revision,
    memory_bytes: usize,
}

#[derive(Default)]
struct State {
    revision: Revision,
    tables: BTreeMap<TableName, BTreeMap<Bytes, Chain>>,
    audit_head: ChainHead,
    journal_oldest: Option<Revision>,
    journal_len: u64,
    data_bytes: u64,
    /// Keys holding more than one version: candidates for garbage collection.
    multi_version: BTreeSet<(TableName, Bytes)>,
    /// The oldest live view revision at the last full sweep.
    gc_floor: Revision,
    indexes: Vec<Registered>,
}

/// The version of a chain visible at `at`.
fn visible(chain: &Chain, at: Revision) -> Option<Versioned> {
    chain
        .iter()
        .rev()
        .find(|(revision, _)| *revision <= at)
        .and_then(|(revision, value)| {
            value.as_ref().map(|value| Versioned {
                value: value.clone(),
                revision: *revision,
            })
        })
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

impl State {
    /// Stages the batch's mutations; bumps read earlier staged values of the same counter.
    fn stage_mutations(&self, mutations: &[Mutation]) -> Result<Overlay, StoreError> {
        let mut overlay = Overlay::new();
        for mutation in mutations {
            match mutation {
                Mutation::Put { table, key, value } => {
                    overlay.insert((table.clone(), key.clone()), Some(value.clone()));
                }
                Mutation::Delete { table, key } => {
                    overlay.insert((table.clone(), key.clone()), None);
                }
                Mutation::Bump { counter } => {
                    let key = encode_key(counter);
                    let current = match overlay.get(&(tables::COUNTERS, key.clone())) {
                        Some(value) => decode_counter(value.as_deref())?,
                        None => self.counter(counter)?,
                    };
                    overlay.insert(
                        (tables::COUNTERS, key),
                        Some(Bytes::copy_from_slice(&(current + 1).to_be_bytes())),
                    );
                }
            }
        }
        Ok(overlay)
    }

    /// Seals the batch's audit drafts into chained records and stages them.
    fn stage_audit(
        &self,
        batch: &WriteBatch,
        revision: Revision,
        overlay: &mut Overlay,
    ) -> Result<(ChainHead, Vec<AuditSeq>), StoreError> {
        let mut head = self.audit_head;
        let mut sequence = Vec::with_capacity(batch.audit.len());
        for draft in &batch.audit {
            let seq = head.seq.next();
            let record = AuditRecord::seal(
                seq,
                revision,
                batch.proposed_at,
                batch.principal.clone(),
                batch.request,
                draft.clone(),
                head.hash,
            )?;
            overlay.insert(
                (tables::AUDIT.name().clone(), tables::AUDIT.key(&seq)),
                Some(tables::AUDIT.encode(&record)?),
            );
            head = ChainHead {
                seq,
                hash: record.hash,
            };
            sequence.push(seq);
        }
        Ok((head, sequence))
    }

    /// The changed keys of journaled tables, sorted, once per key; deleting an absent key
    /// is not a change.
    fn change_list(&self, overlay: &Overlay) -> Vec<Change> {
        overlay
            .iter()
            .filter(|((table, _), _)| is_journaled(table))
            .filter_map(|((table, key), value)| {
                let deleted = match value {
                    Some(_) => false,
                    None if self.latest(table, key).is_some() => true,
                    None => return None,
                };
                Some(Change {
                    table: table.clone(),
                    key: key.clone(),
                    deleted,
                })
            })
            .collect()
    }

    /// Stages the journal entry and the removal of entries beyond the retention; returns
    /// the oldest retained revision and the journal length after the commit.
    fn stage_journal(
        &self,
        change_set: &ChangeSet,
        retention: usize,
        overlay: &mut Overlay,
    ) -> Result<(Revision, u64), StoreError> {
        let revision = change_set.revision;
        overlay.insert(
            (
                tables::JOURNAL.name().clone(),
                tables::JOURNAL.key(&revision),
            ),
            Some(tables::JOURNAL.encode(change_set)?),
        );
        let retention = u64::try_from(retention.max(1)).unwrap_or(u64::MAX);
        let mut oldest = self.journal_oldest.unwrap_or(revision);
        let mut len = self.journal_len + 1;
        while len > retention {
            overlay.insert(
                (tables::JOURNAL.name().clone(), tables::JOURNAL.key(&oldest)),
                None,
            );
            oldest = oldest.next();
            len -= 1;
        }
        Ok((oldest, len))
    }

    fn get(&self, table: &TableName, key: &[u8], at: Revision) -> Option<Versioned> {
        self.tables
            .get(table)
            .and_then(|rows| rows.get(key))
            .and_then(|chain| visible(chain, at))
    }

    fn latest(&self, table: &TableName, key: &[u8]) -> Option<Versioned> {
        self.get(table, key, self.revision)
    }

    fn counter(&self, counter: &CounterKey) -> Result<u64, StoreError> {
        let key = encode_key(counter);
        decode_counter(
            self.latest(&tables::COUNTERS, &key)
                .as_ref()
                .map(|versioned| &versioned.value[..]),
        )
    }

    fn counter_at(&self, counter: &CounterKey, at: Revision) -> Result<u64, StoreError> {
        let key = encode_key(counter);
        decode_counter(
            self.get(&tables::COUNTERS, &key, at)
                .as_ref()
                .map(|versioned| &versioned.value[..]),
        )
    }

    fn scan(
        &self,
        table: &TableName,
        range: &KeyRange,
        limit: usize,
        reverse: bool,
        at: Revision,
    ) -> Vec<(Bytes, Versioned)> {
        let Some(rows) = self.tables.get(table) else {
            return Vec::new();
        };
        if limit == 0 || range.is_empty() {
            return Vec::new();
        }
        let bounds = (range.start.clone(), range.end.clone());
        let visible_rows = |(key, chain): (&Bytes, &Chain)| {
            visible(chain, at).map(|versioned| (key.clone(), versioned))
        };
        if reverse {
            rows.range(bounds)
                .rev()
                .filter_map(visible_rows)
                .take(limit)
                .collect()
        } else {
            rows.range(bounds)
                .filter_map(visible_rows)
                .take(limit)
                .collect()
        }
    }

    fn check_preconditions(
        &self,
        preconditions: &[Precondition],
    ) -> Result<Vec<FailedPrecondition>, StoreError> {
        let mut failures = Vec::new();
        for precondition in preconditions {
            match precondition {
                Precondition::Version { table, key, expect } => {
                    let actual = self.latest(table, key).map(|versioned| versioned.revision);
                    if actual != *expect {
                        failures.push(FailedPrecondition::Version {
                            table: table.clone(),
                            key: key.clone(),
                            expected: *expect,
                            actual,
                        });
                    }
                }
                Precondition::Counter { counter, expect } => {
                    let actual = self.counter(counter)?;
                    if actual != *expect {
                        failures.push(FailedPrecondition::Counter {
                            counter: counter.clone(),
                            expected: *expect,
                            actual,
                        });
                    }
                }
            }
        }
        Ok(failures)
    }

    /// Writes one version at `revision` (replacing a version of the same revision).
    fn write(&mut self, table: TableName, key: Bytes, value: Option<Bytes>, revision: Revision) {
        let previous_len = self
            .latest(&table, &key)
            .map_or(0, |versioned| key.len() + versioned.value.len());
        let new_len = value.as_ref().map_or(0, |value| key.len() + value.len());
        let rows = self.tables.entry(table.clone()).or_default();
        let chain = rows.entry(key.clone()).or_default();
        if let Some((last, slot)) = chain.last_mut()
            && *last == revision
        {
            *slot = value;
        } else if !(chain.is_empty() && value.is_none()) {
            chain.push((revision, value));
        }
        if chain.is_empty() {
            rows.remove(&key);
        } else if chain.len() > 1 {
            self.multi_version.insert((table, key));
        }
        self.data_bytes = self
            .data_bytes
            .saturating_sub(len_u64(previous_len))
            .saturating_add(len_u64(new_len));
    }

    /// Drops versions older than the newest one visible at `min_live`, for the touched keys
    /// and, when `min_live` advanced, for every multi-version key.
    fn collect_garbage(&mut self, min_live: Revision, touched: Vec<(TableName, Bytes)>) {
        let candidates: Vec<(TableName, Bytes)> = if min_live > self.gc_floor {
            self.gc_floor = min_live;
            let mut all = touched;
            all.extend(self.multi_version.iter().cloned());
            all
        } else {
            touched
        };
        for (table, key) in candidates {
            let Some(rows) = self.tables.get_mut(&table) else {
                continue;
            };
            let Some(chain) = rows.get_mut(&key) else {
                self.multi_version.remove(&(table, key));
                continue;
            };
            if let Some(keep_from) = chain
                .iter()
                .rposition(|(revision, _)| *revision <= min_live)
            {
                chain.drain(..keep_from);
            }
            let removable = matches!(chain.as_slice(), [(revision, None)] if *revision <= min_live);
            if removable {
                rows.remove(&key);
                self.multi_version.remove(&(table, key));
            } else if chain.len() <= 1 {
                self.multi_version.remove(&(table, key));
            }
        }
    }
}

/// A registered read view of a `MemStore`.
struct MemView {
    inner: Arc<Inner>,
    revision: Revision,
}

impl Drop for MemView {
    fn drop(&mut self) {
        let mut views = self
            .inner
            .views
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = views.get_mut(&self.revision) {
            *count -= 1;
            if *count == 0 {
                views.remove(&self.revision);
            }
        }
    }
}

impl ReadView for MemView {
    fn revision(&self) -> Revision {
        self.revision
    }

    fn get(&self, table: &TableName, key: &[u8]) -> Result<Option<Versioned>, StoreError> {
        Ok(self.inner.read_state().get(table, key, self.revision))
    }

    fn scan(
        &self,
        table: &TableName,
        range: KeyRange,
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Bytes, Versioned)>, StoreError> {
        Ok(self
            .inner
            .read_state()
            .scan(table, &range, limit, reverse, self.revision))
    }

    fn counter(&self, counter: &CounterKey) -> Result<u64, StoreError> {
        self.inner.read_state().counter_at(counter, self.revision)
    }
}

/// A view over state the caller already holds locked (the apply path).
struct LockedView<'a> {
    state: &'a State,
    revision: Revision,
}

impl ReadView for LockedView<'_> {
    fn revision(&self) -> Revision {
        self.revision
    }

    fn get(&self, table: &TableName, key: &[u8]) -> Result<Option<Versioned>, StoreError> {
        Ok(self.state.get(table, key, self.revision))
    }

    fn scan(
        &self,
        table: &TableName,
        range: KeyRange,
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Bytes, Versioned)>, StoreError> {
        Ok(self
            .state
            .scan(table, &range, limit, reverse, self.revision))
    }

    fn counter(&self, counter: &CounterKey) -> Result<u64, StoreError> {
        self.state.counter_at(counter, self.revision)
    }
}

/// State of one watch stream.
struct Watcher {
    inner: Arc<Inner>,
    /// The last revision handed to the consumer (or skipped by the filter).
    cursor: Revision,
    filter: WatchFilter,
    notified: watch::Receiver<Revision>,
    pending: VecDeque<ChangeSet>,
    /// Whether the stream has reached the live revision once; only then does lag count.
    caught_up: bool,
    done: bool,
}

enum Step {
    Wait,
    Loaded(Vec<ChangeSet>, Revision),
    Fail(WatchError),
}

impl Watcher {
    async fn next(&mut self) -> Option<Result<ChangeSet, WatchError>> {
        loop {
            if self.done {
                return None;
            }
            if let Some(change_set) = self.pending.pop_front() {
                return Some(Ok(change_set));
            }
            if self.inner.shutdown.load(Ordering::SeqCst) {
                self.done = true;
                return None;
            }
            // Mark the notification as seen before reading the state, so a commit after
            // the read always wakes the wait below.
            self.notified.borrow_and_update();
            match self.load() {
                Step::Fail(error) => {
                    self.done = true;
                    return Some(Err(error));
                }
                Step::Loaded(change_sets, current) => {
                    for change_set in change_sets {
                        self.cursor = change_set.revision;
                        if let Some(filtered) = self.filter.apply(&change_set) {
                            self.pending.push_back(filtered);
                        }
                    }
                    if self.cursor >= current {
                        self.caught_up = true;
                    }
                }
                Step::Wait => {
                    self.caught_up = true;
                    if self.notified.changed().await.is_err() {
                        self.done = true;
                        return None;
                    }
                }
            }
        }
    }

    fn load(&self) -> Step {
        let state = self.inner.read_state();
        let current = state.revision;
        if current <= self.cursor {
            return Step::Wait;
        }
        if self.caught_up && current.get() - self.cursor.get() > self.inner.config.watch_max_lag {
            return Step::Fail(WatchError::Lagged { last: self.cursor });
        }
        match state.journal_oldest {
            Some(oldest) if oldest <= self.cursor.next() => {}
            oldest => {
                return Step::Fail(WatchError::Compacted {
                    oldest: oldest.unwrap_or(current),
                });
            }
        }
        let range = KeyRange::all().after(tables::JOURNAL.key(&self.cursor));
        let mut change_sets = Vec::new();
        for (_, versioned) in state.scan(
            tables::JOURNAL.name(),
            &range,
            JOURNAL_CHUNK,
            false,
            current,
        ) {
            match tables::JOURNAL.decode(&versioned.value) {
                Ok(change_set) => change_sets.push(change_set),
                // An unreadable journal entry: the consumer must reload, like after a lag.
                Err(_) => return Step::Fail(WatchError::Lagged { last: self.cursor }),
            }
        }
        if change_sets.is_empty() {
            // The journal must hold every revision after the oldest retained one; a hole
            // would make the stream spin, so the consumer reloads instead.
            return Step::Fail(WatchError::Lagged { last: self.cursor });
        }
        Step::Loaded(change_sets, current)
    }
}

#[async_trait::async_trait]
impl Store for MemStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        self.inner.propose(&batch)
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.inner.check_running()?;
        if let ReadConsistency::AtLeast(target) = consistency {
            let mut notified = self.inner.notify.subscribe();
            let reached = async {
                loop {
                    notified.borrow_and_update();
                    if self.inner.read_state().revision >= target {
                        return Ok(());
                    }
                    if notified.changed().await.is_err() {
                        return Err(StoreError::ShuttingDown);
                    }
                    self.inner.check_running()?;
                }
            };
            tokio::time::timeout(self.inner.config.read_wait, reached)
                .await
                .map_err(|_| StoreError::Timeout)??;
        }
        Ok(Arc::new(self.inner.view()))
    }

    fn watch(
        &self,
        from: Option<Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        self.inner.check_running()?;
        let state = self.inner.read_state();
        let current = state.revision;
        let cursor = from.unwrap_or(current);
        if cursor < current {
            match state.journal_oldest {
                Some(oldest) if oldest <= cursor.next() => {}
                oldest => {
                    return Err(StoreError::Compacted {
                        oldest: oldest.unwrap_or(current),
                    });
                }
            }
        }
        drop(state);
        let watcher = Watcher {
            inner: Arc::clone(&self.inner),
            cursor,
            filter,
            notified: self.inner.notify.subscribe(),
            pending: VecDeque::new(),
            caught_up: cursor >= current,
            done: false,
        };
        Ok(Box::pin(futures::stream::unfold(
            watcher,
            |mut watcher| async move { watcher.next().await.map(|item| (item, watcher)) },
        )))
    }

    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        self.inner.check_running()?;
        self.inner.register_index(index)
    }

    fn status(&self) -> StoreStatus {
        let state = self.inner.read_state();
        StoreStatus {
            role: if self.inner.shutdown.load(Ordering::SeqCst) {
                StoreRole::Shutdown
            } else {
                StoreRole::Memory
            },
            node: None,
            leader: None,
            revision: state.revision,
            lag: Some(0),
            audit_head: state.audit_head.seq,
            journal_oldest: state.journal_oldest,
            journal_len: state.journal_len,
            data_bytes: state.data_bytes,
            disk_bytes: None,
            indexes: state
                .indexes
                .iter()
                .map(|registered| IndexStatus {
                    name: registered.index.name().to_owned(),
                    revision: registered.revision,
                    memory_bytes: registered.memory_bytes,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{Principal, SystemComponent, codec::encode_key};

    use super::*;

    const ROWS: TableName = TableName::from_static("ipam.test_rows");

    fn batch() -> WriteBatch {
        WriteBatch::new(
            Principal::system(SystemComponent::Ipam),
            "2026-10-09T12:00:00Z".parse().expect("time"),
        )
    }

    #[tokio::test]
    async fn old_versions_are_collected_once_views_close() {
        let store = MemStore::default();
        let key = encode_key(&1_u64);
        let mut first = batch();
        first.put(ROWS, key.clone(), vec![1]);
        store.propose(first).await.expect("commit");

        let view = store.read(ReadConsistency::Local).await.expect("view");
        for value in 2..5_u8 {
            let mut next = batch();
            next.put(ROWS, key.clone(), vec![value]);
            store.propose(next).await.expect("commit");
        }
        assert_eq!(
            view.get(&ROWS, &key).expect("get").map(|v| v.value),
            Some(Bytes::from_static(&[1]))
        );
        {
            let state = store.inner.read_state();
            assert!(
                state.tables[&ROWS][&key].len() > 1,
                "versions kept for the view"
            );
        }
        drop(view);
        let mut last = batch();
        last.put(ROWS, encode_key(&2_u64), vec![9]);
        store.propose(last).await.expect("commit");
        let state = store.inner.read_state();
        assert_eq!(state.tables[&ROWS][&key].len(), 1, "old versions collected");
        assert!(!state.multi_version.contains(&(ROWS, key)));
    }

    #[tokio::test]
    async fn deleted_keys_disappear_from_memory() {
        let store = MemStore::default();
        let key = encode_key(&7_u64);
        let mut put = batch();
        put.put(ROWS, key.clone(), vec![1]);
        store.propose(put).await.expect("commit");
        let mut delete = batch();
        delete.delete(ROWS, key.clone());
        store.propose(delete).await.expect("commit");
        let state = store.inner.read_state();
        assert!(!state.tables[&ROWS].contains_key(&key));
        assert_eq!(
            state.data_bytes,
            state
                .tables
                .values()
                .flat_map(|rows| rows.iter())
                .filter_map(|(k, chain)| visible(chain, state.revision)
                    .map(|v| len_u64(k.len() + v.value.len())))
                .sum::<u64>()
        );
    }

    #[tokio::test]
    async fn shutdown_stops_proposals_and_watchers() {
        use futures::StreamExt as _;
        let store = MemStore::default();
        let mut stream = store.watch(None, WatchFilter::all()).expect("watch");
        store.shutdown();
        assert_eq!(store.propose(batch()).await, Err(StoreError::ShuttingDown));
        assert!(stream.next().await.is_none());
        assert_eq!(store.status().role, StoreRole::Shutdown);
    }
}
