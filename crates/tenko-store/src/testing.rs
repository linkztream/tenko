//! The store conformance suite (feature `testing`).
//!
//! Every [`Store`] implementation must pass the same tests: `MemStore` here, the Raft store
//! of WP1.1 unchanged. A test file runs the whole suite with one macro call and a factory
//! that builds a fresh, empty store from a [`ConformanceConfig`]:
//!
//! ```ignore
//! use tenko_store::{mem::MemStore, testing::ConformanceConfig};
//!
//! tenko_store::conformance_tests!(|config: ConformanceConfig| async move {
//!     MemStore::new(config.mem_store_config())
//! });
//! ```
//!
//! A store that writes files keeps them under `std::env::temp_dir()` (never under the
//! repository) and maps the configuration hints onto its own settings. Each test also
//! exists as a public async function in [`conformance`], so an implementation can run a
//! single test with its own runtime.

use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use arc_swap::ArcSwap;
use bytes::Bytes;
use futures::future::BoxFuture;
use tenko_core::{Revision, TableName};

use crate::{
    api::{
        ChangeSet, DerivedIndex, IndexImage, KeyRange, ReadView, Store, StoreError, WatchFilter,
        downcast_image,
    },
    mem::MemStoreConfig,
};

/// Settings a store under test should honour. Each test states which ones it relies on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceConfig {
    /// Change sets the journal retains, at least. Compaction tests use small values.
    pub journal_retention: usize,
    /// Revisions a live watcher may fall behind before its stream ends with `Lagged`.
    pub watch_max_lag: u64,
    /// Payload limit of one batch.
    pub max_batch_bytes: usize,
    /// How long `ReadConsistency::AtLeast` waits.
    pub read_wait: Duration,
}

impl Default for ConformanceConfig {
    fn default() -> Self {
        Self {
            journal_retention: 100_000,
            watch_max_lag: 100_000,
            max_batch_bytes: 16 * 1024 * 1024,
            read_wait: Duration::from_secs(5),
        }
    }
}

impl ConformanceConfig {
    /// The matching `MemStore` configuration.
    pub fn mem_store_config(&self) -> MemStoreConfig {
        let mut config = MemStoreConfig {
            journal_retention: self.journal_retention,
            watch_max_lag: self.watch_max_lag,
            read_wait: self.read_wait,
            ..MemStoreConfig::default()
        };
        config.coalescer.max_batch_bytes = self.max_batch_bytes;
        config
    }
}

/// Creates fresh, empty stores for the suite.
pub trait StoreFactory: Send + Sync {
    /// The store type.
    type Store: Store;

    /// Builds an empty store honouring `config`.
    fn create(&self, config: ConformanceConfig) -> BoxFuture<'_, Self::Store>;
}

impl<F, Fut, S> StoreFactory for F
where
    F: Fn(ConformanceConfig) -> Fut + Send + Sync,
    Fut: Future<Output = S> + Send + 'static,
    S: Store,
{
    type Store = S;

    fn create(&self, config: ConformanceConfig) -> BoxFuture<'_, S> {
        Box::pin(self(config))
    }
}

/// Runs a future on a fresh multi-threaded Tokio runtime (used by the generated tests).
///
/// # Panics
///
/// Panics if the runtime cannot be built.
pub fn run<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("build a Tokio runtime")
        .block_on(future)
}

/// Generates one `#[test]` per conformance test for a store factory expression.
///
/// The expression is evaluated once per test and must implement
/// [`StoreFactory`](crate::testing::StoreFactory), for example a closure
/// `|config: ConformanceConfig| async move { ... }`.
#[macro_export]
macro_rules! conformance_tests {
    ($factory:expr) => {
        $crate::__conformance_tests!(
            $factory;
            empty_store,
            batch_is_atomic_with_one_revision,
            revisions_increase_by_one,
            views_are_snapshots,
            failed_batch_changes_nothing,
            version_preconditions,
            counter_preconditions,
            idempotent_replay,
            idempotency_is_scoped_per_principal,
            audit_chain_is_continuous_and_verifies,
            audit_only_batches_are_recorded,
            scan_ranges_and_order,
            deletes_and_tombstones,
            validation_rejects_bad_batches,
            watch_follows_live_commits,
            watch_replays_from_revision,
            watch_filters_changes,
            watch_rejects_compacted_revisions,
            watch_reports_compaction_in_stream,
            watch_reports_lag,
            read_consistency,
            derived_index_build_install_apply,
            derived_index_registered_under_load,
            concurrent_proposers,
            concurrent_counter_increments_with_retry,
            status_reports_fields,
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_tests {
    ($factory:expr; $($name:ident),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                $crate::testing::run(async {
                    let factory = $factory;
                    $crate::testing::conformance::$name(&factory).await;
                });
            }
        )+
    };
}

/// A derived index for the suite: a copy of one table, installed through an `ArcSwap`,
/// that records the revisions it was applied at.
pub struct RecordingIndex {
    table: TableName,
    live: ArcSwap<RecordingImage>,
    applied: Mutex<Vec<Revision>>,
}

/// The image of a [`RecordingIndex`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordingImage {
    /// The revision the image reflects.
    pub revision: Revision,
    /// Key to value.
    pub rows: BTreeMap<Bytes, Bytes>,
}

impl IndexImage for RecordingImage {
    fn revision(&self) -> Revision {
        self.revision
    }

    fn memory_bytes(&self) -> usize {
        self.rows.iter().map(|(k, v)| k.len() + v.len()).sum()
    }
}

impl RecordingIndex {
    /// An index over `table`.
    pub fn new(table: TableName) -> Self {
        Self {
            table,
            live: ArcSwap::from_pointee(RecordingImage::default()),
            applied: Mutex::new(Vec::new()),
        }
    }

    /// The live image.
    pub fn image(&self) -> Arc<RecordingImage> {
        self.live.load_full()
    }

    /// Revisions passed to `apply`, in call order.
    pub fn applied(&self) -> Vec<Revision> {
        self.applied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl DerivedIndex for RecordingIndex {
    fn name(&self) -> &'static str {
        "conformance.recording"
    }

    fn filter(&self) -> WatchFilter {
        WatchFilter::tables([self.table.clone()])
    }

    fn build(&self, view: &dyn ReadView) -> Result<Box<dyn IndexImage>, StoreError> {
        let mut rows = BTreeMap::new();
        let mut range = KeyRange::all();
        loop {
            let page = view.scan(&self.table, range.clone(), 512, false)?;
            let Some((last, _)) = page.last() else {
                break;
            };
            range = KeyRange::all().after(last.clone());
            rows.extend(
                page.into_iter()
                    .map(|(key, versioned)| (key, versioned.value)),
            );
        }
        Ok(Box::new(RecordingImage {
            revision: view.revision(),
            rows,
        }))
    }

    fn install(&self, image: Box<dyn IndexImage>) {
        let image = downcast_image::<RecordingImage>(image).expect("a RecordingImage");
        self.live.store(Arc::from(image));
    }

    fn apply(&self, changes: &ChangeSet, view: &dyn ReadView) {
        let mut next = RecordingImage::clone(&self.live.load());
        for change in changes
            .changes
            .iter()
            .filter(|change| change.table == self.table)
        {
            let value = view
                .get(&self.table, &change.key)
                .expect("read the changed value");
            match value {
                Some(versioned) if !change.deleted => {
                    next.rows.insert(change.key.clone(), versioned.value);
                }
                _ => {
                    next.rows.remove(&change.key);
                }
            }
        }
        next.revision = changes.revision;
        self.live.store(Arc::new(next));
        self.applied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(changes.revision);
    }
}

/// The conformance tests. Each takes a factory and panics on a violation; that is the
/// purpose of every function here, so their docs carry no `# Panics` sections.
#[allow(clippy::missing_panics_doc)]
pub mod conformance {
    use std::{collections::BTreeSet, sync::Arc, time::Duration};

    use bytes::Bytes;
    use futures::StreamExt as _;
    use tenko_core::{
        AuditSeq, CounterKey, IdempotencyKey, Principal, RequestId, Revision, SessionId,
        SystemComponent, TableName, Timestamp, UserId,
        audit::{AuditAction, AuditDraft, verify_chain},
        codec::encode_key,
        principal::AuthStrength,
        secret::VaultEnvelope,
    };

    use super::{ConformanceConfig, RecordingIndex, StoreFactory};
    use crate::api::{
        Change, ChangeSet, ChangeStream, Committed, FailedPrecondition, KeyRange, ReadConsistency,
        ReadView, ReadViewExt as _, Store, StoreError, WatchError, WatchFilter, WriteBatch, tables,
    };

    const ROWS: TableName = TableName::from_static("ipam.conformance_rows");
    const OTHER: TableName = TableName::from_static("jobs.conformance_rows");
    const SECRETS: TableName = TableName::from_static("vault.conformance_secrets");
    const COUNTER: CounterKey = CounterKey::new("ipam.conformance_counter");
    const CREATE: AuditAction = AuditAction::from_static("ipam.conformance.create");
    const DENIED: AuditAction = AuditAction::from_static("auth.conformance.denied");
    const WAIT: Duration = Duration::from_secs(10);

    fn principal() -> Principal {
        Principal::system(SystemComponent::Ipam)
    }

    fn user() -> Principal {
        Principal::User {
            id: UserId::generate(),
            session: SessionId::generate(),
            strength: AuthStrength::Passkey,
        }
    }

    fn at(second: u64) -> Timestamp {
        Timestamp::from_unix_nanos(1_791_547_200_000_000_000 + i128::from(second) * 1_000_000_000)
            .expect("timestamp in range")
    }

    fn batch() -> WriteBatch {
        WriteBatch::new(principal(), at(0))
    }

    fn key(n: u64) -> Bytes {
        encode_key(&n)
    }

    fn value(text: &str) -> Bytes {
        Bytes::copy_from_slice(text.as_bytes())
    }

    async fn store<F: StoreFactory>(factory: &F, config: ConformanceConfig) -> Arc<F::Store> {
        Arc::new(factory.create(config).await)
    }

    async fn fresh<F: StoreFactory>(factory: &F) -> Arc<F::Store> {
        store(factory, ConformanceConfig::default()).await
    }

    async fn view<S: Store + ?Sized>(store: &S) -> Arc<dyn ReadView> {
        store.read(ReadConsistency::Local).await.expect("read view")
    }

    async fn put<S: Store + ?Sized>(store: &S, table: &TableName, k: u64, v: &str) -> Committed {
        let mut b = batch();
        b.put(table.clone(), key(k), value(v));
        store.propose(b).await.expect("commit a put")
    }

    fn get(view: &dyn ReadView, table: &TableName, k: u64) -> Option<(Bytes, Revision)> {
        view.get(table, &key(k))
            .expect("get")
            .map(|versioned| (versioned.value, versioned.revision))
    }

    async fn next(stream: &mut ChangeStream) -> Option<Result<ChangeSet, WatchError>> {
        tokio::time::timeout(WAIT, stream.next())
            .await
            .expect("the watch stream answers within the timeout")
    }

    async fn next_ok(stream: &mut ChangeStream) -> ChangeSet {
        next(stream)
            .await
            .expect("the stream continues")
            .expect("a change set, not an error")
    }

    /// An empty store is at revision 0 with no audit records, data or counters.
    pub async fn empty_store<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let status = store.status();
        assert_eq!(status.revision, Revision::ZERO);
        assert_eq!(status.audit_head, AuditSeq::NONE);
        let view = view(store.as_ref()).await;
        assert_eq!(view.revision(), Revision::ZERO);
        assert_eq!(get(view.as_ref(), &ROWS, 1), None);
        assert_eq!(view.counter(&COUNTER).expect("counter"), 0);
        assert_eq!(
            view.scan(&ROWS, KeyRange::all(), 10, false)
                .expect("scan")
                .len(),
            0
        );
    }

    /// Every mutation of a batch applies together, under one new revision.
    pub async fn batch_is_atomic_with_one_revision<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let mut seed = batch();
        seed.put(ROWS, key(1), value("a"))
            .put(ROWS, key(2), value("b"));
        assert_eq!(
            store.propose(seed).await.expect("seed").revision,
            Revision(1)
        );

        let mut b = batch();
        b.put(ROWS, key(1), value("a2"))
            .put(ROWS, key(3), value("c"))
            .delete(ROWS, key(2))
            .bump(COUNTER)
            .put(OTHER, key(1), value("x"));
        let committed = store.propose(b).await.expect("commit");
        assert_eq!(
            committed,
            Committed {
                revision: Revision(2),
                audit: vec![],
                replayed: false
            }
        );
        let view = view(store.as_ref()).await;
        assert_eq!(view.revision(), Revision(2));
        assert_eq!(
            get(view.as_ref(), &ROWS, 1),
            Some((value("a2"), Revision(2)))
        );
        assert_eq!(get(view.as_ref(), &ROWS, 2), None);
        assert_eq!(
            get(view.as_ref(), &ROWS, 3),
            Some((value("c"), Revision(2)))
        );
        assert_eq!(
            get(view.as_ref(), &OTHER, 1),
            Some((value("x"), Revision(2)))
        );
        assert_eq!(view.counter(&COUNTER).expect("counter"), 1);
    }

    /// Each applied batch increments the revision by exactly one, and values carry the
    /// revision that wrote them.
    pub async fn revisions_increase_by_one<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        for n in 1..=10 {
            let committed = put(store.as_ref(), &ROWS, n, "v").await;
            assert_eq!(committed.revision, Revision(n));
            let view = store
                .read(ReadConsistency::AtLeast(committed.revision))
                .await
                .expect("read your write");
            assert_eq!(
                get(view.as_ref(), &ROWS, n),
                Some((value("v"), Revision(n)))
            );
        }
        assert_eq!(store.status().revision, Revision(10));
    }

    /// A view keeps reading the revision it was opened at while writes continue.
    pub async fn views_are_snapshots<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let mut b = batch();
        b.put(ROWS, key(1), value("old")).bump(COUNTER);
        store.propose(b).await.expect("commit");
        let old = view(store.as_ref()).await;

        let mut b = batch();
        b.put(ROWS, key(1), value("new"))
            .put(ROWS, key(2), value("added"))
            .bump(COUNTER);
        store.propose(b).await.expect("commit");
        let mut b = batch();
        b.delete(ROWS, key(1));
        store.propose(b).await.expect("commit");

        assert_eq!(old.revision(), Revision(1));
        assert_eq!(
            get(old.as_ref(), &ROWS, 1),
            Some((value("old"), Revision(1)))
        );
        assert_eq!(get(old.as_ref(), &ROWS, 2), None);
        assert_eq!(old.counter(&COUNTER).expect("counter"), 1);
        assert_eq!(
            old.scan(&ROWS, KeyRange::all(), 10, false)
                .expect("scan")
                .len(),
            1
        );

        let new = view(store.as_ref()).await;
        assert_eq!(new.revision(), Revision(3));
        assert_eq!(get(new.as_ref(), &ROWS, 1), None);
        assert_eq!(
            get(new.as_ref(), &ROWS, 2),
            Some((value("added"), Revision(2)))
        );
        assert_eq!(new.counter(&COUNTER).expect("counter"), 2);
    }

    /// A rejected batch applies nothing and consumes no revision and no audit number.
    pub async fn failed_batch_changes_nothing<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        put(store.as_ref(), &ROWS, 1, "a").await;
        let mut watch = store.watch(None, WatchFilter::all()).expect("watch");

        let mut b = batch();
        b.put(ROWS, key(1), value("changed"))
            .put(ROWS, key(2), value("new"))
            .bump(COUNTER)
            .audit(AuditDraft::success(CREATE, vec![]))
            .expect_version(ROWS, key(1), Some(Revision(99)));
        let error = store.propose(b).await.expect_err("precondition fails");
        assert_eq!(
            error,
            StoreError::PreconditionFailed(vec![FailedPrecondition::Version {
                table: ROWS,
                key: key(1),
                expected: Some(Revision(99)),
                actual: Some(Revision(1)),
            }])
        );
        let status = store.status();
        assert_eq!(status.revision, Revision(1));
        assert_eq!(status.audit_head, AuditSeq::NONE);
        let view = view(store.as_ref()).await;
        assert_eq!(
            get(view.as_ref(), &ROWS, 1),
            Some((value("a"), Revision(1)))
        );
        assert_eq!(get(view.as_ref(), &ROWS, 2), None);
        assert_eq!(view.counter(&COUNTER).expect("counter"), 0);

        let mut b = batch();
        b.put(ROWS, key(3), value("c"))
            .audit(AuditDraft::success(CREATE, vec![]));
        let committed = store.propose(b).await.expect("commit");
        assert_eq!(committed.revision, Revision(2));
        assert_eq!(committed.audit, vec![AuditSeq(1)]);
        assert_eq!(
            next_ok(&mut watch).await.revision,
            Revision(2),
            "no change set for the failed batch"
        );
    }

    /// Version preconditions compare the revision of the current value; `None` means
    /// absent. All failures are reported, in batch order.
    pub async fn version_preconditions<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let mut b = batch();
        b.expect_version(ROWS, key(1), None)
            .put(ROWS, key(1), value("v1"));
        assert_eq!(
            store.propose(b).await.expect("absent key").revision,
            Revision(1)
        );

        let mut b = batch();
        b.expect_version(ROWS, key(1), None)
            .put(ROWS, key(1), value("dup"));
        assert_eq!(
            store.propose(b).await,
            Err(StoreError::PreconditionFailed(vec![
                FailedPrecondition::Version {
                    table: ROWS,
                    key: key(1),
                    expected: None,
                    actual: Some(Revision(1)),
                }
            ]))
        );

        let mut b = batch();
        b.expect_version(ROWS, key(1), Some(Revision(1)))
            .put(ROWS, key(1), value("v2"));
        assert_eq!(
            store.propose(b).await.expect("matching revision").revision,
            Revision(2)
        );

        let mut b = batch();
        b.expect_version(ROWS, key(1), Some(Revision(1)))
            .put(ROWS, key(1), value("stale"));
        assert!(matches!(
            store.propose(b).await,
            Err(StoreError::PreconditionFailed(failures))
                if failures == vec![FailedPrecondition::Version {
                    table: ROWS, key: key(1), expected: Some(Revision(1)), actual: Some(Revision(2)),
                }]
        ));

        let mut b = batch();
        b.expect_version(ROWS, key(1), Some(Revision(2)))
            .delete(ROWS, key(1));
        assert_eq!(
            store.propose(b).await.expect("delete").revision,
            Revision(3)
        );
        let mut b = batch();
        b.expect_version(ROWS, key(1), None)
            .put(ROWS, key(1), value("again"));
        assert_eq!(
            store
                .propose(b)
                .await
                .expect("absent after delete")
                .revision,
            Revision(4)
        );

        let mut b = batch();
        b.expect_version(ROWS, key(9), Some(Revision(1)))
            .expect_version(OTHER, key(1), None)
            .expect_version(ROWS, key(1), None);
        let Err(StoreError::PreconditionFailed(failures)) = store.propose(b).await else {
            panic!("two preconditions fail");
        };
        assert_eq!(
            failures,
            vec![
                FailedPrecondition::Version {
                    table: ROWS,
                    key: key(9),
                    expected: Some(Revision(1)),
                    actual: None,
                },
                FailedPrecondition::Version {
                    table: ROWS,
                    key: key(1),
                    expected: None,
                    actual: Some(Revision(4)),
                },
            ]
        );
    }

    /// Counter preconditions compare the counter value; bumps add one each, also twice in
    /// one batch; qualified counters are independent.
    pub async fn counter_preconditions<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let mut b = batch();
        b.expect_counter(COUNTER, 0).bump(COUNTER);
        store.propose(b).await.expect("counter starts at 0");

        let mut b = batch();
        b.expect_counter(COUNTER, 0).bump(COUNTER);
        assert_eq!(
            store.propose(b).await,
            Err(StoreError::PreconditionFailed(vec![
                FailedPrecondition::Counter {
                    counter: COUNTER,
                    expected: 0,
                    actual: 1,
                }
            ]))
        );

        let mut b = batch();
        b.expect_counter(COUNTER, 1).bump(COUNTER).bump(COUNTER);
        store.propose(b).await.expect("two bumps");
        let one = CounterKey::with("ipam.conformance_counter", &1_u64);
        let two = CounterKey::with("ipam.conformance_counter", &2_u64);
        let mut b = batch();
        b.bump(one.clone()).expect_counter(two.clone(), 0);
        store.propose(b).await.expect("qualified counters");

        let view = view(store.as_ref()).await;
        assert_eq!(view.counter(&COUNTER).expect("counter"), 3);
        assert_eq!(view.counter(&one).expect("counter"), 1);
        assert_eq!(view.counter(&two).expect("counter"), 0);
    }

    /// The same batch under the same idempotency key commits once; a different batch under
    /// that key is rejected; failed batches do not consume their key.
    pub async fn idempotent_replay<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let mut first = batch();
        first.idempotency = Some(IdempotencyKey::new("conformance-1").expect("key"));
        first.request = Some(RequestId::generate());
        first
            .put(ROWS, key(1), value("once"))
            .audit(AuditDraft::success(CREATE, vec![]));
        let committed = store.propose(first.clone()).await.expect("commit");
        assert_eq!(committed.revision, Revision(1));
        assert_eq!(committed.audit, vec![AuditSeq(1)]);
        assert!(!committed.replayed);

        let mut retry = first.clone();
        retry.proposed_at = at(30);
        retry.request = Some(RequestId::generate());
        let replay = store.propose(retry).await.expect("replay");
        assert_eq!(
            replay,
            Committed {
                replayed: true,
                ..committed.clone()
            }
        );
        let status = store.status();
        assert_eq!(status.revision, Revision(1), "a replay applies nothing");
        assert_eq!(status.audit_head, AuditSeq(1));

        let mut different = first.clone();
        different.mutations.clear();
        different.put(ROWS, key(2), value("other"));
        assert_eq!(
            store.propose(different).await,
            Err(StoreError::IdempotencyMismatch)
        );

        let mut failing = batch();
        failing.idempotency = Some(IdempotencyKey::new("conformance-2").expect("key"));
        failing
            .expect_version(ROWS, key(1), None)
            .put(ROWS, key(3), value("x"));
        assert!(matches!(
            store.propose(failing.clone()).await,
            Err(StoreError::PreconditionFailed(_))
        ));
        failing.preconditions.clear();
        assert_eq!(
            store
                .propose(failing)
                .await
                .expect("key not consumed")
                .revision,
            Revision(2)
        );
    }

    /// Idempotency keys are scoped per principal subject.
    pub async fn idempotency_is_scoped_per_principal<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let key_text = IdempotencyKey::new("shared-key").expect("key");
        for (n, principal) in [user(), user()].into_iter().enumerate() {
            let mut b = WriteBatch::new(principal, at(0));
            b.idempotency = Some(key_text.clone());
            b.put(ROWS, key(n as u64), value("v"));
            let committed = store.propose(b).await.expect("independent commit");
            assert!(!committed.replayed);
        }
        assert_eq!(store.status().revision, Revision(2));
    }

    /// Audit drafts become a gap-free chain from 1, sealed at apply with the batch's
    /// principal, request, time and revision, readable from `sys.audit`, and verifiable.
    pub async fn audit_chain_is_continuous_and_verifies<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let mut expected = Vec::new();
        let mut next_seq = 1;
        for (n, drafts) in [1_u64, 0, 3, 2, 1].into_iter().enumerate() {
            let mut b = WriteBatch::new(user(), at(n as u64));
            b.request = Some(RequestId::generate());
            b.put(ROWS, key(n as u64), value("v"));
            for d in 0..drafts {
                b.audit(
                    AuditDraft::success(CREATE, vec![])
                        .with_context("draft", d.to_string())
                        .with_source_ip(Some("192.0.2.33".parse().expect("ip"))),
                );
            }
            let committed = store.propose(b.clone()).await.expect("commit");
            let seqs: Vec<AuditSeq> = (next_seq..next_seq + drafts).map(AuditSeq).collect();
            assert_eq!(committed.audit, seqs, "consecutive sequence numbers");
            next_seq += drafts;
            for (seq, draft) in seqs.into_iter().zip(b.audit.clone()) {
                expected.push((seq, committed.revision, b.clone(), draft));
            }
        }
        let view = view(store.as_ref()).await;
        let records: Vec<_> = view
            .scan_typed(&tables::AUDIT, KeyRange::all(), 100, false)
            .expect("scan the audit table")
            .into_iter()
            .map(|(seq, record, _)| {
                assert_eq!(seq, record.seq);
                record
            })
            .collect();
        assert_eq!(records.len(), expected.len());
        let head = verify_chain(&records).expect("the chain verifies");
        assert_eq!(head.seq, AuditSeq(7));
        assert_eq!(store.status().audit_head, AuditSeq(7));
        for (record, (seq, revision, b, draft)) in records.iter().zip(&expected) {
            assert_eq!(record.seq, *seq);
            assert_eq!(record.revision, *revision);
            assert_eq!(record.at, b.proposed_at);
            assert_eq!(record.principal, b.principal);
            assert_eq!(record.request, b.request);
            assert_eq!(&record.draft, draft);
        }
        let (single, _) = view
            .get_typed(&tables::AUDIT, &AuditSeq(3))
            .expect("get")
            .expect("record 3 exists");
        assert_eq!(single, records[2]);
    }

    /// A batch with only audit drafts (a denied action) commits a revision and appears in
    /// the journal as new `sys.audit` rows.
    pub async fn audit_only_batches_are_recorded<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let mut watch = store.watch(None, WatchFilter::all()).expect("watch");
        let mut b = WriteBatch::new(user(), at(5));
        b.audit(AuditDraft::denied(DENIED, vec![]));
        let committed = store.propose(b).await.expect("commit");
        assert_eq!(committed.revision, Revision(1));
        assert_eq!(committed.audit, vec![AuditSeq(1)]);
        let change_set = next_ok(&mut watch).await;
        assert_eq!(
            change_set.changes,
            vec![Change {
                table: tables::AUDIT.name().clone(),
                key: tables::AUDIT.key(&AuditSeq(1)),
                deleted: false,
            }]
        );
    }

    /// Scans honour ranges, prefixes, limits, direction and pagination, and skip deleted
    /// keys.
    pub async fn scan_ranges_and_order<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let mut b = batch();
        for n in 1..=20_u64 {
            b.put(ROWS, key(n), value(&n.to_string()));
            b.put(
                OTHER,
                encode_key(&(u8::try_from(n % 3).expect("small"), n)),
                value("g"),
            );
        }
        store.propose(b).await.expect("commit");
        let mut b = batch();
        b.delete(ROWS, key(5));
        store.propose(b).await.expect("commit");

        let view = view(store.as_ref()).await;
        let keys = |rows: Vec<(Bytes, crate::api::Versioned)>| -> Vec<Bytes> {
            rows.into_iter().map(|(k, _)| k).collect()
        };
        let all = keys(view.scan(&ROWS, KeyRange::all(), 100, false).expect("scan"));
        assert_eq!(all.len(), 19);
        assert!(all.windows(2).all(|w| w[0] < w[1]), "ascending");
        assert!(!all.contains(&key(5)), "deleted keys are skipped");
        let reverse = keys(view.scan(&ROWS, KeyRange::all(), 3, true).expect("scan"));
        assert_eq!(reverse, vec![key(20), key(19), key(18)]);
        let between = keys(
            view.scan(&ROWS, KeyRange::between(key(3), key(8)), 100, false)
                .expect("scan"),
        );
        assert_eq!(between, vec![key(3), key(4), key(6), key(7)]);
        let page = keys(
            view.scan(&ROWS, KeyRange::all().after(key(17)), 100, false)
                .expect("scan"),
        );
        assert_eq!(page, vec![key(18), key(19), key(20)]);
        let back = keys(
            view.scan(&ROWS, KeyRange::all().before(key(3)), 100, true)
                .expect("scan"),
        );
        assert_eq!(back, vec![key(2), key(1)]);
        let group = view
            .scan(&OTHER, KeyRange::prefix(encode_key(&(1_u8,))), 100, false)
            .expect("scan");
        assert_eq!(group.len(), 7, "n % 3 == 1 for 1, 4, ..., 19");
        assert_eq!(
            view.scan(&ROWS, KeyRange::all(), 0, false)
                .expect("scan")
                .len(),
            0
        );
        assert_eq!(
            view.scan(&ROWS, KeyRange::between(key(8), key(3)), 10, false)
                .expect("scan")
                .len(),
            0
        );
        assert_eq!(
            view.scan(
                &TableName::from_static("ipam.conformance_missing"),
                KeyRange::all(),
                10,
                false
            )
            .expect("scan")
            .len(),
            0
        );
    }

    /// Deletes remove values, deleting an absent key changes nothing, and a re-created key
    /// carries its new revision.
    pub async fn deletes_and_tombstones<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        put(store.as_ref(), &ROWS, 1, "v").await;
        let mut watch = store.watch(None, WatchFilter::all()).expect("watch");
        let mut b = batch();
        b.delete(ROWS, key(1)).delete(ROWS, key(2));
        assert_eq!(
            store.propose(b).await.expect("delete").revision,
            Revision(2)
        );
        let change_set = next_ok(&mut watch).await;
        assert_eq!(
            change_set.changes,
            vec![Change {
                table: ROWS,
                key: key(1),
                deleted: true
            }],
            "deleting an absent key is not a change"
        );
        assert_eq!(get(view(store.as_ref()).await.as_ref(), &ROWS, 1), None);
        let committed = put(store.as_ref(), &ROWS, 1, "again").await;
        assert_eq!(
            get(view(store.as_ref()).await.as_ref(), &ROWS, 1),
            Some((value("again"), committed.revision))
        );
        let mut b = batch();
        b.put(ROWS, key(7), value("short-lived"))
            .delete(ROWS, key(7));
        store.propose(b).await.expect("put then delete");
        assert_eq!(
            get(view(store.as_ref()).await.as_ref(), &ROWS, 7),
            None,
            "the last mutation wins"
        );
    }

    /// Validation rejects writes to reserved tables, plaintext in secret-bearing tables and
    /// oversized batches, before anything applies.
    pub async fn validation_rejects_bad_batches<F: StoreFactory>(factory: &F) {
        let config = ConformanceConfig {
            max_batch_bytes: 4096,
            ..ConformanceConfig::default()
        };
        let store = store(factory, config).await;
        for table in [
            tables::AUDIT.name().clone(),
            tables::JOURNAL.name().clone(),
            tables::COUNTERS,
            tables::IDEMPOTENCY,
        ] {
            let mut b = batch();
            b.put(table.clone(), key(1), value("forged"));
            assert_eq!(
                store.propose(b).await,
                Err(StoreError::ReservedTable { table })
            );
        }
        let mut b = batch();
        b.put(SECRETS, key(1), value("JBSWY3DPEHPK3PXP"));
        assert_eq!(
            store.propose(b).await,
            Err(StoreError::PlaintextSecret { table: SECRETS })
        );
        let mut b = batch();
        b.put(ROWS, key(1), vec![0_u8; 8192]);
        assert!(matches!(
            store.propose(b).await,
            Err(StoreError::BatchTooLarge { limit: 4096, .. })
        ));
        assert_eq!(store.status().revision, Revision::ZERO);

        let envelope = VaultEnvelope {
            format: 1,
            key_id: "kek-test".to_owned(),
            payload: Bytes::from_static(b"sealed"),
        }
        .to_bytes()
        .expect("envelope");
        let mut b = batch();
        b.put(SECRETS, key(1), envelope);
        assert_eq!(
            store.propose(b).await.expect("envelope accepted").revision,
            Revision(1)
        );
    }

    /// A watcher from the current revision receives every later change set in order, with
    /// principal, time and the changed keys sorted by table and key.
    pub async fn watch_follows_live_commits<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let mut watch = store.watch(None, WatchFilter::all()).expect("watch");
        let writer = user();
        for n in 1..=3_u64 {
            let mut b = WriteBatch::new(writer.clone(), at(n));
            b.put(ROWS, key(10 - n), value("v"))
                .put(OTHER, key(n), value("w"));
            if n == 3 {
                b.delete(ROWS, key(9));
            }
            store.propose(b).await.expect("commit");
        }
        for n in 1..=3_u64 {
            let change_set = next_ok(&mut watch).await;
            assert_eq!(change_set.revision, Revision(n));
            assert_eq!(change_set.principal, writer);
            assert_eq!(change_set.at, at(n));
            let mut expected = vec![
                Change {
                    table: ROWS,
                    key: key(10 - n),
                    deleted: false,
                },
                Change {
                    table: OTHER,
                    key: key(n),
                    deleted: false,
                },
            ];
            if n == 3 {
                expected.push(Change {
                    table: ROWS,
                    key: key(9),
                    deleted: true,
                });
            }
            expected.sort_by(|a, b| (&a.table, &a.key).cmp(&(&b.table, &b.key)));
            assert_eq!(change_set.changes, expected);
        }
    }

    /// `watch(Some(r))` replays every change set after `r` from the journal, then follows
    /// live commits.
    pub async fn watch_replays_from_revision<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        for n in 1..=5 {
            put(store.as_ref(), &ROWS, n, "v").await;
        }
        let mut watch = store
            .watch(Some(Revision(2)), WatchFilter::all())
            .expect("watch");
        for n in 3..=5 {
            assert_eq!(next_ok(&mut watch).await.revision, Revision(n));
        }
        put(store.as_ref(), &ROWS, 6, "v").await;
        assert_eq!(next_ok(&mut watch).await.revision, Revision(6));

        let mut caught_up = store
            .watch(Some(Revision(6)), WatchFilter::all())
            .expect("watch");
        put(store.as_ref(), &ROWS, 7, "v").await;
        assert_eq!(next_ok(&mut caught_up).await.revision, Revision(7));
    }

    /// Filters pass only matching changes and skip change sets with none.
    pub async fn watch_filters_changes<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let mut jobs = store
            .watch(None, WatchFilter::namespaces(["jobs"]))
            .expect("watch");
        let mut rows = store
            .watch(None, WatchFilter::tables([ROWS]))
            .expect("watch");
        put(store.as_ref(), &ROWS, 1, "ipam only").await;
        let mut b = batch();
        b.put(ROWS, key(2), value("both"))
            .put(OTHER, key(2), value("both"));
        store.propose(b).await.expect("commit");

        let change_set = next_ok(&mut jobs).await;
        assert_eq!(
            change_set.revision,
            Revision(2),
            "revision 1 had no jobs change"
        );
        assert_eq!(
            change_set.changes,
            vec![Change {
                table: OTHER,
                key: key(2),
                deleted: false
            }]
        );
        assert_eq!(next_ok(&mut rows).await.revision, Revision(1));
        let second = next_ok(&mut rows).await;
        assert_eq!(second.revision, Revision(2));
        assert!(second.changes.iter().all(|change| change.table == ROWS));
    }

    /// Asking for revisions the journal no longer holds fails with `Compacted`; replay from
    /// just before the oldest retained revision works.
    pub async fn watch_rejects_compacted_revisions<F: StoreFactory>(factory: &F) {
        let config = ConformanceConfig {
            journal_retention: 4,
            ..ConformanceConfig::default()
        };
        let store = store(factory, config).await;
        for n in 1..=40 {
            put(store.as_ref(), &ROWS, n, "v").await;
        }
        let Err(StoreError::Compacted { oldest }) =
            store.watch(Some(Revision(1)), WatchFilter::all())
        else {
            panic!("revision 2 must be compacted with a retention of 4 after 40 batches");
        };
        assert!(
            oldest > Revision(2) && oldest <= Revision(37),
            "retains at least 4: {oldest}"
        );
        let mut watch = store
            .watch(Some(Revision(oldest.get() - 1)), WatchFilter::all())
            .expect("replay from the oldest retained revision");
        for n in oldest.get()..=40 {
            assert_eq!(next_ok(&mut watch).await.revision, Revision(n));
        }
    }

    /// A consumer still replaying when the journal is compacted past it receives
    /// `Compacted` after a gap-free prefix, and the stream ends.
    pub async fn watch_reports_compaction_in_stream<F: StoreFactory>(factory: &F) {
        let config = ConformanceConfig {
            journal_retention: 4,
            ..ConformanceConfig::default()
        };
        let store = store(factory, config).await;
        put(store.as_ref(), &ROWS, 1, "v").await;
        put(store.as_ref(), &ROWS, 2, "v").await;
        let mut watch = store
            .watch(Some(Revision(1)), WatchFilter::all())
            .expect("watch");
        for n in 3..=42 {
            put(store.as_ref(), &ROWS, n, "v").await;
        }
        let mut expected = 2;
        loop {
            match next(&mut watch).await {
                Some(Ok(change_set)) => {
                    assert_eq!(
                        change_set.revision,
                        Revision(expected),
                        "no gaps before the error"
                    );
                    expected += 1;
                    assert!(expected <= 42, "the stream must report compaction");
                }
                Some(Err(WatchError::Compacted { .. })) => break,
                other => panic!("expected Compacted, got {other:?}"),
            }
        }
        assert!(
            next(&mut watch).await.is_none(),
            "the stream ends after the error"
        );
    }

    /// A live consumer that falls further behind than the watch lag limit receives `Lagged`
    /// after a gap-free prefix, and the stream ends.
    pub async fn watch_reports_lag<F: StoreFactory>(factory: &F) {
        let config = ConformanceConfig {
            watch_max_lag: 4,
            ..ConformanceConfig::default()
        };
        let store = store(factory, config).await;
        let mut watch = store.watch(None, WatchFilter::all()).expect("watch");
        put(store.as_ref(), &ROWS, 1, "v").await;
        assert_eq!(next_ok(&mut watch).await.revision, Revision(1));
        for n in 2..=41 {
            put(store.as_ref(), &ROWS, n, "v").await;
        }
        let mut expected = 2;
        loop {
            match next(&mut watch).await {
                Some(Ok(change_set)) => {
                    assert_eq!(
                        change_set.revision,
                        Revision(expected),
                        "no gaps before the error"
                    );
                    expected += 1;
                    assert!(expected <= 41, "the stream must report the lag");
                }
                Some(Err(WatchError::Lagged { .. })) => break,
                other => panic!("expected Lagged, got {other:?}"),
            }
        }
        assert!(
            next(&mut watch).await.is_none(),
            "the stream ends after the error"
        );
    }

    /// `AtLeast` waits for the revision and times out; `Local` and `Linearizable` see every
    /// commit made before the call on this node.
    pub async fn read_consistency<F: StoreFactory>(factory: &F) {
        let config = ConformanceConfig {
            read_wait: Duration::from_secs(5),
            ..ConformanceConfig::default()
        };
        let store = store(factory, config).await;
        put(store.as_ref(), &ROWS, 1, "v").await;
        for consistency in [
            ReadConsistency::Local,
            ReadConsistency::Linearizable,
            ReadConsistency::AtLeast(Revision(1)),
        ] {
            assert_eq!(
                store.read(consistency).await.expect("read").revision(),
                Revision(1)
            );
        }
        let writer = Arc::clone(&store);
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            put(writer.as_ref(), &ROWS, 2, "v").await;
        });
        let view = store
            .read(ReadConsistency::AtLeast(Revision(2)))
            .await
            .expect("waits for revision 2");
        assert!(view.revision() >= Revision(2));
        assert_eq!(
            get(view.as_ref(), &ROWS, 2),
            Some((value("v"), Revision(2)))
        );
        task.await.expect("writer");

        let short = ConformanceConfig {
            read_wait: Duration::from_millis(200),
            ..ConformanceConfig::default()
        };
        let idle = store_with(factory, short).await;
        assert_eq!(
            idle.read(ReadConsistency::AtLeast(Revision(5))).await.err(),
            Some(StoreError::Timeout)
        );
    }

    async fn store_with<F: StoreFactory>(factory: &F, config: ConformanceConfig) -> Arc<F::Store> {
        store(factory, config).await
    }

    /// An index is built from a view, installed, and then applied incrementally in
    /// revision order, only for change sets that pass its filter, before `propose`
    /// returns.
    pub async fn derived_index_build_install_apply<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        for n in 1..=5 {
            put(store.as_ref(), &ROWS, n, &format!("v{n}")).await;
        }
        let index = Arc::new(RecordingIndex::new(ROWS));
        store.register_index(index.clone()).expect("register");
        let image = index.image();
        assert_eq!(image.revision, Revision(5));
        assert_eq!(image.rows.len(), 5);
        assert!(
            index.applied().is_empty(),
            "nothing to apply after the build"
        );

        let committed = put(store.as_ref(), &ROWS, 6, "v6").await;
        assert_eq!(
            index.image().rows.get(&key(6)),
            Some(&value("v6")),
            "applied before propose returns"
        );
        assert_eq!(index.image().revision, committed.revision);
        let mut b = batch();
        b.delete(ROWS, key(1)).put(ROWS, key(2), value("changed"));
        store.propose(b).await.expect("commit");
        put(store.as_ref(), &OTHER, 1, "filtered out").await;
        let image = index.image();
        assert_eq!(image.rows.len(), 5);
        assert_eq!(image.rows.get(&key(1)), None);
        assert_eq!(image.rows.get(&key(2)), Some(&value("changed")));
        assert_eq!(index.applied(), vec![Revision(6), Revision(7)]);
        let status = store.status();
        assert_eq!(status.indexes.len(), 1);
        assert!(status.indexes[0].revision >= Revision(7));
    }

    /// An index registered while writers are busy ends identical to a fresh scan, with
    /// strictly increasing applied revisions.
    pub async fn derived_index_registered_under_load<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        for n in 0..50 {
            put(store.as_ref(), &ROWS, n, "seed").await;
        }
        let writer = Arc::clone(&store);
        let task = tokio::spawn(async move {
            for n in 0..300_u64 {
                let mut b = batch();
                b.put(ROWS, key(n % 120), value(&format!("w{n}")));
                if n % 7 == 0 {
                    b.delete(ROWS, key((n + 3) % 120));
                }
                writer.propose(b).await.expect("commit");
            }
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        let index = Arc::new(RecordingIndex::new(ROWS));
        store
            .register_index(index.clone())
            .expect("register under load");
        task.await.expect("writer");

        let view = view(store.as_ref()).await;
        let fresh_rows: std::collections::BTreeMap<Bytes, Bytes> = view
            .scan(&ROWS, KeyRange::all(), 1_000, false)
            .expect("scan")
            .into_iter()
            .map(|(k, v)| (k, v.value))
            .collect();
        assert_eq!(index.image().rows, fresh_rows);
        let applied = index.applied();
        assert!(
            applied.windows(2).all(|w| w[0] < w[1]),
            "applied in revision order"
        );
    }

    /// 32 tasks of 100 batches each, with counter preconditions on their own counters, all
    /// commit with distinct revisions, and the final state is consistent.
    pub async fn concurrent_proposers<F: StoreFactory>(factory: &F) {
        const TASKS: u64 = 32;
        const BATCHES: u64 = 100;
        let store = fresh(factory).await;
        let shared = CounterKey::new("ipam.conformance_shared");
        let mut tasks = Vec::new();
        for task in 0..TASKS {
            let store = Arc::clone(&store);
            let shared = shared.clone();
            tasks.push(tokio::spawn(async move {
                let own = CounterKey::with("ipam.conformance_task", &task);
                let mut revisions = Vec::new();
                for n in 0..BATCHES {
                    let mut b = batch();
                    b.expect_counter(own.clone(), n)
                        .bump(own.clone())
                        .bump(shared.clone())
                        .put(ROWS, encode_key(&(task, n)), value("v"))
                        .audit(AuditDraft::success(CREATE, vec![]));
                    revisions.push(store.propose(b).await.expect("no conflicts").revision);
                }
                revisions
            }));
        }
        let mut revisions = BTreeSet::new();
        for task in tasks {
            for revision in task.await.expect("task") {
                assert!(
                    revisions.insert(revision),
                    "revision {revision} committed twice"
                );
            }
        }
        let total = TASKS * BATCHES;
        assert_eq!(revisions.len() as u64, total);
        assert_eq!(revisions.first(), Some(&Revision(1)));
        assert_eq!(revisions.last(), Some(&Revision(total)));
        let view = view(store.as_ref()).await;
        assert_eq!(view.revision(), Revision(total));
        assert_eq!(view.counter(&shared).expect("counter"), total);
        for task in 0..TASKS {
            let own = CounterKey::with("ipam.conformance_task", &task);
            assert_eq!(view.counter(&own).expect("counter"), BATCHES);
        }
        let rows = view
            .scan(&ROWS, KeyRange::all(), 10_000, false)
            .expect("scan");
        assert_eq!(rows.len() as u64, total);
        let records: Vec<_> = view
            .scan_typed(&tables::AUDIT, KeyRange::all(), 10_000, false)
            .expect("scan")
            .into_iter()
            .map(|(_, record, _)| record)
            .collect();
        assert_eq!(
            verify_chain(&records).expect("the chain verifies").seq,
            AuditSeq(total)
        );
    }

    /// Optimistic concurrency on one hot counter: readers retry on conflicts and no
    /// increment is lost.
    pub async fn concurrent_counter_increments_with_retry<F: StoreFactory>(factory: &F) {
        const TASKS: u64 = 8;
        const INCREMENTS: u64 = 10;
        let store = fresh(factory).await;
        let mut tasks = Vec::new();
        for _ in 0..TASKS {
            let store = Arc::clone(&store);
            tasks.push(tokio::spawn(async move {
                let mut conflicts = 0_u64;
                for _ in 0..INCREMENTS {
                    loop {
                        let current = store
                            .read(ReadConsistency::Local)
                            .await
                            .expect("view")
                            .counter(&COUNTER)
                            .expect("counter");
                        let mut b = batch();
                        b.expect_counter(COUNTER, current).bump(COUNTER);
                        match store.propose(b).await {
                            Ok(_) => break,
                            Err(StoreError::PreconditionFailed(_)) => conflicts += 1,
                            Err(other) => panic!("unexpected error {other}"),
                        }
                    }
                }
                conflicts
            }));
        }
        for task in tasks {
            task.await.expect("task");
        }
        let view = view(store.as_ref()).await;
        assert_eq!(view.counter(&COUNTER).expect("counter"), TASKS * INCREMENTS);
        assert_eq!(
            view.revision(),
            Revision(TASKS * INCREMENTS),
            "failed attempts consume no revision"
        );
    }

    /// Status reports the revision, the audit head, the journal and registered indexes.
    pub async fn status_reports_fields<F: StoreFactory>(factory: &F) {
        let store = fresh(factory).await;
        let mut b = batch();
        b.put(ROWS, key(1), value("v"))
            .audit(AuditDraft::success(CREATE, vec![]))
            .audit(AuditDraft::success(CREATE, vec![]));
        store.propose(b).await.expect("commit");
        put(store.as_ref(), &ROWS, 2, "v").await;
        store
            .register_index(Arc::new(RecordingIndex::new(ROWS)))
            .expect("register");
        let status = store.status();
        assert_eq!(status.revision, Revision(2));
        assert_eq!(status.audit_head, AuditSeq(2));
        assert!(
            status
                .journal_oldest
                .is_some_and(|oldest| oldest <= Revision(2))
        );
        assert!(status.journal_len >= 2);
        assert!(status.data_bytes > 0);
        assert_eq!(status.indexes.len(), 1);
        assert_eq!(status.indexes[0].name, "conformance.recording");
        assert_ne!(status.role, crate::api::StoreRole::Shutdown);
    }
}
