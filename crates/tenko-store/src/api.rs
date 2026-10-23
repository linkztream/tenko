//! The store contract (plan section 2.4, ADR 0002, ADR 0011).
//!
//! A write is a [`WriteBatch`]: physical mutations with preconditions and audit drafts,
//! computed by the proposer from a [`ReadView`] and checked deterministically at apply.
//! Domain logic never runs inside the store, so replicas of different versions apply a
//! batch identically (OPS-08).
//!
//! Every [`Store`] implementation upholds these invariants, and
//! the conformance suite (`tenko_store::testing`, feature `testing`) checks them:
//!
//! 1. **Atomic batches, one revision each.** A batch either applies completely or not at
//!    all, and an applied batch increments the store-wide [`Revision`] by exactly one. A
//!    failed batch (preconditions, idempotency, validation) changes nothing, consumes no
//!    revision and no audit sequence number.
//! 2. **Preconditions at apply.** [`Precondition::Version`] compares the revision of the
//!    key's current value (`None`: the key must be absent); [`Precondition::Counter`]
//!    compares a counter (absent counters are 0). All failures are reported together in
//!    [`StoreError::PreconditionFailed`].
//! 3. **Idempotency.** A batch with an idempotency key is recorded under
//!    (`Principal::subject`, key). Proposing a batch with the same fingerprint again
//!    returns the first [`Committed`] with `replayed: true` and applies nothing; a different
//!    batch under the same key fails with [`StoreError::IdempotencyMismatch`]. The
//!    fingerprint covers principal, key, preconditions, mutations and audit drafts, not
//!    `proposed_at` or `request`. Only committed batches record their key.
//! 4. **Audit chain.** The drafts of a batch become `AuditRecord`s at apply, with
//!    gap-free sequence numbers from 1, `at = proposed_at`, the batch's principal and
//!    request, linked and sealed with SHA-256 (see `tenko_core::audit`), stored in
//!    [`tables::AUDIT`] in the same atomic step. [`Committed::audit`] lists their numbers.
//! 5. **Journal and watch.** Every applied batch appends a [`ChangeSet`] (the changed keys
//!    of user tables plus the new `sys.audit` rows) to [`tables::JOURNAL`]. [`Store::watch`]
//!    replays it and then follows live commits, in revision order.
//! 6. **Derived indexes** are built aside from a read view, installed atomically and then
//!    kept current by [`DerivedIndex::apply`] in revision order, on the apply path, before
//!    `propose` returns on the proposing node.
//! 7. **Validation before the log** ([`WriteBatch::validate`]): size limit, no writes to
//!    reserved tables, and no plaintext in secret-bearing tables (NEVER-01).

use std::{
    any::Any,
    collections::BTreeSet,
    fmt,
    ops::{Bound, RangeBounds},
    sync::Arc,
};

use bytes::Bytes;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tenko_core::{
    Anchors, AuditSeq, Coded, CounterKey, IdempotencyKey, NodeId, ObjectRef, Principal, RequestCtx,
    RequestId, Revision, TableName, Timestamp,
    audit::{AuditDraft, Digest},
    codec::{CodecError, KeyCodec, KeyError, canonical_sha256, prefix_successor},
    secret::VaultEnvelope,
    table::TableDef,
};

/// Tables the store maintains itself. Batches may read them but never write them.
pub mod tables {
    use tenko_core::{AuditSeq, Revision, TableName, audit::AuditRecord, table::TableDef};

    use super::ChangeSet;

    /// Sealed audit records by sequence number.
    pub const AUDIT: TableDef<AuditSeq, AuditRecord> = TableDef::new("sys.audit");
    /// Change sets by revision; feeds `watch` and SSE replay (ADR 0008).
    pub const JOURNAL: TableDef<Revision, ChangeSet> = TableDef::new("sys.journal");
    /// Counters (`Mutation::Bump`): key is the encoded `CounterKey`, value a big-endian
    /// `u64`.
    pub const COUNTERS: TableName = TableName::from_static("sys.counters");
    /// Idempotency records by principal subject and key.
    pub const IDEMPOTENCY: TableName = TableName::from_static("sys.idempotency");

    /// Whether batches are forbidden to write the table.
    pub fn is_reserved(table: &TableName) -> bool {
        [AUDIT.name(), JOURNAL.name(), &COUNTERS, &IDEMPOTENCY].contains(&table)
    }
}

/// A precondition, checked deterministically when the batch applies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Precondition {
    /// The key's current value was written at `expect`; `None` means the key is absent.
    Version {
        /// The table.
        table: TableName,
        /// The encoded key.
        key: Bytes,
        /// The expected revision of the current value.
        expect: Option<Revision>,
    },
    /// The counter has the expected value (absent counters are 0).
    Counter {
        /// The counter.
        counter: CounterKey,
        /// The expected value.
        expect: u64,
    },
}

/// A physical change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mutation {
    /// Inserts or replaces a value.
    Put {
        /// The table.
        table: TableName,
        /// The encoded key.
        key: Bytes,
        /// The encoded value.
        value: Bytes,
    },
    /// Removes a value; removing an absent key is a no-op.
    Delete {
        /// The table.
        table: TableName,
        /// The encoded key.
        key: Bytes,
    },
    /// Increments a counter by one.
    Bump {
        /// The counter.
        counter: CounterKey,
    },
}

/// A set of mutations that applies atomically with one revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteBatch {
    /// Who writes (mandatory, NEVER-03).
    pub principal: Principal,
    /// The proposer's clock; apply never reads the replica's clock.
    pub proposed_at: Timestamp,
    /// The request that produced the batch.
    #[serde(default)]
    pub request: Option<RequestId>,
    /// Idempotency key (API-04).
    #[serde(default)]
    pub idempotency: Option<IdempotencyKey>,
    /// Checked at apply; any failure rejects the whole batch.
    #[serde(default)]
    pub preconditions: Vec<Precondition>,
    /// Applied in order; a later mutation of the same key wins.
    #[serde(default)]
    pub mutations: Vec<Mutation>,
    /// Sealed into the audit chain at apply (IAM-18).
    #[serde(default)]
    pub audit: Vec<AuditDraft>,
}

impl WriteBatch {
    /// An empty batch.
    pub fn new(principal: Principal, proposed_at: Timestamp) -> Self {
        Self {
            principal,
            proposed_at,
            request: None,
            idempotency: None,
            preconditions: Vec::new(),
            mutations: Vec::new(),
            audit: Vec::new(),
        }
    }

    /// An empty batch carrying the principal, time, request id and idempotency key of a
    /// request.
    pub fn for_request(ctx: &RequestCtx) -> Self {
        Self {
            request: Some(ctx.request),
            idempotency: ctx.idempotency.clone(),
            ..Self::new(ctx.principal.clone(), ctx.now)
        }
    }

    /// Adds a `Put`.
    pub fn put(
        &mut self,
        table: TableName,
        key: impl Into<Bytes>,
        value: impl Into<Bytes>,
    ) -> &mut Self {
        self.mutations.push(Mutation::Put {
            table,
            key: key.into(),
            value: value.into(),
        });
        self
    }

    /// Adds a `Delete`.
    pub fn delete(&mut self, table: TableName, key: impl Into<Bytes>) -> &mut Self {
        self.mutations.push(Mutation::Delete {
            table,
            key: key.into(),
        });
        self
    }

    /// Adds a `Bump`.
    pub fn bump(&mut self, counter: CounterKey) -> &mut Self {
        self.mutations.push(Mutation::Bump { counter });
        self
    }

    /// Adds a version precondition (`None`: the key must be absent).
    pub fn expect_version(
        &mut self,
        table: TableName,
        key: impl Into<Bytes>,
        expect: Option<Revision>,
    ) -> &mut Self {
        self.preconditions.push(Precondition::Version {
            table,
            key: key.into(),
            expect,
        });
        self
    }

    /// Adds a counter precondition.
    pub fn expect_counter(&mut self, counter: CounterKey, expect: u64) -> &mut Self {
        self.preconditions
            .push(Precondition::Counter { counter, expect });
        self
    }

    /// Adds an audit draft.
    pub fn audit(&mut self, draft: AuditDraft) -> &mut Self {
        self.audit.push(draft);
        self
    }

    /// Adds a typed `Put`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Codec`] if the value cannot be encoded.
    pub fn put_typed<K: KeyCodec, V: Serialize + DeserializeOwned>(
        &mut self,
        table: &TableDef<K, V>,
        key: &K,
        value: &V,
    ) -> Result<&mut Self, StoreError> {
        let value = table.encode(value)?;
        Ok(self.put(table.name().clone(), table.key(key), value))
    }

    /// Adds a typed `Delete`.
    pub fn delete_typed<K: KeyCodec, V: Serialize + DeserializeOwned>(
        &mut self,
        table: &TableDef<K, V>,
        key: &K,
    ) -> &mut Self {
        self.delete(table.name().clone(), table.key(key))
    }

    /// Adds a typed version precondition.
    pub fn expect_typed<K: KeyCodec, V: Serialize + DeserializeOwned>(
        &mut self,
        table: &TableDef<K, V>,
        key: &K,
        expect: Option<Revision>,
    ) -> &mut Self {
        self.expect_version(table.name().clone(), table.key(key), expect)
    }

    /// Whether the batch has no preconditions, mutations or audit drafts.
    pub fn is_empty(&self) -> bool {
        self.preconditions.is_empty() && self.mutations.is_empty() && self.audit.is_empty()
    }

    /// Payload size used for the batch limit: table names, keys and values of mutations
    /// and preconditions, plus the encoded audit drafts.
    pub fn payload_size(&self) -> usize {
        let mutations: usize = self
            .mutations
            .iter()
            .map(|m| match m {
                Mutation::Put { table, key, value } => {
                    table.as_str().len() + key.len() + value.len()
                }
                Mutation::Delete { table, key } => table.as_str().len() + key.len(),
                Mutation::Bump { counter } => {
                    counter.name().as_str().len() + counter.qualifier().len()
                }
            })
            .sum();
        let preconditions: usize = self
            .preconditions
            .iter()
            .map(|p| match p {
                Precondition::Version { table, key, .. } => table.as_str().len() + key.len() + 8,
                Precondition::Counter { counter, .. } => {
                    counter.name().as_str().len() + counter.qualifier().len() + 8
                }
            })
            .sum();
        let audit = tenko_core::codec::to_cbor(&self.audit).map_or(0, |bytes| bytes.len());
        mutations + preconditions + audit
    }

    /// The idempotency fingerprint: SHA-256 over the canonical CBOR of the principal, the
    /// idempotency key, the preconditions, the mutations and the audit drafts.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Codec`] if the batch cannot be encoded.
    pub fn fingerprint(&self) -> Result<Digest, StoreError> {
        #[derive(Serialize)]
        struct Fingerprinted<'a> {
            principal: &'a Principal,
            idempotency: &'a Option<IdempotencyKey>,
            preconditions: &'a [Precondition],
            mutations: &'a [Mutation],
            audit: &'a [AuditDraft],
        }
        Ok(Digest(canonical_sha256(&Fingerprinted {
            principal: &self.principal,
            idempotency: &self.idempotency,
            preconditions: &self.preconditions,
            mutations: &self.mutations,
            audit: &self.audit,
        })?))
    }

    /// The validation every store runs before a batch enters the log: the size limit,
    /// no writes to [reserved tables](tables::is_reserved), and only
    /// [vault envelopes](VaultEnvelope) in secret-bearing tables (NEVER-01).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::BatchTooLarge`], [`StoreError::ReservedTable`] or
    /// [`StoreError::PlaintextSecret`].
    pub fn validate(&self, max_batch_bytes: usize) -> Result<(), StoreError> {
        let size = self.payload_size();
        if size > max_batch_bytes {
            return Err(StoreError::BatchTooLarge {
                size,
                limit: max_batch_bytes,
            });
        }
        for mutation in &self.mutations {
            let table = match mutation {
                Mutation::Put { table, .. } | Mutation::Delete { table, .. } => table,
                Mutation::Bump { .. } => continue,
            };
            if tables::is_reserved(table) {
                return Err(StoreError::ReservedTable {
                    table: table.clone(),
                });
            }
            if let Mutation::Put { table, value, .. } = mutation
                && table.is_secret_bearing()
                && !VaultEnvelope::is_envelope(value)
            {
                return Err(StoreError::PlaintextSecret {
                    table: table.clone(),
                });
            }
        }
        Ok(())
    }
}

/// The result of an applied batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Committed {
    /// The batch's revision.
    pub revision: Revision,
    /// Sequence numbers of the batch's audit records, in draft order.
    pub audit: Vec<AuditSeq>,
    /// `true` when an earlier commit was returned for a repeated idempotency key.
    pub replayed: bool,
}

/// A precondition that did not hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailedPrecondition {
    /// A version precondition.
    Version {
        /// The table.
        table: TableName,
        /// The encoded key.
        key: Bytes,
        /// What the batch expected.
        expected: Option<Revision>,
        /// The revision of the current value (`None`: absent).
        actual: Option<Revision>,
    },
    /// A counter precondition.
    Counter {
        /// The counter.
        counter: CounterKey,
        /// What the batch expected.
        expected: u64,
        /// The current value.
        actual: u64,
    },
}

/// How fresh a read view must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadConsistency {
    /// Whatever this node has applied.
    Local,
    /// At least this revision (read-your-writes); waits for the node to catch up, then
    /// fails with [`StoreError::Timeout`].
    AtLeast(Revision),
    /// Everything committed before the call (asks the leader for its commit index).
    Linearizable,
}

/// A value with the revision of the batch that wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Versioned {
    /// The encoded value.
    pub value: Bytes,
    /// The revision that wrote it.
    pub revision: Revision,
}

/// A range of encoded keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyRange {
    /// Lower bound.
    pub start: Bound<Bytes>,
    /// Upper bound.
    pub end: Bound<Bytes>,
}

impl KeyRange {
    /// Every key.
    pub fn all() -> Self {
        Self {
            start: Bound::Unbounded,
            end: Bound::Unbounded,
        }
    }

    /// Every key that starts with `prefix` (for composite keys, an encoded leading
    /// component such as `encode_key(&(vrf,))`).
    pub fn prefix(prefix: impl Into<Bytes>) -> Self {
        let prefix = prefix.into();
        let end = prefix_successor(&prefix)
            .map_or(Bound::Unbounded, |end| Bound::Excluded(Bytes::from(end)));
        Self {
            start: Bound::Included(prefix),
            end,
        }
    }

    /// Keys from `start` (inclusive) to `end` (exclusive).
    pub fn between(start: impl Into<Bytes>, end: impl Into<Bytes>) -> Self {
        Self {
            start: Bound::Included(start.into()),
            end: Bound::Excluded(end.into()),
        }
    }

    /// Keys after `key` (exclusive), within the same upper bound: the next page of a
    /// forward scan.
    #[must_use]
    pub fn after(mut self, key: impl Into<Bytes>) -> Self {
        self.start = Bound::Excluded(key.into());
        self
    }

    /// Keys before `key` (exclusive), within the same lower bound: the next page of a
    /// reverse scan.
    #[must_use]
    pub fn before(mut self, key: impl Into<Bytes>) -> Self {
        self.end = Bound::Excluded(key.into());
        self
    }

    /// Whether `key` lies in the range.
    pub fn contains(&self, key: &[u8]) -> bool {
        let after_start = match &self.start {
            Bound::Included(start) => key >= &start[..],
            Bound::Excluded(start) => key > &start[..],
            Bound::Unbounded => true,
        };
        let before_end = match &self.end {
            Bound::Included(end) => key <= &end[..],
            Bound::Excluded(end) => key < &end[..],
            Bound::Unbounded => true,
        };
        after_start && before_end
    }

    /// Whether no key can lie in the range (inverted or empty bounds).
    pub fn is_empty(&self) -> bool {
        match (&self.start, &self.end) {
            (Bound::Unbounded, _) | (_, Bound::Unbounded) => false,
            (Bound::Included(start), Bound::Included(end)) => start > end,
            (Bound::Included(start) | Bound::Excluded(start), Bound::Excluded(end))
            | (Bound::Excluded(start), Bound::Included(end)) => start >= end,
        }
    }
}

impl RangeBounds<Bytes> for KeyRange {
    fn start_bound(&self) -> Bound<&Bytes> {
        self.start.as_ref()
    }
    fn end_bound(&self) -> Bound<&Bytes> {
        self.end.as_ref()
    }
}

/// A consistent snapshot of the store at one revision (an MVCC read transaction).
pub trait ReadView: Send + Sync {
    /// The revision the view reads at.
    fn revision(&self) -> Revision;

    /// The current value of a key.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] on storage failure.
    fn get(&self, table: &TableName, key: &[u8]) -> Result<Option<Versioned>, StoreError>;

    /// Up to `limit` entries in key order (descending when `reverse`).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] on storage failure.
    fn scan(
        &self,
        table: &TableName,
        range: KeyRange,
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Bytes, Versioned)>, StoreError>;

    /// The value of a counter (0 if never bumped).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] on storage failure.
    fn counter(&self, counter: &CounterKey) -> Result<u64, StoreError>;
}

/// Typed access through a [`TableDef`]; implemented for every [`ReadView`].
pub trait ReadViewExt: ReadView {
    /// Reads and decodes one value with its revision.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Codec`] if the stored value does not decode, or a storage
    /// error.
    fn get_typed<K: KeyCodec, V: Serialize + DeserializeOwned>(
        &self,
        table: &TableDef<K, V>,
        key: &K,
    ) -> Result<Option<(V, Revision)>, StoreError> {
        self.get(table.name(), &table.key(key))?
            .map(|versioned| Ok((table.decode(&versioned.value)?, versioned.revision)))
            .transpose()
    }

    /// Scans and decodes a range of a table.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Codec`] if a key or value does not decode, or a storage
    /// error.
    fn scan_typed<K: KeyCodec, V: Serialize + DeserializeOwned>(
        &self,
        table: &TableDef<K, V>,
        range: KeyRange,
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(K, V, Revision)>, StoreError> {
        self.scan(table.name(), range, limit, reverse)?
            .into_iter()
            .map(|(key, versioned)| {
                Ok((
                    table.decode_key(&key)?,
                    table.decode(&versioned.value)?,
                    versioned.revision,
                ))
            })
            .collect()
    }
}

impl<T: ReadView + ?Sized> ReadViewExt for T {}

/// One changed key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Change {
    /// The table.
    pub table: TableName,
    /// The encoded key.
    pub key: Bytes,
    /// Whether the key was removed (otherwise it was written).
    pub deleted: bool,
}

/// The journal entry of one applied batch.
///
/// `changes` lists every changed key of user tables and the new `sys.audit` rows, once
/// each, sorted by table and key. Counters, the journal itself and idempotency records are
/// not listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSet {
    /// The batch's revision.
    pub revision: Revision,
    /// Who wrote it.
    pub principal: Principal,
    /// The proposer's time.
    pub at: Timestamp,
    /// The changed keys.
    pub changes: Vec<Change>,
}

/// Which changes a watcher or an index receives.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WatchFilter {
    all: bool,
    tables: BTreeSet<TableName>,
    namespaces: BTreeSet<String>,
}

impl WatchFilter {
    /// Every change set, including those without changes.
    pub fn all() -> Self {
        Self {
            all: true,
            ..Self::default()
        }
    }

    /// Changes in the given tables.
    pub fn tables(tables: impl IntoIterator<Item = TableName>) -> Self {
        Self {
            tables: tables.into_iter().collect(),
            ..Self::default()
        }
    }

    /// Changes in tables of the given namespaces (`ipam`, `jobs`, `sys`, ...).
    pub fn namespaces<S: Into<String>>(namespaces: impl IntoIterator<Item = S>) -> Self {
        Self {
            namespaces: namespaces.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Adds a table.
    #[must_use]
    pub fn with_table(mut self, table: TableName) -> Self {
        self.tables.insert(table);
        self
    }

    /// Adds a namespace.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespaces.insert(namespace.into());
        self
    }

    /// Whether changes of `table` pass.
    pub fn matches(&self, table: &TableName) -> bool {
        self.all || self.tables.contains(table) || self.namespaces.contains(table.namespace())
    }

    /// The part of a change set that passes: `None` when nothing passes. With
    /// [`WatchFilter::all`] every change set passes unchanged.
    pub fn apply(&self, changes: &ChangeSet) -> Option<ChangeSet> {
        if self.all {
            return Some(changes.clone());
        }
        let kept: Vec<Change> = changes
            .changes
            .iter()
            .filter(|change| self.matches(&change.table))
            .cloned()
            .collect();
        (!kept.is_empty()).then(|| ChangeSet {
            changes: kept,
            ..changes.clone()
        })
    }
}

/// A watch stream ended because the consumer cannot continue from where it is; the
/// client reloads its state (SSE `reset`, ADR 0008).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WatchError {
    /// The consumer fell further behind the live revision than the store buffers.
    #[error("watcher lagged behind after revision {last}")]
    Lagged {
        /// The last revision delivered to the consumer.
        last: Revision,
    },
    /// The journal no longer holds the revisions the consumer needs.
    #[error("journal compacted; the oldest retained revision is {oldest}")]
    Compacted {
        /// The oldest revision still in the journal.
        oldest: Revision,
    },
}

impl Coded for WatchError {
    fn code(&self) -> &'static str {
        match self {
            WatchError::Lagged { .. } => "sys.store.watch_lagged",
            WatchError::Compacted { .. } => "sys.store.compacted",
        }
    }
    fn http_status(&self) -> u16 {
        410
    }
}

/// Change sets in revision order; ends after an error.
pub type ChangeStream = BoxStream<'static, Result<ChangeSet, WatchError>>;

/// A built index image, handed from [`DerivedIndex::build`] to [`DerivedIndex::install`].
pub trait IndexImage: Any + Send + Sync {
    /// The revision of the view the image was built from.
    fn revision(&self) -> Revision;

    /// Approximate memory use in bytes, for status (OPS-20).
    fn memory_bytes(&self) -> usize {
        0
    }
}

/// Recovers the concrete image type inside [`DerivedIndex::install`].
pub fn downcast_image<T: IndexImage>(image: Box<dyn IndexImage>) -> Option<Box<T>> {
    let any: Box<dyn Any + Send + Sync> = image;
    any.downcast::<T>().ok()
}

/// An in-memory structure derived from store tables (a serving index, the prefix tree).
///
/// The store builds a new image aside from a read view (at registration, at start and,
/// for the Raft store, on snapshot install), installs it atomically, so readers never see
/// a cleared index, and then calls [`apply`](DerivedIndex::apply) for every later change set
/// that passes [`filter`](DerivedIndex::filter), in revision order, without gaps.
///
/// `apply` runs on the store's apply path: it must be fast, must not panic and must not
/// call back into the store; it reads the changed values through the view it is given.
pub trait DerivedIndex: Send + Sync + 'static {
    /// A name for status and logs.
    fn name(&self) -> &str {
        std::any::type_name::<Self>()
    }

    /// The tables the index derives from. Defaults to everything.
    fn filter(&self) -> WatchFilter {
        WatchFilter::all()
    }

    /// Builds a complete image from a view. Runs aside, without blocking writers.
    ///
    /// # Errors
    ///
    /// Returns a store error if reading or decoding fails; registration then fails.
    fn build(&self, view: &dyn ReadView) -> Result<Box<dyn IndexImage>, StoreError>;

    /// Replaces the live image atomically (an `arc_swap::ArcSwap` store).
    fn install(&self, image: Box<dyn IndexImage>);

    /// Applies one change set. `view` reads the store at `changes.revision`.
    fn apply(&self, changes: &ChangeSet, view: &dyn ReadView);
}

/// Write coalescing limits of the Raft store (ADR 0002 decision 4, defaults from Spike A).
/// `MemStore` uses only `max_batch_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoalescerConfig {
    /// Batches per Raft entry.
    pub max_batches_per_entry: usize,
    /// Bytes per Raft entry.
    pub max_entry_bytes: usize,
    /// Entries in flight before proposers wait.
    pub max_inflight_entries: usize,
    /// Payload limit of one batch ([`WriteBatch::payload_size`]); a bulk import splits into
    /// batches below it.
    pub max_batch_bytes: usize,
}

impl Default for CoalescerConfig {
    fn default() -> Self {
        Self {
            max_batches_per_entry: 1_000,
            max_entry_bytes: 8 * 1024 * 1024,
            max_inflight_entries: 4,
            max_batch_bytes: 16 * 1024 * 1024,
        }
    }
}

/// The role of this node in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreRole {
    /// An in-memory store (tests and development).
    Memory,
    /// Raft leader.
    Leader,
    /// Raft follower.
    Follower,
    /// Raft learner (catching up, not voting).
    Learner,
    /// Raft candidate (election in progress).
    Candidate,
    /// Shutting down.
    Shutdown,
}

/// Status of one derived index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexStatus {
    /// The index name.
    pub name: String,
    /// The last revision built or applied.
    pub revision: Revision,
    /// Approximate memory use of the installed image at install time.
    pub memory_bytes: usize,
}

/// Store status for health checks and the dashboard (OPS-20). Cheap to call: sizes are
/// cached values, not computed on demand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreStatus {
    /// This node's role.
    pub role: StoreRole,
    /// This node's id (`None` for `MemStore`).
    pub node: Option<NodeId>,
    /// The current leader.
    pub leader: Option<NodeId>,
    /// The last applied revision.
    pub revision: Revision,
    /// Entries this node is behind the leader's commit index (`Some(0)` when current).
    pub lag: Option<u64>,
    /// The last audit sequence number.
    pub audit_head: AuditSeq,
    /// The oldest revision in the journal (`None` while it is empty).
    pub journal_oldest: Option<Revision>,
    /// Change sets in the journal.
    pub journal_len: u64,
    /// Bytes of live keys and values.
    pub data_bytes: u64,
    /// Bytes on disk (`None` for `MemStore`).
    pub disk_bytes: Option<u64>,
    /// Median latency in microseconds of a durable commit on the data directory, measured
    /// by the start-up probe (OPS-19; the store warns above 10 ms). `None` for `MemStore` or
    /// when the probe did not run.
    pub fsync_p50_micros: Option<u64>,
    /// Bytes of the state-machine file alone (`None` for `MemStore`). Compare with
    /// `data_bytes`: a node is re-seeded from a snapshot when the file passes about twice
    /// the live data (ADR 0002).
    #[serde(default)]
    pub sm_file_bytes: Option<u64>,
    /// Registered derived indexes.
    pub indexes: Vec<IndexStatus>,
    /// Whether this member reaches a quorum (OPS-26). Status written before Slice 3 reads
    /// as [`QuorumState::Single`].
    #[serde(default)]
    pub quorum: QuorumState,
    /// The Raft term this member knows (`1` for `MemStore`).
    #[serde(default)]
    pub term: u64,
    /// The members of the cluster with their replication state, filled on the leader only
    /// (empty on a follower and for `MemStore`).
    #[serde(default)]
    pub members: Vec<MemberStatus>,
}

/// Whether a member of the store can reach a quorum (OPS-26, plan section 2.2). The
/// partition layer refuses writes on a member that is not [`QuorumState::Single`] or
/// [`QuorumState::Healthy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum QuorumState {
    /// The only voter: never isolated (`MemStore` and a single controller).
    #[default]
    Single,
    /// A leader is known and in contact with a quorum.
    Healthy,
    /// No leader is known; an election is running.
    Electing {
        /// When the member lost its leader.
        since: Timestamp,
    },
    /// No contact with a quorum for longer than `[cluster] isolation_after_ms`; reads serve
    /// the local copy, writes are refused.
    Isolated {
        /// When the member became isolated.
        since: Timestamp,
        /// The last message from a leader (follower) or the last quorum acknowledgement
        /// (leader), if any.
        last_contact: Option<Timestamp>,
        /// The last revision this member applied: the age of its local copy.
        applied: Revision,
    },
}

impl QuorumState {
    /// Whether writes can commit through this member.
    pub fn accepts_writes(&self) -> bool {
        matches!(self, Self::Single | Self::Healthy)
    }
}

/// Who leads the store, as one member sees it ([`Store::leadership`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Leadership {
    /// The leader.
    pub leader: NodeId,
    /// The term of its leadership.
    pub term: u64,
    /// Whether this member is the leader and has applied every entry up to its first
    /// commit in the term, so leader-only work never starts on a stale view.
    pub is_self: bool,
}

/// The replication state of one member, as the leader sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberStatus {
    /// The member.
    pub node: NodeId,
    /// A voter (otherwise a learner catching up).
    pub voter: bool,
    /// The last log index known to match the leader's log.
    pub matched: Option<u64>,
    /// Entries the member is behind the leader's last log index.
    pub lag_entries: Option<u64>,
    /// Milliseconds since the leader last heard from the member.
    pub last_contact_ms: Option<u64>,
}

/// The precondition that fences a leader-only write to the term of office it was planned
/// in: the counter [`tenko_core::cluster::LEADER_EPOCH`] still has the value `epoch` that
/// [`tenko_core::cluster::LeaderService::run`] received. Once another member has taken
/// office the counter has moved on and the batch fails with
/// [`StoreError::PreconditionFailed`], so a deposed leader cannot write.
pub fn fence(epoch: u64) -> Precondition {
    Precondition::Counter {
        counter: tenko_core::cluster::LEADER_EPOCH,
        expect: epoch,
    }
}

/// Finds the [`Anchors`] of an object for scope checks (IAM-01, plan section 2.5): a prefix
/// anchors to itself and its ancestors, an address or a range to its most specific prefix,
/// a host to its site and the prefixes of its addresses, and so on. Implemented over the
/// prefix tree by `tenko-ipam`; the authorizer of `tenko-auth` asks it before
/// [`tenko_core::ScopeFilter::admits`]. It lives here, beside [`ReadView`], because both
/// crates depend on this one and the anchors of most objects need a read.
pub trait AnchorResolver: Send + Sync {
    /// The anchors of `object` in `view`.
    ///
    /// # Errors
    ///
    /// A storage or decoding failure of the read.
    fn anchors(&self, view: &dyn ReadView, object: &ObjectRef) -> Result<Anchors, StoreError>;
}

impl StoreStatus {
    /// `sm_file_bytes / data_bytes` when both are known and there is live data.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn sm_file_ratio(&self) -> Option<f64> {
        let file = self.sm_file_bytes?;
        (self.data_bytes > 0).then(|| file as f64 / self.data_bytes as f64)
    }
}

/// Store errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// One or more preconditions did not hold; nothing was applied. Re-read and retry.
    #[error("{} precondition(s) failed", .0.len())]
    PreconditionFailed(Vec<FailedPrecondition>),
    /// The idempotency key was used before for a different batch.
    #[error("idempotency key reused for a different request")]
    IdempotencyMismatch,
    /// The batch exceeds the payload limit.
    #[error("batch of {size} bytes exceeds the limit of {limit} bytes")]
    BatchTooLarge {
        /// The payload size.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// No Raft quorum is reachable.
    #[error("no quorum")]
    NoQuorum,
    /// The operation timed out.
    #[error("store operation timed out")]
    Timeout,
    /// The store is shutting down.
    #[error("store is shutting down")]
    ShuttingDown,
    /// The requested revision is older than the journal retains.
    #[error("journal compacted; the oldest retained revision is {oldest}")]
    Compacted {
        /// The oldest revision still in the journal.
        oldest: Revision,
    },
    /// A batch writes a table the store maintains itself.
    #[error("table {table} is maintained by the store and cannot be written")]
    ReservedTable {
        /// The table.
        table: TableName,
    },
    /// A batch writes a value that is not a vault envelope into a secret-bearing table
    /// (NEVER-01).
    #[error("plaintext value for secret-bearing table {table}")]
    PlaintextSecret {
        /// The table.
        table: TableName,
    },
    /// The storage engine failed.
    #[error("storage failure: {0}")]
    Storage(String),
    /// A key or value did not encode or decode.
    #[error("encoding failure: {0}")]
    Codec(String),
}

impl From<CodecError> for StoreError {
    fn from(error: CodecError) -> Self {
        StoreError::Codec(error.to_string())
    }
}

impl From<KeyError> for StoreError {
    fn from(error: KeyError) -> Self {
        StoreError::Codec(error.to_string())
    }
}

impl Coded for StoreError {
    fn code(&self) -> &'static str {
        match self {
            StoreError::PreconditionFailed(_) => "sys.store.precondition_failed",
            StoreError::IdempotencyMismatch => "sys.store.idempotency_mismatch",
            StoreError::BatchTooLarge { .. } => "sys.store.batch_too_large",
            StoreError::NoQuorum => "sys.store.no_quorum",
            StoreError::Timeout => "sys.store.timeout",
            StoreError::ShuttingDown => "sys.store.shutting_down",
            StoreError::Compacted { .. } => "sys.store.compacted",
            StoreError::ReservedTable { .. } => "sys.store.reserved_table",
            StoreError::PlaintextSecret { .. } => "sys.store.plaintext_secret",
            StoreError::Storage(_) => "sys.store.storage",
            StoreError::Codec(_) => "sys.store.codec",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            StoreError::PreconditionFailed(_) => 409,
            StoreError::IdempotencyMismatch => 422,
            StoreError::BatchTooLarge { .. } => 413,
            StoreError::NoQuorum | StoreError::Timeout | StoreError::ShuttingDown => 503,
            StoreError::Compacted { .. } => 410,
            StoreError::ReservedTable { .. }
            | StoreError::PlaintextSecret { .. }
            | StoreError::Storage(_)
            | StoreError::Codec(_) => 500,
        }
    }

    fn params(&self) -> std::collections::BTreeMap<&'static str, String> {
        match self {
            StoreError::PreconditionFailed(failures) => {
                [("count", failures.len().to_string())].into()
            }
            StoreError::BatchTooLarge { size, limit } => {
                [("size", size.to_string()), ("limit", limit.to_string())].into()
            }
            StoreError::Compacted { oldest } => [("oldest", oldest.to_string())].into(),
            StoreError::ReservedTable { table } | StoreError::PlaintextSecret { table } => {
                [("table", table.to_string())].into()
            }
            _ => std::collections::BTreeMap::new(),
        }
    }
}

/// The replicated store (ADR 0002): one Raft group over redb in production, [`MemStore`]
/// in tests. Every package builds against this trait.
///
/// [`MemStore`]: crate::mem::MemStore
#[async_trait::async_trait]
pub trait Store: Send + Sync + 'static {
    /// Validates and applies a batch (see the module invariants).
    ///
    /// # Errors
    ///
    /// Returns the [`StoreError`] that stopped the batch; nothing was applied.
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError>;

    /// A consistent read view.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Timeout`] if `AtLeast` or `Linearizable` cannot be met in
    /// time, or [`StoreError::NoQuorum`].
    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError>;

    /// A stream of change sets after `from` (the last revision the caller has seen, as an
    /// SSE `Last-Event-ID`), then live ones. `None` starts at the current revision.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Compacted`] if revisions after `from` are no longer in the
    /// journal.
    fn watch(
        &self,
        from: Option<Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError>;

    /// Builds, installs and from then on maintains a derived index.
    ///
    /// # Errors
    ///
    /// Returns the error of [`DerivedIndex::build`].
    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError>;

    /// Role, leader, revision, lag and cached sizes.
    fn status(&self) -> StoreStatus;

    /// Who leads, as this member sees it: `None` while no leader is known. The value
    /// changes when the leader or the term changes and when this member's `is_self` turns
    /// true after it has applied its first commit of the term. The leader supervisor of
    /// `tenko serve` starts leader-only work on `is_self` and stops it when that ends.
    /// `MemStore` is always the leader.
    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<Leadership>>;

    // The reconciler's proposal batches (the Slice 8 follow-ups): the limit a writer splits
    // its work under.
    /// The payload limit of one batch ([`WriteBatch::payload_size`]), the store's
    /// `max_batch_bytes` ([`CoalescerConfig`]); a writer with more than that splits its
    /// work into batches below it. A store that wraps another and does not say reports the
    /// default limit.
    fn max_batch_bytes(&self) -> usize {
        CoalescerConfig::default().max_batch_bytes
    }
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verb = if self.deleted { "deleted" } else { "written" };
        write!(
            f,
            "{} {} {verb}",
            self.table,
            tenko_core::serde_util::to_hex(&self.key)
        )
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        SystemComponent, audit::AuditAction, codec::encode_key, secret::VaultEnvelope,
    };

    use super::*;

    const HOSTS: TableName = TableName::from_static("ipam.hosts");

    fn batch() -> WriteBatch {
        WriteBatch::new(
            Principal::system(SystemComponent::Ipam),
            "2026-10-09T12:00:00Z".parse().expect("time"),
        )
    }

    #[test]
    fn key_ranges() {
        let range = KeyRange::prefix(vec![1, 2]);
        assert!(range.contains(&[1, 2]));
        assert!(range.contains(&[1, 2, 0xFF]));
        assert!(!range.contains(&[1, 3]));
        assert!(!range.is_empty());
        assert!(KeyRange::between(vec![2], vec![1]).is_empty());
        assert!(KeyRange::between(vec![1], vec![1]).is_empty());
        assert!(!KeyRange::all().is_empty());
        let page = KeyRange::prefix(vec![1]).after(vec![1, 5]);
        assert!(!page.contains(&[1, 5]));
        assert!(page.contains(&[1, 6]));
    }

    #[test]
    fn validation_rejects_reserved_tables_secrets_and_size() {
        let mut b = batch();
        b.put(tables::AUDIT.name().clone(), vec![1], vec![2]);
        assert!(matches!(
            b.validate(1024),
            Err(StoreError::ReservedTable { .. })
        ));

        let secrets = TableName::from_static("vault.secrets");
        let mut b = batch();
        b.put(secrets.clone(), vec![1], b"plaintext".to_vec());
        assert!(matches!(
            b.validate(1024),
            Err(StoreError::PlaintextSecret { .. })
        ));

        let envelope = VaultEnvelope {
            format: 1,
            key_id: "kek".to_owned(),
            payload: Bytes::from_static(b"sealed"),
        }
        .to_bytes()
        .expect("envelope");
        let mut b = batch();
        b.put(secrets, vec![1], envelope);
        assert!(b.validate(1024).is_ok());

        let mut b = batch();
        b.put(HOSTS, vec![1], vec![0; 2048]);
        assert!(matches!(
            b.validate(1024),
            Err(StoreError::BatchTooLarge { limit: 1024, .. })
        ));
    }

    #[test]
    fn fingerprint_ignores_time_and_request() {
        let mut a = batch();
        a.put(HOSTS, encode_key(&1_u64), vec![1])
            .audit(AuditDraft::success(
                AuditAction::from_static("ipam.host.create"),
                vec![],
            ));
        let mut b = a.clone();
        b.proposed_at = "2026-10-10T00:00:00Z".parse().expect("time");
        b.request = Some(RequestId::generate());
        assert_eq!(a.fingerprint(), b.fingerprint());
        b.put(HOSTS, encode_key(&2_u64), vec![2]);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn filters_select_changes() {
        let changes = ChangeSet {
            revision: Revision(3),
            principal: Principal::system(SystemComponent::Ipam),
            at: Timestamp::UNIX_EPOCH,
            changes: vec![
                Change {
                    table: HOSTS,
                    key: Bytes::from_static(&[1]),
                    deleted: false,
                },
                Change {
                    table: tables::AUDIT.name().clone(),
                    key: Bytes::from_static(&[2]),
                    deleted: false,
                },
            ],
        };
        assert_eq!(WatchFilter::all().apply(&changes), Some(changes.clone()));
        let ipam = WatchFilter::namespaces(["ipam"])
            .apply(&changes)
            .expect("passes");
        assert_eq!(ipam.changes.len(), 1);
        assert_eq!(ipam.revision, Revision(3));
        assert!(
            WatchFilter::tables([TableName::from_static("jobs.jobs")])
                .apply(&changes)
                .is_none()
        );
    }

    #[test]
    fn fence_expects_the_leader_epoch() {
        let mut b = batch();
        b.preconditions.push(fence(7));
        assert_eq!(
            b.preconditions,
            vec![Precondition::Counter {
                counter: tenko_core::cluster::LEADER_EPOCH,
                expect: 7,
            }]
        );
        assert!(QuorumState::Single.accepts_writes());
        assert!(QuorumState::Healthy.accepts_writes());
        assert!(
            !QuorumState::Electing {
                since: Timestamp::UNIX_EPOCH
            }
            .accepts_writes()
        );
        assert_eq!(QuorumState::default(), QuorumState::Single);
    }

    #[test]
    fn errors_are_coded() {
        assert_eq!(StoreError::IdempotencyMismatch.http_status(), 422);
        assert_eq!(
            StoreError::Compacted {
                oldest: Revision(7)
            }
            .params()["oldest"],
            "7"
        );
        assert_eq!(
            WatchError::Lagged { last: Revision(1) }.code(),
            "sys.store.watch_lagged"
        );
    }
}
