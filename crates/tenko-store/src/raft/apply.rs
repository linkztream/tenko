//! Applying write batches inside one redb write transaction.
//!
//! This is the deterministic core of the state machine. Every replica runs it on the same
//! entries and reaches the same state: it never reads a clock or local configuration, only
//! the entry (batches, journal retention, fingerprints) and the transaction. The semantics
//! are those of `MemStore` (see `crate::api`):
//!
//! 1. A batch that fails to decode, writes a reserved table, repeats an idempotency key or
//!    fails a precondition becomes an outcome; nothing of it is written and it consumes no
//!    revision and no audit sequence number.
//! 2. Otherwise its mutations are staged in an overlay (a later mutation of the same key
//!    wins; a bump reads earlier staged bumps), its audit drafts are sealed into the chain
//!    with `at = proposed_at`, its idempotency record and its journal change set are staged,
//!    and only then is the overlay written, under the next revision.
//! 3. Batches of one entry apply in order, each against its own preconditions: a batch reads
//!    what the previous batches of the same transaction wrote.
//!
//! Storage failures are not outcomes: they abort the transaction and stop the state machine
//! (`StoreError::Storage` here, converted to openraft's storage error at the boundary).

use std::collections::{BTreeMap, HashMap, hash_map::Entry as MapEntry};

use bytes::Bytes;
use redb::{ReadableTable, Table, WriteTransaction};
use serde::{Deserialize, Serialize};
use tenko_core::{
    AuditSeq, CounterKey, Revision, TableName,
    audit::{AuditRecord, ChainHead, Digest},
    codec::{CodecError, encode_key, from_cbor, to_cbor},
};

use super::{
    stored::{
        SmMeta, data_table, decode_counter, decode_stored, encode_stored, len_u64, storage,
        stored_value_len,
    },
    types::{BatchOutcome, ProposedBatch},
};
use crate::api::{
    Change, ChangeSet, Committed, FailedPrecondition, Mutation, Precondition, StoreError,
    Versioned, WriteBatch, tables,
};

/// Staged writes of one batch, by table and key; `None` is a deletion.
type Staged = BTreeMap<(TableName, Bytes), Option<Bytes>>;

/// The idempotency record of a committed batch.
#[derive(Serialize, Deserialize)]
struct IdempotencyRecord {
    fingerprint: Digest,
    committed: Committed,
}

/// The journal after a batch: oldest revision, change sets and their bytes.
struct JournalBounds {
    oldest: Revision,
    len: u64,
    bytes: u64,
}

/// One key written by an applied batch, with its values before and after.
#[derive(Debug, Clone)]
pub(crate) struct Write {
    pub(crate) table: TableName,
    pub(crate) key: Bytes,
    pub(crate) old: Option<Versioned>,
    pub(crate) new: Option<Versioned>,
}

/// An applied batch as derived indexes need it: the change set and every write.
#[derive(Debug, Clone)]
pub(crate) struct AppliedBatch {
    pub(crate) change_set: ChangeSet,
    pub(crate) writes: Vec<Write>,
}

/// Store tables opened in one write transaction, opened on first use.
pub(crate) struct TxnTables<'txn> {
    txn: &'txn WriteTransaction,
    open: HashMap<TableName, Table<'txn, &'static [u8], &'static [u8]>>,
}

impl<'txn> TxnTables<'txn> {
    pub(crate) fn new(txn: &'txn WriteTransaction) -> Self {
        Self {
            txn,
            open: HashMap::new(),
        }
    }

    fn table(
        &mut self,
        name: &TableName,
    ) -> Result<&mut Table<'txn, &'static [u8], &'static [u8]>, StoreError> {
        Ok(match self.open.entry(name.clone()) {
            MapEntry::Occupied(entry) => entry.into_mut(),
            MapEntry::Vacant(entry) => {
                entry.insert(self.txn.open_table(data_table(name)).map_err(storage)?)
            }
        })
    }

    /// The current value of a key, including writes earlier in this transaction.
    pub(crate) fn get(
        &mut self,
        name: &TableName,
        key: &[u8],
    ) -> Result<Option<Versioned>, StoreError> {
        let table = self.table(name)?;
        let value = table.get(key).map_err(storage)?;
        value.map(|value| decode_stored(value.value())).transpose()
    }

    /// The length of a stored value (without its revision), without copying it.
    fn value_len(&mut self, name: &TableName, key: &[u8]) -> Result<Option<usize>, StoreError> {
        Ok(self
            .table(name)?
            .get(key)
            .map_err(storage)?
            .map(|value| stored_value_len(value.value())))
    }

    fn exists(&mut self, name: &TableName, key: &[u8]) -> Result<bool, StoreError> {
        Ok(self.table(name)?.get(key).map_err(storage)?.is_some())
    }

    fn counter(&mut self, counter: &CounterKey) -> Result<u64, StoreError> {
        let value = self.get(&tables::COUNTERS, &encode_key(counter))?;
        decode_counter(value.as_ref().map(|versioned| &versioned.value[..]))
    }

    /// Writes (`Some`) or removes (`None`) a value. Returns the length of the previous
    /// value part, and the previous value itself when `keep_old`.
    fn write(
        &mut self,
        name: &TableName,
        key: &[u8],
        stored: Option<&[u8]>,
        keep_old: bool,
    ) -> Result<(Option<usize>, Option<Versioned>), StoreError> {
        let table = self.table(name)?;
        let previous = match stored {
            Some(stored) => table.insert(key, stored).map_err(storage)?,
            None => table.remove(key).map_err(storage)?,
        };
        let Some(previous) = previous else {
            return Ok((None, None));
        };
        let raw = previous.value();
        let old = if keep_old {
            Some(decode_stored(raw)?)
        } else {
            None
        };
        Ok((Some(stored_value_len(raw)), old))
    }

    /// Releases the open tables (they borrow the transaction, which must be committed).
    pub(crate) fn close(self) {
        drop(self.open);
    }
}

/// Applies the batches of one transaction and collects what derived indexes need.
pub(crate) struct Applier<'a, 'txn> {
    tables: TxnTables<'txn>,
    meta: &'a mut SmMeta,
    capture: bool,
    applied: Vec<AppliedBatch>,
}

impl<'a, 'txn> Applier<'a, 'txn> {
    /// An applier over `tables`; `capture` keeps every write for derived indexes.
    pub(crate) fn new(tables: TxnTables<'txn>, meta: &'a mut SmMeta, capture: bool) -> Self {
        Self {
            tables,
            meta,
            capture,
            applied: Vec::new(),
        }
    }

    /// The metadata being updated.
    pub(crate) fn meta(&mut self) -> &mut SmMeta {
        self.meta
    }

    /// Ends the transaction's work: releases the tables and returns the applied batches
    /// (empty unless capturing).
    pub(crate) fn finish(self) -> Vec<AppliedBatch> {
        self.tables.close();
        self.applied
    }

    /// Applies one batch of an entry.
    pub(crate) fn apply(
        &mut self,
        proposed: &ProposedBatch,
        journal_retention: u64,
        journal_max_bytes: u64,
    ) -> Result<BatchOutcome, StoreError> {
        let batch: WriteBatch = match from_cbor(&proposed.batch) {
            Ok(batch) => batch,
            Err(error) => return Ok(BatchOutcome::Codec(error.to_string())),
        };
        if let Some(table) = reserved_write(&batch) {
            return Ok(BatchOutcome::ReservedTable(table));
        }

        // 1. Idempotency: a repeated key returns the first commit.
        let idempotency = match &batch.idempotency {
            Some(key) => {
                let fingerprint = match proposed.fingerprint {
                    Some(fingerprint) => fingerprint,
                    None => match batch.fingerprint() {
                        Ok(fingerprint) => fingerprint,
                        Err(error) => return Ok(BatchOutcome::Codec(error.to_string())),
                    },
                };
                Some((
                    encode_key(&(batch.principal.subject(), key.as_str().to_owned())),
                    fingerprint,
                ))
            }
            None => None,
        };
        if let Some((key, fingerprint)) = &idempotency
            && let Some(existing) = self.tables.get(&tables::IDEMPOTENCY, key)?
        {
            let record: IdempotencyRecord = match from_cbor(&existing.value) {
                Ok(record) => record,
                Err(error) => return Ok(BatchOutcome::Codec(error.to_string())),
            };
            return Ok(if record.fingerprint == *fingerprint {
                BatchOutcome::Committed(Committed {
                    replayed: true,
                    ..record.committed
                })
            } else {
                BatchOutcome::IdempotencyMismatch
            });
        }

        // 2. Preconditions, all reported together.
        let failures = self.check_preconditions(&batch)?;
        if !failures.is_empty() {
            return Ok(BatchOutcome::PreconditionFailed(failures));
        }

        self.commit_batch(&batch, idempotency, (journal_retention, journal_max_bytes))
    }

    /// Stages and writes a batch whose preconditions hold.
    fn commit_batch(
        &mut self,
        batch: &WriteBatch,
        idempotency: Option<(Bytes, Digest)>,
        (journal_retention, journal_max_bytes): (u64, u64),
    ) -> Result<BatchOutcome, StoreError> {
        // 3. Stage everything; nothing may fail once writing starts.
        let revision = self.meta.revision.next();
        let mut staged = self.stage_mutations(&batch.mutations)?;
        let staged_rest = (|| -> Result<_, CodecError> {
            let (head, sequence) = stage_audit(batch, self.meta.audit_head, revision, &mut staged)?;
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
                staged.insert((tables::IDEMPOTENCY, key), Some(to_cbor(&record)?));
            }
            Ok((head, committed))
        })();
        let (head, committed) = match staged_rest {
            Ok(staged) => staged,
            Err(error) => return Ok(BatchOutcome::Codec(error.to_string())),
        };
        let change_set = ChangeSet {
            revision,
            principal: batch.principal.clone(),
            at: batch.proposed_at,
            changes: self.change_list(&staged)?,
        };
        let encoded = match tables::JOURNAL.encode(&change_set) {
            Ok(encoded) => encoded,
            Err(error) => return Ok(BatchOutcome::Codec(error.to_string())),
        };
        let added = encoded.len();
        staged.insert(
            (
                tables::JOURNAL.name().clone(),
                tables::JOURNAL.key(&revision),
            ),
            Some(encoded),
        );
        let journal = self.trim_journal(
            revision,
            added,
            journal_retention,
            journal_max_bytes,
            &mut staged,
        )?;

        // 4. Write.
        let mut writes = Vec::new();
        let mut data_bytes = self.meta.data_bytes;
        for ((table, key), value) in staged {
            let stored = value.as_ref().map(|value| encode_stored(revision, value));
            let (previous_len, old) =
                self.tables
                    .write(&table, &key, stored.as_deref(), self.capture)?;
            if let Some(previous_len) = previous_len {
                data_bytes = data_bytes.saturating_sub(len_u64(key.len() + previous_len));
            }
            if let Some(value) = &value {
                data_bytes = data_bytes.saturating_add(len_u64(key.len() + value.len()));
            }
            if self.capture {
                writes.push(Write {
                    table,
                    key,
                    old,
                    new: value.map(|value| Versioned { value, revision }),
                });
            }
        }
        self.meta.revision = revision;
        self.meta.audit_head = head;
        self.meta.journal_oldest = Some(journal.oldest);
        self.meta.journal_len = journal.len;
        self.meta.journal_bytes = journal.bytes;
        self.meta.data_bytes = data_bytes;
        if self.capture {
            self.applied.push(AppliedBatch { change_set, writes });
        }
        Ok(BatchOutcome::Committed(committed))
    }

    /// Stages the removal of the oldest journal entries while the journal, including the
    /// entry just staged for `revision` (`added` bytes), holds more than `retention` change
    /// sets or more than `max_bytes` bytes (`0`: no byte limit). The newest change set always
    /// stays. Both limits come from the entry, so every replica trims identically.
    fn trim_journal(
        &mut self,
        revision: Revision,
        added: usize,
        retention: u64,
        max_bytes: u64,
        staged: &mut Staged,
    ) -> Result<JournalBounds, StoreError> {
        let retention = retention.max(1);
        let max_bytes = if max_bytes == 0 { u64::MAX } else { max_bytes };
        let mut oldest = self.meta.journal_oldest.unwrap_or(revision);
        let mut len = self.meta.journal_len + 1;
        let mut bytes = self.meta.journal_bytes.saturating_add(len_u64(added));
        while len > 1 && (len > retention || bytes > max_bytes) {
            let key = tables::JOURNAL.key(&oldest);
            let size = self
                .tables
                .value_len(tables::JOURNAL.name(), &key)?
                .unwrap_or(0);
            staged.insert((tables::JOURNAL.name().clone(), key), None);
            bytes = bytes.saturating_sub(len_u64(size));
            oldest = oldest.next();
            len -= 1;
        }
        Ok(JournalBounds { oldest, len, bytes })
    }

    fn check_preconditions(
        &mut self,
        batch: &WriteBatch,
    ) -> Result<Vec<FailedPrecondition>, StoreError> {
        let mut failures = Vec::new();
        for precondition in &batch.preconditions {
            match precondition {
                Precondition::Version { table, key, expect } => {
                    let actual = self
                        .tables
                        .get(table, key)?
                        .map(|versioned| versioned.revision);
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
                    let actual = self.tables.counter(counter)?;
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

    /// Stages the mutations; bumps read earlier staged values of the same counter.
    fn stage_mutations(&mut self, mutations: &[Mutation]) -> Result<Staged, StoreError> {
        let mut staged = Staged::new();
        for mutation in mutations {
            match mutation {
                Mutation::Put { table, key, value } => {
                    staged.insert((table.clone(), key.clone()), Some(value.clone()));
                }
                Mutation::Delete { table, key } => {
                    staged.insert((table.clone(), key.clone()), None);
                }
                Mutation::Bump { counter } => {
                    let key = encode_key(counter);
                    let current = match staged.get(&(tables::COUNTERS, key.clone())) {
                        Some(value) => decode_counter(value.as_deref())?,
                        None => self.tables.counter(counter)?,
                    };
                    staged.insert(
                        (tables::COUNTERS, key),
                        Some(Bytes::copy_from_slice(
                            &current.wrapping_add(1).to_be_bytes(),
                        )),
                    );
                }
            }
        }
        Ok(staged)
    }

    /// The changed keys of journaled tables, sorted, once per key; deleting an absent key is
    /// not a change.
    fn change_list(&mut self, staged: &Staged) -> Result<Vec<Change>, StoreError> {
        let mut changes = Vec::new();
        for ((table, key), value) in staged {
            if !is_journaled(table) {
                continue;
            }
            let deleted = match value {
                Some(_) => false,
                None if self.tables.exists(table, key)? => true,
                None => continue,
            };
            changes.push(Change {
                table: table.clone(),
                key: key.clone(),
                deleted,
            });
        }
        Ok(changes)
    }
}

/// The first reserved table a batch writes, if any (validation runs before the log; this
/// keeps a replica safe from a batch that skipped it).
fn reserved_write(batch: &WriteBatch) -> Option<TableName> {
    batch.mutations.iter().find_map(|mutation| match mutation {
        Mutation::Put { table, .. } | Mutation::Delete { table, .. }
            if tables::is_reserved(table) =>
        {
            Some(table.clone())
        }
        _ => None,
    })
}

/// Tables whose changes appear in change sets.
fn is_journaled(table: &TableName) -> bool {
    *table != tables::COUNTERS && *table != tables::IDEMPOTENCY && table != tables::JOURNAL.name()
}

/// Seals the batch's audit drafts into chained records and stages them.
fn stage_audit(
    batch: &WriteBatch,
    mut head: ChainHead,
    revision: Revision,
    staged: &mut Staged,
) -> Result<(ChainHead, Vec<AuditSeq>), CodecError> {
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
        staged.insert(
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
