//! Read views over `sm.redb`.
//!
//! [`RedbView`] wraps one redb read transaction (an MVCC snapshot) and the [`SmMeta`] read
//! in it, so its revision, its data and its journal bounds always agree. Writers never wait
//! for it.
//!
//! [`OverlayView`] reads the store as of an earlier revision than its base view: the overlay
//! holds, for every key written after that revision, the value it had then (`None`: absent).
//! The apply path uses it to hand each derived index a view at exactly the revision of the
//! change set it applies, although several batches commit in one redb transaction.

use std::{collections::BTreeMap, ops::Bound};

use bytes::Bytes;
use redb::{AccessGuard, Database, ReadOnlyTable, ReadTransaction, ReadableDatabase, TableError};
use tenko_core::{CounterKey, Revision, TableName, codec::encode_key};

use super::stored::{META, META_STATE, SmMeta, data_table, decode_counter, decode_stored, storage};
use crate::api::{KeyRange, ReadView, StoreError, Versioned, tables};

/// The values keys had at an earlier revision, by table and key (`None`: absent).
pub(crate) type Overlay = BTreeMap<(TableName, Bytes), Option<Versioned>>;

type RawTable = ReadOnlyTable<&'static [u8], &'static [u8]>;

type RawRow<'a> = (
    AccessGuard<'a, &'static [u8]>,
    AccessGuard<'a, &'static [u8]>,
);

/// A read view over one redb read transaction.
pub(crate) struct RedbView {
    txn: ReadTransaction,
    meta: SmMeta,
}

impl RedbView {
    /// Opens a view at the last committed state.
    pub(crate) fn open(db: &Database) -> Result<Self, StoreError> {
        let txn = db.begin_read().map_err(storage)?;
        let meta = read_meta(&txn)?;
        Ok(Self { txn, meta })
    }

    /// The metadata as of this view.
    pub(crate) fn meta(&self) -> &SmMeta {
        &self.meta
    }

    /// The read transaction.
    pub(crate) fn txn(&self) -> &ReadTransaction {
        &self.txn
    }

    fn table(&self, table: &TableName) -> Result<Option<RawTable>, StoreError> {
        match self.txn.open_table(data_table(table)) {
            Ok(table) => Ok(Some(table)),
            Err(TableError::TableDoesNotExist(_)) => Ok(None),
            Err(error) => Err(storage(error)),
        }
    }
}

/// Reads the metadata row of a read transaction (defaults for a new database).
pub(crate) fn read_meta(txn: &ReadTransaction) -> Result<SmMeta, StoreError> {
    let table = match txn.open_table(META) {
        Ok(table) => table,
        Err(TableError::TableDoesNotExist(_)) => return Ok(SmMeta::default()),
        Err(error) => return Err(storage(error)),
    };
    match table.get(META_STATE).map_err(storage)? {
        Some(value) => SmMeta::decode(value.value()),
        None => Ok(SmMeta::default()),
    }
}

fn decode_row(
    item: Result<RawRow<'_>, redb::StorageError>,
) -> Result<(Bytes, Versioned), StoreError> {
    let (key, value) = item.map_err(storage)?;
    Ok((
        Bytes::copy_from_slice(key.value()),
        decode_stored(value.value())?,
    ))
}

impl ReadView for RedbView {
    fn revision(&self) -> Revision {
        self.meta.revision
    }

    fn get(&self, table: &TableName, key: &[u8]) -> Result<Option<Versioned>, StoreError> {
        let Some(rows) = self.table(table)? else {
            return Ok(None);
        };
        rows.get(key)
            .map_err(storage)?
            .map(|value| decode_stored(value.value()))
            .transpose()
    }

    fn scan(
        &self,
        table: &TableName,
        range: KeyRange,
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Bytes, Versioned)>, StoreError> {
        if limit == 0 || range.is_empty() {
            return Ok(Vec::new());
        }
        let Some(rows) = self.table(table)? else {
            return Ok(Vec::new());
        };
        let bounds: (Bound<&[u8]>, Bound<&[u8]>) = (
            range.start.as_ref().map(|key| &key[..]),
            range.end.as_ref().map(|key| &key[..]),
        );
        let iter = rows.range::<&[u8]>(bounds).map_err(storage)?;
        if reverse {
            iter.rev().take(limit).map(decode_row).collect()
        } else {
            iter.take(limit).map(decode_row).collect()
        }
    }

    fn counter(&self, counter: &CounterKey) -> Result<u64, StoreError> {
        let value = self.get(&tables::COUNTERS, &encode_key(counter))?;
        decode_counter(value.as_ref().map(|versioned| &versioned.value[..]))
    }
}

/// A view at an earlier revision than its base: overlay entries win over the base.
pub(crate) struct OverlayView<'a> {
    /// The newer view.
    pub(crate) base: &'a dyn ReadView,
    /// Values as of `revision` for keys written after it.
    pub(crate) overlay: &'a Overlay,
    /// The revision this view reads at.
    pub(crate) revision: Revision,
}

impl OverlayView<'_> {
    /// Overlay entries of `table` inside `range`, in key order.
    fn overlay_range(
        &self,
        table: &TableName,
        range: &KeyRange,
    ) -> Vec<(Bytes, Option<Versioned>)> {
        let start = match &range.start {
            Bound::Included(key) => Bound::Included((table.clone(), key.clone())),
            Bound::Excluded(key) => Bound::Excluded((table.clone(), key.clone())),
            Bound::Unbounded => Bound::Included((table.clone(), Bytes::new())),
        };
        let end = match &range.end {
            Bound::Included(key) => Bound::Included((table.clone(), key.clone())),
            Bound::Excluded(key) => Bound::Excluded((table.clone(), key.clone())),
            Bound::Unbounded => Bound::Unbounded,
        };
        self.overlay
            .range((start, end))
            .take_while(|((name, _), _)| name == table)
            .map(|((_, key), value)| (key.clone(), value.clone()))
            .collect()
    }
}

impl ReadView for OverlayView<'_> {
    fn revision(&self) -> Revision {
        self.revision
    }

    fn get(&self, table: &TableName, key: &[u8]) -> Result<Option<Versioned>, StoreError> {
        match self
            .overlay
            .get(&(table.clone(), Bytes::copy_from_slice(key)))
        {
            Some(value) => Ok(value.clone()),
            None => self.base.get(table, key),
        }
    }

    fn scan(
        &self,
        table: &TableName,
        range: KeyRange,
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Bytes, Versioned)>, StoreError> {
        if limit == 0 || range.is_empty() {
            return Ok(Vec::new());
        }
        let overlaid = self.overlay_range(table, &range);
        if overlaid.is_empty() {
            return self.base.scan(table, range, limit, reverse);
        }
        // Each overlay entry can hide at most one base row, so `limit` plus their number of
        // base rows always cover the first `limit` rows of the merged result.
        let base = self
            .base
            .scan(table, range, limit.saturating_add(overlaid.len()), reverse)?;
        let mut merged: BTreeMap<Bytes, Option<Versioned>> = base
            .into_iter()
            .map(|(key, value)| (key, Some(value)))
            .collect();
        merged.extend(overlaid);
        let live = |(key, value): (Bytes, Option<Versioned>)| value.map(|value| (key, value));
        Ok(if reverse {
            merged
                .into_iter()
                .rev()
                .filter_map(live)
                .take(limit)
                .collect()
        } else {
            merged.into_iter().filter_map(live).take(limit).collect()
        })
    }

    fn counter(&self, counter: &CounterKey) -> Result<u64, StoreError> {
        let value = self.get(&tables::COUNTERS, &encode_key(counter))?;
        decode_counter(value.as_ref().map(|versioned| &versioned.value[..]))
    }
}
