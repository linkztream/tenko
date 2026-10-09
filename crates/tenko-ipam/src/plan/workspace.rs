//! The planner's working set: a read view with staged writes on top, and the read set
//! that becomes the batch's preconditions.
//!
//! Reads through [`Workspace::get`] see staged writes first, then the view. A tracked read
//! of a key the plan has not written records the revision it saw (or its absence) as a
//! version precondition, so the batch fails at apply if that key changed since the plan
//! read it (optimistic concurrency, ADR 0011). Scans and untracked reads record nothing;
//! the caller covers them with a counter precondition ([`Workspace::expect`]), because a
//! counter is bumped whenever the scanned set changes.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
};

use bytes::Bytes;
use serde::{Serialize, de::DeserializeOwned};
use tenko_core::{CounterKey, Revision, TableName, codec::KeyCodec, table::TableDef};
use tenko_store::{KeyRange, Mutation, Precondition, ReadView};

use crate::error::IpamResult;

/// A view plus staged writes and the recorded read set.
pub(crate) struct Workspace<'v> {
    view: &'v dyn ReadView,
    staged: BTreeMap<(TableName, Bytes), Option<Bytes>>,
    reads: BTreeMap<(TableName, Bytes), Option<Revision>>,
    counters: BTreeMap<CounterKey, u64>,
    bumps: BTreeSet<CounterKey>,
}

impl<'v> Workspace<'v> {
    pub(crate) fn new(view: &'v dyn ReadView) -> Self {
        Self {
            view,
            staged: BTreeMap::new(),
            reads: BTreeMap::new(),
            counters: BTreeMap::new(),
            bumps: BTreeSet::new(),
        }
    }

    /// The revision of the underlying view.
    pub(crate) fn revision(&self) -> Revision {
        self.view.revision()
    }

    /// Reads a key. Returns the value and, when it comes from the view, its revision
    /// (`None` for a value staged by this plan). With `track`, a view read records a
    /// version precondition.
    pub(crate) fn get(
        &mut self,
        table: &TableName,
        key: &[u8],
        track: bool,
    ) -> IpamResult<Option<(Bytes, Option<Revision>)>> {
        let slot = (table.clone(), Bytes::copy_from_slice(key));
        if let Some(staged) = self.staged.get(&slot) {
            return Ok(staged.clone().map(|value| (value, None)));
        }
        let found = self.view.get(table, key)?;
        if track {
            self.reads
                .entry(slot)
                .or_insert_with(|| found.as_ref().map(|v| v.revision));
        }
        Ok(found.map(|versioned| (versioned.value, Some(versioned.revision))))
    }

    /// Typed [`get`](Self::get).
    pub(crate) fn get_typed<K: KeyCodec, V: Serialize + DeserializeOwned>(
        &mut self,
        table: &TableDef<K, V>,
        key: &K,
        track: bool,
    ) -> IpamResult<Option<(V, Option<Revision>)>> {
        match self.get(table.name(), &table.key(key), track)? {
            Some((bytes, revision)) => Ok(Some((table.decode(&bytes)?, revision))),
            None => Ok(None),
        }
    }

    /// Whether a key exists (tracked when `track`).
    pub(crate) fn exists<K: KeyCodec, V: Serialize + DeserializeOwned>(
        &mut self,
        table: &TableDef<K, V>,
        key: &K,
        track: bool,
    ) -> IpamResult<bool> {
        Ok(self.get(table.name(), &table.key(key), track)?.is_some())
    }

    /// Stages a write.
    pub(crate) fn put_typed<K: KeyCodec, V: Serialize + DeserializeOwned>(
        &mut self,
        table: &TableDef<K, V>,
        key: &K,
        value: &V,
    ) -> IpamResult<()> {
        let value = table.encode(value)?;
        self.staged
            .insert((table.name().clone(), table.key(key)), Some(value));
        Ok(())
    }

    /// Stages a removal.
    pub(crate) fn delete_typed<K: KeyCodec, V: Serialize + DeserializeOwned>(
        &mut self,
        table: &TableDef<K, V>,
        key: &K,
    ) {
        self.staged
            .insert((table.name().clone(), table.key(key)), None);
    }

    /// Every entry of `range` in key order, staged writes applied. Records nothing.
    pub(crate) fn scan(
        &self,
        table: &TableName,
        range: &KeyRange,
    ) -> IpamResult<Vec<(Bytes, Bytes)>> {
        let mut merged: BTreeMap<Bytes, Bytes> = self
            .view
            .scan(table, range.clone(), usize::MAX, false)?
            .into_iter()
            .map(|(key, versioned)| (key, versioned.value))
            .collect();
        let start = match &range.start {
            Bound::Included(start) | Bound::Excluded(start) => start.clone(),
            Bound::Unbounded => Bytes::new(),
        };
        for ((staged_table, key), value) in self
            .staged
            .range((Bound::Included((table.clone(), start)), Bound::Unbounded))
        {
            if staged_table != table {
                break;
            }
            if !range.contains(key) {
                if range_ended(range, key) {
                    break;
                }
                continue;
            }
            match value {
                Some(value) => {
                    merged.insert(key.clone(), value.clone());
                }
                None => {
                    merged.remove(key);
                }
            }
        }
        Ok(merged.into_iter().collect())
    }

    /// Typed [`scan`](Self::scan).
    pub(crate) fn scan_typed<K: KeyCodec, V: Serialize + DeserializeOwned>(
        &self,
        table: &TableDef<K, V>,
        range: &KeyRange,
    ) -> IpamResult<Vec<(K, V)>> {
        self.scan(table.name(), range)?
            .into_iter()
            .map(|(key, value)| Ok((table.decode_key(&key)?, table.decode(&value)?)))
            .collect()
    }

    /// Typed keys of a scan, values ignored.
    pub(crate) fn scan_keys<K: KeyCodec, V: Serialize + DeserializeOwned>(
        &self,
        table: &TableDef<K, V>,
        range: &KeyRange,
    ) -> IpamResult<Vec<K>> {
        self.scan(table.name(), range)?
            .into_iter()
            .map(|(key, _)| Ok(table.decode_key(&key)?))
            .collect()
    }

    /// Expects the counter to keep the value it has in the view; returns that value.
    pub(crate) fn expect(&mut self, counter: &CounterKey) -> IpamResult<u64> {
        if let Some(value) = self.counters.get(counter) {
            return Ok(*value);
        }
        let value = self.view.counter(counter)?;
        self.counters.insert(counter.clone(), value);
        Ok(value)
    }

    /// Expects the counter and bumps it once in this batch.
    pub(crate) fn expect_and_bump(&mut self, counter: &CounterKey) -> IpamResult<()> {
        self.expect(counter)?;
        self.bumps.insert(counter.clone());
        Ok(())
    }

    /// Bumps a counter once in this batch without expecting it.
    pub(crate) fn bump(&mut self, counter: &CounterKey) {
        self.bumps.insert(counter.clone());
    }

    /// Whether anything was staged.
    pub(crate) fn has_writes(&self) -> bool {
        !self.staged.is_empty() || !self.bumps.is_empty()
    }

    /// The preconditions and mutations, in a deterministic order: version preconditions
    /// by table and key, then counter preconditions; writes by table and key, then bumps.
    pub(crate) fn into_parts(self) -> (Vec<Precondition>, Vec<Mutation>) {
        let mut preconditions: Vec<Precondition> = self
            .reads
            .into_iter()
            .map(|((table, key), expect)| Precondition::Version { table, key, expect })
            .collect();
        preconditions.extend(
            self.counters
                .into_iter()
                .map(|(counter, expect)| Precondition::Counter { counter, expect }),
        );
        let mut mutations: Vec<Mutation> = self
            .staged
            .into_iter()
            .map(|((table, key), value)| match value {
                Some(value) => Mutation::Put { table, key, value },
                None => Mutation::Delete { table, key },
            })
            .collect();
        mutations.extend(
            self.bumps
                .into_iter()
                .map(|counter| Mutation::Bump { counter }),
        );
        (preconditions, mutations)
    }
}

/// Whether every key at or after `key` lies beyond the range's end.
fn range_ended(range: &KeyRange, key: &[u8]) -> bool {
    match &range.end {
        Bound::Included(end) => key > &end[..],
        Bound::Excluded(end) => key >= &end[..],
        Bound::Unbounded => false,
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{PrefixId, codec::encode_key};
    use tenko_store::{MemStore, Store, WriteBatch};

    use super::*;
    use crate::{tables::PREFIX_RANGES, testutil::principal};

    #[tokio::test]
    async fn staged_writes_overlay_the_view_and_reads_become_preconditions() {
        let store = MemStore::default();
        let prefix = PrefixId::generate();
        let ranges: Vec<_> = (0..3).map(|_| tenko_core::RangeId::generate()).collect();
        let mut batch = WriteBatch::new(principal(), tenko_core::Timestamp::now());
        for range in &ranges {
            batch
                .put_typed(&PREFIX_RANGES, &(prefix, *range), &())
                .expect("put");
        }
        let committed = store.propose(batch).await.expect("commit");
        let view = store
            .read(tenko_store::ReadConsistency::Local)
            .await
            .expect("view");

        let mut ws = Workspace::new(view.as_ref());
        let extra = tenko_core::RangeId::generate();
        ws.put_typed(&PREFIX_RANGES, &(prefix, extra), &())
            .expect("put");
        ws.delete_typed(&PREFIX_RANGES, &(prefix, ranges[0]));
        let keys = ws
            .scan_keys(&PREFIX_RANGES, &KeyRange::prefix(encode_key(&prefix)))
            .expect("scan");
        assert_eq!(keys.len(), 3);
        assert!(!keys.contains(&(prefix, ranges[0])));
        assert!(keys.contains(&(prefix, extra)));

        let seen = ws
            .get_typed(&PREFIX_RANGES, &(prefix, ranges[1]), true)
            .expect("get");
        assert_eq!(seen, Some(((), Some(committed.revision))));
        let staged = ws
            .get_typed(&PREFIX_RANGES, &(prefix, extra), true)
            .expect("get");
        assert_eq!(staged, Some(((), None)));
        let counter = crate::tables::alloc_counter(prefix);
        ws.expect_and_bump(&counter).expect("counter");

        let (preconditions, mutations) = ws.into_parts();
        assert_eq!(preconditions.len(), 2);
        assert_eq!(mutations.len(), 3);
        assert!(matches!(mutations.last(), Some(Mutation::Bump { .. })));
    }
}
