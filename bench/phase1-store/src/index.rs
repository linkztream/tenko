//! A test `DerivedIndex` modelled on the serving index of Spike A.
//!
//! The image is a set of shards, each a `RwLock<HashMap<Bytes, Bytes>>`, behind an
//! `ArcSwap`. `apply` updates the live image in place (write-locking only the shards a change
//! touches); `build` scans the table in pages into a new image aside; `install` swaps the new
//! image in atomically, so a reader holds either the old or the new image and never an empty
//! one.

use std::{
    collections::HashMap,
    hash::{BuildHasher as _, RandomState},
    sync::{
        PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use arc_swap::ArcSwap;
use bytes::Bytes;
use tenko_core::{Revision, TableName};
use tenko_store::{
    ChangeSet, DerivedIndex, IndexImage, KeyRange, ReadView, StoreError, WatchFilter,
    downcast_image,
};

const SHARDS: usize = 64;
/// Rows per page of the build scan.
const PAGE: usize = 20_000;

type Shard = HashMap<Bytes, Bytes>;

fn shard_index(hasher: &RandomState, key: &[u8]) -> usize {
    usize::try_from(hasher.hash_one(key) % SHARDS as u64).unwrap_or(0)
}

/// One complete image of the index.
#[derive(Debug)]
pub struct Image {
    revision: AtomicU64,
    hasher: RandomState,
    shards: Vec<RwLock<Shard>>,
    raw_bytes: u64,
}

impl Image {
    fn empty() -> Self {
        Self {
            revision: AtomicU64::new(0),
            hasher: RandomState::new(),
            shards: (0..SHARDS).map(|_| RwLock::new(HashMap::new())).collect(),
            raw_bytes: 0,
        }
    }

    fn shard_of(&self, key: &[u8]) -> usize {
        shard_index(&self.hasher, key)
    }

    pub fn get(&self, key: &[u8]) -> Option<Bytes> {
        self.shards[self.shard_of(key)]
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.read().unwrap_or_else(PoisonError::into_inner).len())
            .sum()
    }
}

impl IndexImage for Image {
    fn revision(&self) -> Revision {
        Revision(self.revision.load(Ordering::Acquire))
    }

    fn memory_bytes(&self) -> usize {
        usize::try_from(self.raw_bytes).unwrap_or(usize::MAX)
    }
}

/// The index: `ArcSwap` over [`Image`].
#[derive(Debug)]
pub struct BenchIndex {
    table: TableName,
    live: ArcSwap<Image>,
}

impl BenchIndex {
    pub fn new(table: TableName) -> Self {
        Self {
            table,
            live: ArcSwap::from_pointee(Image::empty()),
        }
    }

    /// Looks a key up in the live image.
    pub fn get(&self, key: &[u8]) -> Option<Bytes> {
        self.live.load().get(key)
    }

    /// Records in the live image.
    pub fn len(&self) -> usize {
        self.live.load().len()
    }

    /// The revision the live image reflects.
    pub fn revision(&self) -> Revision {
        self.live.load().revision()
    }
}

impl DerivedIndex for BenchIndex {
    fn name(&self) -> &'static str {
        "phase1-store.bench-index"
    }

    fn filter(&self) -> WatchFilter {
        WatchFilter::tables([self.table.clone()])
    }

    fn build(&self, view: &dyn ReadView) -> Result<Box<dyn IndexImage>, StoreError> {
        let hasher = RandomState::new();
        let mut maps: Vec<Shard> = (0..SHARDS).map(|_| HashMap::new()).collect();
        let mut raw_bytes = 0_u64;
        let mut range = KeyRange::all();
        loop {
            let page = view.scan(&self.table, range.clone(), PAGE, false)?;
            let Some((last, _)) = page.last() else {
                break;
            };
            range = KeyRange::all().after(last.clone());
            let full = page.len() == PAGE;
            for (key, versioned) in page {
                raw_bytes += (key.len() + versioned.value.len()) as u64;
                maps[shard_index(&hasher, &key)].insert(key, versioned.value);
            }
            if !full {
                break;
            }
        }
        Ok(Box::new(Image {
            revision: AtomicU64::new(view.revision().get()),
            hasher,
            shards: maps.into_iter().map(RwLock::new).collect(),
            raw_bytes,
        }))
    }

    fn install(&self, image: Box<dyn IndexImage>) {
        if let Some(image) = downcast_image::<Image>(image) {
            self.live.store(std::sync::Arc::from(image));
        }
    }

    fn apply(&self, changes: &ChangeSet, view: &dyn ReadView) {
        let image = self.live.load();
        for change in changes.changes.iter().filter(|c| c.table == self.table) {
            let value = if change.deleted {
                None
            } else if let Ok(value) = view.get(&self.table, &change.key) {
                value
            } else {
                tracing::error!(table = %self.table, "reading a changed value failed");
                continue;
            };
            let mut shard = image.shards[image.shard_of(&change.key)]
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            match value {
                Some(versioned) => {
                    shard.insert(change.key.clone(), versioned.value);
                }
                None => {
                    shard.remove(&change.key[..]);
                }
            }
        }
        image
            .revision
            .store(changes.revision.get(), Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tenko_store::{MemStore, ReadConsistency, Store as _};

    use super::*;
    use crate::data::{self, RRSETS};

    #[tokio::test]
    async fn index_builds_applies_and_swaps() {
        let store = MemStore::default();
        let mut seed = data::put_batch(&[1, 2, 3, 4, 5], 0);
        seed.audit.clear();
        store.propose(seed).await.expect("seed");

        let index = Arc::new(BenchIndex::new(RRSETS));
        store.register_index(index.clone()).expect("register");
        assert_eq!(index.len(), 5);
        assert_eq!(
            data::generation_of(&index.get(&data::key_array(3)).expect("present")),
            Some(0)
        );

        let mut change = data::mixed_batch(&[3, 6], 1, &[1]);
        change.audit.clear();
        let committed = store.propose(change).await.expect("change");
        assert_eq!(index.len(), 5);
        assert!(index.get(&data::key_array(1)).is_none());
        assert_eq!(
            data::generation_of(&index.get(&data::key_array(3)).expect("updated")),
            Some(1)
        );
        assert!(index.get(&data::key_array(6)).is_some());
        assert_eq!(index.revision(), committed.revision);

        // A rebuilt image installs atomically.
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let image = index.build(view.as_ref()).expect("build");
        assert_eq!(image.revision(), committed.revision);
        index.install(image);
        assert_eq!(index.len(), 5);
    }
}
