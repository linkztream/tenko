//! Derived indexes of the Raft store: registration, exact incremental application and the
//! capture that lets an index be built aside while writers continue.
//!
//! Several batches commit in one redb transaction, but [`DerivedIndex::apply`] must see the
//! store at exactly the revision of each change set. [`replay`] does that with one view of
//! the committed state and a rollback overlay: for change set `k` the overlay holds, for
//! every key a later batch of the same run wrote, the value it had at revision `k`. The
//! overlay moves forward batch by batch, so the cost is linear in the number of writes.
//!
//! Registration builds an image from a read view without holding any lock that writers
//! need. While it builds, the apply path captures every applied batch (with its writes);
//! the registration then installs the image and replays the captured batches with the same
//! exact views, so the index never misses a change set and never sees a later state early.

use std::{collections::HashMap, sync::Arc};

use bytes::Bytes;
use tenko_core::{Revision, TableName};

use super::{
    apply::AppliedBatch,
    view::{Overlay, OverlayView},
};
use crate::api::{DerivedIndex, IndexStatus, ReadView, WatchFilter};

/// A registered index.
pub(crate) struct Registered {
    pub(crate) index: Arc<dyn DerivedIndex>,
    pub(crate) filter: WatchFilter,
    /// The last revision built or applied.
    pub(crate) revision: Revision,
    /// Memory use of the image at its last install.
    pub(crate) memory_bytes: usize,
}

impl Registered {
    pub(crate) fn status(&self) -> IndexStatus {
        IndexStatus {
            name: self.index.name().to_owned(),
            revision: self.revision,
            memory_bytes: self.memory_bytes,
        }
    }
}

/// Batches applied while a registration builds its image.
pub(crate) enum Capture {
    /// No registration in progress.
    Idle,
    /// A registration builds from a view; every applied batch since is kept here.
    Capturing(Vec<AppliedBatch>),
    /// A snapshot replaced the state during the build; the registration starts over.
    Invalidated,
}

/// The registered indexes and the registration capture. The apply path holds this lock
/// from the start of a transaction until its indexes are updated.
pub(crate) struct Registry {
    pub(crate) indexes: Vec<Registered>,
    pub(crate) capture: Capture,
}

impl Registry {
    pub(crate) fn new() -> Self {
        Self {
            indexes: Vec::new(),
            capture: Capture::Idle,
        }
    }

    /// Whether applied batches must keep their writes.
    pub(crate) fn wants_writes(&self) -> bool {
        !self.indexes.is_empty() || matches!(self.capture, Capture::Capturing(_))
    }

    /// Statuses of the registered indexes.
    pub(crate) fn statuses(&self) -> Vec<IndexStatus> {
        self.indexes.iter().map(Registered::status).collect()
    }

    /// Hands newly applied batches to the registered indexes (with exact views over
    /// `base`, the state after the last of them) and to a registration in progress.
    pub(crate) fn absorb(&mut self, base: &dyn ReadView, applied: Vec<AppliedBatch>) {
        if applied.is_empty() {
            return;
        }
        replay(base, &applied, &mut self.indexes);
        if let Capture::Capturing(captured) = &mut self.capture {
            captured.extend(applied);
        }
    }
}

/// Applies `batches` (consecutive revisions ending at `base`'s state) to `targets`, each
/// change set with a view at exactly its revision.
pub(crate) fn replay(base: &dyn ReadView, batches: &[AppliedBatch], targets: &mut [Registered]) {
    if batches.is_empty() || targets.is_empty() {
        return;
    }
    // The last batch that writes each key.
    let mut last_touch: HashMap<(&TableName, &Bytes), usize> = HashMap::new();
    for (position, batch) in batches.iter().enumerate() {
        for write in &batch.writes {
            last_touch.insert((&write.table, &write.key), position);
        }
    }
    // The view at the first batch: every key a later batch writes, as it was before that
    // write.
    let mut overlay = Overlay::new();
    for batch in &batches[1..] {
        for write in &batch.writes {
            overlay
                .entry((write.table.clone(), write.key.clone()))
                .or_insert_with(|| write.old.clone());
        }
    }
    for (position, batch) in batches.iter().enumerate() {
        let change_set = &batch.change_set;
        let view = OverlayView {
            base,
            overlay: &overlay,
            revision: change_set.revision,
        };
        for target in targets.iter_mut() {
            if let Some(filtered) = target.filter.apply(change_set) {
                target.index.apply(&filtered, &view);
            }
            target.revision = change_set.revision;
        }
        // Move the overlay to the next batch: the keys it writes now hold its values when a
        // later batch writes them again, and the committed values otherwise.
        let Some(next) = batches.get(position + 1) else {
            break;
        };
        for write in &next.writes {
            let key = (write.table.clone(), write.key.clone());
            let written_later = last_touch
                .get(&(&write.table, &write.key))
                .is_some_and(|last| *last > position + 1);
            if written_later {
                overlay.insert(key, write.new.clone());
            } else {
                overlay.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tenko_core::{CounterKey, Principal, SystemComponent, Timestamp};

    use super::*;
    use crate::api::{Change, ChangeSet, IndexImage, KeyRange, StoreError, Versioned, WatchFilter};
    use crate::raft::apply::Write;

    const ROWS: TableName = TableName::from_static("ipam.index_rows");

    /// The final state of a run, as a plain map.
    struct MapView {
        revision: Revision,
        rows: std::collections::BTreeMap<Bytes, Versioned>,
    }

    impl ReadView for MapView {
        fn revision(&self) -> Revision {
            self.revision
        }
        fn get(&self, _table: &TableName, key: &[u8]) -> Result<Option<Versioned>, StoreError> {
            Ok(self.rows.get(key).cloned())
        }
        fn scan(
            &self,
            _table: &TableName,
            range: KeyRange,
            limit: usize,
            reverse: bool,
        ) -> Result<Vec<(Bytes, Versioned)>, StoreError> {
            let rows = self
                .rows
                .iter()
                .filter(|(key, _)| range.contains(key))
                .map(|(key, value)| (key.clone(), value.clone()));
            Ok(if reverse {
                rows.rev().take(limit).collect()
            } else {
                rows.take(limit).collect()
            })
        }
        fn counter(&self, _counter: &CounterKey) -> Result<u64, StoreError> {
            Ok(0)
        }
    }

    /// What one `apply` saw: the revision, every key's value and the scanned keys.
    type Seen = (Revision, Vec<(u8, Option<u8>)>, Vec<u8>);

    /// Records, per applied revision, what the view returned for every key and a scan.
    #[derive(Default)]
    struct Probe {
        seen: Mutex<Vec<Seen>>,
    }

    impl DerivedIndex for Probe {
        fn build(&self, _view: &dyn ReadView) -> Result<Box<dyn IndexImage>, StoreError> {
            unreachable!("not built in this test")
        }
        fn install(&self, _image: Box<dyn IndexImage>) {}
        fn apply(&self, changes: &crate::api::ChangeSet, view: &dyn ReadView) {
            assert_eq!(view.revision(), changes.revision);
            let values = (1..=3_u8)
                .map(|k| {
                    let value = view.get(&ROWS, &[k]).expect("get");
                    (k, value.map(|v| v.value[0]))
                })
                .collect();
            let scanned = view
                .scan(&ROWS, KeyRange::all(), 10, false)
                .expect("scan")
                .into_iter()
                .map(|(key, _)| key[0])
                .collect();
            self.seen
                .lock()
                .expect("lock")
                .push((changes.revision, values, scanned));
        }
    }

    fn versioned(value: u8, revision: u64) -> Versioned {
        Versioned {
            value: Bytes::copy_from_slice(&[value]),
            revision: Revision(revision),
        }
    }

    fn batch(
        revision: u64,
        writes: Vec<(u8, Option<Versioned>, Option<Versioned>)>,
    ) -> AppliedBatch {
        AppliedBatch {
            change_set: ChangeSet {
                revision: Revision(revision),
                principal: Principal::system(SystemComponent::Ipam),
                at: Timestamp::UNIX_EPOCH,
                changes: writes
                    .iter()
                    .map(|(key, _, new)| Change {
                        table: ROWS,
                        key: Bytes::copy_from_slice(&[*key]),
                        deleted: new.is_none(),
                    })
                    .collect(),
            },
            writes: writes
                .into_iter()
                .map(|(key, old, new)| Write {
                    table: ROWS,
                    key: Bytes::copy_from_slice(&[key]),
                    old,
                    new,
                })
                .collect(),
        }
    }

    #[test]
    fn every_change_set_sees_its_own_revision() {
        // Before the run (revision 10): key 1 = 1, key 2 = 2.
        // 11: key 1 = 11.        12: delete key 2, key 3 = 12.        13: key 1 = 13.
        let batches = vec![
            batch(
                11,
                vec![(1, Some(versioned(1, 10)), Some(versioned(11, 11)))],
            ),
            batch(
                12,
                vec![
                    (2, Some(versioned(2, 10)), None),
                    (3, None, Some(versioned(12, 12))),
                ],
            ),
            batch(
                13,
                vec![(1, Some(versioned(11, 11)), Some(versioned(13, 13)))],
            ),
        ];
        let base = MapView {
            revision: Revision(13),
            rows: [
                (Bytes::from_static(&[1]), versioned(13, 13)),
                (Bytes::from_static(&[3]), versioned(12, 12)),
            ]
            .into(),
        };
        let probe = Arc::new(Probe::default());
        let mut targets = vec![Registered {
            index: probe.clone(),
            filter: WatchFilter::all(),
            revision: Revision(10),
            memory_bytes: 0,
        }];
        replay(&base, &batches, &mut targets);
        let seen = probe.seen.lock().expect("lock").clone();
        assert_eq!(
            seen,
            vec![
                (
                    Revision(11),
                    vec![(1, Some(11)), (2, Some(2)), (3, None)],
                    vec![1, 2]
                ),
                (
                    Revision(12),
                    vec![(1, Some(11)), (2, None), (3, Some(12))],
                    vec![1, 3]
                ),
                (
                    Revision(13),
                    vec![(1, Some(13)), (2, None), (3, Some(12))],
                    vec![1, 3]
                ),
            ]
        );
        assert_eq!(targets[0].revision, Revision(13));
    }
}
