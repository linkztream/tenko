//! The disk guard of the Raft store: the free space of the data directory's file system
//! against two lines computed from the store's own sizes, so that a snapshot, a compaction
//! and a start always fit (a full disk stopped a store for good once).
//!
//! - `reserve` = the live data + 2 × the latest snapshot + 256 MiB: room for one re-seed (a
//!   compacted copy of the live data), the next snapshot beside the current one, and the log.
//! - `margin` = 2 × `reserve`.
//!
//! Above the margin every batch passes. Below it only batches that free space pass: every
//! mutation deletes, bumps a counter or replaces a value with one no larger, with at most
//! one audit draft of at most [`MAX_DRAFT_BYTES`]; those with a draft at most
//! [`DRAFTS_PER_MINUTE`] a minute. Below the reserve no batch passes: only the store's own
//! snapshot and compaction run. A refused batch gets [`StoreError::DiskReserve`]. The
//! [`Pressure`] is published on a watch (`Store::pressure`) for work that frees space.

use std::{
    io,
    path::Path,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use tenko_core::{TableName, codec::to_cbor};
use tokio::sync::watch;

use crate::api::{Mutation, Pressure, StoreError, WriteBatch};

/// The part of the reserve beyond the data and the snapshots: the log and the files beside.
pub(crate) const RESERVE_BASE: u64 = 256 * 1024 * 1024;
/// The largest encoded audit draft a batch that frees space may carry below the margin.
pub(crate) const MAX_DRAFT_BYTES: usize = 1024;
/// How many batches that free space and carry an audit draft pass a minute below the margin.
pub(crate) const DRAFTS_PER_MINUTE: u32 = 600;
/// The longest the store waits for prunes after the pressure rose before it compacts.
pub(crate) const PRUNE_WINDOW: Duration = Duration::from_secs(300);
/// The prunes are over once no batch that frees space passed for this long.
pub(crate) const PRUNE_QUIET: Duration = Duration::from_secs(10);

/// The two lines for `live` bytes of data and a latest snapshot of `snapshot` bytes.
pub(crate) fn lines(live: u64, snapshot: u64) -> (u64, u64) {
    let reserve = live
        .saturating_add(snapshot.saturating_mul(2))
        .saturating_add(RESERVE_BASE);
    (reserve, reserve.saturating_mul(2))
}

/// Where `free` bytes stand against the lines.
pub(crate) fn pressure_of(free: u64, (reserve, margin): (u64, u64)) -> Pressure {
    if free < reserve {
        Pressure::Reserve
    } else if free < margin {
        Pressure::Margin
    } else {
        Pressure::Normal
    }
}

/// Free bytes of the file system that holds `dir`. With the test hooks, the byte count in
/// the file [`crate::test_hooks::FREE_BYTES`] of `dir` stands in for it.
///
/// # Errors
///
/// The I/O error of the file system query.
pub(crate) fn free_space(dir: &Path) -> io::Result<u64> {
    #[cfg(feature = "test-hooks")]
    if let Some(free) = std::fs::read_to_string(dir.join(crate::test_hooks::FREE_BYTES))
        .ok()
        .and_then(|text| text.trim().parse().ok())
    {
        return Ok(free);
    }
    fs4::available_space(dir)
}

/// Whether `batch` only frees space: `existing` answers the stored size of a key.
fn frees_space(
    batch: &WriteBatch,
    mut existing: impl FnMut(&TableName, &Bytes) -> Result<Option<usize>, StoreError>,
) -> Result<bool, StoreError> {
    if batch.audit.len() > 1 {
        return Ok(false);
    }
    for draft in &batch.audit {
        if to_cbor(draft)?.len() > MAX_DRAFT_BYTES {
            return Ok(false);
        }
    }
    for mutation in &batch.mutations {
        match mutation {
            Mutation::Delete { .. } | Mutation::Bump { .. } => {}
            Mutation::Put { table, key, value } => {
                if existing(table, key)?.is_none_or(|len| len < value.len()) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// The disk guard of one store.
pub(crate) struct Guard {
    pressure: watch::Sender<Pressure>,
    free: AtomicU64,
    reserve: AtomicU64,
    margin: AtomicU64,
    /// The start of the current minute and the batches with a draft passed in it.
    drafts: Mutex<(Instant, u32)>,
    /// When a batch that frees space last passed below the margin.
    last_prune: Mutex<Option<Instant>>,
}

impl Guard {
    pub(crate) fn new() -> Self {
        Self {
            pressure: watch::Sender::new(Pressure::Normal),
            free: AtomicU64::new(u64::MAX),
            reserve: AtomicU64::new(0),
            margin: AtomicU64::new(0),
            drafts: Mutex::new((Instant::now(), 0)),
            last_prune: Mutex::new(None),
        }
    }

    /// Sets the free space and the store's sizes; answers the pressure before and after.
    pub(crate) fn update(&self, free: u64, live: u64, snapshot: u64) -> (Pressure, Pressure) {
        let lines = lines(live, snapshot);
        self.free.store(free, Ordering::Relaxed);
        self.reserve.store(lines.0, Ordering::Relaxed);
        self.margin.store(lines.1, Ordering::Relaxed);
        let now = pressure_of(free, lines);
        let mut before = now;
        self.pressure.send_if_modified(|current| {
            before = *current;
            *current = now;
            before != now
        });
        (before, now)
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Pressure> {
        self.pressure.subscribe()
    }

    /// The free bytes, the reserve and the margin, and the pressure.
    pub(crate) fn status(&self) -> (u64, u64, u64, Pressure) {
        (
            self.free.load(Ordering::Relaxed),
            self.reserve.load(Ordering::Relaxed),
            self.margin.load(Ordering::Relaxed),
            *self.pressure.borrow(),
        )
    }

    /// Lets `batch` through or refuses it, by the pressure (see the module documentation).
    /// `existing` answers the stored size of a key; it is asked only below the margin.
    pub(crate) fn admit(
        &self,
        batch: &WriteBatch,
        existing: impl FnMut(&TableName, &Bytes) -> Result<Option<usize>, StoreError>,
    ) -> Result<(), StoreError> {
        let pressure = *self.pressure.borrow();
        let refused = |line: &AtomicU64| StoreError::DiskReserve {
            free: self.free.load(Ordering::Relaxed),
            needed: line.load(Ordering::Relaxed),
        };
        match pressure {
            Pressure::Normal => return Ok(()),
            Pressure::Reserve => return Err(refused(&self.reserve)),
            Pressure::Margin => {}
        }
        if !frees_space(batch, existing)? {
            return Err(refused(&self.margin));
        }
        let now = Instant::now();
        if !batch.audit.is_empty() && !self.take_draft(now) {
            return Err(refused(&self.margin));
        }
        *self
            .last_prune
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(now);
        Ok(())
    }

    /// Takes one of the minute's [`DRAFTS_PER_MINUTE`] at `now`; `false` once they are used.
    fn take_draft(&self, now: Instant) -> bool {
        let mut drafts = self.drafts.lock().unwrap_or_else(PoisonError::into_inner);
        if now.saturating_duration_since(drafts.0) >= Duration::from_secs(60) {
            *drafts = (now, 0);
        }
        if drafts.1 >= DRAFTS_PER_MINUTE {
            return false;
        }
        drafts.1 += 1;
        true
    }

    /// Whether the prunes that the pressure rising at `since` started are over at `now`:
    /// [`PRUNE_WINDOW`] passed, or no batch that frees space passed for [`PRUNE_QUIET`].
    pub(crate) fn prunes_over(&self, since: Instant, now: Instant) -> bool {
        let last = self
            .last_prune
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .filter(|at| *at >= since)
            .unwrap_or(since);
        now.saturating_duration_since(since) >= PRUNE_WINDOW
            || now.saturating_duration_since(last) >= PRUNE_QUIET
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        CounterKey, Principal, SystemComponent, Timestamp,
        audit::{AuditAction, AuditDraft},
    };

    use super::*;

    const ROWS: TableName = TableName::from_static("ipam.disk_rows");
    const MIB: u64 = 1024 * 1024;

    fn batch() -> WriteBatch {
        WriteBatch::new(Principal::system(SystemComponent::Ipam), Timestamp::now())
    }

    /// Nothing is stored: no put shrinks anything.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "the signature `Guard::admit` asks for"
    )]
    fn nothing(_: &TableName, _: &Bytes) -> Result<Option<usize>, StoreError> {
        Ok(None)
    }

    fn deletes(drafts: usize) -> WriteBatch {
        let mut batch = batch();
        batch
            .delete(ROWS, Bytes::from_static(b"k"))
            .bump(CounterKey::new("ipam.disk_counter"));
        for _ in 0..drafts {
            batch.audit(AuditDraft::success(
                AuditAction::from_static("ipam.disk.prune"),
                Vec::new(),
            ));
        }
        batch
    }

    fn refused(result: &Result<(), StoreError>) -> bool {
        matches!(result, Err(StoreError::DiskReserve { .. }))
    }

    /// A guard at `pressure` for 1 GiB of data and a 100 MiB snapshot.
    fn at(pressure: Pressure) -> Guard {
        let guard = Guard::new();
        let (reserve, margin) = lines(1024 * MIB, 100 * MIB);
        let free = match pressure {
            Pressure::Normal => margin,
            Pressure::Margin => margin - 1,
            Pressure::Reserve => reserve - 1,
        };
        guard.update(free, 1024 * MIB, 100 * MIB);
        guard
    }

    #[test]
    fn the_lines_follow_the_stores_own_sizes() {
        assert_eq!(
            lines(1024 * MIB, 100 * MIB),
            (1480 * MIB, 2960 * MIB),
            "data + 2 snapshots + 256 MiB, and twice that"
        );
        let lines = lines(0, 0);
        assert_eq!(pressure_of(lines.1, lines), Pressure::Normal);
        assert_eq!(pressure_of(lines.1 - 1, lines), Pressure::Margin);
        assert_eq!(pressure_of(lines.0 - 1, lines), Pressure::Reserve);
    }

    #[test]
    fn the_watch_tells_each_change_of_the_pressure_once() {
        let guard = Guard::new();
        let mut pressure = guard.subscribe();
        let (reserve, margin) = lines(0, 0);
        assert_eq!(
            guard.update(margin, 0, 0),
            (Pressure::Normal, Pressure::Normal)
        );
        assert!(!pressure.has_changed().expect("open"));
        assert_eq!(
            guard.update(margin - 1, 0, 0),
            (Pressure::Normal, Pressure::Margin)
        );
        assert!(pressure.has_changed().expect("open"));
        assert_eq!(*pressure.borrow_and_update(), Pressure::Margin);
        assert_eq!(
            guard.update(reserve - 1, 0, 0),
            (Pressure::Margin, Pressure::Reserve)
        );
        assert_eq!(*pressure.borrow_and_update(), Pressure::Reserve);
        guard.update(margin, 0, 0);
        assert_eq!(*pressure.borrow_and_update(), Pressure::Normal);
        // The lines grow with the data: the same free space can enter the margin.
        guard.update(margin, 1, 0);
        assert_eq!(*pressure.borrow_and_update(), Pressure::Margin);
    }

    #[test]
    fn below_the_margin_only_a_batch_that_frees_space_passes() {
        let guard = at(Pressure::Margin);
        let mut put = batch();
        put.put(ROWS, Bytes::from_static(b"k"), Bytes::from_static(b"value"));
        assert!(matches!(
            guard.admit(&put, nothing),
            Err(StoreError::DiskReserve { needed, .. }) if needed == lines(1024 * MIB, 100 * MIB).1
        ));
        // The same put over a larger stored value shrinks it.
        guard
            .admit(&put, |_, _| Ok(Some(64)))
            .expect("a smaller value");
        guard.admit(&deletes(0), nothing).expect("deletes");
        guard.admit(&deletes(1), nothing).expect("one small draft");
        assert!(refused(&guard.admit(&deletes(2), nothing)), "two drafts");
        let mut large = deletes(0);
        large.audit(AuditDraft::success(
            AuditAction::from_static("ipam.disk.prune"),
            vec![tenko_core::ObjectRef::singleton(tenko_core::ObjectKind::Prefix); 64],
        ));
        assert!(
            refused(&guard.admit(&large, nothing)),
            "a draft above 1 KiB"
        );
        // Above the margin everything passes, without asking for stored sizes.
        at(Pressure::Normal)
            .admit(&put, |_, _| panic!("not asked"))
            .expect("normal");
    }

    #[test]
    fn below_the_reserve_no_batch_passes() {
        let guard = at(Pressure::Reserve);
        assert!(matches!(
            guard.admit(&deletes(0), nothing),
            Err(StoreError::DiskReserve { needed, .. }) if needed == lines(1024 * MIB, 100 * MIB).0
        ));
    }

    #[test]
    fn batches_with_a_draft_are_capped_per_minute_below_the_margin() {
        let guard = at(Pressure::Margin);
        for _ in 0..DRAFTS_PER_MINUTE {
            guard.admit(&deletes(1), nothing).expect("within the cap");
        }
        assert!(refused(&guard.admit(&deletes(1), nothing)), "past the cap");
        guard.admit(&deletes(0), nothing).expect("no draft, no cap");
        // A new minute opens the cap again.
        assert!(guard.take_draft(Instant::now() + Duration::from_secs(60)));
    }

    #[test]
    fn the_prunes_end_when_they_go_quiet_or_the_window_ends() {
        let guard = at(Pressure::Margin);
        let since = Instant::now();
        assert!(!guard.prunes_over(since, since), "the window just opened");
        assert!(
            guard.prunes_over(since, since + PRUNE_QUIET),
            "no prune came"
        );
        guard.admit(&deletes(0), nothing).expect("a prune");
        let pruned = guard.last_prune.lock().expect("lock").expect("set");
        assert!(!guard.prunes_over(since, pruned + PRUNE_QUIET / 2));
        assert!(guard.prunes_over(since, pruned + PRUNE_QUIET));
        assert!(guard.prunes_over(since, since + PRUNE_WINDOW));
    }
}
