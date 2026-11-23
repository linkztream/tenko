//! The disk guard of the Raft store: the free space of the data directory's file system
//! against two lines computed from the store's own sizes, so that a snapshot, a compaction
//! and a start always fit (a full disk stopped a store for good once).
//!
//! - `reserve` = the live data + 2 × the latest snapshot + 256 MiB: room for one re-seed (a
//!   compacted copy of the live data), the next snapshot beside the current one, and the log.
//! - `margin` = 2 × `reserve`.
//!
//! Above the margin every batch passes. Below it:
//!
//! - A batch that frees space always passes, below the reserve too: every mutation deletes
//!   a stored row, bumps a counter or replaces a value with one no larger, with at most one
//!   audit draft of at most [`MAX_DRAFT_BYTES`], and a draft only when the batch removes at
//!   least as many bytes as the draft holds. Those with a draft pass at most
//!   [`DRAFTS_PER_MINUTE`] a minute. Below the reserve such a batch passes when it removes
//!   a stored row, up to [`RESERVE_BATCH_BYTES`] and [`RESERVE_BATCH_CHANGES`], and not below
//!   [`FLOOR`]; a batch larger in bytes is answered with [`StoreError::BatchTooLarge`]
//!   (`sys.store.batch_too_large`, 413) naming its size and that limit, and its caller splits
//!   it into batches of at most the limit and retries.
//! - Below the margin only, a batch its proposer marked as a sign-in's writes passes
//!   ([`WriteBatch::completed_sign_in`], [`WriteBatch::failed_sign_in`]), whatever it writes,
//!   within a budget of bytes (its payload) a minute: [`COMPLETED_BYTES_PER_MINUTE`] for
//!   completed sign-ins, which only valid credentials reach, and [`FAILED_BYTES_PER_MINUTE`]
//!   for failed ones, which anybody can spend. A failure passes only while a completed
//!   sign-in would too, so a right and a wrong password are refused alike. The mark is not
//!   encoded: a forwarded batch arrives without it.
//! - Nothing else passes: a refused batch gets [`StoreError::DiskReserve`].
//!
//! A state is left only 10 percent above its line, so free space that hovers at a line does
//! not flip the state. The [`Pressure`] is published on a watch (`Store::pressure`) for work
//! that frees space. Batches admitted before the pressure rose still commit.

use std::{
    io,
    path::Path,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use tenko_core::{TableName, codec::to_cbor};
use tokio::sync::watch;

use crate::api::{Mutation, Pressure, SignIn, StoreError, WriteBatch};

/// The part of the reserve beyond the data and the snapshots: the log and the files beside.
pub(crate) const RESERVE_BASE: u64 = 256 * 1024 * 1024;
/// The largest batch (its payload, `WriteBatch::payload_size`) that frees space and passes
/// below the reserve: a prune sends its deletes in batches no larger.
pub(crate) const RESERVE_BATCH_BYTES: usize = 256 * 1024;
/// The most changes of a batch that frees space and passes below the reserve.
pub(crate) const RESERVE_BATCH_CHANGES: usize = 16_384;
/// The free space below which nothing passes, from what a delete batch below the reserve
/// needs: at most [`RESERVE_BATCH_CHANGES`] rows; copy-on-write rewrites at most one 4 KiB
/// leaf per row, 64 MiB, and the branch pages above them, at most half as much again; with
/// the batch's log record (at most [`RESERVE_BATCH_BYTES`]) and its journal row, about
/// 97 MiB; with a fifth more, 128 MiB (half of [`RESERVE_BASE`]). The bound holds per
/// reading of the free space (every 250 ms), not per batch: pages a commit frees are reused
/// only after the next durable checkpoint.
pub(crate) const FLOOR: u64 = crate::api::DISK_FLOOR_BYTES;
/// The largest encoded audit draft a batch may carry below the margin.
pub(crate) const MAX_DRAFT_BYTES: usize = 1024;
/// How many batches that free space and carry an audit draft pass a minute below the margin.
pub(crate) const DRAFTS_PER_MINUTE: u64 = 600;
/// The bytes of completed sign-ins that pass a minute below the margin (a password sign-in
/// is about 2 KiB).
pub(crate) const COMPLETED_BYTES_PER_MINUTE: u64 = crate::api::SIGN_IN_BYTES_PER_MINUTE;
/// The bytes of failed sign-ins (their record, a lock, an alarm) that pass a minute below
/// the margin; beyond them the failures are only counted, for one summary record later.
pub(crate) const FAILED_BYTES_PER_MINUTE: u64 = crate::api::FAILED_SIGN_IN_BYTES_PER_MINUTE;
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

/// The pressure after `before` at `free` bytes: a better state is entered only 10 percent
/// above the line it crosses.
fn pressure_after(before: Pressure, free: u64, (reserve, margin): (u64, u64)) -> Pressure {
    let above = |line: u64| free >= line.saturating_add(line / 10);
    match (before, pressure_of(free, (reserve, margin))) {
        (Pressure::Reserve, Pressure::Margin | Pressure::Normal) if !above(reserve) => {
            Pressure::Reserve
        }
        (Pressure::Reserve | Pressure::Margin, Pressure::Normal) if !above(margin) => {
            Pressure::Margin
        }
        (_, now) => now,
    }
}

/// The OS error codes of a full disk: `ENOSPC` and `EDQUOT` (122 on Linux, 69 on macOS
/// and the BSDs), `ERROR_HANDLE_DISK_FULL` and `ERROR_DISK_FULL` on Windows.
#[cfg(target_os = "linux")]
const FULL_DISK_CODES: &[&str] = &["os error 28)", "os error 122)"];
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const FULL_DISK_CODES: &[&str] = &["os error 28)", "os error 69)"];
#[cfg(windows)]
const FULL_DISK_CODES: &[&str] = &["os error 39)", "os error 112)"];
#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
const FULL_DISK_CODES: &[&str] = &["os error 28)"];

/// Whether the cause of a stop names a full disk: the one cause a start cures once there
/// is room again.
pub(crate) fn names_a_full_disk(cause: &str) -> bool {
    FULL_DISK_CODES.iter().any(|code| cause.contains(code))
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

/// The bytes `batch` removes when it only removes or keeps (`None` once it writes anything
/// new): a delete of a stored row its key and value; `existing` answers the stored size of
/// a key's value.
fn removed_bytes(
    batch: &WriteBatch,
    mut existing: impl FnMut(&TableName, &Bytes) -> Result<Option<usize>, StoreError>,
) -> Result<Option<u64>, StoreError> {
    let mut removed = 0_usize;
    for mutation in &batch.mutations {
        match mutation {
            Mutation::Delete { table, key } => {
                if let Some(len) = existing(table, key)? {
                    removed = removed.saturating_add(key.len()).saturating_add(len);
                }
            }
            Mutation::Bump { .. } => {}
            Mutation::Put { table, key, value } => match existing(table, key)? {
                Some(len) if len >= value.len() => {
                    removed = removed.saturating_add(len - value.len());
                }
                _ => return Ok(None),
            },
        }
    }
    Ok(Some(u64::try_from(removed).unwrap_or(u64::MAX)))
}

/// Units (batches or bytes) that pass a minute.
struct Budget {
    per_minute: u64,
    /// The start of the current minute and the units passed in it.
    window: Mutex<(Instant, u64)>,
}

impl Budget {
    fn new(per_minute: u64) -> Self {
        Self {
            per_minute,
            window: Mutex::new((Instant::now(), 0)),
        }
    }

    /// Takes `units` of the minute's at `now`; `false` once the minute's are used (the
    /// last one taken may go past them).
    fn take(&self, now: Instant, units: u64) -> bool {
        self.spend(now, units)
    }

    /// Whether the minute at `now` has units left.
    fn has_room(&self, now: Instant) -> bool {
        self.spend(now, 0)
    }

    fn spend(&self, now: Instant, units: u64) -> bool {
        let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        if now.saturating_duration_since(window.0) >= Duration::from_secs(60) {
            *window = (now, 0);
        }
        if window.1 >= self.per_minute {
            return false;
        }
        window.1 = window.1.saturating_add(units);
        true
    }
}

/// The disk guard of one store.
pub(crate) struct Guard {
    pressure: watch::Sender<Pressure>,
    free: AtomicU64,
    reserve: AtomicU64,
    margin: AtomicU64,
    /// The free space could not be read at the last tick.
    unknown: AtomicBool,
    drafts: Budget,
    completed: Budget,
    failed: Budget,
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
            unknown: AtomicBool::new(false),
            drafts: Budget::new(DRAFTS_PER_MINUTE),
            completed: Budget::new(COMPLETED_BYTES_PER_MINUTE),
            failed: Budget::new(FAILED_BYTES_PER_MINUTE),
            last_prune: Mutex::new(None),
        }
    }

    /// Sets the free space and the store's sizes; answers the pressure before and after.
    pub(crate) fn update(&self, free: u64, live: u64, snapshot: u64) -> (Pressure, Pressure) {
        let lines = lines(live, snapshot);
        self.free.store(free, Ordering::Relaxed);
        self.reserve.store(lines.0, Ordering::Relaxed);
        self.margin.store(lines.1, Ordering::Relaxed);
        self.unknown.store(false, Ordering::Relaxed);
        self.set(|before| pressure_after(before, free, lines))
    }

    /// The free space could not be read: the guard holds at least the margin until it can.
    pub(crate) fn unknown(&self) -> (Pressure, Pressure) {
        self.unknown.store(true, Ordering::Relaxed);
        self.set(|before| match before {
            Pressure::Normal => Pressure::Margin,
            other => other,
        })
    }

    fn set(&self, next: impl FnOnce(Pressure) -> Pressure) -> (Pressure, Pressure) {
        let mut moved = (Pressure::Normal, Pressure::Normal);
        self.pressure.send_if_modified(|current| {
            moved = (*current, next(*current));
            *current = moved.1;
            moved.0 != moved.1
        });
        moved
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

    /// Whether the free space was unknown at the last reading.
    pub(crate) fn free_unknown(&self) -> bool {
        self.unknown.load(Ordering::Relaxed)
    }

    /// Lets `batch` through or refuses it, by the pressure (see the module documentation).
    /// `existing` answers the stored size of a key; it is asked only below the margin.
    pub(crate) fn admit(
        &self,
        batch: &WriteBatch,
        existing: impl FnMut(&TableName, &Bytes) -> Result<Option<usize>, StoreError>,
    ) -> Result<(), StoreError> {
        let pressure = *self.pressure.borrow();
        if pressure == Pressure::Normal {
            return Ok(());
        }
        let free = self.free.load(Ordering::Relaxed);
        let line = match pressure {
            Pressure::Reserve => self.reserve.load(Ordering::Relaxed),
            _ => self.margin.load(Ordering::Relaxed),
        };
        let refused = |needed| Err(StoreError::DiskReserve { free, needed });
        let now = Instant::now();
        if let Some(kind) = batch.sign_in() {
            let size = u64::try_from(batch.payload_size()).unwrap_or(u64::MAX);
            let passes = pressure == Pressure::Margin
                && match kind {
                    SignIn::Completed => self.completed.take(now, size),
                    SignIn::Failed => self.completed.has_room(now) && self.failed.take(now, size),
                };
            return if passes { Ok(()) } else { refused(line) };
        }
        let draft = match batch.audit.as_slice() {
            [] => None,
            [draft] => Some(to_cbor(draft)?.len()),
            _ => return refused(line),
        };
        if draft.is_some_and(|len| len > MAX_DRAFT_BYTES) {
            return refused(line);
        }
        let removed = removed_bytes(batch, existing)?;
        let frees = removed.is_some_and(|removed| {
            draft.is_none_or(|len| removed >= u64::try_from(len).unwrap_or(u64::MAX))
        });
        if frees {
            if pressure == Pressure::Reserve {
                if free < FLOOR {
                    return refused(FLOOR);
                }
                let size = batch.payload_size();
                if size > RESERVE_BATCH_BYTES {
                    // The caller splits it into batches of at most this size and retries.
                    return Err(StoreError::BatchTooLarge {
                        size,
                        limit: RESERVE_BATCH_BYTES,
                    });
                }
                // Below the reserve a batch must remove a stored row (a delete of absent keys
                // grows the log and frees nothing), and its rows are bounded for the floor.
                if removed == Some(0) || batch.mutations.len() > RESERVE_BATCH_CHANGES {
                    return refused(line);
                }
            }
            if draft.is_some() && !self.drafts.take(now, 1) {
                return refused(line);
            }
            *self
                .last_prune
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(now);
            return Ok(());
        }
        refused(line)
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

    fn draft() -> AuditDraft {
        AuditDraft::success(AuditAction::from_static("ipam.disk.prune"), Vec::new())
    }

    /// Every key holds a row of 4 KiB.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "the signature `Guard::admit` asks for"
    )]
    fn stored(_: &TableName, _: &Bytes) -> Result<Option<usize>, StoreError> {
        Ok(Some(4096))
    }

    /// Nothing is stored.
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
            batch.audit(draft());
        }
        batch
    }

    fn refused(result: &Result<(), StoreError>) -> bool {
        matches!(result, Err(StoreError::DiskReserve { .. }))
    }

    /// A guard at `free` bytes for 1 GiB of data and a 100 MiB snapshot.
    fn with_free(free: u64) -> Guard {
        let guard = Guard::new();
        guard.update(free, 1024 * MIB, 100 * MIB);
        guard
    }

    /// A guard at `pressure` for 1 GiB of data and a 100 MiB snapshot.
    fn at(pressure: Pressure) -> Guard {
        let (reserve, margin) = lines(1024 * MIB, 100 * MIB);
        with_free(match pressure {
            Pressure::Normal => margin,
            Pressure::Margin => margin - 1,
            Pressure::Reserve => reserve - 1,
        })
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
        assert!(FLOOR < lines.0, "the floor lies below every reserve");
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
        guard.update(margin + margin / 10, 0, 0);
        assert_eq!(*pressure.borrow_and_update(), Pressure::Normal);
        // The lines grow with the data: the same free space can enter the margin.
        guard.update(margin + margin / 10, 64 * MIB, 0);
        assert_eq!(*pressure.borrow_and_update(), Pressure::Margin);
    }

    #[test]
    fn a_state_is_left_only_ten_percent_above_its_line() {
        let guard = Guard::new();
        let (reserve, margin) = lines(0, 0);
        guard.update(reserve - 1, 0, 0);
        assert_eq!(
            guard.update(reserve, 0, 0).1,
            Pressure::Reserve,
            "at the line"
        );
        assert_eq!(
            guard.update(reserve + reserve / 10, 0, 0).1,
            Pressure::Margin
        );
        assert_eq!(
            guard.update(margin, 0, 0).1,
            Pressure::Margin,
            "at the line"
        );
        assert_eq!(guard.update(margin + margin / 10, 0, 0).1, Pressure::Normal);
        assert_eq!(
            guard.update(margin - 1, 0, 0).1,
            Pressure::Margin,
            "entered at once"
        );
    }

    #[test]
    fn an_unknown_free_space_holds_the_guard_at_the_margin() {
        let guard = at(Pressure::Normal);
        assert_eq!(guard.unknown(), (Pressure::Normal, Pressure::Margin));
        assert!(guard.free_unknown());
        let reserve = at(Pressure::Reserve);
        assert_eq!(reserve.unknown().1, Pressure::Reserve, "never eased");
        let (_, margin) = lines(1024 * MIB, 100 * MIB);
        guard.update(margin * 2, 1024 * MIB, 100 * MIB);
        assert!(!guard.free_unknown());
        assert_eq!(guard.status().3, Pressure::Normal);
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
        guard.admit(&put, stored).expect("a smaller value");
        guard.admit(&deletes(0), stored).expect("deletes");
        guard.admit(&deletes(1), stored).expect("one small draft");
        assert!(refused(&guard.admit(&deletes(2), stored)), "two drafts");
        let mut large = deletes(0);
        large.audit(AuditDraft::success(
            AuditAction::from_static("ipam.disk.prune"),
            vec![tenko_core::ObjectRef::singleton(tenko_core::ObjectKind::Prefix); 64],
        ));
        assert!(
            refused(&guard.admit(&large, |_, _| Ok(Some(4096)))),
            "a draft above 1 KiB"
        );
        // Above the margin everything passes, without asking for stored sizes.
        at(Pressure::Normal)
            .admit(&put, |_, _| panic!("not asked"))
            .expect("normal");
    }

    /// A row with an empty value (an expiry index) frees its key's bytes when deleted.
    #[test]
    fn below_the_reserve_a_delete_of_a_row_with_an_empty_value_frees_its_key() {
        let mut sweep = batch();
        sweep.delete(ROWS, Bytes::from_static(b"expiry-key"));
        at(Pressure::Reserve)
            .admit(&sweep, |_, _| Ok(Some(0)))
            .expect("the key's bytes are freed");
    }

    #[test]
    fn a_draft_passes_only_with_a_batch_that_removes_more_than_it_holds() {
        let guard = at(Pressure::Margin);
        guard
            .admit(&deletes(0), nothing)
            .expect("a delete of nothing writes nothing");
        assert!(
            refused(&guard.admit(&deletes(1), nothing)),
            "a delete of an absent row with an audit record grows the store"
        );
        assert!(
            refused(&guard.admit(&deletes(1), |_, _| Ok(Some(0)))),
            "removes less than the draft holds"
        );
        guard.admit(&deletes(1), stored).expect("removes more");
    }

    #[test]
    fn below_the_reserve_a_batch_that_frees_space_passes_down_to_the_floor() {
        let guard = at(Pressure::Reserve);
        guard
            .admit(&deletes(1), stored)
            .expect("a prune below the reserve");
        assert!(
            refused(&guard.admit(&deletes(0), nothing)),
            "a delete of absent rows frees nothing"
        );
        let mut many = batch();
        for n in 0..=u32::try_from(RESERVE_BATCH_CHANGES).expect("fits") {
            many.delete(
                TableName::from_static("dns.a"),
                Bytes::from(n.to_be_bytes().to_vec()),
            );
        }
        assert!(many.payload_size() <= RESERVE_BATCH_BYTES);
        assert!(
            refused(&guard.admit(&many, stored)),
            "more than 16,384 changes"
        );
        let mut put = batch();
        put.put(ROWS, Bytes::from_static(b"k"), Bytes::from_static(b"value"));
        assert!(matches!(
            guard.admit(&put, nothing),
            Err(StoreError::DiskReserve { needed, .. }) if needed == lines(1024 * MIB, 100 * MIB).0
        ));
        let mut large = batch();
        for n in 0..20_000_u32 {
            large.delete(ROWS, Bytes::from(n.to_be_bytes().to_vec()));
        }
        assert!(large.payload_size() > RESERVE_BATCH_BYTES);
        assert!(
            matches!(
                guard.admit(&large, stored),
                Err(StoreError::BatchTooLarge { size, limit })
                    if size == large.payload_size() && limit == RESERVE_BATCH_BYTES
            ),
            "a prune batch above 256 KiB is to be split"
        );
        let floor = with_free(FLOOR - 1);
        assert_eq!(floor.status().3, Pressure::Reserve);
        assert!(matches!(
            floor.admit(&deletes(0), stored),
            Err(StoreError::DiskReserve { needed, .. }) if needed == FLOOR
        ));
        with_free(FLOOR)
            .admit(&deletes(0), stored)
            .expect("at the floor");
    }

    #[test]
    fn batches_with_a_draft_are_capped_per_minute_below_the_margin() {
        let guard = at(Pressure::Margin);
        for _ in 0..DRAFTS_PER_MINUTE {
            guard.admit(&deletes(1), stored).expect("within the cap");
        }
        assert!(refused(&guard.admit(&deletes(1), stored)), "past the cap");
        guard.admit(&deletes(0), stored).expect("no draft, no cap");
        // A new minute opens the cap again.
        assert!(
            guard
                .drafts
                .take(Instant::now() + Duration::from_secs(60), 1)
        );
    }

    /// A batch of 2 KiB marked as a sign-in's writes, whatever it holds.
    fn sign_in(kind: SignIn) -> WriteBatch {
        let principal = Principal::system(SystemComponent::Auth);
        let mut batch = match kind {
            SignIn::Completed => WriteBatch::completed_sign_in(principal, Timestamp::now()),
            SignIn::Failed => WriteBatch::failed_sign_in(principal, Timestamp::now()),
        };
        batch.put(
            ROWS,
            Bytes::from_static(b"s"),
            Bytes::from(vec![0_u8; 2048]),
        );
        batch.audit(draft());
        batch
    }

    #[test]
    fn a_marked_sign_in_passes_below_the_margin_within_its_budget_of_bytes() {
        let guard = at(Pressure::Margin);
        let size = u64::try_from(sign_in(SignIn::Failed).payload_size()).expect("fits");
        // The failures' budget, then only counted; a completed sign-in still passes.
        for _ in 0..FAILED_BYTES_PER_MINUTE.div_ceil(size) {
            guard
                .admit(&sign_in(SignIn::Failed), nothing)
                .expect("within the failures' budget");
        }
        assert!(refused(&guard.admit(&sign_in(SignIn::Failed), nothing)));
        guard
            .admit(&sign_in(SignIn::Completed), nothing)
            .expect("the completed sign-ins' own budget");
        // Once the completed sign-ins' budget is spent a failure is refused too, so a right
        // and a wrong password answer alike.
        let guard = at(Pressure::Margin);
        let mut spent = 0;
        while guard.admit(&sign_in(SignIn::Completed), nothing).is_ok() {
            spent += size;
        }
        assert!(spent >= COMPLETED_BYTES_PER_MINUTE);
        assert!(refused(&guard.admit(&sign_in(SignIn::Failed), nothing)));
        // The same batch unmarked is refused, and below the reserve no sign-in passes.
        let mut unmarked = batch();
        unmarked.put(
            ROWS,
            Bytes::from_static(b"s"),
            Bytes::from(vec![0_u8; 2048]),
        );
        assert!(refused(&at(Pressure::Margin).admit(&unmarked, nothing)));
        for kind in [SignIn::Completed, SignIn::Failed] {
            assert!(refused(
                &at(Pressure::Reserve).admit(&sign_in(kind), nothing)
            ));
        }
        // The mark is not encoded.
        let decoded: WriteBatch =
            tenko_core::codec::from_cbor(&to_cbor(&sign_in(SignIn::Completed)).expect("encoded"))
                .expect("decoded");
        assert_eq!(decoded.sign_in(), None);
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
        guard.admit(&deletes(0), stored).expect("a prune");
        let pruned = guard.last_prune.lock().expect("lock").expect("set");
        assert!(!guard.prunes_over(since, pruned + PRUNE_QUIET / 2));
        assert!(guard.prunes_over(since, pruned + PRUNE_QUIET));
        assert!(guard.prunes_over(since, since + PRUNE_WINDOW));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_a_full_disk_is_a_cause_a_start_cures() {
        assert!(names_a_full_disk("No space left on device (os error 28)"));
        assert!(names_a_full_disk("Disk quota exceeded (os error 122)"));
        assert!(!names_a_full_disk("Input/output error (os error 5)"));
        // Windows' codes mean other things here (ENOTEMPTY, EHOSTDOWN).
        assert!(!names_a_full_disk("Directory not empty (os error 39)"));
        assert!(!names_a_full_disk("Host is down (os error 112)"));
        assert!(!names_a_full_disk("the test hook fails the write"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn only_a_full_disk_is_a_cause_a_start_cures() {
        assert!(names_a_full_disk("No space left on device (os error 28)"));
        assert!(names_a_full_disk("Disc quota exceeded (os error 69)"));
        assert!(!names_a_full_disk("(os error 122)"), "Linux's EDQUOT");
    }

    #[cfg(windows)]
    #[test]
    fn only_a_full_disk_is_a_cause_a_start_cures() {
        assert!(names_a_full_disk(
            "There is not enough space on the disk. (os error 112)"
        ));
        assert!(names_a_full_disk("The disk is full. (os error 39)"));
        assert!(!names_a_full_disk(
            "The request could not be performed because of an I/O device error. (os error 1117)"
        ));
        assert!(!names_a_full_disk("(os error 28)"), "a Unix code");
        assert!(!names_a_full_disk("the test hook fails the write"));
    }
}
