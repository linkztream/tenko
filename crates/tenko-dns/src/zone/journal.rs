//! The journal of each zone scope (`dns.journal`): one entry per committed serial step,
//! what IXFR sends (RFC 1995, read by WP6.1).
//!
//! An entry holds the serial before and after, the time, and the records removed and
//! added; `removed` starts with the old SOA record and `added` with the new one, in the
//! order an IXFR answer carries them. The key is (zone, scope, revision) with the revision
//! the change was planned against, which grows with every step of a scope.
//!
//! The journal is bounded per scope by entries, by bytes and by days ([`JournalLimits`]).
//! Every append drops, in the same batch, the oldest entries beyond the count or the bytes
//! and those older than the age limit (at most [`DROP_PER_WRITE`] at a time, so a backlog
//! shrinks over the next writes); the entry it appends always stays, whatever its size. Two
//! counters per scope, appended and dropped, give the count without a scan, and a row per
//! scope (`dns.journal_bytes`) the bytes: an append reads the scope's entries only when it
//! has something to drop, their sizes from the stored bytes and the age of the oldest
//! alone. An append the store refuses for disk room is followed by a trim alone
//! ([`stage_trim`]), which deletes only and so passes the store's disk guard. A request for
//! a serial the journal does not reach within its bytes is answered with AXFR (RFC 1995
//! section 4).

use std::time::Duration;

use bytes::Bytes;
use serde::Deserialize;
use tenko_core::{
    CounterKey, Principal, Revision, SystemComponent, Timestamp,
    codec::{cbor::from_cbor, key::encode_key},
    dns::{
        JournalEntry, ScopeName, ZoneId,
        tables::{JOURNAL, JOURNAL_BYTES},
    },
};
use tenko_store::{
    Committed, KeyRange, Mutation, ReadConsistency, ReadView, ReadViewExt, Store, StoreError,
    Versioned, WriteBatch,
};

use super::ZoneResult;

/// Entries dropped by one append at most.
pub const DROP_PER_WRITE: usize = 32;

/// The bytes of entries one zone scope keeps: a picked ceiling. An IXFR longer than the
/// zone is not worth sending (RFC 1995 section 5); without a byte count of the zone, 64 MiB
/// keeps hours of ordinary changes and minutes of a flood of name updates, and a secondary
/// further behind gets AXFR.
pub const MAX_BYTES: u64 = 64 << 20;

/// Entries read per page where a scope is read whole (a recount, a reset).
const PAGE: usize = 64;

/// How long and how large the journal of one zone scope may grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalLimits {
    /// Entries per scope.
    pub entries: u64,
    /// Days an entry is kept.
    pub days: u32,
    /// Bytes of entries per scope, as stored.
    pub bytes: u64,
}

impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            entries: 1_000,
            days: 30,
            bytes: MAX_BYTES,
        }
    }
}

/// The time of an entry, read without the records.
#[derive(Deserialize)]
struct Stamped {
    at: Timestamp,
}

/// The serials of an entry, read without the records.
#[derive(Deserialize)]
struct Serials {
    from_serial: u32,
    to_serial: u32,
}

fn appended(zone: ZoneId, scope: &ScopeName) -> CounterKey {
    CounterKey::with("dns.journal.appended", &(zone, scope.clone()))
}

fn dropped(zone: ZoneId, scope: &ScopeName) -> CounterKey {
    CounterKey::with("dns.journal.dropped", &(zone, scope.clone()))
}

/// The entries of a scope the view holds.
///
/// # Errors
///
/// The store's error.
pub fn count(view: &dyn ReadView, zone: ZoneId, scope: &ScopeName) -> ZoneResult<u64> {
    let added = view.counter(&appended(zone, scope))?;
    let gone = view.counter(&dropped(zone, scope))?;
    Ok(added.saturating_sub(gone))
}

fn scope_range(zone: ZoneId, scope: &ScopeName) -> KeyRange {
    KeyRange::prefix(encode_key(&(zone, scope.clone())))
}

/// Adds an entry to `batch` and drops what falls out of the limits.
///
/// # Errors
///
/// The store's error, or a codec error.
pub fn stage_append(
    batch: &mut WriteBatch,
    view: &dyn ReadView,
    limits: JournalLimits,
    entry: &JournalEntry,
) -> ZoneResult<()> {
    let (zone, scope) = (entry.zone, &entry.scope);
    let key = (zone, scope.clone(), entry.revision);
    let value = JOURNAL.encode(entry)?;
    let added = len(&value);
    batch.expect_typed(&JOURNAL, &key, None);
    batch.put(JOURNAL.name().clone(), JOURNAL.key(&key), value);
    batch.bump(appended(zone, scope));
    stage_drops(batch, view, limits, zone, scope, added, entry.at, true)
}

/// Drops, alone, what falls out of a scope's limits at `now`: for a scope whose append the
/// store refused for disk room. Deletes only, and puts the bytes row only where it exists
/// (smaller); nothing when nothing is to drop.
///
/// # Errors
///
/// The store's error, or a codec error.
pub fn stage_trim(
    batch: &mut WriteBatch,
    view: &dyn ReadView,
    limits: JournalLimits,
    zone: ZoneId,
    scope: &ScopeName,
    now: Timestamp,
) -> ZoneResult<()> {
    stage_drops(batch, view, limits, zone, scope, 0, now, false)
}

/// Proposes `batch`; when the store refuses it for disk room, trims alone the journals it
/// would have appended to ([`trim`]): the writers outside the zone service's own writes
/// (an import, the signer, a transfer in) go through it.
///
/// # Errors
///
/// The store's error for `batch`.
pub async fn propose_or_trim(
    store: &dyn Store,
    limits: JournalLimits,
    batch: WriteBatch,
) -> Result<Committed, StoreError> {
    let scopes = appended_scopes(&batch);
    let refused = store.propose(batch).await;
    if let Err(StoreError::DiskReserve { .. }) = &refused {
        trim(store, limits, &scopes).await;
    }
    refused
}

/// Trims the journals of `scopes` alone, as the DNS component and with no request's
/// idempotency key, after a write that would have appended to them was refused for disk
/// room: the trim deletes only, so the store's disk guard takes it, and a journal shrinks
/// while the disk is short. Best effort: a failure is logged.
pub async fn trim(store: &dyn Store, limits: JournalLimits, scopes: &[(ZoneId, ScopeName)]) {
    for (zone, scope) in scopes {
        let trimmed = async {
            let view = store.read(ReadConsistency::Local).await?;
            let now = Timestamp::now();
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dns), now);
            stage_trim(&mut batch, view.as_ref(), limits, *zone, scope, now)?;
            if !batch.mutations.is_empty() {
                store.propose(batch).await?;
            }
            Ok::<_, super::ZoneError>(())
        };
        if let Err(error) = trimmed.await {
            tracing::debug!(%error, "a journal could not be trimmed while the disk is short");
        }
    }
}

/// The scopes whose journal `batch` appends to.
pub fn appended_scopes(batch: &WriteBatch) -> Vec<(ZoneId, ScopeName)> {
    batch
        .mutations
        .iter()
        .filter_map(|mutation| match mutation {
            Mutation::Put { table, key, .. } if table == JOURNAL.name() => JOURNAL
                .decode_key(key)
                .ok()
                .map(|(zone, scope, _)| (zone, scope)),
            _ => None,
        })
        .collect()
}

/// Drops the oldest entries of a scope beyond its limits, with `added` bytes appended at
/// `at`, and puts the bytes row (one that does not exist only when `create`).
#[allow(clippy::too_many_arguments, reason = "the parts of one append or trim")]
fn stage_drops(
    batch: &mut WriteBatch,
    view: &dyn ReadView,
    limits: JournalLimits,
    zone: ZoneId,
    scope: &ScopeName,
    added: u64,
    at: Timestamp,
    create: bool,
) -> ZoneResult<()> {
    let row = (zone, scope.clone());
    let held = view.get_typed(&JOURNAL_BYTES, &row)?;
    let revision = held.as_ref().map(|(_, revision)| *revision);
    let mut bytes = added;
    if let Some((held, _)) = held {
        bytes = bytes.saturating_add(held);
    } else {
        each_entry(view, zone, scope, |_, entry| {
            bytes = bytes.saturating_add(len(&entry.value));
        })?;
    }
    let mut excess = count(view, zone, scope)?
        .saturating_add(u64::from(added > 0))
        .saturating_sub(limits.entries);
    let oldest_kept = at
        .to_utc()
        .unix_nanos()
        .saturating_sub(i128::from(limits.days) * 86_400 * 1_000_000_000);
    // The oldest entry, one at a time: each read is either dropped or the one that stops.
    let mut range = scope_range(zone, scope);
    let mut oldest = view.scan(JOURNAL.name(), range.clone(), 1, false)?.pop();
    let mut drops = 0;
    while drops < DROP_PER_WRITE {
        let Some((old_key, old)) = oldest else {
            break;
        };
        let over = excess > 0 || bytes > limits.bytes;
        if !over && from_cbor::<Stamped>(&old.value)?.at.unix_nanos() >= oldest_kept {
            break;
        }
        bytes = bytes.saturating_sub(len(&old.value));
        batch.delete(JOURNAL.name().clone(), old_key.clone());
        batch.bump(dropped(zone, scope));
        excess = excess.saturating_sub(1);
        drops += 1;
        range = range.after(old_key);
        oldest = view.scan(JOURNAL.name(), range.clone(), 1, false)?.pop();
    }
    if create || (revision.is_some() && drops > 0) {
        batch.expect_typed(&JOURNAL_BYTES, &row, revision);
        batch.put_typed(&JOURNAL_BYTES, &row, &bytes)?;
    }
    Ok(())
}

/// The keys of the entries that take a client from the serial `from` to `to`, oldest
/// first, decided from the stored entries' sizes and serials alone: read from the newest
/// back, one at a time, within `budget` bytes as stored. `None` when no such chain lies
/// within them: the client then gets AXFR. The answer then reads each entry by its key
/// ([`entry`]) as it sends it.
///
/// # Errors
///
/// The store's error, or a codec error.
pub fn steps(
    view: &dyn ReadView,
    zone: ZoneId,
    scope: &ScopeName,
    from: u32,
    to: u32,
    budget: u64,
) -> ZoneResult<Option<Vec<Bytes>>> {
    let mut range = scope_range(zone, scope);
    let (mut read, mut bytes) = (Vec::new(), 0u64);
    while let Some((key, stored)) = view.scan(JOURNAL.name(), range.clone(), 1, true)?.pop() {
        bytes = bytes.saturating_add(len(&stored.value));
        if bytes > budget {
            return Ok(None);
        }
        let serials: Serials = from_cbor(&stored.value)?;
        read.push((key.clone(), serials.from_serial, serials.to_serial));
        if serials.from_serial == from {
            let mut at = from;
            let mut keys = Vec::new();
            for (key, from_serial, to_serial) in read.into_iter().rev() {
                if from_serial == at && to_serial != at {
                    keys.push(key);
                    at = to_serial;
                    if at == to {
                        return Ok(Some(keys));
                    }
                }
            }
            return Ok(None);
        }
        range = range.before(key);
    }
    Ok(None)
}

/// The entry stored at `key`, if it is still there.
///
/// # Errors
///
/// The store's error, or a codec error.
pub fn entry(view: &dyn ReadView, key: &[u8]) -> ZoneResult<Option<JournalEntry>> {
    Ok(view
        .get(JOURNAL.name(), key)?
        .map(|stored| JOURNAL.decode(&stored.value))
        .transpose()?)
}

fn len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// Every entry of a scope as stored, a page at a time.
fn each_entry(
    view: &dyn ReadView,
    zone: ZoneId,
    scope: &ScopeName,
    mut each: impl FnMut(&Bytes, &Versioned),
) -> ZoneResult<()> {
    let mut range = scope_range(zone, scope);
    loop {
        let page = view.scan(JOURNAL.name(), range.clone(), PAGE, false)?;
        for (key, entry) in &page {
            each(key, entry);
        }
        match page.last() {
            Some((last, _)) if page.len() == PAGE => range = range.after(last.clone()),
            _ => return Ok(()),
        }
    }
}

/// Drops every entry of a scope and its count of bytes: after an import too large for one
/// entry and when the scope or the zone goes. A transfer request for an older serial then
/// gets AXFR.
///
/// # Errors
///
/// The store's error.
pub fn stage_reset(
    batch: &mut WriteBatch,
    view: &dyn ReadView,
    zone: ZoneId,
    scope: &ScopeName,
) -> ZoneResult<usize> {
    let mut dropped_entries = 0;
    each_entry(view, zone, scope, |key, _| {
        batch.delete(JOURNAL.name().clone(), key.clone());
        batch.bump(dropped(zone, scope));
        dropped_entries += 1;
    })?;
    batch.delete_typed(&JOURNAL_BYTES, &(zone, scope.clone()));
    Ok(dropped_entries)
}

/// Up to `limit` entries of a scope, newest first, before the revision `before`.
///
/// # Errors
///
/// The store's error.
pub fn list(
    view: &dyn ReadView,
    zone: ZoneId,
    scope: &ScopeName,
    before: Option<Revision>,
    limit: usize,
) -> ZoneResult<Vec<JournalEntry>> {
    let mut range = scope_range(zone, scope);
    if let Some(before) = before {
        range = range.before(encode_key(&(zone, scope.clone(), before)));
    }
    Ok(view
        .scan_typed(&JOURNAL, range, limit, true)?
        .into_iter()
        .map(|(_, entry, _)| entry)
        .collect())
}

/// The age limit as a duration.
pub fn max_age(limits: JournalLimits) -> Duration {
    Duration::from_secs(u64::from(limits.days) * 86_400)
}

/// Whether an entry at `at` is past the age limit at `now`.
pub fn expired(limits: JournalLimits, at: Timestamp, now: Timestamp) -> bool {
    now.saturating_since(at) > max_age(limits)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tenko_core::{
        Principal, SystemComponent,
        dns::{DnsName, JournalRecord, Rdata, RecordData, Rtype},
    };
    use tenko_store::{
        CounterKey, MemStore, ReadConsistency, Store, StoreError, TableName,
        raft::{RaftStore, RaftStoreConfig},
    };

    use super::*;

    const ZONE: ZoneId = ZoneId(uuid::Uuid::from_u128(7));

    /// A view that counts the journal entries its scans return.
    struct Counting {
        inner: Arc<dyn ReadView>,
        read: AtomicUsize,
    }

    impl ReadView for Counting {
        fn revision(&self) -> Revision {
            self.inner.revision()
        }

        fn get(&self, table: &TableName, key: &[u8]) -> Result<Option<Versioned>, StoreError> {
            self.inner.get(table, key)
        }

        fn scan(
            &self,
            table: &TableName,
            range: KeyRange,
            limit: usize,
            reverse: bool,
        ) -> Result<Vec<(Bytes, Versioned)>, StoreError> {
            let rows = self.inner.scan(table, range, limit, reverse)?;
            if table == JOURNAL.name() {
                self.read.fetch_add(rows.len(), Ordering::SeqCst);
            }
            Ok(rows)
        }

        fn counter(&self, counter: &CounterKey) -> Result<u64, StoreError> {
            self.inner.counter(counter)
        }
    }

    /// An entry of `records` records from `serial` to the next, at `at`.
    fn entry(serial: u32, records: u32, at: Timestamp) -> JournalEntry {
        let record = |n: u32| JournalRecord {
            name: DnsName::new(&format!("host{n}.example.test")).expect("name"),
            rtype: Rtype::A,
            ttl: 300,
            rdata: Rdata::from_data(&RecordData::A {
                address: std::net::Ipv4Addr::from(0xc000_0200 | (n & 0xff)),
            }),
        };
        JournalEntry {
            zone: ZONE,
            scope: ScopeName::DEFAULT,
            from_serial: serial,
            to_serial: serial + 1,
            revision: Revision(u64::from(serial)),
            at,
            removed: Vec::new(),
            added: (0..records).map(record).collect(),
        }
    }

    async fn counting(store: &dyn Store) -> Counting {
        Counting {
            inner: store.read(ReadConsistency::Local).await.expect("view"),
            read: AtomicUsize::new(0),
        }
    }

    fn batch() -> WriteBatch {
        WriteBatch::new(Principal::system(SystemComponent::Dns), Timestamp::now())
    }

    /// Appends `entry` under `limits`; returns the journal entries the append read.
    async fn append(store: &dyn Store, limits: JournalLimits, entry: &JournalEntry) -> usize {
        let view = counting(store).await;
        let mut batch = batch();
        stage_append(&mut batch, &view, limits, entry).expect("append");
        store.propose(batch).await.expect("written");
        view.read.load(Ordering::SeqCst)
    }

    /// The row's bytes, and the entries' serials and bytes as stored.
    async fn held(store: &dyn Store) -> (Option<u64>, Vec<u32>, u64) {
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let row = view
            .get_typed(&JOURNAL_BYTES, &(ZONE, ScopeName::DEFAULT))
            .expect("row")
            .map(|(bytes, _)| bytes);
        let (mut serials, mut bytes) = (Vec::new(), 0);
        each_entry(view.as_ref(), ZONE, &ScopeName::DEFAULT, |_, stored| {
            serials.push(JOURNAL.decode(&stored.value).expect("entry").from_serial);
            bytes += len(&stored.value);
        })
        .expect("entries");
        (row, serials, bytes)
    }

    fn size(entry: &JournalEntry) -> u64 {
        len(&JOURNAL.encode(entry).expect("encoded"))
    }

    async fn raft() -> Arc<RaftStore> {
        let mut config = RaftStoreConfig::new("unused");
        config.fsync_probe_samples = 0;
        Arc::new(RaftStore::open_temp(config).await.expect("open"))
    }

    /// The row is the entries' bytes as stored through appends, drops and a reset, the
    /// journal stays within its bytes, an append with nothing to drop reads one entry (the
    /// oldest, for its age), and the steps of a client one behind read one entry.
    async fn bytes_row_through_drops_and_a_reset(store: &dyn Store) {
        let now = Timestamp::now();
        let limits = JournalLimits {
            bytes: 3 * size(&entry(0, 20, now)),
            ..JournalLimits::default()
        };
        assert_eq!(append(store, limits, &entry(0, 20, now)).await, 0, "empty");
        for serial in 1..10 {
            let read = append(store, limits, &entry(serial, 20, now)).await;
            let (row, serials, bytes) = held(store).await;
            assert_eq!(row, Some(bytes));
            assert!(bytes <= limits.bytes, "{bytes} bytes");
            assert_eq!(read, if serial < 3 { 1 } else { 2 }, "serial {serial}");
            assert!(serials.len() <= 3);
        }
        assert_eq!(held(store).await.1, vec![7, 8, 9]);
        let view = counting(store).await;
        let one = steps(&view, ZONE, &ScopeName::DEFAULT, 9, 10, u64::MAX).expect("read");
        assert_eq!(one.map(|keys| keys.len()), Some(1));
        assert_eq!(view.read.load(Ordering::SeqCst), 1);

        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mut reset = batch();
        let dropped = stage_reset(&mut reset, view.as_ref(), ZONE, &ScopeName::DEFAULT);
        assert_eq!(dropped.expect("reset"), 3);
        store.propose(reset).await.expect("reset");
        assert_eq!(held(store).await, (None, Vec::new(), 0));
        append(store, limits, &entry(20, 20, now)).await;
        let (row, _, bytes) = held(store).await;
        assert_eq!(row, Some(bytes));
    }

    #[tokio::test]
    async fn the_bytes_row_holds_the_journal_bytes_through_drops_and_a_reset() {
        bytes_row_through_drops_and_a_reset(&MemStore::default()).await;
    }

    #[tokio::test]
    async fn the_bytes_row_holds_the_journal_bytes_on_a_raft_store() {
        bytes_row_through_drops_and_a_reset(raft().await.as_ref()).await;
    }

    /// Two appends planned on one view: the second meets the bytes row the first moved, so
    /// the row never counts one append twice or misses one.
    #[tokio::test]
    async fn two_appends_planned_on_one_view_collide_on_the_bytes_row() {
        let store = MemStore::default();
        let now = Timestamp::now();
        let limits = JournalLimits::default();
        append(&store, limits, &entry(0, 20, now)).await;
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mut first = batch();
        stage_append(&mut first, view.as_ref(), limits, &entry(1, 20, now)).expect("append");
        let mut second = batch();
        stage_append(&mut second, view.as_ref(), limits, &entry(2, 20, now)).expect("append");
        store.propose(first).await.expect("the first");
        let error = store.propose(second).await.expect_err("the second");
        assert!(
            matches!(error, StoreError::PreconditionFailed(_)),
            "{error:?}"
        );
    }

    /// An entry larger than the bound is the scope's whole journal until the next append
    /// drops it: the rule holds whatever an entry's size.
    #[tokio::test]
    async fn an_entry_larger_than_the_bound_stays_alone_and_goes_at_the_next_append() {
        let store = MemStore::default();
        let now = Timestamp::now();
        let limits = JournalLimits {
            bytes: 64 * 1024,
            ..JournalLimits::default()
        };
        for serial in 0..3 {
            append(&store, limits, &entry(serial, 20, now)).await;
        }
        let large = entry(3, 5_000, now);
        assert!(size(&large) > limits.bytes, "{} bytes", size(&large));
        eprintln!("an entry of 5,000 records: {} bytes", size(&large));
        append(&store, limits, &large).await;
        let (row, serials, bytes) = held(&store).await;
        assert_eq!((row, serials), (Some(bytes), vec![3]));
        append(&store, limits, &entry(4, 20, now)).await;
        let (row, serials, bytes) = held(&store).await;
        assert_eq!((row, serials), (Some(bytes), vec![4]));
    }

    /// A journal written before its row existed is counted once from its entries, and the
    /// age limit still drops the oldest.
    #[tokio::test]
    async fn a_missing_row_is_counted_from_the_entries_and_old_entries_expire() {
        let store = MemStore::default();
        let now = Timestamp::now();
        let old = now
            .checked_sub(Duration::from_secs(31 * 86_400))
            .expect("a time");
        let limits = JournalLimits::default();
        append(&store, limits, &entry(0, 20, old)).await;
        for serial in 1..3 {
            append(&store, limits, &entry(serial, 20, now)).await;
        }
        let mut forget = batch();
        forget.delete_typed(&JOURNAL_BYTES, &(ZONE, ScopeName::DEFAULT));
        store.propose(forget).await.expect("the row removed");
        append(&store, limits, &entry(3, 20, now)).await;
        let (row, serials, bytes) = held(&store).await;
        assert_eq!((row, serials), (Some(bytes), vec![1, 2, 3]));
    }

    /// The steps of an IXFR are decided from the newest entry back within the read budget,
    /// need every step from the client's serial to the served one, and come oldest first.
    #[tokio::test]
    async fn the_steps_of_an_ixfr_are_read_from_the_newest_back_within_its_budget() {
        let store = MemStore::default();
        let now = Timestamp::now();
        for serial in 0..10 {
            append(&store, JournalLimits::default(), &entry(serial, 20, now)).await;
        }
        let one = size(&entry(0, 20, now));
        let view = counting(&store).await;
        let far = steps(&view, ZONE, &ScopeName::DEFAULT, 0, 10, 5 * one).expect("read");
        assert_eq!(far, None);
        assert_eq!(
            view.read.load(Ordering::SeqCst),
            6,
            "five within, the sixth past"
        );
        let all = steps(&view, ZONE, &ScopeName::DEFAULT, 0, 10, 10 * one).expect("read");
        let serials: Vec<u32> = all
            .expect("steps")
            .iter()
            .map(|key| entry_at(&view, key))
            .collect();
        assert_eq!(serials, (0..10).collect::<Vec<_>>());
        let short = steps(&view, ZONE, &ScopeName::DEFAULT, 4, 12, u64::MAX).expect("read");
        assert_eq!(short, None, "the journal does not reach 12");
    }

    fn entry_at(view: &dyn ReadView, key: &[u8]) -> u32 {
        super::entry(view, key)
            .expect("read")
            .expect("there")
            .from_serial
    }

    /// Below the disk margin an append is refused, and the trim that follows passes alone:
    /// the journal shrinks to its bound and the row stays exact. The import, the signer and
    /// a transfer in write through this path.
    #[tokio::test]
    async fn a_trim_alone_passes_below_the_disk_margin() {
        use tenko_core::testing::wait_until_async;
        use tenko_store::{Pressure, test_hooks::FREE_BYTES};
        let store = raft().await;
        let now = Timestamp::now();
        for serial in 0..10 {
            append(
                store.as_ref(),
                JournalLimits::default(),
                &entry(serial, 20, now),
            )
            .await;
        }
        let reserve = store.safety().expect("safety").reserve_bytes;
        let free = reserve / 2 * 3;
        std::fs::write(store.config().data_dir.join(FREE_BYTES), free.to_string())
            .expect("the free space");
        wait_until_async("the store at its margin", async || {
            store.safety().expect("safety").pressure == Pressure::Margin
        })
        .await;
        let limits = JournalLimits {
            bytes: 3 * size(&entry(0, 20, now)),
            ..JournalLimits::default()
        };
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mut grows = batch();
        stage_append(&mut grows, view.as_ref(), limits, &entry(10, 20, now)).expect("append");
        drop(view);
        let error = propose_or_trim(store.as_ref(), limits, grows)
            .await
            .expect_err("refused");
        assert!(matches!(error, StoreError::DiskReserve { .. }), "{error:?}");
        let (row, serials, bytes) = held(store.as_ref()).await;
        assert_eq!((row, serials), (Some(bytes), vec![7, 8, 9]));
    }
}
