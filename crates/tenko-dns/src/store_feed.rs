//! The in-process zone feed (plan section 2.1, WP4.3): the `dns` role of a controller reads
//! its rows from the controller's own store through a [`DerivedIndex`].
//!
//! [`register`] registers a [`StoreIndex`] with the store and returns the [`StoreFeed`]
//! the catalog follows. The store drives the index:
//!
//! - **build and install**: at registration, and again whenever the store rebuilds its
//!   derived indexes (a snapshot install on the Raft store), the index reads every table of
//!   the `dns` node role (`tenko_core::dns::tables::NODE_TABLES`) into one [`DnsData`] image
//!   and hands it to the feed. The first image is what [`ZoneFeed::snapshot`] returns before
//!   the role listens; a later one reaches the catalog as one [`FeedEvent::Reset`], which it
//!   builds aside and swaps whole (M1).
//! - **apply**: every change set that touches those tables becomes one [`Delta`] with the
//!   changed rows read at the change set's revision, in revision order, on the store's apply
//!   path. `apply` only looks the changed rows up and queues their stored bytes; the feed
//!   decodes them (on the blocking pool for large change sets), and the index is updated
//!   by the catalog's writer, never on the apply path. A change set that cannot be read or
//!   decoded makes the feed read a whole image instead (a reset), so a delta never goes
//!   missing.
//!
//! The feed holds the store handle only to read a fresh image when the catalog asks for one
//! after a gap; the engine itself never sees the store (plan section 2.10). A change set
//! that touches no `dns` table does not reach the feed, so a delta runs from the revision of
//! the previous `dns` change (or the image) to its own revision: the rows in between did not
//! change.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use serde::{Serialize, de::DeserializeOwned};
use tenko_core::{
    Revision, TableName,
    codec::KeyCodec,
    dns::tables::{
        ACLS, FORWARDERS, JOURNAL, KEYS_META, LIST_VERSIONS, LISTS, NODE_TABLES, RRSETS, VIEWS,
        ZONES,
    },
    table::TableDef,
};
use tenko_store::{
    ChangeSet, DerivedIndex, IndexImage, KeyRange, ReadConsistency, ReadView, Store, StoreError,
    WatchFilter, downcast_image,
};
use tokio::sync::Notify;

use crate::feed::{Change, Delta, DnsData, FeedError, FeedEvent, ZoneFeed};

/// Rows read per scan while an image is built, so that the decoded rows and the raw page
/// are never both whole tables in memory.
const PAGE: usize = 4_096;

/// What the index hands to the feed.
#[derive(Debug)]
enum Pushed {
    /// A complete image (registration, a rebuild after a snapshot install).
    Image(Box<DnsData>),
    /// The rows of one change set, at its revision, as the store holds them: decoded by
    /// the feed, off the store's apply path.
    Changes {
        revision: Revision,
        rows: Vec<RawRow>,
    },
    /// A change set could not be read: the feed reads a whole image instead.
    Lost(Revision),
}

/// One changed row as stored: its table, its encoded key and its encoded value (`None`
/// when it was removed).
#[derive(Debug)]
struct RawRow {
    table: TableName,
    key: Bytes,
    value: Option<Bytes>,
}

/// Change sets at least this large are decoded on the blocking pool.
const DECODE_ASIDE: usize = 64;

/// Rows of queued change sets merged into one delta at most.
const MERGE_ROWS: usize = 100_000;

/// The queue between the store's apply path and the feed: never blocks the store.
#[derive(Debug, Default)]
struct Queue {
    items: Mutex<VecDeque<Pushed>>,
    ready: Notify,
}

impl Queue {
    fn push(&self, item: Pushed) {
        self.items
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(item);
        self.ready.notify_one();
    }

    fn pop(&self) -> Option<Pushed> {
        self.items
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }

    fn len(&self) -> usize {
        self.items
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// The image the store builds aside and installs.
struct Image(DnsData);

impl IndexImage for Image {
    fn revision(&self) -> Revision {
        self.0.revision
    }
}

/// The derived index of the `dns` role: turns the store's change sets into the feed's
/// events. Registered once per process by [`register`].
#[derive(Debug)]
pub struct StoreIndex {
    queue: Arc<Queue>,
    /// The revision of the newest `dns` change the store applied (or of the newest image).
    pushed: Arc<AtomicU64>,
}

impl StoreIndex {
    /// The changed rows of a change set, as stored. Only a lookup per row: the decoding
    /// happens in the feed.
    fn raw(changes: &ChangeSet, view: &dyn ReadView) -> Result<Vec<RawRow>, StoreError> {
        let mut rows = Vec::with_capacity(changes.changes.len());
        for change in &changes.changes {
            let value = if change.deleted {
                None
            } else {
                view.get(&change.table, &change.key)?
                    .map(|versioned| versioned.value)
            };
            rows.push(RawRow {
                table: change.table.clone(),
                key: change.key.clone(),
                value,
            });
        }
        Ok(rows)
    }
}

fn decode_row<K: KeyCodec, V: Serialize + DeserializeOwned>(
    table: &TableDef<K, V>,
    row: &RawRow,
) -> Result<(K, Option<V>), StoreError> {
    let key = table.decode_key(&row.key)?;
    let value = row
        .value
        .as_ref()
        .map(|value| table.decode(value))
        .transpose()?;
    Ok((key, value))
}

/// Decodes the changed rows of one change set; rows of other tables are skipped.
fn decode(rows: &[RawRow]) -> Result<Vec<Change>, StoreError> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let table = &row.table;
        let change = if table == ZONES.name() {
            let (key, value) = decode_row(&ZONES, row)?;
            Change::Zone(key, value)
        } else if table == RRSETS.name() {
            let (key, value) = decode_row(&RRSETS, row)?;
            Change::RrSet(key, value)
        } else if table == VIEWS.name() {
            let (key, value) = decode_row(&VIEWS, row)?;
            Change::View(key, value)
        } else if table == FORWARDERS.name() {
            let (key, value) = decode_row(&FORWARDERS, row)?;
            Change::Forwarder(key, value)
        } else if table == ACLS.name() {
            let (key, value) = decode_row(&ACLS, row)?;
            Change::Acl(key, value)
        } else if table == KEYS_META.name() {
            let (key, value) = decode_row(&KEYS_META, row)?;
            Change::Key(key, value)
        } else if table == LISTS.name() {
            let (key, value) = decode_row(&LISTS, row)?;
            Change::List(key, value)
        } else if table == LIST_VERSIONS.name() {
            let (key, value) = decode_row(&LIST_VERSIONS, row)?;
            Change::ListVersion(key, value)
        } else if table == JOURNAL.name() {
            let (key, value) = decode_row(&JOURNAL, row)?;
            Change::Journal(key, value)
        } else {
            continue;
        };
        out.push(change);
    }
    Ok(out)
}

/// Every row of `table`, read in pages.
fn scan_all<K: KeyCodec, V: Serialize + DeserializeOwned>(
    view: &dyn ReadView,
    table: &TableDef<K, V>,
    mut each: impl FnMut(K, V),
) -> Result<(), StoreError> {
    let mut range = KeyRange::all();
    loop {
        let page = view.scan(table.name(), range.clone(), PAGE, false)?;
        let Some((last, _)) = page.last() else {
            return Ok(());
        };
        let last: Bytes = last.clone();
        let full = page.len() == PAGE;
        for (key, versioned) in page {
            each(table.decode_key(&key)?, table.decode(&versioned.value)?);
        }
        if !full {
            return Ok(());
        }
        range = KeyRange::all().after(last);
    }
}

/// Reads every row of the `dns` node role at the view's revision.
///
/// # Errors
///
/// A store or codec error.
pub fn read_image(view: &dyn ReadView) -> Result<DnsData, StoreError> {
    let mut data = DnsData::at(view.revision());
    scan_all(view, &ZONES, |key, value| {
        data.zones.insert(key, value);
    })?;
    scan_all(view, &RRSETS, |key, value| {
        data.rrsets.insert(key, value);
    })?;
    scan_all(view, &VIEWS, |key, value| {
        data.views.insert(key, value);
    })?;
    scan_all(view, &FORWARDERS, |key, value| {
        data.forwarders.insert(key, value);
    })?;
    scan_all(view, &ACLS, |key, value| {
        data.acls.insert(key, value);
    })?;
    scan_all(view, &KEYS_META, |key, value| {
        data.keys.insert(key, value);
    })?;
    scan_all(view, &LISTS, |key, value| {
        data.lists.insert(key, value);
    })?;
    scan_all(view, &LIST_VERSIONS, |key, value| {
        data.list_versions.insert(key, value);
    })?;
    scan_all(view, &JOURNAL, |key, value| {
        data.journal.insert(key, value);
    })?;
    Ok(data)
}

impl DerivedIndex for StoreIndex {
    fn name(&self) -> &'static str {
        "dns.serving"
    }

    fn filter(&self) -> WatchFilter {
        WatchFilter::tables(NODE_TABLES.iter().cloned())
    }

    fn build(&self, view: &dyn ReadView) -> Result<Box<dyn IndexImage>, StoreError> {
        Ok(Box::new(Image(read_image(view)?)))
    }

    fn install(&self, image: Box<dyn IndexImage>) {
        if let Some(image) = downcast_image::<Image>(image) {
            let Image(data) = *image;
            self.pushed
                .fetch_max(data.revision.get(), Ordering::Relaxed);
            self.queue.push(Pushed::Image(Box::new(data)));
        }
    }

    fn apply(&self, changes: &ChangeSet, view: &dyn ReadView) {
        self.pushed
            .fetch_max(changes.revision.get(), Ordering::Relaxed);
        match Self::raw(changes, view) {
            Ok(rows) => self.queue.push(Pushed::Changes {
                revision: changes.revision,
                rows,
            }),
            Err(error) => {
                tracing::error!(%error, revision = %changes.revision, "the DNS feed could not read a change set; it reads a whole image instead");
                self.queue.push(Pushed::Lost(changes.revision));
            }
        }
    }
}

/// The feed the `dns` role's catalog follows: the [`ZoneFeed`] over a [`StoreIndex`].
pub struct StoreFeed {
    store: Arc<dyn Store>,
    queue: Arc<Queue>,
    pushed: Arc<AtomicU64>,
    /// The revision of the image or the last event handed out.
    held: Revision,
}

impl std::fmt::Debug for StoreFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreFeed")
            .field("held", &self.held)
            .field("queued", &self.queue.len())
            .finish_non_exhaustive()
    }
}

/// What the role reads about its feed for the status report. The default has seen no
/// change.
#[derive(Debug, Clone, Default)]
pub struct FeedProgress {
    pushed: Arc<AtomicU64>,
}

impl FeedProgress {
    /// The revision of the newest `dns` change the store applied.
    pub fn store_revision(&self) -> Revision {
        Revision(self.pushed.load(Ordering::Relaxed))
    }

    /// Revisions between the newest `dns` change and `held` (0 when the index holds it).
    pub fn lag(&self, held: Revision) -> u64 {
        self.store_revision().get().saturating_sub(held.get())
    }
}

/// Registers the index of the `dns` role with `store` and returns its feed. The store
/// builds the first image here, from a local read view: run it off the async threads when
/// the zones are large.
///
/// # Errors
///
/// The store error of the first build.
pub fn register(store: Arc<dyn Store>) -> Result<StoreFeed, StoreError> {
    let queue = Arc::new(Queue::default());
    let pushed = Arc::new(AtomicU64::new(0));
    store.register_index(Arc::new(StoreIndex {
        queue: Arc::clone(&queue),
        pushed: Arc::clone(&pushed),
    }))?;
    Ok(StoreFeed {
        store,
        queue,
        pushed,
        held: Revision::ZERO,
    })
}

impl StoreFeed {
    /// The progress of the store's side, for the status report.
    pub fn progress(&self) -> FeedProgress {
        FeedProgress {
            pushed: Arc::clone(&self.pushed),
        }
    }

    async fn read_fresh(&self) -> Result<DnsData, FeedError> {
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| FeedError::Source(error.to_string()))?;
        tokio::task::spawn_blocking(move || read_image(view.as_ref()))
            .await
            .map_err(|error| FeedError::Source(error.to_string()))?
            .map_err(|error| FeedError::Source(error.to_string()))
    }

    /// Appends the change sets queued right behind one, up to [`MERGE_ROWS`] rows, and
    /// moves `revision` to the last of them. Rows are whole values in commit order, so the
    /// merged list applies as the change sets would one by one.
    fn merge_queued(&self, revision: &mut Revision, rows: &mut Vec<RawRow>) {
        let mut items = self
            .queue
            .items
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while rows.len() < MERGE_ROWS {
            let Some(Pushed::Changes { revision: next, .. }) = items.front() else {
                break;
            };
            *revision = *next;
            if let Some(Pushed::Changes { rows: mut more, .. }) = items.pop_front() {
                rows.append(&mut more);
            }
        }
    }

    /// A whole image read from the store, as a reset.
    async fn reset(&mut self) -> Result<FeedEvent, FeedError> {
        let data = self.read_fresh().await?;
        self.held = data.revision;
        self.pushed
            .fetch_max(data.revision.get(), Ordering::Relaxed);
        Ok(FeedEvent::Reset(Box::new(data)))
    }

    /// The next queued event the image does not already hold.
    fn next_queued(&mut self) -> Option<Pushed> {
        while let Some(item) = self.queue.pop() {
            let revision = match &item {
                Pushed::Changes { revision, .. } | Pushed::Lost(revision) => *revision,
                Pushed::Image(data) => data.revision,
            };
            if revision > self.held {
                return Some(item);
            }
        }
        None
    }
}

impl ZoneFeed for StoreFeed {
    async fn snapshot(&mut self) -> Result<DnsData, FeedError> {
        // The image of the registration (or of a rebuild) when it is the next event; else a
        // fresh read, after which queued events up to its revision are skipped.
        let queued = {
            let mut items = self
                .queue
                .items
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match items.front() {
                Some(Pushed::Image(_)) => items.pop_front(),
                _ => None,
            }
        };
        let data = match queued {
            Some(Pushed::Image(data)) => *data,
            _ => self.read_fresh().await?,
        };
        self.held = data.revision;
        self.pushed
            .fetch_max(data.revision.get(), Ordering::Relaxed);
        Ok(data)
    }

    async fn next(&mut self) -> Result<FeedEvent, FeedError> {
        loop {
            let queue = Arc::clone(&self.queue);
            let notified = queue.ready.notified();
            if let Some(item) = self.next_queued() {
                return match item {
                    Pushed::Image(data) => {
                        self.held = data.revision;
                        Ok(FeedEvent::Reset(data))
                    }
                    Pushed::Changes {
                        mut revision,
                        mut rows,
                    } => {
                        // Change sets that queued up while the writer was busy become one
                        // delta: the writer copies each touched scope once for all of them.
                        self.merge_queued(&mut revision, &mut rows);
                        let decoded = if rows.len() < DECODE_ASIDE {
                            decode(&rows)
                        } else {
                            tokio::task::spawn_blocking(move || decode(&rows))
                                .await
                                .map_err(|error| FeedError::Source(error.to_string()))?
                        };
                        match decoded {
                            Ok(changes) => {
                                let from = self.held;
                                self.held = revision;
                                Ok(FeedEvent::Delta(Delta {
                                    from,
                                    to: revision,
                                    changes,
                                }))
                            }
                            Err(error) => {
                                tracing::error!(%error, %revision, "the DNS feed could not decode a change set; it reads a whole image instead");
                                self.reset().await
                            }
                        }
                    }
                    Pushed::Lost(_) => self.reset().await,
                };
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests;
