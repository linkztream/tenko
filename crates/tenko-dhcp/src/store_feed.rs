//! The in-process DHCP feed (plan section 2.2, WP7.5): the `dhcp` role of a controller
//! reads its rows from the controller's own store through a [`DerivedIndex`], as the `dns`
//! role does (`tenko_dns::store_feed`).
//!
//! [`register`] registers a [`StoreIndex`] with the store and returns the [`StoreFeed`]
//! the role follows. The store drives the index:
//!
//! - **build and install**: at registration, and again whenever the store rebuilds its
//!   derived indexes (a snapshot install on the Raft store), the index reads every row the
//!   role serves from ([`crate::config::load::data`]: the `dhcp` tables of the node role,
//!   the leases, and the IPAM rows of `NODE_IPAM_TABLES`) into one [`DhcpData`] and hands
//!   it to the feed. The first image is what [`DhcpFeed::snapshot`] returns before the role
//!   listens; a later one reaches the role as one [`FeedEvent::Reset`], from which it
//!   builds the configuration image and the lease table aside and swaps both at once.
//! - **apply**: every change set that touches those tables becomes one [`Delta`] with the
//!   changed rows read at the change set's revision, in revision order. `apply` only looks
//!   the rows up and queues their stored bytes; the feed decodes them, never the store's
//!   apply path. A change set that cannot be read or decoded makes the feed read a whole
//!   image instead (a reset), so a delta never goes missing.
//!
//! The rows of `dhcp.leases.by_client` are in the filter (the index is part of a lease
//! commit) but are not carried: the role derives its client index from the rows. A change
//! set that touches none of the tables does not reach the feed, so a delta runs from the
//! revision of the previous one (or the image) to its own.

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
    dhcp::tables::{
        CLASSES, EXCLUSIONS, FILTERS, LEASES, LEASES6, NODE_IPAM_TABLES, NODE_TABLES, OPTION_DEFS,
        OPTION_SETS, POLICIES, POOLS, SCOPES, SETTINGS, SHARED_NETWORKS,
    },
    table::TableDef,
};
use tenko_ipam::tables::{ADDRESSES, HOSTS, INTERFACES, PREFIXES, RANGES};
use tenko_store::{
    ChangeSet, DerivedIndex, IndexImage, ReadConsistency, ReadView, Store, StoreError, WatchFilter,
    downcast_image,
};
use tokio::sync::Notify;

use crate::feed::{Change, Delta, DhcpData, DhcpFeed, FeedError, FeedEvent};

/// The name of the derived index.
pub const INDEX: &str = "dhcp.serving";

/// What the index hands to the feed.
#[derive(Debug)]
enum Pushed {
    /// A complete image (registration, a rebuild after a snapshot install).
    Image(Box<DhcpData>),
    /// The rows of one change set, at its revision, as the store holds them.
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
struct Image(DhcpData);

impl IndexImage for Image {
    fn revision(&self) -> Revision {
        self.0.revision
    }
}

/// Every row the role serves from at the view's revision, the leases included.
///
/// # Errors
///
/// A store or codec error.
pub fn read_image(view: &dyn ReadView) -> Result<DhcpData, StoreError> {
    crate::config::load::data(view, true).map_err(|error| StoreError::Codec(error.to_string()))
}

/// The derived index of the `dhcp` role. Registered once per process by [`register`].
#[derive(Debug)]
pub struct StoreIndex {
    queue: Arc<Queue>,
    /// The revision of the newest change the store applied (or of the newest image).
    pushed: Arc<AtomicU64>,
}

impl StoreIndex {
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

/// Decodes one row into its change; rows of tables the role does not carry give `None`.
fn decode_one(row: &RawRow) -> Result<Option<Change>, StoreError> {
    let table = &row.table;
    macro_rules! pick {
        ($($def:expr => $variant:ident),* $(,)?) => {
            $(if table == $def.name() {
                let (key, value) = decode_row(&$def, row)?;
                return Ok(Some(Change::$variant(key, value)));
            })*
        };
    }
    if table == SETTINGS.name() {
        let ((), value) = decode_row(&SETTINGS, row)?;
        return Ok(Some(Change::Settings(value)));
    }
    pick!(
        SCOPES => Scope,
        SHARED_NETWORKS => SharedNetwork,
        POOLS => Pool,
        EXCLUSIONS => Exclusion,
        OPTION_DEFS => OptionDef,
        OPTION_SETS => OptionSet,
        CLASSES => Class,
        POLICIES => Policy,
        FILTERS => Filter,
        LEASES => Lease,
        // WP9.1: the DHCPv6 leases.
        LEASES6 => Lease6,
        PREFIXES => Prefix,
        RANGES => Range,
        HOSTS => Host,
        INTERFACES => Interface,
        ADDRESSES => Address,
    );
    Ok(None)
}

/// Decodes the changed rows of change sets; rows of other tables are skipped.
fn decode(rows: &[RawRow]) -> Result<Vec<Change>, StoreError> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(change) = decode_one(row)? {
            out.push(change);
        }
    }
    Ok(out)
}

impl DerivedIndex for StoreIndex {
    fn name(&self) -> &'static str {
        INDEX
    }

    fn filter(&self) -> WatchFilter {
        WatchFilter::tables(NODE_TABLES.iter().chain(NODE_IPAM_TABLES.iter()).cloned())
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
                tracing::error!(%error, revision = %changes.revision, "the DHCP feed could not read a change set; it reads a whole image instead");
                self.queue.push(Pushed::Lost(changes.revision));
            }
        }
    }
}

/// What the role reads about its feed for the status report.
#[derive(Debug, Clone, Default)]
pub struct FeedProgress {
    pushed: Arc<AtomicU64>,
}

impl FeedProgress {
    /// The revision of the newest change of the role's tables the store applied.
    pub fn store_revision(&self) -> Revision {
        Revision(self.pushed.load(Ordering::Relaxed))
    }

    /// Revisions between that change and `held` (0 when the role holds it).
    pub fn lag(&self, held: Revision) -> u64 {
        self.store_revision().get().saturating_sub(held.get())
    }
}

/// The feed the `dhcp` role follows: the [`DhcpFeed`] over a [`StoreIndex`].
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

/// Registers the index of the `dhcp` role with `store` and returns its feed. The store
/// builds the first image here, from a local read view: run it off the async threads.
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

    async fn read_fresh(&self) -> Result<DhcpData, FeedError> {
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
    /// moves `revision` to the last of them.
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

    async fn reset(&mut self) -> Result<FeedEvent, FeedError> {
        let data = self.read_fresh().await?;
        self.held = data.revision;
        self.pushed
            .fetch_max(data.revision.get(), Ordering::Relaxed);
        Ok(FeedEvent::Reset(Box::new(data)))
    }

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

impl DhcpFeed for StoreFeed {
    async fn snapshot(&mut self) -> Result<DhcpData, FeedError> {
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
                                tracing::error!(%error, %revision, "the DHCP feed could not decode a change set; it reads a whole image instead");
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
