//! The zone feed (plan section 2.1): how the engine learns the rows it serves.
//!
//! The engine never holds a store handle. A [`ZoneFeed`] gives it one image of the DNS rows
//! at a revision ([`DnsData`]) and then the changes after it as [`Delta`]s in revision
//! order, or a new image ([`FeedEvent::Reset`]) when it cannot (a snapshot was installed,
//! the journal no longer covers the gap). In Phase 2 the only production feed is the
//! in-process feed of WP4.3 on the controller's `DerivedIndex`; the node-file feed of a `dns`
//! node without a controller is Phase 5 (plan section 2.10). [`MemFeed`] is the reference
//! implementation for tests and the index's oracle.

use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex, PoisonError},
};

use tenko_core::{
    Revision,
    dns::{
        Acl, AclId, BlockList, BlockListId, ForwardRule, ForwardRuleId, JournalEntry, KeyMeta,
        KeyName, ListVersion, RrSet, RrSetKey, ScopeName, View, ViewId, Zone, ZoneId,
    },
};
use tokio::sync::mpsc;

/// Every row the engine serves from, at one revision. The tables are those of the `dns`
/// node role (`tenko_core::dns::tables::NODE_TABLES`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsData {
    /// The store revision of the image.
    pub revision: Revision,
    /// `dns.zones`.
    pub zones: BTreeMap<ZoneId, Zone>,
    /// `dns.rrsets`.
    pub rrsets: BTreeMap<RrSetKey, RrSet>,
    /// `dns.views`.
    pub views: BTreeMap<ViewId, View>,
    /// `dns.forwarders`.
    pub forwarders: BTreeMap<ForwardRuleId, ForwardRule>,
    /// `dns.acls`.
    pub acls: BTreeMap<AclId, Acl>,
    /// `dns.keys.meta`.
    pub keys: BTreeMap<KeyName, KeyMeta>,
    /// `dns.lists`.
    pub lists: BTreeMap<BlockListId, BlockList>,
    /// `dns.list_versions`.
    pub list_versions: BTreeMap<(BlockListId, u64), ListVersion>,
    /// `dns.journal`.
    pub journal: BTreeMap<(ZoneId, ScopeName, Revision), JournalEntry>,
}

/// One changed row: its key and its value after the change, or `None` when it is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "changes are built once per commit and moved into a delta, never kept in bulk"
)]
pub enum Change {
    /// A zone.
    Zone(ZoneId, Option<Zone>),
    /// An RRset.
    RrSet(RrSetKey, Option<RrSet>),
    /// A view.
    View(ViewId, Option<View>),
    /// A forwarding rule.
    Forwarder(ForwardRuleId, Option<ForwardRule>),
    /// An access list.
    Acl(AclId, Option<Acl>),
    /// TSIG key metadata.
    Key(KeyName, Option<KeyMeta>),
    /// A block list.
    List(BlockListId, Option<BlockList>),
    /// A compiled block list version.
    ListVersion((BlockListId, u64), Option<ListVersion>),
    /// A journal entry.
    Journal((ZoneId, ScopeName, Revision), Option<JournalEntry>),
}

fn set<K: Ord + Clone, V: Clone>(map: &mut BTreeMap<K, V>, key: &K, value: Option<&V>) {
    match value {
        Some(value) => {
            map.insert(key.clone(), value.clone());
        }
        None => {
            map.remove(key);
        }
    }
}

impl DnsData {
    /// An empty image at a revision.
    pub fn at(revision: Revision) -> Self {
        Self {
            revision,
            ..Self::default()
        }
    }

    /// Applies one change.
    pub fn apply_change(&mut self, change: &Change) {
        match change {
            Change::Zone(key, value) => set(&mut self.zones, key, value.as_ref()),
            Change::RrSet(key, value) => set(&mut self.rrsets, key, value.as_ref()),
            Change::View(key, value) => set(&mut self.views, key, value.as_ref()),
            Change::Forwarder(key, value) => set(&mut self.forwarders, key, value.as_ref()),
            Change::Acl(key, value) => set(&mut self.acls, key, value.as_ref()),
            Change::Key(key, value) => set(&mut self.keys, key, value.as_ref()),
            Change::List(key, value) => set(&mut self.lists, key, value.as_ref()),
            Change::ListVersion(key, value) => set(&mut self.list_versions, key, value.as_ref()),
            Change::Journal(key, value) => set(&mut self.journal, key, value.as_ref()),
        }
    }

    /// Applies a delta that starts at this image's revision.
    ///
    /// # Errors
    ///
    /// [`FeedError::Gap`] when the delta does not start at this revision or does not move
    /// forward; the image is unchanged.
    pub fn apply(&mut self, delta: &Delta) -> Result<(), FeedError> {
        if delta.from != self.revision || delta.to <= delta.from {
            return Err(FeedError::Gap {
                held: self.revision,
                from: delta.from,
            });
        }
        for change in &delta.changes {
            self.apply_change(change);
        }
        self.revision = delta.to;
        Ok(())
    }
}

/// The changes between two revisions. Rows are whole values: applying a change twice
/// changes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    /// The revision the delta starts from.
    pub from: Revision,
    /// The revision after it.
    pub to: Revision,
    /// The changed rows, in commit order.
    pub changes: Vec<Change>,
}

/// What a feed delivers after the first image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedEvent {
    /// The changes after the revision the engine holds.
    Delta(Delta),
    /// A new image that replaces everything; the engine rebuilds and swaps (M1).
    Reset(Box<DnsData>),
}

/// Why a feed failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    /// The source went away; the engine keeps serving what it holds (OPS-02).
    #[error("the zone feed is closed")]
    Closed,
    /// A delta does not follow the revision held.
    #[error("a delta from revision {from} does not follow revision {held}")]
    Gap {
        /// The revision held.
        held: Revision,
        /// The revision the delta starts at.
        from: Revision,
    },
    /// The source could not be read.
    #[error("the zone feed failed: {0}")]
    Source(String),
}

/// The source of the rows the engine serves.
pub trait ZoneFeed: Send {
    /// The current image. The engine builds its index from it before it listens.
    ///
    /// # Errors
    ///
    /// [`FeedError`] when the source cannot be read.
    fn snapshot(&mut self) -> impl Future<Output = Result<DnsData, FeedError>> + Send;

    /// Waits for what follows the image or the last event: a delta starting at its
    /// revision, or a reset.
    ///
    /// # Errors
    ///
    /// [`FeedError::Closed`] when the source went away.
    fn next(&mut self) -> impl Future<Output = Result<FeedEvent, FeedError>> + Send;
}

#[derive(Debug)]
struct Shared {
    data: DnsData,
}

/// The in-memory reference feed: [`MemFeedHandle::publish`] commits changes to its image
/// and hands them to the feed as one delta.
#[derive(Debug)]
pub struct MemFeed {
    shared: Arc<Mutex<Shared>>,
    events: mpsc::UnboundedReceiver<FeedEvent>,
    held: Revision,
}

/// The writing side of a [`MemFeed`].
#[derive(Debug, Clone)]
pub struct MemFeedHandle {
    shared: Arc<Mutex<Shared>>,
    events: mpsc::UnboundedSender<FeedEvent>,
}

impl MemFeed {
    /// A feed whose first image is `data`, and its handle.
    pub fn new(data: DnsData) -> (MemFeed, MemFeedHandle) {
        let held = data.revision;
        let shared = Arc::new(Mutex::new(Shared { data }));
        let (sender, receiver) = mpsc::unbounded_channel();
        (
            MemFeed {
                shared: Arc::clone(&shared),
                events: receiver,
                held,
            },
            MemFeedHandle {
                shared,
                events: sender,
            },
        )
    }
}

impl MemFeedHandle {
    /// Commits `changes` as the next revision and returns it.
    pub fn publish(&self, changes: Vec<Change>) -> Revision {
        let mut shared = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        let from = shared.data.revision;
        let delta = Delta {
            from,
            to: from.next(),
            changes,
        };
        for change in &delta.changes {
            shared.data.apply_change(change);
        }
        shared.data.revision = delta.to;
        let to = delta.to;
        // A dropped feed is no error for the writer.
        let _ = self.events.send(FeedEvent::Delta(delta));
        to
    }

    /// Replaces the image, as a snapshot install does.
    pub fn reset(&self, data: DnsData) {
        let mut shared = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        shared.data = data.clone();
        let _ = self.events.send(FeedEvent::Reset(Box::new(data)));
    }

    /// The current image.
    pub fn image(&self) -> DnsData {
        self.shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .data
            .clone()
    }
}

impl ZoneFeed for MemFeed {
    fn snapshot(&mut self) -> impl Future<Output = Result<DnsData, FeedError>> + Send {
        let data = self
            .shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .data
            .clone();
        self.held = data.revision;
        std::future::ready(Ok(data))
    }

    async fn next(&mut self) -> Result<FeedEvent, FeedError> {
        loop {
            let event = self.events.recv().await.ok_or(FeedError::Closed)?;
            match &event {
                // A delta the image already holds.
                FeedEvent::Delta(delta) if delta.to <= self.held => {}
                FeedEvent::Delta(delta) => {
                    self.held = delta.to;
                    return Ok(event);
                }
                FeedEvent::Reset(data) => {
                    self.held = data.revision;
                    return Ok(event);
                }
            }
        }
    }
}
