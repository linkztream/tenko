//! The controller side of `Config.Watch` (OPS-28): a node's configuration as resumable
//! deltas from the journal, or a compressed snapshot when the journal no longer covers the
//! revision the node holds.
//!
//! A node's configuration is the set of rows keyed by its node id in the tables of
//! [`CONFIG_TABLES`](super::tables::CONFIG_TABLES) for its roles (its [`Subset`]). Every
//! message is computed against one read view `V`: a delta from revision `S` lists every
//! row of the subset that a change set in `(S, V]` of `sys.journal` touched, with its value
//! at `V` (or none when it is gone), and says revision `V`. Rows are whole values, so
//! applying a delta twice, or a delta whose rows the node already holds, changes nothing,
//! and a delta never misses a change: every revision in `(S, V]` was read in the same view.
//! The first message answers the node's `from_revision`; later ones follow the store's
//! watch. Any controller serves a node from its own copy: a follower answers once it has
//! applied the revision the node holds, otherwise it refuses with `node.config.behind` and
//! the node tries another controller.
//!
//! The stream is paced by the bandwidth cap ([`super::rate`]): a payload is sent in chunks
//! with `partial` set on all but the last, and each chunk waits for its tokens.

use std::{collections::BTreeSet, time::Duration};

use futures::{FutureExt as _, StreamExt as _};
use tenko_core::{NodeId, Revision, Role, TableName, codec::key::encode_key, serde_util::HexBytes};
use tenko_store::{
    ChangeStream, KeyRange, ReadConsistency, ReadView, ReadViewExt, StoreError, WatchError,
    WatchFilter, tables::JOURNAL,
};
use tokio::sync::mpsc;
use tonic::Status;

use super::{
    NodeSync, codes,
    payload::{self, ConfigEntry, ConfigPayload},
    rate::{TokenBucket, chunks},
    store_error,
    tables::{role_tables_for, tables_for},
};
use crate::{error::ClusterError, proto::v1, server::status_of};

/// A delta that would read more change sets than this is sent as a snapshot instead.
pub const MAX_JOURNAL_SCAN: u64 = 50_000;
/// Change sets read from the journal per page.
const JOURNAL_PAGE: usize = 1024;
/// How long the watch waits before it opens the store's change stream again after an
/// error.
const REOPEN_PAUSE: Duration = Duration::from_millis(200);

/// The rows a node receives.
///
/// The stream carries the node's configuration rows. The whole tables its roles will serve
/// from ([`Subset::role_tables`], the `dns` tables for a `dns` node) are declared here and
/// served from Phase 5 on; in Phase 2 no node consumes them (plan section 2.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subset {
    node: NodeId,
    tables: Vec<TableName>,
    role_tables: Vec<TableName>,
    key: Vec<u8>,
}

/// One message of the stream, before it is chunked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The revision after the message.
    pub revision: Revision,
    /// Whether it replaces what the node holds.
    pub snapshot: bool,
    /// The rows.
    pub payload: ConfigPayload,
}

impl Subset {
    /// The subset of a node with `roles`.
    pub fn new(node: NodeId, roles: &[Role]) -> Self {
        Self {
            node,
            tables: tables_for(roles),
            role_tables: role_tables_for(roles),
            key: encode_key(&node.0).to_vec(),
        }
    }

    /// The node.
    pub fn node(&self) -> NodeId {
        self.node
    }

    /// The whole tables the node's roles serve from (declared, not streamed in Phase 2).
    pub fn role_tables(&self) -> &[TableName] {
        &self.role_tables
    }

    /// Whether the subset has configuration rows at all (a node whose roles use no
    /// configuration); the declared [`Subset::role_tables`] do not count.
    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }

    /// The store filter that wakes the stream.
    pub fn filter(&self) -> WatchFilter {
        WatchFilter::tables(self.tables.iter().cloned())
    }

    /// Whether a row belongs to the subset.
    pub fn contains(&self, table: &TableName, key: &[u8]) -> bool {
        key == self.key.as_slice() && self.tables.contains(table)
    }

    /// Every row of the subset in `view`.
    ///
    /// # Errors
    ///
    /// A store error.
    pub fn snapshot(&self, view: &dyn ReadView) -> Result<ConfigPayload, StoreError> {
        let mut entries = Vec::new();
        for table in &self.tables {
            if let Some(row) = view.get(table, &self.key)? {
                entries.push(ConfigEntry {
                    table: table.as_str().to_owned(),
                    key: HexBytes(self.key.clone()),
                    value: Some(HexBytes(row.value.to_vec())),
                });
            }
        }
        Ok(ConfigPayload { entries })
    }

    /// The rows of the subset that a change set in `(from, view]` touched, with their
    /// values in `view`; `None` when the journal of `view` no longer covers `from`, or the
    /// gap is larger than [`MAX_JOURNAL_SCAN`].
    ///
    /// # Errors
    ///
    /// A store error.
    pub fn delta_since(
        &self,
        view: &dyn ReadView,
        from: Revision,
    ) -> Result<Option<ConfigPayload>, StoreError> {
        let to = view.revision();
        if to <= from {
            return Ok(Some(ConfigPayload::default()));
        }
        if to.0 - from.0 > MAX_JOURNAL_SCAN {
            return Ok(None);
        }
        let mut touched: BTreeSet<TableName> = BTreeSet::new();
        let mut expected = from.next();
        let mut range = KeyRange::all().after(JOURNAL.key(&from));
        loop {
            let page = view.scan_typed(&JOURNAL, range.clone(), JOURNAL_PAGE, false)?;
            let full = page.len() == JOURNAL_PAGE;
            for (revision, change_set, _) in &page {
                if *revision > to {
                    break;
                }
                if *revision != expected {
                    // A gap: the journal was compacted past `from`.
                    return Ok(None);
                }
                expected = expected.next();
                for change in &change_set.changes {
                    if self.contains(&change.table, &change.key) {
                        touched.insert(change.table.clone());
                    }
                }
            }
            match page.last() {
                Some((revision, _, _)) if full && *revision < to => {
                    range = KeyRange::all().after(JOURNAL.key(revision));
                }
                _ => break,
            }
        }
        if expected <= to {
            // The journal ends before the view's revision.
            return Ok(None);
        }
        let mut entries = Vec::with_capacity(touched.len());
        for table in touched {
            let value = view.get(&table, &self.key)?;
            entries.push(ConfigEntry {
                table: table.as_str().to_owned(),
                key: HexBytes(self.key.clone()),
                value: value.map(|row| HexBytes(row.value.to_vec())),
            });
        }
        Ok(Some(ConfigPayload { entries }))
    }

    /// The message that brings a node from `from` to `view`: a snapshot for `from` 0 or a
    /// journal that does not cover it, a delta otherwise (possibly empty).
    ///
    /// # Errors
    ///
    /// A store error.
    pub fn catch_up(&self, view: &dyn ReadView, from: Revision) -> Result<Message, StoreError> {
        let revision = view.revision();
        if from != Revision::ZERO
            && let Some(payload) = self.delta_since(view, from)?
        {
            return Ok(Message {
                revision,
                snapshot: false,
                payload,
            });
        }
        Ok(Message {
            revision,
            snapshot: true,
            payload: self.snapshot(view)?,
        })
    }
}

/// Encodes a message into the stream messages it is sent as, chunked for `kbps`.
///
/// # Errors
///
/// The error of a payload that does not encode.
pub fn frames(message: &Message, kbps: u64) -> Result<Vec<v1::ConfigDelta>, ClusterError> {
    let (encoding, bytes) = if message.snapshot {
        payload::encode_snapshot(&message.payload)?
    } else {
        payload::encode_delta(&message.payload)?
    };
    let parts = chunks(&bytes, kbps);
    let last = parts.len().saturating_sub(1);
    Ok(parts
        .into_iter()
        .enumerate()
        .map(|(index, part)| v1::ConfigDelta {
            revision: message.revision.0,
            snapshot: message.snapshot,
            encoding: encoding.to_owned(),
            payload: part.to_vec(),
            partial: index < last,
        })
        .collect())
}

type Sink = mpsc::Sender<Result<v1::ConfigDelta, Status>>;

/// Sends a message through `tx` under the cap; `false` when the node went away.
async fn send(
    tx: &Sink,
    message: &Message,
    kbps: u64,
    bucket: &mut Option<TokenBucket>,
) -> Result<bool, ClusterError> {
    for frame in frames(message, kbps)? {
        if let Some(bucket) = bucket.as_mut() {
            bucket.take(frame.payload.len()).await;
        }
        if tx.send(Ok(frame)).await.is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The view a node at `from` can be served from: the local copy once it has reached
/// `from`, waiting for it for a while on a follower that lags.
async fn view_at_least(
    sync: &NodeSync,
    from: Revision,
) -> Result<std::sync::Arc<dyn ReadView>, ClusterError> {
    let local = sync
        .store()
        .read(ReadConsistency::Local)
        .await
        .map_err(store_error)?;
    if local.revision() >= from {
        return Ok(local);
    }
    drop(local);
    match sync.store().read(ReadConsistency::AtLeast(from)).await {
        Ok(view) => Ok(view),
        Err(StoreError::Timeout) => Err(ClusterError::new(
            codes::CONFIG_BEHIND,
            503,
            format!("this controller has not reached revision {from} of the configuration yet"),
        )),
        Err(error) => Err(store_error(error)),
    }
}

/// Serves one `Config.Watch` stream of `node` (with `roles`) from revision `from` into
/// `tx` until the node closes it.
pub async fn serve_watch(sync: NodeSync, node: NodeId, roles: Vec<Role>, from: u64, tx: Sink) {
    let subset = Subset::new(node, &roles);
    let kbps = sync.rate_kbps();
    let mut bucket = TokenBucket::new(kbps);
    let result = run(&sync, &subset, Revision(from), kbps, &mut bucket, &tx).await;
    if let Err(error) = result {
        tracing::debug!(node = %node, code = %error.code(), "the configuration stream ended: {}", error.detail());
        let _ = tx.send(Err(status_of(&error))).await;
    }
}

async fn run(
    sync: &NodeSync,
    subset: &Subset,
    from: Revision,
    kbps: u64,
    bucket: &mut Option<TokenBucket>,
    tx: &Sink,
) -> Result<(), ClusterError> {
    let view = view_at_least(sync, from).await?;
    let first = subset.catch_up(view.as_ref(), from)?;
    drop(view);
    let mut sent = first.revision;
    tracing::debug!(
        node = %subset.node(),
        revision = %sent,
        snapshot = first.snapshot,
        rows = first.payload.entries.len(),
        "configuration stream opened"
    );
    if !send(tx, &first, kbps, bucket).await? {
        return Ok(());
    }
    let mut changes = open(sync, subset, sent);
    loop {
        let woke = tokio::select! {
            () = tx.closed() => return Ok(()),
            item = next(&mut changes) => item,
        };
        match woke {
            Wake::Changed => drain(&mut changes),
            Wake::Reopen => {
                tokio::time::sleep(REOPEN_PAUSE).await;
                changes = open(sync, subset, sent);
                // The journal may be gone; the catch-up below decides.
            }
        }
        let view = sync
            .store()
            .read(ReadConsistency::Local)
            .await
            .map_err(store_error)?;
        if view.revision() <= sent {
            continue;
        }
        let message = subset.catch_up(view.as_ref(), sent)?;
        drop(view);
        let revision = message.revision;
        if message.snapshot || !message.payload.entries.is_empty() {
            if !send(tx, &message, kbps, bucket).await? {
                return Ok(());
            }
            tracing::debug!(node = %subset.node(), revision = %revision, snapshot = message.snapshot, "configuration change sent");
        }
        sent = revision;
    }
}

enum Wake {
    Changed,
    Reopen,
}

fn open(sync: &NodeSync, subset: &Subset, from: Revision) -> Option<ChangeStream> {
    match sync.store().watch(Some(from), subset.filter()) {
        Ok(stream) => Some(stream),
        Err(error) => {
            tracing::debug!(%error, "the configuration watch could not open; it is retried");
            None
        }
    }
}

async fn next(changes: &mut Option<ChangeStream>) -> Wake {
    let Some(stream) = changes else {
        tokio::time::sleep(REOPEN_PAUSE).await;
        return Wake::Reopen;
    };
    match stream.next().await {
        Some(Ok(_)) => Wake::Changed,
        Some(Err(WatchError::Lagged { .. } | WatchError::Compacted { .. })) | None => {
            *changes = None;
            Wake::Reopen
        }
    }
}

/// Takes the change sets that have arrived already, without waiting.
fn drain(changes: &mut Option<ChangeStream>) {
    if let Some(stream) = changes {
        while let Some(Some(Ok(_))) = stream.next().now_or_never() {}
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tenko_core::{RequestCtx, SystemComponent};
    use tenko_store::{
        Store, WriteBatch,
        mem::{MemStore, MemStoreConfig},
    };

    use super::super::tables::PROBE_CONFIG;
    use super::*;

    fn row(value: u32) -> Vec<u8> {
        tenko_core::codec::to_cbor(&std::collections::BTreeMap::from([(
            "value".to_owned(),
            value,
        )]))
        .expect("encode")
        .to_vec()
    }

    async fn put(store: &MemStore, node: u64, value: Option<u32>) -> Revision {
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Scan));
        let key = encode_key(&node);
        match value {
            Some(value) => batch.put(PROBE_CONFIG, key, row(value)),
            None => batch.delete(PROBE_CONFIG, key),
        };
        store.propose(batch).await.expect("propose").revision
    }

    async fn view(store: &MemStore) -> Arc<dyn ReadView> {
        store.read(ReadConsistency::Local).await.expect("view")
    }

    #[tokio::test]
    async fn a_delta_carries_only_the_rows_of_the_node_that_changed() {
        let store = MemStore::default();
        let subset = Subset::new(NodeId(1001), &[Role::Probe]);
        assert!(!subset.is_empty());
        assert_eq!(subset.role_tables(), []);
        // A dns node has no configuration rows of its role yet; its tables are declared for
        // Phase 5.
        let dns = Subset::new(NodeId(1001), &[Role::Dns]);
        // node-roles: every node receives its stored role set.
        assert!(!dns.is_empty());
        assert!(dns.contains(
            &TableName::from_static("nodes.roles"),
            &encode_key(&1001u64)
        ));
        assert!(!dns.contains(&PROBE_CONFIG, &encode_key(&1001u64)));
        // node-roles: end.
        let tables: Vec<&str> = dns.role_tables().iter().map(TableName::as_str).collect();
        // WP10.0: the trust anchors, the negative trust anchors and their index.
        assert_eq!(tables.len(), 12);
        assert!(tables.contains(&"dns.zones") && tables.contains(&"dns.rrsets"));
        assert!(tables.contains(&"dns.journal") && tables.contains(&"dns.keys.meta"));
        assert!(!tables.contains(&"dns.sign_state"));
        // WP7.0: a dhcp node's tables are declared for Phase 5 as well.
        let dhcp = Subset::new(NodeId(1001), &[Role::Dhcp]);
        let tables: Vec<&str> = dhcp.role_tables().iter().map(TableName::as_str).collect();
        assert!(tables.contains(&"dhcp.scopes") && tables.contains(&"dhcp.leases"));
        assert!(!tables.contains(&"dhcp.history") && !tables.contains(&"dns.zones"));
        let first = put(&store, 1001, Some(1)).await;
        put(&store, 1002, Some(9)).await;
        // From scratch: a snapshot with the one row.
        let message = subset
            .catch_up(view(&store).await.as_ref(), Revision::ZERO)
            .expect("catch up");
        assert!(message.snapshot);
        assert_eq!(message.payload.entries.len(), 1);
        assert_eq!(
            message.payload.entries[0]
                .value
                .as_ref()
                .map(|v| v.0.clone()),
            Some(row(1))
        );
        // From the first write: nothing of this node changed since.
        let message = subset
            .catch_up(view(&store).await.as_ref(), first)
            .expect("catch up");
        assert!(!message.snapshot);
        assert_eq!(message.payload.entries.len(), 0);
        // A change and a removal show up as rows.
        put(&store, 1001, Some(2)).await;
        let message = subset
            .catch_up(view(&store).await.as_ref(), first)
            .expect("catch up");
        assert_eq!(message.payload.entries.len(), 1);
        assert_eq!(
            message.payload.entries[0]
                .value
                .as_ref()
                .map(|v| v.0.clone()),
            Some(row(2))
        );
        put(&store, 1001, None).await;
        let message = subset
            .catch_up(view(&store).await.as_ref(), first)
            .expect("catch up");
        assert_eq!(message.payload.entries.len(), 1);
        assert!(message.payload.entries[0].value.is_none());
        assert_eq!(message.revision, view(&store).await.revision());
    }

    #[tokio::test]
    async fn a_revision_the_journal_does_not_hold_gets_a_snapshot() {
        let store = MemStore::default();
        let subset = Subset::new(NodeId(1001), &[Role::Probe]);
        put(&store, 1001, Some(1)).await;
        let current = view(&store).await;
        // A revision far ahead of the view (another installation) cannot be a delta.
        assert!(
            subset
                .delta_since(current.as_ref(), Revision(0))
                .expect("delta")
                .is_some()
        );
        let far = Revision(current.revision().0 + 10);
        assert_eq!(
            subset.delta_since(current.as_ref(), far).expect("delta"),
            Some(ConfigPayload::default())
        );
        // A journal that keeps two change sets no longer covers the first revisions.
        let store = MemStore::new(MemStoreConfig {
            journal_retention: 2,
            ..MemStoreConfig::default()
        });
        let first = put(&store, 1001, Some(1)).await;
        for value in 2..6 {
            put(&store, 1001, Some(value)).await;
        }
        let current = view(&store).await;
        assert_eq!(
            subset.delta_since(current.as_ref(), first).expect("delta"),
            None
        );
        let message = subset.catch_up(current.as_ref(), first).expect("catch up");
        assert!(message.snapshot);
        assert_eq!(message.payload.entries.len(), 1);
    }

    #[test]
    fn frames_chunk_under_a_cap_and_mark_the_continuations() {
        let message = Message {
            revision: Revision(7),
            snapshot: false,
            payload: ConfigPayload {
                entries: vec![ConfigEntry {
                    table: "scan.probe_config".to_owned(),
                    key: HexBytes(vec![1; 8]),
                    value: Some(HexBytes(vec![0x42; 100_000])),
                }],
            },
        };
        let whole = frames(&message, 0).expect("frames");
        assert_eq!(whole.len(), 1);
        assert!(!whole[0].partial);
        let paced = frames(&message, 64).expect("frames");
        assert!(paced.len() > 1);
        assert!(paced[..paced.len() - 1].iter().all(|frame| frame.partial));
        assert!(!paced[paced.len() - 1].partial);
        let joined: Vec<u8> = paced
            .iter()
            .flat_map(|frame| frame.payload.clone())
            .collect();
        assert_eq!(joined, whole[0].payload);
        assert_eq!(
            payload::decode(&paced[0].encoding, &joined).expect("decode"),
            message.payload
        );
    }
}
