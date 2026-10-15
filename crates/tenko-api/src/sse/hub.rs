//! The event hub: encoding, the replay ring, fan-out, the journal feeder and the
//! per-subscriber stream.

use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    convert::Infallible,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt, stream};
use tenko_core::{ObjectRef, Principal, Revision, codec::decode_key};
use tenko_store::{
    ChangeSet, KeyRange, ReadConsistency, Store, StoreError, WatchError, WatchFilter, tables,
};
use tokio::sync::{
    Notify,
    broadcast::{self, error::RecvError},
    watch,
};
use uuid::Uuid;

use super::{
    Admission, AdmitAll, EventData, EventFilter, EventRoutes, ResetData, ResetReason, SseConfig,
};
use crate::dto::events::{Topic, TopicSet};

const KEEPALIVE_FRAME: Bytes = Bytes::from_static(b": keep-alive\n\n");
const SHUTDOWN_FRAME: Bytes = Bytes::from_static(b"event: shutdown\ndata: {}\n\n");

/// One encoded event.
#[derive(Debug)]
pub(crate) struct Frame {
    /// Store revision (the SSE id); `None` for system events outside the journal.
    revision: Option<Revision>,
    topic: Topic,
    /// References the event carries, for the authorization filter.
    objects: Vec<ObjectRef>,
    /// The event itself, re-encoded when a filter keeps only some of its references.
    data: EventData,
    /// The complete SSE frame.
    bytes: Bytes,
}

/// What travels on the broadcast channel.
#[derive(Debug, Clone)]
enum Msg {
    Frame(Arc<Frame>),
    /// Frames published within one coalescing window.
    Batch(Arc<Vec<Arc<Frame>>>),
    KeepAlive,
    /// Every subscriber must reload (`reset` frame, revision to reload at).
    Reset(Bytes),
    Shutdown,
}

/// Replay state, guarded by one lock that `publish` also holds while it sends, so a
/// subscriber taking a snapshot sees no gap and no duplicate.
#[derive(Debug)]
struct Ring {
    frames: VecDeque<Arc<Frame>>,
    capacity: usize,
    /// Every frame with a revision above `floor` (up to `newest`) is in `frames`.
    floor: Revision,
    /// The newest revision handed to the channel.
    newest: Revision,
    /// Coalescing only: frames published since the last flush, and their newest revision.
    pending: Vec<Arc<Frame>>,
    pending_newest: Option<Revision>,
}

impl Ring {
    fn push(&mut self, frame: &Arc<Frame>) {
        if self.frames.len() == self.capacity
            && let Some(evicted) = self.frames.pop_front()
            && let Some(revision) = evicted.revision
        {
            self.floor = self.floor.max(revision);
        }
        self.frames.push_back(Arc::clone(frame));
    }
}

/// What a new subscriber is sent before live events.
#[derive(Debug)]
enum Replay {
    /// Up to date, or no position given.
    Nothing,
    /// Frames from the ring, oldest first.
    Frames(Vec<Arc<Frame>>),
    /// The ring does not reach back far enough: replay the journal in `(after, upto]`.
    Journal { after: Revision, upto: Revision },
    /// The position cannot be served: send `reset` at `revision`.
    Reset(Revision),
}

/// The event hub of a controller. Cloning is cheap and shares the hub.
#[derive(Clone)]
pub struct EventHub {
    inner: Arc<Inner>,
}

struct Inner {
    tx: broadcast::Sender<Msg>,
    ring: Mutex<Ring>,
    config: SseConfig,
    routes: EventRoutes,
    filter: ArcSwap<Box<dyn EventFilter>>,
    shutting_down: AtomicBool,
    subscribers: AtomicUsize,
    /// Open streams by topic, in the order of [`Topic::ALL`].
    topic_subscribers: [AtomicUsize; Topic::ALL.len()],
    /// Signalled when the count of a topic leaves zero.
    listened: Notify,
    published: AtomicU64,
}

impl std::fmt::Debug for EventHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventHub")
            .field("newest", &self.newest())
            .field("subscribers", &self.subscribers())
            .finish_non_exhaustive()
    }
}

impl EventHub {
    /// Creates a hub positioned at `start` (the store revision when the API starts).
    pub fn new(config: SseConfig, routes: EventRoutes, start: Revision) -> Self {
        let (tx, _) = broadcast::channel(config.channel_capacity.max(1));
        Self {
            inner: Arc::new(Inner {
                tx,
                ring: Mutex::new(Ring {
                    frames: VecDeque::with_capacity(config.ring_capacity.max(1)),
                    capacity: config.ring_capacity.max(1),
                    floor: start,
                    newest: start,
                    pending: Vec::new(),
                    pending_newest: None,
                }),
                config,
                routes,
                filter: ArcSwap::from_pointee(Box::new(AdmitAll)),
                shutting_down: AtomicBool::new(false),
                subscribers: AtomicUsize::new(0),
                topic_subscribers: std::array::from_fn(|_| AtomicUsize::new(0)),
                listened: Notify::new(),
                published: AtomicU64::new(0),
            }),
        }
    }

    /// The configuration.
    pub fn config(&self) -> &SseConfig {
        &self.inner.config
    }

    /// Installs the authorization filter of the stream (RBAC scopes, Slice 3).
    pub fn set_filter(&self, filter: Box<dyn EventFilter>) {
        self.inner.filter.store(Arc::new(filter));
    }

    /// The newest revision sent to subscribers.
    pub fn newest(&self) -> Revision {
        self.ring().newest
    }

    /// Open event streams.
    pub fn subscribers(&self) -> usize {
        self.inner.subscribers.load(Ordering::Relaxed)
    }

    /// Open event streams that receive `topic`. A stream that asked for `metrics` without
    /// the right to read it does not count.
    pub fn subscribers_of(&self, topic: Topic) -> usize {
        self.inner.topic_subscribers[topic as usize].load(Ordering::SeqCst)
    }

    /// Returns once at least one open stream receives `topic` (at once when one does).
    pub async fn listened(&self, topic: Topic) {
        loop {
            let notified = self.inner.listened.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.subscribers_of(topic) > 0 {
                return;
            }
            notified.await;
        }
    }

    /// Frames published since start.
    pub fn published(&self) -> u64 {
        self.inner.published.load(Ordering::Relaxed)
    }

    /// Whether [`EventHub::shutdown`] ran.
    pub fn is_shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::SeqCst)
    }

    fn ring(&self) -> std::sync::MutexGuard<'_, Ring> {
        self.inner
            .ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Publishes the events of one journal change set, in revision order.
    pub fn publish_change_set(&self, changes: &ChangeSet) {
        let frames = self.frames_for(changes);
        let mut ring = self.ring();
        if changes.revision <= ring.pending_newest.unwrap_or(ring.newest) {
            // Already published (a feeder restart replays from its last position).
            return;
        }
        for frame in &frames {
            ring.push(frame);
        }
        self.inner
            .published
            .fetch_add(frames.len() as u64, Ordering::Relaxed);
        if self.inner.config.coalesce.is_some() {
            ring.pending.extend(frames);
            ring.pending_newest = Some(changes.revision);
            return;
        }
        ring.newest = changes.revision;
        for frame in frames {
            let _ = self.inner.tx.send(Msg::Frame(frame));
        }
    }

    /// Publishes a system event that does not come from the store (no SSE id, not
    /// replayed). Store-backed alarms (`ipam.alarms`, `auth.alarms`) need no call: the
    /// journal routes them to the `system` topic.
    pub fn publish_system(&self, data: &EventData) {
        let frame = Arc::new(encode(None, data));
        self.inner.published.fetch_add(1, Ordering::Relaxed);
        let _ = self.inner.tx.send(Msg::Frame(frame));
    }

    /// Coalescing: sends everything published since the last flush as one batch.
    pub fn flush(&self) {
        let mut ring = self.ring();
        let Some(newest) = ring.pending_newest.take() else {
            return;
        };
        let frames = std::mem::take(&mut ring.pending);
        ring.newest = newest;
        if !frames.is_empty() {
            let _ = self.inner.tx.send(Msg::Batch(Arc::new(frames)));
        }
    }

    /// Tells every subscriber to reload at `revision` and restarts the ring there.
    pub fn reset_all(&self, revision: Revision, reason: ResetReason) {
        let mut ring = self.ring();
        ring.frames.clear();
        ring.pending.clear();
        ring.pending_newest = None;
        ring.floor = revision;
        ring.newest = revision;
        let _ = self
            .inner
            .tx
            .send(Msg::Reset(reset_frame(reason, revision)));
    }

    /// Sends the shared keep-alive comment.
    pub fn keepalive(&self) {
        let _ = self.inner.tx.send(Msg::KeepAlive);
    }

    /// Ends every stream with a `shutdown` event; new subscriptions are refused.
    pub fn shutdown(&self) {
        self.flush();
        self.inner.shutting_down.store(true, Ordering::SeqCst);
        let _ = self.inner.tx.send(Msg::Shutdown);
    }

    /// Subscribes to live events and computes the replay for `last`, atomically with
    /// respect to publishing.
    fn subscribe(&self, last: Option<Revision>) -> (broadcast::Receiver<Msg>, Replay) {
        let ring = self.ring();
        let rx = self.inner.tx.subscribe();
        let replay = match last {
            None => Replay::Nothing,
            Some(last) if last == ring.newest => Replay::Nothing,
            Some(last) if last > ring.newest => Replay::Reset(ring.newest),
            Some(last) if last >= ring.floor => Replay::Frames(
                ring.frames
                    .iter()
                    .filter(|frame| {
                        frame
                            .revision
                            .is_some_and(|revision| revision > last && revision <= ring.newest)
                    })
                    .cloned()
                    .collect(),
            ),
            Some(last) => Replay::Journal {
                after: last,
                upto: ring.newest,
            },
        };
        drop(ring);
        (rx, replay)
    }

    /// Turns a change set into at most one frame per topic.
    fn frames_for(&self, changes: &ChangeSet) -> Vec<Arc<Frame>> {
        let limit = self.inner.config.max_objects_per_event;
        let mut events: BTreeMap<Topic, (EventData, HashSet<ObjectRef>)> = BTreeMap::new();
        let revision = changes.revision;
        let new_entry = |topic: Topic| (EventData::new(topic, Some(revision)), HashSet::new());
        for change in &changes.changes {
            if &change.table == tables::AUDIT.name() {
                if let Ok(seq) = tables::AUDIT.decode_key(&change.key) {
                    let (data, _) = events
                        .entry(Topic::Audit)
                        .or_insert_with(|| new_entry(Topic::Audit));
                    data.audit.push(seq);
                }
                continue;
            }
            let Some(route) = self.inner.routes.lookup(&change.table) else {
                continue;
            };
            let (data, seen) = events
                .entry(route.topic)
                .or_insert_with(|| new_entry(route.topic));
            let object = route.kind.and_then(|kind| {
                decode_key::<Uuid>(&change.key)
                    .ok()
                    .map(|id| ObjectRef::new(kind, id))
            });
            match object {
                Some(object) if seen.insert(object) => {
                    if change.deleted {
                        data.deleted.push(object);
                    } else {
                        data.objects.push(object);
                    }
                }
                Some(_) => {}
                None => {
                    let name = change.table.as_str();
                    if !data.tables.iter().any(|table| table == name) {
                        data.tables.push(name.to_owned());
                    }
                }
            }
        }
        events
            .into_values()
            .map(|(mut data, _)| {
                if data.objects.len() + data.deleted.len() > limit {
                    data.objects.clear();
                    data.deleted.clear();
                    data.params
                        .insert("truncated".to_owned(), "true".to_owned());
                    data.kind = Some("truncated".to_owned());
                }
                Arc::new(encode(Some(changes.revision), &data))
            })
            .collect()
    }

    /// Starts the background tasks on the current runtime: the journal feeder, the shared
    /// keep-alive timer and, when coalescing, the flusher. They stop when `stop` turns
    /// true or the store shuts down.
    pub(crate) fn spawn_tasks(&self, store: Arc<dyn Store>, stop: watch::Receiver<bool>) {
        let hub = self.clone();
        let feeder_stop = stop.clone();
        tokio::spawn(async move { hub.feed(store, feeder_stop).await });

        let hub = self.clone();
        let mut keepalive_stop = stop.clone();
        let period = self.inner.config.keepalive.max(Duration::from_millis(10));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => hub.keepalive(),
                    _ = keepalive_stop.changed() => break,
                }
                if hub.is_shutting_down() {
                    break;
                }
            }
        });

        if let Some(window) = self.inner.config.coalesce {
            let hub = self.clone();
            let mut flush_stop = stop;
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(window.max(Duration::from_millis(1)));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = tick.tick() => hub.flush(),
                        _ = flush_stop.changed() => break,
                    }
                    if hub.is_shutting_down() {
                        break;
                    }
                }
            });
        }
    }

    /// Follows the store journal from the hub's position and publishes every change set.
    async fn feed(&self, store: Arc<dyn Store>, mut stop: watch::Receiver<bool>) {
        loop {
            if *stop.borrow() || self.is_shutting_down() {
                return;
            }
            let from = {
                let ring = self.ring();
                ring.pending_newest.unwrap_or(ring.newest)
            };
            let mut changes = match store.watch(Some(from), WatchFilter::all()) {
                Ok(changes) => changes,
                Err(StoreError::Compacted { .. }) => {
                    let current = store.status().revision;
                    tracing::warn!(%from, %current, "event feeder lost its journal position");
                    self.reset_all(current, ResetReason::Journal);
                    continue;
                }
                Err(StoreError::ShuttingDown) => return,
                Err(error) => {
                    tracing::warn!(%error, "event feeder cannot watch the store; retrying");
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_secs(1)) => continue,
                        _ = stop.changed() => return,
                    }
                }
            };
            loop {
                tokio::select! {
                    item = changes.next() => match item {
                        Some(Ok(change_set)) => self.publish_change_set(&change_set),
                        Some(Err(WatchError::Lagged { last })) => {
                            tracing::debug!(%last, "event feeder lagged; resuming from the journal");
                            break;
                        }
                        Some(Err(WatchError::Compacted { oldest })) => {
                            let current = store.status().revision;
                            tracing::warn!(%oldest, %current, "event feeder lost its journal position");
                            self.reset_all(current, ResetReason::Journal);
                            break;
                        }
                        None => return,
                    },
                    _ = stop.changed() => return,
                }
            }
        }
    }

    /// Frames of the journal in `(after, upto]`, for a subscriber whose position is older
    /// than the ring. `None` when the journal no longer reaches back to `after`.
    async fn journal_frames(
        &self,
        store: &dyn Store,
        after: Revision,
        upto: Revision,
    ) -> Option<Vec<Arc<Frame>>> {
        let span = upto.get().saturating_sub(after.get());
        let limit = usize::try_from(span).ok()?;
        if limit > self.inner.config.journal_replay_limit {
            return None;
        }
        let view = store.read(ReadConsistency::AtLeast(upto)).await.ok()?;
        let range = KeyRange::all()
            .after(tables::JOURNAL.key(&after))
            .before(tables::JOURNAL.key(&upto.next()));
        let rows = view
            .scan(tables::JOURNAL.name(), range, limit, false)
            .ok()?;
        let mut expected = after.next();
        let mut frames = Vec::new();
        for (_, versioned) in rows {
            let change_set = tables::JOURNAL.decode(&versioned.value).ok()?;
            if change_set.revision != expected {
                return None;
            }
            expected = expected.next();
            frames.extend(self.frames_for(&change_set));
        }
        (expected == upto.next()).then_some(frames)
    }
}

/// Encodes one event frame. JSON from `serde_json` is a single line, so the frame cannot
/// break the line-based SSE format.
fn encode(revision: Option<Revision>, data: &EventData) -> Frame {
    let json = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_owned());
    let topic = data.topic.as_str();
    let mut bytes = BytesMut::with_capacity(40 + topic.len() + json.len());
    if let Some(revision) = revision {
        bytes.extend_from_slice(b"id: ");
        bytes.extend_from_slice(revision.get().to_string().as_bytes());
        bytes.extend_from_slice(b"\n");
    }
    bytes.extend_from_slice(b"event: ");
    bytes.extend_from_slice(topic.as_bytes());
    bytes.extend_from_slice(b"\ndata: ");
    bytes.extend_from_slice(json.as_bytes());
    bytes.extend_from_slice(b"\n\n");
    Frame {
        revision,
        topic: data.topic,
        objects: data.objects.iter().chain(&data.deleted).copied().collect(),
        data: data.clone(),
        bytes: bytes.freeze(),
    }
}

/// The `reset` frame; its id is the revision to reload at, so a later reconnect resumes
/// from there.
fn reset_frame(reason: ResetReason, revision: Revision) -> Bytes {
    let data =
        serde_json::to_string(&ResetData { reason, revision }).unwrap_or_else(|_| "{}".to_owned());
    Bytes::from(format!("id: {revision}\nevent: reset\ndata: {data}\n\n"))
}

/// Counts an open stream, in all and per topic; dropped with the stream.
struct SubscriberGuard {
    inner: Arc<Inner>,
    topics: TopicSet,
}

impl SubscriberGuard {
    fn new(inner: &Arc<Inner>, topics: TopicSet) -> Self {
        inner.subscribers.fetch_add(1, Ordering::Relaxed);
        let mut first = false;
        for topic in topics.topics() {
            first |= inner.topic_subscribers[topic as usize].fetch_add(1, Ordering::SeqCst) == 0;
        }
        if first {
            inner.listened.notify_waiters();
        }
        Self {
            inner: Arc::clone(inner),
            topics,
        }
    }
}

impl Drop for SubscriberGuard {
    fn drop(&mut self) {
        self.inner.subscribers.fetch_sub(1, Ordering::Relaxed);
        for topic in self.topics.topics() {
            self.inner.topic_subscribers[topic as usize].fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Per-subscriber state of the stream.
struct Subscriber {
    rx: broadcast::Receiver<Msg>,
    first: Option<Bytes>,
    topics: TopicSet,
    principal: Principal,
    hub: EventHub,
    /// After a lag reset: frames at or below this revision are stale.
    skip_upto: Option<Revision>,
    done: bool,
    _guard: SubscriberGuard,
}

impl Subscriber {
    /// The bytes of `frame` this subscriber may see: the frame as it is, the frame re-encoded
    /// with the references the filter keeps, or nothing.
    fn render(&self, frame: &Frame) -> Option<Bytes> {
        let fresh = self.topics.contains(frame.topic)
            && self
                .skip_upto
                .is_none_or(|skip| frame.revision.is_none_or(|revision| revision > skip));
        if !fresh {
            return None;
        }
        let filter = self.hub.inner.filter.load();
        match filter.select(&self.principal, frame.topic, &frame.objects) {
            Admission::All => Some(frame.bytes.clone()),
            Admission::None => None,
            Admission::Only(kept) => {
                let mut data = frame.data.clone();
                data.objects.retain(|object| kept.contains(object));
                data.deleted.retain(|object| kept.contains(object));
                (!data.objects.is_empty() || !data.deleted.is_empty())
                    .then(|| encode(frame.revision, &data).bytes)
            }
        }
    }

    async fn next_chunk(&mut self) -> Option<Bytes> {
        if let Some(first) = self.first.take() {
            return Some(first);
        }
        if self.done {
            return None;
        }
        loop {
            match self.rx.recv().await {
                Ok(Msg::Frame(frame)) => {
                    if let Some(bytes) = self.render(&frame) {
                        return Some(bytes);
                    }
                }
                Ok(Msg::Batch(frames)) => {
                    let mut chunk = BytesMut::new();
                    for bytes in frames.iter().filter_map(|frame| self.render(frame)) {
                        chunk.extend_from_slice(&bytes);
                    }
                    if !chunk.is_empty() {
                        return Some(chunk.freeze());
                    }
                }
                Ok(Msg::KeepAlive) => return Some(KEEPALIVE_FRAME),
                Ok(Msg::Reset(frame)) => {
                    self.skip_upto = None;
                    return Some(frame);
                }
                Ok(Msg::Shutdown) => {
                    self.done = true;
                    return Some(SHUTDOWN_FRAME);
                }
                Err(RecvError::Lagged(_)) => {
                    let newest = self.hub.newest();
                    self.skip_upto = Some(newest);
                    return Some(reset_frame(ResetReason::Lagged, newest));
                }
                Err(RecvError::Closed) => return None,
            }
        }
    }
}

/// Builds the byte stream of one subscriber: the hello and replay chunk, then live frames.
///
/// `last` is the position the client resumes after (`Last-Event-ID` or `from`).
pub(crate) async fn event_stream(
    hub: &EventHub,
    store: &dyn Store,
    last: Option<Revision>,
    topics: TopicSet,
    principal: Principal,
) -> impl Stream<Item = Result<Bytes, Infallible>> + Send + use<> {
    let mut topics = topics;
    // The metrics snapshots go only to principals that read the metrics; a stream that may
    // not does not count as a listener, so it does not start the publisher either.
    if topics.contains(Topic::Metrics)
        && hub
            .inner
            .filter
            .load()
            .select(&principal, Topic::Metrics, &[])
            != Admission::All
    {
        topics.remove(Topic::Metrics);
    }
    let guard = SubscriberGuard::new(&hub.inner, topics);
    let (rx, replay) = hub.subscribe(last);
    let retry = hub.inner.config.retry.as_millis();
    let mut first = BytesMut::from(format!("retry: {retry}\n: connected\n\n").as_bytes());
    let mut subscriber = Subscriber {
        rx,
        first: None,
        topics,
        principal,
        hub: hub.clone(),
        skip_upto: None,
        done: false,
        _guard: guard,
    };
    let frames = match replay {
        Replay::Nothing => Vec::new(),
        Replay::Frames(frames) => frames,
        Replay::Journal { after, upto } => {
            if let Some(frames) = hub.journal_frames(store, after, upto).await {
                frames
            } else {
                first.extend_from_slice(&reset_frame(ResetReason::Gap, upto));
                Vec::new()
            }
        }
        Replay::Reset(revision) => {
            first.extend_from_slice(&reset_frame(ResetReason::Gap, revision));
            Vec::new()
        }
    };
    for bytes in frames.iter().filter_map(|frame| subscriber.render(frame)) {
        first.extend_from_slice(&bytes);
    }
    subscriber.first = Some(first.freeze());
    stream::unfold(subscriber, |mut subscriber| async move {
        subscriber
            .next_chunk()
            .await
            .map(|chunk| (Ok(chunk), subscriber))
    })
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tenko_core::{ObjectKind, SystemComponent, TableName, Timestamp, codec::encode_key};
    use tenko_store::Change;

    use super::*;

    const PREFIXES: TableName = TableName::from_static("ipam.prefixes");

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(0x0190_d1c2_0000_7000_8000_0000_0000_0000 + n)
    }

    fn change_set(revision: u64, changes: Vec<Change>) -> ChangeSet {
        ChangeSet {
            revision: Revision(revision),
            principal: Principal::system(SystemComponent::Ipam),
            at: Timestamp::UNIX_EPOCH,
            changes,
        }
    }

    fn change(table: TableName, key: Bytes, deleted: bool) -> Change {
        Change {
            table,
            key,
            deleted,
        }
    }

    fn prefix_change(revision: u64, n: u128) -> ChangeSet {
        change_set(revision, vec![change(PREFIXES, encode_key(&id(n)), false)])
    }

    fn hub(config: SseConfig) -> EventHub {
        EventHub::new(config, EventRoutes::default(), Revision(10))
    }

    fn text(frame: &Frame) -> String {
        String::from_utf8(frame.bytes.to_vec()).expect("utf-8")
    }

    fn revisions(replay: &Replay) -> Vec<u64> {
        match replay {
            Replay::Frames(frames) => frames
                .iter()
                .filter_map(|frame| frame.revision.map(Revision::get))
                .collect(),
            other => panic!("expected frames, got {other:?}"),
        }
    }

    #[test]
    fn change_sets_become_one_event_per_topic() {
        let hub = hub(SseConfig::default());
        let changes = change_set(
            11,
            vec![
                change(PREFIXES, encode_key(&id(1)), false),
                change(PREFIXES, encode_key(&id(1)), false),
                change(
                    TableName::from_static("ipam.addresses"),
                    encode_key(&id(2)),
                    true,
                ),
                change(
                    TableName::from_static("ipam.prefix_cidrs"),
                    Bytes::from_static(b"x"),
                    false,
                ),
                change(
                    tables::AUDIT.name().clone(),
                    tables::AUDIT.key(&tenko_core::AuditSeq(5)),
                    false,
                ),
                change(
                    TableName::from_static("auth.sessions"),
                    Bytes::from_static(b"s"),
                    false,
                ),
            ],
        );
        let frames = hub.frames_for(&changes);
        let topics: Vec<Topic> = frames.iter().map(|frame| frame.topic).collect();
        assert_eq!(topics, vec![Topic::Ipam, Topic::Audit, Topic::Admin]);
        let ipam = text(&frames[0]);
        assert!(ipam.starts_with("id: 11\nevent: ipam\ndata: {"), "{ipam}");
        assert!(ipam.ends_with("}\n\n"), "{ipam}");
        let data: EventData = serde_json::from_str(
            ipam.lines()
                .nth(2)
                .expect("data")
                .trim_start_matches("data: "),
        )
        .expect("json");
        assert_eq!(
            data.objects,
            vec![ObjectRef::new(ObjectKind::Prefix, id(1))]
        );
        assert_eq!(
            data.deleted,
            vec![ObjectRef::new(ObjectKind::Address, id(2))]
        );
        assert_eq!(frames[0].objects.len(), 2);
        assert!(text(&frames[1]).contains("\"audit\":[5]"));
        assert!(text(&frames[2]).contains("\"tables\":[\"auth.sessions\"]"));
    }

    #[test]
    fn large_changes_are_truncated() {
        let hub = hub(SseConfig {
            max_objects_per_event: 2,
            ..SseConfig::default()
        });
        let changes = change_set(
            11,
            (0..3)
                .map(|n| change(PREFIXES, encode_key(&id(n)), false))
                .collect(),
        );
        let frames = hub.frames_for(&changes);
        assert!(text(&frames[0]).contains("\"kind\":\"truncated\""));
        assert_eq!(frames[0].objects.len(), 0);
    }

    #[test]
    fn replay_window_and_fallbacks() {
        let hub = hub(SseConfig {
            ring_capacity: 3,
            ..SseConfig::default()
        });
        for revision in 11..=15 {
            hub.publish_change_set(&prefix_change(revision, u128::from(revision)));
        }
        // An unrouted change set still advances the position.
        hub.publish_change_set(&change_set(16, vec![]));
        assert_eq!(hub.newest(), Revision(16));

        assert!(matches!(hub.subscribe(None).1, Replay::Nothing));
        assert!(matches!(
            hub.subscribe(Some(Revision(16))).1,
            Replay::Nothing
        ));
        assert_eq!(
            revisions(&hub.subscribe(Some(Revision(13))).1),
            vec![14, 15]
        );
        assert_eq!(
            revisions(&hub.subscribe(Some(Revision(12))).1),
            vec![13, 14, 15]
        );
        assert!(matches!(
            hub.subscribe(Some(Revision(11))).1,
            Replay::Journal {
                after: Revision(11),
                upto: Revision(16)
            }
        ));
        assert!(matches!(
            hub.subscribe(Some(Revision(99))).1,
            Replay::Reset(Revision(16))
        ));
        // Replays of already published change sets are ignored.
        hub.publish_change_set(&prefix_change(15, 15));
        assert_eq!(revisions(&hub.subscribe(Some(Revision(14))).1), vec![15]);
    }

    #[tokio::test]
    async fn coalescing_sends_one_batch_per_window() {
        let hub = hub(SseConfig {
            coalesce: Some(Duration::from_millis(50)),
            ..SseConfig::default()
        });
        let (mut rx, _) = hub.subscribe(None);
        hub.publish_change_set(&prefix_change(11, 1));
        hub.publish_change_set(&prefix_change(12, 2));
        assert!(rx.try_recv().is_err(), "nothing before the flush");
        assert_eq!(hub.newest(), Revision(10));
        assert!(
            matches!(hub.subscribe(Some(Revision(11))).1, Replay::Reset(_)),
            "an unsent id is from the future"
        );
        hub.flush();
        let Ok(Msg::Batch(frames)) = rx.try_recv() else {
            panic!("expected a batch")
        };
        assert_eq!(frames.len(), 2);
        assert_eq!(hub.newest(), Revision(12));
        hub.flush();
        assert!(rx.try_recv().is_err(), "an empty flush sends nothing");
    }

    #[tokio::test]
    async fn streams_filter_topics_and_end_on_shutdown() {
        let hub = hub(SseConfig::default());
        let store = tenko_store::MemStore::default();
        let principal = Principal::system(SystemComponent::Api);
        let jobs_only = TopicSet::parse("jobs").expect("topics");
        let mut stream =
            Box::pin(event_stream(&hub, &store, None, jobs_only, principal.clone()).await);
        let hello = stream.next().await.expect("hello").expect("ok");
        assert!(hello.starts_with(b"retry: 3000\n"));
        assert_eq!(hub.subscribers(), 1);

        hub.publish_change_set(&prefix_change(11, 1));
        hub.publish_change_set(&change_set(
            12,
            vec![change(
                TableName::from_static("jobs.jobs"),
                encode_key(&id(3)),
                false,
            )],
        ));
        let chunk = stream.next().await.expect("event").expect("ok");
        assert!(
            chunk.starts_with(b"id: 12\nevent: jobs\n"),
            "ipam is filtered out"
        );
        hub.keepalive();
        assert_eq!(
            stream.next().await.expect("ka").expect("ok"),
            KEEPALIVE_FRAME
        );
        hub.reset_all(Revision(40), ResetReason::Journal);
        let reset = stream.next().await.expect("reset").expect("ok");
        assert!(reset.starts_with(b"id: 40\nevent: reset\n"));
        hub.shutdown();
        assert_eq!(
            stream.next().await.expect("shutdown").expect("ok"),
            SHUTDOWN_FRAME
        );
        assert!(stream.next().await.is_none());
        drop(stream);
        assert_eq!(hub.subscribers(), 0);
        assert!(hub.is_shutting_down());
    }

    /// A filter that keeps only the first reference of an `ipam` event, and only when it is
    /// object 1.
    struct FirstOnly;

    impl EventFilter for FirstOnly {
        fn admit(&self, _: &Principal, _: Topic, _: &[ObjectRef]) -> bool {
            true
        }

        fn select(&self, _: &Principal, topic: Topic, objects: &[ObjectRef]) -> Admission {
            match (topic, objects.first()) {
                (Topic::Ipam, Some(first)) if first.id == id(1) => Admission::Only(vec![*first]),
                (Topic::Ipam, _) => Admission::None,
                _ => Admission::All,
            }
        }
    }

    #[tokio::test]
    async fn a_narrowing_filter_re_encodes_the_event_for_the_subscriber() {
        let hub = hub(SseConfig::default());
        hub.set_filter(Box::new(FirstOnly));
        let store = tenko_store::MemStore::default();
        let principal = Principal::system(SystemComponent::Api);
        let ipam = TopicSet::parse("ipam").expect("topics");
        let mut stream = Box::pin(event_stream(&hub, &store, None, ipam, principal).await);
        stream.next().await.expect("hello").expect("ok");

        hub.publish_change_set(&change_set(
            21,
            vec![
                change(PREFIXES, encode_key(&id(1)), false),
                change(PREFIXES, encode_key(&id(2)), true),
            ],
        ));
        let chunk = stream.next().await.expect("event").expect("ok");
        let text = String::from_utf8(chunk.to_vec()).expect("utf-8");
        assert!(
            text.starts_with(
                "id: 21
event: ipam
"
            ),
            "{text}"
        );
        assert!(text.contains(&id(1).to_string()), "{text}");
        assert!(
            !text.contains(&id(2).to_string()),
            "the reference outside the admission is dropped: {text}"
        );

        hub.publish_change_set(&prefix_change(22, 2));
        hub.keepalive();
        assert_eq!(
            stream.next().await.expect("ka").expect("ok"),
            KEEPALIVE_FRAME,
            "an event with no reference left is not sent"
        );
    }

    #[tokio::test]
    async fn lagging_subscribers_get_a_reset() {
        let hub = hub(SseConfig {
            channel_capacity: 2,
            ..SseConfig::default()
        });
        let store = tenko_store::MemStore::default();
        let mut stream = Box::pin(
            event_stream(
                &hub,
                &store,
                None,
                TopicSet::ALL,
                Principal::system(SystemComponent::Api),
            )
            .await,
        );
        let _hello = stream.next().await;
        for revision in 11..=20 {
            hub.publish_change_set(&prefix_change(revision, u128::from(revision)));
        }
        let reset = stream.next().await.expect("reset").expect("ok");
        let text = String::from_utf8(reset.to_vec()).expect("utf-8");
        assert!(text.starts_with("id: 20\nevent: reset\n"), "{text}");
        assert!(text.contains("\"reason\":\"lagged\""), "{text}");
        hub.publish_change_set(&prefix_change(21, 21));
        let next = stream.next().await.expect("next").expect("ok");
        assert!(next.starts_with(b"id: 21\n"), "stale frames are skipped");
    }

    /// Admits everything except the `metrics` topic.
    struct NoMetrics;

    impl EventFilter for NoMetrics {
        fn admit(&self, _: &Principal, topic: Topic, _: &[ObjectRef]) -> bool {
            topic != Topic::Metrics
        }
    }

    #[tokio::test]
    async fn streams_are_counted_per_topic_and_the_first_listener_wakes_a_waiter() {
        let hub = hub(SseConfig::default());
        let store = tenko_store::MemStore::default();
        let principal = Principal::system(SystemComponent::Api);
        let waiter = {
            let hub = hub.clone();
            tokio::spawn(async move { hub.listened(Topic::Metrics).await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        let jobs = event_stream(
            &hub,
            &store,
            None,
            TopicSet::parse("jobs").expect("topics"),
            principal.clone(),
        )
        .await;
        assert_eq!(hub.subscribers_of(Topic::Jobs), 1);
        assert_eq!(hub.subscribers_of(Topic::Metrics), 0);
        let metrics = event_stream(
            &hub,
            &store,
            None,
            TopicSet::parse("metrics,jobs").expect("topics"),
            principal.clone(),
        )
        .await;
        assert_eq!(hub.subscribers_of(Topic::Metrics), 1);
        assert_eq!(hub.subscribers_of(Topic::Jobs), 2);
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("woken")
            .expect("no panic");
        // Listened already: returns at once.
        tokio::time::timeout(Duration::from_secs(5), hub.listened(Topic::Metrics))
            .await
            .expect("at once");
        drop(metrics);
        assert_eq!(hub.subscribers_of(Topic::Metrics), 0);
        assert_eq!(hub.subscribers_of(Topic::Jobs), 1);
        drop(jobs);
        assert_eq!(hub.subscribers_of(Topic::Jobs), 0);
        assert_eq!(hub.subscribers(), 0);

        // A principal that may not read the metrics does not count as their listener.
        hub.set_filter(Box::new(NoMetrics));
        let refused = event_stream(
            &hub,
            &store,
            None,
            TopicSet::parse("metrics").expect("topics"),
            principal,
        )
        .await;
        assert_eq!(hub.subscribers(), 1);
        assert_eq!(hub.subscribers_of(Topic::Metrics), 0);
        drop(refused);
    }

    #[test]
    fn system_events_have_no_id() {
        let hub = hub(SseConfig::default());
        let (mut rx, _) = hub.subscribe(None);
        let mut data = EventData::new(Topic::System, None);
        data.kind = Some("auth.break_glass_used".to_owned());
        hub.publish_system(&data);
        let Ok(Msg::Frame(frame)) = rx.try_recv() else {
            panic!("expected a frame")
        };
        assert!(text(&frame).starts_with("event: system\ndata: {"));
        assert_eq!(hub.newest(), Revision(10), "not a revision");
    }
}
