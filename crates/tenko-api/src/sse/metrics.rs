//! The `metrics` topic of the event stream (OPS-20, plan section 2.7): one metrics
//! snapshot per second, per controller and cluster-wide, while at least one subscriber
//! asked for the topic, and the history of the dashboard's tiles. The snapshots come from the
//! metrics registry, not from the store journal, so they have no revision and are never
//! replayed; a reconnecting client simply receives a fresh history and the next snapshot.
//!
//! - **The sample.** [`Sampler::take`] brings the gauges a sample reads up to date
//!   ([`SampleSources::refresh`]: cheap status reads only), takes one snapshot of the
//!   registry, turns it, against the snapshot before it, into this controller's
//!   [`MetricsSample`] ([`SampleBuilder`]) and folds that into this controller's [`History`].
//!   The publisher takes one sample a second whether anyone listens or not, so the history has
//!   no hole while nobody watches; that part runs off the query, DORA and renew paths and
//!   allocates as the sample always did (OPS-21). The newest sample, its CBOR encoding and the
//!   history's closed buckets stay in a `watch` channel, for the peers.
//! - **The publisher.** While an open stream receives the topic
//!   ([`EventHub::subscribers_of`]), each tick also asks every other controller for its newest
//!   sample through `Metrics.Snapshot` (500 ms per peer; a peer that does not answer keeps its
//!   last good sample marked `stale`, one of an older build is marked `unsupported`), sums
//!   them ([`cluster_sum`]) and publishes one system event of kind [`SNAPSHOT_KIND`] whose
//!   `metrics` field carries them and the cluster's buckets that closed. One aggregation per
//!   second, whatever the number of subscribers: the frame is encoded once and shared.
//! - **The cluster's history.** Each answer of a peer carries the buckets of its history that
//!   closed in its last two ticks; its whole history is fetched through `Metrics.History` when
//!   it first answers, when it answers again after a missed call or a hole, and when it
//!   restarted, never per subscription. A peer without the history is combined as a missing
//!   controller. While nobody listens, the peers' tiers are dropped and fetched again with the
//!   next listener.
//! - **The history frame.** Every new stream of the topic first receives one `metrics.history`
//!   ([`METRICS_HISTORY_KIND`]): the cluster's history, built at most once per tick however
//!   many streams open, and shared ([`EventHub::set_first_frame`]). When a peer's history was
//!   fetched again, the new frame also goes to the open streams.
//! - **The peers' read.** The sampler is the [`MetricsSource`] of the node registry:
//!   `Metrics.Snapshot` answers the last tick's sample and closed buckets, never a sample taken
//!   on demand (that would reset the baseline of the local rates), and `Metrics.History` this
//!   controller's whole history. [`PeerLayer`] asks the other controllers through the peer
//!   transport.

mod history;
mod sample;

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::future::{BoxFuture, join_all};
use tenko_cluster::{
    metrics::{EncodedHistory, EncodedSample, HistoryReply, MetricsSource, PeerReply},
    peers::Peers,
};
use tenko_core::{
    NodeId, Timestamp,
    codec::{from_cbor, to_cbor},
};
use tokio::{sync::watch, task::JoinHandle};

pub use self::history::{History, RING_BYTES};
use self::history::{Peer, Rings};
pub use sample::{SampleBuilder, cluster_sum};

use super::{EventHub, FirstFrame, SystemFrame};
use crate::{
    dto::events::{
        CONTROLLER_TIERS_ENCODING, ControllerTiers, EventData, METRICS_HISTORY_KIND, MetricsClosed,
        MetricsSample, MetricsSnapshot, Topic,
    },
    state::AppState,
};

/// The `kind` of the per-second events of the `metrics` topic.
pub const SNAPSHOT_KIND: &str = crate::dto::events::METRICS_SNAPSHOT_KIND;
/// The tick of the sampler and the publisher.
pub const TICK: Duration = Duration::from_secs(1);
/// How long the publisher waits for a peer's sample.
pub const PEER_DEADLINE: Duration = Duration::from_millis(500);
/// How long the publisher waits for a peer's whole history (about 230 KB).
pub const HISTORY_DEADLINE: Duration = Duration::from_secs(2);
/// After a failed fetch of a peer's history, the publisher asks again no sooner than this.
pub const HISTORY_RETRY: Duration = Duration::from_secs(30);
/// The encoding of a sample for a peer.
pub const SAMPLE_ENCODING: &str = tenko_cluster::metrics::SAMPLE_ENCODING;

/// What a sample reads besides the metrics registry; the server binary implements it over
/// its status interfaces.
pub trait SampleSources: Send + Sync + 'static {
    /// Brings the gauges the sample reads up to date (the store, Raft, the jobs, the event
    /// hub and the connected nodes); called once before each snapshot.
    fn refresh(&self) -> BoxFuture<'_, ()>;

    /// The batches each connected node dropped, as the node registry reports them.
    fn node_drops(&self) -> BTreeMap<NodeId, u64>;
}

/// No sources: the gauges are as their timer left them and no node reports drops.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSources;

impl SampleSources for NoSources {
    fn refresh(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    fn node_drops(&self) -> BTreeMap<NodeId, u64> {
        BTreeMap::new()
    }
}

/// This controller's sample as it was taken.
#[derive(Debug, Clone)]
pub struct LocalSample {
    /// The sample.
    pub sample: MetricsSample,
    /// When it was taken.
    pub taken: Instant,
    /// The sample in [`SAMPLE_ENCODING`], for the peers.
    pub encoded: Bytes,
    /// The buckets of the history that closed in this tick and the tick before
    /// ([`History::closed`]) in [`CONTROLLER_TIERS_ENCODING`], for the peers; empty on a
    /// controller without a node id, which has no peers.
    pub closed: Bytes,
}

/// Takes this controller's samples, each against the snapshot before it, and keeps its
/// history. Cloning is cheap.
#[derive(Clone)]
pub struct Sampler {
    inner: Arc<SamplerInner>,
}

struct SamplerInner {
    state: AppState,
    sources: Arc<dyn SampleSources>,
    builder: tokio::sync::Mutex<SampleBuilder>,
    history: Mutex<History>,
    latest: watch::Sender<Option<Arc<LocalSample>>>,
    taken: AtomicU64,
}

impl std::fmt::Debug for Sampler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sampler")
            .field("taken", &self.taken())
            .finish_non_exhaustive()
    }
}

impl Sampler {
    /// A sampler of the registry of `state`, with `sources` for the rest. Allocates the rings
    /// of the history ([`RING_BYTES`]) and reports them in the status.
    pub fn new(state: AppState, sources: Arc<dyn SampleSources>) -> Self {
        let history = History::new(state.platform.started_at);
        let sampler = Self {
            inner: Arc::new(SamplerInner {
                state,
                sources,
                builder: tokio::sync::Mutex::new(SampleBuilder::new()),
                history: Mutex::new(history),
                latest: watch::channel(None).0,
                taken: AtomicU64::new(0),
            }),
        };
        sampler.account(0);
        sampler
    }

    /// The node id of this controller.
    pub fn node(&self) -> Option<NodeId> {
        self.inner.state.platform.node.id
    }

    /// Takes a sample now and folds it into the history.
    pub async fn take(&self) -> Arc<LocalSample> {
        let inner = &self.inner;
        let mut builder = inner.builder.lock().await;
        inner.sources.refresh().await;
        let snapshot = inner.state.metrics().snapshot();
        let drops = inner.sources.node_drops();
        let taken = Instant::now();
        let sample = builder.build(self.node(), Timestamp::now(), taken, &snapshot, &drops);
        let encoded = to_cbor(&sample).unwrap_or_default();
        let closed = {
            let mut history = self.history();
            history.fold(&sample);
            if self.node().is_some() {
                to_cbor(&history.closed()).unwrap_or_default()
            } else {
                Bytes::new()
            }
        };
        let local = Arc::new(LocalSample {
            sample,
            taken,
            encoded,
            closed,
        });
        inner.latest.send_replace(Some(Arc::clone(&local)));
        inner.taken.fetch_add(1, Ordering::SeqCst);
        local
    }

    /// This controller's history.
    pub fn history(&self) -> MutexGuard<'_, History> {
        self.inner
            .history
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The newest sample, if one was taken.
    pub fn latest(&self) -> Option<Arc<LocalSample>> {
        self.inner.latest.borrow().clone()
    }

    /// Follows the newest sample.
    pub fn subscribe(&self) -> watch::Receiver<Option<Arc<LocalSample>>> {
        self.inner.latest.subscribe()
    }

    /// Samples taken since start.
    pub fn taken(&self) -> u64 {
        self.inner.taken.load(Ordering::SeqCst)
    }

    /// Reports the bytes of the history in the status: this controller's rings and `more`
    /// (the peers' tiers and the history frame on the serving controller).
    fn account(&self, more: usize) {
        let bytes = self.history().bytes().saturating_add(more);
        self.inner
            .state
            .platform
            .history_bytes
            .store(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}

impl MetricsSource for Sampler {
    fn current(&self) -> BoxFuture<'_, Option<EncodedSample>> {
        Box::pin(async {
            let node = self.node()?;
            let local = self.latest()?;
            Some(EncodedSample {
                node,
                at: local.sample.at,
                encoding: SAMPLE_ENCODING.to_owned(),
                payload: local.encoded.to_vec(),
                closed: local.closed.to_vec(),
            })
        })
    }

    fn history(&self) -> BoxFuture<'_, Option<EncodedHistory>> {
        Box::pin(async {
            let node = self.node()?;
            let (at, tiers) = {
                let history = Sampler::history(self);
                (history.at().unwrap_or(history.started()), history.tiers())
            };
            Some(EncodedHistory {
                node,
                at,
                encoding: CONTROLLER_TIERS_ENCODING.to_owned(),
                payload: to_cbor(&tiers).ok()?.to_vec(),
            })
        })
    }
}

/// What a peer answered to `Metrics.Snapshot`.
#[derive(Debug, Clone, PartialEq)]
pub enum PeerAnswer {
    /// Its newest sample, and the buckets of its history that closed in its last two ticks
    /// (CBOR of `ControllerTiers`; empty from a build without the history).
    Sample(Box<MetricsSample>, Vec<u8>),
    /// It runs an older build without the service.
    Unsupported,
    /// No answer, or an error.
    Failed(String),
}

/// The other controllers of the cluster, for the publisher.
pub trait PeerSamples: Send + Sync + 'static {
    /// The other members, the leader first.
    fn others(&self) -> Vec<NodeId>;

    /// Asks `node` for its newest sample, within `deadline`.
    fn fetch(&self, node: NodeId, deadline: Duration) -> BoxFuture<'_, PeerAnswer>;

    /// Asks `node` for its whole history, within `deadline`.
    fn history(&self, node: NodeId, deadline: Duration) -> BoxFuture<'_, HistoryReply>;
}

/// The other controllers of the cluster through the peer layer.
#[derive(Debug, Clone)]
pub struct PeerLayer(pub Peers);

impl PeerSamples for PeerLayer {
    fn others(&self) -> Vec<NodeId> {
        self.0.others_leader_first()
    }

    fn fetch(&self, node: NodeId, deadline: Duration) -> BoxFuture<'_, PeerAnswer> {
        Box::pin(async move {
            answer_of(tenko_cluster::metrics::fetch(self.0.network(), node, deadline).await)
        })
    }

    fn history(&self, node: NodeId, deadline: Duration) -> BoxFuture<'_, HistoryReply> {
        Box::pin(tenko_cluster::metrics::fetch_history(
            self.0.network(),
            node,
            deadline,
        ))
    }
}

/// A peer's reply as a sample: decoded when it is in [`SAMPLE_ENCODING`]. Its closed buckets
/// stay encoded: the publisher decodes them only while it combines the peers' histories.
pub fn answer_of(reply: PeerReply) -> PeerAnswer {
    match reply {
        PeerReply::Sample(sample) if sample.encoding == SAMPLE_ENCODING => {
            match from_cbor::<MetricsSample>(&sample.payload) {
                Ok(decoded) => PeerAnswer::Sample(Box::new(decoded), sample.closed),
                Err(error) => PeerAnswer::Failed(format!("the sample does not decode: {error}")),
            }
        }
        PeerReply::Sample(sample) => PeerAnswer::Failed(format!(
            "the sample is in an unknown encoding {}",
            sample.encoding
        )),
        PeerReply::Unsupported => PeerAnswer::Unsupported,
        PeerReply::Failed(detail) => PeerAnswer::Failed(detail),
    }
}

/// What a peer's answer to `Metrics.Snapshot` said about its history.
enum Heard {
    /// No answer.
    Nothing,
    /// An answer without the history: an older build.
    Without,
    /// Its closed buckets, encoded.
    Closed(Vec<u8>),
}

/// The cluster's history on the serving controller: the other controllers' tiers and the one
/// history frame every new stream receives.
struct Cluster {
    sampler: Sampler,
    peers: Mutex<Vec<Peer>>,
    /// Changes whenever the peers' tiers change.
    version: AtomicU64,
    /// The frame and the sample count and version it was built at.
    frame: tokio::sync::Mutex<Option<((u64, u64), SystemFrame)>>,
    frame_bytes: AtomicUsize,
    built: AtomicU64,
}

impl FirstFrame for Cluster {
    fn first(&self) -> BoxFuture<'_, Option<SystemFrame>> {
        Box::pin(async { Some(self.frame().await) })
    }
}

impl Cluster {
    fn peers(&self) -> MutexGuard<'_, Vec<Peer>> {
        self.peers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The history frame of the newest tick: built once per tick or change of the peers, then
    /// shared, however many streams ask at once.
    async fn frame(&self) -> SystemFrame {
        let mut cached = self.frame.lock().await;
        let version = (self.sampler.taken(), self.version.load(Ordering::SeqCst));
        if let Some((built, frame)) = cached.as_ref()
            && *built == version
        {
            return frame.clone();
        }
        let history = {
            let own = self.sampler.history();
            history::history(&own, self.sampler.node(), &self.peers())
        };
        let mut data = EventData::new(Topic::Metrics, None);
        data.kind = Some(METRICS_HISTORY_KIND.to_owned());
        data.history = Some(history);
        let frame = SystemFrame::of(&data);
        self.built.fetch_add(1, Ordering::Relaxed);
        self.frame_bytes
            .store(frame.bytes().len(), Ordering::Relaxed);
        *cached = Some((version, frame.clone()));
        self.account();
        frame
    }

    /// Reports the bytes of the history in the status.
    fn account(&self) {
        let peers: usize = self
            .peers()
            .iter()
            .filter_map(|peer| peer.rings.as_ref())
            .map(|rings| rings.bytes())
            .sum();
        self.sampler
            .account(peers + self.frame_bytes.load(Ordering::Relaxed));
    }

    /// The combined buckets that closed in this tick, with the peers' `delivered` ones.
    fn closed(&self, delivered: &[ControllerTiers]) -> Vec<MetricsClosed> {
        let own = self.sampler.history();
        history::closed(&own, &self.peers(), delivered)
    }

    /// Drops the peers' tiers while nobody listens.
    fn forget(&self) {
        let forgot = !std::mem::take(&mut *self.peers()).is_empty();
        if forgot {
            self.version.fetch_add(1, Ordering::SeqCst);
            self.account();
        }
    }

    /// Takes in what the peers `others` said about their histories (`heard`, in the same
    /// order): merges their closed buckets, fetches the whole history of a peer that is new,
    /// missed a call, left a hole or restarted, and marks one without the history. Returns the
    /// closed buckets merged, and whether the past changed (the open streams then need a new
    /// history).
    async fn heard(
        &self,
        source: &dyn PeerSamples,
        others: &[NodeId],
        heard: Vec<Heard>,
    ) -> (Vec<ControllerTiers>, bool) {
        let now = Instant::now();
        let mut delivered = Vec::new();
        let mut fetch = Vec::new();
        let mut changed = false;
        {
            let mut peers = self.peers();
            let mut before = std::mem::take(&mut *peers);
            changed |= before.len() != others.len()
                || before
                    .iter()
                    .zip(others)
                    .any(|(peer, node)| peer.node != *node);
            *peers = others
                .iter()
                .map(
                    |node| match before.iter().position(|peer| peer.node == *node) {
                        Some(at) => before.swap_remove(at),
                        None => Peer::new(*node),
                    },
                )
                .collect();
            for (peer, heard) in peers.iter_mut().zip(heard) {
                match heard {
                    Heard::Nothing => peer.stale = true,
                    Heard::Without => {
                        changed |= !peer.unsupported;
                        *peer = Peer::without_history(peer.node);
                    }
                    Heard::Closed(bytes) => {
                        match ControllerTiers::decode(CONTROLLER_TIERS_ENCODING, &bytes) {
                            Err(detail) => {
                                tracing::debug!(node = %peer.node, %detail, "a controller's closed buckets were refused");
                                peer.stale = true;
                            }
                            Ok(tiers) => {
                                changed |= std::mem::take(&mut peer.unsupported);
                                let current = !peer.stale && peer.started == Some(tiers.started);
                                match peer.rings.as_mut().filter(|_| current) {
                                    Some(rings) => {
                                        peer.stale = rings.merge(&tiers);
                                        delivered.push(tiers);
                                    }
                                    None if peer.retry.is_none_or(|at| now >= at) => {
                                        fetch.push(peer.node);
                                    }
                                    None => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        let replies = join_all(
            fetch
                .iter()
                .map(|node| source.history(*node, HISTORY_DEADLINE)),
        )
        .await;
        {
            let mut peers = self.peers();
            for (node, reply) in fetch.iter().zip(replies) {
                let Some(peer) = peers.iter_mut().find(|peer| peer.node == *node) else {
                    continue;
                };
                let tiers = match reply {
                    HistoryReply::History(history) => {
                        ControllerTiers::decode(&history.encoding, &history.payload)
                    }
                    HistoryReply::Unsupported => {
                        *peer = Peer::without_history(*node);
                        changed = true;
                        continue;
                    }
                    HistoryReply::Failed(detail) => Err(detail),
                };
                match tiers {
                    Ok(tiers) => {
                        peer.rings = Some(Box::new(Rings::of(&tiers)));
                        peer.started = Some(tiers.started);
                        peer.stale = false;
                        peer.retry = None;
                        changed = true;
                    }
                    Err(detail) => {
                        tracing::debug!(node = %node, %detail, "a controller sent no history");
                        peer.retry = Some(now + HISTORY_RETRY);
                    }
                }
            }
        }
        if changed || !delivered.is_empty() {
            self.version.fetch_add(1, Ordering::SeqCst);
        }
        if changed {
            self.account();
        }
        (delivered, changed)
    }
}

/// Publishes one metrics snapshot per second on the `metrics` topic while it has a listener,
/// and gives every new stream of the topic the cluster's history first.
pub struct MetricsPublisher {
    hub: EventHub,
    sampler: Sampler,
    peers: Option<Arc<dyn PeerSamples>>,
    /// The last good sample of every peer.
    last: Mutex<BTreeMap<NodeId, MetricsSample>>,
    cluster: Arc<Cluster>,
    ticks: AtomicU64,
}

impl std::fmt::Debug for MetricsPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsPublisher")
            .field("ticks", &self.ticks())
            .field("peers", &self.peers.is_some())
            .finish_non_exhaustive()
    }
}

impl MetricsPublisher {
    /// A publisher on the event hub of `state`; `peers` on a controller of a cluster. It
    /// becomes the source of the first event of the `metrics` topic on a new stream.
    pub fn new(state: &AppState, sampler: Sampler, peers: Option<Arc<dyn PeerSamples>>) -> Self {
        let cluster = Arc::new(Cluster {
            sampler: sampler.clone(),
            peers: Mutex::new(Vec::new()),
            version: AtomicU64::new(0),
            frame: tokio::sync::Mutex::new(None),
            frame_bytes: AtomicUsize::new(0),
            built: AtomicU64::new(0),
        });
        let first: Arc<dyn FirstFrame> = cluster.clone();
        state
            .events()
            .set_first_frame(Topic::Metrics, Arc::downgrade(&first));
        Self {
            hub: state.events().clone(),
            sampler,
            peers,
            last: Mutex::new(BTreeMap::new()),
            cluster,
            ticks: AtomicU64::new(0),
        }
    }

    /// The sampler.
    pub fn sampler(&self) -> &Sampler {
        &self.sampler
    }

    /// Snapshots published since start.
    pub fn ticks(&self) -> u64 {
        self.ticks.load(Ordering::Relaxed)
    }

    /// History frames built since start.
    pub fn histories_built(&self) -> u64 {
        self.cluster.built.load(Ordering::Relaxed)
    }

    /// Runs the sampler and the publisher on the current runtime until `stop` turns true or
    /// the hub shuts down.
    pub fn spawn(self: Arc<Self>, stop: watch::Receiver<bool>) -> JoinHandle<()> {
        tokio::spawn(async move { self.run(stop).await })
    }

    async fn run(&self, mut stop: watch::Receiver<bool>) {
        // The baseline of the rates.
        self.sampler.take().await;
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + TICK, TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            if *stop.borrow() || self.hub.is_shutting_down() {
                return;
            }
            tokio::select! {
                _ = tick.tick() => {}
                changed = stop.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    continue;
                }
            }
            let local = self.sampler.take().await;
            if self.hub.subscribers_of(Topic::Metrics) > 0 {
                self.publish(&local).await;
            } else {
                self.cluster.forget();
            }
        }
    }

    /// One tick: this controller's sample, the peers' and their sum, published as one event.
    /// Returns what it published.
    pub async fn tick(&self) -> MetricsSnapshot {
        let local = self.sampler.take().await;
        self.publish(&local).await
    }

    async fn publish(&self, local: &LocalSample) -> MetricsSnapshot {
        let at = local.sample.at;
        let mut nodes = vec![local.sample.clone()];
        let mut delivered = Vec::new();
        if let Some(peers) = &self.peers {
            let others = peers.others();
            let answers =
                join_all(others.iter().map(|node| peers.fetch(*node, PEER_DEADLINE))).await;
            let (samples, heard) = self.merge_answers(&others, answers, at);
            nodes.extend(samples);
            let changed;
            (delivered, changed) = self.cluster.heard(peers.as_ref(), &others, heard).await;
            if changed {
                let frame = self.cluster.frame().await;
                self.hub.publish_frame(&frame);
            }
        }
        let snapshot = MetricsSnapshot {
            cluster: cluster_sum(&nodes, at),
            nodes,
            closed: self.cluster.closed(&delivered),
        };
        let mut data = EventData::new(Topic::Metrics, None);
        data.kind = Some(SNAPSHOT_KIND.to_owned());
        data.metrics = Some(snapshot.clone());
        self.hub.publish_system(&data);
        self.ticks.fetch_add(1, Ordering::Relaxed);
        snapshot
    }

    /// The samples of the peers from their answers: a fresh sample replaces the last good
    /// one, a failed answer repeats the last good one marked stale (or an empty one), an
    /// unsupported peer has an empty one so marked. Also what each answer said about the
    /// peer's history.
    fn merge_answers(
        &self,
        others: &[NodeId],
        answers: Vec<PeerAnswer>,
        at: Timestamp,
    ) -> (Vec<MetricsSample>, Vec<Heard>) {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        last.retain(|node, _| others.contains(node));
        others
            .iter()
            .zip(answers)
            .map(|(node, answer)| match answer {
                PeerAnswer::Sample(sample, closed) => {
                    let mut sample = *sample;
                    sample.node = Some(*node);
                    sample.stale = false;
                    sample.unsupported = false;
                    last.insert(*node, sample.clone());
                    let heard = if closed.is_empty() {
                        Heard::Without
                    } else {
                        Heard::Closed(closed)
                    };
                    (sample, heard)
                }
                PeerAnswer::Unsupported => {
                    last.remove(node);
                    let mut sample = MetricsSample::empty(Some(*node), at);
                    sample.unsupported = true;
                    (sample, Heard::Without)
                }
                PeerAnswer::Failed(detail) => {
                    tracing::debug!(node = %node, %detail, "a controller sent no metrics sample");
                    let mut sample = last
                        .get(node)
                        .cloned()
                        .unwrap_or_else(|| MetricsSample::empty(Some(*node), at));
                    sample.stale = true;
                    (sample, Heard::Nothing)
                }
            })
            .unzip()
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt as _;
    use tenko_core::{Principal, SystemComponent};

    use super::*;
    use crate::{
        dto::{
            events::{MetricsBucket, MetricsFigure, TopicSet},
            system::NodeStatus,
        },
        sse::event_stream,
        state::StateOptions,
    };

    /// Peers that answer from a script: node 2 with a sample, node 3 not at all, node 4 as an
    /// older build; a peer's history as set with [`Scripted::history_of`].
    struct Scripted {
        answers: Mutex<BTreeMap<NodeId, PeerAnswer>>,
        histories: Mutex<BTreeMap<NodeId, HistoryReply>>,
        fetched: AtomicU64,
    }

    impl Scripted {
        fn new() -> Self {
            let mut two = MetricsSample::empty(Some(NodeId(2)), Timestamp::now());
            two.api.requests_per_second = 5.0;
            two.raft.role = Some("follower".to_owned());
            two.raft.term = 4;
            let answers = BTreeMap::from([
                (NodeId(2), PeerAnswer::Sample(Box::new(two), Vec::new())),
                (NodeId(3), PeerAnswer::Failed("no answer".to_owned())),
                (NodeId(4), PeerAnswer::Unsupported),
            ]);
            Self {
                answers: Mutex::new(answers),
                histories: Mutex::new(BTreeMap::new()),
                fetched: AtomicU64::new(0),
            }
        }

        fn set(&self, node: u64, answer: PeerAnswer) {
            self.answers
                .lock()
                .expect("lock")
                .insert(NodeId(node), answer);
        }

        /// Node `node` answers with `history`'s closed buckets and whole history.
        fn history_of(&self, node: u64, history: &History) {
            let sample = MetricsSample::empty(Some(NodeId(node)), Timestamp::now());
            let closed = to_cbor(&history.closed()).expect("cbor").to_vec();
            self.set(node, PeerAnswer::Sample(Box::new(sample), closed));
            self.reply(node, HistoryReply::History(encoded(node, history)));
        }

        fn reply(&self, node: u64, reply: HistoryReply) {
            self.histories
                .lock()
                .expect("lock")
                .insert(NodeId(node), reply);
        }

        fn fetched(&self) -> u64 {
            self.fetched.load(Ordering::SeqCst)
        }
    }

    impl PeerSamples for Scripted {
        fn others(&self) -> Vec<NodeId> {
            self.answers.lock().expect("lock").keys().copied().collect()
        }

        fn fetch(&self, node: NodeId, _deadline: Duration) -> BoxFuture<'_, PeerAnswer> {
            let answer = self.answers.lock().expect("lock").get(&node).cloned();
            Box::pin(async move { answer.unwrap_or_else(|| PeerAnswer::Failed("unknown".into())) })
        }

        fn history(&self, node: NodeId, _deadline: Duration) -> BoxFuture<'_, HistoryReply> {
            self.fetched.fetch_add(1, Ordering::SeqCst);
            let reply = self.histories.lock().expect("lock").get(&node).cloned();
            Box::pin(async move { reply.unwrap_or(HistoryReply::Unsupported) })
        }
    }

    fn encoded(node: u64, history: &History) -> EncodedHistory {
        EncodedHistory {
            node: NodeId(node),
            at: history.at().unwrap_or(history.started()),
            encoding: CONTROLLER_TIERS_ENCODING.to_owned(),
            payload: to_cbor(&history.tiers()).expect("cbor").to_vec(),
        }
    }

    /// A peer's history of the last `seconds` seconds of the summed figure at `value`.
    #[allow(clippy::cast_precision_loss, reason = "a test series")]
    fn peer_history(seconds: u64, value: f64) -> History {
        let now = Timestamp::now();
        let start = now
            .checked_sub(Duration::from_secs(seconds + 1))
            .expect("now");
        let mut history = History::new(start);
        for second in 1..=seconds {
            let at = start
                .checked_add(Duration::from_secs(second))
                .expect("later");
            let mut sample = MetricsSample::empty(None, at);
            sample.interval_ms = 1_000;
            sample.api.requests_per_second = value;
            history.fold(&sample);
        }
        history
    }

    fn state(node: Option<u64>) -> AppState {
        AppState::with_options(
            Arc::new(tenko_store::MemStore::default()),
            StateOptions {
                node: NodeStatus {
                    id: node.map(NodeId),
                    ..NodeStatus::default()
                },
                ..StateOptions::default()
            },
        )
    }

    fn publisher(peers: Option<Arc<dyn PeerSamples>>) -> (AppState, Arc<MetricsPublisher>) {
        let state = state(peers.as_ref().map(|_| 1));
        let sampler = Sampler::new(state.clone(), Arc::new(NoSources));
        let publisher = Arc::new(MetricsPublisher::new(&state, sampler, peers));
        (state, publisher)
    }

    /// Takes samples until one is folded into the history: the first only sets the baseline
    /// of the rates, and one taken within the same millisecond has no interval.
    async fn fold_once(sampler: &Sampler) {
        sampler.take().await;
        while sampler.history().at().is_none() {
            tokio::task::yield_now().await;
            sampler.take().await;
        }
    }

    async fn open(
        state: &AppState,
    ) -> impl futures::Stream<Item = Result<Bytes, std::convert::Infallible>> + use<> {
        event_stream(
            state.events(),
            state.store.as_ref(),
            None,
            TopicSet::parse("metrics").expect("topics"),
            Principal::system(SystemComponent::Api),
        )
        .await
    }

    /// The events of a chunk of the stream.
    fn events(chunk: &[u8]) -> Vec<EventData> {
        String::from_utf8(chunk.to_vec())
            .expect("utf-8")
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .map(|data| serde_json::from_str(data).expect("an event"))
            .collect()
    }

    fn requests(history: &crate::dto::events::MetricsHistory) -> &crate::dto::events::MetricsTier {
        &history
            .figures
            .iter()
            .find(|figure| figure.figure == MetricsFigure::Requests)
            .expect("requests")
            .tiers[0]
    }

    #[tokio::test]
    async fn a_tick_merges_the_peers_and_keeps_the_last_good_sample_of_a_silent_one() {
        let peers = Arc::new(Scripted::new());
        let (_, publisher) = publisher(Some(peers.clone()));
        publisher.sampler().take().await;
        let first = publisher.tick().await;
        let nodes: Vec<_> = first.nodes.iter().map(|sample| sample.node).collect();
        assert_eq!(
            nodes,
            vec![
                Some(NodeId(1)),
                Some(NodeId(2)),
                Some(NodeId(3)),
                Some(NodeId(4))
            ]
        );
        assert!(!first.nodes[1].stale);
        assert!(first.nodes[2].stale, "no answer yet: an empty stale sample");
        assert_eq!(first.nodes[2].raft.role, None);
        assert!(first.nodes[3].unsupported);
        assert!((first.cluster.api.requests_per_second - 5.0).abs() < 1e-9);
        assert_eq!(first.cluster.raft.term, 4);
        assert_eq!(peers.fetched(), 0, "no peer has the history: none is asked");

        // Node 2 goes silent: its last good sample stays, marked stale, and leaves the sum.
        peers.set(2, PeerAnswer::Failed("deadline".to_owned()));
        let second = publisher.tick().await;
        assert!(second.nodes[1].stale);
        assert_eq!(second.nodes[1].raft.role.as_deref(), Some("follower"));
        assert!(second.cluster.api.requests_per_second.abs() < 1e-9);
        assert_eq!(publisher.ticks(), 2);
    }

    #[tokio::test]
    async fn a_single_controller_sends_its_history_first_then_its_own_sample_as_the_cluster() {
        let (state, publisher) = publisher(None);
        fold_once(publisher.sampler()).await;
        let mut stream = Box::pin(open(&state).await);
        let first = events(&stream.next().await.expect("hello").expect("ok"));
        assert_eq!(first.len(), 1, "the hello, then the history");
        assert_eq!(first[0].kind.as_deref(), Some(METRICS_HISTORY_KIND));
        let history = first[0].history.as_ref().expect("history");
        assert_eq!(history.controllers.len(), 1);
        assert!(requests(history).open);
        let sent = publisher.tick().await;
        assert_eq!(sent.nodes.len(), 1);
        let chunk = stream.next().await.expect("event").expect("ok");
        assert!(chunk.starts_with(b"event: metrics\ndata: {"));
        let data = events(&chunk).remove(0);
        assert_eq!(data.kind.as_deref(), Some(SNAPSHOT_KIND));
        assert_eq!(data.metrics, Some(sent));
    }

    /// The sampler ticks once a second whether a stream listens or not, so the history has no
    /// hole; the snapshots are published only while one listens. On a paused clock.
    #[tokio::test(start_paused = true)]
    async fn the_sampler_ticks_always_and_publishes_only_while_someone_listens() {
        let (state, publisher) = publisher(None);
        let (stop_tx, stop) = watch::channel(false);
        let task = Arc::clone(&publisher).spawn(stop);
        tokio::time::sleep(Duration::from_millis(3_500)).await;
        assert_eq!(publisher.ticks(), 0, "nobody listens");
        assert_eq!(
            publisher.sampler().taken(),
            4,
            "the baseline and three ticks"
        );

        let mut stream = Box::pin(open(&state).await);
        let first = stream.next().await.expect("hello").expect("ok");
        assert_eq!(
            events(&first)[0].kind.as_deref(),
            Some(METRICS_HISTORY_KIND)
        );
        let event = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await
            .expect("the next tick")
            .expect("event")
            .expect("ok");
        assert!(event.starts_with(b"event: metrics\n"));
        assert_eq!(publisher.ticks(), 1);
        drop(stream);
        tokio::time::sleep(Duration::from_millis(3_500)).await;
        assert_eq!(publisher.ticks(), 1, "nobody listens again");
        assert_eq!(publisher.sampler().taken(), 8, "and the sampler goes on");

        stop_tx.send(true).expect("stop");
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("stops")
            .expect("no panic");
    }

    /// A peer's read answers the last tick's sample and its closed buckets, never a sample
    /// taken on demand, so it does not reset the baseline of the rates.
    #[tokio::test]
    async fn a_peer_read_answers_the_last_tick_and_takes_no_sample() {
        let sampler = Sampler::new(state(Some(1)), Arc::new(NoSources));
        assert_eq!(MetricsSource::current(&sampler).await, None, "no tick yet");
        fold_once(&sampler).await;
        let local = sampler.latest().expect("taken");
        let taken = sampler.taken();
        let answer = MetricsSource::current(&sampler).await.expect("a sample");
        let again = MetricsSource::current(&sampler).await.expect("a sample");
        assert_eq!(sampler.taken(), taken, "the reads took nothing");
        assert_eq!(answer, again);
        assert_eq!(answer.payload, local.encoded.to_vec());
        let decoded: MetricsSample = from_cbor(&answer.payload).expect("cbor");
        assert_eq!(decoded, local.sample);
        let closed = ControllerTiers::decode(CONTROLLER_TIERS_ENCODING, &answer.closed)
            .expect("the closed buckets pass the peer's check");
        assert_eq!(closed.started, sampler.history().started());
        let history = MetricsSource::history(&sampler).await.expect("a history");
        let tiers = ControllerTiers::decode(&history.encoding, &history.payload).expect("checked");
        assert!(
            tiers
                .figures
                .iter()
                .any(|held| held.figure == MetricsFigure::Requests)
        );
        // Without a node id there are no peers to answer.
        let alone = Sampler::new(state(None), Arc::new(NoSources));
        alone.take().await;
        assert_eq!(MetricsSource::current(&alone).await, None);
        assert_eq!(MetricsSource::history(&alone).await, None);
        assert!(alone.latest().expect("taken").closed.is_empty());
    }

    #[test]
    fn a_peer_reply_decodes_in_its_encoding_only() {
        let mut sample = MetricsSample::empty(Some(NodeId(2)), Timestamp::now());
        sample.api.requests_per_second = 7.0;
        let encoded = EncodedSample {
            node: NodeId(2),
            at: sample.at,
            encoding: SAMPLE_ENCODING.to_owned(),
            payload: to_cbor(&sample).expect("cbor").to_vec(),
            closed: vec![1, 2, 3],
        };
        assert_eq!(
            answer_of(PeerReply::Sample(encoded.clone())),
            PeerAnswer::Sample(Box::new(sample), vec![1, 2, 3])
        );
        let json = EncodedSample {
            encoding: "json/1".to_owned(),
            ..encoded.clone()
        };
        assert!(matches!(
            answer_of(PeerReply::Sample(json)),
            PeerAnswer::Failed(_)
        ));
        let garbage = EncodedSample {
            payload: vec![0xff, 0x00],
            ..encoded
        };
        assert!(matches!(
            answer_of(PeerReply::Sample(garbage)),
            PeerAnswer::Failed(_)
        ));
        assert_eq!(answer_of(PeerReply::Unsupported), PeerAnswer::Unsupported);
    }

    /// E115 (R195): a thousand streams opened at once get the same history frame, built once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_thousand_streams_opened_at_once_build_the_history_once() {
        let (state, publisher) = publisher(None);
        fold_once(publisher.sampler()).await;
        let streams = join_all((0..1_000).map(|_| {
            let state = state.clone();
            tokio::spawn(async move {
                let mut stream = Box::pin(open(&state).await);
                stream.next().await.expect("hello").expect("ok")
            })
        }))
        .await;
        let firsts: Vec<Bytes> = streams
            .into_iter()
            .map(|first| first.expect("no panic"))
            .collect();
        assert_eq!(publisher.histories_built(), 1);
        assert!(firsts.iter().all(|first| first == &firsts[0]));
        assert_eq!(
            events(&firsts[0])[0].kind.as_deref(),
            Some(METRICS_HISTORY_KIND)
        );
        // The next tick's history is a new frame.
        publisher.sampler().take().await;
        let mut stream = Box::pin(open(&state).await);
        stream.next().await.expect("hello").expect("ok");
        assert_eq!(publisher.histories_built(), 2);
    }

    /// The cluster's history: a peer's whole history is fetched once when it first answers
    /// with the history, combined, and sent to the open streams; its closed buckets then come
    /// with each answer; after a restart (another start) it is fetched again; a peer of the
    /// previous release is combined as a missing controller and never asked.
    #[tokio::test]
    async fn the_peers_histories_are_fetched_once_combined_and_fetched_again_after_a_restart() {
        let peers = Arc::new(Scripted::new());
        let two = peer_history(30, 7.0);
        peers.history_of(2, &two);
        let (state, publisher) = publisher(Some(peers.clone()));
        fold_once(publisher.sampler()).await;
        let mut stream = Box::pin(open(&state).await);
        let first = events(&stream.next().await.expect("hello").expect("ok")).remove(0);
        let alone = first.history.expect("history");
        assert_eq!(alone.controllers.len(), 1, "no peer heard yet");

        publisher.tick().await;
        assert_eq!(peers.fetched(), 1);
        let chunk = stream.next().await.expect("event").expect("ok");
        let sent = events(&chunk);
        assert_eq!(
            sent[0].kind.as_deref(),
            Some(METRICS_HISTORY_KIND),
            "the new past"
        );
        let history = sent[0].history.as_ref().expect("history");
        let controllers: Vec<_> = history
            .controllers
            .iter()
            .map(|controller| {
                (
                    controller.node,
                    controller.started.is_some(),
                    controller.unsupported,
                )
            })
            .collect();
        assert_eq!(
            controllers,
            [
                (Some(NodeId(1)), true, false),
                (Some(NodeId(2)), true, false),
                (Some(NodeId(3)), false, false),
                (Some(NodeId(4)), false, true),
            ]
        );
        let seconds = requests(history);
        assert!(seconds.controllers.contains(&1), "the peer's own seconds");
        assert!(
            seconds
                .mean
                .iter()
                .flatten()
                .any(|mean| (mean - 7.0).abs() < 1e-9)
        );

        // The next answers bring closed buckets: merged, no fetch, no new history.
        publisher.tick().await;
        assert_eq!(peers.fetched(), 1);
        // A restart: another start in the closed buckets.
        let restarted = peer_history(5, 9.0);
        peers.history_of(2, &restarted);
        publisher.tick().await;
        assert_eq!(peers.fetched(), 2);
        let history = publisher.cluster.frame().await;
        let data = events(history.bytes()).remove(0);
        assert_eq!(
            data.history.expect("history").controllers[1].started,
            Some(restarted.started())
        );
        // Nobody listens: the peers' tiers are forgotten and fetched again with the next one.
        drop(stream);
        publisher.cluster.forget();
        assert!(publisher.cluster.peers().is_empty());
    }

    /// A peer's malformed or oversized answer is refused without a panic and without memory:
    /// garbage closed buckets and a history with a ring larger than the plan's leave the peer
    /// out of the combination and the status's bytes where they were; the fetch is retried only
    /// after a while.
    #[tokio::test]
    async fn a_peers_malformed_or_oversized_answer_is_refused() {
        let peers = Arc::new(Scripted::new());
        let (state, publisher) = publisher(Some(peers.clone()));
        fold_once(publisher.sampler()).await;
        let bytes = || state.platform.history_bytes.load(Ordering::Relaxed);
        let before = bytes();
        assert!(before >= u64::try_from(RING_BYTES).expect("small"));

        let sample = || Box::new(MetricsSample::empty(Some(NodeId(2)), Timestamp::now()));
        peers.set(2, PeerAnswer::Sample(sample(), vec![0xff; 64]));
        publisher.tick().await;
        assert_eq!(peers.fetched(), 0, "garbage is refused before any fetch");

        let mut oversized = peer_history(3, 1.0).tiers();
        let mut big = oversized.figures[0].tiers[0].clone();
        big.buckets = vec![MetricsBucket::EMPTY; 72];
        oversized.figures[0].tiers[0] = big;
        let started = oversized.started;
        let closed = ControllerTiers {
            started,
            figures: Vec::new(),
        };
        peers.set(
            2,
            PeerAnswer::Sample(sample(), to_cbor(&closed).expect("cbor").to_vec()),
        );
        peers.reply(
            2,
            HistoryReply::History(EncodedHistory {
                node: NodeId(2),
                at: started,
                encoding: CONTROLLER_TIERS_ENCODING.to_owned(),
                payload: to_cbor(&oversized).expect("cbor").to_vec(),
            }),
        );
        publisher.tick().await;
        assert_eq!(peers.fetched(), 1);
        publisher.tick().await;
        assert_eq!(peers.fetched(), 1, "no second fetch before the retry");
        {
            let held = publisher.cluster.peers();
            assert!(held[0].rings.is_none(), "the oversized history is refused");
            assert!(held[0].retry.is_some());
        }
        assert_eq!(
            bytes(),
            before + publisher.cluster.frame_bytes.load(Ordering::Relaxed) as u64
        );
        let frame = publisher.cluster.frame().await;
        let data = events(frame.bytes()).remove(0);
        let history = data.history.expect("history");
        assert!(
            history.controllers[1].started.is_none(),
            "missing from the combination"
        );
        assert!(requests(&history).controllers.iter().all(|n| *n <= 1));
    }

    #[tokio::test]
    async fn the_status_reports_the_bytes_of_the_history() {
        let state = AppState::default();
        assert_eq!(
            crate::routes::system::status_of(&state, Timestamp::UNIX_EPOCH).metrics,
            None,
            "no sampler"
        );
        let (state, publisher) = publisher(None);
        publisher.sampler().take().await;
        let frame = publisher.cluster.frame().await;
        let status = crate::routes::system::status_of(&state, Timestamp::UNIX_EPOCH);
        assert_eq!(
            status.metrics.expect("metrics").history_bytes,
            u64::try_from(RING_BYTES + frame.bytes().len()).expect("small")
        );
    }
}
