//! The `metrics` topic of the event stream (OPS-20, plan section 2.7): one metrics
//! snapshot per second, per controller and cluster-wide, while at least one subscriber
//! asked for the topic. The snapshots come from the metrics registry, not from the store
//! journal, so they have no revision and are never replayed; a reconnecting client simply
//! receives the next one.
//!
//! - **The sample.** [`Sampler::take`] brings the gauges a sample reads up to date
//!   ([`SampleSources::refresh`]: cheap status reads only), takes one snapshot of the
//!   registry and turns it, against the snapshot before it, into this controller's
//!   [`MetricsSample`] ([`SampleBuilder`]). The newest sample and its CBOR encoding stay in a
//!   `watch` channel, for the peers.
//! - **The publisher.** [`MetricsPublisher`] sleeps while no open stream receives the topic
//!   ([`EventHub::subscribers_of`]) and wakes with the first one ([`EventHub::listened`]).
//!   While someone listens it runs a one-second tick: one sample of this controller, on a
//!   cluster the newest sample of every other controller through `Metrics.Snapshot` (500 ms
//!   per peer; a peer that does not answer keeps its last good sample marked `stale`, one of
//!   an older build is marked `unsupported`), their sum ([`cluster_sum`]), and one system
//!   event of kind [`SNAPSHOT_KIND`] whose `metrics` field carries them. One aggregation per
//!   second, whatever the number of subscribers: the frame is encoded once and shared.
//! - **The peers' read.** [`Sampler::for_peer`] answers `Metrics.Snapshot` (the sampler is
//!   the [`MetricsSource`] of the node registry): the tick's sample while the publisher runs
//!   here, otherwise one taken on demand, at most one per 500 ms. [`PeerLayer`] asks the other
//!   controllers through the peer transport and decodes their samples.

mod sample;

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::future::{BoxFuture, join_all};
use tenko_cluster::{
    metrics::{EncodedSample, MetricsSource, PeerReply},
    peers::Peers,
};
use tenko_core::{
    NodeId, Timestamp,
    codec::{from_cbor, to_cbor},
};
use tokio::{sync::watch, task::JoinHandle};

pub use sample::{SampleBuilder, cluster_sum};

use super::EventHub;
use crate::{
    dto::events::{EventData, MetricsSample, MetricsSnapshot, Topic},
    state::AppState,
};

/// The `kind` of the events of the `metrics` topic.
pub const SNAPSHOT_KIND: &str = "metrics.snapshot";
/// The tick of the publisher.
pub const TICK: Duration = Duration::from_secs(1);
/// How long the publisher waits for a peer's sample.
pub const PEER_DEADLINE: Duration = Duration::from_millis(500);
/// The youngest sample a peer's read takes again when the publisher does not run here.
pub const ON_DEMAND_EVERY: Duration = Duration::from_millis(500);
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
}

/// Takes this controller's samples, each against the snapshot before it. Cloning is cheap.
#[derive(Clone)]
pub struct Sampler {
    inner: Arc<SamplerInner>,
}

struct SamplerInner {
    state: AppState,
    sources: Arc<dyn SampleSources>,
    builder: tokio::sync::Mutex<SampleBuilder>,
    latest: watch::Sender<Option<Arc<LocalSample>>>,
    ticking: AtomicBool,
    taken: AtomicU64,
}

impl std::fmt::Debug for Sampler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sampler")
            .field("taken", &self.taken())
            .field("ticking", &self.inner.ticking.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Sampler {
    /// A sampler of the registry of `state`, with `sources` for the rest.
    pub fn new(state: AppState, sources: Arc<dyn SampleSources>) -> Self {
        Self {
            inner: Arc::new(SamplerInner {
                state,
                sources,
                builder: tokio::sync::Mutex::new(SampleBuilder::new()),
                latest: watch::channel(None).0,
                ticking: AtomicBool::new(false),
                taken: AtomicU64::new(0),
            }),
        }
    }

    /// The node id of this controller.
    pub fn node(&self) -> Option<NodeId> {
        self.inner.state.platform.node.id
    }

    /// Takes a sample now.
    pub async fn take(&self) -> Arc<LocalSample> {
        let mut builder = self.inner.builder.lock().await;
        self.take_locked(&mut builder).await
    }

    async fn take_locked(&self, builder: &mut SampleBuilder) -> Arc<LocalSample> {
        let inner = &self.inner;
        inner.sources.refresh().await;
        let snapshot = inner.state.metrics().snapshot();
        let drops = inner.sources.node_drops();
        let taken = Instant::now();
        let sample = builder.build(self.node(), Timestamp::now(), taken, &snapshot, &drops);
        let encoded = to_cbor(&sample).unwrap_or_default();
        let local = Arc::new(LocalSample {
            sample,
            taken,
            encoded,
        });
        inner.latest.send_replace(Some(Arc::clone(&local)));
        inner.taken.fetch_add(1, Ordering::Relaxed);
        local
    }

    /// The newest sample for a peer: while the publisher ticks here, the tick's; otherwise
    /// one taken now unless the newest is younger than [`ON_DEMAND_EVERY`].
    pub async fn for_peer(&self) -> Arc<LocalSample> {
        if let Some(latest) = self.fresh() {
            return latest;
        }
        let mut builder = self.inner.builder.lock().await;
        // Another reader may have taken one while this one waited.
        if let Some(latest) = self.fresh() {
            return latest;
        }
        self.take_locked(&mut builder).await
    }

    fn fresh(&self) -> Option<Arc<LocalSample>> {
        let latest = self.latest()?;
        let age = latest.taken.elapsed();
        let ticking = self.inner.ticking.load(Ordering::Relaxed);
        (age < ON_DEMAND_EVERY || (ticking && age < 3 * TICK)).then_some(latest)
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
        self.inner.taken.load(Ordering::Relaxed)
    }

    fn set_ticking(&self, ticking: bool) {
        self.inner.ticking.store(ticking, Ordering::Relaxed);
    }
}

impl MetricsSource for Sampler {
    fn current(&self) -> BoxFuture<'_, Option<EncodedSample>> {
        Box::pin(async {
            let node = self.node()?;
            let local = self.for_peer().await;
            Some(EncodedSample {
                node,
                at: local.sample.at,
                encoding: SAMPLE_ENCODING.to_owned(),
                payload: local.encoded.to_vec(),
            })
        })
    }
}

/// What a peer answered to `Metrics.Snapshot`.
#[derive(Debug, Clone, PartialEq)]
pub enum PeerAnswer {
    /// Its newest sample.
    Sample(Box<MetricsSample>),
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
}

/// A peer's reply as a sample: decoded when it is in [`SAMPLE_ENCODING`].
pub fn answer_of(reply: PeerReply) -> PeerAnswer {
    match reply {
        PeerReply::Sample(sample) if sample.encoding == SAMPLE_ENCODING => {
            match from_cbor::<MetricsSample>(&sample.payload) {
                Ok(decoded) => PeerAnswer::Sample(Box::new(decoded)),
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

/// Publishes one metrics snapshot per second on the `metrics` topic while it has a listener.
pub struct MetricsPublisher {
    hub: EventHub,
    sampler: Sampler,
    peers: Option<Arc<dyn PeerSamples>>,
    /// The last good sample of every peer.
    last: Mutex<BTreeMap<NodeId, MetricsSample>>,
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
    /// A publisher on the event hub of `state`; `peers` on a controller of a cluster.
    pub fn new(state: &AppState, sampler: Sampler, peers: Option<Arc<dyn PeerSamples>>) -> Self {
        Self {
            hub: state.events().clone(),
            sampler,
            peers,
            last: Mutex::new(BTreeMap::new()),
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

    /// Runs the publisher on the current runtime until `stop` turns true or the hub shuts
    /// down.
    pub fn spawn(self: Arc<Self>, stop: watch::Receiver<bool>) -> JoinHandle<()> {
        tokio::spawn(async move { self.run(stop).await })
    }

    async fn run(&self, mut stop: watch::Receiver<bool>) {
        loop {
            if *stop.borrow() || self.hub.is_shutting_down() {
                return;
            }
            if self.hub.subscribers_of(Topic::Metrics) == 0 {
                self.sampler.set_ticking(false);
                tokio::select! {
                    () = self.hub.listened(Topic::Metrics) => {}
                    changed = stop.changed() => if changed.is_err() { return },
                }
                continue;
            }
            self.sampler.set_ticking(true);
            // The baseline, so that the first event has rates.
            self.sampler.take().await;
            let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + TICK, TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    changed = stop.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        break;
                    }
                }
                if self.hub.subscribers_of(Topic::Metrics) == 0 || self.hub.is_shutting_down() {
                    break;
                }
                self.tick().await;
            }
        }
    }

    /// One aggregation: this controller's sample, the peers' and their sum, published as
    /// one event. Returns what it published.
    pub async fn tick(&self) -> MetricsSnapshot {
        let local = self.sampler.take().await;
        let at = local.sample.at;
        let mut nodes = vec![local.sample.clone()];
        if let Some(peers) = &self.peers {
            let others = peers.others();
            let answers =
                join_all(others.iter().map(|node| peers.fetch(*node, PEER_DEADLINE))).await;
            nodes.extend(self.merge_answers(&others, answers, at));
        }
        let snapshot = MetricsSnapshot {
            cluster: cluster_sum(&nodes, at),
            nodes,
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
    /// unsupported peer has an empty one so marked.
    fn merge_answers(
        &self,
        others: &[NodeId],
        answers: Vec<PeerAnswer>,
        at: Timestamp,
    ) -> Vec<MetricsSample> {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        last.retain(|node, _| others.contains(node));
        others
            .iter()
            .zip(answers)
            .map(|(node, answer)| match answer {
                PeerAnswer::Sample(sample) => {
                    let mut sample = *sample;
                    sample.node = Some(*node);
                    sample.stale = false;
                    sample.unsupported = false;
                    last.insert(*node, sample.clone());
                    sample
                }
                PeerAnswer::Unsupported => {
                    last.remove(node);
                    let mut sample = MetricsSample::empty(Some(*node), at);
                    sample.unsupported = true;
                    sample
                }
                PeerAnswer::Failed(detail) => {
                    tracing::debug!(node = %node, %detail, "a controller sent no metrics sample");
                    let mut sample = last
                        .get(node)
                        .cloned()
                        .unwrap_or_else(|| MetricsSample::empty(Some(*node), at));
                    sample.stale = true;
                    sample
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt as _;
    use tenko_core::{Principal, SystemComponent};

    use super::*;
    use crate::{dto::events::TopicSet, sse::event_stream};

    /// Peers that answer from a script: node 2 with a sample, node 3 not at all, node 4 as an
    /// older build.
    struct Scripted {
        answers: Mutex<BTreeMap<NodeId, PeerAnswer>>,
    }

    impl Scripted {
        fn new() -> Self {
            let mut two = MetricsSample::empty(Some(NodeId(2)), Timestamp::now());
            two.api.requests_per_second = 5.0;
            two.raft.role = Some("follower".to_owned());
            two.raft.term = 4;
            let answers = BTreeMap::from([
                (NodeId(2), PeerAnswer::Sample(Box::new(two))),
                (NodeId(3), PeerAnswer::Failed("no answer".to_owned())),
                (NodeId(4), PeerAnswer::Unsupported),
            ]);
            Self {
                answers: Mutex::new(answers),
            }
        }

        fn set(&self, node: u64, answer: PeerAnswer) {
            self.answers
                .lock()
                .expect("lock")
                .insert(NodeId(node), answer);
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
    }

    fn publisher(peers: Option<Arc<dyn PeerSamples>>) -> (AppState, Arc<MetricsPublisher>) {
        let state = AppState::default();
        let sampler = Sampler::new(state.clone(), Arc::new(NoSources));
        let publisher = Arc::new(MetricsPublisher::new(&state, sampler, peers));
        (state, publisher)
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
            vec![None, Some(NodeId(2)), Some(NodeId(3)), Some(NodeId(4))]
        );
        assert!(!first.nodes[1].stale);
        assert!(first.nodes[2].stale, "no answer yet: an empty stale sample");
        assert_eq!(first.nodes[2].raft.role, None);
        assert!(first.nodes[3].unsupported);
        assert!((first.cluster.api.requests_per_second - 5.0).abs() < 1e-9);
        assert_eq!(first.cluster.raft.term, 4);

        // Node 2 goes silent: its last good sample stays, marked stale, and leaves the sum.
        peers.set(2, PeerAnswer::Failed("deadline".to_owned()));
        let second = publisher.tick().await;
        assert!(second.nodes[1].stale);
        assert_eq!(second.nodes[1].raft.role.as_deref(), Some("follower"));
        assert!(second.cluster.api.requests_per_second.abs() < 1e-9);
        assert_eq!(publisher.ticks(), 2);
    }

    #[tokio::test]
    async fn a_single_controller_publishes_its_own_sample_as_the_cluster() {
        let (state, publisher) = publisher(None);
        let mut stream = Box::pin(
            event_stream(
                state.events(),
                state.store.as_ref(),
                None,
                TopicSet::parse("metrics").expect("topics"),
                Principal::system(SystemComponent::Api),
            )
            .await,
        );
        stream.next().await.expect("hello").expect("ok");
        let sent = publisher.tick().await;
        assert_eq!(sent.nodes.len(), 1);
        let chunk = stream.next().await.expect("event").expect("ok");
        let text = String::from_utf8(chunk.to_vec()).expect("utf-8");
        assert!(text.starts_with("event: metrics\ndata: {"), "{text}");
        let data: EventData = serde_json::from_str(
            text.lines()
                .nth(1)
                .expect("data")
                .trim_start_matches("data: "),
        )
        .expect("json");
        assert_eq!(data.kind.as_deref(), Some(SNAPSHOT_KIND));
        assert_eq!(data.metrics, Some(sent));
    }

    #[tokio::test]
    async fn the_publisher_ticks_only_while_someone_listens() {
        let (state, publisher) = publisher(None);
        let (stop_tx, stop) = watch::channel(false);
        let task = Arc::clone(&publisher).spawn(stop);
        tokio::time::sleep(Duration::from_millis(1_300)).await;
        assert_eq!(publisher.ticks(), 0, "nobody listens");
        assert_eq!(publisher.sampler().taken(), 0);

        let mut stream = Box::pin(
            event_stream(
                state.events(),
                state.store.as_ref(),
                None,
                TopicSet::parse("metrics").expect("topics"),
                Principal::system(SystemComponent::Api),
            )
            .await,
        );
        stream.next().await.expect("hello").expect("ok");
        let event = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .expect("an event within three seconds")
            .expect("event")
            .expect("ok");
        assert!(event.starts_with(b"event: metrics\n"));
        assert!(publisher.ticks() >= 1);
        drop(stream);
        // The tick notices that nobody listens and the publisher sleeps again.
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        let ticks = publisher.ticks();
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        assert_eq!(publisher.ticks(), ticks);

        stop_tx.send(true).expect("stop");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("stops")
            .expect("no panic");
    }

    #[tokio::test]
    async fn a_peer_read_reuses_a_young_sample_and_takes_a_new_one_after_half_a_second() {
        let (_, publisher) = publisher(None);
        let sampler = publisher.sampler().clone();
        let first = sampler.for_peer().await;
        let again = sampler.for_peer().await;
        assert!(Arc::ptr_eq(&first, &again), "younger than 500 ms");
        assert_eq!(sampler.taken(), 1);
        tokio::time::sleep(ON_DEMAND_EVERY + Duration::from_millis(50)).await;
        let later = sampler.for_peer().await;
        assert!(!Arc::ptr_eq(&first, &later));
        assert_eq!(sampler.taken(), 2);
        assert!(later.sample.interval_ms >= 500);
        let decoded: MetricsSample = from_cbor(&later.encoded).expect("cbor");
        assert_eq!(decoded, later.sample);
        // Without a node id, nothing to answer a peer with.
        assert_eq!(MetricsSource::current(&sampler).await, None);
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
        };
        assert_eq!(
            answer_of(PeerReply::Sample(encoded.clone())),
            PeerAnswer::Sample(Box::new(sample))
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
}
