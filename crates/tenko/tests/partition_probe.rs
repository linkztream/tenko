//! A probe on the minority's side of a partition keeps its observations and delivers them
//! to the majority: two controllers over one store, the first of which cannot write.

use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use tenko_cluster::{
    buffer::BufferConfig,
    ca::{CaPolicy, InternalCa, TlsResolver, generate_csr, pem_block},
    client::{Agent, AgentConfig},
    error::ClusterError,
    identity::{AgentState, Credentials, NodeIdentity, NodePaths},
    model::{EnrolRequest, NewEnrolment},
    probe::{IngestCounts, ProbeBatch, ProbeSink, Sighting, SightingSubject},
    registry::{NodeRegistry, RegistryConfig},
    server::ClusterListener,
};
use tenko_core::{
    NodeId, RequestCtx, Revision, SystemComponent, Timestamp, VrfId, observe::ProbeMethod,
};
use tenko_jobs::{EngineConfig, JobEngine};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, QuorumState, ReadConsistency, ReadView, Store,
    StoreError, StoreStatus, WatchFilter, WriteBatch, mem::MemStore,
};
use tenko_vault::{MemVault, SecretBytes};
use tokio::{sync::watch, task::JoinHandle};

const WAIT: Duration = Duration::from_secs(20);

/// Records every batch it gets.
#[derive(Default)]
struct RecordingSink {
    batches: Mutex<Vec<(NodeId, Option<VrfId>, ProbeBatch)>>,
}

impl RecordingSink {
    fn batches(&self) -> Vec<(NodeId, Option<VrfId>, ProbeBatch)> {
        self.batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl ProbeSink for RecordingSink {
    async fn ingest(
        &self,
        node: NodeId,
        vrf: Option<VrfId>,
        batch: ProbeBatch,
    ) -> Result<IngestCounts, ClusterError> {
        let new = u32::try_from(batch.sightings.len()).unwrap_or(u32::MAX);
        self.batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((node, vrf, batch));
        Ok(IngestCounts {
            new,
            ..IngestCounts::default()
        })
    }
}

/// A view of a store that delegates everything and, while `isolated` is set, reports the
/// member as cut off from its quorum.
struct PartitionedStore {
    inner: Arc<MemStore>,
    isolated: AtomicBool,
}

impl PartitionedStore {
    fn new(inner: Arc<MemStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            isolated: AtomicBool::new(true),
        })
    }

    fn set_isolated(&self, isolated: bool) {
        self.isolated.store(isolated, Ordering::SeqCst);
    }
}

#[async_trait]
impl Store for PartitionedStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        self.inner.propose(batch).await
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.inner.read(consistency).await
    }

    fn watch(
        &self,
        from: Option<Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        self.inner.watch(from, filter)
    }

    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> StoreStatus {
        let mut status = self.inner.status();
        if self.isolated.load(Ordering::SeqCst) {
            status.quorum = QuorumState::Isolated {
                since: Timestamp::now(),
                last_contact: None,
                applied: status.revision,
            };
        }
        status
    }

    fn leadership(&self) -> watch::Receiver<Option<tenko_store::Leadership>> {
        self.inner.leadership()
    }
}

/// One controller: a registry and a cluster port on the loopback over a given store view.
struct Controller {
    registry: Arc<NodeRegistry>,
    sink: Arc<RecordingSink>,
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

fn system() -> RequestCtx {
    RequestCtx::system(SystemComponent::Cluster)
}

impl Controller {
    /// `mem` holds the data and `vault` its secrets (one vault for every controller, as
    /// they share one key); `view` is what this controller sees of it.
    async fn start(mem: &Arc<MemStore>, vault: &MemVault, view: Arc<dyn Store>) -> Self {
        let ca = InternalCa::load_or_init(&**mem, vault, &system(), CaPolicy::default())
            .await
            .expect("CA");
        let engine = JobEngine::new(Arc::clone(&view), EngineConfig::default());
        let mut config = RegistryConfig::new(NodeId(1));
        config.heartbeat_secs = 1;
        let registry = NodeRegistry::new(view, Arc::new(ca), config);
        registry.register_steps(&engine);
        let material = registry
            .controller_material(vault, &system())
            .await
            .expect("controller certificate");
        let resolver = Arc::new(TlsResolver::default());
        resolver.set(Some(material));
        let sink = Arc::new(RecordingSink::default());
        let listener = ClusterListener::bind(&["127.0.0.1:0".parse().expect("address")])
            .await
            .expect("bind the cluster port");
        let addr = listener.local_addrs()[0];
        let (stop, stopped) = watch::channel(false);
        let task = listener
            .serve(
                &registry,
                sink.clone() as Arc<dyn ProbeSink>,
                resolver,
                stopped,
            )
            .expect("serve");
        Self {
            registry,
            sink,
            addr,
            stop,
            task,
        }
    }

    async fn halt(self) {
        let _ = self.stop.send(true);
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("the cluster port stops")
            .expect("task");
    }

    /// Enrols a node whose files live in `dir`; it learns `endpoints` in the given order.
    async fn enrol(&self, dir: &Path, name: &str, endpoints: Vec<String>) -> Credentials {
        let (_, token) = self
            .registry
            .create_enrolment(&system(), NewEnrolment::default())
            .await
            .expect("token");
        let (key, csr) = generate_csr().expect("csr");
        let mut ctx = system();
        ctx.source_ip = Some("192.0.2.20".parse().expect("ip"));
        let enrolled = self
            .registry
            .enrol(
                &ctx,
                EnrolRequest {
                    token: token.to_text().to_string(),
                    csr: pem_block("CERTIFICATE REQUEST", &csr),
                    name: Some(name.to_owned()),
                    roles: Vec::new(),
                    address: None,
                    version: "0.0.1".to_owned(),
                    majors: vec![1],
                },
            )
            .await
            .expect("enrol");
        let identity = NodeIdentity {
            node: enrolled.node.id,
            name: enrolled.node.name.clone(),
            roles: enrolled.node.roles.clone(),
            controller: "https://ddi.example.test:8443".to_owned(),
            endpoints,
            cluster_port: None,
            heartbeat_secs: 1,
            enrolled_at: Timestamp::now(),
            ca_sha256: self.registry.ca().root_info().sha256.clone(),
        };
        let credentials = Credentials::from_pem(
            identity,
            &enrolled.certificate_pem,
            SecretBytes::from_slice(key.expose()),
            &enrolled.ca_root_pem,
        )
        .expect("credentials");
        credentials.save(&NodePaths::new(dir)).expect("save");
        credentials
    }
}

fn agent(dir: &Path) -> Arc<Agent> {
    let paths = NodePaths::new(dir);
    let mut config = AgentConfig::new(paths.clone(), "0.0.1");
    config.backoff_min = Duration::from_millis(50);
    config.backoff_max = Duration::from_millis(200);
    config.refused_pause = Duration::from_millis(200);
    config.buffer = BufferConfig::new(paths.buffer());
    Agent::new(config).expect("agent")
}

async fn wait_for(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !check() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn batch(n: u8) -> ProbeBatch {
    ProbeBatch {
        method: ProbeMethod::Arp,
        vrf: None,
        complete: false,
        collected_at: Timestamp::now(),
        sightings: vec![Sighting {
            observed_at: Timestamp::now(),
            ttl_secs: None,
            subject: SightingSubject::Address {
                ip: format!("192.0.2.{n}").parse().expect("ip"),
                mac: None,
            },
        }],
    }
}

fn address_of(batch: &ProbeBatch) -> String {
    match &batch.sightings[0].subject {
        SightingSubject::Address { ip, .. } => ip.to_string(),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn a_probe_whose_controller_lost_quorum_delivers_to_another_controller() {
    let mem = Arc::new(MemStore::default());
    let minority_store = PartitionedStore::new(Arc::clone(&mem));
    let vault = MemVault::with_store(mem.clone());
    let x = Controller::start(&mem, &vault, minority_store.clone() as Arc<dyn Store>).await;
    let y = Controller::start(&mem, &vault, mem.clone() as Arc<dyn Store>).await;

    let dir = tempfile::tempdir().expect("dir");
    let credentials = x
        .enrol(
            dir.path(),
            "probe-minority",
            vec![x.addr.to_string(), y.addr.to_string()],
        )
        .await;
    assert_eq!(credentials.identity.endpoints[0], x.addr.to_string());

    let agent = agent(dir.path());
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&agent).run(stopped));
    wait_for("the node to connect", || {
        agent.status().state == AgentState::Connected
    })
    .await;

    agent.push(&batch(10)).expect("push");
    wait_for("the batch to reach the majority", || {
        y.sink.batches().len() == 1
    })
    .await;
    wait_for("the buffer to drain", || {
        agent.outbox().stats().batches == 0
    })
    .await;
    assert_eq!(y.sink.batches().len(), 1, "delivered exactly once");
    let (node, _, delivered) = y.sink.batches().remove(0);
    assert_eq!(node, credentials.identity.node);
    assert_eq!(address_of(&delivered), "192.0.2.10");
    assert_eq!(x.sink.batches().len(), 0, "the minority took nothing");

    // Once the first controller accepts writes again, it takes batches too.
    minority_store.set_isolated(false);
    for n in 11..=14 {
        agent.push(&batch(n)).expect("push");
    }
    wait_for("the second batches to arrive", || {
        x.sink.batches().len() + y.sink.batches().len() == 5
    })
    .await;
    wait_for("the buffer to drain again", || {
        agent.outbox().stats().batches == 0
    })
    .await;
    let mut seen: Vec<String> = x
        .sink
        .batches()
        .iter()
        .chain(y.sink.batches().iter())
        .map(|(_, _, delivered)| address_of(delivered))
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        [
            "192.0.2.10",
            "192.0.2.11",
            "192.0.2.12",
            "192.0.2.13",
            "192.0.2.14"
        ]
    );

    let _ = stop.send(true);
    tokio::time::timeout(WAIT, task)
        .await
        .expect("the agent stops")
        .expect("agent");
    x.halt().await;
    y.halt().await;
}
