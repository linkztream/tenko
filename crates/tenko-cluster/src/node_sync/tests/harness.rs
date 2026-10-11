//! The controller and agent helpers of the node sync tests.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use serde::Serialize;
use tenko_core::{
    NodeId, RequestCtx, Revision, SystemComponent, Timestamp, VrfId,
    codec::{key::encode_key, to_cbor},
    observe::ProbeMethod,
    serde_util::HexBytes,
};
use tenko_jobs::{EngineConfig, JobEngine};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, KeyRange, QuorumState, ReadConsistency, ReadView,
    ReadViewExt, Store, StoreError, StoreStatus, WatchFilter, WriteBatch,
    mem::{MemStore, MemStoreConfig},
    tables,
};
use tenko_vault::{MemVault, SecretBytes, Vault};
use tokio::{sync::watch, task::JoinHandle};

use crate::{
    buffer::BufferConfig,
    ca::{CaPolicy, InternalCa, TlsResolver, generate_csr, pem_block},
    client::{self, Agent, AgentConfig},
    error::ClusterError,
    identity::{Credentials, NodeIdentity, NodePaths},
    model::{EnrolRequest, NewEnrolment},
    node_sync::{NodeSync, local::ConfigFiles, secrets::SecretUse, tables::PROBE_CONFIG},
    probe::{IngestCounts, ProbeBatch, ProbeSink, Sighting, SightingSubject},
    registry::{NodeRegistry, RegistryConfig},
    server::ClusterListener,
};

/// How long a test waits for anything before it fails.
pub const WAIT: Duration = Duration::from_secs(20);

/// The id of the first node a controller enrols.
pub const FIRST_NODE: NodeId = NodeId(1001);

/// Records every batch it gets.
#[derive(Default)]
pub struct RecordingSink {
    batches: Mutex<Vec<(NodeId, Option<VrfId>, ProbeBatch)>>,
}

impl RecordingSink {
    pub fn batches(&self) -> Vec<(NodeId, Option<VrfId>, ProbeBatch)> {
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

/// A store that refuses writes on demand the way a controller cut off from its cluster
/// does: `status().quorum` says `Electing`. Everything else goes to the inner store.
pub struct GateStore {
    inner: Arc<MemStore>,
    cut_off: AtomicBool,
}

impl GateStore {
    pub fn new(inner: Arc<MemStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            cut_off: AtomicBool::new(false),
        })
    }

    /// Cuts the controller off from (or reconnects it to) its quorum.
    pub fn cut_off(&self, cut_off: bool) {
        self.cut_off.store(cut_off, Ordering::SeqCst);
    }
}

#[async_trait]
impl Store for GateStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        if self.cut_off.load(Ordering::SeqCst) {
            return Err(StoreError::NoQuorum);
        }
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
        if self.cut_off.load(Ordering::SeqCst) {
            status.quorum = QuorumState::Electing {
                since: Timestamp::now(),
            };
        }
        status
    }

    fn leadership(&self) -> watch::Receiver<Option<tenko_store::Leadership>> {
        self.inner.leadership()
    }
}

/// How a controller is set up.
#[derive(Clone)]
pub struct Options {
    /// The journal and watch limits of the store.
    pub store: MemStoreConfig,
    /// The bandwidth cap per configuration stream (`[cluster] sync_kbps`); 0 is none.
    pub rate_kbps: u64,
    /// Whether the node sync has a vault (node secrets).
    pub vault: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            store: MemStoreConfig::default(),
            rate_kbps: 0,
            vault: true,
        }
    }
}

/// One controller: store, vault, CA, registry and a cluster port on the loopback.
pub struct Controller {
    pub store: Arc<MemStore>,
    pub vault: Arc<MemVault>,
    pub gate: Arc<GateStore>,
    pub registry: Arc<NodeRegistry>,
    pub sink: Arc<RecordingSink>,
    pub resolver: Arc<TlsResolver>,
    pub addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

pub fn system() -> RequestCtx {
    RequestCtx::system(SystemComponent::Cluster)
}

impl Controller {
    pub async fn start() -> Self {
        Self::start_with(Options::default()).await
    }

    pub async fn start_with(options: Options) -> Self {
        let store = Arc::new(MemStore::new(options.store.clone()));
        let vault = Arc::new(MemVault::with_store(store.clone()));
        Self::over(store, vault, NodeId(1), &options).await
    }

    /// A second controller over the same store and vault (the controllers of a cluster
    /// share both), with its own registry, sink and cluster port.
    pub async fn join(&self, local: u64) -> Self {
        let options = Options::default();
        Self::over(
            self.store.clone(),
            self.vault.clone(),
            NodeId(local),
            &options,
        )
        .await
    }

    async fn over(
        store: Arc<MemStore>,
        vault: Arc<MemVault>,
        local: NodeId,
        options: &Options,
    ) -> Self {
        let ca = InternalCa::load_or_init(&*store, &*vault, &system(), CaPolicy::default())
            .await
            .expect("CA");
        let gate = GateStore::new(store.clone());
        let store_dyn: Arc<dyn Store> = gate.clone();
        let engine = JobEngine::new(Arc::clone(&store_dyn), EngineConfig::default());
        let mut config = RegistryConfig::new(local);
        config.heartbeat_secs = 1;
        let registry = NodeRegistry::new(Arc::clone(&store_dyn), Arc::new(ca), config);
        registry.register_steps(&engine);
        let mut sync = NodeSync::new(store_dyn).with_rate_kbps(options.rate_kbps);
        if options.vault {
            sync = sync.with_vault(vault.clone() as Arc<dyn Vault>);
        }
        registry.set_node_sync(sync);
        let material = registry
            .controller_material(&*vault, &system())
            .await
            .expect("controller certificate");
        let resolver = Arc::new(TlsResolver::default());
        resolver.set(Some(material));
        let (stop, _) = watch::channel(false);
        let mut controller = Self {
            store,
            vault,
            gate,
            registry,
            sink: Arc::new(RecordingSink::default()),
            resolver,
            addr: "127.0.0.1:0".parse().expect("address"),
            stop,
            task: None,
        };
        controller.listen().await;
        controller
    }

    /// Opens the cluster port (again, on the same port after a stop).
    pub async fn listen(&mut self) {
        let listener = ClusterListener::bind(&[self.addr])
            .await
            .expect("bind the cluster port");
        self.addr = listener.local_addrs()[0];
        let (stop, stopped) = watch::channel(false);
        self.stop = stop;
        self.task = Some(
            listener
                .serve(
                    &self.registry,
                    self.sink.clone() as Arc<dyn ProbeSink>,
                    self.resolver.clone(),
                    stopped,
                )
                .expect("serve"),
        );
    }

    /// Enrols a node whose files live in `dir`, with this controller's cluster port as
    /// its endpoint.
    pub async fn enrol(&self, dir: &Path, name: &str) -> Credentials {
        self.enrol_at(dir, name, &[self.addr]).await
    }

    /// As [`enrol`](Self::enrol), with these endpoints in the node's identity.
    pub async fn enrol_at(&self, dir: &Path, name: &str, endpoints: &[SocketAddr]) -> Credentials {
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
            endpoints: endpoints.iter().map(ToString::to_string).collect(),
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
        credentials
            .save(&NodePaths::new(dir))
            .expect("save the credentials");
        credentials
    }

    /// A gRPC channel to the cluster port of `controller` with the credentials of a node.
    pub async fn channel(&self, credentials: &Credentials) -> tonic::transport::Channel {
        let config = credentials.client_config().expect("client configuration");
        client::connect(&self.addr.to_string(), config)
            .await
            .expect("channel")
    }

    /// The audit actions of the `cluster.` family, oldest first.
    pub async fn audit_actions(&self) -> Vec<String> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.scan_typed(&tables::AUDIT, KeyRange::all(), usize::MAX, false)
            .expect("audit")
            .into_iter()
            .map(|(_, record, _)| record.draft.action.as_str().to_owned())
            .filter(|action| action.starts_with("cluster."))
            .collect()
    }

    /// Writes the probe configuration row of `node`.
    pub async fn put_config(&self, node: NodeId, row: &Row) -> Revision {
        let mut batch = WriteBatch::for_request(&system());
        batch.put(PROBE_CONFIG, encode_key(&node.0), row.encode());
        self.store.propose(batch).await.expect("propose").revision
    }

    /// Removes the probe configuration row of `node`.
    pub async fn delete_config(&self, node: NodeId) -> Revision {
        let mut batch = WriteBatch::for_request(&system());
        batch.delete(PROBE_CONFIG, encode_key(&node.0));
        self.store.propose(batch).await.expect("propose").revision
    }

    /// Writes `count` rows of another node: revisions that do not concern the nodes
    /// under test, but push older change sets out of a short journal.
    pub async fn churn(&self, count: u32) {
        for value in 0..count {
            self.put_config(NodeId(1999), &Row::plain(value)).await;
        }
    }
}

/// A probe configuration row as the tests write it: any CBOR map will do for the sync,
/// and `secrets` is the field the secret hand-over reads.
#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub value: u32,
    pub pad: HexBytes,
    pub secrets: Vec<SecretUse>,
}

impl Row {
    pub fn plain(value: u32) -> Self {
        Self {
            value,
            pad: HexBytes(Vec::new()),
            secrets: Vec::new(),
        }
    }

    /// A row with `len` bytes of noise that does not compress.
    pub fn heavy(value: u32, len: usize) -> Self {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let pad = (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[3]
            })
            .collect();
        Self {
            value,
            pad: HexBytes(pad),
            secrets: Vec::new(),
        }
    }

    /// A row that names `secrets`.
    pub fn naming(value: u32, secrets: Vec<SecretUse>) -> Self {
        Self {
            secrets,
            ..Self::plain(value)
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        to_cbor(self).expect("encode the row").to_vec()
    }
}

pub fn agent(dir: &Path) -> Arc<Agent> {
    let paths = NodePaths::new(dir);
    let mut config = AgentConfig::new(paths.clone(), "0.0.1");
    config.backoff_min = Duration::from_millis(50);
    config.backoff_max = Duration::from_millis(200);
    config.refused_pause = Duration::from_millis(200);
    config.buffer = BufferConfig::new(paths.buffer());
    Agent::new(config).expect("agent")
}

/// A running agent.
pub struct Running {
    pub agent: Arc<Agent>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Running {
    /// Starts an agent over the node files in `dir`.
    pub fn start(dir: &Path) -> Self {
        let agent = agent(dir);
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(Arc::clone(&agent).run(stopped));
        Self { agent, stop, task }
    }

    /// Stops the agent and waits until it is gone.
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("the agent stops")
            .expect("task");
    }
}

pub async fn wait_for(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !check() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The configuration files of the node whose files live in `dir`.
pub fn config_files(dir: &Path) -> ConfigFiles {
    ConfigFiles::new(NodePaths::new(dir).config())
}

/// The path of the node's configuration file.
pub fn state_file(dir: &Path) -> PathBuf {
    config_files(dir).state()
}

pub fn batch(n: u8) -> ProbeBatch {
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
