//! The controller cluster over the real cluster port inside one process: three Raft
//! stores, each with its own cluster port on the loopback interface, mutual TLS with
//! controller certificates of one internal CA, joins through `Cluster.Join`, automatic
//! promotion to three voters, write forwarding, linearizable reads and the hand-over of
//! leadership through `Cluster.Campaign`. The follower cases of the store conformance
//! suite run through a member that does not lead, over this transport.
//!
//! Also: a snapshot streamed over mutual TLS to a learner whose log the leader purged, the
//! refusal of a probe certificate and of another installation's CA on the `Raft` service,
//! the single-use key transfer, membership changes forwarded from a follower, and equal
//! state digests on every member.

use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rustls::pki_types::pem::PemObject as _;
use tenko_cluster::{
    admin::{ClusterAdmin, MemberRole, PromoteRequest},
    ca::{CaPolicy, CertSource, InternalCa, TlsMaterial, TlsResolver, generate_csr, pem_block},
    error::ClusterError,
    kek::{KekSource, SealedKeks},
    model::{EnrollRequest, NewEnrollment},
    mtls::RevocationSet,
    peers::{
        CONTACT_WINDOW, ControllerIdentity, PeerConfig, PeerNetwork, PeerTimings, Peers,
        certificate_ref,
    },
    proto::v1,
    registry::{NodeRegistry, RegistryConfig},
    server::{ClusterListener, NodeServices, Port, code_of},
    session::Sessions,
};
use tenko_core::{
    NodeId, RequestCtx, Role, SystemComponent, TableName,
    testing::{free_port, wait_until_async},
};
use tenko_jobs::{EngineConfig, JobEngine};
use tenko_store::{
    Committed, KeyRange, Mutation, ReadConsistency, ReadViewExt as _, Store, StoreError, StoreRole,
    WriteBatch,
    raft::{RaftStore, RaftStoreConfig, SnapshotPolicy},
    testing::{ClusterFixture, ConformanceConfig},
};
use tenko_vault::{KekRing, MemKek, SecretBytes, StoreVault};
use tokio::{sync::watch, task::JoinHandle};

fn system() -> RequestCtx {
    RequestCtx::system(SystemComponent::Cluster)
}

/// A key source that "seals" by echoing the recipient: enough to test the service path.
struct EchoKek;

impl KekSource for EchoKek {
    fn seal_for(&self, recipient: &[u8], context: &[u8]) -> Result<SealedKeks, ClusterError> {
        let mut sealed = recipient.to_vec();
        sealed.extend_from_slice(context);
        Ok(SealedKeks {
            format: "test-echo".to_owned(),
            sealed,
            generation_ids: vec!["kek-test-1".to_owned()],
        })
    }
}

/// The identity of the first member in the tests: its certificate, never moved.
struct FixedIdentity(tenko_cluster::model::CertificateRef);

#[async_trait::async_trait]
impl ControllerIdentity for FixedIdentity {
    async fn portable(&self) -> Result<tenko_cluster::model::CertificateRef, ClusterError> {
        Ok(self.0.clone())
    }

    fn name(&self) -> String {
        "controller-one".to_owned()
    }
}

/// A store that a test can make refuse every write to one table as a lost race, or that
/// puts another write right before the next write to it: what a concurrent request does
/// between the plan of a write and the write.
struct Interposed<S> {
    inner: S,
    table: TableName,
    refuse: AtomicBool,
    before: Mutex<Option<WriteBatch>>,
}

impl<S> Interposed<S> {
    fn new(inner: S, table: &TableName) -> Self {
        Self {
            inner,
            table: table.clone(),
            refuse: AtomicBool::new(false),
            before: Mutex::new(None),
        }
    }

    /// From now on every write to the table fails as a lost race (`refuse`), or not.
    fn refuse(&self, refuse: bool) {
        self.refuse.store(refuse, Ordering::SeqCst);
    }

    /// `batch` commits right before the next write to the table.
    fn before_next(&self, batch: WriteBatch) {
        *self.before.lock().unwrap_or_else(PoisonError::into_inner) = Some(batch);
    }
}

#[async_trait::async_trait]
impl<S: Store> Store for Interposed<S> {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        let touches = batch.mutations.iter().any(|mutation| match mutation {
            Mutation::Put { table, .. } | Mutation::Delete { table, .. } => *table == self.table,
            Mutation::Bump { .. } => false,
        });
        if touches {
            if self.refuse.load(Ordering::SeqCst) {
                return Err(StoreError::PreconditionFailed(Vec::new()));
            }
            let before = self
                .before
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(before) = before {
                self.inner
                    .propose(before)
                    .await
                    .expect("the write in between");
            }
        }
        self.inner.propose(batch).await
    }

    async fn read(
        &self,
        consistency: ReadConsistency,
    ) -> Result<Arc<dyn tenko_store::ReadView>, StoreError> {
        self.inner.read(consistency).await
    }

    fn watch(
        &self,
        from: Option<tenko_core::Revision>,
        filter: tenko_store::WatchFilter,
    ) -> Result<tenko_store::ChangeStream, StoreError> {
        self.inner.watch(from, filter)
    }

    fn register_index(&self, index: Arc<dyn tenko_store::DerivedIndex>) -> Result<(), StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> tenko_store::StoreStatus {
        self.inner.status()
    }

    fn leadership(&self) -> watch::Receiver<Option<tenko_store::Leadership>> {
        self.inner.leadership()
    }
}

/// One controller: store, registry, peer layer and cluster port.
struct Member {
    store: RaftStore,
    peers: Peers,
    registry: Arc<NodeRegistry>,
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    engine: JobEngine,
    /// The certificate chain and key it presents to its peers.
    identity: (Vec<rustls::pki_types::CertificateDer<'static>>, SecretBytes),
    /// What its registry and job engine write through, with the revocation table under
    /// the test's control.
    writes: Arc<Interposed<RaftStore>>,
}

impl Member {
    fn node(&self) -> NodeId {
        self.store.node_id()
    }
}

fn store_config(node: u64, configure: &(dyn Fn(&mut RaftStoreConfig) + Sync)) -> RaftStoreConfig {
    let mut config = RaftStoreConfig::for_conformance(&ConformanceConfig::default());
    config.node_id = NodeId(node);
    config.bootstrap = node == 1;
    config.timings.heartbeat_ms = 50;
    configure(&mut config);
    config
}

/// The controllers of one installation.
struct Lab {
    members: Mutex<Vec<Arc<Member>>>,
    ca: Arc<InternalCa>,
    first: Arc<Member>,
}

/// Starts a member over `store` with the certificate `chain`/`key`.
async fn start_member(
    store: RaftStore,
    ca: &Arc<InternalCa>,
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: &SecretBytes,
    identity: Arc<dyn ControllerIdentity>,
    bookkeeping: bool,
) -> Member {
    let node = store.node_id();
    let writes = Arc::new(Interposed::new(
        store.clone(),
        tenko_cluster::model::tables::REVOCATIONS.name(),
    ));
    let store_dyn: Arc<dyn Store> = Arc::clone(&writes) as Arc<dyn Store>;
    let engine = JobEngine::new(Arc::clone(&store_dyn), EngineConfig::default());
    let revocations = Arc::new(RevocationSet::new());
    let sessions = Sessions::new();
    let registry = NodeRegistry::with_port(
        Arc::clone(&store_dyn),
        Arc::clone(ca),
        RegistryConfig::new(node),
        Arc::clone(&revocations),
        Arc::clone(&sessions),
    );
    registry.register_steps(&engine);
    let listener = ClusterListener::bind(&["127.0.0.1:0".parse().expect("address")])
        .await
        .expect("bind");
    let addr = listener.local_addrs()[0];
    registry.set_listening(vec![addr]);
    let network = PeerNetwork::new(node, PeerTimings::from_store(store.config()));
    network.set_tls(
        tenko_cluster::mtls::client_config(ca.root_der(), chain.clone(), key)
            .expect("client config"),
    );
    let mut config = PeerConfig::new(node, 2);
    config.address = addr.to_string();
    config.promote_after = Duration::from_millis(300);
    let peers = Peers::new(store.clone(), network, config);
    if bookkeeping {
        peers.attach_registry(Arc::clone(&registry));
        peers.register_steps(&engine);
    }
    peers.attach_identity(identity);
    peers.attach_kek(Arc::new(EchoKek));
    let resolver = Arc::new(TlsResolver::default());
    resolver.set(Some(
        TlsMaterial::from_der(chain.clone(), key, CertSource::Inline).expect("material"),
    ));
    let (stop, stopped) = watch::channel(false);
    let mut tasks = peers.spawn(stopped.clone());
    tasks.push(registry.follow_revocations(stopped.clone()));
    tasks.push(
        listener
            .serve_port(
                Port {
                    ca_root: ca.root_der().clone(),
                    resolver,
                    revocations,
                    sessions,
                    nodes: NodeServices::ready(&tenko_cluster::server::ClusterService::new(
                        Arc::clone(&registry),
                        Arc::new(tenko_cluster::probe::DiscardProbes),
                    )),
                    peers: Some(peers.clone()),
                },
                stopped,
                || {},
            )
            .expect("serve"),
    );
    Member {
        store,
        peers,
        registry,
        addr,
        stop,
        tasks,
        engine,
        identity: (chain, SecretBytes::from_slice(key.expose())),
        writes,
    }
}

impl Lab {
    /// The first controller alone.
    async fn first(configure: &(dyn Fn(&mut RaftStoreConfig) + Sync)) -> Self {
        Self::first_with(configure, CaPolicy::default()).await
    }

    /// The first controller, with a CA that issues by `policy`.
    async fn first_with(
        configure: &(dyn Fn(&mut RaftStoreConfig) + Sync),
        policy: CaPolicy,
    ) -> Self {
        let store = RaftStore::open_temp(store_config(1, configure))
            .await
            .expect("store");
        let store_dyn: Arc<dyn Store> = Arc::new(store.clone());
        let ring = KekRing::new(Arc::new(MemKek::generate("kek-test-1")));
        let vault = StoreVault::open(Arc::clone(&store_dyn), ring)
            .await
            .expect("vault");
        let ca = Arc::new(
            InternalCa::load_or_init(store_dyn.as_ref(), &vault, &system(), policy)
                .await
                .expect("CA"),
        );
        let registry = NodeRegistry::new(
            Arc::clone(&store_dyn),
            Arc::clone(&ca),
            RegistryConfig::new(NodeId(1)),
        );
        let (chain, key) = registry
            .controller_identity(&vault, &system())
            .await
            .expect("controller certificate");
        let info = tenko_cluster::ca::CertInfo::from_der(&chain[0]).expect("info");
        let identity: Arc<dyn ControllerIdentity> = Arc::new(FixedIdentity(certificate_ref(&info)));
        let first = Arc::new(start_member(store, &ca, chain, &key, identity, true).await);
        Self {
            members: Mutex::new(vec![Arc::clone(&first)]),
            ca,
            first,
        }
    }

    fn members(&self) -> Vec<Arc<Member>> {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Enrolls a controller through the first member's registry: its certificate and key.
    async fn enroll_controller(
        &self,
        name: &str,
    ) -> (
        NodeId,
        Vec<rustls::pki_types::CertificateDer<'static>>,
        SecretBytes,
        uuid::Uuid,
    ) {
        let (enrollment, token) = self
            .first
            .registry
            .create_enrollment(
                &system(),
                NewEnrollment {
                    roles: vec![Role::Controller],
                    name: Some(name.to_owned()),
                    ..NewEnrollment::default()
                },
            )
            .await
            .expect("controller token");
        let (key, csr) = generate_csr().expect("csr");
        let enrolled = self
            .first
            .registry
            .enroll(
                &system(),
                EnrollRequest {
                    token: token.to_text().to_string(),
                    csr: pem_block("CERTIFICATE REQUEST", &csr),
                    name: Some(name.to_owned()),
                    roles: vec![Role::Controller],
                    address: None,
                    version: "0.0.1".to_owned(),
                    majors: vec![1],
                },
            )
            .await
            .expect("enroll a controller");
        let chain =
            rustls::pki_types::CertificateDer::pem_slice_iter(enrolled.certificate_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("chain");
        (enrolled.node.id, chain, key, enrollment.id)
    }

    /// Enrolls, starts and joins another controller.
    async fn join(
        &self,
        name: &str,
        configure: &(dyn Fn(&mut RaftStoreConfig) + Sync),
    ) -> Arc<Member> {
        let (node, chain, key, _) = self.enroll_controller(name).await;
        let store = RaftStore::open_temp(store_config(node.0, configure))
            .await
            .expect("store");
        let info = tenko_cluster::ca::CertInfo::from_der(&chain[0]).expect("info");
        let credentials_identity: Arc<dyn ControllerIdentity> =
            Arc::new(FixedIdentity(certificate_ref(&info)));
        let member =
            Arc::new(start_member(store, &self.ca, chain, &key, credentials_identity, true).await);
        member
            .peers
            .network()
            .pin(NodeId(1), self.first.addr.to_string());
        let mut client = member
            .peers
            .network()
            .cluster_client(NodeId(1))
            .await
            .expect("a channel to the first controller");
        client
            .join(v1::JoinRequest {
                node_id: node.0,
                address: member.addr.to_string(),
                version: "0.0.1".to_owned(),
                capabilities: Vec::new(),
                data_format: 2,
            })
            .await
            .expect("join");
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&member));
        member
    }

    /// The first controller and two that joined, promoted to three voters.
    async fn three(configure: &(dyn Fn(&mut RaftStoreConfig) + Sync)) -> Self {
        Self::three_with(configure, CaPolicy::default()).await
    }

    /// Three voters, with a CA that issues by `policy`.
    async fn three_with(
        configure: &(dyn Fn(&mut RaftStoreConfig) + Sync),
        policy: CaPolicy,
    ) -> Self {
        let lab = Self::first_with(configure, policy).await;
        lab.join("controller-two", configure).await;
        lab.join("controller-three", configure).await;
        wait_until_async("three voters", async || {
            lab.first.store.membership().voters.len() == 3
        })
        .await;
        lab
    }

    async fn leader(&self) -> Arc<Member> {
        wait_until_async("a member to take office", async || {
            self.members().into_iter().find(|member| {
                member
                    .store
                    .leadership()
                    .borrow()
                    .is_some_and(|seen| seen.is_self)
            })
        })
        .await
    }

    async fn follower(&self) -> Arc<Member> {
        let leader = self.leader().await.node();
        self.members()
            .into_iter()
            .find(|member| member.node() != leader)
            .expect("a follower")
    }

    async fn stop(&self) {
        for member in self.members() {
            let _ = member.stop.send(true);
            for task in &member.tasks {
                task.abort();
            }
            let _ = member.store.shutdown().await;
        }
    }
}

#[async_trait::async_trait]
impl ClusterFixture for Lab {
    async fn leader(&self) -> Arc<dyn Store> {
        Arc::new(Lab::leader(self).await.store.clone())
    }

    async fn follower(&self) -> Arc<dyn Store> {
        Arc::new(Lab::follower(self).await.store.clone())
    }

    async fn change_leader(&self) {
        let leader = Lab::leader(self).await;
        let moved = leader
            .peers
            .hand_over()
            .await
            .expect("hand leadership over");
        assert_ne!(moved, leader.node());
        wait_until_async("the new leader to take office", async || {
            Lab::leader(self).await.node() != leader.node()
        })
        .await;
    }
}

fn no_change(_: &mut RaftStoreConfig) {}

impl Lab {
    /// Three voters over the cluster port without the cluster's own bookkeeping: the CA
    /// lives outside the replicated store, the node and member records are written without
    /// audit records and the voters are set directly, so the store holds nothing but the
    /// conformance cases' own writes (and one setup revision).
    async fn bare_three(config: &ConformanceConfig) -> Self {
        let ca_store = Arc::new(tenko_store::mem::MemStore::default());
        let ca_vault = tenko_vault::MemVault::with_store(Arc::clone(&ca_store));
        let ca = Arc::new(
            InternalCa::load_or_init(ca_store.as_ref(), &ca_vault, &system(), CaPolicy::default())
                .await
                .expect("CA"),
        );
        let roles: tenko_core::RoleSet = [Role::Controller].into_iter().collect();
        let mut members = Vec::new();
        let mut records = Vec::new();
        for node in [1_u64, 1001, 1002] {
            let issued = ca
                .issue_node_cert_with_key_for(NodeId(node), roles, tenko_core::Timestamp::now())
                .expect("certificate");
            let mut store_config = RaftStoreConfig::for_conformance(config);
            store_config.node_id = NodeId(node);
            store_config.bootstrap = node == 1;
            store_config.timings.heartbeat_ms = 50;
            let store = RaftStore::open_temp(store_config).await.expect("store");
            let reference = certificate_ref(&issued.info);
            let identity: Arc<dyn ControllerIdentity> = Arc::new(FixedIdentity(reference.clone()));
            let member = Arc::new(
                start_member(
                    store,
                    &ca,
                    issued.chain.clone(),
                    &issued.key,
                    identity,
                    false,
                )
                .await,
            );
            records.push((NodeId(node), reference, member.addr));
            members.push(member);
        }
        let first = Arc::clone(&members[0]);
        let mut batch = tenko_store::WriteBatch::new(
            tenko_core::Principal::system(SystemComponent::Cluster),
            tenko_core::Timestamp::now(),
        );
        for (node, certificate, addr) in &records {
            batch
                .put_typed(
                    &tenko_cluster::model::tables::NODES,
                    &node.0,
                    &tenko_cluster::model::NodeRecord {
                        id: *node,
                        name: format!("controller-{}", node.0),
                        roles: vec![Role::Controller],
                        address: Some(addr.to_string()),
                        vrf: None,
                        certificate: certificate.clone(),
                        serials: vec![certificate.clone()],
                        enrolled_at: tenko_core::Timestamp::now(),
                        enrollment: uuid::Uuid::nil(),
                        enrolled_by: None,
                        renewed_at: None,
                        last_seen: None,
                        version: None,
                        protocol: tenko_cluster::model::ProtocolState::default(),
                    },
                )
                .expect("node record");
            batch
                .put_typed(
                    &tenko_cluster::model::tables::MEMBERS,
                    &node.0,
                    &tenko_cluster::model::MemberRecord {
                        node: *node,
                        address: addr.to_string(),
                        version: "0.0.1".to_owned(),
                        data_format: 2,
                        joined_at: tenko_core::Timestamp::now(),
                        protocol_majors: Vec::new(),
                        raft_wire: None,
                        formats: Vec::new(),
                    },
                )
                .expect("member record");
        }
        first.store.propose(batch).await.expect("records");
        for (node, _, addr) in &records[1..] {
            first
                .store
                .add_learner(*node, addr.to_string(), true)
                .await
                .expect("learner");
        }
        first
            .store
            .set_voters(records.iter().map(|(node, _, _)| *node).collect(), false)
            .await
            .expect("three voters");
        Self {
            members: Mutex::new(members),
            ca,
            first,
        }
    }
}

// The follower cases of the conformance suite over the cluster port.
tenko_store::follower_conformance_tests!(|config: ConformanceConfig| async move {
    Lab::bare_three(&config).await
});

/// Two controllers join the first: learners first, then three voters at once (one voter
/// and one caught-up learner wait for the second learner); everything replicates and the
/// members agree on the state digest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controllers_join_as_learners_and_become_three_voters() {
    let lab = Lab::first(&no_change).await;
    let second = lab.join("controller-two", &no_change).await;
    // The learner catches up, but a promotion to two voters does not happen on its own.
    wait_until_async("the learner catches up", async || {
        lab.first
            .store
            .status()
            .members
            .iter()
            .any(|member| member.node == second.node() && member.lag_entries == Some(0))
    })
    .await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        lab.first.store.membership().voters.len(),
        1,
        "no even voter count"
    );
    let refused = lab
        .first
        .peers
        .promote(&system(), second.node(), PromoteRequest::default())
        .await
        .expect_err("a promotion to two voters needs force");
    assert_eq!(refused.code(), "cluster.member.even_voters");

    lab.join("controller-three", &no_change).await;
    wait_until_async("three voters", async || {
        lab.first.store.membership().voters.len() == 3
    })
    .await;
    let view = lab.first.peers.view().await.expect("view");
    assert_eq!(view.members.len(), 3);
    assert!(
        view.members
            .iter()
            .all(|member| member.role == MemberRole::Voter)
    );
    assert!(view.members.iter().all(|member| member.address.is_some()));

    // A write through a follower and equal digests on every member.
    let follower = lab.follower().await;
    let mut batch = tenko_store::WriteBatch::new(
        tenko_core::Principal::system(SystemComponent::Ipam),
        tenko_core::Timestamp::now(),
    );
    batch.put(
        tenko_core::TableName::from_static("ipam.peer_rows"),
        prost::bytes::Bytes::from_static(b"k"),
        prost::bytes::Bytes::from_static(b"v"),
    );
    let committed = follower
        .store
        .propose(batch)
        .await
        .expect("forwarded write");
    let report = lab.first.peers.digests(None).await.expect("digests");
    assert!(report.agree, "{report:?}");
    assert!(report.revision >= committed.revision);
    assert_eq!(report.members.len(), 3);
    lab.stop().await;
}

/// A probe certificate and a controller of another installation are refused on the Raft
/// service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_raft_service_refuses_probes_and_foreign_controllers() {
    let lab = Lab::first(&no_change).await;
    // A probe of this installation.
    let (_, token) = lab
        .first
        .registry
        .create_enrollment(&system(), NewEnrollment::default())
        .await
        .expect("probe token");
    let (key, csr) = generate_csr().expect("csr");
    let probe = lab
        .first
        .registry
        .enroll(
            &system(),
            EnrollRequest {
                token: token.to_text().to_string(),
                csr: pem_block("CERTIFICATE REQUEST", &csr),
                name: Some("probe-lab".to_owned()),
                roles: Vec::new(),
                address: None,
                version: "0.0.1".to_owned(),
                majors: vec![1],
            },
        )
        .await
        .expect("enroll a probe");
    let chain = rustls::pki_types::CertificateDer::pem_slice_iter(probe.certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("chain");
    let network = PeerNetwork::new(probe.node.id, PeerTimings::default());
    network.set_tls(
        tenko_cluster::mtls::client_config(lab.ca.root_der(), chain, &key).expect("config"),
    );
    let channel = network
        .channel(&lab.first.addr.to_string())
        .await
        .expect("a probe reaches the port");
    let mut raft = v1::raft_client::RaftClient::new(channel);
    let refused = raft
        .vote(v1::RaftRequest::default())
        .await
        .expect_err("a probe may not vote");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    assert_eq!(code_of(&refused), Some("cluster.peer.not_controller"));

    // A controller certificate of another installation fails the TLS handshake.
    let other_store = Arc::new(tenko_store::mem::MemStore::default());
    let other_vault = tenko_vault::MemVault::with_store(Arc::clone(&other_store));
    let other_ca = InternalCa::load_or_init(
        other_store.as_ref(),
        &other_vault,
        &system(),
        CaPolicy::default(),
    )
    .await
    .expect("other CA");
    let other_registry = NodeRegistry::new(
        other_store.clone() as Arc<dyn Store>,
        Arc::new(other_ca),
        RegistryConfig::new(NodeId(1)),
    );
    let (chain, key) = other_registry
        .controller_identity(&other_vault, &system())
        .await
        .expect("foreign controller certificate");
    // The foreign client trusts this installation's CA, so the client accepts the server:
    // what refuses the connection is the server's check of the client certificate. In TLS
    // 1.3 the server's refusal can arrive with the first call after the handshake; either
    // way no Raft code answers, which only a call that reached the service would carry.
    let refused = raft_vote_refusal(
        &lab,
        NodeId(1),
        chain,
        &key,
        lab.first.addr,
        "a controller certificate of another installation",
    )
    .await;
    assert_eq!(
        refused, None,
        "the foreign certificate must fail the TLS handshake, not reach the Raft service"
    );
    lab.stop().await;
}

/// A revoked controller has no node record left, like the first controller of a cluster,
/// which never enrolled. The `Raft` service accepts a caller without a record only while
/// it is not revoked: a certificate of a revoked controller that is not on the revocation
/// list (one its record no longer held) is refused all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_raft_service_refuses_a_revoked_controller_without_a_record() {
    let lab = Lab::three(&no_change).await;
    let (_, token) = lab
        .first
        .registry
        .create_enrollment(
            &system(),
            NewEnrollment {
                roles: vec![Role::Controller],
                ..NewEnrollment::default()
            },
        )
        .await
        .expect("controller token");
    let (_, csr) = generate_csr().expect("csr");
    let enrolled = lab
        .first
        .registry
        .enroll(
            &system(),
            EnrollRequest {
                token: token.to_text().to_string(),
                csr: pem_block("CERTIFICATE REQUEST", &csr),
                name: Some("controller-gone".to_owned()),
                roles: Vec::new(),
                address: None,
                version: "0.0.1".to_owned(),
                majors: vec![1],
            },
        )
        .await
        .expect("enroll a controller");
    let node = enrolled.node.id;
    // A second certificate for the same controller that its record never held.
    let (key, csr) = generate_csr().expect("csr");
    let other = lab
        .ca
        .issue_node_cert_for(
            node,
            [Role::Controller].into_iter().collect(),
            &csr,
            tenko_core::Timestamp::now(),
        )
        .expect("a second certificate");
    let serials = lab
        .first
        .registry
        .revoke(&system(), node)
        .await
        .expect("revoke");
    assert!(!serials.contains(&other.info.serial));
    // The call goes to another member, which learned of the revocation by replication.
    let second = lab
        .members()
        .into_iter()
        .find(|member| member.node() != NodeId(1))
        .expect("another member");
    wait_until_async("the revocation to reach the other member", async || {
        second.registry.is_revoked_node(node)
    })
    .await;

    let network = PeerNetwork::new(node, PeerTimings::default());
    network.set_tls(
        tenko_cluster::mtls::client_config(lab.ca.root_der(), other.chain.clone(), &key)
            .expect("config"),
    );
    let channel = network
        .channel(&second.addr.to_string())
        .await
        .expect("the certificate passes the handshake");
    let refused = v1::raft_client::RaftClient::new(channel)
        .vote(v1::RaftRequest::default())
        .await
        .expect_err("a revoked controller may not vote");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{refused:?}");
    assert_eq!(code_of(&refused), Some("cluster.node.unknown"));
    lab.stop().await;
}

/// Calls `Raft.Vote` on `addr` as `node` with `chain` and `key`: the refusal's code, or
/// `None` when the connection itself was refused (the TLS handshake, or the first call
/// after it in TLS 1.3). Panics when the call is accepted.
async fn raft_vote_refusal(
    lab: &Lab,
    node: NodeId,
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: &SecretBytes,
    addr: SocketAddr,
    what: &str,
) -> Option<String> {
    let network = PeerNetwork::new(node, PeerTimings::default());
    network.set_tls(
        tenko_cluster::mtls::client_config(lab.ca.root_der(), chain, key).expect("config"),
    );
    let Ok(channel) = network.channel(&addr.to_string()).await else {
        return None;
    };
    match v1::raft_client::RaftClient::new(channel)
        .vote(v1::RaftRequest::default())
        .await
    {
        Ok(_) => panic!("{what}: a removed controller's vote was taken on {addr}"),
        Err(status) => code_of(&status).map(str::to_owned),
    }
}

/// A controller removed from the cluster is refused with every certificate it was issued,
/// on every member that stays: the one it runs with and one a renewal issued before the
/// removal are on the revocation list and fail the handshake; a certificate of it that its
/// record never held passes the handshake and is refused before Raft sees the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_controller_is_refused_with_every_certificate() {
    // Twenty-day certificates are due for renewal at once.
    let lab = Lab::three_with(
        &no_change,
        CaPolicy {
            node_validity_days: 20,
            ..CaPolicy::default()
        },
    )
    .await;
    let leader = lab.leader().await;
    let target = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node() && member.node() != NodeId(1))
        .expect("a joined member that is not the leader");
    let node = target.node();
    let staying: Vec<Arc<Member>> = lab
        .members()
        .into_iter()
        .filter(|member| member.node() != node)
        .collect();

    // The certificate it runs with, and one a renewal issued before the removal.
    let (running_chain, running_key) = target.identity.clone();
    let running = tenko_cluster::ca::CertInfo::from_der(&running_chain[0]).expect("info");
    let (renewed_key, csr) = generate_csr().expect("csr");
    let renewed = lab
        .first
        .registry
        .renew(node, &running.serial, &csr, tenko_core::Timestamp::now())
        .await
        .expect("a renewal before the removal");
    // A certificate of the controller that its record never held.
    let (stray_key, csr) = generate_csr().expect("csr");
    let stray = lab
        .ca
        .issue_node_cert_for(
            node,
            [Role::Controller].into_iter().collect(),
            &csr,
            tenko_core::Timestamp::now(),
        )
        .expect("a certificate outside the record");

    leader
        .peers
        .remove(&system(), node, false)
        .await
        .expect("the removal");
    for member in &staying {
        wait_until_async(
            &format!("the revocation to reach member {}", member.node()),
            async || {
                member.registry.revocations().is_revoked(&running.serial)
                    && member
                        .registry
                        .revocations()
                        .is_revoked(&renewed.info.serial)
                    && member.registry.is_revoked_node(node)
            },
        )
        .await;
    }
    assert!(
        !lab.first
            .registry
            .revocations()
            .is_revoked(&stray.info.serial)
    );

    // Each certificate with the refusal it gets: `None` for the handshake.
    let cases = [
        (
            "the certificate it runs with",
            running_chain,
            running_key,
            None,
        ),
        ("the renewed certificate", renewed.chain, renewed_key, None),
        (
            "the certificate outside the record",
            stray.chain,
            stray_key,
            Some("cluster.node.unknown"),
        ),
    ];
    for member in &staying {
        for (what, chain, key, expected) in &cases {
            let refused =
                raft_vote_refusal(&lab, node, chain.clone(), key, member.addr, what).await;
            assert_eq!(
                refused.as_deref(),
                *expected,
                "{what} on member {}",
                member.node()
            );
        }
    }
    lab.stop().await;
}

/// A learner that joins after the leader purged its log installs a snapshot streamed over
/// mutual TLS, with its digest checked, and replicates by log afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_learner_catches_up_by_a_snapshot_over_the_cluster_port() {
    let purge = |config: &mut RaftStoreConfig| {
        config.snapshot = SnapshotPolicy {
            every_entries: u64::MAX,
            every_log_bytes: u64::MAX,
            keep_entries: 0,
        };
    };
    let lab = Lab::first(&purge).await;
    for n in 0..300_u64 {
        let mut batch = tenko_store::WriteBatch::new(
            tenko_core::Principal::system(SystemComponent::Ipam),
            tenko_core::Timestamp::now(),
        );
        batch.put(
            tenko_core::TableName::from_static("ipam.peer_rows"),
            tenko_core::codec::encode_key(&n),
            prost::bytes::Bytes::from(vec![1_u8; 512]),
        );
        lab.first.store.propose(batch).await.expect("write");
    }
    lab.first.store.snapshot_now().await.expect("snapshot");
    let snapshot = lab.first.store.raft().metrics().borrow().snapshot;
    wait_until_async("the leader purges its log", async || {
        lab.first.store.raft().metrics().borrow().purged >= snapshot
    })
    .await;
    let learner = lab.join("controller-snap", &purge).await;
    let target = lab.first.store.status().revision;
    wait_until_async("the learner installs the snapshot", async || {
        learner.store.status().revision >= target
    })
    .await;
    assert_eq!(learner.store.engine_stats().snapshots_installed, 1);
    let digests = lab
        .first
        .peers
        .digests(Some(target))
        .await
        .expect("digests");
    assert!(digests.agree, "{digests:?}");
    assert_eq!(learner.store.status().role, StoreRole::Learner);
    lab.stop().await;
}

/// The keys go to a joining controller once per enrollment token, audited; a member change
/// asked of a follower runs on the leader; step-down moves leadership.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_transfer_forwarded_changes_and_step_down() {
    let lab = Lab::three(&no_change).await;
    let (node, chain, key, token) = lab.enroll_controller("controller-four").await;
    let network = PeerNetwork::new(node, PeerTimings::default());
    network.set_tls(
        tenko_cluster::mtls::client_config(lab.ca.root_der(), chain, &key).expect("config"),
    );
    let mut client = network
        .cluster_client_at(&lab.first.addr.to_string())
        .await
        .expect("channel");
    let request = v1::TransferKekRequest {
        ephemeral_public_key: vec![9; 32],
        join_token_id: token.to_string(),
    };
    let answer = client
        .transfer_kek(request.clone())
        .await
        .expect("the keys")
        .into_inner();
    assert_eq!(answer.format, "test-echo");
    assert_eq!(answer.generation_ids, vec!["kek-test-1".to_owned()]);
    let again = client
        .transfer_kek(request)
        .await
        .expect_err("a second transfer with the same token");
    assert_eq!(code_of(&again), Some("vault.kek.transfer.used"));
    // Audited once, for the transfer that happened: the node, its enrollment token and the
    // generation identifiers, never the sealed material.
    let leader = lab.leader().await;
    let view = leader
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("the leader reads");
    let transfers: Vec<_> = view
        .scan_typed(&tenko_store::tables::AUDIT, KeyRange::all(), 100_000, false)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .filter(|record| record.draft.action.as_str() == "vault.kek.transfer")
        .collect();
    drop(view);
    assert_eq!(transfers.len(), 1, "{transfers:?}");
    let record = &transfers[0];
    let context = &record.draft.details.context;
    let field = |name: &str| context.get(name).map(String::as_str);
    assert_eq!(field("purpose"), Some("join"));
    assert_eq!(field("generations"), Some("kek-test-1"));
    assert_eq!(field("node"), Some(node.to_string().as_str()));
    assert_eq!(field("enrollment"), Some(token.to_string().as_str()));
    assert_eq!(
        record.draft.objects,
        vec![tenko_core::ObjectRef::node(node)],
        "the record names the controller that received the keys"
    );
    assert_eq!(
        context.keys().map(String::as_str).collect::<Vec<_>>(),
        ["enrollment", "generations", "node", "purpose"],
        "nothing but the identifiers"
    );

    // Removal asked of a follower runs on the leader; the removed controller's
    // certificates are revoked.
    let follower = lab.follower().await;
    let leader = lab.leader().await;
    let target = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node() && member.node() != follower.node())
        .expect("the third member");
    let view = follower
        .peers
        .remove(&system(), target.node(), false)
        .await
        .expect("removal through a follower");
    assert_eq!(view.members.len(), 2);
    // The removal ran as an inline job on the follower that took the request.
    let job = view.job_id.expect("the job of the removal");
    let record = follower.engine.job(job).await.expect("the job is recorded");
    assert_eq!(record.spec.kind.as_str(), "cluster.edit");
    assert!(
        lab.first
            .registry
            .record(target.node())
            .await
            .expect("read")
            .is_none(),
        "the removed controller's record is gone"
    );

    // Step-down hands leadership to the other voter.
    let moved = follower
        .peers
        .step_down(&system())
        .await
        .expect("step-down");
    assert_eq!(moved.previous, leader.node());
    assert_eq!(moved.leader, follower.node());
    let read = follower
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("the new leader reads");
    drop(read);
    let _ = Path::new(".");
    lab.stop().await;
}

/// Enrolls a probe through the first controller's registry: its id and client credentials.
async fn enroll_probe(lab: &Lab, name: &str) -> (NodeId, Arc<rustls::ClientConfig>, String) {
    let (_, token) = lab
        .first
        .registry
        .create_enrollment(&system(), NewEnrollment::default())
        .await
        .expect("probe token");
    let (key, csr) = generate_csr().expect("csr");
    let probe = lab
        .first
        .registry
        .enroll(
            &system(),
            EnrollRequest {
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
        .expect("enroll a probe");
    let chain = rustls::pki_types::CertificateDer::pem_slice_iter(probe.certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("chain");
    let config =
        tenko_cluster::mtls::client_config(lab.ca.root_der(), chain, &key).expect("config");
    (probe.node.id, config, probe.certificate.info.serial.clone())
}

/// A revocation made on the leader reaches every member: their TLS verifiers refuse the
/// node within a moment, and a node that another member enrolled a moment ago is not
/// refused as unknown. `Hello` names the cluster ports of every controller.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocations_and_endpoints_reach_every_member() {
    let lab = Lab::three(&no_change).await;
    let (probe, config, serial) = enroll_probe(&lab, "probe-everywhere").await;
    let second = lab
        .members()
        .into_iter()
        .find(|member| member.node() != NodeId(1))
        .expect("another member");
    let channel = tenko_cluster::client::connect(&second.addr.to_string(), Arc::clone(&config))
        .await
        .expect("the probe reaches another member");
    let mut handshake = v1::handshake_client::HandshakeClient::new(channel.clone());
    let hello = handshake
        .hello(v1::HelloRequest {
            majors: vec![1],
            version: "0.0.1".to_owned(),
            roles: vec!["probe".to_owned()],
            capabilities: Vec::new(),
        })
        .await
        .expect("hello on another member")
        .into_inner();
    let mut endpoints = hello.endpoints.clone();
    endpoints.sort();
    let mut expected: Vec<String> = lab
        .members()
        .iter()
        .map(|member| member.addr.to_string())
        .collect();
    expected.sort();
    assert_eq!(endpoints, expected);
    assert_eq!(
        hello.endpoints[0],
        second.addr.to_string(),
        "the answering controller first"
    );
    // A stream the probe holds open on that member; this is the first revocation the
    // installation sees, so the member's revocation table was empty until now.
    let mut watch = v1::config_client::ConfigClient::new(channel)
        .watch(v1::WatchRequest { from_revision: 0 })
        .await
        .expect("watch on another member")
        .into_inner();

    lab.first
        .registry
        .revoke(&system(), probe)
        .await
        .expect("revoke on the first controller");
    wait_until_async("the revocation to reach the other member", async || {
        second.registry.revocations().is_revoked(&serial)
    })
    .await;
    // The member closes the probe's connection, and the open stream with it.
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match watch.message().await {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => return,
            }
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "the revoked probe's stream stayed open on another member"
    );
    // In TLS 1.3 the client may finish its side before the alert arrives; the first call
    // fails then.
    let answered = async {
        let channel = tenko_cluster::client::connect(&second.addr.to_string(), config)
            .await
            .ok()?;
        v1::handshake_client::HandshakeClient::new(channel)
            .hello(v1::HelloRequest {
                majors: vec![1],
                version: "0.0.1".to_owned(),
                roles: vec!["probe".to_owned()],
                capabilities: Vec::new(),
            })
            .await
            .ok()
    }
    .await;
    assert!(
        answered.is_none(),
        "another member still accepts the revoked probe"
    );
    lab.stop().await;
}

/// The connected view: a node connected to another controller of the cluster shows as
/// connected to that controller; once that controller has left, it does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_through_other_controllers_are_shown() {
    let lab = Lab::three(&no_change).await;
    let (probe, _, _) = enroll_probe(&lab, "probe-elsewhere").await;
    let second = lab
        .members()
        .into_iter()
        .find(|member| member.node() != NodeId(1))
        .expect("another member");
    let live = tenko_cluster::model::ConnectionView {
        since: tenko_core::Timestamp::now(),
        peer: Some("192.0.2.20:50000".parse().expect("address")),
        major: 1,
        version: "0.0.1".to_owned(),
        last_beat: None,
        buffered_batches: 0,
        buffered_bytes: 0,
        dropped_batches: 0,
        certificate_not_after: None,
        controller: Some(second.node()),
    };
    second
        .registry
        .record_connection(probe, &live)
        .await
        .expect("record");
    let view = wait_until_async("the connection to replicate", async || {
        let view = lab.first.registry.get_node(probe).await.expect("node");
        view.connected.then_some(view)
    })
    .await;
    assert_eq!(
        view.connection.and_then(|connection| connection.controller),
        Some(second.node())
    );
    // The first controller's own view of the node it does not hold is no session of its
    // own: clearing there changes nothing, clearing on the holder removes it.
    lab.first
        .registry
        .clear_connection(probe)
        .await
        .expect("noop");
    assert!(
        lab.first
            .registry
            .get_node(probe)
            .await
            .expect("node")
            .connected
    );
    second
        .registry
        .clear_connection(probe)
        .await
        .expect("clear");
    wait_until_async("the disconnect to replicate", async || {
        !lab.first
            .registry
            .get_node(probe)
            .await
            .expect("node")
            .connected
    })
    .await;
    lab.stop().await;
}

/// The prune as leader-only work carries the leader epoch: with another epoch it changes
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_fenced_prune_needs_the_current_epoch() {
    let store = Arc::new(tenko_store::mem::MemStore::default());
    let vault = tenko_vault::MemVault::with_store(Arc::clone(&store));
    let ca = InternalCa::load_or_init(store.as_ref(), &vault, &system(), CaPolicy::default())
        .await
        .expect("CA");
    let registry = NodeRegistry::new(
        store.clone() as Arc<dyn Store>,
        Arc::new(ca),
        RegistryConfig::new(NodeId(1)),
    );
    assert_eq!(
        registry
            .prune_fenced(tenko_core::Timestamp::now(), Some(0))
            .await
            .expect("epoch 0 holds before anyone took office"),
        0
    );
    // Nothing to prune is not a write; make one: an expired revocation.
    let mut batch = tenko_store::WriteBatch::new(
        tenko_core::Principal::system(SystemComponent::Cluster),
        tenko_core::Timestamp::now(),
    );
    batch
        .put_typed(
            &tenko_cluster::model::tables::REVOCATIONS,
            &"0a".to_owned(),
            &tenko_cluster::model::Revocation {
                node: NodeId(1005),
                revoked_at: "2025-01-01T00:00:00Z".parse().expect("time"),
                not_after: "2025-02-01T00:00:00Z".parse().expect("time"),
            },
        )
        .expect("revocation");
    batch.bump(tenko_core::cluster::LEADER_EPOCH);
    store.propose(batch).await.expect("write");
    let stale = registry
        .prune_fenced(tenko_core::Timestamp::now(), Some(0))
        .await
        .expect_err("a deposed leader's prune fails");
    assert_eq!(stale.code(), "sys.store.precondition_failed");
    assert_eq!(
        registry
            .prune_fenced(tenko_core::Timestamp::now(), Some(1))
            .await
            .expect("the current epoch prunes"),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_reports_its_binary_once_after_a_start() {
    let lab = Lab::three(&no_change).await;
    let follower = lab
        .members()
        .into_iter()
        .find(|member| member.node() != lab.first.node())
        .expect("a joined controller");
    // The voters are set before a leader is elected or known to the follower, and a write
    // needs both.
    lab.leader().await;
    wait_until_async("the follower to see the leader", async || {
        follower.store.leadership().borrow().is_some()
    })
    .await;
    // A controller that joined has a record without its binary's details until it reports
    // them at its next start.
    assert!(follower.peers.announce().await.expect("announce"));
    assert!(!follower.peers.announce().await.expect("unchanged"));
    let leader = lab.leader().await;
    let view = leader.peers.view().await.expect("view");
    let member = view
        .members
        .iter()
        .find(|member| member.node == follower.node())
        .expect("the follower");
    assert_eq!(
        member.protocol_majors,
        tenko_cluster::version::SUPPORTED_MAJORS.to_vec()
    );
    assert_eq!(member.raft_wire.as_deref(), Some("openraft-0.9/cbor-1"));
    assert_eq!(
        member.formats,
        (1..=member.data_format.expect("format")).collect::<Vec<_>>()
    );
}

/// The subscriber of this test process: the spans of Tenko's crates go to memory, with the
/// W3C propagator, as `tenko serve` sets them up with an OTLP endpoint.
fn in_memory_traces() -> opentelemetry_sdk::trace::InMemorySpanExporter {
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::{Layer as _, filter::filter_fn, layer::SubscriberExt as _};

    let exporter = opentelemetry_sdk::trace::InMemorySpanExporter::default();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
    let layer = tracing_opentelemetry::layer()
        .with_tracer(provider.tracer("test"))
        .with_filter(filter_fn(|metadata| metadata.target().starts_with("tenko")));
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
        .expect("the only subscriber of this test process");
    exporter
}

/// The finished spans named `name`, waiting until `ready` holds for them.
async fn finished(
    exporter: &opentelemetry_sdk::trace::InMemorySpanExporter,
    name: &str,
    ready: impl Fn(&[opentelemetry_sdk::trace::SpanData]) -> bool,
) -> Vec<opentelemetry_sdk::trace::SpanData> {
    wait_until_async(&format!("a matching span {name}"), async || {
        let spans: Vec<_> = exporter
            .get_finished_spans()
            .expect("the finished spans")
            .into_iter()
            .filter(|span| span.name == name)
            .collect();
        ready(&spans).then_some(spans)
    })
    .await
}

fn attribute(span: &opentelemetry_sdk::trace::SpanData, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|attribute| attribute.key.as_str() == key)
        .map(|attribute| attribute.value.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_members_call_continues_the_trace_of_its_caller() {
    use opentelemetry::trace::{SpanId, TraceContextExt as _, TraceId};
    use tracing::Instrument as _;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    let exporter = in_memory_traces();
    let lab = Lab::first(&no_change).await;
    let second = lab.join("controller-two", &no_change).await;
    let mut client = second
        .peers
        .network()
        .cluster_client(NodeId(1))
        .await
        .expect("a channel to the first controller");

    // A `traceparent` put into the metadata by hand: the server span is its child.
    let trace_id = "0af7651916cd43dd8448eb211c80319c";
    let parent = "b7ad6b7169203331";
    let mut request = tonic::Request::new(v1::MembersRequest {});
    request.metadata_mut().insert(
        "traceparent",
        format!("00-{trace_id}-{parent}-01")
            .parse()
            .expect("metadata"),
    );
    client.members(request).await.expect("members");
    let served = finished(&exporter, "tenko.cluster.request", |spans| {
        spans
            .iter()
            .any(|span| span.span_context.trace_id() == TraceId::from_hex(trace_id).expect("id"))
    })
    .await;
    let request_span = served
        .iter()
        .find(|span| span.span_context.trace_id() == TraceId::from_hex(trace_id).expect("id"))
        .expect("the server span of the call");
    assert_eq!(
        request_span.parent_span_id,
        SpanId::from_hex(parent).expect("span id")
    );
    assert_eq!(
        attribute(request_span, "rpc.service").as_deref(),
        Some("tenko.cluster.v1.Cluster")
    );
    assert_eq!(
        attribute(request_span, "rpc.method").as_deref(),
        Some("Members")
    );
    assert_eq!(
        attribute(request_span, "rpc.system").as_deref(),
        Some("grpc")
    );
    assert_eq!(
        attribute(request_span, "tenko.cluster.peer"),
        Some(second.node().0.to_string())
    );
    assert_eq!(
        attribute(request_span, "rpc.grpc.status_code").as_deref(),
        Some("0")
    );

    // Through the client helpers: the server span is a child of the client span, which is
    // a child of the caller's span.
    let caller = tracing::info_span!(target: "tenko::test", "caller");
    let caller_ids = caller.context().span().span_context().clone();
    tenko_cluster::trace::rpc(
        Some(NodeId(1)),
        tenko_cluster::trace::CLUSTER,
        "Members",
        async {
            let mut request = tonic::Request::new(v1::MembersRequest {});
            tenko_cluster::trace::inject(&mut request);
            client.members(request).await
        },
    )
    .instrument(caller.clone())
    .await
    .expect("members through the helpers");
    drop(caller);
    let rpc = finished(&exporter, "tenko.cluster.rpc", |spans| {
        spans
            .iter()
            .any(|span| span.span_context.trace_id() == caller_ids.trace_id())
    })
    .await
    .into_iter()
    .find(|span| span.span_context.trace_id() == caller_ids.trace_id())
    .expect("the client span");
    assert_eq!(rpc.parent_span_id, caller_ids.span_id());
    assert_eq!(attribute(&rpc, "tenko.cluster.peer").as_deref(), Some("1"));
    let child = finished(&exporter, "tenko.cluster.request", |spans| {
        spans
            .iter()
            .any(|span| span.parent_span_id == rpc.span_context.span_id())
    })
    .await
    .into_iter()
    .find(|span| span.parent_span_id == rpc.span_context.span_id())
    .expect("the server span under the client span");
    assert_eq!(
        child.span_context.trace_id(),
        caller_ids.trace_id(),
        "the server span is in the caller's trace"
    );
    lab.stop().await;
}

/// A certificate chain with its key.
type Identity = (Vec<rustls::pki_types::CertificateDer<'static>>, SecretBytes);

/// The refusal that `member` gives each call a removed controller `node` makes with
/// `identity`: `Raft.Vote`, `Raft.AppendEntries`, `Raft.InstallSnapshot` and `Cluster.Join`.
/// Each is the refusal's code, or `None` when the connection itself was refused (the TLS
/// handshake, or the first call after it in TLS 1.3). Panics when a call is taken.
async fn calls_refused(
    lab: &Lab,
    node: NodeId,
    identity: &Identity,
    member: &Member,
) -> [Option<String>; 4] {
    let channel = async || {
        let network = PeerNetwork::new(node, PeerTimings::default());
        network.set_tls(
            tenko_cluster::mtls::client_config(lab.ca.root_der(), identity.0.clone(), &identity.1)
                .expect("config"),
        );
        network.channel(&member.addr.to_string()).await.ok()
    };
    let refusal = |what: &str, result: Result<(), tonic::Status>| match result {
        Ok(()) => panic!(
            "{what} of removed controller {node} was taken by member {}",
            member.node()
        ),
        Err(status) => code_of(&status).map(str::to_owned),
    };
    let raft = async || channel().await.map(v1::raft_client::RaftClient::new);
    let vote = match raft().await {
        None => None,
        Some(mut client) => refusal(
            "a vote",
            client.vote(v1::RaftRequest::default()).await.map(drop),
        ),
    };
    let append = match raft().await {
        None => None,
        Some(mut client) => refusal(
            "an append",
            client
                .append_entries(v1::RaftRequest::default())
                .await
                .map(drop),
        ),
    };
    let snapshot = match raft().await {
        None => None,
        Some(mut client) => refusal(
            "a snapshot",
            client
                .install_snapshot(futures::stream::iter([v1::SnapshotChunk::default()]))
                .await
                .map(drop),
        ),
    };
    let join = match channel().await {
        None => None,
        Some(channel) => refusal(
            "a join",
            v1::cluster_client::ClusterClient::new(channel)
                .join(v1::JoinRequest {
                    node_id: node.0,
                    address: "127.0.0.1:9".to_owned(),
                    version: "0.0.1".to_owned(),
                    capabilities: Vec::new(),
                    data_format: 2,
                })
                .await
                .map(drop),
        ),
    };
    [vote, append, snapshot, join]
}

/// What a removed controller gets from a member: nothing with the certificate it ran with
/// (the handshake fails), and the refusal of the services with a certificate its record
/// never held, which passes the handshake and so shows that the member is reachable.
async fn assert_cut_off(lab: &Lab, node: NodeId, running: &Identity, member: &Member) {
    assert_eq!(
        calls_refused(lab, node, running, member).await,
        [None, None, None, None],
        "the certificate it ran with, on member {}",
        member.node()
    );
    let unknown = Some("cluster.node.unknown".to_owned());
    assert_eq!(
        calls_refused(lab, node, &stray_certificate(lab, node), member).await,
        [
            unknown.clone(),
            unknown.clone(),
            unknown,
            Some("cluster.join.not_controller".to_owned())
        ],
        "a certificate outside its record, on member {}",
        member.node()
    );
}

/// A certificate of `node` that its record never held: it passes the handshake, so the
/// refusal comes from the services themselves.
fn stray_certificate(lab: &Lab, node: NodeId) -> Identity {
    let (key, csr) = generate_csr().expect("csr");
    let stray = lab
        .ca
        .issue_node_cert_for(
            node,
            [Role::Controller].into_iter().collect(),
            &csr,
            tenko_core::Timestamp::now(),
        )
        .expect("a certificate outside the record");
    (stray.chain, key)
}

/// Whether `member` has `node` neither in its Raft group nor among its member records.
async fn gone_from(member: &Member, node: NodeId) -> bool {
    let membership = member.store.membership();
    if membership.voters.contains(&node) || membership.learners.contains(&node) {
        return false;
    }
    let view = member
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    view.get_typed(&tenko_cluster::model::tables::MEMBERS, &node.0)
        .expect("member record")
        .is_none()
}

/// Waits until every one of `members` has applied the revocation of `node`.
async fn wait_revoked_on(members: &[Arc<Member>], node: NodeId) {
    for member in members {
        wait_until_async(
            &format!("the revocation to reach member {}", member.node()),
            async || member.registry.is_revoked_node(node),
        )
        .await;
    }
}

/// Whether `from` sends Raft messages to `to`: a vote request of term 0 through `from`'s
/// transport, which `to` answers without changing anything. The error text when not.
async fn sends_raft(from: &Member, to: &Member) -> Result<(), String> {
    use tenko_store::raft::network::PeerTransport as _;
    let vote = tenko_store::raft::openraft::Vote::new(0, from.node().0);
    from.peers
        .network()
        .vote(
            to.node().0,
            &tenko_store::raft::openraft::BasicNode::new(to.addr.to_string()),
            tenko_store::raft::openraft::raft::VoteRequest::new(vote, None),
        )
        .await
        .map(drop)
        .map_err(|error| error.to_string())
}

/// Cuts `member` off from every other member of `lab`, both ways (`cut`), or joins it
/// again.
fn set_cut(lab: &Lab, member: &Member, cut: bool) {
    let closed = format!("127.0.0.1:{}", free_port().release());
    for other in lab.members() {
        if other.node() == member.node() {
            continue;
        }
        let (to_member, to_other) = if cut {
            (closed.clone(), closed.clone())
        } else {
            (member.addr.to_string(), other.addr.to_string())
        };
        other.peers.network().pin(member.node(), to_member);
        member.peers.network().pin(other.node(), to_other);
    }
}

/// A write through `member`'s store commits.
async fn write_commits(member: &Member, n: u64) {
    let mut batch = WriteBatch::new(
        tenko_core::Principal::system(SystemComponent::Ipam),
        tenko_core::Timestamp::now(),
    );
    batch.put(
        TableName::from_static("ipam.peer_rows"),
        tenko_core::codec::encode_key(&n),
        prost::bytes::Bytes::from(vec![1_u8; 16]),
    );
    member.store.propose(batch).await.expect("a write commits");
}

/// The first controller and one that joined, both voters.
async fn two_voters() -> (Lab, Arc<Member>) {
    let lab = Lab::first(&no_change).await;
    let second = lab.join("controller-two", &no_change).await;
    lab.first
        .peers
        .promote(
            &system(),
            second.node(),
            PromoteRequest {
                force: true,
                replace: None,
            },
        )
        .await
        .expect("two voters");
    (lab, second)
}

/// A removal whose revocation fails is not reported as done and changes nothing: the
/// controller stays a voter, keeps its records and is still trusted. Done again once the
/// revocation can be written, the removal completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_that_cannot_revoke_changes_nothing() {
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let target = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node() && member.node() != NodeId(1))
        .expect("a joined member that is not the leader");
    let node = target.node();
    // Every revocation loses its race, as against a renewal that wins three times.
    for member in lab.members() {
        member.writes.refuse(true);
    }
    let refused = leader
        .peers
        .remove(&system(), node, false)
        .await
        .expect_err("a removal whose revocation fails");
    assert_eq!(refused.code(), "cluster.member.not_revoked", "{refused}");
    assert_eq!(refused.status(), 409);
    let params = &refused.as_coded().params;
    assert_eq!(
        params.get("cause").map(String::as_str),
        Some("cluster.node.conflict")
    );
    assert_eq!(params.get("node"), Some(&node.0.to_string()));
    // Nothing changed.
    assert!(leader.store.membership().voters.contains(&node));
    assert!(!gone_from(&leader, node).await);
    assert!(
        leader.registry.record(node).await.expect("read").is_some(),
        "the node record stays"
    );
    assert!(!leader.registry.is_revoked_node(node));
    let view = leader.peers.view().await.expect("view");
    let member = view
        .members
        .iter()
        .find(|member| member.node == node)
        .expect("still a member");
    assert!(!member.revoked);

    for member in lab.members() {
        member.writes.refuse(false);
    }
    let view = leader
        .peers
        .remove(&system(), node, false)
        .await
        .expect("the removal once the revocation can be written");
    assert!(view.members.iter().all(|member| member.node != node));
    assert!(leader.registry.is_revoked_node(node));
    lab.stop().await;
}

/// A controller that is a member of the cluster is not revoked through the registry: it
/// leaves through its removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_is_not_revoked_outside_its_removal() {
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    for member in lab.members() {
        let refused = leader
            .registry
            .revoke(&system(), member.node())
            .await
            .expect_err("a member revoked through the registry");
        assert_eq!(refused.code(), "cluster.node.is_member");
        assert_eq!(refused.status(), 409);
        assert!(!leader.registry.is_revoked_node(member.node()));
    }
    lab.stop().await;
}

/// After a removal, no member accepts a vote, an append, a snapshot or a join from the
/// removed controller's identity. A member that was out of contact during the removal is
/// named in the answer (`propagate`), and once it is back it refuses the controller too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_controller_is_refused_by_every_member_even_one_that_was_away() {
    let lab = Lab::three(&no_change).await;
    // A fourth controller, a learner beside three voters: it is cut off during the removal.
    let away = lab.join("controller-away", &no_change).await;
    let leader = lab.leader().await;
    let target = lab
        .members()
        .into_iter()
        .find(|member| ![leader.node(), NodeId(1), away.node()].contains(&member.node()))
        .expect("a joined voter that is not the leader");
    let node = target.node();
    let present: Vec<Arc<Member>> = lab
        .members()
        .into_iter()
        .filter(|member| member.node() != node && member.node() != away.node())
        .collect();
    set_cut(&lab, &away, true);

    let pending = leader
        .peers
        .remove(&system(), node, false)
        .await
        .expect_err("a member has not received the removal");
    assert_eq!(pending.code(), "cluster.member.remove_pending", "{pending}");
    let params = &pending.as_coded().params;
    assert_eq!(params.get("pending").map(String::as_str), Some("propagate"));
    assert_eq!(params.get("members"), Some(&away.node().0.to_string()));
    assert!(gone_from(&leader, node).await);
    assert!(
        !away.registry.is_revoked_node(node),
        "the member away has not heard of the removal"
    );
    wait_revoked_on(&present, node).await;
    for member in &present {
        assert_cut_off(&lab, node, &target.identity, member).await;
    }

    set_cut(&lab, &away, false);
    wait_until_async("the member that was away applies the removal", async || {
        away.registry.is_revoked_node(node) && gone_from(&away, node).await
    })
    .await;
    assert_cut_off(&lab, node, &target.identity, &away).await;
    lab.stop().await;
}

/// A revoked learner gets no Raft message from the leader: it is never needed for a quorum.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_learner_gets_no_raft_message() {
    let lab = Lab::three(&no_change).await;
    let learner = lab.join("controller-learner", &no_change).await;
    let leader = lab.leader().await;
    sends_raft(&leader, &learner)
        .await
        .expect("a learner gets Raft messages");
    leader
        .peers
        .remove(&system(), learner.node(), false)
        .await
        .expect("the removal");
    let refused = sends_raft(&leader, &learner)
        .await
        .expect_err("a revoked learner gets no Raft message");
    assert!(refused.contains("revoked"), "{refused}");
    lab.stop().await;
}

/// Case 1, two voters: the removed one is needed for the change that takes it out, so it is
/// still sent to until the change commits; the removal completes and writes go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_voters_remove_one_and_keep_writing() {
    let (lab, _) = two_voters().await;
    let leader = lab.leader().await;
    let target = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node())
        .expect("the other voter");
    let view = leader
        .peers
        .remove(&system(), target.node(), false)
        .await
        .expect("the removal of one of two voters");
    assert_eq!(
        view.members
            .iter()
            .map(|member| member.node)
            .collect::<Vec<_>>(),
        [leader.node()]
    );
    write_commits(&leader, 1).await;
    assert_cut_off(&lab, target.node(), &target.identity, &leader).await;
    lab.stop().await;
}

/// Case 2, three voters with one out of contact: the removal of another would leave the
/// leader without a quorum once it stops sending to the revoked voter, so it is refused
/// and changes nothing. Forced, the controller is revoked and refused at once, the view
/// marks it, and the removal is finished when the absent voter is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_that_would_stop_the_writes_needs_force() {
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let others: Vec<Arc<Member>> = lab
        .members()
        .into_iter()
        .filter(|member| member.node() != leader.node())
        .collect();
    let (target, absent) = (&others[0], &others[1]);
    let node = target.node();
    set_cut(&lab, absent, true);
    wait_until_async("the leader sees the voter out of contact", async || {
        leader.store.status().members.iter().any(|member| {
            member.node == absent.node()
                && member
                    .last_contact_ms
                    .is_none_or(|ms| Duration::from_millis(ms) > CONTACT_WINDOW)
        })
    })
    .await;
    let refused = leader
        .peers
        .remove(&system(), node, false)
        .await
        .expect_err("a removal that stops the writes");
    assert_eq!(refused.code(), "cluster.member.stops_writes", "{refused}");
    assert_eq!(refused.status(), 409);
    assert_eq!(
        refused.as_coded().params.get("members"),
        Some(&absent.node().0.to_string())
    );
    assert!(!leader.registry.is_revoked_node(node), "nothing changed");
    assert!(leader.store.membership().voters.contains(&node));

    let removal = tokio::spawn({
        let peers = leader.peers.clone();
        async move { peers.remove(&system(), node, true).await }
    });
    wait_until_async("the cluster view marks the member revoked", async || {
        leader.peers.view().await.ok().and_then(|view| {
            view.members
                .into_iter()
                .find(|member| member.node == node && member.revoked)
        })
    })
    .await;
    let refused = sends_raft(&leader, target)
        .await
        .expect_err("the revoked voter gets no Raft message");
    assert!(refused.contains("revoked"), "{refused}");
    set_cut(&lab, absent, false);
    match removal.await.expect("the removal task") {
        Ok(view) => assert!(view.members.iter().all(|member| member.node != node)),
        Err(error) => {
            assert_eq!(error.code(), "cluster.member.remove_pending", "{error}");
            assert_eq!(
                error.as_coded().params.get("done").map(String::as_str),
                Some("revoke")
            );
        }
    }
    for member in [&leader, absent] {
        wait_until_async("the removal is finished", async || {
            gone_from(member, node).await
        })
        .await;
    }
    write_commits(&*lab.leader().await, 1).await;
    lab.stop().await;
}

/// Case 3, the leader: it cannot remove itself; after a step-down the new leader removes
/// it, with three voters and with two.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_leader_is_removed_after_a_step_down() {
    for voters in [3, 2] {
        let lab = if voters == 3 {
            Lab::three(&no_change).await
        } else {
            two_voters().await.0
        };
        let old = lab.leader().await;
        let refused = old
            .peers
            .remove(&system(), old.node(), false)
            .await
            .expect_err("the leader removes itself");
        assert_eq!(refused.code(), "cluster.member.is_leader");
        let moved = old.peers.step_down(&system()).await.expect("step-down");
        let new = lab
            .members()
            .into_iter()
            .find(|member| member.node() == moved.leader)
            .expect("the new leader");
        let view = new
            .peers
            .remove(&system(), old.node(), false)
            .await
            .expect("the old leader's removal");
        assert_eq!(view.members.len(), voters - 1, "{voters} voters");
        write_commits(&new, 1).await;
        assert_cut_off(&lab, old.node(), &old.identity, &new).await;
        lab.stop().await;
    }
}

/// The prune that loses the race for one of its rows (a token deleted while it planned)
/// fails nothing: only the fence's failure means that another controller took office.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_prune_that_loses_a_row_race_is_not_a_lost_office() {
    let mem = Arc::new(tenko_store::mem::MemStore::default());
    let vault = tenko_vault::MemVault::with_store(Arc::clone(&mem));
    let ca = InternalCa::load_or_init(mem.as_ref(), &vault, &system(), CaPolicy::default())
        .await
        .expect("CA");
    let store = Arc::new(Interposed::new(
        (*mem).clone(),
        tenko_cluster::model::tables::ENROLLMENTS.name(),
    ));
    let registry = NodeRegistry::new(
        Arc::clone(&store) as Arc<dyn Store>,
        Arc::new(ca),
        RegistryConfig::new(NodeId(1)),
    );
    let (token, _) = registry
        .create_enrollment(&system(), NewEnrollment::default())
        .await
        .expect("a token");
    // Eight days on, the token expired a week ago and goes; an administrator deletes it
    // while the prune plans.
    let later = tenko_core::Timestamp::now()
        .checked_add(Duration::from_secs(8 * 24 * 3600))
        .expect("eight days on");
    let mut delete = WriteBatch::new(
        tenko_core::Principal::system(SystemComponent::Cluster),
        tenko_core::Timestamp::now(),
    );
    delete.delete_typed(&tenko_cluster::model::tables::ENROLLMENTS, &token.id);
    store.before_next(delete);
    assert_eq!(
        registry
            .prune_fenced(later, Some(0))
            .await
            .expect("a row that changed is no lost office"),
        0
    );
    assert_eq!(
        registry
            .prune_fenced(later, Some(0))
            .await
            .expect("the next pass"),
        0
    );
}
