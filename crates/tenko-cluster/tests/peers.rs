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
    /// Its data directory: where a fence is kept.
    data: tenko_core::testing::TempDir,
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
    let data = tenko_core::testing::TempDir::new("member");
    let mut config = PeerConfig::new(node, 2);
    config.address = addr.to_string();
    config.data_dir = Some(data.path().to_path_buf());
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
        data,
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
        let answer = client
            .join(v1::JoinRequest {
                node_id: node.0,
                address: member.addr.to_string(),
                version: "0.0.1".to_owned(),
                capabilities: Vec::new(),
                data_format: 2,
            })
            .await
            .expect("join")
            .into_inner();
        // As `tenko cluster join` does: the empty store takes its first copy only from a
        // voter the answer names.
        member.peers.seed_from(&answer);
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
        // On every member, and settled: a follower may still be applying the last change.
        wait_until_async("three voters on every member", async || {
            lab.members().iter().all(|member| {
                let membership = member.store.membership();
                membership.voters.len() == 3 && !membership.changing
            })
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
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture reads best as one sequence"
    )]
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
        // What a join answer gives a learner: the voter it takes its first copy from.
        let seeds = v1::JoinResponse {
            leader_id: 1,
            term: 0,
            members: Vec::new(),
            voter_serials: vec![v1::VoterSerial {
                node_id: 1,
                serial: records[0].1.serial.clone(),
                sha256: records[0].1.sha256.clone(),
            }],
        };
        for member in &members[1..] {
            member.peers.seed_from(&seeds);
        }
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
/// and one caught-up learner wait for the second learner); everything replicates, a
/// follower's write is forwarded except to the generation tables, and the members agree on
/// the state digest.
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
    // Only a forced step writes the generation tables, on its own store: the leader refuses
    // a forwarded write of either.
    for table in [
        tenko_cluster::generation::GENERATION.name(),
        tenko_cluster::generation::SUPERSEDED.name(),
    ] {
        let mut batch = WriteBatch::new(
            tenko_core::Principal::system(SystemComponent::Cluster),
            tenko_core::Timestamp::now(),
        );
        batch.delete(table.clone(), prost::bytes::Bytes::from_static(b"k"));
        let refused = follower.store.propose(batch).await.expect_err("refused");
        assert!(
            matches!(&refused, StoreError::ReservedTable { table: named } if named == table),
            "{refused:?}"
        );
    }
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
        .seed_channel(&lab.first.addr.to_string())
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
        .seed_channel(&second.addr.to_string())
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
    let Ok(channel) = network.seed_channel(&addr.to_string()).await else {
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
/// removal are on the revocation list and pass the handshake marked, so that every method
/// of every service on the port refuses them, one by one, and only the generation records
/// a call carries are taken; a certificate of it that its record never held is refused
/// before Raft sees the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "every certificate of one removed controller, on every member, in order"
)]
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

    // Each certificate with the refusal it gets.
    let cases = [
        (
            "the certificate it runs with",
            running_chain,
            running_key,
            Some("cluster.peer.revoked"),
        ),
        (
            "the renewed certificate",
            renewed.chain,
            renewed_key,
            Some("cluster.peer.revoked"),
        ),
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
        for path in EVERY_METHOD {
            let refused = call_path(&lab, &target.identity, member, path, &|_| {}).await;
            assert_eq!(
                code_of(&refused),
                Some("cluster.peer.revoked"),
                "{path} on member {}",
                member.node()
            );
        }
    }
    // The exchange: a record the revoked certificate signed stops a member's writes.
    let forged = record(1, None, node, &[], &target.identity);
    let refused = call_path(
        &lab,
        &target.identity,
        &staying[0],
        "/tenko.cluster.v1.Cluster/Members",
        &offering(std::slice::from_ref(&forged)),
    )
    .await;
    assert_eq!(
        code_of(&refused),
        Some("cluster.peer.revoked"),
        "{refused:?}"
    );
    assert!(!still_writes(&staying[0]).await, "the record was taken");
    lab.stop().await;
}

/// Every method the cluster port serves, by its gRPC path.
const EVERY_METHOD: [&str; 23] = [
    "/tenko.cluster.v1.Handshake/Hello",
    "/tenko.cluster.v1.Node/Heartbeat",
    "/tenko.cluster.v1.Node/Renew",
    "/tenko.cluster.v1.Observations/Ingest",
    "/tenko.cluster.v1.Config/Watch",
    "/tenko.cluster.v1.Config/Secrets",
    "/tenko.cluster.v1.Config/Offer",
    "/tenko.cluster.v1.Config/Report",
    "/tenko.cluster.v1.Commands/Subscribe",
    "/tenko.cluster.v1.Commands/Report",
    "/tenko.cluster.v1.Metrics/Snapshot",
    "/tenko.cluster.v1.Metrics/History",
    "/tenko.cluster.v1.Raft/AppendEntries",
    "/tenko.cluster.v1.Raft/Vote",
    "/tenko.cluster.v1.Raft/InstallSnapshot",
    "/tenko.cluster.v1.Cluster/Join",
    "/tenko.cluster.v1.Cluster/Propose",
    "/tenko.cluster.v1.Cluster/ReadIndex",
    "/tenko.cluster.v1.Cluster/Members",
    "/tenko.cluster.v1.Cluster/Digest",
    "/tenko.cluster.v1.Cluster/TransferKek",
    "/tenko.cluster.v1.Cluster/Campaign",
    "/tenko.cluster.v1.Cluster/Change",
];

/// Calls `path` on `member` as `identity` with an empty message: the refusal.
async fn call_path(
    lab: &Lab,
    identity: &Identity,
    member: &Member,
    path: &'static str,
    stamp: &(dyn Fn(&mut tonic::metadata::MetadataMap) + Sync),
) -> tonic::Status {
    let network = PeerNetwork::new(NodeId(0), PeerTimings::default());
    network.set_tls(
        tenko_cluster::mtls::client_config(lab.ca.root_der(), identity.0.clone(), &identity.1)
            .expect("config"),
    );
    let channel = network
        .seed_channel(&member.addr.to_string())
        .await
        .expect("the handshake passes");
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.expect("ready");
    let mut request = tonic::Request::new(());
    stamp(request.metadata_mut());
    grpc.unary::<(), (), _>(
        request,
        tonic::codegen::http::uri::PathAndQuery::from_static(path),
        tonic_prost::ProstCodec::default(),
    )
    .await
    .expect_err(path)
}

/// Two controllers forced on the two sides of a split, each of its own store and one CA,
/// both renewed after the fork (neither knows the other's certificate), and one revoked by
/// the other's forced step, meet over real ports: the revoked side's call, with its old
/// certificate (on the revocation list) or its renewed one (unknown), carries its record to
/// the other, whose refusal carries that side's record back. Both stop writing. A side that
/// has no CA root yet keeps writing until it has one: the record reaches it again with the
/// next call (the push repeats every ten seconds).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "two forked sides, their renewals and their meeting, in order"
)]
async fn two_forced_sides_that_renewed_and_revoked_both_stop_when_they_meet() {
    let ca_store = Arc::new(tenko_store::mem::MemStore::default());
    let ca_vault = tenko_vault::MemVault::with_store(Arc::clone(&ca_store));
    let ca = Arc::new(
        InternalCa::load_or_init(ca_store.as_ref(), &ca_vault, &system(), CaPolicy::default())
            .await
            .expect("CA"),
    );
    let roles: tenko_core::RoleSet = [Role::Controller].into_iter().collect();
    let issue = |node: u64| -> Identity {
        let issued = ca
            .issue_node_cert_with_key_for(NodeId(node), roles, tenko_core::Timestamp::now())
            .expect("certificate");
        (issued.chain, issued.key)
    };
    let mut sides = Vec::new();
    for node in [1001_u64, 1002] {
        let store = RaftStore::open_temp(store_config(node, &|config| config.bootstrap = true))
            .await
            .expect("store");
        let (chain, key) = issue(node);
        let reference =
            certificate_ref(&tenko_cluster::ca::CertInfo::from_der(&chain[0]).expect("info"));
        sides.push(Arc::new(
            start_member(
                store,
                &ca,
                chain,
                &key,
                Arc::new(FixedIdentity(reference)),
                false,
            )
            .await,
        ));
    }
    let lab = Lab {
        members: Mutex::new(sides.clone()),
        ca: Arc::clone(&ca),
        first: Arc::clone(&sides[0]),
    };
    let (a, b) = (&sides[0], &sides[1]);
    a.peers.attach_ca_root(ca.root_der().clone());
    // Each side's forced step: generation 1 forced on itself, the other superseded.
    let mut forced = Vec::new();
    for (side, other) in [(a, b), (b, a)] {
        let own = record(1, None, side.node(), &[other.node()], &side.identity);
        wait_until_async("the side's own record written", async || {
            let mut batch = WriteBatch::for_request(&system());
            batch
                .put_typed(&tenko_cluster::generation::GENERATION, &1_u64, &own)
                .expect("record");
            side.store.propose(batch).await.is_ok()
        })
        .await;
        side.peers.load_generation().await.expect("generation");
        assert!(still_writes(side).await);
        forced.push(own);
    }
    // After the fork: both renew, and the first side's step revoked the second's old one.
    let (renewed_a, renewed_b) = (issue(a.node().0), issue(b.node().0));
    let old_b = tenko_cluster::ca::CertInfo::from_der(&b.identity.0[0]).expect("info");
    a.registry.revocations().insert([old_b.serial]);
    // The first side's renewed certificate reaches the second, which cannot check the record
    // before it has the CA root, and checks it at the next call once it does.
    for root in [false, true] {
        if root {
            b.peers.attach_ca_root(lab.ca.root_der().clone());
        }
        let refused = call_path(
            &lab,
            &renewed_a,
            b,
            "/tenko.cluster.v1.Cluster/Members",
            &offering(std::slice::from_ref(&forced[0])),
        )
        .await;
        assert_eq!(
            code_of(&refused),
            Some("cluster.node.unknown"),
            "{refused:?}"
        );
        assert_eq!(still_writes(b).await, !root, "with the CA root: {root}");
    }
    // The second side calls the first with each of its certificates; each call carries its
    // record, and each refusal the first side's.
    for (what, identity, code) in [
        ("old", &b.identity, "cluster.peer.revoked"),
        ("renewed", &renewed_b, "cluster.node.unknown"),
    ] {
        let refused = call_path(
            &lab,
            identity,
            a,
            "/tenko.cluster.v1.Raft/Vote",
            &offering(std::slice::from_ref(&forced[1])),
        )
        .await;
        assert_eq!(code_of(&refused), Some(code), "{what}: {refused:?}");
        let back = tenko_cluster::generation::decode_lineage(
            &refused
                .metadata()
                .get_bin(tenko_cluster::generation::RECORD_METADATA)
                .expect("the first side's records")
                .to_bytes()
                .expect("bytes"),
        )
        .expect("a lineage");
        assert_eq!(
            back.last()
                .map(tenko_cluster::generation::GenerationRecord::hash),
            Some(forced[0].hash()),
            "{what}"
        );
    }
    for side in [a, b] {
        assert_eq!(
            side.peers
                .generation()
                .fence
                .as_ref()
                .map(|(reason, _)| *reason),
            Some(tenko_store::FenceReason::Conflict),
            "side {}",
            side.node()
        );
        assert!(!still_writes(side).await, "side {}", side.node());
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
        .seed_client(&lab.first.addr.to_string())
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
                controller: false,
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
        network.seed_channel(&member.addr.to_string()).await.ok()
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

/// What a removed controller gets from a member: the revocation with the certificate it ran
/// with (its handshake passes marked, for the exchange of generation records only), and the
/// refusal of the services with a certificate its record never held.
async fn assert_cut_off(lab: &Lab, node: NodeId, running: &Identity, member: &Member) {
    let revoked = Some("cluster.peer.revoked".to_owned());
    assert_eq!(
        calls_refused(lab, node, running, member).await,
        [revoked.clone(), revoked.clone(), revoked.clone(), revoked],
        "the certificate it ran with, on member {}",
        member.node()
    );
    let unknown = Some("cluster.node.unknown".to_owned());
    assert_eq!(
        calls_refused(lab, node, &stray_certificate(lab, node), member).await,
        [unknown.clone(), unknown.clone(), unknown.clone(), unknown],
        "a certificate outside its record, on member {}",
        member.node()
    );
}

/// The `Cluster` calls a caller with `identity` makes to `member`, beside the join of
/// [`calls_refused`]: the members, a key transfer with a join token, a forwarded write.
/// Each refusal's code, or `Ok` when a call was taken.
async fn cluster_calls(
    lab: &Lab,
    node: NodeId,
    identity: &Identity,
    member: &Member,
) -> [Result<(), Option<String>>; 3] {
    let network = PeerNetwork::new(node, PeerTimings::default());
    network.set_tls(
        tenko_cluster::mtls::client_config(lab.ca.root_der(), identity.0.clone(), &identity.1)
            .expect("config"),
    );
    let channel = network
        .seed_channel(&member.addr.to_string())
        .await
        .expect("the handshake passes");
    let code = |result: Result<(), tonic::Status>| {
        result.map_err(|status| code_of(&status).map(str::to_owned))
    };
    let mut client = v1::cluster_client::ClusterClient::new(channel);
    let members = code(client.members(v1::MembersRequest {}).await.map(drop));
    let kek = code(
        client
            .transfer_kek(v1::TransferKekRequest {
                ephemeral_public_key: vec![4; 65],
                join_token_id: uuid::Uuid::now_v7().to_string(),
            })
            .await
            .map(drop),
    );
    let propose = code(
        client
            .propose(v1::ProposeRequest {
                wire: tenko_cluster::wire::BATCH_WIRE.to_owned(),
                batch: Vec::new(),
                ..Default::default()
            })
            .await
            .map(drop),
    );
    [members, kek, propose]
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
    // The removed voter may have won an election before the absent voter applied the
    // revocation: cut off since, it still leads its old configuration and commits nothing.
    let current = wait_until_async("a remaining member to take office", async || {
        [&leader, absent]
            .into_iter()
            .find(|member| {
                member
                    .store
                    .leadership()
                    .borrow()
                    .is_some_and(|seen| seen.is_self)
            })
            .cloned()
    })
    .await;
    write_commits(&current, 1).await;
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

/// A certificate of the installation's CA that the caller's node record does not hold (one
/// minted with the CA's key) is refused on every call of the controller services, for an
/// unused node id, for an enrolled controller and for a superseded one; a renewal in
/// progress, whose record holds both certificates, is accepted with either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_certificate_its_record_does_not_hold_is_refused_on_every_call() {
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
    let member = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node())
        .expect("a follower");
    // A superseded controller keeps its record and its identity.
    let mut batch = WriteBatch::for_request(&system());
    batch
        .put_typed(
            &tenko_cluster::generation::SUPERSEDED,
            &member.node().0,
            &tenko_cluster::generation::SupersededMark {
                generation: 1,
                record: tenko_core::audit::Digest([1; 32]),
            },
        )
        .expect("mark");
    leader.store.propose(batch).await.expect("write");
    let unknown = "cluster.node.unknown";
    let not_held = "cluster.node.certificate_unknown";
    for (case, node, code) in [
        ("an unused node id", NodeId(4242), unknown),
        (
            "an enrolled, superseded controller",
            member.node(),
            not_held,
        ),
        ("the leader", leader.node(), not_held),
    ] {
        let minted = stray_certificate(&lab, node);
        for target in lab.members() {
            let expected = Some(code.to_owned());
            assert_eq!(
                calls_refused(&lab, node, &minted, &target).await,
                [
                    expected.clone(),
                    expected.clone(),
                    expected.clone(),
                    expected.clone()
                ],
                "Raft and Join with a minted certificate of {case}, on member {}",
                target.node()
            );
            assert_eq!(
                cluster_calls(&lab, node, &minted, &target).await,
                [Err(expected.clone()), Err(expected.clone()), Err(expected)],
                "Cluster calls with a minted certificate of {case}, on member {}",
                target.node()
            );
        }
    }

    // A renewal in progress: the record holds the running certificate and the renewed one.
    let running = tenko_cluster::ca::CertInfo::from_der(&member.identity.0[0]).expect("info");
    let (renewed_key, csr) = generate_csr().expect("csr");
    let renewed = leader
        .registry
        .renew(
            member.node(),
            &running.serial,
            &csr,
            tenko_core::Timestamp::now(),
        )
        .await
        .expect("a renewal");
    let renewed: Identity = (renewed.chain, renewed_key);
    for target in lab.members() {
        if target.node() == member.node() {
            continue;
        }
        wait_until_async("the renewal on every member", async || {
            target
                .registry
                .record(member.node())
                .await
                .ok()
                .flatten()
                .is_some_and(|(record, _)| record.serials.len() == 2)
        })
        .await;
        for identity in [&member.identity, &renewed] {
            let [members, _, _] = cluster_calls(&lab, member.node(), identity, &target).await;
            assert_eq!(
                members,
                Ok(()),
                "a certificate the record holds, on {}",
                target.node()
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// Generations on the cluster port.

/// Every call of both controller services that `identity` makes to `member`, each with the
/// metadata `stamp` puts on it: the name of the call and its refusal's code, `None` when it
/// was taken (or failed in the service after the checks, with no code of a refusal).
#[allow(clippy::too_many_lines, reason = "one call of each method, in order")]
async fn every_call(
    lab: &Lab,
    node: NodeId,
    identity: &Identity,
    member: &Member,
    stamp: &(dyn Fn(&mut tonic::metadata::MetadataMap) + Sync),
) -> Vec<(&'static str, Option<String>)> {
    let network = PeerNetwork::new(node, PeerTimings::default());
    network.set_tls(
        tenko_cluster::mtls::client_config(lab.ca.root_der(), identity.0.clone(), &identity.1)
            .expect("config"),
    );
    let channel = network
        .seed_channel(&member.addr.to_string())
        .await
        .expect("the handshake passes");
    macro_rules! request {
        ($message:expr) => {{
            let mut request = tonic::Request::new($message);
            stamp(request.metadata_mut());
            request
        }};
    }
    let code = |result: Result<(), tonic::Status>| {
        result
            .err()
            .and_then(|status| code_of(&status).map(str::to_owned))
    };
    let mut raft = v1::raft_client::RaftClient::new(channel.clone());
    let mut cluster = v1::cluster_client::ClusterClient::new(channel);
    vec![
        (
            "Raft.Vote",
            code(
                raft.vote(request!(v1::RaftRequest::default()))
                    .await
                    .map(drop),
            ),
        ),
        (
            "Raft.AppendEntries",
            code(
                raft.append_entries(request!(v1::RaftRequest::default()))
                    .await
                    .map(drop),
            ),
        ),
        (
            "Raft.InstallSnapshot",
            code(
                raft.install_snapshot(request!(futures::stream::iter([
                    v1::SnapshotChunk::default(),
                ])))
                .await
                .map(drop),
            ),
        ),
        (
            "Cluster.Propose",
            code(
                cluster
                    .propose(request!(v1::ProposeRequest {
                        wire: tenko_cluster::wire::BATCH_WIRE.to_owned(),
                        batch: Vec::new(),
                        ..Default::default()
                    }))
                    .await
                    .map(drop),
            ),
        ),
        (
            "Cluster.ReadIndex",
            code(
                cluster
                    .read_index(request!(v1::ReadIndexRequest {}))
                    .await
                    .map(drop),
            ),
        ),
        (
            "Cluster.Members",
            code(
                cluster
                    .members(request!(v1::MembersRequest {}))
                    .await
                    .map(drop),
            ),
        ),
        (
            "Cluster.Digest",
            code(
                cluster
                    .digest(request!(v1::DigestRequest { revision: 0 }))
                    .await
                    .map(drop),
            ),
        ),
        (
            "Cluster.TransferKek",
            code(
                cluster
                    .transfer_kek(request!(v1::TransferKekRequest {
                        ephemeral_public_key: vec![4; 65],
                        join_token_id: uuid::Uuid::now_v7().to_string(),
                    }))
                    .await
                    .map(drop),
            ),
        ),
        (
            "Cluster.Campaign",
            code(
                cluster
                    .campaign(request!(v1::CampaignRequest {}))
                    .await
                    .map(drop),
            ),
        ),
        (
            "Cluster.Change",
            code(
                cluster
                    .change(request!(v1::ChangeRequest {
                        wire: String::new(),
                        change: Vec::new(),
                    }))
                    .await
                    .map(drop),
            ),
        ),
    ]
}

/// The code of `member`'s refusal of a `Cluster.Members` call with `stamp`; `None` when it
/// was taken.
async fn members_with(
    lab: &Lab,
    identity: &Identity,
    node: NodeId,
    member: &Member,
    stamp: &(dyn Fn(&mut tonic::metadata::MetadataMap) + Sync),
) -> Option<String> {
    let network = PeerNetwork::new(node, PeerTimings::default());
    network.set_tls(
        tenko_cluster::mtls::client_config(lab.ca.root_der(), identity.0.clone(), &identity.1)
            .expect("config"),
    );
    let channel = network
        .seed_channel(&member.addr.to_string())
        .await
        .expect("the handshake passes");
    let mut request = tonic::Request::new(v1::MembersRequest {});
    stamp(request.metadata_mut());
    v1::cluster_client::ClusterClient::new(channel)
        .members(request)
        .await
        .err()
        .and_then(|status| code_of(&status).map(str::to_owned))
}

/// A generation record of `number` after `parent`, forced on `forced`, signed with
/// `identity`.
fn record(
    number: u64,
    parent: Option<tenko_core::audit::Digest>,
    forced: NodeId,
    superseded: &[NodeId],
    identity: &Identity,
) -> tenko_cluster::generation::GenerationRecord {
    use tenko_cluster::generation::{ForkPoint, GenerationBody, GenerationRecord, LAYOUT};
    let mut nonce = vec![0; 16];
    nonce[..8].copy_from_slice(&number.to_be_bytes());
    nonce[8..].copy_from_slice(&forced.0.to_be_bytes());
    GenerationRecord::sign(
        &GenerationBody {
            layout: LAYOUT,
            number,
            parent,
            forced,
            fork: ForkPoint {
                term: 1,
                leader: forced.0,
                index: 1,
                revision: tenko_core::Revision(1),
                audit: tenko_core::audit::ChainHead::default(),
            },
            superseded: superseded.to_vec(),
            at: tenko_core::Timestamp::now(),
            nonce: tenko_core::serde_util::HexBytes(nonce),
        },
        &identity.0,
        &identity.1,
    )
    .expect("sign")
}

/// Puts the claim of `records`' newest record and the records themselves on a call.
fn offering(
    records: &[tenko_cluster::generation::GenerationRecord],
) -> impl Fn(&mut tonic::metadata::MetadataMap) + Sync + use<> {
    use tenko_cluster::generation::{Claim, GENERATION_METADATA, RECORD_METADATA, encode_lineage};
    let newest = records.last().expect("a record");
    let number = newest.header().expect("header").number;
    let claim = Claim::of(number, &newest.hash()).render().expect("a claim");
    let lineage = encode_lineage(records).expect("lineage");
    move |metadata| {
        metadata.insert(GENERATION_METADATA, claim.parse().expect("ascii"));
        metadata.insert_bin(
            RECORD_METADATA,
            tonic::metadata::MetadataValue::from_bytes(&lineage),
        );
    }
}

/// Whether `member` still writes: not fenced, and a write through it commits.
async fn still_writes(member: &Member) -> bool {
    member.peers.generation().fence.is_none() && {
        let mut batch = WriteBatch::for_request(&system());
        batch.put(
            TableName::from_static("ipam.generation_test"),
            uuid::Uuid::now_v7().as_bytes().to_vec(),
            b"after the offer".to_vec(),
        );
        member.store.propose(batch).await.is_ok()
    }
}

/// A record signed with a certificate minted from the CA's key, for a node id no member
/// knows, counts like any other: the receiver stops writing and does nothing else. Its store,
/// its Raft membership and its leader stay as they were, and it follows no one; the stop
/// shows the record's claims. (A forced step on the chosen side lifts it:
/// `tenko cluster recover`, in the cluster lab.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_minted_record_stops_writes_and_does_nothing_else() {
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let receiver = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node())
        .expect("a follower");
    let membership = receiver.store.membership();
    let applied = receiver.store.applied_index().expect("applied");
    let minted = stray_certificate(&lab, NodeId(4242));
    let forged = record(1, None, NodeId(4242), &[], &minted);
    assert_eq!(
        receiver
            .peers
            .offer(std::slice::from_ref(&forged), None)
            .await
            .expect("a record of the CA counts"),
        tenko_cluster::generation::Relation::Descendant
    );
    let state = receiver.peers.generation();
    let (reason, records) = state.fence.as_ref().expect("fenced");
    assert_eq!(*reason, tenko_store::FenceReason::Superseded);
    assert_eq!(
        records.tip().map(tenko_cluster::generation::Signed::hash),
        Some(forged.hash())
    );
    assert!(!still_writes(&receiver).await);
    // Nothing taken, nothing followed: the receiver's copy and its group are its own.
    assert_eq!(receiver.store.membership(), membership);
    assert!(receiver.store.applied_index().expect("applied") >= applied);
    assert_eq!(receiver.peers.generation().lineage.number(), 0);
    assert!(
        !receiver.store.membership().voters.contains(&NodeId(4242)),
        "the forced controller of the record joined nothing"
    );
    lab.stop().await;
}

/// A follower that stops on what a leader sent keeps the fence and what it found in its
/// fence file, through the peer layer. A later record of the same rank takes over the
/// reason, in the store too, and what was found stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_store_fence_keeps_what_it_found_under_a_later_record() {
    use tenko_cluster::generation::FenceFile;
    use tenko_store::{FenceReason, raft::openraft};

    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let receiver = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node())
        .expect("a follower");
    let metrics = receiver.store.raft().metrics().borrow().clone();
    let bound = metrics.last_applied.expect("applied");
    let refused = receiver
        .store
        .handle_append_entries(openraft::raft::AppendEntriesRequest {
            vote: metrics.vote,
            prev_log_id: Some(openraft::LogId::new(
                openraft::CommittedLeaderId::new(bound.leader_id.term, 0),
                bound.index,
            )),
            entries: Vec::new(),
            leader_commit: None,
        })
        .await;
    assert!(
        matches!(
            refused,
            Err(openraft::error::RaftError::Fatal(
                openraft::error::Fatal::Stopped
            ))
        ),
        "{refused:?}"
    );
    let kept = FenceFile::load(receiver.data.path())
        .expect("load")
        .expect("the fence file");
    assert_eq!(kept.kind, FenceReason::Diverged);
    let found = kept.detail.expect("what the store found");

    let minted = stray_certificate(&lab, NodeId(4242));
    let forged = record(1, None, NodeId(4242), &[], &minted);
    receiver
        .peers
        .offer(std::slice::from_ref(&forged), None)
        .await
        .expect("a record of the CA counts");
    assert_eq!(receiver.store.fenced(), Some(FenceReason::Superseded));
    let kept = FenceFile::load(receiver.data.path())
        .expect("load")
        .expect("the fence file");
    assert_eq!(
        (kept.kind, kept.detail.as_deref()),
        (FenceReason::Superseded, Some(found.as_str()))
    );
    assert_eq!(receiver.peers.generation().found, Some(found));
    lab.stop().await;
}

/// A member of generation 1 refuses every call of a caller that speaks for generation 0
/// (no generation entry at all counts as 0) except a join, which the joining command makes
/// without one; it refuses a caller that its history superseded even when the caller
/// speaks for generation 1; and once a descendant record fenced it, the fence is on disk
/// before the refusal of the call that carried the record returns, and every call is
/// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "the generations of one cluster, in order"
)]
async fn every_call_is_refused_across_generations_and_by_a_fenced_member() {
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let members = lab.members();
    let followers: Vec<_> = members
        .iter()
        .filter(|member| member.node() != leader.node())
        .cloned()
        .collect();
    let (caller, target) = (&followers[0], &followers[1]);
    // Generation 1 of this history, signed by the leader's own certificate.
    let first = record(1, None, leader.node(), &[], &leader.identity);
    let mut batch = WriteBatch::for_request(&system());
    batch
        .put_typed(&tenko_cluster::generation::GENERATION, &1_u64, &first)
        .expect("record");
    leader.store.propose(batch).await.expect("write");
    // As after a forced step's start: every member speaks for the history it holds.
    for member in &members {
        wait_until_async("generation 1 applied", async || {
            member
                .store
                .read(ReadConsistency::Local)
                .await
                .ok()
                .and_then(|view| {
                    view.get_typed(&tenko_cluster::generation::GENERATION, &1_u64)
                        .ok()
                        .flatten()
                })
                .is_some()
        })
        .await;
    }
    // Each member loads it only once every member holds it: a member that spoke for
    // generation 1 to one that had not applied it yet would fence that one as superseded.
    for member in &members {
        member.peers.load_generation().await.expect("generation");
    }
    let gen1 = offering(std::slice::from_ref(&first));
    assert_eq!(
        members_with(&lab, &caller.identity, caller.node(), target, &gen1).await,
        None,
        "a caller of generation 1 is taken"
    );

    // Generation 0: no generation entry. The key transfer is part of a join, which the
    // joining command makes without one: it reaches the service (its token check).
    let calls = every_call(&lab, caller.node(), &caller.identity, target, &|_| {}).await;
    for (call, code) in &calls {
        let expected = if *call == "Cluster.TransferKek" {
            "vault.kek.transfer.token"
        } else {
            "cluster.superseded"
        };
        assert_eq!(code.as_deref(), Some(expected), "{call}: {calls:?}");
    }

    // A caller this history superseded, speaking for generation 1.
    let mut batch = WriteBatch::for_request(&system());
    batch
        .put_typed(
            &tenko_cluster::generation::SUPERSEDED,
            &caller.node().0,
            &tenko_cluster::generation::SupersededMark {
                generation: 1,
                record: first.hash(),
            },
        )
        .expect("mark");
    leader.store.propose(batch).await.expect("write");
    wait_until_async("the mark on the target", async || {
        members_with(&lab, &caller.identity, caller.node(), target, &gen1).await
            == Some("cluster.superseded".to_owned())
    })
    .await;
    let calls = every_call(&lab, caller.node(), &caller.identity, target, &gen1).await;
    assert!(
        calls
            .iter()
            .all(|(_, code)| code.as_deref() == Some("cluster.superseded")),
        "a superseded caller is refused on every call: {calls:?}"
    );

    // A descendant: the target fences, and the fence is on disk when the refusal returns.
    let second = record(2, Some(first.hash()), leader.node(), &[], &leader.identity);
    let fence = tenko_cluster::identity::NodePaths::new(target.data.path())
        .root()
        .join(tenko_cluster::generation::FENCE_FILE);
    assert!(!fence.exists());
    let calls = every_call(
        &lab,
        leader.node(),
        &leader.identity,
        target,
        &offering(&[first.clone(), second]),
    )
    .await;
    assert_eq!(
        calls[0].1.as_deref(),
        Some("cluster.superseded"),
        "{calls:?}"
    );
    assert!(
        fence.exists(),
        "the fence is kept before the refusal returns"
    );
    assert!(target.peers.generation().fence.is_some());
    let calls = every_call(&lab, leader.node(), &leader.identity, target, &gen1).await;
    assert!(
        calls
            .iter()
            .all(|(_, code)| code.as_deref() == Some("cluster.superseded")),
        "a fenced member refuses every call: {calls:?}"
    );
    lab.stop().await;
}

/// A joining learner's empty store takes its first copy only from a voter that its join
/// answer names, by a certificate the answer names: before the answer nobody, after it the
/// leader with its own certificate, and never a certificate minted for the leader's id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joining_learner_is_seeded_only_by_a_voter_its_answer_names() {
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let (node, chain, key, _) = lab.enroll_controller("controller-seeded").await;
    let store = RaftStore::open_temp(store_config(node.0, &no_change))
        .await
        .expect("store");
    let info = tenko_cluster::ca::CertInfo::from_der(&chain[0]).expect("info");
    let joiner = start_member(
        store,
        &lab.ca,
        chain,
        &key,
        Arc::new(FixedIdentity(certificate_ref(&info))),
        true,
    )
    .await;
    let vote = async |identity: &Identity| {
        raft_vote_refusal(
            &lab,
            leader.node(),
            identity.0.clone(),
            &identity.1,
            joiner.addr,
            "a seed",
        )
        .await
    };
    let unknown = Some("cluster.node.unknown".to_owned());
    assert_eq!(vote(&leader.identity).await, unknown, "before the answer");
    let info = tenko_cluster::ca::CertInfo::from_der(&leader.identity.0[0]).expect("info");
    joiner.peers.seed_from(&v1::JoinResponse {
        leader_id: leader.node().0,
        term: 1,
        members: Vec::new(),
        voter_serials: vec![v1::VoterSerial {
            node_id: leader.node().0,
            serial: info.serial,
            sha256: info.sha256,
        }],
    });
    assert_ne!(
        vote(&leader.identity).await,
        unknown,
        "the leader the answer names"
    );
    assert_eq!(
        vote(&stray_certificate(&lab, leader.node())).await,
        unknown,
        "a certificate minted for the leader's id"
    );
    let other = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node())
        .expect("a follower");
    assert_eq!(
        raft_vote_refusal(
            &lab,
            other.node(),
            other.identity.0.clone(),
            &other.identity.1,
            joiner.addr,
            "a seed",
        )
        .await,
        unknown,
        "a voter the answer does not name"
    );
    let _ = joiner.stop.send(true);
    lab.stop().await;
}

// ---------------------------------------------------------------------------------------
// The identity states of a controller (`tenko_cluster::peers::identity`).

/// A single controller with its key in the vault: its store, vault, registry and peer
/// layer, and the directory its identity moves to.
struct Single {
    store: RaftStore,
    vault: Arc<StoreVault>,
    registry: Arc<NodeRegistry>,
    peers: Peers,
    data: tenko_core::testing::TempDir,
    /// The serials it presented, in the order the switch saw them.
    presented: Arc<Mutex<Vec<String>>>,
}

impl Single {
    async fn start() -> Self {
        Self::start_with(CaPolicy::default()).await
    }

    /// With a CA that issues by `policy`.
    async fn start_with(policy: CaPolicy) -> Self {
        let store = RaftStore::open_temp(store_config(1, &no_change))
            .await
            .expect("store");
        let store_dyn: Arc<dyn Store> = Arc::new(store.clone());
        let ring = KekRing::new(Arc::new(MemKek::generate("kek-test-1")));
        let vault = Arc::new(
            StoreVault::open(Arc::clone(&store_dyn), ring)
                .await
                .expect("vault"),
        );
        let ca = Arc::new(
            InternalCa::load_or_init(store_dyn.as_ref(), vault.as_ref(), &system(), policy)
                .await
                .expect("CA"),
        );
        let registry = NodeRegistry::new(store_dyn, ca, RegistryConfig::new(NodeId(1)));
        registry
            .controller_identity(vault.as_ref(), &system())
            .await
            .expect("the vault's certificate");
        let data = tenko_core::testing::TempDir::new("identity");
        let mut config = PeerConfig::new(NodeId(1), 2);
        "127.0.0.1:9".clone_into(&mut config.address);
        let peers = Peers::new(
            store.clone(),
            PeerNetwork::new(NodeId(1), PeerTimings::default()),
            config,
        );
        peers.attach_registry(Arc::clone(&registry));
        let single = Self {
            store,
            vault,
            registry,
            peers,
            data,
            presented: Arc::new(Mutex::new(Vec::new())),
        };
        single.peers.attach_identity(single.identity());
        single
    }

    /// The identity of this controller's start: a new one after a restart.
    fn identity(&self) -> Arc<dyn ControllerIdentity> {
        let presented = Arc::clone(&self.presented);
        Arc::new(
            tenko_cluster::peers::VaultIdentity::new(
                Arc::clone(&self.registry),
                Arc::clone(&self.vault) as Arc<dyn tenko_vault::Vault>,
                tenko_cluster::identity::NodePaths::new(self.data.path()),
                "controller-1",
            )
            .on_switch(Box::new(move |credentials| {
                presented
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(credentials.info.serial.clone());
            })),
        )
    }

    /// A restart: the same store, vault and data directory, a new peer layer.
    fn restart(&mut self) {
        let mut config = PeerConfig::new(NodeId(1), 2);
        "127.0.0.1:9".clone_into(&mut config.address);
        self.peers = Peers::new(
            self.store.clone(),
            PeerNetwork::new(NodeId(1), PeerTimings::default()),
            config,
        );
        self.peers.attach_registry(Arc::clone(&self.registry));
        self.peers.attach_identity(self.identity());
    }

    /// The serials the node record holds, the vault's serial, whether the node counts as
    /// revoked, and the store's revision.
    async fn state(&self) -> (Vec<String>, Option<String>, bool, tenko_core::Revision) {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        let held = view
            .get_typed(&tenko_cluster::model::tables::NODES, &1_u64)
            .expect("record")
            .map(|(record, _)| record.serials.into_iter().map(|cert| cert.serial).collect())
            .unwrap_or_default();
        let revoked = tenko_cluster::registry::revoked_nodes(view.as_ref())
            .expect("revoked")
            .contains(&NodeId(1));
        let revision = view.revision();
        drop(view);
        (
            held,
            self.registry.vault_serial(NodeId(1)).await.expect("vault"),
            revoked,
            revision,
        )
    }

    fn node_local_serial(&self) -> String {
        tenko_cluster::identity::Credentials::load(&tenko_cluster::identity::NodePaths::new(
            self.data.path(),
        ))
        .expect("identity under node/")
        .info
        .serial
    }
}

/// The first join records the controller and retires its vault key in one write: no state
/// has the vault key revoked while the record is missing (the controller would count as a
/// revoked node). An interruption after the identity under `node/` was written and before
/// that write is finished by the next settle with the same identity, no new key. A repeat
/// writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_join_records_and_retires_in_one_write_and_resumes_after_a_stop() {
    let mut single = Single::start().await;
    let (held, vault, revoked, _) = single.state().await;
    assert!(held.is_empty(), "never joined: no record");
    let old = vault.expect("never joined: the vault's key");
    assert!(!revoked);

    // The identity under node/ is written and presented; the process stops before the write.
    let identity = single.identity();
    let written = identity.portable().await.expect("the identity").serial;
    assert_eq!(single.state().await.0, Vec::<String>::new());
    single.restart();

    let (_, _, _, before) = single.state().await;
    single
        .peers
        .settle_identity(&single.registry)
        .await
        .expect("settle");
    let (held, vault, revoked, after) = single.state().await;
    assert_eq!(
        held,
        vec![written.clone()],
        "the record holds the identity under node/"
    );
    assert_eq!(
        single.node_local_serial(),
        written,
        "no new key after the stop"
    );
    assert_eq!(vault, None, "the vault key is gone");
    assert!(!revoked, "the controller never counts as revoked");
    assert_eq!(after.0, before.0 + 1, "one write");
    let view = single
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    assert!(
        view.get_typed(&tenko_cluster::model::tables::REVOCATIONS, &old)
            .expect("revocation")
            .is_some(),
        "the vault's certificate is revoked"
    );
    drop(view);
    assert_eq!(
        single
            .presented
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last(),
        Some(&written),
        "the controller presents what its record holds"
    );

    single
        .peers
        .settle_identity(&single.registry)
        .await
        .expect("again");
    assert_eq!(single.state().await.3, after, "a repeat writes nothing");
}

/// A restore of a joined controller on a host without its identity under `node/` (the
/// backup's record holds the old host's serial, its vault the backup's key): the settle at
/// the start gives it a new identity, the record holds only that one, and the backup's
/// vault key is retired, in one write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_on_a_new_host_settles_to_a_new_identity_alone() {
    let mut single = Single::start().await;
    single
        .peers
        .settle_identity(&single.registry)
        .await
        .expect("joined");
    let old_host = single.node_local_serial();
    // The backup also carried a vault key (taken before its rotation).
    single
        .registry
        .controller_identity(single.vault.as_ref(), &system())
        .await
        .expect("a vault key");
    std::fs::remove_dir_all(tenko_cluster::identity::NodePaths::new(single.data.path()).root())
        .expect("a new host");
    single.restart();
    single
        .peers
        .settle_identity(&single.registry)
        .await
        .expect("settle");
    let (held, vault, revoked, _) = single.state().await;
    let new_host = single.node_local_serial();
    assert_ne!(new_host, old_host);
    assert_eq!(held, vec![new_host], "only the new identity");
    assert_eq!(vault, None);
    assert!(!revoked);
}

/// A first controller whose identity under `node/` is still the vault's key (moved before
/// keys left the vault) renews at once with the default certificate lifetime, months
/// before the renewal window; then the vault key is retired and the record holds only the
/// renewed certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_vault_key_still_in_use_is_rotated_at_once() {
    let single = Single::start().await;
    let serial = single
        .registry
        .vault_serial(NodeId(1))
        .await
        .expect("vault")
        .expect("a vault key");
    let (chain, _) = single
        .registry
        .controller_identity(single.vault.as_ref(), &system())
        .await
        .expect("the vault's certificate");
    let info = tenko_cluster::ca::CertInfo::from_der(&chain[0]).expect("info");
    // The record as such an installation wrote it: the vault's serial.
    single
        .peers
        .attach_identity(Arc::new(FixedIdentity(certificate_ref(&info))));
    let fixed = Peers::new(
        single.store.clone(),
        PeerNetwork::new(NodeId(1), PeerTimings::default()),
        {
            let mut config = PeerConfig::new(NodeId(1), 2);
            "127.0.0.1:9".clone_into(&mut config.address);
            config
        },
    );
    fixed.attach_registry(Arc::clone(&single.registry));
    fixed.attach_identity(Arc::new(FixedIdentity(certificate_ref(&info))));
    fixed
        .settle_identity(&single.registry)
        .await
        .expect("recorded");
    let (key, csr) = generate_csr().expect("csr");
    drop(key);
    let renewed = single
        .registry
        .renew(NodeId(1), &serial, &csr, tenko_core::Timestamp::now())
        .await
        .expect("a rotation is never early");
    let renewed = tenko_cluster::ca::CertInfo::from_der(&renewed.chain[0])
        .expect("info")
        .serial;
    single
        .registry
        .retire_vault_keys(single.vault.as_ref(), &system(), true, false)
        .await
        .expect("retire");
    let (held, vault, revoked, _) = single.state().await;
    assert_eq!(held, vec![renewed]);
    assert_eq!(vault, None);
    assert!(!revoked);
    // A certificate the vault never held is not rotated early.
    let (_, csr) = generate_csr().expect("csr");
    let early = single
        .registry
        .renew(NodeId(1), &held[0], &csr, tenko_core::Timestamp::now())
        .await
        .expect_err("not due");
    assert!(
        ["cluster.node.renew_not_due", "cluster.node.renew_too_soon"].contains(&early.code()),
        "{}",
        early.code()
    );
}

/// The first start's probe reads a refusal that carries another forced history as a live
/// cluster: a sibling is competing whatever certificate of the CA signed it, this history's
/// own records are not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_with_a_competing_history_is_read_as_one() {
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let other = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node())
        .expect("a follower");
    let voters: Vec<NodeId> = lab
        .members()
        .iter()
        .map(|member| member.node())
        .filter(|node| *node != leader.node())
        .collect();
    let own = record(1, None, leader.node(), &voters, &leader.identity);
    let mut batch = WriteBatch::for_request(&system());
    batch
        .put_typed(&tenko_cluster::generation::GENERATION, &1_u64, &own)
        .expect("record");
    leader.store.propose(batch).await.expect("write");
    leader.peers.load_generation().await.expect("generation");
    let refusal = |records: &[tenko_cluster::generation::GenerationRecord]| {
        let mut status = tonic::Status::failed_precondition("superseded");
        offering(records)(status.metadata_mut());
        status
    };
    let sibling = record(1, None, other.node(), &[], &other.identity);
    assert!(
        leader
            .peers
            .competing(&refusal(std::slice::from_ref(&sibling)))
            .expect("checked")
            .is_some_and(|rival| rival.contains(&other.node().to_string())),
        "a sibling of a controller this history holds"
    );
    assert_eq!(
        leader
            .peers
            .competing(&refusal(std::slice::from_ref(&own)))
            .expect("checked"),
        None,
        "this history's own record"
    );
    let minted = record(
        1,
        None,
        other.node(),
        &[],
        &stray_certificate(&lab, other.node()),
    );
    assert!(
        leader
            .peers
            .competing(&refusal(std::slice::from_ref(&minted)))
            .expect("checked")
            .is_some(),
        "a minted signer"
    );
    lab.stop().await;
}

/// A member's identity is read from `<data_dir>/node/` at every call: after a renewal its
/// record keeps the renewed certificate through a settle, even once the serial it started
/// with left the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_names_the_identity_a_renewal_put_under_node() {
    // Twenty-day certificates are due for renewal at once.
    let mut single = Single::start_with(CaPolicy {
        node_validity_days: 20,
        ..CaPolicy::default()
    })
    .await;
    single
        .peers
        .settle_identity(&single.registry)
        .await
        .expect("joined");
    let paths = tenko_cluster::identity::NodePaths::new(single.data.path());
    let started = tenko_cluster::identity::Credentials::load(&paths).expect("identity");
    let identity =
        Arc::new(tenko_cluster::peers::NodeDirIdentity::new(&started).reloading(paths.clone()));
    let (key, csr) = generate_csr().expect("csr");
    let issued = single
        .registry
        .renew(
            NodeId(1),
            &started.info.serial,
            &csr,
            tenko_core::Timestamp::now(),
        )
        .await
        .expect("a renewal");
    let renewed = started.renewed(&paths, issued.chain, key).expect("renewed");
    assert_eq!(
        identity.portable().await.expect("identity").serial,
        renewed.info.serial
    );
    // The serial it started with leaves the record (as it does once it expires).
    let (mut record, revision) = single
        .registry
        .record(NodeId(1))
        .await
        .expect("record")
        .expect("a record");
    record
        .serials
        .retain(|held| held.serial != started.info.serial);
    let mut batch = WriteBatch::for_request(&system());
    batch.expect_typed(&tenko_cluster::model::tables::NODES, &1_u64, Some(revision));
    batch
        .put_typed(&tenko_cluster::model::tables::NODES, &1_u64, &record)
        .expect("record");
    single.store.propose(batch).await.expect("write");
    single.restart();
    let member = Peers::new(
        single.store.clone(),
        PeerNetwork::new(NodeId(1), PeerTimings::default()),
        PeerConfig::new(NodeId(1), 2),
    );
    member.attach_registry(Arc::clone(&single.registry));
    member.attach_identity(identity);
    member
        .settle_identity(&single.registry)
        .await
        .expect("settle");
    assert_eq!(single.state().await.0, vec![renewed.info.serial]);
}

/// An identity under `<data_dir>/node/` that another installation's CA issued (a host
/// reused for a new installation) is not taken: the first join writes a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_foreign_identity_left_under_node_is_not_reused() {
    let single = Single::start().await;
    let other = Single::start().await;
    other
        .peers
        .settle_identity(&other.registry)
        .await
        .expect("the other installation's identity");
    let paths = tenko_cluster::identity::NodePaths::new(single.data.path());
    let foreign = tenko_cluster::identity::Credentials::load(
        &tenko_cluster::identity::NodePaths::new(other.data.path()),
    )
    .expect("identity");
    foreign.save(&paths).expect("left behind");
    single
        .peers
        .settle_identity(&single.registry)
        .await
        .expect("settle");
    let used = single.node_local_serial();
    assert_ne!(used, foreign.info.serial);
    assert_eq!(single.state().await.0, vec![used]);
}

/// The largest lineage an offer may carry passes the HTTP/2 transport of a real call (whose
/// headers both ends take up to 16 KiB by default), so a controller always hears it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offer_of_the_largest_lineage_passes_the_transport() {
    use tenko_cluster::generation::{MAX_LINEAGE_BYTES, encode_lineage};
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let follower = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node())
        .expect("a follower");
    // A member reports the log index its store applied.
    let applied = follower.store.applied_index().expect("applied");
    assert!(
        leader
            .peers
            .applied_by(follower.node())
            .await
            .expect("an answer")
            .is_some_and(|reported| reported >= applied)
    );
    let mut records = Vec::new();
    let mut parent = None;
    for number in 1..=3 {
        let next = record(number, parent, leader.node(), &[], &leader.identity);
        parent = Some(next.hash());
        records.push(next);
    }
    // Fill the budget with certificate bytes (the service checks them only when it acts).
    let mut pad = (MAX_LINEAGE_BYTES - encode_lineage(&records).expect("cbor").len()) / 2;
    let size = loop {
        for padded in records.iter_mut().skip(1) {
            padded.chain.truncate(1);
            padded
                .chain
                .push(tenko_core::serde_util::HexBytes(vec![1; pad]));
        }
        let size = encode_lineage(&records).expect("cbor").len();
        if size <= MAX_LINEAGE_BYTES {
            break size;
        }
        pad -= 8;
    };
    assert!(
        size <= MAX_LINEAGE_BYTES && size + 512 > MAX_LINEAGE_BYTES,
        "{size}"
    );
    assert!(
        members_with(
            &lab,
            &leader.identity,
            leader.node(),
            &follower,
            &offering(&records)
        )
        .await
        .is_some(),
        "the service answered the call (a refusal with its code), not the transport"
    );
    lab.stop().await;
}

/// A lineage larger than an offer may hold is offered from its newest record back, within
/// the byte bound: a caller always receives the newest record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offer_keeps_the_newest_records_within_its_byte_bound() {
    use tenko_cluster::generation::{
        GENERATION, GenerationRecord, MAX_LINEAGE_BYTES, RECORD_METADATA, decode_lineage,
        encode_lineage,
    };
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let caller = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node())
        .expect("a follower");
    let mut records = Vec::new();
    let mut parent = None;
    let mut batch = WriteBatch::for_request(&system());
    for number in 1..=3_u64 {
        let mut next = record(number, parent, leader.node(), &[], &leader.identity);
        next.chain.push(tenko_core::serde_util::HexBytes(vec![
            1;
            MAX_LINEAGE_BYTES / 3
        ]));
        parent = Some(next.hash());
        batch
            .put_typed(&GENERATION, &number, &next)
            .expect("record");
        records.push(next);
    }
    assert!(encode_lineage(&records).expect("cbor").len() > MAX_LINEAGE_BYTES);
    leader.store.propose(batch).await.expect("write");
    leader.peers.load_generation().await.expect("generation");
    let refused = call_path(
        &lab,
        &caller.identity,
        &leader,
        "/tenko.cluster.v1.Cluster/Members",
        &|_| {},
    )
    .await;
    let offered = decode_lineage(
        &refused
            .metadata()
            .get_bin(RECORD_METADATA)
            .expect("the leader's records")
            .to_bytes()
            .expect("bytes"),
    )
    .expect("within the bound");
    assert_eq!(
        offered.last().map(GenerationRecord::hash),
        Some(records[2].hash())
    );
    assert!(offered.len() < records.len(), "{}", offered.len());
    lab.stop().await;
}

/// A controller renews its cluster certificate itself; the node service that renews other
/// nodes' certificates refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_controller_cannot_renew_through_the_node_service() {
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let member = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node())
        .expect("a follower");
    let network = PeerNetwork::new(member.node(), PeerTimings::default());
    network.set_tls(
        tenko_cluster::mtls::client_config(
            lab.ca.root_der(),
            member.identity.0.clone(),
            &member.identity.1,
        )
        .expect("config"),
    );
    let channel = network
        .seed_channel(&leader.addr.to_string())
        .await
        .expect("the handshake passes");
    let (_, csr) = generate_csr().expect("csr");
    let refused = v1::node_client::NodeClient::new(channel)
        .renew(v1::RenewRequest { csr })
        .await
        .expect_err("a controller");
    assert_eq!(code_of(&refused), Some("cluster.node.controller_renewal"));
    lab.stop().await;
}

// ---------------------------------------------------------------------------------------
// The dialing side: the certificate must name the node dialed and must not be revoked.

/// A TCP relay at a fixed address whose backend a test switches; a switch ends the
/// connections relayed so far: another holder of the address.
struct Relay {
    addr: SocketAddr,
    backend: watch::Sender<SocketAddr>,
}

impl Relay {
    async fn to(backend: SocketAddr) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("address");
        let (backend, chosen) = watch::channel(backend);
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                let mut chosen = chosen.clone();
                let to = *chosen.borrow_and_update();
                tokio::spawn(async move {
                    let Ok(mut outbound) = tokio::net::TcpStream::connect(to).await else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {}
                        _ = chosen.changed() => {}
                    }
                });
            }
        });
        Self { addr, backend }
    }
}

/// A second cluster port of `member` that presents `identity` instead of its own
/// certificate: what a holder of that key answers in the member's place.
async fn impostor(lab: &Lab, member: &Member, identity: &Identity) -> SocketAddr {
    let listener = ClusterListener::bind(&["127.0.0.1:0".parse().expect("address")])
        .await
        .expect("bind");
    let addr = listener.local_addrs()[0];
    let resolver = Arc::new(TlsResolver::default());
    resolver.set(Some(
        TlsMaterial::from_der(identity.0.clone(), &identity.1, CertSource::Inline)
            .expect("material"),
    ));
    drop(
        listener
            .serve_port(
                Port {
                    ca_root: lab.ca.root_der().clone(),
                    resolver,
                    revocations: member.registry.revocations(),
                    sessions: Arc::clone(member.registry.sessions()),
                    nodes: NodeServices::ready(&tenko_cluster::server::ClusterService::new(
                        Arc::clone(&member.registry),
                        Arc::new(tenko_cluster::probe::DiscardProbes),
                    )),
                    peers: Some(member.peers.clone()),
                },
                member.stop.subscribe(),
                || {},
            )
            .expect("serve"),
    );
    addr
}

/// Revokes the certificate of `identity` without removing its node `node`, as the
/// retirement of a vault key does, through `member`'s store. Returns its serial.
async fn revoke_certificate(member: &Member, node: NodeId, identity: &Identity) -> String {
    let info = tenko_cluster::ca::CertInfo::from_der(&identity.0[0]).expect("info");
    let mut batch = WriteBatch::for_request(&system());
    batch
        .put_typed(
            &tenko_cluster::model::tables::REVOCATIONS,
            &info.serial,
            &tenko_cluster::model::Revocation {
                node,
                revoked_at: tenko_core::Timestamp::now(),
                not_after: info.not_after,
                controller: true,
            },
        )
        .expect("row");
    member.store.propose(batch).await.expect("the revocation");
    info.serial
}

/// The detail of the refusal of a `Cluster` channel from `from` to `node`; `None` when the
/// channel opens (or was open).
async fn dial_refusal(from: &Member, node: NodeId) -> Option<String> {
    let refused = from.peers.network().cluster_client(node).await.err()?;
    assert_eq!(refused.code(), "cluster.peer.unreachable", "{refused}");
    Some(refused.detail().to_owned())
}

/// Drops the channels `member` keeps: its next calls dial anew.
fn redial(lab: &Lab, member: &Member) {
    member.peers.network().set_tls(
        tenko_cluster::mtls::client_config(
            lab.ca.root_der(),
            member.identity.0.clone(),
            &member.identity.1,
        )
        .expect("config"),
    );
}

/// A forwarded write and a read index from `from` to `node`.
async fn forwards(
    from: &Member,
    node: NodeId,
) -> (
    Result<Committed, tenko_store::raft::network::ForwardError>,
    Result<tenko_store::raft::network::ReadIndex, tenko_store::raft::network::ForwardError>,
) {
    use tenko_store::raft::network::LeaderLink as _;
    let network = from.peers.network();
    let write = network
        .forward_propose(
            from.node().0,
            node.0,
            prost::bytes::Bytes::from_static(b"never sent"),
            None,
        )
        .await;
    let read = network.forward_read_index(from.node().0, node.0).await;
    (write, read)
}

/// The certificate of another controller of the installation, in the place of the node
/// dialed, is refused on every call: Raft, `Cluster` calls and forwards find the node
/// unreachable, which fences nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_dial_refuses_a_certificate_of_another_controller() {
    use tenko_store::raft::network::ForwardError;
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let others: Vec<Arc<Member>> = lab
        .members()
        .into_iter()
        .filter(|member| member.node() != leader.node())
        .collect();
    let (target, other) = (&others[0], &others[1]);
    leader
        .peers
        .network()
        .pin(target.node(), other.addr.to_string());
    let refused = dial_refusal(&leader, target.node())
        .await
        .expect("another controller's certificate in the target's place");
    assert!(
        refused.contains(&format!(
            "names controller {}, not {}",
            other.node(),
            target.node()
        )),
        "{refused}"
    );
    let vote = sends_raft(&leader, target).await.expect_err("no vote");
    assert!(vote.contains("names controller"), "{vote}");
    let (write, read) = forwards(&leader, target.node()).await;
    assert!(
        matches!(write, Err(ForwardError::Unreachable(_))),
        "{write:?}"
    );
    assert!(
        matches!(read, Err(ForwardError::Unreachable(_))),
        "{read:?}"
    );
    assert!(still_writes(&leader).await, "a refusal fences nothing");
    lab.stop().await;
}

/// A revoked certificate of the node dialed is refused, whether the store holds the
/// revocation or only the registry's set does, while the node keeps its record; its own
/// certificate still passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_dial_refuses_a_revoked_certificate_of_its_target() {
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let target = lab.follower().await;
    let stray = stray_certificate(&lab, target.node());
    let at = impostor(&lab, &target, &stray).await;
    // Transports that read the leader's store and have no registry sets.
    let stored = || {
        let network = PeerNetwork::new(leader.node(), PeerTimings::default());
        network.set_tls(
            tenko_cluster::mtls::client_config(
                lab.ca.root_der(),
                leader.identity.0.clone(),
                &leader.identity.1,
            )
            .expect("config"),
        );
        network.attach(&leader.store);
        network.pin(target.node(), at.to_string());
        network
    };
    stored()
        .cluster_client(target.node())
        .await
        .expect("a certificate of the node that is not revoked");
    let serial = revoke_certificate(&leader, target.node(), &stray).await;
    let refused = stored()
        .cluster_client(target.node())
        .await
        .expect_err("revoked in the store");
    assert_eq!(refused.code(), "cluster.peer.unreachable");
    assert!(refused.detail().contains("is revoked"), "{refused}");

    // Revoked in the registry's set only.
    wait_until_async("the revocation in the leader's set", async || {
        leader.registry.is_revoked_serial(&serial)
    })
    .await;
    let other = stray_certificate(&lab, target.node());
    let at = impostor(&lab, &target, &other).await;
    leader
        .registry
        .revocations()
        .insert([tenko_cluster::ca::CertInfo::from_der(&other.0[0])
            .expect("info")
            .serial]);
    leader.peers.network().pin(target.node(), at.to_string());
    let detail = dial_refusal(&leader, target.node())
        .await
        .expect("revoked in the set");
    assert!(detail.contains("is revoked"), "{detail}");
    leader
        .peers
        .network()
        .pin(target.node(), target.addr.to_string());
    assert_eq!(
        dial_refusal(&leader, target.node()).await,
        None,
        "the node is not removed: its own certificate passes"
    );
    lab.stop().await;
}

/// A dial that expects a node and cannot read this controller's store is refused; the seed
/// of a join, which expects none, is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_whose_store_cannot_be_read_is_refused() {
    let lab = Lab::first(&no_change).await;
    let first = &lab.first;
    let config = tenko_cluster::mtls::client_config(
        lab.ca.root_der(),
        first.identity.0.clone(),
        &first.identity.1,
    )
    .expect("config");
    let unattached = PeerNetwork::new(NodeId(77), PeerTimings::default());
    unattached.set_tls(Arc::clone(&config));
    let stopped = PeerNetwork::new(NodeId(77), PeerTimings::default());
    stopped.set_tls(config);
    let store = RaftStore::open_temp(store_config(77, &no_change))
        .await
        .expect("store");
    stopped.attach(&store);
    let _ = store.shutdown().await;
    for network in [&unattached, &stopped] {
        let refused = network
            .channel(NodeId(1), &first.addr.to_string())
            .await
            .expect_err("no store to read");
        assert_eq!(refused.code(), "cluster.peer.unreachable");
        assert!(refused.detail().contains("cannot be read"), "{refused}");
    }
    unattached
        .seed_channel(&first.addr.to_string())
        .await
        .expect("the seed of a join");
    lab.stop().await;
}

/// A connection open when its certificate is revoked carries no further call: the next
/// one fails, a forward on the cached channel dials again and is refused as unreachable,
/// and a new channel is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_stops_an_open_channel_at_once() {
    use tenko_store::raft::network::ForwardError;
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let target = lab.follower().await;
    let stray = stray_certificate(&lab, target.node());
    let at = impostor(&lab, &target, &stray).await;
    leader.peers.network().pin(target.node(), at.to_string());
    let mut client = leader
        .peers
        .network()
        .cluster_client(target.node())
        .await
        .expect("a certificate of the node that is not revoked");
    client
        .members(v1::MembersRequest {})
        .await
        .expect("the open channel answers");
    let serial = revoke_certificate(&leader, target.node(), &stray).await;
    wait_until_async("the revocation in the leader's set", async || {
        leader.registry.is_revoked_serial(&serial)
    })
    .await;
    client
        .members(v1::MembersRequest {})
        .await
        .expect_err("the open connection carries no further call");
    // Never `NoAnswer`: the dial marks its refusal, so nothing counts as sent.
    let (write, _) = forwards(&leader, target.node()).await;
    assert!(
        matches!(write, Err(ForwardError::Unreachable(_))),
        "a forward on the cached channel: {write:?}"
    );
    let refused = dial_refusal(&leader, target.node())
        .await
        .expect("a new channel");
    assert!(refused.contains("is revoked"), "{refused}");
    lab.stop().await;
}

/// The cached channel of one node never serves another at the same endpoint: a controller
/// that answers at an address another controller used before is reached as itself, and the
/// one that left is refused there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_endpoint_serves_another_node_only_by_its_own_channel() {
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let others: Vec<Arc<Member>> = lab
        .members()
        .into_iter()
        .filter(|member| member.node() != leader.node())
        .collect();
    let (gone, new) = (&others[0], &others[1]);
    let relay = Relay::to(gone.addr).await;
    let network = leader.peers.network();
    network.pin(gone.node(), relay.addr.to_string());
    network.pin(new.node(), relay.addr.to_string());
    let mut client = network
        .cluster_client(gone.node())
        .await
        .expect("the controller at the address");
    client
        .members(v1::MembersRequest {})
        .await
        .expect("answers");
    relay.backend.send_replace(new.addr);
    let mut client = network
        .cluster_client(new.node())
        .await
        .expect("the controller now at the address");
    client
        .members(v1::MembersRequest {})
        .await
        .expect("answers as itself");
    redial(&lab, &leader);
    let refused = dial_refusal(&leader, gone.node())
        .await
        .expect("the controller that left the address");
    assert!(
        refused.contains(&format!("names controller {}", new.node())),
        "{refused}"
    );
    lab.stop().await;
}

/// A renewed certificate of the node dialed passes, and so does the one it renewed while
/// it lasts: a renewal revokes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_renewed_certificate_of_the_node_dialed_passes() {
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
    let target = lab.follower().await;
    let running = tenko_cluster::ca::CertInfo::from_der(&target.identity.0[0]).expect("info");
    let (key, csr) = generate_csr().expect("csr");
    let renewed = lab
        .first
        .registry
        .renew(
            target.node(),
            &running.serial,
            &csr,
            tenko_core::Timestamp::now(),
        )
        .await
        .expect("a renewal");
    let at = impostor(&lab, &target, &(renewed.chain, key)).await;
    leader.peers.network().pin(target.node(), at.to_string());
    assert_eq!(dial_refusal(&leader, target.node()).await, None, "renewed");
    leader
        .peers
        .network()
        .pin(target.node(), target.addr.to_string());
    assert_eq!(
        dial_refusal(&leader, target.node()).await,
        None,
        "renewed from"
    );
    lab.stop().await;
}

/// The removal of one of two voters needs the removed one's acknowledgment: no Raft call
/// to it is refused, from its revocation in the store or in the registry's sets to the end
/// of the removal. The refusals are counted by this lab's transports, never read from the
/// logs of a process that runs other tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_two_voter_removal_sees_no_refused_raft_call() {
    let (lab, _) = two_voters().await;
    let leader = lab.leader().await;
    let target = lab
        .members()
        .into_iter()
        .find(|member| member.node() != leader.node())
        .expect("the other voter");
    let removal = leader.peers.remove(&system(), target.node(), false).await;
    let refused = |member: &Member| member.peers.network().exempt_refusals();
    assert_eq!((refused(&leader), refused(&target)), (0, 0), "{removal:?}");
    removal.expect("the removal of one of two voters");
    write_commits(&leader, 1).await;
    assert_eq!((refused(&leader), refused(&target)), (0, 0));
    lab.stop().await;
}

/// A forced step on the first of two controllers that each run alone: its record, the mark
/// of the old voter, whose member record stays, and the old voter's revocation (it has no
/// node record). With `bookkeeping` both run with their registries, as in production.
/// Returns the lab, the forced controller and the old voter.
async fn forced_step(bookkeeping: bool) -> (Lab, Arc<Member>, Arc<Member>) {
    use tenko_cluster::{
        generation::{GENERATION, SUPERSEDED, SupersededMark},
        model::{MemberRecord, Revocation, tables},
    };
    let ca_store = Arc::new(tenko_store::mem::MemStore::default());
    let ca_vault = tenko_vault::MemVault::with_store(Arc::clone(&ca_store));
    let ca = Arc::new(
        InternalCa::load_or_init(ca_store.as_ref(), &ca_vault, &system(), CaPolicy::default())
            .await
            .expect("CA"),
    );
    let mut sides = Vec::new();
    for node in [1_u64, 1001] {
        let issued = ca
            .issue_node_cert_with_key_for(
                NodeId(node),
                [Role::Controller].into_iter().collect(),
                tenko_core::Timestamp::now(),
            )
            .expect("certificate");
        let store = RaftStore::open_temp(store_config(node, &|config| config.bootstrap = true))
            .await
            .expect("store");
        let reference = certificate_ref(&issued.info);
        let side = Arc::new(
            start_member(
                store,
                &ca,
                issued.chain,
                &issued.key,
                Arc::new(FixedIdentity(reference)),
                bookkeeping,
            )
            .await,
        );
        side.peers.attach_ca_root(ca.root_der().clone());
        wait_until_async("the controller writes on its own", async || {
            still_writes(&side).await
        })
        .await;
        sides.push(side);
    }
    let lab = Lab {
        members: Mutex::new(sides.clone()),
        ca: Arc::clone(&ca),
        first: Arc::clone(&sides[0]),
    };
    let (first, old) = (Arc::clone(&sides[0]), Arc::clone(&sides[1]));
    let node = old.node();
    let info = tenko_cluster::ca::CertInfo::from_der(&old.identity.0[0]).expect("info");
    let forced = record(1, None, first.node(), &[node], &first.identity);
    let mut batch = WriteBatch::for_request(&system());
    batch
        .put_typed(&GENERATION, &1_u64, &forced)
        .expect("record");
    batch
        .put_typed(
            &SUPERSEDED,
            &node.0,
            &SupersededMark {
                generation: 1,
                record: forced.hash(),
            },
        )
        .expect("mark");
    batch
        .put_typed(
            &tables::MEMBERS,
            &node.0,
            &MemberRecord {
                node,
                address: old.addr.to_string(),
                version: "0.0.1".to_owned(),
                data_format: 2,
                joined_at: tenko_core::Timestamp::now(),
                protocol_majors: Vec::new(),
                raft_wire: None,
                formats: Vec::new(),
            },
        )
        .expect("member record");
    batch
        .put_typed(
            &tables::REVOCATIONS,
            &info.serial,
            &Revocation {
                node,
                revoked_at: tenko_core::Timestamp::now(),
                not_after: info.not_after,
                controller: true,
            },
        )
        .expect("revocation");
    first.store.propose(batch).await.expect("the forced step");
    first.peers.load_generation().await.expect("generation");
    (lab, first, old)
}

/// The probe of a forced step's first start, which runs before the registry is attached,
/// reaches a removed old voter, and only with a certificate that names it; every other call
/// to it is refused, also after the probe opened its channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_probe_alone_reaches_a_removed_old_voter() {
    use tenko_store::raft::network::{ForwardError, LeaderLink as _};
    let (lab, first, old) = forced_step(false).await;
    let node = old.node();
    let removed = async || {
        let refused = first
            .peers
            .network()
            .cluster_client(node)
            .await
            .expect_err("a removed controller gets no other call");
        assert_eq!(refused.code(), "cluster.peer.unreachable");
        assert!(refused.detail().contains("was removed"), "{refused}");
    };
    removed().await;
    let read = first
        .peers
        .network()
        .forward_read_index(first.node().0, node.0)
        .await;
    assert!(
        matches!(read, Err(ForwardError::Unreachable(_))),
        "{read:?}"
    );
    let answer = first
        .peers
        .probe_members(node, &old.addr.to_string(), None)
        .await;
    // The old voter answers itself: its own copy does not know the forced controller.
    let Some(Err(status)) = &answer else {
        panic!("the probe reaches a removed old voter: {answer:?}");
    };
    assert_eq!(code_of(status), Some("cluster.node.unknown"), "{status:?}");
    removed().await;
    // Another controller's certificate in the removed old voter's place.
    first.peers.network().pin(node, first.addr.to_string());
    let answer = first
        .peers
        .probe_members(node, &old.addr.to_string(), None)
        .await;
    let Some(Err(status)) = &answer else {
        panic!("another controller in the old voter's place: {answer:?}");
    };
    assert!(
        status
            .message()
            .contains(&format!("names controller {}, not {node}", first.node())),
        "{status:?}"
    );
    lab.stop().await;
}

/// A controller that a forced step superseded and revoked, still running on its own copy,
/// stops writing when it calls the forced controller, whose registry keeps it from being
/// called: no connection to it is even made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_superseded_controller_fences_when_it_calls_the_forced_one() {
    let (lab, first, old) = forced_step(true).await;
    let node = old.node();
    wait_until_async("the removal in the forced controller's set", async || {
        first.registry.is_revoked_node(node)
    })
    .await;
    // Nothing listens there: only a refusal before the connection names the removal.
    first
        .peers
        .network()
        .pin(node, format!("127.0.0.1:{}", free_port().release()));
    let refused = first
        .peers
        .network()
        .cluster_client(node)
        .await
        .expect_err("a removed controller gets no call");
    assert!(refused.detail().contains("was removed"), "{refused}");
    let refused = sends_raft(&old, &first)
        .await
        .expect_err("the forced controller takes only the exchange of records");
    assert!(refused.contains("cluster.peer.revoked"), "{refused}");
    wait_until_async("the old controller fenced", async || {
        old.peers.generation().fence.is_some()
    })
    .await;
    assert!(!still_writes(&old).await);
    lab.stop().await;
}

/// The hosts of old voters that rejoined under new node ids at the same addresses still
/// answer the probe of a forced step on a stale copy: the certificate there names another
/// node, and that refusal is an answer whose code keeps the forced controller out of office,
/// never silence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_probe_hears_a_controller_that_answers_in_an_old_voters_place() {
    let lab = Lab::three(&no_change).await;
    let prober = Arc::clone(&lab.first);
    for (old, live) in lab
        .members()
        .into_iter()
        .filter(|member| member.node() != prober.node())
        .enumerate()
    {
        let old = NodeId(2001 + u64::try_from(old).expect("small"));
        let answer = prober
            .peers
            .probe_members(old, &live.addr.to_string(), None)
            .await;
        let Some(Err(status)) = &answer else {
            panic!(
                "controller {} answered in {old}'s place: {answer:?}",
                live.node()
            );
        };
        let code = code_of(status).expect("a coded answer");
        assert_ne!(code, tenko_cluster::generation::codes::SUPERSEDED);
        assert_eq!(
            prober.peers.competing(status).expect("no records"),
            None,
            "{status:?}"
        );
        // The reason alone: the log line that names the old voter shows it.
        assert_eq!(
            status.message(),
            format!(
                "the certificate names controller {}, not {old}",
                live.node()
            ),
            "{status:?}"
        );
    }
    lab.stop().await;
}

/// An open channel of other calls carries no call once its node is removed, also with a
/// certificate whose serial the removal did not revoke.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_channel_ends_when_its_node_is_removed() {
    let lab = Lab::three(&no_change).await;
    let leader = lab.leader().await;
    let node = NodeId(4242);
    let shown = stray_certificate(&lab, node);
    let stays = lab.follower().await;
    let at = impostor(&lab, &stays, &shown).await;
    leader.peers.network().pin(node, at.to_string());
    let mut client = leader
        .peers
        .network()
        .cluster_client(node)
        .await
        .expect("a node that is not removed");
    client
        .members(v1::MembersRequest {})
        .await
        .expect("the open channel answers");
    // A revocation that names the node, with no node record, removes it.
    revoke_certificate(&leader, node, &stray_certificate(&lab, node)).await;
    wait_until_async("the removal in the leader's set", async || {
        leader.registry.is_revoked_node(node)
    })
    .await;
    let serial = tenko_cluster::ca::CertInfo::from_der(&shown.0[0])
        .expect("info")
        .serial;
    assert!(!leader.registry.is_revoked_serial(&serial));
    client
        .members(v1::MembersRequest {})
        .await
        .expect_err("the open connection carries no further call");
    lab.stop().await;
}
