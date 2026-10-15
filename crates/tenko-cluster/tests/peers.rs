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
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use rustls::pki_types::pem::PemObject as _;
use tenko_cluster::{
    admin::{ClusterAdmin, MemberRole, PromoteRequest},
    ca::{CaPolicy, CertSource, InternalCa, TlsMaterial, TlsResolver, generate_csr, pem_block},
    error::ClusterError,
    kek::{KekSource, SealedKeks},
    model::{EnrolRequest, NewEnrolment},
    mtls::RevocationSet,
    peers::{ControllerIdentity, PeerConfig, PeerNetwork, PeerTimings, Peers, certificate_ref},
    proto::v1,
    registry::{NodeRegistry, RegistryConfig},
    server::{ClusterListener, NodeServices, Port, code_of},
    session::Sessions,
};
use tenko_core::{NodeId, RequestCtx, Role, SystemComponent};
use tenko_jobs::{EngineConfig, JobEngine};
use tenko_store::{
    ReadConsistency, Store, StoreRole,
    raft::{RaftStore, RaftStoreConfig, SnapshotPolicy},
    testing::{ClusterFixture, ConformanceConfig},
};
use tenko_vault::{KekRing, MemKek, SecretBytes, StoreVault};
use tokio::{sync::watch, task::JoinHandle};

const WAIT: Duration = Duration::from_secs(30);

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

/// One controller: store, registry, peer layer and cluster port.
struct Member {
    store: RaftStore,
    peers: Peers,
    registry: Arc<NodeRegistry>,
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    engine: JobEngine,
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
    let store_dyn: Arc<dyn Store> = Arc::new(store.clone());
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
        TlsMaterial::from_der(chain, key, CertSource::Inline).expect("material"),
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
    }
}

impl Lab {
    /// The first controller alone.
    async fn first(configure: &(dyn Fn(&mut RaftStoreConfig) + Sync)) -> Self {
        let store = RaftStore::open_temp(store_config(1, configure))
            .await
            .expect("store");
        let store_dyn: Arc<dyn Store> = Arc::new(store.clone());
        let ring = KekRing::new(Arc::new(MemKek::generate("kek-test-1")));
        let vault = StoreVault::open(Arc::clone(&store_dyn), ring)
            .await
            .expect("vault");
        let ca = Arc::new(
            InternalCa::load_or_init(store_dyn.as_ref(), &vault, &system(), CaPolicy::default())
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

    /// Enrols a controller through the first member's registry: its certificate and key.
    async fn enrol_controller(
        &self,
        name: &str,
    ) -> (
        NodeId,
        Vec<rustls::pki_types::CertificateDer<'static>>,
        SecretBytes,
        uuid::Uuid,
    ) {
        let (enrolment, token) = self
            .first
            .registry
            .create_enrolment(
                &system(),
                NewEnrolment {
                    roles: vec![Role::Controller],
                    name: Some(name.to_owned()),
                    ..NewEnrolment::default()
                },
            )
            .await
            .expect("controller token");
        let (key, csr) = generate_csr().expect("csr");
        let enrolled = self
            .first
            .registry
            .enrol(
                &system(),
                EnrolRequest {
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
            .expect("enrol a controller");
        let chain =
            rustls::pki_types::CertificateDer::pem_slice_iter(enrolled.certificate_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("chain");
        (enrolled.node.id, chain, key, enrolment.id)
    }

    /// Enrols, starts and joins another controller.
    async fn join(
        &self,
        name: &str,
        configure: &(dyn Fn(&mut RaftStoreConfig) + Sync),
    ) -> Arc<Member> {
        let (node, chain, key, _) = self.enrol_controller(name).await;
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
        let lab = Self::first(configure).await;
        lab.join("controller-two", configure).await;
        lab.join("controller-three", configure).await;
        wait_until("three voters", || {
            lab.first.store.membership().voters.len() == 3
        })
        .await;
        lab
    }

    async fn leader(&self) -> Arc<Member> {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(leader) = self.members().into_iter().find(|member| {
                member
                    .store
                    .leadership()
                    .borrow()
                    .is_some_and(|seen| seen.is_self)
            }) {
                return leader;
            }
            assert!(Instant::now() < deadline, "no member took office");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
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
        let deadline = Instant::now() + WAIT;
        while Lab::leader(self).await.node() == leader.node() {
            assert!(
                Instant::now() < deadline,
                "the new leader did not take office"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

async fn wait_until(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
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
                        enrolment: uuid::Uuid::nil(),
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
    wait_until("the learner catches up", || {
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
    wait_until("three voters", || {
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
        .create_enrolment(&system(), NewEnrolment::default())
        .await
        .expect("probe token");
    let (key, csr) = generate_csr().expect("csr");
    let probe = lab
        .first
        .registry
        .enrol(
            &system(),
            EnrolRequest {
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
        .expect("enrol a probe");
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
    let foreign = PeerNetwork::new(NodeId(1), PeerTimings::default());
    foreign.set_tls(
        tenko_cluster::mtls::client_config(other_registry.ca().root_der(), chain, &key)
            .expect("config"),
    );
    assert!(
        foreign.channel(&lab.first.addr.to_string()).await.is_err(),
        "a foreign CA is refused"
    );
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
    wait_until("the leader purges its log", || {
        lab.first.store.raft().metrics().borrow().purged >= snapshot
    })
    .await;
    let learner = lab.join("controller-snap", &purge).await;
    let target = lab.first.store.status().revision;
    wait_until("the learner installs the snapshot", || {
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

/// The keys go to a joining controller once per enrolment token, audited; a member change
/// asked of a follower runs on the leader; step-down moves leadership.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_transfer_forwarded_changes_and_step_down() {
    let lab = Lab::three(&no_change).await;
    let (node, chain, key, token) = lab.enrol_controller("controller-four").await;
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
        .remove(&system(), target.node())
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

/// Enrols a probe through the first controller's registry: its id and client credentials.
async fn enrol_probe(lab: &Lab, name: &str) -> (NodeId, Arc<rustls::ClientConfig>, String) {
    let (_, token) = lab
        .first
        .registry
        .create_enrolment(&system(), NewEnrolment::default())
        .await
        .expect("probe token");
    let (key, csr) = generate_csr().expect("csr");
    let probe = lab
        .first
        .registry
        .enrol(
            &system(),
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
        .expect("enrol a probe");
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
    let (probe, config, serial) = enrol_probe(&lab, "probe-everywhere").await;
    let second = lab
        .members()
        .into_iter()
        .find(|member| member.node() != NodeId(1))
        .expect("another member");
    let channel = tenko_cluster::client::connect(&second.addr.to_string(), Arc::clone(&config))
        .await
        .expect("the probe reaches another member");
    let mut handshake = v1::handshake_client::HandshakeClient::new(channel);
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

    lab.first
        .registry
        .revoke(&system(), probe)
        .await
        .expect("revoke on the first controller");
    let deadline = Instant::now() + Duration::from_secs(2);
    while !second.registry.revocations().is_revoked(&serial) {
        assert!(
            Instant::now() < deadline,
            "the revocation did not reach the other member"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
    let (probe, _, _) = enrol_probe(&lab, "probe-elsewhere").await;
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
    let deadline = Instant::now() + WAIT;
    let view = loop {
        let view = lab.first.registry.get_node(probe).await.expect("node");
        if view.connected {
            break view;
        }
        assert!(
            Instant::now() < deadline,
            "the connection did not replicate"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
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
    let deadline = Instant::now() + WAIT;
    while lab
        .first
        .registry
        .get_node(probe)
        .await
        .expect("node")
        .connected
    {
        assert!(
            Instant::now() < deadline,
            "the disconnect did not replicate"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
    let deadline = Instant::now() + WAIT;
    loop {
        let spans: Vec<_> = exporter
            .get_finished_spans()
            .expect("the finished spans")
            .into_iter()
            .filter(|span| span.name == name)
            .collect();
        if ready(&spans) {
            return spans;
        }
        assert!(Instant::now() < deadline, "no matching span {name}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
