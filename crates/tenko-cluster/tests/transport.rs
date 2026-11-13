//! The node transport end to end inside one process, over real TCP on the loopback
//! interface: enrollment through the registry, mutual TLS, the handshake, heartbeats, the
//! observation buffer and its replay after a controller outage, renewal, revocation, version
//! negotiation, and the refusal of another installation's CA.

use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, Mutex, OnceLock, PoisonError, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use tenko_cluster::{
    buffer::BufferConfig,
    ca::{CaPolicy, InternalCa, TlsResolver, generate_csr, pem_block},
    client::{self, Agent, AgentConfig},
    error::ClusterError,
    identity::{AgentState, Credentials, NodeIdentity, NodePaths},
    model::{self, EnrollRequest, NewEnrollment},
    probe::{IngestCounts, ProbeBatch, ProbeSink, Sighting, SightingSubject},
    registry::{self, NODE_EDIT_ATTEMPTS, NodeRegistry, RegistryConfig},
    server::ClusterListener,
};
use tenko_core::{
    NodeId, RequestCtx, Revision, Role, SystemComponent, Timestamp, VrfId, observe::ProbeMethod,
    testing::wait_until_async,
};
use tenko_jobs::{EngineConfig, JobEngine};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, KeyRange, Precondition, ReadConsistency, ReadView,
    ReadViewExt, Store, StoreError, StoreStatus, WatchFilter, WriteBatch, mem::MemStore, tables,
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

/// One controller: store, vault, CA, registry and a cluster port on the loopback.
struct Controller {
    store: Arc<MemStore>,
    registry: Arc<NodeRegistry>,
    sink: Arc<RecordingSink>,
    resolver: Arc<TlsResolver>,
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

fn system() -> RequestCtx {
    RequestCtx::system(SystemComponent::Cluster)
}

impl Controller {
    async fn start() -> Self {
        Self::start_with(CaPolicy::default()).await
    }

    /// A controller whose CA issues by `policy`: a short node lifetime puts a new node
    /// certificate inside its renewal window at once.
    async fn start_with(policy: CaPolicy) -> Self {
        let store = Arc::new(MemStore::default());
        let vault = MemVault::with_store(store.clone());
        let ca = InternalCa::load_or_init(&*store, &vault, &system(), policy)
            .await
            .expect("CA");
        let store_dyn: Arc<dyn Store> = store.clone();
        let engine = JobEngine::new(Arc::clone(&store_dyn), EngineConfig::default());
        let mut config = RegistryConfig::new(NodeId(1));
        config.heartbeat_secs = 1;
        let registry = NodeRegistry::new(store_dyn, Arc::new(ca), config);
        registry.register_steps(&engine);
        let material = registry
            .controller_material(&vault, &system())
            .await
            .expect("controller certificate");
        let resolver = Arc::new(TlsResolver::default());
        resolver.set(Some(material));
        let (stop, _) = watch::channel(false);
        let mut controller = Self {
            store,
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
    async fn listen(&mut self) {
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

    /// Closes the cluster port: an outage of the controller.
    async fn halt(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            tokio::time::timeout(WAIT, task)
                .await
                .expect("the cluster port stops")
                .expect("task");
        }
    }

    async fn token(&self, request: NewEnrollment) -> String {
        let (_, token) = self
            .registry
            .create_enrollment(&system(), request)
            .await
            .expect("token");
        token.to_text().to_string()
    }

    async fn audit_actions(&self) -> Vec<String> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.scan_typed(&tables::AUDIT, KeyRange::all(), usize::MAX, false)
            .expect("audit")
            .into_iter()
            .map(|(_, record, _)| record.draft.action.as_str().to_owned())
            .filter(|action| action.starts_with("cluster."))
            .collect()
    }

    /// Enrolls a node whose files live in `dir`, with this controller's cluster port as
    /// its endpoint.
    async fn enroll(&self, dir: &Path, name: &str) -> Credentials {
        let token = self.token(NewEnrollment::default()).await;
        let (credentials, _) = self
            .enroll_with(dir, name, &token, vec![1])
            .await
            .expect("enroll");
        credentials
    }

    async fn enroll_with(
        &self,
        dir: &Path,
        name: &str,
        token: &str,
        majors: Vec<u32>,
    ) -> Result<(Credentials, SecretBytes), ClusterError> {
        let (key, csr) = generate_csr().expect("csr");
        let mut ctx = system();
        ctx.source_ip = Some("192.0.2.20".parse().expect("ip"));
        let enrolled = self
            .registry
            .enroll(
                &ctx,
                EnrollRequest {
                    token: token.to_owned(),
                    csr: pem_block("CERTIFICATE REQUEST", &csr),
                    name: Some(name.to_owned()),
                    roles: Vec::new(),
                    address: None,
                    version: "0.0.1".to_owned(),
                    majors,
                },
            )
            .await?;
        let identity = NodeIdentity {
            node: enrolled.node.id,
            name: enrolled.node.name.clone(),
            roles: enrolled.node.roles.clone(),
            controller: "https://ddi.example.net:8443".to_owned(),
            endpoints: vec![self.addr.to_string()],
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
        )?;
        credentials.save(&NodePaths::new(dir))?;
        Ok((credentials, key))
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

fn run(agent: &Arc<Agent>) -> (watch::Sender<bool>, JoinHandle<()>) {
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(agent).run(stopped));
    (stop, task)
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
async fn a_node_enrolls_connects_and_delivers_a_batch() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enroll(dir.path(), "probe-dmz").await;
    assert_eq!(credentials.identity.node, NodeId(1001));
    assert!(credentials.certificate_roles().contains(Role::Probe));

    let agent = agent(dir.path());
    let (stop, task) = run(&agent);
    wait_until_async("the node to connect", async || {
        agent.status().state == AgentState::Connected
            && controller.registry.sessions().view(NodeId(1001)).is_some()
    })
    .await;
    agent.push(&batch(10)).expect("push");
    wait_until_async("the batch to arrive", async || {
        controller.sink.batches().len() == 1
    })
    .await;
    let (node, vrf, delivered) = controller.sink.batches().remove(0);
    assert_eq!(node, NodeId(1001));
    assert_eq!(vrf, None);
    assert_eq!(address_of(&delivered), "192.0.2.10");
    wait_until_async("the buffer to empty", async || {
        agent.outbox().stats().batches == 0
    })
    .await;

    let view = controller
        .registry
        .get_node(NodeId(1001))
        .await
        .expect("node");
    assert!(view.connected);
    assert_eq!(view.name, "probe-dmz");
    assert_eq!(view.address.as_deref(), Some("192.0.2.20"));
    assert_eq!(view.protocol.agreed, Some(1));
    wait_until_async("a heartbeat", async || {
        controller
            .registry
            .sessions()
            .view(NodeId(1001))
            .is_some_and(|live| live.last_beat.is_some() && live.version == "0.0.1")
    })
    .await;
    let health = controller.registry.health().await.expect("health");
    assert_eq!((health.nodes, health.connected), (1, 1));
    assert_eq!(health.versions.get("0.0.1"), Some(&1));

    let actions = controller.audit_actions().await;
    assert!(
        actions.contains(&"cluster.enrollment.create".to_owned()),
        "{actions:?}"
    );
    assert!(
        actions.contains(&"cluster.node.enroll".to_owned()),
        "{actions:?}"
    );

    let _ = stop.send(true);
    task.await.expect("agent");
    assert_eq!(agent.status().state, AgentState::Stopped);
}

#[tokio::test]
async fn the_buffer_replays_in_order_after_a_controller_outage() {
    let mut controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    controller.enroll(dir.path(), "probe-lan").await;
    let agent = agent(dir.path());
    let (stop, task) = run(&agent);
    wait_until_async("the node to connect", async || {
        agent.status().state == AgentState::Connected
    })
    .await;

    controller.halt().await;
    wait_until_async("the node to notice the outage", async || {
        agent.status().state != AgentState::Connected
    })
    .await;
    for n in 1..=3 {
        agent.push(&batch(n)).expect("push");
    }
    assert_eq!(agent.outbox().stats().batches, 3);
    assert_eq!(controller.sink.batches().len(), 0);

    controller.listen().await;
    wait_until_async("the replay", async || controller.sink.batches().len() == 3).await;
    let order: Vec<String> = controller
        .sink
        .batches()
        .iter()
        .map(|(_, _, batch)| address_of(batch))
        .collect();
    assert_eq!(order, ["192.0.2.1", "192.0.2.2", "192.0.2.3"]);
    wait_until_async("the buffer to empty", async || {
        agent.outbox().stats().batches == 0
    })
    .await;
    let _ = stop.send(true);
    task.await.expect("agent");
}

#[tokio::test]
async fn revocation_closes_the_connection_and_refuses_the_certificate() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enroll(dir.path(), "probe-iot").await;
    let node = credentials.identity.node;
    let agent = agent(dir.path());
    let (stop, task) = run(&agent);
    wait_until_async("the heartbeat session", async || {
        agent.status().state == AgentState::Connected
            && controller.registry.sessions().view(node).is_some()
    })
    .await;
    assert_eq!(controller.registry.sessions().connection_count(node), 1);

    let serials = controller
        .registry
        .revoke(&system(), node)
        .await
        .expect("revoke");
    assert_eq!(serials, std::slice::from_ref(&credentials.info.serial));
    wait_until_async("the node to learn it was revoked", async || {
        agent.status().state == AgentState::Revoked
    })
    .await;
    wait_until_async("the connection to close", async || {
        controller.registry.sessions().connection_count(node) == 0
            && controller.registry.sessions().view(node).is_none()
    })
    .await;
    let _ = stop.send(true);
    task.await.expect("agent");

    // A new attempt fails in the TLS handshake: the serial is on the revocation list.
    let refused = client::check(&credentials, "0.0.1", &[1])
        .await
        .expect_err("revoked");
    assert_eq!(refused.0, AgentState::Revoked, "{refused:?}");
    assert_eq!(refused.1.code, "cluster.node.revoked");
    assert!(
        controller
            .registry
            .get_node(node)
            .await
            .is_err_and(|error| error.code() == "cluster.node.not_found")
    );
    assert!(
        controller
            .audit_actions()
            .await
            .contains(&"cluster.node.revoke".to_owned())
    );
}

/// Writes a revocation of `node` the way another controller's does when it replicates
/// here: the record and its name go, every serial the record holds becomes a revocation
/// row, and nothing on this controller is told directly.
async fn revoke_on_another_controller(controller: &Controller, node: NodeId) {
    let view = controller
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    let (record, revision) = view
        .get_typed(&model::tables::NODES, &node.0)
        .expect("read")
        .expect("the node record");
    drop(view);
    let mut batch = WriteBatch::for_request(&system());
    batch.expect_typed(&model::tables::NODES, &node.0, Some(revision));
    batch.delete_typed(&model::tables::NODES, &node.0);
    batch.delete_typed(&model::tables::NODE_NAMES, &record.name.to_lowercase());
    for cert in &record.serials {
        batch
            .put_typed(
                &model::tables::REVOCATIONS,
                &cert.serial,
                &model::Revocation {
                    node,
                    revoked_at: Timestamp::now(),
                    not_after: cert.not_after,
                    controller: false,
                },
            )
            .expect("row");
    }
    controller.store.propose(batch).await.expect("replicated");
}

/// The first revocation an installation ever sees arrives from another controller into an
/// empty revocation table: the node's open connection here closes all the same.
#[tokio::test]
async fn a_revocation_from_another_controller_into_an_empty_table_closes_the_connection() {
    let controller = Controller::start().await;
    let (stop_follow, stopped) = watch::channel(false);
    let follow = controller.registry.follow_revocations(stopped);
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enroll(dir.path(), "probe-first").await;
    let node = credentials.identity.node;
    let agent = agent(dir.path());
    let (stop, task) = run(&agent);
    wait_until_async("the heartbeat session", async || {
        agent.status().state == AgentState::Connected
            && controller.registry.sessions().view(node).is_some()
    })
    .await;
    assert!(controller.registry.revocations().is_empty());

    revoke_on_another_controller(&controller, node).await;
    wait_until_async("the connection to close", async || {
        controller.registry.sessions().connection_count(node) == 0
            && controller.registry.sessions().view(node).is_none()
    })
    .await;
    assert!(
        controller
            .registry
            .revocations()
            .is_revoked(&credentials.info.serial)
    );
    let _ = stop.send(true);
    task.await.expect("agent");
    let _ = stop_follow.send(true);
    follow.await.expect("follow");
}

/// A revocation that is in the table when the controller starts to follow it closes a
/// connection of that node that is open by then.
#[tokio::test]
async fn a_revocation_present_when_following_starts_closes_the_connection() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enroll(dir.path(), "probe-early").await;
    let node = credentials.identity.node;
    let agent = agent(dir.path());
    let (stop, task) = run(&agent);
    wait_until_async("the heartbeat session", async || {
        agent.status().state == AgentState::Connected
            && controller.registry.sessions().view(node).is_some()
    })
    .await;
    revoke_on_another_controller(&controller, node).await;

    let (stop_follow, stopped) = watch::channel(false);
    let follow = controller.registry.follow_revocations(stopped);
    wait_until_async("the connection to close", async || {
        controller.registry.sessions().connection_count(node) == 0
            && controller.registry.sessions().view(node).is_none()
    })
    .await;
    let _ = stop.send(true);
    task.await.expect("agent");
    let _ = stop_follow.send(true);
    follow.await.expect("follow");
}

#[tokio::test]
async fn a_node_offering_only_an_older_major_is_refused_with_a_notice() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enroll(dir.path(), "probe-old").await;
    let node = credentials.identity.node;

    let refused = client::check(&credentials, "0.0.0", &[0])
        .await
        .expect_err("no common major");
    assert_eq!(refused.0, AgentState::ProtocolMismatch, "{refused:?}");
    assert_eq!(refused.1.code, "cluster.protocol.unsupported");
    assert!(
        refused.1.detail.contains("upgrade the node"),
        "{}",
        refused.1.detail
    );
    assert!(
        refused.1.detail.contains("implements 1"),
        "{}",
        refused.1.detail
    );

    let view = controller.registry.get_node(node).await.expect("node");
    let mismatch = view.protocol.mismatch.expect("the mismatch is recorded");
    assert_eq!(mismatch.majors.theirs, [0]);
    assert_eq!(mismatch.majors.ours, [1]);
    assert_eq!(mismatch.version, "0.0.0");
    let health = controller.registry.health().await.expect("health");
    assert_eq!(health.mismatched.len(), 1);
    assert_eq!(health.mismatched[0].node, node);
    assert!(
        controller
            .audit_actions()
            .await
            .contains(&"cluster.node.version_mismatch".to_owned())
    );

    // The same node offering the current major is accepted and the notice clears.
    let agreed = client::check(&credentials, "0.0.1", &[1])
        .await
        .expect("current major");
    assert_eq!(agreed.major, 1);
    let view = controller.registry.get_node(node).await.expect("node");
    assert!(view.protocol.mismatch.is_none());
    assert_eq!(
        controller
            .registry
            .health()
            .await
            .expect("health")
            .mismatched
            .len(),
        0
    );
}

#[tokio::test]
async fn a_controller_of_another_installation_is_refused() {
    let home = Controller::start().await;
    let foreign = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let mut credentials = home.enroll(dir.path(), "probe-dmz").await;

    // The node dials a controller whose certificate comes from another CA.
    credentials.identity.endpoints = vec![foreign.addr.to_string()];
    let refused = client::check(&credentials, "0.0.1", &[1])
        .await
        .expect_err("foreign controller");
    assert_eq!(refused.0, AgentState::Refused, "{refused:?}");
    assert_eq!(refused.1.code, "cluster.tls.foreign_ca");

    // A node that trusts the foreign controller but holds a certificate of the home CA is
    // refused by the foreign controller.
    credentials.ca_root = foreign.registry.ca().root_der().clone();
    let refused = client::check(&credentials, "0.0.1", &[1])
        .await
        .expect_err("foreign node certificate");
    assert_eq!(refused.0, AgentState::Refused, "{refused:?}");
    assert_eq!(refused.1.code, "cluster.tls.refused");
    assert_eq!(foreign.sink.batches().len(), 0);
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario over every refusal")]
async fn tokens_are_single_use_expire_and_limit_the_roles() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let token = controller.token(NewEnrollment::default()).await;
    controller
        .enroll_with(dir.path(), "probe-a", &token, vec![1])
        .await
        .expect("first use");
    let again = tempfile::tempdir().expect("dir");
    let used = controller
        .enroll_with(again.path(), "probe-b", &token, vec![1])
        .await
        .expect_err("second use");
    assert_eq!(used.code(), "cluster.enrollment.used");

    // A wrong secret under a real token id is the same answer as an unknown token.
    // The secret ends at character 81 of a `tnk2` token; the CA fingerprint follows it.
    let mut forged = controller.token(NewEnrollment::default()).await;
    let last = forged.as_bytes()[80];
    let replacement = if last == b'A' { "Q" } else { "A" };
    forged.replace_range(80..81, replacement);
    let invalid = controller
        .enroll_with(again.path(), "probe-c", &forged, vec![1])
        .await
        .expect_err("forged");
    assert_eq!(invalid.code(), "cluster.enrollment.invalid_token");
    let garbage = controller
        .enroll_with(again.path(), "probe-c", "tnk1.nope", vec![1])
        .await
        .expect_err("garbage");
    assert_eq!(garbage.code(), "cluster.enrollment.invalid_token");

    // Expiry: a token of 60 seconds presented two minutes later.
    let (_, short) = controller
        .registry
        .create_enrollment(
            &system(),
            NewEnrollment {
                expires_in_secs: Some(60),
                ..NewEnrollment::default()
            },
        )
        .await
        .expect("token");
    let (key, csr) = generate_csr().expect("csr");
    drop(key);
    let mut later = system();
    later.now = Timestamp::now()
        .checked_add(Duration::from_secs(120))
        .expect("time");
    let expired = controller
        .registry
        .enroll(
            &later,
            EnrollRequest {
                token: short.to_text().to_string(),
                csr: pem_block("CERTIFICATE REQUEST", &csr),
                name: None,
                roles: Vec::new(),
                address: None,
                version: "0.0.1".to_owned(),
                majors: vec![1],
            },
        )
        .await
        .expect_err("expired");
    assert_eq!(expired.code(), "cluster.enrollment.expired");

    // Roles: a probe token does not make a DNS node, and no token makes a controller.
    let probe_only = controller.token(NewEnrollment::default()).await;
    let (_, csr) = generate_csr().expect("csr");
    let refused = controller
        .registry
        .enroll(
            &system(),
            EnrollRequest {
                token: probe_only,
                csr: pem_block("CERTIFICATE REQUEST", &csr),
                name: None,
                roles: vec![Role::Dns],
                address: None,
                version: "0.0.1".to_owned(),
                majors: vec![1],
            },
        )
        .await
        .expect_err("role");
    assert_eq!(refused.code(), "cluster.enrollment.roles");
    assert_eq!(refused.status(), 403);
    // A controller token carries the role alone and lives at most an hour.
    let mixed = controller
        .registry
        .create_enrollment(
            &system(),
            NewEnrollment {
                roles: vec![Role::Controller, Role::Probe],
                ..NewEnrollment::default()
            },
        )
        .await
        .expect_err("controller beside another role");
    assert_eq!(mixed.code(), "cluster.enrollment.roles");
    assert_eq!(mixed.status(), 403);
    let long = controller
        .registry
        .create_enrollment(
            &system(),
            NewEnrollment {
                roles: vec![Role::Controller],
                expires_in_secs: Some(7_200),
                ..NewEnrollment::default()
            },
        )
        .await
        .expect_err("a controller token for two hours");
    assert_eq!(long.code(), "cluster.enrollment.lifetime");
    let (token, _) = controller
        .registry
        .create_enrollment(
            &system(),
            NewEnrollment {
                roles: vec![Role::Controller],
                ..NewEnrollment::default()
            },
        )
        .await
        .expect("a controller token");
    assert_eq!(token.roles, vec![Role::Controller]);
    assert!(token.expires_at.saturating_since(token.created_at) <= Duration::from_secs(3_600));

    // A node offering no common major cannot enroll either.
    let token = controller.token(NewEnrollment::default()).await;
    let mismatch = controller
        .enroll_with(again.path(), "probe-d", &token, vec![0])
        .await
        .expect_err("major");
    assert_eq!(mismatch.code(), "cluster.protocol.unsupported");

    let tokens = controller
        .registry
        .list_enrollments(Timestamp::now())
        .await
        .expect("list");
    assert!(tokens.iter().any(|token| token.used.is_some()));
    let refusals = controller
        .audit_actions()
        .await
        .iter()
        .filter(|action| *action == "cluster.node.enroll")
        .count();
    // One success and six refusals.
    assert_eq!(refusals, 7);
}

#[tokio::test]
async fn renewal_issues_a_new_certificate_that_connects() {
    // Twenty-day certificates are due for renewal from the start.
    let controller = Controller::start_with(CaPolicy {
        node_validity_days: 20,
        ..CaPolicy::default()
    })
    .await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enroll(dir.path(), "probe-renew").await;
    let paths = NodePaths::new(dir.path());
    let renewed = client::renew_once(&paths, "0.0.1").await.expect("renew");
    assert_ne!(renewed.info.serial, credentials.info.serial);
    assert_eq!(renewed.identity.node, credentials.identity.node);
    assert!(renewed.certificate_roles().contains(Role::Probe));
    let loaded = Credentials::load(&paths).expect("load");
    assert_eq!(loaded.info.serial, renewed.info.serial);

    let view = controller
        .registry
        .get_node(credentials.identity.node)
        .await
        .expect("node");
    assert_eq!(view.certificate.serial, renewed.info.serial);
    assert!(view.renewed_at.is_some());
    // The old certificate keeps working until the node shows it holds the new one; both
    // connect.
    client::check(&credentials, "0.0.1", &[1])
        .await
        .expect("old");
    client::check(&loaded, "0.0.1", &[1]).await.expect("new");
    assert!(
        controller
            .audit_actions()
            .await
            .contains(&"cluster.node.renew".to_owned())
    );
    // Revocation covers both.
    let serials = controller
        .registry
        .revoke(&system(), credentials.identity.node)
        .await
        .expect("revoke");
    assert_eq!(serials.len(), 2);
}

// ---------------------------------------------------------------------------------------
// Edits that race the node's bookkeeping
// ---------------------------------------------------------------------------------------

/// A store that lets the node's bookkeeping win the race against the next `races` edits of
/// a node record: before it forwards a revocation or a renewal, it rewrites the record the
/// way a heartbeat does ([`NodeRegistry::touch`]), so the edit's precondition fails. That
/// is the window between the read and the write of an edit, made certain.
struct RacingStore {
    inner: Arc<MemStore>,
    registry: OnceLock<Weak<NodeRegistry>>,
    races: Mutex<usize>,
    raced: AtomicUsize,
}

impl RacingStore {
    fn new(inner: Arc<MemStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            registry: OnceLock::new(),
            races: Mutex::new(0),
            raced: AtomicUsize::new(0),
        })
    }

    /// Lets the heartbeat win the next `races` edits.
    fn arm(&self, races: usize) {
        *self.races.lock().unwrap_or_else(PoisonError::into_inner) = races;
    }

    /// Whether the heartbeat wins this edit (one race fewer to go).
    fn race(&self) -> bool {
        let mut left = self.races.lock().unwrap_or_else(PoisonError::into_inner);
        let race = *left > 0;
        if race {
            *left -= 1;
        }
        race
    }

    /// The node an edit of a node record names, when `batch` is a revocation or a renewal.
    fn edited_node(batch: &WriteBatch) -> Option<NodeId> {
        let edit = batch.audit.iter().any(|draft| {
            draft.action == registry::actions::NODE_REVOKE
                || draft.action == registry::actions::NODE_RENEW
        });
        if !edit {
            return None;
        }
        batch
            .preconditions
            .iter()
            .find_map(|precondition| match precondition {
                Precondition::Version { table, key, .. }
                    if table == model::tables::NODES.name() =>
                {
                    model::tables::NODES.decode_key(key).ok().map(NodeId)
                }
                _ => None,
            })
    }
}

#[async_trait]
impl Store for RacingStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        if let Some(node) = Self::edited_node(&batch)
            && self.race()
        {
            let registry = self
                .registry
                .get()
                .and_then(Weak::upgrade)
                .expect("the registry");
            registry
                .touch(node, Timestamp::now(), true)
                .await
                .expect("the heartbeat's write");
            self.raced.fetch_add(1, Ordering::SeqCst);
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
        self.inner.status()
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<tenko_store::Leadership>> {
        self.inner.leadership()
    }
}

/// A registry over a [`RacingStore`], with its job engine, and one enrolled node: its id,
/// its certificate serial, and the CSR of a renewal for the same key.
async fn racing_registry() -> (Arc<RacingStore>, Arc<NodeRegistry>, NodeId, String, Vec<u8>) {
    let mem = Arc::new(MemStore::default());
    let vault = MemVault::with_store(mem.clone());
    let ca = InternalCa::load_or_init(&*mem, &vault, &system(), CaPolicy::default())
        .await
        .expect("CA");
    let store = RacingStore::new(mem);
    let store_dyn: Arc<dyn Store> = store.clone();
    let engine = JobEngine::new(Arc::clone(&store_dyn), EngineConfig::default());
    let registry = NodeRegistry::new(store_dyn, Arc::new(ca), RegistryConfig::new(NodeId(1)));
    registry.register_steps(&engine);
    let _ = store.registry.set(Arc::downgrade(&registry));
    let (_, token) = registry
        .create_enrollment(&system(), NewEnrollment::default())
        .await
        .expect("token");
    let (_, csr) = generate_csr().expect("csr");
    let enrolled = registry
        .enroll(
            &system(),
            EnrollRequest {
                token: token.to_text().to_string(),
                csr: pem_block("CERTIFICATE REQUEST", &csr),
                name: Some("probe-race".to_owned()),
                roles: Vec::new(),
                address: None,
                version: "0.0.1".to_owned(),
                majors: vec![1],
            },
        )
        .await
        .expect("enroll");
    let serial = enrolled.certificate.info.serial.clone();
    (store, registry, enrolled.node.id, serial, csr)
}

/// The audit actions of the registry, in order.
async fn registry_actions(store: &RacingStore) -> Vec<String> {
    let view = store
        .inner
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    view.scan_typed(&tables::AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record.draft.action.as_str().to_owned())
        .filter(|action| action.starts_with("cluster.node."))
        .collect()
}

#[tokio::test]
async fn a_revocation_that_races_the_heartbeat_is_planned_again() {
    let (store, registry, node, serial, _) = racing_registry().await;
    // The heartbeat wins twice; the third plan goes through.
    store.arm(2);
    let serials = registry.revoke(&system(), node).await.expect("revoke");
    assert_eq!(serials, std::slice::from_ref(&serial));
    assert_eq!(store.raced.load(Ordering::SeqCst), 2);
    assert_eq!(
        registry.get_node(node).await.expect_err("gone").code(),
        "cluster.node.not_found"
    );
    assert!(registry.revocations().is_revoked(&serial));
    // The lost attempts left nothing behind: one revocation in the audit log.
    assert_eq!(
        registry_actions(&store).await,
        ["cluster.node.enroll", "cluster.node.revoke"]
    );
}

#[tokio::test]
async fn a_revocation_that_loses_every_race_is_a_conflict_that_changes_nothing() {
    let (store, registry, node, serial, _) = racing_registry().await;
    store.arm(NODE_EDIT_ATTEMPTS);
    let error = registry
        .revoke(&system(), node)
        .await
        .expect_err("every attempt lost");
    assert_eq!(error.code(), "cluster.node.conflict");
    assert_eq!(error.status(), 409);
    assert_eq!(store.raced.load(Ordering::SeqCst), NODE_EDIT_ATTEMPTS);
    let view = registry.get_node(node).await.expect("still enrolled");
    assert_eq!(view.certificate.serial, serial);
    assert!(view.last_seen.is_some(), "the heartbeats were written");
    assert!(!registry.revocations().is_revoked(&serial));
    assert_eq!(registry_actions(&store).await, ["cluster.node.enroll"]);
}

#[tokio::test]
async fn a_renewal_that_races_the_heartbeat_is_planned_again_with_the_same_certificate() {
    let (store, registry, node, serial, csr) = racing_registry().await;
    let due = days_before(node_record(&registry, node).await.certificate.not_after, 10);
    store.arm(1);
    let renewed = registry
        .renew(node, &serial, &csr, due)
        .await
        .expect("renew");
    assert_eq!(store.raced.load(Ordering::SeqCst), 1);
    let view = registry.get_node(node).await.expect("node");
    assert_eq!(view.certificate.serial, renewed.info.serial);
    assert!(view.last_seen.is_some(), "the heartbeat's write is kept");
    assert_eq!(
        registry_actions(&store).await,
        ["cluster.node.enroll", "cluster.node.renew"]
    );
}

use tenko_cluster::proto::v1;

/// A gRPC channel to the controller's cluster port with the credentials of a node that is
/// enrolled there.
async fn enrolled_channel(
    controller: &Controller,
    dir: &Path,
    name: &str,
) -> tonic::transport::Channel {
    let credentials = controller.enroll(dir, name).await;
    let config = credentials.client_config().expect("client configuration");
    client::connect(&controller.addr.to_string(), config)
        .await
        .expect("channel")
}

#[tokio::test]
async fn a_port_without_controller_services_answers_unimplemented_and_metrics_refuse_a_probe() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let channel = enrolled_channel(&controller, dir.path(), "probe-stubs").await;

    // A port that serves no controller cluster has no `Raft` and `Cluster` services.
    let unimplemented = |status: tonic::Status| {
        assert_eq!(status.code(), tonic::Code::Unimplemented, "{status:?}");
    };
    let mut raft = v1::raft_client::RaftClient::new(channel.clone());
    unimplemented(
        raft.vote(v1::RaftRequest::default())
            .await
            .expect_err("no Raft"),
    );
    let mut cluster = v1::cluster_client::ClusterClient::new(channel.clone());
    unimplemented(
        cluster
            .propose(v1::ProposeRequest::default())
            .await
            .expect_err("no Cluster"),
    );

    // The metrics of a controller are for controllers only.
    let mut metrics = v1::metrics_client::MetricsClient::new(channel);
    let refused = metrics
        .snapshot(v1::SnapshotRequest::default())
        .await
        .expect_err("a probe may not read them");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{refused:?}");
    assert_eq!(
        tenko_cluster::server::code_of(&refused),
        Some("cluster.peer.not_controller")
    );
}

/// A source that answers one fixed sample.
struct FixedSample(tenko_cluster::metrics::EncodedSample);

impl tenko_cluster::metrics::MetricsSource for FixedSample {
    fn current(
        &self,
    ) -> futures::future::BoxFuture<'_, Option<tenko_cluster::metrics::EncodedSample>> {
        Box::pin(async { Some(self.0.clone()) })
    }
}

#[tokio::test]
async fn metrics_snapshot_answers_the_newest_sample_to_a_controller() {
    use tenko_cluster::{
        metrics::{EncodedSample, PeerReply, SAMPLE_ENCODING, fetch},
        peers::{PeerNetwork, PeerTimings},
    };

    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let token = controller
        .token(NewEnrollment {
            roles: vec![Role::Controller],
            ..NewEnrollment::default()
        })
        .await;
    let (credentials, _) = controller
        .enroll_with(dir.path(), "controller-2", &token, vec![1])
        .await
        .expect("a controller enrolls");
    let network = PeerNetwork::new(credentials.identity.node, PeerTimings::default());
    network.set_tls(credentials.client_config().expect("client configuration"));
    network.pin(NodeId(1), controller.addr.to_string());
    let deadline = Duration::from_millis(500);

    // Before the API started there is no sample.
    let PeerReply::Failed(detail) = fetch(&network, NodeId(1), deadline).await else {
        panic!("no sample before the source is set");
    };
    assert!(detail.contains("no metrics sample yet"), "{detail}");

    let sample = EncodedSample {
        node: NodeId(1),
        at: Timestamp::from_unix_nanos(1_791_547_200_000_000_000).expect("time"),
        encoding: SAMPLE_ENCODING.to_owned(),
        payload: vec![0xa1, 0x61, 0x6e, 0x01],
        closed: vec![0xa0],
    };
    controller
        .registry
        .set_metrics_source(Arc::new(FixedSample(sample.clone())));
    assert_eq!(
        fetch(&network, NodeId(1), deadline).await,
        PeerReply::Sample(sample)
    );

    // A controller that does not answer in time.
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    network.pin(NodeId(3), silent.local_addr().expect("addr").to_string());
    let started = std::time::Instant::now();
    assert!(matches!(
        fetch(&network, NodeId(3), deadline).await,
        PeerReply::Failed(_)
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
}

// WP18.0: the history of a controller's dashboard figures.
/// A source with a sample and, when given, a history.
struct WithHistory(
    tenko_cluster::metrics::EncodedSample,
    Option<tenko_cluster::metrics::EncodedHistory>,
);

impl tenko_cluster::metrics::MetricsSource for WithHistory {
    fn current(
        &self,
    ) -> futures::future::BoxFuture<'_, Option<tenko_cluster::metrics::EncodedSample>> {
        Box::pin(async { Some(self.0.clone()) })
    }

    fn history(
        &self,
    ) -> futures::future::BoxFuture<'_, Option<tenko_cluster::metrics::EncodedHistory>> {
        Box::pin(async { self.1.clone() })
    }
}

/// `Metrics.History` answers a controller with the callee's history; a callee that keeps none
/// (the default of the source, as a build before the history) answers `UNIMPLEMENTED`, which
/// the caller reports as unsupported, so it is combined as a missing controller. A probe may
/// not read it.
#[tokio::test]
async fn metrics_history_answers_a_controller_and_an_older_source_is_unsupported() {
    use tenko_cluster::{
        metrics::{EncodedHistory, EncodedSample, HistoryReply, SAMPLE_ENCODING, fetch_history},
        peers::{PeerNetwork, PeerTimings},
    };

    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let token = controller
        .token(NewEnrollment {
            roles: vec![Role::Controller],
            ..NewEnrollment::default()
        })
        .await;
    let (credentials, _) = controller
        .enroll_with(dir.path(), "controller-2", &token, vec![1])
        .await
        .expect("a controller enrolls");
    let network = PeerNetwork::new(credentials.identity.node, PeerTimings::default());
    network.set_tls(credentials.client_config().expect("client configuration"));
    network.pin(NodeId(1), controller.addr.to_string());
    // Each call below is answered at once; the limit only bounds a call that never is.
    let deadline = Duration::from_secs(30);
    let at = Timestamp::from_unix_nanos(1_791_547_200_000_000_000).expect("time");

    // Before the API started there is no source.
    let HistoryReply::Failed(detail) = fetch_history(&network, NodeId(1), deadline).await else {
        panic!("no history before the source is set");
    };
    assert!(detail.contains("no metrics sample yet"), "{detail}");

    let sample = EncodedSample {
        node: NodeId(1),
        at,
        encoding: SAMPLE_ENCODING.to_owned(),
        payload: vec![0xa0],
        closed: Vec::new(),
    };
    // A source of the previous kind: a sample and no history.
    controller
        .registry
        .set_metrics_source(Arc::new(FixedSample(sample.clone())));
    assert_eq!(
        fetch_history(&network, NodeId(1), deadline).await,
        HistoryReply::Unsupported
    );

    // The registry keeps its first source, so a second controller has the history.
    let second = Controller::start().await;
    let history = EncodedHistory {
        node: NodeId(1),
        at,
        encoding: SAMPLE_ENCODING.to_owned(),
        payload: vec![0xa2, 0x01, 0x02, 0x03, 0x04],
    };
    second
        .registry
        .set_metrics_source(Arc::new(WithHistory(sample, Some(history.clone()))));
    let token = second
        .token(NewEnrollment {
            roles: vec![Role::Controller],
            ..NewEnrollment::default()
        })
        .await;
    let other = tempfile::tempdir().expect("dir");
    let (credentials, _) = second
        .enroll_with(other.path(), "controller-3", &token, vec![1])
        .await
        .expect("a controller enrolls");
    let network = PeerNetwork::new(credentials.identity.node, PeerTimings::default());
    network.set_tls(credentials.client_config().expect("client configuration"));
    network.pin(NodeId(1), second.addr.to_string());
    assert_eq!(
        fetch_history(&network, NodeId(1), deadline).await,
        HistoryReply::History(history)
    );

    // A probe may not read it.
    let probe = tempfile::tempdir().expect("dir");
    let channel = enrolled_channel(&second, probe.path(), "probe-history").await;
    let refused = v1::metrics_client::MetricsClient::new(channel)
        .history(v1::HistoryRequest::default())
        .await
        .expect_err("a probe may not read it");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{refused:?}");
    assert_eq!(
        tenko_cluster::server::code_of(&refused),
        Some("cluster.peer.not_controller")
    );
}

#[tokio::test]
async fn hello_answers_with_its_old_fields_and_empty_capabilities_and_endpoints() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let channel = enrolled_channel(&controller, dir.path(), "probe-hello").await;

    let mut handshake = v1::handshake_client::HandshakeClient::new(channel);
    let response = handshake
        .hello(v1::HelloRequest {
            majors: vec![1],
            version: "0.0.1".to_owned(),
            roles: vec!["probe".to_owned()],
            capabilities: Vec::new(),
        })
        .await
        .expect("hello")
        .into_inner();
    assert_eq!(response.major, 1);
    assert_eq!(response.majors, [1]);
    assert_eq!(response.version, tenko_cluster::version());
    assert_eq!(response.node_id, 1001);
    assert_eq!(response.heartbeat_secs, 1);
    assert!(response.server_time.is_some());
    assert!(response.capabilities.is_empty(), "{response:?}");
    assert!(response.endpoints.is_empty(), "{response:?}");
}

/// Removes a node's record directly, as a replicated revocation does, without any
/// revocation row: nothing closes the node's connection, so only the streams' own checks
/// can end them.
async fn forget_node(controller: &Controller, node: NodeId) {
    let mut batch = WriteBatch::for_request(&system());
    batch.delete_typed(&model::tables::NODES, &node.0);
    controller
        .store
        .propose(batch)
        .await
        .expect("forget the node");
}

/// Waits for the next item of a stream of the cluster port and returns its refusal code.
async fn ended_with<T: std::fmt::Debug>(
    what: &str,
    stream: &mut tonic::Streaming<T>,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let next = tokio::time::timeout_at(deadline, stream.message())
            .await
            .unwrap_or_else(|_| panic!("the {what} stream is still open"));
        match next {
            Ok(Some(_)) => {}
            Ok(None) => return None,
            Err(status) => {
                return tenko_cluster::server::code_of(&status).map(str::to_owned);
            }
        }
    }
}

/// The configuration, command and heartbeat streams of a node check its record again while
/// they are open: once the record is gone they end with the refusal of a new call.
#[tokio::test]
async fn open_streams_end_once_the_node_record_is_gone() {
    let controller = Controller::start().await;
    controller.registry.set_timings(registry::Timings {
        stream_recheck: Duration::from_millis(100),
        ..registry::Timings::default()
    });
    let dir = tempfile::tempdir().expect("dir");
    let channel = enrolled_channel(&controller, dir.path(), "probe-streams").await;
    let node = NodeId(1001);

    let mut config = v1::config_client::ConfigClient::new(channel.clone())
        .watch(v1::WatchRequest { from_revision: 0 })
        .await
        .expect("watch")
        .into_inner();
    let mut commands = v1::commands_client::CommandsClient::new(channel.clone())
        .subscribe(v1::SubscribeRequest {
            after: String::new(),
        })
        .await
        .expect("subscribe")
        .into_inner();
    let (beats, inbound) = tokio::sync::mpsc::channel::<v1::Beat>(4);
    let mut directives = v1::node_client::NodeClient::new(channel.clone())
        .heartbeat(futures::stream::unfold(inbound, |mut inbound| async move {
            inbound.recv().await.map(|beat| (beat, inbound))
        }))
        .await
        .expect("heartbeat")
        .into_inner();
    // The node beats every 50 ms for as long as the test runs.
    let beating = tokio::spawn(async move {
        let mut sequence = 0;
        loop {
            sequence += 1;
            let beat = v1::Beat {
                sequence,
                version: "0.0.1".to_owned(),
                ..v1::Beat::default()
            };
            if beats.send(beat).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    wait_until_async("the heartbeat session", async || {
        controller.registry.sessions().view(node).is_some()
    })
    .await;

    forget_node(&controller, node).await;
    assert_eq!(
        ended_with("configuration", &mut config).await.as_deref(),
        Some("cluster.node.unknown")
    );
    assert_eq!(
        ended_with("command", &mut commands).await.as_deref(),
        Some("cluster.node.unknown")
    );
    assert_eq!(
        ended_with("heartbeat", &mut directives).await.as_deref(),
        Some("cluster.node.unknown")
    );
    beating.abort();
}

// ---------------------------------------------------------------------------------------
// Renewal: the window, the pace and the certificates a renewal replaces
// ---------------------------------------------------------------------------------------

/// The node record of `node`.
async fn node_record(registry: &NodeRegistry, node: NodeId) -> model::NodeRecord {
    registry
        .record(node)
        .await
        .expect("read")
        .expect("the node record")
        .0
}

/// `days` days before `at`.
fn days_before(at: Timestamp, days: u64) -> Timestamp {
    Timestamp(at.0 - Duration::from_secs(days * 86_400))
}

/// A renewal is accepted only inside the renewal window of the calling certificate: from a
/// third of its lifetime (or 30 days) before its expiry.
#[tokio::test]
async fn a_renewal_before_the_window_is_refused() {
    let (_, registry, node, serial, csr) = racing_registry().await;
    let record = node_record(&registry, node).await;
    let error = registry
        .renew(node, &serial, &csr, Timestamp::now())
        .await
        .expect_err("not due yet");
    assert_eq!(error.code(), "cluster.node.renew_not_due");
    assert_eq!(error.status(), 409);
    // A year's certificate is due 121 days before it expires, not 125.
    let early = days_before(record.certificate.not_after, 125);
    assert_eq!(
        registry
            .renew(node, &serial, &csr, early)
            .await
            .expect_err("still early")
            .code(),
        "cluster.node.renew_not_due"
    );
    let due = days_before(record.certificate.not_after, 121);
    registry.renew(node, &serial, &csr, due).await.expect("due");
    assert_eq!(node_record(&registry, node).await.serials.len(), 2);
}

/// A node renews at most once an hour; a renewal keeps only the calling certificate beside
/// the new one, so the record and a revocation stay small however often a node renews.
#[tokio::test]
async fn renewals_are_paced_and_keep_two_certificates() {
    let (_, registry, node, serial, csr) = racing_registry().await;
    let enrolled = node_record(&registry, node).await;
    let mut now = days_before(enrolled.certificate.not_after, 10);
    let first = registry
        .renew(node, &serial, &csr, now)
        .await
        .expect("first renewal");
    let error = registry
        .renew(
            node,
            &serial,
            &csr,
            now.checked_add(Duration::from_secs(60)).expect("time"),
        )
        .await
        .expect_err("a minute later");
    assert_eq!(error.code(), "cluster.node.renew_too_soon");
    assert_eq!(error.status(), 409);
    // The answer was lost: the node asks again with the certificate it still has, every
    // hour, and gets one each time; the record never holds more than two.
    let mut last = first.info.serial.clone();
    for _ in 0..12 {
        now = now
            .checked_add(registry::RENEW_INTERVAL + Duration::from_secs(1))
            .expect("time");
        let issued = registry
            .renew(node, &serial, &csr, now)
            .await
            .expect("an hour later");
        let record = node_record(&registry, node).await;
        let serials: Vec<&str> = record
            .serials
            .iter()
            .map(|cert| cert.serial.as_str())
            .collect();
        assert_eq!(serials, [serial.as_str(), issued.info.serial.as_str()]);
        assert_ne!(issued.info.serial, last);
        last = issued.info.serial.clone();
    }
    // The certificate of a renewal that never reached the node no longer works.
    assert_eq!(
        registry
            .authenticate(node, &first.info.serial, now)
            .await
            .expect_err("dropped")
            .code(),
        "cluster.node.certificate_unknown"
    );
    let revoked = registry.revoke(&system(), node).await.expect("revoke");
    assert_eq!(revoked.len(), 2);
}

/// Once the node shows that it holds the newest certificate, the certificates the renewal
/// replaced work for [`registry::RETIRE_GRACE`] more and are refused afterwards with a code
/// that sends the node to connect again.
#[tokio::test]
async fn the_replaced_certificate_retires_once_the_node_holds_the_new_one() {
    let (_, registry, node, serial, csr) = racing_registry().await;
    let enrolled = node_record(&registry, node).await;
    let now = days_before(enrolled.certificate.not_after, 10);
    let issued = registry
        .renew(node, &serial, &csr, now)
        .await
        .expect("renewal");
    // A report of another certificate changes nothing.
    assert!(
        !registry
            .retire_replaced(node, enrolled.certificate.not_after, now)
            .await
            .expect("retire")
    );
    let later = now
        .checked_add(registry::RETIRE_GRACE + Duration::from_secs(1))
        .expect("time");
    registry
        .authenticate(node, &serial, later)
        .await
        .expect("no proof yet: the old certificate keeps working");

    assert!(
        registry
            .retire_replaced(node, issued.info.not_after, now)
            .await
            .expect("retire")
    );
    registry
        .authenticate(node, &serial, now)
        .await
        .expect("inside the grace");
    let error = registry
        .authenticate(node, &serial, later)
        .await
        .expect_err("retired");
    assert_eq!(error.code(), "cluster.node.certificate_replaced");
    assert_eq!(error.status(), 503);
    registry
        .authenticate(node, &issued.info.serial, later)
        .await
        .expect("the new certificate");
    // Retiring again finds nothing left to retire.
    assert!(
        registry
            .retire_replaced(node, issued.info.not_after, now)
            .await
            .expect("retire")
    );
    // A revocation after the grace still lists the retired certificate: it has not
    // expired, so the TLS verifier must refuse it too.
    let mut cx = system();
    cx.now = later;
    let revoked = registry.revoke(&cx, node).await.expect("revoke");
    assert!(revoked.contains(&serial), "{revoked:?}");
    assert!(registry.revocations().is_revoked(&serial));
    assert!(registry.revocations().is_revoked(&issued.info.serial));
}

/// A node renews by itself over its connection, reports the new certificate on its next
/// beat, and moves to it: the old one is retired, the old connection's streams end, and the
/// node connects again with the new certificate without a refusal.
#[tokio::test]
async fn a_node_renews_and_moves_to_its_new_certificate() {
    let controller = Controller::start_with(CaPolicy {
        node_validity_days: 20,
        ..CaPolicy::default()
    })
    .await;
    controller.registry.set_timings(registry::Timings {
        stream_recheck: Duration::from_millis(100),
        retire_grace: Duration::from_millis(300),
        ..registry::Timings::default()
    });
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enroll(dir.path(), "probe-moves").await;
    let node = credentials.identity.node;
    // Expiries have whole seconds: the renewed certificate must end later than this one.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let agent = agent(dir.path());
    let (stop, task) = run(&agent);
    wait_until_async("the renewal", async || {
        Credentials::load(&NodePaths::new(dir.path()))
            .is_ok_and(|now| now.info.serial != credentials.info.serial)
    })
    .await;
    let renewed = Credentials::load(&NodePaths::new(dir.path())).expect("load");
    let renewed_by = Timestamp::now();
    let refused = std::cell::Cell::new(false);
    wait_until_async("the node to move to its new certificate", async || {
        let status = agent.status();
        if matches!(status.state, AgentState::Refused | AgentState::Revoked) {
            refused.set(true);
        }
        let moved = controller
            .registry
            .sessions()
            .view(node)
            .is_some_and(|live| {
                live.since > renewed_by
                    && live.certificate_not_after == Some(renewed.info.not_after)
            });
        let retired = controller
            .registry
            .authenticate(node, &credentials.info.serial, Timestamp::now())
            .await
            .is_err();
        if moved && retired && status.state == AgentState::Connected {
            Ok(())
        } else {
            Err(format!("moved {moved}, retired {retired}: {status:?}"))
        }
    })
    .await;
    assert!(!refused.get(), "the node was refused on the way");
    let _ = stop.send(true);
    task.await.expect("agent");
}

/// A record that collected many certificates before renewals kept two is cut back to the
/// newest and the one before it by the maintenance pass, so it stays revocable in one
/// write.
#[tokio::test]
async fn the_maintenance_pass_trims_a_record_with_many_certificates() {
    let (store, registry, node, serial, _) = racing_registry().await;
    let (mut record, revision) = registry
        .record(node)
        .await
        .expect("read")
        .expect("the record");
    let newest = record.certificate.clone();
    let mut older = Vec::new();
    for n in 0..200u32 {
        let mut cert = newest.clone();
        cert.serial = format!("{n:032x}");
        cert.not_after = days_before(newest.not_after, u64::from(200 - n));
        older.push(cert);
    }
    record.serials = older.clone();
    record.serials.push(newest.clone());
    let mut batch = WriteBatch::for_request(&system());
    batch.expect_typed(&model::tables::NODES, &node.0, Some(revision));
    batch
        .put_typed(&model::tables::NODES, &node.0, &record)
        .expect("row");
    store.inner.propose(batch).await.expect("write");

    registry.prune(Timestamp::now()).await.expect("prune");
    let trimmed = node_record(&registry, node).await;
    let serials: Vec<&str> = trimmed
        .serials
        .iter()
        .map(|cert| cert.serial.as_str())
        .collect();
    assert_eq!(serials, [older[199].serial.as_str(), serial.as_str()]);
    assert_eq!(
        registry
            .revoke(&system(), node)
            .await
            .expect("revoke")
            .len(),
        2
    );
}

/// The heartbeat answer asks for a renewal at most once an hour per stream: a node whose
/// renewal answer was lost is not sent to renew on every beat.
#[tokio::test]
async fn the_renewal_directive_is_paced() {
    let controller = Controller::start_with(CaPolicy {
        node_validity_days: 20,
        ..CaPolicy::default()
    })
    .await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enroll(dir.path(), "probe-paced").await;
    let channel = client::connect(
        &controller.addr.to_string(),
        credentials.client_config().expect("config"),
    )
    .await
    .expect("channel");
    let (beats, inbound) = tokio::sync::mpsc::channel::<v1::Beat>(8);
    let mut directives = v1::node_client::NodeClient::new(channel)
        .heartbeat(futures::stream::unfold(inbound, |mut inbound| async move {
            inbound.recv().await.map(|beat| (beat, inbound))
        }))
        .await
        .expect("heartbeat")
        .into_inner();
    let mut asked = 0;
    for sequence in 1..=5 {
        beats
            .send(v1::Beat {
                sequence,
                version: "0.0.1".to_owned(),
                certificate_not_after: Some(tenko_cluster::probe::timestamp_to_proto(
                    credentials.info.not_after,
                )),
                ..v1::Beat::default()
            })
            .await
            .expect("beat");
        let directive = tokio::time::timeout(WAIT, directives.message())
            .await
            .expect("an answer")
            .expect("ok")
            .expect("a directive");
        asked += usize::from(directive.renew);
    }
    assert_eq!(asked, 1);
}
