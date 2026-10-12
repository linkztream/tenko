//! The controller cluster on the cluster port (OPS-03, WP3.1a): the peers of a controller,
//! its membership in the Raft group, and the work the leader does for the group.
//!
//! [`Peers`] holds this controller's [`RaftStore`] and the [`PeerNetwork`] it replicates
//! over, and serves the `Raft` and `Cluster` services of the cluster port
//! ([`PeerService`]). It also implements [`ClusterAdmin`], the operations behind
//! `/cluster/*`.
//!
//! # Who may call
//!
//! Every caller presents a certificate of the installation's CA with the role
//! `controller` (the TLS verifier already refused other CAs and revoked serials). The
//! `Cluster` service then needs the caller's record in the node registry, holding the
//! presented certificate. The `Raft` service accepts a controller without a record as
//! long as this member has not replicated it yet (a learner catching up from an empty
//! store knows nobody); a record that exists must hold the certificate. A Raft message
//! must name its sender as the leader or candidate it speaks for.
//!
//! # Membership
//!
//! A controller joins as a learner: `Cluster.Join` (forwarded to the leader by any member)
//! records the member (`cluster.members`: its cluster port, version and data format) and
//! adds it to the Raft group without waiting. The leader promotes caught-up learners
//! (10 seconds below `[cluster] promote_lag_entries` and in contact) when
//! `[cluster] auto_promote` is on, and only to an odd number of voters: one voter and one
//! caught-up learner wait for a second learner (R21). An administrator promotes with
//! `force`, replaces a dead voter in one joint change (`replace`), removes a member (its
//! certificates are revoked) and hands leadership over before a planned restart
//! (step-down). Membership changes run on the leader; a follower hands them over
//! (`Cluster.Change`). A promotion or removal is an inline job `cluster.edit` (step
//! `cluster.member`) on the controller that took the request. The audit actions are
//! `cluster.member.join`, `.promote`, `.remove` and `.step_down`.
//!
//! The first controller has no node record and keeps its cluster key in the vault. When
//! the first peer joins, it records itself (node and member record) and moves its identity
//! to `<data_dir>/node/` ([`ControllerIdentity`]).

mod identity;
mod network;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, PoisonError, Weak},
    time::{Duration, Instant},
};

use tenko_core::{
    MessageKey, NodeId, ObjectRef, RequestCtx, Revision, Role, SystemComponent, Timestamp,
    audit::{AuditAction, AuditDraft},
    codec::{from_cbor, to_cbor},
    serde_util::HexBytes,
};
use tenko_jobs::{
    JobEngine, JobKind, JobSpec, StepContext, StepError, StepHandler, StepKind, StepOutcome,
    StepPreview, StepSpec,
};
use tenko_store::{
    KeyRange, MemberStatus, ReadConsistency, ReadView, ReadViewExt as _, Store as _, StoreError,
    StoreRole, WriteBatch,
    raft::{Membership, RaftStore},
};
use tokio::{sync::watch, task::JoinHandle};
use tonic::Status;
use uuid::Uuid;

pub use self::{
    identity::{ControllerIdentity, NodeDirIdentity, VaultIdentity, certificate_ref},
    network::{MAX_APPEND_BYTES, PeerNetwork, PeerTimings},
};
use crate::{
    admin::{
        ClusterAdmin, ClusterView, DigestReport, MemberDigest, MemberRole, MemberView,
        PromoteRequest, StepDown, member_not_found,
    },
    error::ClusterError,
    identity::split_host_port,
    kek::{KekSource, fetch_context, join_context, unavailable},
    model::{KekTransferRecord, MemberRecord, NodeRecord, ProtocolState, tables},
    mtls::PeerInfo,
    proto::v1,
    registry::{EDIT_JOB, EDIT_TITLE, NodeRegistry, WRITE_PREVIEW, check_name},
    server::{code_of, status_of},
    wire::{self, CLUSTER_WIRE, ChangeEnvelope, ChangeResult, MemberChange, RAFT_WIRE, WireCtx},
};

/// How long a learner stays caught up before the leader promotes it (default of
/// [`PeerConfig::promote_after`]).
pub const PROMOTE_AFTER: Duration = Duration::from_secs(10);
/// A learner counts as in contact while the leader heard from it within this time.
pub const CONTACT_WINDOW: Duration = Duration::from_secs(2);
/// How long a hand-over of leadership may take.
pub const STEP_DOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Audit actions of the controller cluster.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// A controller joined as a learner (or the first controller recorded itself).
    pub const MEMBER_JOIN: AuditAction = AuditAction::from_static("cluster.member.join");
    /// Learners became voters.
    pub const MEMBER_PROMOTE: AuditAction = AuditAction::from_static("cluster.member.promote");
    /// A member left the cluster.
    pub const MEMBER_REMOVE: AuditAction = AuditAction::from_static("cluster.member.remove");
    /// A member reported a changed binary (version, protocol majors, Raft wire version or
    /// data formats) after a start.
    pub const MEMBER_ANNOUNCE: AuditAction = AuditAction::from_static("cluster.member.announce");
    /// The leader handed leadership over.
    pub const MEMBER_STEP_DOWN: AuditAction = AuditAction::from_static("cluster.member.step_down");
    /// The key encryption keys went to a joining controller, or to a member that lacked
    /// generations (`tenko_vault::transfer::TRANSFER_AUDIT`).
    pub const KEK_TRANSFER: AuditAction = tenko_vault::transfer::TRANSFER_AUDIT;
}

/// Settings of the peer layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    /// This controller's node id (`[node] id`), also its Raft id.
    pub local: NodeId,
    /// Its cluster port as its peers reach it (`host:port`); empty: the address a joining
    /// controller reached it at.
    pub address: String,
    /// The software version.
    pub version: String,
    /// The data format the binary knows.
    pub data_format: u32,
    /// The data formats the binary can open, oldest first.
    pub formats: Vec<u32>,
    /// `[cluster] auto_promote`.
    pub auto_promote: bool,
    /// `[cluster] promote_lag_entries`.
    pub promote_lag_entries: u64,
    /// How long a learner stays caught up before it is promoted ([`PROMOTE_AFTER`]).
    pub promote_after: Duration,
}

impl PeerConfig {
    /// The defaults for controller `local`.
    pub fn new(local: NodeId, data_format: u32) -> Self {
        Self {
            local,
            address: String::new(),
            version: crate::version().to_owned(),
            data_format,
            formats: (1..=data_format).collect(),
            auto_promote: true,
            promote_lag_entries: 100,
            promote_after: PROMOTE_AFTER,
        }
    }
}

/// Replication figures of a member as the leader sees them: matched index, lag in
/// entries, milliseconds since the last contact.
type Figures = HashMap<NodeId, (Option<u64>, Option<u64>, Option<u64>)>;

/// What a peer may call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// The `Raft` service.
    Raft,
    /// The `Cluster` service.
    Member,
}

/// The peer layer of a controller. Cloning is cheap.
#[derive(Clone)]
pub struct Peers {
    inner: Arc<Inner>,
}

struct Inner {
    config: PeerConfig,
    store: RaftStore,
    network: PeerNetwork,
    registry: OnceLock<Arc<NodeRegistry>>,
    identity: OnceLock<Arc<dyn ControllerIdentity>>,
    kek: OnceLock<Arc<dyn KekSource>>,
    /// The job engine of this controller, once [`Peers::register_steps`] ran.
    jobs: OnceLock<JobEngine>,
    /// Learners and since when they are caught up (on the leader).
    caught_up: Mutex<HashMap<NodeId, Instant>>,
    /// One membership change at a time on this controller.
    changes: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Peers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peers")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

/// The `Raft` and `Cluster` services over the peer layer.
#[derive(Clone, Debug)]
pub struct PeerService {
    pub(crate) peers: Peers,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn system() -> RequestCtx {
    RequestCtx::system(SystemComponent::Cluster)
}

fn starting() -> ClusterError {
    ClusterError::new(
        "cluster.member.starting",
        503,
        "this controller is still starting; try again in a few seconds",
    )
}

fn not_leader() -> ClusterError {
    ClusterError::new(
        "cluster.member.not_leader",
        503,
        "no leader is known to take the change; try again when the cluster has elected one",
    )
}

fn changing() -> ClusterError {
    ClusterError::new(
        "cluster.member.changing",
        409,
        "another membership change is in progress; try again when it is done",
    )
}

/// A membership error of the store as a cluster error.
fn membership_error(error: &StoreError) -> ClusterError {
    match error {
        StoreError::NoQuorum => not_leader(),
        StoreError::Storage(detail) if detail.contains("in progress") => changing(),
        other => ClusterError::coded(other),
    }
}

/// The cluster error a refused `Cluster` call carries.
fn error_of_status(status: &Status) -> ClusterError {
    let code = code_of(status).unwrap_or("cluster.peer.call");
    let http = match status.code() {
        tonic::Code::InvalidArgument => 400,
        tonic::Code::Unauthenticated => 401,
        tonic::Code::PermissionDenied => 403,
        tonic::Code::NotFound => 404,
        tonic::Code::FailedPrecondition | tonic::Code::AlreadyExists => 409,
        tonic::Code::DeadlineExceeded => 504,
        tonic::Code::Unavailable => 503,
        _ => 500,
    };
    let mut error =
        tenko_core::CodedError::new("cluster.peer.call", http, status.message().to_owned());
    error.code = std::borrow::Cow::Owned(code.to_owned());
    error.into()
}

impl Peers {
    /// The peer layer over `store`, which from now on replicates over `network`.
    pub fn new(store: RaftStore, network: PeerNetwork, config: PeerConfig) -> Self {
        network.attach(&store);
        store.set_transport(Arc::new(network.clone()));
        Self {
            inner: Arc::new(Inner {
                config,
                store,
                network,
                registry: OnceLock::new(),
                identity: OnceLock::new(),
                kek: OnceLock::new(),
                jobs: OnceLock::new(),
                caught_up: Mutex::new(HashMap::new()),
                changes: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// The settings.
    pub fn config(&self) -> &PeerConfig {
        &self.inner.config
    }

    /// Registers the step `cluster.member`: from now on a promotion or removal through
    /// [`ClusterAdmin`] runs as an inline job `cluster.edit`, whose id the answer carries.
    pub fn register_steps(&self, engine: &JobEngine) {
        let mut registered = engine.clone();
        registered.register(Arc::new(MemberStep {
            peers: Arc::downgrade(&self.inner),
        }));
        let _ = self.inner.jobs.set(engine.clone());
    }

    /// A promotion or removal, as an inline job `cluster.edit` once the job engine is
    /// registered: the step hands the change to the leader and records the members after it.
    async fn change_as_job(
        &self,
        cx: &RequestCtx,
        node: NodeId,
        change: MemberChange,
    ) -> Result<ClusterView, ClusterError> {
        let Some(engine) = self.inner.jobs.get() else {
            return view_of(self.apply_change(cx, change).await?);
        };
        let spec = JobSpec {
            kind: JobKind::from_static(EDIT_JOB),
            title: MessageKey::from_static(EDIT_TITLE),
            targets: vec![ObjectRef::node(node)],
            steps: vec![StepSpec {
                kind: StepKind::from_static(MEMBER_STEP),
                params: HexBytes(to_cbor(&change)?.to_vec()),
                timeout: None,
            }],
            timeout: MEMBER_JOB_TIMEOUT,
            group: None,
            group_limit: None,
            idempotency: None,
            node: None,
        };
        let job = engine.run_inline(spec, cx).await?;
        let output = job
            .steps
            .first()
            .and_then(|step| step.output.as_ref())
            .ok_or_else(|| ClusterError::internal("the membership change recorded no members"))?;
        let mut view: ClusterView = from_cbor(&output.0)?;
        view.job_id = Some(job.id);
        Ok(view)
    }

    /// The store.
    pub fn store(&self) -> &RaftStore {
        &self.inner.store
    }

    /// The transport.
    pub fn network(&self) -> &PeerNetwork {
        &self.inner.network
    }

    /// The services of the cluster port.
    pub fn service(&self) -> PeerService {
        PeerService {
            peers: self.clone(),
        }
    }

    /// Hands over the node registry (the `nodes` start step): joins, membership changes
    /// and key transfers need it.
    pub fn attach_registry(&self, registry: Arc<NodeRegistry>) {
        let _ = self.inner.registry.set(registry);
    }

    /// Hands over this controller's identity (the first controller's key moves at the
    /// first join).
    pub fn attach_identity(&self, identity: Arc<dyn ControllerIdentity>) {
        let _ = self.inner.identity.set(identity);
    }

    /// Hands over the key encryption keys a joining controller receives.
    pub fn attach_kek(&self, source: Arc<dyn KekSource>) {
        let _ = self.inner.kek.set(source);
    }

    /// Whether the Raft group has another node besides this one.
    pub fn is_member(&self) -> bool {
        let membership = self.store().membership();
        membership.voters.len() + membership.learners.len() > 1
    }

    fn local(&self) -> NodeId {
        self.inner.config.local
    }

    fn registry(&self) -> Result<&Arc<NodeRegistry>, ClusterError> {
        self.inner.registry.get().ok_or_else(starting)
    }

    fn leads(&self) -> bool {
        self.store().current_leader() == Some(self.local())
    }

    /// Starts the leader's background work: promotion of caught-up learners. It ends when
    /// `stop` turns true.
    pub fn spawn(&self, stop: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
        vec![tokio::spawn(promote_loop(self.clone(), stop))]
    }

    // -----------------------------------------------------------------------------------
    // Authentication.

    /// Checks a caller of the `Raft` or `Cluster` service; returns its node record when
    /// this member knows it.
    pub(crate) async fn authenticate(
        &self,
        peer: &PeerInfo,
        access: Access,
    ) -> Result<Option<NodeRecord>, Status> {
        let node = peer.identity.node;
        if !peer.identity.roles.contains(Role::Controller) {
            return Err(status_of(&ClusterError::new(
                "cluster.peer.not_controller",
                403,
                format!("node {node} is not a controller; the controller services refuse it"),
            )));
        }
        let mut record = self
            .node_record(node, ReadConsistency::Local)
            .await
            .map_err(|error| status_of(&error))?;
        if record.is_none() && access == Access::Member {
            // Enrolled through another controller a moment ago: ask the leader.
            record = self
                .node_record(node, ReadConsistency::Linearizable)
                .await
                .unwrap_or(None);
        }
        match record {
            Some(record) => {
                if !record.roles.contains(&Role::Controller)
                    || !record.holds(&peer.identity.serial, Timestamp::now())
                {
                    return Err(status_of(&ClusterError::new(
                        "cluster.node.certificate_unknown",
                        403,
                        "the certificate is not one this controller was issued, or it expired",
                    )));
                }
                Ok(Some(record))
            }
            None if access == Access::Raft => Ok(None),
            None => Err(status_of(&ClusterError::new(
                "cluster.node.unknown",
                403,
                format!("controller {node} is not enrolled in this installation"),
            ))),
        }
    }

    async fn node_record(
        &self,
        node: NodeId,
        consistency: ReadConsistency,
    ) -> Result<Option<NodeRecord>, ClusterError> {
        let view = self.store().read(consistency).await?;
        Ok(view
            .get_typed(&tables::NODES, &node.0)?
            .map(|(record, _)| record))
    }

    async fn member_records(&self) -> Result<BTreeMap<NodeId, MemberRecord>, ClusterError> {
        let view = self.store().read(ReadConsistency::Local).await?;
        Ok(view
            .scan_typed(&tables::MEMBERS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(node, record, _)| (NodeId(node), record))
            .collect())
    }

    // -----------------------------------------------------------------------------------
    // Joining.

    /// `Cluster.Join`: adds an enrolled controller as a learner (on the leader; any other
    /// member forwards). `local_addr` is where the call arrived: the first controller's
    /// cluster port as the joiner reached it, used when no address is configured.
    pub(crate) async fn join(
        &self,
        request: v1::JoinRequest,
        local_addr: Option<SocketAddr>,
    ) -> Result<v1::JoinResponse, ClusterError> {
        let node = NodeId(request.node_id);
        if node.0 == 0 || split_host_port(&request.address).is_err() {
            return Err(ClusterError::new(
                "cluster.join.request",
                400,
                "a join names the joining controller and its cluster port as host:port",
            ));
        }
        let record = match self.node_record(node, ReadConsistency::Local).await? {
            Some(record) => Some(record),
            None => {
                self.node_record(node, ReadConsistency::Linearizable)
                    .await?
            }
        };
        if !record.is_some_and(|record| record.roles.contains(&Role::Controller)) {
            return Err(ClusterError::new(
                "cluster.join.not_controller",
                403,
                format!(
                    "node {node} was not enrolled as a controller; enrol it with a controller token"
                ),
            ));
        }
        let format = self.stored_format().await?;
        if let Some(format) = format
            && format > request.data_format
        {
            return Err(ClusterError::new(
                "cluster.join.format_newer",
                409,
                format!(
                    "the cluster's data is in format {format}, which the joining binary (format \
                     {}) does not know; upgrade the joining controller first",
                    request.data_format
                ),
            )
            .with_param("cluster", format.to_string())
            .with_param("joiner", request.data_format.to_string()));
        }
        if !self.leads() {
            let leader = self.store().current_leader().ok_or_else(not_leader)?;
            let mut client = self.network().cluster_client(leader).await?;
            return client
                .join(tonic::Request::new(request))
                .await
                .map(tonic::Response::into_inner)
                .map_err(|status| error_of_status(&status));
        }
        let registry = Arc::clone(self.registry()?);
        let _change = self.inner.changes.lock().await;
        self.register_self(&registry, local_addr).await?;
        self.record_member(&registry, &request).await?;
        self.network().forget(node);
        let membership = self.store().membership();
        if !membership.voters.contains(&node) && !membership.learners.contains(&node) {
            self.store()
                .add_learner(node, request.address.clone(), false)
                .await
                .map_err(|error| membership_error(&error))?;
            tracing::info!(node = %node, address = %request.address, "a controller joined as a learner");
        }
        let view = self.view_local(None).await?;
        Ok(v1::JoinResponse {
            leader_id: self.local().0,
            term: view.term,
            members: view.members.iter().map(member_proto).collect(),
        })
    }

    /// Writes the member record of a joining controller: new with an audit record, or
    /// updated quietly when its address, version or format changed.
    async fn record_member(
        &self,
        registry: &Arc<NodeRegistry>,
        request: &v1::JoinRequest,
    ) -> Result<(), ClusterError> {
        let node = NodeId(request.node_id);
        let records = self.member_records().await?;
        let fresh = MemberRecord {
            node,
            address: request.address.clone(),
            version: request.version.clone(),
            data_format: request.data_format,
            joined_at: Timestamp::now(),
            protocol_majors: Vec::new(),
            raft_wire: None,
            formats: Vec::new(),
        };
        match records.get(&node) {
            None => {
                let mut batch = WriteBatch::for_request(&system());
                batch.expect_typed(&tables::MEMBERS, &node.0, None);
                batch.put_typed(&tables::MEMBERS, &node.0, &fresh)?;
                batch.audit(
                    AuditDraft::success(actions::MEMBER_JOIN, vec![ObjectRef::node(node)])
                        .with_context("address", request.address.clone())
                        .with_context("version", request.version.clone())
                        .with_context("data_format", request.data_format.to_string()),
                );
                registry
                    .commit(
                        &system(),
                        format!("controller {node} joins the cluster"),
                        vec![ObjectRef::node(node)],
                        batch,
                    )
                    .await?;
            }
            Some(known)
                if known.address != fresh.address
                    || known.version != fresh.version
                    || known.data_format != fresh.data_format =>
            {
                // What the member reported at its own start stays until it reports again.
                let updated = MemberRecord {
                    joined_at: known.joined_at,
                    protocol_majors: known.protocol_majors.clone(),
                    raft_wire: known.raft_wire.clone(),
                    formats: known.formats.clone(),
                    ..fresh
                };
                let mut batch = WriteBatch::for_request(&system());
                batch.put_typed(&tables::MEMBERS, &node.0, &updated)?;
                self.store().propose(batch).await?;
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// The member record this controller writes about itself.
    fn own_record(&self, address: String, joined_at: Timestamp) -> MemberRecord {
        let config = &self.inner.config;
        MemberRecord {
            node: config.local,
            address,
            version: config.version.clone(),
            data_format: config.data_format,
            joined_at,
            protocol_majors: crate::version::SUPPORTED_MAJORS.to_vec(),
            raft_wire: Some(RAFT_WIRE.to_owned()),
            formats: config.formats.clone(),
        }
    }

    /// Reports this controller's binary in its member record after a start: the version,
    /// the protocol majors, the Raft wire version and the data formats it knows (OPS-08).
    /// The record changes only when one of them differs; the write is forwarded to the
    /// leader like any other. Returns whether the record was written; `Ok(false)` also for
    /// a controller without a member record (a single controller).
    ///
    /// # Errors
    ///
    /// The read or the write failed (no quorum, no leader yet): try again later.
    pub async fn announce(&self) -> Result<bool, ClusterError> {
        let me = self.local();
        let view = self.store().read(ReadConsistency::Linearizable).await?;
        let Some((known, revision)) = view.get_typed(&tables::MEMBERS, &me.0)? else {
            return Ok(false);
        };
        drop(view);
        let fresh = self.own_record(known.address.clone(), known.joined_at);
        if fresh == known {
            return Ok(false);
        }
        let mut batch = WriteBatch::for_request(&system());
        batch.expect_typed(&tables::MEMBERS, &me.0, Some(revision));
        batch.put_typed(&tables::MEMBERS, &me.0, &fresh)?;
        batch.audit(
            AuditDraft::success(actions::MEMBER_ANNOUNCE, vec![ObjectRef::node(me)])
                .with_context("version", fresh.version.clone())
                .with_context("previous_version", known.version.clone())
                .with_context("data_format", fresh.data_format.to_string()),
        );
        self.store().propose(batch).await?;
        tracing::info!(
            version = %fresh.version,
            previous = %known.version,
            data_format = fresh.data_format,
            "reported this controller's binary in its member record"
        );
        Ok(true)
    }

    /// The format the stored data is in (`sys.format`), if recorded.
    async fn stored_format(&self) -> Result<Option<u32>, ClusterError> {
        let view = self.store().read(ReadConsistency::Local).await?;
        Ok(tenko_store::format::read_stored(view.as_ref())?.map(|(stored, _)| stored.version))
    }

    /// Records this controller as a member (node record and member record) and moves its
    /// identity out of the vault, once: at the first join.
    async fn register_self(
        &self,
        registry: &Arc<NodeRegistry>,
        local_addr: Option<SocketAddr>,
    ) -> Result<(), ClusterError> {
        let me = self.local();
        let view = self.store().read(ReadConsistency::Local).await?;
        let node = view.get_typed(&tables::NODES, &me.0)?;
        let member = view.get_typed(&tables::MEMBERS, &me.0)?;
        drop(view);
        if node.is_some() && member.is_some() {
            return Ok(());
        }
        let identity = self.inner.identity.get().ok_or_else(starting)?;
        let address = if self.inner.config.address.is_empty() {
            local_addr.map(|addr| addr.to_string()).ok_or_else(|| {
                ClusterError::new(
                    "cluster.member.no_address",
                    409,
                    "this controller does not know the address of its cluster port; set \
                         [node] address or [cluster] advertise",
                )
            })?
        } else {
            self.inner.config.address.clone()
        };
        let certificate = identity.portable().await?;
        let now = Timestamp::now();
        let ctx = system();
        let mut batch = WriteBatch::for_request(&ctx);
        if node.is_none() {
            let mut name = identity.name();
            if check_name(&name).is_err() {
                name = format!("controller-{}", me.0);
            }
            let view = self.store().read(ReadConsistency::Local).await?;
            if view
                .get_typed(&tables::NODE_NAMES, &name.to_lowercase())?
                .is_some()
            {
                name = format!("{name}-{}", me.0);
            }
            drop(view);
            let record = NodeRecord {
                id: me,
                name: name.clone(),
                roles: vec![Role::Controller],
                address: Some(address.clone()),
                vrf: None,
                certificate: certificate.clone(),
                serials: vec![certificate],
                enrolled_at: now,
                enrolment: Uuid::nil(),
                enrolled_by: None,
                renewed_at: None,
                last_seen: None,
                version: Some(self.inner.config.version.clone()),
                protocol: ProtocolState::default(),
            };
            batch.expect_typed(&tables::NODES, &me.0, None);
            batch.put_typed(&tables::NODES, &me.0, &record)?;
            batch.expect_typed(&tables::NODE_NAMES, &name.to_lowercase(), None);
            batch.put_typed(&tables::NODE_NAMES, &name.to_lowercase(), &me.0)?;
        }
        if member.is_none() {
            batch.expect_typed(&tables::MEMBERS, &me.0, None);
            batch.put_typed(
                &tables::MEMBERS,
                &me.0,
                &self.own_record(address.clone(), now),
            )?;
        }
        batch.audit(
            AuditDraft::success(actions::MEMBER_JOIN, vec![ObjectRef::node(me)])
                .with_context("address", address)
                .with_context("first", "true".to_owned()),
        );
        registry
            .commit(
                &ctx,
                format!("controller {me} records itself as the first member"),
                vec![ObjectRef::node(me)],
                batch,
            )
            .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------------------
    // Views.

    /// The replication figures by member from the leader: this controller's status when it
    /// leads, else the leader's `Members` answer (none when it cannot be asked).
    async fn figures(&self) -> Figures {
        let status = self.store().status();
        if status.role == StoreRole::Leader {
            return status
                .members
                .iter()
                .map(|member| {
                    (
                        member.node,
                        (member.matched, member.lag_entries, member.last_contact_ms),
                    )
                })
                .collect();
        }
        let Some(leader) = status.leader else {
            return HashMap::new();
        };
        let asked = async {
            let mut client = self.network().cluster_client(leader).await.ok()?;
            let answer = tokio::time::timeout(
                Duration::from_secs(2),
                client.members(tonic::Request::new(v1::MembersRequest {})),
            )
            .await
            .ok()?
            .ok()?;
            Some(answer.into_inner())
        };
        asked
            .await
            .map(|answer| {
                answer
                    .members
                    .into_iter()
                    .map(|member| {
                        (
                            NodeId(member.node_id),
                            (member.matched, member.lag_entries, None),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The cluster as this controller sees it, with the replication figures given.
    async fn view_local(&self, figures: Option<Figures>) -> Result<ClusterView, ClusterError> {
        let status = self.store().status();
        let membership = self.store().membership();
        let records = self.member_records().await?;
        let names: HashMap<NodeId, String> = {
            let view = self.store().read(ReadConsistency::Local).await?;
            membership
                .voters
                .iter()
                .chain(&membership.learners)
                .filter_map(|node| {
                    view.get_typed(&tables::NODES, &node.0)
                        .ok()
                        .flatten()
                        .map(|(record, _)| (*node, record.name))
                })
                .collect()
        };
        let figures = match figures {
            Some(figures) => figures,
            None => status
                .members
                .iter()
                .map(|member| {
                    (
                        member.node,
                        (member.matched, member.lag_entries, member.last_contact_ms),
                    )
                })
                .collect(),
        };
        let members = membership
            .voters
            .iter()
            .map(|node| (*node, MemberRole::Voter))
            .chain(
                membership
                    .learners
                    .iter()
                    .map(|node| (*node, MemberRole::Learner)),
            )
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .map(|(node, role)| {
                let record = records.get(&node);
                let (matched, lag_entries, last_contact_ms) =
                    figures.get(&node).copied().unwrap_or((None, None, None));
                MemberView {
                    node,
                    name: names.get(&node).cloned(),
                    address: record.map(|record| record.address.clone()),
                    role,
                    leader: status.leader == Some(node),
                    matched,
                    lag_entries,
                    last_contact_ms,
                    version: record.map(|record| record.version.clone()),
                    data_format: record.map(|record| record.data_format),
                    joined_at: record.map(|record| record.joined_at),
                    protocol_majors: record
                        .map(|record| record.protocol_majors.clone())
                        .unwrap_or_default(),
                    raft_wire: record.and_then(|record| record.raft_wire.clone()),
                    formats: record
                        .map(|record| record.formats.clone())
                        .unwrap_or_default(),
                }
            })
            .collect();
        Ok(ClusterView {
            node: self.local(),
            leader: status.leader,
            term: status.term,
            quorum: status.quorum.into(),
            changing: membership.changing,
            members,
            job_id: None,
        })
    }

    /// `Cluster.Members`: the members as this controller sees them.
    pub(crate) async fn members_proto(&self) -> Result<v1::MembersResponse, ClusterError> {
        let view = self.view_local(None).await?;
        Ok(v1::MembersResponse {
            leader_id: view.leader.map_or(0, |leader| leader.0),
            term: view.term,
            members: view.members.iter().map(member_proto).collect(),
        })
    }

    // -----------------------------------------------------------------------------------
    // Membership changes (on the leader).

    /// Whether the leader sees `node` caught up and in contact now.
    fn in_step(&self, member: Option<&MemberStatus>) -> bool {
        member.is_some_and(|member| {
            member
                .lag_entries
                .is_some_and(|lag| lag <= self.inner.config.promote_lag_entries)
                && member
                    .last_contact_ms
                    .is_some_and(|ms| Duration::from_millis(ms) <= CONTACT_WINDOW)
        })
    }

    fn member_status(&self, node: NodeId) -> Option<MemberStatus> {
        self.store()
            .status()
            .members
            .into_iter()
            .find(|member| member.node == node)
    }

    /// Changes the voters and audits the change.
    async fn set_voters(
        &self,
        cx: &RequestCtx,
        voters: BTreeSet<NodeId>,
        action: AuditAction,
        targets: &[NodeId],
        context: Vec<(&'static str, String)>,
    ) -> Result<(), ClusterError> {
        self.store()
            .set_voters(voters.clone(), true)
            .await
            .map_err(|error| membership_error(&error))?;
        let mut draft = AuditDraft::success(
            action.clone(),
            targets.iter().copied().map(ObjectRef::node).collect(),
        )
        .with_source_ip(cx.source_ip)
        .with_context(
            "voters",
            voters
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        for (key, value) in context {
            draft = draft.with_context(key, value);
        }
        // A plain write: the Raft change cannot commit with it, and a change an
        // administrator asked for is already the inline job `cluster.edit`.
        let mut batch = WriteBatch::for_request(cx);
        batch.audit(draft);
        if let Err(error) = self.store().propose(batch).await {
            tracing::warn!(%error, "a membership change could not be audited");
        }
        Ok(())
    }

    /// Promotes learners that stayed caught up long enough, to an odd number of voters.
    async fn auto_promote(&self) -> Result<(), ClusterError> {
        let membership = self.store().membership();
        if membership.changing {
            return Ok(());
        }
        let status = self.store().status();
        let eligible: Vec<NodeId> = {
            let mut caught = lock(&self.inner.caught_up);
            caught.retain(|node, _| membership.learners.contains(node));
            for learner in &membership.learners {
                let member = status.members.iter().find(|member| member.node == *learner);
                if self.in_step(member) {
                    caught.entry(*learner).or_insert_with(Instant::now);
                } else {
                    caught.remove(learner);
                }
            }
            let mut eligible: Vec<(u64, NodeId)> = caught
                .iter()
                .filter(|(_, since)| since.elapsed() >= self.inner.config.promote_after)
                .map(|(node, _)| {
                    let lag = status
                        .members
                        .iter()
                        .find(|member| member.node == *node)
                        .and_then(|member| member.lag_entries)
                        .unwrap_or(u64::MAX);
                    (lag, *node)
                })
                .collect();
            eligible.sort();
            eligible.into_iter().map(|(_, node)| node).collect()
        };
        let take = odd_promotions(membership.voters.len(), eligible.len());
        if take == 0 {
            return Ok(());
        }
        let chosen = &eligible[..take];
        let _change = self.inner.changes.lock().await;
        let mut voters = membership.voters.clone();
        voters.extend(chosen.iter().copied());
        self.set_voters(
            &system(),
            voters,
            actions::MEMBER_PROMOTE,
            chosen,
            vec![("automatic", "true".to_owned())],
        )
        .await?;
        lock(&self.inner.caught_up).retain(|node, _| !chosen.contains(node));
        tracing::info!(promoted = %list(chosen), "caught-up learners became voters");
        Ok(())
    }

    async fn promote_here(
        &self,
        cx: &RequestCtx,
        node: NodeId,
        request: PromoteRequest,
    ) -> Result<ClusterView, ClusterError> {
        let _change = self.inner.changes.lock().await;
        let membership = self.store().membership();
        if membership.changing {
            return Err(changing());
        }
        if membership.voters.contains(&node) && request.replace.is_none() {
            return self.view_local(None).await;
        }
        if !membership.learners.contains(&node) {
            return Err(member_not_found(node));
        }
        let mut voters = membership.voters.clone();
        let mut targets = vec![node];
        if let Some(dead) = request.replace {
            if !voters.contains(&dead) {
                return Err(member_not_found(dead));
            }
            if dead == self.local() {
                return Err(is_leader(dead));
            }
            voters.remove(&dead);
            targets.push(dead);
        }
        voters.insert(node);
        if !request.force {
            if voters.len().is_multiple_of(2) {
                return Err(ClusterError::new(
                    "cluster.member.even_voters",
                    409,
                    format!(
                        "the promotion would leave {} voters; an even number is less available \
                         than one fewer: promote two learners together, or pass force",
                        voters.len()
                    ),
                )
                .with_param("voters", voters.len().to_string()));
            }
            if !self.in_step(self.member_status(node).as_ref()) {
                return Err(ClusterError::new(
                    "cluster.member.not_caught_up",
                    409,
                    format!(
                        "controller {node} is behind or out of contact; wait until it caught \
                         up, or pass force"
                    ),
                )
                .with_param("node", node.to_string()));
            }
        }
        let mut context = vec![("force", request.force.to_string())];
        if let Some(dead) = request.replace {
            context.push(("replaced", dead.to_string()));
        }
        self.set_voters(cx, voters, actions::MEMBER_PROMOTE, &targets, context)
            .await?;
        if let Some(dead) = request.replace {
            self.forget_member(cx, dead).await;
        }
        self.view_local(None).await
    }

    async fn remove_here(
        &self,
        cx: &RequestCtx,
        node: NodeId,
    ) -> Result<ClusterView, ClusterError> {
        if node == self.local() {
            return Err(is_leader(node));
        }
        let _change = self.inner.changes.lock().await;
        let membership = self.store().membership();
        if membership.changing {
            return Err(changing());
        }
        if membership.voters.contains(&node) {
            let voters: BTreeSet<NodeId> = membership
                .voters
                .iter()
                .copied()
                .filter(|voter| *voter != node)
                .collect();
            if voters.is_empty() {
                return Err(ClusterError::new(
                    "cluster.member.last_voter",
                    409,
                    "the cluster cannot lose its last voter",
                ));
            }
            self.store()
                .set_voters(voters, false)
                .await
                .map_err(|error| membership_error(&error))?;
        } else if membership.learners.contains(&node) {
            self.store()
                .remove_learner(node)
                .await
                .map_err(|error| membership_error(&error))?;
        } else if !self.member_records().await?.contains_key(&node) {
            return Err(member_not_found(node));
        }
        let mut batch = WriteBatch::for_request(cx);
        batch.delete_typed(&tables::MEMBERS, &node.0);
        batch.audit(
            AuditDraft::success(actions::MEMBER_REMOVE, vec![ObjectRef::node(node)])
                .with_source_ip(cx.source_ip),
        );
        self.store().propose(batch).await?;
        self.forget_member(cx, node).await;
        self.view_local(None).await
    }

    /// Drops the member record of a node that left and revokes its certificates.
    async fn forget_member(&self, cx: &RequestCtx, node: NodeId) {
        lock(&self.inner.caught_up).remove(&node);
        self.network().forget(node);
        let mut batch = WriteBatch::for_request(cx);
        batch.delete_typed(&tables::MEMBERS, &node.0);
        if let Err(error) = self.store().propose(batch).await {
            tracing::warn!(node = %node, %error, "the member record could not be removed");
        }
        if let Ok(registry) = self.registry() {
            match registry.revoke(cx, node).await {
                Ok(serials) => {
                    tracing::warn!(node = %node, count = serials.len(), "the certificates of a removed controller are revoked");
                }
                Err(error) if error.code() == "cluster.node.not_found" => {}
                Err(error) => {
                    tracing::warn!(node = %node, code = %error.code(), "the certificates of a removed controller could not be revoked: {}", error.detail());
                }
            }
        }
    }

    async fn step_down_here(&self, cx: &RequestCtx) -> Result<StepDown, ClusterError> {
        let _change = self.inner.changes.lock().await;
        let me = self.local();
        let leader = self.hand_over().await?;
        let term = self.store().status().term;
        let mut batch = WriteBatch::for_request(cx);
        batch.audit(
            AuditDraft::success(actions::MEMBER_STEP_DOWN, vec![ObjectRef::node(me)])
                .with_source_ip(cx.source_ip)
                .with_context("leader", leader.to_string())
                .with_context("term", term.to_string()),
        );
        if let Err(error) = self.store().propose(batch).await {
            tracing::warn!(%error, "the step-down could not be audited");
        }
        tracing::info!(previous = %me, leader = %leader, term, "leadership handed over");
        Ok(StepDown {
            previous: me,
            leader,
            term,
        })
    }

    /// Hands leadership to the most caught-up voter in contact (this controller must
    /// lead) and returns the new leader; writes nothing to the store.
    ///
    /// # Errors
    ///
    /// `cluster.member.no_successor` (409), `cluster.member.step_down_timeout` (504), or
    /// `cluster.member.not_leader` (503) when this controller does not lead.
    pub async fn hand_over(&self) -> Result<NodeId, ClusterError> {
        let me = self.local();
        let membership = self.store().membership();
        let status = self.store().status();
        let target = status
            .members
            .iter()
            .filter(|member| {
                member.node != me
                    && membership.voters.contains(&member.node)
                    && member
                        .last_contact_ms
                        .is_some_and(|ms| Duration::from_millis(ms) <= CONTACT_WINDOW)
            })
            .max_by_key(|member| (member.matched, std::cmp::Reverse(member.node)))
            .map(|member| member.node)
            .ok_or_else(|| {
                ClusterError::new(
                    "cluster.member.no_successor",
                    409,
                    "no other voter is in contact to take over leadership",
                )
            })?;
        let network = self.network().clone();
        let leader = self
            .store()
            .step_down(
                target,
                move || async move {
                    let mut client = network
                        .cluster_client(target)
                        .await
                        .map_err(|_| StoreError::NoQuorum)?;
                    client
                        .campaign(tonic::Request::new(v1::CampaignRequest {}))
                        .await
                        .map(|_| ())
                        .map_err(|_| StoreError::NoQuorum)
                },
                STEP_DOWN_TIMEOUT,
            )
            .await
            .map_err(|error| match error {
                StoreError::Timeout => ClusterError::new(
                    "cluster.member.step_down_timeout",
                    504,
                    "leadership did not move in time; this controller keeps leading",
                ),
                other => membership_error(&other),
            })?;
        Ok(leader)
    }

    /// A membership change: here when this controller leads, else at the leader through
    /// `Cluster.Change`.
    pub(crate) async fn apply_change(
        &self,
        cx: &RequestCtx,
        change: MemberChange,
    ) -> Result<ChangeResult, ClusterError> {
        if self.leads() {
            return match change {
                MemberChange::Promote { node, request } => self
                    .promote_here(cx, node, request)
                    .await
                    .map(ChangeResult::View),
                MemberChange::Remove { node } => {
                    self.remove_here(cx, node).await.map(ChangeResult::View)
                }
                MemberChange::StepDown => self.step_down_here(cx).await.map(ChangeResult::StepDown),
            };
        }
        if !self.is_member() {
            return Err(ClusterError::new(
                "cluster.single",
                409,
                "this controller is not part of a controller cluster",
            ));
        }
        let leader = self.store().current_leader().ok_or_else(not_leader)?;
        let envelope = ChangeEnvelope {
            ctx: WireCtx::from(cx),
            change,
        };
        let mut client = self.network().cluster_client(leader).await?;
        let mut request = tonic::Request::new(v1::ChangeRequest {
            wire: CLUSTER_WIRE.to_owned(),
            change: wire::encode(&envelope)?,
        });
        request.set_timeout(STEP_DOWN_TIMEOUT + Duration::from_secs(10));
        let answer = client
            .change(request)
            .await
            .map_err(|status| error_of_status(&status))?
            .into_inner();
        wire::check(&answer.wire, CLUSTER_WIRE)?;
        wire::decode("change result", &answer.result)
    }

    // -----------------------------------------------------------------------------------
    // Key transfer.

    /// The other members, the leader first: whom to ask for key generations.
    pub fn others_leader_first(&self) -> Vec<NodeId> {
        let membership = self.store().membership();
        let leader = self.store().current_leader();
        let mut nodes: Vec<NodeId> = membership
            .voters
            .iter()
            .chain(&membership.learners)
            .copied()
            .filter(|node| *node != self.local())
            .collect();
        nodes.sort_by_key(|node| (Some(*node) != leader, node.0));
        nodes
    }

    /// `Cluster.TransferKek`: seals the KEK generations for the controller `caller`: once
    /// per enrolment token for a joining controller, or for a member of the Raft group that
    /// lacks generations (an empty token id: a fetch).
    pub(crate) async fn transfer_kek(
        &self,
        caller: &NodeRecord,
        request: v1::TransferKekRequest,
    ) -> Result<v1::TransferKekResponse, ClusterError> {
        if request.join_token_id.is_empty() {
            return self.fetch_kek(caller, &request).await;
        }
        let token: Uuid = request.join_token_id.parse().map_err(|_| {
            ClusterError::new(
                "vault.kek.transfer.token",
                400,
                "the join token id is not a UUID",
            )
        })?;
        if token != caller.enrolment || token.is_nil() {
            return Err(ClusterError::new(
                "vault.kek.transfer.token",
                403,
                "the join token is not the one this controller enrolled with",
            ));
        }
        if request.ephemeral_public_key.len() != 32 {
            return Err(ClusterError::new(
                "vault.kek.transfer.key",
                400,
                "the ephemeral public key is not 32 bytes",
            ));
        }
        let source = self.inner.kek.get().ok_or_else(unavailable)?;
        let registry = Arc::clone(self.registry()?);
        let view = self.store().read(ReadConsistency::Linearizable).await?;
        if view.get_typed(&tables::KEK_TRANSFERS, &token)?.is_some() {
            return Err(ClusterError::new(
                "vault.kek.transfer.used",
                409,
                "the keys were transferred with this join token already; enrol again",
            ));
        }
        drop(view);
        let context = join_context(caller.id, token);
        let sealed = source.seal_for(&request.ephemeral_public_key, &context)?;
        let ctx = system();
        let mut batch = WriteBatch::for_request(&ctx);
        batch.expect_typed(&tables::KEK_TRANSFERS, &token, None);
        batch.put_typed(
            &tables::KEK_TRANSFERS,
            &token,
            &KekTransferRecord {
                node: caller.id,
                at: ctx.now,
                generations: sealed.generation_ids.clone(),
            },
        )?;
        batch.audit(
            AuditDraft::success(actions::KEK_TRANSFER, vec![ObjectRef::node(caller.id)])
                .with_context("generations", sealed.generation_ids.join(","))
                .with_context("node", caller.id.to_string())
                .with_context("enrolment", token.to_string())
                .with_context("purpose", "join".to_owned()),
        );
        registry
            .commit(
                &ctx,
                format!("hand the key encryption keys to controller {}", caller.id),
                vec![ObjectRef::node(caller.id)],
                batch,
            )
            .await
            .map_err(|error| {
                if error.code() == "sys.store.precondition_failed" {
                    ClusterError::new(
                        "vault.kek.transfer.used",
                        409,
                        "the keys were transferred with this join token already; enrol again",
                    )
                } else {
                    error
                }
            })?;
        Ok(v1::TransferKekResponse {
            format: sealed.format,
            sealed: sealed.sealed,
            generation_ids: sealed.generation_ids,
        })
    }

    /// A fetch of the generations by a member of the Raft group (start step 3, an online
    /// rotation it missed): no single use, audited with `purpose=fetch`.
    async fn fetch_kek(
        &self,
        caller: &NodeRecord,
        request: &v1::TransferKekRequest,
    ) -> Result<v1::TransferKekResponse, ClusterError> {
        let membership = self.store().membership();
        if !membership.voters.contains(&caller.id) && !membership.learners.contains(&caller.id) {
            return Err(ClusterError::new(
                "vault.kek.transfer.token",
                403,
                "only a member of the controller cluster fetches key generations without a join token",
            ));
        }
        let source = self.inner.kek.get().ok_or_else(unavailable)?;
        let sealed = source.seal_for(&request.ephemeral_public_key, &fetch_context(caller.id))?;
        let mut batch = WriteBatch::for_request(&system());
        batch.audit(
            AuditDraft::success(actions::KEK_TRANSFER, vec![ObjectRef::node(caller.id)])
                .with_context("generations", sealed.generation_ids.join(","))
                .with_context("node", caller.id.to_string())
                .with_context("purpose", "fetch".to_owned()),
        );
        self.store().propose(batch).await?;
        Ok(v1::TransferKekResponse {
            format: sealed.format,
            sealed: sealed.sealed,
            generation_ids: sealed.generation_ids,
        })
    }

    /// `Cluster.Campaign`: the leader asks this voter to take over.
    pub(crate) async fn campaign(
        &self,
        caller: NodeId,
    ) -> Result<v1::CampaignResponse, ClusterError> {
        if self.store().current_leader() != Some(caller) {
            return Err(ClusterError::new(
                "cluster.member.not_leader",
                403,
                "only the leader may ask a member to campaign",
            ));
        }
        self.store().campaign().await?;
        Ok(v1::CampaignResponse {
            term: self.store().status().term,
        })
    }
}

/// The number of learners to promote so that the voters stay odd: as many as possible.
fn odd_promotions(voters: usize, eligible: usize) -> usize {
    if eligible == 0 {
        0
    } else if !(voters + eligible).is_multiple_of(2) {
        eligible
    } else {
        eligible - 1
    }
}

fn is_leader(node: NodeId) -> ClusterError {
    ClusterError::new(
        "cluster.member.is_leader",
        409,
        format!("controller {node} leads; hand leadership over first (step-down)"),
    )
    .with_param("node", node.to_string())
}

fn list(nodes: &[NodeId]) -> String {
    nodes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn member_proto(member: &MemberView) -> v1::Member {
    v1::Member {
        node_id: member.node.0,
        address: member.address.clone().unwrap_or_default(),
        voter: member.role == MemberRole::Voter,
        matched: member.matched,
        lag_entries: member.lag_entries,
        version: member.version.clone().unwrap_or_default(),
    }
}

async fn promote_loop(peers: Peers, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
            _ = tick.tick() => {}
        }
        if !peers.inner.config.auto_promote || peers.inner.registry.get().is_none() {
            continue;
        }
        let leads = peers
            .store()
            .leadership()
            .borrow()
            .is_some_and(|seen| seen.is_self);
        if !leads {
            lock(&peers.inner.caught_up).clear();
            continue;
        }
        if let Err(error) = peers.auto_promote().await {
            tracing::debug!(code = %error.code(), "automatic promotion: {}", error.detail());
        }
    }
}

#[async_trait::async_trait]
impl ClusterAdmin for Peers {
    async fn view(&self) -> Result<ClusterView, ClusterError> {
        let figures = self.figures().await;
        self.view_local(Some(figures)).await
    }

    async fn promote(
        &self,
        cx: &RequestCtx,
        node: NodeId,
        request: PromoteRequest,
    ) -> Result<ClusterView, ClusterError> {
        self.change_as_job(cx, node, MemberChange::Promote { node, request })
            .await
    }

    async fn remove(&self, cx: &RequestCtx, node: NodeId) -> Result<ClusterView, ClusterError> {
        self.change_as_job(cx, node, MemberChange::Remove { node })
            .await
    }

    async fn step_down(&self, cx: &RequestCtx) -> Result<StepDown, ClusterError> {
        if !self.is_member() {
            return Err(ClusterError::new(
                "cluster.single",
                409,
                "this controller is not part of a controller cluster",
            ));
        }
        match self.apply_change(cx, MemberChange::StepDown).await? {
            ChangeResult::StepDown(outcome) => Ok(outcome),
            ChangeResult::View(_) => Err(ClusterError::internal("unexpected change result")),
        }
    }

    async fn digests(&self, revision: Option<Revision>) -> Result<DigestReport, ClusterError> {
        let mut target = revision.unwrap_or_else(|| self.store().status().revision);
        let mut report = self.digests_at(target).await;
        // Without a requested revision, members that applied more answer a later one: ask
        // everyone again at the newest revision seen (a quiet cluster agrees then).
        for _ in 0..3 {
            if report.agree || revision.is_some() {
                break;
            }
            let newest = report
                .members
                .iter()
                .filter_map(|member| member.revision)
                .max()
                .unwrap_or(target);
            if newest == target && report.members.iter().all(|member| member.error.is_none()) {
                break;
            }
            target = newest;
            report = self.digests_at(target).await;
        }
        Ok(report)
    }
}

impl Peers {
    /// The digest of every member, each after it applied `target`.
    async fn digests_at(&self, target: Revision) -> DigestReport {
        let membership: Membership = self.store().membership();
        let mut nodes: BTreeSet<NodeId> = membership.voters.clone();
        nodes.extend(membership.learners.iter().copied());
        nodes.insert(self.local());
        let mut members = Vec::with_capacity(nodes.len());
        for node in nodes {
            let digest = if node == self.local() {
                self.store()
                    .digest(Some(target))
                    .await
                    .map(|digest| {
                        (
                            digest.revision,
                            digest.sha256.to_vec(),
                            digest.tables,
                            digest.entries,
                        )
                    })
                    .map_err(|error| ClusterError::coded(&error))
            } else {
                async {
                    let mut client = self.network().cluster_client(node).await?;
                    let answer = client
                        .digest(tonic::Request::new(v1::DigestRequest {
                            revision: target.0,
                        }))
                        .await
                        .map_err(|status| error_of_status(&status))?
                        .into_inner();
                    Ok((
                        Revision(answer.revision),
                        answer.sha256,
                        answer.tables,
                        answer.entries,
                    ))
                }
                .await
            };
            members.push(match digest {
                Ok((revision, sha256, tables, entries)) => MemberDigest {
                    node,
                    revision: Some(revision),
                    sha256: Some(hex(&sha256)),
                    tables: Some(tables),
                    entries: Some(entries),
                    error: None,
                },
                Err(error) => MemberDigest {
                    node,
                    revision: None,
                    sha256: None,
                    tables: None,
                    entries: None,
                    error: Some(error.code().to_owned()),
                },
            });
        }
        let agree = members.iter().all(|member| {
            member.error.is_none()
                && member.revision == members[0].revision
                && member.sha256 == members[0].sha256
        });
        DigestReport {
            revision: target,
            agree,
            members,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The step of a promotion or removal inside the inline job `cluster.edit`.
pub const MEMBER_STEP: &str = "cluster.member";

/// How long a membership change as a job may take: a joint change and the catch-up of the
/// leader's figures.
const MEMBER_JOB_TIMEOUT: Duration = Duration::from_secs(120);

/// The members after a promotion or removal.
fn view_of(result: ChangeResult) -> Result<ClusterView, ClusterError> {
    match result {
        ChangeResult::View(view) => Ok(view),
        ChangeResult::StepDown(_) => Err(ClusterError::internal("unexpected change result")),
    }
}

/// A refusal of the cluster as a step error, with its code and status.
fn step_error(error: ClusterError) -> StepError {
    StepError::Coded(Box::new(error.into_coded()))
}

/// `cluster.member`: hands a promotion or removal ([`MemberChange`]) to the leader and
/// records the members after it as the step output.
struct MemberStep {
    peers: Weak<Inner>,
}

#[async_trait::async_trait]
impl StepHandler for MemberStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(MEMBER_STEP)
    }

    /// Not idempotent: a promotion that happened refuses a second one.
    fn idempotent(&self) -> bool {
        false
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let change: MemberChange =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        let (summary, node) = match &change {
            MemberChange::Promote { node, .. } => (format!("promote controller {node}"), *node),
            MemberChange::Remove { node } => (format!("remove controller {node}"), *node),
            MemberChange::StepDown => {
                return Err(StepError::InvalidParams(
                    "a step-down is not a job step".to_owned(),
                ));
            }
        };
        Ok(StepPreview {
            summary: MessageKey::from_static(WRITE_PREVIEW),
            args: BTreeMap::from([("summary".to_owned(), summary)]),
            changes: vec![ObjectRef::node(node)],
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let change: MemberChange =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        if matches!(change, MemberChange::StepDown) {
            return Err(StepError::InvalidParams(
                "a step-down is not a job step".to_owned(),
            ));
        }
        let peers = Peers {
            inner: self.peers.upgrade().ok_or_else(|| step_error(starting()))?,
        };
        let view = view_of(
            peers
                .apply_change(&cx.request, change)
                .await
                .map_err(step_error)?,
        )
        .map_err(step_error)?;
        let output = to_cbor(&view).map_err(|error| step_error(error.into()))?;
        Ok(StepOutcome::Done {
            output: Some(output),
        })
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        Err(StepError::NotCompensable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotions_keep_the_voters_odd() {
        // One voter and one caught-up learner wait for a second learner (R21).
        assert_eq!(odd_promotions(1, 1), 0);
        assert_eq!(odd_promotions(1, 2), 2);
        assert_eq!(odd_promotions(1, 3), 2);
        assert_eq!(odd_promotions(3, 1), 0);
        assert_eq!(odd_promotions(2, 1), 1);
        assert_eq!(odd_promotions(3, 0), 0);
    }

    #[test]
    fn digests_print_as_hex() {
        assert_eq!(hex(&[0, 15, 255]), "000fff");
    }
}
