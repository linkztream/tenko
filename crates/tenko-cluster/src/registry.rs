//! The node registry of a controller: enrollment tokens, enrollment, renewal, revocation,
//! the protocol state of each node, and the controller's own certificate on the cluster
//! port (OPS-04, OPS-08).
//!
//! # Enrollment
//!
//! An administrator creates a token ([`NodeRegistry::create_enrollment`]); the controller
//! keeps only its digest and shows the text once. The node presents the token with a
//! certificate request ([`NodeRegistry::enroll`]); the controller checks the token (it
//! exists, its secret matches, it is unused and unexpired), the roles (each allowed by the
//! token), the protocol majors and the name, issues a certificate for the node's key with
//! a new node id and the roles, and records the node. Token use and node creation commit
//! in one batch whose precondition on the token makes the token single-use even when two
//! nodes race with it.
//!
//! # Revocation
//!
//! [`NodeRegistry::revoke`] removes the node and adds the serial of every certificate it
//! was issued and that has not expired to `cluster.revocations` and to the
//! [`RevocationSet`] the TLS verifier of the cluport checks; the node's sessions get a
//! revocation directive and its connections close.
//!
//! # Writes
//!
//! Edits by people and nodes (tokens, enrollment, renewal, revocation) are inline jobs with
//! the step `cluster.write`, like every edit in Tenko. Bookkeeping of the controller itself
//! (`last_seen`, the protocol state, pruning) is written directly.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use futures::StreamExt as _;
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use tenko_core::{
    Coded, MessageKey, NodeId, ObjectKind, ObjectRef, Principal, RequestCtx, Revision, Role,
    RoleSet, SystemComponent, Timestamp,
    audit::AuditDraft,
    cluster::LEADER_EPOCH,
    codec::{from_cbor, to_cbor},
    secret::SecretClass,
    serde_util::HexBytes,
};
use tenko_jobs::{
    JobEngine, JobKind, JobSpec, StepContext, StepError, StepHandler, StepKind, StepOutcome,
    StepPreview, StepSpec,
};
use tenko_store::WatchFilter;
use tenko_store::{
    FailedPrecondition, KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError,
    WriteBatch,
};
use tenko_vault::{SecretPurpose, SecretSpec, Vault, VaultError};
use tokio::{
    sync::{Notify, watch},
    task::JoinHandle,
};
use uuid::Uuid;

use crate::{
    ca::{CertSource, InternalCa, NodeCert, TlsMaterial},
    error::ClusterError,
    model::{
        CertificateRef, ClusterHealth, ConnectionRecord, ConnectionView, ControllerCertRecord,
        EnrollRequest, EnrollmentRecord, EnrollmentView, FIRST_ENROLLED_NODE_ID,
        LAST_SEEN_INTERVAL_SECS, MismatchRecord, NewEnrollment, NodeMismatch, NodeRecord, NodeView,
        Revocation, TokenUse, tables, valid_address,
    },
    mtls::RevocationSet,
    session::Sessions,
    token::{CaFingerprint, EnrollmentToken},
    version::{self, VersionMismatch},
};

/// Audit actions of the registry.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// An enrollment token was created.
    pub const ENROLLMENT_CREATE: AuditAction =
        AuditAction::from_static("cluster.enrollment.create");
    /// An enrollment token was deleted.
    pub const ENROLLMENT_DELETE: AuditAction =
        AuditAction::from_static("cluster.enrollment.delete");
    /// A node enrolled (or failed to).
    pub const NODE_ENROLL: AuditAction = AuditAction::from_static("cluster.node.enroll");
    /// A node renewed its certificate.
    pub const NODE_RENEW: AuditAction = AuditAction::from_static("cluster.node.renew");
    /// A node was revoked.
    pub const NODE_REVOKE: AuditAction = AuditAction::from_static("cluster.node.revoke");
    /// A node's handshake was refused for want of a common protocol major.
    pub const VERSION_MISMATCH: AuditAction =
        AuditAction::from_static("cluster.node.version_mismatch");
    /// A controller certificate for the cluster port was issued.
    pub const CONTROLLER_CERT: AuditAction =
        AuditAction::from_static("cluster.node.controller_cert");
}

/// Vault purpose of a controller's cluster-port key.
pub const NODE_KEY_PURPOSE: SecretPurpose = SecretPurpose::from_static("cluster.node_key");

/// Kind of the inline job of every registry edit.
pub const EDIT_JOB: &str = "cluster.edit";
/// Step kind of that job.
pub const WRITE_STEP: &str = "cluster.write";
/// Title key of that job.
pub const EDIT_TITLE: &str = "cluster.job.edit";
/// Preview key of the step.
pub const WRITE_PREVIEW: &str = "cluster.job.write_preview";

/// Default lifetime of an enrollment token.
pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(3600);
/// Shortest lifetime of an enrollment token.
pub const MIN_TOKEN_TTL: Duration = Duration::from_secs(60);
/// Longest lifetime of an enrollment token.
pub const MAX_TOKEN_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
/// Longest lifetime of a token for a controller (it lets a host join the cluster and
/// receive the key encryption keys, R22).
pub const MAX_CONTROLLER_TOKEN_TTL: Duration = Duration::from_secs(3600);
/// Used and expired tokens stay listed this long.
pub const TOKEN_RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);
/// A repeated refused handshake with the same offer is recorded and audited at most this
/// often.
pub const MISMATCH_REPEAT: Duration = Duration::from_secs(3600);
/// How often an open configuration, command or heartbeat stream of a node checks again
/// that the node is enrolled and holds the certificate of its connection. A revocation
/// closes the node's connections at once; this check ends a stream whose connection
/// outlived its record for any other reason.
pub const STREAM_RECHECK: Duration = Duration::from_secs(60);
/// A node renews its certificate at most once in this time. A node whose renewal answer was
/// lost asks again with the certificate it still holds after its own pause of an hour
/// (`client::RENEW_RETRY`).
pub const RENEW_INTERVAL: Duration = Duration::from_secs(3600);
/// The fewest days before expiry from which a node certificate may be renewed, whatever
/// the CA policy says: the node's own rule asks from 30 days or a third of the lifetime,
/// whichever is longer (`identity::Credentials::needs_renewal`).
pub const RENEW_FROM_DAYS: u32 = 30;
/// How long the certificates a renewal replaced keep working once the node has shown that
/// it holds the new one: long enough for the calls under way on its old connection, after
/// which its streams end and it connects again with the new certificate.
pub const RETIRE_GRACE: Duration = Duration::from_secs(15 * 60);
/// Refused enrollments a controller audits one by one in each [`REFUSAL_WINDOW`]; the
/// rest of the window's refusals go into one summary record at its end.
pub const REFUSAL_AUDIT_BURST: u32 = 10;
/// The window of [`REFUSAL_AUDIT_BURST`].
pub const REFUSAL_WINDOW: Duration = Duration::from_secs(60);
/// Longest node name.
pub const MAX_NAME_LEN: usize = 63;
/// How many times a revocation or a renewal is planned before a conflict is reported: the
/// node's bookkeeping writes the same record, and a lost race records nothing.
pub const NODE_EDIT_ATTEMPTS: usize = 3;
/// The code of a refusal for a node that is not enrolled (or was revoked).
pub const NODE_NOT_FOUND: &str = "cluster.node.not_found";
/// The code of an edit of a node that lost the race for its record every time.
pub const NODE_CONFLICT: &str = "cluster.node.conflict";

/// Settings of the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryConfig {
    /// This controller's node id (`[node] id`).
    pub local_node: NodeId,
    /// Seconds between two heartbeats of a node.
    pub heartbeat_secs: u32,
    /// `host:port` endpoints of the cluster port that nodes are told at enrollment.
    pub advertise: Vec<String>,
    /// The port nodes connect to when nothing is advertised and the listener is not up
    /// yet.
    pub default_port: u16,
    /// Lifetime of a token whose request names none.
    pub default_token_ttl: Duration,
    /// The protocol majors this controller implements.
    pub majors: Vec<u32>,
}

impl RegistryConfig {
    /// The defaults for a controller with this node id.
    pub fn new(local_node: NodeId) -> Self {
        Self {
            local_node,
            heartbeat_secs: 10,
            advertise: Vec::new(),
            default_port: 8444,
            default_token_ttl: DEFAULT_TOKEN_TTL,
            majors: version::SUPPORTED_MAJORS.to_vec(),
        }
    }
}

/// The pace of the checks of connected nodes and of the audit of refused enrollments. The
/// defaults are [`STREAM_RECHECK`], [`RETIRE_GRACE`] and [`REFUSAL_WINDOW`]; tests
/// shorten them with [`NodeRegistry::set_timings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timings {
    /// How often an open stream of a node checks the node's record again.
    pub stream_recheck: Duration,
    /// How long replaced certificates keep working once the node holds the new one.
    pub retire_grace: Duration,
    /// The window in which a few refused enrollments are audited one by one.
    pub refusal_window: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            stream_recheck: STREAM_RECHECK,
            retire_grace: RETIRE_GRACE,
            refusal_window: REFUSAL_WINDOW,
        }
    }
}

/// What a successful enrollment hands back to the node.
#[derive(Debug, Clone)]
pub struct Enrolled {
    /// The node as registered.
    pub node: NodeView,
    /// The node certificate.
    pub certificate: NodeCert,
    /// The node certificate, PEM.
    pub certificate_pem: String,
    /// The CA root, PEM.
    pub ca_root_pem: String,
}

/// A coded error with a static code, for audit records of refused requests.
struct Refusal<'a>(&'static str, &'a str);

impl std::fmt::Display for Refusal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.1)
    }
}

impl Coded for Refusal<'_> {
    fn code(&self) -> &'static str {
        self.0
    }

    fn http_status(&self) -> u16 {
        400
    }
}

fn not_found(id: NodeId) -> ClusterError {
    ClusterError::new(
        NODE_NOT_FOUND,
        404,
        format!("there is no enrolled node {id}"),
    )
    .with_param("node", id.to_string())
}

fn invalid_token() -> ClusterError {
    ClusterError::new(
        "cluster.enrollment.invalid_token",
        401,
        "the enrollment token is not valid",
    )
}

/// How an enrollment request reached the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollTransport {
    /// Over TLS: to this controller, or to a trusted reverse proxy that said so.
    Https,
    /// Over plain HTTP. Only the Lab profile accepts it ([`NodeRegistry::refuse_plain_http`]).
    PlainHttp,
    /// Through a trusted reverse proxy that did not say whether the client used HTTPS (no
    /// `X-Forwarded-Proto`, no PROXY protocol SSL record). Only the Lab profile accepts it
    /// ([`NodeRegistry::refuse_unstated_scheme`]).
    Unstated,
}

fn plain_http_refused() -> ClusterError {
    ClusterError::new(
        "cluster.enrollment.plain_http",
        403,
        "this controller accepts enrollment tokens only over HTTPS: the token crossed the \
         network in clear text and is withdrawn; create a new token and enroll with the \
         https:// URL of the controller (plain HTTP is accepted only under the Lab profile)",
    )
}

fn scheme_unknown() -> ClusterError {
    ClusterError::new(
        "cluster.enrollment.scheme_unknown",
        403,
        "this controller accepts enrollment tokens only over HTTPS, and the reverse proxy in \
         front of it did not say whether the client used HTTPS; let the proxy set the header \
         X-Forwarded-Proto (HAProxy: `http-request set-header X-Forwarded-Proto https` on the \
         TLS frontend; nginx: `proxy_set_header X-Forwarded-Proto $scheme;`) or send the \
         PROXY protocol version 2 with its SSL record (HAProxy: `send-proxy-v2-ssl`), then \
         enroll again with the same token, which is kept",
    )
}

fn wrong_controller() -> ClusterError {
    ClusterError::new(
        "cluster.enrollment.wrong_controller",
        401,
        "the enrollment token was created by another controller: its CA fingerprint is not \
         this controller's; use the controller that showed the token",
    )
}

/// What the cluster port that opens on demand (`[cluster] listen` not set) serves
/// ([`NodeRegistry::port_demand`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortDemand {
    /// No node is enrolled and no token is waiting: the port closes.
    Idle,
    /// No node is enrolled; tokens are waiting, the last of them until this time.
    Until(Timestamp),
    /// A node is enrolled: nodes connect to the port.
    Enrolled,
}

/// Most source addresses a summary of refused enrollments keeps; beyond them it counts.
const SUMMARY_ADDRESSES: usize = 1024;
/// Most source addresses a summary of refused enrollments names in its record.
const SUMMARY_NAMED: usize = 16;

/// The audit pace of refused enrollments on this controller.
#[derive(Debug, Default)]
struct Refusals {
    /// When the current window started.
    started: Option<Instant>,
    /// Refusals recorded one by one in it, of requests that did not know a token's
    /// secret.
    recorded: u32,
    /// Refusals recorded one by one in it, of requests that knew one (a used or expired
    /// token, a refused role or name): they have a budget of their own, so a flood of
    /// invalid tokens does not hide them.
    recorded_known: u32,
    /// The refusals past the burst, until the window's summary is written.
    pending: Option<PendingRefusals>,
}

/// The refused enrollments a summary record covers.
#[derive(Debug)]
struct PendingRefusals {
    since: Timestamp,
    count: u64,
    codes: BTreeMap<&'static str, u64>,
    /// The source addresses in the order they were first seen.
    addresses: Vec<std::net::IpAddr>,
    seen: HashSet<std::net::IpAddr>,
    more_addresses: bool,
}

impl PendingRefusals {
    fn new(since: Timestamp) -> Self {
        Self {
            since,
            count: 0,
            codes: BTreeMap::new(),
            addresses: Vec::new(),
            seen: HashSet::new(),
            more_addresses: false,
        }
    }

    fn add(&mut self, code: &'static str, source: Option<std::net::IpAddr>) {
        self.count += 1;
        *self.codes.entry(code).or_default() += 1;
        if let Some(source) = source
            && !self.seen.contains(&source)
        {
            if self.addresses.len() < SUMMARY_ADDRESSES {
                self.seen.insert(source);
                self.addresses.push(source);
            } else {
                self.more_addresses = true;
            }
        }
    }

    /// Writes the summary record.
    async fn audit(self, store: &dyn Store) {
        let codes = self
            .codes
            .iter()
            .map(|(code, count)| format!("{code}={count}"))
            .collect::<Vec<_>>()
            .join(",");
        let sources = if self.more_addresses {
            format!("more than {SUMMARY_ADDRESSES}")
        } else {
            self.addresses.len().to_string()
        };
        let named = self
            .addresses
            .iter()
            .take(SUMMARY_NAMED)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let detail = format!(
            "{} more enrollment requests were refused since {}; they are counted here, not \
             recorded one by one",
            self.count, self.since
        );
        tracing::warn!(refusals = self.count, codes = %codes, sources = %sources, "refused enrollments since {}", self.since);
        let draft = AuditDraft::failed(
            actions::NODE_ENROLL,
            Vec::new(),
            &Refusal("cluster.enrollment.refusals", &detail),
        )
        .with_context("refusals", self.count.to_string())
        .with_context("codes", codes)
        .with_context("sources", sources)
        .with_context("addresses", named)
        .with_context("since", self.since.to_rfc3339());
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Cluster));
        batch.audit(draft);
        if let Err(error) = store.propose(batch).await {
            tracing::warn!(%error, "the summary of refused enrollments could not be audited");
        }
    }
}

/// The node registry of a controller.
pub struct NodeRegistry {
    store: Arc<dyn Store>,
    ca: Arc<InternalCa>,
    config: RegistryConfig,
    jobs: OnceLock<JobEngine>,
    revoked: Arc<RevocationSet>,
    revoked_nodes: ArcSwap<HashSet<NodeId>>,
    sessions: Arc<Sessions>,
    listening: ArcSwap<Vec<SocketAddr>>,
    listener_wanted: Notify,
    wanted: std::sync::atomic::AtomicBool,
    touched: Mutex<HashMap<NodeId, Instant>>,
    mismatches: Mutex<HashMap<NodeId, (VersionMismatch, Instant)>>,
    node_sync: OnceLock<crate::node_sync::NodeSync>,
    timings: Mutex<Timings>,
    refusals: Arc<Mutex<Refusals>>,
    metrics: OnceLock<Arc<dyn crate::metrics::MetricsSource>>,
}

impl std::fmt::Debug for NodeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeRegistry")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl NodeRegistry {
    /// A registry over `store` with the internal CA `ca`.
    pub fn new(store: Arc<dyn Store>, ca: Arc<InternalCa>, config: RegistryConfig) -> Arc<Self> {
        Self::with_port(
            store,
            ca,
            config,
            Arc::new(RevocationSet::new()),
            Sessions::new(),
        )
    }

    /// A registry that shares the revocation set and the sessions of a cluster port that
    /// opened before it (a member of a controller cluster opens its port in the `cluster`
    /// start step).
    pub fn with_port(
        store: Arc<dyn Store>,
        ca: Arc<InternalCa>,
        config: RegistryConfig,
        revoked: Arc<RevocationSet>,
        sessions: Arc<Sessions>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            ca,
            config,
            jobs: OnceLock::new(),
            revoked,
            revoked_nodes: ArcSwap::from_pointee(HashSet::new()),
            sessions,
            listening: ArcSwap::from_pointee(Vec::new()),
            listener_wanted: Notify::new(),
            wanted: std::sync::atomic::AtomicBool::new(false),
            touched: Mutex::new(HashMap::new()),
            mismatches: Mutex::new(HashMap::new()),
            node_sync: OnceLock::new(),
            timings: Mutex::new(Timings::default()),
            refusals: Arc::new(Mutex::new(Refusals::default())),
            metrics: OnceLock::new(),
        })
    }

    /// Hands the registry this controller's metrics samples, which `Metrics.Snapshot`
    /// answers to the other controllers; called once by the server's `api` start step. Until
    /// then the call answers `UNAVAILABLE`.
    pub fn set_metrics_source(&self, source: Arc<dyn crate::metrics::MetricsSource>) {
        let _ = self.metrics.set(source);
    }

    /// The source of `Metrics.Snapshot`, once set.
    pub fn metrics_source(&self) -> Option<&Arc<dyn crate::metrics::MetricsSource>> {
        self.metrics.get()
    }

    /// Hands the registry the node-sync services (configuration, commands, node secrets)
    /// that the cluster port serves; called once by the `nodes` start step before the port
    /// listens.
    pub fn set_node_sync(&self, sync: crate::node_sync::NodeSync) {
        let _ = self.node_sync.set(sync);
    }

    /// The node-sync services; without `set_node_sync`, ones over the registry's store with
    /// no vault and no bandwidth cap.
    pub fn node_sync(&self) -> &crate::node_sync::NodeSync {
        self.node_sync
            .get_or_init(|| crate::node_sync::NodeSync::new(Arc::clone(&self.store)))
    }

    /// Registers the `cluster.write` step; from now on every edit is an inline job.
    pub fn register_steps(&self, engine: &JobEngine) {
        let mut registered = engine.clone();
        registered.register(Arc::new(WriteStep));
        let _ = self.jobs.set(engine.clone());
    }

    /// Sets the pace of the checks of connected nodes ([`Timings::default`] unless set;
    /// tests shorten it). Streams opened afterwards use it.
    pub fn set_timings(&self, timings: Timings) {
        *self.timings.lock().unwrap_or_else(PoisonError::into_inner) = Timings {
            stream_recheck: timings.stream_recheck.max(Duration::from_millis(10)),
            retire_grace: timings.retire_grace,
            refusal_window: timings.refusal_window,
        };
    }

    /// The pace of the checks of connected nodes.
    pub fn timings(&self) -> Timings {
        *self.timings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The settings.
    pub fn config(&self) -> &RegistryConfig {
        &self.config
    }

    /// The internal CA.
    pub fn ca(&self) -> &Arc<InternalCa> {
        &self.ca
    }

    /// The fingerprint of the internal CA's root, as a `tnk2` token carries it.
    pub fn ca_fingerprint(&self) -> CaFingerprint {
        CaFingerprint::of_der(self.ca.root_der())
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// The revoked serials the TLS verifier checks.
    pub fn revocations(&self) -> Arc<RevocationSet> {
        Arc::clone(&self.revoked)
    }

    /// The live sessions.
    pub fn sessions(&self) -> &Arc<Sessions> {
        &self.sessions
    }

    /// Records the addresses the cluster port listens on.
    pub fn set_listening(&self, addrs: Vec<SocketAddr>) {
        self.listening.store(Arc::new(addrs));
    }

    /// The addresses the cluster port listens on; empty while it is off.
    pub fn listening(&self) -> Vec<SocketAddr> {
        self.listening.load().as_ref().clone()
    }

    /// Asks a listener that starts on demand to start (a token was created).
    pub fn want_listener(&self) {
        self.wanted.store(true, std::sync::atomic::Ordering::SeqCst);
        self.listener_wanted.notify_waiters();
        self.listener_wanted.notify_one();
    }

    /// Resolves once [`want_listener`](Self::want_listener) was called (since the last
    /// [`forget_listener_wanted`](Self::forget_listener_wanted)).
    pub async fn listener_wanted(&self) {
        while !self.wanted.load(std::sync::atomic::Ordering::SeqCst) {
            self.listener_wanted.notified().await;
        }
    }

    /// Forgets the requests of [`want_listener`](Self::want_listener) so far. The listener
    /// that starts on demand calls it before it reads [`port_demand`](Self::port_demand): a
    /// token created after the call asks again, so a token that the read did not see yet
    /// opens the port again at once after it closed.
    pub fn forget_listener_wanted(&self) {
        self.wanted
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    // -----------------------------------------------------------------------------------
    // Start and maintenance.

    /// Loads the revocation list into the TLS verifier's set. Call at start and
    /// periodically (other controllers revoke too).
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn load_revocations(&self) -> Result<usize, ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let rows = view.scan_typed(&tables::REVOCATIONS, KeyRange::all(), usize::MAX, false)?;
        let count = rows.len();
        self.revoked_nodes.store(Arc::new(
            rows.iter()
                .map(|(_, revocation, _)| revocation.node)
                .collect(),
        ));
        self.revoked
            .replace(rows.into_iter().map(|(serial, _, _)| serial));
        Ok(count)
    }

    /// Whether a node is enrolled or a token is pending: the listener that starts on
    /// demand starts at once then.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn in_use(&self, now: Timestamp) -> Result<bool, ClusterError> {
        Ok(self.port_demand(now).await? != PortDemand::Idle)
    }

    /// What the cluster port that opens on demand serves at `now`: enrolled nodes, waiting
    /// tokens (until the last of them expires), or nothing.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn port_demand(&self, now: Timestamp) -> Result<PortDemand, ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        if !view
            .scan_typed(&tables::NODES, KeyRange::all(), 1, false)?
            .is_empty()
        {
            return Ok(PortDemand::Enrolled);
        }
        Ok(view
            .scan_typed(&tables::ENROLLMENTS, KeyRange::all(), usize::MAX, false)?
            .iter()
            .filter(|(_, record, _)| record.used.is_none() && record.expires_at > now)
            .map(|(_, record, _)| record.expires_at)
            .max()
            .map_or(PortDemand::Idle, PortDemand::Until))
    }

    /// Removes expired revocations, and used or expired tokens older than
    /// [`TOKEN_RETENTION`], and cuts a node record that names more than two certificates
    /// back to the newest and the one that ends last beside it. Returns how many rows went
    /// or were cut back.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn prune(&self, now: Timestamp) -> Result<usize, ClusterError> {
        self.prune_fenced(now, None).await
    }

    /// [`NodeRegistry::prune`] as leader-only work: the batch carries the leader epoch
    /// (`tenko_store::fence`), so a deposed leader's prune fails instead of racing.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn prune_fenced(
        &self,
        now: Timestamp,
        epoch: Option<u64>,
    ) -> Result<usize, ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let ctx = RequestCtx::system(SystemComponent::Cluster);
        let mut batch = WriteBatch::for_request(&ctx);
        if let Some(epoch) = epoch {
            batch.preconditions.push(tenko_store::fence(epoch));
        }
        let mut removed = 0;
        for (serial, revocation, revision) in
            view.scan_typed(&tables::REVOCATIONS, KeyRange::all(), usize::MAX, false)?
        {
            if revocation.not_after <= now {
                batch.expect_typed(&tables::REVOCATIONS, &serial, Some(revision));
                batch.delete_typed(&tables::REVOCATIONS, &serial);
                removed += 1;
            }
        }
        for (id, record, revision) in
            view.scan_typed(&tables::ENROLLMENTS, KeyRange::all(), usize::MAX, false)?
        {
            let ended = record
                .used
                .as_ref()
                .map_or(record.expires_at, |used| used.at);
            if (record.used.is_some() || record.expires_at <= now)
                && now.saturating_since(ended) >= TOKEN_RETENTION
            {
                batch.expect_typed(&tables::ENROLLMENTS, &id, Some(revision));
                batch.delete_typed(&tables::ENROLLMENTS, &id);
                removed += 1;
            }
        }
        // A record with more than the two certificates a renewal keeps (from before
        // renewals kept two): the newest and the one that ends last beside it stay.
        let mut trims = Vec::new();
        for (id, mut record, revision) in
            view.scan_typed(&tables::NODES, KeyRange::all(), usize::MAX, false)?
        {
            if record.serials.len() <= 2 {
                continue;
            }
            let newest = record.certificate.serial.clone();
            let keep = record
                .serials
                .iter()
                .filter(|cert| cert.serial != newest)
                .max_by_key(|cert| cert.not_after)
                .map(|cert| cert.serial.clone());
            record
                .serials
                .retain(|cert| cert.serial == newest || Some(&cert.serial) == keep.as_ref());
            trims.push((id, record, revision));
        }
        drop(view);
        if removed > 0 {
            match self.store.propose(batch).await {
                Ok(_) => {
                    self.load_revocations().await?;
                }
                // A row changed since the plan (a token deleted meanwhile): the next pass
                // plans again. Only the fence's failure means that the office moved on.
                Err(StoreError::PreconditionFailed(failed)) if !failed.iter().any(is_fence) => {
                    removed = 0;
                }
                Err(error) => return Err(error.into()),
            }
        }
        for (id, record, revision) in trims {
            let mut batch = WriteBatch::for_request(&ctx);
            if let Some(epoch) = epoch {
                batch.preconditions.push(tenko_store::fence(epoch));
            }
            batch.expect_typed(&tables::NODES, &id, Some(revision));
            batch.put_typed(&tables::NODES, &id, &record)?;
            match self.store.propose(batch).await {
                Ok(_) => removed += 1,
                // The node's bookkeeping won the race, or the office moved on: the next
                // pass trims it.
                Err(StoreError::PreconditionFailed(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(removed)
    }

    // -----------------------------------------------------------------------------------
    // The controller's own certificate.

    /// The certificate this controller presents on the cluster port: the stored one while
    /// it was issued by this CA and is not due for renewal, else a new one with the role
    /// `controller` (and a new key in the vault, the old one deleted, audited). Call at
    /// start and daily.
    ///
    /// # Errors
    ///
    /// A CA, vault or store error.
    pub async fn controller_material(
        &self,
        vault: &dyn Vault,
        ctx: &RequestCtx,
    ) -> Result<TlsMaterial, ClusterError> {
        let node = self.config.local_node;
        let view = self.store.read(ReadConsistency::Local).await?;
        let current = view.get_typed(&tables::CONTROLLER_CERTS, &node.0)?;
        drop(view);
        if let Some((record, _)) = &current
            && let Some(material) = self.reusable(vault, ctx, record).await?
        {
            return Ok(material);
        }
        let roles: RoleSet = [Role::Controller].into_iter().collect();
        let issued = self.ca.issue_node_cert_with_key_for(node, roles, ctx.now)?;
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(
            &tables::CONTROLLER_CERTS,
            &node.0,
            current.as_ref().map(|(_, revision)| *revision),
        );
        let key = vault.stage_put(
            &mut batch,
            ctx,
            SecretClass::System,
            SecretSpec::new(NODE_KEY_PURPOSE).labeled(format!("cluster port of node {node}")),
            &issued.key,
        )?;
        if let Some((old, _)) = &current {
            vault.stage_delete(&mut batch, ctx, old.key);
        }
        batch.put_typed(
            &tables::CONTROLLER_CERTS,
            &node.0,
            &ControllerCertRecord {
                chain_pem: issued.chain_pem(),
                key,
                issued_at: ctx.now,
            },
        )?;
        batch.audit(
            AuditDraft::success(actions::CONTROLLER_CERT, vec![ObjectRef::node(node)])
                .with_context("serial", issued.info.serial.clone())
                .with_context("not_after", issued.info.not_after.to_rfc3339()),
        );
        self.store.propose(batch).await?;
        tracing::info!(
            node = %node,
            not_after = %issued.info.not_after,
            "issued the certificate of the cluster port"
        );
        Ok(issued.material()?)
    }

    /// The certificate chain and key this controller presents on the cluster port (issued
    /// as by [`NodeRegistry::controller_material`] when needed): what moves to
    /// `<data_dir>/node/` when the first peer joins.
    ///
    /// # Errors
    ///
    /// A CA, vault or store error.
    pub async fn controller_identity(
        &self,
        vault: &dyn Vault,
        ctx: &RequestCtx,
    ) -> Result<(Vec<CertificateDer<'static>>, tenko_vault::SecretBytes), ClusterError> {
        self.controller_material(vault, ctx).await?;
        let node = self.config.local_node;
        let view = self.store.read(ReadConsistency::Local).await?;
        let (record, _) = view
            .get_typed(&tables::CONTROLLER_CERTS, &node.0)?
            .ok_or_else(|| ClusterError::internal("the controller certificate is missing"))?;
        drop(view);
        let chain = CertificateDer::pem_slice_iter(record.chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                ClusterError::internal(format!("the controller certificate is unreadable: {error}"))
            })?;
        let key = vault.get_system(ctx, record.key).await?;
        Ok((chain, key))
    }

    async fn reusable(
        &self,
        vault: &dyn Vault,
        ctx: &RequestCtx,
        record: &ControllerCertRecord,
    ) -> Result<Option<TlsMaterial>, ClusterError> {
        let Ok(chain) = CertificateDer::pem_slice_iter(record.chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
        else {
            return Ok(None);
        };
        let Some(leaf) = chain.first() else {
            return Ok(None);
        };
        let info = crate::ca::CertInfo::from_der(leaf)?;
        if info.issuer != self.ca.root_info().subject || self.ca.needs_renewal(&info, ctx.now) {
            return Ok(None);
        }
        let key = match vault.get_system(ctx, record.key).await {
            Ok(key) => key,
            Err(VaultError::NotFound { .. } | VaultError::Integrity) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(TlsMaterial::from_der(chain, &key, CertSource::InternalCa).ok())
    }

    // -----------------------------------------------------------------------------------
    // Enrollment tokens.

    /// Creates an enrollment token; the text is in the returned token and nowhere else.
    ///
    /// # Errors
    ///
    /// `cluster.enrollment.roles` (403) for the role controller beside another role,
    /// `cluster.enrollment.lifetime` (422; a controller token lives at most an hour),
    /// `cluster.node.name` (422),
    /// `cluster.node.name_taken` (409), or a store or job error.
    pub async fn create_enrollment(
        &self,
        cx: &RequestCtx,
        request: NewEnrollment,
    ) -> Result<(EnrollmentView, EnrollmentToken), ClusterError> {
        let mut roles = request.roles.clone();
        if roles.is_empty() {
            roles.push(Role::Probe);
        }
        roles.sort();
        roles.dedup();
        let controller = roles.contains(&Role::Controller);
        if controller && roles.len() > 1 {
            return Err(ClusterError::new(
                "cluster.enrollment.roles",
                403,
                "a controller token carries the role controller alone",
            )
            .with_param("field", "roles"));
        }
        let ttl = match request.expires_in_secs {
            Some(secs) => Duration::from_secs(secs),
            None if controller => self.config.default_token_ttl.min(MAX_CONTROLLER_TOKEN_TTL),
            None => self.config.default_token_ttl,
        };
        if controller && ttl > MAX_CONTROLLER_TOKEN_TTL {
            return Err(ClusterError::new(
                "cluster.enrollment.lifetime",
                422,
                format!(
                    "a controller token lives at most {} seconds",
                    MAX_CONTROLLER_TOKEN_TTL.as_secs()
                ),
            )
            .with_param("field", "expires_in_secs"));
        }
        if !(MIN_TOKEN_TTL..=MAX_TOKEN_TTL).contains(&ttl) {
            return Err(ClusterError::new(
                "cluster.enrollment.lifetime",
                422,
                format!(
                    "a token lives {} to {} seconds",
                    MIN_TOKEN_TTL.as_secs(),
                    MAX_TOKEN_TTL.as_secs()
                ),
            )
            .with_param("field", "expires_in_secs"));
        }
        let name = match request.name.as_deref().map(str::trim) {
            Some(name) if !name.is_empty() => {
                check_name(name)?;
                self.name_free(name, cx.now).await?;
                Some(name.to_owned())
            }
            _ => None,
        };
        let id = Uuid::now_v7();
        // The token carries the fingerprint of this controller's CA root (`tnk2`), so the
        // node verifies the root it fetches without a separate fingerprint.
        let token = EnrollmentToken::generate(id)?.with_ca_fingerprint(self.ca_fingerprint());
        let expires_at = cx
            .now
            .checked_add(ttl)
            .ok_or_else(|| ClusterError::internal("the token expiry is out of range"))?;
        let record = EnrollmentRecord {
            id,
            digest: token.digest(),
            name,
            roles,
            vrf: request.vrf,
            created_by: cx.principal.user(),
            created_at: cx.now,
            expires_at,
            used: None,
        };
        let mut batch = WriteBatch::for_request(cx);
        batch.expect_typed(&tables::ENROLLMENTS, &id, None);
        batch.put_typed(&tables::ENROLLMENTS, &id, &record)?;
        batch.audit(
            AuditDraft::success(
                actions::ENROLLMENT_CREATE,
                vec![ObjectRef::singleton(ObjectKind::Node)],
            )
            .with_source_ip(cx.source_ip)
            .with_context("enrollment", id.to_string())
            .with_context("roles", role_list(&record.roles))
            .with_context("expires_at", expires_at.to_rfc3339()),
        );
        let revision = self
            .commit(
                cx,
                format!("create enrollment token {id}"),
                vec![ObjectRef::singleton(ObjectKind::Node)],
                batch,
            )
            .await?;
        self.want_listener();
        Ok((EnrollmentView::new(record, revision, cx.now), token))
    }

    /// Every enrollment token, newest first.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn list_enrollments(
        &self,
        now: Timestamp,
    ) -> Result<Vec<EnrollmentView>, ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let mut out: Vec<EnrollmentView> = view
            .scan_typed(&tables::ENROLLMENTS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, record, revision)| EnrollmentView::new(record, revision, now))
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        Ok(out)
    }

    /// Deletes a token (pending, used or expired).
    ///
    /// # Errors
    ///
    /// `cluster.enrollment.not_found` (404), or a store or job error.
    pub async fn delete_enrollment(&self, cx: &RequestCtx, id: Uuid) -> Result<(), ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let (record, revision) = view.get_typed(&tables::ENROLLMENTS, &id)?.ok_or_else(|| {
            ClusterError::new(
                "cluster.enrollment.not_found",
                404,
                format!("there is no enrollment token {id}"),
            )
        })?;
        drop(view);
        let mut batch = WriteBatch::for_request(cx);
        batch.expect_typed(&tables::ENROLLMENTS, &id, Some(revision));
        batch.delete_typed(&tables::ENROLLMENTS, &id);
        batch.audit(
            AuditDraft::success(
                actions::ENROLLMENT_DELETE,
                vec![ObjectRef::singleton(ObjectKind::Node)],
            )
            .with_source_ip(cx.source_ip)
            .with_context("enrollment", id.to_string())
            .with_context(
                "state",
                format!("{:?}", record.state(cx.now)).to_lowercase(),
            ),
        );
        self.commit(
            cx,
            format!("delete enrollment token {id}"),
            vec![ObjectRef::singleton(ObjectKind::Node)],
            batch,
        )
        .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------------------
    // Enrollment.

    /// Enrolls a node: checks the token and the request, issues the certificate and records
    /// the node, consuming the token. Refusals are audited with their code.
    ///
    /// # Errors
    ///
    /// `cluster.enrollment.invalid_token`, `cluster.enrollment.wrong_controller`,
    /// `cluster.enrollment.used`, `cluster.enrollment.expired` (401),
    /// `cluster.enrollment.roles` (403),
    /// `cluster.protocol.unsupported` (409), `cluster.node.name` (422),
    /// `cluster.node.name_taken` (409), `cluster.node.address` (422),
    /// `cluster.ca.invalid_csr` (422), or a store or job error.
    pub async fn enroll(
        &self,
        cx: &RequestCtx,
        request: EnrollRequest,
    ) -> Result<Enrolled, ClusterError> {
        self.enroll_over(cx, request, EnrollTransport::Https).await
    }

    /// [`Self::enroll`] for a request that arrived over `transport`. An enrollment over
    /// plain HTTP is recorded with the context `transport: http`, one whose scheme the
    /// trusted proxy did not state with `transport: unknown`; the caller has checked that
    /// the profile allows it.
    ///
    /// # Errors
    ///
    /// Those of [`Self::enroll`].
    pub async fn enroll_over(
        &self,
        cx: &RequestCtx,
        request: EnrollRequest,
        transport: EnrollTransport,
    ) -> Result<Enrolled, ClusterError> {
        match transport {
            EnrollTransport::PlainHttp => {
                tracing::warn!(source = ?cx.source_ip, "an enrollment token arrived over plain HTTP (Lab profile)");
            }
            EnrollTransport::Unstated => {
                tracing::warn!(source = ?cx.source_ip, "an enrollment token arrived through a reverse proxy that did not state the scheme (Lab profile)");
            }
            EnrollTransport::Https => {}
        }
        match self.try_enroll(cx, request, transport).await {
            Ok(enrolled) => Ok(enrolled),
            Err((error, token)) => {
                self.audit_refusal(cx, &error, token).await;
                Err(error)
            }
        }
    }

    /// Refuses an enrollment that arrived over plain HTTP where the profile does not allow it
    /// (every profile but Lab), whatever the client was told: the refusal is audited with the
    /// code `cluster.enrollment.plain_http`, and a token whose secret matches and that is
    /// not used yet is withdrawn, since it crossed the network in clear text and anyone on
    /// the path may hold it now. The refusal names the token only when its secret matched,
    /// and counts among the refusals anyone can send otherwise. Returns the error to answer
    /// with.
    pub async fn refuse_plain_http(
        &self,
        cx: &RequestCtx,
        request: &EnrollRequest,
    ) -> ClusterError {
        let error = plain_http_refused();
        let mut proven = None;
        if let Ok(token) = EnrollmentToken::parse(&request.token)
            && self.withdraw_exposed(cx, &token).await
        {
            proven = Some(token.id());
        }
        self.audit_refusal(cx, &error, proven).await;
        error
    }

    /// Refuses an enrollment whose scheme the trusted reverse proxy did not state, where the
    /// profile does not allow it (every profile but Lab): 403
    /// `cluster.enrollment.scheme_unknown`, audited with that code among the refusals anyone
    /// can send (one summary per window past the burst, as the other refusals). The token
    /// is kept: nothing shows that it crossed the network in clear text. Returns the error
    /// to answer with.
    pub async fn refuse_unstated_scheme(&self, cx: &RequestCtx) -> ClusterError {
        let error = scheme_unknown();
        self.audit_refusal(cx, &error, None).await;
        error
    }

    /// Deletes the pending token record of `token` when its secret matches, audited as
    /// `cluster.enrollment.delete` with the reason `plain_http`. Returns whether the secret
    /// matched (whether or not the token could still be withdrawn).
    async fn withdraw_exposed(&self, cx: &RequestCtx, token: &EnrollmentToken) -> bool {
        let id = token.id();
        let Ok(view) = self.store.read(ReadConsistency::Local).await else {
            return false;
        };
        let Ok(Some((record, revision))) = view.get_typed(&tables::ENROLLMENTS, &id) else {
            return false;
        };
        drop(view);
        if !record.digest.matches(token) {
            return false;
        }
        if record.used.is_some() {
            return true;
        }
        let mut batch = WriteBatch::for_request(cx);
        batch.expect_typed(&tables::ENROLLMENTS, &id, Some(revision));
        batch.delete_typed(&tables::ENROLLMENTS, &id);
        batch.audit(
            AuditDraft::success(
                actions::ENROLLMENT_DELETE,
                vec![ObjectRef::singleton(ObjectKind::Node)],
            )
            .with_source_ip(cx.source_ip)
            .with_context("enrollment", id.to_string())
            .with_context("reason", "plain_http"),
        );
        match self.store.propose(batch).await {
            Ok(_) => {
                tracing::warn!(enrollment = %id, "withdrew an enrollment token that arrived over plain HTTP");
            }
            Err(error) => {
                tracing::warn!(%error, "could not withdraw an enrollment token that arrived over plain HTTP");
            }
        }
        true
    }

    /// Audits a refused enrollment. In each [`Timings::refusal_window`] this controller
    /// records [`REFUSAL_AUDIT_BURST`] refusals one by one of requests that did not know a
    /// token's secret (anyone can send those), and as many again of requests that did (a
    /// used or expired token, a refused role or name); the rest of the window's are counted
    /// and recorded at its end as one summary (`cluster.enrollment.refusals`: how many, by
    /// code, and from which addresses), so a flood from the network cannot fill the audit
    /// log and the store, and cannot push a refusal of a real token out of it.
    async fn audit_refusal(&self, cx: &RequestCtx, error: &ClusterError, token: Option<Uuid>) {
        if error.status() >= 500 {
            return;
        }
        let code = match error.code() {
            "cluster.enrollment.invalid_token" => "cluster.enrollment.invalid_token",
            "cluster.enrollment.wrong_controller" => "cluster.enrollment.wrong_controller",
            "cluster.enrollment.used" => "cluster.enrollment.used",
            "cluster.enrollment.expired" => "cluster.enrollment.expired",
            "cluster.enrollment.roles" => "cluster.enrollment.roles",
            "cluster.protocol.unsupported" => "cluster.protocol.unsupported",
            "cluster.node.name_taken" => "cluster.node.name_taken",
            "cluster.ca.invalid_csr" => "cluster.ca.invalid_csr",
            "cluster.enrollment.plain_http" => "cluster.enrollment.plain_http",
            "cluster.enrollment.scheme_unknown" => "cluster.enrollment.scheme_unknown",
            _ => "cluster.enrollment.refused",
        };
        let window = self.timings().refusal_window;
        let flush_at = {
            let mut refusals = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
            let now = Instant::now();
            let started = match refusals.started {
                Some(started) if now.saturating_duration_since(started) < window => started,
                _ => {
                    refusals.started = Some(now);
                    refusals.recorded = 0;
                    refusals.recorded_known = 0;
                    now
                }
            };
            // Before the secret matched: the token is malformed, unknown, wrong or from
            // another controller, which anyone can send; so is a refusal over plain HTTP that
            // names no token, and one through a proxy that did not state the scheme.
            let unproven = matches!(
                error.code(),
                "cluster.enrollment.invalid_token"
                    | "cluster.enrollment.wrong_controller"
                    | "cluster.enrollment.scheme_unknown"
            ) || (error.code() == "cluster.enrollment.plain_http"
                && token.is_none());
            let recorded = if unproven {
                &mut refusals.recorded
            } else {
                &mut refusals.recorded_known
            };
            if *recorded < REFUSAL_AUDIT_BURST {
                *recorded += 1;
                None
            } else {
                let first = refusals.pending.is_none();
                refusals
                    .pending
                    .get_or_insert_with(|| PendingRefusals::new(cx.now))
                    .add(code, cx.source_ip);
                // The first refusal past the burst schedules the summary of the window.
                Some(first.then_some(started + window))
            }
        };
        match flush_at {
            None => {}
            Some(None) => return,
            Some(Some(at)) => {
                let store = Arc::clone(&self.store);
                let refusals = Arc::clone(&self.refusals);
                tokio::spawn(async move {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
                    let pending = refusals
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .pending
                        .take();
                    if let Some(pending) = pending {
                        pending.audit(store.as_ref()).await;
                    }
                });
                return;
            }
        }
        let mut draft = AuditDraft::failed(
            actions::NODE_ENROLL,
            Vec::new(),
            &Refusal(code, error.detail()),
        )
        .with_source_ip(cx.source_ip);
        if let Some(token) = token {
            draft = draft.with_context("enrollment", token.to_string());
        }
        let mut batch = WriteBatch::for_request(cx);
        batch.audit(draft);
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(%error, "a refused enrollment could not be audited");
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the enrollment checks read best as one sequence"
    )]
    async fn try_enroll(
        &self,
        cx: &RequestCtx,
        request: EnrollRequest,
        transport: EnrollTransport,
    ) -> Result<Enrolled, (ClusterError, Option<Uuid>)> {
        let token = EnrollmentToken::parse(&request.token).map_err(|_| (invalid_token(), None))?;
        // A `tnk2` token names the CA root of the controller that issued it: one that reached
        // another controller is a misdirected enrollment, refused before its record is
        // looked up. A `tnk1` token names none and goes on.
        if let Some(fingerprint) = token.ca_fingerprint()
            && fingerprint != self.ca_fingerprint()
        {
            return Err((wrong_controller(), None));
        }
        let token_id = token.id();
        let with_token = |error: ClusterError| (error, Some(token_id));
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| with_token(error.into()))?;
        // An unknown id and a wrong secret name no token: anyone can send those.
        let (mut record, token_revision) = view
            .get_typed(&tables::ENROLLMENTS, &token_id)
            .map_err(|error| with_token(error.into()))?
            .ok_or_else(|| (invalid_token(), None))?;
        if !record.digest.matches(&token) {
            return Err((invalid_token(), None));
        }
        drop(token);
        if record.used.is_some() {
            return Err(with_token(ClusterError::new(
                "cluster.enrollment.used",
                401,
                "the enrollment token was used already; create a new one",
            )));
        }
        if cx.now >= record.expires_at {
            return Err(with_token(ClusterError::new(
                "cluster.enrollment.expired",
                401,
                "the enrollment token expired; create a new one",
            )));
        }
        let mut roles = if request.roles.is_empty() {
            record.roles.clone()
        } else {
            request.roles.clone()
        };
        roles.sort();
        roles.dedup();
        if let Some(role) = roles.iter().find(|role| !record.roles.contains(role)) {
            return Err(with_token(
                ClusterError::new(
                    "cluster.enrollment.roles",
                    403,
                    format!(
                        "the token does not allow the role {role}; it allows {}",
                        role_list(&record.roles)
                    ),
                )
                .with_param("role", role.as_str()),
            ));
        }
        if !request.majors.is_empty() {
            version::negotiate(&self.config.majors, &request.majors).map_err(|mismatch| {
                with_token(ClusterError::new(
                    "cluster.protocol.unsupported",
                    409,
                    mismatch.detail("the controller", "the node"),
                ))
            })?;
        }
        let address = match request.address.as_deref().map(str::trim) {
            Some(address) if !address.is_empty() => {
                if !valid_address(address) {
                    return Err(with_token(
                        ClusterError::new(
                            "cluster.node.address",
                            422,
                            "the address is neither an IP address nor a host name",
                        )
                        .with_param("field", "address"),
                    ));
                }
                Some(address.to_owned())
            }
            _ => cx.source_ip.map(|ip| ip.to_string()),
        };
        let csr = CertificateSigningRequestDer::from_pem_slice(request.csr.as_bytes()).map_err(
            |error| {
                with_token(ClusterError::coded(&crate::ca::CaError::InvalidCsr {
                    reason: format!("it is not a PEM certificate request: {error}"),
                }))
            },
        )?;
        // The node id: one past the last one handed out, never below the first enrolled
        // id, never this controller's id or a node that exists.
        let seq = view
            .get_typed(&tables::NODE_SEQ, &())
            .map_err(|error| with_token(error.into()))?;
        let mut id = seq
            .as_ref()
            .map_or(FIRST_ENROLLED_NODE_ID, |(last, _)| last + 1)
            .max(FIRST_ENROLLED_NODE_ID);
        while id == self.config.local_node.0
            || view
                .get_typed(&tables::NODES, &id)
                .map_err(|error| with_token(error.into()))?
                .is_some()
        {
            id += 1;
        }
        let node = NodeId(id);
        let name = match record
            .name
            .clone()
            .or_else(|| request.name.as_deref().map(str::trim).map(str::to_owned))
            .filter(|name| !name.is_empty())
        {
            Some(name) => name,
            None => format!("node-{id}"),
        };
        check_name(&name).map_err(with_token)?;
        let name_key = name.to_lowercase();
        let in_use = || -> Result<bool, ClusterError> {
            Ok(view.get_typed(&tables::NODE_NAMES, &name_key)?.is_some()
                || reserved(view.as_ref(), &name_key, cx.now, Some(token_id))?)
        };
        if in_use().map_err(with_token)? {
            return Err(with_token(name_taken(&name)));
        }
        drop(view);
        let issued = self
            .ca
            .issue_node_cert_for(node, roles.iter().copied().collect(), csr.as_ref(), cx.now)
            .map_err(|error| with_token(error.into()))?;
        let certificate = CertificateRef {
            serial: issued.info.serial.clone(),
            sha256: issued.info.sha256.clone(),
            not_before: issued.info.not_before,
            not_after: issued.info.not_after,
        };
        let node_record = NodeRecord {
            id: node,
            name: name.clone(),
            roles: roles.clone(),
            address,
            vrf: record.vrf,
            certificate: certificate.clone(),
            serials: vec![certificate],
            enrolled_at: cx.now,
            enrollment: token_id,
            enrolled_by: record.created_by,
            renewed_at: None,
            last_seen: None,
            version: Some(request.version.clone()).filter(|version| !version.is_empty()),
            protocol: crate::model::ProtocolState {
                offered: request.majors.clone(),
                agreed: None,
                mismatch: None,
            },
        };
        record.used = Some(TokenUse { node, at: cx.now });
        let mut node_cx = cx.clone();
        node_cx.principal = Principal::Node { id: node };
        let build = || -> Result<WriteBatch, ClusterError> {
            let mut batch = WriteBatch::for_request(&node_cx);
            batch.expect_typed(
                &tables::NODE_SEQ,
                &(),
                seq.as_ref().map(|(_, revision)| *revision),
            );
            batch.put_typed(&tables::NODE_SEQ, &(), &id)?;
            batch.expect_typed(&tables::ENROLLMENTS, &token_id, Some(token_revision));
            batch.put_typed(&tables::ENROLLMENTS, &token_id, &record)?;
            batch.expect_typed(&tables::NODE_NAMES, &name_key, None);
            batch.put_typed(&tables::NODE_NAMES, &name_key, &id)?;
            batch.expect_typed(&tables::NODES, &id, None);
            batch.put_typed(&tables::NODES, &id, &node_record)?;
            let mut draft = AuditDraft::success(actions::NODE_ENROLL, vec![ObjectRef::node(node)])
                .with_source_ip(cx.source_ip)
                .with_context("name", name.clone())
                .with_context("roles", role_list(&roles))
                .with_context("enrollment", token_id.to_string())
                .with_context("serial", issued.info.serial.clone())
                .with_context("not_after", issued.info.not_after.to_rfc3339());
            match transport {
                EnrollTransport::PlainHttp => draft = draft.with_context("transport", "http"),
                EnrollTransport::Unstated => draft = draft.with_context("transport", "unknown"),
                EnrollTransport::Https => {}
            }
            batch.audit(draft);
            Ok(batch)
        };
        let batch = build().map_err(with_token)?;
        let revision = match self
            .commit(
                &node_cx,
                format!("enroll node {name}"),
                vec![ObjectRef::node(node)],
                batch,
            )
            .await
        {
            Ok(revision) => revision,
            Err(error) if error.code() == StoreError::PRECONDITION_FAILED => {
                // Another enrollment won the race for the token, the id or the name.
                return Err(with_token(self.race_error(token_id, &name_key).await));
            }
            Err(error) => return Err(with_token(error)),
        };
        tracing::info!(node = %node, name = %name, roles = %role_list(&roles), "node enrolled");
        let certificate_pem = issued.chain_pem();
        Ok(Enrolled {
            node: NodeView::new(node_record, revision, None),
            certificate: issued,
            certificate_pem,
            ca_root_pem: self.ca.root_pem(),
        })
    }

    async fn race_error(&self, token: Uuid, name_key: &str) -> ClusterError {
        let Ok(view) = self.store.read(ReadConsistency::Linearizable).await else {
            return ClusterError::new(
                "cluster.enrollment.conflict",
                409,
                "another enrollment happened at the same time; try again",
            );
        };
        if let Ok(Some((record, _))) = view.get_typed(&tables::ENROLLMENTS, &token)
            && record.used.is_some()
        {
            return ClusterError::new(
                "cluster.enrollment.used",
                401,
                "the enrollment token was used already; create a new one",
            );
        }
        if let Ok(Some(_)) = view.get_typed(&tables::NODE_NAMES, &name_key.to_owned()) {
            return name_taken(name_key);
        }
        ClusterError::new(
            "cluster.enrollment.conflict",
            409,
            "another enrollment happened at the same time; try again",
        )
    }

    /// Whether `name` is free for a new token: no node has it, and no token that can still
    /// be used names it (the enrollment of the second one could never succeed).
    async fn name_free(&self, name: &str, now: Timestamp) -> Result<(), ClusterError> {
        let key = name.to_lowercase();
        let view = self.store.read(ReadConsistency::Local).await?;
        if reserved(view.as_ref(), &key, now, None)?
            || view.get_typed(&tables::NODE_NAMES, &key)?.is_some()
        {
            return Err(name_taken(name));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------
    // Nodes.

    /// A node's record and revision.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn record(
        &self,
        node: NodeId,
    ) -> Result<Option<(NodeRecord, Revision)>, ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        Ok(view.get_typed(&tables::NODES, &node.0)?)
    }

    /// Every node with its live connection, by id.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn list_nodes(&self) -> Result<Vec<NodeView>, ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let remote = remote_connections(view.as_ref(), self.config.local_node)?;
        Ok(view
            .scan_typed(&tables::NODES, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, record, revision)| {
                let live = self
                    .sessions
                    .view(record.id)
                    .or_else(|| remote.get(&record.id).cloned());
                NodeView::new(record, revision, live)
            })
            .collect())
    }

    /// One node with its live connection, to this controller or another one.
    ///
    /// # Errors
    ///
    /// `cluster.node.not_found` (404), or a store error.
    pub async fn get_node(&self, node: NodeId) -> Result<NodeView, ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let (record, revision) = view
            .get_typed(&tables::NODES, &node.0)?
            .ok_or_else(|| not_found(node))?;
        let live = match self.sessions.view(node) {
            Some(live) => Some(live),
            None => remote_connections(view.as_ref(), self.config.local_node)?.remove(&node),
        };
        Ok(NodeView::new(record, revision, live))
    }

    /// Records that `node` is connected to this controller (written when it connects).
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn record_connection(
        &self,
        node: NodeId,
        live: &ConnectionView,
    ) -> Result<(), ClusterError> {
        let mut ctx = RequestCtx::system(SystemComponent::Cluster);
        ctx.now = live.since;
        let mut batch = WriteBatch::for_request(&ctx);
        batch.put_typed(
            &tables::CONNECTIONS,
            &node.0,
            &ConnectionRecord {
                controller: self.config.local_node,
                since: live.since,
                peer: live.peer,
                version: live.version.clone(),
                major: live.major,
            },
        )?;
        self.store.propose(batch).await?;
        Ok(())
    }

    /// Removes the connection record of `node` while it names this controller (written
    /// when the node disconnects; a newer connection to another controller stays).
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn clear_connection(&self, node: NodeId) -> Result<(), ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let Some((record, revision)) = view.get_typed(&tables::CONNECTIONS, &node.0)? else {
            return Ok(());
        };
        drop(view);
        if record.controller != self.config.local_node {
            return Ok(());
        }
        let ctx = RequestCtx::system(SystemComponent::Cluster);
        let mut batch = WriteBatch::for_request(&ctx);
        batch.expect_typed(&tables::CONNECTIONS, &node.0, Some(revision));
        batch.delete_typed(&tables::CONNECTIONS, &node.0);
        match self.store.propose(batch).await {
            Ok(_) | Err(StoreError::PreconditionFailed(_)) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Removes every connection record that names this controller: the connections of a
    /// previous run (call at start, before the cluster port serves nodes).
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn clear_own_connections(&self) -> Result<usize, ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let ctx = RequestCtx::system(SystemComponent::Cluster);
        let mut batch = WriteBatch::for_request(&ctx);
        let mut removed = 0;
        for (node, record, revision) in
            view.scan_typed(&tables::CONNECTIONS, KeyRange::all(), usize::MAX, false)?
        {
            if record.controller == self.config.local_node {
                batch.expect_typed(&tables::CONNECTIONS, &node, Some(revision));
                batch.delete_typed(&tables::CONNECTIONS, &node);
                removed += 1;
            }
        }
        drop(view);
        if removed > 0 {
            match self.store.propose(batch).await {
                Ok(_) | Err(StoreError::PreconditionFailed(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(removed)
    }

    /// Follows `cluster.revocations` until `stop` turns true: every revocation, made on
    /// this controller or another one, reaches the TLS verifier's set, and the connections
    /// of a revoked node close, within a moment of its replication.
    pub fn follow_revocations(self: &Arc<Self>, mut stop: watch::Receiver<bool>) -> JoinHandle<()> {
        let registry = Arc::clone(self);
        tokio::spawn(async move {
            let filter = WatchFilter::tables([tables::REVOCATIONS.name().clone()]);
            let mut known: HashSet<String> = HashSet::new();
            if let Err(error) = registry.apply_revocations(&mut known).await {
                tracing::debug!(code = %error.code(), "revocations: {}", error.detail());
            }
            loop {
                let Ok(mut changes) = registry.store.watch(None, filter.clone()) else {
                    tokio::select! {
                        () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
                        () = tokio::time::sleep(Duration::from_secs(1)) => continue,
                    }
                };
                loop {
                    tokio::select! {
                        () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
                        change = changes.next() => {
                            let following = matches!(change, Some(Ok(_)));
                            if let Err(error) = registry.apply_revocations(&mut known).await {
                                tracing::warn!(code = %error.code(), "revocations could not be read: {}", error.detail());
                            }
                            // Lagged or compacted: everything was read again; a new stream
                            // follows from here.
                            if !following {
                                break;
                            }
                        }
                    }
                }
            }
        })
    }

    /// Reloads the revocation set and closes the connections of nodes revoked since
    /// `known`. On the first call `known` is empty, so every revoked node that still has a
    /// session or a connection here loses it: the revocations that were in the table
    /// before, and the first one ever made, are no exception.
    async fn apply_revocations(&self, known: &mut HashSet<String>) -> Result<(), ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let rows = view.scan_typed(&tables::REVOCATIONS, KeyRange::all(), usize::MAX, false)?;
        drop(view);
        let fresh: BTreeSet<NodeId> = rows
            .iter()
            .filter(|(serial, _, _)| !known.contains(serial))
            .map(|(_, revocation, _)| revocation.node)
            .collect();
        let nodes: HashSet<NodeId> = rows
            .iter()
            .map(|(_, revocation, _)| revocation.node)
            .collect();
        let serials: HashSet<String> = rows.into_iter().map(|(serial, _, _)| serial).collect();
        // The verifier first: a handshake after this point is refused. A connection whose
        // handshake completed before it and that is not tracked yet when the loop below
        // looks finds the node record gone at its first call (the record and the rows
        // commit together).
        self.revoked.replace(serials.iter().cloned());
        self.revoked_nodes.store(Arc::new(nodes));
        *known = serials;
        let now = Timestamp::now();
        for node in fresh {
            if self.sessions.connection_count(node) == 0 && self.sessions.view(node).is_none() {
                continue;
            }
            tracing::warn!(node = %node, "closing the connections of a revoked node");
            self.sessions.revoke(node, now);
        }
        Ok(())
    }

    /// Whether `node` was revoked: a row of `cluster.revocations` names it. A controller
    /// that is not enrolled through a token has no node record, so the Raft service checks
    /// this instead of the record for a caller without one.
    pub fn is_revoked_node(&self, node: NodeId) -> bool {
        self.revoked_nodes.load().contains(&node)
    }

    /// The record of `node` for an edit: as this node has applied it on the first attempt,
    /// and linearizable after a lost race, so that the next plan starts from the write that
    /// won.
    async fn record_for_edit(
        &self,
        node: NodeId,
        attempt: usize,
    ) -> Result<Option<(NodeRecord, Revision)>, ClusterError> {
        let consistency = if attempt == 1 {
            ReadConsistency::Local
        } else {
            ReadConsistency::Linearizable
        };
        let view = self.store.read(consistency).await?;
        Ok(view.get_typed(&tables::NODES, &node.0)?)
    }

    /// Revokes a node: removes it, revokes every certificate it holds, tells its sessions
    /// and closes its connections. Returns the revoked serials.
    ///
    /// The node's own bookkeeping writes the same record (the last sighting when it
    /// connects, disconnects and every five minutes, the agreed protocol), so a revocation
    /// can lose the race for the record's revision. The job engine then records nothing and
    /// leaves re-planning to the caller: the record is read again, with the certificates it
    /// holds by then, up to [`NODE_EDIT_ATTEMPTS`] times.
    ///
    /// A controller that is a member of the controller cluster is refused: it leaves through
    /// the cluster's removal, which revokes it in the order that keeps the cluster able to
    /// write and to take it out (`crate::peers`).
    ///
    /// # Errors
    ///
    /// `cluster.node.not_found` (404), `cluster.node.is_member` (409),
    /// `cluster.node.conflict` (409) when every attempt lost the race, or a store or job
    /// error.
    pub async fn revoke(&self, cx: &RequestCtx, node: NodeId) -> Result<Vec<String>, ClusterError> {
        let view = self.store.read(ReadConsistency::Linearizable).await?;
        if view.get_typed(&tables::MEMBERS, &node.0)?.is_some() {
            return Err(ClusterError::new(
                "cluster.node.is_member",
                409,
                format!(
                    "node {node} is a member of the controller cluster: remove it with                      `tenko cluster remove {node} --yes`, which revokes it"
                ),
            )
            .with_param("node", node.to_string()));
        }
        drop(view);
        self.revoke_member(cx, node).await
    }

    /// [`Self::revoke`] for a controller that the cluster's removal takes out, which may
    /// be a member.
    ///
    /// # Errors
    ///
    /// As [`Self::revoke`], without `cluster.node.is_member`.
    pub(crate) async fn revoke_member(
        &self,
        cx: &RequestCtx,
        node: NodeId,
    ) -> Result<Vec<String>, ClusterError> {
        let mut attempt = 1;
        let (record, serial_list) = loop {
            let (record, revision) = self
                .record_for_edit(node, attempt)
                .await?
                .ok_or_else(|| not_found(node))?;
            // Every certificate the record names. One that a renewal retired has its end in
            // the record moved forward but may be valid for longer: its row lives until the
            // newest certificate expires (an older one never ends later unless the CA's
            // lifetime was shortened in between).
            let newest = record.certificate.not_after;
            let serials: Vec<(&str, Timestamp)> = record
                .serials
                .iter()
                .filter_map(|cert| {
                    let until = if cert.serial == record.certificate.serial {
                        cert.not_after
                    } else {
                        cert.not_after.max(newest)
                    };
                    (until > cx.now).then_some((cert.serial.as_str(), until))
                })
                .collect();
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&tables::NODES, &node.0, Some(revision));
            batch.delete_typed(&tables::NODES, &node.0);
            batch.delete_typed(&tables::NODE_NAMES, &record.name.to_lowercase());
            for (serial, until) in &serials {
                batch.put_typed(
                    &tables::REVOCATIONS,
                    &(*serial).to_owned(),
                    &Revocation {
                        node,
                        revoked_at: cx.now,
                        not_after: *until,
                    },
                )?;
            }
            let serial_list: Vec<String> = serials
                .iter()
                .map(|(serial, _)| (*serial).to_owned())
                .collect();
            batch.audit(
                AuditDraft::success(actions::NODE_REVOKE, vec![ObjectRef::node(node)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", record.name.clone())
                    .with_context("serials", serial_list.join(",")),
            );
            match self
                .commit(
                    cx,
                    format!("revoke node {}", record.name),
                    vec![ObjectRef::node(node)],
                    batch,
                )
                .await
            {
                Ok(_) => break (record, serial_list),
                Err(error) if error.code() == StoreError::PRECONDITION_FAILED => {
                    if attempt == NODE_EDIT_ATTEMPTS {
                        return Err(ClusterError::new(
                            NODE_CONFLICT,
                            409,
                            "the node changed at the same time; try again",
                        ));
                    }
                    tracing::debug!(node = %node, attempt, "the node record changed during the revocation; planning it again");
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        };
        self.revoked.insert(serial_list.iter().cloned());
        let mut nodes = HashSet::clone(&self.revoked_nodes.load());
        nodes.insert(node);
        self.revoked_nodes.store(Arc::new(nodes));
        self.sessions.revoke(node, cx.now);
        self.lock_touched().remove(&node);
        tracing::warn!(node = %node, name = %record.name, "node revoked");
        Ok(serial_list)
    }

    /// Renews the certificate of a connected node for the key of `csr_der`, with the node's
    /// id and roles. The calling certificate (`serial`) must be one the node holds, inside
    /// its renewal window ([`renewal_window`]), and the node's last renewal at least
    /// [`RENEW_INTERVAL`] ago.
    ///
    /// The record keeps the calling certificate beside the new one and drops any other: a
    /// certificate an earlier renewal replaced, or one whose answer never reached the node.
    /// So a node holds at most two certificates however often it renews, and its revocation
    /// stays small. The calling certificate works on until the node shows that it holds the
    /// new one ([`retire_replaced`](Self::retire_replaced)), or until it expires.
    ///
    /// The certificate is issued once. Like [`revoke`](Self::revoke), the write of the
    /// record is planned again from a fresh read when the node's bookkeeping changed the
    /// record in between, up to [`NODE_EDIT_ATTEMPTS`] times.
    ///
    /// # Errors
    ///
    /// `cluster.node.not_found` (404), `cluster.node.certificate_unknown` (403),
    /// `cluster.node.renew_not_due`, `cluster.node.renew_too_soon` (409),
    /// `cluster.ca.invalid_csr` (422), or a store or job error (the store's conflict when
    /// every attempt lost the race).
    pub async fn renew(
        &self,
        node: NodeId,
        serial: &str,
        csr_der: &[u8],
        now: Timestamp,
    ) -> Result<NodeCert, ClusterError> {
        let (mut record, mut revision) = self
            .record_for_edit(node, 1)
            .await?
            .ok_or_else(|| not_found(node))?;
        self.check_renewal(&record, serial, now)?;
        let issued = self
            .ca
            .issue_node_cert_for(node, record.role_set(), csr_der, now)?;
        let certificate = CertificateRef {
            serial: issued.info.serial.clone(),
            sha256: issued.info.sha256.clone(),
            not_before: issued.info.not_before,
            not_after: issued.info.not_after,
        };
        let mut cx = RequestCtx::new(Principal::Node { id: node });
        cx.now = now;
        let mut attempt = 1;
        loop {
            record
                .serials
                .retain(|cert| cert.serial == serial && cert.not_after > now);
            record.serials.push(certificate.clone());
            record.certificate = certificate.clone();
            record.renewed_at = Some(now);
            let mut batch = WriteBatch::for_request(&cx);
            batch.expect_typed(&tables::NODES, &node.0, Some(revision));
            batch.put_typed(&tables::NODES, &node.0, &record)?;
            batch.audit(
                AuditDraft::success(actions::NODE_RENEW, vec![ObjectRef::node(node)])
                    .with_context("serial", issued.info.serial.clone())
                    .with_context("previous", serial.to_owned())
                    .with_context("not_after", issued.info.not_after.to_rfc3339()),
            );
            match self
                .commit(
                    &cx,
                    format!("renew the certificate of node {}", record.name),
                    vec![ObjectRef::node(node)],
                    batch,
                )
                .await
            {
                Ok(_) => break,
                Err(error)
                    if error.code() == StoreError::PRECONDITION_FAILED
                        && attempt < NODE_EDIT_ATTEMPTS =>
                {
                    tracing::debug!(node = %node, attempt, "the node record changed during the renewal; planning it again");
                    attempt += 1;
                    (record, revision) = self
                        .record_for_edit(node, attempt)
                        .await?
                        .ok_or_else(|| not_found(node))?;
                    // A renewal through another controller that won the race counts.
                    self.check_renewal(&record, serial, now)?;
                }
                Err(error) => return Err(error),
            }
        }
        tracing::info!(node = %node, not_after = %issued.info.not_after, "node certificate renewed");
        Ok(issued)
    }

    /// Whether `serial` of `record` may be renewed at `now`.
    fn check_renewal(
        &self,
        record: &NodeRecord,
        serial: &str,
        now: Timestamp,
    ) -> Result<(), ClusterError> {
        let Some(cert) = record
            .serials
            .iter()
            .find(|cert| cert.serial == serial && cert.not_after > now)
        else {
            return Err(unknown_certificate());
        };
        if let Some(at) = record.renewed_at
            && now.saturating_since(at) < RENEW_INTERVAL
        {
            let next = at.checked_add(RENEW_INTERVAL).unwrap_or(at);
            return Err(ClusterError::new(
                "cluster.node.renew_too_soon",
                409,
                format!(
                    "the node renewed its certificate less than an hour ago; it may renew \
                     again from {next}"
                ),
            )
            .with_param("from", next.to_rfc3339()));
        }
        let window = renewal_window(cert, self.ca.policy().renew_before_days);
        let due = Timestamp(cert.not_after.0 - window);
        if now < due {
            return Err(ClusterError::new(
                "cluster.node.renew_not_due",
                409,
                format!("the certificate is not due for renewal before {due}"),
            )
            .with_param("from", due.to_rfc3339()));
        }
        Ok(())
    }

    /// Retires the certificates a renewal replaced once the node shows that it holds the
    /// newest one: its connection presents it, or its heartbeat reports the expiry
    /// `newest_not_after` of the newest certificate. Each other certificate the record holds
    /// then ends, in the record, [`Timings::retire_grace`] from `now` (or at its own expiry
    /// when that is sooner); [`authenticate`](Self::authenticate) refuses it afterwards with
    /// `cluster.node.certificate_replaced`, which sends the node to connect again with the
    /// new one. A node that never got the new certificate keeps the old one: nothing here
    /// happens without that proof. Returns `true` when nothing is left to retire for this
    /// proof (retired now or before), `false` when the proof does not name the newest
    /// certificate or a race with the node's bookkeeping was lost: the caller tries again
    /// later.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn retire_replaced(
        &self,
        node: NodeId,
        newest_not_after: Timestamp,
        now: Timestamp,
    ) -> Result<bool, ClusterError> {
        let Some((mut record, revision)) = self.record(node).await? else {
            return Ok(false);
        };
        if record.certificate.not_after != newest_not_after {
            return Ok(false);
        }
        let Some(until) = now.checked_add(self.timings().retire_grace) else {
            return Ok(false);
        };
        let newest = record.certificate.serial.clone();
        let mut retired = Vec::new();
        for cert in &mut record.serials {
            if cert.serial != newest && cert.not_after > until {
                cert.not_after = until;
                retired.push(cert.serial.clone());
            }
        }
        if retired.is_empty() {
            return Ok(true);
        }
        let mut ctx = RequestCtx::system(SystemComponent::Cluster);
        ctx.now = now;
        let mut batch = WriteBatch::for_request(&ctx);
        batch.expect_typed(&tables::NODES, &node.0, Some(revision));
        batch.put_typed(&tables::NODES, &node.0, &record)?;
        match self.store.propose(batch).await {
            Ok(_) => {}
            Err(StoreError::PreconditionFailed(_)) => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        tracing::info!(node = %node, serials = %retired.join(","), until = %until, "the node holds its renewed certificate; the replaced ones retire");
        Ok(true)
    }

    /// Whether `record` names a certificate besides the newest that
    /// [`retire_replaced`](Self::retire_replaced) would still retire at `now`: a cheap
    /// look before the store is read again.
    pub fn retirable(&self, record: &NodeRecord, now: Timestamp) -> bool {
        let Some(until) = now.checked_add(self.timings().retire_grace) else {
            return false;
        };
        record
            .serials
            .iter()
            .any(|cert| cert.serial != record.certificate.serial && cert.not_after > until)
    }

    /// Checks a caller on the cluster port: the node exists and holds the certificate.
    ///
    /// # Errors
    ///
    /// `cluster.node.unknown` or `cluster.node.certificate_unknown` (403).
    pub async fn authenticate(
        &self,
        node: NodeId,
        serial: &str,
        now: Timestamp,
    ) -> Result<NodeRecord, ClusterError> {
        let local = self.record(node).await?;
        let record = match local {
            Some(record) => Some(record),
            // Enrolled through another controller a moment ago: ask the leader before
            // refusing.
            None => match self.store.read(ReadConsistency::Linearizable).await {
                Ok(view) => view.get_typed(&tables::NODES, &node.0)?,
                Err(_) => None,
            },
        };
        let (record, _) = record.ok_or_else(|| {
            ClusterError::new(
                "cluster.node.unknown",
                403,
                format!("node {node} is not enrolled in this installation"),
            )
        })?;
        if !record.holds(serial, now) {
            // A certificate a renewal replaced: the node holds a newer one and connects
            // again with it (503 tells it to; 403 would hold it back as refused).
            if record.certificate.serial != serial
                && record.serials.iter().any(|cert| cert.serial == serial)
            {
                return Err(ClusterError::new(
                    "cluster.node.certificate_replaced",
                    503,
                    "the certificate of this connection was replaced by a renewal; connect \
                     again with the new one",
                ));
            }
            return Err(unknown_certificate());
        }
        Ok(record)
    }

    /// Records a successful handshake: the offer, the agreed major and the version, written
    /// only when something changed.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn hello_ok(
        &self,
        node: NodeId,
        offered: &[u32],
        agreed: u32,
        version: &str,
    ) -> Result<(), ClusterError> {
        self.lock_mismatches().remove(&node);
        let Some((mut record, revision)) = self.record(node).await? else {
            return Ok(());
        };
        let version = Some(version.to_owned()).filter(|version| !version.is_empty());
        if record.protocol.offered == offered
            && record.protocol.agreed == Some(agreed)
            && record.protocol.mismatch.is_none()
            && record.version == version
        {
            return Ok(());
        }
        record.protocol.offered = offered.to_vec();
        record.protocol.agreed = Some(agreed);
        record.protocol.mismatch = None;
        record.version = version;
        self.write_bookkeeping(&record, revision, Timestamp::now())
            .await
    }

    /// Records a refused handshake: the mismatch on the node and an audit record, at most
    /// once per [`MISMATCH_REPEAT`] for the same offer.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn hello_mismatch(
        &self,
        node: NodeId,
        mismatch: &VersionMismatch,
        version: &str,
        now: Timestamp,
    ) -> Result<(), ClusterError> {
        {
            let mut seen = self.lock_mismatches();
            if let Some((previous, at)) = seen.get(&node)
                && previous == mismatch
                && at.elapsed() < MISMATCH_REPEAT
            {
                return Ok(());
            }
            seen.insert(node, (mismatch.clone(), Instant::now()));
        }
        tracing::warn!(
            node = %node,
            version,
            "refused a handshake: {}",
            mismatch.detail("this controller", "the node")
        );
        let Some((mut record, revision)) = self.record(node).await? else {
            return Ok(());
        };
        record.protocol.offered.clone_from(&mismatch.theirs);
        record.protocol.agreed = None;
        record.protocol.mismatch = Some(MismatchRecord {
            majors: mismatch.clone(),
            at: now,
            version: version.to_owned(),
        });
        record.version = Some(version.to_owned()).filter(|version| !version.is_empty());
        let mut ctx = RequestCtx::system(SystemComponent::Cluster);
        ctx.now = now;
        let mut batch = WriteBatch::for_request(&ctx);
        batch.expect_typed(&tables::NODES, &node.0, Some(revision));
        batch.put_typed(&tables::NODES, &node.0, &record)?;
        batch.audit(
            AuditDraft::failed(
                actions::VERSION_MISMATCH,
                vec![ObjectRef::node(node)],
                mismatch,
            )
            .with_context("name", record.name.clone())
            .with_context("offered", version::format_majors(&mismatch.theirs))
            .with_context("supported", version::format_majors(&mismatch.ours))
            .with_context("version", version.to_owned()),
        );
        match self.store.propose(batch).await {
            Ok(_) | Err(StoreError::PreconditionFailed(_)) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Records that a node was heard from: `last_seen` is written when `force` is set
    /// (connect, disconnect) or [`LAST_SEEN_INTERVAL_SECS`] passed since the last write.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn touch(
        &self,
        node: NodeId,
        now: Timestamp,
        force: bool,
    ) -> Result<(), ClusterError> {
        {
            let mut touched = self.lock_touched();
            let due = touched
                .get(&node)
                .is_none_or(|at| at.elapsed() >= Duration::from_secs(LAST_SEEN_INTERVAL_SECS));
            if !force && !due {
                return Ok(());
            }
            touched.insert(node, Instant::now());
        }
        let Some((mut record, revision)) = self.record(node).await? else {
            return Ok(());
        };
        record.last_seen = Some(now);
        self.write_bookkeeping(&record, revision, now).await
    }

    async fn write_bookkeeping(
        &self,
        record: &NodeRecord,
        revision: Revision,
        now: Timestamp,
    ) -> Result<(), ClusterError> {
        let mut ctx = RequestCtx::system(SystemComponent::Cluster);
        ctx.now = now;
        let mut batch = WriteBatch::for_request(&ctx);
        batch.expect_typed(&tables::NODES, &record.id.0, Some(revision));
        batch.put_typed(&tables::NODES, &record.id.0, record)?;
        match self.store.propose(batch).await {
            // A concurrent edit (renewal, revocation) wins; bookkeeping is not worth a retry.
            Ok(_) | Err(StoreError::PreconditionFailed(_)) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// The cluster summary of `GET /system/status`.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn health(&self) -> Result<ClusterHealth, ClusterError> {
        let nodes = self.list_nodes().await?;
        let mut versions: BTreeMap<String, u64> = BTreeMap::new();
        for node in nodes.iter().filter(|node| node.connected) {
            let version = node.version.clone().unwrap_or_else(|| "unknown".to_owned());
            *versions.entry(version).or_default() += 1;
        }
        Ok(ClusterHealth {
            listening: self.listening().iter().map(ToString::to_string).collect(),
            majors: self.config.majors.clone(),
            nodes: u64::try_from(nodes.len()).unwrap_or(u64::MAX),
            connected: u64::try_from(nodes.iter().filter(|node| node.connected).count())
                .unwrap_or(u64::MAX),
            versions,
            mismatched: nodes
                .into_iter()
                .filter_map(|node| {
                    let mismatch = node.protocol.mismatch?;
                    Some(NodeMismatch {
                        node: node.id,
                        name: node.name,
                        mismatch,
                    })
                })
                .collect(),
        })
    }

    /// The endpoints a node enrolling through `host` is told: the advertised ones, else
    /// none (the node uses `host` with [`cluster_port`](Self::cluster_port)).
    pub fn endpoints(&self) -> Vec<String> {
        self.config.advertise.clone()
    }

    /// The cluster ports of every controller of the cluster (`host:port`, from the member
    /// records): what a node's `Hello` answer lists so that it can reach another controller
    /// when this one is down. Empty on a single controller.
    pub async fn cluster_endpoints(&self) -> Vec<String> {
        let Ok(view) = self.store.read(ReadConsistency::Local).await else {
            return Vec::new();
        };
        let Ok(members) = view.scan_typed(&tables::MEMBERS, KeyRange::all(), usize::MAX, false)
        else {
            return Vec::new();
        };
        let mut endpoints: Vec<String> = members
            .into_iter()
            .map(|(_, member, _)| member.address)
            .filter(|address| !address.is_empty())
            .collect();
        // The answering controller first.
        if let Some(position) = members_position(&endpoints, &self.listening()) {
            endpoints.swap(0, position);
        }
        endpoints
    }

    /// The cluster port: the first listening address, else the configured default.
    pub fn cluster_port(&self) -> u16 {
        self.listening()
            .first()
            .map_or(self.config.default_port, SocketAddr::port)
    }

    fn lock_touched(&self) -> std::sync::MutexGuard<'_, HashMap<NodeId, Instant>> {
        self.touched.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_mismatches(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<NodeId, (VersionMismatch, Instant)>> {
        self.mismatches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Commits an edit as an inline job (or directly before the engine is registered) and
    /// returns its revision.
    pub(crate) async fn commit(
        &self,
        cx: &RequestCtx,
        summary: String,
        targets: Vec<ObjectRef>,
        batch: WriteBatch,
    ) -> Result<Revision, ClusterError> {
        let Some(engine) = self.jobs.get() else {
            return Ok(self.store.propose(batch).await?.revision);
        };
        let params = WriteParams {
            summary,
            targets: targets.clone(),
            batch,
        };
        let spec = JobSpec {
            kind: JobKind::from_static(EDIT_JOB),
            title: MessageKey::from_static(EDIT_TITLE),
            targets,
            steps: vec![StepSpec {
                kind: StepKind::from_static(WRITE_STEP),
                params: HexBytes(to_cbor(&params)?.to_vec()),
                timeout: None,
            }],
            timeout: Duration::from_secs(30),
            group: None,
            group_limit: None,
            idempotency: None,
            node: None,
        };
        let job = engine.run_inline(spec, cx).await?;
        Ok(job.revision)
    }
}

/// The connections that other controllers of the cluster hold, from their records: a record
/// whose controller is no longer a member (no member record) counts as disconnected.
fn remote_connections(
    view: &dyn ReadView,
    local: NodeId,
) -> Result<HashMap<NodeId, ConnectionView>, ClusterError> {
    let members: HashSet<u64> = view
        .scan_typed(&tables::MEMBERS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(node, _, _)| node)
        .collect();
    Ok(view
        .scan_typed(&tables::CONNECTIONS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .filter(|(_, record, _)| {
            record.controller != local && members.contains(&record.controller.0)
        })
        .map(|(node, record, _)| {
            (
                NodeId(node),
                ConnectionView {
                    since: record.since,
                    peer: record.peer,
                    major: record.major,
                    version: record.version,
                    last_beat: None,
                    buffered_batches: 0,
                    buffered_bytes: 0,
                    dropped_batches: 0,
                    certificate_not_after: None,
                    controller: Some(record.controller),
                },
            )
        })
        .collect())
}

/// The hourly prune of expired revocations and old enrollment tokens as leader-only work
/// (`tenko_core::cluster::LeaderService`, name `cluster.prune`): every prune carries the
/// leader epoch.
pub struct PruneService {
    registry: Arc<NodeRegistry>,
    every: Duration,
}

impl std::fmt::Debug for PruneService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PruneService")
            .field("every", &self.every)
            .finish_non_exhaustive()
    }
}

impl PruneService {
    /// The prune of `registry`, once an hour.
    pub fn new(registry: Arc<NodeRegistry>) -> Self {
        Self {
            registry,
            every: Duration::from_secs(3600),
        }
    }
}

#[async_trait::async_trait]
impl tenko_core::cluster::LeaderService for PruneService {
    fn name(&self) -> &'static str {
        "cluster.prune"
    }

    async fn run(
        &self,
        epoch: u64,
        stop: tokio_util::sync::CancellationToken,
    ) -> Result<(), String> {
        let mut tick = tokio::time::interval(self.every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                _ = tick.tick() => {}
            }
            match self
                .registry
                .prune_fenced(Timestamp::now(), Some(epoch))
                .await
            {
                Ok(0) => {}
                Ok(count) => tracing::info!(
                    count,
                    "expired revocations and old enrollment tokens removed"
                ),
                Err(error) if error.code() == StoreError::PRECONDITION_FAILED => {
                    return Err("another controller took office".to_owned());
                }
                Err(error) => tracing::warn!(code = %error.code(), "{}", error.detail()),
            }
        }
    }
}

/// Whether a token that can still be used, other than `except`, names `key` (a lower-case
/// node name).
fn reserved(
    view: &dyn ReadView,
    key: &str,
    now: Timestamp,
    except: Option<Uuid>,
) -> Result<bool, ClusterError> {
    Ok(view
        .scan_typed(&tables::ENROLLMENTS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .any(|(id, token, _)| {
            Some(id) != except
                && token.used.is_none()
                && token.expires_at > now
                && token.name.is_some_and(|name| name.to_lowercase() == key)
        }))
}

/// Whether `failed` is the leader fence of [`tenko_store::fence`].
fn is_fence(failed: &FailedPrecondition) -> bool {
    matches!(failed, FailedPrecondition::Counter { counter, .. } if *counter == LEADER_EPOCH)
}

/// The position of the endpoint that names one of `listening` (by port), if any.
fn members_position(endpoints: &[String], listening: &[SocketAddr]) -> Option<usize> {
    endpoints.iter().position(|endpoint| {
        endpoint
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .is_some_and(|port| listening.iter().any(|addr| addr.port() == port))
    })
}

fn role_list(roles: &[Role]) -> String {
    roles
        .iter()
        .map(|role| role.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn name_taken(name: &str) -> ClusterError {
    ClusterError::new(
        "cluster.node.name_taken",
        409,
        format!("another node, or an enrollment token that can still be used, is named `{name}`"),
    )
    .with_param("field", "name")
}

/// How long before its expiry a node certificate may be renewed: a third of its lifetime,
/// or `renew_before_days` of the CA policy but at least [`RENEW_FROM_DAYS`], whichever is
/// longer, and never more than the lifetime. A node asks by the rule of
/// `identity::Credentials::needs_renewal` (a third of the lifetime or 30 days), which never
/// asks earlier than this accepts.
pub fn renewal_window(cert: &CertificateRef, renew_before_days: u32) -> Duration {
    let lifetime = cert.not_after.saturating_since(cert.not_before);
    let days = Duration::from_secs(u64::from(renew_before_days.max(RENEW_FROM_DAYS)) * 86_400);
    (lifetime / 3).max(days).min(lifetime)
}

fn unknown_certificate() -> ClusterError {
    ClusterError::new(
        "cluster.node.certificate_unknown",
        403,
        "the certificate is not one this node was issued, or it expired",
    )
}

/// Checks a node name: 1 to 63 characters, letters, digits, `.`, `-` and `_`, starting
/// with a letter or digit.
///
/// # Errors
///
/// `cluster.node.name` (422).
pub fn check_name(name: &str) -> Result<(), ClusterError> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(ClusterError::new(
            "cluster.node.name",
            422,
            format!(
                "a node name has 1 to {MAX_NAME_LEN} letters, digits, dots, hyphens and \
                 underscores and starts with a letter or digit"
            ),
        )
        .with_param("field", "name"))
    }
}

/// Parameters of `cluster.write`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WriteParams {
    summary: String,
    targets: Vec<ObjectRef>,
    batch: WriteBatch,
}

/// Stages the batch of a registry edit, so the change, the job record and the audit
/// record commit as one write.
#[derive(Debug, Clone, Copy, Default)]
struct WriteStep;

/// The code `tenko_jobs::stage` answers outside a step the engine runs.
const OUTSIDE_STEP: &str = "jobs.stage.outside_step";

#[async_trait::async_trait]
impl StepHandler for WriteStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(WRITE_STEP)
    }

    /// Not idempotent: its preconditions fail once the batch committed.
    fn idempotent(&self) -> bool {
        false
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params: WriteParams =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepPreview {
            summary: MessageKey::from_static(WRITE_PREVIEW),
            args: BTreeMap::from([("summary".to_owned(), params.summary)]),
            changes: params.targets,
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params: WriteParams =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        match tenko_jobs::stage(cx, params.batch.clone()) {
            Ok(()) => Ok(StepOutcome::Done { output: None }),
            Err(StepError::Coded(error)) if error.code == OUTSIDE_STEP => {
                cx.store.propose(params.batch).await?;
                Ok(StepOutcome::Done { output: None })
            }
            Err(error) => Err(error),
        }
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
    use tenko_core::testing::wait_until_async;

    use super::*;

    #[test]
    fn names_are_checked() {
        for good in ["probe-dmz", "probe.lan", "p1", "node_7", "A"] {
            assert!(check_name(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "-probe",
            ".probe",
            "probe dmz",
            "probé",
            &"a".repeat(64),
        ] {
            assert_eq!(
                check_name(bad).expect_err(bad).code(),
                "cluster.node.name",
                "{bad}"
            );
        }
    }

    /// A registry over an in-memory store, without a job engine.
    async fn mem_registry() -> (Arc<tenko_store::mem::MemStore>, Arc<NodeRegistry>) {
        let store = Arc::new(tenko_store::mem::MemStore::default());
        let vault = tenko_vault::MemVault::with_store(store.clone());
        let ca = InternalCa::load_or_init(
            &*store,
            &vault,
            &RequestCtx::system(SystemComponent::Cluster),
            crate::ca::CaPolicy::default(),
        )
        .await
        .expect("CA");
        let registry = NodeRegistry::new(
            store.clone() as Arc<dyn Store>,
            Arc::new(ca),
            RegistryConfig::new(NodeId(1)),
        );
        (store, registry)
    }

    /// The failed `cluster.node.enroll` records: their code and context.
    async fn refused_enrollments(
        store: &tenko_store::mem::MemStore,
    ) -> Vec<(String, BTreeMap<String, String>)> {
        let view = store.read(ReadConsistency::Local).await.expect("view");
        view.scan_typed(
            &tenko_store::tables::AUDIT,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("audit")
        .into_iter()
        .filter(|(_, record, _)| record.draft.action == actions::NODE_ENROLL)
        .filter_map(|(_, record, _)| match record.draft.outcome {
            tenko_core::audit::AuditOutcome::Failed { code } => {
                Some((code.into_owned(), record.draft.details.context))
            }
            _ => None,
        })
        .collect()
    }

    fn enroll_with(token: &str, roles: Vec<Role>) -> EnrollRequest {
        EnrollRequest {
            token: token.to_owned(),
            csr: String::new(),
            name: None,
            roles,
            address: None,
            version: String::new(),
            majors: Vec::new(),
        }
    }

    /// A refusal names the token only when the request knew its secret: an unknown id and
    /// a wrong secret are refusals anyone can send.
    #[tokio::test]
    async fn a_refusal_names_the_token_only_when_its_secret_matched() {
        let (store, registry) = mem_registry().await;
        let cx = RequestCtx::system(SystemComponent::Cluster);
        let (created, token) = registry
            .create_enrollment(&cx, NewEnrollment::default())
            .await
            .expect("a probe token");
        let forged = EnrollmentToken::generate(created.id)
            .expect("the token's id with another secret")
            .with_ca_fingerprint(registry.ca_fingerprint());
        let unknown = EnrollmentToken::generate(Uuid::now_v7())
            .expect("an id no token has")
            .with_ca_fingerprint(registry.ca_fingerprint());
        for text in [forged.to_text(), unknown.to_text()] {
            let refused = registry
                .enroll(&cx, enroll_with(&text, Vec::new()))
                .await
                .expect_err("a token whose secret does not match");
            assert_eq!(refused.code(), "cluster.enrollment.invalid_token");
        }
        // The real secret, asking for a role the token does not allow.
        let refused = registry
            .enroll(&cx, enroll_with(&token.to_text(), vec![Role::Dns]))
            .await
            .expect_err("a role the token does not allow");
        assert_eq!(refused.code(), "cluster.enrollment.roles");
        let named: Vec<(String, Option<String>)> = refused_enrollments(&store)
            .await
            .into_iter()
            .map(|(code, context)| (code, context.get("enrollment").cloned()))
            .collect();
        assert_eq!(
            named,
            [
                ("cluster.enrollment.invalid_token".to_owned(), None),
                ("cluster.enrollment.invalid_token".to_owned(), None),
                (
                    "cluster.enrollment.roles".to_owned(),
                    Some(created.id.to_string())
                ),
            ]
        );
    }

    /// A name that a token which can still be used reserves is taken for a second token,
    /// whose enrollment could never succeed; an expired or used token reserves nothing.
    #[tokio::test]
    async fn a_name_that_a_pending_token_reserves_is_taken() {
        let (_, registry) = mem_registry().await;
        let cx = RequestCtx::system(SystemComponent::Cluster);
        let named = |name: &str| NewEnrollment {
            name: Some(name.to_owned()),
            expires_in_secs: Some(60),
            ..NewEnrollment::default()
        };
        registry
            .create_enrollment(&cx, named("dns-1"))
            .await
            .expect("the first token");
        let second = registry
            .create_enrollment(&cx, named("DNS-1"))
            .await
            .expect_err("a second token for the same name");
        assert_eq!(second.code(), "cluster.node.name_taken");
        assert_eq!(second.status(), 409);
        let expired = cx
            .now
            .checked_add(Duration::from_secs(61))
            .expect("a minute later");
        registry
            .name_free("dns-1", expired)
            .await
            .expect("an expired token reserves nothing");
        // A token without a name cannot take the reserved name through its request either.
        let (_, unnamed) = registry
            .create_enrollment(&cx, NewEnrollment::default())
            .await
            .expect("a token without a name");
        let (_, csr) = crate::ca::generate_csr().expect("csr");
        let mut request = enroll_with(&unnamed.to_text(), Vec::new());
        request.csr = crate::ca::pem_block("CERTIFICATE REQUEST", &csr);
        request.name = Some("Dns-1".to_owned());
        let refused = registry
            .enroll(&cx, request)
            .await
            .expect_err("a name another token reserves");
        assert_eq!(refused.code(), "cluster.node.name_taken");
    }

    /// The roles a token asks for are refused with 403 at creation as at enrollment.
    #[tokio::test]
    async fn a_controller_token_beside_another_role_is_refused_with_403() {
        let (_, registry) = mem_registry().await;
        let refused = registry
            .create_enrollment(
                &RequestCtx::system(SystemComponent::Cluster),
                NewEnrollment {
                    roles: vec![Role::Controller, Role::Probe],
                    ..NewEnrollment::default()
                },
            )
            .await
            .expect_err("controller beside another role");
        assert_eq!(refused.code(), "cluster.enrollment.roles");
        assert_eq!(refused.status(), 403);
    }

    /// A flood of refused enrollments writes a few records one by one and then one summary
    /// per window, not a record each.
    #[tokio::test]
    async fn refused_enrollments_are_audited_as_a_summary_beyond_a_few() {
        let (store, registry) = mem_registry().await;
        registry.set_timings(Timings {
            refusal_window: Duration::from_secs(3),
            ..Timings::default()
        });
        for n in 0..50u8 {
            let mut cx = RequestCtx::system(SystemComponent::Cluster);
            cx.source_ip = Some(std::net::IpAddr::from([192, 0, 2, 10 + n % 3]));
            let refused = registry
                .enroll(
                    &cx,
                    EnrollRequest {
                        token: "x".to_owned(),
                        csr: String::new(),
                        name: None,
                        roles: Vec::new(),
                        address: None,
                        version: String::new(),
                        majors: Vec::new(),
                    },
                )
                .await
                .expect_err("garbage");
            assert_eq!(refused.code(), "cluster.enrollment.invalid_token");
        }
        let one_by_one = refused_enrollments(&store).await;
        assert_eq!(one_by_one.len(), REFUSAL_AUDIT_BURST as usize);
        assert!(
            one_by_one
                .iter()
                .all(|(code, _)| code == "cluster.enrollment.invalid_token")
        );

        // At the end of the window the rest arrive as one summary.
        let all = wait_until_async("the summary of the refusals", async || {
            let all = refused_enrollments(&store).await;
            (all.len() > one_by_one.len()).then_some(all)
        })
        .await;
        assert_eq!(all.len(), REFUSAL_AUDIT_BURST as usize + 1, "{all:?}");
        let (code, context) = all.last().expect("the summary");
        assert_eq!(code, "cluster.enrollment.refusals");
        let expected = 50 - REFUSAL_AUDIT_BURST;
        assert_eq!(context.get("refusals"), Some(&expected.to_string()));
        assert_eq!(
            context.get("codes"),
            Some(&format!("cluster.enrollment.invalid_token={expected}"))
        );
        assert_eq!(context.get("sources").map(String::as_str), Some("3"));
        // In the order first seen past the burst: the 11th request came from .11.
        assert_eq!(
            context.get("addresses").map(String::as_str),
            Some("192.0.2.11,192.0.2.12,192.0.2.10")
        );

        // A new window records one by one again.
        let refused = registry
            .enroll(
                &RequestCtx::system(SystemComponent::Cluster),
                EnrollRequest {
                    token: "x".to_owned(),
                    csr: String::new(),
                    name: None,
                    roles: Vec::new(),
                    address: None,
                    version: String::new(),
                    majors: Vec::new(),
                },
            )
            .await;
        assert!(refused.is_err());
        assert_eq!(
            refused_enrollments(&store).await.len(),
            REFUSAL_AUDIT_BURST as usize + 2
        );
    }

    /// A refusal of a request that knew a token's secret (a used or expired token) is
    /// recorded one by one even while a flood of invalid tokens fills the summary.
    #[tokio::test]
    async fn a_refusal_that_knew_the_secret_is_recorded_during_a_flood() {
        let (store, registry) = mem_registry().await;
        registry.set_timings(Timings {
            refusal_window: Duration::from_secs(30),
            ..Timings::default()
        });
        let system = RequestCtx::system(SystemComponent::Cluster);
        let (_, token) = registry
            .create_enrollment(&system, NewEnrollment::default())
            .await
            .expect("token");
        let (_, csr) = crate::ca::generate_csr().expect("csr");
        let request = |token: &str| EnrollRequest {
            token: token.to_owned(),
            csr: crate::ca::pem_block("CERTIFICATE REQUEST", &csr),
            name: None,
            roles: Vec::new(),
            address: None,
            version: String::new(),
            majors: Vec::new(),
        };
        let text = token.to_text().to_string();
        registry
            .enroll(&system, request(&text))
            .await
            .expect("enrolled");
        for _ in 0..(REFUSAL_AUDIT_BURST + 5) {
            let _ = registry.enroll(&system, request("x")).await;
        }
        let refused = registry
            .enroll(&system, request(&text))
            .await
            .expect_err("used");
        assert_eq!(refused.code(), "cluster.enrollment.used");
        let codes: Vec<String> = refused_enrollments(&store)
            .await
            .into_iter()
            .map(|(code, _)| code)
            .collect();
        assert_eq!(
            codes
                .iter()
                .filter(|code| *code == "cluster.enrollment.used")
                .count(),
            1,
            "{codes:?}"
        );
    }
}
