//! The node registry of a controller: enrolment tokens, enrolment, renewal, revocation,
//! the protocol state of each node, and the controller's own certificate on the cluster
//! port (OPS-04, OPS-08).
//!
//! # Enrolment
//!
//! An administrator creates a token ([`NodeRegistry::create_enrolment`]); the controller
//! keeps only its digest and shows the text once. The node presents the token with a
//! certificate request ([`NodeRegistry::enrol`]); the controller checks the token (it
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
//! Edits by people and nodes (tokens, enrolment, renewal, revocation) are inline jobs with
//! the step `cluster.write`, like every edit in Tenko. Bookkeeping of the controller itself
//! (`last_seen`, the protocol state, pruning) is written directly.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use tenko_core::{
    Coded, MessageKey, NodeId, ObjectKind, ObjectRef, Principal, RequestCtx, Revision, Role,
    RoleSet, SystemComponent, Timestamp,
    audit::AuditDraft,
    codec::{from_cbor, to_cbor},
    secret::SecretClass,
    serde_util::HexBytes,
};
use tenko_jobs::{
    JobEngine, JobKind, JobSpec, StepContext, StepError, StepHandler, StepKind, StepOutcome,
    StepPreview, StepSpec,
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError, WriteBatch,
};
use tenko_vault::{SecretPurpose, SecretSpec, Vault, VaultError};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::{
    ca::{CertSource, InternalCa, NodeCert, TlsMaterial},
    error::ClusterError,
    model::{
        CertificateRef, ClusterHealth, ControllerCertRecord, EnrolRequest, EnrolmentRecord,
        EnrolmentView, FIRST_ENROLLED_NODE_ID, LAST_SEEN_INTERVAL_SECS, MismatchRecord,
        NewEnrolment, NodeMismatch, NodeRecord, NodeView, Revocation, TokenUse, tables,
        valid_address,
    },
    mtls::RevocationSet,
    session::Sessions,
    token::EnrolmentToken,
    version::{self, VersionMismatch},
};

/// Audit actions of the registry.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// An enrolment token was created.
    pub const ENROLMENT_CREATE: AuditAction = AuditAction::from_static("cluster.enrolment.create");
    /// An enrolment token was deleted.
    pub const ENROLMENT_DELETE: AuditAction = AuditAction::from_static("cluster.enrolment.delete");
    /// A node enrolled (or failed to).
    pub const NODE_ENROL: AuditAction = AuditAction::from_static("cluster.node.enrol");
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

/// Default lifetime of an enrolment token.
pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(3600);
/// Shortest lifetime of an enrolment token.
pub const MIN_TOKEN_TTL: Duration = Duration::from_secs(60);
/// Longest lifetime of an enrolment token.
pub const MAX_TOKEN_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
/// Used and expired tokens stay listed this long.
pub const TOKEN_RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);
/// A repeated refused handshake with the same offer is recorded and audited at most this
/// often.
pub const MISMATCH_REPEAT: Duration = Duration::from_secs(3600);
/// Longest node name.
pub const MAX_NAME_LEN: usize = 63;
/// How many times a revocation or a renewal is planned before a conflict is reported: the
/// node's bookkeeping writes the same record, and a lost race records nothing.
pub const NODE_EDIT_ATTEMPTS: usize = 3;
/// The code of a store write whose precondition failed (a lost race).
const PRECONDITION_FAILED: &str = "sys.store.precondition_failed";

/// Settings of the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryConfig {
    /// This controller's node id (`[node] id`).
    pub local_node: NodeId,
    /// Seconds between two heartbeats of a node.
    pub heartbeat_secs: u32,
    /// `host:port` endpoints of the cluster port that nodes are told at enrolment.
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

/// What a successful enrolment hands back to the node.
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
        "cluster.node.not_found",
        404,
        format!("there is no enrolled node {id}"),
    )
    .with_param("node", id.to_string())
}

fn invalid_token() -> ClusterError {
    ClusterError::new(
        "cluster.enrolment.invalid_token",
        401,
        "the enrolment token is not valid",
    )
}

/// The node registry of a controller.
pub struct NodeRegistry {
    store: Arc<dyn Store>,
    ca: Arc<InternalCa>,
    config: RegistryConfig,
    jobs: OnceLock<JobEngine>,
    revoked: Arc<RevocationSet>,
    sessions: Arc<Sessions>,
    listening: ArcSwap<Vec<SocketAddr>>,
    listener_wanted: Notify,
    wanted: std::sync::atomic::AtomicBool,
    touched: Mutex<HashMap<NodeId, Instant>>,
    mismatches: Mutex<HashMap<NodeId, (VersionMismatch, Instant)>>,
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
        Arc::new(Self {
            store,
            ca,
            config,
            jobs: OnceLock::new(),
            revoked: Arc::new(RevocationSet::new()),
            sessions: Sessions::new(),
            listening: ArcSwap::from_pointee(Vec::new()),
            listener_wanted: Notify::new(),
            wanted: std::sync::atomic::AtomicBool::new(false),
            touched: Mutex::new(HashMap::new()),
            mismatches: Mutex::new(HashMap::new()),
        })
    }

    /// Registers the `cluster.write` step; from now on every edit is an inline job.
    pub fn register_steps(&self, engine: &JobEngine) {
        let mut registered = engine.clone();
        registered.register(Arc::new(WriteStep));
        let _ = self.jobs.set(engine.clone());
    }

    /// The settings.
    pub fn config(&self) -> &RegistryConfig {
        &self.config
    }

    /// The internal CA.
    pub fn ca(&self) -> &Arc<InternalCa> {
        &self.ca
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

    /// Resolves once [`want_listener`](Self::want_listener) was called.
    pub async fn listener_wanted(&self) {
        while !self.wanted.load(std::sync::atomic::Ordering::SeqCst) {
            self.listener_wanted.notified().await;
        }
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
        let view = self.store.read(ReadConsistency::Local).await?;
        if !view
            .scan_typed(&tables::NODES, KeyRange::all(), 1, false)?
            .is_empty()
        {
            return Ok(true);
        }
        Ok(view
            .scan_typed(&tables::ENROLMENTS, KeyRange::all(), usize::MAX, false)?
            .iter()
            .any(|(_, record, _)| record.used.is_none() && record.expires_at > now))
    }

    /// Removes expired revocations, and used or expired tokens older than
    /// [`TOKEN_RETENTION`]. Returns how many rows went.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn prune(&self, now: Timestamp) -> Result<usize, ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let ctx = RequestCtx::system(SystemComponent::Cluster);
        let mut batch = WriteBatch::for_request(&ctx);
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
            view.scan_typed(&tables::ENROLMENTS, KeyRange::all(), usize::MAX, false)?
        {
            let ended = record
                .used
                .as_ref()
                .map_or(record.expires_at, |used| used.at);
            if (record.used.is_some() || record.expires_at <= now)
                && now.saturating_since(ended) >= TOKEN_RETENTION
            {
                batch.expect_typed(&tables::ENROLMENTS, &id, Some(revision));
                batch.delete_typed(&tables::ENROLMENTS, &id);
                removed += 1;
            }
        }
        drop(view);
        if removed > 0 {
            self.store.propose(batch).await?;
            self.load_revocations().await?;
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
            SecretSpec::new(NODE_KEY_PURPOSE).labelled(format!("cluster port of node {node}")),
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
    // Enrolment tokens.

    /// Creates an enrolment token; the text is in the returned token and nowhere else.
    ///
    /// # Errors
    ///
    /// `cluster.enrolment.roles` (422) for a controller role or an empty list after the
    /// default, `cluster.enrolment.lifetime` (422), `cluster.node.name` (422),
    /// `cluster.node.name_taken` (409), or a store or job error.
    pub async fn create_enrolment(
        &self,
        cx: &RequestCtx,
        request: NewEnrolment,
    ) -> Result<(EnrolmentView, EnrolmentToken), ClusterError> {
        let mut roles = request.roles.clone();
        if roles.is_empty() {
            roles.push(Role::Probe);
        }
        roles.sort();
        roles.dedup();
        if roles.contains(&Role::Controller) {
            return Err(ClusterError::new(
                "cluster.enrolment.roles",
                422,
                "controllers do not enrol with a token yet; a token is for probe, dns and dhcp nodes",
            )
            .with_param("field", "roles"));
        }
        let ttl = match request.expires_in_secs {
            Some(secs) => Duration::from_secs(secs),
            None => self.config.default_token_ttl,
        };
        if !(MIN_TOKEN_TTL..=MAX_TOKEN_TTL).contains(&ttl) {
            return Err(ClusterError::new(
                "cluster.enrolment.lifetime",
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
                self.name_free(name).await?;
                Some(name.to_owned())
            }
            _ => None,
        };
        let id = Uuid::now_v7();
        let token = EnrolmentToken::generate(id)?;
        let expires_at = cx
            .now
            .checked_add(ttl)
            .ok_or_else(|| ClusterError::internal("the token expiry is out of range"))?;
        let record = EnrolmentRecord {
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
        batch.expect_typed(&tables::ENROLMENTS, &id, None);
        batch.put_typed(&tables::ENROLMENTS, &id, &record)?;
        batch.audit(
            AuditDraft::success(
                actions::ENROLMENT_CREATE,
                vec![ObjectRef::singleton(ObjectKind::Node)],
            )
            .with_source_ip(cx.source_ip)
            .with_context("enrolment", id.to_string())
            .with_context("roles", role_list(&record.roles))
            .with_context("expires_at", expires_at.to_rfc3339()),
        );
        let revision = self
            .commit(
                cx,
                format!("create enrolment token {id}"),
                vec![ObjectRef::singleton(ObjectKind::Node)],
                batch,
            )
            .await?;
        self.want_listener();
        Ok((EnrolmentView::new(record, revision, cx.now), token))
    }

    /// Every enrolment token, newest first.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn list_enrolments(
        &self,
        now: Timestamp,
    ) -> Result<Vec<EnrolmentView>, ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let mut out: Vec<EnrolmentView> = view
            .scan_typed(&tables::ENROLMENTS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, record, revision)| EnrolmentView::new(record, revision, now))
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        Ok(out)
    }

    /// Deletes a token (pending, used or expired).
    ///
    /// # Errors
    ///
    /// `cluster.enrolment.not_found` (404), or a store or job error.
    pub async fn delete_enrolment(&self, cx: &RequestCtx, id: Uuid) -> Result<(), ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let (record, revision) = view.get_typed(&tables::ENROLMENTS, &id)?.ok_or_else(|| {
            ClusterError::new(
                "cluster.enrolment.not_found",
                404,
                format!("there is no enrolment token {id}"),
            )
        })?;
        drop(view);
        let mut batch = WriteBatch::for_request(cx);
        batch.expect_typed(&tables::ENROLMENTS, &id, Some(revision));
        batch.delete_typed(&tables::ENROLMENTS, &id);
        batch.audit(
            AuditDraft::success(
                actions::ENROLMENT_DELETE,
                vec![ObjectRef::singleton(ObjectKind::Node)],
            )
            .with_source_ip(cx.source_ip)
            .with_context("enrolment", id.to_string())
            .with_context(
                "state",
                format!("{:?}", record.state(cx.now)).to_lowercase(),
            ),
        );
        self.commit(
            cx,
            format!("delete enrolment token {id}"),
            vec![ObjectRef::singleton(ObjectKind::Node)],
            batch,
        )
        .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------------------
    // Enrolment.

    /// Enrols a node: checks the token and the request, issues the certificate and records
    /// the node, consuming the token. Refusals are audited with their code.
    ///
    /// # Errors
    ///
    /// `cluster.enrolment.invalid_token`, `cluster.enrolment.used`,
    /// `cluster.enrolment.expired` (401), `cluster.enrolment.roles` (403),
    /// `cluster.protocol.unsupported` (409), `cluster.node.name` (422),
    /// `cluster.node.name_taken` (409), `cluster.node.address` (422),
    /// `cluster.ca.invalid_csr` (422), or a store or job error.
    pub async fn enrol(
        &self,
        cx: &RequestCtx,
        request: EnrolRequest,
    ) -> Result<Enrolled, ClusterError> {
        match self.try_enrol(cx, request).await {
            Ok(enrolled) => Ok(enrolled),
            Err((error, token)) => {
                self.audit_refusal(cx, &error, token).await;
                Err(error)
            }
        }
    }

    async fn audit_refusal(&self, cx: &RequestCtx, error: &ClusterError, token: Option<Uuid>) {
        if error.status() >= 500 {
            return;
        }
        let code = match error.code() {
            "cluster.enrolment.invalid_token" => "cluster.enrolment.invalid_token",
            "cluster.enrolment.used" => "cluster.enrolment.used",
            "cluster.enrolment.expired" => "cluster.enrolment.expired",
            "cluster.enrolment.roles" => "cluster.enrolment.roles",
            "cluster.protocol.unsupported" => "cluster.protocol.unsupported",
            "cluster.node.name_taken" => "cluster.node.name_taken",
            "cluster.ca.invalid_csr" => "cluster.ca.invalid_csr",
            _ => "cluster.enrolment.refused",
        };
        let mut draft = AuditDraft::failed(
            actions::NODE_ENROL,
            Vec::new(),
            &Refusal(code, error.detail()),
        )
        .with_source_ip(cx.source_ip);
        if let Some(token) = token {
            draft = draft.with_context("enrolment", token.to_string());
        }
        let mut batch = WriteBatch::for_request(cx);
        batch.audit(draft);
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(%error, "a refused enrolment could not be audited");
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the enrolment checks read best as one sequence"
    )]
    async fn try_enrol(
        &self,
        cx: &RequestCtx,
        request: EnrolRequest,
    ) -> Result<Enrolled, (ClusterError, Option<Uuid>)> {
        let token = EnrolmentToken::parse(&request.token).map_err(|_| (invalid_token(), None))?;
        let token_id = token.id();
        let with_token = |error: ClusterError| (error, Some(token_id));
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| with_token(error.into()))?;
        let (mut record, token_revision) = view
            .get_typed(&tables::ENROLMENTS, &token_id)
            .map_err(|error| with_token(error.into()))?
            .ok_or_else(|| with_token(invalid_token()))?;
        if !record.digest.matches(&token) {
            return Err(with_token(invalid_token()));
        }
        drop(token);
        if record.used.is_some() {
            return Err(with_token(ClusterError::new(
                "cluster.enrolment.used",
                401,
                "the enrolment token was used already; create a new one",
            )));
        }
        if cx.now >= record.expires_at {
            return Err(with_token(ClusterError::new(
                "cluster.enrolment.expired",
                401,
                "the enrolment token expired; create a new one",
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
                    "cluster.enrolment.roles",
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
        if view
            .get_typed(&tables::NODE_NAMES, &name_key)
            .map_err(|error| with_token(error.into()))?
            .is_some()
        {
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
            enrolment: token_id,
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
            batch.expect_typed(&tables::ENROLMENTS, &token_id, Some(token_revision));
            batch.put_typed(&tables::ENROLMENTS, &token_id, &record)?;
            batch.expect_typed(&tables::NODE_NAMES, &name_key, None);
            batch.put_typed(&tables::NODE_NAMES, &name_key, &id)?;
            batch.expect_typed(&tables::NODES, &id, None);
            batch.put_typed(&tables::NODES, &id, &node_record)?;
            batch.audit(
                AuditDraft::success(actions::NODE_ENROL, vec![ObjectRef::node(node)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", name.clone())
                    .with_context("roles", role_list(&roles))
                    .with_context("enrolment", token_id.to_string())
                    .with_context("serial", issued.info.serial.clone())
                    .with_context("not_after", issued.info.not_after.to_rfc3339()),
            );
            Ok(batch)
        };
        let batch = build().map_err(with_token)?;
        let revision = match self
            .commit(
                &node_cx,
                format!("enrol node {name}"),
                vec![ObjectRef::node(node)],
                batch,
            )
            .await
        {
            Ok(revision) => revision,
            Err(error) if error.code() == "sys.store.precondition_failed" => {
                // Another enrolment won the race for the token, the id or the name.
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
                "cluster.enrolment.conflict",
                409,
                "another enrolment happened at the same time; try again",
            );
        };
        if let Ok(Some((record, _))) = view.get_typed(&tables::ENROLMENTS, &token)
            && record.used.is_some()
        {
            return ClusterError::new(
                "cluster.enrolment.used",
                401,
                "the enrolment token was used already; create a new one",
            );
        }
        if let Ok(Some(_)) = view.get_typed(&tables::NODE_NAMES, &name_key.to_owned()) {
            return name_taken(name_key);
        }
        ClusterError::new(
            "cluster.enrolment.conflict",
            409,
            "another enrolment happened at the same time; try again",
        )
    }

    async fn name_free(&self, name: &str) -> Result<(), ClusterError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        if view
            .get_typed(&tables::NODE_NAMES, &name.to_lowercase())?
            .is_some()
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
        Ok(view
            .scan_typed(&tables::NODES, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, record, revision)| {
                let live = self.sessions.view(record.id);
                NodeView::new(record, revision, live)
            })
            .collect())
    }

    /// One node with its live connection.
    ///
    /// # Errors
    ///
    /// `cluster.node.not_found` (404), or a store error.
    pub async fn get_node(&self, node: NodeId) -> Result<NodeView, ClusterError> {
        let (record, revision) = self.record(node).await?.ok_or_else(|| not_found(node))?;
        Ok(NodeView::new(record, revision, self.sessions.view(node)))
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
    /// # Errors
    ///
    /// `cluster.node.not_found` (404), `cluster.node.conflict` (409) when every attempt
    /// lost the race, or a store or job error.
    pub async fn revoke(&self, cx: &RequestCtx, node: NodeId) -> Result<Vec<String>, ClusterError> {
        let mut attempt = 1;
        let (record, serial_list) = loop {
            let (record, revision) = self
                .record_for_edit(node, attempt)
                .await?
                .ok_or_else(|| not_found(node))?;
            let serials: Vec<&CertificateRef> = record
                .serials
                .iter()
                .filter(|cert| cert.not_after > cx.now)
                .collect();
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&tables::NODES, &node.0, Some(revision));
            batch.delete_typed(&tables::NODES, &node.0);
            batch.delete_typed(&tables::NODE_NAMES, &record.name.to_lowercase());
            for cert in &serials {
                batch.put_typed(
                    &tables::REVOCATIONS,
                    &cert.serial,
                    &Revocation {
                        node,
                        revoked_at: cx.now,
                        not_after: cert.not_after,
                    },
                )?;
            }
            let serial_list: Vec<String> = serials.iter().map(|cert| cert.serial.clone()).collect();
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
                Err(error) if error.code() == PRECONDITION_FAILED => {
                    if attempt == NODE_EDIT_ATTEMPTS {
                        return Err(ClusterError::new(
                            "cluster.node.conflict",
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
        self.sessions.revoke(node, cx.now);
        self.lock_touched().remove(&node);
        tracing::warn!(node = %node, name = %record.name, "node revoked");
        Ok(serial_list)
    }

    /// Renews the certificate of a connected node for the key of `csr_der`, with the node's
    /// id and roles. The calling certificate (`serial`) must be one the node holds.
    ///
    /// The certificate is issued once. Like [`revoke`](Self::revoke), the write of the
    /// record is planned again from a fresh read when the node's bookkeeping changed the
    /// record in between, up to [`NODE_EDIT_ATTEMPTS`] times.
    ///
    /// # Errors
    ///
    /// `cluster.node.not_found` (404), `cluster.node.certificate_unknown` (403),
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
        if !record.holds(serial, now) {
            return Err(unknown_certificate());
        }
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
            record.serials.retain(|cert| cert.not_after > now);
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
                    if error.code() == PRECONDITION_FAILED && attempt < NODE_EDIT_ATTEMPTS =>
                {
                    tracing::debug!(node = %node, attempt, "the node record changed during the renewal; planning it again");
                    attempt += 1;
                    (record, revision) = self
                        .record_for_edit(node, attempt)
                        .await?
                        .ok_or_else(|| not_found(node))?;
                    if !record.holds(serial, now) {
                        return Err(unknown_certificate());
                    }
                }
                Err(error) => return Err(error),
            }
        }
        tracing::info!(node = %node, not_after = %issued.info.not_after, "node certificate renewed");
        Ok(issued)
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
        let (record, _) = self.record(node).await?.ok_or_else(|| {
            ClusterError::new(
                "cluster.node.unknown",
                403,
                format!("node {node} is not enrolled with this controller"),
            )
        })?;
        if !record.holds(serial, now) {
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
    async fn commit(
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
        };
        let job = engine.run_inline(spec, cx).await?;
        Ok(job.revision)
    }
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
        format!("another node is named `{name}`"),
    )
    .with_param("field", "name")
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
}
