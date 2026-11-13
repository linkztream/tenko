//! The cluster identity of a controller: the certificate it presents to its peers, which
//! must live outside the store because the cluster step of `tenko serve` runs before the
//! vault opens (plan section 2.7).
//!
//! A controller that joined keeps its identity under `<data_dir>/node/` from its
//! enrollment, like a probe ([`NodeDirIdentity`]). The first controller of an installation
//! starts with its cluster-port key as a system secret of the vault (`cluster.node_key`);
//! when the first peer joins, [`VaultIdentity::portable`] gives it a fresh key and
//! certificate that only `<data_dir>/node/` holds (the key sealed with DPAPI on Windows,
//! mode 0600 elsewhere) and switches the running controller to them; the write that records
//! the controller ([`super::Peers`], `settle_identity`) takes the old key out of the vault
//! with its certificate revoked: a key in the replicated vault is readable by every
//! controller and every copy of the data directory.
//!
//! # The states of a controller's identity
//!
//! The rule the table follows: a controller with a node record presents a certificate from
//! `<data_dir>/node/` that its record holds, and the vault holds no key of it.
//!
//! | State | Vault key | `<data_dir>/node/` | Node record | Presents | Start path |
//! |---|---|---|---|---|---|
//! | Never joined | yes | no | no | the vault's | single; the vault's certificate renewed daily |
//! | First join in progress | yes | written, switched to | written with the node-local serial, the vault key retired, in one write | node-local | single, until the restart |
//! | Joined | no | yes | holds it | node-local | member; renewed under `node/` |
//! | Joined before keys left the vault | yes, the same key as `node/` | yes | holds it | node-local | member; rotated at once (the registry skips the renewal window for a certificate the vault holds), then the vault key retired |
//! | Shrunk to one controller | no | yes | holds it | node-local | member (a record and an identity under `node/`) |
//! | Restored from a backup of a never-joined controller | yes, from the backup | no | no | the vault's | single, as never joined |
//! | Restored from a backup of a joined one, same host | the backup's, retired at start | yes | may lack the identity's serial | node-local | member; the start settles: the record holds only that identity |
//! | Restored from a backup of a joined one, new host | the backup's | no | holds the old serials | node-local, issued at the start | single; the start settles: a new identity under `node/`, the record holds only it, the vault key retired, in one write |
//!
//! An interruption between two writes leaves a state of the table: the identity under
//! `node/` is written before the record names it, and the record and the retirement are one
//! write, so a restart either finds the identity and settles again (the same serial, no new
//! key) or finds the record already holding it. Until its record holds the identity under
//! `node/`, a controller is treated as presenting the vault's certificate: the vault key is
//! neither retired nor left unrenewed.
//!
//! A join only adds the certificate a controller presents to its record; only a settle at a
//! start replaces the record's serials (a restore, whose serials belong to an earlier host).

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tenko_core::{NodeId, RequestCtx, Role, SystemComponent, Timestamp};
use tenko_store::{ReadView, WriteBatch};
use tenko_vault::Vault;

use crate::{
    ca::CertInfo,
    error::ClusterError,
    identity::{Credentials, NodeIdentity, NodePaths},
    model::CertificateRef,
    registry::{NodeRegistry, stage_vault_retirement},
};

/// The certificate a controller presents on the cluster port.
#[async_trait::async_trait]
pub trait ControllerIdentity: Send + Sync + 'static {
    /// The certificate, after making sure it is kept under `<data_dir>/node/` from now on
    /// and presented.
    ///
    /// # Errors
    ///
    /// A vault, CA or file error.
    async fn portable(&self) -> Result<CertificateRef, ClusterError>;

    /// Stages into `batch` the retirement of a key of this controller that the vault
    /// still holds; returns the revoked serial. The batch also writes the node record.
    ///
    /// # Errors
    ///
    /// A store or codec error.
    fn stage_retirement(
        &self,
        _view: &dyn ReadView,
        _batch: &mut WriteBatch,
    ) -> Result<Option<String>, ClusterError> {
        Ok(None)
    }

    /// Takes note of serials a committed write revoked.
    fn retired(&self, _serials: &[String]) {}

    /// The controller's name in the node registry.
    fn name(&self) -> String;
}

/// The reference the registry keeps of a certificate.
pub fn certificate_ref(info: &CertInfo) -> CertificateRef {
    CertificateRef {
        serial: info.serial.clone(),
        sha256: info.sha256.clone(),
        not_before: info.not_before,
        not_after: info.not_after,
    }
}

/// The identity of a controller that keeps it under `<data_dir>/node/`.
pub struct NodeDirIdentity {
    certificate: CertificateRef,
    name: String,
    /// Where it is kept, read again at every call: a renewal replaces it while the
    /// controller runs.
    paths: Option<NodePaths>,
}

impl std::fmt::Debug for NodeDirIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeDirIdentity")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl NodeDirIdentity {
    /// The identity of loaded credentials.
    pub fn new(credentials: &Credentials) -> Self {
        Self {
            certificate: certificate_ref(&credentials.info),
            name: credentials.identity.name.clone(),
            paths: None,
        }
    }

    /// Reads the identity from `paths` again at every call, so that the certificate a
    /// renewal put there is the one named.
    #[must_use]
    pub fn reloading(mut self, paths: NodePaths) -> Self {
        self.paths = Some(paths);
        self
    }
}

#[async_trait::async_trait]
impl ControllerIdentity for NodeDirIdentity {
    async fn portable(&self) -> Result<CertificateRef, ClusterError> {
        match &self.paths {
            Some(paths) => Credentials::load(paths).map(|loaded| certificate_ref(&loaded.info)),
            None => Ok(self.certificate.clone()),
        }
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}

/// What the running controller does with the identity it moved to: present it on its port
/// and to its peers.
pub type Switch = Box<dyn Fn(&Credentials) + Send + Sync>;

/// The identity of the first controller while its key is a system secret of the vault.
pub struct VaultIdentity {
    registry: Arc<NodeRegistry>,
    vault: Arc<dyn Vault>,
    paths: NodePaths,
    name: String,
    switch: Option<Switch>,
    /// The running controller presents the identity under `node/` already.
    switched: AtomicBool,
}

impl std::fmt::Debug for VaultIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultIdentity")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl VaultIdentity {
    /// The identity of the controller `registry` serves, with its key in `vault`; `paths`
    /// is where it moves at the first join.
    pub fn new(
        registry: Arc<NodeRegistry>,
        vault: Arc<dyn Vault>,
        paths: NodePaths,
        name: impl Into<String>,
    ) -> Self {
        Self {
            registry,
            vault,
            paths,
            name: name.into(),
            switch: None,
            switched: AtomicBool::new(false),
        }
    }

    /// Calls `switch` with the identity under `node/` before the record names it.
    #[must_use]
    pub fn on_switch(mut self, switch: Switch) -> Self {
        self.switch = Some(switch);
        self
    }

    fn local(&self) -> NodeId {
        self.registry.config().local_node
    }

    /// The identity under `node/`: the one there (an earlier settle that stopped before
    /// its write, or a host that keeps it), else a new one written there.
    fn node_local(&self) -> Result<Credentials, ClusterError> {
        if self.paths.is_enrolled() {
            let credentials = Credentials::load(&self.paths)?;
            if credentials.identity.node == self.local() {
                return Ok(credentials);
            }
        }
        let ca = self.registry.ca();
        let issued = ca.issue_node_cert_with_key_for(
            self.local(),
            [Role::Controller].into_iter().collect(),
            Timestamp::now(),
        )?;
        let credentials = Credentials {
            identity: NodeIdentity {
                node: self.local(),
                name: self.name.clone(),
                roles: vec![Role::Controller],
                controller: String::new(),
                endpoints: Vec::new(),
                cluster_port: None,
                heartbeat_secs: self.registry.config().heartbeat_secs,
                enrolled_at: Timestamp::now(),
                ca_sha256: ca.root_info().sha256.clone(),
            },
            info: issued.info,
            chain: issued.chain,
            key: issued.key,
            ca_root: ca.root_der().clone(),
        };
        credentials.save(&self.paths)?;
        tracing::info!(
            node = %self.local(),
            dir = %self.paths.root().display(),
            "this controller has a new cluster identity of its own under its data directory"
        );
        Ok(credentials)
    }
}

#[async_trait::async_trait]
impl ControllerIdentity for VaultIdentity {
    async fn portable(&self) -> Result<CertificateRef, ClusterError> {
        let credentials = self.node_local()?;
        // Presented before the record names it: until that write commits, only a joining
        // learner that is being seeded talks to this controller, and it checks no record.
        if !self.switched.swap(true, Ordering::SeqCst)
            && let Some(switch) = &self.switch
        {
            switch(&credentials);
        }
        Ok(certificate_ref(&credentials.info))
    }

    fn stage_retirement(
        &self,
        view: &dyn ReadView,
        batch: &mut WriteBatch,
    ) -> Result<Option<String>, ClusterError> {
        let ctx = RequestCtx::system(SystemComponent::Cluster);
        stage_vault_retirement(view, batch, self.vault.as_ref(), &ctx, self.local())
    }

    fn retired(&self, serials: &[String]) {
        self.registry.note_retired(serials);
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}
