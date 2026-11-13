//! The cluster identity of a controller: the certificate it presents to its peers, which
//! must live outside the store because the cluster step of `tenko serve` runs before the
//! vault opens (plan section 2.7).
//!
//! A controller that joined keeps its identity under `<data_dir>/node/` from its
//! enrollment, like a probe ([`NodeDirIdentity`]). The first controller of an installation
//! starts with its cluster-port key as a system secret of the vault (`cluster.node_key`);
//! when the first peer joins, [`VaultIdentity::portable`] gives it a fresh key and
//! certificate that only `<data_dir>/node/` holds (the key sealed with DPAPI on Windows,
//! mode 0600 elsewhere), switches the running controller to them, and takes the old key out
//! of the vault with its certificate revoked: a key in the replicated vault is readable by
//! every controller and every copy of the data directory. From then on it starts like every
//! other member.

use std::sync::Arc;

use tenko_core::{NodeId, RequestCtx, Role, SystemComponent, Timestamp};
use tenko_vault::Vault;

use crate::{
    ca::CertInfo,
    error::ClusterError,
    identity::{Credentials, NodeIdentity, NodePaths},
    model::CertificateRef,
    registry::NodeRegistry,
};

/// The certificate a controller presents on the cluster port.
#[async_trait::async_trait]
pub trait ControllerIdentity: Send + Sync + 'static {
    /// The certificate, after making sure it is kept under `<data_dir>/node/` from now on.
    ///
    /// # Errors
    ///
    /// A vault, CA or file error.
    async fn portable(&self) -> Result<CertificateRef, ClusterError>;

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
        }
    }
}

#[async_trait::async_trait]
impl ControllerIdentity for NodeDirIdentity {
    async fn portable(&self) -> Result<CertificateRef, ClusterError> {
        Ok(self.certificate.clone())
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
        }
    }

    /// Calls `switch` with the new identity once it is written, before the old key is
    /// revoked.
    #[must_use]
    pub fn on_switch(mut self, switch: Switch) -> Self {
        self.switch = Some(switch);
        self
    }

    fn local(&self) -> NodeId {
        self.registry.config().local_node
    }
}

#[async_trait::async_trait]
impl ControllerIdentity for VaultIdentity {
    async fn portable(&self) -> Result<CertificateRef, ClusterError> {
        if self.paths.is_enrolled() {
            let credentials = Credentials::load(&self.paths)?;
            if credentials.identity.node == self.local() {
                return Ok(certificate_ref(&credentials.info));
            }
        }
        let ctx = RequestCtx::system(SystemComponent::Cluster);
        let ca = self.registry.ca();
        let issued = ca.issue_node_cert_with_key_for(
            self.local(),
            [Role::Controller].into_iter().collect(),
            ctx.now,
        )?;
        let (chain, key, info) = (issued.chain, issued.key, issued.info);
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
            info: info.clone(),
            chain,
            key,
            ca_root: ca.root_der().clone(),
        };
        credentials.save(&self.paths)?;
        if let Some(switch) = &self.switch {
            switch(&credentials);
        }
        // A failure here leaves the old key in the vault; the next start retires it.
        self.registry
            .retire_vault_keys(self.vault.as_ref(), &ctx, true, false)
            .await?;
        tracing::info!(
            node = %self.local(),
            dir = %self.paths.root().display(),
            "this controller has a new cluster identity of its own under its data directory; \
             the key it had in the vault is gone and its certificate revoked"
        );
        Ok(certificate_ref(&info))
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}
