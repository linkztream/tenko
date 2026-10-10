//! The cluster identity of a controller: the certificate it presents to its peers, which
//! must live outside the store because the cluster step of `tenko serve` runs before the
//! vault opens (plan section 2.7).
//!
//! A controller that joined keeps its identity under `<data_dir>/node/` from its
//! enrolment, like a probe ([`NodeDirIdentity`]). The first controller of an installation
//! starts with its cluster-port key as a system secret of the vault (`cluster.node_key`);
//! when the first peer joins, [`VaultIdentity::portable`] writes that certificate and key
//! to `<data_dir>/node/` (the key sealed with DPAPI on Windows, mode 0600 elsewhere), and
//! from then on it starts like every other member.

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

/// The identity of the first controller while its key is a system secret of the vault.
pub struct VaultIdentity {
    registry: Arc<NodeRegistry>,
    vault: Arc<dyn Vault>,
    paths: NodePaths,
    name: String,
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
        }
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
        let (chain, key) = self
            .registry
            .controller_identity(self.vault.as_ref(), &ctx)
            .await?;
        let leaf = chain
            .first()
            .ok_or_else(|| ClusterError::internal("the controller certificate is empty"))?;
        let info = CertInfo::from_der(leaf)?;
        let ca = self.registry.ca();
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
        tracing::info!(
            node = %self.local(),
            dir = %self.paths.root().display(),
            "the cluster identity of this controller moved out of the vault for the controller cluster"
        );
        Ok(certificate_ref(&info))
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}
