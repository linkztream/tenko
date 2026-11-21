//! The internal CA: root creation and loading, certificate issuance, and the persisted
//! server certificate of TLS mode a.

use std::{fmt, net::IpAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use tenko_core::{
    NodeId, ObjectRef, RequestCtx, RoleSet, Timestamp,
    audit::{AuditAction, AuditDraft},
    secret::{SecretClass, SecretRef},
    table::TableDef,
};
use tenko_store::{ReadConsistency, ReadViewExt, Store, StoreError, WriteBatch};
use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec, Vault, VaultError};

use super::{
    CaError, CertInfo, CertSource, TlsError, TlsMaterial,
    certs::{self, Signer},
};

/// The CA's store tables (namespace `cluster`).
pub mod tables {
    use tenko_core::table::TableDef;

    use super::{CaRecord, ServerCertRecord};

    /// The CA record (singleton).
    pub const CA: TableDef<(), CaRecord> = TableDef::new("cluster.ca");
    /// The server certificate of TLS mode a of versions that kept one for the whole
    /// cluster; the controller whose names it carries moves it to [`SERVER_CERTS`].
    pub const SERVER_CERT: TableDef<(), ServerCertRecord> = TableDef::new("cluster.server_cert");
    /// The server certificate of TLS mode a of each controller, by node id.
    pub const SERVER_CERTS: TableDef<u64, ServerCertRecord> = TableDef::new("cluster.server_certs");
    /// The integration CA record (singleton, ADR 0035).
    pub const INTEGRATION_CA: TableDef<(), CaRecord> = TableDef::new("cluster.integration_ca");
}

/// Vault purpose of the CA root key.
pub const CA_KEY_PURPOSE: SecretPurpose = SecretPurpose::from_static("cluster.ca_key");
/// Vault purpose of the server certificate key.
pub const TLS_KEY_PURPOSE: SecretPurpose = SecretPurpose::from_static("cluster.tls_key");

/// Audit action: the CA root was created.
pub const CA_CREATE: AuditAction = AuditAction::from_static("cluster.ca.create");
/// Audit action: a server certificate was issued (first issue, renewal or name change).
pub const SERVER_CERT_ISSUE: AuditAction = AuditAction::from_static("cluster.tls.issue");

/// The stored CA: root certificate and a reference to its key in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaRecord {
    /// The root certificate, PEM.
    pub cert_pem: String,
    /// The root key (a [`SecretClass::System`] secret, PKCS#8).
    pub key: SecretRef,
    /// When the CA was created.
    pub created_at: Timestamp,
}

/// The stored server certificate of TLS mode a.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCertRecord {
    /// The chain, PEM, leaf first.
    pub chain_pem: String,
    /// The key (a [`SecretClass::System`] secret, PKCS#8).
    pub key: SecretRef,
    /// The names it was issued for.
    pub identity: ServerIdentity,
    /// When it was issued.
    pub issued_at: Timestamp,
}

/// The names a server certificate covers: the host name from first-run setup (Q5), extra
/// names and addresses.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerIdentity {
    /// The host name clients use (also the WebAuthn relying-party ID).
    pub host_name: String,
    /// Further DNS names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alt_names: Vec<String>,
    /// IP addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<IpAddr>,
}

impl ServerIdentity {
    /// An identity for one host name.
    pub fn new(host_name: impl Into<String>) -> Self {
        Self {
            host_name: host_name.into(),
            alt_names: Vec::new(),
            addresses: Vec::new(),
        }
    }

    /// Adds a DNS name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.alt_names.push(name.into());
        self
    }

    /// Adds an address.
    #[must_use]
    pub fn with_address(mut self, address: IpAddr) -> Self {
        self.addresses.push(address);
        self
    }
}

/// Validity periods of the internal CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaPolicy {
    /// Root validity (default ten years).
    pub root_validity_days: u32,
    /// Server certificate validity (default 397 days, accepted by every browser).
    pub server_validity_days: u32,
    /// Node certificate validity (default one year).
    pub node_validity_days: u32,
    /// Renew a server certificate this many days before it expires (default 30).
    pub renew_before_days: u32,
}

impl Default for CaPolicy {
    fn default() -> Self {
        Self {
            root_validity_days: 3650,
            server_validity_days: 397,
            node_validity_days: 365,
            renew_before_days: 30,
        }
    }
}

/// A certificate with the private key generated for it.
pub struct IssuedCert {
    /// The chain, leaf first (the root is not included).
    pub chain: Vec<CertificateDer<'static>>,
    /// The private key, PKCS#8 DER.
    pub key: SecretBytes,
    /// What the leaf says.
    pub info: CertInfo,
}

impl fmt::Debug for IssuedCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCert")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl IssuedCert {
    /// The chain as PEM.
    pub fn chain_pem(&self) -> String {
        self.chain
            .iter()
            .map(|cert| pem("CERTIFICATE", cert))
            .collect()
    }

    /// The material for rustls.
    ///
    /// # Errors
    ///
    /// As [`TlsMaterial::from_der`].
    pub fn material(&self) -> Result<TlsMaterial, TlsError> {
        TlsMaterial::from_der(self.chain.clone(), &self.key, CertSource::InternalCa)
    }
}

/// A node certificate issued for a CSR (enrollment, Slice 2); the node keeps its key.
#[derive(Debug, Clone)]
pub struct NodeCert {
    /// The node.
    pub node: NodeId,
    /// The chain, leaf first.
    pub chain: Vec<CertificateDer<'static>>,
    /// What the leaf says.
    pub info: CertInfo,
}

impl NodeCert {
    /// The chain as PEM.
    pub fn chain_pem(&self) -> String {
        self.chain
            .iter()
            .map(|cert| pem("CERTIFICATE", cert))
            .collect()
    }
}

/// Where a root lives and how its creation is named: the roots of the internal CA and of the
/// integration CA are created and loaded the same way from different slots.
pub(crate) struct RootSlot {
    /// The singleton table of its record.
    pub(crate) table: TableDef<(), CaRecord>,
    /// The vault purpose of its key.
    pub(crate) purpose: SecretPurpose,
    /// The audit action of its creation.
    pub(crate) created: AuditAction,
    /// The start of its common name; three random octets in hexadecimal follow.
    pub(crate) name: &'static str,
}

/// The internal CA's root.
const INTERNAL_ROOT: RootSlot = RootSlot {
    table: tables::CA,
    purpose: CA_KEY_PURPOSE,
    created: CA_CREATE,
    name: "Tenko DDI local CA",
};

/// A root read from its slot, with the signer of its key.
pub(crate) struct LoadedRoot {
    pub(crate) record: CaRecord,
    pub(crate) root: CertificateDer<'static>,
    pub(crate) root_info: CertInfo,
    pub(crate) signer: Signer,
}

impl RootSlot {
    /// Creates the root and stores it: the certificate in the slot's table, the key in the
    /// vault, atomically, with the slot's audit record.
    pub(crate) async fn init(
        &self,
        store: &dyn Store,
        vault: &dyn Vault,
        ctx: &RequestCtx,
        validity_days: u32,
    ) -> Result<LoadedRoot, CaError> {
        let view = store.read(ReadConsistency::Local).await?;
        if view.get_typed(&self.table, &())?.is_some() {
            return Err(CaError::AlreadyInitialized);
        }
        let mut tag = [0u8; 3];
        aws_lc_rs::rand::fill(&mut tag).map_err(|_| CaError::Generation {
            reason: "random number generator failed".to_owned(),
        })?;
        let common_name = format!("{} {}", self.name, super::tls::hex(&tag));
        let root = certs::generate_root(&common_name, ctx.now.0, validity_days)?;
        let signer = Signer::new(&root.cert_der, &root.key_pkcs8)?;
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&self.table, &(), None);
        let key = vault.stage_put(
            &mut batch,
            ctx,
            SecretClass::System,
            SecretSpec::new(self.purpose.clone()).labeled(common_name.clone()),
            &root.key_pkcs8,
        )?;
        let record = CaRecord {
            cert_pem: pem("CERTIFICATE", &root.cert_der),
            key,
            created_at: ctx.now,
        };
        batch.put_typed(&self.table, &(), &record)?;
        let root_info = CertInfo::from_der(&root.cert_der)?;
        batch.audit(
            AuditDraft::success(self.created.clone(), Vec::new())
                .with_source_ip(ctx.source_ip)
                .with_context("subject", root_info.subject.clone())
                .with_context("sha256", root_info.sha256.clone()),
        );
        match store.propose(batch).await {
            Ok(_) => {}
            Err(StoreError::PreconditionFailed(_)) => return Err(CaError::AlreadyInitialized),
            Err(error) => return Err(error.into()),
        }
        tracing::info!(subject = %root_info.subject, sha256 = %root_info.sha256, "certificate authority created");
        Ok(LoadedRoot {
            record,
            root: root.cert_der,
            root_info,
            signer,
        })
    }

    /// Loads the root, or `None` before [`init`](RootSlot::init).
    pub(crate) async fn load(
        &self,
        store: &dyn Store,
        vault: &dyn Vault,
        ctx: &RequestCtx,
    ) -> Result<Option<LoadedRoot>, CaError> {
        let view = store.read(ReadConsistency::Local).await?;
        let Some((record, _)) = view.get_typed(&self.table, &())? else {
            return Ok(None);
        };
        let root = CertificateDer::from_pem_slice(record.cert_pem.as_bytes()).map_err(|e| {
            CaError::Corrupt {
                reason: format!("root certificate: {e}"),
            }
        })?;
        let key = vault.get_system(ctx, record.key).await?;
        let signer = Signer::new(&root, &key).map_err(|e| match e {
            CaError::Corrupt { .. } => e,
            other => CaError::Corrupt {
                reason: other.to_string(),
            },
        })?;
        let root_info = CertInfo::from_der(&root)?;
        Ok(Some(LoadedRoot {
            record,
            root,
            root_info,
            signer,
        }))
    }

    /// Loads the root, creating it on first use; two controllers that create it at the same
    /// moment end with one root.
    pub(crate) async fn load_or_init(
        &self,
        store: &dyn Store,
        vault: &dyn Vault,
        ctx: &RequestCtx,
        validity_days: u32,
    ) -> Result<LoadedRoot, CaError> {
        if let Some(root) = self.load(store, vault, ctx).await? {
            return Ok(root);
        }
        match self.init(store, vault, ctx, validity_days).await {
            Err(CaError::AlreadyInitialized) => self
                .load(store, vault, ctx)
                .await?
                .ok_or(CaError::NotInitialized),
            other => other,
        }
    }
}

/// The internal certificate authority: an ECDSA P-256 root whose key is a system secret in
/// the vault.
pub struct InternalCa {
    record: CaRecord,
    root: CertificateDer<'static>,
    root_info: CertInfo,
    signer: Signer,
    policy: CaPolicy,
}

impl fmt::Debug for InternalCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InternalCa")
            .field("root", &self.root_info)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl InternalCa {
    /// Creates the root and stores it: the certificate in `cluster.ca`, the key in the
    /// vault, atomically, with a `cluster.ca.create` audit record.
    ///
    /// # Errors
    ///
    /// [`CaError::AlreadyInitialized`] when a CA exists, or a generation, vault or store
    /// error.
    pub async fn init(
        store: &dyn Store,
        vault: &dyn Vault,
        ctx: &RequestCtx,
        policy: CaPolicy,
    ) -> Result<Self, CaError> {
        let root = INTERNAL_ROOT
            .init(store, vault, ctx, policy.root_validity_days)
            .await?;
        Ok(Self::from_root(root, policy))
    }

    /// Loads the CA, or `None` before [`init`](InternalCa::init).
    ///
    /// # Errors
    ///
    /// [`CaError::Corrupt`] when the stored key does not match the root, or a vault or
    /// store error.
    pub async fn load(
        store: &dyn Store,
        vault: &dyn Vault,
        ctx: &RequestCtx,
        policy: CaPolicy,
    ) -> Result<Option<Self>, CaError> {
        Ok(INTERNAL_ROOT
            .load(store, vault, ctx)
            .await?
            .map(|root| Self::from_root(root, policy)))
    }

    /// Loads the CA, creating it on first use.
    ///
    /// # Errors
    ///
    /// As [`load`](InternalCa::load) and [`init`](InternalCa::init).
    pub async fn load_or_init(
        store: &dyn Store,
        vault: &dyn Vault,
        ctx: &RequestCtx,
        policy: CaPolicy,
    ) -> Result<Self, CaError> {
        let root = INTERNAL_ROOT
            .load_or_init(store, vault, ctx, policy.root_validity_days)
            .await?;
        Ok(Self::from_root(root, policy))
    }

    fn from_root(root: LoadedRoot, policy: CaPolicy) -> Self {
        let LoadedRoot {
            record,
            root,
            root_info,
            signer,
        } = root;
        Self {
            record,
            root,
            root_info,
            signer,
            policy,
        }
    }

    /// The root certificate as PEM, for installation on admin clients (Q5).
    pub fn root_pem(&self) -> String {
        self.record.cert_pem.clone()
    }

    /// The root certificate, DER.
    pub fn root_der(&self) -> &CertificateDer<'static> {
        &self.root
    }

    /// What the root says (subject, validity, fingerprint for the settings page).
    pub fn root_info(&self) -> &CertInfo {
        &self.root_info
    }

    /// The stored record.
    pub fn record(&self) -> &CaRecord {
        &self.record
    }

    /// The validity policy.
    pub fn policy(&self) -> &CaPolicy {
        &self.policy
    }

    /// Issues a server certificate for `identity`, valid from `now` (not stored; see
    /// [`server_material`](InternalCa::server_material)).
    ///
    /// # Errors
    ///
    /// [`CaError::InvalidName`] or a generation error.
    pub fn issue_server_cert(
        &self,
        identity: &ServerIdentity,
        now: Timestamp,
    ) -> Result<IssuedCert, CaError> {
        let (cert, key) = certs::issue_server(
            &self.signer,
            identity,
            now.0,
            self.policy.server_validity_days,
        )?;
        let info = CertInfo::from_der(&cert)?;
        Ok(IssuedCert {
            chain: vec![cert],
            key,
            info,
        })
    }

    /// Issues a node certificate for the key in a PKCS#10 CSR, with
    /// `urn:tenko:node:<id>` as URI subject alternative name and both server and client
    /// authentication (mTLS, Slice 2 enrollment).
    ///
    /// # Errors
    ///
    /// [`CaError::InvalidCsr`] or a generation error.
    pub fn issue_node_cert(
        &self,
        node: NodeId,
        csr_der: &[u8],
        now: Timestamp,
    ) -> Result<NodeCert, CaError> {
        let cert = certs::issue_node_from_csr(
            &self.signer,
            node,
            csr_der,
            now.0,
            self.policy.node_validity_days,
        )?;
        let info = CertInfo::from_der(&cert)?;
        Ok(NodeCert {
            node,
            chain: vec![cert],
            info,
        })
    }

    /// Issues a node certificate with a freshly generated key (a node on this host, tests).
    ///
    /// # Errors
    ///
    /// A generation error.
    pub fn issue_node_cert_with_key(
        &self,
        node: NodeId,
        now: Timestamp,
    ) -> Result<IssuedCert, CaError> {
        let (cert, key) =
            certs::issue_node(&self.signer, node, now.0, self.policy.node_validity_days)?;
        let info = CertInfo::from_der(&cert)?;
        Ok(IssuedCert {
            chain: vec![cert],
            key,
            info,
        })
    }

    /// Issues a node certificate for the key in a PKCS#10 CSR with the node's roles:
    /// `urn:tenko:node:<id>` and one `urn:tenko:role:<role>` per role as URI subject
    /// alternative names, server and client authentication (enrollment and renewal, WP2.2).
    ///
    /// # Errors
    ///
    /// [`CaError::InvalidCsr`] or a generation error.
    pub fn issue_node_cert_for(
        &self,
        node: NodeId,
        roles: RoleSet,
        csr_der: &[u8],
        now: Timestamp,
    ) -> Result<NodeCert, CaError> {
        let cert = certs::issue_node_with_roles_from_csr(
            &self.signer,
            node,
            roles,
            csr_der,
            now.0,
            self.policy.node_validity_days,
        )?;
        let info = CertInfo::from_der(&cert)?;
        Ok(NodeCert {
            node,
            chain: vec![cert],
            info,
        })
    }

    /// Issues a node certificate with roles and a freshly generated key (the controller's
    /// own certificate on the cluster port).
    ///
    /// # Errors
    ///
    /// A generation error.
    pub fn issue_node_cert_with_key_for(
        &self,
        node: NodeId,
        roles: RoleSet,
        now: Timestamp,
    ) -> Result<IssuedCert, CaError> {
        let (cert, key) = certs::issue_node_with_roles(
            &self.signer,
            node,
            roles,
            now.0,
            self.policy.node_validity_days,
        )?;
        let info = CertInfo::from_der(&cert)?;
        Ok(IssuedCert {
            chain: vec![cert],
            key,
            info,
        })
    }

    /// Whether a certificate is due for renewal at `now` (within
    /// [`CaPolicy::renew_before_days`] of expiry, or already expired).
    pub fn needs_renewal(&self, info: &CertInfo, now: Timestamp) -> bool {
        (info.not_after.0 - now.0).whole_days() < i64::from(self.policy.renew_before_days)
    }

    /// The server certificate of TLS mode a of controller `node`: its stored one while it
    /// matches `identity`, was issued by this root and is not due for renewal (read
    /// without a write, so an isolated controller restarts with it); otherwise a new one,
    /// stored (certificate in `cluster.server_certs` under `node`, key in the vault, the
    /// old key deleted) with a `cluster.tls.issue` audit record. A controller without a
    /// record takes over `cluster.server_cert` of earlier versions when it carries its
    /// names. Call at start and periodically (daily), and after the host name changes;
    /// install the result in the TLS service.
    ///
    /// # Errors
    ///
    /// A generation, vault or store error.
    pub async fn server_material(
        &self,
        store: &dyn Store,
        vault: &dyn Vault,
        ctx: &RequestCtx,
        node: NodeId,
        identity: &ServerIdentity,
    ) -> Result<TlsMaterial, CaError> {
        let view = store.read(ReadConsistency::Local).await?;
        let own = view.get_typed(&tables::SERVER_CERTS, &node.0)?;
        // The record of earlier versions belongs to the controller whose names it carries;
        // it leaves with its key in one write, so an older controller never deletes a key
        // that a record of this table holds.
        let legacy = match own {
            None => view
                .get_typed(&tables::SERVER_CERT, &())?
                .filter(|(record, _)| record.identity == *identity),
            Some(_) => None,
        };
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(
            &tables::SERVER_CERTS,
            &node.0,
            own.as_ref().map(|(_, revision)| *revision),
        );
        if let Some((_, revision)) = &legacy {
            batch.expect_typed(&tables::SERVER_CERT, &(), Some(*revision));
            batch.delete_typed(&tables::SERVER_CERT, &());
        }
        let current = own.as_ref().or(legacy.as_ref()).map(|(record, _)| record);
        if let Some(record) = current
            && let Some(material) = self.reusable(vault, ctx, record, identity).await?
        {
            if legacy.is_some() {
                batch.put_typed(&tables::SERVER_CERTS, &node.0, record)?;
                if let Err(error) = store.propose(batch).await {
                    tracing::warn!(%error, "the server certificate of an earlier version is served; it moves to this controller's record at the next check");
                }
            }
            return Ok(material);
        }
        let issued = self.issue_server_cert(identity, ctx.now)?;
        let key = vault.stage_put(
            &mut batch,
            ctx,
            SecretClass::System,
            SecretSpec::new(TLS_KEY_PURPOSE).labeled(identity.host_name.clone()),
            &issued.key,
        )?;
        if let Some(old) = current {
            vault.stage_delete(&mut batch, ctx, old.key);
        }
        let record = ServerCertRecord {
            chain_pem: issued.chain_pem(),
            key,
            identity: identity.clone(),
            issued_at: ctx.now,
        };
        batch.put_typed(&tables::SERVER_CERTS, &node.0, &record)?;
        batch.audit(
            AuditDraft::success(SERVER_CERT_ISSUE, vec![ObjectRef::node(node)])
                .with_source_ip(ctx.source_ip)
                .with_context("host_name", identity.host_name.clone())
                .with_context("not_after", issued.info.not_after.to_rfc3339())
                .with_context("sha256", issued.info.sha256.clone()),
        );
        store.propose(batch).await?;
        tracing::info!(
            host = %identity.host_name,
            not_after = %issued.info.not_after,
            "issued a server certificate from the internal CA"
        );
        Ok(issued.material()?)
    }

    async fn reusable(
        &self,
        vault: &dyn Vault,
        ctx: &RequestCtx,
        record: &ServerCertRecord,
        identity: &ServerIdentity,
    ) -> Result<Option<TlsMaterial>, CaError> {
        if record.identity != *identity {
            return Ok(None);
        }
        let Ok(chain) = CertificateDer::pem_slice_iter(record.chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
        else {
            return Ok(None);
        };
        let Some(leaf) = chain.first() else {
            return Ok(None);
        };
        let info = CertInfo::from_der(leaf)?;
        if info.issuer != self.root_info.subject || self.needs_renewal(&info, ctx.now) {
            return Ok(None);
        }
        // A key that is gone or no longer opens is replaced by a new certificate rather than
        // failing every start; store and KEK failures still surface.
        let key = match vault.get_system(ctx, record.key).await {
            Ok(key) => key,
            Err(VaultError::NotFound { .. } | VaultError::Integrity) => {
                tracing::warn!("the stored server certificate key is unusable; issuing a new one");
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        Ok(TlsMaterial::from_der(chain, &key, CertSource::InternalCa).ok())
    }
}

/// PEM-encodes one DER block, for example `pem("CERTIFICATE", der)`.
pub fn pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_round_trips_through_the_parser() {
        for len in [0usize, 1, 2, 3, 47, 48, 49, 100] {
            let der: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i % 251).expect("byte"))
                .collect();
            let text = pem("CERTIFICATE", &der);
            let back = CertificateDer::from_pem_slice(text.as_bytes());
            if len == 0 {
                continue;
            }
            assert_eq!(
                back.expect("parse").as_ref(),
                der.as_slice(),
                "length {len}"
            );
        }
    }

    #[test]
    fn default_policy_is_browser_friendly() {
        let policy = CaPolicy::default();
        assert!(policy.server_validity_days <= 398);
        assert!(policy.renew_before_days < policy.server_validity_days);
    }
}
