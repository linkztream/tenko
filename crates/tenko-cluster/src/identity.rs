//! The credentials of an enrolled node on its own disk, in `<data_dir>/node/`:
//!
//! | File | Contents |
//! |---|---|
//! | `identity.json` | node id, name, roles, the controller, the cluster endpoints |
//! | `ca-root.pem` | the internal CA root the node trusts on the cluster port |
//! | `node-cert.pem` | the node certificate, leaf first |
//! | `node-key.pem` (Unix) or `node-key.dpapi` (Windows) | the node's private key |
//! | `status.json` | what the running node process last saw (see [`AgentStatus`]) |
//! | `buffer/` | the observation buffer ([`crate::buffer`]) |
//! | `config/` | the configuration the controllers hand the node ([`crate::node_sync::local`]) |
//!
//! The key never leaves the node. On Unix the directory is `0700` and the files `0600`;
//! on Windows the key is sealed with DPAPI in the machine scope, so a copied data directory
//! does not carry a usable key to another host. A renewal writes the new certificate and
//! key next to the old ones and renames them into place; the old pair stays as `.old`
//! until the new one loads, so a crash in between leaves a working pair.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustls::{
    ClientConfig,
    pki_types::{CertificateDer, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use tenko_core::{NodeId, Role, RoleSet, Timestamp};
use tenko_vault::SecretBytes;
use zeroize::Zeroizing;

use crate::{
    buffer::BufferStats,
    ca::{CertInfo, roles_in},
    error::ClusterError,
};

/// The node directory under the data directory.
pub const NODE_DIR: &str = "node";

#[cfg(windows)]
const KEY_FILE: &str = "node-key.dpapi";
#[cfg(not(windows))]
const KEY_FILE: &str = "node-key.pem";

/// The DPAPI label of the node key (bound into the seal).
#[cfg(windows)]
const KEY_LABEL: &str = "node-key";

/// The paths of a node's files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePaths {
    root: PathBuf,
}

impl NodePaths {
    /// The node directory of a data directory.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join(NODE_DIR),
        }
    }

    /// The node directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `identity.json`.
    pub fn identity(&self) -> PathBuf {
        self.root.join("identity.json")
    }

    /// `ca-root.pem`.
    pub fn ca_root(&self) -> PathBuf {
        self.root.join("ca-root.pem")
    }

    /// `node-cert.pem`.
    pub fn certificate(&self) -> PathBuf {
        self.root.join("node-cert.pem")
    }

    /// The key file.
    pub fn key(&self) -> PathBuf {
        self.root.join(KEY_FILE)
    }

    /// `status.json`.
    pub fn status(&self) -> PathBuf {
        self.root.join("status.json")
    }

    /// `buffer/`.
    pub fn buffer(&self) -> PathBuf {
        self.root.join("buffer")
    }

    /// `config/`: the configuration the controllers hand the node.
    pub fn config(&self) -> PathBuf {
        self.root.join("config")
    }

    /// Whether the node is enrolled (its identity file exists).
    pub fn is_enrolled(&self) -> bool {
        self.identity().is_file()
    }
}

/// Who the node is and where its controllers are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// The node id.
    pub node: NodeId,
    /// Its name.
    pub name: String,
    /// Its roles.
    pub roles: Vec<Role>,
    /// The controller URL it enrolled with (`https://host:port`).
    pub controller: String,
    /// `host:port` endpoints of the cluster port; empty: the controller's host with
    /// `cluster_port`.
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// The cluster port of the controller.
    #[serde(default)]
    pub cluster_port: Option<u16>,
    /// Seconds between two heartbeats, as the controller said at enrolment.
    pub heartbeat_secs: u32,
    /// When it enrolled.
    pub enrolled_at: Timestamp,
    /// SHA-256 of the CA root, lower-case hex.
    pub ca_sha256: String,
}

impl NodeIdentity {
    /// The `host:port` targets to dial, in order.
    pub fn dial_targets(&self) -> Vec<String> {
        if !self.endpoints.is_empty() {
            return self.endpoints.clone();
        }
        let Some(host) = url_host(&self.controller) else {
            return Vec::new();
        };
        let port = self.cluster_port.unwrap_or(8444);
        if host.contains(':') && !host.starts_with('[') {
            vec![format!("[{host}]:{port}")]
        } else {
            vec![format!("{host}:{port}")]
        }
    }

    /// The roles as a set.
    pub fn role_set(&self) -> RoleSet {
        self.roles.iter().copied().collect()
    }
}

/// The host of an `http(s)://host[:port][/path]` URL, with IPv6 brackets kept.
pub fn url_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = if authority.starts_with('[') {
        let end = authority.find(']')?;
        &authority[..=end]
    } else {
        authority.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_owned())
}

/// Splits `host:port` (IPv6 hosts in brackets).
///
/// # Errors
///
/// `cluster.node.endpoint` (400).
pub fn split_host_port(target: &str) -> Result<(String, u16), ClusterError> {
    let invalid = || {
        ClusterError::new(
            "cluster.node.endpoint",
            400,
            format!("`{target}` is not a host and port such as ddi.example.net:8444"),
        )
    };
    let (host, port) = target.rsplit_once(':').ok_or_else(invalid)?;
    let port: u16 = port.parse().map_err(|_| invalid())?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || port == 0 {
        return Err(invalid());
    }
    Ok((host.to_owned(), port))
}

/// A node's loaded credentials.
pub struct Credentials {
    /// The identity.
    pub identity: NodeIdentity,
    /// The certificate chain, leaf first.
    pub chain: Vec<CertificateDer<'static>>,
    /// The private key, PKCS#8.
    pub key: SecretBytes,
    /// The CA root.
    pub ca_root: CertificateDer<'static>,
    /// What the leaf says.
    pub info: CertInfo,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("identity", &self.identity)
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

fn io_error(path: &Path, error: &impl std::fmt::Display) -> ClusterError {
    ClusterError::new(
        "cluster.node.files",
        500,
        format!("{}: {error}", path.display()),
    )
    .with_param("path", path.display().to_string())
}

fn not_enrolled() -> ClusterError {
    ClusterError::new(
        "cluster.node.not_enrolled",
        409,
        "this node is not enrolled; run `tenko node enrol --controller <url> --token <token>` first",
    )
}

/// Creates the node directory, private to the service account on Unix.
///
/// # Errors
///
/// `cluster.node.files`.
pub fn create_private_dir(dir: &Path) -> Result<(), ClusterError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|error| io_error(dir, &error))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir).map_err(|error| io_error(dir, &error))
    }
}

/// Writes a file atomically (temporary file, flush to disk, rename), `0600` on Unix.
///
/// # Errors
///
/// `cluster.node.files`.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ClusterError> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(|error| io_error(&tmp, &error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(&tmp, &error))?;
    drop(file);
    fs::rename(&tmp, path).map_err(|error| io_error(path, &error))
}

fn read(path: &Path) -> Result<Vec<u8>, ClusterError> {
    fs::read(path).map_err(|error| io_error(path, &error))
}

#[cfg_attr(
    not(windows),
    allow(
        clippy::unnecessary_wraps,
        reason = "sealing fails only with DPAPI on Windows"
    )
)]
fn seal_key(key: &SecretBytes) -> Result<Zeroizing<Vec<u8>>, ClusterError> {
    #[cfg(windows)]
    {
        use tenko_vault::{KekSealer as _, kek::DpapiScope, kek::DpapiSealer};
        DpapiSealer::new(DpapiScope::Machine)
            .seal(KEY_LABEL, key.expose())
            .map(Zeroizing::new)
            .map_err(|error| ClusterError::coded(&error))
    }
    #[cfg(not(windows))]
    {
        Ok(Zeroizing::new(
            crate::ca::pem_block("PRIVATE KEY", key.expose()).into_bytes(),
        ))
    }
}

fn unseal_key(bytes: &[u8]) -> Result<SecretBytes, ClusterError> {
    #[cfg(windows)]
    {
        use tenko_vault::{KekSealer as _, kek::DpapiScope, kek::DpapiSealer};
        let plain = DpapiSealer::new(DpapiScope::Machine)
            .unseal(KEY_LABEL, bytes)
            .map_err(|error| ClusterError::coded(&error))?;
        Ok(SecretBytes::from_slice(&plain))
    }
    #[cfg(not(windows))]
    {
        use rustls::pki_types::PrivateKeyDer;
        match PrivateKeyDer::from_pem_slice(bytes) {
            Ok(PrivateKeyDer::Pkcs8(key)) => Ok(SecretBytes::from_slice(key.secret_pkcs8_der())),
            _ => Err(ClusterError::new(
                "cluster.node.key",
                500,
                "the node key file holds no PKCS#8 key",
            )),
        }
    }
}

fn parse_chain(pem: &[u8], path: &Path) -> Result<Vec<CertificateDer<'static>>, ClusterError> {
    let chain = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(path, &error))?;
    if chain.is_empty() {
        return Err(io_error(path, &"no certificate in the file"));
    }
    Ok(chain)
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

impl Credentials {
    /// Loads the credentials, falling back to the previous certificate and key when a
    /// renewal was interrupted.
    ///
    /// # Errors
    ///
    /// `cluster.node.not_enrolled` (409) when the node has no identity, `cluster.node.files`
    /// or `cluster.node.key` when a file is unreadable or the key does not fit.
    pub fn load(paths: &NodePaths) -> Result<Self, ClusterError> {
        if !paths.is_enrolled() {
            return Err(not_enrolled());
        }
        let identity: NodeIdentity = serde_json::from_slice(&read(&paths.identity())?)
            .map_err(|error| io_error(&paths.identity(), &error))?;
        let ca_root = CertificateDer::from_pem_slice(&read(&paths.ca_root())?)
            .map_err(|error| io_error(&paths.ca_root(), &error))?;
        match Self::pair(paths, &identity, &ca_root, "") {
            Ok(credentials) => Ok(credentials),
            Err(error) => Self::pair(paths, &identity, &ca_root, ".old").map_err(|_| error),
        }
    }

    fn pair(
        paths: &NodePaths,
        identity: &NodeIdentity,
        ca_root: &CertificateDer<'static>,
        suffix: &str,
    ) -> Result<Self, ClusterError> {
        let cert_path = with_suffix(&paths.certificate(), suffix);
        let key_path = with_suffix(&paths.key(), suffix);
        let chain = parse_chain(&read(&cert_path)?, &cert_path)?;
        let key = unseal_key(&read(&key_path)?)?;
        let credentials = Self {
            identity: identity.clone(),
            info: CertInfo::from_der(&chain[0])?,
            chain,
            key,
            ca_root: ca_root.clone(),
        };
        // A key that does not fit its certificate fails here, not at the first handshake.
        credentials.client_config()?;
        Ok(credentials)
    }

    /// The credentials an enrolment produced: the identity, the certificate chain and
    /// CA root as PEM, and the key the node generated.
    ///
    /// # Errors
    ///
    /// `cluster.node.enrol_answer` (502) when the PEM is unreadable, the certificate names
    /// another node or the key does not fit.
    pub fn from_pem(
        identity: NodeIdentity,
        certificate_pem: &str,
        key: SecretBytes,
        ca_root_pem: &str,
    ) -> Result<Self, ClusterError> {
        let bad = |detail: String| ClusterError::new("cluster.node.enrol_answer", 502, detail);
        let chain = CertificateDer::pem_slice_iter(certificate_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| bad(format!("the certificate is unreadable: {error}")))?;
        let leaf = chain
            .first()
            .ok_or_else(|| bad("the answer holds no certificate".to_owned()))?;
        if crate::ca::node_id_of(leaf) != Some(identity.node) {
            return Err(bad(format!(
                "the certificate does not name node {}",
                identity.node
            )));
        }
        let ca_root = CertificateDer::from_pem_slice(ca_root_pem.as_bytes())
            .map_err(|error| bad(format!("the CA root is unreadable: {error}")))?;
        let credentials = Self {
            identity,
            info: CertInfo::from_der(leaf)?,
            chain,
            key,
            ca_root,
        };
        credentials.client_config()?;
        Ok(credentials)
    }

    /// Writes everything (at enrolment).
    ///
    /// # Errors
    ///
    /// `cluster.node.files`, or a sealing error on Windows.
    pub fn save(&self, paths: &NodePaths) -> Result<(), ClusterError> {
        create_private_dir(paths.root())?;
        write_private(&paths.key(), &seal_key(&self.key)?)?;
        write_private(&paths.certificate(), self.chain_pem().as_bytes())?;
        write_private(
            &paths.ca_root(),
            crate::ca::pem_block("CERTIFICATE", &self.ca_root).as_bytes(),
        )?;
        let identity = serde_json::to_vec_pretty(&self.identity)
            .map_err(|error| io_error(&paths.identity(), &error))?;
        write_private(&paths.identity(), &identity)
    }

    /// Replaces the certificate and key after a renewal: the old pair is kept as `.old`
    /// until the next renewal.
    ///
    /// # Errors
    ///
    /// `cluster.node.files`, `cluster.node.key`, or a sealing error.
    pub fn renewed(
        &self,
        paths: &NodePaths,
        chain: Vec<CertificateDer<'static>>,
        key: SecretBytes,
    ) -> Result<Self, ClusterError> {
        let next = Self {
            identity: self.identity.clone(),
            info: CertInfo::from_der(&chain[0])?,
            chain,
            key,
            ca_root: self.ca_root.clone(),
        };
        next.client_config()?;
        let (cert, key_file) = (paths.certificate(), paths.key());
        let (cert_new, key_new) = (with_suffix(&cert, ".new"), with_suffix(&key_file, ".new"));
        write_private(&cert_new, next.chain_pem().as_bytes())?;
        write_private(&key_new, &seal_key(&next.key)?)?;
        for (current, old) in [
            (&cert, with_suffix(&cert, ".old")),
            (&key_file, with_suffix(&key_file, ".old")),
        ] {
            if current.exists() {
                fs::rename(current, &old).map_err(|error| io_error(current, &error))?;
            }
        }
        fs::rename(&key_new, &key_file).map_err(|error| io_error(&key_file, &error))?;
        fs::rename(&cert_new, &cert).map_err(|error| io_error(&cert, &error))?;
        Ok(next)
    }

    /// The credentials with the cluster endpoints a controller named (`HelloResponse`),
    /// written to `identity.json`; `None` when the list is empty or unchanged.
    ///
    /// # Errors
    ///
    /// `cluster.node.files`.
    pub fn with_endpoints(
        &self,
        paths: &NodePaths,
        endpoints: &[String],
    ) -> Result<Option<Self>, ClusterError> {
        let endpoints: Vec<String> = endpoints
            .iter()
            .filter(|endpoint| split_host_port(endpoint).is_ok())
            .take(32)
            .cloned()
            .collect();
        if endpoints.is_empty() || endpoints == self.identity.endpoints {
            return Ok(None);
        }
        let mut identity = self.identity.clone();
        identity.endpoints = endpoints;
        let bytes = serde_json::to_vec_pretty(&identity)
            .map_err(|error| io_error(&paths.identity(), &error))?;
        write_private(&paths.identity(), &bytes)?;
        Ok(Some(Self {
            identity,
            chain: self.chain.clone(),
            key: self.key.clone(),
            ca_root: self.ca_root.clone(),
            info: self.info.clone(),
        }))
    }

    /// The chain as PEM.
    pub fn chain_pem(&self) -> String {
        self.chain
            .iter()
            .map(|cert| crate::ca::pem_block("CERTIFICATE", cert))
            .collect()
    }

    /// The TLS configuration of this node.
    ///
    /// # Errors
    ///
    /// As [`crate::mtls::client_config`].
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, ClusterError> {
        crate::mtls::client_config(&self.ca_root, self.chain.clone(), &self.key)
    }

    /// The roles in the certificate.
    pub fn certificate_roles(&self) -> RoleSet {
        roles_in(&self.info.uris)
    }

    /// Whether the certificate is due for renewal at `now`: less than a third of its
    /// lifetime or fewer than 30 days left.
    pub fn needs_renewal(&self, now: Timestamp) -> bool {
        let lifetime = self.info.not_after.saturating_since(self.info.not_before);
        let left = self.info.not_after.saturating_since(now);
        left < lifetime / 3 || left < Duration::from_secs(30 * 24 * 3600)
    }
}

/// What the running node process last saw, in `status.json` (read by `tenko node status`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatus {
    /// The state.
    pub state: AgentState,
    /// The cluster endpoint of the current or last connection.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Since when the state holds.
    pub since: Timestamp,
    /// When the file was written.
    pub updated_at: Timestamp,
    /// The agreed protocol major.
    #[serde(default)]
    pub major: Option<u32>,
    /// The controller's software version.
    #[serde(default)]
    pub controller_version: Option<String>,
    /// The last error, with its code.
    #[serde(default)]
    pub last_error: Option<StatusError>,
    /// The observation buffer.
    #[serde(default)]
    pub buffer: Option<BufferStats>,
    /// When the node certificate expires.
    #[serde(default)]
    pub certificate_not_after: Option<Timestamp>,
    /// The process id of the node process.
    pub pid: u32,
    /// The revision of the configuration the controllers handed the node; `None` before
    /// its first sync.
    #[serde(default)]
    pub config_revision: Option<u64>,
}

/// The state of a node process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    /// Dialling a controller.
    Connecting,
    /// Connected and sending heartbeats.
    Connected,
    /// Not connected; trying again after a pause.
    Disconnected,
    /// The controller and the node share no protocol major.
    ProtocolMismatch,
    /// The controller refused the node (unknown node, unknown certificate), or the
    /// controller's certificate is not from this node's CA.
    Refused,
    /// The node was revoked; enrol it again.
    Revoked,
    /// The node process stopped.
    Stopped,
}

/// An error in the status file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusError {
    /// The stable code.
    pub code: String,
    /// The English detail.
    pub detail: String,
    /// When.
    pub at: Timestamp,
}

impl AgentStatus {
    /// Reads `status.json`; `None` when there is none.
    ///
    /// # Errors
    ///
    /// `cluster.node.files` when it cannot be read or parsed.
    pub fn load(paths: &NodePaths) -> Result<Option<Self>, ClusterError> {
        let path = paths.status();
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| io_error(&path, &error)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error(&path, &error)),
        }
    }

    /// Writes `status.json`.
    ///
    /// # Errors
    ///
    /// `cluster.node.files`.
    pub fn save(&self, paths: &NodePaths) -> Result<(), ClusterError> {
        let bytes =
            serde_json::to_vec_pretty(self).map_err(|error| io_error(&paths.status(), &error))?;
        write_private(&paths.status(), &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(controller: &str) -> NodeIdentity {
        NodeIdentity {
            node: NodeId(1001),
            name: "probe-dmz".to_owned(),
            roles: vec![Role::Probe],
            controller: controller.to_owned(),
            endpoints: Vec::new(),
            cluster_port: Some(8444),
            heartbeat_secs: 10,
            enrolled_at: "2026-10-10T08:00:00Z".parse().expect("time"),
            ca_sha256: "00".repeat(32),
        }
    }

    #[test]
    fn dial_targets_follow_the_controller_url() {
        assert_eq!(
            identity("https://ddi.example.net:8443").dial_targets(),
            ["ddi.example.net:8444"]
        );
        assert_eq!(
            identity("https://192.0.2.1:8443/").dial_targets(),
            ["192.0.2.1:8444"]
        );
        assert_eq!(
            identity("https://[2001:db8::1]:8443").dial_targets(),
            ["[2001:db8::1]:8444"]
        );
        let mut advertised = identity("https://ddi.example.net:8443");
        advertised.endpoints = vec!["cluster.example.net:9444".to_owned()];
        assert_eq!(advertised.dial_targets(), ["cluster.example.net:9444"]);
        assert_eq!(
            identity("ddi.example.net").dial_targets(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn host_and_port_split() {
        assert_eq!(
            split_host_port("ddi.example.net:8444").expect("split"),
            ("ddi.example.net".to_owned(), 8444)
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:8444").expect("split"),
            ("2001:db8::1".to_owned(), 8444)
        );
        for bad in [
            "ddi.example.net",
            ":8444",
            "ddi.example.net:0",
            "ddi.example.net:x",
        ] {
            assert!(split_host_port(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn status_round_trips() {
        let dir = tempfile::tempdir().expect("dir");
        let paths = NodePaths::new(dir.path());
        assert_eq!(AgentStatus::load(&paths).expect("load"), None);
        create_private_dir(paths.root()).expect("dir");
        let status = AgentStatus {
            state: AgentState::Connected,
            endpoint: Some("ddi.example.net:8444".to_owned()),
            since: "2026-10-10T08:00:00Z".parse().expect("time"),
            updated_at: "2026-10-10T08:00:10Z".parse().expect("time"),
            major: Some(1),
            controller_version: Some("0.0.1".to_owned()),
            last_error: None,
            buffer: None,
            certificate_not_after: None,
            pid: 4242,
            config_revision: Some(17),
        };
        status.save(&paths).expect("save");
        assert_eq!(AgentStatus::load(&paths).expect("load"), Some(status));
    }

    #[test]
    fn an_unenrolled_node_says_so() {
        let dir = tempfile::tempdir().expect("dir");
        let error = Credentials::load(&NodePaths::new(dir.path())).expect_err("not enrolled");
        assert_eq!(error.code(), "cluster.node.not_enrolled");
    }
}
