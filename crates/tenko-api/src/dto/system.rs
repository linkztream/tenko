//! Health, readiness and status of the node (OPS-05, OPS-22).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tenko_core::{AuditSeq, NodeId, Revision, Timestamp};
use utoipa::ToSchema;

/// Body of `GET /health` (liveness): the process answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Health {
    /// Always `ok`.
    pub status: String,
    /// Version of the server.
    pub version: String,
}

/// Body of `GET /health/ready` when the node serves requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Readiness {
    /// Always `ready`.
    pub status: String,
    /// Store revision the node has applied.
    pub revision: Revision,
}

/// Body of `GET /system/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SystemStatus {
    /// Version of the server.
    pub version: String,
    /// When the API started.
    pub started_at: Timestamp,
    /// Seconds since the API started.
    pub uptime_seconds: u64,
    /// This node.
    pub node: NodeStatus,
    /// The replicated store as this node sees it.
    pub store: StoreSummary,
    /// TLS and reverse proxy settings of the listener; absent while no listener runs.
    pub tls: Option<TlsStatus>,
    /// Whether the build embeds the real web UI or the development placeholder.
    pub ui: UiStatus,
    /// The product modules this installation runs (OPS-25); the UI shows only their
    /// areas. Absent in answers of servers that predate the module switch: all modules.
    #[serde(default)]
    pub modules: crate::modules::ModuleSet,
    /// Conditions an administrator should look at, for example a certificate close to
    /// expiry or plain HTTP in the Lab profile.
    pub warnings: Vec<StatusWarning>,
}

/// Identity and roles of the node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NodeStatus {
    /// Raft node id, once enrolled.
    pub id: Option<NodeId>,
    /// Roles this node runs: `controller`, `dns`, `dhcp`, `probe`.
    pub roles: Vec<String>,
}

/// Summary of the store status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StoreSummary {
    /// `memory`, `leader`, `follower`, `learner`, `candidate` or `shutdown`.
    pub role: String,
    /// Current leader, when known.
    pub leader: Option<NodeId>,
    /// Last applied revision.
    pub revision: Revision,
    /// Revisions behind the leader, when known.
    pub lag: Option<u64>,
    /// Sequence number of the newest audit record.
    pub audit_head: AuditSeq,
    /// Oldest revision still in the journal (SSE replay reaches back to it).
    pub journal_oldest: Option<Revision>,
    /// Change sets in the journal.
    pub journal_len: u64,
    /// Bytes of live data.
    pub data_bytes: u64,
    /// Bytes on disk, when the store is persistent.
    pub disk_bytes: Option<u64>,
}

/// How the listener secures connections (OPS-22, TGL-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Mode a: TLS with a server certificate from the internal CA.
    InternalCa,
    /// Mode b: TLS with an imported certificate and key, reloaded on change.
    Imported,
    /// Mode c: plain HTTP from trusted reverse proxies that terminate TLS.
    ReverseProxy,
    /// Lab profile only: plain HTTP from any source.
    Plain,
}

impl TlsMode {
    /// Whether the listener itself terminates TLS.
    pub const fn terminates_tls(self) -> bool {
        matches!(self, TlsMode::InternalCa | TlsMode::Imported)
    }
}

/// TLS status of the listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TlsStatus {
    /// The TLS mode.
    pub mode: TlsMode,
    /// The served certificate (modes a and b).
    pub certificate: Option<CertificateStatus>,
    /// Lowest TLS version accepted (`1.2` or `1.3`), when the listener terminates TLS.
    pub min_version: Option<String>,
    /// Whether HTTPS responses carry `Strict-Transport-Security`.
    pub hsts: bool,
    /// Trusted reverse proxy networks (CIDR).
    pub trusted_proxies: Vec<String>,
    /// Whether the PROXY protocol is read from trusted proxies.
    pub proxy_protocol: bool,
}

/// The certificate the listener serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CertificateStatus {
    /// Names the certificate is valid for, when known.
    pub names: Vec<String>,
    /// End of validity, when known.
    pub not_after: Option<Timestamp>,
    /// Whole days until `not_after` (negative once expired).
    pub days_remaining: Option<i64>,
    /// When the listener loaded this certificate.
    pub loaded_at: Timestamp,
}

/// Which web UI the binary serves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UiStatus {
    /// The development placeholder page instead of the web UI (`TENKO_UI_STUB=1`).
    pub stub: bool,
    /// The UI is served from a directory (`--ui-dir`, development).
    pub from_directory: bool,
}

/// A condition an administrator should look at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StatusWarning {
    /// Stable code, for example `sys.tls.certificate_expiring`.
    pub code: String,
    /// English explanation.
    pub detail: String,
    /// Parameters for the UI's translated message.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
}
