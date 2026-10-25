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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
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
    /// The node transport of a controller (OPS-04, OPS-08): enrolled and connected nodes,
    /// their versions; absent on servers without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<ClusterStatus>,
    /// The key-encryption key of this controller (IAM-15): provider, protection, the active
    /// generation and the online rotation; absent on servers without the vault service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kek: Option<super::kek::KekSummaryView>,
    /// The leader-only work of this controller (plan section 2.3): whether it leads, the
    /// leader epoch of its term of office and the state of every leader service; absent
    /// on servers without the leader supervisor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leader: Option<LeaderStatus>,
    /// Backups (OPS-07): the schedule, the last good and the last failed backup and the
    /// restore this installation started from; absent on servers without the backup
    /// service. Its warnings (`backup.stale`, `backup.failed`, `backup.restored`) are in
    /// `warnings`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<super::backup::BackupSummaryView>,
    /// The data-directory format (OPS-08, OPS-23): the format of the stored data, the
    /// newest one this controller's binary knows, and a migration that waits until every
    /// voter of the cluster runs a binary that knows its format; absent on servers that
    /// predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_format: Option<DataFormatStatus>,
    /// The host under this node (OPS-20): CPU, memory and the file system of the data
    /// directory, as last read (at most five seconds ago). Absent when nothing could be read.
    /// `node.disk.low` in `warnings` says the file system is running out of room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostStatus>,
}

/// The host under the node, for `GET /system/status`. A figure that could not be read is absent;
/// CPU and memory are read on Linux only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct HostStatus {
    /// The share of the CPU's time that was busy since the previous reading, 0 to 100; absent
    /// when there was no earlier reading to compare with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<f64>,
    /// Physical memory in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_total: Option<u64>,
    /// Memory a program can use without swapping, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_available: Option<u64>,
    /// The size of the file system of the data directory in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_total: Option<u64>,
    /// The space available to the node on that file system in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_available: Option<u64>,
    /// When the node read these figures.
    pub sampled_at: Timestamp,
}

/// The data-directory format of the installation, for `GET /system/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DataFormatStatus {
    /// The format the stored (replicated) data is in.
    pub stored: u32,
    /// The newest format this controller's binary knows.
    pub binary: u32,
    /// A migration the leader runs once nothing blocks it; absent when the stored data is
    /// at the newest format of this binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<PendingMigration>,
}

/// A format migration of a controller cluster that waits for the last voters to be
/// upgraded (leader-gated migration, R26).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PendingMigration {
    /// The format the stored data is migrated to.
    pub target: u32,
    /// The voters whose binary does not know the target format yet; empty when the leader
    /// is about to run the migration.
    pub blocked_by: Vec<FormatBlocker>,
}

/// A voter that keeps a migration from running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FormatBlocker {
    /// The node id of the voter.
    #[schema(value_type = u64)]
    pub node: NodeId,
    /// The software version it reported; absent when it never reported one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The newest data format its binary knows, as it reported it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_format: Option<u32>,
}

/// The leader-only work of a controller, for `GET /system/status`. In a cluster exactly
/// one controller leads and runs the leader services (the job runner, purges, the online
/// KEK rotation and others); the other controllers list them as `idle`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LeaderStatus {
    /// Whether this controller holds the office and runs the leader services.
    pub leads: bool,
    /// The leader epoch of the term of office (the counter `sys.leader_epoch`) while this
    /// controller leads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    /// When this controller took office, or left it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<Timestamp>,
    /// Every registered leader service, in start order.
    pub services: Vec<LeaderServiceStatus>,
    /// This controller's clock minus the leader's, in milliseconds, as measured on the
    /// leader's last clock beat; absent on a single controller and while no beat arrived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_ms: Option<i64>,
}

/// One leader-only service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LeaderServiceStatus {
    /// The stable name, such as `jobs.runner`.
    pub name: String,
    /// What the service does now.
    pub state: LeaderServiceState,
    /// How often the service was restarted after it gave up, in this term of office.
    pub restarts: u32,
    /// The error the service last gave up with, in this term of office.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Since when the service is in its state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<Timestamp>,
}

/// The state of a leader-only service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LeaderServiceState {
    /// This controller does not lead: the service runs on the leader.
    Idle,
    /// The service runs on this controller.
    Running,
    /// The service gave up and is restarted after a pause.
    Restarting,
    /// The service ended its work for this term of office.
    Finished,
}

/// The node transport of a controller, for `GET /system/status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ClusterStatus {
    /// The addresses the cluster port listens on; empty while it is off.
    pub listening: Vec<String>,
    /// The protocol majors this controller implements.
    pub majors: Vec<u32>,
    /// Enrolled nodes.
    pub nodes: u64,
    /// Nodes connected to this controller now.
    pub connected: u64,
    /// Software versions of the connected nodes and how many run each.
    pub versions: BTreeMap<String, u64>,
    /// Nodes whose last handshake was refused for want of a common protocol major; each
    /// also has a `cluster.protocol.mismatch` warning.
    pub mismatched: u64,
}

/// Identity and roles of the node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NodeStatus {
    /// Raft node id, once enrolled.
    pub id: Option<NodeId>,
    /// Roles this node runs: `controller`, `dns`, `dhcp`, `probe`.
    pub roles: Vec<String>,
    /// What the installer prepared this machine for, per role, with what the server found
    /// missing at start; absent when no installer recorded it (a container, a node set up
    /// by hand, an installer older than the record).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared: Option<PreparedRoles>,
}

/// What the installer prepared this machine for (OPS-01): the file `prepared-roles` beside
/// `tenko.toml`, which `deploy/install.sh` and the MSI write and the server reads at start,
/// joined with what the server checks itself (`CAP_NET_RAW` in its bounding and effective
/// sets on Linux). The Hardened profile prepares only the roles chosen at installation;
/// every other profile prepares every role.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreparedRoles {
    /// The file the record was read from.
    pub file: String,
    /// The security profile of the installer run that wrote it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// The systemd drop-ins it put in place (Linux): `probe.conf`, `dhcp-direct.conf`.
    #[serde(default)]
    pub dropins: Vec<String>,
    /// The ports it prepared, as `53/udp`: opened on the host firewall where one runs.
    #[serde(default)]
    pub ports: Vec<String>,
    /// The host firewall it configured: `firewalld`, `ufw`, `windows`, or `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall: Option<String>,
    /// Every role in canonical order, prepared or not.
    pub roles: Vec<RolePreparation>,
}

/// Whether the machine is prepared for one role.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RolePreparation {
    /// `controller`, `dns`, `dhcp` or `probe`.
    pub role: String,
    /// Whether the role finds what it needs: the installer prepared it and nothing the
    /// server checks is missing.
    pub prepared: bool,
    /// What is missing, in technical names: a drop-in (`probe.conf`), a capability
    /// (`CAP_NET_RAW`), a port (`67/udp`).
    #[serde(default)]
    pub missing: Vec<String>,
    /// The installer command that prepares the role, when it is not prepared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
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
    /// Whether this controller reaches a quorum (OPS-26). Absent in answers of servers
    /// that predate the controller cluster: a single controller.
    #[serde(default)]
    pub quorum: QuorumView,
}

/// The kind of quorum state of a controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuorumKind {
    /// The only voter.
    Single,
    /// In contact with a quorum.
    Healthy,
    /// No leader known; an election runs.
    Electing,
    /// Out of contact with a quorum: reads serve the local copy, writes are refused.
    Isolated,
}

/// The quorum state of a controller (OPS-26), for `GET /system/status` and `/cluster`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct QuorumView {
    /// The state.
    pub state: QuorumKind,
    /// When an election started (`electing`) or the controller became isolated
    /// (`isolated`).
    pub since: Option<Timestamp>,
    /// The last contact with a quorum while isolated.
    pub last_contact: Option<Timestamp>,
    /// The revision the controller applied last, while isolated: the age of its copy.
    pub applied: Option<Revision>,
}

impl Default for QuorumView {
    /// A single controller.
    fn default() -> Self {
        Self {
            state: QuorumKind::Single,
            since: None,
            last_contact: None,
            applied: None,
        }
    }
}

#[cfg(feature = "server")]
impl From<tenko_store::QuorumState> for QuorumView {
    fn from(state: tenko_store::QuorumState) -> Self {
        use tenko_store::QuorumState;
        match state {
            QuorumState::Single => Self::default(),
            QuorumState::Healthy => Self {
                state: QuorumKind::Healthy,
                ..Self::default()
            },
            QuorumState::Electing { since } => Self {
                state: QuorumKind::Electing,
                since: Some(since),
                ..Self::default()
            },
            QuorumState::Isolated {
                since,
                last_contact,
                applied,
            } => Self {
                state: QuorumKind::Isolated,
                since: Some(since),
                last_contact,
                applied: Some(applied),
            },
        }
    }
}

#[cfg(feature = "server")]
impl From<tenko_cluster::admin::QuorumView> for QuorumView {
    fn from(view: tenko_cluster::admin::QuorumView) -> Self {
        use tenko_cluster::admin::QuorumKind as Kind;
        Self {
            state: match view.state {
                Kind::Single => QuorumKind::Single,
                Kind::Healthy => QuorumKind::Healthy,
                Kind::Electing => QuorumKind::Electing,
                Kind::Isolated => QuorumKind::Isolated,
            },
            since: view.since,
            last_contact: view.last_contact,
            applied: view.applied,
        }
    }
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

/// How close a certificate is to its end of validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertificateState {
    /// 30 whole days or more left.
    Valid,
    /// Fewer than 30 whole days left.
    Warning,
    /// Fewer than 7 whole days left.
    Critical,
    /// Past its end of validity.
    Expired,
    /// Its validity has not begun (a wrong clock, or a certificate dated ahead).
    NotYetValid,
}

/// What a certificate says: the leaf of a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TlsCertificate {
    /// Subject distinguished name (RFC 4514 text).
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// DNS names of the subject alternative name.
    pub dns_names: Vec<String>,
    /// IP addresses of the subject alternative name.
    pub ip_addresses: Vec<String>,
    /// Start of validity.
    pub not_before: Timestamp,
    /// End of validity.
    pub not_after: Timestamp,
    /// Whole days until `not_after` (negative once expired).
    pub days_left: i64,
    /// The classification of `days_left`.
    pub state: CertificateState,
    /// Number of certificates in the chain: the leaf and its intermediates.
    pub chain_len: u32,
    /// SHA-256 of the leaf certificate (DER), lower-case hexadecimal.
    pub sha256: String,
}

/// Mode b: the files the certificate is read from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ImportedTls {
    /// The certificate chain file (PEM, leaf first).
    pub cert_path: String,
    /// The private key file; its contents are never part of any answer.
    pub key_path: String,
    /// Seconds between checks of the files for a change, once the watcher runs.
    pub watch_interval_secs: Option<u64>,
    /// Whether a certificate replaced in the files while the listener runs is loaded. The
    /// security profile decides: on under Lab and Home, off under Standard unless
    /// `tls.accept_external_replacement` is set, never under Hardened.
    pub accept_external_replacement: bool,
}

/// Mode a: the root of the internal CA that issued the server certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct InternalCaTls {
    /// Subject of the CA root certificate, when it can be read.
    pub root_subject: Option<String>,
    /// End of validity of the CA root, when it can be read.
    pub root_not_after: Option<Timestamp>,
    /// SHA-256 of the CA root certificate, lower-case hexadecimal.
    pub root_sha256: Option<String>,
    /// Where the root is downloaded (`GET /system/ca-root`, no sign-in needed).
    pub download_path: String,
}

/// Mode c: the reverse proxy that ends TLS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ReverseProxyTls {
    /// Addresses and networks (CIDR) of the proxies allowed to connect.
    pub trusted_proxies: Vec<String>,
    /// Whether the proxies speak the PROXY protocol.
    pub proxy_protocol: bool,
    /// The public host name clients use.
    pub public_host: String,
}

/// A certificate that is on disk but not served: the profile does not accept a
/// replacement while the listener runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PendingTlsCertificate {
    /// What the certificate in the files says.
    pub certificate: TlsCertificate,
    /// When the watcher first saw it.
    pub detected_at: Timestamp,
}

/// `GET /system/tls`: the certificates of this node's listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TlsDetails {
    /// The TLS mode.
    pub mode: TlsMode,
    /// Lowest TLS version accepted (`1.2` or `1.3`), when the listener terminates TLS.
    pub min_version: Option<String>,
    /// Whether HTTPS responses carry `Strict-Transport-Security`.
    pub hsts: bool,
    /// The certificate the listener serves (modes a and b).
    pub certificate: Option<TlsCertificate>,
    /// When the listener loaded the served certificate.
    pub loaded_at: Option<Timestamp>,
    /// The last failed load or reload; the previous certificate keeps serving.
    pub last_error: Option<String>,
    /// A newer certificate on disk that waits for the next start (mode b).
    pub pending: Option<PendingTlsCertificate>,
    /// Mode b: the files and the replacement setting.
    pub imported: Option<ImportedTls>,
    /// Mode a: the CA root.
    pub internal_ca: Option<InternalCaTls>,
    /// Mode c: the proxies and the public host name.
    pub reverse_proxy: Option<ReverseProxyTls>,
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

/// How serious a health finding is, as `GET /system/diagnostics` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    /// Nothing to act on: a state worth knowing when reading a report.
    Info,
    /// An administrator should look at it.
    Warning,
    /// A role or a service does not do its work.
    Error,
}

/// One active health finding of `GET /system/status`, reduced to what a bug report may
/// carry in public: the code and the severity, never the detail text or the parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DiagnosticFinding {
    /// The stable code of the warning, for example `dns.role.lagging`.
    pub code: String,
    /// How serious it is.
    pub severity: FindingSeverity,
}

/// `GET /system/diagnostics`: what a bug report needs about this node, redacted before it
/// leaves it. Every IP address, MAC address, host name, zone name and account name in the
/// log lines is a numbered placeholder from the documentation ranges and `example.test`,
/// the same placeholder for the same value within one document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SystemDiagnostics {
    /// The version this server runs as (what `GET /system/status` reports).
    pub version: String,
    /// The version of the API crate the binary was built from.
    pub api_version: String,
    /// The operating system family of the node (`linux`, `windows`, `macos`).
    pub os: String,
    /// The processor architecture (`x86_64`, `aarch64`).
    pub arch: String,
    /// The security profile of the installation (`home`, `standard`, `hardened`, `lab`).
    pub profile: String,
    /// The roles this node runs.
    pub roles: Vec<String>,
    /// The product modules this installation runs.
    pub modules: crate::modules::ModuleSet,
    /// Seconds since the API state was built.
    pub uptime_seconds: u64,
    /// The active health findings: code and severity only.
    pub findings: Vec<DiagnosticFinding>,
    /// The last lines of the node's own log at warn level or above, redacted; at most 20.
    pub log: Vec<String>,
    /// The whole document as text, the same for the UI, the CLI and the issue: what the
    /// fields above say, rendered line by line.
    pub text: String,
}
