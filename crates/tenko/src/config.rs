//! The server configuration file `tenko.toml`.
//!
//! The file carries only bootstrap settings: where the state lives, what to listen on, how
//! TLS is done, which key-encryption key provider protects the vault, and how to log.
//! Everything an administrator changes at run time (the security profile and its toggles,
//! users, IPAM data) lives in the replicated store after first-run setup.
//!
//! Every field has a default, so an empty file (or no file at all, with `--data-dir`) is a
//! valid configuration. `deploy/tenko.example.toml` documents every field.
//!
//! # Sources, in increasing precedence
//!
//! 1. The defaults of this module.
//! 2. The file given with `--config` (or `TENKO_CONFIG`).
//! 3. Environment variables with the `TENKO_` prefix, for containers: the rest of the name,
//!    lower-cased, is the key path, with a double underscore between a section and its key
//!    (`TENKO_DATA_DIR`, `TENKO_TLS__MODE=reverse_proxy`, `TENKO_LOG__LEVEL=debug`). A
//!    value is read as a TOML value when it parses as one (`true`, `8443`, `["a", "b"]`)
//!    and as a string otherwise; list fields also accept a comma-separated string
//!    (`TENKO_SERVER__LISTEN=0.0.0.0:8443,[::]:8443`). Variables whose first key is not a
//!    configuration key (`TENKO_CONFIG`, `TENKO_URL`, `TENKO_TOKEN`) are ignored here.
//! 4. The command-line flags `--data-dir` and `--roles`.
//!
//! [`load`] merges the sources; [`Config::resolve`] validates the result into the typed
//! [`Resolved`] settings that `tenko serve` uses. `tenko config check` prints the effective
//! configuration; it holds no secrets (the KEK file is named by its path only).

use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Deserializer, Serialize};
use tenko_api::{
    middleware::{Quota, RateLimitConfig},
    modules::ModuleSet,
    sse::SseConfig,
};
use tenko_auth::settings::Profile;
use tenko_cluster::ca::TrustedProxies;
use tenko_core::{NodeId, RoleSet, net::HostName};
use tenko_vault::kek::{CredsKey, DEFAULT_CREDENTIAL, DpapiScope, KekConfig, KekOptions};

/// Prefix of the environment variables that override configuration keys.
pub const ENV_PREFIX: &str = "TENKO_";

/// Separator between a section and its key in an environment variable name.
pub const ENV_SEPARATOR: &str = "__";

/// The default listen address of the API and UI.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8443";

/// The top-level keys of the file; environment variables are matched against them.
const TOP_LEVEL_KEYS: [&str; 23] = [
    "audit_export",
    "cluster",
    "scan",
    "telemetry",
    "metrics",
    "backup",
    "data_dir",
    "roles",
    "modules",
    "updates",
    "node",
    "profile",
    "server",
    "tls",
    "kek",
    "auth",
    "hibp",
    "sse",
    "rate_limit",
    "store",
    "jobs",
    "log",
    "runtime",
];

/// The whole configuration file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Directory that holds the state of this node: `kek/`, `store/`, `tls/`, `logs/`.
    /// Required here, with `--data-dir` or with `TENKO_DATA_DIR`. Must be on SSD or `NVMe`
    /// storage (OPS-19).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<PathBuf>,
    /// Roles of this node: a comma-separated list of `controller`, `dns`, `dhcp` and
    /// `probe`, or `all`. Phase 1 implements `controller` only.
    pub roles: String,
    /// The product modules this installation runs (OPS-25): a list of `ipam`, `dns`,
    /// `dhcp` and `discovery`, or `all`. Not set (the default): the choice made in the
    /// first-run wizard, else every module. When set, it pins the set and the wizard cannot
    /// change it. A disabled module registers no routes and starts nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modules: Option<ModuleSet>,
    /// Identity of this node in the cluster.
    pub node: NodeSection,
    /// The security profile used before first-run setup.
    pub profile: ProfileSection,
    /// The HTTP listener of the API and UI.
    pub server: ServerSection,
    /// TLS mode of the listener (OPS-22).
    pub tls: TlsSection,
    /// The key-encryption key provider of the vault.
    pub kek: KekSection,
    /// Authentication: the WebAuthn relying party.
    pub auth: AuthSection,
    /// The breached-password check (IAM-04, TGL-06).
    pub hibp: HibpSection,
    /// Server-sent events.
    pub sse: SseSection,
    /// Rate limits of the API.
    pub rate_limit: RateLimitSection,
    /// The replicated store.
    pub store: StoreSection,
    /// The job engine.
    pub jobs: JobsSection,
    /// The core runtime of the process.
    pub runtime: RuntimeSection,
    /// Logging.
    pub log: LogSection,
    /// In-app updates (OPS-24).
    pub updates: UpdatesSection,
    /// The node transport between controllers and data-plane nodes (OPS-04).
    pub cluster: ClusterSection,
    /// The scanner of the probe role (SCAN-01 to SCAN-09); read by the probe itself until
    /// the controller hands out scan configuration (WP3.1).
    pub scan: tenko_scan::config::ScanConfig,
    /// OpenTelemetry traces (OPS-05), off unless an endpoint is set.
    pub telemetry: TelemetrySection,
    /// The metrics collector and the optional loopback listener (OPS-05, OPS-21).
    pub metrics: MetricsSection,
    /// Where backups of this node are written (OPS-07).
    pub backup: BackupSection,
    /// Where file sinks of the audit export write on this node (IAM-18).
    pub audit_export: AuditExportSection,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: None,
            roles: "controller".to_owned(),
            node: NodeSection::default(),
            profile: ProfileSection::default(),
            server: ServerSection::default(),
            tls: TlsSection::default(),
            kek: KekSection::default(),
            auth: AuthSection::default(),
            hibp: HibpSection::default(),
            sse: SseSection::default(),
            rate_limit: RateLimitSection::default(),
            store: StoreSection::default(),
            jobs: JobsSection::default(),
            runtime: RuntimeSection::default(),
            log: LogSection::default(),
            modules: None,
            updates: UpdatesSection::default(),
            cluster: ClusterSection::default(),
            scan: tenko_scan::config::ScanConfig::default(),
            telemetry: TelemetrySection::default(),
            metrics: MetricsSection::default(),
            backup: BackupSection::default(),
            audit_export: AuditExportSection::default(),
        }
    }
}

/// `[node]`: identity of this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeSection {
    /// Raft node id (default 1). Slice 1 runs a single voter.
    pub id: u64,
    /// Address other nodes reach this node at; empty for a single node.
    pub address: String,
}

impl Default for NodeSection {
    fn default() -> Self {
        Self {
            id: 1,
            address: String::new(),
        }
    }
}

/// The default address of the cluster port on a controller.
pub const DEFAULT_CLUSTER_LISTEN: &str = "0.0.0.0:8444";

/// `[cluster]`: the node transport, gRPC over mutual TLS between controllers and
/// data-plane nodes (OPS-04, OPS-08, OPS-28).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterSection {
    /// Controller: socket addresses of the cluster port. Not set: `0.0.0.0:8444`, opened
    /// once a node is enrolled or an enrolment token is waiting. An empty list keeps the
    /// port closed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<Vec<String>>,
    /// Controller: `host:port` endpoints nodes are told at enrolment. Empty: the host name
    /// a node enrols through, with the port of the cluster port.
    pub advertise: Vec<String>,
    /// Controller: seconds between two heartbeats of a node (default 10).
    pub heartbeat_secs: u32,
    /// Controller: lifetime in seconds of an enrolment token whose request names none
    /// (default 3600, at most 604800).
    pub enrolment_ttl_secs: u64,
    /// Data-plane node: mebibytes the observation buffer keeps on disk while no controller
    /// is reachable; the oldest batches go first when it is full (default 64).
    pub buffer_mib: u64,
    /// Controller in a cluster: milliseconds without contact to a quorum after which this
    /// controller counts as isolated, refuses writes and serves reads from its local copy
    /// (OPS-26; default 3000, 500 to 60000).
    pub isolation_after_ms: u64,
    /// Controller in a cluster: seconds a start waits for the local store to catch up with
    /// the leader before the controller starts isolated (default 120, 5 to 3600).
    pub catch_up_timeout_secs: u64,
    /// Controller in a cluster: the leader promotes a caught-up learner to a voter on its
    /// own, and only to an odd number of voters (default true).
    pub auto_promote: bool,
    /// Controller in a cluster: a learner counts as caught up while it stays fewer than
    /// this many log entries behind the leader for 10 seconds (default 100, 1 to 1000000).
    pub promote_lag_entries: u64,
    /// Controller: the bandwidth cap per node configuration stream in kilobits per second;
    /// 0 is no cap (default 0, at most 10000000; OPS-28).
    pub sync_kbps: u64,
    /// Controller in a cluster: the address this controller dials instead of the cluster
    /// port a peer advertises, from the advertised `host:port` to the `host:port` to use
    /// (split-horizon setups and labs). Empty: every peer is dialled at the address of its
    /// member record.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_address_map: BTreeMap<String, String>,
}

impl Default for ClusterSection {
    fn default() -> Self {
        Self {
            listen: None,
            advertise: Vec::new(),
            heartbeat_secs: 10,
            enrolment_ttl_secs: 3600,
            buffer_mib: 64,
            isolation_after_ms: 3_000,
            catch_up_timeout_secs: 120,
            auto_promote: true,
            promote_lag_entries: 100,
            sync_kbps: 0,
            peer_address_map: BTreeMap::new(),
        }
    }
}

/// How the cluster port of a controller opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterListen {
    /// `listen` not set: the default address, once a node or a token exists.
    OnDemand(Vec<SocketAddr>),
    /// `listen` names addresses: always.
    Always(Vec<SocketAddr>),
    /// `listen = []`: never.
    Off,
}

impl ClusterSection {
    /// The listening mode.
    ///
    /// # Errors
    ///
    /// `config.invalid` for an address that is not an address with a port.
    pub fn listen_mode(&self) -> Result<ClusterListen, ConfigError> {
        let parse = |text: &str| {
            text.parse::<SocketAddr>().map_err(|_| {
                ConfigError::invalid(format!(
                    "cluster.listen: `{text}` is not an address with a port, such as 0.0.0.0:8444"
                ))
            })
        };
        match &self.listen {
            None => Ok(ClusterListen::OnDemand(vec![parse(
                DEFAULT_CLUSTER_LISTEN,
            )?])),
            Some(list) if list.is_empty() => Ok(ClusterListen::Off),
            Some(list) => Ok(ClusterListen::Always(
                list.iter()
                    .map(|text| parse(text))
                    .collect::<Result<_, _>>()?,
            )),
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.listen_mode()?;
        for endpoint in &self.advertise {
            if !is_host_port(endpoint) {
                return Err(ConfigError::invalid(format!(
                    "cluster.advertise: `{endpoint}` is not a host and port, such as ddi.example.net:8444"
                )));
            }
        }
        if !(1..=300).contains(&self.heartbeat_secs) {
            return Err(ConfigError::invalid(
                "cluster.heartbeat_secs must be between 1 and 300",
            ));
        }
        if !(60..=604_800).contains(&self.enrolment_ttl_secs) {
            return Err(ConfigError::invalid(
                "cluster.enrolment_ttl_secs must be between 60 and 604800",
            ));
        }
        if !(1..=4096).contains(&self.buffer_mib) {
            return Err(ConfigError::invalid(
                "cluster.buffer_mib must be between 1 and 4096",
            ));
        }
        if !(500..=60_000).contains(&self.isolation_after_ms) {
            return Err(ConfigError::invalid(
                "cluster.isolation_after_ms must be between 500 and 60000",
            ));
        }
        if !(5..=3_600).contains(&self.catch_up_timeout_secs) {
            return Err(ConfigError::invalid(
                "cluster.catch_up_timeout_secs must be between 5 and 3600",
            ));
        }
        if !(1..=1_000_000).contains(&self.promote_lag_entries) {
            return Err(ConfigError::invalid(
                "cluster.promote_lag_entries must be between 1 and 1000000",
            ));
        }
        if self.sync_kbps > 10_000_000 {
            return Err(ConfigError::invalid(
                "cluster.sync_kbps must be at most 10000000 (0 is no cap)",
            ));
        }
        for (advertised, dialled) in &self.peer_address_map {
            for endpoint in [advertised, dialled] {
                if !is_host_port(endpoint) {
                    return Err(ConfigError::invalid(format!(
                        "cluster.peer_address_map: `{endpoint}` is not a host and port, such as ddi.example.net:8444"
                    )));
                }
            }
            if advertised == dialled {
                return Err(ConfigError::invalid(format!(
                    "cluster.peer_address_map: `{advertised}` maps to itself"
                )));
            }
        }
        Ok(())
    }
}

/// Whether `endpoint` is a host and a port above 0, such as `ddi.example.net:8444`.
fn is_host_port(endpoint: &str) -> bool {
    endpoint.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty() && port.parse::<u16>().is_ok_and(|port| port > 0)
    })
}

/// `[telemetry]`: OpenTelemetry traces exported over OTLP (OPS-05, owner decision S3-Q7).
/// Off by default: no endpoint, no traces, no exporter task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetrySection {
    /// The OTLP endpoint traces go to, `http://` or `https://` with host and port, such as
    /// `http://127.0.0.1:4317`. Not set (the default): traces are off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otlp_endpoint: Option<String>,
    /// The share of traces exported, from 0.0 to 1.0 (default 1.0: every trace while an
    /// endpoint is set).
    pub sampling_ratio: f64,
}

impl Default for TelemetrySection {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            sampling_ratio: 1.0,
        }
    }
}

impl TelemetrySection {
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(endpoint) = &self.otlp_endpoint {
            let rest = endpoint
                .strip_prefix("https://")
                .or_else(|| endpoint.strip_prefix("http://"));
            let host = rest.map(|rest| rest.split('/').next().unwrap_or_default());
            if !host.is_some_and(|host| !host.is_empty() && !host.starts_with(':')) {
                return Err(ConfigError::invalid(format!(
                    "telemetry.otlp_endpoint: `{endpoint}` is not an http(s) URL with a host, \
                     such as http://127.0.0.1:4317"
                )));
            }
        }
        if !self.sampling_ratio.is_finite() || !(0.0..=1.0).contains(&self.sampling_ratio) {
            return Err(ConfigError::invalid(
                "telemetry.sampling_ratio must be between 0.0 and 1.0",
            ));
        }
        Ok(())
    }
}

/// `[metrics]`: the metrics collector (OPS-05, OPS-21). The API serves
/// `GET /api/v1/metrics` to a token with the `metrics` scope (owner decision S3-Q7); the
/// optional listener serves the same text without authentication, on loopback only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsSection {
    /// A loopback address and port for an unauthenticated metrics listener, such as
    /// `127.0.0.1:9464`. Not set (the default): no such listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// Seconds between two computations of the gauges read from status interfaces (store
    /// size, jobs by state, buffers; default 30, 5 to 3600).
    pub gauge_interval_secs: u64,
}

impl Default for MetricsSection {
    fn default() -> Self {
        Self {
            listen: None,
            gauge_interval_secs: 30,
        }
    }
}

impl MetricsSection {
    /// The address of the loopback listener, if one is configured.
    ///
    /// # Errors
    ///
    /// `config.invalid` for a value that is not an address with a port, or not a loopback
    /// address.
    pub fn listen_addr(&self) -> Result<Option<SocketAddr>, ConfigError> {
        let Some(text) = &self.listen else {
            return Ok(None);
        };
        let addr: SocketAddr = text.parse().map_err(|_| {
            ConfigError::invalid(format!(
                "metrics.listen: `{text}` is not an address with a port, such as 127.0.0.1:9464"
            ))
        })?;
        if !addr.ip().is_loopback() {
            return Err(ConfigError::invalid(format!(
                "metrics.listen: `{text}` is not a loopback address; the listener has no \
                 authentication, so it binds 127.0.0.1 or [::1] only"
            )));
        }
        Ok(Some(addr))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.listen_addr()?;
        if !(5..=3_600).contains(&self.gauge_interval_secs) {
            return Err(ConfigError::invalid(
                "metrics.gauge_interval_secs must be between 5 and 3600",
            ));
        }
        Ok(())
    }
}

/// `[backup]`: where this node writes backups (OPS-07, owner decision S3-Q11). The
/// schedule and the number of backups kept are settings in the store, the same on every
/// controller; the directory belongs to the host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupSection {
    /// An absolute directory for backup files. Not set (the default): `backups/` in the data
    /// directory. Prefer another disk: a backup next to the data it protects does not survive
    /// the loss of that disk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_dir: Option<PathBuf>,
}

impl BackupSection {
    fn validate(&self) -> Result<(), ConfigError> {
        match &self.target_dir {
            Some(dir) if dir.as_os_str().is_empty() => {
                Err(ConfigError::invalid("backup.target_dir is empty"))
            }
            Some(dir) if !dir.is_absolute() => Err(ConfigError::invalid(format!(
                "backup.target_dir: `{}` is not an absolute path",
                dir.display()
            ))),
            _ => Ok(()),
        }
    }
}

/// `[audit_export]`: the directory of the audit export's file sinks on this node (IAM-18,
/// S3-Q6). The sinks themselves are settings in the store, the same on every controller; a
/// file sink names a file inside this directory and writes on the controller that leads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditExportSection {
    /// An absolute directory for the files of file sinks. Not set (the default):
    /// `audit-export/` in the data directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_dir: Option<PathBuf>,
}

impl AuditExportSection {
    fn validate(&self) -> Result<(), ConfigError> {
        match &self.file_dir {
            Some(dir) if dir.as_os_str().is_empty() => {
                Err(ConfigError::invalid("audit_export.file_dir is empty"))
            }
            Some(dir) if !dir.is_absolute() => Err(ConfigError::invalid(format!(
                "audit_export.file_dir: `{}` is not an absolute path",
                dir.display()
            ))),
            _ => Ok(()),
        }
    }
}

/// `[profile]`: the bootstrap security profile.
///
/// Before first-run setup it governs the listener: `hardened` serves TLS 1.3 only and `lab`
/// allows `tls.mode = "plain"` (TGL-08). The first-run wizard then stores the chosen
/// profile and every toggle override in the store; from then on the stored profile wins
/// and this value is ignored (with a notice in the log when they differ).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileSection {
    /// `home` (default), `standard`, `hardened` or `lab`.
    pub name: Profile,
}

impl Default for ProfileSection {
    fn default() -> Self {
        Self {
            name: Profile::Home,
        }
    }
}

/// `[server]`: the HTTP listener of the API and UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSection {
    /// Socket addresses to listen on (default `0.0.0.0:8443`).
    #[serde(deserialize_with = "string_or_list")]
    pub listen: Vec<String>,
    /// Worker threads of the API runtime, 1 to 16 (default 2, ADR 0008).
    pub workers: usize,
    /// Most open connections (default 20,000).
    pub max_connections: usize,
    /// Seconds open connections may finish after shutdown starts (default 10).
    pub shutdown_grace_secs: u64,
    /// Seconds allowed for the TLS handshake and the PROXY protocol header (default 10).
    pub handshake_timeout_secs: u64,
    /// Seconds allowed for reading an HTTP/1.1 request head (default 30).
    pub header_read_timeout_secs: u64,
    /// Origins the CSRF guard accepts besides the request's own, for example
    /// `http://localhost:5173` for `vite dev`.
    #[serde(deserialize_with = "string_or_list")]
    pub allowed_origins: Vec<String>,
    /// Serve the UI from this directory instead of the embedded copy (debug builds only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_dir: Option<PathBuf>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen: vec![DEFAULT_LISTEN.to_owned()],
            workers: 2,
            max_connections: 20_000,
            shutdown_grace_secs: 10,
            handshake_timeout_secs: 10,
            header_read_timeout_secs: 30,
            allowed_origins: Vec::new(),
            ui_dir: None,
        }
    }
}

/// The three TLS modes of OPS-22, and plain HTTP for the Lab profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsModeName {
    /// (a) A server certificate from the internal CA (default).
    #[default]
    InternalCa,
    /// (b) An imported certificate and key, reloaded when the files change.
    Imported,
    /// (c) TLS terminates in a reverse proxy in front of Tenko.
    ReverseProxy,
    /// Plain HTTP from any source: the Lab profile only (TGL-08).
    Plain,
}

impl TlsModeName {
    /// The `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InternalCa => "internal_ca",
            Self::Imported => "imported",
            Self::ReverseProxy => "reverse_proxy",
            Self::Plain => "plain",
        }
    }
}

/// `[tls]`: the TLS mode of the listener (OPS-22).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsSection {
    /// `internal_ca` (default), `imported`, `reverse_proxy` or `plain` (Lab only).
    pub mode: TlsModeName,
    /// Mode a: the host name of the server certificate until first-run setup stores one
    /// (default `localhost`); afterwards the installation's host name is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    /// Mode a: further DNS names on the server certificate.
    #[serde(deserialize_with = "string_or_list")]
    pub alt_names: Vec<String>,
    /// Mode a: IP addresses on the server certificate.
    #[serde(deserialize_with = "string_or_list")]
    pub addresses: Vec<String>,
    /// Mode b: PEM file with the leaf certificate first, then intermediates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<PathBuf>,
    /// Mode b: PEM file with the private key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<PathBuf>,
    /// Mode b: seconds between checks of the files for changes (default 5).
    pub watch_interval_secs: u64,
    /// Mode c: addresses or networks of the reverse proxies; every other source is refused.
    #[serde(deserialize_with = "string_or_list")]
    pub trusted_proxies: Vec<String>,
    /// Mode c: the proxies send the PROXY protocol (v1 or v2) instead of forwarded headers.
    pub proxy_protocol: bool,
    /// Mode c: the public host name clients use (the WebAuthn relying-party ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_host: Option<String>,
    /// Refuse TLS 1.2 (always on under the Hardened profile).
    pub tls13_only: bool,
    /// Send `Strict-Transport-Security` on HTTPS answers (default on, TGL-08).
    pub hsts: bool,
    /// Mode a: hours between checks whether the server certificate needs renewal
    /// (default 24).
    pub renew_check_hours: u64,
}

impl Default for TlsSection {
    fn default() -> Self {
        Self {
            mode: TlsModeName::InternalCa,
            host_name: None,
            alt_names: Vec::new(),
            addresses: Vec::new(),
            cert_path: None,
            key_path: None,
            watch_interval_secs: 5,
            trusted_proxies: Vec::new(),
            proxy_protocol: false,
            public_host: None,
            tls13_only: false,
            hsts: true,
            renew_check_hours: 24,
        }
    }
}

/// Which KEK provider protects the vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KekProviderName {
    /// DPAPI on Windows, `systemd-creds` on Linux (default).
    #[default]
    Platform,
    /// DPAPI-sealed key generations (Windows only).
    Dpapi,
    /// `systemd-creds`-sealed key generations (Linux).
    SystemdCreds,
    /// A credential the service manager decrypts from `LoadCredentialEncrypted=` (Linux).
    SystemdCredential,
    /// An explicit key file (containers, CI); warns at every start.
    File,
}

/// `[kek]`: the key-encryption key provider of the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KekSection {
    /// `platform` (default), `dpapi`, `systemd_creds`, `systemd_credential` or `file`.
    pub provider: KekProviderName,
    /// Directory of the key generations (default `<data_dir>/kek`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<PathBuf>,
    /// DPAPI: `user` (default, bound to the service account) or `machine`.
    pub scope: DpapiScope,
    /// `systemd-creds`: `auto` (default), `tpm2` or `host`; `systemd_credential`: the key the
    /// credential was encrypted with, as the operator declares it.
    pub with_key: CredsKey,
    /// `systemd-creds`: path of the tool (default: found on `PATH`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<PathBuf>,
    /// `file`: the active key file (32 raw bytes, 64 hexadecimal digits or base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// `systemd_credential`: the credential name, as in `LoadCredentialEncrypted=<name>:…`
    /// (default `tenko_kek`).
    pub credential: String,
    /// `file`: earlier key files, `systemd_credential`: earlier credential names, still
    /// needed until a rotation completes.
    #[serde(deserialize_with = "paths_or_list")]
    pub retired: Vec<PathBuf>,
    /// Load, create and import plain key generations even beside a sealed one (R15). Off by
    /// default: such a generation is refused and an alarm is raised.
    pub allow_plain: bool,
}

impl Default for KekSection {
    fn default() -> Self {
        Self {
            provider: KekProviderName::Platform,
            dir: None,
            scope: DpapiScope::User,
            with_key: CredsKey::Auto,
            tool: None,
            path: None,
            credential: DEFAULT_CREDENTIAL.to_owned(),
            retired: Vec::new(),
            allow_plain: false,
        }
    }
}

/// `[auth]`: the WebAuthn relying party.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthSection {
    /// The relying-party ID; default: the public host in mode c, otherwise the host name
    /// from first-run setup. `localhost` for development.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    /// Origins the UI is served from; default `https://<rp id>`.
    #[serde(deserialize_with = "string_or_list")]
    pub origins: Vec<String>,
    /// The name browsers show for the relying party.
    pub rp_name: String,
    /// DER or PEM files with attestation roots of accepted hardware keys (ADR 0010).
    #[serde(deserialize_with = "paths_or_list")]
    pub attestation_roots: Vec<PathBuf>,
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            rp_id: None,
            origins: Vec::new(),
            rp_name: "Tenko DDI".to_owned(),
            attestation_roots: Vec::new(),
        }
    }
}

/// `[hibp]`: sources of the breached-password check. Whether the check runs, and which
/// source it prefers, is the TGL-06 setting of the stored profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HibpSection {
    /// Allow the online range API (k-anonymity: only five hexadecimal characters of the
    /// SHA-1 leave the host). Default on.
    pub online: bool,
    /// A mirror of the range API (default the public service).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range_url: Option<String>,
    /// The offline filter built with `tenko hibp build`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_filter: Option<PathBuf>,
}

impl Default for HibpSection {
    fn default() -> Self {
        Self {
            online: true,
            range_url: None,
            offline_filter: None,
        }
    }
}

/// `[sse]`: server-sent events (ADR 0008).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SseSection {
    /// Events a subscriber may fall behind before it gets `reset` (default 1,024).
    pub channel_capacity: usize,
    /// Frames kept in memory for `Last-Event-ID` replay (default 256).
    pub ring_capacity: usize,
    /// Seconds between keep-alive comments (default 15).
    pub keepalive_secs: u64,
    /// Coalescing window in milliseconds; 0 (default) sends every event at once.
    pub coalesce_ms: u64,
    /// Most journal change sets replayed for one reconnecting subscriber (default 10,000).
    pub journal_replay_limit: usize,
    /// Seconds clients wait before reconnecting (default 3).
    pub retry_secs: u64,
    /// Most object references in one event (default 500).
    pub max_objects_per_event: usize,
}

impl Default for SseSection {
    fn default() -> Self {
        let defaults = SseConfig::default();
        Self {
            channel_capacity: defaults.channel_capacity,
            ring_capacity: defaults.ring_capacity,
            keepalive_secs: defaults.keepalive.as_secs(),
            coalesce_ms: defaults
                .coalesce
                .map_or(0, |window| u64::try_from(window.as_millis()).unwrap_or(0)),
            journal_replay_limit: defaults.journal_replay_limit,
            retry_secs: defaults.retry.as_secs(),
            max_objects_per_event: defaults.max_objects_per_event,
        }
    }
}

/// A token bucket: sustained rate and burst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaSection {
    /// Requests per second, sustained.
    pub per_second: u32,
    /// Requests at once.
    pub burst: u32,
}

impl From<Quota> for QuotaSection {
    fn from(quota: Quota) -> Self {
        Self {
            per_second: quota.per_second,
            burst: quota.burst,
        }
    }
}

/// `[rate_limit]`: request rate limits of the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitSection {
    /// Master switch (default on).
    pub enabled: bool,
    /// IPv6 clients are grouped by this many leading bits (default 64).
    pub ipv6_prefix_len: u8,
    /// Most keys tracked per limiter (default 100,000).
    pub max_keys: usize,
    /// Quota per client address, before authentication (default 20/s, burst 100). Leave
    /// out to switch it off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per_ip: Option<QuotaSection>,
    /// Quota per principal (default 50/s, burst 200). Leave out to switch it off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per_principal: Option<QuotaSection>,
}

impl Default for RateLimitSection {
    fn default() -> Self {
        let defaults = RateLimitConfig::default();
        Self {
            enabled: defaults.enabled,
            ipv6_prefix_len: defaults.ipv6_prefix_len,
            max_keys: defaults.max_keys,
            per_ip: defaults.per_ip.map(QuotaSection::from),
            per_principal: defaults.per_principal.map(QuotaSection::from),
        }
    }
}

impl RateLimitSection {
    /// The limiter settings of the API.
    pub fn to_config(&self) -> RateLimitConfig {
        let quota = |section: QuotaSection| Quota {
            per_second: section.per_second,
            burst: section.burst,
        };
        RateLimitConfig {
            enabled: self.enabled,
            per_ip: self.per_ip.map(quota),
            per_principal: self.per_principal.map(quota),
            ipv6_prefix_len: self.ipv6_prefix_len,
            max_keys: self.max_keys,
        }
    }
}

/// When the state machine makes its commits durable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityName {
    /// Durable checkpoints every `checkpoint_interval_ms` (default); the Raft log is
    /// fsynced before every commit either way.
    #[default]
    Deferred,
    /// Every apply is fsynced.
    Immediate,
}

/// `[store]`: the replicated store (openraft over redb, ADR 0002).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StoreSection {
    /// Page cache of `log.redb` in MiB (default 4, OPS-15).
    pub log_cache_mib: usize,
    /// Page cache of `sm.redb` in MiB (default 32, OPS-15).
    pub sm_cache_mib: usize,
    /// `deferred` (default) or `immediate`.
    pub durability: DurabilityName,
    /// Milliseconds between durable checkpoints under `deferred` (default 1,000).
    pub checkpoint_interval_ms: u64,
    /// Change sets kept for event replay (default 100,000).
    pub journal_retention: usize,
    /// Snapshot after this many entries (default 10,000).
    pub snapshot_every_entries: u64,
    /// Snapshot after this many MiB of log (default 64).
    pub snapshot_every_log_mib: u64,
    /// Log entries kept behind a snapshot (default 1,000).
    pub snapshot_keep_entries: u64,
    /// Seconds a write waits to be applied (default 60).
    pub write_timeout_secs: u64,
    /// Seconds a consistent read waits (default 5).
    pub read_wait_secs: u64,
    /// Durable commits measured by the start-up fsync probe (default 20; 0 disables it).
    pub fsync_probe_samples: usize,
    /// Verify every audit record at start instead of the chain head (default off).
    pub verify_full_audit_chain: bool,
    /// MiB of change sets kept for event replay at most (default 32).
    pub journal_max_mib: u64,
    /// Hours between maintenance checks of the state file (default 24).
    pub maintenance_interval_hours: u64,
    /// Re-seed the state file when it is larger than this percentage of the live data at
    /// start (default 200, ADR 0002); while running the threshold is twice as high, because
    /// redb keeps growth slack.
    pub reseed_ratio_percent: u32,
    /// State files below this many MiB are never re-seeded (default 64).
    pub reseed_min_mib: u64,
}

impl Default for StoreSection {
    fn default() -> Self {
        Self {
            log_cache_mib: 4,
            sm_cache_mib: 32,
            durability: DurabilityName::Deferred,
            checkpoint_interval_ms: 1_000,
            journal_retention: 100_000,
            snapshot_every_entries: 10_000,
            snapshot_every_log_mib: 64,
            snapshot_keep_entries: 1_000,
            write_timeout_secs: 60,
            read_wait_secs: 5,
            fsync_probe_samples: 20,
            verify_full_audit_chain: false,
            journal_max_mib: 32,
            maintenance_interval_hours: 24,
            reseed_ratio_percent: 200,
            reseed_min_mib: 64,
        }
    }
}

/// `[jobs]`: the job engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JobsSection {
    /// Jobs driven at once (default 16).
    pub workers: usize,
    /// Started jobs per group at once (default 10, CONN-09).
    pub default_group_limit: usize,
    /// Seconds a runner lease lasts without renewal (default 30).
    pub lease_ttl_secs: u64,
    /// Seconds between scans for jobs of other runners (default 15).
    pub scan_interval_secs: u64,
}

impl Default for JobsSection {
    fn default() -> Self {
        Self {
            workers: 16,
            default_group_limit: 10,
            lease_ttl_secs: 30,
            scan_interval_secs: 15,
        }
    }
}

/// `[runtime]`: the core runtime (store, authentication, jobs). The API has its own
/// runtime (`server.workers`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeSection {
    /// Worker threads of the core runtime, 1 to 64 (default 2).
    pub workers: usize,
}

impl Default for RuntimeSection {
    fn default() -> Self {
        Self { workers: 2 }
    }
}

/// Log line format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// Human-readable lines (default).
    #[default]
    Text,
    /// One JSON object per line.
    Json,
}

/// `[log]`: logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogSection {
    /// Level or filter directive, for example `info` (default) or
    /// `info,tenko_store=debug`. `RUST_LOG` takes precedence when set.
    pub level: String,
    /// `text` (default) or `json`.
    pub format: LogFormat,
    /// Also append the log to this file. Under the Windows Service Control Manager the log
    /// goes to `<data_dir>/logs/tenko.log` when this is not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    /// The size in MiB at which the log file is rotated: `tenko.log` becomes `tenko.log.1`,
    /// `tenko.log.1` becomes `tenko.log.2` and so on (default 64; 0: never rotate).
    pub max_file_mb: u64,
    /// Rotated files kept besides the active one, 1 to 100 (default 5).
    pub keep_files: u32,
    /// The Windows service also writes events at or above this level to the Application
    /// Event Log under the service name (OPS-10): `error`, `warn` (default), `info`,
    /// `debug`, `trace` or `off`. The start and stop of the service are always written.
    /// Ignored outside the Windows service.
    pub event_log: EventLogLevel,
}

impl Default for LogSection {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            format: LogFormat::Text,
            file: None,
            max_file_mb: 64,
            keep_files: 5,
            event_log: EventLogLevel::Warn,
        }
    }
}

/// The level of the Windows Event Log sink.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventLogLevel {
    /// Nothing but the start and stop of the service.
    Off,
    /// Errors.
    Error,
    /// Warnings and errors (default).
    #[default]
    Warn,
    /// Informational events and above.
    Info,
    /// Debug events and above.
    Debug,
    /// Everything.
    Trace,
}

/// The release manifest the update check reads by default: the project's releases.
pub const DEFAULT_UPDATE_SOURCE: &str =
    "https://github.com/linkztream/tenko/releases/latest/download/releases.json";

/// `[updates]`: in-app updates (OPS-24). Whether the check runs and how a new version may be
/// installed is TGL-23 of the stored security settings; this section names the source and
/// the deployment facts the server cannot know by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdatesSection {
    /// The release manifest (`releases.json`). Release files are downloaded only from the
    /// same scheme and host (the pinned source, R17). Default: the project's releases.
    pub source_url: String,
    /// Never contact the release source: no check, no download. New versions are installed
    /// from an uploaded manifest and release file. Default off.
    pub air_gapped: bool,
    /// Hours between two checks (default 24).
    pub check_interval_hours: u64,
    /// Offer pre-release versions (default off).
    pub prereleases: bool,
    /// Seconds a newly installed version has to become ready before the previous version
    /// is switched back in (default 180).
    pub ready_timeout_secs: u64,
    /// Versions kept in `<data_dir>/updates` besides the ones `current` and `previous`
    /// point at (default 2).
    pub keep_versions: usize,
    /// The server runs in a container: updates come as a new image, never from the UI. The
    /// image sets it (`TENKO_UPDATES__CONTAINER=true`); `/.dockerenv` and
    /// `/run/.containerenv` are recognized as well.
    pub container: bool,
    /// The image the pull command names for containers (default
    /// `ghcr.io/linkztream/tenko`).
    pub image: String,
}

impl Default for UpdatesSection {
    fn default() -> Self {
        Self {
            source_url: DEFAULT_UPDATE_SOURCE.to_owned(),
            air_gapped: false,
            check_interval_hours: 24,
            prereleases: false,
            ready_timeout_secs: 180,
            keep_versions: 2,
            container: false,
            image: "ghcr.io/linkztream/tenko".to_owned(),
        }
    }
}

impl UpdatesSection {
    fn validate(&self) -> Result<(), ConfigError> {
        let url = self.source_url.trim();
        let loopback = ["http://localhost", "http://127.0.0.1", "http://[::1]"]
            .iter()
            .any(|prefix| {
                url.strip_prefix(prefix)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
            });
        if !(url.starts_with("https://") || loopback) {
            return Err(ConfigError::invalid(
                "updates.source_url must be an https URL (plain http only on the loopback \
                 host, for tests)",
            ));
        }
        if url.chars().any(char::is_whitespace) {
            return Err(ConfigError::invalid(
                "updates.source_url must not contain whitespace",
            ));
        }
        if !(1..=720).contains(&self.check_interval_hours) {
            return Err(ConfigError::invalid(
                "updates.check_interval_hours must be between 1 and 720",
            ));
        }
        if !(30..=3_600).contains(&self.ready_timeout_secs) {
            return Err(ConfigError::invalid(
                "updates.ready_timeout_secs must be between 30 and 3600",
            ));
        }
        if !(1..=10).contains(&self.keep_versions) {
            return Err(ConfigError::invalid(
                "updates.keep_versions must be between 1 and 10",
            ));
        }
        if self.image.trim().is_empty() || self.image.chars().any(char::is_whitespace) {
            return Err(ConfigError::invalid(
                "updates.image must be an image name without whitespace",
            ));
        }
        Ok(())
    }

    /// Whether the server runs in a container: the setting, or the marker files of Docker
    /// and Podman.
    pub fn in_container(&self) -> bool {
        self.container
            || (cfg!(target_os = "linux")
                && (Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists()))
    }
}

/// Deserializes a list from a list or from one comma-separated string (environment
/// variables).
fn string_or_list<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(text) => text
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect(),
        OneOrMany::Many(list) => list,
    })
}

/// [`string_or_list`] for paths.
fn paths_or_list<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<PathBuf>, D::Error> {
    string_or_list(deserializer).map(|list| list.into_iter().map(PathBuf::from).collect())
}

/// Why a configuration is unusable. The code is stable; the message is English.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// Stable code: `config.read`, `config.parse`, `config.env` or `config.invalid`.
    pub code: &'static str,
    /// What is wrong, naming the key.
    pub message: String,
}

impl ConfigError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: "config.invalid",
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ConfigError {}

/// Where the configuration comes from.
#[derive(Debug, Clone, Default)]
pub struct Sources {
    /// The file (`--config`).
    pub file: Option<PathBuf>,
    /// `--data-dir`.
    pub data_dir: Option<PathBuf>,
    /// `--roles`.
    pub roles: Option<String>,
}

/// A merged configuration and where its values came from.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The merged configuration.
    pub config: Config,
    /// The file that was read, if any.
    pub file: Option<PathBuf>,
    /// Environment variables that overrode keys, by name.
    pub env_overrides: Vec<String>,
}

/// Reads the file, applies the environment and the flags.
///
/// # Errors
///
/// `config.read` if the file cannot be read, `config.parse` for a syntax error or an
/// unknown key, `config.env` for an environment variable that does not fit its key.
pub fn load(
    sources: &Sources,
    env: impl IntoIterator<Item = (String, String)>,
) -> Result<Loaded, ConfigError> {
    let text = match &sources.file {
        Some(path) => std::fs::read_to_string(path).map_err(|error| ConfigError {
            code: "config.read",
            message: format!("cannot read {}: {error}", path.display()),
        })?,
        None => String::new(),
    };
    let origin = sources.file.as_ref().map_or_else(
        || "(defaults)".to_owned(),
        |path| path.display().to_string(),
    );
    let mut table: toml::Table = toml::from_str(&text).map_err(|error| ConfigError {
        code: "config.parse",
        message: format!("{origin}: {error}"),
    })?;
    let env_overrides = apply_env(&mut table, env)?;
    let mut config: Config = if env_overrides.is_empty() {
        // Parsing the text again keeps line numbers in the messages.
        toml::from_str(&text)
    } else {
        table.try_into()
    }
    .map_err(|error| ConfigError {
        code: if env_overrides.is_empty() {
            "config.parse"
        } else {
            "config.env"
        },
        message: format!("{origin}: {error}"),
    })?;
    if let Some(dir) = &sources.data_dir {
        config.data_dir = Some(dir.clone());
    }
    if let Some(roles) = &sources.roles {
        config.roles.clone_from(roles);
    }
    Ok(Loaded {
        config,
        file: sources.file.clone(),
        env_overrides,
    })
}

/// Applies `TENKO_*` variables to the parsed file and returns the names it used.
///
/// # Errors
///
/// `config.env` when a variable names a key below a value that is not a table.
pub fn apply_env(
    table: &mut toml::Table,
    env: impl IntoIterator<Item = (String, String)>,
) -> Result<Vec<String>, ConfigError> {
    let mut applied = Vec::new();
    let mut vars: Vec<(String, String)> = env
        .into_iter()
        .filter(|(name, _)| name.starts_with(ENV_PREFIX))
        .collect();
    vars.sort();
    for (name, raw) in vars {
        let path: Vec<String> = name[ENV_PREFIX.len()..]
            .split(ENV_SEPARATOR)
            .map(str::to_ascii_lowercase)
            .collect();
        let Some((last, sections)) = path.split_last() else {
            continue;
        };
        let first = path.first().map_or("", String::as_str);
        if !TOP_LEVEL_KEYS.contains(&first) || last.is_empty() {
            continue;
        }
        let mut current = &mut *table;
        for section in sections {
            let entry = current
                .entry(section.clone())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            current = match entry {
                toml::Value::Table(inner) => inner,
                _ => {
                    return Err(ConfigError {
                        code: "config.env",
                        message: format!("{name}: `{section}` is not a section"),
                    });
                }
            };
        }
        current.insert(last.clone(), env_value(&raw));
        applied.push(name);
    }
    Ok(applied)
}

/// An environment value as TOML when it parses as a value, else as a string.
fn env_value(raw: &str) -> toml::Value {
    let trimmed = raw.trim();
    toml::from_str::<toml::Table>(&format!("v = {trimmed}"))
        .ok()
        .and_then(|mut parsed| parsed.remove("v"))
        .unwrap_or_else(|| toml::Value::String(raw.to_owned()))
}

/// The TLS mode with its validated settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsSpec {
    /// (a) The internal CA.
    InternalCa {
        /// Certificate name until setup stores a host name.
        host_name: String,
        /// Further DNS names.
        alt_names: Vec<String>,
        /// IP addresses.
        addresses: Vec<IpAddr>,
    },
    /// (b) Imported files.
    Imported {
        /// Certificate chain PEM.
        cert_path: PathBuf,
        /// Key PEM.
        key_path: PathBuf,
    },
    /// (c) Reverse proxy.
    ReverseProxy {
        /// Trusted peers.
        trusted_proxies: TrustedProxies,
        /// PROXY protocol instead of forwarded headers.
        proxy_protocol: bool,
        /// Public host name.
        public_host: String,
    },
    /// Plain HTTP (Lab).
    Plain,
}

/// The validated settings `tenko serve` runs with.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The merged configuration they came from.
    pub config: Config,
    /// Absolute data directory.
    pub data_dir: PathBuf,
    /// Roles.
    pub roles: RoleSet,
    /// Node id.
    pub node_id: NodeId,
    /// Listen addresses.
    pub listen: Vec<SocketAddr>,
    /// The TLS mode.
    pub tls: TlsSpec,
    /// The KEK provider.
    pub kek: KekConfig,
    /// The policy of the key generations: `[kek] allow_plain` and the generation directory.
    pub kek_options: KekOptions,
}

/// The layout of a data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataLayout {
    /// The data directory.
    pub root: PathBuf,
}

impl DataLayout {
    /// The store files (`log.redb`, `sm.redb`, `snapshots/`).
    pub fn store(&self) -> PathBuf {
        self.root.join("store")
    }

    /// The default KEK directory.
    pub fn kek(&self) -> PathBuf {
        self.root.join("kek")
    }

    /// Public TLS files: the internal CA root for admin clients.
    pub fn tls(&self) -> PathBuf {
        self.root.join("tls")
    }

    /// The internal CA root certificate (public).
    pub fn ca_root(&self) -> PathBuf {
        self.tls().join("ca-root.pem")
    }

    /// Staged import uploads (encrypted under a key that lives in memory only).
    pub fn imports(&self) -> PathBuf {
        self.root.join("imports")
    }

    /// Log files of the service.
    pub fn logs(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// The default directory of backup files (`[backup] target_dir` overrides it).
    pub fn backups(&self) -> PathBuf {
        self.root.join("backups")
    }

    /// The default directory of the audit export's file sinks (`[audit_export] file_dir`
    /// overrides it).
    pub fn audit_export(&self) -> PathBuf {
        self.root.join("audit-export")
    }

    /// The one-time setup token of a first start, readable by the service account only,
    /// while first-run setup is open (`tenko setup token` prints it).
    pub fn setup_token(&self) -> PathBuf {
        self.root.join("setup-token")
    }

    /// The identity of this node in the cluster: the node key and certificate of a
    /// controller or a data-plane node (Slice 3 moves a controller's identity here).
    pub fn node(&self) -> PathBuf {
        self.root.join("node")
    }

    /// Whether the store was never created here: the first start.
    pub fn is_fresh(&self) -> bool {
        !self.store().join("log.redb").exists()
    }
}

impl Resolved {
    /// The data directory layout.
    pub fn layout(&self) -> DataLayout {
        DataLayout {
            root: self.data_dir.clone(),
        }
    }

    /// Where backups are written: `[backup] target_dir`, else `backups/` in the data
    /// directory.
    pub fn backup_dir(&self) -> PathBuf {
        self.config
            .backup
            .target_dir
            .clone()
            .unwrap_or_else(|| self.layout().backups())
    }

    /// Where the audit export's file sinks write: `[audit_export] file_dir`, else
    /// `audit-export/` in the data directory.
    pub fn audit_export_dir(&self) -> PathBuf {
        self.config
            .audit_export
            .file_dir
            .clone()
            .unwrap_or_else(|| self.layout().audit_export())
    }
}

impl Config {
    /// Validates the configuration into [`Resolved`] settings.
    ///
    /// # Errors
    ///
    /// `config.invalid` naming the first offending key.
    pub fn resolve(&self) -> Result<Resolved, ConfigError> {
        let data_dir = self.data_dir.as_ref().ok_or_else(|| {
            ConfigError::invalid(
                "data_dir is not set: give it in the file, with --data-dir or with TENKO_DATA_DIR",
            )
        })?;
        if data_dir.as_os_str().is_empty() {
            return Err(ConfigError::invalid("data_dir is empty"));
        }
        let data_dir = std::path::absolute(data_dir)
            .map_err(|error| ConfigError::invalid(format!("data_dir: {error}")))?;
        let roles: RoleSet = self
            .roles
            .parse()
            .map_err(|error| ConfigError::invalid(format!("roles: {error}")))?;
        if self.node.id == 0 {
            return Err(ConfigError::invalid("node.id must be at least 1"));
        }
        let listen = self.server.listen_addrs()?;
        self.server.validate()?;
        let tls = self.tls.resolve(self.profile.name)?;
        let (kek, kek_options) = self.kek.resolve(&data_dir)?;
        self.rate_limit
            .to_config()
            .validate()
            .map_err(|error| ConfigError::invalid(format!("rate_limit: {error}")))?;
        self.store.validate()?;
        self.jobs.validate()?;
        if !(1..=64).contains(&self.runtime.workers) {
            return Err(ConfigError::invalid(
                "runtime.workers must be between 1 and 64",
            ));
        }
        self.log.validate()?;
        self.updates.validate()?;
        self.cluster.validate()?;
        self.telemetry.validate()?;
        self.metrics.validate()?;
        self.backup.validate()?;
        self.audit_export.validate()?;
        self.scan
            .validate()
            .map_err(|error| ConfigError::invalid(error.detail().to_owned()))?;
        if let Some(url) = &self.hibp.range_url
            && !(url.starts_with("https://") || url.starts_with("http://"))
        {
            return Err(ConfigError::invalid(
                "hibp.range_url must be an http(s) URL",
            ));
        }
        if let Some(rp_id) = &self.auth.rp_id {
            checked_host("auth.rp_id", rp_id)?;
        }
        if self.sse.channel_capacity == 0 || self.sse.ring_capacity == 0 {
            return Err(ConfigError::invalid(
                "sse.channel_capacity and sse.ring_capacity must be at least 1",
            ));
        }
        Ok(Resolved {
            config: self.clone(),
            data_dir,
            roles,
            node_id: NodeId(self.node.id),
            listen,
            tls,
            kek,
            kek_options,
        })
    }

    /// The configuration as TOML, for `tenko config check`.
    ///
    /// # Errors
    ///
    /// A serialization error (not expected).
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }
}

/// A host name for a certificate subject or a relying-party ID: DNS syntax, lower case,
/// and not an IP address (an RP ID cannot be one, Q5).
fn checked_host(key: &str, name: &str) -> Result<String, ConfigError> {
    let bare = name.trim().trim_start_matches('[').trim_end_matches(']');
    let numeric = bare
        .trim_end_matches('.')
        .split('.')
        .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()));
    if bare.parse::<IpAddr>().is_ok() || numeric {
        return Err(ConfigError::invalid(format!(
            "{key}: `{name}` is an IP address; a host name is required"
        )));
    }
    HostName::new(name)
        .map(|host| host.as_str().to_owned())
        .map_err(|error| ConfigError::invalid(format!("{key}: {error}")))
}

impl ServerSection {
    fn listen_addrs(&self) -> Result<Vec<SocketAddr>, ConfigError> {
        if self.listen.is_empty() {
            return Err(ConfigError::invalid("server.listen is empty"));
        }
        self.listen
            .iter()
            .map(|text| {
                text.parse::<SocketAddr>().map_err(|_| {
                    ConfigError::invalid(format!(
                        "server.listen: `{text}` is not an address with a port, such as \
                         0.0.0.0:8443 or [::]:8443"
                    ))
                })
            })
            .collect()
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=16).contains(&self.workers) {
            return Err(ConfigError::invalid(
                "server.workers must be between 1 and 16 (2 to 4 recommended)",
            ));
        }
        if self.max_connections == 0 {
            return Err(ConfigError::invalid(
                "server.max_connections must be at least 1",
            ));
        }
        if self.handshake_timeout_secs == 0 || self.header_read_timeout_secs == 0 {
            return Err(ConfigError::invalid(
                "server.handshake_timeout_secs and server.header_read_timeout_secs must be at \
                 least 1",
            ));
        }
        for origin in &self.allowed_origins {
            if !(origin.starts_with("https://") || origin.starts_with("http://")) {
                return Err(ConfigError::invalid(format!(
                    "server.allowed_origins: `{origin}` is not an http(s) origin"
                )));
            }
        }
        if self.ui_dir.is_some() && cfg!(not(debug_assertions)) {
            return Err(ConfigError::invalid(
                "server.ui_dir is a development feature of debug builds",
            ));
        }
        Ok(())
    }

    /// The shutdown grace period.
    pub fn shutdown_grace(&self) -> Duration {
        Duration::from_secs(self.shutdown_grace_secs)
    }
}

impl TlsSection {
    fn resolve(&self, profile: Profile) -> Result<TlsSpec, ConfigError> {
        let host = |key: &str, name: &str| checked_host(&format!("tls.{key}"), name);
        if self.watch_interval_secs == 0 || self.renew_check_hours == 0 {
            return Err(ConfigError::invalid(
                "tls.watch_interval_secs and tls.renew_check_hours must be at least 1",
            ));
        }
        match self.mode {
            TlsModeName::InternalCa => {
                let host_name = match &self.host_name {
                    Some(name) => host("host_name", name)?,
                    None => "localhost".to_owned(),
                };
                let alt_names = self
                    .alt_names
                    .iter()
                    .map(|name| host("alt_names", name))
                    .collect::<Result<_, _>>()?;
                let addresses = self
                    .addresses
                    .iter()
                    .map(|text| {
                        text.parse::<IpAddr>().map_err(|_| {
                            ConfigError::invalid(format!(
                                "tls.addresses: `{text}` is not an IP address"
                            ))
                        })
                    })
                    .collect::<Result<_, _>>()?;
                Ok(TlsSpec::InternalCa {
                    host_name,
                    alt_names,
                    addresses,
                })
            }
            TlsModeName::Imported => match (&self.cert_path, &self.key_path) {
                (Some(cert_path), Some(key_path)) => Ok(TlsSpec::Imported {
                    cert_path: cert_path.clone(),
                    key_path: key_path.clone(),
                }),
                _ => Err(ConfigError::invalid(
                    "tls.mode = \"imported\" needs tls.cert_path and tls.key_path",
                )),
            },
            TlsModeName::ReverseProxy => {
                let public_host = self.public_host.as_deref().ok_or_else(|| {
                    ConfigError::invalid(
                        "tls.mode = \"reverse_proxy\" needs tls.public_host, the name clients use",
                    )
                })?;
                let public_host = host("public_host", public_host)?;
                if self.trusted_proxies.is_empty() {
                    return Err(ConfigError::invalid(
                        "tls.mode = \"reverse_proxy\" needs tls.trusted_proxies; without them \
                         every connection is refused",
                    ));
                }
                let trusted_proxies =
                    TrustedProxies::parse(&self.trusted_proxies).map_err(|error| {
                        ConfigError::invalid(format!("tls.trusted_proxies: {error}"))
                    })?;
                Ok(TlsSpec::ReverseProxy {
                    trusted_proxies,
                    proxy_protocol: self.proxy_protocol,
                    public_host,
                })
            }
            TlsModeName::Plain if profile == Profile::Lab => Ok(TlsSpec::Plain),
            TlsModeName::Plain => Err(ConfigError::invalid(format!(
                "tls.mode = \"plain\" is allowed under the Lab profile only (TGL-08); the \
                 profile is `{}`",
                profile.as_str()
            ))),
        }
    }
}

impl KekSection {
    fn resolve(&self, data_dir: &Path) -> Result<(KekConfig, KekOptions), ConfigError> {
        let dir = self.dir.clone().unwrap_or_else(|| data_dir.join("kek"));
        let options = KekOptions {
            allow_plain: self.allow_plain,
            file_dir: Some(dir.clone()),
        };
        let config = match self.provider {
            KekProviderName::Platform => match KekConfig::platform_default(data_dir) {
                KekConfig::Dpapi { .. } => KekConfig::Dpapi {
                    dir,
                    scope: self.scope,
                },
                KekConfig::SystemdCreds { .. } => KekConfig::SystemdCreds {
                    dir,
                    with_key: self.with_key,
                    tool: self.tool.clone(),
                },
                other => other,
            },
            KekProviderName::Dpapi if cfg!(windows) => KekConfig::Dpapi {
                dir,
                scope: self.scope,
            },
            KekProviderName::Dpapi => {
                return Err(ConfigError::invalid(
                    "kek.provider = \"dpapi\" is available on Windows only",
                ));
            }
            KekProviderName::SystemdCreds if cfg!(unix) => KekConfig::SystemdCreds {
                dir,
                with_key: self.with_key,
                tool: self.tool.clone(),
            },
            KekProviderName::SystemdCreds => {
                return Err(ConfigError::invalid(
                    "kek.provider = \"systemd_creds\" is available on Linux only",
                ));
            }
            KekProviderName::SystemdCredential if cfg!(unix) => {
                if self.credential.trim().is_empty() {
                    return Err(ConfigError::invalid("kek.credential must not be empty"));
                }
                KekConfig::SystemdCredential {
                    name: self.credential.clone(),
                    retired: self
                        .retired
                        .iter()
                        .map(|name| name.to_string_lossy().into_owned())
                        .collect(),
                    dir,
                    with_key: self.with_key,
                    directory: None,
                }
            }
            KekProviderName::SystemdCredential => {
                return Err(ConfigError::invalid(
                    "kek.provider = \"systemd_credential\" is available on Linux only",
                ));
            }
            KekProviderName::File => KekConfig::File {
                path: self.path.clone().ok_or_else(|| {
                    ConfigError::invalid("kek.provider = \"file\" needs kek.path")
                })?,
                retired: self.retired.clone(),
            },
        };
        Ok((config, options))
    }
}

impl StoreSection {
    fn validate(&self) -> Result<(), ConfigError> {
        let positive = [
            ("store.log_cache_mib", self.log_cache_mib as u64),
            ("store.sm_cache_mib", self.sm_cache_mib as u64),
            ("store.checkpoint_interval_ms", self.checkpoint_interval_ms),
            ("store.journal_retention", self.journal_retention as u64),
            ("store.snapshot_every_entries", self.snapshot_every_entries),
            ("store.snapshot_every_log_mib", self.snapshot_every_log_mib),
            ("store.write_timeout_secs", self.write_timeout_secs),
            ("store.read_wait_secs", self.read_wait_secs),
            ("store.journal_max_mib", self.journal_max_mib),
            (
                "store.maintenance_interval_hours",
                self.maintenance_interval_hours,
            ),
            (
                "store.reseed_ratio_percent",
                u64::from(self.reseed_ratio_percent),
            ),
        ];
        match positive.iter().find(|(_, value)| *value == 0) {
            Some((key, _)) => Err(ConfigError::invalid(format!("{key} must be at least 1"))),
            None => Ok(()),
        }
    }
}

impl JobsSection {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.workers == 0
            || self.default_group_limit == 0
            || self.lease_ttl_secs == 0
            || self.scan_interval_secs == 0
        {
            return Err(ConfigError::invalid(
                "jobs.workers, jobs.default_group_limit, jobs.lease_ttl_secs and \
                 jobs.scan_interval_secs must be at least 1",
            ));
        }
        Ok(())
    }
}

impl LogSection {
    fn validate(&self) -> Result<(), ConfigError> {
        tracing_subscriber::EnvFilter::try_new(&self.level)
            .map_err(|error| ConfigError::invalid(format!("log.level: {error}")))?;
        if self.max_file_mb > 65_536 {
            return Err(ConfigError::invalid(
                "log.max_file_mb must be between 0 (no rotation) and 65536",
            ));
        }
        if !(1..=100).contains(&self.keep_files) {
            return Err(ConfigError::invalid(
                "log.keep_files must be between 1 and 100",
            ));
        }
        Ok(())
    }
}

impl SseSection {
    /// The event hub settings.
    pub fn to_config(&self) -> SseConfig {
        SseConfig {
            channel_capacity: self.channel_capacity,
            ring_capacity: self.ring_capacity,
            keepalive: Duration::from_secs(self.keepalive_secs.max(1)),
            coalesce: (self.coalesce_ms > 0).then(|| Duration::from_millis(self.coalesce_ms)),
            journal_replay_limit: self.journal_replay_limit,
            retry: Duration::from_secs(self.retry_secs),
            max_objects_per_event: self.max_objects_per_event,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn from_text(text: &str, vars: &[(&str, &str)]) -> Result<Loaded, ConfigError> {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("tenko.toml");
        std::fs::write(&path, text).expect("write configuration");
        load(
            &Sources {
                file: Some(path),
                ..Sources::default()
            },
            env(vars),
        )
    }

    #[test]
    fn defaults_resolve_with_a_data_dir() {
        let loaded = load(
            &Sources {
                data_dir: Some(std::env::temp_dir().join("tenko-config-defaults")),
                ..Sources::default()
            },
            Vec::new(),
        )
        .expect("defaults load");
        let resolved = loaded.config.resolve().expect("defaults are valid");
        assert!(resolved.data_dir.is_absolute());
        assert_eq!(resolved.roles.to_string(), "controller");
        assert_eq!(
            resolved.listen,
            vec![DEFAULT_LISTEN.parse().expect("address")]
        );
        assert!(
            matches!(resolved.tls, TlsSpec::InternalCa { ref host_name, .. } if host_name == "localhost")
        );
    }

    #[test]
    fn a_missing_data_dir_is_named() {
        let error = Config::default().resolve().expect_err("no data dir");
        assert_eq!(error.code, "config.invalid");
        assert!(error.message.contains("data_dir"), "{error}");
    }

    #[test]
    fn unknown_keys_are_refused_with_their_line() {
        let error = from_text("data_dir = \"/x\"\n[server]\nlisten_on = 1\n", &[])
            .expect_err("unknown key");
        assert_eq!(error.code, "config.parse");
        assert!(error.message.contains("listen_on"), "{error}");
    }

    #[test]
    fn syntax_errors_are_parse_errors() {
        let error = from_text("data_dir = \n", &[]).expect_err("syntax error");
        assert_eq!(error.code, "config.parse");
    }

    #[test]
    fn environment_overrides_the_file() {
        let loaded = from_text(
            "data_dir = \"/from/file\"\n[log]\nlevel = \"warn\"\n",
            &[
                ("TENKO_DATA_DIR", "/from/env"),
                ("TENKO_LOG__LEVEL", "debug"),
                ("TENKO_SERVER__LISTEN", "127.0.0.1:1, [::1]:2"),
                ("TENKO_SERVER__WORKERS", "3"),
                ("TENKO_TLS__PROXY_PROTOCOL", "true"),
                ("TENKO_KEK__RETIRED", "/a.key,/b.key"),
                ("TENKO_CONFIG", "/ignored.toml"),
                ("TENKO_URL", "https://ignored"),
                ("OTHER", "x"),
            ],
        )
        .expect("loads");
        let config = &loaded.config;
        assert_eq!(config.data_dir.as_deref(), Some(Path::new("/from/env")));
        assert_eq!(config.log.level, "debug");
        assert_eq!(config.server.listen, ["127.0.0.1:1", "[::1]:2"]);
        assert_eq!(config.server.workers, 3);
        assert!(config.tls.proxy_protocol);
        assert_eq!(
            config.kek.retired,
            [PathBuf::from("/a.key"), PathBuf::from("/b.key")]
        );
        assert_eq!(loaded.env_overrides.len(), 6);
    }

    #[test]
    fn the_kek_options_follow_the_section() {
        let loaded = from_text(
            "data_dir = \"/d\"
[kek]
allow_plain = true
dir = \"/keys\"
",
            &[],
        )
        .expect("parses");
        let resolved = loaded.config.resolve().expect("resolves");
        assert!(resolved.kek_options.allow_plain);
        assert_eq!(
            resolved.kek_options.file_dir.as_deref(),
            Some(Path::new("/keys"))
        );
        let loaded = from_text(
            "data_dir = \"/d\"
",
            &[],
        )
        .expect("parses");
        let resolved = loaded.config.resolve().expect("resolves");
        assert!(!resolved.kek_options.allow_plain);
        assert_eq!(
            resolved.kek_options.file_dir,
            Some(resolved.data_dir.join("kek"))
        );
    }

    #[test]
    fn the_systemd_credential_provider_is_linux_only() {
        let loaded = from_text(
            "data_dir = \"/d\"
[kek]
provider = \"systemd_credential\"
retired = [\"tenko_kek_old\"]
",
            &[],
        )
        .expect("parses");
        assert_eq!(loaded.config.kek.credential, "tenko_kek");
        let resolved = loaded.config.resolve();
        if cfg!(unix) {
            match resolved.expect("resolves").kek {
                KekConfig::SystemdCredential {
                    name,
                    retired,
                    directory,
                    ..
                } => {
                    assert_eq!(name, "tenko_kek");
                    assert_eq!(retired, ["tenko_kek_old"]);
                    assert_eq!(directory, None);
                }
                other => panic!("unexpected provider {other:?}"),
            }
        } else {
            let error = resolved.expect_err("refused");
            assert!(error.message.contains("kek.provider"), "{error}");
        }
    }

    #[test]
    fn environment_values_of_the_wrong_type_are_env_errors() {
        let error = from_text("", &[("TENKO_SERVER__WORKERS", "many")]).expect_err("bad type");
        assert_eq!(error.code, "config.env");
    }

    #[test]
    fn flags_override_the_environment() {
        let loaded = load(
            &Sources {
                data_dir: Some(PathBuf::from("/flag")),
                roles: Some("all".to_owned()),
                file: None,
            },
            env(&[("TENKO_DATA_DIR", "/env"), ("TENKO_ROLES", "dns")]),
        )
        .expect("loads");
        assert_eq!(loaded.config.data_dir.as_deref(), Some(Path::new("/flag")));
        assert_eq!(loaded.config.roles, "all");
    }

    #[test]
    fn tls_modes_need_their_fields() {
        let base = "data_dir = \"/d\"\n";
        let cases = [
            ("[tls]\nmode = \"imported\"\n", "cert_path"),
            (
                "[tls]\nmode = \"reverse_proxy\"\ntrusted_proxies = [\"10.0.0.1\"]\n",
                "public_host",
            ),
            (
                "[tls]\nmode = \"reverse_proxy\"\npublic_host = \"ddi.example.org\"\n",
                "trusted_proxies",
            ),
            ("[tls]\nmode = \"plain\"\n", "Lab"),
            ("[tls]\nhost_name = \"192.0.2.1\"\n", "host_name"),
        ];
        for (text, needle) in cases {
            let loaded = from_text(&format!("{base}{text}"), &[]).expect("parses");
            let error = loaded.config.resolve().expect_err("invalid");
            assert!(error.message.contains(needle), "{text}: {error}");
        }
    }

    #[test]
    fn plain_http_needs_the_lab_profile() {
        let loaded = from_text(
            "data_dir = \"/d\"\n[profile]\nname = \"lab\"\n[tls]\nmode = \"plain\"\n",
            &[],
        )
        .expect("parses");
        let resolved = loaded.config.resolve().expect("valid under Lab");
        assert_eq!(resolved.tls, TlsSpec::Plain);
    }

    #[test]
    fn reverse_proxy_mode_resolves() {
        let loaded = from_text(
            "data_dir = \"/d\"\n[tls]\nmode = \"reverse_proxy\"\npublic_host = \"DDI.example.org\"\n\
             trusted_proxies = [\"127.0.0.1\", \"10.0.0.0/8\"]\n",
            &[],
        )
        .expect("parses");
        match loaded.config.resolve().expect("valid").tls {
            TlsSpec::ReverseProxy {
                public_host,
                trusted_proxies,
                ..
            } => {
                assert_eq!(public_host, "ddi.example.org");
                assert!(trusted_proxies.is_trusted("10.1.2.3".parse().expect("ip")));
            }
            other => panic!("unexpected mode {other:?}"),
        }
    }

    #[test]
    fn bad_values_are_named() {
        let cases = [
            ("roles = \"dns,ntp\"", "roles"),
            ("[server]\nlisten = [\"localhost\"]", "server.listen"),
            ("[server]\nworkers = 0", "server.workers"),
            ("[kek]\nprovider = \"file\"", "kek.path"),
            ("[log]\nlevel = \"=\"", "log.level"),
            ("[log]\nkeep_files = 0", "log.keep_files"),
            ("[log]\nmax_file_mb = 70000", "log.max_file_mb"),
            ("[store]\nsm_cache_mib = 0", "store.sm_cache_mib"),
            (
                "[rate_limit]\nper_ip = { per_second = 0, burst = 1 }",
                "rate_limit",
            ),
            ("[node]\nid = 0", "node.id"),
        ];
        for (text, needle) in cases {
            let loaded = from_text(&format!("data_dir = \"/d\"\n{text}\n"), &[]).expect("parses");
            let error = loaded.config.resolve().expect_err("invalid");
            assert!(error.message.contains(needle), "{text}: {error}");
        }
    }

    #[test]
    fn the_effective_configuration_round_trips() {
        let mut config = Config {
            data_dir: Some(PathBuf::from("/var/lib/tenko")),
            ..Config::default()
        };
        config.tls.mode = TlsModeName::ReverseProxy;
        config.tls.public_host = Some("ddi.example.org".to_owned());
        config.tls.trusted_proxies = vec!["10.0.0.1".to_owned()];
        let text = config.to_toml().expect("serializes");
        let again: Config = toml::from_str(&text).expect("parses back");
        assert_eq!(again, config);
    }

    #[test]
    fn the_example_file_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/tenko.example.toml");
        let loaded = load(
            &Sources {
                file: Some(path),
                ..Sources::default()
            },
            Vec::new(),
        )
        .expect("the example parses");
        loaded.config.resolve().expect("the example is valid");
    }

    #[test]
    fn the_cluster_section_is_read_and_checked() {
        let loaded = from_text(
            "data_dir = \"/d\"\n[cluster]\nlisten = [\"127.0.0.1:9444\"]\nheartbeat_secs = 5\n",
            &[("TENKO_CLUSTER__BUFFER_MIB", "16")],
        )
        .expect("loads");
        assert_eq!(
            loaded.config.cluster.listen_mode().expect("mode"),
            ClusterListen::Always(vec!["127.0.0.1:9444".parse().expect("address")])
        );
        assert_eq!(loaded.config.cluster.heartbeat_secs, 5);
        assert_eq!(loaded.config.cluster.buffer_mib, 16);
        loaded.config.resolve().expect("valid");

        let off =
            from_text("data_dir = \"/d\"\n", &[("TENKO_CLUSTER__LISTEN", "[]")]).expect("loads");
        assert_eq!(
            off.config.cluster.listen_mode().expect("mode"),
            ClusterListen::Off
        );
        let default = from_text("data_dir = \"/d\"\n", &[]).expect("loads");
        assert_eq!(
            default.config.cluster.listen_mode().expect("mode"),
            ClusterListen::OnDemand(vec![DEFAULT_CLUSTER_LISTEN.parse().expect("address")])
        );

        for bad in [
            "listen = [\"nowhere\"]",
            "heartbeat_secs = 0",
            "advertise = [\"ddi.example.net\"]",
            "buffer_mib = 0",
            "enrolment_ttl_secs = 10",
            "isolation_after_ms = 100",
            "catch_up_timeout_secs = 0",
            "promote_lag_entries = 0",
            "sync_kbps = 20000000",
            "peer_address_map = { \"127.0.0.1:9002\" = \"127.0.0.1\" }",
            "peer_address_map = { \"9002\" = \"127.0.0.1:9102\" }",
            "peer_address_map = { \"127.0.0.1:9002\" = \"127.0.0.1:0\" }",
            "peer_address_map = { \"127.0.0.1:9002\" = \"127.0.0.1:9002\" }",
        ] {
            let loaded =
                from_text(&format!("data_dir = \"/d\"\n[cluster]\n{bad}\n"), &[]).expect("loads");
            let error = loaded.config.resolve().expect_err(bad);
            assert_eq!(error.code, "config.invalid", "{bad}");
            assert!(error.message.starts_with("cluster."), "{bad}: {error}");
        }
    }

    #[test]
    fn the_slice_3_cluster_keys_have_defaults_and_are_read() {
        let default = from_text("data_dir = \"/d\"\n", &[]).expect("loads");
        let cluster = &default.config.cluster;
        assert_eq!(cluster.isolation_after_ms, 3_000);
        assert_eq!(cluster.catch_up_timeout_secs, 120);
        assert!(cluster.auto_promote);
        assert_eq!(cluster.promote_lag_entries, 100);
        assert_eq!(cluster.sync_kbps, 0);
        let loaded = from_text(
            "data_dir = \"/d\"\n[cluster]\nisolation_after_ms = 5000\nauto_promote = false\n",
            &[("TENKO_CLUSTER__SYNC_KBPS", "512")],
        )
        .expect("loads");
        assert_eq!(loaded.config.cluster.isolation_after_ms, 5_000);
        assert!(!loaded.config.cluster.auto_promote);
        assert_eq!(loaded.config.cluster.sync_kbps, 512);
        loaded.config.resolve().expect("valid");
    }

    #[test]
    fn the_peer_address_map_is_read_from_the_file_and_the_environment() {
        let default = from_text("data_dir = \"/d\"\n", &[]).expect("loads");
        assert!(default.config.cluster.peer_address_map.is_empty());
        let loaded = from_text(
            "data_dir = \"/d\"\n[cluster]\npeer_address_map = { \"controller-2.example.test:8444\" = \"192.0.2.12:8444\", \"127.0.0.1:9002\" = \"127.0.0.1:9102\" }\n",
            &[],
        )
        .expect("loads");
        let map = &loaded.config.cluster.peer_address_map;
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get("controller-2.example.test:8444")
                .map(String::as_str),
            Some("192.0.2.12:8444")
        );
        assert_eq!(
            map.get("127.0.0.1:9002").map(String::as_str),
            Some("127.0.0.1:9102")
        );
        loaded.config.resolve().expect("valid");
        let from_env = from_text(
            "data_dir = \"/d\"\n",
            &[(
                "TENKO_CLUSTER__PEER_ADDRESS_MAP",
                "{ \"[2001:db8::2]:8444\" = \"[2001:db8::12]:8444\" }",
            )],
        )
        .expect("loads");
        assert_eq!(
            from_env
                .config
                .cluster
                .peer_address_map
                .get("[2001:db8::2]:8444")
                .map(String::as_str),
            Some("[2001:db8::12]:8444")
        );
        from_env.config.resolve().expect("valid");
    }

    #[test]
    fn telemetry_metrics_and_backup_sections_are_checked() {
        let default = from_text("data_dir = \"/d\"\n", &[]).expect("loads");
        assert_eq!(default.config.telemetry.otlp_endpoint, None);
        assert!((default.config.telemetry.sampling_ratio - 1.0).abs() < f64::EPSILON);
        assert_eq!(default.config.metrics.listen_addr().expect("valid"), None);
        assert_eq!(default.config.metrics.gauge_interval_secs, 30);
        let resolved = default.config.resolve().expect("valid");
        assert_eq!(resolved.backup_dir(), resolved.layout().backups());
        assert_eq!(
            resolved.audit_export_dir(),
            resolved.layout().audit_export()
        );

        let loaded = from_text(
            "data_dir = \"/d\"\n[telemetry]\notlp_endpoint = \"http://127.0.0.1:4317\"\n\
             sampling_ratio = 0.25\n[metrics]\nlisten = \"127.0.0.1:9464\"\n",
            &[
                ("TENKO_BACKUP__TARGET_DIR", "/mnt/backup/tenko"),
                ("TENKO_AUDIT_EXPORT__FILE_DIR", "/var/log/tenko-audit"),
            ],
        )
        .expect("loads");
        assert_eq!(
            loaded.config.metrics.listen_addr().expect("valid"),
            Some("127.0.0.1:9464".parse().expect("address"))
        );
        if cfg!(unix) {
            let resolved = loaded.config.resolve().expect("valid");
            assert_eq!(resolved.backup_dir(), Path::new("/mnt/backup/tenko"));
            assert_eq!(
                resolved.audit_export_dir(),
                Path::new("/var/log/tenko-audit")
            );
        }

        for (section, bad) in [
            ("telemetry", "otlp_endpoint = \"collector:4317\""),
            ("telemetry", "otlp_endpoint = \"http://\""),
            ("telemetry", "sampling_ratio = 1.5"),
            ("metrics", "listen = \"0.0.0.0:9464\""),
            ("metrics", "listen = \"nowhere\""),
            ("metrics", "gauge_interval_secs = 1"),
            ("backup", "target_dir = \"relative/backups\""),
            ("backup", "target_dir = \"\""),
            ("audit_export", "file_dir = \"relative/audit\""),
            ("audit_export", "file_dir = \"\""),
        ] {
            let loaded =
                from_text(&format!("data_dir = \"/d\"\n[{section}]\n{bad}\n"), &[]).expect("loads");
            let error = loaded.config.resolve().expect_err(bad);
            assert_eq!(error.code, "config.invalid", "{bad}");
            assert!(error.message.starts_with(section), "{bad}: {error}");
        }
    }

    #[test]
    fn modules_and_updates_are_read_from_the_file_and_the_environment() {
        let loaded = from_text(
            "data_dir = \"/d\"\nmodules = [\"ipam\", \"dns\"]\n[updates]\nair_gapped = true\n",
            &[("TENKO_UPDATES__READY_TIMEOUT_SECS", "60")],
        )
        .expect("loads");
        let modules = loaded.config.modules.expect("modules");
        assert_eq!(modules.to_string(), "ipam,dns");
        assert!(loaded.config.updates.air_gapped);
        assert_eq!(loaded.config.updates.ready_timeout_secs, 60);
        loaded.config.resolve().expect("valid");

        let from_env =
            from_text("data_dir = \"/d\"\n", &[("TENKO_MODULES", "dhcp")]).expect("loads");
        assert_eq!(
            from_env.config.modules.map(|set| set.to_string()),
            Some("dhcp".to_owned())
        );
        assert_eq!(
            from_text("data_dir = \"/d\"\n", &[])
                .expect("loads")
                .config
                .modules,
            None
        );
        let unknown =
            from_text("data_dir = \"/d\"\nmodules = [\"ntp\"]\n", &[]).expect_err("unknown module");
        assert!(
            unknown.message.contains("unknown module `ntp`"),
            "{unknown}"
        );
    }

    #[test]
    fn update_settings_are_checked() {
        for (text, needle) in [
            (
                "[updates]\nsource_url = \"http://example.com/r.json\"\n",
                "https URL",
            ),
            (
                "[updates]\ncheck_interval_hours = 0\n",
                "check_interval_hours",
            ),
            ("[updates]\nready_timeout_secs = 5\n", "ready_timeout_secs"),
            ("[updates]\nkeep_versions = 0\n", "keep_versions"),
        ] {
            let loaded = from_text(&format!("data_dir = \"/d\"\n{text}"), &[]).expect("parses");
            let error = loaded.config.resolve().expect_err(text);
            assert!(error.message.contains(needle), "{error}");
        }
        let loopback = from_text(
            "data_dir = \"/d\"\n[updates]\nsource_url = \"http://127.0.0.1:9/releases.json\"\n",
            &[],
        )
        .expect("parses");
        loopback
            .config
            .resolve()
            .expect("loopback http is allowed for tests");
    }

    #[test]
    fn the_layout_names_the_store_files() {
        let layout = DataLayout {
            root: PathBuf::from("/d"),
        };
        assert_eq!(layout.store(), Path::new("/d").join("store"));
        assert_eq!(
            layout.ca_root(),
            Path::new("/d").join("tls").join("ca-root.pem")
        );
        assert!(layout.is_fresh());
    }
}
