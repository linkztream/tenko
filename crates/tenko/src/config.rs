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
    fmt,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Deserializer, Serialize};
use tenko_api::{
    middleware::{Quota, RateLimitConfig},
    sse::SseConfig,
};
use tenko_auth::settings::Profile;
use tenko_cluster::ca::TrustedProxies;
use tenko_core::{NodeId, RoleSet, net::HostName};
use tenko_vault::kek::{CredsKey, DpapiScope, KekConfig};

/// Prefix of the environment variables that override configuration keys.
pub const ENV_PREFIX: &str = "TENKO_";

/// Separator between a section and its key in an environment variable name.
pub const ENV_SEPARATOR: &str = "__";

/// The default listen address of the API and UI.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8443";

/// The top-level keys of the file; environment variables are matched against them.
const TOP_LEVEL_KEYS: [&str; 15] = [
    "data_dir",
    "roles",
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
    /// An explicit key file (containers, CI); warns at every start.
    File,
}

/// `[kek]`: the key-encryption key provider of the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KekSection {
    /// `platform` (default), `dpapi`, `systemd_creds` or `file`.
    pub provider: KekProviderName,
    /// Directory of the key generations (default `<data_dir>/kek`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<PathBuf>,
    /// DPAPI: `user` (default, bound to the service account) or `machine`.
    pub scope: DpapiScope,
    /// `systemd-creds`: `auto` (default), `tpm2` or `host`.
    pub with_key: CredsKey,
    /// `systemd-creds`: path of the tool (default: found on `PATH`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<PathBuf>,
    /// `file`: the active key file (32 raw bytes, 64 hexadecimal digits or base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// `file`: earlier key files still needed until a rotation completes.
    #[serde(deserialize_with = "paths_or_list")]
    pub retired: Vec<PathBuf>,
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
            retired: Vec::new(),
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
}

impl Default for LogSection {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            format: LogFormat::Text,
            file: None,
        }
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
        let kek = self.kek.resolve(&data_dir)?;
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
    fn resolve(&self, data_dir: &Path) -> Result<KekConfig, ConfigError> {
        let dir = self.dir.clone().unwrap_or_else(|| data_dir.join("kek"));
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
            KekProviderName::File => KekConfig::File {
                path: self.path.clone().ok_or_else(|| {
                    ConfigError::invalid("kek.provider = \"file\" needs kek.path")
                })?,
                retired: self.retired.clone(),
            },
        };
        Ok(config)
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
            .map(drop)
            .map_err(|error| ConfigError::invalid(format!("log.level: {error}")))
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
