//! The `[scan]` section of `tenko.toml`: what a probe scans, how fast and when.
//!
//! A probe reads this section of its own configuration file until its first sync with the
//! controllers; from then on the configuration the controllers hold for it
//! (`scan.probe_config`, `PUT /nodes/{id}/scan-config`) wins, and the file serves only
//! `tenko node scan run --dry-run` and the probe's offer of an initial configuration at its
//! first connection. Every key has a default, so an empty section is valid; without
//! `prefixes` the scanner scans nothing, because scans never leave the configured
//! prefixes.
//!
//! SNMP passwords come from one of three places: a file (`auth_password_file`), the file
//! itself (`auth_password`, for a lab), or an operator secret of the vault
//! (`auth_secret`), which the probe fetches from the controllers when it polls and keeps in
//! memory only (S3-Q19). A configuration held by the controllers names vault secrets only
//! ([`ScanConfig::validate_stored`]).
//!
//! ```toml
//! [scan]
//! prefixes = ["192.0.2.0/24", "2001:db8:10::/64"]
//! exclude = ["192.0.2.1"]
//! rate = "slow"
//! blackout = ["mon-fri 08:00-17:00"]
//!
//! [scan.tcp_connect]
//! ports = [22, 80, 443, 3389]
//!
//! [[scan.snmp.devices]]
//! address = "192.0.2.2"
//! user = "tenko"
//! auth = "sha256"
//! auth_password_file = "/etc/tenko/snmp-auth"
//! privacy = "aes128"
//! privacy_password_file = "/etc/tenko/snmp-priv"
//! ```

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tenko_core::{SecretId, VrfId};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::{
    blackout::Blackout, error::ScanError, limit::PaceLimits, method::MethodKind, scope::Scope,
};

/// The TCP ports `tcp_connect` tries by default: remote access, web, file sharing,
/// directory, databases, printing, home automation and hypervisor consoles.
pub const DEFAULT_TCP_PORTS: [u16; 28] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 515, 548, 554, 631, 636, 1883, 3306,
    3389, 5432, 5900, 6053, 8006, 8080, 8123, 8443,
];

/// The rate profile of TGL-19.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = ScanRateProfile)]
pub enum RateProfile {
    /// 100 probes per second (Home).
    #[default]
    Normal,
    /// 50 probes per second (Standard).
    Slow,
    /// 10 probes per second (Hardened).
    Slowest,
    /// No limit (Lab).
    Unlimited,
}

impl RateProfile {
    /// Probes per second; `None` is unlimited.
    pub const fn per_second(self) -> Option<u32> {
        match self {
            RateProfile::Normal => Some(100),
            RateProfile::Slow => Some(50),
            RateProfile::Slowest => Some(10),
            RateProfile::Unlimited => None,
        }
    }
}

/// A secret read from the configuration file. It never prints: `Debug` and the serialized
/// form (`tenko config check`) show `(hidden)`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    /// The secret.
    pub fn new(text: impl Into<String>) -> Self {
        Self(Zeroizing::new(text.into()))
    }

    /// The text.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(hidden)")
    }
}

impl Serialize for SecretText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("(hidden)")
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// `[scan]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    /// Runs the scanner when the node has the `probe` role (default true).
    pub enabled: bool,
    /// The prefixes the probe covers (`192.0.2.0/24`, `2001:db8:10::/64`, or an address).
    /// Nothing outside them is probed or reported. Empty: the scanner scans nothing.
    pub prefixes: Vec<String>,
    /// Prefixes and addresses inside `prefixes` that are never probed or reported.
    pub exclude: Vec<String>,
    /// The VRF of the addresses (a VRF id); not set: the VRF of the probe's enrolment
    /// token, else the default VRF.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vrf: Option<String>,
    /// Active probing (TGL-18): ICMP sweeps and TCP connect scans. `false` keeps the probe
    /// passive: neighbour tables, mDNS, LLMNR, reverse DNS and SNMP only.
    pub active: bool,
    /// Rate profile (TGL-19): `normal` (100 probes/s), `slow` (50), `slowest` (10) or
    /// `unlimited`.
    pub rate: RateProfile,
    /// Probes per second; overrides `rate` when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets_per_second: Option<u32>,
    /// Minimum milliseconds between two probes to the same address (default 100).
    pub per_host_interval_ms: u64,
    /// Most probes in flight at once (default 32).
    pub concurrency: usize,
    /// Largest IPv4 prefix, in addresses, that a sweep enumerates (default 4096); larger
    /// prefixes and IPv6 networks are covered through the addresses other methods saw.
    pub max_hosts_per_prefix: u32,
    /// The time zone of `blackout` (an IANA name such as `Europe/Stockholm`); not set: the
    /// system time zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// Blackout windows such as `mon-fri 08:00-17:00`: no method that sends packets runs in
    /// them, and a run that reaches one stops.
    pub blackout: Vec<String>,
    /// IPv4 neighbours from the operating system's ARP table.
    pub arp: BasicMethod,
    /// IPv6 neighbours from the operating system's neighbour table.
    pub nd: BasicMethod,
    /// ICMP echo sweeps.
    pub icmp: IcmpMethod,
    /// TCP connect scans.
    pub tcp_connect: TcpConnectMethod,
    /// Reverse DNS of the discovered addresses.
    pub reverse_dns: ReverseDnsMethod,
    /// Multicast DNS.
    pub mdns: MdnsMethod,
    /// LLMNR.
    pub llmnr: LlmnrMethod,
    /// SNMPv3 polling of switches.
    pub snmp: SnmpMethod,
    /// ARP sweep over raw sockets (WP3.14, SCAN-04).
    pub arp_sweep: ArpSweepMethod,
    /// TCP SYN scan over raw sockets (WP3.14, SCAN-04).
    pub tcp_syn: TcpSynMethod,
    /// OS fingerprinting over raw sockets (WP3.14, SCAN-04).
    pub os_fingerprint: OsFingerprintMethod,
    /// Passive LLDP and CDP listening over raw sockets (WP3.14, SCAN-02, SCAN-05).
    pub lldp: LldpMethod,
    /// Passive DHCPv4 snooping over raw sockets (WP3.14, SCAN-03).
    pub dhcp_snoop: DhcpSnoopMethod,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefixes: Vec::new(),
            exclude: Vec::new(),
            vrf: None,
            active: true,
            rate: RateProfile::Normal,
            packets_per_second: None,
            per_host_interval_ms: 100,
            concurrency: 32,
            max_hosts_per_prefix: 4096,
            timezone: None,
            blackout: Vec::new(),
            arp: BasicMethod::every(300),
            nd: BasicMethod::every(300),
            icmp: IcmpMethod::default(),
            tcp_connect: TcpConnectMethod::default(),
            reverse_dns: ReverseDnsMethod::default(),
            mdns: MdnsMethod::default(),
            llmnr: LlmnrMethod::default(),
            snmp: SnmpMethod::default(),
            arp_sweep: ArpSweepMethod::default(),
            tcp_syn: TcpSynMethod::default(),
            os_fingerprint: OsFingerprintMethod::default(),
            lldp: LldpMethod::default(),
            dhcp_snoop: DhcpSnoopMethod::default(),
        }
    }
}

/// The schedule keys every method has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    /// Whether the method runs on schedule.
    pub enabled: bool,
    /// Seconds between two runs.
    pub interval: Duration,
    /// How long a sighting stays current without a refresh.
    pub ttl: Duration,
}

/// Seconds a sighting lives by default: three intervals, at least 15 minutes and at most
/// seven days, so one missed run does not age a device out.
fn default_ttl(interval_secs: u64, ttl_secs: Option<u64>) -> Duration {
    Duration::from_secs(
        ttl_secs.unwrap_or_else(|| interval_secs.saturating_mul(3).clamp(900, 604_800)),
    )
}

/// A method with only the schedule keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
#[schema(as = ScanBasicMethod)]
pub struct BasicMethod {
    /// Runs on schedule (default true).
    pub enabled: bool,
    /// Seconds between two runs.
    pub interval_secs: u64,
    /// Seconds a sighting stays current; default three intervals (15 minutes to 7 days).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

impl BasicMethod {
    /// Enabled, every `interval_secs` seconds.
    pub const fn every(interval_secs: u64) -> Self {
        Self {
            enabled: true,
            interval_secs,
            ttl_secs: None,
        }
    }

    fn schedule(&self) -> Schedule {
        Schedule {
            enabled: self.enabled,
            interval: Duration::from_secs(self.interval_secs),
            ttl: default_ttl(self.interval_secs, self.ttl_secs),
        }
    }
}

impl Default for BasicMethod {
    fn default() -> Self {
        Self::every(300)
    }
}

/// `[scan.icmp]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct IcmpMethod {
    /// Runs on schedule (default true; needs `active`).
    pub enabled: bool,
    /// Seconds between two sweeps (default 1800).
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Milliseconds to wait for an echo reply (default 1000).
    pub timeout_ms: u64,
}

impl Default for IcmpMethod {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 1800,
            ttl_secs: None,
            timeout_ms: 1000,
        }
    }
}

/// Which addresses `tcp_connect` scans.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = ScanTcpTargets)]
pub enum TcpTargets {
    /// The addresses the other methods of this probe saw (default).
    #[default]
    Known,
    /// Every address of the prefixes that a sweep enumerates, and the known addresses.
    All,
}

/// `[scan.tcp_connect]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TcpConnectMethod {
    /// Runs on schedule (default true; needs `active`).
    pub enabled: bool,
    /// Seconds between two scans (default 21600, six hours).
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// The ports (default [`DEFAULT_TCP_PORTS`]).
    pub ports: Vec<u16>,
    /// Milliseconds to wait for a connection (default 1500).
    pub timeout_ms: u64,
    /// Sends a TLS `ClientHello` to every open port and records which answer as TLS
    /// (default true). Nothing else is sent; no banner is read.
    pub tls_hint: bool,
    /// `known` (default) or `all`.
    pub targets: TcpTargets,
}

impl Default for TcpConnectMethod {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 21_600,
            ttl_secs: None,
            ports: DEFAULT_TCP_PORTS.to_vec(),
            timeout_ms: 1500,
            tls_hint: true,
            targets: TcpTargets::Known,
        }
    }
}

/// `[scan.reverse_dns]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ReverseDnsMethod {
    /// Runs on schedule (default true).
    pub enabled: bool,
    /// Seconds between two runs (default 3600).
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// DNS servers (`192.0.2.53` or `192.0.2.53:53`); empty: the system's resolvers.
    pub servers: Vec<String>,
    /// Milliseconds to wait for an answer (default 2000).
    pub timeout_ms: u64,
}

impl Default for ReverseDnsMethod {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 3600,
            ttl_secs: None,
            servers: Vec::new(),
            timeout_ms: 2000,
        }
    }
}

/// `[scan.mdns]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct MdnsMethod {
    /// Runs on schedule (default true).
    pub enabled: bool,
    /// Seconds between two runs (default 900).
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Seconds to collect answers and announcements per run (default 4).
    pub listen_secs: u64,
    /// Also listens on port 5353 for announcements during the window (default true);
    /// when another program holds the port exclusively, the run uses queries only.
    pub passive: bool,
    /// Where queries go (default `224.0.0.251:5353`).
    pub group: String,
    /// The port of unicast queries to known addresses (default 5353).
    pub unicast_port: u16,
}

impl Default for MdnsMethod {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 900,
            ttl_secs: None,
            listen_secs: 4,
            passive: true,
            group: "224.0.0.251:5353".to_owned(),
            unicast_port: 5353,
        }
    }
}

/// `[scan.llmnr]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct LlmnrMethod {
    /// Runs on schedule (default true).
    pub enabled: bool,
    /// Seconds between two runs (default 3600).
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Milliseconds to wait for answers after the last query (default 1000).
    pub timeout_ms: u64,
    /// The port of the queries (default 5355).
    pub port: u16,
}

impl Default for LlmnrMethod {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 3600,
            ttl_secs: None,
            timeout_ms: 1000,
            port: 5355,
        }
    }
}

/// SNMPv3 authentication protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnmpAuth {
    /// HMAC-SHA-96 (RFC 3414).
    Sha1,
    /// HMAC-128-SHA-224 (RFC 7860).
    Sha224,
    /// HMAC-192-SHA-256 (RFC 7860).
    Sha256,
    /// HMAC-256-SHA-384 (RFC 7860).
    Sha384,
    /// HMAC-384-SHA-512 (RFC 7860).
    Sha512,
}

/// SNMPv3 privacy protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnmpPrivacy {
    /// AES-128-CFB (RFC 3826).
    Aes128,
}

/// One switch to poll.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SnmpDevice {
    /// Its management address.
    #[schema(value_type = String)]
    pub address: IpAddr,
    /// Its SNMP port (default 161).
    #[serde(default = "snmp_port")]
    pub port: u16,
    /// The device name in attachments and links; default its `sysName`, else the address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The SNMPv3 user.
    pub user: String,
    /// The authentication protocol; not set: no authentication (lab use only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<SnmpAuth>,
    /// The authentication password, in clear in this file. Never in a configuration held
    /// by the controllers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(ignore)]
    pub auth_password: Option<SecretText>,
    /// A file that holds the authentication password (preferred over `auth_password`).
    /// Never in a configuration held by the controllers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(ignore)]
    pub auth_password_file: Option<PathBuf>,
    /// The operator secret of the vault that holds the authentication password; the probe
    /// fetches it from the controllers when it polls and keeps it in memory only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub auth_secret: Option<SecretId>,
    /// The privacy protocol; not set: no encryption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<SnmpPrivacy>,
    /// The privacy password, in clear in this file. Never in a configuration held by the
    /// controllers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(ignore)]
    pub privacy_password: Option<SecretText>,
    /// A file that holds the privacy password. Never in a configuration held by the
    /// controllers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(ignore)]
    pub privacy_password_file: Option<PathBuf>,
    /// The operator secret of the vault that holds the privacy password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub privacy_secret: Option<SecretId>,
    /// The SNMPv3 context name (default empty).
    #[serde(default)]
    pub context: String,
}

const fn snmp_port() -> u16 {
    161
}

impl SnmpDevice {
    /// The address and port.
    pub fn socket(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

/// `[scan.snmp]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SnmpMethod {
    /// Runs on schedule (default true; needs at least one device).
    pub enabled: bool,
    /// Seconds between two polls (default 900).
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Milliseconds to wait for an answer (default 2000).
    pub timeout_ms: u64,
    /// Retries of an unanswered request (default 2).
    pub retries: u32,
    /// Reports clients on ports where an LLDP neighbour is seen (default false: those
    /// ports lead to other network devices, which report their own clients).
    pub attach_on_lldp_ports: bool,
    /// The switches.
    pub devices: Vec<SnmpDevice>,
}

impl Default for SnmpMethod {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 900,
            ttl_secs: None,
            timeout_ms: 2000,
            retries: 2,
            attach_on_lldp_ports: false,
            devices: Vec::new(),
        }
    }
}

/// A port in a raw-method port list: a single port, or a range `"a-b"` (inclusive). TOML
/// writes the list as a mixed array, such as `ports = [22, 80, "1-1024"]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
#[schema(as = ScanPortSpec)]
pub enum PortSpec {
    /// A single port.
    Single(u16),
    /// A range `"a-b"`, inclusive.
    Range(String),
}

/// Default ports for the SYN scan when none are configured: the connect-scan default set.
fn default_syn_ports() -> Vec<PortSpec> {
    DEFAULT_TCP_PORTS
        .iter()
        .map(|p| PortSpec::Single(*p))
        .collect()
}

/// Default ports for the fingerprint: a short set across remote access, web, file sharing
/// and directory, so most hosts answer at least one.
fn default_fingerprint_ports() -> Vec<PortSpec> {
    [22u16, 80, 135, 139, 443, 445, 3389]
        .iter()
        .map(|p| PortSpec::Single(*p))
        .collect()
}

/// Expands a port list to sorted, unique ports, failing on a bad range or an out-of-range
/// port. The result holds at most 65,535 ports.
///
/// # Errors
///
/// Returns [`ScanError`] when a port is 0 or out of range, or a range is malformed or
/// reversed.
pub fn expand_ports(specs: &[PortSpec], section: &str) -> Result<Vec<u16>, ScanError> {
    let mut ports = std::collections::BTreeSet::new();
    for spec in specs {
        match spec {
            PortSpec::Single(port) => {
                if *port == 0 {
                    return Err(ScanError::config(format!(
                        "scan.{section}.ports: 0 is not a port"
                    )));
                }
                ports.insert(*port);
            }
            PortSpec::Range(text) => {
                let (start, end) = text.split_once('-').ok_or_else(|| {
                    ScanError::config(format!(
                        "scan.{section}.ports: `{text}` is not a port or an `a-b` range"
                    ))
                })?;
                let start: u16 = start.trim().parse().map_err(|_| {
                    ScanError::config(format!("scan.{section}.ports: `{text}` has a bad start"))
                })?;
                let end: u16 = end.trim().parse().map_err(|_| {
                    ScanError::config(format!("scan.{section}.ports: `{text}` has a bad end"))
                })?;
                if start == 0 || start > end {
                    return Err(ScanError::config(format!(
                        "scan.{section}.ports: `{text}` is not a valid range (1 to 65535, a<=b)"
                    )));
                }
                ports.extend(start..=end);
            }
        }
    }
    Ok(ports.into_iter().collect())
}

/// `[scan.arp_sweep]`: an active ARP sweep over raw sockets (SCAN-04). Disabled by
/// default; needs `CAP_NET_RAW` on Linux and `active`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
#[schema(as = ScanArpSweepMethod)]
pub struct ArpSweepMethod {
    /// Runs on schedule (default false).
    pub enabled: bool,
    /// Seconds between two sweeps (default 3600).
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Milliseconds to wait for ARP replies after the last request (default 2000).
    pub timeout_ms: u64,
    /// The interface to sweep on; not set: the one the probe's address chooses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

impl Default for ArpSweepMethod {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 3600,
            ttl_secs: None,
            timeout_ms: 2000,
            interface: None,
        }
    }
}

/// `[scan.tcp_syn]`: a half-open TCP SYN scan over raw sockets (SCAN-04). The port list may
/// hold up to the full range of 65,535 ports, which the connect scan cannot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
#[schema(as = ScanTcpSynMethod)]
pub struct TcpSynMethod {
    /// Runs on schedule (default false; needs `active`).
    pub enabled: bool,
    /// Seconds between two scans (default 3600).
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// The ports, as single ports and `"a-b"` ranges (default [`DEFAULT_TCP_PORTS`]).
    pub ports: Vec<PortSpec>,
    /// `known` (default) or `all`.
    pub targets: TcpTargets,
    /// Milliseconds to wait for a reply after the last SYN (default 2000).
    pub timeout_ms: u64,
    /// The interface to scan on; not set: the one the probe's address chooses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

impl Default for TcpSynMethod {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 3600,
            ttl_secs: None,
            ports: default_syn_ports(),
            targets: TcpTargets::Known,
            timeout_ms: 2000,
            interface: None,
        }
    }
}

/// `[scan.os_fingerprint]`: passive and active-assisted OS fingerprinting (SCAN-04). It
/// SYNs a short port list and classifies the SYN-ACKs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
#[schema(as = ScanOsFingerprintMethod)]
pub struct OsFingerprintMethod {
    /// Runs on schedule (default false; needs `active`).
    pub enabled: bool,
    /// Seconds between two runs (default 3600).
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// A short port list to probe, as single ports and `"a-b"` ranges.
    pub ports: Vec<PortSpec>,
    /// Milliseconds to wait for a reply after the last SYN (default 2000).
    pub timeout_ms: u64,
    /// The interface to probe on; not set: the one the probe's address chooses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

impl Default for OsFingerprintMethod {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 3600,
            ttl_secs: None,
            ports: default_fingerprint_ports(),
            timeout_ms: 2000,
            interface: None,
        }
    }
}

/// `[scan.lldp]`: passive LLDP and CDP listening over raw sockets (SCAN-02, SCAN-05). It
/// sends nothing, so blackout windows do not hold it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
#[schema(as = ScanLldpMethod)]
pub struct LldpMethod {
    /// Runs on schedule (default false).
    pub enabled: bool,
    /// Seconds between two listens (default 3600).
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Seconds to listen for LLDP (and CDP) frames (default 35, one LLDP interval plus a
    /// margin; raised to at least 65 when `cdp` is on, since CDP sends every 60 seconds).
    pub listen_secs: u64,
    /// Also listen for CDP frames and parse them (default true).
    pub cdp: bool,
    /// The interface to listen on; not set: the one the probe's address chooses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

impl Default for LldpMethod {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 3600,
            ttl_secs: None,
            listen_secs: 35,
            cdp: true,
            interface: None,
        }
    }
}

impl LldpMethod {
    /// The listen window: `listen_secs`, but at least 65 seconds when CDP is on.
    pub fn window_secs(&self) -> u64 {
        if self.cdp {
            self.listen_secs.max(65)
        } else {
            self.listen_secs
        }
    }
}

/// `[scan.dhcp_snoop]`: passive DHCPv4 snooping over raw sockets (SCAN-03). It listens for
/// DISCOVER, REQUEST and ACK on UDP 67 and 68 and sends nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
#[schema(as = ScanDhcpSnoopMethod)]
pub struct DhcpSnoopMethod {
    /// Runs on schedule (default false).
    pub enabled: bool,
    /// Seconds between two listens (default 3600).
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Seconds to listen for DHCP frames in one run (default 120).
    pub listen_secs: u64,
    /// The interface to listen on; not set: the one the probe's address chooses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

impl Default for DhcpSnoopMethod {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 3600,
            ttl_secs: None,
            listen_secs: 120,
            interface: None,
        }
    }
}

impl ScanConfig {
    /// The schedule of a method.
    pub fn schedule(&self, kind: MethodKind) -> Schedule {
        let (enabled, interval_secs, ttl_secs) = match kind {
            MethodKind::Arp => return self.arp.schedule(),
            MethodKind::Nd => return self.nd.schedule(),
            MethodKind::Icmp => (
                self.icmp.enabled,
                self.icmp.interval_secs,
                self.icmp.ttl_secs,
            ),
            MethodKind::TcpConnect => (
                self.tcp_connect.enabled,
                self.tcp_connect.interval_secs,
                self.tcp_connect.ttl_secs,
            ),
            MethodKind::ReverseDns => (
                self.reverse_dns.enabled,
                self.reverse_dns.interval_secs,
                self.reverse_dns.ttl_secs,
            ),
            MethodKind::Mdns => (
                self.mdns.enabled,
                self.mdns.interval_secs,
                self.mdns.ttl_secs,
            ),
            MethodKind::Llmnr => (
                self.llmnr.enabled,
                self.llmnr.interval_secs,
                self.llmnr.ttl_secs,
            ),
            MethodKind::Snmp => (
                self.snmp.enabled,
                self.snmp.interval_secs,
                self.snmp.ttl_secs,
            ),
            MethodKind::ArpSweep => (
                self.arp_sweep.enabled,
                self.arp_sweep.interval_secs,
                self.arp_sweep.ttl_secs,
            ),
            MethodKind::TcpSyn => (
                self.tcp_syn.enabled,
                self.tcp_syn.interval_secs,
                self.tcp_syn.ttl_secs,
            ),
            MethodKind::OsFingerprint => (
                self.os_fingerprint.enabled,
                self.os_fingerprint.interval_secs,
                self.os_fingerprint.ttl_secs,
            ),
            MethodKind::Lldp => (
                self.lldp.enabled,
                self.lldp.interval_secs,
                self.lldp.ttl_secs,
            ),
            MethodKind::DhcpSnoop => (
                self.dhcp_snoop.enabled,
                self.dhcp_snoop.interval_secs,
                self.dhcp_snoop.ttl_secs,
            ),
        };
        Schedule {
            enabled,
            interval: Duration::from_secs(interval_secs),
            ttl: default_ttl(interval_secs, ttl_secs),
        }
    }

    /// The scope of the probe.
    ///
    /// # Errors
    ///
    /// `scan.config` for a prefix or exclusion that does not parse.
    pub fn scope(&self) -> Result<Scope, ScanError> {
        Scope::parse(&self.prefixes, &self.exclude, self.max_hosts_per_prefix)
    }

    /// The rate limits.
    pub fn pace_limits(&self) -> PaceLimits {
        PaceLimits {
            per_second: match self.packets_per_second {
                Some(0) => None,
                Some(rate) => Some(rate),
                None => self.rate.per_second(),
            },
            per_host_interval: Duration::from_millis(self.per_host_interval_ms),
            concurrency: self.concurrency,
        }
    }

    /// The blackout windows.
    ///
    /// # Errors
    ///
    /// `scan.config` for a window or a zone that does not parse.
    pub fn blackout(&self) -> Result<Blackout, ScanError> {
        Blackout::parse(&self.blackout, self.timezone.as_deref())
    }

    /// The VRF the batches name, if one is configured.
    ///
    /// # Errors
    ///
    /// `scan.config` when `vrf` is not a VRF id.
    pub fn vrf(&self) -> Result<Option<VrfId>, ScanError> {
        self.vrf
            .as_deref()
            .map(|text| {
                text.trim()
                    .parse::<VrfId>()
                    .map_err(|_| ScanError::config(format!("scan.vrf: `{text}` is not a VRF id")))
            })
            .transpose()
    }

    /// Checks every key of a probe's own file.
    ///
    /// # Errors
    ///
    /// `scan.config` naming the first key that is out of range.
    pub fn validate(&self) -> Result<(), ScanError> {
        self.validate_with(Credentials::Local)
    }

    fn validate_with(&self, credentials: Credentials) -> Result<(), ScanError> {
        self.scope()?;
        self.blackout()?;
        self.vrf()?;
        if self.concurrency == 0 || self.concurrency > 1024 {
            return Err(ScanError::config(
                "scan.concurrency must be between 1 and 1024",
            ));
        }
        if self.per_host_interval_ms > 60_000 {
            return Err(ScanError::config(
                "scan.per_host_interval_ms must be at most 60000",
            ));
        }
        if !(1..=65_536).contains(&self.max_hosts_per_prefix) {
            return Err(ScanError::config(
                "scan.max_hosts_per_prefix must be between 1 and 65536",
            ));
        }
        for kind in MethodKind::ALL {
            let schedule = self.schedule(kind);
            let secs = schedule.interval.as_secs();
            if !(30..=604_800).contains(&secs) {
                return Err(ScanError::config(format!(
                    "scan.{kind}.interval_secs must be between 30 and 604800"
                )));
            }
            if !(60..=2_592_000).contains(&schedule.ttl.as_secs()) {
                return Err(ScanError::config(format!(
                    "scan.{kind}.ttl_secs must be between 60 and 2592000"
                )));
            }
        }
        let timeouts = [
            ("icmp", self.icmp.timeout_ms),
            ("tcp_connect", self.tcp_connect.timeout_ms),
            ("reverse_dns", self.reverse_dns.timeout_ms),
            ("llmnr", self.llmnr.timeout_ms),
            ("snmp", self.snmp.timeout_ms),
            ("arp_sweep", self.arp_sweep.timeout_ms),
            ("tcp_syn", self.tcp_syn.timeout_ms),
            ("os_fingerprint", self.os_fingerprint.timeout_ms),
        ];
        for (name, timeout) in timeouts {
            if !(10..=60_000).contains(&timeout) {
                return Err(ScanError::config(format!(
                    "scan.{name}.timeout_ms must be between 10 and 60000"
                )));
            }
        }
        if self.tcp_connect.ports.is_empty()
            || self.tcp_connect.ports.len() > 1024
            || self.tcp_connect.ports.contains(&0)
        {
            return Err(ScanError::config(
                "scan.tcp_connect.ports must list 1 to 1024 ports between 1 and 65535",
            ));
        }
        for server in &self.reverse_dns.servers {
            parse_server(server)?;
        }
        if !(1..=60).contains(&self.mdns.listen_secs) {
            return Err(ScanError::config(
                "scan.mdns.listen_secs must be between 1 and 60",
            ));
        }
        self.mdns_group()?;
        let syn_ports = expand_ports(&self.tcp_syn.ports, "tcp_syn")?;
        if syn_ports.is_empty() {
            return Err(ScanError::config(
                "scan.tcp_syn.ports must list at least one port between 1 and 65535",
            ));
        }
        let fingerprint_ports = expand_ports(&self.os_fingerprint.ports, "os_fingerprint")?;
        if fingerprint_ports.is_empty() {
            return Err(ScanError::config(
                "scan.os_fingerprint.ports must list at least one port between 1 and 65535",
            ));
        }
        for (name, secs) in [
            ("lldp", self.lldp.listen_secs),
            ("dhcp_snoop", self.dhcp_snoop.listen_secs),
        ] {
            if !(1..=3600).contains(&secs) {
                return Err(ScanError::config(format!(
                    "scan.{name}.listen_secs must be between 1 and 3600"
                )));
            }
        }
        if self.snmp.retries > 10 {
            return Err(ScanError::config("scan.snmp.retries must be at most 10"));
        }
        for device in &self.snmp.devices {
            validate_device(device, credentials)?;
        }
        Ok(())
    }

    /// Checks a configuration that the controllers hold for a probe (`PUT
    /// /nodes/{id}/scan-config`, a probe's offer): every key as [`validate`](Self::validate),
    /// SNMP passwords only as vault secrets, and a device may still lack its secret.
    ///
    /// # Errors
    ///
    /// `scan.config` naming the first key that is out of range.
    pub fn validate_stored(&self) -> Result<(), ScanError> {
        self.validate_with(Credentials::Stored)
    }

    /// The configuration a probe offers the controllers as its initial one: this one with
    /// every SNMP password and password file removed (vault secrets stay), and the
    /// addresses of the devices that then lack a password, which an administrator has to
    /// give a vault secret.
    pub fn offer_form(&self) -> (ScanConfig, Vec<IpAddr>) {
        let mut offer = self.clone();
        let mut lacking = Vec::new();
        for device in &mut offer.snmp.devices {
            device.auth_password = None;
            device.auth_password_file = None;
            device.privacy_password = None;
            device.privacy_password_file = None;
            if !device.has_credentials() {
                lacking.push(device.address);
            }
        }
        (offer, lacking)
    }

    /// The vault secrets the configuration names, each once.
    pub fn secrets(&self) -> Vec<SecretId> {
        let mut secrets: Vec<SecretId> = self
            .snmp
            .devices
            .iter()
            .flat_map(SnmpDevice::secrets)
            .collect();
        secrets.sort_unstable_by_key(|secret| secret.uuid());
        secrets.dedup();
        secrets
    }

    /// The DNS servers of `reverse_dns` as socket addresses (port 53 unless given).
    ///
    /// # Errors
    ///
    /// `scan.config` for an entry that is not an address.
    pub fn dns_servers(&self) -> Result<Vec<SocketAddr>, ScanError> {
        self.reverse_dns
            .servers
            .iter()
            .map(|server| parse_server(server))
            .collect()
    }

    /// The destination of mDNS queries.
    ///
    /// # Errors
    ///
    /// `scan.config` when `scan.mdns.group` is not an address with a port.
    pub fn mdns_group(&self) -> Result<SocketAddr, ScanError> {
        self.mdns.group.parse().map_err(|_| {
            ScanError::config(format!(
                "scan.mdns.group: `{}` is not an address with a port, such as 224.0.0.251:5353",
                self.mdns.group
            ))
        })
    }
}

fn parse_server(text: &str) -> Result<SocketAddr, ScanError> {
    let text = text.trim();
    text.parse::<SocketAddr>()
        .ok()
        .or_else(|| {
            text.parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .ok_or_else(|| {
            ScanError::config(format!(
                "scan.reverse_dns.servers: `{text}` is not an address, such as 192.0.2.53"
            ))
        })
}

/// Where the passwords of a device may come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Credentials {
    /// A file of the probe: files, inline passwords or vault secrets, each required.
    Local,
    /// A configuration held by the controllers: vault secrets only; a device without one
    /// is kept but not polled until an administrator picks the secret.
    Stored,
}

fn validate_device(device: &SnmpDevice, credentials: Credentials) -> Result<(), ScanError> {
    let at = device.address;
    if device.user.trim().is_empty() || device.user.len() > 32 {
        return Err(ScanError::config(format!(
            "scan.snmp.devices ({at}): user must have 1 to 32 characters"
        )));
    }
    let sources = |inline: bool, file: bool, secret: bool| {
        usize::from(inline) + usize::from(file) + usize::from(secret)
    };
    let auth_sources = sources(
        device.auth_password.is_some(),
        device.auth_password_file.is_some(),
        device.auth_secret.is_some(),
    );
    let privacy_sources = sources(
        device.privacy_password.is_some(),
        device.privacy_password_file.is_some(),
        device.privacy_secret.is_some(),
    );
    if credentials == Credentials::Stored
        && (device.auth_password.is_some()
            || device.auth_password_file.is_some()
            || device.privacy_password.is_some()
            || device.privacy_password_file.is_some())
    {
        return Err(ScanError::config(format!(
            "scan.snmp.devices ({at}): a configuration held by the controllers names vault              secrets (auth_secret, privacy_secret), never passwords or password files"
        )));
    }
    if device.auth_secret.is_some() && auth_sources > 1 {
        return Err(ScanError::config(format!(
            "scan.snmp.devices ({at}): auth_secret cannot be combined with auth_password or              auth_password_file"
        )));
    }
    if device.privacy_secret.is_some() && privacy_sources > 1 {
        return Err(ScanError::config(format!(
            "scan.snmp.devices ({at}): privacy_secret cannot be combined with              privacy_password or privacy_password_file"
        )));
    }
    if device.auth.is_some() && auth_sources == 0 && credentials == Credentials::Local {
        return Err(ScanError::config(format!(
            "scan.snmp.devices ({at}): auth needs auth_password_file, auth_password or              auth_secret"
        )));
    }
    if device.privacy.is_some() {
        if device.auth.is_none() {
            return Err(ScanError::config(format!(
                "scan.snmp.devices ({at}): privacy needs auth (SNMPv3 has no privacy without                  authentication)"
            )));
        }
        if privacy_sources == 0 && credentials == Credentials::Local {
            return Err(ScanError::config(format!(
                "scan.snmp.devices ({at}): privacy needs privacy_password_file,                  privacy_password or privacy_secret"
            )));
        }
    }
    if device.port == 0 {
        return Err(ScanError::config(format!(
            "scan.snmp.devices ({at}): port must be between 1 and 65535"
        )));
    }
    Ok(())
}

impl SnmpDevice {
    /// Whether the device has every password its protocols need, so it can be polled; a
    /// device of a configuration held by the controllers may wait for its vault secret.
    pub fn has_credentials(&self) -> bool {
        let auth = self.auth_password.is_some()
            || self.auth_password_file.is_some()
            || self.auth_secret.is_some();
        let privacy = self.privacy_password.is_some()
            || self.privacy_password_file.is_some()
            || self.privacy_secret.is_some();
        (self.auth.is_none() || auth) && (self.privacy.is_none() || privacy)
    }

    /// The vault secrets the device names.
    pub fn secrets(&self) -> impl Iterator<Item = SecretId> {
        self.auth_secret.into_iter().chain(self.privacy_secret)
    }
}

/// The purpose under which a probe fetches SNMP secrets from the controllers.
pub const SNMP_SECRET_PURPOSE: &str = "snmp";

#[cfg(test)]
mod tests {
    use super::*;

    /// The section as JSON; the binary reads TOML through the same serde derive.
    fn parse(text: &str) -> ScanConfig {
        #[derive(Deserialize)]
        struct File {
            scan: ScanConfig,
        }
        let file: File = serde_json::from_str(text).expect("config");
        file.scan
    }

    #[test]
    fn defaults_are_valid_and_gentle() {
        let config = ScanConfig::default();
        config.validate().expect("valid");
        assert!(config.scope().expect("scope").is_empty());
        assert_eq!(config.pace_limits().per_second, Some(100));
        assert_eq!(
            config.schedule(MethodKind::Arp).interval,
            Duration::from_secs(300)
        );
        assert_eq!(
            config.schedule(MethodKind::Arp).ttl,
            Duration::from_secs(900)
        );
        assert_eq!(
            config.schedule(MethodKind::TcpConnect).ttl,
            Duration::from_secs(64_800)
        );
        assert!(!config.schedule(MethodKind::TcpSyn).enabled);
        assert!(config.vrf().expect("vrf").is_none());
    }

    #[test]
    fn rate_profiles_follow_tgl_19() {
        let mut config = ScanConfig {
            rate: RateProfile::Slowest,
            ..ScanConfig::default()
        };
        assert_eq!(config.pace_limits().per_second, Some(10));
        config.rate = RateProfile::Unlimited;
        assert_eq!(config.pace_limits().per_second, None);
        config.packets_per_second = Some(25);
        assert_eq!(config.pace_limits().per_second, Some(25));
        config.packets_per_second = Some(0);
        assert_eq!(config.pace_limits().per_second, None);
    }

    #[test]
    fn sections_parse_and_unknown_keys_are_refused() {
        let config = parse(
            r#"{"scan": {
                "prefixes": ["192.0.2.0/24"],
                "rate": "slow",
                "tcp_connect": {"ports": [22, 443], "targets": "all"},
                "snmp": {"devices": [{"address": "192.0.2.2", "user": "tenko",
                    "auth": "sha256", "auth_password": "example-auth-secret",
                    "privacy": "aes128", "privacy_password_file": "/etc/tenko/snmp-priv"}]}
            }}"#,
        );
        config.validate().expect("valid");
        assert_eq!(config.tcp_connect.ports, [22, 443]);
        assert_eq!(config.tcp_connect.targets, TcpTargets::All);
        let device = &config.snmp.devices[0];
        assert_eq!(device.port, 161);
        assert_eq!(
            device.auth_password.as_ref().map(SecretText::expose),
            Some("example-auth-secret")
        );
        let shown = serde_json::to_string(&config).expect("json");
        assert!(!shown.contains("example-auth-secret"), "{shown}");
        assert!(!format!("{config:?}").contains("example-auth-secret"));
        let error = serde_json::from_str::<ScanConfig>(r#"{"prefix": []}"#).expect_err("typo");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn out_of_range_values_name_their_key() {
        let cases: [(ScanConfig, &str); 6] = [
            (
                ScanConfig {
                    concurrency: 0,
                    ..ScanConfig::default()
                },
                "scan.concurrency",
            ),
            (
                ScanConfig {
                    arp: BasicMethod::every(5),
                    ..ScanConfig::default()
                },
                "scan.arp.interval_secs",
            ),
            (
                ScanConfig {
                    prefixes: vec!["192.0.2.0/40".to_owned()],
                    ..ScanConfig::default()
                },
                "scan.prefixes",
            ),
            (
                ScanConfig {
                    tcp_connect: TcpConnectMethod {
                        ports: vec![0],
                        ..TcpConnectMethod::default()
                    },
                    ..ScanConfig::default()
                },
                "scan.tcp_connect.ports",
            ),
            (
                ScanConfig {
                    vrf: Some("default".to_owned()),
                    ..ScanConfig::default()
                },
                "scan.vrf",
            ),
            (
                ScanConfig {
                    reverse_dns: ReverseDnsMethod {
                        servers: vec!["dns.example.net".to_owned()],
                        ..ReverseDnsMethod::default()
                    },
                    ..ScanConfig::default()
                },
                "scan.reverse_dns.servers",
            ),
        ];
        for (config, key) in cases {
            let error = config.validate().expect_err(key);
            assert_eq!(error.code(), "scan.config");
            assert!(error.detail().contains(key), "{key}: {}", error.detail());
        }
    }

    #[test]
    fn snmp_devices_need_their_passwords() {
        let device = SnmpDevice {
            address: "192.0.2.2".parse().expect("ip"),
            port: 161,
            name: None,
            user: "tenko".to_owned(),
            auth: None,
            auth_password: None,
            auth_password_file: None,
            privacy: Some(SnmpPrivacy::Aes128),
            privacy_password: Some(SecretText::new("example-priv-secret")),
            privacy_password_file: None,
            privacy_secret: None,
            auth_secret: None,
            context: String::new(),
        };
        let error = validate_device(&device, Credentials::Local).expect_err("privacy without auth");
        assert!(error.detail().contains("privacy needs auth"));
        let device = SnmpDevice {
            auth: Some(SnmpAuth::Sha1),
            ..device
        };
        assert!(
            validate_device(&device, Credentials::Local)
                .expect_err("no password")
                .detail()
                .contains("auth_password")
        );
    }

    fn vault_device() -> SnmpDevice {
        SnmpDevice {
            address: "192.0.2.3".parse().expect("ip"),
            port: 161,
            name: None,
            user: "tenko".to_owned(),
            auth: Some(SnmpAuth::Sha256),
            auth_password: None,
            auth_password_file: None,
            auth_secret: Some(SecretId::generate()),
            privacy: Some(SnmpPrivacy::Aes128),
            privacy_password: None,
            privacy_password_file: None,
            privacy_secret: Some(SecretId::generate()),
            context: String::new(),
        }
    }

    #[test]
    fn vault_secrets_are_a_password_source_of_their_own() {
        let device = vault_device();
        validate_device(&device, Credentials::Local).expect("local");
        validate_device(&device, Credentials::Stored).expect("stored");
        assert!(device.has_credentials());
        assert_eq!(device.secrets().count(), 2);
        let both = SnmpDevice {
            auth_password_file: Some(PathBuf::from("/etc/tenko/snmp-auth")),
            ..device.clone()
        };
        assert!(
            validate_device(&both, Credentials::Local)
                .expect_err("two sources")
                .detail()
                .contains("cannot be combined")
        );
    }

    #[test]
    fn a_stored_configuration_names_vault_secrets_only() {
        let mut config = ScanConfig::default();
        config.snmp.devices.push(vault_device());
        config.validate_stored().expect("vault secrets");
        // A device still waiting for its secret is kept, but cannot be polled yet.
        let waiting = SnmpDevice {
            auth_secret: None,
            privacy_secret: None,
            ..vault_device()
        };
        config.snmp.devices.push(waiting.clone());
        config.validate_stored().expect("waiting for its secret");
        assert!(config.validate().is_err(), "a file needs every password");
        assert!(!waiting.has_credentials());
        // Inline passwords and password files are refused.
        for device in [
            SnmpDevice {
                auth_password: Some(SecretText::new("example-auth-secret")),
                auth_secret: None,
                ..vault_device()
            },
            SnmpDevice {
                privacy_password_file: Some(PathBuf::from("/etc/tenko/snmp-priv")),
                privacy_secret: None,
                ..vault_device()
            },
        ] {
            let mut config = ScanConfig::default();
            config.snmp.devices.push(device);
            let error = config.validate_stored().expect_err("password");
            assert!(error.detail().contains("vault"), "{}", error.detail());
        }
    }

    #[test]
    fn an_offer_leaves_the_passwords_on_the_probe() {
        let mut config = ScanConfig::default();
        config.snmp.devices.push(SnmpDevice {
            address: "192.0.2.4".parse().expect("ip"),
            port: 161,
            name: None,
            user: "tenko".to_owned(),
            auth: Some(SnmpAuth::Sha1),
            auth_password: Some(SecretText::new("example-auth-secret")),
            auth_password_file: None,
            auth_secret: None,
            privacy: None,
            privacy_password: None,
            privacy_password_file: None,
            privacy_secret: None,
            context: String::new(),
        });
        config.snmp.devices.push(vault_device());
        let (offer, lacking) = config.offer_form();
        assert_eq!(lacking, vec!["192.0.2.4".parse::<IpAddr>().expect("ip")]);
        assert!(
            offer
                .snmp
                .devices
                .iter()
                .all(|device| device.auth_password.is_none())
        );
        offer
            .validate_stored()
            .expect("the offer validates as a stored configuration");
        assert_eq!(offer.secrets().len(), 2);
        let encoded = serde_json::to_string(&offer).expect("json");
        assert!(!encoded.contains("example-auth-secret"));
    }
}
