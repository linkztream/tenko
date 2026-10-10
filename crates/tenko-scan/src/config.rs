//! The `[scan]` section of `tenko.toml`: what a probe scans, how fast and when.
//!
//! The probe reads its own configuration file for now; the controller hands the scan
//! configuration to its probes with the configuration sync of a later package (WP3.1).
//! Every key has a default, so an empty section is valid; without `prefixes` the scanner
//! scans nothing, because scans never leave the configured prefixes.
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
use tenko_core::VrfId;
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// ARP sweep over raw sockets (declared; not implemented yet).
    pub arp_sweep: RawMethod,
    /// TCP SYN scan over raw sockets (declared; not implemented yet).
    pub tcp_syn: RawMethod,
    /// OS fingerprinting over raw sockets (declared; not implemented yet).
    pub os_fingerprint: RawMethod,
    /// LLDP listening over raw sockets (declared; not implemented yet).
    pub lldp: RawMethod,
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
            arp_sweep: RawMethod::default(),
            tcp_syn: RawMethod::default(),
            os_fingerprint: RawMethod::default(),
            lldp: RawMethod::default(),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpTargets {
    /// The addresses the other methods of this probe saw (default).
    #[default]
    Known,
    /// Every address of the prefixes that a sweep enumerates, and the known addresses.
    All,
}

/// `[scan.tcp_connect]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnmpPrivacy {
    /// AES-128-CFB (RFC 3826).
    Aes128,
}

/// One switch to poll.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnmpDevice {
    /// Its management address.
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
    /// The authentication password, in clear in this file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_password: Option<SecretText>,
    /// A file that holds the authentication password (preferred over `auth_password`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_password_file: Option<PathBuf>,
    /// The privacy protocol; not set: no encryption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<SnmpPrivacy>,
    /// The privacy password, in clear in this file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_password: Option<SecretText>,
    /// A file that holds the privacy password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_password_file: Option<PathBuf>,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// A raw-socket method: declared, switched off, not implemented yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawMethod {
    /// Runs on schedule once implemented (default false).
    pub enabled: bool,
    /// Seconds between two runs (default 3600).
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

impl Default for RawMethod {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 3600,
            ttl_secs: None,
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
            MethodKind::ArpSweep => raw(&self.arp_sweep),
            MethodKind::TcpSyn => raw(&self.tcp_syn),
            MethodKind::OsFingerprint => raw(&self.os_fingerprint),
            MethodKind::Lldp => raw(&self.lldp),
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

    /// Checks every key.
    ///
    /// # Errors
    ///
    /// `scan.config` naming the first key that is out of range.
    pub fn validate(&self) -> Result<(), ScanError> {
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
        if self.snmp.retries > 10 {
            return Err(ScanError::config("scan.snmp.retries must be at most 10"));
        }
        for device in &self.snmp.devices {
            validate_device(device)?;
        }
        Ok(())
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

fn raw(method: &RawMethod) -> (bool, u64, Option<u64>) {
    (method.enabled, method.interval_secs, method.ttl_secs)
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

fn validate_device(device: &SnmpDevice) -> Result<(), ScanError> {
    let at = device.address;
    if device.user.trim().is_empty() || device.user.len() > 32 {
        return Err(ScanError::config(format!(
            "scan.snmp.devices ({at}): user must have 1 to 32 characters"
        )));
    }
    if device.auth.is_some()
        && device.auth_password.is_none()
        && device.auth_password_file.is_none()
    {
        return Err(ScanError::config(format!(
            "scan.snmp.devices ({at}): auth needs auth_password_file or auth_password"
        )));
    }
    if device.privacy.is_some() {
        if device.auth.is_none() {
            return Err(ScanError::config(format!(
                "scan.snmp.devices ({at}): privacy needs auth (SNMPv3 has no privacy without \
                 authentication)"
            )));
        }
        if device.privacy_password.is_none() && device.privacy_password_file.is_none() {
            return Err(ScanError::config(format!(
                "scan.snmp.devices ({at}): privacy needs privacy_password_file or \
                 privacy_password"
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
            context: String::new(),
        };
        let error = validate_device(&device).expect_err("privacy without auth");
        assert!(error.detail().contains("privacy needs auth"));
        let device = SnmpDevice {
            auth: Some(SnmpAuth::Sha1),
            ..device
        };
        assert!(
            validate_device(&device)
                .expect_err("no password")
                .detail()
                .contains("auth_password")
        );
    }
}
