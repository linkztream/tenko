//! `[dhcp]`: the node-local settings of the `dhcp` role (WP7.5, `docs/dhcp-contracts.md`
//! section 9, `docs/dhcp.md` section 10). The replicated settings of the service (lease
//! times, options, the history days of the installation) are `dhcp.settings` in the store.
//!
//! WP9.1: a `listen` entry with an IPv6 address is a DHCPv6 listener on `[dhcp.v6] port`
//! (547); `[dhcp.v6]` holds the DHCPv6 ports and the server's DUID.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, SocketAddrV6};

use serde::{Deserialize, Deserializer, Serialize, de};

use super::ConfigError;

/// How a listener receives (plan section 2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DhcpListenMode {
    /// The unicast address: relayed (and unicast) traffic only.
    #[default]
    Relay,
    /// The interface: the broadcasts of clients on the link as well.
    Direct,
}

/// One entry of `[dhcp] listen`: a table, or an address alone for relay mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DhcpListen {
    /// The interface's unicast address: IPv4 for DHCPv4 on `port`, IPv6 for DHCPv6 on
    /// `[dhcp.v6] port` (WP9.1).
    pub address: IpAddr,
    /// Relay (default) or direct.
    pub mode: DhcpListenMode,
    /// The interface of a direct listener (Linux binds to it with `SO_BINDTODEVICE` and
    /// sends link-layer replies through it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListenTable {
    address: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    interface: Option<String>,
}

fn mode<E: de::Error>(text: Option<&str>) -> Result<DhcpListenMode, E> {
    match text.map(str::trim) {
        None | Some("relay") => Ok(DhcpListenMode::Relay),
        Some("direct") => Ok(DhcpListenMode::Direct),
        Some(other) => Err(E::custom(format!(
            "dhcp.listen: mode `{other}` is not relay or direct"
        ))),
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ListenEntry {
    Address(String),
    Table(ListenTable),
}

fn address<E: de::Error>(text: &str) -> Result<IpAddr, E> {
    text.trim().parse().map_err(|_| {
        E::custom(format!(
            "dhcp.listen: `{text}` is not an IP address such as 192.0.2.10 or 2001:db8::10"
        ))
    })
}

impl<'de> Deserialize<'de> for DhcpListen {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match ListenEntry::deserialize(deserializer)? {
            ListenEntry::Address(text) => Ok(Self {
                address: address(&text)?,
                mode: DhcpListenMode::Relay,
                interface: None,
            }),
            ListenEntry::Table(table) => Ok(Self {
                address: address(&table.address)?,
                mode: mode(table.mode.as_deref())?,
                interface: table
                    .interface
                    .map(|name| name.trim().to_owned())
                    .filter(|name| !name.is_empty()),
            }),
        }
    }
}

/// `[dhcp.probe]`: the conflict probe (WP8.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpProbeSection {
    /// The probe's cap in milliseconds, 10 to 1,000 (default 300, P3-Q7).
    pub timeout_ms: u64,
    /// How long a clean probe result is kept, 0 to 86,400 seconds (default 600).
    pub cache_secs: u64,
    // WP8.5: the size of the pending table.
    /// Offers that may wait for a probe at once, 16 to 65,536 (default 1,024); beyond, an
    /// offer goes out unprobed.
    pub pending: usize,
}

impl Default for DhcpProbeSection {
    fn default() -> Self {
        Self {
            timeout_ms: 300,
            cache_secs: 600,
            pending: 1_024,
        }
    }
}

/// `[dhcp.decline]`: what a DECLINE does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpDeclineSection {
    /// How long a declined address stays abandoned, 60 to 2,592,000 seconds (default one
    /// day).
    pub hold_secs: u32,
    // WP8.5: the per-client DECLINE limit.
    /// DECLINEs one client may send per window before more are dropped, 0 to 100 (default
    /// 3), so that a broken client cannot drain a pool.
    pub limit: u32,
    /// The window of the limit, 60 to 86,400 seconds (default 3,600).
    pub window_secs: u64,
}

impl Default for DhcpDeclineSection {
    fn default() -> Self {
        Self {
            hold_secs: 86_400,
            limit: 3,
            window_secs: 3_600,
        }
    }
}

/// `[dhcp.ddns]`: the DDNS worker's retries (WP8.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpDdnsSection {
    /// Retries of a change set, 0 to 20 (default 5).
    pub retries: u32,
    /// The first backoff in milliseconds, 10 to 60,000 (default 1,000).
    pub backoff_ms: u64,
}

impl Default for DhcpDdnsSection {
    fn default() -> Self {
        Self {
            retries: 5,
            backoff_ms: 1_000,
        }
    }
}

/// `[dhcp.history]`: the lease history of this node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpHistorySection {
    /// Days of history kept, 1 to 3,650; unset: the installation's setting, else the
    /// profile's default (Home 30, Standard and Hardened 90, Lab 7; P3-Q13).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days: Option<u32>,
}

// WP9.1: the DHCPv6 side of the role.
/// `[dhcp.v6]`: the DHCPv6 listeners' ports and the server's identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpV6Section {
    /// The DHCPv6 server port (default 547).
    pub port: u16,
    /// The port replies to relay agents go to (default 547).
    pub relay_port: u16,
    /// The port replies to clients go to (default 546).
    pub client_port: u16,
    /// The server's DUID in hexadecimal (option 2, RFC 8415 section 11), 3 to 130 octets;
    /// unset: a DUID-UUID derived from the node identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_duid: Option<String>,
}

impl Default for DhcpV6Section {
    fn default() -> Self {
        Self {
            port: 547,
            relay_port: 547,
            client_port: 546,
            server_duid: None,
        }
    }
}

impl DhcpV6Section {
    /// The configured server DUID as octets, when it is set and valid.
    pub fn server_duid_octets(&self) -> Option<Vec<u8>> {
        let text: String = self
            .server_duid
            .as_deref()?
            .chars()
            .filter(|c| !matches!(c, ':' | '-' | ' '))
            .collect();
        if !text.len().is_multiple_of(2) {
            return None;
        }
        let octets: Option<Vec<u8>> = (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
            .collect();
        octets.filter(|octets| (3..=130).contains(&octets.len()))
    }
}

/// `[dhcp]`: the `dhcp` role of this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpSection {
    /// The listeners: `{ address, mode = "relay" | "direct", interface }`, or an address
    /// alone for relay mode. Empty (the default): the role builds its tables and answers
    /// nothing, and the health view says so.
    pub listen: Vec<DhcpListen>,
    /// The server port (default 67).
    pub port: u16,
    /// UDP workers per listener, 0 to 64; 0 (the default) is one per CPU, at most 8.
    pub workers: usize,
    /// How long an offer holds its address in memory, 1 to 300 seconds (default 10).
    pub offer_secs: u32,
    /// The port replies to relay agents go to (default 67; tests and labs use another).
    pub relay_port: u16,
    /// The port replies to clients go to (default 68).
    pub client_port: u16,
    /// The conflict probe.
    pub probe: DhcpProbeSection,
    /// DECLINE.
    pub decline: DhcpDeclineSection,
    /// DDNS retries.
    pub ddns: DhcpDdnsSection,
    /// The lease history.
    pub history: DhcpHistorySection,
    // WP8.4: proxy DHCP (DHCP-05, P3-Q16).
    /// The addresses of proxy DHCP listeners: boot clients get their boot information there
    /// and no address (PXE boot server discovery). Empty (the default): none.
    pub proxy: Vec<Ipv4Addr>,
    /// The proxy DHCP port (default 4011, the PXE boot server port).
    pub proxy_port: u16,
    // WP9.1: the DHCPv6 ports and the server's DUID.
    /// DHCPv6.
    pub v6: DhcpV6Section,
}

impl Default for DhcpSection {
    fn default() -> Self {
        Self {
            listen: Vec::new(),
            port: 67,
            workers: 0,
            offer_secs: 10,
            relay_port: 67,
            client_port: 68,
            probe: DhcpProbeSection::default(),
            decline: DhcpDeclineSection::default(),
            ddns: DhcpDdnsSection::default(),
            history: DhcpHistorySection::default(),
            proxy: Vec::new(),
            proxy_port: 4011,
            v6: DhcpV6Section::default(),
        }
    }
}

impl DhcpSection {
    /// The workers per listener: the setting, or one per CPU up to 8.
    pub fn worker_count(&self) -> usize {
        if self.workers == 0 {
            std::thread::available_parallelism()
                .map_or(1, std::num::NonZeroUsize::get)
                .min(8)
        } else {
            self.workers
        }
    }

    /// The socket address of a listener: the DHCPv4 port for an IPv4 address, the
    /// DHCPv6 port for an IPv6 one.
    pub fn socket_addr(&self, listen: &DhcpListen) -> std::net::SocketAddr {
        match listen.address {
            IpAddr::V4(address) => SocketAddrV4::new(address, self.port).into(),
            IpAddr::V6(address) => SocketAddrV6::new(address, self.v6.port, 0, 0).into(),
        }
    }

    // WP8.4: the proxy DHCP listeners.
    fn validate_proxy(&self) -> Result<(), ConfigError> {
        let check = |ok: bool, message: String| {
            if ok {
                Ok(())
            } else {
                Err(ConfigError::invalid(message))
            }
        };
        for (index, address) in self.proxy.iter().enumerate() {
            check(
                !address.is_unspecified() && !address.is_broadcast() && !address.is_multicast(),
                format!(
                    "dhcp.proxy[{index}]: {address} is not a unicast address; name the \
                     interface's address"
                ),
            )?;
            check(
                !self.proxy.iter().take(index).any(|other| other == address),
                format!("dhcp.proxy[{index}]: {address} is listed twice"),
            )?;
            check(
                self.proxy_port != self.port
                    || !self
                        .listen
                        .iter()
                        .any(|l| l.address == IpAddr::V4(*address)),
                format!(
                    "dhcp.proxy[{index}]: {address} listens on dhcp.port already; give \
                     dhcp.proxy_port another port (4011)"
                ),
            )?;
        }
        check(
            self.proxy_port > 0,
            "dhcp.proxy_port must be between 1 and 65535".to_owned(),
        )
    }

    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        fn check(ok: bool, message: &str) -> Result<(), ConfigError> {
            if ok {
                Ok(())
            } else {
                Err(ConfigError::invalid(message.to_owned()))
            }
        }
        for (index, listen) in self.listen.iter().enumerate() {
            let address = listen.address;
            let broadcast = matches!(address, IpAddr::V4(v4) if v4.is_broadcast());
            check(
                !address.is_unspecified() && !broadcast && !address.is_multicast(),
                &format!(
                    "dhcp.listen[{index}]: {address} is not a unicast address; name the \
                     interface's address"
                ),
            )?;
            check(
                listen.mode == DhcpListenMode::Direct || listen.interface.is_none(),
                &format!(
                    "dhcp.listen[{index}]: interface is for direct mode; a relay listener \
                     binds its address"
                ),
            )?;
            if let Some(name) = &listen.interface {
                check(
                    name.len() <= 15 && !name.contains(['/', ' ']),
                    &format!("dhcp.listen[{index}]: `{name}` is not an interface name"),
                )?;
            }
            let same = self
                .listen
                .iter()
                .take(index)
                .any(|other| other.address == address);
            check(
                !same,
                &format!("dhcp.listen[{index}]: {address} is listed twice"),
            )?;
        }
        // WP8.4: the proxy DHCP listeners.
        self.validate_proxy()?;
        check(self.port > 0, "dhcp.port must be between 1 and 65535")?;
        check(
            self.relay_port > 0 && self.client_port > 0,
            "dhcp.relay_port and dhcp.client_port must be between 1 and 65535",
        )?;
        check(self.workers <= 64, "dhcp.workers must be between 0 and 64")?;
        check(
            (1..=300).contains(&self.offer_secs),
            "dhcp.offer_secs must be between 1 and 300",
        )?;
        check(
            (10..=1_000).contains(&self.probe.timeout_ms),
            "dhcp.probe.timeout_ms must be between 10 and 1000",
        )?;
        check(
            self.probe.cache_secs <= 86_400,
            "dhcp.probe.cache_secs must be between 0 and 86400",
        )?;
        check(
            (60..=2_592_000).contains(&self.decline.hold_secs),
            "dhcp.decline.hold_secs must be between 60 and 2592000",
        )?;
        // WP8.5: the pending table and the DECLINE limit.
        check(
            (16..=65_536).contains(&self.probe.pending),
            "dhcp.probe.pending must be between 16 and 65536",
        )?;
        check(
            self.decline.limit <= 100,
            "dhcp.decline.limit must be between 0 and 100",
        )?;
        check(
            (60..=86_400).contains(&self.decline.window_secs),
            "dhcp.decline.window_secs must be between 60 and 86400",
        )?;
        check(
            self.ddns.retries <= 20,
            "dhcp.ddns.retries must be between 0 and 20",
        )?;
        check(
            (10..=60_000).contains(&self.ddns.backoff_ms),
            "dhcp.ddns.backoff_ms must be between 10 and 60000",
        )?;
        check(
            self.history
                .days
                .is_none_or(|days| (1..=3_650).contains(&days)),
            "dhcp.history.days must be between 1 and 3650",
        )?;
        // WP9.1: the DHCPv6 ports and DUID.
        check(
            self.v6.port > 0 && self.v6.relay_port > 0 && self.v6.client_port > 0,
            "dhcp.v6.port, dhcp.v6.relay_port and dhcp.v6.client_port must be between 1 and 65535",
        )?;
        check(
            self.v6.server_duid.is_none() || self.v6.server_duid_octets().is_some(),
            "dhcp.v6.server_duid must be 3 to 130 octets in hexadecimal",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<DhcpSection, String> {
        let section: DhcpSection = toml::from_str(text).map_err(|error| error.to_string())?;
        section.validate().map_err(|error| error.to_string())?;
        Ok(section)
    }

    #[test]
    fn listeners_are_tables_or_addresses() {
        let section = parse(
            "listen = [\"192.0.2.10\", { address = \"198.51.100.1\", mode = \"direct\", \
             interface = \"eth1\" }]\nworkers = 2\n",
        )
        .expect("valid");
        assert_eq!(section.listen.len(), 2);
        assert_eq!(section.listen[0].mode, DhcpListenMode::Relay);
        assert_eq!(section.listen[1].mode, DhcpListenMode::Direct);
        assert_eq!(section.listen[1].interface.as_deref(), Some("eth1"));
        assert_eq!(
            section.socket_addr(&section.listen[0]),
            "192.0.2.10:67".parse().expect("address")
        );
        assert_eq!(section.worker_count(), 2);
    }

    #[test]
    fn the_defaults_are_the_contracts() {
        let section = parse("").expect("valid");
        assert_eq!(section.listen.len(), 0);
        assert_eq!(
            (
                section.port,
                section.offer_secs,
                section.relay_port,
                section.client_port
            ),
            (67, 10, 67, 68)
        );
        assert_eq!(section.probe.timeout_ms, 300);
        assert_eq!(section.probe.cache_secs, 600);
        assert_eq!(section.decline.hold_secs, 86_400);
        // WP8.5: the pending table and the DECLINE limit.
        assert_eq!(section.probe.pending, 1_024);
        assert_eq!(
            (section.decline.limit, section.decline.window_secs),
            (3, 3_600)
        );
        assert_eq!(section.history.days, None);
        assert!((1..=8).contains(&section.worker_count()));
    }

    #[test]
    fn bad_values_are_refused_with_their_key() {
        for (text, key) in [
            ("listen = [\"0.0.0.0\"]", "dhcp.listen[0]"),
            ("listen = [\"192.0.2.300\"]", "dhcp.listen"),
            // WP9.1: an IPv6 address is a DHCPv6 listener; a multicast one is not.
            ("listen = [\"ff02::1:2\"]", "dhcp.listen[0]"),
            ("[v6]\nserver_duid = \"0001\"", "dhcp.v6.server_duid"),
            ("[v6]\nport = 0", "dhcp.v6.port"),
            (
                "listen = [{ address = \"192.0.2.1\", interface = \"eth0\" }]",
                "interface is for direct mode",
            ),
            ("listen = [\"192.0.2.1\", \"192.0.2.1\"]", "listed twice"),
            (
                "listen = [{ address = \"192.0.2.1\", mode = \"other\" }]",
                "mode `other` is not relay or direct",
            ),
            ("offer_secs = 0", "dhcp.offer_secs"),
            ("workers = 65", "dhcp.workers"),
            ("port = 0", "dhcp.port"),
            ("[probe]\ntimeout_ms = 5", "dhcp.probe.timeout_ms"),
            ("[decline]\nhold_secs = 1", "dhcp.decline.hold_secs"),
            // WP8.5: the pending table and the DECLINE limit.
            ("[probe]\npending = 1", "dhcp.probe.pending"),
            ("[decline]\nlimit = 101", "dhcp.decline.limit"),
            ("[decline]\nwindow_secs = 1", "dhcp.decline.window_secs"),
            ("[ddns]\nretries = 99", "dhcp.ddns.retries"),
            ("[history]\ndays = 0", "dhcp.history.days"),
            // WP8.4: the proxy DHCP listeners.
            ("proxy = [\"0.0.0.0\"]", "dhcp.proxy[0]"),
            ("proxy = [\"192.0.2.1\", \"192.0.2.1\"]", "listed twice"),
            (
                "listen = [\"192.0.2.1\"]\nproxy = [\"192.0.2.1\"]\nproxy_port = 67",
                "dhcp.proxy_port",
            ),
            ("proxy_port = 0", "dhcp.proxy_port"),
            ("unknown = 1", "unknown"),
        ] {
            let error = parse(text).expect_err(text);
            assert!(error.contains(key), "{text}: {error}");
        }
    }

    // WP8.4: the proxy DHCP listeners on port 4011 by default.
    #[test]
    fn proxy_listeners_default_to_the_pxe_boot_server_port() {
        let section = parse("listen = [\"192.0.2.1\"]\nproxy = [\"192.0.2.1\"]").expect("valid");
        assert_eq!(section.proxy, vec![Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(section.proxy_port, 4011);
        assert_eq!(DhcpSection::default().proxy, Vec::<Ipv4Addr>::new());
    }
}
