//! Trusted reverse proxies (OPS-22 mode c).

use std::{fmt, net::IpAddr, str::FromStr};

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};

use super::TlsError;

/// The addresses allowed to send forwarded headers (`X-Forwarded-For`, `-Proto`, `-Host`)
/// or the PROXY protocol. Everything else is refused (OPS-22). Empty trusts nobody.
///
/// Entries are networks (`10.0.0.0/8`, `2001:db8::/32`) or single addresses (`192.0.2.7`,
/// taken as `/32` or `/128`). IPv4-mapped IPv6 peers (`::ffff:192.0.2.7`, as a dual-stack
/// listener reports them) match their IPv4 entries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct TrustedProxies(Vec<IpNet>);

impl TrustedProxies {
    /// Trusts the given networks.
    pub fn new(networks: impl IntoIterator<Item = IpNet>) -> Self {
        Self(networks.into_iter().map(|net| net.trunc()).collect())
    }

    /// Parses entries (networks or single addresses).
    ///
    /// # Errors
    ///
    /// [`TlsError::InvalidProxy`] naming the first bad entry.
    pub fn parse<S: AsRef<str>>(entries: impl IntoIterator<Item = S>) -> Result<Self, TlsError> {
        entries
            .into_iter()
            .map(|entry| parse_entry(entry.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map(Self::new)
    }

    /// Whether a peer address may send forwarded headers.
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        self.0.iter().any(|net| net.contains(&ip))
    }

    /// Whether no address is trusted.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The trusted networks.
    pub fn networks(&self) -> &[IpNet] {
        &self.0
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn parse_entry(entry: &str) -> Result<IpNet, TlsError> {
    let entry = entry.trim();
    let invalid = || TlsError::InvalidProxy {
        entry: entry.to_owned(),
    };
    if entry.contains('/') {
        let net: IpNet = entry.parse().map_err(|_| invalid())?;
        // A mapped IPv6 network is stored as its IPv4 network so peers match canonically.
        if let IpNet::V6(v6) = net
            && let Some(v4) = v6.addr().to_ipv4_mapped()
            && v6.prefix_len() >= 96
        {
            return IpNet::new(IpAddr::V4(v4), v6.prefix_len() - 96).map_err(|_| invalid());
        }
        Ok(net)
    } else {
        let ip: IpAddr = entry.parse().map_err(|_| invalid())?;
        Ok(IpNet::from(canonical(ip)))
    }
}

impl FromStr for TrustedProxies {
    type Err = TlsError;

    /// Parses a comma- or whitespace-separated list.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(
            s.split(|c: char| c == ',' || c.is_whitespace())
                .filter(|entry| !entry.is_empty()),
        )
    }
}

impl fmt::Display for TrustedProxies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, net) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{net}")?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for TrustedProxies {
    /// Accepts a list of strings, so single addresses work in configuration files.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = Vec::<String>::deserialize(deserializer)?;
        Self::parse(entries).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn networks_and_single_addresses() {
        let proxies: TrustedProxies = "10.0.0.0/8, 192.0.2.7 2001:db8::/32"
            .parse()
            .expect("parse");
        assert!(proxies.is_trusted(ip("10.200.1.1")));
        assert!(proxies.is_trusted(ip("192.0.2.7")));
        assert!(!proxies.is_trusted(ip("192.0.2.8")));
        assert!(proxies.is_trusted(ip("2001:db8::1")));
        assert!(!proxies.is_trusted(ip("2001:db9::1")));
        assert!(!proxies.is_trusted(ip("11.0.0.1")));
    }

    #[test]
    fn mapped_ipv6_peers_match_ipv4_entries() {
        let proxies =
            TrustedProxies::parse(["192.0.2.7", "::ffff:198.51.100.0/120"]).expect("parse");
        assert!(proxies.is_trusted(ip("::ffff:192.0.2.7")));
        assert!(proxies.is_trusted(ip("198.51.100.20")));
        assert!(proxies.is_trusted(ip("::ffff:198.51.100.20")));
        assert!(!proxies.is_trusted(ip("::ffff:192.0.2.8")));
    }

    #[test]
    fn empty_trusts_nobody() {
        let proxies = TrustedProxies::default();
        assert!(proxies.is_empty());
        assert!(!proxies.is_trusted(ip("127.0.0.1")));
        assert!(!proxies.is_trusted(ip("::1")));
    }

    #[test]
    fn bad_entries_are_named() {
        assert_eq!(
            TrustedProxies::parse(["10.0.0.0/8", "proxy.example"]).expect_err("bad"),
            TlsError::InvalidProxy {
                entry: "proxy.example".to_owned()
            }
        );
        assert!(TrustedProxies::parse(["10.0.0.0/33"]).is_err());
    }

    #[test]
    fn host_bits_are_truncated_and_serde_round_trips() {
        let proxies = TrustedProxies::parse(["10.1.2.3/8"]).expect("parse");
        assert_eq!(proxies.to_string(), "10.0.0.0/8");
        let json = serde_json::to_string(&proxies).expect("json");
        assert_eq!(json, r#"["10.0.0.0/8"]"#);
        let back: TrustedProxies =
            serde_json::from_str(r#"["10.0.0.0/8","192.0.2.1"]"#).expect("json");
        assert!(back.is_trusted(ip("192.0.2.1")));
        assert!(serde_json::from_str::<TrustedProxies>(r#"["nope"]"#).is_err());
    }
}
