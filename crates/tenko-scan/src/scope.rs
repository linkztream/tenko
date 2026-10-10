//! The scan scope: the prefixes a probe may look at, minus the exclusions. Scans never leave
//! it: every method filters what it reports through [`Scope::contains`], and the active
//! methods only probe addresses that [`Scope::hosts`] or [`Scope::contains`] allow.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::{IpNet, Ipv4Net};

use crate::error::ScanError;

/// The prefixes a probe covers and the addresses it leaves alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    prefixes: Vec<IpNet>,
    exclude: Vec<IpNet>,
    max_hosts: u32,
}

/// The addresses of an enumeration, and whether every prefix fit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hosts {
    /// The addresses, sorted and without duplicates.
    pub addresses: Vec<IpAddr>,
    /// Prefixes left out because they hold more than the per-prefix limit of addresses
    /// (IPv6 networks always), so a sweep cannot cover them.
    pub skipped: Vec<IpNet>,
}

impl Scope {
    /// A scope over `prefixes` without `exclude`; a sweep enumerates at most `max_hosts`
    /// addresses per prefix.
    pub fn new(prefixes: Vec<IpNet>, exclude: Vec<IpNet>, max_hosts: u32) -> Self {
        let mut prefixes: Vec<IpNet> = prefixes.into_iter().map(|net| net.trunc()).collect();
        prefixes.sort();
        prefixes.dedup();
        let mut exclude: Vec<IpNet> = exclude.into_iter().map(|net| net.trunc()).collect();
        exclude.sort();
        exclude.dedup();
        Self {
            prefixes,
            exclude,
            max_hosts,
        }
    }

    /// Parses prefixes and exclusions (`192.0.2.0/24`, `2001:db8::/64`, or a single address
    /// such as `192.0.2.1`).
    ///
    /// # Errors
    ///
    /// `scan.config` for an entry that is neither.
    pub fn parse(
        prefixes: &[String],
        exclude: &[String],
        max_hosts: u32,
    ) -> Result<Self, ScanError> {
        let parse = |key: &str, text: &str| {
            parse_net(text).ok_or_else(|| {
                ScanError::config(format!(
                    "scan.{key}: `{text}` is not a prefix or an address, such as 192.0.2.0/24"
                ))
            })
        };
        let prefixes = prefixes
            .iter()
            .map(|text| parse("prefixes", text))
            .collect::<Result<Vec<_>, _>>()?;
        let exclude = exclude
            .iter()
            .map(|text| parse("exclude", text))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(prefixes, exclude, max_hosts))
    }

    /// The prefixes.
    pub fn prefixes(&self) -> &[IpNet] {
        &self.prefixes
    }

    /// The exclusions.
    pub fn exclusions(&self) -> &[IpNet] {
        &self.exclude
    }

    /// The per-prefix limit of an enumeration.
    pub fn max_hosts(&self) -> u32 {
        self.max_hosts
    }

    /// Whether the scope has no prefix.
    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }

    /// Whether `ip` is inside a prefix and not excluded.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        self.prefixes.iter().any(|net| net.contains(&ip))
            && !self.exclude.iter().any(|net| net.contains(&ip))
    }

    /// A narrower scope for an on-demand run: `target` must lie inside one prefix.
    ///
    /// # Errors
    ///
    /// `scan.out_of_scope` when it does not; `scan.config` when it is not a prefix.
    pub fn narrow(&self, target: &str) -> Result<Self, ScanError> {
        let net = parse_net(target).ok_or_else(|| {
            ScanError::config(format!(
                "`{target}` is not a prefix or an address, such as 192.0.2.10"
            ))
        })?;
        if !self.prefixes.iter().any(|prefix| prefix.contains(&net)) {
            return Err(ScanError::out_of_scope(format!(
                "{net} is not inside the configured prefixes ({}); scans never leave them",
                self.describe()
            )));
        }
        Ok(Self::new(vec![net], self.exclude.clone(), self.max_hosts))
    }

    /// The prefixes as text, for messages.
    pub fn describe(&self) -> String {
        if self.prefixes.is_empty() {
            return "none".to_owned();
        }
        self.prefixes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The addresses a sweep probes: every usable address of each IPv4 prefix with at most
    /// [`Scope::max_hosts`] of them, without the exclusions. The network and broadcast
    /// addresses of prefixes shorter than /31 are left out.
    pub fn hosts(&self) -> Hosts {
        let mut hosts = Hosts::default();
        for net in &self.prefixes {
            match net {
                IpNet::V4(v4) if host_count(*v4) <= u64::from(self.max_hosts) => {
                    hosts
                        .addresses
                        .extend(v4_hosts(v4).map(IpAddr::V4).filter(|ip| self.contains(*ip)));
                }
                _ => hosts.skipped.push(*net),
            }
        }
        hosts.addresses.sort();
        hosts.addresses.dedup();
        hosts
    }
}

/// An IPv4-mapped IPv6 address as IPv4, anything else unchanged.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn parse_net(text: &str) -> Option<IpNet> {
    let text = text.trim();
    text.parse::<IpNet>()
        .ok()
        .or_else(|| text.parse::<IpAddr>().ok().map(IpNet::from))
        .map(|net| net.trunc())
}

fn host_count(net: Ipv4Net) -> u64 {
    let size = 1u64 << (32 - u32::from(net.prefix_len()));
    if net.prefix_len() >= 31 {
        size
    } else {
        size - 2
    }
}

fn v4_hosts(net: &Ipv4Net) -> impl Iterator<Item = Ipv4Addr> {
    let start = u32::from(net.network());
    let end = u32::from(net.broadcast());
    let (first, last) = if net.prefix_len() >= 31 {
        (start, end)
    } else {
        (start + 1, end - 1)
    };
    (first..=last).map(Ipv4Addr::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    fn scope() -> Scope {
        Scope::parse(
            &[
                "192.0.2.0/29".to_owned(),
                "2001:db8:10::/64".to_owned(),
                "203.0.113.7".to_owned(),
                "198.51.100.0/24".to_owned(),
            ],
            &["192.0.2.3".to_owned()],
            16,
        )
        .expect("scope")
    }

    #[test]
    fn contains_honours_prefixes_and_exclusions() {
        let scope = scope();
        assert!(scope.contains(ip("192.0.2.1")));
        assert!(!scope.contains(ip("192.0.2.3")), "excluded");
        assert!(!scope.contains(ip("192.0.2.8")), "outside the /29");
        assert!(scope.contains(ip("2001:db8:10::42")));
        assert!(
            scope.contains(ip("::ffff:192.0.2.2")),
            "mapped addresses count"
        );
        assert!(scope.contains(ip("203.0.113.7")));
        assert!(!scope.contains(ip("203.0.113.8")));
        assert!(scope.contains(ip("198.51.100.200")));
    }

    #[test]
    fn hosts_enumerate_small_ipv4_prefixes_only() {
        let hosts = scope().hosts();
        assert_eq!(
            hosts.addresses,
            [
                ip("192.0.2.1"),
                ip("192.0.2.2"),
                ip("192.0.2.4"),
                ip("192.0.2.5"),
                ip("192.0.2.6"),
                ip("203.0.113.7"),
            ]
        );
        assert_eq!(
            hosts.skipped,
            [
                "198.51.100.0/24".parse::<IpNet>().expect("net"),
                "2001:db8:10::/64".parse().expect("net")
            ]
        );
    }

    #[test]
    fn narrowing_stays_inside_the_scope() {
        let scope = scope();
        let narrow = scope.narrow("192.0.2.4").expect("inside");
        assert_eq!(narrow.hosts().addresses, [ip("192.0.2.4")]);
        assert!(narrow.contains(ip("192.0.2.4")));
        assert!(!narrow.contains(ip("192.0.2.5")));
        let error = scope.narrow("192.0.2.0/24").expect_err("wider");
        assert_eq!(error.code(), "scan.out_of_scope");
        assert_eq!(
            scope.narrow("nonsense").expect_err("bad").code(),
            "scan.config"
        );
    }

    #[test]
    fn bad_entries_are_refused() {
        let error = Scope::parse(&["192.0.2.0/33".to_owned()], &[], 10).expect_err("bad");
        assert_eq!(error.code(), "scan.config");
        assert!(error.detail().contains("scan.prefixes"));
    }
}
