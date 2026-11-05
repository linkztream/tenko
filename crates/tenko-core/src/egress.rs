//! The egress policy of server-side fetches (NEVER-01, ADR 0023): where the server itself
//! may open a connection on an operator's behalf, such as the URL of a block list or the
//! primaries of a secondary zone.
//!
//! The policy refuses the addresses a server must not be made to reach from the outside:
//! loopback, link-local (with the metadata services of cloud platforms, which live
//! there), multicast, unspecified and broadcast addresses, and the well-known metadata
//! addresses outside those ranges. An operator who needs one of them lists its prefix in
//! `[dns] egress_allow`, and the policy carries those prefixes. The policy judges
//! addresses, never host names: a host name is judged by the addresses it resolves to,
//! every time it is resolved, and a redirect is judged like the first request.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnet::IpNet;

/// The well-known metadata addresses outside the link-local ranges.
const METADATA: &[IpAddr] = &[
    // The AWS, Azure, Google Cloud and OpenStack metadata service (link-local).
    IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
    // The AWS metadata service over IPv6.
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254)),
    // The Alibaba Cloud metadata service.
    IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200)),
];

/// Why an address is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressRefusal {
    /// A loopback address.
    Loopback,
    /// A link-local address.
    LinkLocal,
    /// A multicast address.
    Multicast,
    /// The unspecified address.
    Unspecified,
    /// The broadcast address.
    Broadcast,
    /// A well-known metadata service address.
    Metadata,
}

impl EgressRefusal {
    /// The reason as a short English phrase.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Loopback => "a loopback address",
            Self::LinkLocal => "a link-local address",
            Self::Multicast => "a multicast address",
            Self::Unspecified => "the unspecified address",
            Self::Broadcast => "the broadcast address",
            Self::Metadata => "a metadata service address",
        }
    }
}

impl fmt::Display for EgressRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

/// The policy: the refused classes with the prefixes an operator allows regardless.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    allowed: Vec<IpNet>,
}

impl EgressPolicy {
    /// The policy with `allowed` as the prefixes that are reached although a class
    /// refuses them (`[dns] egress_allow`).
    pub fn with_allowed(allowed: Vec<IpNet>) -> Self {
        Self { allowed }
    }

    /// The prefixes the operator allows.
    pub fn allowed(&self) -> &[IpNet] {
        &self.allowed
    }

    /// Why `address` is refused by its class alone, before the operator's prefixes.
    fn class(address: IpAddr) -> Option<EgressRefusal> {
        if METADATA.contains(&address) {
            return Some(EgressRefusal::Metadata);
        }
        match address {
            IpAddr::V4(v4) => {
                if v4.is_unspecified() || v4.octets()[0] == 0 {
                    Some(EgressRefusal::Unspecified)
                } else if v4.is_loopback() {
                    Some(EgressRefusal::Loopback)
                } else if v4.is_link_local() {
                    Some(EgressRefusal::LinkLocal)
                } else if v4.is_multicast() {
                    Some(EgressRefusal::Multicast)
                } else if v4.is_broadcast() {
                    Some(EgressRefusal::Broadcast)
                } else {
                    None
                }
            }
            IpAddr::V6(v6) => {
                // An IPv4-mapped address is judged as the IPv4 address it carries.
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return Self::class(IpAddr::V4(v4));
                }
                if v6.is_unspecified() {
                    Some(EgressRefusal::Unspecified)
                } else if v6.is_loopback() {
                    Some(EgressRefusal::Loopback)
                } else if v6.is_unicast_link_local() {
                    Some(EgressRefusal::LinkLocal)
                } else if v6.is_multicast() {
                    Some(EgressRefusal::Multicast)
                } else {
                    None
                }
            }
        }
    }

    /// Checks one address the server would connect to.
    ///
    /// # Errors
    ///
    /// The class that refuses it, unless an allowed prefix holds it.
    pub fn check(&self, address: IpAddr) -> Result<(), EgressRefusal> {
        match Self::class(address) {
            Some(refusal) if !self.allowed.iter().any(|prefix| prefix.contains(&address)) => {
                Err(refusal)
            }
            _ => Ok(()),
        }
    }

    /// Checks every address a host name resolved to: the name is refused when any of
    /// them is, so that a name cannot answer with a mix of reachable and refused
    /// addresses and have the connection fall through to a refused one.
    ///
    /// # Errors
    ///
    /// The class that refuses the first refused address.
    pub fn check_all<'a>(
        &self,
        addresses: impl IntoIterator<Item = &'a IpAddr>,
    ) -> Result<(), EgressRefusal> {
        addresses
            .into_iter()
            .try_for_each(|address| self.check(*address))
    }
}

/// The parts of a fetch URL the policy judges before any connection: the scheme is
/// `http` or `https`, it carries no credentials, and a host written as an address passes
/// the policy. A host name passes here and is judged when it resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlRefusal {
    /// Not an `http` or `https` URL.
    Scheme,
    /// The URL carries a user name or a password.
    Credentials,
    /// The URL names no host.
    NoHost,
    /// The host is an address the policy refuses.
    Address(EgressRefusal),
}

impl UrlRefusal {
    /// The reason as a short English phrase.
    pub fn reason(self) -> String {
        match self {
            Self::Scheme => "an http or https URL".to_owned(),
            Self::Credentials => "a URL without credentials".to_owned(),
            Self::NoHost => "a URL with a host".to_owned(),
            Self::Address(refusal) => format!("the host is {refusal}"),
        }
    }
}

/// The authority of a URL from the text after its scheme: what stands between `://` and
/// the first `/`, `?` or `#`.
fn authority(after_scheme: &str) -> Option<&str> {
    let rest = after_scheme.strip_prefix("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The host of a fetch URL whose shape passes: the scheme is `http` or `https` (compared
/// without case), it carries no credentials and it names a host. The host is returned
/// without its port and without the brackets of an IPv6 address.
///
/// # Errors
///
/// The first refusal.
pub fn url_host(url: &str) -> Result<&str, UrlRefusal> {
    let scheme_len = url.find(':').unwrap_or(url.len());
    let scheme = &url[..scheme_len];
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return Err(UrlRefusal::Scheme);
    }
    let authority = authority(&url[scheme_len..]).ok_or(UrlRefusal::Scheme)?;
    if authority.contains('@') {
        return Err(UrlRefusal::Credentials);
    }
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or("")
    } else {
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, port)| {
                if port.chars().all(|c| c.is_ascii_digit()) {
                    host
                } else {
                    authority
                }
            })
    };
    if host.is_empty() {
        return Err(UrlRefusal::NoHost);
    }
    Ok(host)
}

/// Checks a fetch URL against `policy`: its shape ([`url_host`]) and, when the host is
/// written as an address, the address. A host name passes here and is judged by the
/// addresses it resolves to.
///
/// # Errors
///
/// The first refusal.
pub fn check_url(policy: &EgressPolicy, url: &str) -> Result<(), UrlRefusal> {
    let host = url_host(url)?;
    if let Ok(address) = host.parse::<IpAddr>() {
        policy.check(address).map_err(UrlRefusal::Address)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> IpAddr {
        text.parse().expect("address")
    }

    #[test]
    fn the_refused_classes_are_refused_and_public_addresses_pass() {
        let policy = EgressPolicy::default();
        let refused = [
            ("127.0.0.1", EgressRefusal::Loopback),
            ("127.255.255.254", EgressRefusal::Loopback),
            ("::1", EgressRefusal::Loopback),
            ("::ffff:127.0.0.1", EgressRefusal::Loopback),
            ("169.254.1.1", EgressRefusal::LinkLocal),
            ("fe80::1", EgressRefusal::LinkLocal),
            ("224.0.0.1", EgressRefusal::Multicast),
            ("ff02::1", EgressRefusal::Multicast),
            ("0.0.0.0", EgressRefusal::Unspecified),
            ("0.1.2.3", EgressRefusal::Unspecified),
            ("::", EgressRefusal::Unspecified),
            ("255.255.255.255", EgressRefusal::Broadcast),
            ("169.254.169.254", EgressRefusal::Metadata),
            ("fd00:ec2::254", EgressRefusal::Metadata),
            ("100.100.100.200", EgressRefusal::Metadata),
            ("::ffff:169.254.169.254", EgressRefusal::Metadata),
        ];
        for (text, reason) in refused {
            assert_eq!(policy.check(addr(text)), Err(reason), "{text}");
        }
        for text in [
            "192.0.2.10",
            "198.51.100.1",
            "203.0.113.200",
            "2001:db8::1",
            "10.0.0.1",
            "192.168.1.1",
            "fd12::1",
        ] {
            assert_eq!(policy.check(addr(text)), Ok(()), "{text}");
        }
    }

    #[test]
    fn an_allowed_prefix_lets_a_refused_address_through() {
        let policy = EgressPolicy::with_allowed(vec!["127.0.0.0/8".parse().expect("prefix")]);
        assert_eq!(policy.check(addr("127.0.0.1")), Ok(()));
        assert_eq!(policy.check(addr("::1")), Err(EgressRefusal::Loopback));
        assert_eq!(
            policy.check(addr("169.254.169.254")),
            Err(EgressRefusal::Metadata)
        );
        assert_eq!(
            policy.check_all(&[addr("192.0.2.1"), addr("::1")]),
            Err(EgressRefusal::Loopback)
        );
        assert_eq!(
            policy.check_all(&[addr("192.0.2.1"), addr("127.0.0.1")]),
            Ok(())
        );
    }

    #[test]
    fn urls_are_checked_for_scheme_credentials_and_address() {
        let policy = EgressPolicy::default();
        for url in [
            "https://lists.example.test/hosts.txt",
            "HTTPS://lists.example.test:8443/hosts.txt?x=1",
            "http://192.0.2.10/hosts",
            "http://[2001:db8::1]:8080/hosts",
            "https://lists.example.test",
        ] {
            assert_eq!(check_url(&policy, url), Ok(()), "{url}");
        }
        assert_eq!(
            check_url(&policy, "ftp://lists.example.test/hosts"),
            Err(UrlRefusal::Scheme)
        );
        assert_eq!(
            check_url(&policy, "lists.example.test"),
            Err(UrlRefusal::Scheme)
        );
        assert_eq!(
            check_url(&policy, "https:lists.example.test"),
            Err(UrlRefusal::Scheme)
        );
        assert_eq!(url_host("https://[2001:db8::1]:8080/x"), Ok("2001:db8::1"));
        assert_eq!(
            url_host("http://lists.example.test:8080"),
            Ok("lists.example.test")
        );
        assert_eq!(
            check_url(&policy, "https://user:secret@lists.example.test/hosts"),
            Err(UrlRefusal::Credentials)
        );
        assert_eq!(
            check_url(&policy, "https://user@lists.example.test/hosts"),
            Err(UrlRefusal::Credentials)
        );
        assert_eq!(
            check_url(&policy, "https:///hosts"),
            Err(UrlRefusal::NoHost)
        );
        assert_eq!(check_url(&policy, "https://"), Err(UrlRefusal::NoHost));
        assert_eq!(
            check_url(&policy, "http://127.0.0.1:8080/hosts"),
            Err(UrlRefusal::Address(EgressRefusal::Loopback))
        );
        assert_eq!(
            check_url(&policy, "http://[::1]/hosts"),
            Err(UrlRefusal::Address(EgressRefusal::Loopback))
        );
        assert_eq!(
            check_url(&policy, "http://169.254.169.254/latest/meta-data"),
            Err(UrlRefusal::Address(EgressRefusal::Metadata))
        );
        assert_eq!(
            check_url(&policy, "http://[fd00:ec2::254]/"),
            Err(UrlRefusal::Address(EgressRefusal::Metadata))
        );
        let allowing = EgressPolicy::with_allowed(vec!["127.0.0.1/32".parse().expect("prefix")]);
        assert_eq!(check_url(&allowing, "http://127.0.0.1:8080/hosts"), Ok(()));
    }
}
