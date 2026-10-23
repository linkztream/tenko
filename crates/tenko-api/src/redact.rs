//! Redaction of text that leaves the node in a bug report: every IP address, MAC address,
//! host name, zone name and account name is replaced by a placeholder from the documentation
//! ranges (RFC 5737, RFC 3849, RFC 7042) and `example.test`, numbered in order of first
//! appearance, so that one diagnostics document still tells its story (the same address is
//! always the same placeholder) while nothing of the network it came from is in it.
//!
//! The [`Redactor`] is a pure function over text with its numbering as the only state: it
//! reads no clock, no store and no configuration. What it knows about the installation (the
//! zones of the catalog, the account names) is given at construction.
//!
//! Names and addresses that are placeholders already (the documentation ranges, the reserved
//! names of RFC 2606 and RFC 6761, loopback, unspecified and multicast addresses) and a few
//! public names the product itself talks to are left as they are.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

/// Suffixes of names that are redacted even when the catalog has no zone for them: the
/// private-use and local suffixes, and the common public top-level domains.
pub const KNOWN_SUFFIXES: &[&str] = &[
    // Private and local use.
    "local",
    "lan",
    "home",
    "internal",
    "intranet",
    "corp",
    "private",
    "localdomain",
    "home.arpa",
    "arpa",
    // Generic top-level domains.
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "mil",
    "int",
    "info",
    "biz",
    "io",
    "dev",
    "app",
    "cloud",
    "tech",
    "me",
    "tv",
    "cc",
    "co",
    "ai",
    "xyz",
    "nu",
    // Country codes.
    "se",
    "no",
    "dk",
    "fi",
    "is",
    "de",
    "uk",
    "nl",
    "fr",
    "ch",
    "at",
    "be",
    "eu",
    "it",
    "es",
    "pt",
    "pl",
    "cz",
    "ie",
    "ca",
    "us",
    "au",
    "nz",
    "jp",
    "br",
    "in",
    "ru",
];

/// Names that are placeholders already (RFC 2606, RFC 6761) or public names of the services
/// the product talks to; left as they are, with everything under them.
const KEPT_NAMES: &[&str] = &[
    "example.com",
    "example.net",
    "example.org",
    "example",
    "test",
    "invalid",
    "localhost",
    "github.com",
    "githubusercontent.com",
];

/// Characters that make up one token of the scan: the characters of addresses (with their
/// prefix lengths, ports, brackets and scope ids), of names and of account names.
fn is_token_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | ':' | '-' | '_' | '/' | '[' | ']' | '%')
}

/// Punctuation a token may end with that belongs to the sentence, not to the value.
fn is_trailing_punctuation(c: char) -> bool {
    matches!(c, '.' | ':' | ';' | ',')
}

/// Replaces addresses, names and account names in text with numbered placeholders.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    /// The zones of the catalog, lower case, without a trailing dot, longest first.
    zones: Vec<String>,
    /// The account names, lower case.
    accounts: Vec<String>,
    v4: BTreeMap<Ipv4Addr, u32>,
    v6: BTreeMap<Ipv6Addr, u32>,
    macs: BTreeMap<[u8; 6], u32>,
    hosts: BTreeMap<String, u32>,
    zone_numbers: BTreeMap<String, u32>,
    users: BTreeMap<String, u32>,
}

impl Redactor {
    /// A redactor that also knows `zones` (apex names, with or without a trailing dot) and
    /// `accounts` (login names).
    pub fn new<Z, A>(zones: Z, accounts: A) -> Self
    where
        Z: IntoIterator,
        Z::Item: AsRef<str>,
        A: IntoIterator,
        A::Item: AsRef<str>,
    {
        let mut zones: Vec<String> = zones
            .into_iter()
            .map(|zone| {
                zone.as_ref()
                    .trim()
                    .trim_end_matches('.')
                    .to_ascii_lowercase()
            })
            .filter(|zone| !zone.is_empty())
            .collect();
        zones.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        zones.dedup();
        let mut accounts: Vec<String> = accounts
            .into_iter()
            .map(|account| account.as_ref().trim().to_ascii_lowercase())
            .filter(|account| !account.is_empty())
            .collect();
        accounts.sort();
        accounts.dedup();
        Self {
            zones,
            accounts,
            ..Self::default()
        }
    }

    /// `text` with every address, name and account name replaced. The numbering continues
    /// across calls, so the lines of one document agree with each other.
    pub fn redact(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut token = String::new();
        for c in text.chars() {
            if is_token_char(c) {
                token.push(c);
            } else {
                self.flush(&mut token, &mut out);
                out.push(c);
            }
        }
        self.flush(&mut token, &mut out);
        out
    }

    fn flush(&mut self, token: &mut String, out: &mut String) {
        if token.is_empty() {
            return;
        }
        out.push_str(&self.redact_token(token));
        token.clear();
    }

    /// One token: the value with the sentence punctuation it ends with kept.
    fn redact_token(&mut self, token: &str) -> String {
        let core_len = token.trim_end_matches(is_trailing_punctuation).len();
        let (core, tail) = token.split_at(core_len);
        // A fully qualified name keeps its trailing dot; so does a sentence its full stop.
        match self.redact_value(core) {
            Some(replaced) => format!("{replaced}{tail}"),
            None => token.to_owned(),
        }
    }

    /// One value without trailing punctuation; `None` when nothing in it is redacted.
    fn redact_value(&mut self, value: &str) -> Option<String> {
        if value.is_empty() {
            return None;
        }
        if let Some(user) = self.account(value) {
            return Some(user);
        }
        // `[2001:db8::1]:53`: a bracketed IPv6 address, usually with a port.
        if let Some(inner) = value.strip_prefix('[')
            && let Some((address, rest)) = inner.split_once(']')
            && let Some(replaced) = self.ipv6(address)
        {
            return Some(format!("[{replaced}]{rest}"));
        }
        // `192.0.2.0/24`, `2001:db8::/32`, or the segments of a path or a URL.
        if let Some((address, length)) = value.split_once('/') {
            if !length.is_empty()
                && length.bytes().all(|b| b.is_ascii_digit())
                && let Some(replaced) = self.ip(address)
            {
                return Some(format!("{replaced}/{length}"));
            }
            let mut changed = false;
            let segments: Vec<String> = value
                .split('/')
                .map(|segment| match self.redact_value(segment) {
                    Some(replaced) => {
                        changed = true;
                        replaced
                    }
                    None => segment.to_owned(),
                })
                .collect();
            return changed.then(|| segments.join("/"));
        }
        if let Some(replaced) = self.ip(value) {
            return Some(replaced);
        }
        if let Some(replaced) = self.mac(value) {
            return Some(replaced);
        }
        // `192.0.2.1:53`, `ns1.example.lan:53`: a port after an address or a name.
        if let Some((left, port)) = value.rsplit_once(':')
            && !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
            && !left.contains(':')
        {
            if let Some(replaced) = self.ipv4(left).or_else(|| self.name(left)) {
                return Some(format!("{replaced}:{port}"));
            }
            return None;
        }
        self.name(value)
    }

    fn account(&mut self, value: &str) -> Option<String> {
        let lower = value.to_ascii_lowercase();
        if !self.accounts.contains(&lower) {
            return None;
        }
        let next = u32::try_from(self.users.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let number = *self.users.entry(lower).or_insert(next);
        Some(format!("user-{number}"))
    }

    fn ip(&mut self, value: &str) -> Option<String> {
        self.ipv4(value).or_else(|| self.ipv6(value))
    }

    fn ipv4(&mut self, value: &str) -> Option<String> {
        let address: Ipv4Addr = value.parse().ok()?;
        if keep_v4(address) {
            return None;
        }
        let next = u32::try_from(self.v4.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let number = *self.v4.entry(address).or_insert(next);
        Some(placeholder_v4(number))
    }

    /// An IPv6 address, with its scope id (`%eth0`) kept.
    fn ipv6(&mut self, value: &str) -> Option<String> {
        let (address, scope) = match value.split_once('%') {
            Some((address, scope)) => (address, Some(scope)),
            None => (value, None),
        };
        let address: Ipv6Addr = address.parse().ok()?;
        if keep_v6(address) {
            return None;
        }
        let next = u32::try_from(self.v6.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let number = *self.v6.entry(address).or_insert(next);
        let placeholder = format!("2001:db8::{number}");
        Some(match scope {
            Some(scope) => format!("{placeholder}%{scope}"),
            None => placeholder,
        })
    }

    /// A MAC address in any of its three notations.
    fn mac(&mut self, value: &str) -> Option<String> {
        let octets = parse_mac(value)?;
        let next = u32::try_from(self.macs.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let number = *self.macs.entry(octets).or_insert(next);
        let low = number & 0xff;
        let high = (number >> 8) & 0xff;
        Some(format!("00-00-5e-00-{high:02x}-{low:02x}"))
    }

    /// A host or zone name: one the catalog knows as a zone (or a host under it), or one
    /// that ends with a known suffix.
    fn name(&mut self, value: &str) -> Option<String> {
        let lower = value.to_ascii_lowercase();
        if !looks_like_name(&lower) {
            return None;
        }
        // A zone of the catalog is redacted whatever its name; the reserved and public names
        // are kept only outside the catalog.
        let zones = std::mem::take(&mut self.zones);
        let known_zone = zones
            .iter()
            .find(|zone| lower == **zone || lower.ends_with(&format!(".{zone}")))
            .cloned();
        self.zones = zones;
        if let Some(zone) = known_zone {
            let zone_number = self.zone_number(&zone);
            let zone_placeholder = format!("zone-{zone_number}.example.test");
            if lower.len() == zone.len() {
                return Some(zone_placeholder);
            }
            let host_number = self.host_number(&lower);
            return Some(format!("host-{host_number}.{zone_placeholder}"));
        }
        if is_kept_name(&lower)
            || !KNOWN_SUFFIXES
                .iter()
                .any(|suffix| lower.ends_with(&format!(".{suffix}")))
        {
            return None;
        }
        let host_number = self.host_number(&lower);
        Some(format!("host-{host_number}.example.test"))
    }

    fn zone_number(&mut self, zone: &str) -> u32 {
        let next = u32::try_from(self.zone_numbers.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        *self.zone_numbers.entry(zone.to_owned()).or_insert(next)
    }

    fn host_number(&mut self, host: &str) -> u32 {
        let next = u32::try_from(self.hosts.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        *self.hosts.entry(host.to_owned()).or_insert(next)
    }
}

/// The `n`-th IPv4 placeholder: the three documentation ranges of RFC 5737 in turn.
fn placeholder_v4(n: u32) -> String {
    match n {
        255..=508 => format!("198.51.100.{}", n - 254),
        509..=762 => format!("203.0.113.{}", n - 508),
        _ => format!("192.0.2.{n}"),
    }
}

/// Addresses that name no network of the reporter: loopback, unspecified, broadcast, the
/// documentation ranges and multicast.
fn keep_v4(address: Ipv4Addr) -> bool {
    address.is_loopback()
        || address.is_unspecified()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_multicast()
}

fn keep_v6(address: Ipv6Addr) -> bool {
    if address.is_loopback() || address.is_unspecified() || address.is_multicast() {
        return true;
    }
    // RFC 3849: 2001:db8::/32.
    let segments = address.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

/// A name is at least two labels of letters, digits, `-` and `_` whose last label has a
/// letter, so that a version or a decimal number is not one.
fn looks_like_name(lower: &str) -> bool {
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let valid_label = |label: &str| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    labels.iter().all(|label| valid_label(label))
        && labels
            .last()
            .is_some_and(|last| last.bytes().any(|b| b.is_ascii_alphabetic()))
}

fn is_kept_name(lower: &str) -> bool {
    KEPT_NAMES
        .iter()
        .any(|kept| lower == *kept || lower.ends_with(&format!(".{kept}")))
}

/// `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` or `aabb.ccdd.eeff`.
fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let hex: Vec<u8> = if value.len() == 17 && (value.contains(':') || value.contains('-')) {
        let separator = if value.contains(':') { ':' } else { '-' };
        let parts: Vec<&str> = value.split(separator).collect();
        if parts.len() != 6 || parts.iter().any(|part| part.len() != 2) {
            return None;
        }
        parts
            .iter()
            .map(|part| u8::from_str_radix(part, 16).ok())
            .collect::<Option<Vec<u8>>>()?
    } else if value.len() == 14 && value.matches('.').count() == 2 {
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() != 3 || parts.iter().any(|part| part.len() != 4) {
            return None;
        }
        let mut octets = Vec::with_capacity(6);
        for part in parts {
            let word = u16::from_str_radix(part, 16).ok()?;
            octets.extend_from_slice(&word.to_be_bytes());
        }
        octets
    } else {
        return None;
    };
    hex.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor() -> Redactor {
        Redactor::new(["corp.example.", "Lab.Internal"], ["alice", "Bob"])
    }

    #[test]
    fn ipv4_addresses_in_every_notation() {
        let mut r = redactor();
        assert_eq!(
            r.redact("peer 10.1.2.3 asked for 10.1.2.0/24 via 10.1.2.3:53."),
            "peer 192.0.2.1 asked for 192.0.2.2/24 via 192.0.2.1:53."
        );
        assert_eq!(r.redact("again 10.1.2.3"), "again 192.0.2.1");
    }

    #[test]
    fn ipv6_addresses_in_every_notation() {
        let mut r = redactor();
        assert_eq!(
            r.redact("fd00:1::5 and [fd00:1::5]:53 and fd00:1::/64 and fe80::1%eth0"),
            "2001:db8::1 and [2001:db8::1]:53 and 2001:db8::2/64 and 2001:db8::3%eth0"
        );
    }

    #[test]
    fn placeholders_and_local_addresses_stay() {
        let mut r = redactor();
        let text = "127.0.0.1 0.0.0.0 192.0.2.7 198.51.100.9 203.0.113.1 ::1 :: 2001:db8::9 \
                    224.0.0.251 ff02::fb 255.255.255.255";
        assert_eq!(r.redact(text), text);
    }

    #[test]
    fn mac_addresses() {
        let mut r = redactor();
        assert_eq!(
            r.redact("00:11:22:33:44:55, 00-11-22-33-44-55, 0011.2233.4455 and 00:11:22:33:44:56"),
            "00-00-5e-00-00-01, 00-00-5e-00-00-01, 00-00-5e-00-00-01 and 00-00-5e-00-00-02"
        );
    }

    #[test]
    fn host_names_with_known_suffixes() {
        let mut r = redactor();
        assert_eq!(
            r.redact("zone transfer from NS1.Example.LAN failed; ns1.example.lan. retried, pc.home.arpa too"),
            "zone transfer from host-1.example.test failed; host-1.example.test. retried, host-2.example.test too"
        );
        assert_eq!(
            r.redact("sent to ns1.example.lan:53"),
            "sent to host-1.example.test:53"
        );
    }

    #[test]
    fn zones_of_the_catalog_and_hosts_under_them() {
        let mut r = redactor();
        assert_eq!(
            r.redact("zone corp.example expired; www.corp.example and db.lab.internal moved; lab.internal is signed"),
            "zone zone-1.example.test expired; host-1.zone-1.example.test and host-2.zone-2.example.test moved; \
             zone-2.example.test is signed"
        );
    }

    #[test]
    fn account_names_as_whole_words() {
        let mut r = redactor();
        assert_eq!(
            r.redact("user=alice signed in; Bob locked; alice's token; alicia stays"),
            "user=user-1 signed in; user-2 locked; user-1's token; alicia stays"
        );
    }

    #[test]
    fn reserved_and_public_names_stay() {
        let mut r = redactor();
        let text = "tenko1.example.test ns.example.com foo.invalid localhost github.com \
                    https://api.github.com/repos/x";
        assert_eq!(r.redact(text), text);
    }

    #[test]
    fn names_inside_urls_and_paths() {
        let mut r = redactor();
        assert_eq!(
            r.redact("GET https://ns1.example.lan:8443/api/v1/health from /var/log/tenko.log"),
            "GET https://host-1.example.test:8443/api/v1/health from /var/log/tenko.log"
        );
    }

    #[test]
    fn versions_times_targets_and_files_are_not_names() {
        let mut r = redactor();
        let text = "0.0.3 at 2026-10-23T10:00:05Z tenko_dns::zone::mod.rs tenko.toml 12:00:01 \
                    openraft=warn 1.2.3.4.5";
        assert_eq!(r.redact(text), text);
    }

    #[test]
    fn numbering_continues_across_lines() {
        let mut r = redactor();
        let first = r.redact("10.0.0.1 then 10.0.0.2");
        let second = r.redact("10.0.0.2 again, and 10.0.0.3");
        assert_eq!(first, "192.0.2.1 then 192.0.2.2");
        assert_eq!(second, "192.0.2.2 again, and 192.0.2.3");
    }

    #[test]
    fn more_than_one_documentation_range_is_used() {
        assert_eq!(placeholder_v4(254), "192.0.2.254");
        assert_eq!(placeholder_v4(255), "198.51.100.1");
        assert_eq!(placeholder_v4(509), "203.0.113.1");
    }

    #[test]
    fn an_empty_redactor_still_redacts_addresses_and_suffixes() {
        let mut r = Redactor::default();
        assert_eq!(
            r.redact("10.9.8.7 host.corp.example files.example.se"),
            "192.0.2.1 host.corp.example host-1.example.test"
        );
    }
}
