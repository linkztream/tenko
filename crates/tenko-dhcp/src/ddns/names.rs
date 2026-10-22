//! The name a lease gets (plan section 2.9, ADR 0020 point 3).
//!
//! - The name of option 81 (RFC 4702) goes under the scope's forward zone: a single label
//!   becomes `label.zone`; a name below the zone stays as it is; a name outside the zone
//!   is cut to its first label under the zone, or refused when the scope's policy says
//!   `refuse_foreign`.
//! - A client without option 81 that sends option 12 gets its host name under the zone
//!   when the scope serves legacy clients (`legacy_clients`, DHCP-13); a host name with
//!   dots counts by its first label.
//! - A client with neither gets no name.
//!
//! Every label keeps to the host-name rules (RFC 952 and RFC 1123: letters, digits and
//! hyphens, 1 to 63 octets, no hyphen at either end); a name with another label is refused
//! rather than rewritten. Names are lowercase.

use tenko_core::{dhcp::DdnsPolicy, dns::DnsName};

/// Why a lease gets no name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameRefusal {
    /// The client sent no usable name (or option 12 only, and the scope serves no legacy
    /// clients). Not an error: the lease simply has no name.
    #[error("the client sent no name")]
    NoName,
    /// The name lies outside the forward zone and the scope refuses such names.
    #[error("the name {0} lies outside the zone {1}")]
    Foreign(String, String),
    /// A label breaks the host-name rules.
    #[error("the name {0} is not a valid host name")]
    Invalid(String),
}

/// Whether `label` keeps to the host-name rules.
pub fn is_host_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
}

fn under(zone: &DnsName, label: &str) -> Result<DnsName, NameRefusal> {
    let label = label.to_ascii_lowercase();
    if !is_host_label(&label) {
        return Err(NameRefusal::Invalid(label));
    }
    zone.child(&label)
        .map_err(|_| NameRefusal::Invalid(format!("{label}.{}", zone.as_str())))
}

/// The forward name of a lease: from option 81 (`fqdn`), else option 12 (`hostname`),
/// under `zone`.
///
/// # Errors
///
/// [`NameRefusal`] when the lease gets no name.
pub fn forward_name(
    fqdn: Option<&str>,
    hostname: Option<&str>,
    policy: &DdnsPolicy,
    zone: &DnsName,
) -> Result<DnsName, NameRefusal> {
    let fqdn = fqdn
        .map(str::trim)
        .filter(|name| !name.is_empty() && *name != ".");
    if let Some(text) = fqdn {
        let text = text.strip_suffix('.').unwrap_or(text);
        let labels: Vec<&str> = text.split('.').collect();
        if labels.len() == 1 {
            return under(zone, labels[0]);
        }
        let Ok(name) = DnsName::new(text) else {
            return Err(NameRefusal::Invalid(text.to_ascii_lowercase()));
        };
        if !name.labels().all(is_host_label) {
            return Err(NameRefusal::Invalid(name.as_str().to_owned()));
        }
        if name != *zone && name.is_subdomain_of(zone) {
            return Ok(name);
        }
        if policy.refuse_foreign {
            return Err(NameRefusal::Foreign(
                name.as_str().to_owned(),
                zone.as_str().to_owned(),
            ));
        }
        return under(zone, labels[0]);
    }
    if !policy.legacy_clients {
        return Err(NameRefusal::NoName);
    }
    let host = hostname
        .map(str::trim)
        .and_then(|name| name.split('.').next())
        .filter(|label| !label.is_empty());
    match host {
        Some(label) => under(zone, label),
        None => Err(NameRefusal::NoName),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone() -> DnsName {
        DnsName::new("lan.example.test").expect("zone")
    }

    fn named(fqdn: Option<&str>, hostname: Option<&str>, policy: &DdnsPolicy) -> String {
        match forward_name(fqdn, hostname, policy, &zone()) {
            Ok(name) => name.as_str().to_owned(),
            Err(refusal) => format!("refused: {refusal}"),
        }
    }

    #[test]
    fn option_81_goes_under_the_zone() {
        let policy = DdnsPolicy::default();
        assert_eq!(
            named(Some("Laptop"), None, &policy),
            "laptop.lan.example.test"
        );
        assert_eq!(
            named(Some("laptop.lan.example.test."), Some("other"), &policy),
            "laptop.lan.example.test"
        );
        assert_eq!(
            named(Some("a.b.lan.example.test"), None, &policy),
            "a.b.lan.example.test"
        );
        // Outside the zone: cut to the first label, or refused.
        assert_eq!(
            named(Some("laptop.corp.example.test"), None, &policy),
            "laptop.lan.example.test"
        );
        let strict = DdnsPolicy {
            refuse_foreign: true,
            ..DdnsPolicy::default()
        };
        assert_eq!(
            named(Some("laptop.corp.example.test"), None, &strict),
            "refused: the name laptop.corp.example.test lies outside the zone lan.example.test"
        );
        // The apex itself is not a host's name.
        assert_eq!(
            named(Some("lan.example.test"), None, &policy),
            "lan.lan.example.test"
        );
    }

    #[test]
    fn legacy_clients_use_option_12() {
        let policy = DdnsPolicy::default();
        assert_eq!(
            named(None, Some("printer"), &policy),
            "printer.lan.example.test"
        );
        assert_eq!(
            named(None, Some("printer.home"), &policy),
            "printer.lan.example.test"
        );
        assert_eq!(
            named(Some(""), Some("printer"), &policy),
            "printer.lan.example.test"
        );
        let modern = DdnsPolicy {
            legacy_clients: false,
            ..DdnsPolicy::default()
        };
        assert_eq!(
            named(None, Some("printer"), &modern),
            "refused: the client sent no name"
        );
        assert_eq!(
            named(None, None, &policy),
            "refused: the client sent no name"
        );
    }

    #[test]
    fn labels_keep_to_the_host_name_rules() {
        let policy = DdnsPolicy::default();
        assert!(named(Some("my_laptop"), None, &policy).starts_with("refused"));
        assert!(named(None, Some("-bad"), &policy).starts_with("refused"));
        assert!(named(None, Some(&"a".repeat(64)), &policy).starts_with("refused"));
        assert!(named(Some("x_y.lan.example.test"), None, &policy).starts_with("refused"));
        assert!(is_host_label("host-1"));
    }
}
