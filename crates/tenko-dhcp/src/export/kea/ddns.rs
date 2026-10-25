//! The DDNS settings (ADR 0020) as Kea's `ddns-*` parameters per subnet, `dhcp-ddns` and a
//! `DhcpDdns` skeleton for `kea-dhcp-ddns` (decision P3-Q17 (a): the DNS side is the
//! operator's choice after leaving, so the skeleton names the domains and leaves the DNS
//! servers' keys to fill in). One skeleton serves both families: `kea-dhcp4` and
//! `kea-dhcp6` send their name changes to the same `kea-dhcp-ddns`.
//!
//! | Tenko | Kea |
//! |---|---|
//! | `enabled` | `ddns-send-updates` (false at the global level) |
//! | `forward_zone`, else the scope's option 15 (DHCPv4) or the first name of option 24 (DHCPv6) | `ddns-qualifying-suffix` |
//! | `conflict` `protect` / `replace` | `ddns-conflict-resolution-mode` `check-with-dhcid` / `no-check-with-dhcid` |
//! | `client_may_update_a` false / true | `ddns-override-client-update` and `ddns-override-no-update` true / false |
//! | `ttl` | `ddns-ttl-percent` of the scope's default lease time (reported) |
//! | `reverse` | the network's reverse domain in the skeleton (`in-addr.arpa` or `ip6.arpa`), or none |
//! | `legacy_clients` off (DHCPv4), `refuse_foreign` on | reported: Kea has no such switch |

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
};

use serde_json::{Map, Value, json};
use tenko_core::dhcp::{DdnsConflict, DdnsPolicy, OptionValue};

use super::{Cx, at, codes, options};
use crate::{image::ScopeImage, v6::image::Scope6Image};

/// What a subnet that writes names needs in the skeleton.
#[derive(Debug, Clone)]
pub(crate) struct Domain {
    scope: String,
    forward: Option<String>,
    reverse: Option<String>,
    reverse_on: bool,
    dns: Option<IpAddr>,
}

fn option(values: &[OptionValue], code: u16) -> Option<&OptionValue> {
    values
        .iter()
        .find(|value| value.space.is_dhcp4() && value.code == code)
}

fn option6(values: &[OptionValue], code: u16) -> Option<&OptionValue> {
    values
        .iter()
        .find(|value| value.space.is_dhcp6() && value.code == code)
}

/// The reverse domain of a network, on the octet boundary at or above its length.
fn reverse_name(network: ipnet::Ipv4Net) -> Option<String> {
    let octets = usize::from(network.prefix_len() / 8);
    if octets == 0 {
        return None;
    }
    let address = network.network().octets();
    let mut labels: Vec<String> = address[..octets].iter().rev().map(u8::to_string).collect();
    labels.push("in-addr.arpa.".to_owned());
    Some(labels.join("."))
}

/// The reverse domain of an IPv6 network, on the nibble boundary at or above its length.
fn reverse_name6(network: ipnet::Ipv6Net) -> Option<String> {
    let nibbles = usize::from(network.prefix_len() / 4);
    if nibbles == 0 {
        return None;
    }
    let digits: Vec<char> = network
        .network()
        .octets()
        .iter()
        .flat_map(|b| [b >> 4, b & 0x0f])
        .take(nibbles)
        .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
        .collect();
    let mut labels: Vec<String> = digits.iter().rev().map(char::to_string).collect();
    labels.push("ip6.arpa.".to_owned());
    Some(labels.join("."))
}

/// The parameters both families share; the suffix when the scope names one.
fn params(
    cx: &mut Cx<'_>,
    policy: &DdnsPolicy,
    label: &str,
    suffix: Option<&String>,
    lease_secs: u32,
    out: &mut Map<String, Value>,
) {
    out.insert("ddns-send-updates".into(), json!(true));
    out.insert("ddns-replace-client-name".into(), json!("never"));
    let server_writes = !policy.client_may_update_a;
    out.insert("ddns-override-client-update".into(), json!(server_writes));
    out.insert("ddns-override-no-update".into(), json!(server_writes));
    out.insert(
        "ddns-conflict-resolution-mode".into(),
        json!(match policy.conflict {
            DdnsConflict::Protect => "check-with-dhcid",
            DdnsConflict::Replace => "no-check-with-dhcid",
        }),
    );
    match suffix {
        Some(suffix) => {
            out.insert("ddns-qualifying-suffix".into(), json!(format!("{suffix}.")));
        }
        None => cx.report.push(
            at("scope", label),
            codes::DDNS_ZONE,
            "the scope writes names but names no forward zone the export knows and has no domain option (15 for DHCPv4, 24 for DHCPv6): set ddns-qualifying-suffix",
        ),
    }
    if let Some(ttl) = policy.ttl {
        let lease = lease_secs.max(1);
        let percent = (f64::from(ttl) / f64::from(lease)).clamp(0.01, 1.0);
        out.insert(
            "ddns-ttl-percent".into(),
            json!((percent * 1000.0).round() / 1000.0),
        );
        cx.report.push(
            at("scope", label),
            codes::DDNS_TTL,
            format!(
                "Tenko writes the records with a TTL of {ttl} s; Kea 2.6 takes a share of the lease time, so the export sets ddns-ttl-percent from the default lease time of {lease} s"
            ),
        );
    }
    if policy.refuse_foreign {
        cx.report.push(
            at("scope", label),
            codes::DDNS_FOREIGN,
            "Tenko refuses a client name outside the forward zone here; Kea sends a fully qualified client name as it is",
        );
    }
}

/// The `ddns-*` parameters of a subnet; the domain it needs when it writes names.
pub(crate) fn subnet(
    cx: &mut Cx<'_>,
    scope: &ScopeImage,
    out: &mut Map<String, Value>,
) -> Option<Domain> {
    let policy = &scope.ddns;
    if !policy.enabled {
        return None;
    }
    let label = scope.network.to_string();
    let suffix = match policy.forward_zone {
        Some(zone) => cx.input.zones.get(&zone).map(ToString::to_string),
        None => option(&scope.options, 15)
            .and_then(options::text)
            .map(|text| text.trim().trim_end_matches('.').to_ascii_lowercase()),
    };
    params(
        cx,
        policy,
        &label,
        suffix.as_ref(),
        scope.lease.default_secs,
        out,
    );
    if !policy.legacy_clients {
        cx.report.push(
            at("scope", &label),
            codes::DDNS_LEGACY,
            "Tenko writes no name for clients without option 81 here; Kea also writes names from option 12, with no switch to stop it per subnet",
        );
    }
    Some(Domain {
        scope: label,
        forward: suffix,
        reverse: reverse_name(scope.network),
        reverse_on: policy.reverse,
        dns: option(&scope.options, 6)
            .and_then(options::first_ipv4)
            .map(IpAddr::V4),
    })
}

/// The first name of a DHCPv6 domain list (option 24), as text without the root.
fn first_domain(value: &OptionValue) -> Option<String> {
    let list = crate::v6::option::DomainList::parse(24, &value.data.0).ok()?;
    let first = list.iter().next()?.to_string();
    let name = first.trim_end_matches('.').to_ascii_lowercase();
    (!name.is_empty()).then_some(name)
}

/// The `ddns-*` parameters of a DHCPv6 subnet; the domain it needs when it writes names.
/// A DHCPv6 client has no host name option, so a scope that serves legacy clients writes
/// the same names in Kea as in Tenko: those of option 39.
pub(crate) fn subnet6(
    cx: &mut Cx<'_>,
    scope: &Scope6Image,
    out: &mut Map<String, Value>,
) -> Option<Domain> {
    let policy = &scope.ddns;
    if !policy.enabled {
        return None;
    }
    let label = scope.network.to_string();
    let suffix = match policy.forward_zone {
        Some(zone) => cx.input.zones.get(&zone).map(ToString::to_string),
        None => option6(&scope.options, 24).and_then(first_domain),
    };
    params(
        cx,
        policy,
        &label,
        suffix.as_ref(),
        scope.lease.default_secs,
        out,
    );
    let dns = option6(&scope.options, 23)
        .and_then(|value| <[u8; 16]>::try_from(value.data.0.get(..16)?).ok())
        .map(|octets| IpAddr::V6(octets.into()));
    Some(Domain {
        scope: label,
        forward: suffix,
        reverse: reverse_name6(scope.network),
        reverse_on: policy.reverse,
        dns,
    })
}

fn domain_entry(name: &str, dns: Option<IpAddr>) -> Value {
    json!({
        "name": name,
        "key-name": "",
        "dns-servers": [{"ip-address": dns.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)).to_string(), "port": 53}],
    })
}

/// How a server sends name changes to `kea-dhcp-ddns`.
fn sender() -> Value {
    json!({
        "enable-updates": true,
        "server-ip": "127.0.0.1",
        "server-port": 53001,
        "ncr-protocol": "UDP",
        "ncr-format": "JSON",
    })
}

/// The global parameters of both documents, and the `DhcpDdns` skeleton when a subnet of
/// either family writes names.
pub(crate) fn global(
    cx: &mut Cx<'_>,
    domains4: &[Domain],
    dhcp4: &mut Map<String, Value>,
    dhcp6: Option<(&mut Map<String, Value>, &[Domain])>,
) -> Option<Value> {
    dhcp4.insert("ddns-send-updates".into(), json!(false));
    if !domains4.is_empty() {
        dhcp4.insert("dhcp-ddns".into(), sender());
    }
    let mut domains: Vec<Domain> = domains4.to_vec();
    if let Some((dhcp6, domains6)) = dhcp6 {
        dhcp6.insert("ddns-send-updates".into(), json!(false));
        if !domains6.is_empty() {
            dhcp6.insert("dhcp-ddns".into(), sender());
        }
        domains.extend_from_slice(domains6);
    }
    if domains.is_empty() {
        return None;
    }
    let mut forward: BTreeMap<String, Option<IpAddr>> = BTreeMap::new();
    let mut reverse: BTreeMap<String, Option<IpAddr>> = BTreeMap::new();
    let mut unknown_dns = false;
    for domain in &domains {
        unknown_dns |= domain.dns.is_none();
        if let Some(name) = &domain.forward {
            let entry = forward.entry(format!("{name}.")).or_insert(domain.dns);
            if entry.is_none() {
                *entry = domain.dns;
            }
        }
        if domain.reverse_on
            && let Some(name) = &domain.reverse
        {
            let entry = reverse.entry(name.clone()).or_insert(domain.dns);
            if entry.is_none() {
                *entry = domain.dns;
            }
        }
    }
    for domain in domains.iter().filter(|domain| !domain.reverse_on) {
        if let Some(name) = &domain.reverse
            && reverse.contains_key(name)
        {
            cx.report.push(
                at("scope", &domain.scope),
                codes::DDNS_REVERSE,
                format!(
                    "Tenko writes no PTR records for this scope, but another scope needs the reverse domain {name}, so kea-dhcp-ddns updates it for this scope too"
                ),
            );
        }
    }
    cx.report.push(
        at("settings", "DDNS"),
        codes::DDNS_D2,
        format!(
            "Kea sends name changes to kea-dhcp-ddns, which updates the DNS servers: kea-dhcp-ddns.json is a skeleton with the domains; check its DNS servers{} and add the TSIG keys the servers require",
            if unknown_dns {
                " (127.0.0.1 where the scope names no option 6 or, for DHCPv6, 23)"
            } else {
                ""
            }
        ),
    );
    let forward: Vec<Value> = forward
        .iter()
        .map(|(name, dns)| domain_entry(name, *dns))
        .collect();
    let reverse: Vec<Value> = reverse
        .iter()
        .map(|(name, dns)| domain_entry(name, *dns))
        .collect();
    Some(json!({
        "DhcpDdns": {
            "ip-address": "127.0.0.1",
            "port": 53001,
            "dns-server-timeout": 500,
            "ncr-protocol": "UDP",
            "ncr-format": "JSON",
            "tsig-keys": [],
            "forward-ddns": {"ddns-domains": forward},
            "reverse-ddns": {"ddns-domains": reverse},
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_domains_round_down_to_an_octet() {
        assert_eq!(
            reverse_name("192.0.2.64/26".parse().expect("net")).as_deref(),
            Some("2.0.192.in-addr.arpa.")
        );
        assert_eq!(
            reverse_name("198.18.0.0/15".parse().expect("net")).as_deref(),
            Some("198.in-addr.arpa.")
        );
        assert_eq!(reverse_name("192.0.0.0/7".parse().expect("net")), None);
    }

    #[test]
    fn ipv6_reverse_domains_round_down_to_a_nibble() {
        assert_eq!(
            reverse_name6("2001:db8:101::/64".parse().expect("net")).as_deref(),
            Some("0.0.0.0.1.0.1.0.8.b.d.0.1.0.0.2.ip6.arpa.")
        );
        assert_eq!(
            reverse_name6("2001:db8:100::/46".parse().expect("net")).as_deref(),
            Some("0.1.0.8.b.d.0.1.0.0.2.ip6.arpa.")
        );
        assert_eq!(reverse_name6("::/3".parse().expect("net")), None);
    }
}
