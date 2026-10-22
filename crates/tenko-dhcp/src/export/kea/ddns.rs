//! The DDNS settings (ADR 0020) as Kea's `ddns-*` parameters per subnet, `dhcp-ddns` and a
//! `DhcpDdns` skeleton for `kea-dhcp-ddns` (decision P3-Q17 (a): the DNS side is the
//! operator's choice after leaving, so the skeleton names the domains and leaves the DNS
//! servers' keys to fill in).
//!
//! | Tenko | Kea |
//! |---|---|
//! | `enabled` | `ddns-send-updates` (false at the global level) |
//! | `forward_zone`, else the scope's option 15 | `ddns-qualifying-suffix` |
//! | `conflict` `protect` / `replace` | `ddns-conflict-resolution-mode` `check-with-dhcid` / `no-check-with-dhcid` |
//! | `client_may_update_a` false / true | `ddns-override-client-update` and `ddns-override-no-update` true / false |
//! | `ttl` | `ddns-ttl-percent` of the scope's default lease time (reported) |
//! | `reverse` | the network's reverse domain in the skeleton, or none |
//! | `legacy_clients` off, `refuse_foreign` on | reported: Kea has no such switch |

use std::{collections::BTreeMap, net::Ipv4Addr};

use serde_json::{Map, Value, json};
use tenko_core::dhcp::{DdnsConflict, OptionValue};

use super::{Cx, at, codes, options};
use crate::image::ScopeImage;

/// What a subnet that writes names needs in the skeleton.
#[derive(Debug, Clone)]
pub(crate) struct Domain {
    scope: String,
    forward: Option<String>,
    reverse: Option<String>,
    reverse_on: bool,
    dns: Option<Ipv4Addr>,
}

fn option(values: &[OptionValue], code: u16) -> Option<&OptionValue> {
    values
        .iter()
        .find(|value| value.space.is_dhcp4() && value.code == code)
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
    match &suffix {
        Some(suffix) => {
            out.insert("ddns-qualifying-suffix".into(), json!(format!("{suffix}.")));
        }
        None => cx.report.push(
            at("scope", &label),
            codes::DDNS_ZONE,
            "the scope writes names but names no forward zone the export knows and has no option 15: set ddns-qualifying-suffix",
        ),
    }
    if let Some(ttl) = policy.ttl {
        let lease = scope.lease.default_secs.max(1);
        let percent = (f64::from(ttl) / f64::from(lease)).clamp(0.01, 1.0);
        out.insert(
            "ddns-ttl-percent".into(),
            json!((percent * 1000.0).round() / 1000.0),
        );
        cx.report.push(
            at("scope", &label),
            codes::DDNS_TTL,
            format!(
                "Tenko writes the records with a TTL of {ttl} s; Kea 2.6 takes a share of the lease time, so the export sets ddns-ttl-percent from the default lease time of {lease} s"
            ),
        );
    }
    if !policy.legacy_clients {
        cx.report.push(
            at("scope", &label),
            codes::DDNS_LEGACY,
            "Tenko writes no name for clients without option 81 here; Kea also writes names from option 12, with no switch to stop it per subnet",
        );
    }
    if policy.refuse_foreign {
        cx.report.push(
            at("scope", &label),
            codes::DDNS_FOREIGN,
            "Tenko refuses a client name outside the forward zone here; Kea sends a fully qualified client name as it is",
        );
    }
    Some(Domain {
        scope: label,
        forward: suffix,
        reverse: reverse_name(scope.network),
        reverse_on: policy.reverse,
        dns: option(&scope.options, 6).and_then(options::first_ipv4),
    })
}

fn domain_entry(name: &str, dns: Option<Ipv4Addr>) -> Value {
    json!({
        "name": name,
        "key-name": "",
        "dns-servers": [{"ip-address": dns.unwrap_or(Ipv4Addr::LOCALHOST).to_string(), "port": 53}],
    })
}

/// The global parameters, and the `DhcpDdns` skeleton when a subnet writes names.
pub(crate) fn global(
    cx: &mut Cx<'_>,
    domains: &[Domain],
    dhcp4: &mut Map<String, Value>,
) -> Option<Value> {
    dhcp4.insert("ddns-send-updates".into(), json!(false));
    if domains.is_empty() {
        return None;
    }
    dhcp4.insert(
        "dhcp-ddns".into(),
        json!({
            "enable-updates": true,
            "server-ip": "127.0.0.1",
            "server-port": 53001,
            "ncr-protocol": "UDP",
            "ncr-format": "JSON",
        }),
    );
    let mut forward: BTreeMap<String, Option<Ipv4Addr>> = BTreeMap::new();
    let mut reverse: BTreeMap<String, Option<Ipv4Addr>> = BTreeMap::new();
    let mut unknown_dns = false;
    for domain in domains {
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
                " (127.0.0.1 where the scope names no option 6)"
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
}
