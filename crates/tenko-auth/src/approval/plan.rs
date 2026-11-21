//! Tenko's own limits on a takeover plan (plan section 2.16.2), checked before a request is
//! accepted.

use std::{collections::BTreeSet, net::IpAddr};

use ipnet::Ipv4Net;
use tenko_core::migrate::plan::{
    MAX_ADDRESSES, MAX_CONTROLLERS, MAX_DHCP_SERVERS, MAX_FORWARDERS, MAX_RELATIONSHIP_LEN,
    MAX_SCOPES, MAX_ZONES, TakeoverPlan,
};

/// Names a run's node may never take: names clients look up to find a proxy or a router, and
/// the loopback name (Windows' global query block list and `localhost`).
const DENIED_NODE_NAMES: [&str; 3] = ["wpad", "isatap", "localhost"];

/// Checks `plan` against Tenko's limits; the reason of a refusal names the rule.
///
/// - The counts: 1 to 64 zones, 1 to 16 controllers with exactly one PDC emulator, at most 32
///   DHCP servers, 256 scopes and 64 forwarders, each controller and forwarder with 1 to 8
///   addresses, at least one operation; no name, scope or operation twice.
/// - The domain is the forest root or below it.
/// - The zones are the domain, `_msdcs.<forest root>` and reverse zones that cover a scope's
///   network or lie inside one, nothing else.
/// - The scopes are networks (no host bits); the mirror host is no controller; the node's
///   name is one label and not on the deny list; the relationship's name is printable ASCII.
///
/// # Errors
///
/// The reason, as `field: rule`.
pub fn check_plan(plan: &TakeoverPlan) -> Result<(), &'static str> {
    let within = |count: usize, max: usize| (1..=max).contains(&count);
    if !within(plan.zones.len(), MAX_ZONES) {
        return Err("zones: 1 to 64");
    }
    if !within(plan.controllers.len(), MAX_CONTROLLERS) {
        return Err("controllers: 1 to 16");
    }
    if plan.dhcp_servers.len() > MAX_DHCP_SERVERS {
        return Err("dhcp_servers: at most 32");
    }
    if plan.scopes.len() > MAX_SCOPES {
        return Err("scopes: at most 256");
    }
    if plan.forwarders.len() > MAX_FORWARDERS {
        return Err("forwarders: at most 64");
    }
    if plan
        .controllers
        .iter()
        .filter(|controller| controller.pdc)
        .count()
        != 1
    {
        return Err("controllers: exactly one PDC emulator");
    }
    let addresses = |list: &[IpAddr]| within(list.len(), MAX_ADDRESSES) && distinct(list);
    if !plan.controllers.iter().all(|c| addresses(&c.addresses)) {
        return Err("controllers.addresses: 1 to 8, each once");
    }
    if !plan.forwarders.iter().all(|f| addresses(&f.servers)) {
        return Err("forwarders.servers: 1 to 8, each once");
    }
    if !distinct(plan.controllers.iter().map(|c| c.name.as_str()))
        || !distinct(plan.dhcp_servers.iter().map(|s| s.name.as_str()))
        || !distinct(&plan.zones)
        || !distinct(plan.forwarders.iter().map(|f| &f.zone))
        || !distinct(&plan.scopes)
        || plan.operations.is_empty()
        || !distinct(&plan.operations)
    {
        return Err("a name, zone, scope or operation is listed twice, or no operation");
    }
    if !plan.domain.is_subdomain_of(&plan.forest_root) || plan.forest_root.is_root() {
        return Err("domain: the forest root or below it");
    }
    if plan.scopes.iter().any(|scope| scope.trunc() != *scope) {
        return Err("scopes: networks without host bits");
    }
    let msdcs = format!("_msdcs.{}", plan.forest_root.as_str());
    let allowed = |zone: &str| {
        zone == plan.domain.as_str()
            || zone == msdcs
            || match tenko_net::reverse::zone_network(zone) {
                Some((IpAddr::V4(address), len)) => Ipv4Net::new(address, len).is_ok_and(|net| {
                    plan.scopes
                        .iter()
                        .any(|scope| net.contains(scope) || scope.contains(&net))
                }),
                _ => false,
            }
    };
    if !plan.zones.iter().all(|zone| allowed(zone.as_str())) {
        return Err(
            "zones: the domain, _msdcs of the forest root and the reverse zones of the scopes only",
        );
    }
    if plan
        .controllers
        .iter()
        .any(|controller| controller.name == plan.mirror_host.name)
    {
        return Err("mirror_host: a domain controller is never the mirror host");
    }
    let node = plan.node_name.as_str();
    if node.contains('.') || DENIED_NODE_NAMES.contains(&node) {
        return Err("node_name: one label, not wpad, isatap or localhost");
    }
    if let Some(name) = &plan.relationship {
        let printable = name.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
        if name.is_empty() || name.len() > MAX_RELATIONSHIP_LEN || !printable || name.trim() != name
        {
            return Err("relationship: 1 to 64 printable ASCII characters");
        }
    }
    Ok(())
}

fn distinct<T: Ord>(items: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    items.into_iter().all(|item| seen.insert(item))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn plan() -> serde_json::Value {
        json!({
            "domain": "corp.example.test",
            "forest_root": "corp.example.test",
            "controllers": [
                { "name": "dc1.corp.example.test", "addresses": ["192.0.2.11"], "pdc": true },
                { "name": "dc2.corp.example.test", "addresses": ["192.0.2.12", "2001:db8::12"] }
            ],
            "zones": ["corp.example.test", "_msdcs.corp.example.test", "2.0.192.in-addr.arpa"],
            "forwarders": [{ "zone": ".", "servers": ["198.51.100.53"] }],
            "dhcp_servers": [
                { "name": "dhcp1.corp.example.test", "address": "192.0.2.21" },
                { "name": "dhcp2.corp.example.test", "address": "192.0.2.22" }
            ],
            "relationship": "dhcp1-dhcp2",
            "scopes": ["192.0.2.0/24"],
            "mirror_host": { "name": "mgmt1.corp.example.test", "address": "192.0.2.30" },
            "node_name": "tenko",
            "operations": ["mirrors", "secondary_zones", "prepare", "flip", "takeover"]
        })
    }

    fn checked(edit: impl FnOnce(&mut serde_json::Value)) -> Result<(), &'static str> {
        let mut value = plan();
        edit(&mut value);
        check_plan(&serde_json::from_value(value).expect("a plan"))
    }

    #[test]
    fn the_reference_plan_passes() {
        assert_eq!(checked(|_| {}), Ok(()));
        // A reverse zone of a wider network that holds the scope, and one inside it.
        assert_eq!(
            checked(
                |plan| plan["zones"] = json!(["0.192.in-addr.arpa", "130.2.0.192.in-addr.arpa"])
            ),
            Ok(())
        );
    }

    #[test]
    fn plans_outside_the_limits_are_refused() {
        type Edit = fn(&mut serde_json::Value);
        let refused: [(Edit, &str); 14] = [
            (
                |plan| plan["zones"] = json!(["other.example.test"]),
                "zones:",
            ),
            (
                |plan| plan["zones"] = json!(["100.51.198.in-addr.arpa"]),
                "zones:",
            ),
            (
                |plan| plan["zones"] = json!(["8.b.d.0.1.0.0.2.ip6.arpa"]),
                "zones:",
            ),
            (|plan| plan["zones"] = json!([]), "zones: 1 to 64"),
            (
                |plan| plan["controllers"][1]["pdc"] = json!(true),
                "controllers: exactly one",
            ),
            (
                |plan| plan["controllers"][1]["name"] = json!("dc1.corp.example.test"),
                "a name,",
            ),
            (
                |plan| plan["controllers"][0]["addresses"] = json!([]),
                "controllers.addresses",
            ),
            (|plan| plan["scopes"] = json!(["192.0.2.1/24"]), "scopes:"),
            (|plan| plan["node_name"] = json!("wpad"), "node_name"),
            (
                |plan| plan["node_name"] = json!("tenko.corp.example.test"),
                "node_name",
            ),
            (
                |plan| plan["mirror_host"]["name"] = json!("dc2.corp.example.test"),
                "mirror_host",
            ),
            (
                |plan| plan["forest_root"] = json!("other.example.test"),
                "domain:",
            ),
            (
                |plan| plan["operations"] = json!(["flip", "flip"]),
                "a name,",
            ),
            (
                |plan| plan["relationship"] = json!("a\u{202e}b"),
                "relationship:",
            ),
        ];
        for (edit, reason) in refused {
            let found = checked(edit);
            assert!(
                found.is_err_and(|found| found.starts_with(reason)),
                "{reason}"
            );
        }
        let scopes: Vec<String> = (0..=MAX_SCOPES)
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
            .collect();
        assert_eq!(
            checked(|plan| plan["scopes"] = json!(scopes)),
            Err("scopes: at most 256")
        );
    }
}
