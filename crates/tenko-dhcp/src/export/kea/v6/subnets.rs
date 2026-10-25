//! `subnet6` and `shared-networks` of the `Dhcp6` document: the DHCPv6 scopes with their
//! pools, reservations, options, lifetimes, rapid commit, relay selection and DDNS hints.
//!
//! **Selection.** The engine selects a scope by the Interface-Id of a relay, then by the
//! link address of the relay on the client's link, then by the address of the listener a
//! client on its link reached. Kea selects a subnet by its `interface-id`, then by the
//! prefix that holds the relay's link address, then by the subnet's `interface` for
//! direct traffic; so the export writes the scope's Interface-Id and, for a scope whose
//! network holds the address of a direct listener, that listener's interface. A relay's
//! link address lies in the network of the scope it selects (that is how the engine
//! selects it), so no subnet needs Kea's `relay` list. In a shared network both go on the
//! shared network, as Kea requires; Kea also takes only one of the two per subnet or
//! shared network, so the interface wins and the Interface-Id is reported.
//!
//! **Pools.** A pool is an IPAM range of role `dhcp_pool` with the scope's exclusions cut
//! out (the image's merged list: explicit exclusions, reserved and infrastructure ranges,
//! static addresses) and the network's first address, the Subnet-Router anycast address
//! the engine never leases. The pools of a restricted scope require the allow class.
//!
//! **Delegation pools** (WP9.4). A delegation pool (an IPAM range of role `dhcp_pd_pool`)
//! is cut into the prefixes of its delegated length; a prefix that holds an excluded
//! address is never delegated by the engine, so the rest is written as Kea's `pd-pools`:
//! each run of delegable prefixes as the fewest aligned prefixes that cover it exactly,
//! each with `prefix`, `prefix-len` and `delegated-len`. Kea, like the engine, offers the
//! `pd-pools` of a subnet to the clients of every subnet of its shared network.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv6Addr,
};

use serde_json::{Map, Value, json};
use tenko_core::{PrefixId, dhcp::OptionOwner};

use super::{lifetime_params, option_data};
use crate::{
    export::kea::{Cx, at, classes::ALLOW, codes, ddns, subnets::colon_hex},
    v4::engine::ListenMode,
    v6::{
        engine::alloc::lifetimes,
        image::{PdPool6Image, Pool6Image, Reservation6Key, Scope6Image},
    },
};

/// Numbers the DHCPv6 scopes the export holds and reports the duplicates.
pub(crate) fn number(cx: &mut Cx<'_>) {
    let mut seen = BTreeSet::new();
    let mut next = 1u32;
    for scope in cx.built.image.v6().scopes() {
        if !seen.insert(scope.network) {
            cx.report.push(
                at("scope", scope.network),
                codes::SCOPE_DUPLICATE,
                "another VRF serves the same network; Kea has no VRFs, so only the first scope of the network is exported",
            );
            continue;
        }
        cx.subnet_ids6.insert(scope.prefix, next);
        next += 1;
    }
}

/// The free intervals of a pool: the pool without the excluded addresses (sorted and
/// merged) and without the network's first address.
pub(crate) fn free(
    pool: &Pool6Image,
    network: Ipv6Addr,
    excluded: &[(Ipv6Addr, Ipv6Addr)],
) -> Vec<(u128, u128)> {
    let mut out = Vec::new();
    let mut start = u128::from(pool.first);
    let end = u128::from(pool.last);
    let anycast = (network, network);
    for &(first, last) in std::iter::once(&anycast).chain(excluded) {
        let (first, last) = (u128::from(first), u128::from(last));
        if last < start || first > end {
            continue;
        }
        if first > start {
            out.push((start, first - 1));
        }
        match last.checked_add(1) {
            Some(after) => start = start.max(after),
            None => return out,
        }
        if start > end {
            return out;
        }
    }
    if start <= end {
        out.push((start, end));
    }
    out
}

fn pools(cx: &mut Cx<'_>, scope: &Scope6Image) -> Vec<Value> {
    let mut out = Vec::new();
    for pool in &scope.pools {
        let label = format!("{} - {}", pool.first, pool.last);
        if pool.lease != scope.lease {
            cx.report.push(
                at("pool", &label),
                codes::POOL_LEASE,
                format!(
                    "the pool's valid lifetime ({} s) is left out: Kea's pools have no lifetimes, so the subnet's ({} s) applies",
                    pool.lease.default_secs, scope.lease.default_secs
                ),
            );
        }
        let data = option_data(cx, &pool.options);
        for (first, last) in free(pool, scope.network.network(), &scope.excluded) {
            let mut entry = Map::new();
            entry.insert(
                "pool".into(),
                json!(format!(
                    "{} - {}",
                    Ipv6Addr::from(first),
                    Ipv6Addr::from(last)
                )),
            );
            if scope.restricted {
                cx.need_allow6 = true;
                entry.insert("client-class".into(), json!(ALLOW));
            }
            if !data.is_empty() {
                entry.insert("option-data".into(), Value::Array(data.clone()));
            }
            out.push(Value::Object(entry));
        }
    }
    out
}

// WP9.4: the delegation pools as Kea's `pd-pools`.
/// The fewest aligned prefixes that cover `first` to `last` exactly, as (prefix, length).
pub(crate) fn cover(first: u128, last: u128) -> Vec<(Ipv6Addr, u8)> {
    let mut out = Vec::new();
    let mut at = first;
    loop {
        // The largest block aligned at `at` that ends at or before `last`.
        let span = last - at;
        let fits = |bits: u32| {
            if bits >= 128 {
                span == u128::MAX
            } else {
                (1u128 << bits) - 1 <= span
            }
        };
        let mut bits = at.trailing_zeros();
        while !fits(bits) {
            bits -= 1;
        }
        out.push((Ipv6Addr::from(at), u8::try_from(128 - bits).unwrap_or(0)));
        let end = if bits >= 128 {
            u128::MAX
        } else {
            at + ((1u128 << bits) - 1)
        };
        if end >= last {
            return out;
        }
        at = end + 1;
    }
}

/// The `pd-pools` of a delegation pool: the delegable prefixes ([`Scope6Image::delegable`])
/// as aligned prefixes with the pool's delegated length.
fn pd_pool_entries(
    scope: &Scope6Image,
    pool: &PdPool6Image,
    data: &[Value],
    restricted: bool,
) -> Vec<Value> {
    let mut out = Vec::new();
    for (first, last) in scope.delegable(pool) {
        for (prefix, len) in cover(u128::from(first), u128::from(last)) {
            let mut entry = Map::new();
            entry.insert("prefix".into(), json!(prefix.to_string()));
            entry.insert("prefix-len".into(), json!(len));
            entry.insert("delegated-len".into(), json!(pool.delegated_len));
            if restricted {
                entry.insert("client-class".into(), json!(ALLOW));
            }
            if !data.is_empty() {
                entry.insert("option-data".into(), Value::Array(data.to_vec()));
            }
            out.push(Value::Object(entry));
        }
    }
    out
}

/// The `pd-pools` of a scope: its delegation pools, the pool lifetimes reported as for the
/// address pools.
fn pd_pools(cx: &mut Cx<'_>, scope: &Scope6Image) -> Vec<Value> {
    let mut out = Vec::new();
    for pool in &scope.pd_pools {
        let label = format!("{} - {}", pool.first, pool.last);
        if pool.lease != scope.lease {
            cx.report.push(
                at("delegation pool", &label),
                codes::POOL_LEASE,
                format!(
                    "the delegation pool's valid lifetime ({} s) is left out: Kea's pd-pools have no lifetimes, so the subnet's ({} s) applies",
                    pool.lease.default_secs, scope.lease.default_secs
                ),
            );
        }
        let data = option_data(cx, &pool.options);
        let entries = pd_pool_entries(scope, pool, &data, scope.restricted);
        if scope.restricted && !entries.is_empty() {
            cx.need_allow6 = true;
        }
        out.extend(entries);
    }
    out
}

fn reservations(cx: &mut Cx<'_>, scope: &Scope6Image) -> Vec<Value> {
    let mut out = Vec::new();
    for reservation in cx
        .built
        .image
        .v6()
        .reservations()
        .iter()
        .filter(|reservation| reservation.scope == scope.prefix)
        .cloned()
        .collect::<Vec<_>>()
    {
        let mut entry = Map::new();
        match &reservation.key {
            Reservation6Key::Duid(duid) => {
                entry.insert("duid".into(), json!(colon_hex(duid)));
            }
            Reservation6Key::Mac(mac) => {
                entry.insert("hw-address".into(), json!(colon_hex(mac)));
            }
        }
        entry.insert("ip-addresses".into(), json!([reservation.addr.to_string()]));
        if let Some(host) = cx.data.hosts.get(&reservation.host) {
            entry.insert("hostname".into(), json!(host.name.as_str()));
        }
        let data = option_data(cx, &reservation.options);
        if !data.is_empty() {
            entry.insert("option-data".into(), Value::Array(data));
        }
        out.push(Value::Object(entry));
    }
    out
}

/// The interface of each scope whose network holds the address of a direct listener.
fn direct_interfaces(cx: &Cx<'_>) -> BTreeMap<PrefixId, String> {
    let mut out = BTreeMap::new();
    for listener in cx.input.listeners6.unwrap_or_default() {
        if listener.mode != ListenMode::Direct {
            continue;
        }
        let (Some(interface), Some(scope)) = (
            &listener.interface,
            cx.built.image.v6().select(*listener.address.ip()),
        ) else {
            continue;
        };
        out.entry(scope.prefix).or_insert_with(|| interface.clone());
    }
    out
}

/// Puts `interface` or `interface-id` into a subnet or a shared network: Kea takes one of
/// them, so the interface of a direct link wins and an Interface-Id beside it is reported.
fn selection(
    cx: &mut Cx<'_>,
    label: &str,
    interface: Option<String>,
    interface_id: Option<&str>,
    out: &mut Map<String, Value>,
) {
    match (interface, interface_id) {
        (Some(interface), Some(id)) => {
            cx.report.push(
                at("scope", label),
                codes::V6_INTERFACE_ID,
                format!(
                    "the relay Interface-Id {id} is left out: Kea takes either the interface of a direct link ({interface}) or an Interface-Id, so relayed requests select by their link address alone"
                ),
            );
            out.insert("interface".into(), json!(interface));
        }
        (Some(interface), None) => {
            out.insert("interface".into(), json!(interface));
        }
        (None, Some(id)) => {
            out.insert("interface-id".into(), json!(id));
        }
        (None, None) => {}
    }
}

fn subnet(
    cx: &mut Cx<'_>,
    scope: &Scope6Image,
    id: u32,
    selected: Option<(Option<String>, Option<&str>)>,
    domains: &mut Vec<ddns::Domain>,
) -> Value {
    let prefix = scope.prefix;
    let label = scope.network.to_string();
    let mut entry = Map::new();
    entry.insert("id".into(), json!(id));
    entry.insert("subnet".into(), json!(label));
    let own = cx.values(OptionOwner::Scope(prefix));
    let data = option_data(cx, own);
    entry.insert("option-data".into(), Value::Array(data));
    lifetime_params(lifetimes(scope, None), &mut entry);
    entry.insert("rapid-commit".into(), json!(scope.v6.rapid_commit()));
    if let Some((interface, interface_id)) = selected {
        selection(cx, &label, interface, interface_id, &mut entry);
    }
    entry.insert("pools".into(), Value::Array(pools(cx, scope)));
    if !scope.pd_pools.is_empty() {
        entry.insert("pd-pools".into(), Value::Array(pd_pools(cx, scope)));
    }
    entry.insert("reservations".into(), Value::Array(reservations(cx, scope)));
    if scope.restricted {
        cx.report.push(
            at("scope", &label),
            codes::SCOPE_RESTRICTED,
            "the scope serves allow-listed and reserved clients only: in Kea its pools require the class tenko.allow and reservations lie outside the pools, so other clients get no address, but Kea still answers them (a status NoAddrsAvail) where Tenko stays silent",
        );
    }
    if let Some(domain) = ddns::subnet6(cx, scope, &mut entry) {
        domains.push(domain);
    }
    let mut context = Map::new();
    context.insert("tenko-prefix".into(), json!(prefix.to_string()));
    if let Some(description) = cx
        .data
        .scopes
        .get(&prefix)
        .and_then(|row| row.description.clone())
    {
        context.insert("description".into(), json!(description));
    }
    entry.insert("user-context".into(), Value::Object(context));
    Value::Object(entry)
}

/// The shared networks and the subnets outside them, and the domains DDNS needs.
pub(crate) fn build(cx: &mut Cx<'_>) -> (Vec<Value>, Vec<Value>, Vec<ddns::Domain>) {
    let direct = direct_interfaces(cx);
    let scopes: Vec<(Scope6Image, u32)> = cx
        .built
        .image
        .v6()
        .scopes()
        .iter()
        .filter_map(|scope| {
            cx.subnet_ids6
                .get(&scope.prefix)
                .map(|id| (scope.clone(), *id))
        })
        .collect();
    let mut domains = Vec::new();
    let mut groups: BTreeMap<String, (tenko_core::dhcp::SharedNetworkId, Vec<(Scope6Image, u32)>)> =
        BTreeMap::new();
    let mut alone = Vec::new();
    for (scope, id) in scopes {
        match scope.shared_network.and_then(|network| {
            cx.data
                .shared_networks
                .get(&network)
                .map(|row| (network, row))
        }) {
            Some((network, row)) => groups
                .entry(row.name.clone())
                .or_insert_with(|| (network, Vec::new()))
                .1
                .push((scope, id)),
            None => alone.push((scope, id)),
        }
    }
    let mut subnet6 = Vec::new();
    for (scope, id) in &alone {
        let interface_id = scope.v6.interface_id.clone();
        let selected = (direct.get(&scope.prefix).cloned(), interface_id.as_deref());
        subnet6.push(subnet(cx, scope, *id, Some(selected), &mut domains));
    }
    let mut shared = Vec::new();
    for (name, (network, members)) in groups {
        let row = cx.data.shared_networks.get(&network).cloned();
        let mut entry = Map::new();
        entry.insert("name".into(), json!(name));
        let interface = row
            .as_ref()
            .and_then(|row| row.interface.clone())
            .or_else(|| {
                members
                    .iter()
                    .find_map(|(scope, _)| direct.get(&scope.prefix).cloned())
            });
        let ids: Vec<String> = members
            .iter()
            .filter_map(|(scope, _)| scope.v6.interface_id.clone())
            .fold(Vec::new(), |mut ids, id| {
                if !ids.contains(&id) {
                    ids.push(id);
                }
                ids
            });
        if ids.len() > 1 {
            cx.report.push(
                at("shared network", &name),
                codes::V6_INTERFACE_ID,
                format!(
                    "the scopes of the shared network name the relay Interface-Ids {}; Kea takes one per shared network, so {} selects it and the others select by the relay's link address alone",
                    ids.join(", "),
                    ids[0]
                ),
            );
        }
        selection(
            cx,
            &name,
            interface,
            ids.first().map(String::as_str),
            &mut entry,
        );
        let values = cx.values(OptionOwner::SharedNetwork(network));
        let data = option_data(cx, values);
        entry.insert("option-data".into(), Value::Array(data));
        let mut inside = Vec::new();
        for (scope, id) in &members {
            inside.push(subnet(cx, scope, *id, None, &mut domains));
        }
        entry.insert("subnet6".into(), Value::Array(inside));
        if let Some(description) = row.and_then(|row| row.description) {
            entry.insert("user-context".into(), json!({"description": description}));
        }
        shared.push(Value::Object(entry));
    }
    (shared, subnet6, domains)
}

#[cfg(test)]
mod cover_tests {
    use std::net::Ipv6Addr;

    use super::cover;

    fn ip(text: &str) -> u128 {
        u128::from(text.parse::<Ipv6Addr>().expect("an address"))
    }

    fn shown(first: &str, last: &str) -> Vec<String> {
        cover(ip(first), ip(last))
            .into_iter()
            .map(|(prefix, len)| format!("{prefix}/{len}"))
            .collect()
    }

    #[test]
    fn a_run_of_prefixes_is_covered_by_the_fewest_aligned_prefixes() {
        assert_eq!(
            shown("2001:db8:180:100::", "2001:db8:180:1ff:ffff:ffff:ffff:ffff"),
            ["2001:db8:180:100::/56"]
        );
        assert_eq!(
            shown("2001:db8:180:120::", "2001:db8:180:1ff:ffff:ffff:ffff:ffff"),
            [
                "2001:db8:180:120::/59",
                "2001:db8:180:140::/58",
                "2001:db8:180:180::/57"
            ]
        );
        assert_eq!(
            shown("2001:db8:180:110::", "2001:db8:180:12f:ffff:ffff:ffff:ffff"),
            ["2001:db8:180:110::/60", "2001:db8:180:120::/60"]
        );
        assert_eq!(shown("2001:db8::5", "2001:db8::5"), ["2001:db8::5/128"]);
        assert_eq!(cover(0, u128::MAX), [(Ipv6Addr::UNSPECIFIED, 0)]);
        assert_eq!(
            cover(0, u128::MAX >> 1),
            [(Ipv6Addr::UNSPECIFIED, 1)],
            "half of the space"
        );
    }

    proptest::proptest! {
        /// The prefixes are aligned, in order, adjacent, and cover the run exactly.
        #[test]
        fn the_cover_is_exact(first in proptest::num::u128::ANY, span in 0u128..(1u128 << 80)) {
            let last = first.saturating_add(span);
            let parts = cover(first, last);
            let mut at = first;
            for (index, (prefix, len)) in parts.iter().enumerate() {
                let start = u128::from(*prefix);
                proptest::prop_assert_eq!(start, at);
                let size_bits = 128 - u32::from(*len);
                let end = if size_bits >= 128 { u128::MAX } else { start + ((1u128 << size_bits) - 1) };
                if size_bits < 128 {
                    proptest::prop_assert_eq!(start % (1u128 << size_bits), 0);
                }
                proptest::prop_assert!(end <= last);
                if index + 1 < parts.len() {
                    at = end + 1;
                } else {
                    proptest::prop_assert_eq!(end, last);
                }
            }
            // At most two prefixes of each length.
            proptest::prop_assert!(parts.len() <= 2 * 128);
        }
    }
}
