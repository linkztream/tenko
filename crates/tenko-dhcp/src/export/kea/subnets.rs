//! `subnet4` and `shared-networks`: the scopes with their pools, reservations, options,
//! lease times, boot fields and DDNS hints.
//!
//! **Pools.** A pool is an IPAM range of role `dhcp_pool` with the scope's exclusions cut
//! out (the image's merged list), split where the range of a policy of the scope or of the
//! server begins or ends, so that each piece has one admission rule as Tenko applies it:
//! a client whose first matching range policy is `P` takes addresses only from `P`'s
//! range, and an address in some policy's range goes only to the clients that policy's
//! range applies to. With the scope's classes, the pool's classes and the restricted flag
//! (the allow list) the rule is a class expression; a single `member(..)` is the pool's
//! `client-class`, anything else a class `admit.<n>` defined after the policies.
//!
//! **Options.** Kea puts subnet and shared-network options above class options, Tenko a
//! policy's above the scope's and the shared network's. A code that a policy applying to
//! the subnet also sets therefore moves from the subnet (and from the shared network, for
//! every member) into the class `scope.<network>.defaults`, required last by the subnet, so
//! the first matching policy wins and the scope's value comes after it.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use serde_json::{Map, Value, json};
use tenko_core::{
    PrefixId,
    dhcp::{OptionOwner, OptionValue, Policy, ReservationWarning, merge},
};

use super::{
    Cx, at, boot_fields,
    classes::{self, ALLOW},
    codes, ddns,
    expr::Expr,
    lease_params,
};
use crate::image::{PoolImage, ScopeImage};

/// Numbers the scopes the export holds and reports the ones it leaves out.
pub(crate) fn number(cx: &mut Cx<'_>) {
    let mut disabled: Vec<_> = cx
        .data
        .scopes
        .values()
        .filter(|scope| !scope.enabled)
        .filter_map(|scope| cx.data.prefixes.get(&scope.prefix))
        .map(|prefix| prefix.cidr)
        .collect();
    disabled.sort();
    for cidr in disabled {
        cx.report.push(
            at("scope", cidr),
            codes::SCOPE_DISABLED,
            "the scope is disabled and is left out; Kea has no disabled subnets",
        );
    }
    let mut seen = BTreeSet::new();
    let mut next = 1u32;
    for scope in cx.built.image.scopes() {
        if !seen.insert(scope.network) {
            cx.report.push(
                at("scope", scope.network),
                codes::SCOPE_DUPLICATE,
                "another VRF serves the same network; Kea has no VRFs, so only the first scope of the network is exported",
            );
            continue;
        }
        cx.subnet_ids.insert(scope.prefix, next);
        next += 1;
    }
}

fn applicable<'a>(cx: &Cx<'a>, prefix: PrefixId) -> Vec<&'a Policy> {
    cx.policies
        .iter()
        .copied()
        .filter(|policy| policy.scope.is_none_or(|scope| scope == prefix))
        .collect()
}

fn v4(address: std::net::IpAddr) -> Option<Ipv4Addr> {
    match address {
        std::net::IpAddr::V4(address) => Some(address),
        std::net::IpAddr::V6(_) => None,
    }
}

/// The range policies of a scope in order, with their ranges.
fn range_policies<'a>(policies: &[&'a Policy]) -> Vec<(&'a Policy, Ipv4Addr, Ipv4Addr)> {
    policies
        .iter()
        .filter_map(|policy| {
            let range = policy.action.range?;
            let (first, last) = (v4(range.first)?, v4(range.last)?);
            (first <= last).then_some((*policy, first, last))
        })
        .collect()
}

/// The free intervals of a pool: the pool without the excluded addresses.
fn free(pool: &PoolImage, excluded: &[(Ipv4Addr, Ipv4Addr)]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut start = u32::from(pool.first);
    let end = u32::from(pool.last);
    for &(first, last) in excluded {
        let (first, last) = (u32::from(first), u32::from(last));
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

/// Splits the intervals where a range begins or ends.
fn split(intervals: Vec<(u32, u32)>, ranges: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut cuts: BTreeSet<u32> = BTreeSet::new();
    for &(first, last) in ranges {
        cuts.insert(first);
        if let Some(after) = last.checked_add(1) {
            cuts.insert(after);
        }
    }
    let mut out = Vec::new();
    for (first, last) in intervals {
        let mut start = first;
        for &cut in cuts.range(first.saturating_add(1)..=last) {
            out.push((start, cut - 1));
            start = cut;
        }
        out.push((start, last));
    }
    out
}

fn members(cx: &Cx<'_>, ids: &[tenko_core::dhcp::ClassId]) -> Expr {
    Expr::or(ids.iter().map(|id| {
        cx.class_names
            .get(id)
            .map_or(Expr::False, |name| Expr::member(name))
    }))
}

/// The admission rule of a piece of a pool.
fn admission(
    cx: &mut Cx<'_>,
    scope: &ScopeImage,
    pool: &PoolImage,
    ranges: &[(&Policy, Ipv4Addr, Ipv4Addr)],
    piece: (u32, u32),
) -> Expr {
    let mut parts = Vec::new();
    if scope.restricted {
        cx.need_allow = true;
        parts.push(Expr::member(ALLOW));
    }
    if !scope.classes.is_empty() {
        parts.push(members(cx, &scope.classes));
    }
    if !pool.classes.is_empty() {
        parts.push(members(cx, &pool.classes));
    }
    let member = |policy: &Policy| {
        cx.policy_names
            .get(&policy.id)
            .map_or(Expr::False, |name| Expr::member(name))
    };
    let covering: Vec<usize> = ranges
        .iter()
        .enumerate()
        .filter(|(_, (_, first, last))| u32::from(*first) <= piece.0 && piece.1 <= u32::from(*last))
        .map(|(index, _)| index)
        .collect();
    if covering.is_empty() {
        parts.push(Expr::or(ranges.iter().map(|(policy, ..)| member(policy))).negate());
    } else {
        parts.push(Expr::or(covering.iter().map(|&k| {
            Expr::and(
                std::iter::once(member(ranges[k].0)).chain(
                    ranges[..k]
                        .iter()
                        .map(|(policy, ..)| member(policy).negate()),
                ),
            )
        })));
    }
    Expr::and(parts)
}

/// The `client-class` of a pool piece: the class itself for one membership, else a class
/// `admit.<n>` added after the policies.
fn admission_class(cx: &mut Cx<'_>, rule: Expr) -> Option<String> {
    match rule {
        Expr::True => None,
        Expr::Member(name) => Some(name),
        rule => {
            let test = rule.render();
            if let Some(name) = cx.admission.get(&test) {
                return Some(name.clone());
            }
            let name = format!("admit.{}", cx.admission.len() + 1);
            cx.late_classes.push(json!({"name": name, "test": test}));
            cx.admission.insert(test, name.clone());
            Some(name)
        }
    }
}

fn dotted(address: u32) -> String {
    Ipv4Addr::from(address).to_string()
}

fn pools(
    cx: &mut Cx<'_>,
    scope: &ScopeImage,
    policies: &[&Policy],
    policy_codes: &BTreeSet<u16>,
) -> Vec<Value> {
    let ranges = range_policies(policies);
    let bounds: Vec<(u32, u32)> = ranges
        .iter()
        .map(|(_, first, last)| (u32::from(*first), u32::from(*last)))
        .collect();
    let mut out = Vec::new();
    for pool in &scope.pools {
        let label = format!("{} - {}", pool.first, pool.last);
        if pool.lease != scope.lease {
            cx.report.push(
                at("pool", &label),
                codes::POOL_LEASE,
                format!(
                    "the pool's lease time ({} s) is left out: Kea's pools have no lease times, so the subnet's ({} s) applies",
                    pool.lease.default_secs, scope.lease.default_secs
                ),
            );
        }
        let pool_values = cx.values(OptionOwner::Pool(pool.range));
        for value in pool_values
            .iter()
            .filter(|value| value.space.is_dhcp4() && policy_codes.contains(&value.code))
        {
            cx.report.push(
                at("pool", &label),
                codes::POOL_PRECEDENCE,
                format!(
                    "option {} is set by the pool and by a policy: in Kea the pool's value wins over every class, in Tenko the matching policy's",
                    value.code
                ),
            );
        }
        let data = cx.option_data(pool_values, &format!("pool {label}"), |_| false);
        for piece in split(free(pool, &scope.excluded), &bounds) {
            let rule = admission(cx, scope, pool, &ranges, piece);
            let mut entry = Map::new();
            entry.insert(
                "pool".into(),
                json!(format!("{} - {}", dotted(piece.0), dotted(piece.1))),
            );
            if let Some(class) = admission_class(cx, rule) {
                entry.insert("client-class".into(), json!(class));
            }
            if !data.is_empty() {
                entry.insert("option-data".into(), Value::Array(data.clone()));
            }
            out.push(Value::Object(entry));
        }
    }
    // A scope policy whose range touches none of the scope's pools gives nothing in Kea or
    // in Tenko; it is reported, since it is likely a mistake.
    for (policy, first, last) in &ranges {
        let inside = scope
            .pools
            .iter()
            .any(|pool| *first <= pool.last && *last >= pool.first);
        if policy.scope == Some(scope.prefix) && !inside {
            cx.report.push(
                at("policy", &policy.name),
                codes::POLICY_RANGE,
                format!(
                    "the range {first} - {last} lies outside the pools of {}: no pool is restricted to it",
                    scope.network
                ),
            );
        }
    }
    out
}

fn reservations(cx: &mut Cx<'_>, scope: &ScopeImage) -> Vec<Value> {
    let mut out = Vec::new();
    for reservation in cx
        .built
        .image
        .reservations()
        .iter()
        .filter(|reservation| reservation.scope == scope.prefix)
        .cloned()
        .collect::<Vec<_>>()
    {
        let mut entry = Map::new();
        match reservation.identity.split_first() {
            Some((1, client_id)) => {
                entry.insert("client-id".into(), json!(colon_hex(client_id)));
            }
            Some((0, rest)) if rest.len() > 1 => {
                entry.insert("hw-address".into(), json!(colon_hex(&rest[1..])));
            }
            _ => continue,
        }
        entry.insert("ip-address".into(), json!(reservation.addr.to_string()));
        if let Some(host) = cx.data.hosts.get(&reservation.host) {
            entry.insert("hostname".into(), json!(host.name.as_str()));
        }
        let label = format!("reservation {}", reservation.addr);
        let data = cx.option_data(&reservation.options, &label, |_| false);
        if !data.is_empty() {
            entry.insert("option-data".into(), Value::Array(data));
        }
        boot_fields(&reservation.options, &mut entry);
        out.push(Value::Object(entry));
    }
    out
}

/// Octets as Kea writes identifiers: lowercase hexadecimal pairs separated by colons.
pub(crate) fn colon_hex(octets: &[u8]) -> String {
    octets
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn reservation_findings(cx: &mut Cx<'_>) {
    for warning in cx.built.warnings.clone() {
        if let ReservationWarning::NoIdentity { host } = warning {
            let name = cx
                .data
                .hosts
                .get(&host)
                .map_or_else(|| host.to_string(), |host| host.name.to_string());
            cx.report.push(
                at("host", name),
                codes::RESERVATION_NO_IDENTITY,
                "the reserved host has no MAC address or client identifier, so it has no reservation in Tenko or in Kea (IPAM-18)",
            );
        }
    }
    for dropped in cx.built.dropped.clone() {
        let name = cx
            .data
            .hosts
            .get(&dropped.host)
            .map_or_else(|| dropped.host.to_string(), |host| host.name.to_string());
        cx.report.push(
            at("host", name),
            codes::RESERVATION_DROPPED,
            format!(
                "the reservation of {} is left out: its address or client is reserved by another host in the scope (IPAM-23), as in Tenko's image",
                dropped.addr
            ),
        );
    }
}

/// What one subnet needs from its shared network.
struct SharedPlan {
    /// Codes moved from the shared network's options.
    removed: BTreeSet<u16>,
}

/// The codes a scope's applicable policies set, and those of them the scope or its shared
/// network sets too.
fn conflicts(cx: &Cx<'_>, scope: &ScopeImage) -> (BTreeSet<u16>, BTreeSet<u16>) {
    let mut codes = BTreeSet::new();
    for policy in applicable(cx, scope.prefix) {
        codes.extend(classes::policy_codes(cx, policy));
    }
    let lower = level_codes(cx, OptionOwner::Scope(scope.prefix))
        .into_iter()
        .chain(
            scope
                .shared_network
                .map(|id| level_codes(cx, OptionOwner::SharedNetwork(id)))
                .unwrap_or_default(),
        )
        .filter(|code| codes.contains(code))
        .collect();
    (codes, lower)
}

fn level_codes(cx: &Cx<'_>, owner: OptionOwner) -> BTreeSet<u16> {
    cx.values(owner)
        .iter()
        .filter(|value| value.space.is_dhcp4())
        .map(|value| value.code)
        .collect()
}

fn by_code(values: &[OptionValue], codes: &BTreeSet<u16>, keep: bool) -> Vec<OptionValue> {
    values
        .iter()
        .filter(|value| !value.space.is_dhcp4() || codes.contains(&value.code) == keep)
        .cloned()
        .collect()
}

fn subnet(
    cx: &mut Cx<'_>,
    scope: &ScopeImage,
    id: u32,
    shared: Option<&SharedPlan>,
    in_shared_network: bool,
    domains: &mut Vec<ddns::Domain>,
) -> Value {
    let prefix = scope.prefix;
    let label = scope.network.to_string();
    let policies = applicable(cx, prefix);
    let (policy_codes, moved) = conflicts(cx, scope);
    let own = cx.values(OptionOwner::Scope(prefix));
    let shared_values = scope.shared_network.map_or(&[][..], |network| {
        cx.values(OptionOwner::SharedNetwork(network))
    });
    // The subnet's options: its own without the moved codes, plus the shared network's
    // values that the shared network gave up for another member and this one keeps.
    let mut values = by_code(own, &moved, false);
    if let Some(shared) = shared {
        let own_codes = level_codes(cx, OptionOwner::Scope(prefix));
        values.extend(
            shared_values
                .iter()
                .filter(|value| {
                    value.space.is_dhcp4()
                        && shared.removed.contains(&value.code)
                        && !moved.contains(&value.code)
                        && !own_codes.contains(&value.code)
                })
                .cloned(),
        );
    }
    if let Some(server_id) = scope.server_id {
        values.push(OptionValue::v4(54, server_id.octets().to_vec()));
    }
    let mut entry = Map::new();
    entry.insert("id".into(), json!(id));
    entry.insert("subnet".into(), json!(scope.network.to_string()));
    let data = cx.option_data(&values, &format!("scope {label}"), |_| false);
    entry.insert("option-data".into(), Value::Array(data));
    boot_fields(&values, &mut entry);
    if let Some(row) = cx.data.scopes.get(&prefix) {
        if let Some(lease) = &row.lease {
            lease_params(lease, true, &mut entry);
        }
        if !in_shared_network && let Some(authoritative) = row.authoritative {
            entry.insert("authoritative".into(), json!(authoritative));
        }
    }
    entry.insert(
        "pools".into(),
        Value::Array(pools(cx, scope, &policies, &policy_codes)),
    );
    entry.insert("reservations".into(), Value::Array(reservations(cx, scope)));
    let mut required: Vec<String> = policies
        .iter()
        .filter_map(|policy| classes::options_class(cx, policy))
        .collect();
    if !moved.is_empty() {
        let defaults = merge([
            by_code(shared_values, &moved, true).as_slice(),
            by_code(own, &moved, true).as_slice(),
        ]);
        let name = format!("scope.{}.defaults", scope.network);
        let data = cx.option_data(&defaults, &format!("scope {label}"), |_| false);
        let mut class = Map::new();
        class.insert("name".into(), json!(name));
        class.insert("test".into(), json!(Expr::True.render()));
        class.insert("only-if-required".into(), json!(true));
        class.insert("option-data".into(), Value::Array(data));
        boot_fields(&defaults, &mut class);
        cx.late_classes.push(Value::Object(class));
        required.push(name);
    }
    if !required.is_empty() {
        entry.insert("require-client-classes".into(), json!(required));
    }
    if scope.restricted {
        cx.report.push(
            at("scope", &label),
            codes::SCOPE_RESTRICTED,
            "the scope serves allow-listed and reserved clients only: in Kea its pools require the class tenko.allow and reservations lie outside the pools, so other clients get no address, but Kea still answers them (a NAK or an INFORM reply) where Tenko stays silent",
        );
    }
    if let Some(domain) = ddns::subnet(cx, scope, &mut entry) {
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

/// The shared networks and the subnets outside them, and what DDNS needs.
pub(crate) fn build(cx: &mut Cx<'_>) -> (Vec<Value>, Vec<Value>, Vec<ddns::Domain>) {
    reservation_findings(cx);
    let scopes: Vec<(ScopeImage, u32)> = cx
        .built
        .image
        .scopes()
        .iter()
        .filter_map(|scope| {
            cx.subnet_ids
                .get(&scope.prefix)
                .map(|id| (scope.clone(), *id))
        })
        .collect();
    let mut domains = Vec::new();
    let mut groups: BTreeMap<String, (tenko_core::dhcp::SharedNetworkId, Vec<(ScopeImage, u32)>)> =
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
    let mut subnet4 = Vec::new();
    for (scope, id) in &alone {
        subnet4.push(subnet(cx, scope, *id, None, false, &mut domains));
    }
    let mut shared = Vec::new();
    for (name, (network, members)) in groups {
        let mut removed = BTreeSet::new();
        for (scope, _) in &members {
            let (_, moved) = conflicts(cx, scope);
            removed.extend(moved);
        }
        let shared_codes = level_codes(cx, OptionOwner::SharedNetwork(network));
        let removed: BTreeSet<u16> = removed.intersection(&shared_codes).copied().collect();
        let plan = SharedPlan { removed };
        let kept = by_code(
            cx.values(OptionOwner::SharedNetwork(network)),
            &plan.removed,
            false,
        );
        let mut entry = Map::new();
        entry.insert("name".into(), json!(name));
        let row = cx.data.shared_networks.get(&network).cloned();
        if let Some(interface) = row.as_ref().and_then(|row| row.interface.clone()) {
            entry.insert("interface".into(), json!(interface));
        }
        let data = cx.option_data(&kept, &format!("shared network {name}"), |_| false);
        entry.insert("option-data".into(), Value::Array(data));
        boot_fields(&kept, &mut entry);
        let flags: BTreeSet<bool> = members
            .iter()
            .map(|(scope, _)| scope.authoritative)
            .collect();
        if flags.len() > 1 {
            cx.report.push(
                at("shared network", &name),
                codes::SHARED_AUTHORITATIVE,
                "the scopes of the shared network differ in the authoritative flag; Kea needs one value per shared network, so the first scope's is used",
            );
        }
        if let Some((first, _)) = members.first() {
            entry.insert("authoritative".into(), json!(first.authoritative));
        }
        let mut inside = Vec::new();
        for (scope, id) in &members {
            inside.push(subnet(cx, scope, *id, Some(&plan), true, &mut domains));
        }
        entry.insert("subnet4".into(), Value::Array(inside));
        if let Some(description) = row.and_then(|row| row.description) {
            entry.insert("user-context".into(), json!({"description": description}));
        }
        shared.push(Value::Object(entry));
    }
    (shared, subnet4, domains)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pools_lose_their_exclusions_and_split_at_ranges() {
        let a = |text: &str| u32::from(text.parse::<Ipv4Addr>().expect("address"));
        let pool = PoolImage {
            range: tenko_core::RangeId::generate(),
            first: "192.0.2.10".parse().expect("address"),
            last: "192.0.2.50".parse().expect("address"),
            lease: tenko_core::dhcp::LeaseTimes::default(),
            classes: Vec::new(),
            options: Vec::new(),
        };
        let excluded = [
            (
                "192.0.2.1".parse().expect("a"),
                "192.0.2.10".parse().expect("a"),
            ),
            (
                "192.0.2.20".parse().expect("a"),
                "192.0.2.20".parse().expect("a"),
            ),
            (
                "192.0.2.50".parse().expect("a"),
                "192.0.2.60".parse().expect("a"),
            ),
        ];
        let free = free(&pool, &excluded);
        assert_eq!(
            free,
            [
                (a("192.0.2.11"), a("192.0.2.19")),
                (a("192.0.2.21"), a("192.0.2.49"))
            ]
        );
        let pieces = split(free, &[(a("192.0.2.30"), a("192.0.2.39"))]);
        assert_eq!(
            pieces,
            [
                (a("192.0.2.11"), a("192.0.2.19")),
                (a("192.0.2.21"), a("192.0.2.29")),
                (a("192.0.2.30"), a("192.0.2.39")),
                (a("192.0.2.40"), a("192.0.2.49")),
            ]
        );
    }
}
