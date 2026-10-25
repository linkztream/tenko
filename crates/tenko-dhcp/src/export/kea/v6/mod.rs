//! The `Dhcp6` document of the Kea export (WP9.3, the DHCPv6 half; `docs/dhcp.md` section
//! 18): the DHCPv6 scopes of WP9.1 as `kea-dhcp6` reads them, and the DHCPv6 leases as
//! its memfile lease file (`kea-leases6.csv`, [`leases`]).
//!
//! - **Global.** The server's lease times as the engine derives them (the preferred
//!   lifetime five eighths of the valid one, T1 and T2 half and four fifths of the
//!   preferred one, unless set), each with its `min-` and `max-` set to the same value
//!   because the engine grants the default and nothing a client asks for; the server's
//!   `dhcp6` options; `server-id` from the role's server DUID (DUID-LLT, DUID-EN and
//!   DUID-LL; Kea holds no DUID-UUID); `interfaces-config` from the DHCPv6 listeners;
//!   `mac-sources` in the engine's order (option 79, then the DUID) and
//!   `host-reservation-identifiers` DUID first, so that reservations by MAC address match
//!   as in Tenko; the memfile lease database.
//! - **Shared networks and subnets** ([`subnets`]). Tenko's shared networks become
//!   `shared-networks`, the other DHCPv6 scopes `subnet6` entries numbered from 1 in the
//!   order of their networks, each with its lifetimes, `rapid-commit` (on unless the scope
//!   turns it off, as in Tenko), the relay Interface-Id as `interface-id` and the
//!   interface of a direct listener as `interface`. Pools are the `dhcp_pool` ranges with
//!   the exclusions cut out (and the Subnet-Router anycast address, which the engine never
//!   leases); `pd-pools` are the delegation pools (`dhcp_pd_pool`, WP9.2) as prefixes with
//!   their delegated length, every delegated prefix an exclusion touches cut out (WP9.4);
//!   reservations go by `duid`, else `hw-address`, with `ip-addresses`, the host name and
//!   the interface's options.
//! - **Options.** `option-data` at the global, shared-network, subnet, pool and
//!   reservation levels with Kea's names; options 23 and 24 are `always-send`, as the
//!   engine sends them unasked; the custom definitions of `dhcp6` as `option-def`.
//! - **Filters.** Deny entries become the `DROP` class and allow entries the class
//!   `tenko.allow` that the pools of restricted scopes require, both tested against the
//!   client's link-layer address as the engine takes it ([`super::expr::mac6`]).
//! - **DDNS.** The `ddns-*` parameters per subnet with the DHCPv6 names and `dhcp-ddns`,
//!   sharing the `DhcpDdns` skeleton with the DHCPv4 half.
//!
//! What Kea does not express, or what Tenko does not do for DHCPv6, goes to the report:
//! classes and policies (DHCPv4 only in Tenko), the MAC filters' relay caveat, a server
//! DUID Kea cannot hold or that is not known, relay listeners that bind an address,
//! diverging Interface-Ids in a shared network, pool lifetimes and the reservations Tenko's
//! image drops.

mod leases;
mod subnets;

#[cfg(test)]
mod tests;

use ipnet::IpNet;
use serde_json::{Map, Value, json};
use tenko_core::dhcp::{
    FilterKind, LeaseTimes, OptionOwner, OptionValue, ReservationWarning, Scope6Settings,
};

use super::{Cx, LEASE_FILE6, at, classes::ALLOW, codes, ddns, expr, options::hex};
use crate::{v4::engine::ListenMode, v6::engine::alloc::Lifetimes};

pub use leases::HEADER;

/// The codes the engine sends without being asked (RFC 3646): Kea's `always-send`.
const UNASKED: [u16; 2] = [23, 24];

/// Whether the export has a `Dhcp6` document: a scope on an IPv6 prefix, or a DHCPv6
/// listener of the role.
pub(crate) fn wanted(cx: &Cx<'_>) -> bool {
    cx.input
        .listeners6
        .is_some_and(|listeners| !listeners.is_empty())
        || cx.data.scopes.keys().any(|prefix| {
            cx.data
                .prefixes
                .get(prefix)
                .is_some_and(|row| matches!(row.cidr, IpNet::V6(_)))
        })
}

/// The lifetimes of an address under `times` and `settings`, derived as the engine derives
/// them (`v6::engine::alloc::lifetimes`, which a property test compares this with).
pub fn lifetimes(times: &LeaseTimes, settings: &Scope6Settings) -> Lifetimes {
    let valid = times.grant(None).max(1);
    let preferred = settings.preferred(valid).max(1);
    let (t1, t2) = if times.t1_secs.is_some() || times.t2_secs.is_some() {
        times.renewal_times(valid)
    } else {
        (
            preferred / 2,
            u32::try_from(u64::from(preferred) * 4 / 5).unwrap_or(preferred),
        )
    };
    let t2 = t2.min(preferred);
    let t1 = t1.min(t2);
    Lifetimes {
        valid,
        preferred,
        t1,
        t2,
    }
}

/// The lifetimes as Kea's parameters: the engine grants exactly these, so the bounds are
/// the same values.
pub(crate) fn lifetime_params(lifetimes: Lifetimes, out: &mut Map<String, Value>) {
    for (name, value) in [
        ("valid-lifetime", lifetimes.valid),
        ("min-valid-lifetime", lifetimes.valid),
        ("max-valid-lifetime", lifetimes.valid),
        ("preferred-lifetime", lifetimes.preferred),
        ("min-preferred-lifetime", lifetimes.preferred),
        ("max-preferred-lifetime", lifetimes.preferred),
        ("renew-timer", lifetimes.t1),
        ("rebind-timer", lifetimes.t2),
    ] {
        out.insert(name.into(), json!(value));
    }
}

/// `option-data` of the `dhcp6` values; the other spaces belong to DHCPv4.
pub(crate) fn option_data(cx: &mut Cx<'_>, values: &[OptionValue]) -> Vec<Value> {
    values
        .iter()
        .filter(|value| value.space.is_dhcp6())
        .map(|value| cx.options6.entry(value, UNASKED.contains(&value.code)))
        .collect()
}

/// `server-id` from the role's server DUID.
fn server_id(cx: &mut Cx<'_>) -> Option<Value> {
    const AFTER: &str = "so the clients' next RENEW, which names Tenko's DUID, goes unanswered and they keep their addresses through a REBIND at T2, which Kea answers from the lease file";
    let Some(duid) = cx.input.server_duid else {
        cx.report.push(
            at("settings", "server DUID"),
            codes::V6_SERVER_ID_UNKNOWN,
            format!(
                "the dhcp role's server DUID is not known to the export: the Dhcp6 document has no server-id and Kea makes a DUID-LLT of its own, {AFTER}; set server-id to the DUID of [dhcp.v6] server_duid"
            ),
        );
        return None;
    };
    let u16_at = |at: usize| u16::from_be_bytes([duid[at], duid[at + 1]]);
    let u32_at =
        |at: usize| u32::from_be_bytes([duid[at], duid[at + 1], duid[at + 2], duid[at + 3]]);
    match (duid.len(), duid.get(..2)) {
        (9.., Some([0, 1])) => Some(json!({
            "type": "LLT",
            "htype": u16_at(2),
            "time": u32_at(4),
            "identifier": hex(&duid[8..]),
        })),
        (7.., Some([0, 2])) => Some(json!({
            "type": "EN",
            "enterprise-id": u32_at(2),
            "identifier": hex(&duid[6..]),
        })),
        (5.., Some([0, 3])) => Some(json!({
            "type": "LL",
            "htype": u16_at(2),
            "identifier": hex(&duid[4..]),
        })),
        _ => {
            let kind = if duid.get(..2) == Some(&[0, 4]) {
                "a DUID-UUID (RFC 6355)"
            } else {
                "of a type Kea does not know"
            };
            cx.report.push(
                at("settings", "server DUID"),
                codes::V6_SERVER_ID_TYPE,
                format!(
                    "the server DUID {} is {kind}, which Kea's server-id cannot hold (it takes a DUID-LLT, DUID-EN or DUID-LL): Kea makes a DUID-LLT of its own, {AFTER}",
                    hex(duid)
                ),
            );
            None
        }
    }
}

/// `interfaces-config` from the role's DHCPv6 listeners.
fn interfaces(cx: &mut Cx<'_>) -> Value {
    let Some(listeners) = cx.input.listeners6 else {
        cx.report.push(
            at("listeners", "DHCPv6 of the role"),
            codes::INTERFACES_UNKNOWN,
            "the dhcp role does not run in this process, so its DHCPv6 listeners are not known: interfaces-config of Dhcp6 lists none; name the interfaces kea-dhcp6 listens on (`<interface>/<address>` for relayed traffic)",
        );
        return json!({"interfaces": []});
    };
    let mut names: Vec<String> = Vec::new();
    let mut by_address = Vec::new();
    for listener in listeners {
        let address = listener.address.ip();
        let name = match (&listener.interface, listener.mode) {
            (Some(interface), ListenMode::Relay) => format!("{interface}/{address}"),
            (Some(interface), ListenMode::Direct) => interface.clone(),
            (None, _) => {
                by_address.push(address.to_string());
                "*".to_owned()
            }
        };
        if !names.contains(&name) {
            names.push(name);
        }
    }
    if !by_address.is_empty() {
        cx.report.push(
            at("listeners", by_address.join(", ")),
            codes::V6_INTERFACES_ADDRESS,
            format!(
                "Tenko receives relayed DHCPv6 on the address {}; kea-dhcp6 receives unicast only on an address that interfaces-config names as `<interface>/<address>`, so replace the `*` the export lists with it",
                by_address.join(", ")
            ),
        );
    }
    if names.is_empty() {
        cx.report.push(
            at("listeners", "DHCPv6 of the role"),
            codes::INTERFACES_UNKNOWN,
            "the dhcp role has no DHCPv6 listener: interfaces-config of Dhcp6 lists none",
        );
    }
    json!({ "interfaces": names })
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// The findings of the DHCPv6 half that belong to no subnet.
fn findings(cx: &mut Cx<'_>) {
    let scopes6 = cx.subnet_ids6.len();
    let classes = cx.data.classes.len();
    let policies = cx.data.policies.len();
    let admitting = cx
        .built
        .image
        .v6()
        .scopes()
        .iter()
        .filter(|scope| {
            cx.data
                .scopes
                .get(&scope.prefix)
                .is_some_and(|row| !row.classes.is_empty())
        })
        .count();
    if scopes6 > 0 && classes + policies + admitting > 0 {
        cx.report.push(
            at("classes", "and policies"),
            codes::V6_CLASSES,
            format!(
                "Tenko's classes and policies ({} and {}) apply to DHCPv4 clients only, as do the classes a scope or pool admits{}: the Dhcp6 document has no client classes from them, and Kea serves the DHCPv6 clients without them, as Tenko does",
                plural(classes, "class", "classes"),
                plural(policies, "policy", "policies"),
                if admitting > 0 {
                    format!(" (named on {})", plural(admitting, "DHCPv6 scope", "DHCPv6 scopes"))
                } else {
                    String::new()
                }
            ),
        );
    }
    let filters = cx.data.filters.len();
    if scopes6 > 0 && filters > 0 {
        cx.report.push(
            at("filters", "DHCPv6"),
            codes::V6_FILTERS,
            format!(
                "the {} apply to DHCPv6 clients by their link-layer address: in Dhcp6 the deny entries are the DROP class and the allow entries the class tenko.allow, which test option 79 (RFC 6939) of the relay nearest the server and the client's DUID-LLT or DUID-LL; where more than one relay forwards, Tenko reads option 79 of the relay on the client's link instead",
                plural(filters, "MAC filter entry", "MAC filter entries"),
            ),
        );
    }
    for warning in cx.built.warnings6.clone() {
        if let ReservationWarning::NoIdentity { host } = warning {
            let name = cx
                .data
                .hosts
                .get(&host)
                .map_or_else(|| host.to_string(), |host| host.name.to_string());
            cx.report.push(
                at("host", name),
                codes::RESERVATION_NO_IDENTITY,
                "the reserved host has an IPv6 address but no DUID or MAC address, so it has no DHCPv6 reservation in Tenko or in Kea (IPAM-18)",
            );
        }
    }
    for dropped in cx.built.dropped6.clone() {
        let name = cx
            .data
            .hosts
            .get(&dropped.host)
            .map_or_else(|| dropped.host.to_string(), |host| host.name.to_string());
        cx.report.push(
            at("host", name),
            codes::RESERVATION_DROPPED,
            format!(
                "the DHCPv6 reservation of {} is left out: its address or client is reserved by another host in the scope (IPAM-23), as in Tenko's image",
                dropped.addr
            ),
        );
    }
}

/// The client classes of the `Dhcp6` document: `DROP` for the deny filters, the allow class
/// when a restricted scope's pools name it.
fn client_classes(cx: &Cx<'_>) -> Vec<Value> {
    let patterns = |kind: FilterKind| {
        expr::Expr::or(
            cx.data
                .filters
                .values()
                .filter(|filter| filter.kind == kind)
                .map(|filter| expr::mac6(&filter.mac)),
        )
    };
    let mut out = Vec::new();
    if !cx.subnet_ids6.is_empty()
        && cx
            .data
            .filters
            .values()
            .any(|filter| filter.kind == FilterKind::Deny)
    {
        out.push(json!({"name": "DROP", "test": patterns(FilterKind::Deny).render()}));
    }
    if cx.need_allow6 {
        out.push(json!({"name": ALLOW, "test": patterns(FilterKind::Allow).render()}));
    }
    out
}

/// The `Dhcp6` document without its `option-def` and `user-context` ([`finish`]), and the
/// domains its subnets write names in.
pub(crate) fn build(cx: &mut Cx<'_>) -> (Map<String, Value>, Vec<ddns::Domain>) {
    subnets::number(cx);
    findings(cx);
    let mut dhcp6 = Map::new();
    dhcp6.insert("interfaces-config".into(), interfaces(cx));
    dhcp6.insert(
        "lease-database".into(),
        json!({"type": "memfile", "persist": true, "name": LEASE_FILE6, "lfc-interval": 3600}),
    );
    let settings = cx.data.settings.clone().unwrap_or_default();
    lifetime_params(
        lifetimes(&settings.lease, &Scope6Settings::default()),
        &mut dhcp6,
    );
    dhcp6.insert(
        "host-reservation-identifiers".into(),
        json!(["duid", "hw-address"]),
    );
    dhcp6.insert(
        "mac-sources".into(),
        json!(["client-link-addr-option", "duid"]),
    );
    if let Some(server_id) = server_id(cx) {
        dhcp6.insert("server-id".into(), server_id);
    }
    let server = cx.values(OptionOwner::Server);
    let global = option_data(cx, server);
    dhcp6.insert("option-data".into(), Value::Array(global));
    let (shared, subnet6, domains) = subnets::build(cx);
    // Kea 2.6 refuses an empty client-classes list, so none is written then.
    let classes = client_classes(cx);
    if !classes.is_empty() {
        dhcp6.insert("client-classes".into(), Value::Array(classes));
    }
    dhcp6.insert("shared-networks".into(), Value::Array(shared));
    dhcp6.insert("subnet6".into(), Value::Array(subnet6));
    (dhcp6, domains)
}

/// The parts written after DDNS: the option definitions and the export's context.
pub(crate) fn finish(cx: &mut Cx<'_>, dhcp6: &mut Map<String, Value>) {
    dhcp6.insert("option-def".into(), Value::Array(cx.options6.defs()));
    dhcp6.insert(
        "user-context".into(),
        json!({"tenko-export": {"revision": cx.data.revision.0, "generated": cx.input.now.to_string(), "format": "kea 2.6"}}),
    );
}

/// The DHCPv6 lease file.
pub(crate) fn leases_csv(cx: &mut Cx<'_>) -> String {
    leases::csv(cx)
}
