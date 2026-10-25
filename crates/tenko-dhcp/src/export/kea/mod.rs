//! The Kea export (WP9.3, MIG-16, decision P3-Q17): the configurations of Kea 2.6's
//! `kea-dhcp4` and `kea-dhcp6` with the leases as their memfile lease files, so that Kea
//! starts from them and keeps the clients' addresses, plus a report of what Kea cannot
//! express.
//!
//! [`export`] takes the rows the role serves from ([`DhcpData`], with the leases when they
//! are wanted), the names of the DNS zones, the role's listeners, its server DUID and the
//! time, and gives a [`KeaExport`]:
//!
//! - `dhcp4`: the document `{"Dhcp4": {..}}` that `kea-dhcp4 -c` reads;
//! - `dhcp6`: the document `{"Dhcp6": {..}}` that `kea-dhcp6 -c` reads, when the
//!   configuration has a scope on an IPv6 prefix or the role a DHCPv6 listener ([`v6`]);
//! - `dhcp_ddns`: a `{"DhcpDdns": {..}}` skeleton for `kea-dhcp-ddns` when a scope of
//!   either family writes names (its DNS servers and TSIG keys are the operator's);
//! - `leases4_csv` and `leases6_csv`: `kea-leases4.csv` and `kea-leases6.csv` in the
//!   columns Kea 2.6 reads;
//! - `report`: the [`LossReport`] of both families, one entry per item Kea does not
//!   express as Tenko does, in the shape of the migration imports (`location`, a stable
//!   `code`, an English `detail`).
//!
//! The translation, level by level (`docs/dhcp.md` section 18 has the tables):
//!
//! - **Global.** The server's lease times (`valid-lifetime`, `min-` and `max-valid-lifetime`,
//!   T1 and T2 as half and seven eighths unless set), `authoritative`, the server's options,
//!   the `option-def` entries, `interfaces-config` from the role's listeners, the memfile
//!   lease database, `host-reservation-identifiers` client identifier first.
//! - **Shared networks and subnets.** Tenko's shared networks become `shared-networks` with
//!   their scopes inside; the other scopes are `subnet4` entries, numbered from 1 in the
//!   order of their networks. Pools are the IPAM ranges of role `dhcp_pool` with the
//!   scope's exclusions (explicit, the reserved and infrastructure ranges, static
//!   addresses) cut out and split where a policy's range begins or ends; reservations are
//!   the reserved hosts the image derives, by client identifier or MAC address.
//! - **Classes and policies.** Each class is a client class whose test is the OR of its
//!   matches ([`expr`]). Each enabled policy is a client class whose test is its condition
//!   and which carries its lease times; its options are a second class that is
//!   `only-if-required` and named in the `require-client-classes` of every subnet the
//!   policy applies to, in Tenko's order (the scope's policies, then the server's), so that
//!   the first matching policy wins per option as in Tenko. Kea puts a subnet's options
//!   above a class's, Tenko a policy's above a scope's: an option a policy also sets moves
//!   from the subnet and its shared network into a last required class of the subnet.
//!   Policy ranges, pool and scope classes and the restricted flag become the
//!   `client-class` of a pool.
//! - **Filters.** Deny entries become Kea's `DROP` class; allow entries a class that the
//!   pools of restricted scopes require.
//! - **Boot.** `next-server` from option 150 (else 66 when it is an address) and
//!   `boot-file-name` from option 67 at each level; PXE and HTTP boot clients get option 60
//!   echoed and option 43 as Tenko sends them.
//! - **DDNS.** `ddns-*` parameters per subnet and `dhcp-ddns` (ADR 0020 mapped onto Kea's
//!   parameters), and the `DhcpDdns` skeleton.
//!
//! The `Dhcp6` document ([`v6`]) follows the same levels for the DHCPv6 scopes of WP9.1:
//! `subnet6` and `shared-networks` with pools, DUID and MAC reservations, options, the
//! lifetimes as the engine derives them, rapid commit, the relay Interface-Id, the MAC
//! filters, the server DUID and DDNS.

mod classes;
pub mod expr;
mod leases;
pub mod options;
mod subnets;
// The DDNS hints and the DhcpDdns skeleton.
mod ddns;
// The DHCPv6 half of WP9.3: the Dhcp6 document and the DHCPv6 lease file.
pub mod v6;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use tenko_core::{
    PrefixId, Timestamp,
    dhcp::{ClassId, OptionDef, OptionOwner, OptionValue, Policy, PolicyId},
    dns::{DnsName, ZoneId, tables::ZONES},
    ir::{LossReport, SourceLocation},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, StoreError};

use crate::{
    config::image::{Built, build},
    feed::DhcpData,
    server::ListenerInfo,
    v4::engine::ListenMode,
    v6::server::Listener6Info,
};

pub use self::options::Options;

/// The file names the command line writes.
pub mod files {
    /// The `Dhcp4` configuration.
    pub const CONFIG: &str = "kea-dhcp4.json";
    /// The memfile lease file.
    pub const LEASES: &str = "kea-leases4.csv";
    /// The loss report.
    pub const REPORT: &str = "kea-export-report.json";
    /// The `DhcpDdns` skeleton.
    pub const DDNS: &str = "kea-dhcp-ddns.json";
    /// The `Dhcp6` configuration.
    pub const CONFIG6: &str = "kea-dhcp6.json";
    /// The DHCPv6 memfile lease file.
    pub const LEASES6: &str = "kea-leases6.csv";
}

/// Where Kea's memfile keeps the leases: its default data directory, the only one Kea 2.6
/// accepts for the lease file.
pub const LEASE_FILE: &str = "/var/lib/kea/kea-leases4.csv";

/// Where Kea's memfile keeps the DHCPv6 leases.
pub const LEASE_FILE6: &str = "/var/lib/kea/kea-leases6.csv";

/// The stable codes of the loss report's entries.
pub mod codes {
    /// A scope that is disabled is left out.
    pub const SCOPE_DISABLED: &str = "export.kea.scope.disabled";
    /// A second scope on a network that another VRF serves already.
    pub const SCOPE_DUPLICATE: &str = "export.kea.scope.duplicate";
    /// A restricted scope: the allow list becomes the class of its pools.
    pub const SCOPE_RESTRICTED: &str = "export.kea.scope.restricted";
    /// A pool's own lease times: Kea's pools have none.
    pub const POOL_LEASE: &str = "export.kea.pool.lease";
    /// A pool option that a policy also sets: Kea's pool level wins.
    pub const POOL_PRECEDENCE: &str = "export.kea.pool.precedence";
    /// A class match Kea reads only in part (a user class beyond the first instance).
    pub const CLASS_PARTIAL: &str = "export.kea.class.partial";
    /// A disabled policy is left out.
    pub const POLICY_DISABLED: &str = "export.kea.policy.disabled";
    /// A policy term names a class that no longer exists: false, as in Tenko.
    pub const POLICY_CLASS_MISSING: &str = "export.kea.policy.class_missing";
    /// A policy condition Kea reads only in part.
    pub const POLICY_PARTIAL: &str = "export.kea.policy.partial";
    /// A policy's DDNS settings: Kea's classes carry none.
    pub const POLICY_DDNS: &str = "export.kea.policy.ddns";
    /// A policy's T1 and T2: Kea's classes carry none.
    pub const POLICY_TIMERS: &str = "export.kea.policy.timers";
    /// A scope policy's lease times apply in every subnet in Kea.
    pub const POLICY_LEASE_EVERYWHERE: &str = "export.kea.policy.lease_everywhere";
    /// A scope policy's range lies outside its scope's pools.
    pub const POLICY_RANGE: &str = "export.kea.policy.range";
    /// Deny filters become Kea's `DROP` class.
    pub const FILTER_DENY: &str = "export.kea.filter.deny";
    /// An option value of a vendor space: Kea needs option 43 to encapsulate the space.
    pub const OPTION_VENDOR_SPACE: &str = "export.kea.option.vendor_space";
    /// Option 1: Kea derives the subnet mask from the subnet.
    pub const OPTION_SUBNET_MASK: &str = "export.kea.option.subnet_mask";
    /// A reservation the image dropped (an identity or an address reserved twice).
    pub const RESERVATION_DROPPED: &str = "export.kea.reservation.dropped";
    /// A reserved host without a MAC address or client identifier (IPAM-18).
    pub const RESERVATION_NO_IDENTITY: &str = "export.kea.reservation.no_identity";
    /// The scopes of a shared network differ in the authoritative flag.
    pub const SHARED_AUTHORITATIVE: &str = "export.kea.shared_network.authoritative";
    /// The role's listeners are not known (the role does not run in this process).
    pub const INTERFACES_UNKNOWN: &str = "export.kea.interfaces.unknown";
    /// A relay listener binds an address; Kea binds interfaces.
    pub const INTERFACES_ADDRESS: &str = "export.kea.interfaces.address";
    /// A proxy DHCP listener (port 4011): Kea has none.
    pub const INTERFACES_PROXY: &str = "export.kea.interfaces.proxy";
    /// Conflict detection before an offer (TGL-16): Kea's core has none.
    pub const CONFLICT_DETECTION: &str = "export.kea.conflict_detection";
    /// The lease history: Kea keeps none.
    pub const HISTORY: &str = "export.kea.history";
    /// A DDNS TTL in seconds: Kea takes a share of the lease time.
    pub const DDNS_TTL: &str = "export.kea.ddns.ttl";
    /// DDNS without option 81 off: Kea writes names for option 12 clients too.
    pub const DDNS_LEGACY: &str = "export.kea.ddns.legacy_clients";
    /// Names outside the zone refused: Kea has no such check.
    pub const DDNS_FOREIGN: &str = "export.kea.ddns.refuse_foreign";
    /// PTR records off for a scope whose reverse domain another scope needs.
    pub const DDNS_REVERSE: &str = "export.kea.ddns.reverse";
    /// A scope that writes names but has no zone the export can name.
    pub const DDNS_ZONE: &str = "export.kea.ddns.zone";
    /// `kea-dhcp-ddns` needs the DNS servers and keys filled in.
    pub const DDNS_D2: &str = "export.kea.ddns.d2";
    /// A lease of a scope the export left out.
    pub const LEASE_SCOPE: &str = "export.kea.lease.scope";
    // The DHCPv6 half: what only the Dhcp6 document reports.
    /// Tenko's classes and policies apply to DHCPv4 only: the Dhcp6 document has none.
    pub const V6_CLASSES: &str = "export.kea.v6.classes";
    /// The MAC filters in Dhcp6: Kea reads option 79 of the relay nearest the server.
    pub const V6_FILTERS: &str = "export.kea.v6.filters";
    /// The server DUID is not known (the role does not run in this process).
    pub const V6_SERVER_ID_UNKNOWN: &str = "export.kea.v6.server_id.unknown";
    /// A server DUID of a type Kea's `server-id` cannot hold (DUID-UUID).
    pub const V6_SERVER_ID_TYPE: &str = "export.kea.v6.server_id.type";
    /// A relay Interface-Id Kea cannot take: beside an interface, or one of several in a
    /// shared network.
    pub const V6_INTERFACE_ID: &str = "export.kea.v6.interface_id";
    /// A DHCPv6 relay listener binds an address; Kea receives unicast only on
    /// `<interface>/<address>`.
    pub const V6_INTERFACES_ADDRESS: &str = "export.kea.v6.interfaces.address";
}

/// What the export reads besides the rows.
#[derive(Debug, Clone, Copy)]
pub struct KeaInput<'a> {
    /// The rows: the configuration, the IPAM rows and, for the lease file, the leases.
    pub data: &'a DhcpData,
    /// The names of the DNS zones a scope's DDNS settings name.
    pub zones: &'a BTreeMap<ZoneId, DnsName>,
    /// The role's listeners; none when the role does not run in this process.
    pub listeners: Option<&'a [ListenerInfo]>,
    /// The role's DHCPv6 listeners; none when the role does not run in this process.
    pub listeners6: Option<&'a [Listener6Info]>,
    /// The role's server DUID (option 2); none when it is not known.
    pub server_duid: Option<&'a [u8]>,
    /// The time of the export.
    pub now: Timestamp,
    /// Whether the lease file is written.
    pub leases: bool,
    /// Whether conflict detection is on (the setting, else the security profile's
    /// default).
    pub conflict_detection: bool,
}

/// The export.
#[derive(Debug, Clone, PartialEq)]
pub struct KeaExport {
    /// `{"Dhcp4": {..}}`.
    pub dhcp4: Value,
    /// `{"Dhcp6": {..}}` when the configuration has a scope on an IPv6 prefix or the role
    /// a DHCPv6 listener.
    pub dhcp6: Option<Value>,
    /// `{"DhcpDdns": {..}}` when a scope writes names.
    pub dhcp_ddns: Option<Value>,
    /// The memfile lease file, when the leases were asked for.
    pub leases4_csv: Option<String>,
    /// The DHCPv6 memfile lease file, when the leases were asked for and there is a
    /// `Dhcp6` document.
    pub leases6_csv: Option<String>,
    /// What Kea does not express as Tenko does.
    pub report: LossReport,
}

/// The names of the DNS zones, for the DDNS settings.
///
/// # Errors
///
/// The store's error.
pub fn zone_names(view: &dyn ReadView) -> Result<BTreeMap<ZoneId, DnsName>, StoreError> {
    Ok(view
        .scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(id, zone, _)| (id, zone.name))
        .collect())
}

/// A location in the report: the kind of item and its name.
pub(crate) fn at(kind: &str, name: impl std::fmt::Display) -> SourceLocation {
    SourceLocation {
        sheet: Some(format!("{kind} {name}")),
        row: None,
        column: None,
    }
}

/// What the parts of the export share.
pub(crate) struct Cx<'a> {
    pub(crate) input: KeaInput<'a>,
    pub(crate) data: &'a DhcpData,
    pub(crate) built: Built,
    pub(crate) report: LossReport,
    pub(crate) options: Options,
    /// The option writer of the `Dhcp6` document.
    pub(crate) options6: Options,
    /// Kea's subnet identifier of each exported scope.
    pub(crate) subnet_ids: BTreeMap<PrefixId, u32>,
    /// Kea's subnet identifier of each exported DHCPv6 scope.
    pub(crate) subnet_ids6: BTreeMap<PrefixId, u32>,
    /// Kea's name of each class.
    pub(crate) class_names: BTreeMap<ClassId, String>,
    /// Kea's name of each exported policy's class.
    pub(crate) policy_names: BTreeMap<PolicyId, String>,
    /// The exported policies, in Tenko's order (scope policies by scope and order, then the
    /// server's).
    pub(crate) policies: Vec<&'a Policy>,
    /// Whether a restricted scope's pools name the allow class.
    pub(crate) need_allow: bool,
    /// The classes the subnets add (pool admission, scope defaults), after the policies'.
    pub(crate) late_classes: Vec<Value>,
    /// Pool admission classes by their test.
    pub(crate) admission: BTreeMap<String, String>,
    /// Whether a restricted DHCPv6 scope's pools name the allow class.
    pub(crate) need_allow6: bool,
}

impl<'a> Cx<'a> {
    /// The values of an owner's option set.
    pub(crate) fn values(&self, owner: OptionOwner) -> &'a [OptionValue] {
        self.data
            .option_sets
            .get(&owner)
            .map_or(&[][..], |set| set.values.as_slice())
    }

    /// `option-data` of values, leaving out (and reporting) what Kea cannot take there.
    pub(crate) fn option_data(
        &mut self,
        values: &[OptionValue],
        owner: &str,
        always_send: impl Fn(&OptionValue) -> bool,
    ) -> Vec<Value> {
        let mut out = Vec::new();
        for value in values {
            if value.space.is_vendor() {
                self.report.push(
                    at("option set", owner),
                    codes::OPTION_VENDOR_SPACE,
                    format!(
                        "option {} of the vendor space {} is left out: Kea sends a vendor space only inside an option 43 that encapsulates it, which the export cannot tie to the vendor class",
                        value.code,
                        value.space.as_str()
                    ),
                );
                continue;
            }
            if value.space.is_dhcp4() && value.code == 1 {
                self.report.push(
                    at("option set", owner),
                    codes::OPTION_SUBNET_MASK,
                    "option 1 (subnet-mask) is left out: Kea derives the subnet mask from the subnet",
                );
                continue;
            }
            if !value.space.is_dhcp4() {
                continue;
            }
            out.push(self.options.entry(value, always_send(value)));
        }
        out
    }
}

/// Puts the boot fields of a level's options into `out`: `boot-file-name` from option 67,
/// `next-server` from option 150 (its first address) or option 66 when it is an address.
pub(crate) fn boot_fields(values: &[OptionValue], out: &mut Map<String, Value>) {
    let code = |code: u16| {
        values
            .iter()
            .find(|value| value.space.is_dhcp4() && value.code == code)
    };
    if let Some(file) = code(67).and_then(options::text) {
        out.insert("boot-file-name".into(), json!(file));
    }
    let next = code(150).and_then(options::first_ipv4).or_else(|| {
        code(66)
            .and_then(options::text)
            .and_then(|text| text.parse().ok())
    });
    if let Some(next) = next {
        out.insert("next-server".into(), json!(next.to_string()));
    }
}

/// Lease times as Kea's parameters.
pub(crate) fn lease_params(
    lease: &tenko_core::dhcp::LeaseTimes,
    timers: bool,
    out: &mut Map<String, Value>,
) {
    out.insert("valid-lifetime".into(), json!(lease.default_secs));
    out.insert("min-valid-lifetime".into(), json!(lease.min_secs));
    out.insert("max-valid-lifetime".into(), json!(lease.max_secs));
    if timers {
        if let Some(t1) = lease.t1_secs {
            out.insert("renew-timer".into(), json!(t1));
        }
        if let Some(t2) = lease.t2_secs {
            out.insert("rebind-timer".into(), json!(t2));
        }
    }
}

/// `interfaces-config` from the role's listeners.
fn interfaces(cx: &mut Cx<'_>) -> Value {
    let Some(listeners) = cx.input.listeners else {
        cx.report.push(
            at("listeners", "of the role"),
            codes::INTERFACES_UNKNOWN,
            "the dhcp role does not run in this process, so its listeners are not known: interfaces-config lists none; name the interfaces Kea listens on",
        );
        return json!({"interfaces": []});
    };
    let mut names: Vec<String> = Vec::new();
    let mut direct = false;
    let mut by_address = Vec::new();
    for listener in listeners {
        if listener.address.port() != 67 {
            cx.report.push(
                at("listener", listener.address),
                codes::INTERFACES_PROXY,
                "a proxy DHCP listener (PXE boot server discovery) has no counterpart in Kea and is left out",
            );
            continue;
        }
        let name = match (&listener.interface, listener.mode) {
            (Some(interface), ListenMode::Relay) => {
                format!("{interface}/{}", listener.address.ip())
            }
            (Some(interface), ListenMode::Direct) => interface.clone(),
            (None, _) => {
                by_address.push(listener.address.ip().to_string());
                "*".to_owned()
            }
        };
        direct |= listener.mode == ListenMode::Direct;
        if !names.contains(&name) {
            names.push(name);
        }
    }
    if !by_address.is_empty() {
        cx.report.push(
            at("listeners", by_address.join(", ")),
            codes::INTERFACES_ADDRESS,
            format!(
                "Tenko binds the address {}; Kea binds interfaces, so the export lists `*` (every interface): replace it with `<interface>/<address>`",
                by_address.join(", ")
            ),
        );
    }
    if names.is_empty() {
        cx.report.push(
            at("listeners", "of the role"),
            codes::INTERFACES_UNKNOWN,
            "the dhcp role has no DHCPv4 listener on port 67: interfaces-config lists none",
        );
    }
    if direct || names.is_empty() {
        json!({"interfaces": names, "dhcp-socket-type": "raw"})
    } else {
        // Relay mode: only relayed traffic, replies routed to the relay.
        json!({"interfaces": names, "dhcp-socket-type": "udp", "outbound-interface": "use-routing"})
    }
}

/// The global findings that do not belong to one item.
fn global_findings(cx: &mut Cx<'_>) {
    if cx.input.conflict_detection {
        cx.report.push(
            at("settings", "conflict detection"),
            codes::CONFLICT_DETECTION,
            "Tenko probes an address before it offers it (TGL-16); Kea's core does not (Kea's ping_check hook library does)",
        );
    }
    cx.report.push(
        at("settings", "lease history"),
        codes::HISTORY,
        "the lease history (dhcp.history) is not exported: Kea keeps the current leases only",
    );
}

fn sorted_policies<'a>(data: &'a DhcpData, exported: &BTreeMap<PrefixId, u32>) -> Vec<&'a Policy> {
    let mut policies: Vec<&Policy> = data
        .policies
        .values()
        .filter(|policy| policy.enabled)
        .filter(|policy| {
            policy
                .scope
                .is_none_or(|scope| exported.contains_key(&scope))
        })
        .collect();
    policies.sort_by_key(|policy| (policy.scope.is_none(), policy.scope, policy.order));
    policies
}

/// The export of `input`.
pub fn export(input: &KeaInput<'_>) -> KeaExport {
    let data = input.data;
    // The custom definitions of the DHCPv6 space go to Dhcp6, the others to Dhcp4.
    let (defs6, defs4): (Vec<OptionDef>, Vec<OptionDef>) = data
        .option_defs
        .values()
        .cloned()
        .partition(|def| def.space.is_dhcp6());
    let mut cx = Cx {
        input: *input,
        data,
        built: build(data),
        report: LossReport::default(),
        options: Options::new(defs4),
        options6: Options::new(defs6),
        subnet_ids: BTreeMap::new(),
        subnet_ids6: BTreeMap::new(),
        class_names: BTreeMap::new(),
        policy_names: BTreeMap::new(),
        policies: Vec::new(),
        need_allow: false,
        late_classes: Vec::new(),
        admission: BTreeMap::new(),
        need_allow6: false,
    };
    subnets::number(&mut cx);
    cx.policies = sorted_policies(data, &cx.subnet_ids);
    classes::name(&mut cx);
    global_findings(&mut cx);

    let mut dhcp4 = Map::new();
    dhcp4.insert("interfaces-config".into(), interfaces(&mut cx));
    dhcp4.insert(
        "lease-database".into(),
        json!({"type": "memfile", "persist": true, "name": LEASE_FILE, "lfc-interval": 3600}),
    );
    let settings = data.settings.clone().unwrap_or_default();
    lease_params(&settings.lease, true, &mut dhcp4);
    // Tenko's T1 and T2 are half and seven eighths of the granted time unless set.
    dhcp4.insert("calculate-tee-times".into(), json!(true));
    dhcp4.insert("t1-percent".into(), json!(0.5));
    dhcp4.insert("t2-percent".into(), json!(0.875));
    dhcp4.insert("authoritative".into(), json!(settings.authoritative));
    dhcp4.insert("match-client-id".into(), json!(true));
    dhcp4.insert(
        "host-reservation-identifiers".into(),
        json!(["client-id", "hw-address"]),
    );
    let server = cx.values(OptionOwner::Server);
    let global = cx.option_data(server, "server", |_| false);
    dhcp4.insert("option-data".into(), Value::Array(global));
    boot_fields(server, &mut dhcp4);

    let (shared, subnet4, domains) = subnets::build(&mut cx);
    let mut client_classes = classes::early(&mut cx);
    client_classes.extend(classes::policies(&mut cx));
    client_classes.append(&mut cx.late_classes);
    // Kea 2.6 refuses an empty client-classes list, so none is written then.
    if !client_classes.is_empty() {
        dhcp4.insert("client-classes".into(), Value::Array(client_classes));
    }
    dhcp4.insert("shared-networks".into(), Value::Array(shared));
    dhcp4.insert("subnet4".into(), Value::Array(subnet4));
    let mut dhcp6 = v6::wanted(&cx).then(|| v6::build(&mut cx));
    let dhcp_ddns = ddns::global(
        &mut cx,
        &domains,
        &mut dhcp4,
        dhcp6
            .as_mut()
            .map(|(dhcp6, domains6)| (dhcp6, domains6.as_slice())),
    );
    dhcp4.insert("option-def".into(), Value::Array(cx.options.defs()));
    dhcp4.insert(
        "user-context".into(),
        json!({"tenko-export": {"revision": data.revision.0, "generated": input.now.to_string(), "format": "kea 2.6"}}),
    );
    let leases4_csv = input.leases.then(|| leases::csv(&mut cx));
    let dhcp6 = dhcp6.map(|(mut dhcp6, _)| {
        v6::finish(&mut cx, &mut dhcp6);
        dhcp6
    });
    let leases6_csv = (input.leases && dhcp6.is_some()).then(|| v6::leases_csv(&mut cx));
    KeaExport {
        dhcp4: json!({ "Dhcp4": Value::Object(dhcp4) }),
        dhcp6: dhcp6.map(|dhcp6| json!({ "Dhcp6": Value::Object(dhcp6) })),
        dhcp_ddns,
        leases4_csv,
        leases6_csv,
        report: cx.report,
    }
}
