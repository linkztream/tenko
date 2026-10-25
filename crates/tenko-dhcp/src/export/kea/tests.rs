//! The export of a configuration with every level, class, policy and filter kind: what
//! Kea gets, that every class a test, a pool or a subnet names is defined before it is
//! named, the lease file and the loss report.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use serde_json::{Value, json};
use tenko_core::{
    AddressId, HostId, InterfaceId, NodeId, PrefixId, Principal, RangeId, SystemComponent,
    TenantId, Timestamp, VrfId,
    dhcp::{
        AddressRange, BindingState, Class, ClassId, ClientKey, Condition, DdnsPolicy, DdnsState,
        DhcpSettings, ExclusionId, ExclusionRange, Filter, FilterId, FilterKind, Join, Lease,
        LeaseTimes, MacPattern, Match, OptionOwner, OptionSet, OptionValue, Policy, PolicyAction,
        PolicyId, Scope, SharedNetwork, SharedNetworkId, Term,
    },
    dns::{DnsName, ZoneId},
    ipam::{
        Address, AllocPolicy, AssignmentMode, Host, Interface, Meta, Prefix, PrefixRole, Range,
        RangeRole, Stamp, Status,
    },
    net::{HostName, MacAddr},
    serde_util::HexBytes,
};

use super::{KeaInput, codes, export, leases::HEADER};
use crate::{feed::DhcpData, server::ListenerInfo, v4::engine::ListenMode};

fn stamp() -> Stamp {
    Stamp::new(
        "2026-10-22T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Api),
    )
}

fn time(text: &str) -> Timestamp {
    text.parse().expect("time")
}

fn ip(text: &str) -> std::net::IpAddr {
    text.parse().expect("ip")
}

/// A configuration in the shape of the DHCP lab: three networks, one of them restricted,
/// two in a shared network, a reservation, classes and policies of every kind, filters
/// and leases.
struct Lab {
    data: DhcpData,
    lan: PrefixId,
    iot: PrefixId,
    guest: PrefixId,
    zone: ZoneId,
}

fn mac(last: u8) -> MacAddr {
    MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, last])
}

impl Lab {
    fn prefix(&mut self, cidr: &str, vrf: VrfId) -> PrefixId {
        let id = PrefixId::generate();
        self.data.prefixes.insert(
            id,
            Prefix {
                id,
                vrf,
                cidr: cidr.parse().expect("cidr"),
                role: PrefixRole::Network,
                status: Status::Active,
                vlan: None,
                site: None,
                alarm: None,
                alloc: AllocPolicy::Lowest,
                dns_reverse: None,
                meta: Meta::new(stamp()),
            },
        );
        id
    }

    fn range(&mut self, prefix: PrefixId, first: &str, last: &str, role: RangeRole) -> RangeId {
        let id = RangeId::generate();
        self.data.ranges.insert(
            id,
            Range {
                id,
                prefix,
                first: ip(first),
                last: ip(last),
                role,
                lease_secs: None,
                delegated_len: None,
                status: Status::Active,
                meta: Meta::new(stamp()),
            },
        );
        id
    }

    fn scope(&mut self, prefix: PrefixId) -> &mut Scope {
        self.data.scopes.insert(
            prefix,
            Scope {
                v6: None,
                prefix,
                enabled: true,
                lease: None,
                authoritative: None,
                server_id: None,
                ddns: DdnsPolicy::default(),
                shared_network: None,
                restricted: false,
                classes: Vec::new(),
                description: None,
                created: stamp(),
                updated: stamp(),
            },
        );
        self.data.scopes.get_mut(&prefix).expect("scope")
    }

    fn options(&mut self, owner: OptionOwner, values: Vec<OptionValue>) {
        self.data.option_sets.insert(
            owner,
            OptionSet {
                owner,
                values,
                updated: stamp(),
            },
        );
    }

    fn host(&mut self, name: &str, mode: AssignmentMode, mac: MacAddr, at: (PrefixId, &str)) {
        let host = Host {
            id: HostId::generate(),
            tenant: TenantId::generate(),
            name: HostName::new(name).expect("name"),
            mode,
            lock: false,
            site: None,
            meta: Meta::new(stamp()),
        };
        let interface = Interface {
            id: InterfaceId::generate(),
            host: host.id,
            name: "eth0".to_owned(),
            mac: Some(mac),
            duid: None,
            client_id: None,
            meta: Meta::new(stamp()),
        };
        let prefix = self.data.prefixes[&at.0].clone();
        let address = Address {
            id: AddressId::generate(),
            vrf: prefix.vrf,
            ip: ip(at.1),
            prefix: prefix.id,
            status: Status::Active,
            interface: Some(interface.id),
            dns_name: None,
            meta: Meta::new(stamp()),
        };
        self.data.hosts.insert(host.id, host);
        self.data.interfaces.insert(interface.id, interface);
        self.data.addresses.insert(address.id, address);
    }

    fn class(&mut self, name: &str, matches: Vec<Match>) -> ClassId {
        let id = ClassId::generate();
        self.data.classes.insert(
            id,
            Class {
                id,
                name: name.to_owned(),
                matches,
                description: None,
                created: stamp(),
                updated: stamp(),
            },
        );
        id
    }

    fn policy(
        &mut self,
        name: &str,
        scope: Option<PrefixId>,
        order: u32,
        terms: Vec<Term>,
        action: PolicyAction,
    ) -> PolicyId {
        let id = PolicyId::generate();
        self.data.policies.insert(
            id,
            Policy {
                id,
                name: name.to_owned(),
                scope,
                order,
                enabled: true,
                condition: Condition {
                    join: Join::Or,
                    terms,
                },
                action,
                description: None,
                created: stamp(),
                updated: stamp(),
            },
        );
        id
    }

    fn lease(&mut self, scope: PrefixId, addr: &str, last: u8, state: BindingState) {
        let vrf = self.data.prefixes[&scope].vrf;
        let addr: Ipv4Addr = addr.parse().expect("addr");
        self.data.leases.insert(
            (vrf, addr),
            Lease {
                addr,
                vrf,
                scope,
                client: ClientKey {
                    htype: 1,
                    chaddr: HexBytes(mac(last).octets().to_vec()),
                    client_id: (last == 0x46).then(|| HexBytes(vec![1, 0, 0, 0x5e, 0, 0x53, last])),
                },
                state,
                cltt: time("2026-10-22T12:00:00Z"),
                ends: time("2026-10-22T13:00:00Z"),
                tstp: None,
                tsfp: None,
                atsfp: None,
                node: NodeId(1),
                share: None,
                hostname: Some("laptop,one".to_owned()),
                fqdn: None,
                fqdn_flags: None,
                ddns_policy: None,
                ddns: DdnsState::default(),
                fingerprint: None,
                relay: None,
                observed_at: None,
            },
        );
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one configuration, read top to bottom"
    )]
    fn new() -> Self {
        let mut lab = Self {
            data: DhcpData::default(),
            lan: PrefixId::generate(),
            iot: PrefixId::generate(),
            guest: PrefixId::generate(),
            zone: ZoneId::generate(),
        };
        let vrf = VrfId::generate();
        lab.data.settings = Some(DhcpSettings::default());
        lab.options(
            OptionOwner::Server,
            vec![
                OptionValue::v4(6, vec![192, 0, 2, 53]),
                OptionValue::v4(15, b"example.test".to_vec()),
                OptionValue::v4(42, vec![192, 0, 2, 123]),
            ],
        );
        // lan: a pool with a static address inside it, a reservation outside, a scope
        // option 15 that a policy also sets, DDNS on.
        lab.lan = lab.prefix("192.0.2.64/26", vrf);
        let lan = lab.lan;
        lab.range(lan, "192.0.2.94", "192.0.2.123", RangeRole::DhcpPool);
        lab.range(lan, "192.0.2.65", "192.0.2.70", RangeRole::Infrastructure);
        let zone = lab.zone;
        let scope = lab.scope(lan);
        scope.ddns = DdnsPolicy {
            enabled: true,
            forward_zone: Some(zone),
            ttl: Some(600),
            ..DdnsPolicy::default()
        };
        scope.lease = Some(LeaseTimes {
            t1_secs: Some(1_800),
            t2_secs: Some(3_000),
            ..LeaseTimes::fixed(3_600)
        });
        lab.options(
            OptionOwner::Scope(lan),
            vec![
                OptionValue::v4(3, vec![192, 0, 2, 66]),
                OptionValue::v4(15, b"lan.example.test".to_vec()),
                OptionValue::v4(150, vec![192, 0, 2, 21]),
            ],
        );
        lab.host(
            "printer",
            AssignmentMode::Reserved,
            mac(0x45),
            (lan, "192.0.2.80"),
        );
        lab.host(
            "nas",
            AssignmentMode::Static,
            mac(0x47),
            (lan, "192.0.2.110"),
        );
        lab.data.exclusions.insert(
            (lan, ExclusionId::generate()),
            ExclusionRange {
                id: ExclusionId::generate(),
                scope: lan,
                first: ip("192.0.2.120"),
                last: ip("192.0.2.123"),
                description: None,
                created: stamp(),
            },
        );
        // iot: restricted (the allow list).
        lab.iot = lab.prefix("192.0.2.128/26", vrf);
        let iot = lab.iot;
        lab.range(iot, "192.0.2.158", "192.0.2.187", RangeRole::DhcpPool);
        lab.scope(iot).restricted = true;
        // guest and a fourth network in one shared network.
        let network = SharedNetworkId::generate();
        lab.data.shared_networks.insert(
            network,
            SharedNetwork {
                id: network,
                name: "campus".to_owned(),
                interface: None,
                description: None,
                created: stamp(),
                updated: stamp(),
            },
        );
        lab.options(
            OptionOwner::SharedNetwork(network),
            vec![OptionValue::v4(42, vec![192, 0, 2, 124])],
        );
        lab.guest = lab.prefix("192.0.2.192/26", vrf);
        let guest = lab.guest;
        lab.range(guest, "192.0.2.222", "192.0.2.251", RangeRole::DhcpPool);
        lab.scope(guest).shared_network = Some(network);
        let extra = lab.prefix("198.51.100.0/24", vrf);
        lab.range(extra, "198.51.100.10", "198.51.100.20", RangeRole::DhcpPool);
        lab.scope(extra).shared_network = Some(network);
        // A disabled scope.
        let off = lab.prefix("203.0.113.0/24", vrf);
        lab.scope(off).enabled = false;
        // Classes and policies.
        let printers = lab.class(
            "printers",
            vec![Match::VendorClass {
                value: "Printer".into(),
                prefix: true,
            }],
        );
        let wildcard = lab.class(
            "iot-wildcard",
            vec![Match::Mac {
                pattern: MacPattern::new("00:00:5e:00:*:85").expect("pattern"),
            }],
        );
        let ops = lab.class(
            "ops",
            vec![Match::UserClass {
                value: "lab-ops".into(),
            }],
        );
        let printers_policy = lab.policy(
            "printers",
            Some(lan),
            1,
            vec![Term::Class(printers)],
            PolicyAction {
                range: Some(AddressRange {
                    first: ip("192.0.2.100"),
                    last: ip("192.0.2.104"),
                }),
                ..PolicyAction::default()
            },
        );
        lab.options(
            OptionOwner::Policy(printers_policy),
            vec![
                OptionValue::v4(15, b"printers.example.test".to_vec()),
                OptionValue::v4(67, b"printer.cfg".to_vec()),
            ],
        );
        lab.policy(
            "iot-devices",
            Some(iot),
            1,
            vec![Term::Class(wildcard)],
            PolicyAction {
                lease: Some(LeaseTimes::fixed(120)),
                ..PolicyAction::default()
            },
        );
        let ops_policy = lab.policy(
            "ops",
            None,
            1,
            vec![
                Term::Class(ops),
                Term::NotMatch(Match::HostName {
                    value: "Build".into(),
                    prefix: true,
                }),
            ],
            PolicyAction::default(),
        );
        lab.options(
            OptionOwner::Policy(ops_policy),
            vec![OptionValue::v4(
                252,
                b"http://wpad.example.test/wpad.dat".to_vec(),
            )],
        );
        lab.policy(
            "names",
            Some(lan),
            2,
            vec![Term::Class(ClassId::generate())],
            PolicyAction {
                ddns: Some(DdnsPolicy::default()),
                ..PolicyAction::default()
            },
        );
        let off_policy = lab.policy(
            "old",
            Some(lan),
            3,
            vec![Term::Class(printers)],
            PolicyAction::default(),
        );
        lab.data
            .policies
            .get_mut(&off_policy)
            .expect("policy")
            .enabled = false;
        // Filters.
        for (kind, pattern) in [
            (FilterKind::Deny, "00:00:5e:00:53:c5"),
            (FilterKind::Allow, "00:00:5e:00:53:*"),
            (FilterKind::Allow, "00:00:5e:00:53:85"),
        ] {
            let id = FilterId::generate();
            lab.data.filters.insert(
                id,
                Filter {
                    id,
                    mac: MacPattern::new(pattern).expect("pattern"),
                    kind,
                    note: None,
                    created: stamp(),
                    updated: stamp(),
                },
            );
        }
        // Leases: active, abandoned, released, and one of the disabled scope.
        lab.lease(lan, "192.0.2.95", 0x46, BindingState::Active);
        lab.lease(lan, "192.0.2.96", 0x48, BindingState::Abandoned);
        lab.lease(lan, "192.0.2.97", 0x49, BindingState::Released);
        lab.lease(off, "203.0.113.5", 0x4a, BindingState::Active);
        lab
    }
}

fn listeners() -> Vec<ListenerInfo> {
    vec![
        ListenerInfo {
            address: "192.0.2.10:67".parse().expect("address"),
            mode: ListenMode::Relay,
            interface: None,
            workers: 2,
            link_layer: false,
        },
        ListenerInfo {
            address: "192.0.2.10:4011".parse().expect("address"),
            mode: ListenMode::Relay,
            interface: None,
            workers: 1,
            link_layer: false,
        },
    ]
}

fn run(lab: &Lab) -> super::KeaExport {
    let mut zones = BTreeMap::new();
    zones.insert(lab.zone, DnsName::new("lan.example.test").expect("zone"));
    let listeners = listeners();
    export(&KeaInput {
        data: &lab.data,
        zones: &zones,
        listeners: Some(&listeners),
        listeners6: None,
        server_duid: None,
        now: time("2026-10-22T12:30:00Z"),
        leases: true,
        conflict_detection: true,
    })
}

fn all_subnets(dhcp4: &Value) -> Vec<Value> {
    let mut out: Vec<Value> = dhcp4["subnet4"].as_array().cloned().unwrap_or_default();
    for network in dhcp4["shared-networks"].as_array().into_iter().flatten() {
        out.extend(network["subnet4"].as_array().cloned().unwrap_or_default());
    }
    out
}

fn subnet<'a>(subnets: &'a [Value], network: &str) -> &'a Value {
    subnets
        .iter()
        .find(|subnet| subnet["subnet"] == json!(network))
        .expect("the subnet")
}

fn class<'a>(dhcp4: &'a Value, name: &str) -> &'a Value {
    dhcp4["client-classes"]
        .as_array()
        .expect("classes")
        .iter()
        .find(|class| class["name"] == json!(name))
        .unwrap_or_else(|| panic!("no class {name}"))
}

fn codes_of(report: &tenko_core::ir::LossReport) -> BTreeSet<String> {
    report
        .entries
        .iter()
        .map(|entry| entry.code.to_string())
        .collect()
}

#[test]
fn subnets_pools_and_reservations() {
    let lab = Lab::new();
    let out = run(&lab);
    write_sample(&out);
    check_subnets(&out);
}

/// With `KEA_EXPORT_SAMPLE=<dir>` the export of the lab configuration is written there, for
/// `kea-dhcp4 -t` by hand (the lab's row runs it on the lab's own configuration).
fn write_sample(out: &super::KeaExport) {
    if let Some(dir) = std::env::var_os("KEA_EXPORT_SAMPLE") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).expect("the sample directory");
        std::fs::write(
            dir.join(super::files::CONFIG),
            serde_json::to_string_pretty(&out.dhcp4).expect("JSON"),
        )
        .expect("the sample");
        if let Some(csv) = &out.leases4_csv {
            std::fs::write(dir.join(super::files::LEASES), csv).expect("the lease file");
        }
    }
}

fn check_subnets(out: &super::KeaExport) {
    let dhcp4 = &out.dhcp4["Dhcp4"];
    let subnets = all_subnets(dhcp4);
    assert_eq!(subnets.len(), 4, "the disabled scope is left out");
    let ids: BTreeSet<u64> = subnets
        .iter()
        .map(|s| s["id"].as_u64().expect("id"))
        .collect();
    assert_eq!(ids, BTreeSet::from([1, 2, 3, 4]));
    let lan = subnet(&subnets, "192.0.2.64/26");
    // The static address .110 and the exclusion .120 to .123 are cut out; the printers'
    // range .100 to .104 is a piece of its own.
    let pools: Vec<&str> = lan["pools"]
        .as_array()
        .expect("pools")
        .iter()
        .map(|pool| pool["pool"].as_str().expect("pool"))
        .collect();
    assert_eq!(
        pools,
        [
            "192.0.2.94 - 192.0.2.99",
            "192.0.2.100 - 192.0.2.104",
            "192.0.2.105 - 192.0.2.109",
            "192.0.2.111 - 192.0.2.119",
        ]
    );
    let printers = "policy.192.0.2.64/26.printers";
    assert_eq!(lan["pools"][1]["client-class"], json!(printers));
    let general = lan["pools"][0]["client-class"].as_str().expect("class");
    assert_eq!(
        class(dhcp4, general)["test"],
        json!(format!("not member('{printers}')"))
    );
    assert_eq!(lan["pools"][2]["client-class"], json!(general));
    assert_eq!(
        lan["reservations"],
        json!([{"hw-address": "00:00:5e:00:53:45", "ip-address": "192.0.2.80", "hostname": "printer"}])
    );
    assert_eq!(lan["valid-lifetime"], json!(3_600));
    assert_eq!(lan["renew-timer"], json!(1_800));
    assert_eq!(lan["rebind-timer"], json!(3_000));
    assert_eq!(lan["next-server"], json!("192.0.2.21"));
    // Option 15 is set by the scope and by the printers' policy: it moves to the scope's
    // defaults class, required after the policies.
    let data: Vec<u64> = lan["option-data"]
        .as_array()
        .expect("options")
        .iter()
        .map(|o| o["code"].as_u64().expect("code"))
        .collect();
    assert_eq!(data, [3, 150]);
    assert_eq!(
        lan["require-client-classes"],
        json!([
            format!("{printers}.options"),
            "policy.ops.options",
            "scope.192.0.2.64/26.defaults"
        ])
    );
    let defaults = class(dhcp4, "scope.192.0.2.64/26.defaults");
    assert_eq!(defaults["only-if-required"], json!(true));
    assert_eq!(
        defaults["option-data"][0]["data"],
        json!("lan.example.test")
    );
    let options = class(dhcp4, &format!("{printers}.options"));
    assert_eq!(options["boot-file-name"], json!("printer.cfg"));
    assert_eq!(options["test"], json!(format!("member('{printers}')")));
    // iot is restricted: its pool requires the allow class.
    let iot = subnet(&subnets, "192.0.2.128/26");
    let allow = iot["pools"][0]["client-class"].as_str().expect("class");
    assert_eq!(allow, "tenko.allow");
    let test = class(dhcp4, "tenko.allow")["test"]
        .as_str()
        .expect("test")
        .to_owned();
    assert!(
        test.contains("(substring(pkt4.mac,0,5) == 0x00005e0053)"),
        "{test}"
    );
    assert!(test.contains("(pkt4.mac == 0x00005e005385)"), "{test}");
    assert!(test.contains(") or ("), "{test}");
    // The shared network holds guest and the fourth network, with its option 42.
    let shared = &dhcp4["shared-networks"][0];
    assert_eq!(shared["name"], json!("campus"));
    assert_eq!(shared["subnet4"].as_array().expect("subnets").len(), 2);
    assert_eq!(shared["option-data"][0]["data"], json!("192.0.2.124"));
    // Interfaces: the relay listener by address, the proxy listener left out.
    assert_eq!(
        dhcp4["interfaces-config"],
        json!({"interfaces": ["*"], "dhcp-socket-type": "udp", "outbound-interface": "use-routing"})
    );
    // Option 252 has no Kea definition: the export adds one.
    let defs = dhcp4["option-def"].as_array().expect("defs");
    assert!(
        defs.iter()
            .any(|def| def["code"] == json!(252) && def["name"] == json!("wpad"))
    );
    assert!(defs.iter().any(|def| def["code"] == json!(150)));
}

#[test]
fn classes_are_defined_before_they_are_named() {
    let lab = Lab::new();
    let out = run(&lab);
    let dhcp4 = &out.dhcp4["Dhcp4"];
    let builtin = ["ALL", "KNOWN", "UNKNOWN"];
    let mut defined: BTreeSet<String> = builtin.iter().map(|name| (*name).to_owned()).collect();
    for class in dhcp4["client-classes"].as_array().expect("classes") {
        let test = class["test"].as_str().unwrap_or("");
        let mut rest = test;
        while let Some(at) = rest.find("member('") {
            let tail = &rest[at + 8..];
            let end = tail.find('\'').expect("a closing quote");
            assert!(
                defined.contains(&tail[..end]),
                "{} names {} before it is defined",
                class["name"],
                &tail[..end]
            );
            rest = &tail[end..];
        }
        assert!(
            defined.insert(class["name"].as_str().expect("name").to_owned()),
            "{} is defined twice",
            class["name"]
        );
    }
    for subnet in all_subnets(dhcp4) {
        for name in subnet["require-client-classes"]
            .as_array()
            .into_iter()
            .flatten()
        {
            assert!(defined.contains(name.as_str().expect("name")), "{name}");
        }
        for pool in subnet["pools"].as_array().into_iter().flatten() {
            if let Some(name) = pool["client-class"].as_str() {
                assert!(defined.contains(name), "{name}");
            }
        }
    }
    assert_eq!(
        class(dhcp4, "DROP")["test"],
        json!("pkt4.mac == 0x00005e0053c5")
    );
    assert_eq!(
        class(dhcp4, "printers")["test"],
        json!("substring(option[60].hex,0,7) == 'Printer'")
    );
    assert_eq!(
        class(dhcp4, "policy.ops")["test"],
        json!("member('ops') or (not (substring(lcase(option[12].text),0,5) == 'build'))")
    );
    assert_eq!(
        class(dhcp4, "policy.192.0.2.128/26.iot-devices")["valid-lifetime"],
        json!(120)
    );
    // The deleted class's term is false.
    assert_eq!(
        class(dhcp4, "policy.192.0.2.64/26.names")["test"],
        json!("not member('ALL')")
    );
    // The PXE echo, since a policy sets option 67.
    let pxe = class(dhcp4, "tenko.pxe");
    assert_eq!(pxe["option-data"][1]["data"], json!("060108FF"));
}

#[test]
fn the_report_names_what_did_not_translate() {
    let lab = Lab::new();
    let out = run(&lab);
    let codes = codes_of(&out.report);
    for code in [
        codes::SCOPE_DISABLED,
        codes::SCOPE_RESTRICTED,
        codes::FILTER_DENY,
        codes::POLICY_DISABLED,
        codes::POLICY_DDNS,
        codes::POLICY_CLASS_MISSING,
        codes::POLICY_LEASE_EVERYWHERE,
        codes::CLASS_PARTIAL,
        codes::INTERFACES_ADDRESS,
        codes::INTERFACES_PROXY,
        codes::CONFLICT_DETECTION,
        codes::HISTORY,
        codes::DDNS_TTL,
        codes::DDNS_D2,
        codes::LEASE_SCOPE,
    ] {
        assert!(codes.contains(code), "{code} missing from {codes:?}");
    }
    let ddns = out
        .report
        .entries
        .iter()
        .find(|entry| entry.code == codes::POLICY_DDNS)
        .expect("the DDNS policy");
    assert_eq!(
        ddns.location.sheet.as_deref(),
        Some("policy names (192.0.2.64/26)")
    );
    let disabled = out
        .report
        .entries
        .iter()
        .find(|entry| entry.code == codes::POLICY_DISABLED)
        .expect("the disabled policy");
    assert_eq!(
        disabled.location.sheet.as_deref(),
        Some("policy old (192.0.2.64/26)")
    );
}

#[test]
fn ddns_hints_and_the_skeleton() {
    let lab = Lab::new();
    let out = run(&lab);
    let dhcp4 = &out.dhcp4["Dhcp4"];
    let subnets = all_subnets(dhcp4);
    let lan = subnet(&subnets, "192.0.2.64/26");
    assert_eq!(lan["ddns-send-updates"], json!(true));
    assert_eq!(lan["ddns-qualifying-suffix"], json!("lan.example.test."));
    assert_eq!(
        lan["ddns-conflict-resolution-mode"],
        json!("check-with-dhcid")
    );
    assert_eq!(lan["ddns-override-client-update"], json!(true));
    assert_eq!(lan["ddns-ttl-percent"], json!(0.167));
    assert_eq!(dhcp4["ddns-send-updates"], json!(false));
    assert_eq!(dhcp4["dhcp-ddns"]["enable-updates"], json!(true));
    let d2 = out.dhcp_ddns.expect("the skeleton");
    assert_eq!(
        d2["DhcpDdns"]["forward-ddns"]["ddns-domains"][0]["name"],
        json!("lan.example.test.")
    );
    assert_eq!(
        d2["DhcpDdns"]["forward-ddns"]["ddns-domains"][0]["dns-servers"][0]["ip-address"],
        json!("192.0.2.53")
    );
    assert_eq!(
        d2["DhcpDdns"]["reverse-ddns"]["ddns-domains"][0]["name"],
        json!("2.0.192.in-addr.arpa.")
    );
}

#[test]
fn the_lease_file() {
    let lab = Lab::new();
    let out = run(&lab);
    let csv = out.leases4_csv.expect("the lease file");
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines[0], HEADER);
    let lan_id = all_subnets(&out.dhcp4["Dhcp4"])
        .iter()
        .find(|s| s["subnet"] == json!("192.0.2.64/26"))
        .and_then(|s| s["id"].as_u64())
        .expect("id");
    let expire = time("2026-10-22T13:00:00Z").unix_nanos() / 1_000_000_000;
    assert_eq!(
        lines[1..],
        [
            format!(
                "192.0.2.95,00:00:5e:00:53:46,01:00:00:5e:00:53:46,3600,{expire},{lan_id},0,0,laptop&#x2cone,0,,0"
            ),
            format!("192.0.2.96,,,3600,{expire},{lan_id},0,0,,1,,0"),
        ]
    );
    // Without the leases there is no file.
    let zones = BTreeMap::new();
    let none = export(&KeaInput {
        data: &lab.data,
        zones: &zones,
        listeners: None,
        listeners6: None,
        server_duid: None,
        now: time("2026-10-22T12:30:00Z"),
        leases: false,
        conflict_detection: false,
    });
    assert!(none.leases4_csv.is_none());
    assert!(codes_of(&none.report).contains(codes::INTERFACES_UNKNOWN));
    assert!(!codes_of(&none.report).contains(codes::CONFLICT_DETECTION));
    assert_eq!(
        none.dhcp4["Dhcp4"]["interfaces-config"]["interfaces"],
        json!([])
    );
}

#[test]
fn an_empty_configuration_is_still_a_configuration() {
    let data = DhcpData::default();
    let zones = BTreeMap::new();
    let out = export(&KeaInput {
        data: &data,
        zones: &zones,
        listeners: Some(&[]),
        listeners6: None,
        server_duid: None,
        now: time("2026-10-22T12:30:00Z"),
        leases: true,
        conflict_detection: false,
    });
    let dhcp4 = &out.dhcp4["Dhcp4"];
    assert_eq!(dhcp4["subnet4"], json!([]));
    // Kea refuses an empty client-classes list.
    assert!(dhcp4.get("client-classes").is_none());
    assert_eq!(dhcp4["valid-lifetime"], json!(86_400));
    assert_eq!(
        out.leases4_csv.as_deref(),
        Some(format!("{HEADER}\n").as_str())
    );
    assert!(out.dhcp_ddns.is_none());
}
