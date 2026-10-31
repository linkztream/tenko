//! The `Dhcp6` document of a configuration with every level and every DHCPv6 setting:
//! the golden files `fixtures/kea-dhcp6.json` and `fixtures/kea-leases6.csv` (the lab
//! checks the first with `kea-dhcp6 -t`), each mapping on its own, the report, and
//! property tests of the lifetimes (against the engine's) and of the pools.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv6Addr,
};

use proptest::prelude::*;
use serde_json::{Value, json};
use tenko_core::{
    AddressId, HostId, InterfaceId, NodeId, PrefixId, Principal, RangeId, SystemComponent,
    TenantId, Timestamp, VrfId,
    dhcp::{
        BindingState, Class, ClassId, DdnsPolicy, DdnsState, DhcpSettings, ExclusionId,
        ExclusionRange, Filter, FilterId, FilterKind, Lease6, Lease6Kind, LeaseTimes, MacPattern,
        Match, OptionDef, OptionDefId, OptionKind, OptionOwner, OptionSet, OptionSpace,
        OptionValue, PoolSettings, Scope, Scope6Settings, SharedNetwork, SharedNetworkId,
    },
    dns::{DnsName, ZoneId},
    ipam::{
        Address, AllocPolicy, AssignmentMode, Host, Interface, Meta, Prefix, PrefixRole, Range,
        RangeRole, Stamp, Status,
    },
    net::{Duid, HostName, MacAddr},
    serde_util::HexBytes,
};
use uuid::Uuid;

use super::{HEADER, lifetimes};
use crate::{
    export::kea::{KeaExport, KeaInput, codes, export},
    feed::DhcpData,
    v4::engine::ListenMode,
    v6::{
        image::{Pool6Image, Scope6Image},
        server::Listener6Info,
    },
};

fn stamp() -> Stamp {
    Stamp::new(
        "2026-10-25T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Api),
    )
}

fn time(text: &str) -> Timestamp {
    text.parse().expect("time")
}

fn ip(text: &str) -> std::net::IpAddr {
    text.parse().expect("ip")
}

fn a6(text: &str) -> Ipv6Addr {
    text.parse().expect("an IPv6 address")
}

fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0000 | n)
}

fn v6(code: u16, data: Vec<u8>) -> OptionValue {
    OptionValue {
        space: OptionSpace::dhcp6(),
        code,
        data: HexBytes(data),
    }
}

fn addresses(list: &[&str]) -> Vec<u8> {
    list.iter().flat_map(|text| a6(text).octets()).collect()
}

/// A domain list in the wire encoding.
fn names(list: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for name in list {
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).expect("a label"));
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }
    out
}

fn mac(last: u8) -> MacAddr {
    MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, last])
}

/// The DUID-LL of a MAC address.
fn duid_ll(last: u8) -> Vec<u8> {
    let mut out = vec![0, 3, 0, 1];
    out.extend_from_slice(&mac(last).octets());
    out
}

/// A DUID-LLT of the documentation MAC `00:00:5e:00:53:10`: the server's.
const SERVER_DUID: [u8; 14] = [0, 1, 0, 1, 0x2e, 0x8b, 0x58, 0, 0, 0, 0x5e, 0, 0x53, 0x10];

/// The configuration of the lab's round dhcp6 and more: lan6 (a pool with an exclusion,
/// lifetimes, DDNS, a reservation by DUID and one by MAC), iot6 (restricted, selected by
/// the relay's Interface-Id, no rapid commit), the shared network campus6 of two scopes
/// with different Interface-Ids on a direct link, a disabled scope, a DHCPv4 scope, the
/// filters, a class, custom definitions of both families and leases of every kind.
struct Lab {
    data: DhcpData,
    lan6: PrefixId,
    iot6: PrefixId,
    zone: ZoneId,
    next: u128,
}

impl Lab {
    fn id(&mut self) -> Uuid {
        self.next += 1;
        uuid(self.next)
    }

    fn prefix(&mut self, cidr: &str) -> PrefixId {
        let id = PrefixId::from_uuid(self.id());
        self.data.prefixes.insert(
            id,
            Prefix {
                id,
                vrf: VrfId::from_uuid(uuid(1)),
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
        let id = RangeId::from_uuid(self.id());
        self.data.ranges.insert(
            id,
            Range {
                id,
                prefix,
                first: ip(first),
                last: ip(last),
                role,
                delegated_len: None,
                lease_secs: None,
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

    fn host(
        &mut self,
        name: &str,
        mac: Option<MacAddr>,
        duid: Option<Vec<u8>>,
        at: (PrefixId, &str),
    ) -> InterfaceId {
        let host = Host {
            id: HostId::from_uuid(self.id()),
            tenant: TenantId::from_uuid(uuid(2)),
            name: HostName::new(name).expect("name"),
            mode: AssignmentMode::Reserved,
            lock: false,
            site: None,
            decommissioned: None,
            meta: Meta::new(stamp()),
        };
        let interface = Interface {
            id: InterfaceId::from_uuid(self.id()),
            host: host.id,
            name: "eth0".to_owned(),
            mac,
            duid: duid.map(|octets| Duid::new(octets).expect("a DUID")),
            client_id: None,
            meta: Meta::new(stamp()),
        };
        let address = Address {
            id: AddressId::from_uuid(self.id()),
            vrf: VrfId::from_uuid(uuid(1)),
            ip: ip(at.1),
            prefix: at.0,
            status: Status::Active,
            interface: Some(interface.id),
            dns_name: None,
            meta: Meta::new(stamp()),
        };
        let id = interface.id;
        self.data.hosts.insert(host.id, host);
        self.data.interfaces.insert(interface.id, interface);
        self.data.addresses.insert(address.id, address);
        id
    }

    #[allow(clippy::too_many_arguments, reason = "one lease row, field by field")]
    fn lease(
        &mut self,
        scope: PrefixId,
        addr: &str,
        duid: Vec<u8>,
        link_layer: Option<Vec<u8>>,
        kind: Lease6Kind,
        state: BindingState,
        forward: Option<&str>,
    ) {
        let addr = a6(addr);
        let vrf = VrfId::from_uuid(uuid(1));
        self.data.leases6.insert(
            (vrf, addr),
            Lease6 {
                addr: addr.into(),
                prefix_len: if kind == Lease6Kind::Pd { 60 } else { 128 },
                kind,
                vrf,
                scope,
                iaid: 7,
                duid: Duid::new(duid).expect("a DUID"),
                link_layer: link_layer.map(HexBytes),
                link_layer_type: Some(1),
                state,
                cltt: time("2026-10-25T12:00:00Z"),
                ends: time("2026-10-25T12:02:00Z"),
                preferred_ends: time("2026-10-25T12:01:00Z"),
                node: NodeId(1),
                fqdn: Some("host6,a.example.test.".to_owned()),
                fqdn_flags: Some(1),
                relay: None,
                observed_at: None,
                granted: None,
                ddns: DdnsState {
                    forward: forward.map(|name| DnsName::new(name).expect("a name")),
                    reverse: forward.map(|_| {
                        DnsName::new("0.0.0.0.1.0.1.0.8.b.d.0.1.0.0.2.ip6.arpa").expect("a name")
                    }),
                    ..DdnsState::default()
                },
            },
        );
    }

    fn filter(&mut self, kind: FilterKind, pattern: &str) {
        let id = FilterId::from_uuid(self.id());
        self.data.filters.insert(
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

    fn def(&mut self, space: OptionSpace, code: u16, name: &str) {
        let id = OptionDefId::from_uuid(self.id());
        self.data.option_defs.insert(
            id,
            OptionDef {
                id,
                space,
                code,
                name: name.to_owned(),
                kind: OptionKind::String,
                array: false,
                vendor_class: None,
                description: None,
                created: stamp(),
                updated: stamp(),
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
            lan6: PrefixId::from_uuid(uuid(0)),
            iot6: PrefixId::from_uuid(uuid(0)),
            zone: ZoneId::from_uuid(uuid(3)),
            next: 16,
        };
        lab.data.settings = Some(DhcpSettings::default());
        lab.options(
            OptionOwner::Server,
            vec![
                OptionValue::v4(6, vec![192, 0, 2, 53]),
                v6(23, addresses(&["2001:db8:100::53"])),
                v6(24, names(&["lab6.example.test"])),
                v6(56, addresses(&["2001:db8:100::123"])),
            ],
        );
        lab.def(OptionSpace::dhcp6(), 65_001, "tenko-site");
        lab.def(OptionSpace::dhcp4(), 224, "tenko-site4");

        // lan6: a pool with an exclusion and a pool option, valid 120 s and preferred 60 s,
        // rapid commit, DDNS into a known zone; a reservation by DUID and one by MAC.
        lab.lan6 = lab.prefix("2001:db8:101::/64");
        let lan6 = lab.lan6;
        let pool = lab.range(
            lan6,
            "2001:db8:101::1000",
            "2001:db8:101::1fff",
            RangeRole::DhcpPool,
        );
        lab.options(
            OptionOwner::Pool(pool),
            vec![v6(31, addresses(&["2001:db8:100::123"]))],
        );
        let exclusion = ExclusionId(lab.id());
        lab.data.exclusions.insert(
            (lan6, exclusion),
            ExclusionRange {
                id: exclusion,
                scope: lan6,
                first: ip("2001:db8:101::1800"),
                last: ip("2001:db8:101::18ff"),
                description: None,
                created: stamp(),
            },
        );
        let zone = lab.zone;
        let scope = lab.scope(lan6);
        scope.lease = Some(LeaseTimes::fixed(120));
        scope.v6 = Some(Scope6Settings {
            preferred_secs: Some(60),
            rapid_commit: Some(true),
            interface_id: None,
        });
        scope.ddns = DdnsPolicy {
            enabled: true,
            forward_zone: Some(zone),
            reverse: true,
            ..DdnsPolicy::default()
        };
        scope.description = Some("lab link lan6".to_owned());
        lab.options(OptionOwner::Scope(lan6), vec![v6(65_001, b"lan6".to_vec())]);
        lab.host(
            "lab6-reserved",
            None,
            Some(duid_ll(0x61)),
            (lan6, "2001:db8:101::80"),
        );
        let printer = lab.host(
            "lab6-printer",
            Some(mac(0x62)),
            None,
            (lan6, "2001:db8:101::81"),
        );
        lab.options(
            OptionOwner::Host(printer),
            vec![v6(23, addresses(&["2001:db8:100::54"]))],
        );

        // iot6: restricted, selected by the relay's Interface-Id, no rapid commit, and a
        // pool with lifetimes of its own.
        lab.iot6 = lab.prefix("2001:db8:102::/64");
        let iot6 = lab.iot6;
        let pool = lab.range(
            iot6,
            "2001:db8:102::1000",
            "2001:db8:102::1fff",
            RangeRole::DhcpPool,
        );
        lab.data.pools.insert(
            pool,
            PoolSettings {
                range: pool,
                classes: Vec::new(),
                lease: Some(LeaseTimes::fixed(600)),
                updated: stamp(),
            },
        );
        let scope = lab.scope(iot6);
        scope.lease = Some(LeaseTimes::fixed(3_600));
        scope.restricted = true;
        scope.v6 = Some(Scope6Settings {
            preferred_secs: None,
            rapid_commit: Some(false),
            interface_id: Some("lab-iot6".to_owned()),
        });

        // campus6: a shared network of two scopes on a direct link, with Interface-Ids
        // that differ.
        let campus = SharedNetworkId::from_uuid(lab.id());
        lab.data.shared_networks.insert(
            campus,
            SharedNetwork {
                id: campus,
                name: "campus6".to_owned(),
                interface: None,
                description: Some("two links in one".to_owned()),
                created: stamp(),
                updated: stamp(),
            },
        );
        lab.options(
            OptionOwner::SharedNetwork(campus),
            vec![v6(23, addresses(&["2001:db8:200::53"]))],
        );
        for (cidr, first, last, id) in [
            (
                "2001:db8:201::/64",
                "2001:db8:201::",
                "2001:db8:201::ff",
                "campus-a",
            ),
            (
                "2001:db8:202::/64",
                "2001:db8:202::100",
                "2001:db8:202::1ff",
                "campus-b",
            ),
        ] {
            let prefix = lab.prefix(cidr);
            lab.range(prefix, first, last, RangeRole::DhcpPool);
            let scope = lab.scope(prefix);
            scope.shared_network = Some(campus);
            scope.v6 = Some(Scope6Settings {
                interface_id: Some(id.to_owned()),
                ..Scope6Settings::default()
            });
        }

        // WP9.4: a delegation network with a scope and a delegation pool of sixteen /60s,
        // one of them touched by an exclusion, with a pool option.
        let delegation = lab.prefix("2001:db8:180::/48");
        let pd_pool = lab.range(
            delegation,
            "2001:db8:180:100::",
            "2001:db8:180:1ff:ffff:ffff:ffff:ffff",
            RangeRole::DhcpPdPool,
        );
        lab.data
            .ranges
            .get_mut(&pd_pool)
            .expect("the pool")
            .delegated_len = Some(60);
        lab.options(
            OptionOwner::Pool(pd_pool),
            vec![v6(23, addresses(&["2001:db8:180::53"]))],
        );
        let exclusion = ExclusionId(lab.id());
        lab.data.exclusions.insert(
            (delegation, exclusion),
            ExclusionRange {
                id: exclusion,
                scope: delegation,
                first: ip("2001:db8:180:115::5"),
                last: ip("2001:db8:180:115::5"),
                description: None,
                created: stamp(),
            },
        );
        lab.scope(delegation).lease = Some(LeaseTimes::fixed(7_200));

        // A disabled DHCPv6 scope, and a DHCPv4 scope that stays out of Dhcp6.
        let off = lab.prefix("2001:db8:300::/64");
        lab.range(
            off,
            "2001:db8:300::10",
            "2001:db8:300::20",
            RangeRole::DhcpPool,
        );
        lab.scope(off).enabled = false;
        let lan4 = lab.prefix("192.0.2.64/26");
        lab.range(lan4, "192.0.2.94", "192.0.2.123", RangeRole::DhcpPool);
        lab.scope(lan4);

        // A class (DHCPv4 only in Tenko) and the filters.
        let class = ClassId::from_uuid(lab.id());
        lab.data.classes.insert(
            class,
            Class {
                id: class,
                name: "printers".to_owned(),
                matches: vec![Match::Mac {
                    pattern: MacPattern::new("00:00:5e:00:53:*").expect("pattern"),
                }],
                description: None,
                created: stamp(),
                updated: stamp(),
            },
        );
        lab.filter(FilterKind::Deny, "00:00:5e:00:53:ee");
        lab.filter(FilterKind::Allow, "00:00:5e:00:53:*");

        // Leases: active by DUID-LL (its MAC from the DUID) with DDNS written, active with
        // the MAC from a relay's option 79, declined, a delegated prefix, a released one
        // and one of the disabled scope.
        lab.lease(
            lan6,
            "2001:db8:101::1234",
            duid_ll(0x61),
            Some(mac(0x61).octets().to_vec()),
            Lease6Kind::Na,
            BindingState::Active,
            Some("host6.example.test"),
        );
        lab.lease(
            iot6,
            "2001:db8:102::1abc",
            vec![0, 2, 0, 0, 0x7e, 0xd9, 1, 2, 3],
            Some(mac(0x6f).octets().to_vec()),
            Lease6Kind::Na,
            BindingState::Active,
            None,
        );
        lab.lease(
            lan6,
            "2001:db8:101::1235",
            duid_ll(0x63),
            None,
            Lease6Kind::Na,
            BindingState::Abandoned,
            None,
        );
        lab.lease(
            delegation,
            "2001:db8:180:120::",
            duid_ll(0x64),
            Some(mac(0x64).octets().to_vec()),
            Lease6Kind::Pd,
            BindingState::Active,
            None,
        );
        // A released delegated prefix stays out of the lease file.
        lab.lease(
            delegation,
            "2001:db8:180:130::",
            duid_ll(0x67),
            None,
            Lease6Kind::Pd,
            BindingState::Released,
            None,
        );
        lab.lease(
            lan6,
            "2001:db8:101::1236",
            duid_ll(0x65),
            None,
            Lease6Kind::Na,
            BindingState::Released,
            None,
        );
        lab.lease(
            off,
            "2001:db8:300::10",
            duid_ll(0x66),
            None,
            Lease6Kind::Na,
            BindingState::Active,
            None,
        );
        lab
    }
}

fn listeners6() -> Vec<Listener6Info> {
    vec![
        Listener6Info {
            address: "[2001:db8:100::10]:547".parse().expect("address"),
            mode: ListenMode::Relay,
            interface: None,
            workers: 2,
        },
        Listener6Info {
            address: "[2001:db8:201::1]:547".parse().expect("address"),
            mode: ListenMode::Direct,
            interface: Some("eth0".to_owned()),
            workers: 1,
        },
    ]
}

fn run_with(lab: &Lab, server_duid: Option<&[u8]>) -> KeaExport {
    let mut zones = BTreeMap::new();
    zones.insert(lab.zone, DnsName::new("example.test").expect("zone"));
    let listeners6 = listeners6();
    export(&KeaInput {
        data: &lab.data,
        zones: &zones,
        listeners: Some(&[]),
        listeners6: Some(&listeners6),
        server_duid,
        now: time("2026-10-25T12:30:00Z"),
        leases: true,
        conflict_detection: false,
    })
}

fn run(lab: &Lab) -> KeaExport {
    run_with(lab, Some(&SERVER_DUID))
}

fn dhcp6(out: &KeaExport) -> &Value {
    &out.dhcp6.as_ref().expect("a Dhcp6 document")["Dhcp6"]
}

fn all_subnets(dhcp6: &Value) -> Vec<Value> {
    let mut out: Vec<Value> = dhcp6["subnet6"].as_array().cloned().unwrap_or_default();
    for network in dhcp6["shared-networks"].as_array().into_iter().flatten() {
        out.extend(network["subnet6"].as_array().cloned().unwrap_or_default());
    }
    out
}

fn subnet<'a>(subnets: &'a [Value], network: &str) -> &'a Value {
    subnets
        .iter()
        .find(|subnet| subnet["subnet"] == json!(network))
        .unwrap_or_else(|| panic!("no subnet {network}"))
}

fn codes_of(out: &KeaExport) -> BTreeSet<String> {
    out.report
        .entries
        .iter()
        .map(|entry| entry.code.to_string())
        .collect()
}

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/export/kea/fixtures")
        .join(name)
}

/// The golden files: `KEA_GOLDEN=update` writes them anew, for review in the diff.
#[test]
fn the_golden_files() {
    let out = run(&Lab::new());
    let mut json = serde_json::to_string_pretty(out.dhcp6.as_ref().expect("Dhcp6")).expect("JSON");
    json.push('\n');
    let csv = out.leases6_csv.expect("the lease file");
    if std::env::var("KEA_GOLDEN").as_deref() == Ok("update") {
        std::fs::create_dir_all(fixture("")).expect("the fixture directory");
        std::fs::write(fixture("kea-dhcp6.json"), &json).expect("the fixture");
        std::fs::write(fixture("kea-leases6.csv"), &csv).expect("the fixture");
    }
    let read = |name: &str| {
        std::fs::read_to_string(fixture(name))
            .unwrap_or_default()
            .replace("\r\n", "\n")
    };
    assert_eq!(
        json,
        read("kea-dhcp6.json"),
        "KEA_GOLDEN=update rewrites it"
    );
    assert_eq!(
        csv,
        read("kea-leases6.csv"),
        "KEA_GOLDEN=update rewrites it"
    );
}

#[test]
fn global_parameters() {
    let out = run(&Lab::new());
    let dhcp6 = dhcp6(&out);
    // The server's lease times: valid one day, preferred five eighths, T1 and T2 half and
    // four fifths of the preferred lifetime.
    assert_eq!(dhcp6["valid-lifetime"], json!(86_400));
    assert_eq!(dhcp6["min-valid-lifetime"], json!(86_400));
    assert_eq!(dhcp6["preferred-lifetime"], json!(54_000));
    assert_eq!(dhcp6["max-preferred-lifetime"], json!(54_000));
    assert_eq!(dhcp6["renew-timer"], json!(27_000));
    assert_eq!(dhcp6["rebind-timer"], json!(43_200));
    assert_eq!(
        dhcp6["server-id"],
        json!({"type": "LLT", "htype": 1, "time": 0x2e8b_5800_u32, "identifier": "00005E005310"})
    );
    assert_eq!(
        dhcp6["interfaces-config"],
        json!({"interfaces": ["*", "eth0"]})
    );
    assert_eq!(
        dhcp6["host-reservation-identifiers"],
        json!(["duid", "hw-address"])
    );
    assert_eq!(
        dhcp6["lease-database"]["name"],
        json!("/var/lib/kea/kea-leases6.csv")
    );
    // The server's DHCPv6 options only, 23 and 24 sent unasked, 56 as sub-options.
    let options = dhcp6["option-data"].as_array().expect("options");
    assert_eq!(options.len(), 3);
    assert_eq!(
        options[0],
        json!({"code": 23, "space": "dhcp6", "name": "dns-servers", "csv-format": true, "data": "2001:db8:100::53", "always-send": true})
    );
    assert_eq!(options[1]["name"], json!("domain-search"));
    assert_eq!(options[1]["data"], json!("lab6.example.test"));
    assert_eq!(options[1]["always-send"], json!(true));
    assert_eq!(options[2]["name"], json!("ntp-server"));
    assert_eq!(
        options[2]["data"],
        json!("0001001020010DB8010000000000000000000123")
    );
    // The custom definition of dhcp6 here, the one of dhcp4 in Dhcp4 only.
    assert_eq!(
        dhcp6["option-def"],
        json!([{"name": "tenko-site", "code": 65_001, "space": "dhcp6", "type": "string", "array": false, "record-types": "", "encapsulate": ""}])
    );
    let defs4 = out.dhcp4["Dhcp4"]["option-def"].as_array().expect("defs");
    assert!(defs4.iter().all(|def| def["space"] == json!("dhcp4")));
    assert_eq!(defs4.len(), 1);
    assert_eq!(dhcp6["ddns-send-updates"], json!(false));
    assert_eq!(dhcp6["dhcp-ddns"]["server-port"], json!(53_001));
}

#[test]
fn subnets_pools_and_reservations() {
    let out = run(&Lab::new());
    let dhcp6 = dhcp6(&out);
    let subnets = all_subnets(dhcp6);
    assert_eq!(subnets.len(), 5, "the disabled scope is left out");
    let ids: BTreeSet<u64> = subnets
        .iter()
        .map(|subnet| subnet["id"].as_u64().expect("id"))
        .collect();
    assert_eq!(ids, BTreeSet::from([1, 2, 3, 4, 5]));

    let lan6 = subnet(&subnets, "2001:db8:101::/64");
    for (name, value) in [
        ("valid-lifetime", 120),
        ("max-valid-lifetime", 120),
        ("preferred-lifetime", 60),
        ("min-preferred-lifetime", 60),
        ("renew-timer", 30),
        ("rebind-timer", 48),
    ] {
        assert_eq!(lan6[name], json!(value), "{name}");
    }
    assert_eq!(lan6["rapid-commit"], json!(true));
    assert!(lan6.get("interface-id").is_none());
    assert_eq!(
        lan6["pools"],
        json!([
            {"pool": "2001:db8:101::1000 - 2001:db8:101::17ff", "option-data": [{"code": 31, "space": "dhcp6", "name": "sntp-servers", "csv-format": true, "data": "2001:db8:100::123"}]},
            {"pool": "2001:db8:101::1900 - 2001:db8:101::1fff", "option-data": [{"code": 31, "space": "dhcp6", "name": "sntp-servers", "csv-format": true, "data": "2001:db8:100::123"}]},
        ])
    );
    assert_eq!(
        lan6["option-data"],
        json!([{"code": 65_001, "space": "dhcp6", "name": "tenko-site", "csv-format": true, "data": "lan6"}])
    );
    let reservations = lan6["reservations"].as_array().expect("reservations");
    assert_eq!(reservations.len(), 2);
    let by_duid = reservations
        .iter()
        .find(|r| r["hostname"] == json!("lab6-reserved"))
        .expect("by DUID");
    assert_eq!(by_duid["duid"], json!("00:03:00:01:00:00:5e:00:53:61"));
    assert_eq!(by_duid["ip-addresses"], json!(["2001:db8:101::80"]));
    let by_mac = reservations
        .iter()
        .find(|r| r["hostname"] == json!("lab6-printer"))
        .expect("by MAC");
    assert_eq!(by_mac["hw-address"], json!("00:00:5e:00:53:62"));
    assert_eq!(by_mac["ip-addresses"], json!(["2001:db8:101::81"]));
    assert_eq!(by_mac["option-data"][0]["data"], json!("2001:db8:100::54"));
    assert_eq!(lan6["ddns-send-updates"], json!(true));
    assert_eq!(lan6["ddns-qualifying-suffix"], json!("example.test."));
    assert_eq!(lan6["user-context"]["description"], json!("lab link lan6"));

    let iot6 = subnet(&subnets, "2001:db8:102::/64");
    assert_eq!(iot6["rapid-commit"], json!(false));
    assert_eq!(iot6["interface-id"], json!("lab-iot6"));
    assert_eq!(iot6["valid-lifetime"], json!(3_600));
    assert_eq!(iot6["preferred-lifetime"], json!(2_250));
    assert_eq!(
        iot6["pools"],
        json!([{"pool": "2001:db8:102::1000 - 2001:db8:102::1fff", "client-class": "tenko.allow"}])
    );

    // campus6: the direct listener's interface on the shared network, no Interface-Id
    // beside it; the first pool loses the network's first address.
    let shared = dhcp6["shared-networks"]
        .as_array()
        .expect("shared networks");
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0]["name"], json!("campus6"));
    assert_eq!(shared[0]["interface"], json!("eth0"));
    assert!(shared[0].get("interface-id").is_none());
    assert_eq!(
        shared[0]["option-data"][0]["data"],
        json!("2001:db8:200::53")
    );
    let campus_a = subnet(&subnets, "2001:db8:201::/64");
    assert_eq!(
        campus_a["pools"],
        json!([{"pool": "2001:db8:201::1 - 2001:db8:201::ff"}])
    );
    assert!(campus_a.get("interface").is_none());
    assert!(campus_a.get("interface-id").is_none());
}

#[test]
fn the_filters_are_classes_of_the_link_layer_address() {
    let out = run(&Lab::new());
    let classes = dhcp6(&out)["client-classes"]
        .as_array()
        .expect("classes")
        .clone();
    assert_eq!(classes.len(), 2);
    assert_eq!(classes[0]["name"], json!("DROP"));
    assert_eq!(
        classes[0]["test"],
        json!(
            "((relay6[0].option[79].exists) and (substring(relay6[0].option[79].hex,0,2) == 0x0001) and (substring(relay6[0].option[79].hex,2,6) == 0x00005e0053ee)) or ((not (relay6[0].option[79].exists)) and (((substring(option[1].hex,0,4) == 0x00010001) and (substring(option[1].hex,8,6) == 0x00005e0053ee)) or ((substring(option[1].hex,0,4) == 0x00030001) and (substring(option[1].hex,4,6) == 0x00005e0053ee))))"
        )
    );
    assert_eq!(classes[1]["name"], json!("tenko.allow"));
    assert!(
        classes[1]["test"]
            .as_str()
            .expect("a test")
            .contains("substring(option[1].hex,4,5) == 0x00005e0053")
    );
}

#[test]
fn the_report_names_what_did_not_translate() {
    let out = run(&Lab::new());
    let codes = codes_of(&out);
    for code in [
        codes::V6_CLASSES,
        codes::V6_FILTERS,
        codes::V6_INTERFACE_ID,
        codes::V6_INTERFACES_ADDRESS,
        codes::POOL_LEASE,
        codes::SCOPE_RESTRICTED,
        codes::SCOPE_DISABLED,
        codes::LEASE_SCOPE,
        codes::DDNS_D2,
    ] {
        assert!(codes.contains(code), "{code} missing from {codes:?}");
    }
    assert!(!codes.contains(codes::V6_SERVER_ID_UNKNOWN));
    assert!(!codes.contains(codes::V6_SERVER_ID_TYPE));
    // Two Interface-Id findings: campus6's two values, and the one beside the interface.
    let interface_ids = out
        .report
        .entries
        .iter()
        .filter(|entry| entry.code == codes::V6_INTERFACE_ID)
        .count();
    assert_eq!(interface_ids, 2);
    // The skeleton holds the IPv6 reverse domain.
    let ddns = out.dhcp_ddns.expect("the skeleton");
    let reverse = &ddns["DhcpDdns"]["reverse-ddns"]["ddns-domains"];
    assert_eq!(
        reverse[0]["name"],
        json!("0.0.0.0.1.0.1.0.8.b.d.0.1.0.0.2.ip6.arpa.")
    );
    assert_eq!(
        reverse[0]["dns-servers"][0]["ip-address"],
        json!("2001:db8:100::53")
    );
}

#[test]
fn the_lease_file() {
    let lab = Lab::new();
    let out = run(&lab);
    let csv = out.leases6_csv.clone().expect("the lease file");
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines[0], HEADER);
    let subnets = all_subnets(dhcp6(&out));
    let id = |network: &str| subnet(&subnets, network)["id"].as_u64().expect("id");
    let (lan6, iot6) = (id("2001:db8:101::/64"), id("2001:db8:102::/64"));
    let delegation = id("2001:db8:180::/48");
    let expire = time("2026-10-25T12:02:00Z").unix_nanos() / 1_000_000_000;
    assert_eq!(
        lines[1..],
        [
            format!(
                "2001:db8:101::1234,00:03:00:01:00:00:5e:00:53:61,120,{expire},{lan6},60,0,7,128,1,1,host6.example.test.,00:00:5e:00:53:61,0,,1,2,0"
            ),
            format!("2001:db8:101::1235,00:00:00,120,{expire},{lan6},60,0,0,128,0,0,,,1,,0,0,0"),
            format!(
                "2001:db8:102::1abc,00:02:00:00:7e:d9:01:02:03,120,{expire},{iot6},60,0,7,128,0,0,host6&#x2ca.example.test.,00:00:5e:00:53:6f,0,,1,8,0"
            ),
            // WP9.4: a delegated prefix is lease type 2 with its delegated length.
            format!(
                "2001:db8:180:120::,00:03:00:01:00:00:5e:00:53:64,120,{expire},{delegation},60,2,7,60,0,0,,00:00:5e:00:53:64,0,,1,2,0"
            ),
        ]
    );
}

// WP9.4: the delegation pools as `pd-pools`.
#[test]
fn the_delegation_pools_are_pd_pools_without_the_excluded_prefixes() {
    let out = run(&Lab::new());
    let subnets = all_subnets(dhcp6(&out));
    let delegation = subnet(&subnets, "2001:db8:180::/48");
    let pd = delegation["pd-pools"].as_array().expect("pd-pools");
    let shown: Vec<(String, u64, u64)> = pd
        .iter()
        .map(|entry| {
            (
                entry["prefix"].as_str().expect("prefix").to_owned(),
                entry["prefix-len"].as_u64().expect("prefix-len"),
                entry["delegated-len"].as_u64().expect("delegated-len"),
            )
        })
        .collect();
    // The /56 without 2001:db8:180:110::/60, which holds the excluded address.
    assert_eq!(
        shown,
        [
            ("2001:db8:180:100::".to_owned(), 60, 60),
            ("2001:db8:180:120::".to_owned(), 59, 60),
            ("2001:db8:180:140::".to_owned(), 58, 60),
            ("2001:db8:180:180::".to_owned(), 57, 60),
        ]
    );
    for entry in pd {
        assert_eq!(
            entry["option-data"],
            json!([{"name": "dns-servers", "code": 23, "space": "dhcp6", "csv-format": true, "data": "2001:db8:180::53", "always-send": true}]),
            "{entry}"
        );
    }
    // The delegation network has no address pool; the other subnets have no pd-pools.
    assert_eq!(delegation["pools"], json!([]));
    assert!(
        subnet(&subnets, "2001:db8:101::/64")
            .get("pd-pools")
            .is_none()
    );
    // Nothing about delegated prefixes goes to the report any more.
    assert!(
        !codes_of(&out)
            .iter()
            .any(|code| code.starts_with("export.kea.v6.pd")),
        "{:?}",
        codes_of(&out)
    );
}

#[test]
fn a_server_duid_kea_cannot_hold_or_does_not_know() {
    let lab = Lab::new();
    let uuid_duid = crate::v6::server::server_duid(NodeId(1));
    let out = run_with(&lab, Some(&uuid_duid));
    assert!(dhcp6(&out).get("server-id").is_none());
    assert!(codes_of(&out).contains(codes::V6_SERVER_ID_TYPE));
    let out = run_with(&lab, None);
    assert!(dhcp6(&out).get("server-id").is_none());
    assert!(codes_of(&out).contains(codes::V6_SERVER_ID_UNKNOWN));
    let ll = duid_ll(0x10);
    assert_eq!(
        dhcp6(&run_with(&lab, Some(&ll)))["server-id"],
        json!({"type": "LL", "htype": 1, "identifier": "00005E005310"})
    );
    let en = [0, 2, 0, 0, 0x7e, 0xd9, 0xab, 0xcd];
    assert_eq!(
        dhcp6(&run_with(&lab, Some(&en)))["server-id"],
        json!({"type": "EN", "enterprise-id": 32_473, "identifier": "ABCD"})
    );
}

#[test]
fn without_dhcpv6_there_is_no_dhcp6_document() {
    let mut data = DhcpData::default();
    let prefix = PrefixId::from_uuid(uuid(9));
    data.prefixes.insert(
        prefix,
        Prefix {
            id: prefix,
            vrf: VrfId::from_uuid(uuid(1)),
            cidr: "192.0.2.0/26".parse().expect("cidr"),
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
    let zones = BTreeMap::new();
    let input = |listeners6| KeaInput {
        data: &data,
        zones: &zones,
        listeners: None,
        listeners6,
        server_duid: None,
        now: time("2026-10-25T12:30:00Z"),
        leases: true,
        conflict_detection: false,
    };
    let out = export(&input(Some(&[])));
    assert!(out.dhcp6.is_none());
    assert!(out.leases6_csv.is_none());
    // A DHCPv6 listener alone is enough for a document, without subnets.
    let listeners6 = listeners6();
    let out = export(&input(Some(&listeners6)));
    assert_eq!(dhcp6(&out)["subnet6"], json!([]));
    // Kea refuses an empty client-classes list.
    assert!(dhcp6(&out).get("client-classes").is_none());
    assert_eq!(
        out.leases6_csv.as_deref(),
        Some(format!("{HEADER}\n").as_str())
    );
}

fn scope_image(lease: LeaseTimes, settings: Scope6Settings) -> Scope6Image {
    Scope6Image {
        pd_pools: Vec::new(),
        prefix: PrefixId::from_uuid(uuid(5)),
        vrf: VrfId::from_uuid(uuid(1)),
        network: "2001:db8::/64".parse().expect("network"),
        authoritative: true,
        restricted: false,
        lease,
        v6: settings,
        interface_id: None,
        shared_network: None,
        pools: Vec::new(),
        excluded: Vec::new(),
        options: Vec::new(),
        ddns: DdnsPolicy::default(),
    }
}

proptest! {
    /// The export's lifetimes are the engine's for every lease time and setting.
    #[test]
    fn lifetimes_are_the_engines(
        default in 1u32..2_000_000,
        t1 in proptest::option::of(0u32..2_000_000),
        t2 in proptest::option::of(0u32..2_000_000),
        preferred in proptest::option::of(1u32..2_000_000),
    ) {
        let times = LeaseTimes { t1_secs: t1, t2_secs: t2, ..LeaseTimes::fixed(default) };
        let settings = Scope6Settings { preferred_secs: preferred, ..Scope6Settings::default() };
        let engine = crate::v6::engine::alloc::lifetimes(&scope_image(times, settings.clone()), None);
        prop_assert_eq!(lifetimes(&times, &settings), engine);
    }

    /// The pools hold exactly the addresses of the range the engine may lease: none
    /// excluded, not the network's first address, in order and apart.
    #[test]
    fn pools_hold_the_leasable_addresses(
        first in 0u128..64,
        len in 0u128..64,
        cuts in proptest::collection::vec((0u128..140, 0u128..8), 0..6),
    ) {
        let network = "2001:db8::/64".parse::<ipnet::Ipv6Net>().expect("network");
        let base = u128::from(network.network());
        let pool = Pool6Image {
            range: RangeId::from_uuid(uuid(6)),
            first: Ipv6Addr::from(base + first),
            last: Ipv6Addr::from(base + first + len),
            lease: LeaseTimes::default(),
            options: Vec::new(),
        };
        let mut image = scope_image(LeaseTimes::default(), Scope6Settings::default());
        image.excluded = cuts
            .iter()
            .map(|(at, width)| (Ipv6Addr::from(base + at), Ipv6Addr::from(base + at + width)))
            .collect();
        let mut held = crate::v6::image::Image6::default();
        held.add_scope(image.clone());
        let image = held.scope(image.prefix).expect("the scope").clone();
        let pieces = super::subnets::free(&pool, network.network(), &image.excluded);
        for pair in pieces.windows(2) {
            prop_assert!(pair[0].1 + 1 < pair[1].0, "pieces are sorted and apart");
        }
        let got: BTreeSet<u128> = pieces.iter().flat_map(|(a, b)| *a..=*b).collect();
        let want: BTreeSet<u128> = (base + first..=base + first + len)
            .filter(|addr| !image.is_excluded(Ipv6Addr::from(*addr)))
            .collect();
        prop_assert_eq!(got, want);
    }
}
