use std::net::{IpAddr, Ipv4Addr};

use super::*;
use crate::{
    Action, Coded,
    codec::{decode_key, encode_key, from_cbor, to_cbor},
    id::{InterfaceId, NodeId, VrfId},
    ipam::{AllocPolicy, Meta, Status},
    names::is_valid_name,
    principal::{Principal, SystemComponent},
    serde_util::HexBytes,
    timestamp::Timestamp,
};

fn stamp() -> Stamp {
    Stamp::new(
        "2026-10-22T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Dhcp),
    )
}

fn prefix(cidr: &str, role: PrefixRole) -> Prefix {
    Prefix {
        id: PrefixId::generate(),
        vrf: VrfId::generate(),
        cidr: cidr.parse().expect("cidr"),
        role,
        status: Status::Active,
        vlan: None,
        site: None,
        alarm: None,
        alloc: AllocPolicy::default(),
        dns_reverse: None,
        meta: Meta::new(stamp()),
    }
}

fn scope(prefix: PrefixId) -> Scope {
    Scope {
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
        v6: None,
        created: stamp(),
        updated: stamp(),
    }
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}

fn lease() -> Lease {
    Lease {
        addr: Ipv4Addr::new(192, 0, 2, 50),
        vrf: VrfId::generate(),
        scope: PrefixId::generate(),
        client: ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]),
            client_id: None,
        },
        state: BindingState::Active,
        cltt: "2026-10-22T12:00:00Z".parse().expect("time"),
        ends: "2026-10-23T12:00:00Z".parse().expect("time"),
        tstp: None,
        tsfp: None,
        atsfp: None,
        node: NodeId(1),
        share: None,
        hostname: Some("printer01".to_owned()),
        fqdn: None,
        fqdn_flags: None,
        ddns_policy: None,
        ddns: DdnsState::default(),
        fingerprint: Some(Fingerprint {
            parameters: HexBytes(vec![1, 3, 6, 15, 119, 252]),
            vendor_class: Some("MSFT 5.0".to_owned()),
            user_class: false,
            client_fqdn: true,
            architecture: None,
        }),
        relay: Some(RelayInfo {
            giaddr: Ipv4Addr::new(192, 0, 2, 1),
            circuit_id: Some(HexBytes(b"eth0/1".to_vec())),
            remote_id: None,
            link_selection: None,
            server_id_override: None,
            raw: HexBytes(vec![1, 6, b'e', b't', b'h', b'0', b'/', b'1']),
        }),
        observed_at: None,
    }
}

#[test]
fn names_are_in_the_namespace() {
    for table in tables::all() {
        assert_eq!(table.namespace(), "dhcp", "{table}");
    }
    let mut names: Vec<&str> = tables::all().iter().map(|t| t.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), tables::all().len());
    // Every table except the histories is in the node subset.
    for table in tables::all() {
        assert_eq!(
            tables::NODE_TABLES.contains(table),
            !matches!(table.as_str(), "dhcp.history" | "dhcp.history6"),
            "{table}"
        );
    }
    for table in &tables::NODE_IPAM_TABLES {
        assert_eq!(table.namespace(), "ipam");
    }
    for code in codes::ALL {
        assert!(is_valid_name(code) && code.starts_with("dhcp."), "{code}");
    }
    let mut all: Vec<&str> = codes::ALL.to_vec();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), codes::ALL.len());
    let mut actions: Vec<&str> = audit::ALL.iter().map(|a| a.as_str()).collect();
    assert!(actions.iter().all(|a| a.starts_with("dhcp.")));
    actions.sort_unstable();
    actions.dedup();
    assert_eq!(actions.len(), audit::ALL.len());
    for kind in [
        events::LEASE_CHANGED,
        events::LEASES_SAMPLED,
        events::CONFIG_CHANGED,
        events::CONFLICT,
        events::STORE_STATE,
    ] {
        assert!(is_valid_name(kind), "{kind}");
    }
    assert_eq!(TOPIC, "dhcp");
    assert!(is_valid_name(FAILOVER_PURPOSE));
    assert_eq!(SystemComponent::Dhcp.as_str(), "dhcp");
}

#[test]
fn scopes_follow_the_actions() {
    for kind in OBJECT_KINDS {
        assert_eq!(
            DhcpScope::required(Action::Read, kind),
            Some(DhcpScope::Read)
        );
        for action in [
            Action::Create,
            Action::Update,
            Action::Delete,
            Action::Execute,
        ] {
            assert_eq!(DhcpScope::required(action, kind), Some(DhcpScope::Write));
        }
        for action in [Action::Approve, Action::Reveal, Action::Administer] {
            assert_eq!(DhcpScope::required(action, kind), None);
        }
        assert!(kind.as_str().starts_with("dhcp_"));
    }
    assert_eq!(DhcpScope::required(Action::Read, ObjectKind::Zone), None);
    assert_eq!(
        serde_json::to_value(DhcpScope::Write).expect("json"),
        "dhcp.write"
    );
    let prefix = PrefixId::generate();
    assert_eq!(scope_object(prefix).id, prefix.0);
    assert!(server_object().id.is_nil());
    assert_eq!(
        ObjectRef::from(ClassId::generate()).kind,
        ObjectKind::DhcpClass
    );
}

#[test]
fn lease_times_are_ordered() {
    let times = LeaseTimes::default();
    assert!(times.validate("lease").is_ok());
    assert_eq!(times.grant(None), 86_400);
    assert_eq!(times.grant(Some(60)), 3_600);
    assert_eq!(times.grant(Some(10_000_000)), 604_800);
    assert_eq!(times.renewal_times(86_400), (43_200, 75_600));
    let explicit = LeaseTimes {
        t1_secs: Some(40_000),
        t2_secs: Some(70_000),
        ..times
    };
    assert!(explicit.validate("lease").is_ok());
    assert_eq!(explicit.renewal_times(43_200), (20_000, 35_000));
    for bad in [
        LeaseTimes {
            min_secs: 0,
            ..times
        },
        LeaseTimes {
            default_secs: 100,
            ..times
        },
        LeaseTimes {
            max_secs: MAX_LEASE_SECS + 1,
            ..times
        },
        LeaseTimes {
            t1_secs: Some(80_000),
            t2_secs: Some(70_000),
            ..times
        },
        LeaseTimes {
            t2_secs: Some(86_400),
            ..times
        },
    ] {
        let error = bad.validate("lease").expect_err("invalid");
        assert_eq!(error.code(), codes::LEASE_TIMES_INVALID);
        assert_eq!(error.http_status(), 400);
    }
}

#[test]
fn a_scope_serves_a_network() {
    let network = prefix("192.0.2.0/24", PrefixRole::Network);
    let mut item = scope(network.id);
    assert!(item.validate(&network).is_ok());
    assert_eq!(item.options(), OptionOwner::Scope(network.id));
    let supernet = prefix("192.0.0.0/16", PrefixRole::Supernet);
    let error = scope(supernet.id)
        .validate(&supernet)
        .expect_err("supernet");
    assert_eq!(error.code(), codes::SCOPE_NOT_NETWORK);
    item.server_id = Some(ip("2001:db8::1"));
    assert_eq!(
        item.validate(&network).expect_err("family").code(),
        codes::SCOPE_INVALID
    );
    item.server_id = Some(ip("198.51.100.10"));
    let class = ClassId::generate();
    item.classes = vec![class, class];
    assert!(item.validate(&network).is_err());
    assert!(scope(PrefixId::generate()).validate(&network).is_err());
}

#[test]
fn exclusions_lie_inside_their_scope() {
    let network = prefix("192.0.2.0/24", PrefixRole::Network);
    let mut range = ExclusionRange {
        id: ExclusionId::generate(),
        scope: network.id,
        first: ip("192.0.2.10"),
        last: ip("192.0.2.19"),
        description: None,
        created: stamp(),
    };
    assert!(range.validate(&network).is_ok());
    assert!(range.contains(ip("192.0.2.15")) && !range.contains(ip("192.0.2.20")));
    range.last = ip("192.0.2.5");
    assert_eq!(
        range.validate(&network).expect_err("order").code(),
        codes::EXCLUSION_INVALID
    );
    range.last = ip("198.51.100.5");
    assert!(range.validate(&network).is_err());
}

#[test]
fn pool_settings_need_a_pool_range() {
    let network = prefix("192.0.2.0/24", PrefixRole::Network);
    let mut range = Range {
        id: RangeId::generate(),
        prefix: network.id,
        first: ip("192.0.2.100"),
        last: ip("192.0.2.199"),
        role: RangeRole::DhcpPool,
        lease_secs: Some(3_600),
        status: Status::Active,
        meta: Meta::new(stamp()),
    };
    let pool = PoolSettings {
        range: range.id,
        classes: Vec::new(),
        lease: None,
        updated: stamp(),
    };
    assert!(pool.validate(&range, &network).is_ok());
    range.role = RangeRole::Reserved;
    assert_eq!(
        pool.validate(&range, &network).expect_err("role").code(),
        codes::POOL_NOT_POOL
    );
    range.role = RangeRole::DhcpPool;
    let other = prefix("198.51.100.0/24", PrefixRole::Network);
    assert_eq!(
        pool.validate(&range, &other).expect_err("outside").code(),
        codes::POOL_OUTSIDE
    );
}

#[test]
fn option_kinds_check_their_data() {
    assert!(
        OptionKind::Ipv4Address
            .check(false, &[192, 0, 2, 1])
            .is_ok()
    );
    assert!(
        OptionKind::Ipv4Address
            .check(false, &[192, 0, 2, 1, 192, 0, 2, 2])
            .is_err()
    );
    assert!(
        OptionKind::Ipv4Address
            .check(true, &[192, 0, 2, 1, 192, 0, 2, 2])
            .is_ok()
    );
    assert!(OptionKind::Ipv4Address.check(true, &[192, 0, 2]).is_err());
    assert!(OptionKind::String.check(false, b"example.test").is_ok());
    assert!(OptionKind::String.check(false, b"a\0b").is_err());
    assert!(OptionKind::String.check(false, b"").is_err());
    assert!(OptionKind::Bool.check(false, &[2]).is_err());
    assert!(OptionKind::Empty.check(false, &[]).is_ok());
    assert!(OptionKind::Empty.check(false, &[0]).is_err());
    let names = [
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's', b't', 0,
    ];
    assert!(OptionKind::Fqdn.check(false, &names).is_ok());
    assert!(OptionKind::Fqdn.check(false, &[0xc0, 0x0c]).is_err());
    assert!(
        OptionKind::ClasslessRoutes
            .check(false, &[24, 203, 0, 113, 192, 0, 2, 1])
            .is_ok()
    );
    assert!(
        OptionKind::ClasslessRoutes
            .check(false, &[33, 0, 0, 0, 0])
            .is_err()
    );
    assert!(
        OptionKind::Binary
            .check(false, &[0; MAX_OPTION_DATA + 1])
            .is_err()
    );
}

use option::MAX_OPTION_DATA;

#[test]
fn option_data_round_trips_through_the_wire_form() {
    let cases = [
        (
            OptionKind::Ipv4Address,
            true,
            OptionData::Ipv4 {
                values: vec![
                    Ipv4Addr::new(192, 0, 2, 53),
                    Ipv4Addr::new(198, 51, 100, 53),
                ],
            },
        ),
        (OptionKind::U16, false, OptionData::Unsigned(vec![1_500])),
        (OptionKind::I32, false, OptionData::Signed(-3_600)),
        (
            OptionKind::String,
            false,
            OptionData::Text("example.test".to_owned()),
        ),
        (
            OptionKind::Fqdn,
            true,
            OptionData::Names(vec![
                crate::dns::DnsName::new("eng.example.test").expect("name"),
                crate::dns::DnsName::new("example.test").expect("name"),
            ]),
        ),
        (
            OptionKind::ClasslessRoutes,
            false,
            OptionData::Routes(vec![StaticRoute {
                destination: "203.0.113.0/24".parse().expect("net"),
                router: Ipv4Addr::new(192, 0, 2, 1),
            }]),
        ),
        (OptionKind::Empty, false, OptionData::Empty),
    ];
    for (kind, array, data) in cases {
        let wire = data.encode(kind, array).expect("encode");
        assert_eq!(
            OptionData::decode(kind, array, &wire).expect("decode"),
            data,
            "{kind:?}"
        );
    }
    assert!(
        OptionData::Text("x".to_owned())
            .encode(OptionKind::U8, false)
            .is_err()
    );
    assert!(
        OptionData::Unsigned(vec![300])
            .encode(OptionKind::U8, false)
            .is_err()
    );
}

#[test]
fn option_values_follow_their_definitions() {
    let dns = OptionValue::v4(6, vec![192, 0, 2, 53, 198, 51, 100, 53]);
    assert!(dns.validate(&[]).is_ok());
    assert_eq!(
        OptionValue::v4(6, vec![1, 2, 3])
            .validate(&[])
            .expect_err("length")
            .code(),
        codes::OPTION_INVALID
    );
    assert_eq!(
        OptionValue::v4(51, vec![0, 0, 0, 1])
            .validate(&[])
            .expect_err("managed")
            .code(),
        codes::OPTION_CODE_RESERVED
    );
    let site = OptionValue::v4(224, b"lab".to_vec());
    assert_eq!(
        site.validate(&[]).expect_err("unknown").code(),
        codes::OPTION_UNKNOWN
    );
    let def = OptionDef {
        id: OptionDefId::generate(),
        space: OptionSpace::dhcp4(),
        code: 224,
        name: "site-label".to_owned(),
        kind: OptionKind::String,
        array: false,
        vendor_class: None,
        description: None,
        created: stamp(),
        updated: stamp(),
    };
    assert!(def.validate().is_ok());
    assert!(site.validate([&def]).is_ok());
    let catalog = OptionDef {
        code: 6,
        ..def.clone()
    };
    assert_eq!(
        catalog.validate().expect_err("catalog").code(),
        codes::OPTION_CODE_RESERVED
    );
    assert!(
        OptionDef {
            array: true,
            ..def.clone()
        }
        .validate()
        .is_err()
    );
    assert!(
        OptionDef {
            name: "Site Label".to_owned(),
            ..def.clone()
        }
        .validate()
        .is_err()
    );
    assert!(
        OptionDef {
            vendor_class: Some("MSFT".to_owned()),
            ..def.clone()
        }
        .validate()
        .is_err()
    );
    let vendor = OptionDef {
        space: OptionSpace::new("vendor-pxe").expect("space"),
        code: 6,
        vendor_class: Some("PXEClient".to_owned()),
        ..def
    };
    assert!(vendor.validate().is_ok());
    assert!(OptionSpace::new("Vendor").is_err());

    let set = OptionSet {
        owner: OptionOwner::Server,
        values: vec![dns.clone(), dns.clone()],
        updated: stamp(),
    };
    assert!(set.validate(&[]).is_err());
    let merged = merge([
        [
            OptionValue::v4(6, vec![192, 0, 2, 53]),
            OptionValue::v4(15, b"example.test".to_vec()),
        ]
        .as_slice(),
        [OptionValue::v4(6, vec![198, 51, 100, 53])].as_slice(),
    ]);
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].data.0, vec![198, 51, 100, 53]);
}

#[test]
fn option_owners_round_trip() {
    for owner in [
        OptionOwner::Server,
        OptionOwner::SharedNetwork(SharedNetworkId::generate()),
        OptionOwner::Scope(PrefixId::generate()),
        OptionOwner::Pool(RangeId::generate()),
        OptionOwner::Policy(PolicyId::generate()),
        OptionOwner::Host(InterfaceId::generate()),
    ] {
        assert_eq!(
            OptionOwner::from_path(&owner.to_path()).expect("path"),
            owner
        );
        assert_eq!(decode_key::<OptionOwner>(&encode_key(&owner)), Ok(owner));
        let back: OptionOwner = from_cbor(&to_cbor(&owner).expect("cbor")).expect("cbor");
        assert_eq!(back, owner);
        let json = serde_json::to_string(&owner).expect("json");
        assert_eq!(
            serde_json::from_str::<OptionOwner>(&json).expect("json"),
            owner
        );
    }
    assert!(OptionOwner::from_path("zone:x").is_err());
    assert!(OptionOwner::from_path("scope:not-a-uuid").is_err());
}

#[test]
fn mac_patterns_and_filters() {
    let pattern = MacPattern::new("00-00-5E-00-53-*").expect("pattern");
    assert_eq!(pattern.to_string(), "00:00:5e:00:53:*");
    assert!(pattern.matches(&[0, 0, 0x5e, 0, 0x53, 0x42]));
    assert!(!pattern.matches(&[0, 0, 0x5e, 0, 0x54, 0x42]));
    let open = MacPattern::new("00:00:5e:*").expect("open");
    assert_eq!(open.to_string(), "00:00:5e:*:*:*");
    assert!(MacPattern::new("00:00:5e").is_err());
    assert!(MacPattern::new("00:00:5e:00:53:01:02").is_err());
    assert!(MacPattern::new("zz:00:5e:00:53:01").is_err());
    let exact = MacPattern::new("00:00:5e:00:53:01").expect("exact");
    assert!(exact.is_exact() && !pattern.is_exact());
    let json = serde_json::to_string(&pattern).expect("json");
    assert_eq!(
        serde_json::from_str::<MacPattern>(&json).expect("json"),
        pattern
    );

    let entry = |mac: &str, kind| Filter {
        id: FilterId::generate(),
        mac: MacPattern::new(mac).expect("mac"),
        kind,
        note: None,
        created: stamp(),
        updated: stamp(),
    };
    let filters = [
        entry("00:00:5e:00:53:*", FilterKind::Allow),
        entry("00:00:5e:00:53:66", FilterKind::Deny),
    ];
    assert_eq!(
        filter_verdict(&filters, &[0, 0, 0x5e, 0, 0x53, 1]),
        FilterVerdict::Allowed
    );
    assert_eq!(
        filter_verdict(&filters, &[0, 0, 0x5e, 0, 0x53, 0x66]),
        FilterVerdict::Denied
    );
    assert_eq!(
        filter_verdict(&filters, &[2, 0, 0, 0, 0, 1]),
        FilterVerdict::Unlisted
    );
}

#[test]
fn classes_and_policies_validate() {
    let class = Class {
        id: ClassId::generate(),
        name: "uefi-x64".to_owned(),
        matches: vec![
            Match::Architecture { code: 7 },
            Match::VendorClass {
                value: "PXEClient:Arch:00007".to_owned(),
                prefix: true,
            },
        ],
        description: None,
        created: stamp(),
        updated: stamp(),
    };
    assert!(class.validate().is_ok());
    assert!(
        Class {
            matches: Vec::new(),
            ..class.clone()
        }
        .validate()
        .is_err()
    );
    assert!(
        Class {
            matches: vec![Match::UserClass {
                value: String::new()
            }],
            ..class.clone()
        }
        .validate()
        .is_err()
    );
    let policy = Policy {
        id: PolicyId::generate(),
        name: "uefi-boot".to_owned(),
        scope: None,
        order: 1,
        enabled: true,
        condition: Condition {
            join: Join::And,
            terms: vec![
                Term::Class(class.id),
                Term::NotMatch(Match::HostName {
                    value: "lab".to_owned(),
                    prefix: true,
                }),
            ],
        },
        action: PolicyAction {
            range: Some(AddressRange {
                first: ip("192.0.2.150"),
                last: ip("192.0.2.159"),
            }),
            lease: Some(LeaseTimes::fixed(600)),
            ddns: None,
        },
        description: None,
        created: stamp(),
        updated: stamp(),
    };
    assert!(policy.validate().is_ok());
    let back: Policy = from_cbor(&to_cbor(&policy).expect("cbor")).expect("cbor");
    assert_eq!(back, policy);
    let mut bad = policy.clone();
    bad.action.range = Some(AddressRange {
        first: ip("192.0.2.159"),
        last: ip("192.0.2.150"),
    });
    assert_eq!(
        bad.validate().expect_err("range").code(),
        codes::POLICY_INVALID
    );
    let mut empty = policy;
    empty.condition.terms.clear();
    assert!(empty.validate().is_err());
}

#[test]
fn leases_round_trip_and_know_their_client() {
    let lease = lease();
    let back: Lease = from_cbor(&to_cbor(&lease).expect("cbor")).expect("cbor");
    assert_eq!(back, lease);
    let json = serde_json::to_string(&lease).expect("json");
    assert_eq!(serde_json::from_str::<Lease>(&json).expect("json"), lease);
    assert_eq!(lease.client.identity(), vec![0, 1, 0, 0, 0x5e, 0, 0x53, 1]);
    assert_eq!(lease.client.mac(), Some([0, 0, 0x5e, 0, 0x53, 1]));
    let with_id = ClientKey {
        client_id: Some(HexBytes(vec![1, 2, 3])),
        ..lease.client.clone()
    };
    assert_eq!(with_id.identity(), vec![1, 1, 2, 3]);
    let before: Timestamp = "2026-10-22T18:00:00Z".parse().expect("time");
    let after: Timestamp = "2026-10-24T00:00:00Z".parse().expect("time");
    assert!(lease.is_bound(before) && !lease.is_bound(after));
    assert!(lease.blocks(before));
    let event = LeaseEvent::of(&lease, LeaseEventKind::Granted, lease.cltt);
    assert_eq!(event.addr, lease.addr);
    let back: LeaseEvent = from_cbor(&to_cbor(&event).expect("cbor")).expect("cbor");
    assert_eq!(back, event);
    assert!(BindingState::Abandoned.holds_address());
    assert!(!BindingState::Released.holds_address());
}

#[test]
fn settings_and_ddns_validate() {
    let settings = DhcpSettings::default();
    assert!(settings.validate().is_ok());
    assert!(
        DhcpSettings {
            history_days: Some(0),
            ..settings.clone()
        }
        .validate()
        .is_err()
    );
    let back: DhcpSettings = from_cbor(&to_cbor(&settings).expect("cbor")).expect("cbor");
    assert_eq!(back, settings);
    let ddns = DdnsPolicy {
        ttl: Some(700_000),
        ..DdnsPolicy::default()
    };
    assert_eq!(
        ddns.validate("ddns").expect_err("ttl").code(),
        codes::DDNS_INVALID
    );
    // An empty JSON object reads as the defaults.
    let read: DdnsPolicy = serde_json::from_str("{}").expect("json");
    assert_eq!(read, DdnsPolicy::default());
}

#[test]
fn reservation_findings() {
    let scope = PrefixId::generate();
    let (a, b, c) = (HostId::generate(), HostId::generate(), HostId::generate());
    let candidate = |host, address: &str, identity: Option<Vec<u8>>| ReservationCandidate {
        host,
        scope,
        address: ip(address),
        identity,
    };
    let warnings = check_reservations(&[
        candidate(a, "192.0.2.10", Some(vec![0, 1, 1])),
        candidate(b, "192.0.2.10", Some(vec![0, 1, 2])),
        candidate(c, "192.0.2.11", None),
    ]);
    assert!(warnings.contains(&ReservationWarning::NoIdentity { host: c }));
    let mut hosts = vec![a, b];
    hosts.sort();
    assert!(warnings.contains(&ReservationWarning::AddressCollision {
        address: ip("192.0.2.10"),
        hosts,
    }));
    let warnings = check_reservations(&[
        candidate(a, "192.0.2.10", Some(vec![0, 1, 1])),
        candidate(b, "192.0.2.12", Some(vec![0, 1, 1])),
    ]);
    assert!(matches!(
        warnings.as_slice(),
        [ReservationWarning::ClientCollision { .. }]
    ));
    assert_eq!(
        check_reservations(&[candidate(a, "192.0.2.10", Some(vec![0]))]),
        Vec::new()
    );
}
