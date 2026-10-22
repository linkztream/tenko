use std::net::{IpAddr, Ipv4Addr};

use super::*;
use crate::{
    Action, Coded,
    codec::{decode_key, encode_key, from_cbor, to_cbor},
    names::is_valid_name,
    principal::{Principal, SystemComponent},
    secret::SecretRef,
};

fn stamp() -> Stamp {
    Stamp::new(
        "2026-10-17T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Dns),
    )
}

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn zone() -> Zone {
    Zone {
        id: ZoneId::generate(),
        name: name("example.test"),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: vec![ZoneScope::default_scope()],
        serial: SerialPolicy::default(),
        soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
        transfer: TransferPolicy::default(),
        update: UpdatePolicy::default(),
        dnssec: DnssecPolicy::default(),
        source: None,
        reverse_of: None,
        catalog: false,
        description: None,
        created: stamp(),
        updated: stamp(),
    }
}

fn rrset(zone: &Zone, owner: &str, data: &[RecordData]) -> RrSet {
    RrSet {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        name: name(owner),
        rtype: data[0].rtype(),
        ttl: 300,
        rdata: data.iter().map(Rdata::from_data).collect(),
        origin: Origin::Manual,
        key: None,
        updated: stamp(),
    }
}

fn a(last: u8) -> RecordData {
    RecordData::A {
        address: Ipv4Addr::new(192, 0, 2, last),
    }
}

fn cname(target: &str) -> RecordData {
    RecordData::Cname {
        target: name(target),
    }
}

fn ns(host: &str) -> RecordData {
    RecordData::Ns { host: name(host) }
}

fn soa() -> RecordData {
    RecordData::Soa {
        mname: name("ns1.example.test"),
        rname: name("hostmaster.example.test"),
        serial: 1,
        refresh: 3600,
        retry: 900,
        expire: 1_209_600,
        minimum: 300,
    }
}

fn code(error: &DnsError) -> &'static str {
    error.code()
}

#[test]
fn a_zone_round_trips_and_defaults_its_policies() {
    let zone = zone();
    zone.validate().expect("valid");
    let json = serde_json::to_value(&zone).expect("json");
    assert_eq!(json["kind"], "primary");
    assert_eq!(json["serial"], "date_counter");
    assert_eq!(json["dnssec"]["mode"], "off");
    assert_eq!(json["dnssec"]["algorithm"], "ecdsa_p256_sha256");
    assert_eq!(json["transfer"]["require_tsig"], true);
    let back: Zone = serde_json::from_value(json.clone()).expect("json");
    assert_eq!(back, zone);
    assert_eq!(
        from_cbor::<Zone>(&to_cbor(&zone).expect("cbor")).expect("cbor"),
        zone
    );
    // Policies and scopes default when absent.
    let mut object = json;
    for field in ["scopes", "serial", "transfer", "update", "dnssec"] {
        object.as_object_mut().expect("object").remove(field);
    }
    let back: Zone = serde_json::from_value(object).expect("json");
    assert_eq!(back.scopes, vec![ZoneScope::default_scope()]);
    assert!(back.update.require_tsig && !back.update.may_replace_ipam);
}

#[test]
fn zone_rules_hold() {
    let mut wildcard = zone();
    wildcard.name = name("*.example.test");
    assert_eq!(
        code(&wildcard.validate().expect_err("wildcard")),
        codes::ZONE_INVALID
    );

    let mut no_default = zone();
    no_default.scopes = vec![ZoneScope {
        name: ScopeName::new("internal").expect("scope"),
        description: None,
    }];
    assert!(no_default.validate().is_err());

    let mut twice = zone();
    twice.scopes.push(ZoneScope::default_scope());
    assert!(twice.validate().is_err());

    let mut secondary = zone();
    secondary.kind = ZoneKind::Secondary;
    assert!(secondary.validate().is_err(), "a secondary needs a primary");
    secondary.source = Some(SecondarySource {
        primaries: vec![PrimaryServer {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
            port: 53,
            key: Some(name("xfr-key")),
            xot: false,
            tls_name: None,
        }],
    });
    secondary.validate().expect("valid secondary");
    secondary.dnssec.mode = DnssecMode::Online;
    assert!(secondary.validate().is_err(), "only primaries sign online");

    let mut reverse = zone();
    reverse.reverse_of = Some(crate::PrefixId::generate());
    assert!(
        reverse.validate().is_err(),
        "a forward zone is no reverse zone"
    );
    reverse.name = name("2.0.192.in-addr.arpa");
    reverse.validate().expect("reverse zone");
    reverse.name = name("0/26.2.0.192.in-addr.arpa");
    reverse.validate().expect("RFC 2317 zone");

    let mut soa_bounds = zone();
    soa_bounds.soa.expire = 100;
    let error = soa_bounds.validate().expect_err("expiry");
    assert_eq!(error.as_coded_error().params["field"], "soa.expire");
    assert_eq!(error.field_errors()[0].field, "soa.expire");

    let mut signing = zone();
    signing.dnssec.resign_before_days = 20;
    assert!(signing.validate().is_err());
}

#[test]
fn rrset_rules_hold() {
    let zone = zone();
    let apex = &zone.name;
    rrset(&zone, "www.example.test", &[a(1), a(2)])
        .check(apex)
        .expect("valid");
    rrset(&zone, "*.example.test", &[a(1)])
        .check(apex)
        .expect("wildcard data");

    let fails = |set: RrSet| code(&set.check(apex).expect_err("refused"));
    assert_eq!(
        fails(rrset(&zone, "www.example.net", &[a(1)])),
        codes::RECORD_INVALID
    );
    assert_eq!(
        fails(rrset(&zone, "www.example.test", &[a(1), a(1)])),
        codes::RECORD_INVALID
    );
    assert_eq!(
        fails(rrset(
            &zone,
            "www.example.test",
            &[cname("a.example.test"), cname("b.example.test")]
        )),
        codes::RECORD_INVALID
    );
    assert_eq!(
        fails(rrset(&zone, "www.example.test", &[soa()])),
        codes::RECORD_INVALID
    );
    assert_eq!(
        fails(rrset(&zone, "example.test", &[cname("a.example.net")])),
        codes::RECORD_INVALID
    );
    assert_eq!(
        fails(rrset(&zone, "*.example.test", &[ns("ns1.example.net")])),
        codes::RECORD_INVALID
    );
    let mut long = rrset(&zone, "www.example.test", &[a(1)]);
    long.ttl = MAX_TTL + 1;
    assert_eq!(fails(long), codes::RECORD_INVALID);
    let mut empty = rrset(&zone, "www.example.test", &[a(1)]);
    empty.rdata.clear();
    assert_eq!(fails(empty), codes::RECORD_INVALID);
    let mut wrong = rrset(&zone, "www.example.test", &[a(1)]);
    wrong.rtype = Rtype::AAAA;
    assert_eq!(fails(wrong), codes::RECORD_INVALID);
    let mut meta = rrset(&zone, "www.example.test", &[a(1)]);
    meta.rtype = Rtype::ANY;
    assert_eq!(fails(meta), codes::RECORD_INVALID);
    let mut ds = rrset(
        &zone,
        "example.test",
        &[RecordData::Ds {
            key_tag: 1,
            algorithm: 13,
            digest_type: 2,
            digest: HexBytes(vec![1; 32]),
        }],
    );
    assert_eq!(fails(ds.clone()), codes::RECORD_INVALID);
    ds.name = name("child.example.test");
    ds.check(apex).expect("DS at a delegation");

    let error = rrset(&zone, "www.example.test", &[soa()])
        .check(apex)
        .expect_err("SOA below the apex");
    let coded = error.to_coded_error();
    assert_eq!(coded.params["name"], "www.example.test");
    assert_eq!(coded.params["type"], "SOA");
}

#[test]
fn node_rules_hold() {
    let zone = zone();
    let apex = &zone.name;
    let www_a = rrset(&zone, "www.example.test", &[a(1)]);
    let www_cname = rrset(&zone, "www.example.test", &[cname("host.example.test")]);
    let error = check_node(apex, [&www_a, &www_cname]).expect_err("CNAME beside data");
    assert_eq!(code(&error), codes::RECORD_CONFLICT);
    let rrsig = rrset(
        &zone,
        "www.example.test",
        &[RecordData::Rrsig {
            type_covered: Rtype::CNAME,
            algorithm: 13,
            labels: 3,
            original_ttl: 300,
            expiration: 2,
            inception: 1,
            key_tag: 1,
            signer: name("example.test"),
            signature: HexBytes(vec![1; 64]),
        }],
    );
    check_node(apex, [&www_cname, &rrsig]).expect("CNAME with its signature");
    assert!(check_node(apex, [&www_a, &www_a]).is_err(), "a type twice");

    let child_ns = rrset(&zone, "child.example.test", &[ns("ns.child.example.test")]);
    let child_glue = rrset(&zone, "child.example.test", &[a(53)]);
    check_node(apex, [&child_ns, &child_glue]).expect("glue at the cut");
    let child_txt = rrset(&zone, "child.example.test", &[RecordData::txt("occluded")]);
    assert_eq!(
        code(&check_node(apex, [&child_ns, &child_txt]).expect_err("data at a cut")),
        codes::RECORD_CONFLICT
    );
    let apex_ns = rrset(&zone, "example.test", &[ns("ns1.example.test")]);
    let apex_txt = rrset(&zone, "example.test", &[RecordData::txt("v=spf1 -all")]);
    check_node(apex, [&apex_ns, &apex_txt]).expect("the apex is no delegation");
    check_node(apex, std::iter::empty()).expect("nothing to check");

    let apex_soa = rrset(&zone, "example.test", &[soa()]);
    check_apex(apex, [&apex_soa, &apex_ns, &www_a]).expect("complete apex");
    assert!(check_apex(apex, [&apex_ns]).is_err());
    assert!(check_apex(apex, [&apex_soa]).is_err());
}

#[test]
fn rrset_keys_order_by_zone_scope_name_and_type() {
    let zone = zone();
    let key = |owner: &str, rtype: Rtype| RrSetKey {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        name: name(owner),
        rtype,
    };
    let apex_ns = key("example.test", Rtype::NS);
    let apex_soa = key("example.test", Rtype::SOA);
    let www = key("www.example.test", Rtype::A);
    assert!(encode_key(&apex_ns) < encode_key(&apex_soa));
    assert!(encode_key(&apex_soa) < encode_key(&www));
    assert_eq!(decode_key::<RrSetKey>(&encode_key(&www)), Ok(www.clone()));
    let set = rrset(&zone, "www.example.test", &[a(1)]);
    assert_eq!(set.key(), www);
    assert_eq!(set.records().expect("records"), vec![a(1)]);
}

#[test]
fn origins_follow_the_ownership_rules() {
    let strict = UpdatePolicy::default();
    let lenient = UpdatePolicy {
        may_replace_ipam: true,
        ..UpdatePolicy::default()
    };
    assert!(Origin::Manual.may_replace(Origin::Ipam, &strict));
    assert!(Origin::Ipam.may_replace(Origin::Ipam, &strict));
    assert!(!Origin::Ipam.may_replace(Origin::Manual, &strict));
    assert!(!Origin::Dynamic.may_replace(Origin::Ipam, &strict));
    assert!(Origin::Dynamic.may_replace(Origin::Ipam, &lenient));
    assert!(Origin::Dynamic.may_replace(Origin::Manual, &strict));
    assert!(!Origin::Dhcp.may_replace(Origin::Ipam, &strict));
    assert!(!Origin::Manual.may_replace(Origin::Transfer, &lenient));
    assert!(!Origin::Ipam.may_replace(Origin::Transfer, &lenient));
    assert!(Origin::Transfer.may_replace(Origin::Manual, &strict));
    assert_eq!(
        serde_json::to_value(Origin::Dynamic).expect("json"),
        "dynamic"
    );
}

#[test]
fn views_validate_their_rules_and_weights() {
    let zone = zone();
    let mut view = View {
        id: ViewId::generate(),
        name: "internal".to_owned(),
        rules: vec![
            MatchRule::ClientSubnet {
                prefixes: vec!["192.0.2.0/24".parse().expect("net")],
            },
            MatchRule::Transport {
                transports: vec![QueryTransport::Udp, QueryTransport::Dot],
            },
            MatchRule::TimeOfDay {
                from_minute: 1320,
                to_minute: 360,
            },
        ],
        scope_map: vec![ScopeWeight {
            zone: zone.id,
            scope: ScopeName::DEFAULT,
            weight: 100,
        }],
        order: 10,
        recursion: None,
        resolution: None,
        description: None,
    };
    view.validate().expect("valid");
    let json = serde_json::to_value(&view).expect("json");
    assert_eq!(json["rules"][0]["test"], "client_subnet");
    assert_eq!(
        serde_json::from_value::<View>(json.clone()).expect("json"),
        view
    );
    assert!(
        json.get("recursion").is_none(),
        "no recursion list, no field"
    );
    view.recursion = Some(AclId::generate());
    let json = serde_json::to_value(&view).expect("json");
    assert_eq!(serde_json::from_value::<View>(json).expect("json"), view);
    view.recursion = None;
    assert!(MatchRule::minute_in_window(1400, 1320, 360));
    assert!(MatchRule::minute_in_window(100, 1320, 360));
    assert!(!MatchRule::minute_in_window(700, 1320, 360));
    assert!(MatchRule::minute_in_window(700, 600, 720));

    view.scope_map[0].weight = 0;
    assert_eq!(
        code(&view.validate().expect_err("weight")),
        codes::VIEW_INVALID
    );
    view.scope_map[0].weight = 1;
    view.rules.push(MatchRule::Qtype { types: Vec::new() });
    assert!(view.validate().is_err());
    view.rules.pop();
    view.name = " internal".to_owned();
    assert!(view.validate().is_err());
}

#[test]
fn forward_rules_validate_their_transport() {
    let mut rule = ForwardRule {
        id: ForwardRuleId::generate(),
        suffix: DnsName::root(),
        upstreams: vec![Upstream {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: None,
            path: None,
        }],
        transport: ForwardTransport::Plain,
        tls_name: None,
        view: None,
        mode: RuleMode::Forward,
        validate: true,
        description: None,
    };
    rule.validate().expect("plain");
    rule.transport = ForwardTransport::Dot;
    assert_eq!(
        code(&rule.validate().expect_err("tls name")),
        codes::FORWARDER_INVALID
    );
    rule.tls_name = Some("resolver.example.net".to_owned());
    rule.validate().expect("dot");
    rule.upstreams[0].path = Some("/dns-query".to_owned());
    assert!(rule.validate().is_err(), "a path is for DoH only");
    rule.transport = ForwardTransport::Doh;
    rule.validate().expect("doh");
    assert_eq!(ForwardTransport::Doh.default_port(), 443);
    rule.upstreams.clear();
    assert!(rule.validate().is_err());
}

#[test]
fn acls_decide_by_the_first_match() {
    let key = name("update-key");
    let acl = Acl {
        id: AclId::generate(),
        name: "updaters".to_owned(),
        entries: vec![
            AclEntry::Prefix {
                prefix: "192.0.2.128/25".parse().expect("net"),
                deny: true,
            },
            AclEntry::Prefix {
                prefix: "192.0.2.0/24".parse().expect("net"),
                deny: false,
            },
            AclEntry::Key {
                name: key.clone(),
                deny: false,
            },
        ],
        description: None,
    };
    let ip = |last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last));
    assert!(acl.allows(ip(10), None));
    assert!(!acl.allows(ip(200), Some(&key)), "the deny comes first");
    assert!(acl.allows("198.51.100.1".parse().expect("ip"), Some(&key)));
    assert!(
        !acl.allows("198.51.100.1".parse().expect("ip"), None),
        "no match refuses"
    );
    let json = serde_json::to_value(&acl).expect("json");
    assert_eq!(json["entries"][2]["kind"], "key");
    assert_eq!(serde_json::from_value::<Acl>(json).expect("json"), acl);
}

#[test]
fn keys_and_lists_round_trip() {
    let key = KeyMeta {
        id: DnsKeyId::generate(),
        name: name("xfr.example.test"),
        algorithm: TsigAlgorithm::default(),
        secret: SecretRef {
            secret: crate::SecretId::generate(),
        },
        description: None,
        created: stamp(),
    };
    let json = serde_json::to_value(&key).expect("json");
    assert_eq!(json["algorithm"], "hmac-sha256");
    assert_eq!(serde_json::from_value::<KeyMeta>(json).expect("json"), key);
    assert_eq!(TsigAlgorithm::HmacSha1.wire_name(), "hmac-sha1");
    assert_eq!(DnssecAlgorithm::Ed25519.number(), 15);

    let mut list = BlockList {
        id: BlockListId::generate(),
        name: "ads".to_owned(),
        kind: ListKind::Block,
        source: ListSource::Url {
            url: "https://lists.example.net/hosts".to_owned(),
        },
        format: ListFormat::Hosts,
        interval_hours: 24,
        action: BlockAction::Redirect {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80)),
        },
        enabled: true,
        exempt: vec!["192.0.2.10/32".parse().expect("prefix")],
        description: None,
    };
    list.validate().expect("valid");
    let json = serde_json::to_value(&list).expect("json");
    assert_eq!(json["kind"], "block");
    assert_eq!(json["exempt"][0], "192.0.2.10/32");
    let mut bare = json.clone();
    bare.as_object_mut().expect("object").remove("kind");
    bare.as_object_mut().expect("object").remove("exempt");
    let read: BlockList = serde_json::from_value(bare).expect("json");
    assert_eq!((read.kind, read.exempt.len()), (ListKind::Block, 0));
    assert_eq!(
        from_cbor::<BlockList>(&to_cbor(&list).expect("cbor")).expect("cbor"),
        list
    );
    assert_eq!(
        serde_json::to_value(&list).expect("json")["action"]["kind"],
        "redirect"
    );
    list.source = ListSource::Url {
        url: "ftp://lists.example.net".to_owned(),
    };
    assert_eq!(
        code(&list.validate().expect_err("url")),
        codes::LIST_INVALID
    );
    list.source = ListSource::Upload;
    list.interval_hours = 0;
    assert!(list.validate().is_err());
}

#[test]
fn scopes_cover_the_dns_kinds() {
    assert_eq!(
        DnsScope::required(Action::Read, ObjectKind::Zone),
        Some(DnsScope::Read)
    );
    assert_eq!(
        DnsScope::required(Action::Update, ObjectKind::DnsView),
        Some(DnsScope::Write)
    );
    assert_eq!(
        DnsScope::required(Action::Execute, ObjectKind::Zone),
        Some(DnsScope::Write)
    );
    assert_eq!(
        DnsScope::required(Action::Read, ObjectKind::DnsKey),
        Some(DnsScope::Keys)
    );
    assert_eq!(
        DnsScope::required(Action::Create, ObjectKind::DnsKey),
        Some(DnsScope::Keys)
    );
    assert_eq!(
        DnsScope::required(Action::Administer, ObjectKind::Zone),
        None
    );
    assert_eq!(DnsScope::required(Action::Read, ObjectKind::Prefix), None);
    for kind in OBJECT_KINDS {
        assert!(DnsScope::required(Action::Read, kind).is_some(), "{kind}");
        assert_eq!(ObjectRef::from(ZoneId::generate()).kind, ObjectKind::Zone);
    }
    let names: Vec<&str> = DnsScope::ALL.iter().map(|scope| scope.as_str()).collect();
    assert_eq!(names, ["dns.read", "dns.write", "dns.keys"]);
    assert_eq!(
        serde_json::to_value(DnsScope::Keys).expect("json"),
        "dns.keys"
    );
}

#[test]
fn tables_codes_and_actions_are_in_the_namespace() {
    for table in tables::all() {
        assert_eq!(table.namespace(), "dns", "{table}");
        assert!(!table.is_secret_bearing(), "{table}");
    }
    assert_eq!(tables::RRSETS.name().as_str(), "dns.rrsets");
    assert_eq!(tables::KEYS_META.name().as_str(), "dns.keys.meta");
    let node: Vec<&str> = tables::NODE_TABLES.iter().map(TableName::as_str).collect();
    let all: Vec<&str> = tables::all().iter().map(|table| table.as_str()).collect();
    let without_sign_state: Vec<&str> = all
        .iter()
        .copied()
        .filter(|table| *table != "dns.sign_state")
        .collect();
    assert_eq!(node, without_sign_state);
    assert!(!node.contains(&"dns.sign_state"));
    // WP10.0: the trust anchors reach a Phase 5 node.
    for table in ["dns.trust_anchors", "dns.ntas", "dns.ntas.by_zone"] {
        assert!(node.contains(&table), "{table}");
    }
    for finding in findings::ALL {
        assert!(
            finding.starts_with("dns.") && is_valid_name(finding),
            "{finding}"
        );
    }
    for code in codes::ALL {
        assert!(code.starts_with("dns.") && is_valid_name(code), "{code}");
    }
    for required in [
        "dns.zone.not_found",
        "dns.zone.exists",
        "dns.record.invalid",
        "dns.record.conflict",
        "dns.key.not_found",
        "dns.update.refused",
        "dns.transfer.refused",
        "dns.module.disabled",
    ] {
        assert!(codes::ALL.contains(&required), "{required}");
    }
    for prefix in [
        "dns.zone.",
        "dns.record.",
        "dns.key.",
        "dns.update.",
        "dns.view.",
        "dns.list.",
    ] {
        assert!(
            audit::ALL
                .iter()
                .any(|action| action.as_str().starts_with(prefix)),
            "{prefix}"
        );
    }
    assert_eq!(TOPIC, "dns");
    assert_eq!([TSIG_PURPOSE, DNSSEC_PURPOSE], ["tsig", "dnssec"]);
}

use crate::names::TableName;

#[test]
fn addresses_in_tagged_enums_round_trip_in_cbor_and_json() {
    let acl = Acl {
        id: AclId::generate(),
        name: "secondaries".to_owned(),
        entries: vec![
            AclEntry::Prefix {
                prefix: "192.0.2.0/24".parse().expect("prefix"),
                deny: false,
            },
            AclEntry::Prefix {
                prefix: "2001:db8::/32".parse().expect("prefix"),
                deny: true,
            },
        ],
        description: None,
    };
    assert_eq!(
        from_cbor::<Acl>(&to_cbor(&acl).expect("cbor")).expect("cbor"),
        acl
    );
    let json = serde_json::to_value(&acl).expect("json");
    assert_eq!(json["entries"][0]["prefix"], "192.0.2.0/24");
    assert_eq!(serde_json::from_value::<Acl>(json).expect("json"), acl);

    let rules = vec![
        MatchRule::ClientSubnet {
            prefixes: vec!["198.51.100.0/24".parse().expect("prefix")],
        },
        MatchRule::Interface {
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
        },
    ];
    assert_eq!(
        from_cbor::<Vec<MatchRule>>(&to_cbor(&rules).expect("cbor")).expect("cbor"),
        rules
    );
    let redirect = BlockAction::Redirect {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80)),
    };
    assert_eq!(
        from_cbor::<BlockAction>(&to_cbor(&redirect).expect("cbor")).expect("cbor"),
        redirect
    );
    assert_eq!(
        serde_json::to_value(&redirect).expect("json")["address"],
        "192.0.2.80"
    );
}
