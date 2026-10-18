use std::net::Ipv4Addr;

use tenko_core::{
    Principal,
    dns::{RecordData, SerialPolicy, SoaDefaults, TransferPolicy, UpdatePolicy, ZoneScope},
};

use super::*;
use crate::xfr::inbound::Step;

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn stamp() -> Stamp {
    Stamp::new(Timestamp::now(), Principal::system(SystemComponent::Dns))
}

fn secondary() -> Zone {
    Zone {
        id: ZoneId::generate(),
        name: name("example.test"),
        kind: ZoneKind::Secondary,
        tenant: None,
        scopes: vec![ZoneScope::default_scope()],
        serial: SerialPolicy::default(),
        soa: SoaDefaults::new(name("ns.example.test"), name("hostmaster.example.test")),
        transfer: TransferPolicy::default(),
        update: UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        reverse_of: None,
        catalog: false,
        description: None,
        created: stamp(),
        updated: stamp(),
    }
}

fn soa(serial: u32) -> RecordData {
    RecordData::Soa {
        mname: name("ns.example.test"),
        rname: name("hostmaster.example.test"),
        serial,
        refresh: 60,
        retry: 10,
        expire: 3600,
        minimum: 5,
    }
}

fn record(owner: &str, ttl: u32, data: &RecordData) -> Record {
    Record {
        name: name(owner),
        rtype: data.rtype(),
        class: 1,
        ttl,
        rdata: Rdata::from_data(data),
    }
}

fn a(last: u8) -> RecordData {
    RecordData::A {
        address: Ipv4Addr::new(192, 0, 2, last),
    }
}

fn full(serial: u32, hosts: &[u8]) -> Fetched {
    let mut records = vec![
        record("example.test", 60, &soa(serial)),
        record(
            "example.test",
            60,
            &RecordData::Ns {
                host: name("ns.example.test"),
            },
        ),
    ];
    for host in hosts {
        records.push(record("www.example.test", 300, &a(*host)));
    }
    Fetched::Full { records, bytes: 0 }
}

fn copy_of(zone: &Zone, fetched: &Fetched) -> BTreeMap<(DnsName, Rtype), (RrSet, Revision)> {
    target(zone, &BTreeMap::new(), fetched, &stamp())
        .expect("a copy")
        .into_iter()
        .map(|(key, set)| (key, (set, Revision(1))))
        .collect()
}

#[test]
fn an_axfr_becomes_rrsets_of_the_origin_transfer() {
    let zone = secondary();
    let after = target(&zone, &BTreeMap::new(), &full(7, &[1, 2, 2]), &stamp()).expect("target");
    assert_eq!(after.len(), 3, "SOA, NS and one A set");
    let www = &after[&(name("www.example.test"), Rtype::A)];
    assert_eq!(www.rdata.len(), 2, "a duplicate record counts once");
    assert!(after.values().all(|set| set.origin == Origin::Transfer));
    assert_eq!(
        super::super::soa_serial(&after[&(name("example.test"), Rtype::SOA)]),
        Some(7)
    );
    // A transfer without the apex SOA is refused; a record outside the zone is left out.
    let Fetched::Full { mut records, .. } = full(7, &[1]) else {
        unreachable!()
    };
    records.push(record("www.other.test", 300, &a(9)));
    let outside = target(
        &zone,
        &BTreeMap::new(),
        &Fetched::Full {
            records: records.clone(),
            bytes: 0,
        },
        &stamp(),
    )
    .expect("target");
    assert!(!outside.contains_key(&(name("www.other.test"), Rtype::A)));
    records.remove(0);
    let error = target(
        &zone,
        &BTreeMap::new(),
        &Fetched::Full { records, bytes: 0 },
        &stamp(),
    )
    .expect_err("no SOA");
    assert_eq!(error.code, codes::TRANSFER_FAILED);
}

#[test]
fn an_ixfr_applies_its_steps_to_the_copy() {
    let zone = secondary();
    let before = copy_of(&zone, &full(7, &[1, 2]));
    let delta = Fetched::Delta {
        steps: vec![
            Step {
                removed: vec![
                    record("example.test", 60, &soa(7)),
                    record("www.example.test", 300, &a(1)),
                ],
                added: vec![
                    record("example.test", 60, &soa(8)),
                    record("mail.example.test", 300, &a(25)),
                ],
            },
            Step {
                removed: vec![record("example.test", 60, &soa(8))],
                added: vec![
                    record("example.test", 60, &soa(9)),
                    record("www.example.test", 300, &a(3)),
                ],
            },
        ],
        soa: record("example.test", 60, &soa(9)),
        bytes: 0,
    };
    let after = target(&zone, &before, &delta, &stamp()).expect("target");
    let www: Vec<&Rdata> = after[&(name("www.example.test"), Rtype::A)]
        .rdata
        .iter()
        .collect();
    assert_eq!(
        www,
        vec![&Rdata::from_data(&a(2)), &Rdata::from_data(&a(3))]
    );
    assert!(after.contains_key(&(name("mail.example.test"), Rtype::A)));
    assert_eq!(
        super::super::soa_serial(&after[&(name("example.test"), Rtype::SOA)]),
        Some(9)
    );
    // The diff holds the changed sets only: the SOA, www and mail.
    let changes = diff(&before, &after);
    assert_eq!(changes.len(), 3);
    assert!(changes.iter().any(|(old, new)| {
        old.is_none()
            && new
                .as_ref()
                .is_some_and(|set| set.name == name("mail.example.test"))
    }));
}

#[test]
fn removing_the_last_record_drops_the_rrset() {
    let zone = secondary();
    let before = copy_of(&zone, &full(7, &[1]));
    let delta = Fetched::Delta {
        steps: vec![Step {
            removed: vec![
                record("example.test", 60, &soa(7)),
                record("www.example.test", 300, &a(1)),
            ],
            added: vec![record("example.test", 60, &soa(8))],
        }],
        soa: record("example.test", 60, &soa(8)),
        bytes: 0,
    };
    let after = target(&zone, &before, &delta, &stamp()).expect("target");
    assert!(!after.contains_key(&(name("www.example.test"), Rtype::A)));
    let changes = diff(&before, &after);
    assert!(
        changes.iter().any(|(old, new)| new.is_none()
            && old.as_ref().is_some_and(|(set, _)| set.rtype == Rtype::A))
    );
}

#[test]
fn a_secondary_zone_is_read_only_and_a_primary_is_not() {
    let mut zone = secondary();
    let error = check_writable(&zone).expect_err("read-only");
    assert!(error.is(codes::ZONE_SECONDARY), "{error:?}");
    assert_eq!(error.coded().status, 409);
    zone.kind = ZoneKind::Primary;
    assert!(check_writable(&zone).is_ok());
}

#[test]
fn the_soa_timers_of_a_copy_read_from_its_soa() {
    let timers = Timers::of(&Rdata::from_data(&soa(1)));
    assert_eq!(
        (timers.refresh, timers.retry, timers.expire),
        (60, 10, 3600)
    );
    let fallback = Timers::of(&Rdata::from_data(&a(1)));
    assert_eq!(fallback.refresh, Timers::DEFAULT.refresh);
    let at = Timestamp::now();
    assert_eq!(after(at, 60).saturating_since(at), Duration::from_secs(60));
}

#[test]
fn xot_on_the_default_port_goes_to_853() {
    let mut server = PrimaryServer {
        address: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        port: 53,
        key: None,
        xot: true,
        tls_name: None,
    };
    assert_eq!(primary_address(&server).port(), 853);
    server.port = 8530;
    assert_eq!(primary_address(&server).port(), 8530);
    server.xot = false;
    server.port = 53;
    assert_eq!(primary_address(&server).port(), 53);
}
