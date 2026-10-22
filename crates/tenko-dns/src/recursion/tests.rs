//! The oracles of the recursion contracts: what they can script, and a small iterative
//! walk over them (root, TLD, zone) to show that they compose without a socket.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use tenko_core::{
    Timestamp,
    dns::{DnsName, NegativeTrustAnchor, NtaId, RecordData, Rtype, SecurityState},
    principal::{Principal, SystemComponent},
};

use super::*;
use crate::{cache::CacheKey, wire};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
}

fn ns(host: &str) -> RecordData {
    RecordData::Ns { host: name(host) }
}

fn a(last: u8) -> RecordData {
    RecordData::A {
        address: Ipv4Addr::new(192, 0, 2, last),
    }
}

fn soa(zone: &str) -> RecordData {
    RecordData::Soa {
        mname: name(&format!("ns.{zone}")),
        rname: name(&format!("hostmaster.{zone}")),
        serial: 1,
        refresh: 3600,
        retry: 900,
        expire: 1_209_600,
        minimum: 60,
    }
}

const ROOT: u8 = 10;
const TLD: u8 = 20;
const LEAF: u8 = 30;

/// The lab's shape: a root, the TLD `test`, the zone `example.test` with a wildcard and a
/// CNAME.
fn lab() -> MemAuthority {
    let root = MemZone::new(DnsName::root())
        .record(DnsName::root(), 86_400, ns("a.root.test"))
        .record(DnsName::root(), 86_400, soa("root.test"))
        .record(name("test"), 3600, ns("ns.test"))
        .record(
            name("ns.test"),
            3600,
            RecordData::A {
                address: Ipv4Addr::new(203, 0, 113, TLD),
            },
        );
    let tld = MemZone::new(name("test"))
        .record(name("test"), 3600, ns("ns.test"))
        .record(name("test"), 3600, soa("test"))
        .record(name("example.test"), 3600, ns("ns.example.test"))
        .record(
            name("ns.example.test"),
            3600,
            RecordData::A {
                address: Ipv4Addr::new(203, 0, 113, LEAF),
            },
        );
    let leaf = MemZone::new(name("example.test"))
        .record(name("example.test"), 3600, ns("ns.example.test"))
        .record(name("example.test"), 3600, soa("example.test"))
        .record(name("www.example.test"), 300, a(1))
        .record(name("*.wild.example.test"), 300, a(2))
        .record(
            name("alias.example.test"),
            300,
            RecordData::Cname {
                target: name("www.example.test"),
            },
        );
    MemAuthority::new()
        .serve(v4(ROOT), root)
        .serve(v4(TLD), tld)
        .serve(v4(LEAF), leaf)
}

fn query(server: u8, qname: &[u8], qtype: u16, edns: bool) -> AuthorityQuery<'_> {
    AuthorityQuery {
        server: SocketAddr::new(v4(server), 53),
        qname,
        qtype,
        qclass: 1,
        edns,
        tcp: false,
        mix_case: false,
        client_cookie: None,
        server_cookie: None,
        fresh_port: true,
        deadline: Instant::now() + Duration::from_secs(1),
    }
}

async fn ask(
    authority: &MemAuthority,
    server: u8,
    qname: &str,
    qtype: u16,
) -> (Result<Exchange, AuthorityError>, Vec<u8>) {
    let wire = name(qname).to_wire();
    let mut out = Vec::new();
    let result = authority
        .exchange(&query(server, &wire, qtype, true), &mut out)
        .await;
    (result, out)
}

/// The records of a message: (section, owner, type).
fn records(message: &[u8]) -> Vec<(usize, DnsName, u16)> {
    let header = wire::parse_header(message).expect("header");
    let mut pos = wire::questions_end(message, 1).expect("question");
    let counts = [header.ancount, header.nscount, header.arcount];
    let mut out = Vec::new();
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            let record = wire::read_record(message, pos).expect("record");
            if record.rtype != 41 {
                let (owner, _) = DnsName::from_wire(&message[record.start..]).expect("owner");
                out.push((section, owner, record.rtype));
            }
            pos = record.end();
        }
    }
    out
}

#[tokio::test]
async fn a_scripted_root_refers_and_the_zone_answers() {
    let lab = lab();
    let (result, answer) = ask(&lab, ROOT, "www.example.test", 1).await;
    let exchange = result.expect("an answer");
    assert_eq!(exchange.transport, AuthorityTransport::Udp);
    let header = wire::parse_header(&answer).expect("header");
    assert!(!header.aa && header.rcode == 0, "a referral");
    assert_eq!(
        records(&answer),
        [(1, name("test"), 2), (2, name("ns.test"), 1)]
    );

    let (_, answer) = ask(&lab, LEAF, "www.example.test", 1).await;
    let header = wire::parse_header(&answer).expect("header");
    assert!(header.aa);
    assert_eq!(records(&answer), [(0, name("www.example.test"), 1)]);

    let (_, answer) = ask(&lab, LEAF, "nothing.example.test", 1).await;
    assert_eq!(wire::parse_header(&answer).expect("header").rcode, 3);
    assert_eq!(records(&answer), [(1, name("example.test"), 6)]);

    let (_, answer) = ask(&lab, LEAF, "www.example.test", 28).await;
    let header = wire::parse_header(&answer).expect("header");
    assert_eq!((header.rcode, header.ancount), (0, 0), "NODATA");

    let (_, answer) = ask(&lab, LEAF, "any.wild.example.test", 1).await;
    assert_eq!(records(&answer), [(0, name("any.wild.example.test"), 1)]);

    let (_, answer) = ask(&lab, LEAF, "alias.example.test", 1).await;
    assert_eq!(records(&answer), [(0, name("alias.example.test"), 5)]);

    let (_, answer) = ask(&lab, LEAF, "www.example.net", 1).await;
    assert_eq!(wire::parse_header(&answer).expect("header").rcode, 5);
    assert_eq!(lab.asked_of(v4(LEAF)), 6);
    assert_eq!(lab.asked()[0].qname, name("www.example.test"));
}

#[tokio::test]
async fn quirks_follow_the_ladder_or_fail() {
    let lame = Quirks {
        refuse: true,
        ..Quirks::default()
    };
    let lab = lab()
        .quirks(
            v4(40),
            Quirks {
                silent: true,
                ..Quirks::default()
            },
        )
        .quirks(
            v4(41),
            Quirks {
                formerr_on_edns: true,
                ..Quirks::default()
            },
        )
        .quirks(
            v4(42),
            Quirks {
                truncate_udp: true,
                ..Quirks::default()
            },
        )
        .quirks(v4(43), lame)
        .quirks(
            v4(44),
            Quirks {
                case_broken: true,
                cookie: ServerCookie::new(&[9; 16]),
                ..Quirks::default()
            },
        );
    assert_eq!(
        ask(&lab, 40, "www.example.test", 1).await.0,
        Err(AuthorityError::Timeout)
    );
    let exchange = ask(&lab, 41, "www.example.test", 1)
        .await
        .0
        .expect("answer");
    assert!(!exchange.edns, "asked again without EDNS");
    let exchange = ask(&lab, 42, "www.example.test", 1)
        .await
        .0
        .expect("answer");
    assert_eq!(exchange.transport, AuthorityTransport::Tcp);
    assert!(exchange.truncated);
    let (_, answer) = ask(&lab, 43, "www.example.test", 1).await;
    assert_eq!(wire::parse_header(&answer).expect("header").rcode, 5);
    assert!(matches!(
        ask(&lab, 99, "www.example.test", 1).await.0,
        Err(AuthorityError::Unreachable(_))
    ));
    let mixed = b"\x03WwW\x07example\x04test\x00";
    let mut out = Vec::new();
    let mut asking = query(44, mixed, 1, true);
    asking.mix_case = true;
    assert_eq!(
        lab.exchange(&asking, &mut out).await,
        Err(AuthorityError::Malformed("0x20"))
    );
    asking.mix_case = false;
    let exchange = lab.exchange(&asking, &mut out).await.expect("lower case");
    assert_eq!(
        exchange.server_cookie.map(|cookie| cookie.as_bytes().len()),
        Some(16)
    );
    // The ladder shows in the log: FORMERR then without EDNS, UDP then TCP.
    let ladder: Vec<(u8, bool, AuthorityTransport)> = lab
        .asked()
        .iter()
        .filter_map(|asked| match asked.server {
            IpAddr::V4(address) if [41, 42].contains(&address.octets()[3]) => {
                Some((address.octets()[3], asked.edns, asked.transport))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        ladder,
        [
            (41, true, AuthorityTransport::Udp),
            (41, false, AuthorityTransport::Udp),
            (42, true, AuthorityTransport::Udp),
            (42, true, AuthorityTransport::Tcp),
        ]
    );
}

#[tokio::test]
async fn the_oracles_compose_into_an_iterative_walk() {
    let lab = lab();
    let infra = MemInfra::new(InfraBounds::HOME);
    let now = Instant::now();
    // Priming from the hints.
    infra.put_cut(&DnsName::root(), vec![name("a.root.test")], 86_400, now);
    infra.put_addresses(
        &name("a.root.test"),
        &[(v4(ROOT), 86_400)],
        AddressOrigin::Hints,
        now,
    );
    let qname = name("www.example.test");
    let mut sent = 0;
    let answer = loop {
        let cut = infra.closest_cut(&qname, now).expect("a cut");
        let server = infra
            .name_server(&cut.servers[0], now)
            .expect("an address")
            .addresses[0]
            .address;
        let IpAddr::V4(server) = server else {
            panic!("v4 only")
        };
        let (result, answer) = ask(&lab, server.octets()[3], qname.as_str(), 1).await;
        result.expect("answered");
        sent += 1;
        let header = wire::parse_header(&answer).expect("header");
        if header.aa {
            break answer;
        }
        // A referral: the NS set and the in-domain glue.
        let found = records(&answer);
        let (_, zone, _) = found
            .iter()
            .find(|(section, _, _)| *section == 1)
            .expect("NS");
        let hosts: Vec<DnsName> = vec![if zone.as_str() == "test" {
            name("ns.test")
        } else {
            name("ns.example.test")
        }];
        infra.put_cut(zone, hosts.clone(), 3600, now);
        let glue = if zone.as_str() == "test" { TLD } else { LEAF };
        infra.put_addresses(&hosts[0], &[(v4(glue), 3600)], AddressOrigin::Glue, now);
        assert!(sent < 4, "the walk ends");
    };
    assert_eq!(sent, 3, "root, TLD, zone");
    assert_eq!(records(&answer), [(0, qname.clone(), 1)]);
    assert_eq!(
        infra.closest_cut(&qname, now).expect("cut").zone,
        name("example.test")
    );
    assert_eq!(infra.sizes().cuts, 3);
}

#[test]
fn the_infrastructure_cache_keeps_its_rules() {
    let infra = MemInfra::new(InfraBounds {
        cuts: 2,
        servers: 2,
        ttl: Duration::from_secs(900),
    });
    let now = Instant::now();
    let first = infra.put_cut(&name("test"), vec![name("ns.test")], 60, now);
    assert_eq!(
        infra.put_cut(&name("test"), vec![name("ns2.test")], 60, now),
        first
    );
    infra.set_ds(
        &name("test"),
        DsState::Insecure {
            until: now + Duration::from_secs(30),
        },
    );
    let cut = infra.cut(&name("test"), now).expect("cut");
    assert_eq!((cut.servers.len(), cut.ds.as_str()), (1, "insecure"));
    assert_eq!(
        infra
            .cut(&name("test"), now + Duration::from_secs(31))
            .expect("cut")
            .ds,
        DsState::Unknown
    );
    assert!(
        infra
            .cut(&name("test"), now + Duration::from_secs(61))
            .is_none()
    );
    infra.put_cut(
        &name("example.test"),
        vec![name("ns.example.test")],
        60,
        now,
    );
    infra.put_cut(&name("other.test"), vec![name("ns.other.test")], 60, now);
    assert_eq!(infra.sizes().cuts, 2, "bounded");
    assert_eq!(
        infra
            .closest_cut(&name("www.example.test"), now)
            .expect("cut")
            .zone,
        name("example.test")
    );
    assert_eq!(
        infra
            .list(Some(&name("test")), None, 10, now)
            .iter()
            .map(|cut| cut.zone.as_str().to_owned())
            .collect::<Vec<_>>(),
        ["example.test", "other.test"]
    );

    // Glue never replaces an authoritative address; an authoritative one replaces glue.
    let host = name("ns.example.test");
    infra.put_addresses(&host, &[(v4(1), 60)], AddressOrigin::Authoritative, now);
    infra.put_addresses(&host, &[(v4(2), 60)], AddressOrigin::Glue, now);
    let known = infra.name_server(&host, now).expect("addresses");
    assert_eq!(known.addresses.len(), 1);
    assert_eq!(known.addresses[0].address, v4(1));
    let later = now + Duration::from_secs(61);
    infra.put_addresses(&host, &[(v4(2), 60)], AddressOrigin::SiblingGlue, later);
    assert_eq!(
        infra
            .name_server(&host, later)
            .expect("addresses")
            .addresses[0]
            .origin,
        AddressOrigin::SiblingGlue
    );

    infra.update_server(v4(1), now, &mut |state| {
        state.edns = infra::EdnsSupport::No;
        state
            .lame
            .push((name("example.test"), now + Duration::from_secs(10)));
    });
    let state = infra.server(v4(1), now);
    assert_eq!(state.edns, infra::EdnsSupport::No);
    assert!(state.is_lame(&name("example.test"), now));
    assert!(!state.is_lame(&name("example.test"), now + Duration::from_secs(11)));
    assert_eq!(infra.server(v4(9), now), ServerState::unknown(v4(9)));
    assert!(infra.flush(Some(&name("example.test"))) >= 1);
    assert!(infra.flush(None) >= 1);
    assert_eq!(infra.sizes(), InfraSizes::default());
}

#[tokio::test]
async fn the_anchors_start_from_the_shipped_file() {
    let now: Timestamp = "2026-10-22T00:00:00Z".parse().expect("time");
    let anchors = MemAnchors::shipped("0.0.2", now);
    let root = anchors
        .closest(&name("www.example.test"))
        .expect("the root");
    assert!(root.zone.is_root());
    let tags: Vec<u16> = root.keys.iter().map(|key| key.key_tag).collect();
    assert_eq!(tags, [20326, 38696], "the keys valid in 2026");
    root.validate(false).expect("a valid row");
    let generation = anchors.generation();
    anchors.add_negative(NegativeTrustAnchor {
        id: NtaId::generate(),
        zone: name("bogus.example.test"),
        expires_at: "2026-10-23T00:00:00Z".parse().expect("time"),
        reason: "the lab's broken zone".to_owned(),
        created_by: Principal::system(SystemComponent::Dns),
        created_at: now,
    });
    assert!(anchors.generation() > generation);
    assert!(
        anchors
            .negative(&name("www.bogus.example.test"), now)
            .is_some()
    );
    assert!(anchors.negative(&name("www.example.test"), now).is_none());
    assert_eq!(
        anchors.dnskeys(&DnsName::root()).await,
        Err(AnchorError::Unreachable)
    );
    anchors.script_dnskeys(
        DnsName::root(),
        Ok(DnskeySet {
            keys: vec![vec![1, 1, 3, 8, 7]],
            state: SecurityState::Secure,
            ttl: 172_800,
            original_ttl: 172_800,
            signature_expiry: None,
        }),
    );
    assert_eq!(
        anchors
            .dnskeys(&DnsName::root())
            .await
            .expect("scripted")
            .keys
            .len(),
        1
    );
}

#[test]
fn failures_hold_five_seconds_doubling_to_the_bound() {
    let failures = MemFailures::new(Duration::from_secs(20));
    let key = CacheKey::new(None, &name("www.example.test").to_wire(), 1, 1);
    let now = Instant::now();
    let cause = FailureCause::Budget(BudgetBound::Queries);
    assert_eq!(failures.record(&key, cause, now), Duration::from_secs(5));
    assert_eq!(failures.lookup(&key, now), Some(cause));
    assert_eq!(
        cause.ede(),
        tenko_core::dns::ExtendedError::NO_REACHABLE_AUTHORITY
    );
    let mut at = now;
    for expected in [10, 20, 20] {
        at += Duration::from_secs(6);
        assert_eq!(
            failures.record(&key, cause, at),
            Duration::from_secs(expected)
        );
    }
    assert_eq!(failures.flush(Some(&name("example.test").to_wire())), 1);
    assert!(failures.is_empty());
    let later = now + Duration::from_secs(3600);
    assert_eq!(
        failures.record(&key, cause, later),
        Duration::from_secs(5),
        "a fresh start"
    );
}

#[test]
fn the_budget_and_the_local_zones_are_well_formed() {
    let budget = WorkBudget::default();
    assert_eq!((budget.queries, budget.restarts, budget.depth), (32, 8, 6));
    assert_eq!(
        (0..6)
            .map(|depth| budget.lookups_at(depth))
            .collect::<Vec<_>>(),
        [3, 2, 1, 0, 0, 0]
    );
    for (zone, _) in LOCAL_ZONES {
        DnsName::new(zone).expect("a name");
    }
    assert_eq!(RecursionSettings::default().budget, WorkBudget::DEFAULT);
    assert_eq!(Rtype::DS.0, 43);
}
