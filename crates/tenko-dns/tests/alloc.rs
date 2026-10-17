//! The no-allocation rule of the query path (ADR 0009, risk R39), as a test: a counting
//! global allocator (`stats_alloc`, the approach of the Spike B bench) wraps the system
//! allocator, and `Codec::parse`, `Codec::build` and `Index::lookup` must not allocate once
//! their buffers have capacity; nor must the whole path of a query through the responder,
//! the authoritative resolver, the production index and the codec, with metrics and
//! cookies on. The first test proves that the counter sees an allocation, so a pass means
//! something.
//!
//! The allocator counts every thread of the process, so the file has one test that runs
//! the measured sections one after another: no other test of the binary runs beside them.

use std::{alloc::System, hint::black_box, net::Ipv4Addr, time::Instant};

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_core::{
    Revision,
    dns::{
        DnsName, Origin, QueryTransport, Rdata, RecordData, RrSet, ScopeName, SoaDefaults, Zone,
        ZoneId, ZoneKind,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
};
use tenko_dns::{
    AnswerBuf, Codec, DnsData, DomainCodec, Index, Lookup, MemIndex, NameBuf, Request,
    authoritative::Authoritative,
    catalog::{Catalog, CatalogHandle},
    codec::{Owner, Section},
    cookie::CookieSecret,
    index::DefaultScopes,
    respond::{Clock, Conn, Reply, Responder, Scratch},
    wire::{self, MAX_MESSAGE_LEN, TsigRecord},
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Runs `f` `rounds` times after one warm-up round and returns the allocations, the
/// reallocations and the bytes allocated during the measured rounds.
fn measure(rounds: usize, mut f: impl FnMut()) -> (usize, usize, usize) {
    f();
    let region = Region::new(GLOBAL);
    for _ in 0..rounds {
        f();
    }
    let stats = region.change();
    (
        stats.allocations,
        stats.reallocations,
        stats.bytes_allocated,
    )
}

fn the_counter_sees_a_deliberate_allocation() {
    let (allocations, _, bytes) = measure(10, || {
        let v: Vec<u8> = black_box(Vec::with_capacity(64));
        black_box(&v);
    });
    assert_eq!(allocations, 10);
    assert!(bytes >= 640);
}

fn soa_rdata() -> Vec<u8> {
    let mut data = b"\x03ns1\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00".to_vec();
    for value in [1u32, 3600, 900, 1_209_600, 300] {
        data.extend_from_slice(&value.to_be_bytes());
    }
    data
}

fn queries() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (name, qtype, edns) in [
        ("www.example.test", 1, Some(1232)),
        ("WWW.Example.TEST", 1, None),
        ("nohost.example.test", 28, Some(4096)),
        ("example.test", 6, Some(512)),
    ] {
        let mut query = Vec::new();
        wire::write_query(&mut query, 0x1234, name, qtype, edns);
        out.push(query);
    }
    // A signed query.
    let mut signed = Vec::new();
    wire::write_query(&mut signed, 7, "example.test", 252, None);
    let tsig = TsigRecord {
        key: b"\x07xfr-key\x00",
        algorithm: b"\x0bhmac-sha256\x00",
        time_signed: 1_790_000_000,
        fudge: 300,
        mac: &[1; 32],
        original_id: 7,
        error: 0,
        other: &[],
    };
    assert!(wire::append_tsig(&mut signed, &tsig, MAX_MESSAGE_LEN));
    out.push(signed);
    out
}

fn parse_and_build_do_not_allocate() {
    let codec = DomainCodec::new();
    let queries = queries();
    let mut request = Request::default();
    let mut out = Vec::with_capacity(MAX_MESSAGE_LEN);
    let mut answer = AnswerBuf::with_capacity(64, 16_384);
    let soa = soa_rdata();
    let mut cookie = [0u8; 24];
    cookie[0] = 1;
    let (allocations, reallocations, bytes) = measure(1000, || {
        for query in &queries {
            let parsed = codec.parse(query, &mut request).expect("parse");
            answer.clear();
            answer.authoritative = true;
            answer
                .push(Section::Answer, Owner::Qname, 1, 300, &[192, 0, 2, 1])
                .expect("push");
            answer
                .push(
                    Section::Authority,
                    Owner::Name(b"\x07example\x04test\x00"),
                    6,
                    300,
                    &soa,
                )
                .expect("push");
            answer
                .push(
                    Section::Additional,
                    Owner::Name(b"\x03ns1\x07example\x04test\x00"),
                    1,
                    300,
                    &[192, 0, 2, 53],
                )
                .expect("push");
            answer.set_cookie(&cookie).expect("cookie");
            answer.set_extended_error(15, "blocked").expect("ede");
            let limit = request.max_udp_len();
            codec
                .build(&parsed, &request, &answer, limit, &mut out)
                .expect("build");
            black_box(&out);
        }
    });
    assert_eq!(
        (allocations, reallocations, bytes),
        (0, 0, 0),
        "the codec allocated on the query path"
    );
}

fn truncation_and_formerr_do_not_allocate() {
    let codec = DomainCodec::new();
    let queries = queries();
    let mut request = Request::default();
    let mut out = Vec::with_capacity(MAX_MESSAGE_LEN);
    let mut answer = AnswerBuf::with_capacity(128, 16_384);
    let (allocations, reallocations, _) = measure(200, || {
        answer.clear();
        for last in 0..100u8 {
            answer
                .push(Section::Answer, Owner::Qname, 1, 300, &[192, 0, 2, last])
                .expect("push");
        }
        let parsed = codec.parse(&queries[1], &mut request).expect("parse");
        let outcome = codec
            .build(&parsed, &request, &answer, 512, &mut out)
            .expect("build");
        assert!(outcome.truncated);
        let mut broken = [0u8; 20];
        broken[..12].copy_from_slice(&queries[1][..12]);
        // A 63-octet label that runs past the end.
        broken[12] = 63;
        assert!(codec.parse(&broken, &mut request).is_err());
        assert!(wire::write_formerr(&broken, &mut out));
    });
    assert_eq!((allocations, reallocations), (0, 0));
}

fn stamp() -> Stamp {
    Stamp::new(
        "2026-10-17T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Dns),
    )
}

fn index_lookups_do_not_allocate() {
    let apex = DnsName::new("example.test").expect("name");
    let zone = Zone {
        id: ZoneId::generate(),
        name: apex.clone(),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: vec![tenko_core::dns::ZoneScope::default_scope()],
        serial: tenko_core::dns::SerialPolicy::default(),
        soa: SoaDefaults::new(
            DnsName::new("ns1.example.test").expect("name"),
            DnsName::new("hostmaster.example.test").expect("name"),
        ),
        transfer: tenko_core::dns::TransferPolicy::default(),
        update: tenko_core::dns::UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        reverse_of: None,
        description: None,
        created: stamp(),
        updated: stamp(),
    };
    let mut image = DnsData::at(Revision(1));
    let mut add = |owner: &str, data: RecordData| {
        let set = RrSet {
            zone: zone.id,
            scope: ScopeName::DEFAULT,
            name: DnsName::new(owner).expect("name"),
            rtype: data.rtype(),
            ttl: 300,
            rdata: vec![Rdata::from_data(&data)],
            origin: Origin::Manual,
            key: None,
            updated: stamp(),
        };
        image.rrsets.insert(set.key(), set);
    };
    add(
        "example.test",
        RecordData::Soa {
            mname: DnsName::new("ns1.example.test").expect("name"),
            rname: DnsName::new("hostmaster.example.test").expect("name"),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 1_209_600,
            minimum: 300,
        },
    );
    add(
        "www.example.test",
        RecordData::A {
            address: Ipv4Addr::new(192, 0, 2, 1),
        },
    );
    add(
        "*.example.test",
        RecordData::A {
            address: Ipv4Addr::new(192, 0, 2, 9),
        },
    );
    image.zones.insert(zone.id, zone);
    let index = MemIndex::build(&image);
    let names: Vec<NameBuf> = [
        "www.example.test",
        "other.example.test",
        "deep.www.example.test",
        "example.org",
    ]
    .iter()
    .map(|text| NameBuf::from_dns_name(&DnsName::new(text).expect("name")))
    .collect();
    let (allocations, reallocations, _) = measure(1000, || {
        for name in &names {
            let lookup = index.lookup(&DefaultScopes, name.as_wire(), tenko_core::dns::Rtype::A);
            black_box(matches!(lookup, Lookup::Answer { .. }));
        }
    });
    assert_eq!(
        (allocations, reallocations),
        (0, 0),
        "the index allocated on the query path"
    );
}

fn zone_row() -> Zone {
    Zone {
        id: ZoneId::generate(),
        name: DnsName::new("example.test").expect("name"),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: vec![tenko_core::dns::ZoneScope::default_scope()],
        serial: tenko_core::dns::SerialPolicy::default(),
        soa: SoaDefaults::new(
            DnsName::new("ns1.example.test").expect("name"),
            DnsName::new("hostmaster.example.test").expect("name"),
        ),
        transfer: tenko_core::dns::TransferPolicy::default(),
        update: tenko_core::dns::UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        reverse_of: None,
        description: None,
        created: stamp(),
        updated: stamp(),
    }
}

fn dns_name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn address(last: u8) -> RecordData {
    RecordData::A {
        address: Ipv4Addr::new(192, 0, 2, last),
    }
}

/// A zone with every kind of answer the full path writes.
fn full_image() -> DnsData {
    let zone = zone_row();
    let mut image = DnsData::at(Revision(1));
    let mut add = |owner: &str, data: RecordData| {
        let set = RrSet {
            zone: zone.id,
            scope: ScopeName::DEFAULT,
            name: dns_name(owner),
            rtype: data.rtype(),
            ttl: 300,
            rdata: vec![Rdata::from_data(&data)],
            origin: Origin::Manual,
            key: None,
            updated: stamp(),
        };
        image.rrsets.insert(set.key(), set);
    };
    add(
        "example.test",
        RecordData::Soa {
            mname: dns_name("ns1.example.test"),
            rname: dns_name("hostmaster.example.test"),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 1_209_600,
            minimum: 300,
        },
    );
    add(
        "example.test",
        RecordData::Ns {
            host: dns_name("ns1.example.test"),
        },
    );
    add("ns1.example.test", address(53));
    for n in 0..1000u32 {
        let last = u8::try_from(n % 250).expect("octet");
        add(&format!("host-{n}.example.test"), address(last));
    }
    add("*.wild.example.test", address(9));
    add(
        "alias.example.test",
        RecordData::Cname {
            target: dns_name("host-1.example.test"),
        },
    );
    add(
        "mail.example.test",
        RecordData::Mx {
            preference: 10,
            exchange: dns_name("host-2.example.test"),
        },
    );
    add(
        "old.example.test",
        RecordData::Dname {
            target: dns_name("example.test"),
        },
    );
    add(
        "child.example.test",
        RecordData::Ns {
            host: dns_name("ns.child.example.test"),
        },
    );
    add("ns.child.example.test", address(54));
    image.zones.insert(zone.id, zone);
    image
}

/// Queries of every kind the full path answers: positive, mixed case, NXDOMAIN, NODATA,
/// wildcard, CNAME, MX with additional data, DNAME, referral with glue, ANY, outside the
/// zones, a client cookie and an EDNS version 1.
fn full_queries() -> Vec<Vec<u8>> {
    let mut queries: Vec<Vec<u8>> = [
        ("host-7.example.test", 1u16),
        ("HOST-8.Example.TEST", 1),
        ("nohost.example.test", 1),
        ("host-9.example.test", 28),
        ("x.wild.example.test", 1),
        ("alias.example.test", 1),
        ("mail.example.test", 15),
        ("host-3.old.example.test", 1),
        ("www.child.example.test", 1),
        ("example.test", 255),
        ("www.example.org", 1),
    ]
    .iter()
    .map(|(name, qtype)| {
        let mut query = Vec::new();
        wire::write_query(&mut query, 0x4242, name, *qtype, Some(1232));
        query
    })
    .collect();
    // An OPT with a client cookie: the empty OPT's data length, then the option.
    let mut cookie = Vec::new();
    wire::write_query(&mut cookie, 9, "host-7.example.test", 1, Some(1232));
    let len = cookie.len();
    cookie[len - 2..].copy_from_slice(&12u16.to_be_bytes());
    cookie.extend_from_slice(&[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
    queries.push(cookie);
    // EDNS version 1: the version octet is the sixth from the end of the empty OPT.
    let mut badvers = Vec::new();
    wire::write_query(&mut badvers, 10, "host-7.example.test", 1, Some(1232));
    let at = badvers.len() - 5;
    badvers[at] = 1;
    queries.push(badvers);
    queries
}

fn the_full_query_path_does_not_allocate() {
    let catalog = CatalogHandle::new(Catalog::build(&full_image()));
    let responder = Responder::new(
        Authoritative::new(catalog),
        CookieSecret::with_secret([5; 16]),
    )
    .with_metrics(true);
    let queries = full_queries();
    let mut scratch = Scratch::new();
    let clock = Clock::now();
    let conn = Conn {
        client: "192.0.2.77:40000".parse().expect("client"),
        local: "192.0.2.53:53".parse().expect("local"),
        transport: QueryTransport::Udp,
    };
    let (allocations, reallocations, bytes) = measure(500, || {
        for query in &queries {
            let reply = responder.respond(query, &conn, &clock, Instant::now(), &mut scratch);
            assert_eq!(reply, Reply::Send);
            black_box(&scratch.out);
        }
    });
    assert_eq!(
        (allocations, reallocations, bytes),
        (0, 0, 0),
        "the full query path allocated"
    );
}

#[test]
fn the_query_path_allocates_nothing() {
    // First: a pass of the checks below means something.
    the_counter_sees_a_deliberate_allocation();
    parse_and_build_do_not_allocate();
    truncation_and_formerr_do_not_allocate();
    index_lookups_do_not_allocate();
    the_full_query_path_does_not_allocate();
}
