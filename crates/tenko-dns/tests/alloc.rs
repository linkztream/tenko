//! The no-allocation rule of the query path (ADR 0009, risk R39), as a test: a counting
//! global allocator (`stats_alloc`, the approach of the Spike B bench) wraps the system
//! allocator, and `Codec::parse`, `Codec::build` and `Index::lookup` must not allocate once
//! their buffers have capacity; nor must the whole path of a query through the responder,
//! the authoritative resolver, the production index and the codec, with metrics and
//! cookies on; nor must a query the forwarder's cache answers (WP5.1), in a view whose
//! recursion access list allows the client, nor one the recursion check refuses; nor, with
//! the policy and the rate limiter of WP5.2 installed, a name an RPZ zone or a block list
//! blocks, an allowed name, a cache hit the policy rewrites (an answer address in an RPZ
//! IP trigger) or passes, and a flood that RRL drops and slips. The first test proves that
//! the counter sees an allocation, so a pass means something.
//!
//! The allocator counts every thread of the process, so the file has one test that runs
//! the measured sections one after another: no other test of the binary runs beside them.

use std::{alloc::System, hint::black_box, net::Ipv4Addr, sync::Arc, time::Instant};

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_core::{
    Revision,
    dns::{
        Acl, AclEntry, AclId, BlockAction, BlockList, BlockListId, DnsName, ForwardTransport,
        ListFormat, ListKind, ListSource, ListVersion, MatchRule, Origin, QueryTransport, Rdata,
        RecordData, RrSet, ScopeName, SoaDefaults, View, ViewId, Zone, ZoneId, ZoneKind,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
};
use tenko_dns::{
    AnswerBuf, Codec, DnsData, DomainCodec, Index, Lookup, MemIndex, NameBuf, Request,
    authoritative::{Authoritative, Settings},
    cache::CacheKey,
    catalog::{Catalog, CatalogHandle},
    codec::{Owner, Section},
    cookie::CookieSecret,
    forward::{ForwardSettings, Forwarder, RecursionDefault, RecursionPolicy},
    index::DefaultScopes,
    lists::compile_text,
    policy::{Policy, answer::PolicySink},
    pool::UpstreamSpec,
    rate::limiter::{ClientLimit, LimitSettings, Limiter, RrlSettings},
    respond::ForwardSink,
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
        catalog: false,
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
        catalog: false,
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

/// An upstream's answer to `www.example.org` A: one record, TTL 300.
fn upstream_answer() -> Vec<u8> {
    let mut answer = Vec::new();
    wire::write_query(&mut answer, 0, "www.example.org", 1, None);
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[7] = 1;
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 80]);
    answer
}

#[allow(clippy::too_many_lines, reason = "one setup and one measured loop")]
fn the_cache_hit_path_does_not_allocate() {
    let acl = Acl {
        id: AclId::generate(),
        name: "clients".to_owned(),
        entries: vec![AclEntry::Prefix {
            prefix: "192.0.2.0/24".parse().expect("prefix"),
            deny: false,
        }],
        description: None,
    };
    let view = View {
        id: ViewId::generate(),
        name: "clients".to_owned(),
        rules: vec![MatchRule::ClientSubnet {
            prefixes: vec!["192.0.2.0/24".parse().expect("prefix")],
        }],
        scope_map: Vec::new(),
        order: 1,
        recursion: Some(acl.id),
        description: None,
    };
    let mut image = full_image();
    image.acls.insert(acl.id, acl);
    image.views.insert(view.id, view.clone());
    let catalog = CatalogHandle::new(Catalog::build(&image));
    // The forwarder's tasks go to a runtime that is not driven while the path is measured.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let stop = tokio_util::sync::CancellationToken::new();
    let (forwarder, _task) = runtime.block_on(async {
        Forwarder::start(
            ForwardSettings {
                upstreams: vec![UpstreamSpec {
                    address: "192.0.2.1:53".parse().expect("address"),
                    transport: ForwardTransport::Plain,
                    tcp_only: false,
                    tls_name: None,
                    path: None,
                }],
                ..ForwardSettings::default()
            },
            catalog.clone(),
            None,
            Arc::new(RecursionPolicy::new(RecursionDefault::KnownPrefixes)),
            stop.clone(),
        )
    });
    let cache = forwarder.cache().expect("a cache");
    let key = CacheKey::new(
        Some(view.id),
        b"\x03www\x07example\x03org\x00",
        1,
        1,
        false,
        false,
    );
    assert!(cache.insert(&key, &upstream_answer(), Instant::now(), None));
    let responder = Responder::new(
        Authoritative::new(catalog).with_settings(Settings {
            recursion_available: true,
            default_forwarder: true,
            ..Settings::default()
        }),
        CookieSecret::with_secret([5; 16]),
    )
    .with_metrics(true)
    .with_forwarder(Arc::clone(&forwarder) as Arc<dyn ForwardSink>);
    let mut hits = Vec::new();
    for (id, name) in [(1, "www.example.org"), (2, "WWW.Example.ORG")] {
        let mut query = Vec::new();
        wire::write_query(&mut query, id, name, 1, Some(1232));
        query[2] |= 0x01;
        hits.push(query);
    }
    let mut with_cookie = hits[0].clone();
    let len = with_cookie.len();
    with_cookie[len - 2..].copy_from_slice(&12u16.to_be_bytes());
    with_cookie.extend_from_slice(&[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
    hits.push(with_cookie);
    let inside = Conn {
        client: "192.0.2.77:40000".parse().expect("client"),
        local: "192.0.2.53:53".parse().expect("local"),
        transport: QueryTransport::Udp,
    };
    // Outside the view and outside the prefixes IPAM knows: refused on the query path.
    let outside = Conn {
        client: "198.51.100.9:40000".parse().expect("client"),
        ..inside
    };
    let mut scratch = Scratch::new();
    let clock = Clock::now();
    let (allocations, reallocations, bytes) = measure(500, || {
        for query in &hits {
            let reply = responder.respond(query, &inside, &clock, Instant::now(), &mut scratch);
            assert_eq!(reply, Reply::Send, "a cache hit");
            assert_eq!(scratch.out[3] & 0x0f, 0);
            black_box(&scratch.out);
        }
        let reply = responder.respond(&hits[0], &outside, &clock, Instant::now(), &mut scratch);
        assert_eq!(reply, Reply::Send, "refused");
        assert_eq!(scratch.out[3] & 0x0f, 5);
        black_box(&scratch.out);
    });
    assert_eq!(
        (allocations, reallocations, bytes),
        (0, 0, 0),
        "the cache hit path allocated"
    );
    assert!(forwarder.stats().hits >= 1_500);
    stop.cancel();
}

/// An RRset of `zone` in its default scope.
fn rrset_of(zone: &Zone, owner: &str, data: &RecordData) -> RrSet {
    RrSet {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        name: dns_name(owner),
        rtype: data.rtype(),
        ttl: 300,
        rdata: vec![Rdata::from_data(data)],
        origin: Origin::Manual,
        key: None,
        updated: stamp(),
    }
}

/// An upstream's answer to `name` A with the address `192.0.2.<last>`, TTL 300.
fn answer_for(name: &str, last: u8) -> Vec<u8> {
    let mut answer = Vec::new();
    wire::write_query(&mut answer, 0, name, 1, None);
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[7] = 1;
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, last]);
    answer
}

/// The full image with an RPZ zone (a QNAME trigger, local data and an IP trigger), a block
/// list and an allow list with their versions.
fn policy_image() -> DnsData {
    let mut image = full_image();
    let mut rpz = zone_row();
    rpz.id = ZoneId::generate();
    rpz.name = dns_name("rpz.test");
    rpz.kind = ZoneKind::Rpz;
    let nxdomain = RecordData::Cname {
        target: DnsName::root(),
    };
    for set in [
        rrset_of(&rpz, "blocked.example.org.rpz.test", &nxdomain),
        rrset_of(&rpz, "local.example.org.rpz.test", &address(99)),
        rrset_of(&rpz, "32.80.2.0.192.rpz-ip.rpz.test", &nxdomain),
    ] {
        image.rrsets.insert(set.key(), set);
    }
    image.zones.insert(rpz.id, rpz);
    let lists: [(&str, ListKind, &[u8]); 2] = [
        (
            "ads",
            ListKind::Block,
            b"ads.example.org\nredirect.example.org\n",
        ),
        ("allowed", ListKind::Allow, b"fine.ads.example.org\n"),
    ];
    for (name, kind, text) in lists {
        let list = BlockList {
            id: BlockListId::generate(),
            name: name.to_owned(),
            kind,
            source: ListSource::Upload,
            format: ListFormat::Domains,
            interval_hours: 24,
            action: BlockAction::Nxdomain,
            enabled: true,
            exempt: Vec::new(),
            description: None,
        };
        let (compiled, _) = compile_text(text, ListFormat::Domains).expect("compile");
        image.list_versions.insert(
            (list.id, 1),
            ListVersion {
                list: list.id,
                revision: 1,
                compiled: tenko_core::serde_util::HexBytes(compiled.bytes),
                entries: compiled.entries,
                fetched: "2026-10-18T12:00:00Z".parse().expect("time"),
                etag: None,
            },
        );
        image.lists.insert(list.id, list);
    }
    image
}

#[allow(clippy::too_many_lines, reason = "one setup and one measured loop")]
fn the_policy_and_the_limiter_do_not_allocate() {
    let catalog = CatalogHandle::new(Catalog::build(&policy_image()));
    assert_eq!(catalog.load().policy().blocks().len(), 1);
    assert_eq!(catalog.load().policy().zones().len(), 1);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let stop = tokio_util::sync::CancellationToken::new();
    let (forwarder, _task) = runtime.block_on(async {
        Forwarder::start(
            ForwardSettings {
                upstreams: vec![UpstreamSpec {
                    address: "192.0.2.1:53".parse().expect("address"),
                    transport: ForwardTransport::Plain,
                    tcp_only: false,
                    tls_name: None,
                    path: None,
                }],
                ..ForwardSettings::default()
            },
            catalog.clone(),
            None,
            Arc::new(RecursionPolicy::new(RecursionDefault::Anyone)),
            stop.clone(),
        )
    });
    let cache = forwarder.cache().expect("a cache");
    for (name, last) in [("www.example.org", 80), ("clean.example.org", 81)] {
        let wire_name = NameBuf::from_dns_name(&dns_name(name));
        let key = CacheKey::new(None, wire_name.as_wire(), 1, 1, false, false);
        assert!(cache.insert(&key, &answer_for(name, last), Instant::now(), None));
    }
    let limiter = Limiter::new(LimitSettings {
        rrl: Some(RrlSettings {
            responses_per_second: 5,
            ..RrlSettings::default()
        }),
        client: Some(ClientLimit {
            queries_per_second: 1_000_000,
            burst: 1_000_000,
        }),
        exempt: Vec::new(),
        table: 65_536,
    });
    let policy = Arc::new(Policy);
    let sink = PolicySink::new(
        Arc::clone(&forwarder) as Arc<dyn ForwardSink>,
        catalog.clone(),
        Arc::clone(&policy) as Arc<dyn tenko_dns::PolicyEngine>,
        runtime.handle().clone(),
    );
    let responder = Responder::new(
        Authoritative::new(catalog)
            .with_settings(Settings {
                recursion_available: true,
                default_forwarder: true,
                ..Settings::default()
            })
            .with_policy(policy)
            .with_rate_limiter(Arc::new(limiter)),
        CookieSecret::with_secret([5; 16]),
    )
    .with_metrics(true)
    .with_forwarder(Arc::new(sink) as Arc<dyn ForwardSink>);
    let mut queries = full_queries();
    for name in [
        "blocked.example.org",
        "local.example.org",
        "ads.example.org",
        "x.ads.example.org",
        "fine.ads.example.org",
        "redirect.example.org",
    ] {
        let mut query = Vec::new();
        wire::write_query(&mut query, 7, name, 1, Some(1232));
        queries.push(query);
    }
    // Cache hits: one the IP trigger rewrites, one the policy passes.
    let mut hits = Vec::new();
    for name in ["www.example.org", "clean.example.org"] {
        let mut query = Vec::new();
        wire::write_query(&mut query, 3, name, 1, Some(1232));
        query[2] |= 0x01;
        hits.push(query);
    }
    let client = Conn {
        client: "198.51.100.77:40000".parse().expect("client"),
        local: "192.0.2.53:53".parse().expect("local"),
        transport: QueryTransport::Udp,
    };
    // The role registers the limiter's families at its start, which seals them.
    tenko_dns::rate::limiter::register_metrics(&tenko_core::metrics::Registry::new());
    let mut scratch = Scratch::new();
    let clock = Clock::now();
    let mut rewritten = 0u32;
    let (allocations, reallocations, bytes) = measure(500, || {
        for query in queries.iter().chain(&hits) {
            let reply = responder.respond(query, &client, &clock, Instant::now(), &mut scratch);
            black_box((reply, &scratch.out));
        }
        // The cache hit of www.example.org: its address is in the IP trigger.
        let reply = responder.respond(&hits[0], &client, &clock, Instant::now(), &mut scratch);
        if reply == Reply::Send && scratch.out[3] & 0x0f == 3 {
            rewritten += 1;
        }
    });
    assert_eq!(
        (allocations, reallocations, bytes),
        (0, 0, 0),
        "the policy or the limiter allocated"
    );
    assert!(rewritten > 0, "the cache hit was rewritten to NXDOMAIN");
    // The flood was limited, and the policy blocked.
    let counts = tenko_dns::status::RateCounts::read();
    assert!(counts.dropped > 0 && counts.slipped > 0, "{counts:?}");
    assert!(tenko_dns::policy::counters::total_of("ads") > 0);
    assert!(tenko_dns::policy::counters::total_of("rpz.test") > 0);
    stop.cancel();
}

#[test]
fn the_query_path_allocates_nothing() {
    // First: a pass of the checks below means something.
    the_counter_sees_a_deliberate_allocation();
    parse_and_build_do_not_allocate();
    truncation_and_formerr_do_not_allocate();
    index_lookups_do_not_allocate();
    the_full_query_path_does_not_allocate();
    the_cache_hit_path_does_not_allocate();
    the_policy_and_the_limiter_do_not_allocate();
    tsig_verify_and_sign_do_not_allocate();
}

/// TSIG on the transfer path (WP6.1): once the key is in the keyring, verifying a signed
/// request and signing an answer allocate nothing.
fn tsig_verify_and_sign_do_not_allocate() {
    use tenko_dns::tsig::{Keyring, Signer, TsigKey, find, verify_request};
    let key = TsigKey::new(
        &dns_name("transfer.example.test"),
        tenko_core::dns::TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef",
    );
    let ring = Keyring::new([key]);
    let now = 1_790_000_000;
    let mut request = Vec::new();
    wire::write_query(&mut request, 7, "example.test", 252, None);
    let shared = ring
        .by_name(&dns_name("transfer.example.test"))
        .expect("the key");
    assert!(Signer::request(std::sync::Arc::clone(&shared)).sign(
        &mut request,
        now,
        0,
        &[],
        MAX_MESSAGE_LEN
    ));
    let mut answer = Vec::with_capacity(4096);
    let (allocations, reallocations, _) = measure(1000, || {
        let tsig = find(black_box(&request)).expect("parse").expect("signed");
        let verified = verify_request(&ring, &request, &tsig, now).expect("verifies");
        answer.clear();
        answer.extend_from_slice(&request[..tsig.record_start]);
        answer[2] |= 0x80;
        let mut signer = Signer::answer(verified.key, verified.mac);
        assert!(signer.sign(&mut answer, now, 0, &[], MAX_MESSAGE_LEN));
        black_box(&answer);
    });
    assert_eq!(
        (allocations, reallocations),
        (0, 0),
        "TSIG verify and sign allocated"
    );
}
