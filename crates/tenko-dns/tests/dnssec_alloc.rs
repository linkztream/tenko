//! The no-allocation rule of the query path (ADR 0009) for the answers of signed zones
//! (WP6.3): with the DO bit, a positive answer with its RRSIGs, a wildcard answer with its
//! proof, NODATA and NXDOMAIN with their NSEC or NSEC3 proofs (the NSEC3 hash and the hashed
//! owner composed in fixed buffers) go through the responder, the authoritative resolver,
//! the production index and the codec without allocating. The zone is signed by the signer
//! over an in-memory store first; then the counting allocator (`stats_alloc`, as in
//! `tests/alloc.rs`) measures the answers. The first measurement proves that the counter
//! sees an allocation.
//!
//! The allocator counts every thread of the process, so the file has one test that runs
//! the measured sections one after another.

use std::{alloc::System, hint::black_box, sync::Arc, time::Instant};

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_core::{
    RequestCtx, SystemComponent,
    dns::{
        Denial, DnsName, DnssecMode, DnssecPolicy, Origin, QueryTransport, RecordData, Rtype,
        ScopeName, SerialPolicy, SoaDefaults, ZoneKind,
        tables::{RRSETS, ZONES},
    },
    serde_util::HexBytes,
};
use tenko_dns::{
    DnsData,
    authoritative::Authoritative,
    catalog::{Catalog, CatalogHandle},
    cookie::CookieSecret,
    dnssec::{Signer, SignerConfig, Trigger},
    respond::{Clock, Conn, Reply, Responder, Scratch},
    wire,
    zone::{
        NewZone, ZoneChange, ZoneConfig, ZoneService,
        records::{Change, Op},
    },
};
use tenko_store::{KeyRange, MemStore, ReadViewExt, Store};
use tenko_vault::MemVault;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

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

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn set(owner: &str, records: Vec<RecordData>) -> Change {
    Change {
        op: Op::Set,
        scope: ScopeName::DEFAULT,
        name: name(owner),
        rtype: records.first().expect("records").rtype(),
        ttl: Some(300),
        records,
        take_over: false,
        origin: Origin::Manual,
    }
}

/// The image of a zone signed with `denial`.
#[allow(
    clippy::too_many_lines,
    reason = "one zone from creation to its signed image"
)]
fn signed_image(denial: Denial) -> DnsData {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let store = Arc::new(MemStore::default());
        let vault = Arc::new(MemVault::with_store(Arc::clone(&store)));
        let zones = ZoneService::with_direct_jobs(
            Arc::clone(&store) as Arc<dyn Store>,
            Some(Arc::clone(&vault) as Arc<dyn tenko_vault::Vault>),
            ZoneConfig::default(),
        );
        let cx = RequestCtx::system(SystemComponent::Dns);
        let zone = zones
            .create(
                &cx,
                NewZone {
                    name: name("example.test"),
                    kind: ZoneKind::Primary,
                    tenant: None,
                    scopes: Vec::new(),
                    serial: SerialPolicy::Counter,
                    soa: SoaDefaults::new(
                        name("ns1.example.test"),
                        name("hostmaster.example.test"),
                    ),
                    name_servers: vec![name("ns1.example.test")],
                    transfer: tenko_core::dns::TransferPolicy::default(),
                    update: tenko_core::dns::UpdatePolicy::default(),
                    dnssec: DnssecPolicy::default(),
                    source: None,
                    description: None,
                    reverse_of: None,
                    catalog: false,
                },
            )
            .await
            .expect("zone")
            .zone;
        let a = |address: &str| RecordData::A {
            address: address.parse().expect("address"),
        };
        zones
            .change_records(
                &cx,
                zone.id,
                &[
                    set("ns1.example.test", vec![a("192.0.2.1")]),
                    set("www.example.test", vec![a("192.0.2.10")]),
                    set("a.b.example.test", vec![a("192.0.2.11")]),
                    set(
                        "*.wild.example.test",
                        vec![RecordData::Txt {
                            strings: vec![tenko_core::dns::TextBytes(b"w".to_vec())],
                        }],
                    ),
                ],
                false,
            )
            .await
            .expect("records");
        zones
            .update(
                &cx,
                zone.id,
                ZoneChange {
                    dnssec: Some(DnssecPolicy {
                        mode: DnssecMode::Online,
                        denial,
                        ..DnssecPolicy::default()
                    }),
                    ..ZoneChange::default()
                },
                None,
            )
            .await
            .expect("policy");
        let signer = Signer::new(
            Arc::clone(&zones),
            vault as Arc<dyn tenko_vault::Vault>,
            SignerConfig::default(),
        );
        signer
            .sync(zone.id, Trigger::full(false))
            .await
            .expect("signed");
        let view = zones.view(None).await.expect("view");
        let mut image = DnsData {
            revision: view.revision(),
            ..DnsData::default()
        };
        for (id, zone, _) in view
            .scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)
            .expect("zones")
        {
            image.zones.insert(id, zone);
        }
        for (key, row, _) in view
            .scan_typed(&RRSETS, KeyRange::all(), usize::MAX, false)
            .expect("rows")
        {
            image.rrsets.insert(key, row);
        }
        assert!(image.rrsets.keys().any(|key| key.rtype == Rtype::RRSIG));
        image
    })
}

/// Queries with DO for `qname` and `qtype`.
fn query(qname: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(&mut out, 9, qname, qtype, Some(1232));
    let at = out.len() - 4;
    out[at] |= 0x80;
    out
}

fn signed_answers_do_not_allocate(denial: Denial) {
    let catalog = CatalogHandle::new(Catalog::build(&signed_image(denial)));
    let responder = Responder::new(
        Authoritative::new(catalog),
        CookieSecret::with_secret([5; 16]),
    )
    .with_metrics(true);
    let queries = [
        query("www.example.test", 1),
        query("www.example.test", 28),
        query("b.example.test", 1),
        query("missing.example.test", 1),
        query("x.missing.b.example.test", 1),
        query("host.wild.example.test", 16),
        query("example.test", 48),
    ];
    let mut scratch = Scratch::new();
    let clock = Clock::now();
    let conn = Conn {
        client: "192.0.2.77:40000".parse().expect("client"),
        local: "192.0.2.53:53".parse().expect("local"),
        transport: QueryTransport::Udp,
    };
    for q in &queries {
        assert_eq!(
            responder.respond(q, &conn, &clock, Instant::now(), &mut scratch),
            Reply::Send
        );
        let header = wire::parse_header(&scratch.out).expect("header");
        assert!(
            header.ancount + header.nscount >= 2,
            "a signed answer: {header:?}"
        );
    }
    let (allocations, reallocations, bytes) = measure(200, || {
        for q in &queries {
            let reply = responder.respond(q, &conn, &clock, Instant::now(), &mut scratch);
            assert_eq!(reply, Reply::Send);
            black_box(&scratch.out);
        }
    });
    assert_eq!(
        (allocations, reallocations, bytes),
        (0, 0, 0),
        "a signed answer allocated"
    );
}

#[test]
fn signed_answers_do_not_allocate_with_nsec_or_nsec3() {
    let (allocations, _, _) = measure(10, || {
        let v: Vec<u8> = black_box(Vec::with_capacity(64));
        black_box(&v);
    });
    assert_eq!(allocations, 10, "the counter sees an allocation");
    signed_answers_do_not_allocate(Denial::Nsec);
    signed_answers_do_not_allocate(Denial::Nsec3 {
        iterations: 0,
        salt: HexBytes(Vec::new()),
    });
}
