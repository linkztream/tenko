//! M18 (index memory): the heap the production index holds for the data set of
//! `bench/phase2-dns zonegen`, counted by the instrumented global allocator (the same
//! approach as `tests/alloc.rs`). It builds the image of `--records N` (the forward zone
//! with N `host-{n}` A records and the three reverse zones with a PTR record for every
//! fifth host), builds the index from it, drops the image and reports the bytes the index
//! still holds: what the role keeps per node, without the allocator's own overhead or
//! anything the allocator keeps after a free.
//!
//! Ignored by default (it needs several GiB at 6,000,000 records). Run it in release:
//!
//! ```text
//! TENKO_INDEX_RECORDS=6000000 cargo test -p tenko-dns --release --test index_memory -- --ignored --nocapture
//! ```

use std::{alloc::System, net::Ipv4Addr, time::Instant};

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_core::{
    Revision,
    dns::{
        DnsName, Origin, Rdata, RecordData, RrSet, ScopeName, SerialPolicy, SoaDefaults, Zone,
        ZoneId, ZoneKind, ZoneScope,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
};
use tenko_dns::{DnsData, tree::ZoneIndex};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// The first three octets of the generator's networks, in its order.
const NETWORKS: [[u8; 3]; 3] = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];
const REVERSE: [&str; 3] = [
    "2.0.192.in-addr.arpa",
    "100.51.198.in-addr.arpa",
    "113.0.203.in-addr.arpa",
];

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("a valid name")
}

fn last_octet(host: u64) -> u8 {
    u8::try_from(1 + (host / 3) % 254).unwrap_or(1)
}

fn zone(apex: &str, stamp: &Stamp) -> Zone {
    Zone {
        id: ZoneId::generate(),
        name: name(apex),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: vec![ZoneScope::default_scope()],
        serial: SerialPolicy::default(),
        soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
        transfer: tenko_core::dns::TransferPolicy::default(),
        update: tenko_core::dns::UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        reverse_of: None,
        catalog: false,
        description: None,
        created: stamp.clone(),
        updated: stamp.clone(),
    }
}

/// The image of `zonegen --records records`: four zones, every record its own RRset.
fn image(records: u64) -> DnsData {
    let stamp = Stamp::new(
        "2026-10-17T12:00:00Z".parse().expect("a time"),
        Principal::system(SystemComponent::Dns),
    );
    let forward = zone("example.test", &stamp);
    let reverse: Vec<Zone> = REVERSE.iter().map(|apex| zone(apex, &stamp)).collect();
    let mut data = DnsData::at(Revision(1));
    let mut add = |zone: &Zone, owner: DnsName, record: RecordData| {
        let set = RrSet {
            zone: zone.id,
            scope: ScopeName::DEFAULT,
            name: owner,
            rtype: record.rtype(),
            ttl: 300,
            rdata: vec![Rdata::from_data(&record)],
            origin: Origin::Manual,
            key: None,
            updated: stamp.clone(),
        };
        data.rrsets.insert(set.key(), set);
    };
    for zone in std::iter::once(&forward).chain(reverse.iter()) {
        add(
            zone,
            zone.name.clone(),
            RecordData::Soa {
                mname: name("ns1.example.test"),
                rname: name("hostmaster.example.test"),
                serial: 1,
                refresh: 3600,
                retry: 900,
                expire: 604_800,
                minimum: 300,
            },
        );
        add(
            zone,
            zone.name.clone(),
            RecordData::Ns {
                host: name("ns1.example.test"),
            },
        );
    }
    add(
        &forward,
        name("ns1.example.test"),
        RecordData::A {
            address: Ipv4Addr::new(192, 0, 2, 254),
        },
    );
    for host in 0..records {
        let [a, b, c] = NETWORKS[usize::try_from(host % 3).unwrap_or(0)];
        let address = Ipv4Addr::new(a, b, c, last_octet(host));
        add(
            &forward,
            name(&format!("host-{host}.example.test")),
            RecordData::A { address },
        );
    }
    // A PTR record for every fifth host, owner `{octet}.{block}` as the generator writes it.
    for ptr in 0..records / 5 {
        let host = ptr * 5;
        let zone = &reverse[usize::try_from(host % 3).unwrap_or(0)];
        let owner = format!("{}.{}.{}", last_octet(host), host / 762, zone.name);
        add(
            zone,
            name(&owner),
            RecordData::Ptr {
                target: name(&format!("host-{host}.example.test")),
            },
        );
    }
    data.zones.insert(forward.id, forward);
    for zone in reverse {
        data.zones.insert(zone.id, zone);
    }
    data
}

fn held(region: &Region<'_, System>) -> i128 {
    let change = region.change();
    i128::try_from(change.bytes_allocated).unwrap_or(i128::MAX)
        - i128::try_from(change.bytes_deallocated).unwrap_or(i128::MAX)
}

#[allow(clippy::cast_precision_loss, reason = "a size for the report")]
fn mib(bytes: i128) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

#[test]
#[allow(clippy::cast_precision_loss, reason = "sizes for the report")]
#[ignore = "M18: needs several GiB at 6,000,000 records; run it by hand in release"]
fn the_index_holds_its_bytes_for_the_m18_data_set() {
    let records: u64 = std::env::var("TENKO_INDEX_RECORDS")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(1_000_000);
    let region = Region::new(GLOBAL);
    let began = Instant::now();
    let data = image(records);
    let image_bytes = held(&region);
    let built = Instant::now();
    let index = ZoneIndex::build(&data);
    let build_secs = built.elapsed().as_secs_f64();
    let rrsets = data.rrsets.len();
    drop(data);
    let index_bytes = held(&region);
    let stats = index.stats();
    println!(
        "M18 index memory: {records} records, {rrsets} RRsets in {} zones; image {:.1} MiB \
         (generated in {:.1} s); index built in {build_secs:.1} s, holds {:.1} MiB \
         ({:.0} octets per RRset); its own count of the bases {:.1} MiB",
        stats.zones,
        mib(image_bytes),
        began.elapsed().as_secs_f64() - build_secs,
        mib(index_bytes),
        index_bytes as f64 / rrsets as f64,
        mib(i128::try_from(stats.base_bytes).unwrap_or(i128::MAX)),
    );
    assert_eq!(stats.base_rrsets, rrsets);
    assert!(index_bytes > 0);
}
