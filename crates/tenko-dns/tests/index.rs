//! The reference index and feed: what `MemIndex` answers for a zone with every kind of
//! node, and how `MemFeed` delivers images and deltas. WP4.1 tests its index against the
//! same cases.

use std::net::Ipv4Addr;

use tenko_core::{
    Revision,
    dns::{
        DnsName, Origin, Rdata, RecordData, RrSet, Rtype, ScopeName, SoaDefaults, Zone, ZoneId,
        ZoneKind, ZoneScope,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
    serde_util::HexBytes,
};
use tenko_dns::{
    DnsData, Index, Lookup, MemFeed, MemIndex, NameBuf, ZoneFeed,
    feed::{Change, FeedEvent},
    index::{Chain, DefaultScopes, MAX_CHAIN, ScopeOf},
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

fn wire(text: &str) -> Vec<u8> {
    NameBuf::from_dns_name(&name(text)).as_wire().to_vec()
}

fn zone(apex: &str) -> Zone {
    Zone {
        id: ZoneId::generate(),
        name: name(apex),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: vec![
            ZoneScope::default_scope(),
            ZoneScope {
                name: ScopeName::new("internal").expect("scope"),
                description: None,
            },
        ],
        serial: tenko_core::dns::SerialPolicy::default(),
        soa: SoaDefaults::new(
            name(&format!("ns1.{apex}")),
            name(&format!("hostmaster.{apex}")),
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

fn rrset(zone: &Zone, scope: &ScopeName, owner: &str, data: &[RecordData]) -> RrSet {
    RrSet {
        zone: zone.id,
        scope: scope.clone(),
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

fn soa(apex: &str) -> RecordData {
    RecordData::Soa {
        mname: name(&format!("ns1.{apex}")),
        rname: name(&format!("hostmaster.{apex}")),
        serial: 1,
        refresh: 3600,
        retry: 900,
        expire: 1_209_600,
        minimum: 300,
    }
}

/// `example.test` with an apex, plain data, an empty non-terminal (`b.example.test` above
/// `a.b.example.test`), a wildcard, a CNAME chain, a CNAME loop, a delegation with glue
/// and DS, a DNAME and an internal scope; and `sub.example.test` as its own zone.
fn data() -> (DnsData, Zone, Zone) {
    let parent = zone("example.test");
    let child = zone("sub.example.test");
    let default = ScopeName::DEFAULT;
    let internal = ScopeName::new("internal").expect("scope");
    let sets = vec![
        rrset(&parent, &default, "example.test", &[soa("example.test")]),
        rrset(
            &parent,
            &default,
            "example.test",
            &[RecordData::Ns {
                host: name("ns1.example.test"),
            }],
        ),
        rrset(&parent, &default, "ns1.example.test", &[a(53)]),
        rrset(&parent, &default, "www.example.test", &[a(1), a(2)]),
        rrset(&parent, &default, "a.b.example.test", &[a(3)]),
        rrset(&parent, &default, "*.example.test", &[a(9)]),
        rrset(
            &parent,
            &default,
            "alias.example.test",
            &[cname("hop.example.test")],
        ),
        rrset(
            &parent,
            &default,
            "hop.example.test",
            &[cname("www.example.test")],
        ),
        rrset(
            &parent,
            &default,
            "out.example.test",
            &[cname("www.example.net")],
        ),
        rrset(
            &parent,
            &default,
            "loop1.example.test",
            &[cname("loop2.example.test")],
        ),
        rrset(
            &parent,
            &default,
            "loop2.example.test",
            &[cname("loop1.example.test")],
        ),
        rrset(
            &parent,
            &default,
            "child.example.test",
            &[RecordData::Ns {
                host: name("ns.child.example.test"),
            }],
        ),
        rrset(
            &parent,
            &default,
            "child.example.test",
            &[RecordData::Ds {
                key_tag: 1,
                algorithm: 13,
                digest_type: 2,
                digest: HexBytes(vec![7; 32]),
            }],
        ),
        rrset(&parent, &default, "ns.child.example.test", &[a(54)]),
        rrset(
            &parent,
            &default,
            "old.example.test",
            &[RecordData::Dname {
                target: name("example.net"),
            }],
        ),
        rrset(&parent, &internal, "example.test", &[soa("example.test")]),
        rrset(&parent, &internal, "www.example.test", &[a(100)]),
        rrset(
            &child,
            &default,
            "sub.example.test",
            &[soa("sub.example.test")],
        ),
        rrset(&child, &default, "host.sub.example.test", &[a(77)]),
    ];
    let mut image = DnsData::at(Revision(5));
    image.zones.insert(parent.id, parent.clone());
    image.zones.insert(child.id, child.clone());
    for set in sets {
        image.rrsets.insert(set.key(), set);
    }
    (image, parent, child)
}

fn first_a(lookup: &Lookup<'_>) -> Option<Vec<u8>> {
    match lookup {
        Lookup::Answer { rrset, .. } => Some(rrset.rdata[0].as_bytes().to_vec()),
        _ => None,
    }
}

#[test]
fn positive_answers_and_the_zone_of_a_name() {
    let (image, parent, child) = data();
    let index = MemIndex::build(&image);
    assert_eq!(index.revision(), Revision(5));
    let www = index.lookup(&DefaultScopes, &wire("www.example.test"), Rtype::A);
    let Lookup::Answer {
        zone,
        rrset,
        wildcard,
    } = www
    else {
        panic!("{www:?}");
    };
    assert_eq!((zone.id, rrset.rdata.len(), wildcard), (parent.id, 2, None));
    assert_eq!(rrset.owner, wire("www.example.test"));
    // The longest apex wins.
    let host = index.lookup(&DefaultScopes, &wire("host.sub.example.test"), Rtype::A);
    assert!(matches!(host, Lookup::Answer { zone, .. } if zone.id == child.id));
    // ANY answers one RRset (RFC 8482).
    assert!(matches!(
        index.lookup(&DefaultScopes, &wire("example.test"), Rtype::ANY),
        Lookup::Answer { .. }
    ));
    assert_eq!(
        index.lookup(&DefaultScopes, &wire("www.example.org"), Rtype::A),
        Lookup::NotAuthoritative
    );
}

#[test]
fn negative_answers_know_empty_non_terminals_and_the_closest_encloser() {
    let (image, ..) = data();
    let index = MemIndex::build(&image);
    let nodata = index.lookup(&DefaultScopes, &wire("www.example.test"), Rtype::AAAA);
    assert!(
        matches!(
            nodata,
            Lookup::NoData {
                soa: Some(_),
                wildcard: None,
                ..
            }
        ),
        "{nodata:?}"
    );
    // `b.example.test` exists only because `a.b.example.test` does.
    let empty = index.lookup(&DefaultScopes, &wire("b.example.test"), Rtype::A);
    assert!(
        matches!(empty, Lookup::NoData { wildcard: None, .. }),
        "{empty:?}"
    );
    // Below an existing name the wildcard of the closest encloser does not apply.
    let below = index.lookup(&DefaultScopes, &wire("x.www.example.test"), Rtype::A);
    let Lookup::NxDomain {
        closest_encloser,
        soa,
        ..
    } = below
    else {
        panic!("{below:?}");
    };
    assert_eq!(closest_encloser, wire("www.example.test"));
    assert!(soa.is_some());
}

#[test]
fn wildcards_are_synthesized() {
    let (image, ..) = data();
    let index = MemIndex::build(&image);
    let synthesized = index.lookup(&DefaultScopes, &wire("anything.example.test"), Rtype::A);
    let Lookup::Answer {
        wildcard, rrset, ..
    } = synthesized
    else {
        panic!("{synthesized:?}");
    };
    assert_eq!(wildcard, Some(&wire("*.example.test")[..]));
    assert_eq!(rrset.rdata[0].as_bytes(), [192, 0, 2, 9]);
    let nodata = index.lookup(&DefaultScopes, &wire("anything.example.test"), Rtype::MX);
    assert!(matches!(
        nodata,
        Lookup::NoData {
            wildcard: Some(_),
            ..
        }
    ));
    // The wildcard does not cover the empty non-terminal's children either way.
    assert_eq!(
        first_a(&index.lookup(&DefaultScopes, &wire("a.b.example.test"), Rtype::A)),
        Some(vec![192, 0, 2, 3])
    );
}

#[test]
fn cuts_refer_and_answer_ds_from_the_parent() {
    let (image, parent, _) = data();
    let index = MemIndex::build(&image);
    for qname in [
        "child.example.test",
        "deep.ns.child.example.test",
        "ns.child.example.test",
    ] {
        let lookup = index.lookup(&DefaultScopes, &wire(qname), Rtype::A);
        assert!(
            matches!(lookup, Lookup::Delegation { zone, ds: Some(_), .. } if zone.id == parent.id),
            "{qname}: {lookup:?}"
        );
    }
    let ds = index.lookup(&DefaultScopes, &wire("child.example.test"), Rtype::DS);
    assert!(matches!(ds, Lookup::Answer { rrset, .. } if rrset.rtype == Rtype::DS));
    // Glue is reachable below the cut.
    let [address, none] = index.addresses(&DefaultScopes, &wire("ns.child.example.test"));
    assert_eq!(
        address.map(|rrset| rrset.rdata[0].as_bytes().to_vec()),
        Some(vec![192, 0, 2, 54])
    );
    assert!(none.is_none());
    // A DNAME redirects the names below it, not itself.
    let below = index.lookup(&DefaultScopes, &wire("www.old.example.test"), Rtype::A);
    assert!(matches!(below, Lookup::Dname { .. }), "{below:?}");
    let itself = index.lookup(&DefaultScopes, &wire("old.example.test"), Rtype::DNAME);
    assert!(matches!(itself, Lookup::Answer { .. }));
}

#[test]
fn cname_chains_are_followed_inside_the_index() {
    let (image, ..) = data();
    let index = MemIndex::build(&image);
    let mut chain = Chain::default();
    let last = index.resolve(
        &DefaultScopes,
        &wire("alias.example.test"),
        Rtype::A,
        &mut chain,
    );
    assert_eq!(chain.len(), 2);
    assert!(!chain.exhausted);
    assert_eq!(first_a(&last), Some(vec![192, 0, 2, 1]));
    let owners: Vec<Vec<u8>> = chain
        .steps()
        .map(|(_, rrset, _)| rrset.owner.to_vec())
        .collect();
    assert_eq!(
        owners,
        [wire("alias.example.test"), wire("hop.example.test")]
    );
    // A CNAME query is answered with the CNAME itself.
    let mut direct = Chain::default();
    let own = index.resolve(
        &DefaultScopes,
        &wire("alias.example.test"),
        Rtype::CNAME,
        &mut direct,
    );
    assert!(matches!(own, Lookup::Answer { .. }) && direct.is_empty());
    // A target outside the zones ends the chain.
    let mut out = Chain::default();
    let end = index.resolve(
        &DefaultScopes,
        &wire("out.example.test"),
        Rtype::A,
        &mut out,
    );
    assert_eq!((end, out.len()), (Lookup::NotAuthoritative, 1));
    // A loop stops.
    let mut looped = Chain::default();
    index.resolve(
        &DefaultScopes,
        &wire("loop1.example.test"),
        Rtype::A,
        &mut looped,
    );
    assert!(looped.exhausted);
    assert!(looped.len() <= MAX_CHAIN);
}

struct Internal(ScopeName);

impl ScopeOf for Internal {
    fn scope_of(&self, _zone: ZoneId) -> &ScopeName {
        &self.0
    }
}

#[test]
fn scopes_select_the_data_a_view_sees() {
    let (image, ..) = data();
    let index = MemIndex::build(&image);
    let internal = Internal(ScopeName::new("internal").expect("scope"));
    assert_eq!(
        first_a(&index.lookup(&internal, &wire("www.example.test"), Rtype::A)),
        Some(vec![192, 0, 2, 100])
    );
    // A zone without the scope is seen in its default scope.
    assert_eq!(
        first_a(&index.lookup(&internal, &wire("host.sub.example.test"), Rtype::A)),
        Some(vec![192, 0, 2, 77])
    );
}

#[test]
fn nsec_covering_follows_the_canonical_order() {
    let (mut image, parent, _) = data();
    let nsec = |owner: &str, next: &str| {
        rrset(
            &parent,
            &ScopeName::DEFAULT,
            owner,
            &[RecordData::Nsec {
                next: name(next),
                types: vec![Rtype::A, Rtype::RRSIG, Rtype::NSEC],
            }],
        )
    };
    for set in [
        nsec("example.test", "a.b.example.test"),
        nsec("www.example.test", "example.test"),
    ] {
        image.rrsets.insert(set.key(), set);
    }
    let index = MemIndex::build(&image);
    let Lookup::NxDomain { zone, .. } =
        index.lookup(&DefaultScopes, &wire("zzz.www.example.test"), Rtype::A)
    else {
        panic!("NXDOMAIN");
    };
    let covering = index
        .covering_nsec(&zone, &wire("zzz.www.example.test"))
        .expect("covering");
    assert_eq!(covering.owner, wire("www.example.test"));
    let apex = index
        .covering_nsec(&zone, &wire("a.example.test"))
        .expect("apex");
    assert_eq!(apex.owner, wire("example.test"));
}

#[tokio::test]
async fn the_feed_delivers_an_image_and_then_deltas_in_order() {
    let (image, parent, _) = data();
    let (mut feed, handle) = MemFeed::new(image.clone());
    let first = feed.snapshot().await.expect("snapshot");
    assert_eq!(first, image);
    let added = rrset(&parent, &ScopeName::DEFAULT, "new.example.test", &[a(42)]);
    let revision = handle.publish(vec![Change::RrSet(added.key(), Some(added.clone()))]);
    assert_eq!(revision, Revision(6));
    let FeedEvent::Delta(delta) = feed.next().await.expect("event") else {
        panic!("a delta");
    };
    assert_eq!((delta.from, delta.to), (Revision(5), Revision(6)));
    let mut copy = first;
    copy.apply(&delta).expect("apply");
    assert_eq!(copy, handle.image());
    assert!(copy.apply(&delta).is_err(), "a delta applies once");
    let index = MemIndex::build(&copy);
    assert_eq!(
        first_a(&index.lookup(&DefaultScopes, &wire("new.example.test"), Rtype::A)),
        Some(vec![192, 0, 2, 42])
    );
    // A snapshot after changes skips the deltas it already holds.
    handle.publish(vec![Change::RrSet(added.key(), None)]);
    let again = feed.snapshot().await.expect("snapshot");
    assert_eq!(again.revision, Revision(7));
    handle.reset(DnsData::at(Revision(9)));
    let FeedEvent::Reset(reset) = feed.next().await.expect("event") else {
        panic!("the delta to 7 is skipped, the reset arrives");
    };
    assert_eq!(reset.revision, Revision(9));
    drop(handle);
    assert!(feed.next().await.is_err(), "closed");
}
