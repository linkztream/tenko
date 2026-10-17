//! The production index against the reference: `ZoneIndex` and `MemIndex` built from the
//! same `DnsData` must give the same lookups, chains, addresses and NSEC coverings, over a
//! generated zone of 100,000 names with every kind of node, and after every delta of a
//! random sequence that adds and removes RRsets, cuts, DNAMEs, wildcards and zones.

mod support;

use std::collections::BTreeSet;

use support::{
    Rng, a, aaaa, cname, dname, internal, mx, name, ns, rrset, rrset_ttl, soa, txt, wire, zone,
};
use tenko_core::{
    Revision,
    dns::{RecordData, RrSet, Rtype, ScopeName, Zone, ZoneId},
    serde_util::HexBytes,
};
use tenko_dns::{
    DnsData, Index, MemIndex,
    feed::{Change, Delta},
    index::{Chain, DefaultScopes, ScopeOf},
    tree::ZoneIndex,
};

struct Scoped(ScopeName);

impl ScopeOf for Scoped {
    fn scope_of(&self, _zone: ZoneId) -> &ScopeName {
        &self.0
    }
}

const TYPES: [Rtype; 11] = [
    Rtype::A,
    Rtype::AAAA,
    Rtype::MX,
    Rtype::NS,
    Rtype::DS,
    Rtype::ANY,
    Rtype::CNAME,
    Rtype::DNAME,
    Rtype::TXT,
    Rtype::SOA,
    Rtype::NSEC,
];

fn nsec(next: &str) -> RecordData {
    RecordData::Nsec {
        next: name(next),
        types: vec![Rtype::A, Rtype::RRSIG, Rtype::NSEC],
    }
}

fn ds() -> RecordData {
    RecordData::Ds {
        key_tag: 1,
        algorithm: 13,
        digest_type: 2,
        digest: HexBytes(vec![7; 32]),
    }
}

fn insert(image: &mut DnsData, set: RrSet) {
    image.rrsets.insert(set.key(), set);
}

/// Compares every answer of the two indexes for one name and type.
fn same(
    production: &ZoneIndex,
    reference: &MemIndex,
    scopes: &dyn ScopeOf,
    qname: &[u8],
    qtype: Rtype,
) {
    let label = || format!("{qname:?} {qtype}");
    assert_eq!(
        production.lookup(scopes, qname, qtype),
        reference.lookup(scopes, qname, qtype),
        "lookup {}",
        label()
    );
    let (mut chain_p, mut chain_r) = (Chain::default(), Chain::default());
    let last_p = production.resolve(scopes, qname, qtype, &mut chain_p);
    let last_r = reference.resolve(scopes, qname, qtype, &mut chain_r);
    assert_eq!(last_p, last_r, "resolve {}", label());
    assert_eq!(chain_p.exhausted, chain_r.exhausted, "chain {}", label());
    assert!(
        chain_p.steps().eq(chain_r.steps()),
        "chain steps {}",
        label()
    );
    assert_eq!(
        production.addresses(scopes, qname),
        reference.addresses(scopes, qname),
        "addresses {}",
        label()
    );
}

fn same_nsec(production: &ZoneIndex, reference: &MemIndex, scopes: &dyn ScopeOf, qname: &[u8]) {
    let (lookup_p, lookup_r) = (
        production.lookup(scopes, qname, Rtype::A),
        reference.lookup(scopes, qname, Rtype::A),
    );
    let zone = |lookup| match lookup {
        tenko_dns::Lookup::Answer { zone, .. }
        | tenko_dns::Lookup::Cname { zone, .. }
        | tenko_dns::Lookup::Dname { zone, .. }
        | tenko_dns::Lookup::Delegation { zone, .. }
        | tenko_dns::Lookup::NoData { zone, .. }
        | tenko_dns::Lookup::NxDomain { zone, .. } => Some(zone),
        tenko_dns::Lookup::NotAuthoritative => None,
    };
    if let (Some(zone_p), Some(zone_r)) = (zone(lookup_p), zone(lookup_r)) {
        assert_eq!(
            production.covering_nsec(&zone_p, qname),
            reference.covering_nsec(&zone_r, qname),
            "nsec {qname:?}"
        );
    }
}

/// `example.test` with 100,000 hosts and every special node, `sub.example.test` inside it,
/// `alias.test` with a DNAME at the apex and `signed.test` with an NSEC chain.
#[allow(clippy::too_many_lines, reason = "one data set, written out")]
fn generated(hosts: u32) -> (DnsData, Vec<Vec<u8>>) {
    let parent = zone("example.test");
    let child = zone("sub.example.test");
    let alias = zone("alias.test");
    let signed = zone("signed.test");
    let default = ScopeName::DEFAULT;
    let internal = internal();
    let mut image = DnsData::at(Revision(1));
    let mut queries: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut add = |image: &mut DnsData, set: RrSet| {
        queries.insert(set.name.to_wire());
        insert(image, set);
    };
    add(
        &mut image,
        rrset(
            &parent,
            &default,
            "example.test",
            &[soa("example.test", 300)],
        ),
    );
    add(
        &mut image,
        rrset(&parent, &default, "example.test", &[ns("ns1.example.test")]),
    );
    add(
        &mut image,
        rrset(
            &parent,
            &internal,
            "example.test",
            &[soa("example.test", 60)],
        ),
    );
    add(
        &mut image,
        rrset(&parent, &default, "ns1.example.test", &[a(53)]),
    );
    add(
        &mut image,
        rrset(&parent, &default, "*.example.test", &[txt("wild")]),
    );
    for n in 0..hosts {
        let host = format!("host-{n}.example.test");
        let last = u8::try_from(n % 250).expect("octet") + 1;
        let ttl = [300, 600, 900, 3600][n as usize % 4];
        add(
            &mut image,
            rrset_ttl(&parent, &default, &host, ttl, &[a(last)]),
        );
        if n % 7 == 0 {
            add(
                &mut image,
                rrset(
                    &parent,
                    &default,
                    &host,
                    &[aaaa(u16::try_from(n % 60_000).expect("word"))],
                ),
            );
        }
        if n % 50 == 0 {
            add(
                &mut image,
                rrset(
                    &parent,
                    &default,
                    &host,
                    &[mx(10, &format!("host-{}.example.test", n + 1))],
                ),
            );
        }
        if n % 97 == 0 {
            let target = if n % 2 == 0 {
                format!("host-{}.example.test", n + 3)
            } else {
                "www.example.net".to_string()
            };
            add(
                &mut image,
                rrset(
                    &parent,
                    &default,
                    &format!("alias-{n}.example.test"),
                    &[cname(&target)],
                ),
            );
        }
        if n % 101 == 0 {
            add(
                &mut image,
                rrset(
                    &parent,
                    &default,
                    &format!("x.y.deep-{n}.example.test"),
                    &[a(9)],
                ),
            );
            add(
                &mut image,
                rrset(
                    &parent,
                    &default,
                    &format!("*.wild-{n}.example.test"),
                    &[a(8)],
                ),
            );
            add(
                &mut image,
                rrset(
                    &parent,
                    &default,
                    &format!("w.wild-{n}.example.test"),
                    &[cname(&format!("host-{n}.example.test"))],
                ),
            );
        }
        if n % 211 == 0 {
            let cut = format!("child-{n}.example.test");
            add(
                &mut image,
                rrset(
                    &parent,
                    &default,
                    &cut,
                    &[
                        ns(&format!("ns.{cut}")),
                        ns("ns1.example.test"),
                        ns("ns.example.net"),
                    ],
                ),
            );
            if n % 2 == 0 {
                add(&mut image, rrset(&parent, &default, &cut, &[ds()]));
            }
            add(
                &mut image,
                rrset(&parent, &default, &format!("ns.{cut}"), &[a(54), a(55)]),
            );
            add(
                &mut image,
                rrset(&parent, &default, &format!("ns.{cut}"), &[aaaa(54)]),
            );
            add(
                &mut image,
                rrset(&parent, &default, &format!("*.{cut}"), &[a(56)]),
            );
            add(
                &mut image,
                rrset(&parent, &default, &format!("deep.occluded.{cut}"), &[a(57)]),
            );
        }
        if n % 307 == 0 {
            let old = format!("old-{n}.example.test");
            add(
                &mut image,
                rrset(&parent, &default, &old, &[dname("example.net")]),
            );
            add(
                &mut image,
                rrset(&parent, &default, &format!("hidden.{old}"), &[a(58)]),
            );
        }
        if n % 401 == 0 {
            add(&mut image, rrset(&parent, &internal, &host, &[a(200)]));
        }
    }
    add(
        &mut image,
        rrset(
            &parent,
            &default,
            "loop1.example.test",
            &[cname("loop2.example.test")],
        ),
    );
    add(
        &mut image,
        rrset(
            &parent,
            &default,
            "loop2.example.test",
            &[cname("loop1.example.test")],
        ),
    );
    let mut previous = "chain-0.example.test".to_string();
    for step in 1..12 {
        let next = format!("chain-{step}.example.test");
        add(
            &mut image,
            rrset(&parent, &default, &previous, &[cname(&next)]),
        );
        previous = next;
    }
    add(&mut image, rrset(&parent, &default, &previous, &[a(12)]));
    add(
        &mut image,
        rrset(
            &child,
            &default,
            "sub.example.test",
            &[soa("sub.example.test", 120)],
        ),
    );
    add(
        &mut image,
        rrset(&child, &default, "host.sub.example.test", &[a(77)]),
    );
    add(
        &mut image,
        rrset(&alias, &default, "alias.test", &[soa("alias.test", 300)]),
    );
    add(
        &mut image,
        rrset(&alias, &default, "alias.test", &[dname("example.test")]),
    );
    add(
        &mut image,
        rrset(&signed, &default, "signed.test", &[soa("signed.test", 300)]),
    );
    for (owner, next) in [
        ("signed.test", "a.signed.test"),
        ("a.signed.test", "m.signed.test"),
        ("m.signed.test", "z.b.signed.test"),
        ("z.b.signed.test", "signed.test"),
    ] {
        add(&mut image, rrset(&signed, &default, owner, &[nsec(next)]));
        if owner != "signed.test" {
            add(&mut image, rrset(&signed, &default, owner, &[a(1)]));
        }
    }
    for set in [&parent, &child, &alias, &signed] {
        image.zones.insert(set.id, Zone::clone(set));
    }
    let owners: Vec<Vec<u8>> = queries.into_iter().collect();
    let mut names = Vec::new();
    for (index, owner) in owners.iter().enumerate() {
        names.push(owner.clone());
        if index % 3 == 0 {
            // Below the owner, and a sibling that does not exist.
            let mut below = b"\x01q".to_vec();
            below.extend_from_slice(owner);
            names.push(below);
        }
    }
    for extra in [
        "nohost.example.test",
        "a.b.c.example.test",
        "y.deep-0.example.test",
        "deep-0.example.test",
        "q.wild-0.example.test",
        "w.wild-0.example.test",
        "z.q.wild-0.example.test",
        "child-0.example.test",
        "x.y.child-0.example.test",
        "occluded.child-0.example.test",
        "www.old-0.example.test",
        "old-0.example.test",
        "www.alias.test",
        "alias.test",
        "host-5.alias.test",
        "zz.signed.test",
        "b.signed.test",
        "n.signed.test",
        "example.net",
        "test",
        "",
    ] {
        names.push(wire(extra));
    }
    (image, names)
}

#[test]
fn the_index_agrees_with_the_reference_over_a_generated_zone() {
    let (image, names) = generated(100_000);
    let production = ZoneIndex::build(&image);
    let reference = MemIndex::build(&image);
    assert_eq!(production.revision(), reference.revision());
    let stats = production.stats();
    assert_eq!(stats.zones, 4);
    assert!(stats.base_nodes > 100_000, "{stats:?}");
    let internal = Scoped(internal());
    let mut rng = Rng(7);
    for (index, qname) in names.iter().enumerate() {
        same(&production, &reference, &DefaultScopes, qname, Rtype::A);
        let qtype = *rng.pick(&TYPES);
        same(&production, &reference, &DefaultScopes, qname, qtype);
        if index % 10 == 0 {
            same(&production, &reference, &internal, qname, qtype);
        }
        // The reference walks the whole zone backwards when it has no NSEC chain, so the
        // covering is compared in the signed zone and on a sparse sample elsewhere.
        if qname.ends_with(b"\x06signed\x04test\x00") || index % 5000 == 0 {
            same_nsec(&production, &reference, &DefaultScopes, qname);
        }
    }
}

/// A random change: one RRset of a pool of owners set or removed.
fn random_change(rng: &mut Rng, zones: &[Zone], pool: &[String]) -> Change {
    let zone = rng.pick(zones);
    let apex = zone.name.as_str();
    let scope = if rng.chance(20) {
        internal()
    } else {
        ScopeName::DEFAULT
    };
    let owner = if rng.chance(10) {
        apex.to_string()
    } else {
        format!("{}.{apex}", rng.pick(pool))
    };
    let target = format!("{}.{apex}", rng.pick(pool));
    let data = match rng.below(10) {
        0 => vec![a(1), a(2)],
        1 => vec![aaaa(3)],
        2 => vec![txt("t")],
        3 => vec![mx(5, &target)],
        4 => vec![ns(&format!("ns.{owner}"))],
        5 => vec![ds()],
        6 => vec![dname("example.net")],
        7 => vec![cname(&target)],
        8 => vec![nsec(&target)],
        _ => vec![soa(apex, 60)],
    };
    let set = rrset(zone, &scope, &owner, &data);
    if rng.chance(35) {
        Change::RrSet(set.key(), None)
    } else {
        Change::RrSet(set.key(), Some(set))
    }
}

#[test]
fn the_index_agrees_with_the_reference_after_every_delta() {
    let zones = vec![
        zone("example.test"),
        zone("sub.example.test"),
        zone("other.test"),
    ];
    let pool: Vec<String> = [
        "www", "mail", "a.b", "b", "c.b", "*", "*.b", "deep.a.b", "cut", "x.cut", "*.cut",
        "ns.cut", "dn", "x.dn", "y.x.dn", "sub", "q.sub", "host.sub", "*.sub", "e.f.g.h", "f.g.h",
        "h",
    ]
    .iter()
    .map(ToString::to_string)
    .chain((0..1500).map(|n| format!("n{n}")))
    .chain((0..300).map(|n| format!("m{n}.g.h")))
    .collect();
    let mut image = DnsData::at(Revision(1));
    for set in &zones {
        image.zones.insert(set.id, set.clone());
    }
    let mut rng = Rng(42);
    for _ in 0..3000 {
        if let Change::RrSet(key, Some(set)) = random_change(&mut rng, &zones, &pool) {
            image.rrsets.insert(key, set);
        }
    }
    let mut production = ZoneIndex::build(&image);
    let mut names: Vec<Vec<u8>> = Vec::new();
    for set in &zones {
        let apex = set.name.as_str();
        names.push(wire(apex));
        for owner in &pool {
            names.push(wire(&format!("{owner}.{apex}").replace('*', "star")));
            names.push(wire(&format!("{owner}.{apex}")));
            names.push(wire(&format!("zz.{owner}.{apex}")));
        }
    }
    names.push(wire("nothing.test"));
    let internal_scope = Scoped(internal());
    let mut compacted = false;
    let mut overlay_seen = 0;
    for step in 0..120 {
        let mut changes = Vec::new();
        for _ in 0..=rng.below(40) {
            changes.push(random_change(&mut rng, &zones, &pool));
        }
        if step % 30 == 17 {
            // A zone leaves with its RRsets still in the store, and comes back later.
            changes.push(Change::Zone(zones[1].id, None));
        }
        if step % 30 == 23 {
            changes.push(Change::Zone(zones[1].id, Some(zones[1].clone())));
        }
        if step == 50 {
            let mut renamed = zones[2].clone();
            renamed.kind = tenko_core::dns::ZoneKind::Secondary;
            changes.push(Change::Zone(renamed.id, Some(renamed)));
        }
        let delta = Delta {
            from: image.revision,
            to: image.revision.next(),
            changes,
        };
        image.apply(&delta).expect("image");
        production = production.apply(&delta).expect("delta");
        assert!(production.apply(&delta).is_err(), "a delta applies once");
        let stats = production.stats();
        if stats.overlay_nodes < overlay_seen {
            compacted = true;
        }
        overlay_seen = stats.overlay_nodes;
        let reference = MemIndex::build(&image);
        assert_eq!(production.revision(), reference.revision());
        for (index, qname) in names.iter().enumerate() {
            if (index + step) % 4 != 0 {
                continue;
            }
            let qtype = *rng.pick(&TYPES);
            same(&production, &reference, &DefaultScopes, qname, qtype);
            if index % 3 == 0 {
                same(&production, &reference, &internal_scope, qname, qtype);
            }
            if index % 5 == 0 {
                same_nsec(&production, &reference, &DefaultScopes, qname);
            }
        }
    }
    assert!(
        compacted,
        "the overlay was folded into a new base at least once"
    );
    // A fresh build of the last image agrees with the index the deltas made.
    let fresh = ZoneIndex::build(&image);
    for qname in &names {
        for qtype in TYPES {
            assert_eq!(
                fresh.lookup(&DefaultScopes, qname, qtype),
                production.lookup(&DefaultScopes, qname, qtype)
            );
        }
    }
}
