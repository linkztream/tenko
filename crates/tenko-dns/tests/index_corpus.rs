//! A hand-written corpus of the special cases of the index: wildcards and zone cuts, empty
//! non-terminals, DNAMEs, occlusion, glue, case, CNAME chains and nested zones. Every case
//! asserts the exact `Lookup` of the production index (`ZoneIndex`) and that the reference
//! (`MemIndex`) gives the same one, and for chains the same `resolve` result and steps.

mod support;

use support::{a, aaaa, cname, dname, name, ns, rrset, soa, txt, wire, zone};
use tenko_core::{
    Revision,
    dns::{Rdata, RecordData, RrSet, Rtype, ScopeName, Zone, check_node},
    serde_util::HexBytes,
};
use tenko_dns::{
    DnsData, Index, Lookup, MemIndex, NameBuf,
    index::{Chain, DefaultScopes, MAX_CHAIN},
    tree::ZoneIndex,
};

fn ds() -> RecordData {
    RecordData::Ds {
        key_tag: 1,
        algorithm: 13,
        digest_type: 2,
        digest: HexBytes(vec![7; 32]),
    }
}

fn rdata(data: &[RecordData]) -> Vec<Rdata> {
    data.iter().map(Rdata::from_data).collect()
}

fn apex_of(zone: &Zone) -> Vec<u8> {
    NameBuf::from_dns_name(&zone.name).as_wire().to_vec()
}

/// A zone with its SOA and an apex NS set, the minimum of a complete zone.
fn base(apex: &str) -> (Zone, Vec<RrSet>) {
    let zone = zone(apex);
    let default = ScopeName::DEFAULT;
    let sets = vec![
        rrset(&zone, &default, apex, &[soa(apex, 300)]),
        rrset(&zone, &default, apex, &[ns(&format!("ns1.{apex}"))]),
        rrset(&zone, &default, &format!("ns1.{apex}"), &[a(53)]),
    ];
    (zone, sets)
}

/// `owner` with `data` in the default scope of `zone`.
fn put(zone: &Zone, owner: &str, data: &[RecordData]) -> RrSet {
    rrset(zone, &ScopeName::DEFAULT, owner, data)
}

/// Both indexes built from the same image.
struct Pair {
    production: ZoneIndex,
    reference: MemIndex,
}

impl Pair {
    fn new(zones: &[&Zone], sets: Vec<RrSet>) -> Self {
        let mut image = DnsData::at(Revision(1));
        for zone in zones {
            image.zones.insert(zone.id, Zone::clone(zone));
        }
        for set in sets {
            image.rrsets.insert(set.key(), set);
        }
        Self {
            production: ZoneIndex::build(&image),
            reference: MemIndex::build(&image),
        }
    }

    /// The production lookup, after asserting that the reference gives an equal one.
    fn lookup(&self, qname: &str, qtype: Rtype) -> Lookup<'_> {
        self.lookup_wire(&wire(qname), qtype)
    }

    fn lookup_wire(&self, qname: &[u8], qtype: Rtype) -> Lookup<'_> {
        let production = self.production.lookup(&DefaultScopes, qname, qtype);
        let reference = self.reference.lookup(&DefaultScopes, qname, qtype);
        assert_eq!(production, reference, "lookup {qname:?} {qtype}");
        production
    }

    /// The production `resolve`, after asserting that the reference gives the same last
    /// lookup, the same `exhausted` and the same steps.
    fn resolve(&self, qname: &str, qtype: Rtype) -> (Lookup<'_>, Chain<'_>) {
        let qname = wire(qname);
        let mut chain_p = Chain::default();
        let last_p = self
            .production
            .resolve(&DefaultScopes, &qname, qtype, &mut chain_p);
        let mut chain_r = Chain::default();
        let last_r = self
            .reference
            .resolve(&DefaultScopes, &qname, qtype, &mut chain_r);
        assert_eq!(last_p, last_r, "resolve {qname:?} {qtype}");
        assert_eq!(chain_p.exhausted, chain_r.exhausted, "exhausted {qname:?}");
        assert_eq!(chain_p.len(), chain_r.len(), "chain length {qname:?}");
        assert!(chain_p.steps().eq(chain_r.steps()), "steps {qname:?}");
        (last_p, chain_p)
    }

    /// The A and AAAA of `name` as (A rdata, AAAA rdata), after asserting agreement.
    fn addresses(&self, name: &str) -> [Option<Vec<Rdata>>; 2] {
        let name = wire(name);
        let production = self.production.addresses(&DefaultScopes, &name);
        let reference = self.reference.addresses(&DefaultScopes, &name);
        assert_eq!(production, reference, "addresses {name:?}");
        production.map(|set| set.map(|view| view.rdata.to_vec()))
    }
}

fn assert_zone(view: &tenko_dns::index::ZoneView<'_>, zone: &Zone) {
    assert_eq!(view.id, zone.id, "zone id");
    assert_eq!(view.apex, apex_of(zone).as_slice(), "zone apex");
    assert_eq!(*view.scope, ScopeName::DEFAULT, "scope");
}

fn assert_soa(soa: Option<tenko_dns::index::RrSetView<'_>>, zone: &Zone, present: bool) {
    if present {
        let soa = soa.expect("the negative answer carries the SOA");
        assert_eq!(soa.owner, apex_of(zone).as_slice());
        assert_eq!(soa.rtype, Rtype::SOA);
    } else {
        assert!(soa.is_none(), "no SOA expected");
    }
}

fn expect_answer(
    lookup: Lookup<'_>,
    zone: &Zone,
    owner: &str,
    rtype: Rtype,
    data: &[RecordData],
    source: Option<&str>,
) {
    let Lookup::Answer {
        zone: view,
        rrset,
        wildcard,
    } = lookup
    else {
        panic!("expected an Answer for {owner}, got {lookup:?}");
    };
    assert_zone(&view, zone);
    assert_eq!(rrset.owner, wire(owner).as_slice(), "owner");
    assert_eq!(rrset.rtype, rtype, "type");
    assert_eq!(rrset.rdata, rdata(data).as_slice(), "rdata");
    assert_eq!(wildcard, source.map(wire).as_deref(), "wildcard source");
}

fn expect_cname(lookup: Lookup<'_>, zone: &Zone, owner: &str, target: &str) {
    let Lookup::Cname {
        zone: view,
        cname: set,
        wildcard,
    } = lookup
    else {
        panic!("expected a Cname for {owner}, got {lookup:?}");
    };
    assert_zone(&view, zone);
    assert_eq!(set.owner, wire(owner).as_slice());
    assert_eq!(set.rtype, Rtype::CNAME);
    assert_eq!(set.rdata, rdata(&[cname(target)]).as_slice());
    assert_eq!(wildcard, None);
}

fn expect_dname(lookup: Lookup<'_>, zone: &Zone, owner: &str, target: &str) {
    let Lookup::Dname {
        zone: view,
        dname: set,
    } = lookup
    else {
        panic!("expected a Dname above {owner}, got {lookup:?}");
    };
    assert_zone(&view, zone);
    assert_eq!(set.owner, wire(owner).as_slice());
    assert_eq!(set.rtype, Rtype::DNAME);
    assert_eq!(set.rdata, rdata(&[dname(target)]).as_slice());
}

fn expect_delegation(
    lookup: Lookup<'_>,
    zone: &Zone,
    cut: &str,
    servers: &[RecordData],
    signed: bool,
) {
    let Lookup::Delegation { zone: view, ns, ds } = lookup else {
        panic!("expected a Delegation at {cut}, got {lookup:?}");
    };
    assert_zone(&view, zone);
    assert_eq!(ns.owner, wire(cut).as_slice());
    assert_eq!(ns.rtype, Rtype::NS);
    assert_eq!(ns.rdata, rdata(servers).as_slice());
    if signed {
        let ds = ds.expect("the delegation carries the DS");
        assert_eq!(ds.owner, wire(cut).as_slice());
        assert_eq!(ds.rtype, Rtype::DS);
        assert_eq!(ds.rdata, rdata(&[self::ds()]).as_slice());
    } else {
        assert!(ds.is_none(), "no DS expected");
    }
}

fn expect_nodata(lookup: Lookup<'_>, zone: &Zone, source: Option<&str>) {
    let Lookup::NoData {
        zone: view,
        soa,
        wildcard,
    } = lookup
    else {
        panic!("expected NoData, got {lookup:?}");
    };
    assert_zone(&view, zone);
    assert_soa(soa, zone, true);
    assert_eq!(wildcard, source.map(wire).as_deref(), "wildcard source");
}

fn expect_nxdomain(lookup: Lookup<'_>, zone: &Zone, encloser: &str) {
    let Lookup::NxDomain {
        zone: view,
        soa,
        closest_encloser,
    } = lookup
    else {
        panic!("expected NxDomain, got {lookup:?}");
    };
    assert_zone(&view, zone);
    assert_soa(soa, zone, true);
    assert_eq!(
        closest_encloser,
        wire(encloser).as_slice(),
        "closest encloser"
    );
}

#[test]
fn wildcard_is_occluded_by_a_zone_cut_and_stops_at_existing_nodes() {
    let (zone, mut sets) = base("example.test");
    sets.extend([
        put(&zone, "*.example.test", &[a(1)]),
        put(&zone, "www.example.test", &[a(2)]),
        put(&zone, "www2.example.test", &[a(3)]),
        put(&zone, "*.www2.example.test", &[a(4)]),
        put(&zone, "cut.example.test", &[ns("ns.cut.example.test")]),
        put(&zone, "ns.cut.example.test", &[a(5)]),
        put(&zone, "*.cut.example.test", &[a(6)]),
    ]);
    let pair = Pair::new(&[&zone], sets);
    let cut_ns = [ns("ns.cut.example.test")];

    // The wildcard below the cut is occluded: the referral wins, also for the wildcard
    // owner itself and for the glue name.
    for qname in [
        "x.cut.example.test",
        "*.cut.example.test",
        "a.b.cut.example.test",
    ] {
        expect_delegation(
            pair.lookup(qname, Rtype::A),
            &zone,
            "cut.example.test",
            &cut_ns,
            false,
        );
    }
    // The apex wildcard answers names that do not exist, with the owner of the source.
    expect_answer(
        pair.lookup("x.example.test", Rtype::A),
        &zone,
        "*.example.test",
        Rtype::A,
        &[a(1)],
        Some("*.example.test"),
    );
    // A type the wildcard lacks is NoData and still names the source.
    expect_nodata(
        pair.lookup("x.example.test", Rtype::AAAA),
        &zone,
        Some("*.example.test"),
    );
    // The wildcard does not reach below an existing node (RFC 4592): the closest encloser
    // is the existing parent, and the wildcard of the apex is not consulted.
    expect_nxdomain(
        pair.lookup("y.www.example.test", Rtype::A),
        &zone,
        "www.example.test",
    );
    expect_nxdomain(
        pair.lookup("a.y.www.example.test", Rtype::A),
        &zone,
        "www.example.test",
    );
    // ... unless that node has a wildcard of its own.
    expect_answer(
        pair.lookup("y.www2.example.test", Rtype::A),
        &zone,
        "*.www2.example.test",
        Rtype::A,
        &[a(4)],
        Some("*.www2.example.test"),
    );
    // Existing names answer themselves, not the wildcard.
    expect_answer(
        pair.lookup("www.example.test", Rtype::A),
        &zone,
        "www.example.test",
        Rtype::A,
        &[a(2)],
        None,
    );
}

#[test]
fn empty_non_terminals_have_no_data_and_are_not_wildcard_matches() {
    for with_wildcard in [false, true] {
        let (zone, mut sets) = base("example.test");
        sets.extend([
            put(&zone, "*.example.test", &[a(1)]),
            put(&zone, "a.b.c.example.test", &[a(2)]),
        ]);
        if with_wildcard {
            sets.push(put(&zone, "*.c.example.test", &[a(3)]));
        }
        let pair = Pair::new(&[&zone], sets);

        expect_answer(
            pair.lookup("a.b.c.example.test", Rtype::A),
            &zone,
            "a.b.c.example.test",
            Rtype::A,
            &[a(2)],
            None,
        );
        // The empty non-terminals exist: NoData, not NxDomain, and not the apex wildcard.
        for qname in ["b.c.example.test", "c.example.test"] {
            for qtype in [Rtype::A, Rtype::AAAA, Rtype::ANY, Rtype::TXT] {
                expect_nodata(pair.lookup(qname, qtype), &zone, None);
            }
        }
        if with_wildcard {
            expect_answer(
                pair.lookup("z.c.example.test", Rtype::A),
                &zone,
                "*.c.example.test",
                Rtype::A,
                &[a(3)],
                Some("*.c.example.test"),
            );
            // Below b.c the closest encloser b.c has no wildcard of its own.
            expect_nxdomain(
                pair.lookup("z.b.c.example.test", Rtype::A),
                &zone,
                "b.c.example.test",
            );
        } else {
            expect_nxdomain(
                pair.lookup("z.c.example.test", Rtype::A),
                &zone,
                "c.example.test",
            );
            expect_nxdomain(
                pair.lookup("z.b.c.example.test", Rtype::A),
                &zone,
                "b.c.example.test",
            );
        }
    }
}

#[test]
fn model_refuses_a_cname_at_the_apex_and_beside_other_data() {
    let zone = zone("example.test");
    let apex = name("example.test");
    let default = ScopeName::DEFAULT;

    let at_apex = rrset(
        &zone,
        &default,
        "example.test",
        &[cname("target.example.test")],
    );
    assert!(at_apex.check(&apex).is_err(), "CNAME at the apex");
    // The same set below the apex is fine for the single-set rules.
    let below = rrset(
        &zone,
        &default,
        "www.example.test",
        &[cname("target.example.test")],
    );
    below.check(&apex).expect("CNAME below the apex");

    let data = rrset(&zone, &default, "www.example.test", &[a(1)]);
    assert!(
        check_node(&apex, [&below, &data]).is_err(),
        "CNAME beside A"
    );
    let text = rrset(&zone, &default, "www.example.test", &[txt("x")]);
    assert!(
        check_node(&apex, [&text, &below]).is_err(),
        "CNAME beside TXT"
    );
    check_node(&apex, [&below]).expect("CNAME alone");
    check_node(&apex, [&data, &text]).expect("plain data together");
}

#[test]
fn dname_redirects_names_below_it_and_answers_itself() {
    let (zone, mut sets) = base("example.test");
    let (alias, alias_sets) = base("alias.test");
    sets.push(put(&zone, "old.example.test", &[dname("example.net")]));
    // A hidden node below the DNAME is never reached.
    sets.push(put(&zone, "hidden.old.example.test", &[a(7)]));
    sets.extend(alias_sets);
    sets.push(put(&alias, "alias.test", &[dname("example.test")]));
    let pair = Pair::new(&[&zone, &alias], sets);

    expect_dname(
        pair.lookup("www.old.example.test", Rtype::A),
        &zone,
        "old.example.test",
        "example.net",
    );
    expect_dname(
        pair.lookup("hidden.old.example.test", Rtype::A),
        &zone,
        "old.example.test",
        "example.net",
    );
    expect_dname(
        pair.lookup("a.b.old.example.test", Rtype::AAAA),
        &zone,
        "old.example.test",
        "example.net",
    );
    // The owner of a DNAME is not redirected: its own types answer, others are NoData.
    expect_answer(
        pair.lookup("old.example.test", Rtype::DNAME),
        &zone,
        "old.example.test",
        Rtype::DNAME,
        &[dname("example.net")],
        None,
    );
    expect_nodata(pair.lookup("old.example.test", Rtype::A), &zone, None);

    // A DNAME at a zone apex redirects the names below it (RFC 6672) ...
    expect_dname(
        pair.lookup("www.alias.test", Rtype::A),
        &alias,
        "alias.test",
        "example.test",
    );
    // ... but the apex answers its own data.
    expect_answer(
        pair.lookup("alias.test", Rtype::SOA),
        &alias,
        "alias.test",
        Rtype::SOA,
        &[soa("alias.test", 300)],
        None,
    );
    expect_answer(
        pair.lookup("alias.test", Rtype::DNAME),
        &alias,
        "alias.test",
        Rtype::DNAME,
        &[dname("example.test")],
        None,
    );
    expect_nodata(pair.lookup("alias.test", Rtype::A), &alias, None);
}

#[test]
fn everything_at_or_below_a_cut_is_a_delegation_except_the_ds() {
    let (zone, mut sets) = base("example.test");
    sets.extend([
        put(&zone, "cut.example.test", &[ns("ns.cut.example.test")]),
        put(&zone, "cut.example.test", &[ds()]),
        put(&zone, "ns.cut.example.test", &[a(5)]),
        put(&zone, "deep.x.cut.example.test", &[a(6)]),
        put(&zone, "plain.example.test", &[a(7)]),
    ]);
    let pair = Pair::new(&[&zone], sets);
    let cut_ns = [ns("ns.cut.example.test")];

    for qname in [
        "cut.example.test",
        "ns.cut.example.test",
        "x.cut.example.test",
        "deep.x.cut.example.test",
        "unknown.cut.example.test",
    ] {
        for qtype in [Rtype::A, Rtype::AAAA, Rtype::TXT, Rtype::ANY] {
            expect_delegation(
                pair.lookup(qname, qtype),
                &zone,
                "cut.example.test",
                &cut_ns,
                true,
            );
        }
    }
    // The NS query at the cut is a referral too.
    expect_delegation(
        pair.lookup("cut.example.test", Rtype::NS),
        &zone,
        "cut.example.test",
        &cut_ns,
        true,
    );
    // The DS at the cut belongs to the parent: it answers.
    expect_answer(
        pair.lookup("cut.example.test", Rtype::DS),
        &zone,
        "cut.example.test",
        Rtype::DS,
        &[ds()],
        None,
    );
    // A DS query below the cut is still a referral.
    expect_delegation(
        pair.lookup("x.cut.example.test", Rtype::DS),
        &zone,
        "cut.example.test",
        &cut_ns,
        true,
    );
    // A neighbour of the cut is unaffected.
    expect_answer(
        pair.lookup("plain.example.test", Rtype::A),
        &zone,
        "plain.example.test",
        Rtype::A,
        &[a(7)],
        None,
    );
}

#[test]
fn glue_addresses_come_from_the_zone_even_below_a_cut() {
    let (zone, mut sets) = base("example.test");
    sets.extend([
        put(
            &zone,
            "cut.example.test",
            &[
                ns("ns.cut.example.test"),
                ns("ns1.example.test"),
                ns("ns.example.net"),
            ],
        ),
        put(&zone, "ns.cut.example.test", &[a(54), a(55)]),
        put(&zone, "ns.cut.example.test", &[aaaa(54)]),
    ]);
    let pair = Pair::new(&[&zone], sets);

    // Glue below the cut: both families.
    assert_eq!(
        pair.addresses("ns.cut.example.test"),
        [Some(rdata(&[a(54), a(55)])), Some(rdata(&[aaaa(54)]))]
    );
    // In the parent zone, outside the cut: the A only.
    assert_eq!(
        pair.addresses("ns1.example.test"),
        [Some(rdata(&[a(53)])), None]
    );
    // Outside every zone: nothing.
    assert_eq!(pair.addresses("ns.example.net"), [None, None]);
    // A name that holds no address.
    assert_eq!(pair.addresses("cut.example.test"), [None, None]);
    assert_eq!(pair.addresses("missing.example.test"), [None, None]);
    // The cut itself lists all three servers in the referral.
    expect_delegation(
        pair.lookup("www.cut.example.test", Rtype::A),
        &zone,
        "cut.example.test",
        &[
            ns("ns.cut.example.test"),
            ns("ns1.example.test"),
            ns("ns.example.net"),
        ],
        false,
    );
}

#[test]
fn names_are_matched_in_lowercase_wire_form() {
    let (zone, mut sets) = base("example.test");
    sets.push(put(&zone, "www.example.test", &[a(1)]));
    let pair = Pair::new(&[&zone], sets);

    let mixed = NameBuf::from_wire(b"\x03WWW\x07Example\x04TEST\x00").expect("name");
    assert_eq!(mixed.as_wire(), b"\x03www\x07example\x04test\x00");
    assert_eq!(mixed.as_wire(), wire("www.example.test").as_slice());
    let lookup = pair.lookup_wire(mixed.as_wire(), Rtype::A);
    assert_eq!(lookup, pair.lookup("www.example.test", Rtype::A));
    expect_answer(lookup, &zone, "www.example.test", Rtype::A, &[a(1)], None);
}

#[test]
fn chains_stop_at_the_limit_and_on_loops_and_leave_the_zones() {
    let (zone, mut sets) = base("example.test");
    // c0 -> c1 -> ... -> c12, twelve CNAMEs and an A at the end.
    for n in 0..12 {
        sets.push(put(
            &zone,
            &format!("c{n}.example.test"),
            &[cname(&format!("c{}.example.test", n + 1))],
        ));
    }
    sets.push(put(&zone, "c12.example.test", &[a(12)]));
    sets.extend([
        put(&zone, "loop1.example.test", &[cname("loop2.example.test")]),
        put(&zone, "loop2.example.test", &[cname("loop1.example.test")]),
        put(&zone, "self.example.test", &[cname("self.example.test")]),
        put(&zone, "out.example.test", &[cname("www.example.net")]),
        put(&zone, "alias.example.test", &[cname("c12.example.test")]),
    ]);
    let pair = Pair::new(&[&zone], sets);

    // Twelve steps do not fit: the chain keeps MAX_CHAIN of them and says so.
    let (last, chain) = pair.resolve("c0.example.test", Rtype::A);
    assert!(chain.exhausted);
    assert_eq!(chain.len(), MAX_CHAIN);
    let owners: Vec<Vec<u8>> = chain
        .steps()
        .map(|(_, set, _)| set.owner.to_vec())
        .collect();
    let expected: Vec<Vec<u8>> = (0..MAX_CHAIN)
        .map(|n| wire(&format!("c{n}.example.test")))
        .collect();
    assert_eq!(owners, expected);
    expect_cname(last, &zone, "c8.example.test", "c9.example.test");

    // Seven steps (c5 ... c11) reach the A.
    let (last, chain) = pair.resolve("c5.example.test", Rtype::A);
    assert!(!chain.exhausted);
    assert_eq!(chain.len(), 7);
    for (zone_view, set, source) in chain.steps() {
        assert_zone(&zone_view, &zone);
        assert_eq!(set.rtype, Rtype::CNAME);
        assert_eq!(source, None);
    }
    expect_answer(last, &zone, "c12.example.test", Rtype::A, &[a(12)], None);
    // Exactly MAX_CHAIN steps still succeed.
    let (last, chain) = pair.resolve("c4.example.test", Rtype::A);
    assert!(!chain.exhausted);
    assert_eq!(chain.len(), MAX_CHAIN);
    expect_answer(last, &zone, "c12.example.test", Rtype::A, &[a(12)], None);

    // A two-name loop and a self-loop stop at once.
    let (last, chain) = pair.resolve("loop1.example.test", Rtype::A);
    assert!(chain.exhausted);
    assert_eq!(chain.len(), 2);
    expect_cname(last, &zone, "loop1.example.test", "loop2.example.test");
    let (last, chain) = pair.resolve("self.example.test", Rtype::A);
    assert!(chain.exhausted);
    assert_eq!(chain.len(), 1);
    expect_cname(last, &zone, "self.example.test", "self.example.test");

    // A target outside every zone ends the chain with NotAuthoritative after one step.
    let (last, chain) = pair.resolve("out.example.test", Rtype::A);
    assert!(!chain.exhausted);
    assert_eq!(chain.len(), 1);
    assert_eq!(last, Lookup::NotAuthoritative);

    // The CNAME type itself answers the CNAME and follows nothing.
    let (last, chain) = pair.resolve("alias.example.test", Rtype::CNAME);
    assert!(chain.is_empty());
    assert!(!chain.exhausted);
    expect_answer(
        last,
        &zone,
        "alias.example.test",
        Rtype::CNAME,
        &[cname("c12.example.test")],
        None,
    );
    // Another type follows it.
    let (last, chain) = pair.resolve("alias.example.test", Rtype::A);
    assert_eq!(chain.len(), 1);
    expect_answer(last, &zone, "c12.example.test", Rtype::A, &[a(12)], None);
}

#[test]
fn nested_zone_answers_for_its_own_names_and_wins_the_ds() {
    let (parent, mut sets) = base("example.test");
    let (child, child_sets) = base("sub.example.test");
    sets.extend([
        put(&parent, "sub.example.test", &[ns("ns2.sub.example.test")]),
        put(&parent, "sub.example.test", &[ds()]),
        put(&parent, "ns2.sub.example.test", &[a(60)]),
        put(&parent, "www.example.test", &[a(1)]),
    ]);
    sets.extend(child_sets);
    sets.push(put(&child, "www.sub.example.test", &[a(2)]));
    let pair = Pair::new(&[&parent, &child], sets);

    // Names of the child zone answer from the child zone.
    expect_answer(
        pair.lookup("www.sub.example.test", Rtype::A),
        &child,
        "www.sub.example.test",
        Rtype::A,
        &[a(2)],
        None,
    );
    expect_answer(
        pair.lookup("sub.example.test", Rtype::SOA),
        &child,
        "sub.example.test",
        Rtype::SOA,
        &[soa("sub.example.test", 300)],
        None,
    );
    expect_answer(
        pair.lookup("sub.example.test", Rtype::NS),
        &child,
        "sub.example.test",
        Rtype::NS,
        &[ns("ns1.sub.example.test")],
        None,
    );
    expect_nxdomain(
        pair.lookup("nope.sub.example.test", Rtype::A),
        &child,
        "sub.example.test",
    );
    // The longest apex wins: the NS of the parent at the child apex is not a referral
    // and the DS the parent holds is not visible; both indexes answer NoData from the
    // child zone.
    expect_nodata(pair.lookup("sub.example.test", Rtype::DS), &child, None);
    expect_nodata(pair.lookup("sub.example.test", Rtype::A), &child, None);
    // Records the parent holds below its own cut are shadowed by the child zone.
    expect_nxdomain(
        pair.lookup("ns2.sub.example.test", Rtype::A),
        &child,
        "sub.example.test",
    );
    assert_eq!(pair.addresses("ns2.sub.example.test"), [None, None]);
    // The parent keeps its own names.
    expect_answer(
        pair.lookup("www.example.test", Rtype::A),
        &parent,
        "www.example.test",
        Rtype::A,
        &[a(1)],
        None,
    );
    expect_nxdomain(
        pair.lookup("nope.example.test", Rtype::A),
        &parent,
        "example.test",
    );
}

#[test]
fn corpus_names_outside_every_zone_are_not_authoritative() {
    let (zone, sets) = base("example.test");
    let pair = Pair::new(&[&zone], sets);
    for qname in ["example.net", "test", "other.test", "xexample.test"] {
        assert_eq!(
            pair.lookup(qname, Rtype::A),
            Lookup::NotAuthoritative,
            "{qname}"
        );
    }
}
