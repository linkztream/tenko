//! The authoritative resolver and the responder end to end, without sockets: a query's
//! octets in, the answer's octets out, decoded here and by `hickory-proto`. One case per
//! rule of the lookup: positive answers and their additional data, wildcards with the case
//! of the question kept, negative answers with the SOA TTL of RFC 2308, referrals with the
//! glue of RFC 9471, DS at a cut, CNAME chains and their limit, DNAME synthesis, ANY (RFC
//! 8482), the RCODEs of the header checks, EDNS and cookies, views, forwarding, the policy
//! and the rate limiter hooks.

mod support;

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Instant,
};

use support::{
    a, aaaa,
    answer::{Answer, decode, query},
    cname, dname, internal, mx, name, ns, rrset, rrset_ttl, soa, zone,
};
use tenko_core::{
    Revision,
    dns::{
        BlockAction, BlockListId, ForwardRule, ForwardRuleId, ForwardTransport, MatchRule,
        QueryTransport, RecordData, RrSet, Rtype, ScopeName, ScopeWeight, Upstream, View, ViewId,
        Zone,
    },
    serde_util::HexBytes,
};
use tenko_dns::{
    DnsData,
    authoritative::{Authoritative, EDE_NOT_AUTHORITATIVE, EDE_PROHIBITED, Settings, rcode},
    catalog::{Catalog, CatalogHandle},
    cookie::{CookieMode, CookieSecret},
    policy::{EDE_BLOCKED, PolicyEngine, Verdict},
    rate::{RateDecision, RateLimiter, ResponseKind},
    respond::{Clock, Conn, ForwardQuery, ForwardSink, Reply, Responder, Scratch},
};

const A: u16 = 1;
const NS: u16 = 2;
const CNAME: u16 = 5;
const SOA: u16 = 6;
const MX: u16 = 15;
const AAAA: u16 = 28;
const SRV: u16 = 33;
const DNAME: u16 = 39;
const DS: u16 = 43;
const ANY: u16 = 255;

struct Fixture {
    image: DnsData,
    parent: Zone,
    view: ViewId,
    rule: ForwardRuleId,
}

fn set(image: &mut DnsData, rrset: RrSet) {
    image.rrsets.insert(rrset.key(), rrset);
}

fn srv(target: &str) -> RecordData {
    RecordData::Srv {
        priority: 0,
        weight: 5,
        port: 5060,
        target: name(target),
    }
}

fn long_label(letter: char, len: usize) -> String {
    std::iter::repeat_n(letter, len).collect()
}

#[allow(clippy::too_many_lines, reason = "one data set, written out")]
fn fixture() -> Fixture {
    let parent = zone("example.test");
    let default = ScopeName::DEFAULT;
    let mut image = DnsData::at(Revision(3));
    let p = &parent;
    for rrset in [
        rrset_ttl(
            p,
            &default,
            "example.test",
            3600,
            &[soa("example.test", 60)],
        ),
        rrset(
            p,
            &default,
            "example.test",
            &[ns("ns1.example.test"), ns("ns2.example.test")],
        ),
        rrset(p, &default, "ns1.example.test", &[a(53)]),
        rrset(p, &default, "ns2.example.test", &[aaaa(53)]),
        rrset(p, &default, "www.example.test", &[a(1), a(2)]),
        rrset(p, &internal(), "example.test", &[soa("example.test", 60)]),
        rrset(p, &internal(), "www.example.test", &[a(100)]),
        rrset(p, &default, "*.wild.example.test", &[a(9)]),
        rrset(
            p,
            &default,
            "mail.example.test",
            &[
                mx(10, "mx1.example.test"),
                mx(20, "mx.example.net"),
                mx(30, "mx1.example.test"),
            ],
        ),
        rrset(p, &default, "mx1.example.test", &[a(25)]),
        rrset(p, &default, "mx1.example.test", &[aaaa(25)]),
        rrset(
            p,
            &default,
            "_sip._tcp.example.test",
            &[srv("sip.example.test")],
        ),
        rrset(p, &default, "sip.example.test", &[a(60)]),
        rrset(
            p,
            &default,
            "alias.example.test",
            &[cname("www.example.test")],
        ),
        rrset(
            p,
            &default,
            "alias2.example.test",
            &[cname("alias.example.test")],
        ),
        rrset(p, &default, "out.example.test", &[cname("www.example.net")]),
        rrset(
            p,
            &default,
            "loop1.example.test",
            &[cname("loop2.example.test")],
        ),
        rrset(
            p,
            &default,
            "loop2.example.test",
            &[cname("loop1.example.test")],
        ),
        rrset(
            p,
            &default,
            "child.example.test",
            &[
                ns("ns.child.example.test"),
                ns("ns1.example.test"),
                ns("ns.example.net"),
            ],
        ),
        rrset(
            p,
            &default,
            "child.example.test",
            &[RecordData::Ds {
                key_tag: 1,
                algorithm: 13,
                digest_type: 2,
                digest: HexBytes(vec![7; 32]),
            }],
        ),
        rrset(p, &default, "ns.child.example.test", &[a(54)]),
        rrset(p, &default, "old.example.test", &[dname("example.net")]),
        rrset(p, &default, "here.example.test", &[dname("example.test")]),
        rrset(
            p,
            &default,
            "big.example.test",
            &[dname(&format!(
                "{}.{}.{}.example.test",
                long_label('x', 63),
                long_label('y', 63),
                long_label('z', 63)
            ))],
        ),
    ] {
        set(&mut image, rrset);
    }
    let mut previous = "c0.example.test".to_string();
    for step in 1..=10 {
        let next = format!("c{step}.example.test");
        set(&mut image, rrset(p, &default, &previous, &[cname(&next)]));
        previous = next;
    }
    set(&mut image, rrset(p, &default, &previous, &[a(10)]));
    image.zones.insert(parent.id, parent.clone());
    let view = View {
        id: ViewId::generate(),
        name: "lab".to_string(),
        rules: vec![MatchRule::ClientSubnet {
            prefixes: vec!["198.51.100.0/24".parse().expect("prefix")],
        }],
        scope_map: vec![ScopeWeight {
            zone: parent.id,
            scope: internal(),
            weight: 1,
        }],
        order: 1,
        recursion: None,
        description: None,
    };
    let rule = ForwardRule {
        id: ForwardRuleId::generate(),
        suffix: name("example.net"),
        upstreams: vec![Upstream {
            address: "192.0.2.200".parse().expect("address"),
            port: None,
            path: None,
        }],
        transport: ForwardTransport::Plain,
        tls_name: None,
        view: None,
        description: None,
    };
    let (view_id, rule_id) = (view.id, rule.id);
    image.views.insert(view.id, view);
    image.forwarders.insert(rule.id, rule);
    Fixture {
        image,
        parent,
        view: view_id,
        rule: rule_id,
    }
}

struct Engine {
    responder: Responder<Authoritative>,
    scratch: Scratch,
    clock: Clock,
}

fn handle(image: &DnsData) -> CatalogHandle {
    CatalogHandle::new(Catalog::build(image))
}

impl Engine {
    fn new(resolver: Authoritative) -> Self {
        Self::with(Responder::new(resolver, CookieSecret::with_secret([3; 16])).with_metrics(false))
    }

    fn with(responder: Responder<Authoritative>) -> Self {
        Self {
            responder,
            scratch: Scratch::new(),
            clock: Clock::now(),
        }
    }

    fn reply(&mut self, message: &[u8], client: &str, transport: QueryTransport) -> Reply {
        let conn = Conn {
            client: SocketAddr::new(client.parse().expect("client"), 40000),
            local: "192.0.2.53:53".parse().expect("local"),
            transport,
        };
        self.responder.respond(
            message,
            &conn,
            &self.clock,
            Instant::now(),
            &mut self.scratch,
        )
    }

    fn ask_from(&mut self, query: &support::answer::Query, client: &str) -> Answer {
        let bytes = query.bytes(0x1234);
        assert_eq!(
            self.reply(&bytes, client, QueryTransport::Udp),
            Reply::Send,
            "{query:?}"
        );
        let answer = decode(&self.scratch.out);
        assert_eq!(answer.header.id, 0x1234);
        answer
    }

    fn ask(&mut self, query: &support::answer::Query) -> Answer {
        self.ask_from(query, "192.0.2.77")
    }
}

fn engine() -> (Engine, Fixture) {
    let fixture = fixture();
    let engine = Engine::new(Authoritative::new(handle(&fixture.image)));
    (engine, fixture)
}

fn targets(records: &[support::answer::Rec]) -> Vec<String> {
    records
        .iter()
        .filter_map(|record| record.target.clone())
        .collect()
}

fn owners_and_types(records: &[support::answer::Rec]) -> Vec<(String, u16)> {
    records
        .iter()
        .map(|record| (record.owner.clone(), record.rtype))
        .collect()
}

#[test]
fn positive_answers_carry_the_addresses_of_their_targets() {
    let (mut engine, _) = engine();
    let www = engine.ask(&query("www.example.test", A));
    assert_eq!(
        (www.rcode, www.header.aa, www.header.ra),
        (rcode::NOERROR, true, false)
    );
    assert_eq!(www.answers.len(), 2);
    assert!(
        www.authority.is_empty(),
        "minimal responses: no NS in authority"
    );
    assert_eq!(www.additional, []);
    assert_eq!(www.opt.as_ref().map(|opt| opt.udp_size), Some(1232));
    // MX: the addresses of the exchange inside the zone, once, none for the outside one.
    let mail = engine.ask(&query("mail.example.test", MX));
    assert_eq!(mail.answers.len(), 3);
    assert_eq!(
        owners_and_types(&mail.additional),
        [
            ("mx1.example.test".to_string(), A),
            ("mx1.example.test".to_string(), AAAA)
        ]
    );
    let sip = engine.ask(&query("_sip._tcp.example.test", SRV));
    assert_eq!(
        owners_and_types(&sip.additional),
        [("sip.example.test".to_string(), A)]
    );
    // NS at the apex: the addresses of both servers.
    let apex = engine.ask(&query("example.test", NS));
    assert_eq!(
        targets(&apex.answers),
        ["ns1.example.test", "ns2.example.test"]
    );
    assert_eq!(
        owners_and_types(&apex.additional),
        [
            ("ns1.example.test".to_string(), A),
            ("ns2.example.test".to_string(), AAAA)
        ]
    );
    // ANY gets one RRset (RFC 8482).
    let any = engine.ask(&query("example.test", ANY));
    assert_eq!(any.answers.len(), 2, "the two NS records, not the SOA too");
    assert!(any.answers.iter().all(|record| record.rtype == NS));
}

#[test]
fn names_keep_the_case_of_the_question() {
    let (mut engine, _) = engine();
    let mixed = engine.ask(&query("WwW.ExAmPlE.TeSt", A));
    assert_eq!(mixed.question, "WwW.ExAmPlE.TeSt");
    assert_eq!(mixed.answers[0].owner, "WwW.ExAmPlE.TeSt");
    let wild = engine.ask(&query("Foo.Wild.Example.TEST", A));
    assert_eq!(wild.rcode, rcode::NOERROR);
    assert_eq!(
        wild.answers[0].owner, "Foo.Wild.Example.TEST",
        "synthesized at the question name"
    );
    assert_eq!(wild.answers[0].rdata, [192, 0, 2, 9]);
}

#[test]
fn negative_answers_carry_the_soa_with_the_negative_ttl() {
    let (mut engine, _) = engine();
    for (qname, qtype, code) in [
        ("www.example.test", AAAA, rcode::NOERROR),
        ("nohost.example.test", A, rcode::NXDOMAIN),
        ("x.www.example.test", A, rcode::NXDOMAIN),
        ("foo.wild.example.test", MX, rcode::NOERROR),
    ] {
        let answer = engine.ask(&query(qname, qtype));
        assert_eq!((answer.rcode, answer.header.aa), (code, true), "{qname}");
        assert_eq!(answer.answers, []);
        assert_eq!(
            owners_and_types(&answer.authority),
            [("example.test".to_string(), SOA)]
        );
        // The SOA's TTL is 3600 and its MINIMUM 60: the smaller goes out (RFC 2308).
        assert_eq!(answer.authority[0].ttl, 60, "{qname}");
    }
}

#[test]
fn referrals_carry_the_glue_and_ds_for_dnssec_clients() {
    let (mut engine, _) = engine();
    for qname in [
        "child.example.test",
        "www.child.example.test",
        "ns.child.example.test",
    ] {
        let referral = engine.ask(&query(qname, A));
        assert_eq!(
            (referral.rcode, referral.header.aa),
            (rcode::NOERROR, false),
            "{qname}"
        );
        assert_eq!(referral.answers, []);
        assert_eq!(
            targets(&referral.authority),
            [
                "ns.child.example.test",
                "ns1.example.test",
                "ns.example.net"
            ]
        );
        // The in-domain glue first, then the other glue in the parent zone.
        assert_eq!(
            owners_and_types(&referral.additional),
            [
                ("ns.child.example.test".to_string(), A),
                ("ns1.example.test".to_string(), A)
            ]
        );
    }
    let signed = engine.ask(&query("www.child.example.test", A).dnssec());
    assert_eq!(
        owners_and_types(&signed.authority),
        [
            ("child.example.test".to_string(), NS),
            ("child.example.test".to_string(), NS),
            ("child.example.test".to_string(), NS),
            ("child.example.test".to_string(), DS)
        ]
    );
    assert!(
        signed.opt.as_ref().is_some_and(|opt| opt.dnssec_ok),
        "DO echoed"
    );
    // DS at the cut is the parent's data.
    let ds = engine.ask(&query("child.example.test", DS));
    assert_eq!((ds.header.aa, ds.answers.len()), (true, 1));
    assert_eq!(ds.answers[0].rtype, DS);
}

#[test]
fn a_referral_whose_glue_does_not_fit_is_truncated() {
    let mut fixture = fixture();
    let p = fixture.parent.clone();
    let hosts: Vec<String> = (0..30).map(|n| format!("ns{n}.big.example.test")).collect();
    let set_ns: Vec<RecordData> = hosts.iter().map(|host| ns(host)).collect();
    set(
        &mut fixture.image,
        rrset(&p, &ScopeName::DEFAULT, "big.example.test", &set_ns),
    );
    for host in &hosts {
        set(
            &mut fixture.image,
            rrset(&p, &ScopeName::DEFAULT, host, &[a(1), a(2), a(3), a(4)]),
        );
        set(
            &mut fixture.image,
            rrset(&p, &ScopeName::DEFAULT, host, &[aaaa(1), aaaa(2)]),
        );
    }
    let mut engine = Engine::new(Authoritative::new(handle(&fixture.image)));
    let small = engine.ask(&query("www.big.example.test", A).no_edns());
    assert!(
        small.header.tc,
        "the in-domain glue does not fit 512 octets"
    );
    assert!(small.authority.is_empty() && small.additional.is_empty());
    let large = engine.ask_from(&query("www.big.example.test", A), "192.0.2.77");
    assert!(large.header.tc, "nor 1232");
    let mut tcp = Engine::new(Authoritative::new(handle(&fixture.image)));
    let bytes = query("www.big.example.test", A).bytes(7);
    assert_eq!(
        tcp.reply(&bytes, "192.0.2.77", QueryTransport::Tcp),
        Reply::Send
    );
    let whole = decode(&tcp.scratch.out);
    assert!(!whole.header.tc);
    assert_eq!(whole.additional.len(), 30 * 6);
}

#[test]
fn cname_chains_are_followed_and_stopped() {
    let (mut engine, _) = engine();
    let chain = engine.ask(&query("Alias2.example.test", A));
    assert_eq!(
        owners_and_types(&chain.answers),
        [
            ("Alias2.example.test".to_string(), CNAME),
            ("alias.example.test".to_string(), CNAME),
            ("www.example.test".to_string(), A),
            ("www.example.test".to_string(), A),
        ]
    );
    assert!(chain.header.aa);
    // A CNAME query answers the CNAME.
    let own = engine.ask(&query("alias.example.test", CNAME));
    assert_eq!(
        owners_and_types(&own.answers),
        [("alias.example.test".to_string(), CNAME)]
    );
    // Out of the zones: the CNAME and nothing else.
    let out = engine.ask(&query("out.example.test", A));
    assert_eq!((out.rcode, out.answers.len()), (rcode::NOERROR, 1));
    assert_eq!(targets(&out.answers), ["www.example.net"]);
    // A loop stops with what was found.
    let looped = engine.ask(&query("loop1.example.test", A));
    assert_eq!(looped.rcode, rcode::NOERROR);
    assert!(looped.answers.len() <= 3, "{:?}", looped.answers);
    // Ten hops: the chain stops at eight (MAX_CHAIN).
    let long = engine.ask(&query("c0.example.test", A));
    assert_eq!(long.answers.len(), 8);
    assert!(long.answers.iter().all(|record| record.rtype == CNAME));
    let short = engine.ask(&query("c4.example.test", A));
    assert_eq!(short.answers.len(), 7);
    assert_eq!(short.answers.last().map(|record| record.rtype), Some(A));
    // A CNAME to a name that does not exist: NXDOMAIN for the target (RFC 6604).
    let mut fixture = fixture();
    let p = fixture.parent.clone();
    set(
        &mut fixture.image,
        rrset(
            &p,
            &ScopeName::DEFAULT,
            "dangling.example.test",
            &[cname("gone.example.test")],
        ),
    );
    let mut engine = Engine::new(Authoritative::new(handle(&fixture.image)));
    let dangling = engine.ask(&query("dangling.example.test", A));
    assert_eq!(
        (dangling.rcode, dangling.answers.len()),
        (rcode::NXDOMAIN, 1)
    );
    assert_eq!(
        owners_and_types(&dangling.authority),
        [("example.test".to_string(), SOA)]
    );
}

#[test]
fn dnames_synthesize_cnames() {
    let (mut engine, _) = engine();
    let away = engine.ask(&query("Www.Old.example.test", A));
    // The DNAME owner is compressed against the question, so it carries its case.
    assert_eq!(
        owners_and_types(&away.answers),
        [
            ("Old.example.test".to_string(), DNAME),
            ("Www.Old.example.test".to_string(), CNAME)
        ]
    );
    assert_eq!(targets(&away.answers), ["example.net", "www.example.net"]);
    assert_eq!(
        away.answers[1].ttl, away.answers[0].ttl,
        "the CNAME has the DNAME's TTL"
    );
    // A DNAME into the zone itself: the lookup restarts at the new name.
    let back = engine.ask(&query("www.here.example.test", A));
    assert_eq!(
        owners_and_types(&back.answers),
        [
            ("here.example.test".to_string(), DNAME),
            ("www.here.example.test".to_string(), CNAME),
            ("www.example.test".to_string(), A),
            ("www.example.test".to_string(), A),
        ]
    );
    // The DNAME owner itself is not redirected.
    let itself = engine.ask(&query("old.example.test", DNAME));
    assert_eq!(
        owners_and_types(&itself.answers),
        [("old.example.test".to_string(), DNAME)]
    );
    // A result longer than 255 octets is YXDOMAIN (RFC 6672).
    let long = format!(
        "{}.{}.big.example.test",
        long_label('a', 63),
        long_label('b', 40)
    );
    let too_long = engine.ask(&query(&long, A));
    assert_eq!(too_long.rcode, rcode::YXDOMAIN);
    assert_eq!(too_long.answers.len(), 1, "the DNAME only");
}

#[test]
fn the_header_checks_answer_with_their_rcodes() {
    let (mut engine, _) = engine();
    let notify = engine.ask(&query("example.test", SOA).opcode(4));
    assert_eq!(notify.rcode, rcode::NOTIMP);
    let chaos = engine.ask(&query("version.bind", 16).class(3));
    assert_eq!(
        (chaos.rcode, chaos.ede()),
        (rcode::REFUSED, Some(EDE_NOT_AUTHORITATIVE))
    );
    let axfr = engine.ask(&query("example.test", 252));
    assert_eq!(
        (axfr.rcode, axfr.ede()),
        (rcode::REFUSED, Some(EDE_PROHIBITED))
    );
    let opt = engine.ask(&query("example.test", 41));
    assert_eq!(opt.rcode, rcode::FORMERR);
    let outside = engine.ask(&query("www.example.org", A));
    assert_eq!((outside.rcode, outside.header.aa), (rcode::REFUSED, false));
    assert_eq!(outside.ede(), Some(EDE_NOT_AUTHORITATIVE));
    // A query that does not parse gets the header-only FORMERR; a response is dropped.
    let mut broken = query("www.example.test", A).bytes(9);
    broken.truncate(20);
    assert_eq!(
        engine.reply(&broken, "192.0.2.77", QueryTransport::Udp),
        Reply::Send
    );
    let formerr = decode(&engine.scratch.out);
    assert_eq!((formerr.rcode, formerr.header.qdcount), (rcode::FORMERR, 0));
    let mut response = query("www.example.test", A).bytes(9);
    response[2] |= 0x80;
    assert_eq!(
        engine.reply(&response, "192.0.2.77", QueryTransport::Udp),
        Reply::Drop
    );
    // A signed query: the keys reach the engine with WP6.2.
    let mut signed = query("example.test", SOA).no_edns().bytes(5);
    let tsig = tenko_dns::wire::TsigRecord {
        key: b"\x03key\x00",
        algorithm: b"\x0bhmac-sha256\x00",
        time_signed: 1_790_000_000,
        fudge: 300,
        mac: &[1; 32],
        original_id: 5,
        error: 0,
        other: &[],
    };
    assert!(tenko_dns::wire::append_tsig(&mut signed, &tsig, 65_535));
    assert_eq!(
        engine.reply(&signed, "192.0.2.77", QueryTransport::Udp),
        Reply::Send
    );
    assert_eq!(decode(&engine.scratch.out).rcode, rcode::NOTAUTH);
}

#[test]
fn edns_versions_unknown_options_and_sizes() {
    let (mut engine, _) = engine();
    let badvers = engine.ask(&query("www.example.test", A).version(1));
    assert_eq!(badvers.rcode, rcode::BADVERS);
    assert_eq!(badvers.answers, []);
    // An unknown option is ignored.
    let unknown = engine.ask(&query("www.example.test", A).option(65001, b"abc"));
    assert_eq!((unknown.rcode, unknown.answers.len()), (rcode::NOERROR, 2));
    // Without EDNS: no OPT; the answer stays within 512 octets.
    let classic = engine.ask(&query("www.example.test", A).no_edns());
    assert!(classic.opt.is_none());
    // A requester asking for 4096 gets at most 1232 (the server's size).
    let big = engine.ask(&query("www.example.test", A).size(4096));
    assert_eq!(big.opt.map(|opt| opt.udp_size), Some(1232));
    // The server's size is a setting (`edns.udp_size`), clamped to 512 to 4096.
    let fixture = fixture();
    for (setting, advertised) in [(4096, 4096), (9000, 4096), (100, 512)] {
        let mut sized = Engine::with(
            Responder::new(
                Authoritative::new(handle(&fixture.image)),
                CookieSecret::with_secret([3; 16]),
            )
            .with_metrics(false)
            .with_udp_size(setting),
        );
        let answer = sized.ask(&query("www.example.test", A).size(4096));
        assert_eq!(answer.opt.map(|opt| opt.udp_size), Some(advertised));
    }
}

#[test]
fn cookies_are_answered_and_required_on_udp_when_set() {
    let (mut engine, fixture) = engine();
    let client = [9u8; 8];
    let first = engine.ask(&query("www.example.test", A).cookie(&client));
    let cookie = first
        .opt
        .as_ref()
        .and_then(|opt| opt.option(10))
        .expect("cookie")
        .to_vec();
    assert_eq!(cookie.len(), 24);
    assert_eq!(&cookie[..8], &client);
    assert_eq!(cookie[8], 1, "an RFC 9018 server cookie");
    // A malformed cookie (5 octets) is FORMERR (RFC 7873, section 5.2.2).
    let bad = engine.ask(&query("www.example.test", A).cookie(&[1, 2, 3, 4, 5]));
    assert_eq!(bad.rcode, rcode::FORMERR);
    // Required: a client cookie alone gets BADCOOKIE with a cookie over UDP...
    let mut strict = Engine::with(
        Responder::new(
            Authoritative::new(handle(&fixture.image)),
            CookieSecret::with_secret([3; 16]),
        )
        .with_metrics(false)
        .with_cookie_mode(CookieMode::Required),
    );
    let refused = strict.ask(&query("www.example.test", A).cookie(&client));
    assert_eq!(refused.rcode, rcode::BADCOOKIE);
    assert_eq!(refused.answers, []);
    let fresh = refused
        .opt
        .as_ref()
        .and_then(|opt| opt.option(10))
        .expect("cookie")
        .to_vec();
    // ...and the full cookie it returned is accepted.
    let accepted = strict.ask(&query("www.example.test", A).cookie(&fresh));
    assert_eq!(
        (accepted.rcode, accepted.answers.len()),
        (rcode::NOERROR, 2)
    );
    // Over TCP the client cookie alone is enough.
    let bytes = query("www.example.test", A).cookie(&client).bytes(3);
    assert_eq!(
        strict.reply(&bytes, "192.0.2.77", QueryTransport::Tcp),
        Reply::Send
    );
    assert_eq!(decode(&strict.scratch.out).rcode, rcode::NOERROR);
    // A query without a cookie is answered without one, even when required.
    let none = strict.ask(&query("www.example.test", A));
    assert!(
        none.opt
            .as_ref()
            .is_some_and(|opt| opt.option(10).is_none())
    );
    assert_eq!(none.rcode, rcode::NOERROR);
}

#[test]
fn views_choose_the_scope_and_forwarders_the_outside() {
    let (mut engine, fixture) = engine();
    let inside = engine.ask_from(&query("www.example.test", A), "198.51.100.7");
    assert_eq!(inside.answers.len(), 1);
    assert_eq!(inside.answers[0].rdata, [192, 0, 2, 100]);
    let elsewhere = engine.ask_from(&query("www.example.test", A), "203.0.113.7");
    assert_eq!(elsewhere.answers.len(), 2);
    // Outside the zones with RD and a rule: forwarded; without a forwarder: SERVFAIL.
    let forwarded = engine.ask(&query("host.example.net", A).rd());
    assert_eq!(forwarded.rcode, rcode::SERVFAIL);
    let without_rd = engine.ask(&query("host.example.net", A));
    assert_eq!(without_rd.rcode, rcode::REFUSED);
    let sink = Arc::new(Sink::default());
    let resolver = Authoritative::new(handle(&fixture.image)).with_settings(Settings {
        recursion_available: true,
        default_forwarder: true,
        redirect_ttl: 60,
    });
    let mut forwarding = Engine::with(
        Responder::new(resolver, CookieSecret::with_secret([3; 16]))
            .with_metrics(false)
            .with_forwarder(Arc::clone(&sink) as Arc<dyn ForwardSink>),
    );
    let bytes = query("host.example.net", A).rd().bytes(11);
    let reply = forwarding.reply(&bytes, "198.51.100.7", QueryTransport::Udp);
    assert_eq!(
        reply,
        Reply::Forward {
            view: Some(fixture.view),
            rule: Some(fixture.rule)
        }
    );
    let other = query("www.example.org", A).rd().bytes(12);
    assert_eq!(
        forwarding.reply(&other, "203.0.113.7", QueryTransport::Udp),
        Reply::Forward {
            view: None,
            rule: None
        },
        "the default forwarder"
    );
    // RA is set when a forwarder exists.
    assert!(forwarding.ask(&query("www.example.test", A)).header.ra);
}

/// A forwarder that keeps what it is given.
#[derive(Default)]
struct Sink(Mutex<Vec<ForwardQuery>>);
impl ForwardSink for Sink {
    fn submit(&self, query: ForwardQuery) {
        self.0.lock().expect("lock").push(query);
    }
}

struct Blocker;

impl PolicyEngine for Blocker {
    fn check<'a>(
        &'a self,
        _view: Option<ViewId>,
        _client: IpAddr,
        qname: &[u8],
        _qtype: Rtype,
    ) -> Verdict<'a> {
        static NX: BlockAction = BlockAction::Nxdomain;
        static REDIRECT: std::sync::LazyLock<BlockAction> =
            std::sync::LazyLock::new(|| BlockAction::Redirect {
                address: "192.0.2.80".parse().expect("address"),
            });
        let list = BlockListId::generate();
        if qname.starts_with(b"\x07blocked") {
            Verdict::Block { list, action: &NX }
        } else if qname.starts_with(b"\x08redirect") {
            Verdict::Block {
                list,
                action: &REDIRECT,
            }
        } else {
            Verdict::Pass
        }
    }
}

struct Limiter;

impl RateLimiter for Limiter {
    fn admit_query(&self, client: IpAddr, _now: Instant) -> bool {
        client != "203.0.113.66".parse::<IpAddr>().expect("address")
    }

    fn admit_response(
        &self,
        client: IpAddr,
        kind: ResponseKind,
        zone: &[u8],
        _now: Instant,
    ) -> RateDecision {
        assert!(zone.ends_with(b"\x00"));
        if client == "203.0.113.67".parse::<IpAddr>().expect("address") {
            return RateDecision::Drop;
        }
        if kind == ResponseKind::NxDomain {
            RateDecision::Slip
        } else {
            RateDecision::Send
        }
    }
}

#[test]
fn the_policy_and_the_rate_limiter_are_called_in_order() {
    let fixture = fixture();
    let resolver = Authoritative::new(handle(&fixture.image))
        .with_policy(Arc::new(Blocker))
        .with_rate_limiter(Arc::new(Limiter));
    let mut engine = Engine::new(resolver);
    let blocked = engine.ask(&query("blocked.example.org", A).rd());
    assert_eq!(
        (blocked.rcode, blocked.ede()),
        (rcode::NXDOMAIN, Some(EDE_BLOCKED))
    );
    let redirected = engine.ask(&query("redirect.example.org", A).rd());
    assert_eq!(redirected.answers[0].rdata, [192, 0, 2, 80]);
    assert_eq!(redirected.answers[0].ttl, 60);
    let none = engine.ask(&query("redirect.example.org", AAAA).rd());
    assert!(none.answers.is_empty() && none.rcode == rcode::NOERROR);
    // The policy is not asked about the zones' own names.
    let own = engine.ask(&query("www.example.test", A));
    assert_eq!(own.answers.len(), 2);
    // The slip: NXDOMAIN answers become empty answers with TC.
    let slipped = engine.ask(&query("nohost.example.test", A));
    assert!(slipped.header.tc);
    assert!(slipped.answers.is_empty() && slipped.authority.is_empty());
    assert_eq!(slipped.rcode, rcode::NOERROR);
    // Dropped queries and responses get nothing.
    let bytes = query("www.example.test", A).bytes(1);
    assert_eq!(
        engine.reply(&bytes, "203.0.113.66", QueryTransport::Udp),
        Reply::Drop
    );
    assert_eq!(
        engine.reply(&bytes, "203.0.113.67", QueryTransport::Udp),
        Reply::Drop
    );
}

#[test]
fn a_new_catalog_is_seen_by_the_next_query() {
    let fixture = fixture();
    let handle = handle(&fixture.image);
    let mut engine = Engine::new(Authoritative::new(handle.clone()));
    assert_eq!(
        engine.ask(&query("new.example.test", A)).rcode,
        rcode::NXDOMAIN
    );
    let added = rrset(
        &fixture.parent,
        &ScopeName::DEFAULT,
        "new.example.test",
        &[a(42)],
    );
    let delta = tenko_dns::feed::Delta {
        from: Revision(3),
        to: Revision(4),
        changes: vec![tenko_dns::feed::Change::RrSet(added.key(), Some(added))],
    };
    let next = handle.load_full().apply(&delta).expect("delta");
    handle.store(next);
    assert_eq!(handle.revision(), Revision(4));
    let answer = engine.ask(&query("new.example.test", A));
    assert_eq!(answer.answers[0].rdata, [192, 0, 2, 42]);
}
