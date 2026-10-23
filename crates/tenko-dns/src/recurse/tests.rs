//! The engine against the scripted lab (E36, M40), before a socket is involved.
//!
//! The lab of these tests has the zones of the compose lab (`deploy/compose/lab-dns`, the
//! profile `recursion`) spread over servers of their own, so that every referral of the
//! Internet happens: the root at .10, the TLD `test` at .20, `example.test` at .30 with the
//! children the E36 cases need, BIND's copy of `example.test` at .2 (the target of the lame
//! delegation), the quirk servers at .11, .13 and .14, `elsewhere.test` at .41 and a silent
//! server at .250 for the TLD `unreachable`. The addresses are 203.0.113.0/24.
//!
//! Every case starts from a primed engine with nothing else learnt and records the queries
//! sent ([`CASES`]): the figures of M40, documented in `docs/dns-resolver.md` section 10.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use tenko_core::dns::{DnsName, ExtendedError, RecordData};

use super::*;
use crate::{
    infra::Infra,
    recursion::{
        InfraBounds, MemAuthority, MemFailures, MemInfra, MemZone, Quirks, infra::EdnsSupport,
    },
    wire,
};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn wire_name(text: &str) -> Vec<u8> {
    name(text).to_wire()
}

fn lab_ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
}

fn ns(host: &str) -> RecordData {
    RecordData::Ns { host: name(host) }
}

fn a(address: [u8; 4]) -> RecordData {
    RecordData::A {
        address: Ipv4Addr::from(address),
    }
}

fn glue(last: u8) -> RecordData {
    a([203, 0, 113, last])
}

fn cname(target: &str) -> RecordData {
    RecordData::Cname {
        target: name(target),
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
const ZONE: u8 = 30;
const BIND: u8 = 2;
const NO_EDNS: u8 = 11;
const CASE: u8 = 13;
const TRUNCATE: u8 = 14;
const ELSEWHERE: u8 = 41;
const ATTACKER: u8 = 66;
const SILENT: u8 = 250;
// WP10.3: the server that is not RFC 8020 clean.
const BROKEN: u8 = 15;

/// A zone at `apex` with its SOA and NS.
fn zone(apex: &str, server: &str) -> MemZone {
    MemZone::new(name(apex))
        .record(name(apex), 3600, soa(apex))
        .record(name(apex), 3600, ns(server))
}

/// The scripted lab; see the module documentation.
#[allow(
    clippy::too_many_lines,
    reason = "the zone data of the lab, read top to bottom"
)]
fn lab() -> MemAuthority {
    let root = MemZone::new(DnsName::root())
        .record(DnsName::root(), 86_400, soa("root.test"))
        .record(DnsName::root(), 86_400, ns("a.root.test"))
        .record(name("a.root.test"), 86_400, glue(ROOT))
        .record(name("test"), 3600, ns("ns.test"))
        .record(name("ns.test"), 3600, glue(TLD))
        .record(name("unreachable"), 3600, ns("ns.unreachable"))
        .record(name("ns.unreachable"), 3600, glue(SILENT));
    let tld = zone("test", "ns.test")
        .record(name("example.test"), 3600, ns("ns.example.test"))
        .record(name("ns.example.test"), 3600, glue(ZONE))
        .record(name("elsewhere.test"), 3600, ns("ns.elsewhere.test"))
        .record(name("ns.elsewhere.test"), 3600, glue(ELSEWHERE));
    let mut example = zone("example.test", "ns.example.test")
        .record(name("ns.example.test"), 3600, glue(ZONE))
        .record(name("www.example.test"), 300, a([192, 0, 2, 1]))
        .record(name("*.wild.example.test"), 300, a([192, 0, 2, 2]))
        .record(name("alias.example.test"), 300, cname("www.example.test"))
        .record(
            name("loop1.cname.example.test"),
            300,
            cname("loop2.cname.example.test"),
        )
        .record(
            name("loop2.cname.example.test"),
            300,
            cname("loop1.cname.example.test"),
        )
        // A lame delegation: BIND serves example.test, not lame.example.test.
        .record(name("lame.example.test"), 3600, ns("bind.example.test"))
        .record(name("bind.example.test"), 3600, glue(BIND))
        // Each the other's name server, no glue.
        .record(name("loop.example.test"), 3600, ns("ns.loop2.example.test"))
        .record(name("loop2.example.test"), 3600, ns("ns.loop.example.test"))
        // The quirk servers, delegated with glue.
        .record(
            name("noedns.quirk.example.test"),
            3600,
            ns("ns.noedns.quirk.example.test"),
        )
        .record(name("ns.noedns.quirk.example.test"), 3600, glue(NO_EDNS))
        .record(
            name("case.quirk.example.test"),
            3600,
            ns("ns.case.quirk.example.test"),
        )
        .record(name("ns.case.quirk.example.test"), 3600, glue(CASE))
        .record(
            name("tc.quirk.example.test"),
            3600,
            ns("ns.tc.quirk.example.test"),
        )
        .record(name("ns.tc.quirk.example.test"), 3600, glue(TRUNCATE))
        // A delegation whose name server is outside the bailiwick.
        .record(name("oob.example.test"), 3600, ns("ns.elsewhere.test"))
        // WP10.3: a server that answers NXDOMAIN for its empty non-terminals.
        .record(
            name("broken.example.test"),
            3600,
            ns("ns.broken.example.test"),
        )
        .record(name("ns.broken.example.test"), 3600, glue(BROKEN));
    // A chain of ten.
    for link in 1..=10 {
        let target = if link == 10 {
            "www.example.test".to_owned()
        } else {
            format!("c{}.cname.example.test", link + 1)
        };
        example = example.record(
            name(&format!("c{link}.cname.example.test")),
            300,
            cname(&target),
        );
    }
    example = example
        .record(
            name("short1.cname.example.test"),
            300,
            cname("short2.cname.example.test"),
        )
        .record(
            name("short2.cname.example.test"),
            300,
            cname("www.example.test"),
        );
    // Answers above 1,232 octets.
    for index in 0..80u16 {
        let [high, low] = index.to_be_bytes();
        example = example.record(
            name("big.example.test"),
            300,
            RecordData::Aaaa {
                address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, u16::from(high), u16::from(low)),
            },
        );
    }
    // The server of example.test also holds a zone it uses to give out-of-bailiwick glue
    // for ns.elsewhere.test, pointing at an address nobody serves.
    let poison = MemZone::new(name("elsewhere.test")).record(
        name("ns.elsewhere.test"),
        3600,
        glue(ATTACKER),
    );
    let elsewhere = zone("elsewhere.test", "ns.elsewhere.test").record(
        name("ns.elsewhere.test"),
        3600,
        glue(ELSEWHERE),
    );
    let oob = zone("oob.example.test", "ns.elsewhere.test").record(
        name("www.oob.example.test"),
        300,
        a([192, 0, 2, 66]),
    );
    let bind = zone("example.test", "bind.example.test").record(
        name("www.example.test"),
        300,
        a([192, 0, 2, 99]),
    );
    let quirk = |apex: &str, server: &str| {
        zone(apex, server).record(name(&format!("www.{apex}")), 300, a([192, 0, 2, 7]))
    };
    MemAuthority::new()
        .serve(lab_ip(ROOT), root)
        .serve(lab_ip(TLD), tld)
        .serve(lab_ip(ZONE), example)
        .serve(lab_ip(ZONE), poison)
        .serve(lab_ip(ELSEWHERE), elsewhere)
        .serve(lab_ip(ELSEWHERE), oob)
        .serve(lab_ip(BIND), bind)
        .serve(
            lab_ip(NO_EDNS),
            quirk("noedns.quirk.example.test", "ns.noedns.quirk.example.test"),
        )
        .quirks(
            lab_ip(NO_EDNS),
            Quirks {
                formerr_on_edns: true,
                ..Quirks::default()
            },
        )
        .serve(
            lab_ip(CASE),
            quirk("case.quirk.example.test", "ns.case.quirk.example.test"),
        )
        .quirks(
            lab_ip(CASE),
            Quirks {
                case_broken: true,
                ..Quirks::default()
            },
        )
        .serve(
            lab_ip(TRUNCATE),
            quirk("tc.quirk.example.test", "ns.tc.quirk.example.test"),
        )
        .quirks(
            lab_ip(TRUNCATE),
            Quirks {
                truncate_udp: true,
                ..Quirks::default()
            },
        )
        .quirks(
            lab_ip(SILENT),
            Quirks {
                silent: true,
                ..Quirks::default()
            },
        )
        .serve(
            lab_ip(BROKEN),
            zone("broken.example.test", "ns.broken.example.test")
                .record(name("ns.broken.example.test"), 3600, glue(BROKEN))
                .record(name("www.a.b.broken.example.test"), 300, a([192, 0, 2, 15]))
                .record(name("www.c.broken.example.test"), 300, a([192, 0, 2, 16])),
        )
        .quirks(
            lab_ip(BROKEN),
            Quirks {
                nxdomain_for_ent: true,
                ..Quirks::default()
            },
        )
}

/// The lab's hints file.
const LAB_HINTS: &str = ".  3600000 NS a.root.test.\na.root.test. 3600000 A 203.0.113.10\n";

fn settings() -> EngineSettings {
    EngineSettings {
        recursion: RecursionSettings {
            outbound: Outbound::V4,
            ..RecursionSettings::default()
        },
        hints: None,
        local_zones_except: vec![name("test")],
        metrics: false,
    }
}

type Lab = Engine<Arc<MemAuthority>>;

impl Authority for Arc<MemAuthority> {
    fn exchange<'a>(
        &'a self,
        query: &'a AuthorityQuery<'a>,
        answer: &'a mut Vec<u8>,
    ) -> impl Future<Output = Result<crate::recursion::Exchange, AuthorityError>> + Send + 'a {
        self.as_ref().exchange(query, answer)
    }
}

fn engine_with(lab: &Arc<MemAuthority>, settings: &EngineSettings) -> Lab {
    let hints = hints::parse(LAB_HINTS).expect("hints");
    Engine::new(
        Arc::clone(lab),
        Arc::new(Infra::new(settings.recursion.infra)),
        Arc::new(ServerTable::new(1_000, Duration::from_secs(900))),
        Arc::new(MemFailures::default()),
        hints,
        settings,
    )
}

async fn primed(lab: &Arc<MemAuthority>) -> Lab {
    let engine = engine_with(lab, &settings());
    engine.prime().await.expect("primed");
    lab.clear_log();
    engine
}

fn question(qname: &[u8], qtype: u16) -> Question<'_> {
    Question {
        qname,
        qtype,
        qclass: 1,
        view: None,
    }
}

/// The records of a message: (section, owner, type).
fn records(message: &[u8]) -> Vec<(usize, String, u16)> {
    let parsed = message::parse(message).expect("parses");
    let mut out = Vec::new();
    for (section, list) in [parsed.answer, parsed.authority, parsed.additional]
        .into_iter()
        .enumerate()
    {
        for rr in list {
            let owner = DnsName::from_wire(&rr.owner).expect("owner").0;
            out.push((section, owner.as_str().to_owned(), rr.rtype));
        }
    }
    out
}

/// What a case expects.
#[derive(Debug, Clone, Copy)]
enum Expect {
    /// NOERROR with records of the type asked.
    Answer,
    /// NOERROR without data.
    Nodata,
    /// NXDOMAIN.
    Nxdomain,
    /// SERVFAIL with this extended error.
    Servfail(ExtendedError),
}

/// One case of E36 and the resolutions around it: the name, the type, the outcome and the
/// queries sent to authorities (logged by the scripted servers, the fallback ladder's
/// retries included), from a primed engine with a cold infrastructure cache.
struct Case {
    what: &'static str,
    qname: &'static str,
    qtype: u16,
    expect: Expect,
    /// WP10.3: the queries sent with QNAME minimisation relaxed, strict and off (M40).
    queries: [usize; 3],
}

// WP10.3: the modes of the case table, in the order of `Case::queries`.
const MODES: [Minimisation; 3] = [
    Minimisation::Relaxed,
    Minimisation::Strict,
    Minimisation::Off,
];

/// The cases and their query counts (M40).
const CASES: &[Case] = &[
    Case {
        what: "a name three labels down: root, TLD, zone",
        qname: "www.example.test",
        qtype: types::A,
        expect: Expect::Answer,
        queries: [3, 3, 3],
    },
    Case {
        what: "a wildcard",
        qname: "any.wild.example.test",
        qtype: types::A,
        expect: Expect::Answer,
        queries: [4, 4, 3],
    },
    Case {
        what: "NXDOMAIN",
        qname: "nothing.example.test",
        qtype: types::A,
        expect: Expect::Nxdomain,
        queries: [3, 3, 3],
    },
    Case {
        what: "NODATA",
        qname: "www.example.test",
        qtype: types::AAAA,
        expect: Expect::Nodata,
        queries: [3, 3, 3],
    },
    Case {
        what: "a CNAME within the zone, asked again for the target",
        qname: "alias.example.test",
        qtype: types::A,
        expect: Expect::Answer,
        queries: [4, 4, 4],
    },
    Case {
        what: "a chain of two",
        qname: "short1.cname.example.test",
        qtype: types::A,
        expect: Expect::Answer,
        queries: [6, 6, 5],
    },
    Case {
        what: "a lame delegation (NS at BIND, which serves the parent)",
        qname: "www.lame.example.test",
        qtype: types::A,
        expect: Expect::Servfail(ExtendedError::NO_REACHABLE_AUTHORITY),
        queries: [4, 4, 4],
    },
    Case {
        what: "a delegation whose name servers point at each other without glue",
        qname: "www.loop.example.test",
        qtype: types::A,
        expect: Expect::Servfail(ExtendedError::NO_REACHABLE_AUTHORITY),
        queries: [4, 4, 4],
    },
    Case {
        what: "a CNAME loop",
        qname: "loop1.cname.example.test",
        qtype: types::A,
        expect: Expect::Servfail(ExtendedError::NO_REACHABLE_AUTHORITY),
        queries: [5, 5, 4],
    },
    Case {
        what: "a chain of ten, over the eight restarts",
        qname: "c1.cname.example.test",
        qtype: types::A,
        expect: Expect::Servfail(ExtendedError::NO_REACHABLE_AUTHORITY),
        queries: [12, 12, 11],
    },
    Case {
        what: "a TLD whose server does not answer",
        qname: "www.unreachable",
        qtype: types::A,
        expect: Expect::Servfail(ExtendedError::NO_REACHABLE_AUTHORITY),
        queries: [4, 4, 4],
    },
    Case {
        what: "a server that breaks 0x20, asked again in lower case",
        qname: "www.case.quirk.example.test",
        qtype: types::A,
        expect: Expect::Answer,
        queries: [6, 6, 5],
    },
    Case {
        what: "a server that answers FORMERR to EDNS, asked again without",
        qname: "www.noedns.quirk.example.test",
        qtype: types::A,
        expect: Expect::Answer,
        queries: [6, 6, 5],
    },
    Case {
        what: "a server that truncates everything, asked again over TCP",
        qname: "www.tc.quirk.example.test",
        qtype: types::A,
        expect: Expect::Answer,
        queries: [6, 6, 5],
    },
    Case {
        what: "a referral with out-of-bailiwick glue, the glue ignored",
        qname: "www.oob.example.test",
        qtype: types::A,
        expect: Expect::Answer,
        queries: [6, 6, 6],
    },
    Case {
        what: "an answer above 1,232 octets, over TCP",
        qname: "big.example.test",
        qtype: types::AAAA,
        expect: Expect::Answer,
        queries: [4, 4, 4],
    },
];

#[tokio::test]
async fn every_case_of_e36_ends_within_the_budget_with_its_query_count() {
    let mut report = Vec::new();
    let mut wrong = Vec::new();
    // WP10.3: every case under each minimisation mode.
    for (mode_index, mode) in MODES.into_iter().enumerate() {
        for case in CASES {
            let lab = Arc::new(lab());
            let mut settings = settings();
            settings.recursion.minimisation = mode;
            let engine = engine_with(&lab, &settings);
            engine.prime().await.expect("primed");
            lab.clear_log();
            let qname = wire_name(case.qname);
            let resolved = engine.resolve(question(&qname, case.qtype)).await;
            let asked = lab.asked();
            let sent = asked.len();
            report.push(format!("{mode:?} {:>2} {}", sent, case.what));
            if sent != case.queries[mode_index] {
                wrong.push(format!(
                    "{mode:?} {}: {sent} sent, {} expected: {:?}",
                    case.what,
                    case.queries[mode_index],
                    asked
                        .iter()
                        .map(|asked| (asked.server, asked.qname.as_str().to_owned(), asked.qtype))
                        .collect::<Vec<_>>()
                ));
            }
            check_case(case, &lab, &engine, &qname, &resolved).await;
            assert!(
                usize::from(resolved.subqueries) <= usize::from(WorkBudget::DEFAULT.queries),
                "{}",
                case.what
            );
            assert_eq!(
                usize::from(resolved.subqueries),
                sent,
                "{}: the budget counts what was sent",
                case.what
            );
        }
    }
    println!(
        "queries per case (M40):
{}",
        report.join(
            "
"
        )
    );
    assert!(
        wrong.is_empty(),
        "{}",
        wrong.join(
            "
"
        )
    );
}

/// The outcome of one case.
async fn check_case(
    case: &Case,
    lab: &Arc<MemAuthority>,
    engine: &Lab,
    qname: &[u8],
    resolved: &Resolved,
) {
    let found = records(&resolved.message);
    let header = wire::parse_header(&resolved.message).expect("header");
    match case.expect {
        Expect::Answer => {
            assert_eq!(header.rcode, 0, "{}", case.what);
            assert!(
                found
                    .iter()
                    .any(|(section, _, rtype)| *section == 0 && *rtype == case.qtype),
                "{}: {found:?}",
                case.what
            );
            assert_eq!(resolved.outcome, Outcome::Answered, "{}", case.what);
        }
        Expect::Nodata | Expect::Nxdomain => {
            let rcode = if matches!(case.expect, Expect::Nxdomain) {
                3
            } else {
                0
            };
            assert_eq!(header.rcode, rcode, "{}", case.what);
            assert!(
                found
                    .iter()
                    .any(|(section, _, rtype)| *section == 1 && *rtype == types::SOA),
                "{}: the SOA for the negative cache",
                case.what
            );
            assert!(
                !found.iter().any(|(section, _, _)| *section == 0),
                "{}",
                case.what
            );
        }
        Expect::Servfail(ede) => {
            assert_eq!(header.rcode, 2, "{}", case.what);
            assert_eq!(resolved.ede(), Some(ede), "{}", case.what);
            // The failure is cached (RFC 9520): the second ask sends nothing.
            lab.clear_log();
            let again = engine.resolve(question(qname, case.qtype)).await;
            assert_eq!(lab.asked().len(), 0, "{}: cached", case.what);
            assert!(
                matches!(again.outcome, Outcome::Failed { cached: true, .. }),
                "{}",
                case.what
            );
        }
    }
}

#[tokio::test]
async fn priming_from_a_hints_file_and_again_before_the_root_expires() {
    let lab = Arc::new(lab());
    let engine = engine_with(&lab, &settings());
    assert!(engine.priming_due(Instant::now()), "at start");
    let took = engine.prime().await.expect("the lab root answers");
    assert!(took < Duration::from_millis(100), "{took:?}");
    assert_eq!(lab.asked().len(), 1, "one query");
    let report = engine.report();
    assert!(report.priming.is_some_and(|priming| priming.ok));
    assert_eq!(report.problems, Vec::<String>::new());
    assert_eq!(report.root.len(), 1);
    assert_eq!(report.root[0].address, lab_ip(ROOT));
    // The root's NS set lives 86,400 s: the next priming is a tenth earlier, at most an
    // hour, so 23 hours from now.
    let now = Instant::now();
    assert!(!engine.priming_due(now + Duration::from_secs(22 * 3600)));
    assert!(engine.priming_due(now + Duration::from_secs(23 * 3600 + 1)));
    assert!(
        report
            .root_expires_in
            .is_some_and(|left| left > Duration::from_secs(86_000))
    );
    // A flush drops the root and the next query primes again.
    engine.flush_infra(None);
    assert!(engine.priming_due(Instant::now()));
    assert_eq!(engine.infra().sizes().cuts, 1, "the hints are back");
}

#[tokio::test]
async fn priming_fails_with_unreachable_hints_and_names_the_problem() {
    let lab = Arc::new(MemAuthority::new());
    let engine = Engine::new(
        Arc::clone(&lab),
        Arc::new(Infra::default()),
        Arc::new(ServerTable::new(100, Duration::from_secs(900))),
        Arc::new(MemFailures::default()),
        Hints::shipped(),
        &EngineSettings {
            metrics: false,
            ..EngineSettings::default()
        },
    );
    assert_eq!(
        engine.prime().await,
        Err(FailureCause::NoReachableAuthority)
    );
    assert_eq!(lab.asked().len(), 0, "unknown servers are unreachable");
    let report = engine.report();
    assert_eq!(report.problems, ["priming_failed"]);
    assert_eq!(report.hints_source, "shipped");
    assert!(!engine.priming_due(Instant::now()), "the back-off runs");
    let qname = wire_name("www.example.com");
    let resolved = engine.resolve(question(&qname, types::A)).await;
    assert_eq!(resolved.rcode, 2);
    assert!(matches!(
        resolved.ede(),
        Some(ExtendedError::NO_REACHABLE_AUTHORITY | ExtendedError::NETWORK_ERROR)
    ));
}

#[tokio::test]
async fn the_ladder_and_the_bailiwick_leave_their_marks_in_the_caches() {
    let lab = Arc::new(lab());
    let engine = primed(&lab).await;
    let now = Instant::now();
    for qname in ["www.noedns.quirk.example.test", "www.oob.example.test"] {
        let qname = wire_name(qname);
        assert_eq!(engine.resolve(question(&qname, types::A)).await.rcode, 0);
    }
    assert_eq!(
        engine.infra().server(lab_ip(NO_EDNS), now).edns,
        EdnsSupport::No
    );
    // The out-of-bailiwick glue was never cached nor asked.
    assert_eq!(lab.asked_of(lab_ip(ATTACKER)), 0);
    let elsewhere = engine
        .infra()
        .name_server(&name("ns.elsewhere.test"), Instant::now())
        .expect("learnt");
    assert!(
        elsewhere
            .addresses
            .iter()
            .all(|address| address.address == lab_ip(ELSEWHERE)),
        "{elsewhere:?}"
    );
    // A server that truncates three answers in a row is asked over TCP from the start.
    for qname in [
        "www.tc.quirk.example.test",
        "a.tc.quirk.example.test",
        "b.tc.quirk.example.test",
    ] {
        let qname = wire_name(qname);
        engine.resolve(question(&qname, types::A)).await;
    }
    assert!(
        engine
            .infra()
            .server(lab_ip(TRUNCATE), Instant::now())
            .tcp_only
    );
    lab.clear_log();
    let qname = wire_name("c.tc.quirk.example.test");
    engine.resolve(question(&qname, types::A)).await;
    assert!(
        lab.asked()
            .iter()
            .all(|asked| asked.transport == crate::recursion::AuthorityTransport::Tcp),
        "{:?}",
        lab.asked()
    );
    // The lame server is lame for its zone.
    let qname = wire_name("www.lame.example.test");
    engine.resolve(question(&qname, types::A)).await;
    assert!(
        engine
            .infra()
            .server(lab_ip(BIND), Instant::now())
            .is_lame(&name("lame.example.test"), Instant::now())
    );
    let page = engine.infra_page(Some(&name("example.test")), None, 100);
    assert!(page.iter().any(|cut| cut.zone == name("lame.example.test")));
    assert!(engine.counters().subqueries > 0);
}

#[tokio::test]
async fn a_warm_cache_asks_only_the_zone_and_the_budget_bounds_the_rest() {
    let lab = Arc::new(lab());
    let engine = primed(&lab).await;
    let qname = wire_name("www.example.test");
    engine.resolve(question(&qname, types::A)).await;
    lab.clear_log();
    let other = wire_name("any.wild.example.test");
    let resolved = engine.resolve(question(&other, types::A)).await;
    // WP10.3: the cut is known; minimised, its server is asked for `wild.example.test`
    // first and then the name.
    assert_eq!(
        (resolved.rcode, lab.asked().len()),
        (0, 2),
        "the cut is known"
    );
    // WP10.3: `wild.example.test` is known to exist without a cut now: the next name
    // under it costs one query.
    lab.clear_log();
    let next = wire_name("next.wild.example.test");
    let resolved = engine.resolve(question(&next, types::A)).await;
    assert_eq!((resolved.rcode, lab.asked().len()), (0, 1), "remembered");
    // The flush of the infrastructure cache forgets it.
    engine.flush_infra(Some(&name("example.test")));
    engine.prime().await.expect("primed");
    lab.clear_log();
    let after = wire_name("after.wild.example.test");
    engine.resolve(question(&after, types::A)).await;
    assert!(
        lab.asked()
            .iter()
            .any(|asked| asked.qname.as_str() == "wild.example.test"),
        "asked again after the flush"
    );

    // Two queries allowed: the root and the TLD, then the bound.
    let lab = Arc::new(self::lab());
    let mut tight = settings();
    tight.recursion.budget.queries = 2;
    let engine = engine_with(&lab, &tight);
    engine.prime().await.expect("primed");
    let resolved = engine.resolve(question(&qname, types::A)).await;
    assert_eq!(resolved.rcode, 2);
    assert_eq!(
        resolved.outcome,
        Outcome::Failed {
            cause: FailureCause::Budget(BudgetBound::Queries),
            cached: false
        }
    );
    assert_eq!(engine.counters().bound_queries, 1);
    assert_eq!(engine.counters().budget, 1);

    // No time left at all: the wall clock bound.
    let lab = Arc::new(self::lab());
    let mut hurried = settings();
    hurried.recursion.budget.wall = Duration::ZERO;
    let engine = engine_with(&lab, &hurried);
    let resolved = engine.resolve(question(&qname, types::A)).await;
    assert_eq!(
        resolved.outcome,
        Outcome::Failed {
            cause: FailureCause::Budget(BudgetBound::Time),
            cached: false
        }
    );
    assert_eq!(engine.counters().timeout, 1);
}

#[tokio::test]
async fn locally_served_names_never_reach_an_authority() {
    let lab = Arc::new(lab());
    let engine = engine_with(
        &lab,
        &EngineSettings {
            local_zones_except: Vec::new(),
            ..settings()
        },
    );
    for (qname, rcode) in [
        ("printer.local", 3),
        ("www.example.test", 3),
        ("1.0.168.192.in-addr.arpa", 3),
        ("host.home.arpa", 3),
    ] {
        let wire = wire_name(qname);
        let resolved = engine.resolve(question(&wire, types::A)).await;
        assert_eq!(
            (resolved.rcode, resolved.outcome),
            (rcode, Outcome::Local),
            "{qname}"
        );
        assert!(
            records(&resolved.message)
                .iter()
                .any(|(_, _, rtype)| *rtype == types::SOA)
        );
    }
    let apex = wire_name("168.192.in-addr.arpa");
    let resolved = engine.resolve(question(&apex, types::SOA)).await;
    assert_eq!(resolved.rcode, 0);
    assert_eq!(lab.asked().len(), 0);
    assert_eq!(engine.counters().local, 5);
}

#[tokio::test]
async fn ipv6_addresses_without_a_route_are_marked_and_skipped() {
    // Under `auto` an IPv6 address that cannot be reached is marked for six hours.
    let lab = Arc::new(lab());
    let mut auto = settings();
    auto.recursion.outbound = Outbound::Auto;
    let engine = engine_with(&lab, &auto);
    engine.prime().await.expect("primed");
    let now = Instant::now();
    let v6: IpAddr = "2001:db8::53".parse().expect("address");
    engine.infra().put_addresses(
        &name("ns.example.test"),
        &[(v6, 3600)],
        AddressOrigin::Authoritative,
        now,
    );
    engine.infra().put_cut(
        &name("example.test"),
        vec![name("ns.example.test")],
        3600,
        now,
    );
    let qname = wire_name("www.example.test");
    let resolved = engine.resolve(question(&qname, types::A)).await;
    assert_eq!(resolved.rcode, 2, "the only address has no route");
    assert!(
        engine
            .infra()
            .server(v6, Instant::now())
            .is_unreachable(Instant::now())
    );
    // Under `v4` it is never tried.
    let engine = engine_with(&lab, &settings());
    engine.prime().await.expect("primed");
    engine.infra().put_addresses(
        &name("ns.example.test"),
        &[(v6, 3600)],
        AddressOrigin::Authoritative,
        now,
    );
    engine.infra().put_cut(
        &name("example.test"),
        vec![name("ns.example.test")],
        3600,
        now,
    );
    lab.clear_log();
    let resolved = engine.resolve(question(&qname, types::A)).await;
    assert_eq!(resolved.ede(), Some(ExtendedError::NO_REACHABLE_AUTHORITY));
    assert_eq!(lab.asked().len(), 0);
}

#[tokio::test]
async fn answers_carry_the_delegation_for_the_rpz_triggers() {
    let lab = Arc::new(lab());
    let engine = primed(&lab).await;
    engine.carry_delegation(true);
    let qname = wire_name("www.case.quirk.example.test");
    let resolved = engine.resolve(question(&qname, types::A)).await;
    let found = records(&resolved.message);
    assert!(
        found.contains(&(1, "case.quirk.example.test".to_owned(), types::NS)),
        "{found:?}"
    );
    assert!(
        found.contains(&(2, "ns.case.quirk.example.test".to_owned(), types::A)),
        "{found:?}"
    );
}

#[tokio::test]
async fn the_reference_infrastructure_cache_runs_the_engine_as_well() {
    let lab = Arc::new(lab());
    let settings = settings();
    let engine = Engine::new(
        Arc::clone(&lab),
        Arc::new(MemInfra::new(InfraBounds::HOME)),
        Arc::new(ServerTable::new(100, Duration::from_secs(900))),
        Arc::new(MemFailures::default()),
        hints::parse(LAB_HINTS).expect("hints"),
        &settings,
    );
    let qname = wire_name("www.example.test");
    let resolved = engine.resolve(question(&qname, types::A)).await;
    assert_eq!(resolved.rcode, 0);
    assert_eq!(lab.asked().len(), 3, "from the hints, unprimed");
}

#[test]
fn cookies_are_per_server_and_the_extended_error_goes_into_the_opt_record() {
    let lab = Arc::new(MemAuthority::new());
    let engine = engine_with(&lab, &settings());
    let first = engine.client_cookie(lab_ip(1));
    assert_eq!(first, engine.client_cookie(lab_ip(1)));
    assert_ne!(first, engine.client_cookie(lab_ip(2)));
    let message = message::compose(&Composed {
        qname: &wire_name("www.example.test"),
        qtype: 1,
        qclass: 1,
        rcode: 2,
        ..Composed::default()
    });
    let mut with = message.clone();
    add_ede(&mut with, ExtendedError::NO_REACHABLE_AUTHORITY);
    assert_eq!(with.len(), message.len() + 6);
    assert_eq!(&with[with.len() - 6..], &[0, 15, 0, 2, 0, 22]);
    let mut name = wire_name("www.example.test");
    mix_case(&mut name);
    assert!(name.eq_ignore_ascii_case(&wire_name("www.example.test")));
}

// WP10.3: QNAME minimisation (E35, M40).
fn asked_of(lab: &MemAuthority, server: u8) -> Vec<String> {
    lab.asked()
        .iter()
        .filter(|asked| asked.server == lab_ip(server))
        .map(|asked| asked.qname.as_str().to_owned())
        .collect()
}

async fn engine_in(lab: &Arc<MemAuthority>, mode: Minimisation) -> Lab {
    let mut settings = settings();
    settings.recursion.minimisation = mode;
    let engine = engine_with(lab, &settings);
    engine.prime().await.expect("primed");
    lab.clear_log();
    engine
}

#[tokio::test]
async fn the_tld_sees_only_the_labels_minimisation_sends() {
    // Three labels below the TLD.
    let qname = wire_name("any.wild.example.test");
    for (mode, root, tld, zone) in [
        (
            Minimisation::Relaxed,
            vec!["test"],
            vec!["example.test"],
            vec!["wild.example.test", "any.wild.example.test"],
        ),
        (
            Minimisation::Strict,
            vec!["test"],
            vec!["example.test"],
            vec!["wild.example.test", "any.wild.example.test"],
        ),
        (
            Minimisation::Off,
            vec!["any.wild.example.test"],
            vec!["any.wild.example.test"],
            vec!["any.wild.example.test"],
        ),
    ] {
        let lab = Arc::new(lab());
        let engine = engine_in(&lab, mode).await;
        let resolved = engine.resolve(question(&qname, types::A)).await;
        assert_eq!(resolved.outcome, Outcome::Answered, "{mode:?}");
        assert_eq!(asked_of(&lab, ROOT), root, "{mode:?}");
        assert_eq!(asked_of(&lab, TLD), tld, "{mode:?}");
        assert_eq!(asked_of(&lab, ZONE), zone, "{mode:?}");
        // The original type, A here, on every minimised question.
        assert!(lab.asked().iter().all(|asked| asked.qtype == types::A));
        let expected = if mode == Minimisation::Off { 0 } else { 3 };
        assert_eq!(engine.minimisation_counters(), [expected, 0, 0], "{mode:?}");
    }
}

#[tokio::test]
async fn relaxed_minimisation_falls_back_for_a_server_that_denies_its_empty_non_terminals() {
    let qname = wire_name("www.a.b.broken.example.test");
    let broken = name("broken.example.test");

    // Relaxed: the NXDOMAIN for `b.broken.example.test` is asked again with the full name,
    // which exists: the zone is asked with full names from now on.
    let lab = Arc::new(lab());
    let engine = engine_in(&lab, Minimisation::Relaxed).await;
    let resolved = engine.resolve(question(&qname, types::A)).await;
    assert_eq!(resolved.outcome, Outcome::Answered);
    assert_eq!(
        asked_of(&lab, BROKEN),
        vec!["b.broken.example.test", "www.a.b.broken.example.test"]
    );
    assert_eq!(lab.asked().len(), 5);
    assert_eq!(engine.minimisation_counters()[1..], [1, 1]);
    let cut = engine
        .infra()
        .cut(&broken, Instant::now())
        .expect("the cut");
    assert!(cut.minimise_fallback.is_some(), "remembered");
    lab.clear_log();
    let other = wire_name("www.c.broken.example.test");
    let resolved = engine.resolve(question(&other, types::A)).await;
    assert_eq!(resolved.outcome, Outcome::Answered);
    assert_eq!(asked_of(&lab, BROKEN), vec!["www.c.broken.example.test"]);
    assert_eq!(lab.asked().len(), 1, "the full name at once");

    // Strict: the NXDOMAIN stands (RFC 8020) and nothing falls back.
    let lab = Arc::new(self::lab());
    let engine = engine_in(&lab, Minimisation::Strict).await;
    let resolved = engine.resolve(question(&qname, types::A)).await;
    let header = wire::parse_header(&resolved.message).expect("header");
    assert_eq!(header.rcode, 3);
    assert_eq!(asked_of(&lab, BROKEN), vec!["b.broken.example.test"]);
    assert_eq!(lab.asked().len(), 4);
    assert_eq!(engine.minimisation_counters()[1..], [0, 0]);
    let cut = engine
        .infra()
        .cut(&broken, Instant::now())
        .expect("the cut");
    assert!(cut.minimise_fallback.is_none());

    // Off: the full name everywhere.
    let lab = Arc::new(self::lab());
    let engine = engine_in(&lab, Minimisation::Off).await;
    let resolved = engine.resolve(question(&qname, types::A)).await;
    assert_eq!(resolved.outcome, Outcome::Answered);
    assert!(
        lab.asked()
            .iter()
            .all(|asked| asked.qname.as_str() == "www.a.b.broken.example.test")
    );
    assert_eq!(lab.asked().len(), 4);
}

#[tokio::test]
async fn a_clean_nxdomain_under_relaxed_minimisation_costs_one_query_and_no_fallback() {
    let qname = wire_name("x.nothing.example.test");
    let lab = Arc::new(lab());
    let engine = engine_in(&lab, Minimisation::Relaxed).await;
    let resolved = engine.resolve(question(&qname, types::A)).await;
    let header = wire::parse_header(&resolved.message).expect("header");
    assert_eq!(header.rcode, 3);
    assert_eq!(
        asked_of(&lab, ZONE),
        vec!["nothing.example.test", "x.nothing.example.test"]
    );
    assert_eq!(engine.minimisation_counters()[1..], [1, 0]);
    let cut = engine
        .infra()
        .cut(&name("example.test"), Instant::now())
        .expect("the cut");
    assert!(cut.minimise_fallback.is_none(), "the server is clean");

    let lab = Arc::new(self::lab());
    let engine = engine_in(&lab, Minimisation::Strict).await;
    let resolved = engine.resolve(question(&qname, types::A)).await;
    let header = wire::parse_header(&resolved.message).expect("header");
    assert_eq!(header.rcode, 3);
    assert_eq!(asked_of(&lab, ZONE), vec!["nothing.example.test"]);
}

#[test]
fn the_minimiser_adds_one_label_four_times_then_more_and_stops_at_ten() {
    let mut labels: Vec<String> = (0..20).map(|index| format!("l{index}")).collect();
    labels.push("test".to_owned());
    let qname = wire_name(&labels.join("."));
    let mut minimiser = Minimiser::new(Minimisation::Relaxed, &qname, types::AAAA);
    let root = DnsName::root().to_wire();
    let mut steps = Vec::new();
    loop {
        let (asked, qtype) = minimiser.next(&root, false, &|_| false);
        steps.push(name::label_count(asked));
        assert_eq!(qtype, types::AAAA, "the original type");
        if asked.len() == qname.len() {
            break;
        }
    }
    assert_eq!(steps, vec![1, 2, 3, 4, 7, 10, 13, 16, 19, 21]);
    assert!(steps.len() - 1 <= usize::from(MAX_MINIMISE));

    // A referral starts again from the delegated zone; the names known to exist are
    // skipped; a fallback (relaxed) and the mode off ask the full name.
    let qname = wire_name("a.b.c.example.test");
    let mut minimiser = Minimiser::new(Minimisation::Relaxed, &qname, types::DS);
    assert_eq!(
        minimiser.next(&root, false, &|_| false),
        (&wire_name("test")[..], types::A)
    );
    minimiser.referred(&wire_name("example.test"));
    let known_name = wire_name("c.example.test");
    let known = |name: &[u8]| name == known_name.as_slice();
    let (asked, _) = minimiser.next(&wire_name("example.test"), false, &known);
    assert_eq!(asked, wire_name("b.c.example.test"));
    let mut minimiser = Minimiser::new(Minimisation::Relaxed, &qname, types::A);
    assert_eq!(minimiser.next(&root, true, &|_| false).0, &qname[..]);
    let mut minimiser = Minimiser::new(Minimisation::Strict, &qname, types::A);
    assert_eq!(minimiser.next(&root, true, &|_| false).0, wire_name("test"));
    let mut minimiser = Minimiser::new(Minimisation::Off, &qname, types::A);
    assert_eq!(minimiser.next(&root, false, &|_| false).0, &qname[..]);
    assert_eq!(minimised_type(types::ANY), types::A);
    assert_eq!(minimised_type(types::AAAA), types::AAAA);
}
// WP10.3: end.
