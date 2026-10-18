//! The response policy (DNS-21, DNS-23) at the level of the engine and end to end through
//! the resolver and the responder: the actions of an RPZ zone on a QNAME trigger, the
//! precedence of exact names, wildcards and zones, the client-IP triggers, the block and
//! allow lists with their exemptions, the answer phase (response IP, CNAME cloaking,
//! NSDNAME, NSIP), the rewrite of a blocked answer and the sink that applies it to a
//! forwarder's answers, the catalog following the feed's deltas and the blocked counters.
//!
//! Every list and zone here is a row of a [`DnsData`] image, the way the store feed
//! delivers it; the lists are compiled with the production compiler from their text.

mod support;

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use support::{
    a, aaaa,
    answer::{Answer, Query, decode, query},
    cname, rrset, soa, wire, zone,
};
use tenko_core::{
    Revision,
    dns::{
        BlockAction, BlockList, BlockListId, ListFormat, ListKind, ListSource, ListVersion,
        MatchRule, QueryTransport, RecordData, RrSet, Rtype, ScopeName, ScopeWeight, View, ViewId,
        Zone, ZoneKind,
    },
    serde_util::HexBytes,
};
use tenko_dns::{
    DnsData, NameBuf, Request,
    authoritative::{Authoritative, EDE_NOT_AUTHORITATIVE, rcode},
    catalog::{Catalog, CatalogHandle},
    cookie::CookieSecret,
    feed::{Change, Delta},
    lists::compile_text,
    policy::{
        Action, EDE_BLOCKED, Hit, Policy, PolicyEngine, PolicyQuery, Source, Verdict,
        answer::{PolicySink, REDIRECT_TTL, rewrite},
        counters::total_of,
    },
    respond::{
        Clock, Conn, ForwardQuery, ForwardSink, Intake, IntakeQuery, Reply, ReplyPath, Responder,
        Scratch,
    },
};

const A: u16 = 1;
const NS: u16 = 2;
const CNAME: u16 = 5;
const MX: u16 = 15;
const AAAA: u16 = 28;

const CLIENT: &str = "192.0.2.77";

/// The targets of the actions of an RPZ record (draft-vixie-dnsop-dns-rpz).
const NXDOMAIN: &str = ".";
const NODATA: &str = "*.";
const PASSTHRU: &str = "rpz-passthru.";
const DROP: &str = "rpz-drop.";
const TCP_ONLY: &str = "rpz-tcp-only.";

// ---------------------------------------------------------------------------------------
// The rows

/// A set of rows: RPZ zones with their triggers and lists with their first version.
struct World {
    image: DnsData,
}

fn trigger_set(zone: &Zone, owner: &str, data: RecordData) -> RrSet {
    rrset(
        zone,
        &ScopeName::DEFAULT,
        &format!("{owner}.{}", zone.name.as_str()),
        &[data],
    )
}

fn list_row(
    name: &str,
    kind: ListKind,
    action: BlockAction,
    exempt: &[&str],
    enabled: bool,
) -> BlockList {
    BlockList {
        id: BlockListId::generate(),
        name: name.to_string(),
        kind,
        source: ListSource::Upload,
        format: ListFormat::Domains,
        interval_hours: 24,
        action,
        enabled,
        exempt: exempt
            .iter()
            .map(|prefix| prefix.parse().expect("prefix"))
            .collect(),
        description: None,
    }
}

fn list_version(list: &BlockList, revision: u64, names: &[&str]) -> ListVersion {
    let (compiled, _) =
        compile_text(names.join("\n").as_bytes(), ListFormat::Domains).expect("the list compiles");
    ListVersion {
        list: list.id,
        revision,
        compiled: HexBytes(compiled.bytes),
        entries: compiled.entries,
        fetched: "2026-10-17T12:00:00Z".parse().expect("time"),
        etag: None,
    }
}

fn redirect(address: &str) -> BlockAction {
    BlockAction::Redirect {
        address: address.parse().expect("address"),
    }
}

impl World {
    fn new() -> Self {
        Self {
            image: DnsData::at(Revision(1)),
        }
    }

    /// An RPZ zone with the SOA record of its apex.
    fn rpz(&mut self, apex: &str) -> Zone {
        let mut zone = zone(apex);
        zone.kind = ZoneKind::Rpz;
        let apex_soa = rrset(&zone, &ScopeName::DEFAULT, apex, &[soa(apex, 60)]);
        self.image.rrsets.insert(apex_soa.key(), apex_soa);
        self.image.zones.insert(zone.id, zone.clone());
        zone
    }

    /// A trigger at `owner` (relative to the apex) with the records `data`.
    fn trigger(&mut self, zone: &Zone, owner: &str, data: RecordData) {
        let set = trigger_set(zone, owner, data);
        self.image.rrsets.insert(set.key(), set);
    }

    /// A trigger whose action is the CNAME `target`.
    fn act(&mut self, zone: &Zone, owner: &str, target: &str) {
        self.trigger(zone, owner, cname(target));
    }

    fn add_list(&mut self, list: BlockList, names: &[&str]) -> BlockList {
        let version = list_version(&list, 1, names);
        self.image.lists.insert(list.id, list.clone());
        self.image.list_versions.insert((list.id, 1), version);
        list
    }

    /// An enabled block list that answers NXDOMAIN.
    fn block_list(&mut self, name: &str, names: &[&str]) -> BlockList {
        self.add_list(
            list_row(name, ListKind::Block, BlockAction::Nxdomain, &[], true),
            names,
        )
    }

    /// An enabled allow list.
    fn allow_list(&mut self, name: &str, names: &[&str], exempt: &[&str]) -> BlockList {
        self.add_list(
            list_row(name, ListKind::Allow, BlockAction::Nxdomain, exempt, true),
            names,
        )
    }

    fn catalog(&self) -> Catalog {
        Catalog::build(&self.image)
    }
}

// ---------------------------------------------------------------------------------------
// The engine

fn verdict<'a>(
    catalog: &'a Catalog,
    view: Option<ViewId>,
    client: &str,
    transport: QueryTransport,
    qname: &str,
    qtype: u16,
) -> Verdict<'a> {
    let wire = wire(qname);
    Policy.check(
        catalog,
        &PolicyQuery {
            view,
            client: client.parse().expect("client"),
            qname: &wire,
            qtype: Rtype(qtype),
            transport,
        },
    )
}

/// The verdict for an `A` query over UDP from the default client.
fn check<'a>(catalog: &'a Catalog, qname: &str) -> Verdict<'a> {
    verdict(catalog, None, CLIENT, QueryTransport::Udp, qname, A)
}

fn check_from<'a>(catalog: &'a Catalog, client: &str, qname: &str) -> Verdict<'a> {
    verdict(catalog, None, client, QueryTransport::Udp, qname, A)
}

fn check_answer_as<'a>(
    catalog: &'a Catalog,
    client: &str,
    qname: &str,
    qtype: u16,
    message: &[u8],
) -> Verdict<'a> {
    let wire = wire(qname);
    Policy.check_answer(
        catalog,
        &PolicyQuery {
            view: None,
            client: client.parse().expect("client"),
            qname: &wire,
            qtype: Rtype(qtype),
            transport: QueryTransport::Udp,
        },
        message,
    )
}

/// The verdict for the answer `message` to an `A` query for `www.example.org`.
fn check_answer<'a>(catalog: &'a Catalog, message: &Message) -> Verdict<'a> {
    check_answer_as(catalog, CLIENT, "www.example.org", A, &message.bytes())
}

fn block(verdict: Verdict<'_>) -> Hit<'_> {
    match verdict {
        Verdict::Block(hit) => hit,
        other => panic!("expected a block, got {other:?}"),
    }
}

fn is_zone(hit: &Hit<'_>, zone: &Zone) -> bool {
    hit.source == Source::Zone(zone.id) && hit.name == zone.name.as_str()
}

fn is_list(hit: &Hit<'_>, list: &BlockList) -> bool {
    hit.source == Source::List(list.id) && hit.name == list.name
}

// ---------------------------------------------------------------------------------------
// Messages

/// One record of a hand-built message.
struct Rr {
    owner: String,
    rtype: u16,
    rdata: Vec<u8>,
}

fn rr(owner: &str, rtype: u16, rdata: Vec<u8>) -> Rr {
    Rr {
        owner: owner.to_string(),
        rtype,
        rdata,
    }
}

fn v4(text: &str) -> Vec<u8> {
    text.parse::<Ipv4Addr>().expect("address").octets().to_vec()
}

fn v6(text: &str) -> Vec<u8> {
    text.parse::<Ipv6Addr>().expect("address").octets().to_vec()
}

/// A response to a query for `qname`, written without name compression.
struct Message {
    qname: String,
    qtype: u16,
    answers: Vec<Rr>,
    authority: Vec<Rr>,
    additional: Vec<Rr>,
    /// The options of an OPT record.
    opt: Option<Vec<(u16, Vec<u8>)>>,
}

impl Message {
    fn new(qname: &str, qtype: u16) -> Self {
        Self {
            qname: qname.to_string(),
            qtype,
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            opt: None,
        }
    }

    /// The usual answer of `www.example.org`.
    fn www() -> Self {
        Self::new("www.example.org", A)
    }

    fn answer(mut self, owner: &str, rtype: u16, rdata: Vec<u8>) -> Self {
        self.answers.push(rr(owner, rtype, rdata));
        self
    }

    fn authority(mut self, owner: &str, rtype: u16, rdata: Vec<u8>) -> Self {
        self.authority.push(rr(owner, rtype, rdata));
        self
    }

    fn additional(mut self, owner: &str, rtype: u16, rdata: Vec<u8>) -> Self {
        self.additional.push(rr(owner, rtype, rdata));
        self
    }

    fn opt(mut self, options: Vec<(u16, Vec<u8>)>) -> Self {
        self.opt = Some(options);
        self
    }

    fn bytes(&self) -> Vec<u8> {
        let count = |records: &[Rr]| u16::try_from(records.len()).expect("count");
        let mut out = vec![0x42, 0x42, 0x81, 0x80];
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&count(&self.answers).to_be_bytes());
        out.extend_from_slice(&count(&self.authority).to_be_bytes());
        out.extend_from_slice(
            &(count(&self.additional) + u16::from(self.opt.is_some())).to_be_bytes(),
        );
        out.extend_from_slice(&wire(&self.qname));
        out.extend_from_slice(&self.qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        for record in self
            .answers
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
        {
            out.extend_from_slice(&wire(&record.owner));
            out.extend_from_slice(&record.rtype.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&300u32.to_be_bytes());
            let len = u16::try_from(record.rdata.len()).expect("length");
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&record.rdata);
        }
        if let Some(options) = &self.opt {
            let mut data = Vec::new();
            for (code, value) in options {
                data.extend_from_slice(&code.to_be_bytes());
                data.extend_from_slice(&u16::try_from(value.len()).expect("length").to_be_bytes());
                data.extend_from_slice(value);
            }
            out.push(0);
            out.extend_from_slice(&41u16.to_be_bytes());
            out.extend_from_slice(&1232u16.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&u16::try_from(data.len()).expect("length").to_be_bytes());
            out.extend_from_slice(&data);
        }
        out
    }
}

// ---------------------------------------------------------------------------------------
// The responder

struct Engine {
    responder: Responder<Authoritative>,
    scratch: Scratch,
    clock: Clock,
}

impl Engine {
    fn new(catalog: &Catalog) -> Self {
        let resolver =
            Authoritative::new(CatalogHandle::new(catalog.clone())).with_policy(Arc::new(Policy));
        Self {
            responder: Responder::new(resolver, CookieSecret::with_secret([3; 16]))
                .with_metrics(false),
            scratch: Scratch::new(),
            clock: Clock::now(),
        }
    }

    fn reply(&mut self, query: &Query, client: &str, transport: QueryTransport) -> Reply {
        let conn = Conn {
            client: SocketAddr::new(client.parse().expect("client"), 40000),
            local: "192.0.2.53:53".parse().expect("local"),
            transport,
        };
        self.responder.respond(
            &query.bytes(0x1234),
            &conn,
            &self.clock,
            Instant::now(),
            &mut self.scratch,
        )
    }

    fn ask_over(&mut self, query: &Query, client: &str, transport: QueryTransport) -> Answer {
        assert_eq!(self.reply(query, client, transport), Reply::Send);
        let answer = decode(&self.scratch.out);
        assert_eq!(answer.header.id, 0x1234);
        answer
    }

    /// A query for `qname` and `qtype` with RD over UDP, from the default client.
    fn ask(&mut self, qname: &str, qtype: u16) -> Answer {
        self.ask_over(&query(qname, qtype).rd(), CLIENT, QueryTransport::Udp)
    }

    fn ask_from(&mut self, qname: &str, qtype: u16, client: &str) -> Answer {
        self.ask_over(&query(qname, qtype).rd(), client, QueryTransport::Udp)
    }
}

/// The answer is blocked: the RCODE, no records and the extended error `Blocked`.
fn assert_blocked(answer: &Answer, code: u16) {
    assert_eq!(answer.rcode, code, "{answer:?}");
    assert_eq!(answer.ede(), Some(EDE_BLOCKED), "{answer:?}");
    assert!(answer.answers.is_empty(), "{answer:?}");
}

/// The policy did not block: this resolver has no zone and no forwarder, so the query is
/// refused as not authoritative.
fn assert_not_blocked(answer: &Answer) {
    assert_eq!(answer.rcode, rcode::REFUSED, "{answer:?}");
    assert_eq!(answer.ede(), Some(EDE_NOT_AUTHORITATIVE), "{answer:?}");
}

// ---------------------------------------------------------------------------------------
// 1. The actions of an RPZ QNAME trigger

#[test]
fn an_nxdomain_trigger_answers_nxdomain_with_the_extended_error_blocked() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "bad.example.org", NXDOMAIN);
    let catalog = world.catalog();
    let hit = block(check(&catalog, "bad.example.org"));
    assert!(is_zone(&hit, &rpz));
    assert_eq!(hit.action, Action::Nxdomain);
    assert_eq!(check(&catalog, "good.example.org"), Verdict::Pass);
    let mut engine = Engine::new(&catalog);
    assert_blocked(&engine.ask("bad.example.org", A), rcode::NXDOMAIN);
    assert_not_blocked(&engine.ask("good.example.org", A));
}

#[test]
fn a_nodata_trigger_answers_noerror_without_records() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "bad.example.org", NODATA);
    let catalog = world.catalog();
    let hit = block(check(&catalog, "bad.example.org"));
    assert!(is_zone(&hit, &rpz));
    assert_eq!(hit.action, Action::Nodata);
    let mut engine = Engine::new(&catalog);
    assert_blocked(&engine.ask("bad.example.org", A), rcode::NOERROR);
    assert_blocked(&engine.ask("bad.example.org", AAAA), rcode::NOERROR);
}

#[test]
fn a_drop_trigger_gives_no_answer() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "bad.example.org", DROP);
    let catalog = world.catalog();
    let hit = block(check(&catalog, "bad.example.org"));
    assert!(is_zone(&hit, &rpz));
    assert_eq!(hit.action, Action::Drop);
    let mut engine = Engine::new(&catalog);
    let bad = query("bad.example.org", A).rd();
    assert_eq!(engine.reply(&bad, CLIENT, QueryTransport::Udp), Reply::Drop);
    assert_eq!(engine.reply(&bad, CLIENT, QueryTransport::Tcp), Reply::Drop);
    assert_not_blocked(&engine.ask("good.example.org", A));
}

#[test]
fn a_passthru_trigger_passes_a_name_that_a_block_list_holds() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "ads.example.org", PASSTHRU);
    let list = world.block_list("ads", &["example.org"]);
    let catalog = world.catalog();
    // The name of the trigger passes, and no list is asked about it.
    assert_eq!(check(&catalog, "ads.example.org"), Verdict::Allowed);
    // The list blocks the other names of its domain.
    assert!(is_list(&block(check(&catalog, "www.example.org")), &list));
    let mut engine = Engine::new(&catalog);
    assert_not_blocked(&engine.ask("ads.example.org", A));
    assert_blocked(&engine.ask("www.example.org", A), rcode::NXDOMAIN);
}

#[test]
fn a_passthru_in_the_first_zone_ends_the_policy_for_the_later_zones() {
    let mut world = World::new();
    let first = world.rpz("a.rpz.example.test");
    let second = world.rpz("b.rpz.example.test");
    world.act(&first, "bad.example.org", PASSTHRU);
    world.act(&second, "bad.example.org", NXDOMAIN);
    let catalog = world.catalog();
    assert_eq!(check(&catalog, "bad.example.org"), Verdict::Allowed);
}

#[test]
fn a_tcp_only_trigger_truncates_over_udp_and_passes_over_tcp() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "big.example.org", TCP_ONLY);
    let catalog = world.catalog();
    let hit = block(check(&catalog, "big.example.org"));
    assert!(is_zone(&hit, &rpz));
    assert_eq!(hit.action, Action::TcpOnly);
    for transport in [
        QueryTransport::Tcp,
        QueryTransport::Dot,
        QueryTransport::Doh,
    ] {
        assert_eq!(
            verdict(&catalog, None, CLIENT, transport, "big.example.org", A),
            Verdict::Allowed,
            "{transport:?}"
        );
    }
    let mut engine = Engine::new(&catalog);
    let udp = engine.ask("big.example.org", A);
    assert!(udp.header.tc, "{udp:?}");
    assert_blocked(&udp, rcode::NOERROR);
    assert_eq!(udp.authority, []);
    let tcp = engine.ask_over(
        &query("big.example.org", A).rd(),
        CLIENT,
        QueryTransport::Tcp,
    );
    assert!(!tcp.header.tc);
    assert_not_blocked(&tcp);
}

#[test]
fn local_data_answers_the_asked_type_and_nodata_for_the_others() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.trigger(&rpz, "walled.example.org", a(80));
    let catalog = world.catalog();
    let hit = block(check(&catalog, "walled.example.org"));
    assert!(is_zone(&hit, &rpz));
    let Action::Local(records) = hit.action else {
        panic!("expected local data, got {:?}", hit.action);
    };
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].rtype, Rtype::A);
    assert_eq!(&*records[0].rdata, [192, 0, 2, 80]);
    let mut engine = Engine::new(&catalog);
    let address = engine.ask("walled.example.org", A);
    assert_eq!((address.rcode, address.ede()), (rcode::NOERROR, Some(15)));
    assert_eq!(address.answers.len(), 1);
    assert_eq!(address.answers[0].rtype, A);
    assert_eq!(address.answers[0].rdata, [192, 0, 2, 80]);
    assert_eq!(address.answers[0].owner, "walled.example.org");
    assert_blocked(&engine.ask("walled.example.org", AAAA), rcode::NOERROR);
}

#[test]
fn local_data_with_several_types_answers_each_by_its_type() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.trigger(&rpz, "walled.example.org", a(80));
    world.trigger(&rpz, "walled.example.org", aaaa(80));
    let mut engine = Engine::new(&world.catalog());
    let v4 = engine.ask("walled.example.org", A);
    assert_eq!(v4.answers.len(), 1);
    assert_eq!(v4.answers[0].rdata, [192, 0, 2, 80]);
    let v6 = engine.ask("walled.example.org", AAAA);
    assert_eq!(v6.answers.len(), 1);
    assert_eq!(v6.answers[0].rtype, AAAA);
    assert_blocked(&engine.ask("walled.example.org", MX), rcode::NOERROR);
}

#[test]
fn local_data_that_is_a_cname_answers_for_any_type() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "bad.example.org", "walled.example.test");
    let catalog = world.catalog();
    let hit = block(check(&catalog, "bad.example.org"));
    let Action::Local(records) = hit.action else {
        panic!("expected local data, got {:?}", hit.action);
    };
    assert_eq!(records[0].rtype, Rtype::CNAME);
    let mut engine = Engine::new(&catalog);
    for qtype in [A, AAAA, MX] {
        let answer = engine.ask("bad.example.org", qtype);
        assert_eq!(
            (answer.rcode, answer.ede()),
            (rcode::NOERROR, Some(EDE_BLOCKED))
        );
        assert_eq!(answer.answers.len(), 1, "type {qtype}");
        assert_eq!(answer.answers[0].rtype, CNAME);
        assert_eq!(
            answer.answers[0].target.as_deref(),
            Some("walled.example.test")
        );
    }
}

// ---------------------------------------------------------------------------------------
// 2. Exact names and wildcards

#[test]
fn an_exact_trigger_wins_over_a_wildcard() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "*.example.org", NODATA);
    world.act(&rpz, "www.example.org", NXDOMAIN);
    let catalog = world.catalog();
    assert_eq!(
        block(check(&catalog, "www.example.org")).action,
        Action::Nxdomain
    );
    assert_eq!(
        block(check(&catalog, "mail.example.org")).action,
        Action::Nodata
    );
    // The exact trigger does not reach below its name; the wildcard does.
    assert_eq!(
        block(check(&catalog, "a.www.example.org")).action,
        Action::Nodata
    );
}

#[test]
fn a_wildcard_matches_the_names_below_and_not_the_name_itself() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "*.bad.example.org", NXDOMAIN);
    let catalog = world.catalog();
    assert_eq!(check(&catalog, "bad.example.org"), Verdict::Pass);
    assert_eq!(check(&catalog, "example.org"), Verdict::Pass);
    assert_eq!(check(&catalog, "xbad.example.org"), Verdict::Pass);
    for blocked in ["a.bad.example.org", "a.b.c.bad.example.org"] {
        let hit = block(check(&catalog, blocked));
        assert!(is_zone(&hit, &rpz), "{blocked}");
        assert_eq!(hit.action, Action::Nxdomain, "{blocked}");
    }
    let mut engine = Engine::new(&catalog);
    assert_not_blocked(&engine.ask("bad.example.org", A));
    assert_blocked(&engine.ask("a.bad.example.org", A), rcode::NXDOMAIN);
}

#[test]
fn a_name_and_its_wildcard_are_two_triggers() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "bad.example.org", NXDOMAIN);
    world.act(&rpz, "*.bad.example.org", NODATA);
    let catalog = world.catalog();
    assert_eq!(
        block(check(&catalog, "bad.example.org")).action,
        Action::Nxdomain
    );
    assert_eq!(
        block(check(&catalog, "www.bad.example.org")).action,
        Action::Nodata
    );
}

#[test]
fn a_closer_wildcard_wins_over_one_further_up() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "*.example.org", NODATA);
    world.act(&rpz, "*.deep.example.org", NXDOMAIN);
    let catalog = world.catalog();
    for closer in ["x.deep.example.org", "x.y.deep.example.org"] {
        assert_eq!(
            block(check(&catalog, closer)).action,
            Action::Nxdomain,
            "{closer}"
        );
    }
    // `deep.example.org` itself is not below `*.deep.example.org`.
    for further in ["x.example.org", "deep.example.org", "x.y.example.org"] {
        assert_eq!(
            block(check(&catalog, further)).action,
            Action::Nodata,
            "{further}"
        );
    }
    assert_eq!(check(&catalog, "example.org"), Verdict::Pass);
}

#[test]
fn names_match_without_regard_to_case() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "Bad.Example.ORG", NXDOMAIN);
    let mut engine = Engine::new(&world.catalog());
    assert_blocked(&engine.ask("BAD.example.org", A), rcode::NXDOMAIN);
}

// ---------------------------------------------------------------------------------------
// 3. The order of the zones

struct TwoZones {
    catalog: Catalog,
    first: Zone,
    second: Zone,
    view: ViewId,
}

/// Two RPZ zones that both hold `bad.example.org` (the first NXDOMAIN, the second NODATA),
/// the second also `only.example.org`, and a view for `198.51.100.0/24` whose scope map
/// names the second zone.
fn two_zones() -> TwoZones {
    let mut world = World::new();
    let first = world.rpz("a.rpz.example.test");
    let second = world.rpz("b.rpz.example.test");
    world.act(&first, "bad.example.org", NXDOMAIN);
    world.act(&second, "bad.example.org", NODATA);
    world.act(&second, "only.example.org", NXDOMAIN);
    let view = View {
        id: ViewId::generate(),
        name: "lab".to_string(),
        rules: vec![MatchRule::ClientSubnet {
            prefixes: vec!["198.51.100.0/24".parse().expect("prefix")],
        }],
        scope_map: vec![ScopeWeight {
            zone: second.id,
            scope: ScopeName::DEFAULT,
            weight: 1,
        }],
        order: 1,
        recursion: None,
        description: None,
    };
    let id = view.id;
    world.image.views.insert(id, view);
    TwoZones {
        catalog: world.catalog(),
        first,
        second,
        view: id,
    }
}

#[test]
fn the_first_zone_by_name_wins_for_the_implicit_default_view() {
    let zones = two_zones();
    let hit = block(check(&zones.catalog, "bad.example.org"));
    assert!(is_zone(&hit, &zones.first));
    assert_eq!(hit.action, Action::Nxdomain);
    // A zone without a match lets the next one decide.
    let hit = block(check(&zones.catalog, "only.example.org"));
    assert!(is_zone(&hit, &zones.second));
}

#[test]
fn a_view_that_names_the_second_zone_puts_it_first() {
    let zones = two_zones();
    let hit = block(verdict(
        &zones.catalog,
        Some(zones.view),
        CLIENT,
        QueryTransport::Udp,
        "bad.example.org",
        A,
    ));
    assert!(is_zone(&hit, &zones.second));
    assert_eq!(hit.action, Action::Nodata);
    // The zone the view does not name still applies after it.
    let hit = block(verdict(
        &zones.catalog,
        Some(zones.view),
        CLIENT,
        QueryTransport::Udp,
        "only.example.org",
        A,
    ));
    assert!(is_zone(&hit, &zones.second));
}

#[test]
fn the_view_a_client_matches_orders_the_zones_end_to_end() {
    let zones = two_zones();
    let mut engine = Engine::new(&zones.catalog);
    let outside = engine.ask_from("bad.example.org", A, "203.0.113.7");
    assert_blocked(&outside, rcode::NXDOMAIN);
    let inside = engine.ask_from("bad.example.org", A, "198.51.100.7");
    assert_blocked(&inside, rcode::NOERROR);
}

#[test]
fn zones_beyond_the_scope_map_follow_in_name_order() {
    let mut world = World::new();
    let alpha = world.rpz("a.rpz.example.test");
    let beta = world.rpz("b.rpz.example.test");
    let gamma = world.rpz("c.rpz.example.test");
    for zone in [&alpha, &beta, &gamma] {
        world.act(zone, "bad.example.org", NXDOMAIN);
    }
    let view = View {
        id: ViewId::generate(),
        name: "lab".to_string(),
        rules: Vec::new(),
        scope_map: vec![ScopeWeight {
            zone: gamma.id,
            scope: ScopeName::DEFAULT,
            weight: 1,
        }],
        order: 1,
        recursion: None,
        description: None,
    };
    let id = view.id;
    world.image.views.insert(id, view);
    let catalog = world.catalog();
    let hit = block(verdict(
        &catalog,
        Some(id),
        CLIENT,
        QueryTransport::Udp,
        "bad.example.org",
        A,
    ));
    assert!(is_zone(&hit, &gamma));
    // Without the view, by name.
    assert!(is_zone(&block(check(&catalog, "bad.example.org")), &alpha));
}

// ---------------------------------------------------------------------------------------
// 4. Client-IP triggers

#[test]
fn a_client_ip_passthru_exempts_that_client() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "bad.example.org", NXDOMAIN);
    world.act(&rpz, "32.10.113.0.203.rpz-client-ip", PASSTHRU);
    let catalog = world.catalog();
    assert_eq!(
        check_from(&catalog, "203.0.113.10", "bad.example.org"),
        Verdict::Allowed
    );
    assert!(is_zone(
        &block(check_from(&catalog, "203.0.113.11", "bad.example.org")),
        &rpz
    ));
    let mut engine = Engine::new(&catalog);
    assert_not_blocked(&engine.ask_from("bad.example.org", A, "203.0.113.10"));
    assert_blocked(
        &engine.ask_from("bad.example.org", A, "203.0.113.11"),
        rcode::NXDOMAIN,
    );
}

#[test]
fn a_client_ip_nxdomain_blocks_every_name_for_that_client() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "24.0.113.0.203.rpz-client-ip", NXDOMAIN);
    let catalog = world.catalog();
    for qname in ["www.example.org", "example.net", "anything.example.test"] {
        let hit = block(check_from(&catalog, "203.0.113.50", qname));
        assert!(is_zone(&hit, &rpz), "{qname}");
        assert_eq!(hit.action, Action::Nxdomain, "{qname}");
    }
    assert_eq!(
        check_from(&catalog, "198.51.100.50", "www.example.org"),
        Verdict::Pass
    );
    let mut engine = Engine::new(&catalog);
    assert_blocked(
        &engine.ask_from("www.example.org", A, "203.0.113.50"),
        rcode::NXDOMAIN,
    );
    assert_not_blocked(&engine.ask_from("www.example.org", A, "198.51.100.50"));
}

#[test]
fn the_longer_client_prefix_wins() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "24.0.113.0.203.rpz-client-ip", NXDOMAIN);
    world.act(&rpz, "32.10.113.0.203.rpz-client-ip", PASSTHRU);
    let catalog = world.catalog();
    assert_eq!(
        check_from(&catalog, "203.0.113.10", "www.example.org"),
        Verdict::Allowed
    );
    assert!(matches!(
        check_from(&catalog, "203.0.113.11", "www.example.org"),
        Verdict::Block(_)
    ));
}

#[test]
fn a_client_trigger_is_found_for_an_ipv6_client_and_a_mapped_address() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "128.1.zz.db8.2001.rpz-client-ip", NXDOMAIN);
    world.act(&rpz, "32.10.113.0.203.rpz-client-ip", NODATA);
    let catalog = world.catalog();
    assert!(matches!(
        check_from(&catalog, "2001:db8::1", "www.example.org"),
        Verdict::Block(_)
    ));
    assert_eq!(
        check_from(&catalog, "2001:db8::2", "www.example.org"),
        Verdict::Pass
    );
    let mapped = block(check_from(
        &catalog,
        "::ffff:203.0.113.10",
        "www.example.org",
    ));
    assert_eq!(mapped.action, Action::Nodata);
}

// ---------------------------------------------------------------------------------------
// 5. Block lists

#[test]
fn a_list_blocks_the_name_and_the_names_below_it_and_nothing_beside() {
    let mut world = World::new();
    let list = world.block_list("ads", &["ads.example.org"]);
    let catalog = world.catalog();
    for blocked in [
        "ads.example.org",
        "www.ads.example.org",
        "a.b.ads.example.org",
    ] {
        let hit = block(check(&catalog, blocked));
        assert!(is_list(&hit, &list), "{blocked}");
        assert_eq!(hit.action, Action::Nxdomain, "{blocked}");
    }
    for beside in [
        "example.org",
        "xads.example.org",
        "ads.example.net",
        "www.example.org",
        "ads.example.org.example.net",
    ] {
        assert_eq!(check(&catalog, beside), Verdict::Pass, "{beside}");
    }
    let mut engine = Engine::new(&catalog);
    assert_blocked(&engine.ask("www.ads.example.org", A), rcode::NXDOMAIN);
    assert_not_blocked(&engine.ask("example.org", A));
}

#[test]
fn a_list_holding_a_parent_blocks_the_names_of_its_children_too() {
    let mut world = World::new();
    let list = world.block_list(
        "ads",
        &["ads.example.org", "example.org", "tracker.example.net"],
    );
    let catalog = world.catalog();
    assert!(is_list(&block(check(&catalog, "www.example.org")), &list));
    assert!(is_list(
        &block(check(&catalog, "tracker.example.net")),
        &list
    ));
    assert_eq!(check(&catalog, "example.net"), Verdict::Pass);
}

#[test]
fn a_list_answers_nxdomain() {
    let mut world = World::new();
    world.block_list("ads", &["ads.example.org"]);
    let mut engine = Engine::new(&world.catalog());
    for qtype in [A, AAAA, MX] {
        assert_blocked(&engine.ask("ads.example.org", qtype), rcode::NXDOMAIN);
    }
}

#[test]
fn a_list_answers_nodata() {
    let mut world = World::new();
    let list = world.add_list(
        list_row("ads", ListKind::Block, BlockAction::Nodata, &[], true),
        &["ads.example.org"],
    );
    let catalog = world.catalog();
    let hit = block(check(&catalog, "ads.example.org"));
    assert!(is_list(&hit, &list));
    assert_eq!(hit.action, Action::Nodata);
    let mut engine = Engine::new(&catalog);
    for qtype in [A, AAAA] {
        assert_blocked(&engine.ask("ads.example.org", qtype), rcode::NOERROR);
    }
}

#[test]
fn a_list_redirects_an_a_query_to_its_address_and_answers_nodata_for_aaaa() {
    let mut world = World::new();
    let list = world.add_list(
        list_row("ads", ListKind::Block, redirect("192.0.2.80"), &[], true),
        &["ads.example.org"],
    );
    let catalog = world.catalog();
    let hit = block(check(&catalog, "ads.example.org"));
    assert!(is_list(&hit, &list));
    assert_eq!(
        hit.action,
        Action::Redirect("192.0.2.80".parse().expect("address"))
    );
    let mut engine = Engine::new(&catalog);
    let address = engine.ask("www.ads.example.org", A);
    assert_eq!(address.ede(), Some(EDE_BLOCKED));
    assert_eq!(address.rcode, rcode::NOERROR);
    assert_eq!(address.answers.len(), 1);
    assert_eq!(address.answers[0].rdata, [192, 0, 2, 80]);
    assert_eq!(address.answers[0].ttl, REDIRECT_TTL);
    assert_eq!(address.answers[0].owner, "www.ads.example.org");
    assert_blocked(&engine.ask("ads.example.org", AAAA), rcode::NOERROR);
}

#[test]
fn an_ipv6_redirect_answers_aaaa_and_nodata_for_a() {
    let mut world = World::new();
    world.add_list(
        list_row("ads", ListKind::Block, redirect("2001:db8::80"), &[], true),
        &["ads.example.org"],
    );
    let mut engine = Engine::new(&world.catalog());
    let address = engine.ask("ads.example.org", AAAA);
    assert_eq!(address.answers.len(), 1);
    assert_eq!(address.answers[0].rtype, AAAA);
    assert_eq!(address.answers[0].rdata, v6("2001:db8::80"));
    assert_blocked(&engine.ask("ads.example.org", A), rcode::NOERROR);
}

#[test]
fn a_disabled_list_blocks_nothing() {
    let mut world = World::new();
    world.add_list(
        list_row("ads", ListKind::Block, BlockAction::Nxdomain, &[], false),
        &["ads.example.org"],
    );
    // A disabled allow list allows nothing either.
    world.add_list(
        list_row(
            "keep",
            ListKind::Allow,
            BlockAction::Nxdomain,
            &["192.0.2.77/32"],
            false,
        ),
        &["www.example.org"],
    );
    let live = world.block_list("live", &["www.example.org"]);
    let catalog = world.catalog();
    assert_eq!(check(&catalog, "ads.example.org"), Verdict::Pass);
    assert!(is_list(&block(check(&catalog, "www.example.org")), &live));
    let mut engine = Engine::new(&catalog);
    assert_not_blocked(&engine.ask("ads.example.org", A));
}

#[test]
fn a_client_a_list_exempts_is_not_blocked_by_it() {
    let mut world = World::new();
    let strict = world.block_list("strict", &["ads.example.org"]);
    let lenient = world.add_list(
        list_row(
            "lenient",
            ListKind::Block,
            BlockAction::Nodata,
            &["192.0.2.0/24", "2001:db8::/32"],
            true,
        ),
        &["ads.example.org", "only-lenient.example.org"],
    );
    let catalog = world.catalog();
    // The names are in order of the lists: `lenient` before `strict`.
    let hit = block(check_from(&catalog, "203.0.113.5", "ads.example.org"));
    assert!(is_list(&hit, &lenient));
    // The exempt client falls through to the list that does not exempt it.
    let hit = block(check_from(&catalog, "192.0.2.5", "ads.example.org"));
    assert!(is_list(&hit, &strict));
    assert_eq!(
        check_from(&catalog, "192.0.2.5", "only-lenient.example.org"),
        Verdict::Pass
    );
    assert_eq!(
        check_from(&catalog, "2001:db8::5", "only-lenient.example.org"),
        Verdict::Pass
    );
    assert!(is_list(
        &block(check_from(
            &catalog,
            "203.0.113.5",
            "only-lenient.example.org"
        )),
        &lenient
    ));
}

#[test]
fn an_exempt_client_of_the_only_list_gets_the_real_answer() {
    let mut world = World::new();
    world.add_list(
        list_row(
            "ads",
            ListKind::Block,
            BlockAction::Nxdomain,
            &["192.0.2.77/32"],
            true,
        ),
        &["ads.example.org"],
    );
    let mut engine = Engine::new(&world.catalog());
    assert_not_blocked(&engine.ask("ads.example.org", A));
    assert_blocked(
        &engine.ask_from("ads.example.org", A, "192.0.2.78"),
        rcode::NXDOMAIN,
    );
}

#[test]
fn an_allow_list_prevents_a_block_by_a_list_and_by_an_rpz_trigger() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "cdn.ads.example.org", NXDOMAIN);
    world.act(&rpz, "*.ads.example.org", NXDOMAIN);
    let blocks = world.block_list("ads", &["example.org"]);
    world.allow_list("keep", &["ads.example.org"], &[]);
    let catalog = world.catalog();
    // At and below the allowed name nothing blocks, whatever the list or the zone says.
    for allowed in [
        "ads.example.org",
        "cdn.ads.example.org",
        "x.y.ads.example.org",
    ] {
        assert_eq!(check(&catalog, allowed), Verdict::Allowed, "{allowed}");
    }
    // Beside it the list still blocks.
    assert!(is_list(&block(check(&catalog, "www.example.org")), &blocks));
    let mut engine = Engine::new(&catalog);
    assert_not_blocked(&engine.ask("cdn.ads.example.org", A));
    assert_blocked(&engine.ask("www.example.org", A), rcode::NXDOMAIN);
}

#[test]
fn an_allow_list_exempts_its_clients_from_every_list_and_zone() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "bad.example.org", NXDOMAIN);
    world.act(&rpz, "24.0.113.0.203.rpz-client-ip", NXDOMAIN);
    let blocks = world.block_list("ads", &["ads.example.org"]);
    world.allow_list("admins", &["unrelated.example.test"], &["203.0.113.10/32"]);
    let catalog = world.catalog();
    for qname in ["bad.example.org", "ads.example.org", "www.example.net"] {
        assert_eq!(
            check_from(&catalog, "203.0.113.10", qname),
            Verdict::Allowed,
            "{qname}"
        );
    }
    // Another client of the same prefix is blocked by the client trigger.
    assert!(is_zone(
        &block(check_from(&catalog, "203.0.113.11", "www.example.net")),
        &rpz
    ));
    assert!(is_list(
        &block(check_from(&catalog, "198.51.100.1", "ads.example.org")),
        &blocks
    ));
    let mut engine = Engine::new(&catalog);
    assert_not_blocked(&engine.ask_from("bad.example.org", A, "203.0.113.10"));
}

// ---------------------------------------------------------------------------------------
// 6. The answer phase

fn answer_catalog_with_ip_triggers() -> (Catalog, Zone) {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "24.0.2.0.192.rpz-ip", NXDOMAIN);
    world.act(&rpz, "32.1.2.0.192.rpz-ip", PASSTHRU);
    world.act(&rpz, "128.1.zz.db8.2001.rpz-ip", NODATA);
    (world.catalog(), rpz)
}

#[test]
fn an_address_in_a_response_ip_prefix_blocks_the_answer() {
    let (catalog, rpz) = answer_catalog_with_ip_triggers();
    let message = Message::www().answer("www.example.org", A, v4("192.0.2.9"));
    let hit = block(check_answer(&catalog, &message));
    assert!(is_zone(&hit, &rpz));
    assert_eq!(hit.action, Action::Nxdomain);
    // One record out of several is enough.
    let message = Message::www()
        .answer("www.example.org", A, v4("198.51.100.1"))
        .answer("www.example.org", A, v4("192.0.2.200"));
    assert!(matches!(
        check_answer(&catalog, &message),
        Verdict::Block(_)
    ));
}

#[test]
fn an_address_outside_the_prefixes_passes_and_the_longer_prefix_wins() {
    let (catalog, _) = answer_catalog_with_ip_triggers();
    let clean = Message::www().answer("www.example.org", A, v4("198.51.100.1"));
    assert_eq!(check_answer(&catalog, &clean), Verdict::Pass);
    // 192.0.2.1 has its own PASSTHRU inside the blocked /24.
    let passthru = Message::www().answer("www.example.org", A, v4("192.0.2.1"));
    assert_eq!(check_answer(&catalog, &passthru), Verdict::Allowed);
}

#[test]
fn an_ipv6_address_in_a_response_ip_prefix_blocks_the_answer() {
    let (catalog, _) = answer_catalog_with_ip_triggers();
    let message =
        Message::new("www.example.org", AAAA).answer("www.example.org", AAAA, v6("2001:db8::1"));
    let verdict = check_answer_as(&catalog, CLIENT, "www.example.org", AAAA, &message.bytes());
    assert_eq!(block(verdict).action, Action::Nodata);
    let other =
        Message::new("www.example.org", AAAA).answer("www.example.org", AAAA, v6("2001:db8::2"));
    assert_eq!(
        check_answer_as(&catalog, CLIENT, "www.example.org", AAAA, &other.bytes()),
        Verdict::Pass
    );
}

#[test]
fn an_address_in_the_additional_section_is_no_response_ip() {
    let (catalog, _) = answer_catalog_with_ip_triggers();
    let message = Message::www()
        .answer("www.example.org", A, v4("198.51.100.1"))
        .additional("other.example.org", A, v4("192.0.2.9"));
    assert_eq!(check_answer(&catalog, &message), Verdict::Pass);
}

#[test]
fn a_cname_target_on_a_list_blocks_the_answer() {
    let mut world = World::new();
    let list = world.block_list("trackers", &["tracker.example.net"]);
    let catalog = world.catalog();
    for target in ["tracker.example.net", "cdn.tracker.example.net"] {
        let message = Message::www()
            .answer("www.example.org", CNAME, wire(target))
            .answer(target, A, v4("198.51.100.5"));
        let hit = block(check_answer(&catalog, &message));
        assert!(is_list(&hit, &list), "{target}");
        assert_eq!(hit.action, Action::Nxdomain);
    }
    // A target beside the listed name passes, and so does an answer without a CNAME.
    let beside = Message::www()
        .answer("www.example.org", CNAME, wire("cdn.example.net"))
        .answer("cdn.example.net", A, v4("198.51.100.5"));
    assert_eq!(check_answer(&catalog, &beside), Verdict::Pass);
    // The address records of a listed name are not looked at by name.
    let direct = Message::www().answer("tracker.example.net", A, v4("198.51.100.5"));
    assert_eq!(check_answer(&catalog, &direct), Verdict::Pass);
}

#[test]
fn a_cname_target_in_the_middle_of_a_chain_blocks_the_answer() {
    let mut world = World::new();
    let list = world.block_list("trackers", &["tracker.example.net"]);
    let message = Message::www()
        .answer("www.example.org", CNAME, wire("edge.example.net"))
        .answer("edge.example.net", CNAME, wire("tracker.example.net"))
        .answer("tracker.example.net", A, v4("198.51.100.5"));
    assert!(is_list(
        &block(check_answer(&world.catalog(), &message)),
        &list
    ));
}

#[test]
fn a_cname_target_on_an_allow_list_is_not_blocked() {
    let mut world = World::new();
    world.block_list("trackers", &["tracker.example.net"]);
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "tracker.example.net", NXDOMAIN);
    let blocked_message = Message::www()
        .answer("www.example.org", CNAME, wire("tracker.example.net"))
        .answer("tracker.example.net", A, v4("198.51.100.5"));
    let before = world.catalog();
    assert!(matches!(
        check_answer(&before, &blocked_message),
        Verdict::Block(_)
    ));
    world.allow_list("keep", &["tracker.example.net"], &[]);
    let after = world.catalog();
    assert_eq!(check_answer(&after, &blocked_message), Verdict::Pass);
}

#[test]
fn a_cname_target_with_an_rpz_qname_trigger_blocks_the_answer() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "*.example.net", NODATA);
    let message = Message::www()
        .answer("www.example.org", CNAME, wire("tracker.example.net"))
        .answer("tracker.example.net", A, v4("198.51.100.5"));
    let catalog = world.catalog();
    let hit = block(check_answer(&catalog, &message));
    assert!(is_zone(&hit, &rpz));
    assert_eq!(hit.action, Action::Nodata);
}

fn nsdname_catalog() -> (Catalog, Zone) {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "ns.example.org.rpz-nsdname", NXDOMAIN);
    world.act(&rpz, "*.badns.example.net.rpz-nsdname", NODATA);
    world.act(&rpz, "32.53.2.0.192.rpz-nsip", NXDOMAIN);
    (world.catalog(), rpz)
}

#[test]
fn an_ns_record_of_the_authority_section_matching_nsdname_blocks() {
    let (catalog, rpz) = nsdname_catalog();
    let message = Message::www().authority("example.org", NS, wire("ns.example.org"));
    let hit = block(check_answer(&catalog, &message));
    assert!(is_zone(&hit, &rpz));
    assert_eq!(hit.action, Action::Nxdomain);
    let wildcard = Message::www().authority("example.net", NS, wire("a.badns.example.net"));
    assert_eq!(
        block(check_answer(&catalog, &wildcard)).action,
        Action::Nodata
    );
    let other = Message::www().authority("example.org", NS, wire("ns2.example.org"));
    assert_eq!(check_answer(&catalog, &other), Verdict::Pass);
    // The wildcard does not cover its own name.
    let itself = Message::www().authority("example.net", NS, wire("badns.example.net"));
    assert_eq!(check_answer(&catalog, &itself), Verdict::Pass);
}

#[test]
fn for_an_ns_query_the_ns_records_of_the_answer_section_are_looked_at() {
    let (catalog, rpz) = nsdname_catalog();
    let message = Message::new("example.org", NS).answer("example.org", NS, wire("ns.example.org"));
    let verdict = check_answer_as(&catalog, CLIENT, "example.org", NS, &message.bytes());
    assert!(is_zone(&block(verdict), &rpz));
    // An NS record in the answer section of an address query is not a name server.
    let strange = Message::www().answer("example.org", NS, wire("ns.example.org"));
    assert_eq!(check_answer(&catalog, &strange), Verdict::Pass);
}

#[test]
fn an_address_of_a_name_server_in_the_additional_section_matching_nsip_blocks() {
    let (catalog, rpz) = nsdname_catalog();
    let message = Message::www()
        .authority("example.org", NS, wire("ns3.example.org"))
        .additional("ns3.example.org", A, v4("192.0.2.53"));
    let hit = block(check_answer(&catalog, &message));
    assert!(is_zone(&hit, &rpz));
    assert_eq!(hit.action, Action::Nxdomain);
    let elsewhere = Message::www()
        .authority("example.org", NS, wire("ns3.example.org"))
        .additional("ns3.example.org", A, v4("192.0.2.54"));
    assert_eq!(check_answer(&catalog, &elsewhere), Verdict::Pass);
    // Without a name server in the message the glue is just an address.
    let glue_only = Message::www().additional("ns3.example.org", A, v4("192.0.2.53"));
    assert_eq!(check_answer(&catalog, &glue_only), Verdict::Pass);
}

#[test]
fn a_clean_answer_passes() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "24.0.2.0.192.rpz-ip", NXDOMAIN);
    world.act(&rpz, "ns.example.org.rpz-nsdname", NXDOMAIN);
    world.act(&rpz, "bad.example.net", NXDOMAIN);
    world.block_list("trackers", &["tracker.example.net"]);
    let catalog = world.catalog();
    let message = Message::www()
        .answer("www.example.org", CNAME, wire("edge.example.com"))
        .answer("edge.example.com", A, v4("198.51.100.1"))
        .authority("example.com", NS, wire("ns.example.com"))
        .additional("ns.example.com", A, v4("203.0.113.53"));
    assert_eq!(check_answer(&catalog, &message), Verdict::Pass);
    let empty = Message::www();
    assert_eq!(check_answer(&catalog, &empty), Verdict::Pass);
    // Octets that are no message pass as well.
    assert_eq!(
        check_answer_as(&catalog, CLIENT, "www.example.org", A, &[1, 2, 3]),
        Verdict::Pass
    );
}

#[test]
fn a_query_blocked_before_the_answer_is_blocked_by_the_same_hit() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "www.example.org", NODATA);
    let catalog = world.catalog();
    let message = Message::www().answer("www.example.org", A, v4("198.51.100.1"));
    let hit = block(check_answer(&catalog, &message));
    assert!(is_zone(&hit, &rpz));
    assert_eq!(hit.action, Action::Nodata);
}

#[test]
fn an_allowed_query_name_is_never_rewritten() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "24.0.2.0.192.rpz-ip", NXDOMAIN);
    world.block_list("trackers", &["tracker.example.net"]);
    world.allow_list("keep", &["example.org"], &[]);
    let catalog = world.catalog();
    let in_prefix = Message::www().answer("www.example.org", A, v4("192.0.2.9"));
    assert_eq!(check_answer(&catalog, &in_prefix), Verdict::Allowed);
    let cloaked = Message::www()
        .answer("www.example.org", CNAME, wire("tracker.example.net"))
        .answer("tracker.example.net", A, v4("198.51.100.5"));
    assert_eq!(check_answer(&catalog, &cloaked), Verdict::Allowed);
    // The same answers to a name beside the allowed one are blocked.
    let other = check_answer_as(
        &catalog,
        CLIENT,
        "www.example.com",
        A,
        &Message::new("www.example.com", A)
            .answer("www.example.com", A, v4("192.0.2.9"))
            .bytes(),
    );
    assert!(matches!(other, Verdict::Block(_)));
}

// ---------------------------------------------------------------------------------------
// 7. The rewrite and the sink

fn nxdomain_hit() -> Hit<'static> {
    Hit::new(
        Source::List(BlockListId::generate()),
        "ads",
        Action::Nxdomain,
    )
}

/// An answer with an OPT record that carries a cookie option.
fn cached_answer() -> Message {
    Message::www()
        .answer("www.example.org", A, v4("192.0.2.9"))
        .answer("www.example.org", A, v4("192.0.2.10"))
        .opt(vec![(10, vec![7; 8])])
}

#[test]
fn an_nxdomain_rewrite_keeps_the_id_the_question_and_the_opt_record_and_adds_the_extended_error() {
    let bytes = cached_answer().bytes();
    let mut out = Vec::new();
    let code = rewrite(&bytes, &nxdomain_hit(), Rtype::A, &mut out);
    assert_eq!(code, Some(rcode::NXDOMAIN));
    let answer = decode(&out);
    assert_eq!(answer.header.id, 0x4242);
    assert_eq!(answer.rcode, rcode::NXDOMAIN);
    assert_eq!(answer.question, "www.example.org");
    assert!(answer.header.qr && answer.header.rd && answer.header.ra);
    assert!(answer.answers.is_empty() && answer.authority.is_empty());
    assert_eq!(answer.additional, []);
    let opt = answer.opt.as_ref().expect("the OPT record is kept");
    assert_eq!(opt.udp_size, 1232);
    assert_eq!(opt.option(10), Some(&[7u8; 8][..]), "the options are kept");
    assert_eq!(opt.ede(), Some(EDE_BLOCKED));
    // The question section is copied octet for octet.
    assert_eq!(out[..2], bytes[..2]);
    let question = 12 + wire("www.example.org").len() + 4;
    assert_eq!(out[12..question], bytes[12..question]);
}

#[test]
fn a_rewrite_of_an_answer_without_opt_has_no_extended_error() {
    let bytes = Message::www()
        .answer("www.example.org", A, v4("192.0.2.9"))
        .bytes();
    let mut out = Vec::new();
    assert_eq!(
        rewrite(&bytes, &nxdomain_hit(), Rtype::A, &mut out),
        Some(rcode::NXDOMAIN)
    );
    let answer = decode(&out);
    assert!(answer.opt.is_none());
    assert_eq!(answer.rcode, rcode::NXDOMAIN);
}

#[test]
fn a_nodata_rewrite_is_noerror_without_records() {
    let bytes = cached_answer().bytes();
    let hit = Hit::new(Source::List(BlockListId::generate()), "ads", Action::Nodata);
    let mut out = Vec::new();
    assert_eq!(
        rewrite(&bytes, &hit, Rtype::A, &mut out),
        Some(rcode::NOERROR)
    );
    let answer = decode(&out);
    assert_eq!(
        (answer.rcode, answer.ede()),
        (rcode::NOERROR, Some(EDE_BLOCKED))
    );
    assert_eq!(answer.answers, []);
}

#[test]
fn a_redirect_rewrite_writes_one_address_record_with_ttl_60() {
    let bytes = cached_answer().bytes();
    let hit = Hit::new(
        Source::List(BlockListId::generate()),
        "ads",
        Action::Redirect("192.0.2.80".parse().expect("address")),
    );
    let mut out = Vec::new();
    assert_eq!(
        rewrite(&bytes, &hit, Rtype::A, &mut out),
        Some(rcode::NOERROR)
    );
    let answer = decode(&out);
    assert_eq!(answer.answers.len(), 1);
    let record = &answer.answers[0];
    assert_eq!((record.rtype, record.ttl, record.class), (A, 60, 1));
    assert_eq!(REDIRECT_TTL, 60);
    assert_eq!(record.rdata, [192, 0, 2, 80]);
    assert_eq!(record.owner, "www.example.org");
    assert_eq!(answer.ede(), Some(EDE_BLOCKED));
    // An address of the other family answers a query of this type with nothing.
    let mut none = Vec::new();
    assert_eq!(
        rewrite(&bytes, &hit, Rtype::AAAA, &mut none),
        Some(rcode::NOERROR)
    );
    assert_eq!(decode(&none).answers, []);
}

#[test]
fn a_local_data_rewrite_writes_the_records_of_the_asked_type() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.trigger(&rpz, "walled.example.org", a(80));
    let catalog = world.catalog();
    let hit = block(check(&catalog, "walled.example.org"));
    let bytes = Message::new("walled.example.org", A)
        .answer("walled.example.org", A, v4("198.51.100.1"))
        .opt(Vec::new())
        .bytes();
    let mut out = Vec::new();
    assert_eq!(
        rewrite(&bytes, &hit, Rtype::A, &mut out),
        Some(rcode::NOERROR)
    );
    let answer = decode(&out);
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(answer.answers[0].rdata, [192, 0, 2, 80]);
    assert_eq!(answer.ede(), Some(EDE_BLOCKED));
}

#[test]
fn a_tcp_only_rewrite_is_an_empty_truncated_answer() {
    let bytes = cached_answer().bytes();
    let hit = Hit::new(
        Source::List(BlockListId::generate()),
        "rpz",
        Action::TcpOnly,
    );
    let mut out = Vec::new();
    assert_eq!(
        rewrite(&bytes, &hit, Rtype::A, &mut out),
        Some(rcode::NOERROR)
    );
    let answer = decode(&out);
    assert!(answer.header.tc);
    assert_eq!(answer.answers, []);
}

#[test]
fn a_drop_rewrite_and_a_message_that_does_not_parse_give_nothing() {
    let bytes = cached_answer().bytes();
    let drop = Hit::new(Source::List(BlockListId::generate()), "rpz", Action::Drop);
    let mut out = vec![1, 2, 3];
    assert_eq!(rewrite(&bytes, &drop, Rtype::A, &mut out), None);
    assert_eq!(out, [1, 2, 3], "the buffer is left alone");
    assert_eq!(
        rewrite(&[1, 2, 3], &nxdomain_hit(), Rtype::A, &mut out),
        None
    );
    assert_eq!(
        rewrite(&bytes[..20], &nxdomain_hit(), Rtype::A, &mut out),
        None
    );
}

/// A forwarder with a cached answer for every query: `intake` writes it, `submit` replies
/// with it as an upstream answer would.
struct Cached {
    answer: Vec<u8>,
    submitted: Mutex<usize>,
}

impl Cached {
    fn new(answer: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            answer,
            submitted: Mutex::new(0),
        })
    }
}

impl ForwardSink for Cached {
    fn submit(&self, query: ForwardQuery) {
        *self
            .submitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner) += 1;
        if let ReplyPath::Tcp(sender) = query.reply {
            sender
                .try_send(self.answer.clone())
                .expect("the reply path takes the answer");
        }
    }

    fn intake(&self, _query: &IntakeQuery<'_>, out: &mut Vec<u8>) -> Intake {
        out.clear();
        out.extend_from_slice(&self.answer);
        Intake::Answered { rcode: 0 }
    }
}

fn sink_over(catalog: &Catalog, inner: Arc<Cached>) -> PolicySink {
    PolicySink::new(
        inner,
        CatalogHandle::new(catalog.clone()),
        Arc::new(Policy),
        tokio::runtime::Handle::current(),
    )
}

fn intake_through(sink: &PolicySink, qname: &str, out: &mut Vec<u8>) -> Intake {
    let message = query(qname, A).bytes(1);
    let request = Request {
        id: 1,
        rd: true,
        qname: NameBuf::from_wire(&wire(qname)).expect("name"),
        qtype: A,
        qclass: 1,
        ..Request::default()
    };
    sink.intake(
        &IntakeQuery {
            message: &message,
            request: &request,
            client: SocketAddr::new(CLIENT.parse().expect("client"), 40000),
            transport: QueryTransport::Udp,
            view: None,
            rule: None,
            max_len: 1232,
            udp_size: 1232,
            cookie: None,
            now: Instant::now(),
        },
        out,
    )
}

fn ip_trigger_catalog(action: &str) -> Catalog {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "24.0.2.0.192.rpz-ip", action);
    world.catalog()
}

#[tokio::test]
async fn the_sink_rewrites_a_blocked_cache_hit_and_leaves_a_clean_one_unchanged() {
    let catalog = ip_trigger_catalog(NXDOMAIN);
    let blocked = cached_answer().bytes();
    let sink = sink_over(&catalog, Cached::new(blocked.clone()));
    let mut out = Vec::new();
    let intake = intake_through(&sink, "www.example.org", &mut out);
    assert_eq!(
        intake,
        Intake::Answered {
            rcode: rcode::NXDOMAIN
        }
    );
    let answer = decode(&out);
    assert_eq!(answer.rcode, rcode::NXDOMAIN);
    assert_eq!(answer.ede(), Some(EDE_BLOCKED));
    assert_eq!(answer.answers, []);
    assert_eq!(answer.header.id, 0x4242);

    let clean = Message::www()
        .answer("www.example.org", A, v4("198.51.100.1"))
        .opt(vec![(10, vec![7; 8])])
        .bytes();
    let sink = sink_over(&catalog, Cached::new(clean.clone()));
    let mut out = Vec::new();
    assert_eq!(
        intake_through(&sink, "www.example.org", &mut out),
        Intake::Answered { rcode: 0 }
    );
    assert_eq!(out, clean);
}

#[tokio::test]
async fn the_sink_hands_a_cache_hit_with_a_drop_action_to_the_forwarder() {
    let catalog = ip_trigger_catalog(DROP);
    let sink = sink_over(&catalog, Cached::new(cached_answer().bytes()));
    let mut out = Vec::new();
    assert_eq!(
        intake_through(&sink, "www.example.org", &mut out),
        Intake::Forward
    );
}

#[tokio::test]
async fn the_sink_without_a_policy_hands_over_the_cache_hit_unchanged() {
    let catalog = World::new().catalog();
    let bytes = cached_answer().bytes();
    let sink = sink_over(&catalog, Cached::new(bytes.clone()));
    let mut out = Vec::new();
    assert_eq!(
        intake_through(&sink, "www.example.org", &mut out),
        Intake::Answered { rcode: 0 }
    );
    assert_eq!(out, bytes);
}

/// The answer a query handed to the sink reaches its client with.
async fn upstream_answer(catalog: &Catalog, upstream: Vec<u8>) -> Option<Vec<u8>> {
    let inner = Cached::new(upstream);
    let sink = sink_over(catalog, Arc::clone(&inner));
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    sink.submit(ForwardQuery {
        message: query("www.example.org", A).rd().bytes(1),
        client: SocketAddr::new(CLIENT.parse().expect("client"), 40000),
        transport: QueryTransport::Tcp,
        view: None,
        rule: None,
        cookie: None,
        reply: ReplyPath::Tcp(sender),
    });
    assert_eq!(
        *inner
            .submitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
        1
    );
    tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("the client's path answers or closes")
}

#[tokio::test]
async fn the_sink_rewrites_a_blocked_upstream_answer_and_forwards_a_clean_one() {
    let catalog = ip_trigger_catalog(NODATA);
    let rewritten = upstream_answer(&catalog, cached_answer().bytes())
        .await
        .expect("an answer");
    let answer = decode(&rewritten);
    assert_eq!(
        (answer.rcode, answer.ede()),
        (rcode::NOERROR, Some(EDE_BLOCKED))
    );
    assert_eq!(answer.answers, []);

    let clean = Message::www()
        .answer("www.example.org", A, v4("198.51.100.1"))
        .bytes();
    let passed = upstream_answer(&catalog, clean.clone())
        .await
        .expect("an answer");
    assert_eq!(passed, clean);
}

#[tokio::test]
async fn the_sink_sends_nothing_for_an_upstream_answer_with_a_drop_action() {
    let catalog = ip_trigger_catalog(DROP);
    assert_eq!(
        upstream_answer(&catalog, cached_answer().bytes()).await,
        None
    );
}

// ---------------------------------------------------------------------------------------
// 8. The catalog follows the feed

fn delta(catalog: &Catalog, changes: Vec<Change>) -> Delta {
    let from = catalog.revision();
    Delta {
        from,
        to: from.next(),
        changes,
    }
}

fn apply(catalog: &Catalog, changes: Vec<Change>) -> Catalog {
    catalog
        .apply(&delta(catalog, changes))
        .expect("the delta follows")
}

#[test]
fn a_newer_list_version_replaces_the_matcher() {
    let mut world = World::new();
    let list = world.block_list("ads", &["old.example.org"]);
    let first = world.catalog();
    assert_eq!(first.policy().list_version(list.id), Some(1));
    assert!(matches!(
        check(&first, "old.example.org"),
        Verdict::Block(_)
    ));
    assert_eq!(check(&first, "new.example.org"), Verdict::Pass);
    let version = list_version(&list, 2, &["new.example.org"]);
    let second = apply(
        &first,
        vec![Change::ListVersion((list.id, 2), Some(version))],
    );
    assert_eq!(second.policy().list_version(list.id), Some(2));
    assert_eq!(check(&second, "old.example.org"), Verdict::Pass);
    assert!(is_list(&block(check(&second, "new.example.org")), &list));
    // The catalog before the delta is unchanged.
    assert!(matches!(
        check(&first, "old.example.org"),
        Verdict::Block(_)
    ));
}

#[test]
fn an_older_version_or_one_that_does_not_decode_keeps_the_matcher() {
    let mut world = World::new();
    let list = world.block_list("ads", &["kept.example.org"]);
    let two = apply(
        &world.catalog(),
        vec![Change::ListVersion(
            (list.id, 2),
            Some(list_version(
                &list,
                2,
                &["kept.example.org", "two.example.org"],
            )),
        )],
    );
    let stale = apply(
        &two,
        vec![Change::ListVersion(
            (list.id, 1),
            Some(list_version(&list, 1, &["stale.example.org"])),
        )],
    );
    assert_eq!(stale.policy().list_version(list.id), Some(2));
    assert_eq!(check(&stale, "stale.example.org"), Verdict::Pass);
    assert!(matches!(
        check(&stale, "two.example.org"),
        Verdict::Block(_)
    ));
    let mut garbage = list_version(&list, 3, &["garbage.example.org"]);
    garbage.compiled = HexBytes(b"not a compiled list".to_vec());
    let broken = apply(
        &stale,
        vec![Change::ListVersion((list.id, 3), Some(garbage))],
    );
    assert_eq!(broken.policy().list_version(list.id), Some(2));
    assert!(matches!(
        check(&broken, "two.example.org"),
        Verdict::Block(_)
    ));
    assert_eq!(check(&broken, "garbage.example.org"), Verdict::Pass);
}

#[test]
fn a_list_and_its_first_version_arriving_together_block() {
    let first = World::new().catalog();
    assert!(first.policy().is_empty());
    let list = list_row("ads", ListKind::Block, BlockAction::Nxdomain, &[], true);
    let version = list_version(&list, 1, &["ads.example.org"]);
    let next = apply(
        &first,
        vec![
            Change::ListVersion((list.id, 1), Some(version)),
            Change::List(list.id, Some(list.clone())),
        ],
    );
    assert!(is_list(&block(check(&next, "ads.example.org")), &list));
}

#[test]
fn deleting_the_list_row_removes_the_list() {
    let mut world = World::new();
    let list = world.block_list("ads", &["ads.example.org"]);
    let allow = world.allow_list("keep", &["www.example.org"], &["198.51.100.0/24"]);
    let first = world.catalog();
    assert!(matches!(
        check(&first, "ads.example.org"),
        Verdict::Block(_)
    ));
    assert_eq!(check(&first, "www.example.org"), Verdict::Allowed);
    let second = apply(&first, vec![Change::List(list.id, None)]);
    assert_eq!(check(&second, "ads.example.org"), Verdict::Pass);
    assert_eq!(second.policy().list_version(list.id), None);
    assert_eq!(check(&second, "www.example.org"), Verdict::Allowed);
    let third = apply(&second, vec![Change::List(allow.id, None)]);
    assert_eq!(check(&third, "www.example.org"), Verdict::Pass);
    assert!(third.policy().is_empty());
    assert_eq!(
        check_from(&third, "198.51.100.9", "ads.example.org"),
        Verdict::Pass
    );
}

#[test]
fn disabling_a_list_row_stops_it_and_enabling_it_again_resumes() {
    let mut world = World::new();
    let list = world.block_list("ads", &["ads.example.org"]);
    let first = world.catalog();
    let mut off = list.clone();
    off.enabled = false;
    let second = apply(&first, vec![Change::List(list.id, Some(off))]);
    assert_eq!(check(&second, "ads.example.org"), Verdict::Pass);
    let third = apply(&second, vec![Change::List(list.id, Some(list.clone()))]);
    assert!(is_list(&block(check(&third, "ads.example.org")), &list));
    // A changed action takes effect with the row.
    let mut nodata = list.clone();
    nodata.action = BlockAction::Nodata;
    let fourth = apply(&third, vec![Change::List(list.id, Some(nodata))]);
    assert_eq!(
        block(check(&fourth, "ads.example.org")).action,
        Action::Nodata
    );
}

#[test]
fn an_rrset_added_to_an_rpz_zone_takes_effect_and_its_removal_ends_it() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "old.example.org", NXDOMAIN);
    let first = world.catalog();
    assert_eq!(check(&first, "new.example.org"), Verdict::Pass);
    let added = trigger_set(&rpz, "new.example.org", cname(NODATA));
    let second = apply(
        &first,
        vec![Change::RrSet(added.key(), Some(added.clone()))],
    );
    let hit = block(check(&second, "new.example.org"));
    assert!(is_zone(&hit, &rpz));
    assert_eq!(hit.action, Action::Nodata);
    assert!(matches!(
        check(&second, "old.example.org"),
        Verdict::Block(_)
    ));
    // The trigger changes its action...
    let changed = trigger_set(&rpz, "new.example.org", cname(NXDOMAIN));
    let third = apply(&second, vec![Change::RrSet(changed.key(), Some(changed))]);
    assert_eq!(
        block(check(&third, "new.example.org")).action,
        Action::Nxdomain
    );
    // ...and goes away with its RRset.
    let fourth = apply(&third, vec![Change::RrSet(added.key(), None)]);
    assert_eq!(check(&fourth, "new.example.org"), Verdict::Pass);
    assert!(matches!(
        check(&fourth, "old.example.org"),
        Verdict::Block(_)
    ));
    // An answer-phase trigger added by a delta works as well.
    let ip = trigger_set(&rpz, "24.0.2.0.192.rpz-ip", cname(NXDOMAIN));
    let fifth = apply(&fourth, vec![Change::RrSet(ip.key(), Some(ip))]);
    let message = Message::www().answer("www.example.org", A, v4("192.0.2.9"));
    assert!(is_zone(&block(check_answer(&fifth, &message)), &rpz));
    assert_eq!(check_answer(&fourth, &message), Verdict::Pass);
}

#[test]
fn an_rrset_in_a_zone_scope_other_than_the_default_is_no_trigger() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    let first = world.catalog();
    let internal = support::internal();
    let set = rrset(
        &rpz,
        &internal,
        "bad.example.org.rpz.example.test",
        &[cname(NXDOMAIN)],
    );
    let second = apply(&first, vec![Change::RrSet(set.key(), Some(set))]);
    assert_eq!(check(&second, "bad.example.org"), Verdict::Pass);
}

#[test]
fn changing_the_kind_of_an_rpz_zone_away_from_rpz_removes_its_triggers() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "bad.example.org", NXDOMAIN);
    world.act(&rpz, "24.0.2.0.192.rpz-ip", NXDOMAIN);
    let first = world.catalog();
    assert!(matches!(
        check(&first, "bad.example.org"),
        Verdict::Block(_)
    ));
    let mut primary = rpz.clone();
    primary.kind = ZoneKind::Primary;
    let second = apply(&first, vec![Change::Zone(rpz.id, Some(primary))]);
    assert_eq!(check(&second, "bad.example.org"), Verdict::Pass);
    let message = Message::www().answer("www.example.org", A, v4("192.0.2.9"));
    assert_eq!(check_answer(&second, &message), Verdict::Pass);
    assert!(second.policy().is_empty());
    // Deleting the zone removes the triggers as well.
    let third = apply(&first, vec![Change::Zone(rpz.id, None)]);
    assert_eq!(check(&third, "bad.example.org"), Verdict::Pass);
    assert!(third.policy().zone(rpz.id).is_none());
}

#[test]
fn a_new_rpz_zone_arriving_in_a_delta_is_applied() {
    let first = World::new().catalog();
    let mut scratch = World::new();
    let rpz = scratch.rpz("rpz.example.test");
    let trigger = trigger_set(&rpz, "bad.example.org", cname(NXDOMAIN));
    let second = apply(
        &first,
        vec![
            Change::Zone(rpz.id, Some(rpz.clone())),
            Change::RrSet(trigger.key(), Some(trigger)),
        ],
    );
    assert!(is_zone(&block(check(&second, "bad.example.org")), &rpz));
}

#[test]
fn a_delta_that_touches_no_policy_row_keeps_the_policy() {
    let mut world = World::new();
    let rpz = world.rpz("rpz.example.test");
    world.act(&rpz, "bad.example.org", NXDOMAIN);
    world.block_list("ads", &["ads.example.org"]);
    let first = world.catalog();
    let primary = support::zone("example.test");
    let host = rrset(&primary, &ScopeName::DEFAULT, "www.example.test", &[a(1)]);
    let second = apply(
        &first,
        vec![
            Change::Zone(primary.id, Some(primary.clone())),
            Change::RrSet(host.key(), Some(host)),
        ],
    );
    assert!(matches!(
        check(&second, "bad.example.org"),
        Verdict::Block(_)
    ));
    assert!(matches!(
        check(&second, "ads.example.org"),
        Verdict::Block(_)
    ));
}

// ---------------------------------------------------------------------------------------
// 9. The counters

#[test]
fn a_blocked_query_raises_the_counter_of_its_list_by_one() {
    let mut world = World::new();
    world.block_list("counted-list", &["ads.example.org"]);
    let catalog = world.catalog();
    let before = total_of("counted-list");
    for step in 1..=3 {
        assert!(matches!(
            check(&catalog, "ads.example.org"),
            Verdict::Block(_)
        ));
        assert_eq!(total_of("counted-list"), before + step);
    }
    // A pass counts nowhere.
    assert_eq!(check(&catalog, "www.example.org"), Verdict::Pass);
    assert_eq!(total_of("counted-list"), before + 3);
}

#[test]
fn a_blocked_query_raises_the_counter_of_its_rpz_zone_by_one() {
    let mut world = World::new();
    let rpz = world.rpz("counted.rpz.example.test");
    world.act(&rpz, "bad.example.org", NODATA);
    world.act(&rpz, "ok.example.org", PASSTHRU);
    let catalog = world.catalog();
    let name = rpz.name.as_str();
    let before = total_of(name);
    for step in 1..=2 {
        assert!(matches!(
            check(&catalog, "bad.example.org"),
            Verdict::Block(_)
        ));
        assert_eq!(total_of(name), before + step);
    }
    // PASSTHRU is no block.
    assert_eq!(check(&catalog, "ok.example.org"), Verdict::Allowed);
    assert_eq!(total_of(name), before + 2);
}

#[test]
fn a_blocked_answer_counts_once_and_the_end_to_end_answer_counts_too() {
    let mut world = World::new();
    let rpz = world.rpz("answer-counted.rpz.example.test");
    world.act(&rpz, "24.0.2.0.192.rpz-ip", NXDOMAIN);
    world.act(&rpz, "bad.example.org", NXDOMAIN);
    world.block_list(
        "answer-counted-list",
        &["ads.example.org", "tracker.example.net"],
    );
    let catalog = world.catalog();
    let (zone_before, list_before) = (
        total_of("answer-counted.rpz.example.test"),
        total_of("answer-counted-list"),
    );
    let by_address = Message::www().answer("www.example.org", A, v4("192.0.2.9"));
    assert!(matches!(
        check_answer(&catalog, &by_address),
        Verdict::Block(_)
    ));
    assert_eq!(total_of("answer-counted.rpz.example.test"), zone_before + 1);
    let cloaked = Message::www()
        .answer("www.example.org", CNAME, wire("tracker.example.net"))
        .answer("tracker.example.net", A, v4("198.51.100.5"));
    assert!(matches!(
        check_answer(&catalog, &cloaked),
        Verdict::Block(_)
    ));
    assert_eq!(total_of("answer-counted-list"), list_before + 1);
    assert_eq!(total_of("answer-counted.rpz.example.test"), zone_before + 1);
    // A query blocked in the first phase counts once, whichever phase reports it.
    let by_name = Message::new("bad.example.org", A);
    let verdict = check_answer_as(&catalog, CLIENT, "bad.example.org", A, &by_name.bytes());
    assert!(matches!(verdict, Verdict::Block(_)));
    assert_eq!(total_of("answer-counted.rpz.example.test"), zone_before + 2);
    // And through the responder.
    let mut engine = Engine::new(&catalog);
    assert_blocked(&engine.ask("ads.example.org", A), rcode::NXDOMAIN);
    assert_eq!(total_of("answer-counted-list"), list_before + 2);
    assert_blocked(&engine.ask("bad.example.org", A), rcode::NXDOMAIN);
    assert_eq!(total_of("answer-counted.rpz.example.test"), zone_before + 3);
}
