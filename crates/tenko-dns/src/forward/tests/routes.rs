//! Route changes and alias chains across routes, end to end through the forwarder against
//! servers of the test's own on loopback addresses: a rule added, changed or removed takes
//! effect for the next question of a name it governs, an answer asked before the change is
//! not kept after it, a run of changes is audited once; a CNAME chain that crosses into a
//! rule's names is resolved through the rule, one that leaves a rule is resolved outside it,
//! across several rules within the chain's budget, and the resolver asks no public server
//! for a name a rule governs.

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex, PoisonError, mpsc},
    time::Duration,
};

use tenko_core::{
    Revision,
    audit::AuditDraft,
    dns::{DnsName, ForwardRule, ForwardRuleId, RuleMode},
    testing::wait_until_async,
};
use tokio_util::sync::CancellationToken;

use super::{Peer, settings};
use crate::{
    catalog::{Catalog, CatalogHandle},
    feed::DnsData,
    forward::{ForwardSettings, Forwarder, RecursionDefault, RecursionPolicy},
    name::NameBuf,
    recurse::EngineSettings,
    recursion::{Minimization, Outbound, RecursionSettings},
    respond::Intake,
    wire,
    xfr::TransferAudit,
};

/// The time an upstream or an authority has to answer an attempt: the servers of the test
/// answer at once, and a loaded machine must not turn a late answer into a retry.
const WAIT: Duration = Duration::from_secs(10);

/// The settings of the tests' forwarder: the default upstreams `upstreams`.
fn generous(upstreams: Vec<crate::pool::UpstreamSpec>) -> ForwardSettings {
    ForwardSettings {
        timeout: WAIT,
        ..settings(upstreams)
    }
}

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;

/// What a scripted server holds for a name.
#[derive(Debug, Clone, Copy)]
enum Data {
    Cname(&'static str),
    A([u8; 4]),
}

/// A server on a loopback address that answers from a table: as a resolver (RA, the chain
/// followed through its table) or as the authority of the root zone (AA, one record at a
/// time, `./NS` with its glue). It records the names it is asked.
struct Scripted {
    address: SocketAddr,
    asked: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Scripted {
    fn start(table: &[(&'static str, Data)], authority: bool) -> Self {
        let table: Vec<(Vec<u8>, Data)> = table
            .iter()
            .map(|(name, data)| (wire_name(name), *data))
            .collect();
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let address = socket.local_addr().expect("address");
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&asked);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            while let Ok((len, from)) = socket.recv_from(&mut buf) {
                let query = buf[..len].to_vec();
                let mut qname = NameBuf::root();
                if wire::read_name(&query, wire::HEADER_LEN, &mut qname).is_none() {
                    continue;
                }
                log.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(qname.as_wire().to_vec());
                let answer = scripted_answer(&query, qname.as_wire(), &table, authority);
                let _ = socket.send_to(&answer, from);
            }
        });
        Self { address, asked }
    }

    /// How often `name` was asked.
    fn asked(&self, name: &str) -> usize {
        let name = wire_name(name);
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|asked| **asked == name)
            .count()
    }

    fn upstream(&self) -> tenko_core::dns::Upstream {
        tenko_core::dns::Upstream {
            address: self.address.ip(),
            port: Some(self.address.port()),
            path: None,
        }
    }
}

fn wire_name(text: &str) -> Vec<u8> {
    DnsName::new(text).expect("name").to_wire()
}

fn push_record(out: &mut Vec<u8>, owner: &[u8], rtype: u16, data: &[u8]) {
    out.extend_from_slice(owner);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&300u32.to_be_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).expect("len").to_be_bytes());
    out.extend_from_slice(data);
}

fn scripted_answer(
    query: &[u8],
    qname: &[u8],
    table: &[(Vec<u8>, Data)],
    authority: bool,
) -> Vec<u8> {
    let end = wire::questions_end(query, 1).expect("question");
    let qtype = u16::from_be_bytes([query[end - 4], query[end - 3]]);
    let mut records = Vec::new();
    let mut count = 0u16;
    let mut additional = 0u16;
    if authority && qname == [0] && qtype == TYPE_NS {
        push_record(&mut records, &[0], TYPE_NS, &wire_name("a.root.test"));
        push_record(
            &mut records,
            &wire_name("a.root.test"),
            TYPE_A,
            &[127, 0, 0, 1],
        );
        count = 1;
        additional = 1;
    } else {
        let mut name = qname.to_vec();
        while let Some((_, data)) = table.iter().find(|(owner, _)| *owner == name) {
            count += 1;
            match data {
                Data::A(address) => {
                    push_record(&mut records, &name, TYPE_A, address);
                    break;
                }
                Data::Cname(target) => {
                    let target = wire_name(target);
                    push_record(&mut records, &name, TYPE_CNAME, &target);
                    name = target;
                    if authority {
                        break;
                    }
                }
            }
        }
    }
    let mut out = query[..2].to_vec();
    out.push(if authority {
        0x84
    } else {
        0x80 | (query[2] & 0x01)
    });
    out.push(match (authority, count) {
        (_, 0) if qname != [0] => 0x83,
        (false, _) => 0x80,
        (true, _) => 0,
    });
    for value in [1, count, 0, additional] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&query[wire::HEADER_LEN..end]);
    out.extend_from_slice(&records);
    out
}

fn rule(id: ForwardRuleId, suffix: &str, server: &Scripted) -> ForwardRule {
    ForwardRule {
        id,
        suffix: DnsName::new(suffix).expect("suffix"),
        upstreams: vec![server.upstream()],
        transport: tenko_core::dns::ForwardTransport::Plain,
        tls_name: None,
        view: None,
        mode: RuleMode::Forward,
        validate: false,
        description: None,
    }
}

fn catalog(revision: u64, rules: &[ForwardRule]) -> Catalog {
    let mut data = DnsData::at(Revision(revision));
    for rule in rules {
        data.forwarders.insert(rule.id, rule.clone());
    }
    Catalog::build(&data)
}

/// The forwarder with `settings` over the catalog of `rules`, and its catalog's handle.
struct Node {
    forwarder: Arc<Forwarder>,
    catalog: CatalogHandle,
    peer: Arc<Peer>,
    stop: CancellationToken,
    _hints: Option<tempfile::TempDir>,
}

impl Node {
    fn start(settings: ForwardSettings, rules: &[ForwardRule]) -> Self {
        Self::with_hints(settings, rules, None)
    }

    fn with_hints(
        settings: ForwardSettings,
        rules: &[ForwardRule],
        hints: Option<tempfile::TempDir>,
    ) -> Self {
        let catalog = CatalogHandle::new(catalog(1, rules));
        let stop = CancellationToken::new();
        let (forwarder, _task) = Forwarder::start(
            settings,
            catalog.clone(),
            None,
            Arc::new(RecursionPolicy::new(RecursionDefault::KnownPrefixes)),
            stop.clone(),
        );
        Self {
            forwarder,
            catalog,
            peer: Arc::new(Peer::new()),
            stop,
            _hints: hints,
        }
    }

    /// The resolver from the test's root at `root`, with `rules`.
    fn recursing(root: &Scripted, rules: &[ForwardRule]) -> Self {
        let hints = tempfile::tempdir().expect("a directory");
        let path = hints.path().join("root.hints");
        std::fs::write(
            &path,
            ". 3600000 NS a.root.test.\na.root.test. 3600000 A 127.0.0.1\n",
        )
        .expect("the hints");
        let settings = ForwardSettings {
            timeout: WAIT,
            metrics: false,
            recursion: Some(EngineSettings {
                recursion: RecursionSettings {
                    outbound: Outbound::V4,
                    validate: false,
                    minimization: Minimization::Off,
                    timeout: WAIT,
                    ..RecursionSettings::default()
                },
                hints: Some(path),
                local_zones_except: vec![DnsName::new("test").expect("name")],
                metrics: false,
                authority_port: root.address.port(),
                unwanted_flush: false,
            }),
            validation: None,
            ..ForwardSettings::default()
        };
        Self::with_hints(settings, rules, Some(hints))
    }

    async fn ask(&self, name: &str) -> Vec<u8> {
        self.peer.ask(&self.forwarder, query(name)).await
    }

    /// What the query path answers for `name` without the runtime.
    fn intake(&self, name: &str) -> Intake {
        let mut out = Vec::new();
        super::intake(
            &self.forwarder,
            &query(name),
            "127.0.0.1:4000",
            None,
            &mut out,
        )
    }

    fn cached(&self, name: &str) -> bool {
        matches!(self.intake(name), Intake::Answered { .. })
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn query(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(&mut out, 0x7357, name, TYPE_A, Some(1232));
    out[2] |= 0x01;
    out
}

/// The answer section of `answer`: each record's owner, type and data.
fn records(answer: &[u8]) -> Vec<(Vec<u8>, u16, Vec<u8>)> {
    let parsed = crate::recurse::message::parse(answer).expect("parses");
    parsed
        .answer
        .into_iter()
        .map(|rr| (rr.owner, rr.rtype, rr.data))
        .collect()
}

fn rcode(answer: &[u8]) -> u8 {
    wire::parse_header(answer).expect("header").rcode
}

fn cname(owner: &str, target: &str) -> (Vec<u8>, u16, Vec<u8>) {
    (wire_name(owner), TYPE_CNAME, wire_name(target))
}

fn a(owner: &str, address: [u8; 4]) -> (Vec<u8>, u16, Vec<u8>) {
    (wire_name(owner), TYPE_A, address.to_vec())
}

const PUBLIC: [u8; 4] = [192, 0, 2, 66];
const INSIDE: [u8; 4] = [198, 51, 100, 7];
const OTHER: [u8; 4] = [203, 0, 113, 9];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_change_takes_effect_for_the_next_question_of_a_name_it_governs() {
    let public = Scripted::start(
        &[
            ("host.corp.test", Data::A(PUBLIC)),
            ("www.example.test", Data::A(PUBLIC)),
        ],
        false,
    );
    let inside = Scripted::start(&[("host.corp.test", Data::A(INSIDE))], false);
    let other = Scripted::start(&[("host.corp.test", Data::A(OTHER))], false);
    let node = Node::start(generous(vec![public_spec(&public)]), &[]);
    node.ask("host.corp.test").await;
    node.ask("www.example.test").await;
    assert!(node.cached("host.corp.test") && node.cached("www.example.test"));
    // A rule appears: the default path's answer no longer answers its names.
    let id = ForwardRuleId::generate();
    node.catalog
        .store(catalog(2, &[rule(id, "corp.test", &inside)]));
    assert!(!node.cached("host.corp.test"), "flushed with the rule");
    assert!(node.cached("www.example.test"), "a name outside it stays");
    assert_eq!(
        records(&node.ask("host.corp.test").await),
        vec![a("host.corp.test", INSIDE)]
    );
    // The rule's servers change: what the old ones taught goes.
    node.catalog
        .store(catalog(3, &[rule(id, "corp.test", &other)]));
    assert!(!node.cached("host.corp.test"));
    assert_eq!(
        records(&node.ask("host.corp.test").await),
        vec![a("host.corp.test", OTHER)]
    );
    // A description routes nothing: the answer stays.
    let described = ForwardRule {
        description: Some("the branch office".to_owned()),
        ..rule(id, "corp.test", &other)
    };
    node.catalog.store(catalog(4, &[described]));
    assert!(node.cached("host.corp.test"));
    // The rule goes: the default path answers again at once.
    node.catalog.store(catalog(5, &[]));
    assert!(!node.cached("host.corp.test"));
    assert_eq!(
        records(&node.ask("host.corp.test").await),
        vec![a("host.corp.test", PUBLIC)]
    );
    assert_eq!(
        (
            public.asked("host.corp.test"),
            inside.asked("host.corp.test")
        ),
        (2, 1)
    );
}

fn public_spec(server: &Scripted) -> crate::pool::UpstreamSpec {
    super::plain(server.address, false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_asked_before_a_rule_change_is_not_kept_after_it() {
    // The default upstream holds its answer until the test lets it go.
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let address = socket.local_addr().expect("address");
    let (received, asked) = mpsc::channel::<()>();
    let (release, released) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 4096];
        while let Ok((len, from)) = socket.recv_from(&mut buf) {
            let query = buf[..len].to_vec();
            let _ = received.send(());
            if released.recv().is_err() {
                return;
            }
            let mut qname = NameBuf::root();
            wire::read_name(&query, wire::HEADER_LEN, &mut qname).expect("name");
            let table = [(qname.as_wire().to_vec(), Data::A(PUBLIC))];
            let _ = socket.send_to(
                &scripted_answer(&query, qname.as_wire(), &table, false),
                from,
            );
        }
    });
    let inside = Scripted::start(&[("host.corp.test", Data::A(INSIDE))], false);
    let node = Node::start(
        ForwardSettings {
            ..generous(vec![super::plain(address, false)])
        },
        &[],
    );
    node.peer.submit(&node.forwarder, query("host.corp.test"));
    tokio::task::spawn_blocking(move || {
        asked
            .recv_timeout(Duration::from_secs(10))
            .expect("the upstream is asked");
    })
    .await
    .expect("joins");
    // The rule comes while the default path's answer is on its way.
    node.catalog.store(catalog(
        2,
        &[rule(ForwardRuleId::generate(), "corp.test", &inside)],
    ));
    release.send(()).expect("released");
    let peer = Arc::clone(&node.peer);
    let answer = tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; 65_535];
        let (len, _) = peer.socket.recv_from(&mut buf).expect("an answer");
        buf.truncate(len);
        buf
    })
    .await
    .expect("joins");
    assert_eq!(records(&answer), vec![a("host.corp.test", PUBLIC)]);
    // The answer reached its client, and no other: the next question goes to the rule.
    assert!(!node.cached("host.corp.test"), "not kept past the flush");
    assert_eq!(
        records(&node.ask("host.corp.test").await),
        vec![a("host.corp.test", INSIDE)]
    );
}

/// The audit records the forwarder writes.
#[derive(Default)]
struct Audit(Mutex<Vec<AuditDraft>>);

impl TransferAudit for Audit {
    fn record(&self, draft: AuditDraft) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(draft);
    }
}

impl Audit {
    fn drafts(&self) -> Vec<AuditDraft> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_of_route_changes_is_audited_once_with_its_cause() {
    let server = Scripted::start(&[], false);
    let node = Node::start(generous(vec![public_spec(&server)]), &[]);
    let audit = Arc::new(Audit::default());
    node.forwarder
        .set_audit(Arc::clone(&audit) as Arc<dyn TransferAudit>);
    let (first, second) = (ForwardRuleId::generate(), ForwardRuleId::generate());
    // A node catching up: three changes in a row.
    node.catalog
        .store(catalog(2, &[rule(first, "one.test", &server)]));
    node.catalog.store(catalog(
        3,
        &[
            rule(first, "one.test", &server),
            rule(second, "two.test", &server),
        ],
    ));
    node.catalog
        .store(catalog(4, &[rule(second, "two.test", &server)]));
    wait_until_async("the flush is audited", async || !audit.drafts().is_empty()).await;
    let drafts = audit.drafts();
    assert_eq!(drafts.len(), 1, "one record for the run: {drafts:?}");
    let draft = &drafts[0];
    assert_eq!(draft.action, tenko_core::dns::audit::CACHE_FLUSH);
    let context = &draft.details.context;
    assert_eq!(
        context.get("cause").map(String::as_str),
        Some(crate::forward::FLUSH_CAUSE_ROUTES)
    );
    assert_eq!(context.get("revision").map(String::as_str), Some("4"));
    let suffixes = context.get("suffixes").expect("the suffixes");
    assert!(suffixes.contains("one.test") && suffixes.contains("two.test"));
    assert_eq!(
        draft.objects,
        vec![
            tenko_core::ObjectRef::from(first.min(second)),
            tenko_core::ObjectRef::from(first.max(second)),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_alias_into_a_rule_is_resolved_through_the_rule_and_flushed_with_it() {
    // The default upstream follows the alias itself, into the public view of the name.
    let public = Scripted::start(
        &[
            ("alias.example.test", Data::Cname("host.corp.test")),
            ("host.corp.test", Data::A(PUBLIC)),
        ],
        false,
    );
    let inside = Scripted::start(&[("host.corp.test", Data::A(INSIDE))], false);
    let node = Node::start(
        generous(vec![public_spec(&public)]),
        &[rule(ForwardRuleId::generate(), "corp.test", &inside)],
    );
    let answer = node.ask("alias.example.test").await;
    assert_eq!(rcode(&answer), 0);
    assert_eq!(
        records(&answer),
        vec![
            cname("alias.example.test", "host.corp.test"),
            a("host.corp.test", INSIDE),
        ]
    );
    assert_eq!(inside.asked("host.corp.test"), 1);
    // Cached under the question and under the target's own.
    assert!(node.cached("alias.example.test") && node.cached("host.corp.test"));
    // The rule goes: the combined answer goes with it.
    node.catalog.store(catalog(2, &[]));
    assert!(!node.cached("alias.example.test"));
    assert_eq!(
        records(&node.ask("alias.example.test").await),
        vec![
            cname("alias.example.test", "host.corp.test"),
            a("host.corp.test", PUBLIC),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_alias_out_of_a_rule_leaves_it() {
    let public = Scripted::start(&[("www.example.test", Data::A(PUBLIC))], false);
    // The rule's servers know their own view of the outside name.
    let inside = Scripted::start(
        &[
            ("in.corp.test", Data::Cname("www.example.test")),
            ("www.example.test", Data::A(INSIDE)),
        ],
        false,
    );
    let node = Node::start(
        generous(vec![public_spec(&public)]),
        &[rule(ForwardRuleId::generate(), "corp.test", &inside)],
    );
    assert_eq!(
        records(&node.ask("in.corp.test").await),
        vec![
            cname("in.corp.test", "www.example.test"),
            a("www.example.test", PUBLIC),
        ]
    );
    assert_eq!(public.asked("www.example.test"), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chain_through_several_rules_takes_each_rule_in_turn() {
    let public = Scripted::start(
        &[
            ("start.example.test", Data::Cname("b.one.test")),
            ("end.example.test", Data::A(PUBLIC)),
        ],
        false,
    );
    let one = Scripted::start(&[("b.one.test", Data::Cname("c.two.test"))], false);
    let two = Scripted::start(&[("c.two.test", Data::Cname("end.example.test"))], false);
    let node = Node::start(
        generous(vec![public_spec(&public)]),
        &[
            rule(ForwardRuleId::generate(), "one.test", &one),
            rule(ForwardRuleId::generate(), "two.test", &two),
        ],
    );
    assert_eq!(
        records(&node.ask("start.example.test").await),
        vec![
            cname("start.example.test", "b.one.test"),
            cname("b.one.test", "c.two.test"),
            cname("c.two.test", "end.example.test"),
            a("end.example.test", PUBLIC),
        ]
    );
    assert_eq!(
        (
            public.asked("start.example.test"),
            one.asked("b.one.test"),
            two.asked("c.two.test"),
            public.asked("end.example.test"),
        ),
        (1, 1, 1, 1)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chain_that_loops_between_two_rules_fails_after_one_round() {
    let public = Scripted::start(&[], false);
    let one = Scripted::start(&[("x.one.test", Data::Cname("y.two.test"))], false);
    let two = Scripted::start(&[("y.two.test", Data::Cname("x.one.test"))], false);
    let node = Node::start(
        generous(vec![public_spec(&public)]),
        &[
            rule(ForwardRuleId::generate(), "one.test", &one),
            rule(ForwardRuleId::generate(), "two.test", &two),
        ],
    );
    assert_eq!(rcode(&node.ask("x.one.test").await), 2, "SERVFAIL");
    assert_eq!((one.asked("x.one.test"), two.asked("y.two.test")), (1, 1));
    assert!(!node.cached("x.one.test"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_link_budget_bounds_a_chain_across_rules() {
    // Ten links, each into the other rule: past the budget of eight.
    let names: Vec<String> = (0..=10)
        .map(|n| format!("n{n}.{}.test", if n % 2 == 0 { "one" } else { "two" }))
        .collect();
    let names: &'static [String] = Box::leak(names.into_boxed_slice());
    let table = |parity: usize| -> Vec<(&'static str, Data)> {
        (0..10)
            .filter(|n| n % 2 == parity)
            .map(|n| (names[n].as_str(), Data::Cname(names[n + 1].as_str())))
            .collect()
    };
    let one = Scripted::start(&table(0), false);
    let two = Scripted::start(&table(1), false);
    let public = Scripted::start(&[], false);
    let node = Node::start(
        generous(vec![public_spec(&public)]),
        &[
            rule(ForwardRuleId::generate(), "one.test", &one),
            rule(ForwardRuleId::generate(), "two.test", &two),
        ],
    );
    assert_eq!(rcode(&node.ask("n0.one.test").await), 2, "SERVFAIL");
    let asked = |server: &Scripted| {
        server
            .asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    };
    let budget = usize::from(crate::recursion::WorkBudget::DEFAULT.restarts);
    assert_eq!(
        asked(&one) + asked(&two),
        budget + 1,
        "one question per link within it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_link_budget_counts_the_links_of_the_last_part() {
    // One link into the rule, then nine inside it: ten links, past the budget of eight.
    let names: Vec<String> = (0..=9).map(|n| format!("c{n}.one.test")).collect();
    let names: &'static [String] = Box::leak(names.into_boxed_slice());
    let mut table: Vec<(&'static str, Data)> = (0..9)
        .map(|n| (names[n].as_str(), Data::Cname(names[n + 1].as_str())))
        .collect();
    table.push((names[9].as_str(), Data::A(INSIDE)));
    let one = Scripted::start(&table, false);
    let public = Scripted::start(&[("start.example.test", Data::Cname("c0.one.test"))], false);
    let node = Node::start(
        generous(vec![public_spec(&public)]),
        &[rule(ForwardRuleId::generate(), "one.test", &one)],
    );
    assert_eq!(rcode(&node.ask("start.example.test").await), 2, "SERVFAIL");
    assert!(!node.cached("start.example.test"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_resolver_asks_no_public_server_for_a_name_a_rule_governs() {
    // The root's server answers the alias, and would answer the target with its own data.
    let root = Scripted::start(
        &[
            ("alias.zone.test", Data::Cname("host.corp.test")),
            ("host.corp.test", Data::A(PUBLIC)),
            ("www.zone.test", Data::A(PUBLIC)),
        ],
        true,
    );
    let inside = Scripted::start(
        &[
            ("host.corp.test", Data::A(INSIDE)),
            ("out.corp.test", Data::Cname("www.zone.test")),
            ("www.zone.test", Data::A(INSIDE)),
        ],
        false,
    );
    let node = Node::recursing(
        &root,
        &[rule(ForwardRuleId::generate(), "corp.test", &inside)],
    );
    assert_eq!(
        records(&node.ask("alias.zone.test").await),
        vec![
            cname("alias.zone.test", "host.corp.test"),
            a("host.corp.test", INSIDE),
        ]
    );
    assert_eq!(
        root.asked("host.corp.test"),
        0,
        "the target stays on the rule"
    );
    // And out of the rule: the resolver answers the outside name.
    assert_eq!(
        records(&node.ask("out.corp.test").await),
        vec![
            cname("out.corp.test", "www.zone.test"),
            a("www.zone.test", PUBLIC),
        ]
    );
}
