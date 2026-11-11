//! The RPZ triggers NSDNAME and NSIP on the resolver's answers, end to end through the
//! forwarder and the policy sink, against a root server of the test's own on a loopback
//! address: an answer kept before the first trigger came, an answer resolved after a new
//! trigger reached the catalog but before the housekeeping noticed it, a trigger added while
//! the answers carry their delegation, and a denial synthesized from the denial cache.

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tenko_core::{
    Revision,
    dns::{
        DnsName, QueryTransport, RecordData, RrSet, ScopeName, SoaDefaults, Zone, ZoneId, ZoneKind,
        ZoneScope,
    },
};
use tokio_util::sync::CancellationToken;

use super::{Peer, stamp};
use crate::{
    Request,
    catalog::{Catalog, CatalogHandle},
    codec::{Codec, DomainCodec},
    feed::DnsData,
    forward::{ForwardSettings, Forwarder, RecursionDefault, RecursionPolicy},
    name::NameBuf,
    policy::{Policy, answer::PolicySink},
    recurse::EngineSettings,
    recursion::{Minimization, Outbound, RecursionSettings},
    respond::{ForwardQuery, ForwardSink, Intake, IntakeQuery},
    wire,
};

/// The name server of the test's root: what the NSDNAME trigger names.
const ROOT_SERVER: &str = "a.root.test";

/// A root server on a loopback address: `./NS` with its glue, NXDOMAIN with the root's
/// SOA for every other name; it counts what it is asked.
struct Root {
    address: SocketAddr,
    asked: Arc<AtomicUsize>,
}

fn root() -> Root {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind the root");
    let address = socket.local_addr().expect("address");
    let asked = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&asked);
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 4096];
        while let Ok((len, from)) = socket.recv_from(&mut buf) {
            counter.fetch_add(1, Ordering::Relaxed);
            if let Some(answer) = root_answer(&buf[..len]) {
                let _ = socket.send_to(&answer, from);
            }
        }
    });
    Root { address, asked }
}

fn push_record(out: &mut Vec<u8>, owner: &[u8], rtype: u16, ttl: u32, data: &[u8]) {
    out.extend_from_slice(owner);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).expect("len").to_be_bytes());
    out.extend_from_slice(data);
}

fn wire_name(text: &str) -> Vec<u8> {
    DnsName::new(text).expect("name").to_wire()
}

/// The root's answer to `query`, its question echoed as asked (0x20).
fn root_answer(query: &[u8]) -> Option<Vec<u8>> {
    let end = wire::questions_end(query, 1)?;
    let mut qname = NameBuf::root();
    wire::read_name(query, wire::HEADER_LEN, &mut qname)?;
    let qtype = u16::from_be_bytes([query[end - 4], query[end - 3]]);
    let mut out = query[..2].to_vec();
    let priming = qname.as_wire() == [0] && qtype == 2;
    out.push(0x84);
    out.push(if priming { 0 } else { 3 });
    let counts: [u16; 4] = if priming { [1, 1, 0, 1] } else { [1, 0, 1, 0] };
    for count in counts {
        out.extend_from_slice(&count.to_be_bytes());
    }
    out.extend_from_slice(&query[wire::HEADER_LEN..end]);
    if priming {
        push_record(&mut out, &[0], 2, 3600, &wire_name(ROOT_SERVER));
        push_record(&mut out, &wire_name(ROOT_SERVER), 1, 3600, &[127, 0, 0, 1]);
    } else {
        let mut soa = wire_name(ROOT_SERVER);
        soa.extend(wire_name("hostmaster.root.test"));
        for value in [1u32, 3600, 900, 1_209_600, 300] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        push_record(&mut out, &[0], 6, 300, &soa);
    }
    Some(out)
}

/// The RPZ zone `rpz.test` with NSDNAME triggers on `servers` (action NXDOMAIN).
fn catalog(servers: &[&str]) -> Catalog {
    let mut data = DnsData::at(Revision(1));
    if !servers.is_empty() {
        let zone = Zone {
            id: ZoneId::generate(),
            name: DnsName::new("rpz.test").expect("name"),
            kind: ZoneKind::Rpz,
            tenant: None,
            scopes: vec![ZoneScope::default_scope()],
            serial: tenko_core::dns::SerialPolicy::default(),
            soa: SoaDefaults::new(
                DnsName::new("ns1.rpz.test").expect("name"),
                DnsName::new("hostmaster.rpz.test").expect("name"),
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
        let set = |owner: &str, data: RecordData| RrSet {
            zone: zone.id,
            scope: ScopeName::DEFAULT,
            name: DnsName::new(owner).expect("owner"),
            rtype: data.rtype(),
            ttl: 60,
            rdata: vec![tenko_core::dns::Rdata::from_data(&data)],
            origin: tenko_core::dns::Origin::Manual,
            key: None,
            principal: None,
            updated: stamp(),
        };
        let mut sets = vec![set(
            "rpz.test",
            RecordData::Soa {
                mname: DnsName::new("ns1.rpz.test").expect("name"),
                rname: DnsName::new("hostmaster.rpz.test").expect("name"),
                serial: 1,
                refresh: 3600,
                retry: 900,
                expire: 1_209_600,
                minimum: 60,
            },
        )];
        for server in servers {
            sets.push(set(
                &format!("{server}.rpz-nsdname.rpz.test"),
                RecordData::Cname {
                    target: DnsName::root(),
                },
            ));
        }
        for set in sets {
            data.rrsets.insert(set.key(), set);
        }
        data.zones.insert(zone.id, zone);
    }
    Catalog::build(&data)
}

/// The node: the forwarder recursing from the test's root, behind the policy sink.
struct Node {
    forwarder: Arc<Forwarder>,
    sink: PolicySink,
    catalog: CatalogHandle,
    peer: Arc<Peer>,
    stop: CancellationToken,
    _hints: tempfile::TempDir,
}

fn node(root: &Root, servers: &[&str]) -> Node {
    let hints = tempfile::tempdir().expect("a directory");
    let path = hints.path().join("root.hints");
    std::fs::write(
        &path,
        format!(". 3600000 NS {ROOT_SERVER}.\n{ROOT_SERVER}. 3600000 A 127.0.0.1\n"),
    )
    .expect("the hints");
    let settings = ForwardSettings {
        timeout: Duration::from_millis(1_000),
        metrics: false,
        cache: Some(crate::cache::CacheSettings::default()),
        recursion: Some(EngineSettings {
            recursion: RecursionSettings {
                outbound: Outbound::V4,
                validate: false,
                minimization: Minimization::Off,
                timeout: Duration::from_millis(1_000),
                ..RecursionSettings::default()
            },
            hints: Some(path),
            local_zones_except: vec![DnsName::new("test").expect("name")],
            metrics: false,
            authority_port: root.address.port(),
        }),
        validation: None,
        ..ForwardSettings::default()
    };
    let catalog = CatalogHandle::new(catalog(servers));
    let stop = CancellationToken::new();
    let (forwarder, _task) = Forwarder::start(
        settings,
        catalog.clone(),
        None,
        Arc::new(RecursionPolicy::new(RecursionDefault::KnownPrefixes)),
        stop.clone(),
    );
    let sink = PolicySink::new(
        Arc::clone(&forwarder) as Arc<dyn ForwardSink>,
        catalog.clone(),
        Arc::new(Policy),
        tokio::runtime::Handle::current(),
    );
    Node {
        forwarder,
        sink,
        catalog,
        peer: Arc::new(Peer::new()),
        stop,
        _hints: hints,
    }
}

const CLIENT: &str = "127.0.0.1:4000";

fn query(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(&mut out, 0x5150, name, 1, Some(1232));
    out[2] |= 0x01;
    out
}

impl Node {
    /// What the query path (the sink over the forwarder) answers for `name` without the
    /// runtime, and the answer it wrote.
    fn intake(&self, name: &str) -> (Intake, Vec<u8>) {
        let message = query(name);
        let mut request = Request::default();
        DomainCodec::new()
            .parse(&message, &mut request)
            .expect("parses");
        let mut out = Vec::with_capacity(65_535);
        let intake = self.sink.intake(
            &IntakeQuery {
                message: &message,
                request: &request,
                client: CLIENT.parse().expect("client"),
                transport: QueryTransport::Udp,
                view: None,
                rule: None,
                max_len: 1232,
                udp_size: wire::SERVER_UDP_PAYLOAD,
                cookie: None,
                now: Instant::now(),
            },
            &mut out,
        );
        (intake, out)
    }

    /// The answer for `name` through the sink and the runtime (the resolver when the
    /// caches have nothing).
    async fn ask(&self, name: &str) -> Vec<u8> {
        self.sink.submit(ForwardQuery {
            message: query(name),
            client: self.peer.address,
            transport: QueryTransport::Udp,
            view: None,
            rule: None,
            cookie: None,
            reply: Peer::reply_path(),
        });
        let peer = Arc::clone(&self.peer);
        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 65_535];
            let (len, _) = peer.socket.recv_from(&mut buf).expect("an answer");
            buf.truncate(len);
            buf
        })
        .await
        .expect("joins")
    }

    /// What the query path answers for `name`: from a cache when it can, else from the
    /// resolver.
    async fn answer(&self, name: &str) -> (Intake, Vec<u8>) {
        let (intake, out) = self.intake(name);
        match intake {
            Intake::Answered { .. } | Intake::Synthesized { .. } => (intake, out),
            other => (other, self.ask(name).await),
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// Whether `answer` is the policy's NXDOMAIN: the extended error 15 (Blocked).
fn blocked(answer: &[u8]) -> bool {
    let header = wire::parse_header(answer).expect("header");
    header.rcode == 3
        && answer
            .windows(6)
            .any(|window| window == [0, 15, 0, 2, 0, 15])
}

fn natural_nxdomain(answer: &[u8]) -> bool {
    wire::parse_header(answer).expect("header").rcode == 3 && !blocked(answer)
}

/// Two housekeeping ticks.
async fn ticks() {
    tokio::time::sleep(Duration::from_millis(450)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_kept_before_the_first_trigger_is_not_served_past_it() {
    let root = root();
    let node = node(&root, &[]);
    let answer = node.ask("gone.test").await;
    assert!(natural_nxdomain(&answer));
    let (intake, _) = node.intake("gone.test");
    assert!(
        matches!(intake, Intake::Answered { .. }),
        "kept in the answer cache: {intake:?}"
    );
    node.catalog.store(catalog(&[ROOT_SERVER]));
    ticks().await;
    let (intake, answer) = node.answer("gone.test").await;
    assert!(
        blocked(&answer),
        "the NSDNAME trigger blocks the name; the query path answered {intake:?}"
    );
    assert!(
        node.forwarder
            .shared
            .engine
            .as_ref()
            .expect("engine")
            .carries()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trigger_applies_to_the_next_resolution_before_the_housekeeping_tick() {
    let root = root();
    let node = node(&root, &[]);
    ticks().await;
    let engine = node.forwarder.shared.engine.clone().expect("engine");
    assert!(!engine.carries());
    // The lab's row: the trigger reaches the catalog, the next query is asked at once.
    node.catalog.store(catalog(&[ROOT_SERVER]));
    let answer = node.ask("fresh.test").await;
    assert!(blocked(&answer), "resolved with its delegation");
    // And from the answer cache as well.
    let (intake, answer) = node.answer("fresh.test").await;
    assert!(matches!(intake, Intake::Answered { .. }), "{intake:?}");
    assert!(blocked(&answer));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trigger_added_while_answers_carry_their_delegation_blocks_a_cached_answer() {
    let root = root();
    let node = node(&root, &["ns.elsewhere.test"]);
    ticks().await;
    let answer = node.ask("kept.test").await;
    assert!(
        natural_nxdomain(&answer),
        "the trigger names another server"
    );
    let before = root.asked.load(Ordering::Relaxed);
    node.catalog
        .store(catalog(&["ns.elsewhere.test", ROOT_SERVER]));
    let (intake, answer) = node.intake("kept.test");
    assert!(
        matches!(intake, Intake::Answered { .. }),
        "answered from the cache: {intake:?}"
    );
    assert!(blocked(&answer), "the cached answer carries its delegation");
    ticks().await;
    let (intake, answer) = node.intake("kept.test");
    assert!(
        matches!(intake, Intake::Answered { .. }),
        "no flush while the carry stays on: {intake:?}"
    );
    assert!(blocked(&answer));
    assert_eq!(
        root.asked.load(Ordering::Relaxed),
        before,
        "no query was sent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_synthesized_denial_is_judged_with_the_delegation_of_its_zone() {
    let root = root();
    let node = node(&root, &[]);
    let answer = node.ask("gone.test").await;
    assert!(natural_nxdomain(&answer));
    // RFC 8020: a name below the NXDOMAIN is synthesized.
    let (intake, answer) = node.intake("below.gone.test");
    assert!(
        matches!(intake, Intake::Synthesized { .. }),
        "synthesized: {intake:?}"
    );
    assert!(natural_nxdomain(&answer));
    node.catalog.store(catalog(&[ROOT_SERVER]));
    ticks().await;
    // The denial was kept without the delegation: not synthesized under the carry, the
    // resolver answers with it.
    let (intake, answer) = node.answer("below.gone.test").await;
    assert!(
        blocked(&answer),
        "the NSDNAME trigger blocks a synthesized name; the query path answered {intake:?}"
    );
    // That answer gave the zone its delegation: the next name below a denied one is
    // synthesized again, with the delegation, and blocked.
    let asked = root.asked.load(Ordering::Relaxed);
    let (intake, answer) = node.intake("x.below.gone.test");
    assert!(
        matches!(intake, Intake::Answered { .. }),
        "synthesized and rewritten by the policy: {intake:?}"
    );
    assert!(blocked(&answer));
    assert_eq!(
        root.asked.load(Ordering::Relaxed),
        asked,
        "no query was sent"
    );
}
