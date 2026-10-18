//! Tests of the forwarder against upstreams that run in the test: the relay, the transports
//! of a plain upstream, the cache on the query path, serve-stale, the recursion policy and
//! stub zones.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, UdpSocket},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use tenko_core::{
    Revision,
    dns::{
        Acl, AclEntry, AclId, PrimaryServer, QueryTransport, SecondarySource, SoaDefaults, View,
        ZoneKind, ZoneScope,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{
    catalog::{Catalog, CatalogHandle},
    feed::DnsData,
};

/// What a fake upstream does with a query.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Answers NOERROR with one A record of this TTL.
    Answer(u32),
    /// Answers with a wrong id first, then correctly.
    WrongIdFirst,
    /// Answers with TC set and no records.
    Truncate,
    /// Answers with `n` A records (a large answer).
    Large(u16),
    /// Never answers.
    Silent,
    /// A stub zone's source: NS queries get `ns1.<apex>` with glue 127.0.0.1, every other
    /// query one A record 192.0.2.77.
    Stub,
}

fn record(out: &mut Vec<u8>, rtype: u16, ttl: u32, data: &[u8]) {
    out.extend_from_slice(&[0xc0, 0x0c]);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).expect("len").to_be_bytes());
    out.extend_from_slice(data);
}

/// An answer to `query`: its id and question, QR, and `records` A records of `ttl`.
fn answer_to(query: &[u8], records: u16, ttl: u32, tc: bool) -> Vec<u8> {
    let end = wire::questions_end(query, 1).expect("question");
    let mut out = Vec::new();
    out.extend_from_slice(&query[..2]);
    out.push(0x80 | (query[2] & 0x01) | if tc { 0x02 } else { 0 });
    out.push(0x80);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&records.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[HEADER_LEN..end]);
    for n in 0..records {
        #[allow(clippy::cast_possible_truncation)]
        let last = (n % 250) as u8 + 1;
        record(&mut out, TYPE_A, ttl, &[192, 0, 2, last]);
    }
    out
}

/// The stub source's answer: NS of the apex with glue, or an A record.
fn stub_answer(query: &[u8]) -> Vec<u8> {
    let end = wire::questions_end(query, 1).expect("question");
    let qtype = u16::from_be_bytes([query[end - 4], query[end - 3]]);
    if qtype != TYPE_NS {
        let mut out = answer_to(query, 0, 0, false);
        out[7] = 1;
        record(&mut out, TYPE_A, 60, &[192, 0, 2, 77]);
        return out;
    }
    let mut out = answer_to(query, 0, 0, false);
    out[7] = 1;
    out[11] = 1;
    // NS ns1 + pointer to the apex in the question.
    record(&mut out, TYPE_NS, 3600, &[3, b'n', b's', b'1', 0xc0, 0x0c]);
    let ns_at = out.len() - 6;
    out.extend_from_slice(&[
        0xc0 | u8::try_from(ns_at >> 8).expect("hi"),
        u8::try_from(ns_at & 0xff).expect("lo"),
    ]);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&3600u32.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&[127, 0, 0, 1]);
    out
}

struct Upstream {
    address: SocketAddr,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    silent: Arc<AtomicBool>,
}

impl Upstream {
    fn count(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn first(&self) -> Vec<u8> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)[0].clone()
    }

    fn spec(&self) -> UpstreamSpec {
        plain(self.address, false)
    }
}

fn plain(address: SocketAddr, tcp_only: bool) -> UpstreamSpec {
    UpstreamSpec {
        address,
        transport: ForwardTransport::Plain,
        tcp_only,
        tls_name: None,
        path: None,
    }
}

/// A UDP upstream on loopback.
fn udp_upstream(behaviour: Behaviour) -> Upstream {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let address = socket.local_addr().expect("address");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let silent = Arc::new(AtomicBool::new(false));
    let (log, quiet) = (Arc::clone(&seen), Arc::clone(&silent));
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((len, from)) = socket.recv_from(&mut buf) {
            let query = buf[..len].to_vec();
            log.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(query.clone());
            if quiet.load(Ordering::Relaxed) {
                continue;
            }
            let reply = match behaviour {
                Behaviour::Answer(ttl) => answer_to(&query, 1, ttl, false),
                Behaviour::WrongIdFirst => {
                    let mut wrong = answer_to(&query, 1, 60, false);
                    wrong[0] ^= 0xff;
                    let _ = socket.send_to(&wrong, from);
                    answer_to(&query, 1, 60, false)
                }
                Behaviour::Truncate => answer_to(&query, 0, 60, true),
                Behaviour::Large(records) => answer_to(&query, records, 60, false),
                Behaviour::Silent => continue,
                Behaviour::Stub => stub_answer(&query),
            };
            let _ = socket.send_to(&reply, from);
        }
    });
    Upstream {
        address,
        seen,
        silent,
    }
}

/// A TCP upstream on `address`'s port, answering every query with `records` records.
fn tcp_upstream(address: SocketAddr, records: u16) -> Arc<AtomicUsize> {
    let listener = TcpListener::bind(address).expect("bind tcp");
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut prefix = [0u8; 2];
            if stream.read_exact(&mut prefix).is_err() {
                continue;
            }
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
            if stream.read_exact(&mut query).is_err() {
                continue;
            }
            seen.fetch_add(1, Ordering::Relaxed);
            let reply = answer_to(&query, records, 60, false);
            let len = u16::try_from(reply.len()).expect("len").to_be_bytes();
            let _ = stream.write_all(&len);
            let _ = stream.write_all(&reply);
        }
    });
    count
}

fn settings(upstreams: Vec<UpstreamSpec>) -> ForwardSettings {
    ForwardSettings {
        upstreams,
        timeout: Duration::from_millis(300),
        retries: 1,
        metrics: false,
        stale_budget: Duration::from_millis(200),
        ..ForwardSettings::default()
    }
}

fn query_for(name: &str, id: u16, edns: Option<u16>) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(&mut out, id, name, 1, edns);
    out[2] |= 0x01;
    out
}

fn query(id: u16, edns: Option<u16>) -> Vec<u8> {
    query_for("www.Example.org", id, edns)
}

/// A client of the node: a socket the forwarder answers to.
struct Peer {
    socket: Arc<std::net::UdpSocket>,
    address: SocketAddr,
}

impl Peer {
    fn new() -> Self {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind client");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let address = socket.local_addr().expect("address");
        Self {
            socket: Arc::new(socket),
            address,
        }
    }

    fn reply_path() -> ReplyPath {
        ReplyPath::Udp(Arc::new(
            std::net::UdpSocket::bind("127.0.0.1:0").expect("bind node"),
        ))
    }

    fn submit(&self, forwarder: &Forwarder, message: Vec<u8>) {
        forwarder.submit(ForwardQuery {
            message,
            client: self.address,
            transport: QueryTransport::Udp,
            view: None,
            rule: None,
            cookie: None,
            reply: Self::reply_path(),
        });
    }

    async fn ask(self: &Arc<Self>, forwarder: &Forwarder, message: Vec<u8>) -> Vec<u8> {
        self.submit(forwarder, message);
        let peer = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 65_535];
            let (len, _) = peer.socket.recv_from(&mut buf).expect("an answer");
            buf.truncate(len);
            buf
        })
        .await
        .expect("joins")
    }
}

fn start_with(
    settings: ForwardSettings,
    catalog: Catalog,
    recursion: RecursionDefault,
) -> (Arc<Forwarder>, CancellationToken) {
    let stop = CancellationToken::new();
    let (forwarder, _task) = Forwarder::start(
        settings,
        CatalogHandle::new(catalog),
        None,
        Arc::new(RecursionPolicy::new(recursion)),
        stop.clone(),
    );
    (forwarder, stop)
}

fn start(upstreams: Vec<UpstreamSpec>) -> (Arc<Forwarder>, CancellationToken) {
    start_with(
        settings(upstreams),
        Catalog::default(),
        RecursionDefault::KnownPrefixes,
    )
}

fn first_ttl(message: &[u8]) -> u32 {
    let end = wire::questions_end(message, 1).expect("question");
    wire::read_record(message, end).expect("record").ttl
}

/// What the forwarder decides on the query path for `message` from `client`.
fn intake(
    forwarder: &Forwarder,
    message: &[u8],
    client: &str,
    view: Option<ViewId>,
    out: &mut Vec<u8>,
) -> Intake {
    let mut request = Request::default();
    DomainCodec::new()
        .parse(message, &mut request)
        .expect("parses");
    forwarder.intake(
        &IntakeQuery {
            message,
            request: &request,
            client: client.parse().expect("client"),
            transport: QueryTransport::Udp,
            view,
            rule: None,
            max_len: 512,
            udp_size: SERVER_UDP_PAYLOAD,
            cookie: None,
            now: Instant::now(),
        },
        out,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_is_relayed_with_the_client_id_case_and_ra() {
    let upstream = udp_upstream(Behaviour::Answer(60));
    let (forwarder, stop) = start(vec![upstream.spec()]);
    let peer = Arc::new(Peer::new());
    let answer = peer.ask(&forwarder, query(0x1234, Some(4096))).await;
    let header = wire::parse_header(&answer).expect("header");
    assert_eq!(header.id, 0x1234);
    assert!(header.qr && header.ra && header.rd && !header.ad);
    assert_eq!((header.rcode, header.ancount), (0, 1));
    assert!(
        answer.windows(7).any(|window| window == b"Example"),
        "the client's case"
    );
    let sent = upstream.first();
    let upstream_header = wire::parse_header(&sent).expect("upstream query");
    assert!(upstream_header.rd);
    // The question as asked, in some case (0x20), and an OPT record with 1232 octets.
    let end = wire::questions_end(&sent, 1).expect("question");
    assert!(sent[HEADER_LEN..end].eq_ignore_ascii_case(&query(0, None)[HEADER_LEN..end]));
    let opt = wire::read_record(&sent, end).expect("opt");
    assert_eq!((opt.rtype, opt.class), (wire::TYPE_OPT, 1232));
    assert_eq!(forwarder.stats().answered, 1);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_with_another_id_is_ignored() {
    let upstream = udp_upstream(Behaviour::WrongIdFirst);
    let (forwarder, stop) = start(vec![upstream.spec()]);
    let peer = Arc::new(Peer::new());
    let answer = peer.ask(&forwarder, query(7, None)).await;
    assert_eq!(wire::parse_header(&answer).expect("header").ancount, 1);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_truncated_answer_is_asked_again_over_tcp() {
    let upstream = udp_upstream(Behaviour::Truncate);
    let tcp = tcp_upstream(upstream.address, 3);
    let (forwarder, stop) = start(vec![upstream.spec()]);
    let peer = Arc::new(Peer::new());
    let answer = peer.ask(&forwarder, query(9, Some(1232))).await;
    assert_eq!(wire::parse_header(&answer).expect("header").ancount, 3);
    assert_eq!(tcp.load(Ordering::Relaxed), 1);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tcp_only_upstream_is_asked_over_tcp() {
    let address = TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("address");
    let tcp = tcp_upstream(address, 2);
    let (forwarder, stop) = start(vec![plain(address, true)]);
    let peer = Arc::new(Peer::new());
    let answer = peer.ask(&forwarder, query(11, None)).await;
    assert_eq!(wire::parse_header(&answer).expect("header").ancount, 2);
    assert_eq!(tcp.load(Ordering::Relaxed), 1);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_too_long_for_the_client_is_cut_with_tc() {
    let upstream = udp_upstream(Behaviour::Large(60));
    let (forwarder, stop) = start(vec![upstream.spec()]);
    let peer = Arc::new(Peer::new());
    let answer = peer.ask(&forwarder, query(13, None)).await;
    let header = wire::parse_header(&answer).expect("header");
    assert!(header.tc);
    assert_eq!(header.ancount, 0);
    assert!(answer.len() <= 512);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_upstream_is_skipped_for_the_next_one() {
    let silent = udp_upstream(Behaviour::Silent);
    let good = udp_upstream(Behaviour::Answer(60));
    let (forwarder, stop) = start(vec![silent.spec(), good.spec()]);
    let peer = Arc::new(Peer::new());
    for id in 0..4 {
        let message = query_for(&format!("host{id}.example.org"), id, None);
        let answer = peer.ask(&forwarder, message).await;
        assert_eq!(wire::parse_header(&answer).expect("header").rcode, 0);
    }
    assert!(good.count() >= 4);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn servfail_when_every_attempt_fails() {
    let silent = udp_upstream(Behaviour::Silent);
    let (forwarder, stop) = start(vec![silent.spec()]);
    let peer = Arc::new(Peer::new());
    let answer = peer.ask(&forwarder, query(15, None)).await;
    let header = wire::parse_header(&answer).expect("header");
    assert_eq!((header.id, header.rcode), (15, 2));
    assert_eq!(forwarder.stats().failed, 1);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tcp_client_gets_the_answer_through_its_connection() {
    let upstream = udp_upstream(Behaviour::Answer(60));
    let (forwarder, stop) = start(vec![upstream.spec()]);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
    forwarder.submit(ForwardQuery {
        message: query(17, None),
        client: "127.0.0.1:5000".parse().expect("address"),
        transport: QueryTransport::Tcp,
        view: None,
        rule: None,
        cookie: None,
        reply: ReplyPath::Tcp(sender),
    });
    let answer = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("in time")
        .expect("an answer");
    assert_eq!(wire::parse_header(&answer).expect("header").id, 17);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_second_query_is_answered_from_the_cache_on_the_query_path() {
    let upstream = udp_upstream(Behaviour::Answer(300));
    let (forwarder, stop) = start(vec![upstream.spec()]);
    let peer = Arc::new(Peer::new());
    let message = query(19, None);
    let mut out = Vec::with_capacity(65_535);
    assert_eq!(
        intake(&forwarder, &message, "127.0.0.1:4000", None, &mut out),
        Intake::Forward
    );
    peer.ask(&forwarder, message.clone()).await;
    assert_eq!(
        intake(&forwarder, &message, "127.0.0.1:4000", None, &mut out),
        Intake::Answered { rcode: 0 }
    );
    let header = wire::parse_header(&out).expect("header");
    assert_eq!((header.id, header.ancount), (19, 1));
    assert!(first_ttl(&out) <= 300);
    assert_eq!(upstream.count(), 1);
    let stats = forwarder.stats();
    assert_eq!((stats.hits, stats.misses), (1, 1));
    assert!(
        stats
            .hit_ratio()
            .is_some_and(|ratio| (ratio - 0.5).abs() < 1e-9)
    );
    assert_eq!(
        forwarder.flush(None).map(|flushed| flushed.entries),
        Some(1)
    );
    assert_eq!(
        intake(&forwarder, &message, "127.0.0.1:4000", None, &mut out),
        Intake::Forward
    );
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_answer_comes_while_the_upstream_is_silent_then_a_fresh_one() {
    let upstream = udp_upstream(Behaviour::Answer(1));
    let mut settings = settings(vec![upstream.spec()]);
    settings.retries = 0;
    let (forwarder, stop) = start_with(
        settings,
        Catalog::default(),
        RecursionDefault::KnownPrefixes,
    );
    let peer = Arc::new(Peer::new());
    let first = peer.ask(&forwarder, query(21, None)).await;
    assert_eq!(first_ttl(&first), 1);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    upstream.silent.store(true, Ordering::Relaxed);
    let started = Instant::now();
    let stale = peer.ask(&forwarder, query(22, None)).await;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "within the stale budget"
    );
    let header = wire::parse_header(&stale).expect("header");
    assert_eq!((header.id, header.rcode, header.ancount), (22, 0, 1));
    assert_eq!(first_ttl(&stale), crate::cache::STALE_TTL);
    assert_eq!(forwarder.stats().stale, 1);
    upstream.silent.store(false, Ordering::Relaxed);
    let fresh = peer.ask(&forwarder, query(23, None)).await;
    assert!(first_ttl(&fresh) <= 1, "refreshed from the upstream");
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_any_upstream_the_query_is_refused_as_not_authoritative() {
    let (forwarder, stop) = start(Vec::new());
    let mut out = Vec::new();
    assert_eq!(
        intake(
            &forwarder,
            &query(25, None),
            "127.0.0.1:4000",
            None,
            &mut out
        ),
        Intake::Refuse {
            ede: EDE_NOT_AUTHORITATIVE
        }
    );
    assert_eq!(forwarder.stats().refused, 1);
    stop.cancel();
}

fn stamp() -> Stamp {
    Stamp::new(
        "2026-10-17T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Dns),
    )
}

fn view(recursion: Option<AclId>) -> View {
    View {
        id: ViewId::generate(),
        name: "clients".to_owned(),
        rules: Vec::new(),
        scope_map: Vec::new(),
        order: 1,
        recursion,
        description: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines, reason = "one policy, every case in turn")]
async fn the_recursion_policy_decides_who_may_recurse() {
    let upstream = udp_upstream(Behaviour::Answer(60));
    let acl = Acl {
        id: AclId::generate(),
        name: "lab".to_owned(),
        entries: vec![AclEntry::Prefix {
            prefix: "198.51.100.0/24".parse().expect("prefix"),
            deny: false,
        }],
        description: None,
    };
    let with_list = view(Some(acl.id));
    let dangling = view(Some(AclId::generate()));
    let plain_view = view(None);
    let mut data = DnsData::at(Revision(1));
    data.acls.insert(acl.id, acl);
    for row in [&with_list, &dangling, &plain_view] {
        data.views.insert(row.id, row.clone());
    }
    let (forwarder, stop) = start_with(
        settings(vec![upstream.spec()]),
        Catalog::build(&data),
        RecursionDefault::KnownPrefixes,
    );
    let message = query(27, None);
    let mut out = Vec::new();
    let prohibited = Intake::Refuse {
        ede: EDE_PROHIBITED,
    };
    // The profile's default: loopback and the prefixes IPAM knows.
    assert_eq!(
        intake(&forwarder, &message, "127.0.0.1:4000", None, &mut out),
        Intake::Forward
    );
    assert_eq!(
        intake(&forwarder, &message, "192.0.2.5:4000", None, &mut out),
        prohibited
    );
    forwarder
        .recursion()
        .set_prefixes(vec!["192.0.2.0/24".parse().expect("prefix")]);
    assert_eq!(
        intake(&forwarder, &message, "192.0.2.5:4000", None, &mut out),
        Intake::Forward
    );
    assert_eq!(
        intake(
            &forwarder,
            &message,
            "[::ffff:192.0.2.5]:4000",
            None,
            &mut out
        ),
        Intake::Forward,
        "an IPv4-mapped address is its IPv4 address"
    );
    // A view's list decides for its clients, whatever the default says.
    assert_eq!(
        intake(
            &forwarder,
            &message,
            "198.51.100.7:4000",
            Some(with_list.id),
            &mut out
        ),
        Intake::Forward
    );
    assert_eq!(
        intake(
            &forwarder,
            &message,
            "192.0.2.5:4000",
            Some(with_list.id),
            &mut out
        ),
        prohibited
    );
    // A view without a list follows the default; a list that is gone allows nobody.
    assert_eq!(
        intake(
            &forwarder,
            &message,
            "192.0.2.5:4000",
            Some(plain_view.id),
            &mut out
        ),
        Intake::Forward
    );
    assert_eq!(
        intake(
            &forwarder,
            &message,
            "127.0.0.1:4000",
            Some(dangling.id),
            &mut out
        ),
        prohibited
    );
    let problems = forwarder.recursion_problems();
    assert_eq!(problems.len(), 1);
    assert!(problems[0].contains("does not exist"));
    // The other defaults.
    forwarder.recursion().set_default(RecursionDefault::Nobody);
    assert_eq!(
        intake(&forwarder, &message, "127.0.0.1:4000", None, &mut out),
        prohibited
    );
    forwarder.recursion().set_default(RecursionDefault::Anyone);
    assert_eq!(
        intake(&forwarder, &message, "203.0.113.9:4000", None, &mut out),
        Intake::Forward
    );
    stop.cancel();
}

fn stub_zone(apex: &str, source: SocketAddr) -> Zone {
    Zone {
        id: ZoneId::generate(),
        name: DnsName::new(apex).expect("name"),
        kind: ZoneKind::Stub,
        tenant: None,
        scopes: vec![ZoneScope::default_scope()],
        serial: tenko_core::dns::SerialPolicy::default(),
        soa: SoaDefaults::new(
            DnsName::new("ns1.example.test").expect("name"),
            DnsName::new("hostmaster.example.test").expect("name"),
        ),
        transfer: tenko_core::dns::TransferPolicy::default(),
        update: tenko_core::dns::UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: Some(SecondarySource {
            primaries: vec![PrimaryServer {
                address: source.ip(),
                port: source.port(),
                key: None,
                xot: false,
                tls_name: None,
            }],
        }),
        reverse_of: None,
        description: None,
        created: stamp(),
        updated: stamp(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stub_zone_learns_its_name_servers_and_a_dead_one_is_reported() {
    let source = udp_upstream(Behaviour::Stub);
    let dead = udp_upstream(Behaviour::Silent);
    let good = stub_zone("stub.example.test", source.address);
    let broken = stub_zone("dead.example.test", dead.address);
    let mut data = DnsData::at(Revision(1));
    data.zones.insert(good.id, good);
    data.zones.insert(broken.id, broken);
    let (forwarder, stop) = start_with(
        settings(Vec::new()),
        Catalog::build(&data),
        RecursionDefault::KnownPrefixes,
    );
    let message = query_for("www.stub.example.test", 29, None);
    let mut out = Vec::new();
    assert_eq!(
        intake(&forwarder, &message, "127.0.0.1:4000", None, &mut out),
        Intake::Forward,
        "the stub zone covers the name"
    );
    let peer = Arc::new(Peer::new());
    let answer = peer.ask(&forwarder, message).await;
    let header = wire::parse_header(&answer).expect("header");
    assert_eq!((header.rcode, header.ancount), (0, 1));
    assert!(answer.ends_with(&[192, 0, 2, 77]));
    let failed = peer
        .ask(&forwarder, query_for("www.dead.example.test", 30, None))
        .await;
    assert_eq!(wire::parse_header(&failed).expect("header").rcode, 2);
    let reports = forwarder.stubs();
    assert_eq!(reports.len(), 2);
    let learnt = reports
        .iter()
        .find(|report| report.zone.as_str() == "stub.example.test")
        .expect("report");
    assert_eq!(learnt.servers, vec![source.address.to_string()]);
    assert_eq!(learnt.error, None);
    let failing = reports
        .iter()
        .find(|report| report.zone.as_str() == "dead.example.test")
        .expect("report");
    assert_eq!(failing.servers, Vec::<String>::new());
    assert!(failing.error.is_some());
    // A name outside every stub zone, rule and default is refused.
    assert_eq!(
        intake(
            &forwarder,
            &query(31, None),
            "127.0.0.1:4000",
            None,
            &mut out
        ),
        Intake::Refuse {
            ede: EDE_NOT_AUTHORITATIVE
        }
    );
    stop.cancel();
}

#[test]
fn names_are_matched_against_suffixes_by_label() {
    let name = |text: &str| crate::name::NameBuf::from_dns_name(&DnsName::new(text).expect("name"));
    let suffix = |text: &str| DnsName::new(text).expect("name");
    assert!(within(
        name("www.example.test").as_wire(),
        &suffix("example.test")
    ));
    assert!(within(
        name("example.test").as_wire(),
        &suffix("example.test")
    ));
    assert!(within(name("www.example.test").as_wire(), &DnsName::root()));
    assert!(!within(
        name("www.badexample.test").as_wire(),
        &suffix("example.test")
    ));
    assert!(!within(name("test").as_wire(), &suffix("example.test")));
    assert!(!within(
        name("www.example.net").as_wire(),
        &suffix("example.test")
    ));
}
