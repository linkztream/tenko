//! Tests of the plain forwarder against upstreams that run in the test.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, UdpSocket},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tenko_core::dns::QueryTransport;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::catalog::{Catalog, CatalogHandle};

/// What a fake upstream does with a query.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Answers NOERROR with one A record.
    Answer,
    /// Answers with a wrong id first, then correctly.
    WrongIdFirst,
    /// Answers with TC set and no records.
    Truncate,
    /// Answers with `n` A records (a large answer).
    Large(u16),
    /// Never answers.
    Silent,
}

/// An answer to `query`: its id and question, QR, `ancount` A records for the question.
fn answer_to(query: &[u8], records: u16, tc: bool) -> Vec<u8> {
    let end = wire::questions_end(query, 1).expect("question");
    let mut out = Vec::new();
    out.extend_from_slice(&query[..2]);
    out.push(0x80 | (query[2] & 0x01) | if tc { 0x02 } else { 0 });
    out.push(0x00);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&records.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[HEADER_LEN..end]);
    for n in 0..records {
        out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2]);
        #[allow(clippy::cast_possible_truncation)]
        out.push((n % 250) as u8 + 1);
    }
    out
}

/// A UDP upstream on loopback; returns its address and the queries it saw.
fn udp_upstream(behaviour: Behaviour) -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let address = socket.local_addr().expect("address");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((len, from)) = socket.recv_from(&mut buf) {
            let query = buf[..len].to_vec();
            log.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(query.clone());
            let reply = match behaviour {
                Behaviour::Answer => answer_to(&query, 1, false),
                Behaviour::WrongIdFirst => {
                    let mut wrong = answer_to(&query, 1, false);
                    wrong[0] ^= 0xff;
                    let _ = socket.send_to(&wrong, from);
                    answer_to(&query, 1, false)
                }
                Behaviour::Truncate => answer_to(&query, 0, true),
                Behaviour::Large(records) => answer_to(&query, records, false),
                Behaviour::Silent => continue,
            };
            let _ = socket.send_to(&reply, from);
        }
    });
    (address, seen)
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
            let reply = answer_to(&query, records, false);
            let len = u16::try_from(reply.len()).expect("len").to_be_bytes();
            let _ = stream.write_all(&len);
            let _ = stream.write_all(&reply);
        }
    });
    count
}

fn settings(upstreams: Vec<PlainUpstream>) -> ForwardSettings {
    ForwardSettings {
        upstreams,
        timeout: Duration::from_millis(300),
        retries: 1,
        udp_size: SERVER_UDP_PAYLOAD,
        metrics: false,
    }
}

fn query(id: u16, edns: Option<u16>) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(&mut out, id, "www.Example.org", 1, edns);
    out[2] |= 0x01;
    out
}

struct Client {
    socket: Arc<std::net::UdpSocket>,
    address: SocketAddr,
}

impl Client {
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

    /// The node's side: a socket that sends to the client.
    fn reply_path() -> ReplyPath {
        ReplyPath::Udp(Arc::new(
            std::net::UdpSocket::bind("127.0.0.1:0").expect("bind node"),
        ))
    }

    fn submit(&self, forwarder: &PlainForwarder, message: Vec<u8>) {
        forwarder.submit(ForwardQuery {
            message,
            client: self.address,
            transport: QueryTransport::Udp,
            view: None,
            rule: None,
            reply: Self::reply_path(),
        });
    }

    fn receive(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 65_535];
        let (len, _) = self.socket.recv_from(&mut buf).expect("an answer");
        buf.truncate(len);
        buf
    }
}

fn start(upstreams: Vec<PlainUpstream>) -> (Arc<PlainForwarder>, CancellationToken) {
    let stop = CancellationToken::new();
    let (forwarder, _task) = PlainForwarder::start(
        settings(upstreams),
        CatalogHandle::new(Catalog::default()),
        None,
        stop.clone(),
    );
    (forwarder, stop)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_is_relayed_with_the_client_id_and_ra() {
    let (upstream, seen) = udp_upstream(Behaviour::Answer);
    let (forwarder, stop) = start(vec![PlainUpstream::udp(upstream)]);
    let client = Client::new();
    client.submit(&forwarder, query(0x1234, Some(4096)));
    let answer = tokio::task::spawn_blocking(move || client.receive())
        .await
        .expect("joins");
    let header = wire::parse_header(&answer).expect("header");
    assert_eq!(header.id, 0x1234);
    assert!(header.qr && header.ra && header.rd);
    assert_eq!((header.rcode, header.ancount), (0, 1));
    // The question comes back as the client wrote it.
    assert!(answer.windows(7).any(|window| window == b"Example"));
    let sent = seen.lock().unwrap_or_else(PoisonError::into_inner)[0].clone();
    let upstream_header = wire::parse_header(&sent).expect("upstream query");
    assert!(upstream_header.rd);
    // EDNS without the client's options: an OPT record of 11 octets.
    assert_eq!(upstream_header.arcount, 1);
    assert_eq!(
        sent.len(),
        wire::questions_end(&sent, 1).expect("question") + wire::OPT_LEN
    );
    assert_eq!(forwarder.stats().answered, 1);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_with_another_id_is_ignored() {
    let (upstream, _) = udp_upstream(Behaviour::WrongIdFirst);
    let (forwarder, stop) = start(vec![PlainUpstream::udp(upstream)]);
    let client = Client::new();
    client.submit(&forwarder, query(7, None));
    let answer = tokio::task::spawn_blocking(move || client.receive())
        .await
        .expect("joins");
    let header = wire::parse_header(&answer).expect("header");
    assert_eq!((header.id, header.rcode, header.ancount), (7, 0, 1));
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_truncated_answer_is_asked_again_over_tcp() {
    let (upstream, _) = udp_upstream(Behaviour::Truncate);
    let over_tcp = tcp_upstream(upstream, 3);
    let (forwarder, stop) = start(vec![PlainUpstream::udp(upstream)]);
    let client = Client::new();
    client.submit(&forwarder, query(9, Some(1232)));
    let answer = tokio::task::spawn_blocking(move || client.receive())
        .await
        .expect("joins");
    let header = wire::parse_header(&answer).expect("header");
    assert_eq!((header.id, header.tc, header.ancount), (9, false, 3));
    assert_eq!(over_tcp.load(Ordering::Relaxed), 1);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tcp_only_upstream_is_asked_over_tcp() {
    let probe = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let address = probe.local_addr().expect("address");
    drop(probe);
    let over_tcp = tcp_upstream(address, 1);
    let (forwarder, stop) = start(vec![PlainUpstream::tcp(address)]);
    let client = Client::new();
    client.submit(&forwarder, query(10, None));
    let answer = tokio::task::spawn_blocking(move || client.receive())
        .await
        .expect("joins");
    assert_eq!(wire::parse_header(&answer).expect("header").ancount, 1);
    assert_eq!(over_tcp.load(Ordering::Relaxed), 1);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_too_long_for_the_client_is_cut_with_tc() {
    let (upstream, _) = udp_upstream(Behaviour::Large(60));
    let (forwarder, stop) = start(vec![PlainUpstream::udp(upstream)]);
    let client = Client::new();
    // No EDNS: 512 octets at most; 60 records are about 1,000.
    client.submit(&forwarder, query(11, None));
    let answer = tokio::task::spawn_blocking(move || client.receive())
        .await
        .expect("joins");
    let header = wire::parse_header(&answer).expect("header");
    assert!(header.tc);
    assert_eq!((header.id, header.qdcount, header.ancount), (11, 1, 0));
    assert!(answer.len() <= 512);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_upstream_is_skipped_for_the_next_one() {
    let (silent, silent_seen) = udp_upstream(Behaviour::Silent);
    let (good, good_seen) = udp_upstream(Behaviour::Answer);
    let (forwarder, stop) = start(vec![PlainUpstream::udp(silent), PlainUpstream::udp(good)]);
    let client = Arc::new(Client::new());
    for id in 0..2 {
        client.submit(&forwarder, query(100 + id, None));
    }
    let receiver = Arc::clone(&client);
    let answers = tokio::task::spawn_blocking(move || [receiver.receive(), receiver.receive()])
        .await
        .expect("joins");
    for answer in answers {
        let header = wire::parse_header(&answer).expect("header");
        assert_eq!(header.rcode, 0);
    }
    // Round-robin start: each upstream was asked first once.
    assert_eq!(
        silent_seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len(),
        1
    );
    assert_eq!(
        good_seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len(),
        2
    );
    assert_eq!(forwarder.stats().timeouts, 1);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn servfail_when_every_attempt_fails() {
    let (silent, seen) = udp_upstream(Behaviour::Silent);
    let (forwarder, stop) = start(vec![PlainUpstream::udp(silent)]);
    let client = Client::new();
    client.submit(&forwarder, query(12, None));
    let answer = tokio::task::spawn_blocking(move || client.receive())
        .await
        .expect("joins");
    let header = wire::parse_header(&answer).expect("header");
    assert_eq!((header.id, header.rcode, header.qdcount), (12, 2, 1));
    // The first attempt and one retry.
    assert_eq!(seen.lock().unwrap_or_else(PoisonError::into_inner).len(), 2);
    assert_eq!(forwarder.stats().failed, 1);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_upstream_answers_servfail_at_once() {
    let (forwarder, stop) = start(Vec::new());
    let client = Client::new();
    client.submit(&forwarder, query(13, None));
    let answer = tokio::task::spawn_blocking(move || client.receive())
        .await
        .expect("joins");
    assert_eq!(wire::parse_header(&answer).expect("header").rcode, 2);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tcp_client_gets_the_answer_through_its_connection() {
    let (upstream, _) = udp_upstream(Behaviour::Answer);
    let (forwarder, stop) = start(vec![PlainUpstream::udp(upstream)]);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
    forwarder.submit(ForwardQuery {
        message: query(14, None),
        client: "127.0.0.1:5000".parse().expect("address"),
        transport: QueryTransport::Tcp,
        view: None,
        rule: None,
        reply: ReplyPath::Tcp(sender),
    });
    let answer = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("in time")
        .expect("an answer");
    assert_eq!(wire::parse_header(&answer).expect("header").id, 14);
    stop.cancel();
}

#[test]
fn an_answer_matches_its_query_by_id_and_question() {
    let asked = query(1, None);
    let mut got = answer_to(&asked, 1, false);
    assert!(matches(&asked, &got));
    // The case of the name does not matter; the type does.
    got[HEADER_LEN + 5] = b'E';
    assert!(matches(&asked, &got));
    let end = wire::questions_end(&got, 1).expect("question");
    got[end - 3] = 28;
    assert!(!matches(&asked, &got));
    let mut other = answer_to(&asked, 1, false);
    other[1] ^= 1;
    assert!(!matches(&asked, &other));
    let mut not_answer = answer_to(&asked, 1, false);
    not_answer[2] &= 0x7f;
    assert!(!matches(&asked, &not_answer));
}
