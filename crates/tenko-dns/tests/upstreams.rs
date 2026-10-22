//! The upstream transports and the pool on real loopback sockets: plain DNS over UDP, with
//! TCP on truncation and TCP only, DNS over TLS and DNS over HTTPS against in-test servers
//! whose certificates a test CA signs, and the pool's choice by round-trip time, its
//! back-off, its 0x20 fallback and its handling of SERVFAIL.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use rustls::{
    ServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tenko_core::dns::ForwardTransport;
use tenko_dns::{
    outbound::{Question, build_query},
    pool::{Budget, PoolKey, Pools, UpstreamSet, UpstreamSpec},
    upstream::{
        AnyUpstream, DohUpstream, DotUpstream, PlainUpstream, TlsClient, Upstream, UpstreamError,
        server_name,
    },
    wire,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tokio_rustls::TlsAcceptor;

const DNS_MESSAGE: &str = "application/dns-message";
const LOOPBACK: &str = "127.0.0.1:0";

// ---------------------------------------------------------------------------------------
// Queries and answers

/// What an in-test server does with a query.
#[derive(Debug, Clone, Copy)]
enum Mode {
    /// Answers at once.
    Good,
    /// Answers after a delay (plain UDP only).
    Delay(Duration),
    /// Never answers.
    Silent,
    /// Answers with the question in lower case, which breaks 0x20.
    LowerCase,
    /// Answers SERVFAIL.
    ServFail,
    /// Answers with TC set and no records.
    Truncate,
}

fn wire_name(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in text.split('.') {
        out.push(u8::try_from(label.len()).expect("label length"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn question(name: &[u8]) -> Question<'_> {
    Question {
        qname: name,
        qtype: 1,
        qclass: 1,
        rd: true,
        cd: false,
        dnssec_ok: false,
    }
}

/// A query for `www.example.test` in lower case with `id`.
fn query(id: u16) -> Vec<u8> {
    let name = wire_name("www.example.test");
    let mut out = Vec::new();
    build_query(&mut out, id, &question(&name), false);
    out
}

/// The answer `mode` gives to `query`: the id and the question echoed byte for byte, QR and
/// RA set, one A record `192.0.2.1` with TTL 300 (the owner a pointer to offset 12).
fn respond(query: &[u8], mode: Mode) -> Option<Vec<u8>> {
    if matches!(mode, Mode::Silent) {
        return None;
    }
    let end = wire::questions_end(query, 1)?;
    let mut out = query[..end].to_vec();
    out[2] = 0x80 | (query[2] & 0x01);
    out[3] = 0x80;
    out[8..12].fill(0);
    match mode {
        Mode::ServFail => {
            out[3] |= 2;
            out[6..8].fill(0);
            return Some(out);
        }
        Mode::Truncate => {
            out[2] |= 0x02;
            out[6..8].fill(0);
            return Some(out);
        }
        Mode::LowerCase => out[12..end].make_ascii_lowercase(),
        Mode::Good | Mode::Delay(_) | Mode::Silent => {}
    }
    out[6..8].copy_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
    out.extend_from_slice(&300u32.to_be_bytes());
    out.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
    Some(out)
}

/// Checks the id, the QR bit, the RCODE and, for NOERROR, the one A record.
fn assert_answer(query: &[u8], answer: &[u8], rcode: u8) {
    let asked = wire::parse_header(query).expect("query header");
    let got = wire::parse_header(answer).expect("answer header");
    assert_eq!(got.id, asked.id, "the id is echoed");
    assert!(got.qr, "QR is set");
    assert_eq!(got.rcode, rcode);
    if rcode == 0 {
        assert_eq!(got.ancount, 1);
        assert!(answer.ends_with(&[192, 0, 2, 1]), "the A record's address");
    }
}

async fn exchange(upstream: &impl Upstream, query: &[u8]) -> Result<Vec<u8>, UpstreamError> {
    let mut answer = Vec::new();
    upstream
        .exchange(query, &mut answer, Instant::now() + Duration::from_secs(3))
        .await?;
    Ok(answer)
}

// ---------------------------------------------------------------------------------------
// Plain DNS servers

async fn serve_framed<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, mode: Mode) {
    loop {
        let mut prefix = [0u8; 2];
        if stream.read_exact(&mut prefix).await.is_err() {
            return;
        }
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        if stream.read_exact(&mut query).await.is_err() {
            return;
        }
        let Some(answer) = respond(&query, mode) else {
            continue;
        };
        let len = u16::try_from(answer.len()).expect("answer length");
        let mut framed = len.to_be_bytes().to_vec();
        framed.extend_from_slice(&answer);
        if stream.write_all(&framed).await.is_err() || stream.flush().await.is_err() {
            return;
        }
    }
}

fn spawn_udp(socket: UdpSocket, mode: Mode) {
    tokio::spawn(async move {
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; 4_096];
        loop {
            let (len, from) = match socket.recv_from(&mut buf).await {
                Ok(received) => received,
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Err(_) => return,
            };
            let Some(answer) = respond(&buf[..len], mode) else {
                continue;
            };
            if let Mode::Delay(delay) = mode {
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = socket.send_to(&answer, from).await;
                });
            } else {
                let _ = socket.send_to(&answer, from).await;
            }
        }
    });
}

/// Accepts connections on `listener`, counts them and serves each with `mode`.
fn spawn_framed_listener(listener: TcpListener, mode: Mode, accepted: Arc<AtomicUsize>) {
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_framed(stream, mode));
        }
    });
}

struct PlainServer {
    addr: SocketAddr,
    tcp_accepts: Arc<AtomicUsize>,
}

/// A UDP server on a loopback port, with a TCP server on the same port when `tcp` is set.
async fn plain_server(udp: Mode, tcp: Option<Mode>) -> PlainServer {
    let tcp_accepts = Arc::new(AtomicUsize::new(0));
    for _ in 0..50 {
        let listener = match tcp {
            Some(_) => Some(TcpListener::bind(LOOPBACK).await.expect("TCP listener")),
            None => None,
        };
        let bind_to: SocketAddr = match &listener {
            Some(listener) => listener.local_addr().expect("TCP address"),
            None => LOOPBACK.parse().expect("address"),
        };
        let Ok(socket) = UdpSocket::bind(bind_to).await else {
            continue;
        };
        let addr = socket.local_addr().expect("UDP address");
        spawn_udp(socket, udp);
        if let (Some(listener), Some(mode)) = (listener, tcp) {
            spawn_framed_listener(listener, mode, Arc::clone(&tcp_accepts));
        }
        return PlainServer { addr, tcp_accepts };
    }
    panic!("no loopback port free for both UDP and TCP");
}

/// A plain UDP upstream behaving as `mode`.
async fn udp_upstream(mode: Mode) -> (SocketAddr, AnyUpstream) {
    let server = plain_server(mode, None).await;
    (
        server.addr,
        AnyUpstream::Plain(PlainUpstream::udp(server.addr)),
    )
}

fn plain_spec(address: SocketAddr) -> UpstreamSpec {
    UpstreamSpec {
        address,
        transport: ForwardTransport::Plain,
        tcp_only: false,
        tls_name: None,
        path: None,
    }
}

// ---------------------------------------------------------------------------------------
// TLS: a test CA, a DoT server and a DoH server

struct Pki {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Tenko upstream test CA");
        let key = rcgen::KeyPair::generate().expect("CA key");
        Self {
            issuer: rcgen::CertifiedIssuer::self_signed(params, key).expect("CA"),
        }
    }

    fn ca_pem(&self) -> String {
        self.issuer.pem()
    }

    fn client(&self) -> TlsClient {
        TlsClient::new(Some(self.ca_pem().as_bytes())).expect("TLS client")
    }

    /// An acceptor with a certificate for `name`, choosing ALPN `alpn`.
    fn acceptor(&self, name: &str, alpn: &[u8]) -> TlsAcceptor {
        let key = rcgen::KeyPair::generate().expect("leaf key");
        let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
            .expect("leaf params")
            .signed_by(&key, &self.issuer)
            .expect("leaf certificate");
        let mut config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("server config");
        config.alpn_protocols = vec![alpn.to_vec()];
        TlsAcceptor::from(Arc::new(config))
    }
}

struct DotServer {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

async fn dot_server(acceptor: TlsAcceptor) -> DotServer {
    let listener = TcpListener::bind(LOOPBACK).await.expect("listener");
    let addr = listener.local_addr().expect("address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    serve_framed(tls, Mode::Good).await;
                }
            });
        }
    });
    DotServer { addr, accepted }
}

struct DohServer {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    /// Answer HTTP 500 while set.
    failing: Arc<AtomicBool>,
    /// Requests that were not a POST of `application/dns-message` with id 0 to the path.
    bad_requests: Arc<AtomicUsize>,
}

async fn doh_request(
    request: http::Request<h2::RecvStream>,
    mut respond_to: h2::server::SendResponse<Bytes>,
    path: &str,
    failing: &AtomicBool,
    bad_requests: &AtomicUsize,
) {
    let (parts, mut body) = request.into_parts();
    let mut query = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else {
            return;
        };
        let _ = body.flow_control().release_capacity(chunk.len());
        query.extend_from_slice(&chunk);
    }
    let well_formed = parts.method == http::Method::POST
        && parts.uri.path() == path
        && parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .is_some_and(|value| value == DNS_MESSAGE)
        && query.starts_with(&[0, 0]);
    let answer = respond(&query, Mode::Good);
    let (status, answer) = if !well_formed || answer.is_none() {
        bad_requests.fetch_add(1, Ordering::SeqCst);
        (http::StatusCode::BAD_REQUEST, None)
    } else if failing.load(Ordering::SeqCst) {
        (http::StatusCode::INTERNAL_SERVER_ERROR, None)
    } else {
        (http::StatusCode::OK, answer)
    };
    let response = http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, DNS_MESSAGE)
        .body(())
        .expect("response");
    let Ok(mut send) = respond_to.send_response(response, answer.is_none()) else {
        return;
    };
    if let Some(answer) = answer {
        let _ = send.send_data(Bytes::from(answer), true);
    }
}

async fn doh_server(acceptor: TlsAcceptor, path: &'static str) -> DohServer {
    let listener = TcpListener::bind(LOOPBACK).await.expect("listener");
    let server = DohServer {
        addr: listener.local_addr().expect("address"),
        accepted: Arc::new(AtomicUsize::new(0)),
        failing: Arc::new(AtomicBool::new(false)),
        bad_requests: Arc::new(AtomicUsize::new(0)),
    };
    let accepted = Arc::clone(&server.accepted);
    let failing = Arc::clone(&server.failing);
    let bad_requests = Arc::clone(&server.bad_requests);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let failing = Arc::clone(&failing);
            let bad_requests = Arc::clone(&bad_requests);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut connection) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, respond_to))) = connection.accept().await {
                    let failing = Arc::clone(&failing);
                    let bad_requests = Arc::clone(&bad_requests);
                    tokio::spawn(async move {
                        doh_request(request, respond_to, path, &failing, &bad_requests).await;
                    });
                }
            });
        }
    });
    server
}

// ---------------------------------------------------------------------------------------
// Plain upstreams

#[tokio::test]
async fn plain_udp_exchange_returns_the_answer() {
    let server = plain_server(Mode::Good, None).await;
    let upstream = PlainUpstream::udp(server.addr);
    let asked = query(0x1234);
    let answer = exchange(&upstream, &asked).await.expect("answer");
    assert_answer(&asked, &answer, 0);
}

#[tokio::test]
async fn plain_udp_truncated_answer_is_asked_again_over_tcp() {
    let server = plain_server(Mode::Truncate, Some(Mode::Good)).await;
    let upstream = PlainUpstream::udp(server.addr);
    let asked = query(0x2345);
    let answer = exchange(&upstream, &asked).await.expect("answer");
    assert_answer(&asked, &answer, 0);
    assert!(
        !wire::parse_header(&answer).expect("header").tc,
        "the full TCP answer replaced the truncated one"
    );
    assert_eq!(server.tcp_accepts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn plain_tcp_only_upstream_skips_udp() {
    // The UDP side never answers: only TCP can produce the answer.
    let server = plain_server(Mode::Silent, Some(Mode::Good)).await;
    let upstream = PlainUpstream::tcp(server.addr);
    let asked = query(0x3456);
    let answer = exchange(&upstream, &asked).await.expect("answer");
    assert_answer(&asked, &answer, 0);
    assert_eq!(server.tcp_accepts.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------------------
// DNS over TLS

#[tokio::test]
async fn dot_exchange_is_answered_through_the_test_ca() {
    let pki = Pki::new();
    let server = dot_server(pki.acceptor("dot.example.test", b"dot")).await;
    let upstream = DotUpstream::new(
        server.addr,
        server_name("dot.example.test").expect("name"),
        &pki.client(),
    );
    let asked = query(0x4567);
    let answer = exchange(&upstream, &asked).await.expect("answer");
    assert_answer(&asked, &answer, 0);
}

#[tokio::test]
async fn dot_exchanges_share_one_connection() {
    let pki = Pki::new();
    let server = dot_server(pki.acceptor("dot.example.test", b"dot")).await;
    let upstream = DotUpstream::new(
        server.addr,
        server_name("dot.example.test").expect("name"),
        &pki.client(),
    );
    for id in [1, 2] {
        let asked = query(id);
        let answer = exchange(&upstream, &asked).await.expect("answer");
        assert_answer(&asked, &answer, 0);
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(upstream.idle_connections(), 1);
}

#[tokio::test]
async fn dot_certificate_name_mismatch_is_unreachable() {
    let pki = Pki::new();
    let server = dot_server(pki.acceptor("dot.example.test", b"dot")).await;
    let upstream = DotUpstream::new(
        server.addr,
        server_name("other.example.test").expect("name"),
        &pki.client(),
    );
    let error = exchange(&upstream, &query(5)).await.expect_err("mismatch");
    assert!(matches!(error, UpstreamError::Unreachable(_)), "{error:?}");
    assert_eq!(upstream.idle_connections(), 0);
}

#[test]
fn tls_client_rejects_a_ca_that_is_not_pem() {
    let error = TlsClient::new(Some(b"not pem")).expect_err("no certificate in the CA");
    assert!(error.contains("no certificate"), "{error}");
}

// ---------------------------------------------------------------------------------------
// DNS over HTTPS

#[tokio::test]
async fn doh_exchange_is_answered_at_the_default_path() {
    let pki = Pki::new();
    let server = doh_server(pki.acceptor("doh.example.test", b"h2"), "/dns-query").await;
    let upstream = DohUpstream::new(
        server.addr,
        server_name("doh.example.test").expect("name"),
        None,
        &pki.client(),
    );
    assert_eq!(
        upstream.uri(),
        format!("https://doh.example.test:{}/dns-query", server.addr.port())
    );
    let asked = query(0);
    let answer = exchange(&upstream, &asked).await.expect("answer");
    assert_answer(&asked, &answer, 0);
    assert_eq!(server.bad_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn doh_exchange_is_answered_at_a_custom_path() {
    let pki = Pki::new();
    let server = doh_server(pki.acceptor("doh.example.test", b"h2"), "/resolve/dns").await;
    let upstream = DohUpstream::new(
        server.addr,
        server_name("doh.example.test").expect("name"),
        Some("/resolve/dns"),
        &pki.client(),
    );
    let asked = query(0);
    let answer = exchange(&upstream, &asked).await.expect("answer");
    assert_answer(&asked, &answer, 0);
    assert_eq!(server.bad_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn doh_exchanges_share_one_connection() {
    let pki = Pki::new();
    let server = doh_server(pki.acceptor("doh.example.test", b"h2"), "/dns-query").await;
    let upstream = DohUpstream::new(
        server.addr,
        server_name("doh.example.test").expect("name"),
        None,
        &pki.client(),
    );
    for _ in 0..3 {
        let asked = query(0);
        let answer = exchange(&upstream, &asked).await.expect("answer");
        assert_answer(&asked, &answer, 0);
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(server.bad_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn doh_http_error_is_malformed() {
    let pki = Pki::new();
    let server = doh_server(pki.acceptor("doh.example.test", b"h2"), "/dns-query").await;
    server.failing.store(true, Ordering::SeqCst);
    let upstream = DohUpstream::new(
        server.addr,
        server_name("doh.example.test").expect("name"),
        None,
        &pki.client(),
    );
    let error = exchange(&upstream, &query(0)).await.expect_err("HTTP 500");
    assert!(matches!(error, UpstreamError::Malformed(_)), "{error:?}");
    // The server recovers: the same connection answers the next query.
    server.failing.store(false, Ordering::SeqCst);
    let asked = query(0);
    let answer = exchange(&upstream, &asked).await.expect("answer");
    assert_answer(&asked, &answer, 0);
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------------------
// The pool

const NAME: &str = "www.example.test";

async fn ask(set: &UpstreamSet, budget: Budget) -> Result<Vec<u8>, UpstreamError> {
    let name = wire_name(NAME);
    let mut answer = Vec::new();
    set.query(&question(&name), budget, &mut answer).await?;
    Ok(answer)
}

fn budget(timeout_ms: u64, retries: u8) -> Budget {
    Budget {
        timeout: Duration::from_millis(timeout_ms),
        retries,
    }
}

fn rcode_of(answer: &[u8]) -> u8 {
    wire::parse_header(answer).expect("header").rcode
}

#[tokio::test]
async fn pool_prefers_the_faster_upstream() {
    let (_, slow) = udp_upstream(Mode::Delay(Duration::from_millis(40))).await;
    let (_, fast) = udp_upstream(Mode::Good).await;
    let set = UpstreamSet::new("test-rtt-choice", vec![slow, fast]);
    for _ in 0..30 {
        let answer = ask(&set, budget(1_000, 0)).await.expect("answer");
        assert_eq!(rcode_of(&answer), 0);
    }
    let slow_ok = set.members()[0].stats().outcomes()[0];
    let fast_ok = set.members()[1].stats().outcomes()[0];
    assert_eq!(slow_ok + fast_ok, 30);
    assert!(slow_ok >= 1, "the slow upstream was measured");
    assert!(fast_ok >= 24, "the fast one answered {fast_ok} of 30");
    let health = set.health();
    assert!(health[0].srtt.expect("measured") > health[1].srtt.expect("measured"));
}

#[tokio::test]
async fn pool_backs_off_a_silent_upstream_and_keeps_answering() {
    let (_, silent) = udp_upstream(Mode::Silent).await;
    let (_, good) = udp_upstream(Mode::Good).await;
    let set = UpstreamSet::new("test-backoff", vec![silent, good]);
    let mut asked = 0;
    while !set.health()[0].down {
        assert!(
            asked < 600,
            "the silent upstream was never asked three times"
        );
        let answer = ask(&set, budget(150, 1))
            .await
            .expect("the good one answers");
        assert_eq!(rcode_of(&answer), 0);
        asked += 1;
    }
    let health = set.health();
    assert!(health[0].failures >= 3, "{health:?}");
    assert!(health[0].down);
    assert!(!health[1].down);
    assert_eq!(health[1].failures, 0);
    assert!(!set.all_down(Instant::now()));
    assert!(
        set.members()[0].stats().outcomes()[2] >= 3,
        "timeouts counted"
    );
    // With the silent upstream in back-off the good one answers every query.
    for _ in 0..5 {
        ask(&set, budget(150, 0)).await.expect("answer");
    }
}

#[tokio::test]
async fn pool_of_only_silent_upstreams_times_out() {
    let (_, first) = udp_upstream(Mode::Silent).await;
    let (_, second) = udp_upstream(Mode::Silent).await;
    let set = UpstreamSet::new("test-all-silent", vec![first, second]);
    let error = ask(&set, budget(100, 1)).await.expect_err("nobody answers");
    assert_eq!(error, UpstreamError::Timeout);
    let health = set.health();
    assert!(
        health.iter().all(|member| member.failures == 1),
        "{health:?}"
    );
}

#[tokio::test]
async fn pool_asks_in_lower_case_after_two_broken_cases() {
    let (_, upstream) = udp_upstream(Mode::LowerCase).await;
    let set = UpstreamSet::new("test-case-fallback", vec![upstream]);
    // A name with many letters: a random case is all lower case with chance 2^-37.
    let name = wire_name("abcdefghijklmnopqrstuvwxyz.example.test");
    let mut answer = Vec::new();
    set.query(&question(&name), budget(500, 2), &mut answer)
        .await
        .expect("the third attempt is in lower case");
    assert_eq!(rcode_of(&answer), 0);
    let health = set.health();
    assert!(health[0].lower_case, "{health:?}");
    let outcomes = set.members()[0].stats().outcomes();
    assert!(outcomes[4] >= 2, "malformed answers counted: {outcomes:?}");
    assert_eq!(outcomes[0], 1);
    // From then on one attempt is enough.
    set.query(&question(&name), budget(500, 0), &mut answer)
        .await
        .expect("answer in one attempt");
    assert_eq!(set.members()[0].stats().outcomes()[0], 2);
}

#[tokio::test]
async fn pool_moves_on_from_servfail_to_the_next_upstream() {
    let (_, failing) = udp_upstream(Mode::ServFail).await;
    let (_, good) = udp_upstream(Mode::Good).await;
    let set = UpstreamSet::new("test-servfail-next", vec![failing, good]);
    for _ in 0..10 {
        let answer = ask(&set, budget(500, 1)).await.expect("answer");
        assert_eq!(rcode_of(&answer), 0, "the good answer wins");
    }
    assert!(
        set.members()[0].stats().outcomes()[1] >= 1,
        "SERVFAIL counted"
    );
}

#[tokio::test]
async fn pool_relays_servfail_when_nothing_better_comes() {
    let (_, lone) = udp_upstream(Mode::ServFail).await;
    let set = UpstreamSet::new("test-servfail-lone", vec![lone]);
    let answer = ask(&set, budget(500, 1)).await.expect("relayed");
    assert_eq!(rcode_of(&answer), 2);

    let (_, first) = udp_upstream(Mode::ServFail).await;
    let (_, second) = udp_upstream(Mode::ServFail).await;
    let set = UpstreamSet::new("test-servfail-both", vec![first, second]);
    let answer = ask(&set, budget(500, 1)).await.expect("relayed");
    assert_eq!(rcode_of(&answer), 2);
    let tried: u64 = set
        .members()
        .iter()
        .map(|member| member.stats().outcomes()[1])
        .sum();
    assert_eq!(
        tried, 1,
        "the first SERVFAIL moved on, the second was relayed"
    );
}

#[tokio::test]
async fn pool_mixes_plain_dot_and_doh_members() {
    let pki = Pki::new();
    let dot = dot_server(pki.acceptor("dot.example.test", b"dot")).await;
    let doh = doh_server(pki.acceptor("doh.example.test", b"h2"), "/dns-query").await;
    let plain = plain_server(Mode::Good, None).await;
    let pools = Pools::new(Some(pki.ca_pem().into_bytes()));
    let specs = [
        UpstreamSpec {
            address: dot.addr,
            transport: ForwardTransport::Dot,
            tcp_only: false,
            tls_name: Some("dot.example.test".to_owned()),
            path: None,
        },
        UpstreamSpec {
            address: doh.addr,
            transport: ForwardTransport::Doh,
            tcp_only: false,
            tls_name: Some("doh.example.test".to_owned()),
            path: None,
        },
        plain_spec(plain.addr),
    ];
    let set = pools
        .get(PoolKey::Default, "test-mixed", &specs)
        .expect("set");
    // An upstream never measured counts as the fastest: the first queries visit each one.
    for _ in 0..6 {
        let answer = ask(&set, budget(2_000, 0)).await.expect("answer");
        assert_eq!(rcode_of(&answer), 0);
    }
    for (index, member) in set.members().iter().enumerate() {
        assert!(member.stats().outcomes()[0] >= 1, "member {index} answered");
    }
    let transports: Vec<_> = set.health().iter().map(|member| member.transport).collect();
    assert_eq!(
        transports,
        [
            ForwardTransport::Dot,
            ForwardTransport::Doh,
            ForwardTransport::Plain
        ]
    );
    assert_eq!(
        doh.bad_requests.load(Ordering::SeqCst),
        0,
        "DoH queries carry id 0"
    );
}

// ---------------------------------------------------------------------------------------
// The set registry

#[tokio::test]
async fn pools_keep_the_set_while_the_specs_are_unchanged() {
    let first = plain_server(Mode::Good, None).await;
    let second = plain_server(Mode::Good, None).await;
    let pools = Pools::new(None);
    let specs = [plain_spec(first.addr)];
    let held = pools
        .get(PoolKey::Default, "test-registry", &specs)
        .expect("set");
    let again = pools
        .get(PoolKey::Default, "test-registry", &specs)
        .expect("set");
    assert!(Arc::ptr_eq(&held, &again), "unchanged specs keep the set");
    assert!(Arc::ptr_eq(
        &held,
        &pools.held(PoolKey::Default).expect("held")
    ));

    let changed = pools
        .get(
            PoolKey::Default,
            "test-registry",
            &[plain_spec(second.addr)],
        )
        .expect("set");
    assert!(
        !Arc::ptr_eq(&held, &changed),
        "changed specs build a new set"
    );
    assert_eq!(changed.members().len(), 1);
    assert_eq!(
        changed.members()[0].state().upstream,
        second.addr.to_string()
    );
}

#[tokio::test]
async fn pools_reject_a_dot_spec_without_a_tls_name() {
    let pools = Pools::new(None);
    let spec = UpstreamSpec {
        address: "127.0.0.1:853".parse().expect("address"),
        transport: ForwardTransport::Dot,
        tcp_only: false,
        tls_name: None,
        path: None,
    };
    let error = pools
        .get(PoolKey::Default, "test-no-name", &[spec])
        .expect_err("a DoT upstream needs a name");
    assert!(error.contains("tls_name"), "{error}");
    assert!(pools.held(PoolKey::Default).is_none());
}

#[tokio::test]
async fn pools_reject_a_ca_without_certificates_for_tls_upstreams() {
    let pools = Pools::new(Some(b"not pem".to_vec()));
    let spec = UpstreamSpec {
        address: "127.0.0.1:853".parse().expect("address"),
        transport: ForwardTransport::Dot,
        tcp_only: false,
        tls_name: Some("dot.example.test".to_owned()),
        path: None,
    };
    assert!(pools.get(PoolKey::Default, "test-bad-ca", &[spec]).is_err());
}

// dns-visibility: the figures of the upstreams.
#[tokio::test]
async fn pool_reports_the_times_the_state_and_the_chosen_upstream() {
    use tenko_core::metrics::{Registry, encode};
    use tenko_dns::pool::{UPSTREAM_HEALTH_FAMILY, UPSTREAM_RTT_FAMILY, UpstreamState};

    let (_, slow) = udp_upstream(Mode::Delay(Duration::from_millis(30))).await;
    let (_, fast) = udp_upstream(Mode::Good).await;
    let (_, silent) = udp_upstream(Mode::Silent).await;
    let set = UpstreamSet::new("test-figures", vec![slow, fast, silent]);
    let before = set.health();
    assert!(
        before
            .iter()
            .all(|member| member.state == UpstreamState::Unknown && member.p50.is_none()),
        "{before:?}"
    );
    assert_eq!(
        before.iter().filter(|member| member.chosen).count(),
        1,
        "one upstream is chosen"
    );
    for _ in 0..40 {
        ask(&set, budget(150, 2)).await.expect("an answer");
    }
    let health = set.health();
    let (slow, fast, silent) = (&health[0], &health[1], &health[2]);
    assert_eq!(fast.state, UpstreamState::Up, "{fast:?}");
    assert!(fast.chosen, "{health:?}");
    assert!(!slow.chosen && !silent.chosen);
    assert!(fast.last_rtt.is_some() && fast.srtt.is_some());
    let (p50, p99) = (fast.p50.expect("p50"), fast.p99.expect("p99"));
    assert!(p50 <= p99, "{fast:?}");
    assert!(fast.window_answers >= 30, "{fast:?}");
    assert!(fast.outcomes[0] >= 30);
    assert_eq!(slow.state, UpstreamState::Up);
    assert!(
        slow.p50.expect("the slow one was measured") >= Duration::from_millis(25),
        "{slow:?}"
    );
    assert!(
        matches!(silent.state, UpstreamState::Degraded | UpstreamState::Down),
        "{silent:?}"
    );
    assert!(silent.failures >= 1);
    assert!(
        silent
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("did not answer in time")),
        "{silent:?}"
    );
    assert!(silent.last_error_at.is_some());
    assert!(silent.p50.is_none());

    let registry = Registry::new();
    registry.register(&UPSTREAM_HEALTH_FAMILY);
    registry.register(&UPSTREAM_RTT_FAMILY);
    let mut text = String::new();
    encode(&registry.snapshot(), &mut text);
    let up = format!(
        "tenko_dns_upstream_health{{rule=\"test-figures\",upstream=\"{}\"}} 1\n",
        fast.upstream
    );
    assert!(text.contains(&up), "{text}");
    let failing = format!(
        "tenko_dns_upstream_health{{rule=\"test-figures\",upstream=\"{}\"}} 0",
        silent.upstream
    );
    assert!(text.contains(&failing), "{text}");
    let count = format!(
        "tenko_dns_upstream_rtt_seconds_count{{rule=\"test-figures\",upstream=\"{}\"}}",
        fast.upstream
    );
    assert!(text.contains(&count), "{text}");
    // A set no one holds leaves the health gauge.
    drop(set);
    let mut after = String::new();
    encode(&registry.snapshot(), &mut after);
    assert!(
        !after.contains("tenko_dns_upstream_health{rule=\"test-figures\""),
        "{after}"
    );
}
