//! DoT (RFC 7858) and DoH (RFC 8484) on real sockets with a rustls client that trusts a
//! test CA: answers, pipelining, `GET` and `POST` over HTTP/2 and HTTP/1.1, the error
//! statuses, the connection limits and the handshake timeout, the hot reload of an
//! imported certificate through the process's TLS service, and the reverse-proxy mode
//! with the PROXY protocol and `X-Forwarded-For`.

mod support;

use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, StatusCode, client::conn::http1, client::conn::http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
    server::ResolvesServerCert,
};
use support::{
    a,
    answer::{Answer, decode, query},
    rrset_ttl, soa, zone,
};
use tenko_cluster::ca::{TlsMode, TlsPolicy, TlsService};
use tenko_core::{
    Revision,
    dns::{QueryTransport, RrSet, ScopeName},
};
use tenko_dns::{
    DnsData,
    catalog::{Catalog, CatalogHandle},
    log::{QueryLogEntry, QueryLogSink},
    metrics::{QUERY_COUNTER, query_index},
    server::{Hooks, Server, ServerConfig},
    tls::{self, Termination, TlsListen},
    transport::udp::UdpSettings,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

const NOERROR: u16 = 0;
const NXDOMAIN: u16 = 3;

fn catalog() -> CatalogHandle {
    let parent = zone("example.test");
    let mut image = DnsData::at(Revision(1));
    let rows: Vec<RrSet> = vec![
        rrset_ttl(
            &parent,
            &ScopeName::DEFAULT,
            "example.test",
            600,
            &[soa("example.test", 120)],
        ),
        rrset_ttl(
            &parent,
            &ScopeName::DEFAULT,
            "www.example.test",
            300,
            &[a(1)],
        ),
    ];
    for row in rows {
        image.rrsets.insert(row.key(), row);
    }
    image.zones.insert(parent.id, parent);
    CatalogHandle::new(Catalog::build(&image))
}

/// A test CA and two leaves for `localhost`, as PEM files in a directory.
struct Pki {
    dir: tempfile::TempDir,
    ca_pem: String,
    leaves: [(String, String); 2],
}

impl Pki {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Tenko DNS test CA");
        let ca_key = rcgen::KeyPair::generate().expect("a CA key");
        let issuer = rcgen::CertifiedIssuer::self_signed(params, ca_key).expect("a CA");
        let ca_pem = issuer.as_ref().pem();
        let leaf = || {
            let key = rcgen::KeyPair::generate().expect("a leaf key");
            let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
                .expect("params")
                .signed_by(&key, &issuer)
                .expect("a leaf");
            (format!("{}{ca_pem}", cert.pem()), key.serialize_pem())
        };
        let leaves = [leaf(), leaf()];
        let pki = Self {
            dir: tempfile::tempdir().expect("a directory"),
            ca_pem,
            leaves,
        };
        pki.install(0);
        pki
    }

    fn cert_path(&self) -> PathBuf {
        self.dir.path().join("cert.pem")
    }

    fn key_path(&self) -> PathBuf {
        self.dir.path().join("key.pem")
    }

    /// Writes leaf `index` to the certificate and key files.
    fn install(&self, index: usize) {
        let (cert, key) = &self.leaves[index];
        write(&self.cert_path(), cert);
        write(&self.key_path(), key);
    }

    /// The DER of leaf `index`.
    fn leaf_der(&self, index: usize) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(self.leaves[index].0.as_bytes()).expect("a leaf")
    }

    /// The process's TLS service in the imported mode over the files.
    fn service(&self) -> TlsService {
        let mode = TlsMode::Imported {
            cert_path: self.cert_path(),
            key_path: self.key_path(),
        };
        let service = TlsService::new(mode.clone(), TlsPolicy::default()).expect("a service");
        service.set_mode(mode).expect("the files load");
        service
    }

    fn client(&self, alpn: &[&[u8]]) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(self.ca_pem.as_bytes()) {
            roots.add(cert.expect("the CA")).expect("a root");
        }
        let mut config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|alpn| alpn.to_vec()).collect();
        TlsConnector::from(Arc::new(config))
    }
}

fn write(path: &Path, text: &str) {
    std::fs::write(path, text).expect("write");
}

/// The client addresses and transports the query path logged.
#[derive(Debug, Default)]
struct Seen(Mutex<Vec<(IpAddr, QueryTransport)>>);

impl QueryLogSink for Seen {
    fn record(&self, entry: &QueryLogEntry<'_>) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((entry.client, entry.transport));
    }

    fn dropped(&self) -> u64 {
        0
    }
}

impl Seen {
    fn has(&self, client: &str, transport: QueryTransport) -> bool {
        let client: IpAddr = client.parse().expect("an address");
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&(client, transport))
    }
}

fn listen(termination: Termination) -> TlsListen {
    let loopback: SocketAddr = "127.0.0.1:0".parse().expect("address");
    TlsListen {
        dot: vec![loopback],
        doh: vec![loopback],
        termination,
        ..TlsListen::default()
    }
}

async fn start(
    tls: TlsListen,
    certificates: Option<Arc<dyn ResolvesServerCert>>,
    log: Option<Arc<dyn QueryLogSink>>,
) -> Server {
    let config = ServerConfig {
        listen: vec!["127.0.0.1:0".parse().expect("address")],
        udp: UdpSettings {
            workers: 1,
            ..UdpSettings::default()
        },
        tls: Some(tls),
        ..ServerConfig::default()
    };
    let hooks = Hooks {
        log,
        certificates,
        ..Hooks::default()
    };
    Server::start_authoritative(config, catalog(), hooks)
        .await
        .expect("start")
}

fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").expect("a name")
}

async fn dot(
    connector: &TlsConnector,
    address: SocketAddr,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(address).await?;
    connector.connect(localhost(), tcp).await
}

/// Sends a query per id in one write and reads the answers in order.
async fn ask<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ids: &[u16],
    name: &str,
) -> Vec<Answer> {
    let mut out = Vec::new();
    for id in ids {
        let message = query(name, 1).bytes(*id);
        out.extend_from_slice(&u16::try_from(message.len()).expect("len").to_be_bytes());
        out.extend_from_slice(&message);
    }
    stream.write_all(&out).await.expect("write");
    stream.flush().await.expect("flush");
    let mut answers = Vec::new();
    for _ in ids {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.expect("the length");
        let mut message = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut message).await.expect("the answer");
        answers.push(decode(&message));
    }
    answers
}

/// Whether the peer closes the stream within a few seconds (after a TLS alert, say).
async fn closed<S: AsyncRead + Unpin>(stream: &mut S) -> bool {
    let mut buf = [0u8; 256];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => return true,
            Ok(Ok(_)) => {}
            Err(_) => return false,
        }
    }
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let n = (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
        for index in 0..=chunk.len() {
            let six = (n >> (18 - 6 * index)) & 63;
            out.push(char::from(
                ALPHABET[usize::try_from(six).expect("six bits")],
            ));
        }
    }
    out
}

/// One DoH exchange's outcome.
struct Http {
    status: StatusCode,
    content_type: Option<String>,
    cache_control: Option<String>,
    body: Bytes,
}

async fn collect(response: hyper::Response<hyper::body::Incoming>) -> Http {
    let header = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value: &hyper::header::HeaderValue| value.to_str().ok())
            .map(str::to_owned)
    };
    let content_type = header(hyper::header::CONTENT_TYPE);
    let cache_control = header(hyper::header::CACHE_CONTROL);
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("a body")
        .to_bytes();
    Http {
        status,
        content_type,
        cache_control,
        body,
    }
}

fn get(path_and_query: &str) -> Request<Full<Bytes>> {
    Request::get(format!("https://localhost{path_and_query}"))
        .body(Full::new(Bytes::new()))
        .expect("a request")
}

fn post(media: &str, body: Vec<u8>) -> Request<Full<Bytes>> {
    Request::post("https://localhost/dns-query")
        .header(hyper::header::CONTENT_TYPE, media)
        .body(Full::new(Bytes::from(body)))
        .expect("a request")
}

async fn h2<S>(stream: S) -> http2::SendRequest<Full<Bytes>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .expect("an HTTP/2 connection");
    tokio::spawn(connection);
    sender
}

async fn h1<S>(stream: S) -> http1::SendRequest<Full<Bytes>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .expect("an HTTP/1.1 connection");
    tokio::spawn(connection);
    sender
}

fn counted(transport: QueryTransport, rcode: u16) -> u64 {
    QUERY_COUNTER.get(query_index(transport, false, rcode))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "one server, both transports, top to bottom"
)]
async fn dot_and_doh_answer_with_the_imported_certificate() {
    let pki = Pki::new();
    let service = pki.service();
    let resolver: Arc<dyn ResolvesServerCert> = service.resolver();
    let server = start(
        listen(Termination::Tls { tls13_only: false }),
        Some(resolver),
        None,
    )
    .await;
    let dot_address = server.dot_addresses()[0];
    let https_address = server.doh_addresses()[0];
    assert_ne!(dot_address.port(), 0);

    // DoT: one query, then three pipelined, answered in order.
    let mut stream = dot(&pki.client(&[b"dot"]), dot_address)
        .await
        .expect("a DoT handshake");
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"dot"[..]));
    let answers = ask(&mut stream, &[1], "www.example.test").await;
    assert_eq!((answers[0].rcode, answers[0].answers.len()), (NOERROR, 1));
    let answers = ask(&mut stream, &[2, 3, 4], "www.example.test").await;
    let ids: Vec<u16> = answers.iter().map(|answer| answer.header.id).collect();
    assert_eq!(ids, [2, 3, 4]);
    let missing = ask(&mut stream, &[5], "nohost.example.test").await;
    assert_eq!(missing[0].rcode, NXDOMAIN);
    // A client without ALPN is served too.
    let mut plain_alpn = dot(&pki.client(&[]), dot_address).await.expect("no ALPN");
    assert_eq!(
        ask(&mut plain_alpn, &[6], "www.example.test").await[0].rcode,
        NOERROR
    );

    // DoH over HTTP/2: GET and POST.
    let tls = dot(&pki.client(&[b"h2"]), https_address)
        .await
        .expect("a DoH handshake");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let mut sender = h2(tls).await;
    let message = query("www.example.test", 1).bytes(0);
    let got = collect(
        sender
            .send_request(get(&format!("/dns-query?dns={}", base64url(&message))))
            .await
            .expect("a GET answer"),
    )
    .await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.content_type.as_deref(), Some(tls::doh::MEDIA_TYPE));
    let answer = decode(&got.body);
    assert_eq!(
        (answer.header.id, answer.rcode, answer.answers.len()),
        (0, NOERROR, 1)
    );
    assert_eq!(got.cache_control.as_deref(), Some("max-age=300"));
    let posted = collect(
        sender
            .send_request(post(
                "application/dns-message",
                query("nohost.example.test", 1).bytes(0),
            ))
            .await
            .expect("a POST answer"),
    )
    .await;
    assert_eq!(posted.status, StatusCode::OK);
    let answer = decode(&posted.body);
    assert_eq!(answer.rcode, NXDOMAIN);
    // The SOA of a negative answer bounds its freshness: its TTL there is the smaller of
    // the SOA's TTL and its minimum (RFC 2308 section 5).
    assert_eq!(posted.cache_control.as_deref(), Some("max-age=120"));

    // The statuses of what is not a DNS query.
    for (request, expected) in [
        (get("/dns-query?dns=***"), StatusCode::BAD_REQUEST),
        (get("/dns-query"), StatusCode::BAD_REQUEST),
        (get("/other"), StatusCode::NOT_FOUND),
        (
            post("text/plain", message.clone()),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            post("application/dns-message", vec![0; 4]),
            StatusCode::BAD_REQUEST,
        ),
        (
            post("application/dns-message", vec![0; 70_000]),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            Request::put("https://localhost/dns-query")
                .body(Full::new(Bytes::new()))
                .expect("a request"),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ] {
        let got = collect(sender.send_request(request).await.expect("an answer")).await;
        assert_eq!(got.status, expected);
    }

    // DoH over HTTP/1.1.
    let tls = dot(&pki.client(&[b"http/1.1"]), https_address)
        .await
        .expect("a handshake");
    let mut sender = h1(tls).await;
    let request = Request::get(format!("/dns-query?dns={}", base64url(&message)))
        .header(hyper::header::HOST, "localhost")
        .body(Full::new(Bytes::new()))
        .expect("a request");
    let got = collect(sender.send_request(request).await.expect("an answer")).await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(decode(&got.body).answers.len(), 1);

    // Counted with their own `proto`, shown in the layout.
    assert!(counted(QueryTransport::Dot, NOERROR) >= 5);
    assert!(counted(QueryTransport::Doh, NOERROR) >= 2);
    let layout = server.layout().tls.expect("the TLS side");
    assert!(!layout.behind_proxy);
    assert_eq!(
        (layout.dot.clone(), layout.doh.clone()),
        (vec![dot_address], vec![https_address])
    );
    assert!(layout.dot_open >= 2, "{layout:?}");
    assert!(layout.doh_open >= 1, "{layout:?}");

    // The stop closes the open connections.
    server.stop().await;
    assert!(closed(&mut stream).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_limits_and_the_handshake_timeout_hold() {
    let pki = Pki::new();
    let service = pki.service();
    let settings = TlsListen {
        per_client: 2,
        idle: Duration::from_millis(400),
        handshake_timeout: Duration::from_millis(300),
        ..listen(Termination::Tls { tls13_only: true })
    };
    let server = start(settings, Some(service.resolver()), None).await;
    let address = server.dot_addresses()[0];
    let connector = pki.client(&[b"dot"]);

    // Two connections from the loopback address, the third over the per-client cap.
    let mut first = dot(&connector, address).await.expect("first");
    let mut second = dot(&connector, address).await.expect("second");
    assert_eq!(
        first.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    let third = dot(&connector, address).await;
    assert!(third.is_err(), "over the per-client cap");
    assert!(server.layout().tls.expect("tls").dot_refused >= 1);
    assert_eq!(
        ask(&mut first, &[1], "www.example.test").await[0].rcode,
        NOERROR
    );

    // The idle timeout closes a quiet connection.
    let quiet = Instant::now();
    assert!(closed(&mut second).await);
    assert!(quiet.elapsed() >= Duration::from_millis(300));
    drop(first);
    drop(second);

    // A handshake that never comes, one that is no TLS, and one that offers no `dot`.
    let mut silent = TcpStream::connect(address).await.expect("connect");
    assert!(closed(&mut silent).await, "the handshake timeout");
    let mut junk = TcpStream::connect(address).await.expect("connect");
    junk.write_all(b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("write");
    assert!(closed(&mut junk).await);
    assert!(
        dot(&pki.client(&[b"h2"]), address).await.is_err(),
        "no common ALPN"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while server.layout().tls.expect("tls").dot_handshake_failures < 3 && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(server.layout().tls.expect("tls").dot_handshake_failures >= 3);

    // DoH idles out too.
    let tls = dot(&pki.client(&[b"h2"]), server.doh_addresses()[0])
        .await
        .expect("a handshake");
    let mut sender = h2(tls).await;
    let message = query("www.example.test", 1).bytes(0);
    let got = collect(
        sender
            .send_request(get(&format!("/dns-query?dns={}", base64url(&message))))
            .await
            .expect("an answer"),
    )
    .await;
    assert_eq!(got.status, StatusCode::OK);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !sender.is_closed() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sender.is_closed(), "GOAWAY after the idle time");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_imported_certificate_reloads_without_dropping_the_listener() {
    let pki = Pki::new();
    let service = pki.service();
    let server = start(
        listen(Termination::Tls { tls13_only: false }),
        Some(service.resolver()),
        None,
    )
    .await;
    let address = server.dot_addresses()[0];
    let connector = pki.client(&[b"dot"]);
    let mut old = dot(&connector, address).await.expect("before");
    let peer = |stream: &TlsStream<TcpStream>| {
        stream.get_ref().1.peer_certificates().expect("a chain")[0].clone()
    };
    assert_eq!(peer(&old), pki.leaf_der(0));

    // New files: the next handshake gets the new certificate, the old connection answers.
    pki.install(1);
    assert!(service.reload().expect("the reload"), "new material");
    let mut new = dot(&connector, address).await.expect("after");
    assert_eq!(peer(&new), pki.leaf_der(1));
    assert_eq!(
        ask(&mut old, &[1], "www.example.test").await[0].rcode,
        NOERROR
    );
    assert_eq!(
        ask(&mut new, &[2], "www.example.test").await[0].rcode,
        NOERROR
    );
    assert_eq!(server.dot_addresses(), [address], "the same listener");
    server.stop().await;
}

/// A PROXY protocol version 2 header for TCP over IPv4 from `client`.
fn proxy_header(client: SocketAddr, local: SocketAddr) -> Vec<u8> {
    let (SocketAddr::V4(client), SocketAddr::V4(local)) = (client, local) else {
        panic!("IPv4 only");
    };
    let mut out = tls::proxy::SIGNATURE.to_vec();
    out.extend_from_slice(&[0x21, 0x11, 0, 12]);
    out.extend_from_slice(&client.ip().octets());
    out.extend_from_slice(&local.ip().octets());
    out.extend_from_slice(&client.port().to_be_bytes());
    out.extend_from_slice(&local.port().to_be_bytes());
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines, reason = "three proxy setups in a row")]
async fn behind_a_proxy_plain_dns_and_http_answer_trusted_peers() {
    let loopback: ipnet::IpNet = "127.0.0.1/32".parse().expect("a network");
    let seen = Arc::new(Seen::default());

    // The PROXY protocol on both listeners.
    let server = start(
        listen(Termination::Proxy {
            trusted: vec![loopback],
            proxy_protocol: true,
        }),
        None,
        Some(Arc::clone(&seen) as Arc<dyn QueryLogSink>),
    )
    .await;
    let dot_address = server.dot_addresses()[0];
    let mut stream = TcpStream::connect(dot_address).await.expect("connect");
    stream
        .write_all(&proxy_header(
            "192.0.2.7:4711".parse().expect("address"),
            dot_address,
        ))
        .await
        .expect("the header");
    assert_eq!(
        ask(&mut stream, &[1], "www.example.test").await[0].rcode,
        NOERROR
    );
    assert!(seen.has("192.0.2.7", QueryTransport::Dot));
    let https_address = server.doh_addresses()[0];
    let mut tcp = TcpStream::connect(https_address).await.expect("connect");
    tcp.write_all(&proxy_header(
        "198.51.100.4:4711".parse().expect("address"),
        https_address,
    ))
    .await
    .expect("the header");
    let mut sender = h1(tcp).await;
    let message = query("www.example.test", 1).bytes(0);
    let request = Request::get(format!("/dns-query?dns={}", base64url(&message)))
        .header(hyper::header::HOST, "dns.example.test")
        .body(Full::new(Bytes::new()))
        .expect("a request");
    let got = collect(sender.send_request(request).await.expect("an answer")).await;
    assert_eq!(got.status, StatusCode::OK);
    assert!(seen.has("198.51.100.4", QueryTransport::Doh));
    // A connection without the header is closed.
    let mut bare = TcpStream::connect(dot_address).await.expect("connect");
    bare.write_all(&[0; 16]).await.expect("write");
    assert!(closed(&mut bare).await);
    let layout = server.layout().tls.expect("tls");
    assert!(layout.behind_proxy);
    server.stop().await;

    // Without the PROXY protocol: DoH takes the client from X-Forwarded-For.
    let server = start(
        listen(Termination::Proxy {
            trusted: vec![loopback],
            proxy_protocol: false,
        }),
        None,
        Some(Arc::clone(&seen) as Arc<dyn QueryLogSink>),
    )
    .await;
    let tcp = TcpStream::connect(server.doh_addresses()[0])
        .await
        .expect("connect");
    let mut sender = h1(tcp).await;
    let request = Request::post("/dns-query")
        .header(hyper::header::HOST, "dns.example.test")
        .header(hyper::header::CONTENT_TYPE, tls::doh::MEDIA_TYPE)
        .header("x-forwarded-for", "192.0.2.200, 203.0.113.9")
        .body(Full::new(Bytes::from(message.clone())))
        .expect("a request");
    let got = collect(sender.send_request(request).await.expect("an answer")).await;
    assert_eq!(got.status, StatusCode::OK);
    assert!(seen.has("203.0.113.9", QueryTransport::Doh));
    let mut plain = TcpStream::connect(server.dot_addresses()[0])
        .await
        .expect("connect");
    assert_eq!(
        ask(&mut plain, &[2], "www.example.test").await[0].rcode,
        NOERROR
    );
    assert!(seen.has("127.0.0.1", QueryTransport::Dot));
    server.stop().await;

    // A peer that is not a trusted proxy is refused at once.
    let server = start(
        listen(Termination::Proxy {
            trusted: vec!["192.0.2.0/24".parse().expect("a network")],
            proxy_protocol: false,
        }),
        None,
        None,
    )
    .await;
    let mut refused = TcpStream::connect(server.dot_addresses()[0])
        .await
        .expect("connect");
    assert!(closed(&mut refused).await);
    assert!(server.layout().tls.expect("tls").dot_refused >= 1);
    server.stop().await;

    // Ending TLS without a certificate does not start.
    let config = ServerConfig {
        listen: vec!["127.0.0.1:0".parse().expect("address")],
        tls: Some(listen(Termination::Tls { tls13_only: false })),
        ..ServerConfig::default()
    };
    assert!(
        Server::start_authoritative(config, catalog(), Hooks::default())
            .await
            .is_err()
    );
}
