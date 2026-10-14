//! The server end to end: listener modes, TLS with hot reload, HTTP/2, trusted proxies and
//! the PROXY protocol, middleware, server-sent events across a restart, and shutdown.
//!
//! Every test binds `127.0.0.1:0` and talks raw HTTP/1.1 (or HTTP/2 through hyper) so that
//! the exact bytes on the wire are visible.

use std::{fmt::Write as _, net::SocketAddr, sync::Arc, time::Duration};

use axum::http::{Request, StatusCode};
use rustls::pki_types::{CertificateDer, ServerName};
use tenko_api::{
    RunningServer, ServerConfig,
    middleware::{Quota, RateLimitConfig},
    state::AppState,
};
use tenko_cluster::ca::{CertSource, TlsMaterial, TlsMode, TlsPolicy, TlsService, TrustedProxies};
use tenko_core::{
    Principal, SystemComponent, TableName, Timestamp,
    audit::{AuditAction, AuditDraft},
    codec::encode_key,
};
use tenko_store::{MemStore, MemStoreConfig, Store, WriteBatch};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use uuid::Uuid;

const PREFIXES: TableName = TableName::from_static("ipam.prefixes");
const WAIT: Duration = Duration::from_secs(10);

fn reverse_proxy(trusted: &str, proxy_protocol: bool) -> TlsMode {
    TlsMode::ReverseProxy {
        trusted_proxies: trusted.parse::<TrustedProxies>().expect("proxies"),
        proxy_protocol,
        public_host: "ddi.example.org".to_owned(),
    }
}

fn config(mode: TlsMode) -> ServerConfig {
    let tls = TlsService::new(mode, TlsPolicy::default()).expect("tls service");
    ServerConfig::new(
        vec!["127.0.0.1:0".parse().expect("addr")],
        tls,
        TlsPolicy::default(),
    )
}

/// Plain HTTP from every source (Lab), the simplest way to reach the server in tests.
fn lab_config() -> ServerConfig {
    let mut config = config(reverse_proxy("192.0.2.1", false));
    config.lab_plain_http = true;
    config
}

async fn start(config: ServerConfig, state: AppState) -> (RunningServer, SocketAddr) {
    let server = tenko_api::start(config, state)
        .await
        .expect("server starts");
    let addr = server.local_addrs()[0];
    (server, addr)
}

async fn stop(server: RunningServer) {
    server.shutdown();
    timeout(WAIT, server.wait())
        .await
        .expect("shutdown in time")
        .expect("clean shutdown");
}

#[derive(Debug)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("JSON body")
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn parse_head(raw: &[u8]) -> (u16, Vec<(String, String)>, usize) {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("end of headers")
        + 4;
    let head = std::str::from_utf8(&raw[..end]).expect("ASCII head");
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status line");
    let headers = lines
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect();
    (status, headers, end)
}

/// Decodes a chunked body (the server streams JSON bodies without a length sometimes).
fn dechunk(headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let chunked = headers.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked")
    });
    if !chunked {
        return body.to_vec();
    }
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") {
        let size = usize::from_str_radix(
            std::str::from_utf8(&rest[..line_end]).expect("size").trim(),
            16,
        )
        .expect("hex size");
        if size == 0 {
            break;
        }
        let start = line_end + 2;
        out.extend_from_slice(&rest[start..start + size]);
        rest = &rest[start + size + 2..];
    }
    out
}

/// Sends `head` (request line and headers, without the final blank line) plus `body` on
/// `stream` and reads the response until the server closes the connection.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    head: &str,
    body: &str,
) -> Reply {
    let mut request = format!("{head}\r\nConnection: close\r\n");
    if !body.is_empty() {
        let _ = write!(
            request,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut raw))
        .await
        .expect("response in time")
        .expect("read");
    let (status, headers, end) = parse_head(&raw);
    let body = dechunk(&headers, &raw[end..]);
    Reply {
        status,
        headers,
        body,
    }
}

async fn get(addr: SocketAddr, path: &str, extra: &[(&str, &str)]) -> Reply {
    send(addr, "GET", path, extra, "").await
}

async fn send(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &str,
) -> Reply {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: ddi.example.org");
    for (name, value) in extra {
        let _ = write!(head, "\r\n{name}: {value}");
    }
    exchange(&mut stream, &head, body).await
}

async fn read_until<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>, needle: &[u8]) {
    timeout(WAIT, async {
        while !buf.windows(needle.len()).any(|w| w == needle) {
            let mut chunk = [0_u8; 4096];
            let n = stream.read(&mut chunk).await.expect("read");
            assert!(
                n > 0,
                "stream closed before {:?}; got {:?}",
                String::from_utf8_lossy(needle),
                String::from_utf8_lossy(buf)
            );
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .expect("timed out waiting for stream data");
}

/// Opens an event stream; returns the socket and what was read so far.
async fn open_events(addr: SocketAddr, query: &str, last_id: Option<&str>) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let mut request = format!(
        "GET /api/v1/events{query} HTTP/1.1\r\nHost: ddi.example.org\r\nAccept: text/event-stream\r\n"
    );
    if let Some(id) = last_id {
        let _ = write!(request, "Last-Event-ID: {id}\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    read_until(&mut stream, &mut buf, b": connected\n\n").await;
    let (status, headers, _) = parse_head(&buf);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&buf));
    assert!(
        headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v == "text/event-stream")
    );
    (stream, buf)
}

/// Commits a batch that writes one prefix row (an `ipam` event) and returns its revision.
async fn write_prefix(store: &MemStore, n: u128) -> u64 {
    let id = Uuid::from_u128(0x0190_d1c2_0000_7000_8000_0000_0000_0000 + n);
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Ipam), Timestamp::now());
    batch
        .put(PREFIXES, encode_key(&id), vec![1_u8])
        .audit(AuditDraft::success(
            AuditAction::from_static("ipam.prefix.create"),
            vec![],
        ));
    store.propose(batch).await.expect("commit").revision.get()
}

#[tokio::test]
async fn serves_the_api_and_the_ui_with_security_headers() {
    let (server, addr) = start(lab_config(), AppState::default()).await;

    let health = get(addr, "/api/v1/health", &[]).await;
    assert_eq!(health.status, 200);
    assert_eq!(health.json()["status"], "ok");
    assert_eq!(health.header("cache-control"), Some("no-store"));
    assert_eq!(health.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(health.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(
        health.header("cross-origin-opener-policy"),
        Some("same-origin")
    );
    assert!(
        health
            .header("content-security-policy")
            .expect("csp")
            .contains("frame-ancestors 'none'")
    );
    assert!(health.header("x-request-id").is_some());
    assert!(
        health.header("strict-transport-security").is_none(),
        "no HSTS over plain HTTP"
    );

    let ui = get(addr, "/ipam/192.0.2.0/24", &[]).await;
    assert_eq!(ui.status, 200);
    assert_eq!(ui.header("content-type"), Some("text/html; charset=utf-8"));
    assert_eq!(ui.header("cache-control"), Some("no-cache"));
    assert!(ui.header("etag").is_some());
    assert_eq!(ui.header("x-content-type-options"), Some("nosniff"));
    let etag = ui.header("etag").expect("etag").to_owned();
    let cached = get(addr, "/", &[("If-None-Match", &etag)]).await;
    assert_eq!(cached.status, 304);

    for path in ["/api/v2/nope", "/api/v1/nope", "/api"] {
        let missing = get(addr, path, &[]).await;
        assert_eq!(missing.status, 404, "{path}");
        assert_eq!(
            missing.header("content-type"),
            Some("application/problem+json")
        );
        assert_eq!(missing.json()["code"], "sys.route_not_found", "{path}");
    }
    let wrong_method = send(addr, "DELETE", "/api/v1/health", &[], "").await;
    assert_eq!(wrong_method.status, 405);
    assert_eq!(wrong_method.json()["code"], "sys.method_not_allowed");

    let ready = get(addr, "/api/v1/health/ready", &[]).await;
    assert_eq!(ready.status, 200);
    assert_eq!(ready.json()["status"], "ready");

    let status = get(addr, "/api/v1/system/status", &[]).await;
    assert_eq!(status.status, 200);
    let status = status.json();
    assert_eq!(status["tls"]["mode"], "plain");
    assert_eq!(status["ui"]["stub"], tenko_api::ui::UI_STUB);
    assert!(
        status["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|w| w["code"] == "sys.tls.plain_http")
    );

    let metrics = get(addr, "/api/v1/metrics", &[]).await;
    assert_eq!(metrics.status, 200);
    assert!(
        metrics
            .header("content-type")
            .expect("type")
            .starts_with("application/openmetrics-text")
    );
    let text = metrics.text();
    assert!(
        text.contains(
            "tenko_http_requests_total{route=\"/api/v1/health\",method=\"GET\",status=\"200\"} 1"
        ),
        "{text}"
    );
    assert!(text.contains("route=\"other\""), "{text}");
    assert!(text.ends_with("# EOF\n"));

    stop(server).await;
}

#[tokio::test]
async fn plain_http_is_refused_outside_trusted_proxies() {
    // Mode c, the test client (127.0.0.1) is not a trusted proxy.
    let (server, addr) = start(
        config(reverse_proxy("192.0.2.1", false)),
        AppState::default(),
    )
    .await;
    let refused = get(addr, "/api/v1/health", &[]).await;
    assert_eq!(refused.status, 403);
    assert_eq!(
        refused.header("content-type"),
        Some("application/problem+json")
    );
    assert_eq!(refused.json()["code"], "sys.proxy_only");
    let ui = get(addr, "/", &[]).await;
    assert_eq!(ui.status, 403, "the UI is refused as well");
    stop(server).await;
}

#[tokio::test]
async fn forwarded_headers_count_only_from_trusted_proxies() {
    // The per-address limit (burst 1) shows which address the server attributes a request to.
    let mut config = config(reverse_proxy("127.0.0.1", false));
    config.http.rate_limit = RateLimitConfig {
        per_ip: Some(Quota {
            per_second: 1,
            burst: 1,
        }),
        per_principal: None,
        ..RateLimitConfig::default()
    };
    let (server, addr) = start(config, AppState::default()).await;
    let client_a = [("X-Forwarded-For", "198.51.100.7")];
    let client_b = [("X-Forwarded-For", "203.0.113.9, 198.51.100.8")];
    assert_eq!(get(addr, "/api/v1/health", &client_a).await.status, 200);
    let limited = get(addr, "/api/v1/health", &client_a).await;
    assert_eq!(limited.status, 429);
    assert_eq!(limited.json()["code"], "sys.rate_limited");
    assert_eq!(limited.json()["params"]["scope"], "ip");
    assert!(limited.header("retry-after").is_some());
    // Another forwarded client has its own bucket: the header was honoured.
    assert_eq!(get(addr, "/api/v1/health", &client_b).await.status, 200);
    // The left-most entry is the client's own claim and does not count.
    let spoofed = [("X-Forwarded-For", "192.0.2.200, 198.51.100.8")];
    assert_eq!(get(addr, "/api/v1/health", &spoofed).await.status, 429);
    stop(server).await;

    // From a peer that is not a trusted proxy the same header is ignored: one bucket for
    // the peer.
    let mut lab = lab_config();
    lab.tls =
        TlsService::new(reverse_proxy("192.0.2.1", false), TlsPolicy::default()).expect("tls");
    lab.http.rate_limit = RateLimitConfig {
        per_ip: Some(Quota {
            per_second: 1,
            burst: 1,
        }),
        per_principal: None,
        ..RateLimitConfig::default()
    };
    let (server, addr) = start(lab, AppState::default()).await;
    assert_eq!(get(addr, "/api/v1/health", &client_a).await.status, 200);
    assert_eq!(get(addr, "/api/v1/health", &client_b).await.status, 429);
    stop(server).await;
}

#[tokio::test]
async fn the_proxy_protocol_is_read_from_trusted_proxies() {
    let mut config = config(reverse_proxy("127.0.0.1", true));
    config.http.rate_limit = RateLimitConfig {
        per_ip: Some(Quota {
            per_second: 1,
            burst: 1,
        }),
        per_principal: None,
        ..RateLimitConfig::default()
    };
    let (server, addr) = start(config, AppState::default()).await;
    let proxied = |client: &'static str| async move {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(format!("PROXY TCP4 {client} 192.0.2.5 51000 443\r\n").as_bytes())
            .await
            .expect("header");
        exchange(
            &mut stream,
            "GET /api/v1/health HTTP/1.1\r\nHost: ddi.example.org",
            "",
        )
        .await
    };
    assert_eq!(proxied("198.51.100.20").await.status, 200);
    assert_eq!(
        proxied("198.51.100.20").await.status,
        429,
        "same client address"
    );
    assert_eq!(proxied("198.51.100.21").await.status, 200, "another client");

    // A connection without the header still works (health checks of the proxy).
    assert_eq!(get(addr, "/api/v1/health", &[]).await.status, 200);

    // A malformed header closes the connection without a response.
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"PROXY TCP4 not-an-address 192.0.2.5 1 2\r\nGET / HTTP/1.1\r\n\r\n")
        .await
        .expect("write");
    let mut rest = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut rest))
        .await
        .expect("closed in time")
        .ok();
    assert!(rest.is_empty(), "{}", String::from_utf8_lossy(&rest));
    stop(server).await;
}

#[tokio::test]
async fn the_csrf_guard_checks_the_origin_of_mutations() {
    let (server, addr) = start(lab_config(), AppState::default()).await;
    let foreign = send(
        addr,
        "POST",
        "/api/v1/prefixes",
        &[("Origin", "https://evil.example.com")],
        "{}",
    )
    .await;
    assert_eq!(foreign.status, 403);
    assert_eq!(foreign.json()["code"], "sys.csrf_rejected");

    let cookie_without_origin = send(
        addr,
        "POST",
        "/api/v1/prefixes",
        &[("Cookie", "tenko_session=abc")],
        "{}",
    )
    .await;
    assert_eq!(cookie_without_origin.status, 403);

    // Same origin (plain HTTP in the lab, so http://), and a CLI request without Origin,
    // reach the handler (a stub until WP1.4 lands, so anything but the guard's 403).
    for extra in [vec![("Origin", "http://ddi.example.org")], vec![]] {
        let passed = send(addr, "POST", "/api/v1/prefixes", &extra, "{}").await;
        assert_ne!(passed.json()["code"], "sys.csrf_rejected", "{extra:?}");
    }
    // Reads are never checked.
    let read = get(
        addr,
        "/api/v1/health",
        &[("Origin", "https://evil.example.com")],
    )
    .await;
    assert_eq!(read.status, 200);
    stop(server).await;
}

#[tokio::test]
async fn invalid_idempotency_keys_are_refused_and_failures_not_replayed() {
    let (server, addr) = start(lab_config(), AppState::default()).await;
    let invalid = send(
        addr,
        "POST",
        "/api/v1/prefixes",
        &[("Idempotency-Key", "has space")],
        "{}",
    )
    .await;
    assert_eq!(invalid.status, 400);
    assert_eq!(invalid.json()["code"], "sys.invalid_value");
    // A stub answers 501; failures are not stored, so the retry runs the handler again.
    for _ in 0..2 {
        let stub = send(
            addr,
            "POST",
            "/api/v1/prefixes",
            &[("Idempotency-Key", "import-a1")],
            "{}",
        )
        .await;
        assert!(stub.header("idempotency-replayed").is_none());
    }
    stop(server).await;
}

/// A test certificate authority and a server certificate for `ddi.example.org`.
struct TestCa {
    root: CertificateDer<'static>,
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl TestCa {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Tenko test CA");
        let key = rcgen::KeyPair::generate().expect("key");
        let issuer = rcgen::CertifiedIssuer::self_signed(params, key).expect("CA");
        let root = issuer.as_ref().der().clone();
        Self { root, issuer }
    }

    fn server_material(&self) -> (TlsMaterial, CertificateDer<'static>) {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["ddi.example.org".to_owned()])
            .expect("params")
            .signed_by(&key, &self.issuer)
            .expect("leaf");
        let material = TlsMaterial::from_pem(
            cert.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            CertSource::Inline,
        )
        .expect("material");
        (material, cert.der().clone())
    }

    fn connector(&self) -> tokio_rustls::TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.root.clone()).expect("root");
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }
}

async fn tls_connect(ca: &TestCa, addr: SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.expect("connect");
    ca.connector()
        .connect(ServerName::try_from("ddi.example.org").expect("name"), tcp)
        .await
        .expect("handshake")
}

#[tokio::test]
async fn tls_with_hot_reload_and_http2() {
    let ca = TestCa::new();
    let (first, first_der) = ca.server_material();
    let config = config(TlsMode::InternalCa);
    config.tls.install(first);
    let tls = config.tls.clone();
    let (server, addr) = start(config, AppState::default()).await;

    let stream = tls_connect(&ca, addr).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let peer = stream.get_ref().1.peer_certificates().expect("certs")[0].clone();
    assert_eq!(peer, first_der);
    drop(stream);

    // HTTP/2 over TLS.
    let stream = tls_connect(&ca, addr).await;
    let (mut sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .expect("h2 handshake");
    tokio::spawn(connection);
    let response = sender
        .send_request(
            Request::get("https://ddi.example.org/api/v1/health")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), axum::http::Version::HTTP_2);
    assert_eq!(
        response.headers()["strict-transport-security"],
        "max-age=31536000",
        "HSTS over TLS"
    );

    // HTTP/1.1 over TLS still works.
    let mut stream = tls_connect(&ca, addr).await;
    let reply = exchange(
        &mut stream,
        "GET /api/v1/system/status HTTP/1.1\r\nHost: ddi.example.org",
        "",
    )
    .await;
    assert_eq!(reply.status, 200);
    let status = reply.json();
    assert_eq!(status["tls"]["mode"], "internal_ca");
    assert_eq!(status["tls"]["min_version"], "1.2");
    assert_eq!(status["tls"]["certificate"]["names"][0], "ddi.example.org");
    assert!(
        status["tls"]["certificate"]["days_remaining"]
            .as_i64()
            .expect("days")
            > 30
    );

    // A new certificate applies to new connections without a restart.
    let (second, second_der) = ca.server_material();
    tls.install(second);
    let stream = tls_connect(&ca, addr).await;
    let peer = stream.get_ref().1.peer_certificates().expect("certs")[0].clone();
    assert_eq!(peer, second_der);
    assert_ne!(peer, first_der);
    drop(stream);

    // Plain HTTP on the TLS port gets no HTTP answer.
    let mut plain = TcpStream::connect(addr).await.expect("connect");
    plain
        .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: ddi.example.org\r\n\r\n")
        .await
        .expect("write");
    let mut rest = Vec::new();
    let _ = timeout(WAIT, plain.read_to_end(&mut rest)).await;
    assert!(!rest.starts_with(b"HTTP/1.1 200"));

    stop(server).await;
}

#[tokio::test]
async fn events_replay_across_a_server_restart() {
    let store = MemStore::default();
    let shared: Arc<dyn Store> = Arc::new(store.clone());
    let (server, addr) = start(lab_config(), AppState::new(Arc::clone(&shared))).await;

    let (mut live, mut buf) = open_events(addr, "?topics=ipam,audit", None).await;
    let first = write_prefix(&store, 1).await;
    read_until(
        &mut live,
        &mut buf,
        format!("id: {first}\nevent: ipam\n").as_bytes(),
    )
    .await;
    read_until(&mut live, &mut buf, b"event: audit\n").await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    assert!(text.contains("\"objects\":[{\"kind\":\"prefix\""), "{text}");

    // A subscriber to jobs only sees no ipam events, but does see shutdown.
    let (mut jobs, mut jobs_buf) = open_events(addr, "?topics=jobs", None).await;

    // Shutdown ends every stream with a `shutdown` event.
    server.shutdown();
    read_until(&mut live, &mut buf, b"event: shutdown\n").await;
    read_until(&mut jobs, &mut jobs_buf, b"event: shutdown\n").await;
    assert!(!String::from_utf8_lossy(&jobs_buf).contains("event: ipam"));
    let mut rest = Vec::new();
    timeout(WAIT, live.read_to_end(&mut rest))
        .await
        .expect("closed")
        .ok();
    timeout(WAIT, server.wait())
        .await
        .expect("stopped")
        .expect("clean");

    // Changes while the API is down.
    let second = write_prefix(&store, 2).await;
    let third = write_prefix(&store, 3).await;

    // A new server over the same store replays them from the journal.
    let (server, addr) = start(lab_config(), AppState::new(Arc::clone(&shared))).await;
    let (mut resumed, mut buf) = open_events(addr, "", Some(&first.to_string())).await;
    read_until(
        &mut resumed,
        &mut buf,
        format!("id: {third}\nevent: audit\n").as_bytes(),
    )
    .await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    assert!(
        text.contains(&format!("id: {second}\nevent: ipam\n")),
        "{text}"
    );
    assert!(!text.contains(&format!("id: {first}\n")), "{text}");

    // Live events follow the replay.
    let fourth = write_prefix(&store, 4).await;
    read_until(
        &mut resumed,
        &mut buf,
        format!("id: {fourth}\nevent: ipam\n").as_bytes(),
    )
    .await;

    // `from` works like Last-Event-ID for the first connection.
    let (mut from, mut from_buf) = open_events(addr, &format!("?from={third}"), None).await;
    let fifth = write_prefix(&store, 5).await;
    read_until(
        &mut from,
        &mut from_buf,
        format!("id: {fifth}\n").as_bytes(),
    )
    .await;
    assert!(String::from_utf8_lossy(&from_buf).contains(&format!("id: {fourth}\n")));

    // Ids the server cannot serve get a reset to the current revision.
    let (mut future, mut future_buf) = open_events(addr, "", Some("999999")).await;
    read_until(&mut future, &mut future_buf, b"event: reset\n").await;
    assert!(String::from_utf8_lossy(&future_buf).contains("\"reason\":\"gap\""));
    let (mut garbage, mut garbage_buf) = open_events(addr, "", Some("not-a-number")).await;
    read_until(&mut garbage, &mut garbage_buf, b"event: reset\n").await;

    // Unknown topics are refused.
    let unknown = get(addr, "/api/v1/events?topics=dns", &[]).await;
    assert_eq!(unknown.status, 400);
    assert_eq!(unknown.json()["code"], "sys.events.unknown_topic");

    stop(server).await;
}

#[tokio::test]
async fn events_older_than_the_journal_get_a_reset() {
    let store = MemStore::new(MemStoreConfig {
        journal_retention: 2,
        ..MemStoreConfig::default()
    });
    let shared: Arc<dyn Store> = Arc::new(store.clone());
    for n in 1..=6 {
        write_prefix(&store, n).await;
    }
    let (server, addr) = start(lab_config(), AppState::new(shared)).await;
    let (mut stream, mut buf) = open_events(addr, "", Some("1")).await;
    read_until(&mut stream, &mut buf, b"event: reset\n").await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    assert!(text.contains("id: 6\nevent: reset\n"), "{text}");
    stop(server).await;
}

#[tokio::test]
async fn invalid_configurations_are_refused() {
    let mut no_listen = lab_config();
    no_listen.listen.clear();
    assert!(
        tenko_api::start(no_listen, AppState::default())
            .await
            .is_err()
    );
    let mut workers = lab_config();
    workers.workers = 0;
    assert!(
        tenko_api::start(workers, AppState::default())
            .await
            .is_err()
    );
    let mut missing_ui = lab_config();
    missing_ui.ui = tenko_api::ui::UiSource::Dir(std::env::temp_dir().join("tenko-no-such-ui-dir"));
    let error = tenko_api::start(missing_ui, AppState::default())
        .await
        .expect_err("missing index.html");
    assert!(error.to_string().contains("index.html"), "{error}");
    let (server, addr) = start(lab_config(), AppState::default()).await;
    let mut taken = lab_config();
    taken.listen = vec![addr];
    assert!(matches!(
        tenko_api::start(taken, AppState::default()).await,
        Err(tenko_api::ServeError::Bind { .. })
    ));
    stop(server).await;
}

/// Accepts the bearer token `t0k3n` as one user.
struct OneToken;

impl tenko_core::Authenticator for OneToken {
    fn authenticate<'a>(
        &'a self,
        credentials: &'a tenko_core::Credentials,
        _source_ip: Option<std::net::IpAddr>,
        _now: Timestamp,
    ) -> tenko_core::auth::AuthFuture<'a> {
        Box::pin(async move {
            match credentials {
                tenko_core::Credentials::Bearer(token) if token == "t0k3n" => {
                    let user = tenko_core::UserId::from_uuid(Uuid::from_u128(7));
                    Ok(tenko_core::Authenticated {
                        principal: Principal::Token {
                            id: tenko_core::ApiTokenId::from_uuid(Uuid::from_u128(8)),
                            owner: user,
                        },
                        user: Some(user),
                        roles: std::collections::BTreeSet::new(),
                        strength: tenko_core::AuthStrength::Password,
                        expires_at: None,
                        flags: tenko_core::AuthFlags::default(),
                    })
                }
                tenko_core::Credentials::None => Err(tenko_core::AuthFailure::Missing),
                _ => Err(tenko_core::AuthFailure::Invalid),
            }
        })
    }
}

#[tokio::test]
async fn authentication_and_the_principal_limit() {
    let mut config = lab_config();
    config.http.rate_limit = RateLimitConfig {
        per_ip: None,
        per_principal: Some(Quota {
            per_second: 1,
            burst: 2,
        }),
        ..RateLimitConfig::default()
    };
    let mut state = AppState::default();
    state.auth = Some(Arc::new(OneToken));
    let (server, addr) = start(config, state).await;
    let bearer = [("Authorization", "Bearer t0k3n")];

    // Public endpoints need no credentials; protected ones answer 401.
    assert_eq!(get(addr, "/api/v1/health", &[]).await.status, 200);
    let anonymous = get(addr, "/api/v1/system/status", &[]).await;
    assert_eq!(anonymous.status, 401);
    assert_eq!(anonymous.json()["code"], "auth.unauthenticated");
    let wrong = get(
        addr,
        "/api/v1/system/status",
        &[("Authorization", "Bearer nope")],
    )
    .await;
    assert_eq!(wrong.status, 401);

    assert_eq!(
        get(addr, "/api/v1/system/status", &bearer).await.status,
        200
    );
    assert_eq!(get(addr, "/api/v1/metrics", &bearer).await.status, 200);
    let limited = get(addr, "/api/v1/system/status", &bearer).await;
    assert_eq!(limited.status, 429);
    assert_eq!(limited.json()["params"]["scope"], "principal");
    // Anonymous requests do not share the token's bucket.
    assert_eq!(get(addr, "/api/v1/health", &[]).await.status, 200);
    stop(server).await;
}
