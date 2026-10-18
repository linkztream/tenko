//! Acceptance of DoT and DoH served by the `dns` role (WP5.3, DNS-14, E20) through the real
//! binary, in each TLS mode of OPS-22 (P2-Q8):
//!
//! - The internal CA: DoT and DoH answer with the CA's certificate for `localhost`, trusted
//!   through the CA root the server writes; GET and POST over HTTP/2, `Cache-Control` from
//!   the TTL; the node status lists both listeners.
//! - Imported files: DoT and DoH serve the imported chain; new files are served on the next
//!   handshake while the listener and an open connection keep running.
//! - Behind a reverse proxy: plain DNS (the DoT address) and plain HTTP (the DoH address)
//!   from the trusted loopback proxy, with the client's address from a PROXY v2 header in
//!   the query log; a connection without the header is closed.
//!
//! The clients are in the test (rustls with the mode's CA, hyper's HTTP/2 client). When
//! `kdig` is on the `PATH`, `kdig +tls` and `kdig +https` are asked as well.

mod serve_support;

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use serde_json::{Value, json};
use serve_support::{Node, Proc, Transport, api::Api, free_port, wait_for_setup_token};
use tenko_dns::wire;

const ZONE: &str = "example.test";
const WWW: &str = "www.example.test";
const TYPE_A: u16 = 1;
const NOERROR: u8 = 0;
const NXDOMAIN: u8 = 3;

/// The addresses of one node: plain DNS, DoT and DoH, all on loopback.
struct Ports {
    dns: SocketAddr,
    dot: SocketAddr,
    doh: SocketAddr,
}

impl Ports {
    fn new() -> Self {
        let at = |port| SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        Self {
            dns: at(free_port()),
            dot: at(free_port()),
            doh: at(free_port()),
        }
    }

    fn config(&self, extra: &str) -> String {
        format!(
            "[dns]\nlisten = [\"{}\"]\nworkers = 1\n[dns.tls]\ndot = true\ndoh = true\n\
             dot_listen = [\"{}\"]\ndoh_listen = [\"{}\"]\n{extra}",
            self.dns, self.dot, self.doh
        )
    }
}

fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(&mut out, id, name, qtype, Some(1232));
    out[2] |= 0x01;
    out
}

fn header(answer: &[u8]) -> wire::RawHeader {
    wire::parse_header(answer).expect("a header")
}

/// Whether `answer` holds the four octets of `address` in a record.
fn holds(answer: &[u8], address: [u8; 4]) -> bool {
    answer.windows(4).any(|window| window == address)
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

fn client_config(ca: &Path, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let pem = std::fs::read(ca).expect("read the CA");
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&pem) {
        roots.add(cert.expect("a CA certificate")).expect("a root");
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|alpn| alpn.to_vec()).collect();
    Arc::new(config)
}

fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").expect("a name")
}

/// A DoT connection with a client that trusts `ca`.
struct Dot {
    stream: StreamOwned<ClientConnection, TcpStream>,
}

impl Dot {
    fn connect(address: SocketAddr, ca: &Path) -> Result<Self, String> {
        let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(3))
            .map_err(|error| error.to_string())?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        let connection = ClientConnection::new(client_config(ca, &[b"dot"]), localhost())
            .map_err(|error| error.to_string())?;
        let mut stream = StreamOwned::new(connection, tcp);
        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(|error| error.to_string())?;
        }
        Ok(Self { stream })
    }

    fn ask(&mut self, id: u16, name: &str) -> Vec<u8> {
        let message = query(id, name, TYPE_A);
        let mut framed = u16::try_from(message.len())
            .expect("length")
            .to_be_bytes()
            .to_vec();
        framed.extend_from_slice(&message);
        self.stream.write_all(&framed).expect("write");
        self.stream.flush().expect("flush");
        let mut len = [0u8; 2];
        self.stream.read_exact(&mut len).expect("the length");
        let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
        self.stream.read_exact(&mut answer).expect("the answer");
        assert_eq!(header(&answer).id, id);
        answer
    }

    /// The leaf certificate the server presented.
    fn leaf(&self) -> Vec<u8> {
        self.stream.conn.peer_certificates().expect("a chain")[0].to_vec()
    }
}

/// What a DoH request answered.
struct Doh {
    status: u16,
    cache_control: Option<String>,
    body: Vec<u8>,
}

/// One DoH request over HTTP/2 with a client that trusts `ca`: GET when `post` is false.
fn doh(address: SocketAddr, ca: &Path, message: &[u8], post: bool) -> Doh {
    let config = client_config(ca, &[b"h2"]);
    let message = message.to_vec();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async move {
        let tcp = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect to DoH");
        let tls = tokio_rustls::TlsConnector::from(config)
            .connect(localhost(), tcp)
            .await
            .expect("a DoH handshake");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .expect("HTTP/2");
        tokio::spawn(connection);
        let request = if post {
            hyper::Request::post("https://localhost/dns-query")
                .header("content-type", "application/dns-message")
                .body(Full::new(Bytes::from(message)))
        } else {
            hyper::Request::get(format!(
                "https://localhost/dns-query?dns={}",
                base64url(&message)
            ))
            .body(Full::new(Bytes::new()))
        }
        .expect("a request");
        let response = sender.send_request(request).await.expect("a DoH answer");
        let status = response.status().as_u16();
        let cache_control = response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("the body")
            .to_bytes()
            .to_vec();
        Doh {
            status,
            cache_control,
            body,
        }
    })
}

/// `kdig` with these arguments, when it is installed.
fn kdig(args: &[String]) -> Option<String> {
    let output = Command::new("kdig").args(args).output().ok()?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn kdig_both(ports: &Ports, ca: &Path) {
    for (port, transport) in [(ports.dot.port(), "+tls"), (ports.doh.port(), "+https")] {
        let args = vec![
            "@127.0.0.1".to_owned(),
            "-p".to_owned(),
            port.to_string(),
            transport.to_owned(),
            format!("+tls-ca={}", ca.display()),
            "+tls-hostname=localhost".to_owned(),
            WWW.to_owned(),
            "A".to_owned(),
        ];
        let Some(out) = kdig(&args) else {
            eprintln!("acceptance_dns_tls: kdig is not installed, the in-test clients only");
            return;
        };
        assert!(out.contains("192.0.2.10"), "kdig {transport}: {out}");
    }
}

/// Starts the node and waits for the role's line, which names the encrypted listeners.
fn start(node: &mut Node, ports: &Ports) -> Proc {
    let server = node.start();
    let line = server
        .wait_stdout_line(Duration::from_secs(10), |line| {
            line.starts_with(&format!("dns role answering on {}", ports.dns))
        })
        .unwrap_or_else(|| panic!("no dns line\n{}", server.diagnostics()));
    assert!(
        line.contains(&format!("DoT on {}", ports.dot))
            && line.contains(&format!("DoH on {}", ports.doh)),
        "{line}"
    );
    server
}

/// Sets the node up and creates the zone with `www` at 192.0.2.10.
fn zone(node: &Node, server: &Proc) -> Api {
    let token = wait_for_setup_token(server);
    let mut api = Api::new(node);
    api.setup(&token);
    let zone = api
        .post(
            "/dns/zones",
            &json!({
                "name": ZONE,
                "kind": "primary",
                "serial": "counter",
                "soa": {"mname": "ns1.example.test", "rname": "hostmaster.example.test"},
                "name_servers": ["ns1.example.test"],
            }),
        )
        .expect(201);
    let zone_id = zone["id"].as_str().expect("a zone id").to_owned();
    api.post(
        &format!("/dns/zones/{zone_id}/records/batch"),
        &json!({ "changes": [{
            "op": "set", "name": WWW, "type": "A", "ttl": 300,
            "records": [{"type": "A", "address": "192.0.2.10"}],
        }] }),
    )
    .expect(200);
    api
}

/// Asks over DoT until the record is served (the feed applies the batch first).
fn served(dot: &mut Dot) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut id = 100;
    loop {
        id += 1;
        let answer = dot.ask(id, WWW);
        if holds(&answer, [192, 0, 2, 10]) || Instant::now() > deadline {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn node_report(api: &Api) -> Value {
    let status = api.get("/system/status").expect(200);
    let node_id = status["node"]["id"].as_u64().expect("a node id");
    api.get(&format!("/nodes/{node_id}/dns")).expect(200)
}

#[test]
fn dot_and_doh_serve_the_internal_ca_certificate() {
    let began = Instant::now();
    let ports = Ports::new();
    let mut node = Node::new()
        .with_transport(Transport::InternalCa)
        .with_args(&["--roles", "controller,dns"])
        .with_config(&ports.config(""));
    let mut server = start(&mut node, &ports);
    let api = zone(&node, &server);
    let ca = node.ca_file().expect("the CA root");

    let mut dot = Dot::connect(ports.dot, &ca).expect("a DoT handshake");
    let answer = served(&mut dot);
    assert_eq!(
        (header(&answer).rcode, header(&answer).ancount),
        (NOERROR, 1)
    );
    assert!(holds(&answer, [192, 0, 2, 10]));
    assert_eq!(header(&dot.ask(7, "missing.example.test")).rcode, NXDOMAIN);

    let got = doh(ports.doh, &ca, &query(0, WWW, TYPE_A), false);
    assert_eq!(got.status, 200);
    assert!(holds(&got.body, [192, 0, 2, 10]));
    assert_eq!(got.cache_control.as_deref(), Some("max-age=300"));
    let posted = doh(
        ports.doh,
        &ca,
        &query(0, "missing.example.test", TYPE_A),
        true,
    );
    assert_eq!((posted.status, header(&posted.body).rcode), (200, NXDOMAIN));

    let report = node_report(&api);
    let listeners = report["listeners"].as_array().expect("listeners");
    for (transport, address) in [("dot", ports.dot), ("doh", ports.doh)] {
        assert!(
            listeners
                .iter()
                .any(|listener| listener["transport"] == transport
                    && listener["address"] == address.to_string()),
            "{report}"
        );
    }
    kdig_both(&ports, &ca);
    server.stop().assert_graceful_shutdown();
    eprintln!(
        "acceptance_dns_tls: internal CA mode in {} s",
        began.elapsed().as_secs()
    );
}

/// A new test CA and a leaf for `localhost`, written over the node's imported files; the
/// path of the new CA.
fn replace_imported(node: &Node) -> std::path::PathBuf {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Tenko renewed test CA");
    let ca_key = rcgen::KeyPair::generate().expect("a CA key");
    let issuer = rcgen::CertifiedIssuer::self_signed(params, ca_key).expect("a CA");
    let key = rcgen::KeyPair::generate().expect("a leaf key");
    let leaf = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .expect("params")
        .signed_by(&key, &issuer)
        .expect("a leaf");
    let ca_pem = issuer.as_ref().pem();
    let ca_path = node.root().join("renewed-ca.pem");
    std::fs::write(&ca_path, &ca_pem).expect("write the CA");
    // The key first: a watcher that reads in between sees a pair that does not match and
    // keeps serving the old one until the next check.
    std::fs::write(node.imported_key_path(), key.serialize_pem()).expect("write the key");
    std::fs::write(node.imported_cert_path(), format!("{}{ca_pem}", leaf.pem()))
        .expect("write the chain");
    ca_path
}

#[test]
fn dot_and_doh_serve_the_imported_certificate_and_follow_its_reload() {
    let began = Instant::now();
    let ports = Ports::new();
    let mut node = Node::new()
        .with_transport(Transport::Imported)
        .with_args(&["--roles", "controller,dns"])
        .with_config(&ports.config(""));
    let mut server = start(&mut node, &ports);
    let _api = zone(&node, &server);
    let ca = node.ca_file().expect("the imported CA");

    let mut old = Dot::connect(ports.dot, &ca).expect("a DoT handshake");
    assert!(holds(&served(&mut old), [192, 0, 2, 10]));
    let first_leaf = old.leaf();
    let got = doh(ports.doh, &ca, &query(0, WWW, TYPE_A), false);
    assert_eq!(got.status, 200);
    assert!(holds(&got.body, [192, 0, 2, 10]));
    kdig_both(&ports, &ca);

    // New files: within the watch interval (5 s) a new connection gets the new chain.
    let renewed = replace_imported(&node);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut new = loop {
        match Dot::connect(ports.dot, &renewed) {
            Ok(dot) => break dot,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "the new certificate was not served: {error}\n{}",
                    server.diagnostics()
                );
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    };
    let reloaded = Instant::now();
    assert_ne!(new.leaf(), first_leaf);
    assert!(holds(&new.ask(1, WWW), [192, 0, 2, 10]));
    // The connection opened before the reload still answers on the old certificate.
    assert!(holds(&old.ask(2, WWW), [192, 0, 2, 10]));
    assert_eq!(old.leaf(), first_leaf);
    let got = doh(ports.doh, &renewed, &query(0, WWW, TYPE_A), true);
    assert_eq!(got.status, 200);
    assert!(holds(&got.body, [192, 0, 2, 10]));
    server.stop().assert_graceful_shutdown();
    eprintln!(
        "acceptance_dns_tls: imported mode in {} s, the reload seen {} ms before the stop",
        began.elapsed().as_secs(),
        reloaded.elapsed().as_millis()
    );
}

/// A PROXY protocol version 2 header for TCP over IPv4 from `client` to `local`.
fn proxy_header(client: [u8; 4], local: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(local) = local else {
        panic!("IPv4 only");
    };
    let mut out = tenko_dns::tls::proxy::SIGNATURE.to_vec();
    out.extend_from_slice(&[0x21, 0x11, 0, 12]);
    out.extend_from_slice(&client);
    out.extend_from_slice(&local.ip().octets());
    out.extend_from_slice(&4711u16.to_be_bytes());
    out.extend_from_slice(&local.port().to_be_bytes());
    out
}

/// Plain DNS on the DoT address, as the proxy forwards it after ending TLS.
fn plain_dot(address: SocketAddr, client: [u8; 4], name: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let message = query(9, name, TYPE_A);
    let mut out = proxy_header(client, address);
    out.extend_from_slice(&u16::try_from(message.len()).expect("len").to_be_bytes());
    out.extend_from_slice(&message);
    stream.write_all(&out).expect("write");
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).expect("the length");
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut answer).expect("the answer");
    answer
}

/// Plain HTTP/1.1 on the DoH address, as the proxy forwards it: the status and the body.
fn plain_doh(address: SocketAddr, client: [u8; 4], message: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut out = proxy_header(client, address);
    out.extend_from_slice(
        format!(
            "GET /dns-query?dns={} HTTP/1.1\r\nHost: dns.example.test\r\nAccept: \
             application/dns-message\r\nConnection: close\r\n\r\n",
            base64url(message)
        )
        .as_bytes(),
    );
    stream.write_all(&out).expect("write");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("the answer");
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("the end of the head");
    let head = String::from_utf8_lossy(&response[..split]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("a status");
    (status, response[split + 4..].to_vec())
}

#[test]
fn behind_the_proxy_plain_dns_and_http_answer_with_the_client_address() {
    let began = Instant::now();
    let ports = Ports::new();
    let mut node = Node::new()
        .with_transport(Transport::Plain)
        .with_args(&["--roles", "controller,dns"])
        .with_config(&ports.config(
            "behind_proxy = true\nproxy_protocol = true\n[dns.log]\nenabled = true\n\
             pseudonymise = false\n",
        ));
    let mut server = start(&mut node, &ports);
    let api = zone(&node, &server);

    let deadline = Instant::now() + Duration::from_secs(3);
    let answer = loop {
        let answer = plain_dot(ports.dot, [192, 0, 2, 7], WWW);
        if holds(&answer, [192, 0, 2, 10]) || Instant::now() > deadline {
            break answer;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(header(&answer).rcode, NOERROR);
    assert!(holds(&answer, [192, 0, 2, 10]));
    let (status, body) = plain_doh(ports.doh, [198, 51, 100, 4], &query(0, WWW, TYPE_A));
    assert_eq!(status, 200);
    assert!(holds(&body, [192, 0, 2, 10]));

    // A connection that does not start with the header is closed.
    let mut bare = TcpStream::connect(ports.dot).expect("connect");
    bare.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    bare.write_all(&[0u8; 16]).expect("write");
    let mut byte = [0u8; 1];
    assert!(matches!(bare.read(&mut byte), Ok(0) | Err(_)));

    // The query log has the clients the proxy named.
    let status = api.get("/system/status").expect(200);
    let node_id = status["node"]["id"].as_u64().expect("a node id");
    let deadline = Instant::now() + Duration::from_secs(5);
    let clients = loop {
        let log = api
            .get(&format!("/nodes/{node_id}/dns/log?limit=50&qname=www"))
            .expect(200);
        let clients: Vec<String> = log["items"]
            .as_array()
            .map(|lines| {
                lines
                    .iter()
                    .filter_map(|line| line["client"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let both = ["192.0.2.7", "198.51.100.4"]
            .iter()
            .all(|client| clients.iter().any(|seen| seen == client));
        if both || Instant::now() > deadline {
            break clients;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    for client in ["192.0.2.7", "198.51.100.4"] {
        assert!(clients.iter().any(|seen| seen == client), "{clients:?}");
    }
    server.stop().assert_graceful_shutdown();
    eprintln!(
        "acceptance_dns_tls: reverse-proxy mode in {} s",
        began.elapsed().as_secs()
    );
}
