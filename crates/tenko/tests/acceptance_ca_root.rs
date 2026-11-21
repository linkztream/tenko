//! `GET /api/v1/system/ca-root` at the HTTP level against the real binary (OPS-22, mode
//! a): the gaps `serve_ca_root.rs` (the `tenko ca-root` command) leaves. In internal CA
//! mode the route is public, answers the PEM of `<data_dir>/tls/ca-root.pem` with its media
//! type, a one-hour public cache and a download name, before and after setup, and the
//! setup answer carries the fingerprint the server printed, and the listener presents its
//! certificate followed by that root over TLS 1.2 and 1.3. In the reverse-proxy mode it
//! answers 404 `tls.no_internal_ca` as problem details.

mod serve_support;

use std::{fs, net::TcpStream, sync::Arc};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, SupportedProtocolVersion,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use serve_support::{Node, READY_TIMEOUT, Transport, api::Api, wait_for_setup_token};
use tenko_cluster::ca::CertInfo;

const FINGERPRINT_LINE: &str = "SHA-256 fingerprint: ";

#[test]
fn the_internal_ca_root_is_public_and_equals_the_data_directory_file() {
    let mut node = Node::new().with_transport(Transport::InternalCa);
    let mut server = node.start();
    let printed = server
        .wait_stdout_line(READY_TIMEOUT, |line| line.contains(FINGERPRINT_LINE))
        .unwrap_or_else(|| panic!("no fingerprint line\n{}", server.diagnostics()));
    let printed = printed
        .trim()
        .trim_start_matches(FINGERPRINT_LINE)
        .to_owned();
    let on_disk = fs::read_to_string(node.ca_file().expect("internal CA mode"))
        .expect("the server writes the CA root");
    assert!(
        on_disk.starts_with("-----BEGIN CERTIFICATE-----"),
        "{on_disk}"
    );

    let mut api = Api::new(&node);
    let check = |api: &Api| {
        let reply = api.get("/system/ca-root");
        assert_eq!(reply.status, 200, "{}", reply.text);
        assert_eq!(reply.text, on_disk);
        assert_eq!(
            reply.header("content-type").as_deref(),
            Some("application/x-pem-file")
        );
        assert_eq!(
            reply.header("cache-control").as_deref(),
            Some("public, max-age=3600")
        );
        assert!(
            reply
                .header("content-disposition")
                .is_some_and(|value| value.contains("tenko-ca-root.pem")),
            "{:?}",
            reply.headers
        );
    };
    // Before setup, without a session.
    check(&api);

    // The handshake shows the certificate and then the root the route serves; a client that
    // trusts only that root verifies the chain.
    let root = CertificateDer::from_pem_slice(api.get("/system/ca-root").text.as_bytes())
        .expect("the root");
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let chain = presented(node.port, &root, version);
        assert_eq!(chain.len(), 2, "{:?}", version.version);
        assert_eq!(chain[1], root, "{:?}", version.version);
        let info = CertInfo::from_der(&chain[1]).expect("the second certificate");
        assert!(info.is_ca && info.subject == info.issuer, "{info:?}");
    }

    // Setup answers the same fingerprint the server printed (it is what the wizard shows).
    let token = wait_for_setup_token(&server);
    let answer = api.setup(&token);
    let fingerprint = answer["ca_fingerprint"]
        .as_str()
        .unwrap_or_else(|| panic!("no ca_fingerprint in the setup answer: {answer}"));
    let hex = |text: &str| -> String {
        text.chars()
            .filter(char::is_ascii_hexdigit)
            .collect::<String>()
            .to_ascii_uppercase()
    };
    assert_eq!(hex(fingerprint), hex(&printed));

    // After setup, with a session and without one: unchanged.
    check(&api);
    check(&api.anonymous());
    server.stop().assert_graceful_shutdown();
}

/// The certificates the listener on `port` presents over `version` to a client that trusts
/// only `root`; the handshake fails unless the chain verifies to it.
fn presented(
    port: u16,
    root: &CertificateDer<'static>,
    version: &'static SupportedProtocolVersion,
) -> Vec<CertificateDer<'static>> {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).expect("the root");
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[version])
    .expect("the version")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = ServerName::try_from("localhost").expect("a name");
    let mut connection = ClientConnection::new(Arc::new(config), name).expect("a client");
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    tcp.set_read_timeout(Some(READY_TIMEOUT)).expect("timeout");
    while connection.is_handshaking() {
        connection.complete_io(&mut tcp).expect("the handshake");
    }
    assert_eq!(connection.protocol_version(), Some(version.version));
    connection.peer_certificates().expect("a chain").to_vec()
}

#[test]
fn the_reverse_proxy_mode_has_no_internal_ca_root() {
    let mut node = Node::new();
    let mut server = node.start();
    let mut api = Api::new(&node);
    let reply = api.get("/system/ca-root");
    assert_eq!(reply.status, 404, "{}", reply.text);
    assert_eq!(reply.code().as_deref(), Some("tls.no_internal_ca"));
    assert!(
        reply
            .header("content-type")
            .is_some_and(|value| value.starts_with("application/problem+json")),
        "{:?}",
        reply.headers
    );
    assert!(!node.data_dir().join("tls").join("ca-root.pem").exists());

    // Setup answers no fingerprint in this mode.
    let token = wait_for_setup_token(&server);
    let answer = api.setup(&token);
    assert!(answer.get("ca_fingerprint").is_none(), "{answer}");
    assert_eq!(api.get("/system/ca-root").status, 404);
    server.stop().assert_graceful_shutdown();
}
