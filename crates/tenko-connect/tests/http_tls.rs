//! The certificate checks of `sdk::http` against a local TLS server with a test certificate
//! authority: each mode accepts what it should, and each failure names its cause.
#![cfg(feature = "http-client")]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tenko_connect::{
    ConnectorError,
    sdk::http::{Failure, TlsMode, TlsSettings, WebClient, fingerprint_of},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// A test CA and a server certificate for `names`, signed by it.
struct Pki {
    ca_pem: String,
    leaf_der: Vec<u8>,
    config: Arc<rustls::ServerConfig>,
}

fn make_pki(ca_name: &str, names: &[&str]) -> Pki {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, ca_name);
    let ca_key = rcgen::KeyPair::generate().expect("key");
    let issuer = rcgen::CertifiedIssuer::self_signed(params, ca_key).expect("CA");
    let key = rcgen::KeyPair::generate().expect("key");
    let leaf =
        rcgen::CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
            .expect("params")
            .signed_by(&key, &issuer)
            .expect("leaf");
    let leaf_der = leaf.der().to_vec();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(leaf_der.clone())],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .expect("server config");
    Pki {
        ca_pem: issuer.as_ref().pem(),
        leaf_der,
        config: Arc::new(config),
    }
}

/// Serves `{}` over TLS (or plain HTTP without a config) on a loopback port.
async fn serve(config: Option<Arc<rustls::ServerConfig>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let config = config.clone();
            tokio::spawn(async move {
                match config {
                    Some(config) => {
                        let acceptor = tokio_rustls::TlsAcceptor::from(config);
                        if let Ok(stream) = acceptor.accept(stream).await {
                            answer(stream).await;
                        }
                    }
                    None => answer(stream).await,
                }
            });
        }
    });
    addr
}

async fn answer<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut stream: S) {
    let mut buffer = vec![0u8; 4096];
    let mut seen = Vec::new();
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(n) => seen.extend_from_slice(&buffer[..n]),
        }
        // Like a real HTTP server, answer a TLS hello (or other garbage) with an error.
        if !seen[0].is_ascii_uppercase() {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = stream.shutdown().await;
            return;
        }
    }
    let _ = stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
        .await;
    let _ = stream.shutdown().await;
}

fn client(url: &str, tls: &TlsSettings) -> WebClient {
    WebClient::new(url, tls, Duration::from_secs(5), "tenko-test").expect("client")
}

fn settings(mode: TlsMode) -> TlsSettings {
    TlsSettings {
        mode,
        ..TlsSettings::default()
    }
}

/// The failure of a GET of `/`, or `None` when it answered 200.
async fn fetch(client: &WebClient) -> Option<Failure> {
    match client.get("/").send().await {
        Ok(response) => {
            assert_eq!(response.status(), 200);
            None
        }
        Err(error) => Some(client.failure(&error)),
    }
}

fn tls_text(failure: Option<Failure>) -> String {
    match failure {
        Some(Failure::Tls(text)) => text,
        other => panic!("expected a TLS failure, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unknown_issuer_is_named_and_maps_to_invalid_settings() {
    let pki = make_pki("Tenko test CA", &["127.0.0.1"]);
    let addr = serve(Some(pki.config.clone())).await;
    let client = client(&format!("https://{addr}"), &settings(TlsMode::System));
    let error = client.get("/").send().await.expect_err("untrusted");
    let failure = client.failure(&error);
    assert!(
        matches!(&failure, Failure::Tls(text) if text.contains("unknown issuer")),
        "{failure:?}"
    );
    assert!(matches!(
        client.error(&error),
        ConnectorError::InvalidSettings(text) if text.starts_with("TLS: ")
    ));
    assert_eq!(
        client.presented_fingerprint().await.as_deref(),
        Some(fingerprint_of(&pki.leaf_der).as_str())
    );
}

#[tokio::test]
async fn a_pinned_ca_checks_the_host_name_through_a_connect_address() {
    let pki = make_pki("Tenko test CA", &["pve.example.test"]);
    let addr = serve(Some(pki.config.clone())).await;
    let ca = |connect: Option<String>| TlsSettings {
        mode: TlsMode::Ca,
        ca: Some(pki.ca_pem.replace('\n', " ")),
        connect_address: connect,
        ..TlsSettings::default()
    };
    // The certificate names pve.example.test; connecting to that name at 127.0.0.1 works.
    let named = client(
        &format!("https://pve.example.test:{}", addr.port()),
        &ca(Some("127.0.0.1".to_owned())),
    );
    assert_eq!(fetch(&named).await, None);
    assert!(named.notes().iter().any(|note| note.contains("127.0.0.1")));
    // The same certificate at the IP address does not name the host of the URL.
    let by_ip = client(&format!("https://{addr}"), &ca(None));
    let text = tls_text(fetch(&by_ip).await);
    assert!(text.contains("does not name the host"), "{text}");
    // Another CA does not sign it.
    let other = make_pki("Another test CA", &["pve.example.test"]);
    let wrong_ca = client(
        &format!("https://pve.example.test:{}", addr.port()),
        &TlsSettings {
            mode: TlsMode::Ca,
            ca: Some(other.ca_pem),
            connect_address: Some("127.0.0.1".to_owned()),
            ..TlsSettings::default()
        },
    );
    let text = tls_text(fetch(&wrong_ca).await);
    assert!(text.contains("unknown issuer"), "{text}");
}

#[tokio::test]
async fn a_pinned_fingerprint_accepts_only_that_certificate() {
    let pki = make_pki("Tenko test CA", &["pve.example.test"]);
    let addr = serve(Some(pki.config.clone())).await;
    let pinned = |fingerprint: String| TlsSettings {
        mode: TlsMode::Fingerprint,
        fingerprint: Some(fingerprint),
        ..TlsSettings::default()
    };
    let right = client(
        &format!("https://{addr}"),
        &pinned(fingerprint_of(&pki.leaf_der).to_ascii_lowercase()),
    );
    assert_eq!(fetch(&right).await, None);
    assert!(right.notes()[0].contains("fingerprint"));
    let wrong = client(
        &format!("https://{addr}"),
        &pinned(fingerprint_of(b"another certificate")),
    );
    let text = tls_text(fetch(&wrong).await);
    assert!(
        text.contains("does not match the pinned fingerprint"),
        "{text}"
    );
}

#[tokio::test]
async fn insecure_accepts_anything_and_says_so() {
    let pki = make_pki("Tenko test CA", &["pve.example.test"]);
    let addr = serve(Some(pki.config.clone())).await;
    let client = client(&format!("https://{addr}"), &settings(TlsMode::Insecure));
    assert_eq!(fetch(&client).await, None);
    assert!(client.notes()[0].contains("certificate checks are off"));
}

#[tokio::test]
async fn plain_http_on_an_https_url_and_a_closed_port_are_told_apart() {
    let addr = serve(None).await;
    let client_tls = client(&format!("https://{addr}"), &settings(TlsMode::System));
    let text = tls_text(fetch(&client_tls).await);
    assert!(text.contains("does not speak TLS"), "{text}");
    assert_eq!(client_tls.presented_fingerprint().await, None);
    let plain = client(&format!("http://{addr}"), &settings(TlsMode::System));
    assert_eq!(fetch(&plain).await, None);
    let closed = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = closed.local_addr().expect("addr").port();
    drop(closed);
    let refused = client(
        &format!("http://127.0.0.1:{port}"),
        &settings(TlsMode::System),
    );
    assert_eq!(fetch(&refused).await, Some(Failure::Connect));
    assert_eq!(
        fetch(&refused).await.map(Failure::into_error),
        Some(ConnectorError::Unreachable)
    );
}
