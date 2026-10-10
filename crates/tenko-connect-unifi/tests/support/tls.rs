//! A TLS listener for `axum::serve`: accepts TCP connections, performs the TLS handshake
//! with a fresh self-signed certificate and skips connections whose handshake fails (a
//! client that rejects the certificate, a probe that stops after the handshake).

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use axum::serve::Listener;
use tenko_connect::sdk::http::fingerprint_of;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer},
    },
    server::TlsStream,
};

/// How long a handshake may take before the connection is dropped.
const HANDSHAKE: Duration = Duration::from_secs(5);

/// A TCP listener whose connections are TLS streams.
pub(super) struct TlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
}

/// Wraps `tcp` with a new self-signed certificate for `unifi.example.test`; returns the
/// listener and the certificate's fingerprint (SHA-256, colon-separated upper-case hex).
pub(super) fn listener(tcp: TcpListener) -> (TlsListener, String) {
    let certified = rcgen::generate_simple_self_signed(vec!["unifi.example.test".to_owned()])
        .expect("a self-signed certificate");
    let der = certified.cert.der().to_vec();
    let key = PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![CertificateDer::from(der.clone())], key)
    .expect("a server configuration");
    let fingerprint = fingerprint_of(&der);
    (
        TlsListener {
            tcp,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        },
        fingerprint,
    )
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((stream, addr)) = self.tcp.accept().await else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            };
            if let Ok(Ok(io)) = tokio::time::timeout(HANDSHAKE, self.acceptor.accept(stream)).await
            {
                return (io, addr);
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}
