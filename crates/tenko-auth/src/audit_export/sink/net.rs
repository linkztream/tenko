//! Syslog over UDP, TCP and TLS.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket, lookup_host},
    time::{Instant, timeout, timeout_at},
};
use tokio_rustls::{TlsConnector, client::TlsStream};

use super::{MAX_DATAGRAM, Timeouts, Transport};
use crate::audit_export::{
    error::{FailureKind, SinkError},
    format::syslog::frame,
    model::{SyslogTarget, TlsOptions},
};

/// Resolves the receiver; the deadline covers the lookup.
async fn resolve(target: &SyslogTarget, deadline: Instant) -> Result<Vec<SocketAddr>, SinkError> {
    let port = target.port();
    let failure = |why: &str| {
        SinkError::new(
            FailureKind::Resolve,
            format!("{} port {port} did not resolve: {why}", target.host),
        )
    };
    let found = timeout_at(deadline, lookup_host((target.host.as_str(), port)))
        .await
        .map_err(|_| failure("timed out"))?
        .map_err(|error| failure(&error.to_string()))?;
    let addresses: Vec<SocketAddr> = found.collect();
    if addresses.is_empty() {
        return Err(failure("no address"));
    }
    Ok(addresses)
}

/// Syslog over UDP (RFC 5426).
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
    write: Duration,
}

impl UdpTransport {
    /// Resolves the receiver and connects a UDP socket to it.
    ///
    /// # Errors
    ///
    /// [`SinkError`] on resolution or socket failure.
    pub async fn connect(target: &SyslogTarget, timeouts: Timeouts) -> Result<Self, SinkError> {
        let deadline = Instant::now() + timeouts.connect;
        let addresses = resolve(target, deadline).await?;
        let address = addresses[0];
        let local: SocketAddr = match address {
            SocketAddr::V4(_) => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).into(),
            SocketAddr::V6(_) => (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).into(),
        };
        let failure = |error: std::io::Error| {
            SinkError::new(
                FailureKind::Connect,
                format!("UDP socket for {address} failed: {error}"),
            )
        };
        let socket = UdpSocket::bind(local).await.map_err(failure)?;
        socket.connect(address).await.map_err(failure)?;
        Ok(Self {
            socket,
            write: timeouts.write,
        })
    }
}

/// The longest prefix of `message` of at most `limit` bytes that ends at a character
/// boundary.
fn cut(message: &[u8], limit: usize) -> &[u8] {
    if message.len() <= limit {
        return message;
    }
    let mut end = limit;
    // A UTF-8 continuation byte is 0b10xxxxxx; step back to the start of the character.
    while end > 0 && message[end] & 0xC0 == 0x80 {
        end -= 1;
    }
    &message[..end]
}

#[async_trait::async_trait]
impl Transport for UdpTransport {
    async fn send(&mut self, messages: &[Vec<u8>]) -> Result<(), SinkError> {
        for message in messages {
            let datagram = cut(message, MAX_DATAGRAM);
            match timeout(self.write, self.socket.send(datagram)).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    return Err(SinkError::new(
                        FailureKind::Send,
                        format!("sending a datagram failed: {error}"),
                    ));
                }
                Err(_) => {
                    return Err(SinkError::new(
                        FailureKind::Send,
                        "sending a datagram timed out",
                    ));
                }
            }
        }
        Ok(())
    }
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Stream {
    async fn write_all_flush(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => {
                stream.write_all(bytes).await?;
                stream.flush().await
            }
            Self::Tls(stream) => {
                stream.write_all(bytes).await?;
                stream.flush().await
            }
        }
    }
}

/// Syslog over TCP (RFC 6587 octet counting) or TLS (RFC 5425).
pub struct TcpTransport {
    stream: Stream,
    write: Duration,
}

impl fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpTransport")
            .field("tls", &matches!(self.stream, Stream::Tls(_)))
            .field("write", &self.write)
            .finish()
    }
}

impl TcpTransport {
    /// Connects, and with `tls` runs the TLS handshake.
    ///
    /// # Errors
    ///
    /// [`SinkError`] on resolution, connection or TLS failure.
    pub async fn connect(
        target: &SyslogTarget,
        tls: Option<Arc<rustls::ClientConfig>>,
        timeouts: Timeouts,
    ) -> Result<Self, SinkError> {
        let deadline = Instant::now() + timeouts.connect;
        let addresses = resolve(target, deadline).await?;
        let tcp = connect_any(&addresses, deadline).await?;
        let _ = tcp.set_nodelay(true);
        let stream = match tls {
            None => Stream::Plain(tcp),
            Some(config) => {
                let name = target.tls.server_name.as_deref().unwrap_or(&target.host);
                let server_name = ServerName::try_from(name.to_owned()).map_err(|_| {
                    SinkError::new(
                        FailureKind::Tls,
                        format!("{name} is not a valid TLS server name"),
                    )
                })?;
                let handshake = TlsConnector::from(config).connect(server_name, tcp);
                let stream = timeout_at(deadline, handshake)
                    .await
                    .map_err(|_| SinkError::new(FailureKind::Tls, "the TLS handshake timed out"))?
                    .map_err(|error| {
                        SinkError::new(
                            FailureKind::Tls,
                            format!("the TLS handshake with {name} failed: {error}"),
                        )
                    })?;
                Stream::Tls(Box::new(stream))
            }
        };
        Ok(Self {
            stream,
            write: timeouts.write,
        })
    }
}

/// Tries the addresses in order; the deadline covers all of them.
async fn connect_any(addresses: &[SocketAddr], deadline: Instant) -> Result<TcpStream, SinkError> {
    let mut last = String::from("no address");
    for address in addresses {
        match timeout_at(deadline, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last = format!("{address}: {error}"),
            Err(_) => {
                last = format!("{address}: timed out");
                break;
            }
        }
    }
    Err(SinkError::new(
        FailureKind::Connect,
        format!("the connection failed ({last})"),
    ))
}

#[async_trait::async_trait]
impl Transport for TcpTransport {
    async fn send(&mut self, messages: &[Vec<u8>]) -> Result<(), SinkError> {
        let mut bytes = Vec::new();
        for message in messages {
            bytes.extend_from_slice(&frame(message));
        }
        match timeout(self.write, self.stream.write_all_flush(&bytes)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(SinkError::new(
                FailureKind::Send,
                format!("writing to the connection failed: {error}"),
            )),
            Err(_) => Err(SinkError::new(
                FailureKind::Send,
                "writing to the connection timed out",
            )),
        }
    }
}

/// The TLS client configuration of a sink.
///
/// # Errors
///
/// [`SinkError`] with [`FailureKind::Tls`] or [`FailureKind::ClientKey`].
pub fn client_config(
    tls: &TlsOptions,
    client_key_pem: Option<&[u8]>,
) -> Result<Arc<rustls::ClientConfig>, SinkError> {
    let tls_error = |detail: String| SinkError::new(FailureKind::Tls, detail);
    let mut roots = RootCertStore::empty();
    if let Some(ca_pem) = &tls.ca_pem {
        let mut count = 0_usize;
        for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            let cert = cert.map_err(|error| tls_error(format!("ca_pem is not valid: {error}")))?;
            roots
                .add(cert)
                .map_err(|error| tls_error(format!("ca_pem holds a bad certificate: {error}")))?;
            count += 1;
        }
        if count == 0 {
            return Err(tls_error("ca_pem holds no certificate".to_owned()));
        }
    } else {
        let loaded = rustls_native_certs::load_native_certs();
        let (_added, _ignored) = roots.add_parsable_certificates(loaded.certs);
        if roots.is_empty() {
            return Err(tls_error("no system root certificates".to_owned()));
        }
    }

    let builder = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| tls_error(format!("no usable TLS protocol version: {error}")))?
    .with_root_certificates(roots);

    let config = if let Some(cert_pem) = &tls.client_cert_pem {
        let chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| tls_error(format!("client_cert_pem is not valid: {error}")))?;
        if chain.is_empty() {
            return Err(tls_error("client_cert_pem holds no certificate".to_owned()));
        }
        let pem = client_key_pem
            .ok_or_else(|| SinkError::new(FailureKind::ClientKey, "the client key is missing"))?;
        let key = PrivateKeyDer::from_pem_slice(pem).map_err(|_| {
            SinkError::new(
                FailureKind::ClientKey,
                "the client key is not a PEM private key",
            )
        })?;
        builder.with_client_auth_cert(chain, key).map_err(|error| {
            SinkError::new(
                FailureKind::ClientKey,
                format!("the client key does not fit the client certificate: {error}"),
            )
        })?
    } else {
        builder.with_no_client_auth()
    };
    Ok(Arc::new(config))
}

#[cfg(test)]
pub(crate) mod tests {
    use tokio::{
        io::{AsyncReadExt, BufReader},
        net::TcpListener,
    };
    use tokio_rustls::TlsAcceptor;

    use super::*;

    fn timeouts() -> Timeouts {
        Timeouts {
            connect: Duration::from_secs(5),
            write: Duration::from_secs(5),
        }
    }

    fn target(transport: crate::audit_export::model::SyslogTransport, port: u16) -> SyslogTarget {
        SyslogTarget {
            transport,
            host: "127.0.0.1".to_owned(),
            port: Some(port),
            facility: crate::audit_export::model::Facility::default(),
            tls: TlsOptions::default(),
        }
    }

    use crate::audit_export::model::SyslogTransport;

    /// Reads `count` octet-counted frames.
    async fn read_frames<R: tokio::io::AsyncRead + Unpin>(reader: R, count: usize) -> Vec<String> {
        let mut reader = BufReader::new(reader);
        let mut out = Vec::new();
        for _ in 0..count {
            let mut len = 0_usize;
            loop {
                let byte = reader.read_u8().await.expect("length byte");
                if byte == b' ' {
                    break;
                }
                len = len * 10 + usize::from(byte - b'0');
            }
            let mut body = vec![0_u8; len];
            reader.read_exact(&mut body).await.expect("body");
            out.push(String::from_utf8(body).expect("utf8"));
        }
        out
    }

    fn messages() -> Vec<Vec<u8>> {
        vec![
            b"<14>1 first".to_vec(),
            "<14>1 second \u{e5}".as_bytes().to_vec(),
        ]
    }

    fn expected() -> Vec<String> {
        vec!["<14>1 first".to_owned(), "<14>1 second \u{e5}".to_owned()]
    }

    #[tokio::test]
    async fn udp_delivers_messages_in_order() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = receiver.local_addr().expect("addr").port();
        let mut transport = UdpTransport::connect(&target(SyslogTransport::Udp, port), timeouts())
            .await
            .expect("connect");
        transport.send(&messages()).await.expect("send");
        let mut buffer = vec![0_u8; 70_000];
        for want in expected() {
            let (n, _) = receiver.recv_from(&mut buffer).await.expect("recv");
            assert_eq!(String::from_utf8_lossy(&buffer[..n]), want);
        }
    }

    #[tokio::test]
    async fn udp_cuts_long_messages_at_a_character_boundary() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = receiver.local_addr().expect("addr").port();
        let mut transport = UdpTransport::connect(&target(SyslogTransport::Udp, port), timeouts())
            .await
            .expect("connect");
        // One ASCII byte, then three-byte characters: the limit falls inside one.
        let mut text = String::from("a");
        while text.len() < MAX_DATAGRAM + 10 {
            text.push('\u{20ac}');
        }
        transport
            .send(&[text.clone().into_bytes()])
            .await
            .expect("send");
        let mut buffer = vec![0_u8; 70_000];
        let (n, _) = receiver.recv_from(&mut buffer).await.expect("recv");
        assert!(n <= MAX_DATAGRAM);
        assert!(n > MAX_DATAGRAM - 4);
        let got = std::str::from_utf8(&buffer[..n]).expect("valid UTF-8");
        assert!(text.starts_with(got));
    }

    #[tokio::test]
    async fn tcp_frames_messages_with_octet_counting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            read_frames(stream, 2).await
        });
        let mut transport =
            TcpTransport::connect(&target(SyslogTransport::Tcp, port), None, timeouts())
                .await
                .expect("connect");
        transport.send(&messages()).await.expect("send");
        assert_eq!(server.await.expect("server"), expected());
    }

    #[tokio::test]
    async fn tcp_without_listener_fails_to_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let error = TcpTransport::connect(&target(SyslogTransport::Tcp, port), None, timeouts())
            .await
            .expect_err("refused");
        assert_eq!(error.kind, FailureKind::Connect);
    }

    pub(crate) struct Pki {
        pub(crate) ca_pem: String,
        issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    }

    pub(crate) fn make_ca(name: &str) -> Pki {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let key = rcgen::KeyPair::generate().expect("key");
        let issuer = rcgen::CertifiedIssuer::self_signed(params, key).expect("CA");
        Pki {
            ca_pem: issuer.as_ref().pem(),
            issuer,
        }
    }

    /// A leaf certificate for `names` as (certificate PEM, key PEM).
    pub(crate) fn make_leaf(pki: &Pki, names: &[&str]) -> (String, String) {
        let key = rcgen::KeyPair::generate().expect("key");
        let leaf = rcgen::CertificateParams::new(
            names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>(),
        )
        .expect("params")
        .signed_by(&key, &pki.issuer)
        .expect("leaf");
        (leaf.pem(), key.serialize_pem())
    }

    pub(crate) fn server_config(pki: &Pki, require_client: bool) -> Arc<rustls::ServerConfig> {
        let (cert_pem, key_pem) = make_leaf(pki, &["siem.example.test", "127.0.0.1"]);
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("versions");
        let builder = if require_client {
            let mut roots = RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(pki.ca_pem.as_bytes()) {
                roots.add(cert.expect("pem")).expect("root");
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .expect("verifier");
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        let chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("chain");
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("key");
        Arc::new(builder.with_single_cert(chain, key).expect("server config"))
    }

    /// Serves one TLS connection and returns the frames it received (empty when the
    /// handshake failed).
    async fn serve_tls(
        config: Arc<rustls::ServerConfig>,
        count: usize,
    ) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            match TlsAcceptor::from(config).accept(stream).await {
                Ok(stream) => read_frames(stream, count).await,
                Err(_) => Vec::new(),
            }
        });
        (port, handle)
    }

    fn tls_target(port: u16, ca_pem: &str) -> SyslogTarget {
        let mut target = target(SyslogTransport::Tls, port);
        target.tls.ca_pem = Some(ca_pem.to_owned());
        target.tls.server_name = Some("siem.example.test".to_owned());
        target
    }

    #[tokio::test]
    async fn tls_delivers_frames() {
        let pki = make_ca("Test CA");
        let (port, server) = serve_tls(server_config(&pki, false), 2).await;
        let target = tls_target(port, &pki.ca_pem);
        let config = client_config(&target.tls, None).expect("config");
        let mut transport = TcpTransport::connect(&target, Some(config), timeouts())
            .await
            .expect("connect");
        transport.send(&messages()).await.expect("send");
        assert_eq!(server.await.expect("server"), expected());
    }

    #[tokio::test]
    async fn tls_with_another_ca_fails() {
        let pki = make_ca("Test CA");
        let other = make_ca("Other CA");
        let (port, server) = serve_tls(server_config(&pki, false), 1).await;
        let target = tls_target(port, &other.ca_pem);
        let config = client_config(&target.tls, None).expect("config");
        let error = TcpTransport::connect(&target, Some(config), timeouts())
            .await
            .expect_err("untrusted");
        assert_eq!(error.kind, FailureKind::Tls);
        let _ = server.await;
    }

    #[tokio::test]
    async fn tls_client_certificate_is_presented() {
        let pki = make_ca("Test CA");
        let (client_cert, client_key) = make_leaf(&pki, &["client.example.test"]);
        let (port, server) = serve_tls(server_config(&pki, true), 2).await;
        let mut target = tls_target(port, &pki.ca_pem);
        target.tls.client_cert_pem = Some(client_cert);
        let config = client_config(&target.tls, Some(client_key.as_bytes())).expect("config");
        let mut transport = TcpTransport::connect(&target, Some(config), timeouts())
            .await
            .expect("connect");
        transport.send(&messages()).await.expect("send");
        assert_eq!(server.await.expect("server"), expected());
    }

    #[test]
    fn client_key_problems() {
        let pki = make_ca("Test CA");
        let (client_cert, client_key) = make_leaf(&pki, &["client.example.test"]);
        let mut tls = TlsOptions {
            ca_pem: Some(pki.ca_pem.clone()),
            client_cert_pem: Some(client_cert),
            ..TlsOptions::default()
        };
        let garbage = client_config(&tls, Some(b"not a key".as_slice())).expect_err("garbage");
        assert_eq!(garbage.kind, FailureKind::ClientKey);
        let missing = client_config(&tls, None).expect_err("missing");
        assert_eq!(missing.kind, FailureKind::ClientKey);
        // A key of another certificate does not fit.
        let (_, other_key) = make_leaf(&pki, &["other.example.test"]);
        let mismatch = client_config(&tls, Some(other_key.as_bytes()));
        assert_eq!(mismatch.expect_err("mismatch").kind, FailureKind::ClientKey);
        assert!(!garbage.detail.contains("not a key"));
        // A broken certificate PEM is a TLS problem.
        tls.client_cert_pem =
            Some("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n".to_owned());
        let broken = client_config(&tls, Some(client_key.as_bytes())).expect_err("broken");
        assert_eq!(broken.kind, FailureKind::Tls);
    }

    #[test]
    fn ca_pem_without_certificate_is_rejected() {
        let tls = TlsOptions {
            ca_pem: Some("nothing here".to_owned()),
            ..TlsOptions::default()
        };
        let error = client_config(&tls, None).expect_err("no certificate");
        assert_eq!(error.kind, FailureKind::Tls);
        assert!(error.detail.contains("ca_pem"));
    }
}
