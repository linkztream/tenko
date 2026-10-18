//! Upstream resolvers of the forwarder (DNS-02, DNS-08, DNS-15, TGL-14).
//!
//! An [`Upstream`] sends one query to one resolver over its transport and returns the
//! answer's octets; the pool ([`crate::pool`]) chooses among the upstreams of a rule, keeps
//! their health and round-trip times and checks the 0x20 case. The resolver never talks to
//! the network itself. Three transports:
//!
//! | Transport | How |
//! |---|---|
//! | [`PlainUpstream`] | UDP from a socket of [`UdpSockets`] (a random port), the same query again over TCP when the answer is truncated; or TCP only |
//! | [`DotUpstream`] | DNS over TLS (RFC 7858): a TLS connection to port 853 with the rule's TLS name, length-prefixed messages; a few idle connections are kept for the next queries, and TLS sessions resume from the client configuration's session store |
//! | [`DohUpstream`] | DNS over HTTPS (RFC 8484): `POST` of `application/dns-message` to the upstream's path (`/dns-query` by default) over one HTTP/2 connection that every query of the upstream shares, opened again when the server closes it or an exchange times out |
//!
//! The certificates of DoT and DoH upstreams are checked against the system's root
//! certificates, or against the CA of `[dns] upstream_ca` alone when it is set
//! ([`TlsClient`]); the name checked is the rule's `tls_name`.

use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use bytes::Bytes;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tenko_core::dns::ForwardTransport;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::{
    outbound::{AnswerCheck, UdpSockets, check_answer},
    wire::{self, MAX_MESSAGE_LEN},
};

/// Why an exchange with an upstream failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamError {
    /// No answer before the deadline.
    #[error("the upstream did not answer in time")]
    Timeout,
    /// The connection or the TLS session failed.
    #[error("the upstream could not be reached: {0}")]
    Unreachable(&'static str),
    /// The answer does not match the query (id, question, 0x20 case) or does not parse.
    #[error("the upstream answer is malformed: {0}")]
    Malformed(&'static str),
}

/// One upstream resolver.
pub trait Upstream: Send + Sync {
    /// The transport.
    fn transport(&self) -> ForwardTransport;

    /// The resolver's address.
    fn address(&self) -> SocketAddr;

    /// Sends `query` and writes the answer into `answer` (replaced) before `deadline`.
    ///
    /// # Errors
    ///
    /// [`UpstreamError`] for a timeout, a failed connection or a malformed answer.
    fn exchange<'a>(
        &'a self,
        query: &'a [u8],
        answer: &'a mut Vec<u8>,
        deadline: Instant,
    ) -> impl Future<Output = Result<(), UpstreamError>> + Send + 'a;
}

/// Idle DoT connections kept per upstream.
pub const DOT_IDLE: usize = 4;

/// The time an idle DoT connection is kept (servers close idle connections after some
/// seconds; a connection closed by the server costs one retry on a new connection).
pub const DOT_IDLE_TIME: Duration = Duration::from_secs(10);

/// The default URL path of a DoH upstream.
pub const DOH_PATH: &str = "/dns-query";

/// The media type of DNS messages over HTTPS.
pub const DNS_MESSAGE: &str = "application/dns-message";

// ---------------------------------------------------------------------------------------
// Plain DNS

/// One upstream resolver over plain DNS: UDP with TCP on truncation, or TCP only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainUpstream {
    /// The resolver's address and port.
    pub address: SocketAddr,
    /// Always TCP (`transport = "tcp"` of the configuration).
    pub tcp_only: bool,
}

impl PlainUpstream {
    /// An upstream reached over UDP, TCP when an answer is truncated.
    pub const fn udp(address: SocketAddr) -> Self {
        Self {
            address,
            tcp_only: false,
        }
    }

    /// An upstream reached over TCP only.
    pub const fn tcp(address: SocketAddr) -> Self {
        Self {
            address,
            tcp_only: true,
        }
    }

    /// Returns whether the answer is truncated.
    async fn over_udp(
        &self,
        query: &[u8],
        answer: &mut Vec<u8>,
        deadline: Instant,
    ) -> Result<bool, UpstreamError> {
        let sockets = UdpSockets::global();
        let pooled = sockets
            .take(self.address)
            .await
            .map_err(|_| UpstreamError::Unreachable("no local UDP socket"))?;
        let socket = pooled.socket();
        socket
            .send_to(query, self.address)
            .await
            .map_err(|_| UpstreamError::Unreachable("the query could not be sent"))?;
        answer.clear();
        answer.resize(MAX_MESSAGE_LEN, 0);
        let deadline = tokio::time::Instant::from_std(deadline);
        loop {
            match tokio::time::timeout_at(deadline, socket.recv_from(answer)).await {
                Err(_) => {
                    answer.clear();
                    return Err(UpstreamError::Timeout);
                }
                // A refused port (ICMP) or a receive error: this upstream does not answer.
                Ok(Err(_)) => {
                    answer.clear();
                    return Err(UpstreamError::Unreachable("the upstream refused the query"));
                }
                Ok(Ok((len, from))) => {
                    if same_address(from, self.address)
                        && check_answer(query, &answer[..len], false) != AnswerCheck::Other
                    {
                        answer.truncate(len);
                        sockets.give(pooled, self.address);
                        let truncated = wire::parse_header(answer).is_some_and(|h| h.tc);
                        return Ok(truncated);
                    }
                    // Not the answer to this query: keep waiting until the deadline.
                }
            }
        }
    }

    async fn over_tcp(
        &self,
        query: &[u8],
        answer: &mut Vec<u8>,
        deadline: Instant,
    ) -> Result<(), UpstreamError> {
        let exchange = async {
            let mut stream = TcpStream::connect(self.address)
                .await
                .map_err(|_| UpstreamError::Unreachable("no TCP connection to the upstream"))?;
            let _ = stream.set_nodelay(true);
            framed_exchange(&mut stream, query, answer).await
        };
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), exchange)
            .await
            .map_err(|_| UpstreamError::Timeout)?
    }
}

/// Whether two socket addresses are the same, an IPv4-mapped IPv6 address being its IPv4
/// address.
fn same_address(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && a.ip().to_canonical() == b.ip().to_canonical()
}

/// One length-prefixed exchange on a stream (RFC 7766, RFC 7858).
async fn framed_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    query: &[u8],
    answer: &mut Vec<u8>,
) -> Result<(), UpstreamError> {
    let len = u16::try_from(query.len())
        .map_err(|_| UpstreamError::Malformed("the query is too long"))?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream
        .write_all(&framed)
        .await
        .map_err(|_| UpstreamError::Unreachable("the query could not be sent"))?;
    stream
        .flush()
        .await
        .map_err(|_| UpstreamError::Unreachable("the query could not be sent"))?;
    let mut prefix = [0u8; 2];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|_| UpstreamError::Unreachable("the connection closed"))?;
    answer.clear();
    answer.resize(usize::from(u16::from_be_bytes(prefix)), 0);
    stream
        .read_exact(answer)
        .await
        .map_err(|_| UpstreamError::Unreachable("the connection closed"))?;
    if check_answer(query, answer, false) == AnswerCheck::Other {
        answer.clear();
        return Err(UpstreamError::Malformed(
            "the answer does not match the query",
        ));
    }
    Ok(())
}

impl Upstream for PlainUpstream {
    fn transport(&self) -> ForwardTransport {
        ForwardTransport::Plain
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    async fn exchange(
        &self,
        query: &[u8],
        answer: &mut Vec<u8>,
        deadline: Instant,
    ) -> Result<(), UpstreamError> {
        if !self.tcp_only && !self.over_udp(query, answer, deadline).await? {
            return Ok(());
        }
        self.over_tcp(query, answer, deadline).await
    }
}

// ---------------------------------------------------------------------------------------
// TLS

/// The TLS client configurations of the DoT and DoH upstreams: aws-lc-rs, TLS 1.2 and 1.3,
/// the system's root certificates or a configured CA, ALPN `dot` and `h2`. The session
/// store of each configuration lets connections to the same upstream resume their session.
#[derive(Debug, Clone)]
pub struct TlsClient {
    dot: Arc<ClientConfig>,
    doh: Arc<ClientConfig>,
}

impl TlsClient {
    /// The configurations with the roots of `ca_pem` (PEM certificates) alone, or the
    /// system's root certificates when it is `None`.
    ///
    /// # Errors
    ///
    /// English text when the CA file holds no certificate, the system has no root
    /// certificate, or no protocol version is usable.
    pub fn new(ca_pem: Option<&[u8]>) -> Result<Self, String> {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let mut roots = RootCertStore::empty();
        if let Some(pem) = ca_pem {
            for cert in CertificateDer::pem_slice_iter(pem) {
                let cert = cert.map_err(|error| format!("the upstream CA: {error}"))?;
                roots
                    .add(cert)
                    .map_err(|error| format!("the upstream CA: {error}"))?;
            }
            if roots.is_empty() {
                return Err("the upstream CA file holds no certificate".to_owned());
            }
        } else {
            let loaded = rustls_native_certs::load_native_certs();
            let _ = roots.add_parsable_certificates(loaded.certs);
            if roots.is_empty() {
                return Err("the system has no root certificates".to_owned());
            }
        }
        let roots = Arc::new(roots);
        let build = |alpn: &[u8]| -> Result<Arc<ClientConfig>, String> {
            let mut config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("no usable TLS protocol version: {error}"))?
            .with_root_certificates(Arc::clone(&roots))
            .with_no_client_auth();
            config.alpn_protocols = vec![alpn.to_vec()];
            Ok(Arc::new(config))
        };
        Ok(Self {
            dot: build(b"dot")?,
            doh: build(b"h2")?,
        })
    }

    /// The configuration of DoT upstreams.
    pub fn dot(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.dot)
    }

    /// The configuration of DoH upstreams.
    pub fn doh(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.doh)
    }
}

/// The name checked in an upstream's certificate.
///
/// # Errors
///
/// English text when the name is neither a DNS name nor an IP address.
pub fn server_name(name: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(name.trim().trim_end_matches('.').to_owned())
        .map_err(|_| format!("`{name}` is not a certificate name"))
}

async fn tls_connect(
    config: Arc<ClientConfig>,
    address: SocketAddr,
    name: ServerName<'static>,
) -> Result<TlsStream<TcpStream>, UpstreamError> {
    let tcp = TcpStream::connect(address)
        .await
        .map_err(|_| UpstreamError::Unreachable("no TCP connection to the upstream"))?;
    let _ = tcp.set_nodelay(true);
    TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .map_err(|_| UpstreamError::Unreachable("the TLS handshake failed"))
}

// ---------------------------------------------------------------------------------------
// DNS over TLS

/// One upstream over DNS over TLS (RFC 7858).
pub struct DotUpstream {
    address: SocketAddr,
    name: ServerName<'static>,
    config: Arc<ClientConfig>,
    idle: Mutex<Vec<(TlsStream<TcpStream>, Instant)>>,
}

impl std::fmt::Debug for DotUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotUpstream")
            .field("address", &self.address)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl DotUpstream {
    /// An upstream at `address` whose certificate names `name`.
    pub fn new(address: SocketAddr, name: ServerName<'static>, tls: &TlsClient) -> Self {
        Self {
            address,
            name,
            config: tls.dot(),
            idle: Mutex::new(Vec::new()),
        }
    }

    fn take_idle(&self) -> Option<TlsStream<TcpStream>> {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some((stream, since)) = idle.pop() {
            if since.elapsed() < DOT_IDLE_TIME {
                return Some(stream);
            }
        }
        None
    }

    fn give(&self, stream: TlsStream<TcpStream>) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() < DOT_IDLE {
            idle.push((stream, Instant::now()));
        }
    }

    /// Idle connections held.
    pub fn idle_connections(&self) -> usize {
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl Upstream for DotUpstream {
    fn transport(&self) -> ForwardTransport {
        ForwardTransport::Dot
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    async fn exchange(
        &self,
        query: &[u8],
        answer: &mut Vec<u8>,
        deadline: Instant,
    ) -> Result<(), UpstreamError> {
        let exchange = async {
            // A connection the server closed while it was idle fails at once: then a new one.
            if let Some(mut stream) = self.take_idle()
                && framed_exchange(&mut stream, query, answer).await.is_ok()
            {
                self.give(stream);
                return Ok(());
            }
            let mut stream =
                tls_connect(Arc::clone(&self.config), self.address, self.name.clone()).await?;
            framed_exchange(&mut stream, query, answer).await?;
            self.give(stream);
            Ok(())
        };
        if let Ok(result) =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), exchange).await
        {
            return result;
        }
        // The idle connections may have gone silent with it (a cut network sends no reset).
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        Err(UpstreamError::Timeout)
    }
}

// ---------------------------------------------------------------------------------------
// DNS over HTTPS

/// One upstream over DNS over HTTPS (RFC 8484), HTTP/2 only.
pub struct DohUpstream {
    address: SocketAddr,
    name: ServerName<'static>,
    uri: String,
    config: Arc<ClientConfig>,
    connection: tokio::sync::Mutex<Option<h2::client::SendRequest<Bytes>>>,
}

impl std::fmt::Debug for DohUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohUpstream")
            .field("address", &self.address)
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}

impl DohUpstream {
    /// An upstream at `address` whose certificate names `name`, queried at `path`
    /// (`/dns-query` when `None`).
    pub fn new(
        address: SocketAddr,
        name: ServerName<'static>,
        path: Option<&str>,
        tls: &TlsClient,
    ) -> Self {
        let host = match &name {
            ServerName::DnsName(dns) => dns.as_ref().to_owned(),
            ServerName::IpAddress(ip) => match std::net::IpAddr::from(*ip) {
                std::net::IpAddr::V4(v4) => v4.to_string(),
                std::net::IpAddr::V6(v6) => format!("[{v6}]"),
            },
            _ => address.ip().to_string(),
        };
        let authority = if address.port() == 443 {
            host
        } else {
            format!("{host}:{}", address.port())
        };
        Self {
            address,
            name,
            uri: format!("https://{authority}{}", path.unwrap_or(DOH_PATH)),
            config: tls.doh(),
            connection: tokio::sync::Mutex::new(None),
        }
    }

    /// The URI queries are posted to.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The shared HTTP/2 connection, opened when there is none or it closed.
    async fn sender(&self, fresh: bool) -> Result<h2::client::SendRequest<Bytes>, UpstreamError> {
        let mut held = self.connection.lock().await;
        if !fresh && let Some(sender) = held.as_ref() {
            return Ok(sender.clone());
        }
        let tls = tls_connect(Arc::clone(&self.config), self.address, self.name.clone()).await?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(UpstreamError::Unreachable(
                "the upstream does not speak HTTP/2",
            ));
        }
        let (sender, connection) = h2::client::handshake(tls)
            .await
            .map_err(|_| UpstreamError::Unreachable("the HTTP/2 handshake failed"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        *held = Some(sender.clone());
        Ok(sender)
    }

    async fn post(
        &self,
        sender: h2::client::SendRequest<Bytes>,
        query: &[u8],
        answer: &mut Vec<u8>,
    ) -> Result<(), PostError> {
        let mut sender = sender.ready().await.map_err(|_| PostError::Connection)?;
        let request = http::Request::post(&self.uri)
            .header(http::header::CONTENT_TYPE, DNS_MESSAGE)
            .header(http::header::ACCEPT, DNS_MESSAGE)
            .header(http::header::CONTENT_LENGTH, query.len())
            .body(())
            .map_err(|_| PostError::Failed(UpstreamError::Malformed("the request")))?;
        let (response, mut body) = sender
            .send_request(request, false)
            .map_err(|_| PostError::Connection)?;
        body.send_data(Bytes::copy_from_slice(query), true)
            .map_err(|_| PostError::Connection)?;
        let response = response.await.map_err(|_| PostError::Connection)?;
        if response.status() != http::StatusCode::OK {
            return Err(PostError::Failed(UpstreamError::Malformed(
                "the upstream answered with an HTTP error",
            )));
        }
        let mut received = response.into_body();
        answer.clear();
        while let Some(chunk) = received.data().await {
            let chunk = chunk.map_err(|_| PostError::Connection)?;
            let _ = received.flow_control().release_capacity(chunk.len());
            if answer.len() + chunk.len() > MAX_MESSAGE_LEN {
                return Err(PostError::Failed(UpstreamError::Malformed(
                    "the answer is too long",
                )));
            }
            answer.extend_from_slice(&chunk);
        }
        if check_answer(query, answer, false) == AnswerCheck::Other {
            answer.clear();
            return Err(PostError::Failed(UpstreamError::Malformed(
                "the answer does not match the query",
            )));
        }
        Ok(())
    }
}

/// Why a DoH request failed: the connection (worth one new connection) or the exchange.
enum PostError {
    Connection,
    Failed(UpstreamError),
}

impl Upstream for DohUpstream {
    fn transport(&self) -> ForwardTransport {
        ForwardTransport::Doh
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    async fn exchange(
        &self,
        query: &[u8],
        answer: &mut Vec<u8>,
        deadline: Instant,
    ) -> Result<(), UpstreamError> {
        let exchange = async {
            let sender = self.sender(false).await?;
            match self.post(sender, query, answer).await {
                Ok(()) => return Ok(()),
                Err(PostError::Failed(error)) => return Err(error),
                Err(PostError::Connection) => {}
            }
            // The shared connection went away (the server closed it): one new connection.
            let sender = self.sender(true).await?;
            match self.post(sender, query, answer).await {
                Ok(()) => Ok(()),
                Err(PostError::Failed(error)) => Err(error),
                Err(PostError::Connection) => {
                    Err(UpstreamError::Unreachable("the HTTP/2 connection failed"))
                }
            }
        };
        if let Ok(result) =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), exchange).await
        {
            return result;
        }
        // A connection that went silent (a cut network sends no reset) would only ever
        // time out: the next query opens a new one.
        *self.connection.lock().await = None;
        Err(UpstreamError::Timeout)
    }
}

// ---------------------------------------------------------------------------------------
// Any transport

/// An upstream of any transport, for a pool that mixes them.
#[derive(Debug)]
pub enum AnyUpstream {
    /// Plain DNS.
    Plain(PlainUpstream),
    /// DNS over TLS.
    Dot(DotUpstream),
    /// DNS over HTTPS.
    Doh(DohUpstream),
}

impl Upstream for AnyUpstream {
    fn transport(&self) -> ForwardTransport {
        match self {
            AnyUpstream::Plain(upstream) => upstream.transport(),
            AnyUpstream::Dot(upstream) => upstream.transport(),
            AnyUpstream::Doh(upstream) => upstream.transport(),
        }
    }

    fn address(&self) -> SocketAddr {
        match self {
            AnyUpstream::Plain(upstream) => upstream.address(),
            AnyUpstream::Dot(upstream) => upstream.address(),
            AnyUpstream::Doh(upstream) => upstream.address(),
        }
    }

    async fn exchange(
        &self,
        query: &[u8],
        answer: &mut Vec<u8>,
        deadline: Instant,
    ) -> Result<(), UpstreamError> {
        match self {
            AnyUpstream::Plain(upstream) => upstream.exchange(query, answer, deadline).await,
            AnyUpstream::Dot(upstream) => upstream.exchange(query, answer, deadline).await,
            AnyUpstream::Doh(upstream) => upstream.exchange(query, answer, deadline).await,
        }
    }
}
