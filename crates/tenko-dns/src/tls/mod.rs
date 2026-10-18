//! DNS over TLS (RFC 7858) and DNS over HTTPS (RFC 8484) served to clients (DNS-14,
//! plan section 2.2, WP5.3).
//!
//! Both transports run on the tokio runtime beside TCP and call the same
//! [`Responder`](crate::respond::Responder) with the same cookie secret and metrics; only the
//! framing differs:
//!
//! - [`dot`]: the length-prefixed messages of RFC 7766 inside TLS, pipelined and answered in
//!   order, with an idle timeout; ALPN `dot`.
//! - [`doh`]: `GET /dns-query?dns=<base64url>` and `POST /dns-query` with
//!   `application/dns-message` over HTTP/2 and HTTP/1.1; ALPN `h2` and `http/1.1`. One DNS
//!   message in, one out; the answer's smallest TTL is its `max-age`.
//!
//! # TLS material
//!
//! A listener terminates TLS with a certificate resolver it is given
//! ([`Hooks::certificates`](crate::server::Hooks::certificates)): in `tenko serve` the
//! resolver of the API's TLS service (the internal CA's certificate, or the imported files
//! with their watcher), or of a service of its own for a separate DNS certificate. The
//! resolver swaps its certificate in place, so a renewal or a reload reaches the next
//! handshake while the listener keeps running and open connections finish on the
//! certificate they started with. TLS 1.3 is preferred and 1.2 allowed unless
//! [`Termination::Tls::tls13_only`]; TLS 1.3 sessions resume with tickets; there is no
//! early data and no client authentication.
//!
//! Behind a reverse proxy ([`Termination::Proxy`]) the proxy ends TLS: the DoT addresses
//! then take plain length-prefixed DNS (`HAProxy` in TCP mode), the DoH addresses plain HTTP
//! (`HAProxy` as HTTPS), only from the trusted proxies. The client address comes from a
//! PROXY protocol version 2 header when `proxy_protocol` is set, else, for DoH, from the
//! last `X-Forwarded-For` entry, else it is the proxy's.
//!
//! # Limits
//!
//! Each transport has its own count of open connections, apart from TCP's: at most
//! [`TlsListen::max_connections`] per node and [`TlsListen::per_client`] per client address
//! (behind a proxy only the node cap applies, every connection comes from the proxy). A
//! connection over a cap, or from an address that is not a trusted proxy, is closed at once
//! and counted as refused. The TLS handshake and the PROXY header have
//! [`TlsListen::handshake_timeout`]; a failed or late one is counted. A connection is
//! closed after [`TlsListen::idle`] without a query, and an HTTP/2 connection carries at
//! most [`TlsListen::doh_streams`] requests at a time.

pub mod doh;
mod dot;
pub mod proxy;

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use ipnet::IpNet;
use rustls::server::ResolvesServerCert;
use tenko_core::{
    dns::QueryTransport,
    metrics::{CounterVec, Desc, GaugeVec, Registry},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{
    resolver::Resolver,
    respond::{Conn, Responder},
    transport::tcp::{self, Limits, Permit, TcpSettings},
};

/// The default port of DNS over TLS (RFC 7858).
pub const DOT_PORT: u16 = 853;

/// The default port of DNS over HTTPS.
pub const DOH_PORT: u16 = 443;

/// How the encrypted listeners get their TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Termination {
    /// The listeners end TLS with the certificate resolver of
    /// [`Hooks::certificates`](crate::server::Hooks::certificates).
    Tls {
        /// Refuse TLS 1.2 (the Hardened profile, `[tls] tls13_only`).
        tls13_only: bool,
    },
    /// A reverse proxy ends TLS: plain DNS and plain HTTP from the trusted proxies only.
    Proxy {
        /// The addresses or networks of the proxies; every other source is refused.
        trusted: Vec<IpNet>,
        /// Every connection starts with a PROXY protocol version 2 header.
        proxy_protocol: bool,
    },
}

/// The settings of the DoT and DoH listeners; the `[dns.tls]` keys map onto them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsListen {
    /// The DoT addresses; empty serves no DoT.
    pub dot: Vec<SocketAddr>,
    /// The DoH addresses; empty serves no DoH.
    pub doh: Vec<SocketAddr>,
    /// Who ends TLS.
    pub termination: Termination,
    /// Open connections per node and transport.
    pub max_connections: usize,
    /// Open connections per client address and transport (not behind a proxy).
    pub per_client: usize,
    /// Time without a query before a connection is closed.
    pub idle: Duration,
    /// Time for the TLS handshake and the PROXY header.
    pub handshake_timeout: Duration,
    /// Concurrent requests per HTTP/2 connection.
    pub doh_streams: u32,
}

impl Default for TlsListen {
    fn default() -> Self {
        Self {
            dot: Vec::new(),
            doh: Vec::new(),
            termination: Termination::Tls { tls13_only: false },
            max_connections: 1000,
            per_client: 10,
            idle: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(5),
            doh_streams: 100,
        }
    }
}

/// The encrypted listeners of a running server, as the worker layout shows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsLayout {
    /// Whether a reverse proxy ends TLS (the listeners speak plain DNS and HTTP).
    pub behind_proxy: bool,
    /// The DoT listeners.
    pub dot: Vec<SocketAddr>,
    /// Open DoT connections.
    pub dot_open: usize,
    /// DoT connections refused: over a cap, or not from a trusted proxy.
    pub dot_refused: u64,
    /// DoT handshakes (TLS or PROXY header) that failed or ran out of time.
    pub dot_handshake_failures: u64,
    /// The DoH listeners.
    pub doh: Vec<SocketAddr>,
    /// Open DoH connections.
    pub doh_open: usize,
    /// DoH connections refused.
    pub doh_refused: u64,
    /// DoH handshakes that failed or ran out of time.
    pub doh_handshake_failures: u64,
}

/// Open connections of the encrypted transports, by `proto` (`dot`, `doh`).
pub const CONNECTIONS: Desc = Desc::gauge(
    "tenko_dns_connections",
    "Open DNS over TLS and DNS over HTTPS connections",
)
.labels(&["proto"]);

/// Connections refused by a cap or because they did not come from a trusted proxy.
pub const CONNECTIONS_REFUSED: Desc = Desc::counter(
    "tenko_dns_connections_refused",
    "DNS over TLS and DNS over HTTPS connections refused by a limit",
)
.labels(&["proto"]);

/// TLS handshakes and PROXY headers that failed or ran out of time.
pub const HANDSHAKE_FAILURES: Desc = Desc::counter(
    "tenko_dns_tls_handshake_failures",
    "DNS over TLS and DNS over HTTPS handshakes that failed or timed out",
)
.labels(&["proto"]);

/// The open connections by transport ([`CONNECTIONS`]).
pub static OPEN_GAUGE: GaugeVec = GaugeVec::new(CONNECTIONS);

/// The refused connections by transport ([`CONNECTIONS_REFUSED`]).
pub static REFUSED_COUNTER: CounterVec = CounterVec::new(CONNECTIONS_REFUSED);

/// The failed handshakes by transport ([`HANDSHAKE_FAILURES`]).
pub static HANDSHAKE_COUNTER: CounterVec = CounterVec::new(HANDSHAKE_FAILURES);

/// The `proto` label values of the three families, in series order.
pub const PROTOS: [&str; 2] = ["dot", "doh"];

/// Seals the families of the encrypted transports (once per process).
pub fn seal() {
    let series: Vec<&[&str]> = PROTOS.iter().map(std::slice::from_ref).collect();
    OPEN_GAUGE.seal(&series);
    REFUSED_COUNTER.seal(&series);
    HANDSHAKE_COUNTER.seal(&series);
    for kind in [Kind::Dot, Kind::Doh] {
        publish_open(kind, 0);
    }
}

/// Sets the open connections of a transport in [`OPEN_GAUGE`].
fn publish_open(kind: Kind, open: usize) {
    OPEN_GAUGE.set(
        kind.series(),
        f64::from(u32::try_from(open).unwrap_or(u32::MAX)),
    );
}

/// Seals the families and registers them with `registry` (the role start step calls it
/// when DoT or DoH is on).
pub fn register(registry: &Registry) {
    seal();
    registry.register(&OPEN_GAUGE);
    registry.register(&REFUSED_COUNTER);
    registry.register(&HANDSHAKE_COUNTER);
}

/// The two encrypted transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dot,
    Doh,
}

impl Kind {
    const fn transport(self) -> QueryTransport {
        match self {
            Kind::Dot => QueryTransport::Dot,
            Kind::Doh => QueryTransport::Doh,
        }
    }

    const fn series(self) -> u16 {
        match self {
            Kind::Dot => 0,
            Kind::Doh => 1,
        }
    }

    const fn alpn(self) -> &'static [&'static [u8]] {
        match self {
            Kind::Dot => &[b"dot"],
            Kind::Doh => &[b"h2", b"http/1.1"],
        }
    }
}

/// The counters of one transport.
#[derive(Debug)]
struct Side {
    kind: Kind,
    limits: Arc<Limits>,
    untrusted: AtomicU64,
    handshake_failures: AtomicU64,
}

impl Side {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            limits: Arc::new(Limits::default()),
            untrusted: AtomicU64::new(0),
            handshake_failures: AtomicU64::new(0),
        }
    }

    fn refused(&self) -> u64 {
        self.limits.refused() + self.untrusted.load(Ordering::Relaxed)
    }

    fn count_refused(&self) {
        REFUSED_COUNTER.inc(self.kind.series());
    }

    fn count_handshake_failure(&self) {
        self.handshake_failures.fetch_add(1, Ordering::Relaxed);
        HANDSHAKE_COUNTER.inc(self.kind.series());
    }

    fn publish_open(&self) {
        publish_open(self.kind, self.limits.open());
    }
}

/// An open connection: the place under the caps, and the gauge kept current.
struct Opened {
    permit: Option<Permit>,
    side: Arc<Side>,
}

impl Drop for Opened {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.side.publish_open();
    }
}

/// The listeners bound and the acceptors built, before anything runs.
pub(crate) struct Prepared {
    settings: TlsListen,
    dot: Vec<TcpListener>,
    doh: Vec<TcpListener>,
    stream_tls: Option<TlsAcceptor>,
    http_tls: Option<TlsAcceptor>,
}

/// The encrypted side of a running server.
#[derive(Debug)]
pub(crate) struct Running {
    behind_proxy: bool,
    dot: Vec<SocketAddr>,
    doh: Vec<SocketAddr>,
    dot_side: Arc<Side>,
    doh_side: Arc<Side>,
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason.to_owned())
}

/// A rustls server configuration over `resolver` for one transport.
fn server_config(
    resolver: &Arc<dyn ResolvesServerCert>,
    tls13_only: bool,
    kind: Kind,
) -> io::Result<Arc<rustls::ServerConfig>> {
    let versions: &[&'static rustls::SupportedProtocolVersion] = if tls13_only {
        &[&rustls::version::TLS13]
    } else {
        rustls::DEFAULT_VERSIONS
    };
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(versions)
    .map_err(io::Error::other)?
    .with_no_client_auth()
    .with_cert_resolver(Arc::clone(resolver));
    config.alpn_protocols = kind.alpn().iter().map(|alpn| alpn.to_vec()).collect();
    // RFC 7858 section 3.4: resumption saves a round trip on every reconnection.
    config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().map_err(io::Error::other)?;
    Ok(Arc::new(config))
}

impl Prepared {
    /// Binds every DoT and DoH address and builds the acceptors.
    ///
    /// # Errors
    ///
    /// An address that cannot be bound, a cap of zero, or TLS termination without a
    /// certificate resolver.
    pub(crate) fn bind(
        settings: TlsListen,
        certificates: Option<&Arc<dyn ResolvesServerCert>>,
    ) -> io::Result<Self> {
        if settings.max_connections == 0 || settings.per_client == 0 || settings.doh_streams == 0 {
            return Err(invalid(
                "the DoT and DoH caps must be at least one connection and one stream",
            ));
        }
        let (stream_tls, http_tls) = match &settings.termination {
            Termination::Tls { tls13_only } => {
                let Some(resolver) = certificates else {
                    return Err(invalid("DoT and DoH need a certificate to serve"));
                };
                (
                    Some(TlsAcceptor::from(server_config(
                        resolver,
                        *tls13_only,
                        Kind::Dot,
                    )?)),
                    Some(TlsAcceptor::from(server_config(
                        resolver,
                        *tls13_only,
                        Kind::Doh,
                    )?)),
                )
            }
            Termination::Proxy { trusted, .. } => {
                if trusted.is_empty() {
                    return Err(invalid(
                        "behind a reverse proxy, DoT and DoH need the trusted proxies",
                    ));
                }
                (None, None)
            }
        };
        let dot = settings
            .dot
            .iter()
            .map(|address| tcp::bind(*address))
            .collect::<io::Result<Vec<_>>>()?;
        let doh = settings
            .doh
            .iter()
            .map(|address| tcp::bind(*address))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            settings,
            dot,
            doh,
            stream_tls,
            http_tls,
        })
    }

    /// Starts the accept loops.
    pub(crate) fn spawn<R: Resolver + 'static>(
        self,
        responder: &Arc<Responder<R>>,
        stop: &CancellationToken,
    ) -> (Running, Vec<JoinHandle<()>>) {
        let Self {
            settings,
            dot,
            doh,
            stream_tls,
            http_tls,
        } = self;
        let (trusted, proxy_protocol) = match &settings.termination {
            Termination::Tls { .. } => (None, false),
            Termination::Proxy {
                trusted,
                proxy_protocol,
            } => (Some(trusted.clone()), *proxy_protocol),
        };
        let caps = TcpSettings {
            max_connections: settings.max_connections,
            // Behind a proxy every connection comes from the proxy's address.
            per_client: if trusted.is_some() {
                settings.max_connections
            } else {
                settings.per_client
            },
            idle: settings.idle,
        };
        let running = Running {
            behind_proxy: trusted.is_some(),
            dot: dot.iter().filter_map(|l| l.local_addr().ok()).collect(),
            doh: doh.iter().filter_map(|l| l.local_addr().ok()).collect(),
            dot_side: Arc::new(Side::new(Kind::Dot)),
            doh_side: Arc::new(Side::new(Kind::Doh)),
        };
        let mut tasks = Vec::new();
        for (listeners, acceptor, side) in [
            (dot, stream_tls, &running.dot_side),
            (doh, http_tls, &running.doh_side),
        ] {
            let shared = Arc::new(Shared {
                responder: Arc::clone(responder),
                side: Arc::clone(side),
                caps,
                handshake: settings.handshake_timeout,
                acceptor,
                proxy_protocol,
                trusted: trusted.clone(),
                doh_streams: settings.doh_streams,
            });
            for listener in listeners {
                tasks.push(tokio::spawn(accept(
                    listener,
                    Arc::clone(&shared),
                    stop.clone(),
                )));
            }
        }
        (running, tasks)
    }
}

impl Running {
    pub(crate) fn dot_addresses(&self) -> &[SocketAddr] {
        &self.dot
    }

    pub(crate) fn doh_addresses(&self) -> &[SocketAddr] {
        &self.doh
    }

    /// Open connections of both transports.
    pub(crate) fn open(&self) -> usize {
        self.dot_side.limits.open() + self.doh_side.limits.open()
    }

    pub(crate) fn layout(&self) -> TlsLayout {
        TlsLayout {
            behind_proxy: self.behind_proxy,
            dot: self.dot.clone(),
            dot_open: self.dot_side.limits.open(),
            dot_refused: self.dot_side.refused(),
            dot_handshake_failures: self.dot_side.handshake_failures.load(Ordering::Relaxed),
            doh: self.doh.clone(),
            doh_open: self.doh_side.limits.open(),
            doh_refused: self.doh_side.refused(),
            doh_handshake_failures: self.doh_side.handshake_failures.load(Ordering::Relaxed),
        }
    }
}

/// What every connection of one transport shares.
struct Shared<R> {
    responder: Arc<Responder<R>>,
    side: Arc<Side>,
    caps: TcpSettings,
    handshake: Duration,
    acceptor: Option<TlsAcceptor>,
    proxy_protocol: bool,
    trusted: Option<Vec<IpNet>>,
    doh_streams: u32,
}

fn trusted(networks: &[IpNet], address: IpAddr) -> bool {
    let address = address.to_canonical();
    networks.iter().any(|network| network.contains(&address))
}

/// Accepts connections until `stop` is cancelled.
async fn accept<R: Resolver + 'static>(
    socket: TcpListener,
    shared: Arc<Shared<R>>,
    stop: CancellationToken,
) {
    let Ok(local) = socket.local_addr() else {
        return;
    };
    loop {
        let accepted = tokio::select! {
            () = stop.cancelled() => return,
            accepted = socket.accept() => accepted,
        };
        let Ok((stream, peer)) = accepted else {
            // Out of file descriptors and the like: let the system recover.
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        if let Some(networks) = &shared.trusted
            && !trusted(networks, peer.ip())
        {
            shared.side.untrusted.fetch_add(1, Ordering::Relaxed);
            shared.side.count_refused();
            drop(stream);
            continue;
        }
        let Some(permit) = shared.side.limits.acquire(peer.ip(), &shared.caps) else {
            shared.side.count_refused();
            drop(stream);
            continue;
        };
        shared.side.publish_open();
        let opened = Opened {
            permit: Some(permit),
            side: Arc::clone(&shared.side),
        };
        tokio::spawn(connection(
            stream,
            peer,
            local,
            Arc::clone(&shared),
            stop.clone(),
            opened,
        ));
    }
}

/// One connection: the PROXY header, the TLS handshake, then the transport.
async fn connection<R: Resolver + 'static>(
    mut stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    shared: Arc<Shared<R>>,
    stop: CancellationToken,
    _opened: Opened,
) {
    let _ = stream.set_nodelay(true);
    let mut client = peer;
    if shared.proxy_protocol {
        match tokio::time::timeout(shared.handshake, proxy::read_v2(&mut stream)).await {
            Ok(Ok(Some(source))) => client = source,
            // A LOCAL header (the proxy's own health check): the proxy is the client.
            Ok(Ok(None)) => {}
            Ok(Err(_)) | Err(_) => {
                shared.side.count_handshake_failure();
                return;
            }
        }
    }
    let conn = Conn {
        client,
        local,
        transport: shared.side.kind.transport(),
    };
    match &shared.acceptor {
        Some(acceptor) => {
            let accepted = tokio::select! {
                () = stop.cancelled() => return,
                accepted = tokio::time::timeout(shared.handshake, acceptor.accept(stream)) => accepted,
            };
            match accepted {
                Ok(Ok(tls)) => serve(tls, conn, &shared, stop).await,
                Ok(Err(_)) | Err(_) => shared.side.count_handshake_failure(),
            }
        }
        None => serve(stream, conn, &shared, stop).await,
    }
}

async fn serve<R, S>(stream: S, conn: Conn, shared: &Shared<R>, stop: CancellationToken)
where
    R: Resolver + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match shared.side.kind {
        Kind::Dot => {
            dot::connection(
                stream,
                conn,
                Arc::clone(&shared.responder),
                shared.caps.idle,
                stop,
                // WP6.1: XoT only where this node ends TLS, never behind a proxy.
                shared.acceptor.is_some(),
            )
            .await;
        }
        Kind::Doh => {
            doh::connection(
                stream,
                conn,
                doh::Options {
                    idle: shared.caps.idle,
                    streams: shared.doh_streams,
                    forwarded_for: shared.trusted.is_some() && !shared.proxy_protocol,
                },
                Arc::clone(&shared.responder),
                stop,
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::metrics::{check, encode};

    use super::*;

    #[test]
    fn the_connection_families_encode_and_check() {
        let registry = Registry::new();
        register(&registry);
        let side = Side::new(Kind::Dot);
        let caps = TcpSettings::default();
        let first = side.limits.acquire("192.0.2.1".parse().expect("ip"), &caps);
        let second = side.limits.acquire("192.0.2.2".parse().expect("ip"), &caps);
        side.publish_open();
        Side::new(Kind::Doh).count_refused();
        side.count_handshake_failure();
        let mut text = String::new();
        encode(&registry.snapshot(), &mut text);
        check(&text).expect("valid OpenMetrics");
        assert!(
            text.contains("tenko_dns_connections{proto=\"dot\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("tenko_dns_connections{proto=\"doh\"} 0"),
            "{text}"
        );
        assert!(
            text.contains("tenko_dns_connections_refused_total{proto=\"doh\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("tenko_dns_tls_handshake_failures_total{proto=\"dot\"} 1"),
            "{text}"
        );
        drop((first, second));
        side.publish_open();
        let mut text = String::new();
        encode(&registry.snapshot(), &mut text);
        assert!(
            text.contains("tenko_dns_connections{proto=\"dot\"} 0"),
            "{text}"
        );
    }
}
