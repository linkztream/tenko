//! The accept loop: PROXY protocol, TLS and HTTP/1.1 plus HTTP/2 per connection.
//!
//! Every accepted connection runs in its own task, so a slow TLS handshake or PROXY header
//! never blocks the accept loop. The TLS mode is read per connection from the
//! [`TlsService`], so a mode or certificate change applies to new connections at once:
//!
//! - **Modes a and b** (internal CA, imported certificate): TLS through the service's
//!   rustls configuration, whose resolver swaps certificates without a restart; ALPN offers
//!   `h2` and `http/1.1`.
//! - **Mode c** (reverse proxy): plain HTTP, only from trusted proxies; with the PROXY
//!   protocol enabled their header is read first (optional per connection, so proxy health
//!   checks without it still work). Any other peer is answered with 403
//!   `sys.proxy_only` and the connection is closed, unless the Lab profile allows plain
//!   HTTP from everyone (TGL-08).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    extract::ConnectInfo,
    http::{HeaderValue, Request, header},
    response::IntoResponse,
};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::{
        conn::auto,
        graceful::{GracefulShutdown, Watcher},
    },
};
use tenko_cluster::ca::{TlsMode, TlsService};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt as _;

use super::{
    forwarded::ConnInfo,
    proxy_protocol::{self, Rewind},
};
use crate::{
    middleware::metrics::{Event, Metrics},
    problem::{ApiError, codes},
    state::AppState,
};

/// What every connection task needs.
pub(crate) struct Shared {
    pub(crate) router: Router,
    pub(crate) tls: TlsService,
    pub(crate) acceptor: TlsAcceptor,
    pub(crate) lab_plain_http: bool,
    pub(crate) handshake_timeout: Duration,
    pub(crate) header_read_timeout: Duration,
    pub(crate) connections: Arc<Semaphore>,
    pub(crate) state: AppState,
}

impl Shared {
    fn metrics(&self) -> &Metrics {
        &self.state.platform.metrics
    }
}

/// Accepts connections until `stop` turns true.
pub(crate) async fn accept_loop(
    listener: TcpListener,
    shared: Arc<Shared>,
    graceful: Arc<GracefulShutdown>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = stop.changed() => break,
        };
        if *stop.borrow() {
            break;
        }
        let (tcp, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                // Out of file descriptors and similar: back off instead of spinning.
                tracing::warn!(%error, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&shared.connections).try_acquire_owned() else {
            shared.metrics().count(Event::ConnectionOverLimit);
            drop(tcp);
            continue;
        };
        shared.metrics().count(Event::ConnectionAccepted);
        // SSE frames are small writes; Nagle plus delayed ACK would hold them back.
        let _ = tcp.set_nodelay(true);
        let watcher = graceful.watcher();
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            connection(tcp, peer, &shared, watcher).await;
            drop(permit);
        });
    }
}

/// Serves one connection.
async fn connection(tcp: TcpStream, peer: SocketAddr, shared: &Shared, watcher: Watcher) {
    let status = shared.tls.status();
    let mode = Arc::new(status.mode.clone());
    let (trusted, proxy_protocol) = match &*mode {
        TlsMode::ReverseProxy {
            trusted_proxies,
            proxy_protocol,
            ..
        } => (trusted_proxies.is_trusted(peer.ip()), *proxy_protocol),
        _ => (false, false),
    };

    let mut tcp = tcp;
    let (io, proxy) = if trusted && proxy_protocol {
        match proxy_protocol::read_header(&mut tcp, shared.handshake_timeout).await {
            Ok((header, rest)) => (Rewind::new(rest, tcp), header),
            Err(error) => {
                shared.metrics().count(Event::ProxyHeaderFailed);
                tracing::debug!(%peer, %error, "PROXY protocol header refused");
                return;
            }
        }
    } else {
        (Rewind::new(Bytes::new(), tcp), None)
    };

    let mut info = ConnInfo {
        peer,
        tls: false,
        mode: Arc::clone(&mode),
        trusted,
        proxy,
    };
    if mode.terminates_tls() {
        let handshake =
            tokio::time::timeout(shared.handshake_timeout, shared.acceptor.accept(io)).await;
        match handshake {
            Ok(Ok(stream)) => {
                info.tls = true;
                serve_http(stream, info, shared.router.clone(), shared, watcher, true).await;
            }
            Ok(Err(error)) => {
                shared.metrics().count(Event::TlsHandshakeFailed);
                tracing::debug!(%peer, %error, "TLS handshake failed");
            }
            Err(_) => {
                shared.metrics().count(Event::TlsHandshakeFailed);
                tracing::debug!(%peer, "TLS handshake timed out");
            }
        }
    } else if trusted || shared.lab_plain_http {
        serve_http(io, info, shared.router.clone(), shared, watcher, true).await;
    } else {
        shared.metrics().count(Event::ProxyOnlyRefused);
        serve_http(io, info, proxy_only_router(), shared, watcher, false).await;
    }
}

/// Runs HTTP/1.1 or HTTP/2 (detected from the preface or ALPN) over `io`.
async fn serve_http<IO>(
    io: IO,
    info: ConnInfo,
    router: Router,
    shared: &Shared,
    watcher: Watcher,
    keep_alive: bool,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let peer = info.peer;
    let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
        request.extensions_mut().insert(info.clone());
        request.extensions_mut().insert(ConnectInfo(info.peer));
        let router = router.clone();
        async move { router.oneshot(request).await }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(shared.header_read_timeout)
        .keep_alive(keep_alive);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(30))
        .max_concurrent_streams(256);
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    if let Err(error) = watcher.watch(connection.into_owned()).await {
        tracing::debug!(%peer, %error, "connection ended with an error");
    }
}

/// The router that answers every request of a refused plain HTTP connection.
fn proxy_only_router() -> Router {
    Router::new().fallback(|| async {
        let mut response = ApiError::new(
            codes::PROXY_ONLY,
            403,
            "this server accepts plain HTTP only from its trusted reverse proxies; connect \
             through the proxy over HTTPS",
        )
        .into_response();
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
        crate::middleware::headers::apply(response.headers_mut(), false);
        response
    })
}
