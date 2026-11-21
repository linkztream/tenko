//! The integration listener (ADR 0035, decision 3): mutual TLS with integration certificates,
//! on a port of its own, with limits of its own.
//!
//! - It opens only after the first full load of the certificate records, and on demand
//!   (while an enrollment code waits or a certificate is in use) unless the configuration
//!   names its addresses; it closes again when the demand ends.
//! - At most [`MAX_CONNECTIONS`] connections, at most [`MAX_PER_SOURCE`] from one source and
//!   at most [`HANDSHAKES_PER_SECOND`] new handshakes a second from one source (burst
//!   [`HANDSHAKE_BURST`]), counted before the handshake; an IPv6 source is its /64. The
//!   handshake must finish within [`HANDSHAKE_TIMEOUT`].
//! - The handshake asks the certificate records ([`ClientCerts`]); after it, every request
//!   is checked again by `middleware::integration`, and a connection whose certificate stops
//!   passing is closed at once, also in the middle of a long answer: at a change of the
//!   records, at the next moment its acceptance can change by time alone (its end, the end of
//!   its overlap, the bound of unread records), and once the controller has been cut off
//!   from its quorum for longer than the isolation limit.
//! - It reads no PROXY protocol header, no forwarded header and no cookie: the client
//!   address is the TCP peer.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Router, extract::ConnectInfo, http::Request};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::{ServerConfig, pki_types::CertificateDer, server::ResolvesServerCert};
use tenko_auth::client_cert::{Acceptance, ClientCerts};
use tenko_cluster::{
    ca::{IntegrationIdentity, TlsMode},
    client_tls::{CertificateGate, HANDSHAKE_TIMEOUT, integration_server_config},
};
use tenko_core::Timestamp;
use tenko_core::{RequestCtx, SystemComponent};
use tenko_store::Store;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt as _;

use super::forwarded::{ConnInfo, IntegrationClient};
use crate::{
    middleware::{
        Quota, RateLimitConfig, RateLimiter, integration::ISOLATION_LIMIT, quorum::Staleness,
    },
    routes::integrations::CaIssuer,
};

/// The most open connections of the integration listener.
pub const MAX_CONNECTIONS: usize = 512;
/// The most open connections from one source, handshakes included.
pub const MAX_PER_SOURCE: usize = 16;
/// New handshakes a source may start per second, sustained.
pub const HANDSHAKES_PER_SECOND: u32 = 4;
/// New handshakes a source may start at once.
pub const HANDSHAKE_BURST: u32 = 32;
/// How often an open connection asks whether its controller has been cut off.
const ISOLATION_CHECK: Duration = Duration::from_secs(5);

/// What the server binary hands the integration listener.
#[derive(Clone)]
pub struct IntegrationListener {
    /// Its addresses.
    pub listen: Vec<SocketAddr>,
    /// Whether it opens only on demand; `false` when the configuration names its addresses.
    pub on_demand: bool,
    /// The certificate records.
    pub certs: Arc<ClientCerts>,
    /// The integration CA, for its root.
    pub issuer: Arc<CaIssuer>,
    /// The server certificate, from the internal CA.
    pub resolver: Arc<dyn ResolvesServerCert>,
}

impl std::fmt::Debug for IntegrationListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntegrationListener")
            .field("listen", &self.listen)
            .field("on_demand", &self.on_demand)
            .finish_non_exhaustive()
    }
}

/// The handshake asks the records: a certificate passes when it passes for some route.
struct Gate(Arc<ClientCerts>);

impl CertificateGate for Gate {
    fn admits(&self, identity: &IntegrationIdentity, now: Timestamp) -> bool {
        !matches!(
            self.0
                .index()
                .accept(&identity.serial, identity.account, now),
            Acceptance::Refused(_)
        )
    }
}

/// The open connections per source address.
#[derive(Debug, Default)]
struct Sources(Mutex<HashMap<IpAddr, usize>>);

/// One connection counted against its source; uncounted when dropped.
struct SourceSlot {
    sources: Arc<Sources>,
    source: IpAddr,
}

impl Sources {
    fn claim(self: &Arc<Self>, source: IpAddr) -> Option<SourceSlot> {
        let mut open = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = open.entry(source).or_default();
        if *count >= MAX_PER_SOURCE {
            return None;
        }
        *count += 1;
        Some(SourceSlot {
            sources: Arc::clone(self),
            source,
        })
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut open = self
            .sources
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = open.get_mut(&self.source) {
            *count -= 1;
            if *count == 0 {
                open.remove(&self.source);
            }
        }
    }
}

/// What every connection of an open listener shares.
struct Shared {
    router: Router,
    store: Arc<dyn Store>,
    certs: Arc<ClientCerts>,
    /// The handshake rate per source; its key is also the source of [`Sources`].
    handshakes: RateLimiter,
    tls13: Arc<ServerConfig>,
    tls12: Arc<ServerConfig>,
    header_read_timeout: Duration,
    connections: Arc<Semaphore>,
    sources: Arc<Sources>,
}

/// Opens and closes the listener as the records ask until `stop` turns true.
pub(super) async fn supervise(
    listener: IntegrationListener,
    router: Router,
    store: Arc<dyn Store>,
    header_read_timeout: Duration,
    mut stop: watch::Receiver<bool>,
) {
    let index = Arc::clone(listener.certs.index());
    let mut changes = index.subscribe();
    let mut open: Option<(watch::Sender<bool>, Vec<JoinHandle<()>>)> = None;
    loop {
        let wanted = index.is_loaded()
            && !listener.listen.is_empty()
            && (!listener.on_demand || index.wanted(Timestamp::now()));
        if wanted && open.is_none() {
            // Without an integration CA nothing could pass; the first code creates it.
            let ctx = RequestCtx::system(SystemComponent::Api);
            if let Some(root) = listener.issuer.integration_root(&ctx).await {
                match bind(&listener, &root, &router, &store, header_read_timeout) {
                    Ok(opened) => open = Some(opened),
                    Err(reason) => tracing::warn!("the integration listener cannot open: {reason}"),
                }
            }
        } else if !wanted && let Some((closing, loops)) = open.take() {
            let _ = closing.send(true);
            for accept_loop in loops {
                let _ = accept_loop.await;
            }
            tracing::info!("the integration listener closed: nothing uses it");
        }
        tokio::select! {
            followed = changes.changed() => if followed.is_err() { break },
            _ = stop.changed() => break,
        }
        if *stop.borrow() {
            break;
        }
    }
    if let Some((closing, loops)) = open {
        let _ = closing.send(true);
        for accept_loop in loops {
            let _ = accept_loop.await;
        }
    }
}

fn bind(
    listener: &IntegrationListener,
    root: &CertificateDer<'static>,
    router: &Router,
    store: &Arc<dyn Store>,
    header_read_timeout: Duration,
) -> Result<(watch::Sender<bool>, Vec<JoinHandle<()>>), String> {
    let gate: Arc<dyn CertificateGate> = Arc::new(Gate(Arc::clone(&listener.certs)));
    let config = |allow_tls12| {
        integration_server_config(
            root,
            Arc::clone(&listener.resolver),
            Arc::clone(&gate),
            allow_tls12,
        )
        .map_err(|error| error.to_string())
    };
    let shared = Arc::new(Shared {
        router: router.clone(),
        store: Arc::clone(store),
        certs: Arc::clone(&listener.certs),
        handshakes: RateLimiter::new(RateLimitConfig {
            enabled: true,
            per_ip: Some(Quota {
                per_second: HANDSHAKES_PER_SECOND,
                burst: HANDSHAKE_BURST,
            }),
            per_principal: None,
            ipv6_prefix_len: 64,
            max_keys: 4 * MAX_CONNECTIONS,
        }),
        tls13: config(false)?,
        tls12: config(true)?,
        header_read_timeout,
        connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        sources: Arc::default(),
    });
    let mut sockets = Vec::new();
    for addr in &listener.listen {
        sockets.push(super::bind(*addr).map_err(|error| format!("{addr}: {error}"))?);
    }
    let (closing, closed) = watch::channel(false);
    tracing::info!(addrs = ?listener.listen, "the integration listener is open");
    let loops = sockets
        .into_iter()
        .map(|socket| tokio::spawn(accept_loop(socket, Arc::clone(&shared), closed.clone())))
        .collect();
    Ok((closing, loops))
}

async fn accept_loop(socket: TcpListener, shared: Arc<Shared>, mut closed: watch::Receiver<bool>) {
    loop {
        let (tcp, peer) = tokio::select! {
            accepted = socket.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    super::accept_failed(&error).await;
                    continue;
                }
            },
            _ = closed.changed() => return,
        };
        // Every limit is counted before the handshake costs anything; an IPv6 source is its
        // /64, so one host cannot claim a share per address.
        let source = shared.handshakes.ip_key(peer.ip());
        if shared
            .handshakes
            .check_ip(source, std::time::Instant::now())
            .is_err()
        {
            continue;
        }
        let Ok(permit) = Arc::clone(&shared.connections).try_acquire_owned() else {
            continue;
        };
        let Some(slot) = shared.sources.claim(source) else {
            continue;
        };
        tokio::spawn(connection(
            tcp,
            peer,
            Arc::clone(&shared),
            (permit, slot),
            closed.clone(),
        ));
    }
}

async fn connection(
    tcp: TcpStream,
    peer: SocketAddr,
    shared: Arc<Shared>,
    _counted: (OwnedSemaphorePermit, SourceSlot),
    mut closed: watch::Receiver<bool>,
) {
    let config = if shared.certs.index().policy().allow_tls12 {
        Arc::clone(&shared.tls12)
    } else {
        Arc::clone(&shared.tls13)
    };
    let stream = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        TlsAcceptor::from(config).accept(tcp),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tracing::debug!(%peer, %error, "integration handshake failed");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "integration handshake timed out");
            return;
        }
    };
    let Some(identity) = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .and_then(|leaf| IntegrationIdentity::from_der(leaf).ok())
    else {
        return;
    };
    let client = Arc::new(IntegrationClient {
        serial: identity.serial,
        account: identity.account,
    });
    let info = ConnInfo {
        peer,
        tls: true,
        // No trusted proxies: no forwarded header is ever read here.
        mode: Arc::new(TlsMode::InternalCa),
        trusted: false,
        proxy: None,
        client: Some(Arc::clone(&client)),
    };
    let router = shared.router.clone();
    let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
        // Only bearer tokens are read here, never a session cookie.
        request.headers_mut().remove(axum::http::header::COOKIE);
        request.extensions_mut().insert(info.clone());
        request.extensions_mut().insert(ConnectInfo(peer));
        let router = router.clone();
        async move { router.oneshot(request).await }
    });
    let builder = super::listener::http_builder(shared.header_read_timeout, true);
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
    let mut connection = std::pin::pin!(connection);
    let mut changes = shared.certs.index().subscribe();
    let mut isolation = tokio::time::interval(ISOLATION_CHECK);
    // A connection of a replaced certificate past its overlap may only renew (where a renewal
    // from it is reuse, which must be seen); one that began with full acceptance ends when
    // that ends.
    let full = matches!(
        shared
            .certs
            .index()
            .accept(&client.serial, client.account, Timestamp::now()),
        Acceptance::Accepted(_)
    );
    loop {
        // Every wake-up asks again, so a boundary that passed while the loop slept, or a
        // jump of the wall clock, ends the connection at the next tick at the latest.
        if !stands(&shared, &client, full) {
            return;
        }
        // The next moment the certificate's acceptance can change without a change of the
        // records; a certificate that passes no longer has none and is closed below.
        let boundary = shared
            .certs
            .index()
            .next_boundary(&client.serial, Timestamp::now())
            .map(|at| at.saturating_since(Timestamp::now()));
        tokio::select! {
            result = connection.as_mut() => {
                if let Err(error) = result {
                    tracing::debug!(%peer, %error, "integration connection ended with an error");
                }
                return;
            }
            followed = changes.changed() => {
                if followed.is_err() {
                    return;
                }
            }
            () = sleep_or_never(boundary) => {}
            _ = isolation.tick() => {
                if cut_off(shared.store.as_ref(), Timestamp::now()) {
                    return;
                }
            }
            _ = closed.changed() => {
                connection.as_mut().graceful_shutdown();
                let _ = tokio::time::timeout(Duration::from_secs(10), connection.as_mut()).await;
                return;
            }
        }
    }
}

/// Whether an open connection may go on; dropping it closes it, also in the middle of an
/// answer. A certificate that no longer passes ends it. A replaced certificate past its
/// overlap passes for the renewal route only: a connection that began with full acceptance
/// (and may be in the middle of a long answer) ends then, one that began as a renewal goes
/// on, so that a renewal from it is still seen as reuse.
fn stands(shared: &Shared, client: &IntegrationClient, full: bool) -> bool {
    match shared
        .certs
        .index()
        .accept(&client.serial, client.account, Timestamp::now())
    {
        Acceptance::Accepted(_) => true,
        Acceptance::RenewOnly(_) => !full,
        Acceptance::Refused(_) => false,
    }
}

/// Whether the controller has been cut off from its quorum for longer than the isolation
/// limit: it can no longer know of a revocation made elsewhere.
fn cut_off(store: &dyn Store, now: Timestamp) -> bool {
    let status = store.status();
    Staleness::of(&status.quorum, status.revision)
        .is_some_and(|staleness| now.saturating_since(staleness.since) > ISOLATION_LIMIT)
}

/// Sleeps `after` (a moment just past it, so the boundary itself has gone), or forever.
async fn sleep_or_never(after: Option<Duration>) {
    match after {
        Some(after) => tokio::time::sleep(after + Duration::from_millis(10)).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
#[path = "integration_tests.rs"]
mod listener_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ipv6_source_is_its_64_and_a_mapped_address_its_ipv4() {
        let limiter = RateLimiter::new(RateLimitConfig {
            ipv6_prefix_len: 64,
            ..RateLimitConfig::default()
        });
        let key = |text: &str| limiter.ip_key(text.parse().expect("address"));
        assert_eq!(key("2001:db8:1:2::10"), key("2001:db8:1:2:ffff::1"));
        assert_ne!(key("2001:db8:1:2::10"), key("2001:db8:1:3::10"));
        assert_eq!(key("::ffff:192.0.2.7"), key("192.0.2.7"));
    }

    #[test]
    fn a_source_holds_at_most_its_share_of_connections() {
        let sources = Arc::new(Sources::default());
        let one: IpAddr = "192.0.2.40".parse().expect("address");
        let other: IpAddr = "2001:db8::40".parse().expect("address");
        let mut held: Vec<SourceSlot> = (0..MAX_PER_SOURCE)
            .map(|_| sources.claim(one).expect("within the share"))
            .collect();
        assert!(sources.claim(one).is_none(), "one more is refused");
        let elsewhere = sources
            .claim(other)
            .expect("another source has its own share");
        held.pop();
        let again = sources
            .claim(one)
            .expect("a closed connection frees its place");
        drop((held, again, elsewhere));
        assert!(
            sources
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty(),
            "every slot was given back"
        );
    }
}
