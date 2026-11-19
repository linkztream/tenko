//! The integration listener (ADR 0035, decision 3): mutual TLS with integration certificates,
//! on a port of its own, with limits of its own.
//!
//! - It opens only after the first full load of the certificate records, and on demand
//!   (while an enrollment code waits or a certificate is in use) unless the configuration
//!   names its addresses; it closes again when the demand ends.
//! - At most [`MAX_CONNECTIONS`] connections, at most [`MAX_PER_SOURCE`] from one address,
//!   counted before the handshake; the handshake must finish within
//!   [`HANDSHAKE_TIMEOUT`].
//! - The handshake asks the certificate records ([`ClientCerts`]); after it, every request
//!   is checked again by `middleware::integration`, and a connection whose certificate stops
//!   passing is closed at once, also in the middle of a long answer.
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
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt as _;

use super::forwarded::{ConnInfo, IntegrationClient};
use crate::routes::integrations::CaIssuer;

/// The most open connections of the integration listener.
pub const MAX_CONNECTIONS: usize = 512;
/// The most open connections from one address, handshakes included.
pub const MAX_PER_SOURCE: usize = 16;

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
    certs: Arc<ClientCerts>,
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
                match bind(&listener, &root, &router, header_read_timeout) {
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
        certs: Arc::clone(&listener.certs),
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
                    tracing::debug!(%error, "integration accept failed");
                    continue;
                }
            },
            _ = closed.changed() => return,
        };
        // Both limits are counted before the handshake costs anything.
        let Ok(permit) = Arc::clone(&shared.connections).try_acquire_owned() else {
            continue;
        };
        let Some(slot) = shared.sources.claim(peer.ip()) else {
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
    loop {
        tokio::select! {
            result = connection.as_mut() => {
                if let Err(error) = result {
                    tracing::debug!(%peer, %error, "integration connection ended with an error");
                }
                return;
            }
            followed = changes.changed() => {
                let refused = matches!(
                    shared.certs.index().accept(&client.serial, client.account, Timestamp::now()),
                    Acceptance::Refused(_)
                );
                if followed.is_err() || refused {
                    // Dropping the connection closes it, also in the middle of an answer.
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

#[cfg(test)]
mod tests {
    use super::*;

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
