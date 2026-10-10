//! The controller side of the node transport: the cluster port, its accept loop with the
//! mutual TLS handshake, and the router that serves the gRPC services of package
//! `tenko.cluster.v1`.
//!
//! This file holds the listener, the router and the helpers every service shares. Each
//! service is implemented for [`ClusterService`] in its own file under `service/` (see the
//! table there), so work packages edit disjoint files.
//!
//! Every call is checked twice: the TLS verifier refused certificates of another CA and
//! revoked serials during the handshake; each service then requires that the certificate's
//! node is enrolled and still holds that certificate ([`NodeRegistry::authenticate`]).
//! Errors carry the metadata entry `tenko-error-code`.

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use rustls::{ServerConfig, server::ResolvesServerCert};
use tenko_core::{NodeId, Timestamp};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tonic::{Request, Status, metadata::MetadataValue};

use crate::{
    error::ClusterError,
    mtls::{KillSwitch, NodeStream, PeerIdentity, PeerInfo},
    probe::ProbeSink,
    proto::v1,
    registry::NodeRegistry,
};

/// Metadata entry with the stable error code of a refused call.
pub const ERROR_CODE_METADATA: &str = "tenko-error-code";
/// Metadata entry with the controller's protocol majors on a refused handshake.
pub const MAJORS_METADATA: &str = "tenko-majors";
/// Largest message on the cluster port (an observation batch).
pub const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
/// How long a TLS handshake on the cluster port may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the server waits for its connections after the stop signal.
pub const STOP_GRACE: Duration = Duration::from_secs(5);

/// A gRPC status for a coded error, with the code in [`ERROR_CODE_METADATA`].
pub fn status_of(error: &ClusterError) -> Status {
    let code = match error.status() {
        400 | 413 | 422 => tonic::Code::InvalidArgument,
        401 => tonic::Code::Unauthenticated,
        403 => tonic::Code::PermissionDenied,
        404 => tonic::Code::NotFound,
        409 => tonic::Code::FailedPrecondition,
        503 => tonic::Code::Unavailable,
        504 => tonic::Code::DeadlineExceeded,
        _ => tonic::Code::Internal,
    };
    let mut status = Status::new(code, error.detail().to_owned());
    if let Ok(value) = MetadataValue::try_from(error.code()) {
        status.metadata_mut().insert(ERROR_CODE_METADATA, value);
    }
    status
}

/// The error code a refused call carries, if any.
pub fn code_of(status: &Status) -> Option<&str> {
    status
        .metadata()
        .get(ERROR_CODE_METADATA)
        .and_then(|value| value.to_str().ok())
}

/// The mutual TLS identity of the caller, which the accept loop attached to the connection.
pub(crate) fn peer_of<T>(request: &Request<T>) -> Result<PeerInfo, Status> {
    request
        .extensions()
        .get::<PeerInfo>()
        .cloned()
        .ok_or_else(|| {
            status_of(&ClusterError::new(
                "cluster.tls.no_peer",
                401,
                "the call did not arrive over the mutual TLS of the cluster port",
            ))
        })
}

/// The gRPC services of the cluster port.
#[derive(Clone)]
pub struct ClusterService {
    /// The node registry the services authenticate against.
    pub(crate) registry: Arc<NodeRegistry>,
    /// Where the `Observations` service hands probe batches.
    pub(crate) sink: Arc<dyn ProbeSink>,
    /// The last ingested batch of each node: (epoch, sequence).
    pub(crate) ingested: Arc<Mutex<HashMap<NodeId, (String, u64)>>>,
}

impl std::fmt::Debug for ClusterService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterService").finish_non_exhaustive()
    }
}

impl ClusterService {
    /// The services over a registry, handing probe batches to `sink`.
    pub fn new(registry: Arc<NodeRegistry>, sink: Arc<dyn ProbeSink>) -> Self {
        Self {
            registry,
            sink,
            ingested: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Requires that the caller's node is enrolled and still holds the presented
    /// certificate.
    pub(crate) async fn authenticate(
        &self,
        peer: &PeerInfo,
    ) -> Result<crate::model::NodeRecord, Status> {
        self.registry
            .authenticate(peer.identity.node, &peer.identity.serial, Timestamp::now())
            .await
            .map_err(|error| status_of(&error))
    }

    fn router(&self) -> tonic::transport::server::Router {
        tonic::transport::Server::builder()
            .http2_keepalive_interval(Some(Duration::from_secs(20)))
            .http2_keepalive_timeout(Some(Duration::from_secs(20)))
            .add_service(
                v1::handshake_server::HandshakeServer::new(self.clone())
                    .max_decoding_message_size(64 * 1024),
            )
            .add_service(
                v1::node_server::NodeServer::new(self.clone())
                    .max_decoding_message_size(1024 * 1024),
            )
            .add_service(
                v1::observations_server::ObservationsServer::new(self.clone())
                    .max_decoding_message_size(MAX_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_MESSAGE_BYTES),
            )
            // A snapshot chunk is 1 MiB and a forwarded write batch at most 16 MiB.
            .add_service(
                v1::raft_server::RaftServer::new(self.clone())
                    .max_decoding_message_size(MAX_MESSAGE_BYTES),
            )
            .add_service(
                v1::cluster_server::ClusterServer::new(self.clone())
                    .max_decoding_message_size(MAX_MESSAGE_BYTES),
            )
            .add_service(
                v1::config_server::ConfigServer::new(self.clone())
                    .max_decoding_message_size(1024 * 1024)
                    .max_encoding_message_size(MAX_MESSAGE_BYTES),
            )
            .add_service(
                v1::commands_server::CommandsServer::new(self.clone())
                    .max_decoding_message_size(1024 * 1024),
            )
            .add_service(
                v1::metrics_server::MetricsServer::new(self.clone())
                    .max_decoding_message_size(1024 * 1024),
            )
    }
}

/// The bound sockets of the cluster port, before it serves.
#[derive(Debug)]
pub struct ClusterListener {
    listeners: Vec<TcpListener>,
}

impl ClusterListener {
    /// Binds every address.
    ///
    /// # Errors
    ///
    /// `cluster.listen` (500) naming the address that could not be bound.
    pub async fn bind(addrs: &[SocketAddr]) -> Result<Self, ClusterError> {
        let mut listeners = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let listener = TcpListener::bind(addr).await.map_err(|error| {
                ClusterError::new(
                    "cluster.listen",
                    500,
                    format!("the cluster port cannot listen on {addr}: {error}"),
                )
                .with_param("address", addr.to_string())
            })?;
            listeners.push(listener);
        }
        Ok(Self { listeners })
    }

    /// The bound addresses.
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .collect()
    }

    /// Serves the cluster port until `stop` turns true: TLS handshakes with `resolver`'s
    /// controller certificate and the registry's CA root and revocation set, then gRPC.
    /// Records the listening addresses in the registry.
    ///
    /// # Errors
    ///
    /// The TLS configuration error.
    pub fn serve(
        self,
        registry: &Arc<NodeRegistry>,
        sink: Arc<dyn ProbeSink>,
        resolver: Arc<dyn ResolvesServerCert>,
        stop: watch::Receiver<bool>,
    ) -> Result<JoinHandle<()>, ClusterError> {
        let root = registry.ca().root_der().clone();
        let config = crate::mtls::server_config(&root, resolver, registry.revocations())?;
        let addrs = self.local_addrs();
        registry.set_listening(addrs.clone());
        tracing::info!(
            addresses = %addrs.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
            "cluster port listening (gRPC over mutual TLS)"
        );
        let service = ClusterService::new(Arc::clone(registry), sink);
        let registry = Arc::clone(registry);
        Ok(tokio::spawn(run(
            self.listeners,
            config,
            service,
            registry,
            stop,
        )))
    }
}

type Incoming = io::Result<NodeStream<TlsStream<TcpStream>>>;

async fn run(
    listeners: Vec<TcpListener>,
    config: Arc<ServerConfig>,
    service: ClusterService,
    registry: Arc<NodeRegistry>,
    stop: watch::Receiver<bool>,
) {
    let (tx, mut rx) = mpsc::channel::<Incoming>(64);
    let mut loops = Vec::with_capacity(listeners.len());
    for listener in listeners {
        loops.push(tokio::spawn(accept_loop(
            listener,
            Arc::clone(&config),
            tx.clone(),
            Arc::clone(&registry),
            stop.clone(),
        )));
    }
    drop(tx);
    let incoming = futures::stream::poll_fn(move |cx| rx.poll_recv(cx));
    let mut stopped = stop.clone();
    let (trigger, triggered) = tokio::sync::oneshot::channel::<()>();
    let server = service
        .router()
        .serve_with_incoming_shutdown(incoming, async move {
            let _ = triggered.await;
        });
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => {
            if let Err(error) = result {
                tracing::error!(%error, "the cluster port stopped with an error");
            }
        }
        () = async { let _ = stopped.wait_for(|stopped| *stopped).await; } => {
            let _ = trigger.send(());
            registry.sessions().kill_all();
            if tokio::time::timeout(STOP_GRACE, &mut server).await.is_err() {
                tracing::warn!("the cluster port did not stop in time");
            }
        }
    }
    for accept in loops {
        accept.abort();
        let _ = accept.await;
    }
    registry.set_listening(Vec::new());
    tracing::info!("cluster port stopped");
}

async fn accept_loop(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    tx: mpsc::Sender<Incoming>,
    registry: Arc<NodeRegistry>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
            accepted = listener.accept() => accepted,
        };
        let (tcp, remote) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "the cluster port could not accept a connection");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = TlsAcceptor::from(Arc::clone(&config));
        let tx = tx.clone();
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(error)) => {
                    tracing::info!(%remote, %error, "refused a connection on the cluster port");
                    return;
                }
                Err(_) => {
                    tracing::info!(%remote, "a TLS handshake on the cluster port timed out");
                    return;
                }
            };
            let identity = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .and_then(|leaf| PeerIdentity::from_der(leaf).ok());
            let Some(identity) = identity else {
                tracing::info!(%remote, "refused a connection without a node certificate");
                return;
            };
            let kill = KillSwitch::new();
            registry.sessions().track(identity.node, &kill);
            let peer = PeerInfo {
                identity,
                remote: Some(remote),
                kill,
            };
            let _ = tx.send(Ok(NodeStream::new(tls, peer))).await;
        });
    }
}
