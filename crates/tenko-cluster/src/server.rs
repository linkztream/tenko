//! The controller side of the node transport: the cluster port, its accept loop with the
//! mutual TLS handshake, and the router that serves the gRPC services of package
//! `tenko.cluster.v1`.
//!
//! This file holds the listener, the router and the helpers every service shares. Each
//! service is implemented in its own file under `service/` (see the table there), so work
//! packages edit disjoint files: the node services for [`ClusterService`], the controller
//! services `Raft` and `Cluster` for [`PeerService`](crate::peers::PeerService).
//!
//! Every call is checked twice: the TLS verifier refused certificates of another CA and
//! revoked serials during the handshake; each service then requires that the certificate's
//! node is enrolled and still holds that certificate ([`NodeRegistry::authenticate`], or
//! the peer check of the controller services). Errors carry the metadata entry
//! `tenko-error-code`.
//!
//! # One port, two start steps
//!
//! A member of a controller cluster opens its cluster port in the `cluster` start step,
//! before the vault: its peers replicate to it while it catches up. The node registry, and
//! with it the node services, exists only after the `nodes` step. The port therefore
//! serves the node services through [`NodeServices`], which answer `UNAVAILABLE`
//! (`cluster.port.starting`) until the `nodes` step attaches them; a node retries. A
//! single controller opens the port in the `nodes` step as before, with everything
//! attached at once ([`ClusterListener::serve`], [`ClusterListener::serve_port`]).
//!
//! At most [`MAX_HANDSHAKES`] TLS handshakes run at once per listener; a connection
//! beyond that is closed at once.

use std::{
    collections::HashMap,
    convert::Infallible,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
    task::{Context, Poll},
    time::Duration,
};

use futures::future::BoxFuture;
use rustls::{ServerConfig, pki_types::CertificateDer, server::ResolvesServerCert};
use tenko_core::{NodeId, Timestamp};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc, watch},
    task::JoinHandle,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tonic::{
    Request, Status, body::Body, codegen::http, metadata::MetadataValue, server::NamedService,
};

use crate::{
    error::ClusterError,
    mtls::{KillSwitch, NodeStream, PeerIdentity, PeerInfo, RevocationSet},
    peers::{PeerService, Peers},
    probe::ProbeSink,
    proto::v1,
    registry::NodeRegistry,
    session::Sessions,
};

/// Metadata entry with the stable error code of a refused call.
pub const ERROR_CODE_METADATA: &str = "tenko-error-code";
/// Metadata entry with the controller's protocol majors on a refused handshake.
pub const MAJORS_METADATA: &str = "tenko-majors";
/// Largest message on the cluster port (an observation batch, an append-entries request).
pub const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
/// How long a TLS handshake on the cluster port may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the server waits for its connections after the stop signal.
pub const STOP_GRACE: Duration = Duration::from_secs(5);
/// TLS handshakes in progress at once per listener.
pub const MAX_HANDSHAKES: usize = 128;

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

/// The gRPC services of the cluster port for data-plane nodes.
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
}

/// A service of the cluster port that answers `UNAVAILABLE` until it is attached.
struct Gated<S> {
    slot: Arc<OnceLock<S>>,
}

impl<S> Clone for Gated<S> {
    fn clone(&self) -> Self {
        Self {
            slot: Arc::clone(&self.slot),
        }
    }
}

impl<S: NamedService> NamedService for Gated<S> {
    const NAME: &'static str = S::NAME;
}

impl<S> tower::Service<http::Request<Body>> for Gated<S>
where
    S: tower::Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<http::Response<Body>, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        match self.slot.get() {
            Some(service) => {
                let service = service.clone();
                Box::pin(async move {
                    use tower::ServiceExt as _;
                    service.oneshot(request).await
                })
            }
            None => Box::pin(async {
                Ok(status_of(&ClusterError::new(
                    "cluster.port.starting",
                    503,
                    "the controller is still starting; try again in a few seconds",
                ))
                .into_http())
            }),
        }
    }
}

/// The node services of the cluster port, attached by the `nodes` start step.
#[derive(Clone, Default)]
pub struct NodeServices {
    handshake: Arc<OnceLock<v1::handshake_server::HandshakeServer<ClusterService>>>,
    node: Arc<OnceLock<v1::node_server::NodeServer<ClusterService>>>,
    observations: Arc<OnceLock<v1::observations_server::ObservationsServer<ClusterService>>>,
    config: Arc<OnceLock<v1::config_server::ConfigServer<ClusterService>>>,
    commands: Arc<OnceLock<v1::commands_server::CommandsServer<ClusterService>>>,
    metrics: Arc<OnceLock<v1::metrics_server::MetricsServer<ClusterService>>>,
}

impl std::fmt::Debug for NodeServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeServices")
            .field("attached", &self.is_attached())
            .finish()
    }
}

impl NodeServices {
    /// Services that answer `UNAVAILABLE` until [`NodeServices::attach`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Services that serve `service` at once.
    pub fn ready(service: &ClusterService) -> Self {
        let services = Self::new();
        services.attach(service);
        services
    }

    /// Whether the services are attached.
    pub fn is_attached(&self) -> bool {
        self.handshake.get().is_some()
    }

    /// Serves `service` from now on; a second call changes nothing.
    pub fn attach(&self, service: &ClusterService) {
        let _ = self.handshake.set(
            v1::handshake_server::HandshakeServer::new(service.clone())
                .max_decoding_message_size(64 * 1024),
        );
        let _ = self.node.set(
            v1::node_server::NodeServer::new(service.clone())
                .max_decoding_message_size(1024 * 1024),
        );
        let _ = self.observations.set(
            v1::observations_server::ObservationsServer::new(service.clone())
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
        );
        let _ = self.config.set(
            v1::config_server::ConfigServer::new(service.clone())
                .max_decoding_message_size(1024 * 1024)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
        );
        let _ = self.commands.set(
            v1::commands_server::CommandsServer::new(service.clone())
                .max_decoding_message_size(1024 * 1024),
        );
        let _ = self.metrics.set(
            v1::metrics_server::MetricsServer::new(service.clone())
                .max_decoding_message_size(1024 * 1024),
        );
    }
}

/// Everything a cluster port serves.
pub struct Port {
    /// The CA root client certificates must chain to.
    pub ca_root: CertificateDer<'static>,
    /// This controller's certificate.
    pub resolver: Arc<dyn ResolvesServerCert>,
    /// Revoked serials, checked at every handshake.
    pub revocations: Arc<RevocationSet>,
    /// The connections by node (a revocation closes them).
    pub sessions: Arc<Sessions>,
    /// The node services.
    pub nodes: NodeServices,
    /// The controller services `Raft` and `Cluster`, on a controller with a peer layer.
    pub peers: Option<Peers>,
}

impl std::fmt::Debug for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Port")
            .field("nodes", &self.nodes)
            .field("peers", &self.peers.is_some())
            .finish_non_exhaustive()
    }
}

fn router(nodes: &NodeServices, peers: Option<&PeerService>) -> tonic::transport::server::Router {
    let mut builder = tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(Duration::from_secs(20)))
        .http2_keepalive_timeout(Some(Duration::from_secs(20)));
    let mut router = builder
        .add_service(Gated {
            slot: Arc::clone(&nodes.handshake),
        })
        .add_service(Gated {
            slot: Arc::clone(&nodes.node),
        })
        .add_service(Gated {
            slot: Arc::clone(&nodes.observations),
        })
        .add_service(Gated {
            slot: Arc::clone(&nodes.config),
        })
        .add_service(Gated {
            slot: Arc::clone(&nodes.commands),
        })
        .add_service(Gated {
            slot: Arc::clone(&nodes.metrics),
        });
    if let Some(peers) = peers {
        // An append-entries request stays below the limit (the transport cuts larger
        // ones); a snapshot chunk is 1 MiB and a forwarded batch at most 16 MiB.
        router = router
            .add_service(
                v1::raft_server::RaftServer::new(peers.clone())
                    .max_decoding_message_size(MAX_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_MESSAGE_BYTES),
            )
            .add_service(
                v1::cluster_server::ClusterServer::new(peers.clone())
                    .max_decoding_message_size(MAX_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_MESSAGE_BYTES),
            );
    }
    router
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
    /// controller certificate and the registry's CA root and revocation set, then gRPC
    /// with the node services over the registry. Records the listening addresses in the
    /// registry.
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
        self.serve_with_peers(registry, sink, resolver, None, stop)
    }

    /// As [`ClusterListener::serve`], with the controller services of `peers` (the first
    /// controller of a cluster, which opens its port in the `nodes` step).
    ///
    /// # Errors
    ///
    /// The TLS configuration error.
    pub fn serve_with_peers(
        self,
        registry: &Arc<NodeRegistry>,
        sink: Arc<dyn ProbeSink>,
        resolver: Arc<dyn ResolvesServerCert>,
        peers: Option<Peers>,
        stop: watch::Receiver<bool>,
    ) -> Result<JoinHandle<()>, ClusterError> {
        let service = ClusterService::new(Arc::clone(registry), sink);
        let port = Port {
            ca_root: registry.ca().root_der().clone(),
            resolver,
            revocations: registry.revocations(),
            sessions: Arc::clone(registry.sessions()),
            nodes: NodeServices::ready(&service),
            peers,
        };
        registry.set_listening(self.local_addrs());
        let registry = Arc::clone(registry);
        self.serve_port(port, stop, move || registry.set_listening(Vec::new()))
    }

    /// Serves `port` until `stop` turns true, then calls `stopped`.
    ///
    /// # Errors
    ///
    /// The TLS configuration error.
    pub fn serve_port(
        self,
        port: Port,
        stop: watch::Receiver<bool>,
        stopped: impl FnOnce() + Send + 'static,
    ) -> Result<JoinHandle<()>, ClusterError> {
        let config = crate::mtls::server_config(
            &port.ca_root,
            port.resolver,
            Arc::clone(&port.revocations),
        )?;
        let addrs = self.local_addrs();
        tracing::info!(
            addresses = %addrs.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
            controller_services = port.peers.is_some(),
            "cluster port listening (gRPC over mutual TLS)"
        );
        let peers = port.peers.as_ref().map(Peers::service);
        let router = router(&port.nodes, peers.as_ref());
        Ok(tokio::spawn(async move {
            run(self.listeners, config, router, port.sessions, stop).await;
            stopped();
        }))
    }
}

type Incoming = io::Result<NodeStream<TlsStream<TcpStream>>>;

async fn run(
    listeners: Vec<TcpListener>,
    config: Arc<ServerConfig>,
    router: tonic::transport::server::Router,
    sessions: Arc<Sessions>,
    stop: watch::Receiver<bool>,
) {
    let (tx, mut rx) = mpsc::channel::<Incoming>(64);
    let mut loops = Vec::with_capacity(listeners.len());
    for listener in listeners {
        loops.push(tokio::spawn(accept_loop(
            listener,
            Arc::clone(&config),
            tx.clone(),
            Arc::clone(&sessions),
            stop.clone(),
        )));
    }
    drop(tx);
    let incoming = futures::stream::poll_fn(move |cx| rx.poll_recv(cx));
    let mut stopped = stop.clone();
    let (trigger, triggered) = tokio::sync::oneshot::channel::<()>();
    let server = router.serve_with_incoming_shutdown(incoming, async move {
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
            sessions.kill_all();
            if tokio::time::timeout(STOP_GRACE, &mut server).await.is_err() {
                tracing::warn!("the cluster port did not stop in time");
            }
        }
    }
    for accept in loops {
        accept.abort();
        let _ = accept.await;
    }
    tracing::info!("cluster port stopped");
}

async fn accept_loop(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    tx: mpsc::Sender<Incoming>,
    sessions: Arc<Sessions>,
    mut stop: watch::Receiver<bool>,
) {
    let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));
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
        let Ok(permit) = Arc::clone(&handshakes).try_acquire_owned() else {
            tracing::debug!(%remote, "too many TLS handshakes in progress; closed a connection");
            continue;
        };
        let acceptor = TlsAcceptor::from(Arc::clone(&config));
        let tx = tx.clone();
        let sessions = Arc::clone(&sessions);
        let local = tcp.local_addr().ok();
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await;
            drop(permit);
            let tls = match handshake {
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
            sessions.track(identity.node, &kill);
            let peer = PeerInfo {
                identity,
                remote: Some(remote),
                local,
                kill,
            };
            let _ = tx.send(Ok(NodeStream::new(tls, peer))).await;
        });
    }
}

/// Runs the decoding and the checks the services of the cluster port apply to a request
/// before it reaches the registry or the store, beyond the Raft payloads of
/// [`wire::fuzz_payload`](crate::wire::fuzz_payload) and the node-sync payloads of
/// [`node_sync::payload::fuzz_payload`](crate::node_sync::payload::fuzz_payload): the first
/// byte picks the request, the rest is the input. Kind 6 reads the rest as the DER
/// certificate a caller presented. The entry point of the fuzz target `cluster_messages`;
/// it never panics on any input.
pub fn fuzz_request(data: &[u8]) {
    use prost::Message as _;

    use crate::{
        ca::csr_public_key,
        identity::split_host_port,
        mtls::PeerIdentity,
        probe::{ProbeBatch, run_of, timestamp_from_proto},
        proto::v1,
        version,
    };

    let Some((&kind, input)) = data.split_first() else {
        return;
    };
    match kind % 7 {
        0 => {
            if let Ok(hello) = v1::HelloRequest::decode(input) {
                for ours in [&[1][..], &[1, 2, 4]] {
                    if let Err(mismatch) = version::negotiate(ours, &hello.majors) {
                        drop(mismatch.detail("the controller", "the node"));
                        let _ = mismatch.newer();
                    }
                }
                drop(version::format_majors(&hello.majors));
            }
        }
        1 => {
            if let Ok(beat) = v1::Beat::decode(input) {
                let _ = beat
                    .certificate_not_after
                    .as_ref()
                    .and_then(timestamp_from_proto);
            }
        }
        2 => {
            if let Ok(renew) = v1::RenewRequest::decode(input) {
                drop(csr_public_key(&renew.csr));
            }
        }
        3 => {
            if let Ok(join) = v1::JoinRequest::decode(input) {
                drop(split_host_port(&join.address));
            }
        }
        4 => {
            if let Ok(ingest) = v1::IngestRequest::decode(input) {
                let _ = run_of(&ingest);
                drop(ProbeBatch::from_request(ingest));
            }
        }
        5 => {
            if let Ok(subscribe) = v1::SubscribeRequest::decode(input) {
                drop(subscribe.after.parse::<uuid::Uuid>());
            }
            drop(v1::SecretsRequest::decode(input));
            drop(v1::DigestRequest::decode(input));
            drop(v1::MembersRequest::decode(input));
            drop(v1::CampaignRequest::decode(input));
            drop(v1::ReadIndexRequest::decode(input));
            drop(v1::SnapshotRequest::decode(input));
        }
        _ => drop(PeerIdentity::from_der(input)),
    }
}

#[cfg(test)]
mod tests {
    use prost::Message as _;
    use tenko_core::{NodeId, Role};

    use super::fuzz_request;
    use crate::{
        ca::{self, csr_public_key},
        identity::split_host_port,
        mtls::PeerIdentity,
        probe::ProbeBatch,
        proto::v1,
        version,
    };

    /// A certificate of node 1001 with the role `probe`, as a caller presents it.
    fn peer_certificate() -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.subject_alt_names = vec![
            rcgen::SanType::URI(ca::node_uri(NodeId(1001)).try_into().expect("uri")),
            rcgen::SanType::URI(ca::role_uri(Role::Probe).try_into().expect("uri")),
        ];
        let key = rcgen::KeyPair::generate().expect("key");
        params
            .self_signed(&key)
            .expect("certificate")
            .der()
            .to_vec()
    }

    fn timestamp(seconds: i64) -> prost_types::Timestamp {
        prost_types::Timestamp { seconds, nanos: 0 }
    }

    /// One request of every kind `fuzz_request` reads, each behind its selector, that
    /// passes the checks the selector runs.
    fn seeds() -> Vec<(&'static str, u8, Vec<u8>)> {
        let hello = |majors: Vec<u32>| {
            v1::HelloRequest {
                majors,
                version: "1.4.0".to_owned(),
                roles: vec!["dns".to_owned(), "dhcp".to_owned()],
                capabilities: Vec::new(),
            }
            .encode_to_vec()
        };
        let batch: ProbeBatch = serde_json::from_str(
            r#"{
                "method": "arp",
                "complete": true,
                "collected_at": "2026-10-10T08:00:05Z",
                "sightings": [
                    {"observed_at": "2026-10-10T08:00:01Z", "ttl_secs": 600,
                     "subject": {"type": "address", "data": {"ip": "192.0.2.30", "mac": "00:00:5e:00:53:30"}}},
                    {"observed_at": "2026-10-10T08:00:02Z",
                     "subject": {"type": "address", "data": {"ip": "2001:db8::30"}}}
                ]
            }"#,
        )
        .expect("batch");
        let mut ingest = batch.to_request();
        ingest.epoch = "0b6f2c1e-55c3-4f0e-9a51-2f1d3c4b5a69".to_owned();
        ingest.sequence = 12;
        ingest.run = Some("6a1f0b9e-3c2d-4e5f-8a7b-9c0d1e2f3a4b".to_owned());
        let (_, csr) = ca::generate_csr().expect("csr");
        vec![
            ("hello", 0, hello(vec![1])),
            ("hello-newer", 0, hello(vec![1, 2, 3])),
            (
                "beat",
                1,
                v1::Beat {
                    sequence: 7,
                    version: "1.4.0".to_owned(),
                    roles: vec!["probe".to_owned()],
                    major: 1,
                    buffered_batches: 2,
                    buffered_bytes: 4096,
                    dropped_batches: 0,
                    certificate_not_after: Some(timestamp(1_790_000_000)),
                    sent_at: Some(timestamp(1_760_000_000)),
                }
                .encode_to_vec(),
            ),
            ("renew", 2, v1::RenewRequest { csr }.encode_to_vec()),
            (
                "join",
                3,
                v1::JoinRequest {
                    node_id: 1002,
                    address: "ctl-2.example.test:8444".to_owned(),
                    version: "1.4.0".to_owned(),
                    capabilities: Vec::new(),
                    data_format: 1,
                }
                .encode_to_vec(),
            ),
            (
                "join-ipv6",
                3,
                v1::JoinRequest {
                    node_id: 1003,
                    address: "[2001:db8::3]:8444".to_owned(),
                    ..v1::JoinRequest::default()
                }
                .encode_to_vec(),
            ),
            ("ingest", 4, ingest.encode_to_vec()),
            (
                "subscribe",
                5,
                v1::SubscribeRequest {
                    after: "6a1f0b9e-3c2d-4e5f-8a7b-9c0d1e2f3a4b".to_owned(),
                }
                .encode_to_vec(),
            ),
            (
                "secrets",
                5,
                v1::SecretsRequest {
                    purposes: vec!["dns.tsig".to_owned()],
                }
                .encode_to_vec(),
            ),
            ("peer-certificate", 6, peer_certificate()),
        ]
    }

    /// The check a seed is meant to pass.
    fn passes(kind: u8, input: &[u8]) -> bool {
        match kind {
            0 => v1::HelloRequest::decode(input)
                .is_ok_and(|hello| version::negotiate(&[1], &hello.majors).is_ok()),
            1 => v1::Beat::decode(input).is_ok_and(|beat| beat.certificate_not_after.is_some()),
            2 => v1::RenewRequest::decode(input)
                .is_ok_and(|renew| csr_public_key(&renew.csr).is_ok()),
            3 => v1::JoinRequest::decode(input)
                .is_ok_and(|join| join.node_id != 0 && split_host_port(&join.address).is_ok()),
            4 => v1::IngestRequest::decode(input).is_ok_and(|ingest| {
                ProbeBatch::from_request(ingest).is_ok_and(|(_, skipped)| skipped == 0)
            }),
            5 => v1::SubscribeRequest::decode(input).is_ok(),
            6 => PeerIdentity::from_der(input)
                .is_ok_and(|peer| peer.node == NodeId(1001) && peer.roles.contains(Role::Probe)),
            _ => false,
        }
    }

    #[test]
    fn the_fuzz_entry_point_survives_garbage() {
        fuzz_request(&[]);
        for kind in 0..7_u8 {
            for data in [
                &b""[..],
                b"\x00",
                b"\xff\xff\xff\xff",
                b"\x0a\x80\x80\x80\x80\x10",
            ] {
                let mut input = vec![kind];
                input.extend_from_slice(data);
                fuzz_request(&input);
            }
        }
    }

    /// The seeds of the fuzz target `cluster_messages` pass their checks; with
    /// `TENKO_FUZZ_SEEDS` set to a directory they are written there
    /// (`fuzz/seeds/cluster_messages/`), one file each.
    #[test]
    fn fuzz_seeds_pass() {
        let seeds = seeds();
        let kinds: std::collections::BTreeSet<u8> = seeds.iter().map(|seed| seed.1).collect();
        assert_eq!(kinds.len(), 7, "every selector has a seed");
        let out = std::env::var_os("TENKO_FUZZ_SEEDS").map(std::path::PathBuf::from);
        for (name, kind, payload) in seeds {
            assert!(passes(kind, &payload), "the seed {name} does not pass");
            let mut data = vec![kind];
            data.extend_from_slice(&payload);
            fuzz_request(&data);
            if let Some(dir) = &out {
                std::fs::create_dir_all(dir).expect("seed directory");
                std::fs::write(dir.join(name), &data).expect("seed");
            }
        }
    }
}
