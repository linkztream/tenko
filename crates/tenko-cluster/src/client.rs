//! The node side of the node transport: the supervised connection of a data-plane node to
//! its controllers (OPS-04, OPS-08, OPS-28).
//!
//! [`Agent::run`] dials the cluster endpoints in turn over mutual TLS, agrees on a
//! protocol major ([`Hello`](crate::proto::v1::handshake_client)), keeps a heartbeat
//! stream open, sends the observation buffer oldest first (one batch at a time, removed
//! only once the controller confirmed it), and renews the certificate before it expires.
//! A broken connection is retried with a growing, jittered pause (1 s up to 60 s); while
//! the controller is away, probes keep filling the buffer, which replays in order on the
//! next connection. Refusals that a retry cannot fix (no common protocol major, an unknown
//! node, a controller of another CA, a revocation) are reported in the status file and
//! retried only every few minutes.
//!
//! Producers (the scanner of WP2.3) put batches into the buffer with
//! [`Agent::outbox`]; other processes on the host drop batches into the buffer's
//! `incoming/` directory ([`crate::buffer::ObservationBuffer::drop_incoming`]), which the
//! agent adopts every second.

use std::{
    io,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use futures::StreamExt;
use rustls::{
    ClientConfig,
    pki_types::{CertificateDer, pem::PemObject as _},
};
use tenko_core::Timestamp;
use tokio::{
    net::TcpStream,
    sync::{mpsc, watch},
};
use tokio_rustls::TlsConnector;
use tonic::transport::Channel;

use crate::{
    buffer::{BufferConfig, ObservationBuffer},
    ca::generate_csr,
    error::ClusterError,
    identity::{AgentState, AgentStatus, Credentials, NodePaths, StatusError, split_host_port},
    probe::{ProbeBatch, timestamp_from_proto, timestamp_to_proto},
    proto::v1,
    server::{MAJORS_METADATA, MAX_MESSAGE_BYTES, code_of},
    version,
};

/// Timeout of one TCP connect and TLS handshake.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout of one call (an ingest of a large batch may take a while).
pub const CALL_TIMEOUT: Duration = Duration::from_secs(120);
/// Shortest pause between two connection attempts.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// Longest pause between two connection attempts.
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Pause after a refusal a retry cannot fix soon.
pub const REFUSED_PAUSE: Duration = Duration::from_secs(300);
/// How often a connected node rewrites its status file when nothing else changed.
pub const STATUS_REFRESH: Duration = Duration::from_secs(60);
/// Pause between two renewal attempts while the certificate is due.
pub const RENEW_RETRY: Duration = Duration::from_secs(3600);
/// How often the agent looks into `incoming/`.
pub const ADOPT_INTERVAL: Duration = Duration::from_secs(1);

/// Settings of a node process.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// The node's files.
    pub paths: NodePaths,
    /// The software version reported to controllers.
    pub version: String,
    /// The protocol majors offered in the handshake.
    pub majors: Vec<u32>,
    /// The observation buffer.
    pub buffer: BufferConfig,
    /// Shortest pause between two connection attempts.
    pub backoff_min: Duration,
    /// Longest pause.
    pub backoff_max: Duration,
    /// Pause after a refusal (protocol, unknown node, foreign CA, revocation).
    pub refused_pause: Duration,
}

impl AgentConfig {
    /// The defaults for a node whose data directory holds `paths`.
    pub fn new(paths: NodePaths, version: impl Into<String>) -> Self {
        let buffer = BufferConfig::new(paths.buffer());
        Self {
            paths,
            version: version.into(),
            majors: version::SUPPORTED_MAJORS.to_vec(),
            buffer,
            backoff_min: BACKOFF_MIN,
            backoff_max: BACKOFF_MAX,
            refused_pause: REFUSED_PAUSE,
        }
    }
}

/// Why a session with a controller ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// The node is stopping.
    Stopped,
    /// The connection broke or could not be made; try again soon.
    Broken(StatusError),
    /// The controller refused in a way a quick retry does not fix.
    Refused(AgentState, StatusError),
}

fn status_error(code: &str, detail: impl Into<String>) -> StatusError {
    StatusError {
        code: code.to_owned(),
        detail: detail.into(),
        at: Timestamp::now(),
    }
}

/// What a handshake agreed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agreed {
    /// The protocol major.
    pub major: u32,
    /// The controller's software version.
    pub controller_version: String,
    /// Seconds between heartbeats.
    pub heartbeat_secs: u32,
    /// The endpoint.
    pub endpoint: String,
}

/// Classifies a failed connection: a controller of another CA, a revoked certificate, or a
/// plain transport failure.
pub fn classify_transport(error: &(dyn std::error::Error + 'static)) -> (AgentState, StatusError) {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = cause {
        let tls = current.downcast_ref::<rustls::Error>().or_else(|| {
            current
                .downcast_ref::<io::Error>()
                .and_then(|io| io.get_ref())
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        });
        if let Some(tls) = tls {
            return classify_tls(tls);
        }
        cause = current.source();
    }
    // HTTP/2 passes TLS alerts on as text, so the structured error is gone by the time a
    // call fails; the alert names are stable.
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = cause {
        if let Some(classified) = classify_text(&current.to_string()) {
            return classified;
        }
        cause = current.source();
    }
    (
        AgentState::Disconnected,
        status_error(
            "cluster.connect",
            match root_cause(error) {
                Some(cause) => format!("cannot reach the controller: {error}: {cause}"),
                None => format!("cannot reach the controller: {error}"),
            },
        ),
    )
}

fn classify_text(text: &str) -> Option<(AgentState, StatusError)> {
    use rustls::{AlertDescription, CertificateError, Error};
    let error = if text.contains("CertificateRevoked") {
        Error::AlertReceived(AlertDescription::CertificateRevoked)
    } else if text.contains("UnknownIssuer") || text.contains("BadSignature") {
        Error::InvalidCertificate(CertificateError::UnknownIssuer)
    } else if text.contains("ApplicationVerificationFailure") {
        Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
    } else if [
        "UnknownCA",
        "BadCertificate",
        "CertificateExpired",
        "CertificateUnknown",
        "AccessDenied",
    ]
    .iter()
    .any(|alert| text.contains(alert))
    {
        Error::AlertReceived(AlertDescription::UnknownCA)
    } else {
        return None;
    };
    Some(classify_tls(&error))
}

fn classify_tls(error: &rustls::Error) -> (AgentState, StatusError) {
    use rustls::{AlertDescription, CertificateError, Error};
    match error {
        Error::InvalidCertificate(
            CertificateError::UnknownIssuer | CertificateError::BadSignature,
        ) => (
            AgentState::Refused,
            status_error(
                "cluster.tls.foreign_ca",
                "the controller's certificate does not come from this node's CA; it belongs to \
                 another installation, or the CA was created again (enrol the node again)",
            ),
        ),
        Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure) => (
            AgentState::Refused,
            status_error(
                "cluster.tls.not_a_controller",
                "the server on the cluster port is not a Tenko controller",
            ),
        ),
        Error::AlertReceived(AlertDescription::CertificateRevoked) => (
            AgentState::Revoked,
            status_error(
                "cluster.node.revoked",
                "the controller refused this node's certificate as revoked; enrol the node again",
            ),
        ),
        Error::AlertReceived(
            AlertDescription::UnknownCA
            | AlertDescription::BadCertificate
            | AlertDescription::CertificateExpired
            | AlertDescription::CertificateUnknown
            | AlertDescription::AccessDenied,
        ) => (
            AgentState::Refused,
            status_error(
                "cluster.tls.refused",
                format!("the controller refused this node's certificate ({error})"),
            ),
        ),
        other => (
            AgentState::Disconnected,
            status_error("cluster.tls", format!("the TLS handshake failed: {other}")),
        ),
    }
}

async fn dial(
    target: String,
    config: Arc<ClientConfig>,
) -> io::Result<hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<TcpStream>>> {
    let (host, port) = split_host_port(&target)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, format!("{target} did not answer"))
        })??;
    let _ = tcp.set_nodelay(true);
    let tls = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(config).connect(crate::mtls::server_name(&host), tcp),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the TLS handshake timed out"))??;
    if tls.get_ref().1.alpn_protocol() != Some(crate::mtls::ALPN_H2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the cluster port did not agree on HTTP/2",
        ));
    }
    Ok(hyper_util::rt::TokioIo::new(tls))
}

/// Opens a gRPC channel to one cluster endpoint over mutual TLS.
///
/// # Errors
///
/// The transport error (see [`classify_transport`]).
pub async fn connect(
    target: &str,
    config: Arc<ClientConfig>,
) -> Result<Channel, tonic::transport::Error> {
    let target = target.to_owned();
    tonic::transport::Endpoint::from_static("http://tenko-cluster.invalid")
        .connect_timeout(CONNECT_TIMEOUT)
        .http2_keep_alive_interval(Duration::from_secs(20))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true)
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            dial(target.clone(), Arc::clone(&config))
        }))
        .await
}

fn refused_status(status: &tonic::Status) -> (AgentState, StatusError) {
    let code = code_of(status).unwrap_or("cluster.call").to_owned();
    let state = match code.as_str() {
        "cluster.protocol.unsupported" => AgentState::ProtocolMismatch,
        "cluster.node.unknown" | "cluster.node.certificate_unknown" => AgentState::Refused,
        _ => match status.code() {
            tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => AgentState::Refused,
            _ => AgentState::Disconnected,
        },
    };
    if state == AgentState::Disconnected
        && let Some(error) = std::error::Error::source(status)
    {
        let (tls_state, tls_error) = classify_transport(error);
        if tls_state != AgentState::Disconnected {
            return (tls_state, tls_error);
        }
    }
    let mut detail = status.message().to_owned();
    if let Some(cause) = root_cause(status) {
        detail = format!("{detail}: {cause}");
    }
    if let Some(majors) = status
        .metadata()
        .get(MAJORS_METADATA)
        .and_then(|value| value.to_str().ok())
    {
        detail = format!("{detail} (the controller implements {majors})");
    }
    (state, status_error(&code, detail))
}

/// The innermost cause of an error, when it says more than the error itself.
fn root_cause(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut cause = error.source()?;
    while let Some(next) = cause.source() {
        cause = next;
    }
    Some(cause.to_string())
}

/// Says hello on a channel.
///
/// # Errors
///
/// The refusal, classified.
pub async fn hello(
    channel: Channel,
    majors: &[u32],
    version: &str,
    credentials: &Credentials,
    endpoint: &str,
) -> Result<Agreed, (AgentState, StatusError)> {
    let mut client = v1::handshake_client::HandshakeClient::new(channel);
    let response = client
        .hello(v1::HelloRequest {
            majors: majors.to_vec(),
            version: version.to_owned(),
            roles: credentials
                .identity
                .roles
                .iter()
                .map(|role| role.as_str().to_owned())
                .collect(),
            capabilities: Vec::new(),
        })
        .await
        .map_err(|status| refused_status(&status))?
        .into_inner();
    if !majors.contains(&response.major) {
        return Err((
            AgentState::ProtocolMismatch,
            status_error(
                "cluster.protocol.unsupported",
                format!(
                    "the controller chose protocol major {}, which this node does not implement",
                    response.major
                ),
            ),
        ));
    }
    Ok(Agreed {
        major: response.major,
        controller_version: response.version,
        heartbeat_secs: response.heartbeat_secs.clamp(1, 3600),
        endpoint: endpoint.to_owned(),
    })
}

/// Renews the node certificate over `channel` and writes the new pair.
///
/// # Errors
///
/// The refusal, or a file error.
pub async fn renew(
    channel: Channel,
    credentials: &Credentials,
    paths: &NodePaths,
) -> Result<Credentials, ClusterError> {
    let (key, csr) = generate_csr()?;
    let mut client = v1::node_client::NodeClient::new(channel);
    let response = client
        .renew(v1::RenewRequest { csr })
        .await
        .map_err(|status| {
            let (_, error) = refused_status(&status);
            ClusterError::new("cluster.node.renew", 502, error.detail)
        })?
        .into_inner();
    let chain = CertificateDer::pem_slice_iter(response.certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            ClusterError::new(
                "cluster.node.renew",
                502,
                format!("the controller sent an unreadable certificate: {error}"),
            )
        })?;
    if chain.is_empty() {
        return Err(ClusterError::new(
            "cluster.node.renew",
            502,
            "the controller sent no certificate",
        ));
    }
    let next = credentials.renewed(paths, chain, key)?;
    tracing::info!(not_after = %next.info.not_after, "node certificate renewed");
    Ok(next)
}

/// The node process: supervised connection, heartbeats, buffer replay, renewal.
pub struct Agent {
    config: AgentConfig,
    buffer: ObservationBuffer,
    credentials: Mutex<Arc<Credentials>>,
    status: Mutex<AgentStatus>,
    renew_now: tokio::sync::Notify,
    /// Set when a session got past the handshake; read and cleared after it ends, so a
    /// connection that worked resets the pause between attempts.
    connected: std::sync::atomic::AtomicBool,
    /// The modification time of the certificate file the credentials came from.
    loaded: Mutex<Option<std::time::SystemTime>>,
    /// When the status file was last written.
    written: Mutex<Option<std::time::Instant>>,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("paths", &self.config.paths)
            .finish_non_exhaustive()
    }
}

impl Agent {
    /// Loads the credentials and opens the buffer.
    ///
    /// # Errors
    ///
    /// `cluster.node.not_enrolled`, a file error, or a buffer error.
    pub fn new(config: AgentConfig) -> Result<Arc<Self>, ClusterError> {
        let paths_certificate = config.paths.certificate();
        let credentials = Credentials::load(&config.paths)?;
        let buffer = ObservationBuffer::open(config.buffer.clone())?;
        let now = Timestamp::now();
        let status = AgentStatus {
            state: AgentState::Connecting,
            endpoint: None,
            since: now,
            updated_at: now,
            major: None,
            controller_version: None,
            last_error: None,
            buffer: Some(buffer.stats()),
            certificate_not_after: Some(credentials.info.not_after),
            pid: std::process::id(),
        };
        Ok(Arc::new(Self {
            config,
            buffer,
            credentials: Mutex::new(Arc::new(credentials)),
            status: Mutex::new(status),
            renew_now: tokio::sync::Notify::new(),
            connected: std::sync::atomic::AtomicBool::new(false),
            loaded: Mutex::new(modified(&paths_certificate)),
            written: Mutex::new(None),
        }))
    }

    /// The buffer probes put their batches into.
    pub fn outbox(&self) -> &ObservationBuffer {
        &self.buffer
    }

    /// Queues a batch for the controller.
    ///
    /// # Errors
    ///
    /// A buffer error (the batch is too large, the disk fails).
    pub fn push(&self, batch: &ProbeBatch) -> Result<u64, ClusterError> {
        Ok(self.buffer.push(&batch.encode())?)
    }

    /// The node's credentials.
    pub fn credentials(&self) -> Arc<Credentials> {
        Arc::clone(
            &self
                .credentials
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// The current status.
    pub fn status(&self) -> AgentStatus {
        self.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_status(&self, change: impl FnOnce(&mut AgentStatus)) {
        let snapshot = {
            let mut status = self.status.lock().unwrap_or_else(PoisonError::into_inner);
            let before = status.state;
            change(&mut status);
            let now = Timestamp::now();
            if status.state != before {
                status.since = now;
            }
            status.updated_at = now;
            status.buffer = Some(self.buffer.stats());
            status.clone()
        };
        if let Err(error) = snapshot.save(&self.config.paths) {
            tracing::debug!(%error, "the status file could not be written");
        }
        *self.written.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(std::time::Instant::now());
    }

    /// Writes the status file again when it is older than [`STATUS_REFRESH`] (heartbeats).
    fn refresh_status(&self) {
        let due = self
            .written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none_or(|at| at.elapsed() >= STATUS_REFRESH);
        if due {
            self.set_status(|_| {});
        }
    }

    /// Runs until `stop` turns true.
    pub async fn run(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        let adopter = tokio::spawn(Arc::clone(&self).adopt(stop.clone()));
        let mut backoff = self.config.backoff_min;
        let mut next_target = 0usize;
        loop {
            if *stop.borrow() {
                break;
            }
            self.reload_credentials();
            let credentials = self.credentials();
            let targets = credentials.identity.dial_targets();
            if targets.is_empty() {
                self.set_status(|status| {
                    status.state = AgentState::Refused;
                    status.last_error = Some(status_error(
                        "cluster.node.endpoint",
                        "the node knows no cluster endpoint; enrol it again",
                    ));
                });
                break;
            }
            let target = targets[next_target % targets.len()].clone();
            next_target = next_target.wrapping_add(1);
            self.set_status(|status| {
                status.state = AgentState::Connecting;
                status.endpoint = Some(target.clone());
            });
            let end = self.session(&target, &mut stop).await;
            if self.connected_once() {
                backoff = self.config.backoff_min;
            }
            let pause = match end {
                SessionEnd::Stopped => break,
                SessionEnd::Broken(error) => {
                    tracing::info!(endpoint = %target, code = %error.code, "{}", error.detail);
                    self.set_status(|status| {
                        status.state = AgentState::Disconnected;
                        status.last_error = Some(error);
                    });
                    let pause = jitter(backoff);
                    backoff = (backoff * 2).min(self.config.backoff_max);
                    pause
                }
                SessionEnd::Refused(state, error) => {
                    tracing::warn!(endpoint = %target, code = %error.code, "{}", error.detail);
                    self.set_status(|status| {
                        status.state = state;
                        status.last_error = Some(error);
                    });
                    self.config.refused_pause
                }
            };
            tokio::select! {
                () = tokio::time::sleep(pause) => {}
                () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => break,
            }
        }
        adopter.abort();
        let _ = adopter.await;
        self.set_status(|status| status.state = AgentState::Stopped);
        tracing::info!("node process stopped");
    }

    fn connected_once(&self) -> bool {
        self.connected
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    /// Loads the credentials again when the certificate file changed (`tenko node renew`
    /// ran beside the node process).
    fn reload_credentials(&self) {
        let now = modified(&self.config.paths.certificate());
        let mut loaded = self.loaded.lock().unwrap_or_else(PoisonError::into_inner);
        if now.is_none() || *loaded == now {
            return;
        }
        match Credentials::load(&self.config.paths) {
            Ok(fresh) => {
                tracing::info!(serial = %fresh.info.serial, "loaded the renewed node certificate");
                *self
                    .credentials
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = Arc::new(fresh);
                *loaded = now;
            }
            Err(error) => {
                tracing::warn!(code = %error.code(), "the node certificate files changed but do not load: {}", error.detail());
            }
        }
    }

    /// Moves batches other processes dropped into `incoming/` into the buffer, every
    /// [`ADOPT_INTERVAL`], connected or not.
    async fn adopt(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        let mut tick = tokio::time::interval(ADOPT_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
                _ = tick.tick() => {}
            }
            let buffer = self.buffer.clone();
            match tokio::task::spawn_blocking(move || buffer.adopt_incoming()).await {
                Ok(Ok(0)) => {}
                Ok(Ok(count)) => {
                    tracing::info!(count, "queued batches from the incoming directory");
                    self.set_status(|_| {});
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "batches in the incoming directory could not be adopted");
                }
                Err(error) => tracing::error!(%error, "the buffer task failed"),
            }
        }
    }

    /// One connection: hello, then heartbeats, buffer replay and renewal until something
    /// breaks or `stop` turns true.
    #[allow(
        clippy::too_many_lines,
        reason = "one select loop over the parts of a session"
    )]
    async fn session(&self, target: &str, stop: &mut watch::Receiver<bool>) -> SessionEnd {
        let credentials = self.credentials();
        let config = match credentials.client_config() {
            Ok(config) => config,
            Err(error) => {
                return SessionEnd::Refused(
                    AgentState::Refused,
                    status_error(error.code(), error.detail()),
                );
            }
        };
        let channel = match connect(target, config).await {
            Ok(channel) => channel,
            Err(error) => {
                return match classify_transport(&error) {
                    (AgentState::Disconnected, error) => SessionEnd::Broken(error),
                    (state, error) => SessionEnd::Refused(state, error),
                };
            }
        };
        let agreed = match hello(
            channel.clone(),
            &self.config.majors,
            &self.config.version,
            &credentials,
            target,
        )
        .await
        {
            Ok(agreed) => agreed,
            Err((AgentState::Disconnected, error)) => return SessionEnd::Broken(error),
            Err((state, error)) => return SessionEnd::Refused(state, error),
        };
        tracing::info!(
            endpoint = %target,
            major = agreed.major,
            controller = %agreed.controller_version,
            "connected to the controller"
        );
        self.connected
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.set_status(|status| {
            status.state = AgentState::Connected;
            status.major = Some(agreed.major);
            status.controller_version = Some(agreed.controller_version.clone());
            status.last_error = None;
        });
        let (beats, outbound) = mpsc::channel::<v1::Beat>(4);
        let mut node_client = v1::node_client::NodeClient::new(channel.clone());
        let outbound = futures::stream::poll_fn({
            let mut outbound = outbound;
            move |cx| outbound.poll_recv(cx)
        });
        let mut directives = match node_client.heartbeat(outbound).await {
            Ok(response) => response.into_inner(),
            Err(status) => {
                return match refused_status(&status) {
                    (AgentState::Disconnected, error) => SessionEnd::Broken(error),
                    (state, error) => SessionEnd::Refused(state, error),
                };
            }
        };
        let interval = Duration::from_secs(u64::from(agreed.heartbeat_secs));
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut sequence = 0u64;
        let mut last_renewal: Option<std::time::Instant> = None;
        let sender = self.send_buffer(channel.clone());
        tokio::pin!(sender);
        loop {
            tokio::select! {
                () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => {
                    return SessionEnd::Stopped;
                }
                _ = ticker.tick() => {
                    sequence += 1;
                    let due = self.credentials().needs_renewal(Timestamp::now());
                    if due && last_renewal.is_none_or(|at: std::time::Instant| at.elapsed() >= RENEW_RETRY) {
                        last_renewal = Some(std::time::Instant::now());
                        self.renew_now.notify_one();
                    }
                    let stats = self.buffer.stats();
                    let beat = v1::Beat {
                        sequence,
                        version: self.config.version.clone(),
                        roles: credentials.identity.roles.iter().map(|role| role.as_str().to_owned()).collect(),
                        major: agreed.major,
                        buffered_batches: stats.batches,
                        buffered_bytes: stats.bytes,
                        dropped_batches: stats.dropped,
                        certificate_not_after: Some(timestamp_to_proto(self.credentials().info.not_after)),
                        sent_at: Some(timestamp_to_proto(Timestamp::now())),
                    };
                    if beats.send(beat).await.is_err() {
                        return SessionEnd::Broken(status_error("cluster.heartbeat", "the heartbeat stream closed"));
                    }
                    self.refresh_status();
                }
                directive = directives.next() => {
                    match directive {
                        Some(Ok(directive)) => {
                            if directive.revoked {
                                return SessionEnd::Refused(
                                    AgentState::Revoked,
                                    status_error("cluster.node.revoked", if directive.detail.is_empty() {
                                        "this node was revoked; enrol it again".to_owned()
                                    } else {
                                        directive.detail
                                    }),
                                );
                            }
                            if directive.renew {
                                self.renew_now.notify_one();
                            }
                            if let Some(at) = directive.server_time.as_ref().and_then(timestamp_from_proto) {
                                let skew = at.0 - Timestamp::now().0;
                                if skew.whole_seconds().abs() > 300 {
                                    tracing::warn!(skew_secs = skew.whole_seconds(), "the clocks of this node and the controller differ by more than five minutes");
                                }
                            }
                        }
                        Some(Err(status)) => {
                            return match refused_status(&status) {
                                (AgentState::Disconnected, error) => SessionEnd::Broken(error),
                                (state, error) => SessionEnd::Refused(state, error),
                            };
                        }
                        None => {
                            return SessionEnd::Broken(status_error("cluster.heartbeat", "the controller closed the heartbeat stream"));
                        }
                    }
                }
                () = self.renew_now.notified() => {
                    match renew(channel.clone(), &self.credentials(), &self.config.paths).await {
                        Ok(next) => {
                            *self.credentials.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
                            self.set_status(|status| status.certificate_not_after = Some(self.credentials().info.not_after));
                        }
                        Err(error) => tracing::warn!(code = %error.code(), "renewal failed: {}", error.detail()),
                    }
                }
                end = &mut sender => return end,
            }
        }
    }

    /// Sends the buffer oldest first, one batch at a time, until a call fails.
    async fn send_buffer(&self, channel: Channel) -> SessionEnd {
        let mut client = v1::observations_client::ObservationsClient::new(channel)
            .max_encoding_message_size(MAX_MESSAGE_BYTES)
            .max_decoding_message_size(MAX_MESSAGE_BYTES);
        let epoch = self.buffer.epoch().to_string();
        let mut adopt = tokio::time::interval(ADOPT_INTERVAL);
        adopt.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let buffer = self.buffer.clone();
            let pending = tokio::task::spawn_blocking(move || buffer.peek()).await;
            let pending = match pending {
                Ok(Ok(pending)) => pending,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "the observation buffer could not be read");
                    tokio::time::sleep(ADOPT_INTERVAL).await;
                    continue;
                }
                Err(error) => {
                    tracing::error!(%error, "the buffer task failed");
                    tokio::time::sleep(ADOPT_INTERVAL).await;
                    continue;
                }
            };
            let Some(pending) = pending else {
                tokio::select! {
                    () = self.buffer.changed() => {}
                    _ = adopt.tick() => {}
                }
                continue;
            };
            let mut request = match <v1::IngestRequest as prost::Message>::decode(
                pending.payload.as_slice(),
            ) {
                Ok(request) => request,
                Err(error) => {
                    tracing::warn!(sequence = pending.sequence, %error, "dropped a batch that does not decode");
                    self.ack(pending.sequence).await;
                    continue;
                }
            };
            request.epoch.clone_from(&epoch);
            request.sequence = pending.sequence;
            let mut call = tonic::Request::new(request);
            call.set_timeout(CALL_TIMEOUT);
            match client.ingest(call).await {
                Ok(response) => {
                    let response = response.into_inner();
                    tracing::debug!(
                        sequence = pending.sequence,
                        duplicate = response.duplicate,
                        new = response.new,
                        changed = response.changed,
                        "batch delivered"
                    );
                    self.ack(pending.sequence).await;
                }
                Err(status) if status.code() == tonic::Code::InvalidArgument => {
                    tracing::warn!(
                        sequence = pending.sequence,
                        code = code_of(&status).unwrap_or_default(),
                        "the controller refused a batch; it is dropped: {}",
                        status.message()
                    );
                    self.ack(pending.sequence).await;
                }
                Err(status) => {
                    return match refused_status(&status) {
                        (AgentState::Disconnected, error) => SessionEnd::Broken(error),
                        (state, error) => SessionEnd::Refused(state, error),
                    };
                }
            }
        }
    }

    async fn ack(&self, sequence: u64) {
        let buffer = self.buffer.clone();
        match tokio::task::spawn_blocking(move || buffer.ack(sequence)).await {
            Ok(Ok(())) => self.set_status(|_| {}),
            Ok(Err(error)) => tracing::warn!(%error, "a delivered batch could not be removed"),
            Err(error) => tracing::error!(%error, "the buffer task failed"),
        }
    }
}

fn modified(path: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
}

/// A pause of `base` with up to a quarter more or less, so many nodes do not reconnect at
/// the same instant.
fn jitter(base: Duration) -> Duration {
    let mut byte = [0u8; 1];
    let _ = aws_lc_rs::rand::fill(&mut byte);
    let quarter = base / 4;
    let offset = quarter.mul_f64(f64::from(byte[0]) / 255.0 * 2.0);
    base.saturating_sub(quarter) + offset
}

/// Connects once with the node's credentials and says hello (`tenko node status --check`).
///
/// # Errors
///
/// The classified failure of the last endpoint tried.
pub async fn check(
    credentials: &Credentials,
    version: &str,
    majors: &[u32],
) -> Result<Agreed, (AgentState, StatusError)> {
    let config = credentials.client_config().map_err(|error| {
        (
            AgentState::Refused,
            status_error(error.code(), error.detail()),
        )
    })?;
    let mut last = (
        AgentState::Refused,
        status_error(
            "cluster.node.endpoint",
            "the node knows no cluster endpoint",
        ),
    );
    for target in credentials.identity.dial_targets() {
        match connect(&target, Arc::clone(&config)).await {
            Ok(channel) => return hello(channel, majors, version, credentials, &target).await,
            Err(error) => last = classify_transport(&error),
        }
    }
    Err(last)
}

/// Renews the certificate now (`tenko node renew`): connects, says hello, renews, writes
/// the new pair. A running node process picks the new pair up at its next connection.
///
/// # Errors
///
/// The classified failure, or the renewal error.
pub async fn renew_once(paths: &NodePaths, version: &str) -> Result<Credentials, ClusterError> {
    let credentials = Credentials::load(paths)?;
    let config = credentials.client_config()?;
    let mut last = ClusterError::new(
        "cluster.node.endpoint",
        409,
        "the node knows no cluster endpoint",
    );
    for target in credentials.identity.dial_targets() {
        let channel = match connect(&target, Arc::clone(&config)).await {
            Ok(channel) => channel,
            Err(error) => {
                let (_, error) = classify_transport(&error);
                last = ClusterError::new("cluster.connect", 503, error.detail);
                continue;
            }
        };
        if let Err((_, error)) = hello(
            channel.clone(),
            version::SUPPORTED_MAJORS,
            version,
            &credentials,
            &target,
        )
        .await
        {
            return Err(ClusterError::new("cluster.node.renew", 502, error.detail));
        }
        return renew(channel, &credentials, paths).await;
    }
    Err(last)
}
