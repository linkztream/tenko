//! The client side of the controller transport: [`PeerNetwork`] implements the store's
//! [`PeerTransport`] and [`LeaderLink`] over gRPC on the cluster port, with this
//! controller's certificate as the client certificate.
//!
//! **Endpoints** come from the replicated member records (`cluster.members`), not from the
//! address in the Raft membership: the first controller joined with an empty one. The
//! Raft address serves as the fallback while a record has not replicated yet, and an
//! endpoint can be pinned (the seed of a join). Resolved endpoints are cached for a few
//! seconds; a connection per endpoint is kept and re-dialled by tonic when it breaks.
//!
//! **Deadlines** derive from the Raft timers and the store timeouts ([`PeerTimings`]).
//!
//! **Message size.** An append-entries request is limited to [`MAX_APPEND_BYTES`]: a
//! larger one is cut after the entries that fit and answered with openraft's
//! `PartialSuccess`, so openraft sends the rest next. The coalescer keeps every single
//! entry below that limit (`max_batch_bytes` plus the audit drafts and the encoding).
//!
//! **Forwarding.** A forwarded write is retried by the store only when the answer proves
//! that nothing was queued: the callee does not lead, or the connection could not be made
//! (the dialler marks its own failures). A call that broke after it was sent is
//! [`ForwardError::NoAnswer`]: the store returns a timeout and the caller's idempotency key
//! or precondition makes a retry safe.

use std::{
    collections::HashMap,
    fmt, io,
    sync::{Arc, Mutex, OnceLock, PoisonError, RwLock},
    time::{Duration, Instant},
};

use arc_swap::ArcSwapOption;
use futures::{StreamExt as _, future::BoxFuture};
use prost::bytes::Bytes;
use rustls::ClientConfig;
use tenko_core::NodeId;
use tenko_store::{
    Committed, ReadConsistency, ReadViewExt as _, Store as _, StoreError,
    raft::{
        RaftStore, RaftStoreConfig, WeakRaftStore,
        network::{
            AppendResult, ForwardError, LeaderLink, PeerTransport, ReadIndex, SNAPSHOT_CHUNK,
            SnapshotResult, VoteResult,
        },
        openraft::{
            BasicNode,
            error::{NetworkError, RPCError, ReplicationClosed, StreamingError, Unreachable},
            raft::AppendEntriesResponse,
        },
        types::{RaftNodeId, Snapshot, Vote},
    },
};
use tokio::{io::AsyncReadExt as _, net::TcpStream};
use tokio_rustls::TlsConnector;
use tonic::{Request, Status, transport::Channel};

use crate::{
    error::ClusterError,
    identity::split_host_port,
    model::tables,
    proto::v1,
    server::{MAX_MESSAGE_BYTES, code_of},
    wire::{self, BATCH_WIRE, NOT_LEADER, RAFT_WIRE},
};

/// The largest append-entries request the transport sends (below the message limit of
/// the Raft service, [`MAX_MESSAGE_BYTES`]).
pub const MAX_APPEND_BYTES: usize = MAX_MESSAGE_BYTES - 2 * 1024 * 1024;
/// How long a resolved endpoint is used before the member records are read again.
const ENDPOINT_TTL: Duration = Duration::from_secs(5);
/// The marker of the dialler's own failures: the request was never sent.
const DIAL_FAILED: &str = "peer dial failed";

/// Deadlines of the peer transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerTimings {
    /// One TCP connect plus TLS handshake.
    pub connect: Duration,
    /// An append-entries call (heartbeats included).
    pub append: Duration,
    /// A vote request.
    pub vote: Duration,
    /// A forwarded write: the leader's write timeout and a margin.
    pub forward: Duration,
    /// A read-index request.
    pub read_index: Duration,
    /// A whole snapshot transfer.
    pub snapshot: Duration,
    /// Other calls (members, digest, join, campaign, change).
    pub call: Duration,
}

impl PeerTimings {
    /// The deadlines for a store configuration.
    pub fn from_store(config: &RaftStoreConfig) -> Self {
        let election = Duration::from_millis(config.timings.election_max_ms);
        Self {
            connect: Duration::from_secs(2),
            append: election + Duration::from_secs(4),
            vote: Duration::from_millis(config.timings.election_min_ms).max(Duration::from_secs(1)),
            forward: config.write_timeout + Duration::from_secs(5),
            read_index: config.read_wait + Duration::from_secs(1),
            snapshot: Duration::from_secs(30 * 60),
            call: Duration::from_secs(30),
        }
    }
}

impl Default for PeerTimings {
    fn default() -> Self {
        Self::from_store(&RaftStoreConfig::new(std::env::temp_dir()))
    }
}

/// An error value for openraft's error types.
#[derive(Debug)]
struct Problem(String);

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Problem {}

fn unreachable(detail: impl fmt::Display) -> Unreachable {
    Unreachable::new(&Problem(detail.to_string()))
}

/// The client side of the controller transport. Cloning is cheap.
#[derive(Clone)]
pub struct PeerNetwork {
    inner: Arc<Inner>,
}

struct Inner {
    local: NodeId,
    timings: PeerTimings,
    tls: ArcSwapOption<ClientConfig>,
    store: OnceLock<WeakRaftStore>,
    pinned: RwLock<HashMap<NodeId, String>>,
    resolved: Mutex<HashMap<NodeId, (String, Instant)>>,
    channels: Mutex<HashMap<String, Channel>>,
}

impl fmt::Debug for PeerNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerNetwork")
            .field("local", &self.inner.local)
            .field("tls", &self.inner.tls.load().is_some())
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl PeerNetwork {
    /// The transport of controller `local`; it reaches nobody until it has client
    /// credentials ([`PeerNetwork::set_tls`]).
    pub fn new(local: NodeId, timings: PeerTimings) -> Self {
        Self {
            inner: Arc::new(Inner {
                local,
                timings,
                tls: ArcSwapOption::empty(),
                store: OnceLock::new(),
                pinned: RwLock::new(HashMap::new()),
                resolved: Mutex::new(HashMap::new()),
                channels: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// This controller.
    pub fn local(&self) -> NodeId {
        self.inner.local
    }

    /// The deadlines.
    pub fn timings(&self) -> PeerTimings {
        self.inner.timings
    }

    /// Sets the client TLS configuration (this controller's certificate and the CA root);
    /// open connections are dropped and dialled again with it.
    pub fn set_tls(&self, config: Arc<ClientConfig>) {
        self.inner.tls.store(Some(config));
        lock(&self.inner.channels).clear();
    }

    /// Whether the transport has client credentials.
    pub fn has_tls(&self) -> bool {
        self.inner.tls.load().is_some()
    }

    /// The store whose member records name the endpoints (a weak handle).
    pub fn attach(&self, store: &RaftStore) {
        let _ = self.inner.store.set(store.downgrade());
    }

    /// Pins the endpoint of a node (the seed of a join, tests); it wins over the member
    /// records.
    pub fn pin(&self, node: NodeId, endpoint: impl Into<String>) {
        self.inner
            .pinned
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(node, endpoint.into());
    }

    /// Forgets the cached endpoint of `node` (its member record changed).
    pub fn forget(&self, node: NodeId) {
        lock(&self.inner.resolved).remove(&node);
    }

    fn store(&self) -> Option<RaftStore> {
        self.inner.store.get().and_then(WeakRaftStore::upgrade)
    }

    /// The endpoint of `node`: pinned, else its member record, else `fallback` (the
    /// address in the Raft membership).
    ///
    /// # Errors
    ///
    /// `cluster.peer.no_endpoint` (503) when none is known.
    pub async fn endpoint(
        &self,
        node: NodeId,
        fallback: Option<&str>,
    ) -> Result<String, ClusterError> {
        if let Some(pinned) = self
            .inner
            .pinned
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&node)
        {
            return Ok(pinned.clone());
        }
        if let Some((endpoint, at)) = lock(&self.inner.resolved).get(&node)
            && at.elapsed() < ENDPOINT_TTL
        {
            return Ok(endpoint.clone());
        }
        let mut found = None;
        if let Some(store) = self.store() {
            if let Ok(view) = store.read(ReadConsistency::Local).await
                && let Ok(Some((record, _))) = view.get_typed(&tables::MEMBERS, &node.0)
                && !record.address.is_empty()
            {
                found = Some(record.address);
            }
            if found.is_none() {
                found = store
                    .raft()
                    .metrics()
                    .borrow()
                    .membership_config
                    .membership()
                    .get_node(&node.0)
                    .map(|basic| basic.addr.clone())
                    .filter(|addr| !addr.is_empty());
            }
        }
        let endpoint = found
            .or_else(|| fallback.filter(|addr| !addr.is_empty()).map(str::to_owned))
            .ok_or_else(|| {
                ClusterError::new(
                    "cluster.peer.no_endpoint",
                    503,
                    format!("no cluster port is known for controller {node}"),
                )
                .with_param("node", node.to_string())
            })?;
        lock(&self.inner.resolved).insert(node, (endpoint.clone(), Instant::now()));
        Ok(endpoint)
    }

    /// A connection to `endpoint`, dialled when there is none.
    ///
    /// # Errors
    ///
    /// `cluster.peer.no_credentials` (503) before [`PeerNetwork::set_tls`], or
    /// `cluster.peer.unreachable` (503).
    pub async fn channel(&self, endpoint: &str) -> Result<Channel, ClusterError> {
        if let Some(channel) = lock(&self.inner.channels).get(endpoint) {
            return Ok(channel.clone());
        }
        let config = self.inner.tls.load_full().ok_or_else(|| {
            ClusterError::new(
                "cluster.peer.no_credentials",
                503,
                "this controller has no certificate for its peers yet",
            )
        })?;
        let channel = connect(endpoint, config, self.inner.timings.connect)
            .await
            .map_err(|error| {
                ClusterError::new(
                    "cluster.peer.unreachable",
                    503,
                    format!("cannot reach the controller at {endpoint}: {error}"),
                )
                .with_param("endpoint", endpoint.to_owned())
            })?;
        lock(&self.inner.channels).insert(endpoint.to_owned(), channel.clone());
        Ok(channel)
    }

    fn drop_channel(&self, endpoint: &str) {
        lock(&self.inner.channels).remove(endpoint);
    }

    /// A `Cluster` client for `node`.
    ///
    /// # Errors
    ///
    /// As [`PeerNetwork::endpoint`] and [`PeerNetwork::channel`].
    pub async fn cluster_client(
        &self,
        node: NodeId,
    ) -> Result<v1::cluster_client::ClusterClient<Channel>, ClusterError> {
        let endpoint = self.endpoint(node, None).await?;
        self.cluster_client_at(&endpoint).await
    }

    /// A `Cluster` client for an endpoint.
    ///
    /// # Errors
    ///
    /// As [`PeerNetwork::channel`].
    pub async fn cluster_client_at(
        &self,
        endpoint: &str,
    ) -> Result<v1::cluster_client::ClusterClient<Channel>, ClusterError> {
        Ok(
            v1::cluster_client::ClusterClient::new(self.channel(endpoint).await?)
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
        )
    }

    async fn raft_client(
        &self,
        node: NodeId,
        fallback: &str,
    ) -> Result<(String, v1::raft_client::RaftClient<Channel>), ClusterError> {
        let endpoint = self.endpoint(node, Some(fallback)).await?;
        let channel = self.channel(&endpoint).await?;
        Ok((
            endpoint,
            v1::raft_client::RaftClient::new(channel)
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
        ))
    }

    /// Runs a call with a deadline, as a request with the gRPC timeout set.
    async fn deadline<T>(
        &self,
        endpoint: &str,
        timeout: Duration,
        call: impl Future<Output = Result<tonic::Response<T>, Status>>,
    ) -> Result<T, Status> {
        match tokio::time::timeout(timeout, call).await {
            Ok(Ok(response)) => Ok(response.into_inner()),
            Ok(Err(status)) => {
                if matches!(
                    status.code(),
                    tonic::Code::Unavailable | tonic::Code::Unknown
                ) && code_of(&status).is_none()
                {
                    // A transport failure: dial again next time.
                    self.drop_channel(endpoint);
                }
                Err(status)
            }
            Err(_) => {
                self.drop_channel(endpoint);
                Err(Status::deadline_exceeded(format!(
                    "no answer from {endpoint} within {} ms",
                    timeout.as_millis()
                )))
            }
        }
    }
}

/// Whether a failed call never left this controller: the dialler failed.
fn never_sent(status: &Status) -> bool {
    if status.code() != tonic::Code::Unavailable || code_of(status).is_some() {
        return false;
    }
    let mut text = status.message().to_owned();
    let mut cause: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(status);
    while let Some(current) = cause {
        text.push_str(": ");
        text.push_str(&current.to_string());
        cause = current.source();
    }
    text.contains(DIAL_FAILED) || text.contains("error trying to connect")
}

fn timed<T>(timeout: Duration, mut request: Request<T>) -> Request<T> {
    request.set_timeout(timeout);
    request
}

/// Cuts an append-entries request to the entries that fit in [`MAX_APPEND_BYTES`];
/// returns the request to send and, when it was cut, the log id to report as partial
/// success.
fn fit(
    mut rpc: wire::AppendRequest,
) -> Result<(Vec<u8>, Option<tenko_store::raft::types::LogId>), ClusterError> {
    let encoded = wire::encode(&rpc)?;
    if encoded.len() <= MAX_APPEND_BYTES || rpc.entries.len() <= 1 {
        return Ok((encoded, None));
    }
    let mut keep = 0;
    let mut bytes = 1024;
    for entry in &rpc.entries {
        let size = wire::encode(entry)?.len();
        if keep > 0 && bytes + size > MAX_APPEND_BYTES {
            break;
        }
        bytes += size;
        keep += 1;
    }
    rpc.entries.truncate(keep);
    let last = rpc.entries.last().map(|entry| entry.log_id);
    if let (Some(last), Some(commit)) = (last, rpc.leader_commit)
        && commit > last
    {
        rpc.leader_commit = Some(last);
    }
    Ok((wire::encode(&rpc)?, last))
}

#[async_trait::async_trait]
impl PeerTransport for PeerNetwork {
    async fn append_entries(
        &self,
        target: RaftNodeId,
        node: &BasicNode,
        rpc: wire::AppendRequest,
    ) -> AppendResult {
        let (payload, partial) =
            fit(rpc).map_err(|error| RPCError::Unreachable(unreachable(error)))?;
        let (endpoint, mut client) = self
            .raft_client(NodeId(target), &node.addr)
            .await
            .map_err(|error| RPCError::Unreachable(unreachable(error)))?;
        let request = timed(
            self.inner.timings.append,
            Request::new(v1::RaftRequest {
                wire: RAFT_WIRE.to_owned(),
                payload,
            }),
        );
        let response = self
            .deadline(
                &endpoint,
                self.inner.timings.append,
                client.append_entries(request),
            )
            .await
            .map_err(|status| raft_call_error(&status))?;
        let answer: wire::AppendResponse = decode_raft(&response.wire, &response.payload)
            .map_err(|error| RPCError::Unreachable(unreachable(error)))?;
        Ok(match (answer, partial) {
            (AppendEntriesResponse::Success, Some(last)) => {
                AppendEntriesResponse::PartialSuccess(Some(last))
            }
            (answer, _) => answer,
        })
    }

    async fn vote(
        &self,
        target: RaftNodeId,
        node: &BasicNode,
        rpc: wire::VoteRequestOf,
    ) -> VoteResult {
        let payload =
            wire::encode(&rpc).map_err(|error| RPCError::Unreachable(unreachable(error)))?;
        let (endpoint, mut client) = self
            .raft_client(NodeId(target), &node.addr)
            .await
            .map_err(|error| RPCError::Unreachable(unreachable(error)))?;
        let request = timed(
            self.inner.timings.vote,
            Request::new(v1::RaftRequest {
                wire: RAFT_WIRE.to_owned(),
                payload,
            }),
        );
        let response = self
            .deadline(&endpoint, self.inner.timings.vote, client.vote(request))
            .await
            .map_err(|status| raft_call_error(&status))?;
        decode_raft(&response.wire, &response.payload)
            .map_err(|error| RPCError::Unreachable(unreachable(error)))
    }

    async fn full_snapshot(
        &self,
        target: RaftNodeId,
        node: &BasicNode,
        vote: Vote,
        snapshot: Snapshot,
        cancel: BoxFuture<'static, ReplicationClosed>,
    ) -> SnapshotResult {
        let network = |error: &dyn fmt::Display| {
            StreamingError::Network(NetworkError::new(&Problem(error.to_string())))
        };
        let path = snapshot.snapshot.path.clone();
        let digest = tokio::task::spawn_blocking(move || file_sha256(&path))
            .await
            .map_err(|error| network(&error))?
            .map_err(|error| network(&error))?;
        let vote = wire::encode(&vote).map_err(|error| network(&error))?;
        let meta = wire::encode(&snapshot.meta).map_err(|error| network(&error))?;
        let file = tokio::fs::File::open(&snapshot.snapshot.path)
            .await
            .map_err(|error| network(&error))?;
        let (endpoint, mut client) = self
            .raft_client(NodeId(target), &node.addr)
            .await
            .map_err(|error| StreamingError::Unreachable(unreachable(error)))?;
        let chunks = snapshot_chunks(file, vote, meta, digest);
        let call = async {
            let request = timed(self.inner.timings.snapshot, Request::new(chunks));
            self.deadline(
                &endpoint,
                self.inner.timings.snapshot,
                client.install_snapshot(request),
            )
            .await
        };
        let response = tokio::select! {
            closed = cancel => return Err(StreamingError::Closed(closed)),
            response = call => response,
        };
        let response = response.map_err(|status| {
            match raft_call_error::<tenko_store::raft::openraft::error::Infallible>(&status) {
                RPCError::Unreachable(error) => StreamingError::Unreachable(error),
                other => network(&other),
            }
        })?;
        decode_raft(&response.wire, &response.payload).map_err(|error| network(&error))
    }
}

/// The chunks of a snapshot file: the first carries the vote, the metadata and the digest;
/// the last is marked done.
fn snapshot_chunks(
    file: tokio::fs::File,
    vote: Vec<u8>,
    meta: Vec<u8>,
    digest: [u8; 32],
) -> impl futures::Stream<Item = v1::SnapshotChunk> + Send + 'static {
    struct State {
        file: tokio::fs::File,
        offset: u64,
        first: Option<(Vec<u8>, Vec<u8>, [u8; 32])>,
        done: bool,
    }
    let state = State {
        file,
        offset: 0,
        first: Some((vote, meta, digest)),
        done: false,
    };
    futures::stream::unfold(state, |mut state| async move {
        if state.done {
            return None;
        }
        let mut data = vec![0_u8; SNAPSHOT_CHUNK];
        let mut filled = 0;
        while filled < data.len() {
            match state.file.read(&mut data[filled..]).await {
                Ok(0) => break,
                Ok(read) => filled += read,
                // The receiver sees a short stream and refuses it.
                Err(_) => return None,
            }
        }
        data.truncate(filled);
        let done = filled < SNAPSHOT_CHUNK;
        let (vote, meta, sha256) = match state.first.take() {
            Some((vote, meta, digest)) => (vote, meta, digest.to_vec()),
            None => (Vec::new(), Vec::new(), Vec::new()),
        };
        let chunk = v1::SnapshotChunk {
            wire: RAFT_WIRE.to_owned(),
            vote,
            meta,
            sha256,
            offset: state.offset,
            data,
            done,
        };
        state.offset += u64::try_from(filled).unwrap_or(u64::MAX);
        state.done = done;
        Some((chunk, state))
    })
    .boxed()
}

/// The SHA-256 of a file.
fn file_sha256(path: &std::path::Path) -> io::Result<[u8; 32]> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    let mut buffer = vec![0_u8; SNAPSHOT_CHUNK];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
    }
    let digest = context.finish();
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn decode_raft<T: serde::de::DeserializeOwned>(
    found: &str,
    payload: &[u8],
) -> Result<T, ClusterError> {
    wire::check(found, RAFT_WIRE)?;
    wire::decode("Raft response", payload)
}

/// openraft's view of a failed Raft call: back off (unreachable) for transport failures
/// and refusals, retry soon for anything else.
fn raft_call_error<E: std::error::Error>(status: &Status) -> RPCError<RaftNodeId, BasicNode, E> {
    let detail = format!(
        "{} ({})",
        status.message(),
        code_of(status).unwrap_or("transport")
    );
    if code_of(status) == Some(wire::WIRE_MISMATCH) {
        tracing::error!(code = wire::WIRE_MISMATCH, "{}", status.message());
    }
    match status.code() {
        tonic::Code::InvalidArgument | tonic::Code::Internal => {
            RPCError::Network(NetworkError::new(&Problem(detail)))
        }
        _ => RPCError::Unreachable(unreachable(detail)),
    }
}

#[async_trait::async_trait]
impl LeaderLink for PeerNetwork {
    async fn forward_propose(
        &self,
        _from: RaftNodeId,
        target: RaftNodeId,
        batch: Bytes,
    ) -> Result<Committed, ForwardError> {
        let endpoint = self
            .endpoint(NodeId(target), None)
            .await
            .map_err(|error| ForwardError::Unreachable(error.to_string()))?;
        let mut client = self
            .cluster_client_at(&endpoint)
            .await
            .map_err(|error| ForwardError::Unreachable(error.to_string()))?;
        let request = timed(
            self.inner.timings.forward,
            Request::new(v1::ProposeRequest {
                wire: BATCH_WIRE.to_owned(),
                batch: batch.to_vec(),
            }),
        );
        match self
            .deadline(
                &endpoint,
                self.inner.timings.forward,
                client.propose(request),
            )
            .await
        {
            Ok(response) => {
                wire::check(&response.wire, BATCH_WIRE)
                    .map_err(|error| ForwardError::Wire(error.to_string()))?;
                wire::decode_committed(&response.committed)
                    .map_err(|error| ForwardError::NoAnswer(error.to_string()))
            }
            Err(status) => Err(forward_error(&status, true)),
        }
    }

    async fn forward_read_index(
        &self,
        _from: RaftNodeId,
        target: RaftNodeId,
    ) -> Result<ReadIndex, ForwardError> {
        let endpoint = self
            .endpoint(NodeId(target), None)
            .await
            .map_err(|error| ForwardError::Unreachable(error.to_string()))?;
        let mut client = self
            .cluster_client_at(&endpoint)
            .await
            .map_err(|error| ForwardError::Unreachable(error.to_string()))?;
        let request = timed(
            self.inner.timings.read_index,
            Request::new(v1::ReadIndexRequest {}),
        );
        match self
            .deadline(
                &endpoint,
                self.inner.timings.read_index,
                client.read_index(request),
            )
            .await
        {
            Ok(response) => Ok(ReadIndex {
                log_index: response.log_index,
                term: response.term,
                leader: response.leader_id,
            }),
            // A read index changes nothing: any failure may be retried.
            Err(status) => match forward_error(&status, false) {
                error @ (ForwardError::NotLeader { .. }
                | ForwardError::Store(_)
                | ForwardError::Wire(_)) => Err(error),
                other => Err(ForwardError::Unreachable(other.to_string())),
            },
        }
    }
}

/// Classifies a failed forward. `queued_unknown`: a call that broke after it was sent may
/// have queued the batch.
fn forward_error(status: &Status, queued_unknown: bool) -> ForwardError {
    if code_of(status) == Some(NOT_LEADER) {
        return ForwardError::NotLeader {
            leader: wire::leader_of(status).map(|node| node.0),
        };
    }
    if code_of(status) == Some(wire::WIRE_MISMATCH) {
        return ForwardError::Wire(status.message().to_owned());
    }
    if let Some(error) = wire::store_error_of(status) {
        return ForwardError::Store(error);
    }
    if never_sent(status) {
        return ForwardError::Unreachable(status.message().to_owned());
    }
    match status.code() {
        // Refused before anything was queued (authentication, a malformed request).
        tonic::Code::PermissionDenied
        | tonic::Code::Unauthenticated
        | tonic::Code::FailedPrecondition => ForwardError::Unreachable(status.message().to_owned()),
        tonic::Code::InvalidArgument => {
            ForwardError::Store(StoreError::Codec(status.message().to_owned()))
        }
        _ if queued_unknown => ForwardError::NoAnswer(status.message().to_owned()),
        _ => ForwardError::Unreachable(status.message().to_owned()),
    }
}

/// Opens a gRPC channel to one endpoint over mutual TLS.
async fn connect(
    target: &str,
    config: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<Channel, tonic::transport::Error> {
    let target = target.to_owned();
    tonic::transport::Endpoint::from_static("http://tenko-peer.invalid")
        .connect_timeout(timeout)
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            dial(target.clone(), Arc::clone(&config), timeout)
        }))
        .await
}

async fn dial(
    target: String,
    config: Arc<ClientConfig>,
    timeout: Duration,
) -> io::Result<hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<TcpStream>>> {
    let failed = |detail: String| io::Error::other(format!("{DIAL_FAILED}: {detail}"));
    let (host, port) = split_host_port(&target).map_err(|error| failed(error.to_string()))?;
    let tcp = tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| failed(format!("{target} did not answer")))?
        .map_err(|error| failed(format!("{target}: {error}")))?;
    let _ = tcp.set_nodelay(true);
    let tls = tokio::time::timeout(
        timeout,
        TlsConnector::from(config).connect(crate::mtls::server_name(&host), tcp),
    )
    .await
    .map_err(|_| failed(format!("the TLS handshake with {target} timed out")))?
    .map_err(|error| failed(format!("the TLS handshake with {target} failed: {error}")))?;
    if tls.get_ref().1.alpn_protocol() != Some(crate::mtls::ALPN_H2) {
        return Err(failed(format!("{target} did not agree on HTTP/2")));
    }
    Ok(hyper_util::rt::TokioIo::new(tls))
}

#[cfg(test)]
mod tests {
    use tenko_store::raft::{
        openraft::{CommittedLeaderId, EntryPayload, LogId},
        types::{Entry, Proposal, ProposedBatch},
    };

    use super::*;

    fn entry(index: u64, bytes: usize) -> Entry {
        Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, 1), index),
            payload: EntryPayload::Normal(Proposal {
                journal_retention: 10,
                journal_max_bytes: 0,
                batches: vec![ProposedBatch {
                    batch: Bytes::from(vec![7_u8; bytes]),
                    fingerprint: None,
                }],
            }),
        }
    }

    #[test]
    fn large_append_requests_are_cut_to_the_entries_that_fit() {
        let small = wire::AppendRequest {
            vote: Vote::new(1, 1),
            prev_log_id: None,
            entries: vec![entry(1, 100), entry(2, 100)],
            leader_commit: None,
        };
        let (_, partial) = fit(small).expect("fits");
        assert_eq!(partial, None);

        let chunk = MAX_APPEND_BYTES / 3;
        let large = wire::AppendRequest {
            vote: Vote::new(1, 1),
            prev_log_id: None,
            entries: (1..=5).map(|index| entry(index, chunk)).collect(),
            leader_commit: Some(LogId::new(CommittedLeaderId::new(1, 1), 5)),
        };
        let (payload, partial) = fit(large).expect("cut");
        assert!(payload.len() <= MAX_APPEND_BYTES);
        assert_eq!(partial.map(|log_id| log_id.index), Some(2));
        let sent: wire::AppendRequest = wire::decode("append", &payload).expect("decode");
        assert_eq!(sent.entries.len(), 2);
        assert_eq!(sent.leader_commit.map(|log_id| log_id.index), Some(2));
    }

    #[test]
    fn dial_failures_mean_never_sent() {
        let status = Status::unavailable(format!("{DIAL_FAILED}: refused"));
        assert!(never_sent(&status));
        assert!(!never_sent(&Status::unavailable("connection reset")));
        assert!(matches!(
            forward_error(&Status::unavailable("connection reset"), true),
            ForwardError::NoAnswer(_)
        ));
        assert!(matches!(
            forward_error(&wire::not_leader_status(Some(NodeId(1001))), true),
            ForwardError::NotLeader { leader: Some(1001) }
        ));
        assert!(matches!(
            forward_error(&wire::store_status(&StoreError::IdempotencyMismatch), true),
            ForwardError::Store(StoreError::IdempotencyMismatch)
        ));
    }
}
