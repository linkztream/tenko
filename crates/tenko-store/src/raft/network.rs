//! The transport between Raft peers.
//!
//! [`PeerTransport`] is the extension point: an object-safe version of openraft's
//! `RaftNetwork` addressed by target node. The store wraps whatever transport it is opened
//! with ([`RaftStore::open_with`](super::RaftStore::open_with)) into openraft's network
//! factory. The receiving side of every transport calls
//! [`RaftStore::handle_append_entries`](super::RaftStore::handle_append_entries),
//! [`RaftStore::handle_vote`](super::RaftStore::handle_vote) and
//! [`RaftStore::receive_snapshot`](super::RaftStore::receive_snapshot), which streams a
//! snapshot in chunks into a file and installs it.
//!
//! # Write forwarding (the leader link)
//!
//! Every transport is also a [`LeaderLink`]: a follower's `propose` sends the encoded batch
//! to the leader ([`LeaderLink::forward_propose`]), which serves it with
//! [`RaftStore::accept_forwarded`](super::RaftStore::accept_forwarded), and a linearizable
//! read on a follower asks the leader for a read index
//! ([`LeaderLink::forward_read_index`], served by
//! [`RaftStore::read_index`](super::RaftStore::read_index)). A forward goes to another
//! leader only when the answer proves that nothing was queued
//! ([`ForwardError::not_queued`]).
//!
//! Implementations here:
//!
//! - [`NoPeers`]: a single voter has no peers (Slice 1); every call is unreachable.
//! - [`InProcessNetwork`]: nodes in one process, for tests and benchmarks; messages are
//!   moved, not serialized, and snapshots stream in 1 MiB chunks through the same receiver
//!   a network transport uses. Nodes can be isolated to simulate a partition. It is the
//!   in-process leader link as well.
//!
//! The real transport (gRPC over mutual TLS, `tenko-cluster`) implements [`PeerTransport`]
//! by serializing the openraft request types (they derive serde with the `serde` feature)
//! and serving the handlers above.
//!
//! A store opened with one transport can be handed another one while it runs
//! ([`RaftStore::set_transport`](super::RaftStore::set_transport)): `tenko serve` opens the
//! store before its cluster step brings up the peer transport.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Mutex, PoisonError, RwLock},
    time::Instant,
};

use bytes::Bytes;
use futures::future::BoxFuture;
use openraft::{
    BasicNode,
    error::{
        Fatal, NetworkError, RPCError, RaftError, RemoteError, ReplicationClosed, StreamingError,
        Unreachable,
    },
    network::{RPCOption, RaftNetwork, RaftNetworkFactory},
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, VoteRequest, VoteResponse,
    },
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt as _;

use super::{
    RaftStore, WeakRaftStore,
    stored::Message,
    types::{RaftNodeId, Snapshot, TypeConfig, Vote},
};
use crate::api::{Committed, StoreError};

/// The result of a forwarded `append_entries`.
pub type AppendResult = Result<
    AppendEntriesResponse<RaftNodeId>,
    RPCError<RaftNodeId, BasicNode, RaftError<RaftNodeId>>,
>;
/// The result of a forwarded `vote`.
pub type VoteResult =
    Result<VoteResponse<RaftNodeId>, RPCError<RaftNodeId, BasicNode, RaftError<RaftNodeId>>>;
/// The result of a streamed snapshot.
pub type SnapshotResult =
    Result<SnapshotResponse<RaftNodeId>, StreamingError<TypeConfig, Fatal<RaftNodeId>>>;

/// Size of one snapshot chunk on the wire.
pub const SNAPSHOT_CHUNK: usize = 1 << 20;

/// The answer of a leader to a read-index request: the log index a linearizable read waits
/// for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadIndex {
    /// The log index to wait for (`None`: the log is empty).
    pub log_index: Option<u64>,
    /// The term in which the leader confirmed its leadership.
    pub term: u64,
    /// The leader that answered.
    pub leader: RaftNodeId,
}

/// Why a forwarded write or read index failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForwardError {
    /// The callee does not lead: nothing was queued, so the call may go to another member.
    #[error("the callee is not the leader (it names {leader:?})")]
    NotLeader {
        /// The leader the callee knows of, if any.
        leader: Option<RaftNodeId>,
    },
    /// The callee could not be reached; the request was not delivered.
    #[error("the leader is unreachable: {0}")]
    Unreachable(String),
    /// The request was delivered but no answer came back: the outcome is unknown.
    #[error("no answer from the leader: {0}")]
    NoAnswer(String),
    /// The callee answered with a store error (preconditions, idempotency, validation).
    #[error(transparent)]
    Store(StoreError),
    /// The peers speak different wire versions (`cluster.forward.wire`).
    #[error("the peers speak different wire versions: {0}")]
    Wire(String),
}

impl ForwardError {
    /// Whether the answer proves that nothing was queued, so the request may be sent again,
    /// to the same or another member.
    pub fn not_queued(&self) -> bool {
        matches!(self, Self::NotLeader { .. } | Self::Unreachable(_))
    }
}

/// Forwards writes and read-index requests from a follower to the leader.
#[async_trait::async_trait]
pub trait LeaderLink: Send + Sync + 'static {
    /// Sends an encoded write batch (`tenko_core::codec::to_cbor` of a
    /// [`WriteBatch`](crate::api::WriteBatch)) from `from` to the leader `target`, which
    /// validates and proposes it and answers once it is committed and applied there.
    async fn forward_propose(
        &self,
        from: RaftNodeId,
        target: RaftNodeId,
        batch: Bytes,
    ) -> Result<Committed, ForwardError>;

    /// Asks the leader `target` for a read index on behalf of `from`, after the leader
    /// confirmed its leadership with a quorum.
    async fn forward_read_index(
        &self,
        from: RaftNodeId,
        target: RaftNodeId,
    ) -> Result<ReadIndex, ForwardError>;
}

/// Sends Raft messages to peers, and forwards writes and reads to the leader.
#[async_trait::async_trait]
pub trait PeerTransport: LeaderLink + Send + Sync + 'static {
    /// Replicates entries (or a heartbeat) to `target`.
    async fn append_entries(
        &self,
        target: RaftNodeId,
        node: &BasicNode,
        rpc: AppendEntriesRequest<TypeConfig>,
    ) -> AppendResult;

    /// Asks `target` for its vote.
    async fn vote(
        &self,
        target: RaftNodeId,
        node: &BasicNode,
        rpc: VoteRequest<RaftNodeId>,
    ) -> VoteResult;

    /// Streams a complete snapshot to `target`, which installs it. `cancel` resolves when
    /// replication to the target stops; the transport should then give up.
    async fn full_snapshot(
        &self,
        target: RaftNodeId,
        node: &BasicNode,
        vote: Vote,
        snapshot: Snapshot,
        cancel: BoxFuture<'static, ReplicationClosed>,
    ) -> SnapshotResult;

    /// Whether this transport can reach peers at all; `false` for [`NoPeers`]. A member of
    /// a cluster whose store runs on such a transport starts no election until it gets a
    /// real one ([`RaftStore::set_transport`](super::RaftStore::set_transport)).
    fn reaches_peers(&self) -> bool {
        true
    }
}

fn unreachable(message: &str) -> Unreachable {
    Unreachable::new(&Message(message.to_owned()))
}

/// The transport of a single voter: there are no peers to reach.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPeers;

#[async_trait::async_trait]
impl PeerTransport for NoPeers {
    async fn append_entries(
        &self,
        _target: RaftNodeId,
        _node: &BasicNode,
        _rpc: AppendEntriesRequest<TypeConfig>,
    ) -> AppendResult {
        Err(RPCError::Unreachable(unreachable(
            "this store has no peers",
        )))
    }

    async fn vote(
        &self,
        _target: RaftNodeId,
        _node: &BasicNode,
        _rpc: VoteRequest<RaftNodeId>,
    ) -> VoteResult {
        Err(RPCError::Unreachable(unreachable(
            "this store has no peers",
        )))
    }

    async fn full_snapshot(
        &self,
        _target: RaftNodeId,
        _node: &BasicNode,
        _vote: Vote,
        _snapshot: Snapshot,
        _cancel: BoxFuture<'static, ReplicationClosed>,
    ) -> SnapshotResult {
        Err(StreamingError::Unreachable(unreachable(
            "this store has no peers",
        )))
    }

    fn reaches_peers(&self) -> bool {
        false
    }
}

#[async_trait::async_trait]
impl LeaderLink for NoPeers {
    async fn forward_propose(
        &self,
        _from: RaftNodeId,
        _target: RaftNodeId,
        _batch: Bytes,
    ) -> Result<Committed, ForwardError> {
        Err(ForwardError::Unreachable(
            "this store has no peers".to_owned(),
        ))
    }

    async fn forward_read_index(
        &self,
        _from: RaftNodeId,
        _target: RaftNodeId,
    ) -> Result<ReadIndex, ForwardError> {
        Err(ForwardError::Unreachable(
            "this store has no peers".to_owned(),
        ))
    }
}

/// The transport a store runs on, replaceable while it runs
/// ([`RaftStore::set_transport`](super::RaftStore::set_transport)).
pub(crate) struct SwitchTransport {
    current: RwLock<Arc<dyn PeerTransport>>,
}

impl SwitchTransport {
    pub(crate) fn new(transport: Arc<dyn PeerTransport>) -> Self {
        Self {
            current: RwLock::new(transport),
        }
    }

    pub(crate) fn current(&self) -> Arc<dyn PeerTransport> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    pub(crate) fn set(&self, transport: Arc<dyn PeerTransport>) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = transport;
    }
}

#[async_trait::async_trait]
impl LeaderLink for SwitchTransport {
    async fn forward_propose(
        &self,
        from: RaftNodeId,
        target: RaftNodeId,
        batch: Bytes,
    ) -> Result<Committed, ForwardError> {
        self.current().forward_propose(from, target, batch).await
    }

    async fn forward_read_index(
        &self,
        from: RaftNodeId,
        target: RaftNodeId,
    ) -> Result<ReadIndex, ForwardError> {
        self.current().forward_read_index(from, target).await
    }
}

#[async_trait::async_trait]
impl PeerTransport for SwitchTransport {
    async fn append_entries(
        &self,
        target: RaftNodeId,
        node: &BasicNode,
        rpc: AppendEntriesRequest<TypeConfig>,
    ) -> AppendResult {
        self.current().append_entries(target, node, rpc).await
    }

    async fn vote(
        &self,
        target: RaftNodeId,
        node: &BasicNode,
        rpc: VoteRequest<RaftNodeId>,
    ) -> VoteResult {
        self.current().vote(target, node, rpc).await
    }

    async fn full_snapshot(
        &self,
        target: RaftNodeId,
        node: &BasicNode,
        vote: Vote,
        snapshot: Snapshot,
        cancel: BoxFuture<'static, ReplicationClosed>,
    ) -> SnapshotResult {
        self.current()
            .full_snapshot(target, node, vote, snapshot, cancel)
            .await
    }

    fn reaches_peers(&self) -> bool {
        self.current().reaches_peers()
    }
}

/// When each peer last answered a replication request of this node: the leader's view of
/// its followers (`MemberStatus::last_contact_ms`).
#[derive(Debug, Default)]
pub(crate) struct ContactBook {
    answered: Mutex<HashMap<RaftNodeId, Instant>>,
}

impl ContactBook {
    fn record(&self, node: RaftNodeId) {
        self.answered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(node, Instant::now());
    }

    /// Milliseconds since `node` last answered, if it ever did.
    pub(crate) fn millis_since(&self, node: RaftNodeId) -> Option<u64> {
        self.answered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&node)
            .map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

/// openraft's network factory over a [`PeerTransport`].
pub(crate) struct NetworkFactory {
    pub(crate) transport: Arc<dyn PeerTransport>,
    pub(crate) contacts: Arc<ContactBook>,
}

#[allow(
    clippy::unused_async_trait_impl,
    reason = "openraft declares the factory method async"
)]
impl RaftNetworkFactory<TypeConfig> for NetworkFactory {
    type Network = PeerClient;

    async fn new_client(&mut self, target: RaftNodeId, node: &BasicNode) -> PeerClient {
        PeerClient {
            transport: Arc::clone(&self.transport),
            contacts: Arc::clone(&self.contacts),
            target,
            node: node.clone(),
        }
    }
}

/// openraft's connection to one peer.
pub(crate) struct PeerClient {
    transport: Arc<dyn PeerTransport>,
    contacts: Arc<ContactBook>,
    target: RaftNodeId,
    node: BasicNode,
}

impl RaftNetwork<TypeConfig> for PeerClient {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> AppendResult {
        let result = self
            .transport
            .append_entries(self.target, &self.node, rpc)
            .await;
        if result.is_ok() {
            self.contacts.record(self.target);
        }
        result
    }

    async fn vote(&mut self, rpc: VoteRequest<RaftNodeId>, _option: RPCOption) -> VoteResult {
        self.transport.vote(self.target, &self.node, rpc).await
    }

    async fn full_snapshot(
        &mut self,
        vote: Vote,
        snapshot: Snapshot,
        cancel: impl Future<Output = ReplicationClosed> + Send + 'static,
        _option: RPCOption,
    ) -> SnapshotResult {
        let result = self
            .transport
            .full_snapshot(self.target, &self.node, vote, snapshot, Box::pin(cancel))
            .await;
        if result.is_ok() {
            self.contacts.record(self.target);
        }
        result
    }
}

/// Raft nodes in one process (tests and benchmarks).
///
/// Register every store with [`InProcessNetwork::register`] after opening it with
/// `RaftStore::open_with(config, Arc::new(network.clone()))`. The network holds weak
/// references, so it never keeps a store alive.
#[derive(Clone, Default)]
pub struct InProcessNetwork {
    nodes: Arc<RwLock<BTreeMap<RaftNodeId, WeakRaftStore>>>,
    isolated: Arc<RwLock<BTreeSet<RaftNodeId>>>,
}

impl std::fmt::Debug for InProcessNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let nodes: Vec<RaftNodeId> = self
            .nodes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect();
        f.debug_struct("InProcessNetwork")
            .field("nodes", &nodes)
            .finish_non_exhaustive()
    }
}

impl InProcessNetwork {
    /// A network without nodes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes a store reachable under its node id.
    pub fn register(&self, store: &RaftStore) {
        self.nodes
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(store.node_id().0, store.downgrade());
    }

    /// Removes a node.
    pub fn unregister(&self, node: RaftNodeId) {
        self.nodes
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&node);
    }

    /// Cuts a node off from every other node (`true`) or reconnects it (`false`): messages
    /// to and from it fail as unreachable.
    pub fn set_isolated(&self, node: RaftNodeId, isolated: bool) {
        let mut set = self
            .isolated
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if isolated {
            set.insert(node);
        } else {
            set.remove(&node);
        }
    }

    fn target(&self, sender: RaftNodeId, target: RaftNodeId) -> Result<RaftStore, Unreachable> {
        {
            let isolated = self.isolated.read().unwrap_or_else(PoisonError::into_inner);
            if isolated.contains(&target) || isolated.contains(&sender) {
                return Err(unreachable("node is isolated"));
            }
        }
        self.nodes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&target)
            .and_then(WeakRaftStore::upgrade)
            .ok_or_else(|| unreachable("node is not registered"))
    }
}

#[async_trait::async_trait]
impl PeerTransport for InProcessNetwork {
    async fn append_entries(
        &self,
        target: RaftNodeId,
        _node: &BasicNode,
        rpc: AppendEntriesRequest<TypeConfig>,
    ) -> AppendResult {
        let store = self
            .target(rpc.vote.leader_id().voted_for().unwrap_or_default(), target)
            .map_err(RPCError::Unreachable)?;
        store
            .handle_append_entries(rpc)
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(target, error)))
    }

    async fn vote(
        &self,
        target: RaftNodeId,
        _node: &BasicNode,
        rpc: VoteRequest<RaftNodeId>,
    ) -> VoteResult {
        let store = self
            .target(rpc.vote.leader_id().voted_for().unwrap_or_default(), target)
            .map_err(RPCError::Unreachable)?;
        store
            .handle_vote(rpc)
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(target, error)))
    }

    async fn full_snapshot(
        &self,
        target: RaftNodeId,
        _node: &BasicNode,
        vote: Vote,
        snapshot: Snapshot,
        _cancel: BoxFuture<'static, ReplicationClosed>,
    ) -> SnapshotResult {
        let sender = vote.leader_id().voted_for().unwrap_or_default();
        let store = self.target(sender, target)?;
        let mut receiver = store
            .receive_snapshot()
            .map_err(|error| StreamingError::Network(NetworkError::new(&error)))?;
        let mut file = tokio::fs::File::open(&snapshot.snapshot.path)
            .await
            .map_err(|error| StreamingError::Network(NetworkError::new(&error)))?;
        let mut chunk = vec![0_u8; SNAPSHOT_CHUNK];
        loop {
            let mut filled = 0;
            while filled < chunk.len() {
                let read = file
                    .read(&mut chunk[filled..])
                    .await
                    .map_err(|error| StreamingError::Network(NetworkError::new(&error)))?;
                if read == 0 {
                    break;
                }
                filled += read;
            }
            if filled == 0 {
                break;
            }
            // A partition during the transfer fails it, as on a real network.
            self.target(sender, target)?;
            receiver
                .write_chunk(&chunk[..filled])
                .await
                .map_err(|error| StreamingError::Network(NetworkError::new(&error)))?;
            if filled < chunk.len() {
                break;
            }
        }
        receiver
            .install(vote, snapshot.meta)
            .await
            .map_err(|error| match error {
                super::SnapshotInstallError::Fatal(fatal) => {
                    StreamingError::RemoteError(RemoteError::new(target, *fatal))
                }
                super::SnapshotInstallError::Io(error) => {
                    StreamingError::Network(NetworkError::new(&error))
                }
            })
    }
}

#[async_trait::async_trait]
impl LeaderLink for InProcessNetwork {
    async fn forward_propose(
        &self,
        from: RaftNodeId,
        target: RaftNodeId,
        batch: Bytes,
    ) -> Result<Committed, ForwardError> {
        let store = self
            .target(from, target)
            .map_err(|error| ForwardError::Unreachable(error.to_string()))?;
        store.accept_forwarded(batch).await
    }

    async fn forward_read_index(
        &self,
        from: RaftNodeId,
        target: RaftNodeId,
    ) -> Result<ReadIndex, ForwardError> {
        let store = self
            .target(from, target)
            .map_err(|error| ForwardError::Unreachable(error.to_string()))?;
        store.read_index().await
    }
}
