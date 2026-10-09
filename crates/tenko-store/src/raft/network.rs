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
//! Implementations here:
//!
//! - [`NoPeers`]: a single voter has no peers (Slice 1); every call is unreachable.
//! - [`InProcessNetwork`]: nodes in one process, for tests and benchmarks; messages are
//!   moved, not serialized, and snapshots stream in 1 MiB chunks through the same receiver
//!   a network transport uses. Nodes can be isolated to simulate a partition.
//!
//! The real transport (gRPC over mTLS, Slice 3, `tenko-cluster`) implements
//! [`PeerTransport`] by serializing the openraft request types (they derive serde with the
//! `serde` feature) and serving the three handlers above.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, PoisonError, RwLock},
};

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
use tokio::io::AsyncReadExt as _;

use super::{
    RaftStore, WeakRaftStore,
    stored::Message,
    types::{RaftNodeId, Snapshot, TypeConfig, Vote},
};

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

/// Sends Raft messages to peers.
#[async_trait::async_trait]
pub trait PeerTransport: Send + Sync + 'static {
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
}

/// openraft's network factory over a [`PeerTransport`].
pub(crate) struct NetworkFactory {
    pub(crate) transport: Arc<dyn PeerTransport>,
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
            target,
            node: node.clone(),
        }
    }
}

/// openraft's connection to one peer.
pub(crate) struct PeerClient {
    transport: Arc<dyn PeerTransport>,
    target: RaftNodeId,
    node: BasicNode,
}

impl RaftNetwork<TypeConfig> for PeerClient {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> AppendResult {
        self.transport
            .append_entries(self.target, &self.node, rpc)
            .await
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
        self.transport
            .full_snapshot(self.target, &self.node, vote, snapshot, Box::pin(cancel))
            .await
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
