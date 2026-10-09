//! In-process Raft network: every node runs an RPC server task fed by an unbounded mpsc
//! channel; clients send a request plus a oneshot reply channel. Messages are moved, not
//! serialized (no wire encoding cost is measured). Snapshots are streamed as 1 MiB chunks
//! through a bounded channel into a file in the receiving node's directory, then installed
//! with `Raft::install_full_snapshot`.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::Ordering;
use std::time::Instant;

use openraft::BasicNode;
use openraft::error::Fatal;
use openraft::error::NetworkError;
use openraft::error::RPCError;
use openraft::error::RaftError;
use openraft::error::RemoteError;
use openraft::error::ReplicationClosed;
use openraft::error::StreamingError;
use openraft::error::Unreachable;
use openraft::network::RPCOption;
use openraft::network::RaftNetwork;
use openraft::network::RaftNetworkFactory;
use openraft::raft::AppendEntriesRequest;
use openraft::raft::AppendEntriesResponse;
use openraft::raft::SnapshotResponse;
use openraft::raft::VoteRequest;
use openraft::raft::VoteResponse;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::raft_types::NodeId;
use crate::raft_types::Raft;
use crate::raft_types::Snapshot;
use crate::raft_types::SnapshotFile;
use crate::raft_types::SnapshotMeta;
use crate::raft_types::TypeConfig;
use crate::raft_types::Vote;
use crate::state_machine::StateMachineStore;

const CHUNK: usize = 1 << 20;

type AppendReply = Result<AppendEntriesResponse<NodeId>, RaftError<NodeId>>;
type VoteReply = Result<VoteResponse<NodeId>, RaftError<NodeId>>;
type SnapshotReply = Result<SnapshotResponse<NodeId>, String>;

pub enum Rpc {
    Append(
        AppendEntriesRequest<TypeConfig>,
        oneshot::Sender<AppendReply>,
    ),
    Vote(VoteRequest<NodeId>, oneshot::Sender<VoteReply>),
    Snapshot {
        vote: Vote,
        meta: SnapshotMeta,
        chunks: mpsc::Receiver<Vec<u8>>,
        reply: oneshot::Sender<SnapshotReply>,
    },
}

#[derive(Debug)]
struct NetErr(String);
impl std::fmt::Display for NetErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for NetErr {}

fn unreachable(msg: &str) -> Unreachable {
    Unreachable::new(&NetErr(msg.to_string()))
}

#[derive(Clone, Default)]
pub struct Router {
    targets: Arc<RwLock<BTreeMap<NodeId, mpsc::UnboundedSender<Rpc>>>>,
}

impl Router {
    fn get(&self, id: NodeId) -> Option<mpsc::UnboundedSender<Rpc>> {
        self.targets.read().expect("router lock").get(&id).cloned()
    }

    /// Register a node and spawn its RPC server task.
    pub fn register(&self, id: NodeId, raft: Raft, sm: StateMachineStore) {
        let (tx, mut rx) = mpsc::unbounded_channel::<Rpc>();
        self.targets.write().expect("router lock").insert(id, tx);
        tokio::spawn(async move {
            while let Some(rpc) = rx.recv().await {
                let raft = raft.clone();
                match rpc {
                    Rpc::Append(req, reply) => {
                        tokio::spawn(async move {
                            let _ = reply.send(raft.append_entries(req).await);
                        });
                    }
                    Rpc::Vote(req, reply) => {
                        tokio::spawn(async move {
                            let _ = reply.send(raft.vote(req).await);
                        });
                    }
                    Rpc::Snapshot {
                        vote,
                        meta,
                        chunks,
                        reply,
                    } => {
                        let sm = sm.clone();
                        tokio::spawn(async move {
                            let res = receive_snapshot(&raft, &sm, vote, meta, chunks).await;
                            let _ = reply.send(res);
                        });
                    }
                }
            }
        });
    }

    pub fn unregister(&self, id: NodeId) {
        self.targets.write().expect("router lock").remove(&id);
    }
}

async fn receive_snapshot(
    raft: &Raft,
    sm: &StateMachineStore,
    vote: Vote,
    meta: SnapshotMeta,
    mut chunks: mpsc::Receiver<Vec<u8>>,
) -> SnapshotReply {
    let path = sm.new_receive_path();
    let t0 = Instant::now();
    {
        let f = tokio::fs::File::create(&path)
            .await
            .map_err(|e| e.to_string())?;
        let mut w = tokio::io::BufWriter::with_capacity(CHUNK, f);
        while let Some(chunk) = chunks.recv().await {
            w.write_all(&chunk).await.map_err(|e| e.to_string())?;
        }
        w.flush().await.map_err(|e| e.to_string())?;
        w.get_ref().sync_all().await.map_err(|e| e.to_string())?;
    }
    sm.stats()
        .snapshot_transfer_ns
        .store(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    let snapshot = Snapshot {
        meta,
        snapshot: Box::new(SnapshotFile { path }),
    };
    raft.install_full_snapshot(vote, snapshot)
        .await
        .map_err(|e| e.to_string())
}

#[derive(Clone)]
pub struct NetworkFactory {
    pub router: Router,
}

impl RaftNetworkFactory<TypeConfig> for NetworkFactory {
    type Network = Connection;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        Connection {
            router: self.router.clone(),
            target,
        }
    }
}

pub struct Connection {
    router: Router,
    target: NodeId,
}

impl RaftNetwork<TypeConfig> for Connection {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let tx = self
            .router
            .get(self.target)
            .ok_or_else(|| unreachable("node not registered"))?;
        let (rtx, rrx) = oneshot::channel();
        tx.send(Rpc::Append(rpc, rtx))
            .map_err(|_| unreachable("node mailbox closed"))?;
        let res = rrx.await.map_err(|_| unreachable("reply dropped"))?;
        res.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let tx = self
            .router
            .get(self.target)
            .ok_or_else(|| unreachable("node not registered"))?;
        let (rtx, rrx) = oneshot::channel();
        tx.send(Rpc::Vote(rpc, rtx))
            .map_err(|_| unreachable("node mailbox closed"))?;
        let res = rrx.await.map_err(|_| unreachable("reply dropped"))?;
        res.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn full_snapshot(
        &mut self,
        vote: Vote,
        snapshot: Snapshot,
        _cancel: impl Future<Output = ReplicationClosed> + Send + 'static,
        _option: RPCOption,
    ) -> Result<SnapshotResponse<NodeId>, StreamingError<TypeConfig, Fatal<NodeId>>> {
        let tx = self
            .router
            .get(self.target)
            .ok_or_else(|| unreachable("node not registered"))?;
        let (ctx, crx) = mpsc::channel::<Vec<u8>>(8);
        let (rtx, rrx) = oneshot::channel();
        tx.send(Rpc::Snapshot {
            vote,
            meta: snapshot.meta.clone(),
            chunks: crx,
            reply: rtx,
        })
        .map_err(|_| unreachable("node mailbox closed"))?;
        let mut f = tokio::fs::File::open(&snapshot.snapshot.path)
            .await
            .map_err(|e| NetworkError::new(&e))?;
        loop {
            let mut buf = vec![0u8; CHUNK];
            let mut filled = 0;
            while filled < CHUNK {
                let n = f
                    .read(&mut buf[filled..])
                    .await
                    .map_err(|e| NetworkError::new(&e))?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }
            buf.truncate(filled);
            ctx.send(buf)
                .await
                .map_err(|_| unreachable("snapshot receiver closed"))?;
            if filled < CHUNK {
                break;
            }
        }
        drop(ctx);
        let res = rrx
            .await
            .map_err(|_| unreachable("snapshot reply dropped"))?;
        res.map_err(|e| StreamingError::Network(NetworkError::new(&NetErr(e))))
    }
}
