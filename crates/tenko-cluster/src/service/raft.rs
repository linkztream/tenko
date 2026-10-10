//! The `Raft` service: consensus traffic between controllers (WP3.1a). Payloads are the
//! openraft 0.9 request types in CBOR (`openraft-0.9/cbor-1`, see [`crate::wire`]); a
//! snapshot arrives as a stream of chunks of at most 1 MiB, is written aside and installed
//! only when the SHA-256 announced in the first chunk matches what arrived (the receiver
//! then builds every derived index aside and swaps them atomically, M1).

use tenko_store::raft::{network::SNAPSHOT_CHUNK, types::Vote};
use tonic::{Request, Response, Status, Streaming};

use crate::{
    error::ClusterError,
    mtls::PeerInfo,
    peers::{Access, PeerService},
    proto::v1,
    server::{peer_of, status_of},
    wire::{self, RAFT_WIRE},
};

/// The answer of a node whose Raft core stopped.
fn stopped(error: &impl std::fmt::Display) -> Status {
    status_of(&ClusterError::new(
        "cluster.raft.stopped",
        503,
        format!("the Raft node of this controller stopped: {error}"),
    ))
}

fn invalid(code: &'static str, detail: impl Into<String>) -> Status {
    status_of(&ClusterError::new(code, 400, detail))
}

/// Refuses a Raft message that speaks for another node than the one that sent it.
fn same_sender(peer: &PeerInfo, vote: &Vote) -> Result<(), Status> {
    let speaks_for = vote.leader_id().voted_for();
    if speaks_for == Some(peer.identity.node.0) {
        Ok(())
    } else {
        Err(status_of(&ClusterError::new(
            "cluster.peer.impersonation",
            403,
            format!(
                "controller {} sent a Raft message for node {}",
                peer.identity.node,
                speaks_for.map_or_else(|| "none".to_owned(), |node| node.to_string())
            ),
        )))
    }
}

fn reply(payload: &impl serde::Serialize) -> Result<Response<v1::RaftResponse>, Status> {
    Ok(Response::new(v1::RaftResponse {
        wire: RAFT_WIRE.to_owned(),
        payload: wire::encode(payload).map_err(|error| status_of(&error))?,
    }))
}

#[tonic::async_trait]
impl v1::raft_server::Raft for PeerService {
    async fn append_entries(
        &self,
        request: Request<v1::RaftRequest>,
    ) -> Result<Response<v1::RaftResponse>, Status> {
        let peer = peer_of(&request)?;
        self.peers.authenticate(&peer, Access::Raft).await?;
        let body = request.into_inner();
        wire::check(&body.wire, RAFT_WIRE).map_err(|error| status_of(&error))?;
        let rpc: wire::AppendRequest =
            wire::decode("append entries", &body.payload).map_err(|error| status_of(&error))?;
        same_sender(&peer, &rpc.vote)?;
        let response = self
            .peers
            .store()
            .handle_append_entries(rpc)
            .await
            .map_err(|error| stopped(&error))?;
        reply(&response)
    }

    async fn vote(
        &self,
        request: Request<v1::RaftRequest>,
    ) -> Result<Response<v1::RaftResponse>, Status> {
        let peer = peer_of(&request)?;
        self.peers.authenticate(&peer, Access::Raft).await?;
        let body = request.into_inner();
        wire::check(&body.wire, RAFT_WIRE).map_err(|error| status_of(&error))?;
        let rpc: wire::VoteRequestOf =
            wire::decode("vote", &body.payload).map_err(|error| status_of(&error))?;
        same_sender(&peer, &rpc.vote)?;
        let response = self
            .peers
            .store()
            .handle_vote(rpc)
            .await
            .map_err(|error| stopped(&error))?;
        reply(&response)
    }

    async fn install_snapshot(
        &self,
        request: Request<Streaming<v1::SnapshotChunk>>,
    ) -> Result<Response<v1::RaftResponse>, Status> {
        let peer = peer_of(&request)?;
        self.peers.authenticate(&peer, Access::Raft).await?;
        let mut stream = request.into_inner();
        let mut chunk = stream
            .message()
            .await?
            .ok_or_else(|| invalid("cluster.snapshot.empty", "the snapshot stream was empty"))?;
        wire::check(&chunk.wire, RAFT_WIRE).map_err(|error| status_of(&error))?;
        let vote: wire::VoteOf =
            wire::decode("snapshot vote", &chunk.vote).map_err(|error| status_of(&error))?;
        same_sender(&peer, &vote)?;
        let meta: wire::SnapshotMetaOf =
            wire::decode("snapshot metadata", &chunk.meta).map_err(|error| status_of(&error))?;
        let expected: [u8; 32] = chunk.sha256.as_slice().try_into().map_err(|_| {
            invalid(
                "cluster.snapshot.digest",
                "the first chunk carries no SHA-256 of the snapshot",
            )
        })?;
        let mut receiver = self
            .peers
            .store()
            .receive_snapshot()
            .map_err(|error| stopped(&error))?;
        let mut digest = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        let mut offset = 0_u64;
        loop {
            if chunk.offset != offset {
                return Err(invalid(
                    "cluster.snapshot.offset",
                    format!(
                        "a snapshot chunk starts at byte {}, expected {offset}",
                        chunk.offset
                    ),
                ));
            }
            if chunk.data.len() > SNAPSHOT_CHUNK {
                return Err(invalid(
                    "cluster.snapshot.chunk",
                    "a snapshot chunk is larger than 1 MiB",
                ));
            }
            digest.update(&chunk.data);
            receiver
                .write_chunk(&chunk.data)
                .await
                .map_err(|error| stopped(&error))?;
            offset += u64::try_from(chunk.data.len()).unwrap_or(u64::MAX);
            if chunk.done {
                break;
            }
            chunk = stream.message().await?.ok_or_else(|| {
                invalid(
                    "cluster.snapshot.truncated",
                    "the snapshot stream ended before its last chunk",
                )
            })?;
            wire::check(&chunk.wire, RAFT_WIRE).map_err(|error| status_of(&error))?;
        }
        if digest.finish().as_ref() != expected.as_slice() {
            // Dropping the receiver removes the partial file; the leader starts again.
            return Err(invalid(
                "cluster.snapshot.digest",
                "the snapshot does not match its SHA-256; it was not installed",
            ));
        }
        let response = receiver
            .install(vote, meta)
            .await
            .map_err(|error| stopped(&error))?;
        tracing::info!(peer = %peer.identity.node, bytes = offset, "installed a snapshot from the leader");
        reply(&response)
    }
}
