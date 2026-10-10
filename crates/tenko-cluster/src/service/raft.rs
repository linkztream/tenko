//! The `Raft` service: consensus traffic between controllers. A stub until WP3.1a: every
//! method answers `UNIMPLEMENTED`.

use tonic::{Request, Response, Status, Streaming};

use super::arrives_with;
use crate::{proto::v1, server::ClusterService};

const PACKAGE: &str = "WP3.1a";

#[tonic::async_trait]
impl v1::raft_server::Raft for ClusterService {
    async fn append_entries(
        &self,
        _request: Request<v1::RaftRequest>,
    ) -> Result<Response<v1::RaftResponse>, Status> {
        Err(arrives_with("Raft", PACKAGE))
    }

    async fn vote(
        &self,
        _request: Request<v1::RaftRequest>,
    ) -> Result<Response<v1::RaftResponse>, Status> {
        Err(arrives_with("Raft", PACKAGE))
    }

    async fn install_snapshot(
        &self,
        _request: Request<Streaming<v1::SnapshotChunk>>,
    ) -> Result<Response<v1::RaftResponse>, Status> {
        Err(arrives_with("Raft", PACKAGE))
    }
}
