//! The `Cluster` service: joining, write forwarding, read index, member list, state digest
//! and key transfer between controllers. A stub until WP3.1a: every method answers
//! `UNIMPLEMENTED`.

use tonic::{Request, Response, Status};

use super::arrives_with;
use crate::{proto::v1, server::ClusterService};

const PACKAGE: &str = "WP3.1a";

#[tonic::async_trait]
impl v1::cluster_server::Cluster for ClusterService {
    async fn join(
        &self,
        _request: Request<v1::JoinRequest>,
    ) -> Result<Response<v1::JoinResponse>, Status> {
        Err(arrives_with("Cluster", PACKAGE))
    }

    async fn propose(
        &self,
        _request: Request<v1::ProposeRequest>,
    ) -> Result<Response<v1::ProposeResponse>, Status> {
        Err(arrives_with("Cluster", PACKAGE))
    }

    async fn read_index(
        &self,
        _request: Request<v1::ReadIndexRequest>,
    ) -> Result<Response<v1::ReadIndexResponse>, Status> {
        Err(arrives_with("Cluster", PACKAGE))
    }

    async fn members(
        &self,
        _request: Request<v1::MembersRequest>,
    ) -> Result<Response<v1::MembersResponse>, Status> {
        Err(arrives_with("Cluster", PACKAGE))
    }

    async fn digest(
        &self,
        _request: Request<v1::DigestRequest>,
    ) -> Result<Response<v1::DigestResponse>, Status> {
        Err(arrives_with("Cluster", PACKAGE))
    }

    async fn transfer_kek(
        &self,
        _request: Request<v1::TransferKekRequest>,
    ) -> Result<Response<v1::TransferKekResponse>, Status> {
        Err(arrives_with("Cluster", PACKAGE))
    }
}
