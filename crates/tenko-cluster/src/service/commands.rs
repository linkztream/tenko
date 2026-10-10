//! The `Commands` service: commands to nodes and their reports back. A stub until WP3.10:
//! every method answers `UNIMPLEMENTED`.

use std::pin::Pin;

use futures::Stream;
use tonic::{Request, Response, Status};

use super::arrives_with;
use crate::{proto::v1, server::ClusterService};

const PACKAGE: &str = "WP3.10";

type CommandStream = Pin<Box<dyn Stream<Item = Result<v1::Command, Status>> + Send>>;

#[tonic::async_trait]
impl v1::commands_server::Commands for ClusterService {
    type SubscribeStream = CommandStream;

    async fn subscribe(
        &self,
        _request: Request<v1::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        Err(arrives_with("Commands", PACKAGE))
    }

    async fn report(
        &self,
        _request: Request<v1::CommandEvent>,
    ) -> Result<Response<v1::ReportResponse>, Status> {
        Err(arrives_with("Commands", PACKAGE))
    }
}
