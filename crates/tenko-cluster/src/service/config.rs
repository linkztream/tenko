//! The `Config` service: configuration sync to nodes and the secrets they need. A stub
//! until WP3.10: every method answers `UNIMPLEMENTED`.

use std::pin::Pin;

use futures::Stream;
use tonic::{Request, Response, Status};

use super::arrives_with;
use crate::{proto::v1, server::ClusterService};

const PACKAGE: &str = "WP3.10";

type DeltaStream = Pin<Box<dyn Stream<Item = Result<v1::ConfigDelta, Status>> + Send>>;

#[tonic::async_trait]
impl v1::config_server::Config for ClusterService {
    type WatchStream = DeltaStream;

    async fn watch(
        &self,
        _request: Request<v1::WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        Err(arrives_with("Config", PACKAGE))
    }

    async fn secrets(
        &self,
        _request: Request<v1::SecretsRequest>,
    ) -> Result<Response<v1::SecretsResponse>, Status> {
        Err(arrives_with("Config", PACKAGE))
    }
}
