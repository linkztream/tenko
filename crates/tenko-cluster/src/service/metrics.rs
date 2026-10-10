//! The `Metrics` service: one controller's metrics snapshot for its peers. A stub until
//! WP3.5: the method answers `UNIMPLEMENTED`.

use tonic::{Request, Response, Status};

use super::arrives_with;
use crate::{proto::v1, server::ClusterService};

const PACKAGE: &str = "WP3.5";

#[tonic::async_trait]
impl v1::metrics_server::Metrics for ClusterService {
    async fn snapshot(
        &self,
        _request: Request<v1::SnapshotRequest>,
    ) -> Result<Response<v1::MetricsSnapshot>, Status> {
        Err(arrives_with("Metrics", PACKAGE))
    }
}
