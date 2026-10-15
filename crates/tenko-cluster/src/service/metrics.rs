//! The `Metrics` service: one controller's newest metrics sample for the other controllers
//! (see [`crate::metrics`]). The caller holds a controller certificate; the answer comes from
//! the source the server set on the node registry.

use tenko_core::{Role, Timestamp};
use tonic::{Request, Response, Status};

use crate::{
    error::ClusterError,
    proto::v1,
    server::{ClusterService, peer_of, status_of},
};

fn unavailable() -> Status {
    status_of(&ClusterError::new(
        "cluster.metrics.unavailable",
        503,
        "this controller has no metrics sample yet; try again in a second",
    ))
}

#[tonic::async_trait]
impl v1::metrics_server::Metrics for ClusterService {
    async fn snapshot(
        &self,
        request: Request<v1::SnapshotRequest>,
    ) -> Result<Response<v1::MetricsSnapshot>, Status> {
        let peer = peer_of(&request)?;
        let node = peer.identity.node;
        if !peer.identity.roles.contains(Role::Controller) {
            return Err(status_of(&ClusterError::new(
                "cluster.peer.not_controller",
                403,
                format!(
                    "node {node} is not a controller; only controllers read the metrics of a controller"
                ),
            )));
        }
        // A controller that joined has a record that must hold the certificate; the first
        // controller's own certificate has none (the TLS handshake verified it).
        if let Some((record, _)) = self
            .registry
            .record(node)
            .await
            .map_err(|error| status_of(&error))?
            && (!record.roles.contains(&Role::Controller)
                || !record.holds(&peer.identity.serial, Timestamp::now()))
        {
            return Err(status_of(&ClusterError::new(
                "cluster.node.certificate_unknown",
                403,
                "the certificate is not one this controller was issued, or it expired",
            )));
        }
        let source = self.registry.metrics_source().ok_or_else(unavailable)?;
        let sample = source.current().await.ok_or_else(unavailable)?;
        Ok(Response::new(sample.to_proto()))
    }
}
